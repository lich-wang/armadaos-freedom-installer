using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// INTERNAL, immutable snapshot of one imported installation package, bound to the exact firmware that was
/// observed on the device at capture time.
/// <para>
/// A snapshot is a lease, not a validation result: capturing it opens the manifest and every declared
/// artefact read-only, rechecks their full length and SHA-256 from the held streams and keeps only those
/// leases. <see cref="Payloads"/> is read-only and every role the manifest declared (the four contract
/// roles, <c>initramfs</c> and any extra artefact) appears with its full absolute path, length and complete
/// digest. <see cref="Firmware"/> is the exact observed snapshot, never a synthesized value.
/// </para>
/// <para>
/// <see cref="BindingSha256"/> is a deterministic canonical digest over the original raw manifest
/// fingerprint, the five observed firmware fields, the model, the declared storage, the seed metadata and
/// every role/path/length/hash entry in ordinal role order. A local extraction path does not change the
/// logical binding.
/// </para>
/// <para>
/// The legacy <see cref="CaptureAsync"/> route never creates, moves or deletes a file, never re-runs the
/// importer, never queries a device and never decides readiness: the caller owns the
/// <see cref="ImportedPackage"/> and its disposal, this type only owns the read leases it opened itself.
/// The schema-2 <see cref="CaptureEdlRawAsync"/> route additionally expands the two bounded gzip images,
/// exactly once each, into one unique child directory it created itself below the caller's explicit
/// expansion parent. That child and the expanded read leases are this instance's own derived state; the
/// caller's parent directory, the imported package and every other caller file stay untouched.
/// </para>
/// </summary>
internal sealed class InternalInstallPackageSnapshot : IDisposable
{
    private const string RequiredModel = "TB322FC";

    private const string MetadataFileName = "package.json";

    private const int Sha256HexLength = 64;

    /// <summary>Bounded streaming-hash chunk: 81920 bytes, the BCL default copy buffer size.</summary>
    private const int HashStreamBufferBytes = 81920;

    /// <summary>Exact prepared runtime length; the runtime role is never derived from another role.</summary>
    private const long RuntimeBytes = 4L * 1024L * 1024L;

    private const string SeedRole = "ostree-seed";

    /// <summary>Bounded expansion chunk: 1 MiB per inflate read, per output write and per digest pass.</summary>
    private const int ExpansionBufferBytes = 1024 * 1024;

    /// <summary>The 10 byte gzip header plus the 8 byte CRC32/ISIZE trailer is the smallest frame.</summary>
    private const int MinimumGzipFrameBytes = 18;

    /// <summary>A device tree is small; a multi megabyte "DTB" is refused instead of buffered.</summary>
    private const int MaxDtbBytes = 16 * 1024 * 1024;

    private const string DtbNormalRole = "dtb-normal";

    private const string DtbDiagnosticRole = "dtb-diagnostic";

    private const long Ext4SuperblockOffset = 1024L;

    private const int Ext4SuperblockBytes = 0x158;

    private const long BtrfsSuperblockOffset = 65536L;

    private const int BtrfsSuperblockBytes = 148;

    private const uint Crc32Initial = 0xFFFFFFFFu;

    private const uint Crc32Polynomial = 0xEDB88320u;

    /// <summary>The standard reflected CRC-32 table, built once for every expanded gzip pass.</summary>
    private static readonly uint[] Crc32Table = BuildCrc32Table();

    /// <summary>Roles the prepared factory needs, each exactly once with a complete, non-empty file.</summary>
    private static readonly string[] PreparedRoles =
    {
        SeedRole, "kernel", "dtb", "runtime", "initramfs",
    };

    private readonly FileStream _manifestStream;

    private readonly IReadOnlyList<PayloadLease> _leases;

    /// <summary>Expanded raw images this instance created itself; empty on the legacy route.</summary>
    private readonly IReadOnlyList<DerivedLease> _derivedLeases;

    /// <summary>The caller's explicit expansion parent, kept only to bound this instance's own child.</summary>
    private readonly string? _expansionParent;

    /// <summary>The one unique child directory this instance created below the expansion parent.</summary>
    private readonly string? _expansionChild;

    private readonly EdlRawPackageContract? _edlRawContract;

    private readonly VerifiedEdlFile? _linuxBootRaw;

    private readonly VerifiedEdlFile? _linuxRootRaw;

    /// <summary>Legacy seed fact; null on the direct route, which never fabricates a seed or RAM receipt.</summary>
    private readonly RamInstallSeed? _seed;

    private int _disposed;

    /// <summary>
    /// Private constructor: a snapshot only ever exists as the result of a complete, verified capture, and
    /// the caller receives the read leases this instance now owns.
    /// </summary>
    private InternalInstallPackageSnapshot(
        FileStream manifestStream,
        IReadOnlyList<PayloadLease> leases,
        string manifestFingerprint,
        string bindingSha256,
        PackageStorage storage,
        FirmwareSnapshot firmware,
        RamInstallSeed seed)
    {
        _manifestStream = manifestStream;
        _leases = leases;
        _derivedLeases = Array.Empty<DerivedLease>();
        _expansionParent = null;
        _expansionChild = null;
        _edlRawContract = null;
        _linuxBootRaw = null;
        _linuxRootRaw = null;
        _seed = seed;

        ManifestFingerprint = manifestFingerprint;
        BindingSha256 = bindingSha256;
        Storage = storage;
        Firmware = firmware;

        var payloads = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);
        foreach (var lease in leases)
        {
            payloads.Add(lease.Role, new VerifiedEdlFile(lease.FullPath, lease.Length, lease.Sha256));
        }

        Payloads = new ReadOnlyDictionary<string, VerifiedEdlFile>(payloads);
    }

    /// <summary>
    /// Private constructor of a direct EDL raw snapshot: it exists only after both expanded raw images were
    /// written, re-hashed from their own held leases and bound to the validated contract, so the instance
    /// owns the manifest, the seven source leases, the two derived leases and its unique expansion child.
    /// </summary>
    private InternalInstallPackageSnapshot(
        FileStream manifestStream,
        IReadOnlyList<PayloadLease> leases,
        IReadOnlyList<DerivedLease> derivedLeases,
        string expansionParent,
        string expansionChild,
        EdlRawPackageContract contract,
        VerifiedEdlFile linuxBootRaw,
        VerifiedEdlFile linuxRootRaw,
        string manifestFingerprint,
        string bindingSha256,
        FirmwareSnapshot firmware)
    {
        _manifestStream = manifestStream;
        _leases = leases;
        _derivedLeases = derivedLeases;
        _expansionParent = expansionParent;
        _expansionChild = expansionChild;
        _edlRawContract = contract;
        _linuxBootRaw = linuxBootRaw;
        _linuxRootRaw = linuxRootRaw;
        _seed = null;

        ManifestFingerprint = manifestFingerprint;
        BindingSha256 = bindingSha256;
        Storage = contract.Storage;
        Firmware = firmware;

        var payloads = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);
        foreach (var lease in leases)
        {
            payloads.Add(lease.Role, new VerifiedEdlFile(lease.FullPath, lease.Length, lease.Sha256));
        }

        Payloads = new ReadOnlyDictionary<string, VerifiedEdlFile>(payloads);
    }

    /// <summary>
    /// Captures <paramref name="package"/> against <paramref name="identity"/>. Argument and cancellation
    /// checks happen before the first read; every refusal after that releases each partially opened lease
    /// again and leaves the caller's <see cref="ImportedPackage"/> untouched.
    /// </summary>
    /// <exception cref="InvalidOperationException">The selection, the observed firmware or the package no
    /// longer satisfy the internal installation contract.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal static Task<InternalInstallPackageSnapshot> CaptureAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(identity);

        cancellationToken.ThrowIfCancellationRequested();

        RequireImportedPackage(package);
        var firmware = RequireObservedFirmware(identity);

        // The guards above are cheap and stay on the caller's thread; the full-length reads and hashes of
        // a multi-gigabyte seed run on the application thread pool so a UI caller is never blocked.
        return Task.Run(() => Capture(package, firmware, cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Captures the schema-2 direct EDL raw package <paramref name="package"/> against
    /// <paramref name="identity"/>. The direct route opens the manifest plus all seven regular read-only
    /// leases, verifies the compressed package files, expands the bounded gzip images under the explicit
    /// <paramref name="expansionParent"/> and keeps the resulting leases for execution and revalidation.
    /// A schema-1 package is refused here; it only ever goes through <see cref="CaptureAsync"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The direct package, its raw facts or the observed
    /// firmware no longer satisfy the contract.</exception>
    /// <exception cref="InvalidDataException">A held raw fact is not a valid schema-2 direct payload.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal static Task<InternalInstallPackageSnapshot> CaptureEdlRawAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        string expansionParent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(expansionParent);

        // The token is observed before any filesystem work, so a pre-cancelled caller can never leave a file
        // behind and never reaches the importer claim or the package directory.
        cancellationToken.ThrowIfCancellationRequested();

        var firmware = RequireDirectObservedFirmware(identity);
        var validation = RequireDirectImportedPackage(package, identity.Model);

        // The cheap claim and identity guards stay on the caller's thread; every file lease, the real
        // contract read, the two bounded expansions and their digests run on the thread pool so a UI caller
        // is never blocked.
        return Task.Run(
            () => CaptureDirect(
                package,
                identity.Model,
                firmware,
                validation.ManifestFingerprint!,
                validation.Storage!,
                expansionParent,
                cancellationToken),
            cancellationToken);
    }

    /// <summary>SHA-256 of the raw package.json bytes that were imported, uppercase hexadecimal.</summary>
    internal string ManifestFingerprint { get; }

    /// <summary>Deterministic canonical binding of package, storage, seed and observed firmware.</summary>
    internal string BindingSha256 { get; }

    /// <summary>Storage declaration of the accepted package.</summary>
    internal PackageStorage Storage { get; }

    /// <summary>Exact firmware snapshot observed at capture time.</summary>
    internal FirmwareSnapshot Firmware { get; }

    /// <summary>
    /// Seed identity derived from the declared <c>ostree-seed</c> artefact and deployment block. A direct
    /// EDL raw capture has no seed at all, so reading this member there is refused instead of returning a
    /// fabricated seed or RAM receipt.
    /// </summary>
    internal RamInstallSeed Seed =>
        _seed
        ?? throw new InvalidOperationException(
            "A direct EDL raw snapshot carries no ostree seed and no RAM install receipt.");

    /// <summary>Every declared payload role, read-only, keyed by the exact declared role.</summary>
    internal IReadOnlyDictionary<string, VerifiedEdlFile> Payloads { get; }

    /// <summary>
    /// Typed schema-2 direct contract of this capture. A legacy seed snapshot carries no direct facts, so
    /// reading this member there is refused instead of returning a synthesized contract.
    /// </summary>
    internal EdlRawPackageContract EdlRawContract =>
        _edlRawContract
        ?? throw new InvalidOperationException("A legacy seed snapshot carries no direct EDL raw contract.");

    /// <summary>
    /// Actual expanded ext4 boot image of this direct capture. A legacy seed snapshot never produces one.
    /// </summary>
    internal VerifiedEdlFile LinuxBootRaw =>
        _linuxBootRaw
        ?? throw new InvalidOperationException("A legacy seed snapshot carries no expanded boot raw image.");

    /// <summary>
    /// Actual expanded Btrfs root image of this direct capture. A legacy seed snapshot never produces one.
    /// </summary>
    internal VerifiedEdlFile LinuxRootRaw =>
        _linuxRootRaw
        ?? throw new InvalidOperationException("A legacy seed snapshot carries no expanded root raw image.");

    /// <summary>
    /// Rechecks the stored manifest fingerprint, every payload hash and every full length from the held
    /// streams, and for a direct capture the two expanded raw images as well. A changed file is detected
    /// here; the stored verdict is never returned unverified.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The snapshot has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <exception cref="InvalidOperationException">A held file no longer matches its captured facts.</exception>
    internal Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();

        return Task.Run(() => Revalidate(cancellationToken), cancellationToken);
    }

    /// <summary>
    /// The synchronous revalidation body; it always runs on the thread pool and never returns a stored
    /// verdict. The snapshot may have been disposed between the caller's guard and the worker starting.
    /// </summary>
    private void Revalidate(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        cancellationToken.ThrowIfCancellationRequested();

        var raw = ReadAllBytes(_manifestStream, cancellationToken);
        var fingerprint = Convert.ToHexString(SHA256.HashData(raw));
        if (!string.Equals(fingerprint, ManifestFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The package manifest no longer matches the captured fingerprint {ManifestFingerprint}.");
        }

        foreach (var lease in _leases)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (lease.Stream.Length != lease.Length)
            {
                throw new InvalidOperationException(
                    $"The held artifact '{lease.Role}' no longer has its captured length {lease.Length}.");
            }

            var sha256 = HashStream(lease.Stream, cancellationToken);
            if (!string.Equals(sha256, lease.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The held artifact '{lease.Role}' no longer matches its captured SHA-256.");
            }
        }

        foreach (var lease in _derivedLeases)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (lease.Stream.Length != lease.Length)
            {
                throw new InvalidOperationException(
                    $"The expanded image '{lease.Path}' no longer has its captured length {lease.Length}.");
            }

            var sha256 = HashStream(lease.Stream, cancellationToken);
            if (!string.Equals(sha256, lease.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The expanded image '{lease.Path}' no longer matches its captured SHA-256.");
            }
        }
    }

    /// <summary>
    /// Releases only the read leases this snapshot owns. It never deletes package files, never disposes the
    /// caller's <see cref="ImportedPackage"/> and is idempotent. A direct EDL raw snapshot also removes the
    /// one unique expansion child it created itself, after proving that the child still lives beneath the
    /// caller's expansion parent; that parent and every file the caller put there stay untouched.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var lease in _leases)
        {
            lease.Stream.Dispose();
        }

        foreach (var lease in _derivedLeases)
        {
            lease.Stream.Dispose();
        }

        _manifestStream.Dispose();

        if (_expansionChild is not null && _expansionParent is not null)
        {
            DeleteOwnChild(_expansionParent, _expansionChild);
        }
    }

    // ---------------------------------------------------------------- capture

    private static InternalInstallPackageSnapshot Capture(
        ImportedPackage package,
        FirmwareSnapshot firmware,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var requiredFingerprint = package.Validation.ManifestFingerprint!;
        var root = ResolvePackageRoot(package.PackageDirectory);
        var metadataPath = Path.Combine(root, MetadataFileName);

        if (!File.Exists(metadataPath))
        {
            throw new InvalidOperationException($"The package metadata {MetadataFileName} is missing.");
        }

        if (IsReparsePoint(metadataPath, isDirectory: false))
        {
            throw new InvalidOperationException(
                $"The package metadata {MetadataFileName} is a symbolic link or reparse point.");
        }

        FileStream? manifestStream = null;
        var leases = new List<PayloadLease>();
        var handedOver = false;

        try
        {
            // The metadata handle is opened and kept before anything is read, so the bytes that are parsed
            // and the bytes that stay locked for revalidation are the same file, not two separate opens.
            manifestStream = new FileStream(metadataPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            var rawMetadata = ReadAllBytes(manifestStream, cancellationToken);
            var manifestFingerprint = Convert.ToHexString(SHA256.HashData(rawMetadata));

            if (!string.Equals(manifestFingerprint, requiredFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The package manifest changed after import; the original manifest is no longer on disk.");
            }

            using var document = JsonDocument.Parse(rawMetadata);
            var metadata = document.RootElement;

            var declared = ReadDeclaredArtifacts(metadata);

            // Every declared artefact is opened first; only then is anything hashed, so a refusal can never
            // leave a file that was checked but not held, or held but not checked.
            foreach (var artifact in declared)
            {
                cancellationToken.ThrowIfCancellationRequested();
                leases.Add(OpenPayload(root, artifact));
            }

            foreach (var lease in leases)
            {
                cancellationToken.ThrowIfCancellationRequested();
                VerifyPayload(root, lease, cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();

            // The generic contract stays the structural authority; it runs once, under the held leases.
            var validation = PackageReader.Validate(root, RequiredModel, InstallationTarget.Internal);

            // PackageReader has no cancellation of its own, so the token is observed immediately after it
            // returns: a cancelled capture may never continue to a snapshot.
            cancellationToken.ThrowIfCancellationRequested();

            if (!validation.IsValid)
            {
                throw new InvalidOperationException(
                    "The package no longer satisfies the internal installation contract: "
                    + string.Join("; ", validation.Reasons));
            }

            if (validation.TestOnly)
            {
                throw new InvalidOperationException(
                    "A test-only package cannot back a production internal install snapshot.");
            }

            if (!string.Equals(validation.ManifestFingerprint, requiredFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The package manifest changed between the held read and the contract check.");
            }

            var storage = validation.Storage
                ?? throw new InvalidOperationException("The validated package declares no storage.");

            var byRole = IndexByRole(leases);
            CheckPreparedRoles(byRole);
            RequireDeclaredFirmwareVersion(metadata, firmware);

            var seed = BuildSeed(metadata, byRole);
            var binding = BuildBinding(manifestFingerprint, storage, firmware, seed, leases);

            // A cancellation requested anywhere above is observed before the leases are handed over, so a
            // cancelled caller never receives a snapshot it cannot use.
            cancellationToken.ThrowIfCancellationRequested();

            var snapshot = new InternalInstallPackageSnapshot(
                manifestStream,
                leases,
                manifestFingerprint,
                binding,
                storage,
                firmware,
                seed);

            handedOver = true;
            return snapshot;
        }
        finally
        {
            if (!handedOver)
            {
                foreach (var lease in leases)
                {
                    lease.Stream.Dispose();
                }

                manifestStream?.Dispose();
            }
        }
    }

    private static string ResolvePackageRoot(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException("The imported package carries no package directory.");
        }

        if (!Directory.Exists(directory))
        {
            throw new InvalidOperationException($"The package directory does not exist: {directory}.");
        }

        var root = Path.GetFullPath(directory);
        if (IsReparsePoint(root, isDirectory: true))
        {
            throw new InvalidOperationException(
                $"The package directory is a symbolic link or reparse point: {directory}.");
        }

        return root;
    }

    // ---------------------------------------------------------------- declared artifacts

    private static List<DeclaredArtifact> ReadDeclaredArtifacts(JsonElement metadata)
    {
        if (!metadata.TryGetProperty("artifacts", out var artifactsElement)
            || artifactsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException($"The manifest does not declare an artifacts array.");
        }

        var artifacts = new List<DeclaredArtifact>();
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var element in artifactsElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException("An artifact declaration is not a JSON object.");
            }

            var role = ReadRequiredString(element, "role");
            var file = ReadRequiredString(element, "file");

            if (!element.TryGetProperty("bytes", out var bytesElement)
                || bytesElement.ValueKind != JsonValueKind.Number
                || !bytesElement.TryGetInt64(out var bytes)
                || bytes < 0)
            {
                throw new InvalidOperationException(
                    $"The artifact '{role}' does not declare a usable byte length.");
            }

            var sha256 = ReadRequiredString(element, "sha256");
            if (!IsSha256Hex(sha256))
            {
                throw new InvalidOperationException(
                    $"The artifact '{role}' does not declare a 64-hex SHA-256.");
            }

            if (!roles.Add(role))
            {
                throw new InvalidOperationException($"The manifest declares the artifact role '{role}' twice.");
            }

            if (!files.Add(file))
            {
                throw new InvalidOperationException($"The manifest declares the artifact file '{file}' twice.");
            }

            artifacts.Add(new DeclaredArtifact(role, file, bytes, sha256));
        }

        if (artifacts.Count == 0)
        {
            throw new InvalidOperationException("The manifest does not declare any artifact.");
        }

        return artifacts;
    }

    private static PayloadLease OpenPayload(string root, DeclaredArtifact artifact)
    {
        if (!TryResolveArtifactPath(root, artifact.RelativePath, out var fullPath))
        {
            throw new InvalidOperationException(
                $"The declared artifact path is not a safe relative path inside the package: {artifact.RelativePath}.");
        }

        if (!File.Exists(fullPath))
        {
            throw new InvalidOperationException(
                $"The declared artifact '{artifact.RelativePath}' is missing.");
        }

        if (IsReparsePoint(fullPath, isDirectory: false))
        {
            throw new InvalidOperationException(
                $"The declared artifact '{artifact.RelativePath}' is a symbolic link or reparse point.");
        }

        var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return new PayloadLease(artifact.Role, artifact.RelativePath, fullPath, artifact.Bytes, artifact.Sha256, stream);
    }

    private static void VerifyPayload(string root, PayloadLease lease, CancellationToken cancellationToken)
    {
        if (!TryResolveArtifactPath(root, lease.RelativePath, out var resolved)
            || !string.Equals(resolved, lease.FullPath, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The held artifact '{lease.RelativePath}' no longer resolves inside the package.");
        }

        if (!File.Exists(lease.FullPath) || IsReparsePoint(lease.FullPath, isDirectory: false))
        {
            throw new InvalidOperationException(
                $"The held artifact '{lease.RelativePath}' is no longer a regular file.");
        }

        if (lease.Stream.Length != lease.Length)
        {
            throw new InvalidOperationException(
                $"The artifact '{lease.Role}' is {lease.Stream.Length} bytes, but {lease.Length} were declared.");
        }

        var sha256 = HashStream(lease.Stream, cancellationToken);
        if (!string.Equals(sha256, lease.DeclaredSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The artifact '{lease.Role}' does not match its declared SHA-256.");
        }

        lease.Sha256 = sha256;
    }

    private static Dictionary<string, PayloadLease> IndexByRole(IReadOnlyList<PayloadLease> leases)
    {
        var byRole = new Dictionary<string, PayloadLease>(StringComparer.OrdinalIgnoreCase);
        foreach (var lease in leases)
        {
            byRole[lease.Role] = lease;
        }

        return byRole;
    }

    private static void CheckPreparedRoles(IReadOnlyDictionary<string, PayloadLease> byRole)
    {
        foreach (var role in PreparedRoles)
        {
            if (!byRole.TryGetValue(role, out var lease))
            {
                throw new InvalidOperationException($"The package does not carry the prepared role '{role}'.");
            }

            if (lease.Length <= 0)
            {
                throw new InvalidOperationException($"The prepared role '{role}' is empty.");
            }
        }

        var runtime = byRole["runtime"];
        if (runtime.Length != RuntimeBytes)
        {
            throw new InvalidOperationException(
                $"The runtime payload is {runtime.Length} bytes, but a prepared runtime is {RuntimeBytes} bytes.");
        }
    }

    // ---------------------------------------------------------------- firmware and binding

    /// <summary>
    /// Requires the manifest's <c>bootCompatibility.firmwareVersions</c> to name the observed DisplayId or
    /// the observed build fingerprint exactly. Neither is trimmed, and a substring or superstring never
    /// matches, so a manifest may not claim a nearby build.
    /// </summary>
    private static void RequireDeclaredFirmwareVersion(JsonElement metadata, FirmwareSnapshot firmware)
    {
        if (!metadata.TryGetProperty("bootCompatibility", out var boot)
            || boot.ValueKind != JsonValueKind.Object
            || !boot.TryGetProperty("firmwareVersions", out var versions)
            || versions.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The manifest does not declare bootCompatibility.firmwareVersions.");
        }

        foreach (var element in versions.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var declared = element.GetString();
            if (declared is null)
            {
                continue;
            }

            if (string.Equals(declared, firmware.DisplayId, StringComparison.Ordinal)
                || string.Equals(declared, firmware.BuildFingerprint, StringComparison.Ordinal))
            {
                return;
            }
        }

        throw new InvalidOperationException(
            "The manifest does not name the observed device build in bootCompatibility.firmwareVersions.");
    }

    private static RamInstallSeed BuildSeed(JsonElement metadata, IReadOnlyDictionary<string, PayloadLease> byRole)
    {
        var seed = byRole[SeedRole];

        if (!metadata.TryGetProperty("deployment", out var deployment)
            || deployment.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("The manifest does not declare a deployment object.");
        }

        return new RamInstallSeed(
            seed.Length,
            seed.Sha256.ToLowerInvariant(),
            ReadRequiredString(deployment, "commit"),
            ReadRequiredString(deployment, "manifestDigest"),
            ReadRequiredString(deployment, "origin"));
    }

    private static string BuildBinding(
        string manifestFingerprint,
        PackageStorage storage,
        FirmwareSnapshot firmware,
        RamInstallSeed seed,
        IReadOnlyList<PayloadLease> leases)
    {
        var firmwareFields = string.Join(
            ",",
            new[]
            {
                "\"displayId\":" + Quote(firmware.DisplayId),
                "\"buildFingerprint\":" + Quote(firmware.BuildFingerprint),
                "\"androidRelease\":" + Quote(firmware.AndroidRelease),
                "\"securityPatch\":" + Quote(firmware.SecurityPatch),
                "\"androidReportedBootloaderState\":" + Quote(firmware.AndroidReportedBootloaderState.ToString()),
            });

        var storageFields = string.Join(
            ",",
            new[]
            {
                "\"linuxBootBytes\":" + storage.LinuxBootBytes.ToString(CultureInfo.InvariantCulture),
                "\"systemRequiredBytes\":" + storage.SystemRequiredBytes.ToString(CultureInfo.InvariantCulture),
                "\"deploymentScratchBytes\":" + storage.DeploymentScratchBytes.ToString(CultureInfo.InvariantCulture),
                "\"minimumLinuxDataBytes\":" + storage.MinimumLinuxDataBytes.ToString(CultureInfo.InvariantCulture),
            });

        var seedFields = string.Join(
            ",",
            new[]
            {
                "\"length\":" + seed.Length.ToString(CultureInfo.InvariantCulture),
                "\"sha256\":" + Quote(seed.Sha256),
                "\"commit\":" + Quote(seed.Commit),
                "\"manifestDigest\":" + Quote(seed.ManifestDigest),
                "\"origin\":" + Quote(seed.Origin),
            });

        var payloads = string.Join(
            ",",
            leases
                .OrderBy(lease => lease.Role, StringComparer.Ordinal)
                .Select(
                    lease => "{"
                        + "\"role\":" + Quote(lease.Role) + ","
                        + "\"relativePath\":" + Quote(lease.RelativePath) + ","
                        + "\"length\":" + lease.Length.ToString(CultureInfo.InvariantCulture) + ","
                        + "\"sha256\":" + Quote(lease.Sha256.ToLowerInvariant())
                        + "}"));

        var canonical = "{"
            + "\"manifestFingerprint\":" + Quote(manifestFingerprint) + ","
            + "\"model\":" + Quote(RequiredModel) + ","
            + "\"firmware\":{" + firmwareFields + "},"
            + "\"storage\":{" + storageFields + "},"
            + "\"seed\":{" + seedFields + "},"
            + "\"payloads\":[" + payloads + "]"
            + "}";

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    // ---------------------------------------------------------------- selection and identity

    private static void RequireImportedPackage(ImportedPackage package)
    {
        var validation = package.Validation;
        if (validation is null || !validation.IsValid)
        {
            throw new InvalidOperationException(
                "The imported package did not validate; no snapshot can be bound to it.");
        }

        if (validation.TestOnly)
        {
            throw new InvalidOperationException("A test-only package cannot back an internal install snapshot.");
        }

        if (!IsSha256Hex(validation.ManifestFingerprint))
        {
            throw new InvalidOperationException(
                "The imported package does not carry a real manifest fingerprint.");
        }

        if (validation.Storage is null)
        {
            throw new InvalidOperationException("The imported package does not carry a storage declaration.");
        }

        if (!string.Equals(package.DeviceModel, RequiredModel, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The imported package was selected for '{package.DeviceModel}', not {RequiredModel}.");
        }
    }

    private static FirmwareSnapshot RequireObservedFirmware(DeviceIdentity identity)
    {
        if (!string.Equals(identity.Model, RequiredModel, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"An internal install snapshot requires model {RequiredModel}, got '{identity.Model}'.");
        }

        var firmware = identity.Firmware
            ?? throw new InvalidOperationException("The observed device identity carries no firmware snapshot.");

        RequireObservedField(firmware.DisplayId, "ro.build.display.id");
        RequireObservedField(firmware.BuildFingerprint, "ro.build.fingerprint");
        RequireObservedField(firmware.AndroidRelease, "ro.build.version.release");
        RequireObservedField(firmware.SecurityPatch, "ro.build.version.security_patch");

        // The supported profile is the only build this snapshot may bind to; nothing is inferred or fetched.
        if (!string.Equals(firmware.DisplayId, MaintenanceProfiles.AndroidBuild, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The observed build '{firmware.DisplayId}' is not the supported profile build "
                + $"'{MaintenanceProfiles.AndroidBuild}'.");
        }

        return firmware;
    }

    private static void RequireObservedField(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"The observed firmware carries no usable {name}.");
        }
    }

    // ---------------------------------------------------------------- small helpers

    private static string ReadRequiredString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException($"The manifest has no '{name}' string.");
        }

        var value = property.GetString()?.Trim() ?? string.Empty;
        if (value.Length == 0)
        {
            throw new InvalidOperationException($"The manifest has an empty '{name}' string.");
        }

        return value;
    }

    private static byte[] ReadAllBytes(FileStream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;

        if (stream.Length > int.MaxValue)
        {
            throw new InvalidOperationException("The package manifest is unreasonably large.");
        }

        var buffer = new byte[stream.Length];
        var offset = 0;
        while (offset < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new InvalidOperationException("The package manifest ended before its declared length.");
            }

            offset += read;
        }

        return buffer;
    }

    /// <summary>
    /// Full SHA-256 of the held stream, read synchronously in bounded chunks on the caller's background
    /// worker. Cancellation is observed before every read and before the digest is completed, and the
    /// stream position is always restored so the lease stays usable.
    /// </summary>
    private static string HashStream(FileStream stream, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[HashStreamBufferBytes];

        try
        {
            stream.Position = 0;

            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hash.AppendData(buffer, 0, read);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        finally
        {
            stream.Position = 0;
        }
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != Sha256HexLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static string Quote(string? value)
    {
        if (value is null)
        {
            return "null";
        }

        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');

        foreach (var character in value)
        {
            switch (character)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (character < '\u0020')
                    {
                        builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        builder.Append('"');
        return builder.ToString();
    }

    /// <summary>
    /// Resolves an artefact path inside <paramref name="root"/> with the exact rules of
    /// <see cref="PackageReader"/>: a trimmed relative path without a leading separator, drive letter,
    /// colon, empty segment, <c>.</c>/<c>..</c> segment or reparse-point component, which must still resolve
    /// beneath the package directory.
    /// </summary>
    private static bool TryResolveArtifactPath(string root, string relativePath, out string fullPath)
    {
        fullPath = string.Empty;

        var candidate = relativePath.Trim();
        if (candidate.Length == 0 || candidate.Contains('\0'))
        {
            return false;
        }

        if (candidate[0] == '/' || candidate[0] == '\\' || Path.IsPathRooted(candidate))
        {
            return false;
        }

        if (candidate.Contains(':'))
        {
            return false;
        }

        // Both separators are inspected so a Windows style path is rejected on Linux as well.
        var segments = candidate.Split(new[] { '/', '\\' }, StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (segment.Length == 0 || segment == "." || segment == "..")
            {
                return false;
            }
        }

        var current = root;
        for (var index = 0; index < segments.Length - 1; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (Directory.Exists(current) && IsReparsePoint(current, isDirectory: true))
            {
                return false;
            }
        }

        var resolved = Path.GetFullPath(Path.Combine(current, segments[^1]));
        var relative = Path.GetRelativePath(root, resolved);
        if (relative.Length == 0
            || relative == "."
            || Path.IsPathRooted(relative)
            || StartsWithParentSegment(relative))
        {
            return false;
        }

        fullPath = resolved;
        return true;
    }

    private static bool StartsWithParentSegment(string relative) =>
        relative == ".."
        || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
        || relative.StartsWith("../", StringComparison.Ordinal)
        || relative.StartsWith("..\\", StringComparison.Ordinal);

    private static bool IsReparsePoint(string path, bool isDirectory)
    {
        FileSystemInfo info = isDirectory ? new DirectoryInfo(path) : new FileInfo(path);
        if (!info.Exists)
        {
            return false;
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return true;
        }

        return info.LinkTarget is not null;
    }

    // ---------------------------------------------------------------- direct raw capture

    /// <summary>
    /// The direct capture body. It opens and keeps the manifest plus all seven source files, re-verifies
    /// their held length and SHA-256, asks the real reader for the typed contract under those held leases,
    /// validates the two prebuilt device trees, then expands the smaller gzip image first into one unique
    /// child directory of the caller's explicit parent. Any refusal releases every lease it opened and
    /// removes only that own child again.
    /// </summary>
    private static InternalInstallPackageSnapshot CaptureDirect(
        ImportedPackage package,
        string observedModel,
        FirmwareSnapshot firmware,
        string claimedFingerprint,
        PackageStorage claimedStorage,
        string expansionParent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(package.DeviceModel)
            || !string.Equals(package.DeviceModel, observedModel, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The imported package was selected for '{package.DeviceModel}', not the observed model "
                + $"'{observedModel}'.");
        }

        var parent = ResolveExpansionParent(expansionParent);
        var root = ResolvePackageRoot(package.PackageDirectory);
        var metadataPath = Path.Combine(root, MetadataFileName);

        if (!File.Exists(metadataPath))
        {
            throw new InvalidOperationException($"The package metadata {MetadataFileName} is missing.");
        }

        if (IsReparsePoint(metadataPath, isDirectory: false))
        {
            throw new InvalidOperationException(
                $"The package metadata {MetadataFileName} is a symbolic link or reparse point.");
        }

        FileStream? manifestStream = null;
        var leases = new List<PayloadLease>();
        var expanded = new List<DerivedLease>();
        string? child = null;
        var handedOver = false;

        try
        {
            // The metadata handle is opened and kept before anything is read, so the bytes that are parsed
            // and the bytes that stay locked for revalidation are the same file.
            manifestStream = new FileStream(metadataPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            var rawMetadata = ReadAllBytes(manifestStream, cancellationToken);
            var manifestFingerprint = Convert.ToHexString(SHA256.HashData(rawMetadata));

            if (!string.Equals(manifestFingerprint, claimedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The package manifest changed after import; the original manifest is no longer on disk.");
            }

            List<DeclaredArtifact> declared;
            using (var document = JsonDocument.Parse(rawMetadata))
            {
                declared = ReadDeclaredArtifacts(document.RootElement);
            }

            // Every declared source file is opened and kept first; only the held bytes are trusted later.
            foreach (var artifact in declared)
            {
                cancellationToken.ThrowIfCancellationRequested();
                leases.Add(OpenPayload(root, artifact));
            }

            foreach (var lease in leases)
            {
                cancellationToken.ThrowIfCancellationRequested();
                VerifyPayload(root, lease, cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();

            // The real reader stays the structural authority and re-reads the same package directory while
            // every source file and the manifest are still held here. A schema 1 package is refused there
            // and is never reinterpreted as direct raw.
            var contract = PackageReader.ReadEdlRawContract(root, observedModel, cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            if (contract.TestOnly)
            {
                throw new InvalidOperationException(
                    "A test-only package cannot back a production direct EDL raw capture.");
            }

            if (!string.Equals(
                    contract.ManifestFingerprint,
                    manifestFingerprint,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The package manifest changed between the held read and the direct contract check.");
            }

            if (!string.Equals(contract.DeviceModel, observedModel, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"The direct contract declares model '{contract.DeviceModel}', not the observed "
                    + $"'{observedModel}'.");
            }

            RequireSameStorage(claimedStorage, contract.Storage);
            RequireHeldDescriptors(contract, leases);
            RequireDirectFirmware(contract, firmware);

            var byRole = IndexByRole(leases);
            var normalEvidence = ValidateHeldDtb(
                RequireRole(byRole, DtbNormalRole),
                contract.BootRecipe.NormalBootArgs,
                EdlRawDtbKind.Normal,
                observedModel,
                cancellationToken);
            var diagnosticEvidence = ValidateHeldDtb(
                RequireRole(byRole, DtbDiagnosticRole),
                contract.BootRecipe.DiagnosticBootArgs,
                EdlRawDtbKind.Diagnostic,
                observedModel,
                cancellationToken);

            EnsureExpansionSpace(parent, contract.BootImage.ExpandedBytes, contract.RootImage.ExpandedBytes);

            cancellationToken.ThrowIfCancellationRequested();
            var childPath = CreateExpansionChild(parent);
            child = childPath;

            // Expanding the shorter declaration first lets a cheap mismatch refuse before the large image is
            // ever inflated, and each image is still expanded exactly once.
            var targets = new[]
                {
                    new ExpandedTarget(RequireRole(byRole, contract.RootImage.Artifact.Role), contract.RootImage),
                    new ExpandedTarget(RequireRole(byRole, contract.BootImage.Artifact.Role), contract.BootImage),
                }
                .OrderBy(target => target.Image.ExpandedBytes)
                .ToArray();

            var expandedByRole = new Dictionary<string, DerivedLease>(StringComparer.Ordinal);
            foreach (var target in targets)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var outputPath = Path.Combine(childPath, target.Image.Artifact.Role + ".img");
                var lease = ExpandGzipImage(target.Source, target.Image, outputPath, cancellationToken);
                expanded.Add(lease);
                expandedByRole.Add(target.Image.Artifact.Role, lease);

                VerifyExpandedFilesystem(lease, target.Image, contract.BootRecipe, cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();

            var bootImage = expandedByRole[contract.BootImage.Artifact.Role];
            var rootImage = expandedByRole[contract.RootImage.Artifact.Role];

            var binding = BuildDirectBinding(
                manifestFingerprint,
                observedModel,
                firmware,
                contract,
                leases,
                bootImage,
                rootImage,
                normalEvidence,
                diagnosticEvidence);

            cancellationToken.ThrowIfCancellationRequested();

            var snapshot = new InternalInstallPackageSnapshot(
                manifestStream,
                leases,
                expanded,
                parent,
                childPath,
                contract,
                new VerifiedEdlFile(bootImage.Path, bootImage.Length, bootImage.Sha256),
                new VerifiedEdlFile(rootImage.Path, rootImage.Length, rootImage.Sha256),
                manifestFingerprint,
                binding,
                firmware);

            handedOver = true;
            return snapshot;
        }
        finally
        {
            if (!handedOver)
            {
                foreach (var lease in leases)
                {
                    lease.Stream.Dispose();
                }

                foreach (var lease in expanded)
                {
                    lease.Stream.Dispose();
                }

                manifestStream?.Dispose();

                if (child is not null)
                {
                    TryDeleteOwnChild(parent, child);
                }
            }
        }
    }

    /// <summary>
    /// Resolves the caller's explicit expansion parent. It must already exist, must be an ordinary
    /// directory (not a reparse point) and is never replaced by a fallback such as a system temp directory.
    /// </summary>
    private static string ResolveExpansionParent(string expansionParent)
    {
        if (string.IsNullOrWhiteSpace(expansionParent) || expansionParent.Contains('\0'))
        {
            throw new InvalidOperationException(
                "The expansion parent must be an explicit, non-empty directory path.");
        }

        string parent;
        try
        {
            parent = Path.GetFullPath(expansionParent);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidOperationException(
                $"The expansion parent is not a usable path: {expansionParent}.",
                exception);
        }

        if (!Directory.Exists(parent))
        {
            throw new InvalidOperationException($"The expansion parent does not exist: {parent}.");
        }

        if (IsReparsePoint(parent, isDirectory: true))
        {
            throw new InvalidOperationException(
                $"The expansion parent is a symbolic link or reparse point: {parent}.");
        }

        return parent;
    }

    private static string CreateExpansionChild(string parent)
    {
        var child = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
        if (!PackageImporter.IsBeneath(child, parent))
        {
            throw new InvalidOperationException($"The expansion child would escape its parent: {child}.");
        }

        Directory.CreateDirectory(child);
        return child;
    }

    /// <summary>
    /// Refuses before any expansion when the explicit parent cannot be shown to hold enough room for the sum
    /// of the two actual expanded images. The check uses the volume the parent actually lives on (the Win32
    /// free-space API for the explicit path, including UNC, and the mounted volume on Unix).
    /// </summary>
    private static void EnsureExpansionSpace(string parent, long bootBytes, long rootBytes)
    {
        long required;
        try
        {
            required = checked(bootBytes + rootBytes);
        }
        catch (OverflowException)
        {
            throw new IOException("The declared expanded image sizes overflow the free-space arithmetic.");
        }

        var available = TryGetAvailableFreeBytes(parent);
        if (available is null)
        {
            throw new IOException(
                $"The free space of the expansion parent could not be determined: {parent}.");
        }

        if (required > available.Value)
        {
            throw new IOException(
                $"The expansion parent holds {available.Value} free bytes, but the expanded images need "
                + $"{required} bytes: {parent}.");
        }
    }

    /// <summary>
    /// The actual free bytes of the volume that holds <paramref name="path"/>, or null when the platform cannot
    /// report it. Shared with the direct preparation's checked evidence budget; the expansion validation above
    /// keeps using exactly the same fact.
    /// </summary>
    internal static long? TryGetAvailableFreeBytes(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return WindowsFreeBytes(path);
        }

        return UnixFreeBytes(path);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool GetDiskFreeSpaceExW(
        string directoryName,
        out ulong freeBytesAvailable,
        out ulong totalBytes,
        out ulong totalFreeBytes);

    private static long? WindowsFreeBytes(string path)
    {
        try
        {
            if (!Path.EndsInDirectorySeparator(path))
            {
                path += Path.DirectorySeparatorChar;
            }

            if (!GetDiskFreeSpaceExW(path, out var available, out _, out _))
            {
                return null;
            }

            return available > (ulong)long.MaxValue ? long.MaxValue : (long)available;
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Uses the actual mounted volume that holds <paramref name="path"/>, not a drive-letter guess.</summary>
    private static long? UnixFreeBytes(string path)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }

        long? best = null;
        var bestLength = -1;

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                var mountPoint = Path.TrimEndingDirectorySeparator(drive.RootDirectory.FullName);
                if (mountPoint.Length == 0
                    || mountPoint.Length <= bestLength
                    || !IsUnder(fullPath, mountPoint))
                {
                    continue;
                }

                if (!drive.IsReady)
                {
                    continue;
                }

                best = drive.AvailableFreeSpace;
                bestLength = mountPoint.Length;
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                continue;
            }
        }

        return best;
    }

    private static bool IsUnder(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative == "."
            || (!Path.IsPathRooted(relative) && !StartsWithParentSegment(relative));
    }

    /// <summary>Expands one gzip image exactly once with a bounded 1 MiB buffer and no whole-image array.</summary>
    private static DerivedLease ExpandGzipImage(
        PayloadLease source,
        EdlRawImage image,
        string outputPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var input = source.Stream;
        var compressedBytes = input.Length;

        if (compressedBytes < MinimumGzipFrameBytes)
        {
            throw new InvalidDataException(
                $"The compressed image '{source.Role}' is shorter than a complete gzip frame.");
        }

        if (!string.Equals(image.Compression, "gzip", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The raw image '{source.Role}' declares compression '{image.Compression}', not gzip.");
        }

        var header = new byte[3];
        try
        {
            input.Position = 0;
            input.ReadExactly(header);
        }
        finally
        {
            input.Position = 0;
        }

        if (header[0] != 0x1F || header[1] != 0x8B || header[2] != 0x08)
        {
            throw new InvalidDataException($"The compressed image '{source.Role}' is not a gzip member.");
        }

        var declared = image.ExpandedBytes;
        var buffer = new byte[ExpansionBufferBytes];
        var crc = Crc32Initial;
        long total = 0;
        string writtenSha;

        var output = new FileStream(
            outputPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            ExpansionBufferBytes,
            FileOptions.SequentialScan);

        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            try
            {
                using (var gzip = new GZipStream(input, CompressionMode.Decompress, leaveOpen: true))
                {
                    while (true)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var read = gzip.Read(buffer, 0, buffer.Length);
                        if (read == 0)
                        {
                            break;
                        }

                        // The declared expanded length is a hard bound, so an over-long stream stops here
                        // instead of being written to the end and compared afterwards.
                        if (read > declared - total)
                        {
                            throw new InvalidDataException(
                                $"The expanded image '{source.Role}' exceeds its declared {declared} bytes.");
                        }

                        total += read;
                        hash.AppendData(buffer, 0, read);
                        crc = AppendCrc32(crc, buffer.AsSpan(0, read));
                        output.Write(buffer, 0, read);
                    }
                }

                output.Flush(flushToDisk: true);
            }
            finally
            {
                output.Dispose();
                input.Position = 0;
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (total != declared)
            {
                throw new InvalidDataException(
                    $"The expanded image '{source.Role}' is {total} bytes, but {declared} were declared.");
            }

            writtenSha = Convert.ToHexString(hash.GetHashAndReset());
        }

        if (!string.Equals(writtenSha, image.ExpandedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The expanded image '{source.Role}' does not match its declared expandedSha256.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // GZipStream alone may accept a frame whose trailer is missing, so the real terminal is verified from
        // the held source: the last eight bytes must carry the CRC-32 of the expanded bytes and the ISIZE
        // modulo 2^32 of the full expanded length.
        var trailer = new byte[8];
        try
        {
            input.Position = compressedBytes - trailer.Length;
            input.ReadExactly(trailer);
        }
        finally
        {
            input.Position = 0;
        }

        var declaredCrc = BinaryPrimitives.ReadUInt32LittleEndian(trailer.AsSpan(0, 4));
        if (declaredCrc != (crc ^ Crc32Initial))
        {
            throw new InvalidDataException(
                $"The compressed image '{source.Role}' does not carry the CRC-32 of its expanded bytes.");
        }

        var declaredSize = BinaryPrimitives.ReadUInt32LittleEndian(trailer.AsSpan(4, 4));
        if (declaredSize != unchecked((uint)total))
        {
            throw new InvalidDataException(
                $"The compressed image '{source.Role}' does not carry its expanded length in the gzip trailer.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // The published output is re-read from a fresh Read/ShareRead lease: the digest that is exposed is
        // the digest of the bytes the final held handle sees, not of a buffer that was written earlier.
        var held = new FileStream(
            outputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            HashStreamBufferBytes,
            FileOptions.SequentialScan);

        var handedOver = false;
        try
        {
            var length = held.Length;
            if (length != declared)
            {
                throw new InvalidDataException(
                    $"The expanded image '{source.Role}' is {length} bytes on disk, but {declared} were expected.");
            }

            var heldSha = HashStream(held, cancellationToken);
            if (!string.Equals(heldSha, writtenSha, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(heldSha, image.ExpandedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The expanded image '{source.Role}' changed after it was written.");
            }

            var lease = new DerivedLease(outputPath, length, heldSha, held);
            handedOver = true;
            return lease;
        }
        finally
        {
            if (!handedOver)
            {
                held.Dispose();
            }
        }
    }

    private static void VerifyExpandedFilesystem(
        DerivedLease lease,
        EdlRawImage image,
        EdlRawBootRecipe recipe,
        CancellationToken cancellationToken)
    {
        if (string.Equals(image.FsType, "ext4", StringComparison.Ordinal))
        {
            VerifyExt4Superblock(lease, image, recipe.BootUuid, cancellationToken);
            return;
        }

        if (string.Equals(image.FsType, "btrfs", StringComparison.Ordinal))
        {
            VerifyBtrfsSuperblock(lease, image, recipe.RootUuid, cancellationToken);
            return;
        }

        throw new InvalidDataException(
            $"The expanded image '{image.Artifact.Role}' declares an unsupported fsType '{image.FsType}'.");
    }

    /// <summary>
    /// Reads the actual ext4 primary superblock at 1024 from the held expanded lease and delegates
    /// the magic, block count/size, total bytes and UUID checks to the shared validator.
    /// </summary>
    private static void VerifyExt4Superblock(
        DerivedLease lease,
        EdlRawImage image,
        Guid bootUuid,
        CancellationToken cancellationToken)
    {
        if (lease.Length < Ext4SuperblockOffset + Ext4SuperblockBytes)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' is too short to carry an ext4 superblock.");
        }

        var superblock = ReadAt(
            lease.Stream,
            Ext4SuperblockOffset,
            Ext4SuperblockBytes,
            cancellationToken);

        EdlRawFilesystemValidator.ValidateExt4(superblock, lease.Length, image, bootUuid);
    }

    /// <summary>
    /// Reads the actual Btrfs primary superblock at 65536 from the held expanded lease and
    /// delegates the magic, FSID, bytenr, total bytes, device count and sector size checks to
    /// the shared validator.
    /// </summary>
    private static void VerifyBtrfsSuperblock(
        DerivedLease lease,
        EdlRawImage image,
        Guid rootUuid,
        CancellationToken cancellationToken)
    {
        if (lease.Length < BtrfsSuperblockOffset + BtrfsSuperblockBytes)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' is too short to carry a Btrfs superblock.");
        }

        var superblock = ReadAt(
            lease.Stream,
            BtrfsSuperblockOffset,
            BtrfsSuperblockBytes,
            cancellationToken);

        EdlRawFilesystemValidator.ValidateBtrfs(superblock, lease.Length, image, rootUuid);
    }

    /// <summary>Bounded read of a small structural header from an already held lease.</summary>
    private static byte[] ReadAt(
        FileStream stream,
        long offset,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var position = stream.Position;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            stream.Position = offset;
            stream.ReadExactly(buffer);
        }
        finally
        {
            stream.Position = position;
        }

        return buffer;
    }

    private static uint[] BuildCrc32Table()
    {
        var table = new uint[256];

        for (var index = 0; index < table.Length; index++)
        {
            var value = (uint)index;
            for (var bit = 0; bit < 8; bit++)
            {
                value = (value & 1u) != 0 ? Crc32Polynomial ^ (value >> 1) : value >> 1;
            }

            table[index] = value;
        }

        return table;
    }

    private static uint AppendCrc32(uint crc, ReadOnlySpan<byte> bytes)
    {
        foreach (var value in bytes)
        {
            crc = Crc32Table[(int)((crc ^ value) & 0xFFu)] ^ (crc >> 8);
        }

        return crc;
    }

    /// <summary>
    /// Strictly removes this instance's own expansion child. The absolute child is proven to live beneath
    /// the absolute caller parent before anything is deleted, so the parent, its sentinel files, the package
    /// and any other caller data stay untouched.
    /// </summary>
    private static void DeleteOwnChild(string parent, string child)
    {
        if (!PackageImporter.IsBeneath(child, parent))
        {
            throw new IOException($"Refusing to delete an expansion directory outside its parent: {child}");
        }

        if (Directory.Exists(child))
        {
            Directory.Delete(child, recursive: true);
        }
    }

    private static void TryDeleteOwnChild(string parent, string child)
    {
        try
        {
            DeleteOwnChild(parent, child);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The refusal that triggered this cleanup stays the observable outcome of the capture.
        }
    }

    private static PackageValidationResult RequireDirectImportedPackage(
        ImportedPackage package,
        string observedModel)
    {
        var validation = package.Validation
            ?? throw new InvalidOperationException("The imported package carries no validation result.");

        if (!validation.IsValid)
        {
            throw new InvalidOperationException(
                "The imported package did not validate; no direct snapshot can be bound to it.");
        }

        if (validation.TestOnly)
        {
            throw new InvalidOperationException("A test-only package cannot back a production direct capture.");
        }

        if (!IsSha256Hex(validation.ManifestFingerprint))
        {
            throw new InvalidOperationException(
                "The imported package does not carry a real manifest fingerprint.");
        }

        if (validation.Storage is null)
        {
            throw new InvalidOperationException(
                "The imported package does not carry a storage declaration.");
        }

        if (string.IsNullOrWhiteSpace(package.DeviceModel) || package.DeviceModel.Contains('\0'))
        {
            throw new InvalidOperationException("The imported package carries no usable device model.");
        }

        if (!string.Equals(package.DeviceModel, observedModel, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The imported package was selected for '{package.DeviceModel}', not '{observedModel}'.");
        }

        return validation;
    }

    /// <summary>
    /// Requires the five observed firmware fields to be complete. This is deliberately parameterized: no
    /// pinned model, profile or build value is used, so the observed identity is the only source of truth.
    /// </summary>
    private static FirmwareSnapshot RequireDirectObservedFirmware(DeviceIdentity identity)
    {
        if (string.IsNullOrWhiteSpace(identity.Model) || identity.Model.Contains('\0'))
        {
            throw new InvalidOperationException("The observed device identity carries no usable model.");
        }

        var firmware = identity.Firmware
            ?? throw new InvalidOperationException(
                "The observed device identity carries no firmware snapshot.");

        RequireObservedField(firmware.DisplayId, "ro.build.display.id");
        RequireObservedField(firmware.BuildFingerprint, "ro.build.fingerprint");
        RequireObservedField(firmware.AndroidRelease, "ro.build.version.release");
        RequireObservedField(firmware.SecurityPatch, "ro.build.version.security_patch");

        return firmware;
    }

    /// <summary>
    /// Binds the observed build to the optional typed contract: a declared Android build must be the
    /// observed display id, and a non-empty firmware list must contain the observed display id or
    /// fingerprint. A common system package that declares neither adds no further firmware restriction;
    /// the actual model and the non-empty observed firmware fields stay mandatory elsewhere.
    /// </summary>
    private static void RequireDirectFirmware(
        EdlRawPackageContract contract,
        FirmwareSnapshot firmware)
    {
        var displayId = firmware.DisplayId ?? string.Empty;
        var buildFingerprint = firmware.BuildFingerprint ?? string.Empty;

        if (contract.AndroidBuild is { } declaredBuild
            && !string.Equals(displayId, declaredBuild, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The observed build '{displayId}' is not the declared direct build "
                + $"'{declaredBuild}'.");
        }

        if (contract.FirmwareVersions.Count > 0
            && !ContainsDeclaredVersion(contract.FirmwareVersions, displayId)
            && !ContainsDeclaredVersion(contract.FirmwareVersions, buildFingerprint))
        {
            throw new InvalidOperationException(
                "The direct contract declares firmware versions, but none matches the observed build "
                + "display id or fingerprint.");
        }
    }

    private static bool ContainsDeclaredVersion(IReadOnlyList<string> versions, string value)
    {
        foreach (var declared in versions)
        {
            if (string.Equals(declared, value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static void RequireSameStorage(PackageStorage claimed, PackageStorage declared)
    {
        if (claimed.LinuxBootBytes != declared.LinuxBootBytes
            || claimed.SystemRequiredBytes != declared.SystemRequiredBytes
            || claimed.DeploymentScratchBytes != declared.DeploymentScratchBytes
            || claimed.MinimumLinuxDataBytes != declared.MinimumLinuxDataBytes)
        {
            throw new InvalidOperationException(
                "The imported storage declaration no longer matches the direct package contract.");
        }
    }

    /// <summary>
    /// Compares every typed contract descriptor against the bytes actually held: the same seven roles, the
    /// same declared relative paths and the same observed length/full SHA-256. A path-only match is never
    /// accepted and no descriptor is copied from the manifest into the exposed facts.
    /// </summary>
    private static void RequireHeldDescriptors(
        EdlRawPackageContract contract,
        IReadOnlyList<PayloadLease> leases)
    {
        if (contract.Artifacts.Count != leases.Count)
        {
            throw new InvalidOperationException(
                $"The direct contract declares {contract.Artifacts.Count} artifacts, but {leases.Count} "
                + "source files were held.");
        }

        foreach (var lease in leases)
        {
            if (!contract.Artifacts.TryGetValue(lease.Role, out var artifact))
            {
                throw new InvalidOperationException(
                    $"The direct contract does not declare the held role '{lease.Role}'.");
            }

            if (!string.Equals(artifact.Role, lease.Role, StringComparison.Ordinal)
                || !string.Equals(artifact.RelativePath, lease.RelativePath, StringComparison.Ordinal)
                || artifact.Bytes != lease.Length
                || !string.Equals(artifact.Sha256, lease.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The direct contract declaration of '{lease.Role}' does not match the held bytes.");
            }
        }

        RequireImageDescriptor(contract.BootImage, leases);
        RequireImageDescriptor(contract.RootImage, leases);
    }

    private static void RequireImageDescriptor(EdlRawImage image, IReadOnlyList<PayloadLease> leases)
    {
        PayloadLease? match = null;
        foreach (var lease in leases)
        {
            if (string.Equals(lease.Role, image.Artifact.Role, StringComparison.Ordinal))
            {
                match = lease;
                break;
            }
        }

        if (match is null
            || image.CompressedBytes != match.Length
            || !string.Equals(image.CompressedSha256, match.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The direct contract image '{image.Artifact.Role}' does not match the held compressed bytes.");
        }
    }

    private static PayloadLease RequireRole(
        IReadOnlyDictionary<string, PayloadLease> byRole,
        string role)
    {
        if (!byRole.TryGetValue(role, out var lease))
        {
            throw new InvalidOperationException($"The package does not carry the direct role '{role}'.");
        }

        return lease;
    }

    /// <summary>
    /// Validates one held prebuilt device tree with the sole <see cref="EdlRawDtbValidator"/> and requires
    /// the returned evidence to describe exactly the held bytes.
    /// </summary>
    private static EdlRawDtbEvidence ValidateHeldDtb(
        PayloadLease lease,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string observedModel,
        CancellationToken cancellationToken)
    {
        if (lease.Length <= 0 || lease.Length > MaxDtbBytes)
        {
            throw new InvalidDataException(
                $"The held '{lease.Role}' is {lease.Length} bytes, which is not a plausible device tree.");
        }

        var bytes = ReadHeldPayload(lease.Stream, lease.Length, lease.Role, cancellationToken);

        EdlRawDtbEvidence evidence;
        try
        {
            evidence = EdlRawDtbValidator.Validate(bytes, expectedBootArgs, kind, observedModel);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                $"The held '{lease.Role}' cannot be validated for model '{observedModel}': "
                + exception.Message,
                exception);
        }

        if (evidence.Length != lease.Length
            || !string.Equals(evidence.Sha256, lease.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The validated '{lease.Role}' evidence does not describe the held bytes.");
        }

        if (!string.Equals(evidence.DeviceModel, observedModel, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The validated '{lease.Role}' evidence names another model.");
        }

        return evidence;
    }

    private static byte[] ReadHeldPayload(
        FileStream stream,
        long length,
        string role,
        CancellationToken cancellationToken)
    {
        if (length <= 0 || length > int.MaxValue)
        {
            throw new InvalidDataException($"The held '{role}' is too large for one bounded inspection.");
        }

        if (stream.Length != length)
        {
            throw new InvalidDataException($"The held '{role}' no longer has its verified length.");
        }

        var buffer = new byte[(int)length];
        var offset = 0;

        try
        {
            stream.Position = 0;

            while (offset < buffer.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var read = stream.Read(buffer, offset, buffer.Length - offset);
                if (read <= 0)
                {
                    throw new InvalidDataException($"The held '{role}' ended before its verified length.");
                }

                offset += read;
            }
        }
        finally
        {
            stream.Position = 0;
        }

        return buffer;
    }

    /// <summary>
    /// Deterministic canonical binding of a direct capture: the held manifest fingerprint, the actual model
    /// and five firmware fields, storage, all seven source role/path/length/full-hash entries, both actual
    /// expanded filesystem facts, both validated device trees, the boot recipe and the deployment
    /// declarations. No physical expansion path is bound, so the same package relocated keeps one identity.
    /// </summary>
    private static string BuildDirectBinding(
        string manifestFingerprint,
        string observedModel,
        FirmwareSnapshot firmware,
        EdlRawPackageContract contract,
        IReadOnlyList<PayloadLease> leases,
        DerivedLease bootImage,
        DerivedLease rootImage,
        EdlRawDtbEvidence normalDtb,
        EdlRawDtbEvidence diagnosticDtb)
    {
        var firmwareFields = string.Join(
            ",",
            new[]
            {
                "\"displayId\":" + Quote(firmware.DisplayId),
                "\"buildFingerprint\":" + Quote(firmware.BuildFingerprint),
                "\"androidRelease\":" + Quote(firmware.AndroidRelease),
                "\"securityPatch\":" + Quote(firmware.SecurityPatch),
                "\"androidReportedBootloaderState\":" + Quote(firmware.AndroidReportedBootloaderState.ToString()),
            });

        var payloadFields = string.Join(
            ",",
            leases
                .OrderBy(lease => lease.Role, StringComparer.Ordinal)
                .Select(
                    lease => "{"
                        + "\"role\":" + Quote(lease.Role) + ","
                        + "\"relativePath\":" + Quote(lease.RelativePath) + ","
                        + "\"length\":" + lease.Length.ToString(CultureInfo.InvariantCulture) + ","
                        + "\"sha256\":" + Quote(lease.Sha256.ToLowerInvariant())
                        + "}"));

        var expandedFields = string.Join(
            ",",
            new[]
            {
                ExpandedBinding(contract.BootImage, bootImage),
                ExpandedBinding(contract.RootImage, rootImage),
            });

        var dtbFields = string.Join(",", new[] { DtbBinding(normalDtb), DtbBinding(diagnosticDtb) });

        var recipeFields = string.Join(
            ",",
            new[]
            {
                "\"bootUuid\":" + Quote(contract.BootRecipe.BootUuid.ToString("D")),
                "\"rootUuid\":" + Quote(contract.BootRecipe.RootUuid.ToString("D")),
                "\"normalBootArgs\":" + Quote(contract.BootRecipe.NormalBootArgs),
                "\"diagnosticBootArgs\":" + Quote(contract.BootRecipe.DiagnosticBootArgs),
                "\"defaultEntry\":" + Quote(contract.BootRecipe.DefaultEntry),
            });

        var deploymentFields = string.Join(
            ",",
            new[]
            {
                "\"kind\":" + Quote(contract.Deployment.Kind),
                "\"commit\":" + Quote(contract.Deployment.Commit),
                "\"manifestDigest\":" + Quote(contract.Deployment.ManifestDigest),
                "\"origin\":" + Quote(contract.Deployment.Origin),
                "\"bootChecksum\":" + Quote(contract.Deployment.BootChecksum),
            });

        var canonical = "{"
            + "\"manifestFingerprint\":" + Quote(manifestFingerprint) + ","
            + "\"model\":" + Quote(observedModel) + ","
            + "\"firmware\":{" + firmwareFields + "},"
            + "\"storage\":{" + DirectStorageFields(contract.Storage) + "},"
            + "\"payloads\":[" + payloadFields + "],"
            + "\"expanded\":[" + expandedFields + "],"
            + "\"dtb\":[" + dtbFields + "],"
            + "\"bootRecipe\":{" + recipeFields + "},"
            + "\"deployment\":{" + deploymentFields + "}"
            + "}";

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string DirectStorageFields(PackageStorage storage) =>
        string.Join(
            ",",
            new[]
            {
                "\"linuxBootBytes\":" + storage.LinuxBootBytes.ToString(CultureInfo.InvariantCulture),
                "\"systemRequiredBytes\":" + storage.SystemRequiredBytes.ToString(CultureInfo.InvariantCulture),
                "\"deploymentScratchBytes\":" + storage.DeploymentScratchBytes.ToString(CultureInfo.InvariantCulture),
                "\"minimumLinuxDataBytes\":" + storage.MinimumLinuxDataBytes.ToString(CultureInfo.InvariantCulture),
            });

    private static string ExpandedBinding(EdlRawImage image, DerivedLease lease) =>
        "{"
        + "\"role\":" + Quote(image.Artifact.Role) + ","
        + "\"fsType\":" + Quote(image.FsType) + ","
        + "\"fsUuid\":" + Quote(image.FsUuid.ToString("D")) + ","
        + "\"length\":" + lease.Length.ToString(CultureInfo.InvariantCulture) + ","
        + "\"sha256\":" + Quote(lease.Sha256.ToLowerInvariant())
        + "}";

    private static string DtbBinding(EdlRawDtbEvidence evidence) =>
        "{"
        + "\"kind\":" + Quote(evidence.Kind.ToString()) + ","
        + "\"length\":" + evidence.Length.ToString(CultureInfo.InvariantCulture) + ","
        + "\"sha256\":" + Quote(evidence.Sha256) + ","
        + "\"bootArgs\":" + Quote(evidence.BootArgs) + ","
        + "\"bootStage\":" + Quote(evidence.BootStage) + ","
        + "\"rootMedium\":" + Quote(evidence.RootMedium) + ","
        + "\"initrdEntryIndex\":" + evidence.InitrdEntryIndex.ToString(CultureInfo.InvariantCulture) + ","
        + "\"compatible\":[" + string.Join(",", evidence.Compatible.Select(Quote)) + "]"
        + "}";

    private readonly record struct ExpandedTarget(PayloadLease Source, EdlRawImage Image);

    private sealed record DeclaredArtifact(string Role, string RelativePath, long Bytes, string Sha256);

    /// <summary>One declared artefact and the read lease this snapshot opened for it.</summary>
    private sealed class PayloadLease
    {
        internal PayloadLease(
            string role,
            string relativePath,
            string fullPath,
            long length,
            string declaredSha256,
            FileStream stream)
        {
            Role = role;
            RelativePath = relativePath;
            FullPath = fullPath;
            Length = length;
            DeclaredSha256 = declaredSha256;
            Stream = stream;
            Sha256 = string.Empty;
        }

        internal string Role { get; }

        internal string RelativePath { get; }

        internal string FullPath { get; }

        /// <summary>Declared length, rechecked against the held stream before it is exposed.</summary>
        internal long Length { get; }

        internal string DeclaredSha256 { get; }

        internal FileStream Stream { get; }

        /// <summary>Full digest computed from the held stream; set before the lease is published.</summary>
        internal string Sha256 { get; set; }
    }

    /// <summary>
    /// One expanded raw image this direct snapshot created and now owns: its actual absolute path, the
    /// verified expanded length, the whole SHA-256 observed through the held read lease and that lease.
    /// </summary>
    private sealed class DerivedLease
    {
        internal DerivedLease(string path, long length, string sha256, FileStream stream)
        {
            Path = path;
            Length = length;
            Sha256 = sha256;
            Stream = stream;
        }

        internal string Path { get; }

        internal long Length { get; }

        internal string Sha256 { get; }

        internal FileStream Stream { get; }
    }
}
