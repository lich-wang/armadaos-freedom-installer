using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The pinned inputs one internal install needs: the new maintenance boot image, the caller-supplied
/// install-support archive and the maintenance toolbox bundle the backend may read later.
/// </summary>
/// <remarks>
/// A caller claim is evidence to verify, never authority: both claims must name the exact compiled
/// maintenance-boot and install-support pins before any bundle is touched, and the bytes that are read
/// afterwards must still match those pins. Nothing here reports readiness, and no public switch can
/// relax a pin.
/// <para>
/// Loading opens its own read-only <see cref="FileShare.Read"/> leases for the boot image, the support
/// archive and the toolbox payload, keeps them until <see cref="Dispose"/> and never takes ownership of
/// the caller's bundle. <see cref="Dispose"/> releases only those three handles: it never disposes the
/// caller's bundle, never deletes a source file and never touches a device.
/// </para>
/// </remarks>
public sealed class InternalInstallAssets : IDisposable
{
    /// <summary>Stable refusal identity for every compiled-pin or held-bytes mismatch.</summary>
    private const string PinMismatchCode = "install-asset-pin-mismatch";

    private const int HashBufferBytes = 81920;

    private const int Sha256HexLength = 64;

    /// <summary>Compiled new maintenance boot pin. This is never the old maintenance-profile boot.</summary>
    private const long MaintenanceBootBytes = 100663296L;

    private const string MaintenanceBootSha256 =
        "14d306d9f85e980b38aa9453eff3ed3f708f3f516fd210ef0f98d77784bc9c7c";

    /// <summary>Compiled install-support archive pin.</summary>
    private const long SupportArchiveBytes = 2883836L;

    private const string SupportArchiveSha256 =
        "ae2fdeeffb6e5e2488d54e7869ef3f68ddc9fdac57dbe398c07300e767d0d3d0";

    private readonly PinnedToolboxView _toolbox;

    private readonly FileStream _bootStream;

    private readonly FileStream _supportStream;

    private readonly FileStream _toolboxStream;

    private int _disposed;

    /// <summary>
    /// Private constructor: an instance only exists after every pinned byte was verified and the three
    /// own leases were opened.
    /// </summary>
    private InternalInstallAssets(
        VerifiedEdlFile maintenanceBoot,
        VerifiedEdlFile supportArchive,
        PinnedToolboxView toolboxBundle,
        FileStream bootStream,
        FileStream supportStream,
        FileStream toolboxStream)
    {
        MaintenanceBoot = maintenanceBoot;
        SupportArchive = supportArchive;

        _toolbox = toolboxBundle;
        _bootStream = bootStream;
        _supportStream = supportStream;
        _toolboxStream = toolboxStream;
    }

    /// <summary>The separately pinned new maintenance boot image. Never the old maintenance-profile boot.</summary>
    public VerifiedEdlFile MaintenanceBoot { get; }

    /// <summary>The caller-supplied install-support archive, verified against the compiled support pin.</summary>
    public VerifiedEdlFile SupportArchive { get; }

    /// <summary>
    /// The toolbox-only view over the verified bundle: metadata for all five reviewed roles and a fresh
    /// read-only stream for the toolbox payload only. It owns no stream and never outlives its bytes.
    /// </summary>
    public IMaintenanceBundle ToolboxBundle => _toolbox;

    /// <summary>True once this instance's own leases have been released.</summary>
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Verifies the caller's two claims against the compiled pins, validates the bundle metadata and
    /// opens independent read leases for the new boot image, the support archive and the toolbox.
    /// </summary>
    /// <remarks>
    /// The argument, cancellation and claim-pin guards are cheap and stay on the caller's thread; the
    /// bundle inspection and the whole-length hashes of multi-hundred-megabyte files run on the thread
    /// pool so a UI caller is never blocked before the task is returned.
    /// </remarks>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="OperationCanceledException">The token is already cancelled.</exception>
    /// <exception cref="InvalidOperationException">A claim, the bundle metadata or the held bytes do not
    /// match the compiled pins; the message carries <c>install-asset-pin-mismatch</c>.</exception>
    public static Task<InternalInstallAssets> LoadAsync(
        VerifiedEdlFile maintenanceBoot,
        VerifiedEdlFile supportArchive,
        IMaintenanceBundle toolboxBundle,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(maintenanceBoot);
        ArgumentNullException.ThrowIfNull(supportArchive);
        ArgumentNullException.ThrowIfNull(toolboxBundle);

        cancellationToken.ThrowIfCancellationRequested();

        RequirePinnedClaim(maintenanceBoot, MaintenanceBootBytes, MaintenanceBootSha256, "maintenance boot claim");
        RequirePinnedClaim(supportArchive, SupportArchiveBytes, SupportArchiveSha256, "install support claim");

        return Task.Run(
            () => Load(maintenanceBoot, supportArchive, toolboxBundle, cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Reopens an independent set of own leases for the backend. The returned instance shares neither the
    /// disposed flag nor a handle with this one and still refuses if its bytes changed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal Task<InternalInstallAssets> AcquireAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        // The private view reopens the already verified toolbox path, so a disposed caller bundle is irrelevant.
        return LoadAsync(MaintenanceBoot, SupportArchive, _toolbox, cancellationToken);
    }

    /// <summary>
    /// Rechecks the whole length and SHA-256 of every held stream against the compiled pins.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <exception cref="InvalidOperationException">A held file no longer matches its compiled pin.</exception>
    internal Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return Task.Run(() => Revalidate(cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Releases only the three read leases this instance owns. It never disposes the caller's bundle,
    /// never deletes a file and is safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _bootStream.Dispose();
        _supportStream.Dispose();
        _toolboxStream.Dispose();
    }

    // ---------------------------------------------------------------- load body

    private static InternalInstallAssets Load(
        VerifiedEdlFile maintenanceBoot,
        VerifiedEdlFile supportArchive,
        IMaintenanceBundle toolboxBundle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // The claims are checked again on the worker so the guard and the read cannot diverge.
        RequirePinnedClaim(maintenanceBoot, MaintenanceBootBytes, MaintenanceBootSha256, "maintenance boot claim");
        RequirePinnedClaim(supportArchive, SupportArchiveBytes, SupportArchiveSha256, "install support claim");

        // Metadata first, then the large payloads: the old boot role and the other three roles are never opened.
        var assets = ValidateBundleMetadata(toolboxBundle);

        cancellationToken.ThrowIfCancellationRequested();

        FileStream? bootStream = null;
        FileStream? supportStream = null;
        FileStream? toolboxStream = null;
        try
        {
            // Both files are opened before either is hashed, so a refusal can never leave a checked file unheld.
            bootStream = OpenRegularRead(maintenanceBoot.Path, "maintenance boot");
            supportStream = OpenRegularRead(supportArchive.Path, "install support");

            VerifyHeld(bootStream, MaintenanceBootBytes, MaintenanceBootSha256, "maintenance boot", cancellationToken);
            VerifyHeld(supportStream, SupportArchiveBytes, SupportArchiveSha256, "install support", cancellationToken);

            var toolbox = OpenPinnedToolbox(toolboxBundle, assets, cancellationToken, out toolboxStream);

            cancellationToken.ThrowIfCancellationRequested();

            var loaded = new InternalInstallAssets(
                new VerifiedEdlFile(Path.GetFullPath(maintenanceBoot.Path), MaintenanceBootBytes, MaintenanceBootSha256),
                new VerifiedEdlFile(Path.GetFullPath(supportArchive.Path), SupportArchiveBytes, SupportArchiveSha256),
                toolbox,
                bootStream,
                supportStream,
                toolboxStream!);

            bootStream = null;
            supportStream = null;
            toolboxStream = null;
            return loaded;
        }
        finally
        {
            bootStream?.Dispose();
            supportStream?.Dispose();
            toolboxStream?.Dispose();
        }
    }

    private void Revalidate(CancellationToken cancellationToken)
    {
        // The instance may have been disposed between the caller's guard and this worker starting.
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        VerifyHeld(_bootStream, MaintenanceBootBytes, MaintenanceBootSha256, "maintenance boot", cancellationToken);
        VerifyHeld(_supportStream, SupportArchiveBytes, SupportArchiveSha256, "install support", cancellationToken);
        VerifyHeld(_toolboxStream, MaintenanceProfiles.ToolboxBytes, MaintenanceProfiles.ToolboxSha256, "toolbox", cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
    }

    // ---------------------------------------------------------------- bundle metadata

    /// <summary>
    /// Repeats <see cref="MaintenanceBootstrap"/>'s bundle validation: the exact known profile, all five
    /// required roles with an exact role key, a positive length and a 64-hex digest, the old boot pin and
    /// the toolbox pin. The other three roles only have to carry valid metadata. Nothing is opened.
    /// </summary>
    private static Dictionary<string, MaintenanceAsset> ValidateBundleMetadata(IMaintenanceBundle bundle)
    {
        if (!Equals(bundle.Profile, MaintenanceProfiles.KnownProfile))
        {
            throw PinMismatch("bundle profile");
        }

        var assets = new Dictionary<string, MaintenanceAsset>(StringComparer.Ordinal);
        foreach (var role in MaintenanceProfiles.RequiredRoles)
        {
            var asset = bundle.GetAsset(role);
            if (asset is null || !string.Equals(asset.Role, role, StringComparison.Ordinal))
            {
                throw PinMismatch("bundle metadata role");
            }

            if (asset.Bytes <= 0 || !IsSha256Hex(asset.Sha256))
            {
                throw PinMismatch("bundle metadata digest");
            }

            assets.Add(role, asset);
        }

        var oldBoot = assets[MaintenanceProfiles.BootRole];
        if (oldBoot.Bytes != MaintenanceProfiles.BootBytes ||
            !ShaEquals(oldBoot.Sha256, MaintenanceProfiles.BootSha256))
        {
            throw PinMismatch("maintenance profile boot metadata");
        }

        var toolbox = assets[MaintenanceProfiles.ToolboxRole];
        if (toolbox.Bytes != MaintenanceProfiles.ToolboxBytes ||
            !ShaEquals(toolbox.Sha256, MaintenanceProfiles.ToolboxSha256))
        {
            throw PinMismatch("toolbox metadata");
        }

        return assets;
    }

    // ---------------------------------------------------------------- toolbox

    /// <summary>
    /// Opens only the toolbox role through the caller's bundle, proves the returned stream is a real,
    /// readable, seekable <see cref="FileStream"/> over a non-reparse regular file, opens a new independent
    /// read lease at that exact name and only then releases the temporary stream. The caller's bundle is
    /// never disposed. The returned view holds no stream of its own.
    /// </summary>
    private static PinnedToolboxView OpenPinnedToolbox(
        IMaintenanceBundle bundle,
        IReadOnlyDictionary<string, MaintenanceAsset> assets,
        CancellationToken cancellationToken,
        out FileStream? toolboxStream)
    {
        toolboxStream = null;

        Stream? temporary = null;
        try
        {
            temporary = bundle.OpenAsset(MaintenanceProfiles.ToolboxRole);

            if (temporary is not FileStream provided || !provided.CanRead || !provided.CanSeek)
            {
                throw PinMismatch("toolbox stream");
            }

            var toolboxPath = RequireRegularPath(provided.Name, "toolbox");
            cancellationToken.ThrowIfCancellationRequested();

            var own = OpenRegularRead(toolboxPath, "toolbox");

            // The independent lease exists; the temporary caller-provided stream can be released now.
            temporary.Dispose();
            temporary = null;

            try
            {
                VerifyHeld(
                    own,
                    MaintenanceProfiles.ToolboxBytes,
                    MaintenanceProfiles.ToolboxSha256,
                    "toolbox",
                    cancellationToken);

                toolboxStream = own;
                return new PinnedToolboxView(assets, bundle.Profile, toolboxPath);
            }
            catch
            {
                own.Dispose();
                throw;
            }
        }
        finally
        {
            temporary?.Dispose();
        }
    }

    // ---------------------------------------------------------------- file access

    private static FileStream OpenRegularRead(string? path, string subject)
    {
        var fullPath = RequireRegularPath(path, subject);

        try
        {
            return new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                HashBufferBytes,
                FileOptions.SequentialScan);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw PinMismatch(subject);
        }
    }

    private static string RequireRegularPath(string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw PinMismatch(subject);
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw PinMismatch(subject);
        }

        if (!IsRegularFile(fullPath))
        {
            throw PinMismatch(subject);
        }

        return fullPath;
    }

    /// <summary>
    /// True only for an existing regular file whose own entry and containing directory are not reparse
    /// points. A missing, unreadable or linked path is never treated as a usable asset.
    /// </summary>
    private static bool IsRegularFile(string fullPath)
    {
        try
        {
            var file = new FileInfo(fullPath);
            if (!file.Exists || IsReparsePoint(file))
            {
                return false;
            }

            var directory = file.Directory;
            if (directory is not null && (IsReparsePoint(directory)))
            {
                return false;
            }

            return true;
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsReparsePoint(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null;

    // ---------------------------------------------------------------- hashing

    /// <summary>
    /// Requires the held stream's whole length and SHA-256 to equal the compiled pin. The position is
    /// always restored, and cancellation is observed before every chunk and before the digest is finished.
    /// </summary>
    private static void VerifyHeld(
        FileStream stream,
        long expectedBytes,
        string expectedSha256,
        string subject,
        CancellationToken cancellationToken)
    {
        if (stream.Length != expectedBytes)
        {
            throw PinMismatch(subject);
        }

        if (!string.Equals(HashHeld(stream, cancellationToken), expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw PinMismatch(subject);
        }
    }

    private static string HashHeld(FileStream stream, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(HashBufferBytes);
        try
        {
            stream.Position = 0;

            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int read;
            while ((read = stream.Read(buffer, 0, HashBufferBytes)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hasher.AppendData(buffer, 0, read);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        }
        finally
        {
            stream.Position = 0;
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ---------------------------------------------------------------- claims and small helpers

    private static void RequirePinnedClaim(VerifiedEdlFile claim, long bytes, string sha256, string subject)
    {
        if (claim.Length != bytes ||
            !IsSha256Hex(claim.Sha256) ||
            !string.Equals(claim.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw PinMismatch(subject);
        }
    }

    private static bool ShaEquals(string? actual, string expected) =>
        actual is not null && string.Equals(actual, expected, StringComparison.Ordinal);

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

    private static InvalidOperationException PinMismatch(string subject) =>
        new(PinMismatchCode + ": the " + subject + " does not match the compiled install asset pin.");

    /// <summary>
    /// Toolbox-only view over the verified bundle. It copies the profile and all five metadata records,
    /// reopens a fresh read lease only for the toolbox payload and rejects every other role, so the old
    /// boot can never be opened through it. It owns no stream, so disposing it is a no-op.
    /// </summary>
    private sealed class PinnedToolboxView : IMaintenanceBundle
    {
        private readonly IReadOnlyDictionary<string, MaintenanceAsset> _assets;

        private readonly MaintenanceProfile _profile;

        private readonly string _toolboxPath;

        internal PinnedToolboxView(
            IReadOnlyDictionary<string, MaintenanceAsset> assets,
            MaintenanceProfile profile,
            string toolboxPath)
        {
            // Every metadata record and the profile are copied, so nothing the caller's bundle still holds
            // can be observed through this view later.
            var copy = new Dictionary<string, MaintenanceAsset>(assets.Count, StringComparer.Ordinal);
            foreach (var pair in assets)
            {
                copy.Add(pair.Key, pair.Value);
            }

            _assets = copy;
            _profile = new MaintenanceProfile(profile.ProfileId, profile.Model, profile.AndroidBuild, profile.Soc);
            _toolboxPath = toolboxPath;
        }

        public MaintenanceProfile Profile => _profile;

        public MaintenanceAsset GetAsset(string role)
        {
            ArgumentException.ThrowIfNullOrEmpty(role);

            if (!_assets.TryGetValue(role, out var asset))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    $"The pinned toolbox view does not carry the '{role}' asset.");
            }

            return asset;
        }

        public Stream OpenAsset(string role)
        {
            ArgumentException.ThrowIfNullOrEmpty(role);

            if (!string.Equals(role, MaintenanceProfiles.ToolboxRole, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    "Only the verified toolbox payload is available from this view.");
            }

            return new FileStream(
                _toolboxPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                HashBufferBytes,
                FileOptions.SequentialScan);
        }

        public void Dispose()
        {
            // The view holds no stream of its own; the owning instance keeps the leases.
        }
    }
}
