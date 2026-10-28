using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GptRewrite = FreedomInstaller.Core.InternalInstallArtifacts.GptRewrite;
using GptWriteDescriptor = FreedomInstaller.Core.InternalInstallArtifacts.GptWriteDescriptor;
using NewPartition = FreedomInstaller.Core.InternalInstallArtifacts.NewPartition;

namespace FreedomInstaller.Core;

/// <summary>
/// The single-use, verified preparation state of one internal install.
/// <para>
/// A context only ever comes out of <see cref="InternalInstallBackend.CreatePreparedAsync"/>. It owns the read
/// leases it opened itself - the package snapshot, its own asset acquisition, every captured backup file, every
/// prepared artifact, every fresh evidence read and the confirmation record - and nothing else. The caller's
/// package, backup set, artifact set, asset instance, client, toolchain and services stay the caller's, are never
/// disposed here and are never mutated.
/// </para>
/// <para>
/// Every getter is a fact derived from bytes this context proved: a caller claim is evidence to re-verify, never
/// authority. <see cref="RevalidateLocalAsync"/> re-hashes every held local claim, and the two device methods
/// capture real warm EDL reads into new evidence files before comparing them with the same claims.
/// </para>
/// </summary>
internal sealed partial class InternalInstallPreparationContext : IDisposable
{
    private const long Gib = 1L << 30;
    private const long TwoMiB = 2L * 1024L * 1024L;
    private const int Sha256HexLength = 64;
    private const int HashBufferBytes = 81920;
    private const int GptCaptureSectors = 64;
    private const int MaximumManifestBytes = 8 * 1024 * 1024;
    private const long BoardArchiveBytes = 2L << 30;
    private const int BoardArchiveHeaderBytes = 65536;
    private const int Arm64MinimumBytes = 64;
    private const long Arm64BranchMaxOffset = 134217728L;
    private const long ManifestUpperBoundBytes = 580L;

    // Exact production FDT overhead: a new chosen node (16 bytes), the four name strings (65 bytes), the four
    // property headers (48 bytes) and the aligned property data. The command lines behind that data are 465 bytes
    // (12 base arguments + root= + rw + boot= + rootflags= + the 96 byte deploy pointer) and 484 bytes when the
    // read-only diagnostic adds " rd.break=pre-mount".
    private const long NewChosenBytes = 16L;
    private const long PropertyNameBytes = 65L;
    private const long PropertyHeaderBytes = 48L;
    private const long NormalFdtDataBytes = 488L;
    private const long DiagnosticFdtDataBytes = 516L;

    private const string RequiredModel = "TB322FC";
    private const string PackageFingerprintPin =
        "0424D61B0B545CAC4B76F089BF294CE5BF0B01911CB655A8D64754ABE22188B7";
    private const string SeedCommitPin =
        "2d4a7bed46110cf5c50e9bfaa3a294aa5e260c9d106f6ca8b8a0bb325afbc54c";
    private const string SeedManifestDigestPin =
        "sha256:af569f306a86a246fac51370e2dc8d54b514e1c06b484dee33d3db02dce108c1";
    private const string SeedOriginPin =
        "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:testing";

    private const string InstallationRecordKind = "armada-internal-install";
    private const string SummaryManifestKind = "armada-install-artifacts";
    private const string RecoveryManifestKind = "armada-board-recovery";
    private const string RecoveryManifestFileName = "armada-recovery-manifest.json";
    private const string RecoveryOffsetSpace = "uncompressed-tar";
    private const string BoardFormat = "armada-gzip-ustar-v2";
    private static bool SupportedBoardFormat(string format) =>
        format == BoardFormat || format == BootSettingsRegion.Format;

    private static readonly (string Role, long Bytes, string Sha256)[] PayloadPins =
    {
        ("ostree-seed", 6625244322L,
            "21c8e7274d05922d4df56564f3ce6ba01777cc30d4e96c75d58ae8f274192244"),
        ("kernel", 78469632L,
            "0643698b4c5c692b8fc45560ee3f635af11c9ff16f567ac48e268a3827eb4292"),
        ("dtb", 142132L,
            "6101266c0a9ba6a03de527a0cc1d51ce6c7a3ffdaaaa043a3f2f483ec382cce4"),
        ("runtime", 4194304L,
            "cf75cfb699e69a2ba586cbdfa2032f38ff69d2bb477ca50d813825ed828352fe"),
        ("initramfs", 51282244L,
            "2e80c27b466e501677f846da13de98e9d4c0cc7ac9491b6b5e747fca36757612"),
    };

    private static readonly string[] SlotOrder = { "b", "a" };

    private readonly InternalInstallPackageSnapshot _package;
    private readonly InternalInstallAssets? _assets;
    private readonly InternalInstallDirectAssets? _directAssets;
    private readonly IReadOnlyList<EdlRawBuiltBoot> _builtBoots;
    private readonly IReadOnlyDictionary<string, EdlRawBuiltBoot> _directBoots;
    private readonly string _actualCurrentSlot;
    private readonly long _directExecutionSpaceBytes;
    private readonly bool _isDirect;
    private readonly EdlEntryResult _binding;
    private readonly EdlToolchain _toolchain;
    private readonly string _backupDirectory;
    private readonly string _backupManifestSha256;
    private readonly IReadOnlyDictionary<string, EdlCapturedRegion> _backupFiles;
    private readonly IReadOnlyDictionary<int, EdlGeometry> _geometries;
    private readonly IReadOnlyDictionary<int, GptTable> _originalTables;
    private readonly InternalAllocationPlan _allocation;
    private readonly GptTable _postGpt;
    private readonly GptPartition _linuxBoot;
    private readonly GptPartition _linuxRoot;
    private readonly GptPartition _backupPartition;
    private readonly IReadOnlyList<InternalArtifactRegion> _gptWriteRegions;
    private readonly InternalArtifactRegion _boardSummary;
    private readonly IReadOnlyDictionary<string, InternalSlotMaterial> _slotMaterials;
    private readonly IReadOnlyDictionary<string, long> _rawUpperBounds;
    private readonly string _evidenceDirectory;
    private readonly Guid _installationId;
    private readonly string _artifactPlanSha256;
    private readonly string _summaryManifestSha256;
    private readonly BootloaderState _fastbootLockState;
    private readonly IReadOnlyDictionary<string, HeldClaim> _artifactClaims;

    private readonly List<HeldClaim> _claims;
    private readonly List<EdlReadEvidence> _deviceEvidence = new();
    private IReadOnlyDictionary<string, string> _currentBootSha256 =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal));
    private string _currentMiscSha256 = string.Empty;
    private string _confirmationId = string.Empty;
    private bool _originalDeviceVerified;
    private int _disposed;

    private InternalInstallPreparationContext(
        InternalInstallPackageSnapshot package,
        InternalInstallAssets? assets,
        EdlEntryResult binding,
        EdlToolchain toolchain,
        BackupFacts backup,
        ArtifactFacts artifacts,
        IReadOnlyDictionary<string, InternalSlotMaterial> slotMaterials,
        IReadOnlyDictionary<string, long> rawUpperBounds,
        string evidenceDirectory,
        BootloaderState fastbootLockState,
        List<HeldClaim> claims,
        InternalInstallDirectAssets? directAssets = null,
        IReadOnlyList<EdlRawBuiltBoot>? builtBoots = null,
        string? actualCurrentSlot = null,
        long directExecutionSpaceBytes = 0,
        IReadOnlyDictionary<string, EdlRawResignedAvbNode>? directAvbRoots = null,
        IReadOnlyList<DirectAvbMetadataNode>? directAvbNodes = null,
        VerifiedGblPlan? directGblPlan = null)
    {
        _package = package;
        _assets = assets;
        _directAssets = directAssets;
        _isDirect = directAssets is not null;
        _builtBoots = builtBoots ?? Array.Empty<EdlRawBuiltBoot>();
        _directBoots = BuildDirectBootMap(builtBoots, _isDirect);

        if (_isDirect && actualCurrentSlot is not ("a" or "b"))
        {
            throw new InvalidOperationException(
                "A direct EDL raw preparation must carry the observed current slot a or b, not '"
                + (actualCurrentSlot ?? "<none>") + "'.");
        }

        _actualCurrentSlot = actualCurrentSlot ?? "a";
        _directExecutionSpaceBytes = directExecutionSpaceBytes;

        // A direct factory hands over the signed roots it actually produced; every other caller keeps the
        // helper's default empty map, so no unproven root can be observed.
        if (directAvbRoots is not null)
        {
            _directAvbRoots = directAvbRoots;
        }

        // The same rule holds for the metadata nodes: only a direct factory hands over the nodes it actually
        // produced, and every other caller keeps the helper's default empty list.
        if (directAvbNodes is not null)
        {
            _directAvbNodes = directAvbNodes;
        }

        // A verified GBL plan preserves the metadata nodes it actually proved, so a context that carries one
        // can never also carry AOSP roots or candidate nodes; only a direct factory may hand over a plan and
        // every other caller keeps the helper's default null.
        _directGblPlan = directGblPlan;

        if (directGblPlan is not null)
        {
            if (!_isDirect)
            {
                throw new InvalidOperationException(
                    "A verified GBL plan can only be handed over by a direct raw factory, not by this caller.");
            }

            if (_directAvbRoots.Count > 0 || _directAvbNodes.Count > 0)
            {
                throw new InvalidOperationException(
                    "A verified GBL plan already preserves the metadata nodes it proved; signed AOSP roots and candidate nodes cannot be mixed in.");
            }
        }

        _binding = binding;
        _toolchain = toolchain;
        _backupDirectory = backup.Directory;
        _backupManifestSha256 = backup.ManifestSha256;
        _backupFiles = backup.Files;
        _geometries = backup.Geometries;
        _originalTables = backup.Tables;
        _allocation = artifacts.Allocation;
        _postGpt = artifacts.PostGpt;
        _linuxBoot = artifacts.LinuxBoot;
        _linuxRoot = artifacts.LinuxRoot;
        _backupPartition = artifacts.BackupPartition;
        _gptWriteRegions = artifacts.GptWriteRegions;
        _boardSummary = artifacts.BoardSummary;
        _slotMaterials = slotMaterials;
        _rawUpperBounds = rawUpperBounds;
        _evidenceDirectory = evidenceDirectory;
        _installationId = artifacts.InstallationId;
        _artifactPlanSha256 = artifacts.PlanSha256;
        _summaryManifestSha256 = artifacts.SummaryManifestSha256;
        _fastbootLockState = fastbootLockState;
        _artifactClaims = artifacts.Claims;
        _claims = claims;
    }

    /// <summary>
    /// The immutable per-slot view of the builder results. A direct preparation carries exactly the built
    /// slots <c>a</c> and <c>b</c>; a duplicate or unknown slot is refused instead of resolved last-wins. The
    /// legacy route builds no direct boot and therefore keeps an empty map.
    /// </summary>
    private static IReadOnlyDictionary<string, EdlRawBuiltBoot> BuildDirectBootMap(
        IReadOnlyList<EdlRawBuiltBoot>? builtBoots,
        bool isDirect)
    {
        Dictionary<string, EdlRawBuiltBoot> map = new(StringComparer.Ordinal);

        if (builtBoots is not null)
        {
            foreach (EdlRawBuiltBoot built in builtBoots)
            {
                ArgumentNullException.ThrowIfNull(built);

                if (built.Slot is not ("a" or "b") || !map.TryAdd(built.Slot, built))
                {
                    throw new InvalidOperationException(
                        "The direct preparation carries an unknown or duplicate built boot slot.");
                }
            }
        }

        if (isDirect && map.Count != 2)
        {
            throw new InvalidOperationException(
                "A direct EDL raw preparation must carry exactly one built boot for slot a and slot b.");
        }

        return new ReadOnlyDictionary<string, EdlRawBuiltBoot>(map);
    }

    // ------------------------------------------------------------------ frozen getters

    internal InternalInstallPackageSnapshot Package => _package;

    internal InternalInstallAssets Assets =>
        _assets
        ?? throw new InvalidOperationException("A direct EDL raw preparation carries no legacy install assets.");

    internal bool IsDirect => _isDirect;

    internal InternalInstallDirectAssets DirectAssets =>
        _directAssets
        ?? throw new InvalidOperationException("A legacy preparation carries no direct EDL tool assets.");

    internal IReadOnlyDictionary<string, EdlRawBuiltBoot> DirectBoots => _directBoots;

    internal string ActualCurrentSlot => _actualCurrentSlot;

    internal IReadOnlyDictionary<string, EdlCapturedRegion> BackupFiles => _backupFiles;

    internal IReadOnlyDictionary<int, EdlGeometry> Geometries => _geometries;

    internal IReadOnlyDictionary<int, GptTable> OriginalTables => _originalTables;

    internal InternalAllocationPlan Allocation => _allocation;

    internal GptTable PostGpt => _postGpt;

    internal GptPartition LinuxBoot => _linuxBoot;

    internal GptPartition LinuxRoot => _linuxRoot;

    internal GptPartition BackupPartition => _backupPartition;

    internal IReadOnlyList<InternalArtifactRegion> GptWriteRegions => _gptWriteRegions;

    internal InternalArtifactRegion BoardSummary => _boardSummary;

    internal IReadOnlyDictionary<string, InternalSlotMaterial> SlotMaterials => _slotMaterials;

    internal IReadOnlyDictionary<string, long> RawUpperBoundBytes => _rawUpperBounds;

    internal string EvidenceDirectory => _evidenceDirectory;

    internal Guid InstallationId => _installationId;

    internal string ArtifactPlanSha256 => _artifactPlanSha256;

    internal string BackupManifestSha256 => _backupManifestSha256;

    // ------------------------------------------------------------------ factory

    /// <summary>
    /// Verifies every local input, makes the install package binding explicit, computes the per-slot raw upper
    /// bound, creates the evidence directory and proves the original device before returning.
    /// </summary>
    internal static async Task<InternalInstallPreparationContext> PrepareAsync(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup,
        InternalArtifactSet artifactSet,
        ImportedPackage package,
        InternalInstallAssets installAssets,
        InternalInstallServices services,
        string evidenceParent,
        CancellationToken cancellationToken)
    {
        _ = services;

        cancellationToken.ThrowIfCancellationRequested();

        AndroidMaintenanceIdentity android = deviceCheck.Android
            ?? throw new InvalidOperationException("The verified Step 1 result carries no Android identity.");
        DeviceIdentity identity = android.Identity
            ?? throw new InvalidOperationException("The verified Step 1 result carries no device identity.");
        FirmwareSnapshot firmware = identity.Firmware
            ?? throw new InvalidOperationException("The verified Step 1 result carries no firmware snapshot.");

        InternalInstallPackageSnapshot? packageSnapshot = null;
        InternalInstallAssets? ownAssets = null;
        InternalInstallPreparationContext? context = null;
        List<HeldClaim> claims = new();
        bool transferred = false;

        try
        {
            packageSnapshot = await InternalInstallPackageSnapshot
                .CaptureAsync(package, identity, cancellationToken)
                .ConfigureAwait(false);

            RequireBoundPackage(packageSnapshot, cancellationToken);

            KernelHeader kernel = ReadKernelHeader(packageSnapshot, cancellationToken);

            ownAssets = await installAssets.AcquireAsync(cancellationToken).ConfigureAwait(false);

            BackupFacts backupFacts = BindBackup(backup, claims, cancellationToken);

            // The maintenance boot is written into the actual boot_a range, never into an assumed copy of boot_b,
            // so its verified length must be exactly that range before any artifact, slot or device work runs.
            EdlCapturedRegion bootA = backupFacts.Files["boot_a"];
            EdlGeometry bootAGeometry = backupFacts.Geometries[bootA.Lun];
            long bootRangeBytes = CheckedMultiply(
                bootA.SectorCount, bootAGeometry.SectorSize, "The boot_a range overflows.");

            if (ownAssets.MaintenanceBoot.Length != bootRangeBytes
                || ownAssets.MaintenanceBoot.Length % bootAGeometry.SectorSize != 0)
            {
                throw new InvalidOperationException(
                    "maintenance-boot-range-mismatch: the maintenance boot is "
                    + ownAssets.MaintenanceBoot.Length + " bytes, not the actual " + bootRangeBytes
                    + " byte boot_a range at a whole number of " + bootAGeometry.SectorSize + " byte sectors.");
            }

            ArtifactFacts artifactFacts = BindArtifacts(
                artifactSet,
                backupFacts,
                identity,
                firmware,
                packageSnapshot.Storage,
                cancellationToken,
                claims);

            Dictionary<string, InternalSlotMaterial> materials = new(StringComparer.Ordinal);
            Dictionary<string, long> uppers = new(StringComparer.Ordinal);

            long kernelLength = RequirePayloadLength(packageSnapshot, "kernel");
            long runtimeLength = RequirePayloadLength(packageSnapshot, "runtime");
            long dtbLength = RequirePayloadLength(packageSnapshot, "dtb");
            long initramfsLength = RequirePayloadLength(packageSnapshot, "initramfs");

            foreach (string slot in new[] { "a", "b" })
            {
                cancellationToken.ThrowIfCancellationRequested();

                InternalSlotMaterial material = await AnalyzeSlotAsync(slot, backupFacts.Files, cancellationToken)
                    .ConfigureAwait(false);

                long upper = ComputeRawUpperBound(
                    material.BaseImageLength,
                    material.BaseImageSize,
                    material.BaseTextOffset,
                    kernelLength,
                    kernel.ImageSize,
                    kernel.TextOffset,
                    runtimeLength,
                    dtbLength,
                    initramfsLength);

                if (upper > material.LoaderBudget.MaxRawBytes)
                {
                    throw new InvalidOperationException(
                        "slot-" + slot + "-raw-upper-bound-exceeds-loader-budget: the packed raw image would need "
                        + upper + " bytes, above the " + material.LoaderBudget.MaxRawBytes
                        + " byte loader budget of '" + material.LoaderBudget.Profile + "'.");
                }

                materials.Add(slot, material);
                uppers.Add(slot, upper);
            }

            string evidenceDirectory = CreateEvidenceDirectory(evidenceParent, identity.Serial);

            DeviceCapture original = await CaptureDeviceAsync(
                initialEdl,
                "original",
                post: false,
                evidenceDirectory,
                claims,
                initialEdl.Binding,
                backupFacts.Geometries,
                backupFacts.Tables,
                postGpt: null,
                backupFacts.Files,
                maintenanceBoot: null,
                cancellationToken).ConfigureAwait(false);

            context = new InternalInstallPreparationContext(
                packageSnapshot,
                ownAssets,
                initialEdl.Binding,
                initialEdl.Toolchain,
                backupFacts,
                artifactFacts,
                new ReadOnlyDictionary<string, InternalSlotMaterial>(
                    new Dictionary<string, InternalSlotMaterial>(materials, StringComparer.Ordinal)),
                new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(uppers, StringComparer.Ordinal)),
                evidenceDirectory,
                deviceCheck.FastbootLockState,
                claims);

            context._currentBootSha256 = new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(original.BootSha256, StringComparer.Ordinal));
            context._currentMiscSha256 = original.MiscSha256;
            context._deviceEvidence.AddRange(original.Evidence);
            context._originalDeviceVerified = true;

            context.SealConfirmation(cancellationToken);

            transferred = true;
            return context;
        }
        finally
        {
            if (!transferred)
            {
                if (context is not null)
                {
                    context.Dispose();
                }
                else
                {
                    foreach (HeldClaim claim in claims)
                    {
                        claim.Stream.Dispose();
                    }

                    ownAssets?.Dispose();
                    packageSnapshot?.Dispose();
                }
            }
        }
    }

    // ------------------------------------------------------------------ direct factory

    /// <summary>
    /// The parameterised direct EDL raw preparation. It binds and re-verifies the 52-file backup, decides the
    /// source slot of both fixed targets once, authenticates the original signed vbmeta root of every
    /// self-sourced target, and only then captures the schema-2 package against the actual observed identity,
    /// acquires its own typed tool lease, re-verifies the nine prepared artifacts, binds the optional package
    /// profile facts, proves the planned partition room and the actual evidence volume budget, then builds the
    /// real candidate B and A through the shared builder and finally captures the original device. Nothing
    /// here writes a device or fabricates a legacy asset.
    /// </summary>
    internal static async Task<InternalInstallPreparationContext> PrepareDirectAsync(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup,
        InternalArtifactSet artifactSet,
        ImportedPackage package,
        InternalInstallDirectAssets installAssets,
        InternalInstallServices services,
        string evidenceParent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        cancellationToken.ThrowIfCancellationRequested();

        if (!Path.IsPathFullyQualified(evidenceParent))
        {
            throw new ArgumentException(
                "The evidence parent must be an absolute path; there is no working-directory fallback.",
                nameof(evidenceParent));
        }

        if (!Directory.Exists(Path.GetFullPath(evidenceParent)))
        {
            throw new ArgumentException(
                "The evidence parent must already exist; the preparation never invents it.",
                nameof(evidenceParent));
        }

        AndroidMaintenanceIdentity android = deviceCheck.Android
            ?? throw new InvalidOperationException("The verified Step 1 result carries no Android identity.");
        DeviceIdentity identity = android.Identity
            ?? throw new InvalidOperationException("The verified Step 1 result carries no device identity.");
        FirmwareSnapshot firmware = identity.Firmware
            ?? throw new InvalidOperationException("The verified Step 1 result carries no firmware snapshot.");

        if (deviceCheck.CurrentSlot is not ("a" or "b"))
        {
            throw new InvalidOperationException(
                "unsupported-current-slot: the direct install supports exactly the observed slot a or slot b.");
        }

        EdlDeviceProfile profile = InternalInstallBackend
            .RequireDirectBoundSession(deviceCheck, initialEdl, backup);

        InternalInstallPackageSnapshot? packageSnapshot = null;
        InternalInstallDirectAssets? ownAssets = null;
        InternalInstallPreparationContext? context = null;
        List<HeldClaim> claims = new();
        List<EdlRawBuiltBoot> builds = new();
        VerifiedGblPlan? gblPlan = null;
        GblPreparationInputs? gblInputs = null;
        Dictionary<string, EdlRawInactiveSlotBackup> inactiveTargets = new(StringComparer.Ordinal);
        bool transferred = false;

        try
        {
            // The original backup claims and the evidence directory come first, because the two early gates
            // below need them: the one strict source-slot proof per valid target and the signed original
            // vbmeta roots. Both are settled before any Linux raw image is expanded or packed.
            BackupFacts backupFacts = BindBackup(backup, claims, cancellationToken);

            string evidenceDirectory = CreateEvidenceDirectory(evidenceParent, identity.Serial);

            Dictionary<string, string> sourceSlots = await DetermineDirectSourceSlotsAsync(
                profile.ProfileId,
                deviceCheck.CurrentSlot,
                backupFacts.Files,
                inactiveTargets,
                cancellationToken).ConfigureAwait(false);

            // The verified GBL gate decides whether this source is a real GBL source before any raw expansion,
            // but it authenticates the original root and the entry, region and EFI eligibility only. The
            // wrapper, the child and the current-XBL capacity are completed from the actual builds later, not
            // here. A null result is the old AOSP eligibility only, and that path keeps its exact signed-root
            // preparation below.
            gblInputs = await PrepareDirectGblInputsAsync(
                deviceCheck.CurrentSlot,
                deviceCheck.FastbootLockState,
                sourceSlots,
                backupFacts,
                evidenceDirectory,
                claims,
                cancellationToken).ConfigureAwait(false);

            IReadOnlyDictionary<string, EdlRawResignedAvbNode> avbRoots;
            if (gblInputs is null)
            {
                avbRoots = await PrepareDirectAvbRootsAsync(
                    deviceCheck.CurrentSlot,
                    deviceCheck.FastbootLockState,
                    sourceSlots,
                    backupFacts.Files,
                    evidenceDirectory,
                    claims,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // A GBL-preferred run generates no AOSP metadata candidate at all, so this typed empty map
                // states only that no candidate was produced and the stock metadata stays untouched. It holds
                // no proved node and is never a bypass.
                avbRoots = new ReadOnlyDictionary<string, EdlRawResignedAvbNode>(
                    new Dictionary<string, EdlRawResignedAvbNode>(StringComparer.Ordinal));
            }

            packageSnapshot = await InternalInstallPackageSnapshot
                .CaptureEdlRawAsync(package, identity, evidenceParent, cancellationToken)
                .ConfigureAwait(false);

            EdlRawPackageContract contract = packageSnapshot.EdlRawContract;

            RequireDirectContract(contract, packageSnapshot, identity, firmware, profile);
            RequireDirectPartitionRoom(contract, artifactSet.Allocation);

            ownAssets = await installAssets.AcquireAsync(cancellationToken).ConfigureAwait(false);

            ArtifactFacts artifactFacts = BindArtifacts(
                artifactSet,
                backupFacts,
                identity,
                firmware,
                packageSnapshot.Storage,
                cancellationToken,
                claims);

            // The metadata nodes come from the very roots this preparation authenticated and held earlier in
            // the early gate. The package expansion has already happened by now, but every node is still held
            // before the native packing and before Prepared is sealed, so the confirmation names the actual
            // nodes this preparation holds instead of a candidate fact. The gate's placement is unchanged.
            // A GBL-preferred run takes the typed empty branch on purpose: it generates no AOSP metadata
            // candidate and leaves the stock metadata unchanged, and no child claim is taken before the native
            // build. The plan itself is completed from the actual built boots afterwards.
            IReadOnlyList<DirectAvbMetadataNode> avbNodes;

            if (gblInputs is null)
            {
                avbNodes = await PrepareDirectAvbNodesAsync(
                    avbRoots,
                    sourceSlots,
                    backupFacts.Files,
                    evidenceDirectory,
                    claims,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                avbNodes = Array.Empty<DirectAvbMetadataNode>();
            }

            Dictionary<string, InternalSlotMaterial> materials = new(StringComparer.Ordinal);

            long requiredExecutionBytes = ComputeDirectPlannedExecutionSpace(
                backupFacts.Geometries,
                artifactFacts.GptWriteRegions,
                artifactFacts.BoardSummary.Length,
                packageSnapshot.LinuxBootRaw.Length,
                packageSnapshot.LinuxRootRaw.Length,
                backupFacts.Files,
                includeOriginalCapture: true,
                avbNodes: avbNodes,
                gblInputs: gblInputs);

            // A GBL run also creates one whole wrapper partition per slot beside the execution work, so the
            // pre-native check reserves those two actual backup partition lengths as real disk bytes. The
            // execution budget itself is left unchanged and still names future execution bytes only.
            long requiredDiskBytes = requiredExecutionBytes;

            if (gblInputs is not null)
            {
                requiredDiskBytes = CheckedAdd(
                    requiredDiskBytes,
                    RequireBudgetRegion(backupFacts.Files, "boot_a").Length,
                    "The GBL wrapper disk reservation overflows.");

                requiredDiskBytes = CheckedAdd(
                    requiredDiskBytes,
                    RequireBudgetRegion(backupFacts.Files, "boot_b").Length,
                    "The GBL wrapper disk reservation overflows.");
            }

            RequireDirectExecutionSpaceAvailable(
                requiredDiskBytes,
                InternalInstallPackageSnapshot.TryGetAvailableFreeBytes(evidenceDirectory));

            Dictionary<string, long> actualRawLengths = new(StringComparer.Ordinal);

            // The fixed write order is candidate b first, then candidate a. Each result is verified here and
            // held by this context until Dispose, which deletes only the builder's own generated child.
            foreach (string slot in SlotOrder)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // The source slot and its optional proof were decided once, before any raw expansion, so the
                // build only consumes that decision: the zero header is never tested a second time and the
                // strict five-file proof is never bought twice.
                string sourceSlot = sourceSlots[slot];
                inactiveTargets.TryGetValue(slot, out EdlRawInactiveSlotBackup? inactiveTarget);

                try
                {
                    EdlRawBuiltBoot built = await EdlRawBootBuilder
                        .BuildAsync(
                            new EdlRawBootBuildRequest(
                                slot,
                                Claim(backupFacts.Files, "boot_" + sourceSlot),
                                Claim(backupFacts.Files, "vendor_boot_" + sourceSlot),
                                Claim(backupFacts.Files, "init_boot_" + sourceSlot),
                                Claim(backupFacts.Files, "abl_" + sourceSlot),
                                Claim(backupFacts.Files, "xbl_config_" + sourceSlot),
                                contract,
                                ownAssets.Tools,
                                evidenceDirectory,
                                inactiveTarget),
                            services.CommandRunner,
                            cancellationToken)
                        .ConfigureAwait(false);

                    builds.Add(built);

                    RequireBuiltBoot(
                        built,
                        slot,
                        sourceSlot,
                        contract,
                        packageSnapshot,
                        backupFacts.Files);

                    // The actual recovered material of this built slot is the only material fact; the old
                    // pre-build recovery read is never repeated. The key stays the target even when that
                    // material itself was recovered from the opposite source slot.
                    materials.Add(slot, built.SlotMaterial);

                    actualRawLengths.Add(slot, built.PackedRaw.Length);

                    CopyVerifiedReport(built, evidenceDirectory, claims, cancellationToken);
                }
                finally
                {
                    // The proof's zero facts are consumed by this build; its leases are released here and
                    // never replace the original backup leases that BindBackup already holds. Removing it
                    // from the map marks it as released, so the outer cleanup never touches it twice.
                    inactiveTarget?.Dispose();
                    inactiveTargets.Remove(slot);
                }
            }

            // Both built boots exist now, so the verified GBL plan is completed from what was actually built
            // before the original partition capture. The plan's effective candidates stay inside the plan; the
            // built boots and their envelopes are never mutated here.
            if (gblInputs is not null)
            {
                // The native source builds and the EFI asset already exist and have already consumed the actual
                // free bytes, so only the whole candidate wrapper partitions are reserved here. Each candidate's
                // whole partition length is used, never the packed raw or payload length.
                long wrapperDiskBytes = requiredExecutionBytes;

                foreach (EdlRawBuiltBoot built in builds)
                {
                    wrapperDiskBytes = CheckedAdd(
                        wrapperDiskBytes,
                        built.CandidateBoot.Length,
                        "The GBL wrapper disk reservation overflows.");
                }

                RequireDirectExecutionSpaceAvailable(
                    wrapperDiskBytes,
                    InternalInstallPackageSnapshot.TryGetAvailableFreeBytes(evidenceDirectory));

                gblPlan = await CompleteDirectGblPlanAsync(
                    gblInputs,
                    builds,
                    backupFacts,
                    evidenceDirectory,
                    claims,
                    cancellationToken).ConfigureAwait(false);
            }

            DeviceCapture original = await CaptureDeviceAsync(
                initialEdl,
                "original",
                post: false,
                evidenceDirectory,
                claims,
                initialEdl.Binding,
                backupFacts.Geometries,
                backupFacts.Tables,
                postGpt: null,
                backupFacts.Files,
                maintenanceBoot: null,
                cancellationToken,
                directMetadataNodes: avbNodes,
                directGblGuardRoles: gblPlan is null ? null : GetGblGuardRoles(gblPlan.Inputs)).ConfigureAwait(false);

            context = new InternalInstallPreparationContext(
                packageSnapshot,
                assets: null,
                initialEdl.Binding,
                initialEdl.Toolchain,
                backupFacts,
                artifactFacts,
                new ReadOnlyDictionary<string, InternalSlotMaterial>(materials),
                new ReadOnlyDictionary<string, long>(actualRawLengths),
                evidenceDirectory,
                deviceCheck.FastbootLockState,
                claims,
                ownAssets,
                builds,
                deviceCheck.CurrentSlot,
                requiredExecutionBytes,
                avbRoots,
                avbNodes,
                gblPlan);

            // The context owns the plan's wrappers and its staged input files from here on, so the local
            // hand-off is cleared before the remaining factory work can fail and dispose something the
            // context now owns.
            gblPlan = null;
            gblInputs = null;

            context._currentBootSha256 = new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(original.BootSha256, StringComparer.Ordinal));
            context._currentMiscSha256 = original.MiscSha256;
            context._deviceEvidence.AddRange(original.Evidence);
            context._originalDeviceVerified = true;

            context.SealConfirmation(cancellationToken);

            // Ready is only reached after every builder output, this factory's own original capture and the
            // confirmation files exist, so the actual free bytes are rechecked against the future execution
            // work instead of the earlier pre-build estimate only. That future work still includes the warm
            // capture the execute-direct flow takes for itself.
            context.EnsureDirectExecutionSpace();

            transferred = true;
            return context;
        }
        finally
        {
            // Any proof the early gate bought whose build never ran - a refused package, asset, root or a
            // cancellation - is released here, so no path leaves an inactive-slot lease open. A proof is only
            // released after its own build finished, because the slot loop removes it there.
            foreach (EdlRawInactiveSlotBackup remaining in inactiveTargets.Values)
            {
                remaining.Dispose();
            }

            inactiveTargets.Clear();

            if (!transferred)
            {
                if (context is not null)
                {
                    context.Dispose();
                }
                else
                {
                    foreach (HeldClaim claim in claims)
                    {
                        claim.Stream.Dispose();
                    }

                    // The context was never built, so the plan's wrappers and the staged GBL inputs are still
                    // this factory's to release: claims first, then the plan's own boots and its two staged
                    // files, then the builders' generated boots.
                    DisposeGblBoots(gblPlan);
                    CleanupGblStagedInputs(gblInputs);

                    foreach (EdlRawBuiltBoot built in builds)
                    {
                        built.Dispose();
                    }

                    ownAssets?.Dispose();
                    packageSnapshot?.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// Requires the schema-2 contract to describe the actual observed model and the actual expanded images.
    /// A declared optional Android profile group is checked strictly against the trusted profile and the
    /// actual build; when the group is absent no extra restriction is invented.
    /// </summary>
    private static void RequireDirectContract(
        EdlRawPackageContract contract,
        InternalInstallPackageSnapshot snapshot,
        DeviceIdentity identity,
        FirmwareSnapshot firmware,
        EdlDeviceProfile profile)
    {
        if (contract.TestOnly)
        {
            throw new InvalidOperationException(
                "unsupported-install-package-bound: a test-only package cannot back a production direct install.");
        }

        if (!SameSha(contract.ManifestFingerprint, snapshot.ManifestFingerprint)
            || !string.Equals(contract.DeviceModel, identity.Model, StringComparison.Ordinal)
            || !string.Equals(contract.DeviceModel, profile.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "unsupported-install-package-bound: the direct contract is not this manifest, model and profile.");
        }

        if (contract.EdlProfileId is not null)
        {
            string? fullHardwareId = profile.FullHardwareId;

            if (!string.Equals(contract.EdlProfileId, profile.ProfileId, StringComparison.Ordinal)
                || fullHardwareId is null
                || !string.Equals(contract.HardwareId, fullHardwareId, StringComparison.Ordinal)
                || !string.Equals(contract.AndroidBuild, firmware.DisplayId, StringComparison.Ordinal)
                || !ContainsDeclaredVersion(contract.FirmwareVersions, firmware.DisplayId))
            {
                throw new InvalidOperationException(
                    "unsupported-install-package-bound: the declared optional direct profile group does not "
                    + "match the trusted profile and the actual observed build.");
            }
        }
        else if (contract.HardwareId is not null
            || contract.AndroidBuild is not null
            || contract.FirmwareVersions.Count != 0)
        {
            throw new InvalidOperationException(
                "unsupported-install-package-bound: a partial optional direct profile group is not accepted.");
        }

        if (snapshot.LinuxBootRaw.Length != contract.BootImage.ExpandedBytes
            || !SameSha(snapshot.LinuxBootRaw.Sha256, contract.BootImage.ExpandedSha256)
            || snapshot.LinuxRootRaw.Length != contract.RootImage.ExpandedBytes
            || !SameSha(snapshot.LinuxRootRaw.Sha256, contract.RootImage.ExpandedSha256))
        {
            throw new InvalidDataException(
                "The actual expanded raw images are not the two declared direct images.");
        }

        if (contract.BootImage.SectorSize != 4096 || contract.RootImage.SectorSize != 4096)
        {
            throw new InvalidDataException(
                "Both declared direct filesystems must use the actual 4096 byte sector geometry.");
        }

        // The package-fixed filesystem UUIDs are facts of the filesystem; the per-install GPT PARTUUIDs are
        // independent random identities and are deliberately never compared with them.
        if (contract.BootImage.FsUuid != contract.BootRecipe.BootUuid
            || contract.RootImage.FsUuid != contract.BootRecipe.RootUuid)
        {
            throw new InvalidDataException("The declared filesystem UUIDs are not the boot recipe UUIDs.");
        }
    }

    private static bool ContainsDeclaredVersion(IReadOnlyList<string> versions, string value)
    {
        foreach (string declared in versions)
        {
            if (string.Equals(declared, value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Both declared minimum sizes and the actual expanded lengths must fit the planned boot and root
    /// partitions, and those partitions must keep the actual 4096 byte sector alignment.
    /// </summary>
    private static void RequireDirectPartitionRoom(
        EdlRawPackageContract contract,
        InternalAllocationPlan allocation)
    {
        long bootBytes = allocation.LinuxBootBytes;
        long rootBytes = allocation.LinuxRootBytes;

        if (bootBytes <= 0 || rootBytes <= 0 || bootBytes % 4096 != 0 || rootBytes % 4096 != 0)
        {
            throw new InvalidDataException(
                "The planned Linux boot and root partitions are not positive 4096 byte aligned ranges.");
        }

        RequireImageFits(contract.BootImage, bootBytes, "boot");
        RequireImageFits(contract.RootImage, rootBytes, "root");
    }

    private static void RequireImageFits(EdlRawImage image, long plannedBytes, string subject)
    {
        if (image.MinimumPartitionBytes > plannedBytes || image.ExpandedBytes > plannedBytes)
        {
            throw new InvalidDataException(
                "The declared Linux " + subject + " image needs " + image.MinimumPartitionBytes
                + " bytes and expands to " + image.ExpandedBytes + " bytes, but the plan holds "
                + plannedBytes + ".");
        }
    }

    /// <summary>
    /// The checked future evidence budget of one direct execution, computed from the actual plan only. The
    /// prepared artifacts, the 52-file backup, the package payloads and the builder work already exist, so only
    /// the bytes a future readback actually creates are counted; the write itself creates no new byte.
    /// </summary>
    internal static long ComputeDirectExecutionSpace(
        long gptCaptureBytes,
        long bootACaptureBytes,
        long bootBCaptureBytes,
        long miscCaptureBytes,
        long gptWriteBytes,
        long boardReadbackBytes,
        long linuxBootRawReadbackBytes,
        long linuxRootRawReadbackBytes,
        long candidateBBytes,
        long candidateABytes,
        long freshMiscBytes,
        long overlayUnitBytes) =>
        ComputeDirectExecutionSpace(
            includeOriginalCapture: true,
            gptCaptureBytes,
            bootACaptureBytes,
            bootBCaptureBytes,
            miscCaptureBytes,
            gptWriteBytes,
            boardReadbackBytes,
            linuxBootRawReadbackBytes,
            linuxRootRawReadbackBytes,
            candidateBBytes,
            candidateABytes,
            freshMiscBytes,
            overlayUnitBytes);

    /// <summary>
    /// The same checked budget with an explicit switch for the one future pre-write original capture. The
    /// capture is twelve GPT windows (each of both copies at its own LUN sector size) plus the full boot_a,
    /// boot_b and misc reads. <paramref name="includeOriginalCapture"/> is false only once that capture exists.
    /// </summary>
    internal static long ComputeDirectExecutionSpace(
        bool includeOriginalCapture,
        long gptCaptureBytes,
        long bootACaptureBytes,
        long bootBCaptureBytes,
        long miscCaptureBytes,
        long gptWriteBytes,
        long boardReadbackBytes,
        long linuxBootRawReadbackBytes,
        long linuxRootRawReadbackBytes,
        long candidateBBytes,
        long candidateABytes,
        long freshMiscBytes,
        long overlayUnitBytes)
    {
        if (gptCaptureBytes < 0 || bootACaptureBytes < 0 || bootBCaptureBytes < 0 || miscCaptureBytes < 0
            || gptWriteBytes < 0 || boardReadbackBytes < 0 || linuxBootRawReadbackBytes < 0
            || linuxRootRawReadbackBytes < 0 || candidateBBytes < 0 || candidateABytes < 0
            || freshMiscBytes < 0 || overlayUnitBytes < 0)
        {
            throw new InvalidDataException("The direct execution space inputs must not be negative.");
        }

        long total = 0;

        if (includeOriginalCapture)
        {
            total = gptCaptureBytes;
            total = CheckedAdd(total, bootACaptureBytes, "The prewrite capture overflows.");
            total = CheckedAdd(total, bootBCaptureBytes, "The prewrite capture overflows.");
            total = CheckedAdd(total, miscCaptureBytes, "The prewrite capture overflows.");
        }

        // Only the readback of the four GPT regions is future bytes: their written bytes already exist as
        // prepared artifacts, so the old extra write copy was counted twice.
        total = CheckedAdd(total, gptWriteBytes, "The GPT readback budget overflows.");

        // Board summary readback, both expanded raw image readbacks and both full candidate partition readbacks.
        total = CheckedAdd(total, boardReadbackBytes, "The board readback budget overflows.");
        total = CheckedAdd(total, linuxBootRawReadbackBytes, "The raw readback budget overflows.");
        total = CheckedAdd(total, linuxRootRawReadbackBytes, "The raw readback budget overflows.");
        total = CheckedAdd(total, candidateBBytes, "The candidate readback budget overflows.");
        total = CheckedAdd(total, candidateABytes, "The candidate readback budget overflows.");

        // Fresh whole misc read, then the rounded BCB unit write and its readback.
        total = CheckedAdd(total, freshMiscBytes, "The fresh misc budget overflows.");
        total = CheckedAdd(total, overlayUnitBytes, "The BCB overlay budget overflows.");
        total = CheckedAdd(total, overlayUnitBytes, "The BCB overlay readback budget overflows.");

        return total;
    }

    /// <summary>
    /// The planned budget from the actual prepared facts: six geometries, the four GPT write regions, the board
    /// summary, both expanded Linux images, the actual boot_a, boot_b and misc captures and every actual direct
    /// metadata node of this preparation.
    /// <para>
    /// Each metadata node adds its real signed candidate length once, for the full readback of its future
    /// whole-partition write. When <paramref name="includeOriginalCapture"/> is set, one separate fresh
    /// pre-write capture of those same bytes is added as well. Already created candidates, the factory's own
    /// capture and the source archive are never counted a second time.
    /// </para>
    /// </summary>
    private static long ComputeDirectPlannedExecutionSpace(
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        IReadOnlyList<InternalArtifactRegion> gptWriteRegions,
        long boardSummaryBytes,
        long linuxBootRawBytes,
        long linuxRootRawBytes,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        bool includeOriginalCapture,
        IReadOnlyList<DirectAvbMetadataNode>? avbNodes = null,
        GblPreparationInputs? gblInputs = null)
    {
        long gptCapture = 0;
        for (int lun = 0; lun < 6; lun++)
        {
            if (!geometries.TryGetValue(lun, out EdlGeometry? geometry) || geometry is null)
            {
                throw new InvalidDataException(
                    "The direct execution budget has no actual geometry for LUN " + lun + ".");
            }

            gptCapture = CheckedAdd(
                gptCapture,
                CheckedMultiply(
                    GptCaptureSectors * 2L,
                    geometry.SectorSize,
                    "The GPT capture budget overflows."),
                "The GPT capture budget overflows.");
        }

        long gptWrite = 0;
        foreach (InternalArtifactRegion region in gptWriteRegions)
        {
            gptWrite = CheckedAdd(gptWrite, region.Length, "The GPT write budget overflows.");
        }

        EdlCapturedRegion bootA = RequireBudgetRegion(files, "boot_a");
        EdlCapturedRegion bootB = RequireBudgetRegion(files, "boot_b");
        EdlCapturedRegion misc = RequireBudgetRegion(files, "misc");

        long overlayUnit = AlignUp(
            2048L, misc.SectorSize, "The BCB overlay unit overflows.");

        long planned = ComputeDirectExecutionSpace(
            includeOriginalCapture,
            gptCapture,
            bootA.Length,
            bootB.Length,
            misc.Length,
            gptWrite,
            boardSummaryBytes,
            linuxBootRawBytes,
            linuxRootRawBytes,
            bootB.Length,
            bootA.Length,
            misc.Length,
            overlayUnit);

        long metadataReadback = 0;
        if (avbNodes is not null)
        {
            foreach (DirectAvbMetadataNode node in avbNodes)
            {
                metadataReadback = CheckedAdd(
                    metadataReadback,
                    node.Node.Candidate.Length,
                    "The direct metadata execution budget overflows.");
            }
        }

        planned = CheckedAdd(
            planned,
            metadataReadback,
            "The direct metadata execution budget overflows.");

        if (includeOriginalCapture)
        {
            planned = CheckedAdd(
                planned,
                metadataReadback,
                "The direct metadata execution budget overflows.");
        }

        if (gblInputs is not null)
        {
            // GBL preserves the stock metadata and produces no AOSP candidate nodes, so a candidate list beside
            // it would be a mixed plan and is refused instead of summed.
            if (avbNodes is not null && avbNodes.Count > 0)
            {
                throw new InvalidOperationException(
                    "A verified GBL execution budget cannot be mixed with AOSP metadata candidates.");
            }

            // The future EFI write reads its own written range back once. This is a write-readback byte of one
            // existing claim, not a metadata writeback and not another full image.
            planned = CheckedAdd(
                planned,
                RequireBudgetRegion(files, "efisp").Length,
                "The GBL EFI write budget overflows.");

            if (includeOriginalCapture)
            {
                // The future guard readback covers exactly the roles this plan guards; every role is an actual
                // existing claim, so no partition constant or synthetic length is invented.
                foreach (string role in GetGblGuardRoles(gblInputs))
                {
                    planned = CheckedAdd(
                        planned,
                        RequireBudgetRegion(files, role).Length,
                        "The GBL guard capture budget overflows.");
                }
            }
        }

        return planned;
    }

    private static EdlCapturedRegion RequireBudgetRegion(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string role)
    {
        if (!files.TryGetValue(role, out EdlCapturedRegion? region) || region is null || region.Length <= 0)
        {
            throw new InvalidDataException(
                "The direct execution budget requires the actual '" + role + "' capture.");
        }

        return region;
    }

    /// <summary>
    /// Refuses a direct preparation whose actual evidence volume cannot hold the checked future evidence
    /// bytes. A missing free-space fact is a refusal, never an unbounded permission.
    /// </summary>
    internal static void RequireDirectExecutionSpaceAvailable(long requiredBytes, long? availableBytes)
    {
        if (requiredBytes <= 0)
        {
            throw new InvalidDataException("The direct execution space requirement is not positive.");
        }

        if (availableBytes is null)
        {
            throw new IOException(
                "insufficient-direct-execution-space: the free space of the evidence volume could not be "
                + "determined.");
        }

        if (availableBytes.Value < requiredBytes)
        {
            throw new IOException(
                "insufficient-direct-execution-space: the evidence volume holds " + availableBytes.Value
                + " free bytes, but the direct execution needs " + requiredBytes + " bytes.");
        }
    }

    /// <summary>
    /// The last budget recheck for the future direct execution owner. It reads the actual evidence volume
    /// again; it never substitutes a cached number for the current free bytes.
    /// <para>
    /// The default counts the one future pre-write original capture, including the full readback of every
    /// actual metadata node. The execution flow passes <c>false</c> immediately after that fresh capture
    /// exists, so its bytes are never counted twice. The prepared artifacts, the backup, the package and the
    /// builder outputs already exist in both cases.
    /// </para>
    /// </summary>
    internal void EnsureDirectExecutionSpace(bool includeOriginalCapture = true)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (!_isDirect)
        {
            throw new InvalidOperationException(
                "The direct execution space check is only defined for a direct EDL raw preparation.");
        }

        long requiredBytes = ComputeDirectPlannedExecutionSpace(
            _geometries,
            _gptWriteRegions,
            _boardSummary.Length,
            _package.LinuxBootRaw.Length,
            _package.LinuxRootRaw.Length,
            _backupFiles,
            includeOriginalCapture,
            _directAvbNodes,
            _directGblPlan?.Inputs);

        RequireDirectExecutionSpaceAvailable(
            requiredBytes,
            InternalInstallPackageSnapshot.TryGetAvailableFreeBytes(_evidenceDirectory));
    }

    /// <summary>
    /// Binds one finished builder result to the exact target slot, the exact source slot whose five claims
    /// were built, that source's own recovered material, the actual target candidate partition length, the
    /// source material's loader budget, the round-trip raw hash, the manifest, the two package DTBs and the
    /// fixed six-role payload map. The material is the built result's own fact, so no second pre-build
    /// recovery read is compared with itself. The BSS-expanded Linux payload is deliberately never compared
    /// with the original package kernel digest.
    /// </summary>
    private static void RequireBuiltBoot(
        EdlRawBuiltBoot built,
        string slot,
        string sourceSlot,
        EdlRawPackageContract contract,
        InternalInstallPackageSnapshot snapshot,
        IReadOnlyDictionary<string, EdlCapturedRegion> files)
    {
        if (!string.Equals(built.Slot, slot, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The builder returned a different slot than the one requested.");
        }

        if (!string.Equals(built.SourceSlot, sourceSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' result names a different source slot than the one requested.");
        }

        if (built.UsesInactiveSlotBackup != !string.Equals(sourceSlot, slot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' result disagrees with its own source-slot kind.");
        }

        InternalSlotMaterial actual = built.SlotMaterial;
        if (!string.Equals(actual.Slot, sourceSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' material is not the material recovered from its source slot's claims.");
        }

        RequireSource(actual, "current_boot", Claim(files, "boot_" + sourceSlot));
        RequireSource(actual, "vendor_boot", Claim(files, "vendor_boot_" + sourceSlot));
        RequireSource(actual, "init_boot", Claim(files, "init_boot_" + sourceSlot));
        RequireSource(actual, "abl", Claim(files, "abl_" + sourceSlot));
        RequireSource(actual, "xbl_config", Claim(files, "xbl_config_" + sourceSlot));

        if (built.BaseImage.Length != actual.BaseImageLength
            || !SameSha(built.BaseImage.Sha256, actual.BaseImageSha256))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' base image is not the actual recovered base.");
        }

        EdlCapturedRegion boot = files["boot_" + slot];
        if (built.CandidateBoot.Length != boot.Length)
        {
            throw new InvalidDataException(
                "The built '" + slot + "' candidate does not cover the full captured boot partition.");
        }

        long loaderBudget = actual.LoaderBudget.MaxRawBytes;
        if (built.PackedRaw.Length <= 0 || built.PackedRaw.Length > loaderBudget)
        {
            throw new InvalidDataException(
                "The built '" + slot + "' packed raw image is outside the loader budget recovered from source slot '"
                + sourceSlot + "'.");
        }

        if (!SameSha(built.Envelope.CandidateBoot.Sha256, built.CandidateBoot.Sha256)
            || built.Envelope.CandidateBoot.Length != built.CandidateBoot.Length)
        {
            throw new InvalidDataException(
                "The built '" + slot + "' envelope does not describe the actual candidate boot.");
        }

        if (!SameSha(built.RoundTripRawSha256, built.PackedRaw.Sha256))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' round-trip raw image is not the packed raw image.");
        }

        if (!SameSha(built.PackageManifestFingerprint, snapshot.ManifestFingerprint)
            || !SameSha(built.PackageManifestFingerprint, contract.ManifestFingerprint))
        {
            throw new InvalidDataException(
                "The built '" + slot + "' result is not bound to the captured package manifest.");
        }

        RequireDtbEvidence(
            built.NormalDtb,
            RequireContractArtifact(contract, "dtb-normal"),
            contract.BootRecipe.NormalBootArgs,
            EdlRawDtbKind.Normal,
            contract.DeviceModel);

        RequireDtbEvidence(
            built.DiagnosticDtb,
            RequireContractArtifact(contract, "dtb-diagnostic"),
            contract.BootRecipe.DiagnosticBootArgs,
            EdlRawDtbKind.Diagnostic,
            contract.DeviceModel);

        RequirePayloadMap(built.UnpackedPayloadSha256, actual, built.NormalDtb, built.DiagnosticDtb, contract);
    }

    /// <summary>
    /// Cheap eight-byte trigger over the already bound backup path. It is only a hint that an inactive
    /// target might be factory zero; it proves nothing, so a false positive is settled by the strict
    /// five-file proof and a false negative falls back to the original same-slot reader.
    /// </summary>
    private static bool IsBootHeaderZero(VerifiedEdlFile boot, CancellationToken cancellationToken)
    {
        using FileStream stream = OpenRead(boot.Path);
        byte[] prefix = ReadPrefix(stream, 8, cancellationToken);
        if (prefix.Length != 8)
        {
            return false;
        }

        foreach (byte value in prefix)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static EdlRawArtifact RequireContractArtifact(EdlRawPackageContract contract, string role)
    {
        if (!contract.Artifacts.TryGetValue(role, out EdlRawArtifact? artifact) || artifact is null)
        {
            throw new InvalidDataException("The direct contract carries no '" + role + "' artifact.");
        }

        return artifact;
    }

    private static void RequireDtbEvidence(
        EdlRawDtbEvidence evidence,
        EdlRawArtifact artifact,
        string bootArgs,
        EdlRawDtbKind kind,
        string model)
    {
        if (evidence.Length != artifact.Bytes
            || !SameSha(evidence.Sha256, artifact.Sha256)
            || evidence.Kind != kind
            || !string.Equals(evidence.DeviceModel, model, StringComparison.Ordinal)
            || !string.Equals(evidence.BootArgs, bootArgs, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A staged direct DTB is not the actual package artifact, model or boot recipe.");
        }
    }

    private static void RequirePayloadMap(
        IReadOnlyDictionary<string, string> payloads,
        InternalSlotMaterial material,
        EdlRawDtbEvidence normalDtb,
        EdlRawDtbEvidence diagnosticDtb,
        EdlRawPackageContract contract)
    {
        string[] required = { "base", "linux-padded", "runtime", "dtb-normal", "dtb-diagnostic", "initramfs" };
        if (payloads.Count != required.Length)
        {
            throw new InvalidDataException("The unpacked payload map does not carry exactly the six fixed roles.");
        }

        foreach (string role in required)
        {
            if (!payloads.TryGetValue(role, out string? sha256) || sha256 is null)
            {
                throw new InvalidDataException("The unpacked payload map is missing the '" + role + "' role.");
            }

            RequireSha256(sha256, "the unpacked '" + role + "' digest");
        }

        if (!SameSha(payloads["base"], material.BaseImageSha256)
            || !SameSha(payloads["runtime"], RequireContractArtifact(contract, "runtime").Sha256)
            || !SameSha(payloads["dtb-normal"], normalDtb.Sha256)
            || !SameSha(payloads["dtb-diagnostic"], diagnosticDtb.Sha256)
            || !SameSha(payloads["initramfs"], RequireContractArtifact(contract, "initramfs").Sha256))
        {
            throw new InvalidDataException(
                "The unpacked payload map does not carry the actual base, runtime, DTB and initramfs facts.");
        }

        // 'linux-padded' is the BSS-expanded image; it must never be compared with the package kernel digest.
    }

    /// <summary>
    /// Copies the builder's small verification report into this preparation's evidence directory as a new
    /// CreateNew file and holds a read lease over the copied bytes, so the report survives the builder
    /// result's own child cleanup. On any refusal only this new file is removed.
    /// </summary>
    private static HeldClaim CopyVerifiedReport(
        EdlRawBuiltBoot built,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        string target = Path.Combine(
            evidenceDirectory, "direct-slot-" + built.Slot + "-verification.json");

        if (File.Exists(target))
        {
            throw new IOException("The direct verification report evidence name is already in use.");
        }

        FileStream? held = null;
        bool created = false;

        try
        {
            using (FileStream source = OpenRead(built.VerificationReport.Path))
            {
                if (source.Length != built.VerificationReport.Length)
                {
                    throw new InvalidDataException("The builder verification report changed length.");
                }

                string sourceSha256 = HashHeld(source, cancellationToken);
                if (!SameSha(sourceSha256, built.VerificationReport.Sha256))
                {
                    throw new InvalidDataException("The builder verification report changed after the build.");
                }

                using FileStream destination = new(
                    target, FileMode.CreateNew, FileAccess.Write, FileShare.None, HashBufferBytes);
                created = true;

                source.Position = 0;
                byte[] buffer = new byte[HashBufferBytes];
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    destination.Write(buffer, 0, read);
                }

                destination.Flush(flushToDisk: true);
            }

            held = OpenRead(target);
            if (held.Length != built.VerificationReport.Length)
            {
                throw new InvalidDataException("The copied verification report has a different length.");
            }

            string sha256 = HashHeld(held, cancellationToken);
            if (!SameSha(sha256, built.VerificationReport.Sha256))
            {
                throw new InvalidDataException("The copied verification report does not match its verified bytes.");
            }

            HeldClaim claim = new(
                "direct-slot-" + built.Slot + "-verification-report",
                target,
                held.Length,
                sha256,
                held);
            held = null;
            claims.Add(claim);
            return claim;
        }
        catch
        {
            held?.Dispose();

            if (created)
            {
                TryDeleteFile(target);
            }

            throw;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The refusal that triggered this cleanup stays the observable outcome.
        }
    }

    // ------------------------------------------------------------------ revalidation

    /// <summary>
    /// Re-hashes every held local claim - the package snapshot, the acquired assets, the backup manifest, all 52
    /// backup files, the nine prepared artifacts, the confirmation record and every device evidence file.
    /// </summary>
    internal async Task RevalidateLocalAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();

        await _package.RevalidateAsync(cancellationToken).ConfigureAwait(false);

        if (_isDirect)
        {
            await DirectAssets.RevalidateAsync(cancellationToken).ConfigureAwait(false);

            if (_directGblPlan is not null)
            {
                // Each preserved wrapper already revalidates the borrowed source build and its own effective
                // candidate, so the raw builds are never revalidated a second time through this pass.
                foreach (string slot in SlotOrder)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await _directGblPlan.Boots[slot].RevalidateAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                foreach (EdlRawBuiltBoot built in _builtBoots)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await built.RevalidateAsync(cancellationToken).ConfigureAwait(false);
                }
            }
        }
        else
        {
            await Assets.RevalidateAsync(cancellationToken).ConfigureAwait(false);
        }

        await Task.Run(() => RevalidateHeldClaims(cancellationToken), cancellationToken).ConfigureAwait(false);
    }

    private void RevalidateHeldClaims(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        foreach (HeldClaim claim in _claims)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (claim.Stream.Length != claim.Length)
            {
                throw new InvalidOperationException(
                    "The held claim '" + claim.Subject + "' no longer has its verified length.");
            }

            string sha256 = HashHeld(claim.Stream, cancellationToken);
            if (!SameSha(sha256, claim.Sha256))
            {
                throw new InvalidOperationException(
                    "The held claim '" + claim.Subject + "' no longer matches its verified SHA-256.");
            }
        }
    }

    // ------------------------------------------------------------------ device verification

    /// <summary>
    /// Captures the original device: six warm geometry probes, the twelve raw GPT windows, the whole
    /// <c>boot_a</c>, <c>boot_b</c> and <c>misc</c> partitions and, on a direct preparation, every actual
    /// metadata node too - three full target readbacks per self-sourced slot, at most six - all into new
    /// evidence files.
    /// <para>
    /// This is the reusable pre-write recheck: every call performs a fresh warm capture and compares it with
    /// the same immutable original claims, so a state flag from the factory never substitutes for the read.
    /// A metadata node is read over its whole actual target range and matched to its own original backup
    /// length and SHA-256 exactly like a base partition. The factory and the execution phase use different
    /// evidence file names, so no capture is retried or overwritten.
    /// </para>
    /// </summary>
    internal async Task VerifyOriginalDeviceAsync(
        EdlClient client,
        string phase,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        DeviceCapture capture = await CaptureDeviceAsync(
            client,
            RequirePhase(phase),
            post: false,
            _evidenceDirectory,
            _claims,
            _binding,
            _geometries,
            _originalTables,
            postGpt: null,
            _backupFiles,
            maintenanceBoot: null,
            cancellationToken,
            directMetadataNodes: _isDirect ? _directAvbNodes : null,
            directGblGuardRoles: _directGblPlan is null ? null : GetGblGuardRoles(_directGblPlan.Inputs)).ConfigureAwait(false);

        _currentBootSha256 = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(capture.BootSha256, StringComparer.Ordinal));
        _currentMiscSha256 = capture.MiscSha256;
        _deviceEvidence.AddRange(capture.Evidence);
        _originalDeviceVerified = true;
    }

    /// <summary>
    /// Captures the device after the partition write: LUN0 must match the planned post-install table, the other
    /// LUNs the original ones and <c>boot_a</c> the prepared maintenance boot. <c>boot_b</c> must still be the
    /// original bytes. The fresh <c>misc</c> capture is a full read of the expected range whose actual bytes are
    /// held as evidence, but it must only carry the canonical normal-boot BCB allow-state instead of matching the
    /// original <c>misc</c> SHA-256, because the maintenance boot may legitimately change the boot control block.
    /// </summary>
    internal async Task VerifyPostPartitionDeviceAsync(
        EdlClient client,
        string phase,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (!_originalDeviceVerified)
        {
            throw new InvalidOperationException(
                "The post-partition verification requires the original device verification first.");
        }

        DeviceCapture capture = await CaptureDeviceAsync(
            client,
            RequirePhase(phase),
            post: true,
            _evidenceDirectory,
            _claims,
            _binding,
            _geometries,
            _originalTables,
            _postGpt,
            _backupFiles,
            Assets.MaintenanceBoot,
            cancellationToken).ConfigureAwait(false);

        _deviceEvidence.AddRange(capture.Evidence);
    }
    // ------------------------------------------------------------------ prepared state

    /// <summary>
    /// Fills the frozen prepared bag from the verified facts. Only the factory calls this, and only after the
    /// whole preparation succeeded.
    /// </summary>
    internal void FillPreparedState(InternalInstallPrepared.State state)
    {
        ArgumentNullException.ThrowIfNull(state);

        Dictionary<int, string> fingerprints = new();
        foreach (KeyValuePair<int, GptTable> pair in _originalTables)
        {
            fingerprints.Add(pair.Key, pair.Value.SourceFingerprint);
        }

        state.ConfirmationId = _confirmationId;
        state.ProfileId = _toolchain.ProfileId;
        state.AndroidSerial = _binding.AndroidIdentity.Identity.Serial;
        state.SocSerial = _binding.AndroidIdentity.SocSerial;
        state.AndroidBuild = _binding.AndroidIdentity.Identity.Firmware!.DisplayId!;
        state.CurrentSlot = _actualCurrentSlot;
        state.AndroidGiB = _allocation.AndroidBytes / Gib;
        state.LinuxRootBytes = _allocation.LinuxRootBytes;
        state.BoardBackupBytes = _allocation.BackupBytes;
        state.BackupDirectory = _backupDirectory;
        state.EvidenceDirectory = _evidenceDirectory;
        state.Firmware = _binding.AndroidIdentity.Identity.Firmware!;
        state.FastbootLockState = _fastbootLockState;
        state.BootTrustMode = DirectBootTrustMode;
        state.PackageFingerprint = _package.ManifestFingerprint;
        state.PackageBindingSha256 = _package.BindingSha256;
        state.BackupManifestSha256 = _backupManifestSha256;
        state.ArtifactPlanSha256 = _artifactPlanSha256;
        if (_isDirect)
        {
            // The legacy asset digests stay empty on the direct route. Native builder facts are recorded in
            // their own confirmation section, never under these old maintenance/support/toolbox semantics.
            state.MaintenanceBootSha256 = string.Empty;
            state.SupportSha256 = string.Empty;
            state.ToolboxSha256 = string.Empty;
        }
        else
        {
            state.MaintenanceBootSha256 = Assets.MaintenanceBoot.Sha256;
            state.SupportSha256 = Assets.SupportArchive.Sha256;
            state.ToolboxSha256 = MaintenanceProfiles.ToolboxSha256;
        }

        if (_isDirect)
        {
            // One fact per actually built target: the key is the built slot, the source slot is the original
            // Android slot whose five claims were built, and the boot-only treatment is only ever the strict
            // five-file proof's own verdict. The legacy route keeps the prepared bag's default empty map.
            Dictionary<string, InternalInstallAvbSlotFacts> avbSlots = new(StringComparer.Ordinal);

            foreach (EdlRawBuiltBoot built in _directBoots.Values)
            {
                avbSlots.Add(
                    built.Slot,
                    new InternalInstallAvbSlotFacts(built.Slot, built.SourceSlot, built.UsesInactiveSlotBackup));
            }

            state.AvbSlots = new ReadOnlyDictionary<string, InternalInstallAvbSlotFacts>(avbSlots);
        }

        state.CurrentMiscSha256 = _currentMiscSha256;
        state.OriginalGptFingerprints = new ReadOnlyDictionary<int, string>(fingerprints);
        state.Geometries = _geometries;
        state.CurrentBootSha256 = _currentBootSha256;
        state.SlotMaterials = _slotMaterials;
        state.RawUpperBoundBytes = _rawUpperBounds;
    }

    /// <summary>
    /// Releases only the read leases this context owns. Idempotent; never deletes evidence, never touches a
    /// device and never disposes the caller's package, backup set, artifact set, assets or client.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (HeldClaim claim in _claims)
        {
            claim.Stream.Dispose();
        }

        _claims.Clear();

        // The plan only owns the wrappers it created and the files it wrote; it never owns the borrowed source
        // builds, the backup or the caller's assets, so it is released after the claim leases and before the
        // builders' own generated boots. Its own staged input files are the only files removed here.
        DisposeGblBoots(_directGblPlan);
        CleanupGblStagedInputs(_directGblPlan?.Inputs);

        foreach (EdlRawBuiltBoot built in _builtBoots)
        {
            built.Dispose();
        }

        _directAssets?.Dispose();
        _assets?.Dispose();
        _package.Dispose();
    }

    // ------------------------------------------------------------------ raw upper bound

    /// <summary>
    /// Conservative upper bound of the packed raw image the kshim packer can produce for one slot, computed from
    /// the recovered arm64 base, the actual kernel header, the production option residue and the exact payload
    /// lengths. Pure arithmetic; it proves no physical boot.
    /// </summary>
    internal static long ComputeRawUpperBound(
        long baseLength,
        long baseImageSize,
        ulong baseTextOffset,
        long kernelLength,
        long kernelImageSize,
        ulong linuxTextOffset,
        long runtimeLength,
        long dtbLength,
        long initramfsLength)
    {
        if (baseLength < Arm64MinimumBytes)
        {
            throw new InvalidDataException("The recovered base image is shorter than an ARM64 Image header.");
        }

        if (baseImageSize < Arm64MinimumBytes)
        {
            throw new InvalidDataException("The base image declares an image_size below the ARM64 header size.");
        }

        if (kernelLength < Arm64MinimumBytes)
        {
            throw new InvalidDataException("The kernel payload is shorter than an ARM64 Image header.");
        }

        if (kernelImageSize < Arm64MinimumBytes)
        {
            throw new InvalidDataException("The kernel declares an image_size below the ARM64 header size.");
        }

        if (runtimeLength <= 0 || dtbLength <= 0 || initramfsLength <= 0)
        {
            throw new InvalidDataException("The runtime, DTB and initramfs payloads must each be non-empty.");
        }

        // The packer can only place the Linux image on its own 2 MiB grid when the two text offsets agree on the
        // low bits. A pair that disagrees cannot be bounded by this expression and is refused instead of guessed.
        // The subtraction is deliberately unchecked, exactly like the packer's size_t arithmetic.
        ulong residue = unchecked(linuxTextOffset - baseTextOffset);
        if ((residue & (ulong)(TwoMiB - 1)) != 0)
        {
            throw new InvalidDataException(
                "The kernel text offset residue is incompatible with the 2 MiB Linux image alignment.");
        }

        long shimOffset = AlignUp(Math.Max(baseLength, baseImageSize), 4L, "The shim slot overflows.");
        if (shimOffset >= Arm64BranchMaxOffset)
        {
            throw new InvalidDataException(
                "The shim offset " + shimOffset + " is outside the strict ARM64 BL range of "
                + Arm64BranchMaxOffset + " bytes.");
        }

        long cursor = CheckedAdd(shimOffset, runtimeLength, "The packed runtime overflows.");
        cursor = AlignUp(cursor, TwoMiB, "The Linux image alignment overflows.");
        cursor = CheckedAdd(
            cursor,
            AlignUp(Math.Max(kernelLength, kernelImageSize), 4096L, "The Linux reserve overflows."),
            "The packed Linux image overflows.");

        cursor = AlignUp(cursor, 8L, "The packed DTB alignment overflows.");
        cursor = CheckedAdd(cursor, ComputeFdtUpperBound(dtbLength, diagnostic: false), "The packed DTB overflows.");
        cursor = AlignUp(cursor, 8L, "The packed diagnostic DTB alignment overflows.");
        cursor = CheckedAdd(
            cursor, ComputeFdtUpperBound(dtbLength, diagnostic: true), "The packed diagnostic DTB overflows.");

        cursor = AlignUp(cursor, 65536L, "The packed initramfs alignment overflows.");
        cursor = CheckedAdd(cursor, initramfsLength, "The packed initramfs overflows.");

        cursor = AlignUp(cursor, 8L, "The packed manifest alignment overflows.");
        return CheckedAdd(cursor, ManifestUpperBoundBytes, "The packed manifest overflows.");
    }

    /// <summary>
    /// Upper bound of one rewritten flat device tree: the source blob, the new chosen node, the four name strings,
    /// the four property headers and the aligned property data of the production command line.
    /// </summary>
    internal static long ComputeFdtUpperBound(long dtbLength, bool diagnostic)
    {
        if (dtbLength <= 0)
        {
            throw new InvalidDataException("The DTB payload must be non-empty.");
        }

        long data = diagnostic ? DiagnosticFdtDataBytes : NormalFdtDataBytes;
        long total = CheckedAdd(dtbLength, NewChosenBytes, "The rewritten DTB overflows.");
        total = CheckedAdd(total, PropertyNameBytes, "The rewritten DTB overflows.");
        total = CheckedAdd(total, PropertyHeaderBytes, "The rewritten DTB overflows.");
        return CheckedAdd(total, data, "The rewritten DTB overflows.");
    }

    // ------------------------------------------------------------------ package binding

    private static void RequireBoundPackage(
        InternalInstallPackageSnapshot package,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!SameSha(package.ManifestFingerprint, PackageFingerprintPin))
        {
            throw new InvalidOperationException(
                "unsupported-install-package-bound: the selected package manifest is '"
                + package.ManifestFingerprint + "', not the one reviewed production install package.");
        }

        RamInstallSeed seed = package.Seed;

        if (!string.Equals(seed.Commit, SeedCommitPin, StringComparison.Ordinal)
            || !string.Equals(seed.ManifestDigest, SeedManifestDigestPin, StringComparison.Ordinal)
            || !string.Equals(seed.Origin, SeedOriginPin, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "unsupported-install-package-bound: the seed commit, manifest digest or origin is not the reviewed "
                + "production deployment.");
        }

        foreach ((string role, long bytes, string sha256) in PayloadPins)
        {
            VerifiedEdlFile payload = RequireRole(package.Payloads, role);
            if (payload.Length != bytes || !SameSha(payload.Sha256, sha256))
            {
                throw new InvalidOperationException(
                    "unsupported-install-package-bound: the '" + role + "' payload is not the reviewed "
                    + "production payload.");
            }
        }
    }

    private static long RequirePayloadLength(InternalInstallPackageSnapshot package, string role)
    {
        VerifiedEdlFile payload = RequireRole(package.Payloads, role);
        if (payload.Length <= 0)
        {
            throw new InvalidDataException("The package payload '" + role + "' is empty.");
        }

        return payload.Length;
    }

    /// <summary>
    /// Looks the role up case-insensitively but requires exactly one declared key, so a package can never smuggle
    /// a second near-duplicate role past the pinned lookup.
    /// </summary>
    private static VerifiedEdlFile RequireRole(
        IReadOnlyDictionary<string, VerifiedEdlFile> payloads,
        string role)
    {
        VerifiedEdlFile? found = null;
        int matches = 0;

        foreach (KeyValuePair<string, VerifiedEdlFile> pair in payloads)
        {
            if (!string.Equals(pair.Key, role, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            matches++;
            found = pair.Value;
        }

        if (matches != 1 || found is null)
        {
            throw new InvalidDataException(
                "The package must declare the '" + role + "' payload exactly once; it declares it " + matches
                + " times.");
        }

        return found;
    }

    private static KernelHeader ReadKernelHeader(
        InternalInstallPackageSnapshot package,
        CancellationToken cancellationToken)
    {
        VerifiedEdlFile kernel = RequireRole(package.Payloads, "kernel");
        using FileStream stream = OpenRead(kernel.Path);

        if (stream.Length != kernel.Length || stream.Length < Arm64MinimumBytes)
        {
            throw new InvalidDataException("The kernel payload does not carry a complete ARM64 Image header.");
        }

        byte[] header = new byte[Arm64MinimumBytes];
        int offset = 0;
        while (offset < header.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(header, offset, header.Length - offset);
            if (read <= 0)
            {
                throw new InvalidDataException("The kernel payload ended inside its ARM64 Image header.");
            }

            offset += read;
        }

        if (!header.AsSpan(56, 4).SequenceEqual("ARMd"u8))
        {
            throw new InvalidDataException("The kernel payload does not carry the ARM64 Image magic.");
        }

        ulong imageSize = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(16, 8));
        ulong textOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8, 8));

        if (imageSize < Arm64MinimumBytes || imageSize > long.MaxValue)
        {
            throw new InvalidDataException("The kernel declares an unusable image_size.");
        }

        return new KernelHeader((long)imageSize, textOffset);
    }

    // ------------------------------------------------------------------ backup binding

    private static BackupFacts BindBackup(
        InternalBackupSet backup,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(backup.DirectoryPath))
        {
            throw new InvalidDataException("The backup set names no directory.");
        }

        string root = Path.GetFullPath(backup.DirectoryPath);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException("The backup directory is missing: " + root + ".");
        }

        RequireNonReparseDirectory(root, "the backup directory");
        RequireSha256(backup.ManifestSha256, "the backup manifest claim");

        string manifestPath = RequireInside(root, backup.ManifestPath, "the backup manifest");
        FileStream manifestStream = OpenRead(manifestPath);
        long manifestLength;

        try
        {
            // The held stream is the verified PC manifest itself, so its actual length is the authoritative
            // entry length for the board archive; no later file metadata is consulted for it.
            manifestLength = manifestStream.Length;

            claims.Add(new HeldClaim(
                "backup manifest",
                manifestPath,
                manifestLength,
                HashHeld(manifestStream, cancellationToken),
                manifestStream));
        }
        catch
        {
            manifestStream.Dispose();
            throw;
        }

        byte[] manifestBytes = ReadAllBytes(manifestStream, MaximumManifestBytes, cancellationToken);
        string manifestSha256 = Convert.ToHexString(SHA256.HashData(manifestBytes));

        if (!SameSha(manifestSha256, backup.ManifestSha256))
        {
            throw new InvalidDataException(
                "The backup manifest bytes do not hash to the SHA-256 the backup set recorded.");
        }

        using JsonDocument document = JsonDocument.Parse(manifestBytes);
        JsonElement manifest = document.RootElement;

        if (RequireInt64(manifest, "schemaVersion") != 1
            || !string.Equals(RequireString(manifest, "status"), "verified", StringComparison.Ordinal)
            || RequireBoolean(manifest, "userDataIncluded")
            || RequireBoolean(manifest, "superIncluded"))
        {
            throw new InvalidDataException("The backup manifest is not a complete verified internal-install backup.");
        }

        EdlEntryResult binding = backup.Binding
            ?? throw new InvalidDataException("The backup set names no session binding.");
        AndroidMaintenanceIdentity android = binding.AndroidIdentity
            ?? throw new InvalidDataException("The backup binding carries no Android identity.");
        DeviceIdentity identity = android.Identity
            ?? throw new InvalidDataException("The backup binding carries no device identity.");
        FirmwareSnapshot? firmware = identity.Firmware;

        RequireProfileBlock(manifest, backup);

        JsonElement identityElement = RequireObject(manifest, "identity");
        if (!string.Equals(RequireString(identityElement, "androidSerial"), identity.Serial, StringComparison.Ordinal)
            || !string.Equals(RequireString(identityElement, "socSerialDecimal"), android.SocSerial, StringComparison.Ordinal)
            || !SameText(RequireString(identityElement, "busSerialHex"), binding.BusSerialHex)
            || !string.Equals(RequireString(identityElement, "model"), identity.Model, StringComparison.Ordinal)
            || !RequireBoolean(identityElement, "hasInitialSaharaProof"))
        {
            throw new InvalidDataException("The backup manifest identity does not agree with the backup binding.");
        }

        JsonElement firmwareElement = RequireObject(identityElement, "firmware");
        if (firmware is null
            || !string.Equals(RequireString(firmwareElement, "displayId"), firmware.DisplayId, StringComparison.Ordinal)
            || !string.Equals(
                RequireString(firmwareElement, "buildFingerprint"),
                firmware.BuildFingerprint,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(firmwareElement, "androidRelease"),
                firmware.AndroidRelease,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(firmwareElement, "securityPatch"),
                firmware.SecurityPatch,
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(firmwareElement, "androidReportedBootloaderState"),
                firmware.AndroidReportedBootloaderState.ToString(),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The backup manifest firmware does not agree with the backup binding.");
        }

        InternalInstallBackupRoles roles = InternalInstallBackupRoles
            .ForModel(backup.Model)
            .ForCapturedRoles(backup.Files.Keys);
        if (backup.Geometries.Count != 6 || backup.Tables.Count != 6 || backup.Files.Count != roles.TotalFileCount)
        {
            throw new InvalidDataException(
                "A verified internal-install backup exposes six geometries, six tables and exactly "
                + roles.TotalFileCount + " captured files.");
        }

        Dictionary<int, EdlGeometry> geometries = ReadManifestLuns(manifest, backup);
        Dictionary<string, ManifestFile> manifestFiles = ReadManifestFiles(manifest, roles.TotalFileCount);

        RequireSameFileSet(manifestFiles, backup.Files, root);

        Dictionary<string, FileStream> streams = new(StringComparer.Ordinal);
        Dictionary<string, EdlCapturedRegion> regions = new(StringComparer.Ordinal);

        foreach (string role in SortedKeys(manifestFiles))
        {
            cancellationToken.ThrowIfCancellationRequested();

            EdlCapturedRegion region = backup.Files[role];
            string path = RequireInside(root, region.FilePath, "the '" + role + "' capture");
            RequireRegularFile(path, "the '" + role + "' capture");

            FileStream stream = OpenRead(path);
            if (stream.Length != region.Length)
            {
                stream.Dispose();
                throw new InvalidDataException("The '" + role + "' capture changed length after the backup.");
            }

            claims.Add(new HeldClaim(role, path, region.Length, region.Sha256, stream));
            streams.Add(role, stream);
            regions.Add(
                role,
                new EdlCapturedRegion(
                    role,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.SectorSize,
                    region.PartUuid,
                    path,
                    region.Length,
                    region.Sha256));
        }

        Dictionary<int, GptTable> tables = new();
        byte[] lun0Primary = Array.Empty<byte>();
        byte[] lun0Backup = Array.Empty<byte>();

        for (int lun = 0; lun < 6; lun++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            EdlGeometry geometry = geometries[lun];
            long diskBytes = CheckedMultiply(
                geometry.TotalSectors, geometry.SectorSize, "The LUN" + lun + " disk length overflows.");

            EdlCapturedRegion primaryRegion = regions["gpt_lun" + lun + "_primary"];
            EdlCapturedRegion backupRegion = regions["gpt_lun" + lun + "_backup"];

            byte[] primaryBytes = ReadExact(streams[primaryRegion.Role], primaryRegion.Length, cancellationToken);
            byte[] backupBytes = ReadExact(streams[backupRegion.Role], backupRegion.Length, cancellationToken);

            GptTable table = OriginalGptImporter.Parse(
                primaryBytes, backupBytes, geometry.SectorSize, diskBytes);

            GptTable claimed = backup.Tables[lun];
            if (!string.Equals(table.SourceFingerprint, claimed.SourceFingerprint, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The raw LUN" + lun + " capture no longer matches the table the backup verified.");
            }

            RequireSameTable(claimed, table, "the LUN" + lun + " capture");

            tables.Add(lun, table);

            if (lun == 0)
            {
                lun0Primary = primaryBytes;
                lun0Backup = backupBytes;
            }
        }

        // The existing verifier stays the single authority for the model's declared ranges and the actual file
        // hashes.
        InternalInstallArtifacts.VerifyCapturedInputs(regions, geometries, tables, backup.Model, cancellationToken);

        return new BackupFacts
        {
            Directory = root,
            ManifestSha256 = manifestSha256,
            ManifestLength = manifestLength,
            Model = backup.Model,
            ProfileId = backup.ProfileId,
            AndroidBuild = backup.AndroidBuild,
            HardwareId = backup.HardwareId,
            Geometries = new ReadOnlyDictionary<int, EdlGeometry>(geometries),
            Tables = new ReadOnlyDictionary<int, GptTable>(tables),
            Files = new ReadOnlyDictionary<string, EdlCapturedRegion>(regions),
            Lun0Primary = lun0Primary,
            Lun0Backup = lun0Backup,
        };
    }

    private static void RequireProfileBlock(JsonElement manifest, InternalBackupSet backup)
    {
        JsonElement profile = RequireObject(manifest, "profile");
        if (!string.Equals(RequireString(profile, "profileId"), backup.ProfileId, StringComparison.Ordinal)
            || !string.Equals(RequireString(profile, "model"), backup.Model, StringComparison.Ordinal)
            || !string.Equals(RequireString(profile, "androidBuild"), backup.AndroidBuild, StringComparison.Ordinal)
            || !string.Equals(RequireString(profile, "hardwareId"), backup.HardwareId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The backup manifest profile does not agree with the backup set.");
        }
    }

    private static Dictionary<int, EdlGeometry> ReadManifestLuns(
        JsonElement manifest,
        InternalBackupSet backup)
    {
        JsonElement luns = RequireArray(manifest, "luns");
        if (luns.GetArrayLength() != 6)
        {
            throw new InvalidDataException("The backup manifest must describe all six LUNs.");
        }

        Dictionary<int, EdlGeometry> geometries = new();

        foreach (JsonElement element in luns.EnumerateArray())
        {
            int lun = checked((int)RequireInt64(element, "lun"));
            if (lun < 0 || lun > 5 || geometries.ContainsKey(lun))
            {
                throw new InvalidDataException("The backup manifest repeats or invents a LUN number.");
            }

            if (!backup.Geometries.TryGetValue(lun, out EdlGeometry? geometry) || geometry is null)
            {
                throw new InvalidDataException("The backup set exposes no geometry for LUN" + lun + ".");
            }

            int sectorSize = checked((int)RequireInt64(element, "sectorSize"));
            long totalSectors = RequireInt64(element, "totalSectors");
            if (sectorSize != geometry.SectorSize
                || totalSectors != geometry.TotalSectors
                || geometry.Lun != lun)
            {
                throw new InvalidDataException("The backup manifest geometry of LUN" + lun + " changed.");
            }

            GptTable table = backup.Tables[lun];
            if (!string.Equals(RequireString(element, "diskGuid"), table.DiskGuid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    RequireString(element, "sourceFingerprint"),
                    table.SourceFingerprint,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("The backup manifest table identity of LUN" + lun + " changed.");
            }

            RequireSamePartitionArray(RequireArray(element, "partitions"), table, "LUN" + lun);

            geometries.Add(lun, new EdlGeometry(lun, sectorSize, totalSectors));
        }

        return geometries;
    }

    private static void RequireSamePartitionArray(JsonElement partitions, GptTable table, string subject)
    {
        if (partitions.GetArrayLength() != table.Partitions.Count)
        {
            throw new InvalidDataException("The backup manifest entry array of " + subject + " has a different size.");
        }

        int index = 0;
        foreach (JsonElement element in partitions.EnumerateArray())
        {
            GptPartition expected = table.Partitions[index++];
            if (checked((int)RequireInt64(element, "number")) != expected.Number
                || !string.Equals(RequireString(element, "name"), expected.Name, StringComparison.Ordinal)
                || !string.Equals(
                    RequireString(element, "typeGuid"), expected.TypeGuid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    RequireString(element, "partUuid"), expected.PartUuid, StringComparison.OrdinalIgnoreCase)
                || RequireInt64(element, "startSector") != expected.StartSector
                || RequireInt64(element, "sectorCount") != expected.SectorCount
                || RequireUInt64(element, "attributes") != expected.Attributes)
            {
                throw new InvalidDataException("The backup manifest entry " + expected.Number
                    + " of " + subject + " is not the parsed table entry.");
            }
        }
    }

    private static Dictionary<string, ManifestFile> ReadManifestFiles(JsonElement manifest, int totalFileCount)
    {
        JsonElement files = RequireArray(manifest, "files");
        if (files.GetArrayLength() != totalFileCount)
        {
            throw new InvalidDataException(
                "The backup manifest must list exactly " + totalFileCount + " captured files.");
        }

        Dictionary<string, ManifestFile> parsed = new(StringComparer.Ordinal);

        foreach (JsonElement element in files.EnumerateArray())
        {
            string role = RequireString(element, "role");
            if (role.Length == 0 || parsed.ContainsKey(role))
            {
                throw new InvalidDataException("The backup manifest repeats or omits a captured file role.");
            }

            int lun = checked((int)RequireInt64(element, "lun"));
            long startSector = RequireInt64(element, "startSector");
            long sectorCount = RequireInt64(element, "sectorCount");
            int sectorSize = checked((int)RequireInt64(element, "sectorSize"));
            string? partUuid = ReadNullableString(element, "partUuid");
            string relativePath = RequireString(element, "relativePath");
            long length = RequireInt64(element, "length");
            string sha256 = RequireString(element, "sha256");

            if (lun < 0 || lun > 5 || (sectorSize != 512 && sectorSize != 4096) || startSector < 0
                || sectorCount <= 0)
            {
                throw new InvalidDataException("The backup manifest file '" + role + "' declares a bad range.");
            }

            if (CheckedMultiply(sectorCount, sectorSize, "The '" + role + "' range overflows.") != length)
            {
                throw new InvalidDataException("The backup manifest file '" + role + "' declares a bad length.");
            }

            RequireSha256(sha256, "the '" + role + "' digest");

            parsed.Add(
                role,
                new ManifestFile(
                    role, lun, startSector, sectorCount, sectorSize, partUuid, relativePath, length, sha256));
        }

        return parsed;
    }

    private static void RequireSameFileSet(
        IReadOnlyDictionary<string, ManifestFile> manifest,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string root)
    {
        foreach (KeyValuePair<string, ManifestFile> pair in manifest)
        {
            if (!files.TryGetValue(pair.Key, out EdlCapturedRegion? region) || region is null)
            {
                throw new InvalidDataException(
                    "The backup manifest lists the role '" + pair.Key + "', which the backup set does not expose.");
            }

            ManifestFile declared = pair.Value;
            if (declared.Lun != region.Lun
                || declared.StartSector != region.StartSector
                || declared.SectorCount != region.SectorCount
                || declared.SectorSize != region.SectorSize
                || declared.Length != region.Length
                || !SameSha(declared.Sha256, region.Sha256)
                || !OptionalUuidEquals(declared.PartUuid, region.PartUuid))
            {
                throw new InvalidDataException(
                    "The backup manifest metadata of '" + pair.Key + "' does not agree with the captured region.");
            }

            string declaredPath = RequireInside(
                root,
                Path.Combine(root, declared.RelativePath),
                "the '" + pair.Key + "' relative path");
            string capturedPath = RequireInside(root, region.FilePath, "the '" + pair.Key + "' capture");

            if (!string.Equals(declaredPath, capturedPath, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The backup manifest relative path of '" + pair.Key + "' is not the captured file.");
            }
        }

        foreach (KeyValuePair<string, EdlCapturedRegion> pair in files)
        {
            if (!manifest.ContainsKey(pair.Key))
            {
                throw new InvalidDataException(
                    "The backup set exposes the extra role '" + pair.Key + "', which the manifest does not declare.");
            }
        }
    }

    // ------------------------------------------------------------------ artifact binding

    private static ArtifactFacts BindArtifacts(
        InternalArtifactSet artifacts,
        BackupFacts backup,
        DeviceIdentity identity,
        FirmwareSnapshot firmware,
        PackageStorage storage,
        CancellationToken cancellationToken,
        List<HeldClaim> claims)
    {
        if (string.IsNullOrWhiteSpace(artifacts.DirectoryPath))
        {
            throw new InvalidDataException("The artifact set names no directory.");
        }

        string root = Path.GetFullPath(artifacts.DirectoryPath);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException("The artifact directory is missing: " + root + ".");
        }

        RequireNonReparseDirectory(root, "the artifact directory");

        GptTable original = backup.Tables[0];
        EdlGeometry geometry = backup.Geometries[0];
        long diskBytes = CheckedMultiply(
            geometry.TotalSectors, geometry.SectorSize, "The LUN0 disk length overflows.");

        if (artifacts.Allocation.AndroidBytes <= 0 || artifacts.Allocation.AndroidBytes % Gib != 0)
        {
            throw new InvalidDataException("The prepared allocation does not hand Android a whole number of GiB.");
        }

        long androidGiB = artifacts.Allocation.AndroidBytes / Gib;
        InternalAllocationPlan recomputed = InternalPartitionPlanner.Plan(original, androidGiB, storage);

        if (!SameAllocation(recomputed, artifacts.Allocation))
        {
            throw new InvalidDataException(
                "The prepared allocation is not the allocation the original LUN0 table and the package produce.");
        }

        Guid bootUuid = RequireUuid(artifacts.LinuxBoot.PartUuid, "ARMADA_BOOT");
        Guid rootUuid = RequireUuid(artifacts.LinuxRoot.PartUuid, "ARMADA_ROOT");
        Guid backupUuid = RequireUuid(artifacts.BackupPartition.PartUuid, "ARMADA_BACKUP");

        GptRewrite rewrite = InternalInstallArtifacts.BuildGptRewrite(
            backup.Lun0Primary,
            backup.Lun0Backup,
            geometry.SectorSize,
            diskBytes,
            original,
            recomputed,
            bootUuid,
            rootUuid,
            backupUuid);

        RequireSameTable(artifacts.PostGpt, rewrite.PostTable, "the prepared post-install table");
        RequireSameTable(rewrite.PostTable, artifacts.PostGpt, "the rebuilt post-install table");

        Dictionary<string, HeldClaim> held = OpenArtifactClaims(
            artifacts, root, claims, cancellationToken);

        byte[] postPrimaryBytes = ReadExact(
            held["post-gpt-primary"].Stream, held["post-gpt-primary"].Length, cancellationToken);
        byte[] postBackupBytes = ReadExact(
            held["post-gpt-backup"].Stream, held["post-gpt-backup"].Length, cancellationToken);

        GptTable postTable = OriginalGptImporter.Parse(
            postPrimaryBytes, postBackupBytes, geometry.SectorSize, diskBytes);

        if (!string.Equals(postTable.SourceFingerprint, rewrite.PostTable.SourceFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The prepared post-GPT files are not the rebuilt table.");
        }

        RequireSameTable(rewrite.PostTable, postTable, "the prepared post-GPT files");

        if (!SameSha(held["post-gpt-primary"].Sha256, rewrite.PostGptPrimarySha256)
            || !SameSha(held["post-gpt-backup"].Sha256, rewrite.PostGptBackupSha256))
        {
            throw new InvalidDataException("The prepared post-GPT copies do not hash to the rebuilt fragments.");
        }

        RequireWriteRegions(artifacts.GptWriteRegions, rewrite, held);
        RequirePostRegions(artifacts, rewrite, geometry, held);
        RequireBoardSummary(artifacts.BoardSummary, rewrite, held);
        RequireInstallationRecord(
            artifacts,
            held["installation-record"],
            backup.ManifestSha256,
            original,
            rewrite,
            recomputed,
            identity,
            backup.ProfileId,
            backup.AndroidBuild,
            backup.HardwareId);
        RequireSummaryManifest(
            artifacts,
            held["summary-manifest"],
            held["board-summary"],
            rewrite,
            recomputed,
            cancellationToken);

        // The single board archive owner decompresses and validates the whole physical image once; the held
        // count/length/SHA of that image were already checked above, so only the returned inner manifest is
        // bound to the trusted captured files, the verified PC manifest, both rebuilt GPT copies and the record.
        JsonElement recovery;

        try
        {
            recovery = InternalInstallArtifacts.VerifyBoardArchive(
                held["board-summary"].Stream, backup.Model, cancellationToken);
        }
        finally
        {
            held["board-summary"].Stream.Position = 0;
        }

        RequireRecoveryBindings(
            recovery,
            artifacts.InstallationId,
            artifacts.PlanSha256,
            backup.ManifestSha256,
            original.SourceFingerprint,
            rewrite.PostTable.SourceFingerprint,
            PlannedOwnedUuids(rewrite),
            TrustedRecoveryEntries(backup, held));

        return new ArtifactFacts
        {
            Allocation = recomputed,
            PostGpt = rewrite.PostTable,
            LinuxBoot = rewrite.LinuxBoot,
            LinuxRoot = rewrite.LinuxRoot,
            BackupPartition = rewrite.BackupPartition,
            GptWriteRegions = new ReadOnlyCollection<InternalArtifactRegion>(
                new List<InternalArtifactRegion>(artifacts.GptWriteRegions)),
            BoardSummary = new InternalArtifactRegion(
                "board-summary",
                0,
                rewrite.BackupPartition.StartSector,
                rewrite.BackupPartition.SectorCount,
                geometry.SectorSize,
                held["board-summary"].Path,
                BoardArchiveBytes,
                held["board-summary"].Sha256),
            InstallationId = artifacts.InstallationId,
            PlanSha256 = held["installation-record"].Sha256,
            SummaryManifestSha256 = held["summary-manifest"].Sha256,
            Claims = new ReadOnlyDictionary<string, HeldClaim>(held),
        };
    }

    private static Dictionary<string, HeldClaim> OpenArtifactClaims(
        InternalArtifactSet artifacts,
        string root,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        Dictionary<string, HeldClaim> held = new(StringComparer.Ordinal);

        foreach (InternalArtifactRegion region in artifacts.GptWriteRegions)
        {
            Add(region.Role, region.FilePath, region.Length, region.Sha256);
        }

        Add("post-gpt-primary", artifacts.PostGptPrimary.FilePath, artifacts.PostGptPrimary.Length, artifacts.PostGptPrimary.Sha256);
        Add("post-gpt-backup", artifacts.PostGptBackup.FilePath, artifacts.PostGptBackup.Length, artifacts.PostGptBackup.Sha256);
        Add("board-summary", artifacts.BoardSummary.FilePath, artifacts.BoardSummary.Length, artifacts.BoardSummary.Sha256);
        Add("installation-record", artifacts.InstallationRecordPath, -1, artifacts.PlanSha256);
        Add("summary-manifest", artifacts.SummaryManifestPath, -1, artifacts.SummaryManifestSha256);

        if (held.Count != 9)
        {
            throw new InvalidDataException("A prepared artifact set must expose exactly nine output claims.");
        }

        return held;

        void Add(string role, string path, long expectedLength, string expectedSha256)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string fullPath = RequireInside(root, path, "the '" + role + "' output");
            RequireRegularFile(fullPath, "the '" + role + "' output");
            RequireSha256(expectedSha256, "the '" + role + "' claim");

            FileStream stream = OpenRead(fullPath);

            try
            {
                long length = stream.Length;
                if (expectedLength >= 0 && length != expectedLength)
                {
                    throw new InvalidDataException("The '" + role + "' output is " + length
                        + " bytes, not the prepared " + expectedLength + ".");
                }

                string sha256 = HashHeld(stream, cancellationToken);
                if (!SameSha(sha256, expectedSha256))
                {
                    throw new InvalidDataException("The '" + role + "' output changed after the preparation.");
                }

                HeldClaim claim = new(role, fullPath, length, sha256, stream);
                claims.Add(claim);
                held.Add(role, claim);
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
    }

    private static void RequireWriteRegions(
        IReadOnlyList<InternalArtifactRegion> prepared,
        GptRewrite rewrite,
        IReadOnlyDictionary<string, HeldClaim> held)
    {
        if (prepared.Count != 4)
        {
            throw new InvalidDataException("A prepared artifact set must expose exactly four GPT write regions.");
        }

        for (int index = 0; index < rewrite.WriteRegions.Count; index++)
        {
            GptWriteDescriptor planned = rewrite.WriteRegions[index];
            InternalArtifactRegion actual = prepared[index];
            HeldClaim claim = held[planned.Role];

            if (!string.Equals(actual.Role, planned.Role, StringComparison.Ordinal)
                || actual.Lun != 0
                || actual.StartSector != planned.StartSector
                || actual.SectorCount != planned.SectorCount
                || actual.SectorSize != planned.SectorSize
                || actual.Length != planned.Length
                || !SameSha(actual.Sha256, planned.Sha256)
                || !SameSha(claim.Sha256, planned.Sha256))
            {
                throw new InvalidDataException(
                    "The GPT write region '" + planned.Role + "' is not the rebuilt region.");
            }
        }
    }

    private static void RequirePostRegions(
        InternalArtifactSet artifacts,
        GptRewrite rewrite,
        EdlGeometry geometry,
        IReadOnlyDictionary<string, HeldClaim> held)
    {
        int sectorSize = geometry.SectorSize;
        long primaryCount = rewrite.PostPrimaryFragment.Length / sectorSize;
        long backupCount = rewrite.PostBackupFragment.Length / sectorSize;

        RequireRegion(
            artifacts.PostGptPrimary,
            held["post-gpt-primary"],
            "post-gpt-primary",
            0,
            primaryCount,
            sectorSize,
            rewrite.PostPrimaryFragment.Length,
            rewrite.PostGptPrimarySha256);

        RequireRegion(
            artifacts.PostGptBackup,
            held["post-gpt-backup"],
            "post-gpt-backup",
            geometry.TotalSectors - backupCount,
            backupCount,
            sectorSize,
            rewrite.PostBackupFragment.Length,
            rewrite.PostGptBackupSha256);
    }

    private static void RequireBoardSummary(
        InternalArtifactRegion region,
        GptRewrite rewrite,
        IReadOnlyDictionary<string, HeldClaim> held)
    {
        if (!string.Equals(region.Role, "board-summary", StringComparison.Ordinal)
            || region.Lun != 0
            || region.StartSector != rewrite.BackupPartition.StartSector
            || region.SectorCount != rewrite.BackupPartition.SectorCount
            || region.Length != BoardArchiveBytes
            || !SameSha(region.Sha256, held["board-summary"].Sha256))
        {
            throw new InvalidDataException(
                "The board recovery archive does not cover the planned backup partition at the fixed 2 GiB size.");
        }
    }

    private static void RequireRegion(
        InternalArtifactRegion region,
        HeldClaim claim,
        string role,
        long startSector,
        long sectorCount,
        int sectorSize,
        long length,
        string sha256)
    {
        if (!string.Equals(region.Role, role, StringComparison.Ordinal)
            || region.Lun != 0
            || region.StartSector != startSector
            || region.SectorCount != sectorCount
            || region.SectorSize != sectorSize
            || region.Length != length
            || !SameSha(region.Sha256, sha256)
            || !SameSha(claim.Sha256, sha256))
        {
            throw new InvalidDataException("The prepared region '" + role + "' is not the rebuilt region.");
        }
    }

    private static void RequireInstallationRecord(
        InternalArtifactSet artifact,
        HeldClaim claim,
        string backupManifestSha256,
        GptTable original,
        GptRewrite rewrite,
        InternalAllocationPlan allocation,
        DeviceIdentity identity,
        string profileId,
        string androidBuild,
        string hardwareId)
    {
        if (!SameSha(claim.Sha256, artifact.PlanSha256))
        {
            throw new InvalidDataException("The installation record does not hash to the prepared plan id.");
        }

        byte[] bytes = ReadExact(claim.Stream, claim.Length, CancellationToken.None);
        using JsonDocument document = JsonDocument.Parse(bytes);
        JsonElement record = document.RootElement;

        if (RequireInt64(record, "schemaVersion") != 2
            || !string.Equals(RequireString(record, "kind"), InstallationRecordKind, StringComparison.Ordinal)
            || !string.Equals(RequireString(record, "status"), "prepared", StringComparison.Ordinal)
            || !string.Equals(
                RequireString(record, "installationId"),
                artifact.InstallationId.ToString("D"),
                StringComparison.Ordinal)
            || !SameSha(RequireString(record, "backupManifestSha256"), backupManifestSha256)
            || !string.Equals(RequireString(record, "profileId"), profileId, StringComparison.Ordinal)
            || !string.Equals(RequireString(record, "androidBuild"), androidBuild, StringComparison.Ordinal)
            || !string.Equals(RequireString(record, "hardwareId"), hardwareId, StringComparison.Ordinal)
            || !string.Equals(RequireString(record, "model"), identity.Model, StringComparison.Ordinal)
            || !SupportedBoardFormat(RequireString(record, "boardFormat"))
            || RequireArray(record, "excludedRoles").GetArrayLength() != 0)
        {
            throw new InvalidDataException("The installation record is not the prepared install record.");
        }

        JsonElement lun0 = RequireObject(record, "originalLun0");
        if (RequireInt64(lun0, "sectorSize") != original.SectorSize
            || RequireInt64(lun0, "totalSectors") != original.DiskBytes / original.SectorSize
            || !string.Equals(
                RequireString(lun0, "sourceFingerprint"), original.SourceFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The installation record names a different original LUN0 table.");
        }

        RequireAllocation(RequireObject(record, "allocation"), allocation);
        RequireNewPartitions(RequireArray(record, "newPartitions"), rewrite);

        JsonElement post = RequireObject(record, "postGpt");
        if (!string.Equals(
                RequireString(post, "sourceFingerprint"),
                rewrite.PostTable.SourceFingerprint,
                StringComparison.Ordinal)
            || !SameSha(RequireString(post, "primaryFileSha256"), rewrite.PostGptPrimarySha256)
            || !SameSha(RequireString(post, "backupFileSha256"), rewrite.PostGptBackupSha256))
        {
            throw new InvalidDataException("The installation record names a different post-install table.");
        }

        JsonElement writes = RequireArray(record, "gptWrites");
        if (writes.GetArrayLength() != 4)
        {
            throw new InvalidDataException("The installation record must describe the four GPT write regions.");
        }

        int index = 0;
        foreach (JsonElement element in writes.EnumerateArray())
        {
            GptWriteDescriptor descriptor = rewrite.WriteRegions[index++];
            if (!string.Equals(RequireString(element, "role"), descriptor.Role, StringComparison.Ordinal)
                || RequireInt64(element, "startSector") != descriptor.StartSector
                || RequireInt64(element, "sectorCount") != descriptor.SectorCount
                || RequireInt64(element, "sectorSize") != descriptor.SectorSize
                || RequireInt64(element, "length") != descriptor.Length
                || !SameSha(RequireString(element, "sha256"), descriptor.Sha256))
            {
                throw new InvalidDataException("The installation record describes a different GPT write region.");
            }
        }
    }

    private static void RequireSummaryManifest(
        InternalArtifactSet artifact,
        HeldClaim claim,
        HeldClaim boardArchive,
        GptRewrite rewrite,
        InternalAllocationPlan allocation,
        CancellationToken cancellationToken)
    {
        if (!SameSha(claim.Sha256, artifact.SummaryManifestSha256))
        {
            throw new InvalidDataException("The summary manifest does not hash to the prepared summary id.");
        }

        byte[] bytes = ReadExact(claim.Stream, claim.Length, cancellationToken);
        using JsonDocument document = JsonDocument.Parse(bytes);
        JsonElement summary = document.RootElement;

        if (RequireInt64(summary, "schemaVersion") != 2
            || !string.Equals(RequireString(summary, "kind"), SummaryManifestKind, StringComparison.Ordinal)
            || !SupportedBoardFormat(RequireString(summary, "boardFormat"))
            || RequireArray(summary, "excludedRoles").GetArrayLength() != 0
            || !string.Equals(
                RequireString(summary, "installationId"),
                artifact.InstallationId.ToString("D"),
                StringComparison.Ordinal)
            || !string.Equals(
                RequireString(summary, "planSha256"),
                artifact.PlanSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The summary manifest is not the prepared artifact summary.");
        }

        JsonElement archive = RequireObject(summary, "boardArchive");
        if (RequireInt64(archive, "length") != BoardArchiveBytes
            || !SameSha(RequireString(archive, "sha256"), artifact.BoardSummary.Sha256))
        {
            throw new InvalidDataException(
                "The summary manifest does not describe the fixed 2 GiB board archive.");
        }

        // Only the fixed 64 KiB outer header prefix of the same held image is read here. The owning physical
        // parser subsequently validates the header and every byte after it before Ready; this comparison uses
        // the tiny JSON alone.
        byte[] header = ReadPrefix(boardArchive.Stream, BoardArchiveHeaderBytes, cancellationToken);
        using JsonDocument headerDocument = JsonDocument.Parse(header);

        RequireBoardArchiveSummary(summary, headerDocument.RootElement, artifact.SummaryUsedBytes);

        JsonElement backupPartition = RequireObject(summary, "backupPartition");
        if (RequireInt64(backupPartition, "number") != rewrite.BackupPartition.Number
            || !string.Equals(
                RequireString(backupPartition, "partUuid"),
                rewrite.BackupPartition.PartUuid,
                StringComparison.OrdinalIgnoreCase)
            || RequireInt64(backupPartition, "startSector") != allocation.BackupStartSector
            || RequireInt64(backupPartition, "sectorCount") != allocation.BackupSectorCount)
        {
            throw new InvalidDataException("The summary manifest names a different backup partition.");
        }

        JsonElement writes = RequireArray(summary, "gptWrites");
        if (writes.GetArrayLength() != 4)
        {
            throw new InvalidDataException("The summary manifest must describe the four GPT write regions.");
        }

        int index = 0;
        foreach (JsonElement element in writes.EnumerateArray())
        {
            GptWriteDescriptor descriptor = rewrite.WriteRegions[index++];
            if (!string.Equals(RequireString(element, "role"), descriptor.Role, StringComparison.Ordinal)
                || RequireInt64(element, "startSector") != descriptor.StartSector
                || RequireInt64(element, "sectorCount") != descriptor.SectorCount
                || RequireInt64(element, "sectorSize") != descriptor.SectorSize
                || RequireInt64(element, "length") != descriptor.Length
                || !SameSha(RequireString(element, "sha256"), descriptor.Sha256))
            {
                throw new InvalidDataException("The summary manifest describes a different GPT write region.");
            }
        }

        JsonElement post = RequireObject(summary, "postGpt");
        RequireSummaryRegion(RequireObject(post, "primary"), artifact.PostGptPrimary);
        RequireSummaryRegion(RequireObject(post, "backup"), artifact.PostGptBackup);
    }

    private static void RequireSummaryRegion(JsonElement element, InternalArtifactRegion region)
    {
        if (!string.Equals(RequireString(element, "role"), region.Role, StringComparison.Ordinal)
            || RequireInt64(element, "startSector") != region.StartSector
            || RequireInt64(element, "sectorCount") != region.SectorCount
            || RequireInt64(element, "length") != region.Length
            || !SameSha(RequireString(element, "sha256"), region.Sha256))
        {
            throw new InvalidDataException("The summary manifest describes a different post-GPT copy.");
        }
    }

    /// <summary>
    /// Compares the summary manifest's compressed archive metadata with the actual fixed 64 KiB outer header of
    /// the held image. Pure JSON comparison of two already parsed values: the 64 KiB plus compressed bytes used
    /// length must be the summary's own used length, and the summary must repeat the header's real metadata.
    /// </summary>
    private static void RequireBoardArchiveSummary(
        JsonElement summary,
        JsonElement outer,
        long summaryUsedBytes)
    {
        JsonElement archive = RequireObject(summary, "boardArchive");

        if (RequireInt64(outer, "imageBytes") != BoardArchiveBytes
            || RequireInt64(outer, "headerBytes") != BoardArchiveHeaderBytes
            || RequireInt64(outer, "payloadOffset") != BoardArchiveHeaderBytes)
        {
            throw new InvalidDataException(
                "The board archive header does not describe the fixed 2 GiB image and 64 KiB payload offset.");
        }

        long schema = RequireInt64(outer, "schemaVersion");
        if (schema is not (2 or 3))
            throw new InvalidDataException("The board archive schema is unsupported.");
        string expectedFormat = schema == 3 ? BootSettingsRegion.Format : BoardFormat;
        long payloadLimit = schema == 3 ? BootSettingsRegion.Offset : BoardArchiveBytes;
        if (RequireString(summary, "boardFormat") != expectedFormat)
            throw new InvalidDataException("The summary and board archive formats differ.");
        long compressedBytes = RequireInt64(outer, "compressedBytes");
        if (compressedBytes <= 0 || compressedBytes > payloadLimit - BoardArchiveHeaderBytes)
        {
            throw new InvalidDataException(
                "The board archive header carries an impossible compressed length.");
        }

        long usedBytes = CheckedAdd(
            BoardArchiveHeaderBytes, compressedBytes, "The board archive used length overflows.");

        if (RequireInt64(archive, "usedBytes") != summaryUsedBytes
            || summaryUsedBytes != usedBytes
            || !string.Equals(RequireString(archive, "format"), expectedFormat, StringComparison.Ordinal)
            || RequireInt64(archive, "payloadOffset") != BoardArchiveHeaderBytes
            || RequireInt64(archive, "compressedBytes") != compressedBytes
            || !SameSha(RequireString(archive, "compressedSha256"), RequireString(outer, "compressedSha256"))
            || RequireInt64(archive, "uncompressedTarBytes") != RequireInt64(outer, "uncompressedTarBytes"))
        {
            throw new InvalidDataException(
                "The summary manifest does not carry the actual board archive compressed metadata.");
        }

        JsonElement recoveryManifest = RequireObject(summary, "recoveryManifest");
        if (!string.Equals(
                RequireString(recoveryManifest, "fileName"),
                RecoveryManifestFileName,
                StringComparison.Ordinal)
            || RequireInt64(recoveryManifest, "length") != BoardArchiveHeaderBytes
            || !SameSha(
                RequireString(recoveryManifest, "sha256"),
                RequireString(outer, "recoveryManifestSha256")))
        {
            throw new InvalidDataException(
                "The summary manifest does not describe the inner recovery manifest.");
        }
    }

    /// <summary>
    /// Binds the inner recovery manifest returned by the board archive verifier to the trusted prepared facts:
    /// the installation identity, the rebuilt GPT fingerprints and owned UUIDs in plan order, and one exact
    /// entry for every captured backup file plus the PC manifest, both GPT copies and the record. The entry
    /// offsets stay structural data of the owning parser and are never interpreted as physical image offsets.
    /// </summary>
    private static void RequireRecoveryBindings(
        JsonElement recovery,
        Guid installationId,
        string planSha256,
        string backupManifestSha256,
        string originalFingerprint,
        string postFingerprint,
        IReadOnlyList<string> ownedPartitionUuids,
        IReadOnlyDictionary<string, (string Path, long Length, string Sha256)> expectedEntries)
    {
        ArgumentNullException.ThrowIfNull(ownedPartitionUuids);
        ArgumentNullException.ThrowIfNull(expectedEntries);

        if (RequireInt64(recovery, "schemaVersion") != 2
            || !string.Equals(RequireString(recovery, "kind"), RecoveryManifestKind, StringComparison.Ordinal)
            || !string.Equals(
                RequireString(recovery, "offsetSpace"), RecoveryOffsetSpace, StringComparison.Ordinal)
            || RequireArray(recovery, "excludedRoles").GetArrayLength() != 0
            || !string.Equals(
                RequireString(recovery, "installationId"),
                installationId.ToString("D"),
                StringComparison.OrdinalIgnoreCase)
            || !SameSha(RequireString(recovery, "planSha256"), planSha256)
            || !SameSha(RequireString(recovery, "pcBackupManifestSha256"), backupManifestSha256)
            || !SameSha(RequireString(recovery, "originalGptSourceFingerprint"), originalFingerprint)
            || !SameSha(RequireString(recovery, "postGptSourceFingerprint"), postFingerprint))
        {
            throw new InvalidDataException(
                "The board recovery manifest is not bound to this prepared install.");
        }

        JsonElement owned = RequireArray(recovery, "ownedPartitionUuids");
        if (owned.GetArrayLength() != ownedPartitionUuids.Count)
        {
            throw new InvalidDataException(
                "The board recovery manifest does not own exactly the " + ownedPartitionUuids.Count
                + " planned partition UUIDs.");
        }

        int ownedIndex = 0;
        foreach (JsonElement element in owned.EnumerateArray())
        {
            string expectedUuid = ownedPartitionUuids[ownedIndex++];

            if (element.ValueKind != JsonValueKind.String
                || !Guid.TryParse(element.GetString(), out Guid actual)
                || !Guid.TryParse(expectedUuid, out Guid expected)
                || actual != expected)
            {
                throw new InvalidDataException(
                    "The board recovery manifest owns a different partition UUID at position " + ownedIndex + ".");
            }
        }

        JsonElement entries = RequireArray(recovery, "entries");
        if (entries.GetArrayLength() != expectedEntries.Count)
        {
            throw new InvalidDataException(
                "The board recovery manifest lists " + entries.GetArrayLength() + " entries, not the "
                + expectedEntries.Count + " trusted captured, manifest, GPT and record files.");
        }

        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> paths = new(StringComparer.Ordinal);

        foreach (JsonElement entry in entries.EnumerateArray())
        {
            string role = RequireString(entry, "role");
            string path = RequireString(entry, "path");
            long length = RequireInt64(entry, "length");
            string sha256 = RequireString(entry, "sha256");

            if (!roles.Add(role))
            {
                throw new InvalidDataException(
                    "The board recovery manifest repeats the entry role '" + role + "'.");
            }

            if (!paths.Add(path))
            {
                throw new InvalidDataException(
                    "The board recovery manifest repeats the entry path '" + path + "'.");
            }

            if (!expectedEntries.TryGetValue(role, out (string Path, long Length, string Sha256) expected))
            {
                throw new InvalidDataException(
                    "The board recovery manifest carries the unexpected entry role '" + role + "'.");
            }

            if (!string.Equals(path, expected.Path, StringComparison.Ordinal)
                || length != expected.Length
                || !SameSha(sha256, expected.Sha256))
            {
                throw new InvalidDataException(
                    "The board recovery entry '" + role + "' is not the trusted file of this preparation.");
            }
        }
    }

    /// <summary>
    /// The three partition UUIDs the rebuilt post-install table owns, in plan order. Read from the rebuilt
    /// table itself, never from a caller claim or a JSON placeholder.
    /// </summary>
    private static IReadOnlyList<string> PlannedOwnedUuids(GptRewrite rewrite)
    {
        if (rewrite.NewPartitions.Count != 3)
        {
            throw new InvalidDataException(
                "A prepared post-install table must own exactly three new partition UUIDs.");
        }

        List<string> uuids = new(3);
        foreach (NewPartition partition in rewrite.NewPartitions)
        {
            uuids.Add(partition.PartUuid.ToString("D"));
        }

        return uuids;
    }

    /// <summary>
    /// The trusted board archive entries derived from the verified backup claims, the held PC manifest stream
    /// and the prepared outputs: every captured role as itself plus <c>.bin</c>, the PC manifest, both rebuilt
    /// GPT copies and the installation record. Exactly one capture per role of the model plus those four.
    /// </summary>
    private static IReadOnlyDictionary<string, (string Path, long Length, string Sha256)> TrustedRecoveryEntries(
        BackupFacts backup,
        IReadOnlyDictionary<string, HeldClaim> held)
    {
        Dictionary<string, (string Path, long Length, string Sha256)> entries = new(StringComparer.Ordinal);

        foreach (KeyValuePair<string, EdlCapturedRegion> pair in backup.Files)
        {
            if (BackupPartitionPolicy.IsExcluded(pair.Key))
            {
                continue;
            }

            entries.Add(pair.Key, (pair.Key + ".bin", pair.Value.Length, pair.Value.Sha256));
        }

        entries.Add(
            "pc-backup-manifest",
            ("pc-backup-manifest.json", backup.ManifestLength, backup.ManifestSha256));
        entries.Add(
            "post-gpt-primary",
            ("post-gpt-primary.bin", held["post-gpt-primary"].Length, held["post-gpt-primary"].Sha256));
        entries.Add(
            "post-gpt-backup",
            ("post-gpt-backup.bin", held["post-gpt-backup"].Length, held["post-gpt-backup"].Sha256));
        entries.Add(
            "installation-record",
            ("installation-record.json", held["installation-record"].Length, held["installation-record"].Sha256));

        List<string> filteredRoles = new();
        foreach (string role in backup.Files.Keys)
        {
            if (!BackupPartitionPolicy.IsExcluded(role))
            {
                filteredRoles.Add(role);
            }
        }

        int totalFileCount = InternalInstallBackupRoles
            .ForModel(backup.Model)
            .ForCapturedRoles(filteredRoles)
            .TotalFileCount;
        if (entries.Count != totalFileCount + 4)
        {
            throw new InvalidDataException(
                "The trusted board recovery entries must be exactly " + totalFileCount
                + " captured files plus the PC manifest, both GPT copies and the installation record.");
        }

        return entries;
    }

    private static void RequireAllocation(JsonElement element, InternalAllocationPlan allocation)
    {
        if (RequireInt64(element, "sectorSize") != allocation.SectorSize
            || RequireInt64(element, "originalUserdataEndSectorExclusive") != allocation.OriginalUserdataEndSectorExclusive
            || RequireInt64(element, "androidBytes") != allocation.AndroidBytes
            || RequireInt64(element, "androidSectorCount") != allocation.AndroidSectorCount
            || RequireInt64(element, "androidEndSectorExclusive") != allocation.AndroidEndSectorExclusive
            || RequireInt64(element, "linuxBytes") != allocation.LinuxBytes
            || RequireInt64(element, "linuxBootBytes") != allocation.LinuxBootBytes
            || RequireInt64(element, "linuxRootBytes") != allocation.LinuxRootBytes
            || RequireInt64(element, "estimatedLinuxDataBytes") != allocation.EstimatedLinuxDataBytes
            || RequireInt64(element, "linuxBootStartSector") != allocation.LinuxBootStartSector
            || RequireInt64(element, "linuxBootSectorCount") != allocation.LinuxBootSectorCount
            || RequireInt64(element, "linuxRootStartSector") != allocation.LinuxRootStartSector
            || RequireInt64(element, "linuxRootSectorCount") != allocation.LinuxRootSectorCount
            || RequireInt64(element, "backupBytes") != allocation.BackupBytes
            || RequireInt64(element, "backupStartSector") != allocation.BackupStartSector
            || RequireInt64(element, "backupSectorCount") != allocation.BackupSectorCount
            || RequireInt64(element, "backupEndSectorExclusive") != allocation.BackupEndSectorExclusive
            || RequireInt64(element, "alignmentGapSectors") != allocation.AlignmentGapSectors
            || RequireInt64(element, "tailUnallocatedSectors") != allocation.TailUnallocatedSectors
            || RequireInt64(element, "alignmentLossBytes") != allocation.AlignmentLossBytes)
        {
            throw new InvalidDataException("The installation record carries a different allocation.");
        }

        JsonElement userdata = RequireObject(element, "originalUserdata");
        GptPartition expected = allocation.OriginalUserdata;
        if (RequireInt64(userdata, "number") != expected.Number
            || !string.Equals(RequireString(userdata, "name"), expected.Name, StringComparison.Ordinal)
            || !string.Equals(RequireString(userdata, "typeGuid"), expected.TypeGuid, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(RequireString(userdata, "partUuid"), expected.PartUuid, StringComparison.OrdinalIgnoreCase)
            || RequireInt64(userdata, "startSector") != expected.StartSector
            || RequireInt64(userdata, "sectorCount") != expected.SectorCount
            || RequireUInt64(userdata, "attributes") != expected.Attributes)
        {
            throw new InvalidDataException("The installation record carries a different original userdata entry.");
        }
    }

    private static void RequireNewPartitions(JsonElement element, GptRewrite rewrite)
    {
        if (element.GetArrayLength() != 3)
        {
            throw new InvalidDataException("The installation record must describe the three new partitions.");
        }

        int index = 0;
        foreach (JsonElement entry in element.EnumerateArray())
        {
            NewPartition planned = rewrite.NewPartitions[index++];
            if (!string.Equals(RequireString(entry, "name"), planned.Name, StringComparison.Ordinal)
                || RequireInt64(entry, "number") != planned.Number
                || !string.Equals(
                    RequireString(entry, "partUuid"),
                    planned.PartUuid.ToString("D").ToUpperInvariant(),
                    StringComparison.Ordinal)
                || RequireInt64(entry, "startSector") != planned.StartSector
                || RequireInt64(entry, "sectorCount") != planned.SectorCount)
            {
                throw new InvalidDataException("The installation record describes a different new partition.");
            }
        }
    }

    // ------------------------------------------------------------------ slot materials

    private static async Task<InternalSlotMaterial> AnalyzeSlotAsync(
        string slot,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        CancellationToken cancellationToken)
    {
        VerifiedEdlFile boot = Claim(files, "boot_" + slot);
        VerifiedEdlFile vendorBoot = Claim(files, "vendor_boot_" + slot);
        VerifiedEdlFile initBoot = Claim(files, "init_boot_" + slot);
        VerifiedEdlFile abl = Claim(files, "abl_" + slot);
        VerifiedEdlFile xblConfig = Claim(files, "xbl_config_" + slot);

        InternalSlotMaterial material = await InternalSlotMaterialReader
            .AnalyzeAsync(slot, boot, vendorBoot, initBoot, abl, xblConfig, cancellationToken)
            .ConfigureAwait(false);

        if (!string.Equals(material.Slot, slot, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The slot material reader returned a different slot.");
        }

        RequireSource(material, "current_boot", boot);
        RequireSource(material, "vendor_boot", vendorBoot);
        RequireSource(material, "init_boot", initBoot);
        RequireSource(material, "abl", abl);
        RequireSource(material, "xbl_config", xblConfig);

        return material;
    }

    private static void RequireSource(InternalSlotMaterial material, string role, VerifiedEdlFile claim)
    {
        if (!material.SourceSha256.TryGetValue(role, out string? sha256)
            || !material.SourceLengths.TryGetValue(role, out long length)
            || !SameSha(sha256, claim.Sha256)
            || length != claim.Length)
        {
            throw new InvalidDataException(
                "The '" + material.Slot + "' slot material does not carry the verified '" + role + "' claim.");
        }
    }

    private static VerifiedEdlFile Claim(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string role)
    {
        if (!files.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
        {
            throw new InvalidDataException("The backup set carries no '" + role + "' capture.");
        }

        return new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);
    }

    // ------------------------------------------------------------------ device capture

    private static async Task<DeviceCapture> CaptureDeviceAsync(
        EdlClient client,
        string phase,
        bool post,
        string evidenceDirectory,
        List<HeldClaim> claims,
        EdlEntryResult binding,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        IReadOnlyDictionary<int, GptTable> originalTables,
        GptTable? postGpt,
        IReadOnlyDictionary<string, EdlCapturedRegion> backupFiles,
        VerifiedEdlFile? maintenanceBoot,
        CancellationToken cancellationToken,
        IReadOnlyList<DirectAvbMetadataNode>? directMetadataNodes = null,
        IReadOnlyList<string>? directGblGuardRoles = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(client);

        if (!client.HasInitialSaharaProof)
        {
            throw new InvalidOperationException(
                "edl-initial-proof-required: the EDL session has no proven initial Sahara loader.");
        }

        RequireSameBinding(binding, client.Binding);

        List<HeldClaim> opened = new();
        DeviceCapture capture = new();

        try
        {
            for (int lun = 0; lun < 6; lun++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                EdlProbeEvidence probe = await client
                    .ProbeAsync(lun, false, cancellationToken)
                    .ConfigureAwait(false);

                if (probe.Geometry is null || probe.Geometry.Lun != lun
                    || probe.Geometry.SectorSize != geometries[lun].SectorSize
                    || probe.Geometry.TotalSectors != geometries[lun].TotalSectors)
                {
                    throw new InvalidOperationException(
                        "The warm probe of LUN" + lun + " does not match the verified geometry.");
                }

                if (!SameText(probe.BusSerialHex, binding.BusSerialHex))
                {
                    throw new InvalidOperationException(
                        "The warm probe of LUN" + lun + " reports a different bus serial.");
                }
            }

            for (int lun = 0; lun < 6; lun++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                EdlGeometry geometry = geometries[lun];
                long diskBytes = CheckedMultiply(
                    geometry.TotalSectors, geometry.SectorSize, "The LUN" + lun + " disk length overflows.");

                string primaryPath = Path.Combine(
                    evidenceDirectory, phase + "-gpt-lun" + lun + "-primary.bin");
                string backupPath = Path.Combine(
                    evidenceDirectory, phase + "-gpt-lun" + lun + "-backup.bin");

                EdlReadEvidence primary = await ReadAsync(
                    client, lun, 0, GptCaptureSectors, primaryPath, geometry, cancellationToken)
                    .ConfigureAwait(false);
                EdlReadEvidence backup = await ReadAsync(
                    client,
                    lun,
                    geometry.TotalSectors - GptCaptureSectors,
                    GptCaptureSectors,
                    backupPath,
                    geometry,
                    cancellationToken).ConfigureAwait(false);

                byte[] primaryBytes = File.ReadAllBytes(primaryPath);
                byte[] backupBytes = File.ReadAllBytes(backupPath);

                GptTable table = OriginalGptImporter.Parse(
                    primaryBytes, backupBytes, geometry.SectorSize, diskBytes);

                GptTable expected = post && lun == 0 && postGpt is not null ? postGpt : originalTables[lun];

                if (!string.Equals(table.SourceFingerprint, expected.SourceFingerprint, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The fresh GPT of LUN" + lun + " is not the expected table for this install step.");
                }

                RequireSameTable(expected, table, "the fresh LUN" + lun + " GPT");

                HeldClaim primaryClaim = Hold(
                    phase + "-gpt-lun" + lun + "-primary",
                    primaryPath,
                    GptCaptureSectors * (long)geometry.SectorSize,
                    primary,
                    cancellationToken);
                opened.Add(primaryClaim);
                claims.Add(primaryClaim);

                HeldClaim backupClaim = Hold(
                    phase + "-gpt-lun" + lun + "-backup",
                    backupPath,
                    GptCaptureSectors * (long)geometry.SectorSize,
                    backup,
                    cancellationToken);
                opened.Add(backupClaim);
                claims.Add(backupClaim);

                capture.Evidence.Add(primary);
                capture.Evidence.Add(backup);
            }

            List<string> captureRoles = new() { "boot_a", "boot_b", "misc" };

            // Every actual metadata node of this preparation joins the three base partitions, so a direct
            // capture reads the whole target range of each one too. The role is already the full partition
            // role, so it names the actual backup the capture must match instead of a bare prefix.
            if (directMetadataNodes is not null)
            {
                foreach (DirectAvbMetadataNode node in directMetadataNodes)
                {
                    captureRoles.Add(node.Role);
                }
            }

            // The guarded GBL roles join the same list only when the base capture does not already name them, so
            // the fresh EFI, selected ABL, current XBL and preserved source metadata are read once as an actual
            // full original range. The existing boot, misc and GPT captures stay exactly as they were.
            if (directGblGuardRoles is not null)
            {
                foreach (string role in directGblGuardRoles)
                {
                    if (!captureRoles.Contains(role))
                    {
                        captureRoles.Add(role);
                    }
                }
            }

            foreach (string role in captureRoles)
            {
                cancellationToken.ThrowIfCancellationRequested();

                EdlCapturedRegion region = backupFiles[role];
                VerifiedEdlFile expected = role == "boot_a" && post && maintenanceBoot is not null
                    ? maintenanceBoot
                    : new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);

                string path = Path.Combine(evidenceDirectory, phase + "-" + role + ".bin");

                EdlReadEvidence evidence = await ReadAsync(
                    client,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    path,
                    geometries[region.Lun],
                    cancellationToken).ConfigureAwait(false);

                bool postMisc = post && role == "misc";
                if (evidence.Length != expected.Length
                    || (!postMisc && !SameSha(evidence.Sha256, expected.Sha256)))
                {
                    throw new InvalidOperationException(
                        "The fresh '" + role + "' bytes are not the expected verified content.");
                }

                HeldClaim claim = Hold(phase + "-" + role, path, expected.Length, evidence, cancellationToken);
                opened.Add(claim);
                claims.Add(claim);
                capture.Evidence.Add(evidence);

                if (role == "misc")
                {
                    ValidateMiscBcb(claim.Stream, cancellationToken);
                    capture.MiscSha256 = evidence.Sha256;
                }
                else if (role is "boot_a" or "boot_b")
                {
                    // Only the two actual boot partitions feed the boot hash map. A metadata node is evidence
                    // and a held claim only, never a boot capture fact.
                    capture.BootSha256.Add(role.Substring("boot_".Length), evidence.Sha256);
                }
            }

            return capture;
        }
        catch
        {
            foreach (HeldClaim claim in opened)
            {
                claims.Remove(claim);
                claim.Stream.Dispose();
            }

            throw;
        }
    }

    private static async Task<EdlReadEvidence> ReadAsync(
        EdlClient client,
        int lun,
        long startSector,
        long sectorCount,
        string path,
        EdlGeometry geometry,
        CancellationToken cancellationToken)
    {
        EdlReadEvidence evidence = await client
            .ReadAsync(lun, startSector, sectorCount, path, cancellationToken)
            .ConfigureAwait(false);

        if (evidence.Geometry is null
            || evidence.Geometry.Lun != lun
            || evidence.Geometry.SectorSize != geometry.SectorSize
            || evidence.Geometry.TotalSectors != geometry.TotalSectors
            || evidence.StartSector != startSector
            || evidence.SectorCount != sectorCount
            || evidence.Length != CheckedMultiply(sectorCount, geometry.SectorSize, "The read length overflows."))
        {
            throw new InvalidOperationException("The fresh read of LUN" + lun + " does not match its request.");
        }

        return evidence;
    }

    private static HeldClaim Hold(
        string subject,
        string path,
        long expectedLength,
        EdlReadEvidence evidence,
        CancellationToken cancellationToken)
    {
        FileStream stream = OpenRead(path);

        try
        {
            if (stream.Length != expectedLength)
            {
                throw new InvalidOperationException("A fresh evidence file changed length after the read.");
            }

            string sha256 = HashHeld(stream, cancellationToken);
            if (!SameSha(sha256, evidence.Sha256))
            {
                throw new InvalidOperationException("A fresh evidence file changed after the read.");
            }

            return new HeldClaim(subject, path, expectedLength, sha256, stream);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reads only the 2048 byte bootloader control block prefix of a held <c>misc</c> capture, restores the
    /// stream position and requires the canonical normal-boot allow-state. No other <c>misc</c> byte is parsed.
    /// </summary>
    private static void ValidateMiscBcb(FileStream stream, CancellationToken cancellationToken)
    {
        byte[] prefix = new byte[2048];

        try
        {
            stream.Position = 0;

            int offset = 0;
            while (offset < prefix.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int read = stream.Read(prefix, offset, prefix.Length - offset);
                if (read <= 0)
                {
                    throw new InvalidDataException(
                        "A held misc capture ended inside its bootloader control block.");
                }

                offset += read;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        finally
        {
            stream.Position = 0;
        }

        ValidateNormalBootBcb(prefix);
    }

    /// <summary>
    /// Requires the exact 2048 byte BCB allow-state that the maintenance
    /// <c>portable_gpt.py::make_factory_reset_bcb</c> contract accepts: an empty or canonical
    /// <c>bootonce-bootloader</c> command in <c>command[0:32]</c> and an empty <c>recovery[64:832]</c>.
    /// <para>
    /// This is an internal format check, not a public readiness or trust switch. The status, stage, reserved
    /// and every other byte are unrestricted, preserved and never rewritten here; the input array is not mutated.
    /// </para>
    /// </summary>
    internal static void ValidateNormalBootBcb(byte[] bcb)
    {
        ArgumentNullException.ThrowIfNull(bcb);

        if (bcb.Length != 2048)
        {
            throw new InvalidDataException("The bootloader control block must be exactly 2048 bytes.");
        }

        ReadOnlySpan<byte> command = bcb.AsSpan(0, 32);
        ReadOnlySpan<byte> canonical = "bootonce-bootloader"u8;

        bool empty = true;
        foreach (byte value in command)
        {
            if (value != 0)
            {
                empty = false;
                break;
            }
        }

        if (!empty)
        {
            if (!command.StartsWith(canonical))
            {
                throw new InvalidDataException(
                    "The bootloader control block carries an unexpected boot command.");
            }

            for (int index = canonical.Length; index < command.Length; index++)
            {
                if (command[index] != 0)
                {
                    throw new InvalidDataException(
                        "The bootloader control block command padding is not all zero.");
                }
            }
        }

        if (bcb.AsSpan(64, 768).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException(
                "The bootloader control block already carries a recovery request.");
        }
    }

    private static void RequireSameBinding(EdlEntryResult expected, EdlEntryResult actual)
    {
        if (actual is null
            || actual.AndroidIdentity is null
            || actual.AndroidIdentity.Identity is null
            || !SameText(expected.BusSerialHex, actual.BusSerialHex))
        {
            throw new InvalidOperationException("The EDL session is not bound to the verified device identity.");
        }

        AndroidMaintenanceIdentity left = expected.AndroidIdentity;
        AndroidMaintenanceIdentity right = actual.AndroidIdentity;

        if (!string.Equals(left.SocSerial, right.SocSerial, StringComparison.Ordinal)
            || !string.Equals(left.Identity.Serial, right.Identity.Serial, StringComparison.Ordinal)
            || !string.Equals(left.Identity.Model, right.Identity.Model, StringComparison.Ordinal)
            || !SameFirmware(left.Identity.Firmware, right.Identity.Firmware))
        {
            throw new InvalidOperationException("The EDL session identity changed after preparation.");
        }
    }

    // ------------------------------------------------------------------ confirmation record

    private void SealConfirmation(CancellationToken cancellationToken)
    {
        string path = Path.Combine(_evidenceDirectory, "prepared-confirmation.json");
        byte[] bytes = BuildConfirmation(out string sha256);

        cancellationToken.ThrowIfCancellationRequested();

        using (FileStream writer = new(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, HashBufferBytes))
        {
            writer.Write(bytes, 0, bytes.Length);
            writer.Flush(flushToDisk: true);
        }

        FileStream held = OpenRead(path);

        try
        {
            string readBack = HashHeld(held, cancellationToken);

            if (!SameSha(readBack, sha256) || held.Length != bytes.Length)
            {
                throw new IOException("The prepared confirmation record failed its read back verification.");
            }

            _claims.Add(new HeldClaim("prepared confirmation", path, bytes.Length, sha256, held));
            _confirmationId = sha256;
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    private byte[] BuildConfirmation(out string sha256)
    {
        Dictionary<string, string> boot = new(StringComparer.Ordinal);
        foreach (KeyValuePair<string, string> pair in _currentBootSha256)
        {
            boot.Add(pair.Key, pair.Value);
        }

        using MemoryStream buffer = new();

        using (Utf8JsonWriter json = new(buffer, new JsonWriterOptions { Indented = false }))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 1);
            json.WriteString("kind", "armada-internal-install-confirmation");
            json.WriteString("installationId", _installationId.ToString("D"));
            json.WriteBoolean("androidDataErase", true);

            json.WriteStartArray("slotOrder");
            foreach (string slot in SlotOrder)
            {
                json.WriteStringValue(slot);
            }

            json.WriteEndArray();

            json.WriteStartObject("device");
            json.WriteString("profileId", _toolchain.ProfileId);
            json.WriteString("androidSerial", _binding.AndroidIdentity.Identity.Serial);
            json.WriteString("socSerialDecimal", _binding.AndroidIdentity.SocSerial);
            json.WriteString("busSerialHex", _binding.BusSerialHex);
            json.WriteString("model", _binding.AndroidIdentity.Identity.Model);
            json.WriteString("androidBuild", _binding.AndroidIdentity.Identity.Firmware!.DisplayId);
            json.WriteString("hardwareId", _toolchain.HardwareId);
            json.WriteString("fastbootLockState", _fastbootLockState.ToString());
            json.WriteString("currentSlot", _actualCurrentSlot);

            FirmwareSnapshot firmware = _binding.AndroidIdentity.Identity.Firmware!;
            json.WriteStartObject("firmware");
            json.WriteString("displayId", firmware.DisplayId);
            json.WriteString("buildFingerprint", firmware.BuildFingerprint);
            json.WriteString("androidRelease", firmware.AndroidRelease);
            json.WriteString("securityPatch", firmware.SecurityPatch);
            json.WriteString(
                "androidReportedBootloaderState", firmware.AndroidReportedBootloaderState.ToString());
            json.WriteEndObject();
            json.WriteEndObject();

            json.WriteStartObject("package");
            json.WriteString("manifestFingerprint", _package.ManifestFingerprint);
            json.WriteString("bindingSha256", _package.BindingSha256);

            if (!_isDirect)
            {
                json.WriteStartObject("seed");
                json.WriteNumber("length", _package.Seed.Length);
                json.WriteString("sha256", _package.Seed.Sha256);
                json.WriteString("commit", _package.Seed.Commit);
                json.WriteString("manifestDigest", _package.Seed.ManifestDigest);
                json.WriteString("origin", _package.Seed.Origin);
                json.WriteEndObject();
            }

            json.WriteStartArray("payloads");
            foreach (string role in SortedKeys(_package.Payloads))
            {
                VerifiedEdlFile payload = _package.Payloads[role];
                json.WriteStartObject();
                json.WriteString("role", role);
                json.WriteNumber("length", payload.Length);
                json.WriteString("sha256", payload.Sha256.ToUpperInvariant());
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();

            json.WriteStartObject("backup");
            json.WriteString("manifestSha256", _backupManifestSha256);

            json.WriteStartArray("luns");
            for (int lun = 0; lun < 6; lun++)
            {
                EdlGeometry geometry = _geometries[lun];
                json.WriteStartObject();
                json.WriteNumber("lun", lun);
                json.WriteNumber("sectorSize", geometry.SectorSize);
                json.WriteNumber("totalSectors", geometry.TotalSectors);
                json.WriteString("diskGuid", _originalTables[lun].DiskGuid);
                json.WriteString("sourceFingerprint", _originalTables[lun].SourceFingerprint);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("files");
            foreach (string role in SortedKeys(_backupFiles))
            {
                EdlCapturedRegion region = _backupFiles[role];
                json.WriteStartObject();
                json.WriteString("role", role);
                json.WriteNumber("lun", region.Lun);
                json.WriteNumber("startSector", region.StartSector);
                json.WriteNumber("sectorCount", region.SectorCount);
                json.WriteNumber("sectorSize", region.SectorSize);
                if (region.PartUuid is null)
                {
                    json.WriteNull("partUuid");
                }
                else
                {
                    json.WriteString("partUuid", region.PartUuid);
                }

                json.WriteNumber("length", region.Length);
                json.WriteString("sha256", region.Sha256.ToUpperInvariant());
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();

            json.WriteStartObject("currentBoot");
            json.WriteString("a", boot["a"]);
            json.WriteString("b", boot["b"]);
            json.WriteEndObject();
            json.WriteString("currentMiscSha256", _currentMiscSha256);

            json.WriteStartObject("gpt");
            json.WriteStartObject("originalFingerprints");
            for (int lun = 0; lun < 6; lun++)
            {
                json.WriteString(lun.ToString(CultureInfo.InvariantCulture), _originalTables[lun].SourceFingerprint);
            }

            json.WriteEndObject();
            json.WriteString("postFingerprint", _postGpt.SourceFingerprint);
            json.WriteString("linuxBootUuid", _linuxBoot.PartUuid);
            json.WriteString("linuxRootUuid", _linuxRoot.PartUuid);
            json.WriteString("backupUuid", _backupPartition.PartUuid);
            json.WriteEndObject();

            json.WriteStartObject("allocation");
            json.WriteNumber("androidBytes", _allocation.AndroidBytes);
            json.WriteNumber("androidGiB", _allocation.AndroidBytes / Gib);
            json.WriteNumber("linuxBootStartSector", _allocation.LinuxBootStartSector);
            json.WriteNumber("linuxBootSectorCount", _allocation.LinuxBootSectorCount);
            json.WriteNumber("linuxRootStartSector", _allocation.LinuxRootStartSector);
            json.WriteNumber("linuxRootSectorCount", _allocation.LinuxRootSectorCount);
            json.WriteNumber("linuxRootBytes", _allocation.LinuxRootBytes);
            json.WriteNumber("backupStartSector", _allocation.BackupStartSector);
            json.WriteNumber("backupSectorCount", _allocation.BackupSectorCount);
            json.WriteNumber("backupBytes", _allocation.BackupBytes);
            json.WriteString("userdataPartUuid", _allocation.OriginalUserdata.PartUuid);
            json.WriteNumber("userdataStartSector", _allocation.OriginalUserdata.StartSector);
            json.WriteNumber("userdataSectorCount", _allocation.OriginalUserdata.SectorCount);
            json.WriteEndObject();

            json.WriteStartObject("artifacts");
            json.WriteString("planSha256", _artifactPlanSha256);
            json.WriteString("summaryManifestSha256", _summaryManifestSha256);
            json.WriteString("boardSummarySha256", _boardSummary.Sha256);
            json.WriteNumber("boardSummaryBytes", _boardSummary.Length);

            json.WriteStartArray("claims");
            foreach (string role in SortedKeys(_artifactClaims))
            {
                HeldClaim claim = _artifactClaims[role];
                json.WriteStartObject();
                json.WriteString("role", role);
                json.WriteString("sha256", claim.Sha256.ToUpperInvariant());
                json.WriteNumber("length", claim.Length);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();

            if (_isDirect)
            {
                WriteDirectConfirmation(json);
            }
            else
            {
                json.WriteStartObject("assets");
                json.WriteStartObject("maintenanceBoot");
                json.WriteNumber("length", Assets.MaintenanceBoot.Length);
                json.WriteString("sha256", Assets.MaintenanceBoot.Sha256.ToUpperInvariant());
                json.WriteEndObject();
                json.WriteStartObject("support");
                json.WriteNumber("length", Assets.SupportArchive.Length);
                json.WriteString("sha256", Assets.SupportArchive.Sha256.ToUpperInvariant());
                json.WriteEndObject();
                json.WriteStartObject("toolbox");
                json.WriteNumber("length", MaintenanceProfiles.ToolboxBytes);
                json.WriteString("sha256", MaintenanceProfiles.ToolboxSha256.ToUpperInvariant());
                json.WriteEndObject();
                json.WriteEndObject();
            }

            json.WriteStartArray("slotMaterials");
            foreach (string slot in SlotOrder)
            {
                InternalSlotMaterial material = _slotMaterials[slot];
                json.WriteStartObject();
                json.WriteString("slot", slot);
                json.WriteString("sourceSlot", material.Slot);
                json.WriteBoolean(
                    "inactiveTargetUninitialized",
                    !string.Equals(slot, material.Slot, StringComparison.Ordinal));
                json.WriteString("baseSha256", material.BaseImageSha256.ToUpperInvariant());
                json.WriteNumber("baseImageLength", material.BaseImageLength);
                json.WriteNumber("baseImageSize", material.BaseImageSize);
                json.WriteNumber("baseTextOffset", material.BaseTextOffset);
                json.WriteBoolean("isKshim", material.IsKshim);
                json.WriteNumber("bootRamdiskSize", material.BootRamdiskSize);
                json.WriteNumber("vendorRamdiskSize", material.VendorRamdiskSize);
                json.WriteNumber("initRamdiskSize", material.InitRamdiskSize);
                json.WriteNumber("pageSize", material.PageSize);
                json.WriteString("loaderProfile", material.LoaderBudget.Profile);
                json.WriteNumber("maxRawBytes", material.LoaderBudget.MaxRawBytes);
                json.WriteBoolean("knownLoaderMatch", material.LoaderBudget.KnownLoaderMatch);
                json.WriteNumber("rawUpperBoundBytes", _rawUpperBounds[slot]);

                json.WriteStartArray("sources");
                foreach (string role in SortedKeys(material.SourceSha256))
                {
                    json.WriteStartObject();
                    json.WriteString("role", role);
                    json.WriteNumber("length", material.SourceLengths[role]);
                    json.WriteString("sha256", material.SourceSha256[role].ToUpperInvariant());
                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        byte[] bytes = buffer.ToArray();
        sha256 = Convert.ToHexString(SHA256.HashData(bytes));
        return bytes;
    }

    /// <summary>
    /// The direct confirmation section: actual schema-2 contract/deployment facts, both filesystem identities
    /// and expanded image facts, the sole native tool hashes, and one entry per built slot with its candidate,
    /// raw, base, round-trip, envelope, DTB, payload-map and copied-report facts. No legacy seed or asset
    /// semantic is reused here.
    /// </summary>
    private void WriteDirectConfirmation(Utf8JsonWriter json)
    {
        EdlRawPackageContract contract = _package.EdlRawContract;

        json.WriteStartObject("direct");
        json.WriteString("packageId", contract.PackageId);
        json.WriteString("version", contract.Version);
        json.WriteString("deviceModel", contract.DeviceModel);
        json.WriteString("sourceCommit", contract.SourceCommit);
        json.WriteString("manifestFingerprint", contract.ManifestFingerprint);
        json.WriteBoolean("testOnly", contract.TestOnly);

        json.WriteStartObject("storage");
        json.WriteNumber("linuxBootBytes", contract.Storage.LinuxBootBytes);
        json.WriteNumber("systemRequiredBytes", contract.Storage.SystemRequiredBytes);
        json.WriteNumber("deploymentScratchBytes", contract.Storage.DeploymentScratchBytes);
        json.WriteNumber("minimumLinuxDataBytes", contract.Storage.MinimumLinuxDataBytes);
        json.WriteEndObject();

        json.WriteStartObject("deployment");
        json.WriteString("kind", contract.Deployment.Kind);
        json.WriteString("commit", contract.Deployment.Commit);
        json.WriteString("manifestDigest", contract.Deployment.ManifestDigest);
        json.WriteString("origin", contract.Deployment.Origin);
        json.WriteString("bootChecksum", contract.Deployment.BootChecksum);
        json.WriteEndObject();

        WriteDirectImage(json, "bootImage", contract.BootImage);
        WriteDirectImage(json, "rootImage", contract.RootImage);

        json.WriteStartObject("bootRecipe");
        json.WriteString("bootUuid", contract.BootRecipe.BootUuid.ToString("D"));
        json.WriteString("rootUuid", contract.BootRecipe.RootUuid.ToString("D"));
        json.WriteString("normalBootArgs", contract.BootRecipe.NormalBootArgs);
        json.WriteString("diagnosticBootArgs", contract.BootRecipe.DiagnosticBootArgs);
        json.WriteString("defaultEntry", contract.BootRecipe.DefaultEntry);
        json.WriteEndObject();

        EdlRawBootTools tools = DirectAssets.Tools;
        json.WriteStartObject("tools");
        json.WriteNumber("packerLength", tools.Packer.Length);
        json.WriteString("packerSha256", tools.Packer.Sha256.ToUpperInvariant());
        json.WriteNumber("unpackerLength", tools.Unpacker.Length);
        json.WriteString("unpackerSha256", tools.Unpacker.Sha256.ToUpperInvariant());
        json.WriteEndObject();

        json.WriteNumber("requiredExecutionBytes", _directExecutionSpaceBytes);

        // The computed trust mode is the only switch. A real GBL run lets the GBL writer emit the trust mode,
        // the gbl facts and the canonical slots of the actual plan, so the AOSP slot, envelope and AVB chain
        // writers never run beside it. The AOSP-resigned path keeps its exact existing writers.
        if (DirectBootTrustMode == InternalInstallBootTrustMode.GblPreserveOem)
        {
            WriteDirectGblConfirmation(json);
        }
        else
        {
            json.WriteString("bootTrustMode", nameof(InternalInstallBootTrustMode.AospResigned));

            json.WriteStartArray("slots");
            foreach (string slot in SlotOrder)
            {
                EdlRawBuiltBoot? built = null;
                foreach (EdlRawBuiltBoot candidate in _builtBoots)
                {
                    if (string.Equals(candidate.Slot, slot, StringComparison.Ordinal))
                    {
                        built = candidate;
                        break;
                    }
                }

                if (built is null)
                {
                    throw new InvalidOperationException("The direct confirmation has no built result for slot " + slot + ".");
                }

                WriteDirectSlot(json, built);
            }

            json.WriteEndArray();

            // The canonical AVB chain section is written inside the same direct object, after the per-slot facts,
            // so no existing slot, boot or source fact is replaced or re-sourced here.
            WriteDirectAvbConfirmation(json);
        }

        json.WriteEndObject();
    }

    private static void WriteDirectImage(Utf8JsonWriter json, string name, EdlRawImage image)
    {
        json.WriteStartObject(name);
        json.WriteString("role", image.Artifact.Role);
        json.WriteNumber("compressedBytes", image.CompressedBytes);
        json.WriteString("compressedSha256", image.CompressedSha256.ToUpperInvariant());
        json.WriteNumber("expandedBytes", image.ExpandedBytes);
        json.WriteString("expandedSha256", image.ExpandedSha256.ToUpperInvariant());
        json.WriteNumber("sectorSize", image.SectorSize);
        json.WriteString("fsType", image.FsType);
        json.WriteString("fsUuid", image.FsUuid.ToString("D"));
        json.WriteNumber("minimumPartitionBytes", image.MinimumPartitionBytes);
        json.WriteEndObject();
    }

    private static void WriteDirectSlot(Utf8JsonWriter json, EdlRawBuiltBoot built)
    {
        json.WriteStartObject();
        json.WriteString("slot", built.Slot);
        json.WriteString("sourceSlot", built.SourceSlot);
        json.WriteBoolean("inactiveTargetUninitialized", built.UsesInactiveSlotBackup);

        WriteVerifiedFile(json, "candidateBoot", built.CandidateBoot);
        WriteVerifiedFile(json, "packedRaw", built.PackedRaw);
        WriteVerifiedFile(json, "baseImage", built.BaseImage);
        WriteVerifiedFile(json, "verificationReport", built.VerificationReport);

        json.WriteString("roundTripRawSha256", built.RoundTripRawSha256.ToUpperInvariant());
        json.WriteString("packageManifestFingerprint", built.PackageManifestFingerprint);

        json.WriteStartObject("envelope");
        WriteVerifiedFile(json, "candidateBoot", built.Envelope.CandidateBoot);
        json.WriteNumber("compressedKernelBytes", built.Envelope.CompressedKernelBytes);
        json.WriteString("compressedKernelSha256", built.Envelope.CompressedKernelSha256);
        json.WriteNumber("originalImageSize", built.Envelope.OriginalImageSize);
        json.WriteNumber("vbmetaOffset", built.Envelope.VbmetaOffset);
        json.WriteNumber("vbmetaBytes", built.Envelope.VbmetaBytes);
        json.WriteString("hashAlgorithm", built.Envelope.HashAlgorithm);
        json.WriteString("saltHex", built.Envelope.SaltHex);
        json.WriteNumber("hashDescriptorFlags", built.Envelope.HashDescriptorFlags);
        json.WriteNumber("rollbackIndex", built.Envelope.RollbackIndex);
        json.WriteNumber("rollbackIndexLocation", built.Envelope.RollbackIndexLocation);
        json.WriteString("digestHex", built.Envelope.DigestHex);
        json.WriteString("sourceEmbeddedVbmetaSha256", built.Envelope.SourceEmbeddedVbmetaSha256);
        json.WriteStartArray("properties");
        foreach (EdlRawAvbProperty property in built.Envelope.Properties)
        {
            json.WriteStartObject();
            json.WriteString("key", property.Key);
            json.WriteString("value", property.Value);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteEndObject();

        WriteDtb(json, "normalDtb", built.NormalDtb);
        WriteDtb(json, "diagnosticDtb", built.DiagnosticDtb);

        json.WriteStartObject("payloadSha256");
        foreach (string role in SortedKeys(built.UnpackedPayloadSha256))
        {
            json.WriteString(role, built.UnpackedPayloadSha256[role]);
        }

        json.WriteEndObject();
        json.WriteEndObject();
    }

    private static void WriteVerifiedFile(Utf8JsonWriter json, string name, VerifiedEdlFile file)
    {
        json.WriteStartObject(name);
        json.WriteNumber("length", file.Length);
        json.WriteString("sha256", file.Sha256.ToUpperInvariant());
        json.WriteEndObject();
    }

    private static void WriteDtb(Utf8JsonWriter json, string name, EdlRawDtbEvidence dtb)
    {
        json.WriteStartObject(name);
        json.WriteString("kind", dtb.Kind.ToString());
        json.WriteString("deviceModel", dtb.DeviceModel);
        json.WriteNumber("length", dtb.Length);
        json.WriteString("sha256", dtb.Sha256.ToUpperInvariant());
        json.WriteString("bootArgs", dtb.BootArgs);
        json.WriteString("bootStage", dtb.BootStage);
        json.WriteString("rootMedium", dtb.RootMedium);
        json.WriteNumber("initrdEntryIndex", dtb.InitrdEntryIndex);
        json.WriteEndObject();
    }

    // ------------------------------------------------------------------ evidence directory

    private static string CreateEvidenceDirectory(string evidenceParent, string androidSerial)
    {
        if (string.IsNullOrWhiteSpace(evidenceParent))
        {
            throw new ArgumentException("An explicit evidence parent directory is required.", nameof(evidenceParent));
        }

        if (!Path.IsPathFullyQualified(evidenceParent))
        {
            throw new ArgumentException(
                "The evidence parent must be an absolute path; there is no working-directory fallback.",
                nameof(evidenceParent));
        }

        string parent = Path.GetFullPath(evidenceParent);
        if (!Directory.Exists(parent))
        {
            throw new ArgumentException(
                "The evidence parent must already exist; the preparation never invents it.", nameof(evidenceParent));
        }

        RequireNonReparseDirectory(parent, "the evidence parent");

        string directory = Path.Combine(
            parent,
            "internal-install-" + SafeToken(androidSerial) + "-" + Guid.NewGuid().ToString("N"));

        if (Directory.Exists(directory) || File.Exists(directory))
        {
            throw new IOException("The evidence directory name is already in use.");
        }

        Directory.CreateDirectory(directory);
        return directory;
    }

    // ------------------------------------------------------------------ nested types

    private sealed class KernelHeader
    {
        internal KernelHeader(long imageSize, ulong textOffset)
        {
            ImageSize = imageSize;
            TextOffset = textOffset;
        }

        internal long ImageSize { get; }

        internal ulong TextOffset { get; }
    }

    private sealed class ManifestFile
    {
        internal ManifestFile(
            string role,
            int lun,
            long startSector,
            long sectorCount,
            int sectorSize,
            string? partUuid,
            string relativePath,
            long length,
            string sha256)
        {
            Role = role;
            Lun = lun;
            StartSector = startSector;
            SectorCount = sectorCount;
            SectorSize = sectorSize;
            PartUuid = partUuid;
            RelativePath = relativePath;
            Length = length;
            Sha256 = sha256;
        }

        internal string Role { get; }

        internal int Lun { get; }

        internal long StartSector { get; }

        internal long SectorCount { get; }

        internal int SectorSize { get; }

        internal string? PartUuid { get; }

        internal string RelativePath { get; }

        internal long Length { get; }

        internal string Sha256 { get; }
    }

    private sealed class HeldClaim
    {
        internal HeldClaim(string subject, string path, long length, string sha256, FileStream stream)
        {
            Subject = subject;
            Path = path;
            Length = length;
            Sha256 = sha256;
            Stream = stream;
        }

        internal string Subject { get; }

        internal string Path { get; }

        internal long Length { get; }

        internal string Sha256 { get; }

        internal FileStream Stream { get; }
    }

    private sealed class BackupFacts
    {
        internal string Directory = string.Empty;
        internal string ManifestSha256 = string.Empty;
        internal long ManifestLength;
        internal string Model = string.Empty;
        internal string ProfileId = string.Empty;
        internal string AndroidBuild = string.Empty;
        internal string HardwareId = string.Empty;
        internal IReadOnlyDictionary<int, EdlGeometry> Geometries =
            new ReadOnlyDictionary<int, EdlGeometry>(new Dictionary<int, EdlGeometry>());
        internal IReadOnlyDictionary<int, GptTable> Tables =
            new ReadOnlyDictionary<int, GptTable>(new Dictionary<int, GptTable>());
        internal IReadOnlyDictionary<string, EdlCapturedRegion> Files =
            new ReadOnlyDictionary<string, EdlCapturedRegion>(
                new Dictionary<string, EdlCapturedRegion>(StringComparer.Ordinal));
        internal byte[] Lun0Primary = Array.Empty<byte>();
        internal byte[] Lun0Backup = Array.Empty<byte>();
    }

    private sealed class ArtifactFacts
    {
        internal InternalAllocationPlan Allocation = null!;
        internal GptTable PostGpt = null!;
        internal GptPartition LinuxBoot = null!;
        internal GptPartition LinuxRoot = null!;
        internal GptPartition BackupPartition = null!;
        internal IReadOnlyList<InternalArtifactRegion> GptWriteRegions = Array.Empty<InternalArtifactRegion>();
        internal InternalArtifactRegion BoardSummary = null!;
        internal IReadOnlyDictionary<string, HeldClaim> Claims =
            new ReadOnlyDictionary<string, HeldClaim>(new Dictionary<string, HeldClaim>(StringComparer.Ordinal));
        internal Guid InstallationId;
        internal string PlanSha256 = string.Empty;
        internal string SummaryManifestSha256 = string.Empty;
    }

    private sealed class DeviceCapture
    {
        internal Dictionary<string, string> BootSha256 { get; } = new(StringComparer.Ordinal);
        internal string MiscSha256 { get; set; } = string.Empty;
        internal List<EdlReadEvidence> Evidence { get; } = new();
    }

    private static List<string> SortedKeys<T>(IReadOnlyDictionary<string, T> dictionary)
    {
        List<string> keys = new(dictionary.Keys);
        keys.Sort(StringComparer.Ordinal);
        return keys;
    }

    private static bool SameAllocation(InternalAllocationPlan left, InternalAllocationPlan right) =>
        left.SectorSize == right.SectorSize
        && left.OriginalUserdataEndSectorExclusive == right.OriginalUserdataEndSectorExclusive
        && left.AndroidBytes == right.AndroidBytes
        && left.AndroidSectorCount == right.AndroidSectorCount
        && left.AndroidEndSectorExclusive == right.AndroidEndSectorExclusive
        && left.LinuxBytes == right.LinuxBytes
        && left.LinuxBootBytes == right.LinuxBootBytes
        && left.LinuxRootBytes == right.LinuxRootBytes
        && left.EstimatedLinuxDataBytes == right.EstimatedLinuxDataBytes
        && left.LinuxBootStartSector == right.LinuxBootStartSector
        && left.LinuxBootSectorCount == right.LinuxBootSectorCount
        && left.LinuxRootStartSector == right.LinuxRootStartSector
        && left.LinuxRootSectorCount == right.LinuxRootSectorCount
        && left.BackupBytes == right.BackupBytes
        && left.BackupStartSector == right.BackupStartSector
        && left.BackupSectorCount == right.BackupSectorCount
        && left.BackupEndSectorExclusive == right.BackupEndSectorExclusive
        && left.AlignmentGapSectors == right.AlignmentGapSectors
        && left.TailUnallocatedSectors == right.TailUnallocatedSectors
        && left.AlignmentLossBytes == right.AlignmentLossBytes
        && SamePartition(left.OriginalUserdata, right.OriginalUserdata);

    private static bool SamePartition(GptPartition left, GptPartition right) =>
        left.Number == right.Number
        && string.Equals(left.Name, right.Name, StringComparison.Ordinal)
        && string.Equals(left.TypeGuid, right.TypeGuid, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.PartUuid, right.PartUuid, StringComparison.OrdinalIgnoreCase)
        && left.StartSector == right.StartSector
        && left.SectorCount == right.SectorCount
        && left.Attributes == right.Attributes;

    private static void RequireSameTable(GptTable expected, GptTable actual, string subject)
    {
        if (!string.Equals(expected.DiskGuid, actual.DiskGuid, StringComparison.OrdinalIgnoreCase)
            || expected.SectorSize != actual.SectorSize
            || expected.DiskBytes != actual.DiskBytes
            || expected.Partitions.Count != actual.Partitions.Count)
        {
            throw new InvalidDataException(subject + " describes a different disk.");
        }

        foreach (GptPartition partition in expected.Partitions)
        {
            GptPartition? match = FindPartition(actual, partition.Number);
            if (match is null || !SamePartition(partition, match))
            {
                throw new InvalidDataException(subject + " changed entry " + partition.Number + ".");
            }
        }
    }

    private static GptPartition? FindPartition(GptTable table, int number)
    {
        foreach (GptPartition partition in table.Partitions)
        {
            if (partition.Number == number)
            {
                return partition;
            }
        }

        return null;
    }

    private static bool SameFirmware(FirmwareSnapshot? left, FirmwareSnapshot? right) =>
        left is not null
        && right is not null
        && string.Equals(left.DisplayId, right.DisplayId, StringComparison.Ordinal)
        && string.Equals(left.BuildFingerprint, right.BuildFingerprint, StringComparison.Ordinal)
        && string.Equals(left.AndroidRelease, right.AndroidRelease, StringComparison.Ordinal)
        && string.Equals(left.SecurityPatch, right.SecurityPatch, StringComparison.Ordinal)
        && left.AndroidReportedBootloaderState == right.AndroidReportedBootloaderState;

    private static bool OptionalUuidEquals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static Guid RequireUuid(string value, string name)
    {
        if (!Guid.TryParse(value, out Guid parsed) || parsed == Guid.Empty)
        {
            throw new InvalidDataException("The prepared '" + name + "' partition UUID is unusable.");
        }

        return parsed;
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, HashBufferBytes, FileOptions.SequentialScan);

    private static string HashHeld(FileStream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[HashBufferBytes];

        try
        {
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

    private static byte[] ReadAllBytes(FileStream stream, int limit, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        if (stream.Length > limit)
        {
            throw new InvalidDataException("A local evidence file is unreasonably large.");
        }

        byte[] buffer = new byte[stream.Length];
        int offset = 0;
        while (offset < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new InvalidDataException("A local evidence file ended before its declared length.");
            }

            offset += read;
        }

        stream.Position = 0;
        return buffer;
    }

    private static byte[] ReadExact(FileStream stream, long length, CancellationToken cancellationToken)
    {
        if (length <= 0 || length > int.MaxValue || stream.Length != length)
        {
            throw new InvalidDataException("A held claim does not carry a usable length.");
        }

        stream.Position = 0;
        byte[] buffer = new byte[(int)length];
        int offset = 0;
        while (offset < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new InvalidDataException("A held claim ended before its verified length.");
            }

            offset += read;
        }

        stream.Position = 0;
        return buffer;
    }

    /// <summary>
    /// Reads only a fixed prefix from the start of a held stream, cancellably, and restores the stream
    /// position. Unlike <see cref="ReadExact"/> it never assumes the stream is exactly that long, so the fixed
    /// 64 KiB board archive header can be read without ever touching the multi-GiB remainder.
    /// </summary>
    private static byte[] ReadPrefix(FileStream stream, int length, CancellationToken cancellationToken)
    {
        if (length <= 0 || stream.Length < length)
        {
            throw new InvalidDataException("A held claim is too short for its fixed header prefix.");
        }

        byte[] buffer = new byte[length];

        try
        {
            stream.Position = 0;

            int offset = 0;
            while (offset < buffer.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int read = stream.Read(buffer, offset, buffer.Length - offset);
                if (read <= 0)
                {
                    throw new InvalidDataException("A held claim ended inside its fixed header prefix.");
                }

                offset += read;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return buffer;
        }
        finally
        {
            stream.Position = 0;
        }
    }

    private static string RequireInside(string root, string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw new InvalidDataException(subject + " has no usable path.");
        }

        string full = Path.GetFullPath(path);
        string relative = Path.GetRelativePath(root, full);

        if (relative.Length == 0
            || relative == "."
            || Path.IsPathRooted(relative)
            || relative == ".."
            || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || relative.StartsWith("../", StringComparison.Ordinal)
            || relative.StartsWith("..\\", StringComparison.Ordinal))
        {
            throw new InvalidDataException(subject + " is not inside the directory it belongs to.");
        }

        return full;
    }

    private static void RequireRegularFile(string path, string subject)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException(subject + " is missing.", path);
        }

        if ((info.Attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException(subject + " is a directory, not a file.");
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null)
        {
            throw new InvalidDataException(subject + " is a symbolic link or reparse point.");
        }

        DirectoryInfo? parent = info.Directory;
        if (parent is not null
            && ((parent.Attributes & FileAttributes.ReparsePoint) != 0 || parent.LinkTarget is not null))
        {
            throw new InvalidDataException(subject + " sits below a reparse point.");
        }
    }

    private static void RequireNonReparseDirectory(string path, string subject)
    {
        DirectoryInfo info = new(path);
        if (!info.Exists)
        {
            throw new DirectoryNotFoundException(subject + " is missing: " + path + ".");
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null)
        {
            throw new InvalidDataException(subject + " is a symbolic link or reparse point.");
        }
    }

    private static void RequireSha256(string? value, string subject)
    {
        if (value is null || value.Length != Sha256HexLength)
        {
            throw new InvalidDataException(subject + " is not a 64 character SHA-256.");
        }

        foreach (char character in value)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                throw new InvalidDataException(subject + " is not hexadecimal.");
            }
        }
    }

    private static bool SameSha(string? left, string? right) =>
        left is not null && right is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool SameText(string? left, string? right) =>
        left is not null && right is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static string RequirePhase(string phase)
    {
        if (string.IsNullOrWhiteSpace(phase) || phase.Length > 32)
        {
            throw new ArgumentException("An EDL evidence phase must be a short non-blank token.", nameof(phase));
        }

        foreach (char character in phase)
        {
            if (!(char.IsAsciiLetterOrDigit(character) || character == '-'))
            {
                throw new ArgumentException(
                    "An EDL evidence phase may only use ASCII letters, digits and hyphens.", nameof(phase));
            }
        }

        return phase;
    }

    private static string SafeToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "UNKNOWN";
        }

        StringBuilder builder = new(value.Length);
        foreach (char character in value)
        {
            builder.Append(char.IsLetterOrDigit(character) ? char.ToUpperInvariant(character) : '-');
        }

        string token = builder.ToString().Trim('-');
        if (token.Length == 0)
        {
            return "UNKNOWN";
        }

        return token.Length <= 32 ? token : token.Substring(0, 32);
    }

    private static long AlignUp(long value, long alignment, string message)
    {
        if (alignment <= 0)
        {
            throw new InvalidDataException(message);
        }

        long remainder = value % alignment;
        return remainder == 0 ? value : CheckedAdd(value, alignment - remainder, message);
    }

    private static long CheckedAdd(long left, long right, string message)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException(message, exception);
        }
    }

    private static long CheckedMultiply(long left, long right, string message)
    {
        try
        {
            return checked(left * right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException(message, exception);
        }
    }

    // ------------------------------------------------------------------ JSON helpers

    private static JsonElement RequireProperty(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value))
        {
            throw new InvalidDataException("A prepared record or the backup manifest has no '" + name + "'.");
        }

        return value;
    }

    private static JsonElement RequireObject(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The field '" + name + "' is not a JSON object.");
        }

        return value;
    }

    private static JsonElement RequireArray(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The field '" + name + "' is not a JSON array.");
        }

        return value;
    }

    private static string RequireString(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("The field '" + name + "' is not a JSON string.");
        }

        return value.GetString()
            ?? throw new InvalidDataException("The field '" + name + "' has no string value.");
    }

    private static string? ReadNullableString(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("The field '" + name + "' is neither null nor a string.");
        }

        return value.GetString();
    }

    private static long RequireInt64(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long parsed))
        {
            throw new InvalidDataException("The field '" + name + "' is not a 64-bit integer.");
        }

        return parsed;
    }

    private static ulong RequireUInt64(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetUInt64(out ulong parsed))
        {
            throw new InvalidDataException("The field '" + name + "' is not an unsigned 64-bit integer.");
        }

        return parsed;
    }

    private static bool RequireBoolean(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name);
        if (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False)
        {
            throw new InvalidDataException("The field '" + name + "' is not a JSON boolean.");
        }

        return value.GetBoolean();
    }
}
