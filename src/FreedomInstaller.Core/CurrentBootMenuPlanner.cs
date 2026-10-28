// BM04: public owner and models of the default-only current-boot menu repack
// shared by uninstall. The planner is the only public surface: it takes a
// verified backup set, re-derives every slot fact through the existing owners
// (slot material reader, stock verifier, pinned unpacker, envelope repack) and
// returns a disposable plan that owns exactly its own unique generated child
// and its own output leases. It performs no device I/O, never disposes or
// deletes a caller backup, and carries no Ready, OEM-acceptance or OS-boot
// claim of any kind.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One slot's derived facts of the default-only menu plan. Every value is an
/// observation of verified input claims and files this plan staged itself; a
/// null <see cref="Candidate"/> means the slot needs no write (stock original
/// or already android-default). <see cref="SourceSlot"/> is never fabricated:
/// it is the same slot the material was read from.
/// </summary>
public sealed class CurrentBootMenuSlot
{
    internal CurrentBootMenuSlot(
        string slot,
        string sourceSlot,
        BootMaintenanceSourceKind sourceKind,
        BootMaintenanceBootTrust bootTrustMode,
        VerifiedEdlFile original,
        VerifiedEdlFile? candidate,
        IReadOnlyDictionary<string, string> payloadSha256,
        string? originalMetadataSha256,
        bool payloadDigestMatchesOem)
    {
        RequireSlot(slot, nameof(slot));
        RequireSlot(sourceSlot, nameof(sourceSlot));

        if (!Enum.IsDefined(sourceKind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(sourceKind), sourceKind, "The boot-maintenance source kind is not a known value.");
        }

        if (!Enum.IsDefined(bootTrustMode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(bootTrustMode), bootTrustMode, "The boot-maintenance boot trust mode is not a known value.");
        }

        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(payloadSha256);

        if (sourceKind == BootMaintenanceSourceKind.Empty && candidate is not null)
        {
            throw new ArgumentException(
                "An empty source slot cannot carry a candidate boot.", nameof(candidate));
        }

        Slot = slot;
        SourceSlot = sourceSlot;
        SourceKind = sourceKind;
        BootTrustMode = bootTrustMode;
        Original = original;
        Candidate = candidate;
        PayloadSha256 = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(payloadSha256, StringComparer.Ordinal));
        OriginalMetadataSha256 = originalMetadataSha256;
        PayloadDigestMatchesOem = payloadDigestMatchesOem;
    }

    /// <summary>Target slot, exactly <c>a</c> or <c>b</c>.</summary>
    public string Slot { get; }

    /// <summary>
    /// The slot the material was really read from, exactly <c>a</c> or <c>b</c>.
    /// This planner never substitutes one slot's material for another.
    /// </summary>
    public string SourceSlot { get; }

    /// <summary>What the slot's boot image is taken from.</summary>
    public BootMaintenanceSourceKind SourceKind { get; }

    /// <summary>How the slot's boot candidate is trusted.</summary>
    public BootMaintenanceBootTrust BootTrustMode { get; }

    /// <summary>The verified current boot of this slot.</summary>
    public VerifiedEdlFile Original { get; }

    /// <summary>
    /// The prepared candidate, or null when this slot needs no write (stock
    /// original, already android-default, or a skipped truly-empty slot).
    /// </summary>
    public VerifiedEdlFile? Candidate { get; }

    /// <summary>
    /// Per-entry payload SHA-256 observed on the slot's own unpack; empty when no
    /// unpack was performed.
    /// </summary>
    public IReadOnlyDictionary<string, string> PayloadSha256 { get; }

    /// <summary>
    /// SHA-256 of the original signed boot metadata blob, or null when none was
    /// authenticated. A stale OEM payload digest is never labelled verified.
    /// </summary>
    public string? OriginalMetadataSha256 { get; }

    /// <summary>
    /// True only when the new payload still satisfies the original signed digest.
    /// False is the expected truth for every rewritten candidate.
    /// </summary>
    public bool PayloadDigestMatchesOem { get; }

    private static void RequireSlot(string? value, string name)
    {
        if (!string.Equals(value, "a", StringComparison.Ordinal) &&
            !string.Equals(value, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("A current-boot menu slot must be exactly 'a' or 'b'.", name);
        }
    }
}

/// <summary>
/// One companion metadata candidate the plan determined is actually required.
/// Both files are derived facts only; binding them to a fresh device target
/// stays with the uninstall owner.
/// </summary>
public sealed class CurrentBootMenuCompanion
{
    internal CurrentBootMenuCompanion(
        string slot,
        string role,
        VerifiedEdlFile original,
        VerifiedEdlFile candidate)
    {
        if (!string.Equals(slot, "a", StringComparison.Ordinal) &&
            !string.Equals(slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("A companion slot must be exactly 'a' or 'b'.", nameof(slot));
        }

        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("A companion requires a role.", nameof(role));
        }

        Slot = slot;
        Role = role;
        Original = original ?? throw new ArgumentNullException(nameof(original));
        Candidate = candidate ?? throw new ArgumentNullException(nameof(candidate));
    }

    /// <summary>Target slot of the companion, exactly <c>a</c> or <c>b</c>.</summary>
    public string Slot { get; }

    /// <summary>The companion's backup role name, for example <c>vbmeta_a</c>.</summary>
    public string Role { get; }

    /// <summary>The verified original companion image.</summary>
    public VerifiedEdlFile Original { get; }

    /// <summary>The independently verified candidate companion image.</summary>
    public VerifiedEdlFile Candidate { get; }
}

/// <summary>
/// The disposable result of one default-only menu preparation. While alive it
/// holds read leases on its own candidate and report files inside its unique
/// generated child; <see cref="Dispose"/> closes exactly those leases and
/// deletes exactly that one child. It never touches a caller backup file, the
/// chosen parent, or any other plan's leases.
/// </summary>
public sealed class CurrentBootMenuPlan : IDisposable
{
    private readonly List<FileStream> _ownedLeases;
    private readonly string _directoryPath;
    private readonly string _currentSlot;
    private readonly string _backupManifestSha256;
    // The sealed authority (and the initialized-B proof it owns) whose real
    // source leases back this successful plan. Disposed before the plan's own
    // child removal; never a caller resource.
    private readonly InternalInstallPreparationContext.TfBootAuthority? _tfAuthority;
    private int _disposed;

    internal CurrentBootMenuPlan(
        string directoryPath,
        IReadOnlyList<CurrentBootMenuSlot> slots,
        IReadOnlyList<CurrentBootMenuCompanion> companions,
        VerifiedEdlFile verificationReport,
        List<FileStream> ownedLeases,
        string currentSlot,
        EdlEntryResult binding,
        string backupManifestSha256,
        InternalInstallPreparationContext.TfBootAuthority? tfAuthority = null)
    {
        if (!string.Equals(currentSlot, "a", StringComparison.Ordinal) &&
            !string.Equals(currentSlot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("The current boot slot must be 'a' or 'b'.", nameof(currentSlot));
        }

        if (string.IsNullOrEmpty(backupManifestSha256) || backupManifestSha256.Length != 64)
        {
            throw new ArgumentException(
                "The backup manifest SHA-256 must be a 64-character hex digest.",
                nameof(backupManifestSha256));
        }

        foreach (char hexDigit in backupManifestSha256)
        {
            bool isHex = (hexDigit >= '0' && hexDigit <= '9') ||
                (hexDigit >= 'a' && hexDigit <= 'f') ||
                (hexDigit >= 'A' && hexDigit <= 'F');
            if (!isHex)
            {
                throw new ArgumentException(
                    "The backup manifest SHA-256 must be a 64-character hex digest.",
                    nameof(backupManifestSha256));
            }
        }

        _directoryPath = directoryPath;
        _currentSlot = currentSlot;
        Binding = binding
            ?? throw new ArgumentNullException(nameof(binding));
        _backupManifestSha256 = backupManifestSha256;
        Slots = new ReadOnlyCollection<CurrentBootMenuSlot>(new List<CurrentBootMenuSlot>(slots));
        Companions = new ReadOnlyCollection<CurrentBootMenuCompanion>(new List<CurrentBootMenuCompanion>(companions));
        VerificationReport = verificationReport
            ?? throw new ArgumentNullException(nameof(verificationReport));
        _ownedLeases = ownedLeases;
        _tfAuthority = tfAuthority;
    }

    /// <summary>
    /// The unique generated child directory this plan owns. Valid while the plan
    /// is held; <see cref="Dispose"/> removes exactly this directory.
    /// </summary>
    public string DirectoryPath => _directoryPath;

    /// <summary>Per-slot facts, in the planner's own order; never caller reorderable.</summary>
    public IReadOnlyList<CurrentBootMenuSlot> Slots { get; }

    /// <summary>Only the companions this plan proved are actually required.</summary>
    public IReadOnlyList<CurrentBootMenuCompanion> Companions { get; }

    /// <summary>The verified factual report file inside <see cref="DirectoryPath"/>.</summary>
    public VerifiedEdlFile VerificationReport { get; }

    /// <summary>The device-reported current slot this plan was prepared for ("a" or "b").</summary>
    public string CurrentSlot => _currentSlot;

    /// <summary>The verified backup manifest binding this plan was prepared against.</summary>
    public EdlEntryResult Binding { get; }

    /// <summary>The SHA-256 of the backup manifest this plan was prepared against.</summary>
    public string BackupManifestSha256 => _backupManifestSha256;

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Releases exactly this plan's own leases and deletes exactly its own
    /// generated child. The held authority (and the initialized-B proof it
    /// owns) is closed BEFORE the recursive child removal, even if one close
    /// fails; a single failure never skips the remaining cleanup and is never
    /// silently represented as success. Idempotent; never deletes a caller
    /// path or sibling.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        List<Exception>? errors = null;

        foreach (FileStream stream in _ownedLeases)
        {
            try
            {
                stream.Dispose();
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }
        }

        _ownedLeases.Clear();

        // The authority closes its own held source leases and its owned
        // initialized-B proof. Its Dispose aggregates its own release failures
        // and throws AggregateException; every failure is collected here so the
        // recursive child removal below still runs and the real aggregate is
        // rethrown afterwards. No failure is silently swallowed as success.
        if (_tfAuthority is not null)
        {
            try
            {
                _tfAuthority.Dispose();
            }
            catch (AggregateException aggregate)
            {
                (errors ??= new List<Exception>()).AddRange(aggregate.InnerExceptions);
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }
        }

        try
        {
            if (Directory.Exists(_directoryPath))
            {
                Directory.Delete(_directoryPath, recursive: true);
            }
        }
        catch (Exception error)
            when (error is IOException or UnauthorizedAccessException)
        {
            (errors ??= new List<Exception>()).Add(error);
        }

        if (errors is not null)
        {
            throw errors.Count == 1
                ? errors[0]
                : new AggregateException(errors);
        }
    }
}

/// <summary>
/// Prepares the default-only current-boot menu repack from an already verified
/// backup set. The result is a factual derived plan only: the uninstall owner
/// separately binds fresh target geometry and capture before anything is
/// written to a device.
/// </summary>
public static partial class CurrentBootMenuPlanner
{
    private const string ChildPrefix = "current-boot-menu-";

    private const string ReportFileName = "current-boot-menu-verification.json";

    private const string OriginalRawSuffix = ".current-raw.img";

    private const string ChangedRawSuffix = ".default-raw.img";

    private const string BaseImageSuffix = ".base.img";

    private const string CandidateSuffix = ".candidate-boot.img";

    private const string UnpackedOriginalDirectoryName = "unpacked-original";

    private const string UnpackedChangedDirectoryName = "unpacked-default";

    public static Task<CurrentBootMenuPlan> PrepareAndroidDefaultAsync(
        InternalBackupSet currentBackup,
        string currentSlot,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        // Compatibility surface: forwards as a factually unknown lock state. The
        // existing authority stays the arbiter of every unknown-AOSP gate; this
        // is never read as unlocked.
        return PrepareAndroidDefaultAsync(
            currentBackup,
            currentSlot,
            BootloaderState.Unknown,
            tools,
            runner,
            chosenParent,
            ct);
    }

    public static Task<CurrentBootMenuPlan> PrepareAndroidDefaultAsync(
        InternalBackupSet currentBackup,
        string currentSlot,
        BootloaderState lockState,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);

        if (currentSlot is not ("a" or "b"))
        {
            throw new ArgumentException("currentSlot must be exactly 'a' or 'b'.", nameof(currentSlot));
        }

        if (lockState is not (BootloaderState.Unknown or BootloaderState.Locked or BootloaderState.Unlocked))
        {
            throw new ArgumentException(
                "lockState must be a defined BootloaderState value.", nameof(lockState));
        }

        ct.ThrowIfCancellationRequested();

        string parent = NormalizeParent(chosenParent);
        RequireBoundBackup(currentBackup);

        string child = Path.GetFullPath(Path.Combine(
            parent, ChildPrefix + Guid.NewGuid().ToString("N")));
        string parentPrefix = Path.EndsInDirectorySeparator(parent)
            ? parent
            : parent + Path.DirectorySeparatorChar;
        if (!child.StartsWith(parentPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("owned plan directory would escape the chosen parent: " + child);
        }

        if (Directory.Exists(child))
        {
            throw new IOException("owned plan directory already exists: " + child);
        }

        return Task.Run(
            () => PrepareCoreAsync(
                currentBackup, currentSlot, tools, runner, parent, child, lockState, ct),
            ct);
    }

    // ------------------------------------------------------------------ core

    private static async Task<CurrentBootMenuPlan> PrepareCoreAsync(
        InternalBackupSet backup,
        string currentSlot,
        EdlRawBootTools callerTools,
        ICommandRunner runner,
        string parent,
        string child,
        BootloaderState lockState,
        CancellationToken ct)
    {
        Directory.CreateDirectory(child);
        bool ownershipTransferred = false;

        EdlRawBootTools? tools = null;
        InternalInstallPreparationContext.TfBootAuthority? authority = null;
        // Declared outside the try so a failed authority factory still lets the
        // finally path dispose the local proof the caller still owns; it is
        // nulled only after a successful authority took over its ownership.
        CurrentBootInitializedInactiveProof? initializedProof = null;
        var ownedLeases = new List<FileStream>();
        // The original preparation error, preserved through cleanup so a later
        // release failure can never replace or mask it.
        Exception? preparationError = null;
        try
        {
            // Own pinned tool leases, independent of the caller's instance.
            tools = await callerTools.AcquireAsync(ct).ConfigureAwait(false);

            // The misc current-slot fact is read and matched before any source
            // analysis, exactly as before.
            BootSlotControlFacts observed = await BootSlotControl.ReadAsync(
                RequireRole(backup, "misc"),
                ct).ConfigureAwait(false);
            string observedCurrentSlot = observed.CurrentSlot;
            if (!string.Equals(observedCurrentSlot, currentSlot, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the device misc current-slot reports '" + observedCurrentSlot
                    + "' but the requested plan targets '" + currentSlot + "'");
            }

            string otherSlot = currentSlot == "a" ? "b" : "a";

            // ---------------------------------------------------- emptiness
            // Whole-hash emptiness of each actual target boot, before any source
            // analysis. The active slot's empty boot rejects outright.
            var targetBootClaims = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                [currentSlot] = RequireRole(backup, "boot_" + currentSlot),
                [otherSlot] = RequireRole(backup, "boot_" + otherSlot),
            };
            var targetEmpty = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, VerifiedEdlFile> target in targetBootClaims)
            {
                ct.ThrowIfCancellationRequested();
                bool empty = await EdlRawBootBuilder
                    .CurrentBootDetectEmptyAsync(target.Value, ct)
                    .ConfigureAwait(false);
                targetEmpty[target.Key] = empty;
                if (empty && string.Equals(target.Key, currentSlot, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "the active slot '" + target.Key
                        + "' boot is entirely empty and cannot be repacked");
                }
            }

            // ---------------------------------------------- stock no-change
            // Before any authority work: if EVERY nonempty target boot really
            // passes the existing stock verifier (whole payload, AVB leaf RSA,
            // root chain child binding, project rejection), this backup is a
            // legitimate keep-everything-as-is case and needs no authority, no
            // lock guess, no native execution and no loader eligibility at all.
            // A verifier InvalidDataException on any target is only a probe
            // failure: the full authority route still runs with every trust
            // gate. Cancellation and unexpected failures always propagate; no
            // exception is ever swallowed into a no-change acceptance.
            var stockFactsByTarget = new Dictionary<string, BootStockOriginalFacts>(StringComparer.Ordinal);
            bool allStockNoChange = true;
            foreach (KeyValuePair<string, VerifiedEdlFile> target in targetBootClaims)
            {
                if (targetEmpty[target.Key])
                {
                    continue;
                }

                ct.ThrowIfCancellationRequested();
                try
                {
                    stockFactsByTarget[target.Key] = await EdlRawBootBuilder
                        .VerifyStockOriginalBootAsync(
                            target.Value,
                            RequireRole(backup, "vbmeta_" + target.Key),
                            ct)
                        .ConfigureAwait(false);
                }
                catch (InvalidDataException)
                {
                    allStockNoChange = false;
                    break;
                }
            }

            // ------------------------------------- same-epoch initialized-B
            // Only when the current slot is 'a', boot_b is nonempty and all four
            // B ancillary loaders are whole-file zero, the actual same-epoch
            // proof is produced and handed to the six-argument authority. Any
            // proof failure propagates; this is only a selection route — the
            // authority still runs every lock/GBL/AVB gate, and the proof's
            // ownership transfers only on successful authority creation.
            if (!allStockNoChange &&
                string.Equals(currentSlot, "a", StringComparison.Ordinal) &&
                !targetEmpty[otherSlot])
            {
                bool bAuxAllZero = true;
                foreach (string role in new[]
                {
                    "vendor_boot_" + otherSlot,
                    "init_boot_" + otherSlot,
                    "abl_" + otherSlot,
                    "xbl_config_" + otherSlot,
                })
                {
                    ct.ThrowIfCancellationRequested();
                    if (!await EdlRawBootBuilder
                            .CurrentBootDetectEmptyAsync(RequireRole(backup, role), ct)
                            .ConfigureAwait(false))
                    {
                        bAuxAllZero = false;
                        break;
                    }
                }

                if (bAuxAllZero)
                {
                    initializedProof = await EdlRawBootBuilder
                        .VerifyInitializedInactiveSlotAsync(
                            backup.ProfileId,
                            currentSlot,
                            otherSlot,
                            RequireRole(backup, "boot_" + currentSlot),
                            RequireRole(backup, "vendor_boot_" + currentSlot),
                            RequireRole(backup, "init_boot_" + currentSlot),
                            RequireRole(backup, "abl_" + currentSlot),
                            RequireRole(backup, "xbl_config_" + currentSlot),
                            targetBootClaims[otherSlot],
                            RequireRole(backup, "vendor_boot_" + otherSlot),
                            RequireRole(backup, "init_boot_" + otherSlot),
                            RequireRole(backup, "abl_" + otherSlot),
                            RequireRole(backup, "xbl_config_" + otherSlot),
                            RequireRole(backup, "vbmeta_" + currentSlot),
                            tools,
                            runner,
                            parent,
                            ct)
                        .ConfigureAwait(false);
                }
            }

            Dictionary<string, InternalSlotMaterial>? materialsBySource = null;
            IReadOnlyDictionary<string, long>? provenBounds = null;

            if (allStockNoChange)
            {
                // The legitimate keep path: no authority, no lock guess, no native
                // call, no reader and no loader eligibility. This plan holds its
                // own verified read-only leases for every accepted stock boot and
                // its same-slot root through the plan lifetime; a caller backup
                // file is never disposed or deleted here.
                foreach (string stockTarget in stockFactsByTarget.Keys)
                {
                    ct.ThrowIfCancellationRequested();
                    ownedLeases.Add(OpenOutputLease(
                        targetBootClaims[stockTarget],
                        "verified stock boot of slot " + stockTarget,
                        ct));
                    ownedLeases.Add(OpenOutputLease(
                        RequireRole(backup, "vbmeta_" + stockTarget),
                        "verified stock root of slot " + stockTarget,
                        ct));
                }
            }
            else
            {
                // ------------------------------------------------ authority
                // The sealed TF boot authority stays the only trust arbiter. An
                // unknown lock state is never read as unlocked; the authority's own
                // unknown-AOSP gate keeps applying. Successful creation owns the
                // transferred proof; every failure path below disposes the local
                // authority before the output leases and the own child.
                authority = initializedProof is null
                    ? await InternalInstallPreparationContext.PrepareTfBootAuthorityAsync(
                            backup, currentSlot, lockState, parent, ct)
                        .ConfigureAwait(false)
                    : await InternalInstallPreparationContext.PrepareTfBootAuthorityAsync(
                            backup, currentSlot, lockState, parent, initializedProof, ct)
                        .ConfigureAwait(false);
                initializedProof = null;

                // ------------------------------------------- phase 1: material
                // One actual reader run per UNIQUE source slot of the sealed map,
                // with source claims from this same backup and a source-specific
                // base export path. The SourceSlots map is sealed truth.
                var materials = new Dictionary<string, InternalSlotMaterial>(StringComparer.Ordinal);
                foreach (string source in authority.SourceSlots.Values)
                {
                    ct.ThrowIfCancellationRequested();
                    if (materials.ContainsKey(source))
                    {
                        continue;
                    }

                    materials[source] = await InternalSlotMaterialReader
                        .AnalyzeAndExportBaseAsync(
                            source,
                            RequireRole(backup, "boot_" + source),
                            RequireRole(backup, "vendor_boot_" + source),
                            RequireRole(backup, "init_boot_" + source),
                            RequireRole(backup, "abl_" + source),
                            RequireRole(backup, "xbl_config_" + source),
                            Path.Combine(child, "source-" + source + BaseImageSuffix),
                            ct)
                        .ConfigureAwait(false);
                }

                materialsBySource = materials;

                // --------------------------------- phase 1: real target raw MAX
                // Every nonempty target boot is opened, whole-verified and actually
                // measured; its real raw length is grouped by source with MAX across
                // targets sharing one source. A truly empty inactive target is
                // skipped. A unique source left with no measured target can never
                // receive a fabricated length.
                var rawLengthsBySource = new Dictionary<string, long>(StringComparer.Ordinal);
                foreach (string target in authority.SourceSlots.Keys)
                {
                    ct.ThrowIfCancellationRequested();
                    if (targetEmpty[target])
                    {
                        continue;
                    }

                    string source = authority.SourceSlots[target];
                    bool targetIsSource = string.Equals(target, source, StringComparison.Ordinal);
                    long rawBytes = await EdlRawBootBuilder
                        .CurrentBootMeasureTargetRawBytesAsync(
                            targetBootClaims[target],
                            materials[source],
                            targetIsSource,
                            ct)
                        .ConfigureAwait(false);
                    if (!rawLengthsBySource.TryGetValue(source, out long existing)
                        || rawBytes > existing)
                    {
                        rawLengthsBySource[source] = rawBytes;
                    }
                }

                foreach (string source in authority.SourceSlots.Values)
                {
                    if (!rawLengthsBySource.ContainsKey(source))
                    {
                        throw new InvalidDataException(
                            "no nonempty target could measure a real raw length for source '" + source + "'");
                    }
                }

                // The authority re-applies the real common-window runtime formula and
                // proves every raw length inside its own per-source bound.
                provenBounds = authority.RequireRuntimeRawBounds(
                    materials, rawLengthsBySource, ct);

                await authority.RevalidateAsync(ct).ConfigureAwait(false);
            }

            var slots = new List<CurrentBootMenuSlot>();
            var companions = new List<CurrentBootMenuCompanion>();
            var reportSlots = new List<SlotReportFacts>();

            // Inactive first, current last; empty inactive stays no candidate.
            foreach (string slot in new[] { otherSlot, currentSlot })
            {
                ct.ThrowIfCancellationRequested();

                bool empty = targetEmpty[slot];
                if (empty)
                {
                    // A truly empty inactive slot is skipped as-is; nothing is
                    // manufactured or copied from the other slot.
                    slots.Add(new CurrentBootMenuSlot(
                        slot,
                        slot,
                        BootMaintenanceSourceKind.Empty,
                        BootMaintenanceBootTrust.StockOriginal,
                        targetBootClaims[slot],
                        null,
                        new Dictionary<string, string>(StringComparer.Ordinal),
                        null,
                        false));

                    reportSlots.Add(new SlotReportFacts(
                        slot,
                        slot,
                        "Empty",
                        "StockOriginal",
                        targetBootClaims[slot].Length,
                        targetBootClaims[slot].Sha256,
                        null,
                        null,
                        null,
                        null,
                        false,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null));
                    continue;
                }

                // The legitimate keep case: the real verifier already proved this
                // whole target boot against its own same-slot root. No candidate,
                // no raw, no budget, no default-cell facts, no loader claim.
                if (allStockNoChange)
                {
                    BootStockOriginalFacts stockFacts = stockFactsByTarget[slot];
                    slots.Add(new CurrentBootMenuSlot(
                        slot,
                        slot,
                        BootMaintenanceSourceKind.StockOriginal,
                        BootMaintenanceBootTrust.StockOriginal,
                        targetBootClaims[slot],
                        null,
                        new Dictionary<string, string>(StringComparer.Ordinal),
                        null,
                        true));

                    reportSlots.Add(new SlotReportFacts(
                        slot,
                        slot,
                        "StockOriginal",
                        "StockOriginal",
                        targetBootClaims[slot].Length,
                        targetBootClaims[slot].Sha256,
                        null,
                        null,
                        new Dictionary<string, string>(StringComparer.Ordinal),
                        null,
                        true,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        new StockFacts(
                            stockFacts.ImageSize,
                            stockFacts.Digest,
                            stockFacts.BootPublicKeySha256,
                            stockFacts.RootPublicKeySha256)));
                    continue;
                }

                string source = authority!.SourceSlots[slot];
                CurrentBootEfispFacts? efisp = null;
                if (backup.Files.TryGetValue("efisp", out EdlCapturedRegion efispRegion))
                {
                    efisp = new CurrentBootEfispFacts(
                        efispRegion.Lun,
                        efispRegion.SectorCount,
                        efispRegion.SectorSize,
                        efispRegion.Length,
                        efispRegion.Sha256);
                }

                InternalSlotMaterial material = materialsBySource![source];
                long bound = provenBounds![source];

                // Target boot is the actual TARGET claim; vendor/init/abl/xbl and
                // the root vbmeta stay the actual SOURCE captures. Target-specific
                // raw/candidate paths and unpack directories remain unique; the
                // source material itself is reused, never re-analyzed per target.
                string originalRawPath = Path.Combine(child, slot + OriginalRawSuffix);
                string changedRawPath = Path.Combine(child, slot + ChangedRawSuffix);
                string candidatePath = Path.Combine(child, slot + CandidateSuffix);

                var inputs = new CurrentBootSlotInputs(
                    slot,
                    targetBootClaims[slot],
                    RequireRole(backup, "vendor_boot_" + source),
                    RequireRole(backup, "init_boot_" + source),
                    RequireRole(backup, "abl_" + source),
                    RequireRole(backup, "xbl_config_" + source),
                    RequireRole(backup, "vbmeta_" + source),
                    efisp,
                    tools,
                    runner,
                    child,
                    Path.Combine(child, "source-" + source + BaseImageSuffix),
                    originalRawPath,
                    changedRawPath,
                    UnpackedOriginalDirectoryName + "-" + slot,
                    UnpackedChangedDirectoryName + "-" + slot,
                    candidatePath,
                    material,
                    authority,
                    bound,
                    source);

                CurrentBootSlotWork work = await EdlRawBootBuilder
                    .CurrentBootPrepareSlotAsync(inputs, ct)
                    .ConfigureAwait(false);

                VerifiedEdlFile? candidate = work.Candidate;
                if (candidate is not null)
                {
                    ownedLeases.Add(OpenOutputLease(candidate, "candidate boot of slot " + slot, ct));
                }

                slots.Add(new CurrentBootMenuSlot(
                    work.Slot,
                    work.SourceSlot,
                    work.SourceKind,
                    work.BootTrustMode,
                    work.Original,
                    work.Candidate,
                    work.PayloadSha256,
                    work.OriginalMetadataSha256,
                    work.PayloadDigestMatchesOem));

                reportSlots.Add(new SlotReportFacts(
                    work.Slot,
                    work.SourceSlot,
                    work.SourceKind.ToString(),
                    work.BootTrustMode.ToString(),
                    work.Original.Length,
                    work.Original.Sha256,
                    work.Candidate?.Length,
                    work.Candidate?.Sha256,
                    work.PayloadSha256,
                    work.OriginalMetadataSha256,
                    work.PayloadDigestMatchesOem,
                    work.DefaultIndexBefore,
                    work.DefaultIndexAfter,
                    work.DefaultCellOffset,
                    work.DefaultCellValueBefore,
                    work.DefaultCellValueAfter,
                    work.OnlyDefaultCellChanged,
                    new BudgetFacts(work.BudgetProfile, work.BudgetMaxRawBytes),
                    work.Gbl is null
                        ? null
                        : new GblFacts(
                            work.Gbl.EfispLun,
                            work.Gbl.EfispBytes,
                            work.Gbl.AblSha256,
                            work.Gbl.XblConfigSha256,
                            work.Gbl.LoaderEvidence),
                    work.Stock is null
                        ? null
                        : new StockFacts(
                            work.Stock.ImageSize,
                            work.Stock.Digest,
                            work.Stock.BootPublicKeySha256,
                            work.Stock.RootPublicKeySha256)));
            }

            // GBL companions are empty by contract; an AOSP root whose chain
            // descriptors keep the same signing key needs no rebuilt companion, and a
            // direct-hash parent refuses before any candidate exists.
            ct.ThrowIfCancellationRequested();

            // The authority and the tools are revalidated once more before any
            // success is reported. The tools revalidation is real: both pinned
            // executables are re-hashed against their compiled pins on both the
            // stock and the project route.
            await tools.RevalidateAsync(ct).ConfigureAwait(false);
            if (authority is not null)
            {
                await authority.RevalidateAsync(ct).ConfigureAwait(false);
            }

            string reportPath = Path.Combine(child, ReportFileName);
            (long reportBytes, string reportSha256) = WriteReport(
                reportPath,
                backup,
                currentSlot,
                slots,
                reportSlots,
                companions.Count,
                ct);

            var reportClaim = new VerifiedEdlFile(reportPath, reportBytes, reportSha256);
            ownedLeases.Add(OpenOutputLease(reportClaim, "verification report", ct));

            var plan = new CurrentBootMenuPlan(
                child,
                new ReadOnlyCollection<CurrentBootMenuSlot>(slots),
                new ReadOnlyCollection<CurrentBootMenuCompanion>(companions),
                reportClaim,
                ownedLeases,
                currentSlot,
                backup.Binding,
                backup.ManifestSha256,
                authority);

            ownershipTransferred = true;
            return plan;
        }
        catch (Exception error)
        {
            // The original exception keeps its identity and stack; cleanup in the
            // finally path must never replace it, only add to it when there was
            // no preparation error at all.
            preparationError = error;
            throw;
        }
        finally
        {
            // Every owned resource is attempted; one close failure never skips a
            // later cleanup step. When an original preparation error exists it is
            // preserved: cleanup failures are only surfaced when preparation had
            // already succeeded up to the release point.
            List<Exception>? cleanupErrors = null;

            if (tools is not null)
            {
                try
                {
                    tools.Dispose();
                }
                catch (Exception error)
                {
                    (cleanupErrors ??= new List<Exception>()).Add(error);
                }
            }

            if (!ownershipTransferred || cleanupErrors is not null)
            {
                // Failed factory, or a release failure with a plan pending
                // return: ownership can never reach the caller in either case,
                // so the authority, any untransferred proof, the output leases
                // and the own child are all cleaned here. Each is attempted in
                // order regardless of earlier failures.
                if (initializedProof is not null)
                {
                    try
                    {
                        initializedProof.Dispose();
                    }
                    catch (Exception error)
                    {
                        (cleanupErrors ??= new List<Exception>()).Add(error);
                    }
                }

                if (authority is not null)
                {
                    try
                    {
                        authority.Dispose();
                    }
                    catch (Exception error)
                    {
                        (cleanupErrors ??= new List<Exception>()).Add(error);
                    }
                }

                foreach (FileStream stream in ownedLeases)
                {
                    try
                    {
                        stream.Dispose();
                    }
                    catch (Exception error)
                    {
                        (cleanupErrors ??= new List<Exception>()).Add(error);
                    }
                }

                TryDeleteOwnedChild(child);
            }

            if (cleanupErrors is not null && preparationError is null)
            {
                throw new AggregateException(cleanupErrors);
            }
        }
    }

    // ------------------------------------------------------------- helpers

    private static string NormalizeParent(string? chosenParent)
    {
        if (string.IsNullOrWhiteSpace(chosenParent) || chosenParent.Contains('\0'))
        {
            throw new ArgumentException(
                "chosen parent must name an existing directory path.", nameof(chosenParent));
        }

        string parent = Path.GetFullPath(chosenParent);
        if (File.Exists(parent))
        {
            throw new IOException("The chosen parent is a file, not a directory: '" + parent + "'.");
        }

        if (!Directory.Exists(parent))
        {
            throw new IOException("The chosen parent directory does not exist: '" + parent + "'.");
        }

        return parent;
    }

    private static void RequireBoundBackup(InternalBackupSet backup)
    {
        if (string.IsNullOrWhiteSpace(backup.Model)
            || string.IsNullOrWhiteSpace(backup.ProfileId)
            || string.IsNullOrWhiteSpace(backup.AndroidBuild)
            || string.IsNullOrWhiteSpace(backup.HardwareId)
            || backup.Binding is null)
        {
            throw new InvalidOperationException(
                "requires-bound-backup: the backup set carries no complete model, profile, hardware id or binding.");
        }
    }

    private static VerifiedEdlFile RequireRole(InternalBackupSet backup, string role)
    {
        if (!backup.Files.TryGetValue(role, out EdlCapturedRegion region))
        {
            throw new InvalidDataException(
                "requires-complete-backup: the verified backup is missing the role '" + role + "'.");
        }

        return new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);
    }

    private static FileStream OpenOutputLease(VerifiedEdlFile claim, string role, CancellationToken ct)
    {
        var stream = new FileStream(
            claim.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);

        try
        {
            if (stream.Length != claim.Length)
            {
                throw new InvalidDataException(role + " length changed before the lease was taken.");
            }

            stream.Position = 0;
            string sha256 = Convert.ToHexString(SHA256.HashDataAsync(stream, ct).GetAwaiter().GetResult()).ToLowerInvariant();
            if (!string.Equals(sha256, claim.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(role + " bytes changed before the lease was taken.");
            }

            stream.Position = 0;
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void TryDeleteOwnedChild(string child)
    {
        try
        {
            if (Directory.Exists(child))
            {
                Directory.Delete(child, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    // -------------------------------------------------------------- report

    private sealed record BudgetFacts(string Profile, long MaxRawBytes);

    private sealed record GblFacts(
        int EfispLun,
        long EfispBytes,
        string AblSha256,
        string XblConfigSha256,
        string LoaderEvidence);

    private sealed record StockFacts(
        long ImageSize,
        string Digest,
        string BootPublicKeySha256,
        string RootPublicKeySha256);

    private sealed record SlotReportFacts(
        string Slot,
        string SourceSlot,
        string SourceKind,
        string BootTrustMode,
        long OriginalBytes,
        string OriginalSha256,
        long? CandidateBytes,
        string? CandidateSha256,
        IReadOnlyDictionary<string, string>? PayloadSha256,
        string? OriginalMetadataSha256,
        bool PayloadDigestMatchesOem,
        uint? DefaultIndexBefore,
        uint? DefaultIndexAfter,
        long? DefaultCellOffset,
        uint? DefaultCellValueBefore,
        uint? DefaultCellValueAfter,
        bool? OnlyDefaultCellChanged,
        BudgetFacts? Budget,
        GblFacts? Gbl,
        StockFacts? Stock);

    private static (long Bytes, string Sha256) WriteReport(
        string reportPath,
        InternalBackupSet backup,
        string currentSlot,
        IReadOnlyList<CurrentBootMenuSlot> slots,
        IReadOnlyList<SlotReportFacts> facts,
        int companionCount,
        CancellationToken ct)
    {
        using (FileStream report = new FileStream(
                   reportPath,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   64 * 1024))
        {
            using (Utf8JsonWriter writer = new(report, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteNumber("schemaVersion", 1);
                writer.WriteString("model", backup.Model);
                writer.WriteString("profileId", backup.ProfileId);
                writer.WriteString("hardwareId", backup.HardwareId);
                writer.WriteString("currentSlot", currentSlot);

                writer.WriteStartArray("slots");
                for (int index = 0; index < slots.Count; index++)
                {
                    CurrentBootMenuSlot slot = slots[index];
                    SlotReportFacts fact = facts[index];

                    writer.WriteStartObject();
                    writer.WriteString("slot", slot.Slot);
                    writer.WriteString("sourceSlot", slot.SourceSlot);
                    writer.WriteString("sourceKind", fact.SourceKind);
                    writer.WriteString("bootTrustMode", fact.BootTrustMode);

                    writer.WriteStartObject("original");
                    writer.WriteNumber("bytes", fact.OriginalBytes);
                    writer.WriteString("sha256", fact.OriginalSha256);
                    writer.WriteEndObject();

                    if (fact.CandidateBytes is long candidateBytes)
                    {
                        writer.WriteStartObject("candidate");
                        writer.WriteNumber("bytes", candidateBytes);
                        writer.WriteString("sha256", fact.CandidateSha256);
                        writer.WriteEndObject();
                    }
                    else
                    {
                        writer.WriteNull("candidate");
                    }

                    writer.WriteStartObject("payloadSha256");
                    if (fact.PayloadSha256 is not null)
                    {
                        foreach (KeyValuePair<string, string> pair in fact.PayloadSha256)
                        {
                            writer.WriteString(pair.Key, pair.Value);
                        }
                    }

                    writer.WriteEndObject();

                    if (fact.OriginalMetadataSha256 is null)
                    {
                        writer.WriteNull("originalMetadataSha256");
                    }
                    else
                    {
                        writer.WriteString("originalMetadataSha256", fact.OriginalMetadataSha256);
                    }

                    writer.WriteBoolean("payloadDigestMatchesOem", fact.PayloadDigestMatchesOem);

                    if (fact.DefaultIndexBefore is uint defaultBefore)
                    {
                        writer.WriteStartObject("defaultCell");
                        writer.WriteNumber("indexBefore", defaultBefore);
                        writer.WriteNumber("indexAfter", fact.DefaultIndexAfter!.Value);
                        writer.WriteNumber("cellOffset", fact.DefaultCellOffset!.Value);
                        writer.WriteNumber("cellValueBefore", fact.DefaultCellValueBefore!.Value);
                        writer.WriteNumber("cellValueAfter", fact.DefaultCellValueAfter!.Value);
                        writer.WriteBoolean("onlyDefaultCellChanged", fact.OnlyDefaultCellChanged!.Value);
                        writer.WriteEndObject();
                    }
                    else
                    {
                        writer.WriteNull("defaultCell");
                    }

                    if (fact.Budget is not null)
                    {
                        writer.WriteStartObject("loaderBudget");
                        writer.WriteString("profile", fact.Budget.Profile);
                        writer.WriteNumber("maxRawBytes", fact.Budget.MaxRawBytes);
                        writer.WriteEndObject();
                    }
                    else
                    {
                        writer.WriteNull("loaderBudget");
                    }

                    if (fact.Gbl is not null)
                    {
                        writer.WriteStartObject("gbl");
                        writer.WriteNumber("efispLun", fact.Gbl.EfispLun);
                        writer.WriteNumber("efispBytes", fact.Gbl.EfispBytes);
                        writer.WriteString("ablSha256", fact.Gbl.AblSha256);
                        writer.WriteString("xblConfigSha256", fact.Gbl.XblConfigSha256);
                        writer.WriteString("loaderEvidence", fact.Gbl.LoaderEvidence);
                        writer.WriteEndObject();
                    }
                    else
                    {
                        writer.WriteNull("gbl");
                    }

                    if (fact.Stock is not null)
                    {
                        writer.WriteStartObject("stock");
                        writer.WriteNumber("imageSize", fact.Stock.ImageSize);
                        writer.WriteString("digest", fact.Stock.Digest);
                        writer.WriteString("bootPublicKeySha256", fact.Stock.BootPublicKeySha256);
                        writer.WriteString("rootPublicKeySha256", fact.Stock.RootPublicKeySha256);
                        writer.WriteEndObject();
                    }
                    else
                    {
                        writer.WriteNull("stock");
                    }

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();

                writer.WriteNumber("companionCount", companionCount);

                // Factual truth only: nothing here claims OEM acceptance, an OS boot,
                // a device write or any readiness. These are the facts the report
                // does and does not carry.
                writer.WriteStartObject("truth");
                writer.WriteBoolean("oemAcceptanceClaimed", false);
                writer.WriteBoolean("osBootVerified", false);
                writer.WriteBoolean("deviceWritten", false);
                writer.WriteBoolean("digestSeparateFromSignature", true);
                writer.WriteEndObject();

                writer.WriteEndObject();
            }

            report.Flush(true);
        }

        string sha;
        using (FileStream readBack = new FileStream(
                   reportPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   64 * 1024,
                   FileOptions.SequentialScan))
        {
            ct.ThrowIfCancellationRequested();
            sha = Convert.ToHexString(SHA256.HashDataAsync(readBack, ct).GetAwaiter().GetResult()).ToLowerInvariant();
        }

        long length = new FileInfo(reportPath).Length;
        return (length, sha);
    }
}
