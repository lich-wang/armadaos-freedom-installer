using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The one real backend of BeforeUpdate/RestoreStock boot maintenance: a stateful, single-use object that owns
/// the preparation evidence and the exact stock source leases of exactly one pass.
/// <para>
/// An instance only ever comes from <see cref="CreatePreparedAsync"/>. The factory verifies the caller's claims
/// against actual facts - the complete Step 1 result, the bound EDL session, an independently re-opened current
/// rollback backup, a fresh six-LUN probe and a fresh readback of every captured region, and the fully verified
/// stock original source - and either produces a <see cref="Prepared"/> result or refuses with a stable error
/// code. <see cref="MaintenanceMode.AfterUpdate"/> routes to its dedicated factory in the
/// <c>BootMaintenanceBackend.After</c> partial, which proves template or repair-package fallback freshness
/// before any plan or write exists.
/// </para>
/// <para>
/// Preparation never writes and never resets: every device operation before execution is a warm probe or a
/// read into this backend's own evidence directory. The candidate claims are the exact whole original stock
/// files of the historical source, byte-identical, never repacked or re-signed, and only the four full
/// partition roles <c>boot_s</c>, <c>recovery_s</c>, <c>vbmeta_system_s</c> and <c>vbmeta_s</c> can enter the
/// plan. No ABL, xbl, efisp, GPT, misc, userdata, Linux, format or set-active action exists here.
/// </para>
/// <para>
/// <see cref="Dispose"/> releases only the read leases this backend owns through its two own sets; it never
/// deletes evidence, never rewinds the device and never disposes the caller's backup, client or runner.
/// </para>
/// </summary>
public sealed partial class BootMaintenanceBackend : IDisposable
{
    private const string DeviceCheckIncompleteCode = "boot-maintenance-device-check-incomplete";

    private const string BindingMismatchCode = "boot-maintenance-session-binding-mismatch";

    private const string ForgedBackupCode = "boot-maintenance-forged-backup";

    private const string SourceUnavailableCode = "boot-maintenance-source-unavailable";

    private const string ActiveSourceEmptyCode = "boot-maintenance-active-source-empty";

    private const string PlanIncompleteCode = "boot-maintenance-plan-incomplete";

    private const string ConfirmationMismatchCode = "boot-maintenance-confirmation-mismatch";

    private const string ExecutionConflictCode = "boot-maintenance-execution-conflict";

    private const string AlreadyExecutedCode = "boot-maintenance-already-executed";

    private const string FreshnessCode = "boot-maintenance-freshness-mismatch";

    private const int HashBufferBytes = 81920;

    private static readonly string[] PlanRolesPerSlot = { "boot_", "recovery_", "vbmeta_system_", "vbmeta_" };

    private readonly object _gate = new();

    private readonly MaintenanceMode? _mode;

    private readonly MaintenanceDeviceFacts _deviceFacts;

    private readonly string _miscControlSha256;

    private readonly EdlClient _client;

    private readonly ICommandRunner _runner;

    /// <summary>The caller's current rollback proof; never disposed here.</summary>
    private readonly InternalBackupSet _callerBackup;

    /// <summary>This backend's own re-opened current rollback set, held until <see cref="Dispose"/>.</summary>
    private readonly InternalBackupSet _ownedCurrent;

    /// <summary>The historical stock original source set, held until <see cref="Dispose"/>.</summary>
    private readonly InternalBackupSet _source;

    private readonly IReadOnlyList<PlannedRegion> _plan;

    private readonly IReadOnlyList<BootMaintenanceSlotSummary> _slotSummaries;

    private readonly string _currentSlot;

    private readonly string _evidenceDirectory;

    private readonly string _confirmationSha256;

    private readonly BootMaintenancePrepared? _prepared;

    /// <summary>Extra read leases this backend owns; only future real TF candidate leases land here.</summary>
    private readonly List<IDisposable> _additionalOwned;

    private List<string> _verifiedRegions = new();

    /// <summary>Private execution-policy selector; not public surface. Only TF RestorePrevious may deviate.</summary>
    private enum RegionExecutionPolicy
    {
        Normal,
        TfRestorePrevious
    }

    /// <summary>The policy fixed at preparation; Normal for every real maintenance mode and existing caller.</summary>
    private readonly RegionExecutionPolicy _executionPolicy;

    private InternalInstallWriteState _writeState = InternalInstallWriteState.NoneIssued;

    private BootMaintenanceSnapshot _snapshot;

    private bool _executionStarted;

    private bool _executing;

    private bool _hasExecuted;

    private bool _disposed;

    /// <summary>
    /// Private constructor: an instance exists only as the result of a successful preparation, so no caller can
    /// assemble a backend from its own parts.
    /// </summary>
    private BootMaintenanceBackend(
        MaintenanceMode? mode,
        MaintenanceDeviceFacts deviceFacts,
        string miscControlSha256,
        EdlClient client,
        ICommandRunner runner,
        InternalBackupSet callerBackup,
        InternalBackupSet ownedCurrent,
        InternalBackupSet source,
        List<PlannedRegion> plan,
        List<BootMaintenanceSlotSummary> slotSummaries,
        string currentSlot,
        string evidenceDirectory,
        string confirmationSha256,
        BootMaintenancePrepared? prepared,
        List<IDisposable>? additionalOwned = null,
        RegionExecutionPolicy executionPolicy = RegionExecutionPolicy.Normal)
    {
        if (executionPolicy != RegionExecutionPolicy.Normal
            && executionPolicy != RegionExecutionPolicy.TfRestorePrevious)
        {
            throw new ArgumentOutOfRangeException(nameof(executionPolicy));
        }

        if (mode.HasValue && executionPolicy != RegionExecutionPolicy.Normal)
        {
            throw new InvalidOperationException(
                "Only an internal TF-plan backend (no maintenance mode) may use a non-Normal "
                + "execution policy.");
        }

        _mode = mode;
        _executionPolicy = executionPolicy;
        _additionalOwned = additionalOwned is null
            ? new List<IDisposable>()
            : new List<IDisposable>(additionalOwned);
        _deviceFacts = deviceFacts;
        _miscControlSha256 = miscControlSha256;
        _client = client;
        _runner = runner;
        _callerBackup = callerBackup;
        _ownedCurrent = ownedCurrent;
        _source = source;
        _plan = plan;
        _slotSummaries = slotSummaries;
        _currentSlot = currentSlot;
        _evidenceDirectory = evidenceDirectory;
        _confirmationSha256 = confirmationSha256;
        _prepared = prepared;
        _snapshot = new BootMaintenanceSnapshot(
            executionStarted: false,
            InternalInstallStage.Prepared,
            InternalInstallWriteState.NoneIssued,
            outcome: null,
            error: null);
    }

    /// <summary>
    /// Verifies every input against actual facts and produces the prepared state for exactly one
    /// BeforeUpdate or RestoreStock pass; AfterUpdate routes to its dedicated AfterUpdate factory.
    /// <para>
    /// Every refusal is an <see cref="InvalidOperationException"/> whose message starts with a stable code:
    /// <c>boot-maintenance-device-check-incomplete</c>,
    /// <c>boot-maintenance-session-binding-mismatch</c>, <c>boot-maintenance-forged-backup</c>,
    /// <c>boot-maintenance-source-unavailable</c>, <c>boot-maintenance-active-source-empty</c>,
    /// <c>boot-maintenance-plan-incomplete</c> or <c>boot-maintenance-freshness-mismatch</c>. Missing
    /// arguments are rejected as <see cref="ArgumentNullException"/>, a blank evidence parent or source
    /// directory as <see cref="ArgumentException"/>, and a pre-cancelled token before anything is read.
    /// </para>
    /// <para>
    /// The original backup directory is required for both supported modes; the repair package and the boot
    /// tools are deliberately not required here. There is no active-slot-A restriction and no Android build
    /// allowlist: the actual observed facts decide.
    /// </para>
    /// </summary>
    public static async Task<BootMaintenanceBackend> CreatePreparedAsync(
        MaintenanceMode mode,
        InternalDeviceCheckResult deviceCheck,
        EdlClient client,
        InternalBackupSet currentBackup,
        BootMaintenanceSources sources,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceCheck);

        // Android route: the facts carry the actual Step-1 result as the only origin; no history exists.
        return await CreatePreparedCoreAsync(
            mode,
            new MaintenanceDeviceFacts(deviceCheck.Android!, deviceCheck, null),
            client,
            currentBackup,
            sources,
            runner,
            evidenceParent,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The shared preparation core of both factory routes (Android-live and EDL-historical). Every guard,
    /// source rule, evidence flow and plan rule is exactly the original factory; the only route difference
    /// is the immutable <see cref="MaintenanceDeviceFacts"/> origin carried in. AfterUpdate routes to its
    /// dedicated factory, and the device-facts validation runs after the mode/argument guards and the
    /// pre-cancel gate.
    /// </summary>
    private static async Task<BootMaintenanceBackend> CreatePreparedCoreAsync(
        MaintenanceMode mode,
        MaintenanceDeviceFacts deviceFacts,
        EdlClient client,
        InternalBackupSet currentBackup,
        BootMaintenanceSources sources,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "The maintenance mode is not a known value.");
        }

        ArgumentNullException.ThrowIfNull(deviceFacts);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(runner);

        if (evidenceParent is null)
        {
            throw new ArgumentNullException(nameof(evidenceParent));
        }

        if (evidenceParent.Trim().Length == 0)
        {
            throw new ArgumentException(
                "An explicit evidence parent directory is required; there is no default location.",
                nameof(evidenceParent));
        }

        // Nothing below this line may run for a caller that already cancelled; no resource is dereferenced first.
        cancellationToken.ThrowIfCancellationRequested();

        if (mode == MaintenanceMode.AfterUpdate)
        {
            return await CreateAfterPreparedCoreAsync(
                deviceFacts,
                client,
                currentBackup,
                sources,
                runner,
                evidenceParent,
                progress,
                cancellationToken).ConfigureAwait(false);
        }

        string? originalDirectory = sources.OriginalBackupDirectory;
        if (string.IsNullOrWhiteSpace(originalDirectory))
        {
            throw new ArgumentException(
                "An explicit original backup directory is required for BeforeUpdate and RestoreStock.",
                nameof(sources));
        }

        await RequireDeviceFactsAsync(deviceFacts, client, cancellationToken).ConfigureAwait(false);
        RequireTrustedProfile(client);
        RequireCallerBackupBinding(client, currentBackup);

        string parent = Path.GetFullPath(evidenceParent);
        if (File.Exists(parent))
        {
            throw new IOException("The evidence parent is a file, not a directory: '" + parent + "'.");
        }

        if (!Directory.Exists(parent))
        {
            throw new IOException("The evidence parent directory does not exist: '" + parent + "'.");
        }

        string evidenceDirectory = Path.Combine(parent, "boot-maint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(evidenceDirectory);

        progress?.Report(new InternalInstallProgress(
            InternalInstallStage.Revalidating,
            InternalInstallProgressKind.Started,
            InternalInstallWriteState.NoneIssued,
            null,
            0,
            0,
            "reopening-current-backup"));

        InternalBackupSet ownedCurrent = await InternalInstallBackup
            .OpenExistingAsync(client, currentBackup.DirectoryPath, null, cancellationToken)
            .ConfigureAwait(false);

        InternalBackupSet source = null!;
        try
        {
            if (!string.Equals(
                    ownedCurrent.ManifestSha256,
                    currentBackup.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    ForgedBackupCode + ": the re-opened backup manifest does not hash to the manifest the "
                    + "caller passed; the selected backup is not the session's current rollback proof.");
            }

            RequireSameCapture(ownedCurrent, currentBackup);

            await ProbeSixLunsAsync(client, ownedCurrent, cancellationToken).ConfigureAwait(false);

            await ReadbackEveryCurrentRegionAsync(
                client, ownedCurrent, evidenceDirectory, progress, cancellationToken).ConfigureAwait(false);

            // The freshly verified misc capture is the only slot authority here: it was just re-read from
            // the device and hashed back to the held capture, so its GPT control bytes are actual facts.
            BootSlotControlFacts miscFacts = await BootSlotControl
                .ReadAsync(RegionClaim(ownedCurrent.Files, "misc", "the current rollback capture"), cancellationToken)
                .ConfigureAwait(false);

            // Same fresh capture, modern virtual A/B message: the OTA must be factually Completed
            // before any rollback mutation. SourceSlot is provenance only and never the active slot.
            BootVirtualAbControlFacts virtualAbFacts = await BootVirtualAbControl
                .ReadAsync(RegionClaim(ownedCurrent.Files, "misc", "the current rollback capture"), cancellationToken)
                .ConfigureAwait(false);

            WriteReceipt(
                evidenceDirectory,
                "virtual-ab-context",
                writer =>
                {
                    writer.WriteString("state", virtualAbFacts.State.ToString());
                    writer.WriteString("messageSha256", virtualAbFacts.MessageSha256);
                    if (virtualAbFacts.SourceSlot is int sourceSlot)
                    {
                        writer.WriteNumber("sourceSlot", sourceSlot);
                    }
                    else
                    {
                        writer.WriteNull("sourceSlot");
                    }

                    writer.WriteString("miscSha256", virtualAbFacts.Misc.Sha256);
                });

            if (!virtualAbFacts.IsFormatValid || virtualAbFacts.State != BootVirtualAbState.Completed)
            {
                throw new InvalidOperationException(
                    "boot-maintenance-ota-not-completed: the fresh misc virtual A/B state is "
                    + virtualAbFacts.State + " (format valid: " + virtualAbFacts.IsFormatValid
                    + "); no rollback maintenance may run before the OTA merge is Completed.");
            }

            progress?.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Started,
                InternalInstallWriteState.NoneIssued,
                null,
                0,
                0,
                "opening-original-source"));

            source = await InternalInstallBackup
                .OpenBootMaintenanceOriginalAsync(client, ownedCurrent, originalDirectory, cancellationToken)
                .ConfigureAwait(false);

            // The Android route keeps its explicit Step-1 slot guard; the EDL route trusts only the fresh
            // misc control slot. There is never a default, a history slot or a VAB source slot guess.
            string currentSlot = miscFacts.CurrentSlot;
            if (deviceFacts.AndroidCheck is not null)
            {
                if (!string.Equals(
                        RequireCurrentSlot(deviceFacts.AndroidCheck), currentSlot, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        DeviceCheckIncompleteCode
                        + ": the Step 1 current slot does not match the freshly verified misc control slot.");
                }
            }

            string inactiveSlot = currentSlot == "a" ? "b" : "a";
            var slotOrder = new[] { inactiveSlot, currentSlot };

            var slotSummaries = new List<BootMaintenanceSlotSummary>(2);
            var plan = new List<PlannedRegion>();

            foreach (string slot in slotOrder)
            {
                cancellationToken.ThrowIfCancellationRequested();

                EdlCapturedRegion sourceBoot = RequireRegion(source.Files, "boot_" + slot, "the original source");
                FileFacts boot = await InspectFileAsync(
                    sourceBoot.FilePath, sourceBoot.Length, cancellationToken).ConfigureAwait(false);

                if (boot.AllZero)
                {
                    if (string.Equals(slot, currentSlot, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            ActiveSourceEmptyCode + ": the active slot's original boot image is entirely zero, "
                            + "so no truthful stock candidate exists; the backend refuses before Ready instead "
                            + "of clearing the active slot or borrowing the other slot's image.");
                    }

                    slotSummaries.Add(new BootMaintenanceSlotSummary(
                        slot,
                        slot,
                        BootMaintenanceSourceKind.Empty,
                        string.Empty,
                        null,
                        willWrite: false));
                    continue;
                }

                BootStockOriginalFacts stock = await EdlRawBootBuilder
                    .VerifyStockOriginalBootAsync(
                        new VerifiedEdlFile(sourceBoot.FilePath, sourceBoot.Length, boot.Sha256),
                        RegionClaim(source.Files, "vbmeta_" + slot, "the original source"),
                        cancellationToken)
                    .ConfigureAwait(false);

                // Companion source-chain proof before any slot candidate or summary enters the plan: the
                // six metadata RSA nodes/root-child keys, the source recovery physical salted digest and
                // the source/current authenticated descriptor, rollback and flags equality. The boot
                // verifier above already proved the boot images; this proves the rest of the stock chain.
                BootStockMaintenanceChainFacts chain = await EdlRawBootBuilder
                    .VerifyStockMaintenanceChainAsync(
                        RegionClaim(source.Files, "vbmeta_" + slot, "the original source"),
                        RegionClaim(source.Files, "recovery_" + slot, "the original source"),
                        RegionClaim(source.Files, "vbmeta_system_" + slot, "the original source"),
                        RegionClaim(ownedCurrent.Files, "vbmeta_" + slot, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "recovery_" + slot, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "vbmeta_system_" + slot, "the current rollback capture"),
                        cancellationToken)
                    .ConfigureAwait(false);

                WriteReceipt(evidenceDirectory, "stock-chain-" + slot, writer =>
                {
                    writer.WriteString("kind", "stock-chain");
                    writer.WriteString("slot", slot);
                    writer.WriteString("sourceRootSha256", chain.SourceRoot.Sha256);
                    writer.WriteString("sourceRecoverySha256", chain.SourceRecovery.Sha256);
                    writer.WriteString("sourceVbmetaSystemSha256", chain.SourceVbmetaSystem.Sha256);
                    writer.WriteString("currentRootSha256", chain.CurrentRoot.Sha256);
                    writer.WriteString("currentRecoverySha256", chain.CurrentRecovery.Sha256);
                    writer.WriteString("currentVbmetaSystemSha256", chain.CurrentVbmetaSystem.Sha256);
                    writer.WriteString("sourceBootPublicKeySha256", stock.BootPublicKeySha256);
                    writer.WriteString("sourceRootPublicKeySha256", stock.RootPublicKeySha256);
                    writer.WriteNumber("sourceBootImageSize", stock.ImageSize);
                    writer.WriteString("sourceBootDigest", stock.Digest);
                    writer.WriteNumber("recoveryImageSize", chain.RecoveryImageSize);
                    writer.WriteString("recoveryDigestHex", chain.RecoveryDigestHex);
                    writer.WriteString("sourceRootKeySha256", chain.SourceRootKeySha256);
                    writer.WriteString("sourceRecoveryKeySha256", chain.SourceRecoveryKeySha256);
                    writer.WriteString("sourceVbmetaSystemKeySha256", chain.SourceVbmetaSystemKeySha256);
                    writer.WriteString("currentRootKeySha256", chain.CurrentRootKeySha256);
                    writer.WriteString("currentRecoveryKeySha256", chain.CurrentRecoveryKeySha256);
                    writer.WriteString("currentVbmetaSystemKeySha256", chain.CurrentVbmetaSystemKeySha256);
                    writer.WriteString("rootNonChainDescriptorsSha256",
                        chain.RootNonChainDescriptorsSha256);
                    writer.WriteString("recoveryNonChainDescriptorsSha256",
                        chain.RecoveryNonChainDescriptorsSha256);
                    writer.WriteString("vbmetaSystemNonChainDescriptorsSha256",
                        chain.VbmetaSystemNonChainDescriptorsSha256);
                    writer.WriteNumber("rollbackIndex", unchecked((decimal)chain.RollbackIndex));
                    writer.WriteNumber("rollbackIndexLocation", chain.RollbackIndexLocation);
                    writer.WriteNumber("flags", chain.Flags);
                    writer.WriteString("scope",
                        "six metadata RSA nodes/root-child keys and the source recovery physical salted "
                        + "digest checked; system filesystem contents, hardware rollback state and OS "
                        + "acceptance are not checked by this proof.");
                });

                bool bootWillWrite = false;
                string? bootCandidateSha = null;

                foreach (string rolePrefix in PlanRolesPerSlot)
                {
                    string role = rolePrefix + slot;
                    EdlCapturedRegion current = RequireRegion(
                        ownedCurrent.Files, role, "the current rollback capture");
                    EdlCapturedRegion sourceRegion = RequireRegion(source.Files, role, "the original source");

                    RequireWholeRegion(current, sourceRegion, role);

                    bool willWrite = !string.Equals(
                        current.Sha256, sourceRegion.Sha256, StringComparison.OrdinalIgnoreCase);

                    if (willWrite)
                    {
                        plan.Add(new PlannedRegion(
                            role,
                            slot,
                            current.Lun,
                            current.StartSector,
                            current.SectorCount,
                            current.Length,
                            current.Sha256,
                            sourceRegion.FilePath,
                            sourceRegion.Sha256));
                    }
                    else
                    {
                        plan.Add(new PlannedRegion(
                            role,
                            slot,
                            current.Lun,
                            current.StartSector,
                            current.SectorCount,
                            current.Length,
                            current.Sha256,
                            null,
                            null));
                    }

                    if (string.Equals(rolePrefix, "boot_", StringComparison.Ordinal))
                    {
                        bootWillWrite = willWrite;
                        bootCandidateSha = willWrite ? sourceRegion.Sha256 : null;
                    }
                }

                slotSummaries.Add(new BootMaintenanceSlotSummary(
                    slot,
                    slot,
                    BootMaintenanceSourceKind.StockOriginal,
                    boot.Sha256,
                    bootCandidateSha,
                    bootWillWrite));
            }

            if (plan.Count == 0 && slotSummaries.Count == 0)
            {
                throw new InvalidOperationException(
                    PlanIncompleteCode + ": neither slot produced a truthful plan from the verified sources.");
            }

            var regionSummaries = new List<BootMaintenanceRegionSummary>(plan.Count);
            foreach (PlannedRegion region in plan)
            {
                regionSummaries.Add(new BootMaintenanceRegionSummary(
                    region.Role,
                    region.Slot,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length,
                    region.CurrentSha256,
                    region.CandidateSha256,
                    region.WillWrite));
            }

            DeviceIdentity identity = deviceFacts.Identity.Identity;
            string confirmationSha256 = BuildConfirmationSha256(
                mode,
                deviceFacts,
                client,
                miscFacts.ControlSha256,
                currentSlot,
                ownedCurrent.ManifestSha256,
                source.ManifestSha256,
                ownedCurrent.Geometries,
                plan,
                Path.GetFileName(evidenceDirectory));

            BootMaintenancePrepared prepared = new(
                mode,
                confirmationSha256,
                identity.Model,
                identity.Serial,
                deviceFacts.Identity.SocSerial,
                currentSlot,
                ownedCurrent.DirectoryPath,
                evidenceDirectory,
                BootMaintenanceBootTrust.StockOriginal,
                slotSummaries,
                regionSummaries);

            WritePrepareReceipt(evidenceDirectory, mode, prepared, plan.Count);

            WriteIdentityContextReceipt(
                evidenceDirectory,
                deviceFacts,
                client,
                RequireRegion(ownedCurrent.Files, "misc", "the current rollback capture").Sha256,
                miscFacts.ControlSha256,
                currentSlot);

            progress?.Report(new InternalInstallProgress(
                InternalInstallStage.Prepared,
                InternalInstallProgressKind.Verified,
                InternalInstallWriteState.NoneIssued,
                currentSlot,
                plan.Count,
                plan.Count,
                "boot-maintenance-prepared"));

            return new BootMaintenanceBackend(
                mode,
                deviceFacts,
                miscFacts.ControlSha256,
                client,
                runner,
                currentBackup,
                ownedCurrent,
                source,
                plan,
                slotSummaries,
                currentSlot,
                evidenceDirectory,
                confirmationSha256,
                prepared);
        }
        catch
        {
            source?.Dispose();
            ownedCurrent.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The verified preparation data of this instance. Getter-only: the value is fixed when the factory succeeds
    /// and can never be replaced or edited by a caller.
    /// </summary>
    public BootMaintenancePrepared Prepared =>
        _prepared
        ?? throw new InvalidOperationException(
            "This backend instance carries an internal TF plan and has no maintenance Prepared data.");

    /// <summary>
    /// The authoritative current state of this instance. Getter-only: the backend replaces its own snapshot, a
    /// caller only reads it.
    /// </summary>
    public BootMaintenanceSnapshot Snapshot
    {
        get
        {
            lock (_gate)
            {
                return _snapshot;
            }
        }
    }

    /// <summary>
    /// Releases only the read leases this backend owns through its own two sets. Idempotent; it never deletes
    /// evidence, resets a device or disposes the caller's objects, and it refuses while an execution is running.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (_executing)
            {
                throw new InvalidOperationException(
                    "The boot maintenance backend cannot be disposed while an execution is running.");
            }

            _disposed = true;
        }

        List<Exception>? closeFailures = null;
        try
        {
            _source.Dispose();
        }
        catch (Exception exception)
        {
            closeFailures = new List<Exception> { exception };
        }
        finally
        {
            try
            {
                _ownedCurrent.Dispose();
            }
            catch (Exception exception)
            {
                closeFailures ??= new List<Exception>();
                closeFailures.Add(exception);
            }
            finally
            {
                foreach (IDisposable lease in _additionalOwned)
                {
                    try
                    {
                        lease.Dispose();
                    }
                    catch (Exception exception)
                    {
                        closeFailures ??= new List<Exception>();
                        closeFailures.Add(exception);
                    }
                }
            }
        }

        if (closeFailures is not null)
        {
            throw new AggregateException(
                "One or more boot maintenance read leases failed to close.", closeFailures);
        }
    }

    // ------------------------------------------------------------------ cheap guards

    private static void RequireCompleteDeviceCheck(InternalDeviceCheckResult deviceCheck)
    {
        AndroidMaintenanceIdentity? android = deviceCheck.Android;
        DeviceIdentity? identity = android?.Identity;
        FirmwareSnapshot? firmware = identity?.Firmware;

        bool complete = deviceCheck.Succeeded
            && android is not null
            && identity is not null
            && firmware is not null
            && !string.IsNullOrWhiteSpace(firmware.DisplayId)
            && !string.IsNullOrWhiteSpace(firmware.BuildFingerprint)
            && !string.IsNullOrWhiteSpace(firmware.AndroidRelease)
            && !string.IsNullOrWhiteSpace(firmware.SecurityPatch);

        if (!complete)
        {
            throw new InvalidOperationException(
                DeviceCheckIncompleteCode
                + ": the Step 1 result is not a complete, verified device check with a full firmware snapshot.");
        }
    }

    private static string RequireCurrentSlot(InternalDeviceCheckResult deviceCheck)
    {
        if (deviceCheck.CurrentSlot is not ("a" or "b"))
        {
            throw new InvalidOperationException(
                DeviceCheckIncompleteCode
                + ": the observed current slot is '" + (deviceCheck.CurrentSlot ?? "<none>")
                + "'; boot maintenance requires an exact a or b.");
        }

        return deviceCheck.CurrentSlot;
    }

    private static void RequireBoundSession(InternalDeviceCheckResult deviceCheck, EdlClient client)
    {
        AndroidMaintenanceIdentity android = deviceCheck.Android!;
        DeviceIdentity identity = android.Identity;

        EdlEntryResult binding = client.Binding
            ?? throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL client carries no binding.");

        if (binding.AndroidIdentity is null || binding.AndroidIdentity.Identity is null)
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL binding carries no Android identity.");
        }

        if (!SameAndroidIdentity(binding.AndroidIdentity, android))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL binding is not the device the Step 1 check verified.");
        }

        if (!string.Equals(deviceCheck.FastbootSerial, identity.Serial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the fastboot serial does not match the verified Android serial.");
        }
    }

    private static void RequireTrustedProfile(EdlClient client)
    {
        EdlToolchain toolchain = client.Toolchain;
        EdlDeviceProfile profile = toolchain.Profile;

        if (profile is null)
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the loaded toolchain carries no trusted EDL profile.");
        }

        if (!ReferenceEquals(EdlDeviceProfiles.FindById(profile.ProfileId), profile))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the loaded EDL profile '" + profile.ProfileId
                + "' is not the trusted built-in instance.");
        }

        profile.RequireComplete();

        AndroidMaintenanceIdentity android = client.Binding.AndroidIdentity!;
        DeviceIdentity identity = android.Identity;

        if (!profile.SupportsIdentity(identity))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the trusted EDL profile '"
                + profile.ProfileId + "' does not support the bound identity.");
        }

        if (!string.Equals(client.Toolchain.HardwareId, profile.FullHardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the loaded toolchain hardware id is not the trusted profile hardware id.");
        }
    }

    private static void RequireCallerBackupBinding(EdlClient client, InternalBackupSet currentBackup)
    {
        EdlToolchain toolchain = client.Toolchain;
        AndroidMaintenanceIdentity android = client.Binding.AndroidIdentity!;
        DeviceIdentity identity = android.Identity;

        if (!ReferenceEquals(currentBackup.Binding, client.Binding))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the backup was not taken from this exact EDL session.");
        }

        if (!string.Equals(currentBackup.ProfileId, toolchain.ProfileId, StringComparison.Ordinal)
            || !string.Equals(currentBackup.Model, toolchain.Model, StringComparison.Ordinal)
            || !string.Equals(currentBackup.AndroidBuild, identity.Firmware!.DisplayId, StringComparison.Ordinal)
            || !string.Equals(currentBackup.HardwareId, toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the backup profile is not the loaded EDL toolchain profile.");
        }
    }

    private static void RequireSameCapture(InternalBackupSet owned, InternalBackupSet passed)
    {
        foreach ((int lun, EdlGeometry geometry) in passed.Geometries)
        {
            if (!owned.Geometries.TryGetValue(lun, out EdlGeometry ownedGeometry)
                || ownedGeometry.SectorSize != geometry.SectorSize
                || ownedGeometry.TotalSectors != geometry.TotalSectors)
            {
                throw new InvalidOperationException(
                    ForgedBackupCode + ": the re-opened backup geometry of LUN" + lun
                    + " does not match the passed backup set.");
            }
        }

        foreach ((string role, EdlCapturedRegion region) in passed.Files)
        {
            if (!owned.Files.TryGetValue(role, out EdlCapturedRegion ownedRegion))
            {
                throw new InvalidOperationException(
                    ForgedBackupCode + ": the re-opened backup is missing the role '" + role + "'.");
            }

            if (ownedRegion.Lun != region.Lun
                || ownedRegion.StartSector != region.StartSector
                || ownedRegion.SectorCount != region.SectorCount
                || ownedRegion.SectorSize != region.SectorSize
                || ownedRegion.Length != region.Length
                || !string.Equals(ownedRegion.Sha256, region.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    ForgedBackupCode + ": the re-opened backup region '" + role
                    + "' does not match the passed backup set.");
            }
        }

        if (owned.Files.Count != passed.Files.Count)
        {
            throw new InvalidOperationException(
                ForgedBackupCode + ": the re-opened backup carries a different number of regions.");
        }
    }

    private static bool SameAndroidIdentity(
        AndroidMaintenanceIdentity left,
        AndroidMaintenanceIdentity right) =>
        string.Equals(left.SocSerial, right.SocSerial, StringComparison.Ordinal)
        && left.Identity is not null
        && right.Identity is not null
        && string.Equals(left.Identity.Serial, right.Identity.Serial, StringComparison.Ordinal)
        && string.Equals(left.Identity.Model, right.Identity.Model, StringComparison.Ordinal)
        && SameFirmware(left.Identity.Firmware, right.Identity.Firmware);

    private static bool SameFirmware(FirmwareSnapshot? left, FirmwareSnapshot? right) =>
        left is not null
        && right is not null
        && string.Equals(left.DisplayId, right.DisplayId, StringComparison.Ordinal)
        && string.Equals(left.BuildFingerprint, right.BuildFingerprint, StringComparison.Ordinal)
        && string.Equals(left.AndroidRelease, right.AndroidRelease, StringComparison.Ordinal)
        && string.Equals(left.SecurityPatch, right.SecurityPatch, StringComparison.Ordinal)
        && left.AndroidReportedBootloaderState == right.AndroidReportedBootloaderState;

    // ------------------------------------------------------------------ region and claim helpers

    private static EdlCapturedRegion RequireRegion(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string role,
        string subject)
    {
        if (!files.TryGetValue(role, out EdlCapturedRegion region))
        {
            throw new InvalidOperationException(
                PlanIncompleteCode + ": " + subject + " is missing the required role '" + role + "'.");
        }

        return region;
    }

    private static VerifiedEdlFile RegionClaim(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string role,
        string subject)
    {
        EdlCapturedRegion region = RequireRegion(files, role, subject);
        return new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);
    }

    private static void RequireWholeRegion(EdlCapturedRegion current, EdlCapturedRegion source, string role)
    {
        if (current.Lun != source.Lun
            || current.StartSector != source.StartSector
            || current.SectorCount != source.SectorCount
            || current.SectorSize != source.SectorSize
            || current.Length != source.Length)
        {
            throw new InvalidOperationException(
                PlanIncompleteCode + ": the stock source region '" + role
                + "' does not cover the same whole extent as the current capture; a partial or oversized "
                + "candidate is never written.");
        }
    }

    // ------------------------------------------------------------------ device validation

    private static async Task ProbeSixLunsAsync(
        EdlClient client,
        InternalBackupSet owned,
        CancellationToken cancellationToken)
    {
        for (int lun = 0; lun < 6; lun++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            EdlProbeEvidence probe = await client
                .ProbeAsync(lun, lun == 0 && !client.HasInitialSaharaProof, cancellationToken)
                .ConfigureAwait(false);

            EdlGeometry actual = probe.Geometry;
            EdlGeometry saved = owned.Geometries[lun];

            if (actual.Lun != lun
                || actual.SectorSize != saved.SectorSize
                || actual.TotalSectors != saved.TotalSectors)
            {
                throw new InvalidOperationException(
                    FreshnessCode + ": LUN" + lun + " now reports " + actual.SectorSize + "-byte sectors and "
                    + actual.TotalSectors + " sectors, not the captured " + saved.SectorSize + " and "
                    + saved.TotalSectors + ".");
            }

            if (!string.Equals(probe.BusSerialHex, client.Binding.BusSerialHex, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    FreshnessCode + ": the probe of LUN" + lun + " selected bus serial '"
                    + (probe.BusSerialHex ?? "<none>") + "', not the bound '"
                    + client.Binding.BusSerialHex + "'.");
            }
        }
    }

    private static async Task ReadbackEveryCurrentRegionAsync(
        EdlClient client,
        InternalBackupSet owned,
        string evidenceDirectory,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        foreach (EdlCapturedRegion region in owned.Files.Values)
        {
            totalBytes += region.Length;
        }

        long completedBytes = 0;
        int completedFiles = 0;

        string readbackDirectory = Path.Combine(
            evidenceDirectory, "readback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(readbackDirectory);

        foreach ((string role, EdlCapturedRegion region) in owned.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string path = Path.Combine(readbackDirectory, role + ".bin");
            EdlReadEvidence evidence = await client
                .ReadAsync(
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    path,
                    null,
                    Path.Combine(readbackDirectory, role + "-reread"),
                    cancellationToken)
                .ConfigureAwait(false);

            if (evidence.Geometry is null
                || evidence.Geometry.Lun != region.Lun
                || evidence.Geometry.SectorSize != region.SectorSize
                || evidence.StartSector != region.StartSector
                || evidence.SectorCount != region.SectorCount
                || evidence.Length != region.Length
                || !string.Equals(evidence.Sha256, region.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    FreshnessCode + ": the fresh readback of '" + role
                    + "' does not match the held current capture; the device no longer matches the rollback "
                    + "proof and no write or reset may be issued.");
            }

            completedBytes += region.Length;
            completedFiles++;

            progress?.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Progress,
                InternalInstallWriteState.NoneIssued,
                null,
                completedBytes,
                totalBytes,
                role));
        }

        progress?.Report(new InternalInstallProgress(
            InternalInstallStage.Revalidating,
            InternalInstallProgressKind.Verified,
            InternalInstallWriteState.NoneIssued,
            null,
            completedBytes,
            totalBytes,
            "current-capture-fresh"));
    }

    // ------------------------------------------------------------------ file inspection and hashing

    private static async Task<FileFacts> InspectFileAsync(
        string path,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, HashBufferBytes, FileOptions.SequentialScan);

        if (stream.Length != expectedLength)
        {
            throw new InvalidOperationException(
                SourceUnavailableCode + ": the source file '" + path + "' is " + stream.Length
                + " bytes, not the declared " + expectedLength + ".");
        }

        var buffer = new byte[HashBufferBytes];
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        bool allZero = true;
        int read;

        while ((read = await stream.ReadAsync(buffer.AsMemory(0, HashBufferBytes), cancellationToken)
            .ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(buffer, 0, read);

            for (int index = 0; index < read; index++)
            {
                if (buffer[index] != 0)
                {
                    allZero = false;
                    break;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        if (stream.Length != expectedLength)
        {
            throw new InvalidOperationException(
                SourceUnavailableCode + ": the source file '" + path + "' changed length while it was read.");
        }

        return new FileFacts(expectedLength, Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant(), allZero);
    }

    private static async Task RehashHeldFileAsync(
        string path,
        long expectedLength,
        string expectedSha256,
        string subject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, HashBufferBytes, FileOptions.SequentialScan);

        if (stream.Length != expectedLength)
        {
            throw new InvalidOperationException(
                FreshnessCode + ": the held " + subject + " is " + stream.Length + " bytes, not the captured "
                + expectedLength + ".");
        }

        string actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();

        if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                FreshnessCode + ": the held " + subject + " no longer hashes to its captured SHA-256.");
        }
    }

    // ------------------------------------------------------------------ confirmation binding

    private static string BuildConfirmationSha256(
        MaintenanceMode mode,
        MaintenanceDeviceFacts deviceFacts,
        EdlClient client,
        string miscControlSha256,
        string currentSlot,
        string currentManifestSha256,
        string sourceManifestSha256,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        IReadOnlyList<PlannedRegion> plan,
        string preparationId)
    {
        DeviceIdentity identity = deviceFacts.Identity.Identity;

        var builder = new StringBuilder();
        builder.Append("boot-maintenance-confirmation-v1\n");
        builder.Append("mode=").Append(mode).Append('\n');
        builder.Append("model=").Append(identity.Model).Append('\n');
        builder.Append("androidSerial=").Append(identity.Serial).Append('\n');
        builder.Append("socSerial=").Append(deviceFacts.Identity.SocSerial).Append('\n');
        builder.Append("busSerial=").Append(client.Binding.BusSerialHex).Append('\n');
        builder.Append("currentSlot=").Append(currentSlot).Append('\n');
        builder.Append("identityOrigin=")
            .Append(deviceFacts.AndroidCheck is not null ? "android-live" : "historical-backup").Append('\n');
        builder.Append("historyManifestSha256=")
            .Append(deviceFacts.History?.ManifestSha256 ?? string.Empty).Append('\n');
        builder.Append("currentFirmwareObserved=")
            .Append(deviceFacts.History is null ? "true" : "false").Append('\n');
        builder.Append("miscControlSha256=").Append(miscControlSha256).Append('\n');
        builder.Append("currentManifestSha256=").Append(currentManifestSha256).Append('\n');
        builder.Append("sourceManifestSha256=").Append(sourceManifestSha256).Append('\n');

        for (int lun = 0; lun < 6; lun++)
        {
            EdlGeometry geometry = geometries[lun];
            builder.Append("lun=").Append(lun)
                .Append(",sectorSize=").Append(geometry.SectorSize)
                .Append(",totalSectors=").Append(geometry.TotalSectors)
                .Append('\n');
        }

        foreach (PlannedRegion region in plan)
        {
            builder.Append("region=").Append(region.Role)
                .Append(",slot=").Append(region.Slot)
                .Append(",lun=").Append(region.Lun)
                .Append(",start=").Append(region.StartSector)
                .Append(",count=").Append(region.SectorCount)
                .Append(",length=").Append(region.Length)
                .Append(",current=").Append(region.CurrentSha256)
                .Append(",candidate=").Append(region.CandidateSha256 ?? "-")
                .Append(",write=").Append(region.WillWrite ? '1' : '0')
                .Append('\n');
        }

        builder.Append("preparationId=").Append(preparationId).Append('\n');

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }

    // ------------------------------------------------------------------ evidence receipts

    private static void WritePrepareReceipt(
        string evidenceDirectory,
        MaintenanceMode mode,
        BootMaintenancePrepared prepared,
        int plannedRegionCount)
    {
        WriteReceipt(evidenceDirectory, "prepare", writer =>
        {
            writer.WriteString("kind", "prepare");
            writer.WriteString("mode", mode.ToString());
            writer.WriteString("confirmationSha256", prepared.ConfirmationId);
            writer.WriteString("model", prepared.Model);
            writer.WriteString("androidSerial", prepared.AndroidSerial);
            writer.WriteString("socSerial", prepared.SocSerial);
            writer.WriteString("currentSlot", prepared.CurrentSlot);
            writer.WriteString("bootTrust", prepared.BootTrustMode.ToString());
            writer.WriteNumber("plannedRegions", plannedRegionCount);
            writer.WriteNumber("slots", prepared.Slots.Count);
        });
    }

    private static void WriteReceipt(
        string evidenceDirectory,
        string name,
        Action<Utf8JsonWriter> fill)
    {
        string path = Path.Combine(evidenceDirectory, name + ".json");
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                fill(writer);
                writer.WriteEndObject();
            }

            using (FileStream stream = new(
                temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, HashBufferBytes))
            {
                stream.Write(buffer.ToArray(), 0, (int)buffer.Length);
                stream.Flush(true);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                try
                {
                    File.Delete(temp);
                }
                catch (Exception)
                {
                }
            }
        }
    }

    /// <summary>One planned whole-region candidate of the pass, in final write order.</summary>
    internal sealed record PlannedRegion(
        string Role,
        string? Slot,
        int Lun,
        long StartSector,
        long SectorCount,
        long Length,
        string CurrentSha256,
        string? CandidatePath,
        string? CandidateSha256)
    {
        /// <summary>True when this region carries a stock candidate that differs from the current bytes.</summary>
        internal bool WillWrite => CandidatePath is not null;
    }

    /// <summary>
    /// Common internal execution facts of one completed plan run, shared by the maintenance and TF
    /// entries. Facts only: no caller flag, mode, readiness or acceptance field lives here; TF result
    /// shaping stays outside this type.
    /// </summary>
    internal sealed record RegionExecutionResult
    {
        internal RegionExecutionResult(
            BootMaintenanceOutcome outcome,
            InternalInstallWriteState writeState,
            IReadOnlyList<string> verifiedRegions,
            string evidenceDirectory,
            string? error)
        {
            Outcome = outcome;
            WriteState = writeState;
            VerifiedRegions = new List<string>(verifiedRegions).AsReadOnly();
            EvidenceDirectory = evidenceDirectory;
            Error = error;
        }

        public BootMaintenanceOutcome Outcome { get; }

        public InternalInstallWriteState WriteState { get; }

        public IReadOnlyList<string> VerifiedRegions { get; }

        public string EvidenceDirectory { get; }

        public string? Error { get; }
    }

    private sealed record FileFacts(long Length, string Sha256, bool AllZero);
}
