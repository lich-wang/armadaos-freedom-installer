using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Stage last reached by the uninstall workflow. On failure the reported stage names the exact step that
/// broke; on success it is <see cref="AwaitingFactoryReset"/>, because the Recovery reset is only queued
/// and nothing has booted into Android yet. The older values are kept so existing callers stay source and
/// binary compatible.
/// </summary>
public enum UninstallStage
{
    Preflight,
    ValidateRestoreInputs,
    BackupCurrentBoot,
    PrepareStockBoot,
    RestoreBootA,
    VerifyBootA,
    RestoreBootB,
    VerifyBootB,
    ReclaimAndroidSpace,
    InitializeAndroid,
    VerifyAndroid,
    AwaitingAndroidBootAcceptance,
    AwaitingFactoryReset,
}

/// <summary>
/// Transport the uninstall snapshot was captured over: either a fastboot maintenance session or the
/// primary 9008/EDL route. Declared here so a snapshot can pin the transport it was read on.
/// </summary>
public enum UninstallTransportKind
{
    RamMaintenance,
    Edl,
}

/// <summary>
/// Point-in-time view of the device used to confirm an uninstall. Every field is evidence an adapter can
/// only supply after actually reading it; the workflow never derives or defaults any of them.
/// </summary>
public sealed record UninstallSnapshot(
    DeviceIdentity Identity,
    string TableFingerprint,
    string CurrentBootFingerprint,
    string StockBackupFingerprint,
    string InstallationRecordFingerprint,
    bool MaintenanceValidated,
    bool BothStockBootsValid,
    OtaUpdateState OtaState)
{
    /// <summary>Transport used to capture this snapshot. Defaults to the RAM-maintenance route.</summary>
    public UninstallTransportKind TransportKind { get; init; } = UninstallTransportKind.RamMaintenance;
}

/// <summary>
/// An uninstall request. <paramref name="ConfirmationId"/> must equal
/// <see cref="UninstallWorkflow.ConfirmationFor(UninstallRequest)"/> over the same body (snapshot, plan
/// fingerprint, data-erase consent and slot order); the confirmation field itself is not part of the digest.
/// </summary>
/// <param name="SlotOrder">Slots to restore and verify, in order.</param>
public sealed record UninstallRequest(
    UninstallSnapshot Snapshot,
    string PlanFingerprint,
    string ConfirmationId,
    bool ConfirmDataErase,
    IReadOnlyList<string> SlotOrder);

/// <summary>
/// Outcome of an uninstall run. <paramref name="DataMayBeErased"/> turns true only once the run is about
/// to reclaim space (just before <see cref="UninstallStage.ReclaimAndroidSpace"/>); a failure at or after
/// that point reports it as true, every earlier failure as false. A successful run means only that the
/// confirmed maintenance writes completed and the Recovery factory reset is still pending - it is not a
/// claim that Android has booted or accepted the device.
/// </summary>
public sealed record UninstallResult(
    bool Success,
    UninstallStage Stage,
    bool DataMayBeErased,
    IReadOnlyList<string> VerifiedSlots,
    string? Error);

/// <summary>
/// Device side of an uninstall, injected by the caller. Restore/verify of the stock boot slots, the space
/// reclaim and the Android re-initialisation are the only writes; there is no formatting or filesystem
/// step here, and the workflow itself never reboots the device.
/// </summary>
public interface IUninstallBackend
{
    Task<UninstallSnapshot> InspectAsync(CancellationToken token);

    /// <summary>Adapter-side validation of the restore inputs (stock images, layout record, table).</summary>
    Task ValidateRestoreInputsAsync(CancellationToken token);

    /// <summary>Stores a fresh original image of both slots before anything is written.</summary>
    Task BackupCurrentBootAsync(CancellationToken token);

    Task PrepareStockBootAsync(CancellationToken token);

    Task RestoreBootAsync(string slot, CancellationToken token);

    Task VerifyBootAsync(string slot, CancellationToken token);

    Task ReclaimAndroidSpaceAsync(CancellationToken token);

    Task InitializeAndroidAsync(CancellationToken token);

    /// <summary>
    /// Confirms that a booted Android accepted the device. Kept on the interface for compatibility with
    /// existing adapters, but <see cref="UninstallWorkflow"/> never calls it: the run stops with the
    /// factory reset pending, so no boot has happened that could be verified.
    /// </summary>
    Task VerifyAndroidAsync(CancellationToken token);
}

/// <summary>
/// Deterministic uninstall workflow. The public surface is frozen and the behaviour is pinned by
/// tests/FreedomInstaller.Core.Tests/UninstallWorkflowTests.cs and UninstallWorkflowPendingTests.cs.
/// Pipeline: preflight -> inspect -> validate -> backup -> prepare -> inspect -> restore/verify each slot ->
/// reclaim -> initialize. It stops at <see cref="UninstallStage.AwaitingFactoryReset"/>: the Recovery
/// factory reset is queued, Android has not been booted and no acceptance is claimed, and the workflow
/// never reboots the device. Once slot restoration has begun the caller token is ignored, so a late
/// cancellation cannot abandon a half-written slot.
/// <para>
/// Business rejections are reported as a failed result, never thrown; only a caller cancellation that
/// arrives before the first slot restore surfaces as an <see cref="OperationCanceledException"/>. A
/// cancellation observed after the first restore has started is a failure like any other: the run stops
/// at the exact stage, reports the slots verified so far and never resumes on its own.
/// </para>
/// <para>
/// Field values are never guessed: an absent fingerprint, a missing identity, an undefined enum value or
/// an unexpected slot order fails closed in preflight, before any backend call. The workflow does not
/// repair a partition table, does not claim any Android file can be recovered and does not invent an
/// Android acceptance; it only orders the calls of the real injected <see cref="IUninstallBackend"/> and
/// leaves the pending reset to the caller.
/// </para>
/// </summary>
public static class UninstallWorkflow
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = false };

    /// <summary>
    /// Digest binding a request to its snapshot, plan fingerprint, data-erase consent and slot order.
    /// The request's own <see cref="UninstallRequest.ConfirmationId"/> is ignored.
    /// <para>
    /// The body is a fixed-shape object serialised by <see cref="JsonSerializer"/> in the order Snapshot,
    /// PlanFingerprint, ConfirmDataErase, SlotOrder, so the digest is canonical and stable without
    /// hand-written JSON. Enum values are serialised by name, so the digest survives a renumbering.
    /// </para>
    /// </summary>
    public static string ConfirmationFor(UninstallRequest request)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var snapshot = request.Snapshot;
        var identity = snapshot?.Identity;

        var payload = new
        {
            Snapshot = snapshot is null
                ? null
                : new
                {
                    Identity = identity is null
                        ? null
                        : new
                        {
                            Serial = identity.Serial,
                            Model = identity.Model,
                            BootloaderState = identity.BootloaderState.ToString(),
                        },
                    TableFingerprint = snapshot.TableFingerprint,
                    CurrentBootFingerprint = snapshot.CurrentBootFingerprint,
                    StockBackupFingerprint = snapshot.StockBackupFingerprint,
                    InstallationRecordFingerprint = snapshot.InstallationRecordFingerprint,
                    MaintenanceValidated = snapshot.MaintenanceValidated,
                    BothStockBootsValid = snapshot.BothStockBootsValid,
                    OtaState = snapshot.OtaState.ToString(),
                    TransportKind = snapshot.TransportKind.ToString(),
                },
            PlanFingerprint = request.PlanFingerprint,
            ConfirmDataErase = request.ConfirmDataErase,
            SlotOrder = CopySlots(request.SlotOrder),
        };

        var json = JsonSerializer.Serialize(payload, SerializerOptions);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static async Task<UninstallResult> RunAsync(
        UninstallRequest request,
        IUninstallBackend backend,
        IProgress<UninstallStage>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (backend is null) throw new ArgumentNullException(nameof(backend));

        // Pin the slot list before the first await: a caller mutating the original list mid-run must not
        // change what was confirmed, what was validated or which slots get restored.
        request = request with { SlotOrder = CopySlots(request.SlotOrder)! };

        // A caller that is already cancelled never reaches the backend at all.
        cancellationToken.ThrowIfCancellationRequested();

        var verified = new List<string>();
        var dataMayBeErased = false;
        var stage = UninstallStage.Preflight;
        SafeReport(progress, stage);

        // Business rejections are reported, never thrown, and never touch the backend.
        var rejection = Rejection(request);
        if (rejection is not null)
        {
            return new UninstallResult(false, stage, dataMayBeErased, Array.Empty<string>(), rejection);
        }

        // First inspection pins the device state the request was confirmed against.
        UninstallSnapshot? live;
        try
        {
            live = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        if (live is null || !live.Equals(request.Snapshot))
        {
            return new UninstallResult(
                false,
                stage,
                dataMayBeErased,
                verified.ToArray(),
                "Device snapshot does not match the confirmed uninstall request.");
        }

        // Adapter-side restore input checks: each slot's factory format, firmware and length plus the
        // installation record. Nothing has been written yet, so the caller token is still honoured.
        stage = UninstallStage.ValidateRestoreInputs;
        SafeReport(progress, stage);
        try
        {
            await backend.ValidateRestoreInputsAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        stage = UninstallStage.BackupCurrentBoot;
        SafeReport(progress, stage);
        try
        {
            await backend.BackupCurrentBootAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        // Non-destructive preparation of the stock boot images; no boot image is written here.
        stage = UninstallStage.PrepareStockBoot;
        SafeReport(progress, stage);
        try
        {
            await backend.PrepareStockBootAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        // Preparation is still read-only, so a cancellation that lands during it is honoured immediately
        // instead of being discovered by the second inspection.
        cancellationToken.ThrowIfCancellationRequested();

        // Second inspection must still agree in every recorded value before anything is written.
        stage = UninstallStage.Preflight;
        SafeReport(progress, stage);
        UninstallSnapshot? afterPrepare;
        try
        {
            afterPrepare = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        if (afterPrepare is null || !afterPrepare.Equals(request.Snapshot))
        {
            return new UninstallResult(
                false,
                stage,
                dataMayBeErased,
                verified.ToArray(),
                "Device snapshot changed after stock boot preparation.");
        }

        // Last point at which the caller may stop the run. Below this the caller token is deliberately
        // ignored: a late cancellation would abandon a half-written slot.
        cancellationToken.ThrowIfCancellationRequested();

        var slots = request.SlotOrder!;

        foreach (var slot in slots)
        {
            var isSlotA = string.Equals(slot, "a", StringComparison.Ordinal);

            stage = isSlotA ? UninstallStage.RestoreBootA : UninstallStage.RestoreBootB;
            SafeReport(progress, stage);
            try
            {
                await backend.RestoreBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                // Once a write has started, a cancellation is a failure like any other: the caller is told
                // which stage broke instead of being handed an exception or a silent resume.
                return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
            }

            stage = isSlotA ? UninstallStage.VerifyBootA : UninstallStage.VerifyBootB;
            SafeReport(progress, stage);
            try
            {
                await backend.VerifyBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
            }

            // A slot counts as verified only after its verification succeeded; a failure above returns
            // immediately, so no later slot is touched.
            verified.Add(slot);
        }

        // Data may be lost from here on, and every later call is non-cancellable.
        stage = UninstallStage.ReclaimAndroidSpace;
        dataMayBeErased = true;
        SafeReport(progress, stage);
        try
        {
            await backend.ReclaimAndroidSpaceAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        stage = UninstallStage.InitializeAndroid;
        SafeReport(progress, stage);
        try
        {
            await backend.InitializeAndroidAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return new UninstallResult(false, stage, dataMayBeErased, verified.ToArray(), exception.Message);
        }

        // The reset is queued for Recovery here and the run ends. Nothing has booted Android, so there is
        // no acceptance to verify and backend.VerifyAndroidAsync is deliberately not called: success means
        // only that the confirmed maintenance writes completed and the factory reset is still pending.
        stage = UninstallStage.AwaitingFactoryReset;
        SafeReport(progress, stage);
        return new UninstallResult(true, stage, dataMayBeErased, verified.ToArray(), null);
    }

    /// <summary>
    /// Business preflight. Returns the rejection reason, or null when the request may run. A missing or
    /// undefined value never passes: every field is evidence an adapter had to read, so none is defaulted.
    /// </summary>
    private static string? Rejection(UninstallRequest request)
    {
        var snapshot = request.Snapshot;
        if (snapshot is null)
        {
            return "Uninstall snapshot is required.";
        }

        var identity = snapshot.Identity;
        if (identity is null)
        {
            return "Device identity is required.";
        }

        if (string.IsNullOrWhiteSpace(identity.Serial))
        {
            return "Device serial is required.";
        }

        if (!string.Equals(identity.Model, "TB322FC", StringComparison.Ordinal)
            && !string.Equals(identity.Model, "TB323FU", StringComparison.Ordinal))
        {
            return "Unsupported device model.";
        }

        // Route policy: the transport captured with the snapshot decides which bootloader states may run.
        // An undefined transport never passes, and an undefined bootloader state is rejected on every
        // route because it is evidence an adapter had to read. Only the RAM-maintenance route still
        // requires an explicit Unlocked bootloader (a fastboot session needs it); the EDL route reaches
        // the device over 9008 without fastboot, so it accepts any defined state and is authorised by the
        // remaining evidence, consent and slot-order guards below - it never short-circuits past them.
        if (!Enum.IsDefined<UninstallTransportKind>(snapshot.TransportKind))
        {
            return "Uninstall transport is not recognised.";
        }

        if (!Enum.IsDefined<BootloaderState>(identity.BootloaderState))
        {
            return "Bootloader state is not recognised.";
        }

        if (snapshot.TransportKind == UninstallTransportKind.RamMaintenance
            && identity.BootloaderState != BootloaderState.Unlocked)
        {
            return "Bootloader must be unlocked.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.TableFingerprint))
        {
            return "Table fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.CurrentBootFingerprint))
        {
            return "Current boot fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.StockBackupFingerprint))
        {
            return "Stock boot backup fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.InstallationRecordFingerprint))
        {
            return "Installation record fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(request.PlanFingerprint))
        {
            return "Plan fingerprint is required.";
        }

        if (!snapshot.MaintenanceValidated)
        {
            return "Maintenance mode must be validated.";
        }

        if (!snapshot.BothStockBootsValid)
        {
            return "Both stock boot slots must be valid.";
        }

        // An unknown, transient or future OTA state is never guessed to be Completed.
        if (!Enum.IsDefined<OtaUpdateState>(snapshot.OtaState)
            || snapshot.OtaState != OtaUpdateState.Completed)
        {
            return "OTA update must be completed before uninstalling.";
        }

        if (!request.ConfirmDataErase)
        {
            return "Android user data erase has not been confirmed.";
        }

        var slots = request.SlotOrder;
        if (slots is null || slots.Count != 2)
        {
            return "Slot order must list slot a and slot b exactly once.";
        }

        var seenA = false;
        var seenB = false;
        foreach (var slot in slots)
        {
            if (string.Equals(slot, "a", StringComparison.Ordinal))
            {
                if (seenA)
                {
                    return "Slot order must list slot a and slot b exactly once.";
                }

                seenA = true;
            }
            else if (string.Equals(slot, "b", StringComparison.Ordinal))
            {
                if (seenB)
                {
                    return "Slot order must list slot a and slot b exactly once.";
                }

                seenB = true;
            }
            else
            {
                return "Slot order contains an unknown slot.";
            }
        }

        // Recomputed over the pinned copy of the slot order, so a list mutated after confirmation cannot
        // ride along under an old digest.
        var pinned = request with { SlotOrder = slots };
        if (!string.Equals(request.ConfirmationId, ConfirmationFor(pinned), StringComparison.Ordinal))
        {
            return "Confirmation id does not match the pinned uninstall request.";
        }

        return null;
    }

    /// <summary>Best-effort progress reporting: a faulty observer must never change the outcome.</summary>
    private static void SafeReport(IProgress<UninstallStage>? progress, UninstallStage stage)
    {
        try
        {
            progress?.Report(stage);
        }
        catch (Exception)
        {
            // Deliberately ignored: reporting is not part of the workflow state.
        }
    }

    private static string[]? CopySlots(IReadOnlyList<string>? slots)
    {
        if (slots is null)
        {
            return null;
        }

        var copy = new string[slots.Count];
        for (var index = 0; index < copy.Length; index++)
        {
            copy[index] = slots[index];
        }

        return copy;
    }

    // -----------------------------------------------------------------
    // C001 userdata-only contract stubs (no behavior yet)
    // -----------------------------------------------------------------

    /// <summary>
    /// Confirmation digest for the userdata-only request: canonical JSON over the fixed
    /// operation name, all six snapshot fields, the actual identity, the plan fingerprint
    /// and the erase consent. The confirmation id itself is excluded.
    /// </summary>
    public static string ConfirmationFor(UserdataUninstallRequest request)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var snapshot = request.Snapshot;
        var identity = snapshot?.Identity;

        var payload = new
        {
            Operation = "remove-linux-preserve-boot",
            Snapshot = snapshot is null
                ? null
                : new
                {
                    // The identity record is serialised as-is, so an optional firmware field is bound
                    // exactly when the adapter supplied one.
                    Identity = identity,
                    TableFingerprint = snapshot.TableFingerprint,
                    MiscFingerprint = snapshot.MiscFingerprint,
                    InstallationRecordFingerprint = snapshot.InstallationRecordFingerprint,
                    MaintenanceValidated = snapshot.MaintenanceValidated,
                    OtaState = snapshot.OtaState.ToString(),
                },
            PlanFingerprint = request.PlanFingerprint,
            ConfirmDataErase = request.ConfirmDataErase,
        };

        var json = JsonSerializer.Serialize(payload, SerializerOptions);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Runs the userdata-only stages in order: preflight, inspect, validate inputs, inspect
    /// again against the pinned snapshot, reclaim userdata, queue the Recovery init.
    /// </summary>
    public static async Task<UninstallResult> RunAsync(
        UserdataUninstallRequest request,
        IUserdataUninstallBackend backend,
        IProgress<UninstallStage>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (backend is null) throw new ArgumentNullException(nameof(backend));

        // A caller that is already cancelled never reaches the backend at all.
        cancellationToken.ThrowIfCancellationRequested();

        var stage = UninstallStage.Preflight;
        var dataMayBeErased = false;
        SafeReport(progress, stage);

        // Business rejections are reported, never thrown, and never touch the backend.
        var rejection = UserdataRejection(request);
        if (rejection is not null)
        {
            return new UninstallResult(false, stage, dataMayBeErased, Array.Empty<string>(), rejection);
        }

        var expected = request.Snapshot;

        // Read-only phase: nothing has been written yet, so a caller cancellation still aborts the run.
        try
        {
            var live = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
            if (live is null || !live.Equals(expected))
            {
                return new UninstallResult(
                    false, stage, dataMayBeErased, Array.Empty<string>(),
                    "Device state no longer matches the confirmed userdata snapshot.");
            }

            stage = UninstallStage.ValidateRestoreInputs;
            SafeReport(progress, stage);
            await backend.ValidateRestoreInputsAsync(cancellationToken).ConfigureAwait(false);

            // A cancellation raised while validating must still stop the run before anything is erased.
            cancellationToken.ThrowIfCancellationRequested();

            stage = UninstallStage.Preflight;
            var pinned = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
            if (pinned is null || !pinned.Equals(expected))
            {
                return new UninstallResult(
                    false, stage, dataMayBeErased, Array.Empty<string>(),
                    "Device state changed while the restore inputs were validated.");
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            return new UninstallResult(false, stage, dataMayBeErased, Array.Empty<string>(), UserdataError(error));
        }

        // The erase flag and stage are set before the attempt, so any later failure reports both truthfully.
        stage = UninstallStage.ReclaimAndroidSpace;
        dataMayBeErased = true;
        SafeReport(progress, stage);

        // From here on the caller token is deliberately not observed: a late cancellation must not
        // abandon a half-erased userdata partition, and the queued init is not retried automatically.
        try
        {
            await backend.ReclaimAndroidSpaceAsync(CancellationToken.None).ConfigureAwait(false);

            stage = UninstallStage.InitializeAndroid;
            SafeReport(progress, stage);
            await backend.InitializeAndroidAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            return new UninstallResult(false, stage, dataMayBeErased, Array.Empty<string>(), UserdataError(error));
        }

        SafeReport(progress, UninstallStage.AwaitingFactoryReset);
        return new UninstallResult(true, UninstallStage.AwaitingFactoryReset, true, Array.Empty<string>(), null);
    }

    /// <summary>Business preflight for the userdata-only request; a message means "reject".</summary>
    private static string? UserdataRejection(UserdataUninstallRequest request)
    {
        var snapshot = request.Snapshot;
        if (snapshot is null)
        {
            return "The userdata uninstall request has no snapshot.";
        }

        var identity = snapshot.Identity;
        if (identity is null)
        {
            return "The userdata uninstall snapshot has no device identity.";
        }

        if (string.IsNullOrWhiteSpace(identity.Serial))
        {
            return "The device identity has no serial number.";
        }

        if (!string.Equals(identity.Model, "TB322FC", StringComparison.Ordinal)
            && !string.Equals(identity.Model, "TB323FU", StringComparison.Ordinal))
        {
            return "The device model is not a supported TB322FC or TB323FU unit.";
        }

        if (!Enum.IsDefined(typeof(BootloaderState), identity.BootloaderState))
        {
            return "The bootloader state is not a defined value.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.TableFingerprint)
            || string.IsNullOrWhiteSpace(snapshot.MiscFingerprint)
            || string.IsNullOrWhiteSpace(snapshot.InstallationRecordFingerprint))
        {
            return "The userdata snapshot is missing a table, misc or installation-record fingerprint.";
        }

        if (string.IsNullOrWhiteSpace(request.PlanFingerprint))
        {
            return "The userdata uninstall request has no plan fingerprint.";
        }

        if (!snapshot.MaintenanceValidated)
        {
            return "Maintenance access was not validated.";
        }

        if (snapshot.OtaState != OtaUpdateState.Completed)
        {
            return "The OTA state is not the completed state required for a userdata erase.";
        }

        if (!request.ConfirmDataErase)
        {
            return "The userdata erase was not confirmed.";
        }

        if (!string.Equals(request.ConfirmationId, ConfirmationFor(request), StringComparison.Ordinal))
        {
            return "Confirmation id does not match the pinned userdata request.";
        }

        return null;
    }

    /// <summary>Readable failure text without inventing a cause the backend did not report.</summary>
    private static string UserdataError(Exception error) =>
        string.IsNullOrWhiteSpace(error.Message)
            ? "The userdata uninstall step failed."
            : error.Message;
}

/// <summary>
/// Point-in-time view used to confirm the userdata-only uninstall. Six fields only: the
/// actual identity, the table/misc/installation-record fingerprints, whether maintenance
/// was validated, and the OTA state read from the GPT bridge response.
/// </summary>
public sealed record UserdataUninstallSnapshot(
    DeviceIdentity Identity,
    string TableFingerprint,
    string MiscFingerprint,
    string InstallationRecordFingerprint,
    bool MaintenanceValidated,
    OtaUpdateState OtaState);

/// <summary>
/// A userdata-only uninstall request. <paramref name="ConfirmationId"/> must equal
/// <see cref="UninstallWorkflow.ConfirmationFor(UserdataUninstallRequest)"/> over the same
/// body (snapshot, plan fingerprint and data-erase consent); the confirmation field itself
/// is not part of the digest.
/// </summary>
public sealed record UserdataUninstallRequest(
    UserdataUninstallSnapshot Snapshot,
    string PlanFingerprint,
    string ConfirmationId,
    bool ConfirmDataErase);

/// <summary>
/// Device side of the userdata-only uninstall: fresh inspection, input validation, the
/// userdata reclaim and the Recovery initialisation. No boot restore and no reset.
/// </summary>
public interface IUserdataUninstallBackend
{
    Task<UserdataUninstallSnapshot> InspectAsync(CancellationToken token);

    Task ValidateRestoreInputsAsync(CancellationToken token);

    Task ReclaimAndroidSpaceAsync(CancellationToken token);

    Task InitializeAndroidAsync(CancellationToken token);
}
