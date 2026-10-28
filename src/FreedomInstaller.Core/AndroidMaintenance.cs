using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Which boot maintenance pass the installer is asking the backend to perform.
/// Prepare semantics per mode:
/// BeforeUpdate  - prepare each slot with the matching stock/original boot image.
/// AfterUpdate   - prepare new kShim candidates built on the post-update bases of each slot.
/// RestoreStock  - prepare each slot with the matching stock/original boot image (restore path).
/// </summary>
public enum MaintenanceMode
{
    BeforeUpdate,
    AfterUpdate,
    RestoreStock
}

/// <summary>OTA state as reported by the device; only <see cref="Completed"/> may pass preflight.</summary>
public enum OtaUpdateState
{
    Unknown,
    Updating,
    PendingReboot,
    UnconfirmedBoot,
    Merging,
    Completed
}

/// <summary>Point-in-time view of the device: recorded workflow inputs, OTA state and slot firmware identity.</summary>
public record MaintenanceSnapshot(
    WorkflowInputs Inputs,
    OtaUpdateState OtaState,
    string SlotVersionsFingerprint);

/// <summary>
/// A maintenance request. <paramref name="ConfirmationId"/> must equal
/// <see cref="AndroidMaintenance.ConfirmationFor(MaintenanceRequest)"/> computed over the same request body
/// (mode, snapshot, test flag and slot order) - the confirmation field itself is not part of the digest.
/// </summary>
/// <param name="SlotOrder">Slots to write/verify, in order.</param>
public record MaintenanceRequest(
    MaintenanceMode Mode,
    MaintenanceSnapshot Snapshot,
    string ConfirmationId,
    bool TestPackage,
    IReadOnlyList<string> SlotOrder);

/// <summary>
/// Outcome of a maintenance run.
/// <paramref name="Stage"/> is the last stage that was reached:
/// "Preflight", "Inspect", "ValidateStockInputs", "BackupCurrentBoot", "PrepareBoot", "WriteBootA",
/// "VerifyBootA", "WriteBootB", "VerifyBootB" on failure, and "AwaitingBootAcceptance" on success.
/// </summary>
public record MaintenanceResult(
    bool Success,
    string Stage,
    IReadOnlyList<string> VerifiedSlots,
    string? Error);

/// <summary>
/// Device/simulation side of boot maintenance. Deliberately limited to boot-image work:
/// it exposes no partition, format, filesystem or rootfs operations.
/// </summary>
public interface IMaintenanceBackend
{
    WorkflowTarget Target { get; }

    Task<MaintenanceSnapshot> InspectAsync(CancellationToken token);

    /// <summary>Adapter-side validation of each slot's stock firmware, format and recorded backup.</summary>
    Task ValidateStockInputsAsync(CancellationToken token);

    /// <summary>Stores a fresh original image of both slots before anything is written.</summary>
    Task BackupCurrentBootAsync(CancellationToken token);

    Task PrepareAsync(MaintenanceMode mode, CancellationToken token);

    Task WriteBootAsync(string slot, CancellationToken token);

    Task VerifyBootAsync(string slot, CancellationToken token);
}

/// <summary>
/// Deterministic boot-maintenance workflow. The public surface is frozen and the behaviour is
/// pinned by tests/FreedomInstaller.Core.Tests/MaintenanceTests.cs.
/// The pipeline only prepares, backs up, writes and verifies boot images: it has no partition,
/// format, filesystem or rootfs step, and it never reboots the device. A successful run stops at
/// "AwaitingBootAcceptance" and leaves acceptance to the caller.
/// </summary>
public static class AndroidMaintenance
{
    private const string PreflightStage = "Preflight";
    private const string InspectStage = "Inspect";
    private const string ValidateStockInputsStage = "ValidateStockInputs";
    private const string BackupCurrentBootStage = "BackupCurrentBoot";
    private const string PrepareBootStage = "PrepareBoot";
    private const string WriteBootAStage = "WriteBootA";
    private const string VerifyBootAStage = "VerifyBootA";
    private const string WriteBootBStage = "WriteBootB";
    private const string VerifyBootBStage = "VerifyBootB";
    private const string AwaitingBootAcceptanceStage = "AwaitingBootAcceptance";

    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = false };

    /// <summary>
    /// Digest binding a request to its mode, snapshot (inputs/OTA state/slot versions), test flag and slot order.
    /// The request's own <see cref="MaintenanceRequest.ConfirmationId"/> is ignored.
    /// The body is a fixed-shape anonymous object serialised by <see cref="JsonSerializer"/> in the
    /// order Mode, Snapshot, TestPackage, SlotOrder, so the digest is stable without hand-written JSON.
    /// </summary>
    public static string ConfirmationFor(MaintenanceRequest request)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var snapshot = request.Snapshot;
        var inputs = snapshot?.Inputs;

        // Enums are serialised by name, so the digest survives reordering of the enum members.
        var payload = new
        {
            Mode = request.Mode.ToString(),
            Snapshot = snapshot is null
                ? null
                : new
                {
                    Inputs = inputs is null
                        ? null
                        : new
                        {
                            Serial = inputs.Serial,
                            Model = inputs.Model,
                            BootloaderState = inputs.BootloaderState.ToString(),
                            TableFingerprint = inputs.TableFingerprint,
                            PackageFingerprint = inputs.PackageFingerprint,
                            BackupFingerprint = inputs.BackupFingerprint,
                            BothSlotBasesValid = inputs.BothSlotBasesValid,
                            MaintenanceValidated = inputs.MaintenanceValidated,
                            // The live-device boot state is part of the digest: a request confirmed
                            // against one pair of current boot images cannot be replayed against
                            // another, and the slot-version fingerprint below stays pinned as well.
                            CurrentBootFingerprint = inputs.CurrentBootFingerprint,
                        },
                    OtaState = snapshot.OtaState.ToString(),
                    SlotVersionsFingerprint = snapshot.SlotVersionsFingerprint,
                },
            TestPackage = request.TestPackage,
            SlotOrder = CopySlots(request.SlotOrder),
        };

        var json = JsonSerializer.Serialize(payload, SerializerOptions);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Pipeline: inspect -> validate stock inputs -> backup current boot -> prepare(mode) -> inspect,
    /// then write/verify each requested slot in order. Slot writes and verifications are not cancellable
    /// once preparation has completed.
    /// Business rejections are reported as a failed result, never thrown; only caller cancellation
    /// before the first write surfaces as an <see cref="OperationCanceledException"/>.
    /// </summary>
    public static async Task<MaintenanceResult> RunAsync(
        MaintenanceRequest request,
        IMaintenanceBackend backend,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (backend is null) throw new ArgumentNullException(nameof(backend));

        // A caller that is already cancelled never reaches the backend at all.
        cancellationToken.ThrowIfCancellationRequested();

        var verifiedSlots = new List<string>();

        // Copy the slot order once: a caller mutating the original list mid-run must not change what
        // was confirmed, what was validated or what gets written.
        var slotOrder = CopySlots(request.SlotOrder);

        var rejection = Rejection(request, slotOrder, backend.Target);
        if (rejection is not null)
        {
            return Failure(PreflightStage, rejection, verifiedSlots);
        }

        // Rejection() guarantees a concrete snapshot and a fully pinned slot order.
        var snapshot = request.Snapshot;
        var slots = slotOrder!;

        // First inspection pins the device state the request was confirmed against.
        var stage = InspectStage;
        MaintenanceSnapshot? live;
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
            return Failure(stage, exception.Message, verifiedSlots);
        }

        if (live is null || !live.Equals(snapshot))
        {
            return Failure(
                PreflightStage,
                "Device snapshot does not match the confirmed maintenance request.",
                verifiedSlots);
        }

        // Adapter-side stock firmware/format/backup validation. It is given the caller token: nothing
        // has been written yet, so a cancellation here is still safe.
        stage = ValidateStockInputsStage;
        try
        {
            await backend.ValidateStockInputsAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Failure(stage, exception.Message, verifiedSlots);
        }

        stage = BackupCurrentBootStage;
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
            return Failure(stage, exception.Message, verifiedSlots);
        }

        // Non-destructive preparation only; no boot image is written here.
        stage = PrepareBootStage;
        try
        {
            await backend.PrepareAsync(request.Mode, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Failure(stage, exception.Message, verifiedSlots);
        }

        // Preparation is still non-destructive, so a cancellation that lands during it is honoured
        // immediately instead of being discovered by the second inspection. This keeps the
        // cancellation boundary read-only: nothing has been written yet at this point.
        cancellationToken.ThrowIfCancellationRequested();

        // Second inspection must still agree in every recorded value before anything is written.
        stage = InspectStage;
        MaintenanceSnapshot? afterPrepare;
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
            return Failure(stage, exception.Message, verifiedSlots);
        }

        if (afterPrepare is null || !afterPrepare.Equals(snapshot))
        {
            return Failure(
                PreflightStage,
                "Device snapshot changed after boot preparation.",
                verifiedSlots);
        }

        // Last point at which the caller may still stop the run. Below this the caller token is
        // deliberately ignored: a late cancellation would abandon a half-written slot.
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var slot in slots)
        {
            var isSlotA = string.Equals(slot, "a", StringComparison.Ordinal);

            stage = isSlotA ? WriteBootAStage : WriteBootBStage;
            try
            {
                await backend.WriteBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                // Once a write has started, cancellation is a failure like any other: the caller is
                // told which stage broke instead of being handed an exception.
                return Failure(stage, exception.Message, verifiedSlots);
            }

            stage = isSlotA ? VerifyBootAStage : VerifyBootBStage;
            try
            {
                await backend.VerifyBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return Failure(stage, exception.Message, verifiedSlots);
            }

            // A slot counts as verified only after its verification succeeded, and a failure above
            // returns immediately so no later slot is touched.
            verifiedSlots.Add(slot);
        }

        stage = AwaitingBootAcceptanceStage;
        return new MaintenanceResult(true, stage, verifiedSlots.ToArray(), null);
    }

    /// <summary>
    /// Business preflight. Returns the rejection reason, or null when the request may run.
    /// </summary>
    private static string? Rejection(
        MaintenanceRequest request,
        IReadOnlyList<string>? slots,
        WorkflowTarget target)
    {
        if (!Enum.IsDefined<MaintenanceMode>(request.Mode))
        {
            return "Maintenance mode is not a known value.";
        }

        if (!Enum.IsDefined<WorkflowTarget>(target))
        {
            return "Workflow target is not a known value.";
        }

        if (request.TestPackage && target != WorkflowTarget.Simulation)
        {
            return "Test packages may not be installed on a device.";
        }

        var snapshot = request.Snapshot;
        if (snapshot is null)
        {
            return "Maintenance snapshot is required.";
        }

        var inputs = snapshot.Inputs;
        if (inputs is null)
        {
            return "Workflow inputs are required.";
        }

        if (string.IsNullOrWhiteSpace(inputs.Serial))
        {
            return "Device serial is required.";
        }

        if (!string.Equals(inputs.Model, "TB322FC", StringComparison.Ordinal) &&
            !string.Equals(inputs.Model, "TB323FU", StringComparison.Ordinal))
        {
            return "Unsupported device model.";
        }

        if (inputs.BootloaderState != BootloaderState.Unlocked)
        {
            return "Bootloader must be unlocked.";
        }

        if (string.IsNullOrWhiteSpace(inputs.TableFingerprint))
        {
            return "Table fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(inputs.PackageFingerprint))
        {
            return "Package fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(inputs.BackupFingerprint))
        {
            return "Backup fingerprint is required.";
        }

        // The digest of the current device boot state is required separately from the recorded
        // backup: a valid backup proves what was saved, not what the device is booting right now.
        // Only a real adapter that read A/B current boot digests plus firmware/slot-version evidence
        // can supply it, so an absent value fails closed instead of being defaulted or derived here.
        if (string.IsNullOrWhiteSpace(inputs.CurrentBootFingerprint))
        {
            return "Current boot fingerprint is required.";
        }

        if (string.IsNullOrWhiteSpace(snapshot.SlotVersionsFingerprint))
        {
            return "Slot versions fingerprint is required.";
        }

        // BothSlotBasesValid / MaintenanceValidated are assertions only a real adapter can make,
        // and only after it has checked the actual contents and firmware of both slot bases. A raw
        // "backup complete" flag is NOT that evidence, so this layer never derives these booleans
        // itself and never treats a plain backup success as proof of a bootable base.
        if (!inputs.BothSlotBasesValid)
        {
            return "Both slot bases must be valid.";
        }

        if (!inputs.MaintenanceValidated)
        {
            return "Maintenance mode must be validated.";
        }

        // An unknown, transient or future OTA state is never guessed to be Completed: only the
        // explicit Completed value passes, so anything else fails closed.
        if (!Enum.IsDefined<OtaUpdateState>(snapshot.OtaState) ||
            snapshot.OtaState != OtaUpdateState.Completed)
        {
            return "OTA update must be completed before boot maintenance.";
        }

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
                if (seenA) return "Slot order must list slot a and slot b exactly once.";
                seenA = true;
            }
            else if (string.Equals(slot, "b", StringComparison.Ordinal))
            {
                if (seenB) return "Slot order must list slot a and slot b exactly once.";
                seenB = true;
            }
            else
            {
                return "Slot order contains an unknown slot.";
            }
        }

        // Recomputed over the pinned copy of the slot order, so a list mutated after confirmation
        // cannot ride along under an old digest.
        var pinned = request with { SlotOrder = slots };
        if (!string.Equals(request.ConfirmationId, ConfirmationFor(pinned), StringComparison.Ordinal))
        {
            return "Confirmation id does not match the pinned maintenance request.";
        }

        return null;
    }

    private static MaintenanceResult Failure(string stage, string? error, List<string> verifiedSlots)
        => new(false, stage, verifiedSlots.ToArray(), error);

    private static string[]? CopySlots(IReadOnlyList<string>? slots)
    {
        if (slots is null)
        {
            return null;
        }

        var copy = new string[slots.Count];
        for (var index = 0; index < copy.Length; index++)
        {
            copy[index] = slots[index]!;
        }

        return copy;
    }
}
