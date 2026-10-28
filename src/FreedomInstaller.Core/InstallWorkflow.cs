using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>Where an install workflow is allowed to run.</summary>
public enum WorkflowTarget
{
    Simulation,
    Device,
}

/// <summary>Ordered stages reported by the install workflow.</summary>
public enum InstallStage
{
    Preflight,
    PrepareBoot,
    Partition,
    DeploySystem,
    VerifySystem,
    WriteBootA,
    VerifyBootA,
    WriteBootB,
    VerifyBootB,
    AwaitingBootAcceptance,
}

/// <summary>Device snapshot captured by inspection and pinned by the confirmation digest.</summary>
/// <param name="CurrentBootFingerprint">
/// Digest of the <em>current</em> boot state as read from the live device: the current boot image
/// digest of slot A and of slot B, together with the firmware / slot-version evidence of both slots,
/// combined canonically (one stable ordering and one unambiguous encoding) into a single digest.
/// A future device adapter MUST read all of those values from the device itself and derive this
/// field from that combination; it MUST NOT substitute the digest of a backup file - or of any other
/// recorded artefact - for the current device state, because a backup that still matches says
/// nothing about what the device is booting from now.
/// The default is empty on purpose: no real adapter exists yet, so any non-empty value here would
/// claim a reading that was never taken. An empty value therefore fails preflight instead of
/// silently passing, and the demo shell passes an explicit DEMO-* marker rather than a plausible
/// looking digest.
/// </param>
public record WorkflowInputs(
    string Serial,
    string Model,
    BootloaderState BootloaderState,
    string TableFingerprint,
    string PackageFingerprint,
    string BackupFingerprint,
    bool BothSlotBasesValid,
    bool MaintenanceValidated,
    string CurrentBootFingerprint = "");

/// <summary>Operator intent: pinned inputs, plan, confirmation and slot ordering.</summary>
public record InstallRequest(
    WorkflowInputs Inputs,
    string PlanFingerprint,
    string ConfirmationId,
    bool UserDataEraseConfirmed,
    bool TestPackage,
    IReadOnlyList<string> SlotOrder);

/// <summary>Outcome of a workflow run.</summary>
public record WorkflowResult(
    bool Success,
    InstallStage Stage,
    bool AndroidDataMayBeErased,
    IReadOnlyList<string> VerifiedSlots,
    string? Error);

/// <summary>Device operations the workflow drives.</summary>
public interface IInstallBackend
{
    WorkflowTarget Target { get; }

    Task<WorkflowInputs> InspectAsync(CancellationToken token);

    Task PrepareBootAsync(CancellationToken token);

    Task PartitionAsync(CancellationToken token);

    Task DeploySystemAsync(CancellationToken token);

    Task VerifySystemAsync(CancellationToken token);

    Task WriteBootAsync(string slot, CancellationToken token);

    Task VerifyBootAsync(string slot, CancellationToken token);
}

/// <summary>Deterministic, backend-agnostic install workflow.</summary>
public static class InstallWorkflow
{
    /// <summary>
    /// SHA-256 over the canonical JSON form of every pinned field except
    /// <see cref="InstallRequest.ConfirmationId"/>, so that the digest is stable and cannot be
    /// confused by fields whose values happen to run together.
    /// </summary>
    public static string ConfirmationFor(InstallRequest request)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var json = new StringBuilder(512);
        json.Append("{\"Inputs\":");
        var inputs = request.Inputs;
        if (inputs is null)
        {
            json.Append("null");
        }
        else
        {
            json.Append("{\"Serial\":");
            AppendJsonString(json, inputs.Serial);
            json.Append(",\"Model\":");
            AppendJsonString(json, inputs.Model);
            json.Append(",\"BootloaderState\":");
            AppendJsonString(json, inputs.BootloaderState.ToString());
            json.Append(",\"TableFingerprint\":");
            AppendJsonString(json, inputs.TableFingerprint);
            json.Append(",\"PackageFingerprint\":");
            AppendJsonString(json, inputs.PackageFingerprint);
            json.Append(",\"BackupFingerprint\":");
            AppendJsonString(json, inputs.BackupFingerprint);
            json.Append(",\"BothSlotBasesValid\":").Append(inputs.BothSlotBasesValid ? "true" : "false");
            json.Append(",\"MaintenanceValidated\":").Append(inputs.MaintenanceValidated ? "true" : "false");
            json.Append(",\"CurrentBootFingerprint\":");
            AppendJsonString(json, inputs.CurrentBootFingerprint);
            json.Append('}');
        }

        json.Append(",\"PlanFingerprint\":");
        AppendJsonString(json, request.PlanFingerprint);
        json.Append(",\"UserDataEraseConfirmed\":").Append(request.UserDataEraseConfirmed ? "true" : "false");
        json.Append(",\"TestPackage\":").Append(request.TestPackage ? "true" : "false");
        json.Append(",\"SlotOrder\":[");
        var slots = request.SlotOrder;
        if (slots is not null)
        {
            for (var i = 0; i < slots.Count; i++)
            {
                if (i > 0) json.Append(',');
                AppendJsonString(json, slots[i]);
            }
        }

        json.Append("]}");

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(json.ToString()));
        var digest = new StringBuilder(hash.Length * 2);
        foreach (var value in hash)
        {
            digest.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return digest.ToString();
    }

    public static async Task<WorkflowResult> RunAsync(
        InstallRequest request,
        IInstallBackend backend,
        IProgress<InstallStage>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (backend is null) throw new ArgumentNullException(nameof(backend));

        // SlotOrder may be a mutable list owned by the caller: copy it before the first await so
        // no later mutation can change which slots are written, and bind the confirmation to the copy.
        request = request with { SlotOrder = request.SlotOrder?.ToArray()! };

        cancellationToken.ThrowIfCancellationRequested();

        var stage = InstallStage.Preflight;
        var verified = new List<string>();
        var androidDataMayBeErased = false;
        SafeReport(progress, stage);

        // Business rejections are reported, never thrown.
        var rejection = Rejection(request, backend.Target);
        if (rejection is not null)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, rejection);
        }

        // First inspection pins the device state the plan was confirmed against.
        WorkflowInputs? snapshot;
        try
        {
            snapshot = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        if (snapshot is null || !snapshot.Equals(request.Inputs))
        {
            return new WorkflowResult(
                false, stage, androidDataMayBeErased, verified,
                "Device snapshot does not match the confirmed inputs.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Non-destructive boot preparation only; nothing is flashed here.
        stage = InstallStage.PrepareBoot;
        SafeReport(progress, stage);
        try
        {
            await backend.PrepareBootAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Second inspection must still match exactly before anything is destroyed.
        stage = InstallStage.Preflight;
        SafeReport(progress, stage);
        WorkflowInputs? confirmationSnapshot;
        try
        {
            confirmationSnapshot = await backend.InspectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        if (confirmationSnapshot is null || !confirmationSnapshot.Equals(request.Inputs))
        {
            return new WorkflowResult(
                false, stage, androidDataMayBeErased, verified,
                "Device snapshot changed after boot preparation.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Past this point the caller token is deliberately ignored: a destructive stage must run to
        // completion, otherwise a late cancellation would abandon a half-written slot.
        androidDataMayBeErased = true;

        stage = InstallStage.Partition;
        SafeReport(progress, stage);
        try
        {
            await backend.PartitionAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        stage = InstallStage.DeploySystem;
        SafeReport(progress, stage);
        try
        {
            await backend.DeploySystemAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        stage = InstallStage.VerifySystem;
        SafeReport(progress, stage);
        try
        {
            await backend.VerifySystemAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
        }

        foreach (var slot in request.SlotOrder)
        {
            var writeStage = string.Equals(slot, "a", StringComparison.Ordinal)
                ? InstallStage.WriteBootA
                : InstallStage.WriteBootB;
            var verifyStage = string.Equals(slot, "a", StringComparison.Ordinal)
                ? InstallStage.VerifyBootA
                : InstallStage.VerifyBootB;

            stage = writeStage;
            SafeReport(progress, stage);
            try
            {
                await backend.WriteBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
            }

            stage = verifyStage;
            SafeReport(progress, stage);
            try
            {
                await backend.VerifyBootAsync(slot, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return new WorkflowResult(false, stage, androidDataMayBeErased, verified, exception.Message);
            }

            // A slot counts as verified only after its verification succeeded.
            verified.Add(slot);
        }

        stage = InstallStage.AwaitingBootAcceptance;
        SafeReport(progress, stage);
        return new WorkflowResult(true, stage, androidDataMayBeErased, verified, null);
    }

    private static string? Rejection(InstallRequest request, WorkflowTarget target)
    {
        if (!request.UserDataEraseConfirmed)
        {
            return "User data erase has not been confirmed.";
        }

        if (request.TestPackage && target != WorkflowTarget.Simulation)
        {
            return "Test packages may not be installed on a device.";
        }

        if (string.IsNullOrWhiteSpace(request.PlanFingerprint))
        {
            return "Plan fingerprint is required.";
        }

        var inputs = request.Inputs;
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

        // Kept separate from BackupFingerprint: a backup proves what was saved, not what the device
        // is booting now. Only a real adapter that read both slots' current boot digests plus their
        // firmware/slot-version evidence can supply this, so a missing value fails closed here rather
        // than being defaulted, derived, or replaced by the backup digest.
        if (string.IsNullOrWhiteSpace(inputs.CurrentBootFingerprint))
        {
            return "Current boot fingerprint is required.";
        }

        if (!inputs.BothSlotBasesValid)
        {
            return "Both slot bases must be valid.";
        }

        if (!inputs.MaintenanceValidated)
        {
            return "Maintenance mode must be validated.";
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

        if (!string.Equals(request.ConfirmationId, ConfirmationFor(request), StringComparison.Ordinal))
        {
            return "Confirmation id does not match the pinned install plan.";
        }

        return null;
    }

    private static void AppendJsonString(StringBuilder builder, string? value)
    {
        if (value is null)
        {
            builder.Append("null");
            return;
        }

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
    }

    private static void SafeReport(IProgress<InstallStage>? progress, InstallStage stage)
    {
        try
        {
            progress?.Report(stage);
        }
        catch (Exception)
        {
            // Progress reporting is best effort: a faulty observer must never change the outcome.
        }
    }
}
