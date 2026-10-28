using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The RH004B part of <see cref="RamInstallClient"/>: the four fixed export downloads and the single
/// finish trigger. Export is one combined operation under the mutating gate: the build proof is
/// validated first, then exactly one export job is started, its exact role readiness is awaited, one
/// connection streams the fixed artifact into a new PC file, and the authoritative status must agree
/// before any file is reported as verified.
/// </summary>
public sealed partial class RamInstallClient
{
    private const string ExportCommand = "export --role ";
    private const string Restart2ReturnedCode = "restart2-returned";
    private const int ExportChunkBytes = 128 * 1024;

    private static readonly RamInstallExportRole[] ExportRoles =
    {
        RamInstallExportRole.BootA,
        RamInstallExportRole.BootB,
        RamInstallExportRole.ReportA,
        RamInstallExportRole.ReportB,
    };

    private static readonly HashSet<string> ExportSuccessAckFields = new(StringComparer.Ordinal)
    {
        "role",
        "length",
        "sha256",
        "receiverAcknowledged",
    };

    private readonly Func<
        Stream,
        string,
        long,
        string,
        string,
        IProgress<RamInstallSeedProgress>?,
        TimeSpan,
        CancellationToken,
        Task>? _exportSender;

    private readonly HashSet<RamInstallExportRole> _exportAttempted = new();
    private readonly HashSet<RamInstallExportRole> _completedExports = new();
    private int _finishAttempted;

    internal RamInstallClient(
        RamInstallSession session,
        RamInstallRequest request,
        Func<
            Stream,
            RamInstallSeed,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task>? seedSender,
        Func<
            Stream,
            string,
            long,
            string,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task>? materialSender,
        Func<
            Stream,
            string,
            long,
            string,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task>? exportSender)
        : this(session, request, seedSender, materialSender)
    {
        _exportSender = exportSender;
    }

    /// <summary>
    /// True once this client actually sent the finish command (or attempted to). It is set immediately
    /// before the console call, never reset, and stays true after a lost acknowledgement or a caller
    /// cancellation, so a caller can tell a lost ACK from a command that was never attempted.
    /// </summary>
    public bool FinishAttempted => Volatile.Read(ref _finishAttempted) != 0;

    /// <summary>
    /// Downloads one of the four locked build artifacts into a brand-new caller path and returns a
    /// claim that is only produced after the local file and the authoritative export status both agree
    /// on the exact role, length and digest.
    /// </summary>
    /// <remarks>
    /// The whole operation shares one caller budget: proof validation, readiness polling, the single TCP
    /// connection, EOF, fsync, the acknowledgement and the final status. The target file is opened with
    /// <see cref="FileMode.CreateNew"/> before any job is started, so an existing file is refused without
    /// touching it or consuming the single-use remote action. No path or role reaches the wire beyond the
    /// closed role literal; no retry, rebuild, redeploy or reformat is performed on failure.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="role"/> or <paramref name="timeout"/> is unusable.</exception>
    /// <exception cref="ArgumentException">The target is not a new file in an existing directory.</exception>
    /// <exception cref="IOException">The target already exists or the local write failed.</exception>
    /// <exception cref="MaintenanceException">The proof, readiness or authoritative result is not exact.</exception>
    /// <exception cref="TimeoutException">The caller budget expired.</exception>
    public async Task<VerifiedEdlFile> ExportAsync(
        RamInstallExportRole role,
        string newFilePath,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(typeof(RamInstallExportRole), role))
        {
            throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown export role.");
        }

        if (string.IsNullOrWhiteSpace(newFilePath))
        {
            throw new ArgumentException("A new target file path is required.", nameof(newFilePath));
        }

        ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();
        _ = RequireBootConfiguration();

        string fullPath = Path.GetFullPath(newFilePath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new ArgumentException(
                "The export target must be a new file inside an existing directory.",
                nameof(newFilePath));
        }

        string roleLiteral = RoleLiteral(role);
        string jobKey = ExportJobKey(role);

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_exportAttempted.Contains(role))
            {
                throw ExportAlreadyInvoked(roleLiteral);
            }

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            CancellationToken token = timeoutSource.Token;
            var stopwatch = Stopwatch.StartNew();

            try
            {
                RamInstallBuiltBoots built = await GetBuiltBootsAsync(token).ConfigureAwait(false);
                RamInstallBuiltFile artifact = built.GetArtifact(role);

                // The exclusive new file is opened before the first mutating command: an existing
                // target is refused without touching it and without burning the single-use remote job.
                using var target = new FileStream(
                    fullPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.Read,
                    ExportChunkBytes,
                    FileOptions.None);

                _exportAttempted.Add(role);

                await RunExportActionAsync(roleLiteral, jobKey, token).ConfigureAwait(false);
                await WaitForExportReadyAsync(
                        jobKey,
                        roleLiteral,
                        stopwatch,
                        timeout,
                        timeoutSource,
                        cancellationToken)
                    .ConfigureAwait(false);

                TimeSpan remaining = timeout - stopwatch.Elapsed;
                if (remaining <= TimeSpan.Zero)
                {
                    throw TimeoutFailure(jobKey);
                }

                await SendExportAsync(target, roleLiteral, artifact, progress, remaining, token)
                    .ConfigureAwait(false);

                await WaitForExportResultAsync(
                        jobKey,
                        roleLiteral,
                        artifact,
                        stopwatch,
                        timeout,
                        timeoutSource,
                        cancellationToken)
                    .ConfigureAwait(false);

                _completedExports.Add(role);
                return new VerifiedEdlFile(fullPath, artifact.Length, artifact.Sha256);
            }
            catch (OperationCanceledException) when (
                timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw TimeoutFailure(jobKey);
            }
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>
    /// Sends the single finish command only after the four exports were locally verified and all four
    /// authoritative export statuses still agree. A normal running job yields
    /// <see cref="RamInstallFinishAttemptState.Requested"/>; a readable RESTART2 diagnostic yields
    /// <see cref="RamInstallFinishAttemptState.Restart2Returned"/> (always a failure); a lost console
    /// acknowledgement yields <see cref="RamInstallFinishAttemptState.AcknowledgementUnknown"/>.
    /// </summary>
    /// <remarks>
    /// This never waits for a RAM-side finish success and never retries. It performs no reboot, no HTTP
    /// request, no shell reboot and no EDL write: the caller must prove the real reset with the backend's
    /// own USB/EDL evidence.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The finish command was already attempted.</exception>
    /// <exception cref="MaintenanceException">A prerequisite or the protocol is not exact.</exception>
    public async Task<RamInstallFinishAttempt> StartFinishAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = RequireBootConfiguration();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (Volatile.Read(ref _finishAttempted) != 0)
            {
                throw new InvalidOperationException(
                    "The finish command was already attempted in this session; it is never resent.");
            }

            RamInstallBuiltBoots built = await GetBuiltBootsAsync(cancellationToken).ConfigureAwait(false);

            foreach (RamInstallExportRole exportRole in ExportRoles)
            {
                if (!_completedExports.Contains(exportRole))
                {
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The finish command requires all four exports to be locally verified.");
                }
            }

            foreach (RamInstallExportRole exportRole in ExportRoles)
            {
                string jobKey = ExportJobKey(exportRole);
                RamInstallJob status = await GetStatusInternalAsync(jobKey, cancellationToken)
                    .ConfigureAwait(false);
                RequireExportSucceeded(status, RoleLiteral(exportRole), built.GetArtifact(exportRole));
            }

            // The action is marked only while the caller is still live at the last safe point: a
            // cancellation before this check leaves an action that was never attempted unmarked.
            cancellationToken.ThrowIfCancellationRequested();

            // The attempt is recorded immediately before the console call. It is never reset, even
            // when the acknowledgement is lost or the caller cancels during the command.
            Volatile.Write(ref _finishAttempted, 1);

            RamInstallJob job;
            try
            {
                job = await RunFinishActionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                return new RamInstallFinishAttempt(
                    RamInstallFinishAttemptState.AcknowledgementUnknown,
                    errno: null,
                    returnCode: null);
            }
            catch (TimeoutException)
            {
                return new RamInstallFinishAttempt(
                    RamInstallFinishAttemptState.AcknowledgementUnknown,
                    errno: null,
                    returnCode: null);
            }

            switch (job.State)
            {
                case RamInstallJobState.Running:
                    return new RamInstallFinishAttempt(
                        RamInstallFinishAttemptState.Requested,
                        errno: null,
                        returnCode: null);

                case RamInstallJobState.Failed:
                    if (job.ExitCode == 1 &&
                        job.Result is { } result &&
                        TryParseFinishDiagnostic(result, out int errno, out long returnCode))
                    {
                        return new RamInstallFinishAttempt(
                            RamInstallFinishAttemptState.Restart2Returned,
                            errno,
                            returnCode);
                    }

                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The finish job failed.");

                default:
                    // A RAM-side finish success cannot be read back: the reset destroys the state that
                    // would persist it. Any such record is treated as a protocol violation, never as
                    // proof of a real EDL reset.
                    throw ProtocolFailure();
            }
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>
    /// Validates the single, exact RESTART2 diagnostic the helper may attach to a failed finish job.
    /// Any other failed result shape stays a protocol failure.
    /// </summary>
    private static bool TryParseFinishDiagnostic(
        JsonElement result,
        out int errno,
        out long returnCode)
    {
        errno = 0;
        returnCode = 0;

        if (result.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in result.EnumerateObject())
        {
            if (!seen.Add(property.Name) ||
                (property.Name != "code" &&
                 property.Name != "errno" &&
                 property.Name != "returnCode"))
            {
                return false;
            }
        }

        if (seen.Count != 3 ||
            !result.TryGetProperty("code", out JsonElement code) ||
            code.ValueKind != JsonValueKind.String ||
            !string.Equals(code.GetString(), Restart2ReturnedCode, StringComparison.Ordinal) ||
            !result.TryGetProperty("errno", out JsonElement errnoElement) ||
            errnoElement.ValueKind != JsonValueKind.Number ||
            !errnoElement.TryGetInt32(out errno) ||
            errno < 0 ||
            !result.TryGetProperty("returnCode", out JsonElement returnElement) ||
            returnElement.ValueKind != JsonValueKind.Number ||
            !returnElement.TryGetInt64(out returnCode))
        {
            return false;
        }

        return true;
    }

    private async Task<RamInstallJob> RunExportActionAsync(
        string roleLiteral,
        string jobKey,
        CancellationToken cancellationToken)
    {
        string transcript = await _console
            .RunCommandAsync(
                BuildCommandScript(ExportCommand + roleLiteral, status: false),
                CommandMarker,
                ActionTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        RamInstallJob job = ParseJob(transcript, jobKey);
        if (job.State == RamInstallJobState.NotStarted)
        {
            throw ProtocolFailure();
        }

        return job;
    }

    private async Task<RamInstallJob> RunFinishActionAsync(CancellationToken cancellationToken)
    {
        string transcript = await _console
            .RunCommandAsync(
                BuildCommandScript(FinishLiteral, status: false),
                CommandMarker,
                ActionTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        RamInstallJob job = ParseJob(transcript, FinishLiteral);
        if (job.State == RamInstallJobState.NotStarted)
        {
            throw ProtocolFailure();
        }

        return job;
    }

    private async Task WaitForExportReadyAsync(
        string jobKey,
        string roleLiteral,
        Stopwatch stopwatch,
        TimeSpan timeout,
        CancellationTokenSource timeoutSource,
        CancellationToken callerToken)
    {
        CancellationToken token = timeoutSource.Token;

        try
        {
            while (true)
            {
                RamInstallJob status = await GetStatusInternalAsync(jobKey, token).ConfigureAwait(false);

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job already succeeded without this export transfer.");
                    case RamInstallJobState.Failed:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job failed.");
                    case RamInstallJobState.Interrupted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job was interrupted.");
                    case RamInstallJobState.NotStarted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job has not been started.");
                    case RamInstallJobState.Running:
                        if (IsMaterialReady(status, roleLiteral))
                        {
                            return;
                        }

                        break;
                }

                if (stopwatch.Elapsed >= timeout)
                {
                    throw TimeoutFailure(jobKey);
                }

                await DelayPollAsync(token, timeoutSource, callerToken, jobKey).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            throw TimeoutFailure(jobKey);
        }
    }

    private async Task<RamInstallJob> WaitForExportResultAsync(
        string jobKey,
        string roleLiteral,
        RamInstallBuiltFile artifact,
        Stopwatch stopwatch,
        TimeSpan timeout,
        CancellationTokenSource timeoutSource,
        CancellationToken callerToken)
    {
        CancellationToken token = timeoutSource.Token;

        try
        {
            while (true)
            {
                RamInstallJob status = await GetStatusInternalAsync(jobKey, token).ConfigureAwait(false);

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        RequireExportSucceeded(status, roleLiteral, artifact);
                        return status;
                    case RamInstallJobState.Failed:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job failed.");
                    case RamInstallJobState.Interrupted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job was interrupted.");
                    case RamInstallJobState.NotStarted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + jobKey + " job has not been started.");
                }

                if (stopwatch.Elapsed >= timeout)
                {
                    throw TimeoutFailure(jobKey);
                }

                await DelayPollAsync(token, timeoutSource, callerToken, jobKey).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            throw TimeoutFailure(jobKey);
        }
    }

    private static void RequireExportSucceeded(
        RamInstallJob job,
        string roleLiteral,
        RamInstallBuiltFile artifact)
    {
        if (job.State != RamInstallJobState.Succeeded ||
            job.ExitCode != 0 ||
            job.HasError ||
            job.Result is not { } result ||
            result.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in result.EnumerateObject())
        {
            if (!seen.Add(property.Name) || !ExportSuccessAckFields.Contains(property.Name))
            {
                throw ProtocolFailure();
            }
        }

        if (seen.Count != ExportSuccessAckFields.Count ||
            !result.TryGetProperty("role", out JsonElement roleElement) ||
            roleElement.ValueKind != JsonValueKind.String ||
            !string.Equals(roleElement.GetString(), roleLiteral, StringComparison.Ordinal) ||
            !result.TryGetProperty("length", out JsonElement lengthElement) ||
            lengthElement.ValueKind != JsonValueKind.Number ||
            !lengthElement.TryGetInt64(out long length) ||
            length != artifact.Length ||
            !result.TryGetProperty("sha256", out JsonElement shaElement) ||
            shaElement.ValueKind != JsonValueKind.String ||
            !string.Equals(shaElement.GetString(), artifact.Sha256, StringComparison.Ordinal) ||
            !result.TryGetProperty("receiverAcknowledged", out JsonElement ackElement) ||
            ackElement.ValueKind != JsonValueKind.True)
        {
            throw ProtocolFailure();
        }
    }

    private Task SendExportAsync(
        Stream target,
        string roleLiteral,
        RamInstallBuiltFile artifact,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Func<
            Stream,
            string,
            long,
            string,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task>? sender = _exportSender;

        if (sender is not null)
        {
            return sender(
                target,
                roleLiteral,
                artifact.Length,
                artifact.Sha256,
                _token,
                progress,
                timeout,
                cancellationToken);
        }

        return new TcpInstallExportTransfer().SendAsync(
            target,
            roleLiteral,
            artifact.Length,
            artifact.Sha256,
            _token,
            progress,
            timeout,
            cancellationToken);
    }

    private static string ExportJobKey(RamInstallExportRole role) => role switch
    {
        RamInstallExportRole.BootA => ExportBootALiteral,
        RamInstallExportRole.BootB => ExportBootBLiteral,
        RamInstallExportRole.ReportA => ExportReportALiteral,
        RamInstallExportRole.ReportB => ExportReportBLiteral,
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown export role."),
    };

    private static InvalidOperationException ExportAlreadyInvoked(string roleLiteral) =>
        new("The " + roleLiteral
            + " export was already attempted in this session; it is never restarted. "
            + "Use GetStatusAsync to observe the persisted job.");
}
