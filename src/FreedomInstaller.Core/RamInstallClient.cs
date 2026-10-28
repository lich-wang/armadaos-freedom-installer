using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>The single-use RAM install actions, including the frozen BOOT-WIRE-v2 keys.</summary>
public enum RamInstallAction
{
    Prepare = 0,
    ReceiveSeed = 1,
    Deploy = 2,
    ReceiveOriginalBootA = 3,
    ReceiveRuntime = 4,
    BuildBoots = 5,
    ExportBootA = 6,
    ExportBootB = 7,
    ExportReportA = 8,
    ExportReportB = 9,
    Finish = 10,
}

/// <summary>The states the helper may persist for an action.</summary>
public enum RamInstallJobState
{
    NotStarted = 0,
    Running = 1,
    Succeeded = 2,
    Failed = 3,
    Interrupted = 4,
}

/// <summary>
/// One validated job record returned by inspect, a start command or status.
/// </summary>
/// <remarks>
/// <see cref="Result"/> is a clone, so it stays valid after the response document is disposed. The
/// raw remote <c>error</c> text is never exposed as a property: <see cref="HasError"/> is the only
/// failure signal, and exceptions use a fixed, sanitized message that cannot contain a token.
/// </remarks>
public sealed class RamInstallJob
{
    private readonly string? _error;

    internal RamInstallJob(
        int schemaVersion,
        string requestSha256,
        string action,
        RamInstallJobState state,
        long? pid,
        string? pidStartTicks,
        int? exitCode,
        JsonElement? result,
        string? error)
    {
        SchemaVersion = schemaVersion;
        RequestSha256 = requestSha256;
        Action = action;
        State = state;
        Pid = pid;
        PidStartTicks = pidStartTicks;
        ExitCode = exitCode;
        Result = result;
        _error = error;
    }

    public int SchemaVersion { get; }

    public string RequestSha256 { get; }

    /// <summary>The literal action (<c>inspect</c>, <c>prepare</c>, <c>receive-seed</c>, <c>deploy</c>).</summary>
    public string Action { get; }

    public RamInstallJobState State { get; }

    public long? Pid { get; }

    public string? PidStartTicks { get; }

    public int? ExitCode { get; }

    /// <summary>A cloned result object, or null when the record has none.</summary>
    public JsonElement? Result { get; }

    /// <summary>True when the record carries a non-null error. The raw text is never exposed.</summary>
    public bool HasError => _error is not null;

    internal string? ErrorText => _error;

    public override string ToString() =>
        nameof(RamInstallJob)
        + " { Action = " + Action
        + ", State = " + State
        + ", ExitCode = " + (ExitCode.HasValue
            ? ExitCode.Value.ToString(CultureInfo.InvariantCulture)
            : "null")
        + " }";
}

/// <summary>
/// Binds one immutable <see cref="RamInstallRequest"/> to one proven <see cref="RamInstallSession"/>
/// and drives the fixed RAM install CLI over that session's console.
/// </summary>
/// <remarks>
/// There is no public constructor that accepts an arbitrary console, token or transport. The session
/// must come from the bootstrap's internal constructor, and the client compares the session's model,
/// normalized SoC serial and boot id with the request before any console call. All scripts are fixed
/// literals; the request is written once as base64 through a checked, no-clobber script, and the token
/// only reaches the shell through an octal <c>printf</c> command substitution.
/// </remarks>
public sealed partial class RamInstallClient
{
    private const string ToolboxRoot = "/tmp/armada-installer-tools";
    private const string StageRoot = "/tmp/freedom-install";
    private const string HostStageRoot = ToolboxRoot + StageRoot;
    private const string HostRequestPath = HostStageRoot + "/request.json";
    private const string Environment =
        "/usr/bin/env -i PATH=/tmp/freedom-install/tools:/usr/sbin:/usr/bin:/sbin:/bin "
        + "LD_LIBRARY_PATH=/tmp/freedom-install/lib HOME=/root LANG=C.UTF-8";
    private const string Python = "/usr/bin/python3";
    private const string HelperPath = StageRoot + "/armada_install.py";
    private const string JsonPrefix = "FREEDOM_INSTALL_JSON ";
    private const string CommandMarker = "FREEDOM_INSTALL_CMD_DONE";
    private const string InitMarker = "FREEDOM_INSTALL_REQUEST_V1_OK";
    private const string InspectAction = "inspect";
    private const string PrepareLiteral = "prepare";
    private const string ReceiveSeedLiteral = "receive-seed";
    private const string DeployLiteral = "deploy";
    private const int MaxJsonBytes = 1 << 20;

    private const string ProtocolMessage =
        "The RAM install console response does not match the frozen protocol.";

    private const string SessionMessage =
        "The RAM install session identity does not match the frozen install request.";

    private const string InitializationMessage =
        "The install request was not written and verified.";

    private static readonly TimeSpan InitTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan InspectTimeout = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan ActionTimeout = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan StatusTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan PollDelay = TimeSpan.FromMilliseconds(250);

    private static readonly HashSet<string> JobProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "requestSha256",
        "action",
        "state",
        "pid",
        "pidStartTicks",
        "exitCode",
        "result",
        "error",
    };

    /// <summary>
    /// The only actions whose running record may carry a readiness result. The set is closed: no other
    /// action may publish progress before its terminal state.
    /// </summary>
    private static readonly HashSet<string> RunningResultActions = new(StringComparer.Ordinal)
    {
        ReceiveSeedLiteral,
        ReceiveOriginalBootALiteral,
        ReceiveRuntimeLiteral,
        ExportBootALiteral,
        ExportBootBLiteral,
        ExportReportALiteral,
        ExportReportBLiteral,
    };

    private readonly IMaintenanceConsole _console;
    private readonly string _token;
    private readonly string _model;
    private readonly string _socSerial;
    private readonly string _bootId;
    private readonly RamInstallRequest _request;
    private readonly Func<
        Stream,
        RamInstallSeed,
        string,
        IProgress<RamInstallSeedProgress>?,
        TimeSpan,
        CancellationToken,
        Task> _seedSender;

    /// <summary>
    /// Serializes every mutating call (initialization, the three starts and the seed transfer) so two
    /// actions can never be launched together. Read-only status never takes this gate.
    /// </summary>
    private readonly SemaphoreSlim _mutatingGate = new(1, 1);

    private int _initializationReserved;
    private int _initialized;
    private bool _prepareStarted;
    private bool _receiveSeedStarted;
    private bool _deployStarted;
    private bool _seedTransferReserved;

    /// <summary>Binds the request to the proven session. Identity is compared before any I/O.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> or <paramref name="request"/> is null.</exception>
    /// <exception cref="MaintenanceException">The session identity does not match the request.</exception>
    public RamInstallClient(RamInstallSession session, RamInstallRequest request)
        : this(session, request, seedSender: null)
    {
    }

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
            Task>? seedSender)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(request);

        IMaintenanceConsole? console = session.Console;
        _console = console ?? throw SessionFailure();
        _token = session.Token;
        _model = session.Model;
        _socSerial = session.SocSerial;
        _bootId = session.BootId;
        _request = request;
        _seedSender = seedSender
            ?? ((content, seed, token, progress, timeout, cancellationToken) =>
                new TcpInstallSeedTransfer().SendAsync(
                    content,
                    seed,
                    token,
                    progress,
                    timeout,
                    cancellationToken));

        ValidateSessionBinding();
    }

    /// <summary>
    /// Writes the exact request bytes once, verifies their length and digest on the device, then runs
    /// the real inspect and validates its full identity, table and request binding.
    /// </summary>
    /// <remarks>
    /// Initialization is reserved before the console call. A failure or an ambiguous result is never
    /// rewritten or retried; a later <see cref="InspectAsync"/> or <see cref="GetStatusAsync"/> may
    /// reconcile the session read-only.
    /// </remarks>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _initialized) == 1)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _initializationReserved, 1, 0) != 0)
            {
                throw new InvalidOperationException(
                    "The install request initialization was already attempted; it is never rewritten or retried.");
            }

            byte[] bytes = _request.CopyRequestBytes();
            string script = BuildInitializationScript(bytes);
            string transcript = await _console
                .RunCommandAsync(script, InitMarker, InitTimeout, cancellationToken)
                .ConfigureAwait(false);

            EnsureInitializationMarker(transcript);
            await RunInspectAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>Runs the read-only inspect again and revalidates the complete response.</summary>
    public async Task<RamInstallJob> InspectAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await RunInspectAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts the single prepare job. It is never retried or restarted.</summary>
    public async Task<RamInstallJob> StartPrepareAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_prepareStarted)
            {
                throw AlreadyInvoked(PrepareLiteral);
            }

            _prepareStarted = true;
            return await RunActionAsync(PrepareLiteral, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>
    /// Starts the single receive-seed job only after the prepare status proved succeeded with exit 0.
    /// The caller then waits for listener readiness and performs exactly one seed transfer.
    /// </summary>
    public async Task<RamInstallJob> StartReceiveSeedAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_receiveSeedStarted)
            {
                throw AlreadyInvoked(ReceiveSeedLiteral);
            }

            await RequireSucceededAsync(PrepareLiteral, cancellationToken).ConfigureAwait(false);
            _receiveSeedStarted = true;
            return await RunActionAsync(ReceiveSeedLiteral, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>
    /// Starts the single deploy job only after the receive-seed status proved succeeded with exit 0.
    /// </summary>
    public async Task<RamInstallJob> StartDeployAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_deployStarted)
            {
                throw AlreadyInvoked(DeployLiteral);
            }

            await RequireSucceededAsync(ReceiveSeedLiteral, cancellationToken).ConfigureAwait(false);
            _deployStarted = true;
            return await RunActionAsync(DeployLiteral, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    /// <summary>Reads one action's persisted status. Never launches or mutates a job.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="action"/> is not a frozen action.</exception>
    /// <exception cref="InvalidOperationException">A boot action was requested on a request without the boot block.</exception>
    public Task<RamInstallJob> GetStatusAsync(
        RamInstallAction action,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string literal = Literal(action);
        RequireBootForLiteral(literal);
        return GetStatusInternalAsync(literal, cancellationToken);
    }

    /// <summary>
    /// Polls only status until the job succeeds with exit 0. Failed, interrupted, not-started and
    /// timeout outcomes throw sanitized errors; the raw remote error text is never surfaced.
    /// </summary>
    public async Task<RamInstallJob> WaitForCompletionAsync(
        RamInstallAction action,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        string literal = Literal(action);
        RequireBootForLiteral(literal);
        if (string.Equals(literal, FinishLiteral, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The finish job has no RAM-side success state; it requires new EDL proof after the reset.");
        }

        ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        CancellationToken token = timeoutSource.Token;
        var stopwatch = Stopwatch.StartNew();

        while (true)
        {
            RamInstallJob job;
            try
            {
                job = await GetStatusInternalAsync(literal, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw TimeoutFailure(literal);
            }

            switch (job.State)
            {
                case RamInstallJobState.Succeeded:
                    return job;
                case RamInstallJobState.Failed:
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The " + literal + " job failed.");
                case RamInstallJobState.Interrupted:
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The " + literal + " job was interrupted.");
                case RamInstallJobState.NotStarted:
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The " + literal + " job has not been started.");
            }

            if (stopwatch.Elapsed >= timeout)
            {
                throw TimeoutFailure(literal);
            }

            try
            {
                await Task.Delay(PollDelay, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw TimeoutFailure(literal);
            }
        }
    }

    /// <summary>
    /// Waits read-only for the receive-seed listener's <c>result.ready=true</c>, sends the imported
    /// seed exactly once over the fixed TCP target, then requires the authoritative receive-seed
    /// status to be succeeded with exit 0.
    /// </summary>
    /// <remarks>
    /// This method never starts the receive-seed action, never retries a partial transfer and never
    /// reconnects on a guess. A failed, interrupted or already-succeeded receive-seed status is
    /// rejected without opening a connection. The supplied timeout is one budget for readiness, the
    /// transfer and the final status polling; cancellation leaves the remote job state untouched.
    /// </remarks>
    public async Task TransferSeedAsync(
        Stream seed,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(seed);

        if (!seed.CanRead)
        {
            throw new ArgumentException("The seed stream must be readable.", nameof(seed));
        }

        ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_seedTransferReserved)
            {
                throw new InvalidOperationException(
                    "The seed transfer was already attempted in this session; it is never resent.");
            }

            await RequireSucceededAsync(PrepareLiteral, cancellationToken).ConfigureAwait(false);
            _seedTransferReserved = true;

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            CancellationToken token = timeoutSource.Token;
            var stopwatch = Stopwatch.StartNew();

            bool ready = false;
            while (!ready)
            {
                RamInstallJob status;
                try
                {
                    status = await GetStatusInternalAsync(ReceiveSeedLiteral, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw TimeoutFailure(ReceiveSeedLiteral);
                }

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job already succeeded without this seed transfer.");
                    case RamInstallJobState.Failed:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job failed.");
                    case RamInstallJobState.Interrupted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job was interrupted.");
                    case RamInstallJobState.NotStarted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job has not been started.");
                    case RamInstallJobState.Running:
                        ready = IsReady(status);
                        break;
                }

                if (ready)
                {
                    break;
                }

                if (stopwatch.Elapsed >= timeout)
                {
                    throw TimeoutFailure(ReceiveSeedLiteral);
                }

                await DelayPollAsync(token, timeoutSource, cancellationToken, ReceiveSeedLiteral)
                    .ConfigureAwait(false);
            }

            TimeSpan remaining = timeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                throw TimeoutFailure(ReceiveSeedLiteral);
            }

            try
            {
                await _seedSender(seed, _request.Seed, _token, progress, remaining, token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw TimeoutFailure(ReceiveSeedLiteral);
            }

            while (true)
            {
                RamInstallJob status;
                try
                {
                    status = await GetStatusInternalAsync(ReceiveSeedLiteral, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw TimeoutFailure(ReceiveSeedLiteral);
                }

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        return;
                    case RamInstallJobState.Failed:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job failed.");
                    case RamInstallJobState.Interrupted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job was interrupted.");
                    case RamInstallJobState.NotStarted:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The receive-seed job has not been started.");
                }

                if (stopwatch.Elapsed >= timeout)
                {
                    throw TimeoutFailure(ReceiveSeedLiteral);
                }

                await DelayPollAsync(token, timeoutSource, cancellationToken, ReceiveSeedLiteral)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    private void ValidateSessionBinding()
    {
        string serial;
        string bootId;
        try
        {
            serial = NormalizeSocSerial(_socSerial);
            bootId = RamInstallValidation.NormalizeUuid(_bootId, nameof(_bootId));
        }
        catch (ArgumentException)
        {
            throw SessionFailure();
        }

        if (!string.Equals(_model, RamInstallRequest.ModelCode, StringComparison.Ordinal) ||
            !string.Equals(serial, _request.ExpectedSocSerial, StringComparison.Ordinal) ||
            !string.Equals(bootId, _request.ExpectedBootId, StringComparison.Ordinal) ||
            !RamInstallValidation.IsLowerSha256(_token))
        {
            throw SessionFailure();
        }
    }

    private async Task<RamInstallJob> RunInspectAsync(CancellationToken cancellationToken)
    {
        string transcript = await _console
            .RunCommandAsync(
                BuildCommandScript(InspectAction, status: false),
                CommandMarker,
                InspectTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        RamInstallJob job = ParseJob(transcript, InspectAction);
        ValidateInspect(job);
        Volatile.Write(ref _initialized, 1);
        return job;
    }

    private async Task<RamInstallJob> RunActionAsync(string literal, CancellationToken cancellationToken)
    {
        string transcript = await _console
            .RunCommandAsync(
                BuildCommandScript(literal, status: false),
                CommandMarker,
                ActionTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        RamInstallJob job = ParseJob(transcript, literal);
        if (job.State == RamInstallJobState.NotStarted)
        {
            throw ProtocolFailure();
        }

        return job;
    }

    private async Task<RamInstallJob> GetStatusInternalAsync(
        string literal,
        CancellationToken cancellationToken)
    {
        string transcript = await _console
            .RunCommandAsync(
                BuildCommandScript(literal, status: true),
                CommandMarker,
                StatusTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        return ParseJob(transcript, literal);
    }

    private async Task RequireSucceededAsync(string literal, CancellationToken cancellationToken)
    {
        RamInstallJob status = await GetStatusInternalAsync(literal, cancellationToken)
            .ConfigureAwait(false);

        if (status.State != RamInstallJobState.Succeeded || status.ExitCode != 0)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.HandshakeMismatch,
                "The " + literal + " job has not succeeded.");
        }
    }

    private void RequireInitialized()
    {
        if (Volatile.Read(ref _initialized) != 1)
        {
            throw new InvalidOperationException(
                "The RAM install request has not been fully initialized and inspected.");
        }
    }

    private static async Task DelayPollAsync(
        CancellationToken token,
        CancellationTokenSource timeoutSource,
        CancellationToken callerToken,
        string literal)
    {
        try
        {
            await Task.Delay(PollDelay, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            throw TimeoutFailure(literal);
        }
    }

    private static bool IsReady(RamInstallJob job)
    {
        if (job.Result is not { } result || result.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        return result.TryGetProperty("ready", out JsonElement ready) &&
            ready.ValueKind == JsonValueKind.True;
    }

    private string BuildInitializationScript(byte[] bytes)
    {
        string base64 = Convert.ToBase64String(bytes);
        string length = bytes.Length.ToString(CultureInfo.InvariantCulture);
        string sha256 = _request.RequestSha256;

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                "umask 077",
                "base=" + HostStageRoot,
                "if [ -h \"$base\" ]; then exit 1; fi",
                "busybox mkdir -p \"$base\"",
                "request=" + HostRequestPath,
                "temporary=" + HostRequestPath + ".tmp",
                "if [ -e \"$request\" ] || [ -h \"$request\" ]; then exit 1; fi",
                "if [ -e \"$temporary\" ] || [ -h \"$temporary\" ]; then exit 1; fi",
                "printf '%s' '" + base64 + "' | busybox base64 -d > \"$temporary\"",
                "bytes=$(busybox wc -c < \"$temporary\" | busybox awk '{print $1}')",
                "[ \"$bytes\" = \"" + length + "\" ] || { busybox rm -f \"$temporary\"; exit 1; }",
                "sha=$(busybox sha256sum \"$temporary\" | busybox awk '{print $1}')",
                "[ \"$sha\" = \"" + sha256 + "\" ] || { busybox rm -f \"$temporary\"; exit 1; }",
                "if [ -e \"$request\" ] || [ -h \"$request\" ]; then busybox rm -f \"$temporary\"; exit 1; fi",
                "busybox ln \"$temporary\" \"$request\"",
                "busybox rm -f \"$temporary\"",
                "printf '" + InitMarker + "\\n'",
            });
    }

    private string BuildCommandScript(string literal, bool status)
    {
        var builder = new StringBuilder(640);
        builder.Append("set -u\n");
        builder.Append("token=$(printf '").Append(OctalToken(_token)).Append("')\n");
        builder.Append("busybox chroot ").Append(ToolboxRoot).Append(' ')
            .Append(Environment).Append(' ')
            .Append(Python).Append(' ')
            .Append(HelperPath).Append(' ');

        if (status)
        {
            builder.Append("status --action ").Append(literal).Append(' ');
        }
        else
        {
            builder.Append(literal).Append(' ');
        }

        builder.Append("--token \"$token\"\n");
        builder.Append("printf '").Append(CommandMarker).Append("\\n'\n");
        return builder.ToString();
    }

    private static string OctalToken(string token)
    {
        var builder = new StringBuilder(token.Length * 4);
        foreach (var character in token)
        {
            builder.Append('\\')
                .Append(Convert.ToString((int)character, 8).PadLeft(3, '0'));
        }

        return builder.ToString();
    }

    private void EnsureInitializationMarker(string transcript)
    {
        var lines = SplitLines(transcript);
        if (lines.Count == 0 ||
            !string.Equals(lines[^1], InitMarker, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.HandshakeMismatch,
                InitializationMessage);
        }

        var matches = 0;
        foreach (var line in lines)
        {
            if (string.Equals(line, InitMarker, StringComparison.Ordinal))
            {
                matches++;
            }
        }

        if (matches != 1)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.HandshakeMismatch,
                InitializationMessage);
        }
    }

    private RamInstallJob ParseJob(string transcript, string expectedAction)
    {
        var lines = SplitLines(transcript);
        RequireFinalMarker(lines);

        string? payload = null;
        foreach (var line in lines)
        {
            if (!line.StartsWith(JsonPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (payload is not null)
            {
                throw ProtocolFailure();
            }

            payload = line[JsonPrefix.Length..];
        }

        if (payload is null || Encoding.UTF8.GetByteCount(payload) > MaxJsonBytes)
        {
            throw ProtocolFailure();
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException exception)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.HandshakeMismatch,
                ProtocolMessage,
                exception);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out JsonElement schema) ||
                schema.ValueKind != JsonValueKind.Number ||
                !schema.TryGetInt32(out var schemaVersion) ||
                schemaVersion != RamInstallRequest.ContractSchemaVersion)
            {
                throw ProtocolFailure();
            }

            if (!root.TryGetProperty("action", out _))
            {
                // A CLI-level failure line has schemaVersion and error only. Its text is not
                // surfaced; it is not trusted and could contain anything.
                if (root.TryGetProperty("error", out JsonElement error) &&
                    error.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrEmpty(error.GetString()))
                {
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The RAM install command failed.");
                }

                throw ProtocolFailure();
            }

            if (!HasExactProperties(root, JobProperties))
            {
                throw ProtocolFailure();
            }

            string requestSha256 = RequireString(root, "requestSha256");
            if (!RamInstallValidation.IsLowerSha256(requestSha256) ||
                !string.Equals(requestSha256, _request.RequestSha256, StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            string action = RequireString(root, "action");
            if (!string.Equals(action, expectedAction, StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            RamInstallJobState state = ParseState(RequireString(root, "state"));
            long? pid = ParsePid(root);
            string? pidStartTicks = ParsePidStartTicks(root);
            if ((pid is null) != (pidStartTicks is null))
            {
                throw ProtocolFailure();
            }

            int? exitCode = ParseExitCode(root);
            string? errorText = ParseError(root);
            JsonElement? result = ParseResult(root);

            ValidateState(action, state, pid, pidStartTicks, exitCode, result, errorText);

            return new RamInstallJob(
                schemaVersion,
                requestSha256,
                action,
                state,
                pid,
                pidStartTicks,
                exitCode,
                result,
                errorText);
        }
    }

    private static void ValidateState(
        string action,
        RamInstallJobState state,
        long? pid,
        string? pidStartTicks,
        int? exitCode,
        JsonElement? result,
        string? error)
    {
        switch (state)
        {
            case RamInstallJobState.NotStarted:
                if (pid is not null ||
                    pidStartTicks is not null ||
                    exitCode is not null ||
                    result is not null ||
                    error is not null)
                {
                    throw ProtocolFailure();
                }

                break;

            case RamInstallJobState.Running:
                if (pid is null ||
                    pidStartTicks is null ||
                    exitCode is not null ||
                    error is not null)
                {
                    throw ProtocolFailure();
                }

                if (result is not null &&
                    !RunningResultActions.Contains(action))
                {
                    throw ProtocolFailure();
                }

                break;

            case RamInstallJobState.Succeeded:
                if (exitCode != 0 || result is null || error is not null)
                {
                    throw ProtocolFailure();
                }

                break;

            case RamInstallJobState.Failed:
                if (exitCode is null || exitCode == 0 || error is null)
                {
                    throw ProtocolFailure();
                }

                // A failed record normally carries no result. The single exception is the finish
                // action's exact RESTART2 diagnostic, which the host may machine-check without ever
                // treating it as success. No other action and no other shape is relaxed.
                if (result is not null &&
                    (!string.Equals(action, FinishLiteral, StringComparison.Ordinal) ||
                     exitCode != 1 ||
                     !TryParseFinishDiagnostic(result.Value, out _, out _)))
                {
                    throw ProtocolFailure();
                }

                break;

            case RamInstallJobState.Interrupted:
                // A dead receive PID may still carry the earlier ready progress in result; that
                // progress is diagnostic only and never grants permission to connect or deploy.
                if (error is null || exitCode == 0)
                {
                    throw ProtocolFailure();
                }

                break;

            default:
                throw ProtocolFailure();
        }
    }

    private void ValidateInspect(RamInstallJob job)
    {
        if (!string.Equals(job.Action, InspectAction, StringComparison.Ordinal) ||
            job.State != RamInstallJobState.Succeeded ||
            job.ExitCode != 0 ||
            job.Pid is not null ||
            job.PidStartTicks is not null ||
            job.HasError ||
            job.Result is not { } result ||
            result.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        RequireInspectString(result, "model", RamInstallRequest.ModelCode);
        RequireInspectString(result, "socSerial", _request.ExpectedSocSerial);
        RequireInspectString(result, "device", RamInstallRequest.DevicePath);

        if (!result.TryGetProperty("bootId", out JsonElement bootIdElement) ||
            bootIdElement.ValueKind != JsonValueKind.String)
        {
            throw ProtocolFailure();
        }

        string bootId;
        try
        {
            bootId = RamInstallValidation.NormalizeUuid(bootIdElement.GetString(), "bootId");
        }
        catch (ArgumentException)
        {
            throw ProtocolFailure();
        }

        if (!string.Equals(bootId, _request.ExpectedBootId, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        if (!result.TryGetProperty("sectorSize", out JsonElement sectorElement) ||
            sectorElement.ValueKind != JsonValueKind.Number ||
            !sectorElement.TryGetInt32(out var sectorSize) ||
            sectorSize != _request.ExpectedTable.SectorSize)
        {
            throw ProtocolFailure();
        }

        if (!result.TryGetProperty("diskBytes", out JsonElement diskElement) ||
            diskElement.ValueKind != JsonValueKind.Number ||
            !diskElement.TryGetInt64(out var diskBytes) ||
            diskBytes != _request.ExpectedTable.DiskBytes)
        {
            throw ProtocolFailure();
        }

        if (!result.TryGetProperty("diskGuid", out JsonElement diskGuidElement) ||
            diskGuidElement.ValueKind != JsonValueKind.String)
        {
            throw ProtocolFailure();
        }

        string diskGuid;
        try
        {
            diskGuid = RamInstallValidation.NormalizeUuid(diskGuidElement.GetString(), "diskGuid");
        }
        catch (ArgumentException)
        {
            throw ProtocolFailure();
        }

        if (!string.Equals(diskGuid, _request.ExpectedTable.DiskGuid, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        if (!result.TryGetProperty("linuxTableFingerprint", out JsonElement fingerprintElement) ||
            fingerprintElement.ValueKind != JsonValueKind.String ||
            !RamInstallValidation.IsLowerSha256(fingerprintElement.GetString()))
        {
            throw ProtocolFailure();
        }

        if (!result.TryGetProperty("partitions", out JsonElement partitionsElement) ||
            partitionsElement.ValueKind != JsonValueKind.Array)
        {
            throw ProtocolFailure();
        }

        var expected = new Dictionary<long, ExpectedPartition>();
        foreach (var partition in _request.ExpectedTable.Partitions)
        {
            expected.Add(partition.Number, partition);
        }

        var actual = new Dictionary<long, JsonElement>();
        foreach (var element in partitionsElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object ||
                !element.TryGetProperty("number", out JsonElement numberElement) ||
                numberElement.ValueKind != JsonValueKind.Number ||
                !numberElement.TryGetInt64(out var number) ||
                !actual.TryAdd(number, element))
            {
                throw ProtocolFailure();
            }
        }

        if (actual.Count != expected.Count)
        {
            throw ProtocolFailure();
        }

        foreach (var pair in expected)
        {
            if (!actual.TryGetValue(pair.Key, out JsonElement element) ||
                !HasPartitionString(element, "name", pair.Value.Name) ||
                !HasPartitionLong(element, "startSector", pair.Value.StartSector) ||
                !HasPartitionLong(element, "sectorCount", pair.Value.SectorCount) ||
                !HasPartitionUuid(element, "typeGuid", pair.Value.TypeGuid) ||
                !HasPartitionUuid(element, "partUuid", pair.Value.PartUuid))
            {
                throw ProtocolFailure();
            }
        }

        // The base nine-field inspect stays exact for every request. Only a request that carries the
        // optional boot block additionally requires the read-only source catalog, which is validated
        // before the client can become initialized.
        if (_request.Boot is not null)
        {
            if (!result.TryGetProperty(CatalogProperty, out JsonElement catalog) ||
                catalog.ValueKind != JsonValueKind.Object)
            {
                throw ProtocolFailure();
            }

            ValidateBootSourceCatalog(result, catalog);
        }
    }

    private static bool HasPartitionString(JsonElement element, string name, string expected)
    {
        return element.TryGetProperty(name, out JsonElement value) &&
            value.ValueKind == JsonValueKind.String &&
            string.Equals(value.GetString(), expected, StringComparison.Ordinal);
    }

    private static bool HasPartitionLong(JsonElement element, string name, long expected)
    {
        return element.TryGetProperty(name, out JsonElement value) &&
            value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt64(out var actual) &&
            actual == expected;
    }

    private static bool HasPartitionUuid(JsonElement element, string name, string expected)
    {
        if (!element.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        try
        {
            return string.Equals(
                RamInstallValidation.NormalizeUuid(value.GetString(), name),
                expected,
                StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void RequireInspectString(JsonElement result, string name, string expected)
    {
        if (!result.TryGetProperty(name, out JsonElement element) ||
            element.ValueKind != JsonValueKind.String ||
            !string.Equals(element.GetString(), expected, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }
    }

    private static string RequireString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement element) ||
            element.ValueKind != JsonValueKind.String ||
            string.IsNullOrEmpty(element.GetString()))
        {
            throw ProtocolFailure();
        }

        return element.GetString()!;
    }

    private static RamInstallJobState ParseState(string value) => value switch
    {
        "not-started" => RamInstallJobState.NotStarted,
        "running" => RamInstallJobState.Running,
        "succeeded" => RamInstallJobState.Succeeded,
        "failed" => RamInstallJobState.Failed,
        "interrupted" => RamInstallJobState.Interrupted,
        _ => throw ProtocolFailure(),
    };

    private static long? ParsePid(JsonElement root)
    {
        JsonElement element = root.GetProperty("pid");
        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.Number ||
            !element.TryGetInt64(out var pid) ||
            pid <= 1 ||
            pid > int.MaxValue)
        {
            throw ProtocolFailure();
        }

        return pid;
    }

    private static string? ParsePidStartTicks(JsonElement root)
    {
        JsonElement element = root.GetProperty("pidStartTicks");
        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            throw ProtocolFailure();
        }

        string value = element.GetString()!;
        if (value.Length == 0 || value.Length > 20 || value[0] < '1' || value[0] > '9')
        {
            throw ProtocolFailure();
        }

        foreach (var character in value)
        {
            if (character < '0' || character > '9')
            {
                throw ProtocolFailure();
            }
        }

        return value;
    }

    private static int? ParseExitCode(JsonElement root)
    {
        JsonElement element = root.GetProperty("exitCode");
        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out var exitCode))
        {
            throw ProtocolFailure();
        }

        return exitCode;
    }

    private static string? ParseError(JsonElement root)
    {
        JsonElement element = root.GetProperty("error");
        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            throw ProtocolFailure();
        }

        string value = element.GetString()!;
        if (value.Length == 0)
        {
            throw ProtocolFailure();
        }

        return value;
    }

    private static JsonElement? ParseResult(JsonElement root)
    {
        JsonElement element = root.GetProperty("result");
        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        return element.Clone();
    }

    private static bool HasExactProperties(JsonElement root, HashSet<string> names)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name) || !names.Contains(property.Name))
            {
                return false;
            }
        }

        return seen.Count == names.Count;
    }

    private static void RequireFinalMarker(List<string> lines)
    {
        if (lines.Count == 0 ||
            !string.Equals(lines[^1], CommandMarker, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        var matches = 0;
        foreach (var line in lines)
        {
            if (string.Equals(line, CommandMarker, StringComparison.Ordinal))
            {
                matches++;
            }
        }

        if (matches != 1)
        {
            throw ProtocolFailure();
        }
    }

    private static List<string> SplitLines(string transcript)
    {
        var normalized = transcript.Replace("\r\n", "\n", StringComparison.Ordinal);
        var lines = new List<string>(normalized.Split('\n'));
        while (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        return lines;
    }

    private static string NormalizeSocSerial(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException("A device SoC serial is required.", nameof(value));
        }

        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ParseHexSocSerial(value[2..]);
        }

        if (RamInstallValidation.IsDecimalDigits(value) &&
            ulong.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var decimalSerial) &&
            decimalSerial > 0)
        {
            return decimalSerial.ToString(CultureInfo.InvariantCulture);
        }

        return ParseHexSocSerial(value);
    }

    private static string ParseHexSocSerial(string value)
    {
        if (value.Length == 0 || value.Length > 16)
        {
            throw new ArgumentException("A device SoC serial is required.", nameof(value));
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                throw new ArgumentException("A device SoC serial is required.", nameof(value));
            }
        }

        if (!ulong.TryParse(
                value,
                NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture,
                out var serial) ||
            serial == 0)
        {
            throw new ArgumentException("A device SoC serial is required.", nameof(value));
        }

        return serial.ToString(CultureInfo.InvariantCulture);
    }

    private static string Literal(RamInstallAction action) => action switch
    {
        RamInstallAction.Prepare => PrepareLiteral,
        RamInstallAction.ReceiveSeed => ReceiveSeedLiteral,
        RamInstallAction.Deploy => DeployLiteral,
        RamInstallAction.ReceiveOriginalBootA => ReceiveOriginalBootALiteral,
        RamInstallAction.ReceiveRuntime => ReceiveRuntimeLiteral,
        RamInstallAction.BuildBoots => BuildBootsLiteral,
        RamInstallAction.ExportBootA => ExportBootALiteral,
        RamInstallAction.ExportBootB => ExportBootBLiteral,
        RamInstallAction.ExportReportA => ExportReportALiteral,
        RamInstallAction.ExportReportB => ExportReportBLiteral,
        RamInstallAction.Finish => FinishLiteral,
        _ => throw new ArgumentOutOfRangeException(
            nameof(action),
            action,
            "Unknown RAM install action."),
    };

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > uint.MaxValue - 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                timeout,
                "The timeout must be a positive finite duration.");
        }
    }

    private static InvalidOperationException AlreadyInvoked(string literal) =>
        new("The " + literal
            + " action has already been invoked in this session; it is never restarted. "
            + "Use GetStatusAsync to observe it.");

    private static TimeoutException TimeoutFailure(string literal) =>
        new("The " + literal + " job did not reach its required state within the allotted time.");

    private static MaintenanceException ProtocolFailure() =>
        new(MaintenanceErrorCode.HandshakeMismatch, ProtocolMessage);

    private static MaintenanceException SessionFailure() =>
        new(MaintenanceErrorCode.UnsafeEnvironment, SessionMessage);
}
