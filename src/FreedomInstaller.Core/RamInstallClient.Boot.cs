using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The BOOT-WIRE-v2 part of <see cref="RamInstallClient"/>: the two fixed material uploads and the
/// single build trigger. Export and finish stay unimplemented until RH004; only their read-only status
/// and literal mapping exist here.
/// </summary>
public sealed partial class RamInstallClient
{
    private const string ReceiveOriginalBootALiteral = "receive-original-boot-a";
    private const string ReceiveRuntimeLiteral = "receive-runtime";
    private const string BuildBootsLiteral = "build-boots";
    private const string ExportBootALiteral = "export-boot-a";
    private const string ExportBootBLiteral = "export-boot-b";
    private const string ExportReportALiteral = "export-report-a";
    private const string ExportReportBLiteral = "export-report-b";
    private const string FinishLiteral = "finish";

    private const string MaterialRoleOriginalBootA = "original-boot-a";
    private const string MaterialRoleRuntime = "runtime";
    private const int MaterialChunkBytes = 128 * 1024;

    /// <summary>Closed set of literals that are only valid when the request carries the boot block.</summary>
    private static readonly HashSet<string> BootLiterals = new(StringComparer.Ordinal)
    {
        ReceiveOriginalBootALiteral,
        ReceiveRuntimeLiteral,
        BuildBootsLiteral,
        ExportBootALiteral,
        ExportBootBLiteral,
        ExportReportALiteral,
        ExportReportBLiteral,
        FinishLiteral,
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
        Task>? _materialSender;

    private bool _receiveOriginalBootAStarted;
    private bool _receiveRuntimeStarted;
    private bool _buildBootsStarted;

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
            Task>? materialSender)
        : this(session, request, seedSender)
    {
        _materialSender = materialSender;
    }

    /// <summary>
    /// Uploads the original boot A material exactly once. The held file is verified against the frozen
    /// request metadata before any mutating command, then streamed over one connection after the helper
    /// publishes the exact role readiness.
    /// </summary>
    public Task<RamInstallJob> ReceiveOriginalBootAAsync(
        VerifiedEdlFile source,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        RamInstallBootConfig boot = RequireBootConfiguration();
        return ReceiveMaterialAsync(
            RamInstallAction.ReceiveOriginalBootA,
            ReceiveOriginalBootALiteral,
            MaterialRoleOriginalBootA,
            new RamInstallFileIdentity(boot.Slots.A.CurrentBoot.Length, boot.Slots.A.CurrentBoot.Sha256),
            source,
            progress,
            timeout,
            cancellationToken);
    }

    /// <summary>Uploads the selected runtime material exactly once.</summary>
    public Task<RamInstallJob> ReceiveRuntimeAsync(
        VerifiedEdlFile source,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        RamInstallBootConfig boot = RequireBootConfiguration();
        return ReceiveMaterialAsync(
            RamInstallAction.ReceiveRuntime,
            ReceiveRuntimeLiteral,
            MaterialRoleRuntime,
            boot.Runtime,
            source,
            progress,
            timeout,
            cancellationToken);
    }

    /// <summary>
    /// Starts the single build-boots job after a real deploy and both exact material jobs succeeded. The
    /// build result is not interpreted here; the caller observes it with the read-only status.
    /// </summary>
    public async Task<RamInstallJob> StartBuildBootsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RamInstallBootConfig boot = RequireBootConfiguration();

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();

            if (_buildBootsStarted)
            {
                throw AlreadyInvoked(BuildBootsLiteral);
            }

            await RequireSucceededAsync(DeployLiteral, cancellationToken).ConfigureAwait(false);
            await RequireMaterialSucceededAsync(
                    ReceiveOriginalBootALiteral,
                    MaterialRoleOriginalBootA,
                    new RamInstallFileIdentity(boot.Slots.A.CurrentBoot.Length, boot.Slots.A.CurrentBoot.Sha256),
                    cancellationToken)
                .ConfigureAwait(false);
            await RequireMaterialSucceededAsync(
                    ReceiveRuntimeLiteral,
                    MaterialRoleRuntime,
                    boot.Runtime,
                    cancellationToken)
                .ConfigureAwait(false);

            _buildBootsStarted = true;
            return await RunActionAsync(BuildBootsLiteral, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    private async Task<RamInstallJob> ReceiveMaterialAsync(
        RamInstallAction action,
        string literal,
        string role,
        RamInstallFileIdentity expected,
        VerifiedEdlFile source,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireBootConfiguration();
        ValidateTimeout(timeout);
        ArgumentNullException.ThrowIfNull(source);
        ValidateClaim(source, expected);

        await _mutatingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequireInitialized();
            RequireMaterialNotStarted(action);
            await RequireSucceededAsync(DeployLiteral, cancellationToken).ConfigureAwait(false);

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            CancellationToken token = timeoutSource.Token;
            var stopwatch = Stopwatch.StartNew();

            try
            {
                // One read-only handle for the whole operation: verification, the start command, the
                // readiness poll, the streamed upload and the authoritative status.
                using var content = new FileStream(source.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                await VerifyMaterialFileAsync(content, expected, token).ConfigureAwait(false);
                RequireBudget(stopwatch, timeout, literal);

                // The single-use action is reserved only now, immediately before the mutating
                // command: a missing, invalid or mismatched local file must not burn it. Once the
                // command is attempted the reservation stands even if it fails.
                ReserveMaterial(action);

                await RunActionAsync(literal, token).ConfigureAwait(false);
                await WaitForMaterialListenerAsync(literal, role, stopwatch, timeout, timeoutSource, cancellationToken)
                    .ConfigureAwait(false);

                TimeSpan remaining = timeout - stopwatch.Elapsed;
                if (remaining <= TimeSpan.Zero)
                {
                    throw TimeoutFailure(literal);
                }

                await SendMaterialAsync(content, role, expected, progress, remaining, token)
                    .ConfigureAwait(false);

                return await WaitForMaterialResultAsync(
                        literal,
                        role,
                        expected,
                        stopwatch,
                        timeout,
                        timeoutSource,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw TimeoutFailure(literal);
            }
        }
        finally
        {
            _mutatingGate.Release();
        }
    }

    private Task SendMaterialAsync(
        Stream content,
        string role,
        RamInstallFileIdentity expected,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (content.CanSeek)
        {
            content.Position = 0;
        }

        Func<
            Stream,
            string,
            long,
            string,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task>? sender = _materialSender;

        if (sender is not null)
        {
            return sender(content, role, expected.Length, expected.Sha256, _token, progress, timeout, cancellationToken);
        }

        return new TcpInstallSeedTransfer().SendMaterialAsync(
            content,
            role,
            expected.Length,
            expected.Sha256,
            _token,
            progress,
            timeout,
            cancellationToken);
    }

    private async Task WaitForMaterialListenerAsync(
        string literal,
        string role,
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
                RamInstallJob status = await GetStatusInternalAsync(literal, token).ConfigureAwait(false);

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        throw new MaintenanceException(
                            MaintenanceErrorCode.HandshakeMismatch,
                            "The " + literal + " job already succeeded without this material transfer.");
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
                    case RamInstallJobState.Running:
                        if (IsMaterialReady(status, role))
                        {
                            return;
                        }

                        break;
                }

                if (stopwatch.Elapsed >= timeout)
                {
                    throw TimeoutFailure(literal);
                }

                await DelayPollAsync(token, timeoutSource, callerToken, literal).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            throw TimeoutFailure(literal);
        }
    }

    private async Task<RamInstallJob> WaitForMaterialResultAsync(
        string literal,
        string role,
        RamInstallFileIdentity expected,
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
                RamInstallJob status = await GetStatusInternalAsync(literal, token).ConfigureAwait(false);

                switch (status.State)
                {
                    case RamInstallJobState.Succeeded:
                        ValidateMaterialResult(status, role, expected);
                        return status;
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

                await DelayPollAsync(token, timeoutSource, callerToken, literal).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !callerToken.IsCancellationRequested)
        {
            throw TimeoutFailure(literal);
        }
    }

    private async Task RequireMaterialSucceededAsync(
        string literal,
        string role,
        RamInstallFileIdentity expected,
        CancellationToken cancellationToken)
    {
        RamInstallJob status = await GetStatusInternalAsync(literal, cancellationToken).ConfigureAwait(false);

        if (status.State != RamInstallJobState.Succeeded || status.ExitCode != 0)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.HandshakeMismatch,
                "The " + literal + " job has not succeeded.");
        }

        ValidateMaterialResult(status, role, expected);
    }

    private static void ValidateMaterialResult(
        RamInstallJob job,
        string role,
        RamInstallFileIdentity expected)
    {
        if (job.Result is not { } result || result.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in result.EnumerateObject())
        {
            if (!seen.Add(property.Name) ||
                (property.Name != "role" && property.Name != "length" && property.Name != "sha256"))
            {
                throw ProtocolFailure();
            }
        }

        if (seen.Count != 3 ||
            !result.TryGetProperty("role", out JsonElement roleElement) ||
            roleElement.ValueKind != JsonValueKind.String ||
            !string.Equals(roleElement.GetString(), role, StringComparison.Ordinal) ||
            !result.TryGetProperty("length", out JsonElement lengthElement) ||
            lengthElement.ValueKind != JsonValueKind.Number ||
            !lengthElement.TryGetInt64(out long length) ||
            length != expected.Length ||
            !result.TryGetProperty("sha256", out JsonElement shaElement) ||
            shaElement.ValueKind != JsonValueKind.String ||
            !string.Equals(shaElement.GetString(), expected.Sha256, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }
    }

    private static bool IsMaterialReady(RamInstallJob job, string role)
    {
        if (job.Result is not { } result || result.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (result.TryGetProperty("role", out JsonElement roleElement))
        {
            if (roleElement.ValueKind != JsonValueKind.String ||
                !string.Equals(roleElement.GetString(), role, StringComparison.Ordinal))
            {
                // A readiness record advertising another role must never authorize a connection.
                throw ProtocolFailure();
            }
        }

        if (!result.TryGetProperty("ready", out JsonElement ready) ||
            ready.ValueKind != JsonValueKind.True)
        {
            return false;
        }

        if (!result.TryGetProperty("role", out _))
        {
            throw ProtocolFailure();
        }

        return true;
    }

    private static void ValidateClaim(VerifiedEdlFile source, RamInstallFileIdentity expected)
    {
        if (string.IsNullOrWhiteSpace(source.Path))
        {
            throw new ArgumentException("A non-blank verified material path is required.", nameof(source));
        }

        if (source.Length != expected.Length)
        {
            throw new InvalidDataException(
                "The verified material length does not match the frozen boot metadata.");
        }

        if (!IsHexSha256(source.Sha256) ||
            !string.Equals(source.Sha256, expected.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The verified material digest does not match the frozen boot metadata.");
        }
    }

    private static bool IsHexSha256(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static async Task VerifyMaterialFileAsync(
        FileStream content,
        RamInstallFileIdentity expected,
        CancellationToken cancellationToken)
    {
        if (content.Length != expected.Length)
        {
            throw new InvalidDataException(
                "The material file length does not match the frozen boot metadata.");
        }

        var buffer = ArrayPool<byte>.Shared.Rent(MaterialChunkBytes);
        try
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;

            while (true)
            {
                int read = await content
                    .ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);

                if (read <= 0)
                {
                    break;
                }

                total += read;
                if (total > expected.Length)
                {
                    break;
                }

                hasher.AppendData(buffer, 0, read);
            }

            if (total != expected.Length)
            {
                throw new InvalidDataException(
                    "The material file ended before or past its frozen length.");
            }

            string actual = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actual),
                    Convert.FromHexString(expected.Sha256)))
            {
                throw new InvalidDataException(
                    "The material file digest does not match the frozen boot metadata.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            content.Position = 0;
        }
    }

    private static void RequireBudget(Stopwatch stopwatch, TimeSpan timeout, string literal)
    {
        if (stopwatch.Elapsed >= timeout)
        {
            throw TimeoutFailure(literal);
        }
    }

    private RamInstallBootConfig RequireBootConfiguration()
    {
        RamInstallBootConfig? boot = _request.Boot;
        if (boot is null)
        {
            throw new InvalidOperationException(
                "The install request was built without the optional boot block; the boot actions are unavailable.");
        }

        return boot;
    }

    private void RequireBootForLiteral(string literal)
    {
        if (BootLiterals.Contains(literal))
        {
            _ = RequireBootConfiguration();
        }
    }

    private void RequireMaterialNotStarted(RamInstallAction action)
    {
        bool started = action switch
        {
            RamInstallAction.ReceiveOriginalBootA => _receiveOriginalBootAStarted,
            RamInstallAction.ReceiveRuntime => _receiveRuntimeStarted,
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unknown material action."),
        };

        if (started)
        {
            throw AlreadyInvoked(
                action == RamInstallAction.ReceiveOriginalBootA
                    ? ReceiveOriginalBootALiteral
                    : ReceiveRuntimeLiteral);
        }
    }

    private void ReserveMaterial(RamInstallAction action)
    {
        switch (action)
        {
            case RamInstallAction.ReceiveOriginalBootA:
                _receiveOriginalBootAStarted = true;
                break;
            case RamInstallAction.ReceiveRuntime:
                _receiveRuntimeStarted = true;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(action), action, "Unknown material action.");
        }
    }
}
