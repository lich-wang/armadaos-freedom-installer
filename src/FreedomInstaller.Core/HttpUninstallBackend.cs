using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Transport and session identity of the maintenance service that runs inside the verified RAM tool
/// environment on the device (HTTP v1 contract, <c>linux-runtime/API-v1.md</c>).
/// <para>
/// <see cref="BearerToken"/> is the shared secret of exactly one Linux boot. It must never be printed,
/// logged, hashed into a user-visible string or copied into an exception message, so
/// <see cref="ToString"/> renders a placeholder instead of the value.
/// </para>
/// </summary>
public sealed record HttpUninstallConnection(Uri BaseAddress, string BearerToken, string BootId)
{
    private const string RedactedToken = "<redacted>";

    /// <summary>Redacted rendering: the bearer token is never part of the text.</summary>
    public override string ToString()
        => $"HttpUninstallConnection {{ BaseAddress = {BaseAddress}, BearerToken = {RedactedToken}, BootId = {BootId} }}";
}

/// <summary>
/// The one physical unit this transaction is bound to: the identity the user confirmed, the SoC serial the
/// inspect endpoint must report, the serial the same unit shows in fastboot, and the OTA state that has to
/// be <see cref="OtaUpdateState.Completed"/> before an uninstall may start.
/// </summary>
public sealed record UninstallDeviceBinding(
    DeviceIdentity Identity,
    string AndroidSocSerial,
    string FastbootSerial,
    OtaUpdateState OtaState);

/// <summary>
/// The five restore assets the runtime expects, named by their local file paths. The paths are read by the
/// host and streamed to <c>PUT /v1/assets/{role}</c>; they are never interpreted as server paths.
/// </summary>
public sealed record UninstallRestoreAssets(
    string StockBootAPath,
    string StockBootBPath,
    string OriginalPrimaryGptPath,
    string OriginalBackupGptPath,
    string TrustedVbmetaBaselinePath);

/// <summary>
/// One boot slot as proven by the runtime's prepare validator: the slot's own signed firmware fingerprint,
/// the digest of the full stock image the host uploaded, both AVB key digests and whether hardware
/// anti-rollback was actually verified. <see cref="HardwareRollbackVerified"/> is never filled in by the host.
/// </summary>
public sealed record UninstallStockSlotEvidence(
    string Slot,
    string Fingerprint,
    string Sha256,
    string RootKeySha256,
    string BootKeySha256,
    bool HardwareRollbackVerified);

/// <summary>
/// Server-side state of one transaction as returned by prepare and status. It carries no bearer token and no
/// long-lived write credential: the confirmation token stays private to the backend.
/// <para>
/// <see cref="ActiveStep"/> and <see cref="CompletedSteps"/> mirror the runtime's required status fields. The
/// parser requires both on every response; a missing array is never read as "nothing completed".
/// </para>
/// </summary>
public sealed record UninstallTransactionStatus(
    string TransactionId,
    string BootId,
    string State,
    string Stage,
    string? NextStep,
    string PlanFingerprint,
    bool BackupAcknowledged,
    string? Error)
{
    /// <summary>Step the runtime is executing right now, or null when no job is running.</summary>
    public string? ActiveStep { get; init; }

    /// <summary>Steps the runtime reports as completed. Empty by contract, never inferred from a gap.</summary>
    public IReadOnlyList<string> CompletedSteps { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Raised when a transaction request may have reached the runtime but its outcome is unknown (timeout,
/// connection loss, unreadable status). The caller must query the transaction status instead of retrying a
/// step: <see cref="TransactionId"/> and <see cref="Step"/> name exactly what has to be re-read.
/// <para>
/// The message never contains the bearer token, the confirmation token or any other secret.
/// </para>
/// </summary>
public sealed class UninstallTransactionUncertainException : System.IO.IOException
{
    /// <summary>Creates the failure with a fixed, secret-free message.</summary>
    public UninstallTransactionUncertainException(string transactionId, string step)
        : this(
            transactionId,
            step,
            $"The outcome of step '{step}' in transaction '{transactionId}' is unknown; query the transaction status before doing anything else.")
    {
    }

    /// <summary>Creates the failure with an explicit, secret-free message.</summary>
    public UninstallTransactionUncertainException(string transactionId, string step, string message)
        : base(message)
    {
        TransactionId = transactionId;
        Step = step;
    }

    /// <summary>Creates the failure with an explicit message and the transport exception that caused it.</summary>
    public UninstallTransactionUncertainException(
        string transactionId, string step, string message, Exception innerException)
        : base(message, innerException)
    {
        TransactionId = transactionId;
        Step = step;
    }

    /// <summary>Transaction whose state is unknown. Never empty when the failure came from a real request.</summary>
    public string TransactionId { get; }

    /// <summary>Step that was in flight when the outcome became unknown.</summary>
    public string Step { get; }
}

/// <summary>
/// Host side of the maintenance HTTP v1 contract: it drives the read-only prepare, then the enumerated
/// write steps of one transaction against the runtime running in the verified RAM tool environment.
/// <para>
/// This type is deliberately not a workflow. Ordering, cancellation and the acceptance boundary stay in
/// <see cref="UninstallWorkflow"/>; this backend only translates the <see cref="IUninstallBackend"/> calls
/// into HTTP requests and refuses to interpret server evidence as something it did not prove.
/// </para>
/// <para>
/// It can only be reached through <see cref="CreatePreparedAsync"/>, which insists on the one USB address,
/// a well formed boot session and a device binding that still names the confirmed unit. Stock validity and
/// the restore plan are taken from the runtime response only after they match the locally validated inputs;
/// nothing is recomputed here and no expected fingerprint is ever supplied to the server.
/// </para>
/// <para>
/// Current state: inspect, restore-input validation, read-only prepare, transaction status, the durable host
/// backup with its acknowledgement and the six fixed write steps are implemented. Every step is journaled
/// locally before its single POST and is only reported as done when the same transaction status proves it.
/// <see cref="VerifyAndroidAsync"/> always refuses because Android acceptance is not part of this transport.
/// </para>
/// </summary>
public sealed class HttpUninstallBackend : IUninstallBackend
{
    /// <summary>The only address the runtime may be bound to: the USB network of the maintenance boot.</summary>
    private const string UsbHostAddress = "192.168.77.1";

    private const int UsbHostPort = 8202;

    private const string UsbBaseUrl = "http://192.168.77.1:8202/";

    /// <summary>32 random bytes rendered as 64 ASCII hexadecimal characters, per the server contract.</summary>
    private const int BearerTokenHexLength = 64;

    private const int HexSha256Length = 64;

    private const long GptFragmentLimit = 16L * 1024 * 1024;

    private const long TrustedVbmetaLimit = 1L * 1024 * 1024;

    private const string RestoreBootAStep = "restore-boot-a";

    private const string VerifyBootAStep = "verify-boot-a";

    private const string RestoreBootBStep = "restore-boot-b";

    private const string VerifyBootBStep = "verify-boot-b";

    private const string ReclaimSpaceStep = "reclaim-space";

    private const string QueueFactoryResetStep = "queue-factory-reset";

    /// <summary>The only six write steps of one transaction, in the only order the runtime accepts.</summary>
    private static readonly string[] FixedSteps =
    {
        RestoreBootAStep,
        VerifyBootAStep,
        RestoreBootBStep,
        VerifyBootBStep,
        ReclaimSpaceStep,
        QueueFactoryResetStep,
    };

    private static readonly TimeSpan StepPollInterval = TimeSpan.FromSeconds(1);

    private static readonly TimeSpan StepPollTimeout = TimeSpan.FromMinutes(10);

    private static readonly TimeSpan MetadataTimeout = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan FileTransferTimeout = TimeSpan.FromMinutes(10);

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 64,
    };

    private static readonly string[] TransactionStates =
    {
        "prepared",
        "running",
        "failed",
        "awaitingFactoryReset",
    };

    private readonly HttpClient _http;
    private readonly HttpUninstallConnection _connection;
    private readonly ValidatedUninstallInputs _inputs;
    private readonly UninstallDeviceBinding _binding;
    private readonly string _stockFingerprint;
    private readonly string _confirmationToken;
    private readonly IReadOnlyList<UninstallStockSlotEvidence> _preparedStockSlots;
    private readonly InspectEvidence _factoryInspect;
    private readonly List<HostBackupEntry> _hostBackupEntries = new(3);

    /// <summary>Serializes the host backup and its acknowledgement; the next step ticket reuses this gate.</summary>
    private readonly SemaphoreSlim _hostBackupGate = new(1, 1);

    private bool _hostBackupComplete;
    private bool _ackSubmitted;

    /// <summary>
    /// Steps this instance has already persisted as pending and put on the wire. A repeated call must poll
    /// this transaction's status instead of sending the step a second time.
    /// </summary>
    private readonly HashSet<string> _submittedSteps = new(StringComparer.Ordinal);

    /// <summary>Step whose submission is persisted but not yet proven, or null when nothing is pending.</summary>
    private string? _pendingStep;

    /// <summary>Stage last written into the local journal, so a failure keeps the runtime's real stage.</summary>
    private string _journalStage = "Prepared";

    private HttpUninstallBackend(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        UninstallSnapshot snapshot,
        string planFingerprint,
        string transactionId,
        string backupDirectory,
        string stockFingerprint,
        string confirmationToken,
        IReadOnlyList<UninstallStockSlotEvidence> preparedStockSlots,
        InspectEvidence factoryInspect)
    {
        _http = http;
        _connection = connection;
        _inputs = inputs;
        _binding = binding;
        _stockFingerprint = stockFingerprint;
        _confirmationToken = confirmationToken;
        _factoryInspect = factoryInspect;

        if (string.IsNullOrWhiteSpace(_confirmationToken))
        {
            throw new InvalidDataException("The prepared transaction carries no confirmation token.");
        }

        _preparedStockSlots = preparedStockSlots;

        Snapshot = snapshot;
        PlanFingerprint = planFingerprint;
        TransactionId = transactionId;
        BackupDirectory = backupDirectory;
    }

    /// <summary>
    /// Snapshot the transaction was confirmed against: the confirmed identity plus the table, current-boot,
    /// stock and installation-record fingerprints the runtime reported and the host independently checked.
    /// </summary>
    public UninstallSnapshot Snapshot { get; }

    /// <summary>Plan fingerprint the runtime derived from the current GPT and returned with the prepared state.</summary>
    public string PlanFingerprint { get; }

    /// <summary>Transaction id sent to the runtime once and retained across retries.</summary>
    public string TransactionId { get; }

    /// <summary>Directory the host saved the current boot and misc snapshots into before any write.</summary>
    public string BackupDirectory { get; }

    /// <summary>
    /// Both stock slots exactly as the runtime's prepare validator proved them. The list is immutable and is
    /// never derived from inspect, which cannot prove stock validity.
    /// </summary>
    public IReadOnlyList<UninstallStockSlotEvidence> PreparedStockSlots => _preparedStockSlots;

    /// <summary>
    /// Uploads the five restore assets, prepares the read-only transaction and returns a backend bound to its
    /// prepared state. Every local argument is checked before the first request: a non-USB address, a malformed
    /// token or boot id, and a fastboot serial that is not the confirmed unit are all refused without any I/O.
    /// </summary>
    /// <exception cref="ArgumentNullException">A required reference is missing.</exception>
    /// <exception cref="ArgumentException">
    /// The base address is not the USB maintenance address, the bearer token is not 64 hexadecimal characters,
    /// the boot id is not a UUID, the backup root is empty, the binding no longer names the confirmed unit, or
    /// an asset path is empty.
    /// </exception>
    /// <exception cref="InvalidDataException">The runtime's inspect or prepare evidence is not trustworthy.</exception>
    /// <exception cref="OperationCanceledException">The caller cancelled before the request was started.</exception>
    public static async Task<HttpUninstallBackend> CreatePreparedAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        UninstallRestoreAssets assets,
        string backupRoot,
        CancellationToken token = default)
    {
        ValidatePrepareArguments(http, connection, inputs, binding, assets, backupRoot);

        token.ThrowIfCancellationRequested();

        var inspect = await ReadInspectAsync(http, connection, inputs, binding, token).ConfigureAwait(false);
        var descriptors = await MeasureAssetsAsync(assets, inputs, token).ConfigureAwait(false);

        foreach (var descriptor in descriptors)
        {
            await UploadAssetAsync(http, connection, descriptor, token).ConfigureAwait(false);
        }

        var transactionId = Guid.NewGuid().ToString("D");

        PreparedEvidence prepared;
        try
        {
            prepared = await SendPrepareAsync(
                    http, connection, inputs, descriptors, transactionId, inspect, token)
                .ConfigureAwait(false);
        }
        catch (UninstallTransactionUncertainException)
        {
            // The prepare response was lost after the request may have reached the runtime. Only this
            // transaction's status may decide what happened, and never with a caller token that is already
            // cancelled: the id is retained so the caller can recover with a fresh read.
            if (token.IsCancellationRequested)
            {
                throw;
            }

            prepared = await ResolvePrepareByStatusAsync(
                    http, connection, inputs, descriptors, transactionId, token)
                .ConfigureAwait(false);
        }

        var snapshot = BuildSnapshot(
            inputs, inspect, prepared.StockFingerprint);
        var backupDirectory = Path.Combine(Path.GetFullPath(backupRoot), "uninstall-" + transactionId);

        return new HttpUninstallBackend(
            http,
            connection,
            inputs,
            binding,
            snapshot,
            prepared.PlanFingerprint,
            transactionId,
            backupDirectory,
            prepared.StockFingerprint,
            prepared.ConfirmationToken,
            prepared.Slots,
            inspect);
    }

    /// <summary>
    /// Re-attaches to the one existing prepared transaction named by <paramref name="transactionId"/> without
    /// creating, re-preparing or otherwise changing it. Recovery is read-only and same-id: the runtime status
    /// must name exactly this transaction and still be the untouched preparation the caller validated.
    /// </summary>
    /// <exception cref="ArgumentNullException">A required reference is missing.</exception>
    /// <exception cref="ArgumentException">A local argument, the binding or the transaction id is invalid.</exception>
    /// <exception cref="InvalidDataException">
    /// The inspect or transaction evidence is not the untouched prepared state, or the transaction has failed.
    /// </exception>
    /// <exception cref="HttpRequestException">
    /// The runtime refused the status read; a 404 keeps the pending transaction context visible to the caller.
    /// </exception>
    public static async Task<HttpUninstallBackend> RecoverPreparedAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        UninstallRestoreAssets assets,
        string backupRoot,
        string transactionId,
        CancellationToken token = default)
    {
        ValidatePrepareArguments(http, connection, inputs, binding, assets, backupRoot);

        if (string.IsNullOrWhiteSpace(transactionId)
            || !Guid.TryParse(transactionId, out var parsedTransactionId)
            || parsedTransactionId == Guid.Empty)
        {
            throw new ArgumentException(
                "The transaction id must be the non-zero UUID the host generated for the prepare request.",
                nameof(transactionId));
        }

        token.ThrowIfCancellationRequested();

        var inspect = await ReadInspectAsync(http, connection, inputs, binding, token).ConfigureAwait(false);
        var descriptors = await MeasureAssetsAsync(assets, inputs, token).ConfigureAwait(false);

        PreparedEvidence prepared;
        using (var document = await SendJsonAsync(
                http,
                connection,
                HttpMethod.Get,
                $"/v1/transactions/{transactionId}/status",
                content: null,
                MetadataTimeout,
                token)
            .ConfigureAwait(false))
        {
            RequireStatusIsNotFailed(document.RootElement);
            prepared = ReadPreparedResponse(
                document.RootElement, transactionId, connection, inputs, descriptors);
        }

        var snapshot = BuildSnapshot(inputs, inspect, prepared.StockFingerprint);
        var backupDirectory = Path.Combine(Path.GetFullPath(backupRoot), "uninstall-" + transactionId);

        return new HttpUninstallBackend(
            http,
            connection,
            inputs,
            binding,
            snapshot,
            prepared.PlanFingerprint,
            transactionId,
            backupDirectory,
            prepared.StockFingerprint,
            prepared.ConfirmationToken,
            prepared.Slots,
            inspect);
    }

    /// <summary>Re-reads the transaction state from the runtime. Read-only; it never replays a step.</summary>
    /// <exception cref="InvalidDataException">The status response is missing, malformed or names another transaction.</exception>
    public Task<UninstallTransactionStatus> RefreshTransactionAsync(CancellationToken token = default)
        => FetchStatusAsync(requireBackupAcknowledged: false, token);

    /// <summary>Reads the runtime's own view of the device. Never derived from the host's expectations.</summary>
    /// <exception cref="InvalidDataException">The inspect evidence is missing or contradicts the validated inputs.</exception>
    public async Task<UninstallSnapshot> InspectAsync(CancellationToken token)
    {
        var inspect = await ReadInspectAsync(_http, _connection, _inputs, _binding, token).ConfigureAwait(false);
        return BuildSnapshot(_inputs, inspect, _stockFingerprint);
    }

    /// <summary>
    /// Re-reads the prepared transaction and refuses a state that is no longer the untouched preparation the
    /// restore inputs were validated against. It is a status read only and never issues a step.
    /// </summary>
    /// <exception cref="InvalidDataException">The transaction moved away from its prepared state.</exception>
    public async Task ValidateRestoreInputsAsync(CancellationToken token)
    {
        var status = await FetchStatusAsync(requireBackupAcknowledged: false, token).ConfigureAwait(false);

        if (!string.Equals(status.State, "prepared", StringComparison.Ordinal)
            || status.Error is not null
            || status.ActiveStep is not null
            || status.CompletedSteps.Count != 0
            || !string.Equals(status.NextStep, RestoreBootAStep, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The runtime transaction is no longer the untouched prepared transaction.");
        }
    }

    /// <summary>
    /// Downloads the current boot_a, boot_b and misc images exactly as the prepared inspect described them,
    /// writes each of them durably into <see cref="BackupDirectory"/>, then creates the manifest and only after
    /// that acknowledges the backups. A repeated call never downloads or acknowledges a second time.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// The transaction moved away from its untouched prepared state, or the runtime no longer reports the same
    /// current boot and misc descriptors.
    /// </exception>
    /// <exception cref="IOException">
    /// A local backup file already exists, or the downloaded bytes do not match the retained descriptor.
    /// </exception>
    /// <exception cref="TimeoutException">A transfer did not finish within its bounded time.</exception>
    /// <exception cref="UninstallTransactionUncertainException">
    /// An acknowledgement was submitted but the runtime status cannot prove whether it was accepted.
    /// </exception>
    public async Task BackupCurrentBootAsync(CancellationToken token)
    {
        await _hostBackupGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();

            if (_hostBackupComplete)
            {
                await VerifyLocalHostBackupAsync(token).ConfigureAwait(false);
                var completed = await FetchStatusAsync(requireBackupAcknowledged: true, token).ConfigureAwait(false);
                RequireUntouchedPrepared(completed);
                return;
            }

            if (_ackSubmitted)
            {
                await VerifyLocalHostBackupAsync(token).ConfigureAwait(false);
                await ResolvePreviouslySubmittedAckAsync(token).ConfigureAwait(false);
                _hostBackupComplete = true;
                return;
            }

            var status = await FetchStatusAsync(requireBackupAcknowledged: false, token).ConfigureAwait(false);
            RequireUntouchedPrepared(status);

            var fresh = await ReadInspectAsync(_http, _connection, _inputs, _binding, token).ConfigureAwait(false);
            RequireFreshInspectMatchesFactory(fresh);

            Directory.CreateDirectory(BackupDirectory);
            if (Directory.GetFileSystemEntries(BackupDirectory).Length != 0)
            {
                throw new IOException(
                    $"The backup directory '{BackupDirectory}' already contains files from an earlier attempt; " +
                    "they are kept for diagnosis and are never overwritten.");
            }

            var entries = new List<HostBackupEntry>(3)
            {
                await DownloadBackupAsync(_factoryInspect.BootA, token).ConfigureAwait(false),
                await DownloadBackupAsync(_factoryInspect.BootB, token).ConfigureAwait(false),
                await DownloadBackupAsync(_factoryInspect.Misc, token).ConfigureAwait(false),
            };

            await VerifyLocalBackupFilesAsync(entries, token).ConfigureAwait(false);

            _hostBackupEntries.Clear();
            _hostBackupEntries.AddRange(entries);

            // No step has been submitted yet, so the journal must not claim one is pending merely because
            // restore-boot-a is the next step the runtime will accept.
            _journalStage = status.Stage;
            await WriteManifestAsync(
                    state: "host-backup-complete",
                    pendingStep: null,
                    completedSteps: Array.Empty<string>(),
                    overwrite: false,
                    token)
                .ConfigureAwait(false);

            await AcknowledgeBackupsAsync(token).ConfigureAwait(false);
            _hostBackupComplete = true;
        }
        finally
        {
            _hostBackupGate.Release();
        }
    }

    /// <summary>
    /// Rewrites the existing manifest with new journal state. It never creates a manifest: the first manifest
    /// is written by the backup itself, and a journal update only ever follows it.
    /// </summary>
    private Task UpdateManifestJournalAsync(
        string state, string? pendingStep, IReadOnlyList<string> completedSteps, CancellationToken token)
        => WriteManifestAsync(state, pendingStep, completedSteps, overwrite: true, token);

    private async Task<HostBackupEntry> DownloadBackupAsync(
        PartitionDescriptor descriptor, CancellationToken token)
    {
        var relativePath = "/v1/boot/" + BootEndpointRole(descriptor.Role);
        var expectedUri = new Uri(_connection.BaseAddress, relativePath);
        var partialPath = Path.Combine(BackupDirectory, descriptor.Role + ".img.partial");
        var finalPath = Path.Combine(BackupDirectory, descriptor.Role + ".img");

        using var request = new HttpRequestMessage(HttpMethod.Get, expectedUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _connection.BearerToken);
        request.Headers.ConnectionClose = true;

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeoutSource.CancelAfter(FileTransferTimeout);

        HttpResponseMessage response;
        try
        {
            response = await _http
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutSource.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"The runtime did not start {relativePath} within {FileTransferTimeout.TotalMinutes:0} minutes.");
        }

        using (response)
        {
            if (response.RequestMessage?.RequestUri is { } actualUri
                && !string.Equals(actualUri.AbsoluteUri, expectedUri.AbsoluteUri, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The runtime answered from {actualUri} instead of the requested {expectedUri}; redirects are refused.");
            }

            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new HttpRequestException(
                    $"The runtime answered GET {relativePath} with HTTP {(int)response.StatusCode}.",
                    null,
                    response.StatusCode);
            }

            if (response.Content is null)
            {
                throw new InvalidDataException($"The runtime answered GET {relativePath} without a body.");
            }

            var declaredBytes = response.Content.Headers.ContentLength;
            if (declaredBytes != descriptor.Bytes)
            {
                throw new InvalidDataException(
                    $"The runtime declared {(declaredBytes.HasValue ? declaredBytes.Value.ToString() : "no")} bytes " +
                    $"for {descriptor.Role} instead of the inspected {descriptor.Bytes}.");
            }

            var declaredSha = ReadSingleContentSha256(response);
            if (!string.Equals(declaredSha, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The runtime declared a different digest for {descriptor.Role} than the inspected one.");
            }

            Stream body;
            try
            {
                body = await response.Content.ReadAsStreamAsync(timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"The runtime did not start sending {descriptor.Role} " +
                    $"within {FileTransferTimeout.TotalMinutes:0} minutes.");
            }

            using (body)
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            using (var file = new FileStream(
                partialPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                81920,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                var buffer = new byte[81920];
                long total = 0;

                while (true)
                {
                    int read;
                    try
                    {
                        read = await body.ReadAsync(buffer.AsMemory(), timeoutSource.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        throw new TimeoutException(
                            $"The runtime did not finish sending {descriptor.Role} " +
                            $"within {FileTransferTimeout.TotalMinutes:0} minutes.");
                    }

                    if (read == 0)
                    {
                        break;
                    }

                    total += read;
                    if (total > descriptor.Bytes)
                    {
                        throw new IOException(
                            $"The runtime sent more than the inspected {descriptor.Bytes} bytes for {descriptor.Role}.");
                    }

                    hash.AppendData(buffer, 0, read);

                    try
                    {
                        await file.WriteAsync(buffer.AsMemory(0, read), timeoutSource.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        throw new TimeoutException(
                            $"Writing {descriptor.Role} did not finish within {FileTransferTimeout.TotalMinutes:0} minutes.");
                    }
                }

                if (total != descriptor.Bytes)
                {
                    throw new IOException(
                        $"The runtime ended {descriptor.Role} after {total} of {descriptor.Bytes} inspected bytes.");
                }

                var actualSha = ToHexLower(hash.GetHashAndReset());
                if (!string.Equals(actualSha, declaredSha, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(actualSha, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException(
                        $"The downloaded bytes for {descriptor.Role} do not match the inspected digest.");
                }

                try
                {
                    await file.FlushAsync(timeoutSource.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"Flushing {descriptor.Role} did not finish within {FileTransferTimeout.TotalMinutes:0} minutes.");
                }

                file.Flush(flushToDisk: true);
            }
        }

        var measurement = await MeasureFileAsync(
                partialPath, maximumBytes: 0, descriptor.Role + " backup", token)
            .ConfigureAwait(false);
        if (measurement.Bytes != descriptor.Bytes
            || !string.Equals(measurement.Sha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException(
                $"The written {descriptor.Role} backup does not match the inspected descriptor after reopening it.");
        }

        File.Move(partialPath, finalPath, overwrite: false);
        return new HostBackupEntry(descriptor.Role, descriptor.Role + ".img", descriptor.Bytes, descriptor.Sha256);
    }

    private async Task AcknowledgeBackupsAsync(CancellationToken token)
    {
        var backupPayloads = new object[_hostBackupEntries.Count];
        for (var index = 0; index < _hostBackupEntries.Count; index++)
        {
            var entry = _hostBackupEntries[index];
            backupPayloads[index] = new { role = entry.Role, bytes = entry.Bytes, sha256 = entry.Sha256 };
        }

        var body = JsonSerializer.Serialize(new
        {
            transactionId = TransactionId,
            bootId = _connection.BootId,
            socSerial = _factoryInspect.SocSerial,
            backups = backupPayloads,
        });

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body);

        // A cancellation before the acknowledgement is put on the wire is an ordinary cancellation; only
        // once it has been submitted does its outcome have to be treated as unknown.
        token.ThrowIfCancellationRequested();
        _ackSubmitted = true;
        try
        {
            using var document = await SendJsonAsync(
                    _http,
                    _connection,
                    HttpMethod.Post,
                    "/v1/ack-backups",
                    content,
                    MetadataTimeout,
                    token)
                .ConfigureAwait(false);

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !RequireBool(root, "acknowledged")
                || string.IsNullOrWhiteSpace(RequireNonEmptyString(root, "backupAckId")))
            {
                throw new InvalidDataException("The runtime did not prove that it accepted the host backups.");
            }
        }
        catch (HttpRequestException exception) when (IsClientRefusal(exception))
        {
            throw;
        }
        catch (HttpRequestException exception)
        {
            await ResolveSubmittedAckAsync(exception, token).ConfigureAwait(false);
            return;
        }
        catch (TimeoutException exception)
        {
            await ResolveSubmittedAckAsync(exception, token).ConfigureAwait(false);
            return;
        }
        catch (InvalidDataException exception)
        {
            await ResolveSubmittedAckAsync(exception, token).ConfigureAwait(false);
            return;
        }
        catch (IOException exception)
        {
            // A plain I/O failure while reading the ACK response body is the same lost reply: the request
            // was already submitted, so only this transaction's status may be read.
            await ResolveSubmittedAckAsync(exception, token).ConfigureAwait(false);
            return;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw SubmittedAckUncertain(null);
        }

        var status = await FetchStatusAsync(requireBackupAcknowledged: true, token).ConfigureAwait(false);
        RequireUntouchedPrepared(status);
    }

    /// <summary>
    /// An earlier call sent the acknowledgement but never proved its outcome. The local files are revalidated
    /// and only the same transaction status is read; no file is created or overwritten and no ACK is resent.
    /// </summary>
    private async Task ResolvePreviouslySubmittedAckAsync(CancellationToken token)
    {
        if (token.IsCancellationRequested)
        {
            throw SubmittedAckUncertain(null);
        }

        UninstallTransactionStatus status;
        try
        {
            status = await FetchStatusAsync(requireBackupAcknowledged: false, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw SubmittedAckUncertain(null);
        }
        catch (Exception exception) when (IsUnreadableStatus(exception))
        {
            throw SubmittedAckUncertain(exception);
        }

        if (!status.BackupAcknowledged)
        {
            throw new UninstallTransactionUncertainException(
                TransactionId,
                "ack-backups",
                "The host backups were already submitted but the runtime does not report them as acknowledged.");
        }

        RequireUntouchedPrepared(status);
    }

    private async Task ResolveSubmittedAckAsync(Exception cause, CancellationToken token)
    {
        if (token.IsCancellationRequested)
        {
            throw SubmittedAckUncertain(cause);
        }

        UninstallTransactionStatus status;
        try
        {
            status = await FetchStatusAsync(requireBackupAcknowledged: false, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw SubmittedAckUncertain(cause);
        }
        catch (Exception exception) when (IsUnreadableStatus(exception))
        {
            throw SubmittedAckUncertain(exception);
        }

        if (!status.BackupAcknowledged)
        {
            throw new UninstallTransactionUncertainException(
                TransactionId,
                "ack-backups",
                "The host backups were submitted but the runtime does not report them as acknowledged.",
                cause);
        }

        RequireUntouchedPrepared(status);
    }

    private UninstallTransactionUncertainException SubmittedAckUncertain(Exception? inner)
        => inner is null
            ? new UninstallTransactionUncertainException(
                TransactionId,
                "ack-backups",
                "The host backups were already submitted but their acknowledgement could not be read; " +
                "query the transaction status before doing anything else.")
            : new UninstallTransactionUncertainException(
                TransactionId,
                "ack-backups",
                "The host backups were submitted but their acknowledgement could not be read; " +
                "query the transaction status before doing anything else.",
                inner);

    private static bool IsClientRefusal(HttpRequestException exception)
        => exception.StatusCode is { } statusCode && (int)statusCode is >= 400 and < 500;

    private static bool IsUnreadableStatus(Exception exception)
        => exception is HttpRequestException or TimeoutException or InvalidDataException or IOException;

    private static string BootEndpointRole(string role) => role switch
    {
        "boot_a" => "a",
        "boot_b" => "b",
        "misc" => "misc",
        _ => throw new InvalidOperationException($"The fixed metadata role '{role}' has no boot endpoint."),
    };

    private static string ReadSingleContentSha256(HttpResponseMessage response)
    {
        var values = new List<string>(1);

        if (response.Headers.TryGetValues("X-Content-SHA256", out var responseValues))
        {
            values.AddRange(responseValues);
        }

        if (response.Content is not null
            && response.Content.Headers.TryGetValues("X-Content-SHA256", out var contentValues))
        {
            values.AddRange(contentValues);
        }

        if (values.Count != 1)
        {
            throw new InvalidDataException(
                $"The runtime must send exactly one X-Content-SHA256 header, but sent {values.Count}.");
        }

        return values[0];
    }

    private async Task VerifyLocalBackupFilesAsync(
        IReadOnlyList<HostBackupEntry> entries, CancellationToken token)
    {
        foreach (var entry in entries)
        {
            var path = Path.Combine(BackupDirectory, entry.FileName);
            if (!File.Exists(path))
            {
                throw new IOException($"The backup file '{path}' is missing.");
            }

            var measurement = await MeasureFileAsync(path, maximumBytes: 0, entry.Role + " backup", token)
                .ConfigureAwait(false);
            if (measurement.Bytes != entry.Bytes
                || !string.Equals(measurement.Sha256, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    $"The backup file '{path}' no longer matches the retained {entry.Role} descriptor.");
            }
        }
    }

    private async Task VerifyLocalHostBackupAsync(CancellationToken token)
    {
        await VerifyLocalBackupFilesAsync(_hostBackupEntries, token).ConfigureAwait(false);

        var manifestPath = Path.Combine(BackupDirectory, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            throw new IOException($"The backup manifest '{manifestPath}' is missing.");
        }

        var bytes = await File.ReadAllBytesAsync(manifestPath, token).ConfigureAwait(false);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(bytes, DocumentOptions);
        }
        catch (JsonException exception)
        {
            throw new IOException($"The backup manifest '{manifestPath}' is not valid JSON.", exception);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || RequireInt64(root, "schemaVersion") != 1
                || !string.Equals(RequireString(root, "transactionId"), TransactionId, StringComparison.Ordinal)
                || !string.Equals(RequireString(root, "bootId"), _connection.BootId, StringComparison.Ordinal)
                || !string.Equals(RequireString(root, "serial"), Snapshot.Identity.Serial, StringComparison.Ordinal)
                || !string.Equals(RequireString(root, "model"), Snapshot.Identity.Model, StringComparison.Ordinal)
                || !string.Equals(RequireString(root, "socSerial"), _factoryInspect.SocSerial, StringComparison.Ordinal)
                || !string.Equals(
                    RequireString(root, "planFingerprint"), PlanFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException($"The backup manifest '{manifestPath}' no longer describes this transaction.");
            }

            var backups = RequireArray(root, "backups");
            if (backups.GetArrayLength() != _hostBackupEntries.Count)
            {
                throw new IOException($"The backup manifest '{manifestPath}' does not list every retained backup.");
            }

            foreach (var entry in _hostBackupEntries)
            {
                if (!ManifestNamesEntry(backups, entry))
                {
                    throw new IOException(
                        $"The backup manifest '{manifestPath}' does not describe the retained {entry.Role} file.");
                }
            }
        }
    }

    private static bool ManifestNamesEntry(JsonElement backups, HostBackupEntry entry)
    {
        foreach (var node in backups.EnumerateArray())
        {
            if (node.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var role = ReadStringOrNull(node, "role");
            var file = ReadStringOrNull(node, "file");
            if (!string.Equals(role, entry.Role, StringComparison.Ordinal)
                || !string.Equals(file, entry.FileName, StringComparison.Ordinal))
            {
                continue;
            }

            return node.TryGetProperty("bytes", out var bytesElement)
                && bytesElement.ValueKind == JsonValueKind.Number
                && bytesElement.TryGetInt64(out var bytes)
                && bytes == entry.Bytes
                && string.Equals(ReadStringOrNull(node, "sha256"), entry.Sha256, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static string? ReadStringOrNull(JsonElement parent, string name)
        => parent.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;

    private async Task WriteManifestAsync(
        string state,
        string? pendingStep,
        IReadOnlyList<string> completedSteps,
        bool overwrite,
        CancellationToken token)
    {
        var manifestPath = Path.Combine(BackupDirectory, "manifest.json");
        var partialPath = manifestPath + ".partial";

        if (overwrite && !File.Exists(manifestPath))
        {
            throw new InvalidOperationException(
                "The backup manifest can only be updated after the backup created it.");
        }

        var backupPayloads = new object[_hostBackupEntries.Count];
        for (var index = 0; index < _hostBackupEntries.Count; index++)
        {
            var entry = _hostBackupEntries[index];
            backupPayloads[index] = new
            {
                role = entry.Role,
                file = entry.FileName,
                bytes = entry.Bytes,
                sha256 = entry.Sha256,
            };
        }

        var steps = new string[completedSteps.Count];
        for (var index = 0; index < completedSteps.Count; index++)
        {
            steps[index] = completedSteps[index];
        }

        var json = JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            transactionId = TransactionId,
            bootId = _connection.BootId,
            serial = Snapshot.Identity.Serial,
            model = Snapshot.Identity.Model,
            socSerial = _factoryInspect.SocSerial,
            planFingerprint = PlanFingerprint,
            backups = backupPayloads,
            state,
            stage = _journalStage,
            pendingStep,
            completedSteps = steps,
        });

        var bytes = Encoding.UTF8.GetBytes(json);

        using (var file = new FileStream(
            partialPath,
            overwrite ? FileMode.Create : FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            81920,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await file.WriteAsync(bytes.AsMemory(), token).ConfigureAwait(false);
            await file.FlushAsync(token).ConfigureAwait(false);
            file.Flush(flushToDisk: true);
        }

        File.Move(partialPath, manifestPath, overwrite);
    }

    private void RequireFreshInspectMatchesFactory(InspectEvidence fresh)
    {
        if (!string.Equals(fresh.CurrentBootFingerprint, _factoryInspect.CurrentBootFingerprint, StringComparison.Ordinal)
            || !string.Equals(fresh.CurrentBootFingerprint, Snapshot.CurrentBootFingerprint, StringComparison.Ordinal)
            || !string.Equals(fresh.MiscFingerprint, _factoryInspect.MiscFingerprint, StringComparison.Ordinal)
            || !string.Equals(fresh.SocSerial, _factoryInspect.SocSerial, StringComparison.Ordinal)
            || fresh.OtaState != _factoryInspect.OtaState
            || fresh.MaintenanceValidated != _factoryInspect.MaintenanceValidated
            || !SameDescriptor(fresh.BootA, _factoryInspect.BootA)
            || !SameDescriptor(fresh.BootB, _factoryInspect.BootB)
            || !SameDescriptor(fresh.Misc, _factoryInspect.Misc))
        {
            throw new InvalidDataException(
                "The runtime no longer reports the current boot and misc descriptors this transaction was prepared against.");
        }
    }

    private static bool SameDescriptor(PartitionDescriptor left, PartitionDescriptor right)
        => string.Equals(left.Role, right.Role, StringComparison.Ordinal)
            && string.Equals(left.PartitionPath, right.PartitionPath, StringComparison.Ordinal)
            && string.Equals(left.PartUuid, right.PartUuid, StringComparison.Ordinal)
            && left.Bytes == right.Bytes
            && string.Equals(left.Sha256, right.Sha256, StringComparison.OrdinalIgnoreCase);

    private static void RequireUntouchedPrepared(UninstallTransactionStatus status)
    {
        if (!string.Equals(status.State, "prepared", StringComparison.Ordinal)
            || status.Error is not null
            || status.ActiveStep is not null
            || status.CompletedSteps.Count != 0
            || !string.Equals(status.NextStep, RestoreBootAStep, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The runtime transaction is no longer the untouched prepared transaction.");
        }
    }

    /// <summary>
    /// Confirms from the runtime status that the prepared stock images are still bound to this transaction and
    /// that the current boot backups were acknowledged. It does not prepare a second transaction or write.
    /// </summary>
    /// <exception cref="InvalidOperationException">The runtime has not acknowledged the backups yet.</exception>
    /// <exception cref="InvalidDataException">The status no longer names this prepared transaction.</exception>
    public async Task PrepareStockBootAsync(CancellationToken token)
    {
        if (!_hostBackupComplete)
        {
            throw new InvalidOperationException(
                "The host backup of the current boot has not completed locally, so the stock step must not start.");
        }

        await VerifyLocalHostBackupAsync(token).ConfigureAwait(false);

        var status = await FetchStatusAsync(requireBackupAcknowledged: true, token).ConfigureAwait(false);

        if (!string.Equals(status.State, "prepared", StringComparison.Ordinal)
            || status.Error is not null
            || status.ActiveStep is not null
            || status.CompletedSteps.Count != 0
            || !string.Equals(status.NextStep, RestoreBootAStep, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The runtime transaction is no longer a prepared transaction with acknowledged backups.");
        }
    }

    /// <summary>Queues the restore step for one slot; the runtime performs the write in its own worker.</summary>
    /// <exception cref="ArgumentException">The slot is not <c>a</c> or <c>b</c>.</exception>
    /// <exception cref="InvalidOperationException">
    /// The host backup is incomplete, the runtime already failed, or the runtime does not expect this step next.
    /// </exception>
    /// <exception cref="UninstallTransactionUncertainException">
    /// The step was submitted but its outcome cannot be proven from this transaction's status.
    /// </exception>
    public Task RestoreBootAsync(string slot, CancellationToken token)
    {
        RequireSlot(slot, nameof(slot));
        return ExecuteStepAsync(
            string.Equals(slot, "a", StringComparison.Ordinal) ? RestoreBootAStep : RestoreBootBStep, token);
    }

    /// <summary>Queues the verify step for one slot and requires the runtime's readback evidence.</summary>
    /// <exception cref="ArgumentException">The slot is not <c>a</c> or <c>b</c>.</exception>
    /// <exception cref="InvalidOperationException">
    /// The host backup is incomplete, the runtime already failed, or the runtime does not expect this step next.
    /// </exception>
    /// <exception cref="UninstallTransactionUncertainException">
    /// The step was submitted but its outcome cannot be proven from this transaction's status.
    /// </exception>
    public Task VerifyBootAsync(string slot, CancellationToken token)
    {
        RequireSlot(slot, nameof(slot));
        return ExecuteStepAsync(
            string.Equals(slot, "a", StringComparison.Ordinal) ? VerifyBootAStep : VerifyBootBStep, token);
    }

    /// <summary>Queues the space reclaim step. Only valid after both slots verified.</summary>
    /// <exception cref="InvalidOperationException">
    /// The host backup is incomplete, the runtime already failed, or the runtime does not expect this step next.
    /// </exception>
    /// <exception cref="UninstallTransactionUncertainException">
    /// The step was submitted but its outcome cannot be proven from this transaction's status.
    /// </exception>
    public Task ReclaimAndroidSpaceAsync(CancellationToken token)
        => ExecuteStepAsync(ReclaimSpaceStep, token);

    /// <summary>Queues the factory reset request. The runtime stops at <c>awaitingFactoryReset</c> afterwards.</summary>
    /// <exception cref="InvalidOperationException">
    /// The host backup is incomplete, the runtime already failed, or the runtime does not expect this step next.
    /// </exception>
    /// <exception cref="UninstallTransactionUncertainException">
    /// The step was submitted but its outcome cannot be proven from this transaction's status.
    /// </exception>
    public Task InitializeAndroidAsync(CancellationToken token)
        => ExecuteStepAsync(QueueFactoryResetStep, token);

    private static void RequireSlot(string slot, string parameterName)
    {
        if (!string.Equals(slot, "a", StringComparison.Ordinal)
            && !string.Equals(slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("The boot slot must be 'a' or 'b'.", parameterName);
        }
    }

    /// <summary>
    /// Submits exactly one fixed step of this transaction and then proves it from the same transaction status.
    /// The local journal is flushed before the single POST; a lost reply is resolved only by reading the status.
    /// </summary>
    private async Task ExecuteStepAsync(string step, CancellationToken token)
    {
        await _hostBackupGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();

            if (!_hostBackupComplete)
            {
                throw new InvalidOperationException(
                    "The host backup of the current boot has not completed locally, so no step may be submitted.");
            }

            await VerifyLocalHostBackupAsync(token).ConfigureAwait(false);

            var status = await FetchStatusAsync(requireBackupAcknowledged: true, token).ConfigureAwait(false);

            _journalStage = status.Stage;

            if (string.Equals(status.State, "failed", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"The runtime transaction already failed at stage '{status.Stage}': {status.Error}.");
            }

            if (ContainsStep(status.CompletedSteps, step))
            {
                await UpdateManifestJournalAsync(status.State, null, status.CompletedSteps, token)
                    .ConfigureAwait(false);
                return;
            }

            if (string.Equals(status.State, "running", StringComparison.Ordinal))
            {
                // A running transaction already has exactly one active step. This instance may not have the
                // submitted marker (for example after recovery), so it may only poll that same active step;
                // it must never post a second copy of it or any other step.
                if (!string.Equals(status.ActiveStep, step, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"The runtime is running '{status.ActiveStep}' but the caller requested '{step}'.");
                }

                // The runtime already accepted this step, so this instance records the submitted marker before
                // polling: a later reply that looks unknown or prepared can never make it post the step again.
                _pendingStep = step;
                _submittedSteps.Add(step);

                await PollSubmittedStepAsync(step, token).ConfigureAwait(false);
                return;
            }

            if (!_submittedSteps.Contains(step)
                && !string.Equals(_pendingStep, step, StringComparison.Ordinal))
            {
                var expected = NextUncompletedStep(status.CompletedSteps);
                if (!string.Equals(expected, step, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"The runtime expects '{expected ?? "no further step"}' " +
                        $"but the caller requested '{step}'.");
                }

                await SubmitStepAsync(step, status, token).ConfigureAwait(false);
            }

            await PollSubmittedStepAsync(step, token).ConfigureAwait(false);
        }
        finally
        {
            _hostBackupGate.Release();
        }
    }

    private async Task SubmitStepAsync(
        string step, UninstallTransactionStatus status, CancellationToken token)
    {
        await UpdateManifestJournalAsync("submitting", step, status.CompletedSteps, token)
            .ConfigureAwait(false);

        // A cancellation before the step is on the wire is ordinary cancellation; only from here on does the
        // submitted marker make every further failure an uncertain outcome that must be polled, never re-posted.
        token.ThrowIfCancellationRequested();

        _pendingStep = step;
        _submittedSteps.Add(step);

        var body = JsonSerializer.Serialize(new
        {
            step,
            bootId = _connection.BootId,
            confirmationToken = _confirmationToken,
            wipeConfirmed = true,
        });

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body);

        try
        {
            using var document = await SendJsonAsync(
                    _http,
                    _connection,
                    HttpMethod.Post,
                    $"/v1/transactions/{TransactionId}/step",
                    content,
                    MetadataTimeout,
                    token)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException exception) when (IsClientRefusal(exception))
        {
            throw new InvalidOperationException(
                $"The runtime refused the '{step}' step: {exception.Message}", exception);
        }
        catch (HttpRequestException)
        {
            // No status or a 5xx: the step may still have been accepted, so only the status may decide.
        }
        catch (TimeoutException)
        {
        }
        catch (IOException)
        {
        }
        catch (InvalidDataException)
        {
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw StepUncertain(step, null);
        }
    }

    private async Task PollSubmittedStepAsync(string step, CancellationToken token)
    {
        using var pollSource = CancellationTokenSource.CreateLinkedTokenSource(token);
        pollSource.CancelAfter(StepPollTimeout);

        var first = true;
        while (true)
        {
            if (!first)
            {
                try
                {
                    await Task.Delay(StepPollInterval, pollSource.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw StepUncertain(step, null);
                }
            }

            first = false;

            UninstallTransactionStatus status;
            try
            {
                status = await FetchStatusAsync(requireBackupAcknowledged: true, pollSource.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw StepUncertain(step, null);
            }
            catch (Exception exception) when (IsUnreadableStatus(exception))
            {
                throw StepUncertain(step, exception);
            }

            _journalStage = status.Stage;

            if (ContainsStep(status.CompletedSteps, step))
            {
                try
                {
                    await UpdateManifestJournalAsync(status.State, null, status.CompletedSteps, token)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException or OperationCanceledException)
                {
                    // The runtime did complete the step; a lost local journal write is still an unsure outcome.
                    throw StepUncertain(step, exception);
                }

                _pendingStep = null;
                return;
            }

            if (string.Equals(status.State, "failed", StringComparison.Ordinal))
            {
                await UpdateManifestJournalAsync("failed", step, status.CompletedSteps, token)
                    .ConfigureAwait(false);
                throw new InvalidOperationException(
                    $"The runtime failed the transaction at stage '{status.Stage}': {status.Error}.");
            }

            if (string.Equals(status.State, "prepared", StringComparison.Ordinal))
            {
                throw StepUncertain(step, null);
            }
        }
    }

    private static bool ContainsStep(IReadOnlyList<string> completedSteps, string step)
    {
        foreach (var candidate in completedSteps)
        {
            if (string.Equals(candidate, step, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string? NextUncompletedStep(IReadOnlyList<string> completedSteps)
        => completedSteps.Count < FixedSteps.Length ? FixedSteps[completedSteps.Count] : null;

    private UninstallTransactionUncertainException StepUncertain(string step, Exception? inner)
    {
        var message =
            $"The '{step}' step was already submitted but its outcome cannot be proven from the " +
            "transaction status; query the status before doing anything else.";

        return inner is null
            ? new UninstallTransactionUncertainException(TransactionId, step, message)
            : new UninstallTransactionUncertainException(TransactionId, step, message, inner);
    }

    /// <summary>
    /// Always refuses. A successful queue and readback only means the runtime accepted the reset request; the
    /// proof that Android actually boots comes from the separate acceptance probe (boot_completed plus capacity)
    /// after the user-authorized reboot, never from this transport.
    /// </summary>
    /// <exception cref="InvalidOperationException">Always: this backend can never prove Android booted.</exception>
    public Task VerifyAndroidAsync(CancellationToken token)
        => throw new InvalidOperationException(
            "HttpUninstallBackend never proves that Android booted: this transport stops at the queued factory reset. " +
            "Android acceptance requires the separate boot_completed and capacity probe after the user-authorized reboot.");

    private static UninstallSnapshot BuildSnapshot(
        ValidatedUninstallInputs inputs, InspectEvidence inspect, string stockFingerprint)
        => new(
            inputs.Identity,
            inputs.CurrentTableFingerprint,
            inspect.CurrentBootFingerprint,
            stockFingerprint,
            inputs.EvidenceFingerprint,
            inspect.MaintenanceValidated,
            true,
            inspect.OtaState);

    /// <summary>
    /// Validates every local prepare argument in the same order before any request is sent. Both preparing a
    /// new transaction and recovering an existing one must refuse the same invalid inputs without I/O.
    /// </summary>
    private static void ValidatePrepareArguments(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        UninstallRestoreAssets assets,
        string backupRoot)
    {
        if (http is null)
        {
            throw new ArgumentNullException(nameof(http));
        }

        if (connection is null)
        {
            throw new ArgumentNullException(nameof(connection));
        }

        if (inputs is null)
        {
            throw new ArgumentNullException(nameof(inputs));
        }

        if (binding is null)
        {
            throw new ArgumentNullException(nameof(binding));
        }

        if (assets is null)
        {
            throw new ArgumentNullException(nameof(assets));
        }

        if (string.IsNullOrWhiteSpace(backupRoot))
        {
            throw new ArgumentException("A backup directory is required.", nameof(backupRoot));
        }

        RequireUsbBaseAddress(connection);
        RequireBearerToken(connection);
        RequireBootId(connection);
        RequireBinding(binding, inputs);
        RequireConfirmedFastbootSerial(binding, inputs);
        RequireTargetDevice(inputs);
        RequireAssetPath(assets.StockBootAPath, nameof(assets.StockBootAPath));
        RequireAssetPath(assets.StockBootBPath, nameof(assets.StockBootBPath));
        RequireAssetPath(assets.OriginalPrimaryGptPath, nameof(assets.OriginalPrimaryGptPath));
        RequireAssetPath(assets.OriginalBackupGptPath, nameof(assets.OriginalBackupGptPath));
        RequireAssetPath(assets.TrustedVbmetaBaselinePath, nameof(assets.TrustedVbmetaBaselinePath));
    }

    private static void RequireStatusIsNotFailed(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("state", out var state)
            || state.ValueKind != JsonValueKind.String
            || !string.Equals(state.GetString(), "failed", StringComparison.Ordinal))
        {
            return;
        }

        var stage = ReadNullableString(root, "stage", required: false) ?? "unknown";
        var error = ReadError(root);
        throw new InvalidDataException(
            $"The runtime transaction failed at stage '{stage}': {error}.");
    }

    private static void RequireUsbBaseAddress(HttpUninstallConnection connection)
    {
        var baseAddress = connection.BaseAddress;
        if (baseAddress is null)
        {
            throw new ArgumentException("The maintenance base address is required.", nameof(connection));
        }

        // Only the point-to-point USB endpoint may be bound: no other host, port, userinfo, query, fragment or
        // path prefix can redirect the token or the assets somewhere else.
        if (!string.Equals(baseAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(baseAddress.Host, UsbHostAddress, StringComparison.Ordinal)
            || baseAddress.Port != UsbHostPort
            || !string.Equals(baseAddress.AbsolutePath, "/", StringComparison.Ordinal)
            || baseAddress.UserInfo.Length != 0
            || baseAddress.Query.Length != 0
            || baseAddress.Fragment.Length != 0
            || !string.Equals(baseAddress.AbsoluteUri, UsbBaseUrl, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The maintenance service must be reached over {UsbBaseUrl}; " +
                $"{baseAddress.AbsoluteUri} is refused before any request is sent.",
                nameof(connection));
        }
    }

    private static void RequireBearerToken(HttpUninstallConnection connection)
    {
        var token = connection.BearerToken;
        if (token is null || token.Length != BearerTokenHexLength)
        {
            throw new ArgumentException(
                $"The bearer token must be {BearerTokenHexLength} hexadecimal characters.",
                nameof(connection));
        }

        foreach (var character in token)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                throw new ArgumentException(
                    $"The bearer token must be {BearerTokenHexLength} hexadecimal characters.",
                    nameof(connection));
            }
        }
    }

    private static void RequireBootId(HttpUninstallConnection connection)
    {
        if (string.IsNullOrWhiteSpace(connection.BootId) || !Guid.TryParse(connection.BootId, out _))
        {
            throw new ArgumentException(
                "The boot id of the maintenance session must be the UUID the runtime reports.",
                nameof(connection));
        }
    }

    private static void RequireBinding(UninstallDeviceBinding binding, ValidatedUninstallInputs inputs)
    {
        var identity = binding.Identity;
        if (identity is null)
        {
            throw new ArgumentException("The device binding carries no identity.", nameof(binding));
        }

        if (!DeviceProbe.IsSupportedModel(identity.Model))
        {
            throw new ArgumentException(
                $"The bound model '{identity.Model}' is not a supported unit.", nameof(binding));
        }

        if (identity.BootloaderState != BootloaderState.Unlocked)
        {
            throw new ArgumentException("The bound bootloader is not unlocked.", nameof(binding));
        }

        if (!Equals(identity, inputs.Identity))
        {
            throw new ArgumentException(
                "The device binding does not name the confirmed device identity.", nameof(binding));
        }

        if (string.IsNullOrWhiteSpace(binding.AndroidSocSerial))
        {
            throw new ArgumentException("The bound Android SoC serial is required.", nameof(binding));
        }

        if (binding.OtaState != OtaUpdateState.Completed)
        {
            throw new ArgumentException(
                "The OTA update of the bound device is not completed.", nameof(binding));
        }
    }

    /// <summary>
    /// The binding is the device this transaction may touch: a fastboot serial that is not the confirmed
    /// identity's serial means a later write could land on a different unit, so it is refused before any
    /// request instead of being compared against the server afterwards.
    /// </summary>
    private static void RequireConfirmedFastbootSerial(
        UninstallDeviceBinding binding, ValidatedUninstallInputs inputs)
    {
        var confirmedSerial = inputs.Identity?.Serial;
        if (string.IsNullOrWhiteSpace(confirmedSerial)
            || !string.Equals(binding.FastbootSerial, confirmedSerial, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The fastboot serial of the device binding does not match the confirmed device identity.",
                nameof(binding));
        }
    }

    private static void RequireTargetDevice(ValidatedUninstallInputs inputs)
    {
        if (!string.Equals(inputs.CurrentTable.DeviceId, "/dev/sda", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The validated table names '{inputs.CurrentTable.DeviceId}' instead of the only supported target /dev/sda.",
                nameof(inputs));
        }
    }

    private static void RequireAssetPath(string path, string parameter)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Every restore asset needs a local file path.", parameter);
        }
    }

    private static async Task<InspectEvidence> ReadInspectAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        CancellationToken token)
    {
        using var document = await SendJsonAsync(
                http,
                connection,
                HttpMethod.Get,
                "/v1/inspect",
                content: null,
                MetadataTimeout,
                token)
            .ConfigureAwait(false);

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The inspect response is not a JSON object.");
        }

        if (RequireInt64(root, "schemaVersion") != 1)
        {
            throw new InvalidDataException("The inspect response does not use schema version 1.");
        }

        var expected = inputs.CurrentTable;

        if (!string.Equals(RequireNonEmptyString(root, "model"), inputs.Identity.Model, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The runtime reports a different model than the confirmed device.");
        }

        var socSerial = RequireNonEmptyString(root, "socSerial");
        if (!string.Equals(socSerial, binding.AndroidSocSerial, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The runtime SoC serial does not match the confirmed device binding.");
        }

        var bootId = RequireNonEmptyString(root, "bootId");
        if (!Guid.TryParse(bootId, out _) || !Guid.TryParse(connection.BootId, out var expectedBootId)
            || !Guid.TryParse(bootId, out var actualBootId) || actualBootId != expectedBootId)
        {
            throw new InvalidDataException("The runtime boot id is not the boot id of this maintenance session.");
        }

        if (!RequireBool(root, "ramRoot"))
        {
            throw new InvalidDataException("The runtime is not running from the verified RAM root.");
        }

        if (!RequireBool(root, "primaryGptValid") || !RequireBool(root, "backupGptValid"))
        {
            throw new InvalidDataException("The runtime does not report both GPT headers as valid.");
        }

        if (!RequireBool(root, "maintenanceValidated"))
        {
            throw new InvalidDataException("The runtime has not validated maintenance mode.");
        }

        var diskPath = RequireNonEmptyString(root, "diskPath");
        if (!string.Equals(diskPath, expected.DeviceId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The runtime reports a different target disk than the validated table.");
        }

        var diskBytes = RequireInt64(root, "diskBytes");
        if (diskBytes != expected.DiskBytes)
        {
            throw new InvalidDataException("The runtime disk size differs from the validated table.");
        }

        var sectorSize = RequireInt64(root, "sectorSize");
        if (sectorSize != expected.SectorSize)
        {
            throw new InvalidDataException("The runtime sector size differs from the validated table.");
        }

        var tableFingerprint = RequireNonEmptyString(root, "tableFingerprint");
        if (!string.Equals(tableFingerprint, inputs.CurrentTableFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The runtime table fingerprint differs from the raw GPT fingerprint the host validated.");
        }

        RequireLayout(root, expected);
        RequireCurrentSfdisk(root, expected);
        var bootA = RequireBootSlot(root, "a");
        var bootB = RequireBootSlot(root, "b");
        var misc = RequireMisc(root);
        RequireDistinctMetadata(bootA, bootB, misc);
        RequireIdleBusy(root);

        var ota = RequireObject(root, "ota");
        var otaStateText = RequireNonEmptyString(ota, "state");
        if (!string.Equals(otaStateText, "completed", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The runtime reports OTA state '{otaStateText}', so the update is not proven completed.");
        }

        // inspect may report the stock flag, but this path deliberately ignores it: only prepare's per-slot
        // validator may claim that both stock boots are valid.
        _ = root.TryGetProperty("bothStockBootsValid", out _);

        return new InspectEvidence(
            RequireHex64(root, "currentBootFingerprint"),
            RequireHex64(root, "miscFingerprint"),
            OtaUpdateState.Completed,
            MaintenanceValidated: true,
            socSerial,
            bootA,
            bootB,
            misc);
    }

    private static void RequireLayout(JsonElement root, GptTable expected)
    {
        var layout = RequireObject(root, "layout");

        if (!string.Equals(RequireNonEmptyString(layout, "device"), expected.DeviceId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The layout names a different device than the validated table.");
        }

        if (RequireInt64(layout, "sectorSize") != expected.SectorSize)
        {
            throw new InvalidDataException("The layout reports a different sector size than the validated table.");
        }

        var partitions = RequireArray(layout, "partitions");
        if (partitions.GetArrayLength() != expected.Partitions.Count)
        {
            throw new InvalidDataException("The layout does not carry exactly the validated partitions.");
        }

        var seen = new HashSet<int>();
        foreach (var node in partitions.EnumerateArray())
        {
            if (node.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("A layout partition is not a JSON object.");
            }

            var number = RequireInt32(node, "number");
            if (!seen.Add(number))
            {
                throw new InvalidDataException($"The layout repeats partition number {number}.");
            }

            var match = FindPartition(expected, number)
                ?? throw new InvalidDataException($"The layout carries the unknown partition number {number}.");

            if (!string.Equals(RequireString(node, "name"), match.Name, StringComparison.Ordinal)
                || RequireInt64(node, "startSector") != match.StartSector
                || RequireInt64(node, "sectorCount") != match.SectorCount
                || !string.Equals(RequireGuid(node, "typeGuid"), CanonicalGuid(match.TypeGuid), StringComparison.Ordinal)
                || !string.Equals(RequireGuid(node, "partUuid"), CanonicalGuid(match.PartUuid), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The layout row for partition {number} differs from the validated current table.");
            }
        }
    }

    private static void RequireCurrentSfdisk(JsonElement root, GptTable expected)
    {
        var json = RequireNonEmptyString(root, "sfdiskJson");

        GptTable current;
        try
        {
            current = UninstallEvidenceValidator.ReadCurrentSfdisk(json, expected.DiskBytes);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidDataException)
        {
            throw new InvalidDataException(
                "The inspect sfdiskJson does not describe a trustworthy current table.", exception);
        }

        if (!string.Equals(current.SourceFingerprint, expected.SourceFingerprint, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.DeviceId, expected.DeviceId, StringComparison.Ordinal)
            || current.SectorSize != expected.SectorSize
            || current.DiskBytes != expected.DiskBytes
            || current.Partitions.Count != expected.Partitions.Count)
        {
            throw new InvalidDataException(
                "The inspect sfdiskJson is not the validated current table.");
        }

        foreach (var match in expected.Partitions)
        {
            var actual = FindPartition(current, match.Number)
                ?? throw new InvalidDataException(
                    $"The inspect sfdiskJson is missing partition {match.Number}.");

            if (!string.Equals(actual.Name, match.Name, StringComparison.Ordinal)
                || actual.StartSector != match.StartSector
                || actual.SectorCount != match.SectorCount
                || !string.Equals(CanonicalGuid(actual.TypeGuid), CanonicalGuid(match.TypeGuid), StringComparison.Ordinal)
                || !string.Equals(CanonicalGuid(actual.PartUuid), CanonicalGuid(match.PartUuid), StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The inspect sfdiskJson row for partition {match.Number} differs from the validated table.");
            }
        }
    }

    private static PartitionDescriptor RequireBootSlot(JsonElement root, string slot)
    {
        var slots = RequireObject(root, "bootSlots");
        var node = RequireObject(slots, slot);

        var partitionPath = RequireSafeDevicePath(node, "partitionPath");
        var partUuid = RequireGuid(node, "partUuid");
        var bytes = RequireInt64(node, "bytes");

        if (bytes <= 0)
        {
            throw new InvalidDataException($"Boot slot {slot} reports no bytes.");
        }

        var sha256 = RequireHex64(node, "sha256");
        RequireHex64(node, "vbmetaSha256");

        if (string.IsNullOrWhiteSpace(RequireNonEmptyString(node, "slotFingerprint")))
        {
            throw new InvalidDataException($"Boot slot {slot} reports no slot fingerprint.");
        }

        return new PartitionDescriptor("boot_" + slot, partitionPath, partUuid, bytes, sha256);
    }

    private static PartitionDescriptor RequireMisc(JsonElement root)
    {
        var misc = RequireObject(root, "misc");
        var partitionPath = RequireSafeDevicePath(misc, "partitionPath");
        var partUuid = RequireGuid(misc, "partUuid");
        var bytes = RequireInt64(misc, "bytes");

        if (bytes <= 0)
        {
            throw new InvalidDataException("The misc partition reports no bytes.");
        }

        var sha256 = RequireHex64(misc, "sha256");

        if (RequireBool(misc, "bcbPending"))
        {
            throw new InvalidDataException("The misc partition carries a pending bootloader command.");
        }

        return new PartitionDescriptor("misc", partitionPath, partUuid, bytes, sha256);
    }

    /// <summary>
    /// The three backup roles must name three different partitions: a repeated path or UUID would make one
    /// download stand in for another role and silently leave one image unbacked.
    /// </summary>
    private static void RequireDistinctMetadata(params PartitionDescriptor[] descriptors)
    {
        for (var left = 0; left < descriptors.Length; left++)
        {
            for (var right = left + 1; right < descriptors.Length; right++)
            {
                if (string.Equals(
                        descriptors[left].PartitionPath, descriptors[right].PartitionPath, StringComparison.Ordinal)
                    || string.Equals(
                        descriptors[left].PartUuid, descriptors[right].PartUuid, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"The metadata roles {descriptors[left].Role} and {descriptors[right].Role} " +
                        "share a partition path or UUID.");
                }
            }
        }
    }

    private static void RequireIdleBusy(JsonElement root)
    {
        var busy = RequireObject(root, "busy");

        if (RequireBool(busy, "rootOnTarget"))
        {
            throw new InvalidDataException("The runtime reports its root filesystem on the target disk.");
        }

        RequireEmptyArray(busy, "mountedPartitions");
        RequireEmptyArray(busy, "swapPartitions");
        RequireEmptyArray(busy, "holderPartitions");
    }

    private static void RequireEmptyArray(JsonElement parent, string name)
    {
        if (RequireArray(parent, name).GetArrayLength() != 0)
        {
            throw new InvalidDataException($"The runtime reports a non-empty '{name}' array.");
        }
    }

    private static async Task<List<AssetDescriptor>> MeasureAssetsAsync(
        UninstallRestoreAssets assets,
        ValidatedUninstallInputs inputs,
        CancellationToken token)
    {
        var primary = await ReadBoundedFileAsync(
                assets.OriginalPrimaryGptPath, GptFragmentLimit, "original primary GPT", token)
            .ConfigureAwait(false);
        var backup = await ReadBoundedFileAsync(
                assets.OriginalBackupGptPath, GptFragmentLimit, "original backup GPT", token)
            .ConfigureAwait(false);

        GptTable original;
        try
        {
            original = OriginalGptImporter.Parse(
                primary, backup, inputs.CurrentTable.SectorSize, inputs.CurrentTable.DiskBytes);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidDataException)
        {
            throw new InvalidDataException(
                "The selected original GPT fragments do not parse as a coherent GPT.", exception);
        }

        if (!string.Equals(original.SourceFingerprint, inputs.OriginalGptFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The selected original GPT fragments do not reproduce the validated original fingerprint.");
        }

        var descriptors = new List<AssetDescriptor>(5)
        {
            new("stock_boot_a", assets.StockBootAPath, await MeasureFileAsync(
                    assets.StockBootAPath, maximumBytes: 0, "stock boot a", token).ConfigureAwait(false)),
            new("stock_boot_b", assets.StockBootBPath, await MeasureFileAsync(
                    assets.StockBootBPath, maximumBytes: 0, "stock boot b", token).ConfigureAwait(false)),
            new("original_primary_gpt", assets.OriginalPrimaryGptPath, new FileMeasurement(
                    primary.LongLength, ToHexLower(SHA256.HashData(primary)))),
            new("original_backup_gpt", assets.OriginalBackupGptPath, new FileMeasurement(
                    backup.LongLength, ToHexLower(SHA256.HashData(backup)))),
            new("trusted_vbmeta_baseline", assets.TrustedVbmetaBaselinePath, await MeasureFileAsync(
                    assets.TrustedVbmetaBaselinePath, TrustedVbmetaLimit, "trusted vbmeta baseline", token)
                .ConfigureAwait(false)),
        };

        return descriptors;
    }

    private static async Task<FileMeasurement> MeasureFileAsync(
        string path, long maximumBytes, string what, CancellationToken token)
    {
        using var stream = OpenAsset(path);
        if (stream.Length <= 0)
        {
            throw new InvalidDataException($"The {what} file is empty.");
        }

        if (maximumBytes > 0 && stream.Length > maximumBytes)
        {
            throw new InvalidDataException($"The {what} file exceeds its {maximumBytes} byte limit.");
        }

        var length = stream.Length;
        using var sha = SHA256.Create();
        var digest = await sha.ComputeHashAsync(stream, token).ConfigureAwait(false);
        return new FileMeasurement(length, ToHexLower(digest));
    }

    private static async Task<byte[]> ReadBoundedFileAsync(
        string path, long maximumBytes, string what, CancellationToken token)
    {
        using var stream = OpenAsset(path);
        if (stream.Length <= 0 || stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                $"The {what} file must be between 1 and {maximumBytes} bytes.");
        }

        var length = checked((int)stream.Length);
        var bytes = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(bytes.AsMemory(offset, length - offset), token).ConfigureAwait(false);
            if (read == 0)
            {
                throw new InvalidDataException($"The {what} file ended before its declared length.");
            }

            offset += read;
        }

        return bytes;
    }

    private static FileStream OpenAsset(string path)
        => new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static async Task UploadAssetAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        AssetDescriptor descriptor,
        CancellationToken token)
    {
        using var file = OpenAsset(descriptor.Path);
        if (file.Length != descriptor.Bytes)
        {
            throw new InvalidDataException(
                $"The asset {descriptor.Role} changed length after it was hashed.");
        }

        using var hashing = new HashingReadStream(file, descriptor.Bytes);
        using var content = new StreamContent(hashing);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Headers.ContentLength = descriptor.Bytes;

        using var document = await SendJsonAsync(
                http,
                connection,
                HttpMethod.Put,
                "/v1/assets/" + descriptor.Role,
                content,
                FileTransferTimeout,
                token)
            .ConfigureAwait(false);

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"The upload receipt for {descriptor.Role} is not a JSON object.");
        }

        var actualHash = hashing.CompleteHash();
        var role = RequireNonEmptyString(root, "role");
        var bytes = RequireInt64(root, "bytes");
        var sha256 = RequireHex64(root, "sha256");

        if (!string.Equals(role, descriptor.Role, StringComparison.Ordinal)
            || bytes != hashing.BytesRead
            || bytes != descriptor.Bytes
            || !string.Equals(sha256, actualHash, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(actualHash, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The runtime upload receipt for {descriptor.Role} does not match the bytes that were uploaded.");
        }
    }

    private static async Task<PreparedEvidence> SendPrepareAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        IReadOnlyList<AssetDescriptor> assets,
        string transactionId,
        InspectEvidence inspect,
        CancellationToken token)
    {
        var assetPayloads = new object[assets.Count];
        for (var index = 0; index < assets.Count; index++)
        {
            var asset = assets[index];
            assetPayloads[index] = new { role = asset.Role, bytes = asset.Bytes, sha256 = asset.Sha256 };
        }

        var body = JsonSerializer.Serialize(new
        {
            transactionId,
            expected = new
            {
                model = inputs.Identity.Model,
                socSerial = inspect.SocSerial,
                bootId = connection.BootId,
                diskPath = inputs.CurrentTable.DeviceId,
                diskBytes = inputs.CurrentTable.DiskBytes,
                sectorSize = inputs.CurrentTable.SectorSize,
                tableFingerprint = inputs.CurrentTableFingerprint,
                currentBootFingerprint = inspect.CurrentBootFingerprint,
                miscFingerprint = inspect.MiscFingerprint,
            },
            ownedPartitions = new
            {
                userdataPartUuid = inputs.Record.UserdataPartUuid,
                linuxBootPartUuid = inputs.Record.LinuxBootPartUuid,
                linuxRootPartUuid = inputs.Record.LinuxRootPartUuid,
            },
            assets = assetPayloads,
        });

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body);

        // A cancellation before the prepare is on the wire is ordinary cancellation. From the next line on,
        // the runtime may already have accepted the transaction, so every ambiguous outcome has to retain the
        // generated id and be resolved by reading this transaction's status only.
        token.ThrowIfCancellationRequested();

        JsonDocument document;
        try
        {
            document = await SendJsonAsync(
                    http,
                    connection,
                    HttpMethod.Post,
                    "/v1/prepare",
                    content,
                    MetadataTimeout,
                    token)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException exception) when (IsClientRefusal(exception))
        {
            // An explicit 4xx is a concrete refusal, not an unknown outcome.
            throw;
        }
        catch (HttpRequestException exception)
        {
            throw PrepareUncertain(transactionId, exception);
        }
        catch (TimeoutException exception)
        {
            throw PrepareUncertain(transactionId, exception);
        }
        catch (InvalidDataException exception)
        {
            throw PrepareUncertain(transactionId, exception);
        }
        catch (IOException exception)
        {
            throw PrepareUncertain(transactionId, exception);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw PrepareUncertain(transactionId, null);
        }

        using (document)
        {
            // A response that arrived intact is validated as proof. Its evidence errors are never turned
            // into transport ambiguity: only the send and the response read above are ambiguous.
            return ReadPreparedResponse(document.RootElement, transactionId, connection, inputs, assets);
        }
    }

    /// <summary>
    /// Resolves an unknown prepare outcome by reading only the same transaction's status and requiring the
    /// same complete prepared proof the prepare response would have to carry. No request is retransmitted.
    /// </summary>
    private static async Task<PreparedEvidence> ResolvePrepareByStatusAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        IReadOnlyList<AssetDescriptor> assets,
        string transactionId,
        CancellationToken token)
    {
        try
        {
            using var document = await SendJsonAsync(
                    http,
                    connection,
                    HttpMethod.Get,
                    $"/v1/transactions/{transactionId}/status",
                    content: null,
                    MetadataTimeout,
                    token)
                .ConfigureAwait(false);

            return ReadPreparedResponse(document.RootElement, transactionId, connection, inputs, assets);
        }
        catch (Exception exception) when (
            IsUnreadableStatus(exception) || exception is OperationCanceledException)
        {
            throw PrepareUncertain(transactionId, exception);
        }
    }

    private static UninstallTransactionUncertainException PrepareUncertain(
        string transactionId, Exception? inner)
    {
        var message =
            $"The prepare request for transaction '{transactionId}' may have been accepted, but its outcome " +
            "could not be read; query this transaction's status before doing anything else.";

        return inner is null
            ? new UninstallTransactionUncertainException(transactionId, "prepare", message)
            : new UninstallTransactionUncertainException(transactionId, "prepare", message, inner);
    }

    private static PreparedEvidence ReadPreparedResponse(
        JsonElement root,
        string transactionId,
        HttpUninstallConnection connection,
        ValidatedUninstallInputs inputs,
        IReadOnlyList<AssetDescriptor> assets)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The prepare response is not a JSON object.");
        }

        if (RequireInt64(root, "schemaVersion") != 1)
        {
            throw new InvalidDataException("The prepare response does not use schema version 1.");
        }

        RequireSameGuid(root, "transactionId", transactionId, "transaction id");
        RequireSameGuid(root, "bootId", connection.BootId, "boot id");

        if (!string.Equals(RequireNonEmptyString(root, "state"), "prepared", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The runtime did not return a prepared transaction.");
        }

        RequireNonEmptyString(root, "stage");

        if (!string.Equals(ReadNullableString(root, "nextStep", required: true), RestoreBootAStep, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The prepared transaction does not start at restore-boot-a.");
        }

        if (ReadNullableString(root, "activeStep", required: true) is not null)
        {
            throw new InvalidDataException("The prepared transaction reports an active step.");
        }

        if (ReadCompletedSteps(root, requireEmpty: true).Length != 0)
        {
            throw new InvalidDataException("The prepared transaction already reports completed steps.");
        }

        var planFingerprint = RequireHex64(root, "planFingerprint");
        var stockFingerprint = RequireHex64(root, "stockFingerprint");

        if (RequireBool(root, "backupAcknowledged"))
        {
            throw new InvalidDataException("The read-only prepare reports acknowledged backups.");
        }

        if (!RequireBool(root, "bothStockBootsValid"))
        {
            throw new InvalidDataException("The runtime did not prove both stock boot slots during prepare.");
        }

        var confirmationToken = RequireNonEmptyString(root, "confirmationToken");
        RequireNull(root, "error");

        var plan = inputs.Plan;
        if (RequireInt64(root, "restoredAndroidBytes") != plan.RestoredAndroidBytes
            || RequireInt64(root, "userdataStartSector") != plan.UserdataStartSector
            || RequireInt64(root, "userdataEndSectorExclusive") != plan.UserdataEndSectorExclusive)
        {
            throw new InvalidDataException("The prepared restore bounds differ from the validated plan.");
        }

        RequireRemovedPartitionNumbers(root, plan);

        var evidence = RequireObject(root, "slotEvidence");
        var slots = new List<UninstallStockSlotEvidence>(2);
        for (var index = 0; index < 2; index++)
        {
            var slot = index == 0 ? "a" : "b";
            var node = RequireObject(evidence, slot);

            if (!string.Equals(RequireNonEmptyString(node, "slot"), slot, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"The prepared evidence for slot {slot} names another slot.");
            }

            var fingerprint = RequireNonEmptyString(node, "fingerprint");
            var sha256 = RequireHex64(node, "sha256");
            var rootKey = RequireHex64(node, "rootKeySha256");
            var bootKey = RequireHex64(node, "bootKeySha256");

            if (RequireBool(node, "hardwareRollbackVerified"))
            {
                throw new InvalidDataException(
                    "The runtime claims hardware anti-rollback was verified, which the host cannot accept.");
            }

            var expectedAsset = FindAsset(assets, slot == "a" ? "stock_boot_a" : "stock_boot_b");
            if (!string.Equals(sha256, expectedAsset.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The prepared evidence for slot {slot} does not name the uploaded stock image.");
            }

            slots.Add(new UninstallStockSlotEvidence(
                slot, fingerprint, sha256, rootKey, bootKey, HardwareRollbackVerified: false));
        }

        return new PreparedEvidence(
            planFingerprint,
            stockFingerprint,
            confirmationToken,
            Array.AsReadOnly(slots.ToArray()));
    }

    private static void RequireRemovedPartitionNumbers(JsonElement root, AndroidRestorePlan plan)
    {
        var array = RequireArray(root, "removedPartitionNumbers");
        if (array.GetArrayLength() != plan.RemovedPartitionNumbers.Count)
        {
            throw new InvalidDataException("The prepared removed partition numbers differ from the validated plan.");
        }

        var index = 0;
        foreach (var element in array.EnumerateArray())
        {
            var value = ReadInteger(element, "removedPartitionNumbers");
            if (value != plan.RemovedPartitionNumbers[index])
            {
                throw new InvalidDataException(
                    "The prepared removed partition numbers differ from the validated plan.");
            }

            index++;
        }
    }

    private async Task<UninstallTransactionStatus> FetchStatusAsync(
        bool requireBackupAcknowledged, CancellationToken token)
    {
        using var document = await SendJsonAsync(
                _http,
                _connection,
                HttpMethod.Get,
                $"/v1/transactions/{TransactionId}/status",
                content: null,
                MetadataTimeout,
                token)
            .ConfigureAwait(false);

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The transaction status is not a JSON object.");
        }

        if (RequireInt64(root, "schemaVersion") != 1)
        {
            throw new InvalidDataException("The transaction status does not use schema version 1.");
        }

        RequireSameGuid(root, "transactionId", TransactionId, "transaction id");
        RequireSameGuid(root, "bootId", _connection.BootId, "boot id");

        var state = RequireNonEmptyString(root, "state");
        if (!IsTransactionState(state))
        {
            throw new InvalidDataException($"The runtime reports the unknown transaction state '{state}'.");
        }

        var stage = RequireNonEmptyString(root, "stage");
        var nextStep = ReadNullableString(root, "nextStep", required: true);
        var activeStep = ReadNullableString(root, "activeStep", required: true);
        var completed = ReadCompletedSteps(root, requireEmpty: false);

        var planFingerprint = RequireHex64(root, "planFingerprint");
        var stockFingerprint = RequireHex64(root, "stockFingerprint");

        if (!string.Equals(planFingerprint, PlanFingerprint, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(stockFingerprint, _stockFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The runtime transaction no longer names the prepared plan and stock evidence.");
        }

        var backupAcknowledged = RequireBool(root, "backupAcknowledged");
        if (requireBackupAcknowledged && !backupAcknowledged)
        {
            throw new InvalidOperationException(
                "The runtime has not acknowledged the current boot backups for this transaction.");
        }

        var error = ReadError(root);

        var status = new UninstallTransactionStatus(
            TransactionId,
            _connection.BootId,
            state,
            stage,
            nextStep,
            planFingerprint,
            backupAcknowledged,
            error)
        {
            ActiveStep = activeStep,
            CompletedSteps = Array.AsReadOnly(completed),
        };

        ValidateStatusInvariants(status);
        return status;
    }

    /// <summary>
    /// Proves that the reported state, active and next step, completed prefix and error belong together. A status
    /// that contradicts the fixed step order is unreadable evidence, never something to act on.
    /// </summary>
    private static void ValidateStatusInvariants(UninstallTransactionStatus status)
    {
        var completed = status.CompletedSteps;
        if (completed.Count > FixedSteps.Length)
        {
            throw new InvalidDataException(
                "The runtime reports more completed steps than this transaction has.");
        }

        for (var index = 0; index < completed.Count; index++)
        {
            if (!string.Equals(completed[index], FixedSteps[index], StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The runtime reports completed steps that are not the exact fixed prefix.");
            }
        }

        // Every completed write must have followed an acknowledged host backup, in every state, including
        // prepared and failed. A non-empty completion without that acknowledgement is contradictory evidence.
        if (completed.Count > 0 && !status.BackupAcknowledged)
        {
            throw new InvalidDataException(
                "The runtime reports completed steps without acknowledged host backups.");
        }

        var next = NextUncompletedStep(completed);

        switch (status.State)
        {
            case "prepared":
                if (status.Error is not null
                    || status.ActiveStep is not null
                    || next is null
                    || !string.Equals(status.NextStep, next, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The prepared transaction status contradicts the fixed step order.");
                }

                break;

            case "running":
                if (status.Error is not null
                    || next is null
                    || !status.BackupAcknowledged
                    || !string.Equals(status.ActiveStep, next, StringComparison.Ordinal)
                    || !string.Equals(status.NextStep, next, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The running transaction status contradicts the fixed step order.");
                }

                break;

            case "awaitingFactoryReset":
                if (status.Error is not null
                    || status.ActiveStep is not null
                    || status.NextStep is not null
                    || completed.Count != FixedSteps.Length
                    || !status.BackupAcknowledged)
                {
                    throw new InvalidDataException(
                        "The transaction awaiting the factory reset does not report every fixed step complete.");
                }

                break;

            case "failed":
                if (status.Error is null
                    || !(status.NextStep is null
                        || string.Equals(status.NextStep, next, StringComparison.Ordinal)))
                {
                    throw new InvalidDataException(
                        "The failed transaction status does not name a real failure or is not safe to stop at.");
                }

                break;
        }
    }

    private static string? ReadError(JsonElement root)
    {
        if (!root.TryGetProperty("error", out var error))
        {
            throw new InvalidDataException("The transaction status is missing the 'error' field.");
        }

        if (error.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (error.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The transaction 'error' field is neither null nor an object.");
        }

        var code = RequireNonEmptyString(error, "code");
        var message = RequireNonEmptyString(error, "message");
        return code + ": " + message;
    }

    private static bool IsTransactionState(string state)
    {
        foreach (var candidate in TransactionStates)
        {
            if (string.Equals(state, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] ReadCompletedSteps(JsonElement root, bool requireEmpty)
    {
        var array = RequireArray(root, "completedSteps");
        var steps = new string[array.GetArrayLength()];

        var index = 0;
        foreach (var element in array.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                throw new InvalidDataException("A completed step is not a string.");
            }

            var step = element.GetString();
            if (string.IsNullOrWhiteSpace(step))
            {
                throw new InvalidDataException("A completed step is empty.");
            }

            steps[index++] = step;
        }

        if (requireEmpty && steps.Length != 0)
        {
            throw new InvalidDataException("The prepared transaction already reports completed steps.");
        }

        return steps;
    }

    private static string? ReadNullableString(JsonElement parent, string name, bool required)
    {
        if (!parent.TryGetProperty(name, out var element))
        {
            if (required)
            {
                throw new InvalidDataException($"The document is missing the '{name}' field.");
            }

            return null;
        }

        if (element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"The '{name}' field is neither null nor a string.");
        }

        var text = element.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidDataException($"The '{name}' field is an empty string.");
        }

        return text;
    }

    private static async Task<JsonDocument> SendJsonAsync(
        HttpClient http,
        HttpUninstallConnection connection,
        HttpMethod method,
        string relativePath,
        HttpContent? content,
        TimeSpan timeout,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var expectedUri = new Uri(connection.BaseAddress, relativePath);
        using var request = new HttpRequestMessage(method, expectedUri) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", connection.BearerToken);

        try
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutSource.CancelAfter(timeout);

            HttpResponseMessage response;
            try
            {
                response = await http
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutSource.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"The runtime did not answer {method} {relativePath} within {timeout.TotalSeconds:0} seconds.");
            }

            using (response)
            {
                if (response.RequestMessage?.RequestUri is { } actualUri
                    && !string.Equals(actualUri.AbsoluteUri, expectedUri.AbsoluteUri, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"The runtime answered from {actualUri} instead of the requested {expectedUri}; redirects are refused.");
                }

                if (response.Content is null)
                {
                    throw new InvalidDataException($"The runtime answered {method} {relativePath} without a body.");
                }

                string text;
                try
                {
                    text = await response.Content.ReadAsStringAsync(timeoutSource.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"The runtime did not finish {method} {relativePath} within {timeout.TotalSeconds:0} seconds.");
                }

                if (!response.IsSuccessStatusCode)
                {
                    var statusCode = (int)response.StatusCode;

                    try
                    {
                        using var errorDocument = JsonDocument.Parse(text, DocumentOptions);
                        var errorRoot = errorDocument.RootElement;
                        if (errorRoot.ValueKind == JsonValueKind.Object
                            && errorRoot.TryGetProperty("error", out var error)
                            && error.ValueKind == JsonValueKind.Object
                            && error.TryGetProperty("code", out var codeElement)
                            && codeElement.ValueKind == JsonValueKind.String
                            && error.TryGetProperty("message", out var messageElement)
                            && messageElement.ValueKind == JsonValueKind.String)
                        {
                            var codeText = codeElement.GetString() ?? string.Empty;
                            var messageText = messageElement.GetString() ?? string.Empty;
                            var stageText = error.TryGetProperty("stage", out var stageElement)
                                && stageElement.ValueKind == JsonValueKind.String
                                    ? stageElement.GetString()
                                    : null;

                            if (!string.IsNullOrWhiteSpace(codeText) && !string.IsNullOrWhiteSpace(messageText))
                            {
                                var bearer = connection.BearerToken;
                                if (!string.IsNullOrEmpty(bearer))
                                {
                                    codeText = codeText.Replace(bearer, "[redacted]", StringComparison.Ordinal);
                                    messageText = messageText.Replace(bearer, "[redacted]", StringComparison.Ordinal);
                                    stageText = stageText?.Replace(bearer, "[redacted]", StringComparison.Ordinal);
                                }

                                throw new HttpRequestException(
                                    $"The runtime answered {method} {relativePath} with HTTP {statusCode}: " +
                                    $"{codeText}: {messageText}" +
                                    (string.IsNullOrWhiteSpace(stageText) ? "." : $" (stage {stageText})."),
                                    null,
                                    response.StatusCode);
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        // Malformed error body: fall through to the HTTP-only diagnostic.
                    }

                    throw new HttpRequestException(
                        $"The runtime answered {method} {relativePath} with HTTP {statusCode}.",
                        null,
                        response.StatusCode);
                }

                try
                {
                    return JsonDocument.Parse(text, DocumentOptions);
                }
                catch (JsonException exception)
                {
                    throw new InvalidDataException(
                        $"The runtime answer to {method} {relativePath} is not valid JSON.", exception);
                }
            }
        }
        finally
        {
            // The caller owns the request content and reads back the transmitted hash after this returns.
            // Detach it so disposal of the request message cannot dispose the upload stream first.
            request.Content = null;
        }
    }

    private static GptPartition? FindPartition(GptTable table, int number)
    {
        foreach (var partition in table.Partitions)
        {
            if (partition.Number == number)
            {
                return partition;
            }
        }

        return null;
    }

    private static AssetDescriptor FindAsset(IReadOnlyList<AssetDescriptor> assets, string role)
    {
        foreach (var asset in assets)
        {
            if (string.Equals(asset.Role, role, StringComparison.Ordinal))
            {
                return asset;
            }
        }

        throw new InvalidOperationException($"The fixed asset role {role} is missing from the upload set.");
    }

    private static void RequireSameGuid(JsonElement parent, string name, string expected, string what)
    {
        var actual = RequireGuid(parent, name);
        var canonical = CanonicalGuid(expected);
        if (!string.Equals(actual, canonical, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"The runtime {what} is not the one this transaction uses.");
        }
    }

    private static JsonElement RequireObject(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"The document is missing the '{name}' object.");
        }

        return element;
    }

    private static JsonElement RequireArray(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"The document is missing the '{name}' array.");
        }

        return element;
    }

    private static void RequireNull(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Null)
        {
            throw new InvalidDataException($"The '{name}' field is not null.");
        }
    }

    private static string RequireString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"The document is missing the '{name}' string.");
        }

        return element.GetString() ?? string.Empty;
    }

    private static string RequireNonEmptyString(JsonElement parent, string name)
    {
        var text = RequireString(parent, name);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidDataException($"The '{name}' field is empty.");
        }

        return text;
    }

    private static string RequireStringOrEmpty(JsonElement parent, string name)
        => parent.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString() ?? string.Empty
            : string.Empty;

    private static bool RequireBool(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element)
            || (element.ValueKind != JsonValueKind.True && element.ValueKind != JsonValueKind.False))
        {
            throw new InvalidDataException($"The document is missing the '{name}' boolean.");
        }

        return element.GetBoolean();
    }

    private static int RequireInt32(JsonElement parent, string name)
    {
        var value = RequireInt64(parent, name);
        if (value is < int.MinValue or > int.MaxValue)
        {
            throw new InvalidDataException($"The '{name}' field is outside the 32-bit range.");
        }

        return (int)value;
    }

    private static long RequireInt64(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var element))
        {
            throw new InvalidDataException($"The document is missing the '{name}' field.");
        }

        return ReadInteger(element, name);
    }

    private static long ReadInteger(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value))
        {
            throw new InvalidDataException($"The '{name}' field is not a representable integer.");
        }

        return value;
    }

    private static string RequireGuid(JsonElement parent, string name)
    {
        var text = RequireNonEmptyString(parent, name);
        if (!Guid.TryParse(text, out var value) || value == Guid.Empty)
        {
            throw new InvalidDataException($"The '{name}' field is not a non-zero GUID.");
        }

        return value.ToString("D").ToUpperInvariant();
    }

    private static string RequireHex64(JsonElement parent, string name)
    {
        var text = RequireNonEmptyString(parent, name);
        if (text.Length != HexSha256Length)
        {
            throw new InvalidDataException($"The '{name}' field is not a 64 character hexadecimal digest.");
        }

        foreach (var character in text)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                throw new InvalidDataException($"The '{name}' field is not a hexadecimal digest.");
            }
        }

        return text;
    }

    private static string RequireSafeDevicePath(JsonElement parent, string name)
    {
        var path = RequireNonEmptyString(parent, name);
        if (!path.StartsWith("/dev/sd", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"The '{name}' field is not a /dev/sd* device path.");
        }

        foreach (var character in path.AsSpan("/dev/sd".Length))
        {
            if (!char.IsAsciiLetterOrDigit(character))
            {
                throw new InvalidDataException($"The '{name}' field is not a safe /dev/sd* device path.");
            }
        }

        return path;
    }

    private static string CanonicalGuid(string value)
        => Guid.TryParse(value, out var parsed) ? parsed.ToString("D").ToUpperInvariant() : value;

    private static string ToHexLower(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private sealed record InspectEvidence(
        string CurrentBootFingerprint,
        string MiscFingerprint,
        OtaUpdateState OtaState,
        bool MaintenanceValidated,
        string SocSerial,
        PartitionDescriptor BootA,
        PartitionDescriptor BootB,
        PartitionDescriptor Misc);

    /// <summary>Immutable descriptor of one fixed metadata role as reported by the strict inspect.</summary>
    private sealed record PartitionDescriptor(
        string Role,
        string PartitionPath,
        string PartUuid,
        long Bytes,
        string Sha256);

    /// <summary>The exact local backup of one role: the durable file, its length and its digest.</summary>
    private sealed record HostBackupEntry(string Role, string FileName, long Bytes, string Sha256);

    private sealed record AssetDescriptor(string Role, string Path, long Bytes, string Sha256)
    {
        internal AssetDescriptor(string role, string path, FileMeasurement measurement)
            : this(role, path, measurement.Bytes, measurement.Sha256)
        {
        }
    }

    private sealed record FileMeasurement(long Bytes, string Sha256);

    private sealed record PreparedEvidence(
        string PlanFingerprint,
        string StockFingerprint,
        string ConfirmationToken,
        IReadOnlyList<UninstallStockSlotEvidence> Slots);

    /// <summary>
    /// Counts and hashes exactly the bytes a request body actually reads, so an upload receipt is compared
    /// against the transmitted stream rather than against a hash computed from a file that may have changed.
    /// </summary>
    private sealed class HashingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _limit;
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long _read;
        private string? _finalHash;
        private bool _disposed;

        internal HashingReadStream(Stream inner, long limit)
        {
            _inner = inner;
            _limit = limit;
        }

        internal long BytesRead => _read;

        /// <summary>
        /// The digest of exactly the bytes that were transmitted. The digest is finalized as soon as the
        /// last permitted byte is appended, so it stays available even when the consumer disposes this
        /// non-seekable stream before the receipt is compared.
        /// </summary>
        /// <exception cref="InvalidDataException">The stream did not transmit all of its declared bytes.</exception>
        internal string CompleteHash()
        {
            if (_read != _limit)
            {
                throw new InvalidDataException(
                    $"The upload stream transmitted {_read} of {_limit} declared bytes, so no complete hash exists.");
            }

            if (_finalHash is null)
            {
                _finalHash = ToHexLower(_hash.GetHashAndReset());
            }

            return _finalHash;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _limit;

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var allowed = Allowed(count);
            if (allowed == 0)
            {
                return 0;
            }

            var read = _inner.Read(buffer, offset, allowed);
            Append(buffer.AsSpan(offset, read));
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var allowed = Allowed(buffer.Length);
            if (allowed == 0)
            {
                return 0;
            }

            var read = await _inner.ReadAsync(buffer[..allowed], cancellationToken).ConfigureAwait(false);
            Append(buffer.Span[..read]);
            return read;
        }

        public override Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                _hash.Dispose();
            }

            base.Dispose(disposing);
        }

        private int Allowed(int requested)
        {
            var remaining = _limit - _read;
            if (remaining <= 0 || requested <= 0)
            {
                return 0;
            }

            return (int)Math.Min(requested, remaining);
        }

        private void Append(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length == 0)
            {
                return;
            }

            _hash.AppendData(bytes);
            _read += bytes.Length;

            if (_read == _limit && _finalHash is null)
            {
                _finalHash = ToHexLower(_hash.GetHashAndReset());
            }
        }
    }
}
