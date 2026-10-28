using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for a prepare whose response was lost, cancelled or answered with 5xx after the runtime had
/// already accepted the transaction. The runtime state is still the untouched prepared transaction, so the
/// host must read it back by the id it generated instead of preparing a second but identically shaped
/// transaction or uploading the assets again.
/// <para>
/// Every test runs against the recording fake of <see cref="HttpHostFixture"/>: the override makes the
/// prepare answer disappear only after the fake stored the exact prepared document it would have returned.
/// There is no socket, no device and no runtime here.
/// </para>
/// <para>
/// The assertions cover the recovery behaviour and never assert on a stub exception, and never accept a
/// broad <see cref="Exception"/> as the expected outcome.
/// </para>
/// </summary>
public sealed class HttpUninstallPrepareRecoveryTests
{
    // Response lost after the runtime accepted the prepared state: the same id must come back from status.

    [Fact]
    public async Task DropAfterPrepareAccepted_RecoversByStatusWithoutSecondPrepare()
    {
        using var host = new HttpHostFixture();

        host.Handler.PreparedResponseOverride = (_, _) =>
            throw new HttpRequestException("connection dropped after the runtime accepted prepare");
        host.Handler.ExtraResponse = (request, _) => Task.FromResult(StatusResponse(host.Handler, request));

        var backend = await HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            CancellationToken.None);

        var savedId = SavedTransactionId(host.Handler);
        Assert.Equal(savedId, backend.TransactionId);

        var requests = host.Handler.Requests;
        Assert.Equal(1, requests.Count(request => request.Signature == "POST /v1/prepare"));
        Assert.Equal(5, requests.Count(request => request.Method == "PUT"));

        var statusReads = requests.Count(request => request.Signature == StatusSignature(savedId));
        Assert.True(statusReads >= 1, "the host must prove the accepted transaction through its status");

        AssertNoAcknowledgementOrStep(requests);
    }

    // Unknown prepare outcome with an unreadable first status read: the id is retained, and the recovery
    // method only reads.

    [Fact]
    public async Task PrepareUnknown_ExposesId_AndRecoverIsPureReadOnly()
    {
        using var host = new HttpHostFixture();

        host.Handler.PreparedResponseOverride = (_, _) =>
            throw new TimeoutException("prepare response did not arrive in time");
        host.Handler.ExtraResponse = (_, _) =>
            throw new HttpRequestException("transaction status could not be read either");

        var failure = await Record.ExceptionAsync(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            CancellationToken.None));

        var uncertain = Assert.IsType<UninstallTransactionUncertainException>(failure);
        var savedId = SavedTransactionId(host.Handler);
        Assert.Equal("prepare", uncertain.Step);
        Assert.Equal(savedId, uncertain.TransactionId);

        // The runtime still holds exactly that transaction; only the read path was failing.
        host.Handler.ExtraResponse = (request, _) => Task.FromResult(StatusResponse(host.Handler, request));

        var mark = host.Handler.Requests.Count;

        var recovered = await HttpUninstallBackend.RecoverPreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            uncertain.TransactionId,
            CancellationToken.None);

        Assert.Equal(uncertain.TransactionId, recovered.TransactionId);

        var requests = host.Handler.Requests;
        Assert.Equal(1, requests.Count(request => request.Signature == "POST /v1/prepare"));
        Assert.Equal(5, requests.Count(request => request.Method == "PUT"));
        AssertNoAcknowledgementOrStep(requests);

        var recoveryRequests = requests.Skip(mark).ToArray();
        Assert.NotEmpty(recoveryRequests);
        Assert.All(recoveryRequests, request => Assert.Equal("GET", request.Method));
        Assert.Contains(recoveryRequests, request => request.Signature == StatusSignature(uncertain.TransactionId));

        // The caller still gets its own transaction child under the chosen backup root, not a fresh one.
        Assert.False(string.IsNullOrWhiteSpace(recovered.BackupDirectory));
        Assert.Equal(Path.GetFullPath(host.BackupRoot), Path.GetDirectoryName(recovered.BackupDirectory));
        Assert.Contains(recovered.TransactionId, Path.GetFileName(recovered.BackupDirectory));
    }

    // A 5xx after the runtime accepted the transaction is not proof that prepare failed.

    [Fact]
    public async Task Http503AfterPrepareAccepted_StatusProvesSameTransaction()
    {
        using var host = new HttpHostFixture();

        host.Handler.PreparedResponseOverride = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = new StringContent(
                "{\"error\":{\"code\":\"REPLY_UNAVAILABLE\",\"message\":\"fake after accepted\"}}",
                Encoding.UTF8,
                "application/json"),
        });
        host.Handler.ExtraResponse = (request, _) => Task.FromResult(StatusResponse(host.Handler, request));

        var backend = await HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            CancellationToken.None);

        var savedId = SavedTransactionId(host.Handler);
        Assert.Equal(savedId, backend.TransactionId);

        var requests = host.Handler.Requests;
        Assert.Equal(1, requests.Count(request => request.Signature == "POST /v1/prepare"));
        Assert.Equal(5, requests.Count(request => request.Method == "PUT"));
        Assert.Contains(requests, request => request.Signature == StatusSignature(savedId));

        AssertNoAcknowledgementOrStep(requests);
    }

    // The caller cancels after the prepare request was already sent. The id is still the only way back.

    [Fact]
    public async Task CancelAfterPreparePost_StillRetainsSameIdForReadOnlyRecovery()
    {
        using var host = new HttpHostFixture();
        using var caller = new CancellationTokenSource();

        host.Handler.PreparedResponseOverride = (_, _) =>
        {
            caller.Cancel();
            throw new OperationCanceledException(caller.Token);
        };
        host.Handler.ExtraResponse = (_, _) =>
            throw new HttpRequestException("transaction status is not readable yet");

        var failure = await Record.ExceptionAsync(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            caller.Token));

        var uncertain = Assert.IsType<UninstallTransactionUncertainException>(failure);
        var savedId = SavedTransactionId(host.Handler);
        Assert.Equal("prepare", uncertain.Step);
        Assert.Equal(savedId, uncertain.TransactionId);

        // Cancellation belongs to the caller, not to the runtime: a fresh read must be allowed.
        host.Handler.ExtraResponse = (request, _) => Task.FromResult(StatusResponse(host.Handler, request));

        var requestsBeforeRecovery = host.Handler.Requests.ToArray();
        var prepareCount = requestsBeforeRecovery.Count(request => request.Signature == "POST /v1/prepare");
        var putCount = requestsBeforeRecovery.Count(request => request.Method == "PUT");

        var recovered = await HttpUninstallBackend.RecoverPreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            uncertain.TransactionId,
            CancellationToken.None);

        Assert.Equal(uncertain.TransactionId, recovered.TransactionId);

        var requests = host.Handler.Requests;
        Assert.Equal(prepareCount, requests.Count(request => request.Signature == "POST /v1/prepare"));
        Assert.Equal(putCount, requests.Count(request => request.Method == "PUT"));
        AssertNoAcknowledgementOrStep(requests);

        var recoveryRequests = requests.Skip(requestsBeforeRecovery.Length).ToArray();
        Assert.NotEmpty(recoveryRequests);
        Assert.All(recoveryRequests, request => Assert.Equal("GET", request.Method));
    }

    private static string StatusSignature(string transactionId)
        => "GET /v1/transactions/" + transactionId + "/status";

    private static string SavedTransactionId(RecordingHostHandler handler)
    {
        Assert.False(string.IsNullOrWhiteSpace(handler.LastPreparedJson));
        using var document = JsonDocument.Parse(handler.LastPreparedJson!);
        var id = document.RootElement.GetProperty("transactionId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(id));
        return id!;
    }

    /// <summary>
    /// Serves exactly the prepared document the fake recorded for the accepted prepare request, so the status
    /// read can only succeed if it names the same transaction the caller generated.
    /// </summary>
    private static HttpResponseMessage StatusResponse(RecordingHostHandler handler, RecordedHttpRequest request)
    {
        Assert.Equal("GET", request.Method);
        Assert.False(string.IsNullOrWhiteSpace(handler.LastPreparedJson));

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(handler.LastPreparedJson!, Encoding.UTF8, "application/json"),
        };
    }

    private static void AssertNoAcknowledgementOrStep(IEnumerable<RecordedHttpRequest> requests)
    {
        Assert.DoesNotContain(requests, request => request.Signature == "POST /v1/ack-backups");
        Assert.DoesNotContain(
            requests,
            request => request.Path.StartsWith("/v1/transactions/", StringComparison.Ordinal)
                && !string.Equals(request.Method, "GET", StringComparison.Ordinal));
        Assert.DoesNotContain(requests, request => request.Path.StartsWith("/v1/boot/", StringComparison.Ordinal));
    }
}
