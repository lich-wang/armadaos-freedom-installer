using System.Net;
using System.Net.Http;
using System.Text;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class TcpMaintenanceTransferLifecycleTests
{
    [Fact]
    public void Constructor_WithNullHttpClient_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new TcpMaintenanceTransfer(null!));
    }

    [Fact]
    public async Task Dispose_DoesNotDisposeInjectedHttpClient()
    {
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
        var client = new HttpClient(handler, disposeHandler: false);
        var transfer = new TcpMaintenanceTransfer(client);

        transfer.Dispose();

        using var response = await client.GetAsync(MaintenanceTransferTestData.RootBaseAddress);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public void DefaultConstructor_OwnsDefaultClient_AndIsIdempotentlyDisposable()
    {
        var transfer = new TcpMaintenanceTransfer();

        transfer.Dispose();
        transfer.Dispose();
    }
}

public sealed class TcpMaintenanceTransferUploadValidationTests
{
    [Theory]
    [InlineData("192.168.77.2")]
    [InlineData("192.168.77.1 ")]
    [InlineData(" 192.168.77.1")]
    [InlineData("localhost")]
    [InlineData("::1")]
    [InlineData("")]
    public async Task Upload_RejectsNonCanonicalHost(string host)
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync(host, 8201, MaintenanceTransferTestData.Payload(4), 4));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Theory]
    [InlineData(8202)]
    [InlineData(80)]
    [InlineData(0)]
    [InlineData(65535)]
    public async Task Upload_RejectsNonCanonicalPort(int port)
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync("192.168.77.1", port, MaintenanceTransferTestData.Payload(4), 4));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(512L * 1024 * 1024 + 1)]
    public async Task Upload_RejectsExpectedLengthOutsideOneByteTo512MiB(long expectedBytes)
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync("192.168.77.1", 8201, MaintenanceTransferTestData.Payload(4), expectedBytes));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Theory]
    [InlineData(10, 0, 9L)]
    [InlineData(10, 0, 11L)]
    [InlineData(10, 2, 9L)]
    public async Task Upload_RejectsSeekableStreamWhoseRemainingBytesDifferFromExpectedLength(
        int length,
        int position,
        long expectedBytes)
    {
        var stream = new MemoryStream(new byte[length]) { Position = position };
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync("192.168.77.1", 8201, stream, expectedBytes));

            Assert.IsAssignableFrom<InvalidDataException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Upload_RejectsNonReadableStream()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync("192.168.77.1", 8201, new MaintenanceTransferWriteOnlyStream(), 4));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Upload_RejectsNullStream()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.UploadAsync("192.168.77.1", 8201, null!, 4));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Upload_PreCanceledToken_ThrowsOperationCanceledBeforeAnyValidation()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();

        using (client)
        using (transfer)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => transfer.UploadAsync("192.168.77.1", 8201, MaintenanceTransferTestData.Payload(4), 4, canceled.Token));

            Assert.Equal(0, handler.CallCount);
        }
    }
}

public sealed class TcpMaintenanceTransferInspectValidationTests
{
    public static TheoryData<string> NonCanonicalBaseAddresses => new()
    {
        "http://192.168.77.2:8202/",
        "https://192.168.77.1:8202/",
        "http://192.168.77.1:8201/",
        "http://192.168.77.1/",
        "http://192.168.77.1:8202/v1/inspect",
        "http://192.168.77.1:8202/v1",
        "http://192.168.77.1:8202/?probe=1",
        "http://192.168.77.1:8202/#frag",
        "http://user:pass@192.168.77.1:8202/",
    };

    public static TheoryData<string> InvalidBearerTokens => new()
    {
        string.Empty,
        new string('a', 63),
        new string('a', 65),
        new string('a', 63) + "z",
        new string('a', 63) + "-",
        "Bearer " + new string('a', 57),
    };

    [Theory]
    [MemberData(nameof(NonCanonicalBaseAddresses))]
    public async Task Inspect_RejectsNonCanonicalBaseAddress_WithoutCallingHandler(string baseAddress)
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.InspectAsync(new Uri(baseAddress), MaintenanceTransferTestData.ValidToken));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Inspect_RejectsRelativeBaseAddress()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.InspectAsync(new Uri("/v1/inspect", UriKind.Relative), MaintenanceTransferTestData.ValidToken));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Theory]
    [MemberData(nameof(InvalidBearerTokens))]
    public async Task Inspect_RejectsNonCanonicalBearerToken_WithoutCallingHandler(string bearerToken)
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, bearerToken));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Inspect_RejectsNullBearerToken()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, null!));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Inspect_RejectedBearerToken_IsNotEchoedInExceptionText()
    {
        string token = new string('a', 63) + "z";
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();

        using (client)
        using (transfer)
        {
            var ex = await MaintenanceTransferTestData.ExpectRejectionAsync(
                () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, token));

            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.False(ex.ToString().Contains(token, StringComparison.Ordinal));
            Assert.False(transfer.ToString().Contains(token, StringComparison.Ordinal));
            Assert.Equal(0, handler.CallCount);
        }
    }

    [Fact]
    public async Task Inspect_PreCanceledToken_ThrowsOperationCanceledWithoutCallingHandler()
    {
        var (client, transfer, handler) = MaintenanceTransferTestData.CreateTransfer();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();

        using (client)
        using (transfer)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, MaintenanceTransferTestData.ValidToken, canceled.Token));

            Assert.Equal(0, handler.CallCount);
        }
    }
}

public sealed class TcpMaintenanceTransferInspectBehaviorTests
{
    private const long MaxResponseBytes = 2L * 1024 * 1024;

    [Fact]
    public async Task Inspect_RequestsExactEndpointWithBearerAndReturnsRawBody()
    {
        const string body = "{\"device\":\"freedom\",\"status\":\"ready\"}";
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });

        using var client = new HttpClient(handler, disposeHandler: false);
        using var transfer = new TcpMaintenanceTransfer(client);

        string result = await transfer.InspectAsync(
            MaintenanceTransferTestData.RootBaseAddress,
            MaintenanceTransferTestData.ValidToken);

        Assert.Equal(body, result);
        Assert.Equal(1, handler.CallCount);
        Assert.Equal(HttpMethod.Get, handler.LastMethod);
        Assert.Equal("http://192.168.77.1:8202/v1/inspect", handler.LastRequestUri!.AbsoluteUri);
        Assert.Equal("Bearer " + MaintenanceTransferTestData.ValidToken, handler.LastAuthorization);
    }

    [Fact]
    public async Task Inspect_RejectsRedirectResponse_WithoutReissuingRequest()
    {
        var handler = new MaintenanceTransferHttpHandler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("http://192.168.77.1:8202/v1/redirected");
            return response;
        });

        using var client = new HttpClient(handler, disposeHandler: false);
        using var transfer = new TcpMaintenanceTransfer(client);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, MaintenanceTransferTestData.ValidToken));

        Assert.Equal(1, handler.CallCount);
        Assert.Equal("http://192.168.77.1:8202/v1/inspect", handler.LastRequestUri!.AbsoluteUri);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task Inspect_RejectsNonSuccessStatus(HttpStatusCode statusCode)
    {
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => new HttpResponseMessage(statusCode) { Content = new StringContent("nope") });

        using var client = new HttpClient(handler, disposeHandler: false);
        using var transfer = new TcpMaintenanceTransfer(client);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, MaintenanceTransferTestData.ValidToken));

        Assert.Equal(1, handler.CallCount);
    }

    [Theory]
    [InlineData(MaxResponseBytes + 1)]
    [InlineData(MaxResponseBytes * 2)]
    public async Task Inspect_RejectsOversizedBody_WhenContentLengthIsMissing(long bodyLength)
    {
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new MaintenanceTransferStreamingContent(bodyLength),
            });

        using var client = new HttpClient(handler, disposeHandler: false);
        using var transfer = new TcpMaintenanceTransfer(client);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => transfer.InspectAsync(MaintenanceTransferTestData.RootBaseAddress, MaintenanceTransferTestData.ValidToken));

        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task Inspect_AcceptsBodyExactlyAtTheTwoMiBBoundary()
    {
        var bytes = new byte[MaxResponseBytes];
        Array.Fill(bytes, (byte)'x');
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) });

        using var client = new HttpClient(handler, disposeHandler: false);
        using var transfer = new TcpMaintenanceTransfer(client);

        string result = await transfer.InspectAsync(
            MaintenanceTransferTestData.RootBaseAddress,
            MaintenanceTransferTestData.ValidToken);

        Assert.Equal(MaxResponseBytes, result.Length);
        Assert.Equal(bytes.Length, result.Length);
    }
}

internal static class MaintenanceTransferTestData
{
    public static readonly Uri RootBaseAddress = new("http://192.168.77.1:8202/", UriKind.Absolute);

    public static string ValidToken => new('a', 64);

    public static Stream Payload(int length) => new MemoryStream(new byte[length]);

    public static (HttpClient Client, TcpMaintenanceTransfer Transfer, MaintenanceTransferHttpHandler Handler) CreateTransfer()
    {
        var handler = new MaintenanceTransferHttpHandler(
            (_, _) => throw new InvalidOperationException("No HTTP call is expected in this test."));

        var client = new HttpClient(handler, disposeHandler: false);
        return (client, new TcpMaintenanceTransfer(client), handler);
    }

    public static async Task<Exception> ExpectRejectionAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Assert.IsNotType<NotImplementedException>(ex);
            return ex;
        }

        throw new Xunit.Sdk.XunitException("Expected the call to be rejected, but it completed successfully.");
    }
}

internal sealed class MaintenanceTransferHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _responder;

    public MaintenanceTransferHttpHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> responder)
    {
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
    }

    public int CallCount { get; private set; }

    public HttpMethod? LastMethod { get; private set; }

    public Uri? LastRequestUri { get; private set; }

    public string? LastAuthorization { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        CallCount++;
        LastMethod = request.Method;
        LastRequestUri = request.RequestUri;
        LastAuthorization = request.Headers.Authorization?.ToString();

        return Task.FromResult(_responder(request, cancellationToken));
    }
}

internal sealed class MaintenanceTransferStreamingContent : HttpContent
{
    private readonly long _length;

    public MaintenanceTransferStreamingContent(long length)
    {
        _length = length;
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        => WriteBodyAsync(stream);

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }

    private async Task WriteBodyAsync(Stream stream)
    {
        var buffer = new byte[8192];
        Array.Fill(buffer, (byte)'x');

        long remaining = _length;
        while (remaining > 0)
        {
            int chunk = (int)Math.Min(buffer.Length, remaining);
            await stream.WriteAsync(buffer.AsMemory(0, chunk)).ConfigureAwait(false);
            remaining -= chunk;
        }
    }
}

internal sealed class MaintenanceTransferWriteOnlyStream : Stream
{
    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
    }
}
