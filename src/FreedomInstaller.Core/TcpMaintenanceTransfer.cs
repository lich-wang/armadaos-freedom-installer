using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>
/// USB-only maintenance transfer target (UI003.a1).
/// Upload uses the fixed device TCP port; inspection uses the fixed HTTP endpoint.
/// </summary>
public sealed class TcpMaintenanceTransfer : IMaintenanceTransfer, IDisposable
{
    private const string TransferHost = "192.168.77.1";
    private const int UploadPort = 8201;
    private const int InspectPort = 8202;
    private const long MaxUploadBytes = 512L * 1024 * 1024;
    private const long MaxInspectBytes = 2L * 1024 * 1024;
    private const int TransferBufferSize = 64 * 1024;
    private const string RootPath = "/";

    private static readonly IPAddress TransferAddress = IPAddress.Parse(TransferHost);
    private static readonly Uri InspectionEndpoint = new("http://192.168.77.1:8202/v1/inspect", UriKind.Absolute);
    private static readonly TimeSpan UploadTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan InspectTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private bool _disposed;

    public TcpMaintenanceTransfer()
        : this(CreateDefaultClient(), ownsClient: true)
    {
    }

    public TcpMaintenanceTransfer(HttpClient httpClient)
        : this(httpClient, ownsClient: false)
    {
    }

    private TcpMaintenanceTransfer(HttpClient httpClient, bool ownsClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _ownsHttpClient = ownsClient;
    }

    public async Task UploadAsync(
        string host,
        int port,
        Stream content,
        long expectedBytes,
        CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        ThrowIfDisposed();
        ValidateUploadArguments(host, port, content, expectedBytes);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(UploadTimeout);
        CancellationToken token = timeout.Token;

        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(TransferAddress, UploadPort, token).ConfigureAwait(false);

        using NetworkStream network = client.GetStream();

        var buffer = new byte[TransferBufferSize];
        long remaining = expectedBytes;

        while (remaining > 0)
        {
            int chunk = (int)Math.Min(buffer.Length, remaining);
            int read = await content.ReadAsync(buffer.AsMemory(0, chunk), token).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new InvalidDataException(
                    "Upload content ended before the declared length was reached.");
            }

            await network.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            remaining -= read;
        }

        int extra = await content.ReadAsync(buffer.AsMemory(0, 1), token).ConfigureAwait(false);
        if (extra != 0)
        {
            throw new InvalidDataException("Upload content contains more bytes than declared.");
        }

        await network.FlushAsync(token).ConfigureAwait(false);
        client.Client.Shutdown(SocketShutdown.Send);
    }

    public async Task<string> InspectAsync(
        Uri baseAddress,
        string bearerToken,
        CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        ThrowIfDisposed();
        ValidateInspectArguments(baseAddress, bearerToken);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(InspectTimeout);
        CancellationToken token = timeout.Token;

        using var request = new HttpRequestMessage(HttpMethod.Get, InspectionEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

        using HttpResponseMessage response = await _httpClient
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Inspection request failed with HTTP status {(int)response.StatusCode}.");
        }

        long? declaredLength = response.Content.Headers.ContentLength;
        if (declaredLength.HasValue && declaredLength.Value > MaxInspectBytes)
        {
            throw new InvalidDataException("Inspection response exceeds the 2 MiB limit.");
        }

        using Stream responseStream = await response.Content
            .ReadAsStreamAsync(token)
            .ConfigureAwait(false);

        using var body = new MemoryStream();
        var chunkBuffer = new byte[TransferBufferSize];
        long total = 0;

        while (true)
        {
            int read = await responseStream
                .ReadAsync(chunkBuffer.AsMemory(0, chunkBuffer.Length), token)
                .ConfigureAwait(false);

            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > MaxInspectBytes)
            {
                throw new InvalidDataException("Inspection response exceeds the 2 MiB limit.");
            }

            body.Write(chunkBuffer, 0, read);
        }

        return Encoding.UTF8.GetString(body.ToArray());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TcpMaintenanceTransfer));
        }
    }

    private static HttpClient CreateDefaultClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    private static void ValidateUploadArguments(string host, int port, Stream content, long expectedBytes)
    {
        if (host is null)
        {
            throw new ArgumentNullException(nameof(host));
        }

        if (!string.Equals(host, TransferHost, StringComparison.Ordinal))
        {
            throw new ArgumentException("Upload target host must be 192.168.77.1.", nameof(host));
        }

        if (port != UploadPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Upload target port must be 8201.");
        }

        if (content is null)
        {
            throw new ArgumentNullException(nameof(content));
        }

        if (!content.CanRead)
        {
            throw new ArgumentException("Upload content stream must be readable.", nameof(content));
        }

        if (expectedBytes <= 0 || expectedBytes > MaxUploadBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedBytes),
                expectedBytes,
                "Expected upload length must be between 1 byte and 512 MiB.");
        }

        if (content.CanSeek)
        {
            long remaining = content.Length - content.Position;
            if (remaining != expectedBytes)
            {
                throw new InvalidDataException(
                    $"Seekable upload stream has {remaining} remaining bytes but {expectedBytes} were declared.");
            }
        }
    }

    private static void ValidateInspectArguments(Uri baseAddress, string bearerToken)
    {
        if (baseAddress is null)
        {
            throw new ArgumentNullException(nameof(baseAddress));
        }

        if (!baseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException("Inspect base address must be absolute.", nameof(baseAddress));
        }

        if (!string.Equals(baseAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Inspect base address must use http.", nameof(baseAddress));
        }

        if (!string.Equals(baseAddress.Host, TransferHost, StringComparison.Ordinal))
        {
            throw new ArgumentException("Inspect base address host must be 192.168.77.1.", nameof(baseAddress));
        }

        if (baseAddress.Port != InspectPort)
        {
            throw new ArgumentException("Inspect base address port must be 8202.", nameof(baseAddress));
        }

        if (baseAddress.UserInfo.Length != 0)
        {
            throw new ArgumentException("Inspect base address must not carry user info.", nameof(baseAddress));
        }

        if (!string.Equals(baseAddress.AbsolutePath, RootPath, StringComparison.Ordinal))
        {
            throw new ArgumentException("Inspect base address must be the root path.", nameof(baseAddress));
        }

        if (baseAddress.Query.Length != 0)
        {
            throw new ArgumentException("Inspect base address must not carry a query.", nameof(baseAddress));
        }

        if (baseAddress.Fragment.Length != 0)
        {
            throw new ArgumentException("Inspect base address must not carry a fragment.", nameof(baseAddress));
        }

        if (bearerToken is null)
        {
            throw new ArgumentNullException(nameof(bearerToken));
        }

        if (!IsValidBearerToken(bearerToken))
        {
            throw new ArgumentException("Bearer token must be exactly 64 ASCII hex characters.", nameof(bearerToken));
        }
    }

    private static bool IsValidBearerToken(string token)
    {
        if (token.Length != 64)
        {
            return false;
        }

        foreach (char c in token)
        {
            bool isHex =
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F');

            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }
}
