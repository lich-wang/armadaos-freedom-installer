using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One-shot TCP sender for the frozen RAM install seed protocol. The production target is fixed to
/// 192.168.77.1:8201; there is no host or port parameter and no retry.
/// </summary>
/// <remarks>
/// The caller owns <c>content</c> and it is never disposed. The sender reads exactly the seed's
/// declared 64-bit length with a 128 KiB buffer, hashes while streaming, validates the digest before
/// half-closing, then requires the receiver's bounded one-line JSON acknowledgement. An acknowledgement
/// is not deployment proof: the caller must poll the authoritative receive-seed job status.
/// </remarks>
public sealed class TcpInstallSeedTransfer
{
    private const string Host = "192.168.77.1";
    private const int Port = 8201;
    private const int MaxHeaderBytes = 256;
    private const int MaxChunkBytes = 128 * 1024;
    private const int MaxAckBytes = 4096;
    private const string SeedPrefix = "FREEDOM-SEED/1";
    private const string MaterialPrefix = "FREEDOM-MATERIAL/1";

    private static readonly IPAddress TargetAddress = IPAddress.Parse(Host);

    private static readonly HashSet<string> SuccessAckProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "ok",
        "receivedBytes",
        "sha256",
    };

    private static readonly HashSet<string> FailureAckProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "ok",
        "error",
    };

    /// <summary>Creates a sender bound to the fixed production endpoint.</summary>
    public TcpInstallSeedTransfer()
    {
    }

    /// <summary>
    /// Sends <paramref name="content"/> to the fixed seed receiver and validates its acknowledgement.
    /// </summary>
    /// <exception cref="ArgumentException">The stream, seed or token is unusable.</exception>
    /// <exception cref="InvalidDataException">Length, digest or acknowledgement does not match.</exception>
    /// <exception cref="TimeoutException">The supplied timeout expired.</exception>
    public async Task SendAsync(
        Stream content,
        RamInstallSeed seed,
        string token,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(seed);

        if (!content.CanRead)
        {
            throw new ArgumentException("The seed content stream must be readable.", nameof(content));
        }

        ValidateToken(token);
        ValidateTimeout(timeout);

        if (content.CanSeek && content.Length - content.Position != seed.Length)
        {
            throw new InvalidDataException("The seekable seed stream does not contain the declared length.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var tokenAtTransport = timeoutSource.Token;

        using var client = new TcpClient(AddressFamily.InterNetwork);

        try
        {
            await client.ConnectAsync(TargetAddress, Port, tokenAtTransport).ConfigureAwait(false);

            using NetworkStream network = client.GetStream();
            await TransferAsync(
                    content,
                    network,
                    seed,
                    token,
                    _ =>
                    {
                        client.Client.Shutdown(SocketShutdown.Send);
                        return Task.CompletedTask;
                    },
                    progress,
                    tokenAtTransport)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The seed transfer did not complete within the allotted time.");
        }
    }

    /// <summary>
    /// Sends one of the two fixed material roles to the same fixed receiver. There is no host, port,
    /// path or magic input; the role set is closed.
    /// </summary>
    /// <exception cref="ArgumentException">The stream, role or token is unusable.</exception>
    /// <exception cref="InvalidDataException">Length, digest or acknowledgement does not match.</exception>
    /// <exception cref="TimeoutException">The supplied timeout expired.</exception>
    internal async Task SendMaterialAsync(
        Stream content,
        string role,
        long length,
        string sha256,
        string token,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (!content.CanRead)
        {
            throw new ArgumentException("The material content stream must be readable.", nameof(content));
        }

        ValidateToken(token);
        ValidateMaterial(role, length, sha256);
        ValidateTimeout(timeout);

        if (content.CanSeek && content.Length - content.Position != length)
        {
            throw new InvalidDataException("The seekable material stream does not contain the declared length.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var tokenAtTransport = timeoutSource.Token;

        using var client = new TcpClient(AddressFamily.InterNetwork);

        try
        {
            await client.ConnectAsync(TargetAddress, Port, tokenAtTransport).ConfigureAwait(false);

            using NetworkStream network = client.GetStream();
            await TransferMaterialAsync(
                    content,
                    network,
                    token,
                    role,
                    length,
                    sha256,
                    _ =>
                    {
                        client.Client.Shutdown(SocketShutdown.Send);
                        return Task.CompletedTask;
                    },
                    progress,
                    tokenAtTransport)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The material transfer did not complete within the allotted time.");
        }
    }

    /// <summary>
    /// Testable material transfer core: the exact <c>FREEDOM-MATERIAL/1</c> header, the same 128 KiB
    /// streaming/hash loop, the caller's half-close and the same bounded bare-JSON acknowledgement.
    /// </summary>
    internal static async Task TransferMaterialAsync(
        Stream content,
        Stream connection,
        string token,
        string role,
        long length,
        string sha256,
        Func<CancellationToken, Task> halfClose,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(halfClose);
        ValidateToken(token);
        ValidateMaterial(role, length, sha256);
        cancellationToken.ThrowIfCancellationRequested();

        await TransferCoreAsync(
                content,
                connection,
                length,
                sha256,
                BuildMaterialHeader(token, role, length, sha256),
                halfClose,
                progress,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Testable transfer core: writes the header and payload to <paramref name="connection"/>,
    /// validates the digest, invokes <paramref name="halfClose"/>, then reads the acknowledgement.
    /// </summary>
    internal static async Task TransferAsync(
        Stream content,
        Stream connection,
        RamInstallSeed seed,
        string token,
        Func<CancellationToken, Task> halfClose,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(halfClose);
        ValidateToken(token);
        cancellationToken.ThrowIfCancellationRequested();

        await TransferCoreAsync(
                content,
                connection,
                seed.Length,
                seed.Sha256,
                BuildHeader(seed, token),
                halfClose,
                progress,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task TransferCoreAsync(
        Stream content,
        Stream connection,
        long length,
        string sha256,
        byte[] header,
        Func<CancellationToken, Task> halfClose,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        await connection.WriteAsync(header, cancellationToken).ConfigureAwait(false);

        var buffer = ArrayPool<byte>.Shared.Rent(MaxChunkBytes);
        try
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long remaining = length;
            long sent = 0;

            while (remaining > 0)
            {
                int chunk = (int)Math.Min((long)buffer.Length, remaining);
                int read = await content
                    .ReadAsync(buffer.AsMemory(0, chunk), cancellationToken)
                    .ConfigureAwait(false);

                if (read <= 0)
                {
                    throw new InvalidDataException("The content ended before its declared length.");
                }

                hasher.AppendData(buffer, 0, read);
                await connection
                    .WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);

                remaining -= read;
                sent += read;
                ReportProgress(progress, sent, length);
            }

            int extra = await content.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (extra != 0)
            {
                // The peer must see that the declared length was exceeded, otherwise a valid
                // declared-prefix digest would let the receiver begin its work on a clean EOF.
                // Transmit exactly the one extra byte, flush it, and fail; never half-close, read
                // an acknowledgement, retry, or drain the unbounded remainder.
                await connection
                    .WriteAsync(buffer.AsMemory(0, extra), cancellationToken)
                    .ConfigureAwait(false);
                await connection.FlushAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidDataException("The content is longer than its declared length.");
            }

            string actualSha256 = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actualSha256),
                    Convert.FromHexString(sha256)))
            {
                throw new InvalidDataException("The content digest does not match the expected digest.");
            }

            await connection.FlushAsync(cancellationToken).ConfigureAwait(false);
            await halfClose(cancellationToken).ConfigureAwait(false);
            await ReadAckAsync(connection, length, sha256, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte[] BuildHeader(RamInstallSeed seed, string token)
    {
        string header = SeedPrefix + " " + token + " seed "
            + seed.Length.ToString(CultureInfo.InvariantCulture)
            + " " + seed.Sha256 + "\n";
        byte[] bytes = Encoding.ASCII.GetBytes(header);

        if (bytes.Length > MaxHeaderBytes)
        {
            throw new ArgumentException("The seed header exceeds 256 bytes.");
        }

        return bytes;
    }

    private static byte[] BuildMaterialHeader(string token, string role, long length, string sha256)
    {
        string header = MaterialPrefix + " " + token + " " + role + " "
            + length.ToString(CultureInfo.InvariantCulture)
            + " " + sha256 + "\n";
        byte[] bytes = Encoding.ASCII.GetBytes(header);

        if (bytes.Length > MaxHeaderBytes)
        {
            throw new ArgumentException("The material header exceeds 256 bytes.");
        }

        return bytes;
    }

    private static async Task ReadAckAsync(
        Stream connection,
        long length,
        string sha256,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxAckBytes];
        int total = 0;

        while (true)
        {
            int read = await connection
                .ReadAsync(buffer.AsMemory(total, MaxAckBytes - total), cancellationToken)
                .ConfigureAwait(false);

            if (read <= 0)
            {
                throw new InvalidDataException(
                    "The seed receiver closed the connection before a complete acknowledgement.");
            }

            total += read;
            int newline = Array.IndexOf(buffer, (byte)'\n', 0, total);
            if (newline >= 0)
            {
                if (newline + 1 != total)
                {
                    throw new InvalidDataException("The seed acknowledgement contains extra data.");
                }

                string text;
                try
                {
                    text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                        .GetString(buffer, 0, newline);
                }
                catch (DecoderFallbackException exception)
                {
                    throw new InvalidDataException(
                        "The seed acknowledgement is not valid UTF-8.",
                        exception);
                }

                ValidateAck(text, length, sha256);
                return;
            }

            if (total == MaxAckBytes)
            {
                throw new InvalidDataException("The seed acknowledgement is too long.");
            }
        }
    }

    private static void ValidateAck(string text, long length, string sha256)
    {
        if (text.Length == 0 || text[0] != '{')
        {
            throw new InvalidDataException("The seed acknowledgement is not a bare JSON object.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The seed acknowledgement is not valid JSON.", exception);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var schema) ||
                schema.ValueKind != JsonValueKind.Number ||
                !schema.TryGetInt32(out var version) ||
                version != 1 ||
                !root.TryGetProperty("ok", out var ok) ||
                (ok.ValueKind != JsonValueKind.True && ok.ValueKind != JsonValueKind.False))
            {
                throw new InvalidDataException("The seed acknowledgement does not match schema 1.");
            }

            if (ok.ValueKind == JsonValueKind.False)
            {
                if (!HasExactProperties(root, FailureAckProperties) ||
                    !root.TryGetProperty("error", out var error) ||
                    error.ValueKind != JsonValueKind.String ||
                    string.IsNullOrEmpty(error.GetString()))
                {
                    throw new InvalidDataException("The seed acknowledgement does not match schema 1.");
                }

                // The remote error text is deliberately not surfaced: it is not trusted and could
                // contain anything, including a secret echoed by a broken receiver.
                throw new InvalidDataException("The seed receiver rejected the transfer.");
            }

            if (!HasExactProperties(root, SuccessAckProperties) ||
                !root.TryGetProperty("receivedBytes", out var receivedElement) ||
                receivedElement.ValueKind != JsonValueKind.Number ||
                !receivedElement.TryGetInt64(out long receivedBytes) ||
                receivedBytes != length ||
                !root.TryGetProperty("sha256", out var shaElement) ||
                shaElement.ValueKind != JsonValueKind.String ||
                !string.Equals(shaElement.GetString(), sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The seed acknowledgement does not match the request.");
            }
        }
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

    private static void ReportProgress(
        IProgress<RamInstallSeedProgress>? progress,
        long sent,
        long total)
    {
        if (progress is null)
        {
            return;
        }

        try
        {
            progress.Report(new RamInstallSeedProgress(sent, total));
        }
        catch (Exception)
        {
            // A faulty observer must never change the transfer outcome.
        }
    }

    private static void ValidateToken(string? token)
    {
        if (!RamInstallValidation.IsLowerSha256(token))
        {
            throw new ArgumentException(
                "The seed transfer token must be 64 lowercase hexadecimal characters.",
                nameof(token));
        }
    }

    private static void ValidateMaterial(string? role, long length, string? sha256)
    {
        if (!string.Equals(role, "original-boot-a", StringComparison.Ordinal) &&
            !string.Equals(role, "runtime", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A material role must be exactly original-boot-a or runtime.",
                nameof(role));
        }

        if (length <= 0)
        {
            throw new ArgumentException(
                "A material length must be a positive 64-bit byte count.",
                nameof(length));
        }

        if (!RamInstallValidation.IsLowerSha256(sha256))
        {
            throw new ArgumentException(
                "A material digest must be 64 lowercase hexadecimal characters.",
                nameof(sha256));
        }
    }

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
}

/// <summary>Streaming progress of one seed transfer, in 64-bit byte counts.</summary>
public sealed class RamInstallSeedProgress
{
    /// <summary>Creates a progress sample.</summary>
    public RamInstallSeedProgress(long sentBytes, long totalBytes)
    {
        SentBytes = sentBytes;
        TotalBytes = totalBytes;
    }

    /// <summary>Bytes written to the receiver so far.</summary>
    public long SentBytes { get; }

    /// <summary>Declared seed length.</summary>
    public long TotalBytes { get; }
}
