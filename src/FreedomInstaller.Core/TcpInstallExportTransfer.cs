using System;
using System.Buffers;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One-shot TCP receiver for the frozen RAM install export protocol. The production target is fixed to
/// 192.168.77.1:8201; there is no host, port or path parameter and no retry.
/// </summary>
/// <remarks>
/// The caller owns both streams: neither is disposed here. Only the fixed role and its locked length
/// and digest reach the wire, and the file path never does. The exact declared length is streamed into
/// the destination in bounded chunks while one SHA-256 hash is accumulated; the peer must then close
/// its send side before any positive acknowledgement is written. The acknowledgement is only sent after
/// the full digest matched, EOF was observed and the caller flushed (and fsynced) the destination.
/// </remarks>
public sealed class TcpInstallExportTransfer
{
    private const string Host = "192.168.77.1";
    private const int Port = 8201;
    private const int MaxHeaderBytes = 256;
    private const int MaxChunkBytes = 128 * 1024;
    private const string ExportPrefix = "FREEDOM-EXPORT/1";

    private static readonly IPAddress TargetAddress = IPAddress.Parse(Host);

    /// <summary>Creates a receiver bound to the fixed production endpoint.</summary>
    public TcpInstallExportTransfer()
    {
    }

    /// <summary>
    /// Receives one fixed-role artifact into <paramref name="destination"/> from the fixed endpoint and
    /// writes the exact schema-1 acknowledgement.
    /// </summary>
    /// <exception cref="ArgumentException">A role, length, digest, token or stream is unusable.</exception>
    /// <exception cref="InvalidDataException">The stream, EOF or digest does not match the declared artifact.</exception>
    /// <exception cref="TimeoutException">The supplied timeout expired.</exception>
    public async Task SendAsync(
        Stream destination,
        string role,
        long length,
        string sha256,
        string token,
        IProgress<RamInstallSeedProgress>? progress,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (!destination.CanWrite)
        {
            throw new ArgumentException("The export destination must be writable.", nameof(destination));
        }

        ValidateToken(token);
        ValidateRole(role);
        ValidateArtifact(length, sha256);
        ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        CancellationToken tokenAtTransport = timeoutSource.Token;

        using var client = new TcpClient(AddressFamily.InterNetwork);

        try
        {
            await client.ConnectAsync(TargetAddress, Port, tokenAtTransport).ConfigureAwait(false);

            using NetworkStream network = client.GetStream();
            await TransferAsync(
                    network,
                    destination,
                    token,
                    role,
                    length,
                    sha256,
                    _ =>
                    {
                        client.Client.Shutdown(SocketShutdown.Send);
                        return Task.CompletedTask;
                    },
                    async atAck =>
                    {
                        await destination.FlushAsync(atAck).ConfigureAwait(false);
                        if (destination is FileStream file)
                        {
                            file.Flush(flushToDisk: true);
                        }
                        else
                        {
                            destination.Flush();
                        }
                    },
                    progress,
                    tokenAtTransport)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The export transfer did not complete within the allotted time.");
        }
    }

    /// <summary>
    /// Testable transfer core: writes the exact <c>FREEDOM-EXPORT/1</c> header, reads exactly the
    /// declared 64-bit length in bounded chunks into <paramref name="destination"/> with one incremental
    /// digest, requires EOF, hashes, flushes, writes the bare schema-1 acknowledgement and half-closes.
    /// </summary>
    /// <remarks>
    /// No in-memory copy of the artifact is ever made: only one 128 KiB pooled buffer is used regardless
    /// of the declared length. No acknowledgement is written for a short, overlong, mismatched or
    /// cancelled stream, and the destination is never disposed.
    /// </remarks>
    internal static async Task TransferAsync(
        Stream connection,
        Stream destination,
        string token,
        string role,
        long length,
        string sha256,
        Func<CancellationToken, Task> halfClose,
        Func<CancellationToken, Task> flushBeforeAck,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(halfClose);
        ArgumentNullException.ThrowIfNull(flushBeforeAck);
        ValidateToken(token);
        ValidateRole(role);
        ValidateArtifact(length, sha256);
        cancellationToken.ThrowIfCancellationRequested();

        await connection
            .WriteAsync(BuildHeader(token, role, length, sha256), cancellationToken)
            .ConfigureAwait(false);
        await connection.FlushAsync(cancellationToken).ConfigureAwait(false);

        var buffer = ArrayPool<byte>.Shared.Rent(MaxChunkBytes);
        try
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long remaining = length;
            long received = 0;

            while (remaining > 0)
            {
                int chunk = (int)Math.Min((long)buffer.Length, remaining);
                int read = await connection
                    .ReadAsync(buffer.AsMemory(0, chunk), cancellationToken)
                    .ConfigureAwait(false);

                if (read <= 0)
                {
                    throw new InvalidDataException("The export stream ended before its declared length.");
                }

                await destination
                    .WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
                hasher.AppendData(buffer, 0, read);

                remaining -= read;
                received += read;
                ReportProgress(progress, received, length);
            }

            // The peer must close its send side after exactly the declared bytes. Anything else,
            // including a lazily withheld trailing byte, is a stream violation: no acknowledgement.
            int extra = await connection
                .ReadAsync(buffer.AsMemory(0, 1), cancellationToken)
                .ConfigureAwait(false);
            if (extra != 0)
            {
                throw new InvalidDataException("The export stream is longer than its declared length.");
            }

            string actualSha256 = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actualSha256),
                    Convert.FromHexString(sha256)))
            {
                throw new InvalidDataException("The export digest does not match the locked build proof.");
            }

            // The destination is flushed (and fsynced by the production caller) before the receiver
            // is told the bytes are durable.
            await flushBeforeAck(cancellationToken).ConfigureAwait(false);

            byte[] acknowledgement = Encoding.ASCII.GetBytes(
                "{\"schemaVersion\":1,\"ok\":true,\"receivedBytes\":"
                + received.ToString(CultureInfo.InvariantCulture)
                + ",\"sha256\":\"" + sha256 + "\"}\n");

            await connection.WriteAsync(acknowledgement, cancellationToken).ConfigureAwait(false);
            await connection.FlushAsync(cancellationToken).ConfigureAwait(false);
            await halfClose(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte[] BuildHeader(string token, string role, long length, string sha256)
    {
        string header = ExportPrefix + " " + token + " " + role + " "
            + length.ToString(CultureInfo.InvariantCulture)
            + " " + sha256 + "\n";
        byte[] bytes = Encoding.ASCII.GetBytes(header);

        if (bytes.Length > MaxHeaderBytes)
        {
            throw new ArgumentException("The export header exceeds 256 bytes.");
        }

        return bytes;
    }

    private static void ReportProgress(
        IProgress<RamInstallSeedProgress>? progress,
        long received,
        long total)
    {
        if (progress is null)
        {
            return;
        }

        try
        {
            progress.Report(new RamInstallSeedProgress(received, total));
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
                "The export transfer token must be 64 lowercase hexadecimal characters.",
                nameof(token));
        }
    }

    private static void ValidateRole(string? role)
    {
        if (!string.Equals(role, "boot_a", StringComparison.Ordinal) &&
            !string.Equals(role, "boot_b", StringComparison.Ordinal) &&
            !string.Equals(role, "report_a", StringComparison.Ordinal) &&
            !string.Equals(role, "report_b", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "An export role must be exactly boot_a, boot_b, report_a or report_b.",
                nameof(role));
        }
    }

    private static void ValidateArtifact(long length, string? sha256)
    {
        if (length <= 0)
        {
            throw new ArgumentException(
                "An export length must be a positive 64-bit byte count.",
                nameof(length));
        }

        if (!RamInstallValidation.IsLowerSha256(sha256))
        {
            throw new ArgumentException(
                "An export digest must be 64 lowercase hexadecimal characters.",
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
