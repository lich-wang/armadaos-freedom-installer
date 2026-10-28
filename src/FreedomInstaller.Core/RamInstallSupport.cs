using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// A caller-supplied install-support archive that has been fully re-read from disk and matched
/// against the caller's own length and SHA-256 claim.
/// </summary>
/// <remarks>
/// The claim in <see cref="VerifiedEdlFile"/> is evidence to verify, never authority: the file is
/// opened exactly as it exists, read-only with <see cref="FileShare.Read"/> so writers and deleters
/// are refused, and its whole length and digest are recomputed before this instance exists. The
/// handle stays open until <see cref="Dispose"/>, and the upload path re-hashes the same held bytes
/// and rewinds immediately before use, so the bytes that were verified cannot be swapped in between.
/// <para>
/// Disposal belongs to whoever loaded the support; a bootstrap that uploads it never disposes it.
/// No pin is hardcoded here and no caller string is treated as a trusted asset identity.
/// </para>
/// </remarks>
public sealed class RamInstallSupport : IDisposable
{
    /// <summary>Upper bound for the support archive: 512 MiB.</summary>
    public const long MaxBytes = 512L * 1024L * 1024L;

    private const int BufferSize = 81920;

    private readonly FileStream _stream;
    private readonly long _length;
    private readonly string _sha256;
    private bool _disposed;

    private RamInstallSupport(FileStream stream, long length, string sha256)
    {
        _stream = stream;
        _length = length;
        _sha256 = sha256;
    }

    /// <summary>Actual verified length in bytes.</summary>
    public long Length => _length;

    /// <summary>Actual verified lowercase 64-hex SHA-256 digest.</summary>
    public string Sha256 => _sha256;

    /// <summary>True once the held handle has been released.</summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Opens <paramref name="claim"/>'s exact path, verifies its full length and SHA-256 against the
    /// claim while holding the handle, and returns the owned support.
    /// </summary>
    /// <exception cref="MaintenanceException">The claim, the file or its bytes are unusable.</exception>
    public static async Task<RamInstallSupport> LoadAsync(
        VerifiedEdlFile claim,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claim);

        if (string.IsNullOrWhiteSpace(claim.Path))
        {
            throw new ArgumentException("A non-blank support file path is required.", nameof(claim));
        }

        if (claim.Length <= 0 || claim.Length > MaxBytes)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetSizeMismatch,
                "The support claim length is outside the permitted range.");
        }

        if (!IsLowercaseSha256(claim.Sha256))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetHashMismatch,
                "The support claim digest is not a lowercase 64-hex SHA-256.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        FileStream? stream = null;
        try
        {
            try
            {
                stream = new FileStream(
                    claim.Path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    BufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.UnsafeEnvironment,
                    "The support file could not be opened read-only.",
                    exception);
            }

            if (stream.Length <= 0 || stream.Length > MaxBytes)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.AssetSizeMismatch,
                    "The support file size is outside the permitted range.");
            }

            if (stream.Length != claim.Length)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.AssetSizeMismatch,
                    "The support file length does not match the claim.");
            }

            var (length, sha256) = await HashHeldFileAsync(stream, cancellationToken).ConfigureAwait(false);
            if (length != claim.Length)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.AssetSizeMismatch,
                    "The support file length does not match the claim.");
            }

            if (!string.Equals(sha256, claim.Sha256, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.AssetHashMismatch,
                    "The support file digest does not match the claim.");
            }

            stream.Position = 0;
            var support = new RamInstallSupport(stream, length, sha256);
            stream = null;
            return support;
        }
        finally
        {
            stream?.Dispose();
        }
    }

    /// <summary>
    /// Re-hashes the exact held bytes, requires them to be the ones this instance verified, rewinds to
    /// zero and returns the held handle. The returned stream is owned by this instance and must not be
    /// disposed by the uploader.
    /// </summary>
    internal async Task<Stream> OpenVerifiedContentAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var (length, sha256) = await HashHeldFileAsync(_stream, cancellationToken).ConfigureAwait(false);
        if (length != _length || !string.Equals(sha256, _sha256, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetHashMismatch,
                "The held support bytes changed after they were verified.");
        }

        _stream.Position = 0;
        return _stream;
    }

    /// <summary>Releases the held handle. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stream.Dispose();
    }

    private static async Task<(long Length, string Sha256)> HashHeldFileAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;

        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                       .ConfigureAwait(false)) > 0)
            {
                hasher.AppendData(buffer, 0, read);
                total += read;
            }

            return (total, Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsLowercaseSha256(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is >= '0' and <= '9' or >= 'a' and <= 'f')
            {
                continue;
            }

            return false;
        }

        return true;
    }
}
