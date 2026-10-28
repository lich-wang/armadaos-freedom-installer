using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The two pinned EDL raw-boot helper executables, held under independent read leases for one caller.
/// </summary>
/// <remarks>
/// A caller claim is evidence to verify, never authority: both claims must name the exact compiled pins
/// before either file is opened, and the bytes read through the held handles must still match those pins
/// before an instance exists. Nothing here executes the tools, reports readiness or offers a pin override.
/// <para>
/// Loading opens its own read-only <see cref="FileShare.Read"/> leases and keeps them until
/// <see cref="Dispose"/>. Disposing closes only those two handles: it never deletes an input file and never
/// disposes another instance's leases.
/// </para>
/// </remarks>
public sealed class EdlRawBootTools : IDisposable
{
    /// <summary>Stable refusal identity for every compiled-pin or held-bytes mismatch.</summary>
    private const string PinMismatchCode = "edl-raw-boot-tool-pin-mismatch";

    private const int HashBufferBytes = 81920;

    private const int Sha256HexLength = 64;

    private const long PackerBytes = 277460L;

    private const string PackerSha256 =
        "a2f03fc6b0e5d1b8defb60dd2a880bd5933c5133613778b17690172570ac20bb";

    private const long UnpackerBytes = 262703L;

    private const string UnpackerSha256 =
        "24d4788646282d23665b61b28460808480420a0a72e45afca6ab1a167b4b656f";

    private readonly FileStream _packerStream;

    private readonly FileStream _unpackerStream;

    private int _disposed;

    /// <summary>
    /// Private constructor: an instance only exists after both pinned byte sets were verified and both own
    /// leases were opened.
    /// </summary>
    private EdlRawBootTools(
        VerifiedEdlFile packer,
        VerifiedEdlFile unpacker,
        FileStream packerStream,
        FileStream unpackerStream)
    {
        Packer = packer;
        Unpacker = unpacker;
        _packerStream = packerStream;
        _unpackerStream = unpackerStream;
    }

    /// <summary>The verified packer with its normalized absolute path and compiled pin.</summary>
    public VerifiedEdlFile Packer { get; }

    /// <summary>The verified unpacker with its normalized absolute path and compiled pin.</summary>
    public VerifiedEdlFile Unpacker { get; }

    /// <summary>True once this instance's own two leases have been released.</summary>
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Verifies the caller's two claims against the compiled pins, then opens and fully hashes both files.
    /// </summary>
    /// <remarks>
    /// The null, cancellation and claim guards are cheap and stay on the caller's thread; opening and
    /// hashing run on the thread pool so a UI caller is never blocked before the task is returned.
    /// </remarks>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="OperationCanceledException">The token is already cancelled.</exception>
    /// <exception cref="InvalidOperationException">A claim, a path or the held bytes do not match a
    /// compiled pin; the message carries <c>edl-raw-boot-tool-pin-mismatch</c>.</exception>
    public static Task<EdlRawBootTools> LoadAsync(
        VerifiedEdlFile packer,
        VerifiedEdlFile unpacker,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(packer);
        ArgumentNullException.ThrowIfNull(unpacker);

        cancellationToken.ThrowIfCancellationRequested();

        RequirePinnedClaim(packer, PackerBytes, PackerSha256, "packer claim");
        RequirePinnedClaim(unpacker, UnpackerBytes, UnpackerSha256, "unpacker claim");

        return Task.Run(() => Load(packer, unpacker, cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Reopens independent leases for a caller that needs its own lifetime. The returned instance shares
    /// neither a handle nor the disposed flag with this one and re-verifies the pinned bytes.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal Task<EdlRawBootTools> AcquireAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return LoadAsync(Packer, Unpacker, cancellationToken);
    }

    /// <summary>Rechecks the whole length and SHA-256 of both held streams against the compiled pins.</summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <exception cref="InvalidOperationException">A held file no longer matches its compiled pin.</exception>
    internal Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return Task.Run(() => Revalidate(cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Releases only the two read leases this instance owns. It never deletes an input file and is safe to
    /// call more than once.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _packerStream.Dispose();
        _unpackerStream.Dispose();
    }

    // ---------------------------------------------------------------- load body

    private static EdlRawBootTools Load(
        VerifiedEdlFile packer,
        VerifiedEdlFile unpacker,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // The claims are checked again on the worker so the guard and the read cannot diverge.
        RequirePinnedClaim(packer, PackerBytes, PackerSha256, "packer claim");
        RequirePinnedClaim(unpacker, UnpackerBytes, UnpackerSha256, "unpacker claim");

        // Each path is normalized exactly once; the result is both opened and published.
        var packerPath = RequireRegularPath(packer.Path, "packer");
        var unpackerPath = RequireRegularPath(unpacker.Path, "unpacker");

        cancellationToken.ThrowIfCancellationRequested();

        FileStream? packerStream = null;
        FileStream? unpackerStream = null;
        try
        {
            // Both files are opened before either is hashed, so a refusal never leaves one checked file unheld.
            packerStream = OpenRead(packerPath, "packer");
            unpackerStream = OpenRead(unpackerPath, "unpacker");

            VerifyHeld(packerStream, PackerBytes, PackerSha256, "packer", cancellationToken);
            VerifyHeld(unpackerStream, UnpackerBytes, UnpackerSha256, "unpacker", cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            var loaded = new EdlRawBootTools(
                new VerifiedEdlFile(packerPath, PackerBytes, PackerSha256),
                new VerifiedEdlFile(unpackerPath, UnpackerBytes, UnpackerSha256),
                packerStream,
                unpackerStream);

            packerStream = null;
            unpackerStream = null;
            return loaded;
        }
        finally
        {
            packerStream?.Dispose();
            unpackerStream?.Dispose();
        }
    }

    private void Revalidate(CancellationToken cancellationToken)
    {
        // The instance may have been disposed between the caller's guard and this worker starting.
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        VerifyHeld(_packerStream, PackerBytes, PackerSha256, "packer", cancellationToken);
        VerifyHeld(_unpackerStream, UnpackerBytes, UnpackerSha256, "unpacker", cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
    }

    // ---------------------------------------------------------------- file access

    private static FileStream OpenRead(string fullPath, string subject)
    {
        try
        {
            return new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                HashBufferBytes,
                FileOptions.SequentialScan);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw PinMismatch(subject);
        }
    }

    private static string RequireRegularPath(string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw PinMismatch(subject);
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw PinMismatch(subject);
        }

        if (!IsRegularFile(fullPath))
        {
            throw PinMismatch(subject);
        }

        return fullPath;
    }

    /// <summary>
    /// True only for an existing regular file whose own entry and containing directory are not reparse
    /// points. A missing, unreadable or linked path is never treated as a usable tool.
    /// </summary>
    private static bool IsRegularFile(string fullPath)
    {
        try
        {
            var file = new FileInfo(fullPath);
            if (!file.Exists || IsReparsePoint(file))
            {
                return false;
            }

            var directory = file.Directory;
            if (directory is not null && IsReparsePoint(directory))
            {
                return false;
            }

            return true;
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsReparsePoint(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null;

    // ---------------------------------------------------------------- hashing

    private static void VerifyHeld(
        FileStream stream,
        long expectedBytes,
        string expectedSha256,
        string subject,
        CancellationToken cancellationToken)
    {
        if (stream.Length != expectedBytes)
        {
            throw PinMismatch(subject);
        }

        if (!string.Equals(HashHeld(stream, cancellationToken), expectedSha256, StringComparison.Ordinal))
        {
            throw PinMismatch(subject);
        }
    }

    /// <summary>
    /// Hashes the whole held stream from position 0 and always restores the position, so repeated
    /// verification sees the same bytes and leaves the lease usable.
    /// </summary>
    private static string HashHeld(FileStream stream, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(HashBufferBytes);
        try
        {
            stream.Position = 0;

            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int read;
            while ((read = stream.Read(buffer, 0, HashBufferBytes)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                hasher.AppendData(buffer, 0, read);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        }
        finally
        {
            stream.Position = 0;
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ---------------------------------------------------------------- claims and small helpers

    private static void RequirePinnedClaim(VerifiedEdlFile claim, long bytes, string sha256, string subject)
    {
        if (claim.Length != bytes ||
            !IsSha256Hex(claim.Sha256) ||
            !string.Equals(claim.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw PinMismatch(subject);
        }
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != Sha256HexLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static InvalidOperationException PinMismatch(string subject) =>
        new(PinMismatchCode + ": the " + subject + " does not match the compiled EDL raw boot tool pin.");
}
