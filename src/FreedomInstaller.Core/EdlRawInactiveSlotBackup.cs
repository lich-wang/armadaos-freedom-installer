// ES2: proof of an original factory-uninitialized inactive slot (A or B).
// This type owns five read leases over zero-filled inputs and makes no device, readiness or write claim.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One verified original inactive slot: the target slot every byte of which is still factory zero while
/// the other slot holds the real source material.
/// <para>
/// <see cref="VerifyAsync"/> resolves a known complete profile, requires the target to be the opposite of
/// the actual current slot, and then makes exactly one bounded streaming pass per input that proves the
/// claimed length, the claimed SHA-256 and the all-zero content at the same time. The instance owns five
/// plain read leases and keeps them until <see cref="Dispose"/>; it never writes, deletes, renames or
/// truncates an input and carries no device, readiness or signature statement.
/// </para>
/// </summary>
public sealed class EdlRawInactiveSlotBackup : IDisposable
{
    private const int ScanBufferBytes = 81920;

    private const int Sha256HexBytes = 64;

    private readonly FileStream _bootStream;

    private readonly FileStream _vendorBootStream;

    private readonly FileStream _initBootStream;

    private readonly FileStream _ablStream;

    private readonly FileStream _xblConfigStream;

    private int _disposed;

    private EdlRawInactiveSlotBackup(
        EdlDeviceProfile profile,
        string sourceSlot,
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        FileStream bootStream,
        FileStream vendorBootStream,
        FileStream initBootStream,
        FileStream ablStream,
        FileStream xblConfigStream)
    {
        Profile = profile;
        SourceSlot = sourceSlot;
        Slot = slot;
        CurrentBoot = currentBoot;
        VendorBoot = vendorBoot;
        InitBoot = initBoot;
        Abl = abl;
        XblConfig = xblConfig;
        _bootStream = bootStream;
        _vendorBootStream = vendorBootStream;
        _initBootStream = initBootStream;
        _ablStream = ablStream;
        _xblConfigStream = xblConfigStream;
    }

    /// <summary>The complete profile whose model and loader materials the backup belongs to.</summary>
    public EdlDeviceProfile Profile { get; }

    /// <summary>The slot that holds the real source material: the opposite of <see cref="Slot"/>.</summary>
    public string SourceSlot { get; }

    /// <summary>The inactive, factory-uninitialized target slot: exactly <c>a</c> or <c>b</c>.</summary>
    public string Slot { get; }

    /// <summary>The held zero-filled current_boot claim of the inactive target.</summary>
    public VerifiedEdlFile CurrentBoot { get; }

    /// <summary>The held zero-filled vendor_boot claim of the inactive target.</summary>
    public VerifiedEdlFile VendorBoot { get; }

    /// <summary>The held zero-filled init_boot claim of the inactive target.</summary>
    public VerifiedEdlFile InitBoot { get; }

    /// <summary>The held zero-filled abl claim of the inactive target.</summary>
    public VerifiedEdlFile Abl { get; }

    /// <summary>The held zero-filled xbl_config claim of the inactive target.</summary>
    public VerifiedEdlFile XblConfig { get; }

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Verifies that one slot is still factory-uninitialized while the opposite slot is the real source.
    /// </summary>
    /// <param name="profileId">Exact profile id; an unknown or incomplete profile is refused.</param>
    /// <param name="actualCurrentSlot">
    /// The slot that currently holds the real source material. It must differ from
    /// <paramref name="targetSlot"/>; it is never assumed to be <c>a</c>.
    /// </param>
    /// <param name="targetSlot">The inactive target slot, the opposite of the actual current slot.</param>
    /// <param name="currentBoot">Claim of the target's current_boot partition.</param>
    /// <param name="vendorBoot">Claim of the target's vendor_boot partition.</param>
    /// <param name="initBoot">Claim of the target's init_boot partition.</param>
    /// <param name="abl">Claim of the target's abl partition.</param>
    /// <param name="xblConfig">Claim of the target's xbl_config partition.</param>
    /// <param name="cancellationToken">Cancels the bounded streaming pass between chunks.</param>
    /// <exception cref="ArgumentException">The profile, a slot or a claim argument is unusable.</exception>
    /// <exception cref="InvalidOperationException">The resolved profile is not complete.</exception>
    /// <exception cref="InvalidDataException">A file is not a regular positive-length zero-filled file or its hash differs.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static Task<EdlRawInactiveSlotBackup> VerifyAsync(
        string profileId,
        string actualCurrentSlot,
        string targetSlot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        CancellationToken cancellationToken = default)
    {
        EdlDeviceProfile profile = RequireProfile(profileId);

        if (actualCurrentSlot is not ("a" or "b"))
        {
            throw new ArgumentException(
                "actual current slot must be exactly 'a' or 'b'.", nameof(actualCurrentSlot));
        }

        if (targetSlot is not ("a" or "b"))
        {
            throw new ArgumentException("target slot must be exactly 'a' or 'b'.", nameof(targetSlot));
        }

        if (string.Equals(actualCurrentSlot, targetSlot, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "the inactive target must be the opposite of the actual current slot.", nameof(targetSlot));
        }

        if (currentBoot is null)
        {
            throw new ArgumentNullException(nameof(currentBoot));
        }

        if (vendorBoot is null)
        {
            throw new ArgumentNullException(nameof(vendorBoot));
        }

        if (initBoot is null)
        {
            throw new ArgumentNullException(nameof(initBoot));
        }

        if (abl is null)
        {
            throw new ArgumentNullException(nameof(abl));
        }

        if (xblConfig is null)
        {
            throw new ArgumentNullException(nameof(xblConfig));
        }

        cancellationToken.ThrowIfCancellationRequested();

        return Task.Run(
            () => VerifyCore(
                profile,
                actualCurrentSlot,
                targetSlot,
                currentBoot,
                vendorBoot,
                initBoot,
                abl,
                xblConfig,
                cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Cheap usability gate for the builder: it repeats no scan and opens nothing. A proof disposed in
    /// the middle of a build must abort that build.
    /// </summary>
    internal void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
    }

    /// <summary>
    /// Releases exactly the five read leases. Idempotent, and a single close failure never skips the
    /// remaining closes. No original file is written, truncated, moved or deleted.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CloseQuietly(_bootStream);
        CloseQuietly(_vendorBootStream);
        CloseQuietly(_initBootStream);
        CloseQuietly(_ablStream);
        CloseQuietly(_xblConfigStream);
    }

    // ------------------------------------------------------------------ verification

    private static EdlDeviceProfile RequireProfile(string profileId)
    {
        EdlDeviceProfile? profile = EdlDeviceProfiles.FindById(profileId);
        if (profile is null)
        {
            throw new ArgumentException("profile id is not a known EDL profile.", nameof(profileId));
        }

        profile.RequireComplete();
        return profile;
    }

    private static EdlRawInactiveSlotBackup VerifyCore(
        EdlDeviceProfile profile,
        string sourceSlot,
        string targetSlot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        CancellationToken cancellationToken)
    {
        var opened = new List<FileStream>(5);
        try
        {
            FileStream boot = OpenZeroLease(opened, "current_boot", currentBoot, cancellationToken);
            FileStream vendor = OpenZeroLease(opened, "vendor_boot", vendorBoot, cancellationToken);
            FileStream init = OpenZeroLease(opened, "init_boot", initBoot, cancellationToken);
            FileStream ablStream = OpenZeroLease(opened, "abl", abl, cancellationToken);
            FileStream xblStream = OpenZeroLease(opened, "xbl_config", xblConfig, cancellationToken);

            return new EdlRawInactiveSlotBackup(
                profile,
                sourceSlot,
                targetSlot,
                currentBoot,
                vendorBoot,
                initBoot,
                abl,
                xblConfig,
                boot,
                vendor,
                init,
                ablStream,
                xblStream);
        }
        catch
        {
            foreach (FileStream stream in opened)
            {
                CloseQuietly(stream);
            }

            throw;
        }
    }

    /// <summary>
    /// Opens one plain read lease and proves in a single bounded pass that the bytes are zero, that the
    /// observed length equals the claim and that the SHA-256 of the same bytes equals the claim.
    /// </summary>
    private static FileStream OpenZeroLease(
        List<FileStream> opened,
        string role,
        VerifiedEdlFile claim,
        CancellationToken cancellationToken)
    {
        string fullPath = RequirePlainFile(claim.Path, role);

        if (claim.Length <= 0)
        {
            throw new InvalidDataException(role + " claim length is not positive");
        }

        if (!IsSha256Hex(claim.Sha256))
        {
            throw new InvalidDataException(role + " claim is not a 64-hex SHA-256");
        }

        FileStream stream;
        try
        {
            stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                ScanBufferBytes,
                FileOptions.SequentialScan);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException(role + ": cannot open the claimed input", exception);
        }

        opened.Add(stream);

        if (stream.Length != claim.Length)
        {
            throw new InvalidDataException(role + " length differs from its claim");
        }

        ScanZeroAndHash(stream, claim, role, cancellationToken);
        return stream;
    }

    private static void ScanZeroAndHash(
        FileStream stream,
        VerifiedEdlFile claim,
        string role,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[ScanBufferBytes];
        long observed = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            if (!IsAllZero(buffer, read))
            {
                throw new InvalidDataException(role + " is not a factory-uninitialized zero-filled slot");
            }

            hash.AppendData(buffer, 0, read);
            observed += read;
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (observed != claim.Length)
        {
            throw new InvalidDataException(role + " ended before its claimed length while scanning");
        }

        string actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        if (!string.Equals(actual, claim.Sha256.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new InvalidDataException(role + " SHA-256 differs from its claim");
        }

        stream.Position = 0;
    }

    private static bool IsAllZero(byte[] buffer, int count)
    {
        for (int index = 0; index < count; index++)
        {
            if (buffer[index] != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != Sha256HexBytes)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F'))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static string RequirePlainFile(string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw new InvalidDataException(subject + " path is empty");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidDataException(subject + " path cannot be normalized", exception);
        }

        var file = new FileInfo(fullPath);
        if (!file.Exists || IsLink(file))
        {
            throw new InvalidDataException(subject + " is not a regular file");
        }

        DirectoryInfo? directory = file.Directory;
        if (directory is null || IsLink(directory))
        {
            throw new InvalidDataException(subject + " containing directory is a reparse point");
        }

        return fullPath;
    }

    private static bool IsLink(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null;

    private static void CloseQuietly(FileStream stream)
    {
        try
        {
            stream.Dispose();
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
