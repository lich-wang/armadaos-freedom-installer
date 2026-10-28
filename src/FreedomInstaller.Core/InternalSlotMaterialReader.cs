using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>Evidence-only loader identity for one slot's Android kernel budget.</summary>
public sealed class InternalSlotLoaderBudget
{
    internal InternalSlotLoaderBudget(
        string profile, long maxRawBytes, bool knownLoaderMatch,
        string evidence, string formula)
    {
        Profile = profile;
        MaxRawBytes = maxRawBytes;
        KnownLoaderMatch = knownLoaderMatch;
        Evidence = evidence;
        Formula = formula;
    }

    public string Profile { get; }
    public long MaxRawBytes { get; }
    public bool KnownLoaderMatch { get; }
    public string Evidence { get; }
    public string Formula { get; }
}

/// <summary>Immutable same-slot Android base-kernel material (no image bytes).</summary>
public sealed class InternalSlotMaterial
{
    internal InternalSlotMaterial(
        string slot,
        bool isKshim,
        long baseImageLength,
        string baseImageSha256,
        long baseImageSize,
        ulong baseTextOffset,
        IReadOnlyDictionary<string, string> sourceSha256,
        IReadOnlyDictionary<string, long> sourceLengths,
        long bootRamdiskSize,
        long vendorRamdiskSize,
        long initRamdiskSize,
        int pageSize,
        InternalSlotLoaderBudget loaderBudget)
    {
        Slot = slot;
        IsKshim = isKshim;
        BaseImageLength = baseImageLength;
        BaseImageSha256 = baseImageSha256;
        BaseImageSize = baseImageSize;
        BaseTextOffset = baseTextOffset;
        SourceSha256 = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(sourceSha256, StringComparer.Ordinal));
        SourceLengths = new ReadOnlyDictionary<string, long>(
            new Dictionary<string, long>(sourceLengths, StringComparer.Ordinal));
        BootRamdiskSize = bootRamdiskSize;
        VendorRamdiskSize = vendorRamdiskSize;
        InitRamdiskSize = initRamdiskSize;
        TotalRamdiskSize = bootRamdiskSize + vendorRamdiskSize + initRamdiskSize;
        PageSize = pageSize;
        LoaderBudget = loaderBudget;
    }

    public string Slot { get; }
    public bool IsKshim { get; }
    public long BaseImageLength { get; }
    public string BaseImageSha256 { get; }
    public long BaseImageSize { get; }
    public ulong BaseTextOffset { get; }
    public IReadOnlyDictionary<string, string> SourceSha256 { get; }
    public IReadOnlyDictionary<string, long> SourceLengths { get; }
    public long BootRamdiskSize { get; }
    public long VendorRamdiskSize { get; }
    public long InitRamdiskSize { get; }
    public long TotalRamdiskSize { get; }
    public int PageSize { get; }
    public InternalSlotLoaderBudget LoaderBudget { get; }
    public bool OemSignedRestored => false;
    public string RecoveryScope => "android-arm64-kernel-only";
    public bool SignatureVerificationPerformed => false;
}

/// <summary>
/// Same-slot Android base kernel reader. Pure in-memory format work; the only
/// I/O is the five explicitly claimed regular files.
/// </summary>
public static class InternalSlotMaterialReader
{
    private const long MaxInputBytes = 256L * 1024 * 1024;
    private const long AbsoluteImageLimit = 268435456;

    private const int BootMinLen = 4096;
    private const int BootPage = 4096;
    private const int BootHeaderSize = 1584;
    private const uint BootVersion = 4;
    private const int BootKernelSizeOffset = 8;
    private const int BootRamdiskSizeOffset = 12;
    private const int BootHeaderSizeOffset = 20;
    private const int BootVersionOffset = 40;
    private const int BootSignatureSizeOffset = 1580;

    private const int VendorHeaderSize = 2128;
    private const uint VendorVersion = 4;
    private const int VendorMinPage = 4096;
    private const int VendorMaxPage = 65536;
    private const int VendorVersionOffset = 8;
    private const int VendorPageOffset = 12;
    private const int VendorRamdiskSizeOffset = 24;
    private const int VendorHeaderSizeOffset = 2096;
    private const int VendorDtbSizeOffset = 2100;
    private const int VendorTableSizeOffset = 2112;
    private const int VendorTableCountOffset = 2116;
    private const int VendorTableEntrySizeOffset = 2120;
    private const int VendorBootconfigSizeOffset = 2124;
    private const uint VendorTableEntryMin = 108;

    private const int Arm64MinLen = 64;
    private const int Arm64MagicOffset = 0x38;
    private const int Arm64TextOffset = 8;
    private const int Arm64ImageSizeOffset = 0x10;
    private const int Arm64FlagsOffset = 0x18;

    private const uint ManifestMagic = 0x464D504B;
    private const ushort ManifestVMajor = 0;
    private const ushort ManifestVMinor = 1;
    private const int ManifestHeaderSize = 60;
    private const int ManifestEntrySize = 56;
    private const int ManifestEntryAlign = 4;
    private const int ManifestMaxEntries = 50;
    private const uint ManifestMaxName = 255;
    private const uint ManifestMinAlign = 2;
    private const uint ManifestMaxAlign = 21;

    private const uint FlagBase = 1;
    private const uint FlagExec = 4;
    private const uint FlagHasDtb = 8;

    private const uint TypeLinux = 1;
    private const uint TypeShim = 3;
    private const uint TypeBlob = 4;
    private const uint TypeDtb = 5;

    private const uint BlOpcode = 0x94000000;
    private const uint BOpcode = 0x14000000;
    private const uint BranchMask = 0xFC000000;
    private const uint Imm26Mask = 0x03FFFFFF;
    private const uint Sign26 = 0x02000000;
    private const long BlSignedRange = 0x08000000;

    private const long LoaderWindow = 268435456;
    private const long LoaderHeadReserve = 524288;
    private const long LoaderTailReserve = 2097152;
    private const long LoaderGuard = 2 * 4096;
    private const int LoaderAlign = 4096;
    private const long DefaultRawBudget = 134217728;
    private const string DefaultProfile = "conservative-default";
    private const string KnownProfile = "tb322fc-abl259-xbl-config-ramdisk-derived";
    private const string StructuralProfile = "tb322fc-abl-kernel-region-derived";
    private const string KnownAblSha256 = "e7062378a1fe977df95341e5d3023dd510cffb283b11902a7cdbe74ba3e43885";
    private const long KnownAblBytes = 1048576;
    private const string KnownXblSha256 = "88e56e47c12b68bca70b8943739bc3114ad6f9166ebc654945919bb1a158fbed";
    private const long KnownXblBytes = 352256;
    private const string KnownBAblSha256 = "811489f0cefb662bccf91a89d2b50187cc1e8fb949486421fe19f820981ecae0";
    private const string KnownBXblSha256 = "1a937da630c966372a67ba60d0103997f61ce7d1df086b7b6c68e4fcc0ba73c3";
    private const int KnownPage = 4096;
    private const int KnownV4Headers = 3;

    private static readonly byte[] GzipMagic = { 0x1F, 0x8B };
    private static readonly byte[] Arm64Magic = { (byte)'A', (byte)'R', (byte)'M', 0x64 };
    private static readonly byte[] QcAbtMagic = Encoding.ASCII.GetBytes("UNCOMPRESSED_IMG");
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly long[] BackupOffsets = { 0, 16, 32, 40, 48 };

    public static Task<InternalSlotMaterial> AnalyzeAsync(
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        CancellationToken token = default)
    {
        if (slot is not ("a" or "b"))
        {
            throw new ArgumentException("slot must be 'a' or 'b'.", nameof(slot));
        }
        ArgumentNullException.ThrowIfNull(currentBoot);
        ArgumentNullException.ThrowIfNull(vendorBoot);
        ArgumentNullException.ThrowIfNull(initBoot);
        ArgumentNullException.ThrowIfNull(abl);
        ArgumentNullException.ThrowIfNull(xblConfig);

        return Task.Run(
            () => Analyze(slot, currentBoot, vendorBoot, initBoot, abl, xblConfig, token),
            token);
    }

    /// <summary>
    /// Same five-source verification and base recovery as <see cref="AnalyzeAsync"/>,
    /// additionally writing the already recovered base image to a caller-owned path.
    /// The export is material only; no bytes are exposed through the public API.
    /// </summary>
    internal static Task<InternalSlotMaterial> AnalyzeAndExportBaseAsync(
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        string baseOutputPath,
        CancellationToken token = default)
    {
        if (slot is not ("a" or "b"))
        {
            throw new ArgumentException("slot must be 'a' or 'b'.", nameof(slot));
        }
        ArgumentNullException.ThrowIfNull(currentBoot);
        ArgumentNullException.ThrowIfNull(vendorBoot);
        ArgumentNullException.ThrowIfNull(initBoot);
        ArgumentNullException.ThrowIfNull(abl);
        ArgumentNullException.ThrowIfNull(xblConfig);
        if (string.IsNullOrWhiteSpace(baseOutputPath))
        {
            throw new ArgumentException(
                "base output path must name a non-empty file path.", nameof(baseOutputPath));
        }

        string outputPath = Path.GetFullPath(baseOutputPath);

        return Task.Run(
            () => Analyze(
                slot, currentBoot, vendorBoot, initBoot, abl, xblConfig, token, outputPath),
            token);
    }

    private static InternalSlotMaterial Analyze(
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        CancellationToken token,
        string? baseOutputPath = null)
    {
        FileStream? currentStream = null;
        FileStream? vendorStream = null;
        FileStream? initStream = null;
        FileStream? ablStream = null;
        FileStream? xblStream = null;
        try
        {
            currentStream = OpenVerified(currentBoot, "current_boot");
            vendorStream = OpenVerified(vendorBoot, "vendor_boot");
            initStream = OpenVerified(initBoot, "init_boot");
            ablStream = OpenVerified(abl, "abl");
            xblStream = OpenVerified(xblConfig, "xbl_config");

            byte[] vendorPrefix = ReadPrefix(vendorStream, VendorHeaderSize, token);
            string vendorSha = HashPrefixThenRest(vendorStream, vendorPrefix, token);
            VendorInfo vendor = ParseVendorHeader(vendorPrefix, vendorBoot.Length);

            byte[] initPrefix = ReadPrefix(initStream, BootMinLen, token);
            string initSha = HashPrefixThenRest(initStream, initPrefix, token);
            BootInfo init = ParseBootHeader(initPrefix, initBoot.Length, "init_boot", false);

            byte[] ablBytes = ReadClaimedFully(ablStream, abl, "abl", token, out string ablSha);
            byte[] xblBytes = ReadClaimedFully(
                xblStream, xblConfig, "xbl_config", token, out string xblSha);

            byte[] currentPrefix = ReadPrefix(currentStream, BootMinLen, token);
            BootInfo current = ParseBootHeader(
                currentPrefix, currentBoot.Length, "current_boot", true);

            InternalSlotLoaderBudget budget = ComputeLoaderBudget(
                ablSha, abl.Length,
                xblSha, xblConfig.Length,
                vendor.PageSize,
                current.RamdiskSize,
                vendor.RamdiskSize,
                init.RamdiskSize,
                KnownV4Headers);

            // The exact-pair fast path above is hash pinned. Only when it declines, and only on the
            // reviewed page size, may the structural recognizer promote the same-slot pair. The three
            // v4 headers were already validated by the parsers before this point, and the one array
            // that was hashed is the one recognized, so identity and recognition cannot diverge.
            if (!budget.KnownLoaderMatch &&
                vendor.PageSize == KnownPage &&
                InternalSlotLoaderStructure.TryRecognize(
                    ablBytes, xblBytes, token, out string loaderEvidence))
            {
                budget = ComputeStructuralLoaderBudget(
                    current.RamdiskSize + vendor.RamdiskSize + init.RamdiskSize,
                    loaderEvidence);
            }

            if (current.KernelSize > int.MaxValue || current.KernelSize > MaxInputBytes)
            {
                throw Reject("current_boot", "kernel size exceeds the supported bound");
            }

            byte[] kernel = ReadKernelThenRest(
                currentStream, currentPrefix, current.KernelSize, token, out string currentSha);

            VerifyClaim(currentBoot, "current_boot", currentSha, currentBoot.Length);
            VerifyClaim(vendorBoot, "vendor_boot", vendorSha, vendorBoot.Length);
            VerifyClaim(initBoot, "init_boot", initSha, initBoot.Length);
            VerifyClaim(abl, "abl", ablSha, abl.Length);
            VerifyClaim(xblConfig, "xbl_config", xblSha, xblConfig.Length);

            (byte[] baseImage, bool isKshim) = RecoverBaseImage(
                kernel, budget.MaxRawBytes, token);
            string baseSha = Sha256Hex(baseImage);
            long baseImageSize = (long)ReadUInt64(baseImage, Arm64ImageSizeOffset);
            ulong baseTextOffset = ReadUInt64(baseImage, Arm64TextOffset);

            if (baseOutputPath is not null)
            {
                WriteRecoveredBase(baseOutputPath, baseImage, token);
            }

            var sourceSha = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["current_boot"] = currentSha,
                ["vendor_boot"] = vendorSha,
                ["init_boot"] = initSha,
                ["abl"] = ablSha,
                ["xbl_config"] = xblSha,
            };
            var sourceLengths = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["current_boot"] = currentBoot.Length,
                ["vendor_boot"] = vendorBoot.Length,
                ["init_boot"] = initBoot.Length,
                ["abl"] = abl.Length,
                ["xbl_config"] = xblConfig.Length,
            };

            return new InternalSlotMaterial(
                slot,
                isKshim,
                baseImage.LongLength,
                baseSha,
                baseImageSize,
                baseTextOffset,
                sourceSha,
                sourceLengths,
                current.RamdiskSize,
                vendor.RamdiskSize,
                init.RamdiskSize,
                vendor.PageSize,
                budget);
        }
        finally
        {
            currentStream?.Dispose();
            vendorStream?.Dispose();
            initStream?.Dispose();
            ablStream?.Dispose();
            xblStream?.Dispose();
        }
    }

    // ---------------------------------------------------------------- I/O

    private static FileStream OpenVerified(VerifiedEdlFile file, string role)
    {
        if (string.IsNullOrEmpty(file.Path))
        {
            throw Reject(role, "path is empty");
        }

        _ = NormalizeClaimedSha(file.Sha256, role);

        FileStream stream;
        try
        {
            stream = new FileStream(
                file.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
                64 * 1024, FileOptions.SequentialScan);
        }
        catch (Exception ex) when (
            ex is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException($"{role}: cannot open input", ex);
        }

        try
        {
            long actual = stream.Length;
            if (file.Length < 0 || actual != file.Length)
            {
                throw Reject(role, $"claimed length {file.Length} differs from actual {actual}");
            }
            if (actual > MaxInputBytes)
            {
                throw Reject(role, $"length {actual} exceeds {MaxInputBytes}");
            }
        }
        catch
        {
            stream.Dispose();
            throw;
        }

        return stream;
    }

    private static byte[] ReadPrefix(FileStream stream, int count, CancellationToken token)
    {
        byte[] prefix = new byte[count];
        int read = 0;
        while (read < count)
        {
            token.ThrowIfCancellationRequested();
            int n = stream.Read(prefix, read, count - read);
            if (n == 0)
            {
                break;
            }
            read += n;
        }
        if (read != count)
        {
            Array.Resize(ref prefix, read);
        }
        return prefix;
    }

    private static string HashPrefixThenRest(
        FileStream stream, byte[] prefix, CancellationToken token)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(prefix, 0, prefix.Length);
        byte[] buffer = new byte[64 * 1024];
        while (true)
        {
            token.ThrowIfCancellationRequested();
            int n = stream.Read(buffer, 0, buffer.Length);
            if (n == 0)
            {
                break;
            }
            hash.AppendData(buffer, 0, n);
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// Reads one already claimed loader file exactly once from offset zero. The returned array is the
    /// byte sequence that is hashed and the byte sequence handed to the structural recognizer, so a
    /// short read is a rejection rather than a silently truncated identity.
    /// </summary>
    private static byte[] ReadClaimedFully(
        FileStream stream, VerifiedEdlFile file, string role, CancellationToken token, out string sha256)
    {
        if (file.Length < 0 || file.Length > MaxInputBytes || file.Length > int.MaxValue)
        {
            throw Reject(role, $"claimed length {file.Length} is outside the bounded input window");
        }

        byte[] bytes = ReadPrefix(stream, (int)file.Length, token);
        if (bytes.LongLength != file.Length)
        {
            throw Reject(role, $"read {bytes.LongLength} of the claimed {file.Length} bytes");
        }

        sha256 = Sha256Hex(bytes);
        return bytes;
    }

    private static void WriteRecoveredBase(
        string baseOutputPath, byte[] baseImage, CancellationToken token)
    {
        // CreateNew only: an existing caller path is never overwritten or truncated.
        // The exclusive write handle is flushed and closed before the caller returns.
        using FileStream output = new FileStream(
            baseOutputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            64 * 1024);
        int offset = 0;
        while (offset < baseImage.Length)
        {
            token.ThrowIfCancellationRequested();
            int count = Math.Min(64 * 1024, baseImage.Length - offset);
            output.Write(baseImage, offset, count);
            offset += count;
        }
        token.ThrowIfCancellationRequested();
        output.Flush(flushToDisk: true);
    }

    private static byte[] ReadKernelThenRest(
        FileStream stream, byte[] prefix, long kernelSize, CancellationToken token,
        out string sha256)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(prefix, 0, prefix.Length);

        byte[] kernel = new byte[(int)kernelSize];
        long copied = 0;
        byte[] buffer = new byte[64 * 1024];
        while (true)
        {
            token.ThrowIfCancellationRequested();
            int n = stream.Read(buffer, 0, buffer.Length);
            if (n == 0)
            {
                break;
            }
            hash.AppendData(buffer, 0, n);
            if (copied < kernelSize)
            {
                int take = (int)Math.Min(n, kernelSize - copied);
                Buffer.BlockCopy(buffer, 0, kernel, (int)copied, take);
                copied += take;
            }
        }

        if (copied != kernelSize)
        {
            throw Reject("current_boot", "kernel region is truncated");
        }
        sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        return kernel;
    }

    private static string NormalizeClaimedSha(string? claimed, string role)
    {
        if (claimed is null || claimed.Length != 64)
        {
            throw Reject(role, "claimed sha256 must be 64 hex characters");
        }
        foreach (char c in claimed)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                throw Reject(role, "claimed sha256 is not hexadecimal");
            }
        }
        return claimed.ToLowerInvariant();
    }

    private static void VerifyClaim(
        VerifiedEdlFile file, string role, string actualSha256, long actualLength)
    {
        string claimed = NormalizeClaimedSha(file.Sha256, role);
        if (file.Length != actualLength)
        {
            throw Reject(role, $"claimed length {file.Length} differs from actual {actualLength}");
        }
        if (!string.Equals(claimed, actualSha256, StringComparison.Ordinal))
        {
            throw Reject(role, "actual sha256 does not match the verified claim");
        }
    }

    // ------------------------------------------------------------- headers

    private readonly record struct BootInfo(long KernelSize, long RamdiskSize);
    private readonly record struct VendorInfo(long RamdiskSize, int PageSize);

    private static BootInfo ParseBootHeader(
        ReadOnlySpan<byte> header, long length, string role, bool kernelRequired)
    {
        if (length < BootMinLen)
        {
            throw Reject(role, $"length {length} is below {BootMinLen}");
        }
        if (!header.Slice(0, 8).SequenceEqual("ANDROID!"u8))
        {
            throw Reject(role, "bad boot magic");
        }
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(BootVersionOffset, 4));
        if (version != BootVersion)
        {
            throw Reject(role, $"boot header version {version}, expected {BootVersion}");
        }
        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(BootHeaderSizeOffset, 4));
        if (headerSize != BootHeaderSize)
        {
            throw Reject(role, $"boot header_size {headerSize}, expected {BootHeaderSize}");
        }

        uint kernelSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(BootKernelSizeOffset, 4));
        uint ramdiskSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(BootRamdiskSizeOffset, 4));
        uint signatureSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(BootSignatureSizeOffset, 4));

        if (kernelRequired)
        {
            if (kernelSize == 0)
            {
                throw Reject(role, "current boot has an empty kernel");
            }
        }
        else if (kernelSize != 0)
        {
            throw Reject(role, $"init_boot kernel_size must be 0, got {kernelSize}");
        }

        long kernelEnd = BootPage + (long)kernelSize;
        long ramdiskStart = AlignUp(kernelEnd, BootPage);
        long ramdiskEnd = ramdiskStart + ramdiskSize;
        long signatureStart = AlignUp(ramdiskEnd, BootPage);
        long signatureEnd = signatureStart + signatureSize;
        if (signatureEnd > length)
        {
            throw Reject(role,
                $"kernel/ramdisk/signature regions exceed input (need {signatureEnd}, have {length})");
        }

        return new BootInfo(kernelSize, ramdiskSize);
    }

    private static VendorInfo ParseVendorHeader(ReadOnlySpan<byte> header, long length)
    {
        const string role = "vendor_boot";
        if (length < VendorHeaderSize)
        {
            throw Reject(role, $"length {length} is below header size {VendorHeaderSize}");
        }
        if (!header.Slice(0, 8).SequenceEqual("VNDRBOOT"u8))
        {
            throw Reject(role, "bad vendor boot magic");
        }
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorVersionOffset, 4));
        if (version != VendorVersion)
        {
            throw Reject(role, $"vendor header version {version}, expected {VendorVersion}");
        }

        uint page = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorPageOffset, 4));
        if (page < VendorMinPage || page > VendorMaxPage)
        {
            throw Reject(role, $"page size {page} outside [{VendorMinPage}, {VendorMaxPage}]");
        }
        if ((page & (page - 1)) != 0)
        {
            throw Reject(role, $"page size {page} is not a power of two");
        }

        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorHeaderSizeOffset, 4));
        if (headerSize != VendorHeaderSize)
        {
            throw Reject(role, $"vendor header_size {headerSize}, expected {VendorHeaderSize}");
        }
        if (headerSize > page)
        {
            throw Reject(role, $"header_size {headerSize} exceeds page {page}");
        }

        uint ramdiskSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorRamdiskSizeOffset, 4));
        uint dtbSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorDtbSizeOffset, 4));
        uint tableSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorTableSizeOffset, 4));
        uint tableCount = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorTableCountOffset, 4));
        uint tableEntrySize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorTableEntrySizeOffset, 4));
        uint bootconfigSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(VendorBootconfigSizeOffset, 4));

        if (tableCount == 0)
        {
            if (tableSize != 0 ||
                (tableEntrySize != 0 && tableEntrySize != VendorTableEntryMin))
            {
                throw Reject(role, "empty table count with non-empty table geometry");
            }
        }
        else
        {
            if (tableSize == 0)
            {
                throw Reject(role, $"table count {tableCount} with empty table");
            }
            if (tableEntrySize < VendorTableEntryMin)
            {
                throw Reject(role, $"table entry size {tableEntrySize} below {VendorTableEntryMin}");
            }
            if ((ulong)tableCount * tableEntrySize > tableSize)
            {
                throw Reject(role,
                    $"table count {tableCount} * entry {tableEntrySize} exceeds table {tableSize}");
            }
        }

        long ramdiskStart = page;
        long ramdiskEnd = ramdiskStart + ramdiskSize;
        long dtbStart = AlignUp(ramdiskEnd, (int)page);
        long dtbEnd = dtbStart + dtbSize;
        long tableStart = AlignUp(dtbEnd, (int)page);
        long tableEnd = tableStart + tableSize;
        long bootconfigStart = AlignUp(tableEnd, (int)page);
        long bootconfigEnd = bootconfigStart + bootconfigSize;
        if (bootconfigEnd > length)
        {
            throw Reject(role,
                $"ramdisk/DTB/table/bootconfig regions exceed input (need {bootconfigEnd}, have {length})");
        }

        return new VendorInfo(ramdiskSize, (int)page);
    }

    // -------------------------------------------------------------- budget

    private static InternalSlotLoaderBudget ComputeLoaderBudget(
        string ablSha256, long ablBytes,
        string xblSha256, long xblBytes,
        int pageSize,
        long bootRamdiskSize,
        long vendorRamdiskSize,
        long initRamdiskSize,
        int v4HeaderCount)
    {
        long total = bootRamdiskSize + vendorRamdiskSize + initRamdiskSize;
        bool knownPair =
            (string.Equals(ablSha256, KnownAblSha256, StringComparison.Ordinal) &&
             string.Equals(xblSha256, KnownXblSha256, StringComparison.Ordinal)) ||
            (string.Equals(ablSha256, KnownBAblSha256, StringComparison.Ordinal) &&
             string.Equals(xblSha256, KnownBXblSha256, StringComparison.Ordinal));
        bool known =
            knownPair &&
            ablBytes == KnownAblBytes &&
            xblBytes == KnownXblBytes &&
            pageSize == KnownPage &&
            v4HeaderCount == KnownV4Headers;

        if (known)
        {
            long aligned = AlignUp(total, LoaderAlign);
            long room = LoaderWindow - LoaderHeadReserve - aligned - LoaderGuard - LoaderTailReserve;
            if (room <= 0)
            {
                throw Reject("loader_budget", $"non-positive raw room {room}");
            }
            return new InternalSlotLoaderBudget(
                KnownProfile,
                room,
                true,
                "identified ABL/xbl_config full sha256+length as a reviewed exact A or B pair, page 4096, three validated v4 headers; static normal GetVariable success path and matching XBL LOAD/FDT capacity arithmetic only; runtime GetVariable results and physical B-slot capacity remain unverified",
                $"max_raw_bytes = 268435456 - 524288 - align_up({total}, 4096) - 8192 - 2097152");
        }

        return new InternalSlotLoaderBudget(
            DefaultProfile,
            DefaultRawBudget,
            false,
            "unrecognized loader identity: conservative 128 MiB policy, not a measured hardware limit",
            "max_raw_bytes = 134217728 (conservative fallback)");
    }

    /// <summary>
    /// Structural (not hash pinned) identity for the reviewed A/B loader capture. It publishes the same
    /// checked arithmetic as the exact pair, and carries the recognizer's own conditional evidence
    /// instead of restating it, so no runtime or physical-capacity claim is promoted here.
    /// </summary>
    private static InternalSlotLoaderBudget ComputeStructuralLoaderBudget(long total, string evidence)
    {
        long aligned = AlignUp(total, LoaderAlign);
        long room = LoaderWindow - LoaderHeadReserve - aligned - LoaderGuard - LoaderTailReserve;
        if (room <= 0)
        {
            throw Reject("loader_budget", $"non-positive raw room {room}");
        }

        return new InternalSlotLoaderBudget(
            StructuralProfile,
            room,
            true,
            evidence,
            $"max_raw_bytes = 268435456 - 524288 - align_up({total}, 4096) - 8192 - 2097152");
    }

    // ------------------------------------------------------------- recover

    private static (byte[] BaseImage, bool IsKshim) RecoverBaseImage(
        byte[] kernel, long budget, CancellationToken token)
    {
        long limit = Math.Min(budget, AbsoluteImageLimit);
        byte[] raw;
        if (kernel.Length >= 2 && kernel[0] == GzipMagic[0] && kernel[1] == GzipMagic[1])
        {
            raw = InflateGzip(kernel, limit, token);
        }
        else
        {
            if (kernel.LongLength > limit)
            {
                throw Reject("kernel", $"raw kernel {kernel.LongLength} exceeds budget {limit}");
            }
            raw = kernel;
        }

        if (IsKshimIndication(raw))
        {
            return (UnpackKshim(raw, budget, token), true);
        }
        ValidatePlainArm64(raw, budget);
        return (raw, false);
    }

    private static bool IsKshimIndication(byte[] raw)
    {
        if (raw.Length < Arm64MinLen)
        {
            return false;
        }
        if ((ReadUInt32(raw, 0) & BranchMask) == BlOpcode)
        {
            return true;
        }
        return ReadUInt64(raw, 32) != 0 ||
               ReadUInt64(raw, 40) != 0 ||
               ReadUInt64(raw, 48) != 0;
    }

    private static void ValidatePlainArm64(byte[] raw, long budget)
    {
        const string label = "kernel";
        if (raw.Length < Arm64MinLen)
        {
            throw Reject(label, $"ARM64 image shorter than {Arm64MinLen} bytes");
        }
        if (raw.AsSpan(0, QcAbtMagic.Length).SequenceEqual(QcAbtMagic))
        {
            throw Reject(label, "Qualcomm UNCOMPRESSED_IMG wrapper is not supported");
        }
        if (!raw.AsSpan(Arm64MagicOffset, 4).SequenceEqual(Arm64Magic))
        {
            throw Reject(label, "bad ARM64 magic at 0x38");
        }
        ulong imageSize = ReadUInt64(raw, Arm64ImageSizeOffset);
        if (imageSize < (ulong)Arm64MinLen)
        {
            throw Reject(label, $"image_size {imageSize} below {Arm64MinLen}");
        }
        if (imageSize > (ulong)budget)
        {
            throw Reject(label, $"image_size {imageSize} exceeds budget {budget}");
        }
        if (raw.LongLength > budget)
        {
            throw Reject(label, $"raw length {raw.LongLength} exceeds budget {budget}");
        }
    }

    private sealed class ManifestEntry
    {
        public int Index;
        public string Name = string.Empty;
        public ulong Offset;
        public ulong Size;
        public uint Type;
        public uint Flags;
        public ulong Load;
        public uint EntryAddress;
        public uint Dtb;
        public uint Align;
        public ulong Copy;
    }

    private static byte[] UnpackKshim(byte[] raw, long budget, CancellationToken token)
    {
        const string label = "kshim";
        int rawLength = raw.Length;
        if (rawLength < Arm64MinLen)
        {
            throw Reject(label, $"image shorter than {Arm64MinLen} bytes");
        }
        if (!raw.AsSpan(Arm64MagicOffset, 4).SequenceEqual(Arm64Magic))
        {
            throw Reject(label, "bad ARM64 magic at 0x38");
        }
        ulong imageSize = ReadUInt64(raw, Arm64ImageSizeOffset);
        if (imageSize != (ulong)rawLength)
        {
            throw Reject(label,
                $"patched image_size {imageSize} must equal composite length {rawLength}");
        }

        ulong manifestOffset = ReadUInt64(raw, 32);
        ulong manifestSize = ReadUInt64(raw, 40);
        ulong shimOffset = ReadUInt64(raw, 48);

        if (manifestOffset < Arm64MinLen)
        {
            throw Reject(label, $"manifest offset {manifestOffset} below {Arm64MinLen}");
        }
        if (manifestSize < ManifestHeaderSize)
        {
            throw Reject(label, $"manifest size {manifestSize} below header size {ManifestHeaderSize}");
        }
        if (manifestOffset > (ulong)rawLength ||
            manifestSize > (ulong)rawLength - manifestOffset)
        {
            throw Reject(label, "manifest must end exactly at end of image");
        }
        if (manifestOffset + manifestSize != (ulong)rawLength)
        {
            throw Reject(label, "manifest must end exactly at end of image");
        }
        if (shimOffset == 0 || shimOffset % 4 != 0)
        {
            throw Reject(label, $"shim offset {shimOffset} is not a positive 4-aligned target");
        }
        if (shimOffset >= BlSignedRange)
        {
            throw Reject(label, $"shim offset {shimOffset} outside BL signed range");
        }

        int mo = (int)manifestOffset;
        uint magic = ReadUInt32(raw, mo);
        ushort vmajor = ReadUInt16(raw, mo + 4);
        ushort vminor = ReadUInt16(raw, mo + 6);
        uint count = ReadUInt32(raw, mo + 8);
        uint defaultIndex = ReadUInt32(raw, mo + 12);
        ulong[] backup = new ulong[5];
        for (int i = 0; i < 5; i++)
        {
            backup[i] = ReadUInt64(raw, mo + 20 + i * 8);
        }

        if (magic != ManifestMagic)
        {
            throw Reject(label, $"bad manifest magic 0x{magic:x8}");
        }
        if (vmajor != ManifestVMajor || vminor != ManifestVMinor)
        {
            throw Reject(label,
                $"manifest version {vmajor}.{vminor}, expected {ManifestVMajor}.{ManifestVMinor}");
        }
        if (count == 0 || count > ManifestMaxEntries)
        {
            throw Reject(label, $"manifest entry count {count} out of range");
        }
        if (defaultIndex >= count)
        {
            throw Reject(label, $"manifest default index {defaultIndex} out of range");
        }

        int limit = rawLength;
        int cursor = mo + ManifestHeaderSize;
        var entries = new ManifestEntry[(int)count];
        for (int index = 0; index < count; index++)
        {
            token.ThrowIfCancellationRequested();
            if ((long)cursor + ManifestEntrySize > limit)
            {
                throw Reject(label, $"entry {index} header runs past manifest table");
            }
            ulong eOffset = ReadUInt64(raw, cursor);
            ulong eSize = ReadUInt64(raw, cursor + 8);
            uint eType = ReadUInt32(raw, cursor + 16);
            uint eFlags = ReadUInt32(raw, cursor + 20);
            ulong eLoad = ReadUInt64(raw, cursor + 24);
            uint eEntry = ReadUInt32(raw, cursor + 32);
            uint eDtb = ReadUInt32(raw, cursor + 36);
            uint eAlign = ReadUInt32(raw, cursor + 40);
            ulong eCopy = ReadUInt64(raw, cursor + 44);
            uint eNamelen = ReadUInt32(raw, cursor + 52);

            long nameEnd = (long)cursor + ManifestEntrySize + eNamelen;
            long recordEnd = (long)cursor + AlignUp(ManifestEntrySize + eNamelen, ManifestEntryAlign);
            if (eNamelen > ManifestMaxName || nameEnd > limit)
            {
                throw Reject(label, $"entry {index} name runs past manifest table");
            }
            if (recordEnd > limit)
            {
                throw Reject(label, $"entry {index} record runs past manifest table");
            }
            for (long pad = nameEnd; pad < recordEnd; pad++)
            {
                if (raw[pad] != 0)
                {
                    throw Reject(label, $"entry {index} has non-zero name padding");
                }
            }
            string name;
            try
            {
                name = StrictUtf8.GetString(
                    raw, cursor + ManifestEntrySize, (int)eNamelen);
            }
            catch (DecoderFallbackException)
            {
                throw Reject(label, $"entry {index} name is not valid UTF-8");
            }
            if (eType != TypeLinux && eType != TypeShim &&
                eType != TypeBlob && eType != TypeDtb)
            {
                throw Reject(label, $"entry {index} has unknown type {eType}");
            }
            if (eAlign < ManifestMinAlign || eAlign > ManifestMaxAlign)
            {
                throw Reject(label,
                    $"entry {index} alignment exponent {eAlign} outside [{ManifestMinAlign}, {ManifestMaxAlign}]");
            }
            if (eOffset % (1UL << (int)eAlign) != 0)
            {
                throw Reject(label,
                    $"entry {index} offset {eOffset} not aligned to 2^{eAlign}");
            }
            if (eOffset + eSize < eOffset || eOffset + eSize > manifestOffset)
            {
                throw Reject(label,
                    $"entry {index} payload {eOffset}+{eSize} overlaps manifest at {manifestOffset}");
            }

            entries[index] = new ManifestEntry
            {
                Index = index,
                Name = name,
                Offset = eOffset,
                Size = eSize,
                Type = eType,
                Flags = eFlags,
                Load = eLoad,
                EntryAddress = eEntry,
                Dtb = eDtb,
                Align = eAlign,
                Copy = eCopy,
            };
            cursor = (int)recordEnd;
        }

        if (cursor != limit)
        {
            throw Reject(label, "entry table does not exactly fill the manifest");
        }

        foreach (ManifestEntry record in entries)
        {
            if ((record.Flags & FlagHasDtb) != 0)
            {
                uint reference = record.Dtb;
                if (reference >= count)
                {
                    throw Reject(label,
                        $"entry {record.Index} DTB index {reference} out of range");
                }
                if (entries[(int)reference].Type != TypeDtb)
                {
                    throw Reject(label,
                        $"entry {record.Index} DTB index {reference} is not a DTB entry");
                }
            }
        }

        int baseIndex = -1;
        int baseCount = 0;
        for (int i = 0; i < entries.Length; i++)
        {
            if ((entries[i].Flags & FlagBase) != 0)
            {
                baseCount++;
                baseIndex = i;
            }
        }
        if (baseCount != 1)
        {
            throw Reject(label, $"expected exactly one BASE entry, found {baseCount}");
        }

        ManifestEntry baseEntry = entries[baseIndex];
        if (baseEntry.Type != TypeLinux)
        {
            throw Reject(label, $"BASE entry type {baseEntry.Type} is not Linux");
        }
        if (baseEntry.Flags != (FlagBase | FlagExec))
        {
            throw Reject(label, $"BASE entry flags 0x{baseEntry.Flags:x} are not exactly BASE|EXEC");
        }
        if (baseEntry.Offset != 0)
        {
            throw Reject(label, $"BASE entry offset {baseEntry.Offset} is not 0");
        }
        if (baseEntry.Size < (ulong)Arm64MinLen)
        {
            throw Reject(label, $"BASE entry size {baseEntry.Size} below {Arm64MinLen}");
        }
        if (baseEntry.Size > (ulong)rawLength)
        {
            throw Reject(label, $"BASE entry size {baseEntry.Size} exceeds image length {rawLength}");
        }
        if (baseEntry.Load != 0 || baseEntry.EntryAddress != 0 || baseEntry.Copy != 0)
        {
            throw Reject(label, "BASE entry carries unexpected load/entry/copy values");
        }

        int shimIndex = -1;
        int shimCount = 0;
        for (int i = 0; i < entries.Length; i++)
        {
            if (entries[i].Type == TypeShim)
            {
                shimCount++;
                shimIndex = i;
            }
        }
        if (shimCount != 1)
        {
            throw Reject(label, $"expected exactly one shim entry, found {shimCount}");
        }
        ManifestEntry shim = entries[shimIndex];
        if (shim.Offset != shimOffset)
        {
            throw Reject(label,
                $"shim entry offset {shim.Offset} differs from header {shimOffset}");
        }
        if ((shim.Flags & FlagExec) == 0)
        {
            throw Reject(label, "shim entry is not executable");
        }
        if (shim.Size == 0)
        {
            throw Reject(label, "shim entry is empty");
        }

        var intervals = new List<(long Start, long End, int Index)>();
        foreach (ManifestEntry record in entries)
        {
            if (record.Index == baseEntry.Index || record.Size == 0)
            {
                continue;
            }
            long start = (long)record.Offset;
            long end = start + (long)record.Size;
            if (start < (long)baseEntry.Size)
            {
                throw Reject(label,
                    $"entry {record.Index} payload overlaps the BASE payload");
            }
            intervals.Add((start, end, record.Index));
        }

        for (int left = 0; left < intervals.Count; left++)
        {
            for (int right = left + 1; right < intervals.Count; right++)
            {
                var first = intervals[left];
                var second = intervals[right];
                if (!(first.Start < second.End && second.Start < first.End))
                {
                    continue;
                }
                if (first.Start != second.Start || first.End != second.End)
                {
                    throw Reject(label,
                        $"entries {first.Index} and {second.Index} partially overlap");
                }
                ManifestEntry leftEntry = entries[first.Index];
                ManifestEntry rightEntry = entries[second.Index];
                if (!(leftEntry.Type == TypeLinux && rightEntry.Type == TypeLinux &&
                      (leftEntry.Flags & FlagExec) != 0 &&
                      (rightEntry.Flags & FlagExec) != 0 &&
                      (leftEntry.Flags & FlagBase) == 0 &&
                      (rightEntry.Flags & FlagBase) == 0))
                {
                    throw Reject(label,
                        $"entries {first.Index} and {second.Index} share an exact interval but are not executable non-BASE Linux entries");
                }
            }
        }

        uint word0 = ReadUInt32(raw, 0);
        uint word1 = ReadUInt32(raw, 4);
        if ((word0 & BranchMask) != BlOpcode)
        {
            throw Reject(label, "patched word0 is not a BL instruction");
        }
        long target = Imm26Target(word0);
        if (target != (long)shimOffset)
        {
            throw Reject(label, $"patched word0 target {target} differs from shim {shimOffset}");
        }
        if (!(target > 0 && target < BlSignedRange))
        {
            throw Reject(label, $"patched BL target {target} outside signed range");
        }

        uint originalWord0 = (uint)(backup[0] & 0xFFFFFFFF);
        uint originalWord1 = (uint)(backup[0] >> 32);
        uint expectedWord1;
        if (IsBranchB(originalWord0) && !IsBranchB(originalWord1))
        {
            expectedWord1 = BOpcode | ((originalWord0 - 1) & Imm26Mask);
        }
        else
        {
            if (!IsBranchB(originalWord1))
            {
                throw Reject(label, "backup word1 is not a B instruction");
            }
            expectedWord1 = originalWord1;
        }
        if (word1 != expectedWord1)
        {
            throw Reject(label,
                $"patched word1 0x{word1:x8}, expected 0x{expectedWord1:x8}");
        }

        int baseSize = (int)baseEntry.Size;
        byte[] payload = new byte[baseSize];
        Buffer.BlockCopy(raw, 0, payload, 0, baseSize);
        byte[] restored = (byte[])payload.Clone();
        for (int i = 0; i < BackupOffsets.Length; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                restored.AsSpan((int)BackupOffsets[i], 8), backup[i]);
        }

        if (restored.Length < Arm64MinLen)
        {
            throw Reject(label, $"restored base is shorter than {Arm64MinLen} bytes");
        }
        if (!restored.AsSpan(Arm64MagicOffset, 4).SequenceEqual(Arm64Magic))
        {
            throw Reject(label, "restored base lost ARM64 magic");
        }
        if (!restored.AsSpan(Arm64TextOffset, 8).SequenceEqual(
                payload.AsSpan(Arm64TextOffset, 8)))
        {
            throw Reject(label, "restore changed text_offset");
        }
        if (!restored.AsSpan(Arm64FlagsOffset, 8).SequenceEqual(
                payload.AsSpan(Arm64FlagsOffset, 8)))
        {
            throw Reject(label, "restore changed Image flags");
        }
        ulong restoredSize = ReadUInt64(restored, Arm64ImageSizeOffset);
        if (restoredSize < (ulong)Arm64MinLen)
        {
            throw Reject(label, $"restored image_size {restoredSize} below {Arm64MinLen}");
        }
        if (restoredSize > (ulong)budget)
        {
            throw Reject(label, $"restored image_size {restoredSize} exceeds budget {budget}");
        }
        if (IsKshimIndication(restored))
        {
            throw Reject(label, "recovered base still carries kshim structures");
        }

        return restored;
    }

    private static bool IsBranchB(uint word) => (word & BranchMask) == BOpcode;

    private static long Imm26Target(uint word)
    {
        int imm = (int)(word & Imm26Mask);
        if ((imm & Sign26) != 0)
        {
            imm -= 0x04000000;
        }
        return (long)imm * 4;
    }

    // ---------------------------------------------------------------- gzip

    private static byte[] InflateGzip(byte[] data, long limit, CancellationToken token)
    {
        const string label = "kernel";
        if (data.Length < 18)
        {
            throw Reject(label, "gzip stream shorter than a header");
        }
        if (data[0] != GzipMagic[0] || data[1] != GzipMagic[1] || data[2] != 8)
        {
            throw Reject(label, "not a gzip/deflate stream");
        }
        int flags = data[3];
        if ((flags & 0xE0) != 0)
        {
            throw Reject(label, "reserved gzip flags are set");
        }

        int position = 10;
        if ((flags & 0x04) != 0)
        {
            if (position + 2 > data.Length)
            {
                throw Reject(label, "truncated gzip extra field");
            }
            int extraLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(position, 2));
            position += 2;
            if (position + extraLength > data.Length)
            {
                throw Reject(label, "truncated gzip extra field");
            }
            position += extraLength;
        }
        if ((flags & 0x08) != 0)
        {
            position = SkipZeroTerminated(data, position, label, "name");
        }
        if ((flags & 0x10) != 0)
        {
            position = SkipZeroTerminated(data, position, label, "comment");
        }
        if ((flags & 0x02) != 0)
        {
            if (position + 2 > data.Length)
            {
                throw Reject(label, "truncated gzip header CRC");
            }
            ushort stored = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(position, 2));
            ushort computed = (ushort)Crc32(data.AsSpan(0, position));
            if (stored != computed)
            {
                throw Reject(label, "gzip header CRC mismatch");
            }
            position += 2;
        }

        using var source = new OneByteReadStream(data, position);
        using var inflater = new DeflateStream(source, CompressionMode.Decompress, leaveOpen: true);
        using var output = new MemoryStream();
        byte[] buffer = new byte[64 * 1024];
        long outLength = 0;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int n = inflater.Read(buffer, 0, buffer.Length);
                if (n == 0)
                {
                    break;
                }
                if (outLength + n > limit)
                {
                    throw Reject(label, $"gzip output exceeds budget {limit}");
                }
                output.Write(buffer, 0, n);
                outLength += n;
            }
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidDataException($"{label}: invalid gzip stream", ex);
        }

        int remaining = data.Length - source.Consumed;
        if (remaining != 8)
        {
            if (remaining > 8 && data.AsSpan(source.Consumed, 2).SequenceEqual(GzipMagic))
            {
                throw Reject(label, "concatenated gzip members are not supported");
            }
            if (remaining > 8)
            {
                throw Reject(label, "trailing data after gzip member");
            }
            throw Reject(label, "truncated gzip stream or trailer");
        }

        byte[] result = output.ToArray();
        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(
            data.AsSpan(source.Consumed, 4));
        uint storedSize = BinaryPrimitives.ReadUInt32LittleEndian(
            data.AsSpan(source.Consumed + 4, 4));
        if (storedCrc != Crc32(result))
        {
            throw Reject(label, "gzip CRC mismatch");
        }
        if (storedSize != (uint)result.Length)
        {
            throw Reject(label, "gzip ISIZE mismatch");
        }
        return result;
    }

    private static int SkipZeroTerminated(byte[] data, int position, string label, string field)
    {
        while (position < data.Length && data[position] != 0)
        {
            position++;
        }
        if (position >= data.Length)
        {
            throw Reject(label, $"truncated gzip {field} field");
        }
        return position + 1;
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }

    /// <summary>In-memory reader that yields at most one byte per read.</summary>
    private sealed class OneByteReadStream : Stream
    {
        private readonly byte[] _data;
        private int _consumed;

        public OneByteReadStream(byte[] data, int offset)
        {
            _data = data;
            _consumed = offset;
        }

        public int Consumed => _consumed;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _data.Length;

        public override long Position
        {
            get => _consumed;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count <= 0 || _consumed >= _data.Length)
            {
                return 0;
            }
            buffer[offset] = _data[_consumed++];
            return 1;
        }

        public override int Read(Span<byte> buffer)
        {
            if (buffer.Length == 0 || _consumed >= _data.Length)
            {
                return 0;
            }
            buffer[0] = _data[_consumed++];
            return 1;
        }

        public override int ReadByte() =>
            _consumed < _data.Length ? _data[_consumed++] : -1;

        public override Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Read(buffer, offset, count));
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new ValueTask<int>(Read(buffer.Span));
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    // ------------------------------------------------------------- helpers

    private static long AlignUp(long value, int alignment)
    {
        long remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
    }

    private static uint ReadUInt32(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));

    private static ushort ReadUInt16(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));

    private static ulong ReadUInt64(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));

    private static string Sha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static InvalidDataException Reject(string role, string message) =>
        new InvalidDataException($"{role}: {message}");
}
