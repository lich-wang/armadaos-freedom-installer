// STOCK-01: read-only proof of the untouched original boot partition.
// The verifier owns both input leases for the whole call, re-derives the payload
// digest from the physical bytes, authenticates the boot leaf and the original
// root chain, and rejects the project kshim composite. It never writes, signs,
// generates, restores, recovers or claims OEM/hardware acceptance.
using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

// Facts observed from the original boot partition and its authenticated root
// chain. An instance exists only after the payload digest, the leaf signature
// and the root-to-leaf binding were all checked in one held pass, so validity is
// never a caller flag, init setter or OEM acceptance statement.
internal sealed class BootStockOriginalFacts
{
    internal BootStockOriginalFacts(
        VerifiedEdlFile boot,
        VerifiedEdlFile rootVbmeta,
        long imageSize,
        string bootPublicKeySha256,
        string rootPublicKeySha256,
        string digest,
        ulong rollbackIndex,
        uint rollbackIndexLocation)
    {
        Boot = boot;
        RootVbmeta = rootVbmeta;
        ImageSize = imageSize;
        BootPublicKeySha256 = bootPublicKeySha256;
        RootPublicKeySha256 = rootPublicKeySha256;
        Digest = digest;
        RollbackIndex = rollbackIndex;
        RollbackIndexLocation = rollbackIndexLocation;
    }

    public VerifiedEdlFile Boot { get; }

    public VerifiedEdlFile RootVbmeta { get; }

    public long ImageSize { get; }

    public string BootPublicKeySha256 { get; }

    public string RootPublicKeySha256 { get; }

    public string Digest { get; }

    public ulong RollbackIndex { get; }

    public uint RollbackIndexLocation { get; }

    // Derived facts of the checks this call already performed. Neither flag is a
    // device, rollback, OEM or hardware acceptance statement.
    public bool SignatureVerified => true;

    public bool PayloadDigestVerified => true;
}

public static partial class EdlRawBootBuilder
{
    private const long MaxOriginalKernelBytes = 268_435_456L;

    private const int OriginalKernelSizeField = 8;

    private const int StockManifestEntryBytes = 56;

    private const int StockManifestNameLimit = 255;

    private const int StockManifestRecordAlignment = 4;

    internal static Task<BootStockOriginalFacts> VerifyStockOriginalBootAsync(
        VerifiedEdlFile boot,
        VerifiedEdlFile rootVbmeta,
        CancellationToken ct = default)
    {
        if (boot is null)
        {
            throw new ArgumentNullException(nameof(boot));
        }

        if (rootVbmeta is null)
        {
            throw new ArgumentNullException(nameof(rootVbmeta));
        }

        // Precancel before any path is normalized, opened or scheduled so a
        // cancelled request never touches either input.
        ct.ThrowIfCancellationRequested();

        string bootPath = Path.GetFullPath(boot.Path);
        string rootPath = Path.GetFullPath(rootVbmeta.Path);

        ct.ThrowIfCancellationRequested();

        return Task.Run(
            () => VerifyStockOriginalBootCoreAsync(boot, rootVbmeta, bootPath, rootPath, ct),
            ct);
    }

    private static async Task<BootStockOriginalFacts> VerifyStockOriginalBootCoreAsync(
        VerifiedEdlFile boot,
        VerifiedEdlFile rootVbmeta,
        string bootPath,
        string rootPath,
        CancellationToken ct)
    {
        // Both inputs stay under this method's own read leases until the facts
        // are returned, including across the root chain await below.
        using FileStream bootStream = OpenStockOriginalLease(bootPath);
        using FileStream rootStream = OpenStockOriginalLease(rootPath);

        VerifyClaim(bootStream, boot, "original stock boot", ct);
        VerifyClaim(rootStream, rootVbmeta, "original stock root vbmeta", ct);

        long partitionBytes = bootStream.Length;
        SourceMetadata source = ReadSourceMetadata(bootStream, partitionBytes, ct);
        AvbNodeMetadata leaf = AvbNodeReadFooterLeafMetadata(bootStream, partitionBytes, ct);

        ct.ThrowIfCancellationRequested();

        long imageSize = source.Vbmeta.Hash.ImageSize;
        string storedDigest = ToHex(source.Vbmeta.Hash.Digest);

        // Re-derive the salted digest from the physical original boot prefix,
        // Android header and padding included. A refreshed outer whole-file hash
        // never repairs a stale signed digest.
        string physicalDigest = ComputeSaltedDigest(
            bootStream,
            source.Vbmeta.Hash.Salt,
            imageSize,
            HashNameFor(source.Vbmeta.Hash.Algorithm),
            ct);

        if (!string.Equals(physicalDigest, storedDigest, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "original stock boot payload digest does not match its own signed hash descriptor");
        }

        ct.ThrowIfCancellationRequested();

        // The real original root chain is authenticated while both leases are
        // still held. Only a chain that actually verifies produces facts.
        EdlRawOriginalBootChainFacts chain =
            await AuthenticateOriginalBootChainAsync(rootVbmeta, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();

        string leafKeySha256 = leaf.SourcePublicKeySha256;
        string rootKeySha256 = chain.PublicKeySha256;
        string bootChainKeySha256 = chain.BootChainPublicKeySha256;

        if (leafKeySha256.Length == 0 || rootKeySha256.Length == 0 || bootChainKeySha256.Length == 0)
        {
            throw new InvalidDataException(
                "original stock root vbmeta does not expose a complete boot chain principal");
        }

        // The root owns the boot child key. A parent principal that differs from
        // the child is expected; only the declared boot binding must match.
        if (!string.Equals(bootChainKeySha256, leafKeySha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "original stock boot leaf key is not bound by the authenticated root boot chain");
        }

        long kernelBytes = ReadLeU32(source.Header, OriginalKernelSizeField);

        if (kernelBytes <= 0 ||
            kernelBytes > MaxOriginalKernelBytes ||
            kernelBytes > partitionBytes - BootHeaderBytes)
        {
            throw new InvalidDataException(
                "original stock kernel length is outside the Android boot image");
        }

        byte[] kernel = new byte[(int)kernelBytes];
        ReadExactly(bootStream, kernel, BootHeaderBytes, kernel.Length);

        byte[] raw = IsOriginalGzipKernel(kernel) ? InflateOriginalKernel(kernel, ct) : kernel;
        RequireOriginalStockKernel(raw);

        // Hold the inputs to the same claims they had when proof began.
        VerifyClaim(bootStream, boot, "original stock boot", ct);
        VerifyClaim(rootStream, rootVbmeta, "original stock root vbmeta", ct);
        ct.ThrowIfCancellationRequested();

        return new BootStockOriginalFacts(
            boot,
            rootVbmeta,
            imageSize,
            leafKeySha256,
            rootKeySha256,
            storedDigest,
            source.Vbmeta.RollbackIndex,
            source.Vbmeta.RollbackIndexLocation);
    }

    private static FileStream OpenStockOriginalLease(string path)
    {
        return new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyChunkBytes,
            FileOptions.SequentialScan);
    }

    private static bool IsOriginalGzipKernel(byte[] kernel)
    {
        return kernel.Length >= 2 && kernel[0] == 0x1F && kernel[1] == 0x8B;
    }

    // Bounded gzip decode only: the inflated kernel never exceeds the hard limit
    // and the token is honoured between chunks.
    private static byte[] InflateOriginalKernel(byte[] kernel, CancellationToken ct)
    {
        using var compressed = new MemoryStream(kernel, writable: false);
        using var inflater = new GZipStream(compressed, CompressionMode.Decompress);
        using var inflated = new MemoryStream();

        byte[] buffer = new byte[CopyChunkBytes];
        long total = 0;

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int read = inflater.Read(buffer, 0, buffer.Length);

            if (read <= 0)
            {
                break;
            }

            total += read;

            if (total > MaxOriginalKernelBytes)
            {
                throw new InvalidDataException(
                    "original stock gzip kernel exceeds the bounded decode limit");
            }

            inflated.Write(buffer, 0, read);
        }

        if (total == 0)
        {
            throw new InvalidDataException("original stock gzip kernel decoded to no bytes");
        }

        return inflated.ToArray();
    }

    // Accepts only a plain ARM64 original image, or recognises the signed project
    // kshim composite and rejects it as project material. KPMF bytes inside an
    // arbitrary plain kernel are never substring-scanned.
    private static void RequireOriginalStockKernel(byte[] raw)
    {
        if (raw.Length < Arm64HeaderProbeBytes)
        {
            throw new InvalidDataException(
                "original stock kernel is smaller than the ARM64 header");
        }

        if (!raw.AsSpan(Arm64MagicField, 4).SequenceEqual(Arm64ImageMagic))
        {
            throw new InvalidDataException(
                "original stock kernel does not carry the ARM64 image magic");
        }

        ulong imageSize = ReadLeU64(raw, Arm64ImageSizeField);
        ulong manifestOffset = ReadLeU64(raw, Arm64ManifestOffsetField);
        ulong manifestSize = ReadLeU64(raw, Arm64ManifestSizeField);
        ulong shimOffset = ReadLeU64(raw, Arm64ShimOffsetField);

        if (manifestOffset != 0 || manifestSize != 0 || shimOffset != 0)
        {
            if (IsProjectCompositeKernel(raw, imageSize, manifestOffset, manifestSize, shimOffset))
            {
                throw new InvalidDataException(
                    "original stock kernel is the project kshim composite");
            }

            throw new InvalidDataException(
                "original stock kernel carries an unsupported composite header");
        }

        // image_size may legitimately exceed the physical kernel length because it
        // includes BSS. With no observed ABL/XBL loader budget here, only basic
        // ARM64 legality is checked, never a fabricated BSS or hardware bound.
        if (imageSize < (ulong)Arm64HeaderProbeBytes)
        {
            throw new InvalidDataException(
                "original stock kernel image_size is below the ARM64 header");
        }
    }

    private static bool IsProjectCompositeKernel(
        byte[] raw,
        ulong imageSize,
        ulong manifestOffset,
        ulong manifestSize,
        ulong shimOffset)
    {
        if (imageSize != (ulong)raw.Length)
        {
            return false;
        }

        if (manifestOffset < (ulong)Arm64HeaderProbeBytes ||
            manifestSize < (ulong)ManifestHeaderBytes ||
            manifestOffset > (ulong)raw.Length ||
            manifestSize > (ulong)raw.Length - manifestOffset ||
            manifestOffset + manifestSize != (ulong)raw.Length)
        {
            return false;
        }

        if (shimOffset == 0 ||
            shimOffset % 4 != 0 ||
            shimOffset > (ulong)raw.Length ||
            shimOffset >= (ulong)BranchSignedRange)
        {
            return false;
        }

        uint firstInstruction = ReadLeU32(raw, 0);

        if ((firstInstruction & BranchOpcodeMask) != BranchLinkOpcode)
        {
            return false;
        }

        if (ResolveBranchTarget(firstInstruction) != (long)shimOffset)
        {
            return false;
        }

        int start = (int)manifestOffset;
        int end = raw.Length;

        if (start < 0 || start + ManifestHeaderBytes > end)
        {
            return false;
        }

        if (ReadLeU32(raw, start) != ManifestMagic)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(start + 4, 2)) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(start + 6, 2)) != 1)
        {
            return false;
        }

        if (ReadLeU32(raw, start + 8) != ManifestEntryCount)
        {
            return false;
        }

        if (ReadLeU32(raw, start + 12) >= ManifestEntryCount)
        {
            return false;
        }

        if (ReadLeU32(raw, start + 16) != ManifestTimeoutMillis)
        {
            return false;
        }

        int cursor = start + ManifestHeaderBytes;

        for (uint index = 0; index < ManifestEntryCount; index++)
        {
            if (cursor < start || cursor > end - StockManifestEntryBytes)
            {
                return false;
            }

            uint nameLength = ReadLeU32(raw, cursor + 52);

            if (nameLength > StockManifestNameLimit)
            {
                return false;
            }

            long unpadded = StockManifestEntryBytes + (long)nameLength;
            long recordBytes = (unpadded + StockManifestRecordAlignment - 1) &
                               ~(long)(StockManifestRecordAlignment - 1);
            long recordEnd = cursor + recordBytes;

            if (recordEnd > end)
            {
                return false;
            }

            cursor = (int)recordEnd;
        }

        return cursor == end;
    }
}
