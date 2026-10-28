// BE001: bounded Android v4 boot repack envelope with a per-slot fixed AOSP AVB
// SHA256_RSA4096 test signature in the vbmeta footer. Parses only the metadata
// contract needed to rebuild the candidate partition and verifies the result by
// re-reading the physical bytes it just wrote.
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

public sealed class EdlRawAvbProperty
{
    internal EdlRawAvbProperty(string key, string value)
    {
        Key = key;
        Value = value;
    }

    public string Key { get; }

    public string Value { get; }
}

public sealed class EdlRawBootEnvelope
{
    internal EdlRawBootEnvelope(
        VerifiedEdlFile candidateBoot,
        long compressedKernelBytes,
        string compressedKernelSha256,
        long originalImageSize,
        long vbmetaOffset,
        long vbmetaBytes,
        string hashAlgorithm,
        string saltHex,
        uint hashDescriptorFlags,
        ulong rollbackIndex,
        uint rollbackIndexLocation,
        IReadOnlyList<EdlRawAvbProperty> properties,
        string digestHex,
        string sourceEmbeddedVbmetaSha256)
    {
        CandidateBoot = candidateBoot;
        CompressedKernelBytes = compressedKernelBytes;
        CompressedKernelSha256 = compressedKernelSha256;
        OriginalImageSize = originalImageSize;
        VbmetaOffset = vbmetaOffset;
        VbmetaBytes = vbmetaBytes;
        HashAlgorithm = hashAlgorithm;
        SaltHex = saltHex;
        HashDescriptorFlags = hashDescriptorFlags;
        RollbackIndex = rollbackIndex;
        RollbackIndexLocation = rollbackIndexLocation;
        Properties = new ReadOnlyCollection<EdlRawAvbProperty>(new List<EdlRawAvbProperty>(properties));
        DigestHex = digestHex;
        SourceEmbeddedVbmetaSha256 = sourceEmbeddedVbmetaSha256;
    }

    public VerifiedEdlFile CandidateBoot { get; }

    public long CompressedKernelBytes { get; }

    public string CompressedKernelSha256 { get; }

    public long OriginalImageSize { get; }

    public long VbmetaOffset { get; }

    public long VbmetaBytes { get; }

    public string HashAlgorithm { get; }

    public string SaltHex { get; }

    public uint HashDescriptorFlags { get; }

    public ulong RollbackIndex { get; }

    public uint RollbackIndexLocation { get; }

    public IReadOnlyList<EdlRawAvbProperty> Properties { get; }

    public string DigestHex { get; }

    public string SourceEmbeddedVbmetaSha256 { get; }

    // The candidate vbmeta always uses the fixed AOSP AVB SHA256_RSA4096 test
    // signature. OemSigned stays false: this is not an OEM key and no hardware
    // trust or rollback acceptance is claimed. SignatureVerificationPerformed is
    // true only because an envelope is constructed after the physical candidate
    // signature has been re-verified.
    public int AlgorithmType => 2;

    public bool OemSigned => false;

    public bool SignatureVerificationPerformed => true;

    public bool HardwareRollbackVerified => false;
}

public static partial class EdlRawBootBuilder
{
    private const int PageSize = 4096;
    private const int BootHeaderBytes = 4096;
    private const int HeaderSizeField = 1584;
    private const int AvbFooterBytes = 64;
    private const int VbmetaHeaderBytes = 256;
    private const long VbmetaReserveBytes = 65536L;
    private const long FooterReserveBytes = 4096L;
    private const long MetadataReserveBytes = VbmetaReserveBytes + FooterReserveBytes;
    private const long MaxVbmetaBytes = 1L << 20;
    private const int GzipChunkBytes = 1 << 16;
    private const int CopyChunkBytes = 81920;

    private static readonly byte[] AndroidMagic = { 0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x21 };
    private static readonly byte[] AvbFooterMagic = { 0x41, 0x56, 0x42, 0x66 };
    private static readonly byte[] AvbVbmetaMagic = { 0x41, 0x56, 0x42, 0x30 };
    private static readonly byte[] Arm64ImageMagic = { 0x41, 0x52, 0x4D, 0x64 };
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private const string ReleaseString = "freedom-edl-direct";

    internal static Task<EdlRawBootEnvelope> RepackEnvelopeAsync(
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile packedRaw,
        long maxRawBytes,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        if (sourceBoot is null)
        {
            throw new ArgumentNullException(nameof(sourceBoot));
        }

        if (packedRaw is null)
        {
            throw new ArgumentNullException(nameof(packedRaw));
        }

        if (outputPath is null)
        {
            throw new ArgumentNullException(nameof(outputPath));
        }

        if (maxRawBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRawBytes));
        }

        if (outputPath.Length == 0)
        {
            throw new ArgumentException("output path is empty", nameof(outputPath));
        }

        string sourcePath = Path.GetFullPath(sourceBoot.Path);
        string rawPath = Path.GetFullPath(packedRaw.Path);
        string targetPath = Path.GetFullPath(outputPath);

        return Task.Run(
            () => RepackEnvelopeCore(sourceBoot, packedRaw, sourcePath, rawPath, maxRawBytes, targetPath, cancellationToken),
            cancellationToken);
    }

    private static EdlRawBootEnvelope RepackEnvelopeCore(
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile packedRaw,
        string sourcePath,
        string rawPath,
        long maxRawBytes,
        string targetPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? tempPath = null;
        bool targetCreated = false;
        bool success = false;
        try
        {
            using FileStream source = new(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, GzipChunkBytes, FileOptions.SequentialScan);
            using FileStream raw = new(rawPath, FileMode.Open, FileAccess.Read, FileShare.Read, GzipChunkBytes, FileOptions.SequentialScan);

            VerifyClaim(source, sourceBoot, "source boot", cancellationToken);
            VerifyClaim(raw, packedRaw, "packed raw", cancellationToken);

            long partitionSize = source.Length;
            SourceMetadata metadata = ReadSourceMetadata(source, partitionSize, cancellationToken);

            long rawLength = raw.Length;
            ValidatePackedRaw(raw, rawLength, maxRawBytes);

            cancellationToken.ThrowIfCancellationRequested();

            string outputDirectory = Path.GetDirectoryName(targetPath)
                ?? throw new InvalidDataException("output path has no directory component");
            tempPath = Path.Combine(
                outputDirectory,
                "." + Path.GetFileName(targetPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");

            long compressedLength;
            string compressedSha256;
            using (FileStream temp = new(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, GzipChunkBytes, FileOptions.SequentialScan))
            {
                raw.Position = 0;
                using (GZipStream compressor = new(temp, CompressionLevel.Optimal, leaveOpen: true))
                {
                    CopyTo(raw, compressor, null, cancellationToken);
                }

                temp.Flush(true);
                compressedLength = temp.Length;
            }

            if (compressedLength <= 0 || compressedLength > uint.MaxValue)
            {
                throw new InvalidDataException("compressed kernel length is not representable in the v4 header");
            }

            compressedSha256 = HashFileSha256(tempPath, cancellationToken);

            long originalImageSize = checked(BootHeaderBytes + Align(compressedLength, PageSize));
            if (partitionSize <= MetadataReserveBytes || originalImageSize > partitionSize - MetadataReserveBytes)
            {
                throw new InvalidDataException(
                    "repacked image exceeds the avbtool metadata and footer reserve for the partition");
            }

            byte[] newHeader = (byte[])metadata.Header.Clone();
            WriteLeU32(newHeader, 8, (uint)compressedLength);

            HashAlgorithmName hashName = HashNameFor(metadata.Vbmeta.Hash.Algorithm);
            byte[] newDigest;
            using (FileStream output = new(targetPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, GzipChunkBytes, FileOptions.SequentialScan))
            {
                targetCreated = true;
                using (IncrementalHash contentHash = IncrementalHash.CreateHash(hashName))
                {
                    contentHash.AppendData(metadata.Vbmeta.Hash.Salt);
                    output.Write(newHeader, 0, newHeader.Length);
                    contentHash.AppendData(newHeader);

                    using (FileStream compressed = new(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read, GzipChunkBytes, FileOptions.SequentialScan))
                    {
                        CopyTo(compressed, output, contentHash, cancellationToken);
                    }

                    WriteZeros(output, originalImageSize - BootHeaderBytes - compressedLength, contentHash, cancellationToken);
                    newDigest = contentHash.GetHashAndReset();
                }

                byte[] hashDescriptor = BuildHashDescriptor(
                    originalImageSize,
                    metadata.Vbmeta.Hash.Algorithm,
                    metadata.Vbmeta.Hash.Salt,
                    newDigest,
                    metadata.Vbmeta.Hash.Flags);
                long descriptorsLength = hashDescriptor.Length;
                foreach (byte[] blob in metadata.Vbmeta.PropertyBlobs)
                {
                    descriptorsLength = checked(descriptorsLength + blob.Length);
                }

                uint minimumMinor = (uint)Math.Max(
                    metadata.Vbmeta.Hash.Flags == 1 ? 1 : 0,
                    metadata.Vbmeta.RollbackIndexLocation > 0 ? 2 : 0);
                uint sourceMinor = ReadBeU32(metadata.Vbmeta.Header, 8);
                uint minorVersion = Math.Max(minimumMinor, sourceMinor);
                byte[] vbmeta = BuildVbmeta(
                    hashDescriptor,
                    metadata.Vbmeta.PropertyBlobs,
                    metadata.Vbmeta.RollbackIndex,
                    metadata.Vbmeta.RollbackIndexLocation,
                    minorVersion,
                    out long auxSize);

                if (vbmeta.Length > VbmetaReserveBytes)
                {
                    throw new InvalidOperationException("AVB metadata exceeds the 64 KiB avbtool reserve");
                }

                output.Write(vbmeta, 0, vbmeta.Length);
                long trailing = partitionSize - AvbFooterBytes - originalImageSize - vbmeta.Length;
                if (trailing < 0)
                {
                    throw new InvalidOperationException("AVB metadata does not fit before the footer");
                }

                WriteZeros(output, trailing, null, cancellationToken);
                byte[] footer = BuildFooter(originalImageSize, originalImageSize, vbmeta.Length);
                output.Write(footer, 0, footer.Length);

                if (output.Position != partitionSize)
                {
                    throw new InvalidOperationException("candidate boot length does not match the partition length");
                }

                output.Flush(true);
                output.Dispose();

                using FileStream check = new(targetPath, FileMode.Open, FileAccess.Read, FileShare.Read, GzipChunkBytes, FileOptions.SequentialScan);
                if (check.Length != partitionSize)
                {
                    throw new InvalidOperationException("candidate boot length changed on disk");
                }

                string candidateSha256 = HashStreamSha256(check, cancellationToken);

                byte[] writtenHeader = new byte[BootHeaderBytes];
                ReadExactly(check, writtenHeader, 0, writtenHeader.Length);
                for (int i = 0; i < BootHeaderBytes; i++)
                {
                    if (i < 8 || i >= 12)
                    {
                        if (writtenHeader[i] != metadata.Header[i])
                        {
                            throw new InvalidOperationException("candidate header differs from the source outside kernel_size");
                        }
                    }
                }

                if (ReadLeU32(writtenHeader, 8) != compressedLength)
                {
                    throw new InvalidOperationException("candidate header kernel_size mismatch");
                }

                string writtenGzipSha256 = HashRangeSha256(check, BootHeaderBytes, compressedLength, cancellationToken);
                if (!string.Equals(writtenGzipSha256, compressedSha256, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("candidate gzip bytes do not match the just-compressed kernel");
                }

                VerifyDecompressedKernel(check, compressedLength, rawLength, packedRaw.Sha256, cancellationToken);

                AssertZeros(check, BootHeaderBytes + compressedLength, originalImageSize - BootHeaderBytes - compressedLength, cancellationToken);
                AssertZeros(check, originalImageSize + vbmeta.Length, trailing, cancellationToken);
                AssertZeros(
                    check,
                    originalImageSize + VbmetaHeaderBytes + AvbAuthBlockBytes + descriptorsLength + AvbPublicKeyBytes,
                    auxSize - descriptorsLength - AvbPublicKeyBytes,
                    cancellationToken);

                byte[] writtenFooter = new byte[AvbFooterBytes];
                ReadExactly(check, writtenFooter, partitionSize - AvbFooterBytes, AvbFooterBytes);
                if (!writtenFooter.AsSpan(0, 4).SequenceEqual(AvbFooterMagic)
                    || ReadBeU32(writtenFooter, 4) != 1
                    || ReadBeU32(writtenFooter, 8) != 0
                    || ReadBeU64(writtenFooter, 12) != (ulong)originalImageSize
                    || ReadBeU64(writtenFooter, 20) != (ulong)originalImageSize
                    || ReadBeU64(writtenFooter, 28) != (ulong)vbmeta.Length)
                {
                    throw new InvalidOperationException("candidate AVB footer mismatch");
                }

                AssertZeros(check, partitionSize - AvbFooterBytes + 36, 28, cancellationToken);

                ParsedVbmeta parsed = ParseVbmeta(check, originalImageSize, vbmeta.Length, originalImageSize, cancellationToken);
                string physicalDigest = ComputeSaltedDigest(
                    check,
                    parsed.Hash.Salt,
                    originalImageSize,
                    HashNameFor(parsed.Hash.Algorithm),
                    cancellationToken);

                // Verify the signature over the bytes actually written to the final
                // candidate file, not over the in-memory build buffer.
                byte[] physicalVbmeta = new byte[checked((int)parsed.Total)];
                ReadExactly(check, physicalVbmeta, originalImageSize, physicalVbmeta.Length);
                VerifyCandidateVbmetaSignature(physicalVbmeta);

                AssertCandidateVbmeta(
                    parsed,
                    auxSize,
                    descriptorsLength,
                    metadata,
                    originalImageSize,
                    newDigest,
                    physicalDigest,
                    minorVersion);

                success = true;
                return new EdlRawBootEnvelope(
                    new VerifiedEdlFile(targetPath, partitionSize, candidateSha256),
                    compressedLength,
                    compressedSha256,
                    originalImageSize,
                    originalImageSize,
                    vbmeta.Length,
                    parsed.Hash.Algorithm,
                    ToHex(parsed.Hash.Salt),
                    parsed.Hash.Flags,
                    parsed.RollbackIndex,
                    parsed.RollbackIndexLocation,
                    parsed.Properties,
                    ToHex(parsed.Hash.Digest),
                    metadata.VbmetaSha256);
            }
        }
        finally
        {
            if (targetCreated && !success)
            {
                try
                {
                    File.Delete(targetPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            if (tempPath is not null)
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
    }

    private static void VerifyClaim(FileStream stream, VerifiedEdlFile claim, string what, CancellationToken cancellationToken)
    {
        if (stream.Length != claim.Length)
        {
            throw new InvalidDataException(what + " length claim does not match the opened file");
        }

        string actual = HashStreamSha256(stream, cancellationToken);
        if (!string.Equals(actual, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(what + " sha256 claim does not match the opened file");
        }
    }

    private static SourceMetadata ReadSourceMetadata(FileStream source, long partitionSize, CancellationToken cancellationToken)
    {
        if (partitionSize < BootHeaderBytes || partitionSize % PageSize != 0)
        {
            throw new InvalidDataException("source boot length must be a positive multiple of 4096 bytes");
        }

        byte[] header = new byte[BootHeaderBytes];
        ReadExactly(source, header, 0, header.Length);

        if (!header.AsSpan(0, 8).SequenceEqual(AndroidMagic))
        {
            throw new InvalidDataException("source boot magic is not ANDROID!");
        }

        uint oldKernelSize = ReadLeU32(header, 8);
        if (oldKernelSize == 0)
        {
            throw new InvalidDataException("source boot kernel_size is zero");
        }

        if (ReadLeU32(header, 12) != 0)
        {
            throw new InvalidDataException("source boot ramdisk_size is nonzero");
        }

        if (ReadLeU32(header, 20) != HeaderSizeField)
        {
            throw new InvalidDataException("source boot header_size is not 1584");
        }

        if (ReadLeU32(header, 40) != 4)
        {
            throw new InvalidDataException("source boot header version is not 4");
        }

        if (ReadLeU32(header, 1580) != 0)
        {
            throw new InvalidDataException("source boot signature_size is nonzero");
        }

        if ((ulong)oldKernelSize > (ulong)partitionSize - (ulong)BootHeaderBytes)
        {
            throw new InvalidDataException("source boot kernel exceeds the partition bounds");
        }

        byte[] footer = new byte[AvbFooterBytes];
        ReadExactly(source, footer, partitionSize - AvbFooterBytes, AvbFooterBytes);

        if (!footer.AsSpan(0, 4).SequenceEqual(AvbFooterMagic))
        {
            throw new InvalidDataException("source boot AVB footer magic missing");
        }

        if (ReadBeU32(footer, 4) != 1)
        {
            throw new InvalidDataException("source boot AVB footer major version is not 1");
        }

        ulong originalImageSize = ReadBeU64(footer, 12);
        ulong vbmetaOffset = ReadBeU64(footer, 20);
        ulong vbmetaSize = ReadBeU64(footer, 28);

        ulong minimumOriginal = (ulong)BootHeaderBytes + Align4096((ulong)oldKernelSize);
        if (originalImageSize < minimumOriginal)
        {
            throw new InvalidDataException("source boot original_image_size is below the kernel-aligned minimum");
        }

        if (vbmetaOffset < originalImageSize)
        {
            throw new InvalidDataException("source boot vbmeta_offset is below original_image_size");
        }

        if (vbmetaSize == 0)
        {
            throw new InvalidDataException("source boot vbmeta_size is zero");
        }

        ulong footerLimit = (ulong)partitionSize - (ulong)AvbFooterBytes;
        if (vbmetaOffset > footerLimit || vbmetaSize > footerLimit - vbmetaOffset)
        {
            throw new InvalidDataException("source boot vbmeta range exceeds the footer start");
        }

        ParsedVbmeta vbmeta = ParseVbmeta(
            source,
            (long)vbmetaOffset,
            (long)vbmetaSize,
            (long)originalImageSize,
            cancellationToken);

        return new SourceMetadata
        {
            Header = header,
            Vbmeta = vbmeta,
            VbmetaSha256 = vbmeta.BlobSha256,
        };
    }

    private static void ValidatePackedRaw(FileStream raw, long rawLength, long maxRawBytes)
    {
        if (rawLength < 64)
        {
            throw new InvalidDataException("packed raw image is smaller than 64 bytes");
        }

        if (rawLength > maxRawBytes)
        {
            throw new InvalidDataException("packed raw image exceeds the allowed maximum");
        }

        byte[] head = new byte[64];
        ReadExactly(raw, head, 0, head.Length);

        if (!head.AsSpan(56, 4).SequenceEqual(Arm64ImageMagic))
        {
            throw new InvalidDataException("packed raw image is missing the ARM64 magic at offset 56");
        }

        if (ReadLeU64(head, 16) != (ulong)rawLength)
        {
            throw new InvalidDataException("packed raw image_size does not match its length");
        }
    }

    private static ParsedVbmeta ParseVbmeta(
        Stream stream,
        long vbmetaOffset,
        long declaredSize,
        long expectedOriginalImageSize,
        CancellationToken cancellationToken)
    {
        if (declaredSize < VbmetaHeaderBytes || declaredSize > MaxVbmetaBytes)
        {
            throw new InvalidDataException("vbmeta size is outside the bounded parser range");
        }

        byte[] header = new byte[VbmetaHeaderBytes];
        ReadExactly(stream, header, vbmetaOffset, header.Length);

        if (!header.AsSpan(0, 4).SequenceEqual(AvbVbmetaMagic))
        {
            throw new InvalidDataException("vbmeta magic is not AVB0");
        }

        ulong authSize = ReadBeU64(header, 12);
        ulong auxSize = ReadBeU64(header, 20);
        if (authSize > (ulong)declaredSize || auxSize > (ulong)declaredSize)
        {
            throw new InvalidDataException("vbmeta block size exceeds the declared vbmeta size");
        }

        ulong total = 256UL + authSize + auxSize;
        if (total > (ulong)declaredSize)
        {
            throw new InvalidDataException("vbmeta header and blocks exceed the declared size");
        }

        if (ReadBeU32(header, 120) != 0)
        {
            throw new InvalidDataException("source vbmeta flags are nonzero");
        }

        RequireSubrange(ReadBeU64(header, 32), ReadBeU64(header, 40), authSize, "vbmeta hash");
        RequireSubrange(ReadBeU64(header, 48), ReadBeU64(header, 56), authSize, "vbmeta signature");
        RequireSubrange(ReadBeU64(header, 64), ReadBeU64(header, 72), auxSize, "vbmeta public key");
        RequireSubrange(ReadBeU64(header, 80), ReadBeU64(header, 88), auxSize, "vbmeta public key metadata");

        ulong descriptorsOffset = ReadBeU64(header, 96);
        ulong descriptorsSize = ReadBeU64(header, 104);
        if (descriptorsOffset > auxSize || descriptorsSize > auxSize - descriptorsOffset)
        {
            throw new InvalidDataException("vbmeta descriptors range is outside the auxiliary block");
        }

        long regionPosition = checked(vbmetaOffset + VbmetaHeaderBytes + (long)authSize + (long)descriptorsOffset);
        byte[] region = new byte[checked((int)descriptorsSize)];
        ReadExactly(stream, region, regionPosition, region.Length);

        ParseDescriptors(region, expectedOriginalImageSize, out HashDescriptorFacts hash, out List<EdlRawAvbProperty> properties, out List<byte[]> propertyBlobs);

        string blobSha256 = HashRangeSha256(stream, vbmetaOffset, (long)total, cancellationToken);

        return new ParsedVbmeta
        {
            Header = header,
            AuxSize = (long)auxSize,
            DescriptorBytes = (long)descriptorsSize,
            Total = (long)total,
            RollbackIndex = ReadBeU64(header, 112),
            RollbackIndexLocation = ReadBeU32(header, 124),
            Hash = hash,
            Properties = properties,
            PropertyBlobs = propertyBlobs,
            BlobSha256 = blobSha256,
        };
    }

    private static void RequireSubrange(ulong offset, ulong size, ulong blockSize, string what)
    {
        if (offset > blockSize || size > blockSize - offset)
        {
            throw new InvalidDataException(what + " range is outside its block");
        }
    }

    private static void ParseDescriptors(
        byte[] region,
        long expectedOriginalImageSize,
        out HashDescriptorFacts hash,
        out List<EdlRawAvbProperty> properties,
        out List<byte[]> propertyBlobs)
    {
        hash = null!;
        bool seenHash = false;
        properties = new List<EdlRawAvbProperty>();
        propertyBlobs = new List<byte[]>();

        int offset = 0;
        while (offset < region.Length)
        {
            if (region.Length - offset < 16)
            {
                throw new InvalidDataException("AVB descriptor header is truncated");
            }

            ulong tag = ReadBeU64(region, offset);
            ulong following = ReadBeU64(region, offset + 8);
            if (following > int.MaxValue)
            {
                throw new InvalidDataException("AVB descriptor body is too large");
            }

            long descriptorLength = 16L + (long)following;
            if (descriptorLength > region.Length - offset)
            {
                throw new InvalidDataException("AVB descriptor exceeds the descriptor region");
            }

            if ((descriptorLength & 7) != 0)
            {
                throw new InvalidDataException("AVB descriptor length is not a multiple of 8");
            }

            if (tag == 2)
            {
                if (seenHash)
                {
                    throw new InvalidDataException("duplicate AVB hash descriptor");
                }

                hash = ParseHashDescriptor(region, offset, (int)descriptorLength, expectedOriginalImageSize);
                seenHash = true;
            }
            else if (tag == 0)
            {
                ParsePropertyDescriptor(region, offset, (int)descriptorLength, properties, propertyBlobs);
            }
            else
            {
                throw new InvalidDataException("unsupported AVB descriptor tag " + tag.ToString());
            }

            offset += (int)descriptorLength;
        }

        if (!seenHash)
        {
            throw new InvalidDataException("source vbmeta is missing the AVB hash descriptor");
        }
    }

    private static HashDescriptorFacts ParseHashDescriptor(byte[] region, int offset, int total, long expectedOriginalImageSize)
    {
        if (total < 136 || region.Length - offset < total)
        {
            throw new InvalidDataException("AVB hash descriptor is too small");
        }

        ulong imageSize = ReadBeU64(region, offset + 16);
        if (imageSize != (ulong)expectedOriginalImageSize)
        {
            throw new InvalidDataException("AVB hash descriptor image_size does not match original_image_size");
        }

        for (int i = 72; i < 132; i++)
        {
            if (region[offset + i] != 0)
            {
                throw new InvalidDataException("AVB hash descriptor reserved bytes are nonzero");
            }
        }

        int algorithmLength = 0;
        while (algorithmLength < 32 && region[offset + 24 + algorithmLength] != 0)
        {
            algorithmLength++;
        }

        for (int i = offset + 24 + algorithmLength; i < offset + 56; i++)
        {
            if (region[i] != 0)
            {
                throw new InvalidDataException("AVB hash algorithm field has nonzero padding");
            }
        }

        string algorithm = Encoding.ASCII.GetString(region, offset + 24, algorithmLength);
        if (algorithm != "sha256" && algorithm != "sha512")
        {
            throw new InvalidDataException("unsupported AVB hash algorithm '" + algorithm + "'");
        }

        int expectedDigestLength = algorithm == "sha256" ? 32 : 64;
        uint nameLength = ReadBeU32(region, offset + 56);
        uint saltLength = ReadBeU32(region, offset + 60);
        uint digestLength = ReadBeU32(region, offset + 64);
        uint flags = ReadBeU32(region, offset + 68);

        if (flags != 0 && flags != 1)
        {
            throw new InvalidDataException("unsupported AVB hash descriptor flags");
        }

        if (nameLength != 4)
        {
            throw new InvalidDataException("AVB hash descriptor partition_name_len is not 4");
        }

        if (digestLength != (uint)expectedDigestLength)
        {
            throw new InvalidDataException("AVB digest length does not match the hash algorithm");
        }

        int nameStart = offset + 132;
        int descriptorEnd = offset + total;
        if (region[nameStart] != (byte)'b'
            || region[nameStart + 1] != (byte)'o'
            || region[nameStart + 2] != (byte)'o'
            || region[nameStart + 3] != (byte)'t')
        {
            throw new InvalidDataException("AVB hash descriptor name is not 'boot'");
        }

        long saltStart = (long)nameStart + 4;
        long digestStart = saltStart + saltLength;
        long exactEnd = digestStart + digestLength;
        if (exactEnd > descriptorEnd)
        {
            throw new InvalidDataException("AVB hash descriptor fields exceed the descriptor length");
        }

        long padded = Align(exactEnd - offset, 8);
        if (padded != total)
        {
            throw new InvalidDataException("AVB hash descriptor length padding is inconsistent");
        }

        for (long i = exactEnd; i < descriptorEnd; i++)
        {
            if (region[i] != 0)
            {
                throw new InvalidDataException("AVB hash descriptor trailing padding is nonzero");
            }
        }

        byte[] salt = new byte[saltLength];
        if (saltLength > 0)
        {
            Buffer.BlockCopy(region, (int)saltStart, salt, 0, salt.Length);
        }

        byte[] digest = new byte[digestLength];
        Buffer.BlockCopy(region, (int)digestStart, digest, 0, digest.Length);

        return new HashDescriptorFacts
        {
            ImageSize = (long)imageSize,
            Algorithm = algorithm,
            Salt = salt,
            Digest = digest,
            Flags = flags,
        };
    }

    private static void ParsePropertyDescriptor(
        byte[] region,
        int offset,
        int total,
        List<EdlRawAvbProperty> properties,
        List<byte[]> propertyBlobs)
    {
        if (total < 32)
        {
            throw new InvalidDataException("AVB property descriptor is too small");
        }

        ulong keyLength = ReadBeU64(region, offset + 16);
        ulong valueLength = ReadBeU64(region, offset + 24);
        if (keyLength > int.MaxValue || valueLength > int.MaxValue)
        {
            throw new InvalidDataException("AVB property length is too large");
        }

        long exactLength = 32L + (long)keyLength + 1L + (long)valueLength + 1L;
        if (exactLength > total)
        {
            throw new InvalidDataException("AVB property fields exceed the descriptor length");
        }

        if (Align(exactLength, 8) != total)
        {
            throw new InvalidDataException("AVB property descriptor length padding is inconsistent");
        }

        int keyStart = offset + 32;
        int keyTerminator = keyStart + (int)keyLength;
        int valueStart = keyTerminator + 1;
        int valueEnd = valueStart + (int)valueLength;
        int exactEnd = valueEnd + 1;
        int descriptorEnd = offset + total;

        if (region[keyTerminator] != 0 || region[valueEnd] != 0)
        {
            throw new InvalidDataException("AVB property descriptor is missing its NUL terminator");
        }

        for (int i = exactEnd; i < descriptorEnd; i++)
        {
            if (region[i] != 0)
            {
                throw new InvalidDataException("AVB property descriptor trailing padding is nonzero");
            }
        }

        string key = DecodeStrictUtf8(region, keyStart, (int)keyLength, "key");
        string value = DecodeStrictUtf8(region, valueStart, (int)valueLength, "value");

        byte[] raw = new byte[total];
        Buffer.BlockCopy(region, offset, raw, 0, total);
        propertyBlobs.Add(raw);
        properties.Add(new EdlRawAvbProperty(key, value));
    }

    private static string DecodeStrictUtf8(byte[] buffer, int offset, int length, string what)
    {
        for (int i = offset; i < offset + length; i++)
        {
            if (buffer[i] == 0)
            {
                throw new InvalidDataException("AVB property " + what + " contains an embedded NUL");
            }
        }

        try
        {
            return StrictUtf8.GetString(buffer, offset, length);
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("AVB property " + what + " is not valid UTF-8");
        }
    }

    private static byte[] BuildHashDescriptor(long imageSize, string algorithm, byte[] salt, byte[] digest, uint flags)
    {
        int exactLength = 132 + 4 + salt.Length + digest.Length;
        byte[] descriptor = new byte[(int)Align(exactLength, 8)];

        WriteBeU64(descriptor, 0, 2);
        WriteBeU64(descriptor, 8, (ulong)(descriptor.Length - 16));
        WriteBeU64(descriptor, 16, (ulong)imageSize);

        byte[] algorithmBytes = Encoding.ASCII.GetBytes(algorithm);
        Buffer.BlockCopy(algorithmBytes, 0, descriptor, 24, algorithmBytes.Length);

        WriteBeU32(descriptor, 56, 4);
        WriteBeU32(descriptor, 60, (uint)salt.Length);
        WriteBeU32(descriptor, 64, (uint)digest.Length);
        WriteBeU32(descriptor, 68, flags);

        int position = 132;
        descriptor[position] = (byte)'b';
        descriptor[position + 1] = (byte)'o';
        descriptor[position + 2] = (byte)'o';
        descriptor[position + 3] = (byte)'t';
        position += 4;

        Buffer.BlockCopy(salt, 0, descriptor, position, salt.Length);
        position += salt.Length;
        Buffer.BlockCopy(digest, 0, descriptor, position, digest.Length);

        return descriptor;
    }

    private static byte[] BuildVbmeta(
        byte[] hashDescriptor,
        IReadOnlyList<byte[]> propertyBlobs,
        ulong rollbackIndex,
        uint rollbackIndexLocation,
        uint minorVersion,
        out long auxSize)
    {
        int descriptorsLength = hashDescriptor.Length;
        foreach (byte[] blob in propertyBlobs)
        {
            descriptorsLength = checked(descriptorsLength + blob.Length);
        }

        auxSize = Align(descriptorsLength + AvbPublicKeyBytes, 64);
        byte[] vbmeta = new byte[checked(VbmetaHeaderBytes + AvbAuthBlockBytes + (int)auxSize)];
        Buffer.BlockCopy(AvbVbmetaMagic, 0, vbmeta, 0, 4);
        WriteBeU32(vbmeta, 4, 1);
        WriteBeU32(vbmeta, 8, (uint)minorVersion);
        WriteBeU64(vbmeta, 12, AvbAuthBlockBytes);
        WriteBeU64(vbmeta, 20, (ulong)auxSize);
        WriteBeU32(vbmeta, 28, AvbAlgorithmRsa4096);
        WriteBeU64(vbmeta, 32, 0);
        WriteBeU64(vbmeta, 40, AvbHashBytes);
        WriteBeU64(vbmeta, 48, AvbHashBytes);
        WriteBeU64(vbmeta, 56, AvbSignatureBytes);
        WriteBeU64(vbmeta, 64, (ulong)descriptorsLength);
        WriteBeU64(vbmeta, 72, AvbPublicKeyBytes);
        WriteBeU64(vbmeta, 80, (ulong)(descriptorsLength + AvbPublicKeyBytes));
        WriteBeU64(vbmeta, 88, 0);
        WriteBeU64(vbmeta, 96, 0);
        WriteBeU64(vbmeta, 104, (ulong)descriptorsLength);
        WriteBeU64(vbmeta, 112, rollbackIndex);
        WriteBeU32(vbmeta, 120, 0);
        WriteBeU32(vbmeta, 124, rollbackIndexLocation);

        byte[] release = Encoding.ASCII.GetBytes(ReleaseString);
        Buffer.BlockCopy(release, 0, vbmeta, 128, release.Length);

        int auxStart = VbmetaHeaderBytes + AvbAuthBlockBytes;
        int position = auxStart;
        Buffer.BlockCopy(hashDescriptor, 0, vbmeta, position, hashDescriptor.Length);
        position += hashDescriptor.Length;
        foreach (byte[] blob in propertyBlobs)
        {
            Buffer.BlockCopy(blob, 0, vbmeta, position, blob.Length);
            position += blob.Length;
        }

        using Stream keyStream = typeof(EdlRawBootBuilder).Assembly.GetManifestResourceStream(AvbSigningKeyResourceName)
            ?? throw new InvalidDataException("the embedded AVB test signing material is missing from the assembly");
        using RSA key = LoadAvbSigningKey(keyStream);

        byte[] publicKey = CreateAvbPublicKey(key);
        Buffer.BlockCopy(publicKey, 0, vbmeta, auxStart + descriptorsLength, AvbPublicKeyBytes);

        byte[] digest;
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            hash.AppendData(vbmeta, 0, VbmetaHeaderBytes);
            hash.AppendData(vbmeta, auxStart, (int)auxSize);
            digest = hash.GetHashAndReset();
        }

        byte[] signature = key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (signature.Length != AvbSignatureBytes)
        {
            throw new InvalidDataException("the AVB signing key produced an unexpected signature length");
        }

        Buffer.BlockCopy(digest, 0, vbmeta, VbmetaHeaderBytes, AvbHashBytes);
        Buffer.BlockCopy(signature, 0, vbmeta, VbmetaHeaderBytes + AvbHashBytes, AvbSignatureBytes);

        return vbmeta;
    }

    private static byte[] BuildFooter(long originalImageSize, long vbmetaOffset, long vbmetaSize)
    {
        byte[] footer = new byte[AvbFooterBytes];
        Buffer.BlockCopy(AvbFooterMagic, 0, footer, 0, 4);
        WriteBeU32(footer, 4, 1);
        WriteBeU32(footer, 8, 0);
        WriteBeU64(footer, 12, (ulong)originalImageSize);
        WriteBeU64(footer, 20, (ulong)vbmetaOffset);
        WriteBeU64(footer, 28, (ulong)vbmetaSize);
        return footer;
    }

    private static void AssertCandidateVbmeta(
        ParsedVbmeta parsed,
        long auxSize,
        long descriptorsLength,
        SourceMetadata source,
        long originalImageSize,
        byte[] expectedDigest,
        string physicalDigest,
        uint minorVersion)
    {
        byte[] header = parsed.Header;
        if (ReadBeU32(header, 8) != minorVersion
            || ReadBeU64(header, 12) != AvbAuthBlockBytes
            || ReadBeU64(header, 20) != (ulong)auxSize
            || ReadBeU32(header, 28) != AvbAlgorithmRsa4096
            || ReadBeU64(header, 32) != 0
            || ReadBeU64(header, 40) != AvbHashBytes
            || ReadBeU64(header, 48) != AvbHashBytes
            || ReadBeU64(header, 56) != AvbSignatureBytes
            || ReadBeU64(header, 64) != (ulong)descriptorsLength
            || ReadBeU64(header, 72) != AvbPublicKeyBytes
            || ReadBeU64(header, 80) != (ulong)(descriptorsLength + AvbPublicKeyBytes)
            || ReadBeU64(header, 88) != 0
            || ReadBeU64(header, 96) != 0
            || ReadBeU64(header, 104) != (ulong)descriptorsLength
            || ReadBeU32(header, 120) != 0)
        {
            throw new InvalidOperationException("candidate vbmeta header is not the expected signed envelope");
        }

        for (int i = 176; i < VbmetaHeaderBytes; i++)
        {
            if (header[i] != 0)
            {
                throw new InvalidOperationException("candidate vbmeta reserved bytes are nonzero");
            }
        }

        byte[] release = Encoding.ASCII.GetBytes(ReleaseString);
        for (int i = 0; i < 48; i++)
        {
            byte expected = i < release.Length ? release[i] : (byte)0;
            if (header[128 + i] != expected)
            {
                throw new InvalidOperationException("candidate vbmeta release string mismatch");
            }
        }

        if (parsed.AuxSize != auxSize || parsed.DescriptorBytes != descriptorsLength || parsed.Total != VbmetaHeaderBytes + AvbAuthBlockBytes + auxSize)
        {
            throw new InvalidOperationException("candidate vbmeta block sizes mismatch");
        }

        HashDescriptorFacts sourceHash = source.Vbmeta.Hash;
        if (parsed.Hash.ImageSize != originalImageSize
            || parsed.Hash.Algorithm != sourceHash.Algorithm
            || parsed.Hash.Flags != sourceHash.Flags
            || !parsed.Hash.Salt.AsSpan().SequenceEqual(sourceHash.Salt)
            || !parsed.Hash.Digest.AsSpan().SequenceEqual(expectedDigest)
            || parsed.RollbackIndex != source.Vbmeta.RollbackIndex
            || parsed.RollbackIndexLocation != source.Vbmeta.RollbackIndexLocation
            || !PropertiesMatch(parsed.Properties, source.Vbmeta.Properties))
        {
            throw new InvalidOperationException("candidate vbmeta metadata does not match the source slot");
        }

        string sourceDigestHex = ToHex(parsed.Hash.Digest);
        if (!string.Equals(physicalDigest, sourceDigestHex, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("candidate hash descriptor digest does not match the physical image");
        }
    }

    private static bool PropertiesMatch(IReadOnlyList<EdlRawAvbProperty> left, IReadOnlyList<EdlRawAvbProperty> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (int i = 0; i < left.Count; i++)
        {
            if (!string.Equals(left[i].Key, right[i].Key, StringComparison.Ordinal)
                || !string.Equals(left[i].Value, right[i].Value, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static string ComputeSaltedDigest(
        Stream physical,
        byte[] salt,
        long originalImageSize,
        HashAlgorithmName hashName,
        CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(hashName);
        hash.AppendData(salt);

        byte[] buffer = new byte[CopyChunkBytes];
        physical.Position = 0;
        long remaining = originalImageSize;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int take = (int)Math.Min(remaining, buffer.Length);
            int read = physical.Read(buffer, 0, take);
            if (read == 0)
            {
                throw new InvalidOperationException("unexpected end of candidate while hashing the image");
            }

            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }

        return ToHex(hash.GetHashAndReset());
    }

    private static void VerifyDecompressedKernel(
        FileStream physical,
        long compressedLength,
        long expectedRawLength,
        string expectedRawSha256,
        CancellationToken cancellationToken)
    {
        physical.Position = BootHeaderBytes;
        using (BoundedReadStream bounded = new(physical, compressedLength))
        using (GZipStream decompressor = new(bounded, CompressionMode.Decompress))
        using (IncrementalHash rawHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[CopyChunkBytes];
            long total = 0;
            int read;
            while ((read = decompressor.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                rawHash.AppendData(buffer, 0, read);
                total += read;
                if (total > expectedRawLength)
                {
                    throw new InvalidOperationException("candidate decompressed kernel exceeds the packed raw length");
                }
            }

            if (total != expectedRawLength)
            {
                throw new InvalidOperationException("candidate decompressed kernel length mismatch");
            }

            if (!string.Equals(ToHex(rawHash.GetHashAndReset()), expectedRawSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("candidate decompressed kernel sha256 mismatch");
            }
        }
    }

    private static void CopyTo(Stream input, Stream output, IncrementalHash? hash, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[CopyChunkBytes];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            output.Write(buffer, 0, read);
            hash?.AppendData(buffer, 0, read);
        }
    }

    private static void WriteZeros(Stream output, long count, IncrementalHash? hash, CancellationToken cancellationToken)
    {
        if (count < 0)
        {
            throw new InvalidOperationException("negative padding length");
        }

        byte[] zeros = new byte[CopyChunkBytes];
        while (count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int take = (int)Math.Min(count, zeros.Length);
            output.Write(zeros, 0, take);
            hash?.AppendData(zeros, 0, take);
            count -= take;
        }
    }

    private static void AssertZeros(Stream stream, long position, long count, CancellationToken cancellationToken)
    {
        if (count < 0)
        {
            throw new InvalidOperationException("negative zero range");
        }

        byte[] buffer = new byte[8192];
        stream.Position = position;
        while (count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int take = (int)Math.Min(count, buffer.Length);
            int read = stream.Read(buffer, 0, take);
            if (read != take)
            {
                throw new InvalidOperationException("unexpected end of candidate while checking zero padding");
            }

            for (int i = 0; i < take; i++)
            {
                if (buffer[i] != 0)
                {
                    throw new InvalidOperationException("candidate zero padding contains nonzero bytes");
                }
            }

            count -= take;
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, long position, int count)
    {
        stream.Position = position;
        int read = 0;
        while (read < count)
        {
            int chunk = stream.Read(buffer, read, count - read);
            if (chunk == 0)
            {
                throw new InvalidDataException("unexpected end of stream at offset " + position.ToString());
            }

            read += chunk;
        }
    }

    private static string HashStreamSha256(Stream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[CopyChunkBytes];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            hash.AppendData(buffer, 0, read);
        }

        return ToHex(hash.GetHashAndReset());
    }

    private static string HashRangeSha256(Stream stream, long offset, long length, CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[CopyChunkBytes];
        stream.Position = offset;
        long remaining = length;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int take = (int)Math.Min(remaining, buffer.Length);
            int read = stream.Read(buffer, 0, take);
            if (read == 0)
            {
                throw new InvalidDataException("unexpected end of stream while hashing a range");
            }

            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }

        return ToHex(hash.GetHashAndReset());
    }

    private static string HashFileSha256(string path, CancellationToken cancellationToken)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, GzipChunkBytes, FileOptions.SequentialScan);
        return HashStreamSha256(stream, cancellationToken);
    }

    private static HashAlgorithmName HashNameFor(string algorithm)
    {
        return algorithm switch
        {
            "sha256" => HashAlgorithmName.SHA256,
            "sha512" => HashAlgorithmName.SHA512,
            _ => throw new InvalidDataException("unsupported AVB hash algorithm '" + algorithm + "'"),
        };
    }

    private static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static long Align(long value, long alignment)
    {
        long remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
    }

    private static ulong Align4096(ulong value)
    {
        return (value + 4095UL) / 4096UL * 4096UL;
    }

    private static uint ReadLeU32(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
    }

    private static ulong ReadLeU64(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
    }

    private static uint ReadBeU32(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset, 4));
    }

    private static ulong ReadBeU64(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
    }

    private static void WriteLeU32(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteBeU32(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteBeU64(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset, 8), value);
    }

    private sealed class SourceMetadata
    {
        public byte[] Header = Array.Empty<byte>();

        public ParsedVbmeta Vbmeta = null!;

        public string VbmetaSha256 = string.Empty;
    }

    private sealed class ParsedVbmeta
    {
        public byte[] Header = Array.Empty<byte>();

        public long AuxSize;

        public long DescriptorBytes;

        public long Total;

        public ulong RollbackIndex;

        public uint RollbackIndexLocation;

        public HashDescriptorFacts Hash = null!;

        public List<EdlRawAvbProperty> Properties = new();

        public List<byte[]> PropertyBlobs = new();

        public string BlobSha256 = string.Empty;
    }

    private sealed class HashDescriptorFacts
    {
        public long ImageSize;

        public string Algorithm = string.Empty;

        public byte[] Salt = Array.Empty<byte>();

        public byte[] Digest = Array.Empty<byte>();

        public uint Flags;
    }

    // Read-only window over the already-opened candidate; never disposes the inner stream.
    private sealed class BoundedReadStream : Stream
    {
        private readonly Stream inner;
        private long remaining;

        public BoundedReadStream(Stream inner, long length)
        {
            this.inner = inner;
            remaining = length;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (remaining <= 0 || count == 0)
            {
                return 0;
            }

            int take = (int)Math.Min(count, remaining);
            int read = inner.Read(buffer, offset, take);
            if (read > 0)
            {
                remaining -= read;
            }

            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
        }
    }
}
