// one narrow current-GBL envelope primitive. The current GBL boot
// hybrid carries a footer image_size of the new payload while the OEM-signed
// vbmeta descriptor still authenticates the old stock size, so the strict
// source envelope parser cannot consume it. This helper authenticates the
// source blob with the existing bounded leaf reader, reads the signed image
// size from the descriptor inside that authenticated blob, recompresses the
// proved packed raw and preserves the original signed blob byte-identically
// over the new payload. No signing key is read, no OEM payload verification
// and no hardware acceptance is claimed; the caller's planner separately
// proves the parent chain, GBL loader, efisp and common budget.
using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    // Repacks the current GBL hybrid: footer image_size is the new payload,
    // but the authenticated OEM descriptor image_size is the old stock size.
    // The signed size is taken from the descriptor, never from the rewritten
    // footer, so the strict parser accepts the genuine blob unchanged.
    internal static Task<CurrentBootGblPreserved> RepackCurrentGblEnvelopeAsync(
        VerifiedEdlFile originalBoot,
        VerifiedEdlFile packedRaw,
        long provenMaxRawBytes,
        string candidatePath,
        CancellationToken ct = default)
    {
        if (originalBoot is null)
        {
            throw new ArgumentNullException(nameof(originalBoot));
        }

        if (packedRaw is null)
        {
            throw new ArgumentNullException(nameof(packedRaw));
        }

        if (provenMaxRawBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(provenMaxRawBytes));
        }

        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            throw new ArgumentException("Candidate path is required.", nameof(candidatePath));
        }

        // Cancellation before scheduling means an already cancelled request
        // never opens a file or creates an output.
        ct.ThrowIfCancellationRequested();

        string sourcePath = Path.GetFullPath(originalBoot.Path);
        string rawPath = Path.GetFullPath(packedRaw.Path);
        string targetPath = Path.GetFullPath(candidatePath);

        return Task.Run(
            () => CurrentGblRepackCore(originalBoot, packedRaw, sourcePath, rawPath, provenMaxRawBytes, targetPath, ct),
            ct);
    }

    private static CurrentBootGblPreserved CurrentGblRepackCore(
        VerifiedEdlFile originalBoot,
        VerifiedEdlFile packedRaw,
        string sourcePath,
        string rawPath,
        long provenMaxRawBytes,
        string candidatePath,
        CancellationToken ct)
    {
        bool candidateCreated = false;
        bool completed = false;
        string? tempPath = null;

        try
        {
            ct.ThrowIfCancellationRequested();

            using FileStream source = new FileStream(
                sourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
            VerifyClaim(source, originalBoot, "current GBL boot", ct);

            using FileStream raw = new FileStream(
                rawPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
            VerifyClaim(raw, packedRaw, "current GBL packed raw", ct);

            long partitionLength = source.Length;
            if (partitionLength < BootHeaderBytes || partitionLength % PageSize != 0)
            {
                throw new InvalidDataException("current GBL boot length must be a positive multiple of 4096 bytes");
            }

            byte[] header = new byte[BootHeaderBytes];
            ReadExactly(source, header, 0, header.Length);

            if (!header.AsSpan(0, 8).SequenceEqual(AndroidMagic))
            {
                throw new InvalidDataException("current GBL boot magic is not ANDROID!");
            }

            if (ReadLeU32(header, 40) != 4 || ReadLeU32(header, 20) != 1584)
            {
                throw new InvalidDataException("current GBL boot must have the Android v4 header shape");
            }

            if (ReadLeU32(header, 12) != 0)
            {
                throw new InvalidDataException("current GBL boot ramdisk_size is nonzero");
            }

            if (ReadLeU32(header, 1580) != 0)
            {
                throw new InvalidDataException("current GBL boot signature_size is nonzero");
            }

            // The original OEM blob is authenticated by the shared bounded leaf
            // reader; the signed image size then comes from the descriptor
            // inside that authenticated blob, never from the (rewritten)
            // footer, and no OEM private key or payload match is involved.
            AvbNodeMetadata sourceMeta = AvbNodeReadFooterLeafMetadata(source, partitionLength, ct);
            long signedSize = CurrentBootSignedImageSize(sourceMeta);
            if (signedSize <= 0 || signedSize > partitionLength - AvbFooterBytes)
            {
                throw new InvalidDataException("current GBL signed image size is outside the partition bounds.");
            }

            // The strict parser still validates the exact boot name, hash
            // algorithm, salt, length and properties — over the authenticated
            // signed size instead of the stale footer value.
            ParsedVbmeta parsed = ParseVbmeta(source, sourceMeta.VbmetaOffset, sourceMeta.VbmetaSize, signedSize, ct);

            long rawLength = raw.Length;
            ValidatePackedRaw(raw, rawLength, provenMaxRawBytes);

            string outputDirectory = Path.GetDirectoryName(candidatePath)
                ?? throw new InvalidDataException("candidate path has no directory component");
            tempPath = Path.Combine(
                outputDirectory,
                "." + Path.GetFileName(candidatePath) + "." + Guid.NewGuid().ToString("N") + ".tmp");

            long compressedLength;
            using (FileStream temp = new FileStream(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.ReadWrite,
                       FileShare.None,
                       CopyChunkBytes,
                       FileOptions.SequentialScan))
            {
                raw.Position = 0;
                using (GZipStream compressor = new GZipStream(temp, CompressionLevel.Optimal, leaveOpen: true))
                {
                    CopyTo(raw, compressor, null, ct);
                }

                // The gzip stream is finalized before the length is measured.
                temp.Flush(true);
                compressedLength = temp.Length;
            }

            if (compressedLength <= 0 || compressedLength > uint.MaxValue)
            {
                throw new InvalidDataException("compressed current GBL raw length is not representable in the v4 header");
            }

            byte[] newHeader = (byte[])header.Clone();
            WriteLeU32(newHeader, 8, (uint)compressedLength);

            long newPayloadBytes = checked(BootHeaderBytes + Align(compressedLength, PageSize));
            if (partitionLength <= MetadataReserveBytes || newPayloadBytes > partitionLength - MetadataReserveBytes)
            {
                throw new InvalidDataException(
                    "repacked current GBL payload exceeds the avbtool metadata and footer reserve for the partition");
            }

            long newVbmetaOffset = newPayloadBytes;
            int blobLength = sourceMeta.Blob.Length;
            if ((long)blobLength > partitionLength - AvbFooterBytes - newVbmetaOffset)
            {
                throw new InvalidDataException("current GBL signed metadata does not fit before the final footer.");
            }

            long bodyZeroBytes = partitionLength - AvbFooterBytes - newVbmetaOffset - blobLength;
            if (bodyZeroBytes < 0)
            {
                throw new InvalidDataException("current GBL effective boot body exceeds the partition body.");
            }

            byte[] footer = BuildFooter(newPayloadBytes, newVbmetaOffset, blobLength);
            using (FileStream target = new FileStream(
                       candidatePath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyChunkBytes))
            {
                candidateCreated = true;
                target.Write(newHeader, 0, newHeader.Length);
                using (FileStream compressed = new FileStream(
                           tempPath,
                           FileMode.Open,
                           FileAccess.Read,
                           FileShare.Read,
                           CopyChunkBytes,
                           FileOptions.SequentialScan))
                {
                    CopyTo(compressed, target, null, ct);
                }

                WriteZeros(target, newPayloadBytes - BootHeaderBytes - compressedLength, null, ct);
                target.Write(sourceMeta.Blob, 0, blobLength);
                WriteZeros(target, bodyZeroBytes, null, ct);
                target.Write(footer, 0, footer.Length);

                if (target.Position != partitionLength)
                {
                    throw new InvalidOperationException("candidate boot length does not match the partition length");
                }

                target.Flush(true);
            }

            // Verify the physical output by re-reading the bytes just written.
            using FileStream check = new FileStream(
                candidatePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
            if (check.Length != partitionLength)
            {
                throw new InvalidOperationException("candidate boot length changed on disk");
            }

            VerifyDecompressedKernel(check, compressedLength, rawLength, packedRaw.Sha256, ct);

            byte[] writtenHeader = new byte[BootHeaderBytes];
            ReadExactly(check, writtenHeader, 0, writtenHeader.Length);
            for (int i = 0; i < BootHeaderBytes; i++)
            {
                if ((i < 8 || i >= 12) && writtenHeader[i] != header[i])
                {
                    throw new InvalidOperationException("candidate header differs from the source outside kernel_size");
                }
            }

            if (ReadLeU32(writtenHeader, 8) != compressedLength)
            {
                throw new InvalidOperationException("candidate header kernel_size mismatch");
            }

            byte[] writtenFooter = new byte[AvbFooterBytes];
            ReadExactly(check, writtenFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);
            if (!writtenFooter.AsSpan().SequenceEqual(footer))
            {
                throw new InvalidOperationException("candidate AVB footer mismatch");
            }

            AvbNodeMetadata candidateMeta = AvbNodeReadFooterLeafMetadata(check, partitionLength, ct);
            if (!candidateMeta.Blob.AsSpan().SequenceEqual(sourceMeta.Blob))
            {
                throw new InvalidOperationException("candidate metadata is not the original signed blob.");
            }

            if (!string.Equals(
                    candidateMeta.SourcePublicKeySha256,
                    sourceMeta.SourcePublicKeySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("candidate metadata key differs from the original signed key.");
            }

            if (candidateMeta.VbmetaOffset != newVbmetaOffset || candidateMeta.VbmetaSize != blobLength)
            {
                throw new InvalidOperationException("candidate metadata geometry is not the new payload geometry.");
            }

            string actualPayloadSha256 = HashRangeSha256(check, 0, newPayloadBytes, ct);
            string effectiveDigest = ComputeSaltedDigest(
                check,
                parsed.Hash.Salt,
                parsed.Hash.ImageSize,
                HashNameFor(parsed.Hash.Algorithm),
                ct);

            var facts = new EdlRawOriginalBootSignatureFacts
            {
                SignedVbmetaSha256 = AvbNodeSha256Hex(sourceMeta.Blob),
                PublicKeySha256 = sourceMeta.SourcePublicKeySha256,
                AlgorithmType = sourceMeta.Algorithm,
                RollbackIndex = sourceMeta.RollbackIndex,
                RollbackIndexLocation = sourceMeta.RollbackIndexLocation,
                Flags = sourceMeta.Flags,
                RequiredMajor = sourceMeta.RequiredMajor,
                RequiredMinor = sourceMeta.RequiredMinor,
                SignedContentBytes = parsed.Hash.ImageSize,
                SignedContentDigestHex = ToHex(parsed.Hash.Digest),
                EffectiveContentDigestHex = effectiveDigest
            };

            string candidateSha256 = HashStreamSha256(check, ct);
            var candidate = new VerifiedEdlFile(candidatePath, partitionLength, candidateSha256);

            // The source and raw claims are re-verified over the untouched
            // physical files right before the record is handed back.
            VerifyClaim(source, originalBoot, "current GBL boot", ct);
            VerifyClaim(raw, packedRaw, "current GBL packed raw", ct);

            completed = true;
            return new CurrentBootGblPreserved(
                candidate,
                facts,
                newPayloadBytes,
                actualPayloadSha256,
                newVbmetaOffset,
                blobLength);
        }
        finally
        {
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

            // Only this call's own candidate is removed; a pre-existing file at
            // the candidate path (which made CreateNew refuse) stays untouched.
            if (candidateCreated && !completed)
            {
                try
                {
                    File.Delete(candidatePath);
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

    // Reads the signed image size from the hash descriptor inside the already
    // authenticated vbmeta blob. The descriptor region starts at the auxiliary
    // block (256 + auth_size); the range comes from the header fields at 96
    // and 104. A bounded authenticated region of eight-byte-aligned descriptors
    // is walked and exactly one tag-2 hash descriptor must exist; its image_size is the BE64 field at +16.
    private static long CurrentBootSignedImageSize(AvbNodeMetadata metadata)
    {
        byte[] blob = metadata.Blob;
        if (blob.Length < VbmetaHeaderBytes)
        {
            throw new InvalidDataException("current GBL signed blob is smaller than the vbmeta header");
        }

        ulong authSize = ReadBeU64(blob, 12);
        ulong auxSize = ReadBeU64(blob, 20);
        if (authSize > (ulong)(blob.Length - VbmetaHeaderBytes) ||
            auxSize > (ulong)(blob.Length - VbmetaHeaderBytes) - authSize)
        {
            throw new InvalidDataException("current GBL vbmeta blocks exceed the signed blob");
        }

        ulong descriptorsOffset = ReadBeU64(blob, 96);
        ulong descriptorsSize = ReadBeU64(blob, 104);
        if (descriptorsOffset > auxSize || descriptorsSize > auxSize - descriptorsOffset)
        {
            throw new InvalidDataException("current GBL descriptor range is outside the auxiliary block");
        }

        long regionStart = VbmetaHeaderBytes + (long)authSize + (long)descriptorsOffset;
        long regionEnd = regionStart + (long)descriptorsSize;
        long hashDescriptor = -1;
        long position = regionStart;
        while (position < regionEnd)
        {
            if (regionEnd - position < 16)
            {
                throw new InvalidDataException("current GBL descriptor header is truncated");
            }

            int at = (int)position;
            ulong tag = ReadBeU64(blob, at);
            ulong following = ReadBeU64(blob, at + 8);
            if (following > int.MaxValue)
            {
                throw new InvalidDataException("current GBL descriptor body is too large");
            }

            long length = 16L + (long)following;
            if (length > regionEnd - position)
            {
                throw new InvalidDataException("current GBL descriptor exceeds the descriptor region");
            }

            if ((length & 7) != 0)
            {
                throw new InvalidDataException("current GBL descriptor length is not a multiple of 8");
            }

            if (tag == 2)
            {
                if (hashDescriptor >= 0)
                {
                    throw new InvalidDataException("duplicate AVB hash descriptor in the current GBL vbmeta");
                }

                if (length < 24)
                {
                    throw new InvalidDataException("current GBL hash descriptor is too small");
                }

                hashDescriptor = at;
            }

            position += length;
        }

        if (hashDescriptor < 0)
        {
            throw new InvalidDataException("current GBL vbmeta is missing the AVB hash descriptor");
        }

        return (long)ReadBeU64(blob, checked((int)(hashDescriptor + 16)));
    }
}
