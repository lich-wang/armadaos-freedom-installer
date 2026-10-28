using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    // GBL-GREEN-B: preserve the original OEM-signed boot metadata over the
    // already-proved AOSP payload. The original blob is copied byte-identically
    // and only the source-built footer's vbmeta_size is retargeted, so no
    // descriptor, digest, key, rollback, flag or padding is re-signed here.
    internal static Task<EdlRawGblPreservedBoot> PreserveOriginalSignedBootMetadataAsync(
        EdlRawBuiltBoot sourceBuiltBoot,
        VerifiedEdlFile originalBoot,
        string candidatePath,
        CancellationToken cancellationToken = default)
    {
        if (sourceBuiltBoot is null)
        {
            throw new ArgumentNullException(nameof(sourceBuiltBoot));
        }

        if (originalBoot is null)
        {
            throw new ArgumentNullException(nameof(originalBoot));
        }

        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            throw new ArgumentException("Candidate path is required.", nameof(candidatePath));
        }

        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(sourceBuiltBoot.IsDisposed, sourceBuiltBoot);

        // Normalize once so scheduling, I/O, cleanup and the candidate claim all
        // refer to the same full path.
        candidatePath = Path.GetFullPath(candidatePath);

        return Task.Run(
            () => GblPreserveCoreAsync(sourceBuiltBoot, originalBoot, candidatePath, cancellationToken),
            cancellationToken);
    }

    // GBL-GREEN-B: read-only authentication of the genuine original vbmeta root
    // chain. The boot child key is hashed from the actual descriptor slot and is
    // reported separately from the root principal; nothing is generated or
    // mutated and no equality between the two keys is assumed.
    internal static Task<EdlRawOriginalBootChainFacts> AuthenticateOriginalBootChainAsync(
        VerifiedEdlFile originalVbmeta,
        CancellationToken cancellationToken = default)
    {
        if (originalVbmeta is null)
        {
            throw new ArgumentNullException(nameof(originalVbmeta));
        }

        cancellationToken.ThrowIfCancellationRequested();

        string path = Path.GetFullPath(originalVbmeta.Path);

        return Task.Run(
            () => GblAuthenticateOriginalChainCore(originalVbmeta, path, cancellationToken),
            cancellationToken);
    }

    private static async Task<EdlRawGblPreservedBoot> GblPreserveCoreAsync(
        EdlRawBuiltBoot sourceBuiltBoot,
        VerifiedEdlFile originalBoot,
        string candidatePath,
        CancellationToken cancellationToken)
    {
        bool candidateCreated = false;
        bool completed = false;
        FileStream effectiveLease = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(sourceBuiltBoot.IsDisposed, sourceBuiltBoot);

            await sourceBuiltBoot.RevalidateAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            long newPayloadBytes = sourceBuiltBoot.Envelope.OriginalImageSize;
            long newVbmetaOffset = sourceBuiltBoot.Envelope.VbmetaOffset;
            long newVbmetaBytes = sourceBuiltBoot.Envelope.VbmetaBytes;

            using FileStream originalStream = new FileStream(
                Path.GetFullPath(originalBoot.Path),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            VerifyClaim(originalStream, originalBoot, "GBL original boot", cancellationToken);

            using FileStream sourceCandidate = new FileStream(
                Path.GetFullPath(sourceBuiltBoot.CandidateBoot.Path),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            VerifyClaim(sourceCandidate, sourceBuiltBoot.CandidateBoot, "GBL source built boot", cancellationToken);

            long partitionLength = originalStream.Length;
            if (sourceCandidate.Length != partitionLength)
            {
                throw new InvalidDataException("GBL source built boot length differs from the original boot partition.");
            }

            // The original OEM blob is authenticated by the shared bounded leaf
            // reader, then bound to the exact blob the source build consumed.
            AvbNodeMetadata originalMeta = AvbNodeReadFooterLeafMetadata(
                originalStream,
                partitionLength,
                cancellationToken);

            string originalBlobSha256 = AvbNodeSha256Hex(originalMeta.Blob);
            if (!string.Equals(
                    originalBlobSha256,
                    sourceBuiltBoot.Envelope.SourceEmbeddedVbmetaSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL original boot metadata does not match the source build binding.");
            }

            AvbNodeMetadata sourceCandidateMeta = AvbNodeReadFooterLeafMetadata(
                sourceCandidate,
                partitionLength,
                cancellationToken);

            // The source proof stays an AOSP proof; it is never reinterpreted as
            // the OEM-signed original metadata.
            if (!string.Equals(
                    sourceCandidateMeta.SourcePublicKeySha256,
                    AvbPublicKeySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL source built boot does not carry the pinned AOSP public key.");
            }

            byte[] originalFooter = new byte[AvbFooterBytes];
            ReadExactly(originalStream, originalFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);

            byte[] sourceFooter = new byte[AvbFooterBytes];
            ReadExactly(sourceCandidate, sourceFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);

            // Keep the source build's NEW payload boundary and metadata location;
            // the stock payload size is never restored.
            if (ReadBeU64(sourceFooter, 12) != (ulong)newPayloadBytes ||
                ReadBeU64(sourceFooter, 20) != (ulong)newVbmetaOffset ||
                ReadBeU64(sourceFooter, 28) != (ulong)newVbmetaBytes)
            {
                throw new InvalidDataException("GBL source built boot footer does not match the recorded envelope.");
            }

            if (sourceCandidateMeta.VbmetaOffset != newVbmetaOffset ||
                sourceCandidateMeta.VbmetaSize != newVbmetaBytes)
            {
                throw new InvalidDataException("GBL source built boot metadata geometry does not match the recorded envelope.");
            }

            if (newPayloadBytes <= 0 || newPayloadBytes > newVbmetaOffset)
            {
                throw new InvalidDataException("GBL source built boot payload exceeds the metadata offset.");
            }

            if (newVbmetaOffset > partitionLength - AvbFooterBytes)
            {
                throw new InvalidDataException("GBL source built boot metadata offset exceeds the partition body.");
            }

            int originalBlobLength = originalMeta.Blob.Length;
            if ((long)originalBlobLength > partitionLength - AvbFooterBytes - newVbmetaOffset)
            {
                throw new InvalidDataException("GBL original signed metadata does not fit before the final footer.");
            }

            // The original descriptor parser is applied to the genuine stock
            // stream only; its digest is deliberately stale for the new payload.
            long originalImageSize = (long)ReadBeU64(originalFooter, 12);
            var originalParsed = ParseVbmeta(
                originalStream,
                originalMeta.VbmetaOffset,
                originalMeta.VbmetaSize,
                originalImageSize,
                cancellationToken);

            string expectedPayloadSha256 = HashRangeSha256(
                sourceCandidate,
                0,
                newPayloadBytes,
                cancellationToken);

            byte[] expectedFooter = (byte[])sourceFooter.Clone();
            BinaryPrimitives.WriteUInt64BigEndian(
                expectedFooter.AsSpan(28, 8),
                (ulong)originalBlobLength);

            using (FileStream target = new FileStream(
                       candidatePath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyChunkBytes))
            {
                candidateCreated = true;

                GblCopyPrefix(sourceCandidate, target, newVbmetaOffset, cancellationToken);
                target.Write(originalMeta.Blob, 0, originalBlobLength);

                long zeroCount = partitionLength - AvbFooterBytes - newVbmetaOffset - originalBlobLength;
                if (zeroCount < 0)
                {
                    throw new InvalidDataException("GBL effective boot body exceeds the partition body.");
                }

                WriteZeros(target, zeroCount, null, cancellationToken);
                target.Write(expectedFooter, 0, AvbFooterBytes);
                target.Flush(true);
            }

            // Verify the physical output independently before handing its lease to
            // the wrapper. The blob must be byte-identical to the OEM original.
            effectiveLease = new FileStream(
                candidatePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            if (effectiveLease.Length != partitionLength)
            {
                throw new InvalidDataException("GBL effective boot length changed.");
            }

            AvbNodeMetadata effectiveMeta = AvbNodeReadFooterLeafMetadata(
                effectiveLease,
                partitionLength,
                cancellationToken);

            if (!effectiveMeta.Blob.AsSpan().SequenceEqual(originalMeta.Blob))
            {
                throw new InvalidDataException("GBL effective boot metadata is not the original signed blob.");
            }

            if (!string.Equals(
                    effectiveMeta.SourcePublicKeySha256,
                    originalMeta.SourcePublicKeySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL effective boot metadata key differs from the original signed key.");
            }

            if (effectiveMeta.VbmetaOffset != newVbmetaOffset ||
                effectiveMeta.VbmetaSize != originalBlobLength)
            {
                throw new InvalidDataException("GBL effective boot metadata geometry is not the new source geometry.");
            }

            byte[] effectiveFooter = new byte[AvbFooterBytes];
            ReadExactly(effectiveLease, effectiveFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);

            if (!effectiveFooter.AsSpan().SequenceEqual(expectedFooter))
            {
                throw new InvalidDataException("GBL effective boot footer differs from the expected clone.");
            }

            if (ReadBeU64(effectiveFooter, 12) != (ulong)newPayloadBytes ||
                ReadBeU64(effectiveFooter, 20) != (ulong)newVbmetaOffset ||
                ReadBeU64(effectiveFooter, 28) != (ulong)originalBlobLength)
            {
                throw new InvalidDataException("GBL effective boot footer geometry is not the new source geometry.");
            }

            string actualPayloadSha256 = HashRangeSha256(
                effectiveLease,
                0,
                newPayloadBytes,
                cancellationToken);

            if (!string.Equals(actualPayloadSha256, expectedPayloadSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL effective boot payload differs from the source build payload.");
            }

            HashAlgorithmName contentAlgorithm;
            if (string.Equals(originalParsed.Hash.Algorithm, "sha256", StringComparison.OrdinalIgnoreCase))
            {
                contentAlgorithm = HashAlgorithmName.SHA256;
            }
            else if (string.Equals(originalParsed.Hash.Algorithm, "sha512", StringComparison.OrdinalIgnoreCase))
            {
                contentAlgorithm = HashAlgorithmName.SHA512;
            }
            else
            {
                throw new InvalidDataException("GBL original boot content hash algorithm is unsupported.");
            }

            string effectiveContentDigest = ComputeSaltedDigest(
                effectiveLease,
                originalParsed.Hash.Salt,
                originalParsed.Hash.ImageSize,
                contentAlgorithm,
                cancellationToken);

            var facts = new EdlRawOriginalBootSignatureFacts
            {
                SignedVbmetaSha256 = originalBlobSha256,
                PublicKeySha256 = originalMeta.SourcePublicKeySha256,
                AlgorithmType = originalMeta.Algorithm,
                RollbackIndex = originalMeta.RollbackIndex,
                RollbackIndexLocation = originalMeta.RollbackIndexLocation,
                Flags = originalMeta.Flags,
                RequiredMajor = originalMeta.RequiredMajor,
                RequiredMinor = originalMeta.RequiredMinor,
                SignedContentBytes = originalParsed.Hash.ImageSize,
                SignedContentDigestHex = ToHex(originalParsed.Hash.Digest),
                EffectiveContentDigestHex = effectiveContentDigest
            };

            string effectiveSha256 = HashStreamSha256(effectiveLease, cancellationToken);
            var effectiveClaim = new VerifiedEdlFile(candidatePath, partitionLength, effectiveSha256);

            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(sourceBuiltBoot.IsDisposed, sourceBuiltBoot);

            effectiveLease.Seek(0, SeekOrigin.Begin);

            var result = new EdlRawGblPreservedBoot(
                sourceBuiltBoot,
                originalBoot,
                effectiveClaim,
                facts,
                newPayloadBytes,
                expectedPayloadSha256,
                newVbmetaOffset,
                originalBlobLength,
                effectiveLease);

            // Ownership of the already-verified lease moved to the wrapper.
            effectiveLease = null;
            completed = true;
            return result;
        }
        finally
        {
            if (effectiveLease is not null)
            {
                effectiveLease.Dispose();
            }

            if (candidateCreated && !completed)
            {
                AvbNodeTryDelete(candidatePath);
            }
        }
    }

    private static void GblCopyPrefix(
        FileStream source,
        FileStream destination,
        long byteCount,
        CancellationToken cancellationToken)
    {
        source.Seek(0, SeekOrigin.Begin);

        byte[] buffer = new byte[CopyChunkBytes];
        long remaining = byteCount;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int chunk = (int)Math.Min(buffer.Length, remaining);
            int read = source.Read(buffer, 0, chunk);

            if (read <= 0)
            {
                throw new InvalidDataException("GBL source built boot ended before the declared prefix.");
            }

            destination.Write(buffer, 0, read);
            remaining -= read;
        }
    }

    private static EdlRawOriginalBootChainFacts GblAuthenticateOriginalChainCore(
        VerifiedEdlFile originalVbmeta,
        string path,
        CancellationToken cancellationToken)
    {
        using FileStream stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyChunkBytes,
            FileOptions.SequentialScan);

        VerifyClaim(stream, originalVbmeta, "GBL original vbmeta", cancellationToken);

        long length = stream.Length;
        AvbNodeMetadata metadata = AvbNodeReadMetadata(
            stream,
            EdlRawAvbNodeKind.Vbmeta,
            length,
            cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();

        AvbNodeChainKey bootKey = null;
        foreach (AvbNodeChainKey chainKey in metadata.ChainKeys)
        {
            if (string.Equals(chainKey.Name, "boot", StringComparison.Ordinal))
            {
                bootKey = chainKey;
                break;
            }
        }

        if (bootKey is null)
        {
            throw new InvalidDataException("GBL original vbmeta does not declare a boot chain partition.");
        }

        if (bootKey.KeyOffset < 0 ||
            bootKey.KeyOffset > metadata.Blob.Length - AvbPublicKeyBytes)
        {
            throw new InvalidDataException("GBL original boot chain key range is outside the metadata blob.");
        }

        byte[] bootKeyBlob = new byte[AvbPublicKeyBytes];
        Array.Copy(metadata.Blob, bootKey.KeyOffset, bootKeyBlob, 0, AvbPublicKeyBytes);
        string bootChainPublicKeySha256 = AvbNodeSha256Hex(bootKeyBlob);

        string signedVbmetaSha256 = AvbNodeSha256Hex(metadata.Blob);

        return new EdlRawOriginalBootChainFacts(
            originalVbmeta,
            signedVbmetaSha256,
            metadata.SourcePublicKeySha256,
            bootChainPublicKeySha256);
    }
}
