using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    internal static string SigningPublicKeySha256 => AvbPublicKeySha256;

    // P1-GREEN-B: bounded AVB re-sign. The source partition metadata is validated
    // in place, cloned at the same length, rekeyed and re-signed with the fixed
    // compiled AOSP key. Only the declared auth hash/signature ranges and the
    // 1032-byte key slots change; every other byte is copied unchanged.
    internal static Task<EdlRawResignedAvbNode> ResignAvbNodeAsync(
        VerifiedEdlFile originalPartition,
        EdlRawAvbNodeKind kind,
        string candidatePath,
        CancellationToken cancellationToken = default)
    {
        if (originalPartition is null)
        {
            throw new ArgumentNullException(nameof(originalPartition));
        }

        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            throw new ArgumentException("Candidate path is required.", nameof(candidatePath));
        }

        if (kind != EdlRawAvbNodeKind.Recovery &&
            kind != EdlRawAvbNodeKind.VbmetaSystem &&
            kind != EdlRawAvbNodeKind.Vbmeta)
        {
            throw new InvalidDataException("Unsupported AVB node kind.");
        }

        // Cancellation before scheduling means an already cancelled request never
        // touches the source or creates an output stream.
        cancellationToken.ThrowIfCancellationRequested();

        // Normalize once so scheduling, I/O, cleanup and the candidate claim all
        // refer to the same full path.
        candidatePath = Path.GetFullPath(candidatePath);

        return Task.Run(
            () => AvbNodeResignCore(originalPartition, kind, candidatePath, cancellationToken),
            cancellationToken);
    }

    private sealed class AvbNodeChainKey
    {
        public string Name = string.Empty;
        public int KeyOffset;
        public uint Location;
        public uint Flags;
    }

    private sealed class AvbNodeMetadata
    {
        public byte[] Blob = Array.Empty<byte>();
        public long VbmetaOffset;
        public int VbmetaSize;
        public int AuthSize;
        public int AuxSize;
        public ulong RollbackIndex;
        public uint RollbackIndexLocation;
        public uint Flags;
        public uint RequiredMajor;
        public uint RequiredMinor;
        public uint Algorithm;
        public string SourcePublicKeySha256 = string.Empty;
        public string NonChainDescriptorsSha256 = string.Empty;
        public List<AvbNodeChainKey> ChainKeys = new List<AvbNodeChainKey>();
    }

    private static EdlRawResignedAvbNode AvbNodeResignCore(
        VerifiedEdlFile originalPartition,
        EdlRawAvbNodeKind kind,
        string candidatePath,
        CancellationToken cancellationToken)
    {
        bool candidateCreated = false;
        bool completed = false;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using FileStream source = new FileStream(
                Path.GetFullPath(originalPartition.Path),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            VerifyClaim(source, originalPartition, "AVB source partition", cancellationToken);

            long sourceLength = source.Length;
            AvbNodeMetadata metadata = AvbNodeReadMetadata(source, kind, sourceLength, cancellationToken);

            // Load and pin the fixed compiled signing key before touching output.
            byte[] targetPublicKey = Array.Empty<byte>();
            byte[] patched = Array.Empty<byte>();
            using (Stream keyStream = typeof(EdlRawBootBuilder).Assembly
                       .GetManifestResourceStream(AvbSigningKeyResourceName)
                   ?? throw new InvalidDataException("AVB signing key resource is missing."))
            using (RSA signingKey = LoadAvbSigningKey(keyStream))
            {
                targetPublicKey = CreateAvbPublicKey(signingKey);
                if (targetPublicKey is null || targetPublicKey.Length != AvbPublicKeyBytes)
                {
                    throw new InvalidDataException("Fixed AVB public key is not a 4096-bit key blob.");
                }

                string targetPublicKeySha256 = AvbNodeSha256Hex(targetPublicKey);
                if (!string.Equals(targetPublicKeySha256, AvbPublicKeySha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Fixed AVB public key does not match the compiled pin.");
                }

                patched = AvbNodeCloneAndPatch(metadata, targetPublicKey);
                byte[] patchedDigest = AvbNodeDigest(patched, VbmetaHeaderBytes + metadata.AuthSize, metadata.AuxSize);

                // Write only the declared auth hash and signature ranges.
                Array.Copy(
                    patchedDigest,
                    0,
                    patched,
                    VbmetaHeaderBytes + AvbNodeReadBeU64AsInt(metadata.Blob, 32),
                    AvbHashBytes);

                byte[] signature = signingKey.SignHash(
                    patchedDigest,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                if (signature is null || signature.Length != AvbSignatureBytes)
                {
                    throw new InvalidDataException("Fixed AVB signing key produced an unexpected signature size.");
                }

                Array.Copy(
                    signature,
                    0,
                    patched,
                    VbmetaHeaderBytes + AvbNodeReadBeU64AsInt(metadata.Blob, 48),
                    AvbSignatureBytes);

                cancellationToken.ThrowIfCancellationRequested();

                using (FileStream candidate = new FileStream(
                           candidatePath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           CopyChunkBytes))
                {
                    candidateCreated = true;

                    source.Seek(0, SeekOrigin.Begin);
                    using IncrementalHash copyHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    CopyTo(source, candidate, copyHash, cancellationToken);

                    string copiedSha256 = ToHex(copyHash.GetHashAndReset());
                    long copiedLength = candidate.Length;

                    if (copiedLength != originalPartition.Length ||
                        !string.Equals(copiedSha256, originalPartition.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("AVB source bytes changed while copying.");
                    }

                    if (patched.Length != metadata.VbmetaSize)
                    {
                        throw new InvalidDataException("AVB patched metadata length changed.");
                    }

                    candidate.Seek(metadata.VbmetaOffset, SeekOrigin.Begin);
                    candidate.Write(patched, 0, patched.Length);
                    candidate.Flush(true);
                }
            }

            // Reopen the written candidate and verify the physical bytes, the
            // embedded target key and the fresh RSA signature independently.
            string candidateSha256 = string.Empty;
            string candidatePublicKeySha256 = string.Empty;
            long candidateLength = 0;
            AvbNodeMetadata verified = null;
            using (FileStream check = new FileStream(
                       candidatePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read,
                       CopyChunkBytes,
                       FileOptions.SequentialScan))
            {
                if (check.Length != originalPartition.Length)
                {
                    throw new InvalidDataException("AVB candidate length differs from the source partition.");
                }

                byte[] physical = new byte[metadata.VbmetaSize];
                ReadExactly(check, physical, metadata.VbmetaOffset, metadata.VbmetaSize);

                if (!physical.AsSpan().SequenceEqual(patched))
                {
                    throw new InvalidDataException("AVB candidate physical metadata differs from the signed clone.");
                }

                candidateLength = check.Length;

                verified = AvbNodeParse(physical, metadata.VbmetaOffset, kind == EdlRawAvbNodeKind.Vbmeta);
                candidatePublicKeySha256 = verified.SourcePublicKeySha256;

                if (verified.VbmetaSize != metadata.VbmetaSize ||
                    verified.RollbackIndex != metadata.RollbackIndex ||
                    verified.RollbackIndexLocation != metadata.RollbackIndexLocation ||
                    verified.Flags != metadata.Flags ||
                    verified.RequiredMajor != metadata.RequiredMajor ||
                    verified.RequiredMinor != metadata.RequiredMinor ||
                    !string.Equals(
                        verified.NonChainDescriptorsSha256,
                        metadata.NonChainDescriptorsSha256,
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException("AVB candidate metadata is not layout-preserving.");
                }

                if (!string.Equals(candidatePublicKeySha256, AvbPublicKeySha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("AVB candidate does not carry the pinned public key.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                candidateSha256 = HashStreamSha256(check, cancellationToken);
            }

            var chainPublicKeys = new Dictionary<string, string>(StringComparer.Ordinal);
            if (kind == EdlRawAvbNodeKind.Vbmeta)
            {
                // Report the physical chain key digests that were actually verified in
                // the written candidate, checking each against the pinned key.
                foreach (AvbNodeChainKey chainKey in verified.ChainKeys)
                {
                    string chainKeySha256 = AvbNodeSha256Hex(
                        AvbNodeSlice(verified.Blob, chainKey.KeyOffset, AvbPublicKeyBytes));

                    if (!string.Equals(chainKeySha256, AvbPublicKeySha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("AVB chain partition key does not match the pinned public key.");
                    }

                    chainPublicKeys[chainKey.Name] = chainKeySha256;
                }
            }

            var chainPublicKeysView = new ReadOnlyDictionary<string, string>(chainPublicKeys);

            var candidateClaim = new VerifiedEdlFile(candidatePath, candidateLength, candidateSha256);

            cancellationToken.ThrowIfCancellationRequested();

            var result = new EdlRawResignedAvbNode(
                originalPartition,
                candidateClaim,
                kind,
                metadata.SourcePublicKeySha256,
                AvbPublicKeySha256,
                chainPublicKeysView,
                metadata.VbmetaOffset,
                metadata.VbmetaSize,
                metadata.RollbackIndex,
                metadata.RollbackIndexLocation,
                metadata.Flags,
                metadata.RequiredMajor,
                metadata.RequiredMinor,
                metadata.NonChainDescriptorsSha256);

            completed = true;
            return result;
        }
        finally
        {
            if (candidateCreated && !completed)
            {
                AvbNodeTryDelete(candidatePath);
            }
        }
    }

    private static AvbNodeMetadata AvbNodeReadMetadata(
        FileStream source,
        EdlRawAvbNodeKind kind,
        long sourceLength,
        CancellationToken cancellationToken)
    {
        if (sourceLength < AvbFooterBytes)
        {
            throw new InvalidDataException("AVB source partition is too small.");
        }

        if (kind == EdlRawAvbNodeKind.Recovery)
        {
            return AvbNodeReadFooterLeafMetadata(source, sourceLength, cancellationToken);
        }

        byte[] header = new byte[VbmetaHeaderBytes];
        ReadExactly(source, header, 0, VbmetaHeaderBytes);

        if (!AvbNodeHasMagic(header, 0, "AVB0"))
        {
            throw new InvalidDataException("AVB metadata header magic is invalid.");
        }

        ulong auth = ReadBeU64(header, 12);
        ulong aux = ReadBeU64(header, 20);

        if (auth > (ulong)VbmetaReserveBytes || aux > (ulong)VbmetaReserveBytes)
        {
            throw new InvalidDataException("AVB standalone metadata block size is out of bounds.");
        }

        ulong total = (ulong)VbmetaHeaderBytes + auth + aux;
        if (total > (ulong)VbmetaReserveBytes || total > (ulong)sourceLength)
        {
            throw new InvalidDataException("AVB standalone metadata exceeds the partition or bounded reserve.");
        }

        long vbmetaOffset = 0;
        int vbmetaSize = (int)total;

        cancellationToken.ThrowIfCancellationRequested();

        byte[] blob = new byte[vbmetaSize];
        ReadExactly(source, blob, vbmetaOffset, vbmetaSize);

        return AvbNodeParse(blob, vbmetaOffset, kind == EdlRawAvbNodeKind.Vbmeta);
    }

    // P1 common footer leaf reader: bounded footer read plus the shared AVB0
    // parse path. Extracted mechanically from the recovery branch so the GBL
    // envelope owner can reuse the same bound without a public node kind.
    private static AvbNodeMetadata AvbNodeReadFooterLeafMetadata(
        FileStream source,
        long sourceLength,
        CancellationToken cancellationToken)
    {
        if (sourceLength < AvbFooterBytes)
        {
            throw new InvalidDataException("AVB footer leaf partition is too small.");
        }

        byte[] footer = new byte[AvbFooterBytes];
        ReadExactly(source, footer, sourceLength - AvbFooterBytes, AvbFooterBytes);

        if (!AvbNodeHasMagic(footer, 0, "AVBf"))
        {
            throw new InvalidDataException("AVB footer leaf magic is invalid.");
        }

        if (ReadBeU32(footer, 4) != 1)
        {
            throw new InvalidDataException("AVB footer leaf major version is unsupported.");
        }

        ulong originalImageSize = ReadBeU64(footer, 12);
        ulong offset = ReadBeU64(footer, 20);
        ulong size = ReadBeU64(footer, 28);

        if (originalImageSize > offset)
        {
            throw new InvalidDataException("AVB footer leaf image size exceeds the vbmeta offset.");
        }

        if (size < VbmetaHeaderBytes || size > (ulong)VbmetaReserveBytes)
        {
            throw new InvalidDataException("AVB footer leaf vbmeta size is out of bounds.");
        }

        ulong beforeFooter = (ulong)(sourceLength - AvbFooterBytes);
        if (offset > beforeFooter || size > beforeFooter - offset)
        {
            throw new InvalidDataException("AVB footer leaf vbmeta location exceeds the partition body.");
        }

        long vbmetaOffset = (long)offset;
        int vbmetaSize = (int)size;

        cancellationToken.ThrowIfCancellationRequested();

        byte[] blob = new byte[vbmetaSize];
        ReadExactly(source, blob, vbmetaOffset, vbmetaSize);

        return AvbNodeParse(blob, vbmetaOffset, false);
    }

    private static AvbNodeMetadata AvbNodeParse(byte[] blob, long vbmetaOffset, bool requireRootChains)
    {
        if (blob.Length < VbmetaHeaderBytes)
        {
            throw new InvalidDataException("AVB metadata header is truncated.");
        }

        if (!AvbNodeHasMagic(blob, 0, "AVB0"))
        {
            throw new InvalidDataException("AVB metadata header magic is invalid.");
        }

        uint major = ReadBeU32(blob, 4);
        uint minor = ReadBeU32(blob, 8);
        uint algorithm = ReadBeU32(blob, 28);

        if (major != 1)
        {
            throw new InvalidDataException("AVB metadata major version is unsupported.");
        }

        if (algorithm != AvbAlgorithmRsa4096)
        {
            throw new InvalidDataException("AVB metadata algorithm is not SHA256_RSA4096.");
        }

        ulong authSize64 = ReadBeU64(blob, 12);
        ulong auxSize64 = ReadBeU64(blob, 20);

        if (authSize64 % 64 != 0 || auxSize64 % 64 != 0)
        {
            throw new InvalidDataException("AVB auth or aux block is not 64-byte aligned.");
        }

        if (authSize64 > (ulong)VbmetaReserveBytes || auxSize64 > (ulong)VbmetaReserveBytes)
        {
            throw new InvalidDataException("AVB auth or aux block is out of bounds.");
        }

        if ((ulong)VbmetaHeaderBytes + authSize64 + auxSize64 != (ulong)blob.Length)
        {
            throw new InvalidDataException("AVB metadata block sizes do not match the declared vbmeta size.");
        }

        int authSize = (int)authSize64;
        int auxSize = (int)auxSize64;
        int auxOffset = VbmetaHeaderBytes + authSize;

        ulong hashOffset = ReadBeU64(blob, 32);
        ulong hashSize = ReadBeU64(blob, 40);
        ulong signatureOffset = ReadBeU64(blob, 48);
        ulong signatureSize = ReadBeU64(blob, 56);
        ulong publicKeyOffset = ReadBeU64(blob, 64);
        ulong publicKeySize = ReadBeU64(blob, 72);
        ulong keyMetadataOffset = ReadBeU64(blob, 80);
        ulong keyMetadataSize = ReadBeU64(blob, 88);
        ulong descriptorOffset = ReadBeU64(blob, 96);
        ulong descriptorSize = ReadBeU64(blob, 104);

        if (hashSize != AvbHashBytes || signatureSize != AvbSignatureBytes)
        {
            throw new InvalidDataException("AVB authentication hash or signature size is unsupported.");
        }

        if (publicKeySize != AvbPublicKeyBytes)
        {
            throw new InvalidDataException("AVB public key size is not 1032 bytes.");
        }

        if (keyMetadataSize != 0)
        {
            throw new InvalidDataException("AVB key metadata is not supported.");
        }

        if (!AvbNodeRangeFits(hashOffset, AvbHashBytes, authSize64) ||
            !AvbNodeRangeFits(signatureOffset, AvbSignatureBytes, authSize64))
        {
            throw new InvalidDataException("AVB auth hash or signature range exceeds the auth block.");
        }

        if (AvbNodeRangesOverlap(
                hashOffset,
                AvbHashBytes,
                signatureOffset,
                AvbSignatureBytes))
        {
            throw new InvalidDataException("AVB auth hash and signature ranges overlap.");
        }

        if (!AvbNodeRangeFits(publicKeyOffset, AvbPublicKeyBytes, auxSize64))
        {
            throw new InvalidDataException("AVB main public key exceeds the aux block.");
        }

        if (descriptorOffset % 8 != 0 || descriptorSize % 8 != 0)
        {
            throw new InvalidDataException("AVB descriptor block is not 8-byte aligned.");
        }

        if (!AvbNodeRangeFits(descriptorOffset, descriptorSize, auxSize64))
        {
            throw new InvalidDataException("AVB descriptor block exceeds the aux block.");
        }

        if (AvbNodeRangesOverlap(
                publicKeyOffset,
                AvbPublicKeyBytes,
                descriptorOffset,
                descriptorSize))
        {
            throw new InvalidDataException("AVB descriptor block overlaps the main public key.");
        }

        // key_metadata_offset is unused when key_metadata_size is zero.
        _ = keyMetadataOffset;

        int publicKeyStart = auxOffset + (int)publicKeyOffset;
        int descriptorStart = auxOffset + (int)descriptorOffset;
        int descriptorEnd = descriptorStart + (int)descriptorSize;

        uint flags = ReadBeU32(blob, 120);
        uint rollbackLocation = ReadBeU32(blob, 124);
        ulong rollbackIndex = ReadBeU64(blob, 112);

        List<AvbNodeChainKey> chainKeys = new List<AvbNodeChainKey>();
        var nonChainNamesHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        try
        {
            int position = descriptorStart;
            while (position < descriptorEnd)
            {
                if (descriptorEnd - position < 16)
                {
                    throw new InvalidDataException("AVB descriptor header is truncated.");
                }

                ulong tag = ReadBeU64(blob, position);
                ulong following = ReadBeU64(blob, position + 8);
                int available = descriptorEnd - position - 16;

                if (following > (ulong)available)
                {
                    throw new InvalidDataException("AVB descriptor length exceeds the descriptor block.");
                }

                ulong total64 = 16UL + following;
                if (total64 % 8 != 0)
                {
                    throw new InvalidDataException("AVB descriptor total length is not 8-byte aligned.");
                }

                int total = (int)total64;

                if (tag == 4)
                {
                    if (total < 92)
                    {
                        throw new InvalidDataException("AVB chain partition descriptor is truncated.");
                    }

                    ulong nameLength = ReadBeU32(blob, position + 20);
                    ulong keyLength = ReadBeU32(blob, position + 24);
                    int nameStart = position + 92;

                    if (nameLength > (ulong)(total - 92))
                    {
                        throw new InvalidDataException("AVB chain partition name exceeds the descriptor.");
                    }

                    int keyStart = nameStart + (int)nameLength;
                    ulong remaining = (ulong)(total - 92 - (int)nameLength);

                    if (keyLength > remaining)
                    {
                        throw new InvalidDataException("AVB chain partition key exceeds the descriptor.");
                    }

                    if (keyLength != AvbPublicKeyBytes)
                    {
                        throw new InvalidDataException("AVB chain partition key is not 1032 bytes.");
                    }

                    if (ReadBeU32(blob, keyStart) != 4096)
                    {
                        throw new InvalidDataException("AVB chain partition key is not 4096 bits.");
                    }

                    string name = AvbNodeReadAsciiName(blob, nameStart, (int)nameLength);
                    chainKeys.Add(new AvbNodeChainKey
                    {
                        Name = name,
                        KeyOffset = keyStart,
                        Location = ReadBeU32(blob, position + 16),
                        Flags = ReadBeU32(blob, position + 28)
                    });
                }
                else
                {
                    nonChainNamesHash.AppendData(blob, position, total);
                }

                position += total;
            }

            if (position != descriptorEnd)
            {
                throw new InvalidDataException("AVB descriptor walk did not end on the descriptor boundary.");
            }

            string nonChainSha256 = ToHex(nonChainNamesHash.GetHashAndReset());

            if (requireRootChains)
            {
                if (chainKeys.Count != 3)
                {
                    throw new InvalidDataException("AVB vbmeta must carry exactly three chain partitions.");
                }

                var seen = new HashSet<string>(StringComparer.Ordinal);
                bool hasBoot = false;
                bool hasRecovery = false;
                bool hasVbmetaSystem = false;

                foreach (AvbNodeChainKey chainKey in chainKeys)
                {
                    if (!seen.Add(chainKey.Name))
                    {
                        throw new InvalidDataException("AVB vbmeta chain partition name is duplicated.");
                    }

                    switch (chainKey.Name)
                    {
                        case "boot":
                            hasBoot = true;
                            break;
                        case "recovery":
                            hasRecovery = true;
                            break;
                        case "vbmeta_system":
                            hasVbmetaSystem = true;
                            break;
                        default:
                            throw new InvalidDataException("AVB vbmeta chain partition name is unexpected.");
                    }
                }

                if (!hasBoot || !hasRecovery || !hasVbmetaSystem)
                {
                    throw new InvalidDataException("AVB vbmeta chain partitions are incomplete.");
                }
            }
            else if (chainKeys.Count != 0)
            {
                throw new InvalidDataException("AVB leaf node must not contain chain partition descriptors.");
            }

            return AvbNodeFinishParse(
                blob,
                vbmetaOffset,
                authSize,
                auxSize,
                auxOffset,
                major,
                minor,
                algorithm,
                flags,
                rollbackLocation,
                rollbackIndex,
                hashOffset,
                signatureOffset,
                publicKeyStart,
                chainKeys,
                nonChainSha256);
        }
        finally
        {
            nonChainNamesHash.Dispose();
        }
    }

    private static AvbNodeMetadata AvbNodeFinishParse(
        byte[] blob,
        long vbmetaOffset,
        int authSize,
        int auxSize,
        int auxOffset,
        uint major,
        uint minor,
        uint algorithm,
        uint flags,
        uint rollbackLocation,
        ulong rollbackIndex,
        ulong hashOffset,
        ulong signatureOffset,
        int publicKeyStart,
        List<AvbNodeChainKey> chainKeys,
        string nonChainSha256)
    {
        if (ReadBeU32(blob, publicKeyStart) != 4096)
        {
            throw new InvalidDataException("AVB main public key is not 4096 bits.");
        }

        byte[] sourcePublicKey = new byte[AvbPublicKeyBytes];
        Array.Copy(blob, publicKeyStart, sourcePublicKey, 0, AvbPublicKeyBytes);
        string sourcePublicKeySha256 = AvbNodeSha256Hex(sourcePublicKey);

        byte[] digest = AvbNodeDigest(blob, auxOffset, auxSize);

        var storedHash = new byte[AvbHashBytes];
        Array.Copy(blob, VbmetaHeaderBytes + (int)hashOffset, storedHash, 0, AvbHashBytes);

        if (!CryptographicOperations.FixedTimeEquals(digest, storedHash))
        {
            throw new InvalidDataException("AVB source authentication hash does not match.");
        }

        var signature = new byte[AvbSignatureBytes];
        Array.Copy(blob, VbmetaHeaderBytes + (int)signatureOffset, signature, 0, AvbSignatureBytes);

        try
        {
            var parameters = new RSAParameters
            {
                Modulus = AvbNodeSlice(sourcePublicKey, 8, AvbRsaModulusBytes),
                Exponent = new byte[] { 1, 0, 1 }
            };

            using RSA verifier = RSA.Create();
            verifier.ImportParameters(parameters);

            if (!verifier.VerifyHash(
                    digest,
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1))
            {
                throw new InvalidDataException("AVB source signature does not verify.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("AVB source public key or signature is invalid.", exception);
        }

        var metadata = new AvbNodeMetadata
        {
            Blob = blob,
            VbmetaOffset = vbmetaOffset,
            VbmetaSize = blob.Length,
            AuthSize = authSize,
            AuxSize = auxSize,
            RollbackIndex = rollbackIndex,
            RollbackIndexLocation = rollbackLocation,
            Flags = flags,
            RequiredMajor = major,
            RequiredMinor = minor,
            Algorithm = algorithm,
            SourcePublicKeySha256 = sourcePublicKeySha256,
            NonChainDescriptorsSha256 = nonChainSha256,
            ChainKeys = chainKeys
        };

        return metadata;
    }

    private static byte[] AvbNodeCloneAndPatch(
        AvbNodeMetadata metadata,
        byte[] targetPublicKey)
    {
        byte[] clone = (byte[])metadata.Blob.Clone();
        int auxOffset = VbmetaHeaderBytes + metadata.AuthSize;
        int publicKeyStart = auxOffset + AvbNodeReadBeU64AsInt(metadata.Blob, 64);

        Array.Copy(targetPublicKey, 0, clone, publicKeyStart, AvbPublicKeyBytes);

        foreach (AvbNodeChainKey chainKey in metadata.ChainKeys)
        {
            if (chainKey.KeyOffset < auxOffset ||
                chainKey.KeyOffset > clone.Length - AvbPublicKeyBytes)
            {
                throw new InvalidDataException("AVB chain partition key range is outside the aux block.");
            }

            Array.Copy(targetPublicKey, 0, clone, chainKey.KeyOffset, AvbPublicKeyBytes);
        }

        return clone;
    }

    private static byte[] AvbNodeDigest(byte[] blob, int auxOffset, int auxSize)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(blob, 0, VbmetaHeaderBytes);
        hash.AppendData(blob, auxOffset, auxSize);
        return hash.GetHashAndReset();
    }

    private static string AvbNodeSha256Hex(byte[] data)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(data);
        return ToHex(hash.GetHashAndReset());
    }

    private static byte[] AvbNodeSlice(byte[] source, int offset, int count)
    {
        var result = new byte[count];
        Array.Copy(source, offset, result, 0, count);
        return result;
    }

    private static bool AvbNodeHasMagic(byte[] buffer, int offset, string magic)
    {
        if (buffer.Length - offset < 4)
        {
            return false;
        }

        return buffer[offset] == magic[0] &&
               buffer[offset + 1] == magic[1] &&
               buffer[offset + 2] == magic[2] &&
               buffer[offset + 3] == magic[3];
    }

    private static string AvbNodeReadAsciiName(byte[] blob, int offset, int length)
    {
        if (length <= 0)
        {
            throw new InvalidDataException("AVB chain partition name is empty.");
        }

        for (int index = 0; index < length; index++)
        {
            byte value = blob[offset + index];
            if (value < 0x20 || value > 0x7E)
            {
                throw new InvalidDataException("AVB chain partition name is not ASCII.");
            }
        }

        return Encoding.ASCII.GetString(blob, offset, length);
    }

    private static int AvbNodeReadBeU64AsInt(byte[] buffer, int offset)
    {
        ulong value = ReadBeU64(buffer, offset);
        if (value > int.MaxValue)
        {
            throw new InvalidDataException("AVB metadata field exceeds the supported range.");
        }

        return (int)value;
    }

    private static bool AvbNodeRangeFits(ulong offset, ulong length, ulong limit)
    {
        return offset <= limit && length <= limit - offset;
    }

    private static bool AvbNodeRangesOverlap(ulong firstOffset, ulong firstLength, ulong secondOffset, ulong secondLength)
    {
        if (firstLength == 0 || secondLength == 0)
        {
            return false;
        }

        if (firstOffset < secondOffset)
        {
            return secondOffset - firstOffset < firstLength;
        }

        return firstOffset - secondOffset < secondLength;
    }

    private static void AvbNodeTryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best-effort cleanup only; the caller owns the work directory.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup only; the caller owns the work directory.
        }
    }
}
