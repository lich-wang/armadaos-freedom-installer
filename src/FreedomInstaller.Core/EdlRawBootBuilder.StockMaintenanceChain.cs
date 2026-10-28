// STOCK-CHAIN-1: read-only companion-chain proof for stock boot maintenance.
// Verifies that a candidate vbmeta/recovery/vbmeta_system triple is a faithful
// AOSP rekey of the original stock triple: every node is RSA-4096 verified in
// place, each child key is pinned by its own root vbmeta chain, every
// declaration beyond the rekey is identical, and the source recovery payload
// is proven physically against its authenticated hash descriptor. The verifier
// produces no files and claims no OEM/hardware/rollback acceptance.
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    internal static Task<BootStockMaintenanceChainFacts> VerifyStockMaintenanceChainAsync(
        VerifiedEdlFile sourceRoot,
        VerifiedEdlFile sourceRecovery,
        VerifiedEdlFile sourceVbmetaSystem,
        VerifiedEdlFile currentRoot,
        VerifiedEdlFile currentRecovery,
        VerifiedEdlFile currentVbmetaSystem,
        CancellationToken ct = default)
    {
        VerifiedEdlFile[] inputs =
        {
            sourceRoot, sourceRecovery, sourceVbmetaSystem,
            currentRoot, currentRecovery, currentVbmetaSystem
        };

        for (int i = 0; i < inputs.Length; i++)
        {
            if (inputs[i] is null)
            {
                throw new ArgumentNullException(
                    new[] { nameof(sourceRoot), nameof(sourceRecovery), nameof(sourceVbmetaSystem),
                        nameof(currentRoot), nameof(currentRecovery), nameof(currentVbmetaSystem) }[i]);
            }
        }

        // Precancel before any path is normalized, opened or scheduled so a
        // cancelled request never touches any input.
        ct.ThrowIfCancellationRequested();

        string[] paths = new string[inputs.Length];
        for (int i = 0; i < inputs.Length; i++)
        {
            paths[i] = Path.GetFullPath(inputs[i]!.Path);
        }

        ct.ThrowIfCancellationRequested();

        return Task.Run(
            () => VerifyStockMaintenanceChainCore(inputs, paths, ct),
            ct);
    }

    private static BootStockMaintenanceChainFacts VerifyStockMaintenanceChainCore(
        VerifiedEdlFile[] inputs,
        string[] paths,
        CancellationToken ct)
    {
        VerifiedEdlFile sourceRoot = inputs[0];
        VerifiedEdlFile sourceRecovery = inputs[1];
        VerifiedEdlFile sourceVbmetaSystem = inputs[2];
        VerifiedEdlFile currentRoot = inputs[3];
        VerifiedEdlFile currentRecovery = inputs[4];
        VerifiedEdlFile currentVbmetaSystem = inputs[5];

        // All six inputs stay under this method's own read leases until the
        // facts are returned; every failure or cancel releases them via using.
        using FileStream sourceRootStream = OpenStockOriginalLease(paths[0]);
        using FileStream sourceRecoveryStream = OpenStockOriginalLease(paths[1]);
        using FileStream sourceSystemStream = OpenStockOriginalLease(paths[2]);
        using FileStream currentRootStream = OpenStockOriginalLease(paths[3]);
        using FileStream currentRecoveryStream = OpenStockOriginalLease(paths[4]);
        using FileStream currentSystemStream = OpenStockOriginalLease(paths[5]);

        VerifyLease(sourceRootStream, sourceRoot, "source root vbmeta", ct);
        VerifyLease(sourceRecoveryStream, sourceRecovery, "source recovery", ct);
        VerifyLease(sourceSystemStream, sourceVbmetaSystem, "source vbmeta_system", ct);
        VerifyLease(currentRootStream, currentRoot, "current root vbmeta", ct);
        VerifyLease(currentRecoveryStream, currentRecovery, "current recovery", ct);
        VerifyLease(currentSystemStream, currentVbmetaSystem, "current vbmeta_system", ct);

        ct.ThrowIfCancellationRequested();

        // These shared reads perform the actual auth hash AND RSA-4096 SHA256
        // PKCS1 verification of each node via AvbNodeFinishParse.
        AvbNodeMetadata sourceRootMeta = AvbNodeReadMetadata(
            sourceRootStream, EdlRawAvbNodeKind.Vbmeta, sourceRootStream.Length, ct);
        AvbNodeMetadata sourceRecoveryMeta = AvbNodeReadMetadata(
            sourceRecoveryStream, EdlRawAvbNodeKind.Recovery, sourceRecoveryStream.Length, ct);
        AvbNodeMetadata sourceSystemMeta = AvbNodeReadMetadata(
            sourceSystemStream, EdlRawAvbNodeKind.VbmetaSystem, sourceSystemStream.Length, ct);
        AvbNodeMetadata currentRootMeta = AvbNodeReadMetadata(
            currentRootStream, EdlRawAvbNodeKind.Vbmeta, currentRootStream.Length, ct);
        AvbNodeMetadata currentRecoveryMeta = AvbNodeReadMetadata(
            currentRecoveryStream, EdlRawAvbNodeKind.Recovery, currentRecoveryStream.Length, ct);
        AvbNodeMetadata currentSystemMeta = AvbNodeReadMetadata(
            currentSystemStream, EdlRawAvbNodeKind.VbmetaSystem, currentSystemStream.Length, ct);

        // Each root must pin the exact key its own child was signed with.
        // Source and current pins may differ freely (AOSP rekey) and the root
        // main key may differ from its children. The original boot image
        // itself is verified by the existing stock original verifier.
        string sourceRecoveryKey = RequirePinnedChildKey(
            sourceRootMeta, sourceRecoveryMeta, "recovery", "source recovery");
        string sourceSystemKey = RequirePinnedChildKey(
            sourceRootMeta, sourceSystemMeta, "vbmeta_system", "source vbmeta_system");
        string currentRecoveryKey = RequirePinnedChildKey(
            currentRootMeta, currentRecoveryMeta, "recovery", "current recovery");
        string currentSystemKey = RequirePinnedChildKey(
            currentRootMeta, currentSystemMeta, "vbmeta_system", "current vbmeta_system");

        (long recoveryImageSize, string recoveryDigestHex) =
            ProveSourceRecoveryPayload(sourceRecoveryStream, sourceRecoveryMeta, ct);

        // The declared external data must be unchanged beyond the rekey. Root
        // nonchain equality alone is insufficient: the root chain key does not
        // commit the child system/vendor descriptors, so each role's own
        // authenticated metadata is compared too. Super/Btrfs/system content
        // is deliberately not read or validated here.
        RequireSameDeclarations(sourceRootMeta, currentRootMeta, "root vbmeta");
        RequireSameDeclarations(sourceRecoveryMeta, currentRecoveryMeta, "recovery");
        RequireSameDeclarations(sourceSystemMeta, currentSystemMeta, "vbmeta_system");
        RequireSameRootChainDeclarations(sourceRootMeta, currentRootMeta);

        ct.ThrowIfCancellationRequested();

        // Re-prove every file byte-for-byte on the still-open leases so the
        // facts only describe content unchanged across the whole proof.
        VerifyLease(sourceRootStream, sourceRoot, "source root vbmeta", ct);
        VerifyLease(sourceRecoveryStream, sourceRecovery, "source recovery", ct);
        VerifyLease(sourceSystemStream, sourceVbmetaSystem, "source vbmeta_system", ct);
        VerifyLease(currentRootStream, currentRoot, "current root vbmeta", ct);
        VerifyLease(currentRecoveryStream, currentRecovery, "current recovery", ct);
        VerifyLease(currentSystemStream, currentVbmetaSystem, "current vbmeta_system", ct);

        return new BootStockMaintenanceChainFacts(
            sourceRoot,
            sourceRecovery,
            sourceVbmetaSystem,
            currentRoot,
            currentRecovery,
            currentVbmetaSystem,
            sourceRootMeta.SourcePublicKeySha256,
            sourceRecoveryKey,
            sourceSystemKey,
            currentRootMeta.SourcePublicKeySha256,
            currentRecoveryKey,
            currentSystemKey,
            recoveryImageSize,
            recoveryDigestHex,
            sourceRootMeta.NonChainDescriptorsSha256,
            sourceRecoveryMeta.NonChainDescriptorsSha256,
            sourceSystemMeta.NonChainDescriptorsSha256,
            sourceRootMeta.RollbackIndex,
            sourceRootMeta.RollbackIndexLocation,
            sourceRootMeta.Flags);
    }

    private static void VerifyLease(FileStream stream, VerifiedEdlFile claim, string what, CancellationToken ct)
    {
        stream.Position = 0;
        VerifyClaim(stream, claim, what, ct);
    }

    private static AvbNodeChainKey FindChainKey(AvbNodeMetadata root, string name, string what)
    {
        foreach (AvbNodeChainKey chainKey in root.ChainKeys)
        {
            if (string.Equals(chainKey.Name, name, StringComparison.Ordinal))
            {
                return chainKey;
            }
        }

        throw new InvalidDataException(what + " does not declare a '" + name + "' chain partition.");
    }

    private static string RequirePinnedChildKey(
        AvbNodeMetadata root,
        AvbNodeMetadata child,
        string chainName,
        string childLabel)
    {
        AvbNodeChainKey chain = FindChainKey(root, chainName, childLabel + " root vbmeta");
        byte[] pinned = new byte[AvbPublicKeyBytes];
        Array.Copy(root.Blob, chain.KeyOffset, pinned, 0, AvbPublicKeyBytes);
        string pinnedSha256 = AvbNodeSha256Hex(pinned);
        if (!string.Equals(pinnedSha256, child.SourcePublicKeySha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                childLabel + " is not signed with the key pinned by its root vbmeta chain.");
        }

        return pinnedSha256;
    }

    private static void RequireSameDeclarations(AvbNodeMetadata source, AvbNodeMetadata current, string what)
    {
        if (!string.Equals(
                source.NonChainDescriptorsSha256,
                current.NonChainDescriptorsSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(what + " declared descriptors differ beyond the allowed rekey.");
        }

        if (source.RollbackIndex != current.RollbackIndex)
        {
            throw new InvalidDataException(what + " rollback index differs beyond the allowed rekey.");
        }

        if (source.RollbackIndexLocation != current.RollbackIndexLocation)
        {
            throw new InvalidDataException(what + " rollback index location differs beyond the allowed rekey.");
        }

        if (source.Flags != current.Flags)
        {
            throw new InvalidDataException(what + " flags differ beyond the allowed rekey.");
        }

        if (source.RequiredMajor != current.RequiredMajor || source.RequiredMinor != current.RequiredMinor)
        {
            throw new InvalidDataException(what + " required version differs beyond the allowed rekey.");
        }
    }

    private static void RequireSameRootChainDeclarations(AvbNodeMetadata sourceRoot, AvbNodeMetadata currentRoot)
    {
        foreach (string name in new[] { "boot", "recovery", "vbmeta_system" })
        {
            AvbNodeChainKey source = FindChainKey(sourceRoot, name, "source root vbmeta");
            AvbNodeChainKey current = FindChainKey(currentRoot, name, "current root vbmeta");
            if (source.Location != current.Location || source.Flags != current.Flags)
            {
                throw new InvalidDataException(
                    "root vbmeta chain declaration for '" + name + "' differs beyond the allowed rekey.");
            }
        }
    }

    private static (long ImageSize, string DigestHex) ProveSourceRecoveryPayload(
        FileStream recoveryStream,
        AvbNodeMetadata metadata,
        CancellationToken ct)
    {
        // The shared metadata parse authenticated the vbmeta blob but never
        // proved the physical payload behind it, so re-read the footer and
        // prove bytes [0, original_image_size) against the authenticated
        // hash descriptor. No ParseHashDescriptor reuse: that one is
        // hardcoded to 'boot'.
        long length = recoveryStream.Length;
        byte[] footer = new byte[AvbFooterBytes];
        ReadExactly(recoveryStream, footer, length - AvbFooterBytes, AvbFooterBytes);

        ulong originalImageSize = ReadBeU64(footer, 12);
        if (originalImageSize == 0UL ||
            originalImageSize > (ulong)long.MaxValue ||
            originalImageSize > (ulong)metadata.VbmetaOffset)
        {
            throw new InvalidDataException(
                "source recovery original image size is not a bounded positive payload.");
        }

        ulong descriptorOffset = ReadBeU64(metadata.Blob, 96);
        ulong descriptorSize = ReadBeU64(metadata.Blob, 104);
        int descriptorStart = VbmetaHeaderBytes + metadata.AuthSize + checked((int)descriptorOffset);
        int descriptorEnd = descriptorStart + checked((int)descriptorSize);

        byte[] salt = Array.Empty<byte>();
        byte[] storedDigest = Array.Empty<byte>();
        string algorithm = string.Empty;
        int hashDescriptors = 0;

        int position = descriptorStart;
        while (position < descriptorEnd)
        {
            if (descriptorEnd - position < 16)
            {
                throw new InvalidDataException("source recovery descriptor header is truncated.");
            }

            ulong tag = ReadBeU64(metadata.Blob, position);
            ulong following = ReadBeU64(metadata.Blob, position + 8);
            if (following > (ulong)(descriptorEnd - position - 16))
            {
                throw new InvalidDataException(
                    "source recovery descriptor length exceeds the descriptor block.");
            }

            ulong total64 = 16UL + following;
            if (total64 % 8 != 0 || total64 > (ulong)(descriptorEnd - position))
            {
                throw new InvalidDataException(
                    "source recovery descriptor total length is not 8-byte aligned.");
            }

            int total = (int)total64;
            if (tag == 2 && IsRecoveryNamedHashDescriptor(metadata.Blob, position, total))
            {
                if (hashDescriptors != 0)
                {
                    throw new InvalidDataException(
                        "source recovery carries more than one 'recovery' hash descriptor.");
                }

                ParseRecoveryHashDescriptor(
                    metadata.Blob,
                    position,
                    total,
                    (long)originalImageSize,
                    out salt,
                    out storedDigest,
                    out algorithm);
                hashDescriptors++;
            }

            position += total;
        }

        if (position != descriptorEnd)
        {
            throw new InvalidDataException("source recovery descriptor walk did not end on the boundary.");
        }

        if (hashDescriptors != 1)
        {
            throw new InvalidDataException("source recovery carries no hash descriptor for 'recovery'.");
        }

        string computed = ComputeSaltedDigest(
            recoveryStream, salt, (long)originalImageSize, HashNameFor(algorithm), ct);
        if (!string.Equals(computed, ToHex(storedDigest), StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "source recovery physical payload does not match its authenticated hash descriptor.");
        }

        return ((long)originalImageSize, ToHex(storedDigest));
    }

    // Bounded pre-selection of the exact self hash descriptor: only a tag-2
    // descriptor whose 8-byte partition name is exactly 'recovery' is the
    // recovery self hash. Other authenticated declarations (e.g. the system
    // hash) may legitimately exist and are skipped here — they stay bound by
    // the actual RSA verification and the source/current nonchain equality.
    private static bool IsRecoveryNamedHashDescriptor(byte[] blob, int offset, int total)
    {
        if (total < 140)
        {
            return false;
        }

        if (ReadBeU32(blob, offset + 56) != 8)
        {
            return false;
        }

        return blob[offset + 132] == (byte)'r' &&
            blob[offset + 133] == (byte)'e' &&
            blob[offset + 134] == (byte)'c' &&
            blob[offset + 135] == (byte)'o' &&
            blob[offset + 136] == (byte)'v' &&
            blob[offset + 137] == (byte)'e' &&
            blob[offset + 138] == (byte)'r' &&
            blob[offset + 139] == (byte)'y';
    }

    private static void ParseRecoveryHashDescriptor(
        byte[] blob,
        int offset,
        int total,
        long expectedOriginalImageSize,
        out byte[] salt,
        out byte[] digest,
        out string algorithm)
    {
        salt = Array.Empty<byte>();
        digest = Array.Empty<byte>();
        algorithm = string.Empty;

        if (total < 16 + 132 + 8)
        {
            throw new InvalidDataException("source recovery hash descriptor is too small.");
        }

        ulong imageSize = ReadBeU64(blob, offset + 16);
        if (imageSize != (ulong)expectedOriginalImageSize)
        {
            throw new InvalidDataException(
                "source recovery hash descriptor image_size does not match the footer original_image_size.");
        }

        int algorithmLength = 0;
        while (algorithmLength < 32 && blob[offset + 24 + algorithmLength] != 0)
        {
            algorithmLength++;
        }

        for (int i = offset + 24 + algorithmLength; i < offset + 56; i++)
        {
            if (blob[i] != 0)
            {
                throw new InvalidDataException("source recovery hash algorithm field has nonzero padding.");
            }
        }

        string candidate = Encoding.ASCII.GetString(blob, offset + 24, algorithmLength);
        if (candidate != "sha256" && candidate != "sha512")
        {
            throw new InvalidDataException("unsupported source recovery hash algorithm '" + candidate + "'.");
        }

        uint nameLength = ReadBeU32(blob, offset + 56);
        ulong saltLength = ReadBeU32(blob, offset + 60);
        uint digestLength = ReadBeU32(blob, offset + 64);
        uint flags = ReadBeU32(blob, offset + 68);

        if (flags != 0 && flags != 1)
        {
            throw new InvalidDataException("unsupported source recovery hash descriptor flags.");
        }

        if (nameLength != 8)
        {
            throw new InvalidDataException("source recovery hash descriptor name length is not 8.");
        }

        uint expectedDigestLength = candidate == "sha256" ? 32U : 64U;
        if (digestLength != expectedDigestLength)
        {
            throw new InvalidDataException(
                "source recovery digest length does not match the hash algorithm.");
        }

        for (int i = offset + 72; i < offset + 132; i++)
        {
            if (blob[i] != 0)
            {
                throw new InvalidDataException("source recovery hash descriptor reserved bytes are nonzero.");
            }
        }

        long nameStart = offset + 132;
        long saltStart = nameStart + nameLength;
        long digestStart = saltStart + (long)saltLength;
        long exactEnd = digestStart + digestLength;
        if (exactEnd > offset + total)
        {
            throw new InvalidDataException(
                "source recovery hash descriptor fields exceed the descriptor length.");
        }

        long padded = (exactEnd - offset + 7) & ~7L;
        if (padded != total)
        {
            throw new InvalidDataException("source recovery hash descriptor length padding is inconsistent.");
        }

        for (long i = exactEnd; i < offset + total; i++)
        {
            if (blob[i] != 0)
            {
                throw new InvalidDataException("source recovery hash descriptor trailing padding is nonzero.");
            }
        }

        if (blob[nameStart] != (byte)'r' || blob[nameStart + 1] != (byte)'e' ||
            blob[nameStart + 2] != (byte)'c' || blob[nameStart + 3] != (byte)'o' ||
            blob[nameStart + 4] != (byte)'v' || blob[nameStart + 5] != (byte)'e' ||
            blob[nameStart + 6] != (byte)'r' || blob[nameStart + 7] != (byte)'y')
        {
            throw new InvalidDataException("source recovery hash descriptor name is not 'recovery'.");
        }

        salt = new byte[saltLength];
        if (saltLength > 0)
        {
            Buffer.BlockCopy(blob, (int)saltStart, salt, 0, (int)saltLength);
        }

        digest = new byte[digestLength];
        Buffer.BlockCopy(blob, (int)digestStart, digest, 0, (int)digestLength);
        algorithm = candidate;
    }
}

// Factual, get-only results of the companion-chain proof: what each input
// claims, which keys actually pinned the children, and the recovery payload
// facts proven from physical bytes. No acceptance booleans of any kind.
internal sealed class BootStockMaintenanceChainFacts
{
    internal BootStockMaintenanceChainFacts(
        VerifiedEdlFile sourceRoot, VerifiedEdlFile sourceRecovery, VerifiedEdlFile sourceVbmetaSystem,
        VerifiedEdlFile currentRoot, VerifiedEdlFile currentRecovery, VerifiedEdlFile currentVbmetaSystem,
        string sourceRootKeySha256, string sourceRecoveryKeySha256, string sourceVbmetaSystemKeySha256,
        string currentRootKeySha256, string currentRecoveryKeySha256, string currentVbmetaSystemKeySha256,
        long recoveryImageSize, string recoveryDigestHex,
        string rootNonChainDescriptorsSha256, string recoveryNonChainDescriptorsSha256,
        string vbmetaSystemNonChainDescriptorsSha256,
        ulong rollbackIndex, uint rollbackIndexLocation, uint flags)
    {
        SourceRoot = sourceRoot;
        SourceRecovery = sourceRecovery;
        SourceVbmetaSystem = sourceVbmetaSystem;
        CurrentRoot = currentRoot;
        CurrentRecovery = currentRecovery;
        CurrentVbmetaSystem = currentVbmetaSystem;
        SourceRootKeySha256 = sourceRootKeySha256;
        SourceRecoveryKeySha256 = sourceRecoveryKeySha256;
        SourceVbmetaSystemKeySha256 = sourceVbmetaSystemKeySha256;
        CurrentRootKeySha256 = currentRootKeySha256;
        CurrentRecoveryKeySha256 = currentRecoveryKeySha256;
        CurrentVbmetaSystemKeySha256 = currentVbmetaSystemKeySha256;
        RecoveryImageSize = recoveryImageSize;
        RecoveryDigestHex = recoveryDigestHex;
        RootNonChainDescriptorsSha256 = rootNonChainDescriptorsSha256;
        RecoveryNonChainDescriptorsSha256 = recoveryNonChainDescriptorsSha256;
        VbmetaSystemNonChainDescriptorsSha256 = vbmetaSystemNonChainDescriptorsSha256;
        RollbackIndex = rollbackIndex;
        RollbackIndexLocation = rollbackIndexLocation;
        Flags = flags;
    }

    public VerifiedEdlFile SourceRoot { get; }
    public VerifiedEdlFile SourceRecovery { get; }
    public VerifiedEdlFile SourceVbmetaSystem { get; }
    public VerifiedEdlFile CurrentRoot { get; }
    public VerifiedEdlFile CurrentRecovery { get; }
    public VerifiedEdlFile CurrentVbmetaSystem { get; }
    public string SourceRootKeySha256 { get; }
    public string SourceRecoveryKeySha256 { get; }
    public string SourceVbmetaSystemKeySha256 { get; }
    public string CurrentRootKeySha256 { get; }
    public string CurrentRecoveryKeySha256 { get; }
    public string CurrentVbmetaSystemKeySha256 { get; }
    public long RecoveryImageSize { get; }
    public string RecoveryDigestHex { get; }
    public string RootNonChainDescriptorsSha256 { get; }
    public string RecoveryNonChainDescriptorsSha256 { get; }
    public string VbmetaSystemNonChainDescriptorsSha256 { get; }
    public ulong RollbackIndex { get; }
    public uint RollbackIndexLocation { get; }
    public uint Flags { get; }
}
