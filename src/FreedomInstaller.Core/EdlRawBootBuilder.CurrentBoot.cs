// BM04: actual format orchestration for the default-only current-boot menu
// repack shared by uninstall. Everything stays inside the existing builder
// partial so the private HeldLease, AVB node and envelope metadata helpers
// remain usable without new public surfaces. This partial performs no device
// I/O, never writes a partition target and makes no OEM or OS acceptance
// claim; every output is a derived fact of the files it staged itself.
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
using FreedomInstaller.Core.Gbl;

namespace FreedomInstaller.Core;

// --------------------------------------------------------------- shared facts

/// <summary>Captured efisp region facts the GBL route requires to exist.</summary>
internal sealed record CurrentBootEfispFacts(
    int Lun,
    long SectorCount,
    int SectorSize,
    long Length,
    string Sha256);

/// <summary>Factual evidence recorded when the GBL preserve route was selected.</summary>
internal sealed record CurrentBootGblFacts(
    int EfispLun,
    long EfispBytes,
    string AblSha256,
    string XblConfigSha256,
    string LoaderEvidence);

/// <summary>Factual evidence recorded when the stock verifier accepted a slot.</summary>
internal sealed record CurrentBootStockFacts(
    long ImageSize,
    string Digest,
    string BootPublicKeySha256,
    string RootPublicKeySha256);

/// <summary>
/// One slot's inputs: all claims plus this plan's own staged paths. The
/// trailing optional facts are required by the default-only menu operation
/// (sealed source authority, actual source material, proven source raw bound
/// and the real source slot) and are left null-compatible for existing
/// positional constructors elsewhere.
/// </summary>
internal sealed record CurrentBootSlotInputs(
    string Slot,
    VerifiedEdlFile Boot,
    VerifiedEdlFile VendorBoot,
    VerifiedEdlFile InitBoot,
    VerifiedEdlFile Abl,
    VerifiedEdlFile XblConfig,
    VerifiedEdlFile Vbmeta,
    CurrentBootEfispFacts? Efisp,
    EdlRawBootTools Tools,
    ICommandRunner Runner,
    string WorkDirectory,
    string BaseImagePath,
    string OriginalRawPath,
    string ChangedRawPath,
    string UnpackedOriginalDirectoryName,
    string UnpackedChangedDirectoryName,
    string CandidatePath,
    InternalSlotMaterial? SourceMaterial = null,
    InternalInstallPreparationContext.TfBootAuthority? Authority = null,
    long? ProvenMaxRawBytes = null,
    string? SourceSlot = null);

/// <summary>One slot's derived facts; every value observes files this call staged.</summary>
internal sealed record CurrentBootSlotWork(
    string Slot,
    string SourceSlot,
    BootMaintenanceSourceKind SourceKind,
    BootMaintenanceBootTrust BootTrustMode,
    VerifiedEdlFile Original,
    VerifiedEdlFile? Candidate,
    IReadOnlyDictionary<string, string> PayloadSha256,
    string? OriginalMetadataSha256,
    bool PayloadDigestMatchesOem,
    uint DefaultIndexBefore,
    uint DefaultIndexAfter,
    long DefaultCellOffset,
    uint DefaultCellValueBefore,
    uint DefaultCellValueAfter,
    bool OnlyDefaultCellChanged,
    string BudgetProfile,
    long BudgetMaxRawBytes,
    CurrentBootGblFacts? Gbl,
    CurrentBootStockFacts? Stock);

public static partial class EdlRawBootBuilder
{
    private const int CurrentBootMaxLoaderBytes = 32 * 1024 * 1024;

    private const uint CurrentBootMaxMenuEntries = 64u;

    // ------------------------------------------------------ emptiness probe

    /// <summary>True only when the verified boot file is entirely zero bytes.</summary>
    internal static Task<bool> CurrentBootDetectEmptyAsync(VerifiedEdlFile boot, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(boot);
        ct.ThrowIfCancellationRequested();
        return Task.Run(() => CurrentBootDetectEmpty(boot, ct), ct);
    }

    private static bool CurrentBootDetectEmpty(VerifiedEdlFile boot, CancellationToken ct)
    {
        using FileStream stream = OpenRead(boot.Path, "boot emptiness probe");
        VerifyClaim(stream, boot, "boot emptiness probe", ct);
        stream.Position = 0;

        byte[] buffer = new byte[CopyChunkBytes];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            for (int index = 0; index < read; index++)
            {
                if (buffer[index] != 0)
                {
                    return false;
                }
            }
        }

        return true;
    }

    // -------------------------------------------------- target raw measurement

    /// <summary>
    /// Measures one actual TARGET boot's real raw length. The claim is opened and
    /// whole-verified and the one-source protocol gate runs; a stock same-slot
    /// target returns its actual exported base image length while any project
    /// target is decoded under the shared 256 MiB kernel bound to its real raw
    /// length. No fake sentinel, no partition length and no caller budget is used.
    /// </summary>
    internal static Task<long> CurrentBootMeasureTargetRawBytesAsync(
        VerifiedEdlFile targetBoot,
        InternalSlotMaterial sourceMaterial,
        bool targetIsSource,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targetBoot);
        ArgumentNullException.ThrowIfNull(sourceMaterial);
        ct.ThrowIfCancellationRequested();
        return Task.Run(
            () =>
            {
                HeldLease boot = OpenClaimLease("target boot raw measurement", targetBoot, ct);
                try
                {
                    RequireProtocolOneSourceBoot(boot, ct);

                    if (targetIsSource && !sourceMaterial.IsKshim)
                    {
                        if (sourceMaterial.BaseImageLength <= 0)
                        {
                            throw new InvalidDataException(
                                "the stock source base image length is not positive");
                        }

                        return sourceMaterial.BaseImageLength;
                    }

                    (byte[] raw, _) = CurrentBootDecodeComposite(boot.Stream, MaxOriginalKernelBytes, ct);
                    return raw.LongLength;
                }
                finally
                {
                    CloseQuietly(boot.Stream);
                }
            },
            ct);
    }

    // --------------------------------------------------------- slot process

    internal static Task<CurrentBootSlotWork> CurrentBootPrepareSlotAsync(
        CurrentBootSlotInputs inputs,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ct.ThrowIfCancellationRequested();
        return Task.Run(() => CurrentBootPrepareSlotCore(inputs, ct), ct);
    }

    private static CurrentBootSlotWork CurrentBootPrepareSlotCore(
        CurrentBootSlotInputs inputs,
        CancellationToken ct)
    {
        // Menu-only operation: the sealed authority, the actual source material
        // and the proven source raw bound are required facts, never optional.
        InternalInstallPreparationContext.TfBootAuthority authority = inputs.Authority
            ?? throw new ArgumentException(
                "current boot menu preparation requires the sealed boot authority.",
                nameof(inputs));
        InternalSlotMaterial material = inputs.SourceMaterial
            ?? throw new ArgumentException(
                "current boot menu preparation requires the actual source slot material.",
                nameof(inputs));
        string sourceSlot = inputs.SourceSlot
            ?? throw new ArgumentException(
                "current boot menu preparation requires the real source slot.",
                nameof(inputs));
        long budget = inputs.ProvenMaxRawBytes
            ?? throw new ArgumentException(
                "current boot menu preparation requires the proven source raw bound.",
                nameof(inputs));

        if (!authority.SourceSlots.TryGetValue(inputs.Slot, out string? mappedSource) ||
            !string.Equals(mappedSource, sourceSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "current boot target '" + inputs.Slot
                + "' does not map to the claimed source slot '" + sourceSlot
                + "' in the sealed authority.");
        }

        if (!string.Equals(material.Slot, sourceSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "current boot material reports slot '" + material.Slot
                + "' instead of its claimed source '" + sourceSlot + "'.");
        }

        if (budget <= 0 || budget > material.LoaderBudget.MaxRawBytes)
        {
            throw new InvalidDataException(
                "the proven raw bound is not positive inside the source loader budget");
        }

        var leases = new List<HeldLease>();
        try
        {
            // The boot claim is the actual TARGET boot; every companion claim is
            // the actual SOURCE capture. All own read leases continue.
            HeldLease boot = OpenClaimLease("boot_" + inputs.Slot, inputs.Boot, ct);
            leases.Add(boot);
            HeldLease vendor = OpenClaimLease("vendor_boot_" + sourceSlot, inputs.VendorBoot, ct);
            leases.Add(vendor);
            HeldLease init = OpenClaimLease("init_boot_" + sourceSlot, inputs.InitBoot, ct);
            leases.Add(init);
            HeldLease abl = OpenClaimLease("abl_" + sourceSlot, inputs.Abl, ct);
            leases.Add(abl);
            HeldLease xbl = OpenClaimLease("xbl_config_" + sourceSlot, inputs.XblConfig, ct);
            leases.Add(xbl);
            HeldLease vbmeta = OpenClaimLease("vbmeta_" + sourceSlot, inputs.Vbmeta, ct);
            leases.Add(vbmeta);

            RequireProtocolOneSourceBoot(boot, ct);

            // Leaf authentication reads the signed image size from the descriptor
            // inside the authenticated blob, never from the rewritten footer. A
            // stale physical digest is routed below, never silently accepted.
            CurrentBootLeafFacts leaf = CurrentBootReadLeafFacts(boot.Stream, boot.Claim.Length, ct);

            // A stock target keeps its own factory image: target equals source and
            // the material carries no project composite. The real stock verifier
            // authenticates the boot and its source root; the physical digest must
            // genuinely match. No candidate exists.
            if (string.Equals(inputs.Slot, sourceSlot, StringComparison.Ordinal) &&
                !material.IsKshim)
            {
                if (!leaf.DigestMatches)
                {
                    throw new InvalidDataException(
                        "stock current boot payload digest does not match its own signed metadata");
                }

                BootStockOriginalFacts stock = VerifyStockOriginalBootAsync(
                    inputs.Boot, inputs.Vbmeta, ct).GetAwaiter().GetResult();
                return new CurrentBootSlotWork(
                    inputs.Slot,
                    sourceSlot,
                    BootMaintenanceSourceKind.StockOriginal,
                    BootMaintenanceBootTrust.StockOriginal,
                    inputs.Boot,
                    null,
                    CurrentBootEmptyPayload(),
                    leaf.BlobSha256,
                    true,
                    0u,
                    0u,
                    0,
                    0u,
                    0u,
                    false,
                    material.LoaderBudget.Profile,
                    budget,
                    null,
                    new CurrentBootStockFacts(
                        stock.ImageSize,
                        stock.Digest,
                        stock.BootPublicKeySha256,
                        stock.RootPublicKeySha256));
            }

            // Trust is chosen through the sealed authority before any default-cell
            // work, so an already-default composite still refuses an untrusted
            // route. There is no weak root-main-only guess here.
            bool usesGbl = authority.UsesGbl;
            CurrentBootGblFacts? gbl;
            if (usesGbl)
            {
                // The authority already ran the real GBL efisp, loader and runtime
                // common-window gates; the parent boot-child key equality remains.
                // A stale leaf physical digest is legal only on this route and is
                // reported truthfully below, never labelled verified.
                string parentKey = authority.RequireGblParentBootKey(sourceSlot);
                if (!CurrentBootSameHex(parentKey, leaf.KeySha256))
                {
                    throw new InvalidDataException(
                        "gbl-parent-leaf-key-mismatch: the authenticated parent boot chain does not bind the target boot leaf key.");
                }

                gbl = CurrentBootDeriveGblFacts(authority, ct);
            }
            else
            {
                EdlRawOriginalBootChainFacts chain = AuthenticateOriginalBootChainAsync(
                    inputs.Vbmeta, ct).GetAwaiter().GetResult();
                if (!CurrentBootSameHex(chain.PublicKeySha256, SigningPublicKeySha256) ||
                    !CurrentBootSameHex(chain.BootChainPublicKeySha256, SigningPublicKeySha256) ||
                    !CurrentBootSameHex(leaf.KeySha256, SigningPublicKeySha256))
                {
                    throw new InvalidDataException(
                        "aosp-pin-mismatch: the authenticated root, its boot chain and the boot leaf must all carry the pinned AOSP key.");
                }

                if (!leaf.DigestMatches)
                {
                    throw new InvalidDataException(
                        "aosp boot leaf payload digest does not match its signed descriptor");
                }

                gbl = null;
            }

            // Preserve the CURRENT whole TARGET composite before any derived work.
            (byte[] raw, string rawSha) = CurrentBootDecodeComposite(boot.Stream, budget, ct);
            WriteNewFile(inputs.OriginalRawPath, raw, "preserved current composite", ct);
            string rawFileSha = HashFileSha256(inputs.OriginalRawPath, ct);
            if (!string.Equals(rawFileSha, rawSha, StringComparison.Ordinal))
            {
                throw new InvalidDataException("preserved current composite changed on disk");
            }

            CurrentBootMenuFacts menu = CurrentBootParseMenu(raw, ct);

            if (menu.DefaultBefore == 0u)
            {
                // Already android-default: no destructive change and no candidate.
                // Every trust gate above has already run; the digest fact below is
                // the actual observed truth, never a hard true.
                BootMaintenanceBootTrust trust = usesGbl
                    ? BootMaintenanceBootTrust.GblPreserveOem
                    : BootMaintenanceBootTrust.AospResigned;
                return new CurrentBootSlotWork(
                    inputs.Slot,
                    sourceSlot,
                    BootMaintenanceSourceKind.Project,
                    trust,
                    inputs.Boot,
                    null,
                    CurrentBootEmptyPayload(),
                    leaf.BlobSha256,
                    leaf.DigestMatches,
                    0u,
                    0u,
                    0,
                    0u,
                    0u,
                    false,
                    material.LoaderBudget.Profile,
                    budget,
                    gbl,
                    null);
            }

            byte[] changed = CurrentBootPatchDefaultCell(raw, menu, ct);
            WriteNewFile(inputs.ChangedRawPath, changed, "default-patched composite", ct);
            string changedSha = HashFileSha256(inputs.ChangedRawPath, ct);

            string originalDir = Path.Combine(
                inputs.WorkDirectory, inputs.UnpackedOriginalDirectoryName);
            string changedDir = Path.Combine(
                inputs.WorkDirectory, inputs.UnpackedChangedDirectoryName);

            RunNativeAsync(
                    inputs.Runner,
                    inputs.Tools.Unpacker.Path,
                    new[] { Path.GetFileName(inputs.OriginalRawPath), inputs.UnpackedOriginalDirectoryName },
                    inputs.WorkDirectory,
                    "current boot original unpack step",
                    ct)
                .GetAwaiter()
                .GetResult();

            RunNativeAsync(
                    inputs.Runner,
                    inputs.Tools.Unpacker.Path,
                    new[] { Path.GetFileName(inputs.ChangedRawPath), inputs.UnpackedChangedDirectoryName },
                    inputs.WorkDirectory,
                    "current boot patched unpack step",
                    ct)
                .GetAwaiter()
                .GetResult();

            CurrentBootCompareUnpacked(
                originalDir,
                changedDir,
                menu.DefaultBefore,
                ct);

            IReadOnlyDictionary<string, string> payloadSha =
                CurrentBootHashUnpackedPayloads(originalDir, ct);

            var changedClaim = new VerifiedEdlFile(inputs.ChangedRawPath, changed.LongLength, changedSha);

            VerifiedEdlFile candidate;
            BootMaintenanceBootTrust trustMode;
            bool payloadDigestMatchesOem;

            if (usesGbl)
            {
                // The GBL route uses the green envelope repack directly: it
                // authenticates and moves the OEM metadata preserving signed-size
                // semantics. No intermediate AOSP envelope is ever generated and
                // the old OEM-preserve-over-envelope path is never used here.
                CurrentBootGblPreserved preserved = RepackCurrentGblEnvelopeAsync(
                    inputs.Boot, changedClaim, budget, inputs.CandidatePath, ct)
                    .GetAwaiter()
                    .GetResult();
                candidate = preserved.Candidate;
                trustMode = BootMaintenanceBootTrust.GblPreserveOem;
                payloadDigestMatchesOem = preserved.Facts.ContentDigestMatches;
            }
            else
            {
                // The pinned AOSP route re-signs with the pinned key; the boot-only
                // change keeps every existing chain descriptor valid.
                EdlRawBootEnvelope envelope = RepackEnvelopeAsync(
                    inputs.Boot, changedClaim, budget, inputs.CandidatePath, ct)
                    .GetAwaiter()
                    .GetResult();
                candidate = envelope.CandidateBoot;
                trustMode = BootMaintenanceBootTrust.AospResigned;
                payloadDigestMatchesOem = false;
            }

            if (candidate.Length != inputs.Boot.Length)
            {
                throw new InvalidDataException(
                    "the prepared candidate length differs from the original target boot length");
            }

            return new CurrentBootSlotWork(
                inputs.Slot,
                sourceSlot,
                BootMaintenanceSourceKind.Project,
                trustMode,
                inputs.Boot,
                candidate,
                payloadSha,
                leaf.BlobSha256,
                payloadDigestMatchesOem,
                menu.DefaultBefore,
                0u,
                menu.DefaultCellOffset,
                menu.DefaultBefore,
                0u,
                true,
                material.LoaderBudget.Profile,
                budget,
                gbl,
                null);
        }
        finally
        {
            foreach (HeldLease lease in leases)
            {
                CloseQuietly(lease.Stream);
            }
        }
    }

    // -------------------------------------------------------- leaf metadata

    private sealed record CurrentBootLeafFacts(
        string BlobSha256,
        string KeySha256,
        bool DigestMatches,
        long ImageSize,
        string DigestHex);

    private static CurrentBootLeafFacts CurrentBootReadLeafFacts(
        FileStream stream,
        long partitionBytes,
        CancellationToken ct)
    {
        stream.Position = 0;
        AvbNodeMetadata leafMeta = AvbNodeReadFooterLeafMetadata(stream, partitionBytes, ct);

        // The signed image size comes only from the hash descriptor inside the
        // authenticated blob, never from the rewritten footer at +12.
        long signedSize = CurrentBootSignedImageSize(leafMeta);

        var parsed = ParseVbmeta(
            stream, leafMeta.VbmetaOffset, leafMeta.VbmetaSize, signedSize, ct);
        string effective = ComputeSaltedDigest(
            stream,
            parsed.Hash.Salt,
            parsed.Hash.ImageSize,
            HashNameFor(parsed.Hash.Algorithm),
            ct);

        bool matches = string.Equals(
            effective, ToHex(parsed.Hash.Digest), StringComparison.OrdinalIgnoreCase);
        return new CurrentBootLeafFacts(
            AvbNodeSha256Hex(leafMeta.Blob),
            leafMeta.SourcePublicKeySha256,
            matches,
            parsed.Hash.ImageSize,
            ToHex(parsed.Hash.Digest));
    }

    private static BootMaintenanceBootTrust CurrentBootRootTrust(
        FileStream vbmetaStream,
        long partitionBytes,
        CancellationToken ct)
    {
        vbmetaStream.Position = 0;
        AvbNodeMetadata metadata = AvbNodeReadMetadata(
            vbmetaStream, EdlRawAvbNodeKind.Vbmeta, partitionBytes, ct);

        return CurrentBootSameHex(metadata.SourcePublicKeySha256, AvbPublicKeySha256)
            ? BootMaintenanceBootTrust.AospResigned
            : BootMaintenanceBootTrust.GblPreserveOem;
    }

    // --------------------------------------------------- composite handling

    private static (byte[] Raw, string Sha256) CurrentBootDecodeComposite(
        FileStream stream,
        long budget,
        CancellationToken ct)
    {
        stream.Position = 0;
        byte[] header = new byte[BootHeaderBytes];
        ReadExactly(stream, header, 0, header.Length);

        long kernelSize = ReadLeU32(header, 8);
        long limit = Math.Min(budget, MaxOriginalKernelBytes);
        if (kernelSize <= 0 || kernelSize > limit)
        {
            throw new InvalidDataException(
                "current boot kernel length is outside the bounded composite window");
        }

        byte[] kernel = new byte[kernelSize];
        ReadExactly(stream, kernel, BootHeaderBytes, kernel.Length);

        byte[] raw = kernel;
        if (kernel.Length >= 2 && kernel[0] == 0x1F && kernel[1] == 0x8B)
        {
            raw = CurrentBootInflate(kernel, limit, ct);
        }

        if (raw.LongLength > limit)
        {
            throw new InvalidDataException("current composite exceeds the measured loader budget");
        }

        RequireArm64Header(raw, "current composite");
        if (ReadLeU64(raw, Arm64ImageSizeField) != (ulong)raw.LongLength)
        {
            throw new InvalidDataException("current composite image_size does not equal its decoded length");
        }

        ulong shimOffset = ReadLeU64(raw, Arm64ShimOffsetField);
        if (shimOffset == 0 || shimOffset % 4 != 0 || shimOffset >= (ulong)BranchSignedRange)
        {
            throw new InvalidDataException("current composite shim offset is not a positive in-range target");
        }

        uint word0 = ReadLeU32(raw, 0);
        if ((word0 & BranchOpcodeMask) != BranchLinkOpcode ||
            ResolveBranchTarget(word0) != (long)shimOffset)
        {
            throw new InvalidDataException("current composite first instruction does not branch to the shim");
        }

        ulong manifestOffset = ReadLeU64(raw, Arm64ManifestOffsetField);
        ulong manifestSize = ReadLeU64(raw, Arm64ManifestSizeField);
        if (manifestOffset < (ulong)Arm64HeaderProbeBytes ||
            manifestSize < (ulong)ManifestHeaderBytes ||
            manifestOffset > (ulong)raw.LongLength ||
            manifestSize > (ulong)raw.LongLength - manifestOffset ||
            manifestOffset + manifestSize != (ulong)raw.LongLength)
        {
            throw new InvalidDataException("current composite manifest does not end exactly at the image end");
        }

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(raw);
        return (raw, ToHex(hash.GetHashAndReset()));
    }

    private static byte[] CurrentBootInflate(byte[] kernel, long limit, CancellationToken ct)
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
            if (total > limit)
            {
                throw new InvalidDataException("current composite exceeds the bounded decode limit");
            }

            inflated.Write(buffer, 0, read);
        }

        if (total == 0)
        {
            throw new InvalidDataException("current composite gzip decoded to no bytes");
        }

        return inflated.ToArray();
    }

    // ------------------------------------------------------ menu manifest

    private sealed class CurrentBootMenuFacts
    {
        internal uint EntryCount;
        internal uint DefaultBefore;
        internal long ManifestOffset;
        internal long DefaultCellOffset;
        internal IReadOnlyList<string> EntryNames = Array.Empty<string>();
    }

    private static CurrentBootMenuFacts CurrentBootParseMenu(byte[] raw, CancellationToken ct)
    {
        int length = raw.Length;
        int mo = (int)ReadLeU64(raw, Arm64ManifestOffsetField);

        if (ReadLeU32(raw, mo) != ManifestMagic)
        {
            throw new InvalidDataException("current menu manifest magic is not the recognized KPMF value");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(mo + 4, 2)) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(mo + 6, 2)) != 1)
        {
            throw new InvalidDataException("current menu manifest version is not 0.1");
        }

        uint count = ReadLeU32(raw, mo + 8);
        uint defaultBefore = ReadLeU32(raw, mo + 12);
        uint timeout = ReadLeU32(raw, mo + 16);

        if (count < ManifestEntryCount || count > CurrentBootMaxMenuEntries)
        {
            throw new InvalidDataException(
                "current menu manifest entry count " + count.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + " is outside the supported recognized range");
        }

        if (defaultBefore >= count)
        {
            throw new InvalidDataException("current menu default index is outside the entry table");
        }

        if (timeout != ManifestTimeoutMillis)
        {
            throw new InvalidDataException("current menu timeout is not the preserved 8000 ms value");
        }

        var names = new List<string>((int)count);
        int cursor = mo + ManifestHeaderBytes;

        for (uint index = 0; index < count; index++)
        {
            ct.ThrowIfCancellationRequested();

            if (cursor < 0 || cursor > length - StockManifestEntryBytes)
            {
                throw new InvalidDataException("current menu entry record runs past the manifest table");
            }

            ulong eOffset = ReadLeU64(raw, cursor);
            ulong eSize = ReadLeU64(raw, cursor + 8);
            uint eType = ReadLeU32(raw, cursor + 16);
            uint eFlags = ReadLeU32(raw, cursor + 20);
            ulong eLoad = ReadLeU64(raw, cursor + 24);
            uint eEntry = ReadLeU32(raw, cursor + 32);
            ulong eCopy = ReadLeU64(raw, cursor + 44);
            uint nameLength = ReadLeU32(raw, cursor + 52);

            if (nameLength > StockManifestNameLimit)
            {
                throw new InvalidDataException("current menu entry name length is out of range");
            }

            long nameStart = cursor + StockManifestEntryBytes;
            long unpadded = StockManifestEntryBytes + nameLength;
            long recordEnd = cursor + ((unpadded + StockManifestRecordAlignment - 1)
                & ~(long)(StockManifestRecordAlignment - 1));

            if (recordEnd > length)
            {
                throw new InvalidDataException("current menu entry record runs past the manifest table");
            }

            for (long pad = nameStart + nameLength; pad < recordEnd; pad++)
            {
                if (raw[pad] != 0)
                {
                    throw new InvalidDataException("current menu entry name padding is not zero");
                }
            }

            string name;
            try
            {
                name = ConfigUtf8.GetString(raw.AsSpan((int)nameStart, (int)nameLength));
            }
            catch (DecoderFallbackException ex)
            {
                throw new InvalidDataException("current menu entry name is not valid UTF-8", ex);
            }

            foreach (char character in name)
            {
                if (char.IsControl(character))
                {
                    throw new InvalidDataException(
                        "current menu entry name contains an embedded control character");
                }
            }

            if (index == 0u)
            {
                if (eType != 1u || eFlags != 5u)
                {
                    throw new InvalidDataException(
                        "the android base entry at index 0 is not a Linux base+exec entry");
                }

                if (eOffset != 0 || eSize < (ulong)Arm64HeaderProbeBytes ||
                    eLoad != 0 || eEntry != 0 || eCopy != 0)
                {
                    throw new InvalidDataException("the android base payload is not a plain base entry at index 0");
                }
            }
            else if ((eFlags & 1u) != 0u)
            {
                throw new InvalidDataException("a non-base menu entry carries the reserved base flag");
            }

            names.Add(name);
            cursor = (int)recordEnd;
        }

        if (cursor != length)
        {
            throw new InvalidDataException("current menu entry table does not exactly fill the manifest");
        }

        return new CurrentBootMenuFacts
        {
            EntryCount = count,
            DefaultBefore = defaultBefore,
            ManifestOffset = mo,
            DefaultCellOffset = mo + 12,
            EntryNames = names,
        };
    }

    private static byte[] CurrentBootPatchDefaultCell(
        byte[] raw,
        CurrentBootMenuFacts menu,
        CancellationToken ct)
    {
        long cellOffset = menu.DefaultCellOffset;
        if (cellOffset < 0 || cellOffset > raw.Length - 4)
        {
            throw new InvalidDataException("the menu default cell does not fit inside the raw image");
        }

        int offset = checked((int)cellOffset);

        uint originalDefault = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset, 4));
        if (originalDefault != menu.DefaultBefore)
        {
            throw new InvalidDataException(
                "the raw default cell does not match the parsed manifest default index");
        }

        byte[] changed = (byte[])raw.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(offset, 4), 0u);

        int differences = 0;
        for (int index = 0; index < raw.Length; index++)
        {
            if ((index & 0xFFFFF) == 0)
            {
                ct.ThrowIfCancellationRequested();
            }

            if (raw[index] != changed[index])
            {
                differences++;
                if (index < offset || index >= offset + 4)
                {
                    throw new InvalidDataException(
                        "the patched composite changed a byte outside the default cell");
                }
            }
        }

        if (originalDefault != 0u && (differences < 1 || differences > 4))
        {
            throw new InvalidDataException(
                "the patched composite changed something other than the nonzero default cell");
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(changed.AsSpan(offset, 4)) != 0u)
        {
            throw new InvalidDataException("the patched default cell is not zero");
        }

        return changed;
    }

    // ------------------------------------------------------- unpack compare

    private static void CurrentBootCompareUnpacked(
        string originalDir,
        string changedDir,
        uint defaultBefore,
        CancellationToken ct)
    {
        string[] originalLines = CurrentBootReadConfigLines(
            Path.Combine(originalDir, UnpackedConfigFileName), ct);
        string[] changedLines = CurrentBootReadConfigLines(
            Path.Combine(changedDir, UnpackedConfigFileName), ct);

        if (originalLines.Length != changedLines.Length)
        {
            throw new InvalidDataException("unpacked configs differ in line count");
        }

        int diffIndex = -1;
        for (int index = 0; index < originalLines.Length; index++)
        {
            if (string.Equals(originalLines[index], changedLines[index], StringComparison.Ordinal))
            {
                continue;
            }

            if (diffIndex >= 0)
            {
                throw new InvalidDataException("unpacked configs differ in more than one line");
            }

            diffIndex = index;
        }

        if (diffIndex < 0)
        {
            throw new InvalidDataException(
                "unpacked configs are identical; the default patch did not reach the config");
        }

        const string defaultPrefix = "Default=";
        if (!originalLines[diffIndex].StartsWith(defaultPrefix, StringComparison.Ordinal) ||
            !changedLines[diffIndex].StartsWith(defaultPrefix, StringComparison.Ordinal))
        {
            throw new InvalidDataException("the only unpacked config difference is not the Default line");
        }

        string originalDefault = originalLines[diffIndex].Substring(defaultPrefix.Length);
        string changedDefault = changedLines[diffIndex].Substring(defaultPrefix.Length);

        string expectedOriginalDefault = "Image-"
            + defaultBefore.ToString("D2", System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(originalDefault, expectedOriginalDefault, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "the original unpacked config default does not match the manifest default entry name");
        }

        if (!string.Equals(changedDefault, "Image-00", StringComparison.Ordinal))
        {
            throw new InvalidDataException("the patched unpacked config default is not the android base entry");
        }

        Dictionary<string, (long Length, string Sha256)> originalFiles =
            CurrentBootHashUnpacked(originalDir, ct);
        Dictionary<string, (long Length, string Sha256)> changedFiles =
            CurrentBootHashUnpacked(changedDir, ct);

        if (originalFiles.Count != changedFiles.Count)
        {
            throw new InvalidDataException(
                "the original and patched unpacks carry different payload file counts");
        }

        foreach (KeyValuePair<string, (long Length, string Sha256)> entry in originalFiles)
        {
            if (!changedFiles.TryGetValue(entry.Key, out (long Length, string Sha256) changedFile))
            {
                throw new InvalidDataException("the patched unpack is missing payload file '" + entry.Key + "'");
            }

            if (entry.Value.Length != changedFile.Length ||
                !string.Equals(entry.Value.Sha256, changedFile.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "payload file '" + entry.Key + "' differs between the original and patched unpacks");
            }
        }
    }

    private static string[] CurrentBootReadConfigLines(string path, CancellationToken ct)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length <= 0 || file.Length > ConfigBytesLimit)
        {
            throw new InvalidDataException("an unpacked config.cfg is missing or outside the bounded range");
        }

        string text;
        try
        {
            text = ConfigUtf8.GetString(File.ReadAllBytes(path));
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("an unpacked config.cfg is not valid UTF-8");
        }

        if (text.Length > 0 && text[0] == '\uFEFF')
        {
            text = text.Substring(1);
        }

        return text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
    }

    private static Dictionary<string, (long Length, string Sha256)> CurrentBootHashUnpacked(
        string directory,
        CancellationToken ct)
    {
        var files = new Dictionary<string, (long Length, string Sha256)>(StringComparer.Ordinal);
        foreach (string path in Directory.EnumerateFiles(directory))
        {
            ct.ThrowIfCancellationRequested();

            string name = Path.GetFileName(path);
            if (string.Equals(name, UnpackedConfigFileName, StringComparison.Ordinal))
            {
                continue;
            }

            if (files.ContainsKey(name))
            {
                throw new InvalidDataException("an unpacked directory repeats payload name '" + name + "'");
            }

            using FileStream stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            files.Add(name, (stream.Length, HashStreamSha256(stream, ct)));
        }

        return files;
    }

    private static IReadOnlyDictionary<string, string> CurrentBootHashUnpackedPayloads(
        string directory,
        CancellationToken ct)
    {
        Dictionary<string, (long Length, string Sha256)> files = CurrentBootHashUnpacked(directory, ct);
        var payload = new Dictionary<string, string>(files.Count, StringComparer.Ordinal);
        foreach (KeyValuePair<string, (long Length, string Sha256)> entry in files)
        {
            payload.Add(entry.Key, entry.Value.Sha256);
        }

        return new ReadOnlyDictionary<string, string>(payload);
    }

    private static IReadOnlyDictionary<string, string> CurrentBootEmptyPayload() =>
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal));

    // ------------------------------------------------------------ GBL gates

    private static void CurrentBootValidateEfispRegion(CurrentBootEfispFacts efisp)
    {
        if (efisp.Lun != 4 || efisp.SectorSize <= 0 || efisp.SectorCount <= 0 ||
            efisp.Length != checked(efisp.SectorCount * efisp.SectorSize))
        {
            throw new InvalidOperationException(
                "requires-complete-backup-with-efisp: the captured efisp region is not a complete LUN4 extent.");
        }
    }

    private static byte[] CurrentBootReadBounded(
        FileStream stream,
        long limit,
        string subject,
        CancellationToken ct)
    {
        if (stream.Length <= 0 || stream.Length > limit)
        {
            throw new InvalidDataException(subject + " length is outside the bounded analysis window");
        }

        byte[] bytes = new byte[(int)stream.Length];
        stream.Position = 0;
        ReadExactly(stream, bytes, 0, bytes.Length);
        ct.ThrowIfCancellationRequested();
        return bytes;
    }

    private static bool CurrentBootSameHex(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    // Derives the factual GBL facts of one menu slot purely from the sealed
    // authority's captured evidence: its captured efisp region, the runtime
    // selected source's authenticated ABL capture hash, the CURRENT slot's
    // captured xbl_config hash and the common loader window evidence. No target
    // or source XBL capture is substituted for the current one, and no fact is
    // fabricated beyond what the authority itself captured.
    private static CurrentBootGblFacts CurrentBootDeriveGblFacts(
        InternalInstallPreparationContext.TfBootAuthority authority,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        EdlCapturedRegion? efisp = authority.EfispTarget;
        if (efisp is null)
        {
            throw new InvalidOperationException(
                "requires-complete-backup-with-efisp: the GBL authority carries no captured efisp region.");
        }

        string selectedSource = authority.RuntimeSelectedSourceSlot
            ?? throw new InvalidOperationException(
                "requires-compatible-bootloader: the GBL authority reports no runtime selected source slot.");
        if (!authority.Files.TryGetValue("abl_" + selectedSource, out EdlCapturedRegion ablCapture))
        {
            throw new InvalidDataException(
                "gbl-facts-unknown-capture: the authority holds no captured abl for the runtime selected source '"
                + selectedSource + "'.");
        }

        string currentSlot = authority.CurrentSlot;
        if (!authority.Files.TryGetValue("xbl_config_" + currentSlot, out EdlCapturedRegion xblCapture))
        {
            throw new InvalidDataException(
                "gbl-facts-unknown-capture: the authority holds no captured xbl_config for the current slot '"
                + currentSlot + "'.");
        }

        string loaderEvidence = authority.CommonLoaderEvidence
            ?? throw new InvalidOperationException(
                "requires-compatible-bootloader: the GBL authority carries no common loader window evidence.");

        return new CurrentBootGblFacts(
            efisp.Lun,
            efisp.Length,
            ablCapture.Sha256,
            xblCapture.Sha256,
            loaderEvidence);
    }

    // --------------------------------------------------- GBL OEM preserve

    internal sealed record CurrentBootGblPreserved(
        VerifiedEdlFile Candidate,
        EdlRawOriginalBootSignatureFacts Facts,
        long PayloadBytes,
        string PayloadSha256,
        long VbmetaOffset,
        long VbmetaBytes);

    // Copies the authenticated original OEM vbmeta blob over the NEW AOSP
    // envelope's metadata location, retargets only the source-built footer to
    // the new payload boundary and blob size, then re-reads and verifies the
    // physical output. The payload digest against the OEM metadata is
    // deliberately stale and is reported as a separate fact.
    private static CurrentBootGblPreserved CurrentBootPreserveOem(
        VerifiedEdlFile originalBoot,
        EdlRawBootEnvelope envelope,
        string candidatePath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            throw new ArgumentException("Candidate path is required.", nameof(candidatePath));
        }

        ct.ThrowIfCancellationRequested();
        candidatePath = Path.GetFullPath(candidatePath);

        return CurrentBootPreserveOemCore(originalBoot, envelope, candidatePath, ct);
    }

    private static CurrentBootGblPreserved CurrentBootPreserveOemCore(
        VerifiedEdlFile originalBoot,
        EdlRawBootEnvelope envelope,
        string candidatePath,
        CancellationToken ct)
    {
        bool candidateCreated = false;
        bool completed = false;

        try
        {
            using FileStream original = new FileStream(
                Path.GetFullPath(originalBoot.Path),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
            VerifyClaim(original, originalBoot, "GBL original boot", ct);

            using FileStream sourceCandidate = new FileStream(
                Path.GetFullPath(envelope.CandidateBoot.Path),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
            VerifyClaim(sourceCandidate, envelope.CandidateBoot, "GBL source built boot", ct);

            long partitionLength = original.Length;
            if (sourceCandidate.Length != partitionLength)
            {
                throw new InvalidDataException("GBL source built boot length differs from the original boot partition.");
            }

            AvbNodeMetadata originalMeta = AvbNodeReadFooterLeafMetadata(original, partitionLength, ct);
            string originalBlobSha256 = AvbNodeSha256Hex(originalMeta.Blob);

            if (!string.Equals(
                    originalBlobSha256,
                    envelope.SourceEmbeddedVbmetaSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL original boot metadata does not match the envelope binding.");
            }

            AvbNodeMetadata sourceMeta = AvbNodeReadFooterLeafMetadata(sourceCandidate, partitionLength, ct);

            if (!string.Equals(
                    sourceMeta.SourcePublicKeySha256,
                    AvbPublicKeySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("GBL source built boot does not carry the pinned AOSP public key.");
            }

            long newPayloadBytes = envelope.OriginalImageSize;
            long newVbmetaOffset = envelope.VbmetaOffset;
            long newVbmetaBytes = envelope.VbmetaBytes;

            byte[] sourceFooter = new byte[AvbFooterBytes];
            ReadExactly(sourceCandidate, sourceFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);

            if (ReadBeU64(sourceFooter, 12) != (ulong)newPayloadBytes ||
                ReadBeU64(sourceFooter, 20) != (ulong)newVbmetaOffset ||
                ReadBeU64(sourceFooter, 28) != (ulong)newVbmetaBytes)
            {
                throw new InvalidDataException("GBL source built boot footer does not match the recorded envelope.");
            }

            if (sourceMeta.VbmetaOffset != newVbmetaOffset || sourceMeta.VbmetaSize != newVbmetaBytes)
            {
                throw new InvalidDataException(
                    "GBL source built boot metadata geometry does not match the recorded envelope.");
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

            byte[] originalFooter = new byte[AvbFooterBytes];
            ReadExactly(original, originalFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);
            long originalImageSize = (long)ReadBeU64(originalFooter, 12);

            var originalParsed = ParseVbmeta(
                original, originalMeta.VbmetaOffset, originalMeta.VbmetaSize, originalImageSize, ct);

            string expectedPayloadSha256 = HashRangeSha256(sourceCandidate, 0, newPayloadBytes, ct);

            byte[] expectedFooter = (byte[])sourceFooter.Clone();
            BinaryPrimitives.WriteUInt64BigEndian(expectedFooter.AsSpan(28, 8), (ulong)originalBlobLength);

            using (FileStream target = new FileStream(
                       candidatePath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyChunkBytes))
            {
                candidateCreated = true;

                CurrentBootCopyPrefix(sourceCandidate, target, newVbmetaOffset, ct);
                target.Write(originalMeta.Blob, 0, originalBlobLength);

                long zeroCount = partitionLength - AvbFooterBytes - newVbmetaOffset - originalBlobLength;
                if (zeroCount < 0)
                {
                    throw new InvalidDataException("GBL effective boot body exceeds the partition body.");
                }

                WriteZeros(target, zeroCount, null, ct);
                target.Write(expectedFooter, 0, AvbFooterBytes);
                target.Flush(true);
            }

            using FileStream effective = new FileStream(
                candidatePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);

            if (effective.Length != partitionLength)
            {
                throw new InvalidDataException("GBL effective boot length changed.");
            }

            AvbNodeMetadata effectiveMeta = AvbNodeReadFooterLeafMetadata(effective, partitionLength, ct);

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
                throw new InvalidDataException("GBL effective boot metadata geometry is not the new envelope geometry.");
            }

            byte[] effectiveFooter = new byte[AvbFooterBytes];
            ReadExactly(effective, effectiveFooter, partitionLength - AvbFooterBytes, AvbFooterBytes);

            if (!effectiveFooter.AsSpan().SequenceEqual(expectedFooter))
            {
                throw new InvalidDataException("GBL effective boot footer differs from the expected clone.");
            }

            string actualPayloadSha256 = HashRangeSha256(effective, 0, newPayloadBytes, ct);
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
                effective,
                originalParsed.Hash.Salt,
                originalParsed.Hash.ImageSize,
                contentAlgorithm,
                ct);

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

            string effectiveSha256 = HashStreamSha256(effective, ct);
            var claim = new VerifiedEdlFile(candidatePath, partitionLength, effectiveSha256);

            ct.ThrowIfCancellationRequested();

            completed = true;
            return new CurrentBootGblPreserved(
                claim,
                facts,
                newPayloadBytes,
                expectedPayloadSha256,
                newVbmetaOffset,
                originalBlobLength);
        }
        finally
        {
            if (candidateCreated && !completed)
            {
                AvbNodeTryDelete(candidatePath);
            }
        }
    }

    // Copies exactly byteCount bytes from the current position of source to the
    // current position of destination, honouring cancellation between chunks.
    private static void CurrentBootCopyPrefix(
        FileStream source,
        FileStream destination,
        long byteCount,
        CancellationToken ct)
    {
        source.Seek(0, SeekOrigin.Begin);

        byte[] buffer = new byte[CopyChunkBytes];
        long remaining = byteCount;

        while (remaining > 0)
        {
            ct.ThrowIfCancellationRequested();

            int chunk = (int)Math.Min(buffer.Length, remaining);
            int read = source.Read(buffer, 0, chunk);
            if (read <= 0)
            {
                throw new InvalidDataException("source ended before the declared prefix length");
            }

            destination.Write(buffer, 0, read);
            remaining -= read;
        }
    }
}
