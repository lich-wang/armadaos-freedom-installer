using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core.Gbl;

namespace FreedomInstaller.Core;

internal sealed partial class InternalInstallPreparationContext
{
    // Coarse runtime-region rule preserved from LTBox a278647 region.rs:87-125:
    // scan for product_region, walk up to 16 consecutive token=3 properties and
    // accept the first exact uppercase PRC/ROW value. Deliberately not a full FDT
    // parser, and no default/conflict resolution happens inside a single buffer.

    private const int GblRuntimeMaxDataBytes = 256 * 1024 * 1024;

    private const int GblRuntimePropertyHeaderBytes = 12;

    private const int GblRuntimePropertyWalkLimit = 16;

    private const uint GblRuntimeFdtPropertyToken = 3u;

    private static readonly byte[] GblRuntimeProductRegionMarker = Encoding.ASCII.GetBytes("product_region\0");

    private static readonly byte[] GblRuntimePrcValue = Encoding.ASCII.GetBytes("PRC");

    private static readonly byte[] GblRuntimeRowValue = Encoding.ASCII.GetBytes("ROW");

    // Assigned only by the verified factory appended in the follow-up ticket; the
    // explicit null keeps this field's initialization visible until then.
    private VerifiedGblPlan? _directGblPlan = null;

    internal InternalInstallBootTrustMode DirectBootTrustMode =>
        _directGblPlan is null
            ? InternalInstallBootTrustMode.AospResigned
            : InternalInstallBootTrustMode.GblPreserveOem;

    internal VerifiedEdlFile GblEfispCandidate => RequireDirectGblPlan().Inputs.EfispCandidate;

    internal EdlCapturedRegion GblEfispTarget => RequireDirectGblPlan().Inputs.EfispTarget;

    internal IReadOnlyDictionary<string, EdlRawGblPreservedBoot> GblBoots => RequireDirectGblPlan().Boots;

    private VerifiedGblPlan RequireDirectGblPlan()
    {
        var plan = _directGblPlan;
        if (plan is null)
        {
            throw new InvalidOperationException("requires-verified-gbl-plan:");
        }

        return plan;
    }

    private static GblRuntimeRegion? ReadGblRuntimeRegion(ReadOnlySpan<byte> data, CancellationToken ct)
    {
        if (data.Length > GblRuntimeMaxDataBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(data), "Gbl runtime data exceeds the 256 MiB caller limit.");
        }

        var marker = GblRuntimeProductRegionMarker;
        var searchFrom = 0;

        while (searchFrom <= data.Length - marker.Length)
        {
            ct.ThrowIfCancellationRequested();

            var relativeIndex = data.Slice(searchFrom).IndexOf(marker);
            if (relativeIndex < 0)
            {
                return null;
            }

            var markerEnd = searchFrom + relativeIndex + marker.Length;

            // A walk that fails on token/truncation/overflow abandons only this
            // marker; the scan resumes at the marker end for the next candidate.
            searchFrom = markerEnd;

            var region = ReadGblRuntimeRegionAt(data, markerEnd, ct);
            if (region is not null)
            {
                return region;
            }
        }

        return null;
    }

    private static GblRuntimeRegion? ReadGblRuntimeRegionAt(ReadOnlySpan<byte> data, int markerEnd, CancellationToken ct)
    {
        if (!TryAlignUp4(markerEnd, data.Length, out var offset))
        {
            return null;
        }

        for (var index = 0; index < GblRuntimePropertyWalkLimit; index++)
        {
            ct.ThrowIfCancellationRequested();

            if (offset > data.Length - GblRuntimePropertyHeaderBytes)
            {
                return null;
            }

            var token = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, sizeof(uint)));
            if (token != GblRuntimeFdtPropertyToken)
            {
                return null;
            }

            var valueLength = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset + sizeof(uint), sizeof(uint)));

            // nameoff (header + 8) is intentionally ignored: the coarse rule keys on values only.
            var valueStart = (long)offset + GblRuntimePropertyHeaderBytes;
            var valueEnd = valueStart + valueLength;
            if (valueEnd > data.Length)
            {
                return null;
            }

            var value = data.Slice((int)valueStart, (int)valueLength);
            var terminator = value.IndexOf((byte)0);
            if (terminator >= 0)
            {
                value = value.Slice(0, terminator);
            }

            if (value.SequenceEqual(GblRuntimePrcValue))
            {
                return GblRuntimeRegion.Prc;
            }

            if (value.SequenceEqual(GblRuntimeRowValue))
            {
                return GblRuntimeRegion.Row;
            }

            if (!TryAlignUp4((int)valueEnd, data.Length, out offset))
            {
                return null;
            }
        }

        return null;
    }

    private static bool TryAlignUp4(int value, int limit, out int aligned)
    {
        var candidate = ((long)value + 3L) & ~3L;
        if (candidate > limit)
        {
            aligned = 0;
            return false;
        }

        aligned = (int)candidate;
        return true;
    }

    private static ReadOnlyDictionary<TKey, TValue> CopyReadOnlyMap<TKey, TValue>(IReadOnlyDictionary<TKey, TValue> source)
        where TKey : notnull
    {
        var copy = new Dictionary<TKey, TValue>(source.Count);
        foreach (var pair in source)
        {
            copy[pair.Key] = pair.Value;
        }

        return new ReadOnlyDictionary<TKey, TValue>(copy);
    }

    // Held bytes are read from the one already-verified backup lease; no second
    // lease framework and no extra full-vendor SHA sweep is opened here.
    private static byte[] ReadGblHeldBytes(string role, VerifiedEdlFile expected, List<HeldClaim> claims, CancellationToken ct)
    {
        HeldClaim? held = null;
        foreach (var claim in claims)
        {
            if (string.Equals(claim.Subject, role, StringComparison.Ordinal))
            {
                held = claim;
                break;
            }
        }

        if (held is null
            || held.Length != expected.Length
            || !SameSha(held.Sha256, expected.Sha256)
            || !string.Equals(held.Path, expected.Path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("gbl-held-bytes-mismatch: '" + role + "' is missing or does not match the verified source.");
        }

        ct.ThrowIfCancellationRequested();
        return ReadAllBytes(held.Stream, GblRuntimeMaxDataBytes, ct);
    }

    // Owns only the two files it stages inside the passed evidence directory; sources,
    // pre-existing files and backup claims are never touched. No EFI device write and
    // no EFI/partition selection happens here.
    private static async Task<(VerifiedEdlFile RuntimeAsset, VerifiedEdlFile Candidate)> StageGblEfispAsync(
        GblRuntimeRegion region,
        EdlCapturedRegion target,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken ct)
    {
        if (target is null)
        {
            throw new ArgumentNullException(nameof(target));
        }

        // Existence, unique GPT, UUID and full-SHA ownership already belong to BindBackup.
        if (target.Lun != 4
            || target.SectorSize <= 0
            || target.SectorCount <= 0
            || target.Length != checked((long)target.SectorCount * target.SectorSize))
        {
            throw new InvalidOperationException(
                "requires-complete-backup-with-efisp: efisp target must be LUN4 with positive sector geometry matching its length.");
        }

        var initialClaimCount = claims.Count;
        var candidatePath = Path.Combine(evidenceDirectory, "gbl-efisp-candidate.img");
        var candidateCreated = false;
        VerifiedEdlFile? asset = null;
        FileStream? writer = null;

        try
        {
            ct.ThrowIfCancellationRequested();

            // Fixed standard embedded 282624 B resource for the exact PRC/ROW region.
            asset = await GblRuntimeAssets.StageAsync(region, evidenceDirectory, ct).ConfigureAwait(false);
            if (asset.Length > target.Length)
            {
                throw new InvalidDataException("gbl-runtime-asset-too-large: staged asset does not fit the efisp target.");
            }

            HoldAvbCandidate("gbl-runtime-asset", asset, claims, ct);

            ct.ThrowIfCancellationRequested();
            writer = new FileStream(candidatePath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            candidateCreated = true;

            using (var assetStream = OpenRead(asset.Path))
            {
                await assetStream.CopyToAsync(writer, 81920, ct).ConfigureAwait(false);
            }

            ct.ThrowIfCancellationRequested();
            writer.SetLength(target.Length); // deterministic zero tail, asset bytes stay verbatim
            writer.Flush(true);
            writer.Position = 0;

            var sha256 = HashHeld(writer, ct);
            writer.Dispose();
            writer = null;

            var candidate = new VerifiedEdlFile(candidatePath, target.Length, sha256);
            HoldAvbCandidate("gbl-efisp-candidate", candidate, claims, ct);

            ct.ThrowIfCancellationRequested();
            return (asset, candidate);
        }
        catch
        {
            if (writer is not null)
            {
                writer.Dispose();
                writer = null;
            }

            ReleaseGblClaims(claims, initialClaimCount);
            if (candidateCreated)
            {
                TryDeleteGblStaged(candidatePath);
            }

            // The provider-returned asset is owned by this call even if holding or sizing failed.
            if (asset is not null)
            {
                TryDeleteGblStaged(asset.Path);
            }

            throw;
        }
    }

    private static void ReleaseGblClaims(List<HeldClaim> claims, int initialCount)
    {
        for (var index = claims.Count - 1; index >= initialCount; index--)
        {
            claims[index].Stream?.Dispose();
            claims.RemoveAt(index);
        }
    }

    private static void TryDeleteGblStaged(string path)
    {
        // Cleanup runs while the original failure is unwinding, so it must not mask it.
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void CleanupGblStagedInputs(GblPreparationInputs? inputs)
    {
        if (inputs is null)
        {
            return;
        }

        // Only the two files this preparation staged are removed. The backup, the caller's own input and the
        // evidence reports stay untouched, and no directory is enumerated.
        TryDeleteGblStaged(inputs.RuntimeAsset.Path);
        TryDeleteGblStaged(inputs.EfispCandidate.Path);
    }

    private sealed record GblAblBytes(VerifiedEdlFile Bound, byte[] Raw, byte[] Pe);

    private static string GblSha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));

    private static GblAblBytes ReadGblAblBytes(string role, VerifiedEdlFile bound, List<HeldClaim> claims, CancellationToken ct)
    {
        var raw = ReadGblHeldBytes(role, bound, claims, ct);
        if (!SameSha(GblSha256Hex(raw), bound.Sha256))
        {
            throw new InvalidDataException("gbl-abl-bytes-mismatch: '" + role + "' does not match the verified source.");
        }

        if (!InternalSlotLoaderStructure.TryDecodeAblForGbl(raw, ct, out var pe))
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: indeterminate first-candidate parseability for '" + role + "'.");
        }

        return new GblAblBytes(bound, raw, pe);
    }

    // Early input factory only: no Ready gate, no final VerifiedGblPlan and no child binding.
    private static async Task<GblPreparationInputs?> PrepareDirectGblInputsAsync(
        string currentSlot,
        BootloaderState fastbootLockState,
        IReadOnlyDictionary<string, string> sourceSlots,
        BackupFacts backup,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken ct)
    {
        if (fastbootLockState == BootloaderState.Unlocked)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }

        if (fastbootLockState is not (BootloaderState.Locked or BootloaderState.Unknown))
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: only the defined Locked or Unknown lock facts continue the GBL "
                + "algorithm; an undefined BootloaderState value is refused.");
        }

        ct.ThrowIfCancellationRequested();

        // Source slots are already decided by the strict five-zero rule; the current slot wins ordering.
        var sources = new List<string>(sourceSlots.Count);
        foreach (var pair in sourceSlots)
        {
            if (!sources.Contains(pair.Value))
            {
                sources.Add(pair.Value);
            }
        }

        var currentIndex = sources.IndexOf(currentSlot);
        if (currentIndex > 0)
        {
            sources.RemoveAt(currentIndex);
            sources.Insert(0, currentSlot);
        }

        var parentFacts = new Dictionary<string, EdlRawOriginalBootChainFacts>(StringComparer.Ordinal);
        var originalIsAosp = true;
        foreach (var source in sources)
        {
            ct.ThrowIfCancellationRequested();

            var facts = await EdlRawBootBuilder
                .AuthenticateOriginalBootChainAsync(Claim(backup.Files, "vbmeta_" + source), ct)
                .ConfigureAwait(false);

            parentFacts[source] = facts;
            if (!SameSha(facts.PublicKeySha256, EdlRawBootBuilder.SigningPublicKeySha256))
            {
                originalIsAosp = false;
            }
        }

        if (originalIsAosp)
        {
            return null;
        }

        var decoded = new Dictionary<string, GblAblBytes>(StringComparer.Ordinal);
        string? runtimeSelectedSourceSlot = null;

        foreach (var target in new[] { "a", "b" })
        {
            ct.ThrowIfCancellationRequested();

            if (!sourceSlots.TryGetValue(target, out var source) || string.IsNullOrEmpty(source))
            {
                throw new InvalidDataException("gbl-source-map-incomplete: missing source for target '" + target + "'.");
            }

            // A source that is not its own target stays empty by the strict five-zero rule.
            if (!string.Equals(source, target, StringComparison.Ordinal))
            {
                continue;
            }

            var role = "abl_" + target;
            decoded[source] = ReadGblAblBytes(role, Claim(backup.Files, role), claims, ct);
            runtimeSelectedSourceSlot = source;
            break;
        }

        if (runtimeSelectedSourceSlot is null)
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: no parseable abl_a or abl_b is bound in the verified backup.");
        }

        var evidence = new Dictionary<string, GblSourceEvidence>(StringComparer.Ordinal);
        GblRuntimeRegion? commonRegion = null;

        foreach (var source in sources)
        {
            ct.ThrowIfCancellationRequested();

            if (!decoded.TryGetValue(source, out var abl))
            {
                var ablRole = "abl_" + source;
                abl = ReadGblAblBytes(ablRole, Claim(backup.Files, ablRole), claims, ct);
                decoded[source] = abl;
            }

            var entry = EfispLoadDetector.Detect(abl.Pe);
            if (entry.Status != EfispLoad.Yes)
            {
                throw new InvalidOperationException(
                    "requires-compatible-bootloader: static entry unavailable or undetermined: " + entry.Reason);
            }

            var vendorRole = "vendor_boot_" + source;
            var region = ReadGblRuntimeRegion(ReadGblHeldBytes(vendorRole, Claim(backup.Files, vendorRole), claims, ct), ct);
            if (region is null)
            {
                throw new InvalidOperationException(
                    "gbl-runtime-region-unknown: '" + vendorRole + "' carries no exact PRC/ROW product_region.");
            }

            if (commonRegion is null)
            {
                commonRegion = region;
            }
            else if (commonRegion != region)
            {
                throw new InvalidOperationException(
                    "gbl-runtime-region-unknown: conflicting product_region across source slots ('" + vendorRole + "').");
            }

            evidence[source] = new GblSourceEvidence(
                source,
                abl.Bound,
                GblSha256Hex(abl.Pe),
                entry,
                region.Value,
                parentFacts[source]);
        }

        var runtimeRegion = evidence[runtimeSelectedSourceSlot].Region;

        if (!backup.Files.TryGetValue("efisp", out var efispTarget))
        {
            throw new InvalidOperationException(
                "requires-complete-backup-with-efisp: a new complete backup containing efisp is required.");
        }

        var (runtimeAsset, candidate) = await StageGblEfispAsync(runtimeRegion, efispTarget, evidenceDirectory, claims, ct)
            .ConfigureAwait(false);

        return new GblPreparationInputs(
            currentSlot,
            sourceSlots,
            evidence,
            runtimeSelectedSourceSlot,
            runtimeRegion,
            efispTarget,
            runtimeAsset,
            candidate);
    }

    private sealed record GblSourceEvidence(
        string SourceSlot,
        VerifiedEdlFile Abl,
        string PeSha256,
        DetectionResult Entry,
        GblRuntimeRegion Region,
        EdlRawOriginalBootChainFacts ParentBootChain);

    private sealed class GblPreparationInputs
    {
        internal GblPreparationInputs(
            string currentSlot,
            IReadOnlyDictionary<string, string> sourceSlots,
            IReadOnlyDictionary<string, GblSourceEvidence> sources,
            string runtimeSelectedSourceSlot,
            GblRuntimeRegion runtimeRegion,
            EdlCapturedRegion efispTarget,
            VerifiedEdlFile runtimeAsset,
            VerifiedEdlFile efispCandidate)
        {
            CurrentSlot = currentSlot ?? throw new ArgumentNullException(nameof(currentSlot));
            SourceSlots = CopyReadOnlyMap(sourceSlots ?? throw new ArgumentNullException(nameof(sourceSlots)));
            Sources = CopyReadOnlyMap(sources ?? throw new ArgumentNullException(nameof(sources)));
            RuntimeSelectedSourceSlot = runtimeSelectedSourceSlot ?? throw new ArgumentNullException(nameof(runtimeSelectedSourceSlot));
            RuntimeRegion = runtimeRegion;
            EfispTarget = efispTarget;
            RuntimeAsset = runtimeAsset;
            EfispCandidate = efispCandidate;
        }

        internal string CurrentSlot { get; }

        internal IReadOnlyDictionary<string, string> SourceSlots { get; }

        internal IReadOnlyDictionary<string, GblSourceEvidence> Sources { get; }

        internal string RuntimeSelectedSourceSlot { get; }

        internal GblRuntimeRegion RuntimeRegion { get; }

        internal EdlCapturedRegion EfispTarget { get; }

        internal VerifiedEdlFile RuntimeAsset { get; }

        internal VerifiedEdlFile EfispCandidate { get; }
    }

    private sealed class VerifiedGblPlan
    {
        internal VerifiedGblPlan(
            GblPreparationInputs inputs,
            IReadOnlyDictionary<string, EdlRawGblPreservedBoot> boots,
            IReadOnlyDictionary<string, long> runtimeRawBounds,
            string currentXblRole,
            VerifiedEdlFile currentXbl,
            string commonLoaderEvidence)
        {
            Inputs = inputs ?? throw new ArgumentNullException(nameof(inputs));
            Boots = CopyReadOnlyMap(boots ?? throw new ArgumentNullException(nameof(boots)));
            RuntimeRawBounds = CopyReadOnlyMap(runtimeRawBounds ?? throw new ArgumentNullException(nameof(runtimeRawBounds)));
            CurrentXblRole = currentXblRole ?? throw new ArgumentNullException(nameof(currentXblRole));
            CurrentXbl = currentXbl;
            CommonLoaderEvidence = commonLoaderEvidence ?? throw new ArgumentNullException(nameof(commonLoaderEvidence));
        }

        internal GblPreparationInputs Inputs { get; }

        internal IReadOnlyDictionary<string, EdlRawGblPreservedBoot> Boots { get; }

        internal IReadOnlyDictionary<string, long> RuntimeRawBounds { get; }

        internal string CurrentXblRole { get; }

        internal VerifiedEdlFile CurrentXbl { get; }

        internal string CommonLoaderEvidence { get; }
    }

    // G1e: verifies the selected runtime source against the current XBL and returns the plan. No Ready gate, no device writes.
    private static async Task<VerifiedGblPlan> CompleteDirectGblPlanAsync(
        GblPreparationInputs inputs,
        IReadOnlyList<EdlRawBuiltBoot> builtBoots,
        BackupFacts backup,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken ct)
    {
        var map = BuildDirectBootMap(builtBoots, true);
        var selected = inputs.RuntimeSelectedSourceSlot;
        if (!map.TryGetValue(selected, out var selectedEntry))
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: selected runtime source slot '" + selected + "' has no built boot.");
        }

        if (!string.Equals(selectedEntry.SourceSlot, selected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "gbl-source-material-mismatch: built boot for slot '" + selected + "' reports source '" + selectedEntry.SourceSlot + "'.");
        }

        if (!inputs.Sources.TryGetValue(selected, out var selectedSource))
        {
            throw new InvalidDataException(
                "gbl-source-material-mismatch: no verified source evidence for runtime source slot '" + selected + "'.");
        }

        var selectedMaterial = selectedEntry.SlotMaterial;
        if (!selectedMaterial.SourceSha256.TryGetValue("abl", out var materialAbl)
            || !SameSha(materialAbl, selectedSource.Abl.Sha256))
        {
            throw new InvalidDataException(
                "gbl-source-material-mismatch: 'abl' hash for slot '" + selected + "' disagrees with the verified source.");
        }

        var sourceXblClaim = Claim(backup.Files, "xbl_config_" + selected);
        if (!selectedMaterial.SourceSha256.TryGetValue("xbl_config", out var materialXbl)
            || !SameSha(materialXbl, sourceXblClaim.Sha256))
        {
            throw new InvalidDataException(
                "gbl-source-material-mismatch: 'xbl_config' hash for slot '" + selected + "' disagrees with the verified source.");
        }

        var currentXblRole = "xbl_config_" + inputs.CurrentSlot;
        var currentXbl = Claim(backup.Files, currentXblRole);
        var currentXblRaw = ReadGblHeldBytes(currentXblRole, currentXbl, claims, ct);
        if (!SameSha(GblSha256Hex(currentXblRaw), currentXbl.Sha256))
        {
            throw new InvalidDataException(
                "gbl-abl-bytes-mismatch: '" + currentXblRole + "' does not match the verified source.");
        }

        var selectedAblRole = "abl_" + selected;
        var selectedAblRaw = ReadGblHeldBytes(selectedAblRole, selectedSource.Abl, claims, ct);
        if (!SameSha(GblSha256Hex(selectedAblRaw), selectedSource.Abl.Sha256))
        {
            throw new InvalidDataException(
                "gbl-abl-bytes-mismatch: '" + selectedAblRole + "' does not match the verified source.");
        }

        if (!InternalSlotLoaderStructure.TryRecognize(selectedAblRaw, currentXblRaw, ct, out var commonEvidence))
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: the selected ABL and the current XBL share no proven common loader window"
                + " under the recognized 256 MiB profile; the 128 MiB fallback is not measured.");
        }

        var wrappers = new Dictionary<string, EdlRawGblPreservedBoot>(StringComparer.Ordinal);
        var bounds = new Dictionary<string, long>(StringComparer.Ordinal);

        try
        {
            foreach (var target in new[] { "b", "a" })
            {
                ct.ThrowIfCancellationRequested();

                var built = map[target];
                if (!inputs.SourceSlots.TryGetValue(target, out var expectedSource)
                    || !string.Equals(built.SourceSlot, expectedSource, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "gbl-source-slot-mismatch: target '" + target + "' does not match its recorded source.");
                }

                if (!inputs.Sources.TryGetValue(built.SourceSlot, out var sourceEvidence))
                {
                    throw new InvalidDataException(
                        "gbl-source-material-mismatch: no verified source evidence for '" + built.SourceSlot + "'.");
                }

                var sourceMaterial = built.SlotMaterial;
                if (!string.Equals(sourceMaterial.Slot, built.SourceSlot, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "gbl-source-material-mismatch: material for target '" + target + "' reports slot '" + sourceMaterial.Slot + "'.");
                }

                var selectedBudget = selectedMaterial.LoaderBudget;
                var sourceBudget = sourceMaterial.LoaderBudget;
                if (!selectedBudget.KnownLoaderMatch
                    || !sourceBudget.KnownLoaderMatch
                    || selectedMaterial.PageSize != 4096
                    || sourceMaterial.PageSize != 4096
                    || selectedBudget.MaxRawBytes <= 0
                    || sourceBudget.MaxRawBytes <= 0)
                {
                    throw new InvalidOperationException(
                        "requires-compatible-bootloader: no statically derived 4096-byte-page loader budget for target '" + target
                        + "' (known=" + sourceBudget.KnownLoaderMatch + ", pageSize=" + sourceMaterial.PageSize
                        + ", maxRawBytes=" + sourceBudget.MaxRawBytes + ").");
                }

                var ramdiskDelta = Math.Max(
                    0L,
                    checked(AlignGblUp4096(sourceMaterial.TotalRamdiskSize) - AlignGblUp4096(selectedMaterial.TotalRamdiskSize)));
                var bound = Math.Min(sourceBudget.MaxRawBytes, checked(selectedBudget.MaxRawBytes - ramdiskDelta));
                if (bound <= 0)
                {
                    throw new InvalidOperationException(
                        "requires-compatible-bootloader: runtime raw bound for target '" + target
                        + "' is not positive (bound=" + bound + ", ramdiskDelta=" + ramdiskDelta + ").");
                }

                if (built.PackedRaw.Length > bound)
                {
                    throw new InvalidOperationException(
                        "requires-compatible-bootloader: packed raw " + built.PackedRaw.Length + " bytes for target '" + target
                        + "' exceeds the statically derived runtime raw bound " + bound + " bytes.");
                }

                var wrapper = await EdlRawBootBuilder.PreserveOriginalSignedBootMetadataAsync(
                        built,
                        Claim(backup.Files, "boot_" + built.SourceSlot),
                        Path.Combine(evidenceDirectory, "gbl-boot_" + target + ".img"),
                        ct)
                    .ConfigureAwait(false);

                wrappers[target] = wrapper;

                var facts = wrapper.OriginalSignatureFacts;
                if (!facts.OriginalSignatureValid)
                {
                    throw new InvalidOperationException(
                        "gbl-boot-signature-invalid: preserved original signature for target '" + target + "' is not valid.");
                }

                if (!SameSha(sourceEvidence.ParentBootChain.BootChainPublicKeySha256, facts.PublicKeySha256))
                {
                    throw new InvalidOperationException(
                        "gbl-boot-chain-key-mismatch: target '" + target + "' public key does not match the authenticated parent boot chain for source '"
                        + built.SourceSlot + "'.");
                }

                bounds[target] = bound;
            }

            ct.ThrowIfCancellationRequested();
            return new VerifiedGblPlan(inputs, wrappers, bounds, currentXblRole, currentXbl, commonEvidence);
        }
        catch
        {
            foreach (var wrapper in wrappers.Values)
            {
                wrapper.Dispose();
            }

            throw;
        }
    }

    private static long AlignGblUp4096(long value) => checked((value + 4095L) & ~4095L);

    private static IReadOnlyList<string> GetGblGuardRoles(GblPreparationInputs inputs)
    {
        var roles = new List<string>
        {
            "efisp",
            "abl_" + inputs.RuntimeSelectedSourceSlot,
            "xbl_config_" + inputs.CurrentSlot,
        };

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in SortedKeys(inputs.SourceSlots))
        {
            var source = inputs.SourceSlots[target];
            if (string.IsNullOrEmpty(source) || !seen.Add(source))
            {
                continue;
            }

            roles.Add("abl_" + source);
            roles.Add("recovery_" + source);
            roles.Add("vbmeta_system_" + source);
            roles.Add("vbmeta_" + source);
        }

        return roles
            .Distinct(StringComparer.Ordinal)
            .OrderBy(role => role, StringComparer.Ordinal)
            .ToList()
            .AsReadOnly();
    }

    private static void DisposeGblBoots(VerifiedGblPlan? plan)
    {
        if (plan is null)
        {
            return;
        }

        foreach (var target in SortedKeys(plan.Boots))
        {
            plan.Boots[target].Dispose();
        }
    }

    internal IReadOnlyList<string> GblGuardRoles => GetGblGuardRoles(RequireDirectGblPlan().Inputs);

    internal IReadOnlyDictionary<string, long> GblRuntimeRawBounds => RequireDirectGblPlan().RuntimeRawBounds;
}
