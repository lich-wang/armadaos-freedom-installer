using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The actual direct EDL execution flow: one warm original-device recheck, then the four GPT regions, the
/// board archive and the two expanded Linux images, followed by the typed boot writes of the prepared trust
/// mode (the efisp runtime region and the two preserved boot candidates, or the two AOSP-resigned boot
/// candidates and the mandatory AVB metadata partitions of every selected slot) over the one initial EDL
/// session, the fresh misc BCB overlay and exactly one normal reset. The route ends at
/// <see cref="InternalInstallStage.InstallationCompleted"/> once every write/readback and the accepted reset
/// are proven; it takes no Android acceptance and claims no operating-system boot or wipe execution. No RAM
/// session, no fresh EDL session and no second transport exists on this route.
/// <para>
/// The flow owns no admission, no state transition and no error classification. The host dispatches here
/// before the legacy revalidation body when <see cref="InternalInstallPreparationContext.IsDirect"/> is set,
/// and its existing outer <c>try</c>/<c>catch</c>/<c>finally</c> turns a failure into the same Unknown,
/// Failed or Cancelled result as the legacy route. A failed step simply stops the sequence: no later write
/// and no reset is issued.
/// </para>
/// <para>
/// Every region handed to a write is a local metadata view of an already verified payload. The raw images
/// describe exactly the bytes actually written, never the whole target partition, and no content hash is
/// recomputed here: the context holds and revalidates the real leases.
/// </para>
/// </summary>
public sealed partial class InternalInstallBackend
{
    private const string DirectExecutionRequiresDirectPreparationCode =
        "direct-execution-requires-direct-preparation";

    private const string DirectExecutionTerminalStateUnprovenCode =
        "direct-execution-terminal-state-unproven";

    private const string DirectExecutionAvbMetadataMismatchCode =
        "direct-execution-avb-metadata-mismatch";

    /// <summary>
    /// The one fixed direct EDL sequence. It starts with the cheap local and cancellation guards, performs the
    /// reusable pre-write device recheck, precomputes every local write view (both boot candidates, the typed
    /// GBL runtime region and, for the AOSP-resigned route only, the mandatory AVB metadata regions), then
    /// issues the writes in the one frozen order and ends with the accepted normal reset and the direct
    /// terminal result. There is no retry, no fallback, no RAM job, no second reset and no Android acceptance.
    /// </summary>
    private async Task<InternalInstallResult> ExecuteDirectFlowAsync(
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(run);

        if (!_context.IsDirect)
        {
            throw new InvalidOperationException(
                DirectExecutionRequiresDirectPreparationCode
                + ": the direct flow only runs for a direct EDL raw preparation.");
        }

        ct.ThrowIfCancellationRequested();

        run.StartStage(InternalInstallStage.Revalidating);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        // The first check counts the future capture; the second one runs after the fresh capture exists, so the
        // already written evidence is never counted twice.
        _context.EnsureDirectExecutionSpace();
        await _context.RevalidateLocalAsync(ct).ConfigureAwait(false);
        await _context.VerifyOriginalDeviceAsync(_initialEdl, "execute-direct", ct).ConfigureAwait(false);
        _context.EnsureDirectExecutionSpace(includeOriginalCapture: false);

        // Every local view is built before the first device write, so a metadata or size mismatch refuses the
        // run while nothing has been issued yet.
        EdlGeometry lun0 = _context.Geometries[0];

        InternalArtifactRegion linuxBoot = CreateDirectRawWriteRegion(
            _context.LinuxBoot, lun0, _context.Package.LinuxBootRaw, "linux_boot");

        InternalArtifactRegion linuxRoot = CreateDirectRawWriteRegion(
            _context.LinuxRoot, lun0, _context.Package.LinuxRootRaw, "linux_root");

        // The route splits on the prepared trust mode, never on caller input: only a GBL-preserving preparation
        // writes the efisp runtime region and no AVB metadata, and only an AOSP-resigned preparation writes AVB
        // metadata. Both branches fill the same two local boot candidate views before the first device write.
        InternalArtifactRegion candidateB;
        InternalArtifactRegion candidateA;
        InternalArtifactRegion? gblRuntime = null;

        var metadataRegions = new List<InternalArtifactRegion>();

        if (_context.DirectBootTrustMode == InternalInstallBootTrustMode.GblPreserveOem)
        {
            // Reading the typed GBL members is the plan check itself: each getter refuses a preparation that
            // carries no verified GBL plan.
            var gblBoots = _context.GblBoots;
            var gblEfispTarget = _context.GblEfispTarget;
            var gblEfispCandidate = _context.GblEfispCandidate;

            // The GBL-preserving route writes no AVB metadata, so any prepared node is a mismatch of the route.
            if (_context.DirectAvbNodes.Count != 0)
            {
                throw new InvalidOperationException(
                    DirectExecutionAvbMetadataMismatchCode + ": the GBL-preserving direct route requires no AVB "
                    + "metadata, but " + _context.DirectAvbNodes.Count + " nodes were prepared.");
            }

            gblRuntime = MakeExecutionRegion(gblEfispTarget, gblEfispCandidate, "efisp");

            candidateB = MakeExecutionRegion(
                RequireCapturedRegion("boot_b"), gblBoots["b"].EffectiveCandidate, "boot_b");

            candidateA = MakeExecutionRegion(
                RequireCapturedRegion("boot_a"), gblBoots["a"].EffectiveCandidate, "boot_a");
        }
        else
        {
            candidateB = MakeExecutionRegion(
                RequireCapturedRegion("boot_b"), _context.DirectBoots["b"].CandidateBoot, "boot_b");

            candidateA = MakeExecutionRegion(
                RequireCapturedRegion("boot_a"), _context.DirectBoots["a"].CandidateBoot, "boot_a");

            // The mandatory AVB metadata regions are derived from the one fixed slot order and the prepared boot
            // facts only: a strict boot-only target receives no metadata at all. No caller, no generic partition
            // selection and no copy of one slot into the other participates here.
            string[] avbSlotOrder = { "b", "a" };
            string[] avbRolePrefixes = { "recovery", "vbmeta_system", "vbmeta" };

            var expectedAvbTargets = new List<(string Slot, string Role)>();

            foreach (string slot in avbSlotOrder)
            {
                if (_context.DirectBoots[slot].UsesInactiveSlotBackup)
                {
                    continue;
                }

                foreach (string prefix in avbRolePrefixes)
                {
                    expectedAvbTargets.Add((slot, prefix + "_" + slot));
                }
            }

            IReadOnlyList<InternalInstallPreparationContext.DirectAvbMetadataNode> avbNodes =
                _context.DirectAvbNodes;

            // The prepared metadata list must match the expected slots, roles and count exactly, in order. A
            // missing, duplicated, extra or reordered node refuses the run before the first device write, so the
            // older write sequence can never stand in for a metadata write.
            if (avbNodes.Count != expectedAvbTargets.Count)
            {
                throw new InvalidOperationException(
                    DirectExecutionAvbMetadataMismatchCode + ": the prepared AVB metadata list has "
                    + avbNodes.Count + " nodes instead of " + expectedAvbTargets.Count + ".");
            }

            for (int index = 0; index < expectedAvbTargets.Count; index++)
            {
                InternalInstallPreparationContext.DirectAvbMetadataNode node = avbNodes[index];
                (string expectedSlot, string expectedRole) = expectedAvbTargets[index];

                if (!string.Equals(node.Slot, expectedSlot, StringComparison.Ordinal)
                    || !string.Equals(node.Role, expectedRole, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        DirectExecutionAvbMetadataMismatchCode + ": AVB metadata node " + index + " is "
                        + node.Slot + "/" + node.Role + " instead of " + expectedSlot + "/" + expectedRole + ".");
                }

                metadataRegions.Add(
                    MakeExecutionRegion(RequireCapturedRegion(expectedRole), node.Node.Candidate, expectedRole));
            }
        }

        run.VerifyStage(InternalInstallStage.Revalidating);
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);

        // The four explicit GPT regions stay in the array order the artifact preparation froze.
        foreach (InternalArtifactRegion region in _context.GptWriteRegions)
        {
            await WriteExecutionRegionAsync(
                    _initialEdl,
                    run,
                    InternalInstallStage.WritingGpt,
                    null,
                    region,
                    true,
                    progress,
                    ct)
                .ConfigureAwait(false);
        }

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingBoardBackup,
                null,
                _context.BoardSummary,
                true,
                progress,
                ct)
            .ConfigureAwait(false);

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingLinuxBoot,
                null,
                linuxBoot,
                true,
                progress,
                ct)
            .ConfigureAwait(false);

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingLinuxRoot,
                null,
                linuxRoot,
                true,
                progress,
                ct)
            .ConfigureAwait(false);

        // On the GBL-preserving route the efisp runtime region is the eighth device write: after the four GPT
        // regions, the board archive and the two Linux images, and still before both boot candidates, the misc
        // overlay and the reset. The AOSP-resigned route has no runtime region and writes nothing here.
        if (gblRuntime != null)
        {
            await WriteExecutionRegionAsync(
                    _initialEdl,
                    run,
                    InternalInstallStage.WritingGblRuntime,
                    null,
                    gblRuntime,
                    true,
                    progress,
                    ct)
                .ConfigureAwait(false);
        }

        // The fixed candidate order is b then a; it is never selectable by a caller.
        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingBootB,
                "b",
                candidateB,
                true,
                progress,
                ct)
            .ConfigureAwait(false);

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingBootA,
                "a",
                candidateA,
                true,
                progress,
                ct)
            .ConfigureAwait(false);

        // Every mandatory AVB metadata region of the AOSP-resigned route is written whole and read back over the
        // same initial session, in the frozen prepared order, before the misc overlay and the reset. The list is
        // empty on the GBL-preserving route, which writes no metadata. The slot argument stays null: these
        // writes never add or reorder the verified boot slots b, a.
        foreach (InternalArtifactRegion region in metadataRegions)
        {
            await WriteExecutionRegionAsync(
                    _initialEdl,
                    run,
                    InternalInstallStage.WritingAvbMetadata,
                    null,
                    region,
                    true,
                    progress,
                    ct)
                .ConfigureAwait(false);
        }

        // Only the fresh misc bytes are read and overlaid; the old backup SHA is never restored.
        await WriteFreshMiscAsync(_initialEdl, run, progress, ct).ConfigureAwait(false);

        // The one reset of this run, and only after every write and readback above.
        await ResetExecutionAsync(
                _initialEdl, run, InternalInstallStage.Restarting, progress, ct)
            .ConfigureAwait(false);

        // An accepted reset is not success by itself: the existing run must still prove every write and the
        // frozen slot order, otherwise no terminal result is produced.
        IReadOnlyList<string> verifiedSlots = run.VerifiedSlots;
        if (run.WriteState != InternalInstallWriteState.AllVerified
            || verifiedSlots.Count != 2
            || !string.Equals(verifiedSlots[0], "b", StringComparison.Ordinal)
            || !string.Equals(verifiedSlots[1], "a", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                DirectExecutionTerminalStateUnprovenCode
                + ": the direct route requires AllVerified writes and verified slots b, a after the accepted reset.");
        }

        // The terminal stage is only a route marker; it verifies nothing about a boot or a wipe execution.
        run.StartStage(InternalInstallStage.InstallationCompleted);

        return FinishResult(
            run,
            InternalInstallOutcome.InstallationCompleted,
            InternalInstallProgressKind.Verified,
            progress,
            InternalInstallUserAction.None,
            androidAcceptance: null,
            errorCode: null,
            diagnostic: null);
    }

    /// <summary>
    /// The pure local view of one expanded Linux raw image written into its target partition.
    /// <para>
    /// <paramref name="raw"/> is already the actual expanded raw image of the verified package snapshot; its
    /// length and SHA-256 describe exactly the bytes that will be written, which may be shorter than the
    /// target partition. The target can therefore be larger than the image, but the image can never exceed
    /// the target or leave LUN 0, and no 64 GiB padding or whole-partition hash is ever claimed.
    /// </para>
    /// <para>
    /// Only metadata arithmetic runs here: no file is opened, no byte is hashed and no argument is promoted
    /// to a verified fact by this helper.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">The role is blank, the geometry or target is unusable, the image
    /// metadata does not fit the target, or a sector end overflows a 64-bit address.</exception>
    private static InternalArtifactRegion CreateDirectRawWriteRegion(
        GptPartition target,
        EdlGeometry geometry,
        VerifiedEdlFile raw,
        string role)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(geometry);
        ArgumentNullException.ThrowIfNull(raw);

        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("The region must have a non-blank role.", nameof(role));
        }

        if (geometry.Lun != 0)
        {
            throw new ArgumentException(
                "The direct raw image is only written to LUN 0, not LUN " + geometry.Lun + ".", nameof(geometry));
        }

        int sectorSize = geometry.SectorSize;

        if (sectorSize <= 0)
        {
            throw new ArgumentException("The LUN 0 sector size must be positive.", nameof(geometry));
        }

        if (geometry.TotalSectors <= 0)
        {
            throw new ArgumentException("The LUN 0 geometry declares no usable sectors.", nameof(geometry));
        }

        if (target.StartSector < 0 || target.SectorCount <= 0)
        {
            throw new ArgumentException("The target partition has no usable sector range.", nameof(target));
        }

        if (string.IsNullOrWhiteSpace(raw.Path))
        {
            throw new ArgumentException("The expanded raw image must have a non-blank path.", nameof(raw));
        }

        if (raw.Length <= 0)
        {
            throw new ArgumentException("The expanded raw image must not be empty.", nameof(raw));
        }

        if (!IsSha256Text(raw.Sha256))
        {
            throw new ArgumentException(
                "The expanded raw image SHA-256 must be 64 hexadecimal characters.", nameof(raw));
        }

        if (raw.Length % sectorSize != 0)
        {
            throw new ArgumentException(
                "The expanded raw image length is not a whole number of " + sectorSize + " byte sectors.",
                nameof(raw));
        }

        long rawSectors = raw.Length / sectorSize;

        if (rawSectors > target.SectorCount)
        {
            throw new ArgumentException(
                "The expanded raw image spans " + rawSectors + " sectors, more than the target's "
                + target.SectorCount + ".", nameof(raw));
        }

        long targetEnd = RequireSectorEnd(
            target.StartSector, target.SectorCount, nameof(target), "The target partition");
        long rawEnd = RequireSectorEnd(
            target.StartSector, rawSectors, nameof(raw), "The expanded raw image");

        if (targetEnd > geometry.TotalSectors)
        {
            throw new ArgumentException(
                "The target partition ends at sector " + targetEnd + ", beyond LUN 0's "
                + geometry.TotalSectors + " sectors.", nameof(target));
        }

        if (rawEnd > geometry.TotalSectors)
        {
            throw new ArgumentException(
                "The expanded raw image ends at sector " + rawEnd + ", beyond LUN 0's "
                + geometry.TotalSectors + " sectors.", nameof(raw));
        }

        return new InternalArtifactRegion(
            role,
            geometry.Lun,
            target.StartSector,
            rawSectors,
            sectorSize,
            raw.Path,
            raw.Length,
            raw.Sha256);
    }

    /// <summary>
    /// The checked 64-bit sector end. An overflow is refused as invalid metadata instead of wrapping around.
    /// </summary>
    private static long RequireSectorEnd(
        long startSector,
        long sectorCount,
        string paramName,
        string what)
    {
        if (sectorCount > long.MaxValue - startSector)
        {
            throw new ArgumentException(
                what + " start and sector count overflow a 64-bit sector address.", paramName);
        }

        return startSector + sectorCount;
    }
}
