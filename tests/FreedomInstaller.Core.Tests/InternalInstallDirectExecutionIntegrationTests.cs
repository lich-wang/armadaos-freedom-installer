using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// DE002/LNX02: real-factory integration facts for the direct EDL execution route. Each fact consumes the
/// frozen <see cref="DirectInstallReadyTestSession"/> factory, which owns the real 52-file backup, the real
/// artifact preparation, the real typed package import, the real native two-slot build and the real
/// <c>CreatePreparedAsync</c>. Nothing here fabricates a Ready flag, a prepared context or a built boot.
/// <para>
/// All I/O is synthetic and offline: the EDL transport is the shared file-backed IB001 fixture, the native
/// commands run through the fixture's Linux oracle, and the Android side is an argv-checking read-only
/// responder. No backup bytes, secrets or credentials are read, and no result claims that a synthetic image
/// is bootable, deployment-valid or accepted on hardware.
/// </para>
/// </summary>
public sealed class InternalInstallDirectExecutionIntegrationTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    private const string Adb = "test-adb";

    private const int RawSectorSize = 4096;

    private const long BoardBytes = 2L << 30;

    private static readonly TimeSpan AdbTimeout = TimeSpan.FromSeconds(15);

    private static readonly InternalInstallStage[] RawWriteStages =
    {
        InternalInstallStage.WritingGpt,
        InternalInstallStage.WritingBoardBackup,
        InternalInstallStage.WritingLinuxBoot,
        InternalInstallStage.WritingLinuxRoot,
        InternalInstallStage.WritingBootB,
        InternalInstallStage.WritingBootA,
        InternalInstallStage.WritingMisc,
        InternalInstallStage.WritingAvbMetadata,
    };

    // Stages of the legacy RAM/bootstrap route that must never appear on the direct route.
    private static readonly InternalInstallStage[] ForbiddenStages =
    {
        InternalInstallStage.WritingMaintenanceBoot,
        InternalInstallStage.BootingRam,
        InternalInstallStage.PreparingFilesystems,
        InternalInstallStage.ReceivingSeed,
        InternalInstallStage.Deploying,
        InternalInstallStage.BuildingCandidates,
        InternalInstallStage.ExportingCandidates,
        InternalInstallStage.ReturningEdl,
    };

    private readonly EdlClientToolchainFixture _toolchain;

    private readonly EdlRawSharedInput _rawShared;

    public InternalInstallDirectExecutionIntegrationTests(
        EdlClientToolchainFixture toolchain,
        EdlRawSharedInput rawShared)
    {
        _toolchain = toolchain;
        _rawShared = rawShared;
    }

    // ------------------------------------------------------------------ case 1: full success stops after the accepted reset

    [Fact]
    public async Task Full_direct_flow_writes_the_frozen_sequence_and_completes_without_android_acceptance()
    {
        var android = new ReadOnlyAndroidResponder();
        using DirectInstallReadyTestSession session = await DirectInstallReadyTestSession.CreateAsync(
            _toolchain, _rawShared, "a", android);

        string model = session.Package.DeviceModel;
        android.ConfigureFacts(session.Backend.Prepared, session.Artifacts, model);

        IB001FakeEdlRunner runner = session.EdlRunner;
        InternalInstallPrepared prepared = session.Backend.Prepared;
        InternalInstallSnapshot preparedSnapshot = session.Backend.Snapshot;

        Assert.Equal(6, session.NativeCommandCount);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        Assert.Equal(1, runner.SaharaResponseCount);
        Assert.Same(prepared, session.Backend.Prepared);
        Assert.False(preparedSnapshot.ExecutionStarted);
        Assert.Equal(InternalInstallStage.Prepared, preparedSnapshot.Stage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, preparedSnapshot.WriteState);
        Assert.Null(preparedSnapshot.Outcome);

        IReadOnlyList<InternalArtifactRegion> gptRegions = session.Artifacts.GptWriteRegions;
        Assert.Equal(4, gptRegions.Count);

        InternalArtifactRegion board = session.Artifacts.BoardSummary;
        Assert.Equal(BoardBytes, board.Length);

        EdlRawPackageContract contract = PackageReader.ReadEdlRawContract(
            session.Package.PackageDirectory, model);
        Assert.Equal(0L, contract.BootImage.ExpandedBytes % contract.BootImage.SectorSize);
        Assert.Equal(0L, contract.RootImage.ExpandedBytes % contract.RootImage.SectorSize);
        Assert.Equal(RawSectorSize, contract.BootImage.SectorSize);
        Assert.Equal(RawSectorSize, contract.RootImage.SectorSize);

        long bootWriteSectors = contract.BootImage.ExpandedBytes / contract.BootImage.SectorSize;
        long rootWriteSectors = contract.RootImage.ExpandedBytes / contract.RootImage.SectorSize;
        Assert.True(
            rootWriteSectors < session.Artifacts.LinuxRoot.SectorCount,
            "the real root image must be shorter than its full target partition");

        EdlCapturedRegion bootB = session.Backup.Files["boot_b"];
        EdlCapturedRegion bootA = session.Backup.Files["boot_a"];
        EdlCapturedRegion misc = session.Backup.Files["misc"];

        // The six complete real AOSP original metadata slots, in the exact order the fixed sixteen-write
        // route writes them right after boot B/A and right before misc.
        EdlCapturedRegion recoveryB = session.Backup.Files["recovery_b"];
        EdlCapturedRegion vbmetaSystemB = session.Backup.Files["vbmeta_system_b"];
        EdlCapturedRegion vbmetaB = session.Backup.Files["vbmeta_b"];
        EdlCapturedRegion recoveryA = session.Backup.Files["recovery_a"];
        EdlCapturedRegion vbmetaSystemA = session.Backup.Files["vbmeta_system_a"];
        EdlCapturedRegion vbmetaA = session.Backup.Files["vbmeta_a"];
        EdlCapturedRegion[] metadataRegions =
        {
            recoveryB,
            vbmetaSystemB,
            vbmetaB,
            recoveryA,
            vbmetaSystemA,
            vbmetaA,
        };

        byte[] originalMisc = File.ReadAllBytes(misc.FilePath);
        Assert.Equal(misc.Length, originalMisc.LongLength);
        Assert.Equal(misc.SectorCount * (long)misc.SectorSize, originalMisc.LongLength);

        // The fresh read keeps a canonical empty BCB header; only the non-BCB bytes below change.
        byte[] lateFreshUnit = (byte[])originalMisc.Clone();
        Array.Clear(lateFreshUnit, 0, 32);
        Array.Clear(lateFreshUnit, 64, 768);
        byte status = DistinctSentinel(originalMisc[32]);
        byte stage = DistinctSentinel(originalMisc[832], status);
        byte suffixStart = DistinctSentinel(originalMisc[2048], status, stage);
        byte suffixEnd = DistinctSentinel(originalMisc[4095], status, stage, suffixStart);
        lateFreshUnit[32] = status;
        lateFreshUnit[832] = stage;
        lateFreshUnit[2048] = suffixStart;
        lateFreshUnit[4095] = suffixEnd;

        // The override answers only the late full misc fresh read, after the fifteen preceding writes. The
        // pre-write VerifyOriginalDeviceAsync full misc read must stay the untouched original bytes.
        runner.PayloadOverride = read =>
            runner.Writes.Count == 15
            && read.Lun == misc.Lun
            && read.StartSector == misc.StartSector
            && read.SectorCount == misc.SectorCount
                ? (byte[])lateFreshUnit.Clone()
                : null;

        int edlCommandCountBefore = runner.Commands.Count;
        int saharaCountBefore = runner.SaharaResponseCount;
        var progress = new InlineProgress();

        InternalInstallResult result = await session.Backend.ExecuteAsync(
            prepared.ConfirmationId, userdataEraseConfirmed: true, progress);

        // The direct execution ends at its own terminal stage: writes and the accepted reset are proven,
        // no Android acceptance was taken and no operating system is claimed.
        Assert.Equal(InternalInstallOutcome.InstallationCompleted, result.Outcome);
        Assert.Equal(InternalInstallUserAction.None, result.RequiredUserAction);
        Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
        Assert.Equal(new List<string> { "b", "a" }, result.VerifiedSlots.ToList());
        Assert.Equal(InternalInstallStage.WritingMisc, result.LastVerifiedStage);
        Assert.False(result.LinuxAcceptanceVerified);
        Assert.Null(result.AndroidAcceptance);
        Assert.NotEqual(InternalInstallOutcome.Completed, result.Outcome);

        Assert.Equal(6, session.NativeCommandCount);
        Assert.Same(prepared, session.Backend.Prepared);
        Assert.Equal(InternalInstallStage.InstallationCompleted, session.Backend.Snapshot.Stage);
        Assert.Equal(InternalInstallWriteState.AllVerified, session.Backend.Snapshot.WriteState);
        Assert.Equal(InternalInstallOutcome.InstallationCompleted, session.Backend.Snapshot.Outcome);
        Assert.Equal(0, android.CommandCount);

        // Exactly sixteen acknowledged writes: GPT4, the 2 GiB board archive, both raw images, B, A, the
        // six original-metadata AVB writes, then misc.
        IReadOnlyList<IB001Write> writes = runner.Writes;
        Assert.Equal(16, writes.Count);
        Assert.Equal(1, runner.ResetCount);

        for (int index = 0; index < gptRegions.Count; index++)
        {
            AssertWriteCovers(writes[index], gptRegions[index]);
        }

        AssertWriteCovers(writes[4], board);

        IB001Write bootWrite = writes[5];
        Assert.Equal(0, bootWrite.Lun);
        Assert.Equal(session.Artifacts.LinuxBoot.StartSector, bootWrite.StartSector);
        Assert.Equal(bootWriteSectors, bootWrite.SectorCount);
        Assert.Equal(contract.BootImage.ExpandedBytes, new FileInfo(bootWrite.FilePath).Length);
        AssertShaEqual(contract.BootImage.ExpandedSha256, bootWrite.Sha256);

        IB001Write rootWrite = writes[6];
        Assert.Equal(0, rootWrite.Lun);
        Assert.Equal(session.Artifacts.LinuxRoot.StartSector, rootWrite.StartSector);
        Assert.Equal(rootWriteSectors, rootWrite.SectorCount);
        Assert.Equal(contract.RootImage.ExpandedBytes, new FileInfo(rootWrite.FilePath).Length);
        AssertShaEqual(contract.RootImage.ExpandedSha256, rootWrite.Sha256);

        IB001Write bootBWrite = writes[7];
        AssertWriteCovers(bootBWrite, bootB);
        Assert.False(string.Equals(bootB.Sha256, bootBWrite.Sha256, StringComparison.OrdinalIgnoreCase));

        IB001Write bootAWrite = writes[8];
        AssertWriteCovers(bootAWrite, bootA);
        Assert.False(string.Equals(bootA.Sha256, bootAWrite.Sha256, StringComparison.OrdinalIgnoreCase));
        Assert.False(string.Equals(bootBWrite.Sha256, bootAWrite.Sha256, StringComparison.OrdinalIgnoreCase));

        // The six metadata writes are the complete original AOSP slots in the frozen order at indices 9..14.
        // Each must cover its full captured region with a file of the captured length; the candidate may
        // legitimately be byte-identical to the already-signed original, so no differing SHA is demanded.
        for (int index = 0; index < metadataRegions.Length; index++)
        {
            AssertWriteCovers(writes[9 + index], metadataRegions[index]);
        }

        // The misc write is exactly one rounded 2 KiB unit at the captured misc LUN/start.
        IB001Write miscWrite = writes[15];
        Assert.Equal(misc.Lun, miscWrite.Lun);
        Assert.Equal(misc.StartSector, miscWrite.StartSector);
        Assert.Equal((2048L + misc.SectorSize - 1) / misc.SectorSize, miscWrite.SectorCount);
        Assert.Equal(miscWrite.SectorCount * (long)misc.SectorSize, new FileInfo(miscWrite.FilePath).Length);

        byte[] writtenMiscUnit = File.ReadAllBytes(miscWrite.FilePath);
        Assert.Equal(4096, writtenMiscUnit.Length);
        Assert.Equal(
            "boot-recovery", Encoding.ASCII.GetString(writtenMiscUnit, 0, "boot-recovery".Length));
        AssertEqualRange(writtenMiscUnit, 13, 32, 0);
        byte[] recovery = Encoding.ASCII.GetBytes("recovery\n--wipe_data\n--reason=armada-internal-install\n");
        Assert.Equal(recovery.ToList(), writtenMiscUnit.Skip(64).Take(recovery.Length).ToList());
        AssertEqualRange(writtenMiscUnit, 64 + recovery.Length, 832, 0);

        // Every non-BCB byte comes from the late fresh read, not from the old backup.
        AssertEqualRange(writtenMiscUnit, 32, 64, lateFreshUnit);
        AssertEqualRange(writtenMiscUnit, 832, 2048, lateFreshUnit);
        AssertEqualRange(writtenMiscUnit, 2048, 4096, lateFreshUnit);
        Assert.NotEqual(originalMisc[32], writtenMiscUnit[32]);
        Assert.NotEqual(originalMisc[832], writtenMiscUnit[832]);
        Assert.NotEqual(originalMisc[2048], writtenMiscUnit[2048]);
        Assert.NotEqual(originalMisc[4095], writtenMiscUnit[4095]);

        // The post-Sahara EDL verb sequence is exactly the fifteen write/read pairs, one fresh misc read,
        // the misc write/read pair and one reset. No second Sahara or fresh session exists.
        List<ProcessCommand> commands = runner.Commands.Skip(edlCommandCountBefore).ToList();
        int firstWrite = commands.FindIndex(command => Arguments(command)[0] == "write-sector");
        Assert.True(firstWrite >= 0, "the direct execution must issue a write-sector command");
        List<ProcessCommand> mutations = commands.Skip(firstWrite).ToList();

        var expectedVerbs = new List<string>();
        for (int index = 0; index < 15; index++)
        {
            expectedVerbs.Add("write-sector");
            expectedVerbs.Add("read-sector");
        }

        expectedVerbs.Add("read-sector"); // the late full misc fresh read
        expectedVerbs.Add("write-sector");
        expectedVerbs.Add("read-sector");
        expectedVerbs.Add("reset");

        Assert.Equal(expectedVerbs, mutations.Select(command => Arguments(command)[0]).ToList());

        // Every actual write-sector after the initial probe/preflight/capture must carry an observer, and so
        // must its immediately following readback. This proves the observed overloads are used at the actual
        // write execution call sites even though the old fake emits no live stream events. The fresh misc
        // read, the reset and everything before the first write are deliberately not covered.
        for (int index = 0; index < mutations.Count; index++)
        {
            if (Arguments(mutations[index])[0] != "write-sector")
            {
                continue;
            }

            Assert.NotNull(mutations[index].OutputReceived);
            Assert.True(index + 1 < mutations.Count);
            Assert.Equal("read-sector", Arguments(mutations[index + 1])[0]);
            Assert.NotNull(mutations[index + 1].OutputReceived);
        }

        Assert.Equal(saharaCountBefore, runner.SaharaResponseCount);
        Assert.Equal(1, runner.SaharaResponseCount);

        AssertDirectProgress(progress.Records, gptRegions, board, contract, bootB, bootA, miscWrite, metadataRegions);
        AssertExecutionEvidenceTransfers(prepared.EvidenceDirectory, runner.Writes.Count);

        // There is no acceptance handoff on this route: a terminal run refuses the read-only check, the
        // snapshot/result stay the terminal facts and no EDL, write, reset, native or adb work is replayed.
        InternalInstallSnapshot completedSnapshot = session.Backend.Snapshot;
        int commandsAfterExecute = runner.Commands.Count;
        int writesAfterExecute = runner.Writes.Count;
        int resetsAfterExecute = runner.ResetCount;
        int nativeAfterExecute = session.NativeCommandCount;
        int adbAfterExecute = android.CommandCount;
        Assert.Equal(0, adbAfterExecute);

        await Assert.ThrowsAsync<InvalidOperationException>(() => session.Backend.CheckAcceptanceAsync());

        Assert.Equal(InternalInstallStage.InstallationCompleted, completedSnapshot.Stage);
        Assert.Equal(InternalInstallOutcome.InstallationCompleted, completedSnapshot.Outcome);
        Assert.Equal(completedSnapshot.Stage, session.Backend.Snapshot.Stage);
        Assert.Equal(completedSnapshot.Outcome, session.Backend.Snapshot.Outcome);
        Assert.Equal(InternalInstallWriteState.AllVerified, session.Backend.Snapshot.WriteState);
        Assert.Equal(InternalInstallOutcome.InstallationCompleted, result.Outcome);
        Assert.Equal(InternalInstallStage.WritingMisc, result.LastVerifiedStage);
        Assert.Null(result.AndroidAcceptance);
        Assert.False(result.LinuxAcceptanceVerified);

        Assert.Equal(commandsAfterExecute, runner.Commands.Count);
        Assert.Equal(writesAfterExecute, runner.Writes.Count);
        Assert.Equal(resetsAfterExecute, runner.ResetCount);
        Assert.Equal(1, runner.ResetCount);
        Assert.Equal(nativeAfterExecute, session.NativeCommandCount);
        Assert.Equal(6, session.NativeCommandCount);
        Assert.Equal(adbAfterExecute, android.CommandCount);
        Assert.Equal(0, android.CommandCount);
    }

    // ------------------------------------------------------------------ case 2: boot B readback fault

    [Fact]
    public async Task Boot_b_readback_failure_stops_unknown_before_a_misc_or_reset()
    {
        var android = new ReadOnlyAndroidResponder();
        using DirectInstallReadyTestSession session = await DirectInstallReadyTestSession.CreateAsync(
            _toolchain, _rawShared, "a", android);

        IB001FakeEdlRunner runner = session.EdlRunner;
        InternalInstallPrepared prepared = session.Backend.Prepared;

        Assert.Equal(6, session.NativeCommandCount);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);

        EdlCapturedRegion bootB = session.Backup.Files["boot_b"];
        EdlCapturedRegion bootA = session.Backup.Files["boot_a"];
        EdlCapturedRegion misc = session.Backup.Files["misc"];
        IReadOnlyList<InternalArtifactRegion> gptRegions = session.Artifacts.GptWriteRegions;
        InternalArtifactRegion board = session.Artifacts.BoardSummary;
        EdlRawPackageContract contract = PackageReader.ReadEdlRawContract(
            session.Package.PackageDirectory, session.Package.DeviceModel);

        // The fault is armed only for the exact full boot_b target; the write is still acknowledged first.
        runner.InjectReadbackFailureOnce(bootB.Lun, bootB.StartSector, bootB.SectorCount);
        int commandsBeforeExecute = runner.Commands.Count;

        var progress = new InlineProgress();
        InternalInstallResult result = await session.Backend.ExecuteAsync(
            prepared.ConfirmationId, userdataEraseConfirmed: true, progress);

        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, result.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, result.WriteState);
        Assert.Empty(result.VerifiedSlots);
        Assert.Equal(InternalInstallStage.WritingLinuxRoot, result.LastVerifiedStage);
        Assert.False(result.LinuxAcceptanceVerified);
        Assert.Null(result.AndroidAcceptance);
        Assert.NotEqual(InternalInstallOutcome.Completed, result.Outcome);
        Assert.NotEqual(InternalInstallOutcome.Failed, result.Outcome);

        Assert.Equal(8, runner.Writes.Count);
        Assert.Equal(0, runner.ResetCount);
        Assert.Equal(6, session.NativeCommandCount);
        Assert.Equal(InternalInstallWriteState.Unknown, session.Backend.Snapshot.WriteState);
        Assert.Equal(InternalInstallStage.WritingBootB, session.Backend.Snapshot.Stage);
        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, session.Backend.Snapshot.Outcome);

        IReadOnlyList<IB001Write> writes = runner.Writes;
        for (int index = 0; index < gptRegions.Count; index++)
        {
            AssertWriteCovers(writes[index], gptRegions[index]);
        }

        AssertWriteCovers(writes[4], board);

        long bootSectors = contract.BootImage.ExpandedBytes / contract.BootImage.SectorSize;
        long rootSectors = contract.RootImage.ExpandedBytes / contract.RootImage.SectorSize;
        Assert.Equal(session.Artifacts.LinuxBoot.StartSector, writes[5].StartSector);
        Assert.Equal(bootSectors, writes[5].SectorCount);
        AssertShaEqual(contract.BootImage.ExpandedSha256, writes[5].Sha256);
        Assert.Equal(session.Artifacts.LinuxRoot.StartSector, writes[6].StartSector);
        Assert.Equal(rootSectors, writes[6].SectorCount);
        AssertShaEqual(contract.RootImage.ExpandedSha256, writes[6].Sha256);

        IB001Write bootBWrite = writes[7];
        AssertWriteCovers(bootBWrite, bootB);
        Assert.False(string.Equals(bootB.Sha256, bootBWrite.Sha256, StringComparison.OrdinalIgnoreCase));

        Assert.DoesNotContain(writes, write =>
            write.Lun == bootA.Lun
            && write.StartSector == bootA.StartSector
            && write.SectorCount == bootA.SectorCount);
        Assert.DoesNotContain(writes, write =>
            write.Lun == misc.Lun
            && write.StartSector == misc.StartSector);

        IB001Read lastRead = runner.Reads[runner.Reads.Count - 1];
        Assert.Equal(bootB.Lun, lastRead.Lun);
        Assert.Equal(bootB.StartSector, lastRead.StartSector);
        Assert.Equal(bootB.SectorCount, lastRead.SectorCount);

        Assert.DoesNotContain(
            runner.Commands.Skip(commandsBeforeExecute),
            command => Arguments(command)[0] == "reset");

        InternalInstallProgress bootBStarted = Assert.Single(
            progress.Records.Where(record =>
                record.Stage == InternalInstallStage.WritingBootB
                && record.Kind == InternalInstallProgressKind.Started));
        Assert.Equal(InternalInstallWriteState.Unknown, bootBStarted.WriteState);
        Assert.Equal("b", bootBStarted.Slot);
        Assert.DoesNotContain(progress.Records, record =>
            record.Stage == InternalInstallStage.WritingBootB
            && record.Kind == InternalInstallProgressKind.Verified);
        Assert.DoesNotContain(progress.Records, record =>
            record.Stage == InternalInstallStage.WritingBootA
            || record.Stage == InternalInstallStage.WritingMisc
            || record.Stage == InternalInstallStage.BootingAndroid
            || record.Stage == InternalInstallStage.CheckingAndroid);
        Assert.DoesNotContain(progress.Records, record => record.Stage == InternalInstallStage.Completed);
        Assert.DoesNotContain(
            progress.Records, record => record.Stage == InternalInstallStage.Restarting);
        Assert.DoesNotContain(
            progress.Records, record => record.Stage == InternalInstallStage.InstallationCompleted);
        Assert.DoesNotContain(progress.Records, record => ForbiddenStages.Contains(record.Stage));

        Assert.NotEqual(InternalInstallOutcome.InstallationCompleted, result.Outcome);
        Assert.NotEqual(InternalInstallStage.InstallationCompleted, session.Backend.Snapshot.Stage);
        Assert.NotEqual(InternalInstallOutcome.InstallationCompleted, session.Backend.Snapshot.Outcome);

        // Nothing retried or replayed: no acceptance query and no additional execution is attempted.
        Assert.Equal(0, android.CommandCount);
        Assert.Empty(result.VerifiedSlots);
        Assert.Null(session.Backend.LastResult?.AndroidAcceptance);
    }

    // ------------------------------------------------------------------ case 3: reset response refused or thrown

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Direct_reset_refusal_or_failure_stops_unknown_without_a_terminal_completion(
        bool throwIoException)
    {
        var android = new ReadOnlyAndroidResponder();
        using DirectInstallReadyTestSession session = await DirectInstallReadyTestSession.CreateAsync(
            _toolchain, _rawShared, "a", android);

        IB001FakeEdlRunner runner = session.EdlRunner;
        InternalInstallPrepared prepared = session.Backend.Prepared;
        InternalInstallSnapshot preparedSnapshot = session.Backend.Snapshot;

        Assert.Equal(6, session.NativeCommandCount);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        Assert.False(preparedSnapshot.ExecutionStarted);

        // The one reset is the last mutation, and its response is either a refusal result or a failed
        // transport call; both leave the same unproven outcome behind.
        runner.ResetOverride = throwIoException
            ? () => throw new IOException("synthetic reset transport failure")
            : () => new ProcessResult(0, string.Empty, "synthetic reset was not accepted");

        int commandsBeforeExecute = runner.Commands.Count;
        var progress = new InlineProgress();

        InternalInstallResult result = await session.Backend.ExecuteAsync(
            prepared.ConfirmationId, userdataEraseConfirmed: true, progress);

        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, result.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, result.WriteState);
        Assert.Equal(new List<string> { "b", "a" }, result.VerifiedSlots.ToList());
        Assert.Equal(InternalInstallStage.WritingMisc, result.LastVerifiedStage);
        Assert.Null(result.AndroidAcceptance);
        Assert.False(result.LinuxAcceptanceVerified);
        Assert.NotEqual(InternalInstallOutcome.Failed, result.Outcome);
        Assert.NotEqual(InternalInstallOutcome.Completed, result.Outcome);
        Assert.NotEqual(InternalInstallOutcome.InstallationCompleted, result.Outcome);

        // All sixteen writes were issued and read back before the one reset attempt, including the six
        // verified metadata writes.
        AssertSingleResetAndNativeCount(session, runner, 16, 1, 6);
        Assert.Equal(1, runner.SaharaResponseCount);
        Assert.Equal(0, android.CommandCount);

        List<ProcessCommand> commands = runner.Commands.Skip(commandsBeforeExecute).ToList();
        int firstWrite = commands.FindIndex(command => Arguments(command)[0] == "write-sector");
        Assert.True(firstWrite >= 0, "the direct execution must issue a write-sector command");
        List<ProcessCommand> mutations = commands.Skip(firstWrite).ToList();
        Assert.Equal("reset", Arguments(mutations[mutations.Count - 1])[0]);
        Assert.Equal(1, mutations.Count(command => Arguments(command)[0] == "reset"));

        Assert.NotEqual(InternalInstallStage.InstallationCompleted, session.Backend.Snapshot.Stage);
        Assert.Equal(InternalInstallWriteState.Unknown, session.Backend.Snapshot.WriteState);
        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, session.Backend.Snapshot.Outcome);

        Assert.DoesNotContain(
            progress.Records, record => record.Stage == InternalInstallStage.InstallationCompleted);
        Assert.DoesNotContain(progress.Records, record => record.Stage == InternalInstallStage.Completed);

        // Neither a second execution nor an acceptance check is allowed; nothing is replayed.
        int commandsAfterExecute = runner.Commands.Count;
        int writesAfterExecute = runner.Writes.Count;
        int resetsAfterExecute = runner.ResetCount;
        int nativeAfterExecute = session.NativeCommandCount;
        int adbAfterExecute = android.CommandCount;

        await Assert.ThrowsAsync<InvalidOperationException>(() => session.Backend.ExecuteAsync(
            prepared.ConfirmationId, userdataEraseConfirmed: true, progress));
        await Assert.ThrowsAsync<InvalidOperationException>(() => session.Backend.CheckAcceptanceAsync());

        Assert.Equal(commandsAfterExecute, runner.Commands.Count);
        Assert.Equal(writesAfterExecute, runner.Writes.Count);
        Assert.Equal(resetsAfterExecute, runner.ResetCount);
        Assert.Equal(1, runner.ResetCount);
        Assert.Equal(nativeAfterExecute, session.NativeCommandCount);
        Assert.Equal(adbAfterExecute, android.CommandCount);
        Assert.Equal(0, android.CommandCount);
    }

    // ------------------------------------------------------------------ assertions

    private static void AssertDirectProgress(
        IReadOnlyList<InternalInstallProgress> records,
        IReadOnlyList<InternalArtifactRegion> gptRegions,
        InternalArtifactRegion board,
        EdlRawPackageContract contract,
        EdlCapturedRegion bootB,
        EdlCapturedRegion bootA,
        IB001Write miscWrite,
        IReadOnlyList<EdlCapturedRegion> metadataRegions)
    {
        Assert.NotEmpty(records);
        Assert.DoesNotContain(records, record => record.Stage == InternalInstallStage.Completed);
        Assert.DoesNotContain(records, record => ForbiddenStages.Contains(record.Stage));

        foreach (InternalInstallProgress record in records)
        {
            if (!RawWriteStages.Contains(record.Stage))
            {
                continue;
            }

            if (record.Kind == InternalInstallProgressKind.Started)
            {
                Assert.Equal(InternalInstallWriteState.Unknown, record.WriteState);
                Assert.Equal(0, record.CompletedBytes);
                Assert.True(record.TotalBytes > 0);
            }
            else if (record.Kind == InternalInstallProgressKind.Verified)
            {
                Assert.Equal(InternalInstallWriteState.AllVerified, record.WriteState);
                Assert.True(record.TotalBytes > 0);
                Assert.Equal(record.TotalBytes, record.CompletedBytes);
            }
            else if (record.Kind == InternalInstallProgressKind.Progress)
            {
                // An observation never claims the whole phase: the proof counters stay at their started
                // values, and the observation never clears the unknown proof state.
                Assert.Equal(InternalInstallWriteState.Unknown, record.WriteState);
                Assert.Equal(0, record.CompletedBytes);
                Assert.True(record.TotalBytes > 0);

                Assert.True(record.IoPhase.HasValue);
                Assert.True(record.IoTotalBytes.HasValue);
                Assert.True(record.IoTotalBytes.Value > 0);

                if (record.IoPhase.Value == InternalInstallIoPhase.Writing
                    || record.IoPhase.Value == InternalInstallIoPhase.ReadingBack)
                {
                    Assert.True(record.IoCompletedBytes.HasValue);
                    Assert.InRange(
                        record.IoCompletedBytes.Value,
                        0L,
                        record.IoTotalBytes.Value);
                }
                else
                {
                    // The hash/check phases are explicitly indeterminate.
                    Assert.Null(record.IoCompletedBytes);
                }
            }
        }

        Assert.Equal(
            gptRegions.Select(region => region.Length).ToArray(),
            VerifiedTotals(records, InternalInstallStage.WritingGpt));
        Assert.Equal(
            new[] { board.Length },
            VerifiedTotals(records, InternalInstallStage.WritingBoardBackup));
        Assert.Equal(
            new[] { contract.BootImage.ExpandedBytes },
            VerifiedTotals(records, InternalInstallStage.WritingLinuxBoot));
        Assert.Equal(
            new[] { contract.RootImage.ExpandedBytes },
            VerifiedTotals(records, InternalInstallStage.WritingLinuxRoot));
        Assert.Equal(
            new[] { bootB.Length },
            VerifiedTotals(records, InternalInstallStage.WritingBootB));
        Assert.Equal(
            new[] { bootA.Length },
            VerifiedTotals(records, InternalInstallStage.WritingBootA));
        Assert.Equal(
            metadataRegions.Select(region => region.Length).ToArray(),
            VerifiedTotals(records, InternalInstallStage.WritingAvbMetadata));
        Assert.Equal(
            new[] { miscWrite.SectorCount * (long)RawSectorSize },
            VerifiedTotals(records, InternalInstallStage.WritingMisc));

        // The two unique four-phase raw stages must report every transport phase before their own Verified
        // report, and their observed transport totals must be the exact expanded image sizes. The four GPT
        // writes share one stage, so no grouping framework is invented for them here.
        AssertIoPhasesBeforeFirstVerified(
            records,
            InternalInstallStage.WritingLinuxBoot,
            contract.BootImage.ExpandedBytes);
        AssertIoPhasesBeforeFirstVerified(
            records,
            InternalInstallStage.WritingLinuxRoot,
            contract.RootImage.ExpandedBytes);

        // The accepted reset is reported as Started only; an accepted reset request is not a boot identity.
        // The final InstallationCompleted progress report, when present, never advances LastVerifiedStage.
        Assert.Contains(records, record =>
            record.Stage == InternalInstallStage.Restarting
            && record.Kind == InternalInstallProgressKind.Started);
        Assert.DoesNotContain(records, record =>
            record.Stage == InternalInstallStage.Restarting
            && record.Kind == InternalInstallProgressKind.Verified);
        Assert.DoesNotContain(records, record => record.Stage == InternalInstallStage.BootingAndroid);
        Assert.DoesNotContain(records, record => record.Stage == InternalInstallStage.CheckingAndroid);
    }

    private static long[] VerifiedTotals(
        IReadOnlyList<InternalInstallProgress> records,
        InternalInstallStage stage) =>
        records
            .Where(record =>
                record.Stage == stage && record.Kind == InternalInstallProgressKind.Verified)
            .Select(record => record.TotalBytes)
            .ToArray();

    private static void AssertIoPhasesBeforeFirstVerified(
        IReadOnlyList<InternalInstallProgress> records,
        InternalInstallStage stage,
        long expectedTotalBytes)
    {
        int firstVerified = -1;
        for (int index = 0; index < records.Count; index++)
        {
            if (records[index].Stage == stage
                && records[index].Kind == InternalInstallProgressKind.Verified)
            {
                firstVerified = index;
                break;
            }
        }

        Assert.True(firstVerified >= 0, "the stage must report its own Verified record");

        List<InternalInstallProgress> observed = records
            .Take(firstVerified)
            .Where(record =>
                record.Stage == stage && record.Kind == InternalInstallProgressKind.Progress)
            .ToList();

        foreach (InternalInstallIoPhase phase in new[]
                 {
                     InternalInstallIoPhase.CheckingPayload,
                     InternalInstallIoPhase.Writing,
                     InternalInstallIoPhase.ReadingBack,
                     InternalInstallIoPhase.CheckingReadback,
                 })
        {
            Assert.Contains(observed, record => record.IoPhase == phase);
        }

        foreach (InternalInstallProgress record in observed)
        {
            Assert.True(record.IoTotalBytes.HasValue);
            Assert.Equal(expectedTotalBytes, record.IoTotalBytes.Value);
        }
    }

    private static void AssertExecutionEvidenceTransfers(
        string evidenceDirectory,
        int expectedWrites)
    {
        string[] writeStdout = Directory.GetFiles(
            evidenceDirectory,
            "*-write-*.transfer.stdout.log",
            SearchOption.TopDirectoryOnly);
        string[] readbackStdout = Directory.GetFiles(
            evidenceDirectory,
            "*-readback-*.transfer.stdout.log",
            SearchOption.TopDirectoryOnly);
        string[] writeStderr = Directory.GetFiles(
            evidenceDirectory,
            "*-write-*.transfer.stderr.log",
            SearchOption.TopDirectoryOnly);
        string[] readbackStderr = Directory.GetFiles(
            evidenceDirectory,
            "*-readback-*.transfer.stderr.log",
            SearchOption.TopDirectoryOnly);

        Assert.Equal(expectedWrites, writeStdout.Length);
        Assert.Equal(expectedWrites, readbackStdout.Length);
        Assert.Equal(expectedWrites, writeStderr.Length);
        Assert.Equal(expectedWrites, readbackStderr.Length);

        foreach (string file in writeStdout)
        {
            Assert.Contains(
                "Program operation successful (final ACK received).",
                File.ReadAllText(file));
        }

        foreach (string file in readbackStdout)
        {
            Assert.Contains(
                "Final ACK received for Read operation.",
                File.ReadAllText(file));
        }
    }

    private static void AssertSingleResetAndNativeCount(
        DirectInstallReadyTestSession session,
        IB001FakeEdlRunner runner,
        int expectedWrites,
        int expectedResets,
        int expectedNativeCommands)
    {
        Assert.Equal(expectedWrites, runner.Writes.Count);
        Assert.Equal(expectedResets, runner.ResetCount);
        Assert.Equal(1, runner.ResetCount);
        Assert.Equal(expectedNativeCommands, session.NativeCommandCount);
        Assert.Equal(6, session.NativeCommandCount);
    }

    private static void AssertWriteCovers(
        IB001Write write,
        InternalArtifactRegion region)
    {
        Assert.Equal(region.Lun, write.Lun);
        Assert.Equal(region.StartSector, write.StartSector);
        Assert.Equal(region.SectorCount, write.SectorCount);
        Assert.Equal(region.Length, new FileInfo(write.FilePath).Length);
        AssertShaEqual(region.Sha256, write.Sha256);
    }

    private static void AssertWriteCovers(
        IB001Write write,
        EdlCapturedRegion region)
    {
        Assert.Equal(region.Lun, write.Lun);
        Assert.Equal(region.StartSector, write.StartSector);
        Assert.Equal(region.SectorCount, write.SectorCount);
        Assert.Equal(region.Length, new FileInfo(write.FilePath).Length);
    }

    private static void AssertShaEqual(string expected, string actual)
    {
        Assert.False(string.IsNullOrWhiteSpace(expected));
        Assert.Equal(expected, actual, ignoreCase: true);
    }

    private static void AssertEqualRange(byte[] actual, int offset, int endExclusive, byte[] expected)
    {
        for (int index = offset; index < endExclusive; index++)
        {
            Assert.Equal(expected[index], actual[index]);
        }
    }

    private static void AssertEqualRange(byte[] actual, int offset, int endExclusive, byte value)
    {
        for (int index = offset; index < endExclusive; index++)
        {
            Assert.Equal(value, actual[index]);
        }
    }

    private static byte DistinctSentinel(byte original, params byte[] avoid)
    {
        byte candidate = 0xA5;
        while (candidate == original || Array.IndexOf(avoid, candidate) >= 0)
        {
            candidate = unchecked((byte)(candidate + 1));
        }

        return candidate;
    }

    private static string[] Arguments(ProcessCommand command) => command.Arguments.ToArray();

    // ------------------------------------------------------------------ read-only Android responder

    private enum AndroidDeviceState
    {
        Unauthorized,
        Authorized,
        Absent,
    }

    /// <summary>
    /// Strict read-only adb double. It answers only the exact argv shapes built by
    /// <see cref="InternalInstallAcceptance"/> and <see cref="AdbAndroidUninstallAcceptanceProbe"/>, with the
    /// literal <c>test-adb</c> executable and the fixed 15 second timeout, and throws on anything else.
    /// It never starts a process and never changes a device.
    /// </summary>
    private sealed class ReadOnlyAndroidResponder : ICommandRunner
    {
        private readonly List<string> _commands = new();

        private string _fullGetprop = string.Empty;

        public AndroidDeviceState DeviceState { get; set; } = AndroidDeviceState.Unauthorized;

        public string BootCompleted { get; set; } = "0";

        public int CommandCount => _commands.Count;

        public IReadOnlyList<string> Commands => _commands;

        public string Serial { get; private set; } = string.Empty;

        public string Model { get; private set; } = string.Empty;

        public string SocSerial { get; private set; } = string.Empty;

        public string SlotSuffix { get; private set; } = string.Empty;

        public int UserdataPartitionNumber { get; private set; }

        public long ExpectedPartitionBytes { get; private set; }

        public long DataFilesystemBytes { get; private set; }

        public long MinimumDataFilesystemBytes => ReadOnlyAndroidResponder.MinimumAcceptedDataBytes;

        private static long MinimumAcceptedDataBytes => 1L << 30;

        public void ConfigureFacts(
            InternalInstallPrepared prepared,
            InternalArtifactSet artifacts,
            string model)
        {
            ArgumentNullException.ThrowIfNull(prepared);
            ArgumentNullException.ThrowIfNull(artifacts);

            Serial = prepared.AndroidSerial;
            SocSerial = prepared.SocSerial;
            SlotSuffix = "_" + prepared.CurrentSlot;
            Model = model;

            FirmwareSnapshot firmware = prepared.Firmware;
            _fullGetprop =
                "[ro.product.model]: [" + Model + "]\n"
                + "[ro.product.vendor.model]: [" + Model + "]\n"
                + "[ro.product.name]: [" + Model + "]\n"
                + "[ro.build.display.id]: [" + firmware.DisplayId + "]\n"
                + "[ro.build.fingerprint]: [" + firmware.BuildFingerprint + "]\n"
                + "[ro.build.version.release]: [" + firmware.AndroidRelease + "]\n"
                + "[ro.build.version.security_patch]: [" + firmware.SecurityPatch + "]\n"
                + "[ro.boot.flash.locked]: [0]\n"
                + "[ro.boot.vbmeta.device_state]: [unlocked]\n"
                + "[ro.serialno]: [" + Serial + "]\n"
                + "[ro.boot.serialno]: [" + Serial + "]\n"
                + "[ro.boot.slot_suffix]: [" + SlotSuffix + "]\n";

            UserdataPartitionNumber = artifacts.Allocation.OriginalUserdata.Number;
            ExpectedPartitionBytes = artifacts.Allocation.AndroidBytes;

            // A real /data filesystem is smaller than its partition; 97% stays inside the production
            // 95%..100% policy and above the fixed 1 GiB floor.
            long dataKib = ExpectedPartitionBytes / 1024 * 97 / 100;
            DataFilesystemBytes = dataKib * 1024;
            if (DataFilesystemBytes < MinimumAcceptedDataBytes)
            {
                DataFilesystemBytes = MinimumAcceptedDataBytes;
            }
        }

        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(command);
            cancellationToken.ThrowIfCancellationRequested();

            if (!string.Equals(command.Executable, Adb, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Unexpected adb executable: " + command.Executable);
            }

            if (command.Timeout != AdbTimeout)
            {
                throw new InvalidOperationException("Every read-only adb query must use the fixed 15 second timeout.");
            }

            string[] arguments = Arguments(command);
            _commands.Add(command.Executable + " " + string.Join(" ", arguments));

            if (arguments.Length == 2
                && arguments[0] == "devices"
                && arguments[1] == "-l")
            {
                return Task.FromResult(Result(DeviceListing()));
            }

            if (arguments.Length < 4
                || arguments[0] != "-s"
                || !string.Equals(arguments[1], Serial, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The read-only acceptance queried an unexpected serial or argv: "
                    + string.Join(" ", arguments));
            }

            if (arguments.Length == 4
                && arguments[2] == "shell"
                && arguments[3] == "getprop")
            {
                return Task.FromResult(Result(_fullGetprop));
            }

            if (arguments.Length == 5
                && arguments[2] == "shell"
                && arguments[3] == "getprop")
            {
                return Task.FromResult(Result(arguments[4] switch
                {
                    "sys.boot_completed" => BootCompleted,
                    "ro.product.model" => Model,
                    "ro.serialno" => Serial,
                    "ro.boot.serialno" => Serial,
                    "ro.boot.slot_suffix" => SlotSuffix,
                    _ => throw new InvalidOperationException("Unexpected getprop: " + arguments[4]),
                }));
            }

            if (arguments.Length == 5
                && arguments[2] == "shell"
                && arguments[3] == "cat"
                && arguments[4] == "/sys/devices/soc0/serial_number")
            {
                return Task.FromResult(Result(SocSerial));
            }

            string sysfsPath = "/sys/class/block/sda"
                + UserdataPartitionNumber.ToString(CultureInfo.InvariantCulture)
                + "/size";
            if (arguments.Length == 5
                && arguments[2] == "shell"
                && arguments[3] == "cat"
                && arguments[4] == sysfsPath)
            {
                return Task.FromResult(Result(
                    (ExpectedPartitionBytes / AdbAndroidUninstallAcceptanceProbe.SysfsUnitBytes)
                    .ToString(CultureInfo.InvariantCulture)));
            }

            if (arguments.Length == 6
                && arguments[2] == "shell"
                && arguments[3] == "readlink"
                && arguments[4] == "-f"
                && arguments[5] == AdbAndroidUninstallAcceptanceProbe.UserdataByNamePath)
            {
                return Task.FromResult(Result(
                    "/dev/block/sda" + UserdataPartitionNumber.ToString(CultureInfo.InvariantCulture)));
            }

            if (arguments.Length == 7
                && arguments[2] == "shell"
                && arguments[3] == "-T"
                && arguments[4] == "df"
                && arguments[5] == "-k"
                && arguments[6] == "/data")
            {
                long totalKib = DataFilesystemBytes / 1024;
                long usedKib = Math.Min(100_000L, totalKib / 10);
                return Task.FromResult(Result(
                    "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                    + "/dev/block/sda" + UserdataPartitionNumber.ToString(CultureInfo.InvariantCulture)
                    + " " + totalKib.ToString(CultureInfo.InvariantCulture)
                    + " " + usedKib.ToString(CultureInfo.InvariantCulture)
                    + " " + (totalKib - usedKib).ToString(CultureInfo.InvariantCulture)
                    + " 1% /data\n"));
            }

            throw new InvalidOperationException("Unexpected adb command: " + string.Join(" ", arguments));
        }

        private string DeviceListing()
        {
            const string Header = "List of devices attached\n";

            return DeviceState switch
            {
                AndroidDeviceState.Unauthorized => Header + Row("unauthorized"),
                AndroidDeviceState.Authorized => Header + Row("device"),
                AndroidDeviceState.Absent => Header + "\n",
                _ => throw new InvalidOperationException("Unknown Android device state."),
            };
        }

        private string Row(string state) =>
            Serial + "\t" + state + " usb:1-1 product:" + Model + " model:" + Model
            + " device:" + Model + " transport_id:1\n";

        private static ProcessResult Result(string output) => new(0, output, string.Empty);
    }

    // ------------------------------------------------------------------ inline progress

    private sealed class InlineProgress : IProgress<InternalInstallProgress>
    {
        private readonly List<InternalInstallProgress> _records = new();

        public IReadOnlyList<InternalInstallProgress> Records => _records;

        public void Report(InternalInstallProgress value)
        {
            ArgumentNullException.ThrowIfNull(value);
            _records.Add(value);
        }
    }
}
