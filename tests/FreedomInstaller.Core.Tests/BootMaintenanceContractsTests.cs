using System;
using System.Collections.Generic;
using System.Reflection;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural contract for the BM01 boot-maintenance model.
/// <para>
/// Every constructor of the model is internal and this project has no test-only factory, so the tests reach
/// the constructors through the non-public activator - the same route the other contract fixtures use. Each
/// assertion is about a truth rule of the model: defensive copying, exact slot identity, usable geometry,
/// outcome/write-state alignment and the fact that a completed operation still awaits Android acceptance.
/// </para>
/// </summary>
public sealed class BootMaintenanceContractsTests
{
    private const string HashA =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private const string HashB =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void Prepared_CopiesBothListsAndRefusesLaterMutation()
    {
        var slots = new List<BootMaintenanceSlotSummary> { Slot("a"), Slot("b") };
        var regions = new List<BootMaintenanceRegionSummary> { Region() };

        var prepared = Prepared(slots: slots, regions: regions);

        slots.Clear();
        regions.Clear();
        regions.Add(Region(role: "boot_b"));

        Assert.Equal(2, prepared.Slots.Count);
        Assert.Single(prepared.Regions);
        Assert.Equal("a", prepared.Slots[0].Slot);
        Assert.Equal("boot_a", prepared.Regions[0].Role);

        Assert.True(((ICollection<BootMaintenanceSlotSummary>)prepared.Slots).IsReadOnly);
        Assert.Throws<NotSupportedException>(
            () => ((IList<BootMaintenanceSlotSummary>)prepared.Slots).Add(Slot("b")));
        Assert.Throws<NotSupportedException>(
            () => ((IList<BootMaintenanceRegionSummary>)prepared.Regions).Add(Region()));
    }

    [Fact]
    public void Prepared_AcceptsSlotBAndRetainsDeviceFactsExactly()
    {
        var prepared = Prepared(
            confirmationId: "confirmation-b",
            model: "TB323FU",
            androidSerial: "ANDROID-B",
            socSerial: "SOC-B",
            currentSlot: "b",
            backupDirectory: @"D:\backup-b",
            evidenceDirectory: @"D:\evidence-b",
            bootTrust: BootMaintenanceBootTrust.GblPreserveOem,
            slots: new[] { Slot("b", "b"), Slot("a", "a") });

        Assert.Equal(MaintenanceMode.BeforeUpdate, prepared.Mode);
        Assert.Equal(BootMaintenanceBootTrust.GblPreserveOem, prepared.BootTrustMode);
        Assert.Equal("confirmation-b", prepared.ConfirmationId);
        Assert.Equal("TB323FU", prepared.Model);
        Assert.Equal("ANDROID-B", prepared.AndroidSerial);
        Assert.Equal("SOC-B", prepared.SocSerial);
        Assert.Equal("b", prepared.CurrentSlot);
        Assert.Equal(@"D:\backup-b", prepared.BackupDirectory);
        Assert.Equal(@"D:\evidence-b", prepared.EvidenceDirectory);

        // The declared b, a order is preserved: this layer never reorders or rejects it.
        Assert.Equal("b", prepared.Slots[0].Slot);
        Assert.Equal("a", prepared.Slots[1].Slot);
    }

    [Theory]
    [InlineData("A")]
    [InlineData("c")]
    [InlineData("")]
    [InlineData(" b")]
    public void Prepared_RejectsNonExactCurrentSlot(string currentSlot)
    {
        Rejects(() => Prepared(currentSlot: currentSlot));
    }

    [Theory]
    [InlineData("c", "a")]
    [InlineData("a", "C")]
    [InlineData("", "a")]
    [InlineData("a/b", "b")]
    public void SlotSummary_RejectsUnsupportedSlotIdentity(string slot, string sourceSlot)
    {
        Rejects(() => Slot(slot, sourceSlot));
    }

    [Theory]
    [InlineData(0, -1L, 10L, 5120L)]
    [InlineData(0, 0L, 0L, 5120L)]
    [InlineData(0, 0L, 10L, 0L)]
    [InlineData(0, 0L, -10L, 5120L)]
    [InlineData(-1, 0L, 10L, 5120L)]
    public void RegionSummary_RejectsUnusableGeometry(
        int lun,
        long startSector,
        long sectorCount,
        long length)
    {
        Rejects(() => Region(
            lun: lun,
            startSector: startSector,
            sectorCount: sectorCount,
            length: length));
    }

    [Fact]
    public void Result_CompletedRequiresAllVerifiedWrites()
    {
        foreach (var writeState in new[]
                 {
                     InternalInstallWriteState.NoneIssued,
                     InternalInstallWriteState.PartiallyVerified,
                     InternalInstallWriteState.Unknown,
                 })
        {
            Rejects(() => Result(writeState: writeState));
        }
    }

    [Fact]
    public void Result_AwaitingAndroidAcceptanceOnlyForCompleted()
    {
        Rejects(() => Result(outcome: BootMaintenanceOutcome.Failed, awaitingAndroidAcceptance: true));
        Rejects(() => Result(outcome: BootMaintenanceOutcome.Cancelled, awaitingAndroidAcceptance: true));
        Rejects(() => Result(awaitingAndroidAcceptance: false));

        var completed = Result();

        Assert.Equal(BootMaintenanceOutcome.Completed, completed.Outcome);
        Assert.Equal(InternalInstallWriteState.AllVerified, completed.WriteState);
        Assert.True(completed.AwaitingAndroidAcceptance);
        Assert.Null(completed.Error);
    }

    [Fact]
    public void Result_UnknownWriteOutcomeRequiresUnknownWriteState()
    {
        foreach (var writeState in new[]
                 {
                     InternalInstallWriteState.AllVerified,
                     InternalInstallWriteState.NoneIssued,
                     InternalInstallWriteState.PartiallyVerified,
                 })
        {
            Rejects(() => Result(
                outcome: BootMaintenanceOutcome.UnknownWriteOutcome,
                writeState: writeState,
                awaitingAndroidAcceptance: false));
        }

        var unknown = Result(
            outcome: BootMaintenanceOutcome.UnknownWriteOutcome,
            writeState: InternalInstallWriteState.Unknown,
            verifiedRegions: Array.Empty<string>(),
            awaitingAndroidAcceptance: false);

        Assert.Equal(BootMaintenanceOutcome.UnknownWriteOutcome, unknown.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, unknown.WriteState);
        Assert.False(unknown.AwaitingAndroidAcceptance);
    }

    [Fact]
    public void Result_CopiesVerifiedRegions()
    {
        var regions = new List<string> { "boot_a", "vbmeta_a" };

        var result = Result(verifiedRegions: regions);

        regions.Clear();
        regions.Add("boot_b");

        Assert.Equal(2, result.VerifiedRegions.Count);
        Assert.Equal("boot_a", result.VerifiedRegions[0]);
        Assert.Equal("vbmeta_a", result.VerifiedRegions[1]);
        Assert.True(((ICollection<string>)result.VerifiedRegions).IsReadOnly);
        Assert.Throws<NotSupportedException>(
            () => ((IList<string>)result.VerifiedRegions).Add("boot_b"));
    }

    [Fact]
    public void Sources_PermitNullRepairPackageForBeforeAndRestore()
    {
        var restore = new BootMaintenanceSources(OriginalBackupDirectory: @"D:\backup");
        var before = new BootMaintenanceSources(@"D:\other-backup", RepairPackage: null, BootTools: null);

        Assert.Equal(@"D:\backup", restore.OriginalBackupDirectory);
        Assert.Null(restore.RepairPackage);
        Assert.Null(restore.BootTools);
        Assert.Null(before.RepairPackage);
        Assert.Null(before.BootTools);

        // An empty source slot is a truthful fact: no original image, no candidate and nothing to write.
        var empty = Slot(
            sourceKind: BootMaintenanceSourceKind.Empty,
            originalSha256: string.Empty,
            candidateSha256: null,
            willWrite: false);

        Assert.Equal(BootMaintenanceSourceKind.Empty, empty.SourceKind);
        Assert.Null(empty.CandidateSha256);
        Assert.False(empty.WillWrite);

        var prepared = Prepared(slots: new[] { empty, Slot("b") });
        Assert.Equal(BootMaintenanceSourceKind.Empty, prepared.Slots[0].SourceKind);
        Assert.Equal(2, prepared.Slots.Count);
    }

    [Fact]
    public void Snapshot_RetainsRunningFactsWithoutOutcome()
    {
        var running = Snapshot();

        Assert.False(running.ExecutionStarted);
        Assert.Equal(InternalInstallStage.Prepared, running.Stage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, running.WriteState);
        Assert.Null(running.Outcome);
        Assert.Null(running.Error);

        var unproven = Snapshot(
            executionStarted: true,
            stage: InternalInstallStage.WritingBootA,
            writeState: InternalInstallWriteState.Unknown,
            outcome: BootMaintenanceOutcome.UnknownWriteOutcome,
            error: "readback did not complete");

        Assert.True(unproven.ExecutionStarted);
        Assert.Equal(BootMaintenanceOutcome.UnknownWriteOutcome, unproven.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, unproven.WriteState);
        Assert.Equal("readback did not complete", unproven.Error);
    }

    private static BootMaintenancePrepared Prepared(
        MaintenanceMode mode = MaintenanceMode.BeforeUpdate,
        string confirmationId = "confirmation-a",
        string model = "TB322FC",
        string androidSerial = "ANDROID-A",
        string socSerial = "SOC-A",
        string currentSlot = "a",
        string backupDirectory = @"C:\backup",
        string evidenceDirectory = @"C:\evidence",
        BootMaintenanceBootTrust bootTrust = BootMaintenanceBootTrust.StockOriginal,
        IReadOnlyList<BootMaintenanceSlotSummary>? slots = null,
        IReadOnlyList<BootMaintenanceRegionSummary>? regions = null)
        => Construct<BootMaintenancePrepared>(
            mode,
            confirmationId,
            model,
            androidSerial,
            socSerial,
            currentSlot,
            backupDirectory,
            evidenceDirectory,
            bootTrust,
            slots ?? new[] { Slot("a"), Slot("b") },
            regions ?? new[] { Region() });

    private static BootMaintenanceSlotSummary Slot(
        string slot = "a",
        string sourceSlot = "a",
        BootMaintenanceSourceKind sourceKind = BootMaintenanceSourceKind.Project,
        string originalSha256 = HashA,
        string? candidateSha256 = HashB,
        bool willWrite = true)
        => Construct<BootMaintenanceSlotSummary>(
            slot,
            sourceSlot,
            sourceKind,
            originalSha256,
            candidateSha256,
            willWrite);

    private static BootMaintenanceRegionSummary Region(
        string role = "boot_a",
        string? slot = "a",
        int lun = 4,
        long startSector = 100,
        long sectorCount = 10,
        long length = 5120,
        string originalSha256 = HashA,
        string? candidateSha256 = HashB,
        bool willWrite = true)
        => Construct<BootMaintenanceRegionSummary>(
            role,
            slot,
            lun,
            startSector,
            sectorCount,
            length,
            originalSha256,
            candidateSha256,
            willWrite);

    private static BootMaintenanceResult Result(
        BootMaintenanceOutcome outcome = BootMaintenanceOutcome.Completed,
        InternalInstallWriteState writeState = InternalInstallWriteState.AllVerified,
        IReadOnlyList<string>? verifiedRegions = null,
        string evidenceDirectory = @"C:\evidence",
        string? error = null,
        bool awaitingAndroidAcceptance = true)
        => Construct<BootMaintenanceResult>(
            outcome,
            writeState,
            verifiedRegions ?? new[] { "boot_a" },
            evidenceDirectory,
            error,
            awaitingAndroidAcceptance);

    private static BootMaintenanceSnapshot Snapshot(
        bool executionStarted = false,
        InternalInstallStage stage = InternalInstallStage.Prepared,
        InternalInstallWriteState writeState = InternalInstallWriteState.NoneIssued,
        BootMaintenanceOutcome? outcome = null,
        string? error = null)
        => Construct<BootMaintenanceSnapshot>(
            executionStarted,
            stage,
            writeState,
            outcome,
            error);

    private static T Construct<T>(params object?[] arguments)
        => (T)Activator.CreateInstance(
            typeof(T),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: arguments,
            culture: null)!;

    private static ArgumentException Rejects(Action action)
    {
        var error = Assert.Throws<TargetInvocationException>(action);
        return Assert.IsAssignableFrom<ArgumentException>(error.InnerException);
    }
}
