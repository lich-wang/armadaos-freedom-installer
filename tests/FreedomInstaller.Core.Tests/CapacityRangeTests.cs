using System;
using System.Collections.Generic;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Specifications for <see cref="PartitionPlanner.GetAndroidRange"/> and <see cref="AndroidAllocationRange"/>.
/// <para>
/// The device side (KshimPlan) demands a Linux root of at least 32 GiB, so the Android share can never
/// grow past <c>userdata - 1 GiB boot - 32 GiB root</c>. The range must report exactly that interval, and
/// every reported bound must be a share <see cref="PartitionPlanner.Plan"/> itself accepts — the range and
/// the plan share one minimum-root rule instead of restating the layout checks.
/// </para>
/// <para>
/// All layouts here are synthetic and every expected value is computed independently from the byte
/// geometry (userdata GiB minus boot minus the root floor), never by mirroring planner code.
/// </para>
/// </summary>
public sealed class CapacityRangeTests
{
    private const long GiB = TestSizes.GiB;

    private const string PartitionTypeEsp = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    private const string PartitionTypeLinux = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string PartUuidSystem = "11111111-2222-3333-4444-555555555555";
    private const string PartUuidUserdata = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

    // The smallest Linux root the device accepts, independent of what the package metadata declares.
    private const long RootFloorGiB = 32;

    // ------------------------------------------------------------------ the 224 GiB ticket shape

    [Fact]
    public void Range_224GiBUserdata_Is16To191AndTheUpperBoundItselfPlans()
    {
        var layout = Layout(512, userdataGiB: 224);

        var range = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 16, TicketStorage());

        // 224 GiB userdata, 1 GiB boot and 32 GiB of mandatory root leave 191 GiB for Android.
        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(224 - 1 - RootFloorGiB, range.MaximumGiB);
        Assert.Equal(191, range.MaximumGiB);

        // Both reported bounds are shares the planner accepts, so the UI can offer them as-is.
        var lower = PartitionPlanner.Plan(layout, range.MinimumGiB, range.MinimumGiB, TicketStorage());
        Assert.Equal(16 * GiB, lower.AndroidBytes);

        var upper = PartitionPlanner.Plan(layout, range.MaximumGiB, range.MinimumGiB, TicketStorage());
        Assert.Equal(191 * GiB, upper.AndroidBytes);
        Assert.Equal(224 * GiB, upper.AndroidBytes + upper.LinuxBytes);
        Assert.Equal(1 * GiB, upper.LinuxBootBytes);
        Assert.Equal(RootFloorGiB * GiB, upper.LinuxRootBytes);
    }

    [Fact]
    public void Plan_AboveTheReportedMaximum_IsRejected()
    {
        var layout = Layout(512, userdataGiB: 224);

        // 192 GiB leaves a 31 GiB root, 193 GiB leaves 30 GiB: both are below the 32 GiB device floor
        // even though 30 GiB still covers the 20 + 2 + 8 GiB the package declares.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 192, 16, TicketStorage()));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 193, 16, TicketStorage()));
    }

    [Fact]
    public void Plan_EnforcesTheRootFloorRatherThanOnlyThePackageMinimum()
    {
        var layout = Layout(512, userdataGiB: 224);
        var storage = TicketStorage();

        Assert.Equal(30 * GiB, storage.SystemRequiredBytes + storage.DeploymentScratchBytes + storage.MinimumLinuxDataBytes);

        // Exactly 32 GiB of root is accepted; one GiB more of Android is not.
        Assert.Equal(RootFloorGiB * GiB, PartitionPlanner.Plan(layout, 191, 16, storage).LinuxRootBytes);
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 192, 16, storage));
    }

    // ------------------------------------------------------------------ larger extent

    [Fact]
    public void Range_512GiBUserdata_ReportsMaximum479()
    {
        var layout = Layout(512, userdataGiB: 512);

        var range = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 16, TicketStorage());

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(512 - 1 - RootFloorGiB, range.MaximumGiB);
        Assert.Equal(479, range.MaximumGiB);

        Assert.Equal(479 * GiB, PartitionPlanner.Plan(layout, 479, 16, TicketStorage()).AndroidBytes);
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 480, 16, TicketStorage()));
    }

    // ------------------------------------------------------------------ profile minimum

    [Fact]
    public void Range_ProfileMinimumWinsOverTheBuiltInOneGiBFloor()
    {
        var layout = Layout(512, userdataGiB: 512);

        Assert.Equal(1, PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 1, TicketStorage()).MinimumGiB);
        Assert.Equal(16, PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 16, TicketStorage()).MinimumGiB);

        var profileMinimum = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 32, TicketStorage());
        Assert.Equal(32, profileMinimum.MinimumGiB);
        Assert.Equal(479, profileMinimum.MaximumGiB);
    }

    [Fact]
    public void Range_UnconfirmedProfileMinimumIsRejected()
    {
        var layout = Layout(512, userdataGiB: 512);

        // An unknown lower bound must never be turned into a valid range: the caller cannot offer 0 GiB.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 0, TicketStorage()));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: -1, TicketStorage()));
    }

    // ------------------------------------------------------------------ package demand versus the floor

    [Fact]
    public void Range_PackageNeeding40GiBRoot_CapsMaximumAt183()
    {
        var layout = Layout(512, userdataGiB: 224);

        // 30 system + 2 scratch + 8 data = 40 GiB root, above the 32 GiB floor, so the package rules.
        var storage = new PackageStorage(1 * GiB, 30 * GiB, 2 * GiB, 8 * GiB);

        var range = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 16, storage);

        Assert.Equal(224 - 1 - 40, range.MaximumGiB);
        Assert.Equal(183, range.MaximumGiB);
        Assert.Equal(40 * GiB, PartitionPlanner.Plan(layout, 183, 16, storage).LinuxRootBytes);
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 184, 16, storage));
    }

    [Fact]
    public void Range_PackageBelowTheFloor_LeavesTheMaximumAtTheRootFloor()
    {
        var layout = Layout(512, userdataGiB: 224);

        // Only 1 + 1 + 1 = 3 GiB declared, yet the device floor of 32 GiB still governs.
        var tiny = new PackageStorage(1 * GiB, 1 * GiB, 1 * GiB, 1 * GiB);

        var range = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 16, tiny);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(191, range.MaximumGiB);
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(layout, 192, 16, tiny));
    }

    // ------------------------------------------------------------------ no room

    [Fact]
    public void Range_ThrowsWhenTheExtentCannotHostTheMinimumRootAtAll()
    {
        // 32 GiB userdata: boot plus the root floor already consume it, so no positive share is left.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 32), 1, TicketStorage()));

        // 33 GiB userdata: exactly zero GiB of Android, still unusable because the minimum must be > 0.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 33), 1, TicketStorage()));
    }

    [Fact]
    public void Range_ThrowsWhenTheProfileMinimumExceedsTheMaximum()
    {
        // The extent allows at most 191 GiB, so a 192 GiB model minimum is unsatisfiable.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 224), 192, TicketStorage()));
    }

    [Fact]
    public void Range_ProfileMinimumEqualToTheMaximumIsStillAValidRange()
    {
        var layout = Layout(512, userdataGiB: 224);

        var range = PartitionPlanner.GetAndroidRange(layout, androidMinimumGiB: 191, TicketStorage());

        Assert.Equal(191, range.MinimumGiB);
        Assert.Equal(191, range.MaximumGiB);
        Assert.Equal(191 * GiB, PartitionPlanner.Plan(layout, 191, 191, TicketStorage()).AndroidBytes);
    }

    // ------------------------------------------------------------------ sector size invariance

    [Fact]
    public void Range_Sector512AndSector4096_ReportTheSameGiBBounds()
    {
        var at512 = PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 224), 16, TicketStorage());
        var at4096 = PartitionPlanner.GetAndroidRange(Layout(4096, userdataGiB: 224), 16, TicketStorage());

        Assert.Equal(at512.MinimumGiB, at4096.MinimumGiB);
        Assert.Equal(at512.MaximumGiB, at4096.MaximumGiB);
        Assert.Equal(191, at4096.MaximumGiB);

        var plan512 = PartitionPlanner.Plan(Layout(512, userdataGiB: 224), at512.MaximumGiB, 16, TicketStorage());
        var plan4096 = PartitionPlanner.Plan(Layout(4096, userdataGiB: 224), at4096.MaximumGiB, 16, TicketStorage());

        Assert.Equal(plan512.AndroidBytes, plan4096.AndroidBytes);
        Assert.Equal(plan512.LinuxBytes, plan4096.LinuxBytes);
        Assert.Equal(plan512.LinuxRootBytes, plan4096.LinuxRootBytes);
    }

    // ------------------------------------------------------------------ untrustworthy input

    [Fact]
    public void Range_RejectsUntrustworthyLayouts()
    {
        var layout = Layout(512, userdataGiB: 224);

        var duplicateUserdata = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                layout.Partitions[0],
                layout.Partitions[1],
                layout.Partitions[1] with { Number = 3 },
            });

        Assert.Throws<InvalidOperationException>(() => PartitionPlanner.GetAndroidRange(duplicateUserdata, 16, TicketStorage()));

        var partitionAfterUserdata = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                layout.Partitions[0],
                layout.Partitions[1],
                new DiskPartition(3, "metadata", 478_150_656, 2_048, PartitionTypeLinux, PartUuidUserdata),
            });

        Assert.Throws<InvalidOperationException>(() => PartitionPlanner.GetAndroidRange(partitionAfterUserdata, 16, TicketStorage()));

        Assert.Throws<ArgumentNullException>(() => PartitionPlanner.GetAndroidRange(null!, 16, TicketStorage()));
        Assert.Throws<ArgumentNullException>(() => PartitionPlanner.GetAndroidRange(layout, 16, null!));
    }

    [Fact]
    public void Range_RejectsArithmeticOverflow()
    {
        var oversizedExtent = new DiskLayout(
            "sdb",
            512,
            new[] { new DiskPartition(1, "userdata", 0, long.MaxValue / 256, PartitionTypeLinux, PartUuidUserdata) });

        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(oversizedExtent, 16, TicketStorage()));

        // A GiB share this large cannot be converted to bytes at all.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 224), long.MaxValue, TicketStorage()));

        // The package demand overflows when summed, so the range cannot be derived.
        var overflowingStorage = new PackageStorage(1 * GiB, long.MaxValue, 1, 1);
        Assert.Throws<ArgumentException>(() => PartitionPlanner.GetAndroidRange(Layout(512, userdataGiB: 224), 16, overflowingStorage));
    }

    // ------------------------------------------------------------------ input table stays untouched

    [Fact]
    public void RangeAndPlan_DoNotReorderOrMutateTheReportedTable()
    {
        // Listed by GPT number rather than by position: userdata comes first, vendor sits before it.
        var layout = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                new DiskPartition(17, "userdata", 8_388_608, 469_762_048, PartitionTypeLinux, PartUuidUserdata),
                new DiskPartition(30, "vendor", 6_291_456, 2_097_152, PartitionTypeLinux, PartUuidSystem),
            });

        var before = layout.Partitions.ToArray();

        var range = PartitionPlanner.GetAndroidRange(layout, 16, TicketStorage());
        _ = PartitionPlanner.Plan(layout, range.MinimumGiB, range.MinimumGiB, TicketStorage());
        _ = PartitionPlanner.Plan(layout, range.MaximumGiB, range.MinimumGiB, TicketStorage());

        Assert.True(before.SequenceEqual(layout.Partitions), "the reported table must keep its original order and contents");
        Assert.Equal(2, layout.Partitions.Count);
        Assert.Equal(17L, layout.Partitions[0].Number);
        Assert.Equal(30L, layout.Partitions[1].Number);
        Assert.Equal(191, range.MaximumGiB);
    }

    // ------------------------------------------------------------------------ helpers

    private static PackageStorage TicketStorage() => new(1 * GiB, 20 * GiB, 2 * GiB, 8 * GiB);

    /// <summary>
    /// Synthetic table: one ext4 system partition at 8 MiB, then a 1 MiB aligned userdata extent that
    /// starts at 4 GiB and spans <paramref name="userdataGiB"/>. Sector counts are derived from the byte
    /// geometry, so the same GiB shape can be expressed with 512 or 4096 byte sectors.
    /// </summary>
    private static DiskLayout Layout(int sectorSize, long userdataGiB)
    {
        var systemStartSector = 8 * 1024 * 1024 / sectorSize;   // 8 MiB
        var systemSectorCount = (4 * GiB - 8 * 1024 * 1024) / sectorSize;
        var userdataStartSector = 4 * GiB / sectorSize;
        var userdataSectorCount = userdataGiB * GiB / sectorSize;

        return new DiskLayout(
            "sdb",
            sectorSize,
            new[]
            {
                new DiskPartition(1, "system", systemStartSector, systemSectorCount, PartitionTypeEsp, PartUuidSystem),
                new DiskPartition(2, "userdata", userdataStartSector, userdataSectorCount, PartitionTypeLinux, PartUuidUserdata),
            });
    }
}
