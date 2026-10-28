using System;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Two concrete review regressions, each reproducing a defect found in review and kept as a separate class
/// so the general behavioural suite stays untouched.
/// <para>
/// They reproduce two defects: the planner rejects a valid layout whose list order differs from the physical
/// order, and the readiness gate accepts an undefined <see cref="BootloaderState"/> value. Both tests must not
/// be weakened.
/// </para>
/// </summary>
public sealed class ReviewRegressionTests
{
    private const long GiB = TestSizes.GiB;

    private const string PartitionTypeLinux = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

    private const string PartUuidVendor = "99999999-8888-7777-6666-555555555555";
    private const string PartUuidUserdata = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

    // ------------------------------------------------------------------ regression 1
    // A layout listed by GPT number, not by physical position: userdata is #17 and comes first in the
    // list, vendor is #30, follows in the list and sits physically *before* userdata. The list order is a
    // display artefact of the GPT dump, so the planner must compare physical extents instead of rejecting
    // userdata for not being the last list entry.

    [Fact]
    public void Plan_ListOrderDiffersFromPhysicalOrder_StillPlansTheRealLastPartition()
    {
        var layout = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                // #17 userdata: 4 GiB .. 228 GiB (224 GiB), the physically last partition.
                new DiskPartition(17, "userdata", 8_388_608, 469_762_048, PartitionTypeLinux, PartUuidUserdata),
                // #30 vendor: 3 GiB .. 4 GiB, listed after userdata but physically before it.
                new DiskPartition(30, "vendor", 6_291_456, 2_097_152, PartitionTypeLinux, PartUuidVendor),
            });

        var plan = PartitionPlanner.Plan(layout, androidGiB: 96, androidMinimumGiB: 16, TicketStorage());

        // Same 96 GiB Android / 224 GiB userdata geometry as the accepted layout, so the bytes must match.
        Assert.Equal(96 * GiB, plan.AndroidBytes);
        Assert.Equal(128 * GiB, plan.LinuxBytes);
        Assert.Equal(1 * GiB, plan.LinuxBootBytes);
        Assert.Equal(127 * GiB, plan.LinuxRootBytes);
        Assert.Equal(107 * GiB, plan.EstimatedLinuxDataBytes);

        Assert.Equal(8_388_608L, plan.UserdataStartSector);     // 4 GiB / 512
        Assert.Equal(201_326_592L, plan.AndroidSectorCount);    // 96 GiB / 512
        Assert.Equal(209_715_200L, plan.LinuxBootStartSector);  // 100 GiB / 512
        Assert.Equal(211_812_352L, plan.LinuxRootStartSector);  // 101 GiB / 512
        Assert.Equal(478_150_656L, plan.EndSectorExclusive);    // 228 GiB / 512

        // The vendor partition stays where it is: the plan starts at the userdata extent.
        var vendor = layout.Partitions[1];
        Assert.True(vendor.StartSector + vendor.SectorCount <= plan.UserdataStartSector);
    }

    // ------------------------------------------------------------------ regression 2
    // InstallationReadiness only compares the bootloader state against Locked and Unknown, so an undefined
    // enum value such as (BootloaderState)99 passes both checks and the gate reports Ready. An unconfirmed
    // state must always block the gate.

    [Fact]
    public void Evaluate_UndefinedBootloaderState_IsNeverReady()
    {
        var undefined = new DeviceIdentity("R58M12345ABC", "TB322FC", (BootloaderState)99);

        // Same manually constructed fixtures the behavioural suite uses, so only the enum value differs.
        var readiness = InstallationReadiness.Evaluate(
            undefined,
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.False(readiness.IsReady);
        Assert.NotEmpty(readiness.Reasons);

        // Control: identical inputs with a confirmed Unlocked bootloader are ready, which isolates the
        // undefined enum value as the only reason the gate closes above.
        var control = InstallationReadiness.Evaluate(
            new DeviceIdentity("R58M12345ABC", "TB322FC", BootloaderState.Unlocked),
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.True(control.IsReady, string.Join("; ", control.Reasons));
    }

    // ------------------------------------------------------------------------ helpers

    private static PackageStorage TicketStorage() => new(1 * GiB, 20 * GiB, 2 * GiB, 8 * GiB);

    private static PackageValidationResult ValidPackage() =>
        new(true, Array.Empty<string>(), TicketStorage());

    // Literal snapshot of the expected plan, so this class never depends on the planner.
    private static AllocationPlan ExpectedPlan() => new(
        AndroidBytes: 96 * GiB,
        LinuxBytes: 128 * GiB,
        LinuxBootBytes: 1 * GiB,
        LinuxRootBytes: 127 * GiB,
        EstimatedLinuxDataBytes: 107 * GiB,
        UserdataStartSector: 8_388_608,
        AndroidSectorCount: 201_326_592,
        LinuxBootStartSector: 209_715_200,
        LinuxRootStartSector: 211_812_352,
        EndSectorExclusive: 478_150_656);
}
