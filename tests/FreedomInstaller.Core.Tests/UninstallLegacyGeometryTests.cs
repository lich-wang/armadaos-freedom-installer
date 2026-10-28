using System;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Regression tests pinned to one authentic TB322FC partition table: the numbers below are taken
/// verbatim from a real device (4096-byte sectors), not synthesised, so they carry the two quirks the
/// idealised suite in <see cref="UninstallPlannerTests"/> never exercises -
/// <list type="bullet">
/// <item><c>userdata</c> does not start on a 1 MiB boundary (5972392 * 4096 leaves a 688128-byte offset);</item>
/// <item><c>ARMADA_BOOT</c> does not begin exactly at <c>userdata</c>'s end: the installer padded 88
/// sectors (360448 bytes) to reach the next 1 MiB boundary.</item>
/// </list>
/// The only padding this geometry may accept is exactly <c>AlignUp(userdata.end, 1 MiB)</c>; any other
/// shift of the Linux tail has to be rejected even when the whole tail stays contiguous and its end still
/// matches the installation record. Nothing here reaches into the implementation or a device.
/// </summary>
public sealed class UninstallLegacyGeometryTests
{
    private const string Device = "sda";

    private const string LinuxType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string UserdataType = "1B81E7E6-F50D-419B-A739-2AEEF8DA3335";

    private const long UserdataNumber = 16;
    private const long BootNumber = 17;
    private const long RootNumber = 18;

    private const string UserdataUuid = "7F6876B2-2CE6-51A0-505D-A7865864D1BD";
    private const string BootUuid = "F7617F07-9D25-C653-DC40-E4F8C5816B6A";
    private const string RootUuid = "C52E5589-00AB-799D-4253-F7A50A6E6191";

    /// <summary>Recorded pre-install Android userdata end, in 4096-byte sectors.</summary>
    private const long UserdataEnd4096 = 123_871_227;

    /// <summary>(123871227 - 5972392) * 4096 - the byte extent the uninstall has to hand back to Android.</summary>
    private const long RestoredBytes = 482_913_628_160;

    // Authentic 4096-byte layout. userdata end 39526824, boot start 39526912 (88-sector / 360448-byte gap),
    // boot end == root start 39789056, root end == recorded end 123871227.
    private const long UserdataStart4096 = 5_972_392;
    private const long UserdataSectors4096 = 33_554_432;
    private const long BootStart4096 = 39_526_912;
    private const long BootSectors4096 = 262_144;
    private const long RootStart4096 = 39_789_056;
    private const long RootSectors4096 = 84_082_171;

    /// <summary>Same geometry expressed in 512-byte sectors: every start and count scaled by 8.</summary>
    private const long UnitScale = 8;

    // ------------------------------------------------------------------ accepted geometry

    [Fact]
    public void Plan_AuthenticTb322fcGeometry_RestoresTheLegacyTailAndRemovesOnlyTheTwoLinuxPartitions()
    {
        var partitions = Authentic4096();
        var before = (DiskPartition[])partitions.Clone();
        var layout = new DiskLayout(Device, 4096, partitions);

        var plan = UninstallPlanner.Plan(layout, Record(UserdataEnd4096));

        // userdata keeps its real, non-1-MiB-aligned start and grows back over boot + root to the
        // recorded factory end.
        Assert.Equal(UserdataStart4096, plan.UserdataStartSector);
        Assert.Equal(UserdataEnd4096, plan.UserdataEndSectorExclusive);
        Assert.Equal(RestoredBytes, plan.RestoredAndroidBytes);

        Assert.Equal(2, plan.RemovedPartitionNumbers.Count);
        Assert.Equal(new long[] { BootNumber, RootNumber }, plan.RemovedPartitionNumbers);

        // The caller's table is inspected, never rewritten.
        Assert.Equal(before.Length, layout.Partitions.Count);
        for (var index = 0; index < before.Length; index++)
        {
            Assert.Equal(before[index], layout.Partitions[index]);
        }
    }

    [Fact]
    public void Plan_SameGeometryIn512ByteSectors_ScalesOffsetsButRestoresTheSameByteExtent()
    {
        var layout = new DiskLayout(Device, 512, Authentic512());

        var plan = UninstallPlanner.Plan(layout, Record(UserdataEnd4096 * UnitScale));

        Assert.Equal(UserdataStart4096 * UnitScale, plan.UserdataStartSector);
        Assert.Equal(UserdataEnd4096 * UnitScale, plan.UserdataEndSectorExclusive);

        // Sector unit changes, bytes do not.
        Assert.Equal(RestoredBytes, plan.RestoredAndroidBytes);

        Assert.Equal(2, plan.RemovedPartitionNumbers.Count);
        Assert.Equal(new long[] { BootNumber, RootNumber }, plan.RemovedPartitionNumbers);
    }

    // ------------------------------------------------------------------ padding rejections

    [Theory]
    [InlineData(1L)]
    [InlineData(256L)]
    public void Plan_RejectsTailPaddingOtherThanTheExactAlignUpToTheNextMiB(long extraSectors)
    {
        // The whole tail is still contiguous, ARMADA_BOOT is still exactly 1 GiB and the root still ends on
        // the recorded sector; the single defect is a padding of 88 + extraSectors instead of 88.
        var bootStart = BootStart4096 + extraSectors;
        var rootStart = bootStart + BootSectors4096;
        var partitions = new[]
        {
            new DiskPartition(UserdataNumber, "userdata", UserdataStart4096, UserdataSectors4096, UserdataType, UserdataUuid),
            new DiskPartition(BootNumber, "ARMADA_BOOT", bootStart, BootSectors4096, LinuxType, BootUuid),
            new DiskPartition(RootNumber, "ARMADA_ROOT", rootStart, UserdataEnd4096 - rootStart, LinuxType, RootUuid),
        };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout(Device, 4096, partitions), Record(UserdataEnd4096)));
    }

    [Fact]
    public void Plan_RejectsRootThatOverlapsBootOnTheAuthenticGeometry()
    {
        // Padding stays correct and the root still ends on the recorded sector, but it starts one sector
        // inside ARMADA_BOOT.
        const long rootStart = BootStart4096 + BootSectors4096 - 1;
        var partitions = new[]
        {
            new DiskPartition(UserdataNumber, "userdata", UserdataStart4096, UserdataSectors4096, UserdataType, UserdataUuid),
            new DiskPartition(BootNumber, "ARMADA_BOOT", BootStart4096, BootSectors4096, LinuxType, BootUuid),
            new DiskPartition(RootNumber, "ARMADA_ROOT", rootStart, UserdataEnd4096 - rootStart, LinuxType, RootUuid),
        };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout(Device, 4096, partitions), Record(UserdataEnd4096)));
    }

    [Fact]
    public void Plan_RejectsAuthenticGeometryWhoseRootPartUuidIsNotTheRecordedOne()
    {
        // Correct labels, sizes, padding and end: only the PARTUUID disagrees with the record, and a name
        // alone never proves ownership.
        var partitions = Authentic4096();
        partitions[2] = partitions[2] with { PartUuid = "00000000-1111-4222-8333-444455556666" };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout(Device, 4096, partitions), Record(UserdataEnd4096)));
    }

    // ------------------------------------------------------------------------ helpers

    private static void AssertRejected(Action action)
    {
        var exception = Xunit.Record.Exception(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is ArgumentException || exception is InvalidOperationException,
            "expected ArgumentException or InvalidOperationException but got " + exception!.GetType().FullName);
    }

    private static LinuxInstallationLayout Record(long userdataEndSector)
        => new(Device, UserdataUuid, BootUuid, RootUuid, userdataEndSector);

    private static DiskPartition[] Authentic4096() => new[]
    {
        new DiskPartition(UserdataNumber, "userdata", UserdataStart4096, UserdataSectors4096, UserdataType, UserdataUuid),
        new DiskPartition(BootNumber, "ARMADA_BOOT", BootStart4096, BootSectors4096, LinuxType, BootUuid),
        new DiskPartition(RootNumber, "ARMADA_ROOT", RootStart4096, RootSectors4096, LinuxType, RootUuid),
    };

    private static DiskPartition[] Authentic512() => new[]
    {
        new DiskPartition(
            UserdataNumber, "userdata", UserdataStart4096 * UnitScale, UserdataSectors4096 * UnitScale, UserdataType, UserdataUuid),
        new DiskPartition(
            BootNumber, "ARMADA_BOOT", BootStart4096 * UnitScale, BootSectors4096 * UnitScale, LinuxType, BootUuid),
        new DiskPartition(
            RootNumber, "ARMADA_ROOT", RootStart4096 * UnitScale, RootSectors4096 * UnitScale, LinuxType, RootUuid),
    };
}
