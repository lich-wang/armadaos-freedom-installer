using System.Reflection;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour tests for <see cref="InternalPartitionPlanner"/>. Every expected value below is an independently
/// derived literal sector/byte endpoint, never a mirror of the planner's own arithmetic. The reserved backup
/// tail is a fixed 2 GiB in every expectation; the Linux boot extent keeps the package's own size (1 GiB in
/// these fixtures). The tests build
/// synthetic immutable GPT snapshots only; <see cref="GptTable"/> and <see cref="GptPartition"/> expose their
/// constructors as internal and no <c>InternalsVisibleTo</c> exists, so this file carries a narrow private
/// reflection helper that invokes exactly those two internal constructors. Nothing else is reflected and the
/// planner itself is always called through its public API.
/// </summary>
public sealed class InternalPartitionPlannerTests
{
    private const long GiB = 1L << 30;
    private const long MiB = 1L << 20;

    private const string LinuxFilesystemType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string EfiSystemType = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    private const string DiskGuid = "7C1D2E3F-4A5B-4C6D-8E9F-0A1B2C3D4E5F";

    // Real G4 geometry: 4096-byte sectors, userdata starts unaligned (5972392 is not a 1 MiB multiple),
    // its 117898835 sectors end at 123871227, which is 251 sectors after the previous 1 MiB boundary
    // (123870976), so those 251 sectors are the unallocated tail, not missing space before the next boundary.
    private const long G4UserdataStart = 5972392;
    private const long G4UserdataCount = 117898835;

    private static readonly ConstructorInfo PartitionCtor = typeof(GptPartition).GetConstructor(
        BindingFlags.Instance | BindingFlags.NonPublic,
        binder: null,
        new[] { typeof(int), typeof(string), typeof(string), typeof(string), typeof(long), typeof(long), typeof(ulong) },
        modifiers: null)!;

    private static readonly ConstructorInfo TableCtor = typeof(GptTable).GetConstructor(
        BindingFlags.Instance | BindingFlags.NonPublic,
        binder: null,
        new[]
        {
            typeof(string), typeof(int), typeof(long), typeof(string),
            typeof(long), typeof(long), typeof(IReadOnlyList<GptPartition>), typeof(string),
        },
        modifiers: null)!;

    // ---------------------------------------------------------------- snapshots

    private static string Uuid(int seed) => $"{seed:X8}-1111-2222-3333-444444444444";

    private static GptPartition Part(
        int number,
        string name,
        long startSector,
        long sectorCount,
        string typeGuid = LinuxFilesystemType,
        ulong attributes = 0)
    {
        return (GptPartition)PartitionCtor.Invoke(new object?[]
        {
            number, name, typeGuid, Uuid(number), startSector, sectorCount, attributes,
        });
    }

    private static GptTable Table(
        int sectorSize,
        long diskBytes,
        long firstUsableSector,
        long lastUsableSector,
        params GptPartition[] partitions)
    {
        return (GptTable)TableCtor.Invoke(new object?[]
        {
            null,
            sectorSize,
            diskBytes,
            DiskGuid,
            firstUsableSector,
            lastUsableSector,
            (IReadOnlyList<GptPartition>)partitions,
            "sha256:ip001-test-snapshot",
        });
    }

    // 512 GiB disk for the 4096-byte-sector G4 fixtures: last usable leaves room for the reserved header.
    private static GptTable G4Table(params GptPartition[] partitions)
        => Table(4096, 512L * GiB, 6, 134184960, partitions);

    // 256 GiB disk for 512-byte-sector fixtures. First usable 34 (MBR + header + 32 entries) so the
    // unaligned start-41 fixture lies inside the usable window; disk size and last usable are unchanged.
    private static GptTable Wide512(params GptPartition[] partitions)
        => Table(512, 256L * GiB, 34, 536838144, partitions);

    private static PackageStorage DefaultStorage() => new(1 * GiB, 8 * GiB, 2 * GiB, 1 * GiB);

    private static AndroidAllocationRange Range(GptTable table, PackageStorage? storage = null)
        => InternalPartitionPlanner.GetAndroidRange(table, storage ?? DefaultStorage());

    // ---------------------------------------------------------------- real G4

    [Fact]
    public void Plan_RealG4With16GiB_ReturnsDerivedGeometry()
    {
        GptTable table = G4Table(Part(1, "efi", 6, 262144, EfiSystemType), Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: unaligned userdata start must be kept, not rounded up or rejected (old planner failure).
        Assert.Equal(4096, plan.SectorSize);
        Assert.Equal(123871227, plan.OriginalUserdataEndSectorExclusive);
        Assert.Equal(16 * GiB, plan.AndroidBytes);
        Assert.Equal(4194304, plan.AndroidSectorCount);
        Assert.Equal(10166696, plan.AndroidEndSectorExclusive);
        Assert.Equal(463584886784, plan.LinuxBytes);
        Assert.Equal(1 * GiB, plan.LinuxBootBytes);
        Assert.Equal(462511144960, plan.LinuxRootBytes);
        Assert.Equal(10166784, plan.LinuxBootStartSector);
        Assert.Equal(262144, plan.LinuxBootSectorCount);
        Assert.Equal(10428928, plan.LinuxRootStartSector);
        Assert.Equal(112917760, plan.LinuxRootSectorCount);
        // Protects: the reserved tail is exactly 2 GiB and a whole number of 4096-byte sectors.
        Assert.Equal(2 * GiB, plan.BackupBytes);
        Assert.Equal(2147483648, plan.BackupBytes);
        Assert.Equal(0, plan.BackupBytes % plan.SectorSize);
        Assert.Equal(plan.BackupBytes, plan.BackupSectorCount * plan.SectorSize);
        Assert.Equal(123346688, plan.BackupStartSector);
        Assert.Equal(524288, plan.BackupSectorCount);
        Assert.Equal(123870976, plan.BackupEndSectorExclusive);
        Assert.Equal(88, plan.AlignmentGapSectors);
        Assert.Equal(251, plan.TailUnallocatedSectors);
        Assert.Equal(1388544, plan.AlignmentLossBytes);
        // Protects: Linux bytes exclude the backup tail and both loss zones, and no extent leaves userdata.
        Assert.Equal(plan.LinuxBootBytes + plan.LinuxRootBytes, plan.LinuxBytes);
        Assert.Equal(plan.AndroidBytes, plan.AndroidSectorCount * 4096);
        Assert.Equal(plan.OriginalUserdataEndSectorExclusive - plan.BackupEndSectorExclusive, plan.TailUnallocatedSectors);
    }

    [Fact]
    public void Plan_RealG4PreservesTheOriginalUserdataAndOtherEntries()
    {
        GptPartition efi = Part(1, "efi", 6, 262144, EfiSystemType, attributes: 0x8000000000000000UL);
        GptPartition userdata = Part(2, "userdata", G4UserdataStart, G4UserdataCount, attributes: 0x1234UL);
        GptTable table = G4Table(efi, userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: planner must not rebuild or mutate the userdata snapshot.
        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal("userdata", plan.OriginalUserdata.Name);
        Assert.Equal(Uuid(2), plan.OriginalUserdata.PartUuid);
        Assert.Equal(LinuxFilesystemType, plan.OriginalUserdata.TypeGuid);
        Assert.Equal(0x1234UL, plan.OriginalUserdata.Attributes);
        Assert.Equal(2, plan.OriginalUserdata.Number);
        Assert.Equal(G4UserdataStart, plan.OriginalUserdata.StartSector);
        Assert.Equal(G4UserdataCount, plan.OriginalUserdata.SectorCount);

        // Protects: the table snapshot itself, its order and every untouched partition.
        Assert.Equal(2, table.Partitions.Count);
        Assert.Same(efi, table.Partitions[0]);
        Assert.Same(userdata, table.Partitions[1]);
        Assert.Equal(6, table.Partitions[0].StartSector);
        Assert.Equal(262144, table.Partitions[0].SectorCount);
    }

    [Fact]
    public void Plan_RealG4With383GiB_ReturnsDerivedGeometry()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 383, DefaultStorage());

        // Protects: the largest legal Android size and the resulting 64.75 GiB Linux extent.
        Assert.Equal(100401152, plan.AndroidSectorCount);
        Assert.Equal(106373544, plan.AndroidEndSectorExclusive);
        Assert.Equal(106373632, plan.LinuxBootStartSector);
        Assert.Equal(106635776, plan.LinuxRootStartSector);
        Assert.Equal(16710912, plan.LinuxRootSectorCount);
        Assert.Equal(123346688, plan.BackupStartSector);
        Assert.Equal(524288, plan.BackupSectorCount);
        Assert.Equal(123870976, plan.BackupEndSectorExclusive);
        Assert.Equal(69521637376, plan.LinuxBytes);
        Assert.Equal(68447895552, plan.LinuxRootBytes);
        Assert.Equal(88, plan.AlignmentGapSectors);
        Assert.Equal(251, plan.TailUnallocatedSectors);
    }

    [Fact]
    public void Plan_RealG4With384GiB_IsRejected()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        // Protects: 384 GiB would leave 63.75 GiB of Linux, below the 64 GiB floor.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 384, DefaultStorage()); });
    }

    [Fact]
    public void GetAndroidRange_RealG4_Reports16To383()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        AndroidAllocationRange range = Range(table);

        // Protects: the maximum must match Plan exactly, not an understated aligned bound.
        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(383, range.MaximumGiB);
    }

    [Fact]
    public void Plan_MatchesUserdataNameAfterTrimmingAndIgnoringCase()
    {
        GptPartition userdata = Part(2, "  UserData  ", G4UserdataStart, G4UserdataCount);
        GptTable table = G4Table(userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(123871227, plan.OriginalUserdataEndSectorExclusive);
    }

    // ---------------------------------------------------------------- exact aligned minimum

    [Fact]
    public void Plan_AlignedMinimumAt512ByteSectors_ReturnsExactly64GiBLinux()
    {
        GptPartition userdata = Part(2, "userdata", 2048, 171966464);
        GptTable table = Wide512(userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: 16 GiB Android + 1 GiB boot + 63 GiB root + 2 GiB backup in one aligned 82 GiB window.
        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(171968512, plan.OriginalUserdataEndSectorExclusive);
        Assert.Equal(33554432, plan.AndroidSectorCount);
        Assert.Equal(33556480, plan.AndroidEndSectorExclusive);
        Assert.Equal(33556480, plan.LinuxBootStartSector);
        Assert.Equal(2097152, plan.LinuxBootSectorCount);
        Assert.Equal(35653632, plan.LinuxRootStartSector);
        Assert.Equal(132120576, plan.LinuxRootSectorCount);
        Assert.Equal(167774208, plan.BackupStartSector);
        // Protects: the reserved tail is exactly 2 GiB and a whole number of 512-byte sectors.
        Assert.Equal(2 * GiB, plan.BackupBytes);
        Assert.Equal(2147483648, plan.BackupBytes);
        Assert.Equal(0, plan.BackupBytes % plan.SectorSize);
        Assert.Equal(plan.BackupBytes, plan.BackupSectorCount * plan.SectorSize);
        Assert.Equal(4194304, plan.BackupSectorCount);
        Assert.Equal(171968512, plan.BackupEndSectorExclusive);
        Assert.Equal(68719476736, plan.LinuxBytes);
        Assert.Equal(67645734912, plan.LinuxRootBytes);
        Assert.Equal(0, plan.AlignmentGapSectors);
        Assert.Equal(0, plan.TailUnallocatedSectors);
        Assert.Equal(0, plan.AlignmentLossBytes);
    }

    [Fact]
    public void Plan_AlignedMinimumAt512ByteSectors_Rejects17GiB()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 171966464));

        // Protects: one more GiB would leave 63 GiB of Linux.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 17, DefaultStorage()); });
    }

    [Fact]
    public void Plan_AlignedMinimumAt512ByteSectors_RejectsTheOld81GiBWindow()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 169869312));

        // Protects: the old 81 GiB window sized for the 1 GiB tail now leaves only 63 GiB of Linux.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void GetAndroidRange_AlignedMinimumAt512ByteSectors_IsExactly16()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 171966464));

        AndroidAllocationRange range = Range(table);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    [Fact]
    public void Plan_AlignedMinimumAt4096ByteSectors_ReturnsExactly64GiBLinux()
    {
        GptPartition userdata = Part(2, "userdata", 256, 21495808);
        GptTable table = G4Table(userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(21496064, plan.OriginalUserdataEndSectorExclusive);
        Assert.Equal(4194304, plan.AndroidSectorCount);
        Assert.Equal(4194560, plan.AndroidEndSectorExclusive);
        Assert.Equal(4194560, plan.LinuxBootStartSector);
        Assert.Equal(262144, plan.LinuxBootSectorCount);
        Assert.Equal(4456704, plan.LinuxRootStartSector);
        Assert.Equal(16515072, plan.LinuxRootSectorCount);
        Assert.Equal(20971776, plan.BackupStartSector);
        // Protects: the same 2 GiB tail is a whole number of 4096-byte sectors too.
        Assert.Equal(2 * GiB, plan.BackupBytes);
        Assert.Equal(2147483648, plan.BackupBytes);
        Assert.Equal(524288, plan.BackupSectorCount);
        Assert.Equal(plan.BackupBytes, plan.BackupSectorCount * plan.SectorSize);
        Assert.Equal(0, plan.BackupBytes % plan.SectorSize);
        Assert.Equal(21496064, plan.BackupEndSectorExclusive);
        Assert.Equal(68719476736, plan.LinuxBytes);
        Assert.Equal(67645734912, plan.LinuxRootBytes);
        Assert.Equal(0, plan.AlignmentGapSectors);
        Assert.Equal(0, plan.TailUnallocatedSectors);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public void Plan_AlignedMinimumAt4096ByteSectors_RejectsNeighbouringSizes(int androidGiB)
    {
        GptTable table = G4Table(Part(2, "userdata", 256, 21495808));

        // Protects: 15 GiB is below the 16 GiB floor; 17 GiB would leave 63 GiB of Linux.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, androidGiB, DefaultStorage()); });
    }

    [Fact]
    public void Plan_AlignedMinimumAt4096ByteSectors_RejectsTheOld81GiBWindow()
    {
        GptTable table = G4Table(Part(2, "userdata", 256, 21233664));

        // Protects: the retired 1 GiB-tail minimum no longer fits once the tail is 2 GiB.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void GetAndroidRange_AlignedMinimumAt4096ByteSectors_IsExactly16()
    {
        GptTable table = G4Table(Part(2, "userdata", 256, 21495808));

        AndroidAllocationRange range = Range(table);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    // ---------------------------------------------------------------- unaligned start plus required gap

    [Fact]
    public void Plan_UnalignedStartAt512ByteSectors_AbsorbsTheGapWithoutLosingLinuxSpace()
    {
        GptPartition userdata = Part(2, "userdata", 41, 171968471);
        GptTable table = Wide512(userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: gap is charged as alignment loss, not silently taken from Android or Linux.
        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(171968512, plan.OriginalUserdataEndSectorExclusive);
        Assert.Equal(33554432, plan.AndroidSectorCount);
        Assert.Equal(33554473, plan.AndroidEndSectorExclusive);
        Assert.Equal(33556480, plan.LinuxBootStartSector);
        Assert.Equal(35653632, plan.LinuxRootStartSector);
        Assert.Equal(132120576, plan.LinuxRootSectorCount);
        Assert.Equal(167774208, plan.BackupStartSector);
        Assert.Equal(171968512, plan.BackupEndSectorExclusive);
        Assert.Equal(2007, plan.AlignmentGapSectors);
        Assert.Equal(0, plan.TailUnallocatedSectors);
        Assert.Equal(68719476736, plan.LinuxBytes);
        Assert.Equal(67645734912, plan.LinuxRootBytes);
        Assert.Equal(2007 * 512, plan.AlignmentLossBytes);
    }

    [Fact]
    public void Plan_UnalignedStartAt512ByteSectors_RejectsOneSectorLess()
    {
        GptTable table = Wide512(Part(2, "userdata", 41, 171968470));

        // Protects: the backup end would drop by one 1 MiB block and Linux would fall below 64 GiB.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_UnalignedStartAt512ByteSectors_Rejects82GiBWindowWithoutGap()
    {
        GptTable table = Wide512(Part(2, "userdata", 41, 171966464));

        // Protects: Android must not be rounded down to 16 GiB to make a window that lacks the gap.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void GetAndroidRange_UnalignedStartAt512ByteSectors_IsExactly16()
    {
        GptTable table = Wide512(Part(2, "userdata", 41, 171968471));

        AndroidAllocationRange range = Range(table);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    [Fact]
    public void Plan_UnalignedStartAt4096ByteSectors_AbsorbsTheGapWithoutLosingLinuxSpace()
    {
        GptPartition userdata = Part(2, "userdata", G4UserdataStart, 21495896);
        GptTable table = G4Table(userdata);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: 88-sector gap at the front of boot is loss, the 64 GiB Linux window stays intact.
        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(27468288, plan.OriginalUserdataEndSectorExclusive);
        Assert.Equal(4194304, plan.AndroidSectorCount);
        Assert.Equal(10166696, plan.AndroidEndSectorExclusive);
        Assert.Equal(10166784, plan.LinuxBootStartSector);
        Assert.Equal(10428928, plan.LinuxRootStartSector);
        Assert.Equal(16515072, plan.LinuxRootSectorCount);
        Assert.Equal(26944000, plan.BackupStartSector);
        Assert.Equal(27468288, plan.BackupEndSectorExclusive);
        Assert.Equal(88, plan.AlignmentGapSectors);
        Assert.Equal(0, plan.TailUnallocatedSectors);
        Assert.Equal(68719476736, plan.LinuxBytes);
        Assert.Equal(67645734912, plan.LinuxRootBytes);
        Assert.Equal(88 * 4096, plan.AlignmentLossBytes);
    }

    [Fact]
    public void Plan_UnalignedStartAt4096ByteSectors_RejectsOneSectorLess()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, 21495895));

        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_UnalignedStartAt4096ByteSectors_Rejects82GiBWindowWithoutGap()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, 21495808));

        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void GetAndroidRange_UnalignedStartAt4096ByteSectors_IsExactly16()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, 21495896));

        AndroidAllocationRange range = Range(table);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    // ---------------------------------------------------------------- package root beats 64 GiB total

    [Fact]
    public void Plan_PackageRootNeeds70GiB_AcceptsAligned89GiBWindow()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 186646528));
        var storage = new PackageStorage(1 * GiB, 60 * GiB, 5 * GiB, 5 * GiB);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, storage);

        // Protects: root must fit system+scratch+minimum data (70 GiB) even though Linux total is only 71 GiB.
        Assert.Equal(33556480, plan.LinuxBootStartSector);
        Assert.Equal(35653632, plan.LinuxRootStartSector);
        Assert.Equal(146800640, plan.LinuxRootSectorCount);
        Assert.Equal(182454272, plan.BackupStartSector);
        Assert.Equal(71 * GiB, plan.LinuxBytes);
        Assert.Equal(70 * GiB, plan.LinuxRootBytes);
        // Protects: scratch is transient and released after deployment, so only system is subtracted.
        Assert.Equal(10 * GiB, plan.EstimatedLinuxDataBytes);
    }

    [Fact]
    public void Plan_PackageRootNeeds70GiB_RejectsAligned88GiBWindow()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 184549376));
        var storage = new PackageStorage(1 * GiB, 60 * GiB, 5 * GiB, 5 * GiB);

        // Protects: one GiB less leaves 69 GiB root, below the package requirement.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, storage); });
    }

    [Fact]
    public void GetAndroidRange_PackageRootNeeds70GiB_IsExactly16()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 186646528));
        var storage = new PackageStorage(1 * GiB, 60 * GiB, 5 * GiB, 5 * GiB);

        AndroidAllocationRange range = Range(table, storage);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    [Fact]
    public void Plan_ZeroScratchWithDefaultPackage_PlansTheFullLinuxExtent()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));
        var storage = new PackageStorage(1 * GiB, 8 * GiB, 0, 1 * GiB);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, storage);

        // Protects: scratch of zero is accepted (not merely non-throwing) and does not shrink Linux or the estimate.
        Assert.Equal(4096, plan.SectorSize);
        Assert.Equal(4194304, plan.AndroidSectorCount);
        Assert.Equal(1 * GiB, plan.LinuxBootBytes);
        Assert.Equal(462511144960, plan.LinuxRootBytes);
        Assert.Equal(463584886784, plan.LinuxBytes);
        Assert.Equal(453921210368, plan.EstimatedLinuxDataBytes);
        Assert.Equal(2 * GiB, plan.BackupBytes);
        Assert.Equal(251, plan.TailUnallocatedSectors);
    }

    // ---------------------------------------------------------------- 32 GiB root floor beats 64 GiB total

    [Fact]
    public void Plan_BootHeavyPackage_AcceptsExactly90GiBWindow()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 188743680));
        var storage = new PackageStorage(40 * GiB, 1 * GiB, 1 * GiB, 1 * GiB);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, storage);

        // Protects: 40 GiB boot forces 72 GiB Linux even though the total floor is only 64 GiB.
        Assert.Equal(83886080, plan.LinuxBootSectorCount);
        Assert.Equal(117442560, plan.LinuxRootStartSector);
        Assert.Equal(67108864, plan.LinuxRootSectorCount);
        Assert.Equal(184551424, plan.BackupStartSector);
        Assert.Equal(188745728, plan.BackupEndSectorExclusive);
        Assert.Equal(72 * GiB, plan.LinuxBytes);
        Assert.Equal(32 * GiB, plan.LinuxRootBytes);
        Assert.Equal(31 * GiB, plan.EstimatedLinuxDataBytes);
    }

    [Fact]
    public void Plan_BootHeavyPackage_Rejects89GiBWindow()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 186646528));
        var storage = new PackageStorage(40 * GiB, 1 * GiB, 1 * GiB, 1 * GiB);

        // Protects: 31 GiB root would be below the 32 GiB floor while Linux total is still 71 GiB.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, storage); });
    }

    [Fact]
    public void Plan_BootHeavyPackage_Rejects64GiBLinuxWithOnly24GiBRoot()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 171966464));
        var storage = new PackageStorage(40 * GiB, 1 * GiB, 1 * GiB, 1 * GiB);

        // Protects: meeting the 64 GiB Linux total is not enough when root is only 24 GiB.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, storage); });
    }

    [Fact]
    public void GetAndroidRange_BootHeavyPackage_IsExactly16()
    {
        GptTable table = Wide512(Part(2, "userdata", 2048, 188743680));
        var storage = new PackageStorage(40 * GiB, 1 * GiB, 1 * GiB, 1 * GiB);

        AndroidAllocationRange range = Range(table, storage);

        Assert.Equal(16, range.MinimumGiB);
        Assert.Equal(16, range.MaximumGiB);
    }

    // ---------------------------------------------------------------- no physical-last restriction

    [Fact]
    public void Plan_AcceptsAnUnrelatedPartitionAfterUserdataAndLeavesBothUntouched()
    {
        GptPartition efi = Part(1, "efi", 6, 262144, EfiSystemType);
        GptPartition userdata = Part(2, "userdata", G4UserdataStart, G4UserdataCount);
        GptPartition opt = Part(3, "opt", 124000000, 1000);
        GptTable table = G4Table(efi, userdata, opt);

        InternalAllocationPlan plan = InternalPartitionPlanner.Plan(table, 16, DefaultStorage());

        // Protects: userdata need not be the physically last partition and later entries must not move.
        Assert.Same(userdata, plan.OriginalUserdata);
        Assert.Equal(3, table.Partitions.Count);
        Assert.Same(efi, table.Partitions[0]);
        Assert.Same(opt, table.Partitions[2]);
        Assert.Equal(124000000, opt.StartSector);
        Assert.Equal(1000, opt.SectorCount);
        Assert.Equal(123870976, plan.BackupEndSectorExclusive);
        Assert.Equal(251, plan.TailUnallocatedSectors);
    }

    // ---------------------------------------------------------------- negative: arguments and package

    [Theory]
    [InlineData(15L)]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(long.MaxValue)]
    public void Plan_RejectsAndroidGiBOutsideTheSupportedRange(long androidGiB)
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        // Protects: floor of 16 GiB and checked GiB-to-byte conversion at long.MaxValue.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, androidGiB, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsNullTable()
    {
        Assert.Throws<ArgumentNullException>(() => { InternalPartitionPlanner.Plan(null!, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsNullStorage()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        Assert.Throws<ArgumentNullException>(() => { InternalPartitionPlanner.Plan(table, 16, null!); });
    }

    [Theory]
    [InlineData(0L, 8 * GiB, 2 * GiB, 1 * GiB)]      // boot must be positive
    [InlineData(-1L, 8 * GiB, 2 * GiB, 1 * GiB)]     // boot must be positive
    [InlineData(MiB + 1L, 8 * GiB, 2 * GiB, 1 * GiB)] // boot must be 1 MiB aligned
    [InlineData(1 * GiB, 0L, 2 * GiB, 1 * GiB)]      // system must be positive
    [InlineData(1 * GiB, 8 * GiB, -1L, 1 * GiB)]     // scratch may be zero but never negative
    [InlineData(1 * GiB, 8 * GiB, 2 * GiB, 0L)]      // minimum data must be positive
    public void Plan_RejectsInvalidPackageStorage(long boot, long system, long scratch, long minimumData)
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));
        var storage = new PackageStorage(boot, system, scratch, minimumData);

        // Protects: each package declaration is validated before any sector arithmetic.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, storage); });
    }

    [Fact]
    public void Plan_RejectsPackageStorageWhoseCheckedSumOverflows()
    {
        GptTable table = G4Table(Part(2, "userdata", G4UserdataStart, G4UserdataCount));
        var storage = new PackageStorage(1 * GiB, long.MaxValue, long.MaxValue, 1);

        // Protects: unchecked sum of system+scratch+minimum data must not wrap into a small requirement.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, storage); });
    }

    // ---------------------------------------------------------------- negative: table structure

    [Theory]
    [InlineData(1024)]
    [InlineData(8192)]
    public void Plan_RejectsUnsupportedSectorSizes(int sectorSize)
    {
        GptTable table = Table(sectorSize, 512L * GiB, 6, 134184960, Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        // Protects: only 512 and 4096 byte sectors are ever planned for.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsATableWithoutUserdata()
    {
        GptTable table = G4Table(Part(1, "efi", 6, 262144, EfiSystemType));

        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsDuplicateUserdataEntries()
    {
        GptTable table = G4Table(
            Part(2, "userdata", G4UserdataStart, 1000000),
            Part(3, "USERDATA", 7000000, 1000000));

        // Protects: trimmed case-insensitive match must detect ambiguity, not pick the first hit.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsDuplicatePartitionNumbers()
    {
        GptTable table = G4Table(
            Part(2, "userdata", G4UserdataStart, G4UserdataCount),
            Part(2, "opt", 6, 1000));

        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsANullEntry()
    {
        GptTable table = G4Table((GptPartition)null!, Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Plan_RejectsOverlappingEntries(bool overlapInsideUserdata)
    {
        GptPartition efi = Part(1, "efi", 6, 400000, EfiSystemType);
        GptPartition userdata = Part(2, "userdata", G4UserdataStart, G4UserdataCount);
        GptPartition intruder = overlapInsideUserdata
            ? Part(3, "intruder", G4UserdataStart + 1000, 1000)
            : Part(3, "intruder", 300000, 262144);
        GptTable table = G4Table(efi, userdata, intruder);

        // Protects: overlap detection both against userdata and between unrelated entries.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(134184960L)]
    public void Plan_RejectsPartitionOutsideTheUsableWindow(long intruderStart)
    {
        GptPartition userdata = Part(2, "userdata", G4UserdataStart, G4UserdataCount);
        GptTable table = G4Table(userdata, Part(3, "intruder", intruderStart, 10));

        // Protects: start below FirstUsable and end past LastUsable are both structural corruption.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Theory]
    [InlineData(0L, 134184960L)]
    [InlineData(100L, 50L)]
    public void Plan_RejectsInvalidUsableBounds(long firstUsable, long lastUsable)
    {
        GptTable table = Table(4096, 512L * GiB, firstUsable, lastUsable, Part(2, "userdata", G4UserdataStart, G4UserdataCount));

        // Protects: a non-positive first usable sector and an inverted usable window.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Theory]
    [InlineData(-1L, 100L)]
    [InlineData(G4UserdataStart, 0L)]
    [InlineData(G4UserdataStart, -5L)]
    public void Plan_RejectsNonPositiveStartOrCount(long startSector, long sectorCount)
    {
        GptTable table = G4Table(Part(2, "userdata", startSector, sectorCount));

        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-512L * 1024L * 1024L * 1024L)]
    [InlineData(1000L)]
    public void Plan_RejectsInvalidDiskLength(long diskBytes)
    {
        GptTable table = Table(512, diskBytes, 2048, 100000, Part(2, "userdata", 4096, 1000));

        // Protects: zero, negative and non-sector-aligned disk sizes.
        Assert.Throws<InvalidOperationException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsAnEntryWhoseEndSectorOverflows()
    {
        GptTable table = G4Table(Part(2, "userdata", long.MaxValue - 10, long.MaxValue));

        // Protects: StartSector + SectorCount must be computed checked, not wrap to a negative end.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }

    [Fact]
    public void Plan_RejectsUserdataWhoseSectorCountToBytesOverflows()
    {
        // start + count is representable; count * 4096 overflows long.
        const long count = long.MaxValue / 4096 + 1;
        GptTable table = G4Table(Part(2, "userdata", 6, count));

        // Protects: byte-size representability is checked before the out-of-window rejection, so it must not wrap.
        Assert.ThrowsAny<ArgumentException>(() => { InternalPartitionPlanner.Plan(table, 16, DefaultStorage()); });
    }
}
