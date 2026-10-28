using System;
using System.Collections.Generic;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural contract for <see cref="UninstallPlanner"/>. Every assertion uses real GPT-style GUIDs and
/// real sector arithmetic; nothing reaches into the (stub) implementation. Rejections only require that an
/// <see cref="ArgumentException"/> or <see cref="InvalidOperationException"/> is raised, never a message.
/// </summary>
public sealed class UninstallPlannerTests
{
    private const long GiB = TestSizes.GiB;

    private const string LinuxType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string MicrosoftBasicData = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    private const string EspType = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

    private const string UserdataUuid = "6F1E2D3C-4B5A-4968-8776-655443322110";
    private const string BootUuid = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
    private const string RootUuid = "B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E";
    private const string VendorUuid = "C3D4E5F6-A7B8-4C9D-8E1F-2A3B4C5D6E7F";

    private const long VendorNumber = 30;
    private const long UserdataNumber = 2;
    private const long BootNumber = 3;
    private const long RootNumber = 4;

    // 512-byte layout: userdata @ 4 GiB (96 GiB), ARMADA_BOOT 1 GiB, ARMADA_ROOT 127 GiB, original end 228 GiB.
    private const long VendorStart512 = 2_048;
    private const long VendorSectors512 = 8_386_560;
    private const long UserdataStart512 = 8_388_608;
    private const long UserdataSectors512 = 201_326_592;
    private const long BootStart512 = 209_715_200;
    private const long BootSectors512 = 2_097_152;
    private const long RootStart512 = 211_812_352;
    private const long RootSectors512 = 266_338_304;
    private const long RootEnd512 = 478_150_656;

    // 4096-byte layout: identical bytes, sector-scaled offsets.
    private const long VendorStart4096 = 256;
    private const long VendorSectors4096 = 1_048_320;
    private const long UserdataStart4096 = 1_048_576;
    private const long UserdataSectors4096 = 25_165_824;
    private const long BootStart4096 = 26_214_400;
    private const long BootSectors4096 = 262_144;
    private const long RootStart4096 = 26_476_544;
    private const long RootSectors4096 = 33_292_288;
    private const long RootEnd4096 = 59_768_832;

    // -------------------------------------------------------------- accepted layouts

    [Fact]
    public void Plan_Sector512_ReclaimsTheTwoOwnedPartitionsAndReportsRestoredExtent()
    {
        var plan = UninstallPlanner.Plan(Layout512(), Record512());

        // Restored userdata extent is exactly the original Android tail: start, and end == original end.
        Assert.Equal(UserdataStart512, plan.UserdataStartSector);
        Assert.Equal(RootEnd512, plan.UserdataEndSectorExclusive);
        Assert.Equal(224 * GiB, plan.RestoredAndroidBytes); // 96 GiB Android + 1 GiB boot + 127 GiB root

        Assert.Equal(2, plan.RemovedPartitionNumbers.Count);
        Assert.Contains(BootNumber, plan.RemovedPartitionNumbers);
        Assert.Contains(RootNumber, plan.RemovedPartitionNumbers);
    }

    [Fact]
    public void Plan_Sector4096_ScalesSectorOffsetsButNotRestoredBytes()
    {
        var plan = UninstallPlanner.Plan(Layout4096(), Record4096());

        Assert.Equal(UserdataStart4096, plan.UserdataStartSector);
        Assert.Equal(RootEnd4096, plan.UserdataEndSectorExclusive);
        Assert.Equal(224 * GiB, plan.RestoredAndroidBytes);

        Assert.Equal(2, plan.RemovedPartitionNumbers.Count);
        Assert.Contains(BootNumber, plan.RemovedPartitionNumbers);
        Assert.Contains(RootNumber, plan.RemovedPartitionNumbers);
    }

    [Fact]
    public void Plan_KeepsVendorWhoseGptNumberIsLargerAndLeavesInputListUnchanged()
    {
        var partitions = BasePartitions512();
        var before = (DiskPartition[])partitions.Clone();
        var layout = new DiskLayout("sdb", 512, partitions);

        var plan = UninstallPlanner.Plan(layout, Record512());

        // The vendor sits physically before userdata but carries the larger GPT number 30: it is neither
        // reclaimed nor considered owned, and only the two Linux partitions are removed.
        Assert.DoesNotContain(VendorNumber, plan.RemovedPartitionNumbers);
        Assert.DoesNotContain(UserdataNumber, plan.RemovedPartitionNumbers);

        // The caller's list is not reordered, resized or rewritten.
        Assert.Equal(before.Length, layout.Partitions.Count);
        for (var index = 0; index < before.Length; index++)
        {
            Assert.Equal(before[index], layout.Partitions[index]);
        }
    }

    // ----------------------------------------------------------- record/identity rejections

    [Fact]
    public void Plan_RejectsSwappedBootAndRootUuids()
    {
        var record = Record512() with
        {
            LinuxBootPartUuid = RootUuid,
            LinuxRootPartUuid = BootUuid,
        };

        AssertRejected(() => UninstallPlanner.Plan(Layout512(), record));
    }

    [Fact]
    public void Plan_RejectsDeviceIdMismatch()
    {
        var record = Record512() with { DeviceId = "sdc" };

        AssertRejected(() => UninstallPlanner.Plan(Layout512(), record));
    }

    [Fact]
    public void Plan_RejectsOriginalUserdataEndThatDoesNotMatchRootEnd()
    {
        AssertRejected(() => UninstallPlanner.Plan(Layout512(), Record512() with { OriginalUserdataEndSector = RootEnd512 - 1 }));
        AssertRejected(() => UninstallPlanner.Plan(Layout512(), Record512() with { OriginalUserdataEndSector = RootEnd512 + 1 }));
    }

    [Fact]
    public void Plan_RejectsMissingInstallationRecord()
    {
        AssertRejected(() => UninstallPlanner.Plan(Layout512(), null!));
    }

    [Fact]
    public void Plan_RejectsUnparseableRecordedPartUuid()
    {
        // The recorded value matches the layout string exactly, so only a real GUID-validity check can
        // reject this; a plain string comparison would wrongly accept it.
        const string invalid = "not-a-valid-guid";
        var partitions = Replace(BasePartitions512(), 1, BasePartitions512()[1] with { PartUuid = invalid });
        var layout = new DiskLayout("sdb", 512, partitions);
        var record = Record512() with { UserdataPartUuid = invalid };

        AssertRejected(() => UninstallPlanner.Plan(layout, record));
    }

    [Fact]
    public void Plan_RejectsDuplicatePartUuidAcrossOwnedPartitions()
    {
        // userdata and boot would share one PARTUUID: the record's three UUIDs are no longer distinct.
        var partitions = Replace(BasePartitions512(), 1, BasePartitions512()[1] with { PartUuid = BootUuid });
        partitions = Replace(partitions, 2, partitions[2] with { PartUuid = BootUuid });
        var layout = new DiskLayout("sdb", 512, partitions);
        var record = Record512() with { UserdataPartUuid = BootUuid };

        AssertRejected(() => UninstallPlanner.Plan(layout, record));
    }

    // ------------------------------------------------------------------ structural rejections

    [Theory]
    [InlineData(2)] // remove ARMADA_BOOT
    [InlineData(3)] // remove ARMADA_ROOT
    public void Plan_RejectsMissingOwnedPartition(int removeIndex)
    {
        var partitions = Remove(BasePartitions512(), removeIndex);

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsOnlyAndroidWithoutLinuxPartitions()
    {
        // post-install table with just vendor + userdata, no ARMADA_BOOT / ARMADA_ROOT to reclaim.
        var partitions = new[] { BasePartitions512()[0], BasePartitions512()[1] };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsWrongLabelOnAnOwnedPartition()
    {
        var wrongBoot = Replace(BasePartitions512(), 2, BasePartitions512()[2] with { Name = "boot" });
        var wrongRoot = Replace(BasePartitions512(), 3, BasePartitions512()[3] with { Name = "ARMADA_OTHER" });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, wrongBoot), Record512()));
        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, wrongRoot), Record512()));
    }

    [Fact]
    public void Plan_RejectsNonLinuxTypeOnAnOwnedPartition()
    {
        var basicBoot = Replace(BasePartitions512(), 2, BasePartitions512()[2] with { TypeGuid = MicrosoftBasicData });
        var espRoot = Replace(BasePartitions512(), 3, BasePartitions512()[3] with { TypeGuid = EspType });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, basicBoot), Record512()));
        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, espRoot), Record512()));
    }

    [Fact]
    public void Plan_RejectsOwnershipInferredFromNameAlone()
    {
        // Named ARMADA_BOOT but with a PARTUUID that is not the recorded one: name proves nothing.
        var impostor = Replace(
            BasePartitions512(),
            2,
            BasePartitions512()[2] with { PartUuid = "99999999-8888-4777-8666-555544443333" });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, impostor), Record512()));
    }

    [Fact]
    public void Plan_RejectsUnknownTrailingPartition()
    {
        var withTail = Append(
            BasePartitions512(),
            new DiskPartition(5, "metadata", RootEnd512, 2_048, LinuxType, "DDDDDDDD-EEEE-4FFF-8000-111122223333"));

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, withTail), Record512()));
    }

    [Fact]
    public void Plan_RejectsGapBetweenUserdataAndBoot()
    {
        // Shift boot and root one 1 MiB forward and keep root end consistent: the only defect left is the
        // gap between userdata's end and ARMADA_BOOT's start.
        var partitions = BasePartitions512();
        partitions = Replace(partitions, 2, partitions[2] with { StartSector = BootStart512 + 2_048 });
        partitions = Replace(partitions, 3, partitions[3] with { StartSector = RootStart512 + 2_048 });
        var record = Record512() with { OriginalUserdataEndSector = RootEnd512 + 2_048 };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), record));
    }

    [Fact]
    public void Plan_RejectsOverlappingOwnedPartitions()
    {
        // Root starts 2048 sectors early but grows to keep its end: it overlaps ARMADA_BOOT only.
        var partitions = BasePartitions512();
        partitions = Replace(
            partitions,
            3,
            partitions[3] with { StartSector = RootStart512 - 2_048, SectorCount = RootSectors512 + 2_048 });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsDuplicatePartitionNumber()
    {
        var partitions = Replace(BasePartitions512(), 2, BasePartitions512()[2] with { Number = UserdataNumber });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsMisalignedLinuxTail()
    {
        // Shift the whole tail by one sector so it stays contiguous and its end is consistent. The factory
        // userdata start may sit off a 1 MiB boundary, but the Linux tail may not: ARMADA_BOOT has to begin
        // on the first 1 MiB boundary at or after userdata's end, and here it starts one sector after it.
        var partitions = BasePartitions512();
        partitions = Replace(partitions, 1, partitions[1] with { StartSector = UserdataStart512 + 1 });
        partitions = Replace(partitions, 2, partitions[2] with { StartSector = BootStart512 + 1 });
        partitions = Replace(partitions, 3, partitions[3] with { StartSector = RootStart512 + 1 });
        var record = Record512() with { OriginalUserdataEndSector = RootEnd512 + 1 };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), record));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-512)]
    [InlineData(500)]
    [InlineData(3)]
    public void Plan_RejectsSectorSizesOtherThan512Or4096(int sectorSize)
    {
        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", sectorSize, BasePartitions512()), Record512()));
    }

    [Fact]
    public void Plan_RejectsNegativePartitionStart()
    {
        var partitions = Replace(BasePartitions512(), 1, BasePartitions512()[1] with { StartSector = -1 });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsSectorRangeOverflow()
    {
        var partitions = Replace(
            BasePartitions512(),
            2,
            BasePartitions512()[2] with { StartSector = long.MaxValue - 1_000 });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsNegativeOriginalUserdataEnd()
    {
        AssertRejected(() => UninstallPlanner.Plan(Layout512(), Record512() with { OriginalUserdataEndSector = -5 }));
    }

    [Fact]
    public void Plan_RejectsBootThatIsNotExactlyOneGiB()
    {
        // Grow boot by 1 MiB and shrink root by the same amount so the tail stays contiguous and its end
        // still matches the record; the only defect is the boot size.
        var partitions = BasePartitions512();
        var bootCount = BootSectors512 + 2_048;
        var bootEnd = BootStart512 + bootCount;
        partitions = Replace(partitions, 2, partitions[2] with { SectorCount = bootCount });
        partitions = Replace(
            partitions,
            3,
            partitions[3] with { StartSector = bootEnd, SectorCount = RootEnd512 - bootEnd });

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), Record512()));
    }

    [Fact]
    public void Plan_RejectsLinuxRootSmallerThan32GiB()
    {
        // 31 GiB root, contiguous, with the record end matching the (shorter) root end.
        const long rootSectors = 65_011_712; // 31 GiB / 512
        var partitions = Replace(BasePartitions512(), 3, BasePartitions512()[3] with { SectorCount = rootSectors });
        var record = Record512() with { OriginalUserdataEndSector = RootStart512 + rootSectors };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", 512, partitions), record));
    }

    [Theory]
    [InlineData(512)]
    [InlineData(4096)]
    public void Plan_RejectsUserdataWhoseLengthIsNotAWholeGiB(int sectorSize)
    {
        // Grow userdata by one sector, shift the whole tail by that same sector but keep boot and root
        // lengths and the recorded end consistent: contiguity, the exact 1 GiB boot and the record all
        // still match, so the only defect left is userdata's non-whole-GiB length.
        var partitions = sectorSize == 512 ? BasePartitions512() : BasePartitions4096();
        var bootStart = sectorSize == 512 ? BootStart512 : BootStart4096;
        var rootStart = sectorSize == 512 ? RootStart512 : RootStart4096;
        var rootEnd = sectorSize == 512 ? RootEnd512 : RootEnd4096;
        var record = sectorSize == 512 ? Record512() : Record4096();

        partitions = Replace(partitions, 1, partitions[1] with { SectorCount = partitions[1].SectorCount + 1 });
        partitions = Replace(partitions, 2, partitions[2] with { StartSector = bootStart + 1 });
        partitions = Replace(partitions, 3, partitions[3] with { StartSector = rootStart + 1 });
        record = record with { OriginalUserdataEndSector = rootEnd + 1 };

        AssertRejected(() => UninstallPlanner.Plan(new DiskLayout("sdb", sectorSize, partitions), record));
    }

    // ------------------------------------------------------------------------ helpers

    private static void AssertRejected(Action action)
    {
        var exception = Record.Exception(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is ArgumentException || exception is InvalidOperationException,
            "expected ArgumentException or InvalidOperationException but got " + exception!.GetType().FullName);
    }

    private static DiskLayout Layout512() => new("sdb", 512, BasePartitions512());

    private static DiskLayout Layout4096() => new("sdb", 4096, BasePartitions4096());

    private static LinuxInstallationLayout Record512()
        => new("sdb", UserdataUuid, BootUuid, RootUuid, RootEnd512);

    private static LinuxInstallationLayout Record4096()
        => new("sdb", UserdataUuid, BootUuid, RootUuid, RootEnd4096);

    private static DiskPartition[] BasePartitions512() => new[]
    {
        new DiskPartition(VendorNumber, "vendor", VendorStart512, VendorSectors512, MicrosoftBasicData, VendorUuid),
        new DiskPartition(UserdataNumber, "userdata", UserdataStart512, UserdataSectors512, MicrosoftBasicData, UserdataUuid),
        new DiskPartition(BootNumber, "ARMADA_BOOT", BootStart512, BootSectors512, LinuxType, BootUuid),
        new DiskPartition(RootNumber, "ARMADA_ROOT", RootStart512, RootSectors512, LinuxType, RootUuid),
    };

    private static DiskPartition[] BasePartitions4096() => new[]
    {
        new DiskPartition(VendorNumber, "vendor", VendorStart4096, VendorSectors4096, MicrosoftBasicData, VendorUuid),
        new DiskPartition(UserdataNumber, "userdata", UserdataStart4096, UserdataSectors4096, MicrosoftBasicData, UserdataUuid),
        new DiskPartition(BootNumber, "ARMADA_BOOT", BootStart4096, BootSectors4096, LinuxType, BootUuid),
        new DiskPartition(RootNumber, "ARMADA_ROOT", RootStart4096, RootSectors4096, LinuxType, RootUuid),
    };

    private static DiskPartition[] Replace(DiskPartition[] source, int index, DiskPartition value)
    {
        var copy = (DiskPartition[])source.Clone();
        copy[index] = value;
        return copy;
    }

    private static DiskPartition[] Remove(DiskPartition[] source, int index)
    {
        var copy = new DiskPartition[source.Length - 1];
        var target = 0;
        for (var cursor = 0; cursor < source.Length; cursor++)
        {
            if (cursor == index)
            {
                continue;
            }

            copy[target++] = source[cursor];
        }

        return copy;
    }

    private static DiskPartition[] Append(DiskPartition[] source, DiskPartition value)
    {
        var copy = new DiskPartition[source.Length + 1];
        source.CopyTo(copy, 0);
        copy[source.Length] = value;
        return copy;
    }
}
