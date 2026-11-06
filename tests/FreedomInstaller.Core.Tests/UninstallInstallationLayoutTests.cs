using System;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class UninstallInstallationLayoutTests
{
    private const string BackupUuid = "9abf724f-5ce5-4adc-8b71-c16040a2dfe3";

    [Theory]
    [InlineData("TB322FC", 4096)]
    [InlineData("TB323FU", 4096)]
    [InlineData("TB322FC", 512)]
    [InlineData("TB323FU", 512)]
    public void InstalledPlannerOutput_CanBeUninstalledWithoutMovingBackup(string model, int sector)
    {
        var (original, current, plan) = Build(sector, 0);
        var inputs = UninstallEvidenceValidator.ValidateEdl(
            new DeviceIdentity("TEST-TAIL-ALIGNMENT", model, BootloaderState.Unlocked), original, current, 0);

        Assert.True(plan.TailUnallocatedSectors > 0);
        Assert.Equal(123870976L * 4096 / sector, plan.BackupEndSectorExclusive);
        Assert.Equal(plan.BackupStartSector, inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal((plan.BackupStartSector - plan.OriginalUserdata.StartSector) * sector,
            inputs.Plan.RestoredAndroidBytes);
        Assert.Equal(new long[] { 3, 4 }, inputs.Plan.RemovedPartitionNumbers);
        var backup = current.Partitions.Single(p => p.Name == "ARMADA_BACKUP");
        Assert.Equal(2L << 30, backup.SectorCount * sector);
        Assert.Equal(1UL << 60, backup.Attributes);
        Assert.Equal(plan.OriginalUserdataEndSectorExclusive, inputs.Record.OriginalUserdataEndSector);
    }

    [Theory]
    [InlineData(4096, -1)]
    [InlineData(4096, 1)]
    [InlineData(4096, -256)]
    [InlineData(512, -1)]
    [InlineData(512, 1)]
    [InlineData(512, -2048)]
    public void RejectsTailThatIsNeitherFactoryEndNorInstallAlignment(int sector, long shift)
    {
        var (original, current, _) = Build(sector, shift);
        Assert.Throws<ArgumentException>(() => UninstallEvidenceValidator.ValidateEdl(
            new DeviceIdentity("TEST-TAIL-ALIGNMENT", "TB323FU", BootloaderState.Unlocked), original, current, 0));
    }

    private static (GptTable Original, GptTable Current, InternalAllocationPlan Plan) Build(int sector, long shift)
    {
        long scale = 4096 / sector;
        GptTable Parse(GptPartitionSpec[] partitions)
        {
            var image = new GptImage(sector, GptFixture.DiskBytes4096, GptFixture.DiskGuid,
                6 * scale, GptFixture.UserdataEndExclusive * scale - 1, partitions);
            return OriginalGptImporter.Parse(image.BuildPrimaryFragment(), image.BuildBackupFragment(),
                sector, GptFixture.DiskBytes4096);
        }

        var vendor = new GptPartitionSpec(1, "proinfo", GptFixture.ProinfoType, GptFixture.ProinfoUuid,
            GptFixture.ProinfoStart * scale, GptFixture.ProinfoCount * scale, 0);
        var original = Parse(new[] {
            vendor,
            new GptPartitionSpec(2, "userdata", GptFixture.UserdataType, GptFixture.UserdataUuid,
                GptFixture.UserdataStart * scale, GptFixture.UserdataCount * scale, 0)
        });
        var plan = InternalPartitionPlanner.Plan(original, 150,
            new PackageStorage(1L << 30, 32L << 30, 2L << 30, 1L << 30));
        var current = Parse(new[] {
            vendor,
            new GptPartitionSpec(2, "userdata", GptFixture.UserdataType, GptFixture.UserdataUuid,
                plan.OriginalUserdata.StartSector, plan.AndroidSectorCount, 0),
            new GptPartitionSpec(3, "ARMADA_BOOT", GptFixture.LinuxType, GptFixture.BootUuid,
                plan.LinuxBootStartSector, plan.LinuxBootSectorCount, 0),
            new GptPartitionSpec(4, "ARMADA_ROOT", GptFixture.LinuxType, GptFixture.RootUuid,
                plan.LinuxRootStartSector, plan.LinuxRootSectorCount + shift, 0),
            new GptPartitionSpec(5, "ARMADA_BACKUP", GptFixture.LinuxType, BackupUuid,
                plan.BackupStartSector + shift, plan.BackupSectorCount, 1UL << 60)
        });
        return (original, current, plan);
    }
}
