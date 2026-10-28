using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for the mounted data filesystem capacity that acceptance must observe in addition to the exact
/// userdata partition size. A full GPT of 449.75GiB can be correct while the filesystem on it is still the
/// old 128GiB one, so partition geometry alone proves nothing about the restored capacity.
/// <para>
/// The policy under test is the current G4 capacity rule: DataFilesystemBytes must be greater than zero, at
/// least 95% of the partition and no larger than the partition. It is not an OEM format guarantee and it is
/// not proof that files were erased; a too small or unknown value is pending capacity evidence.
/// </para>
/// <para>
/// Every test here uses a literal probe or the argv-recording command runner from the existing acceptance
/// tests. No device, USB handle, process or reboot exists in this file, and no test asserts on a stub.
/// </para>
/// </summary>
public sealed class AndroidUninstallFileSystemTests
{
    private const string Serial = "R58TEST0001";
    private const string Model = "TB322FC";
    private const string AdbPath = "/opt/android/platform-tools/adb";
    private const string Disk = "/dev/sda";

    /// <summary>GPT number of the fixture's userdata entry; the probe reads the device's own fact.</summary>
    private const int UserdataNumber = 2;

    /// <summary>The sysfs sector count of the restored 449.75GiB userdata extent, in 512-byte units.</summary>
    private const long RestoredSysfsUnits = 943_190_680L;

    /// <summary>The old filesystem that may survive on a correctly expanded partition.</summary>
    private const long Old128GiBBytes = 137_438_953_472L;

    [Fact]
    public async Task Verify_ExpandedGptWithOld128GiBFilesystemIsPending()
    {
        var inputs = Inputs();
        var partitionBytes = inputs.Plan.RestoredAndroidBytes;

        Assert.True(partitionBytes > Old128GiBBytes, "the fixture must model the expanded 449.75GiB layout");

        var probe = Literal(new AndroidUninstallObservation(Model, Serial, true, partitionBytes)
        {
            DataFilesystemBytes = Old128GiBBytes,
        });

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        // Exact geometry, but the mounted capacity is still the old one: evidence is pending, not accepted.
        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_NewFilesystemWithinPolicyIsAccepted()
    {
        var inputs = Inputs();
        var partitionBytes = inputs.Plan.RestoredAndroidBytes;

        var probe = Literal(new AndroidUninstallObservation(Model, Serial, true, partitionBytes)
        {
            DataFilesystemBytes = partitionBytes * 98L / 100L,
        });

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.True(result.Accepted);
    }

    [Fact]
    public async Task Verify_MissingFilesystemCapacityIsPending()
    {
        var inputs = Inputs();

        // The init property is deliberately omitted: no df row was readable, so nothing is guessed.
        var probe = Literal(new AndroidUninstallObservation(
            Model,
            Serial,
            true,
            inputs.Plan.RestoredAndroidBytes));

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_FilesystemLargerThanPartitionIsPending()
    {
        var inputs = Inputs();
        var partitionBytes = inputs.Plan.RestoredAndroidBytes;

        var probe = Literal(new AndroidUninstallObservation(Model, Serial, true, partitionBytes)
        {
            DataFilesystemBytes = partitionBytes + 1024L,
        });

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        // A mounted filesystem cannot be larger than the partition that holds it.
        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_Below95PercentIsPending()
    {
        var inputs = Inputs();
        var partitionBytes = inputs.Plan.RestoredAndroidBytes;

        var probe = Literal(new AndroidUninstallObservation(Model, Serial, true, partitionBytes)
        {
            DataFilesystemBytes = partitionBytes * 94L / 100L,
        });

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Read_PopulatesDataFilesystemBytesFromExactDataRow()
    {
        const long DataKBlocks = 450_000_000L;
        const long ExpectedFilesystemBytes = DataKBlocks * 1024L;

        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(Adb("shell", "cat", "/sys/class/block/sda2/size"), RestoredSysfsUnits + "\n")
            .Answer(
                Adb("shell", "readlink", "-f", "/dev/block/by-name/userdata"),
                "/dev/block/sda2\n")
            .Answer(
                Adb("shell", "-T", "df", "-k", "/data"),
                "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                    + "/dev/block/dm-6 450000000 1000000 440000000 1% /data\n");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, Disk, UserdataNumber);

        // The capacity comes from the /data row's 1K-blocks column, not from sysfs and not from a UI switch.
        Assert.NotNull(observation.DataFilesystemBytes);
        Assert.Equal(ExpectedFilesystemBytes, observation.DataFilesystemBytes);
        Assert.Equal(RestoredSysfsUnits * 512L, observation.UserdataPartitionBytes);
    }

    // ----------------------------------------------------------------------- helpers

    /// <summary>An argv key for <see cref="AndroidAcceptanceCommandRunner"/>: the serial-bound adb vector.</summary>
    private static string Adb(params string[] arguments)
        => string.Join(" ", new[] { "-s", Serial }.Concat(arguments));

    /// <summary>
    /// The real validated input set: raw GPT bytes through <see cref="OriginalGptImporter.Parse"/>, the
    /// sfdisk document through <see cref="UninstallEvidenceValidator.ReadCurrentSfdisk"/> and both through
    /// <see cref="UninstallEvidenceValidator.Validate"/>. No reflection and no internal constructor.
    /// </summary>
    private static ValidatedUninstallInputs Inputs()
    {
        var image = GptFixture.RealLike4096();

        var original = OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);

        var current = UninstallEvidenceValidator.ReadCurrentSfdisk(Sfdisk.Json(), GptFixture.DiskBytes4096);

        return UninstallEvidenceValidator.Validate(Identity(), original, current, current.SourceFingerprint);
    }

    /// <summary>The identity the user confirmed up front; acceptance compares against it, never re-derives it.</summary>
    private static DeviceIdentity Identity()
        => new(Serial, Model, BootloaderState.Unlocked);

    private static UninstallDeviceBinding Binding(DeviceIdentity identity)
        => new(identity, "SOC-0000-0001", identity.Serial, OtaUpdateState.Completed);

    private static LiteralObservationProbe Literal(AndroidUninstallObservation observation)
        => new(observation);

    /// <summary>A probe that returns one literal observation and reads no device at all.</summary>
    private sealed class LiteralObservationProbe : IAndroidUninstallAcceptanceProbe
    {
        private readonly AndroidUninstallObservation _observation;

        internal LiteralObservationProbe(AndroidUninstallObservation observation)
            => _observation = observation;

        public Task<AndroidUninstallObservation> ReadAsync(
            string serial,
            string diskDeviceId,
            int userdataPartitionNumber,
            CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();

            return Task.FromResult(_observation);
        }
    }
}
