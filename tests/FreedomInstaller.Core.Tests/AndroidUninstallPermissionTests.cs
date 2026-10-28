using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for the narrow, filesystem-only acceptance fallback that the physically proven TEST0001
/// OEM.259 device needs: its sysfs <c>size</c> node is not readable by the shell (and neither are the
/// alternatives), while <c>readlink -f /dev/block/by-name/userdata</c> still identifies the node and
/// <c>df -k /data</c> still reports the mounted capacity as <c>/data/user/0</c>.
/// <para>
/// The fallback is deliberately narrow. A permission denial is evidence about a missing size only when
/// the denial text names the exact sysfs path, the readlink target binds that path to the userdata
/// partition on this device, and the mounted filesystem can be read. Everything else - a wrong target,
/// an ordinary I/O error, a readable but wrong size, a missing or oversized capacity - stays pending,
/// and a readable size is always compared with the restored plan byte for byte even when the flag is set.
/// </para>
/// <para>
/// The validated inputs, the binding and the serial/model come from the real HTTP host fixture, so no
/// test constructs trusted evidence itself. No process, device, network or reboot exists here: the probe
/// level runs against <see cref="AndroidAcceptanceCommandRunner"/> with exact argv vectors, and the
/// decision level against a literal-observation probe. Nothing asserts on a stub exception.
/// </para>
/// </summary>
public sealed class AndroidUninstallPermissionTests
{
    private const string Serial = "R58TEST0001";
    private const string Model = "TB322FC";
    private const string AdbPath = "adb.exe";
    private const string Disk = "/dev/sda";

    /// <summary>The fixture's userdata partition number; 16 is the real device's number, not this table's.</summary>
    private const int UserdataNumber = 2;

    /// <summary>The physically observed ZUI capacity: 134,215,680 KiB mounted at <c>/data/user/0</c>.</summary>
    private const long ObservedDataKib = 134_215_680L;

    /// <summary>The old 128 GiB filesystem that must never be promoted to the expected partition size.</summary>
    private const long OldFilesystemBytes = 128L * 1024L * 1024L * 1024L;

    private const string SysfsPath = "/sys/class/block/sda2/size";
    private const string ReadlinkTarget = "/dev/block/by-name/userdata";

    // ------------------------------------------------------- probe: the permission-denied path

    [Fact]
    public async Task Read_ExplicitPermissionDenialWithExactReadlinkTarget_ReturnsZeroWithFlagAndCapacity()
    {
        using var host = new HttpHostFixture();
        var runner = PermissionDeniedRunner().Answer(
            Adb("shell", "readlink", "-f", ReadlinkTarget),
            "/dev/block/sda2\n");
        runner.Answer(
            Adb("shell", "-T", "df", "-k", "/data"),
            DataFilesystemRow(ObservedDataKib, "/data/user/0"));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, Disk, UserdataNumber);

        // The denied size is recorded as zero - the raw value that was actually read - with the explicit
        // flag, and the flag never turns zero into the expected plan size.
        Assert.Equal(0L, observation.UserdataPartitionBytes);
        Assert.True(observation.PartitionSizePermissionDenied);
        Assert.NotEqual(host.Inputs.Plan.RestoredAndroidBytes, observation.UserdataPartitionBytes);

        // The mounted capacity is the actual df value, converted from 1K-blocks.
        Assert.Equal(ObservedDataKib * 1024L, observation.DataFilesystemBytes);

        Assert.Equal(Model, observation.Model);
        Assert.Equal(Serial, observation.Serial);
        Assert.True(observation.BootCompleted);

        // Exactly the ordinary getprops, the denied size read, the one readlink and the one df.
        Assert.Equal(6, runner.Commands.Count);
        AssertCommand(runner.Commands[0], "-s", Serial, "shell", "getprop", "ro.product.model");
        AssertCommand(runner.Commands[1], "-s", Serial, "shell", "getprop", "ro.serialno");
        AssertCommand(runner.Commands[2], "-s", Serial, "shell", "getprop", "sys.boot_completed");
        AssertCommand(runner.Commands[3], "-s", Serial, "shell", "cat", SysfsPath);
        AssertCommand(runner.Commands[4], "-s", Serial, "shell", "readlink", "-f", ReadlinkTarget);
        AssertCommand(runner.Commands[5], "-s", Serial, "shell", "-T", "df", "-k", "/data");

        // No su, no alternate API, no alternate node: only the one permitted readlink path.
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Contains("su", StringComparer.Ordinal));
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Any(
            argument => argument.Contains("by-name", StringComparison.Ordinal) && argument != ReadlinkTarget));
    }

    [Fact]
    public async Task Read_PermissionDenialWithAWrongReadlinkTarget_IsAnIdentityBindingFailure()
    {
        var runner = PermissionDeniedRunner().Answer(
            Adb("shell", "readlink", "-f", ReadlinkTarget),
            "/dev/block/sda3\n");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        // The denial is real, but it does not describe this userdata partition: no fallback capacity may
        // be accepted for an unbound node, so the read is refused as untrustworthy evidence.
        await Assert.ThrowsAsync<InvalidDataException>(
            () => probe.ReadAsync(Serial, Disk, UserdataNumber));

        Assert.Equal(5, runner.Commands.Count);
        AssertCommand(runner.Commands[4], "-s", Serial, "shell", "readlink", "-f", ReadlinkTarget);
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Contains("df", StringComparer.Ordinal));
    }

    [Fact]
    public async Task Read_NonPermissionSysfsError_PropagatesWithoutAnyFallbackQuery()
    {
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(
                Adb("shell", "cat", SysfsPath),
                string.Empty,
                exitCode: 1,
                standardError: "cat: " + SysfsPath + ": Input/output error");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        await Assert.ThrowsAsync<IOException>(() => probe.ReadAsync(Serial, Disk, UserdataNumber));

        // Only the four reads up to the failing cat: no readlink and no df, because the failure is not
        // a permission denial and therefore proves nothing about the userdata identity.
        Assert.Equal(4, runner.Commands.Count);
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Any(
            argument => argument.Contains("readlink", StringComparison.Ordinal)));
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Contains("df", StringComparer.Ordinal));
    }

    // ---------------------------------------------------- decision: filesystem-only acceptance

    [Fact]
    public async Task Verify_PermissionDeniedWithNinetyEightPercentFilesystem_AcceptsOnFilesystemEvidenceAlone()
    {
        using var host = new HttpHostFixture();
        var plan = host.Inputs.Plan.RestoredAndroidBytes;
        var filesystemBytes = plan * 98L / 100L;

        var observation = Observation(host.Inputs, rawBytes: 0L, denied: true, dataFilesystemBytes: filesystemBytes);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.True(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        // The partition size was never observed, so it stays null; the expected plan value is never echoed.
        Assert.Null(result.UserdataPartitionBytes);

        // The actual mounted capacity is reported, and the result says the evidence was filesystem only.
        Assert.Equal(filesystemBytes, result.DataFilesystemBytes);
        Assert.True(result.FilesystemOnlyEvidence);
        Assert.NotEqual(plan, result.DataFilesystemBytes);
    }

    [Fact]
    public async Task Verify_PermissionDeniedWithTheOld128GiBFilesystem_StaysPending()
    {
        using var host = new HttpHostFixture();

        var observation = Observation(host.Inputs, rawBytes: 0L, denied: true, dataFilesystemBytes: OldFilesystemBytes);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Null(result.UserdataPartitionBytes);
    }

    [Fact]
    public async Task Verify_ZeroSizeWithoutThePermissionFlag_IsNeverAcceptedByCapacityAlone()
    {
        using var host = new HttpHostFixture();
        var plan = host.Inputs.Plan.RestoredAndroidBytes;

        // Zero with no permission proof: the capacity matches a full partition, but the missing size was
        // not explained, so nothing may be promoted to the expected value.
        var observation = Observation(host.Inputs, rawBytes: 0L, denied: false, dataFilesystemBytes: plan);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Null(result.UserdataPartitionBytes);
    }

    [Fact]
    public async Task Verify_ReadableWrongSizeWithTheFlag_RemainsPendingAndKeepsTheObservedValue()
    {
        using var host = new HttpHostFixture();
        var plan = host.Inputs.Plan.RestoredAndroidBytes;
        var wrongBytes = plan - 512L;

        // A readable size is always compared with the plan, even when the flag is set: the flag explains a
        // denial and can never excuse a wrong value.
        var observation = Observation(host.Inputs, wrongBytes, denied: true, dataFilesystemBytes: plan);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Equal(wrongBytes, result.UserdataPartitionBytes);
    }

    [Theory]
    [InlineData(false)] // no df capacity at all
    [InlineData(true)]  // a capacity larger than the restored partition
    public async Task Verify_PermissionDeniedWithUnusableCapacity_StaysPendingWithoutAcceptingAFilesystem(bool abovePlan)
    {
        using var host = new HttpHostFixture();
        var plan = host.Inputs.Plan.RestoredAndroidBytes;
        long? filesystemBytes = abovePlan ? plan + 4096L : null;

        var observation = Observation(host.Inputs, rawBytes: 0L, denied: true, dataFilesystemBytes: filesystemBytes);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Null(result.UserdataPartitionBytes);
        Assert.False(result.FilesystemOnlyEvidence);
    }

    [Fact]
    public async Task Verify_NormalExactSizeWithNinetyEightPercentFilesystem_AcceptsAndReportsTheActualCapacity()
    {
        using var host = new HttpHostFixture();
        var plan = host.Inputs.Plan.RestoredAndroidBytes;
        var filesystemBytes = plan * 98L / 100L;

        var observation = Observation(host.Inputs, plan, denied: false, dataFilesystemBytes: filesystemBytes);
        var probe = new PermissionLiteralProbe(observation);

        var result = await AndroidUninstallAcceptance.VerifyAsync(host.Inputs, host.Binding, probe);

        Assert.True(result.Accepted);
        Assert.Equal(plan, result.UserdataPartitionBytes);
        Assert.Equal(filesystemBytes, result.DataFilesystemBytes);
        Assert.False(result.FilesystemOnlyEvidence);
        Assert.NotEqual(plan, result.DataFilesystemBytes);
    }

    // ----------------------------------------------------------------------- helpers

    /// <summary>
    /// The physically observed permission-denied sequence: model, serial, boot flag and an explicit
    /// <c>Permission denied</c> for the exact sysfs path. The readlink and df answers are added by each test.
    /// </summary>
    private static AndroidAcceptanceCommandRunner PermissionDeniedRunner()
        => new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(
                Adb("shell", "cat", SysfsPath),
                string.Empty,
                exitCode: 1,
                standardError: "cat: " + SysfsPath + ": Permission denied");

    /// <summary>
    /// A literal observation with the confirmed identity from the fixture. Nothing is derived: the caller
    /// states the raw size, the flag and the mounted capacity, and the probe returns exactly those values.
    /// </summary>
    private static AndroidUninstallObservation Observation(
        ValidatedUninstallInputs inputs,
        long rawBytes,
        bool denied,
        long? dataFilesystemBytes)
        => new(inputs.Identity.Model, inputs.Identity.Serial, BootCompleted: true, rawBytes)
        {
            PartitionSizePermissionDenied = denied,
            DataFilesystemBytes = dataFilesystemBytes,
        };

    /// <summary>An exact <c>df -k /data</c> row in 1K-blocks; ZUI reports the alias mount.</summary>
    private static string DataFilesystemRow(long totalKBlocks, string mountPoint)
        => "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            + "/dev/block/dm-6 " + totalKBlocks + " 0 " + totalKBlocks + " 0% " + mountPoint + "\n";

    private static string Adb(params string[] arguments)
        => string.Join(" ", new[] { "-s", Serial }.Concat(arguments));

    private static void AssertCommand(ProcessCommand command, params string[] expectedArguments)
    {
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(expectedArguments, command.Arguments.ToArray());
    }
}

/// <summary>
/// Literal-evidence probe for the decision tests: it returns exactly the observation it was given and
/// records what was asked, so no value is ever derived from the plan or from a device answer.
/// </summary>
internal sealed class PermissionLiteralProbe : IAndroidUninstallAcceptanceProbe
{
    private readonly AndroidUninstallObservation _observation;

    internal PermissionLiteralProbe(AndroidUninstallObservation observation)
        => _observation = observation;

    internal List<ProbeRequest> Requests { get; } = new();

    public Task<AndroidUninstallObservation> ReadAsync(
        string serial,
        string diskDeviceId,
        int userdataPartitionNumber,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        Requests.Add(new ProbeRequest(serial, diskDeviceId, userdataPartitionNumber));
        return Task.FromResult(_observation);
    }
}
