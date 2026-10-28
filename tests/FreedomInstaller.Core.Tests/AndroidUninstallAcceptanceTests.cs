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
/// Contract for <see cref="AndroidUninstallAcceptance"/> and <see cref="AdbAndroidUninstallAcceptanceProbe"/>.
/// The point of this file is that Android acceptance is never inferred: not from a user interface switch,
/// not from a workflow result and not from the fact that the uninstall was requested. It is one read-only
/// observation of a booted device, compared byte for byte with the restored plan.
/// <para>
/// The validated inputs are built through the real <see cref="UninstallEvidenceValidator"/> over the shared
/// GPT and sfdisk fixtures (<see cref="GptFixture.RealLike4096"/>, <see cref="Sfdisk.Json"/>); there is no
/// reflection and no internal-constructor bypass. Until the validator and the acceptance methods are
/// implemented, these tests fail with <see cref="NotImplementedException"/>, which is the intended red
/// state: no test here asserts on <see cref="NotImplementedException"/> itself, so each method will keep
/// checking the behaviour it names once the implementation lands.
/// </para>
/// <para>
/// No process, device, USB handle or reboot exists in this file: every external command goes to
/// <see cref="AndroidAcceptanceCommandRunner"/> and every device reading to <see cref="FakeAcceptanceProbe"/>.
/// </para>
/// </summary>
public sealed class AndroidUninstallAcceptanceTests
{
    private const string Serial = "R58TEST0001";
    private const string Model = "TB322FC";
    private const string AdbPath = "/opt/android/platform-tools/adb";
    private const string Disk = "/dev/sda";

    /// <summary>GPT number of the fixture's userdata entry; deliberately not 16, which is a common guess.</summary>
    private const int UserdataNumber = 2;

    /// <summary>
    /// The restored Android extent in 512-byte sysfs units. sysfs counts 512-byte units whatever the GPT
    /// sector size is, so this is the value a real device would print for the restored userdata.
    /// </summary>
    private const long RestoredSysfsUnits = 943_190_680L;

    /// <summary>Commands that would change the device. No acceptance read may contain any of them.</summary>
    private static readonly string[] ForbiddenVerbs =
    {
        "reboot", "recovery", "sideload", "push", "pull", "install", "uninstall", "rm", "mv", "dd",
        "mkfs", "mke2fs", "resize2fs", "format", "erase", "flash", "flashall", "fastboot", "oem",
        "remount", "root", "wipe", "fsck", "mount", "settings", "pm", "am", "svc", "setprop",
    };

    // ------------------------------------------------------------- argv and timeouts

    [Fact]
    public async Task Read_QueriesOnlyTheAllowedReadOnlyArgvWithFiniteTimeouts()
    {
        var runner = AcceptingRunner();
        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, Disk, UserdataNumber);

        Assert.Equal(Model, observation.Model);
        Assert.Equal(Serial, observation.Serial);
        Assert.True(observation.BootCompleted);

        // 943,190,680 sysfs units of 512 bytes are exactly the restorable userdata extent.
        Assert.Equal(RestoredSysfsUnits * 512L, observation.UserdataPartitionBytes);
        Assert.Equal(GptFixture.RestoredAndroidBytes, observation.UserdataPartitionBytes);

        Assert.Equal(6, runner.Commands.Count);
        AssertCommand(runner.Commands[0], "-s", Serial, "shell", "getprop", "ro.product.model");
        AssertCommand(runner.Commands[1], "-s", Serial, "shell", "getprop", "ro.serialno");
        AssertCommand(runner.Commands[2], "-s", Serial, "shell", "getprop", "sys.boot_completed");

        // The size node is the fixture's own userdata number, and the sysfs path is one literal argument:
        // no shell string, no interpolated disk, no shell metacharacter can enter the command.
        AssertCommand(runner.Commands[3], "-s", Serial, "shell", "cat", "/sys/class/block/sda2/size");

        // The actual userdata node is read once, after the readable size and before the capacity row.
        AssertCommand(
            runner.Commands[4],
            "-s", Serial, "shell", "readlink", "-f", "/dev/block/by-name/userdata");

        // One read-only capacity row, with every argument a separate argv entry and no format command.
        AssertCommand(runner.Commands[5], "-s", Serial, "shell", "-T", "df", "-k", "/data");
        Assert.DoesNotContain(runner.Commands, command => command.Arguments.Any(a => a.Contains("sda16", StringComparison.Ordinal)));

        var dataFilesystemQuery = new[] { "-s", Serial, "shell", "-T", "df", "-k", "/data" };

        foreach (var command in runner.Commands)
        {
            Assert.Equal(AdbPath, command.Executable);
            Assert.True(command.Timeout > TimeSpan.Zero, "a query timeout must be finite and positive");
            Assert.True(command.Timeout <= TimeSpan.FromSeconds(15), "a query timeout must not exceed 15 seconds");

            Assert.Equal("shell", command.Arguments[2]);
            Assert.True(
                command.Arguments[3] == "getprop" || command.Arguments[3] == "cat"
                    || command.Arguments[3] == "readlink"
                    || command.Arguments.SequenceEqual(dataFilesystemQuery),
                "only the documented getprop, cat, readlink and df reads are allowed");

            foreach (var argument in command.Arguments)
            {
                Assert.DoesNotContain(argument.ToLowerInvariant(), ForbiddenVerbs);
            }
        }
    }

    [Fact]
    public async Task Read_ConvertsSysfs512ByteUnitsRegardlessOfTheGptSectorSize()
    {
        // The fixture's current userdata is 33,554,432 GPT sectors of 4096 bytes. sysfs still reports
        // 512-byte units, so the device prints 268,435,456 - not 33,554,432 and not a 4096-byte product.
        const long GptSectors = 33_554_432L;
        const long ExpectedBytes = GptSectors * 4096L;
        const long SysfsUnits = ExpectedBytes / 512L;

        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(Adb("shell", "cat", "/sys/class/block/sda2/size"), SysfsUnits + "\n")
            .Answer(
                Adb("shell", "readlink", "-f", "/dev/block/by-name/userdata"),
                "/dev/block/sda2\n")
            .Answer(Adb("shell", "-T", "df", "-k", "/data"), DataFilesystemRow(ExpectedBytes / 1024L));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, Disk, UserdataNumber);

        Assert.Equal(ExpectedBytes, observation.UserdataPartitionBytes);
        Assert.NotEqual(SysfsUnits * 4096L, observation.UserdataPartitionBytes);
    }

    [Fact]
    public async Task Read_UsesTheBootSerialOnlyWhenTheSerialnoPropertyIsEmpty()
    {
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), "  \n")
            .Answer(Adb("shell", "getprop", "ro.boot.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(Adb("shell", "cat", "/sys/class/block/sda2/size"), RestoredSysfsUnits + "\n")
            .Answer(
                Adb("shell", "readlink", "-f", "/dev/block/by-name/userdata"),
                "/dev/block/sda2\n")
            .Answer(Adb("shell", "-T", "df", "-k", "/data"), DataFilesystemRow(GptFixture.RestoredAndroidBytes / 1024L));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, Disk, UserdataNumber);

        Assert.Equal(Serial, observation.Serial);
        Assert.Equal(7, runner.Commands.Count);
        AssertCommand(runner.Commands[2], "-s", Serial, "shell", "getprop", "ro.boot.serialno");
        AssertCommand(runner.Commands[4], "-s", Serial, "shell", "cat", "/sys/class/block/sda2/size");
        AssertCommand(
            runner.Commands[5],
            "-s", Serial, "shell", "readlink", "-f", "/dev/block/by-name/userdata");
        AssertCommand(runner.Commands[6], "-s", Serial, "shell", "-T", "df", "-k", "/data");
    }

    // ------------------------------------------------ rejected targets and bad device output

    [Theory]
    [InlineData("/dev/sdb", Serial, UserdataNumber)]        // another disk
    [InlineData("/dev/sda2", Serial, UserdataNumber)]       // already carries a partition number
    [InlineData("/dev/../dev/sda", Serial, UserdataNumber)] // path traversal spelling
    [InlineData("", Serial, UserdataNumber)]
    [InlineData(Disk, "", UserdataNumber)]
    [InlineData(Disk, " ", UserdataNumber)]
    [InlineData(Disk, "-s all", UserdataNumber)]            // a serial that looks like an option
    [InlineData(Disk, "R58 TEST0001", UserdataNumber)]      // embedded whitespace
    [InlineData(Disk, "R58\tTEST0001", UserdataNumber)]     // embedded control character
    [InlineData(Disk, Serial, 0)]
    [InlineData(Disk, Serial, -1)]
    [InlineData(Disk, Serial, 129)]                         // above the accepted maximum
    public async Task Read_RejectsAnUntrustworthyTargetBeforeAnyCommand(
        string disk, string? serial, int partitionNumber)
    {
        var runner = new AndroidAcceptanceCommandRunner();
        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => probe.ReadAsync(serial!, disk, partitionNumber));

        // Nothing was started: a bad target must fail before the first adb invocation.
        Assert.Empty(runner.Commands);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("+268435456")]
    [InlineData("268435456.5")]
    [InlineData("not a number")]
    [InlineData("94319068000000000000")]          // above Int64.MaxValue before the multiply
    [InlineData("18446744073709551615")]          // ulong maximum: parses, then overflows on x512
    public async Task Read_RejectsAnInvalidOrOverflowingSysfsLength(string sizeUnits)
    {
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(Adb("shell", "cat", "/sys/class/block/sda2/size"), sizeUnits + "\n");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        // A size that was not read cannot become an observation: no fallback, no zero, no clamp.
        await AssertReadRefusedAsync(() => probe.ReadAsync(Serial, Disk, UserdataNumber));
    }

    [Fact]
    public async Task Read_FailsWhenAQueryExitsNonZero()
    {
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), string.Empty, exitCode: 1, standardError: "error: device offline");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        await AssertReadRefusedAsync(() => probe.ReadAsync(Serial, Disk, UserdataNumber));
    }

    [Fact]
    public async Task Read_FailsWhenAPropertyIsMissing()
    {
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n");

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        await AssertReadRefusedAsync(() => probe.ReadAsync(Serial, Disk, UserdataNumber));
    }

    [Fact]
    public async Task Read_HonoursCancellationBeforeTheFirstCommand()
    {
        var runner = new AndroidAcceptanceCommandRunner();
        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => probe.ReadAsync(Serial, Disk, UserdataNumber, cancellation.Token));

        Assert.Empty(runner.Commands);
    }

    // --------------------------------------------------------------- acceptance decision

    [Fact]
    public async Task Verify_AcceptsOnlyTheConfirmedDeviceWithExactlyTheRestoredUserdataSize()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            inputs.Identity.Serial,
            inputs.Identity.Model,
            bootCompleted: true,
            inputs.Plan.RestoredAndroidBytes);

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.True(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Equal(inputs.Plan.RestoredAndroidBytes, result.UserdataPartitionBytes);

        // The fixture's restored extent is a whole number of 512-byte sysfs units, which is the only unit a
        // real reading can report; this ties the accepted byte count to the probe contract above.
        Assert.Equal(GptFixture.RestoredAndroidBytes, inputs.Plan.RestoredAndroidBytes);
        Assert.Equal(0L, inputs.Plan.RestoredAndroidBytes % 512L);

        // Exactly one read, for the confirmed serial, on the current table's node, for the userdata entry
        // the table actually carries. A hardcoded number such as 16 would ask the device for a wrong node.
        Assert.Single(probe.Requests);
        var request = probe.Requests[0];
        Assert.Equal(inputs.Identity.Serial, request.Serial);
        Assert.Equal(Disk, request.DiskDeviceId);
        Assert.Equal(UserdataNumber, request.UserdataPartitionNumber);
        Assert.NotEqual(16, request.UserdataPartitionNumber);
    }

    [Fact]
    public async Task Verify_RejectsADeviceThatReportsAnotherSerial()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            "R58TEST9999", inputs.Identity.Model, bootCompleted: true, inputs.Plan.RestoredAndroidBytes);

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_RejectsADeviceThatReportsAnotherModel()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            inputs.Identity.Serial, "TB999XX", bootCompleted: true, inputs.Plan.RestoredAndroidBytes);

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_RejectsAndroidThatHasNotCompletedBoot()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            inputs.Identity.Serial, inputs.Identity.Model, bootCompleted: false, inputs.Plan.RestoredAndroidBytes);

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        // sys.boot_completed was not 1: the system is still coming up, so nothing is proven yet.
        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_RejectsAUserdataPartitionOfTheWrongSize()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            inputs.Identity.Serial,
            inputs.Identity.Model,
            bootCompleted: true,
            inputs.Plan.RestoredAndroidBytes - 512L);

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        // One 512-byte unit short is still the wrong partition: sizes are compared, never bounded.
        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public async Task Verify_ReportsPendingEvidenceWhenTheProbeCannotRead()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Failing(new IOException("adb: no devices/emulators found"));

        var result = await AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe);

        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Null(result.UserdataPartitionBytes);
        Assert.Single(probe.Requests);
    }

    [Fact]
    public async Task Verify_PropagatesCallerCancellationWithoutTouchingTheDevice()
    {
        var inputs = Inputs();
        var probe = FakeAcceptanceProbe.Reading(
            inputs.Identity.Serial, inputs.Identity.Model, bootCompleted: true, inputs.Plan.RestoredAndroidBytes);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AndroidUninstallAcceptance.VerifyAsync(inputs, Binding(inputs.Identity), probe, cancellation.Token));

        Assert.Empty(probe.Requests);
    }

    // ----------------------------------------------------------------------- helpers

    /// <summary>
    /// The real validated input set: raw GPT bytes through <see cref="OriginalGptImporter.Parse"/>, the
    /// sfdisk document through <see cref="UninstallEvidenceValidator.ReadCurrentSfdisk"/> and both through
    /// <see cref="UninstallEvidenceValidator.Validate"/>. Nothing here reaches into a private constructor,
    /// so a later validator change cannot silently bypass the evidence checks this contract depends on.
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

    /// <summary>
    /// The identity the user confirmed up front: a supported model and a synthetic serial. The acceptance
    /// check may only ever compare against these values, never re-derive them from a device answer.
    /// </summary>
    private static DeviceIdentity Identity()
        => new(Serial, Model, BootloaderState.Unlocked);

    /// <summary>The binding the HTTP backend built for this device; it names the same confirmed identity.</summary>
    private static UninstallDeviceBinding Binding(DeviceIdentity identity)
        => new(identity, "SOC-0000-0001", identity.Serial, OtaUpdateState.Completed);

    /// <summary>An argv key for <see cref="AndroidAcceptanceCommandRunner"/>: the serial-bound adb command vector.</summary>
    private static string Adb(params string[] arguments)
        => string.Join(" ", new[] { "-s", Serial }.Concat(arguments));

    private static AndroidAcceptanceCommandRunner AcceptingRunner()
        => new AndroidAcceptanceCommandRunner()
            .Answer(Adb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(Adb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(Adb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(Adb("shell", "cat", "/sys/class/block/sda2/size"), RestoredSysfsUnits + "\n")
            .Answer(
                Adb("shell", "readlink", "-f", "/dev/block/by-name/userdata"),
                "/dev/block/sda2\n")
            .Answer(Adb("shell", "-T", "df", "-k", "/data"), DataFilesystemRow(GptFixture.RestoredAndroidBytes / 1024L));

    /// <summary>
    /// The exact <c>df -k /data</c> document: a header plus one data row in 1K-blocks. The capacity is the
    /// only value the probe may use; the block device name and the mount point are the device's own.
    /// </summary>
    private static string DataFilesystemRow(long totalKBlocks)
        => "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            + "/dev/block/dm-6 " + totalKBlocks + " 1 " + (totalKBlocks - 1L) + " 1% /data\n";

    private static void AssertCommand(ProcessCommand command, params string[] expectedArguments)
    {
        // Compared as a sequence of separate argv entries, so a re-joined or re-quoted vector fails here.
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(expectedArguments, command.Arguments.ToArray());
    }

    /// <summary>
    /// A refused read surfaces as <see cref="InvalidDataException"/> (the text is not trustworthy evidence)
    /// or as <see cref="IOException"/> (the query itself failed). What matters is that no observation was
    /// fabricated, so both are allowed and a successful return is not.
    /// </summary>
    private static async Task AssertReadRefusedAsync(Func<Task<AndroidUninstallObservation>> action)
    {
        var exception = await Record.ExceptionAsync(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is InvalidDataException || exception is IOException,
            "expected InvalidDataException or IOException but got " + exception!.GetType().FullName);
    }
}

/// <summary>
/// argv-recording <see cref="ICommandRunner"/>. It only answers the exact vectors a test scripted, so an
/// extra, missing, reordered or differently quoted argument fails the test instead of passing silently.
/// </summary>
internal sealed class AndroidAcceptanceCommandRunner : ICommandRunner
{
    private readonly Dictionary<string, ProcessResult> _replies = new(StringComparer.Ordinal);

    internal List<ProcessCommand> Commands { get; } = new();

    internal AndroidAcceptanceCommandRunner Answer(string arguments, string standardOutput, int exitCode = 0, string standardError = "")
    {
        _replies[arguments] = new ProcessResult(exitCode, standardOutput, standardError);
        return this;
    }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var key = string.Join(" ", command.Arguments);
        Commands.Add(command);

        if (!_replies.TryGetValue(key, out var result))
        {
            throw new InvalidOperationException($"unexpected command vector: {command.Executable} {key}");
        }

        return Task.FromResult(result);
    }
}

/// <summary>One read request the acceptance check made, kept so a test can prove what was asked for.</summary>
internal sealed record ProbeRequest(string Serial, string DiskDeviceId, int UserdataPartitionNumber);

/// <summary>
/// Literal-evidence probe: it never reads a device and never derives a value, it only returns the exact
/// observation a test scripted, or the exact failure it was built with.
/// </summary>
internal sealed class FakeAcceptanceProbe : IAndroidUninstallAcceptanceProbe
{
    private readonly AndroidUninstallObservation? _observation;
    private readonly Exception? _failure;

    private FakeAcceptanceProbe(AndroidUninstallObservation? observation, Exception? failure)
    {
        _observation = observation;
        _failure = failure;
    }

    internal List<ProbeRequest> Requests { get; } = new();

    internal static FakeAcceptanceProbe Reading(string serial, string model, bool bootCompleted, long userdataBytes)
        => new(
            new AndroidUninstallObservation(model, serial, bootCompleted, userdataBytes)
            {
                // Old positive cases already prove partition capacity; the mounted size defaults to the
                // same device fact unless a test explicitly supplies a different one.
                DataFilesystemBytes = userdataBytes,
            },
            null);

    internal static FakeAcceptanceProbe Failing(Exception failure)
        => new(null, failure);

    public Task<AndroidUninstallObservation> ReadAsync(
        string serial,
        string diskDeviceId,
        int userdataPartitionNumber,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        Requests.Add(new ProbeRequest(serial, diskDeviceId, userdataPartitionNumber));

        if (_failure is not null)
        {
            throw _failure;
        }

        return Task.FromResult(_observation!);
    }
}
