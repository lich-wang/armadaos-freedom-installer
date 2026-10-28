using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

internal sealed class FakeCommandRunner : ICommandRunner
{
    private readonly Queue<ProcessResult> _queued = new();

    public List<ProcessCommand> Commands { get; } = new();

    public FakeCommandRunner Enqueue(ProcessResult result)
    {
        _queued.Enqueue(result);
        return this;
    }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Commands.Add(command);

        if (_queued.Count == 0)
        {
            throw new InvalidOperationException("Unexpected command issued: " + command.Executable);
        }

        return Task.FromResult(_queued.Dequeue());
    }
}

internal static class RedAssert
{
    public static Exception Rejected(Action action)
    {
        var exception = Record.Exception(action);
        Assert.NotNull(exception);
        Assert.IsNotType<NotImplementedException>(exception);
        return exception!;
    }

    public static async Task<Exception> RejectedAsync(Func<Task> action)
    {
        var exception = await Record.ExceptionAsync(action);
        Assert.NotNull(exception);
        Assert.IsNotType<NotImplementedException>(exception);
        return exception!;
    }
}

public sealed class MaintenanceEntryAndroidReadTests
{
    private const string AdbPath = "/opt/platform-tools/adb";
    private const string FastbootPath = "/opt/platform-tools/fastboot";
    private const string Serial = "HA1B2C3D4";
    private const string SocSerial = "0A1B2C3D4E5F";

    private static DeviceIdentity CreateIdentity(string model = MaintenanceProfiles.Model, string serial = Serial)
        => new(serial, model, BootloaderState.Unlocked);

    private static MaintenanceEntry CreateEntry(FakeCommandRunner runner)
        => new(AdbPath, FastbootPath, runner);

    [Theory]
    [InlineData("TB322FC")]
    [InlineData("TB323FU")]
    public async Task ReadAndroidAsync_uses_exact_adb_argv_and_preserves_identity(string model)
    {
        var runner = new FakeCommandRunner().Enqueue(new ProcessResult(0, SocSerial + "\n", string.Empty));
        var entry = CreateEntry(runner);
        var identity = CreateIdentity(model);

        var result = await entry.ReadAndroidAsync(identity);

        var command = Assert.Single(runner.Commands);
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(
            new[] { "-s", Serial, "shell", "cat", "/sys/devices/soc0/serial_number" },
            command.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(10), command.Timeout);
        Assert.Equal(SocSerial, result.SocSerial);
        Assert.Equal(identity.Serial, result.Identity.Serial);
        Assert.Equal(identity.Model, result.Identity.Model);
    }

    [Theory]
    [InlineData(1, "0A1B2C3D")]
    [InlineData(0, "")]
    [InlineData(0, "  \n")]
    [InlineData(0, "0A1B 2C3D")]
    [InlineData(0, "0A1B\n2C3D")]
    [InlineData(0, "<serial>")]
    public async Task ReadAndroidAsync_rejects_nonzero_exit_or_malformed_soc_serial(int exitCode, string stdout)
    {
        var runner = new FakeCommandRunner().Enqueue(new ProcessResult(exitCode, stdout, string.Empty));
        var entry = CreateEntry(runner);

        await RedAssert.RejectedAsync(() => entry.ReadAndroidAsync(CreateIdentity()));
    }

    [Fact]
    public async Task ReadAndroidAsync_rejects_soc_serial_longer_than_64_characters()
    {
        var runner = new FakeCommandRunner().Enqueue(new ProcessResult(0, new string('A', 65), string.Empty));
        var entry = CreateEntry(runner);

        await RedAssert.RejectedAsync(() => entry.ReadAndroidAsync(CreateIdentity()));
    }

    [Fact]
    public async Task ReadAndroidAsync_rejects_empty_serial_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = CreateEntry(runner);

        await RedAssert.RejectedAsync(() => entry.ReadAndroidAsync(CreateIdentity(serial: " ")));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task ReadAndroidAsync_rejects_unsupported_model_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = CreateEntry(runner);

        await RedAssert.RejectedAsync(() => entry.ReadAndroidAsync(CreateIdentity(model: "TB999ZZ")));
        Assert.Empty(runner.Commands);
    }
}

public sealed class MaintenanceEntryBootTemporaryTests
{
    private const string AdbPath = "/opt/platform-tools/adb";
    private const string FastbootPath = "/opt/platform-tools/fastboot";
    private const string Serial = "HA1B2C3D4";
    private const string SocSerial = "0A1B2C3D4E5F";
    private const string MissingBootPath = "ui001-boot-image-not-present.img";

    private static AndroidMaintenanceIdentity CreateAndroid(
        string model = MaintenanceProfiles.Model,
        string displayId = MaintenanceProfiles.AndroidBuild,
        string socSerial = SocSerial)
        => new(
            new DeviceIdentity(Serial, model, BootloaderState.Unlocked)
            {
                Firmware = new FirmwareSnapshot(displayId, "google/fingerprint", "16", "2026-06-01", BootloaderState.Unlocked),
            },
            socSerial);

    [Fact]
    public async Task BootTemporaryAsync_rejects_non_g4_model_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        await RedAssert.RejectedAsync(() => entry.BootTemporaryAsync(CreateAndroid(model: "TB323FU"), MissingBootPath));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task BootTemporaryAsync_rejects_build_mismatch_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        await RedAssert.RejectedAsync(() => entry.BootTemporaryAsync(CreateAndroid(displayId: "TB322FC_WRONG_BUILD"), MissingBootPath));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task BootTemporaryAsync_rejects_invalid_soc_serial_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        await RedAssert.RejectedAsync(() => entry.BootTemporaryAsync(CreateAndroid(socSerial: "BAD SOC"), MissingBootPath));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task BootTemporaryAsync_rejects_missing_boot_image_before_running_any_command()
    {
        var runner = new FakeCommandRunner();
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        await RedAssert.RejectedAsync(() => entry.BootTemporaryAsync(CreateAndroid(), MissingBootPath));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task BootTemporaryAsync_observes_cancellation_before_any_io()
    {
        var runner = new FakeCommandRunner();
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => entry.BootTemporaryAsync(CreateAndroid(), MissingBootPath, new CancellationToken(canceled: true)));
        Assert.Empty(runner.Commands);
    }
}

public sealed class MaintenanceEntryParsingTests
{
    [Fact]
    public void ReadFastbootVariable_reads_prefixed_line_and_ignores_finished_banner()
    {
        const string output = "(bootloader) serialno: 8A1B2C3D\nFinished. Total time: 0.002s\n";

        Assert.Equal("8A1B2C3D", MaintenanceEntry.ReadFastbootVariable(output, "serialno"));
    }

    [Fact]
    public void ReadFastbootVariable_reads_unprefixed_line()
    {
        Assert.Equal("8A1B2C3D", MaintenanceEntry.ReadFastbootVariable("serialno: 8A1B2C3D", "serialno"));
    }

    [Fact]
    public void ReadFastbootVariable_accepts_duplicate_identical_value_from_stdout_and_stderr()
    {
        const string output = "(bootloader) serialno: 8A1B2C3D\nserialno: 8A1B2C3D\nFinished. Total time: 0.004s\n";

        Assert.Equal("8A1B2C3D", MaintenanceEntry.ReadFastbootVariable(output, "serialno"));
    }

    [Fact]
    public void ReadFastbootVariable_preserves_value_case()
    {
        Assert.Equal("aBc-DeF", MaintenanceEntry.ReadFastbootVariable("serialno: aBc-DeF", "serialno"));
    }

    [Theory]
    [InlineData("serialno: 8A1B2C3D\nserialno: DEADBEEF\n")]
    [InlineData("Finished. Total time: 0.002s\n")]
    [InlineData("product: TB322FC\n")]
    [InlineData("serialno:\n")]
    [InlineData("")]
    public void ReadFastbootVariable_rejects_missing_empty_or_contradictory_values(string output)
    {
        RedAssert.Rejected(() => MaintenanceEntry.ReadFastbootVariable(output, "serialno"));
    }

    [Theory]
    [InlineData("(bootloader) snapshot-update-status: none\nFinished. Total time: 0.001s\n")]
    [InlineData("snapshot-update-status: NONE")]
    [InlineData("snapshot-update-status: None")]
    public void ParseSnapshotUpdateState_maps_none_to_completed(string output)
    {
        Assert.Equal(OtaUpdateState.Completed, MaintenanceEntry.ParseSnapshotUpdateState(output));
    }

    [Fact]
    public void ParseSnapshotUpdateState_maps_merging_to_merging()
    {
        Assert.Equal(OtaUpdateState.Merging, MaintenanceEntry.ParseSnapshotUpdateState("(bootloader) snapshot-update-status: merging"));
    }

    [Theory]
    [InlineData("Finished. Total time: 0.001s\n")]
    [InlineData("snapshot-update-status: unknown")]
    [InlineData("snapshot-update-status: none\nsnapshot-update-status: merging\n")]
    [InlineData("garbage")]
    [InlineData("")]
    public void ParseSnapshotUpdateState_maps_missing_unknown_or_conflicting_to_unknown_without_throwing(string output)
    {
        Assert.Equal(OtaUpdateState.Unknown, MaintenanceEntry.ParseSnapshotUpdateState(output));
    }

    [Fact]
    public void ParseSnapshotUpdateState_recognised_status_is_never_completed()
    {
        Assert.NotEqual(OtaUpdateState.Completed, MaintenanceEntry.ParseSnapshotUpdateState("snapshot-update-status: pending"));
    }
}
