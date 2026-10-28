using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Transport contract tests. The real <see cref="DeviceTransport"/> and <see cref="ProcessRunner"/> are
/// exercised through the <see cref="ICommandRunner"/> boundary: the fake validates the exact argv and
/// returns a complete <see cref="ProcessResult"/>, so no test ever starts a real adb, fastboot or device.
/// <para>
/// Every device-query test here is red on purpose: the transport bodies currently throw
/// <see cref="NotImplementedException"/>, and these tests must not be weakened to make them pass.
/// </para>
/// </summary>
public sealed class TransportTests
{
    private const string AdbPath = "/evidence/platform-tools/adb";
    private const string FastbootPath = "/evidence/platform-tools/fastboot";
    private const string Serial = "R58M12345ABC";
    private const string Model = "TB322FC";

    // ---------------------------------------------------------------- adb devices

    [Fact]
    public async Task ListDevices_UsesExactAdbDevicesLArgv_AndReportsEveryDeviceState()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "devices", "-l" },
            new ProcessResult(
                0,
                "List of devices attached\n" +
                "R58M12345ABC\tdevice product:TB322FC model:Lenovo_TB322FC device:TB322FC transport_id:1\n" +
                "R58M99999XYZ\tunauthorized usb:1-1 transport_id:2\n" +
                "emulator-5554\toffline\n" +
                "\n",
                string.Empty));

        var devices = await TransportFor(runner).ListDevicesAsync();

        Assert.Equal(3, devices.Count);
        Assert.Equal("R58M12345ABC", devices[0].Serial);
        Assert.Equal(ConnectionState.Authorized, devices[0].ConnectionState);
        Assert.Equal("R58M99999XYZ", devices[1].Serial);
        Assert.Equal(ConnectionState.Unauthorized, devices[1].ConnectionState);
        Assert.Equal("emulator-5554", devices[2].Serial);
        Assert.Equal(ConnectionState.Offline, devices[2].ConnectionState);

        // One plain listing: no retry, no extra probe.
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task ListDevices_NonZeroExit_ThrowsInvalidOperationExceptionWithAdbDiagnostic()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "devices", "-l" },
            new ProcessResult(1, string.Empty, "error: no devices/emulators found\n"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => TransportFor(runner).ListDevicesAsync());

        // A failed listing must never look like "zero devices attached": the adb error text is the
        // diagnostic the user needs, together with a non-empty message.
        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.Contains("no devices", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ListDevices_ForwardsCancellationToken()
    {
        var runner = new FakeCommandRunner();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // The fake cancels through the token it received, so this only throws when the transport really
        // forwards the caller's token instead of dropping it.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => TransportFor(runner).ListDevicesAsync(cancellation.Token));
    }

    // -------------------------------------------------------------- adb identity

    [Fact]
    public async Task ReadAdbIdentity_UsesExactGetpropArgv_AndLeavesBootloaderUnknown()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(
                0,
                "[ro.product.model]: [TB322FC]\n" +
                "[ro.product.vendor.model]: [TB322FC]\n" +
                "[ro.product.name]: [TB322FC_PRC]\n" +
                "[ro.boot.verifiedbootstate]: [orange]\n",
                string.Empty));

        var identity = await TransportFor(runner).ReadAdbIdentityAsync(Serial);

        Assert.Equal(Serial, identity.Serial);
        Assert.Equal(Model, identity.Model);

        // Android properties are not the final fastboot verification, so adb can never report unlocked.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAdbIdentity_UnlockPropsInsideGetprop_StayUnknown()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(
                0,
                "[ro.product.model]: [TB322FC]\n" +
                "[ro.boot.flash.locked]: [0]\n" +
                "Device unlocked: true\n",
                string.Empty));

        var identity = await TransportFor(runner).ReadAdbIdentityAsync(Serial);

        // Only CheckFastbootAsync may open the gate; an adb property claiming an unlock is still no evidence.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
        Assert.Equal(Model, identity.Model);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public async Task ReadAdbIdentity_RejectsBlankSerial_WithoutStartingAdb(string serial)
    {
        var runner = new FakeCommandRunner();

        await Assert.ThrowsAsync<ArgumentException>(
            () => TransportFor(runner).ReadAdbIdentityAsync(serial));

        // An empty -s argument would target whichever device adb picks, so nothing may be launched.
        Assert.Equal(0, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAdbIdentity_UnsupportedModel_Throws()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(0, "[ro.product.model]: [TB324ZC]\n", string.Empty));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => TransportFor(runner).ReadAdbIdentityAsync(Serial));

        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
    }

    [Fact]
    public async Task ReadAdbIdentity_ContradictoryModelFields_Throws()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(
                0,
                "[ro.product.model]: [TB322FC]\n" +
                "[ro.product.vendor.model]: [TB323FU]\n",
                string.Empty));

        // Two supported models in one dump is a contradiction, not a choice.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => TransportFor(runner).ReadAdbIdentityAsync(Serial));
    }

    [Fact]
    public async Task ReadAdbIdentity_NonZeroExit_ThrowsInvalidOperationException()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(1, string.Empty, "error: device offline\n"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => TransportFor(runner).ReadAdbIdentityAsync(Serial));

        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
    }

    [Fact]
    public async Task ReadAdbIdentity_ForwardsCancellationToken()
    {
        var runner = new FakeCommandRunner();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => TransportFor(runner).ReadAdbIdentityAsync(Serial, cancellation.Token));
    }

    // ------------------------------------------------------------ fastboot state

    [Fact]
    public async Task CheckFastboot_UsesExactGetvarArgv_AndReadsUnlockedReportFromStandardError()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(0, string.Empty, "(bootloader) unlocked: yes\nfinished. total time: 0.003s\n"));

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        Assert.Equal(Serial, identity.Serial);
        Assert.Equal(Model, identity.Model);
        Assert.Equal(BootloaderState.Unlocked, identity.BootloaderState);
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task CheckFastboot_LockedReportOnStandardError_IsLocked()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(0, "OKAY", "Device unlocked: false\nfinished. total time: 0.002s\n"));

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        // Locked is reported by the second stream here, so both streams must be read.
        Assert.Equal(BootloaderState.Locked, identity.BootloaderState);
        Assert.Equal(Serial, identity.Serial);
    }

    [Fact]
    public async Task CheckFastboot_ConflictingStreamReports_IsUnknown()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(0, "(bootloader) unlocked: yes\n", "Device unlocked: false\n"));

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        // "unlocked: yes" and "Device unlocked: false" contradict each other, so neither may win.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
    }

    [Fact]
    public async Task CheckFastboot_UnparsableZeroExitOutput_IsUnknown()
    {
        var runner = new FakeCommandRunner();
        var garbage = new ProcessResult(0, "OKAY\n", "finished. total time: 0.001s\n");
        runner.Expect(FastbootPath, new[] { "-s", Serial, "getvar", "unlocked" }, garbage);
        runner.Expect(FastbootPath, new[] { "-s", Serial, "oem", "device-info" }, garbage);

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        // No parseable exit-0 report: Unknown and no exception thrown.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);

        // At most the documented single fallback; a third query would be an unrelated command.
        Assert.InRange(runner.CommandCount, 1, 2);
    }

    [Fact]
    public async Task CheckFastboot_NonZeroExitPrintingUnlocked_IsNotTrusted_AndFallsBackToOemDeviceInfo()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(
                1,
                "(bootloader) unlocked: yes\n",
                "FAILED (remote: 'GetVar Variable Not found')\n"));

        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "oem", "device-info" },
            new ProcessResult(0, "Device unlocked: false\n", string.Empty));

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        // The misleading "unlocked: yes" came from a query that exited non-zero, so only the exit-0
        // fallback counts and the gate stays closed.
        Assert.Equal(BootloaderState.Locked, identity.BootloaderState);
        Assert.Equal(2, runner.CommandCount);
    }

    [Fact]
    public async Task CheckFastboot_BothQueriesFail_IsUnknownWithoutThrowing()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(1, string.Empty, "FAILED (remote: 'unknown command')\n"));
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "oem", "device-info" },
            new ProcessResult(1, string.Empty, "FAILED (remote: 'unknown command')\n"));

        var identity = await TransportFor(runner).CheckFastbootAsync(UnknownIdentity());

        // An unsupported query pair is an expected bootloader property, not an error to throw about.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
        Assert.Equal(2, runner.CommandCount);
    }

    [Fact]
    public async Task CheckFastboot_KeepsConfirmedIdentity_AndNeverAdoptsFastbootProduct()
    {
        var runner = new FakeCommandRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(
                0,
                "(bootloader) unlocked: yes\n(bootloader) product: TB323FU\n(bootloader) serialno: R58M99999XYZ\n",
                string.Empty));

        var confirmed = new DeviceIdentity(Serial, Model, BootloaderState.Unknown);
        var identity = await TransportFor(runner).CheckFastbootAsync(confirmed);

        // Only the lock state may change. The caller-confirmed serial and a mismatching product from
        // fastboot chatter are never adopted, so the identity cannot drift to another device or model.
        Assert.Equal(Serial, identity.Serial);
        Assert.Equal(Model, identity.Model);
        Assert.Equal(BootloaderState.Unlocked, identity.BootloaderState);
    }

    [Fact]
    public async Task CheckFastboot_ForwardsCancellationToken()
    {
        var runner = new FakeCommandRunner();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => TransportFor(runner).CheckFastbootAsync(UnknownIdentity(), cancellation.Token));
    }

    // -------------------------------------------------------- real process runner
    // This suite runs on Linux (remote Docker), so the POSIX shell is the only branch that is covered.

    [Fact]
    public async Task ProcessRunner_CapturesExitCodeAndBothStreams()
    {
        var result = await new ProcessRunner().RunAsync(
            new ProcessCommand(
                "/bin/sh",
                new[] { "-c", "printf stdout; printf stderr >&2; exit 7" },
                TimeSpan.FromSeconds(30)));

        Assert.Equal(7, result.ExitCode);
        Assert.Equal("stdout", result.StandardOutput);
        Assert.Equal("stderr", result.StandardError);
    }

    [Fact]
    public async Task ProcessRunner_TimesOutOnSlowCommand()
    {
        await Assert.ThrowsAsync<TimeoutException>(() => new ProcessRunner().RunAsync(
            new ProcessCommand("/bin/sh", new[] { "-c", "sleep 5" }, TimeSpan.FromMilliseconds(100))));
    }

    [Fact]
    public async Task ProcessRunner_InvalidExecutable_ReportsClearFailure()
    {
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => new ProcessRunner().RunAsync(
            new ProcessCommand(
                "/nonexistent/armada-test-missing-adb",
                new[] { "devices" },
                TimeSpan.FromSeconds(5))));

        // A missing binary must surface as a readable IO/state failure, never as a hang or a fake exit code.
        Assert.True(
            exception is IOException or InvalidOperationException,
            $"expected IOException or InvalidOperationException, got {exception.GetType().FullName}: {exception.Message}");
    }

    [Fact]
    public async Task ProcessRunner_PreCancelledToken_IsOperationCanceled()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ProcessRunner().RunAsync(
            new ProcessCommand("/bin/sh", new[] { "-c", "printf never" }, TimeSpan.FromSeconds(5)),
            cancellation.Token));
    }

    // ------------------------------------------------------------------------ helpers

    private static DeviceTransport TransportFor(FakeCommandRunner runner) => new(AdbPath, FastbootPath, runner);

    private static DeviceIdentity UnknownIdentity() => new(Serial, Model, BootloaderState.Unknown);

    /// <summary>
    /// Fake <see cref="ICommandRunner"/> for the transport boundary. Each expected call pins the executable,
    /// the full argument vector in order, a finite positive timeout and returns a complete
    /// <see cref="ProcessResult"/>. It also throws when a cancelled token reaches it, which is how the
    /// cancellation tests prove the token was forwarded.
    /// </summary>
    private sealed class FakeCommandRunner : ICommandRunner
    {
        private readonly List<Step> _steps = new();
        private readonly List<ProcessCommand> _commands = new();

        internal int CommandCount => _commands.Count;

        internal void Expect(string executable, string[] arguments, ProcessResult result) =>
            _steps.Add(new Step(executable, arguments, result));

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            _commands.Add(command);

            cancellationToken.ThrowIfCancellationRequested();

            var index = _commands.Count - 1;
            Assert.True(
                index < _steps.Count,
                $"unexpected extra command #{index + 1}: {command.Executable} {string.Join(' ', command.Arguments)}");

            var step = _steps[index];

            Assert.Equal(step.Executable, command.Executable);
            Assert.Equal(step.Arguments, command.Arguments.ToArray());
            Assert.True(command.Timeout > TimeSpan.Zero, "a device query must carry a finite positive timeout");
            Assert.NotEqual(Timeout.InfiniteTimeSpan, command.Timeout);

            return Task.FromResult(step.Result);
        }

        private sealed record Step(string Executable, string[] Arguments, ProcessResult Result);
    }
}
