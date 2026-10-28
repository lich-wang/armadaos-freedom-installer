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
/// BCL-only clock for the future poll loops: time advances only when a test says so, and every timer
/// keeps a real due date on that manual clock instead of firing as soon as it is created.
/// </summary>
internal sealed class DeviceCheckClock : TimeProvider
{
    private static readonly TimeSpan AutoAdvanceLimit = TimeSpan.FromMilliseconds(500);

    private readonly object _gate = new();
    private readonly List<ClockTimer> _timers = new();
    private long _milliseconds;

    public override long TimestampFrequency => 1000;

    public override long GetTimestamp() => Interlocked.Read(ref _milliseconds);

    public void Advance(TimeSpan delta) => _ = AdvanceAndDrainCallbacksAsync(delta);

    /// <summary>
    /// Advances the manual clock and waits until every timer that became due has actually run, so a test
    /// can rely on a due timer's effect (for example an expired budget) without guessing at threadpool
    /// ordering.
    /// </summary>
    public async Task AdvanceAndDrainCallbacksAsync(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero) return;

        var due = new List<ClockTimer>();
        lock (_gate)
        {
            var now = Interlocked.Add(ref _milliseconds, (long)delta.TotalMilliseconds);
            foreach (var timer in _timers)
            {
                if (timer.TryTakeDue(now)) due.Add(timer);
            }
        }

        var completions = new List<Task>(due.Count);
        foreach (var timer in due) completions.Add(timer.Invoke()); // queued asynchronously, outside the lock
        foreach (var completion in completions) await completion.ConfigureAwait(false);
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);

        var timer = new ClockTimer(this, callback, state);
        lock (_gate)
        {
            _timers.Add(timer);
            timer.Schedule(dueTime, period);
        }

        // Step over short poll delays only; long deadlines stay pending until Advance crosses them.
        if (dueTime >= TimeSpan.Zero && dueTime <= AutoAdvanceLimit) Advance(dueTime);

        return timer;
    }

    private sealed class ClockTimer : ITimer
    {
        private readonly DeviceCheckClock _clock;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private long? _dueAt;
        private TimeSpan _period;
        private volatile bool _disposed;

        public ClockTimer(DeviceCheckClock clock, TimerCallback callback, object? state)
        {
            _clock = clock;
            _callback = callback;
            _state = state;
        }

        // Caller holds _clock._gate.
        public void Schedule(TimeSpan dueTime, TimeSpan period)
        {
            _period = period == Timeout.InfiniteTimeSpan ? TimeSpan.Zero : period;
            _dueAt = dueTime == Timeout.InfiniteTimeSpan ? null : _clock.GetTimestamp() + (long)dueTime.TotalMilliseconds;
        }

        // Caller holds _clock._gate.
        public bool TryTakeDue(long now)
        {
            if (_disposed || _dueAt is not { } dueAt || dueAt > now) return false;

            _dueAt = _period > TimeSpan.Zero ? dueAt + (long)_period.TotalMilliseconds : null;
            return true;
        }

        public Task Invoke()
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    if (!_disposed) _callback(_state);
                }
                finally
                {
                    completion.TrySetResult();
                }
            });

            return completion.Task;
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (_clock._gate)
            {
                if (_disposed) return false;

                Schedule(dueTime, period);
                return true;
            }
        }

        public void Dispose()
        {
            lock (_clock._gate)
            {
                _disposed = true;
                _dueAt = null;
                _clock._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal enum DeviceCheckPhase
{
    AndroidBefore,
    Fastboot,
    AndroidAfter,
}

/// <summary>
/// One small stateful fake for the whole check: it answers the exact argv vectors the contract names,
/// switches from Android to fastboot and back, and throws clearly on any command it was not taught.
/// Tests customise outliers through <see cref="Intercept"/> instead of mirroring the flow here.
/// </summary>
internal sealed class DeviceCheckRunner : ICommandRunner
{
    private const string SocPath = "/sys/devices/soc0/serial_number";

    private static readonly string[] ForbiddenVerbs =
    {
        "flash", "boot", "unlock", "erase", "format", "set_active", "edl", "loader",
    };

    private readonly string _serial;
    private readonly string _model;
    private readonly string _displayId;
    private readonly string _soc;
    private int _bootPolls;

    public DeviceCheckRunner(
        string serial,
        DeviceCheckClock clock,
        string model = "TB322FC",
        string displayId = "TB322FC.2026.06.01",
        string soc = "3251823604")
    {
        _serial = serial;
        _model = model;
        _displayId = displayId;
        _soc = soc;
        Clock = clock;
        ActualSerial = serial;
        ReturnSerial = serial;
        ReturnModel = model;
        ReturnDisplayId = displayId;
        ReturnSoc = soc;
    }

    public DeviceCheckClock Clock { get; }

    public DeviceCheckPhase Phase { get; private set; } = DeviceCheckPhase.AndroidBefore;

    public List<ProcessCommand> Commands { get; } = new();

    public List<CancellationToken> Tokens { get; } = new();

    public Func<ProcessCommand, DeviceCheckRunner, Task<ProcessResult>?>? Intercept { get; set; }

    public string ActualSerial { get; set; }

    public string FastbootSerialValue { get; set; } = string.Empty;

    public string FastbootProductValue { get; set; } = "elden_prc_wifi";

    public string UnlockedReportValue { get; set; } = "no";

    public string SnapshotStatus { get; set; } = "none";

    public string FastbootCurrentSlot { get; set; } = "a";

    public string ReturnSlotSuffix { get; set; } = "_a";

    public string ReturnSerial { get; set; }

    public string ReturnModel { get; set; }

    public string ReturnDisplayId { get; set; }

    public string ReturnSoc { get; set; }

    public bool BootImmediatelyCompleteOnReturn { get; set; }

    public int UnauthorizedPollsBeforeAuthorized { get; set; }

    public TimeSpan? AdvanceOnUnauthorizedPoll { get; set; }

    public int AdbBootloaderReboots { get; private set; }

    public int FastbootReboots { get; private set; }

    public int FastbootSerialQueries { get; private set; }

    public int FastbootProductQueries { get; private set; }

    public int FastbootCurrentSlotQueries { get; private set; }

    public int UnauthorizedPollsServed { get; private set; }

    public int FastbootCommandCount => Commands.Count(c => c.Executable == AdbOrFastboot.FastbootPath);

    public int ForbiddenModeCommands => Commands.Count(
        c => c.Arguments.Any(a => ForbiddenVerbs.Contains(a, StringComparer.OrdinalIgnoreCase)));

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        Commands.Add(command);
        Tokens.Add(cancellationToken);
        Count(command);

        var intercepted = Intercept?.Invoke(command, this);
        if (intercepted is not null)
        {
            return intercepted;
        }

        return Task.FromResult(Handle(command));
    }

    public void MarkReturnedToAndroid()
    {
        Phase = DeviceCheckPhase.AndroidAfter;
        _bootPolls = 0;
    }

    public CancellationToken LastTokenFor(Func<ProcessCommand, bool> predicate)
    {
        for (var index = Commands.Count - 1; index >= 0; index--)
        {
            if (predicate(Commands[index]))
            {
                return Tokens[index];
            }
        }

        throw new InvalidOperationException("The expected command was never recorded.");
    }

    private void Count(ProcessCommand command)
    {
        var args = command.Arguments;

        if (command.Executable == AdbOrFastboot.AdbPath
            && args.Count == 4
            && args[0] == "-s"
            && args[2] == "reboot"
            && args[3] == "bootloader")
        {
            AdbBootloaderReboots++;
        }
        else if (command.Executable == AdbOrFastboot.FastbootPath && args.Count == 3 && args[2] == "reboot")
        {
            FastbootReboots++;
        }
        else if (command.Executable == AdbOrFastboot.FastbootPath
                 && args.Count == 4
                 && args[2] == "getvar"
                 && args[3] == "serialno")
        {
            FastbootSerialQueries++;
        }
        else if (command.Executable == AdbOrFastboot.FastbootPath
                 && args.Count == 4
                 && args[2] == "getvar"
                 && args[3] == "product")
        {
            FastbootProductQueries++;
        }
        else if (command.Executable == AdbOrFastboot.FastbootPath
                 && args.Count == 4
                 && args[2] == "getvar"
                 && args[3] == "current-slot")
        {
            FastbootCurrentSlotQueries++;
        }
    }

    private ProcessResult Handle(ProcessCommand command)
    {
        var args = command.Arguments;

        if (command.Executable == AdbOrFastboot.AdbPath)
        {
            if (args.Count == 2 && args[0] == "devices" && args[1] == "-l")
            {
                return Ok(ListDevices());
            }

            if (args.Count == 4
                && args[0] == "-s"
                && args[1] == _serial
                && args[2] == "reboot"
                && args[3] == "bootloader")
            {
                Phase = DeviceCheckPhase.Fastboot;
                return Ok(string.Empty);
            }

            if (args.Count >= 4
                && args[0] == "-s"
                && args[1] == _serial
                && args[2] == "shell")
            {
                if (args.Count == 4 && args[3] == "getprop")
                {
                    return Ok(Dump());
                }

                if (args.Count == 5 && args[3] == "getprop")
                {
                    switch (args[4])
                    {
                        case "ro.serialno":
                        case "ro.boot.serialno":
                            return Ok(Phase == DeviceCheckPhase.AndroidAfter ? ReturnSerial : ActualSerial);
                        case "sys.boot_completed":
                            return Ok(BootCompleted());
                        case "ro.boot.slot_suffix":
                            return Ok(ReturnSlotSuffix);
                    }
                }

                if (args.Count == 5 && args[3] == "cat" && args[4] == SocPath)
                {
                    return Ok(Phase == DeviceCheckPhase.AndroidAfter ? ReturnSoc : _soc);
                }
            }

            throw Unexpected(command);
        }

        if (command.Executable == AdbOrFastboot.FastbootPath)
        {
            if (args.Count == 4 && args[0] == "-s" && args[1] == _serial && args[2] == "getvar")
            {
                switch (args[3])
                {
                    case "serialno":
                        return Ok($"(bootloader) serialno: {FastbootSerial()}\nOKAY");
                    case "product":
                        return Ok($"(bootloader) product: {FastbootProductValue}\nOKAY");
                    case "current-slot":
                        return Ok($"(bootloader) current-slot: {FastbootCurrentSlot}\nOKAY");
                    case "unlocked":
                        return Ok($"(bootloader) unlocked: {UnlockedReportValue}\nOKAY");
                    case "snapshot-update-status":
                        return Ok($"(bootloader) snapshot-update-status: {SnapshotStatus}\nOKAY");
                }
            }

            if (args.Count == 3 && args[0] == "-s" && args[1] == _serial && args[2] == "reboot")
            {
                MarkReturnedToAndroid();
                return Ok("OKAY");
            }

            throw Unexpected(command);
        }

        throw Unexpected(command);
    }

    private string FastbootSerial() =>
        string.IsNullOrEmpty(FastbootSerialValue) ? _serial : FastbootSerialValue;

    private string ListDevices()
    {
        if (Phase == DeviceCheckPhase.AndroidAfter && UnauthorizedPollsBeforeAuthorized > 0)
        {
            UnauthorizedPollsBeforeAuthorized--;
            UnauthorizedPollsServed++;

            if (AdvanceOnUnauthorizedPoll is { } delta)
            {
                Clock.Advance(delta);
            }

            return $"List of devices attached\r\n{_serial}\tunauthorized\r\n";
        }

        if (Phase == DeviceCheckPhase.Fastboot)
        {
            // The device is in fastboot, so adb must not claim it is usable.
            return "List of devices attached\r\n";
        }

        return $"List of devices attached\r\n{_serial}\tdevice product:{_model} model:{_model} device:{_model}\r\n";
    }

    private string Dump()
    {
        var after = Phase == DeviceCheckPhase.AndroidAfter;
        var model = after ? ReturnModel : _model;
        var display = after ? ReturnDisplayId : _displayId;
        var serial = after ? ReturnSerial : ActualSerial;

        return string.Join(
            '\n',
            new[]
            {
                $"[ro.product.model]: [{model}]",
                $"[ro.product.name]: [{model}]",
                $"[ro.product.vendor.model]: [{model}]",
                $"[ro.build.display.id]: [{display}]",
                $"[ro.build.fingerprint]: [Lenovo/{model}/{model}:16/BQ2A.260601.001/20260601:user/release-keys]",
                "[ro.build.version.release]: [16]",
                "[ro.build.version.security_patch]: [2026-06-01]",
                $"[ro.serialno]: [{serial}]",
                "[sys.boot_completed]: [1]",
                "[ro.boot.flash.locked]: [1]",
                "[ro.boot.vbmeta.device_state]: [locked]",
            });
    }

    private string BootCompleted()
    {
        if (Phase != DeviceCheckPhase.AndroidAfter)
        {
            return "1";
        }

        var zeroAnswers = BootImmediatelyCompleteOnReturn ? 0 : 1;
        return _bootPolls++ < zeroAnswers ? "0" : "1";
    }

    private static ProcessResult Ok(string standardOutput) => new(0, standardOutput, string.Empty);

    private static InvalidOperationException Unexpected(ProcessCommand command) =>
        new($"Unexpected command: {command.Executable} {string.Join(' ', command.Arguments)}");
}

internal static class AdbOrFastboot
{
    public const string AdbPath = "/opt/platform-tools/adb";
    public const string FastbootPath = "/opt/platform-tools/fastboot";
}

internal sealed class DeviceCheckProgressRecorder : IProgress<InternalDeviceCheckProgress>
{
    public List<InternalDeviceCheckStage> Stages { get; } = new();

    public void Report(InternalDeviceCheckProgress value) => Stages.Add(value.Stage);
}

/// <summary>
/// Future-behavior tests for <see cref="InternalInstallDeviceCheck"/>: each one arranges the real desired
/// fixture and drives the production entry point end to end.
/// </summary>
public sealed class InternalInstallDeviceCheckTests
{
    private const string AdbPath = AdbOrFastboot.AdbPath;
    private const string FastbootPath = AdbOrFastboot.FastbootPath;
    private const string Serial = "HA1B2C3D4";
    private const string ForeignSerial = "FOREIGN0001";
    private const string Soc = "3251823604";
    private const string DisplayId = "TB322FC.2026.06.01";
    private const string G4Product = "elden_prc_wifi";

    [Theory]
    [InlineData(BootloaderState.Locked, "no")]
    [InlineData(BootloaderState.Unlocked, "yes")]
    public async Task Check_CompletesBothLockedStates(BootloaderState expectedLock, string unlockedReport)
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            UnlockedReportValue = unlockedReport,
            SnapshotStatus = "none",
        };
        var check = CreateCheck(runner);
        var progress = new DeviceCheckProgressRecorder();

        var result = await check.CheckAsync(Serial, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(expectedLock, result.FastbootLockState);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(OtaUpdateState.Completed, result.OtaState);
        Assert.Equal(G4Product, result.FastbootProduct);
        Assert.NotNull(result.Android);
        Assert.Equal(expectedLock, result.Android!.Identity.BootloaderState);
        Assert.Equal(Soc, result.Android.SocSerial);
        Assert.Equal("a", result.CurrentSlot);
        Assert.Equal(1, runner.FastbootCurrentSlotQueries);

        // Exactly one entry and one return, with the argv pinned by the contract.
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(
            "-s " + Serial + " reboot bootloader",
            Describe(runner.Commands.Single(c => c.Executable == AdbPath && c.Arguments.Contains("bootloader"))));
        Assert.Equal(
            "-s " + Serial + " reboot",
            Describe(runner.Commands.Single(c => c.Executable == FastbootPath && c.Arguments.Count == 3)));

        // The return is only trusted after boot_completed=1, and no forbidden verb was used.
        Assert.Contains(progress.Stages, stage => stage == InternalDeviceCheckStage.Completed);
        Assert.Equal(0, runner.ForbiddenModeCommands);

        // One initial boot poll plus at least two after the return, with the exact argv each time.
        Assert.True(
            runner.Commands.Count(IsBootCompletedQuery) >= 3,
            "Expected an initial and two returned sys.boot_completed queries.");
        Assert.Contains(progress.Stages, stage => stage == InternalDeviceCheckStage.VerifyingAndroid);
    }

    [Fact]
    public async Task Check_G5UnknownProductStillRequiresSameIdentity()
    {
        // "fixture-unmapped-board" is a synthetic board name, not a real G5 fastboot ID.
        var runner = new DeviceCheckRunner(
            Serial,
            new DeviceCheckClock(),
            model: "TB323FU",
            displayId: "TB323FU.synthetic.g5.firmware")
        {
            FastbootProductValue = "fixture-unmapped-board",
            SnapshotStatus = "none",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // Step 1 only: an unmapped product must not be presented as an install or write capability.
        Assert.True(result.Succeeded);
        Assert.Equal("fixture-unmapped-board", result.FastbootProduct);
        Assert.NotNull(result.Android);
        Assert.Equal("TB323FU", result.Android!.Identity.Model);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    [Fact]
    public async Task Check_InitialActualSerialMismatchStopsBeforeModeSwitch()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            ActualSerial = ForeignSerial,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(AndroidReturnState.NotRequired, result.AndroidReturn);
        Assert.Equal(0, runner.AdbBootloaderReboots);
        Assert.Equal(0, runner.FastbootCommandCount);
    }

    [Fact]
    public async Task Check_FastbootSerialMismatchDoesNotRebootForeignDevice()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootSerialValue = ForeignSerial,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(0, runner.FastbootReboots);
        Assert.Equal(0, runner.FastbootProductQueries);
    }

    [Fact]
    public async Task Check_KnownWrongModelProductStillReturnsOriginalDevice()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootProductValue = "TB323FU",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    [Fact]
    public async Task Check_UnparseableBootloaderStateReturnsButCannotComplete()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            UnlockedReportValue = "maybe",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(BootloaderState.Unknown, result.FastbootLockState);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_MergingOtaCannotCompleteButReturns()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            SnapshotStatus = "merging",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(OtaUpdateState.Merging, result.OtaState);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_QueryExceptionAfterFastbootProofReturnsOnce()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, _) =>
            IsFastbootVariable(command, "product")
                ? Task.FromException<ProcessResult>(new IOException("simulated product query failure"))
                : null;
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_CleanupReturnTimeoutDoesNotReportUserCancellation()
    {
        using var caller = new CancellationTokenSource();
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, state) =>
        {
            if (IsFastbootVariable(command, "product"))
            {
                // The serial is already proven, so this enters the bounded cleanup path while the
                // explicit caller token stays untouched for the whole check.
                return Task.FromException<ProcessResult>(
                    new IOException("simulated cleanup product query failure"));
            }

            if (!IsFastbootReboot(command))
            {
                return null;
            }

            return ReturnAfterCleanupTimeoutAsync();

            async Task<ProcessResult> ReturnAfterCleanupTimeoutAsync()
            {
                var returnToken = state.LastTokenFor(IsFastbootReboot);
                await state.Clock.AdvanceAndDrainCallbacksAsync(
                    InternalInstallDeviceCheck.CleanupTimeout + TimeSpan.FromSeconds(1)).ConfigureAwait(false);

                Assert.True(returnToken.IsCancellationRequested, "the cleanup budget must actually expire");
                Assert.False(caller.Token.IsCancellationRequested, "the caller token must stay untouched");
                throw new OperationCanceledException(returnToken);
            }
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial, null, caller.Token);

        // An expired cleanup budget is a return timeout, never a user cancellation.
        Assert.False(result.Succeeded);
        Assert.False(result.Cancelled);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.NotNull(result.FailedStage);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
        Assert.False(caller.Token.IsCancellationRequested);
    }

    [Fact]
    public async Task Check_ReturnAckLostOnlyPollsAndroid()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            BootImmediatelyCompleteOnReturn = true,
        };
        runner.Intercept = (command, state) =>
        {
            if (!IsFastbootReboot(command))
            {
                return null;
            }

            // The device did reboot, but the ACK was lost: the caller must not resend it.
            state.MarkReturnedToAndroid();
            return Task.FromException<ProcessResult>(new TimeoutException("reboot ACK lost"));
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootSerialQueries);
    }

    [Fact]
    public async Task Check_ReauthorizationWaitsWithoutResendingReboot()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            UnauthorizedPollsBeforeAuthorized = 2,
            AdvanceOnUnauthorizedPoll = TimeSpan.FromSeconds(120),
            BootImmediatelyCompleteOnReturn = true,
        };
        var check = CreateCheck(runner);
        var progress = new DeviceCheckProgressRecorder();

        var result = await check.CheckAsync(Serial, progress);

        // 240 s pass while explicitly unauthorized; that must not expire the user wait.
        Assert.True(runner.Clock.GetTimestamp() >= 240_000);
        Assert.Equal(2, runner.UnauthorizedPollsServed);
        Assert.Contains(progress.Stages, stage => stage == InternalDeviceCheckStage.WaitingUsbAuthorization);
        Assert.True(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_ReturnedSocDriftCannotComplete()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            ReturnSoc = "3823654013",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(1, runner.AdbBootloaderReboots);

        // No operation retry was attempted after the drifted device came back.
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    [Fact]
    public async Task Check_ReturnedFullBuildDriftCannotComplete()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            ReturnDisplayId = DisplayId + ".drift",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // Same model, serial and SoC, but the full display id differs: the short suffix is not accepted.
        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_CancelAfterFastbootProofStillReturnsUsingCleanupToken()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, _) =>
        {
            if (!IsFastbootVariable(command, "serialno"))
            {
                return null;
            }

            // The serial is already proven; cancelling now must still trigger the single cleanup return.
            cancellation.Cancel();
            return Task.FromResult(new ProcessResult(0, $"(bootloader) serialno: {Serial}\nOKAY", string.Empty));
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial, null, cancellation.Token);

        Assert.True(result.Cancelled);
        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);

        var cleanupToken = runner.LastTokenFor(IsFastbootReboot);
        Assert.False(cleanupToken.IsCancellationRequested);
        Assert.NotEqual(cancellation.Token, cleanupToken);
    }

    [Fact]
    public async Task Check_AbsentFastbootTimesOutWithoutUnprovenReboot()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, state) =>
        {
            if (!IsFastbootVariable(command, "serialno"))
            {
                return null;
            }

            // The deadline is crossed before any further delay, so this fails without a 90 s wall wait.
            state.Clock.Advance(InternalInstallDeviceCheck.FastbootTimeout + TimeSpan.FromSeconds(1));
            return Task.FromException<ProcessResult>(new TimeoutException("fastboot serialno timed out"));
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(0, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_LongAuthorizationWaitDoesNotConsumeAndroidBudget()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            UnauthorizedPollsBeforeAuthorized = 400,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // 400 polls at the 500 ms poll interval is 200 s of explicit user time, more than the whole
        // Android budget; only the waits that are not authorization prompts may consume it.
        Assert.True(runner.Clock.GetTimestamp() >= 200_000);
        Assert.Equal(400, runner.UnauthorizedPollsServed);
        Assert.True(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    [Fact]
    public async Task Check_CancelAfterLastFastbootQueryStillReturnsOnce()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, _) =>
        {
            if (!IsFastbootVariable(command, "snapshot-update-status"))
            {
                return null;
            }

            // The last query succeeded and the serial is proven; cancelling now must still leave exactly
            // one return, and it must not be handed the already-cancelled caller token.
            cancellation.Cancel();
            return Task.FromResult(new ProcessResult(
                0,
                "(bootloader) snapshot-update-status: none\nOKAY",
                string.Empty));
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial, null, cancellation.Token);

        Assert.True(result.Cancelled);
        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);

        var returnToken = runner.LastTokenFor(IsFastbootReboot);
        Assert.NotEqual(cancellation.Token, returnToken);
        Assert.False(returnToken.IsCancellationRequested);
    }

    [Fact]
    public async Task Check_CancelAfterLongAuthorizationStartsFreshCleanupBudget()
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        var interceptedList = false;
        runner.Intercept = (command, state) =>
        {
            if (interceptedList
                || state.Phase != DeviceCheckPhase.AndroidAfter
                || !IsAdbDeviceList(command))
            {
                return null;
            }

            interceptedList = true;
            return CancelAfterLongWaitAsync();

            async Task<ProcessResult> CancelAfterLongWaitAsync()
            {
                // 120 s of user wait outlives any timer an eagerly created cleanup budget would have armed.
                await runner.Clock.AdvanceAndDrainCallbacksAsync(TimeSpan.FromSeconds(120))
                    .ConfigureAwait(false);
                cancellation.Cancel();
                return new ProcessResult(
                    0,
                    $"List of devices attached\r\n{Serial}\tunauthorized\r\n",
                    string.Empty);
            }
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial, null, cancellation.Token);

        Assert.True(result.Cancelled);
        Assert.False(result.Succeeded);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);

        // The single cleanup observation ran on its own fresh budget, not on the caller token.
        var finalBootToken = runner.LastTokenFor(IsBootCompletedQuery);
        Assert.NotEqual(cancellation.Token, finalBootToken);
        Assert.False(finalBootToken.IsCancellationRequested);
    }

    [Theory]
    [InlineData("a", "_a")]
    [InlineData("b", "_b")]
    public async Task Check_RecordsActualCurrentSlotMatchedOnReturn(string slot, string suffix)
    {
        // Slot b is a genuine fastboot fact and is checked like a; the install route for it is decided
        // by the backend, never by this device check.
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = slot,
            ReturnSlotSuffix = suffix,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.True(result.Succeeded);
        Assert.Equal(slot, result.CurrentSlot);
        Assert.Equal(AndroidReturnState.Verified, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootCurrentSlotQueries);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    [Theory]
    [InlineData("")]
    [InlineData("unknown")]
    [InlineData("_a")]
    public async Task Check_UnacceptableFastbootCurrentSlotCannotSucceed(string reportedSlot)
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = reportedSlot,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // A missing, empty or suffixed value is never defaulted to "a": the slot stays unknown.
        Assert.False(result.Succeeded);
        Assert.Null(result.CurrentSlot);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.NotEqual(AndroidReturnState.NotRequired, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_ConflictingFastbootCurrentSlotOutputCannotSucceed()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock());
        runner.Intercept = (command, _) =>
            IsFastbootVariable(command, "current-slot")
                ? Task.FromResult(new ProcessResult(
                    0,
                    "(bootloader) current-slot: a\n(bootloader) current-slot: b\nOKAY",
                    string.Empty))
                : null;
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        Assert.False(result.Succeeded);
        Assert.Null(result.CurrentSlot);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Fact]
    public async Task Check_ReturnedSlotSuffixMismatchCannotSucceed()
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = "a",
            ReturnSlotSuffix = "_b",
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // The fastboot fact stays recorded even though the returned Android disagrees with it.
        Assert.False(result.Succeeded);
        Assert.Equal("a", result.CurrentSlot);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.Equal<InternalDeviceCheckStage?>(
            InternalDeviceCheckStage.VerifyingAndroid,
            result.FailedStage);
        Assert.Equal(1, runner.AdbBootloaderReboots);
        Assert.Equal(1, runner.FastbootReboots);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    public async Task Check_ReturnedSlotSuffixMustBeExact(string returnedSuffix)
    {
        var runner = new DeviceCheckRunner(Serial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = "a",
            ReturnSlotSuffix = returnedSuffix,
        };
        var check = CreateCheck(runner);

        var result = await check.CheckAsync(Serial);

        // A plain "a" or an empty suffix does not match the _a/_b Android reports.
        Assert.False(result.Succeeded);
        Assert.Equal("a", result.CurrentSlot);
        Assert.Equal(AndroidReturnState.Unconfirmed, result.AndroidReturn);
        Assert.Equal(1, runner.FastbootReboots);
        Assert.Equal(0, runner.ForbiddenModeCommands);
    }

    private static InternalInstallDeviceCheck CreateCheck(DeviceCheckRunner runner) =>
        new(AdbPath, FastbootPath, runner, runner.Clock);

    private static bool IsFastbootVariable(ProcessCommand command, string name) =>
        command.Executable == FastbootPath
        && command.Arguments.Count == 4
        && command.Arguments[0] == "-s"
        && command.Arguments[2] == "getvar"
        && command.Arguments[3] == name;

    private static bool IsBootCompletedQuery(ProcessCommand command) =>
        command.Executable == AdbPath
        && command.Arguments.SequenceEqual(
            new[] { "-s", Serial, "shell", "getprop", "sys.boot_completed" });

    private static bool IsAdbDeviceList(ProcessCommand command) =>
        command.Executable == AdbPath
        && command.Arguments.Count == 2
        && command.Arguments[0] == "devices"
        && command.Arguments[1] == "-l";

    private static bool IsFastbootReboot(ProcessCommand command) =>
        command.Executable == FastbootPath
        && command.Arguments.Count == 3
        && command.Arguments[2] == "reboot";

    private static string Describe(ProcessCommand command) =>
        string.Join(' ', command.Arguments);
}
