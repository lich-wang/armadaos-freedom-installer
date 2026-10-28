using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Stage of the automatic Step 1 device check, as reported through
/// <see cref="IProgress{T}"/> by <see cref="InternalInstallDeviceCheck.CheckAsync"/>.
/// <para>
/// The stage only names how far the check has got. It is not a permission and not a result: the
/// install route is decided from <see cref="InternalDeviceCheckResult"/> facts only.
/// </para>
/// </summary>
public enum InternalDeviceCheckStage
{
    /// <summary>Reading the Android identity, build and SoC serial of the expected device.</summary>
    ReadingAndroid,

    /// <summary>The single <c>adb reboot bootloader</c> has been issued.</summary>
    EnteringFastboot,

    /// <summary>Polling fastboot until the expected serial responds.</summary>
    WaitingFastboot,

    /// <summary>Querying product, bootloader lock state and OTA state in fastboot.</summary>
    CheckingBootloader,

    /// <summary>The single <c>fastboot reboot</c> back to Android has been issued.</summary>
    ReturningAndroid,

    /// <summary>Polling adb until the expected serial is visible again.</summary>
    WaitingAndroid,

    /// <summary>The expected device is visible but unauthorized: the user must accept the USB prompt.</summary>
    WaitingUsbAuthorization,

    /// <summary>Re-reading and comparing the Android identity, build and SoC serial after the return.</summary>
    VerifyingAndroid,

    /// <summary>The check finished; the result states whether it succeeded.</summary>
    Completed,
}

/// <summary>
/// What happened to the return from fastboot to Android. Only <see cref="Verified"/> is a positive
/// fact; <see cref="Unconfirmed"/> means the device was not proven back in a matching Android.
/// </summary>
public enum AndroidReturnState
{
    /// <summary>No mode change was attempted, so no return was required.</summary>
    NotRequired,

    /// <summary>The original device was proven back in Android with the same identity, build and SoC serial.</summary>
    Verified,

    /// <summary>The return was attempted or required but could not be proven.</summary>
    Unconfirmed,
}

/// <summary>
/// One progress report of <see cref="InternalInstallDeviceCheck.CheckAsync"/>. <paramref name="Detail"/>
/// is optional human-readable context; it never carries a positive result by itself.
/// </summary>
public sealed record InternalDeviceCheckProgress(InternalDeviceCheckStage Stage, string? Detail = null);

/// <summary>
/// Immutable outcome of <see cref="InternalInstallDeviceCheck.CheckAsync"/>.
/// <para>
/// Every property is a fact that was actually observed. The constructor is internal so no caller can
/// fabricate a positive outcome, and there are no setters, so <see cref="Succeeded"/> cannot be forced
/// to true from outside.
/// </para>
/// <para>
/// <see cref="Succeeded"/> is derived and deliberately strict: it is true only when there is no error,
/// the check was not cancelled, no stage failed, an Android identity is present, a fastboot serial was
/// proven, the return to Android was verified, the bootloader lock state is a confirmed Locked or
/// Unlocked, the OTA state is Completed, and the fastboot-reported current slot is exactly <c>a</c> or
/// <c>b</c>. In particular a locked bootloader can complete this
/// check without meaning that any install route is allowed, and an unmapped G5 product can pass
/// Step 1 without meaning that writing is supported.
/// </para>
/// </summary>
public sealed class InternalDeviceCheckResult
{
    internal InternalDeviceCheckResult(
        AndroidMaintenanceIdentity? android,
        string? fastbootSerial,
        string? fastbootProduct,
        BootloaderState fastbootLockState,
        OtaUpdateState otaState,
        AndroidReturnState androidReturn,
        bool cancelled,
        InternalDeviceCheckStage? failedStage,
        string? error,
        string? currentSlot = null)
    {
        Android = android;
        FastbootSerial = fastbootSerial;
        FastbootProduct = fastbootProduct;
        FastbootLockState = fastbootLockState;
        OtaState = otaState;
        AndroidReturn = androidReturn;
        Cancelled = cancelled;
        FailedStage = failedStage;
        Error = error;
        CurrentSlot = currentSlot;
    }

    /// <summary>
    /// Android identity and SoC serial observed before the mode change, or the verified identity
    /// observed after the return. Null when Android was never read successfully.
    /// </summary>
    public AndroidMaintenanceIdentity? Android { get; }

    /// <summary>The serial fastboot reported for the expected device, or null when it was not proven.</summary>
    public string? FastbootSerial { get; }

    /// <summary>The fastboot product reported by the expected device, or null when it was not read.</summary>
    public string? FastbootProduct { get; }

    /// <summary>Bootloader lock state confirmed in fastboot; Unknown when it was not confirmed.</summary>
    public BootloaderState FastbootLockState { get; }

    /// <summary>OTA snapshot-update state read in fastboot; Unknown when it was not read.</summary>
    public OtaUpdateState OtaState { get; }

    /// <summary>Whether the return to Android was verified, not required or unconfirmed.</summary>
    public AndroidReturnState AndroidReturn { get; }

    /// <summary>True when the caller cancelled the check after the mode change had started.</summary>
    public bool Cancelled { get; }

    /// <summary>The stage that failed, or null when no stage failed.</summary>
    public InternalDeviceCheckStage? FailedStage { get; }

    /// <summary>The operational error that stopped the check, or null when there was none.</summary>
    public string? Error { get; }

    /// <summary>
    /// The current slot fastboot actually reported for the expected device, exactly <c>a</c> or
    /// <c>b</c>, or null when no acceptable value was read. This is an observed fastboot fact, not a
    /// permission: it never advertises a writing route by itself.
    /// </summary>
    public string? CurrentSlot { get; }

    /// <summary>
    /// True only for a fully positive, actually verified Step 1 result. See the type remarks for the
    /// exact conjunction; no partial outcome can satisfy it.
    /// </summary>
    public bool Succeeded =>
        string.IsNullOrWhiteSpace(Error)
        && !Cancelled
        && FailedStage is null
        && Android is not null
        && !string.IsNullOrWhiteSpace(FastbootSerial)
        && AndroidReturn == AndroidReturnState.Verified
        && (FastbootLockState == BootloaderState.Locked || FastbootLockState == BootloaderState.Unlocked)
        && OtaState == OtaUpdateState.Completed
        && (CurrentSlot is "a" or "b");
}

/// <summary>
/// Step 1 automatic device check: reads the Android identity, enters fastboot exactly once, proves the
/// expected serial, checks product, lock state and OTA state, returns to Android exactly once and
/// verifies that the same device came back.
/// <para>
/// The only device state changes are those two reboots, issued by this class itself. Every other command
/// is a read; the transport stays query-only and no flash, boot, unlock, erase, format, set-active or
/// EDL command is ever built.
/// </para>
/// </summary>
public sealed class InternalInstallDeviceCheck
{
    /// <summary>Total budget for proving the expected serial in fastboot.</summary>
    public static readonly TimeSpan FastbootTimeout = TimeSpan.FromSeconds(90);

    /// <summary>Total budget for waiting for the expected device to come back in Android.</summary>
    public static readonly TimeSpan AndroidTimeout = TimeSpan.FromSeconds(180);

    /// <summary>Independent budget for the bounded cleanup after cancellation or failure.</summary>
    public static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(90);

    /// <summary>Delay between two polls; all waits go through the injected clock.</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private const string G4Model = "TB322FC";
    private const string G5Model = "TB323FU";
    private const string G4Product = "elden_prc_wifi";

    private static readonly Regex SerialPattern = new("^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly TimeSpan RebootTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan PropertyTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan FastbootQueryTimeout = TimeSpan.FromSeconds(3);

    private readonly string _adbPath;
    private readonly string _fastbootPath;
    private readonly ICommandRunner _runner;
    private readonly TimeProvider _clock;

    /// <summary>
    /// Creates the check. The two tool paths must be non-blank and the runner non-null; nothing is
    /// started here, so construction has no device or process side effect. <paramref name="clock"/>
    /// defaults to <see cref="TimeProvider.System"/> and exists so tests can advance time without waits.
    /// </summary>
    public InternalInstallDeviceCheck(
        string adbPath,
        string fastbootPath,
        ICommandRunner runner,
        TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adbPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(fastbootPath);
        ArgumentNullException.ThrowIfNull(runner);

        _adbPath = adbPath;
        _fastbootPath = fastbootPath;
        _runner = runner;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>
    /// Runs the Step 1 device check for <paramref name="expectedSerial"/>.
    /// <para>
    /// Reads Android first, issues exactly one entry reboot, proves the serial in fastboot, reads
    /// product/lock/OTA, issues exactly one return reboot and re-verifies the returned identity. A failure
    /// returns the facts actually observed with the first failed stage and error; only a fully verified
    /// result satisfies <see cref="InternalDeviceCheckResult.Succeeded"/>.
    /// </para>
    /// </summary>
    public async Task<InternalDeviceCheckResult> CheckAsync(
        string expectedSerial,
        IProgress<InternalDeviceCheckProgress>? progress = null,
        CancellationToken token = default)
    {
        if (expectedSerial is null || !SerialPattern.IsMatch(expectedSerial))
        {
            throw new ArgumentException(
                "期望序列号必须是 1..64 个 ASCII 字母、数字或连字符组成的单一 token。",
                nameof(expectedSerial));
        }

        // Pre-entry cancellation may surface; nothing has been started yet.
        token.ThrowIfCancellationRequested();

        var transport = new DeviceTransport(_adbPath, _fastbootPath, _runner);
        var maintenance = new MaintenanceEntry(_adbPath, _fastbootPath, _runner);

        progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.ReadingAndroid));

        AndroidMaintenanceIdentity? android = null;
        try
        {
            var devices = await transport.ListDevicesAsync(token).ConfigureAwait(false);
            var selected = devices
                .Where(device => string.Equals(device.Serial, expectedSerial, StringComparison.Ordinal))
                .ToList();

            if (selected.Count == 0)
            {
                throw new InvalidOperationException(
                    $"adb 设备列表中没有序列号 {expectedSerial} 的设备；不会重启或改写任何其他设备。");
            }

            if (selected.Count > 1)
            {
                throw new InvalidOperationException(
                    $"adb 设备列表把序列号 {expectedSerial} 报告了 {selected.Count} 次，无法唯一定位设备。");
            }

            if (selected[0].ConnectionState != ConnectionState.Authorized)
            {
                throw new InvalidOperationException(
                    $"设备 {expectedSerial} 当前状态为 {selected[0].ConnectionState}，只有已授权的设备才能开始检查。");
            }

            var identity = await transport.ReadAdbIdentityAsync(expectedSerial, token).ConfigureAwait(false);
            var firmware = identity.Firmware;
            if (firmware is null
                || string.IsNullOrWhiteSpace(firmware.DisplayId)
                || string.IsNullOrWhiteSpace(firmware.BuildFingerprint))
            {
                throw new InvalidOperationException(
                    $"设备 {expectedSerial} 的 getprop 未给出完整的 display id 与 fingerprint，无法建立可比较的固件基线。");
            }

            var actualSerial = await ReadActualSerialAsync(expectedSerial, token).ConfigureAwait(false);
            if (!string.Equals(actualSerial, expectedSerial, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"设备 {expectedSerial} 报告的实际序列号为「{actualSerial}」，与期望序列号不一致，拒绝切换模式。");
            }

            var bootCompleted = await ReadShellPropertyAsync(expectedSerial, "sys.boot_completed", token)
                .ConfigureAwait(false);
            if (!string.Equals(bootCompleted, "1", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"设备 {expectedSerial} 尚未完成启动（sys.boot_completed=「{bootCompleted}」），拒绝切换模式。");
            }

            android = await maintenance.ReadAndroidAsync(identity, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.Completed));

            return new InternalDeviceCheckResult(
                android,
                null,
                null,
                BootloaderState.Unknown,
                OtaUpdateState.Unknown,
                AndroidReturnState.NotRequired,
                false,
                InternalDeviceCheckStage.ReadingAndroid,
                exception.Message);
        }

        var cancelled = false;
        var proven = false;
        var proofTerminal = false;
        var proofExhausted = false;
        var returnAttempted = false;
        string? product = null;
        var lockState = BootloaderState.Unknown;
        var otaState = OtaUpdateState.Unknown;
        string? currentSlot = null;
        InternalDeviceCheckStage? failedStage = null;
        string? error = null;

        void RecordFailure(InternalDeviceCheckStage stage, string message)
        {
            failedStage ??= stage;
            error ??= message;
        }

        // The attempt is recorded before the process starts: a lost ACK must never look like no reboot.
        var modeAttempted = true;
        progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.EnteringFastboot));

        try
        {
            var entry = await _runner.RunAsync(
                new ProcessCommand(
                    _adbPath,
                    new[] { "-s", expectedSerial, "reboot", "bootloader" },
                    RebootTimeout),
                token).ConfigureAwait(false);

            if (entry.ExitCode != 0)
            {
                RecordFailure(
                    InternalDeviceCheckStage.EnteringFastboot,
                    $"进入 fastboot 的 adb reboot 返回退出码 {entry.ExitCode}：{Diagnostic(entry)}");
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            cancelled = true;
        }
        catch (Exception exception)
        {
            RecordFailure(
                InternalDeviceCheckStage.EnteringFastboot,
                $"进入 fastboot 的 adb reboot 失败：{exception.Message}");
        }

        if (!cancelled)
        {
            progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.WaitingFastboot));

            var pollStart = _clock.GetTimestamp();
            string? lastPollError = null;

            while (!proven)
            {
                if (_clock.GetElapsedTime(pollStart) >= FastbootTimeout)
                {
                    proofExhausted = true;
                    RecordFailure(
                        InternalDeviceCheckStage.WaitingFastboot,
                        $"在 {FastbootTimeout.TotalSeconds:0} 秒内未在 fastboot 中确认序列号 {expectedSerial}。"
                        + (lastPollError is null ? string.Empty : $" 最近一次错误：{lastPollError}"));
                    break;
                }

                if (token.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }

                ProcessResult? probe = null;
                try
                {
                    probe = await _runner.RunAsync(
                        new ProcessCommand(
                            _fastbootPath,
                            new[] { "-s", expectedSerial, "getvar", "serialno" },
                            FastbootQueryTimeout),
                        token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }
                catch (Exception exception) when (exception is TimeoutException or IOException)
                {
                    // Transient: the bootloader may not be answering yet. Re-poll until the deadline.
                    lastPollError = exception.Message;
                }
                catch (Exception exception)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.WaitingFastboot,
                        $"读取 fastboot 序列号失败：{exception.Message}");
                    break;
                }

                if (probe is not null)
                {
                    if (probe.ExitCode != 0)
                    {
                        lastPollError =
                            $"fastboot getvar serialno 退出码 {probe.ExitCode}：{Diagnostic(probe)}";
                    }
                    else
                    {
                        string reported;
                        try
                        {
                            reported = MaintenanceEntry.ReadFastbootVariable(Combine(probe), "serialno");
                        }
                        catch (FormatException exception)
                        {
                            // Empty or contradictory output is not proof; keep polling until the deadline.
                            lastPollError = exception.Message;
                            reported = string.Empty;
                        }

                        if (reported.Length > 0)
                        {
                            if (string.Equals(reported, expectedSerial, StringComparison.Ordinal))
                            {
                                // Proof is recorded before any cancellation check: a cancelled token must
                                // not hide a serial fastboot already reported.
                                proven = true;
                                break;
                            }

                            proofTerminal = true;
                            RecordFailure(
                                InternalDeviceCheckStage.WaitingFastboot,
                                $"fastboot 报告的序列号「{reported}」不是期望的 {expectedSerial}；"
                                + "拒绝继续，且绝不重启该设备。");
                            break;
                        }
                    }
                }

                // The deadline is checked before every delay, never after it.
                if (_clock.GetElapsedTime(pollStart) >= FastbootTimeout)
                {
                    continue;
                }

                try
                {
                    await Task.Delay(PollInterval, _clock, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }
            }
        }

        if (proven && token.IsCancellationRequested)
        {
            cancelled = true;
        }

        if (proven && !cancelled && error is null)
        {
            progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.CheckingBootloader));

            try
            {
                var productProbe = await _runner.RunAsync(
                    new ProcessCommand(
                        _fastbootPath,
                        new[] { "-s", expectedSerial, "getvar", "product" },
                        FastbootQueryTimeout),
                    token).ConfigureAwait(false);

                if (productProbe.ExitCode != 0)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.CheckingBootloader,
                        $"fastboot getvar product 退出码 {productProbe.ExitCode}：{Diagnostic(productProbe)}");
                }
                else
                {
                    product = MaintenanceEntry.ReadFastbootVariable(Combine(productProbe), "product");
                    var model = android!.Identity.Model;
                    if (!IsAcceptedProduct(model, product))
                    {
                        RecordFailure(
                            InternalDeviceCheckStage.CheckingBootloader,
                            $"fastboot 产品「{product}」与 Android 型号「{model}」不匹配，拒绝继续。");
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                cancelled = true;
            }
            catch (Exception exception)
            {
                RecordFailure(
                    InternalDeviceCheckStage.CheckingBootloader,
                    $"读取 fastboot 产品失败：{exception.Message}");
            }
        }

        if (proven && !cancelled && error is null)
        {
            try
            {
                var confirmed = await transport.CheckFastbootAsync(android!.Identity, token).ConfigureAwait(false);
                lockState = confirmed.BootloaderState;

                if (lockState == BootloaderState.Unknown)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.CheckingBootloader,
                        "fastboot 未能给出可确认的引导锁定状态（Locked 或 Unlocked），拒绝判定通过。");
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                cancelled = true;
            }
            catch (Exception exception)
            {
                RecordFailure(
                    InternalDeviceCheckStage.CheckingBootloader,
                    $"读取引导锁定状态失败：{exception.Message}");
            }
        }

        // Placed after the product/lock checks and before the final OTA query, inside the same already
        // proven fastboot session, so the OTA query stays the last fastboot command of the cycle.
        if (proven && !cancelled && error is null)
        {
            try
            {
                var slotProbe = await _runner.RunAsync(
                    new ProcessCommand(
                        _fastbootPath,
                        new[] { "-s", expectedSerial, "getvar", "current-slot" },
                        FastbootQueryTimeout),
                    token).ConfigureAwait(false);

                if (slotProbe.ExitCode != 0)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.CheckingBootloader,
                        $"fastboot getvar current-slot 退出码 {slotProbe.ExitCode}：{Diagnostic(slotProbe)}");
                }
                else
                {
                    try
                    {
                        var reportedSlot = MaintenanceEntry.ReadFastbootVariable(
                            Combine(slotProbe),
                            "current-slot");

                        if (reportedSlot is "a" or "b")
                        {
                            currentSlot = reportedSlot;
                        }
                        else
                        {
                            RecordFailure(
                                InternalDeviceCheckStage.CheckingBootloader,
                                $"fastboot 报告的 current-slot「{reportedSlot}」既不是 a 也不是 b，"
                                + "不属于已知槽位，拒绝判定通过。");
                        }
                    }
                    catch (FormatException exception)
                    {
                        RecordFailure(
                            InternalDeviceCheckStage.CheckingBootloader,
                            $"fastboot current-slot 输出为空或不唯一，无法确认当前槽位：{exception.Message}");
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                cancelled = true;
            }
            catch (Exception exception)
            {
                RecordFailure(
                    InternalDeviceCheckStage.CheckingBootloader,
                    $"读取 fastboot current-slot 失败：{exception.Message}");
            }
        }

        if (proven && !cancelled && error is null)
        {
            try
            {
                var otaProbe = await _runner.RunAsync(
                    new ProcessCommand(
                        _fastbootPath,
                        new[] { "-s", expectedSerial, "getvar", "snapshot-update-status" },
                        FastbootQueryTimeout),
                    token).ConfigureAwait(false);

                otaState = otaProbe.ExitCode == 0
                    ? MaintenanceEntry.ParseSnapshotUpdateState(Combine(otaProbe))
                    : OtaUpdateState.Unknown;

                if (otaProbe.ExitCode != 0)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.CheckingBootloader,
                        $"fastboot getvar snapshot-update-status 退出码 {otaProbe.ExitCode}：{Diagnostic(otaProbe)}");
                }
                else if (otaState != OtaUpdateState.Completed)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.CheckingBootloader,
                        $"OTA 快照状态为 {otaState}，只有 Completed 才能判定 Step 1 通过。");
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                cancelled = true;
            }
            catch (Exception exception)
            {
                RecordFailure(
                    InternalDeviceCheckStage.CheckingBootloader,
                    $"读取 OTA 快照状态失败：{exception.Message}");
            }
        }

        // The cleanup budget is created lazily at the first moment a cleanup path actually needs it:
        // an eager timer would silently expire during a legitimate long wait for the user.
        CancellationTokenSource? cleanup = null;
        CancellationToken GetCleanupToken()
        {
            cleanup ??= new CancellationTokenSource(CleanupTimeout, _clock);
            return cleanup.Token;
        }

        try
        {
            if (!proven && !proofTerminal && !proofExhausted)
            {
                // The proof poll was interrupted before it finished: only the original serial is probed once.
                proven = await ProbeOriginalSerialOnceAsync(expectedSerial, GetCleanupToken()).ConfigureAwait(false);
            }

            var useCleanupToken = cancelled || error is not null;
            var androidReturn = modeAttempted ? AndroidReturnState.Unconfirmed : AndroidReturnState.NotRequired;

            if (proven)
            {
                // Sample the caller cancellation after the last successful query, before choosing the
                // return token: the proof is kept, and the single return gets an independent budget.
                if (token.IsCancellationRequested)
                {
                    cancelled = true;
                    useCleanupToken = true;
                }

                // Marked before invocation: an ACK that never arrives is not "no reboot".
                returnAttempted = true;
                progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.ReturningAndroid));

                var returnToken = useCleanupToken ? GetCleanupToken() : token;
                try
                {
                    var reboot = await _runner.RunAsync(
                        new ProcessCommand(_fastbootPath, new[] { "-s", expectedSerial, "reboot" }, RebootTimeout),
                        returnToken).ConfigureAwait(false);

                    if (reboot.ExitCode != 0)
                    {
                        RecordFailure(
                            InternalDeviceCheckStage.ReturningAndroid,
                            $"fastboot reboot 返回退出码 {reboot.ExitCode}：{Diagnostic(reboot)}");
                        useCleanupToken = true;
                    }
                }
                catch (OperationCanceledException) when (returnToken.IsCancellationRequested)
                {
                    // Never resend the reboot: only observe Android with the bounded cleanup token below.
                    if (token.IsCancellationRequested)
                    {
                        cancelled = true;
                    }
                    else
                    {
                        // The independent cleanup budget expired while the caller token was untouched:
                        // that is a return timeout, not a user cancellation.
                        RecordFailure(
                            InternalDeviceCheckStage.ReturningAndroid,
                            $"fastboot reboot 在 {CleanupTimeout.TotalSeconds:0} 秒的清理预算内未确认。");
                    }

                    useCleanupToken = true;
                }
                catch (Exception exception)
                {
                    RecordFailure(
                        InternalDeviceCheckStage.ReturningAndroid,
                        $"fastboot reboot 未确认：{exception.Message}");
                    useCleanupToken = true;
                }
            }

            var resultAndroid = android;
            if (returnAttempted)
            {
                progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.WaitingAndroid));

                var observeToken = useCleanupToken ? GetCleanupToken() : token;
                while (true)
                {
                    try
                    {
                        var observation = await ObserveAndroidAsync(
                            transport,
                            maintenance,
                            expectedSerial,
                            android!,
                            currentSlot,
                            lockState,
                            progress,
                            observeToken).ConfigureAwait(false);

                        if (observation.Identity is not null)
                        {
                            resultAndroid = observation.Identity;
                        }

                        androidReturn = observation.ReturnState;

                        if (observation.Error is not null)
                        {
                            RecordFailure(
                                observation.FailedStage ?? InternalDeviceCheckStage.WaitingAndroid,
                                observation.Error);
                        }

                        break;
                    }
                    catch (OperationCanceledException) when (observeToken.IsCancellationRequested)
                    {
                        if (useCleanupToken)
                        {
                            // The bounded cleanup budget itself is spent; the return stays unconfirmed,
                            // but the timeout is a real fact and is recorded instead of dropped.
                            RecordFailure(
                                InternalDeviceCheckStage.WaitingAndroid,
                                $"在 {CleanupTimeout.TotalSeconds:0} 秒的清理预算内未在 Android 中确认设备 {expectedSerial} 返回。");
                            break;
                        }

                        cancelled = true;
                        useCleanupToken = true;
                        observeToken = GetCleanupToken();
                    }
                    catch (Exception exception)
                    {
                        RecordFailure(
                            InternalDeviceCheckStage.WaitingAndroid,
                            $"读取返回后的 Android 状态失败：{exception.Message}");
                        break;
                    }
                }
            }

            // The cancellation flag is only ever taken from the original caller token, never inferred
            // from the independent cleanup budget expiring.
            if (token.IsCancellationRequested)
            {
                cancelled = true;
            }

            progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.Completed));

            return new InternalDeviceCheckResult(
                resultAndroid,
                proven ? expectedSerial : null,
                product,
                lockState,
                otaState,
                androidReturn,
                cancelled,
                failedStage,
                error,
                currentSlot);
        }
        finally
        {
            cleanup?.Dispose();
        }
    }

    /// <summary>
    /// Polls <c>adb devices -l</c> until the selected serial is authorized and booted, then re-reads and
    /// compares model, firmware, actual serial and SoC serial. Only a fully matching return is Verified.
    /// When fastboot already reported <paramref name="actualSlot"/>, the returned Android
    /// <c>ro.boot.slot_suffix</c> must be exactly <c>_a</c> or <c>_b</c> and match it.
    /// </summary>
    private async Task<AndroidObservation> ObserveAndroidAsync(
        DeviceTransport transport,
        MaintenanceEntry maintenance,
        string serial,
        AndroidMaintenanceIdentity initial,
        string? actualSlot,
        BootloaderState lockState,
        IProgress<InternalDeviceCheckProgress>? progress,
        CancellationToken token)
    {
        var start = _clock.GetTimestamp();

        while (true)
        {
            var before = _clock.GetTimestamp();
            var devices = await transport.ListDevicesAsync(token).ConfigureAwait(false);
            var selected = devices
                .Where(device => string.Equals(device.Serial, serial, StringComparison.Ordinal))
                .ToList();

            if (selected.Count > 1)
            {
                return AndroidObservation.Fail(
                    InternalDeviceCheckStage.WaitingAndroid,
                    $"adb 设备列表把序列号 {serial} 报告了 {selected.Count} 次，无法确认返回的是同一台设备。");
            }

            if (selected.Count == 1 && selected[0].ConnectionState == ConnectionState.Unauthorized)
            {
                // An explicit USB prompt is a user action, not device absence: pause the Android budget
                // for both this listing and the poll delay that follows it.
                progress?.Report(new InternalDeviceCheckProgress(
                    InternalDeviceCheckStage.WaitingUsbAuthorization,
                    $"设备 {serial} 已连接但未授权，请在设备上确认 USB 调试授权。"));
                try
                {
                    await Task.Delay(PollInterval, _clock, token).ConfigureAwait(false);
                }
                finally
                {
                    start += _clock.GetTimestamp() - before;
                }

                continue;
            }

            if (_clock.GetElapsedTime(start) >= AndroidTimeout)
            {
                return AndroidObservation.Fail(
                    InternalDeviceCheckStage.WaitingAndroid,
                    $"在 {AndroidTimeout.TotalSeconds:0} 秒内未在 Android 中确认设备 {serial}。");
            }

            if (selected.Count != 1 || selected[0].ConnectionState != ConnectionState.Authorized)
            {
                await Task.Delay(PollInterval, _clock, token).ConfigureAwait(false);
                continue;
            }

            var bootCompleted = await ReadShellPropertyAsync(serial, "sys.boot_completed", token)
                .ConfigureAwait(false);
            if (!string.Equals(bootCompleted, "1", StringComparison.Ordinal))
            {
                await Task.Delay(PollInterval, _clock, token).ConfigureAwait(false);
                continue;
            }

            progress?.Report(new InternalDeviceCheckProgress(InternalDeviceCheckStage.VerifyingAndroid));

            var returned = await transport.ReadAdbIdentityAsync(serial, token).ConfigureAwait(false);
            var returnedSerial = await ReadActualSerialAsync(serial, token).ConfigureAwait(false);
            var returnedAndroid = await maintenance.ReadAndroidAsync(returned, token).ConfigureAwait(false);

            var drift = new List<string>();
            if (!string.Equals(returned.Model, initial.Identity.Model, StringComparison.Ordinal))
            {
                drift.Add($"型号「{returned.Model}」!=「{initial.Identity.Model}」");
            }

            if (!string.Equals(returnedSerial, serial, StringComparison.Ordinal))
            {
                drift.Add($"实际序列号「{returnedSerial}」!=「{serial}」");
            }

            if (!string.Equals(returnedAndroid.SocSerial, initial.SocSerial, StringComparison.Ordinal))
            {
                drift.Add($"SoC 序列号「{returnedAndroid.SocSerial}」!=「{initial.SocSerial}」");
            }

            var expectedFirmware = initial.Identity.Firmware;
            if (expectedFirmware is null || returned.Firmware is null)
            {
                drift.Add("缺少可比较的固件快照");
            }
            else
            {
                if (!string.Equals(returned.Firmware.DisplayId, expectedFirmware.DisplayId, StringComparison.Ordinal))
                {
                    drift.Add($"display id「{returned.Firmware.DisplayId}」!=「{expectedFirmware.DisplayId}」");
                }

                if (!string.Equals(
                        returned.Firmware.BuildFingerprint,
                        expectedFirmware.BuildFingerprint,
                        StringComparison.Ordinal))
                {
                    drift.Add("build fingerprint 不一致");
                }

                if (!string.Equals(
                        returned.Firmware.AndroidRelease,
                        expectedFirmware.AndroidRelease,
                        StringComparison.Ordinal))
                {
                    drift.Add("Android 版本不一致");
                }

                if (!string.Equals(
                        returned.Firmware.SecurityPatch,
                        expectedFirmware.SecurityPatch,
                        StringComparison.Ordinal))
                {
                    drift.Add("安全补丁级别不一致");
                }

                if (returned.Firmware.AndroidReportedBootloaderState
                    != expectedFirmware.AndroidReportedBootloaderState)
                {
                    drift.Add("Android 报告的锁定状态不一致");
                }
            }

            if (drift.Count > 0)
            {
                return AndroidObservation.Fail(
                    InternalDeviceCheckStage.VerifyingAndroid,
                    $"返回后的设备与进入前的身份不一致，拒绝判定为同一台设备：{string.Join("；", drift)}。");
            }

            if (actualSlot is not null)
            {
                var returnedSuffix = await ReadShellPropertyAsync(serial, "ro.boot.slot_suffix", token)
                    .ConfigureAwait(false);
                if (!string.Equals(returnedSuffix, "_" + actualSlot, StringComparison.Ordinal))
                {
                    return AndroidObservation.Fail(
                        InternalDeviceCheckStage.VerifyingAndroid,
                        $"返回后的 Android 槽位后缀「{returnedSuffix}」与 fastboot 报告的当前槽「{actualSlot}」"
                        + "不一致（要求精确的 _a 或 _b），拒绝判定为同一台设备。");
                }
            }

            // The verified identity carries the fastboot-confirmed lock state, never the adb Unknown.
            return AndroidObservation.Verified(
                new AndroidMaintenanceIdentity(
                    returned with { BootloaderState = lockState },
                    returnedAndroid.SocSerial));
        }
    }

    /// <summary>One bounded serialno query that may only confirm the original serial.</summary>
    private async Task<bool> ProbeOriginalSerialOnceAsync(string serial, CancellationToken token)
    {
        try
        {
            var result = await _runner.RunAsync(
                new ProcessCommand(
                    _fastbootPath,
                    new[] { "-s", serial, "getvar", "serialno" },
                    FastbootQueryTimeout),
                token).ConfigureAwait(false);

            return result.ExitCode == 0
                && string.Equals(
                    MaintenanceEntry.ReadFastbootVariable(Combine(result), "serialno"),
                    serial,
                    StringComparison.Ordinal);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>G4 accepts only its own product aliases; G5 accepts any non-G4 product.</summary>
    private static bool IsAcceptedProduct(string model, string product)
    {
        if (string.IsNullOrWhiteSpace(product))
        {
            return false;
        }

        var isG4Product = string.Equals(product, G4Model, StringComparison.OrdinalIgnoreCase)
            || string.Equals(product, G4Product, StringComparison.OrdinalIgnoreCase);

        return string.Equals(model, G4Model, StringComparison.Ordinal)
            ? isG4Product
            : string.Equals(model, G5Model, StringComparison.Ordinal) && !isG4Product;
    }

    private async Task<string> ReadActualSerialAsync(string serial, CancellationToken token)
    {
        var value = await ReadShellPropertyAsync(serial, "ro.serialno", token).ConfigureAwait(false);

        return string.IsNullOrWhiteSpace(value)
            ? await ReadShellPropertyAsync(serial, "ro.boot.serialno", token).ConfigureAwait(false)
            : value;
    }

    private async Task<string> ReadShellPropertyAsync(string serial, string property, CancellationToken token)
    {
        var result = await _runner.RunAsync(
            new ProcessCommand(_adbPath, new[] { "-s", serial, "shell", "getprop", property }, PropertyTimeout),
            token).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"读取设备 {serial} 的属性 {property} 失败（{_adbPath}，退出码 {result.ExitCode}）：{Diagnostic(result)}");
        }

        return result.StandardOutput.Trim();
    }

    private static string Combine(ProcessResult result) =>
        result.StandardOutput + "\n" + result.StandardError;

    private static string Diagnostic(ProcessResult result)
    {
        var error = result.StandardError.Trim();
        return error.Length > 0 ? error : result.StandardOutput.Trim();
    }

    /// <summary>Outcome of one bounded Android observation.</summary>
    private sealed record AndroidObservation(
        AndroidReturnState ReturnState,
        AndroidMaintenanceIdentity? Identity,
        InternalDeviceCheckStage? FailedStage,
        string? Error)
    {
        public static AndroidObservation Verified(AndroidMaintenanceIdentity identity) =>
            new(AndroidReturnState.Verified, identity, null, null);

        public static AndroidObservation Fail(InternalDeviceCheckStage stage, string error) =>
            new(AndroidReturnState.Unconfirmed, null, stage, error);
    }
}
