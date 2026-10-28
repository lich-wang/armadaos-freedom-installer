using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」的显式退出：在真实 9008 会话仍存在时，只发送一次 <see cref="EdlClient.ResetAsync"/>，
/// 然后用只读 adb 查询在有限时间内确认同一台平板已经回到安卓。
/// <para>
/// 重置命令被接受只代表 Firehose 电源命令被接受，绝不代表安卓已经启动；只有实际读到的
/// 序列号、型号、完整固件 display id 与 SoC 序列号全部与退出前保存的真实身份一致，才写入
/// 「已确认返回安卓」。任何超时、未知结果、身份不一致都保留连接、工具与电脑备份现场。
/// </para>
/// <para>
/// 本流程从不重新进入 9008、不重建客户端、不伪造会话或证明，也不执行 Fastboot 检查、重启、
/// 解锁、格式化、擦除、刷写或清除数据；电脑上的备份文件与清单永远不删除。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>只读等待安卓返回的上限；到点只写「未确认」，不写成功。</summary>
    private static readonly TimeSpan InternalInstallExitWaitTimeout = TimeSpan.FromSeconds(180);

    /// <summary>只读轮询间隔；每个命令自身仍带有限超时。</summary>
    private static readonly TimeSpan InternalInstallExitPollDelay = TimeSpan.FromMilliseconds(500);

    /// <summary>读取 <c>sys.boot_completed</c> 的有限超时。</summary>
    private static readonly TimeSpan InternalInstallExitBootQueryTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// 本次真实会话是否已经调用过 <see cref="EdlClient.ResetAsync"/>（含结果未知）。
    /// 置位之后界面只允许只读检查，绝不会再次重置；只有在确认返回且会话完全结束后才清除。
    /// </summary>
    private bool _internalInstallExitResetAttempted;

    /// <summary>最近一次退出是否已通过真实安卓读数确认；只用于界面状态，不代替任何门槛。</summary>
    private bool _internalInstallExitConfirmed;

    /// <summary>退出流程正在等待时阻止第二个入口并发进入。</summary>
    private bool _internalInstallExitActive;

    /// <summary>共享退出面板是否已经显示过；用于只写一次初始的真实维护说明。</summary>
    private bool _internalInstallExitPanelShown;

    /// <summary>关闭窗口时已经进入确认流程，避免重复弹框或递归退出。</summary>
    private bool _internalInstallExitClosePromptActive;

    private enum InternalInstallExitWaitOutcome
    {
        Verified,
        Mismatch,
        Unconfirmed,
        Cancelled,
    }

    /// <summary>只读等待的结果：成功时带真实读数，失败时带最后一次实际诊断。</summary>
    private sealed record InternalInstallExitWaitResult(
        InternalInstallExitWaitOutcome Outcome,
        AndroidMaintenanceIdentity? Android,
        string? Diagnostic);

    // ---------- 入口 ----------

    /// <summary>共享退出面板上唯一的按钮：用户已经明确点击退出，不再弹第二次确认。</summary>
    private async void OnExitInternalInstallMaintenance(object sender, RoutedEventArgs e)
    {
        // TF 卡安装优先：显式退出按钮不再弹第二次确认（ask:false），成功后安全复位并刷新。
        // 绝不进入通用安卓验收 / 重置流程。
        if (IsModernTfInstallMode)
        {
            if (!_ready || _busy || _tfInstallOperationActive)
            {
                return;
            }

            if (await ConfirmLeaveModernTfInstallAsync(ask: false))
            {
                await SafeResetModernTfInstallStateAsync();
                RenderModernTfInstallPages();
                RefreshModernTfInstallActions();
            }

            return;
        }

        // 现代卸载优先：显式退出按钮不再弹第二次确认（ask:false），成功后安全复位并刷新。
        if (IsModernUserdataUninstallMode)
        {
            if (!_ready || _busy || _userdataUninstallOperationActive)
            {
                return;
            }

            if (await ConfirmLeaveModernUserdataUninstallAsync(ask: false))
            {
                SafeResetModernUserdataUninstallState();
                RenderModernUserdataUninstallPages();
                RefreshModernUserdataUninstallActions();
            }

            return;
        }

        // 维护模式优先：走维护自己的「一次复位离开」例程，绝不进入旧安装的 ADB 等待。
        if (IsBootMaintenanceMode)
        {
            if (!_ready || _busy || _bootMaintenanceOperationActive)
            {
                return;
            }

            await ExitBootMaintenanceAsync();

            // 已批准离开后返回；拒绝时现场原样保留。
            return;
        }

        // 写入已经开始：旧维护退出/重置入口一律不可用，避免用旧流程打断真实安装。
        if (HasInternalInstallExecutionStarted)
        {
            return;
        }

        if (!_ready || _busy || _internalInstallOperationActive || !IsInternalInstallMode)
        {
            return;
        }

        if (!HasInternalInstallLiveEdlState)
        {
            return;
        }

        await ExitInternalInstallMaintenanceAsync();
    }

    /// <summary>
    /// 功能切换、返回首页与关闭窗口共用的确认：真实写入开始后只允许真实 Completed 离开，
    /// 其余已开始状态明确拒绝且不进入旧重置；未开始写入时，只有真实 9008 会话存在才询问，
    /// 默认「否」；选择「是」后严格复用 <see cref="ExitInternalInstallMaintenanceAsync"/>。
    /// </summary>
    private async Task<bool> ConfirmExitInternalInstallMaintenanceAsync()
    {
        if (HasInternalInstallExecutionStarted)
        {
            // 只有真实 Core 报告 Completed 才允许离开；仍会先释放本程序自己的资源并复原界面，
            // 但绝不调用旧重置、绝不改写快照，也不把「离开界面」当成验收通过。
            if (IsCompletedInternalInstallExecution
                && !_busy
                && !_internalInstallOperationActive)
            {
                _internalInstallPostWriteCloseApproved = true;
                ResetInternalInstallUiState();

                // Completed 由真实 Core 给出，设备侧不再需要维护会话：只释放本程序自己的
                // 只读锁与工具链，绝不发送重置、也绝不删除备份或证据文件。
                DisposeInternalInstallResources();
                return true;
            }

            AppendLocalizedLog(M("Dynamic.InternalInstall.Execution.FunctionChangeBlocked"));
            SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Execution.FunctionChangeBlocked"));
            return false;
        }

        if (!HasInternalInstallLiveEdlState)
        {
            return true;
        }

        if (!_ready || _busy || _internalInstallOperationActive)
        {
            return false;
        }

        var answer = MessageBox.Show(
            this,
            T("Dynamic.InternalInstall.Exit.ConfirmBody"),
            T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return false;
        }

        return await ExitInternalInstallMaintenanceAsync();
    }

    /// <summary>
    /// 唯一的显式退出实现：每次实际会话最多一次重置，之后只读等待；返回值只表示
    /// 「确实用同一台安卓的实时读数核对通过」，不表示任何权限或界面状态。
    /// </summary>
    private async Task<bool> ExitInternalInstallMaintenanceAsync()
    {
        // 写入已经开始：旧退出实现（重置并等待安卓返回）永远不能再运行。
        if (HasInternalInstallExecutionStarted)
        {
            return false;
        }

        if (!_ready || _busy || _internalInstallOperationActive || !IsInternalInstallMode)
        {
            return false;
        }

        if (!HasInternalInstallLiveEdlState || _internalInstallExitActive)
        {
            return false;
        }

        var transport = _transport;

        // 保存的身份只能来自真实检查结果或真实 9008 入口证据；绝不使用计划、默认值或第一台设备。
        var expected = _internalInstallDeviceCheck?.Android ?? _internalInstallEdlEntry?.AndroidIdentity;
        if (transport is null || expected is null)
        {
            SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.NeedIdentity"));
            return false;
        }

        _internalInstallExitActive = true;
        _internalInstallOperationActive = true;

        var verified = false;

        try
        {
            // 只调用一次 RunBusyAsync；流程内部不再嵌套忙碌或另起等待框架。
            await RunBusyAsync(async token =>
            {
                var client = _internalInstallEdlClient;
                var resetUnknown = false;
                string? resetDiagnostic = null;

                if (!_internalInstallExitResetAttempted)
                {
                    if (client is null)
                    {
                        // 只有进入尝试，没有真实客户端：绝不构造替代客户端，也不盲发重置。
                        SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.EntryUnconfirmed"));
                    }
                    else
                    {
                        if (!client.HasInitialSaharaProof)
                        {
                            SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.CheckingProof"));
                            try
                            {
                                // 同一个真实客户端上的只读几何与 RAM loader 证明；失败则不发送重置。
                                await client.ProbeAsync(
                                    0,
                                    initialLoader: !client.HasInitialSaharaProof,
                                    cancellationToken: token);
                            }
                            catch (OperationCanceledException) when (token.IsCancellationRequested)
                            {
                                SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.Cancelled"));
                                return;
                            }
                            catch (Exception exception)
                            {
                                SetInternalInstallExitStatus(
                                    M(
                                        "Dynamic.InternalInstall.Exit.ProofFailed",
                                        DiagnosticOf(exception)));
                                return;
                            }
                        }

                        // 标记紧贴真实调用之前：即使 API 校验抛错，也不会再次从界面自动重置。
                        _internalInstallExitResetAttempted = true;
                        SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.Resetting"));

                        try
                        {
                            await client.ResetAsync(token);
                            SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.ResetAccepted"));
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested)
                        {
                            // 重置可能已经在取消前发出：结果只能当作未知，绝不重发。
                            resetUnknown = true;
                            resetDiagnostic = UnknownValue;
                            SetInternalInstallExitStatus(
                                M("Dynamic.InternalInstall.Exit.ResetUnknown", resetDiagnostic));
                        }
                        catch (Exception exception)
                        {
                            resetUnknown = true;
                            resetDiagnostic = DiagnosticOf(exception);
                            SetInternalInstallExitStatus(
                                M("Dynamic.InternalInstall.Exit.ResetUnknown", resetDiagnostic));
                        }
                    }
                }
                else
                {
                    SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.CheckingAgain"));
                }

                // 从这里开始只读：不再 probe、不再 reset、不重新进入 9008。
                var wait = await WaitForInternalInstallAndroidReturnAsync(transport, expected, token);

                switch (wait.Outcome)
                {
                    case InternalInstallExitWaitOutcome.Verified:
                        _internalInstallExitConfirmed = true;
                        verified = true;
                        CompleteInternalInstallExit(wait.Android!);
                        break;

                    case InternalInstallExitWaitOutcome.Mismatch:
                        SetInternalInstallExitStatus(M("Dynamic.InternalInstall.Exit.Mismatch"));
                        break;

                    case InternalInstallExitWaitOutcome.Cancelled:
                        SetInternalInstallExitStatus(
                            resetUnknown
                                ? M(
                                    "Dynamic.InternalInstall.Exit.ResetUnknown",
                                    resetDiagnostic ?? UnknownValue)
                                : M("Dynamic.InternalInstall.Exit.Cancelled"));
                        break;

                    default:
                        var diagnostic = wait.Diagnostic ?? resetDiagnostic ?? UnknownValue;
                        SetInternalInstallExitStatus(
                            resetUnknown
                                ? M(
                                    "Dynamic.InternalInstall.Exit.ResetUnknownUnconfirmed",
                                    resetDiagnostic ?? UnknownValue,
                                    diagnostic)
                                : M("Dynamic.InternalInstall.Exit.ReturnUnconfirmed", diagnostic));
                        break;
                }
            });
        }
        finally
        {
            _internalInstallExitActive = false;
            _internalInstallOperationActive = false;
            RefreshInternalInstallActions();
            UpdateSummary();
        }

        return verified && _internalInstallExitConfirmed;
    }

    // ---------- 有界只读等待 ----------

    /// <summary>
    /// 只在真实身份对得上时轮询：先按目标序列号找设备，未授权 / 离线继续等；安卓报告
    /// <c>sys.boot_completed=1</c> 之后才读取一次完整身份并逐项比对。身份不一致立即停止，
    /// 其他只读查询失败可以在时限内重试，并保留最后一次实际诊断。
    /// </summary>
    private async Task<InternalInstallExitWaitResult> WaitForInternalInstallAndroidReturnAsync(
        DeviceTransport transport,
        AndroidMaintenanceIdentity expected,
        CancellationToken token)
    {
        var expectedSerial = expected.Identity.Serial;
        var diagnostic = string.Empty;
        var lastStage = string.Empty;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(InternalInstallExitWaitTimeout);
        var waitToken = deadline.Token;

        try
        {
            while (true)
            {
                waitToken.ThrowIfCancellationRequested();

                IReadOnlyList<ConnectedDevice> devices;
                try
                {
                    devices = await transport.ListDevicesAsync(waitToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception) when (IsInternalInstallExitQueryFailure(exception))
                {
                    diagnostic = DiagnosticOf(exception);
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.Retrying",
                        diagnostic);
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                // 只认目标序列号；其他设备一概忽略，绝不退回第一台。
                var device = devices.FirstOrDefault(candidate =>
                    string.Equals(candidate.Serial, expectedSerial, StringComparison.Ordinal));

                if (device is null)
                {
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.WaitingAndroid");
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                if (device.ConnectionState == ConnectionState.Unauthorized)
                {
                    // 授权只能在平板上完成；程序只提示并继续等待。
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.WaitingAuthorization");
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                if (device.ConnectionState != ConnectionState.Authorized)
                {
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.WaitingAndroid");
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                var booted = false;
                try
                {
                    var boot = await _runner.RunAsync(
                        new ProcessCommand(
                            transport.AdbPath,
                            new[] { "-s", expectedSerial, "shell", "getprop", "sys.boot_completed" },
                            InternalInstallExitBootQueryTimeout),
                        waitToken);

                    booted = boot.ExitCode == 0
                        && string.Equals(boot.StandardOutput.Trim(), "1", StringComparison.Ordinal);

                    if (!booted && boot.ExitCode != 0)
                    {
                        diagnostic = DiagnosticOf(boot);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception) when (IsInternalInstallExitQueryFailure(exception))
                {
                    diagnostic = DiagnosticOf(exception);
                }

                if (!booted)
                {
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.WaitingBoot");
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                SetInternalInstallExitStage(ref lastStage, "Dynamic.InternalInstall.Exit.Verifying");

                AndroidMaintenanceIdentity fresh;
                try
                {
                    var identity = await transport.ReadAdbIdentityAsync(expectedSerial, waitToken);
                    var entry = new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner);
                    fresh = await entry.ReadAndroidAsync(identity, waitToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception) when (IsInternalInstallExitQueryFailure(exception))
                {
                    diagnostic = DiagnosticOf(exception);
                    SetInternalInstallExitStage(
                        ref lastStage,
                        "Dynamic.InternalInstall.Exit.Retrying",
                        diagnostic);
                    await Task.Delay(InternalInstallExitPollDelay, waitToken);
                    continue;
                }

                if (!InternalInstallAndroidMatches(expected, fresh))
                {
                    // 身份不一致是终止条件：不重试、不再重置、不清理任何现场。
                    return new InternalInstallExitWaitResult(
                        InternalInstallExitWaitOutcome.Mismatch,
                        null,
                        diagnostic);
                }

                return new InternalInstallExitWaitResult(
                    InternalInstallExitWaitOutcome.Verified,
                    fresh,
                    diagnostic);
            }
        }
        catch (OperationCanceledException)
        {
            return new InternalInstallExitWaitResult(
                token.IsCancellationRequested
                    ? InternalInstallExitWaitOutcome.Cancelled
                    : InternalInstallExitWaitOutcome.Unconfirmed,
                null,
                string.IsNullOrWhiteSpace(diagnostic) ? null : diagnostic);
        }
    }

    // ---------- 确认返回后的收尾 ----------

    /// <summary>
    /// 仅在真实四事实核对通过后调用：保留电脑备份的显示证据，结束真实会话并释放只读锁与
    /// 工具链自己的暂存目录，然后回到第 0 步。绝不在超时、取消或结果未知时调用。
    /// </summary>
    private void CompleteInternalInstallExit(AndroidMaintenanceIdentity fresh)
    {
        // 先保留并显示最近一次真实备份的目录、清单、摘要与文件数，再释放只读锁。
        RenderInternalInstallBackupAfterVerifiedExit();

        var directory = _internalInstallRetainedBackupDirectory;
        var manifest = _internalInstallRetainedBackupManifest;
        var hash = _internalInstallRetainedBackupManifestHash;

        SetInternalInstallExitStatus(
            M(
                "Dynamic.InternalInstall.Exit.Verified",
                Placeholder(fresh.Identity.Model),
                Placeholder(fresh.Identity.Serial),
                Placeholder(fresh.Identity.Firmware?.DisplayId)));

        if (directory is not null)
        {
            AppendLocalizedLog(
                M(
                    "Dynamic.InternalInstall.Exit.BackupRetainedLog",
                    directory,
                    manifest ?? UnknownValue,
                    hash ?? UnknownValue));
        }

        // 所有等待的命令都已返回：现在才释放备份只读锁与工具链的 GUID 暂存目录。
        DisposeInternalInstallResources();

        // 退出后不再保留任何可复用的安装资格；下一次安装必须重新检查并重新备份。
        _internalInstallDeviceCheck = null;
        _internalInstallPower = null;
        _internalInstallExitResetAttempted = false;
        _internalInstallExitConfirmed = true;

        _internalInstallStep = 0;
        RenderInternalInstallCheckPlaceholders();

        // 已知的实际读数可以显示，但门槛保持关闭，绝不猜一个型号或固件。
        SetText(InternalInstallModelText, "Dynamic.RawValue", Placeholder(fresh.Identity.Model));
        SetText(InternalInstallSerialText, "Dynamic.RawValue", Placeholder(fresh.Identity.Serial));
        SetText(
            InternalInstallFirmwareText,
            "Dynamic.RawValue",
            Placeholder(fresh.Identity.Firmware?.DisplayId ?? fresh.Identity.Firmware?.BuildFingerprint));
        SetText(
            InternalInstallCheckProgressText,
            "Dynamic.InternalInstall.Exit.ProgressVerified");
        SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Exit.VerifiedState"));

        RenderInternalInstallBackupDetail();
        RenderInternalInstallPages();
    }

    // ---------- 视图与诊断 ----------

    /// <summary>
    /// 共享退出面板的唯一可用性入口：只在真实会话（或未确认的进入尝试）存在时显示，
    /// 忙碌、操作中或退出等待中一律禁用；重置已经尝试过后只提供只读复查按钮。
    /// </summary>
    private void RefreshInternalInstallExitActions()
    {
        if (!_ready || !IsInternalInstallMode)
        {
            return;
        }

        var live = HasInternalInstallLiveEdlState;

        // 真实写入开始后，旧维护退出面板不再提供任何操作，避免把执行现场交给旧重置流程。
        if (HasInternalInstallExecutionStarted)
        {
            _internalInstallExitPanelShown = false;
            InternalInstallExitMaintenancePanel.Visibility = Visibility.Collapsed;
            InternalInstallExitMaintenanceButton.IsEnabled = false;
            return;
        }

        InternalInstallExitMaintenancePanel.Visibility =
            live ? Visibility.Visible : Visibility.Collapsed;

        if (!live)
        {
            _internalInstallExitPanelShown = false;
            InternalInstallExitMaintenanceButton.IsEnabled = false;
            return;
        }

        if (!_internalInstallExitPanelShown)
        {
            _internalInstallExitPanelShown = true;
            _internalInstallExitConfirmed = false;
            SetInternalInstallExitStatus(
                M(
                    _internalInstallEdlClient is null
                        ? "Dynamic.InternalInstall.Exit.EntryUnconfirmed"
                        : "Dynamic.InternalInstall.Exit.StatusIdle"));
        }

        InternalInstallExitMaintenanceButton.IsEnabled =
            !_busy && !_internalInstallOperationActive && !_internalInstallExitActive;

        SetContent(
            InternalInstallExitMaintenanceButton,
            _internalInstallExitResetAttempted && !_internalInstallExitActive
                ? "Dynamic.InternalInstall.Exit.RetryButton"
                : "Dynamic.InternalInstall.Exit.Button");
    }

    private void SetInternalInstallExitStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallExitMaintenanceStatusText, message);
    }

    /// <summary>同一阶段不重复写，避免 500ms 轮询反复刷新同一条状态。</summary>
    private void SetInternalInstallExitStage(ref string lastStage, string key, params object?[] args)
    {
        if (args.Length == 0 && string.Equals(lastStage, key, StringComparison.Ordinal))
        {
            return;
        }

        lastStage = key;
        SetInternalInstallExitStatus(M(key, args));
    }

    /// <summary>只读查询中允许重试的失败；身份不一致不走这里，由调用方直接终止。</summary>
    private static bool IsInternalInstallExitQueryFailure(Exception exception) =>
        exception is InvalidOperationException
            or System.IO.IOException
            or UnauthorizedAccessException
            or TimeoutException
            or ArgumentException
            or NotSupportedException;

    private static string DiagnosticOf(Exception exception) => DiagnosticExcerpt(exception.Message);

    private static string DiagnosticOf(ProcessResult result) =>
        DiagnosticExcerpt(
            string.IsNullOrWhiteSpace(result.StandardError)
                ? result.StandardOutput
                : result.StandardError);
}
