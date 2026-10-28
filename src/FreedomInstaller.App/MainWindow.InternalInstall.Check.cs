using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」第 0 步的真实自动检查：列出真实 adb 设备，由 Core 的
/// <see cref="InternalInstallDeviceCheck"/> 完成一次「安卓 → Fastboot → 同一台安卓」往返，
/// 界面只写入实际返回的结果。
/// <para>
/// 检查通过只说明这台平板可以进入备份页，不代表可以写入，也不代表型号或固件已通过安装资格；
/// 这里没有任何模拟结果、备用成功路径或写死值，进度只用于显示，绝不参与门槛判定。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>最近一次真实检查结果；null 表示还没有可用的检查结论。</summary>
    private InternalDeviceCheckResult? _internalInstallDeviceCheck;

    /// <summary>最近一次真实列出的 adb 设备；下拉框只按它显示，不预造任何条目。</summary>
    private IReadOnlyList<ConnectedDevice> _internalInstallDeviceChoices = Array.Empty<ConnectedDevice>();

    /// <summary>检查进行中：关闭窗口会被拒绝，后续备份也复用同一道闸门。</summary>
    private bool _internalInstallOperationActive;

    /// <summary>程序化重建设备列表 / 恢复选择时抑制 SelectionChanged。</summary>
    private bool _suppressInternalInstallDeviceSelection;

    /// <summary>检查通过后单独采样的安卓电量，不代表 Fastboot 或 9008 状态下的实时读数。</summary>
    private EdlPowerSample? _internalInstallPower;

    /// <summary>
    /// 进入备份页的唯一正面证据：真实检查成功、平板已确认回到安卓，并且返回的安卓身份完整
    /// （型号、序列号、完整 display id 与 SoC 序列号都不为空）。
    /// <para>
    /// 这里不再比对任何固定型号 / 固件，也不要求某个具体资源已经嵌入：信任的 EDL 配置在真正
    /// 进入 9008 之前才按实际型号选择，并逐项核对。它只表示「可以进入下一步、选择电脑备份位置」，
    /// 不表示任何组件已校验通过，也不表示允许写入。
    /// </para>
    /// </summary>
    private bool HasCheckedInternalInstallDevice
    {
        get
        {
            var result = _internalInstallDeviceCheck;
            if (result is null
                || !result.Succeeded
                || result.AndroidReturn != AndroidReturnState.Verified
                || result.Android is null)
            {
                return false;
            }

            var android = result.Android;
            var identity = android.Identity;
            if (identity is null)
            {
                return false;
            }

            return !string.IsNullOrWhiteSpace(identity.Model)
                && !string.IsNullOrWhiteSpace(identity.Serial)
                && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
                && !string.IsNullOrWhiteSpace(android.SocSerial);
        }
    }

    /// <summary>下拉框里用户实际选中的那台设备；没有选择时返回 null，绝不退回第一项。</summary>
    private ConnectedDevice? SelectedInternalInstallDevice() =>
        InternalInstallDevicesCombo.SelectedItem is ComboBoxItem item && item.Tag is ConnectedDevice device
            ? device
            : null;

    // ---------- 检查入口 ----------

    /// <summary>
    /// 「检查平板（自动重启检查）」：一次点击完成设备列举与整轮自动检查。
    /// 唯一设备直接检查；多台设备必须先在下拉框里选一台，本方法绝不替用户选第一台。
    /// </summary>
    private async void OnCheckInternalInstallDevice(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _internalInstallOperationActive || !UsesSharedDevicePreparationPages)
        {
            return;
        }

        // 维护模式且用户已勾选「平板已在 9008」：走真实的历史 9008 只读核对入口，绝不伪造安卓检查。
        // 卸载模式同构：同一历史 9008 只读核对入口（受卸载自己的保护状态约束）。
        // TF 卡安装同构：受 TF 自己的保护状态 / 会话约束。
        if (IsModernTfInstallMode)
        {
            if (_tfInstallOperationActive || ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
            {
                return;
            }

            if (_bootMaintenanceAlreadyEdl)
            {
                await CheckBootMaintenanceEdlAsync();
                return;
            }

            if (HasInternalInstallLiveEdlState)
            {
                SetInternalInstallCheckStatus(M("Dynamic.Workflow.NotPrepared", ModeMessage(CurrentModeTag())));
                return;
            }

            // 安卓路线继续走下面共享的真实自动检查；不重写检查本身。
        }

        if (IsModernUserdataUninstallMode)
        {
            if (_userdataUninstallOperationActive || ProtectedModernUserdataUninstallState)
            {
                return;
            }

            if (_bootMaintenanceAlreadyEdl)
            {
                await CheckBootMaintenanceEdlAsync();
                return;
            }

            if (HasInternalInstallLiveEdlState)
            {
                SetInternalInstallCheckStatus(M("Dynamic.Workflow.NotPrepared", ModeMessage(CurrentModeTag())));
                return;
            }

            // 安卓路线继续走下面共享的真实自动检查；不重写检查本身。
        }

        if (IsBootMaintenanceMode && _bootMaintenanceAlreadyEdl)
        {
            await CheckBootMaintenanceEdlAsync();
            return;
        }

        // 维护模式且存在真实 9008 会话但未勾选路线：不允许把平板当安卓重新检查，保留现状。
        if (IsBootMaintenanceMode && HasInternalInstallLiveEdlState)
        {
            SetInternalInstallCheckStatus(M("Dynamic.Workflow.NotPrepared", ModeMessage(CurrentModeTag())));
            return;
        }

        // 任何维护受保护状态（未确认写入 / 未知复位）都不允许发起新的安卓检查。
        if (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
        {
            return;
        }

        var transport = _transport;
        if (transport is null)
        {
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.ToolsRequired"));
            return;
        }

        var previousSerial = SelectedInternalInstallDevice()?.Serial;

        // 重新检查前先清掉上一轮结论：结果、电量与派生界面一起回到「未检查」。
        ResetInternalInstallCheckState(clearSelection: false);

        _internalInstallOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Listing"));
                    var devices = await transport.ListDevicesAsync(token);
                    PopulateInternalInstallDeviceChoices(devices, previousSerial);
                    RefreshInternalInstallActions();

                    if (devices.Count == 0)
                    {
                        SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.NoDevices"));
                        return;
                    }

                    // 唯一设备直接用；多台只认用户已经选中的那一台。
                    var target = devices.Count == 1 ? devices[0] : SelectedInternalInstallDevice();
                    if (target is null)
                    {
                        SetInternalInstallCheckStatus(
                            M("Dynamic.InternalInstall.Check.MultipleNeedSelection", devices.Count));
                        return;
                    }

                    if (target.ConnectionState != ConnectionState.Authorized)
                    {
                        SetInternalInstallCheckStatus(
                            M(
                                "Dynamic.InternalInstall.Check.NotAuthorized",
                                target.Serial,
                                M(ConnectionStateKey(target.ConnectionState))));
                        return;
                    }

                    SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.Started", target.Serial));

                    // 共享默认路线：非内部模式的默认检查只读安卓身份，不走 Fastboot 往返；
                    // 「高级：核验Bootloader」按钮（SharedFastbootCheckButton）的 sender 保留原有完整检查。
                    var fromSharedAdvancedButton = sender is Button sharedButton
                        && string.Equals(sharedButton.Name, "SharedFastbootCheckButton", StringComparison.Ordinal);
                    if (IsSharedNonInternalDeviceMode && !fromSharedAdvancedButton)
                    {
                        await CheckSharedAndroidTargetAsync(target.Serial, token);
                        return;
                    }

                    var progress = new Progress<InternalDeviceCheckProgress>(report =>
                    {
                        // 终态一旦写出，迟到的进度回调不允许再覆盖它。
                        if (!acceptProgress)
                        {
                            return;
                        }

                        SetInternalInstallCheckProgress(
                            M(InternalInstallCheckStageKey(report.Stage)));
                    });

                    var check = new InternalInstallDeviceCheck(
                        transport.AdbPath,
                        transport.FastbootPath,
                        _runner);
                    var result = await check.CheckAsync(target.Serial, progress, token);

                    acceptProgress = false;
                    _internalInstallDeviceCheck = result;
                    RenderInternalInstallDeviceCheck(result);

                    if (result.Succeeded && result.AndroidReturn == AndroidReturnState.Verified)
                    {
                        _internalInstallPower = await CaptureInternalInstallPowerAsync(
                            transport.AdbPath,
                            result.Android!.Identity.Serial,
                            token);
                    }

                    RenderInternalInstallPower();
                }
                catch (OperationCanceledException)
                {
                    acceptProgress = false;

                    // 调用方取消：只写一条取消说明，不声称平板没有被重启过。
                    SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Cancelled"));
                    SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.Cancelled"));
                    throw;
                }
                catch (Exception exception)
                {
                    acceptProgress = false;
                    _internalInstallDeviceCheck = null;
                    _internalInstallPower = null;
                    RenderInternalInstallCheckPlaceholders();
                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message)
                        ? UnknownValue
                        : exception.Message;
                    SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Failed", diagnostic));
                    SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.Failed", diagnostic));
                }
            });
        }
        finally
        {
            _internalInstallOperationActive = false;
            RefreshActions();
        }
    }

    /// <summary>用户在下拉框里换了设备：上一台设备的一切结论立即作废，并回到第 0 步。</summary>
    private void OnInternalInstallDeviceSelected(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready
            || _busy
            || _internalInstallOperationActive
            || _suppressInternalInstallDeviceSelection
            || !UsesSharedDevicePreparationPages)
        {
            return;
        }

        ResetInternalInstallCheckState(clearSelection: false);
        if (_internalInstallStep != 0)
        {
            NavigateInternalInstallStep(0);
        }

        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 关闭窗口时的额外保护：检查或备份正在等待设备 / 执行客户端命令时拒绝关闭，不取消、不杀进程、
    /// 也不额外重启；已经建立的 9008 会话（含结果未确认的进入尝试）同样先同步取消本次关闭，
    /// 再询问是否显式退出维护。只有真实核对返回安卓之后才会再次关闭窗口。
    /// </summary>
    private async void OnInternalInstallClosing(object? sender, CancelEventArgs e)
    {
        // 读卡器提升重启最优先：UAC 已发起但新窗口尚未被接受时，同步取消本次关闭。
        // 提升被接受后会在 Close 前清掉自己的待定旗标，这里不会拦截那次关闭；
        // 其它维护 / 内部安装的取消策略不受影响。
        if (_tfReaderElevationPending && !_tfReaderRelaunchApproved)
        {
            e.Cancel = true;
            return;
        }

        // TF 卡安装优先：关闭闸门由 TF 自己的异步关闭处理接管；未批准则同步取消本次关闭。
        if (IsModernTfInstallMode)
        {
            if (_tfInstallCloseApproved || IsTfTabletCloseApproved)
            {
                return;
            }

            if (_busy
                || _tfInstallOperationActive
                || HasInternalInstallLiveEdlState
                || HasAnyPreparedModernTfInstall
                || HasUnresolvedModernTfInstallState)
            {
                // 必须先同步取消本次关闭，再等待 TF 自己的确认流程。
                e.Cancel = true;
                await HandleModernTfInstallClosingAsync();
                return;
            }
        }

        // 现代卸载优先：由卸载自己的异步关闭闸门接管；未批准则同步取消本次关闭。
        // 父级 async void 关闭处理必须先同步取消再等待；已批准的递归 Close 不再被通用安装关闭拦截。
        if (IsModernUserdataUninstallMode)
        {
            if (_userdataUninstallCloseApproved)
            {
                return;
            }

            if (_userdataUninstallOperationActive
                || _busy
                || HasInternalInstallLiveEdlState
                || _userdataUninstallBackend is not null)
            {
                e.Cancel = true;
                await HandleModernUserdataUninstallClosingAsync();
                return;
            }
        }

        // 维护模式优先：由维护自己的异步关闭闸门接管；未批准则同步取消本次关闭。
        if (IsBootMaintenanceMode)
        {
            // 已经批准过的递归 Close 直接放行，绝不再取消、不再弹窗（否则永远关不掉）。
            if (_bootMaintenanceCloseApproved)
            {
                return;
            }

            // 自己 / 共享的任何活动操作：一律阻止关闭，等当前操作返回。
            if (_bootMaintenanceOperationActive || _internalInstallOperationActive)
            {
                e.Cancel = true;
                SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.WaitForReturn"));
                return;
            }

            // 未知写入 / 未知复位 / 进入 9008 但没有客户端：只有显式警告（默认「否」）
            // 才允许仅关闭窗口；不复位、不释放文件，先立起批准旗标再递归 Close。
            if (HasUnconfirmedBootMaintenanceWrite
                || HasUnknownBootMaintenanceReset
                || (HasInternalInstallLiveEdlState && _internalInstallEdlClient is null))
            {
                e.Cancel = true;

                if (_bootMaintenanceExitPromptActive)
                {
                    return;
                }

                _bootMaintenanceExitPromptActive = true;
                try
                {
                    var answer = MessageBox.Show(
                        this,
                        T("Dynamic.BootMaintenance.Exit.CloseUnconfirmedBody"),
                        T("Dynamic.BootMaintenance.Exit.ConfirmTitle"),
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning,
                        MessageBoxResult.No);

                    if (answer != MessageBoxResult.Yes)
                    {
                        return;
                    }

                    _bootMaintenanceCloseApproved = true;
                    Close();
                }
                finally
                {
                    _bootMaintenanceExitPromptActive = false;
                }

                return;
            }

            // 已完成或预写入：走统一的维护离开确认（默认「否」），批准后放行关闭。
            e.Cancel = true;

            if (_bootMaintenanceExitPromptActive)
            {
                return;
            }

            _bootMaintenanceExitPromptActive = true;
            try
            {
                if (!await ConfirmLeaveBootMaintenanceAsync())
                {
                    return;
                }

                ResetBootMaintenanceUiState();
                _bootMaintenanceCloseApproved = true;
                Close();
            }
            finally
            {
                _bootMaintenanceExitPromptActive = false;
            }

            // 已批准的维护关闭到此结束，绝不进入旧安装关闭流程。
            return;
        }

        // 真实执行已经开始：关闭策略完全由执行侧接管，绝不进入旧的维护重置流程。
        if (TryHandleInternalInstallExecutionClosing(e))
        {
            return;
        }

        if (_internalInstallOperationActive)
        {
            e.Cancel = true;
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.WaitForReturn"));
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.WaitCurrentOperation"));
            return;
        }

        if (!HasInternalInstallLiveEdlState)
        {
            return;
        }

        // 必须同步取消这次关闭，再等待用户确认；默认「否」，不做任何改动。
        e.Cancel = true;

        if (_internalInstallExitClosePromptActive)
        {
            return;
        }

        _internalInstallExitClosePromptActive = true;
        try
        {
            if (!await ConfirmExitInternalInstallMaintenanceAsync())
            {
                return;
            }

            // 会话已经在真实核对通过后结束；再次关闭不会重复弹出退出确认。
            Close();
        }
        finally
        {
            _internalInstallExitClosePromptActive = false;
        }
    }

    // ---------- 设备列表 ----------

    /// <summary>按真实设备列表重建下拉框，条目只带设备对象；旧选择仍在列表里时才恢复。</summary>
    private void PopulateInternalInstallDeviceChoices(
        IReadOnlyList<ConnectedDevice> devices,
        string? previousSerial)
    {
        _internalInstallDeviceChoices = devices;
        if (!_ready)
        {
            return;
        }

        _suppressInternalInstallDeviceSelection = true;
        try
        {
            InternalInstallDevicesCombo.Items.Clear();
            foreach (var device in devices)
            {
                var item = new ComboBoxItem { Tag = device };
                SetContent(
                    item,
                    "Dynamic.DeviceEntry",
                    device.Serial,
                    M(ConnectionStateKey(device.ConnectionState)));
                InternalInstallDevicesCombo.Items.Add(item);
            }

            var index = -1;
            if (devices.Count == 1)
            {
                // 只有一台时没有可挑的余地；多台设备一律不预选。
                index = 0;
            }
            else if (!string.IsNullOrWhiteSpace(previousSerial))
            {
                for (var candidate = 0; candidate < devices.Count; candidate++)
                {
                    if (string.Equals(devices[candidate].Serial, previousSerial, StringComparison.Ordinal))
                    {
                        index = candidate;
                        break;
                    }
                }
            }

            InternalInstallDevicesCombo.SelectedIndex = index;
        }
        finally
        {
            _suppressInternalInstallDeviceSelection = false;
        }

        UpdateInternalInstallDeviceSelector();
    }

    /// <summary>只有真实列出了设备时才显示并启用选择框。</summary>
    private void UpdateInternalInstallDeviceSelector()
    {
        if (!_ready)
        {
            return;
        }

        var visibility = _internalInstallDeviceChoices.Count > 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        InternalInstallDevicesLabel.Visibility = visibility;
        InternalInstallDevicesCombo.Visibility = visibility;
    }

    // ---------- 结果渲染 ----------

    /// <summary>把真实检查结果写进字段：型号 / 序列号 / 固件 / 引导锁全部来自返回事实。</summary>
    private void RenderInternalInstallDeviceCheck(InternalDeviceCheckResult result)
    {
        if (!_ready)
        {
            return;
        }

        var identity = result.Android?.Identity;
        var firmware = identity?.Firmware;

        SetText(InternalInstallModelText, "Dynamic.RawValue", Placeholder(identity?.Model));
        SetText(
            InternalInstallSerialText,
            "Dynamic.RawValue",
            Placeholder(identity?.Serial ?? result.FastbootSerial));
        SetText(
            InternalInstallFirmwareText,
            "Dynamic.RawValue",
            Placeholder(firmware?.DisplayId ?? firmware?.BuildFingerprint));
        SetText(InternalInstallBootloaderText, BootStateKey(result.FastbootLockState));

        if (result.Cancelled)
        {
            SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Cancelled"));
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.Cancelled"));
            return;
        }

        if (!result.Succeeded)
        {
            SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetInternalInstallCheckProgress(
                M(
                    "Dynamic.InternalInstall.Check.FailedStage",
                    M(InternalInstallCheckStageKey(result.FailedStage))));

            var error = Placeholder(result.Error);
            SetInternalInstallCheckStatus(
                result.AndroidReturn == AndroidReturnState.Unconfirmed
                    ? M("Dynamic.InternalInstall.Check.ReturnUnconfirmed", error)
                    : M("Dynamic.InternalInstall.Check.Failed", error));
            return;
        }

        SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Progress.Completed"));

        if (HasCheckedInternalInstallDevice)
        {
            SetText(InternalInstallRouteText, "Dynamic.InternalInstall.Check.RoutePassed");
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.Passed"));
            return;
        }

        // 检查本身通过，但返回的安卓身份信息不完整：如实说明，备份门槛保持关闭。
        SetText(InternalInstallRouteText, "Dynamic.InternalInstall.Check.RouteUnavailable");
        SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.ProfileUnavailable"));
    }

    /// <summary>把第 0 步的全部结论字段重写成占位值（语言切换后不会复活旧结果）。</summary>
    private void RenderInternalInstallCheckPlaceholders()
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallModelText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallSerialText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallFirmwareText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallBootloaderText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCheckProgressText, "Static.InternalInstall.Check.ProgressInitial");
        SetInternalInstallCheckStatus(M("Static.InternalInstall.Check.StatusInitial"));
        RenderInternalInstallPower();
    }

    /// <summary>
    /// 清空检查结论。仅在检查不在进行中时调用；<paramref name="clearSelection"/> 为 true 时
    /// 连真实设备列表一起清掉，否则保留用户已经选中的那一行。
    /// </summary>
    private void ResetInternalInstallCheckState(bool clearSelection)
    {
        // 真实写入已经开始且尚未完成：拒绝清空检查结论与派生对象，现场必须保留到真实完成。
        if (HasInternalInstallExecutionStarted && !IsCompletedInternalInstallExecution)
        {
            return;
        }

        if (_internalInstallOperationActive)
        {
            return;
        }

        // 维护受保护状态（未确认写入 / 未知复位 / 已发起执行）同样拒绝清空。
        if (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
        {
            return;
        }

        // TF 卡安装受保护状态或仍持有 TF 会话时拒绝清空：绝不先丢弃租约再做异步释放。
        if (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
        {
            return;
        }

        // 维护模式的预写入准备在检查 / 备份结论作废之前先一起作废。
        if (IsBootMaintenanceMode)
        {
            InvalidateBootMaintenancePreparation();
        }

        _internalInstallDeviceCheck = null;
        _internalInstallPower = null;
        // 检查结论作废时，共享安卓读取事实一起作废；真实 9008 历史绑定不受影响。
        ClearSharedAndroidIdentity();

        // 检查结论被作废时，依赖它的备份门槛、容量规划、确认对象与系统包也一起作废；
        // 已有 9008 会话与工具链不受影响。
        InvalidateInternalInstallAllocation(clearPackage: true);
        ReleaseInternalInstallBackupObject();
        RenderInternalInstallBackupDetail();
        SetInternalInstallBackupProgressIndeterminate(false);

        if (clearSelection)
        {
            _internalInstallDeviceChoices = Array.Empty<ConnectedDevice>();
            if (_ready)
            {
                _suppressInternalInstallDeviceSelection = true;
                try
                {
                    InternalInstallDevicesCombo.Items.Clear();
                    InternalInstallDevicesCombo.SelectedIndex = -1;
                }
                finally
                {
                    _suppressInternalInstallDeviceSelection = false;
                }
            }

            UpdateInternalInstallDeviceSelector();
        }

        RenderInternalInstallCheckPlaceholders();
    }

    // ---------- 电量采样 ----------

    /// <summary>
    /// 检查确认回到安卓后，只读一次 <c>dumpsys battery</c>。读不到就保持未知，
    /// 绝不猜测百分比或外部供电；调用方取消照常向外传播。
    /// </summary>
    private async Task<EdlPowerSample?> CaptureInternalInstallPowerAsync(
        string adbPath,
        string serial,
        CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(adbPath) || string.IsNullOrWhiteSpace(serial))
        {
            return new EdlPowerSample(null, null, default);
        }

        try
        {
            var command = new ProcessCommand(
                adbPath,
                new[] { "-s", serial, "shell", "dumpsys", "battery" },
                TimeSpan.FromSeconds(10));
            var result = await _runner.RunAsync(command, token);
            return result.ExitCode == 0
                ? ParseEdlPower(result.StandardOutput)
                : new EdlPowerSample(null, null, default);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return new EdlPowerSample(null, null, default);
        }
    }

    /// <summary>电量行只描述这一次安卓采样；没有采样时明确写未知。</summary>
    private void RenderInternalInstallPower()
    {
        if (!_ready)
        {
            return;
        }

        var sample = _internalInstallPower;
        if (sample is null)
        {
            SetText(InternalInstallPowerText, "Dynamic.InternalInstall.Power.Unknown");
            return;
        }

        // 这些参数保存的是消息而不是已经格式化好的文字，切换语言后会按新语言重新拼装；
        // 只有真实读数（百分比数字、时间）保持字符串形态。
        object percent = sample.Percentage is int value
            ? string.Format(CultureInfo.CurrentCulture, "{0}%", value)
            : M("Dynamic.InternalInstall.Power.PercentUnknown");
        object external = sample.ExternalPower switch
        {
            true => M("Dynamic.UninstallFlow.Common.Yes"),
            false => M("Dynamic.UninstallFlow.Common.No"),
            _ => M("Dynamic.InternalInstall.Power.ExternalUnknown"),
        };
        object time = sample.CapturedAt == default
            ? M("Dynamic.InternalInstall.Power.TimeUnknown")
            : sample.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);

        SetText(InternalInstallPowerText, "Dynamic.InternalInstall.Power.Sample", percent, external, time);
    }

    // ---------- 状态与进度 ----------

    private void SetInternalInstallCheckStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallCheckStatusText, message);
    }

    private void SetInternalInstallCheckProgress(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallCheckProgressText, message);
    }

    private static string Placeholder(string? value) =>
        string.IsNullOrWhiteSpace(value) ? UnknownValue : value.Trim();

    /// <summary>Core 的九个进度阶段各自对应的显示文案；进度只显示，绝不参与门槛。</summary>
    private static string InternalInstallCheckStageKey(InternalDeviceCheckStage? stage) => stage switch
    {
        InternalDeviceCheckStage.ReadingAndroid => "Dynamic.InternalInstall.Check.Progress.ReadingAndroid",
        InternalDeviceCheckStage.EnteringFastboot => "Dynamic.InternalInstall.Check.Progress.EnteringFastboot",
        InternalDeviceCheckStage.WaitingFastboot => "Dynamic.InternalInstall.Check.Progress.WaitingFastboot",
        InternalDeviceCheckStage.CheckingBootloader => "Dynamic.InternalInstall.Check.Progress.CheckingBootloader",
        InternalDeviceCheckStage.ReturningAndroid => "Dynamic.InternalInstall.Check.Progress.ReturningAndroid",
        InternalDeviceCheckStage.WaitingAndroid => "Dynamic.InternalInstall.Check.Progress.WaitingAndroid",
        InternalDeviceCheckStage.WaitingUsbAuthorization => "Dynamic.InternalInstall.Check.Progress.WaitingUsbAuthorization",
        InternalDeviceCheckStage.VerifyingAndroid => "Dynamic.InternalInstall.Check.Progress.VerifyingAndroid",
        _ => "Dynamic.InternalInstall.Check.Progress.Completed",
    };
}
