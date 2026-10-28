using System;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载流程的 9008 入口（N7A/N8A）：自动进入 9008 并确认端点，然后由只读准备读取分区与还原方案。
/// <para>
/// 进入前重新读取同一 USB 序列号的安卓身份与 SoC 序列号，并核对四代 .259 生产配置；
/// 成功后只记录真实的 <see cref="EdlEntryResult"/>，绝不把它当成 Firehose 就绪或还原完成的证据。
/// 分区读取、只读准备与执行由 N8A/N8B 接入（<see cref="PrepareEdlUninstallAsync"/>），
/// 执行只经一次确认后交给真实工作流，并只在成功后发送一次重置。
/// </para>
/// </summary>
public partial class MainWindow
{
    private EdlEntryResult? _uninstallEdlResult;

    private bool _uninstallEdlEntering;

    private UiMessage? _uninstallEdlStatus;

    /// <summary>只按设备身份判断是否支持 9008 维护；安卓上报的 BL 状态不参与。</summary>
    private static bool IsSupportedUninstallEdlIdentity(DeviceIdentity? identity)
    {
        return identity is not null
            && string.Equals(identity.Model, MaintenanceProfiles.Model, StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                identity.Firmware?.DisplayId,
                MaintenanceProfiles.AndroidBuild,
                StringComparison.Ordinal);
    }

    /// <summary>状态行优先显示本次操作的真实消息；否则按当前设备给出待检测 / 不支持 / 就绪。</summary>
    private UiMessage GetUninstallEdlMessage()
    {
        if (_uninstallEdlStatus is not null)
        {
            return _uninstallEdlStatus;
        }

        var identity = _identity;
        if (identity is null)
        {
            return M("Dynamic.UninstallFlow.Edl.NeedDevice");
        }

        if (!IsSupportedUninstallEdlIdentity(identity))
        {
            return M(
                "Dynamic.UninstallFlow.Edl.Unsupported",
                identity.Model,
                identity.Firmware?.DisplayId ?? UnknownValue);
        }

        return M("Dynamic.UninstallFlow.Edl.Ready");
    }

    /// <summary>只清本卡片的派生状态；释放只读准备对象，不删除用户文件或备份。</summary>
    private void ResetUninstallEdlState()
    {
        DisposeEdlUninstallState();
        _uninstallEdlResult = null;
        _uninstallEdlEntering = false;
        _uninstallEdlStatus = null;
        _uninstallEdlPower = null;
        _uninstallEdlResetAttempted = false;

        if (_ready)
        {
            SetText(UninstallEdlStatusText, GetUninstallEdlMessage());
            SetText(UninstallEdlPowerText, PowerMessage());
        }
    }

    /// <summary>
    /// 本卡片与相关控件的统一可用性入口。非卸载模式只收起本卡片并恢复「检查 BL」；
    /// 卸载模式下按真实 9008 连接与只读准备状态开门，未连接时保留确定性禁用，不回退 RAM 会话。
    /// </summary>
    private void RefreshUninstallEdlActions()
    {
        if (!_ready)
        {
            return;
        }

        var uninstall = CurrentModeTag() == "uninstall";
        UninstallEdlSection.Visibility = uninstall ? Visibility.Visible : Visibility.Collapsed;
        CheckBootloaderButton.Visibility = uninstall ? Visibility.Collapsed : Visibility.Visible;

        if (!uninstall)
        {
            // 非卸载模式恢复旧的 Recovery 说明；卸载模式下一律用 9008 专用说明，避免出现手动进模式的指引。
            SetText(UninstallRecoveryNoteText, "Dynamic.UninstallFlow.Transaction.RecoveryNote");
            return;
        }

        SetText(UninstallRecoveryNoteText, "Dynamic.UninstallFlow.EdlRecovery.Note");

        var protectedState = HasProtectedUninstallState;
        var supported = IsSupportedUninstallEdlIdentity(_identity);
        var connected = _uninstallEdlResult is not null;
        var prepared = _uninstallEdlBackend is not null
            && _uninstallInputs is not null
            && _uninstallPhase == UninstallUiPhase.Prepared
            && !_uninstallAttempted
            && !_uninstallEdlResetAttempted;
        var lockedByEntry = connected || _uninstallEdlEntering;

        EnterUninstallEdlButton.IsEnabled = !_busy
            && !protectedState
            && _transport is not null
            && supported
            && _uninstallEdlResult is null
            && !_uninstallEdlEntering;

        SetText(UninstallEdlStatusText, GetUninstallEdlMessage());
        SetText(UninstallEdlPowerText, PowerMessage());

        // 进入 9008 后，工具目录、检测与分区读取都不再属于本次流程；未进入时仍可正常准备工具。
        ToolsPathBox.IsEnabled = !_busy && !protectedState && !lockedByEntry;
        BrowseToolsButton.IsEnabled = !_busy && !protectedState && !lockedByEntry;
        DetectButton.IsEnabled = !_busy
            && !protectedState
            && _transport is not null
            && !lockedByEntry;
        DevicesCombo.IsEnabled = !_busy
            && !protectedState
            && _devices.Count > 0
            && !lockedByEntry;
        ReadLayoutButton.IsEnabled = !_busy
            && !protectedState
            && _transport is not null
            && _identity is not null
            && !lockedByEntry;

        var materialsLocked = _busy || protectedState || _uninstallAttempted;
        BrowseUninstallWorkRootButton.IsEnabled = !materialsLocked;
        ChangeUninstallWorkRootButton.IsEnabled = !materialsLocked;
        BrowseStockBackupButton.IsEnabled = !materialsLocked;
        BrowseInstallationRecordButton.IsEnabled = !materialsLocked;
        RestoreAssetsExpander.IsEnabled = !materialsLocked;
        LegacyRecordExpander.IsEnabled = !materialsLocked;
        ClearInstallationRecordButton.IsEnabled = !materialsLocked
            && (InstallationRecordBox.Text ?? string.Empty).Trim().Length > 0;

        // 只读准备只看真实 9008 入口与已选的两份原始 GPT；没有入口时不制造 RAM 会话或模拟就绪。
        PrepareUninstallButton.IsEnabled = connected
            && !_busy
            && !protectedState
            && !_uninstallAttempted
            && !string.IsNullOrWhiteSpace(_uninstallWorkRoot)
            && AllUninstallGptAssetsExist()
            && ((InstallationRecordBox.Text ?? string.Empty).Trim().Length == 0
                || _installationRecord is not null)
            && _uninstallPhase is UninstallUiPhase.Idle or UninstallUiPhase.Failed;

        NextButton.IsEnabled = connected
            && !_busy
            && !protectedState
            && (_page == 0 || (_page == 1 && prepared));
        NavCapacity.IsEnabled = connected && !_busy && !protectedState;
        NavConfirm.IsEnabled = prepared && !_busy && !protectedState;
        NavConnect.IsEnabled = !_busy && !protectedState;
        PrevButton.IsEnabled = !_busy && !protectedState && _page > 0;

        var riskAccepted = RiskCheck.IsChecked == true;
        ActionButton.IsEnabled = prepared && riskAccepted && !_busy;
        var reasonKey = ActionReasonKey();
        if (_uninstallPhase == UninstallUiPhase.Uncertain && _uninstallEdlBackend is not null)
        {
            // EDL 没有事务查询接口，不能用 HTTP 事务的「只能查询」话术。
            reasonKey = "Dynamic.UninstallFlow.EdlRestore.ActionUnknown";
        }

        ActionButton.ToolTip = T(reasonKey);
        SetText(ActionReasonText, reasonKey);

        RiskCheck.IsEnabled = !_busy
            && !_uninstallAttempted
            && _uninstallPhase is not (UninstallUiPhase.Running
                or UninstallUiPhase.Uncertain
                or UninstallUiPhase.AwaitingFactoryReset
                or UninstallUiPhase.Accepted);

        // 执行与验证由后续工单接线；这里只按真实后端与阶段开门，不提供第二条入口。
        VerifyUninstallAndroidButton.IsEnabled = !_busy
            && _uninstallEdlBackend is not null
            && _uninstallPhase == UninstallUiPhase.AwaitingFactoryReset;
    }

    /// <summary>
    /// 自动进入 9008：重新核对所选安卓身份与 SoC 序列号，然后只调用生产 <see cref="EdlEntry"/>。
    /// 任何失败都保留真实原因，不自动重试、不退回手动 Fastboot，也不宣称设备没有切换模式。
    /// </summary>
    private async void OnEnterUninstallEdl(object sender, RoutedEventArgs e)
    {
        var selected = _identity;
        var transport = _transport;

        if (!_ready
            || _busy
            || CurrentModeTag() != "uninstall"
            || HasProtectedUninstallState
            || !IsSupportedUninstallEdlIdentity(selected)
            || transport is null
            || _uninstallEdlResult is not null
            || selected is null)
        {
            return;
        }

        string expectedSerial = selected.Serial;
        string expectedModel = selected.Model;
        var cachedAndroid = _uninstallAndroid;

        InvalidateUninstallPreparedPlan();

        await RunBusyAsync(async token =>
        {
            try
            {
                var reading = M("Dynamic.UninstallFlow.Edl.Reading");
                _uninstallEdlStatus = reading;
                SetText(UninstallEdlStatusText, reading);
                SetText(ProgressStatusText, "Dynamic.UninstallFlow.Edl.Reading");
                RefreshUninstallEdlActions();
                UpdateSummary();

                var fresh = await transport.ReadAdbIdentityAsync(expectedSerial, token);
                if (!string.Equals(fresh.Serial, expectedSerial, StringComparison.Ordinal)
                    || !string.Equals(fresh.Model, expectedModel, StringComparison.OrdinalIgnoreCase)
                    || !IsSupportedUninstallEdlIdentity(fresh))
                {
                    throw new InvalidOperationException(
                        T("Dynamic.UninstallFlow.Edl.IdentityChanged"));
                }

                var android = await new MaintenanceEntry(
                    transport.AdbPath,
                    transport.FastbootPath,
                    _runner).ReadAndroidAsync(fresh, token);

                if (cachedAndroid is not null
                    && string.Equals(cachedAndroid.Identity.Serial, fresh.Serial, StringComparison.Ordinal)
                    && !string.Equals(cachedAndroid.SocSerial, android.SocSerial, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        T("Dynamic.UninstallFlow.Edl.SocMismatch"));
                }

                _identity = fresh;
                _uninstallAndroid = android;
                RenderBootloaderState(fresh.BootloaderState);

                // 只在这里读取一次进入 9008 之前的安卓电量；它不是 9008 状态下的实时测量。
                await CaptureEdlPowerAsync(transport.AdbPath, fresh.Serial, token);
                var power = PowerMessage();
                SetText(UninstallEdlPowerText, power);
                AppendLocalizedLog(power);

                _uninstallEdlEntering = true;
                var entering = M("Dynamic.UninstallFlow.Edl.Entering");
                _uninstallEdlStatus = entering;
                SetText(UninstallEdlStatusText, entering);
                SetText(ConnectionStatusText, "Dynamic.UninstallFlow.Edl.Connection.Entering");
                SetText(ProgressStatusText, "Dynamic.UninstallFlow.Edl.Connection.Entering");
                RefreshActions();
                RefreshUninstallEdlActions();
                UpdateSummary();

                var result = await new EdlEntry(
                    transport.AdbPath,
                    _runner,
                    new WindowsEdlEndpointDiscovery()).EnterAsync(android, token);

                if (_closed)
                {
                    return;
                }

                _uninstallEdlResult = result;
                _identity = result.AndroidIdentity.Identity;
                _uninstallAndroid = result.AndroidIdentity;
                RenderBootloaderState(result.AndroidIdentity.Identity.BootloaderState);

                var port = string.IsNullOrWhiteSpace(result.Endpoint.PortName)
                    ? M("Dynamic.UninstallFlow.Edl.UsbDevice")
                    : M("Dynamic.UninstallFlow.Edl.Port", result.Endpoint.PortName!);

                var connected = M(
                    "Dynamic.UninstallFlow.Edl.Connected",
                    result.AndroidIdentity.Identity.Model,
                    result.AndroidIdentity.Identity.Serial,
                    port);
                _uninstallEdlStatus = connected;
                SetText(UninstallEdlStatusText, connected);
                SetText(ConnectionStatusText, "Dynamic.UninstallFlow.Edl.Connection.Connected");
                SetText(ProgressStatusText, "Dynamic.UninstallFlow.Edl.Connection.Connected");
                AppendLocalizedLog(connected);
                AppendLocalizedLog(M(
                    "Dynamic.UninstallFlow.Edl.Log.Proof",
                    result.BusSerialHex,
                    result.Endpoint.DeviceInstanceId));
            }
            catch (OperationCanceledException)
            {
                var cancelled = M("Dynamic.UninstallFlow.Edl.Cancelled");
                _uninstallEdlStatus = cancelled;
                if (!_closed)
                {
                    SetText(UninstallEdlStatusText, cancelled);
                    SetText(ConnectionStatusText, "Dynamic.UninstallFlow.Edl.Connection.Unknown");
                    SetText(ProgressStatusText, "Dynamic.UninstallFlow.Edl.Cancelled");
                    AppendLocalizedLog(cancelled);
                }
            }
            catch (Exception exception)
            {
                var failed = M("Dynamic.UninstallFlow.Edl.Failed", exception.Message);
                _uninstallEdlStatus = failed;
                if (!_closed)
                {
                    SetText(UninstallEdlStatusText, failed);
                    SetText(ConnectionStatusText, "Dynamic.UninstallFlow.Edl.Connection.Unknown");
                    SetText(ProgressStatusText, "Dynamic.UninstallFlow.Edl.Failed", exception.Message);
                    AppendLocalizedLog(failed);
                }
            }
            finally
            {
                _uninstallEdlEntering = false;
            }
        });

        RefreshUninstallEdlActions();
        UpdateSummary();
    }
}
