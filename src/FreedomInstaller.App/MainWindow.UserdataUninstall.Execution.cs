using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载（现代四步向导）执行与收尾层：真实执行 <see cref="UninstallWorkflow.RunAsync"/>、
/// 一次复位、离开确认与关闭保护。写入全部由 Core 完成；这里只按真实返回状态渲染，
/// 绝不重发复位、不查询安卓启动、不伪造完成。
/// <para>
/// 运行期字段全部以 <c>_userdataUninstall</c> 为前缀；完成只认
/// 「Success + AwaitingFactoryReset + 一次复位且被接受」，进度只用于显示。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>最近一次真实执行结果；null 表示尚未执行。</summary>
    private UninstallResult? _userdataUninstallLastResult;

    /// <summary>是否已真实发起过执行；置位后执行按钮不再开放，绝无重试。</summary>
    private bool _userdataUninstallExecuteAttempted;

    /// <summary>执行抛出非取消的意外异常：结果未知，现场与证据全部保留。</summary>
    private bool _userdataUninstallExecutionUnknown;

    /// <summary>复位是否已发起（含结果未知）；置位后绝不再发第二次。</summary>
    private bool _userdataUninstallResetAttempted;

    /// <summary>复位命令是否被设备真实接受。</summary>
    private bool _userdataUninstallResetAcked;

    /// <summary>真实完成：Success + AwaitingFactoryReset + 复位被接受，三者齐备才置位。</summary>
    private bool _userdataUninstallCompleted;

    /// <summary>关闭流程已批准：递归 Close 直接放行。</summary>
    private bool _userdataUninstallCloseApproved;

    /// <summary>关闭确认弹窗进行中，避免重复弹框或递归。</summary>
    private bool _userdataUninstallClosePromptActive;

    /// <summary>完成弹窗只显示一次。</summary>
    private bool _userdataUninstallCompletionToastShown;

    /// <summary>最近一次进度回调报告的阶段；只用于显示，绝不参与门槛。</summary>
    private UninstallStage? _userdataUninstallDisplayStage;

    /// <summary>最近一次存储的退出状态前台文案；刷新与换语言后据此稳定显示，绝不被已准备覆盖。</summary>
    private UiMessage? _userdataUninstallExitStatus;

    /// <summary>
    /// 卸载自身的未解决状态：结果未知、复位已发起但未确认、或真实结果声明数据可能已被擦除。
    /// 处于未解决时不允许离开、换功能或清空现场。
    /// </summary>
    private bool HasUnresolvedModernUserdataUninstallState =>
        !_userdataUninstallCompleted
        && (_userdataUninstallExecutionUnknown
            || (_userdataUninstallResetAttempted && !_userdataUninstallResetAcked)
            || _userdataUninstallLastResult?.DataMayBeErased == true);

    /// <summary>
    /// 执行按钮的唯一事实谓词：真实准备完成、仍在第 3 步、空闲、尚未执行且未处于未解决状态，
    /// 并且确认页自己的风险勾选真实勾上。绝不使用旧三页的隐藏 RiskCheck。
    /// </summary>
    private bool CanExecuteModernUserdataUninstall() =>
        _ready
        && IsModernUserdataUninstallMode
        && _internalInstallStep == 3
        && !_busy
        && !_userdataUninstallOperationActive
        && !_userdataUninstallExecuteAttempted
        && !_userdataUninstallCompleted
        && !_userdataUninstallResetAttempted
        && HasBootMaintenanceDeviceProof
        && !HasUnresolvedModernUserdataUninstallState
        && BootMaintenanceRiskCheck.IsChecked == true
        && _userdataUninstallBackend is not null
        && _userdataUninstallMenu is not null
        && _userdataUninstallOriginal is not null
        && _internalInstallBackup is not null
        && _internalInstallEdlClient is not null
        && _internalInstallEdlEntry is not null;

    /// <summary>卸载进度阶段的纯显示文案；旧 boot 还原枚举值不属于本流程，一律归入开始阶段。</summary>
    private static string UserdataUninstallStageKey(UninstallStage stage) => stage switch
    {
        UninstallStage.ValidateRestoreInputs => "Dynamic.UserdataUninstall.Runtime.Stage.ValidateRestoreInputs",
        UninstallStage.ReclaimAndroidSpace => "Dynamic.UserdataUninstall.Runtime.Stage.ReclaimAndroidSpace",
        UninstallStage.InitializeAndroid => "Dynamic.UserdataUninstall.Runtime.Stage.InitializeAndroid",
        UninstallStage.AwaitingFactoryReset => "Dynamic.UserdataUninstall.Runtime.Stage.AwaitingFactoryReset",
        _ => "Dynamic.UserdataUninstall.Runtime.Stage.Preflight",
    };

    /// <summary>
    /// 退出状态的唯一前台写入点：存储文案并同时写入维护确认状态与安装退出状态两处，
    /// 刷新与换语言后由存储值稳定重放，绝不被「已准备」覆盖。
    /// </summary>
    private void SetModernUserdataUninstallExitStatus(UiMessage message)
    {
        _userdataUninstallExitStatus = message;
        SetText(InternalInstallExitMaintenanceStatusText, message);
        SetText(BootMaintenanceConfirmStatusText, message);
    }

    // ---------- 真实执行 ----------

    /// <summary>
    /// 六模式路由的卸载执行入口：先展示真实准备结果与电量记录的默认「否」确认，
    /// 确认后把执行交给 Core，成功到达等待复位时再发送一次复位。绝不重试、不查询安卓。
    /// </summary>
    private async Task ExecuteModernUserdataUninstallAsync()
    {
        if (!CanExecuteModernUserdataUninstall())
        {
            return;
        }

        // 开始新一次真实执行前先清掉上一次的退出状态，避免旧文案残留。
        _userdataUninstallExitStatus = null;

        var backend = _userdataUninstallBackend!;
        var client = _internalInstallEdlClient!;
        var fresh = _internalInstallBackup!;
        var entry = _internalInstallEdlEntry!;
        var inputs = backend.Inputs;
        if (inputs is null)
        {
            return;
        }

        // 电量只读已有安卓采样（可能不存在）；9008 下明确说明读不到实时电量。
        RenderInternalInstallPower();
        var powerLine = InternalInstallPowerText.Text;

        var retained = inputs.Record.BoardBackupPartUuid is not null
            ? T("Dynamic.UserdataUninstall.RetainedBackup") + "\n"
            : string.Empty;
        var body = T(
            "Dynamic.UserdataUninstall.Runtime.ConfirmBody",
            inputs.Identity.Model,
            inputs.Identity.Serial,
            FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)),
            FormatBytes(inputs.Plan.RestoredAndroidBytes),
            DeletedPartitionExtents(inputs),
            retained,
            fresh.DirectoryPath,
            _userdataUninstallOriginal?.DirectoryPath ?? UnknownValue,
            backend.BackupDirectory,
            powerLine);

        // 追加真实分区槽位清单：与实际 View 相同的键与字段，逐槽一行。
        var slotLines = new System.Collections.Generic.List<string>();
        foreach (var slot in _userdataUninstallMenu!.Slots)
        {
            // 与实际 View 同源：Candidate 为 null 表示该槽位不写入；SourceSlot 永远是真实 a/b。
            slotLines.Add(slot.Candidate is null
                ? T("Dynamic.UserdataUninstall.SlotKeep", slot.Slot)
                : T("Dynamic.UserdataUninstall.SlotWriteDefault", slot.Slot, slot.SourceSlot));
        }

        if (slotLines.Count > 0)
        {
            body += "\n" + string.Join("\n", slotLines);
        }

        var answer = MessageBox.Show(
            this,
            body,
            T("Dynamic.UserdataUninstall.Runtime.ConfirmTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        // 确认后逐项复核捕获：模式、步骤、风险、引用与空闲状态任何一个变化都放弃执行。
        if (!CanExecuteModernUserdataUninstall()
            || !ReferenceEquals(_userdataUninstallBackend, backend)
            || !ReferenceEquals(_internalInstallEdlClient, client)
            || !ReferenceEquals(_internalInstallBackup, fresh)
            || !ReferenceEquals(_internalInstallEdlEntry, entry))
        {
            return;
        }

        _userdataUninstallExecuteAttempted = true;
        _userdataUninstallOperationActive = true;
        BootMaintenanceProgressBar.IsIndeterminate = true;

        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    var request = new UserdataUninstallRequest(
                        backend.Snapshot,
                        backend.PlanFingerprint,
                        string.Empty,
                        true);
                    request = request with { ConfirmationId = UninstallWorkflow.ConfirmationFor(request) };

                    var progress = new Progress<UninstallStage>(stage =>
                    {
                        // 迟到的回调在操作结束后被忽略；阶段只写显示，绝不改状态。
                        if (_closed
                            || !_userdataUninstallOperationActive)
                        {
                            return;
                        }

                        _userdataUninstallDisplayStage = stage;
                        SetModernUserdataUninstallExitStatus(
                            M("Dynamic.UserdataUninstall.Runtime.Active", M(UserdataUninstallStageKey(stage))));
                    });

                    SetModernUserdataUninstallExitStatus(
                        M("Dynamic.UserdataUninstall.Runtime.Active", M(UserdataUninstallStageKey(UninstallStage.Preflight))));

                    var result = await UninstallWorkflow.RunAsync(request, backend, progress, token);
                    _userdataUninstallLastResult = result;
                    _userdataUninstallDisplayStage = result.Stage;

                    if (result.Success && result.Stage == UninstallStage.AwaitingFactoryReset)
                    {
                        // 全部写入与读回校验已由 Core 完成：这里才有权发送唯一一次复位。
                        AppendLocalizedLog(M("Dynamic.UserdataUninstall.Runtime.LogSuccess"));
                        _userdataUninstallResetAttempted = true;
                        SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.Resetting"));
                        var reset = await client.ResetAsync(CancellationToken.None);
                        if (reset.CommandAccepted)
                        {
                            _userdataUninstallResetAcked = true;
                            _userdataUninstallCompleted = true;
                        }
                        else
                        {
                            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.ResetUnknown"));
                        }

                        return;
                    }

                    if (!string.IsNullOrWhiteSpace(result.Error))
                    {
                        AppendLocalizedLog(M("Dynamic.RawValue", result.Error));
                    }
                }
                catch (OperationCanceledException) when (!_userdataUninstallResetAttempted)
                {
                    // Core 约定：取消只发生在 Reclaim 之前，属于未开始删除的预写失败。
                    SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
                }
                catch (Exception exception)
                {
                    // 其他意外异常：结果未知，保留现场与证据，绝不复位、绝不重试。
                    _userdataUninstallExecutionUnknown = true;
                    AppendLocalizedLog(M(
                        "Dynamic.RawValue",
                        $"{exception.GetType().FullName}: {exception.Message}"));
                }
            });
        }
        finally
        {
            _userdataUninstallOperationActive = false;
            BootMaintenanceProgressBar.IsIndeterminate = false;
            RenderModernUserdataUninstallRuntimeStatus();
            RefreshModernUserdataUninstallActions();

            if (_userdataUninstallCompleted && !_userdataUninstallCompletionToastShown)
            {
                _userdataUninstallCompletionToastShown = true;
                MessageBox.Show(
                    this,
                    T("Dynamic.UserdataUninstall.Runtime.CompletionBody"),
                    T("Dynamic.UserdataUninstall.Runtime.CompletionTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
    }

    // ---------- 运行状态渲染 ----------

    /// <summary>
    /// 运行期状态的纯显示渲染：在通用「已准备」渲染之后调用，刷新与换语言都不会覆盖真实结局。
    /// 未执行时仍重放已存储的退出状态与未知复位状态，绝不写占位或伪造已准备。
    /// </summary>
    private void RenderModernUserdataUninstallRuntimeStatus()
    {
        if (!_ready || _closed || !IsModernUserdataUninstallMode)
        {
            return;
        }

        if (_userdataUninstallOperationActive)
        {
            BootMaintenanceProgressBar.IsIndeterminate = true;
            return;
        }

        if (_userdataUninstallCompleted)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.Completed"));
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 100;
            return;
        }

        var result = _userdataUninstallLastResult;
        if (result is { Success: true, Stage: UninstallStage.AwaitingFactoryReset })
        {
            // 写入校验完成但复位未被确认：如实说明，绝不写成完成。
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.VerifiedUnknownReset"));
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 100;
            return;
        }

        if (_userdataUninstallExecutionUnknown || result?.DataMayBeErased == true)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.UnresolvedFailure"));
            BootMaintenanceProgressBar.IsIndeterminate = false;
            return;
        }

        if (_userdataUninstallResetAttempted && !_userdataUninstallResetAcked && result is null)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.ResetUnknown"));
            BootMaintenanceProgressBar.IsIndeterminate = false;
            return;
        }

        if (_userdataUninstallExitStatus is { } storedStatus)
        {
            SetModernUserdataUninstallExitStatus(storedStatus);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            return;
        }

        if (_userdataUninstallExecuteAttempted)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
        }

        BootMaintenanceProgressBar.IsIndeterminate = false;
    }

    // ---------- 离开确认 ----------

    /// <summary>
    /// 离开现代卸载的唯一入口：完成/只读/未解决/活动四种情况分别处理。
    /// 预写入状态下先只读核对同一客户端，再发送唯一一次复位；探针失败不复位、不自动重试。
    /// </summary>
    private async Task<bool> ConfirmLeaveModernUserdataUninstallAsync(bool ask = true)
    {
        if (_busy || _userdataUninstallOperationActive)
        {
            return false;
        }

        if (_userdataUninstallCompleted)
        {
            // 已完成：只释放自己的计划与共享资源，绝不发送任何设备调用。
            InvalidateModernUserdataUninstallPreparation();
            DisposeInternalInstallResources();
            return true;
        }

        if (HasUnresolvedModernUserdataUninstallState)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.UnresolvedFailure"));
            return false;
        }

        // 预写入离开时已确认复位被接受（尝试过且已确认）：初始守卫已保证空闲，
        // 只释放计划与共享资源，不发探针/复位，也绝不解锁未知复位。
        if (_userdataUninstallResetAttempted
            && _userdataUninstallResetAcked
            && !_busy)
        {
            InvalidateModernUserdataUninstallPreparation();
            DisposeInternalInstallResources();
            return true;
        }

        if (!HasInternalInstallLiveEdlState)
        {
            // 没有真实 9008 会话：只释放自己的只读计划。
            InvalidateModernUserdataUninstallPreparation();
            return true;
        }

        var client = _internalInstallEdlClient;
        var entry = _internalInstallEdlEntry;
        if (client is null)
        {
            // 已进入 9008 却没有客户端：入口未知，不能假装已清理。
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.EntryUnknown"));
            return false;
        }

        if (ask)
        {
            var answer = MessageBox.Show(
                this,
                T("Dynamic.UserdataUninstall.Exit.ConfirmBody"),
                T("Dynamic.UserdataUninstall.Exit.ConfirmTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);

            if (answer != MessageBoxResult.Yes)
            {
                return false;
            }
        }

        // 退出同意后无条件声明自己的活动与忙碌，先全局刷新动作再碰设备，避免其他动作/主题/语言重入。
        // （初始守卫已保证空闲，这里不会清掉其他动作的忙碌。）
        _userdataUninstallOperationActive = true;
        _busy = true;
        RefreshActions();
        var acknowledged = false;
        try
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.Probing"));
            try
            {
                await client.ProbeAsync(0, false, CancellationToken.None);
            }
            catch (Exception exception)
            {
                // 探针失败：记录真实诊断到折叠日志；不复位、不自动重试，退出状态前台清晰可见。
                AppendLocalizedLog(M("Dynamic.RawValue", exception.Message));
                SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ProbeFailed"));
                return false;
            }

            // 探针通过后核对仍是同一会话、同一入口；变化时放弃离开，不复位。
            if (_closed
                || !IsModernUserdataUninstallMode
                || !ReferenceEquals(_internalInstallEdlClient, client)
                || !ReferenceEquals(_internalInstallEdlEntry, entry))
            {
                return false;
            }

            if (_userdataUninstallResetAttempted)
            {
                // 复位已发起过：绝不重发第二次设备命令。
                SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
                return false;
            }

            _userdataUninstallResetAttempted = true;
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.Resetting"));
            var reset = await client.ResetAsync(CancellationToken.None);
            if (reset.CommandAccepted)
            {
                _userdataUninstallResetAcked = true;
                acknowledged = true;
                SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetAccepted"));
            }
            else
            {
                // 设备未接受：结果未知，保留现场，绝不再次发送。
                SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
            }
        }
        catch (OperationCanceledException)
        {
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
        }
        catch (Exception exception)
        {
            AppendLocalizedLog(M("Dynamic.RawValue", exception.Message));
            SetModernUserdataUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
        }
        finally
        {
            // 只清自己的忙碌/活动；窗口未关闭时全局刷新，保证所有动作与主题/语言控件不残留禁用。
            _userdataUninstallOperationActive = false;
            _busy = false;

            if (!_closed)
            {
                RefreshActions();
            }
        }

        if (!acknowledged)
        {
            RenderModernUserdataUninstallRuntimeStatus();
            RefreshModernUserdataUninstallActions();
            return false;
        }

        // 已知复位被接受：先清活动旗标（finally），再走受保护检查的释放。
        InvalidateModernUserdataUninstallPreparation();
        DisposeInternalInstallResources();
        return true;
    }

    // ---------- 关闭保护 ----------

    /// <summary>
    /// 关闭窗口时的卸载分支：活动操作一律同步取消；未解决写入 / 未知复位 / 进入却无客户端时
    /// 只提供「仅关闭窗口」的默认「否」警告并保留全部现场；完成或只读已解决时走离开确认后放行。
    /// </summary>
    private async Task HandleModernUserdataUninstallClosingAsync()
    {
        if (_userdataUninstallClosePromptActive)
        {
            return;
        }

        if (_busy || _userdataUninstallOperationActive)
        {
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.UserdataUninstall.Runtime.WaitForReturn"));
            return;
        }

        var unresolved = HasUnresolvedModernUserdataUninstallState;
        var liveNoClient = HasInternalInstallLiveEdlState && _internalInstallEdlClient is null;

        if (unresolved || liveNoClient)
        {
            _userdataUninstallClosePromptActive = true;
            try
            {
                var answer = MessageBox.Show(
                    this,
                    T("Dynamic.UserdataUninstall.Exit.CloseUnconfirmedBody"),
                    T("Dynamic.UserdataUninstall.Exit.CloseUnconfirmedTitle"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);

                if (answer != MessageBoxResult.Yes)
                {
                    return;
                }

                _userdataUninstallCloseApproved = true;
                Close();
            }
            finally
            {
                _userdataUninstallClosePromptActive = false;
            }

            return;
        }

        // 已完成或只读已解决：先走统一离开（完成时不发任何设备调用），再批准关闭。
        _userdataUninstallClosePromptActive = true;
        try
        {
            if (!await ConfirmLeaveModernUserdataUninstallAsync())
            {
                return;
            }

            SafeResetModernUserdataUninstallState();
            _userdataUninstallCloseApproved = true;
            Close();
        }
        finally
        {
            _userdataUninstallClosePromptActive = false;
        }
    }

    /// <summary>
    /// 窗口关闭时只在自己的运行已解决（无活动、无未解决、无真实 9008 会话）时释放自有对象；
    /// 未解决现场完整保留 menu/original/backend 与临时、证据文件，绝不做清理。
    /// </summary>
    private void DisposeModernUserdataUninstallResourcesOnClose()
    {
        if (_userdataUninstallOperationActive
            || HasUnresolvedModernUserdataUninstallState
            || HasInternalInstallLiveEdlState)
        {
            return;
        }

        if (_userdataUninstallBackend is { } backend)
        {
            backend.Dispose();
            _userdataUninstallBackend = null;
        }

        if (_userdataUninstallMenu is { } menu)
        {
            menu.Dispose();
            _userdataUninstallMenu = null;
        }

        if (_userdataUninstallOriginal is { } original)
        {
            original.Dispose();
            _userdataUninstallOriginal = null;
        }
    }
}
