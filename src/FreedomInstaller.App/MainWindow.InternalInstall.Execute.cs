using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」第 4 步的真实执行与只读验收复查。
/// <para>
/// 这里只做三件事：把用户已经核对过的确认页事实再问一次、把同一个真实后端的
/// <c>ExecuteAsync</c> 只调用一次、把后端自己的 <see cref="InternalInstallSnapshot"/> 与
/// <see cref="InternalInstallResult"/> 原样呈现。进度回调只用来显示「这个阶段已经验证到多少字节」，
/// 或后端报告的近似传输字节；两者都绝不是开始、成功或完成的证据，所有门槛与结论都只读后端快照。
/// </para>
/// <para>
/// 本文件不创建结果、不伪造阶段、不调用旧退出流程或重置命令，也不做自动重试、回滚或替换后端。
/// 关闭 / 退出入口只在本文件的执行状态标志之上放行或拒绝，从不通过关闭来取消写入。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>真实执行或只读复查正在等待后端返回；只表示界面忙，不是写入证据。</summary>
    private bool _internalInstallExecutionActive = false;

    /// <summary>本次后端实例是否已经提交过一次执行；只用于“同一实例不重复执行”，不是证据。</summary>
    private bool _internalInstallExecuteAttempted = false;

    /// <summary>已经提交过执行的后端实例；换新后端时据此重新允许一次执行。</summary>
    private InternalInstallBackend? _internalInstallAttemptedBackend;

    /// <summary>
    /// 只在用户按正常方式关闭窗口、且后端已到达真实终态后由关闭流程置位；本工单只读它，
    /// 让资源释放闸门知道「这次关闭是被批准的」，它绝不代表安装完成。
    /// </summary>
    private bool _internalInstallPostWriteCloseApproved = false;

    /// <summary>最后一条已经写入日志的进度指纹，避免同一阶段的高频回读刷满日志。</summary>
    private string? _internalInstallLastProgressLog;

    /// <summary>
    /// 已经弹出过「安装完成」提示的后端确认 ID；只在真实完成终态展示前写入，用于避免重复提示。
    /// 它只是提示去重标记，不是安装完成、系统启动或数据状态的证据。
    /// </summary>
    private string? _internalInstallCompletedNotificationId;

    /// <summary>
    /// 只在真实执行入口捕获的安装前复核失败原因（来自后端诊断或实际异常）。
    /// 仅用于界面说明，绝不参与任何权限、写入或完成判断；后端一旦真正开始写入就不会显示。
    /// </summary>
    private string? _internalInstallExecutionError;

    /// <summary>
    /// 当前实例是否已经真正开始过写入（以后端快照为唯一依据）。
    /// 注意：快照的 <c>ExecutionStarted</c> 只是准入标记，一次 Execute 被消费就会置位，
    /// 即使随后的本地 / 设备只读复核被拒绝也会为 true。只有写状态离开 <c>NoneIssued</c>
    /// 才代表真正发出过写入，因此这里用它区分「已准入」和「已写入」。
    /// </summary>
    private bool HasInternalInstallExecutionStarted
    {
        get
        {
            var snapshot = _internalInstallBackend?.Snapshot;
            return snapshot is not null
                && snapshot.ExecutionStarted
                && snapshot.WriteState != InternalInstallWriteState.NoneIssued;
        }
    }

    /// <summary>后端是否已经给出终态（成功、待验收、失败、取消或写入结果未知）。</summary>
    private bool HasTerminalInternalInstallExecution
    {
        get
        {
            var snapshot = _internalInstallBackend?.Snapshot;
            return snapshot is not null && snapshot.ExecutionStarted && snapshot.Outcome is not null;
        }
    }

    /// <summary>
    /// 只有后端快照自己报告「安装完成」或旧的「安卓与 Linux 验收均通过」时才算成功终态。
    /// 前者只表示实际写入、整段回读与一次重启请求都已被接受，不代表任何系统已经启动。
    /// </summary>
    private bool IsCompletedInternalInstallExecution
    {
        get
        {
            var snapshot = _internalInstallBackend?.Snapshot;
            return snapshot is not null
                && snapshot.ExecutionStarted
                && snapshot.Outcome is InternalInstallOutcome.Completed
                    or InternalInstallOutcome.InstallationCompleted;
        }
    }

    /// <summary>
    /// 只读复查的唯一门槛：真实后端、写入与回读全部通过、仍停在三种待验收结局之一，且界面空闲。
    /// 进度回调、勾选框与上一次返回值都不参与判断。
    /// </summary>
    private bool CanRecheckInternalInstallAcceptance
    {
        get
        {
            var backend = _internalInstallBackend;
            if (backend is null || _internalInstallExecutionActive || _internalInstallOperationActive)
            {
                return false;
            }

            var snapshot = backend.Snapshot;
            if (!snapshot.ExecutionStarted || snapshot.WriteState != InternalInstallWriteState.AllVerified)
            {
                return false;
            }

            return snapshot.Outcome
                is InternalInstallOutcome.AwaitingAndroidInitialization
                or InternalInstallOutcome.AwaitingUsbAuthorization
                or InternalInstallOutcome.AwaitingLinuxFirstBoot;
        }
    }

    /// <summary>当前后端实例是否已经提交过执行（换新后端后自动失效）。</summary>
    private bool HasAttemptedCurrentInternalInstallBackend =>
        _internalInstallExecuteAttempted
        && ReferenceEquals(_internalInstallBackend, _internalInstallAttemptedBackend);

    // ---------- 事件入口 ----------

    /// <summary>
    /// 底栏唯一的执行分发：普通三页向导原样交给 <c>OnExecuteUninstall</c>，
    /// 内部存储四步向导走本文件自己的执行入口。
    /// </summary>
    private async void OnExecuteSelectedWorkflow(object sender, RoutedEventArgs e)
    {
        await DispatchSelectedWorkflowAsync(sender, e);
    }

    /// <summary>
    /// 只读的「重新检查」：同一个真实后端上再跑一次 <c>CheckAcceptanceAsync</c>，
    /// 不执行写入、不新建后端、不发重置命令，也不代替用户在平板上授权。
    /// </summary>
    private async void OnRecheckInternalInstallAcceptance(object sender, RoutedEventArgs e)
    {
        var backend = _internalInstallBackend;
        if (!_ready
            || !IsInternalInstallMode
            || _busy
            || _internalInstallExecutionActive
            || _internalInstallOperationActive
            || backend is null
            || !CanRecheckInternalInstallAcceptance)
        {
            return;
        }

        _internalInstallOperationActive = true;
        // 只读复查同样是一次真实后端调用：界面进度与关闭闸门必须把它当作执行中，但它不是写入证据。
        _internalInstallExecutionActive = true;
        AppendLocalizedLog(M("Dynamic.InternalInstall.Execution.Log.RecheckStarted"));

        try
        {
            await RunBusyAsync(async cancellationToken =>
            {
                // Progress<T> 在构造函数所在线程（界面线程）上投递回调，界面语言切换后仍按当前语言重绘。
                var progress = new Progress<InternalInstallProgress>(RenderInternalInstallProgress);

                try
                {
                    await backend.CheckAcceptanceAsync(progress, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    AppendLocalizedLog(M("Dynamic.InternalInstall.Execution.Log.Cancelled"));
                }
                catch (Exception exception)
                {
                    AppendLocalizedLog(
                        M("Dynamic.InternalInstall.Execution.Log.Exception", exception.Message));
                }
                finally
                {
                    AppendInternalInstallResultFacts(backend);
                    RenderInternalInstallExecutionState();
                }
            });
        }
        finally
        {
            _internalInstallOperationActive = false;
            _internalInstallExecutionActive = false;
            RenderInternalInstallExecutionState();
            RefreshActions();
        }
    }

    /// <summary>
    /// 真实执行开始后的唯一关闭策略。返回 false 只表示后端快照还没有开始执行，
    /// 调用方继续使用原有的只读 / 维护退出逻辑；返回 true 表示本次关闭已经由这里决定。
    /// <para>
    /// 执行中的操作一律同步拒绝关闭，绝不通过关闭来取消正在进行的写入；写入与回读全部通过、
    /// 只剩启动验收，或后端已经报告安装完成时，允许正常关闭且不额外确认；其他已开始的终态只询问一次，默认「否」。
    /// 关闭批准只放行资源释放，从不改写快照、结果或完成状态。
    /// </para>
    /// </summary>
    private bool TryHandleInternalInstallExecutionClosing(CancelEventArgs e)
    {
        var snapshot = _internalInstallBackend?.Snapshot;
        if (snapshot is null
            || !snapshot.ExecutionStarted
            || snapshot.WriteState == InternalInstallWriteState.NoneIssued)
        {
            // 仅被准入但从未发出写入的失败不应占用关闭逻辑，交回通用操作 / 只读退出处理。
            return false;
        }

        if (_internalInstallExecutionActive || _internalInstallOperationActive || _busy)
        {
            // 只拒绝并说明等待状态；不调用 Close / Reset / Cancel。
            e.Cancel = true;
            SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Execution.WaitCurrentOperation"));
            return true;
        }

        var postWritePending = snapshot.WriteState == InternalInstallWriteState.AllVerified
            && snapshot.Outcome
                is InternalInstallOutcome.AwaitingAndroidInitialization
                or InternalInstallOutcome.AwaitingUsbAuthorization
                or InternalInstallOutcome.AwaitingLinuxFirstBoot;

        // 新的安装完成结局与旧的验收通过结局都是成功终态，正常关闭不再重复确认。
        var postWriteSucceeded = snapshot.Outcome
            is InternalInstallOutcome.Completed
            or InternalInstallOutcome.InstallationCompleted;

        if (postWritePending || postWriteSucceeded)
        {
            // 页面已经说明写入及回读通过，正常关闭不再重复确认。
            _internalInstallPostWriteCloseApproved = true;
            return true;
        }

        if (_internalInstallPostWriteCloseApproved)
        {
            // 已经批准过的一次关闭（例如递归触发）：不再重复弹窗，也不撤销其他处理器设置的取消。
            return true;
        }

        var answer = MessageBox.Show(
            this,
            T("Dynamic.InternalInstall.Execution.CloseWarning.TerminalBody"),
            T("Dynamic.InternalInstall.Execution.CloseWarning.TerminalTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer == MessageBoxResult.Yes)
        {
            _internalInstallPostWriteCloseApproved = true;
            return true;
        }

        e.Cancel = true;
        return true;
    }

    /// <summary>
    /// 安装助手的关闭按钮：窗口没有任何正在执行的界面操作时才关闭自己；
    /// 真正的关闭策略（执行中阻止、未完成告警）由 <see cref="TryHandleInternalInstallExecutionClosing"/> 接管。
    /// </summary>
    private void OnCloseInternalInstallAssistant(object sender, RoutedEventArgs e)
    {
        if (_internalInstallExecutionActive || _internalInstallOperationActive)
        {
            return;
        }

        Close();
    }

    /// <summary>
    /// 风险勾选只刷新按钮可用性，不构成任何门槛结论；XAML 初始化期间不响应，避免重入。
    /// </summary>
    private void OnInternalInstallEraseRiskChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        RefreshActions();
    }

    // ---------- 真实执行 ----------

    /// <summary>
    /// 执行入口的唯一实现。<see cref="RunBusyAsync"/> 只调用一次，界面忙碌由它统一维护；
    /// 真正的取消与异常在本方法内部消化，避免通用查询措辞覆盖后端的写入事实。
    /// </summary>
    private async Task ExecuteInternalInstallAsync()
    {
        try
        {
            await ExecuteInternalInstallCoreAsync();
        }
        catch (Exception exception)
        {
            // 入口自身的异常同样只在尚未开始写入时作为可见原因；不猜测任何设备状态。
            if (!HasInternalInstallExecutionStarted)
            {
                _internalInstallExecutionError = exception.Message;
            }

            AppendLocalizedLog(
                M("Dynamic.InternalInstall.Execution.Log.Exception", exception.Message));
            RenderInternalInstallExecutionState();
            RefreshActions();
        }
    }

    private async Task ExecuteInternalInstallCoreAsync()
    {
        if (!_ready
            || !IsInternalInstallMode
            || _busy
            || _internalInstallOperationActive
            || _internalInstallExecutionActive
            || HasAttemptedCurrentInternalInstallBackend
            || _internalInstallStep != 3
            || !CanEnterInternalInstallStep(3))
        {
            return;
        }

        var backend = _internalInstallBackend;
        if (backend is null || _internalInstallArtifacts is null || _internalInstallBackup is null)
        {
            return;
        }

        var snapshot = backend.Snapshot;
        if (snapshot.ExecutionStarted || InternalInstallEraseRiskCheck.IsChecked != true)
        {
            return;
        }

        var prepared = backend.Prepared;
        if (string.IsNullOrWhiteSpace(prepared.ConfirmationId))
        {
            return;
        }

        // 唯一一次最终确认：默认“否”，不额外弹窗、不做模拟模式。
        var answer = MessageBox.Show(
            this,
            ComposeInternalInstallConfirmBody(backend),
            T("Dynamic.InternalInstall.Execution.Dialog.Title"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        // 用户确认后重新核对同一个后端、同一个确认 ID、同一个勾选与同一组就绪条件。
        if (!ReferenceEquals(_internalInstallBackend, backend)
            || !string.Equals(
                backend.Prepared.ConfirmationId,
                prepared.ConfirmationId,
                StringComparison.Ordinal)
            || InternalInstallEraseRiskCheck.IsChecked != true
            || _busy
            || _internalInstallOperationActive
            || _internalInstallExecutionActive
            || _internalInstallStep != 3
            || !CanEnterInternalInstallStep(3))
        {
            return;
        }

        _internalInstallExecuteAttempted = true;
        _internalInstallAttemptedBackend = backend;
        _internalInstallExecutionActive = true;
        _internalInstallOperationActive = true;
        _internalInstallLastProgressLog = null;
        _internalInstallExecutionError = null;

        try
        {
            RenderInternalInstallExecutionState();

            await RunBusyAsync(async cancellationToken =>
            {
                // 后端可能按原始数据块高频报告：这里只用一个最新值槽位接收，界面线程每 200 ms 取一次，
                // 不再为每条原始报告单独投递界面回调。泵只降低重绘频率，不合并任何写入事实。
                var progress = new InternalInstallProgressPump(RenderInternalInstallProgress);

                try
                {
                    await backend.ExecuteAsync(
                        prepared.ConfirmationId,
                        userdataEraseConfirmed: true,
                        progress,
                        cancellationToken);
                }
                catch (OperationCanceledException exception)
                {
                    if (backend.Snapshot.WriteState == InternalInstallWriteState.NoneIssued)
                    {
                        _internalInstallExecutionError = exception.Message;
                    }

                    AppendLocalizedLog(M("Dynamic.InternalInstall.Execution.Log.Cancelled"));
                }
                catch (Exception exception)
                {
                    // 后端可能已经发出写入：只记录实际异常，不用“没有改动”之类的猜测替换它。
                    // 准入标记无法区分「被拒绝」与「已写入」，只有写状态仍是 NoneIssued 才说明确实没有写入。
                    if (backend.Snapshot.WriteState == InternalInstallWriteState.NoneIssued)
                    {
                        _internalInstallExecutionError = exception.Message;
                    }

                    AppendLocalizedLog(
                        M("Dynamic.InternalInstall.Execution.Log.Exception", exception.Message));
                }
                finally
                {
                    // 先停止接收并补渲染已排队的离散事件，再写最终结果与终态；
                    // 尚未显示的连续观测进度被丢弃，迟到的报告也不再进入界面。
                    progress.StopAndFlushDiscrete();
                    CaptureInternalInstallPrewriteFailure(backend);
                    AppendInternalInstallResultFacts(backend);
                    RenderInternalInstallExecutionState();
                }
            });
        }
        finally
        {
            _internalInstallExecutionActive = false;
            _internalInstallOperationActive = false;
            RenderInternalInstallExecutionState();
            RefreshActions();
        }

        // 界面忙标志与按钮都已恢复后才提示；只认同一后端快照与结果里的实际安装完成结局。
        ShowInternalInstallCompletionNotification(backend);
    }

    /// <summary>
    /// 只在真实执行正常返回、且同一个后端实例的快照与最后一次结果都报告安装完成时提示一次。
    /// 100% 进度、全部写入已验证或旧的验收通过结局都不足以触发；提示不发送任何设备命令。
    /// </summary>
    private void ShowInternalInstallCompletionNotification(InternalInstallBackend backend)
    {
        if (!_ready
            || !IsInternalInstallMode
            || _busy
            || _internalInstallExecutionActive
            || _internalInstallOperationActive
            || !ReferenceEquals(_internalInstallBackend, backend))
        {
            return;
        }

        if (backend.Snapshot.Outcome != InternalInstallOutcome.InstallationCompleted
            || backend.LastResult?.Outcome != InternalInstallOutcome.InstallationCompleted)
        {
            return;
        }

        var confirmationId = backend.Prepared.ConfirmationId;
        if (string.IsNullOrWhiteSpace(confirmationId)
            || string.Equals(
                _internalInstallCompletedNotificationId,
                confirmationId,
                StringComparison.Ordinal))
        {
            return;
        }

        // 先记录已提示的确认 ID，再弹窗；语言或主题重绘不会再次触发这个提示。
        _internalInstallCompletedNotificationId = confirmationId;

        MessageBox.Show(
            this,
            T("Dynamic.InternalInstall.Execution.Completion.Body"),
            T("Dynamic.InternalInstall.Execution.Completion.Title"),
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    /// <summary>
    /// 只从后端真实返回值里取出「尚未开始写入」的失败原因，供界面说明使用；
    /// 写状态一旦离开 NoneIssued 就什么都不记录，绝不改写结果或推断未写入。
    /// </summary>
    private void CaptureInternalInstallPrewriteFailure(InternalInstallBackend backend)
    {
        if (backend.Snapshot.WriteState != InternalInstallWriteState.NoneIssued)
        {
            return;
        }

        var result = backend.LastResult;
        if (result is null
            || result.Outcome is not (InternalInstallOutcome.Failed or InternalInstallOutcome.Cancelled))
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(result.Diagnostic))
        {
            _internalInstallExecutionError = result.Diagnostic;
        }
        else if (!string.IsNullOrWhiteSpace(result.ErrorCode))
        {
            _internalInstallExecutionError = result.ErrorCode;
        }
    }

    /// <summary>最终确认对话框正文：全部来自工厂返回的方案、真实备份目录与已记录电源事实。</summary>
    private string ComposeInternalInstallConfirmBody(InternalInstallBackend backend)
    {
        var prepared = backend.Prepared;
        var linuxBootBytes = _internalInstallArtifacts?.Allocation.LinuxBootBytes ?? 0L;
        var linuxTotalBytes = checked(prepared.LinuxRootBytes + linuxBootBytes);

        var power = InternalInstallConfirmPowerText.Text;
        if (string.IsNullOrWhiteSpace(power))
        {
            power = T("Dynamic.InternalInstall.Power.Unknown");
        }

        return T(
            "Dynamic.InternalInstall.Execution.Dialog.Body",
            _internalInstallBackup!.Model,
            prepared.AndroidSerial,
            FormatInternalInstallExecutionBytes(prepared.AndroidGiB * 1024L * 1024L * 1024L),
            FormatInternalInstallExecutionBytes(linuxTotalBytes),
            FormatInternalInstallExecutionBytes(prepared.BoardBackupBytes),
            power,
            prepared.BackupDirectory);
    }

    // ---------- 界面结论 ----------

    /// <summary>
    /// 底栏与确认页动作。必须在 <see cref="RefreshInternalInstallActions"/> 的最后调用，
    /// 否则旧三页底栏的赋值会覆盖这里的结论。
    /// </summary>
    private void RefreshInternalInstallExecutionActions()
    {
        if (!_ready || !IsInternalInstallMode)
        {
            return;
        }

        var backend = _internalInstallBackend;
        var started = HasInternalInstallExecutionStarted;
        var attempted = HasAttemptedCurrentInternalInstallBackend;

        // 只有真正开始写入或真实执行调用仍在进行时才冻结输入；仅仅提交过执行但复核失败、
        // 快照仍未开始时，用户必须能回到输入页修改方案或系统包，由释放闸门换一个新后端。
        var frozen = started || _internalInstallExecutionActive;

        SetInternalInstallExecutionInputsFrozen(frozen);

        if (!frozen)
        {
            InternalInstallEraseRiskCheck.IsEnabled =
                !_busy && backend is not null && CanEnterInternalInstallStep(3);
        }

        var canExecute = !frozen
            && !_busy
            && !_internalInstallOperationActive
            && !attempted
            && _internalInstallStep == 3
            && backend is not null
            && CanEnterInternalInstallStep(3)
            && InternalInstallEraseRiskCheck.IsChecked == true;

        // 同一个后端已经提交过执行：即使复核失败也绝不显示可再次执行的动作，换后端后才恢复。
        if (_internalInstallStep == 3 && !frozen && !attempted)
        {
            SetContent(ActionButton, "Dynamic.InternalInstall.Execution.ConfirmButton");
            ActionButton.Visibility = Visibility.Visible;
            ActionButton.IsEnabled = canExecute;
        }
        else
        {
            ActionButton.Visibility = Visibility.Collapsed;
            ActionButton.IsEnabled = false;
        }

        var pending = CanRecheckInternalInstallAcceptance;
        InternalInstallAcceptanceRecheckButton.Visibility =
            pending ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallAcceptanceRecheckButton.IsEnabled = pending && !_busy;

        // 真正开始写入后都保留「关闭安装助手」按钮，包括新的安装完成成功终态；
        // 执行中仍由下面的 IsEnabled 阻止，实际关闭策略由 TryHandleInternalInstallExecutionClosing 决定。
        var showClose = started;
        InternalInstallCloseAssistantButton.Visibility =
            showClose ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallCloseAssistantButton.IsEnabled = showClose
            && !_internalInstallExecutionActive
            && !_internalInstallOperationActive;

        if (_internalInstallStep == 3)
        {
            RenderInternalInstallExecutionState();
        }
    }

    /// <summary>
    /// 一旦提交过执行，就把所有能改变安装输入或离开确认页的入口冻结；
    /// 只冻结这三个页容器与侧栏/前后按钮，确认页本身仍可阅读。
    /// </summary>
    private void SetInternalInstallExecutionInputsFrozen(bool frozen)
    {
        if (frozen)
        {
            InternalInstallCheckPage.IsEnabled = false;
            InternalInstallBackupPage.IsEnabled = false;
            InternalInstallCapacityPage.IsEnabled = false;

            InternalInstallNavCheck.IsEnabled = false;
            InternalInstallNavBackup.IsEnabled = false;
            InternalInstallNavCapacity.IsEnabled = false;
            InternalInstallNavConfirm.IsEnabled = false;

            PrevButton.IsEnabled = false;
            NextButton.IsEnabled = false;
            NextButton.Visibility = Visibility.Collapsed;

            InternalInstallEraseRiskCheck.IsEnabled = false;
            return;
        }

        // 解冻只恢复页容器；侧栏与前后按钮仍由 RefreshInternalInstallActions 的既有规则决定。
        InternalInstallCheckPage.IsEnabled = true;
        InternalInstallBackupPage.IsEnabled = true;
        InternalInstallCapacityPage.IsEnabled = true;
    }

    /// <summary>按后端快照写确认页导语、阶段状态与验收说明；没有执行证据时只说“尚未开始”。</summary>
    private void RenderInternalInstallExecutionState()
    {
        if (!_ready || !IsInternalInstallMode)
        {
            return;
        }

        if (!_internalInstallExecutionActive)
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = false;
            InternalInstallConfirmProgressBar.Value = 0;
            InternalInstallConfirmProgressBar.Visibility = Visibility.Collapsed;
        }
        else if (InternalInstallConfirmProgressBar.Visibility != Visibility.Visible)
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = true;
            InternalInstallConfirmProgressBar.Value = 0;
            InternalInstallConfirmProgressBar.Visibility = Visibility.Visible;
        }

        var backend = _internalInstallBackend;
        var snapshot = backend?.Snapshot;

        if (snapshot is null)
        {
            SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Ready");
            if (!_internalInstallExecutionActive
                && !string.IsNullOrWhiteSpace(_internalInstallExecutionError))
            {
                SetText(
                    InternalInstallConfirmStatusText,
                    M(
                        "Dynamic.InternalInstall.Execution.PrewriteFailed",
                        _internalInstallExecutionError));
            }
            else
            {
                SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Execution.Status.NotStarted");
            }

            SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.NotStarted");
            return;
        }

        var stage = M("Dynamic.InternalInstall.Execution.Stage." + snapshot.Stage);
        var writeState = M("Dynamic.InternalInstall.Execution.WriteState." + snapshot.WriteState);

        // 写状态仍为 NoneIssued 时没有任何写入发生，即使准入标记已置位也按安装前失败展示真实原因。
        if (!snapshot.ExecutionStarted || snapshot.WriteState == InternalInstallWriteState.NoneIssued)
        {
            SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Ready");

            // 仅被准入、从未发出写入的终态同样要给出真实停止原因与证据位置；分支本身保持“尚未开始安装”。
            var prewriteTerminal = snapshot.ExecutionStarted
                && snapshot.Outcome is InternalInstallOutcome.Failed or InternalInstallOutcome.Cancelled;

            if (_internalInstallExecutionActive)
            {
                SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Execution.Status.Starting");
            }
            else if (prewriteTerminal || !string.IsNullOrWhiteSpace(_internalInstallExecutionError))
            {
                // 只显示真实捕获到的后端诊断 / 异常；安装尚未开始，不声称任何个人数据状态。
                object reason = string.IsNullOrWhiteSpace(_internalInstallExecutionError)
                    ? M("Dynamic.InternalInstall.Execution.NoDiagnostic")
                    : _internalInstallExecutionError!;

                UiMessage text = M("Dynamic.InternalInstall.Execution.PrewriteFailed", reason);

                if (prewriteTerminal)
                {
                    text = M(
                        "Dynamic.InternalInstall.Execution.WithFailureDetails",
                        text,
                        ComposeInternalInstallFailureDetails(snapshot, backend?.LastResult));
                }

                SetText(InternalInstallConfirmStatusText, text);
            }
            else
            {
                SetText(
                    InternalInstallConfirmStatusText,
                    M("Dynamic.InternalInstall.Execution.Status.Snapshot", stage, writeState));
            }

            SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.NotStarted");
            return;
        }

        SetText(
            InternalInstallConfirmStatusText,
            M("Dynamic.InternalInstall.Execution.Status.Snapshot", stage, writeState));

        if (snapshot.Outcome is null)
        {
            SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Running");
            SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.Running");
            return;
        }

        var errorCode = backend?.LastResult?.ErrorCode ?? "—";
        var evidence = snapshot.EvidenceDirectory;

        switch (snapshot.Outcome.Value)
        {
            case InternalInstallOutcome.InstallationCompleted:
                // 全新安装完成结局：状态行已按后端实际阶段与写入状态显示，这里只换掉导语与验收说明，
                // 不沿用旧的「待安卓初始化 / 待授权」措辞，也不提示任何后续 ADB 检查。
                SetText(
                    InternalInstallConfirmLeadText,
                    "Dynamic.InternalInstall.Execution.Lead.InstallationCompleted");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    "Dynamic.InternalInstall.Execution.Acceptance.InstallationCompleted");
                break;

            case InternalInstallOutcome.Completed:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Completed");
                SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.Completed");
                break;

            case InternalInstallOutcome.AwaitingAndroidInitialization:
            case InternalInstallOutcome.AwaitingUsbAuthorization:
            case InternalInstallOutcome.AwaitingLinuxFirstBoot:
                if (snapshot.WriteState == InternalInstallWriteState.AllVerified)
                {
                    SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Pending");
                    SetText(
                        InternalInstallAcceptanceStatusText,
                        PendingAcceptanceKey(snapshot.Outcome.Value));
                }
                else
                {
                    SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.PendingUnverified");
                    SetText(
                        InternalInstallAcceptanceStatusText,
                        "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified");
                }

                break;

            case InternalInstallOutcome.Failed:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Terminal");
                // 三个终态只显示后端已经记录的事实：停止阶段、最后验证阶段、写状态、诊断、错误码与证据位置。
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M(
                        "Dynamic.InternalInstall.Execution.WithFailureDetails",
                        M("Dynamic.InternalInstall.Execution.Acceptance.Failed", errorCode, evidence),
                        ComposeInternalInstallFailureDetails(snapshot, backend?.LastResult)));
                break;

            case InternalInstallOutcome.Cancelled:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Terminal");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M(
                        "Dynamic.InternalInstall.Execution.WithFailureDetails",
                        M("Dynamic.InternalInstall.Execution.Acceptance.Cancelled", evidence),
                        ComposeInternalInstallFailureDetails(snapshot, backend?.LastResult)));
                break;

            case InternalInstallOutcome.UnknownWriteOutcome:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Unknown");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M(
                        "Dynamic.InternalInstall.Execution.WithFailureDetails",
                        M("Dynamic.InternalInstall.Execution.Acceptance.Unknown", evidence),
                        ComposeInternalInstallFailureDetails(snapshot, backend?.LastResult)));
                break;

            default:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.PendingUnverified");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified");
                break;
        }
    }

    /// <summary>
    /// 终态失败时唯一的事实清单：停止阶段、最后验证阶段、写状态、后端诊断、补充错误码与证据 / 日志位置。
    /// 全部直接取自后端快照与最后一次结果；不推断任何已完成或未执行的步骤，也不把阶段顺序当作验证证据。
    /// </summary>
    private UiMessage ComposeInternalInstallFailureDetails(
        InternalInstallSnapshot snapshot,
        InternalInstallResult? result)
    {
        var stoppingStage = M("Dynamic.InternalInstall.Execution.Stage." + snapshot.Stage);

        var lastVerifiedStage = result?.LastVerifiedStage is { } verifiedStage
            ? M("Dynamic.InternalInstall.Execution.Stage." + verifiedStage)
            : M("Dynamic.InternalInstall.Execution.NoVerifiedStage");

        var writeState = M("Dynamic.InternalInstall.Execution.WriteState." + snapshot.WriteState);

        object diagnostic;
        if (!string.IsNullOrWhiteSpace(result?.Diagnostic))
        {
            diagnostic = result!.Diagnostic!;
        }
        else if (!string.IsNullOrWhiteSpace(_internalInstallExecutionError))
        {
            // 只回退到执行入口实际捕获的写入前异常；两者都没有时如实说明后端未提供原因。
            diagnostic = _internalInstallExecutionError!;
        }
        else
        {
            diagnostic = M("Dynamic.InternalInstall.Execution.NoDiagnostic");
        }

        var errorCode = string.IsNullOrWhiteSpace(result?.ErrorCode) ? "—" : result!.ErrorCode!;
        var evidence = !string.IsNullOrWhiteSpace(snapshot.EvidenceDirectory)
            ? snapshot.EvidenceDirectory
            : !string.IsNullOrWhiteSpace(result?.EvidenceDirectory)
                ? result!.EvidenceDirectory
                : "—";

        return M(
            "Dynamic.InternalInstall.Execution.FailureDetails",
            stoppingStage,
            lastVerifiedStage,
            writeState,
            diagnostic,
            errorCode,
            evidence);
    }

    private static string PendingAcceptanceKey(InternalInstallOutcome outcome) => outcome switch
    {
        InternalInstallOutcome.AwaitingAndroidInitialization =>
            "Dynamic.InternalInstall.Execution.Acceptance.WaitAndroid",
        InternalInstallOutcome.AwaitingUsbAuthorization =>
            "Dynamic.InternalInstall.Execution.Acceptance.AuthorizeUsb",
        InternalInstallOutcome.AwaitingLinuxFirstBoot =>
            "Dynamic.InternalInstall.Execution.Acceptance.WaitLinux",
        _ => "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified",
    };

    /// <summary>
    /// 进度只描述「当前阶段、本步证据、本阶段已验证字节」，或在有传输阶段时描述近似传输字节；
    /// 它从不代表全局百分比，也不参与任何完成判断。近似传输字节永远不写入已验证计数。
    /// </summary>
    private void RenderInternalInstallProgress(InternalInstallProgress progress)
    {
        if (!_ready || !IsInternalInstallMode || !_internalInstallExecutionActive)
        {
            return;
        }

        var stage = M("Dynamic.InternalInstall.Execution.Stage." + progress.Stage);

        // 离散事件（Started / Verified / Failed / Cancelled / WaitingForUser）即使带传输阶段，
        // 也必须继续走真实的 Kind、已验证计数与日志；只有连续 Progress 观测才用近似传输显示。
        if (progress.IoPhase is { } ioPhase
            && progress.Kind == InternalInstallProgressKind.Progress)
        {
            RenderInternalInstallIoProgress(progress, stage, ioPhase);
            return;
        }

        var kind = M("Dynamic.InternalInstall.Execution.Kind." + progress.Kind);
        var hasSlot = !string.IsNullOrWhiteSpace(progress.Slot);
        var hasBytes = progress.TotalBytes > 0;

        if (hasSlot && hasBytes)
        {
            SetText(
                InternalInstallConfirmStatusText,
                M(
                    "Dynamic.InternalInstall.Execution.Status.ProgressSlotBytes",
                    stage,
                    progress.Slot!,
                    kind,
                    FormatInternalInstallExecutionBytes(progress.CompletedBytes),
                    FormatInternalInstallExecutionBytes(progress.TotalBytes)));
        }
        else if (hasSlot)
        {
            SetText(
                InternalInstallConfirmStatusText,
                M("Dynamic.InternalInstall.Execution.Status.ProgressSlot", stage, progress.Slot!, kind));
        }
        else if (hasBytes)
        {
            SetText(
                InternalInstallConfirmStatusText,
                M(
                    "Dynamic.InternalInstall.Execution.Status.ProgressBytes",
                    stage,
                    kind,
                    FormatInternalInstallExecutionBytes(progress.CompletedBytes),
                    FormatInternalInstallExecutionBytes(progress.TotalBytes)));
        }
        else
        {
            SetText(
                InternalInstallConfirmStatusText,
                M("Dynamic.InternalInstall.Execution.Status.Progress", stage, kind));
        }

        if (hasBytes)
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = false;
            InternalInstallConfirmProgressBar.Value = Math.Clamp(
                progress.CompletedBytes / (double)progress.TotalBytes * 100.0,
                0.0,
                100.0);
        }
        else
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = true;
            InternalInstallConfirmProgressBar.Value = 0;
        }

        InternalInstallConfirmProgressBar.Visibility = Visibility.Visible;

        // 只有完全相同的重复报告才只记一次；不同 Kind、槽位或阶段边界都各自保留一条日志。
        var fingerprint = string.Join(
            "|",
            progress.Stage,
            progress.Kind,
            progress.Slot,
            progress.CompletedBytes,
            progress.TotalBytes,
            progress.Detail);
        if (progress.Kind == InternalInstallProgressKind.Progress
            && string.Equals(fingerprint, _internalInstallLastProgressLog, StringComparison.Ordinal))
        {
            // 只有同签名的连续 Progress 观测去重；离散事件即使内容完全相同也逐条保留日志。
            return;
        }

        _internalInstallLastProgressLog = fingerprint;
        AppendLocalizedLog(
            M(
                "Dynamic.InternalInstall.Execution.Log.Progress",
                stage,
                kind,
                hasSlot ? progress.Slot! : "—",
                FormatInternalInstallExecutionBytes(progress.CompletedBytes),
                progress.TotalBytes > 0
                    ? FormatInternalInstallExecutionBytes(progress.TotalBytes)
                    : "—",
                string.IsNullOrWhiteSpace(progress.Detail) ? "—" : progress.Detail));
    }

    /// <summary>
    /// 原生传输的近似字节只用于「当前传输进度」和日志摘要；它们不是后端已验证字节，
    /// 也不代表整个安装完成，因此文案统一写成「约」。只有已完成字节与总量两个真实可空值
    /// 都存在且总量大于零时才显示当前传输的数值与百分比；否则只显示阶段并使用不确定进度条。
    /// </summary>
    private void RenderInternalInstallIoProgress(
        InternalInstallProgress progress,
        UiMessage stage,
        InternalInstallIoPhase ioPhase)
    {
        // 板端恢复镜像这一阶段单独用一组「含空白填充」的传输文案；其余阶段仍用原始传输文案。
        var phase = progress.Stage == InternalInstallStage.WritingBoardBackup
            ? M("Dynamic.InternalInstall.Execution.BoardIoPhase." + ioPhase)
            : M("Dynamic.InternalInstall.Execution.IoPhase." + ioPhase);
        var hasSlot = !string.IsNullOrWhiteSpace(progress.Slot);
        var ioCompleted = progress.IoCompletedBytes.GetValueOrDefault();
        var ioTotal = progress.IoTotalBytes.GetValueOrDefault();
        var hasIoTotal = progress.IoCompletedBytes is not null
            && progress.IoTotalBytes is > 0;

        if (hasIoTotal)
        {
            SetText(
                InternalInstallConfirmStatusText,
                hasSlot
                    ? M(
                        "Dynamic.InternalInstall.Execution.Status.IoSlot",
                        stage,
                        progress.Slot!,
                        phase,
                        FormatInternalInstallExecutionBytes(ioCompleted),
                        FormatInternalInstallExecutionBytes(ioTotal))
                    : M(
                        "Dynamic.InternalInstall.Execution.Status.Io",
                        stage,
                        phase,
                        FormatInternalInstallExecutionBytes(ioCompleted),
                        FormatInternalInstallExecutionBytes(ioTotal)));
        }
        else
        {
            SetText(
                InternalInstallConfirmStatusText,
                hasSlot
                    ? M(
                        "Dynamic.InternalInstall.Execution.Status.IoPhaseSlot",
                        stage,
                        progress.Slot!,
                        phase)
                    : M("Dynamic.InternalInstall.Execution.Status.IoPhase", stage, phase));
        }

        if (hasIoTotal)
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = false;
            InternalInstallConfirmProgressBar.Value = Math.Clamp(
                ioCompleted / (double)ioTotal * 100.0,
                0.0,
                100.0);
        }
        else
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = true;
            InternalInstallConfirmProgressBar.Value = 0;
        }

        InternalInstallConfirmProgressBar.Visibility = Visibility.Visible;

        // 传输阶段与近似字节都进入指纹：同一阶段的数字变化会另记一条日志，但不改动已验证计数。
        var fingerprint = string.Join(
            "|",
            progress.Stage,
            "Io",
            progress.IoPhase,
            progress.Slot,
            progress.IoCompletedBytes,
            progress.IoTotalBytes,
            progress.Detail);
        if (string.Equals(fingerprint, _internalInstallLastProgressLog, StringComparison.Ordinal))
        {
            return;
        }

        _internalInstallLastProgressLog = fingerprint;
        AppendLocalizedLog(
            M(
                "Dynamic.InternalInstall.Execution.Log.Io",
                stage,
                phase,
                hasSlot ? progress.Slot! : "—",
                progress.IoCompletedBytes is null
                    ? "—"
                    : FormatInternalInstallExecutionBytes(ioCompleted),
                hasIoTotal ? FormatInternalInstallExecutionBytes(ioTotal) : "—",
                string.IsNullOrWhiteSpace(progress.Detail) ? "—" : progress.Detail));
    }

    /// <summary>把后端实际返回的结局、写入状态、最后验证阶段与错误码写进日志，不改写任何状态。</summary>
    private void AppendInternalInstallResultFacts(InternalInstallBackend backend)
    {
        var result = backend.LastResult;
        if (result is null)
        {
            return;
        }

        AppendLocalizedLog(
            M(
                "Dynamic.InternalInstall.Execution.Log.Result",
                M("Dynamic.InternalInstall.Execution.Outcome." + result.Outcome),
                M("Dynamic.InternalInstall.Execution.WriteState." + result.WriteState),
                result.LastVerifiedStage is null
                    ? "—"
                    : (object)M("Dynamic.InternalInstall.Execution.Stage." + result.LastVerifiedStage.Value),
                result.VerifiedSlots.Count,
                result.EvidenceDirectory));

        if (!string.IsNullOrWhiteSpace(result.ErrorCode) || !string.IsNullOrWhiteSpace(result.Diagnostic))
        {
            AppendLocalizedLog(
                M(
                    "Dynamic.InternalInstall.Execution.Log.Diagnostic",
                    string.IsNullOrWhiteSpace(result.ErrorCode) ? "—" : result.ErrorCode,
                    string.IsNullOrWhiteSpace(result.Diagnostic) ? "—" : result.Diagnostic));
        }
    }

    // ---------- 文案与格式 ----------

    /// <summary>
    /// 真实安装执行的进度投递泵：离散事件（Started / Verified / Failed / Cancelled / WaitingForUser
    /// 以及阶段、传输阶段或槽位变化）按顺序进入一个小队列，同一阶段的连续 Progress 只保留最新一条；
    /// 界面线程的 200 ms <see cref="DispatcherTimer"/> 最多每秒取 5 次，把队列与最新观测按时间顺序
    /// 在同一批里渲染。它只合并重复观测，不丢弃任何离散事件，也不推断写入事实或把传输字节当作已验证字节。
    /// 执行结束时用 <see cref="StopAndFlushDiscrete"/> 先补渲染已排队的离散事件，再交给随后的终态渲染；
    /// <see cref="Dispose"/> 只做幂等的停止与清空，从不重放。
    /// </summary>
    private sealed class InternalInstallProgressPump : IProgress<InternalInstallProgress>, IDisposable
    {
        private readonly object _gate = new();
        private readonly DispatcherTimer _timer;
        private readonly Action<InternalInstallProgress> _render;
        private readonly Queue<InternalInstallProgress> _discrete = new();
        private InternalInstallProgress? _latestObservation;
        private InternalInstallStage? _lastStage;
        private InternalInstallIoPhase? _lastIoPhase;
        private string? _lastSlot;
        private bool _hasBoundary;
        private bool _stopped;

        internal InternalInstallProgressPump(Action<InternalInstallProgress> render)
        {
            _render = render;
            _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            _timer.Tick += OnTick;
            _timer.Start();
        }

        /// <summary>离散事件排队；只有同一阶段、同一传输阶段、同一槽位的连续 Progress 才合并为最新一条。</summary>
        public void Report(InternalInstallProgress value)
        {
            if (value is null)
            {
                return;
            }

            lock (_gate)
            {
                if (_stopped)
                {
                    return;
                }

                var boundaryChanged = !_hasBoundary
                    || value.Stage != _lastStage
                    || value.IoPhase != _lastIoPhase
                    || !string.Equals(value.Slot, _lastSlot, StringComparison.Ordinal);

                if (value.Kind == InternalInstallProgressKind.Progress && !boundaryChanged)
                {
                    _latestObservation = value;
                    return;
                }

                // 先把已攒下的观测按时间顺序落进队列，再排入这个离散事件或边界，保证渲染顺序不变。
                if (_latestObservation is not null)
                {
                    _discrete.Enqueue(_latestObservation);
                    _latestObservation = null;
                }

                _discrete.Enqueue(value);
                _hasBoundary = true;
                _lastStage = value.Stage;
                _lastIoPhase = value.IoPhase;
                _lastSlot = value.Slot;
            }
        }

        /// <summary>
        /// 停止接收新报告，按顺序取出全部已排队的离散事件并在界面线程补渲染，
        /// 同时丢弃尚未显示的连续观测进度。调用后迟到的报告一律忽略。
        /// </summary>
        internal void StopAndFlushDiscrete()
        {
            List<InternalInstallProgress> pending;
            lock (_gate)
            {
                _stopped = true;
                pending = new List<InternalInstallProgress>(_discrete.Count);
                while (_discrete.Count > 0)
                {
                    pending.Add(_discrete.Dequeue());
                }

                _latestObservation = null;
            }

            _timer.Stop();
            _timer.Tick -= OnTick;

            foreach (var item in pending)
            {
                // 补渲染的只是已经真实收到的离散事件；权威终态仍由调用方随后重新渲染。
                _render(item);
            }
        }

        /// <summary>幂等清理：停止定时器、清空队列与最新观测，绝不重放任何内容。</summary>
        public void Dispose()
        {
            lock (_gate)
            {
                _stopped = true;
                _discrete.Clear();
                _latestObservation = null;
            }

            _timer.Stop();
            _timer.Tick -= OnTick;
        }

        private void OnTick(object? sender, EventArgs e)
        {
            List<InternalInstallProgress> batch;
            lock (_gate)
            {
                if (_discrete.Count == 0 && _latestObservation is null)
                {
                    return;
                }

                batch = new List<InternalInstallProgress>(_discrete.Count + 1);
                batch.AddRange(_discrete);
                _discrete.Clear();

                if (_latestObservation is not null)
                {
                    // 最新观测总是晚于已排队事件，因此追加在批末即可保持时间顺序。
                    batch.Add(_latestObservation);
                    _latestObservation = null;
                }
            }

            foreach (var item in batch)
            {
                _render(item);
            }
        }
    }

    private static string FormatInternalInstallExecutionBytes(long bytes)
    {
        const double KiB = 1024d;
        const double MiB = 1024d * 1024d;
        const double GiB = 1024d * 1024d * 1024d;

        var value = Math.Abs((double)bytes);
        if (value >= GiB)
        {
            return (bytes / GiB).ToString("0.##", CultureInfo.CurrentCulture) + " GiB";
        }

        if (value >= MiB)
        {
            return (bytes / MiB).ToString("0.#", CultureInfo.CurrentCulture) + " MiB";
        }

        if (value >= KiB)
        {
            return (bytes / KiB).ToString("0.#", CultureInfo.CurrentCulture) + " KiB";
        }

        return bytes.ToString(CultureInfo.CurrentCulture) + " B";
    }

    /// <summary>
    /// 释放前的唯一闸门：真实执行/复查仍在进行时拒绝；尚未开始写入的后端即使处于普通只读
    /// 导入 / 准备操作中也可以被替换；已经真正开始写入的只允许真实成功终态或已批准的关闭释放。
    /// </summary>
    private bool CanReleaseInternalInstallBackend(InternalInstallBackend backend)
    {
        if (_internalInstallExecutionActive)
        {
            return false;
        }

        var snapshot = backend.Snapshot;
        if (!snapshot.ExecutionStarted || snapshot.WriteState == InternalInstallWriteState.NoneIssued)
        {
            // NoneIssued 证明从未发出写入：仅有准入标记也仍可释放并重新准备。
            return true;
        }

        return snapshot.Outcome
                is InternalInstallOutcome.Completed
                or InternalInstallOutcome.InstallationCompleted
            || _internalInstallPostWriteCloseApproved;
    }
}
