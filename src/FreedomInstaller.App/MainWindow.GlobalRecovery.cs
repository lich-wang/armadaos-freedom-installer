using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 全局救援页面的自有状态与视图层。页面有两个独立视图（备份 / 恢复），共用同一份连接、日志与进度，
/// 视图只由 <see cref="GlobalRecoveryMode"/> 与 <see cref="GlobalRecoveryOrigin"/> 决定；
/// 两者都不写进六种功能模式的 <c>_selectedOperation</c> / 页面字段，也不复用内部安装的会话字段。
/// <para>
/// 页面本身不改写环境自检结论；进入页面不做任何设备 IO，真正的设备访问只发生在用户显式点击
/// 连接 / 备份 / 准备还原 / 开始还原 / 重启按钮时，并由 <c>MainWindow.GlobalRecovery.Execution.cs</c> 承担。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>全局页的两种独立视图。它们不是六种功能的操作标签，绝不写进 _selectedOperation。</summary>
    internal enum GlobalRecoveryMode
    {
        Backup,
        Restore,
    }

    /// <summary>进入本页的来源：环境准备完成后的可选页，或首页的独立卡片。</summary>
    internal enum GlobalRecoveryOrigin
    {
        Onboarding,
        Home,
    }

    // ---------- 与六种功能完全隔离的会话状态 ----------

    /// <summary>当前是否停留在全局救援页；由父级导航在展示 / 返回时维护。</summary>
    private bool _showingGlobalRecovery;

    /// <summary>当前视图（备份 / 恢复）。切换视图只改可见性，不清空任何会话。</summary>
    private GlobalRecoveryMode _globalRecoveryMode = GlobalRecoveryMode.Backup;

    /// <summary>当前来源；决定标题文案、返回目标与「可选、可跳过」说明是否出现。</summary>
    private GlobalRecoveryOrigin _globalRecoveryOrigin = GlobalRecoveryOrigin.Onboarding;

    /// <summary>整段外层异步操作（连接 / 备份 / 准备 / 还原 / 重启）正在运行。</summary>
    private bool _globalOperationActive;

    /// <summary>本页唯一持有的工具链；只有自有会话才释放。</summary>
    private EdlToolchain? _globalEdlTools;

    /// <summary>唯一一次真实入口结果（安卓路线或已有 9008 的离线绑定）。</summary>
    private EdlEntryResult? _globalEdlEntry;

    /// <summary>与 <see cref="_globalEdlTools"/> 配对的唯一客户端；Core 客户端不是 IDisposable。</summary>
    private EdlClient? _globalEdlClient;

    /// <summary>建立会话时实际使用的可信配置；用于后续会话复用核对。</summary>
    private EdlDeviceProfile? _globalProfile;

    /// <summary>是否已经发起过入口命令；失败后仍保留，避免把未知现场当成可自由切换。</summary>
    private bool _globalEntryAttempted;

    /// <summary>仅本页自己的安卓电量采样；不写入内部安装字段。</summary>
    private EdlPowerSample? _globalPower;

    /// <summary>用户显式选择的输出父目录（备份目录也作为还原证据父目录）。</summary>
    private string? _globalOutputParent;

    /// <summary>用户显式选择的已有备份目录（还原来源）。</summary>
    private string? _globalRestoreSource;

    /// <summary>本地完整校验通过、可用于准备的备份集；只在未连接或准备阶段持有。</summary>
    private GlobalEdlBackupSet? _globalRestoreSet;

    /// <summary>Core 真实返回的还原方案；只有它存在才允许执行。</summary>
    private GlobalEdlRestorePlan? _globalRestorePlan;

    /// <summary>已经调用过还原执行；无论成功与否都不再自动重试。</summary>
    private bool _globalRestoreWriteAttempted;

    /// <summary>写入已经开始但结果不确定；本会话永久禁止继续 / 重启 / 再次还原。</summary>
    private bool _globalRestoreUncertain;

    /// <summary>Core 明确报告成功且回读校验通过。</summary>
    private bool _globalRestoreSucceeded;

    /// <summary>已经调用过重置；失败或未知时不再自动重试。</summary>
    private bool _globalResetAttempted;

    /// <summary>重置结果未知；禁止自动重新连接或回到首页。</summary>
    private bool _globalResetUnknown;

    /// <summary>关闭警告只弹一次；确认后本次关闭不再阻止。</summary>
    private bool _globalCloseConfirmed;

    /// <summary>进度回调是否仍然有效；操作结束后迟到的回调一律忽略。</summary>
    private bool _globalProgressActive;

    /// <summary>上一次已写入界面的进度阶段；阶段变化时立即记录日志。</summary>
    private string? _globalProgressStage;

    /// <summary>上一次进度文本刷新时间；普通进度最多每秒一次。</summary>
    private DateTime _globalLastProgressAt = DateTime.MinValue;

    /// <summary>父级导航用于判断是否可以离开本页 / 回首页的只读闸门。</summary>
    internal bool HasGlobalRecoveryProtectedState =>
        _globalOperationActive
        || _globalEdlClient is not null
        || _globalEdlEntry is not null
        || _globalEntryAttempted
        || _globalResetAttempted
        || _globalResetUnknown
        || _globalRestoreUncertain
        || _globalRestoreWriteAttempted;

    /// <summary>
    /// 进入指定视图：只校验前置条件并切换可见性，不做任何设备 IO，也不改写六种功能的选择。
    /// 已有受保护现场时拒绝切换到另一个视图，绝不为换页清空唯一可核对的会话。
    /// </summary>
    internal void ShowGlobalRecoveryPage(GlobalRecoveryMode mode, GlobalRecoveryOrigin origin)
    {
        if (!_ready || _closed || !EnvironmentIsReady)
        {
            return;
        }

        if (HasGlobalRecoveryProtectedState
            && (!_showingGlobalRecovery || _globalRecoveryMode != mode))
        {
            return;
        }

        _globalRecoveryMode = mode;
        _globalRecoveryOrigin = origin;
        ResumeGlobalRecoveryPage();
    }

    /// <summary>受保护现场存在时只把视图切回本页：不校验环境、不重置模式，也不碰会话字段。</summary>
    internal void ResumeGlobalRecoveryPage()
    {
        if (!_ready || _closed)
        {
            return;
        }

        _showingGlobalRecovery = true;
        ApplyFunctionView();
        ApplyGlobalRecoveryModeView();
        RefreshGlobalRecoveryActions();
        RenderGlobalConnection();
        RenderGlobalPower();
        GlobalRecoveryPage.ScrollToTop();
    }

    /// <summary>按当前模式 / 来源只切可见性；语言切换与刷新都不会调用它，因此模式不会被改回默认值。</summary>
    private void ApplyGlobalRecoveryModeView()
    {
        if (!_ready)
        {
            return;
        }

        var backup = _globalRecoveryMode == GlobalRecoveryMode.Backup;
        var homeOrigin = _globalRecoveryOrigin == GlobalRecoveryOrigin.Home;

        // 标题、说明与输出目录标签按视图互斥；同一时刻只有一个标题，备份说明不留在恢复页。
        GlobalBackupTitleText.Visibility = backup ? Visibility.Visible : Visibility.Collapsed;
        GlobalRestoreTitleText.Visibility = backup ? Visibility.Collapsed : Visibility.Visible;
        GlobalBackupLeadText.Visibility = backup ? Visibility.Visible : Visibility.Collapsed;
        GlobalRestoreLeadText.Visibility = backup ? Visibility.Collapsed : Visibility.Visible;
        GlobalOutputBackupLabelText.Visibility = backup ? Visibility.Visible : Visibility.Collapsed;
        GlobalOutputRestoreLabelText.Visibility = backup ? Visibility.Collapsed : Visibility.Visible;
        GlobalBackupCard.Visibility = backup ? Visibility.Visible : Visibility.Collapsed;
        GlobalRestoreCard.Visibility = backup ? Visibility.Collapsed : Visibility.Visible;

        // 首页来源返回功能首页；环境来源返回环境准备页，并保留「可选、可跳过」说明。
        GlobalBackEnvironmentButton.Visibility = homeOrigin ? Visibility.Collapsed : Visibility.Visible;
        GlobalBackHomeButton.Visibility = homeOrigin ? Visibility.Visible : Visibility.Collapsed;
        GlobalContinueButton.Visibility = homeOrigin ? Visibility.Collapsed : Visibility.Visible;
        GlobalOptionalNoteText.Visibility = homeOrigin ? Visibility.Collapsed : Visibility.Visible;
    }

    // ---------- 导航 ----------

    /// <summary>首页「9008 全局备份」：只打开备份视图，不写操作标签，也不发起任何设备 IO。</summary>
    private void OnOpenGlobalBackupFromHome(object sender, RoutedEventArgs e) =>
        OpenGlobalRecoveryFromHome(GlobalRecoveryMode.Backup);

    /// <summary>首页「9008 全局恢复」：只打开恢复视图，不写操作标签，也不发起任何设备 IO。</summary>
    private void OnOpenGlobalRestoreFromHome(object sender, RoutedEventArgs e) =>
        OpenGlobalRecoveryFromHome(GlobalRecoveryMode.Restore);

    /// <summary>首页入口的唯一闸门：环境已就绪、当前确实在首页、且没有其它受保护流程。</summary>
    private void OpenGlobalRecoveryFromHome(GlobalRecoveryMode mode)
    {
        if (!_ready || _busy || _closed || _showingSupport || _showingEnvironment || !_showingHome)
        {
            return;
        }

        if (!EnvironmentIsReady)
        {
            return;
        }

        // 有设备侧的受保护流程时只允许留在原视图，不为进入全局页清空任何现场。
        if (HasGlobalRecoveryProtectedState
            || HasProtectedUninstallState
            || ProtectedModernTfInstallState
            || HasInternalInstallLiveEdlState
            || (HasInternalInstallExecutionStarted && !IsCompletedInternalInstallExecution)
            || HasPendingTfTabletRecovery)
        {
            return;
        }

        ShowGlobalRecoveryPage(mode, GlobalRecoveryOrigin.Home);
    }

    private async void OnGlobalBackEnvironment(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed)
        {
            return;
        }

        // 有真实 9008 会话 / 入口尝试 / 未确定写入时，返回会丢掉可核对的现场。
        if (HasGlobalRecoveryProtectedState)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BlockedBySession");
            return;
        }

        // 首页来源：同一个返回按钮直接回功能首页，不重跑环境自检。
        if (_globalRecoveryOrigin == GlobalRecoveryOrigin.Home)
        {
            _showingGlobalRecovery = false;
            ShowFunctionHome();
            RefreshActions();
            return;
        }

        _showingGlobalRecovery = false;
        _showingEnvironment = true;
        ApplyFunctionView();
        RefreshEnvironmentActions();
        await RunEnvironmentCheckAsync();
    }

    private void OnGlobalContinue(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || !EnvironmentIsReady)
        {
            return;
        }

        // 只有完全没有本页现场时才允许直接回首页。
        if (HasGlobalRecoveryProtectedState)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BlockedBySession");
            return;
        }

        _showingGlobalRecovery = false;
        ShowFunctionHome();
        RefreshActions();
    }

    /// <summary>父级关闭钩子：整段操作期间拒绝关闭；有现场时一次性显式确认。</summary>
    internal void OnGlobalRecoveryClosing(CancelEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (!_showingGlobalRecovery && !HasGlobalRecoveryProtectedState)
        {
            return;
        }

        if (_globalOperationActive)
        {
            e.Cancel = true;
            return;
        }

        if (!HasGlobalRecoveryProtectedState || _globalCloseConfirmed)
        {
            return;
        }

        e.Cancel = true;
        MessageBoxResult answer = MessageBox.Show(
            this,
            T("Dynamic.Global.Dialog.CloseWarning"),
            T("Dynamic.Global.Dialog.Title"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer == MessageBoxResult.Yes)
        {
            _globalCloseConfirmed = true;
            e.Cancel = false;
        }
    }

    /// <summary>父级关闭清理：只释放托管对象，绝不删除用户备份或证据目录。</summary>
    internal void DisposeGlobalRecoveryOnClose()
    {
        if (_globalOperationActive)
        {
            return;
        }

        DisposeGlobalRestorePreparation();
        _globalRestoreUncertain = false;
        _globalRestoreWriteAttempted = false;
        _globalRestoreSucceeded = false;
        _globalResetAttempted = false;
        _globalResetUnknown = false;
        _globalEntryAttempted = false;
        _globalEdlEntry = null;
        _globalEdlClient = null;
        _globalProfile = null;
        _globalPower = null;
        _globalEdlTools?.Dispose();
        _globalEdlTools = null;
        _globalProgressActive = false;
    }

    // ---------- 可用性 ----------

    /// <summary>所有本页控件可用性的唯一入口；日志区不受影响。</summary>
    internal void RefreshGlobalRecoveryActions()
    {
        if (!_ready)
        {
            return;
        }

        bool busy = _globalOperationActive || _busy;
        bool live = _globalEdlClient is not null || _globalEntryAttempted;
        bool frozen = _globalRestoreUncertain || _globalResetUnknown;
        bool writesAttempted = _globalRestoreWriteAttempted;

        bool canPickOutput = !busy && !frozen && !writesAttempted;
        bool backupView = _globalRecoveryMode == GlobalRecoveryMode.Backup;
        bool restoreView = _globalRecoveryMode == GlobalRecoveryMode.Restore;

        if (GlobalBrowseBackupButton is not null)
        {
            GlobalBrowseBackupButton.IsEnabled = !busy && !frozen && !writesAttempted && !live;
        }

        if (GlobalBrowseRestoreButton is not null)
        {
            GlobalBrowseRestoreButton.IsEnabled = canPickOutput;
        }

        bool proof = _globalEdlClient?.HasInitialSaharaProof == true;
        bool idleConnect = _globalEdlClient is null && !_globalEntryAttempted;
        bool reprobeConnect = _globalEdlClient is not null && !proof;

        if (GlobalConnectButton is not null)
        {
            // 型号由连接时自动识别：没有已知配置也允许发起一次显式连接。
            // 空闲连接允许还没有输出目录（处理器会先询问）；已有客户端但缺证明时允许一次显式复探。
            // 入口已尝试却没有客户端时不自动重跑安卓命令，交由人工重新连接 / 关闭。
            GlobalConnectButton.IsEnabled = !busy && !frozen && !writesAttempted
                && (idleConnect || reprobeConnect);
        }

        if (GlobalBackupButton is not null)
        {
            GlobalBackupButton.IsEnabled = backupView && !busy && !frozen && !writesAttempted
                && proof
                && !string.IsNullOrWhiteSpace(_globalOutputParent);
        }

        if (GlobalPrepareRestoreButton is not null)
        {
            GlobalPrepareRestoreButton.IsEnabled = restoreView && !busy && !frozen && !writesAttempted
                && !string.IsNullOrWhiteSpace(_globalRestoreSource)
                && !string.IsNullOrWhiteSpace(_globalOutputParent)
                && GlobalRestoreDirectoriesValid();
        }

        if (GlobalRestoreConfirmCheck is not null)
        {
            GlobalRestoreConfirmCheck.IsEnabled = restoreView && !busy && !frozen && !writesAttempted
                && _globalRestorePlan is not null;
        }

        if (GlobalRestoreButton is not null)
        {
            GlobalRestoreButton.IsEnabled = restoreView && !busy && !frozen && !writesAttempted
                && _globalRestorePlan is not null
                && proof
                && GlobalRestoreConfirmCheck?.IsChecked == true;
        }

        if (GlobalRestartButton is not null)
        {
            GlobalRestartButton.IsEnabled = !busy && !frozen
                && !_globalResetAttempted
                && proof
                && (!writesAttempted || _globalRestoreSucceeded);
        }

        if (GlobalBackEnvironmentButton is not null)
        {
            GlobalBackEnvironmentButton.IsEnabled = !busy && !HasGlobalRecoveryProtectedState;
        }

        // 首页来源的「返回功能首页」与准备页返回共用同一道受保护现场闸门。
        if (GlobalBackHomeButton is not null)
        {
            GlobalBackHomeButton.IsEnabled = !busy && !HasGlobalRecoveryProtectedState;
        }

        if (GlobalContinueButton is not null)
        {
            GlobalContinueButton.IsEnabled = !busy
                && !HasGlobalRecoveryProtectedState
                && EnvironmentIsReady;
        }
    }

    // ---------- 视图回调闸门 ----------

    /// <summary>备份动作只属于备份视图；恢复视图里绝不发起只读备份。</summary>
    private void OnGlobalBackupAction(object sender, RoutedEventArgs e)
    {
        if (_globalRecoveryMode != GlobalRecoveryMode.Backup)
        {
            return;
        }

        OnGlobalBackup(sender, e);
    }

    /// <summary>只读准备只属于恢复视图。</summary>
    private void OnGlobalPrepareRestoreAction(object sender, RoutedEventArgs e)
    {
        if (_globalRecoveryMode != GlobalRecoveryMode.Restore)
        {
            return;
        }

        OnGlobalPrepareRestore(sender, e);
    }

    /// <summary>唯一一次写入只属于恢复视图。</summary>
    private void OnGlobalRestoreAction(object sender, RoutedEventArgs e)
    {
        if (_globalRecoveryMode != GlobalRecoveryMode.Restore)
        {
            return;
        }

        OnGlobalRestore(sender, e);
    }

    // ---------- 本地选择 ----------

    /// <summary>
    /// 本页已知的可信配置：已建立会话的配置优先；尚未连接时用已完整校验备份记录里的配置。
    /// 界面没有型号下拉，执行层随后改为完全自动识别。
    /// </summary>
    private EdlDeviceProfile? SelectedGlobalProfile() =>
        _globalProfile
        ?? (_globalRestoreSet is null
            ? null
            : EdlDeviceProfiles.FindById(_globalRestoreSet.Identity.ProfileId));

    private void OnGlobalRestoreConsentChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready || _globalOperationActive)
        {
            return;
        }

        RefreshGlobalRecoveryActions();
    }

    private void OnGlobalBrowseBackup(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _globalOperationActive || _globalRestoreUncertain
            || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        if (_globalEdlClient is not null || _globalEntryAttempted)
        {
            return;
        }

        string? chosen = PickExistingDirectory(_globalOutputParent, "Dynamic.Global.Dialog.PickOutput");
        if (chosen is null)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(_globalRestoreSource)
            && !IsInternalInstallBackupParentOutsideExisting(chosen, _globalRestoreSource!))
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputInsideRestoreSource");
            return;
        }

        // 输出父目录变化只作废本页准备，绝不改写还原来源框。
        InvalidateGlobalRestorePreparation();
        _globalOutputParent = chosen;
        GlobalBackupDirectoryBox.Text = chosen;
        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.OutputSelected");
        RefreshGlobalRecoveryActions();
    }

    private void OnGlobalBrowseRestore(object sender, RoutedEventArgs e)
    {
        // 备份视图里没有恢复来源控件；即使被程序触发也不接受。
        if (_globalRecoveryMode != GlobalRecoveryMode.Restore)
        {
            return;
        }

        // 写入已尝试后不再允许切换来源；已连接但未写入时允许更换，由准备阶段核对真实身份。
        if (!_ready || _busy || _globalOperationActive || _globalRestoreUncertain
            || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        string? chosen = PickExistingDirectory(_globalRestoreSource, "Dynamic.Global.Dialog.PickRestore");
        if (chosen is null)
        {
            return;
        }

        // 输出父目录必须位于还原来源之外，避免把证据写进用户备份树。
        if (!string.IsNullOrWhiteSpace(_globalOutputParent)
            && !IsInternalInstallBackupParentOutsideExisting(_globalOutputParent!, chosen))
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputInsideRestoreSource");
            return;
        }

        _globalRestoreSource = chosen;
        GlobalRestoreDirectoryBox.Text = chosen;
        InvalidateGlobalRestorePreparation();
        SetText(GlobalRestoreSummaryText, "Dynamic.Global.Restore.NotPrepared");
        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.RestoreSourceSelected");
        RefreshGlobalRecoveryActions();
    }

    private string? PickExistingDirectory(string? initial, string titleKey)
    {
        var dialog = new OpenFolderDialog
        {
            Title = T(titleKey),
            Multiselect = false,
        };

        if (!string.IsNullOrWhiteSpace(initial))
        {
            dialog.InitialDirectory = initial;
        }

        if (dialog.ShowDialog(this) != true || string.IsNullOrWhiteSpace(dialog.FolderName))
        {
            return null;
        }

        string candidate = dialog.FolderName;
        return System.IO.Directory.Exists(candidate) ? candidate : null;
    }

    private bool GlobalRestoreDirectoriesValid()
    {
        if (string.IsNullOrWhiteSpace(_globalRestoreSource) || string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            return false;
        }

        try
        {
            return IsInternalInstallBackupParentOutsideExisting(_globalOutputParent!, _globalRestoreSource!);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>只作废本地准备对象：不删备份、不删证据、不触碰设备。</summary>
    private void InvalidateGlobalRestorePreparation()
    {
        DisposeGlobalRestorePreparation();

        if (_ready && GlobalRestoreConfirmCheck is not null)
        {
            GlobalRestoreConfirmCheck.IsChecked = false;
        }
    }

    private void DisposeGlobalRestorePreparation()
    {
        _globalRestorePlan?.Dispose();
        _globalRestorePlan = null;
        _globalRestoreSet?.Dispose();
        _globalRestoreSet = null;
        _globalRestoreWriteAttempted = false;
        _globalRestoreSucceeded = false;
    }

    /// <summary>
    /// 只用备份身份核对内置可信配置：身份未知、配置不完整或与身份不一致时直接拒绝。
    /// 这里不写任何控件状态（没有下拉可写），也不做设备 IO。
    /// </summary>
    private void SelectGlobalProfileFromIdentity(GlobalEdlIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        EdlDeviceProfile? profile = EdlDeviceProfiles.FindById(identity.ProfileId);
        if (profile is null
            || !profile.IsComplete
            || !string.Equals(profile.ProfileId, identity.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                T("Dynamic.Global.Error.RestoreProfileUnsupported", identity.Model));
        }
    }

    // ---------- 渲染 ----------

    private void RenderGlobalConnection()
    {
        if (!_ready)
        {
            return;
        }

        if (_globalEdlClient is null && !_globalEntryAttempted
            && !_globalResetUnknown && !_globalRestoreUncertain)
        {
            SetText(GlobalConnectionText, "Dynamic.Global.Connection.NotConnected");
            return;
        }

        // 只有初始 Sahara 证明才能说「已核实」；未知重置或未确定写入会掩盖过期证明。
        if (_globalEdlClient?.HasInitialSaharaProof != true
            || _globalResetUnknown
            || _globalRestoreUncertain)
        {
            SetText(GlobalConnectionText, "Dynamic.Global.Connection.Unverified");
            return;
        }

        string model = _globalProfile?.Model ?? _globalEdlEntry?.OfflineIdentity?.Model ?? UnknownValue;
        string bus = _globalEdlEntry?.BusSerialHex ?? UnknownValue;

        // 只说「维护连接已核实」，绝不说备份完成或整机就绪。
        SetText(GlobalConnectionText, "Dynamic.Global.Connection.Verified", model, bus);
    }

    private void RenderGlobalPower()
    {
        if (!_ready)
        {
            return;
        }

        var sample = _globalPower;
        if (sample is null)
        {
            SetText(GlobalPowerText, "Dynamic.InternalInstall.Power.Unknown");
            return;
        }

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

        SetText(GlobalPowerText, "Dynamic.InternalInstall.Power.Sample", percent, external, time);
    }

    private string FormatGlobalPowerForDialog()
    {
        var sample = _globalPower;
        if (sample is null)
        {
            return T("Dynamic.InternalInstall.Power.Unknown");
        }

        object percent = sample.Percentage is int value
            ? string.Format(CultureInfo.CurrentCulture, "{0}%", value)
            : T("Dynamic.InternalInstall.Power.PercentUnknown");
        string external = sample.ExternalPower switch
        {
            true => T("Dynamic.UninstallFlow.Common.Yes"),
            false => T("Dynamic.UninstallFlow.Common.No"),
            _ => T("Dynamic.InternalInstall.Power.ExternalUnknown"),
        };
        string time = sample.CapturedAt == default
            ? T("Dynamic.InternalInstall.Power.TimeUnknown")
            : sample.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);

        return T("Dynamic.InternalInstall.Power.Sample", percent, external, time);
    }

    // ---------- 进度 ----------

    private IProgress<GlobalEdlProgress> BeginGlobalProgress()
    {
        _globalProgressActive = true;
        _globalProgressStage = null;
        _globalLastProgressAt = DateTime.MinValue;

        if (GlobalProgressBar is not null)
        {
            GlobalProgressBar.IsIndeterminate = true;
            GlobalProgressBar.Maximum = 100;
            GlobalProgressBar.Value = 0;
        }

        return new Progress<GlobalEdlProgress>(RenderGlobalProgress);
    }

    private void EndGlobalProgress()
    {
        _globalProgressActive = false;
        _globalProgressStage = null;

        if (!_ready || GlobalProgressBar is null)
        {
            return;
        }

        // 只结束不确定进度；已有真实分数或完成标记不得被清零。
        GlobalProgressBar.IsIndeterminate = false;
    }

    /// <summary>固定阶段映射到本地化键；只有真实字节数参与分母，压缩占用从不出现。</summary>
    private void RenderGlobalProgress(GlobalEdlProgress progress)
    {
        if (!_globalProgressActive || !_ready || progress is null)
        {
            return;
        }

        var stageMessage = M("Dynamic.Global.Stage." + NormalizeGlobalStage(progress.Stage));
        bool stageChanged = !string.Equals(_globalProgressStage, progress.Stage, StringComparison.Ordinal);
        DateTime now = DateTime.UtcNow;

        // 阶段变化立即刷新并记录；普通进度最多每秒刷新一次，避免瞬间写满日志。
        if (!stageChanged && (now - _globalLastProgressAt) < TimeSpan.FromSeconds(1))
        {
            return;
        }

        _globalLastProgressAt = now;
        _globalProgressStage = progress.Stage;

        object role = string.IsNullOrWhiteSpace(progress.Role)
            ? M("Dynamic.Global.Progress.NoRole")
            : progress.Role!;
        object lun = progress.Lun is int index
            ? index.ToString(CultureInfo.InvariantCulture)
            : M("Dynamic.Global.Progress.NoLun");

        SetText(
            GlobalProgressStatusText,
            "Dynamic.Global.Progress.Status",
            stageMessage,
            role,
            lun,
            FormatGlobalBytes(progress.CompletedBytes),
            progress.TotalBytes > 0
                ? FormatGlobalBytes(progress.TotalBytes)
                : M("Dynamic.Global.Progress.UnknownTotal"));

        if (GlobalProgressBar is not null)
        {
            if (progress.TotalBytes > 0)
            {
                GlobalProgressBar.IsIndeterminate = false;
                GlobalProgressBar.Maximum = progress.TotalBytes;
                GlobalProgressBar.Value = Math.Min(progress.CompletedBytes, progress.TotalBytes);
            }
            else
            {
                GlobalProgressBar.IsIndeterminate = true;
            }
        }

        if (stageChanged)
        {
            AppendLocalizedLog(M("Dynamic.Global.Log.Stage", stageMessage));
        }
    }

    private static string NormalizeGlobalStage(string stage)
    {
        switch (stage)
        {
            case "probe":
                return "Probe";
            case "read-gpt":
                return "ReadGpt";
            case "read-partition":
                return "ReadPartition";
            case "compress":
                return "Compress";
            case "verify-compression":
                return "VerifyCompression";
            case "verify-backup":
                return "VerifyBackup";
            case "prepare-restore":
                return "PrepareRestore";
            case "write-partition":
                return "WritePartition";
            case "readback-partition":
                return "ReadbackPartition";
            case "write-gpt":
                return "WriteGpt";
            case "readback-gpt":
                return "ReadbackGpt";
            case "initialize-android":
                return "InitializeAndroid";
            case "completed":
                return "Completed";
            default:
                return "Unknown";
        }
    }

    private static string FormatGlobalBytes(long bytes)
    {
        const double GiB = 1024d * 1024d * 1024d;
        const double MiB = 1024d * 1024d;
        const double KiB = 1024d;

        if (bytes >= GiB)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0:0.##} GiB", bytes / GiB);
        }

        if (bytes >= MiB)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0:0.##} MiB", bytes / MiB);
        }

        if (bytes >= KiB)
        {
            return string.Format(CultureInfo.CurrentCulture, "{0:0.##} KiB", bytes / KiB);
        }

        return string.Format(CultureInfo.CurrentCulture, "{0} B", bytes);
    }

    private static string FormatGlobalGiB(long bytes) =>
        string.Format(CultureInfo.CurrentCulture, "{0:0.##} GiB", bytes / (1024d * 1024d * 1024d));
}
