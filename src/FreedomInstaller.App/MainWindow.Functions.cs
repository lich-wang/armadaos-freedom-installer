using System;
using System.Windows;
using System.Windows.Controls;

namespace FreedomInstaller.App;

/// <summary>
/// 功能选择（应用入口）与「功能 → 向导」的视图切换。
/// <para>
/// 首页给出七张卡片：五张操作卡片各自进入一个原有向导，另外两张 9008 全局备份 / 恢复卡片
/// 直接打开全局页视图，不写入操作标签；选中一张就进入原有向导，向导的任意一步都能回到首页重新选择。
/// 这里只持有两个状态：当前选中的操作标签 <see cref="_selectedOperation"/>，
/// 以及当前是否停在首页 <see cref="_showingHome"/>。设备身份、真实分区、安装包路径与日志
/// 仍然留在 <c>MainWindow.xaml.cs</c> 的字段里，换功能时只清理由「上一次操作」派生出来的计划对象。
/// </para>
/// <para>
/// 首页与向导两侧的父容器可见性只由 <see cref="ApplyFunctionView"/> 决定，
/// 任何入口（启动、选卡片、返回、换语言、换主题、刷新按钮）都不会各写一套。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>默认操作：安装到内部存储（与旧版本的默认模式一致）。</summary>
    private const string DefaultOperation = "install";

    /// <summary>当前选中的操作标签，取值与首页五种操作卡片的 <c>Tag</c> 对应；
    /// <c>install-tf</c> 只为旧启动参数与待处理恢复保留，首页不提供入口。</summary>
    private string _selectedOperation = DefaultOperation;

    /// <summary>true 表示正停在功能首页；false 表示正在某个功能的向导里。</summary>
    private bool _showingHome = true;

    // ---------- 操作标签 ----------

    /// <summary>当前操作标签。取代原先读下拉菜单的实现：模式不再由控件保存。</summary>
    private string CurrentModeTag() => _selectedOperation;

    /// <summary>已知操作标签（含仅为旧参数 / 待处理恢复保留的 install-tf）。</summary>
    private static bool IsKnownOperation(string? tag) =>
        tag is "install" or "install-tf" or "prepare" or "repair" or "restore" or "uninstall";

    /// <summary>首页可选择的标签：已知标签中排除暂时关闭的 TF 卡安装。</summary>
    private static bool IsSelectableOperation(string? tag) =>
        IsKnownOperation(tag) && tag != "install-tf";

    /// <summary>两种安装（内部存储 / TF 卡）共用安装包校验与风险确认。</summary>
    private static bool IsInstallOperation(string mode) => mode is "install" or "install-tf";

    // ---------- 首页事件 ----------

    /// <summary>
    /// 点击首页卡片：校验标签、按需清理由上一操作派生的状态，然后进入原有向导的第一步。
    /// 设备身份、真实分区、工具目录、安装包路径与日志始终保留。
    /// </summary>
    private async void OnSelectOperation(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        // 全局救援页或受保护现场存在时不允许换功能，避免丢掉可核对的会话。
        if (_showingGlobalRecovery || HasGlobalRecoveryProtectedState)
        {
            return;
        }

        // 准备页未完成时不允许绕过它进入功能向导。
        if (_showingEnvironment || !EnvironmentIsReady)
        {
            return;
        }

        // 平板恢复现场仍待处理：先打开恢复页，未知 / 未完成的临时写入不能逃进其它五张卡片。
        if (HasPendingTfTabletRecovery)
        {
            ForceOpenTfTabletRecoveryPage();
            return;
        }

        // 卸载事务受保护时不允许换功能，否则界面会丢掉仍在设备上的事务。
        if (HasProtectedUninstallState)
        {
            return;
        }

        if (sender is not Button card || card.Tag is not string tag || !IsSelectableOperation(tag))
        {
            return;
        }

        var operationChanged = !string.Equals(tag, _selectedOperation, StringComparison.Ordinal);

        // TF 卡安装优先：离开 TF 走自己的确认例程并异步释放工作流；拒绝时不改变任何状态。
        if (operationChanged && IsModernTfInstallMode)
        {
            if (!await ConfirmLeaveModernTfInstallAsync())
            {
                return;
            }

            await SafeResetModernTfInstallStateAsync();
        }
        // 现代卸载优先：离开卸载走自己的确认例程（预写入会复位一次）；拒绝时不改变任何状态。
        else if (operationChanged && IsModernUserdataUninstallMode)
        {
            if (!await ConfirmLeaveModernUserdataUninstallAsync())
            {
                return;
            }

            SafeResetModernUserdataUninstallState();
        }
        // 维护模式优先：离开维护走自己的确认例程；拒绝时不改变任何状态，也不进旧安装确认。
        else if (operationChanged && IsBootMaintenanceMode)
        {
            if (!await ConfirmLeaveBootMaintenanceAsync())
            {
                return;
            }

            ResetBootMaintenanceUiState();
        }
        else if (operationChanged
            && (HasInternalInstallLiveEdlState || HasInternalInstallExecutionStarted)
            && !await ConfirmExitInternalInstallMaintenanceAsync())
        {
            return;
        }

        _selectedOperation = tag;
        _showingHome = false;

        if (operationChanged)
        {
            // 卸载侧的准备事务、维护会话与原始路径属于上一种操作，先整体回到初始状态。
            ResetUninstallState();

            // 上一次导入的准备结果属于上一种操作：先释放它拥有的解包目录，再清空派生状态。
            var packageReleased = ReleasePreparedPackage();

            // 计划、校验结果与「容量已初始化」都属于上一种操作：清掉，避免把它们的结论带进新操作。
            _plan = null;
            _restorePlan = null;
            _capacityInitialized = false;

            // TF 卡的目标卡、读取结果与容量计划同样属于上一种操作：换功能时连候选列表一起清掉，
            // 避免把上一次读到的卡片直接当成新功能的写入目标。
            ResetTfSelection(clearInventory: true);

            // 校验结果被清掉后，状态行也必须回到「未校验」，不能继续显示上一次的通过结论；
            // 安装包路径与目录本身保留，身份确认后会按实际型号与当前目标重新导入。
            if (packageReleased)
            {
                SetText(PackageStatusText, "Dynamic.Package.StatusNotValidated");
            }

            // 新的操作需要新的风险同意；取消勾选会同步触发 OnRiskChanged（幂等）。
            RiskCheck.IsChecked = false;

            // 内部存储安装的专属向导回到第一步；其余操作共用真实的共享四步页，页面状态由 Navigate 负责。
            ResetInternalInstallUiState();
        }

        // UpdateModeUi 内部会调用 RenderModeTexts，把文案、导航标签与当前功能名一起重写。
        UpdateModeUi();

        // 两种安装都要求先看到开发者选项与 USB 调试的图片引导；其余操作的折叠区交给用户自己控制。
        if (IsInstallOperation(tag))
        {
            SetSectionExpanded(ConnectHelpToggle, ConnectHelpPanel, true);
        }

        Navigate(0);
        ApplyFunctionView();
        AppendLocalizedLog(M("Dynamic.Log.ModeChanged", ModeMessage(tag)));

        if (operationChanged && tag == "uninstall" && _identity is not null)
        {
            // 旧三页进入卸载时的 ADB 读取已由共享真实检查取代：这里不再发起任何旧设备调用。
        }

        if (operationChanged && !IsModernTfInstallMode && HasImportInputs())
        {
            // 内部存储与 TF 卡的目标不同：换目标后必须按新目标重新导入 / 校验，不能沿用上一个目标的结论。
            await RunBusyAsync(ImportSelectedPackageAsync);
        }
    }

    /// <summary>
    /// 「← 功能选择」：只切回首页，不发起任何查询，也不清空任何已读到的状态
    /// （路径、勾选、计划与日志都原样保留，重新进入同一功能时可以继续）。
    /// 平板仍处于 9008 维护状态时，先走与关闭窗口相同的显式退出流程。
    /// </summary>
    private async void OnBackToFunctions(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // 全局救援页受保护现场存在时不允许离开，避免丢掉仍在设备上的会话。
        if (HasGlobalRecoveryProtectedState)
        {
            return;
        }

        // 只有真实核对返回安卓、或真实安装已完成之后才回首页；其余情况保留当前功能与现场。
        // TF 卡安装优先：走 TF 自己的离开确认并异步释放工作流，绝不进入旧安装的 ADB 等待。
        if (IsModernTfInstallMode)
        {
            if (!await ConfirmLeaveModernTfInstallAsync())
            {
                return;
            }

            await SafeResetModernTfInstallStateAsync();
            ShowFunctionHome();
            return;
        }

        // 现代卸载优先：走卸载自己的离开确认（预写入时一次复位），绝不进入旧安装的 ADB 等待。
        if (IsModernUserdataUninstallMode)
        {
            if (!await ConfirmLeaveModernUserdataUninstallAsync())
            {
                return;
            }

            SafeResetModernUserdataUninstallState();
            ShowFunctionHome();
            return;
        }

        // 维护模式优先：走维护自己的离开确认，绝不进入旧安装的 ADB 等待。
        if (IsBootMaintenanceMode)
        {
            if (!await ConfirmLeaveBootMaintenanceAsync())
            {
                return;
            }

            ResetBootMaintenanceUiState();
            ShowFunctionHome();
            return;
        }

        if ((HasInternalInstallLiveEdlState || HasInternalInstallExecutionStarted)
            && !await ConfirmExitInternalInstallMaintenanceAsync())
        {
            return;
        }

        ShowFunctionHome();
    }

    /// <summary>启动时与「← 功能选择」共用：把视图切到首页。</summary>
    private void ShowFunctionHome()
    {
        // 全局救援受保护现场优先：不切首页，留在本页原来的视图。
        if (HasGlobalRecoveryProtectedState)
        {
            ResumeGlobalRecoveryPage();
            return;
        }

        // 平板恢复现场仍待处理：先打开恢复页，不展示首页。
        if (HasPendingTfTabletRecovery)
        {
            ForceOpenTfTabletRecoveryPage();
            return;
        }

        _showingGlobalRecovery = false;
        _showingHome = true;
        ApplyFunctionView();
    }

    // ---------- 视图 ----------

    /// <summary>首页 / 向导 / 支持页的父容器可见性：唯一入口，重复调用结果一致。</summary>
    private void ApplyFunctionView()
    {
        // 准备页、首页、向导与支持页互斥；支持页打开时三者都收起，返回后按原状态恢复。
        var environment = _showingEnvironment && !_showingSupport;
        var global = !_showingEnvironment && _showingGlobalRecovery && !_showingSupport;
        var home = !_showingEnvironment && _showingHome && !_showingSupport && !_showingGlobalRecovery;
        var workflow = !_showingEnvironment && !_showingHome && !_showingSupport && !_showingGlobalRecovery;

        // 首页占满主体三列；左侧步骤栏、向导正文与底栏的「上一步 / 下一步 / 执行」一起收起。
        EnvironmentPage.Visibility = environment ? Visibility.Visible : Visibility.Collapsed;
        HomePage.Visibility = home ? Visibility.Visible : Visibility.Collapsed;
        WorkflowSidebar.Visibility = workflow ? Visibility.Visible : Visibility.Collapsed;
        WorkflowScrollViewer.Visibility = workflow ? Visibility.Visible : Visibility.Collapsed;
        WorkflowButtons.Visibility = workflow ? Visibility.Visible : Visibility.Collapsed;
        HomeFooterHint.Visibility = home ? Visibility.Visible : Visibility.Collapsed;

        // 支持页同样占满三列，只在打开时显示；当前功能与选中操作始终不变。
        SupportPage.Visibility = _showingSupport ? Visibility.Visible : Visibility.Collapsed;

        // 全局救援页同样占满三列；只在它自己的标志下显示，不改选中操作。
        GlobalRecoveryPage.Visibility = global ? Visibility.Visible : Visibility.Collapsed;

        // 只在新旧向导内容与共享连接图示之间切换，不改首页 / 向导 / 支持页的父容器状态。
        ApplyInternalInstallView();
    }

    /// <summary>
    /// 侧栏的「← 功能选择」与当前功能名按选中标签重新渲染。
    /// 这两处不是导航状态，所以语言切换后重写一遍即可：既不跳页，也不清空任何输入。
    /// </summary>
    private void RerenderSelectedOperation()
    {
        SetContent(BackToFunctionsButton, "Dynamic.BackToFunctions");
        SetText(SelectedOperationText, ModeMessage(_selectedOperation));
    }
}
