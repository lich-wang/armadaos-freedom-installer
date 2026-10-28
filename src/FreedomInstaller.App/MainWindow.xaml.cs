using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using FreedomInstaller.Core;
using Microsoft.Win32;

namespace FreedomInstaller.App;

/// <summary>
/// 单窗口安装助手。只读能力保留：<see cref="DeviceTransport.ListDevicesAsync"/>、
/// <see cref="ReadAdbIdentityAsync"/>、<see cref="CheckFastbootAsync"/>、维护助手 inspect-layout、
/// <see cref="PackageReader.Validate"/>、TF 卡发现与容量估算（见 <c>MainWindow.TfCards.cs</c>），
/// 以及卸载侧的 <see cref="UninstallPlanner.Plan"/>。
/// <para>
/// 没有任何演练 / 模拟入口：所有数字要么来自真实读取，要么显示「—」并说明缺什么输入；
/// 卸载写入只在本流程校验通过、勾选风险并经二次确认后开放。
/// </para>
/// <para>
/// 本文件里所有面向用户的动态文案都通过稳定键名（前缀 <c>Dynamic.</c>）取自
/// <c>Resources/Dynamic.*.json</c>，不再在代码里拼接已翻译的句子：
/// 日志与摘要保存的是消息本身（键名 + 参数），切换语言后可以按当前语言重新渲染。
/// </para>
/// </summary>
public partial class MainWindow : Window
{
    private const long Gibibyte = 1024L * 1024L * 1024L;

    private const string UnknownValue = "—";

    private const string BilibiliUrl = "https://space.bilibili.com/258786";

    private const string GithubUrl = "https://github.com/mydanyi";

    /// <summary>「打开作者主页」两条日志用的标签键，品牌名无需翻译，只翻译上下文。</summary>
    private const string BilibiliLabelKey = "Dynamic.Link.Bilibili";

    private const string GithubLabelKey = "Dynamic.Link.Github";

    /// <summary>DWMWA_USE_IMMERSIVE_DARK_MODE：让原生标题栏跟随主题；调用失败不影响任何功能。</summary>
    private const int DwmUseImmersiveDarkMode = 20;

    private static readonly JsonSerializerOptions InstallationRecordJson = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private readonly ProcessRunner _runner = new();

    private readonly UserPreferences _preferences = UserPreferences.Load();

    private ResourceDictionary? _themeDictionary;

    private DeviceTransport? _transport;

    private DeviceIdentity? _identity;

    private DiskLayout? _layout;

    private string? _layoutFingerprint;

    /// <summary>
    /// 最近一次由 Core <see cref="InternalStorageReader"/> 返回的容量快照。只有维护环境的快照带分区表；
    /// 普通 Android 的快照只有 /data 文件系统容量，所以它永远不会被当成 <see cref="_layout"/> 使用。
    /// </summary>
    private InternalStorageSnapshot? _storage;

    private PackageValidationResult? _package;

    private IReadOnlyList<ConnectedDevice> _devices = Array.Empty<ConnectedDevice>();

    private AllocationPlan? _plan;

    private LinuxInstallationLayout? _installationRecord;

    private AndroidRestorePlan? _restorePlan;

    private CancellationTokenSource? _cts;

    /// <summary>
    /// 设备给出的最低 Android 容量。0 表示尚未确认：此时不给可选范围，也不退回到任何默认值
    /// （例如 16 GiB），<see cref="PartitionPlanner.GetAndroidRange"/> 也会直接拒绝 0。
    /// </summary>
    private int _minimumAndroidGiB;

    private int _page;

    private bool _ready;

    private bool _busy;

    private bool _suppressCapacitySync;

    private bool _capacityInitialized;

    private bool _suppressNav;

    /// <summary>
    /// 引导状态当前的消息（键名 + 参数），不是渲染后的文字：
    /// 字段文本与摘要都从它重新渲染，切换语言时不会留在旧语言上。
    /// </summary>
    private UiMessage? _bootStateMessage;

    /// <summary>容量卡片正文 / 规则行的消息，切换语言时按原消息重新渲染。</summary>
    private UiMessage? _capacityNote;

    private UiMessage? _capacityRule;

    public MainWindow()
    {
        InitializeComponent();
        InitializeLocalization();
        _bootStateMessage = M("Dynamic.BootState.Pending");

        // 启动时先按「未读取设备」渲染引导兼容性：面板在未连接时也必须可读，
        // 而且第一帧就要是本地化文案，而不是等第一次检测后才出现。
        RenderBootRoute();
        ApplyTheme(_preferences.IsDark);
        RenderThemeToggle();
        SourceInitialized += OnSourceInitialized;
        Loaded += OnLoaded;
        Closing += OnUninstallClosing;
        Closing += OnInternalInstallClosing;
        Closing += OnEnvironmentClosing;
        Closing += (_, e) => OnGlobalRecoveryClosing(e);
    }

    // ---------- 生命周期 ----------

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;

        _ready = true;

        // 启动时只读恢复待处理的平板恢复现场；只读缓存，不路由功能、不改 Ready、不发起设备 IO。
        await ReadPendingTfTabletRecoveryAsync();

        // 首次进入时按当前模式决定是否默认展开「连接 / USB 调试」指南：
        // 安装模式下新用户必须看到开发者选项与 USB 调试步骤，其余面板一律保持折叠。
        SetSectionExpanded(ConnectHelpToggle, ConnectHelpPanel, CurrentModeTag() == "install");
        SetSectionExpanded(AdvancedToggle, AdvancedPanel, false);
        SetSectionExpanded(DetailsToggle, DetailsPanel, false);
        SetSectionExpanded(LogToggle, LogPanel, false);

        UpdateModeUi();
        Navigate(0);
        RefreshActions();

        // Navigate(0) 只是把向导渲染在（首页状态下）隐藏的容器里。这里最后统一按首页状态
        // 决定父容器可见性，保证启动后先看到功能选择，而不是某个默认操作的第一步。
        ApplyFunctionView();

        AppendLocalizedLog(M("Dynamic.Log.Ready"));

        // 先进入运行环境准备页做一次只读自检；准备完成由用户自己点「继续」进入功能首页。
        await InitializeEnvironmentAsync();
    }

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;

        // 全局救援：只释放本页自有托管对象，不删除用户备份或证据目录。
        DisposeGlobalRecoveryOnClose();

        // 现代卸载：只在运行已解决（无活动、无未解决、无真实 9008 会话）时释放自有对象；
        // 未解决现场完整保留 menu/original/backend 与证据文件，不做任何清理。
        DisposeModernUserdataUninstallResourcesOnClose();

        // 只有未被事务保护、或用户在等待清除数据的提示里明确同意关闭时，才释放本流程拥有的对象；
        // 不删除用户文件、已有备份，也不结束任何外部进程。
        if (_uninstallCloseApproved || !HasProtectedUninstallState)
        {
            DisposeUninstallState();
        }

        // 只取消本窗口自己发起的查询，不碰任何已在运行的 adb 服务。
        _cts?.Cancel();

        // 先捕获未确认写入 / 未知复位事实：后续释放后端会把快照来源清空，届时再算会失真。
        var preserveBootMaintenanceRepairFiles =
            HasUnconfirmedBootMaintenanceWrite || HasUnknownBootMaintenanceReset;

        // 维护后端只拥有自己的租约：已批准关闭且没有活动操作时先释放它，再走共享释放。
        // 不做任何设备调用；备份与证据文件全部保留，工具链 GUID 清理沿用既有逻辑。
        if (_bootMaintenanceCloseApproved
            && !_bootMaintenanceOperationActive
            && _bootMaintenanceBackend is { } backend)
        {
            backend.Dispose();
            _bootMaintenanceBackend = null;
        }

        // 已导入的修复包只在没有未确认写入、没有未知复位时释放（用上面捕获的事实判断）；
        // 未知写入 / 复位必须保留解包与证据文件，绝不做破坏性清理。
        if (!_bootMaintenanceOperationActive
            && !preserveBootMaintenanceRepairFiles)
        {
            ReleaseBootMaintenanceRepairPackage();
        }

        // 内部存储安装：关闭钩子已经拒绝在有活动操作时退出；写入开始后只有正常关闭批准
        // 或真实 Completed 才释放本程序自己的资源。备份文件与证据目录始终保留。
        if (!_internalInstallOperationActive
            && !ProtectedModernTfInstallState
            && !HasAnyPreparedModernTfInstall
            && (_internalInstallPostWriteCloseApproved
                || IsCompletedInternalInstallExecution
                || (!HasInternalInstallExecutionStarted && !HasInternalInstallLiveEdlState)))
        {
            DisposeInternalInstallResources();
        }

        // 释放本次导入拥有的 ZIP 解包目录；调用方原始的 ZIP / 目录不归本实例所有。
        DisposePreparedPackageOnClose();

        base.OnClosed(e);
    }

    /// <summary>
    /// 先让界面可用，再在后台解包随附工具；解包失败只在工具状态里说明，界面仍然可以手动选目录。
    /// </summary>
    private async Task<bool> InitializeBundledToolsAsync()
    {
        SetText(ToolsStatusText, "Dynamic.ToolsStatus.Preparing");
        try
        {
            var directory = await Task.Run(() => BundledTools.EnsureAvailable());
            if (string.IsNullOrWhiteSpace(directory))
            {
                SetText(ToolsStatusText, "Dynamic.ToolsStatus.BundledMissing");
                AppendLocalizedLog(M("Dynamic.Log.BundledToolsMissing"));
                return false;
            }

            ToolsPathBox.Text = directory;
            AppendLocalizedLog(M("Dynamic.Log.BundledToolsReady"));
            return true;
        }
        catch (Exception exception) when (exception is IOException
            or InvalidOperationException
            or UnauthorizedAccessException
            or InvalidDataException)
        {
            SetText(ToolsStatusText, "Dynamic.ToolsStatus.PrepareFailed", exception.Message);
            AppendLocalizedLog(M("Dynamic.Log.BundledToolsFailed", exception.Message));
            return false;
        }
    }

    private void OnSourceInitialized(object? sender, EventArgs e) => ApplyNativeTitleBar(_preferences.IsDark);

    // ---------- 主题 ----------

    private void OnToggleTheme(object sender, RoutedEventArgs e)
    {
        _preferences.Toggle();
        ApplyTheme(_preferences.IsDark);
        RenderThemeToggle();
        _preferences.Save();
        AppendLocalizedLog(M(_preferences.IsDark ? "Dynamic.Log.ThemeDark" : "Dynamic.Log.ThemeLight"));
    }

    private void ApplyTheme(bool dark)
    {
        var dictionary = LoadThemeDictionary(dark);
        if (_themeDictionary is not null)
        {
            Resources.MergedDictionaries.Remove(_themeDictionary);
        }

        _themeDictionary = dictionary;
        Resources.MergedDictionaries.Insert(0, dictionary);
        ApplyNativeTitleBar(dark);
    }

    /// <summary>主题按钮的文字与提示都是动态文案，按当前语言重新渲染。</summary>
    private void RenderThemeToggle()
    {
        SetText(ThemeToggleText, _preferences.IsDark ? "Dynamic.Theme.SwitchToLight" : "Dynamic.Theme.SwitchToDark");
        ThemeToggleButton.ToolTip = T(_preferences.IsDark ? "Dynamic.Theme.TooltipDark" : "Dynamic.Theme.TooltipLight");
    }

    /// <summary>
    /// 载入一份主题字典。正常情况下读取打包进程序集的 Themes/*.xaml；
    /// 如果资源没能编进程序集，则退回内置调色板，保证界面不会因为主题问题启动失败。
    /// </summary>
    private static ResourceDictionary LoadThemeDictionary(bool dark)
    {
        var relative = dark ? "Themes/Dark.xaml" : "Themes/Light.xaml";
        try
        {
            return new ResourceDictionary { Source = new Uri(relative, UriKind.Relative) };
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return BuildFallbackPalette(dark);
        }
    }

    /// <summary>内置调色板，键名与色值同 Themes/*.xaml 保持一致。</summary>
    private static ResourceDictionary BuildFallbackPalette(bool dark)
    {
        var pairs = dark
            ? new[]
            {
                ("CanvasBrush", "#17191D"),
                ("SurfaceBrush", "#22252A"),
                ("SurfaceAltBrush", "#1B1E22"),
                ("InkBrush", "#F3F4F6"),
                ("MutedBrush", "#A1A6B0"),
                ("AccentBrush", "#B8E46B"),
                ("AccentHoverBrush", "#C9ED8A"),
                ("AccentInkBrush", "#10130A"),
                ("AccentSoftBrush", "#2A3320"),
                ("LinuxSegmentBrush", "#8FB6D2"),
                ("StrokeBrush", "#363A42"),
                ("WarnBrush", "#E3B341"),
                ("DangerBrush", "#F07178"),
                ("HoverBrush", "#2B2F35"),
                ("SelectedBrush", "#2E3525"),
                ("FocusBrush", "#B8E46B"),
                ("ScrollThumbBrush", "#4A4F58"),
            }
            : new[]
            {
                ("CanvasBrush", "#F5F6FA"),
                ("SurfaceBrush", "#FFFFFF"),
                ("SurfaceAltBrush", "#EFF1F6"),
                ("InkBrush", "#111827"),
                ("MutedBrush", "#6B7280"),
                ("AccentBrush", "#6366F1"),
                ("AccentHoverBrush", "#4F46E5"),
                ("AccentInkBrush", "#FFFFFF"),
                ("AccentSoftBrush", "#ECEEFE"),
                ("LinuxSegmentBrush", "#8FB6D2"),
                ("StrokeBrush", "#E4E7EF"),
                ("WarnBrush", "#B45309"),
                ("DangerBrush", "#B91C1C"),
                ("HoverBrush", "#EEF0F6"),
                ("SelectedBrush", "#E5E8FB"),
                ("FocusBrush", "#6366F1"),
                ("ScrollThumbBrush", "#C7CCD8"),
            };

        var dictionary = new ResourceDictionary();
        foreach (var (key, value) in pairs)
        {
            var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
            brush.Freeze();
            dictionary[key] = brush;
        }

        return dictionary;
    }

    /// <summary>原生标题栏跟随主题；DWM 属性不可用时静默跳过，不打扰用户。</summary>
    private void ApplyNativeTitleBar(bool dark)
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            if (handle == IntPtr.Zero)
            {
                return;
            }

            var value = dark ? 1 : 0;
            _ = DwmSetWindowAttribute(handle, DwmUseImmersiveDarkMode, ref value, sizeof(int));
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            // 旧系统上没有该入口：标题栏保持系统默认外观。
        }
    }

    [DllImport("dwmapi.dll", SetLastError = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    // ---------- 页面切换 ----------

    private void OnNavChecked(object sender, RoutedEventArgs e)
    {
        if (!_ready || _suppressNav)
        {
            return;
        }

        // 内部存储安装使用独立的四步向导，旧三页标签在这个模式下不参与导航。
        if (IsInternalInstallMode)
        {
            return;
        }

        if (ReferenceEquals(sender, NavConnect))
        {
            Navigate(0);
        }
        else if (ReferenceEquals(sender, NavCapacity))
        {
            Navigate(1);
        }
        else if (ReferenceEquals(sender, NavConfirm))
        {
            Navigate(2);
        }
    }

    private async void OnNextPage(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        // 卸载（现代四步向导）优先：与维护同构，来源页「下一步」是真实只读准备。
        if (IsModernUserdataUninstallMode)
        {
            if (_internalInstallStep == 2)
            {
                await PrepareModernUserdataUninstallConfirmationAsync();
                return;
            }

            NavigateModernUserdataUninstallStep(_internalInstallStep + 1);
            return;
        }

        // TF 卡安装优先：与卸载 / 维护同构，来源页（第 2 步）的「下一步」是真实准备。
        if (IsModernTfInstallMode)
        {
            if (_internalInstallStep == 2)
            {
                await PrepareModernTfInstallConfirmationAsync();
                return;
            }

            await NavigateModernTfInstallStepAsync(_internalInstallStep + 1);
            return;
        }

        // 维护模式优先：来源页（第 2 步）的「下一步」是真实准备；其余维护步骤纯导航。
        if (IsBootMaintenanceMode)
        {
            if (_internalInstallStep == 2)
            {
                await PrepareBootMaintenanceConfirmationAsync();
                return;
            }

            NavigateBootMaintenanceStep(_internalInstallStep + 1);
            return;
        }

        if (IsInternalInstallMode)
        {
            // 第 3 步（分配空间）的「下一步」需要先完成一次真实主机侧准备；其余内部步骤仍是纯导航。
            if (_internalInstallStep == 2)
            {
                await PrepareInternalInstallConfirmationAsync();
                return;
            }

            NavigateInternalInstallStep(_internalInstallStep + 1);
            return;
        }

        if (_page == 0)
        {
            Navigate(IsCapacityPageApplicable() ? 1 : 2);
        }
        else if (_page == 1)
        {
            Navigate(2);
        }
    }

    private async void OnPreviousPage(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        // 卸载四步导航优先于维护：页码语义由卸载控制器解释。
        if (IsModernUserdataUninstallMode)
        {
            NavigateModernUserdataUninstallStep(_internalInstallStep - 1);
            return;
        }

        // TF 卡安装优先：上一步走 TF 自己的异步导航入口。
        if (IsModernTfInstallMode)
        {
            await NavigateModernTfInstallStepAsync(_internalInstallStep - 1);
            return;
        }

        // 维护模式优先：上一步走维护自己的导航入口。
        if (IsBootMaintenanceMode)
        {
            NavigateBootMaintenanceStep(_internalInstallStep - 1);
            return;
        }

        if (IsInternalInstallMode)
        {
            NavigateInternalInstallStep(_internalInstallStep - 1);
            return;
        }

        if (_page == 2)
        {
            Navigate(IsCapacityPageApplicable() ? 1 : 0);
        }
        else if (_page == 1)
        {
            Navigate(0);
        }
    }

    private void Navigate(int page)
    {
        // 内部存储安装有自己的四步导航；旧三页的页码语义在这里不再适用。
        // 卸载四步导航优先转发：页码语义完全由卸载控制器解释。
        if (IsModernUserdataUninstallMode)
        {
            NavigateModernUserdataUninstallStep(page);
            return;
        }

        if (IsBootMaintenanceMode)
        {
            // 维护模式优先转发：页码语义完全由维护控制器解释。
            NavigateBootMaintenanceStep(page);
            return;
        }

        if (IsModernTfInstallMode)
        {
            // TF 卡安装同步优先转发：只有初始页 0 在完全空闲且无未解决现场时可进入；
            // 其余页码语义由 TF 控制器的异步入口解释，绝不走旧三页的 page1/2。
            if (page == 0
                && !_busy
                && !ProtectedModernTfInstallState
                && !HasAnyPreparedModernTfInstall)
            {
                _internalInstallStep = 0;
                RefreshModernTfInstallActions();
                RenderModernTfInstallPages();
            }
            else
            {
                RestoreInternalInstallNav();
            }

            return;
        }

        if (IsInternalInstallMode)
        {
            NavigateInternalInstallStep(page);
            return;
        }

        page = Math.Clamp(page, 0, 2);
        if (page == 1 && !IsCapacityPageApplicable())
        {
            page = 2;
        }

        if (page != _page && !CanEnterLegacyWorkflowPage(page))
        {
            RestoreLegacyNavigationSelection();
            SetText(ActionReasonText, "Dynamic.Workflow.PreparationRequired", ModeMessage(CurrentModeTag()));
            AppendLocalizedLog(M("Dynamic.Workflow.PreparationRequired", ModeMessage(CurrentModeTag())));
            return;
        }

        _page = page;

        _suppressNav = true;
        try
        {
            NavConnect.IsChecked = page == 0;
            NavCapacity.IsChecked = page == 1;
            NavConfirm.IsChecked = page == 2;
        }
        finally
        {
            _suppressNav = false;
        }

        PageConnect.Visibility = page == 0 ? Visibility.Visible : Visibility.Collapsed;
        PageCapacity.Visibility = page == 1 ? Visibility.Visible : Visibility.Collapsed;
        PageConfirm.Visibility = page == 2 ? Visibility.Visible : Visibility.Collapsed;

        if (page == 1)
        {
            if (CurrentModeTag() == "uninstall")
            {
                UpdateUninstallPanel();
            }
            else
            {
                UpdateCapacityPanel();
            }
        }
        else if (page == 2)
        {
            UpdateSummary();
        }

        PrevButton.IsEnabled = page > 0 && !_busy;
        NextButton.Visibility = page < 2 ? Visibility.Visible : Visibility.Collapsed;
        ActionButton.Visibility = page == 2 ? Visibility.Visible : Visibility.Collapsed;

        // 分页本身只决定可见性；卸载侧还要按会话 / 已准备方案重新收紧「下一步」。
        RefreshUninstallActions();

        // 页面切换只改页内状态；首页 / 向导的父容器可见性与底栏按钮组仍由这一条统一决定。
        ApplyFunctionView();

        RefreshWorkflowRouteGates();
    }

    private bool IsCapacityPageApplicable() => CurrentModeTag() is "install" or "install-tf" or "uninstall";

    // ---------- 模式 ----------

    // CurrentModeTag() / OnModeChanged 已随安装模式下拉菜单一起移除：
    // 操作标签现在由首页卡片写入 _selectedOperation，实现见 MainWindow.Functions.cs。

    private void UpdateModeUi()
    {
        var mode = CurrentModeTag();
        var installMode = IsInstallOperation(mode);

        RenderModeTexts();

        // 分配空间卡片只属于「安装到内部存储」；TF 卡安装将来读的是卡上的分区，不显示内部滑条。
        CapacityInstallPanel.Visibility = mode == "install" ? Visibility.Visible : Visibility.Collapsed;
        UninstallPanel.Visibility = mode == "uninstall" ? Visibility.Visible : Visibility.Collapsed;
        PackageSection.Visibility = installMode ? Visibility.Visible : Visibility.Collapsed;

        // 设备 + 读取内部容量这一张卡是内部存储的读取入口，TF 卡安装时整卡隐藏。
        InternalLayoutSection.Visibility = mode == "install-tf" ? Visibility.Collapsed : Visibility.Visible;

        // 选择目标卡只属于「安装到 TF 卡」；内部安装与卸载都不显示这张卡。
        TfCardSection.Visibility = mode == "install-tf" ? Visibility.Visible : Visibility.Collapsed;
        UninstallInputSection.Visibility = mode == "uninstall" ? Visibility.Visible : Visibility.Collapsed;

        UninstallEdlSection.Visibility =
            mode == "uninstall" ? Visibility.Visible : Visibility.Collapsed;
        BootBackupSection.Visibility = mode == "uninstall" ? Visibility.Collapsed : Visibility.Visible;
        RiskSection.Visibility = installMode || mode == "uninstall" ? Visibility.Visible : Visibility.Collapsed;

        // 模式真正切换时仍然取消勾选：新的模式对应新的风险同意。
        RiskCheck.IsChecked = false;

        NavCapacity.IsEnabled = !_busy && IsCapacityPageApplicable();

        if (_page == 1 && !IsCapacityPageApplicable())
        {
            Navigate(2);
        }
        else if (_page == 1)
        {
            Navigate(1);
        }

        if (mode == "uninstall")
        {
            UpdateUninstallPanel();
        }
        else if (IsInstallOperation(mode))
        {
            // 两种安装都走这里：TF 卡安装由 UpdateCapacityPanel 内部转给卡片容量。
            UpdateCapacityPanel();
        }

        UpdateSummary();
        RefreshActions();
    }

    /// <summary>
    /// 只重写随模式变化的文案，不动任何可见性、勾选或导航状态：
    /// 语言切换后也需要这些文字跟着变，但绝不能顺手清掉用户已勾选的风险确认。
    /// </summary>
    private void RenderModeTexts()
    {
        var mode = CurrentModeTag();

        SetText(ModeHintText, ModeHintKey(mode));
        SetText(ConfirmTitleText, ConfirmTitleKey(mode));
        SetText(CapacityPageTitle, CapacityTitleKey(mode));
        SetText(CapacityPageLead, CapacityLeadKey(mode));
        SetText(RiskCheckText, RiskCheckKey(mode));
        SetContent(ActionButton, ActionLabelKey(mode));

        // 侧栏第二步的标题随功能变化（分配空间 / 选择 TF 卡 / 恢复空间），
        // 与「← 功能选择」和当前功能名一起在这里重写，语言切换后同样生效。
        SetText(NavCapacityLabel, NavCapacityKey(mode));
        RerenderSelectedOperation();

        // 卡片侧的说明、状态与容量计划也是登记过的消息：换语言时按原消息重写，不动选择状态。
        RenderTfTexts();
    }

    private static string? ModeLabelKey(string mode) => mode switch
    {
        "install" => "Dynamic.Mode.Install",
        "install-tf" => "Dynamic.Mode.InstallTf",
        "prepare" => "Dynamic.Mode.Prepare",
        "repair" => "Dynamic.Mode.Repair",
        "restore" => "Dynamic.Mode.Restore",
        "uninstall" => "Dynamic.Mode.Uninstall",
        _ => null,
    };

    private static string ModeHintKey(string mode) => mode switch
    {
        "install" => "Dynamic.ModeHint.Install",
        "install-tf" => "Dynamic.ModeHint.InstallTf",
        "prepare" => "Dynamic.ModeHint.Prepare",
        "repair" => "Dynamic.ModeHint.Repair",
        "restore" => "Dynamic.ModeHint.Restore",
        _ => "Dynamic.ModeHint.Uninstall",
    };

    private static string ConfirmTitleKey(string mode) => mode switch
    {
        "install" => "Dynamic.ConfirmTitle.Install",
        "install-tf" => "Dynamic.ConfirmTitle.InstallTf",
        "prepare" => "Dynamic.ConfirmTitle.Prepare",
        "repair" => "Dynamic.ConfirmTitle.Repair",
        "restore" => "Dynamic.ConfirmTitle.Restore",
        _ => "Dynamic.ConfirmTitle.Uninstall",
    };

    private static string ActionLabelKey(string mode) => mode switch
    {
        "install" => "Dynamic.Action.Install",
        "install-tf" => "Dynamic.Action.InstallTf",
        "prepare" => "Dynamic.Action.Prepare",
        "repair" => "Dynamic.Action.Repair",
        "restore" => "Dynamic.Action.Restore",
        _ => "Dynamic.Action.Uninstall",
    };

    /// <summary>容量页标题：内部安装「分配空间」、TF 卡安装「准备 TF 卡」、卸载「恢复存储空间」。</summary>
    private static string CapacityTitleKey(string mode) => mode switch
    {
        "install-tf" => "Dynamic.Capacity.TitleTf",
        "uninstall" => "Dynamic.Capacity.TitleRestore",
        _ => "Dynamic.Capacity.TitleAllocate",
    };

    private static string CapacityLeadKey(string mode) => mode switch
    {
        "install-tf" => "Dynamic.Capacity.LeadTf",
        "uninstall" => "Dynamic.Capacity.LeadRestore",
        _ => "Dynamic.Capacity.LeadAllocate",
    };

    /// <summary>风险确认文案：两种安装各一条，卸载一条；其余操作不显示风险卡片。</summary>
    private static string RiskCheckKey(string mode) => mode switch
    {
        "install-tf" => "Dynamic.Risk.InstallTf",
        "uninstall" => "Dynamic.Risk.Uninstall",
        _ => "Dynamic.Risk.Install",
    };

    /// <summary>侧栏第二步的标题，与 <see cref="IsCapacityPageApplicable"/> 的三种模式对应。</summary>
    private static string NavCapacityKey(string mode) => mode switch
    {
        "install-tf" => "Dynamic.Nav.CapacityTf",
        "uninstall" => "Dynamic.Nav.CapacityRestore",
        _ => "Dynamic.Nav.CapacityAllocate",
    };

    /// <summary>模式名作为消息参数使用，历史日志切到另一种语言后仍按当前语言渲染。</summary>
    private UiMessage ModeMessage(string mode) => M(ModeLabelKey(mode) ?? "Dynamic.Mode.Uninstall");

    /// <summary>
    /// 所有写入动作共用的禁用原因。每次访问都按当前语言取，绝不缓存成字段：
    /// 前一条已登记的消息也就不会带着旧语言的文字继续传递。
    /// </summary>
    private string ActionDisabledReason => T("Dynamic.Action.DisabledReason");

    /// <summary>可选范围暂时算不出来时，规则行显示的同一条说明（以消息形式登记，可重新渲染）。</summary>
    private UiMessage LiveRangeUnknownRule => M("Dynamic.Capacity.RuleUnknown");

    // ---------- 工具目录 ----------

    private void OnBrowseTools(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        var dialog = new OpenFolderDialog { Title = T("Dynamic.Dialog.SelectToolsFolder") };
        if (dialog.ShowDialog(this) == true)
        {
            ToolsPathBox.Text = dialog.FolderName;
        }
    }

    private void OnToolsPathChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        RefreshTransport();
    }

    private void RefreshTransport()
    {
        _transport = null;
        var root = (ToolsPathBox.Text ?? string.Empty).Trim();

        if (root.Length == 0)
        {
            SetText(ToolsStatusText, "Dynamic.ToolsStatus.NoFolder");
            RefreshActions();
            return;
        }

        if (!Directory.Exists(root))
        {
            SetText(ToolsStatusText, "Dynamic.ToolsStatus.FolderMissing", root);
            RefreshActions();
            return;
        }

        var adbPath = Path.Combine(root, "adb.exe");
        var fastbootPath = Path.Combine(root, "fastboot.exe");
        var missing = new List<string>();
        if (!File.Exists(adbPath))
        {
            missing.Add("adb.exe");
        }

        if (!File.Exists(fastbootPath))
        {
            missing.Add("fastboot.exe");
        }

        if (missing.Count > 0)
        {
            var list = string.Join(T("Dynamic.ToolsStatus.MissingSeparator"), missing);
            SetText(ToolsStatusText, "Dynamic.ToolsStatus.FilesMissing", list);
            RefreshActions();
            return;
        }

        _transport = new DeviceTransport(adbPath, fastbootPath, _runner);
        SetText(ToolsStatusText, "Dynamic.ToolsStatus.Ready");
        RefreshActions();
    }

    // ---------- 设备查询 ----------

    private async void OnDetectDevices(object sender, RoutedEventArgs e)
    {
        if (_transport is null)
        {
            SetText(DeviceHintText, "Dynamic.DeviceHint.ToolsRequired");
            return;
        }

        var transport = _transport;
        await RunBusyAsync(async token =>
        {
            ClearDeviceState();
            DevicesCombo.Items.Clear();
            SetText(ProgressStatusText, "Dynamic.Progress.ListingDevices");
            AppendLocalizedLog(M("Dynamic.Log.ListingDevices"));

            _devices = await transport.ListDevicesAsync(token);

            foreach (var device in _devices)
            {
                // 只把设备对象放在 Tag 上，列表文字是纯展示：逻辑永远读 Tag / 枚举，不解析显示文本。
                var item = new ComboBoxItem { Tag = device };
                SetContent(
                    item,
                    "Dynamic.DeviceEntry",
                    device.Serial,
                    M(ConnectionStateKey(device.ConnectionState)));
                DevicesCombo.Items.Add(item);
            }

            if (_devices.Count == 0)
            {
                SetText(ConnectionStatusText, "Dynamic.DeviceStatus.None");
                SetText(DeviceHintText, "Dynamic.DeviceHint.NoneFound");
                SetText(ProgressStatusText, "Dynamic.Progress.NoDevices");
                AppendLocalizedLog(M("Dynamic.Log.NoDevices"));
                RefreshActions();
                return;
            }

            SetText(ProgressStatusText, "Dynamic.Devices.FoundCount", _devices.Count);
            AppendLocalizedLog(M("Dynamic.Devices.FoundCount", _devices.Count));

            if (_devices.Count == 1)
            {
                // 只有唯一一台时才替用户选中；多台一律等待用户自己选，命令始终按序列号定向。
                DevicesCombo.SelectedIndex = 0;
                var only = _devices[0];
                AppendLocalizedLog(M("Dynamic.Log.SingleDeviceSelected", only.Serial));
                if (only.ConnectionState == ConnectionState.Authorized)
                {
                    await ReadIdentityAsync(only, token);
                }
                else
                {
                    DescribeNotReady(only);
                }

                return;
            }

            SetText(DeviceHintText, "Dynamic.DeviceHint.MultipleFound", _devices.Count);
            SetText(ConnectionStatusText, "Dynamic.DeviceStatus.MultipleUnselected");
            RefreshActions();
        });
    }

    private async void OnDeviceSelected(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        if (DevicesCombo.SelectedItem is not ComboBoxItem item || item.Tag is not ConnectedDevice device)
        {
            return;
        }

        ClearDeviceState();
        if (device.ConnectionState != ConnectionState.Authorized)
        {
            DescribeNotReady(device);
            RefreshActions();
            return;
        }

        await RunBusyAsync(token => ReadIdentityAsync(device, token));
    }

    private void DescribeNotReady(ConnectedDevice device)
    {
        SerialText.Text = device.Serial;
        SetBootState(M("Dynamic.BootState.Pending"));
        SetText(
            ConnectionStatusText,
            device.ConnectionState == ConnectionState.Unauthorized
                ? "Dynamic.DeviceStatus.Unauthorized"
                : "Dynamic.DeviceStatus.Offline");
        SetText(DeviceHintText, "Dynamic.DeviceHint.NotReady");
        AppendLocalizedLog(
            M("Dynamic.Log.DeviceNotReady", device.Serial, M(ConnectionStateKey(device.ConnectionState))));
    }

    private async Task ReadIdentityAsync(ConnectedDevice device, CancellationToken token)
    {
        if (_transport is null)
        {
            return;
        }

        SetText(ProgressStatusText, "Dynamic.Progress.ReadingIdentity", device.Serial);
        AppendLocalizedLog(M("Dynamic.Log.ReadingIdentity", device.Serial));

        DeviceIdentity identity;
        try
        {
            identity = await _transport.ReadAdbIdentityAsync(device.Serial, token);
        }
        catch (InvalidOperationException exception)
        {
            _identity = null;

            // 型号没有确认，上一次为旧型号准备好的安装包就不能继续留着。
            ResetPreparedPackageForIdentityFailure();

            SetText(ConnectionStatusText, "Dynamic.DeviceStatus.IdentityUnconfirmed");
            SerialText.Text = device.Serial;
            SetText(DeviceHintText, "Dynamic.DeviceHint.IdentityFailed", exception.Message);
            AppendLocalizedLog(M("Dynamic.Log.IdentityFailed", exception.Message));

            // 身份读取失败时没有固件可显示：路线必须退回「待读取设备」，
            // 不能继续显示上一台设备的固件或路线结论。
            RenderBootRoute();
            UpdateCapacityPanel();
            UpdateSummary();
            RefreshActions();
            return;
        }

        _identity = identity;
        SetText(ConnectionStatusText, "Dynamic.DeviceStatus.Authorized");
        ModelText.Text = identity.Model;
        SerialText.Text = identity.Serial;
        SetBootState(M("Dynamic.BootState.AwaitingFastboot"));
        SetText(DeviceHintText, "Dynamic.DeviceHint.IdentityConfirmed");
        SetText(ProgressStatusText, "Dynamic.Progress.IdentityDone");
        AppendLocalizedLog(M("Dynamic.Log.IdentityConfirmed", identity.Model, identity.Serial));

        // 卸载模式还要绑定这台设备的 SoC 序列号；这里已经在 RunBusyAsync 内，不能嵌套。
        if (CurrentModeTag() == "uninstall")
        {
            await CaptureUninstallAndroidAsync(identity, token);
        }

        RefreshActions();
        UpdateSummary();
        UpdateCapacityPanel();

        if (HasImportInputs())
        {
            // 型号刚刚确认：直接按实际型号自动选择统一安装包里的对应子树，不再要求手动选型号。
            // 这里已经在 RunBusyAsync 内，绝不能再嵌套一层。
            await ImportSelectedPackageAsync(token);
        }
    }

    private async void OnCheckBootloader(object sender, RoutedEventArgs e)
    {
        if (_transport is null || _identity is null)
        {
            SetText(DeviceHintText, "Dynamic.DeviceHint.IdentityRequiredForBoot");
            return;
        }

        var transport = _transport;
        var identity = _identity;
        await RunBusyAsync(async token =>
        {
            // 重新查询之前先把已确认身份的引导状态降级为 Unknown，并立刻按同一套渲染逻辑刷新界面：
            // 下面这次查询如果超时、被取消或抛异常，界面就停在「未知」，
            // 绝不会继续显示上一轮读到的「已解锁」。
            _identity = identity with { BootloaderState = BootloaderState.Unknown };
            RenderBootloaderState(BootloaderState.Unknown);

            SetText(ProgressStatusText, "Dynamic.Progress.CheckingBootloader");
            AppendLocalizedLog(M("Dynamic.Log.CheckingBootloader"));
            var updated = await transport.CheckFastbootAsync(identity, token);
            _identity = updated;
            RenderBootloaderState(updated.BootloaderState);
            SetText(ProgressStatusText, "Dynamic.Progress.BootloaderDone");
            if (_bootStateMessage is not null)
            {
                AppendLocalizedLog(M("Dynamic.Log.BootloaderState", _bootStateMessage));
            }
        });
    }

    /// <summary>
    /// 引导状态唯一的渲染入口：字段文本与摘要一起刷新，避免「查询前」和「查询后」两条路子写出不一致的结果。
    /// 只有 <see cref="CheckFastbootAsync"/> 之后才可能出现已锁 / 已解锁，其余一律显示为未知。
    /// <para>
    /// 摘要刷新会顺带重算引导兼容性（见 <c>MainWindow.BootRoute.cs</c>），所以 Fastboot 查询前后
    /// 路线结论一起更新；而设备身份里的固件信息由 Core 在更新时原样保留，不会被这次查询清掉。
    /// </para>
    /// </summary>
    private void RenderBootloaderState(BootloaderState state)
    {
        SetBootState(M(BootStateKey(state)));
        UpdateSummary();
    }

    private static string BootStateKey(BootloaderState state) => state switch
    {
        BootloaderState.Unlocked => "Dynamic.BootState.Unlocked",
        BootloaderState.Locked => "Dynamic.BootState.Locked",
        _ => "Dynamic.BootState.Unknown",
    };

    /// <summary>记录引导状态消息再渲染：摘要与语言切换都从这条消息重新取当前语言的文字。</summary>
    private void SetBootState(UiMessage message)
    {
        _bootStateMessage = message;
        SetText(BootStateText, message);
    }

    private static string ConnectionStateKey(ConnectionState state) => state switch
    {
        ConnectionState.Authorized => "Dynamic.ConnectionState.Authorized",
        ConnectionState.Unauthorized => "Dynamic.ConnectionState.Unauthorized",
        _ => "Dynamic.ConnectionState.Offline",
    };

    // ---------- 内部容量 ----------

    /// <summary>
    /// 「读取内部容量」：只调用 Core 的 <see cref="InternalStorageReader"/>，界面自己不再执行
    /// <c>exec-out</c>，也不解析任何 JSON。维护环境的快照带真实分区表与指纹；普通 Android 的快照
    /// 只有 /data 文件系统容量，因此在这里绝不会被当成 userdata 分区表。
    /// <para>
    /// 查询一开始就清空上一轮的分区表 / 指纹 / 规划 / 快照，失败、超时与取消也会再清一次并重绘容量卡片，
    /// 所以旧数字不会在读取过程中或失败之后继续留在界面上。
    /// </para>
    /// </summary>
    private async void OnReadLayout(object sender, RoutedEventArgs e)
    {
        if (_transport is null)
        {
            SetText(LayoutStatusText, "Dynamic.Layout.ToolsRequired");
            return;
        }

        if (_identity is null)
        {
            SetText(LayoutStatusText, "Dynamic.Layout.IdentityRequired");
            return;
        }

        var adbPath = _transport.AdbPath;
        var serial = _identity.Serial;
        var reader = new InternalStorageReader(adbPath, _runner);

        await RunBusyAsync(async token =>
        {
            ClearStorageReadState();
            SetText(LayoutStatusText, "Dynamic.Layout.Reading");
            SetText(ProgressStatusText, "Dynamic.Progress.ReadingLayout");
            UpdateCapacityPanel();
            AppendLocalizedLog(M("Dynamic.Log.ReadingLayout", serial));

            try
            {
                var snapshot = await reader.ReadAsync(serial, token);

                if (snapshot.Source == InternalStorageSource.MaintenanceLayout && snapshot.Layout is not null)
                {
                    // 维护环境：快照自带真实分区表，指纹可能缺失，但不补任何默认值。
                    var layout = snapshot.Layout;
                    _storage = snapshot;
                    _layout = layout;
                    _layoutFingerprint = snapshot.TableFingerprint;

                    if (snapshot.TableFingerprint is null)
                    {
                        SetText(LayoutStatusText, "Dynamic.Layout.Found", layout.Partitions.Count, layout.SectorSize);
                        AppendLocalizedLog(M("Dynamic.Layout.Found", layout.Partitions.Count, layout.SectorSize));
                    }
                    else
                    {
                        SetText(
                            LayoutStatusText,
                            "Dynamic.Layout.FoundWithFingerprint",
                            layout.Partitions.Count,
                            layout.SectorSize,
                            snapshot.TableFingerprint);
                        AppendLocalizedLog(
                            M(
                                "Dynamic.Layout.FoundWithFingerprint",
                                layout.Partitions.Count,
                                layout.SectorSize,
                                snapshot.TableFingerprint));
                    }

                    SetText(ProgressStatusText, "Dynamic.Progress.LayoutDone");
                }
                else
                {
                    // 普通 Android：只有 /data 文件系统容量。没有布局、没有指纹、没有滑条数字。
                    _storage = snapshot;
                    SetText(
                        LayoutStatusText,
                        "Dynamic.Layout.AndroidFileSystemFound",
                        FormatBytes(snapshot.TotalBytes));
                    SetText(ProgressStatusText, "Dynamic.Progress.AndroidCapacityDone");
                    AppendLocalizedLog(M("Dynamic.Log.AndroidCapacityFound", snapshot.TotalBytes));
                }

                UpdateCapacityPanel();
            }
            catch (InternalStorageReadException exception)
            {
                ClearStorageReadState();
                var diagnostic = DiagnosticExcerpt(exception.Diagnostic);
                var unavailable = exception.Failure == InternalStorageReadFailure.Unavailable;
                SetText(
                    LayoutStatusText,
                    unavailable ? "Dynamic.Layout.Unavailable" : "Dynamic.Layout.InvalidResponse",
                    diagnostic);
                SetText(
                    ProgressStatusText,
                    unavailable ? "Dynamic.Progress.LayoutUnavailable" : "Dynamic.Progress.LayoutInvalid");
                AppendLocalizedLog(
                    M(unavailable ? "Dynamic.Log.LayoutUnavailable" : "Dynamic.Log.LayoutInvalid", diagnostic));
                UpdateCapacityPanel();
            }
            catch (TimeoutException)
            {
                ClearStorageReadState();
                SetText(LayoutStatusText, "Dynamic.Layout.Timeout");
                SetText(ProgressStatusText, "Dynamic.Progress.LayoutTimeout");
                AppendLocalizedLog(M("Dynamic.Log.LayoutTimeout"));
                UpdateCapacityPanel();
            }
            catch (OperationCanceledException)
            {
                // 取消同样要清掉旧规划：界面不能停在上一轮的数字上，
                // 也不能把「正在读取」留在状态行上。
                ClearStorageReadState();
                SetText(LayoutStatusText, "Dynamic.Progress.Cancelled");
                UpdateCapacityPanel();
                throw;
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException)
            {
                ClearStorageReadState();
                var diagnostic = DiagnosticExcerpt(exception.Message);
                SetText(LayoutStatusText, "Dynamic.Layout.ReadFailed", diagnostic);
                SetText(ProgressStatusText, "Dynamic.Progress.LayoutFailed");
                AppendLocalizedLog(M("Dynamic.Layout.ReadFailed", diagnostic));
                UpdateCapacityPanel();
            }
        });
    }

    /// <summary>
    /// 丢掉一轮容量读取的全部派生状态：维护环境分区表、指纹、容量规划与最新快照。
    /// 读取开始、读取失败、超时、取消与换设备都经过这里，因此不会出现「旧数字 + 新状态」的组合。
    /// </summary>
    private void ClearStorageReadState()
    {
        _layout = null;
        _layoutFingerprint = null;
        _plan = null;
        _storage = null;
    }

    private static long UserdataBytes(DiskLayout layout)
    {
        foreach (var partition in layout.Partitions)
        {
            if (string.Equals(partition.Name, "userdata", StringComparison.OrdinalIgnoreCase))
            {
                return partition.SectorCount * layout.SectorSize;
            }
        }

        return 0;
    }

    // ---------- 容量面板 ----------

    private void UpdateCapacityPanel()
    {
        var mode = CurrentModeTag();
        if (mode == "install-tf")
        {
            // TF 卡安装不读内部 userdata，也没有滑条：容量只按所选卡片与安装包声明估算。
            // 安装包路径 / 校验结果 / 换设备都会走到这里，因此卡片容量也跟着一起刷新。
            UpdateTfCapacity();
            return;
        }

        if (mode != "install")
        {
            // 内部容量卡片只属于「安装到内部存储」：卸载仍走它自己的面板，
            // TF 卡安装不读内部 userdata，也就没有任何滑条数值要算（卡上分区由后续卡片负责）。
            if (mode == "uninstall")
            {
                UpdateUninstallPanel();
            }

            return;
        }

        _suppressCapacitySync = true;
        try
        {
            RenderDeviceStrip();

            // 两种来源绝不混淆：只有维护环境的分区表才有 userdata 分区与指纹；
            // 普通 Android 只有 /data 文件系统自身的总 / 已用 / 可用容量。
            var userdataBytes = _layout is null ? 0L : UserdataBytes(_layout);
            var androidSnapshot = _layout is null && _storage?.Source == InternalStorageSource.AndroidFileSystem
                ? _storage
                : null;

            if (_layout is not null)
            {
                SetText(CapacityTotalLabelText, "Dynamic.Capacity.TotalLabelMaintenance");
                SetText(
                    UserdataTotalText,
                    "Dynamic.RawValue",
                    userdataBytes > 0 ? FormatBytes(userdataBytes) : UnknownValue);

                // 「userdata 实际容量」只能来自真实分区表；读不到就不写数字。
                SetText(
                    DetailUserdataText,
                    "Dynamic.RawValue",
                    userdataBytes > 0 ? FormatBytes(userdataBytes) : UnknownValue);
            }
            else if (androidSnapshot is not null)
            {
                // 文件系统容量不是 userdata 分区容量：标签说清来源，明细里的 GPT 字段留空。
                SetText(CapacityTotalLabelText, "Dynamic.Capacity.TotalLabelAndroid");
                SetText(UserdataTotalText, "Dynamic.RawValue", FormatBytes(androidSnapshot.TotalBytes));
                SetText(DetailUserdataText, "Dynamic.RawValue", UnknownValue);
            }
            else
            {
                SetText(CapacityTotalLabelText, "Dynamic.Capacity.TotalLabelUnknown");
                SetText(UserdataTotalText, "Dynamic.RawValue", UnknownValue);
                SetText(DetailUserdataText, "Dynamic.RawValue", UnknownValue);
            }

            SetText(
                DetailFingerprintText,
                "Dynamic.RawValue",
                string.IsNullOrWhiteSpace(_layoutFingerprint) ? UnknownValue : _layoutFingerprint);

            if (_layout is null)
            {
                if (androidSnapshot is not null)
                {
                    // 容量确实读到了，只是完整分区表还需要维护环境：不要写成「读取失败」。
                    DisableCapacity(
                        M(
                            "Dynamic.Capacity.NoteAndroidFileSystem",
                            FormatBytes(androidSnapshot.TotalBytes),
                            FormatBytesOrPlaceholder(androidSnapshot.UsedBytes),
                            FormatBytesOrPlaceholder(androidSnapshot.AvailableBytes)),
                        M("Dynamic.Capacity.RuleAndroidMaintenance"));
                    return;
                }

                DisableCapacity(M("Dynamic.Capacity.NoteLayoutMissing"), LiveRangeUnknownRule);
                return;
            }

            if (_minimumAndroidGiB <= 0)
            {
                DisableCapacity(M("Dynamic.Capacity.NoteMinimumUnknown"), LiveRangeUnknownRule);
                return;
            }

            var storage = _package?.Storage;
            if (storage is null)
            {
                DisableCapacity(M("Dynamic.Capacity.NotePackageMissing"), LiveRangeUnknownRule);
                return;
            }

            AndroidAllocationRange range;
            try
            {
                range = PartitionPlanner.GetAndroidRange(_layout, _minimumAndroidGiB, storage);
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                DisableCapacity(M("Dynamic.Capacity.NoteRangeFailed", exception.Message), LiveRangeUnknownRule);
                return;
            }

            // RangeBase 会把 Minimum 夹到不超过 Maximum，所以先写上限再写下限。
            CapacitySlider.Maximum = range.MaximumGiB;
            CapacitySlider.Minimum = range.MinimumGiB;
            SetCapacityEnabled(true);

            var android = _capacityInitialized
                ? (long)Math.Round(CapacitySlider.Value, MidpointRounding.AwayFromZero)
                : range.MinimumGiB;
            _capacityInitialized = true;
            android = Math.Clamp(android, range.MinimumGiB, range.MaximumGiB);

            CapacitySlider.Value = android;
            CapacityBox.Text = android.ToString(CultureInfo.InvariantCulture);
            SetCapacityRule(M("Dynamic.Capacity.RuleRange", range.MinimumGiB, range.MaximumGiB));
            SetCapacityNote(M("Dynamic.Capacity.NoteComputed"));
            SetText(DetailRangeText, "Dynamic.Capacity.RangeValue", range.MinimumGiB, range.MaximumGiB);

            ApplyPlan(_layout, android, _minimumAndroidGiB, storage);
        }
        finally
        {
            _suppressCapacitySync = false;
        }
    }

    /// <summary>容量卡片正文：消息本身被记住，切换语言后按同一条消息重新渲染。</summary>
    private void SetCapacityNote(UiMessage message)
    {
        _capacityNote = message;
        SetText(CapacityNoteText, message);
    }

    /// <summary>容量规则行：同上，记住消息而不是渲染结果。</summary>
    private void SetCapacityRule(UiMessage message)
    {
        _capacityRule = message;
        SetText(CapacityRuleText, message);
    }

    private void DisableCapacity(UiMessage note, UiMessage rule)
    {
        _plan = null;
        _suppressCapacitySync = true;
        try
        {
            SetCapacityEnabled(false);
            CapacityBox.Text = string.Empty;
            CapacitySlider.Value = CapacitySlider.Minimum;
        }
        finally
        {
            _suppressCapacitySync = false;
        }

        AndroidBytesText.Text = UnknownValue;
        LinuxBytesText.Text = UnknownValue;
        DetailLinuxBootText.Text = UnknownValue;
        DetailLinuxDataText.Text = UnknownValue;

        // 之前可能已登记过 Dynamic.Capacity.RangeValue，直接写 Text 会让那条登记继续存在，
        // 切换语言时把范围又画回来；这里用同一套登记机制写入当前占位值。
        SetText(DetailRangeText, "Dynamic.RawValue", UnknownValue);
        RatioBar.Visibility = Visibility.Collapsed;
        SetCapacityNote(note);
        SetCapacityRule(rule);
    }

    private void SetCapacityEnabled(bool enabled)
    {
        CapacitySlider.IsEnabled = enabled;
        CapacityBox.IsEnabled = enabled;
    }

    private void ApplyPlan(DiskLayout layout, long androidGiB, int minimumAndroid, PackageStorage storage)
    {
        try
        {
            var plan = PartitionPlanner.Plan(layout, androidGiB, minimumAndroid, storage);
            _plan = plan;
            AndroidBytesText.Text = FormatBytes(plan.AndroidBytes);
            LinuxBytesText.Text = FormatBytes(plan.LinuxBytes);
            DetailLinuxBootText.Text = FormatBytes(plan.LinuxBootBytes);
            DetailLinuxDataText.Text = FormatBytes(plan.EstimatedLinuxDataBytes);

            RatioAndroidColumn.Width = new GridLength(Math.Max(1d, plan.AndroidBytes), GridUnitType.Star);
            RatioLinuxColumn.Width = new GridLength(Math.Max(1d, plan.LinuxBytes), GridUnitType.Star);
            RatioBar.Visibility = Visibility.Visible;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            _plan = null;
            AndroidBytesText.Text = UnknownValue;
            LinuxBytesText.Text = UnknownValue;
            DetailLinuxBootText.Text = UnknownValue;
            DetailLinuxDataText.Text = UnknownValue;
            RatioBar.Visibility = Visibility.Collapsed;
            SetCapacityNote(M("Dynamic.Capacity.NotePlanFailed", exception.Message));
        }

        UpdateSummary();
    }

    private void OnCapacitySliderChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (!_ready || _suppressCapacitySync)
        {
            return;
        }

        var android = (long)Math.Round(e.NewValue, MidpointRounding.AwayFromZero);
        _suppressCapacitySync = true;
        try
        {
            CapacityBox.Text = android.ToString(CultureInfo.InvariantCulture);
        }
        finally
        {
            _suppressCapacitySync = false;
        }

        if (_layout is not null && _package?.Storage is not null)
        {
            ApplyPlan(_layout, android, _minimumAndroidGiB, _package.Storage);
        }
    }

    private void OnCapacityTextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready || _suppressCapacitySync)
        {
            return;
        }

        if (!long.TryParse(CapacityBox.Text?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var android))
        {
            return;
        }

        var minimum = (long)Math.Round(CapacitySlider.Minimum);
        var maximum = (long)Math.Round(CapacitySlider.Maximum);
        android = Math.Clamp(android, minimum, maximum);

        _suppressCapacitySync = true;
        try
        {
            CapacitySlider.Value = android;
            var text = android.ToString(CultureInfo.InvariantCulture);
            if (CapacityBox.Text != text)
            {
                CapacityBox.Text = text;
            }
        }
        finally
        {
            _suppressCapacitySync = false;
        }

        if (_layout is not null && _package?.Storage is not null)
        {
            ApplyPlan(_layout, android, _minimumAndroidGiB, _package.Storage);
        }
    }

    // ---------- 卸载规划（恢复安卓存储空间） ----------

    private void UpdateUninstallPanel()
    {
        // 已校验的真实方案优先：必须在旧的预览逻辑清掉 _restorePlan 之前直接渲染。
        if (CurrentModeTag() == "uninstall" && TryRenderPreparedUninstallPanel())
        {
            UpdateSummary();
            return;
        }

        _restorePlan = null;
        RenderDeviceStrip();
        RestoredCapacityText.Text = UnknownValue;

        // 上一次可能登记过删除分区 / 扇区范围的消息，直接写 Text 会让它在切语言时被重新渲染；
        // 这里用同一条登记通道写入占位值，登记随之被替换。
        SetText(RemovedRangeText, "Dynamic.RawValue", UnknownValue);

        if (_layout is null)
        {
            // 普通 Android 快照只读到 /data 文件系统容量：容量并不是「没读」，缺的是分区表。
            // 恢复容量与删除范围仍然未知，_restorePlan 保持 null，绝不用 df 数字代替分区规划。
            SetText(
                UninstallPlanStatusText,
                _storage?.Source == InternalStorageSource.AndroidFileSystem
                    ? "Dynamic.Uninstall.StatusMaintenanceRequired"
                    : "Dynamic.Uninstall.StatusLayoutMissing");
            UpdateSummary();
            return;
        }

        if (_installationRecord is null)
        {
            SetText(UninstallPlanStatusText, "Dynamic.Uninstall.StatusRecordMissing");
            UpdateSummary();
            return;
        }

        try
        {
            var plan = UninstallPlanner.Plan(_layout, _installationRecord);
            _restorePlan = plan;
            RestoredCapacityText.Text = FormatBytes(plan.RestoredAndroidBytes);
            if (plan.RemovedPartitionNumbers.Count == 0)
            {
                SetText(RemovedRangeText, "Dynamic.Uninstall.RemovedPartitionsNone");
            }
            else
            {
                var numbers = string.Join(
                    T("Dynamic.Uninstall.PartitionListSeparator"),
                    plan.RemovedPartitionNumbers.Select(number => "#" + number.ToString(CultureInfo.InvariantCulture)));

                if (plan.UserdataEndSectorExclusive > plan.UserdataStartSector)
                {
                    SetText(
                        RemovedRangeText,
                        "Dynamic.Uninstall.RemovedPartitionsWithRange",
                        numbers,
                        plan.UserdataStartSector,
                        plan.UserdataEndSectorExclusive - 1);
                }
                else
                {
                    SetText(RemovedRangeText, "Dynamic.Uninstall.RemovedPartitions", numbers);
                }
            }

            SetText(UninstallPlanStatusText, "Dynamic.Uninstall.StatusPlanReady");
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            _restorePlan = null;
            SetText(UninstallPlanStatusText, "Dynamic.Uninstall.StatusPlanFailed", exception.Message);
        }

        UpdateSummary();
    }

    private void OnBrowseInstallationRecord(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = T("Dynamic.Dialog.SelectInstallationRecord"),
            Filter = T("Dynamic.Dialog.JsonFileFilter"),
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        InstallationRecordBox.Text = dialog.FileName;
        LoadInstallationRecord();
    }

    private void LoadInstallationRecord()
    {
        if (HasProtectedUninstallState)
        {
            return;
        }

        // 记录一改，上一次准备的事务立即失效；即使新文件随后读取失败，也不能继续使用旧方案。
        _installationRecord = null;
        InvalidateUninstallPreparedPlan();
        var path = (InstallationRecordBox.Text ?? string.Empty).Trim();

        if (path.Length == 0)
        {
            SetText(UninstallInputNoteText, "Dynamic.Uninstall.NoteRecordEmpty");
            UpdateUninstallPanel();
            return;
        }

        if (!File.Exists(path))
        {
            SetText(UninstallInputNoteText, "Dynamic.Uninstall.NoteRecordMissing", path);
            UpdateUninstallPanel();
            return;
        }

        try
        {
            var record = JsonSerializer.Deserialize<LinuxInstallationLayout>(File.ReadAllText(path), InstallationRecordJson);
            if (record is null)
            {
                throw new InvalidOperationException(T("Dynamic.Uninstall.RecordNotObject"));
            }

            if (string.IsNullOrWhiteSpace(record.DeviceId)
                || string.IsNullOrWhiteSpace(record.UserdataPartUuid)
                || string.IsNullOrWhiteSpace(record.LinuxBootPartUuid)
                || string.IsNullOrWhiteSpace(record.LinuxRootPartUuid)
                || record.OriginalUserdataEndSector <= 0)
            {
                throw new InvalidOperationException(T("Dynamic.Uninstall.RecordIncomplete"));
            }

            _installationRecord = record;
            SetText(UninstallInputNoteText, "Dynamic.Uninstall.NoteRecordLoaded");
            AppendLocalizedLog(
                M("Dynamic.Log.RecordLoaded", record.DeviceId, record.OriginalUserdataEndSector));
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or JsonException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException)
        {
            SetText(UninstallInputNoteText, "Dynamic.Uninstall.NoteRecordFailed", exception.Message);
            AppendLocalizedLog(M("Dynamic.Uninstall.NoteRecordFailed", exception.Message));
        }

        UpdateUninstallPanel();
    }

    private void OnBrowseStockBackup(object sender, RoutedEventArgs e)
    {
        if (_busy || HasProtectedUninstallState)
        {
            return;
        }

        var uninstall = CurrentModeTag() == "uninstall";
        var dialog = new OpenFolderDialog
        {
            Title = T(
                uninstall
                    ? "Dynamic.UninstallFlow.EdlRestore.Materials.DialogTitle"
                    : "Dynamic.Dialog.SelectStockBackupFolder"),
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        StockBackupBox.Text = dialog.FolderName;

        // 卸载只保留两份原始 GPT：先清掉全部旧路径，再只填入 before-main.bin 与 before-backup.bin；
        // 非卸载的旧流程仍按五个标准文件名探测，保持原有兼容行为。
        var count = PopulateUninstallMaterialPaths(dialog.FolderName);
        if (count == 0)
        {
            SetText(
                UninstallInputNoteText,
                uninstall
                    ? "Dynamic.UninstallFlow.EdlRestore.Materials.None"
                    : "Dynamic.UninstallFlow.Materials.None");
        }
        else
        {
            SetText(
                UninstallInputNoteText,
                uninstall
                    ? "Dynamic.UninstallFlow.EdlRestore.Materials.Populated"
                    : "Dynamic.UninstallFlow.Materials.Populated",
                count);
        }

        UpdateSummary();
    }

    // ---------- 安装包 ----------

    private async void OnBrowsePackage(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // TF 卡安装优先：走 TF 自己的浏览 / 导入包装，绝不走旧版 ImportSelectedPackage。
        if (IsModernTfInstallMode)
        {
            await BrowseModernTfInstallPackageAsync();
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = T("Dynamic.Dialog.SelectPackageFile"),
            Filter = T("Dynamic.Dialog.PackageFileFilter"),
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        // 路径框仍然可以手填旧版安装包目录；「浏览…」只选择统一 ZIP。
        PackagePathBox.Text = dialog.FileName;

        if (!HasImportInputs())
        {
            // 尚未确认型号或不在安装模式：只保留路径，等身份确认后再自动导入。
            return;
        }

        await RunBusyAsync(ImportSelectedPackageAsync);
    }

    private async void OnPackagePathChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        // TF 卡安装优先：手输路径同样走 TF 自己的输入作废；浏览对话框写入时被抑制标志跳过。
        if (IsModernTfInstallMode)
        {
            if (_suppressModernTfPackageChange)
            {
                return;
            }

            if (_busy || ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
            {
                return;
            }

            await BeginModernTfInputChangeAsync(clearPackage: true);
            UpdateTfCapacity();
            RefreshActions();
            return;
        }

        // 路径一改，上一次的导入结果立刻失效，并释放它拥有的解包目录。
        InvalidatePreparedPackage("Dynamic.Package.StatusInvalidated");
    }

    private async void OnValidatePackage(object sender, RoutedEventArgs e)
    {
        // TF 卡安装优先：走 TF 自己的校验包装，不要求旧版 _identity。
        if (IsModernTfInstallMode)
        {
            await ValidateModernTfInstallPackageAsync();
            return;
        }

        var source = (PackagePathBox.Text ?? string.Empty).Trim();
        if (source.Length == 0)
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusNeedsFolder");
            return;
        }

        if (!Directory.Exists(source) && !File.Exists(source))
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusFolderMissing", source);
            return;
        }

        // 型号只能来自已确认的设备身份，绝不从界面默认值或路径推断。
        if (string.IsNullOrWhiteSpace(_identity?.Model))
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusNeedsModel");
            return;
        }

        // 手动按钮与自动导入共用同一条流程：实际型号 + 当前内部 / TF 目标。
        await RunBusyAsync(ImportSelectedPackageAsync);
    }

    // ---------- 摘要 / 状态 ----------

    private void RenderDeviceStrip()
    {
        if (_identity is not null)
        {
            // 也走 SetText 登记：直接写 Text 会把先前「未知」的登记留在注册表里，
            // 切语言时被旧消息覆盖回 Unknown。
            SetText(DeviceStripText, "Dynamic.DeviceEntry", _identity.Model, _identity.Serial);
            return;
        }

        if (_layout is not null && !string.IsNullOrWhiteSpace(_layout.DeviceId))
        {
            SetText(DeviceStripText, "Dynamic.RawValue", _layout.DeviceId);
            return;
        }

        SetText(DeviceStripText, "Dynamic.DeviceStrip.Unknown");
    }

    /// <summary>
    /// 摘要整块按当前语言重建：模式、引导状态、安装包状态都是消息（键名 + 参数），
    /// 所以切换语言后重新调用本方法即可得到新语言的摘要，不需要缓存渲染结果。
    /// </summary>
    private void UpdateSummary()
    {
        // 固件 / Android 上报 / 引导路线这一组只读信息在这里统一重算：
        // 放在任何模式分支与提前返回之前，所以四种摘要格式都保持原样，
        // 而确认页的小面板对所有模式（含 TF 卡安装）都是同一份、当前语言的值。
        RenderBootRoute();

        // 先按已登记的消息重写字段文本，再拼摘要：两处永远取同一条消息、同一种语言。
        if (_bootStateMessage is not null)
        {
            SetText(BootStateText, _bootStateMessage);
        }

        // 已校验的卸载方案优先：所有字段都来自本次读数、原始 GPT 与后端证据。
        if (CurrentModeTag() == "uninstall" && TryRenderUninstallSummary())
        {
            return;
        }

        var mode = CurrentModeTag();
        var modeMessage = ModeMessage(mode);

        var device = _identity is null
            ? UnknownValue
            : $"{_identity.Model} · {_identity.Serial}";
        var bootloader = _bootStateMessage ?? M("Dynamic.BootState.Pending");

        if (mode is "install" or "install-tf")
        {
            var package = _package is null
                ? M("Dynamic.Package.StatusNotValidated")
                : !_package.IsValid
                    ? M("Dynamic.Summary.PackageInvalid")
                    : _package.TestOnly
                        ? M("Dynamic.Summary.PackageEntryTestOnly", _package.PackageId, _package.Version)
                        : M("Dynamic.Summary.PackageEntry", _package.PackageId, _package.Version);

            if (mode == "install-tf")
            {
                // TF 卡安装不分配内部空间，也不写内部规划数字：摘要只说读取方式、所选卡片与卡片容量。
                RenderTfSummary(modeMessage, device, bootloader, package);
                return;
            }

            SetText(
                SummaryText,
                "Dynamic.Summary.Install",
                modeMessage,
                device,
                bootloader,
                _plan is null ? UnknownValue : FormatBytes(_plan.AndroidBytes),
                _plan is null ? UnknownValue : FormatBytes(_plan.LinuxBytes),
                package);
            return;
        }

        if (mode == "uninstall")
        {
            object record = _installationRecord is null
                ? (object)M("Dynamic.Summary.NotSelected")
                : _installationRecord.DeviceId;
            object stockBackup = string.IsNullOrWhiteSpace(StockBackupBox.Text)
                ? (object)M("Dynamic.Summary.NotSelected")
                : StockBackupBox.Text!.Trim();

            SetText(
                SummaryText,
                "Dynamic.Summary.Uninstall",
                modeMessage,
                device,
                bootloader,
                record,
                _restorePlan is null ? UnknownValue : FormatBytes(_restorePlan.RestoredAndroidBytes),
                stockBackup);
            return;
        }

        SetText(SummaryText, "Dynamic.Summary.Other", modeMessage, device, bootloader);
    }

    private void OnRiskChanged(object sender, RoutedEventArgs e) => RefreshActions();

    /// <summary>
    /// 语言切换后的动态文案刷新入口（静态资源由本地化 partial 负责）：
    /// 折叠区标题、主题按钮、模式文案、容量消息、摘要与禁用原因都会按新语言重写；
    /// 风险勾选、导航与设备状态一律不动。
    /// </summary>
    private void RefreshDynamicLocalization()
    {
        RefreshSectionLabels();
        RenderThemeToggle();
        RenderModeTexts();

        if (_capacityNote is not null)
        {
            SetText(CapacityNoteText, _capacityNote);
        }

        if (_capacityRule is not null)
        {
            SetText(CapacityRuleText, _capacityRule);
        }

        UpdateSummary();
        RefreshActions();
    }

    private void RefreshActions()
    {
        var mode = CurrentModeTag();
        var installMode = IsInstallOperation(mode);
        var hasTransport = _transport is not null;

        LanguageToggleButton.IsEnabled = !_busy;
        ToolsPathBox.IsEnabled = !_busy;
        BrowseToolsButton.IsEnabled = !_busy;

        // 首页卡片与「← 功能选择」只在空闲时可用；准备页未完成时卡片保持禁用。
        BackToFunctionsButton.IsEnabled = !_busy;
        HomeCards.IsEnabled = !_busy && !_showingEnvironment && !_showingGlobalRecovery && EnvironmentIsReady;

        // 支持页入口与页内返回按钮同样只按空闲状态启用，不影响任何功能或设备状态。
        SupportProjectButton.IsEnabled = !_busy;
        SupportBackButton.IsEnabled = !_busy;

        DetectButton.IsEnabled = !_busy && hasTransport;
        CheckBootloaderButton.IsEnabled = !_busy && hasTransport && _identity is not null;
        DevicesCombo.IsEnabled = !_busy && _devices.Count > 0;
        ReadLayoutButton.IsEnabled = !_busy && hasTransport && _identity is not null;

        // 两种安装（内部存储 / TF 卡）都要校验安装包。
        PackagePathBox.IsEnabled = !_busy;
        BrowsePackageButton.IsEnabled = !_busy && installMode;
        ValidatePackageButton.IsEnabled = !_busy
            && installMode
            && !string.IsNullOrWhiteSpace(PackagePathBox.Text);

        BrowseInstallationRecordButton.IsEnabled = !_busy;
        BrowseStockBackupButton.IsEnabled = !_busy;

        NavConnect.IsEnabled = !_busy;
        NavCapacity.IsEnabled = !_busy && IsCapacityPageApplicable();
        NavConfirm.IsEnabled = !_busy;

        PrevButton.IsEnabled = !_busy && _page > 0;
        NextButton.IsEnabled = !_busy && _page < 2;

        // 卡片侧的读取方式、读取按钮与目标卡列表同样只看空闲状态，写入按钮保持禁用。
        RefreshTfActions();

        // 具体写入开放由各流程自己的校验与二次确认决定；这里只写共享禁用原因。
        ActionButton.IsEnabled = false;
        ActionButton.ToolTip = ActionDisabledReason;
        BootBackupButton.IsEnabled = false;
        BootBackupButton.ToolTip = ActionDisabledReason;
        SetText(ActionReasonText, "Dynamic.Action.DisabledReason");

        // 卸载相关控件的可用性在既有规则之上叠加，其他模式保持上面的禁用结果。
        RefreshUninstallActions();
        RefreshUninstallEdlActions();

        // 内部存储四步向导的底栏与页内按钮以这里为最终结论，覆盖上面的旧三页可用性。
        RefreshInternalInstallActions();

        // 维护模式自己的底栏与页内按钮在其后刷新；旧模式专用赋值不能放宽维护门槛。
        RefreshBootMaintenanceActions();
        RefreshBootMaintenanceSharedActions();

        // 准备页自己的按钮可用性在视图刷新之前算好，视图本身仍只由 ApplyFunctionView 决定。
        RefreshEnvironmentActions();
        if (HomeEnvironmentButton is not null)
        {
            HomeEnvironmentButton.IsEnabled = HomeEnvironmentButton.IsEnabled && !HasGlobalRecoveryProtectedState;
        }
        RefreshGlobalRecoveryActions();

        // 路由门禁最后统一收紧；它只做 AND，不会把任何按钮从禁用改为可用。
        RefreshWorkflowRouteGates();

        // 可用性刷新永远不改变当前所在的视图（首页仍是首页，向导仍是向导）。
        ApplyFunctionView();
    }

    private void RefreshWorkflowRouteGates()
    {
        var maintenanceProtected = ProtectedBootMaintenanceState;

        HomeCards.IsEnabled = HomeCards.IsEnabled
            && !_busy
            && !_showingEnvironment
            && !_showingGlobalRecovery
            && !HasGlobalRecoveryProtectedState
            && EnvironmentIsReady
            && !HasProtectedUninstallState
            && !maintenanceProtected
            && !ProtectedModernTfInstallState;

        BackToFunctionsButton.IsEnabled = BackToFunctionsButton.IsEnabled
            && !_busy
            && !_showingGlobalRecovery
            && !HasGlobalRecoveryProtectedState
            && !HasProtectedUninstallState
            && !maintenanceProtected
            && !ProtectedModernTfInstallState;

        // 共享设备准备页（安装 + 维护）使用四步侧栏：全局首页 / 返回收紧后直接返回。
        if (UsesSharedDevicePreparationPages)
        {
            return;
        }

        if (IsInternalInstallMode)
        {
            return;
        }

        NavConnect.IsEnabled = NavConnect.IsEnabled && CanEnterLegacyWorkflowPage(0);
        NavCapacity.IsEnabled = NavCapacity.IsEnabled
            && CanEnterLegacyWorkflowPage(1)
            && IsCapacityPageApplicable();
        NavConfirm.IsEnabled = NavConfirm.IsEnabled && CanEnterLegacyWorkflowPage(2);

        var previousPage = _page == 2
            ? (IsCapacityPageApplicable() ? 1 : 0)
            : (_page == 1 ? 0 : _page);
        PrevButton.IsEnabled = PrevButton.IsEnabled && CanEnterLegacyWorkflowPage(previousPage);

        var nextPage = _page == 0
            ? (IsCapacityPageApplicable() ? 1 : 2)
            : (_page == 1 ? 2 : _page);
        NextButton.IsEnabled = NextButton.IsEnabled
            && _page < 2
            && CanEnterLegacyWorkflowPage(nextPage);

        ActionButton.IsEnabled = ActionButton.IsEnabled
            && CurrentModeTag() == "uninstall"
            && _page == 2
            && HasPreparedLegacyUninstall
            && RiskCheck.IsChecked == true
            && !_busy
            && !HasProtectedUninstallState;
    }

    private async Task RunBusyAsync(Func<CancellationToken, Task> work)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        using var cts = new CancellationTokenSource();
        _cts = cts;
        RefreshActions();

        try
        {
            await work(cts.Token);
        }
        catch (OperationCanceledException)
        {
            SetText(ProgressStatusText, "Dynamic.Progress.Cancelled");
            AppendLocalizedLog(M("Dynamic.Log.Cancelled"));
        }
        catch (Exception exception)
        {
            SetText(ProgressStatusText, "Dynamic.Progress.Failed", exception.Message);
            AppendLocalizedLog(M("Dynamic.Log.Failed", exception.Message));
        }
        finally
        {
            _busy = false;
            _cts = null;
            RefreshActions();
            UpdateSummary();
        }
    }

    /// <summary>
    /// 换设备、重新检测或切换设备时清空上一台设备的一切派生状态，
    /// 避免把上一台设备的 identity / layout / 安装包 / 计划 / BL 结果用到新设备上。
    /// 安装包路径本身与设备无关，会保留下来；它对应的准备结果（可能拥有解包目录）在这里释放，
    /// 新设备的型号确认后按实际型号重新导入。
    /// <para>
    /// 卸载侧的界面输入（安装记录 JSON、原厂 boot 备份目录、输入说明、风险确认勾选）也一起清空：
    /// 它们属于「上一台设备」的恢复输入与用户同意，换设备后必须由用户重新选择、重新勾选，
    /// 否则新设备会带着上一台设备的路径与已勾选的同意继续往下走。
    /// </para>
    /// </summary>
    private void ClearDeviceState()
    {
        // 内部存储安装已经开始且尚未真实完成：清设备状态会丢掉仍在使用的安装现场，直接拒绝。
        if (HasInternalInstallExecutionStarted && !IsCompletedInternalInstallExecution)
        {
            return;
        }

        // 执行中 / 结果未知 / 等待清除数据时，清设备状态会把这次事务从界面丢掉，
        // 而设备上的任务仍在继续，所以直接拒绝。
        if (HasProtectedUninstallState)
        {
            return;
        }

        ResetUninstallState();

        _identity = null;
        ClearStorageReadState();
        var packageReleased = ReleasePreparedPackage();
        _minimumAndroidGiB = 0;
        _installationRecord = null;
        _restorePlan = null;
        _capacityInitialized = false;

        // 内部安装的四步界面回到第 0 步；当前不持有任何备份 / 规划资源，因此只重置界面位置。
        ResetInternalInstallUiState();

        SetText(ConnectionStatusText, "Dynamic.DeviceStatus.None");
        ModelText.Text = UnknownValue;
        SerialText.Text = UnknownValue;
        SetBootState(M("Dynamic.BootState.Pending"));
        SetText(DeviceHintText, "Dynamic.DeviceHint.Initial");
        SetText(LayoutStatusText, "Dynamic.Layout.StatusInitial");

        // 安装包路径属于用户输入，与设备无关：换设备时保留，确认新设备的实际型号后按该型号重新导入。
        if (packageReleased)
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusAwaitingDevice");
        }

        SetText(BootBackupStatusText, "Dynamic.BootBackup.StatusUnavailable");
        SetText(ProgressStatusText, "Dynamic.Progress.Idle");

        // 卸载侧路径、记录、方案与风险同意已经由 ResetUninstallState 清空，这里不再重复写界面。

        // 卡片状态：平板内读到的列表属于上一台设备，必须一起清掉；
        // 电脑读卡器读到的列表与设备无关，可以留着，但目标卡、容量计划与风险同意一律清空。
        ResetTfSelection(clearInventory: _tfSource == TfCardSource.Tablet);

        // 取消勾选会同步触发 OnRiskChanged → RefreshActions（幂等，只重算按钮可用性），
        // 因此放在最后一组赋值之后，保证处理器读到的都是已清空的值。
        RiskCheck.IsChecked = false;

        UpdateCapacityPanel();
        UpdateSummary();
        RefreshActions();
    }

    private static string FormatBytes(long bytes) =>
        (bytes / (double)Gibibyte).ToString("0.0", CultureInfo.InvariantCulture) + " GiB";

    /// <summary>可空容量：Core 只报告总量、不报告已用 / 可用时显示占位符，绝不补 0。</summary>
    private static string FormatBytesOrPlaceholder(long? bytes) =>
        bytes is long value && value >= 0 ? FormatBytes(value) : UnknownValue;

    /// <summary>
    /// 失败诊断的用户可读摘录：只保留有界的一段文字，避免把整段原始输出塞进状态行。
    /// 空诊断显示占位符，调用方的本地化文案已经说明了失败类别。
    /// </summary>
    private static string DiagnosticExcerpt(string? diagnostic)
    {
        var text = (diagnostic ?? string.Empty).Trim();
        if (text.Length == 0)
        {
            return UnknownValue;
        }

        const int limit = 160;
        return text.Length <= limit ? text : text.Substring(0, limit) + "…";
    }

    // ---------- 折叠区与外部链接 ----------

    private void OnToggleConnectHelp(object sender, RoutedEventArgs e) =>
        SetSectionExpanded(ConnectHelpToggle, ConnectHelpPanel, ConnectHelpPanel.Visibility != Visibility.Visible);

    private void OnToggleAdvanced(object sender, RoutedEventArgs e) =>
        SetSectionExpanded(AdvancedToggle, AdvancedPanel, AdvancedPanel.Visibility != Visibility.Visible);

    private void OnToggleDetails(object sender, RoutedEventArgs e) =>
        SetSectionExpanded(DetailsToggle, DetailsPanel, DetailsPanel.Visibility != Visibility.Visible);

    private void OnToggleLog(object sender, RoutedEventArgs e) =>
        SetSectionExpanded(LogToggle, LogPanel, LogPanel.Visibility != Visibility.Visible);

    /// <summary>
    /// 折叠区标题由控件身份决定，绝不去掉翻译后的 Content 再拼：箭头只是展开 / 折叠的标记，
    /// 文案本身永远取自该控件固定的键名。
    /// </summary>
    private void SetSectionExpanded(Button toggle, UIElement panel, bool expanded)
    {
        panel.Visibility = expanded ? Visibility.Visible : Visibility.Collapsed;
        ApplySectionLabel(toggle, expanded);
    }

    private void ApplySectionLabel(Button toggle, bool expanded)
    {
        var key = SectionStaticKey(toggle);
        if (key is null)
        {
            return;
        }

        SetContent(
            toggle,
            expanded ? "Dynamic.Section.Expanded" : "Dynamic.Section.Collapsed",
            M(key));
    }

    /// <summary>四个折叠区各自的固定文案键（静态资源由本地化 partial 维护）。</summary>
    private string? SectionStaticKey(Button toggle)
    {
        if (ReferenceEquals(toggle, ConnectHelpToggle))
        {
            return "Static.HelpToggle";
        }

        if (ReferenceEquals(toggle, AdvancedToggle))
        {
            return "Static.AdvancedToggle";
        }

        if (ReferenceEquals(toggle, DetailsToggle))
        {
            return "Static.DetailsToggle";
        }

        if (ReferenceEquals(toggle, LogToggle))
        {
            return "Static.LogToggle";
        }

        return null;
    }

    /// <summary>语言切换后按当前可见性重写四个折叠区标题（箭头不会丢，文案也不会被重复拼接）。</summary>
    private void RefreshSectionLabels()
    {
        ApplySectionLabel(ConnectHelpToggle, ConnectHelpPanel.Visibility == Visibility.Visible);
        ApplySectionLabel(AdvancedToggle, AdvancedPanel.Visibility == Visibility.Visible);
        ApplySectionLabel(DetailsToggle, DetailsPanel.Visibility == Visibility.Visible);
        ApplySectionLabel(LogToggle, LogPanel.Visibility == Visibility.Visible);
    }

    private void OnOpenBilibili(object sender, RoutedEventArgs e) => OpenExternalLink(BilibiliLabelKey, BilibiliUrl);

    private void OnOpenGithub(object sender, RoutedEventArgs e) => OpenExternalLink(GithubLabelKey, GithubUrl);

    /// <summary>只在用户点击时打开固定 HTTPS 地址，不自动打开、不由内容驱动。</summary>
    private void OpenExternalLink(string labelKey, string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            AppendLocalizedLog(M("Dynamic.Log.OpenLink", M(labelKey)));
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or FileNotFoundException)
        {
            AppendLocalizedLog(M("Dynamic.Log.OpenLinkFailed", M(labelKey), exception.Message));
        }
    }
}
