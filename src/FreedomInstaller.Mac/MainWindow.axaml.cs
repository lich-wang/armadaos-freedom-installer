using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Styling;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// Shell of the macOS window: theme and language buttons, the environment page, the function home page, the
/// support page and the footer, laid out like the WPF window. The internal install pages live in
/// MainWindow.Install.cs.
/// </summary>
public partial class MainWindow : Window
{
    private const int MaxLogRows = 200;
    private const long Gibibyte = 1024L * 1024L * 1024L;
    private const string UnknownValue = "—";

    private readonly Preferences _preferences = Preferences.Load();
    private readonly Localization _l;
    private readonly ProcessRunner _runner = new();

    private string? _adbPath;
    private string? _fastbootPath;
    private bool _environmentReady;
    private bool _busy;
    private Control? _pageBeforeSupport;

    public MainWindow()
    {
        _l = new Localization(_preferences.Language);
        _l.Apply();
        ApplyTheme();
        InitializeComponent();
        InitializeOfflineUpgradeView();
        UpdateThemeToggle();
        RenderInternalInstallPlaceholders();
        Closing += OnWindowClosing;
        Opened += async (_, _) => await CheckEnvironmentAsync();
    }

    // ---------- 文案 ----------

    internal static UiMessage M(string key, params object?[] args) => new(key, args);

    private string T(string key, params object?[] args) => _l.T(key, args);

    private void SetText(TextBlock target, string key, params object?[] args) => _l.Set(target, M(key, args));

    private void SetText(TextBlock target, UiMessage message) => _l.Set(target, message);

    private void AppendLog(UiMessage message)
    {
        var row = _l.AppendLogRow(InternalInstallLogList, message, MaxLogRows);
        row.FontSize = 12;
        row.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        row.Margin = new Thickness(0, 0, 0, 4);
        row[!TextBlock.ForegroundProperty] = row.GetResourceObservable("MutedBrush").ToBinding();

        InternalInstallLogEmptyText.IsVisible = false;
        InternalInstallLogScrollViewer.ScrollToEnd();
    }

    // ---------- 顶栏 ----------

    private void OnToggleTheme(object? sender, RoutedEventArgs e)
    {
        _preferences.Dark = !_preferences.Dark;
        _preferences.Save();
        ApplyTheme();
        UpdateThemeToggle();
    }

    private void ApplyTheme() =>
        Application.Current!.RequestedThemeVariant = _preferences.Dark ? ThemeVariant.Dark : ThemeVariant.Light;

    /// <summary>Like the WPF button, the label names the theme the click switches to.</summary>
    private void UpdateThemeToggle() =>
        SetText(ThemeToggleText, _preferences.Dark ? "Static.ThemeLabelLight" : "Static.ThemeLabelDark");

    private void OnToggleLanguage(object? sender, RoutedEventArgs e)
    {
        _preferences.Language = _l.IsEnglish ? "zh-CN" : "en";
        _preferences.Save();
        _l.SetLanguage(_preferences.Language);
        RerenderOfflineUpgradeLog();
    }

    private void OnShowSupport(object? sender, RoutedEventArgs e)
    {
        if (SupportPage.IsVisible)
        {
            return;
        }

        _pageBeforeSupport = EnvironmentPage.IsVisible ? EnvironmentPage
            : HomePage.IsVisible ? HomePage
            : GlobalRecoveryPage.IsVisible ? GlobalRecoveryPage
            : OfflineUpgradePage.IsVisible ? OfflineUpgradePage
            : BootMaintenancePage.IsVisible ? BootMaintenancePage
            : UninstallPage.IsVisible ? UninstallPage
            : WorkflowScrollViewer;
        AboutVersionText.Text = InstallerDisplayVersion.ForAssembly(typeof(MainWindow).Assembly);
        ShowView(SupportPage);
    }

    private void OnCloseSupport(object? sender, RoutedEventArgs e) => ShowView(_pageBeforeSupport ?? HomePage);

    private async void OnOpenBilibili(object? sender, RoutedEventArgs e) =>
        await Launcher.LaunchUriAsync(new Uri("https://space.bilibili.com/258786"));

    private async void OnOpenGithub(object? sender, RoutedEventArgs e) =>
        await Launcher.LaunchUriAsync(new Uri("https://github.com/mydanyi"));

    // ---------- 视图切换 ----------

    /// <summary>One view at a time; the sidebar and the Previous / Next buttons belong to the wizard only.</summary>
    private void ShowView(Control view)
    {
        EnvironmentPage.IsVisible = ReferenceEquals(view, EnvironmentPage);
        HomePage.IsVisible = ReferenceEquals(view, HomePage);
        SupportPage.IsVisible = ReferenceEquals(view, SupportPage);
        GlobalRecoveryPage.IsVisible = ReferenceEquals(view, GlobalRecoveryPage);
        OfflineUpgradePage.IsVisible = ReferenceEquals(view, OfflineUpgradePage);
        BootMaintenancePage.IsVisible = ReferenceEquals(view, BootMaintenancePage);
        UninstallPage.IsVisible = ReferenceEquals(view, UninstallPage);
        var wizard = ReferenceEquals(view, WorkflowScrollViewer);
        WorkflowScrollViewer.IsVisible = wizard;
        WorkflowSidebar.IsVisible = wizard;
        WorkflowButtons.IsVisible = wizard;
        HomeFooterHint.IsVisible = HomePage.IsVisible;
        SupportProjectButton.IsEnabled = !_busy;
    }

    /// <summary>
    /// Like the WPF window, the environment page stays closed while this window has the tablet in (or possibly in)
    /// 9008: a re-check that lost a tool would lock the wizard, and with it the exit card, out.
    /// </summary>
    private void OnShowEnvironment(object? sender, RoutedEventArgs e)
    {
        if (!_busy && !HasLiveDeviceSession)
        {
            ShowView(EnvironmentPage);
        }
    }

    private void OnEnvironmentContinue(object? sender, RoutedEventArgs e)
    {
        if (_environmentReady)
        {
            ShowView(HomePage);
        }
    }

    /// <summary>
    /// The home cards dispatch on their Tag like the WPF window. A page that holds a 9008 session keeps the other
    /// page closed, so one window never drives the tablet from two places.
    /// </summary>
    private void OnSelectOperation(object? sender, RoutedEventArgs e)
    {
        if (_busy || !_environmentReady)
        {
            return;
        }

        switch ((sender as Control)?.Tag as string)
        {
            case "global-backup" when !HasInternalInstallDeviceSession && !HasBootMaintenanceDeviceSession
                && !HasUninstallDeviceSession:
                ShowGlobalRecoveryPage(GlobalRecoveryMode.Backup);
                break;
            case "global-restore" when !HasInternalInstallDeviceSession && !HasBootMaintenanceDeviceSession
                && !HasUninstallDeviceSession:
                ShowGlobalRecoveryPage(GlobalRecoveryMode.Restore);
                break;
            case "offline-upgrade" when !HasLiveDeviceSession:
                ShowOfflineUpgradePage();
                break;
            // Android 更新前准备 / 更新后修复：与 WPF 的 "prepare" / "repair" 标签相同；另一页面持有 9008 会话时不进入。
            case "prepare" or "repair" when !HasInternalInstallDeviceSession && !HasGlobalRecoveryProtectedState
                && !HasUninstallDeviceSession:
                ShowBootMaintenancePage((string)((Control)sender!).Tag!);
                break;
            // 卸载 Linux：与 WPF 的 "uninstall" 标签相同；另一页面持有 9008 会话时不进入。
            case "uninstall" when !HasInternalInstallDeviceSession && !HasGlobalRecoveryProtectedState
                && !HasBootMaintenanceDeviceSession:
                ShowUninstallPage();
                break;
            case "install" when !HasGlobalRecoveryProtectedState && !HasBootMaintenanceDeviceSession
                && !HasUninstallDeviceSession:
                ShowView(WorkflowScrollViewer);
                NavigateInternalInstallStep(_internalInstallStep);
                break;
        }
    }

    private void OnBackToFunctions(object? sender, RoutedEventArgs e)
    {
        if (!_busy)
        {
            ShowView(HomePage);
        }
    }

    // ---------- 运行环境 ----------

    private async void OnEnvironmentCheck(object? sender, RoutedEventArgs e)
    {
        if (_busy || HasLiveDeviceSession)
        {
            return;
        }

        await CheckEnvironmentAsync();
    }

    /// <summary>
    /// Read-only host check, the Mac counterpart of the WPF environment page: the system, the connection tools
    /// and the 9008 path. macOS reaches 9008 through libusb, so there is no driver to install.
    /// </summary>
    private async Task CheckEnvironmentAsync()
    {
        EnvironmentCheckButton.IsEnabled = false;
        EnvironmentContinueButton.IsEnabled = false;
        EnvironmentGlobalRestoreButton.IsEnabled = false;
        SetText(EnvironmentStatusText, "Dynamic.Environment.Checking");
        _environmentReady = false;
        _globalRestoreEnvironmentReady = false;
        try
        {
            var version = Environment.OSVersion.Version;
            var systemOk = OperatingSystem.IsMacOSVersionAtLeast(12)
                && RuntimeInformation.OSArchitecture == Architecture.Arm64;
            SetText(
                EnvironmentSystemStatusText,
                systemOk
                    ? M("Dynamic.Mac.Environment.SystemReady", $"{version.Major}.{version.Minor}", RuntimeInformation.OSArchitecture)
                    : M("Dynamic.Mac.Environment.SystemUnsupported"));

            // 9008 工具按型号各一份归档：至少找到一份才能继续，备份那一步再按平板型号取用。
            // 先提交 EDL 闸门，后续 Android 工具与 boot packer 的 IO 失败不应清除已确认的 EDL 就绪。
            var edlModels = EdlDeviceProfiles.Models
                .Where(model => EdlDeviceProfiles.FindByModel(model)?.ArchiveLogicalName is { } name && MacTools.Exists(name))
                .ToList();
            _globalRestoreEnvironmentReady = systemOk && edlModels.Count > 0;

            await Task.Run(() =>
            {
                _adbPath = MacTools.FindAndroidTool("adb");
                _fastbootPath = MacTools.FindAndroidTool("fastboot");
            });

            var missing = new List<string>();
            if (_adbPath is null)
            {
                missing.Add("adb");
            }

            // Step 1 reboots into fastboot to read the lock state and reboots back with it, so a missing fastboot
            // would only show after the tablet has left Android.
            if (_fastbootPath is null)
            {
                missing.Add("fastboot");
            }

            if (edlModels.Count == 0)
            {
                missing.Add("9008 tools");
            }

            var packersFound = MacTools.Exists(MacTools.PackerResource) && MacTools.Exists(MacTools.UnpackerResource);
            if (!packersFound)
            {
                missing.Add("boot packers");
            }

            var toolsOk = missing.Count == 0;
            SetText(
                EnvironmentToolsStatusText,
                toolsOk
                    ? M("Dynamic.Mac.Environment.ToolsReady",
                        _adbPath,
                        string.Join(" / ", edlModels),
                        MacTools.IsEmbedded(MacTools.PackerResource)
                            ? M("Dynamic.Mac.Environment.Bundled")
                            : MacTools.ToolsDirectory ?? UnknownValue)
                    : M("Dynamic.Mac.Environment.ToolsMissing", string.Join(", ", missing)));
            SetText(EnvironmentDriverStatusText, "Dynamic.Mac.Environment.DriverReady");

            _environmentReady = systemOk && toolsOk;
            SetText(EnvironmentStatusText, _environmentReady ? "Dynamic.Environment.Ready" : "Dynamic.Environment.NotReady");
            EnvironmentContinueButton.IsEnabled = _environmentReady;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
        {
            _environmentReady = false;
            SetText(EnvironmentStatusText, "Dynamic.Environment.CheckFailed");
        }
        finally
        {
            EnvironmentCheckButton.IsEnabled = true;
            EnvironmentGlobalRestoreButton.IsVisible = !_environmentReady;
            EnvironmentGlobalRestoreButton.IsEnabled = true;
        }
    }

    // ---------- 关闭 ----------

    private bool _closeConfirmed;
    private bool _closePromptActive;

    /// <summary>
    /// While a write or any other device step runs the window refuses to close; while only a 9008 session is
    /// open it asks first, like the WPF window. Backups and evidence are never deleted on close.
    /// </summary>
    private async void OnWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_closeConfirmed)
        {
            return;
        }

        // The offline upgrade page goes first, like the WPF window's own closing handler for it: its exchanges run
        // as busy work, so the generic busy refusal below would otherwise keep an SSH session from ever closing.
        // It cancels the running exchange, disconnects, releases the imported package (saved session records stay)
        // and then closes the window itself.
        if (await OnOfflineUpgradeClosingAsync(e))
        {
            return;
        }

        if (_globalOperationActive)
        {
            // A global connect / backup / restore / reset is running: the window stays open until it ends.
            e.Cancel = true;
            await MessageDialog.ShowAsync(
                this,
                T("Dynamic.Mac.Close.BusyTitle"),
                T("Dynamic.Mac.Close.BusyBody"),
                T("Dynamic.Mac.Dialog.Ok"));
            return;
        }

        if (HasGlobalRecoveryProtectedState)
        {
            // The global page holds a 9008 session or an unresolved outcome: close only after the same explicit
            // warning as the WPF page. Nothing is reset on close and no backup or evidence is deleted.
            e.Cancel = true;
            if (_closePromptActive)
            {
                return;
            }

            _closePromptActive = true;
            try
            {
                if (await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.Global.Dialog.Title"),
                        T("Dynamic.Global.Dialog.CloseWarning"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No")))
                {
                    _closeConfirmed = true;
                    DisposeGlobalRecoveryOnClose();
                    DisposeInternalInstall();
                    Close();
                }
            }
            finally
            {
                _closePromptActive = false;
            }

            return;
        }

        if (_internalInstallExecutionActive)
        {
            e.Cancel = true;
            await MessageDialog.ShowAsync(
                this,
                T("Dynamic.InternalInstall.Execution.Dialog.Title"),
                T("Dynamic.InternalInstall.Execution.Lead.Running"),
                T("Dynamic.Mac.Dialog.Ok"));
            return;
        }

        // The boot-maintenance page holds (or may hold) a 9008 session or an unresolved outcome: its own close gate,
        // like the WPF window's maintenance branch of the internal install closing handler.
        if (await OnBootMaintenanceClosingAsync(e))
        {
            return;
        }

        // The uninstall page holds (or may hold) a 9008 session, a prepared plan or an unresolved outcome: its own
        // close gate, like the WPF window's uninstall branch of the internal install closing handler.
        if (await OnUninstallClosingAsync(e))
        {
            return;
        }

        if (_busy)
        {
            // A device step is still running: step 1's fastboot round-trip, the 9008 entry before any client
            // exists, a backup or an exit wait. Closing now would skip that step's own return or recovery and can
            // leave the tablet in fastboot or 9008, so the window stays open until the step has finished.
            e.Cancel = true;
            if (_closePromptActive)
            {
                return;
            }

            _closePromptActive = true;
            try
            {
                await MessageDialog.ShowAsync(
                    this,
                    T("Dynamic.Mac.Close.BusyTitle"),
                    T("Dynamic.Mac.Close.BusyBody"),
                    T("Dynamic.Mac.Dialog.Ok"));
            }
            finally
            {
                _closePromptActive = false;
            }

            return;
        }

        if (HasUnconfirmedEdlEntry)
        {
            // The 9008 entry was sent but produced no client: the tablet may be in 9008 and this window can neither
            // reset it nor verify its return, so closing only goes ahead after an explicit confirmation.
            e.Cancel = true;
            if (_closePromptActive)
            {
                return;
            }

            _closePromptActive = true;
            try
            {
                var leave = await MessageDialog.AskAsync(
                    this,
                    T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
                    T("Dynamic.InternalInstall.Backup.EntryUnconfirmed") + Environment.NewLine + Environment.NewLine
                        + T("Dynamic.Global.Dialog.CloseWarning"),
                    T("Dynamic.Mac.Dialog.Yes"),
                    T("Dynamic.Mac.Dialog.No"));
                if (leave)
                {
                    _closeConfirmed = true;
                    DisposeInternalInstall();
                    Close();
                }
            }
            finally
            {
                _closePromptActive = false;
            }

            return;
        }

        if (_internalInstallClient is not null && !_internalInstallExitVerified)
        {
            e.Cancel = true;
            if (_closePromptActive)
            {
                return;
            }

            _closePromptActive = true;
            try
            {
                bool leave;
                if (HasInternalInstallWriteIssued)
                {
                    // A write was issued: the backend owns the 9008 session and its reset, so closing never
                    // resets; it only releases this window's resources, after the same warning as the WPF window.
                    leave = await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.InternalInstall.Execution.CloseWarning.TerminalTitle"),
                        T("Dynamic.InternalInstall.Execution.CloseWarning.TerminalBody"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No"));
                }
                else
                {
                    // Nothing was written: leaving means the exit the prompt describes (one reset, then the same
                    // tablet verified in Android), and the window closes once that return is verified. If it cannot
                    // be verified (no loader proof, no return, another device), the exit card keeps the reason and
                    // the window only closes after a second, explicit "close anyway", so it is never a trap.
                    leave = await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
                        T("Dynamic.InternalInstall.Exit.StatusIdle"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No"));
                    if (leave && !await ExitInternalInstallMaintenanceAsync())
                    {
                        leave = await MessageDialog.AskAsync(
                            this,
                            T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
                            T("Dynamic.Global.Dialog.CloseWarning"),
                            T("Dynamic.Mac.Dialog.Yes"),
                            T("Dynamic.Mac.Dialog.No"));
                    }
                }

                if (leave)
                {
                    _closeConfirmed = true;
                    DisposeInternalInstall();
                    Close();
                }
            }
            finally
            {
                _closePromptActive = false;
            }

            return;
        }

        DisposeGlobalRecoveryOnClose();
        DisposeBootMaintenanceOnClose();
        DisposeUninstallOnClose();
        DisposeInternalInstall();
    }

    private static string FormatBytes(long bytes) =>
        (bytes / (double)Gibibyte).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " GiB";

    private static string FormatExecutionBytes(long bytes)
    {
        const double KiB = 1024d;
        const double MiB = 1024d * 1024d;
        const double GiB = 1024d * 1024d * 1024d;
        var value = Math.Abs((double)bytes);
        var culture = System.Globalization.CultureInfo.CurrentCulture;
        if (value >= GiB)
        {
            return (bytes / GiB).ToString("0.##", culture) + " GiB";
        }

        if (value >= MiB)
        {
            return (bytes / MiB).ToString("0.#", culture) + " MiB";
        }

        return value >= KiB ? (bytes / KiB).ToString("0.#", culture) + " KiB" : bytes.ToString(culture) + " B";
    }

    private static string Placeholder(string? value) =>
        string.IsNullOrWhiteSpace(value) ? UnknownValue : value.Trim();
}
