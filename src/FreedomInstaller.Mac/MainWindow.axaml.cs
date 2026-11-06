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
        var row = _l.NewLogRow(message, MaxLogRows, out var dropped);
        row.FontSize = 12;
        row.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        row.Margin = new Thickness(0, 0, 0, 4);
        row[!TextBlock.ForegroundProperty] = row.GetResourceObservable("MutedBrush").ToBinding();
        InternalInstallLogList.Children.Add(row);
        if (dropped is not null)
        {
            InternalInstallLogList.Children.Remove(dropped);
        }

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
    }

    private void OnShowSupport(object? sender, RoutedEventArgs e)
    {
        if (SupportPage.IsVisible)
        {
            return;
        }

        _pageBeforeSupport = EnvironmentPage.IsVisible ? EnvironmentPage
            : HomePage.IsVisible ? HomePage
            : WorkflowScrollViewer;
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
        var wizard = ReferenceEquals(view, WorkflowScrollViewer);
        WorkflowScrollViewer.IsVisible = wizard;
        WorkflowSidebar.IsVisible = wizard;
        WorkflowButtons.IsVisible = wizard;
        HomeFooterHint.IsVisible = HomePage.IsVisible;
        SupportProjectButton.IsEnabled = !_busy;
    }

    private void OnShowEnvironment(object? sender, RoutedEventArgs e) => ShowView(EnvironmentPage);

    private void OnEnvironmentContinue(object? sender, RoutedEventArgs e)
    {
        if (_environmentReady)
        {
            ShowView(HomePage);
        }
    }

    private void OnSelectOperation(object? sender, RoutedEventArgs e)
    {
        if (_busy || !_environmentReady)
        {
            return;
        }

        ShowView(WorkflowScrollViewer);
        NavigateInternalInstallStep(_internalInstallStep);
    }

    private void OnBackToFunctions(object? sender, RoutedEventArgs e)
    {
        if (!_busy)
        {
            ShowView(HomePage);
        }
    }

    // ---------- 运行环境 ----------

    private async void OnEnvironmentCheck(object? sender, RoutedEventArgs e) => await CheckEnvironmentAsync();

    /// <summary>
    /// Read-only host check, the Mac counterpart of the WPF environment page: the system, the connection tools
    /// and the 9008 path. macOS reaches 9008 through libusb, so there is no driver to install.
    /// </summary>
    private async Task CheckEnvironmentAsync()
    {
        EnvironmentCheckButton.IsEnabled = false;
        EnvironmentContinueButton.IsEnabled = false;
        SetText(EnvironmentStatusText, "Dynamic.Environment.Checking");
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

            // 9008 工具按型号各一份归档：至少找到一份才能继续，备份那一步再按平板型号取用。
            var edlModels = EdlDeviceProfiles.Models
                .Where(model => EdlDeviceProfiles.FindByModel(model)?.ArchiveLogicalName is { } name && MacTools.Exists(name))
                .ToList();
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
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _environmentReady = false;
            SetText(EnvironmentStatusText, "Dynamic.Environment.CheckFailed");
        }
        finally
        {
            EnvironmentCheckButton.IsEnabled = true;
        }
    }

    // ---------- 关闭 ----------

    private bool _closeConfirmed;

    /// <summary>
    /// While a write runs the window refuses to close; while only a 9008 session is open it asks first, like
    /// the WPF window. Backups and evidence are never deleted on close.
    /// </summary>
    private async void OnWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_closeConfirmed)
        {
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

        if (_internalInstallClient is not null && !_internalInstallExitVerified)
        {
            e.Cancel = true;
            var leave = await MessageDialog.AskAsync(
                this,
                T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
                T("Dynamic.InternalInstall.Exit.StatusIdle"),
                T("Dynamic.Mac.Dialog.Yes"),
                T("Dynamic.Mac.Dialog.No"));
            if (leave)
            {
                _closeConfirmed = true;
                DisposeInternalInstall();
                Close();
            }

            return;
        }

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
