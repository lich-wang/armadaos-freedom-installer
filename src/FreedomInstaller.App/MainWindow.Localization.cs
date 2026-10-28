using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;

namespace FreedomInstaller.App;

/// <summary>
/// 界面语言（简体中文 / English）的唯一实现。与 MainWindow.xaml.cs 拆成两个 partial：
/// 本文件负责文案解析、窗口资源、已注册文本的重渲染与日志行重渲染，
/// 事件与业务状态仍留在 MainWindow.xaml.cs。
/// <para>
/// 切换语言只做「重新上色」：不重新导航、不重算模式、不清空设备 / 路径 / 滑条 / 勾选状态，
/// 所以已经读到的设备信息与用户输入在切换后原样保留，只是文字换成另一种语言。
/// </para>
/// </summary>
public partial class MainWindow
{
    private const int MaxLogRows = 200;

    private readonly UiText _uiText = new(UiText.DefaultLanguage);

    /// <summary>
    /// 已本地化的属性注册表。键是「控件 + 属性名」，所以同一个控件反复赋值只保留一条登记，
    /// 登记里存的是消息（键 + 参数快照）而不是已经格式化好的字符串，切换语言时才能重算。
    /// </summary>
    private readonly Dictionary<(object Target, string Property), LocalizedProperty> _localizedProperties = new();

    /// <summary>日志行登记：保留原始时间戳与消息，语言切换时只重写文本，不重新排序、不新增行。</summary>
    private readonly List<LocalizedLogRow> _localizedLogRows = new();

    /// <summary>
    /// 由 MainWindow.xaml.cs 的构造函数在 InitializeComponent() 之后调用：
    /// 读偏好里的语言、把全部键写进窗口资源（XAML 用 DynamicResource 取值）、同步窗口 Language。
    /// </summary>
    internal void InitializeLocalization()
    {
        _uiText.SetLanguage(_preferences.Language);
        ApplyLanguageResources();
        RerenderLocalizedMessages();
        RefreshSectionLabels();
        UpdateLanguageToggle();
        ApplyWindowLanguage();
    }

    /// <summary>按当前语言取一条文案；未知键原样返回，便于立刻发现漏登记的键。</summary>
    internal string T(string key, params object?[] args) => _uiText.Get(key, args);

    /// <summary>登记一条文案（键 + 参数快照），返回值可直接交给 <see cref="AppendLocalizedLog"/>。</summary>
    internal UiMessage M(string key, params object?[] args) => new(key, args ?? Array.Empty<object?>());

    internal void SetText(TextBlock target, string key, params object?[] args) => SetText(target, M(key, args));

    internal void SetText(TextBlock target, UiMessage message)
    {
        ArgumentNullException.ThrowIfNull(target);
        Register(target, "Text", value => target.Text = value, message);
    }

    internal void SetContent(ContentControl target, string key, params object?[] args)
    {
        ArgumentNullException.ThrowIfNull(target);
        Register(target, "Content", value => target.Content = value, M(key, args));
    }

    /// <summary>
    /// 追加一条日志。时间戳只在追加时取一次（HH:mm:ss），切换语言不会改时间，
    /// 超过 <see cref="MaxLogRows"/> 时连行带登记一起移除，绝不留没有对应行的登记。
    /// </summary>
    internal void AppendLocalizedLog(UiMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        // 共享设备准备页（安装 + 维护）写进它自己的可见日志；其他模式仍写原有日志面板，绝不重复写两份。
        // 初始化期间控件可能尚未生成，此时才退回另一个面板。
        var target = _showingGlobalRecovery
            ? GlobalLogList
            : (UsesSharedDevicePreparationPages ? InternalInstallLogList : LogList);
        target ??= UsesSharedDevicePreparationPages ? InternalInstallLogList : LogList;
        target ??= LogList;
        target ??= InternalInstallLogList;
        if (target is null)
        {
            return;
        }

        var timestamp = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        var row = new TextBlock
        {
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 4),
        };
        row.SetResourceReference(TextBlock.ForegroundProperty, "MutedBrush");

        var entry = new LocalizedLogRow(row, timestamp, message);
        entry.Render(_uiText);
        _localizedLogRows.Add(entry);
        target.Children.Add(row);

        while (_localizedLogRows.Count > MaxLogRows)
        {
            var oldest = _localizedLogRows[0];
            _localizedLogRows.RemoveAt(0);
            // 行可能在上一次执行时落在另一个面板里，只从它真实的父容器移除。
            if (oldest.Row.Parent is Panel owner)
            {
                owner.Children.Remove(oldest.Row);
            }
        }

        if (ReferenceEquals(target, GlobalLogList))
        {
            if (GlobalLogEmptyText is not null)
            {
                GlobalLogEmptyText.Visibility = Visibility.Collapsed;
            }

            GlobalLogScrollViewer?.ScrollToEnd();
        }
        else if (ReferenceEquals(target, InternalInstallLogList))
        {
            if (InternalInstallLogEmptyText is not null)
            {
                InternalInstallLogEmptyText.Visibility = Visibility.Collapsed;
            }

            InternalInstallLogScrollViewer?.ScrollToEnd();
        }
        else if (LogEmptyText is not null)
        {
            LogEmptyText.Visibility = Visibility.Collapsed;
        }
    }

    /// <summary>
    /// 顶部语言按钮：仅切换偏好里的语言并重渲染，不触碰页面、设备、路径、滑条与勾选状态。
    /// 界面刷新（按钮可用性、摘要、主题标签）在 <c>_busy</c> 复位之后执行，避免把整个窗口锁死。
    /// </summary>
    private void OnToggleLanguage(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        try
        {
            _preferences.ToggleLanguage();
            _uiText.SetLanguage(_preferences.Language);
            _preferences.Save();

            ApplyLanguageResources();
            RerenderLocalizedMessages();
            RefreshSectionLabels();
            UpdateLanguageToggle();
            ApplyWindowLanguage();
        }
        finally
        {
            _busy = false;
        }

        RenderThemeToggle();
        UpdateSummary();
        RefreshActions();
    }

    private void Register(object target, string property, Action<string> apply, UiMessage message)
    {
        var slot = (target, property);
        if (_localizedProperties.TryGetValue(slot, out var existing))
        {
            existing.Update(message);
        }
        else
        {
            _localizedProperties[slot] = new LocalizedProperty(apply, message);
        }

        apply(_uiText.Format(message));
    }

    private void RerenderLocalizedMessages()
    {
        foreach (var property in _localizedProperties.Values)
        {
            property.Render(_uiText);
        }

        foreach (var row in _localizedLogRows)
        {
            row.Render(_uiText);
        }
    }

    private void ApplyLanguageResources()
    {
        foreach (var pair in _uiText.Strings)
        {
            Resources[pair.Key] = pair.Value;
        }
    }

    private void UpdateLanguageToggle()
    {
        // 按钮显示「切换到哪种语言」：中文界面显示 English，英文界面显示简体中文。
        LanguageToggleText.Text = T("Static.LanguageToggleLabel");
        LanguageToggleButton.ToolTip = T("Static.LanguageTooltip");
    }

    private void ApplyWindowLanguage()
    {
        try
        {
            Language = XmlLanguage.GetLanguage(_uiText.Language);
        }
        catch (ArgumentException)
        {
            // 语言标记只影响排版细节，取不到合法标记时保留系统默认，不影响文案本身。
        }
    }

    /// <summary>一个已本地化的控件属性：保存消息（键 + 参数快照）并在渲染时取当前语言。</summary>
    private sealed class LocalizedProperty
    {
        internal LocalizedProperty(Action<string> apply, UiMessage message)
        {
            Apply = apply;
            Message = message;
        }

        private Action<string> Apply { get; }

        internal UiMessage Message { get; private set; }

        internal void Update(UiMessage message) => Message = message;

        internal void Render(UiText text) => Apply(text.Format(Message));
    }

    /// <summary>一行日志：固定的时间戳 + 可重渲染的消息。</summary>
    private sealed class LocalizedLogRow
    {
        internal LocalizedLogRow(TextBlock row, string timestamp, UiMessage message)
        {
            Row = row;
            Timestamp = timestamp;
            Message = message;
        }

        internal TextBlock Row { get; }

        internal string Timestamp { get; }

        internal UiMessage Message { get; private set; }

        internal void Render(UiText text) => Row.Text = Timestamp + "  " + text.Format(Message);
    }
}
