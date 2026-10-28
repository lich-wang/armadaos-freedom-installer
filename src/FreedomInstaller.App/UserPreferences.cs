using System;
using System.IO;
using System.Text.Json;

namespace FreedomInstaller.App;

/// <summary>
/// 主题与界面语言偏好的持久化。只依赖 BCL 与同项目内的 <see cref="BundledTools"/>，不引用任何 WPF 类型，
/// 所以偏好读写不会因为界面资源问题而失败。
/// <para>
/// 配置文件固定为 <c>BundledTools.GetCacheRoot()</c> 下的 <c>settings.json</c>：产品运行时是
/// <c>%LOCALAPPDATA%\ArmadaOS Freedom</c>，自测时由 <c>FREEDOM_INSTALLER_CACHE</c> 改到别处，
/// 代码里没有硬编码的服务器或网络路径。
/// </para>
/// <para>
/// 任何读取错误（文件缺失、损坏、无权限、路径非法）都回退到默认值而不是抛异常：
/// 偏好损坏绝不允许阻止程序启动；写入失败同样只做尽力而为，不影响当前会话。
/// </para>
/// <para>
/// 主题与语言是两个独立字段，一次写入一起保存：只存过主题的旧配置读出来是「原主题 + 默认中文」，
/// 任何一个切换都不会重置另一个。
/// </para>
/// </summary>
internal sealed class UserPreferences
{
    private const string FileName = "settings.json";

    private const string DarkTheme = "dark";

    private const string LightTheme = "light";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    private UserPreferences(bool isDark, string language)
    {
        IsDark = isDark;
        Language = language;
    }

    /// <summary>当前是否使用深色主题。默认 <see langword="false"/>（浅色）。</summary>
    internal bool IsDark { get; private set; }

    /// <summary>
    /// 界面语言，只会是 <see cref="UiText.ChineseLanguage"/> 或 <see cref="UiText.EnglishLanguage"/>。
    /// 缺省、未知或损坏的取值一律回落到 <see cref="UiText.DefaultLanguage"/>（简体中文）。
    /// </summary>
    internal string Language { get; private set; }

    /// <summary>
    /// 读取偏好。文件不存在、内容损坏或路径不可用时返回默认浅色主题 + 简体中文，绝不抛出。
    /// </summary>
    internal static UserPreferences Load()
    {
        try
        {
            var path = Path.Combine(BundledTools.GetCacheRoot(), FileName);
            if (!File.Exists(path))
            {
                return new UserPreferences(false, UiText.DefaultLanguage);
            }

            var stored = JsonSerializer.Deserialize<StoredPreferences>(File.ReadAllText(path), JsonOptions);
            return new UserPreferences(
                string.Equals(stored?.Theme, DarkTheme, StringComparison.OrdinalIgnoreCase),
                UiText.NormalizeLanguage(stored?.Language));
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or JsonException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException)
        {
            // 偏好读取失败只是回到默认主题与默认语言，不是启动错误。
            return new UserPreferences(false, UiText.DefaultLanguage);
        }
    }

    /// <summary>浅色 / 深色之间切换。不动语言字段。</summary>
    internal void Toggle() => IsDark = !IsDark;

    /// <summary>简体中文 / English 之间切换。不动主题字段。</summary>
    internal void ToggleLanguage() =>
        Language = string.Equals(Language, UiText.EnglishLanguage, StringComparison.Ordinal)
            ? UiText.ChineseLanguage
            : UiText.EnglishLanguage;

    /// <summary>
    /// 保存当前主题与语言（一次写入两个字段）。尽力而为：目录建不出来或文件写不进去时静默放弃，
    /// 当前会话的主题与语言不受影响，下次启动回到默认值。
    /// </summary>
    internal void Save()
    {
        try
        {
            var root = BundledTools.GetCacheRoot();
            Directory.CreateDirectory(root);
            var payload = JsonSerializer.Serialize(
                new StoredPreferences
                {
                    Theme = IsDark ? DarkTheme : LightTheme,
                    Language = Language,
                },
                JsonOptions);
            File.WriteAllText(Path.Combine(root, FileName), payload);
        }
        catch (Exception)
        {
            // 偏好写入失败不允许影响界面与查询流程。
        }
    }

    /// <summary>settings.json 的结构：主题与语言，其他字段一律不读。</summary>
    private sealed class StoredPreferences
    {
        public string? Theme { get; set; }

        public string? Language { get; set; }
    }
}
