using System.Reflection;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using FreedomInstaller.App;

namespace FreedomInstaller.Mac;

/// <summary>
/// Text catalogs of the window: the WPF installer's Static.* / Dynamic.* catalogs (linked, so both front ends
/// show the same words) with Mac.*.json laid over them for the few lines that name the Mac host. Every key is
/// also written into the application resources, so XAML reads it with DynamicResource exactly like the WPF
/// window, and texts set from code are remembered as messages so a language switch renders them again.
/// </summary>
internal sealed class Localization
{
    private const string ResourcePrefix = "FreedomInstaller.Strings.";

    private readonly UiText _text;
    private readonly Dictionary<TextBlock, UiMessage> _texts = new();
    private readonly List<(TextBlock Row, string Time, UiMessage Message)> _logRows = new();

    internal Localization(string language)
    {
        _text = new UiText(language, LoadCatalog("zh-CN"), LoadCatalog("en"));
    }

    internal string Language => _text.Language;

    internal bool IsEnglish => _text.IsEnglish;

    internal string T(string key, params object?[] args) => _text.Get(key, args);

    internal string Format(UiMessage message) => _text.Format(message);

    internal void SetLanguage(string language)
    {
        _text.SetLanguage(language);
        Apply();
    }

    /// <summary>Writes every key into the application resources and renders the remembered texts again.</summary>
    internal void Apply()
    {
        var resources = Application.Current!.Resources;
        foreach (var pair in _text.Strings)
        {
            resources[pair.Key] = pair.Value;
        }

        foreach (var (target, message) in _texts)
        {
            target.Text = _text.Format(message);
        }

        foreach (var (row, time, message) in _logRows)
        {
            row.Text = time + "  " + _text.Format(message);
        }
    }

    internal void Set(TextBlock target, UiMessage message)
    {
        _texts[target] = message;
        target.Text = _text.Format(message);
    }

    internal void Set(TextBlock target, string key, params object?[] args) => Set(target, new UiMessage(key, args));

    internal TextBlock NewLogRow(UiMessage message, int maxRows, out TextBlock? dropped)
    {
        var time = DateTime.Now.ToString("HH:mm:ss");
        var row = new TextBlock { Text = time + "  " + _text.Format(message) };
        _logRows.Add((row, time, message));
        dropped = null;
        if (_logRows.Count > maxRows)
        {
            dropped = _logRows[0].Row;
            _logRows.RemoveAt(0);
        }

        return row;
    }

    private static Dictionary<string, string> LoadCatalog(string language)
    {
        var catalog = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var category in new[] { "Static.", "Dynamic.", "Mac." })
        {
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream(ResourcePrefix + category + language + ".json");
            if (stream is null)
            {
                continue;
            }

            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String && property.Value.GetString() is { Length: > 0 } value)
                {
                    catalog[property.Name] = value;
                }
            }
        }

        return catalog;
    }
}
