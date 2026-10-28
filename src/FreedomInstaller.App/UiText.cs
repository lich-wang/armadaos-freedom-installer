using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;

namespace FreedomInstaller.App;

/// <summary>
/// One localizable message: a catalog key plus a snapshot of its arguments.
/// Arguments may themselves be <see cref="UiMessage"/> values, so text such as
/// «serial · state» keeps switching language as a whole.
/// </summary>
internal sealed record UiMessage(string Key, params object?[] Arguments);

/// <summary>
/// Localized UI text. Reads the embedded catalogs <c>FreedomInstaller.Strings.Static.&lt;lang&gt;.json</c>
/// and <c>FreedomInstaller.Strings.Dynamic.&lt;lang&gt;.json</c> from the executing assembly and depends on
/// the BCL only (no WPF types), so it can be linked into the test assembly and exercised on Linux.
/// <para>
/// Rules kept deliberately simple: an unknown key renders the key itself, a missing English entry falls
/// back to the Chinese catalog, and a missing or broken catalog never throws — the UI keeps working with
/// whatever text resolves instead of failing to start.
/// </para>
/// </summary>
internal sealed class UiText
{
    /// <summary>Chinese (Simplified) is the product default and the fallback catalog.</summary>
    internal const string ChineseLanguage = "zh-CN";

    /// <summary>Default language used when no preference is stored or the stored value is unknown.</summary>
    internal const string DefaultLanguage = ChineseLanguage;

    /// <summary>The only non-default UI language.</summary>
    internal const string EnglishLanguage = "en";

    /// <summary>Catalog key prefixes; every catalog entry carries one of them.</summary>
    internal const string StaticPrefix = "Static.";

    /// <summary>Catalog key prefix for runtime messages (status lines, log lines, summaries).</summary>
    internal const string DynamicPrefix = "Dynamic.";

    /// <summary>Logical resource name prefix: <c>FreedomInstaller.Strings.&lt;FileName&gt;.json</c>.</summary>
    internal const string ResourceNamePrefix = "FreedomInstaller.Strings.";

    /// <summary>Depth limit for nested <see cref="UiMessage"/> arguments; a self-referencing message cannot hang the UI.</summary>
    private const int MaxFormatDepth = 8;

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    private readonly Dictionary<string, string> _defaultStrings;

    private readonly Dictionary<string, string> _englishStrings;

    private string _language;

    internal UiText(string language)
        : this(language, LoadCatalog(ChineseLanguage), LoadCatalog(EnglishLanguage))
    {
    }

    /// <summary>
    /// Catalog-injecting constructor used by tests. The production constructor above always loads the
    /// embedded catalogs; this overload only exists so formatting can be tested without adding entries
    /// to the shipped catalogs.
    /// </summary>
    internal UiText(string language, Dictionary<string, string> defaultStrings, Dictionary<string, string> englishStrings)
    {
        _defaultStrings = defaultStrings ?? throw new ArgumentNullException(nameof(defaultStrings));
        _englishStrings = englishStrings ?? throw new ArgumentNullException(nameof(englishStrings));
        _language = NormalizeLanguage(language);
    }

    /// <summary>Currently selected language: <c>zh-CN</c> or <c>en</c>.</summary>
    internal string Language => _language;

    /// <summary>True when the English catalog is active.</summary>
    internal bool IsEnglish => string.Equals(_language, EnglishLanguage, StringComparison.Ordinal);

    /// <summary>
    /// Every catalog key with its value in the current language (English falls back to Chinese per key),
    /// ordered by key. Used to fill the window resources that the XAML reads with <c>DynamicResource</c>.
    /// </summary>
    internal IEnumerable<KeyValuePair<string, string>> Strings
    {
        get
        {
            var keys = new List<string>(_defaultStrings.Keys);
            foreach (var key in _englishStrings.Keys)
            {
                if (!_defaultStrings.ContainsKey(key))
                {
                    keys.Add(key);
                }
            }

            keys.Sort(StringComparer.Ordinal);

            var pairs = new List<KeyValuePair<string, string>>(keys.Count);
            foreach (var key in keys)
            {
                pairs.Add(new KeyValuePair<string, string>(key, ResolveFormat(key)));
            }

            return pairs;
        }
    }

    /// <summary>Unknown languages are not supported and resolve to <see cref="DefaultLanguage"/>.</summary>
    internal static string NormalizeLanguage(string? language) =>
        string.Equals((language ?? string.Empty).Trim(), EnglishLanguage, StringComparison.OrdinalIgnoreCase)
            ? EnglishLanguage
            : DefaultLanguage;

    internal void SetLanguage(string language) => _language = NormalizeLanguage(language);

    /// <summary>
    /// Resolves <paramref name="key"/> and applies <paramref name="args"/> with invariant formatting.
    /// An unknown key returns the key; invalid placeholders return the unformatted catalog text.
    /// </summary>
    internal string Get(string key, params object?[] args) =>
        string.IsNullOrEmpty(key) ? string.Empty : FormatKey(key, args, 0);

    /// <summary>Resolves a message, including nested <see cref="UiMessage"/> arguments.</summary>
    internal string Format(UiMessage message) =>
        message is null ? string.Empty : FormatKey(message.Key, message.Arguments, 0);

    private string FormatKey(string key, object?[]? args, int depth)
    {
        var format = ResolveFormat(key);
        if (args is null || args.Length == 0)
        {
            return format;
        }

        var resolved = new object?[args.Length];
        for (var index = 0; index < args.Length; index++)
        {
            resolved[index] = ResolveArgument(args[index], depth);
        }

        try
        {
            return string.Format(CultureInfo.InvariantCulture, format, resolved);
        }
        catch (FormatException)
        {
            // A catalog value with a malformed placeholder must not reach the UI as an exception.
            return format;
        }
    }

    private object? ResolveArgument(object? argument, int depth) =>
        argument is UiMessage message && depth < MaxFormatDepth
            ? FormatKey(message.Key, message.Arguments, depth + 1)
            : argument;

    private string ResolveFormat(string key)
    {
        if (IsEnglish && _englishStrings.TryGetValue(key, out var english) && !string.IsNullOrEmpty(english))
        {
            return english;
        }

        if (_defaultStrings.TryGetValue(key, out var chinese) && !string.IsNullOrEmpty(chinese))
        {
            return chinese;
        }

        return key;
    }

    /// <summary>
    /// Loads both catalogs for <paramref name="language"/>. Static text is expected in every build;
    /// the Dynamic catalogs are optional and are simply absent until they ship.
    /// </summary>
    private static Dictionary<string, string> LoadCatalog(string language)
    {
        var catalog = new Dictionary<string, string>(StringComparer.Ordinal);
        ReadCatalogFile(catalog, StaticPrefix, language);
        ReadCatalogFile(catalog, DynamicPrefix, language);
        return catalog;
    }

    private static void ReadCatalogFile(Dictionary<string, string> catalog, string category, string language)
    {
        var resourceName = ResourceNamePrefix + category + language + ".json";
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream is null)
            {
                return;
            }

            using var document = JsonDocument.Parse(stream, DocumentOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var value = property.Value.GetString();
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                catalog[NormalizeKey(property.Name, category)] = value;
            }
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or JsonException
            or NotSupportedException
            or InvalidOperationException
            or ArgumentException)
        {
            // A missing or damaged catalog only costs localized text, never the window itself.
        }
    }

    /// <summary>Accepts both prefixed keys and bare keys inside a catalog file of the given category.</summary>
    private static string NormalizeKey(string key, string category) =>
        key.StartsWith(StaticPrefix, StringComparison.Ordinal) || key.StartsWith(DynamicPrefix, StringComparison.Ordinal)
            ? key
            : category + key;
}
