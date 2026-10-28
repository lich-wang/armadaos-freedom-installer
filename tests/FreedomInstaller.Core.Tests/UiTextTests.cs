using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using FreedomInstaller.App;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Localization tests for the catalogs the installer actually ships. The four JSON files are embedded
/// in this test assembly under the same logical names as in the App assembly, so <see cref="UiText"/>
/// reads the real strings here instead of a copy that could drift. Nothing is written to disk, so no
/// test artifact directory is needed.
/// </summary>
public sealed class UiTextTests
{
    /// <summary>Logical resource names that must exist in the executing assembly, without culture suffix.</summary>
    private const string StaticChineseCatalog = "FreedomInstaller.Strings.Static.zh-CN.json";
    private const string StaticEnglishCatalog = "FreedomInstaller.Strings.Static.en.json";
    private const string DynamicChineseCatalog = "FreedomInstaller.Strings.Dynamic.zh-CN.json";
    private const string DynamicEnglishCatalog = "FreedomInstaller.Strings.Dynamic.en.json";

    /// <summary>Composite placeholders such as <c>{0}</c> or <c>{1:N0}</c>.</summary>
    private static readonly Regex PlaceholderPattern = new(
        @"\{(\d+)(?:,[^}]*)?(?::[^}]*)?\}",
        RegexOptions.CultureInvariant);

    [Fact]
    public void EmbeddedCatalogs_ResolveAuthorNameInBothLanguagesAndDefaultToChinese()
    {
        // The real catalogs must be readable from this assembly, otherwise every assertion below
        // would silently compare catalog keys against each other.
        var chinese = new UiText("zh-CN");
        Assert.Equal(UiText.ChineseLanguage, chinese.Language);
        Assert.Equal("单翼", chinese.Get("Static.AuthorName"));
        Assert.Equal("已授权", chinese.Get("Dynamic.ConnectionState.Authorized"));
        Assert.Equal("ArmadaOS Freedom 安装助手 0.7.3", chinese.Get("Static.Title"));

        var english = new UiText("en");
        Assert.Equal(UiText.EnglishLanguage, english.Language);
        Assert.Equal("danyi", english.Get("Static.AuthorName"));
        Assert.Equal("Authorized", english.Get("Dynamic.ConnectionState.Authorized"));
        Assert.Equal("ArmadaOS Freedom Installer 0.7.3", english.Get("Static.Title"));

        var unknown = new UiText("fr-FR");
        Assert.Equal(UiText.DefaultLanguage, unknown.Language);
        Assert.Equal("单翼", unknown.Get("Static.AuthorName"));
    }

    [Fact]
    public void CatalogPairs_ShipIdenticalKeySetsWithNonEmptyText()
    {
        AssertCatalogPair(StaticChineseCatalog, StaticEnglishCatalog, minimumKeys: 50);
        AssertCatalogPair(DynamicChineseCatalog, DynamicEnglishCatalog, minimumKeys: 100);
    }

    [Fact]
    public void EveryShippedFormat_RendersWithEnoughDummyArgumentsInBothLanguages()
    {
        var chinese = new UiText(UiText.ChineseLanguage);
        var english = new UiText(UiText.EnglishLanguage);

        AssertAllFormatsRender(StaticChineseCatalog, chinese);
        AssertAllFormatsRender(StaticEnglishCatalog, english);
        AssertAllFormatsRender(DynamicChineseCatalog, chinese);
        AssertAllFormatsRender(DynamicEnglishCatalog, english);
    }

    [Fact]
    public void RetainedNestedMessage_RerendersNestedLabelAfterSetLanguage()
    {
        var text = new UiText(UiText.ChineseLanguage);

        // «serial · state»: the state is itself a catalog message, so switching language must
        // re-render both halves of the already-built message.
        var message = new UiMessage(
            "Dynamic.DeviceEntry",
            "FIXTURE001",
            new UiMessage("Dynamic.ConnectionState.Authorized"));

        Assert.Equal("FIXTURE001 \u00B7 已授权", text.Format(message));

        // 免解锁安装方式只作为第二段追加在主摘要之后；语言切换时两段都必须重渲染。
        var withMode = new UiMessage(
            "Dynamic.InternalInstall.Execution.WithFailureDetails",
            message,
            new UiMessage("Dynamic.InternalInstall.Prepared.GblInstallMode"));

        Assert.Equal("安装方式：免解锁安装", text.Get("Dynamic.InternalInstall.Prepared.GblInstallMode"));
        Assert.Equal(
            "FIXTURE001 \u00B7 已授权\n\n安装方式：免解锁安装",
            text.Format(withMode));

        text.SetLanguage(UiText.EnglishLanguage);

        Assert.Equal(UiText.EnglishLanguage, text.Language);
        Assert.Equal("FIXTURE001 \u00B7 Authorized", text.Format(message));
        Assert.Equal(
            "Installation method: without unlocking the bootloader",
            text.Get("Dynamic.InternalInstall.Prepared.GblInstallMode"));
        Assert.Equal(
            "FIXTURE001 \u00B7 Authorized\n\nInstallation method: without unlocking the bootloader",
            text.Format(withMode));
    }

    /// <summary>
    /// 免解锁安装准备阶段的专用提示与阶段名都不带格式参数，必须直接渲染出真实文案，
    /// 不能回落成键名或残留格式花括号。
    /// </summary>
    [Theory]
    [InlineData(UiText.ChineseLanguage)]
    [InlineData(UiText.EnglishLanguage)]
    public void DynamicCatalog_RendersNewGblMessagesWithoutArguments(string language)
    {
        var text = new UiText(language);
        var keys = new[]
        {
            "Dynamic.InternalInstall.Prepared.CompleteBackupWithEfispRequired",
            "Dynamic.InternalInstall.Prepared.GblBootChainKeyMismatch",
            "Dynamic.InternalInstall.Prepared.GblRuntimeRegionUnknown",
            "Dynamic.InternalInstall.Prepared.GblInstallMode",
            "Dynamic.InternalInstall.Execution.Stage.WritingGblRuntime",
        };

        foreach (var key in keys)
        {
            var rendered = text.Get(key);

            Assert.False(string.IsNullOrWhiteSpace(rendered), $"{language}: '{key}' rendered empty.");
            Assert.NotEqual(key, rendered);
            Assert.DoesNotContain("{", rendered, StringComparison.Ordinal);
            Assert.DoesNotContain("}", rendered, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The board recovery image wording must render real values in both languages and keep the
    /// board-phase transfer labels distinct from the generic ones and from their own keys.
    /// </summary>
    [Theory]
    [InlineData(UiText.ChineseLanguage)]
    [InlineData(UiText.EnglishLanguage)]
    public void DynamicCatalog_RendersBoardRecoveryImageValuesAndDistinctBoardPhases(string language)
    {
        var text = new UiText(language);

        var log = text.Format(new UiMessage(
            "Dynamic.InternalInstall.Prepared.RecoveryImageLog",
            "115.3 MiB",
            "2 GiB"));

        Assert.Contains("115.3 MiB", log);
        Assert.Contains("2 GiB", log);
        Assert.DoesNotContain("{0}", log);
        Assert.DoesNotContain("{1}", log);
        Assert.DoesNotContain("Dynamic.InternalInstall.Prepared.RecoveryImageLog", log);

        var writing = text.Get("Dynamic.InternalInstall.Execution.BoardIoPhase.Writing");
        var readingBack = text.Get("Dynamic.InternalInstall.Execution.BoardIoPhase.ReadingBack");
        Assert.NotEqual(writing, readingBack);
        Assert.NotEqual("Dynamic.InternalInstall.Execution.BoardIoPhase.Writing", writing);
        Assert.NotEqual("Dynamic.InternalInstall.Execution.BoardIoPhase.ReadingBack", readingBack);

        var expand = text.Get("Dynamic.InternalInstall.Log.Expand");
        var collapse = text.Get("Dynamic.InternalInstall.Log.Collapse");
        Assert.NotEqual(expand, collapse);
        Assert.NotEqual("Dynamic.InternalInstall.Log.Expand", expand);
        Assert.NotEqual("Dynamic.InternalInstall.Log.Collapse", collapse);
    }

    private static void AssertCatalogPair(string chineseResourceName, string englishResourceName, int minimumKeys)
    {
        var chinese = ReadCatalog(chineseResourceName);
        var english = ReadCatalog(englishResourceName);

        Assert.True(
            chinese.Count >= minimumKeys,
            $"{chineseResourceName} carries {chinese.Count} keys but at least {minimumKeys} are expected.");
        Assert.True(
            english.Count >= minimumKeys,
            $"{englishResourceName} carries {english.Count} keys but at least {minimumKeys} are expected.");

        Assert.Equal(
            chinese.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray(),
            english.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray());

        Assert.All(
            chinese,
            pair => Assert.False(
                string.IsNullOrWhiteSpace(pair.Value),
                $"{chineseResourceName}: '{pair.Key}' is empty."));
        Assert.All(
            english,
            pair => Assert.False(
                string.IsNullOrWhiteSpace(pair.Value),
                $"{englishResourceName}: '{pair.Key}' is empty."));
    }

    private static void AssertAllFormatsRender(string resourceName, UiText text)
    {
        var catalog = ReadCatalog(resourceName);
        Assert.NotEmpty(catalog);

        foreach (var pair in catalog)
        {
            var arguments = DummyArguments(pair.Value);
            var rendered = text.Get(pair.Key, arguments);

            Assert.False(
                string.IsNullOrEmpty(rendered),
                $"{resourceName}: '{pair.Key}' rendered empty.");
            Assert.DoesNotContain("{", rendered, StringComparison.Ordinal);
            Assert.DoesNotContain("}", rendered, StringComparison.Ordinal);
        }
    }

    /// <summary>One dummy argument per placeholder index, so every composite format is fully applied.</summary>
    private static object?[] DummyArguments(string format)
    {
        var highestIndex = -1;
        foreach (Match match in PlaceholderPattern.Matches(format))
        {
            highestIndex = Math.Max(
                highestIndex,
                int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture));
        }

        if (highestIndex < 0)
        {
            return Array.Empty<object?>();
        }

        var arguments = new object?[highestIndex + 1];
        for (var index = 0; index < arguments.Length; index++)
        {
            arguments[index] = "ARG" + index.ToString(CultureInfo.InvariantCulture);
        }

        return arguments;
    }

    private static Dictionary<string, string> ReadCatalog(string resourceName)
    {
        var stream = typeof(UiText).Assembly.GetManifestResourceStream(resourceName);
        Assert.NotNull(stream);

        using var document = JsonDocument.Parse(stream!);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);

        var catalog = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            Assert.Equal(JsonValueKind.String, property.Value.ValueKind);
            catalog[property.Name] = property.Value.GetString() ?? string.Empty;
        }

        return catalog;
    }
}
