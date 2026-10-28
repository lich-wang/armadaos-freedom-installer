using System;
using System.IO;
using FreedomInstaller.App;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Collection that keeps the preference tests out of the parallel schedule. They replace the
/// process-wide <c>FREEDOM_INSTALLER_CACHE</c> variable, which <see cref="BundledToolsTests"/> reads
/// as well, so the two must never overlap.
/// </summary>
internal static class UserPreferencesEnvironment
{
    internal const string CollectionName = "user-preferences-environment";
}

[CollectionDefinition(UserPreferencesEnvironment.CollectionName, DisableParallelization = true)]
public sealed class UserPreferencesCollection
{
}

/// <summary>
/// Preference tests for the real <see cref="UserPreferences"/> implementation: the persisted theme and
/// language round-trip through <c>settings.json</c>, legacy files keep working, and damaged files fall
/// back to light + Chinese. Every file lives in a directory created below TEST_ARTIFACT_ROOT; nothing is
/// written to the system temp directory and only these own fixture directories are deleted.
/// </summary>
[Collection(UserPreferencesEnvironment.CollectionName)]
public sealed class UserPreferencesTests
{
    private const string CacheOverrideVariable = "FREEDOM_INSTALLER_CACHE";

    private const string SettingsFileName = "settings.json";

    [Fact]
    public void Load_LegacyThemeOnlyFile_KeepsDarkAndDefaultsToChinese()
    {
        var root = CreateCacheRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, root);
            // Written by an older build that only persisted the theme.
            File.WriteAllText(Path.Combine(root, SettingsFileName), """{"Theme":"dark"}""");

            var preferences = UserPreferences.Load();

            Assert.True(preferences.IsDark);
            Assert.Equal(UiText.ChineseLanguage, preferences.Language);
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    [Fact]
    public void ToggleLanguageAndSave_RoundTripsBothDirectionsWithoutChangingTheme()
    {
        var root = CreateCacheRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, root);
            File.WriteAllText(Path.Combine(root, SettingsFileName), """{"Theme":"dark"}""");

            var preferences = UserPreferences.Load();
            Assert.True(preferences.IsDark);
            Assert.Equal(UiText.ChineseLanguage, preferences.Language);

            preferences.ToggleLanguage();
            Assert.Equal(UiText.EnglishLanguage, preferences.Language);
            preferences.Save();

            var english = UserPreferences.Load();
            Assert.True(english.IsDark);
            Assert.Equal(UiText.EnglishLanguage, english.Language);

            english.ToggleLanguage();
            Assert.Equal(UiText.ChineseLanguage, english.Language);
            english.Save();

            var chinese = UserPreferences.Load();
            Assert.True(chinese.IsDark);
            Assert.Equal(UiText.ChineseLanguage, chinese.Language);
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    [Fact]
    public void ToggleThemeAndSave_RoundTripsToLightWithoutChangingLanguage()
    {
        var root = CreateCacheRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, root);
            File.WriteAllText(Path.Combine(root, SettingsFileName), """{"Theme":"dark"}""");

            var preferences = UserPreferences.Load();
            preferences.ToggleLanguage();
            Assert.Equal(UiText.EnglishLanguage, preferences.Language);

            preferences.Toggle();
            Assert.False(preferences.IsDark);
            preferences.Save();

            var reloaded = UserPreferences.Load();
            Assert.False(reloaded.IsDark);
            Assert.Equal(UiText.EnglishLanguage, reloaded.Language);
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    [Fact]
    public void Load_MissingOrCorruptSettingsFile_FallsBackToLightAndChinese()
    {
        var root = CreateCacheRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, root);

            var missing = UserPreferences.Load();
            Assert.False(missing.IsDark);
            Assert.Equal(UiText.ChineseLanguage, missing.Language);

            // Truncated settings: neither field can be trusted.
            File.WriteAllText(
                Path.Combine(root, SettingsFileName),
                "{\"Theme\": \"dark\", \"Language\": \"en\"");

            var corrupt = UserPreferences.Load();
            Assert.False(corrupt.IsDark);
            Assert.Equal(UiText.ChineseLanguage, corrupt.Language);
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    [Fact]
    public void Load_UnknownLanguage_KeepsStoredDarkThemeAndUsesChinese()
    {
        var root = CreateCacheRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, root);
            File.WriteAllText(
                Path.Combine(root, SettingsFileName),
                """{"Theme":"dark","Language":"fr-FR"}""");

            var preferences = UserPreferences.Load();

            Assert.True(preferences.IsDark);
            Assert.Equal(UiText.ChineseLanguage, preferences.Language);
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    private static string CreateCacheRoot()
    {
        var artifactRoot = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(artifactRoot))
        {
            throw new InvalidOperationException(
                "TEST_ARTIFACT_ROOT must be set to a writable directory for these tests; " +
                "scratch data is never placed in the system temp directory.");
        }

        var root = Path.Combine(
            Path.GetFullPath(artifactRoot.Trim()),
            "user-preferences-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(root);
        return root;
    }

    private static void Cleanup(string root)
    {
        try
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort cleanup of our own directory only.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort cleanup of our own directory only.
        }
    }
}
