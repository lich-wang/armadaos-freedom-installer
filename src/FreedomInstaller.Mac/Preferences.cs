using System.Text.Json;

namespace FreedomInstaller.Mac;

/// <summary>Language and theme of the window, kept in ~/Library/Application Support/FreedomInstaller.</summary>
internal sealed class Preferences
{
    public string Language { get; set; } = "zh-CN";

    public bool Dark { get; set; }

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FreedomInstaller",
        "preferences.json");

    internal static Preferences Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<Preferences>(File.ReadAllText(FilePath)) ?? new Preferences()
                : new Preferences();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new Preferences();
        }
    }

    internal void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Losing the remembered language or theme never stops the window.
        }
    }
}
