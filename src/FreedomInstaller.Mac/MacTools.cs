using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// Where the window finds its tools. The 9008 archive and the two boot packers are looked up under the same
/// logical names as in the WPF installer: first as resources embedded in this assembly, then as files with that
/// exact name in a tools directory (FREEDOM_INSTALLER_TOOLS, or "tools" next to the executable / in the app
/// bundle's Resources). adb and fastboot come from a bundled platform-tools archive, the tools directory,
/// or the usual Homebrew and PATH locations. Core re-checks every tool against its own pins.
/// </summary>
internal static class MacTools
{
    internal const string PackerResource = "FreedomInstaller.EdlRawPacker.exe";
    internal const string UnpackerResource = "FreedomInstaller.EdlRawUnpacker.exe";
    private const string PlatformToolsResource = "FreedomInstaller.PlatformTools.zip";

    internal static string? ToolsDirectory
    {
        get
        {
            var candidates = new List<string?>
            {
                Environment.GetEnvironmentVariable("FREEDOM_INSTALLER_TOOLS"),
                Path.Combine(AppContext.BaseDirectory, "tools"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "Resources", "tools")),
            };
            return candidates.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path));
        }
    }

    /// <summary>Opens an embedded or tools-directory copy of a tool, or null when neither exists.</summary>
    internal static Stream? Open(string logicalName)
    {
        var embedded = Assembly.GetExecutingAssembly().GetManifestResourceStream(logicalName);
        if (embedded is not null)
        {
            return embedded;
        }

        var directory = ToolsDirectory;
        var path = directory is null ? null : Path.Combine(directory, logicalName);
        return path is not null && File.Exists(path) ? File.OpenRead(path) : null;
    }

    internal static bool IsEmbedded(string logicalName) =>
        Assembly.GetExecutingAssembly().GetManifestResourceInfo(logicalName) is not null;

    internal static bool Exists(string logicalName)
    {
        using var stream = Open(logicalName);
        return stream is not null;
    }

    internal static string? FindAndroidTool(string name)
    {
        var bundled = EnsureBundledPlatformTools();
        var candidates = new List<string>();
        if (bundled is not null)
        {
            candidates.Add(Path.Combine(bundled, name));
        }

        if (ToolsDirectory is { } directory)
        {
            candidates.Add(Path.Combine(directory, "platform-tools", name));
        }

        candidates.Add(Path.Combine("/opt/homebrew/bin", name));
        candidates.Add(Path.Combine("/usr/local/bin", name));
        foreach (var entry in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            candidates.Add(Path.Combine(entry, name));
        }

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Copies a packer into a fresh material directory, makes it executable and returns the claim Core checks
    /// against its pins, the same hand-off the WPF installer makes with its embedded executables.
    /// </summary>
    internal static async Task<VerifiedEdlFile> StageAsync(string logicalName, string destination, CancellationToken token)
    {
        await using (var input = Open(logicalName)
                         ?? throw new FileNotFoundException(logicalName))
        await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write))
        {
            await input.CopyToAsync(output, token);
        }

        File.SetUnixFileMode(destination, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        await using var staged = File.OpenRead(destination);
        var sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(staged, token));
        return new VerifiedEdlFile(destination, staged.Length, sha256);
    }

    private static string? EnsureBundledPlatformTools()
    {
        using var archive = Assembly.GetExecutingAssembly().GetManifestResourceStream(PlatformToolsResource);
        if (archive is null)
        {
            return null;
        }

        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FreedomInstaller",
            "platform-tools");
        var adb = Path.Combine(root, "platform-tools", "adb");
        if (!File.Exists(adb))
        {
            Directory.CreateDirectory(root);
            ZipFile.ExtractToDirectory(archive, root, overwriteFiles: true);
            foreach (var tool in new[] { "adb", "fastboot" })
            {
                var path = Path.Combine(root, "platform-tools", tool);
                if (File.Exists(path))
                {
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
            }
        }

        return Path.Combine(root, "platform-tools");
    }
}
