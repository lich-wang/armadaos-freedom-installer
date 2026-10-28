using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;

namespace FreedomInstaller.App;

/// <summary>
/// Locates and unpacks the platform-tools archive that is embedded in the single-file installer.
/// Depends on the BCL only (no WPF, no UI types) so the extraction behaviour is unit testable
/// on any OS by linking this file into a test assembly.
/// </summary>
internal static class BundledTools
{
    /// <summary>Logical resource name used by the App project's EmbeddedResource item.</summary>
    internal const string PlatformToolsResourceName = "FreedomInstaller.PlatformTools.zip";

    private const string CacheDirectoryPrefix = "platform-tools-";
    private const string StagingDirectoryPrefix = ".staging-";
    private const string EntryPrefix = "platform-tools/";
    private const string ToolsDirectoryName = "tools";
    private const int CacheHashLength = 16;

    /// <summary>
    /// Fixed whitelist of archive entries (relative to <c>platform-tools/</c>). The same list is the
    /// on-disk file name inside the cache directory, so no archive-supplied path is ever used to build
    /// a target path.
    /// </summary>
    private static readonly string[] RequiredFileNames =
    {
        "adb.exe",
        "fastboot.exe",
        "AdbWinApi.dll",
        "AdbWinUsbApi.dll",
        "libwinpthread-1.dll",
        "NOTICE.txt",
        "source.properties",
    };

    /// <summary>
    /// Base directory for extracted tools. <c>FREEDOM_INSTALLER_CACHE</c> wins when set (its absolute
    /// path is used); otherwise <c>%LOCALAPPDATA%\ArmadaOS Freedom</c>.
    /// </summary>
    internal static string GetCacheRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable("FREEDOM_INSTALLER_CACHE");
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            return Path.GetFullPath(overrideRoot.Trim());
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ArmadaOS Freedom");
    }

    /// <summary>
    /// Extracts the embedded platform-tools archive (when present) into the cache and returns the
    /// directory holding the seven tools, or <see langword="null"/> when this build carries no
    /// embedded archive.
    /// </summary>
    internal static string? EnsureAvailable()
    {
        using var resource = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream(PlatformToolsResourceName);
        if (resource is null)
        {
            return null;
        }

        return ExtractArchive(resource, Path.Combine(GetCacheRoot(), ToolsDirectoryName));
    }

    /// <summary>
    /// Extracts the whitelisted entries of <paramref name="archive"/> into a content-addressed
    /// directory below <paramref name="cacheRoot"/> and returns that directory. A complete cache is
    /// reused; a partially written cache is never reported as success.
    /// </summary>
    internal static string ExtractArchive(Stream archive, string cacheRoot)
    {
        ArgumentNullException.ThrowIfNull(archive);
        if (string.IsNullOrWhiteSpace(cacheRoot))
        {
            throw new ArgumentException("cacheRoot must be a non-empty directory path.", nameof(cacheRoot));
        }

        var rootPath = Path.GetFullPath(cacheRoot);
        Directory.CreateDirectory(rootPath);

        var payload = ReadAllBytes(archive);
        var hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var contentId = hash.Substring(0, CacheHashLength);
        var targetPath = Path.Combine(rootPath, CacheDirectoryPrefix + contentId);

        if (IsCompleteCache(targetPath))
        {
            return targetPath;
        }

        var stagingPath = Path.Combine(
            rootPath,
            StagingDirectoryPrefix + contentId + "-" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(stagingPath);
            ExtractRequiredEntries(payload, stagingPath);
            PublishCache(stagingPath, targetPath);
        }
        finally
        {
            TryDeleteDirectory(stagingPath);
        }

        if (!IsCompleteCache(targetPath))
        {
            throw new InvalidOperationException(
                $"Platform-tools cache '{targetPath}' is incomplete after extraction.");
        }

        return targetPath;
    }

    private static void ExtractRequiredEntries(byte[] payload, string destinationPath)
    {
        using var payloadStream = new MemoryStream(payload, writable: false);
        using var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read, leaveOpen: false);

        foreach (var fileName in RequiredFileNames)
        {
            var entryName = EntryPrefix + fileName;
            var entry = archive.GetEntry(entryName);
            if (entry is null)
            {
                throw new InvalidDataException(
                    $"Platform-tools archive is missing the required entry '{entryName}'.");
            }

            if (entry.Length <= 0)
            {
                throw new InvalidDataException(
                    $"Platform-tools archive entry '{entryName}' is empty.");
            }

            // Target path comes from the fixed whitelist only, so archive paths (including any
            // '../' entries and entries outside platform-tools/) can never escape the cache.
            var targetFile = Path.Combine(destinationPath, fileName);

            using var entryStream = entry.Open();
            using var output = new FileStream(targetFile, FileMode.Create, FileAccess.Write, FileShare.None);
            entryStream.CopyTo(output);
            output.Flush();

            if (output.Length <= 0)
            {
                throw new InvalidDataException(
                    $"Platform-tools archive entry '{entryName}' produced an empty file.");
            }
        }
    }

    private static void PublishCache(string stagingPath, string targetPath)
    {
        if (Directory.Exists(targetPath))
        {
            if (IsCompleteCache(targetPath))
            {
                return;
            }

            // Broken leftover from an interrupted run: drop it and retry the rename.
            TryDeleteDirectory(targetPath);
        }

        try
        {
            Directory.Move(stagingPath, targetPath);
        }
        catch (IOException) when (IsCompleteCache(targetPath))
        {
            // Another writer finished first with identical content; use its cache.
        }
    }

    private static bool IsCompleteCache(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            return false;
        }

        foreach (var fileName in RequiredFileNames)
        {
            var file = new FileInfo(Path.Combine(directoryPath, fileName));
            if (!file.Exists || file.Length <= 0)
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] ReadAllBytes(Stream stream)
    {
        if (stream.CanSeek)
        {
            stream.Seek(0, SeekOrigin.Begin);
        }

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static void TryDeleteDirectory(string directoryPath)
    {
        try
        {
            if (Directory.Exists(directoryPath))
            {
                Directory.Delete(directoryPath, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort cleanup only.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort cleanup only.
        }
    }
}
