using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;

namespace FreedomInstaller.App;

internal record QualcommDriverFiles(string DirectoryPath, string InfPath);

internal static class BundledQualcommDriver
{
    private const string ResourceName = "FreedomInstaller.QualcommUsbDriver.zip";
    private const string DriversDirectoryName = "drivers";
    private const string CacheDirectoryPrefix = "qualcomm-usb-";
    private const string StagingDirectoryPrefix = ".staging-";
    private const string InfRelativePath = "qcser.inf";
    private const string CatRelativePath = "qcser.cat";
    private const string SerialDirectoryName = "serial";
    private const string Amd64RelativePath = "serial/amd64";
    private const string SysRelativePath = "serial/amd64/qcusbser.sys";
    private const int CacheHashLength = 16;

    private static readonly (string RelativePath, long Length, string Sha256)[] PinnedFiles =
    {
        (InfRelativePath, 210084L, "3D77C8FB0EB01E3B1A6CB1DE96BEE48CD4A80A95E91DC055888241FB5E8D69AC"),
        (CatRelativePath, 153527L, "8771CB736412945178FCF087EB172A27F2FDD429026AE633A87271D51EE5212F"),
        (SysRelativePath, 277720L, "2B8361B492C59DE4C856F5DD644FE99CB09C572DFB05C4B5833301A64FCB8EEF"),
    };

    private static readonly string[] OptionalDirectoryEntries = { "serial/", "serial/amd64/" };
    private static readonly StringComparer PathNameComparer =
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    internal static QualcommDriverFiles EnsureAvailable()
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName);
        if (resource is null)
        {
            throw new InvalidOperationException(
                $"Embedded resource '{ResourceName}' was not found in the application assembly.");
        }

        return ExtractArchive(resource, Path.Combine(BundledTools.GetCacheRoot(), DriversDirectoryName));
    }

    internal static QualcommDriverFiles ExtractArchive(Stream archive, string cacheRoot)
    {
        ArgumentNullException.ThrowIfNull(archive);
        if (string.IsNullOrWhiteSpace(cacheRoot))
        {
            throw new ArgumentException("cacheRoot must be a non-empty directory path.", nameof(cacheRoot));
        }

        var rootPath = Path.GetFullPath(cacheRoot);
        var payload = ReadAllBytes(archive);
        ValidateArchive(payload);

        var archiveHash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var targetPath = Path.Combine(rootPath, CacheDirectoryPrefix + archiveHash.Substring(0, CacheHashLength));
        var targetFiles = CreateFiles(targetPath);

        Directory.CreateDirectory(rootPath);
        if (IsValidCache(targetFiles))
        {
            return targetFiles;
        }

        var stagingPath = Path.Combine(rootPath, StagingDirectoryPrefix + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(stagingPath);
            ExtractPinnedEntries(payload, stagingPath);
            ValidateFiles(CreateFiles(stagingPath));
            PublishCache(stagingPath, targetPath);
        }
        finally
        {
            TryDeleteDirectory(stagingPath);
        }

        ValidateFiles(targetFiles);
        return targetFiles;
    }

    internal static void ValidateFiles(QualcommDriverFiles files)
    {
        ArgumentNullException.ThrowIfNull(files);

        var directoryPath = CanonicalPath(files.DirectoryPath);
        var infPath = CanonicalPath(files.InfPath);
        var expectedInfPath = Path.GetFullPath(Path.Combine(directoryPath, InfRelativePath));
        if (!string.Equals(infPath, expectedInfPath, PathComparison))
        {
            throw new InvalidDataException(
                $"Qualcomm driver INF path '{files.InfPath}' is not the qcser.inf below '{files.DirectoryPath}'.");
        }

        ValidateDirectory(directoryPath, new[] { InfRelativePath, CatRelativePath, SerialDirectoryName });
        ValidateDirectory(Path.Combine(directoryPath, SerialDirectoryName), new[] { "amd64" });
        ValidateDirectory(Path.Combine(directoryPath, Amd64RelativePath), new[] { "qcusbser.sys" });

        foreach (var pin in PinnedFiles)
        {
            ValidateFile(Path.Combine(directoryPath, pin.RelativePath), pin);
        }
    }

    private static QualcommDriverFiles CreateFiles(string directoryPath) =>
        new(directoryPath, Path.Combine(directoryPath, InfRelativePath));

    private static bool IsValidCache(QualcommDriverFiles files)
    {
        try
        {
            ValidateFiles(files);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static void ValidateArchive(byte[] payload)
    {
        using var payloadStream = new MemoryStream(payload, writable: false);
        using var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read, leaveOpen: false);

        var entries = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in archive.Entries)
        {
            if (Array.IndexOf(OptionalDirectoryEntries, entry.FullName) >= 0)
            {
                if (!entries.Add(entry.FullName))
                {
                    throw new InvalidDataException(
                        $"Qualcomm driver archive contains duplicate entry '{entry.FullName}'.");
                }

                if (entry.Length != 0)
                {
                    throw new InvalidDataException(
                        $"Qualcomm driver archive directory entry '{entry.FullName}' contains data.");
                }

                continue;
            }

            var pin = FindPin(entry.FullName);
            if (pin is null)
            {
                throw new InvalidDataException(
                    $"Qualcomm driver archive contains unexpected entry '{entry.FullName}'.");
            }

            if (!entries.Add(entry.FullName))
            {
                throw new InvalidDataException(
                    $"Qualcomm driver archive contains duplicate entry '{entry.FullName}'.");
            }

            if (entry.Length != pin.Value.Length)
            {
                throw new InvalidDataException(
                    $"Qualcomm driver archive entry '{entry.FullName}' has an unexpected length.");
            }
        }

        foreach (var pin in PinnedFiles)
        {
            if (!entries.Contains(pin.RelativePath))
            {
                throw new InvalidDataException(
                    $"Qualcomm driver archive is missing the required entry '{pin.RelativePath}'.");
            }
        }
    }

    private static void ExtractPinnedEntries(byte[] payload, string destinationPath)
    {
        using var payloadStream = new MemoryStream(payload, writable: false);
        using var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read, leaveOpen: false);
        Directory.CreateDirectory(Path.Combine(destinationPath, SerialDirectoryName));
        Directory.CreateDirectory(Path.Combine(destinationPath, Amd64RelativePath));

        foreach (var pin in PinnedFiles)
        {
            var entry = archive.GetEntry(pin.RelativePath)
                ?? throw new InvalidDataException(
                    $"Qualcomm driver archive is missing the required entry '{pin.RelativePath}'.");

            using var entryStream = entry.Open();
            using var output = new FileStream(
                Path.Combine(destinationPath, pin.RelativePath),
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None);
            entryStream.CopyTo(output);
            output.Flush();

            if (output.Length != pin.Length)
            {
                throw new InvalidDataException(
                    $"Qualcomm driver archive entry '{pin.RelativePath}' produced an unexpected length.");
            }
        }
    }

    private static void PublishCache(string stagingPath, string targetPath)
    {
        if (Directory.Exists(targetPath))
        {
            if (IsValidCache(CreateFiles(targetPath)))
            {
                return;
            }

            TryDeleteDirectory(targetPath);
        }

        try
        {
            Directory.Move(stagingPath, targetPath);
        }
        catch (IOException) when (IsValidCache(CreateFiles(targetPath)))
        {
            // Another writer published an identical, fully verified cache first.
        }
    }

    private static (string RelativePath, long Length, string Sha256)? FindPin(string entryName)
    {
        foreach (var pin in PinnedFiles)
        {
            if (string.Equals(pin.RelativePath, entryName, StringComparison.Ordinal))
            {
                return pin;
            }
        }

        return null;
    }

    private static string CanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidDataException("Qualcomm driver paths must be non-empty.");
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidDataException($"Qualcomm driver path '{path}' is invalid.", exception);
        }
    }

    private static void ValidateDirectory(string directoryPath, string[] expectedNames)
    {
        if (!Directory.Exists(directoryPath))
        {
            throw new InvalidDataException($"Qualcomm driver cache '{directoryPath}' does not exist.");
        }

        EnsureNotReparsePoint(directoryPath);
        var remaining = new HashSet<string>(expectedNames, PathNameComparer);
        foreach (var entryPath in Directory.EnumerateFileSystemEntries(directoryPath))
        {
            if (!remaining.Remove(Path.GetFileName(entryPath)))
            {
                throw new InvalidDataException(
                    $"Qualcomm driver cache contains unexpected entry '{entryPath}'.");
            }

            EnsureNotReparsePoint(entryPath);
        }

        if (remaining.Count != 0)
        {
            throw new InvalidDataException(
                $"Qualcomm driver cache '{directoryPath}' is missing required entries.");
        }
    }

    private static void ValidateFile(
        string filePath,
        (string RelativePath, long Length, string Sha256) pin)
    {
        if (!File.Exists(filePath))
        {
            throw new InvalidDataException($"Qualcomm driver cache file '{filePath}' is missing.");
        }

        var attributes = File.GetAttributes(filePath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                $"Qualcomm driver cache entry '{filePath}' is not a regular file.");
        }

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != pin.Length)
        {
            throw new InvalidDataException(
                $"Qualcomm driver cache file '{filePath}' has an unexpected length.");
        }

        var actualHash = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actualHash, pin.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Qualcomm driver cache file '{filePath}' has an unexpected SHA-256 hash.");
        }
    }

    private static void EnsureNotReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Reparse point '{path}' is not allowed in the Qualcomm driver cache.");
        }
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
            if (!Directory.Exists(directoryPath))
            {
                return;
            }

            if ((File.GetAttributes(directoryPath) & FileAttributes.ReparsePoint) != 0)
            {
                Directory.Delete(directoryPath, recursive: false);
                return;
            }

            Directory.Delete(directoryPath, recursive: true);
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
