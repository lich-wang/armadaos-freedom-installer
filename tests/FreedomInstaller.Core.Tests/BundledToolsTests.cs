using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FreedomInstaller.App;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour tests for the embedded platform-tools extraction helper. The helper is compiled into
/// this assembly through a Compile/Link item so the WPF App project is not referenced here.
/// All scratch data lives below TEST_ARTIFACT_ROOT; nothing is written to the system temp directory.
/// </summary>
public sealed class BundledToolsTests
{
    private const string CacheOverrideVariable = "FREEDOM_INSTALLER_CACHE";

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

    [Fact]
    public void ExtractArchive_WritesSevenWhitelistedFilesWithArchiveBytes()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var entries = CompleteArchive(marker: 0x41);
            var zip = BuildZip(entries);

            string extracted;
            using (var stream = new MemoryStream(zip, writable: false))
            {
                extracted = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            Assert.True(Directory.Exists(extracted), $"expected cache directory at '{extracted}'");
            Assert.Equal(
                Path.GetFullPath(cacheRoot),
                Path.GetFullPath(Path.GetDirectoryName(extracted)!));

            var expectedId = Convert.ToHexString(SHA256.HashData(zip)).ToLowerInvariant().Substring(0, 16);
            Assert.Equal("platform-tools-" + expectedId, Path.GetFileName(extracted));

            var actualFiles = Directory
                .GetFiles(extracted, "*", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(
                RequiredFileNames.OrderBy(name => name, StringComparer.Ordinal).ToArray(),
                actualFiles);
            Assert.Empty(Directory.GetDirectories(extracted));

            foreach (var fileName in RequiredFileNames)
            {
                Assert.Equal(
                    entries["platform-tools/" + fileName],
                    File.ReadAllBytes(Path.Combine(extracted, fileName)));
            }

            // No staging leftovers inside the cache root.
            Assert.Equal(
                new[] { extracted }.OrderBy(path => path, StringComparer.Ordinal).ToArray(),
                Directory.GetDirectories(cacheRoot).OrderBy(path => path, StringComparer.Ordinal).ToArray());
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void ExtractArchive_SameArchiveTwiceReusesSameCacheDirectory()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var zip = BuildZip(CompleteArchive(marker: 0x42));

            string first;
            using (var stream = new MemoryStream(zip, writable: false))
            {
                first = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            var probeFile = Path.Combine(first, "NOTICE.txt");
            File.WriteAllText(probeFile, "sentinel");
            var stampAfterFirstRun = File.GetLastWriteTimeUtc(probeFile);

            string second;
            using (var stream = new MemoryStream(zip, writable: false))
            {
                second = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            // Same stream instance rewound also resolves to the same cache entry.
            string third;
            using (var stream = new MemoryStream(zip, writable: false))
            {
                BundledTools.ExtractArchive(stream, cacheRoot);
                stream.Position = 0;
                third = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            Assert.Equal(first, second);
            Assert.Equal(first, third);
            Assert.Equal("sentinel", File.ReadAllText(probeFile));
            Assert.Equal(stampAfterFirstRun, File.GetLastWriteTimeUtc(probeFile));
            Assert.Single(Directory.GetDirectories(cacheRoot));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void ExtractArchive_DifferentArchiveContentUsesDifferentCacheDirectory()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");

            string first;
            using (var stream = new MemoryStream(BuildZip(CompleteArchive(marker: 0x41)), writable: false))
            {
                first = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            string second;
            using (var stream = new MemoryStream(BuildZip(CompleteArchive(marker: 0x42)), writable: false))
            {
                second = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            Assert.NotEqual(first, second);
            Assert.True(Directory.Exists(first));
            Assert.True(Directory.Exists(second));
            Assert.Equal(2, Directory.GetDirectories(cacheRoot).Length);
            Assert.NotEqual(
                File.ReadAllBytes(Path.Combine(first, "adb.exe")),
                File.ReadAllBytes(Path.Combine(second, "adb.exe")));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void ExtractArchive_MissingEntryThrowsInvalidDataException()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var entries = CompleteArchive(marker: 0x43);
            entries.Remove("platform-tools/NOTICE.txt");

            using var stream = new MemoryStream(BuildZip(entries), writable: false);

            var error = Assert.Throws<InvalidDataException>(
                () => BundledTools.ExtractArchive(stream, cacheRoot));
            Assert.Contains("NOTICE.txt", error.Message, StringComparison.Ordinal);

            Assert.Empty(Directory.GetDirectories(cacheRoot, "platform-tools-*"));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void ExtractArchive_EmptyEntryThrowsInvalidDataException()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var entries = CompleteArchive(marker: 0x44);
            entries["platform-tools/source.properties"] = Array.Empty<byte>();

            using var stream = new MemoryStream(BuildZip(entries), writable: false);

            var error = Assert.Throws<InvalidDataException>(
                () => BundledTools.ExtractArchive(stream, cacheRoot));
            Assert.Contains("source.properties", error.Message, StringComparison.Ordinal);

            Assert.Empty(Directory.GetDirectories(cacheRoot, "platform-tools-*"));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void ExtractArchive_IgnoresTraversalAndExtraEntriesOutsideCache()
    {
        var root = CreateTestRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var entries = CompleteArchive(marker: 0x45);
            entries["../evil.txt"] = Encoding.UTF8.GetBytes("escape-attempt");
            entries["platform-tools/../../evil2.txt"] = Encoding.UTF8.GetBytes("escape-attempt-2");
            entries["other/adb.exe"] = Encoding.UTF8.GetBytes("not-the-whitelisted-adb");

            string extracted;
            using (var stream = new MemoryStream(BuildZip(entries), writable: false))
            {
                extracted = BundledTools.ExtractArchive(stream, cacheRoot);
            }

            Assert.Equal(RequiredFileNames.Length, Directory.GetFiles(extracted).Length);
            Assert.Equal(
                entries["platform-tools/adb.exe"],
                File.ReadAllBytes(Path.Combine(extracted, "adb.exe")));

            Assert.False(File.Exists(Path.Combine(root, "evil.txt")));
            Assert.False(File.Exists(Path.Combine(cacheRoot, "evil.txt")));
            Assert.False(File.Exists(Path.Combine(root, "evil2.txt")));
            Assert.Empty(Directory.GetFiles(root, "evil*.txt", SearchOption.AllDirectories));
            Assert.Single(Directory.GetDirectories(cacheRoot));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void GetCacheRoot_PrefersAbsoluteOverrideThenLocalApplicationData()
    {
        var root = CreateTestRoot();
        var original = Environment.GetEnvironmentVariable(CacheOverrideVariable);
        try
        {
            var custom = Path.Combine(root, "custom", "cache");
            Environment.SetEnvironmentVariable(CacheOverrideVariable, "  " + custom + "  ");
            Assert.Equal(Path.GetFullPath(custom), BundledTools.GetCacheRoot());

            Environment.SetEnvironmentVariable(CacheOverrideVariable, "   ");
            var expectedDefault = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ArmadaOS Freedom");
            Assert.Equal(expectedDefault, BundledTools.GetCacheRoot());
        }
        finally
        {
            Environment.SetEnvironmentVariable(CacheOverrideVariable, original);
            Cleanup(root);
        }
    }

    private static Dictionary<string, byte[]> CompleteArchive(byte marker)
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var fileName in RequiredFileNames)
        {
            entries["platform-tools/" + fileName] =
                Encoding.UTF8.GetBytes($"platform-tools payload {fileName} {(char)marker}");
        }

        return entries;
    }

    private static byte[] BuildZip(IReadOnlyDictionary<string, byte[]> entries)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var pair in entries.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                var entry = archive.CreateEntry(pair.Key, CompressionLevel.Optimal);
                using var entryStream = entry.Open();
                entryStream.Write(pair.Value, 0, pair.Value.Length);
            }
        }

        return buffer.ToArray();
    }

    private static string CreateTestRoot()
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
            "bundled-tools-" + Guid.NewGuid().ToString("N"));

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
