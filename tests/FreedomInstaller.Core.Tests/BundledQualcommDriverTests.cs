using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using FreedomInstaller.App;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Direct behaviour tests for the bundled Qualcomm USB driver helper. The real driver archive is
/// supplied by CI through QUALCOMM_DRIVER_TEST_ARCHIVE and read here at runtime; no driver binary
/// is read or produced by the authoring environment. All scratch data lives below
/// TestArtifactRoot.Resolve() and is removed again.
/// </summary>
public sealed class BundledQualcommDriverTests
{
    private const string ArchiveVariable = "QUALCOMM_DRIVER_TEST_ARCHIVE";
    private const string InfEntry = "qcser.inf";
    private const string CatEntry = "qcser.cat";
    private const string SysEntry = "serial/amd64/qcusbser.sys";

    // Independent pin table: expected length and SHA-256 of each of the three required files.
    private static readonly (string RelativePath, int Length, string Sha256)[] ExpectedFiles =
    {
        (InfEntry, 210084, "3D77C8FB0EB01E3B1A6CB1DE96BEE48CD4A80A95E91DC055888241FB5E8D69AC"),
        (CatEntry, 153527, "8771CB736412945178FCF087EB172A27F2FDD429026AE633A87271D51EE5212F"),
        (SysEntry, 277720, "2B8361B492C59DE4C856F5DD644FE99CB09C572DFB05C4B5833301A64FCB8EEF"),
    };

    private static readonly string[] ExpectedRelativePaths = ExpectedFiles
        .Select(file => file.RelativePath)
        .OrderBy(path => path, StringComparer.Ordinal)
        .ToArray();

    private static readonly string[] ExpectedRelativeDirectories = { "serial", "serial/amd64" };

    [Fact]
    public void ExtractArchive_WritesPinnedThreeFileLayoutUnderCacheRootWithSpaces()
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache root with spaces", "nested");
            var files = Extract(LoadArchiveBytes(), cacheRoot);

            Assert.Equal(
                Path.GetFullPath(Path.Combine(files.DirectoryPath, InfEntry)),
                Path.GetFullPath(files.InfPath));
            Assert.Equal(
                Path.GetFullPath(cacheRoot),
                Path.GetFullPath(Path.GetDirectoryName(Path.GetFullPath(files.DirectoryPath))));

            AssertPinnedFiles(files.DirectoryPath);
            Assert.Equal(ExpectedRelativeDirectories, RelativeDirectories(files.DirectoryPath));

            // No staging directory survives a successful extraction.
            Assert.Equal(
                new[] { Path.GetFullPath(files.DirectoryPath) },
                Directory.GetDirectories(cacheRoot).Select(Path.GetFullPath).ToArray());

            BundledQualcommDriver.ValidateFiles(files);
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    [Fact]
    public void ExtractArchive_SameArchiveReusesCompleteCacheWithoutRewritingIt()
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var archiveBytes = LoadArchiveBytes();

            var first = Extract(archiveBytes, cacheRoot);
            var pinnedTime = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(first.InfPath, pinnedTime);

            var second = Extract(archiveBytes, cacheRoot);

            Assert.Equal(first.DirectoryPath, second.DirectoryPath);
            Assert.Equal(first.InfPath, second.InfPath);
            Assert.Equal(pinnedTime, File.GetLastWriteTimeUtc(second.InfPath));
            AssertPinnedFiles(second.DirectoryPath);
            BundledQualcommDriver.ValidateFiles(second);
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    [Fact]
    public void ExtractArchive_RepairsCacheWhoseSysFileWasBitFlippedAtSameLength()
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var archiveBytes = LoadArchiveBytes();
            var files = Extract(archiveBytes, cacheRoot);

            var sysPath = Path.Combine(files.DirectoryPath, "serial", "amd64", "qcusbser.sys");
            var damaged = File.ReadAllBytes(sysPath);
            damaged[damaged.Length / 2] ^= 0xFF;
            File.WriteAllBytes(sysPath, damaged);

            Assert.Throws<InvalidDataException>(() => BundledQualcommDriver.ValidateFiles(files));

            var repaired = Extract(archiveBytes, cacheRoot);

            Assert.Equal(files.DirectoryPath, repaired.DirectoryPath);
            AssertPinnedFiles(repaired.DirectoryPath);
            BundledQualcommDriver.ValidateFiles(repaired);
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    [Fact]
    public void ExtractArchive_RepairsOwnedCacheWithExtraFile()
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var archiveBytes = LoadArchiveBytes();
            var files = Extract(archiveBytes, cacheRoot);

            var strayPath = Path.Combine(files.DirectoryPath, "stray.bin");
            File.WriteAllBytes(strayPath, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

            Assert.Throws<InvalidDataException>(() => BundledQualcommDriver.ValidateFiles(files));

            var repaired = Extract(archiveBytes, cacheRoot);

            Assert.False(File.Exists(strayPath));
            Assert.Equal(files.DirectoryPath, repaired.DirectoryPath);
            AssertPinnedFiles(repaired.DirectoryPath);
            BundledQualcommDriver.ValidateFiles(repaired);
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    [Fact]
    public void ValidateFiles_RejectsDescriptorWithInfPathOutsideDirectory()
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var files = Extract(LoadArchiveBytes(), cacheRoot);

            var outside = files with { InfPath = Path.Combine(root, "elsewhere", InfEntry) };

            Assert.Throws<InvalidDataException>(() => BundledQualcommDriver.ValidateFiles(outside));
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    [Fact]
    public void EnsureAvailable_ThrowsBecauseTestAssemblyDoesNotEmbedTheDriverArchive()
    {
        var error = Assert.Throws<InvalidOperationException>(() => BundledQualcommDriver.EnsureAvailable());

        Assert.Contains("FreedomInstaller.QualcommUsbDriver.zip", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("missing-cat")]
    [InlineData("duplicate-inf")]
    [InlineData("unknown-file")]
    [InlineData("traversal-inf")]
    [InlineData("wrong-sys-length")]
    [InlineData("wrong-inf-hash")]
    [InlineData("unexpected-directory")]
    [InlineData("nonempty-directory")]
    public void ExtractArchive_RejectsMalformedArchiveWithoutCreatingCache(string shape)
    {
        var root = NewScratchRoot();
        try
        {
            var cacheRoot = Path.Combine(root, "cache");
            var archiveBytes = BuildMalformedArchive(shape, LoadArchivePayload());

            using (var stream = new MemoryStream(archiveBytes, writable: false))
            {
                Assert.Throws<InvalidDataException>(
                    () => BundledQualcommDriver.ExtractArchive(stream, cacheRoot));
            }

            // Nothing was extracted, not even a staging directory, and nothing escaped the root.
            Assert.Empty(Directory.GetFiles(root, "*", SearchOption.AllDirectories));
            Assert.False(File.Exists(Path.Combine(root, InfEntry)));
            Assert.False(File.Exists(Path.Combine(root, CatEntry)));
        }
        finally
        {
            DeleteScratch(root);
        }
    }

    private static byte[] BuildMalformedArchive(string shape, Dictionary<string, byte[]> payload)
    {
        var entries = new List<(string Name, byte[] Content)>
        {
            (InfEntry, payload[InfEntry]),
            (CatEntry, payload[CatEntry]),
            ("serial/", Array.Empty<byte>()),
            ("serial/amd64/", Array.Empty<byte>()),
            (SysEntry, payload[SysEntry]),
        };

        switch (shape)
        {
            case "missing-cat":
                entries.RemoveAll(entry => entry.Name == CatEntry);
                break;
            case "duplicate-inf":
                entries.Add((InfEntry, payload[InfEntry]));
                break;
            case "unknown-file":
                entries.Add(("readme.txt", new byte[] { 0x52 }));
                break;
            case "traversal-inf":
                entries.RemoveAll(entry => entry.Name == InfEntry);
                entries.Insert(0, ("../" + InfEntry, payload[InfEntry]));
                break;
            case "wrong-sys-length":
                entries.RemoveAll(entry => entry.Name == SysEntry);
                entries.Add((
                    SysEntry,
                    payload[SysEntry].Take(payload[SysEntry].Length / 2).ToArray()));
                break;
            case "wrong-inf-hash":
                var flipped = (byte[])payload[InfEntry].Clone();
                flipped[flipped.Length / 2] ^= 0xFF;
                entries.RemoveAll(entry => entry.Name == InfEntry);
                entries.Insert(0, (InfEntry, flipped));
                break;
            case "unexpected-directory":
                entries.Add(("drivers/", Array.Empty<byte>()));
                break;
            case "nonempty-directory":
                entries.RemoveAll(entry => entry.Name == "serial/");
                entries.Insert(0, ("serial/", new byte[] { 0x42 }));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(shape), shape, "unknown fixture shape");
        }

        return BuildArchive(entries);
    }

    private static byte[] BuildArchive(IEnumerable<(string Name, byte[] Content)> entries)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using var entryStream = entry.Open();
                entryStream.Write(content, 0, content.Length);
            }
        }

        return buffer.ToArray();
    }

    private static byte[] LoadArchiveBytes()
    {
        var path = ArchivePath();
        return File.ReadAllBytes(path);
    }

    private static Dictionary<string, byte[]> LoadArchivePayload()
    {
        var path = ArchivePath();
        using var archive = ZipFile.OpenRead(path);
        var payload = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        foreach (var (relativePath, length, sha256) in ExpectedFiles)
        {
            var entry = archive.GetEntry(relativePath);
            Assert.True(entry != null, $"archive '{path}' has no '{relativePath}' entry");

            using var entryStream = entry.Open();
            using var buffer = new MemoryStream();
            entryStream.CopyTo(buffer);
            var bytes = buffer.ToArray();

            Assert.Equal(length, bytes.Length);
            Assert.Equal(sha256, Convert.ToHexString(SHA256.HashData(bytes)));
            payload[relativePath] = bytes;
        }

        return payload;
    }

    private static string ArchivePath()
    {
        var path = Environment.GetEnvironmentVariable(ArchiveVariable);
        Assert.False(
            string.IsNullOrWhiteSpace(path),
            $"{ArchiveVariable} must point at the real Qualcomm driver ZIP supplied by CI");
        Assert.True(File.Exists(path), $"{ArchiveVariable} points at a missing file: '{path}'");
        return path;
    }

    private static QualcommDriverFiles Extract(byte[] archiveBytes, string cacheRoot)
    {
        using var stream = new MemoryStream(archiveBytes, writable: false);
        return BundledQualcommDriver.ExtractArchive(stream, cacheRoot);
    }

    private static void AssertPinnedFiles(string directoryPath)
    {
        Assert.Equal(ExpectedRelativePaths, RelativeFiles(directoryPath));

        foreach (var (relativePath, length, sha256) in ExpectedFiles)
        {
            var path = Path.Combine(directoryPath, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(path), $"missing '{relativePath}' below '{directoryPath}'");

            var bytes = File.ReadAllBytes(path);
            Assert.Equal(length, bytes.Length);
            Assert.Equal(sha256, Convert.ToHexString(SHA256.HashData(bytes)));
        }
    }

    private static string[] RelativeFiles(string directoryPath)
    {
        return Directory
            .GetFiles(directoryPath, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(directoryPath, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] RelativeDirectories(string directoryPath)
    {
        return Directory
            .GetDirectories(directoryPath, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(directoryPath, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private static string NewScratchRoot()
    {
        var root = Path.Combine(
            TestArtifactRoot.Resolve(),
            "qualcomm-driver-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void DeleteScratch(string root)
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
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
