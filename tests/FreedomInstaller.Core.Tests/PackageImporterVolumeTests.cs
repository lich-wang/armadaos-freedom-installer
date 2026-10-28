using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specification for split-volume delivery: decimal-padded raw parts for every archive
/// format and genuine native RAR5 volumes. Expected manifests are read from the independent
/// expectations fixtures, never derived from the importer output, and no production volume helper
/// is inspected or reproduced here.
/// </summary>
public sealed class PackageImporterVolumeTests
{
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    private const string PackageJsonFileName = "package.json";
    private const string PayloadFileName = "payload.txt";

    private static readonly string[] RawArchiveNames =
    {
        "bundle.zip",
        "bundle.7z",
        "bundle.tar",
        "bundle.tar.gz",
        "bundle.tar.xz",
        "bundle.tar.zst",
        "bundle.tar.bz2",
    };

    public static IEnumerable<object[]> RawSplitCases()
    {
        // Seven delivery formats against both supported models: fourteen explicit cases.
        foreach (var name in RawArchiveNames)
        {
            yield return new object[] { name, ModelA };
            yield return new object[] { name, ModelB };
        }
    }

    public static IEnumerable<object[]> MiddleSelectionCases()
    {
        yield return new object[] { "zip", ModelA };
        yield return new object[] { "7z", ModelB };
        yield return new object[] { "rar", ModelB };
    }

    // ------------------------------------------------------------ raw decimal-padded parts

    [Theory]
    [MemberData(nameof(RawSplitCases))]
    public async Task Import_RawSplitVolumesSelectsModelAndPreservesSelectedSource(
        string archiveFileName,
        string model)
    {
        using var fixture = new ImportFixture();

        var archivePath = FixturePath("Import", archiveFileName);
        Assert.True(File.Exists(archivePath), archivePath);

        var expectedManifestPath = ExpectedManifestPath(model, nativeRar: false);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
        var expectedManifestBytes = File.ReadAllBytes(expectedManifestPath);

        var parts = SplitIntoVolumes(archivePath, fixture.SourceRoot);
        var sourceBefore = SnapshotSources(fixture.SourceRoot);

        using var imported = await PackageImporter.ImportAsync(
            parts[0], model, InstallationTarget.Internal, fixture.WorkRoot);

        var stage = AssertImportSucceeded(fixture, imported, expectedManifestBytes, parts[0], model);

        imported.Dispose();

        AssertDisposed(fixture, stage, sourceBefore, parts[0]);
        Assert.True(File.Exists(archivePath), archivePath);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
    }

    // ---------------------------------------------------------------- genuine RAR5 volumes

    [Theory]
    [InlineData(ModelA)]
    [InlineData(ModelB)]
    public async Task Import_NativeRarVolumesAssembleArtifactAcrossVolumeBoundary(string model)
    {
        using var fixture = new ImportFixture();
        var parts = CopyNativeVolumes(fixture);

        var expectedManifestPath = ExpectedManifestPath(model, nativeRar: true);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
        var expectedManifestBytes = File.ReadAllBytes(expectedManifestPath);

        var sourceBefore = SnapshotSources(fixture.SourceRoot);

        using var imported = await PackageImporter.ImportAsync(
            parts[0], model, InstallationTarget.Internal, fixture.WorkRoot);

        var stage = AssertImportSucceeded(fixture, imported, expectedManifestBytes, parts[0], model);

        imported.Dispose();

        AssertDisposed(fixture, stage, sourceBefore, parts[0]);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
    }

    // ------------------------------------------------------- selecting a later volume

    [Theory]
    [MemberData(nameof(MiddleSelectionCases))]
    public async Task Import_MiddleVolumeNormalizesGroupButKeepsExactSelectedPath(string kind, string model)
    {
        using var fixture = new ImportFixture();
        var parts = PrepareVolumes(fixture, kind);

        string selected;
        if (kind == "zip")
        {
            // Only the selected volume uses an upper-case basename; grouping must stay case-insensitive.
            selected = Path.Combine(fixture.SourceRoot, "BUNDLE.ZIP.002");
            File.Move(parts[1], selected);
        }
        else if (kind == "rar")
        {
            selected = parts[2];
        }
        else
        {
            selected = parts[1];
        }

        var expectedManifestPath = ExpectedManifestPath(
            model, nativeRar: string.Equals(kind, "rar", StringComparison.Ordinal));
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
        var expectedManifestBytes = File.ReadAllBytes(expectedManifestPath);

        var sourceBefore = SnapshotSources(fixture.SourceRoot);

        using var imported = await PackageImporter.ImportAsync(
            selected, model, InstallationTarget.Internal, fixture.WorkRoot);

        var stage = AssertImportSucceeded(fixture, imported, expectedManifestBytes, selected, model);

        imported.Dispose();

        AssertDisposed(fixture, stage, sourceBefore, selected);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
    }

    // ------------------------------------------------------------- missing middle volume

    [Theory]
    [InlineData("zip")]
    [InlineData("7z")]
    [InlineData("rar")]
    public async Task Import_MissingMiddleVolumeIsRejectedNamingTheMissingPart(string kind)
    {
        using var fixture = new ImportFixture();
        var parts = PrepareVolumes(fixture, kind);

        var missingName = Path.GetFileName(parts[1]);
        File.Delete(parts[1]);
        var sourceBefore = SnapshotSources(fixture.SourceRoot);

        using var imported = await PackageImporter.ImportAsync(
            parts[0], ModelB, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        Assert.Contains(
            imported.Validation.Reasons,
            reason => reason.Contains(missingName, StringComparison.OrdinalIgnoreCase));
        AssertNoResidue(fixture);
        AssertSourcesUnchanged(sourceBefore, fixture.SourceRoot);
    }

    // ------------------------------------------------------------ truncated last volume

    [Theory]
    [InlineData("zip")]
    [InlineData("7z")]
    [InlineData("rar")]
    public async Task Import_TruncatedLastVolumeIsRejectedWithoutOutput(string kind)
    {
        using var fixture = new ImportFixture();
        var parts = PrepareVolumes(fixture, kind);

        using (var last = new FileStream(parts[^1], FileMode.Open, FileAccess.Write, FileShare.None))
        {
            last.SetLength(0);
        }

        var sourceBefore = SnapshotSources(fixture.SourceRoot);

        using var imported = await PackageImporter.ImportAsync(
            parts[0], ModelB, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoResidue(fixture);
        AssertSourcesUnchanged(sourceBefore, fixture.SourceRoot);
    }

    // ------------------------------------------------------------------------ success checks

    private static string AssertImportSucceeded(
        ImportFixture fixture,
        ImportedPackage imported,
        byte[] expectedManifestBytes,
        string expectedSourcePath,
        string model)
    {
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));
        Assert.Equal(model, imported.DeviceModel);
        Assert.Equal(expectedSourcePath, imported.SourcePath);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(expectedManifestBytes)),
            imported.Validation.ManifestFingerprint);

        var packageDirectory = imported.PackageDirectory;
        AssertStrictlyInside(packageDirectory, fixture.WorkRoot);

        var manifestPath = Assert.Single(
            Directory.GetFiles(fixture.WorkRoot, PackageJsonFileName, SearchOption.AllDirectories));
        Assert.Equal(expectedManifestBytes, File.ReadAllBytes(manifestPath));

        var payloadPath = Path.Combine(packageDirectory, PayloadFileName);
        Assert.Equal("format-fixture:" + model + "\n", File.ReadAllText(payloadPath, Encoding.UTF8));

        // Exact inventory from the independent expected manifest: any merged or leftover file fails.
        Assert.Equal(ExpectedInventory(expectedManifestBytes), Inventory(packageDirectory));

        foreach (var file in Directory.GetFiles(fixture.WorkRoot, "*", SearchOption.AllDirectories))
        {
            Assert.True(IsStrictlyInside(file, packageDirectory) || IsKeeper(fixture, file), file);
        }

        AssertKeeper(fixture);
        return packageDirectory;
    }

    private static void AssertDisposed(
        ImportFixture fixture,
        string stage,
        SortedDictionary<string, string> sourceBefore,
        string selectedPath)
    {
        Assert.False(Directory.Exists(stage));
        Assert.True(File.Exists(selectedPath), selectedPath);
        AssertSourcesUnchanged(sourceBefore, fixture.SourceRoot);
        AssertKeeper(fixture);
    }

    private static void AssertNoResidue(ImportFixture fixture)
    {
        Assert.Equal(new[] { "neighbor", "sentinel" }, DirectoryNames(fixture.WorkRoot));
        Assert.Equal(
            new[] { "neighbor/keep.bin", "sentinel/keep.txt" },
            Directory.GetFiles(fixture.WorkRoot, "*", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(fixture.WorkRoot, path).Replace('\\', '/'))
                .OrderBy(path => path, StringComparer.Ordinal)
                .ToArray());
        AssertKeeper(fixture);
    }

    // ------------------------------------------------------------------------ source helpers

    private static string[] PrepareVolumes(ImportFixture fixture, string kind)
    {
        switch (kind)
        {
            case "zip":
                return SplitIntoVolumes(FixturePath("Import", "bundle.zip"), fixture.SourceRoot);
            case "7z":
                return SplitIntoVolumes(FixturePath("Import", "bundle.7z"), fixture.SourceRoot);
            case "rar":
                return CopyNativeVolumes(fixture);
            default:
                throw new InvalidOperationException("unknown volume kind " + kind);
        }
    }

    /// <summary>Writes bounded copies of a fixture as .001, .002, ... without producing a full copy.</summary>
    private static string[] SplitIntoVolumes(string sourcePath, string destinationRoot)
    {
        var length = new FileInfo(sourcePath).Length;
        var partSize = (int)Math.Min(1024, Math.Max(1, length / 3));
        var buffer = new byte[partSize];
        var parts = new List<string>();

        using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var number = 1;
        while (true)
        {
            var read = 0;
            while (read < partSize)
            {
                var chunk = source.Read(buffer, read, partSize - read);
                if (chunk == 0)
                {
                    break;
                }

                read += chunk;
            }

            if (read == 0)
            {
                break;
            }

            var partPath = Path.Combine(
                destinationRoot,
                Path.GetFileName(sourcePath) + "." + number.ToString("D3", CultureInfo.InvariantCulture));
            using (var part = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                part.Write(buffer, 0, read);
            }

            parts.Add(partPath);
            number++;
        }

        Assert.True(parts.Count >= 3, "fixture must split into at least three parts");
        return parts.ToArray();
    }

    private static string[] CopyNativeVolumes(ImportFixture fixture)
    {
        var parts = new List<string>();
        for (var number = 1; number <= 6; number++)
        {
            var name = "bundle.part" + number.ToString(CultureInfo.InvariantCulture) + ".rar";
            var destination = Path.Combine(fixture.SourceRoot, name);
            File.Copy(FixturePath("Import", "rar-volumes", name), destination, overwrite: false);
            parts.Add(destination);
        }

        return parts.ToArray();
    }

    private static SortedDictionary<string, string> SnapshotSources(string directory)
    {
        var snapshot = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var path in Directory.GetFiles(directory))
        {
            snapshot[Path.GetFileName(path)] =
                new FileInfo(path).Length.ToString(CultureInfo.InvariantCulture)
                + ":"
                + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        }

        return snapshot;
    }

    private static void AssertSourcesUnchanged(
        SortedDictionary<string, string> before,
        string directory)
    {
        var after = SnapshotSources(directory);
        Assert.Equal(before.Keys.ToArray(), after.Keys.ToArray());
        foreach (var name in before.Keys)
        {
            Assert.Equal(before[name], after[name]);
        }
    }

    // ------------------------------------------------------------------------ generic helpers

    private static string FixturePath(params string[] parts)
    {
        var segments = new List<string> { AppContext.BaseDirectory, "Fixtures" };
        segments.AddRange(parts);
        return Path.Combine(segments.ToArray());
    }

    private static string ExpectedManifestPath(string model, bool nativeRar) =>
        nativeRar
            ? FixturePath("Import", "rar-volumes", "expectations", model, PackageJsonFileName)
            : FixturePath("Import", "expectations", model, PackageJsonFileName);

    private static string[] ExpectedInventory(byte[] manifestBytes)
    {
        using var document = JsonDocument.Parse(manifestBytes);
        var files = document.RootElement
            .GetProperty("artifacts")
            .EnumerateArray()
            .Select(artifact => artifact.GetProperty("file").GetString() ?? string.Empty)
            .ToList();
        files.Add(PackageJsonFileName);
        files.Add(PayloadFileName);
        return files.OrderBy(name => name, StringComparer.Ordinal).ToArray();
    }

    private static string[] Inventory(string directory) =>
        Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(directory, path).Replace('\\', '/'))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

    private static void AssertKeeper(ImportFixture fixture)
    {
        Assert.Equal("sentinel", File.ReadAllText(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.Equal(
            new byte[] { 1, 2, 3 },
            File.ReadAllBytes(Path.Combine(fixture.NeighborDirectory, "keep.bin")));
    }

    private static bool IsKeeper(ImportFixture fixture, string path) =>
        string.Equals(
            Path.GetFullPath(path),
            Path.GetFullPath(Path.Combine(fixture.SentinelDirectory, "keep.txt")),
            StringComparison.OrdinalIgnoreCase)
        || string.Equals(
            Path.GetFullPath(path),
            Path.GetFullPath(Path.Combine(fixture.NeighborDirectory, "keep.bin")),
            StringComparison.OrdinalIgnoreCase);

    private static void AssertStrictlyInside(string path, string root) =>
        Assert.True(IsStrictlyInside(path, root), path);

    private static bool IsStrictlyInside(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return !Path.IsPathRooted(relative)
            && relative != "."
            && relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !relative.StartsWith("../", StringComparison.Ordinal);
    }

    private static string[] DirectoryNames(string root) =>
        Directory.GetDirectories(root)
            .Select(path => Path.GetFileName(path) ?? string.Empty)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
}
