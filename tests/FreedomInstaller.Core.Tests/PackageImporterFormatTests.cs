using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specification for importing real archives in the delivery formats. Each case reads a
/// pre-built bundle from the test output directory (see the fixture contract in U006) and asserts
/// selection, byte-identical manifest preservation, payload identity, staging containment, and
/// dispose isolation. No archive is fabricated and no implementation source text is inspected.
/// </summary>
public sealed class PackageImporterFormatTests
{
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    private const string PackageJsonFileName = "package.json";
    private const string PayloadFileName = "payload.txt";

    public static IEnumerable<object[]> ArchiveAndModelCases()
    {
        // Explicit sixteen cases: every delivery format against both supported models.
        yield return new object[] { "bundle.zip", ModelA };
        yield return new object[] { "bundle.zip", ModelB };
        yield return new object[] { "bundle.7z", ModelA };
        yield return new object[] { "bundle.7z", ModelB };
        yield return new object[] { "bundle.rar", ModelA };
        yield return new object[] { "bundle.rar", ModelB };
        yield return new object[] { "bundle.tar", ModelA };
        yield return new object[] { "bundle.tar", ModelB };
        yield return new object[] { "bundle.tar.gz", ModelA };
        yield return new object[] { "bundle.tar.gz", ModelB };
        yield return new object[] { "bundle.tar.xz", ModelA };
        yield return new object[] { "bundle.tar.xz", ModelB };
        yield return new object[] { "bundle.tar.zst", ModelA };
        yield return new object[] { "bundle.tar.zst", ModelB };
        yield return new object[] { "bundle.tar.bz2", ModelA };
        yield return new object[] { "bundle.tar.bz2", ModelB };
    }

    public static IEnumerable<object[]> UnsafeArchiveCases()
    {
        yield return new object[] { "unsafe-traversal.tar.gz" };
        yield return new object[] { "unsafe-symlink.tar.gz" };
        yield return new object[] { "unsafe-duplicate.tar.gz" };
    }

    // ------------------------------------------------------- real formats, selection, byte identity

    [Theory]
    [MemberData(nameof(ArchiveAndModelCases))]
    public async Task Import_RealArchiveSelectsRequestedModelAndPreservesManifestBytes(
        string archiveFileName,
        string model)
    {
        using var fixture = new ImportFixture();

        var archivePath = FixturePath("Import", archiveFileName);
        Assert.True(File.Exists(archivePath), archivePath);

        var expectedManifestPath = FixturePath("Import", "expectations", model, PackageJsonFileName);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
        var expectedManifestBytes = File.ReadAllBytes(expectedManifestPath);
        var expectedFingerprint = Convert.ToHexString(SHA256.HashData(expectedManifestBytes));

        using var imported = await PackageImporter.ImportAsync(
            archivePath, model, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));
        Assert.Equal(model, imported.DeviceModel);
        Assert.Equal(archivePath, imported.SourcePath);
        Assert.Equal(expectedFingerprint, imported.Validation.ManifestFingerprint);

        // Exactly one manifest may exist under the work root: extracting both profiles fails here.
        var extractedManifests = Directory.GetFiles(
            fixture.WorkRoot, PackageJsonFileName, SearchOption.AllDirectories);
        var manifest = Assert.Single(extractedManifests);
        Assert.Equal(expectedManifestBytes, File.ReadAllBytes(manifest));

        var payloadPath = Path.Combine(imported.PackageDirectory, PayloadFileName);
        Assert.True(File.Exists(payloadPath), payloadPath);
        Assert.Equal("format-fixture:" + model + "\n", File.ReadAllText(payloadPath, Encoding.UTF8));

        AssertStrictlyInside(imported.PackageDirectory, fixture.WorkRoot);
        var staging = imported.PackageDirectory;

        imported.Dispose();

        Assert.False(Directory.Exists(staging));
        Assert.Equal("sentinel", File.ReadAllText(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.Equal(
            new byte[] { 1, 2, 3 },
            File.ReadAllBytes(Path.Combine(fixture.NeighborDirectory, "keep.bin")));
        Assert.True(File.Exists(archivePath), archivePath);
        Assert.True(File.Exists(expectedManifestPath), expectedManifestPath);
    }

    // -------------------------------------------------------------------- unsafe TAR entries

    [Theory]
    [MemberData(nameof(UnsafeArchiveCases))]
    public async Task Import_UnsafeTarArchiveIsRejectedWithoutExtractionOrEscape(string archiveFileName)
    {
        using var fixture = new ImportFixture();

        var archivePath = FixturePath("Import", archiveFileName);
        Assert.True(File.Exists(archivePath), archivePath);

        using var imported = await PackageImporter.ImportAsync(
            archivePath, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);

        Assert.Equal(new[] { "neighbor", "sentinel" }, DirectoryNames(fixture.WorkRoot));
        Assert.Equal("sentinel", File.ReadAllText(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.Equal(
            new byte[] { 1, 2, 3 },
            File.ReadAllBytes(Path.Combine(fixture.NeighborDirectory, "keep.bin")));
        Assert.True(File.Exists(archivePath), archivePath);

        var escaping = Path.GetFullPath(Path.Combine(fixture.WorkRoot, "..", "outside.bin"));
        Assert.False(File.Exists(escaping));
    }

    // ---------------------------------------------------------------------------------- helpers

    private static string FixturePath(params string[] parts)
    {
        var segments = new List<string> { AppContext.BaseDirectory, "Fixtures" };
        segments.AddRange(parts);
        return Path.Combine(segments.ToArray());
    }

    private static void AssertStrictlyInside(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        Assert.False(Path.IsPathRooted(relative));
        Assert.NotEqual(".", relative);
        Assert.False(relative == "..");
        Assert.False(relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal));
        Assert.False(relative.StartsWith("../", StringComparison.Ordinal));
    }

    private static string[] DirectoryNames(string root) =>
        Directory.GetDirectories(root)
            .Select(path => Path.GetFileName(path) ?? string.Empty)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
}
