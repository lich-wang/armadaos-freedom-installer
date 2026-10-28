using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specification for <see cref="PackageImporter"/>. Every test is red on purpose: the
/// skeleton throws <see cref="NotImplementedException"/> and must not be weakened.
/// <para>
/// Bundles are built from the existing <see cref="PackageFixture"/> packages (a few bytes per
/// artefact, never firmware, never flashable) and packed with <see cref="ZipArchive"/> into a real
/// ZIP. Nothing here inspects implementation source text.
/// </para>
/// </summary>
public sealed class PackageImporterTests
{
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    /// <summary>Unix mode S_IFLNK | 0777 stored in the high word of a ZIP external attribute.</summary>
    private static readonly int SymlinkAttributes = unchecked((int)0xA1FF0000);

    // ------------------------------------------------------------- selection and fingerprinting

    [Theory]
    [InlineData(ModelA)]
    [InlineData(ModelB)]
    public async Task Import_SameBundleSelectsOnlyTheRequestedModelAndFingerprintsItsManifest(string model)
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.AddPackage(ModelB);
        var zip = bundle.Write(
            fixture.BundlePath(),
            BundleJson((ModelA, "models/" + ModelA), (ModelB, "models/" + ModelB)));

        using var imported = await PackageImporter.ImportAsync(
            zip, model, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.Equal(zip, imported.SourcePath);
        Assert.Equal(model, imported.DeviceModel);
        Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
        Assert.True(imported.Validation.TestOnly);
        Assert.Equal(PackageFixture.PackageId, imported.Validation.PackageId);
        Assert.Equal(PackageFixture.PackageVersion, imported.Validation.Version);

        var expectedFingerprint = Convert.ToHexString(SHA256.HashData(bundle.Manifests[model]));
        Assert.Equal(expectedFingerprint, imported.Validation.ManifestFingerprint);

        Assert.NotNull(imported.Validation.Storage);
        Assert.Equal(1 * TestSizes.GiB, imported.Validation.Storage!.LinuxBootBytes);
        Assert.Equal(20 * TestSizes.GiB, imported.Validation.Storage.SystemRequiredBytes);

        AssertInside(imported.PackageDirectory, fixture.WorkRoot);

        var extractedManifests = Directory.GetFiles(
            fixture.WorkRoot,
            PackageFixture.MetadataFileName,
            SearchOption.AllDirectories);
        var manifest = Assert.Single(extractedManifests);
        Assert.Equal(expectedFingerprint, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(manifest))));
    }

    [Theory]
    [InlineData(ModelA)]
    [InlineData(ModelB)]
    public async Task Import_LegacyPackageDirectoryValidatesAndDisposeKeepsSourceIntact(string model)
    {
        using var fixture = new ImportFixture();
        var source = fixture.WriteLegacyPackage(model);

        using (var imported = await PackageImporter.ImportAsync(
            source, model, InstallationTarget.Internal, fixture.WorkRoot))
        {
            Assert.Equal(source, imported.SourcePath);
            Assert.Equal(model, imported.DeviceModel);
            Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
            Assert.True(imported.Validation.TestOnly);
            Assert.Equal(PackageFixture.PackageVersion, imported.Validation.Version);
        }

        Assert.True(Directory.Exists(source));
        Assert.True(File.Exists(PackageFixture.MetadataPath(source)));
        Assert.True(File.Exists(Path.Combine(source, PackageFixture.SystemFileName)));
        Assert.True(File.Exists(Path.Combine(source, PackageFixture.LinuxRootFileName)));
    }

    // ------------------------------------------------------------------------ extraction and dispose

    [Fact]
    public async Task Import_StagesBelowWorkRootAndDisposeRemovesOnlyItsOwnOutput()
    {
        using var fixture = new ImportFixture();
        var zip = WriteTwoModelBundle(fixture);

        var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertInside(imported.PackageDirectory, fixture.WorkRoot);
        Assert.NotEqual(fixture.WorkRoot, imported.PackageDirectory);
        Assert.Single(Directory.GetFiles(
            imported.PackageDirectory,
            PackageFixture.MetadataFileName,
            SearchOption.AllDirectories));
        Assert.True(File.Exists(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.True(Directory.Exists(fixture.NeighborDirectory));

        imported.Dispose();

        Assert.False(Directory.Exists(imported.PackageDirectory));
        Assert.True(Directory.Exists(fixture.SentinelDirectory));
        Assert.True(File.Exists(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.True(Directory.Exists(fixture.NeighborDirectory));
        Assert.True(File.Exists(zip));
    }

    // ------------------------------------------------------------------------------ model rejection

    [Theory]
    [InlineData("missing")]
    [InlineData("unsupported")]
    [InlineData("mismatch")]
    public async Task Import_RejectsMissingUnsupportedAndMismatchedModels(string scenario)
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        string source;
        string requested;

        switch (scenario)
        {
            case "missing":
                bundle.AddPackage(ModelA);
                source = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));
                requested = ModelB;
                break;

            case "unsupported":
                bundle.AddPackage(ModelA);
                source = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));
                requested = "TB999ZZ";
                break;

            case "mismatch":
                // The bundle claims TB322FC but the nested package declares TB323FU.
                bundle.AddPackage(ModelB);
                source = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelB)));
                requested = ModelA;
                break;

            default:
                throw new InvalidOperationException("unknown scenario " + scenario);
        }

        using var imported = await PackageImporter.ImportAsync(
            source, requested, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
    }

    [Fact]
    public async Task Import_RejectsDuplicateModelDeclarationsInOneBundle()
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        var zip = bundle.Write(
            fixture.BundlePath(),
            BundleJson((ModelA, "models/" + ModelA), (ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
    }

    // --------------------------------------------------------------------------- artifact integrity

    [Fact]
    public async Task Import_RejectsTamperedSelectedArtifactAndRemovesPartialOutput()
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.Set(
            "models/" + ModelA + "/" + PackageFixture.LinuxBootFileName,
            new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        var zip = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
    }

    [Fact]
    public async Task Import_RejectsMissingArtifactAndRemovesPartialOutput()
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.Remove("models/" + ModelA + "/" + PackageFixture.SystemFileName);
        var zip = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
    }

    // ------------------------------------------------------------------------------ install targets

    [Theory]
    [InlineData(InstallationTarget.Internal, true)]
    [InlineData(InstallationTarget.TfCard, false)]
    public async Task Import_PreservesInstallTargetsAndTestOnlyFromTheExistingValidator(
        InstallationTarget target,
        bool expectedValid)
    {
        using var fixture = new ImportFixture();
        // PackageFixture writes no installTargets list: a legacy package is internal-only.
        var zip = WriteTwoModelBundle(fixture);

        using var imported = await PackageImporter.ImportAsync(zip, ModelA, target, fixture.WorkRoot);

        if (expectedValid)
        {
            Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
            Assert.True(imported.Validation.TestOnly);
        }
        else
        {
            Assert.False(imported.Validation.IsValid);
            Assert.NotEmpty(imported.Validation.Reasons);
            AssertNoOutput(fixture);
        }
    }

    // ------------------------------------------------------------------------- hostile ZIP entries

    [Theory]
    [InlineData("../outside.bin")]
    [InlineData("/outside.bin")]
    [InlineData("C:/outside.bin")]
    public async Task Import_RejectsTraversalAbsoluteAndDriveQualifiedZipEntries(string entryName)
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.Append(entryName, Encoding.UTF8.GetBytes("outside"));
        var zip = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);

        var escaping = Path.GetFullPath(Path.Combine(fixture.WorkRoot, "..", "outside.bin"));
        Assert.False(File.Exists(escaping));
        Assert.False(File.Exists(Path.Combine(fixture.SourceRoot, "outside.bin")));
    }

    [Fact]
    public async Task Import_RejectsDuplicateSelectedZipEntries()
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.Append(
            "models/" + ModelA + "/" + PackageFixture.MetadataFileName,
            bundle.Manifests[ModelA]);
        var zip = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
    }

    [Fact]
    public async Task Import_RejectsSymlinkZipEntryWithoutWritingOutsideWorkRoot()
    {
        using var fixture = new ImportFixture();
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.Set(
            "models/" + ModelA + "/" + PackageFixture.LinuxRootFileName,
            Encoding.UTF8.GetBytes("../outside.bin"),
            SymlinkAttributes);
        var zip = bundle.Write(fixture.BundlePath(), BundleJson((ModelA, "models/" + ModelA)));

        using var imported = await PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        AssertNoOutput(fixture);
        Assert.False(File.Exists(Path.GetFullPath(Path.Combine(fixture.WorkRoot, "..", "outside.bin"))));
    }

    // ----------------------------------------------------------------------- cancellation and errors

    [Fact]
    public async Task Import_PreCancelledTokenLeavesNoExtractionDirectory()
    {
        using var fixture = new ImportFixture();
        var zip = WriteTwoModelBundle(fixture);
        var cancelled = new CancellationToken(canceled: true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PackageImporter.ImportAsync(
            zip, ModelA, InstallationTarget.Internal, fixture.WorkRoot, cancelled));

        Assert.Equal(new[] { "neighbor", "sentinel" }, DirectoryNames(fixture.WorkRoot));
    }

    [Theory]
    [InlineData("missing-file")]
    [InlineData("not-a-zip")]
    [InlineData("no-bundle")]
    [InlineData("bad-json")]
    [InlineData("bad-schema")]
    public async Task Import_MalformedInputIsAnInvalidResultNotALeakedException(string scenario)
    {
        using var fixture = new ImportFixture();
        string source;

        switch (scenario)
        {
            case "missing-file":
                source = Path.Combine(fixture.SourceRoot, "missing-" + Guid.NewGuid().ToString("N") + ".zip");
                break;

            case "not-a-zip":
                source = fixture.BundlePath("not-a-zip.zip");
                File.WriteAllText(source, "this is not a zip archive");
                break;

            case "no-bundle":
                var noBundle = new BundleBuilder(fixture.StagingRoot);
                noBundle.AddPackage(ModelA);
                source = noBundle.Write(fixture.BundlePath(), bundleJson: null);
                break;

            case "bad-json":
                var badJson = new BundleBuilder(fixture.StagingRoot);
                badJson.AddPackage(ModelA);
                source = badJson.Write(
                    fixture.BundlePath(),
                    "{\"schemaVersion\":1,\"bundleId\":\"armadaos-freedom\",\"packages\":[");
                break;

            case "bad-schema":
                var badSchema = new BundleBuilder(fixture.StagingRoot);
                badSchema.AddPackage(ModelA);
                source = badSchema.Write(
                    fixture.BundlePath(),
                    BundleJson(3, (ModelA, "models/" + ModelA)));
                break;

            default:
                throw new InvalidOperationException("unknown scenario " + scenario);
        }

        using var imported = await PackageImporter.ImportAsync(
            source, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.NotNull(imported.Validation);
        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        Assert.Equal(source, imported.SourcePath);
        AssertNoOutput(fixture);
    }

    // --------------------------------------------------------------------------------- helpers

    private static string WriteTwoModelBundle(ImportFixture fixture)
    {
        var bundle = new BundleBuilder(fixture.StagingRoot);
        bundle.AddPackage(ModelA);
        bundle.AddPackage(ModelB);
        return bundle.Write(
            fixture.BundlePath(),
            BundleJson((ModelA, "models/" + ModelA), (ModelB, "models/" + ModelB)));
    }

    private static string BundleJson(params (string Model, string Directory)[] packages)
        => BundleJson(1, packages);

    private static string BundleJson(int schemaVersion, params (string Model, string Directory)[] packages)
    {
        var bundle = new
        {
            schemaVersion,
            bundleId = "armadaos-freedom",
            version = PackageFixture.PackageVersion,
            packages = packages
                .Select(package => new { deviceModel = package.Model, directory = package.Directory })
                .ToArray(),
        };

        return JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string Join(IReadOnlyList<string> reasons) => string.Join("; ", reasons);

    private static void AssertInside(string path, string root)
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

    /// <summary>A rejected or cancelled import must not leave any extraction directory behind.</summary>
    private static void AssertNoOutput(ImportFixture fixture)
    {
        Assert.Equal(new[] { "neighbor", "sentinel" }, DirectoryNames(fixture.WorkRoot));
    }
}

/// <summary>Scratch tree for one import test: source, work root with keepers, and a staging area.</summary>
internal sealed class ImportFixture : IDisposable
{
    private readonly string _root;

    internal ImportFixture()
    {
        _root = Path.Combine(TestArtifactRoot.Resolve(), "import-fixture-" + Guid.NewGuid().ToString("N"));
        SourceRoot = Path.Combine(_root, "source");
        WorkRoot = Path.Combine(_root, "work");
        StagingRoot = Path.Combine(_root, "staging");

        Directory.CreateDirectory(SourceRoot);
        Directory.CreateDirectory(WorkRoot);
        Directory.CreateDirectory(StagingRoot);
        Directory.CreateDirectory(SentinelDirectory);
        Directory.CreateDirectory(NeighborDirectory);
        File.WriteAllText(Path.Combine(SentinelDirectory, "keep.txt"), "sentinel");
        File.WriteAllBytes(Path.Combine(NeighborDirectory, "keep.bin"), new byte[] { 1, 2, 3 });
    }

    internal string SourceRoot { get; }

    internal string WorkRoot { get; }

    internal string StagingRoot { get; }

    internal string SentinelDirectory => Path.Combine(WorkRoot, "sentinel");

    internal string NeighborDirectory => Path.Combine(WorkRoot, "neighbor");

    internal string BundlePath(string fileName = "package.zip") => Path.Combine(SourceRoot, fileName);

    internal string WriteLegacyPackage(string model)
    {
        var directory = Path.Combine(SourceRoot, "legacy-" + model);
        PackageFixture.WritePackage(directory, model);
        return directory;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
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

/// <summary>Builds a real ZIP from the shared fixture packages, plus any extra or replaced entry.</summary>
internal sealed class BundleBuilder
{
    private readonly List<(string Name, byte[] Content, int Attributes)> _entries = new();

    internal BundleBuilder(string stagingRoot)
    {
        Directory.CreateDirectory(stagingRoot);
        StagingRoot = stagingRoot;
    }

    internal string StagingRoot { get; }

    internal Dictionary<string, byte[]> Manifests { get; } = new(StringComparer.Ordinal);

    internal void AddPackage(string model)
    {
        var directory = Path.Combine(StagingRoot, "package-" + model);
        PackageFixture.WritePackage(directory, model);

        foreach (var file in Directory.GetFiles(directory).OrderBy(path => path, StringComparer.Ordinal))
        {
            Set($"models/{model}/{Path.GetFileName(file)}", File.ReadAllBytes(file));
        }

        Manifests[model] = File.ReadAllBytes(PackageFixture.MetadataPath(directory));
    }

    internal void Set(string name, byte[] content, int attributes = 0)
    {
        var index = _entries.FindIndex(entry => string.Equals(entry.Name, name, StringComparison.Ordinal));
        if (index >= 0)
        {
            _entries[index] = (name, content, attributes);
        }
        else
        {
            _entries.Add((name, content, attributes));
        }
    }

    internal void Append(string name, byte[] content, int attributes = 0) =>
        _entries.Add((name, content, attributes));

    internal void Remove(string name) =>
        _entries.RemoveAll(entry => string.Equals(entry.Name, name, StringComparison.Ordinal));

    internal string Write(string zipPath, string? bundleJson)
    {
        if (bundleJson is not null)
        {
            Set("bundle.json", Encoding.UTF8.GetBytes(bundleJson));
        }

        using var stream = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);

        foreach (var entry in _entries)
        {
            var zipEntry = archive.CreateEntry(entry.Name, CompressionLevel.Fastest);
            zipEntry.ExternalAttributes = entry.Attributes;
            using var target = zipEntry.Open();
            target.Write(entry.Content);
        }

        return zipPath;
    }
}
