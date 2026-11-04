using System;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specification for schema2 bundles that carry model-neutral shared files. Each model's
/// nested package stays a valid schema1 manifest whose ostree-seed/kernel entries now point at the
/// mapped destinations; the shared bytes live once under common/ in the archive.
/// </summary>
public sealed class SharedBundleImportTests
{
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";
    private const string BundleVersion = "20261020.freedom.1.cafd1cc";

    private const string PackageJsonFileName = "package.json";
    private const string MarkerFileName = "marker.txt";
    private const string SeedSource = "common/seed/ostree-seed.tar.zst";
    private const string KernelSource = "common/boot/kernel.img";
    private const string SeedDestination = "seed/ostree-seed.tar.zst";
    private const string KernelDestination = "boot/kernel.img";

    // --------------------------------------------------------------- selection and materialization

    [Theory]
    [InlineData("zip", ModelA)]
    [InlineData("zip", ModelB)]
    [InlineData("tar", ModelA)]
    [InlineData("tar", ModelB)]
    public async Task Import_Schema2BundleSelectsModelAndMaterializesSharedFiles(string format, string model)
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, format);
        var archive = builder.Write();
        var archiveHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive)));
        var expectedManifestBytes = builder.Manifests[model];

        using var imported = await PackageImporter.ImportAsync(
            archive, model, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
        Assert.Equal(archive, imported.SourcePath);
        Assert.Equal(model, imported.DeviceModel);
        Assert.Equal(BundleVersion, imported.Validation.Version);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(expectedManifestBytes)),
            imported.Validation.ManifestFingerprint);

        var stage = imported.PackageDirectory;
        AssertInside(stage, fixture.WorkRoot);

        var manifestPath = Assert.Single(Directory.GetFiles(
            fixture.WorkRoot, PackageJsonFileName, SearchOption.AllDirectories));
        Assert.Equal(expectedManifestBytes, File.ReadAllBytes(manifestPath));

        Assert.Equal(SharedBundleBuilder.SharedSeedBytes, File.ReadAllBytes(Path.Combine(stage, SeedDestination)));
        Assert.Equal(SharedBundleBuilder.SharedKernelBytes, File.ReadAllBytes(Path.Combine(stage, KernelDestination)));
        Assert.Equal(
            "shared-fixture:" + model + "\n",
            File.ReadAllText(Path.Combine(stage, MarkerFileName), Encoding.UTF8));

        var expectedManifest = JsonNode.Parse(Encoding.UTF8.GetString(expectedManifestBytes))!.AsObject();
        var expectedFiles = expectedManifest["artifacts"]!.AsArray()
            .Select(artifact => Normalize(artifact!["file"]!.GetValue<string>()))
            .Append(PackageJsonFileName)
            .Append(MarkerFileName)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
        var actualFiles = Directory.GetFiles(stage, "*", SearchOption.AllDirectories)
            .Select(path => Normalize(Path.GetRelativePath(stage, path)))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expectedFiles, actualFiles);
        Assert.DoesNotContain(
            actualFiles,
            path => path.StartsWith("common/", StringComparison.Ordinal)
                || path.StartsWith("models/", StringComparison.Ordinal));

        imported.Dispose();

        Assert.False(Directory.Exists(stage));
        AssertWorkRootHasOnlyKeepers(fixture);
        Assert.Equal(archiveHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive))));
    }

    // ------------------------------------------------------------------------------ unknown models

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    public async Task Import_Schema2BundleSkipsAnEntryForAModelThisInstallerDoesNotKnow(string format)
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, format);
        // Listed first and mapped to a shared source the archive does not contain:
        // the entry is shape-checked but never selected, so neither matters.
        builder.AddUnknownModelFirst("TB999ZZ", "common/missing/unknown.bin");
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
        Assert.Equal(ModelA, imported.DeviceModel);
        var manifestPath = Assert.Single(Directory.GetFiles(
            fixture.WorkRoot, PackageJsonFileName, SearchOption.AllDirectories));
        Assert.Equal(builder.Manifests[ModelA], File.ReadAllBytes(manifestPath));
        Assert.DoesNotContain(
            Directory.GetFiles(fixture.WorkRoot, "*", SearchOption.AllDirectories),
            path => path.Contains("TB999ZZ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Import_Schema2BundleStillShapeChecksAnUnknownModelEntry()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        builder.AddUnknownModelFirst("TB999ZZ", "common/missing/unknown.bin");
        builder.Package("TB999ZZ").Remove("sharedFiles");
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    // -------------------------------------------------------------------------- missing shared data

    [Fact]
    public async Task Import_MissingSharedSourceIsInvalid()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        builder.RemoveEntry(SeedSource);
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    // ------------------------------------------------------------------------------ unsafe mappings

    [Theory]
    [InlineData("source", "../escape.bin")]
    [InlineData("source", "/absolute.bin")]
    [InlineData("source", "C:/escape.bin")]
    [InlineData("source", "..\\escape.bin")]
    [InlineData("destination", "../escape.bin")]
    [InlineData("destination", "/absolute.bin")]
    [InlineData("destination", "C:/escape.bin")]
    [InlineData("destination", "..\\escape.bin")]
    public async Task Import_UnsafeMappedPathIsInvalid(string field, string value)
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        var mapping = builder.Package(ModelA)["sharedFiles"]![0]!.AsObject();
        mapping[field] = value;
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    // ---------------------------------------------------------------------------- target collisions

    [Fact]
    public async Task Import_RejectsSharedTargetCollidingWithSelectedTreeFile()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        // Identical bytes and a hash-consistent manifest: only collision detection can reject this.
        builder.SetEntry("models/" + ModelA + "/" + SeedDestination, SharedBundleBuilder.SharedSeedBytes);
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    [Fact]
    public async Task Import_RejectsDuplicateTargetCaseInsensitively()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        builder.Package(ModelA)["sharedFiles"]!.AsArray().Add(new JsonObject
        {
            ["source"] = SeedSource,
            ["destination"] = "SEED/OSTREE-SEED.TAR.ZST",
        });
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    // ------------------------------------------------------------------------ integrity and schemas

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    public async Task Import_TamperedSharedSeedBytesAreInvalid(string format)
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, format);
        builder.SetEntry(SeedSource, new byte[] { 0x54, 0x41, 0x4D, 0x50, 0x45, 0x52 });
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    [Fact]
    public async Task Import_MissingSelectedManifestIsInvalid()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        builder.RemoveEntry("models/" + ModelA + "/" + PackageJsonFileName);
        var archive = builder.Write();

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    [Fact]
    public async Task Import_UnknownSchemaVersionIsInvalid()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        var archive = builder.Write(schemaVersion: 3);

        using var imported = await PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot);

        AssertRejected(fixture, imported, archive);
    }

    // -------------------------------------------------------------------------------- cancellation

    [Fact]
    public async Task Import_PreCancelledTokenLeavesNoExtractionDirectory()
    {
        using var fixture = new ImportFixture();
        var builder = new SharedBundleBuilder(fixture, "zip");
        var archive = builder.Write();
        var cancelled = new CancellationToken(canceled: true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PackageImporter.ImportAsync(
            archive, ModelA, InstallationTarget.Internal, fixture.WorkRoot, cancelled));

        AssertWorkRootHasOnlyKeepers(fixture);
        Assert.True(File.Exists(archive));
    }

    // ------------------------------------------------------------------------------------- helpers

    private static string Join(IReadOnlyList<string> reasons) => string.Join("; ", reasons);

    private static string Normalize(string path) => path.Replace('\\', '/');

    private static void AssertRejected(ImportFixture fixture, ImportedPackage imported, string archivePath)
    {
        Assert.NotNull(imported.Validation);
        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        Assert.Equal(archivePath, imported.SourcePath);
        AssertWorkRootHasOnlyKeepers(fixture);
        Assert.True(File.Exists(archivePath));
        Assert.False(File.Exists(Path.GetFullPath(Path.Combine(fixture.WorkRoot, "..", "escape.bin"))));
    }

    private static void AssertWorkRootHasOnlyKeepers(ImportFixture fixture)
    {
        Assert.Equal(new[] { "neighbor", "sentinel" }, DirectoryNames(fixture.WorkRoot));
        Assert.Empty(Directory.GetFiles(fixture.WorkRoot));
        Assert.Equal("sentinel", File.ReadAllText(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(fixture.NeighborDirectory, "keep.bin")));
        Assert.Single(Directory.GetFiles(fixture.SentinelDirectory));
        Assert.Single(Directory.GetFiles(fixture.NeighborDirectory));
    }

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

    /// <summary>
    /// Builds one schema2 bundle: both model subtrees, one shared seed/kernel pair under common/, and
    /// the bundle index as mutable JSON. Writer parameter chooses a real ZIP or TAR archive.
    /// </summary>
    private sealed class SharedBundleBuilder
    {
        internal static readonly byte[] SharedSeedBytes = { 0x53, 0x45, 0x45, 0x44, 0x2D, 0x46, 0x49, 0x58 };
        internal static readonly byte[] SharedKernelBytes = { 0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x2D, 0x46 };

        private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

        private readonly ImportFixture _fixture;
        private readonly string _format;
        private readonly Dictionary<string, byte[]> _entries = new(StringComparer.Ordinal);
        private readonly JsonArray _packages = new();

        internal SharedBundleBuilder(ImportFixture fixture, string format)
        {
            _fixture = fixture;
            _format = format;
            AddModel(ModelA);
            AddModel(ModelB);
            SetEntry(SeedSource, SharedSeedBytes);
            SetEntry(KernelSource, SharedKernelBytes);
        }

        /// <summary>Raw manifest bytes produced independently of any import, keyed by model.</summary>
        internal Dictionary<string, byte[]> Manifests { get; } = new(StringComparer.Ordinal);

        internal JsonObject Package(string model) =>
            _packages.Select(node => node!.AsObject())
                .Single(package => package["deviceModel"]!.GetValue<string>() == model);

        internal void SetEntry(string path, byte[] content) => _entries[path] = content;

        /// <summary>Adds a packages[] entry for a model the installer does not support, ahead of the others.</summary>
        internal void AddUnknownModelFirst(string model, string sharedSource)
        {
            SetEntry("models/" + model + "/" + PackageJsonFileName, Encoding.UTF8.GetBytes("{}"));
            _packages.Insert(0, new JsonObject
            {
                ["deviceModel"] = model,
                ["directory"] = "models/" + model,
                ["sharedFiles"] = new JsonArray
                {
                    new JsonObject { ["source"] = sharedSource, ["destination"] = SeedDestination },
                },
            });
        }

        internal void RemoveEntry(string path) => _entries.Remove(path);

        internal string Write(int schemaVersion = 2)
        {
            SetEntry("bundle.json", Encoding.UTF8.GetBytes(BundleJson(schemaVersion)));
            var path = _fixture.BundlePath("shared-bundle." + _format);

            if (string.Equals(_format, "zip", StringComparison.Ordinal))
            {
                WriteZip(path);
            }
            else if (string.Equals(_format, "tar", StringComparison.Ordinal))
            {
                WriteTar(path);
            }
            else
            {
                throw new InvalidOperationException("unsupported format " + _format);
            }

            return path;
        }

        private void AddModel(string model)
        {
            var directory = Path.Combine(_fixture.StagingRoot, "shared-package-" + model);
            PackageFixture.WritePackage(directory, model);

            var manifest = JsonNode.Parse(File.ReadAllText(PackageFixture.MetadataPath(directory)))!.AsObject();
            manifest["version"] = BundleVersion;

            foreach (var node in manifest["artifacts"]!.AsArray())
            {
                var artifact = node!.AsObject();
                var role = artifact["role"]!.GetValue<string>();
                if (role == "ostree-seed")
                {
                    MapArtifact(artifact, SeedDestination, SharedSeedBytes);
                }
                else if (role == "kernel")
                {
                    MapArtifact(artifact, KernelDestination, SharedKernelBytes);
                }
            }

            var manifestBytes = Encoding.UTF8.GetBytes(manifest.ToJsonString(SerializerOptions));
            Manifests[model] = manifestBytes;

            foreach (var file in Directory.GetFiles(directory))
            {
                var fileName = Path.GetFileName(file);
                if (fileName == PackageFixture.MetadataFileName
                    || fileName == PackageFixture.LinuxRootFileName
                    || fileName == PackageFixture.LinuxBootFileName)
                {
                    continue;
                }

                SetEntry("models/" + model + "/" + fileName, File.ReadAllBytes(file));
            }

            SetEntry("models/" + model + "/" + PackageJsonFileName, manifestBytes);
            SetEntry(
                "models/" + model + "/" + MarkerFileName,
                Encoding.UTF8.GetBytes("shared-fixture:" + model + "\n"));

            _packages.Add(new JsonObject
            {
                ["deviceModel"] = model,
                ["directory"] = "models/" + model,
                ["sharedFiles"] = new JsonArray
                {
                    new JsonObject { ["source"] = SeedSource, ["destination"] = SeedDestination },
                    new JsonObject { ["source"] = KernelSource, ["destination"] = KernelDestination },
                },
            });
        }

        private static void MapArtifact(JsonObject artifact, string destination, byte[] payload)
        {
            artifact["file"] = destination;
            artifact["bytes"] = payload.LongLength;
            artifact["sha256"] = Convert.ToHexString(SHA256.HashData(payload));
        }

        private string BundleJson(int schemaVersion) => new JsonObject
        {
            ["schemaVersion"] = schemaVersion,
            ["bundleId"] = "armadaos-freedom",
            ["version"] = BundleVersion,
            ["packages"] = _packages.DeepClone(),
        }.ToJsonString(SerializerOptions);

        private void WriteZip(string path)
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Create);

            foreach (var entry in _entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var zipEntry = archive.CreateEntry(entry.Key, CompressionLevel.NoCompression);
                using var target = zipEntry.Open();
                target.Write(entry.Value);
            }
        }

        private void WriteTar(string path)
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var writer = new TarWriter(stream, TarEntryFormat.Ustar);

            foreach (var entry in _entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var tarEntry = new UstarTarEntry(TarEntryType.RegularFile, entry.Key)
                {
                    DataStream = new MemoryStream(entry.Value, writable: false),
                };
                writer.WriteEntry(tarEntry);
            }
        }
    }
}
