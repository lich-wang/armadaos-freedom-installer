using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// IR1: one real ZIP carries two independently valid schema2 direct EDL raw packages that share only
/// the kernel, and the archive is delivered as numeric split volumes. Importing a volume must select
/// the requested model, materialise the shared kernel once and publish the new source revision.
/// All fixtures are the existing synthetic ones: no device, firmware, backup or real bundle is read.
/// </summary>
public sealed class EdlRawBundleRevisionImportTests
{
    private const string G4Model = "TB322FC";
    private const string G5Model = "TB323FU";
    private const string RevisionCommit = "2d66159b6acdf6463a1d9a0bc527f85f273e570b";
    private const string BundleId = "armadaos-freedom";
    private const string KernelSource = "common/kernel";
    private const string MarkerPrefix = "only-";
    private const string BundleStem = "raw-edl.zip";

    [Theory]
    [InlineData(G4Model)]
    [InlineData(G5Model)]
    public async Task Import_SplitBundleOfTwoEdlRawPackagesImportsTheSelectedRevision(string model)
    {
        using var fixture = new ImportFixture();
        var bundle = RevisionBundle.Build(fixture);
        var otherModel = model == G4Model ? G5Model : G4Model;

        var partHashes = bundle.Parts.Select(path => Sha256Of(path)).ToArray();
        string stage;

        using (var imported = await PackageImporter.ImportAsync(
            bundle.Parts[0], model, InstallationTarget.Internal, fixture.WorkRoot))
        {
            Assert.True(imported.Validation.IsValid, Join(imported.Validation.Reasons));
            Assert.Equal("edl-raw-v1", imported.Validation.DeploymentKind);
            Assert.Equal(model, imported.DeviceModel);

            stage = imported.PackageDirectory;
            Assert.True(Directory.Exists(stage));
            Assert.NotEqual(fixture.WorkRoot, stage);

            var manifestPath = Path.Combine(stage, "package.json");
            Assert.Equal(bundle.Manifests[model], File.ReadAllBytes(manifestPath));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(bundle.Manifests[model])),
                imported.Validation.ManifestFingerprint);

            // The staged manifest still declares the fixed revision the producer shipped.
            var staged = JsonNode.Parse(File.ReadAllText(manifestPath))!.AsObject();
            Assert.Equal(RevisionCommit, staged["sourceCommit"]!.GetValue<string>());
            Assert.Equal("edl-raw-v1", staged["deployment"]!["kind"]!.GetValue<string>());

            var runtime = Path.Combine(stage, EdlRawFixture.RuntimeFile);
            Assert.Equal(bundle.RuntimeBytes[model], File.ReadAllBytes(runtime));
            Assert.Equal(bundle.RuntimeSha[model], Sha256Of(runtime));
            Assert.NotEqual(bundle.RuntimeSha[otherModel], Sha256Of(runtime));

            var kernel = Path.Combine(stage, EdlRawFixture.KernelFile);
            Assert.Equal(bundle.KernelBytes, File.ReadAllBytes(kernel));

            var selectedMarker = Path.Combine(stage, MarkerPrefix + model + ".txt");
            Assert.True(File.Exists(selectedMarker));
            Assert.Equal(model, File.ReadAllText(selectedMarker, Encoding.UTF8));
            Assert.False(File.Exists(Path.Combine(stage, MarkerPrefix + otherModel + ".txt")));

            // The archive layout must not survive staging, and the shared kernel must not be duplicated.
            Assert.False(Directory.Exists(Path.Combine(stage, "models")));
            Assert.False(Directory.Exists(Path.Combine(stage, "common")));
            Assert.Single(Directory.GetFiles(
                stage, "package.json", SearchOption.AllDirectories));

            var contract = PackageReader.ReadEdlRawContract(stage, model);
            Assert.Equal(RevisionCommit, contract.SourceCommit);
            Assert.Equal(model, contract.DeviceModel);
            Assert.Equal(bundle.RuntimeSha[model], contract.Artifacts["runtime"].Sha256);
            Assert.Equal(bundle.KernelBytes.LongLength, contract.Artifacts["kernel"].Bytes);
        }

        Assert.False(Directory.Exists(stage));
        AssertWorkRootHasOnlyKeepers(fixture);
        Assert.All(bundle.Parts, path => Assert.True(File.Exists(path)));
        Assert.Equal(
            partHashes,
            bundle.Parts.Select(path => Sha256Of(path)).ToArray());
    }

    [Fact]
    public async Task Import_MissingMiddleVolumeIsRejectedAndLeavesWorkRootUntouched()
    {
        using var fixture = new ImportFixture();
        var bundle = RevisionBundle.Build(fixture);
        File.Delete(bundle.Parts[1]);

        using var imported = await PackageImporter.ImportAsync(
            bundle.Parts[0], G4Model, InstallationTarget.Internal, fixture.WorkRoot);

        Assert.False(imported.Validation.IsValid);
        Assert.NotEmpty(imported.Validation.Reasons);
        Assert.Contains(
            Path.GetFileName(bundle.Parts[1]),
            string.Join(" ", imported.Validation.Reasons));

        Assert.False(Directory.Exists(imported.PackageDirectory));
        AssertWorkRootHasOnlyKeepers(fixture);
        Assert.True(File.Exists(bundle.Parts[0]));
        Assert.False(File.Exists(bundle.Parts[1]));
        Assert.True(File.Exists(bundle.Parts[2]));
    }

    private static void AssertWorkRootHasOnlyKeepers(ImportFixture fixture)
    {
        Assert.Equal(
            new[] { "neighbor", "sentinel" },
            Directory.GetFileSystemEntries(fixture.WorkRoot)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray());
        Assert.True(File.Exists(Path.Combine(fixture.SentinelDirectory, "keep.txt")));
        Assert.True(File.Exists(Path.Combine(fixture.NeighborDirectory, "keep.bin")));
    }

    private static string Join(IEnumerable<string> reasons) => string.Join("; ", reasons);

    private static string Sha256Of(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    /// <summary>
    /// Builds the shared bundle once: two mutated synthetic schema2 packages nested per model, one
    /// kernel stored under <c>common/</c>, and the whole ZIP split into three numeric volumes.
    /// </summary>
    private sealed class RevisionBundle
    {
        private RevisionBundle(
            string[] parts,
            Dictionary<string, byte[]> manifests,
            Dictionary<string, byte[]> runtimeBytes,
            Dictionary<string, string> runtimeSha,
            byte[] kernelBytes)
        {
            Parts = parts;
            Manifests = manifests;
            RuntimeBytes = runtimeBytes;
            RuntimeSha = runtimeSha;
            KernelBytes = kernelBytes;
        }

        internal string[] Parts { get; }

        internal Dictionary<string, byte[]> Manifests { get; }

        internal Dictionary<string, byte[]> RuntimeBytes { get; }

        internal Dictionary<string, string> RuntimeSha { get; }

        internal byte[] KernelBytes { get; }

        internal static RevisionBundle Build(ImportFixture fixture)
        {
            using var g4 = EdlRawFixture.Create();
            using var g5 = EdlRawFixture.Create();

            var manifests = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var runtimeBytes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var runtimeSha = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var (package, model) in new[] { (g4, G4Model), (g5, G5Model) })
            {
                manifests[model] = Rewrite(package, model);
                runtimeBytes[model] = package.ReadFile(EdlRawFixture.RuntimeFile);
                runtimeSha[model] = package.Sha256Of(EdlRawFixture.RuntimeFile);
            }

            var kernelBytes = g4.ReadFile(EdlRawFixture.KernelFile);
            Assert.Equal(kernelBytes, g5.ReadFile(EdlRawFixture.KernelFile));

            var builder = new BundleBuilder(fixture.StagingRoot);
            var packages = new JsonArray();

            foreach (var (package, model) in new[] { (g4, G4Model), (g5, G5Model) })
            {
                foreach (var file in Directory.GetFiles(package.Path, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(package.Path, file).Replace('\\', '/');
                    if (string.Equals(relative, EdlRawFixture.KernelFile, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    builder.Set("models/" + model + "/" + relative, File.ReadAllBytes(file));
                }

                packages.Add(new JsonObject
                {
                    ["deviceModel"] = model,
                    ["directory"] = "models/" + model,
                    ["sharedFiles"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["source"] = KernelSource,
                            ["destination"] = EdlRawFixture.KernelFile,
                        },
                    },
                });
            }

            builder.Set(KernelSource, kernelBytes);

            var bundleJson = new JsonObject
            {
                ["schemaVersion"] = 2,
                ["bundleId"] = BundleId,
                ["version"] = EdlRawFixture.PackageVersion,
                ["packages"] = packages,
            };

            var zipPath = builder.Write(
                Path.Combine(fixture.StagingRoot, BundleStem),
                bundleJson.ToJsonString());

            var parts = SplitIntoVolumes(File.ReadAllBytes(zipPath), 3, fixture.SourceRoot);
            return new RevisionBundle(parts, manifests, runtimeBytes, runtimeSha, kernelBytes);
        }

        /// <summary>Rewrites one fixture into a common schema2 package and returns its exact bytes.</summary>
        private static byte[] Rewrite(EdlRawFixture package, string model)
        {
            var isG5 = model == G5Model;
            var metadata = package.ReadMetadata();

            metadata["packageId"] = EdlRawFixture.PackageId + "-" + model.ToLowerInvariant();
            metadata["sourceCommit"] = RevisionCommit;
            metadata["deviceModel"] = model;

            var compatible = metadata["compatible"]!.AsObject();
            compatible["soc"] = isG5 ? "SM8850" : "SM8750";
            compatible["device"] = isG5 ? "baldur" : "elden";

            // A common package carries neither the optional profile nor the coupled firmware group.
            metadata.Remove("edlProfile");
            metadata["bootCompatibility"]!.AsObject().Remove("firmwareVersions");

            var recipe = metadata["bootRecipe"]!.AsObject();
            var normal = isG5
                ? EdlRawFixture.NormalBootArgs.Replace(
                    "androidboot.hardware=elden", "androidboot.hardware=baldur", StringComparison.Ordinal)
                : EdlRawFixture.NormalBootArgs;
            recipe["normalBootArgs"] = normal;
            recipe["diagnosticBootArgs"] = normal + EdlRawFixture.DiagnosticSuffix;

            var runtime = package.ReadFile(EdlRawFixture.RuntimeFile);
            var prefix = Encoding.UTF8.GetBytes("runtime:" + model);
            Assert.True(prefix.Length < runtime.Length);
            prefix.CopyTo(runtime, 0);
            Assert.Equal(4194304, runtime.Length);
            package.WriteFile(EdlRawFixture.RuntimeFile, runtime);

            package.WriteFile(MarkerPrefix + model + ".txt", Encoding.UTF8.GetBytes(model));

            var runtimeArtifact = metadata["artifacts"]!.AsArray()
                .Select(artifact => artifact!.AsObject())
                .Single(artifact => artifact["role"]!.GetValue<string>() == "runtime");
            runtimeArtifact["file"] = EdlRawFixture.RuntimeFile;
            runtimeArtifact["bytes"] = package.BytesOf(EdlRawFixture.RuntimeFile);
            runtimeArtifact["sha256"] = package.Sha256Of(EdlRawFixture.RuntimeFile);

            package.WriteMetadata(metadata);
            return File.ReadAllBytes(package.MetadataPath);
        }

        private static string[] SplitIntoVolumes(byte[] archive, int count, string directory)
        {
            var size = (archive.Length + count - 1) / count;
            var parts = new string[count];
            for (var index = 0; index < count; index++)
            {
                var start = index * size;
                var length = Math.Min(size, archive.Length - start);
                var part = Path.Combine(directory, BundleStem + "." + (index + 1).ToString("D3"));
                File.WriteAllBytes(part, archive.AsSpan(start, length).ToArray());
                parts[index] = part;
            }

            Assert.Equal(count, Directory.GetFiles(directory, BundleStem + ".*").Length);
            Assert.False(File.Exists(Path.Combine(directory, BundleStem)));
            return parts;
        }
    }
}
