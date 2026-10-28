using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    /// <summary>
    /// Formal, env-based skip only: skipped while EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH is unset/blank.
    /// Once the environment variable is supplied, a wrong path or a wrong package fails the test.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class G5RealBundleFactAttribute : FactAttribute
    {
        public G5RealBundleFactAttribute()
        {
            Skip = Gen5ToolchainTests.RealBundleSkipReason();
        }
    }

    /// <summary>
    /// Theory counterpart of <see cref="G5RealBundleFactAttribute"/>: every inline case is skipped only
    /// while EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH is unset/blank.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class G5RealBundleTheoryAttribute : TheoryAttribute
    {
        public G5RealBundleTheoryAttribute()
        {
            Skip = Gen5ToolchainTests.RealBundleSkipReason();
        }
    }

    /// <summary>
    /// RED coverage for the future G5 bundle: the real archive is staged through the public
    /// <see cref="EdlToolchain.LoadAsync(Stream, string, System.Threading.CancellationToken)"/> entry point,
    /// and every compile-pinned G5 payload must reject a self-consistent forged clone.
    /// </summary>
    public class Gen5ToolchainTests
    {
        public const string BundleEnvironmentVariable = "EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH";

        // Independent literals of the reviewed G5 contract identity (not shared with production code).
        private const string ExpectedProfileId = "g5-9008-y7005";
        private const string ExpectedModel = "TB323FU";
        private const string ExpectedHardwareId = "002B40E100400000";
        private const string ExpectedProvenance = "QCTool-2026.3.21-1/lenovo/devprg_legion-y700-5";
        private const string ExpectedFirehoseRelPath = "tools/g5/qsahara_device_programmer.xml";

        private static readonly string[] ReferencedPayloadFileNames =
        {
            "multi_image_qti.mbn",
            "multi_image.mbn",
            "xbl_sc.elf",
            "signed_firmware_soc_view.elf",
            "sequencer_ram.elf",
            "tme_config.elf",
            "prog_firehose_ddr.elf",
            "xbl_config_devprg.elf"
        };

        private const string Image38Role = "image38";
        private const string EscapedRolePath = "../../g5-escape.bin";
        private const string ManifestEntryName = "manifest.json";
        private const string SentinelText = "g5p1b-a1-sentinel";

        // ---------------------------------------------------------------- positive

        [G5RealBundleFact]
        public async Task LoadAsync_g5_reference_bundle_stages_every_compile_pinned_payload()
        {
            var bundlePath = RequireBundlePath();
            using var root = new Gen5TempRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            var originalLength = new FileInfo(bundlePath).Length;

            using (var stream = new FileStream(bundlePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var toolchain = await EdlToolchain.LoadAsync(stream, workRoot))
            {
                Assert.Equal(ExpectedProfileId, toolchain.ProfileId);
                Assert.Equal(ExpectedModel, toolchain.Model);
                Assert.Equal(ExpectedHardwareId, toolchain.HardwareId);

                var profile = toolchain.Profile;
                Assert.Equal(ExpectedProfileId, profile.ProfileId);
                Assert.Equal(ExpectedModel, profile.Model);
                Assert.Equal(ExpectedHardwareId, profile.FullHardwareId);
                Assert.True(profile.IsComplete, "The trusted G5 profile must be complete before staging.");
                Assert.Equal(ExpectedFirehoseRelPath, profile.LoaderEntryPath);
                Assert.Contains(toolchain.AndroidBuild, profile.AllowedDisplayIds);

                var builtIn = EdlDeviceProfiles.FindById(ExpectedProfileId);
                Assert.True(
                    builtIn != null,
                    "EdlDeviceProfiles must expose the built-in reference profile '" + ExpectedProfileId + "'.");
                Assert.Same(builtIn, profile);

                Assert.Equal(ExpectedProvenance, toolchain.AndroidBuild);
                Assert.Equal(new[] { ExpectedProvenance }, profile.AllowedDisplayIds);

                var staging = toolchain.StagingDirectory;
                Assert.True(Path.IsPathFullyQualified(staging), "StagingDirectory must be fully qualified.");
                Assert.Equal(
                    0,
                    string.Compare(
                        Path.TrimEndingDirectorySeparator(workRoot),
                        Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(staging)!),
                        StringComparison.OrdinalIgnoreCase));

                Assert.True(Path.IsPathFullyQualified(toolchain.FirehosePath));
                Assert.EndsWith(
                    ExpectedFirehoseRelPath,
                    toolchain.FirehosePath.Replace('\\', '/'),
                    StringComparison.Ordinal);

                var payloadDirectory = Path.GetDirectoryName(toolchain.FirehosePath)!;
                foreach (var fileName in ReferencedPayloadFileNames)
                {
                    var stagedPayload = Path.Combine(payloadDirectory, fileName);
                    Assert.True(File.Exists(stagedPayload), "Referenced G5 payload is not staged: " + stagedPayload);
                    Assert.True(new FileInfo(stagedPayload).Length > 0, "Staged G5 payload is empty: " + stagedPayload);
                }

                foreach (var toolPath in new[]
                         {
                             toolchain.ClientPath, toolchain.UsbLibraryPath, toolchain.PythonPath,
                             toolchain.AvbCliPath, toolchain.GptCliPath
                         })
                {
                    Assert.True(File.Exists(toolPath), "Required staged tool is missing: " + toolPath);
                }

                toolchain.Dispose();
                toolchain.Dispose();

                Assert.False(Directory.Exists(staging), "Dispose must remove only its own staging directory.");
                Assert.True(File.Exists(sentinel), "The sibling sentinel must be preserved.");
                Assert.Equal(SentinelText, File.ReadAllText(sentinel));
                Assert.True(Directory.Exists(workRoot), "The caller workRoot must be preserved.");
                Assert.Equal(originalLength, new FileInfo(bundlePath).Length);
                Assert.True(stream.CanRead, "Caller owns the archive stream; it must stay readable.");
            }
        }

        // ---------------------------------------------------------------- forged payload pins

        [G5RealBundleTheory]
        [InlineData("firehose")]
        [InlineData("image36")]
        [InlineData("image37")]
        [InlineData("image21")]
        [InlineData("image60")]
        [InlineData("image59")]
        [InlineData("image61")]
        [InlineData("image13")]
        [InlineData(Image38Role)]
        public async Task LoadAsync_g5_rejects_forged_payload_with_self_consistent_manifest(string role)
        {
            var bundlePath = RequireBundlePath();
            using var root = new Gen5TempRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            var originalLength = new FileInfo(bundlePath).Length;

            using var clone = CloneWithForgedPayload(bundlePath, role);

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(clone, workRoot));

            AssertNoStagingChild(workRoot);
            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
            Assert.Equal(originalLength, new FileInfo(bundlePath).Length);
        }

        // ---------------------------------------------------------------- missing image38

        [G5RealBundleTheory]
        [InlineData("missingManifestEntry")]
        [InlineData("missingZipEntry")]
        public async Task LoadAsync_g5_rejects_bundle_without_image38(string scenario)
        {
            var bundlePath = RequireBundlePath();
            using var root = new Gen5TempRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            var originalLength = new FileInfo(bundlePath).Length;

            var removeManifestEntry = string.Equals(scenario, "missingManifestEntry", StringComparison.Ordinal);
            var removeZipEntry = string.Equals(scenario, "missingZipEntry", StringComparison.Ordinal);
            if (!removeManifestEntry && !removeZipEntry)
            {
                throw new InvalidOperationException("Unknown scenario: " + scenario);
            }

            using var clone = CloneWithoutRole(bundlePath, Image38Role, removeManifestEntry, removeZipEntry);

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(clone, workRoot));

            AssertNoStagingChild(workRoot);
            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
            Assert.Equal(originalLength, new FileInfo(bundlePath).Length);
        }

        // ---------------------------------------------------------------- escaped image38 path

        [G5RealBundleFact]
        public async Task LoadAsync_g5_rejects_escaped_image38_path_before_staging()
        {
            var bundlePath = RequireBundlePath();
            using var root = new Gen5TempRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            var originalLength = new FileInfo(bundlePath).Length;

            using var clone = CloneWithEscapedRolePath(bundlePath, Image38Role, EscapedRolePath);

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(clone, workRoot));

            AssertNoStagingChild(workRoot);
            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
            Assert.Equal(originalLength, new FileInfo(bundlePath).Length);
        }

        // ---------------------------------------------------------------- helpers

        private static string RequireBundlePath()
        {
            var bundlePath = Environment.GetEnvironmentVariable(BundleEnvironmentVariable);
            Assert.False(
                string.IsNullOrWhiteSpace(bundlePath),
                BundleEnvironmentVariable + " must be set to the real G5 bundle ZIP path.");
            Assert.True(File.Exists(bundlePath!), BundleEnvironmentVariable + " does not exist: " + bundlePath);
            return bundlePath!;
        }

        private static string CreateSentinel(string workRoot)
        {
            var path = Path.Combine(workRoot, "sibling-sentinel.txt");
            File.WriteAllText(path, SentinelText);
            return path;
        }

        private static void AssertNoStagingChild(string workRoot)
        {
            Assert.True(Directory.Exists(workRoot), "The caller workRoot must be preserved.");
            Assert.Empty(Directory.GetDirectories(workRoot));
        }

        private static string Sha256Hex(byte[] payload) =>
            Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        /// <summary>
        /// The single formal skip condition of the G5 real-bundle cases: the environment variable is
        /// unset/blank. A supplied but wrong path or wrong package fails the calling test.
        /// </summary>
        internal static string? RealBundleSkipReason() =>
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(BundleEnvironmentVariable))
                ? BundleEnvironmentVariable +
                  " is unset or blank; the real G5 bundle cases are pending."
                : null;

        /// <summary>
        /// In-memory clone of the real bundle. The source archive is only ever opened for reading and is
        /// never rewritten; the manifest copy and every untouched payload (client, python, all other roles)
        /// stay byte-identical to the real bundle.
        /// </summary>
        private static MemoryStream CloneWithForgedPayload(string bundlePath, string role) =>
            RewriteBundle(bundlePath, (manifest, members) =>
            {
                var manifestEntry = FindManifestEntry(manifest, role);
                var relativePath = manifestEntry["path"]!.GetValue<string>();
                var member = members.Single(m => string.Equals(m.Name, relativePath, StringComparison.Ordinal));

                Assert.True(member.Payload.Length > 0, "The G5 payload for role '" + role + "' must not be empty.");
                member.Payload[0] ^= 0x01;
                manifestEntry["sha256"] = Sha256Hex(member.Payload);
            });

        private static MemoryStream CloneWithoutRole(
            string bundlePath,
            string role,
            bool removeManifestEntry,
            bool removeZipEntry) =>
            RewriteBundle(bundlePath, (manifest, members) =>
            {
                var manifestEntry = FindManifestEntry(manifest, role);
                var relativePath = manifestEntry["path"]!.GetValue<string>();

                if (removeZipEntry)
                {
                    Assert.Equal(
                        1,
                        members.RemoveAll(m => string.Equals(m.Name, relativePath, StringComparison.Ordinal)));
                }

                if (removeManifestEntry)
                {
                    var entries = (JsonArray)manifest["entries"]!;
                    Assert.True(entries.Remove(manifestEntry), "The image38 manifest entry must be removable.");
                }
            });

        private static MemoryStream CloneWithEscapedRolePath(string bundlePath, string role, string escapedPath) =>
            RewriteBundle(bundlePath, (manifest, members) =>
            {
                var manifestEntry = FindManifestEntry(manifest, role);
                var relativePath = manifestEntry["path"]!.GetValue<string>();
                var member = members.Single(m => string.Equals(m.Name, relativePath, StringComparison.Ordinal));

                member.Name = escapedPath;
                manifestEntry["path"] = escapedPath;
            });

        private static JsonObject FindManifestEntry(JsonObject manifest, string role)
        {
            var entries = manifest["entries"] as JsonArray
                ?? throw new InvalidDataException("The G5 test bundle manifest has no entries array.");

            foreach (var node in entries)
            {
                if (node is JsonObject entry &&
                    string.Equals(entry["role"]?.GetValue<string>(), role, StringComparison.Ordinal))
                {
                    return entry;
                }
            }

            throw new InvalidDataException("The G5 test bundle manifest has no entry for role '" + role + "'.");
        }

        private static MemoryStream RewriteBundle(
            string bundlePath,
            Action<JsonObject, List<BundleMember>> mutate)
        {
            var members = ReadBundle(bundlePath);
            var manifestMember = members.Single(m => string.Equals(m.Name, ManifestEntryName, StringComparison.Ordinal));

            var manifest = JsonNode.Parse(Encoding.UTF8.GetString(manifestMember.Payload)) as JsonObject
                ?? throw new InvalidDataException("The G5 test bundle manifest.json must contain a JSON object.");

            mutate(manifest, members);
            manifestMember.Payload = Encoding.UTF8.GetBytes(manifest.ToJsonString());

            var clone = new MemoryStream();
            using (var zip = new ZipArchive(clone, ZipArchiveMode.Create, leaveOpen: true))
            {
                WriteMember(zip, manifestMember);
                foreach (var member in members)
                {
                    if (!ReferenceEquals(member, manifestMember))
                    {
                        WriteMember(zip, member);
                    }
                }
            }

            clone.Position = 0;
            return clone;
        }

        private static List<BundleMember> ReadBundle(string bundlePath)
        {
            var members = new List<BundleMember>();
            using var archive = ZipFile.OpenRead(bundlePath);
            foreach (var entry in archive.Entries)
            {
                using var source = entry.Open();
                using var buffer = new MemoryStream();
                source.CopyTo(buffer);
                members.Add(new BundleMember(entry.FullName, buffer.ToArray(), entry.ExternalAttributes));
            }

            return members;
        }

        private static void WriteMember(ZipArchive zip, BundleMember member)
        {
            var entry = zip.CreateEntry(member.Name, CompressionLevel.Fastest);
            entry.ExternalAttributes = member.ExternalAttributes;

            using var target = entry.Open();
            target.Write(member.Payload, 0, member.Payload.Length);
        }

        private sealed class BundleMember
        {
            public BundleMember(string name, byte[] payload, int externalAttributes)
            {
                Name = name;
                Payload = payload;
                ExternalAttributes = externalAttributes;
            }

            public string Name { get; set; }

            public byte[] Payload { get; set; }

            public int ExternalAttributes { get; }
        }

        /// <summary>
        /// Per-test isolated directory beneath <see cref="Path.GetTempPath"/> (the remote Docker test temp).
        /// Only the GUID child created here is ever deleted.
        /// </summary>
        private sealed class Gen5TempRoot : IDisposable
        {
            public Gen5TempRoot()
            {
                DirectoryPath = Path.Combine(Path.GetTempPath(), "g5p1b-a1-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(DirectoryPath);
            }

            public string DirectoryPath { get; }

            public string CreateWorkRoot()
            {
                var workRoot = Path.Combine(DirectoryPath, "work");
                Directory.CreateDirectory(workRoot);
                return workRoot;
            }

            public void Dispose()
            {
                if (Directory.Exists(DirectoryPath))
                {
                    Directory.Delete(DirectoryPath, recursive: true);
                }
            }
        }
    }
}
