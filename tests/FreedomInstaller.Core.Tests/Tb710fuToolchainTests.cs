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
    /// Formal, env-based skip only: skipped while EDL_TOOLCHAIN_TB710FU_TEST_BUNDLE_PATH is unset/blank.
    /// Once the environment variable is supplied, a wrong path or a wrong package fails the test.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class Tb710fuRealBundleFactAttribute : FactAttribute
    {
        public Tb710fuRealBundleFactAttribute()
        {
            Skip = Tb710fuToolchainTests.RealBundleSkipReason();
        }
    }

    /// <summary>
    /// Real-bundle coverage of the TB710FU EDL tool archive through the public
    /// <see cref="EdlToolchain.LoadAsync(Stream, string, System.Threading.CancellationToken)"/> entry point. The
    /// archive is an external input (it is never part of this repository); without it every case is skipped.
    /// Archive-free cross-profile rejections live in <see cref="EdlToolchainTests"/>.
    /// </summary>
    public class Tb710fuToolchainTests
    {
        public const string BundleEnvironmentVariable = "EDL_TOOLCHAIN_TB710FU_TEST_BUNDLE_PATH";

        // Independent literals of the TB710FU contract identity (not shared with production code).
        private const string ExpectedProfileId = "tb710fu-9008-495";
        private const string ExpectedModel = "TB710FU";
        private const string ExpectedHardwareId = "003050E100400000";
        private const string ExpectedProvenance = "TB710FU/ZUXOS_1.5.04.495_WITHOUT_UBL/EDL/xbl_s_devprg_ns.melf";
        private const string ExpectedFirehoseRelPath = "tools/tb710fu/firehose.melf";
        private const long ExpectedFirehoseBytes = 1573224L;
        private const string ExpectedFirehoseSha = "ad4689b1c52458250d46829ee46a89ec974e69f8e82eee8d4950427919e0b9eb";

        private const string ManifestEntryName = "manifest.json";
        private const string SentinelText = "tb710fu-toolchain-sentinel";

        [Tb710fuRealBundleFact]
        public async Task LoadAsync_tb710fu_bundle_stages_the_pinned_firehose()
        {
            var bundlePath = RequireBundlePath();
            using var root = new TempRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);

            using (var stream = new FileStream(bundlePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var toolchain = await EdlToolchain.LoadAsync(stream, workRoot))
            {
                Assert.Equal(ExpectedProfileId, toolchain.ProfileId);
                Assert.Equal(ExpectedModel, toolchain.Model);
                Assert.Equal(ExpectedHardwareId, toolchain.HardwareId);
                Assert.Equal(ExpectedProvenance, toolchain.AndroidBuild);
                Assert.Same(EdlDeviceProfiles.FindById(ExpectedProfileId), toolchain.Profile);

                Assert.EndsWith(
                    ExpectedFirehoseRelPath,
                    toolchain.FirehosePath.Replace('\\', '/'),
                    StringComparison.Ordinal);
                byte[] firehose = File.ReadAllBytes(toolchain.FirehosePath);
                Assert.Equal(ExpectedFirehoseBytes, firehose.LongLength);
                Assert.Equal(ExpectedFirehoseSha, Sha256Hex(firehose));

                foreach (var toolPath in new[]
                         {
                             toolchain.ClientPath, toolchain.UsbLibraryPath, toolchain.PythonPath,
                             toolchain.AvbCliPath, toolchain.GptCliPath
                         })
                {
                    Assert.True(File.Exists(toolPath), "Required staged tool is missing: " + toolPath);
                }
            }

            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
        }

        [Tb710fuRealBundleFact]
        public async Task LoadAsync_tb710fu_rejects_forged_firehose_with_self_consistent_manifest()
        {
            var bundlePath = RequireBundlePath();
            using var root = new TempRoot();
            var workRoot = root.CreateWorkRoot();

            using var clone = RewriteBundle(bundlePath, (manifest, members) =>
            {
                var entry = FindManifestEntry(manifest, "firehose");
                var member = members.Single(m => string.Equals(m.Name, ExpectedFirehoseRelPath, StringComparison.Ordinal));
                member.Payload[0] ^= 0x01;
                entry["sha256"] = Sha256Hex(member.Payload);
            });

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(clone, workRoot));
            Assert.Empty(Directory.GetDirectories(workRoot));
        }

        [Tb710fuRealBundleFact]
        public async Task LoadAsync_tb710fu_bundle_relabelled_as_another_profile_is_rejected()
        {
            var bundlePath = RequireBundlePath();
            using var root = new TempRoot();
            var workRoot = root.CreateWorkRoot();

            // The real TB710FU payloads under the G4 profile id must never select the G4 profile.
            using var clone = RewriteBundle(bundlePath, (manifest, _) =>
            {
                manifest["profileId"] = "g4-9008-259";
                manifest["model"] = "TB322FC";
            });

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(clone, workRoot));
            Assert.Empty(Directory.GetDirectories(workRoot));
        }

        // ---------------------------------------------------------------- helpers

        /// <summary>
        /// The single formal skip condition of the TB710FU real-bundle cases: the environment variable is
        /// unset/blank. A supplied but wrong path or wrong package fails the calling test.
        /// </summary>
        internal static string? RealBundleSkipReason() =>
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(BundleEnvironmentVariable))
                ? BundleEnvironmentVariable + " is unset or blank; the real TB710FU bundle cases are pending."
                : null;

        private static string RequireBundlePath()
        {
            var bundlePath = Environment.GetEnvironmentVariable(BundleEnvironmentVariable);
            Assert.False(
                string.IsNullOrWhiteSpace(bundlePath),
                BundleEnvironmentVariable + " must be set to the real TB710FU bundle ZIP path.");
            Assert.True(File.Exists(bundlePath!), BundleEnvironmentVariable + " does not exist: " + bundlePath);
            return bundlePath!;
        }

        private static string CreateSentinel(string workRoot)
        {
            var path = Path.Combine(workRoot, "sibling-sentinel.txt");
            File.WriteAllText(path, SentinelText);
            return path;
        }

        private static string Sha256Hex(byte[] payload) =>
            Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        private static JsonObject FindManifestEntry(JsonObject manifest, string role)
        {
            var entries = manifest["entries"] as JsonArray
                ?? throw new InvalidDataException("The TB710FU test bundle manifest has no entries array.");

            foreach (var node in entries)
            {
                if (node is JsonObject entry &&
                    string.Equals(entry["role"]?.GetValue<string>(), role, StringComparison.Ordinal))
                {
                    return entry;
                }
            }

            throw new InvalidDataException("The TB710FU test bundle manifest has no entry for role '" + role + "'.");
        }

        /// <summary>
        /// In-memory clone of the real bundle; the source archive is only opened for reading.
        /// </summary>
        private static MemoryStream RewriteBundle(string bundlePath, Action<JsonObject, List<Member>> mutate)
        {
            var members = new List<Member>();
            using (var archive = ZipFile.OpenRead(bundlePath))
            {
                foreach (var entry in archive.Entries)
                {
                    using var source = entry.Open();
                    using var buffer = new MemoryStream();
                    source.CopyTo(buffer);
                    members.Add(new Member(entry.FullName, buffer.ToArray(), entry.ExternalAttributes));
                }
            }

            var manifestMember = members.Single(m => string.Equals(m.Name, ManifestEntryName, StringComparison.Ordinal));
            var manifest = JsonNode.Parse(Encoding.UTF8.GetString(manifestMember.Payload)) as JsonObject
                ?? throw new InvalidDataException("The TB710FU test bundle manifest.json must contain a JSON object.");

            mutate(manifest, members);
            manifestMember.Payload = Encoding.UTF8.GetBytes(manifest.ToJsonString());

            var clone = new MemoryStream();
            using (var zip = new ZipArchive(clone, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var member in members)
                {
                    var entry = zip.CreateEntry(member.Name, CompressionLevel.Fastest);
                    entry.ExternalAttributes = member.ExternalAttributes;
                    using var target = entry.Open();
                    target.Write(member.Payload, 0, member.Payload.Length);
                }
            }

            clone.Position = 0;
            return clone;
        }

        private sealed class Member
        {
            public Member(string name, byte[] payload, int externalAttributes)
            {
                Name = name;
                Payload = payload;
                ExternalAttributes = externalAttributes;
            }

            public string Name { get; }

            public byte[] Payload { get; set; }

            public int ExternalAttributes { get; }
        }

        /// <summary>Per-test isolated directory; only the GUID child created here is ever deleted.</summary>
        private sealed class TempRoot : IDisposable
        {
            public TempRoot()
            {
                DirectoryPath = Path.Combine(Path.GetTempPath(), "tb710fu-tc-" + Guid.NewGuid().ToString("N"));
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
