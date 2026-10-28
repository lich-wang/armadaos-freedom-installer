using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    /// <summary>
    /// Formal, env-based skip only: skipped while EDL_TOOLCHAIN_TEST_BUNDLE_PATH is unset/blank.
    /// Once the env var is supplied, a wrong path or wrong package fails the test.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class RealEdlToolchainBundleFactAttribute : FactAttribute
    {
        public RealEdlToolchainBundleFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("EDL_TOOLCHAIN_TEST_BUNDLE_PATH")))
            {
                Skip = "EDL_TOOLCHAIN_TEST_BUNDLE_PATH is unset or blank; the real bundle positive is pending.";
            }
        }
    }

    public class EdlToolchainTests
    {
        // Independent literals of the reviewed contract identity (not shared with production code).
        private const string ExpectedProfileId = "g4-9008-259";
        private const string ExpectedModel = "TB322FC";
        private const string ExpectedAndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
        private const string ExpectedHardwareId = "0028D0E100400000";

        private const string ClientRole = "client";
        private const string UsbLibraryRole = "usbLibrary";
        private const string FirehoseRole = "firehose";
        private const string LicenseRole = "license";
        private const string PythonRole = "python";
        private const string AvbRole = "avb";
        private const string AvbCliRole = "avbCli";
        private const string GptRole = "gpt";
        private const string GptCliRole = "gptCli";

        private const string ClientRelPath = "tools/edl-ng.exe";
        private const string UsbLibraryRelPath = "tools/libusb-1.0.dll";
        private const string FirehoseRelPath = "tools/firehose.melf";
        private const string LicenseRelPath = "tools/LICENSE.txt";
        private const string PythonRelPath = "python/python-3.14.8-embed-amd64.zip";
        private const string AvbRelPath = "scripts/avb_stock.py";
        private const string AvbCliRelPath = "scripts/avb_stock_cli.py";
        private const string GptRelPath = "scripts/portable_gpt.py";
        private const string GptCliRelPath = "scripts/edl_gpt_cli.py";

        private const long ClientPinBytes = 12015022L;
        private const long FirehosePinBytes = 1697740L;
        private const long PythonPinBytes = 12601679L;

        private const string ClientPinSha = "655530e926b57d70f1c690869c495253a6eaae28746f370d5b9dbf921d4a4b3b";
        private const string FirehosePinSha = "a38993803139d881f47adfa66309f8d5e545c2e33eb4576d0a585afae9cd3da0";
        private const string PythonPinSha = "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310";

        private const string SentinelText = "edl001-a1-sentinel";

        // ---------------------------------------------------------------- A

        [Theory]
        [InlineData("nullArchive")]
        [InlineData("emptyWorkRoot")]
        [InlineData("blankWorkRoot")]
        [InlineData("disposedStream")]
        [InlineData("nonSeekableStream")]
        public async Task LoadAsync_rejects_invalid_arguments(string scenario)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();

            switch (scenario)
            {
                case "nullArchive":
                {
                    await Assert.ThrowsAnyAsync<ArgumentException>(() => EdlToolchain.LoadAsync(null!, workRoot));
                    break;
                }

                case "emptyWorkRoot":
                {
                    using var zip = Fixture.Default().BuildZip();
                    await Assert.ThrowsAnyAsync<ArgumentException>(() => EdlToolchain.LoadAsync(zip, string.Empty));
                    break;
                }

                case "blankWorkRoot":
                {
                    using var zip = Fixture.Default().BuildZip();
                    await Assert.ThrowsAnyAsync<ArgumentException>(() => EdlToolchain.LoadAsync(zip, "   "));
                    break;
                }

                case "disposedStream":
                {
                    var zip = Fixture.Default().BuildZip();
                    zip.Dispose();
                    await Assert.ThrowsAnyAsync<ArgumentException>(() => EdlToolchain.LoadAsync(zip, workRoot));
                    break;
                }

                case "nonSeekableStream":
                {
                    using var zip = Fixture.Default().BuildZip();
                    using var nonSeekable = new NonSeekableReadStream(zip.ToArray());
                    await Assert.ThrowsAnyAsync<ArgumentException>(() => EdlToolchain.LoadAsync(nonSeekable, workRoot));
                    break;
                }

                default:
                    throw new InvalidOperationException("Unknown scenario: " + scenario);
            }
        }

        // ---------------------------------------------------------------- B

        [Fact]
        public async Task LoadAsync_rejects_malformed_zip()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            using var stream = new MemoryStream(new byte[] { 0x50, 0x4b, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03 }, writable: false);

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(stream, workRoot));
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_missing_manifest()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.IncludeManifest = false;
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("manifest", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_invalid_manifest_json()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.RawManifest = "{ \"schemaVersion\": 1, \"profileId\": ";
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("manifest", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- C

        [Fact]
        public async Task LoadAsync_rejects_unsupported_schema_version()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.SchemaVersionValue = 2;
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("schemaVersion", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- D

        [Theory]
        [InlineData("profileId")]
        [InlineData("model")]
        [InlineData("androidBuild")]
        [InlineData("hardwareId")]
        public async Task LoadAsync_rejects_identity_mismatch_before_payload_io(string mutatedField)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();

            switch (mutatedField)
            {
                case "profileId":
                    fixture.ProfileId = "g4-9008-999";
                    break;
                case "model":
                    fixture.Model = "TB322FX";
                    break;
                case "androidBuild":
                    fixture.AndroidBuild = ExpectedAndroidBuild + "_OTHER";
                    break;
                case "hardwareId":
                    fixture.HardwareId = "0028D0E100400001";
                    break;
                default:
                    throw new InvalidOperationException("Unknown field: " + mutatedField);
            }

            using var zip = fixture.BuildZip();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains(mutatedField, ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- E

        [Fact]
        public async Task LoadAsync_rejects_missing_gpt_cli_role()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.RemoveRole(GptCliRole);
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("role", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_unknown_role()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.AddEntry("mysteryRole", "scripts/mystery.py", new byte[] { 0x7A });
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("role", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_duplicate_role()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.AddEntry(AvbRole, "scripts/avb_stock_second.py", new byte[] { 0x7B });
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("role", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- F

        [Theory]
        [InlineData(ClientRole, "tools/edl-ng-renamed.exe")]
        [InlineData(AvbCliRole, "scripts/renamed_cli.py")]
        public async Task LoadAsync_rejects_wrong_fixed_role_path(string role, string wrongPath)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.RenameRole(role, wrongPath);
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("path", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- G

        [Theory]
        [InlineData("duplicateEntry")]
        [InlineData("caseCollidingEntry")]
        [InlineData("extraEntry")]
        [InlineData("traversalEntry")]
        [InlineData("absoluteEntry")]
        [InlineData("windowsAbsoluteEntry")]
        [InlineData("symlinkEntry")]
        public async Task LoadAsync_rejects_unsafe_zip_entries(string scenario)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();

            switch (scenario)
            {
                case "duplicateEntry":
                    fixture.AddRawMember(ClientRelPath, new byte[] { 0x21 });
                    break;
                case "caseCollidingEntry":
                    fixture.AddRawMember("TOOLS/EDL-NG.EXE", new byte[] { 0x22 });
                    break;
                case "extraEntry":
                    fixture.AddRawMember("tools/extra-payload.bin", new byte[] { 0x23 });
                    break;
                case "traversalEntry":
                    fixture.AddRawMember("../outside", new byte[] { 0x24 });
                    break;
                case "absoluteEntry":
                    fixture.AddRawMember("/outside", new byte[] { 0x25 });
                    break;
                case "windowsAbsoluteEntry":
                    fixture.AddRawMember("C:\\outside", new byte[] { 0x26 });
                    break;
                case "symlinkEntry":
                    // Mark an expected manifest payload as a symlink; the manifest bytes/SHA stay consistent,
                    // so only the entry mode can cause the rejection.
                    fixture.RequireRole(AvbRole).Symlink = true;
                    break;
                default:
                    throw new InvalidOperationException("Unknown scenario: " + scenario);
            }

            using var zip = fixture.BuildZip();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("entry", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- H

        [Theory]
        [InlineData(ClientRole)]
        [InlineData(FirehoseRole)]
        [InlineData(PythonRole)]
        public async Task LoadAsync_rejects_wrong_declared_sha_pin(string role)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.RequireRole(role).Sha256 = new string('0', 64);
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("pin", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(role, ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_wrong_declared_client_byte_pin()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            var client = fixture.RequireRole(ClientRole);

            // Mutate only the declared byte pin; the exact fixed SHA stays unchanged, so this isolates bytes.
            client.Bytes = ClientPinBytes - 1;

            using var zip = fixture.BuildZip();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("pin", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(ClientRole, ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- I

        [Theory]
        [InlineData("zz")]
        [InlineData("")]
        [InlineData("41ada68410a434eaf157211b68aeec287c6bd0b648ca161c75badf84d8bf")]
        public async Task LoadAsync_rejects_malformed_nonnative_sha_hex(string badSha)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.RequireRole(AvbRole).Sha256 = badSha;
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("sha256", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- J

        [Fact]
        public async Task LoadAsync_rejects_pre_cancelled_token_without_touching_caller_state()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            using var zip = Fixture.Default().BuildZip();
            var originalLength = zip.Length;
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => EdlToolchain.LoadAsync(zip, workRoot, cancelled.Token));

            Assert.True(zip.CanRead);
            Assert.Equal(originalLength, zip.Length);
            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
            Assert.True(Directory.Exists(workRoot));
            AssertNoStagingResidue(workRoot, 1);
        }

        // ---------------------------------------------------------------- K

        [Fact]
        public async Task LoadAsync_failing_package_leaves_no_owned_staging_residue()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);

            // Declared fixed pins with deliberately invalid 1-byte native payloads: metadata is valid,
            // payload integrity must fail, and nothing may be left behind.
            using var zip = Fixture.Default().BuildZip();
            var originalLength = zip.Length;

            await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));

            Assert.True(zip.CanRead);
            Assert.Equal(originalLength, zip.Length);
            Assert.Equal(SentinelText, File.ReadAllText(sentinel));
            Assert.True(Directory.Exists(workRoot));
            AssertNoStagingResidue(workRoot, 1);
        }

        // ---------------------------------------------------------------- trusted profile gate

        [Fact]
        public async Task LoadAsync_rejects_unknown_profile_id_before_staging()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();
            fixture.ProfileId = "g5-9008-999";
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("profileId", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("g4-9008-259", ex.Message, StringComparison.Ordinal);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_removed_g5_profile_id_before_staging()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();

            // The former preparation-only id is gone from the trusted table and must resolve to nothing.
            fixture.ProfileId = "g5-9008-092";
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("known", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("g5-9008-092", ex.Message, StringComparison.Ordinal);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Fact]
        public async Task LoadAsync_rejects_forged_g5_identity_before_staging()
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();

            // A hostile manifest selects the real trusted G5 profile, yet keeps the G4 loader source build,
            // the G4 hardware id and the G4 loader pins; it must still be rejected before anything is staged.
            fixture.ProfileId = "g5-9008-y7005";
            fixture.Model = "TB323FU";
            fixture.AndroidBuild = ExpectedAndroidBuild;
            fixture.HardwareId = "0028D0E100400000";
            using var zip = fixture.BuildZip();

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains("androidBuild", ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        [Theory]
        [InlineData("model", "tb322fc")]
        [InlineData("model", "TB322F")]
        [InlineData("model", "TB322FCX")]
        [InlineData("model", ExpectedModel + " ")]
        [InlineData("androidBuild", ExpectedAndroidBuild + "_EXTRA")]
        [InlineData("androidBuild", "tb322fc_cn_open_user_q00041.1_w_zuxos_1.5.10.259_st_260611")]
        [InlineData("androidBuild", "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.25")]
        [InlineData("androidBuild", "")]
        public async Task LoadAsync_rejects_non_exact_g4_identity(string field, string value)
        {
            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var fixture = Fixture.Default();

            switch (field)
            {
                case "model":
                    fixture.Model = value;
                    break;
                case "androidBuild":
                    fixture.AndroidBuild = value;
                    break;
                default:
                    throw new InvalidOperationException("Unknown field: " + field);
            }

            using var zip = fixture.BuildZip();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => EdlToolchain.LoadAsync(zip, workRoot));
            Assert.Contains(field, ex.Message, StringComparison.OrdinalIgnoreCase);
            AssertNoStagingResidue(workRoot, 0);
        }

        // ---------------------------------------------------------------- real bundle positive

        [RealEdlToolchainBundleFact]
        public async Task LoadAsync_real_bundle_builds_complete_verified_staging()
        {
            var bundlePath = Environment.GetEnvironmentVariable("EDL_TOOLCHAIN_TEST_BUNDLE_PATH");
            Assert.False(string.IsNullOrWhiteSpace(bundlePath), "EDL_TOOLCHAIN_TEST_BUNDLE_PATH must not be blank.");
            Assert.True(File.Exists(bundlePath!), "EDL_TOOLCHAIN_TEST_BUNDLE_PATH does not exist: " + bundlePath);

            using var root = new TestRoot();
            var workRoot = root.CreateWorkRoot();
            var sentinel = CreateSentinel(workRoot);
            var originalBundleLength = new FileInfo(bundlePath!).Length;

            var stream = new FileStream(bundlePath!, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                using var toolchain = await EdlToolchain.LoadAsync(stream, workRoot);

                Assert.Equal(ExpectedProfileId, toolchain.ProfileId);
                Assert.Equal(ExpectedModel, toolchain.Model);
                Assert.Equal(ExpectedAndroidBuild, toolchain.AndroidBuild);
                Assert.Equal(ExpectedHardwareId, toolchain.HardwareId);

                Assert.Same(EdlDeviceProfiles.Default, toolchain.Profile);
                Assert.Equal(ExpectedProfileId, toolchain.Profile.ProfileId);
                Assert.Equal(ExpectedModel, toolchain.Profile.Model);
                Assert.Equal(ExpectedHardwareId, toolchain.Profile.FullHardwareId);
                Assert.Equal(ExpectedAndroidBuild, Assert.Single(toolchain.Profile.AllowedDisplayIds));
                Assert.Equal(FirehoseRelPath, toolchain.Profile.LoaderEntryPath);
                Assert.True(toolchain.Profile.IsComplete);

                var staging = toolchain.StagingDirectory;
                Assert.True(Path.IsPathFullyQualified(staging), "StagingDirectory must be fully qualified.");
                foreach (var path in new[]
                         {
                             toolchain.ClientPath, toolchain.UsbLibraryPath, toolchain.FirehosePath,
                             toolchain.PythonPath, toolchain.AvbCliPath, toolchain.GptCliPath, staging
                         })
                {
                    Assert.False(string.IsNullOrWhiteSpace(path));
                    Assert.True(Path.IsPathFullyQualified(path), "Path must be fully qualified: " + path);
                }

                var expectedStagingParent = Path.TrimEndingDirectorySeparator(workRoot);
                var actualStagingParent = Path.TrimEndingDirectorySeparator(
                    Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(staging))!);
                Assert.Equal(0, string.Compare(expectedStagingParent, actualStagingParent, StringComparison.OrdinalIgnoreCase));

                Assert.Equal(Staged(staging, ClientRelPath), toolchain.ClientPath);
                Assert.Equal(Staged(staging, UsbLibraryRelPath), toolchain.UsbLibraryPath);
                Assert.Equal(Staged(staging, FirehoseRelPath), toolchain.FirehosePath);
                Assert.Equal(Path.Combine(staging, "runtime", "python.exe"), toolchain.PythonPath);
                Assert.Equal(Staged(staging, AvbCliRelPath), toolchain.AvbCliPath);
                Assert.Equal(Staged(staging, GptCliRelPath), toolchain.GptCliPath);
                Assert.Equal(
                    0,
                    string.Compare(
                        Path.GetDirectoryName(toolchain.UsbLibraryPath)!,
                        Path.GetDirectoryName(toolchain.ClientPath)!,
                        StringComparison.OrdinalIgnoreCase));

                foreach (var path in new[]
                         {
                             toolchain.ClientPath, toolchain.UsbLibraryPath, toolchain.FirehosePath,
                             toolchain.PythonPath, toolchain.AvbCliPath, toolchain.GptCliPath
                         })
                {
                    Assert.True(File.Exists(path), "Required tool file is missing: " + path);
                }

                var ninePayloads = new[]
                {
                    ClientRelPath, UsbLibraryRelPath, FirehoseRelPath, LicenseRelPath, PythonRelPath,
                    AvbRelPath, AvbCliRelPath, GptRelPath, GptCliRelPath
                };
                foreach (var relative in ninePayloads)
                {
                    var stagedPath = Staged(staging, relative);
                    Assert.True(File.Exists(stagedPath), "Staged manifest payload is missing: " + stagedPath);
                }

                var pythonZipPath = Staged(staging, PythonRelPath);
                Assert.Equal(PythonPinBytes, new FileInfo(pythonZipPath).Length);

                var runtimeDir = Path.Combine(staging, "runtime");
                var pthPath = Path.Combine(runtimeDir, "python314._pth");
                Assert.True(File.Exists(pthPath), "runtime/python314._pth is missing.");

                AssertPthBytes(pthPath);

                using (var stagedPython = ZipFile.OpenRead(pythonZipPath))
                {
                    foreach (var member in stagedPython.Entries)
                    {
                        var name = member.FullName.Replace('\\', '/');
                        if (name.EndsWith("/", StringComparison.Ordinal))
                        {
                            var directory = Path.Combine(
                                runtimeDir,
                                name.TrimEnd('/').Replace('/', Path.DirectorySeparatorChar));
                            Assert.True(Directory.Exists(directory), "Expanded directory is missing: " + directory);
                            continue;
                        }

                        if (name == "python314._pth")
                        {
                            continue;
                        }

                        var target = Path.Combine(runtimeDir, name.Replace('/', Path.DirectorySeparatorChar));
                        Assert.True(File.Exists(target), "Expanded runtime member is missing: " + target);
                        Assert.Equal(member.Length, new FileInfo(target).Length);
                    }
                }

                toolchain.Dispose();
                toolchain.Dispose();

                Assert.False(Directory.Exists(staging), "Dispose must remove only its own staging directory.");
                Assert.True(File.Exists(sentinel), "Sibling sentinel must be preserved.");
                Assert.Equal(SentinelText, File.ReadAllText(sentinel));
                Assert.True(Directory.Exists(workRoot), "Caller workRoot must be preserved.");
                Assert.True(File.Exists(bundlePath!), "Source bundle must be preserved.");
                Assert.Equal(originalBundleLength, new FileInfo(bundlePath!).Length);

                stream.Position = 0;
                Assert.True(stream.CanRead, "Caller owns the archive stream; it must stay readable.");
            }
            finally
            {
                stream.Dispose();
            }
        }

        // ---------------------------------------------------------------- helpers

        private static string Staged(string staging, string relativePath) =>
            Path.Combine(staging, relativePath.Replace('/', Path.DirectorySeparatorChar));

        private static string CreateSentinel(string workRoot)
        {
            var path = Path.Combine(workRoot, "sibling-sentinel.txt");
            File.WriteAllText(path, SentinelText);
            return path;
        }

        private static void AssertNoStagingResidue(string workRoot, int expectedFileCount)
        {
            Assert.Empty(Directory.GetDirectories(workRoot));
            Assert.Equal(expectedFileCount, Directory.GetFiles(workRoot).Length);
        }

        private static void AssertPthBytes(string path)
        {
            var expected = Encoding.UTF8.GetBytes("python314.zip\n.\n../scripts\n");
            var actual = File.ReadAllBytes(path);

            Assert.Equal(expected, actual);
            Assert.NotEqual(0xEF, actual.Length > 0 ? actual[0] : 0xEF);

            var text = Encoding.UTF8.GetString(actual);
            Assert.DoesNotContain("\\n", text, StringComparison.Ordinal);
            Assert.DoesNotContain("import site", text, StringComparison.Ordinal);
            Assert.Equal(3, text.Split('\n').Length - 1);
            Assert.EndsWith("\n", text, StringComparison.Ordinal);
        }

        private static string Sha256Hex(byte[] payload) =>
            Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        /// <summary>
        /// Per-test isolated directory. Requires TEST_ARTIFACT_ROOT; never falls back to a temp path.
        /// Only the GUID child created here is ever deleted.
        /// </summary>
        private sealed class TestRoot : IDisposable
        {
            public string DirectoryPath { get; }

            public TestRoot()
            {
                var artifactRoot = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
                if (string.IsNullOrWhiteSpace(artifactRoot))
                {
                    throw new InvalidOperationException(
                        "TEST_ARTIFACT_ROOT must be set to an existing directory; no temporary-directory fallback is permitted.");
                }

                if (!Directory.Exists(artifactRoot))
                {
                    throw new InvalidOperationException("TEST_ARTIFACT_ROOT does not exist: " + artifactRoot);
                }

                DirectoryPath = Path.Combine(artifactRoot, "edl001-a1-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(DirectoryPath);
            }

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

        private sealed class EntrySpec
        {
            public string Role = string.Empty;
            public string Path = string.Empty;
            public string ZipName = string.Empty;
            public long Bytes;
            public string Sha256 = string.Empty;
            public byte[] Payload = Array.Empty<byte>();
            public bool Symlink;
        }

        /// <summary>
        /// In-memory ZIP fixture with independent literal identity/pins. Fixed native pins are declared
        /// with intentionally invalid 1-byte payloads, so no such fixture can ever be an accepted package.
        /// </summary>
        private sealed class Fixture
        {
            public int SchemaVersionValue = 1;
            public string ProfileId = ExpectedProfileId;
            public string Model = ExpectedModel;
            public string AndroidBuild = ExpectedAndroidBuild;
            public string HardwareId = ExpectedHardwareId;
            public bool IncludeManifest = true;
            public string? RawManifest;
            public List<EntrySpec> Entries = new();
            public List<(string Name, byte[] Payload, bool Symlink)> RawMembers = new();

            public static Fixture Default()
            {
                var fixture = new Fixture();

                void Native(string role, string path, long pinBytes, string pinSha, byte marker) =>
                    fixture.Entries.Add(new EntrySpec
                    {
                        Role = role,
                        Path = path,
                        ZipName = path,
                        Bytes = pinBytes,
                        Sha256 = pinSha,
                        Payload = new[] { marker }
                    });

                void Synthetic(string role, string path, byte marker)
                {
                    var payload = new[] { marker };
                    fixture.Entries.Add(new EntrySpec
                    {
                        Role = role,
                        Path = path,
                        ZipName = path,
                        Bytes = payload.Length,
                        Sha256 = Sha256Hex(payload),
                        Payload = payload
                    });
                }

                Native(ClientRole, ClientRelPath, ClientPinBytes, ClientPinSha, 0x11);
                Synthetic(UsbLibraryRole, UsbLibraryRelPath, 0x12);
                Native(FirehoseRole, FirehoseRelPath, FirehosePinBytes, FirehosePinSha, 0x13);
                Synthetic(LicenseRole, LicenseRelPath, 0x14);
                Native(PythonRole, PythonRelPath, PythonPinBytes, PythonPinSha, 0x15);
                Synthetic(AvbRole, AvbRelPath, 0x16);
                Synthetic(AvbCliRole, AvbCliRelPath, 0x17);
                Synthetic(GptRole, GptRelPath, 0x18);
                Synthetic(GptCliRole, GptCliRelPath, 0x19);
                return fixture;
            }

            public EntrySpec RequireRole(string role) =>
                Entries.Single(e => string.Equals(e.Role, role, StringComparison.Ordinal));

            public void RemoveRole(string role) =>
                Entries.RemoveAll(e => string.Equals(e.Role, role, StringComparison.Ordinal));

            public void RenameRole(string role, string newPath)
            {
                var entry = RequireRole(role);
                entry.Path = newPath;
                entry.ZipName = newPath;
            }

            public void AddEntry(string role, string path, byte[] payload) =>
                Entries.Add(new EntrySpec
                {
                    Role = role,
                    Path = path,
                    ZipName = path,
                    Bytes = payload.Length,
                    Sha256 = Sha256Hex(payload),
                    Payload = payload
                });

            public void AddRawMember(string name, byte[] payload, bool symlink = false) =>
                RawMembers.Add((name, payload, symlink));

            public MemoryStream BuildZip()
            {
                var buffer = new MemoryStream();
                using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
                {
                    if (IncludeManifest)
                    {
                        WriteEntry(
                            zip,
                            "manifest.json",
                            Encoding.UTF8.GetBytes(RawManifest ?? BuildManifestJson()),
                            symlink: false);
                    }

                    foreach (var entry in Entries)
                    {
                        WriteEntry(zip, entry.ZipName, entry.Payload, entry.Symlink);
                    }

                    foreach (var member in RawMembers)
                    {
                        WriteEntry(zip, member.Name, member.Payload, member.Symlink);
                    }
                }

                buffer.Position = 0;
                return buffer;
            }

            private string BuildManifestJson()
            {
                var entries = new JsonArray();
                foreach (var entry in Entries)
                {
                    entries.Add(new JsonObject
                    {
                        ["role"] = entry.Role,
                        ["path"] = entry.Path,
                        ["bytes"] = entry.Bytes,
                        ["sha256"] = entry.Sha256
                    });
                }

                var root = new JsonObject
                {
                    ["schemaVersion"] = SchemaVersionValue,
                    ["profileId"] = ProfileId,
                    ["model"] = Model,
                    ["androidBuild"] = AndroidBuild,
                    ["hardwareId"] = HardwareId,
                    ["entries"] = entries
                };

                return root.ToJsonString();
            }

            private static void WriteEntry(ZipArchive zip, string name, byte[] payload, bool symlink)
            {
                var entry = zip.CreateEntry(name, CompressionLevel.Fastest);
                if (symlink)
                {
                    entry.ExternalAttributes = unchecked((int)(0xA1FFu << 16));
                }

                using var target = entry.Open();
                target.Write(payload, 0, payload.Length);
            }
        }

        private sealed class NonSeekableReadStream : Stream
        {
            private readonly MemoryStream _inner;

            public NonSeekableReadStream(byte[] data) => _inner = new MemoryStream(data, writable: false);

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void Flush() { }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _inner.Dispose();
                }

                base.Dispose(disposing);
            }
        }
    }
}
