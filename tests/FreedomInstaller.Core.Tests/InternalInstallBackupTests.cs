using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract tests for <see cref="InternalInstallBackup"/> (IB002). Every test drives a real
/// <see cref="EdlClient"/> over the real toolchain loaded once by <see cref="EdlClientToolchainFixture"/>;
/// only the external process boundary and the USB endpoint enumeration are faked.
/// <para>
/// The factory produces a verified set for the full 52-role contract: the 12 GPT windows of all six LUNs
/// plus the 40 required labels (LUN0 12, LUN1 2, LUN2 2, LUN3 1, LUN4 19, LUN5 4). The negative tests assert
/// <c>not null AND not NotImplementedException</c>, so a stub can never be mistaken for a business rejection.
/// </para>
/// <para>
/// Fixture files: the six synthetic GPTs are built with the existing <see cref="GptImage"/> /
/// <see cref="GptPartitionSpec"/> helpers (their 64 KiB fragments are padded into the real 64-sector =
/// 256 KiB read windows, primary block first, backup block last), so the reader is exercised on ordinary,
/// CRC-valid GPT bytes and never on a mirrored copy of the production code.
/// </para>
/// </summary>
public sealed class InternalInstallBackupTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string ManifestFileName = "backup-manifest.json";
    private const string VerifiedStatus = "verified";
    private const string PartialStatus = "partial";
    private const string CompleteStage = "complete";

    // FW01: the actual firmware under test. MaintenanceProfiles.AndroidBuild stays the 259 loader profile.
    private const string Actual120AndroidBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
    private const string Actual120BuildFingerprint = "Lenovo/TB322FC/TB322FC:15/TEST/120:user/release-keys";
    private const string Actual120AndroidRelease = "15";
    private const string Actual120SecurityPatch = "2026-06-01";

    private static readonly string[] AllowedStages =
    {
        "reading-gpt", "reading-partition", "verifying", "complete",
    };

    private readonly EdlClientToolchainFixture _fixture;

    public InternalInstallBackupTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ---------------------------------------------------------------- positive workflow

    [Fact]
    public async Task FW01_Create_reads_exactly_the_51_contract_roles_from_fresh_tables()
    {
        string parent = _fixture.NewCaseDirectory(nameof(FW01_Create_reads_exactly_the_51_contract_roles_from_fresh_tables));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, Actual120Firmware());

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.Same(client.Binding, set.Binding);
        Assert.Equal(_fixture.Toolchain.ProfileId, set.ProfileId, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.Model, set.Model, StringComparer.Ordinal);
        // The captured build identity is the bound device's actual firmware, never the 259 loader profile.
        Assert.Equal(Actual120AndroidBuild, set.AndroidBuild, StringComparer.Ordinal);
        Assert.Equal(MaintenanceProfiles.AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);
        Assert.NotEqual(Actual120AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.HardwareId, set.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.True(
            set.DirectoryPath.StartsWith(parent, StringComparison.OrdinalIgnoreCase),
            "the backup directory must live below the chosen parent: " + set.DirectoryPath);
        Assert.NotEqual(parent, set.DirectoryPath, StringComparer.OrdinalIgnoreCase);

        Assert.Equal(6, set.Geometries.Count);
        Assert.Equal(6, set.Tables.Count);
        for (int lun = 0; lun < 6; lun++)
        {
            Assert.Equal(
                new EdlGeometry(lun, IB001SyntheticDevice.SectorSize, device.TotalSectors(lun)),
                set.Geometries[lun]);
            Assert.Equal(device.DiskGuid(lun), set.Tables[lun].DiskGuid, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(IB001SyntheticDevice.SectorSize, set.Tables[lun].SectorSize);
            Assert.Equal(device.TotalSectors(lun) * IB001SyntheticDevice.SectorSize, set.Tables[lun].DiskBytes);
        }

        // Exactly the frozen 52 roles, and nothing else.
        HashSet<string> expectedRoles = device.ExpectedRoles().Select(entry => entry.Role)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Equal(51, expectedRoles.Count);
        Assert.Equal(12, expectedRoles.Count(role => role.StartsWith("gpt_", StringComparison.Ordinal)));
        Assert.Equal(51, set.Files.Count);
        Assert.True(expectedRoles.SetEquals(set.Files.Keys), "the backup must index exactly the 51 contract roles");

        foreach (string role in expectedRoles)
        {
            (int lun, long start, long count, string? partUuid) = device.Expectation(role);
            EdlCapturedRegion region = set.Files[role];

            Assert.Equal(role, region.Role, StringComparer.Ordinal);
            Assert.Equal(lun, region.Lun);
            Assert.Equal(start, region.StartSector);
            Assert.Equal(count, region.SectorCount);
            Assert.Equal(IB001SyntheticDevice.SectorSize, region.SectorSize);
            Assert.Equal(partUuid, region.PartUuid);
            Assert.Equal(count * IB001SyntheticDevice.SectorSize, region.Length);
            Assert.True(
                region.FilePath.StartsWith(set.DirectoryPath, StringComparison.OrdinalIgnoreCase),
                "captured file must live inside the backup root: " + region.FilePath);
            Assert.True(File.Exists(region.FilePath), "captured file is missing: " + region.FilePath);
            Assert.Equal(region.Length, new FileInfo(region.FilePath).Length);
            Assert.Equal(region.Sha256, HashFile(region.FilePath), StringComparer.OrdinalIgnoreCase);
        }

        // The ranges really came from the freshly parsed tables, not from a constant.
        Assert.Equal(device.Expectation("misc").Start, set.Files["misc"].StartSector);
        Assert.Equal(device.Expectation("spunvm").Start, set.Files["spunvm"].StartSector);
        Assert.Equal(device.Expectation("fsc").Start, set.Files["fsc"].StartSector);
        Assert.Equal(device.Expectation("xbl_a").Start, set.Files["xbl_a"].StartSector);
        Assert.Equal(device.Expectation("cdt").Start, set.Files["cdt"].StartSector);
        Assert.Equal(device.Expectation("abl_b").Start, set.Files["abl_b"].StartSector);

        // LUN0 layout carries every fresh entry (userdata and super included) for the planner.
        DiskLayout layout = set.Lun0Layout;
        Assert.Equal("edl:ufs:lun:0", layout.DeviceId, StringComparer.Ordinal);
        Assert.Equal(IB001SyntheticDevice.SectorSize, layout.SectorSize);
        IReadOnlyList<GptPartitionSpec> lun0Specs = device.Specs(0);
        Assert.Equal(lun0Specs.Count, layout.Partitions.Count);
        foreach (GptPartitionSpec spec in lun0Specs)
        {
            DiskPartition actual = layout.Partitions.Single(partition => partition.Number == spec.Number);
            Assert.Equal(spec.Name, actual.Name, StringComparer.Ordinal);
            Assert.Equal(spec.StartSector, actual.StartSector);
            Assert.Equal(spec.SectorCount, actual.SectorCount);
            Assert.Equal(spec.TypeGuid, actual.TypeGuid, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(spec.PartUuid, actual.PartUuid, StringComparer.OrdinalIgnoreCase);
        }

        Assert.Contains(layout.Partitions, partition => partition.Name == "userdata");
        Assert.Contains(layout.Partitions, partition => partition.Name == "super");
        Assert.DoesNotContain("userdata", set.Files.Keys);
        Assert.DoesNotContain("super", set.Files.Keys);

        // Consumer cannot mutate the returned metadata.
        Assert.False(set.Geometries is Dictionary<int, EdlGeometry>);
        Assert.False(set.Tables is Dictionary<int, GptTable>);
        Assert.False(set.Files is Dictionary<string, EdlCapturedRegion>);

        // LUN0 is probed first, the Sahara response is used exactly once, and nothing writes or resets.
        Assert.Equal(6, runner.ProbedLuns.Count);
        Assert.Equal(0, runner.ProbedLuns[0]);
        Assert.Equal(1, runner.SaharaResponseCount);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(51, runner.Reads.Count);

        List<string> readRoles = new();
        foreach (IB001Read read in runner.Reads)
        {
            string? role = device.RoleOf(read);
            Assert.NotNull(role);
            readRoles.Add(role!);
            Assert.DoesNotContain(
                role!,
                new[] { "userdata", "super", "metadata", "rawdump", "dummy_lun1", "dummy_lun2", "dummy_lun3" },
                StringComparer.Ordinal);
        }

        Assert.Equal(51, readRoles.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task FW01_Verified_manifest_and_sidecar_describe_identity_luns_files_and_exclusions()
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(FW01_Verified_manifest_and_sidecar_describe_identity_luns_files_and_exclusions));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, Actual120Firmware());

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.Equal(ManifestFileName, Path.GetFileName(set.ManifestPath), StringComparer.Ordinal);
        Assert.Equal(set.DirectoryPath, Path.GetDirectoryName(set.ManifestPath), StringComparer.OrdinalIgnoreCase);

        byte[] manifestBytes = File.ReadAllBytes(set.ManifestPath);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(manifestBytes)), set.ManifestSha256, StringComparer.OrdinalIgnoreCase);

        string sidecarPath = set.ManifestPath + ".sha256";
        Assert.True(File.Exists(sidecarPath), "a verified backup must publish backup-manifest.json.sha256");
        Assert.Equal(set.ManifestSha256, File.ReadAllText(sidecarPath).Trim(), StringComparer.OrdinalIgnoreCase);

        using JsonDocument document = JsonDocument.Parse(manifestBytes);
        JsonElement root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(VerifiedStatus, root.GetProperty("status").GetString()!, StringComparer.Ordinal);
        Assert.False(root.GetProperty("userDataIncluded").GetBoolean());
        Assert.False(root.GetProperty("superIncluded").GetBoolean());

        JsonElement profile = root.GetProperty("profile");
        Assert.Equal(_fixture.Toolchain.ProfileId, profile.GetProperty("profileId").GetString()!, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.Model, profile.GetProperty("model").GetString()!, StringComparer.Ordinal);
        Assert.Equal(Actual120AndroidBuild, profile.GetProperty("androidBuild").GetString()!, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.HardwareId, profile.GetProperty("hardwareId").GetString()!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(MaintenanceProfiles.AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);
        Assert.NotEqual(Actual120AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);

        JsonElement identity = root.GetProperty("identity");
        Assert.Equal("SN0123456789", identity.GetProperty("androidSerial").GetString()!, StringComparer.Ordinal);
        Assert.Equal(E003EdlTestData.SocSerialDecimal, identity.GetProperty("socSerialDecimal").GetString()!, StringComparer.Ordinal);
        Assert.Equal(E003EdlTestData.BusSerialHex, identity.GetProperty("busSerialHex").GetString()!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(_fixture.Toolchain.Model, identity.GetProperty("model").GetString()!, StringComparer.Ordinal);
        Assert.True(identity.GetProperty("hasInitialSaharaProof").GetBoolean());

        JsonElement firmware = identity.GetProperty("firmware");
        Assert.Equal(JsonValueKind.Object, firmware.ValueKind);
        Assert.Equal(Actual120AndroidBuild, firmware.GetProperty("displayId").GetString()!, StringComparer.Ordinal);
        Assert.Equal(Actual120BuildFingerprint, firmware.GetProperty("buildFingerprint").GetString()!, StringComparer.Ordinal);
        Assert.Equal(Actual120AndroidRelease, firmware.GetProperty("androidRelease").GetString()!, StringComparer.Ordinal);
        Assert.Equal(Actual120SecurityPatch, firmware.GetProperty("securityPatch").GetString()!, StringComparer.Ordinal);
        Assert.Equal(
            nameof(BootloaderState.Locked),
            firmware.GetProperty("androidReportedBootloaderState").GetString()!,
            StringComparer.Ordinal);

        JsonElement luns = root.GetProperty("luns");
        Assert.Equal(6, luns.GetArrayLength());
        foreach (JsonElement lun in luns.EnumerateArray())
        {
            int index = lun.GetProperty("lun").GetInt32();
            Assert.Equal(IB001SyntheticDevice.SectorSize, lun.GetProperty("sectorSize").GetInt32());
            Assert.Equal(device.TotalSectors(index), lun.GetProperty("totalSectors").GetInt64());
            Assert.Equal(device.DiskGuid(index), lun.GetProperty("diskGuid").GetString()!, StringComparer.OrdinalIgnoreCase);
            Assert.False(string.IsNullOrWhiteSpace(lun.GetProperty("sourceFingerprint").GetString()));

            JsonElement partitions = lun.GetProperty("partitions");
            Assert.Equal(device.Specs(index).Count, partitions.GetArrayLength());
            foreach (JsonElement partition in partitions.EnumerateArray())
            {
                int number = partition.GetProperty("number").GetInt32();
                GptPartitionSpec spec = device.Specs(index).Single(candidate => candidate.Number == number);
                Assert.Equal(spec.Name, partition.GetProperty("name").GetString()!, StringComparer.Ordinal);
                Assert.Equal(spec.TypeGuid, partition.GetProperty("typeGuid").GetString()!, StringComparer.OrdinalIgnoreCase);
                Assert.Equal(spec.PartUuid, partition.GetProperty("partUuid").GetString()!, StringComparer.OrdinalIgnoreCase);
                Assert.Equal(spec.StartSector, partition.GetProperty("startSector").GetInt64());
                Assert.Equal(spec.SectorCount, partition.GetProperty("sectorCount").GetInt64());
                Assert.Equal(0UL, partition.GetProperty("attributes").GetUInt64());
            }
        }

        JsonElement files = root.GetProperty("files");
        Assert.Equal(51, files.GetArrayLength());
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (JsonElement file in files.EnumerateArray())
        {
            string role = file.GetProperty("role").GetString()!;
            Assert.True(seen.Add(role), "the manifest repeats role " + role);

            EdlCapturedRegion region = set.Files[role];
            Assert.Equal(region.Lun, file.GetProperty("lun").GetInt32());
            Assert.Equal(region.StartSector, file.GetProperty("startSector").GetInt64());
            Assert.Equal(region.SectorCount, file.GetProperty("sectorCount").GetInt64());
            Assert.Equal(region.SectorSize, file.GetProperty("sectorSize").GetInt32());
            Assert.Equal(region.Length, file.GetProperty("length").GetInt64());
            Assert.Equal(region.Sha256, file.GetProperty("sha256").GetString()!, StringComparer.OrdinalIgnoreCase);

            JsonElement partUuid = file.GetProperty("partUuid");
            if (region.PartUuid is null)
            {
                Assert.Equal(JsonValueKind.Null, partUuid.ValueKind);
            }
            else
            {
                Assert.Equal(region.PartUuid!, partUuid.GetString()!, StringComparer.OrdinalIgnoreCase);
            }

            string relativePath = file.GetProperty("relativePath").GetString()!;
            Assert.False(Path.IsPathRooted(relativePath), "manifest paths must stay relative: " + relativePath);
            Assert.DoesNotContain("..", relativePath.Split('/', '\\'), StringComparer.Ordinal);

            string full = Path.GetFullPath(Path.Combine(set.DirectoryPath, relativePath));
            Assert.True(
                full.StartsWith(set.DirectoryPath, StringComparison.OrdinalIgnoreCase),
                "the manifest path must stay inside the backup root: " + full);
            Assert.Equal(region.Length, new FileInfo(full).Length);
            Assert.Equal(region.Sha256, HashFile(full), StringComparer.OrdinalIgnoreCase);
        }

        Assert.Equal(51, seen.Count);
        Assert.DoesNotContain("userdata", seen);
        Assert.DoesNotContain("super", seen);
    }

    // -------------------------------------------------------------- table validation first

    [Theory]
    [InlineData("primary-header")]
    [InlineData("backup-array")]
    [InlineData("pair-disagrees")]
    public async Task Invalid_gpt_pair_rejects_before_any_partition_read(string variant)
    {
        string parent = _fixture.NewCaseDirectory(nameof(Invalid_gpt_pair_rejects_before_any_partition_read) + "-" + variant);
        IB001SyntheticDevice device = variant switch
        {
            "primary-header" => IB001SyntheticDevice.Create(corruptPrimaryHeaderLun: 4),
            "backup-array" => IB001SyntheticDevice.Create(corruptBackupArrayLun: 5),
            "pair-disagrees" => IB001SyntheticDevice.Create(disagreePairLun: 4),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        IB001Progress progress = new(parent);

        Exception? error = await Record.ExceptionAsync(
            () => InternalInstallBackup.CreateAsync(client, parent, progress));

        AssertBusinessFailure(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.DoesNotContain(progress.Records, record => record.Stage == CompleteStage);
    }

    [Theory]
    [InlineData("boot_b")]
    [InlineData("recovery_b")]
    [InlineData("vbmeta_system_b")]
    [InlineData("spunvm")]
    [InlineData("modemst2")]
    public async Task Missing_required_label_rejects_before_any_partition_read(string role)
    {
        string parent = _fixture.NewCaseDirectory(nameof(Missing_required_label_rejects_before_any_partition_read) + "-" + role);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(omitRole: role);
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessFailure(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Duplicate_required_label_rejects_before_any_partition_read()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Duplicate_required_label_rejects_before_any_partition_read));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(duplicateRole: "boot_b");
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessFailure(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Required_label_on_wrong_lun_rejects_before_any_partition_read()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Required_label_on_wrong_lun_rejects_before_any_partition_read));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(moveRole: "vbmeta_a", moveRoleToLun: 5);
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessFailure(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    // ------------------------------------------------------------------- fresh LBA evidence

    [Fact]
    public async Task Shifted_partition_starts_drive_reads_and_lun0_layout()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Shifted_partition_starts_drive_reads_and_lun0_layout));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(
            startOf: name => name switch
            {
                "misc" => 3000,
                "boot_a" => 2500,
                "userdata" => 4096,
                "super" => 5000,
                _ => null,
            });
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.Equal(3000L, set.Files["misc"].StartSector);
        Assert.Equal(2500L, set.Files["boot_a"].StartSector);
        Assert.Equal(3000L, set.Lun0Layout.Partitions.Single(partition => partition.Name == "misc").StartSector);
        Assert.Equal(4096L, set.Lun0Layout.Partitions.Single(partition => partition.Name == "userdata").StartSector);
        Assert.Equal(5000L, set.Lun0Layout.Partitions.Single(partition => partition.Name == "super").StartSector);

        Assert.Contains(runner.Reads, read => read.Lun == 0 && read.StartSector == 3000 && read.SectorCount == 2);
        Assert.Contains(runner.Reads, read => read.Lun == 4 && read.StartSector == 2500 && read.SectorCount == 2);
    }

    [Fact]
    public async Task Per_lun_geometry_and_backup_start_are_not_reused_from_lun0()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Per_lun_geometry_and_backup_start_are_not_reused_from_lun0));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        for (int lun = 0; lun < 6; lun++)
        {
            Assert.Equal(device.TotalSectors(lun), set.Geometries[lun].TotalSectors);
            Assert.Equal(device.TotalSectors(lun) - IB001SyntheticDevice.GptSectors, set.Files["gpt_lun" + lun + "_backup"].StartSector);
            Assert.Contains(
                runner.Reads,
                read => read.Lun == lun &&
                        read.StartSector == device.TotalSectors(lun) - IB001SyntheticDevice.GptSectors &&
                        read.SectorCount == IB001SyntheticDevice.GptSectors);
        }

        Assert.NotEqual(set.Files["gpt_lun0_backup"].StartSector, set.Files["gpt_lun5_backup"].StartSector);
    }

    // ---------------------------------------------------------------- failures keep evidence

    [Theory]
    [InlineData("short-file")]
    [InlineData("nonzero")]
    [InlineData("transport")]
    public async Task Late_partition_read_failure_keeps_partial_backup_and_never_completes(string variant)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(Late_partition_read_failure_keeps_partial_backup_and_never_completes) + "-" + variant);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);

        switch (variant)
        {
            case "short-file":
                // One sector arrives where two were requested: the client must notice the short file.
                runner.PayloadOverride = read =>
                    device.RoleOf(read) == "spunvm" ? new byte[IB001SyntheticDevice.SectorSize] : null;
                break;

            case "nonzero":
                runner.ReadExitCode = read => device.RoleOf(read) == "spunvm" ? 1 : 0;
                break;

            case "transport":
                runner.ReadFailure = read =>
                    device.RoleOf(read) == "spunvm" ? new IOException("simulated EDL transport failure") : null;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        EdlClient client = NewClient(runner);
        IB001Progress progress = new(parent);

        Exception? error = await Record.ExceptionAsync(
            () => InternalInstallBackup.CreateAsync(client, parent, progress));

        AssertBusinessFailure(error);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.DoesNotContain(progress.Records, record => record.Stage == CompleteStage);

        string directory = Assert.Single(Directory.GetDirectories(parent));
        Assert.NotEmpty(Directory.GetFiles(directory, "*", SearchOption.AllDirectories));

        string manifestPath = Path.Combine(directory, ManifestFileName);
        Assert.True(File.Exists(manifestPath), "a failed backup must keep its partial manifest");

        using JsonDocument document = JsonDocument.Parse(ReadShared(manifestPath));
        Assert.Equal(PartialStatus, document.RootElement.GetProperty("status").GetString()!, StringComparer.Ordinal);
        Assert.False(File.Exists(manifestPath + ".sha256"), "no verified sidecar may exist for a failed backup");
    }

    [Theory]
    [InlineData("before-start")]
    [InlineData("mid-read")]
    public async Task Cancellation_creates_nothing_or_preserves_partial_without_complete(string variant)
    {
        string parent = _fixture.NewCaseDirectory(nameof(Cancellation_creates_nothing_or_preserves_partial_without_complete) + "-" + variant);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        IB001Progress progress = new(parent);

        if (variant == "before-start")
        {
            using CancellationTokenSource cancelled = new();
            cancelled.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => InternalInstallBackup.CreateAsync(client, parent, progress, cancelled.Token));

            Assert.Empty(runner.Commands);
            Assert.Empty(Directory.GetDirectories(parent));
            Assert.Empty(Directory.GetFiles(parent));
            Assert.Empty(progress.Records);
            return;
        }

        runner.ReadFailure = read =>
            device.RoleOf(read) == "fsc" ? new OperationCanceledException("cancelled mid-read") : null;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => InternalInstallBackup.CreateAsync(client, parent, progress));

        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.DoesNotContain(progress.Records, record => record.Stage == CompleteStage);

        string directory = Assert.Single(Directory.GetDirectories(parent));
        Assert.NotEmpty(Directory.GetFiles(directory, "*", SearchOption.AllDirectories));

        string manifestPath = Path.Combine(directory, ManifestFileName);
        if (File.Exists(manifestPath))
        {
            using JsonDocument document = JsonDocument.Parse(ReadShared(manifestPath));
            Assert.Equal(PartialStatus, document.RootElement.GetProperty("status").GetString()!, StringComparer.Ordinal);
        }

        Assert.False(File.Exists(manifestPath + ".sha256"));
    }

    [Theory]
    [InlineData("blank")]
    [InlineData("missing")]
    [InlineData("file")]
    public async Task Invalid_chosen_parent_rejects_without_any_command_or_fallback(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Invalid_chosen_parent_rejects_without_any_command_or_fallback) + "-" + variant);
        string parent = variant switch
        {
            "blank" => "   ",
            "missing" => Path.Combine(caseDirectory, "absent-parent"),
            "file" => Path.Combine(caseDirectory, "parent.txt"),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };

        if (variant == "file")
        {
            File.WriteAllText(parent, "not a directory");
        }

        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessFailure(error);
        Assert.Empty(runner.Commands);
        Assert.Empty(Directory.GetDirectories(caseDirectory));

        if (variant == "file")
        {
            // Only the file this theory prepared may exist; the factory never replaces it with a directory.
            Assert.True(File.Exists(parent));
            Assert.Equal("not a directory", File.ReadAllText(parent), StringComparer.Ordinal);
            Assert.Equal(parent, Assert.Single(Directory.GetFiles(caseDirectory)), StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            Assert.Empty(Directory.GetFiles(caseDirectory));
        }

        if (variant == "missing")
        {
            Assert.False(Directory.Exists(parent));
        }
    }

    // ---------------------------------------------------------------- repeat and warm session

    [Fact]
    public async Task Second_create_on_same_parent_uses_a_new_directory_and_a_warm_probe()
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(Second_create_on_same_parent_uses_a_new_directory_and_a_warm_probe));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        using InternalBackupSet first = await InternalInstallBackup.CreateAsync(client, parent);
        Dictionary<string, string> firstHashes = first.Files.ToDictionary(
            pair => pair.Key, pair => HashFile(pair.Value.FilePath), StringComparer.Ordinal);

        using InternalBackupSet second = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.NotEqual(first.DirectoryPath, second.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(2, Directory.GetDirectories(parent).Length);
        Assert.Equal(51, second.Files.Count);

        // The initial loader response is used once for the session, never again for the second backup.
        Assert.Equal(1, runner.SaharaResponseCount);
        Assert.Equal(12, runner.ProbedLuns.Count);
        Assert.True(client.HasInitialSaharaProof);

        foreach (KeyValuePair<string, string> pair in firstHashes)
        {
            Assert.True(File.Exists(first.Files[pair.Key].FilePath));
            Assert.Equal(pair.Value, HashFile(first.Files[pair.Key].FilePath), StringComparer.OrdinalIgnoreCase);
        }

        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Malformed_table_on_proven_client_fails_without_sahara_or_reset()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Malformed_table_on_proven_client_fails_without_sahara_or_reset));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(corruptPrimaryHeaderLun: 4);
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        // Prove the session first through the real client: the factory must then reuse warm probes.
        await client.ProbeAsync(0, initialLoader: true);
        Assert.True(client.HasInitialSaharaProof);

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessFailure(error);
        Assert.Equal(1, runner.SaharaResponseCount);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.True(client.HasInitialSaharaProof, "a read-only failure must not clear the session proof");
        AssertOnlyGptReads(runner);
    }

    // ------------------------------------------------------------------- dispose and progress

    [Fact]
    public async Task Dispose_is_idempotent_and_preserves_every_file_and_metadata()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Dispose_is_idempotent_and_preserves_every_file_and_metadata));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);
        string directoryPath = set.DirectoryPath;
        string manifestPath = set.ManifestPath;
        string manifestSha = set.ManifestSha256;
        Dictionary<string, string> hashes = set.Files.ToDictionary(
            pair => pair.Key, pair => HashFile(pair.Value.FilePath), StringComparer.Ordinal);

        set.Dispose();
        set.Dispose();

        Assert.Equal(directoryPath, set.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestPath, set.ManifestPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestSha, set.ManifestSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(51, set.Files.Count);
        Assert.Same(client.Binding, set.Binding);

        foreach (KeyValuePair<string, string> pair in hashes)
        {
            EdlCapturedRegion region = set.Files[pair.Key];
            Assert.True(File.Exists(region.FilePath), "dispose must not delete " + region.FilePath);
            Assert.Equal(pair.Value, HashFile(region.FilePath), StringComparer.OrdinalIgnoreCase);
        }

        Assert.Equal(manifestSha, HashFile(manifestPath), StringComparer.OrdinalIgnoreCase);

        // The owned read locks are gone, so the files are writable again for the caller.
        string sample = set.Files["misc"].FilePath;
        using (FileStream stream = new(sample, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.True(stream.Length > 0);
        }

        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Progress_reaches_complete_only_after_verified_manifest_with_exact_totals()
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(Progress_reaches_complete_only_after_verified_manifest_with_exact_totals));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        IB001Progress progress = new(parent);

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent, progress);

        Assert.NotEmpty(progress.Records);
        foreach (InternalBackupProgress record in progress.Records)
        {
            Assert.Contains(record.Stage, AllowedStages, StringComparer.Ordinal);
        }

        long expectedBytes = set.Files.Values.Sum(region => region.Length);
        Assert.Equal(device.ExpectedBytes(), expectedBytes);

        InternalBackupProgress last = progress.Records[progress.Records.Count - 1];
        Assert.Equal(CompleteStage, last.Stage, StringComparer.Ordinal);
        Assert.Equal(51, last.TotalFiles);
        Assert.Equal(51, last.CompletedFiles);
        Assert.Equal(expectedBytes, last.TotalBytes);
        Assert.Equal(expectedBytes, last.CompletedBytes);

        for (int index = 1; index < progress.Records.Count; index++)
        {
            Assert.True(
                progress.Records[index].CompletedFiles >= progress.Records[index - 1].CompletedFiles,
                "completed files must never go backwards");
        }

        // No callback after the completed factory call, and the verified manifest existed while it fired.
        Assert.Equal(progress.Records.Count - 1, progress.CompleteIndex);
        Assert.True(progress.ManifestPresentAtComplete, "the verified manifest must exist at the complete stage");
        Assert.True(progress.SidecarPresentAtComplete, "the manifest sidecar must exist at the complete stage");
    }

    [Fact]
    public async Task Manifest_is_partial_until_every_payload_file_is_verified()
    {
        string parent = _fixture.NewCaseDirectory(nameof(Manifest_is_partial_until_every_payload_file_is_verified));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);

        List<(string Status, int Files)> snapshots = new();
        runner.BeforeFileWrite = read =>
        {
            if (read.SectorCount == IB001SyntheticDevice.GptSectors)
            {
                return;
            }

            string? manifest = Directory.GetDirectories(parent)
                .Select(directory => Path.Combine(directory, ManifestFileName))
                .FirstOrDefault(File.Exists);

            if (manifest is null)
            {
                return;
            }

            using JsonDocument document = JsonDocument.Parse(ReadShared(manifest));
            JsonElement root = document.RootElement;
            int files = root.TryGetProperty("files", out JsonElement array) && array.ValueKind == JsonValueKind.Array
                ? array.GetArrayLength()
                : 0;

            snapshots.Add((root.GetProperty("status").GetString()!, files));
        };

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.NotEmpty(snapshots);
        Assert.All(snapshots, snapshot => Assert.Equal(PartialStatus, snapshot.Status, StringComparer.Ordinal));
        Assert.True(
            snapshots[snapshots.Count - 1].Files < 51,
            "the manifest must not index all 51 files before the last partition write");

        using JsonDocument final = JsonDocument.Parse(ReadShared(set.ManifestPath));
        Assert.Equal(VerifiedStatus, final.RootElement.GetProperty("status").GetString()!, StringComparer.Ordinal);
    }

    // --------------------------------------------------------------------------- helpers

    private EdlClient NewClient(IB001FakeEdlRunner runner, FirmwareSnapshot? firmware = null) => new(
        _fixture.Toolchain,
        NewBinding(firmware),
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    /// <summary>The full actual TB322FC 120 firmware snapshot used by the FW01 regression cases.</summary>
    private static FirmwareSnapshot Actual120Firmware() => new(
        Actual120AndroidBuild,
        BuildFingerprint: Actual120BuildFingerprint,
        AndroidRelease: Actual120AndroidRelease,
        SecurityPatch: Actual120SecurityPatch,
        AndroidReportedBootloaderState: BootloaderState.Locked);

    private EdlEntryResult NewBinding(FirmwareSnapshot? firmware = null) => new(
        new AndroidMaintenanceIdentity(
            new DeviceIdentity("SN0123456789", _fixture.Toolchain.Model, BootloaderState.Unknown)
            {
                Firmware = firmware ?? new FirmwareSnapshot(
                    _fixture.Toolchain.AndroidBuild,
                    BuildFingerprint: null,
                    AndroidRelease: null,
                    SecurityPatch: null,
                    AndroidReportedBootloaderState: BootloaderState.Unknown),
            },
            E003EdlTestData.SocSerialDecimal),
        E003EdlTestData.Endpoint(),
        E003EdlTestData.BusSerialHex);

    private static void AssertBusinessFailure(Exception? error)
    {
        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
    }

    private static void AssertOnlyGptReads(IB001FakeEdlRunner runner)
    {
        Assert.NotEmpty(runner.Reads);
        foreach (IB001Read read in runner.Reads)
        {
            Assert.Equal(IB001SyntheticDevice.GptSectors, read.SectorCount);
        }
    }

    private static string HashFile(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static byte[] ReadShared(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using MemoryStream buffer = new();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }
}

/// <summary>One <c>read-sector</c> invocation exactly as the fake runner received it.</summary>
internal sealed record IB001Read(int Lun, long StartSector, long SectorCount, string FilePath);

/// <summary>One acknowledged <c>write-sector</c> invocation and the stable snapshot that was accepted.</summary>
internal sealed record IB001Write(int Lun, long StartSector, long SectorCount, string FilePath, string Sha256);

/// <summary>
/// Six synthetic 4096-byte-sector disks carrying one GPT each, with the 40 required labels distributed over
/// LUN0..LUN5 as the contract requires. LUN1 and LUN2 additionally carry the xbl pair, LUN3 carries cdt, and
/// LUN0 carries the unbacked userdata/super decoys; LUN1..LUN3 keep one dummy decoy each.
/// <para>
/// Every table is written field by field by <see cref="GptImage"/> with its own CRCs. The 64 KiB fragments are
/// padded into the real 64-sector (256 KiB) read windows - primary block first, backup block last - so both
/// headers and entry arrays keep the LBAs the production reader will actually deliver.
/// </para>
/// </summary>
internal sealed class IB001SyntheticDevice
{
    internal const int SectorSize = 4096;
    internal const int GptSectors = 64;

    private const int FragmentBytes = 64 * 1024;
    private const string AndroidType = "1B81E7E6-F50D-419B-A739-2AEEF8DA3335";
    private const long FirstUsableSector = 128;
    private const long TailReserveSectors = 40;
    private const long MiscSectors = 16;
    private const long SuperSectors = 1024L * 1024 * 1024 / SectorSize;
    private const int CopyBufferBytes = 64 * 1024;

    internal const long BootPartitionBytes = 96L * 1024 * 1024;
    internal const long BootPartitionSectors = BootPartitionBytes / SectorSize;
    internal const long Lun0TotalSectors = 128L * 1024 * 1024 * 1024 / SectorSize;

    internal static readonly string[] Lun0Roles =
    {
        "proinfo", "lenovolock", "lenovocust", "lenovoraw", "ssd", "persist", "misc", "keystore", "frp",
        "metadata", "vbmeta_system_a", "vbmeta_system_b",
    };

    internal static readonly string[] Lun1Roles = { "xbl_a", "xbl_config_a" };

    internal static readonly string[] Lun2Roles = { "xbl_b", "xbl_config_b" };

    internal static readonly string[] Lun3Roles = { "cdt" };

    internal static readonly string[] Lun4Roles =
    {
        "boot_a", "boot_b", "init_boot_a", "init_boot_b", "vendor_boot_a", "vendor_boot_b", "dtbo_a", "dtbo_b",
        "vbmeta_a", "vbmeta_b", "recovery_a", "recovery_b", "devinfo", "uefivarstore", "secdata", "connsec",
        "spunvm", "abl_a", "abl_b",
    };

    internal static readonly string[] Lun5Roles = { "modemst1", "modemst2", "fsg", "fsc" };

    /// <summary>The exact ten GPT labels a direct fixture accepts as file-backed sources.</summary>
    internal static readonly string[] DirectSourceRoles =
    {
        "boot_a", "boot_b", "vendor_boot_a", "vendor_boot_b", "init_boot_a", "init_boot_b",
        "abl_a", "abl_b", "xbl_config_a", "xbl_config_b",
    };

    /// <summary>
    /// The fixed six optional AVB labels; only this bounded set may be opted in on top of the ten base roles.
    /// These names are file-backing slots only - the bytes a test puts here are synthetic filler, not a chain.
    /// </summary>
    internal static readonly string[] DirectAvbSourceRoles =
    {
        "recovery_a", "recovery_b", "vbmeta_system_a", "vbmeta_system_b", "vbmeta_a", "vbmeta_b",
    };

    private readonly Dictionary<int, List<GptPartitionSpec>> _specs = new();
    private readonly Dictionary<int, byte[]> _primary = new();
    private readonly Dictionary<int, byte[]> _backup = new();
    private readonly Dictionary<int, long> _totals = new();
    private readonly Dictionary<int, string> _diskGuids = new();
    private readonly Dictionary<string, (int Lun, GptPartitionSpec Spec)> _roles = new(StringComparer.Ordinal);
    private readonly Dictionary<(int Lun, long Start, long Count), (string Role, byte[] Bytes)> _windows = new();
    private readonly Dictionary<(int Lun, long Start, long Count), (string Role, string Path)> _fileWindows = new();
    private Dictionary<string, VerifiedEdlFile> _directSources = new(StringComparer.Ordinal);
    private Dictionary<string, string> _directPaths = new(StringComparer.Ordinal);
    private readonly List<(int Lun, long StartByte, long Length, string Path)> _overlays = new();
    private bool _isDirect;
    private bool _archiveLayout;
    private string _directChild = string.Empty;
    private int _snapshotSequence;
    private int _uuidSequence;

    private IB001SyntheticDevice()
    {
    }

    internal static IB001SyntheticDevice Create(
        string? omitRole = null,
        string? duplicateRole = null,
        string? moveRole = null,
        int moveRoleToLun = 0,
        Func<string, long?>? startOf = null,
        int? corruptPrimaryHeaderLun = null,
        int? corruptBackupArrayLun = null,
        int? disagreePairLun = null,
        bool gen5 = false,
        bool includeEfisp = false,
        int efispLun = 4,
        bool archiveLayout = false)
    {
        IB001SyntheticDevice device = new();
        device._archiveLayout = archiveLayout;

        List<string> lun0 = Without(Lun0Roles, omitRole, moveRole);
        List<string> lun1 = Without(Lun1Roles, omitRole, moveRole);
        List<string> lun2 = Without(Lun2Roles, omitRole, moveRole);
        List<string> lun3 = Without(Lun3Roles, omitRole, moveRole);
        List<string> lun4 = Without(Lun4Roles, omitRole, moveRole);
        List<string> lun5 = Without(Lun5Roles, omitRole, moveRole);

        List<string> HostForLun(int lun) => lun switch
        {
            0 => lun0,
            1 => lun1,
            2 => lun2,
            3 => lun3,
            4 => lun4,
            5 => lun5,
            _ => throw new ArgumentOutOfRangeException(nameof(lun)),
        };

        if (moveRole is not null)
        {
            List<string> destination = moveRoleToLun switch
            {
                0 => lun0,
                1 => lun1,
                2 => lun2,
                3 => lun3,
                4 => lun4,
                5 => lun5,
                _ => throw new ArgumentOutOfRangeException(nameof(moveRoleToLun)),
            };

            destination.Add(moveRole);
        }

        if (includeEfisp && !string.Equals(omitRole, "efisp", StringComparison.Ordinal))
        {
            // EFISP-A1: efisp is not a member of the static LUN tables, so it joins the selected host
            // list only on opt-in, before duplication, and omitting it still wins.
            HostForLun(efispLun).Add("efisp");
        }

        if (duplicateRole is not null)
        {
            // The second copy gets its own PARTUUID and its own non-overlapping range.
            // GroupOf only knows the static tables, so efisp duplicates its selected host instead.
            List<string> host = duplicateRole == "efisp"
                ? HostForLun(efispLun)
                : GroupOf(duplicateRole, lun0, lun1, lun2, lun3, lun4, lun5);

            if (duplicateRole != "efisp" || host.Contains("efisp", StringComparer.Ordinal))
            {
                host.Add(duplicateRole);
            }
        }

        if (gen5)
        {
            // The Gen5 (Y7005) tables carry only the four G4-only LUN0 labels' absence: proinfo,
            // lenovolock, lenovocust and lenovoraw never exist on this platform.
            lun0.RemoveAll(role => role is "proinfo" or "lenovolock" or "lenovocust" or "lenovoraw");
        }

        if (archiveLayout)
        {
            // Archive layout keeps userdata last so it can absorb the tail up to the last usable sector.
            lun0.AddRange(new[] { "super", "userdata" });
        }
        else
        {
            lun0.AddRange(new[] { "userdata", "super" });
        }

        device.Build(0, lun0, startOf);
        device.Build(1, Append(Append(lun1, "dummy_lun1"), "rawdump"), startOf);
        device.Build(2, Append(lun2, "dummy_lun2"), startOf);
        device.Build(3, Append(lun3, "dummy_lun3"), startOf);
        device.Build(4, lun4, startOf);
        device.Build(5, lun5, startOf);

        if (corruptPrimaryHeaderLun is int headerLun)
        {
            // Only the stored header CRC flips; every header field still describes a legal table.
            device._primary[headerLun][SectorSize + GptBytes.HeaderCrcOffset] ^= 0x01;
        }

        if (corruptBackupArrayLun is int arrayLun)
        {
            byte[] backup = device._backup[arrayLun];
            int arrayOffset = backup.Length - SectorSize - GptImage.EntryCount * GptImage.EntrySize;
            backup[arrayOffset] ^= 0x01;
        }

        if (disagreePairLun is int pairLun)
        {
            byte[] backup = device._backup[pairLun];
            int headerOffset = backup.Length - SectorSize;
            GptBytes.WriteGuid(
                backup.AsSpan(), headerOffset + GptBytes.DiskGuidOffset, "99999999-8888-4777-8666-555544443333");
            GptBytes.RefreshHeaderCrc(backup, headerOffset, GptImage.HeaderSize);
        }

        return device;
    }

    /// <summary>
    /// Opt-in direct fixture (DFX001): the ten GPT labels carry real, file-backed bytes instead of synthetic
    /// arrays. Every claim is re-measured from the actual file before any table is built, each source is copied
    /// once into this factory's own child directory and zero-padded to its 4096-byte extent, and the copies -
    /// never the caller's originals - become the direct file windows. No payload is ever held in a byte array.
    /// An optional map may add exactly the fixed six AVB labels; when it is null the ten-role contract and the
    /// original geometry are byte-for-byte what they were. An optional EFISP claim adds only the fixed "efisp"
    /// label on LUN4, and <c>gen5</c> drops only the four G4-only LUN0 names; both default to the old geometry.
    /// </summary>
    internal static IB001SyntheticDevice CreateDirect(
        string backingDirectory,
        IReadOnlyDictionary<string, VerifiedEdlFile> sourceFiles,
        IReadOnlyDictionary<string, VerifiedEdlFile>? avbSourceFiles = null,
        VerifiedEdlFile? efispSource = null,
        bool gen5 = false)
    {
        ArgumentNullException.ThrowIfNull(sourceFiles);
        if (string.IsNullOrWhiteSpace(backingDirectory))
        {
            throw new ArgumentException("a direct fixture needs an owned backing directory.", nameof(backingDirectory));
        }

        if (sourceFiles.Count != DirectSourceRoles.Length)
        {
            throw new InvalidDataException(
                "the direct fixture accepts exactly " + DirectSourceRoles.Length + " source roles, not " +
                sourceFiles.Count + ".");
        }

        if (avbSourceFiles is not null)
        {
            if (avbSourceFiles.Count != DirectAvbSourceRoles.Length)
            {
                throw new InvalidDataException(
                    "the direct fixture accepts exactly " + DirectAvbSourceRoles.Length +
                    " optional AVB source roles, not " + avbSourceFiles.Count + ".");
            }

            foreach (string role in avbSourceFiles.Keys)
            {
                if (!DirectAvbSourceRoles.Contains(role, StringComparer.Ordinal))
                {
                    throw new InvalidDataException(
                        "the direct fixture does not accept the optional source role '" + role + "'.");
                }
            }

            foreach (string role in DirectAvbSourceRoles)
            {
                if (!avbSourceFiles.ContainsKey(role))
                {
                    throw new InvalidDataException(
                        "the direct fixture is missing the optional source role '" + role + "'.");
                }
            }
        }

        List<string> roles = new(DirectSourceRoles);
        if (avbSourceFiles is not null)
        {
            roles.AddRange(DirectAvbSourceRoles);
        }

        if (efispSource is not null)
        {
            // EFISP-A1: efisp is never a member of the ten or six maps; it joins the claim list only on opt-in.
            roles.Add("efisp");
        }

        Dictionary<string, VerifiedEdlFile> claims = new(StringComparer.Ordinal);
        Dictionary<string, string> paths = new(StringComparer.Ordinal);
        Dictionary<string, long> extents = new(StringComparer.Ordinal);

        foreach (string role in roles)
        {
            VerifiedEdlFile? claim;
            if (string.Equals(role, "efisp", StringComparison.Ordinal))
            {
                // The efisp claim comes from its own explicit input, never from the ten- or six-role maps.
                claim = efispSource;
            }
            else if (avbSourceFiles is not null && DirectAvbSourceRoles.Contains(role, StringComparer.Ordinal))
            {
                avbSourceFiles.TryGetValue(role, out claim);
            }
            else
            {
                sourceFiles.TryGetValue(role, out claim);
            }

            if (claim is null)
            {
                throw new InvalidDataException("the direct fixture is missing the source role '" + role + "'.");
            }

            string full = Path.GetFullPath(claim.Path);
            if (!File.Exists(full))
            {
                throw new InvalidDataException("the direct source '" + role + "' does not exist: " + full);
            }

            long actual = new FileInfo(full).Length;
            if (actual <= 0)
            {
                throw new InvalidDataException("the direct source '" + role + "' is empty.");
            }

            if (actual != claim.Length)
            {
                throw new InvalidDataException(
                    "the direct source '" + role + "' claims " + claim.Length + " bytes but is " + actual + " bytes.");
            }

            if (IsBootRole(role) && actual != BootPartitionBytes)
            {
                throw new InvalidDataException(
                    "the direct boot source '" + role + "' must be exactly " + BootPartitionBytes + " bytes.");
            }

            string measured;
            using (FileStream stream = new(
                full, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan))
            {
                measured = Convert.ToHexString(SHA256.HashData(stream));
            }

            if (!string.Equals(measured, claim.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("the direct source '" + role + "' does not match its claimed SHA-256.");
            }

            claims[role] = claim;
            paths[role] = full;
            extents[role] = SectorExtent(actual);
        }

        IB001SyntheticDevice device = new() { _isDirect = true };
        string child = Path.Combine(Path.GetFullPath(backingDirectory), "direct-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(child);

        Dictionary<string, VerifiedEdlFile> copies = new(StringComparer.Ordinal);
        try
        {
            foreach (string role in roles)
            {
                string copyPath = Path.Combine(child, role + ".img");
                long targetBytes = checked(extents[role] * SectorSize);
                long copied = 0;
                byte[] buffer = new byte[CopyBufferBytes];

                using (FileStream source = new(
                    paths[role], FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes,
                    FileOptions.SequentialScan))
                using (FileStream destination = new(
                    copyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferBytes))
                {
                    int read;
                    while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        destination.Write(buffer, 0, read);
                        copied += read;
                    }

                    if (copied != claims[role].Length)
                    {
                        throw new InvalidDataException("the direct source '" + role + "' changed while it was copied.");
                    }

                    // SetLength is the zero-pad baseline from the real byte count to the whole-sector extent.
                    if (destination.Length != targetBytes)
                    {
                        destination.SetLength(targetBytes);
                    }
                }

                string sha;
                using (FileStream verify = new(
                    copyPath, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan))
                {
                    sha = Convert.ToHexString(SHA256.HashData(verify));
                }

                copies[role] = new VerifiedEdlFile(copyPath, targetBytes, sha);
            }
        }
        catch
        {
            try
            {
                Directory.Delete(child, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }

            throw;
        }

        device._directSources = copies;
        device._directPaths = copies.ToDictionary(pair => pair.Key, pair => pair.Value.Path, StringComparer.Ordinal);
        device._directChild = child;

        // LUN0 is 128 GiB: sequential small roles, one 64 KiB misc, super, then the 1 MiB-aligned userdata tail.
        List<(string Name, long Start, long Count)> lun0 = new();
        long cursor = FirstUsableSector;
        foreach (string name in Lun0Roles)
        {
            if (gen5 && IsG4OnlyLun0Role(name))
            {
                // Gen5 (Y7005) carries none of the four G4-only labels; every other LUN0 role is unchanged.
                continue;
            }

            long count = string.Equals(name, "misc", StringComparison.Ordinal)
                ? MiscSectors
                : extents.TryGetValue(name, out long extent) ? extent : 2;
            lun0.Add((name, cursor, count));
            cursor = checked(cursor + count);
        }

        lun0.Add(("super", cursor, SuperSectors));
        cursor = checked(cursor + SuperSectors);

        long userdataStart = cursor % 256 == 0 ? cursor : cursor + (256 - cursor % 256);
        long lun0LastUsable = Lun0TotalSectors - GptSectors - 1;
        lun0.Add(("userdata", userdataStart, lun0LastUsable - userdataStart + 1));
        device.BuildDirect(0, Lun0TotalSectors, lun0);

        for (int lun = 1; lun < 6; lun++)
        {
            List<(string Name, long Start, long Count)> placements = new();
            long position = FirstUsableSector;
            foreach (string name in DirectNames(lun, efispSource is not null))
            {
                long count = extents.TryGetValue(name, out long extent)
                    ? extent
                    : (string.Equals(name, "misc", StringComparison.Ordinal) ? MiscSectors : 2);
                placements.Add((name, position, count));
                position = checked(position + count);
            }

            long total = Math.Max(LegacyTotalSectors(lun), position - 1 + 128);
            device.BuildDirect(lun, total, placements);
        }

        return device;
    }

    /// <summary>True for this opt-in direct device; the default <see cref="Create"/> device stays false.</summary>
    internal bool IsDirect => _isDirect;

    /// <summary>The padded, owned copy claims of the ten direct sources; empty for a default device.</summary>
    internal IReadOnlyDictionary<string, VerifiedEdlFile> DirectSourceFiles => _directSources;

    /// <summary>A unique, owned path for an accepted write snapshot inside this fixture's child directory.</summary>
    internal string CreateWriteSnapshotPath(string suffix) =>
        Path.Combine(
            _directChild,
            "write-" + (_snapshotSequence++).ToString("D4", CultureInfo.InvariantCulture) + "-" + suffix + ".bin");

    /// <summary>Appends one byte-exact overlay; later overlays win on overlap and originals stay underneath.</summary>
    internal void AddWriteOverlay(int lun, long startSector, long sectorCount, string path)
    {
        _overlays.Add((lun, checked(startSector * SectorSize), checked(sectorCount * SectorSize), path));
    }

    internal long TotalSectors(int lun) => _totals[lun];

    internal string DiskGuid(int lun) => _diskGuids[lun];

    internal IReadOnlyList<GptPartitionSpec> Specs(int lun) => _specs[lun];

    internal byte[]? PayloadFor(IB001Read read) => PayloadFor(read.Lun, read.StartSector, read.SectorCount);

    internal byte[]? PayloadFor(int lun, long startSector, long sectorCount) =>
        _windows.TryGetValue((lun, startSector, sectorCount), out (string Role, byte[] Bytes) window)
            ? window.Bytes
            : null;

    /// <summary>
    /// Exact window lookup for the legacy path. A direct device additionally resolves a whole-sector subrange
    /// to its containing role when exactly one capture contains it, which keeps range assertions expressive.
    /// </summary>
    internal string? RoleOf(IB001Read read)
    {
        if (_windows.TryGetValue(
            (read.Lun, read.StartSector, read.SectorCount), out (string Role, byte[] Bytes) exact))
        {
            return exact.Role;
        }

        if (!_isDirect)
        {
            return null;
        }

        if (_fileWindows.TryGetValue(
            (read.Lun, read.StartSector, read.SectorCount), out (string Role, string Path) file))
        {
            return file.Role;
        }

        string? containing = null;
        foreach (KeyValuePair<(int Lun, long Start, long Count), (string Role, byte[] Bytes)> window in _windows)
        {
            if (!Contains(window.Key, read))
            {
                continue;
            }

            if (containing is not null)
            {
                return null;
            }

            containing = window.Value.Role;
        }

        foreach (KeyValuePair<(int Lun, long Start, long Count), (string Role, string Path)> window in _fileWindows)
        {
            if (!Contains(window.Key, read))
            {
                continue;
            }

            if (containing is not null)
            {
                return null;
            }

            containing = window.Value.Role;
        }

        return containing;

        static bool Contains((int Lun, long Start, long Count) window, IB001Read candidate) =>
            window.Lun == candidate.Lun &&
            candidate.StartSector >= window.Start &&
            candidate.StartSector + candidate.SectorCount <= window.Start + window.Count;
    }

    /// <summary>
    /// Materializes exactly one read output for a direct device: a zero baseline of the requested length, then
    /// the overlapping small windows and the overlapping owned source files at their long offsets. Only the
    /// requested file is created - there is no whole-device image - and every copy is bounded to 64 KiB.
    /// </summary>
    internal async Task MaterializeReadAsync(IB001Read read, CancellationToken cancellationToken)
    {
        long total = TotalSectors(read.Lun);
        if (read.StartSector < 0 || read.SectorCount <= 0 || read.StartSector > total - read.SectorCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(read),
                "the direct read of LUN " + read.Lun + " at " + read.StartSector + "+" + read.SectorCount +
                " is outside the fixture geometry.");
        }

        long bytes = checked(read.SectorCount * SectorSize);
        long readEnd = read.StartSector + read.SectorCount;

        using FileStream output = new(
            read.FilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferBytes, FileOptions.Asynchronous);
        output.SetLength(bytes);

        foreach (KeyValuePair<(int Lun, long Start, long Count), (string Role, byte[] Bytes)> window in _windows)
        {
            if (window.Key.Lun != read.Lun)
            {
                continue;
            }

            long start = Math.Max(read.StartSector, window.Key.Start);
            long end = Math.Min(readEnd, window.Key.Start + window.Key.Count);
            if (end <= start)
            {
                continue;
            }

            int sourceOffset = checked((int)((start - window.Key.Start) * SectorSize));
            int length = checked((int)((end - start) * SectorSize));
            output.Position = checked((start - read.StartSector) * SectorSize);
            await output.WriteAsync(window.Value.Bytes.AsMemory(sourceOffset, length), cancellationToken)
                .ConfigureAwait(false);
        }

        foreach (KeyValuePair<(int Lun, long Start, long Count), (string Role, string Path)> window in _fileWindows)
        {
            if (window.Key.Lun != read.Lun)
            {
                continue;
            }

            long start = Math.Max(read.StartSector, window.Key.Start);
            long end = Math.Min(readEnd, window.Key.Start + window.Key.Count);
            if (end <= start)
            {
                continue;
            }

            using FileStream source = new(
                window.Value.Path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            source.Position = checked((start - window.Key.Start) * SectorSize);
            output.Position = checked((start - read.StartSector) * SectorSize);
            await CopyBoundedAsync(source, output, checked((end - start) * SectorSize), cancellationToken)
                .ConfigureAwait(false);
        }

        // Acknowledged writes were appended in order and win over the original bytes only where they overlap.
        long requestStart = checked(read.StartSector * SectorSize);
        long requestEnd = requestStart + bytes;
        foreach ((int lun, long startByte, long length, string path) in _overlays)
        {
            if (lun != read.Lun)
            {
                continue;
            }

            long from = Math.Max(requestStart, startByte);
            long to = Math.Min(requestEnd, startByte + length);
            if (from >= to)
            {
                continue;
            }

            using FileStream source = new(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            source.Position = from - startByte;
            output.Position = from - requestStart;
            await CopyBoundedAsync(source, output, to - from, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task CopyBoundedAsync(
        FileStream source,
        FileStream destination,
        long length,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[CopyBufferBytes];
        long remaining = length;
        while (remaining > 0)
        {
            int chunk = (int)Math.Min(buffer.Length, remaining);
            int read = await source.ReadAsync(buffer.AsMemory(0, chunk), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new EndOfStreamException("the direct fixture source ended inside the requested range.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            remaining -= read;
        }
    }

    internal IEnumerable<(string Role, int Lun)> ExpectedRoles()
    {
        for (int lun = 0; lun < 6; lun++)
        {
            yield return ("gpt_lun" + lun + "_primary", lun);
            yield return ("gpt_lun" + lun + "_backup", lun);
        }

        foreach (KeyValuePair<string, (int Lun, GptPartitionSpec Spec)> pair in _roles)
        {
            yield return (pair.Key, pair.Value.Lun);
        }
    }

    internal (int Lun, long Start, long Count, string? PartUuid) Expectation(string role)
    {
        if (role.StartsWith("gpt_lun", StringComparison.Ordinal))
        {
            string[] parts = role.Split('_');
            int lun = int.Parse(parts[1].Substring(3), CultureInfo.InvariantCulture);
            bool primary = string.Equals(parts[2], "primary", StringComparison.Ordinal);
            return (lun, primary ? 0 : TotalSectors(lun) - GptSectors, GptSectors, null);
        }

        (int lunOfRole, GptPartitionSpec spec) = _roles[role];
        return (lunOfRole, spec.StartSector, spec.SectorCount, spec.PartUuid);
    }

    internal long ExpectedBytes()
    {
        long total = 12L * GptSectors * SectorSize;
        foreach (KeyValuePair<string, (int Lun, GptPartitionSpec Spec)> pair in _roles)
        {
            total += pair.Value.Spec.SectorCount * SectorSize;
        }

        return total;
    }

    private static List<string> Without(string[] roles, string? omitRole, string? moveRole) =>
        roles.Where(name => name != omitRole && name != moveRole).ToList();

    private static List<string> Append(List<string> roles, string extra)
    {
        List<string> copy = new(roles) { extra };
        return copy;
    }

    private static List<string> GroupOf(
        string role,
        List<string> lun0,
        List<string> lun1,
        List<string> lun2,
        List<string> lun3,
        List<string> lun4,
        List<string> lun5) =>
        Lun0Roles.Contains(role, StringComparer.Ordinal) ? lun0
        : Lun1Roles.Contains(role, StringComparer.Ordinal) ? lun1
        : Lun2Roles.Contains(role, StringComparer.Ordinal) ? lun2
        : Lun3Roles.Contains(role, StringComparer.Ordinal) ? lun3
        : Lun4Roles.Contains(role, StringComparer.Ordinal) ? lun4
        : Lun5Roles.Contains(role, StringComparer.Ordinal) ? lun5
        : throw new ArgumentOutOfRangeException(nameof(role));

    private void Build(int lun, IReadOnlyList<string> names, Func<string, long?>? startOf)
    {
        long total = lun == 0 && _archiveLayout ? Lun0TotalSectors : 8192 + lun * 1024L;
        long lastUsable = total - TailReserveSectors;

        _totals[lun] = total;
        _diskGuids[lun] = "10BEF39" + lun.ToString("X1", CultureInfo.InvariantCulture) +
                          "-0EBA-9668-B82C-4E092F4C446" + lun.ToString("X1", CultureInfo.InvariantCulture);

        long cursor = FirstUsableSector;
        List<GptPartitionSpec> specs = new();

        foreach (string name in names)
        {
            long start = startOf?.Invoke(name) ?? cursor;
            if (start < cursor)
            {
                start = cursor;
            }

            long sectorCount = name switch
            {
                "efisp" => 768,
                "userdata" when _archiveLayout => lastUsable - start + 1,
                _ => 2,
            };

            long end = start + sectorCount - 1;
            if (end > lastUsable)
            {
                throw new InvalidOperationException("IB001 fixture: '" + name + "' does not fit into LUN" + lun + ".");
            }

            cursor = end + 1;

            GptPartitionSpec spec = new(specs.Count + 1, name, AndroidType, NextUuid(), start, sectorCount, 0UL);
            specs.Add(spec);
            if (IsRequiredRole(name))
            {
                // Only the 40 contract labels are indexed as roles; userdata/super/dummy stay decoys.
                _roles.TryAdd(name, (lun, spec));
            }

            if (name == "userdata" && _archiveLayout)
            {
                // The archive-layout userdata payload would span tens of gigabytes, so neither the bytes
                // nor a read window for it are ever materialized.
            }
            else
            {
                _windows[(lun, start, sectorCount)] = (name, PayloadBytes(name, sectorCount));
            }
        }

        _specs[lun] = specs;

        GptImage image = new(
            SectorSize, total * SectorSize, _diskGuids[lun], FirstUsableSector, lastUsable, specs.ToArray());

        byte[] primary = PrimaryWindow(image.BuildPrimaryFragment());
        byte[] backup = BackupWindow(image.BuildBackupFragment());

        _primary[lun] = primary;
        _backup[lun] = backup;
        _windows[(lun, 0, GptSectors)] = ("gpt_lun" + lun + "_primary", primary);
        _windows[(lun, total - GptSectors, GptSectors)] = ("gpt_lun" + lun + "_backup", backup);
    }

    /// <summary>
    /// Direct layout only: the caller supplies total, so last usable is total - 64 - 1 and the 64-sector backup
    /// read window can never overlap a partition. The default <see cref="Build"/> geometry is untouched.
    /// Source roles become file windows; userdata and super are never captured or materialized.
    /// </summary>
    private void BuildDirect(int lun, long total, IReadOnlyList<(string Name, long Start, long Count)> placements)
    {
        long lastUsable = total - GptSectors - 1;
        string diskGuid = "10BEF39" + lun.ToString("X1", CultureInfo.InvariantCulture) +
                          "-0EBA-9668-B82C-4E092F4C446" + lun.ToString("X1", CultureInfo.InvariantCulture);

        _totals[lun] = total;
        _diskGuids[lun] = diskGuid;

        List<GptPartitionSpec> specs = new();
        foreach ((string name, long start, long count) in placements)
        {
            if (count <= 0 || start < FirstUsableSector || start + count - 1 > lastUsable)
            {
                throw new InvalidOperationException(
                    "IB001 direct fixture: '" + name + "' does not fit into LUN" + lun + ".");
            }

            GptPartitionSpec spec = new(specs.Count + 1, name, AndroidType, NextUuid(), start, count, 0UL);
            specs.Add(spec);
            if (IsRequiredRole(name))
            {
                _roles.TryAdd(name, (lun, spec));
            }

            if (_directPaths.TryGetValue(name, out string copyPath))
            {
                _fileWindows[(lun, start, count)] = (name, copyPath);
            }
            else if (!string.Equals(name, "userdata", StringComparison.Ordinal) &&
                     !string.Equals(name, "super", StringComparison.Ordinal))
            {
                _windows[(lun, start, count)] = (
                    name,
                    string.Equals(name, "misc", StringComparison.Ordinal)
                        ? DirectMiscPayload()
                        : PayloadBytes(name, count));
            }
        }

        _specs[lun] = specs;

        GptImage image = new(SectorSize, total * SectorSize, diskGuid, FirstUsableSector, lastUsable, specs.ToArray());

        byte[] primary = PrimaryWindow(image.BuildPrimaryFragment());
        byte[] backup = BackupWindow(image.BuildBackupFragment());

        _primary[lun] = primary;
        _backup[lun] = backup;
        _windows[(lun, 0, GptSectors)] = ("gpt_lun" + lun + "_primary", primary);
        _windows[(lun, total - GptSectors, GptSectors)] = ("gpt_lun" + lun + "_backup", backup);
    }

    /// <summary>
    /// Direct misc seeding only: production refuses a command area that is not all zero in bytes [0,32) and a
    /// recovery area that is not all zero in [64,832). Only those two ranges are cleared; the status bytes,
    /// stage/reserved bytes and the remainder keep their deterministic pattern so preservation stays
    /// observable. The default <see cref="Create"/> misc payload is unchanged.
    /// </summary>
    private static byte[] DirectMiscPayload()
    {
        byte[] bytes = PayloadBytes("misc", MiscSectors);
        Array.Clear(bytes, 0, 32);
        Array.Clear(bytes, 64, 832 - 64);
        return bytes;
    }

    private static List<string> DirectNames(int lun, bool includeEfisp) => lun switch
    {
        1 => new List<string>(Lun1Roles) { "dummy_lun1" },
        2 => new List<string>(Lun2Roles) { "dummy_lun2" },
        3 => new List<string>(Lun3Roles) { "dummy_lun3" },
        4 => includeEfisp ? new List<string>(Lun4Roles) { "efisp" } : new List<string>(Lun4Roles),
        5 => new List<string>(Lun5Roles),
        _ => throw new ArgumentOutOfRangeException(nameof(lun)),
    };

    private static long LegacyTotalSectors(int lun) => 8192 + lun * 1024L;

    private static long SectorExtent(long bytes) => bytes / SectorSize + (bytes % SectorSize == 0 ? 0 : 1);

    private static bool IsBootRole(string role) =>
        string.Equals(role, "boot_a", StringComparison.Ordinal) ||
        string.Equals(role, "boot_b", StringComparison.Ordinal);

    /// <summary>The four LUN0 labels that only a G4 table carries; Gen5 (Y7005) never places them.</summary>
    private static bool IsG4OnlyLun0Role(string role) =>
        role is "proinfo" or "lenovolock" or "lenovocust" or "lenovoraw";

    private string NextUuid() =>
        "580CF9" + (_uuidSequence++ % 256).ToString("X2", CultureInfo.InvariantCulture) +
        "-BA9B-5048-B221-F683F755277C";

    private static bool IsRequiredRole(string name) =>
        name == "efisp" ||
        (name != "metadata" && Lun0Roles.Contains(name, StringComparer.Ordinal)) ||
        Lun1Roles.Contains(name, StringComparer.Ordinal) ||
        Lun2Roles.Contains(name, StringComparer.Ordinal) ||
        Lun3Roles.Contains(name, StringComparer.Ordinal) ||
        Lun4Roles.Contains(name, StringComparer.Ordinal) ||
        Lun5Roles.Contains(name, StringComparer.Ordinal);

    private static byte[] PrimaryWindow(byte[] fragment)
    {
        byte[] window = new byte[GptSectors * SectorSize];
        Buffer.BlockCopy(fragment, 0, window, 0, fragment.Length);
        return window;
    }

    private static byte[] BackupWindow(byte[] fragment)
    {
        byte[] window = new byte[GptSectors * SectorSize];
        Buffer.BlockCopy(fragment, 0, window, window.Length - fragment.Length, fragment.Length);
        return window;
    }

    private static byte[] PayloadBytes(string name, long sectorCount)
    {
        int length = checked((int)(sectorCount * SectorSize));
        byte[] bytes = new byte[length];

        int seed = 17;
        foreach (char character in name)
        {
            seed = unchecked(seed * 31 + character);
        }

        for (int index = 0; index < length; index++)
        {
            bytes[index] = (byte)((seed + index * 7) % 251);
        }

        return bytes;
    }
}

/// <summary>
/// Deterministic EDL transport fake. It answers <c>printgpt</c> and <c>read-sector</c> from the synthetic
/// disks, writes the exact bytes the production reader asked for to the path it passed, and refuses every
/// other command - so an unexpected write or reset route cannot pass silently. Write/reset answers exist only
/// for a <c>CreateDirect</c> device opted in through <c>enableWrites</c>; the one-argument constructor keeps the
/// legacy read-only behaviour and still counts every refused write/reset attempt. No process is ever started
/// and no real device is touched.
/// </summary>
internal sealed class IB001FakeEdlRunner : ICommandRunner
{
    private const int SnapshotBufferBytes = 64 * 1024;

    private readonly IB001SyntheticDevice _device;
    private readonly bool _enableWrites;
    private readonly string _hardwareId;
    private readonly List<ProcessCommand> _commands = new();
    private readonly List<IB001Read> _reads = new();
    private readonly List<IB001Write> _writes = new();
    private readonly List<int> _probedLuns = new();
    private bool _saharaEmitted;
    private (int Lun, long Start, long Count)? _readbackTarget;
    private bool _readbackArmed;
    private bool _readbackFired;

    internal IB001FakeEdlRunner(
        IB001SyntheticDevice device,
        bool enableWrites = false,
        string? hardwareId = null)
    {
        _device = device;
        _hardwareId = string.IsNullOrWhiteSpace(hardwareId) ? E003EdlTestData.HardwareId : hardwareId;

        if (enableWrites && !device.IsDirect)
        {
            throw new InvalidOperationException("IB001 write mode is only available for a CreateDirect device.");
        }

        _enableWrites = enableWrites;
    }

    internal IReadOnlyList<ProcessCommand> Commands => _commands;

    internal IReadOnlyList<IB001Read> Reads => _reads;

    internal IReadOnlyList<IB001Write> Writes => _writes;

    internal IReadOnlyList<int> ProbedLuns => _probedLuns;

    internal int SaharaResponseCount { get; private set; }

    internal int WriteOrResetCount { get; private set; }

    internal int ResetCount { get; private set; }

    internal Func<IB001Read, byte[]?>? PayloadOverride { get; set; }

    internal Func<ProcessResult>? ResetOverride { get; set; }

    internal Func<IB001Read, Exception?>? ReadFailure { get; set; }

    internal Func<IB001Read, int>? ReadExitCode { get; set; }

    internal Action<IB001Read>? BeforeFileWrite { get; set; }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        _commands.Add(command);
        return RunCommandAsync(command.Arguments.ToArray(), cancellationToken);
    }

    /// <summary>Same argv dispatch without a <see cref="ProcessCommand"/>, used by the focused runner cases.</summary>
    internal Task<ProcessResult> RunCommandAsync(string[] arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        cancellationToken.ThrowIfCancellationRequested();

        if (arguments.Length == 0)
        {
            throw new InvalidOperationException("IB001 fake received a command without arguments.");
        }

        switch (arguments[0])
        {
            case "printgpt":
                return Task.FromResult(Probe(arguments));
            case "read-sector":
                return Read(arguments, cancellationToken);
            case "write-sector":
                return Write(arguments);
            case "reset":
                return Task.FromResult(Reset(arguments));
            default:
                WriteOrResetCount++;
                throw new InvalidOperationException(
                    "IB001 fake refuses EDL command '" + arguments[0] + "': the backup never writes or resets.");
        }
    }

    private ProcessResult Probe(string[] arguments)
    {
        int lun = LunArgument(arguments);
        _probedLuns.Add(lun);

        string output = E003EdlTestData.Selected();
        if (!_saharaEmitted)
        {
            output += "\n" + E003EdlTestData.Sahara(hwid: _hardwareId);
            _saharaEmitted = true;
            SaharaResponseCount++;
        }

        output += "\n" + E003EdlTestData.Geometry(lun, _device.TotalSectors(lun));
        return new ProcessResult(0, output, string.Empty);
    }

    private Task<ProcessResult> Read(string[] arguments, CancellationToken cancellationToken)
    {
        IB001Read read = new(
            LunArgument(arguments),
            long.Parse(arguments[1], CultureInfo.InvariantCulture),
            long.Parse(arguments[2], CultureInfo.InvariantCulture),
            arguments[3]);

        _reads.Add(read);

        Exception? failure = ReadFailure?.Invoke(read);
        if (failure is not null)
        {
            return Task.FromException<ProcessResult>(failure);
        }

        if (IsReadbackFailure(read))
        {
            return Task.FromException<ProcessResult>(
                new IOException(
                    "IB001 injected readback failure for LUN " + read.Lun + " at " + read.StartSector + "+" +
                    read.SectorCount + "."));
        }

        // An explicit override keeps absolute priority; otherwise a direct device always renders the range so
        // acknowledged overlays are visible even for an exact GPT/misc window match.
        byte[]? payload = PayloadOverride?.Invoke(read);
        if (payload is null && _device.IsDirect)
        {
            return ReadDirectAsync(read, cancellationToken);
        }

        payload ??= _device.PayloadFor(read);
        if (payload is null)
        {
            throw new InvalidOperationException(
                "IB001 fake has no bytes for LUN " + read.Lun + " sectors " + read.StartSector + "+" +
                read.SectorCount + " (" + read.FilePath + ").");
        }

        BeforeFileWrite?.Invoke(read);
        File.WriteAllBytes(read.FilePath, payload);

        long expected = read.SectorCount * IB001SyntheticDevice.SectorSize;
        int exitCode = ReadExitCode?.Invoke(read) ?? 0;
        string output = E003EdlTestData.ReadSuccess(read.Lun, read.StartSector, read.SectorCount, expected, read.FilePath);
        return Task.FromResult(new ProcessResult(exitCode, output, string.Empty));
    }

    /// <summary>
    /// Direct devices materialize the requested range from their small windows and owned source files. Only the
    /// read hook ordering and the exact E003 success ACK are shared with the legacy path, which stays unchanged.
    /// </summary>
    private async Task<ProcessResult> ReadDirectAsync(IB001Read read, CancellationToken cancellationToken)
    {
        BeforeFileWrite?.Invoke(read);
        await _device.MaterializeReadAsync(read, cancellationToken).ConfigureAwait(false);

        long expected = read.SectorCount * IB001SyntheticDevice.SectorSize;
        int exitCode = ReadExitCode?.Invoke(read) ?? 0;
        string output = E003EdlTestData.ReadSuccess(read.Lun, read.StartSector, read.SectorCount, expected, read.FilePath);
        return new ProcessResult(exitCode, output, string.Empty);
    }

    /// <summary>
    /// Arms one exact readback fault. Nothing happens until a write with the same (lun, start, count) has been
    /// acknowledged; the first later read of that exact tuple then throws <see cref="IOException"/> once.
    /// </summary>
    internal void InjectReadbackFailureOnce(int lun, long startSector, long sectorCount)
    {
        long total = _device.TotalSectors(lun);
        if (startSector < 0 || sectorCount <= 0 || startSector > total - sectorCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(startSector),
                "the IB001 readback fault target is outside LUN " + lun + ".");
        }

        _readbackTarget = (lun, startSector, sectorCount);
    }

    private bool IsReadbackFailure(IB001Read read)
    {
        if (!_readbackArmed || _readbackFired || _readbackTarget is null)
        {
            return false;
        }

        (int lun, long start, long count) = _readbackTarget.Value;
        if (lun != read.Lun || start != read.StartSector || count != read.SectorCount)
        {
            return false;
        }

        _readbackFired = true;
        return true;
    }

    /// <summary>
    /// Accepts <c>write-sector START FILE --lun LUN</c> for an opted-in direct device only: the real source is
    /// snapshotted with a bounded 64 KiB stream (hashing as it copies), the overlay is appended only after the
    /// copy is complete, and the snapshot stays valid even if the caller later mutates or deletes its file.
    /// </summary>
    private Task<ProcessResult> Write(string[] arguments)
    {
        WriteOrResetCount++;
        if (!_enableWrites)
        {
            throw new InvalidOperationException(
                "IB001 fake refuses EDL command '" + arguments[0] + "': the backup never writes or resets.");
        }

        if (arguments.Length < 3)
        {
            throw new InvalidOperationException("IB001 fake write-sector requires START and FILE.");
        }

        long startSector = long.Parse(arguments[1], CultureInfo.InvariantCulture);
        string sourcePath = arguments[2];
        int lun = LunArgument(arguments);

        long total = _device.TotalSectors(lun);
        if (!File.Exists(sourcePath))
        {
            throw new InvalidOperationException("IB001 fake write-sector source does not exist: " + sourcePath);
        }

        long byteLength = new FileInfo(sourcePath).Length;
        if (byteLength <= 0 || byteLength % IB001SyntheticDevice.SectorSize != 0)
        {
            throw new InvalidOperationException(
                "IB001 fake write-sector requires a positive whole-sector file length.");
        }

        long sectorCount = byteLength / IB001SyntheticDevice.SectorSize;
        if (startSector < 0 || startSector > total - sectorCount)
        {
            throw new InvalidOperationException("IB001 fake write-sector range is outside LUN " + lun + ".");
        }

        string snapshotPath = _device.CreateWriteSnapshotPath(
            lun.ToString(CultureInfo.InvariantCulture) + "-" + startSector.ToString(CultureInfo.InvariantCulture));

        long copied = 0;
        string sha;
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[SnapshotBufferBytes];
            using (FileStream source = new(
                sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, SnapshotBufferBytes,
                FileOptions.SequentialScan))
            using (FileStream destination = new(
                snapshotPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, SnapshotBufferBytes))
            {
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    destination.Write(buffer, 0, read);
                    hash.AppendData(buffer, 0, read);
                    copied += read;
                }
            }

            sha = Convert.ToHexString(hash.GetHashAndReset());
        }

        if (copied != byteLength)
        {
            throw new InvalidOperationException("IB001 fake write-sector source changed while it was snapshotted.");
        }

        _device.AddWriteOverlay(lun, startSector, sectorCount, snapshotPath);
        _writes.Add(new IB001Write(lun, startSector, sectorCount, snapshotPath, sha));

        if (_readbackTarget is { } target)
        {
            (int targetLun, long targetStart, long targetCount) = target;
            if (targetLun == lun && targetStart == startSector && targetCount == sectorCount)
            {
                _readbackArmed = true;
            }
        }

        return Task.FromResult(new ProcessResult(
            0,
            E003EdlTestData.WriteSuccess(lun, startSector, sectorCount, byteLength),
            string.Empty));
    }

    /// <summary>Accepts only the exact <c>--mode Reset --delay 1</c> option pair and counts the reset once.</summary>
    private ProcessResult Reset(string[] arguments)
    {
        WriteOrResetCount++;
        if (!_enableWrites)
        {
            throw new InvalidOperationException(
                "IB001 fake refuses EDL command '" + arguments[0] + "': the backup never writes or resets.");
        }

        // The production client appends its common global flags, so only the fixed prefix is required.
        bool exact = arguments.Length >= 5 &&
                     string.Equals(arguments[1], "--mode", StringComparison.Ordinal) &&
                     string.Equals(arguments[2], "Reset", StringComparison.Ordinal) &&
                     string.Equals(arguments[3], "--delay", StringComparison.Ordinal) &&
                     string.Equals(arguments[4], "1", StringComparison.Ordinal);
        if (!exact)
        {
            throw new InvalidOperationException("IB001 fake only accepts reset --mode Reset --delay 1.");
        }

        ResetCount++;
        return ResetOverride is null
            ? new ProcessResult(0, E003EdlTestData.ResetSuccess(), string.Empty)
            : ResetOverride();
    }

    private static int LunArgument(string[] arguments)
    {
        int index = Array.IndexOf(arguments, "--lun");
        if (index < 0 || index + 1 >= arguments.Length)
        {
            throw new InvalidOperationException("IB001 fake requires an explicit --lun argument.");
        }

        return int.Parse(arguments[index + 1], CultureInfo.InvariantCulture);
    }
}

/// <summary>
/// Synchronous <see cref="IProgress{T}"/> recorder. <see cref="Progress{T}"/> would post to the thread pool and
/// hide the ordering this contract is about, so the callback runs inline on the factory's own thread.
/// </summary>
internal sealed class IB001Progress : IProgress<InternalBackupProgress>
{
    private const string ManifestName = "backup-manifest.json";
    private readonly string _parent;
    private readonly List<InternalBackupProgress> _records = new();

    internal IB001Progress(string parent)
    {
        _parent = parent;
    }

    internal IReadOnlyList<InternalBackupProgress> Records => _records;

    internal int CompleteIndex { get; private set; } = -1;

    internal bool ManifestPresentAtComplete { get; private set; }

    internal bool SidecarPresentAtComplete { get; private set; }

    public void Report(InternalBackupProgress value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _records.Add(value);

        if (!string.Equals(value.Stage, "complete", StringComparison.Ordinal))
        {
            return;
        }

        CompleteIndex = _records.Count - 1;

        string? manifest = Directory.GetDirectories(_parent)
            .Select(directory => Path.Combine(directory, ManifestName))
            .FirstOrDefault(File.Exists);

        ManifestPresentAtComplete = manifest is not null;
        SidecarPresentAtComplete = manifest is not null && File.Exists(manifest + ".sha256");
    }
}

/// <summary>
/// DFX001: builds the ten real BM slot sources once for the whole direct class, so the 96 MiB boot copies are
/// authored once per suite instead of once per case. The caller owns the BM workspace until every direct
/// fixture that references it has been asserted; disposal happens after the class has finished.
/// </summary>
public sealed class DirectSourceFixture : IDisposable
{
    public DirectSourceFixture()
    {
        Workspace = new EdlRawBootBuilderTests.Workspace();
        SlotA = EdlRawBootBuilderTests.CreateSlot(Workspace, "a", 0x31);
        SlotB = EdlRawBootBuilderTests.CreateSlot(Workspace, "b", 0x71);
    }

    internal EdlRawBootBuilderTests.Workspace Workspace { get; }

    internal EdlRawBootBuilderTests.SlotFixture SlotA { get; }

    internal EdlRawBootBuilderTests.SlotFixture SlotB { get; }

    /// <summary>The exact ten direct labels, each mapped to the BM file that really backs it.</summary>
    internal IReadOnlyDictionary<string, VerifiedEdlFile> Sources() =>
        new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
        {
            ["boot_a"] = SlotA.CurrentBoot,
            ["boot_b"] = SlotB.CurrentBoot,
            ["vendor_boot_a"] = SlotA.VendorBoot,
            ["vendor_boot_b"] = SlotB.VendorBoot,
            ["init_boot_a"] = SlotA.InitBoot,
            ["init_boot_b"] = SlotB.InitBoot,
            ["abl_a"] = SlotA.Abl,
            ["abl_b"] = SlotB.Abl,
            ["xbl_config_a"] = SlotA.XblConfig,
            ["xbl_config_b"] = SlotB.XblConfig,
        };

    public void Dispose() => Workspace.Dispose();
}

/// <summary>
/// DFX001 focused cases: the direct fixture must copy and pad the ten real BM sources, keep the 52-role backup
/// contract on a 128 GiB LUN0, materialize arbitrary whole-sector subranges from files, and refuse any source
/// claim that does not match the actual file. None of these cases runs locally; the manager runs them remote.
/// </summary>
public sealed class DirectFixtureTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<DirectSourceFixture>
{
    private readonly EdlClientToolchainFixture _fixture;
    private readonly DirectSourceFixture _sources;

    public DirectFixtureTests(EdlClientToolchainFixture fixture, DirectSourceFixture sources)
    {
        _fixture = fixture;
        _sources = sources;
    }

    [Fact]
    public async Task Direct_fixture_copies_the_ten_sources_and_backs_up_the_same_51_roles()
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Direct_fixture_copies_the_ten_sources_and_backs_up_the_same_51_roles));
        IReadOnlyDictionary<string, VerifiedEdlFile> sources = _sources.Sources();
        Dictionary<string, string> originals = sources.ToDictionary(
            pair => pair.Key, pair => HashFile(pair.Value.Path), StringComparer.Ordinal);

        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, sources);

        Assert.True(device.IsDirect);
        Assert.Equal(IB001SyntheticDevice.DirectSourceRoles.Length, device.DirectSourceFiles.Count);
        Assert.Equal(IB001SyntheticDevice.Lun0TotalSectors, device.TotalSectors(0));
        Assert.True(
            device.TotalSectors(0) * IB001SyntheticDevice.SectorSize >= 96L * 1024 * 1024 * 1024,
            "LUN0 must be at least the 96 GiB boot device class");

        // Every claim is the copy actually on disk, and every original stayed untouched.
        foreach (string role in IB001SyntheticDevice.DirectSourceRoles)
        {
            VerifiedEdlFile copy = device.DirectSourceFiles[role];
            string copyPath = Path.GetFullPath(copy.Path);

            Assert.NotEqual(Path.GetFullPath(sources[role].Path), copyPath, StringComparer.OrdinalIgnoreCase);
            Assert.True(copyPath.StartsWith(Path.GetFullPath(backing), StringComparison.OrdinalIgnoreCase));
            Assert.True(File.Exists(copyPath), "the owned copy is missing: " + copyPath);
            Assert.Equal(copy.Length, new FileInfo(copyPath).Length);
            Assert.Equal(copy.Sha256, HashFile(copyPath), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(0L, copy.Length % IB001SyntheticDevice.SectorSize);
            Assert.True(copy.Length >= sources[role].Length);

            long expected = role.StartsWith("boot_", StringComparison.Ordinal)
                ? IB001SyntheticDevice.BootPartitionBytes
                : PaddedBytes(sources[role].Length);
            Assert.Equal(expected, copy.Length);
            Assert.Equal(originals[role], HashFile(sources[role].Path), StringComparer.OrdinalIgnoreCase);
        }

        // LUN0 geometry: super precedes userdata, userdata is physically and numerically last.
        IReadOnlyList<GptPartitionSpec> lun0 = device.Specs(0);
        Assert.Equal(14, lun0.Count);
        Assert.Equal(128L, lun0[0].StartSector);
        for (int index = 1; index < IB001SyntheticDevice.Lun0Roles.Length; index++)
        {
            Assert.Equal(lun0[index - 1].StartSector + lun0[index - 1].SectorCount, lun0[index].StartSector);
        }

        Assert.Equal(16L, lun0.Single(partition => partition.Name == "misc").SectorCount);
        GptPartitionSpec super = lun0.Single(partition => partition.Name == "super");
        GptPartitionSpec userdata = lun0.Single(partition => partition.Name == "userdata");
        Assert.Equal(1024L * 1024 * 1024 / IB001SyntheticDevice.SectorSize, super.SectorCount);
        Assert.True(super.StartSector + super.SectorCount <= userdata.StartSector);
        Assert.Equal("userdata", lun0[lun0.Count - 1].Name);
        Assert.Equal(0L, userdata.StartSector % 256);
        Assert.Equal(
            device.TotalSectors(0) - IB001SyntheticDevice.GptSectors - 1,
            userdata.StartSector + userdata.SectorCount - 1);

        // The real production reader must parse those GPTs and capture the same 52 roles from the direct device.
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        string parent = _fixture.NewCaseDirectory(
            nameof(Direct_fixture_copies_the_ten_sources_and_backs_up_the_same_51_roles) + "-backup");

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        HashSet<string> expectedRoles = device.ExpectedRoles().Select(entry => entry.Role).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(51, expectedRoles.Count);
        Assert.Equal(51, set.Files.Count);
        Assert.True(expectedRoles.SetEquals(set.Files.Keys), "the direct device must index exactly the 51 contract roles");

        for (int lun = 0; lun < 6; lun++)
        {
            Assert.Equal(
                new EdlGeometry(lun, IB001SyntheticDevice.SectorSize, device.TotalSectors(lun)),
                set.Geometries[lun]);
            Assert.Equal(device.DiskGuid(lun), set.Tables[lun].DiskGuid, StringComparer.OrdinalIgnoreCase);
        }

        foreach (string role in expectedRoles)
        {
            (int lun, long start, long count, string? partUuid) = device.Expectation(role);
            EdlCapturedRegion region = set.Files[role];

            Assert.Equal(lun, region.Lun);
            Assert.Equal(start, region.StartSector);
            Assert.Equal(count, region.SectorCount);
            Assert.Equal(partUuid, region.PartUuid);
            Assert.Equal(count * IB001SyntheticDevice.SectorSize, region.Length);
            Assert.Equal(region.Length, new FileInfo(region.FilePath).Length);
            Assert.Equal(region.Sha256, HashFile(region.FilePath), StringComparer.OrdinalIgnoreCase);

            if (device.DirectSourceFiles.TryGetValue(role, out VerifiedEdlFile? claim))
            {
                Assert.Equal(claim.Length, region.Length);
                Assert.Equal(claim.Sha256, region.Sha256, StringComparer.OrdinalIgnoreCase);
            }
        }

        Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, set.Files["boot_a"].Length);
        Assert.Equal(51, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Direct_reads_materialize_whole_sector_subranges_of_misc_gpt_and_boot_tail()
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Direct_reads_materialize_whole_sector_subranges_of_misc_gpt_and_boot_tail));
        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, _sources.Sources());
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        string reads = _fixture.NewCaseDirectory(
            nameof(Direct_reads_materialize_whole_sector_subranges_of_misc_gpt_and_boot_tail) + "-reads");

        await client.ProbeAsync(0, initialLoader: true);
        await client.ProbeAsync(4, initialLoader: false);

        // A 16 KiB fragment in the middle of the 64 KiB misc partition.
        (int miscLun, long miscStart, long miscCount, _) = device.Expectation("misc");
        byte[] miscWindow = device.PayloadFor(miscLun, miscStart, miscCount)!;
        byte[] expectedMisc = miscWindow.Skip(2 * IB001SyntheticDevice.SectorSize)
            .Take(4 * IB001SyntheticDevice.SectorSize).ToArray();
        string miscPath = Path.Combine(reads, "misc-fragment.bin");
        EdlReadEvidence miscRead = await client.ReadAsync(miscLun, miscStart + 2, 4, miscPath);
        Assert.Equal(4L * IB001SyntheticDevice.SectorSize, miscRead.Length);
        Assert.Equal(expectedMisc, ReadFile(miscPath));
        Assert.Equal(
            "misc",
            device.RoleOf(new IB001Read(miscLun, miscStart + 2, 4, miscPath)),
            StringComparer.Ordinal);

        // A 64 KiB fragment of the primary GPT window.
        byte[] primary = device.PayloadFor(0, 0, IB001SyntheticDevice.GptSectors)!;
        string gptPath = Path.Combine(reads, "gpt-fragment.bin");
        await client.ReadAsync(0, 0, 16, gptPath);
        Assert.Equal(primary.Take(16 * IB001SyntheticDevice.SectorSize).ToArray(), ReadFile(gptPath));
        Assert.Equal(
            "gpt_lun0_primary",
            device.RoleOf(new IB001Read(0, 0, 16, gptPath)),
            StringComparer.Ordinal);

        // The 96 MiB boot tail comes from the padded owned copy, never from a whole virtual disk.
        (int bootLun, long bootStart, long bootCount, _) = device.Expectation("boot_a");
        Assert.Equal(IB001SyntheticDevice.BootPartitionSectors, bootCount);
        long tailStart = bootStart + bootCount - 2;
        string tailPath = Path.Combine(reads, "boot-tail.bin");
        await client.ReadAsync(bootLun, tailStart, 2, tailPath);
        byte[] expectedTail = ReadRange(
            device.DirectSourceFiles["boot_a"].Path,
            (bootCount - 2) * IB001SyntheticDevice.SectorSize,
            2 * IB001SyntheticDevice.SectorSize);
        Assert.Equal(expectedTail, ReadFile(tailPath));
        Assert.Equal(
            "boot_a",
            device.RoleOf(new IB001Read(bootLun, tailStart, 2, tailPath)),
            StringComparer.Ordinal);

        // Range validation happens before the output file exists.
        string outsidePath = Path.Combine(reads, "outside.bin");
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => device.MaterializeReadAsync(
                new IB001Read(0, device.TotalSectors(0), 1, outsidePath),
                CancellationToken.None));
        Assert.False(File.Exists(outsidePath));

        Assert.Equal(3, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("length")]
    [InlineData("hash")]
    public void Direct_fixture_rejects_source_claims_that_do_not_match_reality(string variant)
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Direct_fixture_rejects_source_claims_that_do_not_match_reality) + "-" + variant);
        Dictionary<string, VerifiedEdlFile> sources = _sources.Sources()
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

        switch (variant)
        {
            case "missing":
                Assert.True(sources.Remove("abl_b"));
                break;
            case "extra":
                sources["misc"] = sources["abl_b"];
                break;
            case "length":
                VerifiedEdlFile shorter = sources["abl_a"];
                sources["abl_a"] = new VerifiedEdlFile(
                    shorter.Path, shorter.Length + IB001SyntheticDevice.SectorSize, shorter.Sha256);
                break;
            case "hash":
                VerifiedEdlFile changed = sources["abl_a"];
                sources["abl_a"] = new VerifiedEdlFile(changed.Path, changed.Length, new string('0', 64));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        Assert.Throws<InvalidDataException>(() => IB001SyntheticDevice.CreateDirect(backing, sources));
        Assert.Empty(Directory.GetDirectories(backing));
        Assert.Empty(Directory.GetFiles(backing));
    }

    [Fact]
    public async Task Direct_fixture_accepts_the_six_avb_sources_and_backs_up_their_padded_extents()
    {
        string caseName = nameof(Direct_fixture_accepts_the_six_avb_sources_and_backs_up_their_padded_extents);
        string inputs = _fixture.NewCaseDirectory(caseName + "-inputs");
        string backing = _fixture.NewCaseDirectory(caseName);
        Dictionary<string, VerifiedEdlFile> avb = CreateAvbSources(inputs);
        Dictionary<string, string> originals = avb.ToDictionary(
            pair => pair.Key, pair => HashFile(pair.Value.Path), StringComparer.Ordinal);

        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, _sources.Sources(), avb);

        Assert.True(device.IsDirect);
        Assert.Equal(16, device.DirectSourceFiles.Count);

        // Every optional copy is an owned, zero-padded file; no original was rewritten.
        foreach (string role in IB001SyntheticDevice.DirectAvbSourceRoles)
        {
            VerifiedEdlFile copy = device.DirectSourceFiles[role];
            byte[] expected = PaddedCopy(ReadRange(avb[role].Path, 0, checked((int)avb[role].Length)));

            Assert.NotEqual(
                Path.GetFullPath(avb[role].Path), Path.GetFullPath(copy.Path), StringComparer.OrdinalIgnoreCase);
            Assert.True(Path.GetFullPath(copy.Path)
                .StartsWith(Path.GetFullPath(backing), StringComparison.OrdinalIgnoreCase));
            Assert.Equal(PaddedBytes(avb[role].Length), copy.Length);
            Assert.Equal(expected.Length, copy.Length);
            Assert.Equal(0L, copy.Length % IB001SyntheticDevice.SectorSize);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(expected)), copy.Sha256, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(copy.Length, new FileInfo(copy.Path).Length);
            Assert.Equal(expected, ReadFile(copy.Path));
            Assert.Equal(originals[role], HashFile(avb[role].Path), StringComparer.OrdinalIgnoreCase);
        }

        // LUN0 keeps its 14 slots: the two opted-in system vbmeta roles take their real padded extents.
        IReadOnlyList<GptPartitionSpec> lun0 = device.Specs(0);
        Assert.Equal(14, lun0.Count);
        Assert.Equal(3L, lun0.Single(partition => partition.Name == "vbmeta_system_a").SectorCount);
        Assert.Equal(3L, lun0.Single(partition => partition.Name == "vbmeta_system_b").SectorCount);
        Assert.Equal(16L, lun0.Single(partition => partition.Name == "misc").SectorCount);
        for (int index = 1; index < IB001SyntheticDevice.Lun0Roles.Length; index++)
        {
            Assert.Equal(lun0[index - 1].StartSector + lun0[index - 1].SectorCount, lun0[index].StartSector);
        }

        // LUN4 places recovery/vbmeta at their own extents too.
        Assert.Equal(2L, device.Specs(4).Single(partition => partition.Name == "recovery_a").SectorCount);
        Assert.Equal(2L, device.Specs(4).Single(partition => partition.Name == "vbmeta_b").SectorCount);

        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner);
        string parent = _fixture.NewCaseDirectory(caseName + "-backup");

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        Assert.Equal(51, set.Files.Count);

        foreach (string role in IB001SyntheticDevice.DirectAvbSourceRoles)
        {
            (int lun, long start, long count, _) = device.Expectation(role);
            EdlCapturedRegion region = set.Files[role];
            VerifiedEdlFile copy = device.DirectSourceFiles[role];

            Assert.Equal(lun, region.Lun);
            Assert.Equal(start, region.StartSector);
            Assert.Equal(count, region.SectorCount);
            Assert.Equal(copy.Length, region.Length);
            Assert.Equal(count * IB001SyntheticDevice.SectorSize, region.Length);
            Assert.Equal(copy.Sha256, region.Sha256, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(region.Sha256, HashFile(region.FilePath), StringComparer.OrdinalIgnoreCase);
        }

        Assert.Equal(3L * IB001SyntheticDevice.SectorSize, set.Files["vbmeta_system_a"].Length);
        Assert.Equal(51, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("missing")]
    public void Direct_fixture_rejects_an_optional_avb_map_that_is_not_the_fixed_six(string variant)
    {
        string caseName =
            nameof(Direct_fixture_rejects_an_optional_avb_map_that_is_not_the_fixed_six) + "-" + variant;
        string inputs = _fixture.NewCaseDirectory(caseName + "-inputs");
        string backing = _fixture.NewCaseDirectory(caseName);
        Dictionary<string, VerifiedEdlFile> avb = CreateAvbSources(inputs);

        if (string.Equals(variant, "missing", StringComparison.Ordinal))
        {
            Assert.True(avb.Remove("vbmeta_b"));
        }
        else
        {
            // Keep the count at six so only the unknown-key whitelist can reject this map.
            Assert.True(avb.Remove("vbmeta_b"));
            avb["vbmeta"] = avb["vbmeta_a"];
            Assert.Equal(IB001SyntheticDevice.DirectAvbSourceRoles.Length, avb.Count);
        }

        Assert.Throws<InvalidDataException>(
            () => IB001SyntheticDevice.CreateDirect(backing, _sources.Sources(), avb));
        Assert.Empty(Directory.GetDirectories(backing));
        Assert.Empty(Directory.GetFiles(backing));
    }

    [Fact]
    public void Direct_fixture_rejects_a_stale_hash_for_an_optional_source()
    {
        string caseName = nameof(Direct_fixture_rejects_a_stale_hash_for_an_optional_source);
        string inputs = _fixture.NewCaseDirectory(caseName + "-inputs");
        string backing = _fixture.NewCaseDirectory(caseName);
        Dictionary<string, VerifiedEdlFile> avb = CreateAvbSources(inputs);

        VerifiedEdlFile stale = avb["vbmeta_system_b"];
        avb["vbmeta_system_b"] = new VerifiedEdlFile(stale.Path, stale.Length, new string('0', 64));

        Assert.Throws<InvalidDataException>(
            () => IB001SyntheticDevice.CreateDirect(backing, _sources.Sources(), avb));
        Assert.Empty(Directory.GetDirectories(backing));
        Assert.Empty(Directory.GetFiles(backing));
    }

    [Fact]
    public async Task Write_mode_is_opt_in_and_the_legacy_runner_still_refuses_writes_and_resets()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Write_mode_is_opt_in_and_the_legacy_runner_still_refuses_writes_and_resets));
        string source = WriteSectorFile(caseDirectory, "one-sector.bin", 1, 0x5A);

        IB001FakeEdlRunner legacy = new(IB001SyntheticDevice.Create());
        await Assert.ThrowsAsync<InvalidOperationException>(() => SendWriteAsync(legacy, 0, 2048, source));
        await Assert.ThrowsAsync<InvalidOperationException>(() => legacy.RunCommandAsync(
            new[] { "reset", "--mode", "Reset", "--delay", "1" }, CancellationToken.None));

        Assert.Equal(2, legacy.WriteOrResetCount);
        Assert.Empty(legacy.Writes);
        Assert.Equal(0, legacy.ResetCount);

        Assert.Throws<InvalidOperationException>(
            () => new IB001FakeEdlRunner(IB001SyntheticDevice.Create(), enableWrites: true));
    }

    [Fact]
    public async Task Partial_gpt_writes_roundtrip_and_full_windows_keep_untouched_bytes()
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Partial_gpt_writes_roundtrip_and_full_windows_keep_untouched_bytes));
        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, _sources.Sources());
        IB001FakeEdlRunner runner = new(device, enableWrites: true);
        EdlClient client = NewClient(runner);
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Partial_gpt_writes_roundtrip_and_full_windows_keep_untouched_bytes) + "-io");

        await client.ProbeAsync(0, initialLoader: true);

        long total = device.TotalSectors(0);
        byte[] primary = device.PayloadFor(0, 0, IB001SyntheticDevice.GptSectors)!;
        byte[] backup = device.PayloadFor(
            0, total - IB001SyntheticDevice.GptSectors, IB001SyntheticDevice.GptSectors)!;
        byte[] expectedPrimary = (byte[])primary.Clone();
        byte[] expectedBackup = (byte[])backup.Clone();

        // Production order: backup array, last header, primary array, LBA 1 header - each read back at once.
        (long Start, int Count, byte Value)[] steps =
        {
            (total - 33, 4, 0xA1),
            (total - 1, 1, 0xA2),
            (2, 4, 0xA3),
            (1, 1, 0xA4),
        };

        foreach ((long start, int count, byte value) in steps)
        {
            string payload = WriteSectorFile(
                caseDirectory,
                "gpt-" + start.ToString(CultureInfo.InvariantCulture) + ".bin",
                count,
                value);

            await SendWriteAsync(runner, 0, start, payload);

            IB001Write write = runner.Writes[runner.Writes.Count - 1];
            Assert.Equal(0, write.Lun);
            Assert.Equal(start, write.StartSector);
            Assert.Equal(count, (int)write.SectorCount);
            Assert.Equal(HashFile(payload), write.Sha256, StringComparer.OrdinalIgnoreCase);
            Assert.NotEqual(
                Path.GetFullPath(payload),
                Path.GetFullPath(write.FilePath),
                StringComparer.OrdinalIgnoreCase);

            string readback = Path.Combine(
                caseDirectory,
                "readback-" + start.ToString(CultureInfo.InvariantCulture) + ".bin");
            await client.ReadAsync(0, start, count, readback);
            byte[] written = ReadFile(payload);
            Assert.Equal(written, ReadFile(readback));

            if (start < IB001SyntheticDevice.GptSectors)
            {
                Array.Copy(written, 0, expectedPrimary, (int)start * IB001SyntheticDevice.SectorSize, written.Length);
            }
            else
            {
                long offset = start - (total - IB001SyntheticDevice.GptSectors);
                Array.Copy(
                    written, 0, expectedBackup, (int)offset * IB001SyntheticDevice.SectorSize, written.Length);
            }
        }

        // A whole 64-sector window must still expose the acknowledged writes on top of the untouched bytes.
        string primaryPath = Path.Combine(caseDirectory, "primary-full.bin");
        await client.ReadAsync(0, 0, IB001SyntheticDevice.GptSectors, primaryPath);
        Assert.Equal(expectedPrimary, ReadFile(primaryPath));

        string backupPath = Path.Combine(caseDirectory, "backup-full.bin");
        await client.ReadAsync(
            0, total - IB001SyntheticDevice.GptSectors, IB001SyntheticDevice.GptSectors, backupPath);
        Assert.Equal(expectedBackup, ReadFile(backupPath));

        Assert.Equal(4, runner.Writes.Count);
        Assert.Equal(0, runner.ResetCount);
        Assert.Equal(4, runner.WriteOrResetCount);
    }

    [Fact]
    public async Task Misc_write_preserves_other_bytes_latest_wins_and_invalid_writes_are_rejected()
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Misc_write_preserves_other_bytes_latest_wins_and_invalid_writes_are_rejected));
        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, _sources.Sources());
        IB001FakeEdlRunner runner = new(device, enableWrites: true);
        EdlClient client = NewClient(runner);
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Misc_write_preserves_other_bytes_latest_wins_and_invalid_writes_are_rejected) + "-io");

        await client.ProbeAsync(0, initialLoader: true);

        long total = device.TotalSectors(0);
        (int miscLun, long miscStart, long miscCount, _) = device.Expectation("misc");
        byte[] miscWindow = device.PayloadFor(miscLun, miscStart, miscCount)!;

        // The direct misc seed clears only the production command and recovery areas.
        Assert.True(miscWindow.Take(32).All(value => value == 0), "command bytes [0,32) must be zero");
        Assert.True(
            miscWindow.Skip(64).Take(832 - 64).All(value => value == 0),
            "recovery bytes [64,832) must be zero");

        string baselinePath = Path.Combine(caseDirectory, "misc-baseline.bin");
        await client.ReadAsync(miscLun, miscStart, miscCount, baselinePath);
        Assert.Equal(miscWindow, ReadFile(baselinePath));

        // The 2 048-byte BCB rewrite is one 4 096-byte sector at the head of the captured misc region.
        string bcbPath = WriteSectorFile(caseDirectory, "misc-bcb.bin", 1, 0xBC);
        await SendWriteAsync(runner, miscLun, miscStart, bcbPath);

        string updatedPath = Path.Combine(caseDirectory, "misc-updated.bin");
        await client.ReadAsync(miscLun, miscStart, miscCount, updatedPath);
        byte[] updated = ReadFile(updatedPath);
        Assert.Equal(ReadFile(bcbPath), updated.Take(IB001SyntheticDevice.SectorSize).ToArray());
        Assert.Equal(
            miscWindow.Skip(IB001SyntheticDevice.SectorSize).ToArray(),
            updated.Skip(IB001SyntheticDevice.SectorSize).ToArray());

        // Overlapping writes: the later acknowledgement wins only where it overlaps.
        string firstPath = WriteSectorFile(caseDirectory, "misc-first.bin", 2, 0x11);
        string secondPath = WriteSectorFile(caseDirectory, "misc-second.bin", 2, 0x22);
        await SendWriteAsync(runner, miscLun, miscStart + 4, firstPath);
        await SendWriteAsync(runner, miscLun, miscStart + 5, secondPath);

        // A later caller mutation of the accepted file must not reach the runner-owned snapshot.
        IB001Write accepted = runner.Writes[1];
        File.WriteAllBytes(firstPath, new byte[2 * IB001SyntheticDevice.SectorSize]);
        Assert.NotEqual(HashFile(firstPath), accepted.Sha256, StringComparer.OrdinalIgnoreCase);

        string snapshotHash;
        using (FileStream snapshot = new(accepted.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            snapshotHash = Convert.ToHexString(SHA256.HashData(snapshot));
        }

        Assert.Equal(accepted.Sha256, snapshotHash, StringComparer.OrdinalIgnoreCase);

        string overlapPath = Path.Combine(caseDirectory, "misc-overlap.bin");
        await client.ReadAsync(miscLun, miscStart + 4, 3, overlapPath);
        byte[] overlap = ReadFile(overlapPath);
        Assert.Equal((byte)0x11, overlap[0]);
        Assert.Equal((byte)0x22, overlap[IB001SyntheticDevice.SectorSize]);
        Assert.Equal((byte)0x22, overlap[2 * IB001SyntheticDevice.SectorSize]);

        // Unaligned and out-of-range writes are rejected before any overlay is appended.
        int writesBefore = runner.Writes.Count;
        string unalignedPath = Path.Combine(caseDirectory, "unaligned.bin");
        File.WriteAllBytes(unalignedPath, new byte[1000]);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => SendWriteAsync(runner, miscLun, miscStart + 8, unalignedPath));

        string overflowPath = WriteSectorFile(caseDirectory, "misc-overflow.bin", 2, 0x33);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => SendWriteAsync(runner, miscLun, total - 1, overflowPath));
        Assert.Equal(writesBefore, runner.Writes.Count);

        string overflowReadPath = Path.Combine(caseDirectory, "misc-overflow-read.bin");
        await client.ReadAsync(miscLun, miscStart + 8, 2, overflowReadPath);
        Assert.Equal(
            miscWindow.Skip(8 * IB001SyntheticDevice.SectorSize).Take(2 * IB001SyntheticDevice.SectorSize).ToArray(),
            ReadFile(overflowReadPath));

        // A 2.5 GiB sparse overlay keeps every offset above int.MaxValue without a disk-sized allocation.
        const long SparseLength = 2684354560L;
        string sparsePath = Path.Combine(caseDirectory, "misc-sparse.bin");
        using (FileStream sparse = new(sparsePath, FileMode.CreateNew, FileAccess.Write))
        {
            sparse.SetLength(SparseLength);
            sparse.Position = 0;
            sparse.WriteByte(0x7E);
            sparse.Position = IB001SyntheticDevice.SectorSize - 1;
            sparse.WriteByte(0x7F);
        }

        long sparseSector = 2L * 1024 * 1024 * 1024 / IB001SyntheticDevice.SectorSize;
        device.AddWriteOverlay(
            miscLun, sparseSector, SparseLength / IB001SyntheticDevice.SectorSize, sparsePath);

        string sparseReadPath = Path.Combine(caseDirectory, "misc-sparse-read.bin");
        await client.ReadAsync(miscLun, sparseSector, 2, sparseReadPath);
        byte[] sparseBytes = ReadFile(sparseReadPath);
        Assert.Equal(2 * IB001SyntheticDevice.SectorSize, sparseBytes.Length);
        Assert.Equal((byte)0x7E, sparseBytes[0]);
        Assert.Equal((byte)0x7F, sparseBytes[IB001SyntheticDevice.SectorSize - 1]);
        Assert.Equal((byte)0, sparseBytes[IB001SyntheticDevice.SectorSize]);

        Assert.Equal(3, runner.Writes.Count);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Readback_fault_needs_the_matching_ack_fires_once_and_reset_counts_once()
    {
        string backing = _fixture.NewCaseDirectory(
            nameof(Readback_fault_needs_the_matching_ack_fires_once_and_reset_counts_once));
        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, _sources.Sources());
        IB001FakeEdlRunner runner = new(device, enableWrites: true);
        EdlClient client = NewClient(runner);
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Readback_fault_needs_the_matching_ack_fires_once_and_reset_counts_once) + "-io");

        await client.ProbeAsync(0, initialLoader: true);
        await client.ProbeAsync(4, initialLoader: false);

        (int lun, long start, long count, _) = device.Expectation("abl_a");
        runner.InjectReadbackFailureOnce(lun, start, count);

        // Before the matching acknowledgement the armed fault must stay inert.
        string beforePath = Path.Combine(caseDirectory, "abl-before.bin");
        await client.ReadAsync(lun, start, count, beforePath);
        Assert.Equal(ReadFile(device.DirectSourceFiles["abl_a"].Path), ReadFile(beforePath));

        await SendWriteAsync(runner, lun, start, device.DirectSourceFiles["abl_a"].Path);
        Assert.Equal(1, runner.Writes.Count);

        string afterPath = Path.Combine(caseDirectory, "abl-after.bin");
        Exception? failure = await Record.ExceptionAsync(() => client.ReadAsync(lun, start, count, afterPath));
        Assert.NotNull(failure);
        Assert.True(IsOrWrapsIOException(failure!), "the injected read fault must surface as an IOException");
        Assert.False(File.Exists(afterPath));

        // Fires once only: the next identical read succeeds from the overlay.
        string recoveredPath = Path.Combine(caseDirectory, "abl-recovered.bin");
        await client.ReadAsync(lun, start, count, recoveredPath);
        Assert.Equal(ReadFile(beforePath), ReadFile(recoveredPath));

        (int otherLun, long otherStart, long otherCount, _) = device.Expectation("abl_b");
        string otherPath = Path.Combine(caseDirectory, "abl-b.bin");
        await client.ReadAsync(otherLun, otherStart, otherCount, otherPath);
        Assert.Equal(ReadFile(device.DirectSourceFiles["abl_b"].Path), ReadFile(otherPath));

        // The real client reset carries its global flags, so only the fixed `--mode Reset --delay 1` prefix is
        // checked; the trailing --vid/--pid/--memory/--loglevel options must be tolerated.
        EdlResetEvidence reset = await client.ResetAsync();
        Assert.True(reset.CommandAccepted);
        Assert.Equal(1, runner.ResetCount);
        Assert.Equal(1, runner.Commands.Count(command => command.Arguments.ToArray()[0] == "reset"));

        string[] resetArguments = runner.Commands[runner.Commands.Count - 1].Arguments.ToArray();
        Assert.Equal("reset", resetArguments[0]);
        Assert.Contains("--vid", resetArguments);
        Assert.Contains("--pid", resetArguments);

        await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunCommandAsync(
            new[] { "reset", "--mode", "Reset", "--delay", "2" }, CancellationToken.None));
        Assert.Equal(1, runner.ResetCount);
        Assert.Equal(3, runner.WriteOrResetCount);
    }

    [Fact]
    public void Direct_fixture_adds_only_efisp_on_lun4_and_gen5_drops_the_four_g4_only_names()
    {
        string caseName =
            nameof(Direct_fixture_adds_only_efisp_on_lun4_and_gen5_drops_the_four_g4_only_names);
        string inputs = _fixture.NewCaseDirectory(caseName + "-inputs");
        string backing = _fixture.NewCaseDirectory(caseName);
        Dictionary<string, VerifiedEdlFile> avb = CreateAvbSources(inputs);
        VerifiedEdlFile efisp = WriteSyntheticSource(inputs, "efisp", 5001, 0x77);
        byte[] original = ReadFile(efisp.Path);

        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(
            backing, _sources.Sources(), avb, efisp, gen5: true);

        Assert.True(device.IsDirect);

        // Exactly ten base + six AVB + one efisp claims: the efisp input widens nothing else.
        Assert.Equal(17, device.DirectSourceFiles.Count);

        VerifiedEdlFile copy = device.DirectSourceFiles["efisp"];
        string copyPath = Path.GetFullPath(copy.Path);
        Assert.NotEqual(Path.GetFullPath(efisp.Path), copyPath, StringComparer.OrdinalIgnoreCase);
        Assert.True(copyPath.StartsWith(Path.GetFullPath(backing), StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(copyPath), "the owned efisp copy is missing: " + copyPath);
        Assert.Equal(PaddedBytes(efisp.Length), copy.Length);
        Assert.Equal(8192L, copy.Length);
        Assert.Equal(0L, copy.Length % IB001SyntheticDevice.SectorSize);
        Assert.Equal(copy.Length, new FileInfo(copyPath).Length);
        Assert.Equal(copy.Sha256, HashFile(copyPath), StringComparer.OrdinalIgnoreCase);

        byte[] written = ReadFile(copyPath);
        Assert.Equal(original, written.Take(original.Length).ToArray());
        Assert.True(
            written.Skip(original.Length).All(value => value == 0),
            "the efisp copy tail must be zero padding");

        // LUN4 carries one unique efisp label at the measured two-sector extent.
        IReadOnlyList<GptPartitionSpec> lun4 = device.Specs(4);
        GptPartitionSpec efispSpec = lun4.Single(partition => partition.Name == "efisp");
        Assert.Equal(2L, efispSpec.SectorCount);
        Assert.Equal(IB001SyntheticDevice.Lun4Roles.Length + 1, lun4.Count);

        // efisp never lands on any other LUN.
        for (int lun = 0; lun < 6; lun++)
        {
            Assert.Equal(lun == 4 ? 1 : 0, device.Specs(lun).Count(partition => partition.Name == "efisp"));
        }

        // Gen5 removes exactly the four G4-only LUN0 labels and keeps every other role in place.
        string[] g4Only = { "proinfo", "lenovolock", "lenovocust", "lenovoraw" };
        IReadOnlyList<GptPartitionSpec> lun0 = device.Specs(0);
        Assert.Equal(10, lun0.Count);
        foreach (string role in g4Only)
        {
            Assert.False(lun0.Any(partition => partition.Name == role), "Gen5 must not place '" + role + "'.");
        }

        foreach (string role in IB001SyntheticDevice.Lun0Roles.Except(g4Only, StringComparer.Ordinal))
        {
            Assert.True(lun0.Any(partition => partition.Name == role), "Gen5 must keep '" + role + "'.");
        }
    }

    [Fact]
    public void Direct_fixture_rejects_a_stale_efisp_hash_before_it_owns_a_copy()
    {
        string caseName = nameof(Direct_fixture_rejects_a_stale_efisp_hash_before_it_owns_a_copy);
        string inputs = _fixture.NewCaseDirectory(caseName + "-inputs");
        string backing = _fixture.NewCaseDirectory(caseName);
        Dictionary<string, VerifiedEdlFile> sources = _sources.Sources()
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        Dictionary<string, VerifiedEdlFile> avb = CreateAvbSources(inputs);
        VerifiedEdlFile efisp = WriteSyntheticSource(inputs, "efisp", 5001, 0x77);
        Dictionary<string, string> originals = sources.Values
            .Concat(avb.Values)
            .Append(efisp)
            .ToDictionary(
                claim => claim.Path, claim => HashFile(claim.Path), StringComparer.OrdinalIgnoreCase);

        VerifiedEdlFile stale = new(efisp.Path, efisp.Length, new string('0', 64));

        Assert.Throws<InvalidDataException>(
            () => IB001SyntheticDevice.CreateDirect(backing, sources, avb, stale, gen5: true));

        // The claim is rejected before the owned child directory exists, and no input was rewritten.
        Assert.Empty(Directory.GetDirectories(backing));
        Assert.Empty(Directory.GetFiles(backing));

        foreach (KeyValuePair<string, string> original in originals)
        {
            Assert.Equal(original.Value, HashFile(original.Key), StringComparer.OrdinalIgnoreCase);
        }
    }

    private static Task<ProcessResult> SendWriteAsync(
        IB001FakeEdlRunner runner,
        int lun,
        long startSector,
        string path) =>
        runner.RunCommandAsync(
            new[]
            {
                "write-sector",
                startSector.ToString(CultureInfo.InvariantCulture),
                path,
                "--lun",
                lun.ToString(CultureInfo.InvariantCulture),
            },
            CancellationToken.None);

    private static string WriteSectorFile(string directory, string name, int sectorCount, byte value)
    {
        string path = Path.Combine(directory, name);
        byte[] buffer = new byte[IB001SyntheticDevice.SectorSize];
        Array.Fill(buffer, value);

        using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        for (int index = 0; index < sectorCount; index++)
        {
            stream.Write(buffer, 0, buffer.Length);
        }

        return path;
    }

    /// <summary>
    /// Deterministic small filler files for the six optional AVB slots. The bytes deliberately are NOT a valid
    /// AVB/RSA chain - they only exercise file backing, padding and extents; no graph is ever built here.
    /// </summary>
    private static Dictionary<string, VerifiedEdlFile> CreateAvbSources(string directory) =>
        new(StringComparer.Ordinal)
        {
            ["recovery_a"] = WriteSyntheticSource(directory, "recovery_a", 5000, 0x11),
            ["recovery_b"] = WriteSyntheticSource(directory, "recovery_b", 4096, 0x22),
            ["vbmeta_system_a"] = WriteSyntheticSource(directory, "vbmeta_system_a", 8193, 0x33),
            ["vbmeta_system_b"] = WriteSyntheticSource(directory, "vbmeta_system_b", 9000, 0x44),
            ["vbmeta_a"] = WriteSyntheticSource(directory, "vbmeta_a", 3000, 0x55),
            ["vbmeta_b"] = WriteSyntheticSource(directory, "vbmeta_b", 4097, 0x66),
        };

    private static VerifiedEdlFile WriteSyntheticSource(string directory, string role, int length, byte seed)
    {
        string path = Path.Combine(directory, role + ".img");
        byte[] bytes = new byte[length];
        for (int index = 0; index < length; index++)
        {
            bytes[index] = (byte)((seed + index * 13) % 251);
        }

        File.WriteAllBytes(path, bytes);
        return new VerifiedEdlFile(path, length, Convert.ToHexString(SHA256.HashData(bytes)));
    }

    private static byte[] PaddedCopy(byte[] bytes)
    {
        byte[] padded = new byte[checked((int)PaddedBytes(bytes.Length))];
        Buffer.BlockCopy(bytes, 0, padded, 0, bytes.Length);
        return padded;
    }

    private static bool IsOrWrapsIOException(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is IOException)
            {
                return true;
            }
        }

        return false;
    }

    private EdlClient NewClient(IB001FakeEdlRunner runner) => new(
        _fixture.Toolchain,
        new EdlEntryResult(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity("SN0123456789", _fixture.Toolchain.Model, BootloaderState.Unknown)
                {
                    Firmware = new FirmwareSnapshot(
                        _fixture.Toolchain.AndroidBuild,
                        BuildFingerprint: null,
                        AndroidRelease: null,
                        SecurityPatch: null,
                        AndroidReportedBootloaderState: BootloaderState.Unknown),
                },
                E003EdlTestData.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex),
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private static long PaddedBytes(long bytes) =>
        bytes % IB001SyntheticDevice.SectorSize == 0
            ? bytes
            : bytes + (IB001SyntheticDevice.SectorSize - bytes % IB001SyntheticDevice.SectorSize);

    private static string HashFile(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static byte[] ReadFile(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using MemoryStream buffer = new();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static byte[] ReadRange(string path, long offset, int count)
    {
        byte[] buffer = new byte[count];
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
        stream.Position = offset;
        int read = 0;
        while (read < count)
        {
            int chunk = stream.Read(buffer, read, count - read);
            if (chunk == 0)
            {
                throw new InvalidDataException("unexpected end of the direct source while reading a range");
            }

            read += chunk;
        }

        return buffer;
    }
}
