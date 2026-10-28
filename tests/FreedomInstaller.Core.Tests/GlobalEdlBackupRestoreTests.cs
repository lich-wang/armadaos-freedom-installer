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

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// GLOBAL-TESTS-01. Behavioural coverage for the production global backup/restore workflow. The only fake is the
/// process boundary (scripted EDL CLI) and endpoint discovery; the real EdlClient, GlobalEdlBackup and
/// GlobalEdlRestore run against a synthetic, in-memory six-LUN device.
/// </summary>
public sealed class GlobalEdlBackupRestoreTests :
    IClassFixture<EdlClientToolchainFixture>,
    IClassFixture<Gen5EdlToolchainFixture>
{
    private static readonly string DefaultBus = E003EdlTestData.BusSerialHex;
    private const string OtherBus = "1234ABCD";
    private readonly EdlClientToolchainFixture _g4;
    private readonly Gen5EdlToolchainFixture _g5;

    public GlobalEdlBackupRestoreTests(EdlClientToolchainFixture g4, Gen5EdlToolchainFixture g5)
    {
        _g4 = g4;
        _g5 = g5;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BackupOpenRestore_roundtrip_preserves_userdata_and_verifies_every_nondata_partition(bool gen5)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5);
        (GlobalEdlTestRunner backupRunner, _, EdlClient backupClient) = NewClient(device, gen5);
        Dictionary<string, byte[]> baseline = SnapshotPartitions(device);
        Dictionary<int, byte[]> gptBaseline = SnapshotGpt(device);
        HashSet<string> expected = NonUserdataNames(device);
        GptPartitionSpec userdata = device.Partition("userdata");
        string backupParent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(backupParent);
        using var set = await GlobalEdlBackup.CreateAsync(backupClient, backupParent);
        Assert.NotNull(set);
        Assert.Empty(backupRunner.Writes);
        Assert.Equal(0, backupRunner.ResetCount);
        Assert.Equal(device.ExpectedPartitionCount, set.PartitionCount);
        Assert.True(set.RawBytes > 0);
        Assert.True(set.RawBytes > set.CompressedBytes, "the deterministic filler must compress");

        string dir = set.DirectoryPath, manifestPath = set.ManifestPath, identity = set.Identity.ToString()!;
        long rawBytes = set.RawBytes, compressedBytes = set.CompressedBytes;
        int partitionCount = set.PartitionCount;
        JsonObject manifest = ReadManifest(manifestPath);
        Assert.Equal(2, manifest["schemaVersion"]!.GetValue<int>());
        HashSet<string> names = RegionNames(manifest);
        Assert.Equal(
            expected.OrderBy(n => n, StringComparer.Ordinal).ToArray(),
            names.OrderBy(n => n, StringComparer.Ordinal).ToArray());
        AssertExcludedAbsentFromManifest(manifest);
        AssertExcludedPayloadsNotRead(backupRunner, device);
        foreach (string required in new[] { "super", "modem", "extra_lun1", "boot_b", "abl_b", "efisp" })
        {
            Assert.Contains(required, names);
        }

        foreach (GlobalEdlTestIo read in backupRunner.Reads)
        {
            Assert.False(
                read.Lun == 0 && Overlaps(read.StartSector, read.SectorCount, userdata.StartSector, userdata.SectorCount),
                "backup reads (including GPT reads) must never touch userdata");
        }

        foreach (GptPartitionSpec spec in NonUserdataSpecs(device))
        {
            Assert.True(
                Covered(backupRunner.Reads, device.LunOf(spec.Name), spec.StartSector, spec.SectorCount),
                "backup read coverage is missing for " + spec.Name);
        }
        AssertCompleteBackup(dir, manifest);
        set.Dispose();
        using var reopened = await GlobalEdlBackup.OpenAsync(dir);
        Assert.Equal(identity, reopened.Identity.ToString());
        Assert.Equal(rawBytes, reopened.RawBytes);
        Assert.Equal(compressedBytes, reopened.CompressedBytes); Assert.Equal(partitionCount, reopened.PartitionCount);

        device.CorruptAllNonUserdata();
        (GlobalEdlTestRunner restoreRunner, _, EdlClient restoreClient) = NewClient(device, gen5);
        string restoreParent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(restoreParent);
        using var plan = await GlobalEdlRestore.PrepareAsync(restoreClient, reopened, restoreParent);
        Assert.Equal(identity, plan.Identity.ToString());
        Assert.Equal(userdata.SectorCount * (long)GlobalEdlTestDevice.SectorSize, plan.AndroidBytes);
        Assert.True(plan.RegionCount >= expected.Count + 12);
        Assert.True(plan.WriteBytes >= expected.Sum(n => device.Partition(n).SectorCount * (long)GlobalEdlTestDevice.SectorSize));
        Assert.False(string.IsNullOrWhiteSpace(plan.ConfirmationId));
        Assert.True(Directory.Exists(plan.EvidenceDirectory));

        GlobalEdlRestoreResult result = await GlobalEdlRestore.ExecuteAsync(plan, plan.ConfirmationId);
        Assert.True(result.Success, result.Error);
        Assert.True(result.AnyWriteStarted);
        Assert.NotEmpty(result.VerifiedRegions);
        Assert.Equal(0, restoreRunner.ResetCount);
        foreach (GptPartitionSpec spec in NonUserdataSpecs(device).Where(s => s.Name != "misc"))
        {
            Assert.Equal(baseline[spec.Name], device.SnapshotPartition(spec.Name));
        }

        byte[] misc = device.SnapshotPartition("misc");
        string bcb = Encoding.ASCII.GetString(misc, 0, 32);
        int terminator = bcb.IndexOf('\0');
        Assert.True(terminator > 0, "the BCB command must be NUL terminated");
        Assert.Equal("boot-recovery", bcb[..terminator]);
        Assert.StartsWith("recovery\n--wipe_data\n", Encoding.ASCII.GetString(misc, 64, 768));
        Assert.Equal(baseline["misc"][4096..], misc[4096..]);
        Assert.Equal(baseline["userdata"], device.SnapshotPartition("userdata"));
        Assert.Equal(baseline["rawdump"], device.SnapshotPartition("rawdump"));
        Assert.Equal(baseline["metadata"], device.SnapshotPartition("metadata"));
        AssertGptEquals(device, gptBaseline);
        AssertRestoreWriteDiscipline(restoreRunner, device, userdata, expected);
        AssertExcludedPayloadsNotWritten(restoreRunner, device);
    }

    [Theory]
    [InlineData("ARMADA_ROOT")]
    [InlineData("ARMADA_BOOT")]
    [InlineData("ARMADA_RECOVERY")]
    [InlineData("ROCKNIX")]
    [InlineData("linux")]
    [InlineData("rootfs")]
    [InlineData("swap")]
    public async Task Linux_layout_rejects_before_any_partition_payload_read(string linuxName)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false, linuxName: linuxName);
        (GlobalEdlTestRunner runner, _, EdlClient client) = NewClient(device, gen5: false);
        string parent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(parent);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.CreateAsync(client, parent));
        AssertOnlyGptReads(runner, device);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        foreach (string manifestFile in Directory.GetFiles(caseDir, "manifest.json", SearchOption.AllDirectories))
        {
            JsonObject partial = ReadManifest(manifestFile);
            string? state = partial["state"]?.GetValue<string>();
            Assert.False(
                string.Equals(state, "complete", StringComparison.OrdinalIgnoreCase),
                "a rejected backup must not leave a complete manifest");
        }
    }

    [Fact]
    public async Task Linux_root_type_only_partition_rejects_before_any_partition_payload_read()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false, linuxTypeOnly: true);
        (GlobalEdlTestRunner runner, _, EdlClient client) = NewClient(device, gen5: false);
        string parent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(parent);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.CreateAsync(client, parent));
        AssertOnlyGptReads(runner, device);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        foreach (string manifestFile in Directory.GetFiles(caseDir, "manifest.json", SearchOption.AllDirectories))
        {
            JsonObject partial = ReadManifest(manifestFile);
            string? state = partial["state"]?.GetValue<string>();
            Assert.False(
                string.Equals(state, "complete", StringComparison.OrdinalIgnoreCase),
                "a rejected backup must not leave a complete manifest");
        }
    }

    [Fact]
    public async Task Open_rejects_corrupted_gzip()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject chunk = Chunks(PayloadRegion(ReadManifest(manifestPath), "boot_a")).First();
        string path = Path.Combine(dir, chunk["fileName"]!.GetValue<string>());
        byte[] compressed = File.ReadAllBytes(path);
        compressed[compressed.Length / 2] ^= 0xFF;
        File.WriteAllBytes(path, compressed);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Open_rejects_missing_nonuserdata_partition_even_when_totals_are_recomputed()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject manifest = ReadManifest(manifestPath);
        JsonArray regions = manifest["regions"]!.AsArray();
        JsonObject removed = Regions(manifest).Single(r => r["partitionName"]?.GetValue<string>() == "super");
        Assert.True(regions.Remove(removed));
        SaveManifest(dir, manifestPath, manifest);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Open_rejects_missing_final_chunk()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false, multiChunkSuper: true);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject manifest = ReadManifest(manifestPath);
        JsonArray chunks = PayloadRegion(manifest, "super")["chunks"]!.AsArray();
        Assert.True(chunks.Count >= 2, "the 64 MiB + 4096 B super must be stored in more than one chunk");
        chunks.RemoveAt(chunks.Count - 1);
        SaveManifest(dir, manifestPath, manifest);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Open_rejects_path_traversal_even_when_manifest_is_rehashed()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject manifest = ReadManifest(manifestPath);
        JsonObject chunk = Chunks(PayloadRegion(manifest, "boot_a")).First();
        string outside = Path.Combine(Path.GetDirectoryName(dir)!, "outside.gz");
        File.Copy(Path.Combine(dir, chunk["fileName"]!.GetValue<string>()), outside, overwrite: true);
        chunk["fileName"] = "../outside.gz";
        SaveManifest(dir, manifestPath, manifest);
        Assert.True(File.Exists(outside), "the traversal target must exist so only path validation can reject it");
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Open_rejects_userdata_region_claim()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject manifest = ReadManifest(manifestPath);
        JsonObject region = PayloadRegion(manifest, "boot_a");
        GptPartitionSpec userdata = device.Partition("userdata");
        region["partitionName"] = "userdata";
        region["startSector"] = userdata.StartSector;
        region["sectorCount"] = userdata.SectorCount;
        region["partUuid"] = userdata.PartUuid;
        SaveManifest(dir, manifestPath, manifest);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Open_accepts_legacy_schema1_with_metadata_rawdump_and_rejects_as_schema2()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);

        JsonObject manifest = ReadManifest(manifestPath);
        JsonArray regions = manifest["regions"]!.AsArray();

        foreach (string legacy in new[] { "metadata", "rawdump" })
        {
            GptPartitionSpec spec = device.Partition(legacy);
            int lun = device.LunOf(legacy);
            int partitionNumber = spec.Number;
            byte[] raw = device.SnapshotPartition(legacy);
            byte[] compressed;
            using (var buffer = new MemoryStream())
            {
                using (var gzip = new GZipStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }

                compressed = buffer.ToArray();
            }

            string fileName = "legacy-" + legacy + ".gz";
            File.WriteAllBytes(Path.Combine(dir, fileName), compressed);
            regions.Add(new JsonObject
            {
                ["role"] = "lun" + lun + "_part" + partitionNumber,
                ["kind"] = "partition",
                ["lun"] = lun,
                ["startSector"] = spec.StartSector,
                ["sectorCount"] = spec.SectorCount,
                ["sectorSize"] = GlobalEdlTestDevice.SectorSize,
                ["partitionNumber"] = partitionNumber,
                ["partitionName"] = legacy,
                ["partUuid"] = spec.PartUuid,
                ["chunks"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["fileName"] = fileName,
                        ["offsetBytes"] = 0L,
                        ["rawBytes"] = raw.LongLength,
                        ["rawSha256"] = Sha256Hex(raw),
                        ["compressedBytes"] = compressed.LongLength,
                        ["compressedSha256"] = Sha256Hex(compressed),
                    },
                },
            });
        }

        manifest["schemaVersion"] = 1;
        SaveManifest(dir, manifestPath, manifest);
        Assert.Equal(1, ReadManifest(manifestPath)["schemaVersion"]!.GetValue<int>());
        using (GlobalEdlBackupSet legacyOpened = await GlobalEdlBackup.OpenAsync(dir))
        {
            Assert.Equal(device.ExpectedPartitionCount + 2, legacyOpened.PartitionCount);
        }

        JsonObject upgraded = ReadManifest(manifestPath);
        upgraded["schemaVersion"] = 2;
        SaveManifest(dir, manifestPath, upgraded);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    [Fact]
    public async Task Restore_wrong_bus_refuses_before_writes()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        (GlobalEdlTestRunner runner, _, EdlClient wrongBus) = NewClient(device, false, OtherBus);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        await ThrowsRealAsync<Exception>(() => GlobalEdlRestore.PrepareAsync(wrongBus, set, parent));
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Restore_wrong_geometry_refuses_before_writes()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        (GlobalEdlTestRunner runner, _, EdlClient wrongGeometry) = NewClient(
            device, gen5: false,
            tune: r => r.GeometryOverride = lun => lun == 0 ? device.TotalSectors(0) + 1 : null);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        await ThrowsRealAsync<Exception>(() => GlobalEdlRestore.PrepareAsync(wrongGeometry, set, parent));
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Restore_ack_without_matching_readback_is_failure()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        device.CorruptAllNonUserdata();
        (GlobalEdlTestRunner runner, _, EdlClient restoreClient) = NewClient(
            device, gen5: false, tune: r => r.IgnoreWrites = true);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        using var plan = await GlobalEdlRestore.PrepareAsync(restoreClient, set, parent);
        GlobalEdlRestoreResult result = await GlobalEdlRestore.ExecuteAsync(plan, plan.ConfirmationId);
        Assert.False(result.Success); Assert.True(result.AnyWriteStarted);
        Assert.Empty(result.VerifiedRegions);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.True(Directory.Exists(result.EvidenceDirectory));
        Assert.NotEmpty(Directory.GetFiles(result.EvidenceDirectory, "*", SearchOption.AllDirectories)
            .Where(f => new FileInfo(f).Length > 0));
        JsonObject journal = ReadManifest(Path.Combine(result.EvidenceDirectory, "journal.json"));
        Assert.Equal("failed", journal["state"]?.GetValue<string>());
        JsonObject entry = Assert.Single(journal["entries"]!.AsArray().OfType<JsonObject>());
        Assert.Equal("acknowledged", entry["phase"]?.GetValue<string>());
        Assert.Null(entry["readbackSha256"]);
        Assert.Single(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Restore_write_outcome_unknown_keeps_failure_evidence()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        (GlobalEdlTestRunner runner, _, EdlClient restoreClient) = NewClient(device, gen5: false);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        using var plan = await GlobalEdlRestore.PrepareAsync(restoreClient, set, parent);
        runner.FailNextWrite = true;
        GlobalEdlRestoreResult result = await GlobalEdlRestore.ExecuteAsync(plan, plan.ConfirmationId);
        Assert.False(result.Success);
        Assert.True(result.AnyWriteStarted);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.True(Directory.Exists(result.EvidenceDirectory));
        Assert.NotEmpty(Directory.GetFiles(result.EvidenceDirectory, "*", SearchOption.AllDirectories));
        JsonObject journal = ReadManifest(Path.Combine(result.EvidenceDirectory, "journal.json"));
        Assert.Equal("failed", journal["state"]?.GetValue<string>());
        Assert.Contains(
            journal["entries"]!.AsArray().OfType<JsonObject>(),
            e => e["phase"]?.GetValue<string>() == "intent");
        Assert.Single(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Restore_wrong_confirmation_never_writes()
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5: false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        (GlobalEdlTestRunner runner, _, EdlClient restoreClient) = NewClient(device, gen5: false);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        using var plan = await GlobalEdlRestore.PrepareAsync(restoreClient, set, parent);
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlRestore.ExecuteAsync(plan, "WRONG-CONFIRMATION"));
        Assert.NotNull(ex);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public void Direct_binding_ambiguous_endpoint_refuses_before_commands()
    {
        (GlobalEdlTestDevice device, _) = Case(gen5: false);
        EdlDeviceProfile profile = Toolset(gen5: false).Profile;
        var runner = new GlobalEdlTestRunner(device, HardwareId(gen5: false));
        var discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[]
            {
                E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:" + DefaultBus),
                E003EdlTestData.Endpoint(
                    instanceId: E003EdlTestData.OtherInstanceId,
                    description: "QUSB_BULK_CID:045A_SN:" + DefaultBus),
            },
        };
        ThrowsReal<Exception>(() => GlobalEdlBinding.Attach(profile, discovery));
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public void Direct_binding_wrong_expected_bus_refuses()
    {
        (GlobalEdlTestDevice device, _) = Case(gen5: false);
        EdlDeviceProfile profile = Toolset(gen5: false).Profile;
        var runner = new GlobalEdlTestRunner(device, HardwareId(gen5: false));
        var discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[] { E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:" + DefaultBus) },
        };
        ThrowsReal<Exception>(() => GlobalEdlBinding.Attach(profile, discovery, expectedBusSerialHex: OtherBus));
        Assert.Empty(runner.Commands);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Direct_binding_and_raw_probe_prove_hardware_id(bool gen5)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5);
        (EdlToolchain toolchain, EdlDeviceProfile profile, string hardwareId) = Toolset(gen5);
        var runner = new GlobalEdlTestRunner(device, hardwareId);
        var discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[] { E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:" + DefaultBus) },
        };
        EdlEntryResult entry = GlobalEdlBinding.Attach(profile, discovery);
        Assert.NotNull(entry);
        Assert.Null(entry.AndroidIdentity);
        Assert.NotNull(entry.OfflineIdentity);
        var client = new EdlClient(toolchain, entry, runner, discovery);
        Assert.False(client.HasInitialSaharaProof);
        var probe = await client.ProbeRawGeometryAsync(
            0, true, Path.Combine(caseDir, "probe-sector.bin"));
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(hardwareId, probe.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(DefaultBus, probe.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Single(runner.Reads);
        Assert.Equal(1, runner.Reads[0].SectorCount);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Userdata_linux_type_is_valid_original_android_layout(bool gen5)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5, userdataLinuxType: true);
        (GlobalEdlTestRunner runner, _, EdlClient client) = NewClient(device, gen5);
        GptPartitionSpec userdata = device.Partition("userdata");
        string parent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(parent);
        using var set = await GlobalEdlBackup.CreateAsync(client, parent);
        Assert.NotNull(set);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        Assert.Equal(device.ExpectedPartitionCount, set.PartitionCount);
        Assert.Equal(device.ExpectedPartitionCount, RegionNames(ReadManifest(set.ManifestPath)).Count);
        foreach (GlobalEdlTestIo read in runner.Reads)
        {
            Assert.False(
                read.Lun == 0 && Overlaps(read.StartSector, read.SectorCount, userdata.StartSector, userdata.SectorCount),
                "userdata must never be read, even with a Linux partition type");
        }

        Assert.NotEqual(Toolset(gen5: false).Profile.ProfileId, Toolset(gen5: true).Profile.ProfileId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Restore_recovers_when_current_gpt_is_corrupted(bool gen5)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(gen5);
        (_, _, EdlClient client) = NewClient(device, gen5);
        Dictionary<int, byte[]> gptBaseline = SnapshotGpt(device);
        GptPartitionSpec userdata = device.Partition("userdata");
        (string dir, _) = await CreateDisposedAsync(client, caseDir);
        using var set = await GlobalEdlBackup.OpenAsync(dir);
        foreach (int lun in device.Disks.Keys)
        {
            byte[] disk = device.Disks[lun];
            long total = device.TotalSectors(lun);
            Array.Clear(disk, GlobalEdlTestDevice.SectorSize, GlobalEdlTestDevice.SectorSize);
            Array.Clear(disk, checked((int)((total - 1) * GlobalEdlTestDevice.SectorSize)), GlobalEdlTestDevice.SectorSize);
        }

        (GlobalEdlTestRunner runner, _, EdlClient restoreClient) = NewClient(device, gen5);
        string parent = Path.Combine(caseDir, "restore");
        Directory.CreateDirectory(parent);
        using var plan = await GlobalEdlRestore.PrepareAsync(restoreClient, set, parent);
        GlobalEdlRestoreResult result = await GlobalEdlRestore.ExecuteAsync(plan, plan.ConfirmationId);
        Assert.True(result.Success, result.Error);
        Assert.True(result.AnyWriteStarted);
        AssertGptEquals(device, gptBaseline);
        Assert.Equal(0, runner.ResetCount);
        foreach (GlobalEdlTestIo io in runner.Reads.Concat(runner.Writes))
        {
            Assert.False(io.Lun == 0 && Overlaps(io.StartSector, io.SectorCount, userdata.StartSector, userdata.SectorCount));
        }
    }
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task Create_refuses_unsafe_virtual_ab_before_system_payloads(int scenario)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(false, shortMisc: scenario == 7);
        GptPartitionSpec misc = device.Partition("misc");
        byte[] disk = device.Disks[0];
        int cob = checked((int)(misc.StartSector * GlobalEdlTestDevice.SectorSize)) + 32768;
        if (scenario is >= 1 and <= 4)
        {
            disk[cob + 5] = (byte)scenario;
        }
        else if (scenario == 5)
        {
            disk[cob] = 0;
        }
        else if (scenario == 6)
        {
            disk[cob + 1] = 0;
        }

        (GlobalEdlTestRunner runner, _, EdlClient client) = NewClient(device, gen5: false);
        string parent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(parent);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.CreateAsync(client, parent));
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        foreach (GlobalEdlTestIo read in runner.Reads)
        {
            foreach (GptPartitionSpec spec in device.Partitions[read.Lun].Where(s => s.Name != "misc"))
            {
                Assert.False(
                    Overlaps(read.StartSector, read.SectorCount, spec.StartSector, spec.SectorCount),
                    "unsafe Virtual A/B must be rejected before any system payload read");
            }
        }

        foreach (string manifestFile in Directory.GetFiles(caseDir, "manifest.json", SearchOption.AllDirectories))
        {
            JsonObject partial = ReadManifest(manifestFile);
            string? state = partial["state"]?.GetValue<string>();
            Assert.False(
                string.Equals(state, "complete", StringComparison.OrdinalIgnoreCase),
                "a rejected backup must not leave a complete manifest");
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Open_refuses_unsafe_virtual_ab_even_with_valid_hashes(int status)
    {
        (GlobalEdlTestDevice device, string caseDir) = Case(false);
        (_, _, EdlClient client) = NewClient(device, gen5: false);
        (string dir, string manifestPath) = await CreateDisposedAsync(client, caseDir);
        JsonObject manifest = ReadManifest(manifestPath);
        JsonObject chunk = Chunks(PayloadRegion(manifest, "misc")).Single();
        string path = Path.Combine(dir, chunk["fileName"]!.GetValue<string>());
        byte[] plain;
        using (var gzip = new GZipStream(new MemoryStream(File.ReadAllBytes(path)), CompressionMode.Decompress))
        using (var raw = new MemoryStream())
        {
            gzip.CopyTo(raw);
            plain = raw.ToArray();
        }

        plain[32768 + 5] = (byte)status;
        byte[] compressed;
        using (var buffer = new MemoryStream())
        {
            using (var gzip = new GZipStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
            {
                gzip.Write(plain, 0, plain.Length);
            }

            compressed = buffer.ToArray();
        }

        File.WriteAllBytes(path, compressed);
        chunk["rawBytes"] = plain.LongLength;
        chunk["rawSha256"] = Sha256Hex(plain);
        chunk["compressedBytes"] = compressed.LongLength;
        chunk["compressedSha256"] = Sha256Hex(compressed);
        SaveManifest(dir, manifestPath, manifest);
        AssertCompleteBackup(dir, manifest);
        await ThrowsRealAsync<Exception>(() => GlobalEdlBackup.OpenAsync(dir));
    }

    // helpers ---------------------------------------------------------

    private (GlobalEdlTestDevice Device, string CaseDir) Case(
        bool gen5, string? linuxName = null, bool linuxTypeOnly = false,
        bool multiChunkSuper = false, bool userdataLinuxType = false, bool shortMisc = false)
    {
        var device = new GlobalEdlTestDevice(
            gen5: gen5, linuxName: linuxName, linuxTypeOnly: linuxTypeOnly,
            multiChunkSuper: multiChunkSuper, userdataLinuxType: userdataLinuxType, shortMisc: shortMisc);
        return (device, NewCaseDir(gen5));
    }

    private (EdlToolchain Toolchain, EdlDeviceProfile Profile, string HardwareId) Toolset(bool gen5)
    {
        EdlToolchain toolchain = gen5 ? _g5.Toolchain : _g4.Toolchain;
        EdlDeviceProfile profile = EdlDeviceProfiles.FindById(toolchain.ProfileId)
            ?? throw new InvalidOperationException("fixture profile missing");
        return (toolchain, profile, toolchain.HardwareId);
    }

    private string NewCaseDir(bool gen5) =>
        gen5 ? _g5.NewCaseDirectory("global-backup-restore") : _g4.NewCaseDirectory("global-backup-restore");

    private string HardwareId(bool gen5) => Toolset(gen5).HardwareId;

    private (GlobalEdlTestRunner Runner, E003ScriptedEndpointDiscovery Discovery, EdlClient Client) NewClient(
        GlobalEdlTestDevice device, bool gen5, string? bus = null, Action<GlobalEdlTestRunner>? tune = null)
    {
        (EdlToolchain toolchain, EdlDeviceProfile profile, string hardwareId) = Toolset(gen5);
        string effectiveBus = bus ?? DefaultBus;
        var runner = new GlobalEdlTestRunner(device, hardwareId, effectiveBus);
        tune?.Invoke(runner);
        var discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[] { E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:" + effectiveBus) },
        };
        EdlEntryResult binding = GlobalEdlBinding.Attach(profile, discovery);
        return (runner, discovery, new EdlClient(toolchain, binding, runner, discovery));
    }

    private static async Task<(string Directory, string ManifestPath)> CreateDisposedAsync(EdlClient client, string caseDir)
    {
        string parent = Path.Combine(caseDir, "backup");
        Directory.CreateDirectory(parent);
        GlobalEdlBackupSet set = await GlobalEdlBackup.CreateAsync(client, parent);
        Assert.NotNull(set);
        (string dir, string manifestPath) = (set.DirectoryPath, set.ManifestPath);
        set.Dispose();
        return (dir, manifestPath);
    }

    private static Dictionary<string, byte[]> SnapshotPartitions(GlobalEdlTestDevice device)
    {
        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (GptPartitionSpec spec in device.Partitions.Values.SelectMany(s => s))
        {
            map[spec.Name] = device.SnapshotPartition(spec.Name);
        }

        return map;
    }

    private static Dictionary<int, byte[]> SnapshotGpt(GlobalEdlTestDevice device)
    {
        var map = new Dictionary<int, byte[]>();
        foreach (int lun in device.Disks.Keys)
        {
            long total = device.TotalSectors(lun);
            var window = new byte[5 * GlobalEdlTestDevice.SectorSize];
            Array.Copy(device.Disks[lun], 0, window, 0, 3 * GlobalEdlTestDevice.SectorSize);
            Array.Copy(device.Disks[lun], (total - 2) * GlobalEdlTestDevice.SectorSize, window,
                3 * GlobalEdlTestDevice.SectorSize, 2 * GlobalEdlTestDevice.SectorSize);
            map[lun] = window;
        }

        return map;
    }

    private static void AssertGptEquals(GlobalEdlTestDevice device, Dictionary<int, byte[]> baseline)
    {
        foreach (int lun in baseline.Keys)
        {
            long total = device.TotalSectors(lun);
            byte[] disk = device.Disks[lun];
            byte[] expected = baseline[lun];
            Assert.Equal(expected[..(3 * GlobalEdlTestDevice.SectorSize)], disk[..(3 * GlobalEdlTestDevice.SectorSize)]);
            Assert.Equal(expected[(3 * GlobalEdlTestDevice.SectorSize)..],
                disk[checked((int)((total - 2) * GlobalEdlTestDevice.SectorSize))..]);
        }
    }

    private static IEnumerable<GptPartitionSpec> NonUserdataSpecs(GlobalEdlTestDevice device) =>
        device.Partitions.Values.SelectMany(s => s).Where(s => !GlobalEdlTestDevice.IsExcludedName(s.Name));

    private static HashSet<string> NonUserdataNames(GlobalEdlTestDevice device) =>
        NonUserdataSpecs(device).Select(s => s.Name).ToHashSet(StringComparer.Ordinal);

    private static void AssertExcludedAbsentFromManifest(JsonObject manifest)
    {
        foreach (JsonObject region in Regions(manifest))
        {
            string? name = region["partitionName"]?.GetValue<string>();
            if (name is null)
            {
                continue;
            }

            Assert.False(
                GlobalEdlTestDevice.IsExcludedName(name),
                "excluded payload must not appear in the manifest: " + name);
        }
    }

    private static void AssertExcludedPayloadsNotRead(GlobalEdlTestRunner backupRunner, GlobalEdlTestDevice device)
    {
        foreach (GptPartitionSpec spec in device.Partitions.Values.SelectMany(s => s))
        {
            if (!GlobalEdlTestDevice.IsExcludedName(spec.Name))
            {
                continue;
            }

            int lun = device.LunOf(spec.Name);
            foreach (GlobalEdlTestIo read in backupRunner.Reads)
            {
                Assert.False(
                    read.Lun == lun && Overlaps(read.StartSector, read.SectorCount, spec.StartSector, spec.SectorCount),
                    "backup read must not touch excluded payload '" + spec.Name + "'");
            }
        }
    }

    private static bool Overlaps(long start, long count, long otherStart, long otherCount) =>
        start < otherStart + otherCount && otherStart < start + count;

    private static bool Covered(IReadOnlyList<GlobalEdlTestIo> reads, int lun, long start, long count)
    {
        long end = start + count, cursor = start;
        foreach (GlobalEdlTestIo read in reads.Where(r => r.Lun == lun).OrderBy(r => r.StartSector))
        {
            if (read.StartSector + read.SectorCount <= cursor) continue;
            if (read.StartSector > cursor) return false;
            cursor = Math.Max(cursor, read.StartSector + read.SectorCount);
            if (cursor >= end) return true;
        }

        return cursor >= end;
    }

    private static void AssertExcludedPayloadsNotWritten(GlobalEdlTestRunner restoreRunner, GlobalEdlTestDevice device)
    {
        foreach (GptPartitionSpec spec in device.Partitions.Values.SelectMany(s => s))
        {
            if (!GlobalEdlTestDevice.IsExcludedName(spec.Name))
            {
                continue;
            }

            int lun = device.LunOf(spec.Name);
            foreach (GlobalEdlTestIo write in restoreRunner.Writes)
            {
                Assert.False(
                    write.Lun == lun && Overlaps(write.StartSector, write.SectorCount, spec.StartSector, spec.SectorCount),
                    "restore write must not touch excluded payload '" + spec.Name + "'");
            }
        }
    }

    private static void AssertOnlyGptReads(GlobalEdlTestRunner runner, GlobalEdlTestDevice device)
    {
        foreach (GlobalEdlTestIo read in runner.Reads)
        foreach (GptPartitionSpec spec in device.Partitions[read.Lun])
        {
            Assert.False(
                Overlaps(read.StartSector, read.SectorCount, spec.StartSector, spec.SectorCount),
                "a rejecting create must read only GPT windows, never partition payloads");
        }
    }

    private static void AssertRestoreWriteDiscipline(
        GlobalEdlTestRunner runner, GlobalEdlTestDevice device, GptPartitionSpec userdata, HashSet<string> expected)
    {
        foreach (GlobalEdlTestIo write in runner.Writes)
        {
            Assert.False(
                write.Lun == 0 && Overlaps(write.StartSector, write.SectorCount, userdata.StartSector, userdata.SectorCount),
                "restore must never write userdata");
        }

        foreach (string name in expected)
        {
            GptPartitionSpec spec = device.Partition(name);
            Assert.True(
                runner.Writes.Any(w => w.Lun == device.LunOf(name)
                    && Overlaps(w.StartSector, w.SectorCount, spec.StartSector, spec.SectorCount)),
                "restore wrote no payload for " + name);
        }

        GptPartitionSpec misc = device.Partition("misc");
        foreach (int lun in device.Disks.Keys)
        {
            long total = device.TotalSectors(lun);
            int backup = runner.Writes.FindIndex(w => w.Lun == lun && Overlaps(w.StartSector, w.SectorCount, total - 2, 2));
            int primary = runner.Writes.FindIndex(w => w.Lun == lun && Overlaps(w.StartSector, w.SectorCount, 0, 3));
            Assert.True(backup >= 0, "the backup GPT must be rewritten on LUN " + lun);
            Assert.True(primary >= 0, "the primary GPT must be rewritten on LUN " + lun);
            Assert.True(backup < primary, "the backup GPT write must precede the primary on LUN " + lun);
            int lastPayload = runner.Writes.FindLastIndex(w => w.Lun == lun
                && !Overlaps(w.StartSector, w.SectorCount, total - 2, 2)
                && !Overlaps(w.StartSector, w.SectorCount, 0, 3)
                && !(w.Lun == 0 && w.StartSector == misc.StartSector && w.SectorCount == 1));
            Assert.True(lastPayload < primary && lastPayload < backup, "GPT writes must follow payload writes on LUN " + lun);
        }

        GlobalEdlTestIo final = runner.Writes[^1];
        Assert.Equal(0, final.Lun);
        Assert.Equal(misc.StartSector, final.StartSector);
        Assert.Equal(1, final.SectorCount);
    }

    private static JsonObject ReadManifest(string path) => JsonNode.Parse(File.ReadAllText(path))!.AsObject();

    private static IEnumerable<JsonObject> Regions(JsonObject manifest) =>
        manifest["regions"]!.AsArray().OfType<JsonObject>();

    private static IEnumerable<JsonObject> Chunks(JsonObject region) =>
        region["chunks"]!.AsArray().OfType<JsonObject>();

    private static HashSet<string> RegionNames(JsonObject manifest) =>
        Regions(manifest).Select(r => r["partitionName"]?.GetValue<string>())
            .Where(n => n is not null).Select(n => n!).ToHashSet(StringComparer.Ordinal);

    private static JsonObject PayloadRegion(JsonObject manifest, string name) =>
        Regions(manifest).First(r => r["partitionName"]?.GetValue<string>() == name && Chunks(r).Any());

    private static void AssertCompleteBackup(string dir, JsonObject manifest)
    {
        foreach (JsonObject chunk in Regions(manifest).SelectMany(Chunks))
        {
            string path = Path.Combine(dir, chunk["fileName"]!.GetValue<string>());
            Assert.True(File.Exists(path), "chunk file is missing: " + path);
            byte[] compressed = File.ReadAllBytes(path);
            Assert.Equal(chunk["compressedBytes"]!.GetValue<long>(), compressed.LongLength);
            Assert.Equal(chunk["compressedSha256"]!.GetValue<string>(), Sha256Hex(compressed), StringComparer.OrdinalIgnoreCase);
            using var gzip = new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress);
            using var raw = new MemoryStream();
            gzip.CopyTo(raw);
            byte[] plain = raw.ToArray();
            Assert.Equal(chunk["rawBytes"]!.GetValue<long>(), plain.LongLength);
            Assert.Equal(chunk["rawSha256"]!.GetValue<string>(), Sha256Hex(plain), StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>Recomputes aggregate totals from surviving chunks so a tamper cannot hide behind stale numbers.</summary>
    private static void RecomputeTotals(JsonObject manifest)
    {
        manifest["rawBytes"] = Regions(manifest).SelectMany(Chunks).Sum(c => c["rawBytes"]!.GetValue<long>());
        manifest["compressedBytes"] = Regions(manifest).SelectMany(Chunks).Sum(c => c["compressedBytes"]!.GetValue<long>());
    }

    private static void SaveManifest(string dir, string manifestPath, JsonObject manifest)
    {
        RecomputeTotals(manifest);
        byte[] bytes = new UTF8Encoding(false).GetBytes(manifest.ToJsonString());
        File.WriteAllBytes(manifestPath, bytes);
        File.WriteAllText(manifestPath + ".sha256", Sha256Hex(bytes));
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static async Task<T> ThrowsRealAsync<T>(Func<Task> action)
        where T : Exception
    {
        T exception = await Assert.ThrowsAnyAsync<T>(action);
        Assert.NotNull(exception);
        Assert.False(exception is NotImplementedException, "a not-implemented path must not satisfy this test");
        return exception;
    }

    private static T ThrowsReal<T>(Action action)
        where T : Exception
    {
        T exception = Assert.ThrowsAny<T>(action);
        Assert.NotNull(exception);
        Assert.False(exception is NotImplementedException, "a not-implemented path must not satisfy this test");
        return exception;
    }
}
