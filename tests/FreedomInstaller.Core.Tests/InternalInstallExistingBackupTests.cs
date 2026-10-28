using System;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// EB001 focused cases: <see cref="InternalInstallBackup.OpenExistingAsync"/> must reuse an existing, already
/// verified 52 file backup produced by the real <see cref="InternalInstallBackup.CreateAsync"/> factory, prove
/// the selected files, the saved full identity and the fresh six LUN geometry, and never take a new capture.
/// <para>
/// Every case builds its own synthetic backup below a unique fixture directory, disposes the creating set and
/// then loads it through a fresh <see cref="EdlClient"/> over a fresh binding with the same actual identity. No
/// real device, process, USB endpoint or actual 52 file backup is touched; the manager runs these tests remotely.
/// </para>
/// </summary>
public sealed class InternalInstallExistingBackupTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string ManifestFileName = "backup-manifest.json";
    private const string SidecarSuffix = ".sha256";
    private const string VerifyingStage = "verifying";
    private const string CompleteStage = "complete";
    private const int GptHeaderCrcOffset = 16;
    private const long BoardArchiveBytes = 2L * 1024 * 1024 * 1024;
    private const int CopyBufferBytes = 64 * 1024;

    // FW01: the actual firmware under test. MaintenanceProfiles.AndroidBuild stays the 259 loader profile.
    private const string Actual120AndroidBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
    private const string Actual120BuildFingerprint = "Lenovo/TB322FC/TB322FC:15/TEST/120:user/release-keys";
    private const string Actual120AndroidRelease = "15";
    private const string Actual120SecurityPatch = "2026-06-01";

    private readonly EdlClientToolchainFixture _fixture;

    public InternalInstallExistingBackupTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task FW01_OpenExisting_reuses_the_verified_backup_and_probes_only_geometry()
    {
        const string Name = nameof(FW01_OpenExisting_reuses_the_verified_backup_and_probes_only_geometry);
        string parent = _fixture.NewCaseDirectory(Name);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();

        string backupDirectory;
        string manifestSha256;
        string createdAndroidBuild;
        Dictionary<string, EdlCapturedRegion> created;
        string[] entriesBefore;

        EdlClient createClient = NewClient(new IB001FakeEdlRunner(device), NewBinding(firmware: Actual120Firmware()));
        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(createClient, parent))
        {
            backupDirectory = set.DirectoryPath;
            manifestSha256 = set.ManifestSha256;
            createdAndroidBuild = set.AndroidBuild;
            created = set.Files.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            entriesBefore = Directory.GetFileSystemEntries(backupDirectory)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        Assert.Equal(51, created.Count);
        Assert.Single(Directory.GetDirectories(parent));
        string manifestPath = Path.Combine(backupDirectory, ManifestFileName);
        Assert.Equal(manifestSha256, HashFile(manifestPath), StringComparer.OrdinalIgnoreCase);

        // The freshly created set and its saved manifest already carry the actual firmware identity,
        // while the loader toolchain keeps its own 259 profile.
        Assert.Equal(Actual120AndroidBuild, createdAndroidBuild, StringComparer.Ordinal);
        Assert.Equal(MaintenanceProfiles.AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);
        Assert.NotEqual(Actual120AndroidBuild, _fixture.Toolchain.AndroidBuild, StringComparer.Ordinal);

        JsonNode savedManifest = JsonNode.Parse(File.ReadAllText(manifestPath))!;
        Assert.Equal(
            Actual120AndroidBuild,
            (string?)savedManifest["profile"]!["androidBuild"],
            StringComparer.Ordinal);
        Assert.Equal(
            Actual120AndroidBuild,
            (string?)savedManifest["identity"]!["firmware"]!["displayId"],
            StringComparer.Ordinal);

        IB001FakeEdlRunner openRunner = new(device);
        EdlClient openClient = NewClient(openRunner, NewBinding(firmware: Actual120Firmware()));
        ExistingProgress progress = new();

        using InternalBackupSet loaded = await InternalInstallBackup.OpenExistingAsync(
            openClient, backupDirectory, progress);

        Assert.Same(openClient.Binding, loaded.Binding);
        Assert.Equal(backupDirectory, loaded.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestSha256, loaded.ManifestSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestPath, loaded.ManifestPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(_fixture.Toolchain.ProfileId, loaded.ProfileId, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.Model, loaded.Model, StringComparer.Ordinal);
        Assert.Equal(Actual120AndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.HardwareId, loaded.HardwareId, StringComparer.OrdinalIgnoreCase);

        Assert.Equal(51, loaded.Files.Count);
        Assert.True(
            created.Keys.ToHashSet(StringComparer.Ordinal)
                .SetEquals(loaded.Files.Keys.ToHashSet(StringComparer.Ordinal)),
            "the loaded set must expose exactly the same 52 roles");

        foreach (string role in created.Keys)
        {
            EdlCapturedRegion expected = created[role];
            EdlCapturedRegion actual = loaded.Files[role];

            Assert.Equal(expected.Role, actual.Role, StringComparer.Ordinal);
            Assert.Equal(expected.Lun, actual.Lun);
            Assert.Equal(expected.StartSector, actual.StartSector);
            Assert.Equal(expected.SectorCount, actual.SectorCount);
            Assert.Equal(expected.SectorSize, actual.SectorSize);
            Assert.Equal(expected.PartUuid, actual.PartUuid, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(expected.Length, actual.Length);
            Assert.Equal(expected.Sha256, actual.Sha256, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(expected.FilePath, actual.FilePath, StringComparer.OrdinalIgnoreCase);
        }

        // Slot A and slot B stay distinct; nothing was mirrored, swapped or reused across roles.
        Assert.NotEqual(
            loaded.Files["boot_a"].Sha256, loaded.Files["boot_b"].Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.NotEqual(
            loaded.Files["gpt_lun0_primary"].Sha256,
            loaded.Files["gpt_lun0_backup"].Sha256,
            StringComparer.OrdinalIgnoreCase);

        for (int lun = 0; lun < 6; lun++)
        {
            Assert.Equal(
                new EdlGeometry(lun, IB001SyntheticDevice.SectorSize, device.TotalSectors(lun)),
                loaded.Geometries[lun]);
            Assert.Equal(device.DiskGuid(lun), loaded.Tables[lun].DiskGuid, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(
                device.TotalSectors(lun) * IB001SyntheticDevice.SectorSize, loaded.Tables[lun].DiskBytes);
        }

        // The selected directory and its manifest are unchanged, and no new backup directory appeared.
        Assert.Equal(manifestSha256, HashFile(manifestPath), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(
            entriesBefore,
            Directory.GetFileSystemEntries(backupDirectory)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray());
        Assert.Single(Directory.GetDirectories(parent));

        // Loading issues geometry probes only: no payload read, write or reset.
        Assert.Equal(6, openRunner.Commands.Count);
        Assert.All(openRunner.Commands, command => Assert.Equal("printgpt", command.Arguments[0]));
        Assert.Empty(openRunner.Reads);
        Assert.Empty(openRunner.Writes);
        Assert.Equal(0, openRunner.ResetCount);

        // Only the existing stage keys are used, and complete is reported once after every check.
        Assert.Equal(2, progress.Records.Count);
        Assert.Equal(VerifyingStage, progress.Records[0].Stage, StringComparer.Ordinal);
        Assert.Equal(0, progress.Records[0].CompletedFiles);
        Assert.Equal(51, progress.Records[0].TotalFiles);
        Assert.Equal(device.ExpectedBytes(), progress.Records[0].TotalBytes);
        Assert.Equal(CompleteStage, progress.Records[1].Stage, StringComparer.Ordinal);
        Assert.Equal(51, progress.Records[1].CompletedFiles);
        Assert.Equal(progress.Records[1].TotalBytes, progress.Records[1].CompletedBytes);
        Assert.Single(progress.Records.Where(record => record.Stage == CompleteStage));

        loaded.Dispose();
        AssertNoLeaseHeld(backupDirectory);
    }

    [Fact]
    public async Task OpenExisting_large_direct_backup_prepares_the_2GiB_board_archive_with_all_roles()
    {
        const string Name = nameof(OpenExisting_large_direct_backup_prepares_the_2GiB_board_archive_with_all_roles);
        string sourceDirectory = _fixture.NewCaseDirectory(Name + "-sources");
        IReadOnlyDictionary<string, VerifiedEdlFile> sources = CreateDirectSources(sourceDirectory);
        string backing = _fixture.NewCaseDirectory(Name + "-backing");
        IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, sources);

        Assert.Equal(IB001SyntheticDevice.Lun0TotalSectors, device.TotalSectors(0));
        Assert.True(device.TotalSectors(0) * IB001SyntheticDevice.SectorSize >= 96L * 1024 * 1024 * 1024);

        string backupParent = _fixture.NewCaseDirectory(Name + "-backup");
        EdlClient createClient = NewClient(new IB001FakeEdlRunner(device), NewBinding());
        string backupDirectory;

        using (InternalBackupSet created = await InternalInstallBackup.CreateAsync(createClient, backupParent))
        {
            backupDirectory = created.DirectoryPath;
            Assert.Equal(51, created.Files.Count);
            Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, created.Files["boot_a"].Length);
            Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, created.Files["boot_b"].Length);
        }

        EdlClient openClient = NewClient(new IB001FakeEdlRunner(device), NewBinding());
        using InternalBackupSet loaded = await InternalInstallBackup.OpenExistingAsync(openClient, backupDirectory);

        Assert.Equal(51, loaded.Files.Count);
        Assert.NotEqual(
            loaded.Files["boot_a"].Sha256, loaded.Files["boot_b"].Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, loaded.Files["boot_a"].Length);

        string artifactsParent = _fixture.NewCaseDirectory(Name + "-artifacts");
        using InternalArtifactSet artifacts = await InternalInstallArtifacts.PrepareAsync(
            loaded,
            48,
            new PackageStorage(1L << 30, 8L << 30, 4L << 30, 1L << 30),
            artifactsParent);

        Assert.Equal(BoardArchiveBytes, artifacts.BoardSummary.Length);
        Assert.Equal(BoardArchiveBytes, new FileInfo(artifacts.BoardSummary.FilePath).Length);

        Dictionary<string, (long Length, string Sha256)> archive =
            ReadBoardArchive(artifacts.BoardSummary.FilePath);

        foreach (KeyValuePair<string, EdlCapturedRegion> pair in loaded.Files)
        {
            string entryName = pair.Key + ".bin";
            Assert.True(archive.ContainsKey(entryName), "the archive is missing the role entry " + entryName);
            Assert.Equal(pair.Value.Length, archive[entryName].Length);
            Assert.Equal(pair.Value.Sha256, archive[entryName].Sha256, StringComparer.OrdinalIgnoreCase);
        }

        Assert.True(archive.ContainsKey("pc-backup-manifest.json"));
        Assert.Equal(
            new FileInfo(loaded.ManifestPath).Length, archive["pc-backup-manifest.json"].Length);
        Assert.Equal(
            loaded.ManifestSha256, archive["pc-backup-manifest.json"].Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, archive["boot_a.bin"].Length);
        Assert.Equal(IB001SyntheticDevice.BootPartitionBytes, archive["boot_b.bin"].Length);
    }

    [Fact]
    public async Task OpenExisting_precancel_opens_nothing_and_creates_nothing()
    {
        const string Name = nameof(OpenExisting_precancel_opens_nothing_and_creates_nothing);
        string parent = _fixture.NewCaseDirectory(Name);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);
        int directoryCount = Directory.GetDirectories(parent).Length;
        string manifestSha = HashFile(Path.Combine(backupDirectory, ManifestFileName));

        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, NewBinding());
        ExistingProgress progress = new();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.OpenExistingAsync(
            client, backupDirectory, progress, cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.Empty(progress.Records);
        Assert.Empty(runner.Commands);
        Assert.Equal(directoryCount, Directory.GetDirectories(parent).Length);
        Assert.Equal(manifestSha, HashFile(Path.Combine(backupDirectory, ManifestFileName)));
        AssertNoLeaseHeld(backupDirectory);
    }

    [Fact]
    public async Task OpenExisting_rejects_a_sidecar_that_does_not_match_the_manifest()
    {
        const string Name = nameof(OpenExisting_rejects_a_sidecar_that_does_not_match_the_manifest);
        string parent = _fixture.NewCaseDirectory(Name);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);

        string sidecar = Path.Combine(backupDirectory, ManifestFileName) + SidecarSuffix;
        File.WriteAllBytes(sidecar, Encoding.ASCII.GetBytes(new string('0', 64) + "\n"));

        await OpenFailureAsync(device, backupDirectory);
    }

    [Theory]
    [InlineData("modified")]
    [InlineData("swapped")]
    public async Task OpenExisting_rejects_a_changed_or_swapped_payload(string variant)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(OpenExisting_rejects_a_changed_or_swapped_payload) + "-" + variant);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);

        if (string.Equals(variant, "modified", StringComparison.Ordinal))
        {
            FlipByte(Path.Combine(backupDirectory, "misc.bin"), 0);
        }
        else
        {
            string bootA = Path.Combine(backupDirectory, "boot_a.bin");
            string bootB = Path.Combine(backupDirectory, "boot_b.bin");
            byte[] a = File.ReadAllBytes(bootA);
            byte[] b = File.ReadAllBytes(bootB);
            Assert.Equal(a.Length, b.Length);
            File.WriteAllBytes(bootA, b);
            File.WriteAllBytes(bootB, a);
        }

        await OpenFailureAsync(device, backupDirectory);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    public async Task OpenExisting_rejects_a_missing_or_duplicate_role(string variant)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(OpenExisting_rejects_a_missing_or_duplicate_role) + "-" + variant);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);

        RewriteManifest(backupDirectory, root =>
        {
            JsonArray files = root["files"]!.AsArray();
            JsonObject target = files
                .Select(node => node!.AsObject())
                .First(item => string.Equals((string?)item["role"], "misc", StringComparison.Ordinal));

            if (string.Equals(variant, "missing", StringComparison.Ordinal))
            {
                files.Remove(target);
            }
            else
            {
                files.Add(JsonNode.Parse(target.ToJsonString())!);
            }
        });

        await OpenFailureAsync(device, backupDirectory);
    }

    [Theory]
    [InlineData("firmware")]
    [InlineData("serial")]
    public async Task OpenExisting_rejects_a_different_full_identity_with_a_valid_manifest(string variant)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(OpenExisting_rejects_a_different_full_identity_with_a_valid_manifest) + "-" + variant);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);

        RewriteManifest(backupDirectory, root =>
        {
            JsonObject identity = root["identity"]!.AsObject();

            if (string.Equals(variant, "firmware", StringComparison.Ordinal))
            {
                identity["firmware"]!.AsObject()["buildFingerprint"] = "Other/Fingerprint/For/Test";
            }
            else
            {
                identity["androidSerial"] = "SNDIFFERENT";
            }
        });

        // The manifest and sidecar are self-consistent again; only the identity differs from the bound device.
        await OpenFailureAsync(device, backupDirectory);
    }

    [Fact]
    public async Task OpenExisting_rejects_invalid_gpt_crc_even_when_file_sha_and_sidecar_are_consistent()
    {
        const string Name =
            nameof(OpenExisting_rejects_invalid_gpt_crc_even_when_file_sha_and_sidecar_are_consistent);
        string parent = _fixture.NewCaseDirectory(Name);
        (string backupDirectory, IB001SyntheticDevice device) = await CreateSmallBackupAsync(parent);

        string gptPath = Path.Combine(backupDirectory, "gpt_lun0_primary.bin");
        FlipByte(gptPath, (IB001SyntheticDevice.SectorSize * 1) + GptHeaderCrcOffset);
        string changedSha = HashFile(gptPath);

        RewriteManifest(backupDirectory, root =>
        {
            JsonArray files = root["files"]!.AsArray();

            foreach (JsonNode? node in files)
            {
                JsonObject file = node!.AsObject();
                if (string.Equals((string?)file["role"], "gpt_lun0_primary", StringComparison.Ordinal))
                {
                    file["sha256"] = changedSha;
                }
            }
        });

        await OpenFailureAsync(device, backupDirectory);
    }

    // --------------------------------------------------------------------------- helpers

    private async Task<(string Directory, IB001SyntheticDevice Device)> CreateSmallBackupAsync(string parent)
    {
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        EdlClient client = NewClient(new IB001FakeEdlRunner(device), NewBinding());

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);
        return (set.DirectoryPath, device);
    }

    private async Task<Exception> OpenFailureAsync(
        IB001SyntheticDevice device,
        string backupDirectory,
        EdlEntryResult? binding = null,
        CancellationToken token = default)
    {
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, binding ?? NewBinding());
        ExistingProgress progress = new();

        Exception? error = await Record.ExceptionAsync(() => InternalInstallBackup.OpenExistingAsync(
            client, backupDirectory, progress, token));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error!);
        Assert.DoesNotContain(progress.Records, record => record.Stage == CompleteStage);
        Assert.Empty(runner.Writes);
        Assert.Equal(0, runner.ResetCount);
        AssertNoLeaseHeld(backupDirectory);
        return error!;
    }

    private EdlClient NewClient(IB001FakeEdlRunner runner, EdlEntryResult binding) => new(
        _fixture.Toolchain,
        binding,
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private EdlEntryResult NewBinding(
        string serial = "SN0123456789",
        string? buildFingerprint = null,
        string? androidRelease = null,
        string? securityPatch = null,
        FirmwareSnapshot? firmware = null) =>
        new(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(serial, _fixture.Toolchain.Model, BootloaderState.Unknown)
                {
                    Firmware = firmware ?? new FirmwareSnapshot(
                        _fixture.Toolchain.AndroidBuild,
                        BuildFingerprint: buildFingerprint ??
                                         "Lenovo/TB322FC/TB322FC:15/TP1A.220905.001/259:user/release-keys",
                        AndroidRelease: androidRelease ?? "15",
                        SecurityPatch: securityPatch ?? "2026-06-01",
                        AndroidReportedBootloaderState: BootloaderState.Unlocked),
                },
                E003EdlTestData.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex);

    /// <summary>The full actual TB322FC 120 firmware snapshot used by the FW01 regression cases.</summary>
    private static FirmwareSnapshot Actual120Firmware() => new(
        Actual120AndroidBuild,
        BuildFingerprint: Actual120BuildFingerprint,
        AndroidRelease: Actual120AndroidRelease,
        SecurityPatch: Actual120SecurityPatch,
        AndroidReportedBootloaderState: BootloaderState.Locked);

    private static IReadOnlyDictionary<string, VerifiedEdlFile> CreateDirectSources(string directory)
    {
        Dictionary<string, VerifiedEdlFile> sources = new(StringComparer.Ordinal);
        byte seed = 0x31;

        foreach (string role in IB001SyntheticDevice.DirectSourceRoles)
        {
            long length = string.Equals(role, "boot_a", StringComparison.Ordinal) ||
                          string.Equals(role, "boot_b", StringComparison.Ordinal)
                ? IB001SyntheticDevice.BootPartitionBytes
                : IB001SyntheticDevice.SectorSize;

            string path = Path.Combine(directory, role + ".img");
            WritePattern(path, length, seed);
            sources.Add(role, new VerifiedEdlFile(path, length, HashFile(path)));
            seed = unchecked((byte)(seed + 0x11));
        }

        return sources;
    }

    private static void WritePattern(string path, long length, byte seed)
    {
        byte[] buffer = new byte[CopyBufferBytes];
        for (int index = 0; index < buffer.Length; index++)
        {
            buffer[index] = (byte)((seed + (index * 17)) % 251);
        }

        using FileStream stream = new(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferBytes);

        long remaining = length;
        while (remaining > 0)
        {
            int chunk = (int)Math.Min(buffer.Length, remaining);
            stream.Write(buffer, 0, chunk);
            remaining -= chunk;
        }
    }

    private static Dictionary<string, (long Length, string Sha256)> ReadBoardArchive(string path)
    {
        Dictionary<string, (long Length, string Sha256)> entries = new(StringComparer.Ordinal);

        using FileStream image = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);
        image.Position = CopyBufferBytes; // the fixed 64 KiB outer board header precedes the gzip member.

        using GZipStream gzip = new(image, CompressionMode.Decompress, leaveOpen: false);
        using TarReader reader = new(gzip, leaveOpen: false);

        TarEntry? entry;
        while ((entry = reader.GetNextEntry()) is not null)
        {
            Stream? data = entry.DataStream;
            if (entry.EntryType != TarEntryType.RegularFile || data is null)
            {
                throw new InvalidDataException("The board archive carries a non-regular entry '" + entry.Name + "'.");
            }

            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[CopyBufferBytes];
            long total = 0;
            int read;

            while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, read);
                total += read;
            }

            if (total != entry.Length)
            {
                throw new InvalidDataException("The archive entry '" + entry.Name + "' ended early.");
            }

            entries.Add(entry.Name, (total, Convert.ToHexString(hash.GetHashAndReset())));
        }

        return entries;
    }

    private static void RewriteManifest(string backupDirectory, Action<JsonObject> mutate)
    {
        string path = Path.Combine(backupDirectory, ManifestFileName);
        JsonObject root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        mutate(root);

        byte[] bytes = Encoding.UTF8.GetBytes(root.ToJsonString());
        using (FileStream stream = new(path, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }

        File.WriteAllBytes(
            path + SidecarSuffix,
            Encoding.ASCII.GetBytes(Convert.ToHexString(SHA256.HashData(bytes)) + "\n"));
    }

    private static void FlipByte(string path, long offset)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = offset;
        int value = stream.ReadByte();
        Assert.InRange(value, 0, 255);
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
        stream.Flush(true);
    }

    private static void AssertNoLeaseHeld(string backupDirectory)
    {
        foreach (string path in Directory.GetFiles(backupDirectory))
        {
            using FileStream probe = new(path, FileMode.Open, FileAccess.Read, FileShare.None);
        }
    }

    private static string HashFile(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = new byte[CopyBufferBytes];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private sealed class ExistingProgress : IProgress<InternalBackupProgress>
    {
        internal List<InternalBackupProgress> Records { get; } = new();

        public void Report(InternalBackupProgress value) => Records.Add(value);
    }
}
