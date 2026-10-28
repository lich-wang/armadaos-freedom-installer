using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// U2B focused cases: <see cref="InternalInstallBackup.OpenOriginalGptForUninstallAsync"/> is the narrow
/// historical reinstall path - it accepts a verified backup of the same physical unit even when the Android
/// firmware has since moved on, because it validates manifest roles, hashes and the original GPT tables
/// instead of the displayed firmware. The regular <see cref="InternalInstallBackup.OpenExistingAsync"/> stays
/// full-firmware strict and must keep rejecting the same historical directory.
/// <para>
/// Every case creates its original backup through the real <see cref="InternalInstallBackup.CreateAsync"/>
/// factory on a synthetic archive-layout device (userdata last, covering the full tail), disposes the creating
/// set, then mutates or rebinds only what the individual case names. No real device, process, USB endpoint or
/// actual backup is touched; the manager runs these tests remotely.
/// </para>
/// </summary>
public sealed class UninstallOriginalGptBackupTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string ManifestFileName = "backup-manifest.json";
    private const string SidecarSuffix = ".sha256";
    private const string Lun0PrimaryFileName = "gpt_lun0_primary.bin";
    private const string UserdataLabel = "userdata";
    private const string NonFactoryLabelPrefix = "ARMADA_";
    private const string FingerprintBase = "Lenovo/TB322FC/TB322FC:15/TP1A.220905.001/259:user/release-keys";
    private const string CurrentAndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.121_ST_260601";

    private readonly EdlClientToolchainFixture _fixture;

    public UninstallOriginalGptBackupTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task U2B01_NarrowOpen_accepts_the_same_unit_on_newer_firmware_and_never_recaptures()
    {
        const string Name = nameof(U2B01_NarrowOpen_accepts_the_same_unit_on_newer_firmware_and_never_recaptures);
        string parent = _fixture.NewCaseDirectory(Name);

        CreatedOriginalBackup created = await CreateOriginalBackupAsync(parent);
        Dictionary<string, string> filesAfterCreate = SnapshotFiles(created.DirectoryPath);

        // The manifest GPT claim matches the file the factory really wrote below the backup directory.
        Assert.Equal(
            HashFile(Path.Combine(created.DirectoryPath, Lun0PrimaryFileName)),
            created.Files["gpt_lun0_primary"].Sha256,
            StringComparer.OrdinalIgnoreCase);

        IB001FakeEdlRunner openRunner = new(created.Device);
        EdlClient openClient = NewClient(openRunner, NewBinding(firmware: CurrentFirmware()));

        using UninstallOriginalGptBackup loaded = await InternalInstallBackup.OpenOriginalGptForUninstallAsync(
            openClient, created.DirectoryPath);

        Assert.Same(openClient.Binding, loaded.Binding);
        Assert.Equal(created.DirectoryPath, loaded.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(
            Path.Combine(created.DirectoryPath, ManifestFileName),
            loaded.ManifestPath,
            StringComparer.OrdinalIgnoreCase);
        Assert.Equal(created.ManifestSha256, loaded.ManifestSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(_fixture.Toolchain.Model, loaded.Model, StringComparer.Ordinal);
        Assert.Equal(_fixture.Toolchain.HardwareId, loaded.HardwareId, StringComparer.OrdinalIgnoreCase);

        // The narrow open probes all six LUNs to confirm the same physical identity and never takes a new
        // capture: no partition read, no write, no reset.
        Assert.Equal(new[] { 0, 1, 2, 3, 4, 5 }, openRunner.ProbedLuns);
        Assert.Empty(openRunner.Reads);
        Assert.Equal(0, openRunner.WriteOrResetCount);

        Assert.Equal(new[] { 0, 1, 2, 3, 4, 5 }, loaded.Geometries.Keys.OrderBy(lun => lun).ToArray());
        foreach (int lun in new[] { 0, 1, 2, 3, 4, 5 })
        {
            EdlGeometry expectedGeometry = created.Geometries[lun];
            EdlGeometry actualGeometry = loaded.Geometries[lun];
            Assert.Equal(expectedGeometry.Lun, actualGeometry.Lun);
            Assert.Equal(expectedGeometry.SectorSize, actualGeometry.SectorSize);
            Assert.Equal(expectedGeometry.TotalSectors, actualGeometry.TotalSectors);
        }

        Assert.Equal(created.Files["gpt_lun0_primary"], loaded.PrimaryGpt);
        Assert.Equal(created.Files["gpt_lun0_backup"], loaded.BackupGpt);
        Assert.Equal(created.Files["gpt_lun0_primary"].Length, loaded.PrimaryGpt.Length);
        Assert.Equal(
            created.Files["gpt_lun0_primary"].Sha256,
            loaded.PrimaryGpt.Sha256,
            StringComparer.OrdinalIgnoreCase);
        Assert.Equal(created.Files["gpt_lun0_backup"].Length, loaded.BackupGpt.Length);
        Assert.Equal(
            created.Files["gpt_lun0_backup"].Sha256,
            loaded.BackupGpt.Sha256,
            StringComparer.OrdinalIgnoreCase);

        Assert.Equal(created.Table0.DiskGuid, loaded.OriginalTable.DiskGuid, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(
            created.Table0.SourceFingerprint,
            loaded.OriginalTable.SourceFingerprint,
            StringComparer.Ordinal);
        Assert.Equal(
            created.Table0.Partitions.Select(partition => (
                partition.Number,
                partition.Name,
                partition.TypeGuid,
                partition.PartUuid,
                partition.StartSector,
                partition.SectorCount,
                partition.Attributes)),
            loaded.OriginalTable.Partitions.Select(partition => (
                partition.Number,
                partition.Name,
                partition.TypeGuid,
                partition.PartUuid,
                partition.StartSector,
                partition.SectorCount,
                partition.Attributes)));

        // The archive layout makes userdata the last partition and it must end at the last usable sector
        // (inclusive end == LastUsableSector + 1); the original table carries no non-factory ARMADA_ labels.
        GptPartition userdata = Assert.Single(loaded.OriginalTable.Partitions
            .Where(partition => string.Equals(partition.Name, UserdataLabel, StringComparison.Ordinal))
            .ToArray());
        Assert.Equal(created.Table0.LastUsableSector + 1, userdata.StartSector + userdata.SectorCount);
        Assert.Equal(created.Table0.LastUsableSector, loaded.OriginalTable.LastUsableSector);
        Assert.DoesNotContain(
            loaded.OriginalTable.Partitions,
            partition => partition.Name.StartsWith(NonFactoryLabelPrefix, StringComparison.OrdinalIgnoreCase));

        Dictionary<string, string> filesAfterOpen = SnapshotFiles(created.DirectoryPath);
        Assert.Equal(filesAfterCreate, filesAfterOpen);

        // The regular open stays full-firmware strict: a fresh client bound to the current firmware must
        // keep rejecting this historical directory.
        IB001FakeEdlRunner strictRunner = new(created.Device);
        EdlClient strictClient = NewClient(strictRunner, NewBinding(firmware: CurrentFirmware()));

        Exception? strictError = await Record.ExceptionAsync(
            () => InternalInstallBackup.OpenExistingAsync(strictClient, created.DirectoryPath));

        Assert.NotNull(strictError);
        Assert.True(
            strictError is InvalidDataException or InvalidOperationException or ArgumentException,
            "the strict open must fail with a real business exception, got: " + strictError!.GetType().Name);
        Assert.Equal(0, strictRunner.WriteOrResetCount);
    }

    [Fact]
    public async Task U2B02_NarrowOpen_rejects_a_corrupt_manifest_sidecar_and_repairs_nothing()
    {
        const string Name = nameof(U2B02_NarrowOpen_rejects_a_corrupt_manifest_sidecar_and_repairs_nothing);
        string parent = _fixture.NewCaseDirectory(Name);

        CreatedOriginalBackup created = await CreateOriginalBackupAsync(parent);

        // Corrupt only the sidecar, to 64 zeros plus the newline, after the creating set is disposed; the
        // manifest itself and every payload file stay exactly as the factory wrote them.
        string sidecarPath = Path.Combine(created.DirectoryPath, ManifestFileName + SidecarSuffix);
        File.WriteAllText(sidecarPath, new string('0', 64) + "\n", Encoding.ASCII);

        Dictionary<string, string> filesBefore = SnapshotFiles(created.DirectoryPath);

        // The production sidecar check throws the exact IOException below; asserting the precise
        // type and message proves the rejection came from the sidecar verification, not a lock.
        IB001FakeEdlRunner runner = new(created.Device);
        EdlClient client = NewClient(runner, NewBinding(firmware: CurrentFirmware()));

        IOException rejection = await Assert.ThrowsAsync<IOException>(
            () => InternalInstallBackup.OpenOriginalGptForUninstallAsync(
                client, created.DirectoryPath));
        Assert.Equal(
            "The manifest sidecar does not carry the verified manifest SHA-256.",
            rejection.Message);

        // The rejected narrow open must not repair the sidecar or touch any backup file.
        Assert.Empty(runner.Reads);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(filesBefore, SnapshotFiles(created.DirectoryPath));
    }

    [Fact]
    public async Task U2B03_NarrowOpen_rejects_a_flipped_gpt_byte_under_the_old_manifest_claim()
    {
        const string Name = nameof(U2B03_NarrowOpen_rejects_a_flipped_gpt_byte_under_the_old_manifest_claim);
        string parent = _fixture.NewCaseDirectory(Name);

        CreatedOriginalBackup created = await CreateOriginalBackupAsync(parent);

        // Flip exactly one byte inside the LUN0 primary GPT entry area after the source set is disposed,
        // while the manifest still carries the original SHA-256 claim; the real file hash (and entry CRC)
        // coverage must reject this.
        string primaryPath = Path.Combine(created.DirectoryPath, Lun0PrimaryFileName);
        byte[] bytes = File.ReadAllBytes(primaryPath);
        bytes[10_000] ^= 0xFF;
        File.WriteAllBytes(primaryPath, bytes);

        Dictionary<string, string> filesBefore = SnapshotFiles(created.DirectoryPath);

        await NarrowOpenRejectionAsync(
            created.Device,
            created.DirectoryPath,
            NewBinding(firmware: CurrentFirmware()));

        // No expected successful fallback: the file stays corrupted and nothing else is touched.
        Assert.Equal(filesBefore, SnapshotFiles(created.DirectoryPath));
    }

    [Fact]
    public async Task U2B04_NarrowOpen_rejects_a_different_android_serial_on_the_same_hardware()
    {
        const string Name = nameof(U2B04_NarrowOpen_rejects_a_different_android_serial_on_the_same_hardware);
        string parent = _fixture.NewCaseDirectory(Name);

        CreatedOriginalBackup created = await CreateOriginalBackupAsync(parent);
        Dictionary<string, string> filesBefore = SnapshotFiles(created.DirectoryPath);

        // Same SoC serial, bus serial and model (the binding keeps E003EdlTestData defaults), but a
        // different Android serial: the narrow open must reject the unit mismatch.
        await NarrowOpenRejectionAsync(
            created.Device,
            created.DirectoryPath,
            NewBinding(serial: "SN9876543210", firmware: CurrentFirmware()));

        Assert.Equal(filesBefore, SnapshotFiles(created.DirectoryPath));
    }

    // ------------------------------------------------------------------ helpers

    private async Task<CreatedOriginalBackup> CreateOriginalBackupAsync(string parent)
    {
        // archiveLayout is essential here: it makes userdata the last partition and cover the full tail,
        // which is exactly the layout the narrow open's factory guard expects from a real unit.
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(archiveLayout: true);
        EdlClient client = NewClient(new IB001FakeEdlRunner(device), NewBinding(firmware: OldFirmware()));

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent);

        return new CreatedOriginalBackup(
            device,
            set.DirectoryPath,
            set.ManifestSha256,
            set.Files.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
            set.Geometries.ToDictionary(pair => pair.Key, pair => pair.Value),
            set.Tables[0]);
    }

    private async Task<Exception> NarrowOpenRejectionAsync(
        IB001SyntheticDevice device,
        string backupDirectory,
        EdlEntryResult binding)
    {
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, binding);

        Exception? error = await Record.ExceptionAsync(
            () => InternalInstallBackup.OpenOriginalGptForUninstallAsync(client, backupDirectory));

        Assert.NotNull(error);
        Assert.True(
            error is InvalidDataException or InvalidOperationException or ArgumentException,
            "the narrow open must fail with a real business exception, got: " + error!.GetType().Name);
        Assert.Empty(runner.Reads);
        Assert.Equal(0, runner.WriteOrResetCount);
        return error!;
    }

    private EdlClient NewClient(IB001FakeEdlRunner runner, EdlEntryResult binding) => new(
        _fixture.Toolchain,
        binding,
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private EdlEntryResult NewBinding(string serial = "SN0123456789", FirmwareSnapshot? firmware = null) =>
        new(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(serial, _fixture.Toolchain.Model, BootloaderState.Unknown)
                {
                    Firmware = firmware ?? OldFirmware()
                },
                E003EdlTestData.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex);

    /// <summary>
    /// The saved historical firmware: the loader toolchain build with a synthetic fingerprint, an older
    /// patch level and an unlocked report.
    /// </summary>
    private FirmwareSnapshot OldFirmware() => new(
        _fixture.Toolchain.AndroidBuild,
        BuildFingerprint: FingerprintBase + "/old",
        AndroidRelease: "15",
        SecurityPatch: "2026-01-01",
        AndroidReportedBootloaderState: BootloaderState.Unlocked);

    /// <summary>
    /// A different, fully populated current firmware on the same physical unit: new build string and
    /// fingerprint, newer release and patch level, locked report.
    /// </summary>
    private FirmwareSnapshot CurrentFirmware() => new(
        CurrentAndroidBuild,
        BuildFingerprint: FingerprintBase + "/new",
        AndroidRelease: "16",
        SecurityPatch: "2026-06-01",
        AndroidReportedBootloaderState: BootloaderState.Locked);

    private static Dictionary<string, string> SnapshotFiles(string directory) =>
        Directory.GetFiles(directory)
            .ToDictionary(path => path, HashFile, StringComparer.OrdinalIgnoreCase);

    private static string HashFile(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record CreatedOriginalBackup(
        IB001SyntheticDevice Device,
        string DirectoryPath,
        string ManifestSha256,
        Dictionary<string, EdlCapturedRegion> Files,
        Dictionary<int, EdlGeometry> Geometries,
        GptTable Table0);
}
