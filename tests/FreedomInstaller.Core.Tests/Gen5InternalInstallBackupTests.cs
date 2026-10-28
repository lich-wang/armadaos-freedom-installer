using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Loads the real Gen5 (Y7005 / TB323FU) EDL toolchain bundle. There is no skip and no fallback: the bundle
/// must be named by <c>EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH</c> and its scratch space must stay below
/// <c>EDL_CLIENT_TEST_WORK_ROOT</c> so the manager's work area is the only writable location.
/// </summary>
public sealed class Gen5EdlToolchainFixture : IAsyncLifetime
{
    private EdlToolchain? _toolchain;

    public Gen5EdlToolchainFixture()
    {
        string? bundle = Environment.GetEnvironmentVariable("EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH");
        if (string.IsNullOrWhiteSpace(bundle))
        {
            throw new InvalidOperationException(
                "EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH must name the real Gen5 EDL toolchain archive; refusing to skip.");
        }

        BundlePath = Path.GetFullPath(bundle);
        if (!File.Exists(BundlePath))
        {
            throw new InvalidOperationException($"Gen5 EDL toolchain bundle '{BundlePath}' does not exist.");
        }

        string? configuredRoot = Environment.GetEnvironmentVariable("EDL_CLIENT_TEST_WORK_ROOT");
        if (string.IsNullOrWhiteSpace(configuredRoot))
        {
            throw new InvalidOperationException(
                "EDL_CLIENT_TEST_WORK_ROOT must name the manager's work area; refusing to fall back outside it.");
        }

        string parent = Path.GetFullPath(configuredRoot);

        WorkRoot = Path.Combine(parent, "g5-edlclient-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(WorkRoot);
    }

    public string BundlePath { get; }

    public string WorkRoot { get; }

    public EdlToolchain Toolchain =>
        _toolchain ?? throw new InvalidOperationException("The Gen5 EDL toolchain was not loaded by the fixture.");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(WorkRoot);
        string loadRoot = Path.Combine(WorkRoot, "toolchain");
        Directory.CreateDirectory(loadRoot);

        using FileStream archive = File.OpenRead(BundlePath);
        _toolchain = await EdlToolchain.LoadAsync(archive, loadRoot, CancellationToken.None);
    }

    public Task DisposeAsync()
    {
        _toolchain?.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>Creates a new unique case directory below this fixture's work root.</summary>
    public string NewCaseDirectory(string testName)
    {
        string safe = new string(testName.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray());
        string directory = Path.Combine(WorkRoot, "cases", safe + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}

/// <summary>
/// G5P2F: model-specific capture/reuse integration tests for the real Gen5 (TB323FU / Y7005) bundle. The
/// toolchain, the profile and the reader are the production ones; only the external process boundary and
/// the USB endpoint enumeration are faked. All device tables are synthetic (IB001 fixture) — no real device
/// dump, serial, or backup image is involved.
/// </summary>
public sealed class Gen5InternalInstallBackupTests : IClassFixture<Gen5EdlToolchainFixture>
{
    private const string Gen5Model = "TB323FU";
    private const string Gen5HardwareId = "002B40E100400000";
    private const string Gen5ProfileId = "g5-9008-y7005";

    // The build reported by the bound current Android 16 device, never the bundle's loader profile.
    private const string Gen5AndroidBuild =
        "TB323FU_CN_OPEN_USER_Q00020.0_A16_ZUXOS_2.0.11.043_ST_260309";
    private const string Gen5BuildFingerprint =
        "Lenovo/TB323FU/TB323FU:16/UQ1A.240205.004/2.0.11.043:user/release-keys";
    private const string Gen5AndroidRelease = "16";
    private const string Gen5SecurityPatch = "2026-09-05";

    private const int Gen5RoleCount = 47;

    private static readonly string[] AllowedStages =
    {
        "reading-gpt", "reading-partition", "verifying", "complete",
    };

    private readonly Gen5EdlToolchainFixture _fixture;

    public Gen5InternalInstallBackupTests(Gen5EdlToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ---------------------------------------------------------------- positive workflow

    [Fact]
    public async Task G5_01_Create_captures_the_48_gen5_roles_and_reopens_them_read_only()
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(G5_01_Create_captures_the_48_gen5_roles_and_reopens_them_read_only));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: true);
        IB001FakeEdlRunner runner = new(device, hardwareId: Gen5HardwareId);
        EdlClient client = NewClient(runner);
        Gen5Progress progress = new();

        string backupDirectory;
        string manifestSha256;
        Dictionary<string, EdlCapturedRegion> created;
        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(client, parent, progress))
        {
            backupDirectory = set.DirectoryPath;
            manifestSha256 = set.ManifestSha256;
            created = set.Files.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

            Assert.Same(client.Binding, set.Binding);
            Assert.Equal(Gen5ProfileId, set.ProfileId, StringComparer.Ordinal);
            Assert.Equal(Gen5Model, set.Model, StringComparer.Ordinal);
            Assert.Equal(Gen5HardwareId, set.HardwareId, StringComparer.OrdinalIgnoreCase);
            // The captured build identity is the bound device's actual Android 16 firmware.
            Assert.Equal(Gen5AndroidBuild, set.AndroidBuild, StringComparer.Ordinal);
            Assert.True(
                backupDirectory.StartsWith(parent, StringComparison.OrdinalIgnoreCase),
                "the backup directory must live below the chosen parent: " + backupDirectory);

            Assert.Equal(6, set.Geometries.Count);
            Assert.Equal(6, set.Tables.Count);

            HashSet<string> expectedRoles = device.ExpectedRoles().Select(entry => entry.Role)
                .ToHashSet(StringComparer.Ordinal);
            Assert.Equal(Gen5RoleCount, expectedRoles.Count);
            Assert.Equal(12, expectedRoles.Count(role => role.StartsWith("gpt_", StringComparison.Ordinal)));
            Assert.Equal(Gen5RoleCount, set.Files.Count);
            Assert.True(
                expectedRoles.SetEquals(set.Files.Keys),
                "the backup must index exactly the 47 Gen5 contract roles");

            // All six GPT pairs, primary plus backup window, and both slots of every paired label.
            for (int lun = 0; lun < 6; lun++)
            {
                Assert.True(set.Files.ContainsKey("gpt_lun" + lun + "_primary"));
                Assert.True(set.Files.ContainsKey("gpt_lun" + lun + "_backup"));
            }

            Assert.Contains("boot_a", set.Files.Keys);
            Assert.Contains("boot_b", set.Files.Keys);
            Assert.Contains("xbl_a", set.Files.Keys);
            Assert.Contains("xbl_b", set.Files.Keys);
            Assert.Contains("vbmeta_a", set.Files.Keys);
            Assert.Contains("vbmeta_b", set.Files.Keys);

            foreach (string role in expectedRoles)
            {
                (int lun, long start, long count, string? partUuid) = device.Expectation(role);
                EdlCapturedRegion region = set.Files[role];

                Assert.Equal(role, region.Role, StringComparer.Ordinal);
                Assert.Equal(lun, region.Lun);
                Assert.Equal(start, region.StartSector);
                Assert.Equal(count, region.SectorCount);
                Assert.Equal(partUuid, region.PartUuid);
                Assert.True(File.Exists(region.FilePath), "captured file is missing: " + region.FilePath);
                Assert.Equal(region.Length, new FileInfo(region.FilePath).Length);
                Assert.Equal(region.Sha256, HashFile(region.FilePath), StringComparer.OrdinalIgnoreCase);
            }

            Assert.Equal(Gen5RoleCount, runner.Reads.Count);
            Assert.Equal(0, runner.WriteOrResetCount);
        }

        // The create progress reached the terminal stage exactly once, and only known stages were reported.
        Assert.NotEmpty(progress.Events);
        Assert.Equal(1, progress.Events.Count(e => string.Equals(e.Stage, "complete", StringComparison.Ordinal)));
        Assert.Equal("complete", progress.Events[progress.Events.Count - 1].Stage, StringComparer.Ordinal);
        foreach (InternalBackupProgress reported in progress.Events)
        {
            Assert.Contains(reported.Stage, AllowedStages);
        }

        InternalBackupProgress lastCreate = progress.Events[progress.Events.Count - 1];
        Assert.Equal(Gen5RoleCount, lastCreate.CompletedFiles);
        Assert.Equal(Gen5RoleCount, lastCreate.TotalFiles);

        // Reuse: a brand new client over the same directory verifies every hash and never reads partitions.
        IB001FakeEdlRunner openRunner = new(device, hardwareId: Gen5HardwareId);
        EdlClient openClient = NewClient(openRunner);
        Gen5Progress openProgress = new();

        using InternalBackupSet loaded = await InternalInstallBackup.OpenExistingAsync(
            openClient, backupDirectory, openProgress);

        Assert.Same(openClient.Binding, loaded.Binding);
        Assert.Equal(backupDirectory, loaded.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestSha256, loaded.ManifestSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(Gen5ProfileId, loaded.ProfileId, StringComparer.Ordinal);
        Assert.Equal(Gen5Model, loaded.Model, StringComparer.Ordinal);
        Assert.Equal(Gen5HardwareId, loaded.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(Gen5AndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);

        Assert.Equal(Gen5RoleCount, loaded.Files.Count);
        Assert.True(
            created.Keys.ToHashSet(StringComparer.Ordinal)
                .SetEquals(loaded.Files.Keys.ToHashSet(StringComparer.Ordinal)),
            "the loaded set must expose exactly the same 47 roles");

        foreach (string role in created.Keys)
        {
            EdlCapturedRegion expected = created[role];
            EdlCapturedRegion actual = loaded.Files[role];

            Assert.Equal(expected.FilePath, actual.FilePath, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(expected.Length, actual.Length);
            Assert.Equal(expected.Sha256, actual.Sha256, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(expected.Lun, actual.Lun);
            Assert.Equal(expected.StartSector, actual.StartSector);
            Assert.Equal(expected.SectorCount, actual.SectorCount);
        }

        // Six geometry probes, zero partition reads, zero writes or resets.
        Assert.Equal(6, openRunner.ProbedLuns.Count);
        Assert.Empty(openRunner.Reads);
        Assert.Equal(0, openRunner.WriteOrResetCount);
        Assert.Equal(1, openProgress.Events.Count(e => string.Equals(e.Stage, "complete", StringComparison.Ordinal)));
        foreach (InternalBackupProgress reported in openProgress.Events)
        {
            Assert.Contains(reported.Stage, AllowedStages);
        }

        InternalBackupProgress lastOpen = openProgress.Events[openProgress.Events.Count - 1];
        Assert.Equal(Gen5RoleCount, lastOpen.CompletedFiles);
        Assert.Equal(Gen5RoleCount, lastOpen.TotalFiles);
    }

    // ---------------------------------------------------------------- rejected role sets

    [Theory]
    [InlineData("boot_b")]
    [InlineData("persist")]
    [InlineData("modemst1")]
    public async Task G5_02_Create_rejects_a_missing_gen5_role_after_reading_only_the_gpt_windows(string omitted)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(G5_02_Create_rejects_a_missing_gen5_role_after_reading_only_the_gpt_windows) + "-" + omitted);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(omitRole: omitted, gen5: true);
        IB001FakeEdlRunner runner = new(device, hardwareId: Gen5HardwareId);
        EdlClient client = NewClient(runner);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessRejection(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task G5_03_Create_rejects_a_boot_b_that_is_duplicated_or_moved_to_lun0(bool duplicate)
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(G5_03_Create_rejects_a_boot_b_that_is_duplicated_or_moved_to_lun0) + "-" + duplicate);
        IB001SyntheticDevice device = duplicate
            ? IB001SyntheticDevice.Create(duplicateRole: "boot_b", gen5: true)
            : IB001SyntheticDevice.Create(moveRole: "boot_b", moveRoleToLun: 0, gen5: true);
        IB001FakeEdlRunner runner = new(device, hardwareId: Gen5HardwareId);
        EdlClient client = NewClient(runner);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => InternalInstallBackup.CreateAsync(client, parent));

        AssertBusinessRejection(error);
        AssertOnlyGptReads(runner);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    // ---------------------------------------------------------------- reuse integrity

    [Fact]
    public async Task G5_04_OpenExisting_rejects_a_single_flipped_boot_b_byte_without_touching_the_device()
    {
        string parent = _fixture.NewCaseDirectory(
            nameof(G5_04_OpenExisting_rejects_a_single_flipped_boot_b_byte_without_touching_the_device));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: true);

        string backupDirectory;
        string bootBPath;
        using (InternalBackupSet set = await InternalInstallBackup
            .CreateAsync(NewClient(new IB001FakeEdlRunner(device, hardwareId: Gen5HardwareId)), parent))
        {
            backupDirectory = set.DirectoryPath;
            bootBPath = set.Files["boot_b"].FilePath;
        }

        FlipFirstByte(bootBPath);

        IB001FakeEdlRunner openRunner = new(device, hardwareId: Gen5HardwareId);
        EdlClient openClient = NewClient(openRunner);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => InternalInstallBackup.OpenExistingAsync(openClient, backupDirectory, new Gen5Progress()));

        // Integrity is checked before any probe, so nothing on the device is touched.
        Assert.IsType<InvalidDataException>(error);
        Assert.Empty(openRunner.Reads);
        Assert.Empty(openRunner.ProbedLuns);
        Assert.Equal(0, openRunner.WriteOrResetCount);
    }

    // ---------------------------------------------------------------- helpers

    private EdlClient NewClient(IB001FakeEdlRunner runner) => new(
        _fixture.Toolchain,
        NewBinding(),
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    /// <summary>Synthetic Gen5 identity: no real serial, endpoint or dump is used.</summary>
    private EdlEntryResult NewBinding() => new(
        new AndroidMaintenanceIdentity(
            new DeviceIdentity(E003EdlTestData.SocSerialDecimal, Gen5Model, BootloaderState.Unknown)
            {
                Firmware = new FirmwareSnapshot(
                    Gen5AndroidBuild,
                    BuildFingerprint: Gen5BuildFingerprint,
                    AndroidRelease: Gen5AndroidRelease,
                    SecurityPatch: Gen5SecurityPatch,
                    AndroidReportedBootloaderState: BootloaderState.Locked),
            },
            E003EdlTestData.SocSerialDecimal),
        E003EdlTestData.Endpoint(),
        E003EdlTestData.BusSerialHex);

    /// <summary>A business rejection, never a stub or a reflection artefact.</summary>
    private static void AssertBusinessRejection(Exception? error)
    {
        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.True(
            error is InvalidOperationException || error is InvalidDataException,
            "expected a business InvalidOperation/InvalidData rejection, got " + error!.GetType().FullName +
            ": " + error.Message);
    }

    private static void AssertOnlyGptReads(IB001FakeEdlRunner runner)
    {
        Assert.NotEmpty(runner.Reads);
        foreach (IB001Read read in runner.Reads)
        {
            Assert.Equal(IB001SyntheticDevice.GptSectors, read.SectorCount);
        }
    }

    private static void FlipFirstByte(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        int original = stream.ReadByte();
        Assert.InRange(original, 0, 255);
        stream.Position = 0;
        stream.WriteByte((byte)(original ^ 0xFF));
        stream.Flush();
    }

    private static string HashFile(string path)
    {
        using FileStream stream = File.OpenRead(path);
        using SHA256 sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream));
    }

    private sealed class Gen5Progress : IProgress<InternalBackupProgress>
    {
        public List<InternalBackupProgress> Events { get; } = new();

        public void Report(InternalBackupProgress value)
        {
            if (value is not null)
            {
                Events.Add(value);
            }
        }
    }
}
