using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// BM02 focused cases: <c>InternalInstallBackup.OpenBootMaintenanceOriginalAsync</c> must load a
/// historical SOURCE backup of the same device, keep the source's own Android build, prove the same six LUN
/// geometry and the exact current per-slot maintenance chain, and never touch the target.
/// <para>
/// Every case builds real synthetic backups through the production <c>CreateAsync</c> factory over the shared
/// <see cref="IB001SyntheticDevice"/> fixture, disposes the creating set, and then loads the source against a
/// separately captured "current" backup whose client still holds the same <see cref="EdlClient.Binding"/>.
/// The loader is internal and the test assembly has no InternalsVisibleTo, so <see cref="OpenSourceAsync"/>
/// binds that exact production method once by reflection; the behaviour under test is unchanged.
/// The PROJECT template cases bind <c>OpenBootMaintenanceProjectTemplateAsync</c> the same way and prove that
/// only the per-role chain-byte guard is released while every identity, geometry, extent and own-hash proof holds.
/// No real device, process, USB endpoint or actual backup is involved; the manager runs these tests remotely.
/// </para>
/// </summary>
public sealed class BootMaintenanceOriginalSourceTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string ManifestFileName = "backup-manifest.json";
    private const string SidecarSuffix = ".sha256";

    /// <summary>
    /// The exact production entry point, bound once by reflection because it is internal to
    /// <see cref="InternalInstallBackup"/> and this assembly may not see internals. Only the call is routed;
    /// every argument, result and rejection is the real implementation's.
    /// </summary>
    private static readonly MethodInfo OpenBootMaintenanceOriginal = typeof(InternalInstallBackup).GetMethod(
        "OpenBootMaintenanceOriginalAsync",
        BindingFlags.Static | BindingFlags.NonPublic,
        binder: null,
        types: new[] { typeof(EdlClient), typeof(InternalBackupSet), typeof(string), typeof(CancellationToken) },
        modifiers: null)
        ?? throw new InvalidOperationException(
            "InternalInstallBackup.OpenBootMaintenanceOriginalAsync(EdlClient, InternalBackupSet, string, " +
            "CancellationToken) is missing; the boot-maintenance source loader cannot be exercised.");

    // The historical source build: a real TB322FC firmware, deliberately not the 259 loader profile build.
    private const string HistoricalAndroidBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
    private const string HistoricalBuildFingerprint = "Lenovo/TB322FC/TB322FC:15/TEST/120:user/release-keys";

    private const string AndroidSerial = "SN0123456789";

    private readonly EdlClientToolchainFixture _fixture;

    public BootMaintenanceOriginalSourceTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    [Theory]
    [InlineData("vendor_boot_b")]
    [InlineData("init_boot_b")]
    [InlineData("abl_b")]
    public async Task Project_template_loads_an_ota_era_source_whose_old_bytes_the_original_loader_rejects(string role)
    {
        string name = nameof(Project_template_loads_an_ota_era_source_whose_old_bytes_the_original_loader_rejects) +
                      "-" + role;
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(name + "-source", device);

        // The OTA legitimately rewrote this slot on the device: the template stays self-consistent with its
        // own old bytes (own hash, manifest hash and sidecar all updated) while the current device differs.
        RewritePayload(source, role, bytes =>
        {
            bytes[0] ^= 0xFF;
            return bytes;
        });

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(name + "-current", device);
        using InternalBackupSet currentBackup = current;

        // The stock OEM loader must still refuse this exact directory: it pins chain bytes to the capture.
        await RejectAsync(client, runner, currentBackup, source);

        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;
        string manifestPath = Path.Combine(source, ManifestFileName);
        string manifestSha = HashFile(manifestPath);

        using InternalBackupSet loaded = await OpenSourceAsync(
            client, currentBackup, source, projectTemplate: true);

        // The template metadata is the historical source's own authentic fact, bound to the live session.
        Assert.Same(client.Binding, loaded.Binding);
        Assert.Equal(source, loaded.DirectoryPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestPath, loaded.ManifestPath, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(manifestSha, loaded.ManifestSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(HistoricalAndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);
        Assert.NotEqual(currentBackup.AndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);

        // The rewritten role is the one place the template may differ from the current capture.
        Assert.NotEqual(
            currentBackup.Files[role].Sha256, loaded.Files[role].Sha256, StringComparer.OrdinalIgnoreCase);

        // The template load itself reads, writes, probes and resets nothing on the target.
        Assert.Equal(commandsBefore, runner.Commands.Count);
        Assert.Equal(readsBefore, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(0, runner.ResetCount);
    }

    [Fact]
    public async Task Project_template_rejects_a_manifest_of_another_device_identity()
    {
        const string Name = nameof(Project_template_rejects_a_manifest_of_another_device_identity);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(Name + "-source", device);

        // Self-consistent manifest of another serial: identity is proven before any template relaxation.
        RewriteManifest(source, root =>
        {
            JsonObject identity = root["identity"]!.AsObject();
            identity["androidSerial"] = "DIFFERENT";
        });

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", device);
        using InternalBackupSet currentBackup = current;

        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;

        Exception? error = await Record.ExceptionAsync(() => OpenSourceAsync(
            client, currentBackup, source, projectTemplate: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error!);
        Assert.Equal(commandsBefore, runner.Commands.Count);
        Assert.Equal(readsBefore, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(0, runner.ResetCount);
        AssertNoLeaseHeld(source);
    }

    [Fact]
    public async Task Project_template_rejects_a_payload_that_no_longer_matches_its_own_manifest()
    {
        const string Name = nameof(Project_template_rejects_a_payload_that_no_longer_matches_its_own_manifest);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(Name + "-source", device);

        // Flip a real source payload file without restating it in the manifest: the template still re-hashes
        // every source file against its own manifest exactly like the original loader.
        string staleRole = "vendor_boot_b";
        FlipByte(Path.Combine(source, staleRole + ".bin"), 0);

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", device);
        using InternalBackupSet currentBackup = current;

        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;

        Exception? error = await Record.ExceptionAsync(() => OpenSourceAsync(
            client, currentBackup, source, projectTemplate: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error!);
        Assert.Equal(commandsBefore, runner.Commands.Count);
        Assert.Equal(readsBefore, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(0, runner.ResetCount);
        AssertNoLeaseHeld(source);
    }

    [Fact]
    public async Task Historical_source_is_loaded_from_its_own_manifest_and_never_from_the_current_firmware()
    {
        const string Name =
            nameof(Historical_source_is_loaded_from_its_own_manifest_and_never_from_the_current_firmware);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(Name + "-source", device);

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", device);
        using InternalBackupSet currentBackup = current;

        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;
        string manifestPath = Path.Combine(source, ManifestFileName);
        string manifestSha = HashFile(manifestPath);

        Assert.NotEqual(currentBackup.AndroidBuild, HistoricalAndroidBuild, StringComparer.Ordinal);

        using (InternalBackupSet loaded = await OpenSourceAsync(client, currentBackup, source))
        {
            // The live binding is the live one; the metadata is the source's own authentic profile.
            Assert.Same(client.Binding, loaded.Binding);
            Assert.Equal(source, loaded.DirectoryPath, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(manifestPath, loaded.ManifestPath, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(manifestSha, loaded.ManifestSha256, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(HistoricalAndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);
            Assert.NotEqual(currentBackup.AndroidBuild, loaded.AndroidBuild, StringComparer.Ordinal);
            Assert.Equal(_fixture.Toolchain.ProfileId, loaded.ProfileId, StringComparer.Ordinal);
            Assert.Equal(_fixture.Toolchain.Model, loaded.Model, StringComparer.Ordinal);
            Assert.Equal(_fixture.Toolchain.HardwareId, loaded.HardwareId, StringComparer.OrdinalIgnoreCase);

            Assert.Equal(51, loaded.Files.Count);
            Assert.Equal(currentBackup.Files.Count, loaded.Files.Count);

            for (int lun = 0; lun < 6; lun++)
            {
                Assert.Equal(currentBackup.Geometries[lun], loaded.Geometries[lun]);
                Assert.Equal(currentBackup.Tables[lun].DiskGuid, loaded.Tables[lun].DiskGuid, StringComparer.OrdinalIgnoreCase);
            }

            foreach (string role in currentBackup.Files.Keys)
            {
                EdlCapturedRegion sourceRegion = loaded.Files[role];
                EdlCapturedRegion currentRegion = currentBackup.Files[role];

                Assert.Equal(role, sourceRegion.Role, StringComparer.Ordinal);
                Assert.Equal(currentRegion.Lun, sourceRegion.Lun);
                Assert.Equal(currentRegion.StartSector, sourceRegion.StartSector);
                Assert.Equal(currentRegion.SectorCount, sourceRegion.SectorCount);
                Assert.Equal(currentRegion.SectorSize, sourceRegion.SectorSize);
                Assert.Equal(currentRegion.Length, sourceRegion.Length);
                Assert.Equal(currentRegion.PartUuid, sourceRegion.PartUuid, StringComparer.OrdinalIgnoreCase);
                Assert.True(
                    sourceRegion.FilePath.StartsWith(source, StringComparison.OrdinalIgnoreCase),
                    "the loaded region must be the source file: " + sourceRegion.FilePath);
            }

            // The whole per-slot boot chain is byte identical, so this source may be restored.
            foreach (string role in new[] { "vendor_boot_a", "vendor_boot_b", "init_boot_a", "init_boot_b", "abl_a", "abl_b" })
            {
                Assert.Equal(
                    currentBackup.Files[role].Sha256, loaded.Files[role].Sha256, StringComparer.OrdinalIgnoreCase);
            }

            // Reopening the source reads, writes, probes and resets nothing on the target.
            Assert.Equal(commandsBefore, runner.Commands.Count);
            Assert.Equal(readsBefore, runner.Reads.Count);
            Assert.Equal(0, runner.WriteOrResetCount);
            Assert.Equal(0, runner.ResetCount);
        }

        Assert.Equal(manifestSha, HashFile(manifestPath), StringComparer.OrdinalIgnoreCase);
        AssertNoLeaseHeld(source);
    }

    [Fact]
    public async Task Historical_source_allows_a_userdata_resize_while_the_boot_extents_stay_identical()
    {
        const string Name =
            nameof(Historical_source_allows_a_userdata_resize_while_the_boot_extents_stay_identical);

        // The historical GPT predates the Linux resize: userdata sits somewhere else, nothing else moved.
        IB001SyntheticDevice sourceDevice = IB001SyntheticDevice.Create(
            startOf: name => string.Equals(name, "userdata", StringComparison.Ordinal) ? 6000L : (long?)null);
        string source = await CreateSourceAsync(Name + "-source", sourceDevice);

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", IB001SyntheticDevice.Create());
        using InternalBackupSet currentBackup = current;

        using InternalBackupSet loaded = await OpenSourceAsync(client, currentBackup, source);

        DiskPartition sourceUserdata = loaded.Lun0Layout.Partitions.Single(p => p.Name == "userdata");
        DiskPartition currentUserdata = currentBackup.Lun0Layout.Partitions.Single(p => p.Name == "userdata");

        Assert.Equal(6000L, sourceUserdata.StartSector);
        Assert.NotEqual(currentUserdata.StartSector, sourceUserdata.StartSector);
        Assert.NotEqual(
            currentBackup.Tables[0].SourceFingerprint, loaded.Tables[0].SourceFingerprint, StringComparer.Ordinal);

        // Only the userdata window moved: every maintenance role still covers the current extent and bytes.
        foreach (string slot in new[] { "a", "b" })
        {
            foreach (string stem in new[]
                     {
                         "boot", "vendor_boot", "init_boot", "abl", "xbl_config", "vbmeta", "vbmeta_system", "recovery",
                     })
            {
                string role = stem + "_" + slot;
                Assert.Equal(currentBackup.Files[role].StartSector, loaded.Files[role].StartSector);
                Assert.Equal(currentBackup.Files[role].SectorCount, loaded.Files[role].SectorCount);
            }
        }

        Assert.Equal(0, runner.WriteOrResetCount);
    }

    [Theory]
    [InlineData("serial")]
    [InlineData("soc")]
    [InlineData("bus")]
    [InlineData("sahara")]
    public async Task Historical_source_rejects_a_different_device_identity(string variant)
    {
        string name = nameof(Historical_source_rejects_a_different_device_identity) + "-" + variant;
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(name + "-source", device);

        RewriteManifest(source, root =>
        {
            JsonObject identity = root["identity"]!.AsObject();

            switch (variant)
            {
                case "serial":
                    identity["androidSerial"] = "SNDIFFERENT";
                    break;
                case "soc":
                    identity["socSerialDecimal"] = "123456789";
                    break;
                case "bus":
                    identity["busSerialHex"] = "DEADBEEF";
                    break;
                case "sahara":
                    identity["hasInitialSaharaProof"] = false;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(variant));
            }
        });

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(name + "-current", device);
        using InternalBackupSet currentBackup = current;

        await RejectAsync(client, runner, currentBackup, source);
    }

    [Theory]
    [InlineData("vendor_boot_b")]
    [InlineData("init_boot_b")]
    [InlineData("abl_b")]
    public async Task Historical_source_rejects_a_changed_slot_b_chain_even_when_slot_a_still_matches(string role)
    {
        string name = nameof(Historical_source_rejects_a_changed_slot_b_chain_even_when_slot_a_still_matches) +
                      "-" + role;
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(name + "-source", device);

        // Self-consistent again (payload, manifest hash and sidecar), so only the chain comparison can refuse it.
        RewritePayload(source, role, bytes =>
        {
            bytes[0] ^= 0xFF;
            return bytes;
        });

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(name + "-current", device);
        using InternalBackupSet currentBackup = current;

        await RejectAsync(client, runner, currentBackup, source);
    }

    [Fact]
    public async Task Historical_source_rejects_a_relocated_maintenance_role()
    {
        const string Name = nameof(Historical_source_rejects_a_relocated_maintenance_role);

        // Same disks, same totals, same disk GUIDs: only the recovery_b extent moved.
        IB001SyntheticDevice sourceDevice = IB001SyntheticDevice.Create(
            startOf: name => string.Equals(name, "recovery_b", StringComparison.Ordinal) ? 6000L : (long?)null);
        string source = await CreateSourceAsync(Name + "-source", sourceDevice);

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", IB001SyntheticDevice.Create());
        using InternalBackupSet currentBackup = current;

        await RejectAsync(client, runner, currentBackup, source);

        // The looser template hash rule must not become an extent bypass: a relocated role is refused too.
        int commandsAfterReject = runner.Commands.Count;
        int readsAfterReject = runner.Reads.Count;

        Exception? templateError = await Record.ExceptionAsync(() => OpenSourceAsync(
            client, currentBackup, source, projectTemplate: true));

        Assert.NotNull(templateError);
        Assert.IsNotType<NotImplementedException>(templateError!);
        Assert.Equal(commandsAfterReject, runner.Commands.Count);
        Assert.Equal(readsAfterReject, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(0, runner.ResetCount);
        AssertNoLeaseHeld(source);
    }

    [Fact]
    public async Task Historical_source_rejects_a_capture_of_another_disk_geometry()
    {
        const string Name = nameof(Historical_source_rejects_a_capture_of_another_disk_geometry);

        // The archive layout grows LUN0 to the whole disk, so the six LUN geometries no longer agree.
        string source = await CreateSourceAsync(
            Name + "-source", IB001SyntheticDevice.Create(archiveLayout: true));

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", IB001SyntheticDevice.Create());
        using InternalBackupSet currentBackup = current;

        await RejectAsync(client, runner, currentBackup, source);
    }

    [Theory]
    [InlineData("payload")]
    [InlineData("sidecar")]
    public async Task Historical_source_rejects_changed_bytes_or_a_changed_sidecar(string variant)
    {
        string name = nameof(Historical_source_rejects_changed_bytes_or_a_changed_sidecar) + "-" + variant;
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(name + "-source", device);

        if (string.Equals(variant, "payload", StringComparison.Ordinal))
        {
            // The manifest still names the old hash: the source itself is no longer the verified capture.
            FlipByte(Path.Combine(source, "misc.bin"), 0);
        }
        else
        {
            File.WriteAllBytes(
                Path.Combine(source, ManifestFileName) + SidecarSuffix,
                Encoding.ASCII.GetBytes(new string('0', 64) + "\n"));
        }

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(name + "-current", device);
        using InternalBackupSet currentBackup = current;

        await RejectAsync(client, runner, currentBackup, source);
    }

    [Fact]
    public async Task Historical_source_precancel_opens_nothing_and_touches_nothing()
    {
        const string Name = nameof(Historical_source_precancel_opens_nothing_and_touches_nothing);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(Name + "-source", device);

        (EdlClient client, IB001FakeEdlRunner runner, InternalBackupSet current) =
            await CreateCurrentAsync(Name + "-current", device);
        using InternalBackupSet currentBackup = current;

        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;
        string manifestSha = HashFile(Path.Combine(source, ManifestFileName));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        Exception? error = await Record.ExceptionAsync(() => OpenSourceAsync(
            client, currentBackup, source, cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.Equal(commandsBefore, runner.Commands.Count);
        Assert.Equal(readsBefore, runner.Reads.Count);
        Assert.Equal(manifestSha, HashFile(Path.Combine(source, ManifestFileName)), StringComparer.OrdinalIgnoreCase);
        AssertNoLeaseHeld(source);
    }

    [Fact]
    public async Task Historical_source_rejects_a_current_backup_of_another_session()
    {
        const string Name = nameof(Historical_source_rejects_a_current_backup_of_another_session);
        IB001SyntheticDevice device = IB001SyntheticDevice.Create();
        string source = await CreateSourceAsync(Name + "-source", device);

        var captured = await CreateCurrentAsync(Name + "-current", device);
        using InternalBackupSet currentBackup = captured.Current;

        // A second client over the very same identity values is still a different session and a different binding.
        IB001FakeEdlRunner otherRunner = new(device);
        EdlClient otherClient = NewClient(otherRunner, CurrentFirmware());

        Exception? error = await Record.ExceptionAsync(
            () => OpenSourceAsync(otherClient, currentBackup, source));

        Assert.IsType<ArgumentException>(error);
        Assert.Empty(otherRunner.Commands);
        Assert.Equal(0, otherRunner.WriteOrResetCount);
        AssertNoLeaseHeld(source);
    }

    // --------------------------------------------------------------------------- helpers

    /// <summary>
    /// Calls the real, internal <c>InternalInstallBackup.OpenBootMaintenanceOriginalAsync</c> through the
    /// bound <see cref="MethodInfo"/>. A guard that rejects before the first await surfaces synchronously as
    /// <see cref="TargetInvocationException"/>; its own exception is rethrown instead so callers and
    /// <see cref="Record"/> observe the production type.
    /// </summary>
    private static Task<InternalBackupSet> OpenSourceAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string backupDirectory,
        CancellationToken token = default,
        bool projectTemplate = false)
    {
        // TEST-ONLY routing: the bool only selects which internal production entry point this adapter
        // invokes; it carries no production authority and never reaches the implementation.
        MethodInfo method = projectTemplate
            ? typeof(InternalInstallBackup).GetMethod(
                "OpenBootMaintenanceProjectTemplateAsync",
                BindingFlags.Static | BindingFlags.NonPublic,
                binder: null,
                types: new[] { typeof(EdlClient), typeof(InternalBackupSet), typeof(string), typeof(CancellationToken) },
                modifiers: null)
                ?? throw new InvalidOperationException(
                    "InternalInstallBackup.OpenBootMaintenanceProjectTemplateAsync(EdlClient, InternalBackupSet, " +
                    "string, CancellationToken) is missing; the template loader cannot be exercised.")
            : OpenBootMaintenanceOriginal;

        object? invoked;
        try
        {
            invoked = method.Invoke(
                obj: null,
                parameters: new object?[] { client, currentBackup, backupDirectory, token });
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException!).Throw();
            throw;
        }

        Task<InternalBackupSet>? task = invoked as Task<InternalBackupSet>;
        if (task is null)
        {
            throw new InvalidOperationException(
                "InternalInstallBackup.OpenBootMaintenanceOriginalAsync did not return a backup set task.");
        }

        return task;
    }

    private async Task<string> CreateSourceAsync(string caseName, IB001SyntheticDevice device)
    {
        EdlClient client = NewClient(new IB001FakeEdlRunner(device), HistoricalFirmware());
        using InternalBackupSet source = await InternalInstallBackup.CreateAsync(
            client, _fixture.NewCaseDirectory(caseName));
        return source.DirectoryPath;
    }

    private async Task<(EdlClient Client, IB001FakeEdlRunner Runner, InternalBackupSet Current)> CreateCurrentAsync(
        string caseName,
        IB001SyntheticDevice device)
    {
        IB001FakeEdlRunner runner = new(device);
        EdlClient client = NewClient(runner, CurrentFirmware());
        InternalBackupSet current = await InternalInstallBackup.CreateAsync(
            client, _fixture.NewCaseDirectory(caseName));
        return (client, runner, current);
    }

    private async Task<Exception> RejectAsync(
        EdlClient client,
        IB001FakeEdlRunner runner,
        InternalBackupSet currentBackup,
        string source)
    {
        int commandsBefore = runner.Commands.Count;
        int readsBefore = runner.Reads.Count;

        Exception? error = await Record.ExceptionAsync(() => OpenSourceAsync(client, currentBackup, source));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error!);
        Assert.Equal(commandsBefore, runner.Commands.Count);
        Assert.Equal(readsBefore, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
        Assert.Equal(0, runner.ResetCount);
        AssertNoLeaseHeld(source);
        return error!;
    }

    private EdlClient NewClient(IB001FakeEdlRunner runner, FirmwareSnapshot firmware) => new(
        _fixture.Toolchain,
        new EdlEntryResult(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(AndroidSerial, _fixture.Toolchain.Model, BootloaderState.Unknown)
                {
                    Firmware = firmware,
                },
                E003EdlTestData.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex),
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private static FirmwareSnapshot HistoricalFirmware() => new(
        HistoricalAndroidBuild,
        BuildFingerprint: HistoricalBuildFingerprint,
        AndroidRelease: "15",
        SecurityPatch: "2026-06-01",
        AndroidReportedBootloaderState: BootloaderState.Locked);

    private FirmwareSnapshot CurrentFirmware() => new(
        _fixture.Toolchain.AndroidBuild,
        BuildFingerprint: "Lenovo/TB322FC/TB322FC:15/TP1A.220905.001/259:user/release-keys",
        AndroidRelease: "15",
        SecurityPatch: "2026-07-01",
        AndroidReportedBootloaderState: BootloaderState.Unlocked);

    private static void RewritePayload(string backupDirectory, string role, Func<byte[], byte[]> mutate)
    {
        string path = Path.Combine(backupDirectory, role + ".bin");
        byte[] bytes = File.ReadAllBytes(path);
        byte[] changed = mutate(bytes);
        Assert.Equal(bytes.Length, changed.Length);
        File.WriteAllBytes(path, changed);

        string sha = HashFile(path);
        RewriteManifest(backupDirectory, root =>
        {
            foreach (JsonNode? node in root["files"]!.AsArray())
            {
                JsonObject file = node!.AsObject();
                if (string.Equals((string?)file["role"], role, StringComparison.Ordinal))
                {
                    file["sha256"] = sha;
                }
            }
        });
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
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }
}
