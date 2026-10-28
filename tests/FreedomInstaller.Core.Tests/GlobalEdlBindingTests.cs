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
/// G1-TESTS-03. Offline 9008 binding candidate proof and raw one-sector geometry probe behavior.
/// <para>
/// Only the transport boundary is faked (<see cref="E003FakeCommandRunner"/> and
/// <see cref="E003ScriptedEndpointDiscovery"/>); the production <see cref="GlobalEdlBinding"/> and
/// <see cref="EdlClient"/> are the objects under test. No process, client binary or device is touched and
/// every artifact lives below the fixture's own case directory.
/// </para>
/// </summary>
public sealed class GlobalEdlBindingTests : IClassFixture<EdlClientToolchainFixture>
{
    private static readonly TimeSpan ProbeInitialTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ProbeWarmTimeout = TimeSpan.FromSeconds(30);

    private readonly EdlClientToolchainFixture _fixture;

    public GlobalEdlBindingTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ------------------------------------------------------------------ offline binding candidate

    [Fact]
    public void Attach_valid_known_profile_one_endpoint_is_offline_candidate_only()
    {
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);

        Assert.Equal(1, discovery.ReadCount);
        Assert.Null(binding.AndroidIdentity);
        Assert.Equal(E003EdlTestData.BusSerialHex, binding.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.DeviceInstanceId, binding.Endpoint.DeviceInstanceId);

        GlobalEdlIdentity offline = Assert.IsType<GlobalEdlIdentity>(binding.OfflineIdentity);
        Assert.Equal(_fixture.Toolchain.Profile.ProfileId, offline.ProfileId);
        Assert.Equal(_fixture.Toolchain.Profile.Model, offline.Model);
        Assert.Equal(_fixture.Toolchain.HardwareId, offline.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, offline.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Null(offline.AndroidSerial);
        Assert.Null(offline.FirmwareDisplayId);

        // The exact known registry object is what the binding trusted, not a copy.
        Assert.Same(
            _fixture.Toolchain.Profile,
            EdlDeviceProfiles.FindById(_fixture.Toolchain.Profile.ProfileId));

        // Candidate only: nothing has been proven about the hardware until a real probe runs.
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        Assert.False(client.HasInitialSaharaProof);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public void Attach_expected_lowercase_same_bus_is_accepted_and_reported_normalized()
    {
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(
            _fixture.Toolchain.Profile,
            discovery,
            E003EdlTestData.BusSerialHex.ToLowerInvariant());

        Assert.Equal(1, discovery.ReadCount);
        Assert.Equal(E003EdlTestData.BusSerialHex, binding.BusSerialHex, StringComparer.Ordinal);
        Assert.Equal(
            E003EdlTestData.BusSerialHex,
            binding.OfflineIdentity!.BusSerialHex,
            StringComparer.Ordinal);
    }

    [Fact]
    public void Attach_duplicate_same_instance_same_serial_is_accepted()
    {
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[]
            {
                E003EdlTestData.Endpoint(),
                E003EdlTestData.Endpoint(),
            },
        };

        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);

        Assert.Equal(1, discovery.ReadCount);
        Assert.Equal(E003EdlTestData.BusSerialHex, binding.BusSerialHex, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Attach_two_distinct_physical_instances_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[]
            {
                E003EdlTestData.Endpoint(),
                E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
            },
        };

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery));
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public void Attach_conflicting_duplicate_serial_on_one_instance_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[]
            {
                E003EdlTestData.Endpoint(),
                E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:DEADBEEF"),
            },
        };

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery));
        Assert.Equal(1, discovery.ReadCount);
    }

    [Theory]
    [InlineData("QUSB_BULK_CID:045A_SN:00000000")]
    [InlineData("QUSB_BULK_CID:045A_SN:FFFFFFFF")]
    [InlineData("QUSB_BULK_CID:045A_SN:E3E8547")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F40")]
    [InlineData("QUSB_BULK_CID:045A_SN:E3E8547Z")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F4_SN:C1D2E3F4")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F4-x")]
    public void Attach_malformed_bus_serial_rejected(string description)
    {
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[] { E003EdlTestData.Endpoint(description: description) },
        };

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery));
        Assert.Equal(1, discovery.ReadCount);
    }

    [Theory]
    [InlineData("00000000")]
    [InlineData("FFFFFFFF")]
    [InlineData("E3E8547")]
    [InlineData("C1D2E3F40")]
    [InlineData("E3E8547Z")]
    public void Attach_malformed_expected_serial_rejected_before_any_read(string expected)
    {
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery, expected));
        Assert.Equal(0, discovery.ReadCount);
    }

    [Fact]
    public void Attach_expected_serial_mismatch_rejected_after_the_single_read()
    {
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery, "DEADBEEF"));
        Assert.Equal(1, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ raw geometry success

    [Fact]
    public async Task Raw_initial_probe_LUN0_zero_file_without_gpt_log_proves_the_session()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_initial_probe_LUN0_zero_file_without_gpt_log_proves_the_session));
        string outputPath = Path.Combine(caseDirectory, "raw-lun0.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        string log = RawLog(
            E003EdlTestData.BusSerialHex,
            SaharaText(E003EdlTestData.BusSerialHex, _fixture.Toolchain.HardwareId, includeLoaderMarker: true),
            RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, E003EdlTestData.SectorSize),
            PlanLine(0, 0, 1, E003EdlTestData.SectorSize, outputPath),
            E003EdlTestData.SectorSize);

        // The protocol log carries real storage_info and both read ACKs but no GPT header and no printgpt.
        Assert.DoesNotContain("--- GPT Header", log, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("printgpt", log, StringComparison.Ordinal);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            log,
            sideEffect: command => File.WriteAllBytes(
                command.Arguments[3],
                new byte[E003EdlTestData.SectorSize]));

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath);

        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), evidence.Geometry);
        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(_fixture.Toolchain.HardwareId, evidence.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(0, evidence.Command.ExitCode);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(1, runner.CallCount);

        ProcessCommand command = runner.Commands[0];
        Assert.Equal(_fixture.Toolchain.ClientPath, command.Executable);
        Assert.Equal(ProbeInitialTimeout, command.Timeout);
        Assert.True(Path.IsPathFullyQualified(command.Arguments[3]));
        Assert.Equal(outputPath, command.Arguments[3]);
        Assert.Equal(
            WithGlobals("read-sector", "0", "1", outputPath, "--lun", "0"),
            command.Arguments);
        Assert.DoesNotContain("printgpt", command.Arguments);
        Assert.DoesNotContain("write-sector", command.Arguments);
        Assert.DoesNotContain("reset", command.Arguments);

        // Exact bytes of the single-sector artifact: an all-zero file is accepted, no GPT signature needed.
        byte[] bytes = File.ReadAllBytes(outputPath);
        Assert.Equal(E003EdlTestData.SectorSize, bytes.Length);
        Assert.All(bytes, value => Assert.Equal(0, (int)value));
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(new byte[E003EdlTestData.SectorSize])),
            Convert.ToHexString(SHA256.HashData(bytes)),
            StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Raw_initial_probe_512_byte_sector_success()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Raw_initial_probe_512_byte_sector_success));
        string outputPath = Path.Combine(caseDirectory, "raw-512.bin");
        const int sectorSize = 512;

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        string log = RawLog(
            E003EdlTestData.BusSerialHex,
            SaharaText(E003EdlTestData.BusSerialHex, _fixture.Toolchain.HardwareId, includeLoaderMarker: true),
            RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, sectorSize),
            PlanLine(0, 0, 1, sectorSize, outputPath),
            sectorSize);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(log, sideEffect: command => File.WriteAllBytes(command.Arguments[3], new byte[sectorSize]));

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath);

        Assert.Equal(new EdlGeometry(0, sectorSize, E003EdlTestData.InitialTotalSectors), evidence.Geometry);
        Assert.Equal(sectorSize, (int)new FileInfo(outputPath).Length);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(
            WithGlobals("read-sector", "0", "1", outputPath, "--lun", "0"),
            runner.Commands[0].Arguments);
    }

    [Fact]
    public async Task Raw_warm_probe_LUN4_without_sahara_keeps_geometry_owned_per_LUN()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_warm_probe_LUN4_without_sahara_keeps_geometry_owned_per_LUN));
        string initialPath = Path.Combine(caseDirectory, "initial-lun0.bin");
        string warmPath = Path.Combine(caseDirectory, "warm-lun4.bin");
        string readPath = Path.Combine(caseDirectory, "readback-lun0.bin");
        byte[] readPayload = new byte[E003EdlTestData.SectorSize];

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            RawLog(
                E003EdlTestData.BusSerialHex,
                SaharaText(E003EdlTestData.BusSerialHex, _fixture.Toolchain.HardwareId, includeLoaderMarker: true),
                RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, E003EdlTestData.SectorSize),
                PlanLine(0, 0, 1, E003EdlTestData.SectorSize, initialPath),
                E003EdlTestData.SectorSize),
            sideEffect: command => File.WriteAllBytes(
                command.Arguments[3],
                new byte[E003EdlTestData.SectorSize]));

        // The warm probe deliberately has no Sahara section at all.
        string warmLog = RawLog(
            E003EdlTestData.BusSerialHex,
            null,
            RawGeometryLines(4, E003EdlTestData.WarmLun4TotalSectors, E003EdlTestData.SectorSize),
            PlanLine(4, 0, 1, E003EdlTestData.SectorSize, warmPath),
            E003EdlTestData.SectorSize);
        Assert.DoesNotContain("Sahara", warmLog, StringComparison.Ordinal);
        Assert.DoesNotContain("Serial Number:", warmLog, StringComparison.Ordinal);

        runner.Enqueue(
            warmLog,
            sideEffect: command => File.WriteAllBytes(
                command.Arguments[3],
                new byte[E003EdlTestData.SectorSize]));

        runner.Enqueue(
            E003EdlTestData.ReadSuccess(0, 0, 1, readPayload.Length, readPath),
            sideEffect: command => File.WriteAllBytes(command.Arguments[3], readPayload));

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        EdlProbeEvidence initial = await client.ProbeRawGeometryAsync(0, initialLoader: true, initialPath);
        EdlProbeEvidence warm = await client.ProbeRawGeometryAsync(4, initialLoader: false, warmPath);

        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), initial.Geometry);
        Assert.Equal(new EdlGeometry(4, 4096, E003EdlTestData.WarmLun4TotalSectors), warm.Geometry);
        Assert.Null(warm.SaharaSerialHex);
        Assert.Null(warm.HardwareId);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(2, runner.CallCount);

        Assert.Equal(ProbeWarmTimeout, runner.Commands[1].Timeout);
        Assert.Equal(
            WithGlobals("read-sector", "0", "1", warmPath, "--lun", "4"),
            runner.Commands[1].Arguments);

        // A normal read on LUN 0 still uses the LUN 0 geometry; the warm LUN 4 probe did not overwrite it.
        EdlReadEvidence read = await client.ReadAsync(0, 0, 1, readPath);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), read.Geometry);
        Assert.Equal((long)readPayload.Length, read.Length);
    }

    [Fact]
    public async Task Raw_probe_accepts_a_normal_android_binding_not_only_offline()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_probe_accepts_a_normal_android_binding_not_only_offline));
        string outputPath = Path.Combine(caseDirectory, "android-raw.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        string log = RawLog(
            E003EdlTestData.BusSerialHex,
            SaharaText(E003EdlTestData.BusSerialHex, _fixture.Toolchain.HardwareId, includeLoaderMarker: true),
            RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, E003EdlTestData.SectorSize),
            PlanLine(0, 0, 1, E003EdlTestData.SectorSize, outputPath),
            E003EdlTestData.SectorSize);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(log, sideEffect: command => File.WriteAllBytes(
            command.Arguments[3],
            new byte[E003EdlTestData.SectorSize]));

        EdlClient client = new EdlClient(_fixture.Toolchain, NewAndroidBinding(), runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath);

        Assert.Null(client.Binding.OfflineIdentity);
        Assert.NotNull(client.Binding.AndroidIdentity);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), evidence.Geometry);
        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(1, runner.CallCount);
    }

    // ------------------------------------------------------------------ raw geometry failures

    [Theory]
    [InlineData("wrongHWID")]
    [InlineData("wrongbus")]
    [InlineData("wrongSaharaSN")]
    [InlineData("missingloaderstarted")]
    [InlineData("missinginitialACK")]
    [InlineData("missingfinalACK")]
    [InlineData("missingStorageInfo")]
    [InlineData("mismatchedgeometryLUN")]
    [InlineData("wrongreadLUN")]
    [InlineData("wrongreadrange")]
    [InlineData("wrongreportedpath")]
    [InlineData("missingplan")]
    [InlineData("unsupported8192sector")]
    [InlineData("wrongreportedbytes")]
    [InlineData("shortfile")]
    [InlineData("oversizedfile")]
    [InlineData("missingfile")]
    public async Task Raw_initial_failure_rejects_without_proof_and_warm_stays_blocked(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_initial_failure_rejects_without_proof_and_warm_stays_blocked) + "-" + variant);
        string outputPath = Path.Combine(caseDirectory, "raw.bin");
        string otherPath = Path.Combine(caseDirectory, "other.bin");
        string warmPath = Path.Combine(caseDirectory, "warm.bin");

        int geometryLun = 0;
        int sectorSize = E003EdlTestData.SectorSize;
        long planStart = 0;
        long planCount = 1;
        int planLun = 0;
        long reportedBytes = E003EdlTestData.SectorSize;
        string planPath = outputPath;
        string selectedSerial = E003EdlTestData.BusSerialHex;
        string saharaSerial = E003EdlTestData.BusSerialHex;
        string hwid = _fixture.Toolchain.HardwareId;
        bool includeLoaderMarker = true;
        bool includeStoragePayload = true;
        bool includeInitialAck = true;
        bool includeFinalAck = true;
        bool includePlan = true;
        byte[]? fileBytes = new byte[E003EdlTestData.SectorSize];

        switch (variant)
        {
            case "wrongHWID":
                hwid = "0028000000000000";
                break;
            case "wrongbus":
                selectedSerial = "DEADBEEF";
                break;
            case "wrongSaharaSN":
                saharaSerial = "DEADBEEF";
                break;
            case "missingloaderstarted":
                includeLoaderMarker = false;
                break;
            case "missinginitialACK":
                includeInitialAck = false;
                break;
            case "missingfinalACK":
                includeFinalAck = false;
                break;
            case "missingStorageInfo":
                includeStoragePayload = false;
                break;
            case "mismatchedgeometryLUN":
                geometryLun = 3;
                break;
            case "wrongreadLUN":
                planLun = 4;
                break;
            case "wrongreadrange":
                planStart = 8;
                planCount = 2;
                reportedBytes = 2L * E003EdlTestData.SectorSize;
                break;
            case "wrongreportedpath":
                planPath = otherPath;
                break;
            case "missingplan":
                includePlan = false;
                break;
            case "unsupported8192sector":
                sectorSize = 8192;
                reportedBytes = 8192;
                fileBytes = new byte[8192];
                break;
            case "wrongreportedbytes":
                reportedBytes = E003EdlTestData.SectorSize - 1;
                break;
            case "shortfile":
                fileBytes = new byte[E003EdlTestData.SectorSize - 1];
                break;
            case "oversizedfile":
                fileBytes = new byte[E003EdlTestData.SectorSize + 1];
                break;
            case "missingfile":
                fileBytes = null;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant), variant, "unknown raw probe variant");
        }

        string log = RawLog(
            selectedSerial,
            SaharaText(saharaSerial, hwid, includeLoaderMarker),
            RawGeometryLines(
                geometryLun,
                E003EdlTestData.InitialTotalSectors,
                sectorSize,
                includeStoragePayload,
                includeInitialAck,
                includeFinalAck),
            includePlan ? PlanLine(planLun, planStart, planCount, planCount * sectorSize, planPath) : null,
            reportedBytes);

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            log,
            sideEffect: command =>
            {
                if (fileBytes is not null)
                {
                    File.WriteAllBytes(command.Arguments[3], fileBytes);
                }
            });

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);

        Exception initialError = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsNotType<NotImplementedException>(initialError);
        Assert.False(string.IsNullOrWhiteSpace(initialError.Message));
        Assert.False(client.HasInitialSaharaProof);
        Assert.Equal(1, runner.CallCount);

        // A warm probe without the initial proof must fail before the runner sees anything.
        int runnerCalls = runner.CallCount;
        int discoveryReads = discovery.ReadCount;

        Exception warmError = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(4, initialLoader: false, warmPath));

        Assert.IsNotType<NotImplementedException>(warmError);
        Assert.IsType<InvalidOperationException>(warmError);
        Assert.False(client.HasInitialSaharaProof);
        Assert.Equal(runnerCalls, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(File.Exists(warmPath));
    }

    // ------------------------------------------------------------------ raw geometry preflight

    [Fact]
    public async Task Raw_preflight_existing_file_is_rejected_and_left_untouched()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_preflight_existing_file_is_rejected_and_left_untouched));
        string outputPath = Path.Combine(caseDirectory, "occupied.bin");
        byte[] sentinel = { 1, 2, 3, 4, 5, 6, 7, 8 };
        File.WriteAllBytes(outputPath, sentinel);

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsType<IOException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(client.HasInitialSaharaProof);
        Assert.Equal<byte>(sentinel, File.ReadAllBytes(outputPath));
    }

    [Fact]
    public async Task Raw_preflight_existing_directory_is_rejected()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Raw_preflight_existing_directory_is_rejected));
        string outputPath = Path.Combine(caseDirectory, "occupied-dir");
        Directory.CreateDirectory(outputPath);

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsType<IOException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.True(Directory.Exists(outputPath));
    }

    [Fact]
    public async Task Raw_preflight_relative_path_is_rejected()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Raw_preflight_relative_path_is_rejected));
        const string relative = "raw-relative.bin";

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, relative));

        Assert.IsType<IOException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(File.Exists(Path.Combine(caseDirectory, relative)));
    }

    [Fact]
    public async Task Raw_preflight_missing_parent_is_rejected()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Raw_preflight_missing_parent_is_rejected));
        string outputPath = Path.Combine(caseDirectory, "missing-parent", "raw.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsType<IOException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task Raw_preflight_cancelled_token_is_rejected_before_any_read_or_run()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_preflight_cancelled_token_is_rejected_before_any_read_or_run));
        string outputPath = Path.Combine(caseDirectory, "cancelled.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        using CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath, cts.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task Raw_preflight_warm_without_proof_is_rejected_before_path_or_runner()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Raw_preflight_warm_without_proof_is_rejected_before_path_or_runner));
        string outputPath = Path.Combine(caseDirectory, "warm-no-proof.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        int discoveryReads = discovery.ReadCount;

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: false, outputPath));

        Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(discoveryReads, discovery.ReadCount);
        Assert.False(File.Exists(outputPath));
    }

    // ------------------------------------------------------------------ offline identity guards

    [Theory]
    [InlineData("hardware-id")]
    [InlineData("profile-id")]
    [InlineData("model")]
    [InlineData("bus")]
    public async Task Offline_forged_identity_field_is_rejected_before_runner(string field)
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Offline_forged_identity_field_is_rejected_before_runner) + "-" + field);
        string outputPath = Path.Combine(caseDirectory, "forged.bin");

        GlobalEdlIdentity offline = field switch
        {
            "hardware-id" => KnownOfflineIdentity(hardwareId: "0028000000000000"),
            "profile-id" => KnownOfflineIdentity(profileId: "g4-9008-999"),
            "model" => KnownOfflineIdentity(model: "TB999XX"),
            "bus" => KnownOfflineIdentity(busSerialHex: "DEADBEEF"),
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, "unknown forged field"),
        };

        EdlEntryResult binding = new EdlEntryResult(
            null!,
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex)
        {
            OfflineIdentity = offline,
        };

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(RawLog(
            E003EdlTestData.BusSerialHex,
            SaharaText(E003EdlTestData.BusSerialHex, _fixture.Toolchain.HardwareId, includeLoaderMarker: true),
            RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, E003EdlTestData.SectorSize),
            PlanLine(0, 0, 1, E003EdlTestData.SectorSize, outputPath),
            E003EdlTestData.SectorSize));

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsNotType<NotImplementedException>(error);
        Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
        Assert.False(client.HasInitialSaharaProof);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task Offline_mixed_with_a_real_android_identity_is_rejected_before_runner()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Offline_mixed_with_a_real_android_identity_is_rejected_before_runner));
        string outputPath = Path.Combine(caseDirectory, "mixed.bin");

        EdlEntryResult android = NewAndroidBinding();
        EdlEntryResult mixed = new EdlEntryResult(
            android.AndroidIdentity,
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex)
        {
            OfflineIdentity = KnownOfflineIdentity(),
        };

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        EdlClient client = new EdlClient(_fixture.Toolchain, mixed, runner, discovery);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsNotType<NotImplementedException>(error);
        Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
        Assert.False(client.HasInitialSaharaProof);
    }

    [Fact]
    public async Task Offline_exact_profile_but_wrong_initial_hwid_is_still_rejected()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Offline_exact_profile_but_wrong_initial_hwid_is_still_rejected));
        string outputPath = Path.Combine(caseDirectory, "wrong-hwid.bin");

        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlEntryResult binding = GlobalEdlBinding.Attach(_fixture.Toolchain.Profile, discovery);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            RawLog(
                E003EdlTestData.BusSerialHex,
                SaharaText(E003EdlTestData.BusSerialHex, "0028000000000000", includeLoaderMarker: true),
                RawGeometryLines(0, E003EdlTestData.InitialTotalSectors, E003EdlTestData.SectorSize),
                PlanLine(0, 0, 1, E003EdlTestData.SectorSize, outputPath),
                E003EdlTestData.SectorSize),
            sideEffect: command => File.WriteAllBytes(
                command.Arguments[3],
                new byte[E003EdlTestData.SectorSize]));

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);

        Exception error = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(0, initialLoader: true, outputPath));

        Assert.IsNotType<NotImplementedException>(error);
        Assert.False(client.HasInitialSaharaProof);
        Assert.Equal(1, runner.CallCount);

        Exception warmError = await Assert.ThrowsAnyAsync<Exception>(
            () => client.ProbeRawGeometryAsync(4, initialLoader: false, Path.Combine(caseDirectory, "warm.bin")));

        Assert.IsType<InvalidOperationException>(warmError);
        Assert.Equal(1, runner.CallCount);
    }

    // ------------------------------------------------------------------ helpers

    private static string SaharaText(string serial, string hwid, bool includeLoaderMarker)
    {
        string text = "[INFO] Serial Number: " + serial + "\n[INFO] HWID: " + hwid;
        return includeLoaderMarker
            ? text + "\n[INFO] Loader uploaded and started successfully via Sahara."
            : text;
    }

    /// <summary>
    /// Real storage_info/sector/ACK lines for one LUN with every GPT header and printgpt line removed, so
    /// the raw route is proven not to require them.
    /// </summary>
    private static string RawGeometryLines(
        int lun,
        long totalBlocks,
        int sectorSize,
        bool includeStoragePayload = true,
        bool includeInitialAck = true,
        bool includeFinalAck = true)
    {
        IEnumerable<string> kept = E003EdlTestData
            .Geometry(lun, totalBlocks, sectorSize)
            .Split('\n')
            .Where(line =>
                !line.Contains("GPT Header", StringComparison.Ordinal) &&
                !line.Contains("printgpt", StringComparison.Ordinal) &&
                (includeStoragePayload || !line.Contains("\"storage_info\"", StringComparison.Ordinal)) &&
                (includeInitialAck || !line.Contains("Read command ACKed", StringComparison.Ordinal)) &&
                (includeFinalAck || !line.Contains("Final ACK received", StringComparison.Ordinal)));

        return string.Join("\n", kept);
    }

    private static string PlanLine(int lun, long startSector, long sectorCount, long bytes, string path)
    {
        long lastSector = startSector + sectorCount - 1;
        return "[INFO] Preparing to read " + sectorCount + " sectors (LBA " + startSector + " to " +
               lastSector + ", " + bytes + " bytes) from LUN " + lun + " into '" + path + "'...";
    }

    private static string RawLog(
        string selectedSerial,
        string? sahara,
        string geometryBlock,
        string? plan,
        long? reportedBytes)
    {
        List<string> parts = new List<string>
        {
            E003EdlTestData.Selected(busSerial: selectedSerial),
        };

        if (sahara is not null)
        {
            parts.Add(sahara);
        }

        if (geometryBlock.Length > 0)
        {
            parts.Add(geometryBlock);
        }

        if (plan is not null)
        {
            parts.Add(plan);
        }

        if (reportedBytes is not null)
        {
            parts.Add("[INFO] Successfully read and wrote " + reportedBytes.Value + " bytes in 24 ms.");
        }

        parts.Add("[INFO] 'read-sector' command finished");

        return string.Join("\n", parts);
    }

    private static E003ScriptedEndpointDiscovery ValidDiscovery() => new E003ScriptedEndpointDiscovery
    {
        Endpoints = new[] { E003EdlTestData.Endpoint() },
    };

    private GlobalEdlIdentity KnownOfflineIdentity(
        string? profileId = null,
        string? model = null,
        string? hardwareId = null,
        string? busSerialHex = null) => new(
            profileId ?? _fixture.Toolchain.Profile.ProfileId,
            model ?? _fixture.Toolchain.Profile.Model,
            hardwareId ?? _fixture.Toolchain.HardwareId,
            busSerialHex ?? E003EdlTestData.BusSerialHex);

    /// <summary>
    /// Equivalent of the existing EdlClientTests.NewBinding fixture: a real Android maintenance identity
    /// for the staged profile and the same 8-digit hex bus serial the fixture endpoint reports.
    /// </summary>
    private EdlEntryResult NewAndroidBinding() => new(
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
        E003EdlTestData.BusSerialHex);

    private string[] WithGlobals(params string[] head) => head.Concat(new[]
    {
        "--loader", _fixture.Toolchain.FirehosePath,
        "--vid", "05c6",
        "--pid", "9008",
        "--memory", "Ufs",
        "--loglevel", "Debug",
    }).ToArray();
}
