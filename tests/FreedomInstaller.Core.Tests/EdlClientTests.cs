using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Loads the real EDL toolchain once for the whole test class from the bundle named by
/// <c>EDL_TOOLCHAIN_TEST_BUNDLE_PATH</c>. The environment variable is required; a missing value fails the
/// fixture explicitly instead of skipping, so a green run can never mean "nothing was exercised".
/// <para>
/// Every test-owned file lives below a unique directory: <c>EDL_CLIENT_TEST_WORK_ROOT</c> when provided,
/// otherwise the bundle's own parent directory. The toolchain is staged inside that unique root and disposed
/// with the fixture; nothing falls back to a temporary directory or a drive-local default.
/// </para>
/// </summary>
public sealed class EdlClientToolchainFixture : IAsyncLifetime
{
    private EdlToolchain? _toolchain;

    public EdlClientToolchainFixture()
    {
        string? bundle = Environment.GetEnvironmentVariable("EDL_TOOLCHAIN_TEST_BUNDLE_PATH");
        if (string.IsNullOrWhiteSpace(bundle))
        {
            throw new InvalidOperationException(
                "EDL_TOOLCHAIN_TEST_BUNDLE_PATH must name the real EDL toolchain archive; refusing to skip.");
        }

        BundlePath = Path.GetFullPath(bundle);
        if (!File.Exists(BundlePath))
        {
            throw new InvalidOperationException($"EDL toolchain bundle '{BundlePath}' does not exist.");
        }

        string? configuredRoot = Environment.GetEnvironmentVariable("EDL_CLIENT_TEST_WORK_ROOT");
        string parent = string.IsNullOrWhiteSpace(configuredRoot)
            ? Path.GetDirectoryName(BundlePath)!
            : Path.GetFullPath(configuredRoot);

        WorkRoot = Path.Combine(parent, "e003-edlclient-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(WorkRoot);
    }

    public string BundlePath { get; }

    public string WorkRoot { get; }

    public EdlToolchain Toolchain =>
        _toolchain ?? throw new InvalidOperationException("The EDL toolchain was not loaded by the fixture.");

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
/// Deterministic transport fake: records every command and returns scripted results. A scripted side effect
/// may create the read output file at the path the client actually passed, but it never starts a process.
/// </summary>
internal sealed class E003FakeCommandRunner : ICommandRunner
{
    private sealed class Step
    {
        public ProcessResult? Result { get; init; }

        public Exception? Failure { get; init; }

        public Action<ProcessCommand>? SideEffect { get; init; }
    }

    private readonly Queue<Step> _steps = new();
    private readonly List<ProcessCommand> _commands = new();

    public IReadOnlyList<ProcessCommand> Commands => _commands;

    public int CallCount => _commands.Count;

    public E003FakeCommandRunner Enqueue(
        string standardOutput,
        int exitCode = 0,
        string standardError = "",
        Action<ProcessCommand>? sideEffect = null)
    {
        _steps.Enqueue(new Step
        {
            Result = new ProcessResult(exitCode, standardOutput, standardError),
            SideEffect = sideEffect,
        });
        return this;
    }

    public E003FakeCommandRunner EnqueueFailure(Exception failure)
    {
        _steps.Enqueue(new Step { Failure = failure });
        return this;
    }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        _commands.Add(command);
        cancellationToken.ThrowIfCancellationRequested();

        if (_steps.Count == 0)
        {
            throw new InvalidOperationException(
                "E003 fake runner has no scripted result for: " + string.Join(' ', command.Arguments));
        }

        Step step = _steps.Dequeue();
        step.SideEffect?.Invoke(command);

        return step.Failure is not null
            ? Task.FromException<ProcessResult>(step.Failure)
            : Task.FromResult(step.Result!);
    }
}

/// <summary>Scripted endpoint discovery; the endpoint list may change between operations.</summary>
internal sealed class E003ScriptedEndpointDiscovery : IEdlEndpointDiscovery
{
    public IReadOnlyList<EdlEndpoint> Endpoints { get; set; } = Array.Empty<EdlEndpoint>();

    public int ReadCount { get; private set; }

    public IReadOnlyList<EdlEndpoint> ReadPresent()
    {
        ReadCount++;
        return Endpoints;
    }
}

/// <summary>Realistic Firehose log fragments used by the behavioral tests.</summary>
internal static class E003EdlTestData
{
    internal const string BusSerialHex = "C1D2E3F4";
    internal const string SocSerialDecimal = "3251823604";
    internal const string HardwareId = "0028D0E100400000";
    internal const string DeviceInstanceId = @"USB\VID_05C6&PID_9008\8&19888C89&0&8";
    internal const string LowercaseInstanceId = @"USB\VID_05C6&PID_9008\8&19888c89&0&8";
    internal const string OtherInstanceId = @"USB\VID_05C6&PID_9008\8&11112222&0&8";
    internal const string PortName = "COM3";
    internal const string BusDescription = "QUSB_BULK_CID:045A_SN:C1D2E3F4";
    internal const long InitialTotalSectors = 123871232;
    internal const long WarmLun4TotalSectors = 262144;
    internal const int SectorSize = 4096;

    internal static EdlEndpoint Endpoint(
        string description = BusDescription,
        string instanceId = DeviceInstanceId,
        string? portName = PortName) => new(instanceId, portName, description);

    internal static string Selected(string busSerial = BusSerialHex, string instanceLower = "8&19888c89&0&8")
    {
        string description = "QUSB_BULK_CID:045A_SN:" + busSerial;
        return "[INFO] Qualcomm EDL device selected: \\\\?\\usb#vid_05c6&pid_9008#" + instanceLower +
               "#{86e0d1e0-8089-11d0-9ce4-08003e301f73} on bus " + description +
               " (Interface: COM Port, DevInst: 1)\n" +
               "[INFO] Bus Name: " + description;
    }

    internal static string Sahara(string serial = BusSerialHex, string hwid = HardwareId) =>
        "[INFO] Serial Number: " + serial + "\n" +
        "[INFO] HWID: " + hwid + "\n" +
        "[INFO] Loader uploaded and started successfully via Sahara.";

    internal static string Geometry(int lun, long totalBlocks, int blockSize = SectorSize, string memType = "UFS")
    {
        string json = "{\"storage_info\": {\"total_blocks\": " + totalBlocks +
                      ", \"block_size\": " + blockSize +
                      ",\"page_size\":4096,\"num_physical\":6,\"serial_num\":1129467726," +
                      "\"fw_version\":\"101\",\"mem_type\":\"" + memType +
                      "\",\"prod_name\":\"MT512GBGBB4U41\"}}";

        return "[INFO] Getting Storage Info for LUN " + lun + " (StorageType: Ufs, Slot: 0)\n" +
               "[DEBUG] DEVPRG LOG: INFO: " + json + "\n" +
               "[INFO] Using sector size: " + blockSize + " bytes for LUN " + lun + ".\n" +
               "[INFO] Read command ACKed, raw mode enabled.\n" +
               "[INFO] Final ACK received for Read operation.\n" +
               "[INFO] --- GPT Header LUN " + lun + " ---\n" +
               "[INFO] 'printgpt' command finished";
    }

    internal static string InitialProbe(
        long totalBlocks = InitialTotalSectors,
        int lun = 0,
        string saharaSerial = BusSerialHex,
        string hwid = HardwareId,
        bool includeLoaderMarker = true)
    {
        string sahara = "[INFO] Serial Number: " + saharaSerial + "\n[INFO] HWID: " + hwid;
        if (includeLoaderMarker)
        {
            sahara += "\n[INFO] Loader uploaded and started successfully via Sahara.";
        }

        return Selected() + "\n" + sahara + "\n" + Geometry(lun, totalBlocks);
    }

    internal static string ReadSuccess(int lun, long startSector, long sectorCount, long bytes, string path)
    {
        long lastSector = startSector + sectorCount - 1;
        return Selected() + "\n" +
               "[INFO] Configure command ACKed.\n" +
               "[INFO] Preparing to read " + sectorCount + " sectors (LBA " + startSector + " to " + lastSector +
               ", " + bytes + " bytes) from LUN " + lun + " into '" + path + "'...\n" +
               "[INFO] Read command ACKed, raw mode enabled.\n" +
               "[INFO] Successfully read and wrote " + bytes + " bytes in 24 ms.\n" +
               "[INFO] Final ACK received for Read operation.\n" +
               "[INFO] 'read-sector' command finished";
    }

    internal static string WriteSuccess(int lun, long startSector, long sectorCount, long bytes) =>
        Selected() + "\n" +
        "[INFO] Writing " + sectorCount + " sectors (" + bytes + " bytes) to LUN " + lun +
        ", starting at sector " + startSector + "...\n" +
        "[INFO] Program command ACKed, raw mode enabled.\n" +
        "[INFO] Raw data stream (" + bytes + " bytes) sent in 1 ms.\n" +
        "[INFO] Program operation successful (final ACK received).\n" +
        "[INFO] 'write-sector' command finished";

    internal static string ResetSuccess() =>
        Selected() + "\n" +
        "[INFO] Attempting to send power command: Mode 'Reset', Delay '1s'...\n" +
        "[INFO] Power command 'Reset' sent successfully.\n" +
        "[INFO] Device should now be resetting.\n" +
        "[INFO] 'reset' command finished";
}

public sealed class EdlClientTests : IClassFixture<EdlClientToolchainFixture>
{
    private static readonly TimeSpan ProbeInitialTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ProbeWarmTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan WriteTimeout = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan ResetTimeout = TimeSpan.FromSeconds(20);

    /// <summary>
    /// The private pure timeout helper, reached by reflection only so that the byte-dependent formula for
    /// 32/48 GiB writes and for its arithmetic boundaries can be proven without creating or hashing a
    /// multi-gigabyte file and without adding a public test hook.
    /// </summary>
    private static readonly MethodInfo TimeoutHelperMethod = typeof(EdlClient).GetMethod(
        "ByteDependentTimeout",
        BindingFlags.NonPublic | BindingFlags.Static,
        binder: null,
        types: new[] { typeof(long), typeof(TimeSpan) },
        modifiers: null)
        ?? throw new InvalidOperationException(
            "EdlClient must keep its private static byte-dependent timeout helper.");

    private readonly EdlClientToolchainFixture _fixture;

    public EdlClientTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ProbeInitial_valid_real_prefixed_json_identity_exact_argv()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeAsync(0, initialLoader: true);

        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), evidence.Geometry);
        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.HardwareId, evidence.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(0, evidence.Command.ExitCode);
        Assert.Equal(1, runner.CallCount);

        AssertCommand(
            runner.Commands[0],
            _fixture.Toolchain.ClientPath,
            ProbeInitialTimeout,
            WithGlobals("printgpt", "--lun", "0"));
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public void Constructor_retains_exact_toolchain_and_binding()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery();
        EdlEntryResult binding = NewBinding();

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);

        Assert.Same(_fixture.Toolchain, client.Toolchain);
        Assert.Same(binding, client.Binding);
    }

    [Fact]
    public async Task WarmProbe_before_initial_reject_no_run()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        EdlClient client = NewClient(runner, discovery);

        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: false));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(0, runner.CallCount);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("two")]
    [InlineData("wrong-sn")]
    [InlineData("missing-sn")]
    [InlineData("duplicate-conflicting-sn")]
    public async Task Discovery_invalid_rejects_before_runner(string variant)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = variant switch
            {
                "none" => Array.Empty<EdlEndpoint>(),
                "two" => new[]
                {
                    E003EdlTestData.Endpoint(),
                    E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
                },
                "wrong-sn" => new[]
                {
                    E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:DEADBEEF"),
                },
                "missing-sn" => new[]
                {
                    E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A"),
                },
                "duplicate-conflicting-sn" => new[]
                {
                    E003EdlTestData.Endpoint(),
                    E003EdlTestData.Endpoint(
                        instanceId: E003EdlTestData.DeviceInstanceId,
                        description: "QUSB_BULK_CID:045A_SN:DEADBEEF"),
                },
                _ => throw new ArgumentOutOfRangeException(nameof(variant)),
            },
        };

        // Any consumed script would prove the runner was reached, which must not happen.
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task Duplicate_same_physical_interfaces_valid()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        discovery.Endpoints = new[]
        {
            E003EdlTestData.Endpoint(),
            E003EdlTestData.Endpoint(instanceId: E003EdlTestData.LowercaseInstanceId),
        };
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeAsync(0, initialLoader: true);

        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(1, runner.CallCount);
    }

    [Fact]
    public async Task Probe_current_instance_id_may_change_twice_while_binding_remains_original_evidence()
    {
        const string freshInstanceId = @"USB\VID_05C6&PID_9008\8&33334444&0&8";

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = new E003ScriptedEndpointDiscovery
        {
            Endpoints = new[]
            {
                E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
            },
        };
        EdlEntryResult binding = NewBinding();
        runner.Enqueue(
            E003EdlTestData.Selected(instanceLower: "8&11112222&0&8") + "\n" +
            E003EdlTestData.Sahara() + "\n" +
            E003EdlTestData.Geometry(0, E003EdlTestData.InitialTotalSectors));

        EdlClient client = NewClient(runner, discovery, binding);
        EdlProbeEvidence initial = await client.ProbeAsync(0, initialLoader: true);

        Assert.Equal(E003EdlTestData.DeviceInstanceId, binding.Endpoint.DeviceInstanceId);
        Assert.Equal(E003EdlTestData.BusSerialHex, initial.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, initial.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), initial.Geometry);

        discovery.Endpoints = new[]
        {
            E003EdlTestData.Endpoint(instanceId: freshInstanceId),
        };
        runner.Enqueue(
            E003EdlTestData.Selected(instanceLower: "8&33334444&0&8") + "\n" +
            E003EdlTestData.Geometry(4, E003EdlTestData.WarmLun4TotalSectors));

        EdlProbeEvidence warm = await client.ProbeAsync(4, initialLoader: false);

        Assert.Equal(E003EdlTestData.BusSerialHex, warm.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new EdlGeometry(4, 4096, E003EdlTestData.WarmLun4TotalSectors), warm.Geometry);
        Assert.Equal(2, runner.CallCount);
        Assert.Equal(E003EdlTestData.DeviceInstanceId, binding.Endpoint.DeviceInstanceId);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(6)]
    public async Task Probe_invalid_lun_rejects_before_runner(int lun)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(lun, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task Binding_model_mismatch_rejects_before_runner()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlEntryResult binding = NewBinding(model: "TB999XX");

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task FW01_Binding_current_firmware_may_differ_from_loader_source()
    {
        const string currentFirmware = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlEntryResult binding = NewBinding(displayId: currentFirmware);

        EdlClient client = new EdlClient(_fixture.Toolchain, binding, runner, discovery);
        EdlProbeEvidence evidence = await client.ProbeAsync(0, initialLoader: true);

        Assert.Equal(E003EdlTestData.BusSerialHex, evidence.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.HardwareId, evidence.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(0, evidence.Command.ExitCode);
        Assert.Equal(1, runner.CallCount);

        Assert.True(client.HasInitialSaharaProof, "the real initial probe must prove the session");
        Assert.Equal(
            currentFirmware,
            client.Binding.AndroidIdentity.Identity.Firmware!.DisplayId);

        // The loader source keeps its own build; only the device's current firmware is new.
        Assert.Equal(MaintenanceProfiles.AndroidBuild, _fixture.Toolchain.AndroidBuild);
        Assert.NotEqual(currentFirmware, _fixture.Toolchain.AndroidBuild);
    }

    [Theory]
    [InlineData("wrong-sahara")]
    [InlineData("wrong-hwid")]
    [InlineData("missing-loader")]
    public async Task Initial_wrong_sahara_SN_HWID_missing_marker_rejects(string variant)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        string output = variant switch
        {
            "wrong-sahara" => E003EdlTestData.InitialProbe(saharaSerial: "DEADBEEF"),
            "wrong-hwid" => E003EdlTestData.InitialProbe(hwid: "0028000000000000"),
            "missing-loader" => E003EdlTestData.InitialProbe(includeLoaderMarker: false),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };
        runner.Enqueue(output);

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Fact]
    public async Task Actual_selected_bus_SN_wrong_even_prior_found_matching_rejects()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        string output =
            "[INFO] Found device \\\\?\\usb#vid_05c6&pid_9008#8&19888c89&0&8 on bus " +
            E003EdlTestData.BusDescription + "\n" +
            E003EdlTestData.Selected(busSerial: "DEADBEEF") + "\n" +
            E003EdlTestData.Sahara() + "\n" +
            E003EdlTestData.Geometry(0, E003EdlTestData.InitialTotalSectors);
        runner.Enqueue(output);

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Theory]
    [InlineData("bad-json")]
    [InlineData("missing-json")]
    [InlineData("non-ufs")]
    [InlineData("wrong-lun")]
    [InlineData("zero")]
    [InlineData("conflict")]
    public async Task Geometry_invalid_rejects_after_one_run(string variant)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        string prefix = E003EdlTestData.Selected() + "\n" + E003EdlTestData.Sahara() + "\n";
        string output = variant switch
        {
            "bad-json" => prefix +
                "[INFO] Getting Storage Info for LUN 0 (StorageType: Ufs, Slot: 0)\n" +
                "[DEBUG] DEVPRG LOG: INFO: {\"storage_info\": {\"total_blocks\": 123871232, \"block_size\": 4096\n" +
                "[INFO] Using sector size: 4096 bytes for LUN 0.\n" +
                "[INFO] Read command ACKed, raw mode enabled.\n" +
                "[INFO] Final ACK received for Read operation.\n" +
                "[INFO] 'printgpt' command finished",
            "missing-json" => prefix +
                "[INFO] Getting Storage Info for LUN 0 (StorageType: Ufs, Slot: 0)\n" +
                "[INFO] Using sector size: 4096 bytes for LUN 0.\n" +
                "[INFO] Read command ACKed, raw mode enabled.\n" +
                "[INFO] Final ACK received for Read operation.\n" +
                "[INFO] 'printgpt' command finished",
            "non-ufs" => prefix + E003EdlTestData.Geometry(0, E003EdlTestData.InitialTotalSectors, memType: "EMMC"),
            "wrong-lun" => prefix + E003EdlTestData.Geometry(3, E003EdlTestData.InitialTotalSectors),
            "zero" => prefix + E003EdlTestData.Geometry(0, 0),
            "conflict" => prefix +
                E003EdlTestData.Geometry(0, E003EdlTestData.InitialTotalSectors) + "\n" +
                E003EdlTestData.Geometry(0, E003EdlTestData.WarmLun4TotalSectors),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };
        runner.Enqueue(output);

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Fact]
    public async Task Warm_probe_LUN4_separate_geometry_then_read_uses_correct_range()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Warm_probe_LUN4_separate_geometry_then_read_uses_correct_range));
        string outputPath = Path.Combine(caseDirectory, "lun4.bin");
        byte[] payload = Payload(2 * E003EdlTestData.SectorSize);

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe(E003EdlTestData.InitialTotalSectors, 0));
        runner.Enqueue(E003EdlTestData.Selected() + "\n" +
                       E003EdlTestData.Geometry(4, E003EdlTestData.WarmLun4TotalSectors));
        runner.Enqueue(
            E003EdlTestData.ReadSuccess(4, 8, 2, payload.Length, outputPath),
            sideEffect: command => File.WriteAllBytes(command.Arguments[3], payload));

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);
        EdlProbeEvidence warm = await client.ProbeAsync(4, initialLoader: false);

        Assert.Equal(new EdlGeometry(4, 4096, E003EdlTestData.WarmLun4TotalSectors), warm.Geometry);

        EdlReadEvidence read = await client.ReadAsync(4, 8, 2, outputPath);

        Assert.Equal(new EdlGeometry(4, 4096, E003EdlTestData.WarmLun4TotalSectors), read.Geometry);
        Assert.Equal(8L, read.StartSector);
        Assert.Equal(2L, read.SectorCount);
        Assert.Equal((long)payload.Length, read.Length);
        Assert.Equal(0, read.Command.ExitCode);
        Assert.Equal(3, discovery.ReadCount);

        AssertCommand(
            runner.Commands[1],
            _fixture.Toolchain.ClientPath,
            ProbeWarmTimeout,
            WithGlobals("printgpt", "--lun", "4"));
        AssertCommand(
            runner.Commands[2],
            _fixture.Toolchain.ClientPath,
            ReadTimeout,
            WithGlobals("read-sector", "8", "2", outputPath, "--lun", "4"));
        Assert.Equal(3, runner.CallCount);
    }

    [Theory]
    [InlineData("nonzero")]
    [InlineData("finished-only")]
    [InlineData("nak")]
    public async Task Probe_error_nonzero_or_finished_only_rejects(string variant)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();

        string output;
        int exitCode = 0;
        switch (variant)
        {
            case "nonzero":
                output = E003EdlTestData.InitialProbe();
                exitCode = 1;
                break;
            case "finished-only":
                output = E003EdlTestData.Selected() + "\n" +
                         E003EdlTestData.Sahara() + "\n" +
                         "[INFO] Getting Storage Info for LUN 0 (StorageType: Ufs, Slot: 0)\n" +
                         "[INFO] 'printgpt' command finished";
                break;
            case "nak":
                output = E003EdlTestData.InitialProbe() + "\n[ERROR] NAK received";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        runner.Enqueue(output, exitCode);

        EdlClient client = NewClient(runner, discovery);
        Exception? error = await Record.ExceptionAsync(() => client.ProbeAsync(0, initialLoader: true));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Fact]
    public async Task Read_valid_exact_filebytes_SHA_argv_finite_timeout()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Read_valid_exact_filebytes_SHA_argv_finite_timeout));
        string outputPath = Path.Combine(caseDirectory, "read.bin");
        byte[] payload = Payload(2 * E003EdlTestData.SectorSize);
        string expectedSha = Convert.ToHexString(SHA256.HashData(payload));
        bool existedWhenInvoked = true;

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            E003EdlTestData.ReadSuccess(0, 4, 2, payload.Length, outputPath),
            sideEffect: command =>
            {
                existedWhenInvoked = File.Exists(command.Arguments[3]);
                File.WriteAllBytes(command.Arguments[3], payload);
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Assert.False(File.Exists(outputPath));
        EdlReadEvidence read = await client.ReadAsync(0, 4, 2, outputPath);

        Assert.False(existedWhenInvoked);
        Assert.Equal(4L, read.StartSector);
        Assert.Equal(2L, read.SectorCount);
        Assert.Equal((long)payload.Length, read.Length);
        Assert.Equal(expectedSha, read.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), read.Geometry);
        Assert.Equal(0, read.Command.ExitCode);
        Assert.Equal(2, runner.CallCount);

        AssertCommand(
            runner.Commands[1],
            _fixture.Toolchain.ClientPath,
            ReadTimeout,
            WithGlobals("read-sector", "4", "2", outputPath, "--lun", "0"));
    }

    [Theory]
    [InlineData("negative-start")]
    [InlineData("zero-count")]
    [InlineData("beyond-end")]
    [InlineData("overflow")]
    [InlineData("byte-overflow")]
    [InlineData("existing-output")]
    [InlineData("unprobed-lun")]
    public async Task Read_invalid_range_path_or_unprobed_rejects_before_command(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Read_invalid_range_path_or_unprobed_rejects_before_command));
        string outputPath = Path.Combine(caseDirectory, variant + ".bin");

        long probeTotalSectors = E003EdlTestData.InitialTotalSectors;
        long startSector = 4;
        long sectorCount = 2;
        int lun = 0;
        switch (variant)
        {
            case "negative-start":
                startSector = -1;
                break;
            case "zero-count":
                sectorCount = 0;
                break;
            case "beyond-end":
                startSector = E003EdlTestData.InitialTotalSectors - 1;
                break;
            case "overflow":
                startSector = long.MaxValue;
                break;
            case "byte-overflow":
                // Sector end fits the reported total, but count * sector size overflows.
                probeTotalSectors = long.MaxValue;
                startSector = 0;
                sectorCount = long.MaxValue / E003EdlTestData.SectorSize + 1;
                break;
            case "existing-output":
                File.WriteAllBytes(outputPath, new byte[16]);
                break;
            case "unprobed-lun":
                lun = 1;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe(probeTotalSectors));

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Exception? error = await Record.ExceptionAsync(() => client.ReadAsync(lun, startSector, sectorCount, outputPath));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Theory]
    [InlineData("short-file")]
    [InlineData("missing-ack")]
    [InlineData("nonzero")]
    public async Task Read_short_file_or_missing_ACK_or_nonzero_rejects_without_retry(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Read_short_file_or_missing_ACK_or_nonzero_rejects_without_retry));
        string outputPath = Path.Combine(caseDirectory, variant + ".bin");
        byte[] fullPayload = Payload(2 * E003EdlTestData.SectorSize);
        byte[] shortPayload = Payload(E003EdlTestData.SectorSize);

        string output = E003EdlTestData.ReadSuccess(0, 4, 2, fullPayload.Length, outputPath);
        int exitCode = 0;
        byte[] written = fullPayload;

        switch (variant)
        {
            case "short-file":
                written = shortPayload;
                break;
            case "missing-ack":
                output = output.Replace("[INFO] Final ACK received for Read operation.\n", string.Empty);
                break;
            case "nonzero":
                exitCode = 1;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            output,
            exitCode,
            sideEffect: command => File.WriteAllBytes(command.Arguments[3], written));

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Exception? error = await Record.ExceptionAsync(() => client.ReadAsync(0, 4, 2, outputPath));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(2, runner.CallCount);
    }

    [Fact]
    public async Task Write_valid_file_hash_exact_argv_without_count_ACK()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Write_valid_file_hash_exact_argv_without_count_ACK));
        string sourcePath = Path.Combine(caseDirectory, "write.bin");
        byte[] payload = Payload(2 * E003EdlTestData.SectorSize);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(E003EdlTestData.WriteSuccess(0, 4, 2, payload.Length));

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);
        EdlWriteEvidence write = await client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha));

        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), write.Geometry);
        Assert.Equal(4L, write.StartSector);
        Assert.Equal(2L, write.SectorCount);
        Assert.Equal((long)payload.Length, write.Length);
        Assert.Equal(sha, write.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(0, write.Command.ExitCode);
        Assert.Equal(2, runner.CallCount);

        // The CLI has no count positional: start, file, then --lun.
        AssertCommand(
            runner.Commands[1],
            _fixture.Toolchain.ClientPath,
            WriteTimeout,
            WithGlobals("write-sector", "4", sourcePath, "--lun", "0"));
        Assert.Equal(sourcePath, runner.Commands[1].Arguments[2]);
        Assert.Equal("--lun", runner.Commands[1].Arguments[3]);
    }

    [Theory]
    [InlineData("wrong-hash")]
    [InlineData("unaligned-length")]
    [InlineData("missing-file")]
    [InlineData("bad-range")]
    public async Task Write_changed_hash_unaligned_missing_file_bad_range_rejects_before_command(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Write_changed_hash_unaligned_missing_file_bad_range_rejects_before_command));
        string sourcePath = Path.Combine(caseDirectory, variant + ".bin");

        byte[] payload = variant == "unaligned-length"
            ? Payload(E003EdlTestData.SectorSize - 96)
            : Payload(2 * E003EdlTestData.SectorSize);
        long declaredLength = payload.Length;
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long startSector = variant == "bad-range"
            ? E003EdlTestData.InitialTotalSectors - 1
            : 4;

        switch (variant)
        {
            case "wrong-hash":
                File.WriteAllBytes(sourcePath, payload);
                sha = new string('0', 64);
                break;
            case "unaligned-length":
                File.WriteAllBytes(sourcePath, payload);
                break;
            case "missing-file":
                break;
            case "bad-range":
                File.WriteAllBytes(sourcePath, payload);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Exception? error = await Record.ExceptionAsync(
            () => client.WriteAsync(0, startSector, new VerifiedEdlFile(sourcePath, declaredLength, sha)));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
    }

    [Theory]
    [InlineData("missing-final-ack")]
    [InlineData("nonzero")]
    [InlineData("timeout")]
    [InlineData("wrong-selected-sn")]
    public async Task Write_missing_finalACK_nonzero_timeout_or_wrong_SN_is_outcome_unknown_without_retry(string variant)
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Write_missing_finalACK_nonzero_timeout_or_wrong_SN_is_outcome_unknown_without_retry));
        string sourcePath = Path.Combine(caseDirectory, variant + ".bin");
        byte[] payload = Payload(2 * E003EdlTestData.SectorSize);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        string writeOutput = E003EdlTestData.WriteSuccess(0, 4, 2, payload.Length);
        switch (variant)
        {
            case "missing-final-ack":
                runner.Enqueue(writeOutput.Replace(
                    "[INFO] Program operation successful (final ACK received).\n",
                    string.Empty));
                break;
            case "nonzero":
                runner.Enqueue(writeOutput, exitCode: 1);
                break;
            case "timeout":
                runner.EnqueueFailure(new TimeoutException("write-sector timed out"));
                break;
            case "wrong-selected-sn":
                // Only the actual selected identity is wrong; no earlier correct actual selection exists.
                runner.Enqueue(writeOutput.Replace(
                    E003EdlTestData.BusSerialHex,
                    "DEADBEEF",
                    StringComparison.Ordinal));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        IOException error = await Assert.ThrowsAsync<IOException>(
            () => client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha)));

        Assert.True(
            error.Message.Contains("outcome unknown", StringComparison.OrdinalIgnoreCase),
            "write failure must state that the outcome is unknown: " + error.Message);
        Assert.Equal(2, runner.CallCount);
    }

    [Fact]
    public async Task Reset_valid_exact_argv_acceptance()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(E003EdlTestData.ResetSuccess());

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);
        EdlResetEvidence reset = await client.ResetAsync();

        Assert.True(reset.CommandAccepted);
        Assert.Equal(0, reset.Command.ExitCode);
        Assert.Equal(2, runner.CallCount);

        AssertCommand(
            runner.Commands[1],
            _fixture.Toolchain.ClientPath,
            ResetTimeout,
            WithGlobals("reset", "--mode", "Reset", "--delay", "1"));
    }

    [Theory]
    [InlineData("missing-marker")]
    [InlineData("nonzero")]
    [InlineData("timeout")]
    public async Task Reset_timeout_missing_marker_or_nonzero_is_outcome_unknown_without_retry(string variant)
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        switch (variant)
        {
            case "missing-marker":
                runner.Enqueue(E003EdlTestData.ResetSuccess().Replace(
                    "[INFO] Power command 'Reset' sent successfully.\n",
                    string.Empty));
                break;
            case "nonzero":
                runner.Enqueue(E003EdlTestData.ResetSuccess(), exitCode: 1);
                break;
            case "timeout":
                runner.EnqueueFailure(new TimeoutException("reset timed out"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        IOException error = await Assert.ThrowsAsync<IOException>(() => client.ResetAsync());

        Assert.True(
            error.Message.Contains("outcome unknown", StringComparison.OrdinalIgnoreCase),
            "reset failure must state that the outcome is unknown: " + error.Message);
        Assert.Equal(2, runner.CallCount);
    }

    [Fact]
    public async Task Cancelled_before_start_no_new_runner_call_warm_session_allowed()
    {
        string caseDirectory = _fixture.NewCaseDirectory(nameof(Cancelled_before_start_no_new_runner_call_warm_session_allowed));
        string outputPath = Path.Combine(caseDirectory, "cancelled.bin");

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);
        int callsBefore = runner.CallCount;

        using CancellationTokenSource cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.ReadAsync(0, 4, 2, outputPath, cancelled.Token));

        Assert.Equal(callsBefore, runner.CallCount);
        Assert.False(File.Exists(outputPath));
    }

    [Theory]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("reset")]
    public async Task Operation_rechecks_actual_selected_SN_after_successful_probe(string operation)
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Operation_rechecks_actual_selected_SN_after_successful_probe));
        string outputPath = Path.Combine(caseDirectory, "read.bin");
        string sourcePath = Path.Combine(caseDirectory, "write.bin");
        byte[] payload = Payload(2 * E003EdlTestData.SectorSize);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        // Same bound physical instance, but its description now reports a different SN.
        discovery.Endpoints = new[]
        {
            E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:DEADBEEF"),
        };

        Exception? error = operation switch
        {
            "read" => await Record.ExceptionAsync(() => client.ReadAsync(0, 4, 2, outputPath)),
            "write" => await Record.ExceptionAsync(
                () => client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha))),
            "reset" => await Record.ExceptionAsync(() => client.ResetAsync()),
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(1, runner.CallCount);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task Historical_loader_and_misc_logs_replay_anonymized_identity_and_path()
    {
        static string RequireLogPath(string variable)
        {
            string? value = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(value) || !File.Exists(value))
            {
                throw new InvalidOperationException(
                    variable + " must name the historical EDL log file; refusing to skip.");
            }

            return Path.GetFullPath(value);
        }

        string loaderLogPath = RequireLogPath("EDL_CLIENT_LOADER_LOG_PATH");
        string miscLogPath = RequireLogPath("EDL_CLIENT_MISC_LOG_PATH");

        byte[] loaderBytes = File.ReadAllBytes(loaderLogPath);
        Assert.Equal(
            "AEDC633C45EA718DB73E1458C52B2E00955339DEF482280D5E47A2FAA17DD6E2",
            Convert.ToHexString(SHA256.HashData(loaderBytes)));

        byte[] miscBytes = File.ReadAllBytes(miscLogPath);
        Assert.Equal(
            "50C3E999600170A46C13871A72433411B1607E578857360AD27962E2F4F421EE",
            Convert.ToHexString(SHA256.HashData(miscBytes)));

        string loaderLogText = File.ReadAllText(loaderLogPath);
        string miscLogText = File.ReadAllText(miscLogPath);

        var serialMatch = Regex.Match(loaderLogText, @"\bSN:(?<serial>[0-9A-Fa-f]{8})(?![0-9A-Za-z])");
        Assert.True(serialMatch.Success, "Expected 8-hex bus serial in loader log text.");
        string historicalSerial = serialMatch.Groups["serial"].Value;
        loaderLogText = loaderLogText.Replace(historicalSerial, E003EdlTestData.BusSerialHex, StringComparison.OrdinalIgnoreCase);
        miscLogText = miscLogText.Replace(historicalSerial, E003EdlTestData.BusSerialHex, StringComparison.OrdinalIgnoreCase);

        Match outputPathMatch = Regex.Match(
            miscLogText,
            @"Preparing to read 256 sectors \(LBA 89992 to 90247, 1048576 bytes\) from LUN 0 into '(?<path>[^']*)'");
        Assert.True(outputPathMatch.Success, "historical misc log must contain the read output path line");
        string historicalOutputPath = outputPathMatch.Groups["path"].Value;
        Assert.False(string.IsNullOrEmpty(historicalOutputPath));

        string caseDirectory =
            _fixture.NewCaseDirectory(nameof(Historical_loader_and_misc_logs_replay_anonymized_identity_and_path));
        string outputPath = Path.Combine(caseDirectory, "historical-misc.bin");
        Assert.False(File.Exists(outputPath));

        string replayedMiscLog = miscLogText.Replace(historicalOutputPath, outputPath, StringComparison.Ordinal);

        byte[] payload = Payload(1048576);
        string expectedSha = Convert.ToHexString(SHA256.HashData(payload));

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(loaderLogText);
        runner.Enqueue(
            replayedMiscLog,
            sideEffect: command =>
            {
                Assert.Equal("89992", command.Arguments[1]);
                Assert.Equal("256", command.Arguments[2]);
                Assert.Equal(outputPath, command.Arguments[3]);
                File.WriteAllBytes(command.Arguments[3], payload);
            });

        EdlClient client = NewClient(runner, discovery);
        EdlProbeEvidence probe = await client.ProbeAsync(0, initialLoader: true);

        Assert.Equal(E003EdlTestData.BusSerialHex, probe.BusSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, probe.SaharaSerialHex, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.HardwareId, probe.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), probe.Geometry);
        Assert.True(client.HasInitialSaharaProof);

        AssertCommand(
            runner.Commands[0],
            _fixture.Toolchain.ClientPath,
            ProbeInitialTimeout,
            WithGlobals("printgpt", "--lun", "0"));

        EdlReadEvidence read = await client.ReadAsync(0, 89992, 256, outputPath);

        Assert.Equal(1048576L, read.Length);
        Assert.Equal(89992L, read.StartSector);
        Assert.Equal(256L, read.SectorCount);
        Assert.Equal(new EdlGeometry(0, 4096, E003EdlTestData.InitialTotalSectors), read.Geometry);
        Assert.Equal(outputPath, read.FilePath);
        Assert.Equal(expectedSha, read.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(expectedSha, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(outputPath))));
        Assert.Equal(2, runner.CallCount);

        AssertCommand(
            runner.Commands[1],
            _fixture.Toolchain.ClientPath,
            ReadTimeout,
            WithGlobals("read-sector", "89992", "256", outputPath, "--lun", "0"));
    }

    [Theory]
    [InlineData(32, 4126)]
    [InlineData(48, 6174)]
    public async Task Read_large_transfer_uses_byte_dependent_finite_timeout_and_propagates_sentinel(
        int gibibytes,
        int expectedSeconds)
    {
        long byteCount = (long)gibibytes * 1024L * 1024L * 1024L;
        long sectorCount = byteCount / E003EdlTestData.SectorSize;
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Read_large_transfer_uses_byte_dependent_finite_timeout_and_propagates_sentinel) +
            "-" + gibibytes.ToString(CultureInfo.InvariantCulture));
        string outputPath = Path.Combine(
            caseDirectory,
            "read-" + gibibytes.ToString(CultureInfo.InvariantCulture) + "g.bin");

        // Known sentinel thrown by the runner before it could produce or hash anything.
        InvalidOperationException sentinel = new(
            "sentinel: " + gibibytes.ToString(CultureInfo.InvariantCulture) + " GiB read command captured");

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe(sectorCount + 8));
        runner.EnqueueFailure(sentinel);

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Assert.False(File.Exists(outputPath));

        Exception? error = await Record.ExceptionAsync(() => client.ReadAsync(0, 0, sectorCount, outputPath));

        Assert.Same(sentinel, error);
        Assert.False(File.Exists(outputPath));
        Assert.Equal(2, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);

        ProcessCommand read = runner.Commands[1];
        Assert.Equal(
            WithGlobals(
                "read-sector",
                "0",
                sectorCount.ToString(CultureInfo.InvariantCulture),
                outputPath,
                "--lun",
                "0"),
            read.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), read.Timeout);
        Assert.True(read.Timeout > ReadTimeout, "a large read must exceed the old fixed read timeout");
        Assert.True(read.Timeout != Timeout.InfiniteTimeSpan);
        Assert.Equal(byteCount, sectorCount * E003EdlTestData.SectorSize);
    }

    [Fact]
    public void Timeout_helper_is_floor_preserving_linear_and_overflow_checked()
    {
        const long MiB8 = 8L * 1024 * 1024;
        long bytes32 = 32L * 1024 * 1024 * 1024;
        long bytes48 = 48L * 1024 * 1024 * 1024;

        // Read path: 30 s + ceil(bytes / 8 MiB).
        TimeSpan read32 = TimeoutFor(bytes32, ReadTimeout);
        TimeSpan read48 = TimeoutFor(bytes48, ReadTimeout);
        Assert.Equal(TimeSpan.FromSeconds(4126), read32);
        Assert.Equal(TimeSpan.FromSeconds(6174), read48);
        Assert.True(read32 > ReadTimeout);
        Assert.True(read48 > read32, "the timeout must grow with the byte count");

        // The same helper serves writes; only the floor differs.
        Assert.Equal(TimeSpan.FromSeconds(4126), TimeoutFor(bytes32, WriteTimeout));
        Assert.Equal(TimeSpan.FromSeconds(6174), TimeoutFor(bytes48, WriteTimeout));
        Assert.True(TimeoutFor(bytes48, WriteTimeout) > TimeoutFor(bytes32, WriteTimeout));

        // Ceiling boundary and floor thresholds stay exact.
        Assert.Equal(ReadTimeout, TimeoutFor(90 * MiB8, ReadTimeout));
        Assert.Equal(TimeSpan.FromSeconds(121), TimeoutFor(90 * MiB8 + 1, ReadTimeout));
        Assert.Equal(WriteTimeout, TimeoutFor(150 * MiB8, WriteTimeout));
        Assert.Equal(TimeSpan.FromSeconds(181), TimeoutFor(150 * MiB8 + 1, WriteTimeout));

        // Small positive counts keep the pre-existing floors.
        Assert.Equal(ReadTimeout, TimeoutFor(1, ReadTimeout));
        Assert.Equal(WriteTimeout, TimeoutFor(E003EdlTestData.SectorSize, WriteTimeout));

        // Non-positive counts are rejected, never clamped to a floor or made infinite.
        Assert.Throws<InvalidOperationException>(() => { TimeoutFor(0, ReadTimeout); });
        Assert.Throws<InvalidOperationException>(() => { TimeoutFor(-1, ReadTimeout); });
        Assert.Throws<InvalidOperationException>(() => { TimeoutFor(long.MinValue, WriteTimeout); });

        // Checked boundary: the largest whole-second duration is representable; one more byte is not.
        long maxSeconds = TimeSpan.MaxValue.Ticks / TimeSpan.TicksPerSecond;
        long maxBytes = (maxSeconds - 30) * MiB8;
        Assert.Equal(
            TimeSpan.FromTicks(maxSeconds * TimeSpan.TicksPerSecond),
            TimeoutFor(maxBytes, ReadTimeout));
        Assert.Throws<InvalidOperationException>(() => { TimeoutFor(maxBytes + 1, ReadTimeout); });
    }

    // ------------------------------------------------------------------ live transfer observation

    [Fact]
    public async Task Streaming_Write_progress_is_observed_before_command_returns_and_evidence_is_unchanged()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_Write_progress_is_observed_before_command_returns_and_evidence_is_unchanged));
        string sourcePath = Path.Combine(caseDirectory, "stream-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "stream");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        // The live frame is the exact raw prefix of the returned stdout, followed by the canonical result.
        const string progressFrame = "Writing: 50.0% (0.50 / 99.99 MiB)";
        string stdout = progressFrame + "\r" +
                        E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length);

        InlineProgressRecorder recorder = new InlineProgressRecorder();
        EdlTransferProgress[] duringCommand = Array.Empty<EdlTransferProgress>();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            stdout,
            sideEffect: command =>
            {
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, progressFrame, "\r"));
                duringCommand = recorder.Snapshot();
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        EdlWriteEvidence write = await client.WriteAsync(
            0,
            4,
            new VerifiedEdlFile(sourcePath, payload.Length, sha),
            recorder,
            logPrefix);

        // Observed while the command was still running: the rounded 99.99 MiB denominator and the printed
        // percentage are ignored, the trusted total is the validated file length.
        Assert.Contains(
            duringCommand,
            progress => progress.Direction == EdlTransferDirection.Write &&
                        progress.Phase == EdlTransferPhase.Transferring &&
                        progress.CompletedBytes == 524288L &&
                        progress.TotalBytes == 1048576L);

        EdlTransferProgress[] observed = recorder.Snapshot();
        int firstCheck = Array.FindIndex(observed, p => p.Phase == EdlTransferPhase.CheckingInput);
        int firstTransfer = Array.FindIndex(observed, p => p.Phase == EdlTransferPhase.Transferring);
        Assert.True(firstCheck >= 0, "a write must report that it is checking its input file");
        Assert.True(firstTransfer > firstCheck, "input checking must be reported before transfer progress");

        // A progress observation is display only: it never replaces the acknowledged write evidence.
        Assert.Equal((long)payload.Length, write.Length);
        Assert.Equal(sectorCount, write.SectorCount);
        Assert.Equal(sha, write.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(0, write.Command.ExitCode);
        Assert.True(client.HasInitialSaharaProof);
        Assert.Equal(2, runner.CallCount);
    }

    [Fact]
    public async Task Streaming_Read_ignores_wrong_direction_and_malformed_but_accepts_comma_mib_counter()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_Read_ignores_wrong_direction_and_malformed_but_accepts_comma_mib_counter));
        string outputPath = Path.Combine(caseDirectory, "stream-read.bin");
        string logPrefix = Path.Combine(caseDirectory, "stream");
        byte[] payload = Payload(1024 * 1024);
        string expectedSha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        const string wrongDirection = "Writing: 50.0% (0.50 / 99.99 MiB)";
        const string malformed = "Reading: ?% (not a number)";
        const string commaFrame = "Reading:25.0% (0,25 / 99,99 MiB)";

        // The three emitted frames are the exact raw prefix of the returned stdout.
        string stdout = wrongDirection + "\r" + malformed + "\n" + commaFrame + "\r" +
                        E003EdlTestData.ReadSuccess(0, 8, sectorCount, payload.Length, outputPath);

        InlineProgressRecorder recorder = new InlineProgressRecorder();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            stdout,
            sideEffect: command =>
            {
                File.WriteAllBytes(command.Arguments[3], payload);
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, wrongDirection, "\r"));
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, malformed, "\n"));
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, commaFrame, "\r"));
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        EdlReadEvidence read = await client.ReadAsync(0, 8, sectorCount, outputPath, recorder, logPrefix);

        EdlTransferProgress[] observed = recorder.Snapshot();
        Assert.Contains(
            observed,
            progress => progress.Direction == EdlTransferDirection.Read &&
                        progress.Phase == EdlTransferPhase.Transferring &&
                        progress.CompletedBytes == 262144L &&
                        progress.TotalBytes == 1048576L);
        Assert.Contains(observed, progress => progress.Phase == EdlTransferPhase.CheckingOutput);
        Assert.DoesNotContain(observed, progress => progress.Direction == EdlTransferDirection.Write);

        Assert.Equal((long)payload.Length, read.Length);
        Assert.Equal(expectedSha, read.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(2, runner.CallCount);

        // Ignored frames are still raw log evidence.
        string stdoutLog = logPrefix + ".stdout.log";
        Assert.True(File.Exists(stdoutLog), "the read must write its prefixed stdout log: " + stdoutLog);
        string log = File.ReadAllText(stdoutLog);
        Assert.True(
            log.Contains(wrongDirection, StringComparison.Ordinal),
            "a wrong-direction frame must still be logged verbatim");
        Assert.True(
            log.Contains(malformed, StringComparison.Ordinal),
            "a malformed frame must still be logged verbatim");
    }

    [Fact]
    public async Task Streaming_Write_legacy_fake_without_callbacks_still_writes_complete_exact_logs()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_Write_legacy_fake_without_callbacks_still_writes_complete_exact_logs));
        string sourcePath = Path.Combine(caseDirectory, "legacy-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "legacy");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        string stdout = E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length);
        const string stderr = "legacy stderr tail without terminator";

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(stdout, 0, stderr);

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        await client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha), null, logPrefix);

        string stdoutLog = logPrefix + ".stdout.log";
        string stderrLog = logPrefix + ".stderr.log";
        Assert.True(File.Exists(stdoutLog), "with no live frame the full captured stdout must be logged");
        Assert.True(File.Exists(stderrLog), "with no live frame the full captured stderr must be logged");
        Assert.Equal(stdout, File.ReadAllText(stdoutLog));
        Assert.Equal(stderr, File.ReadAllText(stderrLog));
    }

    [Fact]
    public async Task Streaming_partial_live_frames_prefix_result_and_logs_equal_full_result_once()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_partial_live_frames_prefix_result_and_logs_equal_full_result_once));
        string sourcePath = Path.Combine(caseDirectory, "partial-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "partial");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        string stdout = E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length);
        string[] stdoutLines = stdout.Split('\n');
        string firstFrame = stdoutLines[0];
        string secondFrame = stdoutLines[1];
        const string stderr = "progress 10%\rprogress 20%\nfinal stderr tail";

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            stdout,
            0,
            stderr,
            sideEffect: command =>
            {
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, firstFrame, "\n"));
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, secondFrame, "\n"));
                command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stderr, "progress 10%", "\r"));
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        await client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha), null, logPrefix);

        string stdoutLog = logPrefix + ".stdout.log";
        Assert.True(File.Exists(stdoutLog), "the prefixed stdout log must exist: " + stdoutLog);
        Assert.Equal(stdout, File.ReadAllText(stdoutLog));
        Assert.Equal(stderr, File.ReadAllText(logPrefix + ".stderr.log"));
    }

    [Fact]
    public async Task Streaming_flood_frames_are_bounded_monotonic_clamped_and_rate_limited()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_flood_frames_are_bounded_monotonic_clamped_and_rate_limited));
        string sourcePath = Path.Combine(caseDirectory, "flood-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "flood");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        const int frameCount = 500;
        const string malformed = "Writing: nope";
        const string backwards = "Writing: 5.0% (0.05 / 1.00 MiB)";
        const string opposite = "Reading: 50.0% (0.50 / 1.00 MiB)";
        const string oversized = "Writing: 100.0% (5.00 / 1.00 MiB)";

        // One list drives both the emitted frames and the returned stdout, so the live prefix cannot drift
        // from the captured result.
        List<(string Text, string Terminator)> frames = new List<(string Text, string Terminator)>();
        for (int i = 0; i < frameCount; i++)
        {
            double mebibytes = i * 0.99 / (frameCount - 1);
            frames.Add((
                "Writing: " + (mebibytes * 100.0).ToString("F1", CultureInfo.InvariantCulture) +
                "% (" + mebibytes.ToString("F2", CultureInfo.InvariantCulture) + " / 1.00 MiB)",
                "\r"));
        }

        frames.Add((malformed, "\r"));
        frames.Add((backwards, "\r"));
        frames.Add((opposite, "\r"));
        frames.Add((oversized, "\r"));

        string stdout = string.Concat(frames.Select(frame => frame.Text + frame.Terminator)) +
                        E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length);

        InlineProgressRecorder recorder = new InlineProgressRecorder();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            stdout,
            sideEffect: command =>
            {
                foreach ((string text, string terminator) in frames)
                {
                    command.OutputReceived?.Invoke(Frame(ProcessOutputStream.Stdout, text, terminator));
                }
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Stopwatch stopwatch = Stopwatch.StartNew();
        await client.WriteAsync(0, 4, new VerifiedEdlFile(sourcePath, payload.Length, sha), recorder, logPrefix);
        stopwatch.Stop();

        // Only the transfer phase is a monotonic counter: the input-check phase may already own the same
        // range, and a phase transition is not rate limited.
        EdlTransferProgress[] observed = Array.FindAll(
            recorder.Snapshot(),
            progress => progress.Phase == EdlTransferPhase.Transferring);
        Assert.NotEmpty(observed);

        // One observation per 200 ms at most, plus the transfer-phase report at zero, the first native frame
        // and the final native frame.
        long allowed = 3 + (long)Math.Ceiling(stopwatch.Elapsed.TotalMilliseconds / 200.0);
        Assert.True(
            observed.Length <= allowed,
            "expected at most " + allowed + " transfer observations, saw " + observed.Length + " in " +
            stopwatch.ElapsedMilliseconds + " ms");

        long previous = 0;
        bool sawPositive = false;
        bool sawTrustedTotal = false;
        foreach (EdlTransferProgress progress in observed)
        {
            Assert.Equal(EdlTransferDirection.Write, progress.Direction);
            Assert.Equal(1048576L, progress.TotalBytes);
            Assert.InRange(progress.CompletedBytes, 0L, 1048576L);
            Assert.True(
                progress.CompletedBytes >= previous,
                "native progress counters must never move backwards");
            previous = progress.CompletedBytes;
            sawPositive |= progress.CompletedBytes > 0;
            sawTrustedTotal |= progress.CompletedBytes == 1048576L;
        }

        Assert.True(sawPositive, "at least one delivered native counter must be above zero");
        Assert.True(
            sawTrustedTotal,
            "an oversized valid native counter must be clamped to the trusted total, never echoed");

        // Rate limiting is a display concern only: the raw log is the whole returned stdout, once.
        string stdoutLog = logPrefix + ".stdout.log";
        Assert.True(File.Exists(stdoutLog), "the prefixed stdout log must exist: " + stdoutLog);
        Assert.Equal(stdout, File.ReadAllText(stdoutLog));
    }

    [Fact]
    public async Task Streaming_write_observed_100_percent_without_final_ACK_is_still_unknown_and_clears_proof()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_write_observed_100_percent_without_final_ACK_is_still_unknown_and_clears_proof));
        string sourcePath = Path.Combine(caseDirectory, "no-ack-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "no-ack");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        const string progressFrame = "Writing: 100.0% (1.00 / 1.00 MiB)";

        // The live frame is the exact raw prefix; the tail is the canonical result with the final ACK removed.
        string stdout = progressFrame + "\r" +
                        E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length).Replace(
                            "[INFO] Program operation successful (final ACK received).\n",
                            string.Empty,
                            StringComparison.Ordinal);

        InlineProgressRecorder recorder = new InlineProgressRecorder();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            stdout,
            sideEffect: command => command.OutputReceived?.Invoke(
                Frame(ProcessOutputStream.Stdout, progressFrame, "\r")));

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        IOException error = await Assert.ThrowsAsync<IOException>(
            () => client.WriteAsync(
                0,
                4,
                new VerifiedEdlFile(sourcePath, payload.Length, sha),
                recorder,
                logPrefix));

        Assert.True(
            error.Message.Contains("outcome unknown", StringComparison.OrdinalIgnoreCase),
            "a write without the final ACK must stay unknown: " + error.Message);
        Assert.False(client.HasInitialSaharaProof, "an unknown started write invalidates the session proof");
        Assert.Equal(2, runner.CallCount);

        // The observed 100 % is real, and still proves nothing about the acknowledgement.
        Assert.Contains(
            recorder.Snapshot(),
            progress => progress.Direction == EdlTransferDirection.Write &&
                        progress.Phase == EdlTransferPhase.Transferring &&
                        progress.CompletedBytes == 1048576L &&
                        progress.TotalBytes == 1048576L);
    }

    [Fact]
    public async Task Streaming_write_cancelled_after_frames_keeps_original_token_and_flushed_logs()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_write_cancelled_after_frames_keeps_original_token_and_flushed_logs));
        string sourcePath = Path.Combine(caseDirectory, "cancelled-write.bin");
        string logPrefix = Path.Combine(caseDirectory, "cancelled");
        byte[] payload = Payload(1024 * 1024);
        File.WriteAllBytes(sourcePath, payload);
        string sha = Convert.ToHexString(SHA256.HashData(payload));
        long sectorCount = payload.Length / E003EdlTestData.SectorSize;

        using CancellationTokenSource callerCts = new CancellationTokenSource();
        InlineProgressRecorder recorder = new InlineProgressRecorder();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe());
        runner.Enqueue(
            E003EdlTestData.WriteSuccess(0, 4, sectorCount, payload.Length),
            sideEffect: command =>
            {
                command.OutputReceived?.Invoke(Frame(
                    ProcessOutputStream.Stdout,
                    "Writing: 25.0% (0.25 / 1.00 MiB)",
                    "\r"));
                callerCts.Cancel();
                throw new OperationCanceledException(callerCts.Token);
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        IOException error = await Assert.ThrowsAsync<IOException>(
            () => client.WriteAsync(
                0,
                4,
                new VerifiedEdlFile(sourcePath, payload.Length, sha),
                recorder,
                logPrefix,
                callerCts.Token));

        Assert.True(
            error.Message.Contains("outcome unknown", StringComparison.OrdinalIgnoreCase),
            "a cancelled started write must stay unknown: " + error.Message);

        OperationCanceledException? inner =
            Assert.IsAssignableFrom<OperationCanceledException>(error.InnerException);
        Assert.Equal(callerCts.Token, inner.CancellationToken);

        Assert.False(client.HasInitialSaharaProof, "an unknown started write invalidates the session proof");
        Assert.Equal(2, runner.CallCount);

        string stdoutLog = logPrefix + ".stdout.log";
        Assert.True(File.Exists(stdoutLog), "observed frames must be flushed when the write fails: " + stdoutLog);
        Assert.True(
            File.ReadAllText(stdoutLog).Contains("Writing: 25.0%", StringComparison.Ordinal),
            "the frames observed before the cancellation must survive in the log");
    }

    [Fact]
    public async Task Streaming_read_32GiB_reports_64bit_progress_then_preserves_sentinel_and_proof()
    {
        string caseDirectory = _fixture.NewCaseDirectory(
            nameof(Streaming_read_32GiB_reports_64bit_progress_then_preserves_sentinel_and_proof));
        string outputPath = Path.Combine(caseDirectory, "read-32g.bin");
        string logPrefix = Path.Combine(caseDirectory, "big");
        long byteCount = 32L * 1024 * 1024 * 1024;
        long sectorCount = byteCount / E003EdlTestData.SectorSize;

        // Known sentinel thrown after the callback and before any output file or SHA-256 exists.
        InvalidOperationException sentinel = new(
            "sentinel: 32 GiB read command captured before producing a file");
        InlineProgressRecorder recorder = new InlineProgressRecorder();

        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        E003ScriptedEndpointDiscovery discovery = ValidDiscovery();
        runner.Enqueue(E003EdlTestData.InitialProbe(sectorCount + 8));
        runner.Enqueue(
            "the side effect throws before this result could ever exist",
            sideEffect: command =>
            {
                command.OutputReceived?.Invoke(Frame(
                    ProcessOutputStream.Stdout,
                    "Reading: 15.6% (5120.00 / 32768.00 MiB)",
                    "\r"));
                throw sentinel;
            });

        EdlClient client = NewClient(runner, discovery);
        await client.ProbeAsync(0, initialLoader: true);

        Assert.False(File.Exists(outputPath));

        Exception? error = await Record.ExceptionAsync(
            () => client.ReadAsync(0, 0, sectorCount, outputPath, recorder, logPrefix));

        Assert.Same(sentinel, error);
        Assert.False(File.Exists(outputPath));
        Assert.True(client.HasInitialSaharaProof, "a failed read must not clear the initial loader proof");
        Assert.Equal(2, runner.CallCount);

        Assert.Contains(
            recorder.Snapshot(),
            progress => progress.Direction == EdlTransferDirection.Read &&
                        progress.Phase == EdlTransferPhase.Transferring &&
                        progress.CompletedBytes == 5368709120L &&
                        progress.TotalBytes == 34359738368L);
    }

    /// <summary>
    /// Synchronous observer used by the Streaming_ tests. Deliberately not <see cref="Progress{T}"/>: that
    /// type posts to the captured context, so a frame delivered inside the fake would not be visible yet
    /// when the command returns.
    /// </summary>
    private sealed class InlineProgressRecorder : IProgress<EdlTransferProgress>
    {
        private readonly List<EdlTransferProgress> _observed = new();

        public void Report(EdlTransferProgress value)
        {
            lock (_observed)
            {
                _observed.Add(value);
            }
        }

        public EdlTransferProgress[] Snapshot()
        {
            lock (_observed)
            {
                return _observed.ToArray();
            }
        }
    }

    private static ProcessOutputLine Frame(ProcessOutputStream stream, string text, string terminator) =>
        new(stream, text, terminator);

    private static TimeSpan TimeoutFor(long byteCount, TimeSpan minimum)
    {
        try
        {
            return (TimeSpan)TimeoutHelperMethod.Invoke(null, new object[] { byteCount, minimum })!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }
    }

    private E003ScriptedEndpointDiscovery ValidDiscovery() => new E003ScriptedEndpointDiscovery
    {
        Endpoints = new[] { E003EdlTestData.Endpoint() },
    };

    private EdlClient NewClient(
        E003FakeCommandRunner runner,
        E003ScriptedEndpointDiscovery discovery,
        EdlEntryResult? binding = null) =>
        new EdlClient(_fixture.Toolchain, binding ?? NewBinding(), runner, discovery);

    private EdlEntryResult NewBinding(string? model = null, string? displayId = null) => new(
        new AndroidMaintenanceIdentity(
            new DeviceIdentity("SN0123456789", model ?? _fixture.Toolchain.Model, BootloaderState.Unknown)
            {
                Firmware = new FirmwareSnapshot(
                    displayId ?? _fixture.Toolchain.AndroidBuild,
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

    private static void AssertCommand(
        ProcessCommand command,
        string executable,
        TimeSpan timeout,
        params string[] expectedArguments)
    {
        Assert.Equal(executable, command.Executable);
        Assert.True(command.Timeout > TimeSpan.Zero && command.Timeout != Timeout.InfiniteTimeSpan);
        Assert.Equal(timeout, command.Timeout);
        Assert.Equal(expectedArguments, command.Arguments);
    }

    private static byte[] Payload(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(i % 251);
        }

        return bytes;
    }
}
