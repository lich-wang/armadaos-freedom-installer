using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Userdata-only uninstall backend tests. They describe the frozen userdata-only contract:
/// every behavioral test exercises a required behavior and fails when that behavior is missing
/// or wrong, never by treating a NotImplementedException as a valid reject.
///
/// Scope: the LUN 0 GPT pair plus the whole actual misc partition for the capture; the two
/// original GPT files only for the factory; a fresh three-region reinspection for drift. The
/// LUN 4 boot/vbmeta segments of the shared scenario remain an oracle only: production must
/// never read, probe or write them.
/// No test launches a process, touches a device, uses the network, git or reflection.
/// </summary>
public sealed class EbUninstallBackendTests : IClassFixture<EdlClientToolchainFixture>
{
    private readonly EdlClientToolchainFixture _fixture;

    public EbUninstallBackendTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ---------------------------------------------------------------------
    // Capture: LUN 0 GPT pair plus the whole actual misc partition
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Capture_ReadsOnlyLun0PrimaryBackupAndWholeMisc()
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);
        var runner = new EbRunner(_fixture.Toolchain, scenario.Content);
        EdlClient client = scenario.CreateClient(runner);
        string directory = NewUnusedPath("c001-capture");

        using EdlUninstallCapture capture = await EdlUninstallCapture.CaptureAsync(
            client, _fixture.Toolchain, scenario.Binding, directory);

        var roles = new[] { "gpt_lun0_primary", "gpt_lun0_backup", "misc" };
        Assert.Equal(roles.Length, capture.Regions.Count);
        Assert.All(roles, role => Assert.True(capture.Regions.ContainsKey(role), role));

        // One probe on LUN 0 only, and exactly three reads, all of them on LUN 0.
        Assert.Equal(1, runner.Commands.Count(c => HasArgument(c, "printgpt")));
        Assert.DoesNotContain(runner.Commands, c => LunArgument(c) == 4);
        Assert.Equal(3, runner.Reads.Count);
        Assert.All(runner.Reads, r => Assert.Equal(0, r.Lun));
        Assert.Contains(runner.Reads, r => r.Start == 0 && r.Count == EbFixture.CaptureSectors);
        Assert.Contains(runner.Reads, r =>
            r.Start == EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors && r.Count == EbFixture.CaptureSectors);
        Assert.Contains(runner.Reads, r => r.Start == scenario.MiscStart && r.Count == EbFixture.MiscCount);

        foreach (string role in roles)
        {
            EdlCapturedRegion region = capture.Regions[role];
            Assert.Equal(0, region.Lun);
            Assert.Equal(EbFixture.SectorSize, region.SectorSize);
            Assert.True(File.Exists(region.FilePath), role);
            Assert.StartsWith(directory, region.FilePath);

            byte[] bytes = File.ReadAllBytes(region.FilePath);
            Assert.Equal(region.SectorCount * region.SectorSize, region.Length);
            Assert.Equal(region.Length, bytes.LongLength);
            Assert.Equal(EbBytes.ShaHex(bytes), region.Sha256);
        }

        // The whole misc partition, derived from the actual GPT label, not from a G4 constant.
        Assert.Equal(EbFixture.MiscCount, capture.Regions["misc"].SectorCount);
        Assert.Equal(scenario.MiscStart, capture.Regions["misc"].StartSector);
        Assert.Equal(EbFixture.SectorSize, capture.Lun0Geometry.SectorSize);
        Assert.NotNull(capture.Lun0Table);
        Assert.Same(scenario.Binding, capture.Binding);
        Assert.Equal(directory, capture.DirectoryPath);

        Assert.Equal(0, runner.DeviceWriteCount);
        Assert.Equal(0, runner.DeviceResetCount);
        Assert.Equal(0, runner.PythonCallCount);
        Assert.Empty(runner.AvbRequests);
    }

    [Theory]
    [InlineData("corrupt")]
    [InlineData("missing-misc")]
    [InlineData("duplicate-misc")]
    public async Task Capture_RejectsBadOrAmbiguousGpt_BeforeAnyPartitionRead(string fault)
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);

        if (string.Equals(fault, "corrupt", StringComparison.Ordinal))
        {
            // Flip one byte inside the primary header (firstUsableLba area) so the header CRC
            // no longer matches the payload.
            byte[] slice = scenario.Content.Get(0, 0, EbFixture.CaptureSectors);
            slice[EbFixture.SectorSize + 40] ^= 0x5A;
        }
        else
        {
            GptPartitionSpec[] current = EbFixture.CurrentLun0Parts(scenario.MiscStart);

            if (string.Equals(fault, "missing-misc", StringComparison.Ordinal))
            {
                ReplaceLun0Gpt(scenario, new[] { current[0], current[2], current[3], current[4] });
            }
            else
            {
                ReplaceLun0Gpt(scenario, new[]
                {
                    current[0],
                    current[1],
                    current[2],
                    current[3],
                    current[4],
                    new GptPartitionSpec(
                        6,
                        "misc",
                        EbFixture.ProinfoType,
                        "11111111-2222-4333-8444-5555555555e5",
                        scenario.MiscStart + EbFixture.MiscCount,
                        EbFixture.MiscCount,
                        0UL),
                });
            }
        }

        var runner = new EbRunner(_fixture.Toolchain, scenario.Content);
        EdlClient client = scenario.CreateClient(runner);
        string directory = NewUnusedPath("c001-capture-bad-gpt");

        Exception? error = await Record.ExceptionAsync(() =>
            EdlUninstallCapture.CaptureAsync(client, _fixture.Toolchain, scenario.Binding, directory));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Equal(0, runner.PythonCallCount);
        Assert.DoesNotContain(runner.Reads, r => r.Count == EbFixture.MiscCount);

        // The raw probe files are preserved; nothing is deleted on the reject path.
        Assert.True(Directory.Exists(directory));
        Assert.NotEmpty(Directory.GetFiles(directory));
    }

    [Fact]
    public async Task Capture_RejectsForeignBinding_BeforeAnyIo()
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);
        var runner = new EbRunner(_fixture.Toolchain, scenario.Content);
        EdlClient client = scenario.CreateClient(runner);
        EdlEntryResult otherBinding = EbScenario.BindingFor(_fixture.Toolchain, "C0019999");
        string directory = NewUnusedPath("c001-capture-binding");

        Exception? error = await Record.ExceptionAsync(() =>
            EdlUninstallCapture.CaptureAsync(client, _fixture.Toolchain, otherBinding, directory));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Empty(runner.Commands);
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public async Task Capture_HonorsCancellationBeforeAnyIo()
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);
        var runner = new EbRunner(_fixture.Toolchain, scenario.Content);
        EdlClient client = scenario.CreateClient(runner);
        string directory = NewUnusedPath("c001-capture-cancel");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Exception? error = await Record.ExceptionAsync(() =>
            EdlUninstallCapture.CaptureAsync(
                client, _fixture.Toolchain, scenario.Binding, directory, cancelled.Token));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.Empty(runner.Commands);
        Assert.False(Directory.Exists(directory));
    }

    // ---------------------------------------------------------------------
    // Factory: only the original GPT pair, never AVB and never LUN 4
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Factory_PreparesUsingOnlyGptPair_AndNoAvbOrLun4()
    {
        var prepared = await PrepareFactoryAsync();
        using EdlUninstallBackend backend = prepared.Backend;
        EbRunner runner = prepared.Runner;
        EbScenario scenario = prepared.Scenario;

        UserdataUninstallSnapshot snapshot = backend.Snapshot;
        Assert.NotNull(snapshot.Identity);

        string identity = snapshot.Identity.ToString() ?? string.Empty;
        Assert.Contains("EB0010001", identity, StringComparison.Ordinal);
        Assert.Contains(EbFixture.Model, identity, StringComparison.Ordinal);

        // The misc fingerprint covers the whole captured partition, not only the BCB unit.
        Assert.Equal(
            EbBytes.ShaHex(scenario.Content.Get(0, scenario.MiscStart, EbFixture.MiscCount)),
            snapshot.MiscFingerprint);

        // Exactly three LUN 0 captures: primary, backup and the whole misc partition.
        Assert.Equal(3, runner.Reads.Count);
        Assert.All(runner.Reads, read => Assert.Equal(0, read.Lun));
        Assert.Contains(runner.Reads, read => read.Start == 0 && read.Count == EbFixture.CaptureSectors);
        Assert.Contains(runner.Reads, read =>
            read.Start == EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors
            && read.Count == EbFixture.CaptureSectors);
        Assert.Contains(runner.Reads, read => read.Start == scenario.MiscStart && read.Count == EbFixture.MiscCount);

        Assert.Equal("edl:ufs:lun:0", backend.Inputs.CurrentTable.DeviceId);

        // One GPT helper call, zero AVB calls, and never a LUN 4 argument.
        Assert.Equal(1, runner.PythonCallCount);
        Assert.Empty(runner.AvbRequests);
        Assert.DoesNotContain(runner.Commands, command => LunArgument(command) == 4);

        // The backup lives below the test-owned work root and is durable on disk.
        Assert.True(Directory.Exists(backend.BackupDirectory), backend.BackupDirectory);
        Assert.NotEmpty(Directory.GetFiles(backend.BackupDirectory, "*", SearchOption.AllDirectories));
        Assert.StartsWith(_fixture.WorkRoot, backend.BackupDirectory);

        // The supplied original pair is read-only input.
        Assert.Equal(scenario.OriginalPrimary, File.ReadAllBytes(prepared.Assets.OriginalPrimaryGptPath));
        Assert.Equal(scenario.OriginalBackup, File.ReadAllBytes(prepared.Assets.OriginalBackupGptPath));

        // A healthy factory snapshot re-inspects with three fresh LUN 0 reads and still no AVB.
        int readsBeforeInspect = runner.Reads.Count;
        UserdataUninstallSnapshot fresh = await backend.InspectAsync(CancellationToken.None);
        Assert.Equal(readsBeforeInspect + 3, runner.Reads.Count);
        Assert.Equal(snapshot.Identity.ToString(), fresh.Identity.ToString());
        Assert.Equal(snapshot.TableFingerprint, fresh.TableFingerprint);
        Assert.Equal(snapshot.MiscFingerprint, fresh.MiscFingerprint);
        Assert.Equal(snapshot.InstallationRecordFingerprint, fresh.InstallationRecordFingerprint);
        Assert.Equal(snapshot.MaintenanceValidated, fresh.MaintenanceValidated);
        Assert.Equal(snapshot.OtaState, fresh.OtaState);
        Assert.Empty(runner.AvbRequests);
    }

    [Theory]
    [InlineData("bounds")]
    [InlineData("misc")]
    [InlineData("region")]
    public async Task Factory_RejectsInvalidGptPlan(string fault)
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);
        var runner = new EbRunner(_fixture.Toolchain, scenario.Content, new EbFakeOptions { GptFault = fault });
        UninstallGptAssets assets = NewGptAssets(scenario);

        EdlUninstallBackend? backend = null;
        Exception? error = await Record.ExceptionAsync(async () =>
        {
            backend = await EdlUninstallBackend.CreatePreparedAsync(
                scenario.CreateClient(runner),
                _fixture.Toolchain,
                scenario.Binding,
                assets,
                NewUnusedPath("c001-factory-bad-" + fault),
                runner,
                CancellationToken.None);
        });

        try
        {
            Assert.NotNull(error);
            Assert.IsNotType<NotImplementedException>(error);
        }
        finally
        {
            backend?.Dispose();
        }
    }

    [Theory]
    [InlineData("gpt")]
    [InlineData("misc")]
    public async Task Inspect_ReadsFreshAndRejectsDrift(string drift)
    {
        var prepared = await PrepareFactoryAsync();
        using EdlUninstallBackend backend = prepared.Backend;

        if (string.Equals(drift, "gpt", StringComparison.Ordinal))
        {
            // Flip header byte 40 in the primary header sector; the header CRC no longer matches.
            prepared.Scenario.Content.Get(0, 0, EbFixture.CaptureSectors)[EbFixture.SectorSize + 40] ^= 1;
        }
        else
        {
            // Flip a real misc byte so the whole-partition fingerprint changes.
            prepared.Scenario.Content.Get(0, prepared.Scenario.MiscStart, EbFixture.MiscCount)[0] ^= 1;
        }

        int readsBefore = prepared.Runner.Reads.Count;
        Exception? error = await Record.ExceptionAsync(() => backend.InspectAsync(CancellationToken.None));

        Assert.NotNull(error);
        Assert.IsNotType<NotImplementedException>(error);
        Assert.True(prepared.Runner.Reads.Count >= readsBefore + 3);
        Assert.All(prepared.Runner.Reads.Skip(readsBefore), read => Assert.Equal(0, read.Lun));
        Assert.Empty(prepared.Runner.AvbRequests);
    }

    // ---------------------------------------------------------------------
    // Factory helpers: real EdlClient argv through the fake runner, two files only
    // ---------------------------------------------------------------------

    private async Task<(EdlUninstallBackend Backend, EbRunner Runner, EbScenario Scenario, UninstallGptAssets Assets)>
        PrepareFactoryAsync()
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain);
        var runner = new EbRunner(_fixture.Toolchain, scenario.Content);
        UninstallGptAssets assets = NewGptAssets(scenario);
        string jobRoot = NewUnusedPath("c001-factory-jobs");

        EdlUninstallBackend backend = await EdlUninstallBackend.CreatePreparedAsync(
            scenario.CreateClient(runner),
            _fixture.Toolchain,
            scenario.Binding,
            assets,
            jobRoot,
            runner,
            CancellationToken.None);

        return (backend, runner, scenario, assets);
    }

    private UninstallGptAssets NewGptAssets(EbScenario scenario)
    {
        string root = NewDirectory("c001-factory-assets");
        string primary = Path.Combine(root, "original_primary.gpt");
        string backup = Path.Combine(root, "original_backup.gpt");
        File.WriteAllBytes(primary, scenario.OriginalPrimary);
        File.WriteAllBytes(backup, scenario.OriginalBackup);
        return new UninstallGptAssets(primary, backup);
    }

    private string NewUnusedPath(string prefix) =>
        Path.Combine(_fixture.WorkRoot, prefix + "-" + Guid.NewGuid().ToString("N"));

    private string NewDirectory(string prefix)
    {
        string path = NewUnusedPath(prefix);
        Directory.CreateDirectory(path);
        return path;
    }

    private static bool HasArgument(ProcessCommand command, string token) =>
        command.Arguments.Any(argument => string.Equals(argument, token, StringComparison.OrdinalIgnoreCase));

    private static int? LunArgument(ProcessCommand command)
    {
        for (int i = 0; i + 1 < command.Arguments.Count; i++)
        {
            if (string.Equals(command.Arguments[i], "--lun", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(command.Arguments[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int lun))
            {
                return lun;
            }
        }

        return null;
    }

    private static void ReplaceLun0Gpt(EbScenario scenario, GptPartitionSpec[] parts)
    {
        int captureBytes = EbFixture.CaptureSectors * EbFixture.SectorSize;
        var image = new GptImage(
            EbFixture.SectorSize,
            EbFixture.Lun0DiskBytes,
            EbFixture.DiskGuid,
            EbFixture.FirstUsableSector,
            EbFixture.LastUsable4096,
            parts);

        scenario.Content.Replace(
            0, 0, EbFixture.CaptureSectors, EbBytes.PadEnd(image.BuildPrimaryFragment(), captureBytes));
        scenario.Content.Replace(
            0,
            EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors,
            EbFixture.CaptureSectors,
            EbBytes.PadStart(image.BuildBackupFragment(), captureBytes));
    }
}

internal sealed class EbBackendFixture
{
    public EbBackendFixture(
        EdlUninstallBackend backend,
        EbRunner runner,
        EbScenario scenario,
        string jobRoot,
        string assetsRoot,
        UninstallRestoreAssets assets,
        string stockASha)
    {
        Backend = backend;
        Runner = runner;
        Scenario = scenario;
        JobRoot = jobRoot;
        AssetsRoot = assetsRoot;
        Assets = assets;
        StockASha = stockASha;
    }

    public EdlUninstallBackend Backend { get; }
    public EbRunner Runner { get; }
    public EbScenario Scenario { get; }
    public string JobRoot { get; }
    public string AssetsRoot { get; }
    public UninstallRestoreAssets Assets { get; }
    public string StockASha { get; }
}

internal sealed class EbFakeOptions
{
    public string? AvbFault { get; set; }
    public string? AvbFaultSlot { get; set; }
    public string? GptFault { get; set; }
}

/// <summary>
/// Deterministic fake EDL client runner. It answers only through argv it actually
/// receives, writes files only below test-owned paths, and never launches a process.
/// </summary>
internal sealed class EbRunner : ICommandRunner
{
    private readonly EdlToolchain _tools;
    private readonly EbDiskContent _content;
    private readonly EbFakeOptions _options;
    private bool _initialProbeIssued;

    public EbRunner(EdlToolchain tools, EbDiskContent content, EbFakeOptions? options = null)
    {
        _tools = tools;
        _content = content;
        _options = options ?? new EbFakeOptions();
    }

    public List<ProcessCommand> Commands { get; } = new();
    public List<(int Lun, long Start, long Count, string Path)> Reads { get; } = new();
    public List<JsonElement> AvbRequests { get; } = new();
    public List<JsonElement> GptRequests { get; } = new();
    public JsonElement? LastGptResponse { get; private set; }
    public int PythonCallCount { get; private set; }
    public int DeviceWriteCount { get; private set; }
    public int DeviceResetCount { get; private set; }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Commands.Add(command);

        if (string.Equals(command.Executable, _tools.PythonPath, StringComparison.OrdinalIgnoreCase))
        {
            PythonCallCount++;
            return Task.FromResult(RunPython(command));
        }

        return Task.FromResult(RunClient(command));
    }

    private ProcessResult RunClient(ProcessCommand command)
    {
        if (Has(command.Arguments, "printgpt"))
        {
            return RunProbe(command.Arguments);
        }

        if (Has(command.Arguments, "read-sector"))
        {
            return RunRead(command.Arguments);
        }

        if (Has(command.Arguments, "write") || Has(command.Arguments, "write-sector"))
        {
            DeviceWriteCount++;
            return new ProcessResult(0, "ok", string.Empty);
        }

        if (Has(command.Arguments, "reset"))
        {
            DeviceResetCount++;
            return new ProcessResult(0, "ok", string.Empty);
        }

        throw new InvalidOperationException(
            "eb001: unexpected EDL argv: " + string.Join(" ", command.Arguments));
    }

    private ProcessResult RunProbe(IReadOnlyList<string> args)
    {
        int lun = 0;
        int lunIndex = IndexOf(args, "--lun");
        if (lunIndex >= 0 && lunIndex + 1 < args.Count)
        {
            lun = int.Parse(args[lunIndex + 1], CultureInfo.InvariantCulture);
        }

        long totalSectors = lun == 0 ? EbFixture.Lun0TotalSectors : EbFixture.Lun4TotalSectors;

        if (!_initialProbeIssued)
        {
            _initialProbeIssued = true;
            return new ProcessResult(0, E003EdlTestData.InitialProbe(totalSectors, lun), string.Empty);
        }

        return new ProcessResult(
            0,
            E003EdlTestData.Selected() + "\n" + E003EdlTestData.Geometry(lun, totalSectors),
            string.Empty);
    }

    private ProcessResult RunRead(IReadOnlyList<string> args)
    {
        int index = IndexOf(args, "read-sector");
        if (index < 0 || index + 3 >= args.Count)
        {
            throw new InvalidOperationException("eb001: unexpected read argv: " + string.Join(" ", args));
        }

        long start = long.Parse(args[index + 1], CultureInfo.InvariantCulture);
        long count = long.Parse(args[index + 2], CultureInfo.InvariantCulture);
        string path = args[index + 3];

        int lun = 0;
        int lunIndex = IndexOf(args, "--lun");
        if (lunIndex >= 0 && lunIndex + 1 < args.Count)
        {
            lun = int.Parse(args[lunIndex + 1], CultureInfo.InvariantCulture);
        }

        byte[] bytes = _content.Get(lun, start, count);
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllBytes(path, bytes);
        Reads.Add((lun, start, count, path));

        return new ProcessResult(
            0,
            E003EdlTestData.ReadSuccess(lun, start, count, bytes.LongLength, path),
            string.Empty);
    }

    private ProcessResult RunPython(ProcessCommand command)
    {
        if (command.Arguments.Count != 3
            || !string.Equals(command.Arguments[0], "-B", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "eb001: unexpected python argv: " + string.Join(" ", command.Arguments));
        }

        string requestPath = command.Arguments[2];
        string text = File.ReadAllText(requestPath);

        using JsonDocument document = JsonDocument.Parse(text);
        JsonElement request = document.RootElement.Clone();

        if (string.Equals(command.Arguments[1], _tools.AvbCliPath, StringComparison.OrdinalIgnoreCase))
        {
            AvbRequests.Add(request);
            return RunAvb(request);
        }

        if (string.Equals(command.Arguments[1], _tools.GptCliPath, StringComparison.OrdinalIgnoreCase))
        {
            GptRequests.Add(request);
            return RunGpt(request);
        }

        throw new InvalidOperationException(
            "eb001: unexpected python script: " + command.Arguments[1]);
    }

    private ProcessResult RunAvb(JsonElement request)
    {
        string slot = request.GetProperty("slot").GetString() ?? string.Empty;
        string stockPath = request.GetProperty("stockBootPath").GetString() ?? string.Empty;

        bool faultApplies = _options.AvbFault is not null
            && (_options.AvbFaultSlot is null || string.Equals(_options.AvbFaultSlot, slot, StringComparison.Ordinal));

        if (faultApplies && string.Equals(_options.AvbFault, "exit", StringComparison.Ordinal))
        {
            return new ProcessResult(2, string.Empty, "eb001 avb failure");
        }

        if (faultApplies && string.Equals(_options.AvbFault, "malformed", StringComparison.Ordinal))
        {
            return new ProcessResult(0, "{ \"schemaVersion\": 1, ", string.Empty);
        }

        string stockSha = File.Exists(stockPath)
            ? EbBytes.ShaHex(File.ReadAllBytes(stockPath))
            : new string('0', 64);

        string reportedSlot = slot;
        if (faultApplies && string.Equals(_options.AvbFault, "slot", StringComparison.Ordinal))
        {
            reportedSlot = slot == "a" ? "b" : "a";
        }

        if (faultApplies && string.Equals(_options.AvbFault, "hash", StringComparison.Ordinal))
        {
            stockSha = new string('1', 64);
        }

        var evidence = new Dictionary<string, object?>
        {
            ["slot"] = reportedSlot,
            ["stock_sha256"] = stockSha,
            ["fingerprint"] = "Lenovo/TB322FC/TB322FC:16/W1.0"
                + (string.Equals(slot, "a", StringComparison.Ordinal) ? "3" : "4")
                + ".1/20260805:user/release-keys",
            ["root_key_sha256"] = new string('a', 64),
            ["chain_key_sha256"] = new string('b', 64),
            ["hardware_rollback_verified"] = false,
            ["os_version"] = "16",
            ["security_patch"] = "2026-08-05",
            ["boot_rollback_index"] = 2,
            ["boot_rollback_index_location"] = string.Equals(slot, "a", StringComparison.Ordinal) ? 1 : 2,
            ["slot_vbmeta_rollback_index"] = 3,
            ["slot_vbmeta_rollback_index_location"] = string.Equals(slot, "a", StringComparison.Ordinal) ? 3 : 4,
            ["proof"] = "signed-current",
        };

        if (faultApplies && string.Equals(_options.AvbFault, "missing", StringComparison.Ordinal))
        {
            evidence.Remove("fingerprint");
        }

        var response = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["ok"] = true,
            ["evidence"] = evidence,
        };

        return new ProcessResult(0, JsonSerializer.Serialize(response), string.Empty);
    }

    private ProcessResult RunGpt(JsonElement request)
    {
        int sectorSize = request.GetProperty("sectorSize").GetInt32();
        long diskBytes = request.GetProperty("diskBytes").GetInt64();
        long totalSectors = diskBytes / sectorSize;

        string currentPrimaryPath = request.GetProperty("currentPrimary").GetProperty("path").GetString() ?? string.Empty;
        string currentBackupPath = request.GetProperty("currentBackup").GetProperty("path").GetString() ?? string.Empty;
        string originalPrimaryPath = request.GetProperty("originalPrimary").GetProperty("path").GetString() ?? string.Empty;
        string originalBackupPath = request.GetProperty("originalBackup").GetProperty("path").GetString() ?? string.Empty;
        string miscPath = request.GetProperty("misc").GetProperty("path").GetString() ?? string.Empty;
        string outputDirectory = request.GetProperty("outputDirectory").GetString() ?? string.Empty;

        Directory.CreateDirectory(outputDirectory);

        byte[] currentPrimary = File.ReadAllBytes(currentPrimaryPath);
        byte[] currentBackup = File.ReadAllBytes(currentBackupPath);
        byte[] restoredPrimary = File.ReadAllBytes(originalPrimaryPath);
        byte[] restoredBackup = File.ReadAllBytes(originalBackupPath);
        byte[] miscBytes = File.ReadAllBytes(miscPath);

        (long currentPrimaryEntriesLba, int entryCount, int entrySize) =
            ReadHeaderGeometry(currentPrimary, sectorSize, headerAtEnd: false);
        (long currentBackupEntriesLba, _, _) =
            ReadHeaderGeometry(currentBackup, sectorSize, headerAtEnd: true);
        (long restoredPrimaryEntriesLba, _, _) =
            ReadHeaderGeometry(restoredPrimary, sectorSize, headerAtEnd: false);
        (long restoredBackupEntriesLba, _, _) =
            ReadHeaderGeometry(restoredBackup, sectorSize, headerAtEnd: true);

        int arraySectorCount = ArraySectorCount(entryCount, entrySize, sectorSize);
        int alignedArrayBytes = arraySectorCount * sectorSize;

        // Restored fragments are anchored at LBA 0 (primary) or at the disk end (backup) while the
        // current capture may be a larger origin window, so each offset uses its real origin.
        int restoredPrimaryArrayOffset = checked((int)(restoredPrimaryEntriesLba * sectorSize));
        int restoredBackupArrayOffset = checked((int)(
            restoredBackupEntriesLba * sectorSize - (diskBytes - restoredBackup.LongLength)));
        int currentPrimaryArrayOffset = checked((int)(currentPrimaryEntriesLba * sectorSize));
        int currentBackupArrayOffset = checked((int)(
            currentBackupEntriesLba * sectorSize - (diskBytes - currentBackup.LongLength)));

        var regions = new List<Dictionary<string, object?>>
        {
            WriteRegion(outputDirectory, "backup-array", currentBackupEntriesLba * sectorSize, currentBackupEntriesLba, arraySectorCount, Slice(restoredBackup, restoredBackupArrayOffset, alignedArrayBytes)),
            WriteRegion(outputDirectory, "backup-header", diskBytes - sectorSize, totalSectors - 1, 1, Slice(restoredBackup, restoredBackup.Length - sectorSize, sectorSize)),
            WriteRegion(outputDirectory, "primary-array", currentPrimaryEntriesLba * sectorSize, currentPrimaryEntriesLba, arraySectorCount, Slice(restoredPrimary, restoredPrimaryArrayOffset, alignedArrayBytes)),
            WriteRegion(outputDirectory, "primary-header", sectorSize, 1, 1, Slice(restoredPrimary, sectorSize, sectorSize)),
        };

        byte[] postPrimary = (byte[])currentPrimary.Clone();
        Array.Copy(restoredPrimary, restoredPrimaryArrayOffset, postPrimary, currentPrimaryArrayOffset, alignedArrayBytes);
        Array.Copy(restoredPrimary, sectorSize, postPrimary, sectorSize, sectorSize);
        string postPrimaryPath = Path.Combine(outputDirectory, "post-primary.bin");
        File.WriteAllBytes(postPrimaryPath, postPrimary);

        byte[] postBackup = (byte[])currentBackup.Clone();
        Array.Copy(restoredBackup, restoredBackupArrayOffset, postBackup, currentBackupArrayOffset, alignedArrayBytes);
        Array.Copy(restoredBackup, restoredBackup.Length - sectorSize, postBackup, postBackup.Length - sectorSize, sectorSize);
        string postBackupPath = Path.Combine(outputDirectory, "post-backup.bin");
        File.WriteAllBytes(postBackupPath, postBackup);

        // Keep the full first misc sector (including 2048:4096) and only rewrite the BCB fields.
        byte[] miscUnit = Slice(miscBytes, 0, sectorSize);
        Array.Clear(miscUnit, 0, 32);
        Array.Clear(miscUnit, 64, 832 - 64);
        byte[] bcbCommand = Encoding.ASCII.GetBytes("boot-recovery");
        Array.Copy(bcbCommand, 0, miscUnit, 0, bcbCommand.Length);
        byte[] bcbRecovery = Encoding.ASCII.GetBytes("recovery\n--wipe_data\n--reason=armada-uninstall\n");
        Array.Copy(bcbRecovery, 0, miscUnit, 64, bcbRecovery.Length);

        byte[] fullAfterMisc = (byte[])miscBytes.Clone();
        Array.Copy(miscUnit, 0, fullAfterMisc, 0, sectorSize);

        string miscUnitPath = Path.Combine(outputDirectory, "misc-bcb.bin");
        File.WriteAllBytes(miscUnitPath, miscUnit);

        List<(int Number, string Name, long Start, long Count)> originalEntries = ReadEntries(restoredPrimary, sectorSize);
        List<(int Number, string Name, long Start, long Count)> currentEntries = ReadEntries(currentPrimary, sectorSize);

        var originalNames = new HashSet<string>(originalEntries.Select(e => e.Name), StringComparer.Ordinal);
        int[] removed = currentEntries
            .Where(e => !originalNames.Contains(e.Name))
            .Select(e => e.Number)
            .OrderBy(n => n)
            .ToArray();

        long userdataStart = 0;
        long userdataCount = 0;
        foreach (var (_, name, start, count) in originalEntries)
        {
            if (string.Equals(name, "userdata", StringComparison.Ordinal))
            {
                userdataStart = start;
                userdataCount = count;
                break;
            }
        }

        var plan = new Dictionary<string, object?>
        {
            ["userdataStartLba"] = userdataStart,
            ["userdataEndLbaExclusive"] = userdataStart + userdataCount,
            ["restoredBytes"] = userdataCount * sectorSize,
            ["removedPartitionNumbers"] = removed,
            ["miscBeforeSha256"] = EbBytes.ShaHex(miscBytes),
            ["miscAfterSha256"] = EbBytes.ShaHex(fullAfterMisc),
            ["regions"] = regions,
            ["postPrimary"] = new Dictionary<string, object?>
            {
                ["byteOffset"] = 0L,
                ["bytes"] = postPrimary.LongLength,
                ["sha256"] = EbBytes.ShaHex(postPrimary),
                ["path"] = postPrimaryPath,
            },
            ["postBackup"] = new Dictionary<string, object?>
            {
                ["byteOffset"] = diskBytes - currentBackup.LongLength,
                ["bytes"] = postBackup.LongLength,
                ["sha256"] = EbBytes.ShaHex(postBackup),
                ["path"] = postBackupPath,
            },
            ["miscRegion"] = new Dictionary<string, object?>
            {
                ["role"] = "misc-bcb",
                ["relativeMiscOffset"] = 0L,
                ["byteOffset"] = 0L,
                ["startSector"] = 0L,
                ["sectorCount"] = 1L,
                ["bytes"] = (long)sectorSize,
                ["sha256"] = EbBytes.ShaHex(miscUnit),
                ["path"] = miscUnitPath,
            },
            ["currentRawTableFingerprint"] = new string('c', 64),
        };

        if (string.Equals(_options.GptFault, "bounds", StringComparison.Ordinal))
        {
            plan["userdataEndLbaExclusive"] = userdataStart + userdataCount + 1;
        }
        else if (string.Equals(_options.GptFault, "misc", StringComparison.Ordinal))
        {
            plan["miscBeforeSha256"] = new string('0', 64);
        }
        else if (string.Equals(_options.GptFault, "region", StringComparison.Ordinal))
        {
            regions[0]["sha256"] = new string('0', 64);
        }

        var response = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["ok"] = true,
            ["plan"] = plan,
        };

        string json = JsonSerializer.Serialize(response);
        using JsonDocument parsed = JsonDocument.Parse(json);
        LastGptResponse = parsed.RootElement.Clone();
        return new ProcessResult(0, json, string.Empty);
    }

    private static Dictionary<string, object?> WriteRegion(
        string directory,
        string role,
        long byteOffset,
        long startSector,
        int sectorCount,
        byte[] bytes)
    {
        string path = Path.Combine(directory, role + ".bin");
        File.WriteAllBytes(path, bytes);
        return new Dictionary<string, object?>
        {
            ["role"] = role,
            ["byteOffset"] = byteOffset,
            ["startSector"] = startSector,
            ["sectorCount"] = sectorCount,
            ["bytes"] = bytes.LongLength,
            ["sha256"] = EbBytes.ShaHex(bytes),
            ["path"] = path,
        };
    }

    private static (long EntriesLba, int EntryCount, int EntrySize) ReadHeaderGeometry(byte[] fragment, int sectorSize, bool headerAtEnd)
    {
        int headerOffset = headerAtEnd ? fragment.Length - sectorSize : sectorSize;
        long entriesLba = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(fragment.AsSpan(headerOffset + 72, 8)));
        int entryCount = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(fragment.AsSpan(headerOffset + 80, 4)));
        int entrySize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(fragment.AsSpan(headerOffset + 84, 4)));
        return (entriesLba, entryCount, entrySize);
    }

    private static int ArraySectorCount(int entryCount, int entrySize, int sectorSize) =>
        checked((int)((((long)entryCount * entrySize) + sectorSize - 1) / sectorSize));

    private static List<(int Number, string Name, long Start, long Count)> ReadEntries(byte[] primary, int sectorSize)
    {
        var entries = new List<(int, string, long, long)>();
        int arrayOffset = 2 * sectorSize;

        for (int index = 0; index < 128; index++)
        {
            int offset = arrayOffset + index * 128;
            if (offset + 128 > primary.Length)
            {
                break;
            }

            bool used = false;
            for (int i = 0; i < 16; i++)
            {
                if (primary[offset + i] != 0)
                {
                    used = true;
                    break;
                }
            }

            if (!used)
            {
                continue;
            }

            long first = BitConverter.ToInt64(primary, offset + 32);
            long last = BitConverter.ToInt64(primary, offset + 40);
            string name = Encoding.Unicode.GetString(primary, offset + 56, 72).TrimEnd('\0');
            entries.Add((index + 1, name, first, last - first + 1));
        }

        return entries;
    }

    private static byte[] Slice(byte[] source, int offset, int length)
    {
        var slice = new byte[length];
        Array.Copy(source, offset, slice, 0, length);
        return slice;
    }

    private static bool Has(IReadOnlyList<string> args, string token)
    {
        foreach (string arg in args)
        {
            if (string.Equals(arg, token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static int IndexOf(IReadOnlyList<string> args, string token)
    {
        for (int i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], token, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }
}

internal sealed class EbDiskContent
{
    private readonly List<(int Lun, long Start, long Count, byte[] Bytes)> _slices = new();

    public void Add(int lun, long start, long count, byte[] bytes)
    {
        if (bytes.LongLength != count * EbFixture.SectorSize)
        {
            throw new ArgumentException("eb001: slice size does not match sector count", nameof(bytes));
        }

        _slices.Add((lun, start, count, bytes));
    }

    public void Replace(int lun, long start, long count, byte[] bytes)
    {
        for (int i = 0; i < _slices.Count; i++)
        {
            if (_slices[i].Lun == lun && _slices[i].Start == start && _slices[i].Count == count)
            {
                _slices[i] = (lun, start, count, bytes);
                return;
            }
        }

        throw new InvalidOperationException("eb001: no slice to replace");
    }

    public byte[] Get(int lun, long start, long count)
    {
        foreach ((int sliceLun, long sliceStart, long sliceCount, byte[] bytes) in _slices)
        {
            if (sliceLun == lun && sliceStart == start && sliceCount == count)
            {
                return bytes;
            }
        }

        throw new InvalidOperationException(
            string.Format(CultureInfo.InvariantCulture,
                "eb001: unexpected EDL read lun={0} start={1} count={2}", lun, start, count));
    }
}

internal sealed class EbScenario
{
    private EbScenario(
        EdlToolchain toolchain,
        EdlEntryResult binding,
        EbDiskContent content,
        long miscStart,
        long bootAStart,
        byte[] originalPrimary,
        byte[] originalBackup)
    {
        Toolchain = toolchain;
        Binding = binding;
        Content = content;
        MiscStart = miscStart;
        BootAStart = bootAStart;
        OriginalPrimary = originalPrimary;
        OriginalBackup = originalBackup;
    }

    public EdlToolchain Toolchain { get; }
    public EdlEntryResult Binding { get; }
    public EbDiskContent Content { get; }
    public long MiscStart { get; }
    public long BootAStart { get; }
    public byte[] OriginalPrimary { get; }
    public byte[] OriginalBackup { get; }

    public EdlClient CreateClient(EbRunner runner) =>
        new EdlClient(
            Toolchain,
            Binding,
            runner,
            new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    public static EdlEntryResult BindingFor(EdlToolchain tools, string serial) =>
        new EdlEntryResult(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(serial, EbFixture.Model, BootloaderState.Locked)
                {
                    Firmware = new FirmwareSnapshot(
                        tools.AndroidBuild,
                        BuildFingerprint: null,
                        AndroidRelease: null,
                        SecurityPatch: null,
                        AndroidReportedBootloaderState: BootloaderState.Unknown),
                },
                EbFixture.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            EbFixture.BusSerialHex);

    public static EbScenario Create(
        EdlToolchain tools,
        long miscStart = EbFixture.OriginalMiscStart,
        long bootAStart = EbFixture.BootAStart,
        bool duplicateBootA = false,
        bool missingVbmetaB = false)
    {
        var currentLun0 = new GptImage(
            EbFixture.SectorSize,
            EbFixture.Lun0DiskBytes,
            EbFixture.DiskGuid,
            EbFixture.FirstUsableSector,
            EbFixture.LastUsable4096,
            EbFixture.CurrentLun0Parts(miscStart));

        var originalLun0 = new GptImage(
            EbFixture.SectorSize,
            EbFixture.Lun0DiskBytes,
            EbFixture.DiskGuid,
            EbFixture.FirstUsableSector,
            EbFixture.LastUsable4096,
            EbFixture.OriginalLun0Parts());

        var lun4 = new GptImage(
            EbFixture.SectorSize,
            EbFixture.Lun4DiskBytes,
            EbFixture.Lun4DiskGuid,
            EbFixture.FirstUsableSector,
            EbFixture.Lun4LastUsable,
            EbFixture.Lun4Parts(bootAStart, duplicateBootA, missingVbmetaB));

        var content = new EbDiskContent();
        int captureBytes = EbFixture.CaptureSectors * EbFixture.SectorSize;

        content.Add(0, 0, EbFixture.CaptureSectors, EbBytes.PadEnd(currentLun0.BuildPrimaryFragment(), captureBytes));
        content.Add(0, EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors, EbFixture.CaptureSectors, EbBytes.PadStart(currentLun0.BuildBackupFragment(), captureBytes));
        content.Add(0, miscStart, EbFixture.MiscCount, EbBytes.Pattern(miscStart, (int)(EbFixture.MiscCount * EbFixture.SectorSize)));

        content.Add(4, 0, EbFixture.CaptureSectors, EbBytes.PadEnd(lun4.BuildPrimaryFragment(), captureBytes));
        content.Add(4, EbFixture.Lun4TotalSectors - EbFixture.CaptureSectors, EbFixture.CaptureSectors, EbBytes.PadStart(lun4.BuildBackupFragment(), captureBytes));

        content.Add(4, bootAStart, EbFixture.BootPartitionSectors, EbBytes.Pattern(bootAStart, EbFixture.BootPartitionSectors * EbFixture.SectorSize));
        content.Add(4, EbFixture.BootBStart, EbFixture.BootPartitionSectors, EbBytes.Pattern(EbFixture.BootBStart, EbFixture.BootPartitionSectors * EbFixture.SectorSize));
        content.Add(4, EbFixture.VbmetaAStart, EbFixture.VbmetaPartitionSectors, EbBytes.Pattern(EbFixture.VbmetaAStart, EbFixture.VbmetaPartitionSectors * EbFixture.SectorSize));

        if (!missingVbmetaB)
        {
            content.Add(4, EbFixture.VbmetaBStart, EbFixture.VbmetaPartitionSectors, EbBytes.Pattern(EbFixture.VbmetaBStart, EbFixture.VbmetaPartitionSectors * EbFixture.SectorSize));
        }

        return new EbScenario(
            tools,
            BindingFor(tools, "EB0010001"),
            content,
            miscStart,
            bootAStart,
            originalLun0.BuildPrimaryFragment(),
            originalLun0.BuildBackupFragment());
    }
}

internal static class EbFixture
{
    public const int SectorSize = 4096;
    public const int CaptureSectors = 64;

    public const long Lun0TotalSectors = 123871232L;
    public const long Lun0DiskBytes = 507376566272L;
    public const long LastUsable4096 = 123871226L;
    public const long FirstUsableSector = 6L;

    public const long Lun4TotalSectors = 4096L;
    public const long Lun4DiskBytes = Lun4TotalSectors * SectorSize;
    public const long Lun4LastUsable = Lun4TotalSectors - 6L;

    public const long ProinfoStart = 6L;
    public const long ProinfoCount = 768L;

    public const long OriginalMiscStart = 89992L;
    public const long MiscCount = 256L;

    public const long UserdataStart = 5972392L;
    public const long OriginalUserdataCount = 117898835L;
    public const long CurrentUserdataCount = 33554432L;

    public const long BootStart = 39526912L;
    public const long BootCount = 262144L;
    public const long RootStart = 39789056L;
    public const long RootCount = 84082171L;

    public const long RestoredAndroidBytes = 482913628160L;

    public const int BootPartitionSectors = 16;
    public const int VbmetaPartitionSectors = 8;
    public const long BootAStart = 100L;
    public const long BootBStart = 200L;
    public const long VbmetaAStart = 300L;
    public const long VbmetaBStart = 400L;

    public const string Model = "TB322FC";
    public const string BusSerialHex = "C1D2E3F4";
    public const string SocSerialDecimal = "3251823604";

    public const string DiskGuid = "5b4e0c2a-3f7d-4e91-9c6b-1a2d3e4f5061";
    public const string Lun4DiskGuid = "9d2e1f30-5a6b-4c7d-8e9f-0a1b2c3d4e5f";

    public const string ProinfoType = "c1a2b3c4-d5e6-4f70-8192-a3b4c5d6e7f8";
    public const string ProinfoUuid = "11111111-2222-4333-8444-555555555501";
    public const string MiscUuid = "11111111-2222-4333-8444-555555555502";
    public const string UserdataType = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    public const string UserdataUuid = "11111111-2222-4333-8444-555555555503";
    public const string LinuxType = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    public const string BootUuid = "11111111-2222-4333-8444-555555555504";
    public const string RootUuid = "11111111-2222-4333-8444-555555555505";
    public const string BootAType = "aaaa0000-1111-4222-8333-444455556666";
    public const string BootAUuid = "11111111-2222-4333-8444-5555555555a1";
    public const string BootBUuid = "11111111-2222-4333-8444-5555555555b2";
    public const string VbmetaAUuid = "11111111-2222-4333-8444-5555555555c3";
    public const string VbmetaBUuid = "11111111-2222-4333-8444-5555555555d4";

    public static readonly string[] CaptureRoles =
    {
        "gpt_lun0_primary",
        "gpt_lun0_backup",
        "gpt_lun4_primary",
        "gpt_lun4_backup",
        "boot_a",
        "boot_b",
        "vbmeta_a",
        "vbmeta_b",
        "misc",
    };

    public static GptPartitionSpec[] CurrentLun0Parts(long miscStart) => new[]
    {
        new GptPartitionSpec(1, "proinfo", ProinfoType, ProinfoUuid, ProinfoStart, ProinfoCount, 0UL),
        new GptPartitionSpec(2, "misc", ProinfoType, MiscUuid, miscStart, MiscCount, 0UL),
        new GptPartitionSpec(3, "userdata", UserdataType, UserdataUuid, UserdataStart, CurrentUserdataCount, 0UL),
        new GptPartitionSpec(4, "ARMADA_BOOT", LinuxType, BootUuid, BootStart, BootCount, 0UL),
        new GptPartitionSpec(5, "ARMADA_ROOT", LinuxType, RootUuid, RootStart, RootCount, 0UL),
    };

    public static GptPartitionSpec[] OriginalLun0Parts() => new[]
    {
        new GptPartitionSpec(1, "proinfo", ProinfoType, ProinfoUuid, ProinfoStart, ProinfoCount, 0UL),
        new GptPartitionSpec(2, "misc", ProinfoType, MiscUuid, OriginalMiscStart, MiscCount, 0UL),
        new GptPartitionSpec(3, "userdata", UserdataType, UserdataUuid, UserdataStart, OriginalUserdataCount, 0UL),
    };

    public static GptPartitionSpec[] Lun4Parts(long bootAStart, bool duplicateBootA, bool missingVbmetaB)
    {
        var parts = new List<GptPartitionSpec>
        {
            new GptPartitionSpec(1, "boot_a", BootAType, BootAUuid, bootAStart, BootPartitionSectors, 0UL),
            new GptPartitionSpec(2, "boot_b", BootAType, BootBUuid, BootBStart, BootPartitionSectors, 0UL),
            new GptPartitionSpec(3, "vbmeta_a", BootAType, VbmetaAUuid, VbmetaAStart, VbmetaPartitionSectors, 0UL),
        };

        if (!missingVbmetaB)
        {
            parts.Add(new GptPartitionSpec(4, "vbmeta_b", BootAType, VbmetaBUuid, VbmetaBStart, VbmetaPartitionSectors, 0UL));
        }

        if (duplicateBootA)
        {
            parts.Add(new GptPartitionSpec(5, "boot_a", BootAType, "11111111-2222-4333-8444-5555555555ff", 500L, VbmetaPartitionSectors, 0UL));
        }

        return parts.ToArray();
    }
}

internal static class EbBytes
{
    public static byte[] Pattern(long seed, int length)
    {
        var bytes = new byte[length];
        uint state = unchecked((uint)(seed * 2654435761L) + 1u);
        for (int i = 0; i < length; i++)
        {
            state = unchecked(state * 1664525u + 1013904223u);
            bytes[i] = (byte)(state >> 24);
        }

        return bytes;
    }

    public static byte[] PadEnd(byte[] fragment, int totalLength)
    {
        if (fragment.Length >= totalLength)
        {
            return (byte[])fragment.Clone();
        }

        var result = new byte[totalLength];
        Array.Copy(fragment, result, fragment.Length);
        return result;
    }

    public static byte[] PadStart(byte[] fragment, int totalLength)
    {
        if (fragment.Length >= totalLength)
        {
            return (byte[])fragment.Clone();
        }

        var result = new byte[totalLength];
        Array.Copy(fragment, 0, result, totalLength - fragment.Length, fragment.Length);
        return result;
    }

    public static string ShaHex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
