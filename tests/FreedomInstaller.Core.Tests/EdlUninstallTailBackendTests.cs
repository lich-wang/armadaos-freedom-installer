using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// U3d: real EdlUninstallBackend.CreatePreparedAsync coverage for the retained board
/// backup ("modern 3-tail") layout. The EbRunner fixture is used only as a scripted
/// EDL/evidence backend (it never launches a process); the GPT planning call is
/// intercepted so the expected post layout is a fixed known fixture, not a second
/// planner implementation. All validation of captured/current GPT bytes, request JSON,
/// response regions/hashes and post images happens through the actual backend code.
/// </summary>
public sealed class EdlUninstallTailBackendTests : IClassFixture<EdlClientToolchainFixture>
{
    private readonly EdlClientToolchainFixture _fixture;

    public EdlUninstallTailBackendTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task CreatePreparedAsync_ModernBoardBackupTail_PreparesRecordPlanAndPersistsManifest()
    {
        TailCaseContext context = CreateCase(
            nameof(CreatePreparedAsync_ModernBoardBackupTail_PreparesRecordPlanAndPersistsManifest),
            counterfeitScalars: false);

        using EdlUninstallBackend backend = await EdlUninstallBackend.CreatePreparedAsync(
            context.Client,
            context.Client.Toolchain,
            context.Client.Binding,
            new UninstallGptAssets(context.OriginalPrimaryPath, context.OriginalBackupPath),
            context.CaseDirectory,
            context.Wrapper,
            CancellationToken.None);

        Assert.Equal(TailBackupConstants.BoardBackupPartUuid, backend.Inputs.Record.BoardBackupPartUuid, ignoreCase: true);
        Assert.Equal(TailBackupConstants.BackupStartSector, backend.Inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(
            EbFixture.RestoredAndroidBytes - TailBackupConstants.TwoGiBBytes,
            backend.Inputs.Plan.RestoredAndroidBytes);
        Assert.Equal(new long[] { 4L, 5L }, backend.Inputs.Plan.RemovedPartitionNumbers);

        JsonElement request = Assert.Single(context.Wrapper.CapturedGptRequests);
        Assert.Equal(
            TailBackupConstants.BoardBackupPartUuid,
            request.GetProperty("owned").GetProperty("boardBackupPartUuid").GetString(),
            ignoreCase: true);

        // The captured current GPT is the genuine fresh capture (byte-identical to the
        // staged current image), so its partition 6 entry carries the board backup GUID,
        // type, extent and attributes through actual backend capture.
        string currentPrimaryCapturePath = request.GetProperty("currentPrimary").GetProperty("path").GetString() ?? string.Empty;
        byte[] currentPrimaryCapture = File.ReadAllBytes(currentPrimaryCapturePath);
        Assert.Equal(
            context.CurrentPrimaryFragment,
            currentPrimaryCapture[..context.CurrentPrimaryFragment.Length]);

        string currentBackupCapturePath = request.GetProperty("currentBackup").GetProperty("path").GetString() ?? string.Empty;
        byte[] currentBackupCapture = File.ReadAllBytes(currentBackupCapturePath);
        Assert.Equal(
            context.CurrentBackupFragment,
            currentBackupCapture[^context.CurrentBackupFragment.Length..]);

        // The proposed post images are produced by overlaying the known expected post
        // table onto the capture; their GPT tails/head must byte-match the expected post
        // fragments, which encode the retained backup entry (partition number 6 unchanged;
        // same GUID/type/extent/attrs) and no BOOT/ROOT entries.
        JsonElement response = context.Inner.LastGptResponse
            ?? throw new InvalidOperationException("tail010: inner runner produced no gpt response");
        string postBackupPath = response.GetProperty("plan").GetProperty("postBackup").GetProperty("path").GetString() ?? string.Empty;
        string postPrimaryPath = response.GetProperty("plan").GetProperty("postPrimary").GetProperty("path").GetString() ?? string.Empty;

        byte[] postBackup = File.ReadAllBytes(postBackupPath);
        Assert.Equal(
            context.ExpectedPostBackupFragment,
            postBackup[^context.ExpectedPostBackupFragment.Length..]);

        byte[] postPrimary = File.ReadAllBytes(postPrimaryPath);
        Assert.Equal(
            context.ExpectedPostPrimaryFragment,
            postPrimary[..context.ExpectedPostPrimaryFragment.Length]);

        // The persisted manifest records the derived board backup uuid under inputs.record.
        string manifestPath = Path.Combine(backend.BackupDirectory, "manifest.json");
        Assert.True(File.Exists(manifestPath), "tail011: manifest.json missing after prepare");
        JsonNode manifest = JsonNode.Parse(File.ReadAllText(manifestPath))
            ?? throw new InvalidOperationException("tail012: unreadable manifest.json");
        JsonNode record = manifest["inputs"]?["record"]
            ?? throw new InvalidOperationException("tail013: manifest missing inputs.record");
        Assert.Equal(
            TailBackupConstants.BoardBackupPartUuid,
            record["boardBackupPartUuid"]?.GetValue<string>(),
            ignoreCase: true);

        Assert.Equal(0, context.Inner.DeviceWriteCount);
        Assert.Equal(0, context.Inner.DeviceResetCount);

        backend.Dispose();

        // Disposal preserves the durable artifacts in the case directory.
        Assert.True(File.Exists(manifestPath), "tail014: manifest.json lost on dispose");
        Assert.True(File.Exists(context.Wrapper.CapturedGptRequestPaths[0]), "tail015: gpt request lost on dispose");
        Assert.True(File.Exists(postBackupPath), "tail016: post-backup.bin lost on dispose");
        Assert.True(File.Exists(postPrimaryPath), "tail017: post-primary.bin lost on dispose");
    }

    [Fact]
    public async Task CreatePreparedAsync_CounterfeitKeepClaimButPostDropsBackup_ThrowsRetentionGuard()
    {
        TailCaseContext context = CreateCase(
            nameof(CreatePreparedAsync_CounterfeitKeepClaimButPostDropsBackup_ThrowsRetentionGuard),
            counterfeitScalars: true);

        // The response keeps real region/post files and their hashes (geometry, range,
        // hash, overlay and CRC proofs all pass); only the claimed scalars pretend the
        // backup was retained while the actual post images were built from the plain
        // factory table, which has no backup partition.
        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => EdlUninstallBackend.CreatePreparedAsync(
                context.Client,
                context.Client.Toolchain,
                context.Client.Binding,
                new UninstallGptAssets(context.OriginalPrimaryPath, context.OriginalBackupPath),
                context.CaseDirectory,
                context.Wrapper,
                CancellationToken.None));

        Assert.Contains("board backup partition", error.Message, StringComparison.OrdinalIgnoreCase);

        JsonElement request = Assert.Single(context.Wrapper.CapturedGptRequests);
        Assert.Equal(
            TailBackupConstants.BoardBackupPartUuid,
            request.GetProperty("owned").GetProperty("boardBackupPartUuid").GetString(),
            ignoreCase: true);

        Assert.Equal(0, context.Inner.DeviceWriteCount);
        Assert.Equal(0, context.Inner.DeviceResetCount);
    }

    private TailCaseContext CreateCase(string testName, bool counterfeitScalars)
    {
        EdlToolchain tools = _fixture.Toolchain;
        string caseDirectory = _fixture.NewCaseDirectory(testName);

        EbScenario scenario = EbScenario.Create(tools);

        // Replace only the existing LUN 0 capture slices with the modern retained-backup
        // current table. No data regions (Linux/backup content) are materialized.
        GptImage currentImage = TailBackupConstants.BuildCurrentImage();
        byte[] currentPrimaryFragment = currentImage.BuildPrimaryFragment();
        byte[] currentBackupFragment = currentImage.BuildBackupFragment();
        int captureBytes = EbFixture.CaptureSectors * EbFixture.SectorSize;
        scenario.Content.Replace(
            0, 0, EbFixture.CaptureSectors, EbBytes.PadEnd(currentPrimaryFragment, captureBytes));
        scenario.Content.Replace(
            0,
            EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors,
            EbFixture.CaptureSectors,
            EbBytes.PadStart(currentBackupFragment, captureBytes));

        // Stage the genuine factory assets (full factory table, no backup) in the case folder.
        string originalPrimaryPath = Path.Combine(caseDirectory, "original-primary.bin");
        string originalBackupPath = Path.Combine(caseDirectory, "original-backup.bin");
        File.WriteAllBytes(originalPrimaryPath, scenario.OriginalPrimary);
        File.WriteAllBytes(originalBackupPath, scenario.OriginalBackup);

        // Known expected post layout: factory proinfo/misc, userdata restored to
        // originalStart..(originalEnd - 2GiB), retained backup entry, no BOOT/ROOT.
        GptImage expectedPostImage = TailBackupConstants.BuildExpectedPostImage();
        byte[] expectedPostPrimaryFragment = expectedPostImage.BuildPrimaryFragment();
        byte[] expectedPostBackupFragment = expectedPostImage.BuildBackupFragment();
        string expectedPostPrimaryPath = Path.Combine(caseDirectory, "expected-post-primary.bin");
        string expectedPostBackupPath = Path.Combine(caseDirectory, "expected-post-backup.bin");
        File.WriteAllBytes(expectedPostPrimaryPath, expectedPostPrimaryFragment);
        File.WriteAllBytes(expectedPostBackupPath, expectedPostBackupFragment);

        var inner = new EbRunner(tools, scenario.Content);
        var wrapper = new TailGptInterceptRunner(
            tools,
            inner,
            caseDirectory,
            expectedPostPrimaryPath,
            expectedPostBackupPath,
            counterfeitScalars);

        var client = new EdlClient(
            tools,
            scenario.Binding,
            wrapper,
            new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

        return new TailCaseContext(
            caseDirectory,
            originalPrimaryPath,
            originalBackupPath,
            currentPrimaryFragment,
            currentBackupFragment,
            expectedPostPrimaryFragment,
            expectedPostBackupFragment,
            inner,
            wrapper,
            client);
    }
}

internal static class TailBackupConstants
{
    public const string BoardBackupPartUuid = "9abf724f-5ce5-4adc-8b71-c16040a2dfe3";

    public const long TwoGiBSectors = (2L * 1024 * 1024 * 1024) / EbFixture.SectorSize;
    public const long TwoGiBBytes = TwoGiBSectors * EbFixture.SectorSize;

    public const long BackupStartSector =
        EbFixture.UserdataStart + EbFixture.OriginalUserdataCount - TwoGiBSectors;

    public const ulong BoardBackupAttributes = 1UL << 60;

    public const long ExpectedRestoredBytes =
        (EbFixture.OriginalUserdataCount - TwoGiBSectors) * EbFixture.SectorSize;

    public static GptImage BuildCurrentImage() => new(
        EbFixture.SectorSize,
        EbFixture.Lun0DiskBytes,
        EbFixture.DiskGuid,
        EbFixture.FirstUsableSector,
        EbFixture.LastUsable4096,
        new[]
        {
            new GptPartitionSpec(1, "proinfo", EbFixture.ProinfoType, EbFixture.ProinfoUuid, EbFixture.ProinfoStart, EbFixture.ProinfoCount, 0UL),
            new GptPartitionSpec(2, "misc", EbFixture.ProinfoType, EbFixture.MiscUuid, EbFixture.OriginalMiscStart, EbFixture.MiscCount, 0UL),
            new GptPartitionSpec(3, "userdata", EbFixture.UserdataType, EbFixture.UserdataUuid, EbFixture.UserdataStart, EbFixture.CurrentUserdataCount, 0UL),
            new GptPartitionSpec(4, "ARMADA_BOOT", EbFixture.LinuxType, EbFixture.BootUuid, EbFixture.BootStart, EbFixture.BootCount, 0UL),
            new GptPartitionSpec(5, "ARMADA_ROOT", EbFixture.LinuxType, EbFixture.RootUuid, EbFixture.RootStart, EbFixture.RootCount - TwoGiBSectors, 0UL),
            new GptPartitionSpec(6, "ARMADA_BACKUP", EbFixture.LinuxType, BoardBackupPartUuid, BackupStartSector, TwoGiBSectors, BoardBackupAttributes),
        });

    public static GptImage BuildExpectedPostImage() => new(
        EbFixture.SectorSize,
        EbFixture.Lun0DiskBytes,
        EbFixture.DiskGuid,
        EbFixture.FirstUsableSector,
        EbFixture.LastUsable4096,
        new[]
        {
            new GptPartitionSpec(1, "proinfo", EbFixture.ProinfoType, EbFixture.ProinfoUuid, EbFixture.ProinfoStart, EbFixture.ProinfoCount, 0UL),
            new GptPartitionSpec(2, "misc", EbFixture.ProinfoType, EbFixture.MiscUuid, EbFixture.OriginalMiscStart, EbFixture.MiscCount, 0UL),
            new GptPartitionSpec(3, "userdata", EbFixture.UserdataType, EbFixture.UserdataUuid, EbFixture.UserdataStart, EbFixture.OriginalUserdataCount - TwoGiBSectors, 0UL),
            new GptPartitionSpec(6, "ARMADA_BACKUP", EbFixture.LinuxType, BoardBackupPartUuid, BackupStartSector, TwoGiBSectors, BoardBackupAttributes),
        });
}

internal sealed record TailCaseContext(
    string CaseDirectory,
    string OriginalPrimaryPath,
    string OriginalBackupPath,
    byte[] CurrentPrimaryFragment,
    byte[] CurrentBackupFragment,
    byte[] ExpectedPostPrimaryFragment,
    byte[] ExpectedPostBackupFragment,
    EbRunner Inner,
    TailGptInterceptRunner Wrapper,
    EdlClient Client);

/// <summary>
/// Delegating ICommandRunner: every non-GPT EDL/evidence call is forwarded unchanged to
/// the inner EbRunner. The GPT planning call (python + gpt cli) is intercepted: the real
/// backend request JSON is captured (cloned, never mutated), and either the request is
/// pointed at the known expected post fixture files (positive variant) or the genuine
/// response has only its claimed plan scalars rewritten (counterfeit variant).
/// </summary>
internal sealed class TailGptInterceptRunner : ICommandRunner
{
    private readonly EdlToolchain _tools;
    private readonly EbRunner _inner;
    private readonly string _caseDirectory;
    private readonly string? _expectedPostPrimaryPath;
    private readonly string? _expectedPostBackupPath;
    private readonly bool _counterfeitScalars;
    private int _cloneCounter;

    public TailGptInterceptRunner(
        EdlToolchain tools,
        EbRunner inner,
        string caseDirectory,
        string? expectedPostPrimaryPath,
        string? expectedPostBackupPath,
        bool counterfeitScalars)
    {
        _tools = tools;
        _inner = inner;
        _caseDirectory = caseDirectory;
        _expectedPostPrimaryPath = expectedPostPrimaryPath;
        _expectedPostBackupPath = expectedPostBackupPath;
        _counterfeitScalars = counterfeitScalars;
    }

    public List<JsonElement> CapturedGptRequests { get; } = new();

    public List<string> CapturedGptRequestPaths { get; } = new();

    public async Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        if (IsGptCall(command))
        {
            return await RunGptCallAsync(command, cancellationToken);
        }

        return await _inner.RunAsync(command, cancellationToken);
    }

    private bool IsGptCall(ProcessCommand command) =>
        string.Equals(command.Executable, _tools.PythonPath, StringComparison.OrdinalIgnoreCase)
        && command.Arguments.Any(a => string.Equals(a, _tools.GptCliPath, StringComparison.OrdinalIgnoreCase));

    private async Task<ProcessResult> RunGptCallAsync(ProcessCommand command, CancellationToken cancellationToken)
    {
        string requestPath = command.Arguments[^1];
        CapturedGptRequestPaths.Add(requestPath);

        using (JsonDocument document = JsonDocument.Parse(File.ReadAllText(requestPath)))
        {
            CapturedGptRequests.Add(document.RootElement.Clone());
        }

        if (_counterfeitScalars)
        {
            // Forward the backend's original request untouched: the fake builds the post
            // images from the plain factory table, so the actual post drops the backup.
            ProcessResult raw = await _inner.RunAsync(command, cancellationToken);
            return CounterfeitResponse(raw);
        }

        // Positive variant: clone the request into a test-owned file and swap only the
        // originalPrimary/originalBackup references to the known expected post fixture.
        string clonePath = Path.Combine(_caseDirectory, $"gpt-request-expected-{_cloneCounter++}.json");
        JsonNode clone = JsonNode.Parse(File.ReadAllText(requestPath))
            ?? throw new InvalidOperationException("tail001: unreadable backend gpt request");
        ApplyExpectedPost(clone, _expectedPostPrimaryPath!, _expectedPostBackupPath!);
        File.WriteAllText(clonePath, clone.ToJsonString());

        var arguments = command.Arguments.ToList();
        arguments[^1] = clonePath;
        return await _inner.RunAsync(command with { Arguments = arguments }, cancellationToken);
    }

    private static void ApplyExpectedPost(JsonNode request, string primaryPath, string backupPath)
    {
        JsonNode originalPrimary = request["originalPrimary"]
            ?? throw new InvalidOperationException("tail002: request missing originalPrimary");
        originalPrimary["path"] = primaryPath;
        originalPrimary["sha256"] = EbBytes.ShaHex(File.ReadAllBytes(primaryPath));

        JsonNode originalBackup = request["originalBackup"]
            ?? throw new InvalidOperationException("tail003: request missing originalBackup");
        originalBackup["path"] = backupPath;
        originalBackup["sha256"] = EbBytes.ShaHex(File.ReadAllBytes(backupPath));
    }

    private static ProcessResult CounterfeitResponse(ProcessResult raw)
    {
        JsonNode response = JsonNode.Parse(raw.StandardOutput)
            ?? throw new InvalidOperationException("tail004: unreadable gpt response");
        JsonNode plan = response["plan"]
            ?? throw new InvalidOperationException("tail005: response missing plan");

        // Only the claimed scalars lie; region/post files and their hashes stay real.
        plan["userdataEndLbaExclusive"] = TailBackupConstants.BackupStartSector;
        plan["restoredBytes"] = TailBackupConstants.ExpectedRestoredBytes;
        plan["removedPartitionNumbers"] = new JsonArray(4, 5);

        return new ProcessResult(raw.ExitCode, response.ToJsonString(), raw.StandardError);
    }
}
