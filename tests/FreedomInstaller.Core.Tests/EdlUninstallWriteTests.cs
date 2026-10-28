using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Uninstall write-stage tests. They describe the uninstall write contract: behavioral tests
/// fail for missing or incorrect behavior, never because a NotImplementedException is
/// accepted as a valid reject.
///
/// Scope: test-host plumbing plus the real EdlClient argv parser driven through a fake
/// <see cref="ICommandRunner"/>. No process execution, no device/USB/network, no real crypto,
/// no git, no reflection. The AVB evidence produced by the shared fake runner is canned
/// plumbing only (it does not read a real pin file or verify a chain), therefore these tests
/// assert write ordering, ranges, readback and stage transitions only - never device proof.
/// </summary>
public sealed class EbUninstallWriteTests : IClassFixture<EdlClientToolchainFixture>
{
    private readonly EdlClientToolchainFixture _fixture;

    public EbUninstallWriteTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ---------------------------------------------------------------------
    // 1. Happy path: four GPT plan writes plus the misc BCB, then reset wait
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Workflow_WritesGptPlanAndMisc_AndAwaitsFactoryReset()
    {
        const long miscStart = EbFixture.OriginalMiscStart;
        Eb004THarness harness = await PrepareAsync(miscStart: miscStart);
        using EdlUninstallBackend backend = harness.Backend;

        byte[] bootABefore = harness.Runner.Snapshot(4, harness.Scenario.BootAStart, EbFixture.BootPartitionSectors);
        byte[] bootBBefore = harness.Runner.Snapshot(4, EbFixture.BootBStart, EbFixture.BootPartitionSectors);
        int pythonBefore = harness.Runner.PythonCallCount;

        UninstallResult result = await RunWorkflowAsync(backend);

        Assert.True(result.Success);
        AssertStage(result, "AwaitingFactoryReset");
        Assert.True(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);

        IReadOnlyList<Eb004TWrite> writes = harness.Runner.Writes;
        Assert.Equal(5, writes.Count);
        Assert.Equal(0, harness.Runner.ResetCount);
        Assert.DoesNotContain(harness.Runner.CommandLines, line => line.Contains("reboot", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(harness.Runner.Writes, write => write.Lun == 4);
        Assert.DoesNotContain(harness.Runner.Reads, read => read.Lun == 4);
        Assert.Equal(pythonBefore, harness.Runner.PythonCallCount);

        // GPT: exactly the four planned regions, in plan order, on LUN 0.
        JsonElement plan = harness.Runner.LastGptResponse.Value.GetProperty("plan").Clone();
        JsonElement[] regions = plan.GetProperty("regions").EnumerateArray().Select(r => r.Clone()).ToArray();
        Assert.Equal(4, regions.Length);
        Assert.Equal(
            new[] { "backup-array", "backup-header", "primary-array", "primary-header" },
            regions.Select(r => r.GetProperty("role").GetString() ?? string.Empty).ToArray());

        for (int i = 0; i < regions.Length; i++)
        {
            JsonElement region = regions[i];
            Eb004TWrite write = writes[i];
            AssertWrite(
                write,
                lun: 0,
                start: region.GetProperty("startSector").GetInt64(),
                count: region.GetProperty("sectorCount").GetInt64());
            Assert.Equal(region.GetProperty("bytes").GetInt64(), write.PayloadBytes);
            Assert.Equal(region.GetProperty("sha256").GetString(), write.Sha256);
        }

        // Misc: BCB unit only, at the scenario's real misc start.
        JsonElement miscRegion = plan.GetProperty("miscRegion");
        long miscRegionStart = miscStart + miscRegion.GetProperty("relativeMiscOffset").GetInt64();
        AssertWrite(writes[4], lun: 0, start: miscRegionStart, count: miscRegion.GetProperty("sectorCount").GetInt64());
        Assert.Equal(miscRegion.GetProperty("sha256").GetString(), writes[4].Sha256);
        Assert.Equal(EbFixture.SectorSize, writes[4].PayloadBytes);

        // Nothing outside the confirmed plan is written: no vbmeta, no userdata body.
        Assert.DoesNotContain(harness.Runner.Writes, w => w.Lun == 4
            && (w.Start == EbFixture.VbmetaAStart || w.Start == EbFixture.VbmetaBStart));
        Assert.DoesNotContain(harness.Runner.Writes, w => w.Start == plan.GetProperty("userdataStartLba").GetInt64());

        // After the four GPT writes the whole primary/backup captures must be read back.
        int lastGptWrite = writes[3].Sequence;
        Assert.Contains(harness.Runner.Reads, r =>
            r.Lun == 0 && r.Start == 0 && r.Count == EbFixture.CaptureSectors && r.Sequence > lastGptWrite);
        Assert.Contains(harness.Runner.Reads, r =>
            r.Lun == 0
            && r.Start == EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors
            && r.Count == EbFixture.CaptureSectors
            && r.Sequence > lastGptWrite);

        // Final fake physical state matches the plan oracles.
        Assert.Equal(
            plan.GetProperty("postPrimary").GetProperty("sha256").GetString(),
            EbBytes.ShaHex(harness.Runner.Snapshot(0, 0, EbFixture.CaptureSectors)));
        Assert.Equal(
            plan.GetProperty("postBackup").GetProperty("sha256").GetString(),
            EbBytes.ShaHex(harness.Runner.Snapshot(
                0,
                EbFixture.Lun0TotalSectors - EbFixture.CaptureSectors,
                EbFixture.CaptureSectors)));

        // The whole misc region (not just the written unit) is the pending-reset oracle.
        string finalMiscSha = EbBytes.ShaHex(harness.Runner.Snapshot(0, miscStart, EbFixture.MiscCount));
        Assert.Equal(plan.GetProperty("miscAfterSha256").GetString(), finalMiscSha);
        Assert.NotEqual(miscRegion.GetProperty("sha256").GetString(), finalMiscSha);

        // Boot/vbmeta are a non-transport oracle: the fake bytes are untouched.
        Assert.Equal(
            EbBytes.ShaHex(bootABefore),
            EbBytes.ShaHex(harness.Runner.Snapshot(4, harness.Scenario.BootAStart, EbFixture.BootPartitionSectors)));
        Assert.Equal(
            EbBytes.ShaHex(bootBBefore),
            EbBytes.ShaHex(harness.Runner.Snapshot(4, EbFixture.BootBStart, EbFixture.BootPartitionSectors)));
    }

    // ---------------------------------------------------------------------
    // 2. Fail before the first apply: no later writes, no BCB, data may move
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Workflow_FailBeforeFirstWrite_StopsBeforeLaterWritesAndBcb()
    {
        Eb004THarness harness = await PrepareAsync(new Eb004TFaults { FailBeforeApplyWriteIndex = 1 });
        using EdlUninstallBackend backend = harness.Backend;

        UninstallResult result = await RunWorkflowAsync(backend);

        Assert.False(result.Success);
        AssertStage(result, "ReclaimAndroidSpace");
        Assert.True(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Equal(1, harness.Runner.WriteCount);
        Assert.Equal(0, harness.Runner.ResetCount);

        JsonElement plan = harness.Runner.LastGptResponse.Value.GetProperty("plan").Clone();
        Assert.DoesNotContain(harness.Runner.Writes, w => w.Lun == 0 && w.Start == harness.Scenario.MiscStart);
        Assert.Equal(
            plan.GetProperty("miscBeforeSha256").GetString(),
            EbBytes.ShaHex(harness.Runner.Snapshot(0, harness.Scenario.MiscStart, EbFixture.MiscCount)));
    }

    // ---------------------------------------------------------------------
    // 3. Lost write ACK blocks replay without further device IO
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Workflow_LostWriteAck_BlocksReplayWithoutMoreIo()
    {
        Eb004THarness harness = await PrepareAsync(new Eb004TFaults { LostAckWriteIndex = 1 });
        EdlUninstallBackend backend = harness.Backend;

        UninstallResult result = await RunWorkflowAsync(backend);

        Assert.False(result.Success);
        AssertStage(result, "ReclaimAndroidSpace");
        Assert.True(result.DataMayBeErased);
        Assert.Equal(1, harness.Runner.WriteCount);

        int commandCount = harness.Runner.CommandLines.Count;
        int writeCount = harness.Runner.WriteCount;

        Exception replay = await Assert.ThrowsAnyAsync<Exception>(
            () => backend.ReclaimAndroidSpaceAsync(CancellationToken.None));
        Assert.IsNotType<NotImplementedException>(replay);

        Assert.Equal(commandCount, harness.Runner.CommandLines.Count);
        Assert.Equal(writeCount, harness.Runner.WriteCount);
        Assert.Equal(0, harness.Runner.ResetCount);

        string backupDirectory = backend.BackupDirectory;
        backend.Dispose();

        Assert.True(Directory.Exists(backupDirectory), backupDirectory);
        Assert.NotEmpty(Directory.GetFiles(backupDirectory, "*", SearchOption.AllDirectories));
    }

    // ---------------------------------------------------------------------
    // 4. Whole-misc readback mismatch must not claim a pending factory reset
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Workflow_MiscWholeReadbackMismatch_DoesNotClaimPendingReset()
    {
        Eb004THarness harness = await PrepareAsync(new Eb004TFaults { CorruptUnitAfterWriteIndex = 5 });
        using EdlUninstallBackend backend = harness.Backend;

        UninstallResult result = await RunWorkflowAsync(backend);

        Assert.False(result.Success);
        AssertStage(result, "InitializeAndroid");
        Assert.True(result.DataMayBeErased);
        Assert.Equal(5, harness.Runner.WriteCount);
        Assert.Equal(0, harness.Runner.ResetCount);

        JsonElement plan = harness.Runner.LastGptResponse.Value.GetProperty("plan").Clone();
        string miscSha = EbBytes.ShaHex(harness.Runner.Snapshot(0, harness.Scenario.MiscStart, EbFixture.MiscCount));
        Assert.NotEqual(plan.GetProperty("miscAfterSha256").GetString(), miscSha);
        Assert.NotEqual(plan.GetProperty("miscBeforeSha256").GetString(), miscSha);
    }

    // ---------------------------------------------------------------------
    // 5. A byte outside the written primary unit still fails the whole capture
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Workflow_PrimaryMbrMismatch_DetectedOutsideWrittenUnit()
    {
        Eb004THarness harness = await PrepareAsync(new Eb004TFaults { CorruptPrimaryMbrAfterWriteIndex = 4 });
        using EdlUninstallBackend backend = harness.Backend;

        UninstallResult result = await RunWorkflowAsync(backend);

        Assert.False(result.Success);
        AssertStage(result, "ReclaimAndroidSpace");
        Assert.True(result.DataMayBeErased);
        Assert.Equal(4, harness.Runner.WriteCount);
        Assert.Equal(0, harness.Runner.ResetCount);

        JsonElement plan = harness.Runner.LastGptResponse.Value.GetProperty("plan").Clone();
        JsonElement[] regions = plan.GetProperty("regions").EnumerateArray().Select(r => r.Clone()).ToArray();

        // The four written units are still byte-correct on their own.
        foreach (JsonElement region in regions)
        {
            Assert.Equal(
                region.GetProperty("sha256").GetString(),
                EbBytes.ShaHex(harness.Runner.Snapshot(
                    0,
                    region.GetProperty("startSector").GetInt64(),
                    region.GetProperty("sectorCount").GetInt64())));
        }

        // The whole primary capture hash is not, so a region-locally-verified writer must fail.
        Assert.NotEqual(
            plan.GetProperty("postPrimary").GetProperty("sha256").GetString(),
            EbBytes.ShaHex(harness.Runner.Snapshot(0, 0, EbFixture.CaptureSectors)));

        // The misc BCB is never reached.
        Assert.DoesNotContain(harness.Runner.Writes, w => w.Lun == 0 && w.Start == harness.Scenario.MiscStart);
        Assert.Equal(
            plan.GetProperty("miscBeforeSha256").GetString(),
            EbBytes.ShaHex(harness.Runner.Snapshot(0, harness.Scenario.MiscStart, EbFixture.MiscCount)));
    }

    // ---------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------

    private static async Task<UninstallResult> RunWorkflowAsync(EdlUninstallBackend backend)
    {
        UserdataUninstallRequest request = NewRequest(backend);
        return await UninstallWorkflow.RunAsync(
            request, backend, progress: null, cancellationToken: CancellationToken.None);
    }

    private static UserdataUninstallRequest NewRequest(EdlUninstallBackend backend)
    {
        var request = new UserdataUninstallRequest(
            backend.Snapshot,
            backend.PlanFingerprint,
            string.Empty,
            true);

        return request with { ConfirmationId = UninstallWorkflow.ConfirmationFor(request) };
    }

    private static void AssertWrite(Eb004TWrite write, int lun, long start, long count)
    {
        Assert.Equal(lun, write.Lun);
        Assert.Equal(start, write.Start);
        Assert.Equal(count, write.Count);
        Assert.Equal(count * EbFixture.SectorSize, write.PayloadBytes);
    }

    private static void AssertStage(UninstallResult result, string expected)
    {
        Assert.Contains(expected, result.Stage.ToString());
    }

    private async Task<Eb004THarness> PrepareAsync(Eb004TFaults? faults = null, long miscStart = EbFixture.OriginalMiscStart)
    {
        EbScenario scenario = EbScenario.Create(_fixture.Toolchain, miscStart);
        var inner = new EbRunner(_fixture.Toolchain, scenario.Content);
        var runner = new Eb004TRunner(inner, scenario, faults);
        EdlClient client = new EdlClient(
            _fixture.Toolchain,
            scenario.Binding,
            runner,
            new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

        string assetsRoot = NewDirectory("c002-write-assets");
        UninstallGptAssets assets = CreateAssets(assetsRoot, scenario);
        string jobRoot = NewDirectory("c002-write-jobs");

        EdlUninstallBackend backend = await EdlUninstallBackend.CreatePreparedAsync(
            client, _fixture.Toolchain, scenario.Binding, assets, jobRoot, runner, CancellationToken.None);

        return new Eb004THarness(backend, runner, scenario, assets);
    }

    private static UninstallGptAssets CreateAssets(string root, EbScenario scenario)
    {
        string originalPrimary = Path.Combine(root, "original_primary.gpt");
        string originalBackup = Path.Combine(root, "original_backup.gpt");
        File.WriteAllBytes(originalPrimary, scenario.OriginalPrimary);
        File.WriteAllBytes(originalBackup, scenario.OriginalBackup);

        return new UninstallGptAssets(originalPrimary, originalBackup);
    }

    private string NewDirectory(string prefix)
    {
        string path = Path.Combine(_fixture.WorkRoot, prefix + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}

internal sealed class Eb004THarness
{
    public Eb004THarness(
        EdlUninstallBackend backend,
        Eb004TRunner runner,
        EbScenario scenario,
        UninstallGptAssets assets)
    {
        Backend = backend;
        Runner = runner;
        Scenario = scenario;
        Assets = assets;
    }

    public EdlUninstallBackend Backend { get; }
    public Eb004TRunner Runner { get; }
    public EbScenario Scenario { get; }
    public UninstallGptAssets Assets { get; }
}

internal sealed class Eb004TFaults
{
    /// <summary>Apply the write, then throw IOException (the device may have committed it).</summary>
    public int LostAckWriteIndex { get; init; }

    /// <summary>Throw IOException before the payload is applied to the fake physical state.</summary>
    public int FailBeforeApplyWriteIndex { get; init; }

    /// <summary>Corrupt one byte of the just-written unit so the unit readback hash differs.</summary>
    public int CorruptUnitAfterWriteIndex { get; init; }

    /// <summary>Flip MBR byte 0 of the LUN 0 primary capture, outside the just-written primary header.</summary>
    public int CorruptPrimaryMbrAfterWriteIndex { get; init; }
}

internal sealed record Eb004TWrite(
    int Index,
    int Sequence,
    int Lun,
    long Start,
    long Count,
    string Sha256,
    string PayloadPath,
    long PayloadBytes);

internal sealed record Eb004TRead(
    int Sequence,
    int Lun,
    long Start,
    long Count,
    string Path,
    string Sha256,
    bool Intercepted);

/// <summary>
/// Write-stage observer runner. It parses the real EdlClient argv, keeps a mutable nine-range
/// fake physical store (so later subrange readbacks see written bytes), and delegates probes and
/// Python helpers to the shared <see cref="EbRunner"/>. Payload bytes are genuine fake bytes; the
/// write ACK string is a command acknowledgement only, never a physical hash claim.
/// It never launches a process and writes only below test-owned paths.
/// </summary>
internal sealed class Eb004TRunner : ICommandRunner
{
    private readonly EbRunner _inner;
    private readonly Eb004TFaults _faults;
    private readonly List<(int Lun, long Start, long Count, byte[] Bytes)> _segments = new();
    private int _sequence;
    private int _writeAttempts;

    public Eb004TRunner(EbRunner inner, EbScenario scenario, Eb004TFaults? faults = null)
    {
        _inner = inner;
        _faults = faults ?? new Eb004TFaults();

        EbDiskContent content = scenario.Content;
        int capture = EbFixture.CaptureSectors;
        int misc = checked((int)EbFixture.MiscCount);

        AddSegment(0, 0, capture, content.Get(0, 0, capture));
        AddSegment(0, EbFixture.Lun0TotalSectors - capture, capture,
            content.Get(0, EbFixture.Lun0TotalSectors - capture, capture));
        AddSegment(0, scenario.MiscStart, misc, content.Get(0, scenario.MiscStart, misc));

        AddSegment(4, 0, capture, content.Get(4, 0, capture));
        AddSegment(4, EbFixture.Lun4TotalSectors - capture, capture,
            content.Get(4, EbFixture.Lun4TotalSectors - capture, capture));

        AddSegment(4, scenario.BootAStart, EbFixture.BootPartitionSectors,
            content.Get(4, scenario.BootAStart, EbFixture.BootPartitionSectors));
        AddSegment(4, EbFixture.BootBStart, EbFixture.BootPartitionSectors,
            content.Get(4, EbFixture.BootBStart, EbFixture.BootPartitionSectors));
        AddSegment(4, EbFixture.VbmetaAStart, EbFixture.VbmetaPartitionSectors,
            content.Get(4, EbFixture.VbmetaAStart, EbFixture.VbmetaPartitionSectors));
        AddSegment(4, EbFixture.VbmetaBStart, EbFixture.VbmetaPartitionSectors,
            content.Get(4, EbFixture.VbmetaBStart, EbFixture.VbmetaPartitionSectors));
    }

    public List<string> CommandLines { get; } = new();
    public List<Eb004TRead> Reads { get; } = new();
    public List<Eb004TWrite> Writes { get; } = new();
    public JsonElement? LastGptResponse => _inner.LastGptResponse;
    public int PythonCallCount => _inner.PythonCallCount;
    public int WriteCount => _writeAttempts;
    public int ResetCount { get; private set; }

    public async Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        int sequence = ++_sequence;
        CommandLines.Add(command.Executable + " " + string.Join(" ", command.Arguments));

        if (Has(command.Arguments, "reset"))
        {
            ResetCount++;
            throw new InvalidOperationException(
                "eb004t: reset is never allowed during write-stage tests: " + string.Join(" ", command.Arguments));
        }

        if (Has(command.Arguments, "read-sector"))
        {
            return ReadSector(command, sequence);
        }

        if (Has(command.Arguments, "write-sector") || Has(command.Arguments, "write"))
        {
            return WriteSector(command, sequence);
        }

        return await _inner.RunAsync(command, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Current fake physical bytes for an already-observed range (copy).</summary>
    public byte[] Snapshot(int lun, long start, long count)
    {
        (int Lun, long Start, long Count, byte[] Bytes) segment = FindContaining(lun, start, count)
            ?? throw new InvalidOperationException(
                string.Format(CultureInfo.InvariantCulture,
                    "eb004t: no fake segment for lun={0} start={1} count={2}", lun, start, count));

        int offset = checked((int)((start - segment.Start) * EbFixture.SectorSize));
        int length = checked((int)(count * EbFixture.SectorSize));
        byte[] copy = new byte[length];
        Array.Copy(segment.Bytes, offset, copy, 0, length);
        return copy;
    }

    private ProcessResult ReadSector(ProcessCommand command, int sequence)
    {
        IReadOnlyList<string> args = command.Arguments;
        int index = IndexOf(args, "read-sector");
        if (index < 0 || index + 3 >= args.Count)
        {
            throw new InvalidOperationException("eb004t: unexpected read argv: " + string.Join(" ", args));
        }

        long start = long.Parse(args[index + 1], CultureInfo.InvariantCulture);
        long count = long.Parse(args[index + 2], CultureInfo.InvariantCulture);
        string path = args[index + 3];
        int lun = ParseLun(args);

        EnsureDirectory(path);

        (int Lun, long Start, long Count, byte[] Bytes)? segment = FindContaining(lun, start, count);
        byte[] bytes;

        if (segment is null)
        {
            // First observation of this exact range: let the shared fake answer, then adopt the bytes.
            ProcessResult delegated = _inner.RunAsync(command, CancellationToken.None).GetAwaiter().GetResult();
            if (delegated.ExitCode != 0)
            {
                return delegated;
            }

            bytes = File.ReadAllBytes(path);
            if (bytes.LongLength == count * EbFixture.SectorSize)
            {
                AddSegment(lun, start, count, bytes);
            }
        }
        else
        {
            bytes = Slice(segment.Value, start, count);
            File.WriteAllBytes(path, bytes);
        }

        Reads.Add(new Eb004TRead(sequence, lun, start, count, path, EbBytes.ShaHex(bytes), segment is not null));

        return new ProcessResult(
            0,
            E003EdlTestData.ReadSuccess(lun, start, count, bytes.LongLength, path),
            string.Empty);
    }

    private ProcessResult WriteSector(ProcessCommand command, int sequence)
    {
        IReadOnlyList<string> args = command.Arguments;
        int index = IndexOf(args, "write-sector");
        if (index < 0 || index + 2 >= args.Count)
        {
            throw new InvalidOperationException("eb004t: unexpected write argv: " + string.Join(" ", args));
        }

        long start = long.Parse(args[index + 1], CultureInfo.InvariantCulture);
        string payloadPath = args[index + 2];
        int lun = ParseLun(args);

        if (!File.Exists(payloadPath))
        {
            throw new InvalidOperationException("eb004t: write payload is missing: " + payloadPath);
        }

        byte[] payload = File.ReadAllBytes(payloadPath);
        if (payload.Length == 0 || payload.Length % EbFixture.SectorSize != 0)
        {
            throw new InvalidOperationException(
                "eb004t: write payload is not a whole number of sectors: " + payload.LongLength);
        }

        // write-sector carries no count argument; the count is the payload length.
        long count = payload.LongLength / EbFixture.SectorSize;
        int attempt = ++_writeAttempts;

        Writes.Add(new Eb004TWrite(
            attempt,
            sequence,
            lun,
            start,
            count,
            EbBytes.ShaHex(payload),
            payloadPath,
            payload.LongLength));

        if (_faults.FailBeforeApplyWriteIndex == attempt)
        {
            throw new IOException(
                "eb004t: injected write failure before apply #" + attempt.ToString(CultureInfo.InvariantCulture));
        }

        (int Lun, long Start, long Count, byte[] Bytes) target = RequireSingleContaining(lun, start, count);
        int offset = checked((int)((start - target.Start) * EbFixture.SectorSize));
        Array.Copy(payload, 0, target.Bytes, offset, payload.Length);

        if (_faults.CorruptUnitAfterWriteIndex == attempt)
        {
            target.Bytes[offset] ^= 0xFF;
        }

        if (_faults.CorruptPrimaryMbrAfterWriteIndex == attempt)
        {
            // MBR byte 0 of the LUN 0 primary capture: outside the just-written primary header.
            (int Lun, long Start, long Count, byte[] Bytes) primary = RequireSingleContaining(0, 0, EbFixture.CaptureSectors);
            primary.Bytes[0] ^= 0xFF;
        }

        if (_faults.LostAckWriteIndex == attempt)
        {
            throw new IOException(
                "eb004t: injected lost ACK #" + attempt.ToString(CultureInfo.InvariantCulture));
        }

        return new ProcessResult(
            0,
            E003EdlTestData.WriteSuccess(lun, start, count, payload.LongLength),
            string.Empty);
    }

    private byte[] Slice((int Lun, long Start, long Count, byte[] Bytes) segment, long start, long count)
    {
        int offset = checked((int)((start - segment.Start) * EbFixture.SectorSize));
        int length = checked((int)(count * EbFixture.SectorSize));
        byte[] bytes = new byte[length];
        Array.Copy(segment.Bytes, offset, bytes, 0, length);
        return bytes;
    }

    private (int Lun, long Start, long Count, byte[] Bytes)? FindContaining(int lun, long start, long count)
    {
        (int Lun, long Start, long Count, byte[] Bytes)? best = null;

        foreach ((int Lun, long Start, long Count, byte[] Bytes) segment in _segments)
        {
            if (segment.Lun != lun || start < segment.Start || start + count > segment.Start + segment.Count)
            {
                continue;
            }

            if (segment.Start == start && segment.Count == count)
            {
                return segment;
            }

            if (best is null || segment.Start < best.Value.Start)
            {
                best = segment;
            }
        }

        return best;
    }

    private (int Lun, long Start, long Count, byte[] Bytes) RequireSingleContaining(int lun, long start, long count)
    {
        (int Lun, long Start, long Count, byte[] Bytes)? match = null;

        foreach ((int Lun, long Start, long Count, byte[] Bytes) segment in _segments)
        {
            if (segment.Lun != lun || start < segment.Start || start + count > segment.Start + segment.Count)
            {
                continue;
            }

            if (match is not null)
            {
                throw new InvalidOperationException(
                    string.Format(CultureInfo.InvariantCulture,
                        "eb004t: write range lun={0} start={1} count={2} spans two fake segments",
                        lun, start, count));
            }

            match = segment;
        }

        return match ?? throw new InvalidOperationException(
            string.Format(CultureInfo.InvariantCulture,
                "eb004t: write range lun={0} start={1} count={2} is outside the fake captures",
                lun, start, count));
    }

    private void AddSegment(int lun, long start, long count, byte[] bytes)
    {
        if (bytes.LongLength != count * EbFixture.SectorSize)
        {
            throw new ArgumentException("eb004t: segment size does not match its sector count", nameof(bytes));
        }

        byte[] copy = (byte[])bytes.Clone();

        for (int i = 0; i < _segments.Count; i++)
        {
            if (_segments[i].Lun == lun && _segments[i].Start == start && _segments[i].Count == count)
            {
                _segments[i] = (lun, start, count, copy);
                return;
            }
        }

        _segments.Add((lun, start, count, copy));
    }

    private static void EnsureDirectory(string path)
    {
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static int ParseLun(IReadOnlyList<string> args)
    {
        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];

            if (arg.StartsWith("--lun=", StringComparison.Ordinal))
            {
                return int.Parse(arg.Substring("--lun=".Length), CultureInfo.InvariantCulture);
            }

            if (string.Equals(arg, "--lun", StringComparison.Ordinal) && i + 1 < args.Count)
            {
                return int.Parse(args[i + 1], CultureInfo.InvariantCulture);
            }
        }

        return 0;
    }

    private static bool Has(IReadOnlyList<string> args, string token) =>
        args.Any(arg => string.Equals(arg, token, StringComparison.Ordinal));

    private static int IndexOf(IReadOnlyList<string> args, string token)
    {
        for (int i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], token, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }
}
