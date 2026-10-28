using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class TfCardRawWriterTests : IClassFixture<EdlRawSharedInput>
{
    private const long VirtualCardBytes = 64L * 1024 * 1024 * 1024;
    private const string SyntheticBindingSha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private readonly EdlRawSharedInput _shared;

    public TfCardRawWriterTests(EdlRawSharedInput shared) => _shared = shared;

    public static IEnumerable<object[]> SectorSizes()
    {
        yield return new object[] { 512 };
        yield return new object[] { 4096 };
    }

    [Theory]
    [MemberData(nameof(SectorSizes))]
    public async Task WriteAndVerify_SucceedsOnSyntheticCard(int sectorSize)
    {
        using var work = new TempPackageDirectory();
        using var package = InternalInstallEdlRawSnapshotTests.RawPackage.Create(_shared);
        using var images = await CaptureTfPackageAsync(package, work, CancellationToken.None);
        var plan = BuildLayout(images, sectorSize);
        var identity = CreateIdentity(sectorSize);
        await using var target = new SparseCardTarget(
            identity,
            seeds: new[]
            {
                (512L * 1024, Enumerable.Repeat((byte)0xA5, 64).ToArray()),
                (VirtualCardBytes - 2L * 1024 * 1024, Enumerable.Repeat((byte)0x5A, 64).ToArray()),
            });
        var recorder = new ProgressRecorder();

        var evidence = await TfCardRawWriter.WriteAndVerifyAsync(images, target, plan, recorder, CancellationToken.None);

        Assert.True(evidence.FullyVerified);
        Assert.Same(plan, evidence.Layout);
        Assert.Equal(identity, evidence.Target);
        Assert.Equal(images.Contract.ManifestFingerprint, evidence.ManifestFingerprint);
        Assert.Equal(images.Contract.BootImage.ExpandedSha256, evidence.BootImageSha256);
        Assert.Equal(images.Contract.RootImage.ExpandedSha256, evidence.RootImageSha256);
        Assert.Equal(
            images.Contract.BootImage.ExpandedBytes,
            CoveredBytes(target.Reads, plan.BootStartSector * sectorSize, plan.BootSectorCount * (long)sectorSize));
        Assert.Equal(
            images.Contract.RootImage.ExpandedBytes,
            CoveredBytes(target.Reads, plan.RootStartSector * sectorSize, plan.RootSectorCount * (long)sectorSize));
        Assert.Equal(TfCardWriteStage.Completed, recorder.Reports[^1].Stage);

        AssertGptMatchesPlan(target, plan, sectorSize);

        var head = new byte[64];
        await target.ReadExactlyAsync(512L * 1024, head);
        Assert.All(head, b => Assert.Equal((byte)0xA5, b));
        var tail = new byte[64];
        await target.ReadExactlyAsync(VirtualCardBytes - 2L * 1024 * 1024, tail);
        Assert.All(tail, b => Assert.Equal((byte)0x5A, b));

        images.Dispose();
        Assert.True(File.Exists(package.ManifestPath));
        Assert.True(File.Exists(package.ArtifactPath("linux-boot-raw")));
    }

    [Fact]
    public async Task WriteAndVerify_DetectsInteriorBootReadbackCorruption()
    {
        using var work = new TempPackageDirectory();
        using var package = InternalInstallEdlRawSnapshotTests.RawPackage.Create(_shared);
        using var images = await CaptureTfPackageAsync(package, work, CancellationToken.None);
        var plan = BuildLayout(images, 512);
        var corruptAt = plan.BootStartSector * 512L + (64L * 1024 * 1024);
        await using var target = new SparseCardTarget(CreateIdentity(512), corruptReadAt: corruptAt);
        var recorder = new ProgressRecorder();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => TfCardRawWriter.WriteAndVerifyAsync(images, target, plan, recorder, CancellationToken.None));
        Assert.Contains("SHA-256", exception.Message);

        var bootStart = plan.BootStartSector * 512L;
        Assert.Equal(
            images.Contract.BootImage.ExpandedBytes,
            CoveredBytes(target.Writes, bootStart, plan.BootSectorCount * 512L));
        Assert.Contains(target.Reads, r => r.Offset <= corruptAt && corruptAt < r.Offset + r.Length);
        Assert.DoesNotContain(recorder.Reports, p => p.Stage == TfCardWriteStage.Completed);
    }

    [Fact]
    public async Task WriteAndVerify_WriteFailureStopsIoAndBlocksReuse()
    {
        using var work = new TempPackageDirectory();
        using var package = InternalInstallEdlRawSnapshotTests.RawPackage.Create(_shared);
        using var images = await CaptureTfPackageAsync(package, work, CancellationToken.None);
        var plan = BuildLayout(images, 512);
        var gpt = TfCardLayout.SerializeGpt(plan);
        await using var target = new SparseCardTarget(CreateIdentity(512), failWriteNumber: 3);
        var recorder = new ProgressRecorder();

        await Assert.ThrowsAsync<IOException>(
            () => TfCardRawWriter.WriteAndVerifyAsync(images, target, plan, recorder, CancellationToken.None));

        Assert.False(recorder.HasCompleted);
        Assert.Equal(3, target.WriteCalls);
        Assert.Equal(gpt.PrimaryOffsetBytes, target.Writes[0].Offset);
        Assert.Equal(gpt.BackupOffsetBytes, target.Writes[1].Offset);

        var writesBefore = target.Writes.Count;
        var readsBefore = target.Reads.Count;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => TfCardRawWriter.WriteAndVerifyAsync(images, target, plan, recorder, CancellationToken.None));
        Assert.Equal(writesBefore, target.Writes.Count);
        Assert.Equal(readsBefore, target.Reads.Count);
    }

    private static async Task<TfPreparedCardImages> CaptureTfPackageAsync(
        InternalInstallEdlRawSnapshotTests.RawPackage package,
        TempPackageDirectory work,
        CancellationToken ct)
    {
        package.EditManifest(node =>
        {
            node["installTargets"] = new JsonArray("tf");
            node["deployment"]!["kind"] = "tf-raw-v1";
            node["bootRecipe"]!["rootMedium"] = "tf";
            node["bootRecipe"]!["sourceInternalBootUuid"] = "11111111-1111-4111-8111-111111111111";
            node["bootRecipe"]!["sourceInternalRootUuid"] = "22222222-2222-4222-8222-222222222222";
            node["testOnly"] = false;
        });
        package.RewriteArtifact("dtb-normal", SyntheticRawImages.CreateDtb(RawFacts.NormalBootArgs, "os", "tf"));
        package.RewriteArtifact("dtb-diagnostic", SyntheticRawImages.CreateDtb(RawFacts.DiagnosticBootArgs, "maintenance", "tf"));
        using var imported = await PackageImporter.ImportAsync(
            package.Directory + Path.DirectorySeparatorChar,
            RawFacts.Model,
            InstallationTarget.TfCard,
            work.Path,
            ct);
        Assert.True(imported.Validation.IsValid);
        return await TfPreparedCardImages.CaptureAsync(imported, ct);
    }

    private static TfCardLayoutPlan BuildLayout(TfPreparedCardImages images, int sectorSize) =>
        TfCardLayout.Create(
            VirtualCardBytes,
            sectorSize,
            images.Contract.BootImage.ExpandedBytes,
            images.Contract.RootImage.ExpandedBytes,
            images.Contract.Storage.MinimumLinuxDataBytes,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());

    private static TfCardTargetIdentity CreateIdentity(int sectorSize) => new(
        TfCardSource.Reader,
        "reader:synthetic-card",
        "synthetic-card",
        VirtualCardBytes,
        sectorSize,
        SyntheticBindingSha256);

    private static void AssertGptMatchesPlan(SparseCardTarget target, TfCardLayoutPlan plan, int sectorSize)
    {
        var gpt = TfCardLayout.SerializeGpt(plan);
        var primary = new byte[gpt.PrimaryBytes.Length];
        target.ReadExactlyAsync(gpt.PrimaryOffsetBytes, primary).AsTask().GetAwaiter().GetResult();
        var backup = new byte[gpt.BackupBytes.Length];
        target.ReadExactlyAsync(gpt.BackupOffsetBytes, backup).AsTask().GetAwaiter().GetResult();
        var table = OriginalGptImporter.Parse(primary, backup, sectorSize, VirtualCardBytes);
        Assert.Equal(plan.DiskGuid, Guid.Parse(table.DiskGuid));
        Assert.Equal(2, table.Partitions.Count);
        var boot = table.Partitions.Single(p => p.Name == "ARMADA_TF_BOOT");
        Assert.Equal(plan.BootGuid, Guid.Parse(boot.PartUuid));
        Assert.Equal(plan.BootStartSector, boot.StartSector);
        Assert.Equal(plan.BootSectorCount, boot.SectorCount);
        var root = table.Partitions.Single(p => p.Name == "ARMADA_TF_ROOT");
        Assert.Equal(plan.RootGuid, Guid.Parse(root.PartUuid));
        Assert.Equal(plan.RootStartSector, root.StartSector);
        Assert.Equal(plan.RootSectorCount, root.SectorCount);
    }

    private static long CoveredBytes(List<(long Offset, long Length)> calls, long start, long length)
    {
        long covered = 0;
        long cursor = start;
        foreach (var (from, to) in calls
            .Select(r => (From: Math.Max(r.Offset, start), To: Math.Min(r.Offset + r.Length, start + length)))
            .Where(r => r.From < r.To)
            .OrderBy(r => r.From))
        {
            if (to <= cursor)
            {
                continue;
            }

            covered += to - Math.Max(from, cursor);
            cursor = to;
        }

        return covered;
    }

    private sealed class ProgressRecorder : IProgress<TfCardWriteProgress>
    {
        public List<TfCardWriteProgress> Reports { get; } = new();

        public bool HasCompleted => Reports.Any(p => p.Stage == TfCardWriteStage.Completed);

        public void Report(TfCardWriteProgress value) => Reports.Add(value);
    }

    private sealed class SparseCardTarget : ITfCardWriteTarget
    {
        private readonly List<(long Offset, byte[] Bytes)> _chunks = new();
        private readonly int? _failWriteNumber;
        private readonly long? _corruptReadAt;
        private int _writeCalls;

        public SparseCardTarget(
            TfCardTargetIdentity identity,
            (long Offset, byte[] Bytes)[]? seeds = null,
            int? failWriteNumber = null,
            long? corruptReadAt = null)
        {
            Identity = identity;
            _failWriteNumber = failWriteNumber;
            _corruptReadAt = corruptReadAt;
            if (seeds is not null)
            {
                _chunks.AddRange(seeds);
            }
        }

        public TfCardTargetIdentity Identity { get; }

        public List<(long Offset, long Length)> Writes { get; } = new();

        public List<(long Offset, long Length)> Reads { get; } = new();

        public int WriteCalls => _writeCalls;

        public ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Identity);

        public ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Reads.Add((offset, buffer.Length));
            buffer.Span.Clear();
            foreach (var (chunkOffset, chunkBytes) in _chunks)
            {
                var from = Math.Max(offset, chunkOffset);
                var to = Math.Min(offset + buffer.Length, chunkOffset + chunkBytes.Length);
                if (from < to)
                {
                    chunkBytes.AsSpan((int)(from - chunkOffset), (int)(to - from))
                        .CopyTo(buffer.Span[(int)(from - offset)..]);
                }
            }

            if (_corruptReadAt is long corrupt && corrupt >= offset && corrupt < offset + buffer.Length)
            {
                buffer.Span[(int)(corrupt - offset)] ^= 0xFF;
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Writes.Add((offset, buffer.Length));
            _writeCalls++;
            if (_failWriteNumber is int fail && _writeCalls == fail)
            {
                throw new IOException($" deliberate write failure #{fail} at offset {offset}.");
            }

            if (buffer.Span.IndexOfAnyExcept((byte)0) >= 0)
            {
                _chunks.Add((offset, buffer.ToArray()));
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask FlushAsync(CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
