using System.Security.Cryptography;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// RED filesystem behaviour tests for <see cref="BootBackup"/>. They use a real temporary
/// directory under TEST_ARTIFACT_ROOT and a fake <see cref="IBootReader"/> for all external I/O.
/// </summary>
public sealed class BootBackupTests
{
    private const string SupportedModel = "TB322FC";

    // ---------- fixtures ----------

    private static byte[] SlotAPayload() => Enumerable.Range(0, 32).Select(i => (byte)(0x10 + i)).ToArray();

    private static byte[] SlotBPayload() => Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray();

    // Hash is derived from the fixture bytes inside the test only; no production helper is used.
    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string NewArtifactRoot()
    {
        var artifactRoot = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(artifactRoot))
        {
            throw new InvalidOperationException(
                "TEST_ARTIFACT_ROOT must point to a real temporary evidence directory before running these filesystem tests.");
        }

        Directory.CreateDirectory(artifactRoot);
        var root = Path.Combine(artifactRoot, "bootbackup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static string NewDestinationRoot(string artifactRoot)
    {
        var destinationRoot = Path.Combine(artifactRoot, "dest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(destinationRoot);
        return destinationRoot;
    }

    private static DeviceIdentity UnlockedIdentity() =>
        new("SN-T008-0001", SupportedModel, BootloaderState.Unlocked);

    private static BootSlotDescriptor[] ValidSlots(byte[] a, byte[] b) =>
        new[]
        {
            new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
            new BootSlotDescriptor("b", b.Length, Sha256Hex(b)),
        };

    private static JsonDocument ReadManifest(string directory)
    {
        var manifestPath = Path.Combine(directory, "backup.json");
        Assert.True(File.Exists(manifestPath), $"expected backup.json at '{manifestPath}'");
        return JsonDocument.Parse(File.ReadAllBytes(manifestPath));
    }

    private static void AssertNoUserDataEntry(string root)
    {
        var offending = Directory
            .EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
            .Where(path => Path.GetFileName(path).Contains("userdata", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert.Empty(offending);
    }

    private sealed class FakeBootReader : IBootReader
    {
        private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Exception> _faults = new(StringComparer.Ordinal);
        private readonly List<string> _opened = new();

        public int OpenCount => _opened.Count;

        public IReadOnlyList<string> OpenedSlots => _opened;

        public FakeBootReader WithSlot(string slot, byte[] payload)
        {
            _payloads[slot] = payload;
            return this;
        }

        public FakeBootReader WithFault(string slot, Exception fault)
        {
            _faults[slot] = fault;
            return this;
        }

        public Task<Stream> OpenReadAsync(string slot, CancellationToken cancellationToken = default)
        {
            _opened.Add(slot);
            if (_faults.TryGetValue(slot, out var fault))
            {
                return Task.FromException<Stream>(fault);
            }

            if (!_payloads.TryGetValue(slot, out var payload))
            {
                return Task.FromException<Stream>(new FileNotFoundException($"no fixture for slot '{slot}'"));
            }

            return Task.FromResult<Stream>(new MemoryStream(payload, writable: false));
        }
    }

    // ---------- 1 ----------

    [Fact]
    public async Task CreateAsync_CopiesBothSlotsByteIdentically_AndWritesCompleteManifest()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);

        var result = await BootBackup.CreateAsync(request, reader);

        Assert.True(result.IsComplete);
        Assert.Null(result.Error);
        Assert.False(string.IsNullOrWhiteSpace(result.Directory));
        Assert.StartsWith(Path.GetFullPath(destinationRoot), Path.GetFullPath(result.Directory), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, result.Records.Count);
        Assert.Equal(new[] { "a", "b" }, reader.OpenedSlots.OrderBy(s => s, StringComparer.Ordinal).ToArray());

        var recordA = result.Records.Single(r => r.Slot == "a");
        Assert.Equal("boot_a.img", recordA.FileName);
        Assert.Equal(a.Length, recordA.Length);
        Assert.Equal(Sha256Hex(a), recordA.Sha256);
        Assert.Equal(a, File.ReadAllBytes(Path.Combine(result.Directory, recordA.FileName)));

        var recordB = result.Records.Single(r => r.Slot == "b");
        Assert.Equal("boot_b.img", recordB.FileName);
        Assert.Equal(b.Length, recordB.Length);
        Assert.Equal(Sha256Hex(b), recordB.Sha256);
        Assert.Equal(b, File.ReadAllBytes(Path.Combine(result.Directory, recordB.FileName)));

        using var manifest = ReadManifest(result.Directory);
        Assert.True(manifest.RootElement.GetProperty("isComplete").GetBoolean());
        Assert.Equal(2, manifest.RootElement.GetProperty("records").GetArrayLength());
    }

    // ---------- 2 ----------

    [Fact]
    public async Task CreateAsync_RepeatedRequests_CreateDistinctDirectories_AndLeaveFirstBackupIntact()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));

        var first = await BootBackup.CreateAsync(request, new FakeBootReader().WithSlot("a", a).WithSlot("b", b));
        Assert.True(first.IsComplete);

        var firstFileA = Path.Combine(first.Directory, "boot_a.img");
        var firstFileB = Path.Combine(first.Directory, "boot_b.img");
        var firstManifest = Path.Combine(first.Directory, "backup.json");
        var snapshotA = File.ReadAllBytes(firstFileA);
        var snapshotB = File.ReadAllBytes(firstFileB);
        var snapshotManifest = File.ReadAllText(firstManifest);

        var second = await BootBackup.CreateAsync(request, new FakeBootReader().WithSlot("a", a).WithSlot("b", b));
        Assert.True(second.IsComplete);

        Assert.NotEqual(Path.GetFullPath(first.Directory), Path.GetFullPath(second.Directory));
        Assert.True(Directory.Exists(first.Directory));
        Assert.Equal(snapshotA, File.ReadAllBytes(firstFileA));
        Assert.Equal(snapshotB, File.ReadAllBytes(firstFileB));
        Assert.Equal(snapshotManifest, File.ReadAllText(firstManifest));
    }

    // ---------- 3 ----------

    [Fact]
    public async Task CreateAsync_HashMismatchOnB_ReturnsIncomplete_KeepsAFile_AndPersistsIncompleteManifest()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var wrongSha = Sha256Hex(SlotAPayload().Select(x => (byte)(x ^ 0xFF)).ToArray());
        var request = new BootBackupRequest(
            UnlockedIdentity(),
            destinationRoot,
            new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("b", b.Length, wrongSha),
            });
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);

        var result = await BootBackup.CreateAsync(request, reader);

        Assert.False(result.IsComplete);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.False(string.IsNullOrWhiteSpace(result.Directory));

        using (var manifest = ReadManifest(result.Directory))
        {
            Assert.False(manifest.RootElement.GetProperty("isComplete").GetBoolean());
        }

        var keptA = Path.Combine(result.Directory, "boot_a.img");
        Assert.True(File.Exists(keptA), "already verified slot a file must be preserved");
        Assert.Equal(a, File.ReadAllBytes(keptA));
    }

    // ---------- 4 ----------

    [Fact]
    public async Task CreateAsync_ShortStreamOnB_ReturnsIncomplete()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(
            UnlockedIdentity(),
            destinationRoot,
            new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("b", b.Length + 64, Sha256Hex(b)),
            });
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);

        var result = await BootBackup.CreateAsync(request, reader);

        Assert.False(result.IsComplete);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    // ---------- 5 ----------

    [Fact]
    public async Task CreateAsync_ReaderThrowsIoOnB_ReturnsIncomplete_WithoutUserDataPath()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));
        var reader = new FakeBootReader()
            .WithSlot("a", a)
            .WithSlot("b", b)
            .WithFault("b", new IOException("simulated device read failure"));

        var result = await BootBackup.CreateAsync(request, reader);

        Assert.False(result.IsComplete);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.DoesNotContain(reader.OpenedSlots, slot => slot.Contains("userdata", StringComparison.OrdinalIgnoreCase));
        AssertNoUserDataEntry(root);
        AssertNoUserDataEntry(destinationRoot);
    }

    // ---------- 6 ----------

    [Theory]
    [InlineData("slot-traversal")]
    [InlineData("duplicate-slot")]
    [InlineData("missing-b")]
    [InlineData("malformed-sha")]
    [InlineData("zero-length")]
    public async Task CreateAsync_InvalidRequest_ThrowsArgumentException_BeforeReaderAndFileWork(string scenario)
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();

        IReadOnlyList<BootSlotDescriptor> slots = scenario switch
        {
            "slot-traversal" => new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("../userdata", b.Length, Sha256Hex(b)),
            },
            "duplicate-slot" => new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("a", b.Length, Sha256Hex(b)),
            },
            "missing-b" => new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
            },
            "malformed-sha" => new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("b", b.Length, "not-a-sha256-value"),
            },
            "zero-length" => new[]
            {
                new BootSlotDescriptor("a", a.Length, Sha256Hex(a)),
                new BootSlotDescriptor("b", 0, Sha256Hex(b)),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };

        var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, slots);
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);

        await Assert.ThrowsAnyAsync<ArgumentException>(() => BootBackup.CreateAsync(request, reader));

        Assert.Equal(0, reader.OpenCount);
        Assert.Empty(Directory.EnumerateFileSystemEntries(destinationRoot));
    }

    // ---------- 7 ----------

    [Theory]
    [InlineData(SupportedModel, BootloaderState.Locked)]
    [InlineData("TB999XX", BootloaderState.Unlocked)]
    public async Task CreateAsync_UnsupportedIdentity_ThrowsArgumentException_BeforeReaderOpen(string model, BootloaderState state)
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(
            new DeviceIdentity("SN-T008-0002", model, state),
            destinationRoot,
            ValidSlots(a, b));
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);

        await Assert.ThrowsAnyAsync<ArgumentException>(() => BootBackup.CreateAsync(request, reader));

        Assert.Equal(0, reader.OpenCount);
        Assert.Empty(Directory.EnumerateFileSystemEntries(destinationRoot));
    }

    // ---------- 8 ----------

    [Fact]
    public async Task CreateAsync_PrecancelledToken_ThrowsOperationCanceled_WithoutAnyFileWrite()
    {
        var root = NewArtifactRoot();
        var destinationRoot = NewDestinationRoot(root);
        var a = SlotAPayload();
        var b = SlotBPayload();
        var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));
        var reader = new FakeBootReader().WithSlot("a", a).WithSlot("b", b);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BootBackup.CreateAsync(request, reader, cts.Token));

        Assert.Equal(0, reader.OpenCount);
        Assert.Empty(Directory.EnumerateFileSystemEntries(destinationRoot));
    }
}
