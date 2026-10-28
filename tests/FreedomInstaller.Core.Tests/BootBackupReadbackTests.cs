using System.Security.Cryptography;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// RED filesystem tests for the on-disk readback of <see cref="BootBackup"/>. They prove that the bytes
/// which passed through the copy buffer are not trusted on their own: every written file is reopened after
/// its writer closed, and a file that no longer matches the declared descriptor must neither become a
/// <see cref="BootBackupRecord"/> nor complete the backup. A reader-supplied disposal hook mutates the
/// written file in the window between the target stream closing and the readback, resolving the file only
/// by searching inside the destination root. All files live under TEST_ARTIFACT_ROOT and each test deletes
/// only its own unique directory.
/// </summary>
public sealed class BootBackupReadbackTests
{
    private const string SupportedModel = "TB322FC";
    private const string ArtifactRootVariable = "TEST_ARTIFACT_ROOT";

    // ---------- fixtures ----------

    private static byte[] SlotAPayload() => Enumerable.Range(0, 32).Select(i => (byte)(0x10 + i)).ToArray();

    private static byte[] SlotBPayload() => Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray();

    private static byte[] ZeroPayload(int length) => new byte[length];

    // Hash is derived from the fixture bytes inside the test only; no production helper is used.
    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string NewUniqueRoot()
    {
        var artifactRoot = Environment.GetEnvironmentVariable(ArtifactRootVariable);
        if (string.IsNullOrWhiteSpace(artifactRoot))
        {
            throw new InvalidOperationException(
                $"{ArtifactRootVariable} must point to a real temporary evidence directory before running these filesystem tests.");
        }

        Directory.CreateDirectory(artifactRoot);
        var root = Path.Combine(artifactRoot, "bootbackup-readback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    // Only ever the unique directory this test created; the shared artifact root is left alone.
    private static void DeleteOwnRoot(string root)
    {
        try
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
        catch (IOException)
        {
            // Evidence stays on disk rather than failing an otherwise finished test.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string NewDestinationRoot(string root)
    {
        var destinationRoot = Path.Combine(root, "dest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(destinationRoot);
        return destinationRoot;
    }

    private static DeviceIdentity UnlockedIdentity() =>
        new("SN-T008-0101", SupportedModel, BootloaderState.Unlocked);

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

    /// <summary>
    /// Finds a written file by recursively searching the destination root only; a path outside that root is
    /// never returned and therefore never touched.
    /// </summary>
    private static string? FindFileUnder(string root, string fileName)
    {
        var rootFull = Path.GetFullPath(root);
        var prefix = rootFull.EndsWith(Path.DirectorySeparatorChar)
            ? rootFull
            : rootFull + Path.DirectorySeparatorChar;

        foreach (var candidate in Directory.EnumerateFiles(rootFull, fileName, SearchOption.AllDirectories))
        {
            var candidateFull = Path.GetFullPath(candidate);
            if (candidateFull.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return candidateFull;
            }
        }

        return null;
    }

    // Test-side corruption of an already closed backup file; production code never does this.
    private static void FlipFirstByte(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var original = file.ReadByte();
        if (original < 0)
        {
            return;
        }

        file.Position = 0;
        file.WriteByte((byte)(original ^ 0xFF));
        file.Flush(flushToDisk: true);
    }

    private static void TruncateTo(string path, long newLength)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        file.SetLength(newLength);
        file.Flush(flushToDisk: true);
    }

    private sealed class CallbackBootReader : IBootReader
    {
        private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Func<ValueTask>> _afterDispose = new(StringComparer.Ordinal);

        public CallbackBootReader WithSlot(string slot, byte[] payload)
        {
            _payloads[slot] = payload;
            return this;
        }

        public CallbackBootReader WithAfterDispose(string slot, Func<ValueTask> callback)
        {
            _afterDispose[slot] = callback;
            return this;
        }

        public Task<Stream> OpenReadAsync(string slot, CancellationToken cancellationToken = default)
        {
            if (!_payloads.TryGetValue(slot, out var payload))
            {
                return Task.FromException<Stream>(new FileNotFoundException($"no fixture for slot '{slot}'"));
            }

            _afterDispose.TryGetValue(slot, out var callback);
            return Task.FromResult<Stream>(new DisposeHookStream(payload, callback));
        }
    }

    /// <summary>
    /// Read stream whose asynchronous disposal runs a caller supplied hook once, after the stream is closed.
    /// The production <c>await using</c> nesting disposes the target file stream before this source stream,
    /// so the hook observes a fully written and closed backup file and can then corrupt it.
    /// </summary>
    private sealed class DisposeHookStream : MemoryStream
    {
        private readonly Func<ValueTask>? _afterDispose;
        private int _disposed;

        public DisposeHookStream(byte[] payload, Func<ValueTask>? afterDispose)
            : base(payload, writable: false) => _afterDispose = afterDispose;

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync().ConfigureAwait(false);

            if (Interlocked.Exchange(ref _disposed, 1) == 0 && _afterDispose is not null)
            {
                await _afterDispose().ConfigureAwait(false);
            }
        }
    }

    // ---------- 1 ----------

    [Fact]
    public async Task CreateAsync_SlotBChangedAfterTargetClosed_FailsReadback_KeepsOnlySlotA()
    {
        var root = NewUniqueRoot();
        try
        {
            var destinationRoot = NewDestinationRoot(root);
            var a = SlotAPayload();
            var b = SlotBPayload();
            var slots = ValidSlots(a, b);
            var expectedShaB = Sha256Hex(b);
            var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, slots);

            var hookRan = false;
            string? touchedPath = null;
            long observedLength = -1;
            var observedSha = string.Empty;

            var reader = new CallbackBootReader()
                .WithSlot("a", a)
                .WithSlot("b", b)
                .WithAfterDispose("b", () =>
                {
                    hookRan = true;
                    touchedPath = FindFileUnder(destinationRoot, "boot_b.img");
                    if (touchedPath is not null)
                    {
                        // The file is already closed here: what it holds is exactly what the copy wrote.
                        var onDisk = File.ReadAllBytes(touchedPath);
                        observedLength = onDisk.Length;
                        observedSha = Sha256Hex(onDisk);
                        FlipFirstByte(touchedPath);
                    }

                    return ValueTask.CompletedTask;
                });

            var result = await BootBackup.CreateAsync(request, reader);

            Assert.True(hookRan, "the reader disposal hook must run after the target file stream closed");
            Assert.NotNull(touchedPath);

            // The source bytes and the declared hash were correct; only the on-disk file disagrees now.
            Assert.Equal(b.Length, observedLength);
            Assert.Equal(expectedShaB, observedSha);
            Assert.Equal(expectedShaB, slots.Single(s => s.Slot == "b").Sha256);

            Assert.False(result.IsComplete, "a file that changed after the copy must not complete the backup");
            Assert.False(string.IsNullOrWhiteSpace(result.Error));
            Assert.True(
                result.Error!.Contains("readback", StringComparison.OrdinalIgnoreCase),
                $"expected a readback failure, got '{result.Error}'");

            var record = Assert.Single(result.Records);
            Assert.Equal("a", record.Slot);

            using (var manifest = ReadManifest(result.Directory))
            {
                Assert.False(manifest.RootElement.GetProperty("isComplete").GetBoolean());
                Assert.Equal(1, manifest.RootElement.GetProperty("records").GetArrayLength());
            }

            var keptB = Path.Combine(result.Directory, "boot_b.img");
            Assert.True(File.Exists(keptB), "the raw file that failed readback must still be kept");
            Assert.Equal(b.Length, new FileInfo(keptB).Length);
            Assert.NotEqual(expectedShaB, Sha256Hex(File.ReadAllBytes(keptB)));
        }
        finally
        {
            DeleteOwnRoot(root);
        }
    }

    // ---------- 2 ----------

    [Fact]
    public async Task CreateAsync_SlotBTruncatedAfterTargetClosed_FailsReadback_KeepsOnlySlotA()
    {
        var root = NewUniqueRoot();
        try
        {
            var destinationRoot = NewDestinationRoot(root);
            var a = SlotAPayload();
            var b = SlotBPayload();
            var truncatedLength = b.Length - 8;
            var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));

            var hookRan = false;
            string? touchedPath = null;

            var reader = new CallbackBootReader()
                .WithSlot("a", a)
                .WithSlot("b", b)
                .WithAfterDispose("b", () =>
                {
                    hookRan = true;
                    touchedPath = FindFileUnder(destinationRoot, "boot_b.img");
                    if (touchedPath is not null)
                    {
                        TruncateTo(touchedPath, truncatedLength);
                    }

                    return ValueTask.CompletedTask;
                });

            var result = await BootBackup.CreateAsync(request, reader);

            Assert.True(hookRan, "the reader disposal hook must run after the target file stream closed");
            Assert.NotNull(touchedPath);

            Assert.False(result.IsComplete, "a truncated file must not complete the backup");
            Assert.False(string.IsNullOrWhiteSpace(result.Error));
            Assert.True(
                result.Error!.Contains("readback", StringComparison.OrdinalIgnoreCase),
                $"expected a readback failure, got '{result.Error}'");

            var record = Assert.Single(result.Records);
            Assert.Equal("a", record.Slot);

            using (var manifest = ReadManifest(result.Directory))
            {
                Assert.False(manifest.RootElement.GetProperty("isComplete").GetBoolean());
                Assert.Equal(1, manifest.RootElement.GetProperty("records").GetArrayLength());
            }

            var keptB = Path.Combine(result.Directory, "boot_b.img");
            Assert.True(File.Exists(keptB), "the raw file that failed readback must still be kept");
            Assert.Equal(truncatedLength, new FileInfo(keptB).Length);
        }
        finally
        {
            DeleteOwnRoot(root);
        }
    }

    // ---------- 3 ----------

    [Fact]
    public async Task CreateAsync_BothSlotsMatchDisk_Succeeds_WithUnknownContentState()
    {
        var root = NewUniqueRoot();
        try
        {
            var destinationRoot = NewDestinationRoot(root);
            var a = SlotAPayload();
            var b = SlotBPayload();
            var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));
            var reader = new CallbackBootReader().WithSlot("a", a).WithSlot("b", b);

            var result = await BootBackup.CreateAsync(request, reader);

            Assert.True(result.IsComplete);
            Assert.Null(result.Error);
            Assert.Equal(2, result.Records.Count);

            foreach (var record in result.Records)
            {
                Assert.Equal(BootContentState.Unknown, record.ContentState);
                Assert.False(record.RecoveryUsable);
                var path = Path.Combine(result.Directory, record.FileName);
                Assert.True(File.Exists(path), $"expected '{record.FileName}' on disk");
                Assert.Equal(record.Length, new FileInfo(path).Length);
                Assert.Equal(Sha256Hex(File.ReadAllBytes(path)), record.Sha256);
            }

            Assert.Equal(a, File.ReadAllBytes(Path.Combine(result.Directory, "boot_a.img")));
            Assert.Equal(b, File.ReadAllBytes(Path.Combine(result.Directory, "boot_b.img")));

            using var manifest = ReadManifest(result.Directory);
            Assert.True(manifest.RootElement.GetProperty("isComplete").GetBoolean());
            Assert.Equal(2, manifest.RootElement.GetProperty("records").GetArrayLength());
        }
        finally
        {
            DeleteOwnRoot(root);
        }
    }

    // ---------- 4 ----------

    [Fact]
    public async Task CreateAsync_AllZeroSlotB_SucceedsAsRawBackup_WithEmptyContentState()
    {
        var root = NewUniqueRoot();
        try
        {
            var destinationRoot = NewDestinationRoot(root);
            var a = SlotAPayload();
            var b = ZeroPayload(32);
            var request = new BootBackupRequest(UnlockedIdentity(), destinationRoot, ValidSlots(a, b));
            var reader = new CallbackBootReader().WithSlot("a", a).WithSlot("b", b);

            var result = await BootBackup.CreateAsync(request, reader);

            // An all-zero slot is a legitimate raw backup: the bytes are kept, but nothing is claimed about them.
            Assert.True(result.IsComplete);
            Assert.Null(result.Error);
            Assert.Equal(2, result.Records.Count);

            var recordB = result.Records.Single(r => r.Slot == "b");
            Assert.Equal(BootContentState.Empty, recordB.ContentState);
            Assert.False(recordB.RecoveryUsable);
            Assert.Equal(b.Length, recordB.Length);
            Assert.Equal(Sha256Hex(b), recordB.Sha256);

            var keptB = Path.Combine(result.Directory, "boot_b.img");
            Assert.True(File.Exists(keptB), "an empty raw backup must not be dropped");
            Assert.Equal(b, File.ReadAllBytes(keptB));

            var recordA = result.Records.Single(r => r.Slot == "a");
            Assert.Equal(BootContentState.Unknown, recordA.ContentState);
            Assert.False(recordA.RecoveryUsable);

            using var manifest = ReadManifest(result.Directory);
            Assert.True(manifest.RootElement.GetProperty("isComplete").GetBoolean());
            Assert.Equal(2, manifest.RootElement.GetProperty("records").GetArrayLength());
        }
        finally
        {
            DeleteOwnRoot(root);
        }
    }
}
