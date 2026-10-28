using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for <see cref="TcpInstallExportTransfer"/>: the exact export header, the bounded
/// streaming receive, EOF-before-ACK ordering, the flush-before-ACK callback, short/overlong/digest and
/// local write failures, caller stream ownership and the fixed production surface. No socket is opened.
/// </summary>
public sealed class TcpInstallExportTransferTests
{
    private const string HeaderPrefix = "FREEDOM-EXPORT/1";

    [Fact]
    public async Task Transfer_WritesTheHeaderStreamsThePayloadFlushesThenAcks()
    {
        var payload = new byte[32768];
        new Random(211).NextBytes(payload);
        string sha256 = Sha256(payload);

        var wire = new ExportWire(payload);
        var destination = new TrackingWriteStream();
        var progress = new Rh002Progress();
        var order = new System.Collections.Generic.List<string>();

        await InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_a",
            payload.LongLength,
            sha256,
            _ =>
            {
                order.Add("half-close");
                wire.HalfClose();
                Assert.Contains("receivedBytes", ReadWritten(wire), StringComparison.Ordinal);
                return Task.CompletedTask;
            },
            _ =>
            {
                order.Add("flush");
                Assert.True(wire.EofObserved, "the destination must be flushed only after EOF");
                Assert.Equal(payload.LongLength, wire.PayloadRead);
                Assert.False(wire.AckStarted, "the destination must be flushed before the acknowledgement");
                return Task.CompletedTask;
            },
            progress,
            CancellationToken.None);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.True(newline > 0);
        Assert.True(newline + 1 <= 256);
        Assert.Equal(
            HeaderPrefix + " " + Rh002TestData.Token + " boot_a "
            + payload.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + " " + sha256,
            Encoding.ASCII.GetString(written, 0, newline));

        string acknowledgement = Encoding.ASCII.GetString(written, newline + 1, written.Length - newline - 1);
        Assert.Equal(
            "{\"schemaVersion\":1,\"ok\":true,\"receivedBytes\":"
            + payload.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + ",\"sha256\":\"" + sha256 + "\"}\n",
            acknowledgement);

        Assert.Equal(payload, destination.ToArray());
        Assert.Equal(new[] { "flush", "half-close" }, order.ToArray());
        Assert.Equal(1, wire.HalfCloseCalls);
        Assert.False(destination.WasDisposed, "the caller-owned destination is never disposed");
        Assert.False(wire.WasDisposed, "the caller-owned connection is never disposed");
        Assert.NotEmpty(progress.Reports);
        Assert.Equal(payload.LongLength, progress.Reports[^1].SentBytes);
        Assert.Equal(payload.LongLength, progress.Reports[^1].TotalBytes);
    }

    [Theory]
    [InlineData("boot_b", 4096)]
    [InlineData("report_a", 137)]
    [InlineData("report_b", 211)]
    public async Task Transfer_UsesTheExactFixedRoleLiteralOnTheWire(string role, int size)
    {
        var payload = new byte[size];
        new Random(size).NextBytes(payload);
        string sha256 = Sha256(payload);
        var wire = new ExportWire(payload);
        var destination = new TrackingWriteStream();

        await InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            role,
            payload.LongLength,
            sha256,
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            progress: null,
            CancellationToken.None);

        int newline = Array.IndexOf(wire.Written, (byte)'\n');
        Assert.StartsWith(
            HeaderPrefix + " " + Rh002TestData.Token + " " + role + " ",
            Encoding.ASCII.GetString(wire.Written, 0, newline),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transfer_ShortStreamFailsWithoutFlushOrAcknowledgement()
    {
        var declared = new byte[2048];
        new Random(212).NextBytes(declared);
        var wire = new ExportWire(declared[..1024]);
        var destination = new TrackingWriteStream();
        int flushes = 0;
        int halfCloses = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_a",
            declared.LongLength,
            Sha256(declared),
            _ =>
            {
                halfCloses++;
                return Task.CompletedTask;
            },
            _ =>
            {
                flushes++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, flushes);
        Assert.Equal(0, halfCloses);
        Assert.False(wire.AckStarted);
    }

    [Fact]
    public async Task Transfer_OverlongStreamFailsWithoutAcknowledgement()
    {
        var declared = new byte[1024];
        new Random(213).NextBytes(declared);
        var source = new byte[declared.Length + 1];
        Buffer.BlockCopy(declared, 0, source, 0, declared.Length);
        source[^1] = 0x7f;

        var wire = new ExportWire(source);
        var destination = new TrackingWriteStream();
        int flushes = 0;
        int halfCloses = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_a",
            declared.LongLength,
            Sha256(source[..declared.Length]),
            _ =>
            {
                halfCloses++;
                return Task.CompletedTask;
            },
            _ =>
            {
                flushes++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, flushes);
        Assert.Equal(0, halfCloses);
        Assert.False(wire.AckStarted);
        Assert.Equal(declared.Length, destination.Length);
    }

    [Fact]
    public async Task Transfer_DigestMismatchFailsBeforeFlushAndAcknowledgement()
    {
        var payload = new byte[4096];
        new Random(214).NextBytes(payload);
        var wire = new ExportWire(payload);
        var destination = new TrackingWriteStream();
        int flushes = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_a",
            payload.LongLength,
            new string('0', 64),
            _ => Task.CompletedTask,
            _ =>
            {
                flushes++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, flushes);
        Assert.False(wire.AckStarted);
    }

    [Fact]
    public async Task Transfer_LocalWriteFailureFailsWithoutAcknowledgement()
    {
        var payload = new byte[4096];
        new Random(215).NextBytes(payload);
        var wire = new ExportWire(payload);
        var destination = new FailingWriteStream();
        int halfCloses = 0;

        await Assert.ThrowsAsync<IOException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_a",
            payload.LongLength,
            Sha256(payload),
            _ =>
            {
                halfCloses++;
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, halfCloses);
        Assert.False(wire.AckStarted);
    }

    [Fact]
    public async Task Transfer_AcceptsA64BitLengthAndRejectsAShortPayloadWithoutAllocatingIt()
    {
        const long declared = 6L * 1024L * 1024L * 1024L;
        var wire = new ExportWire(Array.Empty<byte>());
        var destination = new TrackingWriteStream();

        Assert.True(declared > int.MaxValue);

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "boot_b",
            declared,
            new string('a', 64),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            progress: null,
            CancellationToken.None));

        int newline = Array.IndexOf(wire.Written, (byte)'\n');
        Assert.Contains(
            " boot_b " + declared.ToString(System.Globalization.CultureInfo.InvariantCulture) + " ",
            Encoding.ASCII.GetString(wire.Written, 0, newline),
            StringComparison.Ordinal);
        Assert.Equal(0, destination.Length);
        Assert.False(wire.AckStarted);
    }

    [Fact]
    public async Task Transfer_CancelledWhileWaitingForBytesNeverAcknowledges()
    {
        var payload = new byte[4096];
        var wire = new ExportWire(payload, holdReadUntilCancel: true);
        var destination = new TrackingWriteStream();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => InvokeTransferAsync(
            wire,
            destination,
            Rh002TestData.Token,
            "report_a",
            payload.LongLength,
            Sha256(payload),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            progress: null,
            cancellation.Token));

        Assert.False(wire.AckStarted);
        Assert.Equal(0, destination.Length);
    }

    [Theory]
    [InlineData("boot_c")]
    [InlineData("")]
    [InlineData("BOOT_A")]
    [InlineData("export-boot-a")]
    public async Task Transfer_RejectsAnyRoleOutsideTheClosedSetBeforeWriting(string role)
    {
        var wire = new ExportWire(new byte[16]);

        await Assert.ThrowsAsync<ArgumentException>(() => InvokeTransferAsync(
            wire,
            new TrackingWriteStream(),
            Rh002TestData.Token,
            role,
            16,
            new string('a', 64),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            progress: null,
            CancellationToken.None));

        Assert.Empty(wire.Written);
    }

    [Fact]
    public async Task Transfer_RejectsAnUnusableTokenBeforeWriting()
    {
        var wire = new ExportWire(new byte[16]);

        await Assert.ThrowsAsync<ArgumentException>(() => InvokeTransferAsync(
            wire,
            new TrackingWriteStream(),
            new string('A', 64),
            "boot_a",
            16,
            new string('a', 64),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            progress: null,
            CancellationToken.None));

        Assert.Empty(wire.Written);
    }

    [Fact]
    public void ProductionSurface_HasOnlyTheFixedParameterlessConstructor()
    {
        ConstructorInfo[] constructors = typeof(TcpInstallExportTransfer)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());

        MethodInfo[] methods = typeof(TcpInstallExportTransfer)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        Assert.DoesNotContain(
            methods,
            method => method.GetParameters().Any(parameter =>
                parameter.Name is not null &&
                (parameter.Name.Contains("host", StringComparison.OrdinalIgnoreCase) ||
                 parameter.Name.Contains("port", StringComparison.OrdinalIgnoreCase))));
    }

    private static string ReadWritten(ExportWire wire) =>
        Encoding.ASCII.GetString(wire.Written);

    private static string Sha256(byte[] payload) =>
        Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

    private static Task InvokeTransferAsync(
        Stream connection,
        Stream destination,
        string token,
        string role,
        long length,
        string sha256,
        Func<CancellationToken, Task> halfClose,
        Func<CancellationToken, Task> flushBeforeAck,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        MethodInfo method = typeof(TcpInstallExportTransfer).GetMethod(
            "TransferAsync",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("TcpInstallExportTransfer.TransferAsync is missing.");

        try
        {
            return (Task)method.Invoke(
                null,
                new object?[]
                {
                    connection,
                    destination,
                    token,
                    role,
                    length,
                    sha256,
                    halfClose,
                    flushBeforeAck,
                    progress,
                    cancellationToken,
                })!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private sealed class ExportWire : Stream
    {
        private readonly MemoryStream _written = new();
        private readonly byte[] _payload;
        private readonly bool _holdReadUntilCancel;
        private int _offset;

        public ExportWire(byte[] payload, bool holdReadUntilCancel = false)
        {
            _payload = payload ?? throw new ArgumentNullException(nameof(payload));
            _holdReadUntilCancel = holdReadUntilCancel;
        }

        public int HalfCloseCalls { get; private set; }

        public bool EofObserved { get; private set; }

        public bool AckStarted { get; private set; }

        public bool WasDisposed { get; private set; }

        public int PayloadRead => _offset;

        public byte[] Written => _written.ToArray();

        public void HalfClose()
        {
            HalfCloseCalls++;
        }

        public override bool CanRead => !WasDisposed;

        public override bool CanSeek => false;

        public override bool CanWrite => !WasDisposed;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_holdReadUntilCancel)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            }

            if (_offset >= _payload.Length)
            {
                EofObserved = true;
                return 0;
            }

            int count = Math.Min(buffer.Length, _payload.Length - _offset);
            _payload.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            byte[] bytes = buffer.ToArray();
            if (Array.IndexOf(bytes, (byte)'{') >= 0)
            {
                AckStarted = true;
            }

            _written.Write(bytes);
            return ValueTask.CompletedTask;
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) =>
            _written.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class TrackingWriteStream : MemoryStream
    {
        public bool WasDisposed { get; private set; }

        public override bool CanWrite => !WasDisposed && base.CanWrite;

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (WasDisposed)
            {
                throw new ObjectDisposedException(nameof(TrackingWriteStream));
            }

            return base.WriteAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class FailingWriteStream : Stream
    {
        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new IOException("injected local write failure"));

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new IOException("injected local write failure");

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
