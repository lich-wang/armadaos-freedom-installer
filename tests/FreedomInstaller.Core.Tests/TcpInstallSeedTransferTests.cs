using System;
using System.Collections.Generic;
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
/// Focused coverage for <see cref="TcpInstallSeedTransfer"/>: the exact header and payload bytes,
/// 64-bit lengths, short/overlong/hash failures, bounded acknowledgement parsing, timeout handling
/// and caller stream ownership.
/// </summary>
public sealed class TcpInstallSeedTransferTests
{
    [Fact]
    public async Task Transfer_WritesHeaderNewlineThenExactPayloadAndValidatesAck()
    {
        var payload = new byte[32768];
        new Random(23).NextBytes(payload);
        RamInstallSeed seed = CreateSeed(payload);
        var wire = new Rh002DuplexStream(Encoding.UTF8.GetBytes(AckSuccess(payload.Length, seed.Sha256)));
        var progress = new Rh002Progress();
        using var source = new MemoryStream(payload);

        await InvokeTransferAsync(
            source,
            wire,
            seed,
            Rh002TestData.Token,
            cancellationToken =>
            {
                wire.HalfClose();
                return Task.CompletedTask;
            },
            progress,
            CancellationToken.None);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.True(newline > 0);
        Assert.True(newline + 1 <= 256);

        string header = Encoding.ASCII.GetString(written, 0, newline);
        Assert.Equal(
            "FREEDOM-SEED/1 " + Rh002TestData.Token + " seed "
            + payload.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + " " + seed.Sha256,
            header);

        Assert.Equal(payload, written[(newline + 1)..]);
        Assert.Equal(1, wire.HalfCloseCalls);
        Assert.True(source.CanRead);
        Assert.NotEmpty(progress.Reports);
        Assert.Equal(payload.LongLength, progress.Reports[^1].SentBytes);
        Assert.Equal(payload.LongLength, progress.Reports[^1].TotalBytes);
    }

    [Fact]
    public async Task Transfer_ShortContent_FailsBeforeHalfClose()
    {
        var payload = new byte[1024];
        RamInstallSeed seed = CreateSeed(payload, declaredLength: 2048);
        var wire = new Rh002DuplexStream(Array.Empty<byte>());
        int halfCloseCalls = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            new MemoryStream(payload),
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                halfCloseCalls++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, halfCloseCalls);
    }

    [Fact]
    public async Task Transfer_OverlongContent_SendsOnlyOneExtraByteThenFailsWithoutHalfClose()
    {
        var declared = new byte[1024];
        new Random(41).NextBytes(declared);
        var extra = new byte[512];
        new Random(42).NextBytes(extra);

        var sourceBytes = new byte[declared.Length + extra.Length];
        Buffer.BlockCopy(declared, 0, sourceBytes, 0, declared.Length);
        Buffer.BlockCopy(extra, 0, sourceBytes, declared.Length, extra.Length);

        RamInstallSeed seed = CreateSeed(declared);
        var wire = new Rh002DuplexStream(Array.Empty<byte>());
        var source = new Rh002NonSeekableReadStream(sourceBytes);
        int halfCloseCalls = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            source,
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                halfCloseCalls++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.False(source.CanSeek);
        Assert.Equal(0, halfCloseCalls);
        Assert.Equal(0, wire.HalfCloseCalls);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.True(newline > 0);

        byte[] afterHeader = written[(newline + 1)..];
        Assert.Equal(declared.Length + 1, afterHeader.Length);
        Assert.Equal(declared, afterHeader[..declared.Length]);
        Assert.Equal(sourceBytes[declared.Length], afterHeader[^1]);
    }

    [Fact]
    public async Task Transfer_HashMismatch_FailsBeforeHalfClose()
    {
        var payload = new byte[4096];
        var seed = new RamInstallSeed(
            payload.Length,
            new string('a', 64),
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            Rh002TestData.Origin);
        var wire = new Rh002DuplexStream(Array.Empty<byte>());
        int halfCloseCalls = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            new MemoryStream(payload),
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                halfCloseCalls++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, halfCloseCalls);
    }

    [Theory]
    [InlineData("ok-false")]
    [InlineData("short-response")]
    [InlineData("received-bytes")]
    [InlineData("sha")]
    [InlineData("extra")]
    [InlineData("too-long")]
    [InlineData("no-newline")]
    [InlineData("not-json")]
    [InlineData("prefix")]
    [InlineData("schema")]
    public async Task Transfer_RejectsBadAcknowledgement(string kind)
    {
        var payload = new byte[4096];
        new Random(31).NextBytes(payload);
        RamInstallSeed seed = CreateSeed(payload);
        byte[] ack = kind switch
        {
            "ok-false" => Encoding.UTF8.GetBytes(
                "{\"schemaVersion\":1,\"ok\":false,\"error\":\"nope\"}\n"),
            "short-response" => Array.Empty<byte>(),
            "received-bytes" => Encoding.UTF8.GetBytes(AckSuccess(payload.Length + 1, seed.Sha256)),
            "sha" => Encoding.UTF8.GetBytes(AckSuccess(payload.Length, new string('0', 64))),
            "extra" => Encoding.UTF8.GetBytes(AckSuccess(payload.Length, seed.Sha256) + "x"),
            "too-long" => Encoding.ASCII.GetBytes(new string('x', 4097)),
            "no-newline" => Encoding.UTF8.GetBytes(AckSuccess(payload.Length, seed.Sha256).TrimEnd('\n')),
            "not-json" => Encoding.UTF8.GetBytes("hello\n"),
            "prefix" => Encoding.UTF8.GetBytes(
                "FREEDOM_INSTALL_JSON " + AckSuccess(payload.Length, seed.Sha256).TrimEnd('\n') + "\n"),
            "schema" => Encoding.UTF8.GetBytes(
                AckSuccess(payload.Length, seed.Sha256).Replace(
                    "\"schemaVersion\":1",
                    "\"schemaVersion\":2",
                    StringComparison.Ordinal)),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        var wire = new Rh002DuplexStream(ack);
        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            new MemoryStream(payload),
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                wire.HalfClose();
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.DoesNotContain("nope", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transfer_TimesOutWhileWaitingForAck()
    {
        var payload = new byte[4096];
        RamInstallSeed seed = CreateSeed(payload);
        var wire = new Rh002DuplexStream(Array.Empty<byte>(), holdAckUntilCancel: true);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => InvokeTransferAsync(
            new MemoryStream(payload),
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                wire.HalfClose();
                return Task.CompletedTask;
            },
            progress: null,
            cancellation.Token));

        Assert.Equal(1, wire.HalfCloseCalls);
    }

    [Fact]
    public async Task Transfer_Accepts64BitLengthWithoutAllocatingTheDeclaredSize()
    {
        const long length = 6L * 1024L * 1024L * 1024L;
        var seed = new RamInstallSeed(
            length,
            new string('a', 64),
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            Rh002TestData.Origin);
        var wire = new Rh002DuplexStream(Array.Empty<byte>());
        int halfCloseCalls = 0;

        Assert.True(length > int.MaxValue);

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeTransferAsync(
            new Rh002EmptyReadStream(),
            wire,
            seed,
            Rh002TestData.Token,
            _ =>
            {
                halfCloseCalls++;
                return Task.CompletedTask;
            },
            progress: null,
            CancellationToken.None));

        Assert.Equal(0, halfCloseCalls);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.True(newline > 0);
        Assert.Contains(
            " seed " + length.ToString(System.Globalization.CultureInfo.InvariantCulture) + " ",
            Encoding.ASCII.GetString(written, 0, newline),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_RejectsSeekableLengthMismatchBeforeConnecting()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var transfer = new TcpInstallSeedTransfer();

        await Assert.ThrowsAsync<InvalidDataException>(() => transfer.SendAsync(
            new MemoryStream(new byte[4]),
            request.Seed,
            Rh002TestData.Token,
            progress: null,
            TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task SendAsync_RejectsInvalidArgumentsBeforeConnecting()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var transfer = new TcpInstallSeedTransfer();
        var content = new MemoryStream(new byte[4]);

        await Assert.ThrowsAsync<ArgumentNullException>(() => transfer.SendAsync(
            content,
            null!,
            Rh002TestData.Token,
            progress: null,
            TimeSpan.FromSeconds(1)));

        await Assert.ThrowsAsync<ArgumentException>(() => transfer.SendAsync(
            content,
            request.Seed,
            new string('a', 63),
            progress: null,
            TimeSpan.FromSeconds(1)));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => transfer.SendAsync(
            content,
            request.Seed,
            Rh002TestData.Token,
            progress: null,
            TimeSpan.Zero));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => transfer.SendAsync(
            content,
            request.Seed,
            Rh002TestData.Token,
            progress: null,
            Timeout.InfiniteTimeSpan));

        await Assert.ThrowsAsync<ArgumentException>(() => transfer.SendAsync(
            new MaintenanceTransferWriteOnlyStream(),
            request.Seed,
            Rh002TestData.Token,
            progress: null,
            TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void ProductionSurface_HasOnlyTheFixedParameterlessConstructor()
    {
        ConstructorInfo[] constructors = typeof(TcpInstallSeedTransfer)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());

        MethodInfo[] methods = typeof(TcpInstallSeedTransfer)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        Assert.DoesNotContain(
            methods,
            method => method.GetParameters().Any(parameter =>
                parameter.Name is not null &&
                (parameter.Name.Contains("host", StringComparison.OrdinalIgnoreCase) ||
                 parameter.Name.Contains("port", StringComparison.OrdinalIgnoreCase))));
    }

    private static RamInstallSeed CreateSeed(byte[] payload, long? declaredLength = null)
    {
        string sha = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        return new RamInstallSeed(
            declaredLength ?? payload.LongLength,
            sha,
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            Rh002TestData.Origin);
    }

    private static string AckSuccess(long receivedBytes, string sha256)
    {
        return "{\"schemaVersion\":1,\"ok\":true,\"receivedBytes\":"
            + receivedBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + ",\"sha256\":\"" + sha256 + "\"}\n";
    }

    private static Task InvokeTransferAsync(
        Stream content,
        Stream connection,
        RamInstallSeed seed,
        string token,
        Func<CancellationToken, Task> halfClose,
        IProgress<RamInstallSeedProgress>? progress,
        CancellationToken cancellationToken)
    {
        MethodInfo method = typeof(TcpInstallSeedTransfer).GetMethod(
            "TransferAsync",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("TcpInstallSeedTransfer.TransferAsync is missing.");

        try
        {
            return (Task)method.Invoke(
                null,
                new object?[]
                {
                    content,
                    connection,
                    seed,
                    token,
                    halfClose,
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

    private sealed class Rh002DuplexStream : Stream
    {
        private readonly MemoryStream _written = new();
        private readonly byte[] _ack;
        private readonly bool _holdAckUntilCancel;
        private int _ackOffset;

        public Rh002DuplexStream(byte[] ack, bool holdAckUntilCancel = false)
        {
            _ack = ack ?? throw new ArgumentNullException(nameof(ack));
            _holdAckUntilCancel = holdAckUntilCancel;
        }

        public int HalfCloseCalls { get; private set; }

        public byte[] Written => _written.ToArray();

        public void HalfClose()
        {
            HalfCloseCalls++;
            _halfClosed = true;
        }

        private bool _halfClosed;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

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
            if (!_halfClosed)
            {
                return 0;
            }

            if (_holdAckUntilCancel)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            }

            if (_ackOffset >= _ack.Length)
            {
                return 0;
            }

            int count = Math.Min(buffer.Length, _ack.Length - _ackOffset);
            _ack.AsMemory(_ackOffset, count).CopyTo(buffer);
            _ackOffset += count;
            return count;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) =>
            _written.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();
    }

    private sealed class Rh002EmptyReadStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(0);

        public override int Read(byte[] buffer, int offset, int count) => 0;

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class Rh002NonSeekableReadStream : Stream
    {
        private readonly byte[] _data;
        private int _position;

        public Rh002NonSeekableReadStream(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_position >= _data.Length)
            {
                return ValueTask.FromResult(0);
            }

            int count = Math.Min(buffer.Length, _data.Length - _position);
            _data.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position >= _data.Length)
            {
                return 0;
            }

            int read = Math.Min(count, _data.Length - _position);
            Array.Copy(_data, _position, buffer, offset, read);
            _position += read;
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
