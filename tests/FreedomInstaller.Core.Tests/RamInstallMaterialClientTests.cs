using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for the two frozen material uploads and the single build trigger: real local file
/// hashing, the held read lock, one connection, the exact material header and the authoritative status.
/// </summary>
public sealed class RamInstallMaterialClientTests
{
    private static readonly Type MaterialSenderType = typeof(Func<
        Stream,
        string,
        long,
        string,
        string,
        IProgress<RamInstallSeedProgress>,
        TimeSpan,
        CancellationToken,
        Task>);

    [Fact]
    public async Task ReceiveOriginalBootA_VerifiesTheHeldFileAndStreamsTheExactBytes()
    {
        byte[] payload = new byte[4096];
        new Random(101).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));

        var statuses = new Queue<string>(new[]
        {
            Status(request, "receive-original-boot-a", "running",
                MaterialReady("original-boot-a"), pid: 2222, pidStartTicks: "9999"),
            Status(request, "receive-original-boot-a", "succeeded",
                MaterialResult("original-boot-a", payload.LongLength, sha256), exitCode: 0),
        });

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            if (script.Contains("armada_install.py receive-original-boot-a --token", StringComparison.Ordinal))
            {
                return Status(request, "receive-original-boot-a", "running", pid: 2222, pidStartTicks: "9999");
            }

            return null;
        });

        int senderCalls = 0;
        byte[]? sent = null;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = async (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                Assert.Equal("original-boot-a", role);
                Assert.Equal(payload.LongLength, length);
                Assert.Equal(sha256, digest);
                Assert.Equal(Rh002TestData.Token, token);

                using var copy = new MemoryStream();
                await content.CopyToAsync(copy, cancellationToken).ConfigureAwait(false);
                sent = copy.ToArray();

                if (OperatingSystem.IsWindows())
                {
                    // The read-only FileShare.Read handle must still refuse writers during the upload.
                    Assert.ThrowsAny<IOException>(() =>
                    {
                        using FileStream probe = File.Open(file.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    });
                }
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        RamInstallJob job = await client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(5));

        Assert.Equal(RamInstallJobState.Succeeded, job.State);
        Assert.Equal(1, senderCalls);
        Assert.Equal<byte>(payload, sent!);
        Assert.Equal(1, Count(console, "armada_install.py receive-original-boot-a --token"));
        Assert.Equal(2, Count(console, "status --action receive-original-boot-a"));
        Assert.Equal(1, Count(console, "status --action deploy"));
    }

    [Fact]
    public async Task ReceiveRuntime_StreamsTheFourMebibyteRuntimeUnderTheRuntimeRole()
    {
        byte[] payload = new byte[RamInstallBootConfig.RuntimeLength];
        new Random(102).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(runtimeLength: payload.Length, runtimeSha256: sha256));

        var statuses = new Queue<string>(new[]
        {
            Status(request, "receive-runtime", "running",
                MaterialReady("runtime"), pid: 3333, pidStartTicks: "1111"),
            Status(request, "receive-runtime", "succeeded",
                MaterialResult("runtime", payload.LongLength, sha256), exitCode: 0),
        });

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-runtime", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            if (script.Contains("armada_install.py receive-runtime --token", StringComparison.Ordinal))
            {
                return Status(request, "receive-runtime", "running", pid: 3333, pidStartTicks: "1111");
            }

            return null;
        });

        int senderCalls = 0;
        long sentLength = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = async (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                Assert.Equal("runtime", role);
                Assert.Equal(RamInstallBootConfig.RuntimeLength, length);
                sentLength = (await ReadAllAsync(content, cancellationToken).ConfigureAwait(false)).LongLength;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        RamInstallJob job = await client.ReceiveRuntimeAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(5));

        Assert.Equal(RamInstallJobState.Succeeded, job.State);
        Assert.Equal(1, senderCalls);
        Assert.Equal(RamInstallBootConfig.RuntimeLength, sentLength);
    }

    [Fact]
    public async Task ClaimMismatch_IsRejectedBeforeAnyConsoleCommand()
    {
        byte[] payload = new byte[4096];
        new Random(103).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));
        var console = new Rh003ScriptedConsole(request, _ => null);
        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender: null);

        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength + 1, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, new string('0', 64)),
            progress: null,
            TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile("  ", payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));

        Assert.Empty(console.Calls);
    }

    [Fact]
    public async Task RealFileMismatch_BlocksTheMutatingCommand()
    {
        byte[] payload = new byte[4096];
        new Random(104).NextBytes(payload);
        using var file = new TempFile(payload);

        // The claim matches the frozen metadata; the real bytes do not.
        string frozenSha = new string('a', 64);
        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: frozenSha));
        var console = new Rh003ScriptedConsole(request, script =>
            script.Contains("status --action deploy", StringComparison.Ordinal)
                ? Succeeded(request, "deploy")
                : null);
        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender: null);

        await client.InitializeAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, frozenSha),
            progress: null,
            TimeSpan.FromSeconds(1)));

        Assert.Equal(0, Count(console, "armada_install.py receive-original-boot-a --token"));
        Assert.Equal(1, Count(console, "status --action deploy"));
    }

    [Fact]
    public async Task DeployNotSucceeded_BlocksTheMaterialAction()
    {
        byte[] payload = new byte[4096];
        new Random(105).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));
        var console = new Rh003ScriptedConsole(request, script =>
            script.Contains("status --action deploy", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request, "deploy", "failed", exitCode: 1, error: "boom"))
                : null);

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));

        Assert.Equal(0, senderCalls);
        Assert.Equal(0, Count(console, "armada_install.py receive-original-boot-a --token"));
    }

    [Fact]
    public async Task WrongReadyRole_IsRejectedBeforeConnecting()
    {
        byte[] payload = new byte[4096];
        new Random(106).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));
        var console = MaterialConsole(
            request,
            "receive-original-boot-a",
            _ => Status(request, "receive-original-boot-a", "running",
                MaterialReady("runtime"), pid: 2222, pidStartTicks: "9999"));

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(0, senderCalls);
    }

    [Fact]
    public async Task InterruptedReadyResult_IsRejectedBeforeConnecting()
    {
        byte[] payload = new byte[4096];
        new Random(107).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));
        var console = MaterialConsole(
            request,
            "receive-original-boot-a",
            _ => Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "receive-original-boot-a",
                "interrupted",
                result: MaterialReady("original-boot-a"),
                pid: 2222,
                pidStartTicks: "9999",
                error: "gone")));

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));

        Assert.Equal(0, senderCalls);
    }

    [Fact]
    public async Task Cancellation_ReleasesTheGateAndNeverRetries()
    {
        byte[] payload = new byte[4096];
        new Random(108).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));
        var console = MaterialConsole(
            request,
            "receive-original-boot-a",
            _ => Status(request, "receive-original-boot-a", "running",
                MaterialReady("original-boot-a", ready: false), pid: 2222, pidStartTicks: "9999"));

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(10),
            cancellation.Token));

        Assert.Equal(0, senderCalls);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));
        Assert.Equal(1, Count(console, "armada_install.py receive-original-boot-a --token"));
    }

    [Fact]
    public async Task AuthoritativeFailure_AfterAGoodAck_StillFails()
    {
        byte[] payload = new byte[4096];
        new Random(109).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));

        var statuses = new Queue<string>(new[]
        {
            Status(request, "receive-original-boot-a", "running",
                MaterialReady("original-boot-a"), pid: 2222, pidStartTicks: "9999"),
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request, "receive-original-boot-a", "failed", exitCode: 1, error: "later")),
        });

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            if (script.Contains("armada_install.py receive-original-boot-a --token", StringComparison.Ordinal))
            {
                return Status(request, "receive-original-boot-a", "running", pid: 2222, pidStartTicks: "9999");
            }

            return null;
        });

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(1, senderCalls);
    }

    [Fact]
    public async Task RepeatedMaterialAction_IsRefusedWithoutASecondTransfer()
    {
        byte[] payload = new byte[4096];
        new Random(110).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));

        var statuses = new Queue<string>(new[]
        {
            Status(request, "receive-original-boot-a", "running",
                MaterialReady("original-boot-a"), pid: 2222, pidStartTicks: "9999"),
            Status(request, "receive-original-boot-a", "succeeded",
                MaterialResult("original-boot-a", payload.LongLength, sha256), exitCode: 0),
        });

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            if (script.Contains("armada_install.py receive-original-boot-a --token", StringComparison.Ordinal))
            {
                return Status(request, "receive-original-boot-a", "running", pid: 2222, pidStartTicks: "9999");
            }

            return null;
        });

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        await client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(1, senderCalls);
        Assert.Equal(1, Count(console, "armada_install.py receive-original-boot-a --token"));
    }

    [Fact]
    public async Task MaterialCore_WritesTheExactHeaderPayloadAndAcceptsTheAck()
    {
        byte[] payload = new byte[4096];
        new Random(111).NextBytes(payload);
        string sha256 = Sha256(payload);

        var wire = new Rh003DuplexStream(Encoding.UTF8.GetBytes(AckSuccess(payload.LongLength, sha256)));
        using var source = new MemoryStream(payload);

        await InvokeMaterialCoreAsync(
            source,
            wire,
            Rh002TestData.Token,
            "original-boot-a",
            payload.LongLength,
            sha256,
            _ =>
            {
                wire.HalfClose();
                return Task.CompletedTask;
            },
            CancellationToken.None);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.True(newline > 0);
        Assert.True(newline + 1 <= 256);
        Assert.Equal(
            "FREEDOM-MATERIAL/1 " + Rh002TestData.Token + " original-boot-a "
            + payload.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + " " + sha256,
            Encoding.ASCII.GetString(written, 0, newline));
        Assert.Equal(payload, written[(newline + 1)..]);
        Assert.Equal(1, wire.HalfCloseCalls);
    }

    [Fact]
    public async Task MaterialCore_UsesTheRuntimeRoleAndRejectsOpenRoles()
    {
        byte[] payload = new byte[1024];
        new Random(112).NextBytes(payload);
        string sha256 = Sha256(payload);

        var wire = new Rh003DuplexStream(Encoding.UTF8.GetBytes(AckSuccess(payload.LongLength, sha256)));
        await InvokeMaterialCoreAsync(
            new MemoryStream(payload),
            wire,
            Rh002TestData.Token,
            "runtime",
            payload.LongLength,
            sha256,
            _ =>
            {
                wire.HalfClose();
                return Task.CompletedTask;
            },
            CancellationToken.None);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        Assert.StartsWith(
            "FREEDOM-MATERIAL/1 " + Rh002TestData.Token + " runtime ",
            Encoding.ASCII.GetString(written, 0, newline),
            StringComparison.Ordinal);

        var openWire = new Rh003DuplexStream(Array.Empty<byte>());
        await Assert.ThrowsAnyAsync<ArgumentException>(() => InvokeMaterialCoreAsync(
            new MemoryStream(payload),
            openWire,
            Rh002TestData.Token,
            "original-boot-b",
            payload.LongLength,
            sha256,
            _ => Task.CompletedTask,
            CancellationToken.None));
        Assert.Empty(openWire.Written);
    }

    [Fact]
    public async Task MaterialCore_OverlongContentSendsOneExtraByteThenFailsWithoutHalfClose()
    {
        var declared = new byte[1024];
        new Random(113).NextBytes(declared);
        var extra = new byte[512];
        new Random(114).NextBytes(extra);

        var sourceBytes = new byte[declared.Length + extra.Length];
        Buffer.BlockCopy(declared, 0, sourceBytes, 0, declared.Length);
        Buffer.BlockCopy(extra, 0, sourceBytes, declared.Length, extra.Length);

        var wire = new Rh003DuplexStream(Array.Empty<byte>());
        int halfCloseCalls = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeMaterialCoreAsync(
            new MemoryStream(sourceBytes),
            wire,
            Rh002TestData.Token,
            "runtime",
            declared.LongLength,
            Sha256(declared),
            _ =>
            {
                halfCloseCalls++;
                return Task.CompletedTask;
            },
            CancellationToken.None));

        Assert.Equal(0, halfCloseCalls);
        Assert.Equal(0, wire.HalfCloseCalls);

        byte[] written = wire.Written;
        int newline = Array.IndexOf(written, (byte)'\n');
        byte[] afterHeader = written[(newline + 1)..];
        Assert.Equal(declared.Length + 1, afterHeader.Length);
        Assert.Equal(declared, afterHeader[..declared.Length]);
        Assert.Equal(sourceBytes[declared.Length], afterHeader[^1]);
    }

    [Fact]
    public async Task StartBuildBoots_RequiresBothMaterialResultsAndStartsOnce()
    {
        RamInstallBootConfig boot = Rh003TestData.CreateBoot();
        RamInstallRequest request = Rh003TestData.CreateRequest(boot);

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return Succeeded(request, "receive-original-boot-a", MaterialResult(
                    "original-boot-a",
                    boot.Slots.A.CurrentBoot.Length,
                    boot.Slots.A.CurrentBoot.Sha256));
            }

            if (script.Contains("status --action receive-runtime", StringComparison.Ordinal))
            {
                return Succeeded(request, "receive-runtime", MaterialResult(
                    "runtime",
                    boot.Runtime.Length,
                    boot.Runtime.Sha256));
            }

            if (script.Contains("armada_install.py build-boots --token", StringComparison.Ordinal))
            {
                return Status(request, "build-boots", "running", pid: 4444, pidStartTicks: "2222");
            }

            return null;
        });

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender: null);
        await client.InitializeAsync();

        RamInstallJob job = await client.StartBuildBootsAsync();

        Assert.Equal(RamInstallJobState.Running, job.State);
        Assert.Equal(1, Count(console, "armada_install.py build-boots --token"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartBuildBootsAsync());
        Assert.Equal(1, Count(console, "armada_install.py build-boots --token"));
    }

    [Fact]
    public async Task StartBuildBoots_RefusesWhenAMaterialIsNotSucceeded()
    {
        RamInstallBootConfig boot = Rh003TestData.CreateBoot();
        RamInstallRequest request = Rh003TestData.CreateRequest(boot);

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return Succeeded(request, "receive-original-boot-a", MaterialResult(
                    "original-boot-a",
                    boot.Slots.A.CurrentBoot.Length,
                    boot.Slots.A.CurrentBoot.Sha256));
            }

            if (script.Contains("status --action receive-runtime", StringComparison.Ordinal))
            {
                return Status(request, "receive-runtime", "running", pid: 3333, pidStartTicks: "1111");
            }

            return null;
        });

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender: null);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.StartBuildBootsAsync());

        Assert.Equal(0, Count(console, "armada_install.py build-boots --token"));
    }

    [Fact]
    public async Task StartBuildBoots_RejectsAMaterialResultThatDisagreesWithTheFrozenMetadata()
    {
        RamInstallBootConfig boot = Rh003TestData.CreateBoot();
        RamInstallRequest request = Rh003TestData.CreateRequest(boot);

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return Succeeded(request, "receive-original-boot-a", MaterialResult(
                    "original-boot-a",
                    boot.Slots.A.CurrentBoot.Length,
                    new string('9', 64)));
            }

            if (script.Contains("status --action receive-runtime", StringComparison.Ordinal))
            {
                return Succeeded(request, "receive-runtime", MaterialResult(
                    "runtime",
                    boot.Runtime.Length,
                    boot.Runtime.Sha256));
            }

            return null;
        });

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender: null);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.StartBuildBootsAsync());

        Assert.Equal(0, Count(console, "armada_install.py build-boots --token"));
    }

    [Fact]
    public async Task LocalFileMismatch_DoesNotConsumeTheSingleActionAndALaterCorrectFileSucceeds()
    {
        byte[] payload = new byte[4096];
        new Random(115).NextBytes(payload);
        string sha256 = Sha256(payload);
        using var file = new TempFile(payload);

        byte[] corrupted = (byte[])payload.Clone();
        corrupted[corrupted.Length / 2] ^= 0x5a;
        File.WriteAllBytes(file.Path, corrupted);

        RamInstallRequest request = Rh003TestData.CreateRequest(
            Rh003TestData.CreateBoot(originalBootALength: payload.Length, originalBootASha256: sha256));

        var statuses = new Queue<string>(new[]
        {
            Status(request, "receive-original-boot-a", "running",
                MaterialReady("original-boot-a"), pid: 2222, pidStartTicks: "9999"),
            Status(request, "receive-original-boot-a", "succeeded",
                MaterialResult("original-boot-a", payload.LongLength, sha256), exitCode: 0),
        });

        var console = new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action receive-original-boot-a", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            if (script.Contains("armada_install.py receive-original-boot-a --token", StringComparison.Ordinal))
            {
                return Status(request, "receive-original-boot-a", "running", pid: 2222, pidStartTicks: "9999");
            }

            return null;
        });

        int senderCalls = 0;
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = (content, role, length, digest, token, progress, timeout, cancellationToken) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            };

        RamInstallClient client = CreateClient(Rh002TestData.CreateSession(console), request, sender);
        await client.InitializeAsync();

        // The claim matches the frozen metadata but the local bytes do not: the single-use remote
        // action must not be burned, and the same client may still make exactly one real upload.
        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));
        Assert.Equal(0, Count(console, "armada_install.py receive-original-boot-a --token"));
        Assert.Equal(0, senderCalls);

        File.WriteAllBytes(file.Path, payload);

        RamInstallJob job = await client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(2));

        Assert.Equal(RamInstallJobState.Succeeded, job.State);
        Assert.Equal(1, senderCalls);
        Assert.Equal(1, Count(console, "armada_install.py receive-original-boot-a --token"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReceiveOriginalBootAAsync(
            new VerifiedEdlFile(file.Path, payload.LongLength, sha256),
            progress: null,
            TimeSpan.FromSeconds(1)));
        Assert.Equal(1, Count(console, "armada_install.py receive-original-boot-a --token"));
    }

    private static Rh003ScriptedConsole MaterialConsole(
        RamInstallRequest request,
        string literal,
        Func<string, string> status)
    {
        return new Rh003ScriptedConsole(request, script =>
        {
            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return Succeeded(request, "deploy");
            }

            if (script.Contains("status --action " + literal, StringComparison.Ordinal))
            {
                return status(script);
            }

            if (script.Contains("armada_install.py " + literal + " --token", StringComparison.Ordinal))
            {
                return Status(request, literal, "running", pid: 2222, pidStartTicks: "9999");
            }

            return null;
        });
    }

    private static RamInstallClient CreateClient(
        RamInstallSession session,
        RamInstallRequest request,
        Func<Stream, string, long, string, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>? sender)
    {
        var constructor = typeof(RamInstallClient).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            new[]
            {
                typeof(RamInstallSession),
                typeof(RamInstallRequest),
                typeof(Func<
                    Stream,
                    RamInstallSeed,
                    string,
                    IProgress<RamInstallSeedProgress>,
                    TimeSpan,
                    CancellationToken,
                    Task>),
                MaterialSenderType,
            },
            modifiers: null)
            ?? throw new InvalidOperationException("RamInstallClient material constructor is missing.");

        return (RamInstallClient)constructor.Invoke(new object?[] { session, request, null, sender });
    }

    private static Task InvokeMaterialCoreAsync(
        Stream content,
        Stream connection,
        string token,
        string role,
        long length,
        string sha256,
        Func<CancellationToken, Task> halfClose,
        CancellationToken cancellationToken)
    {
        MethodInfo method = typeof(TcpInstallSeedTransfer).GetMethod(
            "TransferMaterialAsync",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("TcpInstallSeedTransfer.TransferMaterialAsync is missing.");

        try
        {
            return (Task)method.Invoke(
                null,
                new object?[]
                {
                    content,
                    connection,
                    token,
                    role,
                    length,
                    sha256,
                    halfClose,
                    null,
                    cancellationToken,
                })!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static string Status(
        RamInstallRequest request,
        string action,
        string state,
        JsonNode? result = null,
        long? pid = null,
        string? pidStartTicks = null,
        int? exitCode = null,
        string? error = null)
    {
        return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
            request,
            action,
            state,
            result,
            pid,
            pidStartTicks,
            exitCode,
            error));
    }

    private static string Succeeded(RamInstallRequest request, string action, JsonNode? result = null)
    {
        return Status(request, action, "succeeded", result ?? new JsonObject(), exitCode: 0);
    }

    private static JsonObject MaterialReady(string role, bool ready = true)
    {
        return new JsonObject
        {
            ["ready"] = ready,
            ["role"] = role,
        };
    }

    private static JsonObject MaterialResult(string role, long length, string sha256)
    {
        return new JsonObject
        {
            ["role"] = role,
            ["length"] = length,
            ["sha256"] = sha256,
        };
    }

    private static string AckSuccess(long receivedBytes, string sha256)
    {
        return "{\"schemaVersion\":1,\"ok\":true,\"receivedBytes\":"
            + receivedBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + ",\"sha256\":\"" + sha256 + "\"}\n";
    }

    private static string Sha256(byte[] payload)
    {
        return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    private static async Task<byte[]> ReadAllAsync(Stream content, CancellationToken cancellationToken)
    {
        using var copy = new MemoryStream();
        await content.CopyToAsync(copy, cancellationToken).ConfigureAwait(false);
        return copy.ToArray();
    }

    private static int Count(Rh003ScriptedConsole console, string fragment)
    {
        return console.Calls.Count(call => call.Contains(fragment, StringComparison.Ordinal));
    }

    private sealed class TempFile : IDisposable
    {
        public TempFile(byte[] content)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "rh003-" + Guid.NewGuid().ToString("N") + ".bin");
            File.WriteAllBytes(Path, content);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                if (File.Exists(Path))
                {
                    File.Delete(Path);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class Rh003DuplexStream : Stream
    {
        private readonly MemoryStream _written = new();
        private readonly byte[] _ack;
        private int _ackOffset;
        private bool _halfClosed;

        public Rh003DuplexStream(byte[] ack)
        {
            _ack = ack ?? throw new ArgumentNullException(nameof(ack));
        }

        public int HalfCloseCalls { get; private set; }

        public byte[] Written => _written.ToArray();

        public void HalfClose()
        {
            HalfCloseCalls++;
            _halfClosed = true;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

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
            if (!_halfClosed)
            {
                return ValueTask.FromResult(0);
            }

            if (_ackOffset >= _ack.Length)
            {
                return ValueTask.FromResult(0);
            }

            int count = Math.Min(buffer.Length, _ack.Length - _ackOffset);
            _ack.AsMemory(_ackOffset, count).CopyTo(buffer);
            _ackOffset += count;
            return ValueTask.FromResult(count);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _written.Write(buffer.Span);
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
    }
}

/// <summary>A console that answers the fixed initialization/inspect pair, then a scripted responder.</summary>
internal sealed class Rh003ScriptedConsole : IMaintenanceConsole
{
    private readonly JsonObject _inspect;
    private readonly Func<string, string?> _responder;

    public Rh003ScriptedConsole(RamInstallRequest request, Func<string, string?> responder)
    {
        // Boot-present requests now also require the read-only source catalog in the inspect result.
        _inspect = Rh004TestData.InspectEnvelope(request);
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
    }

    public List<string> Calls { get; } = new();

    public Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Calls.Add(script);

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<string>(cancellationToken);
        }

        if (string.Equals(expectedMarker, Rh002TestData.InitMarker, StringComparison.Ordinal))
        {
            return Task.FromResult(Rh002TestData.InitMarker + "\n");
        }

        if (script.Contains("armada_install.py inspect", StringComparison.Ordinal))
        {
            return Task.FromResult(Rh002TestData.Transcript(_inspect));
        }

        string? response = _responder(script);
        if (response is null)
        {
            throw new InvalidOperationException("Unexpected console command: " + script);
        }

        return Task.FromResult(response);
    }
}
