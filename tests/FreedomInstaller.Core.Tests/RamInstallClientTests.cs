using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for <see cref="RamInstallClient"/>: session binding before I/O, one-shot
/// initialization, strict inspect/job parsing, single-use actions, read-only polling and the
/// readiness-gated seed transfer.
/// </summary>
public sealed class RamInstallClientTests
{
    [Fact]
    public void Constructor_SerialMismatch_ThrowsBeforeConsole()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest(expectedSocSerial: "3823654013");
        var console = new Rh002FakeConsole((_, _) => throw new InvalidOperationException("console must not be used"));
        RamInstallSession session = Rh002TestData.CreateSession(console);

        var exception = Assert.Throws<MaintenanceException>(() => new RamInstallClient(session, request));

        Assert.Equal(MaintenanceErrorCode.UnsafeEnvironment, exception.Code);
        Assert.Empty(console.Calls);
    }

    [Fact]
    public void Constructor_BootIdMismatch_ThrowsBeforeConsole()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest(
            expectedBootId: "11111111-2222-4333-8444-555555555555");
        var console = new Rh002FakeConsole((_, _) => throw new InvalidOperationException("console must not be used"));
        RamInstallSession session = Rh002TestData.CreateSession(console);

        Assert.Throws<MaintenanceException>(() => new RamInstallClient(session, request));
        Assert.Empty(console.Calls);
    }

    [Fact]
    public void Constructor_ModelMismatch_ThrowsBeforeConsole()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = new Rh002FakeConsole((_, _) => throw new InvalidOperationException("console must not be used"));
        RamInstallSession session = Rh002TestData.CreateSession(console, model: "TB323FU");

        Assert.Throws<MaintenanceException>(() => new RamInstallClient(session, request));
        Assert.Empty(console.Calls);
    }

    [Fact]
    public async Task Initialize_WritesExactBytesAsBase64ThenRunsTheRealInspect()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[0] = Rh002TestData.Copy(
            partitions[0],
            name: "$('touch /tmp/rh002-injection')");
        RamInstallRequest request = Rh002TestData.CreateRequest(partitions: partitions);
        byte[] expectedBytes = Rh002TestData.RequestBytes(request);

        var console = new Rh002FakeConsole((script, marker) =>
        {
            if (string.Equals(marker, Rh002TestData.InitMarker, StringComparison.Ordinal))
            {
                return Rh002TestData.InitMarker + "\n";
            }

            if (script.Contains("armada_install.py inspect", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.InspectEnvelope(request));
            }

            throw new InvalidOperationException("Unexpected command.");
        });

        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);
        await client.InitializeAsync();

        Assert.Equal(2, console.Calls.Count);
        Rh002Call initialization = console.Calls[0];
        Rh002Call inspect = console.Calls[1];

        Assert.Equal(Rh002TestData.InitMarker, initialization.ExpectedMarker);
        Assert.Equal(Rh002TestData.CommandMarker, inspect.ExpectedMarker);

        Assert.Equal(expectedBytes, Rh002TestData.ExtractInitializationBytes(initialization.Script));
        Assert.Contains("umask 077", initialization.Script, StringComparison.Ordinal);
        Assert.Contains("request.json", initialization.Script, StringComparison.Ordinal);
        Assert.Contains("busybox ln", initialization.Script, StringComparison.Ordinal);
        Assert.Contains(expectedBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            initialization.Script, StringComparison.Ordinal);
        Assert.Contains(request.RequestSha256, initialization.Script, StringComparison.Ordinal);
        Assert.DoesNotContain("--token", initialization.Script, StringComparison.Ordinal);
        Assert.DoesNotContain(Rh002TestData.Token, initialization.Script, StringComparison.Ordinal);

        string cleaned = initialization.Script.Replace(
            Convert.ToBase64String(expectedBytes),
            "<base64>",
            StringComparison.Ordinal);
        Assert.DoesNotContain("schemaVersion", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("expectedTable", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("origin", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("$('touch", cleaned, StringComparison.Ordinal);

        Assert.Contains(
            "busybox chroot /tmp/armada-installer-tools /usr/bin/env -i "
            + "PATH=/tmp/freedom-install/tools:/usr/sbin:/usr/bin:/sbin:/bin "
            + "LD_LIBRARY_PATH=/tmp/freedom-install/lib HOME=/root LANG=C.UTF-8 "
            + "/usr/bin/python3 /tmp/freedom-install/armada_install.py inspect --token \"$token\"",
            inspect.Script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(Rh002TestData.Token, inspect.Script, StringComparison.Ordinal);
        Assert.Equal(Rh002TestData.Token, Rh002TestData.DecodeToken(inspect.Script));

        await client.InitializeAsync();
        Assert.Equal(2, console.Calls.Count);
    }

    [Fact]
    public async Task Initialize_Failure_IsNeverRewritten()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = new Rh002FakeConsole((_, marker) =>
            string.Equals(marker, Rh002TestData.InitMarker, StringComparison.Ordinal)
                ? "not the marker\n"
                : throw new InvalidOperationException("Unexpected command."));
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.InitializeAsync());

        Assert.Single(console.Calls);
        Assert.Equal(Rh002TestData.InitMarker, console.Calls[0].ExpectedMarker);
    }

    [Fact]
    public async Task Initialize_RejectsInspectSerialMismatch_AndBlocksPrepare()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject inspect = Rh002TestData.InspectEnvelope(request);
        inspect["result"]!.AsObject()["socSerial"] = "3823654013";
        var console = CreateConsole(request, inspect);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());

        Assert.Equal(0, Count(console, "armada_install.py prepare --token"));
    }

    [Fact]
    public async Task Initialize_RejectsInspectDiskMismatch_AndBlocksPrepare()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject inspect = Rh002TestData.InspectEnvelope(request);
        inspect["result"]!.AsObject()["diskBytes"] = request.ExpectedTable.DiskBytes + 512;
        var console = CreateConsole(request, inspect);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());
        Assert.Equal(0, Count(console, "armada_install.py prepare --token"));
    }

    [Fact]
    public async Task Initialize_RejectsInspectPartitionMismatch_AndBlocksPrepare()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject inspect = Rh002TestData.InspectEnvelope(request);
        JsonArray partitions = inspect["result"]!.AsObject()["partitions"]!.AsArray();
        partitions[2]!.AsObject()["startSector"] = Rh002TestData.BootStart + 1;
        var console = CreateConsole(request, inspect);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());
        Assert.Equal(0, Count(console, "armada_install.py prepare --token"));
    }

    [Theory]
    [InlineData("XYZ")]
    [InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
    [InlineData("f")]
    public async Task Initialize_RejectsNonCanonicalLinuxFingerprint(string fingerprint)
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject inspect = Rh002TestData.InspectEnvelope(request);
        inspect["result"]!.AsObject()["linuxTableFingerprint"] = fingerprint;
        var console = CreateConsole(request, inspect);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
    }

    [Fact]
    public async Task StartPrepare_BeforeInitialization_IsBlocked()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());

        Assert.Empty(console.Calls);
        Assert.Equal(0, Count(console, "armada_install.py prepare --token"));
    }

    [Fact]
    public async Task StartPrepare_FirstJobFailed_StillNeverReruns()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
            script.Contains("armada_install.py prepare --token", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "failed",
                    exitCode: 1,
                    error: "boom"))
                : null);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        RamInstallJob first = await client.StartPrepareAsync();
        Assert.Equal(RamInstallJobState.Failed, first.State);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());
        Assert.Equal(1, Count(console, "armada_install.py prepare --token"));
    }

    [Fact]
    public async Task StartPrepare_RepeatedCall_DoesNotRerun()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("armada_install.py prepare --token", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "running",
                    pid: 1234,
                    pidStartTicks: "5678"));
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        RamInstallJob first = await client.StartPrepareAsync();
        Assert.Equal(RamInstallJobState.Running, first.State);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartPrepareAsync());
        Assert.Equal(1, Count(console, "armada_install.py prepare --token"));

        RamInstallJob status = await client.GetStatusAsync(RamInstallAction.Prepare);
        Assert.Equal(RamInstallJobState.Succeeded, status.State);
        Assert.Equal(1, Count(console, "status --action prepare"));
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("running")]
    [InlineData("not-started")]
    public async Task StartReceiveSeed_RequiresSucceededPrepare(string prepareState)
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(PrepareStatus(request, prepareState));
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        await Assert.ThrowsAsync<MaintenanceException>(() => client.StartReceiveSeedAsync());

        Assert.Equal(0, Count(console, "armada_install.py receive-seed --token"));
    }

    [Fact]
    public async Task StartReceiveSeed_StartsOnceAfterSucceededPrepare()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("armada_install.py receive-seed --token", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "receive-seed",
                    "running",
                    pid: 2222,
                    pidStartTicks: "9999"));
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        RamInstallJob started = await client.StartReceiveSeedAsync();

        Assert.Equal(RamInstallJobState.Running, started.State);
        Assert.Equal(1, Count(console, "armada_install.py receive-seed --token"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartReceiveSeedAsync());
        Assert.Equal(1, Count(console, "armada_install.py receive-seed --token"));
    }

    [Fact]
    public async Task StartDeploy_RequiresSucceededReceiveSeed()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "receive-seed",
                    "running",
                    pid: 2222,
                    pidStartTicks: "9999"));
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        await Assert.ThrowsAsync<MaintenanceException>(() => client.StartDeployAsync());

        Assert.Equal(0, Count(console, "armada_install.py deploy --token"));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("schema")]
    [InlineData("action")]
    [InlineData("hash")]
    [InlineData("running-exit")]
    [InlineData("succeeded-exit")]
    [InlineData("succeeded-error")]
    [InlineData("failed-result")]
    [InlineData("failed-no-error")]
    [InlineData("running-pid-one")]
    [InlineData("running-ticks-zero")]
    [InlineData("missing-marker")]
    [InlineData("two-markers")]
    [InlineData("oversized")]
    [InlineData("malformed")]
    [InlineData("cli-error")]
    public async Task GetStatus_RejectsMalformedOrInconsistentResponses(string kind)
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
            script.Contains("status --action prepare", StringComparison.Ordinal)
                ? BuildMalformedStatus(request, kind)
                : null);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(
            () => client.GetStatusAsync(RamInstallAction.Prepare));
    }

    [Fact]
    public async Task FailedStatus_IsNeverSuccess_AndRawErrorTextIsNeverSurfaced()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        const string rawError = "token=deadbeef secret";
        var console = CreateConsole(request, command: script =>
            script.Contains("status --action prepare", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "failed",
                    exitCode: 1,
                    error: rawError))
                : null);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        RamInstallJob job = await client.GetStatusAsync(RamInstallAction.Prepare);
        Assert.Equal(RamInstallJobState.Failed, job.State);
        Assert.True(job.HasError);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => client.WaitForCompletionAsync(RamInstallAction.Prepare, TimeSpan.FromSeconds(1)));

        Assert.DoesNotContain("deadbeef", exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("deadbeef", job.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WaitForCompletion_PollsStatusOnlyAndReturnsSucceededZero()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var statuses = new Queue<string>(new[]
        {
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "prepare",
                "running",
                pid: 1234,
                pidStartTicks: "5678")),
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "prepare",
                "succeeded",
                result: new JsonObject(),
                exitCode: 0)),
        });
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return statuses.Dequeue();
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        RamInstallJob job = await client.WaitForCompletionAsync(
            RamInstallAction.Prepare,
            TimeSpan.FromSeconds(5));

        Assert.Equal(RamInstallJobState.Succeeded, job.State);
        Assert.Equal(0, job.ExitCode);
        Assert.Equal(2, Count(console, "status --action prepare"));
        Assert.Equal(0, Count(console, "armada_install.py prepare --token"));
    }

    [Fact]
    public async Task WaitForCompletion_NotStarted_Throws()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
            script.Contains("status --action prepare", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "not-started"))
                : null);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => client.WaitForCompletionAsync(RamInstallAction.Prepare, TimeSpan.FromSeconds(1)));

        Assert.Contains("has not been started", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WaitForCompletion_TimesOut()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
            script.Contains("status --action prepare", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "running",
                    pid: 1234,
                    pidStartTicks: "5678"))
                : null);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<TimeoutException>(
            () => client.WaitForCompletionAsync(
                RamInstallAction.Prepare,
                TimeSpan.FromMilliseconds(100)));

        Assert.True(Count(console, "status --action prepare") >= 1);
    }

    [Fact]
    public async Task TransferSeed_WaitsForReadySendsOnceAndRequiresAuthoritativeSuccess()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var receiveStatuses = new Queue<string>(new[]
        {
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "receive-seed",
                "running",
                result: new JsonObject { ["ready"] = true },
                pid: 2222,
                pidStartTicks: "9999")),
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "receive-seed",
                "succeeded",
                result: new JsonObject(),
                exitCode: 0)),
        });
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return receiveStatuses.Dequeue();
            }

            return null;
        });

        var payload = new byte[32768];
        new Random(17).NextBytes(payload);
        var sent = new List<byte[]>();
        var progress = new Rh002Progress();

        Func<Stream, RamInstallSeed, string, IProgress<RamInstallSeedProgress>?, TimeSpan, CancellationToken, Task>
            sender = async (stream, seed, token, observer, timeout, cancellationToken) =>
        {
            using var copy = new MemoryStream();
            await stream.CopyToAsync(copy, cancellationToken).ConfigureAwait(false);
            sent.Add(copy.ToArray());
            observer?.Report(new RamInstallSeedProgress(copy.Length, seed.Length));
        };

        var client = CreateClientWithSender(
            Rh002TestData.CreateSession(console),
            request,
            sender);

        await client.InitializeAsync();
        await client.TransferSeedAsync(
            new MemoryStream(payload),
            progress,
            TimeSpan.FromSeconds(5));

        Assert.Single(sent);
        Assert.Equal(payload, sent[0]);
        Assert.Single(progress.Reports);
        Assert.Equal(payload.LongLength, progress.Reports[0].SentBytes);
        Assert.Equal(request.Seed.Length, progress.Reports[0].TotalBytes);
        Assert.Equal(0, Count(console, "armada_install.py receive-seed --token"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.TransferSeedAsync(
                new MemoryStream(payload),
                progress,
                TimeSpan.FromSeconds(5)));
        Assert.Single(sent);
    }

    [Fact]
    public async Task TransferSeed_NotReady_TimesOutWithoutSending()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "receive-seed",
                    "running",
                    result: new JsonObject { ["ready"] = false },
                    pid: 2222,
                    pidStartTicks: "9999"));
            }

            return null;
        });

        var senderCalls = 0;
        var client = CreateClientWithSender(
            Rh002TestData.CreateSession(console),
            request,
            (_, _, _, _, _, _) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            });

        await client.InitializeAsync();
        await Assert.ThrowsAsync<TimeoutException>(
            () => client.TransferSeedAsync(
                new MemoryStream(new byte[16]),
                progress: null,
                TimeSpan.FromMilliseconds(100)));

        Assert.Equal(0, senderCalls);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("interrupted")]
    [InlineData("succeeded")]
    [InlineData("not-started")]
    public async Task TransferSeed_RejectsTerminalOrNotStartedStateWithoutSending(string state)
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(ReceiveStatus(request, state));
            }

            return null;
        });

        var senderCalls = 0;
        var client = CreateClientWithSender(
            Rh002TestData.CreateSession(console),
            request,
            (_, _, _, _, _, _) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            });

        await client.InitializeAsync();
        await Assert.ThrowsAsync<MaintenanceException>(
            () => client.TransferSeedAsync(
                new MemoryStream(new byte[16]),
                progress: null,
                TimeSpan.FromSeconds(1)));

        Assert.Equal(0, senderCalls);
        Assert.Equal(0, Count(console, "armada_install.py receive-seed --token"));
    }

    [Fact]
    public async Task TransferSeed_InterruptedWithReadyResult_DoesNotConnectOrDeploy()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject interrupted = Rh002TestData.JobEnvelope(
            request,
            "receive-seed",
            "interrupted",
            result: new JsonObject { ["ready"] = true },
            pid: 2222,
            pidStartTicks: "9999",
            error: "gone");
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(interrupted);
            }

            return null;
        });

        var senderCalls = 0;
        var client = CreateClientWithSender(
            Rh002TestData.CreateSession(console),
            request,
            (_, _, _, _, _, _) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            });

        await client.InitializeAsync();

        RamInstallJob status = await client.GetStatusAsync(RamInstallAction.ReceiveSeed);
        Assert.Equal(RamInstallJobState.Interrupted, status.State);
        Assert.True(status.Result.HasValue);
        JsonElement result = status.Result.GetValueOrDefault();
        Assert.Equal(JsonValueKind.Object, result.ValueKind);
        Assert.True(result.GetProperty("ready").GetBoolean());

        await Assert.ThrowsAsync<MaintenanceException>(() => client.TransferSeedAsync(
            new MemoryStream(new byte[16]),
            progress: null,
            TimeSpan.FromSeconds(1)));
        Assert.Equal(0, senderCalls);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.StartDeployAsync());
        await Assert.ThrowsAsync<MaintenanceException>(() => client.WaitForCompletionAsync(
            RamInstallAction.ReceiveSeed,
            TimeSpan.FromSeconds(1)));

        Assert.Equal(0, Count(console, "armada_install.py deploy --token"));
        Assert.Equal(0, Count(console, "armada_install.py receive-seed --token"));
    }

    [Fact]
    public async Task TransferSeed_RequiresSucceededPrepareWithoutSending()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
            script.Contains("status --action prepare", StringComparison.Ordinal)
                ? Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "failed",
                    exitCode: 1,
                    error: "boom"))
                : null);

        var senderCalls = 0;
        var client = CreateClientWithSender(
            Rh002TestData.CreateSession(console),
            request,
            (_, _, _, _, _, _) =>
            {
                senderCalls++;
                return Task.CompletedTask;
            });

        await client.InitializeAsync();
        await Assert.ThrowsAsync<MaintenanceException>(
            () => client.TransferSeedAsync(
                new MemoryStream(new byte[16]),
                progress: null,
                TimeSpan.FromSeconds(1)));

        Assert.Equal(0, senderCalls);
        Assert.Equal(0, Count(console, "status --action receive-seed"));
    }

    [Fact]
    public async Task StartAndStatusScripts_UseTheFixedChrootAndNeverExposeTheToken()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = CreateConsole(request, command: script =>
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: new JsonObject(),
                    exitCode: 0));
            }

            if (script.Contains("armada_install.py prepare --token", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "running",
                    pid: 1234,
                    pidStartTicks: "5678"));
            }

            if (script.Contains("status --action receive-seed", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "receive-seed",
                    "running",
                    pid: 2222,
                    pidStartTicks: "9999"));
            }

            return null;
        });
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        await client.StartPrepareAsync();
        await client.GetStatusAsync(RamInstallAction.ReceiveSeed);

        Rh002Call prepare = console.Calls.Single(call =>
            call.Script.Contains("armada_install.py prepare --token", StringComparison.Ordinal));
        Rh002Call status = console.Calls.Single(call =>
            call.Script.Contains("status --action receive-seed", StringComparison.Ordinal));

        Assert.Contains(
            "busybox chroot /tmp/armada-installer-tools /usr/bin/env -i "
            + "PATH=/tmp/freedom-install/tools:/usr/sbin:/usr/bin:/sbin:/bin "
            + "LD_LIBRARY_PATH=/tmp/freedom-install/lib HOME=/root LANG=C.UTF-8 "
            + "/usr/bin/python3 /tmp/freedom-install/armada_install.py prepare --token \"$token\"",
            prepare.Script,
            StringComparison.Ordinal);
        Assert.Contains(
            "/usr/bin/python3 /tmp/freedom-install/armada_install.py "
            + "status --action receive-seed --token \"$token\"",
            status.Script,
            StringComparison.Ordinal);

        Assert.DoesNotContain(Rh002TestData.Token, prepare.Script, StringComparison.Ordinal);
        Assert.DoesNotContain(Rh002TestData.Token, status.Script, StringComparison.Ordinal);
        Assert.Equal(Rh002TestData.Token, Rh002TestData.DecodeToken(prepare.Script));
        Assert.Equal(Rh002TestData.Token, Rh002TestData.DecodeToken(status.Script));
    }

    private static Rh002FakeConsole CreateConsole(
        RamInstallRequest request,
        JsonObject? inspect = null,
        Func<string, string?>? command = null)
    {
        JsonObject envelope = inspect ?? Rh002TestData.InspectEnvelope(request);
        return new Rh002FakeConsole((script, marker) =>
        {
            if (string.Equals(marker, Rh002TestData.InitMarker, StringComparison.Ordinal))
            {
                return Rh002TestData.InitMarker + "\n";
            }

            if (script.Contains("armada_install.py inspect", StringComparison.Ordinal))
            {
                return Rh002TestData.Transcript(envelope);
            }

            string? response = command?.Invoke(script);
            if (response is not null)
            {
                return response;
            }

            return Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                request,
                "prepare",
                "running",
                pid: 1234,
                pidStartTicks: "5678"));
        });
    }

    private static RamInstallClient CreateClientWithSender(
        RamInstallSession session,
        RamInstallRequest request,
        Func<
            Stream,
            RamInstallSeed,
            string,
            IProgress<RamInstallSeedProgress>?,
            TimeSpan,
            CancellationToken,
            Task> sender)
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
            },
            modifiers: null)
            ?? throw new InvalidOperationException("RamInstallClient internal constructor is missing.");

        return (RamInstallClient)constructor.Invoke(new object?[] { session, request, sender });
    }

    private static JsonObject PrepareStatus(RamInstallRequest request, string state) => state switch
    {
        "failed" => Rh002TestData.JobEnvelope(
            request,
            "prepare",
            "failed",
            exitCode: 1,
            error: "boom"),
        "running" => Rh002TestData.JobEnvelope(
            request,
            "prepare",
            "running",
            pid: 1234,
            pidStartTicks: "5678"),
        "not-started" => Rh002TestData.JobEnvelope(request, "prepare", "not-started"),
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };

    private static JsonObject ReceiveStatus(RamInstallRequest request, string state) => state switch
    {
        "failed" => Rh002TestData.JobEnvelope(
            request,
            "receive-seed",
            "failed",
            exitCode: 1,
            error: "boom"),
        "interrupted" => Rh002TestData.JobEnvelope(
            request,
            "receive-seed",
            "interrupted",
            error: "gone"),
        "succeeded" => Rh002TestData.JobEnvelope(
            request,
            "receive-seed",
            "succeeded",
            result: new JsonObject(),
            exitCode: 0),
        "not-started" => Rh002TestData.JobEnvelope(request, "receive-seed", "not-started"),
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };

    private static string BuildMalformedStatus(RamInstallRequest request, string kind)
    {
        JsonObject envelope = Rh002TestData.JobEnvelope(
            request,
            "prepare",
            "running",
            pid: 1234,
            pidStartTicks: "5678");

        switch (kind)
        {
            case "duplicate":
                return Rh002TestData.JsonPrefix + envelope.ToJsonString() + "\n"
                    + Rh002TestData.JsonPrefix + envelope.ToJsonString() + "\n"
                    + Rh002TestData.CommandMarker + "\n";
            case "schema":
                envelope["schemaVersion"] = 2;
                break;
            case "action":
                envelope["action"] = "receive-seed";
                break;
            case "hash":
                envelope["requestSha256"] = new string('0', 64);
                break;
            case "running-exit":
                envelope["exitCode"] = 0;
                break;
            case "succeeded-exit":
                envelope["state"] = "succeeded";
                envelope["exitCode"] = 1;
                envelope["result"] = new JsonObject();
                break;
            case "succeeded-error":
                envelope["state"] = "succeeded";
                envelope["exitCode"] = 0;
                envelope["result"] = new JsonObject();
                envelope["error"] = "boom";
                break;
            case "failed-result":
                envelope["state"] = "failed";
                envelope["exitCode"] = 1;
                envelope["error"] = "boom";
                envelope["result"] = new JsonObject();
                break;
            case "failed-no-error":
                envelope["state"] = "failed";
                envelope["exitCode"] = 1;
                break;
            case "running-pid-one":
                envelope["pid"] = 1;
                break;
            case "running-ticks-zero":
                envelope["pidStartTicks"] = "0";
                break;
            case "missing-marker":
                return Rh002TestData.JsonPrefix + envelope.ToJsonString() + "\n";
            case "two-markers":
                return Rh002TestData.Transcript(envelope) + Rh002TestData.CommandMarker + "\n";
            case "oversized":
                envelope["error"] = new string('x', (1 << 20) + 1);
                break;
            case "malformed":
                return Rh002TestData.JsonPrefix + "{not json\n" + Rh002TestData.CommandMarker + "\n";
            case "cli-error":
                return Rh002TestData.JsonPrefix
                    + "{\"schemaVersion\":1,\"error\":\"boom\"}\n"
                    + Rh002TestData.CommandMarker
                    + "\n";
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }

        return Rh002TestData.Transcript(envelope);
    }

    private static int Count(Rh002FakeConsole console, string fragment) =>
        console.Calls.Count(call => call.Script.Contains(fragment, StringComparison.Ordinal));

    private sealed class Rh002FakeConsole : IMaintenanceConsole
    {
        private readonly Func<string, string, string> _responder;

        public Rh002FakeConsole(Func<string, string, string> responder)
        {
            _responder = responder ?? throw new ArgumentNullException(nameof(responder));
        }

        public List<Rh002Call> Calls { get; } = new();

        public Task<string> RunCommandAsync(
            string script,
            string expectedMarker,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(new Rh002Call(script, expectedMarker, timeout));

            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<string>(cancellationToken);
            }

            return Task.FromResult(_responder(script, expectedMarker));
        }
    }

    private sealed record Rh002Call(string Script, string ExpectedMarker, TimeSpan Timeout);
}
