using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for RH004B: the four fixed export downloads and the single finish trigger. All
/// fixtures are synthetic metadata and small synthetic payloads; no device, partition, backup, socket
/// or real asset is involved. Tests are authored, not run here.
/// </summary>
public sealed class RamInstallExportFinishTests
{
    private static readonly (RamInstallExportRole Role, string Literal, string Job)[] Exports =
    {
        (RamInstallExportRole.BootA, "boot_a", "export-boot-a"),
        (RamInstallExportRole.BootB, "boot_b", "export-boot-b"),
        (RamInstallExportRole.ReportA, "report_a", "export-report-a"),
        (RamInstallExportRole.ReportB, "report_b", "export-report-b"),
    };

    [Fact]
    public async Task ExportAsync_WritesANewFileAndReturnsTheVerifiedClaim()
    {
        using var harness = new Harness();
        ExportFixture fixture = harness.Fixture;
        harness.QueueExportSuccess("boot_a", "export-boot-a", fixture.BootA);
        await harness.Client.InitializeAsync();

        string path = fixture.NewPath("boot-a");
        VerifiedEdlFile claim = await harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            path,
            progress: null,
            TimeSpan.FromSeconds(5));

        Assert.Equal(Path.GetFullPath(path), claim.Path);
        Assert.Equal(fixture.BootA.LongLength, claim.Length);
        Assert.Equal(Sha256(fixture.BootA), claim.Sha256);

        byte[] actual = File.ReadAllBytes(path);
        Assert.Equal(fixture.BootA, actual);
        Assert.Equal(claim.Sha256, Sha256(actual));

        Assert.Equal(1, harness.Count("armada_install.py export --role boot_a --token"));
        Assert.Equal(1, harness.SenderCalls);
        Assert.Equal(new[] { "boot_a" }, harness.SenderRoles.ToArray());
        Assert.Equal(2, harness.Count("status --action export-boot-a"));
    }

    [Fact]
    public async Task ExportAsync_RefusesAnExistingFileWithoutTouchingItOrStartingAJob()
    {
        using var harness = new Harness();
        await harness.Client.InitializeAsync();

        string path = harness.Fixture.NewPath("existing");
        byte[] original = { 1, 2, 3, 4, 5 };
        File.WriteAllBytes(path, original);

        await Assert.ThrowsAsync<IOException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            path,
            progress: null,
            TimeSpan.FromSeconds(5)));

        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Equal(0, harness.Count("armada_install.py export --role boot_a --token"));
        Assert.Equal(0, harness.SenderCalls);
    }

    [Fact]
    public async Task ExportAsync_PartialFailureKeepsTheNewFileWithoutAClaimAndNeverReplays()
    {
        using var harness = new Harness();
        ExportFixture fixture = harness.Fixture;
        harness.QueueExportSuccess("boot_a", "export-boot-a", fixture.BootA);
        harness.SenderOverride = async (destination, bytes, cancellationToken) =>
        {
            await destination.WriteAsync(bytes.AsMemory(0, bytes.Length / 2), cancellationToken)
                .ConfigureAwait(false);
            throw new IOException("injected link loss");
        };
        await harness.Client.InitializeAsync();

        string path = fixture.NewPath("partial");
        await Assert.ThrowsAsync<IOException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            path,
            progress: null,
            TimeSpan.FromSeconds(5)));

        Assert.True(File.Exists(path));
        Assert.Equal(fixture.BootA.Length / 2, new FileInfo(path).Length);
        Assert.Equal(1, harness.SenderCalls);

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            fixture.NewPath("retry"),
            progress: null,
            TimeSpan.FromSeconds(5)));

        Assert.Equal(1, harness.Count("armada_install.py export --role boot_a --token"));
        Assert.Equal(1, harness.SenderCalls);
    }

    [Fact]
    public async Task ExportAsync_RejectsAReadyRecordForAnotherRoleBeforeConnecting()
    {
        using var harness = new Harness();
        harness.Console.Enqueue(
            "export-boot-a",
            harness.Running("export-boot-a", "report_b", ready: true));
        await harness.Client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            harness.Fixture.NewPath("wrong-role"),
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(0, harness.SenderCalls);
        Assert.Equal(1, harness.Count("armada_install.py export --role boot_a --token"));
    }

    [Fact]
    public async Task ExportAsync_RejectsAPrematureSucceededRecordBeforeConnecting()
    {
        using var harness = new Harness();
        ExportFixture fixture = harness.Fixture;
        harness.Console.Enqueue(
            "export-boot-a",
            harness.Succeeded(
                "export-boot-a",
                ExportResult("boot_a", fixture.BootA.LongLength, Sha256(fixture.BootA))));
        await harness.Client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            fixture.NewPath("premature"),
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(0, harness.SenderCalls);
    }

    [Fact]
    public async Task ExportAsync_RejectsABadAuthoritativeResultEvenWhenTheBytesMatch()
    {
        using var harness = new Harness();
        ExportFixture fixture = harness.Fixture;
        string sha256 = Sha256(fixture.BootA);
        harness.Console.Enqueue("export-boot-a", harness.Running("export-boot-a", "boot_a", ready: true));
        JsonObject unacknowledged = new()
        {
            ["role"] = "boot_a",
            ["length"] = fixture.BootA.LongLength,
            ["sha256"] = sha256,
            ["receiverAcknowledged"] = false,
        };
        harness.Console.Enqueue("export-boot-a", harness.Succeeded("export-boot-a", unacknowledged));
        harness.Console.SetFinal("export-boot-a", harness.Succeeded("export-boot-a", unacknowledged.DeepClone()));
        await harness.Client.InitializeAsync();

        string path = fixture.NewPath("unacknowledged");
        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            path,
            progress: null,
            TimeSpan.FromSeconds(2)));

        Assert.Equal(1, harness.SenderCalls);
        Assert.Equal(fixture.BootA, File.ReadAllBytes(path));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Client.ExportAsync(
            RamInstallExportRole.BootA,
            fixture.NewPath("unacknowledged-retry"),
            progress: null,
            TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public async Task StartFinish_RequiresAllFourLocallyVerifiedExports()
    {
        using var harness = new Harness();
        await harness.Client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.StartFinishAsync());

        Assert.False(harness.Client.FinishAttempted);
        Assert.Equal(0, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task StartFinish_RequiresTheFourAuthoritativeExportStatuses()
    {
        using var harness = new Harness();
        ExportFixture fixture = harness.Fixture;
        harness.QueueAllExports();
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, fixture);

        JsonObject badAck = new()
        {
            ["role"] = "boot_b",
            ["length"] = fixture.BootB.LongLength,
            ["sha256"] = Sha256(fixture.BootB),
            ["receiverAcknowledged"] = false,
        };
        harness.Console.SetFinal("export-boot-b", harness.Succeeded("export-boot-b", badAck));

        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.StartFinishAsync());

        Assert.False(harness.Client.FinishAttempted);
        Assert.Equal(0, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task StartFinish_ReturnsRequestedOnceAndNeverResends()
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        harness.FinishResponder = _ => Task.FromResult(
            harness.Running("finish", role: null, ready: false));
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        RamInstallFinishAttempt attempt = await harness.Client.StartFinishAsync();

        Assert.Equal(RamInstallFinishAttemptState.Requested, attempt.State);
        Assert.Null(attempt.Errno);
        Assert.Null(attempt.ReturnCode);
        Assert.True(harness.Client.FinishAttempted);
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Client.StartFinishAsync());
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));
    }

    [Theory]
    [InlineData("io")]
    [InlineData("timeout")]
    public async Task StartFinish_LostAcknowledgementIsUnknownAndNeverResent(string kind)
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        harness.FinishResponder = _ =>
        {
            if (string.Equals(kind, "io", StringComparison.Ordinal))
            {
                throw new IOException("ack lost");
            }

            if (string.Equals(kind, "timeout", StringComparison.Ordinal))
            {
                throw new TimeoutException("console timeout");
            }

            throw new ArgumentOutOfRangeException(nameof(kind));
        };
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        RamInstallFinishAttempt attempt = await harness.Client.StartFinishAsync();

        Assert.Equal(RamInstallFinishAttemptState.AcknowledgementUnknown, attempt.State);
        Assert.Null(attempt.Errno);
        Assert.Null(attempt.ReturnCode);
        Assert.True(harness.Client.FinishAttempted);
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Client.StartFinishAsync());
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));
    }

    [Theory]
    [InlineData(0, 0L)]
    [InlineData(22, 0L)]
    [InlineData(5, -1L)]
    public async Task StartFinish_Restart2ReturnedIsAlwaysAFailure(int errno, long returnCode)
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        harness.FinishResponder = _ => Task.FromResult(harness.Failed(
            "finish",
            FinishDiagnostic(errno, returnCode),
            exitCode: 1));
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        RamInstallFinishAttempt attempt = await harness.Client.StartFinishAsync();

        Assert.Equal(RamInstallFinishAttemptState.Restart2Returned, attempt.State);
        Assert.Equal(errno, attempt.Errno);
        Assert.Equal(returnCode, attempt.ReturnCode);
        Assert.True(harness.Client.FinishAttempted);
    }

    [Theory]
    [InlineData("missing-code")]
    [InlineData("negative-errno")]
    [InlineData("missing-return")]
    [InlineData("extra-field")]
    [InlineData("wrong-code")]
    [InlineData("string-errno")]
    [InlineData("fractional")]
    public async Task StartFinish_RejectsAnyOtherFailedFinishShape(string kind)
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        harness.FinishResponder = _ => Task.FromResult(harness.Failed(
            "finish",
            MalformedDiagnostic(kind),
            exitCode: 1));
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        await Assert.ThrowsAsync<MaintenanceException>(() => harness.Client.StartFinishAsync());

        Assert.True(harness.Client.FinishAttempted);
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task PreCancelledFinish_IsNotMarkedAsAnAttempt()
    {
        using var harness = new Harness();
        await harness.Client.InitializeAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => harness.Client.StartFinishAsync(cancellation.Token));

        Assert.False(harness.Client.FinishAttempted);
        Assert.Equal(0, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task CancellationDuringFinish_KeepsTheAttemptMarked()
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        harness.FinishResponder = async cancellationToken =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("unreachable");
        };
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => harness.Client.StartFinishAsync(cancellation.Token));

        Assert.True(harness.Client.FinishAttempted);
        Assert.Equal(1, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task CancellationAfterTheLastExportStatus_IsNotMarkedAsAnAttempt()
    {
        using var harness = new Harness();
        harness.QueueAllExports();
        await harness.Client.InitializeAsync();
        await ExportAllAsync(harness.Client, harness.Fixture);

        using var cancellation = new CancellationTokenSource();
        bool cancelledAtLastStatus = false;
        harness.BeforeStatusResult = jobKey =>
        {
            if (string.Equals(jobKey, "export-report-b", StringComparison.Ordinal))
            {
                cancelledAtLastStatus = true;
                cancellation.Cancel();
            }
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => harness.Client.StartFinishAsync(cancellation.Token));

        Assert.True(cancelledAtLastStatus);
        Assert.False(harness.Client.FinishAttempted);
        Assert.Equal(0, harness.Count("armada_install.py finish --token"));
    }

    [Fact]
    public async Task GenericFailedResultOnAnotherActionIsStillRejected()
    {
        using var harness = new Harness();
        harness.SetFinal(
            "prepare",
            harness.Failed("prepare", new JsonObject(), exitCode: 1));
        await harness.Client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(
            () => harness.Client.GetStatusAsync(RamInstallAction.Prepare));
    }

    [Fact]
    public async Task WaitForCompletion_FinishRemainsBlocked()
    {
        using var harness = new Harness();
        await harness.Client.InitializeAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.WaitForCompletionAsync(
                RamInstallAction.Finish,
                TimeSpan.FromSeconds(1)));
    }

    private static async Task ExportAllAsync(RamInstallClient client, ExportFixture fixture)
    {
        foreach ((RamInstallExportRole role, string literal, _) in Exports)
        {
            await client.ExportAsync(
                role,
                fixture.NewPath(literal),
                progress: null,
                TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
    }

    private static JsonObject ExportResult(string role, long length, string sha256) => new()
    {
        ["role"] = role,
        ["length"] = length,
        ["sha256"] = sha256,
        ["receiverAcknowledged"] = true,
    };

    private static JsonObject FinishDiagnostic(int errno, long returnCode) => new()
    {
        ["code"] = "restart2-returned",
        ["errno"] = errno,
        ["returnCode"] = returnCode,
    };

    private static JsonObject MalformedDiagnostic(string kind)
    {
        var result = FinishDiagnostic(0, 0);
        switch (kind)
        {
            case "missing-code":
                result.Remove("code");
                break;
            case "negative-errno":
                result["errno"] = -1;
                break;
            case "missing-return":
                result.Remove("returnCode");
                break;
            case "extra-field":
                result["rawError"] = "secret";
                break;
            case "wrong-code":
                result["code"] = "restart2";
                break;
            case "string-errno":
                result["errno"] = "0";
                break;
            case "fractional":
                result["returnCode"] = 0.5;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }

        return result;
    }

    private static byte[] Bytes(int size, int seed)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string Sha256(byte[] payload) =>
        Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

    private static RamInstallClient CreateClient(
        IMaintenanceConsole console,
        RamInstallRequest request,
        Func<
            Stream,
            string,
            long,
            string,
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
                typeof(Func<
                    Stream,
                    string,
                    long,
                    string,
                    string,
                    IProgress<RamInstallSeedProgress>,
                    TimeSpan,
                    CancellationToken,
                    Task>),
                typeof(Func<
                    Stream,
                    string,
                    long,
                    string,
                    string,
                    IProgress<RamInstallSeedProgress>,
                    TimeSpan,
                    CancellationToken,
                    Task>),
            },
            modifiers: null)
            ?? throw new InvalidOperationException("RamInstallClient export constructor is missing.");

        return (RamInstallClient)constructor.Invoke(new object?[]
        {
            Rh002TestData.CreateSession(console),
            request,
            null,
            null,
            sender,
        });
    }

    /// <summary>One synthetic request, its mutable proof and four small synthetic payloads.</summary>
    private sealed class ExportFixture : IDisposable
    {
        public ExportFixture()
        {
            Request = Rh004TestData.CreateRequest();
            Proof = Rh004TestData.CreateProof(Request);

            // The candidate length stays the frozen full partition descriptor; only the digest is
            // synthetic, so the real proof relations remain checked instead of weakened.
            RamInstallBootConfig boot = Request.Boot
                ?? throw new InvalidOperationException("A boot request is required.");
            int candidateLength = checked((int)boot.Slots.A.CurrentBoot.Length);

            BootA = Bytes(candidateLength, 301);
            BootB = Bytes(candidateLength, 302);
            ReportA = Bytes(139, 303);
            ReportB = Bytes(197, 304);

            SetCandidate("a", BootA);
            SetCandidate("b", BootB);
            SetReport("a", ReportA);
            SetReport("b", ReportB);

            Root = Path.Combine(
                Path.GetTempPath(),
                "rh004b-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public RamInstallRequest Request { get; }

        public Rh004Proof Proof { get; }

        public byte[] BootA { get; }

        public byte[] BootB { get; }

        public byte[] ReportA { get; }

        public byte[] ReportB { get; }

        public string Root { get; }

        public string NewPath(string name) =>
            Path.Combine(Root, name + "-" + Guid.NewGuid().ToString("N") + ".bin");

        public byte[] PayloadFor(string role) => role switch
        {
            "boot_a" => BootA,
            "boot_b" => BootB,
            "report_a" => ReportA,
            "report_b" => ReportB,
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private void SetCandidate(string slot, byte[] bytes)
        {
            string sha256 = Sha256(bytes);
            JsonObject candidate = Proof.Build["slots"]!.AsObject()[slot]!.AsObject()["candidate"]!.AsObject();
            candidate["length"] = (long)bytes.Length;
            candidate["sha256"] = sha256;

            JsonObject finalBoot = Proof.BuildReport(slot)["outputs"]!.AsObject()["final_boot"]!.AsObject();
            finalBoot["length"] = (long)bytes.Length;
            finalBoot["sha256"] = sha256;
        }

        private void SetReport(string slot, byte[] bytes)
        {
            JsonObject report = Proof.Build["slots"]!.AsObject()[slot]!.AsObject()["report"]!.AsObject();
            report["length"] = (long)bytes.Length;
            report["sha256"] = Sha256(bytes);
        }
    }

    private sealed class Harness : IDisposable
    {
        private readonly Dictionary<string, string> _finalStatuses = new(StringComparer.Ordinal);

        public Harness()
        {
            Fixture = new ExportFixture();
            Console = new ScriptedConsole(Fixture.Request, RespondAsync);
            Client = CreateClient(Console, Fixture.Request, SenderAsync);
        }

        public ExportFixture Fixture { get; }

        public ScriptedConsole Console { get; }

        public RamInstallClient Client { get; }

        public int SenderCalls { get; private set; }

        public List<string> SenderRoles { get; } = new();

        public Func<Stream, byte[], CancellationToken, Task>? SenderOverride { get; set; }

        public Func<CancellationToken, Task<string>>? FinishResponder { get; set; }

        /// <summary>
        /// Invoked with the export job key after the scripted status was taken but before it is
        /// returned to the client. Only the cancellation-boundary test uses it.
        /// </summary>
        public Action<string>? BeforeStatusResult { get; set; }

        public int Count(string fragment) =>
            Console.Calls.Count(call => call.Contains(fragment, StringComparison.Ordinal));

        public void QueueExportSuccess(string roleLiteral, string jobKey, byte[] payload)
        {
            Console.Enqueue(jobKey, Running(jobKey, roleLiteral, ready: true));
            string success = Succeeded(jobKey, ExportResult(roleLiteral, payload.LongLength, Sha256(payload)));
            Console.Enqueue(jobKey, success);
            Console.SetFinal(jobKey, success);
        }

        public void QueueAllExports()
        {
            foreach ((_, string literal, string jobKey) in Exports)
            {
                QueueExportSuccess(literal, jobKey, Fixture.PayloadFor(literal));
            }
        }

        public string Running(string action, string? role, bool ready)
        {
            JsonNode? result = role is null
                ? null
                : new JsonObject
                {
                    ["ready"] = ready,
                    ["role"] = role,
                };

            return Envelope(action, "running", result, pid: 4100, pidStartTicks: "7777");
        }

        public string Succeeded(string action, JsonNode? result) =>
            Envelope(action, "succeeded", result ?? new JsonObject(), exitCode: 0);

        public string Failed(string action, JsonNode? result, int exitCode) =>
            Envelope(action, "failed", result, exitCode: exitCode, error: "fixed generic failure");

        public void Dispose() => Fixture.Dispose();

        private async Task<string> RespondAsync(string script, CancellationToken cancellationToken)
        {
            if (script.Contains("status --action prepare", StringComparison.Ordinal))
            {
                return FinalOr("prepare", Succeeded("prepare", Fixture.Proof.Prepare));
            }

            if (script.Contains("status --action deploy", StringComparison.Ordinal))
            {
                return FinalOr("deploy", Succeeded("deploy", Fixture.Proof.Deploy));
            }

            if (script.Contains("status --action build-boots", StringComparison.Ordinal))
            {
                return FinalOr("build-boots", Succeeded("build-boots", Fixture.Proof.Build));
            }

            foreach ((_, _, string jobKey) in Exports)
            {
                if (script.Contains("status --action " + jobKey, StringComparison.Ordinal))
                {
                    string transcript = Console.Take(jobKey);
                    BeforeStatusResult?.Invoke(jobKey);
                    return transcript;
                }
            }

            if (script.Contains("armada_install.py finish --token", StringComparison.Ordinal))
            {
                Func<CancellationToken, Task<string>> responder = FinishResponder
                    ?? (_ => Task.FromResult(Running("finish", role: null, ready: false)));
                return await responder(cancellationToken).ConfigureAwait(false);
            }

            foreach ((_, string literal, string jobKey) in Exports)
            {
                if (script.Contains(
                    "armada_install.py export --role " + literal + " --token",
                    StringComparison.Ordinal))
                {
                    return Running(jobKey, role: null, ready: false);
                }
            }

            throw new InvalidOperationException("Unexpected console command: " + script);
        }

        private string FinalOr(string action, string fallback) =>
            _finalStatuses.TryGetValue(action, out string? transcript) ? transcript : fallback;

        public void SetFinal(string action, string transcript) => _finalStatuses[action] = transcript;

        private string Envelope(
            string action,
            string state,
            JsonNode? result,
            long? pid = null,
            string? pidStartTicks = null,
            int? exitCode = null,
            string? error = null) =>
            Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                Fixture.Request,
                action,
                state,
                result,
                pid,
                pidStartTicks,
                exitCode,
                error));

        private async Task SenderAsync(
            Stream destination,
            string role,
            long length,
            string sha256,
            string token,
            IProgress<RamInstallSeedProgress>? progress,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            SenderCalls++;
            SenderRoles.Add(role);
            Assert.Equal(Rh002TestData.Token, token);

            byte[] payload = Fixture.PayloadFor(role);
            Assert.Equal(payload.LongLength, length);
            Assert.Equal(Sha256(payload), sha256);

            if (SenderOverride is not null)
            {
                await SenderOverride(destination, payload, cancellationToken).ConfigureAwait(false);
                return;
            }

            await destination
                .WriteAsync(payload, cancellationToken)
                .ConfigureAwait(false);
            progress?.Report(new RamInstallSeedProgress(payload.LongLength, payload.LongLength));
        }
    }

    /// <summary>A console that serves inspect plus a per-action scripted transcript.</summary>
    private sealed class ScriptedConsole : IMaintenanceConsole
    {
        private readonly JsonObject _inspect;
        private readonly Func<string, CancellationToken, Task<string>> _responder;
        private readonly Dictionary<string, Queue<string>> _queues = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _final = new(StringComparer.Ordinal);

        public ScriptedConsole(
            RamInstallRequest request,
            Func<string, CancellationToken, Task<string>> responder)
        {
            _inspect = Rh004TestData.InspectEnvelope(request);
            _responder = responder ?? throw new ArgumentNullException(nameof(responder));
        }

        public List<string> Calls { get; } = new();

        public void Enqueue(string jobKey, string transcript)
        {
            if (!_queues.TryGetValue(jobKey, out Queue<string>? queue))
            {
                queue = new Queue<string>();
                _queues.Add(jobKey, queue);
            }

            queue.Enqueue(transcript);
        }

        public void SetFinal(string jobKey, string transcript) => _final[jobKey] = transcript;

        public string Take(string jobKey)
        {
            if (_queues.TryGetValue(jobKey, out Queue<string>? queue) && queue.Count > 0)
            {
                return queue.Dequeue();
            }

            if (_final.TryGetValue(jobKey, out string? transcript))
            {
                return transcript;
            }

            throw new InvalidOperationException("No scripted status for " + jobKey + ".");
        }

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

            return _responder(script, cancellationToken);
        }
    }
}
