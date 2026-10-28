using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Backup and write-step contract of <see cref="HttpUninstallBackend"/>. The fake runtime below serves the
/// current-state descriptors, keeps a real transaction state machine and records every request, but never
/// touches a socket. Backups are asserted as files the host produced in <see cref="HttpUninstallBackend.BackupDirectory"/>,
/// not as a particular helper the production code might call.
/// </summary>
public sealed class HttpUninstallTransactionTests
{
    private static readonly string[] SixSteps =
    {
        "restore-boot-a",
        "verify-boot-a",
        "restore-boot-b",
        "verify-boot-b",
        "reclaim-space",
        "queue-factory-reset",
    };

    [Fact]
    public async Task Backup_ThreeVerifiedFilesAndManifestExistBeforeAck()
    {
        using var scenario = new LifecycleFakeScenario();
        var backend = await scenario.PrepareAsync();

        await backend.BackupCurrentBootAsync(CancellationToken.None);

        // The fake verifies the four files and their hashes inside the ACK callback, before it accepts.
        Assert.Equal(1, scenario.AckCount);
        Assert.Equal(0, scenario.StepPostCount);
        Assert.Equal(
            new[] { "a", "b", "misc" },
            scenario.BootRolesRequested.OrderBy(role => role, StringComparer.Ordinal).ToArray());

        Assert.Equal(
            new[] { "boot_a.img", "boot_b.img", "manifest.json", "misc.img" },
            Directory.GetFiles(backend.BackupDirectory)
                .Select(path => Path.GetFileName(path))
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray());

        AssertBackupFile(backend.BackupDirectory, "boot_a.img", HttpHostFixture.CurrentBootABytes);
        AssertBackupFile(backend.BackupDirectory, "boot_b.img", HttpHostFixture.CurrentBootBBytes);
        AssertBackupFile(backend.BackupDirectory, "misc.img", HttpHostFixture.CurrentMiscBytes);

        var manifestPath = Path.Combine(backend.BackupDirectory, "manifest.json");
        var manifestText = File.ReadAllText(manifestPath);
        Assert.DoesNotContain(HttpHostFixture.BearerToken, manifestText);
        Assert.DoesNotContain(HttpHostFixture.ConfirmationToken, manifestText);

        using var document = JsonDocument.Parse(manifestText);
        var manifest = document.RootElement;
        Assert.Equal(1, manifest.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(backend.TransactionId, manifest.GetProperty("transactionId").GetString());
        Assert.Equal(HttpHostFixture.BootId, manifest.GetProperty("bootId").GetString());
        Assert.Equal(backend.Snapshot.Identity.Serial, manifest.GetProperty("serial").GetString());
        Assert.Equal(backend.Snapshot.Identity.Model, manifest.GetProperty("model").GetString());
        Assert.Equal(HttpHostFixture.SocSerial, manifest.GetProperty("socSerial").GetString());
        Assert.Equal(backend.PlanFingerprint, manifest.GetProperty("planFingerprint").GetString());

        var entries = manifest.GetProperty("backups");
        Assert.Equal(3, entries.GetArrayLength());

        var expected = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["boot_a"] = HttpHostFixture.CurrentBootABytes,
            ["boot_b"] = HttpHostFixture.CurrentBootBBytes,
            ["misc"] = HttpHostFixture.CurrentMiscBytes,
        };

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            var role = entry.GetProperty("role").GetString();
            Assert.NotNull(role);
            Assert.True(expected.ContainsKey(role!), $"unexpected manifest role {role}");
            Assert.True(seen.Add(role!), $"duplicate manifest role {role}");

            var file = entry.GetProperty("file").GetString();
            Assert.NotNull(file);
            Assert.Equal(role + ".img", Path.GetFileName(file));

            var path = Path.Combine(backend.BackupDirectory, Path.GetFileName(file));
            Assert.True(File.Exists(path), $"manifest names missing file {file}");
            var actual = File.ReadAllBytes(path);
            Assert.Equal(expected[role!], actual);
            Assert.Equal(actual.LongLength, entry.GetProperty("bytes").GetInt64());
            Assert.Equal(HttpHostFixture.Sha256Hex(actual), entry.GetProperty("sha256").GetString());
        }

        Assert.Equal(3, seen.Count);
    }

    [Fact]
    public async Task Backup_TruncatedBodyNeverAckOrStep()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.BootBodyOverrides["a"] = HttpHostFixture.CurrentBootABytes[..5];
        var backend = await scenario.PrepareAsync();

        await Assert.ThrowsAnyAsync<IOException>(() => backend.BackupCurrentBootAsync(CancellationToken.None));

        Assert.Equal(0, scenario.AckCount);
        Assert.Equal(0, scenario.StepPostCount);
    }

    [Fact]
    public async Task Backup_CorruptSameLengthBodyNeverAckOrStep()
    {
        using var scenario = new LifecycleFakeScenario();
        var corrupt = (byte[])HttpHostFixture.CurrentBootABytes.Clone();
        corrupt[^1] ^= 0xFF;
        scenario.BootBodyOverrides["a"] = corrupt;
        var backend = await scenario.PrepareAsync();

        await Assert.ThrowsAnyAsync<IOException>(() => backend.BackupCurrentBootAsync(CancellationToken.None));

        Assert.Equal(0, scenario.AckCount);
        Assert.Equal(0, scenario.StepPostCount);
    }

    [Fact]
    public async Task Backup_DirectoryWriteFailureNeverAckOrStep()
    {
        using var scenario = new LifecycleFakeScenario();
        var backend = await scenario.PrepareAsync();

        var backupDirectory = backend.BackupDirectory;
        Directory.CreateDirectory(Path.GetDirectoryName(backupDirectory)!);
        if (Directory.Exists(backupDirectory))
        {
            Directory.Delete(backupDirectory, recursive: true);
        }

        File.WriteAllText(backupDirectory, "this file occupies the directory path");

        await Assert.ThrowsAnyAsync<IOException>(() => backend.BackupCurrentBootAsync(CancellationToken.None));

        Assert.Equal(0, scenario.AckCount);
        Assert.Equal(0, scenario.StepPostCount);
    }

    [Fact]
    public async Task RestoreBeforeHostBackupFailsWithoutPost()
    {
        using var scenario = new LifecycleFakeScenario();
        var backend = await scenario.PrepareAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => backend.RestoreBootAsync("a", CancellationToken.None));

        Assert.Equal(0, scenario.AckCount);
        Assert.Equal(0, scenario.StepPostCount);
    }

    [Fact]
    public async Task Transaction_CompletesExactSixStepsThenAwaitsFactoryReset()
    {
        using var scenario = new LifecycleFakeScenario();
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        await backend.PrepareStockBootAsync(CancellationToken.None);
        await backend.RestoreBootAsync("a", CancellationToken.None);
        await backend.VerifyBootAsync("a", CancellationToken.None);
        await backend.RestoreBootAsync("b", CancellationToken.None);
        await backend.VerifyBootAsync("b", CancellationToken.None);
        await backend.ReclaimAndroidSpaceAsync(CancellationToken.None);
        await backend.InitializeAndroidAsync(CancellationToken.None);

        var status = await backend.RefreshTransactionAsync();

        Assert.Equal("awaitingFactoryReset", status.State);
        Assert.Equal("AwaitingFactoryReset", status.Stage);
        Assert.Null(status.NextStep);
        Assert.True(status.BackupAcknowledged);
        Assert.Equal(SixSteps, scenario.PostSteps);
        Assert.Equal(SixSteps, status.CompletedSteps);

        Assert.DoesNotContain(
            scenario.Requests,
            request => request.Path.Contains("verify-factory-reset", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            scenario.Requests,
            request => request.Path.Contains("verifyandroid", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            scenario.Requests,
            request => request.Path.Contains("reboot", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Transaction_PostDropAfterAccepted_OnlyOnePostThenReadOnlyStatusResolves()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.DropAfterAcceptedOnStep = "restore-boot-a";
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        await backend.RestoreBootAsync("a", CancellationToken.None);

        Assert.Equal(1, scenario.StepPostCount);
        Assert.True(scenario.StatusGetCount >= 1, "the host must read the transaction status after the drop");
        Assert.Contains("restore-boot-a", scenario.CompletedSteps);

        await backend.RestoreBootAsync("a", CancellationToken.None);

        Assert.Equal(1, scenario.StepPostCount);
        Assert.Equal(
            1,
            scenario.Requests.Count(request => request.Signature == "POST /v1/prepare"));
    }

    [Fact]
    public async Task Transaction_PostDropBeforeAccepted_BecomesUncertainWithoutReplay()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.DropBeforeAcceptedOnStep = "restore-boot-a";
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        var uncertain = await Assert.ThrowsAsync<UninstallTransactionUncertainException>(
            () => backend.RestoreBootAsync("a", CancellationToken.None));

        Assert.Equal(backend.TransactionId, uncertain.TransactionId);
        Assert.Equal("restore-boot-a", uncertain.Step);
        Assert.Equal(1, scenario.StepPostCount);

        var status = await backend.RefreshTransactionAsync();
        Assert.Equal("prepared", status.State);
        Assert.Equal("restore-boot-a", status.NextStep);
        Assert.True(scenario.StatusGetCount >= 1, "the unresolved step must be re-read with GET status");

        var repeated = await Record.ExceptionAsync(() => backend.RestoreBootAsync("a", CancellationToken.None));
        if (repeated is not null)
        {
            Assert.IsType<UninstallTransactionUncertainException>(repeated);
        }

        Assert.Equal(1, scenario.StepPostCount);
        Assert.Equal(
            1,
            scenario.Requests.Count(request => request.Signature == "POST /v1/prepare"));
    }

    [Fact]
    public async Task Transaction_FailedStageStopsWithNoFollowingWrites()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.FailedStep = "restore-boot-a";
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => backend.RestoreBootAsync("a", CancellationToken.None));

        var status = await backend.RefreshTransactionAsync();
        Assert.Equal("failed", status.State);
        Assert.Equal(LifecycleFakeScenario.FailedStageName, status.Stage);
        Assert.False(string.IsNullOrWhiteSpace(status.Error));

        Assert.Equal(new[] { "restore-boot-a" }, scenario.PostSteps);
        Assert.DoesNotContain(scenario.PostSteps, step => step == "verify-boot-a");
        Assert.DoesNotContain(scenario.PostSteps, step => step == "verify-boot-b");
        Assert.DoesNotContain(scenario.PostSteps, step => step == "reclaim-space");
        Assert.DoesNotContain(scenario.PostSteps, step => step == "queue-factory-reset");
    }

    [Fact]
    public async Task RunningThenCompleted_ReadOnlyPollsDoNotReplayOrPrematurelySucceed()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.DelayedCompletionStatusReads = 2;
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);
        await backend.PrepareStockBootAsync(CancellationToken.None);

        var statusReadsBeforeRestore = scenario.StatusGetCount;

        await backend.RestoreBootAsync("a", CancellationToken.None);

        // Checked before any further status read could advance the fake towards completion.
        Assert.Contains("restore-boot-a", scenario.CompletedSteps);
        Assert.Equal(1, scenario.StepPostCount);
        Assert.True(
            scenario.StatusGetCount - statusReadsBeforeRestore >= 3,
            "the host must keep reading the transaction status until the worker completed the step");

        var status = await backend.RefreshTransactionAsync();
        Assert.Equal("prepared", status.State);
        Assert.Equal("verify-boot-a", status.NextStep);
    }

    [Fact]
    public async Task InvalidCompletedPrefixIsNotAccepted()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.CorruptCompletionEvidence = true;
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);
        await backend.PrepareStockBootAsync(CancellationToken.None);

        await Assert.ThrowsAnyAsync<IOException>(() => backend.RestoreBootAsync("a", CancellationToken.None));

        Assert.Equal(1, scenario.StepPostCount);
        Assert.Equal(new[] { "restore-boot-a" }, scenario.PostSteps);
    }

    [Fact]
    public async Task Http503AfterAccepted_OnlyStatusResolves()
    {
        using var scenario = new LifecycleFakeScenario();
        scenario.Http503AfterAccepted = true;
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        await backend.RestoreBootAsync("a", CancellationToken.None);

        Assert.Equal(1, scenario.StepPostCount);
        Assert.True(scenario.StatusGetCount >= 1, "the 503 reply must be resolved by reading the same transaction status");
        Assert.Contains("restore-boot-a", scenario.CompletedSteps);

        await Record.ExceptionAsync(() => backend.RestoreBootAsync("a", CancellationToken.None));

        Assert.Equal(1, scenario.StepPostCount);
        Assert.Equal(
            1,
            scenario.Requests.Count(request => request.Signature == "POST /v1/prepare"));
    }

    [Fact]
    public async Task InvalidSlotRejectedBeforePost()
    {
        using var scenario = new LifecycleFakeScenario();
        var backend = await scenario.PrepareAsync();
        await backend.BackupCurrentBootAsync(CancellationToken.None);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => backend.RestoreBootAsync("c", CancellationToken.None));

        Assert.Equal(0, scenario.StepPostCount);
    }

    private static void AssertBackupFile(string directory, string fileName, byte[] expected)
    {
        var path = Path.Combine(directory, fileName);
        Assert.True(File.Exists(path), $"missing backup file {fileName}");
        var actual = File.ReadAllBytes(path);
        Assert.Equal(expected, actual);
        Assert.Equal(HttpHostFixture.Sha256Hex(expected), HttpHostFixture.Sha256Hex(actual));
    }
}

/// <summary>
/// One fake transaction server around <see cref="HttpHostFixture"/>: it serves the three current-state boot
/// downloads, acknowledges a complete host backup only after checking the files on disk, advances the six
/// ordered write steps, and can inject a dropped POST or a failed stage. There is no network and no second
/// transaction: every status response is the prepared document with the live state applied.
/// </summary>
internal sealed class LifecycleFakeScenario : IDisposable
{
    internal const string FailedStageName = "RestoreBootA";

    private readonly HttpHostFixture _fixture;
    private readonly List<string> _completed = new();
    private string? _transactionId;
    private string _state = "prepared";
    private string _stage = "Prepared";
    private string? _nextStep = "restore-boot-a";
    private string? _activeStep;
    private bool _acknowledged;
    private string? _error;
    private string? _delayedStep;
    private int _delayedReadsRemaining;

    internal LifecycleFakeScenario()
    {
        _fixture = new HttpHostFixture();
        _fixture.Handler.ExtraResponse = HandleAsync;
    }

    /// <summary>Step that throws after the fake completed it, as if the response was lost.</summary>
    internal string? DropAfterAcceptedOnStep { get; set; }

    /// <summary>Step that throws before the fake recorded acceptance, as if the request never arrived.</summary>
    internal string? DropBeforeAcceptedOnStep { get; set; }

    /// <summary>Step that reaches the fake worker and fails there; the transaction becomes terminal.</summary>
    internal string? FailedStep { get; set; }

    /// <summary>
    /// When set, an accepted step stays <c>running</c> and is only completed after this many read-only status
    /// reads observed it. The POST itself never waits for a worker.
    /// </summary>
    internal int? DelayedCompletionStatusReads { get; set; }

    /// <summary>Records a later step in place of the first completed step to contradict the ordered prefix.</summary>
    internal bool CorruptCompletionEvidence { get; set; }

    /// <summary>Completes the step but answers the POST with HTTP 503, as if the reply was lost after acceptance.</summary>
    internal bool Http503AfterAccepted { get; set; }

    /// <summary>Literal body overrides per boot role, used to serve truncation or corruption.</summary>
    internal Dictionary<string, byte[]> BootBodyOverrides { get; } = new(StringComparer.Ordinal);

    internal int AckCount { get; private set; }

    internal int StepPostCount { get; private set; }

    internal int StatusGetCount { get; private set; }

    internal List<string> PostSteps { get; } = new();

    internal List<string> BootRolesRequested { get; } = new();

    internal IReadOnlyList<string> CompletedSteps => _completed;

    internal IReadOnlyList<RecordedHttpRequest> Requests => _fixture.Handler.Requests;

    public void Dispose() => _fixture.Dispose();

    internal async Task<HttpUninstallBackend> PrepareAsync(CancellationToken token = default)
    {
        var backend = await HttpUninstallBackend.CreatePreparedAsync(
            _fixture.Http,
            _fixture.Connection,
            _fixture.Inputs,
            _fixture.Binding,
            _fixture.Assets,
            _fixture.BackupRoot,
            token);

        _transactionId = backend.TransactionId;
        return backend;
    }

    private Task<HttpResponseMessage> HandleAsync(RecordedHttpRequest request, CancellationToken cancellationToken)
    {
        var path = request.Path;

        if (request.Method == "GET" && path.StartsWith("/v1/boot/", StringComparison.Ordinal))
        {
            return Task.FromResult(BootResponse(path["/v1/boot/".Length..]));
        }

        if (request.Method == "POST" && path.EndsWith("/ack-backups", StringComparison.Ordinal))
        {
            return Task.FromResult(AckResponse(request));
        }

        if (request.Method == "GET" && path.EndsWith("/status", StringComparison.Ordinal))
        {
            return Task.FromResult(StatusResponse(path));
        }

        if (request.Method == "POST" && path.EndsWith("/step", StringComparison.Ordinal))
        {
            return Task.FromResult(StepResponse(request, path));
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(
                $"fake transaction host: unexpected {request.Method} {request.Path}", Encoding.UTF8, "text/plain"),
        });
    }

    private HttpResponseMessage BootResponse(string role)
    {
        if (role.StartsWith("boot_", StringComparison.Ordinal))
        {
            role = role["boot_".Length..];
        }

        BootRolesRequested.Add(role);

        var expected = role switch
        {
            "a" => HttpHostFixture.CurrentBootABytes,
            "b" => HttpHostFixture.CurrentBootBBytes,
            "misc" => HttpHostFixture.CurrentMiscBytes,
            _ => throw new InvalidOperationException($"fake transaction host: unknown boot role {role}"),
        };

        var body = BootBodyOverrides.TryGetValue(role, out var overridden) ? overridden : expected;
        var content = new ByteArrayContent(body);

        // The descriptor headers stay truthful even when the test injects a short or corrupt body.
        content.Headers.ContentLength = expected.LongLength;
        content.Headers.TryAddWithoutValidation("X-Content-SHA256", HttpHostFixture.Sha256Hex(expected));

        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }

    private HttpResponseMessage AckResponse(RecordedHttpRequest request)
    {
        using var document = JsonDocument.Parse(request.Body);
        var body = document.RootElement;

        Require(GetString(body, "transactionId") == _transactionId, "ACK carried another transaction id");
        Require(GetString(body, "bootId") == HttpHostFixture.BootId, "ACK carried another boot id");
        Require(GetString(body, "socSerial") == HttpHostFixture.SocSerial, "ACK carried another SoC serial");

        var expected = CurrentBackups();
        Require(body.GetProperty("backups").GetArrayLength() == expected.Count, "ACK must name exactly three backups");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in body.GetProperty("backups").EnumerateArray())
        {
            var role = GetString(entry, "role");
            Require(role is not null && expected.ContainsKey(role), $"ACK named unknown role {role}");
            Require(seen.Add(role!), $"ACK repeated role {role}");
            Require(entry.GetProperty("bytes").GetInt64() == expected[role!].Bytes.LongLength,
                $"ACK byte length mismatch for {role}");
            Require(GetString(entry, "sha256") == expected[role!].Sha256,
                $"ACK hash mismatch for {role}");
        }

        Require(seen.Count == 3, "ACK did not name all three backup roles");

        // The files and manifest must already be complete when the host asks for acknowledgement.
        VerifyHostBackupOnDisk();

        AckCount++;
        _acknowledged = true;

        return JsonResponse(new JsonObject
        {
            ["acknowledged"] = true,
            ["backupAckId"] = "ack-" + _transactionId,
        });
    }

    private HttpResponseMessage StatusResponse(string path)
    {
        RequireTransaction(path, "/status");
        StatusGetCount++;

        if (_delayedStep is not null)
        {
            if (_delayedReadsRemaining > 0)
            {
                _delayedReadsRemaining--;
            }
            else
            {
                var completedStep = _delayedStep;
                _delayedStep = null;
                CompleteStep(completedStep);
            }
        }

        return JsonResponse(BuildStatus());
    }

    private HttpResponseMessage StepResponse(RecordedHttpRequest request, string path)
    {
        RequireTransaction(path, "/step");

        using var document = JsonDocument.Parse(request.Body);
        var body = document.RootElement;

        var step = GetString(body, "step");
        Require(!string.IsNullOrWhiteSpace(step), "step request carried no step");
        Require(GetString(body, "bootId") == HttpHostFixture.BootId, "step carried another boot id");
        Require(GetString(body, "confirmationToken") == HttpHostFixture.ConfirmationToken,
            "step carried another confirmation token");
        Require(body.GetProperty("wipeConfirmed").GetBoolean(), "step was not sent with wipeConfirmed=true");
        Require(_acknowledged, $"step {step} was posted before the host backup was acknowledged");
        Require(step == _nextStep, $"step {step} is not the next expected step {_nextStep}");

        StepPostCount++;
        PostSteps.Add(step!);

        if (string.Equals(step, DropBeforeAcceptedOnStep, StringComparison.Ordinal))
        {
            throw new HttpRequestException("fake transaction host: connection lost before the step was accepted");
        }

        if (string.Equals(step, FailedStep, StringComparison.Ordinal))
        {
            _state = "failed";
            _stage = FailedStageName;
            _activeStep = null;
            _error = "fake transaction host: worker failed at " + step;

            // The failed step is not completed and nextStep does not advance.
            return JsonResponse(BuildStatus(), HttpStatusCode.Accepted);
        }

        if (DelayedCompletionStatusReads is int delayedReads && delayedReads > 0)
        {
            _delayedStep = step;
            _delayedReadsRemaining = delayedReads;
            _state = "running";
            _stage = "Running";
            _activeStep = step;
            _nextStep = step;

            // The worker is still running: the requested step is neither advanced nor completed here.
            return JsonResponse(BuildStatus(), HttpStatusCode.Accepted);
        }

        CompleteStep(step!);

        if (Http503AfterAccepted && string.Equals(step, "restore-boot-a", StringComparison.Ordinal))
        {
            return JsonResponse(
                new JsonObject
                {
                    ["error"] = new JsonObject
                    {
                        ["code"] = "REPLY_UNAVAILABLE",
                        ["message"] = "fake after accepted",
                    },
                },
                HttpStatusCode.ServiceUnavailable);
        }

        if (string.Equals(step, DropAfterAcceptedOnStep, StringComparison.Ordinal))
        {
            throw new HttpRequestException("fake transaction host: connection lost after the step was accepted");
        }

        return JsonResponse(BuildStatus(), HttpStatusCode.Accepted);
    }

    private void CompleteStep(string step)
    {
        var recorded = step;
        if (CorruptCompletionEvidence && string.Equals(step, "restore-boot-a", StringComparison.Ordinal))
        {
            recorded = "restore-boot-b";
        }

        _completed.Add(recorded);
        _activeStep = null;

        if (string.Equals(step, "queue-factory-reset", StringComparison.Ordinal))
        {
            _state = "awaitingFactoryReset";
            _stage = "AwaitingFactoryReset";
            _nextStep = null;
        }
        else
        {
            _state = "prepared";
            _stage = "Prepared";
            _nextStep = NextAfter(step);
        }
    }

    private JsonObject BuildStatus()
    {
        var prepared = _fixture.Handler.LastPreparedJson
            ?? throw new InvalidOperationException("fake transaction host: status requested before prepare");

        var status = JsonNode.Parse(prepared)!.AsObject();
        status["bootId"] = HttpHostFixture.BootId;
        status["state"] = _state;
        status["stage"] = _stage;

        if (_nextStep is null)
        {
            status["nextStep"] = null;
        }
        else
        {
            status["nextStep"] = JsonValue.Create(_nextStep);
        }

        if (_activeStep is null)
        {
            status["activeStep"] = null;
        }
        else
        {
            status["activeStep"] = JsonValue.Create(_activeStep);
        }

        var completed = new JsonArray();
        foreach (var step in _completed)
        {
            completed.Add(JsonValue.Create(step));
        }

        status["completedSteps"] = completed;
        status["backupAcknowledged"] = _acknowledged;

        if (_error is null)
        {
            status["error"] = null;
        }
        else
        {
            status["error"] = new JsonObject
            {
                ["code"] = "WRITE_FAILED",
                ["message"] = _error,
                ["stage"] = _stage,
            };
        }

        return status;
    }

    private static string? NextAfter(string step) => step switch
    {
        "restore-boot-a" => "verify-boot-a",
        "verify-boot-a" => "restore-boot-b",
        "restore-boot-b" => "verify-boot-b",
        "verify-boot-b" => "reclaim-space",
        "reclaim-space" => "queue-factory-reset",
        "queue-factory-reset" => null,
        _ => throw new InvalidOperationException($"fake transaction host: unknown step {step}"),
    };

    private static Dictionary<string, (byte[] Bytes, string Sha256)> CurrentBackups() => new(StringComparer.Ordinal)
    {
        ["boot_a"] = (HttpHostFixture.CurrentBootABytes, HttpHostFixture.Sha256Hex(HttpHostFixture.CurrentBootABytes)),
        ["boot_b"] = (HttpHostFixture.CurrentBootBBytes, HttpHostFixture.Sha256Hex(HttpHostFixture.CurrentBootBBytes)),
        ["misc"] = (HttpHostFixture.CurrentMiscBytes, HttpHostFixture.Sha256Hex(HttpHostFixture.CurrentMiscBytes)),
    };

    /// <summary>
    /// Runs inside the ACK callback: the host may only acknowledge after the three snapshots and the manifest
    /// are already on disk, byte for byte, and the manifest describes those exact files.
    /// </summary>
    private void VerifyHostBackupOnDisk()
    {
        var root = _fixture.BackupRoot;
        Require(Directory.Exists(root), $"backup root {root} does not exist at ACK time");

        var directories = Directory.GetDirectories(root);
        Require(directories.Length == 1, $"expected one host backup directory at ACK time, found {directories.Length}");
        var directory = directories[0];

        var expected = CurrentBackups();
        foreach (var (role, backup) in expected)
        {
            var path = Path.Combine(directory, role + ".img");
            Require(File.Exists(path), $"missing {role}.img at ACK time");
            var actual = File.ReadAllBytes(path);
            Require(actual.LongLength == backup.Bytes.LongLength, $"{role}.img has the wrong length at ACK time");
            Require(HttpHostFixture.Sha256Hex(actual) == backup.Sha256, $"{role}.img has the wrong hash at ACK time");
        }

        var manifestPath = Path.Combine(directory, "manifest.json");
        Require(File.Exists(manifestPath), "missing manifest.json at ACK time");

        using var document = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        var manifest = document.RootElement;

        Require(manifest.GetProperty("schemaVersion").GetInt32() == 1, "manifest schema is not 1");
        Require(GetString(manifest, "transactionId") == _transactionId, "manifest carried another transaction id");
        Require(GetString(manifest, "bootId") == HttpHostFixture.BootId, "manifest carried another boot id");
        Require(GetString(manifest, "serial") == _fixture.Inputs.Identity.Serial, "manifest carried another serial");
        Require(GetString(manifest, "model") == _fixture.Inputs.Identity.Model, "manifest carried another model");
        Require(GetString(manifest, "socSerial") == HttpHostFixture.SocSerial, "manifest carried another SoC serial");
        Require(GetString(manifest, "planFingerprint") == HttpHostFixture.PlanFingerprint,
            "manifest carried another plan fingerprint");

        var entries = manifest.GetProperty("backups");
        Require(entries.GetArrayLength() == 3, "manifest must describe exactly three backups");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            var role = GetString(entry, "role");
            Require(role is not null && expected.ContainsKey(role), $"manifest named unknown role {role}");
            Require(seen.Add(role!), $"manifest repeated role {role}");

            var file = GetString(entry, "file");
            Require(file is not null && Path.GetFileName(file) == role + ".img",
                $"manifest file for {role} is not {role}.img");

            var actual = File.ReadAllBytes(Path.Combine(directory, Path.GetFileName(file!)));
            Require(actual.LongLength == expected[role!].Bytes.LongLength,
                $"manifest described the wrong {role} length");
            Require(entry.GetProperty("bytes").GetInt64() == actual.LongLength,
                $"manifest byte length does not match {role}.img");
            Require(GetString(entry, "sha256") == HttpHostFixture.Sha256Hex(actual),
                $"manifest hash does not match {role}.img");
            Require(GetString(entry, "sha256") == expected[role!].Sha256,
                $"manifest hash does not match the runtime snapshot for {role}");
        }

        Require(seen.Count == 3, "manifest did not describe all three backups");
    }

    private void RequireTransaction(string path, string suffix)
    {
        var withoutSuffix = path[..^suffix.Length].TrimEnd('/');
        var transactionId = withoutSuffix[(withoutSuffix.LastIndexOf('/') + 1)..];

        Require(_transactionId is not null && string.Equals(transactionId, _transactionId, StringComparison.Ordinal),
            $"request for transaction {transactionId} does not match {_transactionId}");
    }

    private static string? GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException("fake transaction host: " + message);
        }
    }

    private static HttpResponseMessage JsonResponse(JsonNode node, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status)
        {
            Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json"),
        };
}
