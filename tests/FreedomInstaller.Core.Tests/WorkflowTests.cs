using Xunit;

namespace FreedomInstaller.Core.Tests;

public class WorkflowTests
{
    private static readonly string[] NonDestructive = { "inspect", "prepare" };

    private static readonly string[] FullSequence =
    {
        "inspect", "prepare", "inspect", "partition", "deploy", "verify-system",
        "write-a", "verify-a", "write-b", "verify-b",
    };

    private static WorkflowInputs Inputs() =>
        new("S", "TB322FC", BootloaderState.Unlocked, "table-v1", "pkg-v1", "backup-ab-v1",
            BothSlotBasesValid: true, MaintenanceValidated: true,
            CurrentBootFingerprint: "current-boot-a-b-v1");

    private static InstallRequest Draft(bool testPackage = false, bool erase = true, IReadOnlyList<string>? slots = null) =>
        new(Inputs(), "plan-v1", "", erase, testPackage, slots ?? new[] { "a", "b" });

    private static InstallRequest Request(bool testPackage = false, IReadOnlyList<string>? slots = null) =>
        Confirmed(Draft(testPackage, true, slots));

    private static InstallRequest Confirmed(InstallRequest request) =>
        request with { ConfirmationId = InstallWorkflow.ConfirmationFor(request) };

    private static void AssertNoDestructiveCalls(FakeBackend backend) =>
        Assert.All(backend.Calls, call => Assert.Contains(call, NonDestructive));

    [Fact]
    public async Task HappyPathRunsFullSequence()
    {
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.True(result.Success);
        Assert.Equal(InstallStage.AwaitingBootAcceptance, result.Stage);
        Assert.True(result.AndroidDataMayBeErased);
        Assert.Equal(new[] { "a", "b" }, result.VerifiedSlots);
        Assert.Equal(FullSequence, backend.Calls);
    }

    [Fact]
    public async Task SlotOrderIsHonored()
    {
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(Request(slots: new[] { "b", "a" }), backend);

        Assert.True(result.Success);
        Assert.Equal(new[] { "b", "a" }, result.VerifiedSlots);
        Assert.Equal(
            new[]
            {
                "inspect", "prepare", "inspect", "partition", "deploy", "verify-system",
                "write-b", "verify-b", "write-a", "verify-a",
            },
            backend.Calls);
    }

    [Theory]
    [InlineData("serial")]
    [InlineData("model")]
    [InlineData("bootloader-locked")]
    [InlineData("bootloader-unknown")]
    [InlineData("table")]
    [InlineData("package")]
    [InlineData("backup")]
    [InlineData("bases-invalid")]
    [InlineData("maintenance-unvalidated")]
    [InlineData("plan-empty")]
    [InlineData("confirmation-missing")]
    [InlineData("erase-unconfirmed")]
    public async Task PreflightRejectsDriftAndMissingConsent(string mutation)
    {
        var draft = Draft();
        var request = mutation == "confirmation-missing" ? draft : Mutate(Confirmed(draft), mutation);
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.All(backend.Calls, call => Assert.Equal("inspect", call));
    }

    [Fact]
    public async Task TestPackageIsRejectedOnDevice()
    {
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(Request(testPackage: true), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        AssertNoDestructiveCalls(backend);
    }

    [Fact]
    public async Task TestPackageIsAllowedOnSimulation()
    {
        var backend = new FakeBackend(Inputs()) { Target = WorkflowTarget.Simulation };

        var result = await InstallWorkflow.RunAsync(Request(testPackage: true), backend);

        Assert.True(result.Success);
        Assert.Equal(InstallStage.AwaitingBootAcceptance, result.Stage);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("duplicate")]
    [InlineData("unknown")]
    public async Task SlotOrderMustBeTwoDistinctKnownSlots(string kind)
    {
        IReadOnlyList<string> slots = kind switch
        {
            "empty" => Array.Empty<string>(),
            "duplicate" => new[] { "a", "a" },
            _ => new[] { "a", "c" },
        };
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(Request(slots: slots), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        AssertNoDestructiveCalls(backend);
    }

    [Fact]
    public async Task DriftedSnapshotOnFirstInspectFailsPreflight()
    {
        var backend = new FakeBackend(Inputs()) { InspectSnapshot = _ => Inputs() with { Serial = "S2" } };

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Equal(new[] { "inspect" }, backend.Calls);
    }

    [Fact]
    public async Task DriftedSnapshotOnSecondInspectStopsBeforePartition()
    {
        var backend = new FakeBackend(Inputs())
        {
            InspectSnapshot = n => n == 1 ? Inputs() : Inputs() with { TableFingerprint = "table-v2" },
        };

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Equal(new[] { "inspect", "prepare", "inspect" }, backend.Calls);
    }

    [Fact]
    public async Task PrepareFaultFailsAtPrepareBoot()
    {
        var backend = new FakeBackend(Inputs()) { FailOn = "prepare" };

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.PrepareBoot, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.NotNull(result.Error);
        Assert.Equal(new[] { "inspect", "prepare" }, backend.Calls);
    }

    [Theory]
    [InlineData("partition", InstallStage.Partition, "inspect,prepare,inspect")]
    [InlineData("deploy", InstallStage.DeploySystem, "inspect,prepare,inspect,partition")]
    [InlineData("verify-system", InstallStage.VerifySystem, "inspect,prepare,inspect,partition,deploy")]
    [InlineData("write-a", InstallStage.WriteBootA, "inspect,prepare,inspect,partition,deploy,verify-system")]
    [InlineData("verify-a", InstallStage.VerifyBootA, "inspect,prepare,inspect,partition,deploy,verify-system,write-a")]
    [InlineData("write-b", InstallStage.WriteBootB, "inspect,prepare,inspect,partition,deploy,verify-system,write-a,verify-a")]
    [InlineData("verify-b", InstallStage.VerifyBootB, "inspect,prepare,inspect,partition,deploy,verify-system,write-a,verify-a,write-b")]
    public async Task FaultStopsAtFailingStage(string failOn, InstallStage expectedStage, string expectedCalls)
    {
        var backend = new FakeBackend(Inputs()) { FailOn = failOn };

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.False(result.Success);
        Assert.Equal(expectedStage, result.Stage);
        Assert.True(result.AndroidDataMayBeErased);
        Assert.NotNull(result.Error);
        // FakeBackend records the call before injecting the fault, so the failing call is the
        // last entry; the pre-fault fixtures only list what ran before it.
        Assert.Equal(expectedCalls + "," + failOn, string.Join(",", backend.Calls));
        Assert.DoesNotContain(failOn switch { "verify-a" => "a", "verify-b" => "b", _ => "\u0000" }, result.VerifiedSlots);
        if (failOn == "verify-b")
        {
            Assert.Equal(new[] { "a" }, result.VerifiedSlots);
        }
    }

    [Fact]
    public async Task PreCanceledRunThrowsBeforeTouchingBackend()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var backend = new FakeBackend(Inputs());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => InstallWorkflow.RunAsync(Request(), backend, cancellationToken: cts.Token));

        Assert.Empty(backend.Calls);
    }

    [Theory]
    [InlineData("prepare")]
    [InlineData("inspect")]
    public async Task CancellationBetweenPhasesThrowsBeforePartition(string point)
    {
        using var cts = new CancellationTokenSource();
        var backend = new FakeBackend(Inputs());
        backend.Hook = call =>
        {
            if (point == "prepare" && call == "prepare") cts.Cancel();
            if (point == "inspect" && call == "inspect" && backend.Inspects == 2) cts.Cancel();
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => InstallWorkflow.RunAsync(Request(), backend, cancellationToken: cts.Token));

        AssertNoDestructiveCalls(backend);
    }

    [Fact]
    public async Task CancellationInsidePartitionNeverInterruptsDestructiveCalls()
    {
        using var cts = new CancellationTokenSource();
        var backend = new FakeBackend(Inputs());
        backend.Hook = call =>
        {
            if (call == "partition") cts.Cancel();
        };

        var result = await InstallWorkflow.RunAsync(Request(), backend, cancellationToken: cts.Token);

        Assert.True(result.Success);
        Assert.Equal(InstallStage.AwaitingBootAcceptance, result.Stage);
        Assert.Equal(new[] { "a", "b" }, result.VerifiedSlots);
        var calls = backend.Calls.ToList();
        var entered = calls.IndexOf("partition");
        Assert.True(entered >= 0);
        foreach (var call in calls.Skip(entered))
        {
            Assert.False(backend.TokenFor(call).CanBeCanceled, $"{call} received a cancelable token");
        }
    }

    [Fact]
    public void ConfirmationBindsEveryPinnedFieldButItself()
    {
        var baseline = Draft();
        var digest = InstallWorkflow.ConfirmationFor(baseline);

        Assert.Equal(digest, InstallWorkflow.ConfirmationFor(baseline with { ConfirmationId = "chosen-id" }));

        var variants = new[]
        {
            baseline with { Inputs = baseline.Inputs with { Serial = "S2" } },
            baseline with { Inputs = baseline.Inputs with { Model = "OTHER" } },
            baseline with { Inputs = baseline.Inputs with { BootloaderState = BootloaderState.Locked } },
            baseline with { Inputs = baseline.Inputs with { TableFingerprint = "table-v2" } },
            baseline with { Inputs = baseline.Inputs with { PackageFingerprint = "pkg-v2" } },
            baseline with { Inputs = baseline.Inputs with { BackupFingerprint = "backup-ab-v2" } },
            baseline with { Inputs = baseline.Inputs with { BothSlotBasesValid = false } },
            baseline with { Inputs = baseline.Inputs with { MaintenanceValidated = false } },
            baseline with { PlanFingerprint = "plan-v2" },
            baseline with { UserDataEraseConfirmed = false },
            baseline with { TestPackage = true },
            baseline with { SlotOrder = new[] { "b", "a" } },
            baseline with { SlotOrder = new[] { "a" } },
        };

        foreach (var variant in variants)
        {
            Assert.NotEqual(digest, InstallWorkflow.ConfirmationFor(variant));
        }
    }

    [Fact]
    public async Task ChangedCurrentBootFingerprintAfterPrepareStopsBeforePartition()
    {
        // The first inspection still matches the confirmed inputs; the boot state read after
        // preparation differs, which must invalidate the confirmation before anything is destroyed.
        var backend = new FakeBackend(Inputs())
        {
            InspectSnapshot = n => n == 1 ? Inputs() : Inputs() with { CurrentBootFingerprint = "changed" },
        };

        var result = await InstallWorkflow.RunAsync(Request(), backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Equal(new[] { "inspect", "prepare", "inspect" }, backend.Calls);
        Assert.DoesNotContain("partition", backend.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task MissingCurrentBootFingerprintIsRejectedInPreflight(string currentBoot)
    {
        // Confirmed over the empty value on purpose: the confirmation digest matches, so the only
        // reason to reject is the missing current-device boot evidence itself.
        var request = Confirmed(Draft() with { Inputs = Inputs() with { CurrentBootFingerprint = currentBoot } });
        var backend = new FakeBackend(Inputs());

        var result = await InstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(InstallStage.Preflight, result.Stage);
        Assert.False(result.AndroidDataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public void ConfirmationBindsCurrentBootFingerprint()
    {
        var baseline = Draft();
        var digest = InstallWorkflow.ConfirmationFor(baseline);

        Assert.NotEqual(
            digest,
            InstallWorkflow.ConfirmationFor(baseline with { Inputs = baseline.Inputs with { CurrentBootFingerprint = "current-boot-a-b-v2" } }));
        Assert.NotEqual(
            digest,
            InstallWorkflow.ConfirmationFor(baseline with { Inputs = baseline.Inputs with { CurrentBootFingerprint = "" } }));
    }

    private static InstallRequest Mutate(InstallRequest request, string mutation) => mutation switch
    {
        "serial" => request with { Inputs = request.Inputs with { Serial = "S2" } },
        "model" => request with { Inputs = request.Inputs with { Model = "OTHER" } },
        "bootloader-locked" => request with { Inputs = request.Inputs with { BootloaderState = BootloaderState.Locked } },
        "bootloader-unknown" => request with { Inputs = request.Inputs with { BootloaderState = BootloaderState.Unknown } },
        "table" => request with { Inputs = request.Inputs with { TableFingerprint = "table-v2" } },
        "package" => request with { Inputs = request.Inputs with { PackageFingerprint = "pkg-v2" } },
        "backup" => request with { Inputs = request.Inputs with { BackupFingerprint = "backup-ab-v2" } },
        "bases-invalid" => request with { Inputs = request.Inputs with { BothSlotBasesValid = false } },
        "maintenance-unvalidated" => request with { Inputs = request.Inputs with { MaintenanceValidated = false } },
        "plan-empty" => request with { PlanFingerprint = "" },
        "erase-unconfirmed" => request with { UserDataEraseConfirmed = false },
        _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "unknown mutation"),
    };
}

internal sealed class FakeBackend : IInstallBackend
{
    private readonly List<string> _calls = new();
    private readonly Dictionary<string, CancellationToken> _tokens = new();

    public FakeBackend(WorkflowInputs snapshot) => Snapshot = snapshot;

    public WorkflowTarget Target { get; set; } = WorkflowTarget.Device;

    public WorkflowInputs Snapshot { get; set; }

    /// <summary>Returns the snapshot observed by the n-th (1-based) inspection.</summary>
    public Func<int, WorkflowInputs>? InspectSnapshot { get; set; }

    /// <summary>Call name that should raise a backend fault.</summary>
    public string? FailOn { get; set; }

    /// <summary>Invoked after a call is recorded, e.g. to cancel an external token source.</summary>
    public Action<string>? Hook { get; set; }

    public IReadOnlyList<string> Calls => _calls;

    public int Inspects { get; private set; }

    public CancellationToken TokenFor(string call) => _tokens[call];

    public Task<WorkflowInputs> InspectAsync(CancellationToken token)
    {
        Inspects++;
        Step("inspect", token);
        return Task.FromResult(InspectSnapshot?.Invoke(Inspects) ?? Snapshot);
    }

    public Task PrepareBootAsync(CancellationToken token) => Step("prepare", token);

    public Task PartitionAsync(CancellationToken token) => Step("partition", token);

    public Task DeploySystemAsync(CancellationToken token) => Step("deploy", token);

    public Task VerifySystemAsync(CancellationToken token) => Step("verify-system", token);

    public Task WriteBootAsync(string slot, CancellationToken token) => Step($"write-{slot}", token);

    public Task VerifyBootAsync(string slot, CancellationToken token) => Step($"verify-{slot}", token);

    private Task Step(string call, CancellationToken token)
    {
        _calls.Add(call);
        _tokens[call] = token;
        if (FailOn == call) throw new InvalidOperationException($"injected fault at {call}");
        Hook?.Invoke(call);
        return Task.CompletedTask;
    }
}
