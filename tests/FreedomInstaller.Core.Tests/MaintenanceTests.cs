using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural contract for <see cref="AndroidMaintenance"/>.
/// The fake backend records every call it receives, so each test asserts the exact call log
/// that must exist at the point of success or failure.
/// </summary>
public sealed class MaintenanceTests
{
    private const string SlotVersions = "a:v1;b:v2";
    private const string SuccessStage = "AwaitingBootAcceptance";
    private const string PreflightStage = "Preflight";

    [Fact]
    public void IMaintenanceBackend_ExposesNoPartitionFormatOrRootfsMembers()
    {
        var members = typeof(IMaintenanceBackend)
            .GetMembers()
            .Where(member => member.MemberType != MemberTypes.Method || !((MethodInfo)member).IsSpecialName)
            .Select(member => member.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        AssertSequence(
            new[]
            {
                "BackupCurrentBootAsync",
                "InspectAsync",
                "PrepareAsync",
                "Target",
                "ValidateStockInputsAsync",
                "VerifyBootAsync",
                "WriteBootAsync",
            },
            members);

        foreach (var member in members)
        {
            Assert.False(member.Contains("Partition", StringComparison.OrdinalIgnoreCase), "unexpected member: " + member);
            Assert.False(member.Contains("Format", StringComparison.OrdinalIgnoreCase), "unexpected member: " + member);
            Assert.False(member.Contains("RootFs", StringComparison.OrdinalIgnoreCase), "unexpected member: " + member);
        }
    }

    [Theory]
    [InlineData(MaintenanceMode.BeforeUpdate)]
    [InlineData(MaintenanceMode.AfterUpdate)]
    [InlineData(MaintenanceMode.RestoreStock)]
    public async Task RunAsync_PerformsFullSequenceForEveryMode(MaintenanceMode mode)
    {
        var request = Request(mode);
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(SuccessStage, result.Stage);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        AssertSequence(
            new[]
            {
                "inspect",
                "validate",
                "backup",
                "prepare:" + mode,
                "inspect",
                "write:a",
                "verify:a",
                "write:b",
                "verify:b",
            },
            backend.Calls);
    }

    [Theory]
    [InlineData(OtaUpdateState.Unknown)]
    [InlineData(OtaUpdateState.Updating)]
    [InlineData(OtaUpdateState.PendingReboot)]
    [InlineData(OtaUpdateState.UnconfirmedBoot)]
    [InlineData(OtaUpdateState.Merging)]
    public async Task RunAsync_RejectsOtaStatesThatAreNotCompleted(OtaUpdateState ota)
    {
        var snapshot = Snapshot(ota: ota);
        var request = Request(snapshot: snapshot);
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, snapshot, snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    public static TheoryData<string> LiveInputDriftCases => new()
    {
        "serial",
        "model",
        "bootloader-locked",
        "bootloader-unknown",
        "table",
        "package",
        "backup",
        "bases-invalid",
        "maintenance-false",
    };

    [Theory]
    [MemberData(nameof(LiveInputDriftCases))]
    public async Task RunAsync_FailsPreflightWhenLiveInputsDifferFromRequest(string scenario)
    {
        var request = Request();
        var live = Snapshot(inputs: DriftedInputs(scenario));
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, live, live);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    [Fact]
    public async Task RunAsync_FailsPreflightWhenSlotVersionsDrift()
    {
        var request = Request();
        var live = Snapshot(slotVersions: "a:v9;b:v9");
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, live, live);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    [Fact]
    public async Task RunAsync_FailsPreflightWhenConfirmationDoesNotMatch()
    {
        var request = Request() with { ConfirmationId = "not-the-expected-confirmation" };
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    [Fact]
    public async Task RunAsync_FailsPreflightForTestPackageOnDevice()
    {
        var request = Request(testPackage: true);
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Device, request.Snapshot, request.Snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    [Fact]
    public async Task RunAsync_AllowsTestPackageOnSimulation()
    {
        var request = Request(testPackage: true);
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.True(result.Success);
        Assert.Equal(SuccessStage, result.Stage);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        AssertSequence(
            new[]
            {
                "inspect",
                "validate",
                "backup",
                "prepare:BeforeUpdate",
                "inspect",
                "write:a",
                "verify:a",
                "write:b",
                "verify:b",
            },
            backend.Calls);
    }

    [Theory]
    [InlineData("slotversions")]
    [InlineData("ota")]
    [InlineData("table")]
    public async Task RunAsync_FailsPreflightWhenPostPrepareInspectionDrifts(string scenario)
    {
        var request = Request();
        var second = scenario switch
        {
            "slotversions" => Snapshot(slotVersions: "a:v2;b:v3"),
            "ota" => Snapshot(ota: OtaUpdateState.UnconfirmedBoot),
            "table" => Snapshot(inputs: Inputs(table: "table-2")),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, second);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        AssertSequence(
            new[] { "inspect", "validate", "backup", "prepare:BeforeUpdate", "inspect" },
            backend.Calls);
    }

    [Fact]
    public async Task RunAsync_StopsWhenStockValidationFails()
    {
        var request = Request();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot)
        {
            FailAt = "validate",
        };

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal("ValidateStockInputs", result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        AssertSequence(new[] { "inspect", "validate" }, backend.Calls);
    }

    [Fact]
    public async Task RunAsync_StopsWhenBackupFails()
    {
        var request = Request();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot)
        {
            FailAt = "backup",
        };

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal("BackupCurrentBoot", result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        AssertSequence(new[] { "inspect", "validate", "backup" }, backend.Calls);
    }

    public static TheoryData<string, string, string[]> SlotFailureCases => new()
    {
        { "write:a", "WriteBootA", Array.Empty<string>() },
        { "verify:a", "VerifyBootA", Array.Empty<string>() },
        { "write:b", "WriteBootB", new[] { "a" } },
        { "verify:b", "VerifyBootB", new[] { "a" } },
    };

    [Theory]
    [MemberData(nameof(SlotFailureCases))]
    public async Task RunAsync_StopsAtFirstSlotFailureWithoutTouchingLaterSlots(
        string failAt,
        string expectedStage,
        string[] expectedVerifiedSlots)
    {
        var request = Request();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot)
        {
            FailAt = failAt,
        };

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(expectedStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        AssertSequence(expectedVerifiedSlots, result.VerifiedSlots);

        // The log is the read-only prefix plus every slot call up to and including the injected
        // failure: earlier slots completed before the failure, so their write/verify must be present,
        // and no call after the failure may appear.
        var slotCalls = new[] { "write:a", "verify:a", "write:b", "verify:b" };
        var failIndex = Array.IndexOf(slotCalls, failAt);
        Assert.True(failIndex >= 0, "slot failure case must name a write/verify call: " + failAt);

        var expectedCalls = new[]
        {
            "inspect",
            "validate",
            "backup",
            "prepare:BeforeUpdate",
            "inspect",
        }.Concat(slotCalls.Take(failIndex + 1));

        AssertSequence(expectedCalls, backend.Calls);
    }

    [Fact]
    public async Task RunAsync_ThrowsWhenTokenAlreadyCancelled()
    {
        var request = Request();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AndroidMaintenance.RunAsync(request, backend, cts.Token));

        Assert.Empty(backend.Calls);
    }

    [Fact]
    public async Task RunAsync_ThrowsWhenCancelledAfterPrepare()
    {
        var request = Request();
        using var cts = new CancellationTokenSource();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot)
        {
            OnPrepareCompleted = cts.Cancel,
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AndroidMaintenance.RunAsync(request, backend, cts.Token));

        AssertSequence(
            new[] { "inspect", "validate", "backup", "prepare:BeforeUpdate" },
            backend.Calls);
    }

    [Fact]
    public async Task RunAsync_CompletesBothSlotsWhenCancelledDuringFirstSlotWrites()
    {
        var request = Request();
        using var cts = new CancellationTokenSource();
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot)
        {
            OnFirstWrite = cts.Cancel,
        };

        var result = await AndroidMaintenance.RunAsync(request, backend, cts.Token);

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(SuccessStage, result.Stage);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        AssertSequence(
            new[]
            {
                "inspect",
                "validate",
                "backup",
                "prepare:BeforeUpdate",
                "inspect",
                "write:a",
                "verify:a",
                "write:b",
                "verify:b",
            },
            backend.Calls);

        Assert.Equal(4, backend.SlotTokens.Count);
        foreach (var token in backend.SlotTokens)
        {
            Assert.False(token.CanBeCanceled, "slot write/verify must not be cancellable");
        }
    }

    [Fact]
    public void ConfirmationFor_BindsEverythingExceptConfirmationId()
    {
        var request = Request();
        var confirmation = AndroidMaintenance.ConfirmationFor(request);

        Assert.False(string.IsNullOrWhiteSpace(confirmation));

        // Stable across repeated evaluation and independent of the field it is stored in.
        Assert.Equal(confirmation, AndroidMaintenance.ConfirmationFor(request));
        Assert.Equal(confirmation, AndroidMaintenance.ConfirmationFor(request with { ConfirmationId = "other-value" }));
        Assert.Equal(confirmation, AndroidMaintenance.ConfirmationFor(request with { ConfirmationId = string.Empty }));

        // Bound to mode, test flag, slot order, slot versions and OTA state.
        Assert.NotEqual(confirmation, AndroidMaintenance.ConfirmationFor(request with { Mode = MaintenanceMode.AfterUpdate }));
        Assert.NotEqual(confirmation, AndroidMaintenance.ConfirmationFor(request with { Mode = MaintenanceMode.RestoreStock }));
        Assert.NotEqual(confirmation, AndroidMaintenance.ConfirmationFor(request with { TestPackage = true }));
        Assert.NotEqual(confirmation, AndroidMaintenance.ConfirmationFor(request with { SlotOrder = new[] { "b", "a" } }));
        Assert.NotEqual(
            confirmation,
            AndroidMaintenance.ConfirmationFor(
                request with { Snapshot = request.Snapshot with { SlotVersionsFingerprint = "a:v9;b:v9" } }));
        Assert.NotEqual(
            confirmation,
            AndroidMaintenance.ConfirmationFor(
                request with { Snapshot = request.Snapshot with { OtaState = OtaUpdateState.Merging } }));
    }

    [Fact]
    public async Task RunAsync_FailsPreflightWhenCurrentBootFingerprintDrifts()
    {
        var request = Request();
        var live = Snapshot(inputs: Inputs(currentBoot: "current-boot-a-b-v2"));
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, live, live);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    [Fact]
    public async Task RunAsync_FailsPreflightWhenCurrentBootFingerprintChangesAfterPrepare()
    {
        var request = Request();
        var second = Snapshot(inputs: Inputs(currentBoot: "current-boot-a-b-v2"));
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, second);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        AssertSequence(
            new[] { "inspect", "validate", "backup", "prepare:BeforeUpdate", "inspect" },
            backend.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task RunAsync_RejectsMissingCurrentBootFingerprint(string currentBoot)
    {
        // Confirmed over the missing value, so the confirmation id still matches and the only
        // rejection reason left is the absent current-device boot evidence.
        var request = Request(snapshot: Snapshot(inputs: Inputs(currentBoot: currentBoot)));
        var backend = new FakeMaintenanceBackend(WorkflowTarget.Simulation, request.Snapshot, request.Snapshot);

        var result = await AndroidMaintenance.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(PreflightStage, result.Stage);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public void ConfirmationFor_BindsCurrentBootFingerprint()
    {
        var request = Request();
        var confirmation = AndroidMaintenance.ConfirmationFor(request);

        Assert.NotEqual(
            confirmation,
            AndroidMaintenance.ConfirmationFor(
                request with { Snapshot = request.Snapshot with { Inputs = Inputs(currentBoot: "current-boot-a-b-v2") } }));
        Assert.NotEqual(
            confirmation,
            AndroidMaintenance.ConfirmationFor(
                request with { Snapshot = request.Snapshot with { Inputs = Inputs(currentBoot: string.Empty) } }));
    }

    private static void AssertSequence(IEnumerable<string> expected, IEnumerable<string> actual)
        => Assert.Equal(string.Join("|", expected), string.Join("|", actual));

    private static WorkflowInputs Inputs(
        string serial = "S",
        string model = "TB322FC",
        BootloaderState bootloader = BootloaderState.Unlocked,
        string table = "table-1",
        string package = "package-1",
        string backup = "backup-1",
        bool bothSlotBasesValid = true,
        bool maintenanceValidated = true,
        string currentBoot = "current-boot-a-b-v1")
        => new(serial, model, bootloader, table, package, backup, bothSlotBasesValid, maintenanceValidated, currentBoot);

    private static MaintenanceSnapshot Snapshot(
        WorkflowInputs? inputs = null,
        OtaUpdateState ota = OtaUpdateState.Completed,
        string slotVersions = SlotVersions)
        => new(inputs ?? Inputs(), ota, slotVersions);

    private static MaintenanceRequest Request(
        MaintenanceMode mode = MaintenanceMode.BeforeUpdate,
        MaintenanceSnapshot? snapshot = null,
        bool testPackage = false,
        IReadOnlyList<string>? slotOrder = null)
    {
        var draft = new MaintenanceRequest(
            mode,
            snapshot ?? Snapshot(),
            string.Empty,
            testPackage,
            slotOrder ?? new[] { "a", "b" });

        return draft with { ConfirmationId = AndroidMaintenance.ConfirmationFor(draft) };
    }

    private static WorkflowInputs DriftedInputs(string scenario) => scenario switch
    {
        "serial" => Inputs(serial: "S-OTHER"),
        "model" => Inputs(model: "TB322FC-OTHER"),
        "bootloader-locked" => Inputs(bootloader: BootloaderState.Locked),
        "bootloader-unknown" => Inputs(bootloader: BootloaderState.Unknown),
        "table" => Inputs(table: "table-2"),
        "package" => Inputs(package: "package-2"),
        "backup" => Inputs(backup: "backup-2"),
        "bases-invalid" => Inputs(bothSlotBasesValid: false),
        "maintenance-false" => Inputs(maintenanceValidated: false),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "unknown drift scenario"),
    };
}

/// <summary>
/// Records every backend call in order, can fail at a named call, returns a mutable second snapshot
/// for the post-prepare inspection, and can cancel the caller's token at defined points.
/// </summary>
internal sealed class FakeMaintenanceBackend : IMaintenanceBackend
{
    private readonly MaintenanceSnapshot _firstSnapshot;
    private int _inspectCount;
    private bool _firstWriteSeen;

    public FakeMaintenanceBackend(WorkflowTarget target, MaintenanceSnapshot first, MaintenanceSnapshot second)
    {
        Target = target;
        _firstSnapshot = first;
        SecondSnapshot = second;
    }

    public WorkflowTarget Target { get; }

    /// <summary>Snapshot returned by every inspection after the first one.</summary>
    public MaintenanceSnapshot SecondSnapshot { get; set; }

    public List<string> Calls { get; } = new();

    /// <summary>Tokens handed to WriteBootAsync/VerifyBootAsync, in call order.</summary>
    public List<CancellationToken> SlotTokens { get; } = new();

    /// <summary>Call label ("validate", "backup", "write:a", ...) at which the fake throws.</summary>
    public string? FailAt { get; set; }

    public Action? OnPrepareCompleted { get; set; }

    public Action? OnFirstWrite { get; set; }

    /// <summary>Every recorded call that is not an inspection.</summary>
    public IReadOnlyList<string> Mutations => Calls.Where(call => !IsInspect(call)).ToList();

    public Task<MaintenanceSnapshot> InspectAsync(CancellationToken token)
    {
        Calls.Add("inspect");
        token.ThrowIfCancellationRequested();
        ThrowIfFail("inspect");
        _inspectCount++;
        return Task.FromResult(_inspectCount == 1 ? _firstSnapshot : SecondSnapshot);
    }

    public Task ValidateStockInputsAsync(CancellationToken token)
    {
        Calls.Add("validate");
        token.ThrowIfCancellationRequested();
        ThrowIfFail("validate");
        return Task.CompletedTask;
    }

    public Task BackupCurrentBootAsync(CancellationToken token)
    {
        Calls.Add("backup");
        token.ThrowIfCancellationRequested();
        ThrowIfFail("backup");
        return Task.CompletedTask;
    }

    public Task PrepareAsync(MaintenanceMode mode, CancellationToken token)
    {
        var call = "prepare:" + mode;
        Calls.Add(call);
        token.ThrowIfCancellationRequested();
        ThrowIfFail(call);
        OnPrepareCompleted?.Invoke();
        return Task.CompletedTask;
    }

    public Task WriteBootAsync(string slot, CancellationToken token)
    {
        var call = "write:" + slot;
        Calls.Add(call);
        SlotTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail(call);

        if (!_firstWriteSeen)
        {
            _firstWriteSeen = true;
            OnFirstWrite?.Invoke();
        }

        return Task.CompletedTask;
    }

    public Task VerifyBootAsync(string slot, CancellationToken token)
    {
        var call = "verify:" + slot;
        Calls.Add(call);
        SlotTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail(call);
        return Task.CompletedTask;
    }

    private static bool IsInspect(string call) => string.Equals(call, "inspect", StringComparison.Ordinal);

    private void ThrowIfFail(string call)
    {
        if (FailAt is not null && string.Equals(FailAt, call, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Injected failure at " + call);
        }
    }
}
