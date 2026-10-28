using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural contract for <see cref="UninstallWorkflow"/>. The fake backend records every call in
/// order, can fail at a named call, returns a fixed second inspection, and can cancel the caller's token
/// at defined points, so each test pins the exact call log and the exact reported stage/flags.
/// </summary>
public sealed class UninstallWorkflowTests
{
    private static readonly string[] FullCallOrder =
    {
        "inspect",
        "validate",
        "backup",
        "prepare",
        "inspect",
        "restore:a",
        "verify:a",
        "restore:b",
        "verify:b",
        "reclaim",
        "initialize",
    };

    // ------------------------------------------------------------------- happy path

    [Fact]
    public async Task RunAsync_PerformsFullSequenceThenAwaitsFactoryReset()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot);

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.True(result.DataMayBeErased);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        AssertSequence(FullCallOrder, backend.Calls);
        Assert.DoesNotContain("verifyandroid", backend.Calls);
    }

    // ------------------------------------------------------------------- preflight

    public static TheoryData<string> PreflightRejectionCases => new()
    {
        "serial",
        "model",
        "bootloader-locked",
        "bootloader-unknown",
        "table",
        "currentboot",
        "backup",
        "record",
        "plan",
        "maintenance-false",
        "bases-invalid",
        "ota-unknown",
        "ota-updating",
        "ota-pending",
        "ota-unconfirmed",
        "ota-merging",
        "no-confirmation",
        "wrong-confirmation",
        "refuse-erase",
        "slot-order-duplicate",
        "slot-order-unknown",
        "slot-order-single",
    };

    [Theory]
    [MemberData(nameof(PreflightRejectionCases))]
    public async Task RunAsync_RejectsPreflightWithoutAnyMutation(string scenario)
    {
        var request = RequestFor(scenario);
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot);

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.False(result.DataMayBeErased);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
    }

    // ---------------------------------------------------------------- snapshot drift

    public static TheoryData<string> DriftCases => new()
    {
        "identity",
        "currentboot",
        "table",
        "backup",
        "record",
    };

    [Theory]
    [MemberData(nameof(DriftCases))]
    public async Task RunAsync_StopsBeforeRestoreWhenFirstInspectionDrifts(string scenario)
    {
        var request = Request();
        var live = DriftedSnapshot(scenario);
        var backend = new FakeUninstallBackend(live, live);

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Empty(backend.Mutations);
        AssertSequence(new[] { "inspect" }, backend.Calls);
    }

    [Theory]
    [MemberData(nameof(DriftCases))]
    public async Task RunAsync_StopsBeforeRestoreWhenSecondInspectionDrifts(string scenario)
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, DriftedSnapshot(scenario));

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        AssertSequence(new[] { "inspect", "validate", "backup", "prepare", "inspect" }, backend.Calls);
        AssertNoSlotOrSpaceWork(backend.Calls);
    }

    // -------------------------------------------------------------- injected faults

    // No "verifyandroid" row: the workflow intentionally never calls VerifyAndroidAsync, because the run
    // ends with the factory reset still pending.

    public static TheoryData<string, UninstallStage, string[], bool> FaultCases => new()
    {
        { "validate", UninstallStage.ValidateRestoreInputs, Array.Empty<string>(), false },
        { "backup", UninstallStage.BackupCurrentBoot, Array.Empty<string>(), false },
        { "prepare", UninstallStage.PrepareStockBoot, Array.Empty<string>(), false },
        { "restore:a", UninstallStage.RestoreBootA, Array.Empty<string>(), false },
        { "verify:a", UninstallStage.VerifyBootA, Array.Empty<string>(), false },
        { "restore:b", UninstallStage.RestoreBootB, new[] { "a" }, false },
        { "verify:b", UninstallStage.VerifyBootB, new[] { "a" }, false },
        { "reclaim", UninstallStage.ReclaimAndroidSpace, new[] { "a", "b" }, true },
        { "initialize", UninstallStage.InitializeAndroid, new[] { "a", "b" }, true },
    };

    [Theory]
    [MemberData(nameof(FaultCases))]
    public async Task RunAsync_StopsAtTheFailingStageWithTheExactPrefix(
        string failAt,
        UninstallStage expectedStage,
        string[] expectedVerified,
        bool expectedDataMayBeErased)
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot) { FailAt = failAt };

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(expectedStage, result.Stage);
        Assert.Equal(expectedDataMayBeErased, result.DataMayBeErased);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        AssertSequence(expectedVerified, result.VerifiedSlots);

        var failIndex = Array.IndexOf(FullCallOrder, failAt);
        Assert.True(failIndex >= 0, "fault case must name a recorded call: " + failAt);
        AssertSequence(FullCallOrder.Take(failIndex + 1), backend.Calls);
    }

    [Fact]
    public async Task RunAsync_DoesNotReclaimWhenSlotRestoreOrVerifyFails()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot) { FailAt = "restore:b" };

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.RestoreBootB, result.Stage);
        Assert.DoesNotContain("reclaim", backend.Calls);
        Assert.DoesNotContain("initialize", backend.Calls);
        Assert.DoesNotContain("verifyandroid", backend.Calls);
    }

    // ------------------------------------------------------------------ cancellation

    [Fact]
    public async Task RunAsync_ThrowsWhenTokenAlreadyCancelled()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => UninstallWorkflow.RunAsync(request, backend, null, cts.Token));

        Assert.Empty(backend.Calls);
    }

    [Fact]
    public async Task RunAsync_ThrowsWhenCancelledAfterPrepareAndNeverRestores()
    {
        var request = Request();
        using var cts = new CancellationTokenSource();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot)
        {
            OnPrepareCompleted = cts.Cancel,
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => UninstallWorkflow.RunAsync(request, backend, null, cts.Token));

        Assert.Contains("prepare", backend.Calls);
        AssertNoSlotOrSpaceWork(backend.Calls);
    }

    [Fact]
    public async Task RunAsync_CompletesAfterCancellationDuringFirstRestore()
    {
        var request = Request();
        using var cts = new CancellationTokenSource();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot)
        {
            OnFirstRestore = cts.Cancel,
        };

        var result = await UninstallWorkflow.RunAsync(request, backend, null, cts.Token);

        // The caller token is ignored once restoration has begun, so the run finishes cleanly.
        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.True(result.DataMayBeErased);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        AssertSequence(FullCallOrder, backend.Calls);

        // restore a/b, verify a/b, reclaim and initialize must all be non-cancellable.
        Assert.Equal(6, backend.DestructiveTokens.Count);
        foreach (var token in backend.DestructiveTokens)
        {
            Assert.False(token.CanBeCanceled, "slot/space work must not be cancellable");
        }
    }

    // --------------------------------------------------------------- confirmation digest

    [Fact]
    public void ConfirmationFor_BindsEverythingExceptConfirmationId()
    {
        var request = Request();
        var confirmation = UninstallWorkflow.ConfirmationFor(request);

        Assert.False(string.IsNullOrWhiteSpace(confirmation));

        // Stable and independent of the field it is stored in.
        Assert.Equal(confirmation, UninstallWorkflow.ConfirmationFor(request));
        Assert.Equal(confirmation, UninstallWorkflow.ConfirmationFor(request with { ConfirmationId = "other-value" }));
        Assert.Equal(confirmation, UninstallWorkflow.ConfirmationFor(request with { ConfirmationId = string.Empty }));

        // Bound to plan fingerprint, data-erase consent, slot order and every snapshot field.
        Assert.NotEqual(confirmation, UninstallWorkflow.ConfirmationFor(request with { PlanFingerprint = "plan-2" }));
        Assert.NotEqual(confirmation, UninstallWorkflow.ConfirmationFor(request with { ConfirmDataErase = false }));
        Assert.NotEqual(confirmation, UninstallWorkflow.ConfirmationFor(request with { SlotOrder = new[] { "b", "a" } }));
        Assert.NotEqual(
            confirmation,
            UninstallWorkflow.ConfirmationFor(request with { Snapshot = Snapshot(identity: Identity(serial: "S-OTHER")) }));
        Assert.NotEqual(
            confirmation,
            UninstallWorkflow.ConfirmationFor(request with { Snapshot = Snapshot(table: "table-2") }));
        Assert.NotEqual(
            confirmation,
            UninstallWorkflow.ConfirmationFor(request with { Snapshot = Snapshot(ota: OtaUpdateState.Merging) }));
    }

    // ---------------------------------------------------------------------- helpers

    private static void AssertSequence(IEnumerable<string> expected, IEnumerable<string> actual)
        => Assert.Equal(string.Join("|", expected), string.Join("|", actual));

    private static void AssertNoSlotOrSpaceWork(IReadOnlyList<string> calls)
    {
        foreach (var call in calls)
        {
            Assert.False(call.StartsWith("restore", StringComparison.Ordinal), "unexpected call: " + call);
            Assert.False(call.StartsWith("verify", StringComparison.Ordinal), "unexpected call: " + call);
            Assert.NotEqual("reclaim", call);
            Assert.NotEqual("initialize", call);
        }
    }

    private static DeviceIdentity Identity(
        string serial = "S",
        string model = "TB322FC",
        BootloaderState bootloader = BootloaderState.Unlocked)
        => new(serial, model, bootloader);

    private static UninstallSnapshot Snapshot(
        DeviceIdentity? identity = null,
        string table = "table-1",
        string currentBoot = "current-boot-a-b-v1",
        string stockBackup = "stock-backup-1",
        string installationRecord = "record-1",
        bool maintenanceValidated = true,
        bool bothStockBootsValid = true,
        OtaUpdateState ota = OtaUpdateState.Completed)
        => new(
            identity ?? Identity(),
            table,
            currentBoot,
            stockBackup,
            installationRecord,
            maintenanceValidated,
            bothStockBootsValid,
            ota);

    private static UninstallRequest Request(
        UninstallSnapshot? snapshot = null,
        string plan = "plan-1",
        bool confirmDataErase = true,
        IReadOnlyList<string>? slotOrder = null)
    {
        var draft = new UninstallRequest(
            snapshot ?? Snapshot(),
            plan,
            string.Empty,
            confirmDataErase,
            slotOrder ?? new[] { "a", "b" });

        return draft with { ConfirmationId = UninstallWorkflow.ConfirmationFor(draft) };
    }

    private static UninstallRequest RequestFor(string scenario) => scenario switch
    {
        "serial" => Request(Snapshot(identity: Identity(serial: ""))),
        "model" => Request(Snapshot(identity: Identity(model: "TB999ZZ"))),
        "bootloader-locked" => Request(Snapshot(identity: Identity(bootloader: BootloaderState.Locked))),
        "bootloader-unknown" => Request(Snapshot(identity: Identity(bootloader: BootloaderState.Unknown))),
        "table" => Request(Snapshot(table: string.Empty)),
        "currentboot" => Request(Snapshot(currentBoot: string.Empty)),
        "backup" => Request(Snapshot(stockBackup: string.Empty)),
        "record" => Request(Snapshot(installationRecord: string.Empty)),
        "plan" => Request(plan: string.Empty),
        "maintenance-false" => Request(Snapshot(maintenanceValidated: false)),
        "bases-invalid" => Request(Snapshot(bothStockBootsValid: false)),
        "ota-unknown" => Request(Snapshot(ota: OtaUpdateState.Unknown)),
        "ota-updating" => Request(Snapshot(ota: OtaUpdateState.Updating)),
        "ota-pending" => Request(Snapshot(ota: OtaUpdateState.PendingReboot)),
        "ota-unconfirmed" => Request(Snapshot(ota: OtaUpdateState.UnconfirmedBoot)),
        "ota-merging" => Request(Snapshot(ota: OtaUpdateState.Merging)),
        "no-confirmation" => Request() with { ConfirmationId = string.Empty },
        "wrong-confirmation" => Request() with { ConfirmationId = "tampered" },
        "refuse-erase" => Request(confirmDataErase: false),
        "slot-order-duplicate" => Request(slotOrder: new[] { "a", "a" }),
        "slot-order-unknown" => Request(slotOrder: new[] { "a", "c" }),
        "slot-order-single" => Request(slotOrder: new[] { "a" }),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "unknown preflight scenario"),
    };

    private static UninstallSnapshot DriftedSnapshot(string scenario) => scenario switch
    {
        "identity" => Snapshot(identity: Identity(serial: "S-OTHER")),
        "currentboot" => Snapshot(currentBoot: "current-boot-a-b-v9"),
        "table" => Snapshot(table: "table-2"),
        "backup" => Snapshot(stockBackup: "stock-backup-2"),
        "record" => Snapshot(installationRecord: "record-2"),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "unknown drift scenario"),
    };
}

/// <summary>
/// Records every backend call in order, can fail at a named call, returns a fixed second inspection, and
/// can cancel the caller's token after prepare or during the first restore.
/// </summary>
internal sealed class FakeUninstallBackend : IUninstallBackend
{
    private readonly UninstallSnapshot _firstSnapshot;
    private int _inspectCount;
    private bool _firstRestoreSeen;

    public FakeUninstallBackend(UninstallSnapshot first, UninstallSnapshot second)
    {
        _firstSnapshot = first;
        SecondSnapshot = second;
    }

    /// <summary>Snapshot returned by every inspection after the first one.</summary>
    public UninstallSnapshot SecondSnapshot { get; set; }

    public List<string> Calls { get; } = new();

    /// <summary>Tokens handed to the restore/verify/reclaim/initialize/verify-android calls, in order.</summary>
    public List<CancellationToken> DestructiveTokens { get; } = new();

    /// <summary>Call label ("validate", "restore:a", "verifyandroid", ...) at which the fake throws.</summary>
    public string? FailAt { get; set; }

    public Action? OnPrepareCompleted { get; set; }

    public Action? OnFirstRestore { get; set; }

    /// <summary>Every recorded call that is not an inspection.</summary>
    public IReadOnlyList<string> Mutations => Calls.Where(IsMutation).ToList();

    public Task<UninstallSnapshot> InspectAsync(CancellationToken token)
    {
        Calls.Add("inspect");
        token.ThrowIfCancellationRequested();
        ThrowIfFail("inspect");
        _inspectCount++;
        return Task.FromResult(_inspectCount == 1 ? _firstSnapshot : SecondSnapshot);
    }

    public Task ValidateRestoreInputsAsync(CancellationToken token)
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

    public Task PrepareStockBootAsync(CancellationToken token)
    {
        Calls.Add("prepare");
        token.ThrowIfCancellationRequested();
        ThrowIfFail("prepare");
        OnPrepareCompleted?.Invoke();
        return Task.CompletedTask;
    }

    public Task RestoreBootAsync(string slot, CancellationToken token)
    {
        var call = "restore:" + slot;
        Calls.Add(call);
        DestructiveTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail(call);

        if (!_firstRestoreSeen)
        {
            _firstRestoreSeen = true;
            OnFirstRestore?.Invoke();
        }

        return Task.CompletedTask;
    }

    public Task VerifyBootAsync(string slot, CancellationToken token)
    {
        var call = "verify:" + slot;
        Calls.Add(call);
        DestructiveTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail(call);
        return Task.CompletedTask;
    }

    public Task ReclaimAndroidSpaceAsync(CancellationToken token)
    {
        Calls.Add("reclaim");
        DestructiveTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail("reclaim");
        return Task.CompletedTask;
    }

    public Task InitializeAndroidAsync(CancellationToken token)
    {
        Calls.Add("initialize");
        DestructiveTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail("initialize");
        return Task.CompletedTask;
    }

    public Task VerifyAndroidAsync(CancellationToken token)
    {
        Calls.Add("verifyandroid");
        DestructiveTokens.Add(token);
        token.ThrowIfCancellationRequested();
        ThrowIfFail("verifyandroid");
        return Task.CompletedTask;
    }

    private static bool IsMutation(string call) => !string.Equals(call, "inspect", StringComparison.Ordinal);

    private void ThrowIfFail(string call)
    {
        if (FailAt is not null && string.Equals(FailAt, call, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Injected failure at " + call);
        }
    }
}
