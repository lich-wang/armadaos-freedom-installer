using System;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Transport-contract tests for the primary 9008/EDL uninstall route. They drive the real
/// <see cref="UninstallWorkflow.RunAsync"/> against the existing fake backend, so the call order and
/// every guard are exercised end to end; nothing here fabricates a success result. The EDL acceptance
/// rules (defined non-Unlocked bootloader state, transport-bound confirmation) are the target of the
/// later implementation stage - these rows are expected to be red until then.
/// </summary>
public sealed class UninstallEdlWorkflowTests
{
    [Theory]
    [InlineData(BootloaderState.Unknown)]
    [InlineData(BootloaderState.Locked)]
    public async Task EdlRoute_DefinedNotUnlockedState_RunsCompleteMaintenanceSequence(BootloaderState state)
    {
        var snapshot = Snapshot(state);
        var backend = new FakeUninstallBackend(snapshot, snapshot);

        var result = await UninstallWorkflow.RunAsync(Request(snapshot), backend, cancellationToken: CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.True(result.DataMayBeErased);
        Assert.Equal(new[] { "a", "b" }, result.VerifiedSlots);
        Assert.Equal(
            new[]
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
            },
            backend.Calls);
        Assert.DoesNotContain("verifyandroid", backend.Calls);

        // The device evidence must be reported untouched: no spoofed Unlocked identity.
        Assert.Equal(state, snapshot.Identity.BootloaderState);
        Assert.Equal(UninstallTransportKind.Edl, snapshot.TransportKind);
    }

    [Fact]
    public async Task EdlRoute_UndefinedTransport_IsRejectedInPreflightBeforeAnyBackendCall()
    {
        var snapshot = Snapshot(BootloaderState.Unlocked, (UninstallTransportKind)12345);
        var backend = new FakeUninstallBackend(snapshot, snapshot);

        var result = await UninstallWorkflow.RunAsync(Request(snapshot), backend, cancellationToken: CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.Empty(backend.Calls);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
    }

    [Fact]
    public async Task EdlRoute_UndefinedBootloaderState_IsRejectedInPreflightBeforeAnyBackendCall()
    {
        var snapshot = Snapshot((BootloaderState)12345);
        var backend = new FakeUninstallBackend(snapshot, snapshot);

        var result = await UninstallWorkflow.RunAsync(Request(snapshot), backend, cancellationToken: CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.Empty(backend.Calls);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
    }

    [Fact]
    public void ConfirmationFor_BindsTransportKind()
    {
        var ramMaintenance = Snapshot(BootloaderState.Unlocked, UninstallTransportKind.RamMaintenance);
        var edl = Snapshot(BootloaderState.Unlocked, UninstallTransportKind.Edl);

        var ramConfirmation = UninstallWorkflow.ConfirmationFor(
            new UninstallRequest(ramMaintenance, "plan-edl", "", true, new[] { "a", "b" }));
        var edlConfirmation = UninstallWorkflow.ConfirmationFor(
            new UninstallRequest(edl, "plan-edl", "", true, new[] { "a", "b" }));

        Assert.NotEqual(ramConfirmation, edlConfirmation);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EdlRoute_LiveTransportDrift_IsRejectedInPreflight(bool driftOnFirstInspection)
    {
        var confirmed = Snapshot(BootloaderState.Unlocked, UninstallTransportKind.Edl);
        var drifted = confirmed with { TransportKind = UninstallTransportKind.RamMaintenance };
        var backend = driftOnFirstInspection
            ? new FakeUninstallBackend(drifted, drifted)
            : new FakeUninstallBackend(confirmed, drifted);

        var result = await UninstallWorkflow.RunAsync(Request(confirmed), backend, cancellationToken: CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.Equal(
            driftOnFirstInspection
                ? new[] { "inspect" }
                : new[] { "inspect", "validate", "backup", "prepare", "inspect" },
            backend.Calls);
        Assert.DoesNotContain("restore:a", backend.Calls);
        Assert.DoesNotContain("restore:b", backend.Calls);
        Assert.DoesNotContain("reclaim", backend.Calls);
        Assert.DoesNotContain("initialize", backend.Calls);
        Assert.DoesNotContain("verifyandroid", backend.Calls);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
    }

    [Theory]
    [InlineData("maintenance", "Maintenance mode must be validated.")]
    [InlineData("both-stock-boots", "Both stock boot slots must be valid.")]
    [InlineData("ota", "OTA update must be completed before uninstalling.")]
    [InlineData("table", "Table fingerprint is required.")]
    [InlineData("confirm-erase", "Android user data erase has not been confirmed.")]
    [InlineData("bad-confirmation", "Confirmation id does not match the pinned uninstall request.")]
    public async Task EdlRoute_ExistingCriticalGuardsStillRejectInPreflight(string defect, string expectedError)
    {
        var valid = Snapshot(BootloaderState.Unknown);
        UninstallRequest request;
        switch (defect)
        {
            case "maintenance":
                request = Request(valid with { MaintenanceValidated = false });
                break;
            case "both-stock-boots":
                request = Request(valid with { BothStockBootsValid = false });
                break;
            case "ota":
                request = Request(valid with { OtaState = OtaUpdateState.Unknown });
                break;
            case "table":
                request = Request(valid with { TableFingerprint = "" });
                break;
            case "confirm-erase":
                request = Request(valid, confirmDataErase: false);
                break;
            case "bad-confirmation":
                request = Request(valid) with { ConfirmationId = "tampered" };
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(defect), defect, "unknown guard defect");
        }

        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot);

        var result = await UninstallWorkflow.RunAsync(request, backend, cancellationToken: CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.Preflight, result.Stage);
        Assert.Empty(backend.Calls);
        Assert.False(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Equal(expectedError, result.Error);
    }

    private static UninstallSnapshot Snapshot(
        BootloaderState state,
        UninstallTransportKind transport = UninstallTransportKind.Edl)
        => new UninstallSnapshot(
            new DeviceIdentity("EDL-TEST-0001", "TB322FC", state),
            "table-edl",
            "current-edl",
            "stock-edl",
            "record-edl",
            true,
            true,
            OtaUpdateState.Completed)
        {
            TransportKind = transport,
        };

    private static UninstallRequest Request(UninstallSnapshot snapshot, bool confirmDataErase = true)
    {
        var draft = new UninstallRequest(snapshot, "plan-edl", "", confirmDataErase, new[] { "a", "b" });
        return draft with { ConfirmationId = UninstallWorkflow.ConfirmationFor(draft) };
    }
}
