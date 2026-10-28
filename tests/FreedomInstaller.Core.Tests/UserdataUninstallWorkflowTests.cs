using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// C001 workflow red tests for the frozen userdata-only contract. They use only a minimal
/// in-memory <see cref="IUserdataUninstallBackend"/>: no device, no client, no file system.
/// ConfirmationFor and RunAsync are still NotImplementedException stubs, so these tests are
/// expected to fail RED for missing behavior; a NotImplementedException is never accepted as
/// a business rejection.
/// </summary>
public sealed class UserdataUninstallWorkflowTests
{
    private const string TableFingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string MiscFingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string InstallationFingerprint = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string PlanFingerprint = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    [Fact]
    public async Task Workflow_UsesExactCallOrder_AndReportsNoVerifiedSlots()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);

        UninstallResult result = await RunAsync(request, backend, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains("AwaitingFactoryReset", result.Stage.ToString());
        Assert.True(result.DataMayBeErased);
        Assert.Empty(result.VerifiedSlots);
        Assert.Equal(new[] { "Inspect", "Validate", "Inspect", "Reclaim", "Initialize" }, backend.Calls);
        Assert.All(backend.Tokens, token => Assert.Equal(CancellationToken.None, token));
    }

    [Fact]
    public async Task Preflight_RejectsMissingConsent_BeforeAnyBackendCall()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        var backend = new FakeUserdataBackend(snapshot);
        var request = new UserdataUninstallRequest(snapshot, PlanFingerprint, "confirmation", false);

        UninstallResult result = await RunAsync(request, backend, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("Preflight", result.Stage.ToString());
        Assert.NotNull(result.Error);
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public async Task Preflight_RejectsChangedSecondSnapshot_WithoutReclaim()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        UserdataUninstallSnapshot changed = NewSnapshot(miscFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        var backend = new FakeUserdataBackend(snapshot);
        backend.Inspections.Enqueue(snapshot);
        backend.Inspections.Enqueue(changed);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);

        UninstallResult result = await RunAsync(request, backend, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("Preflight", result.Stage.ToString());
        Assert.NotNull(result.Error);
        Assert.Equal(new[] { "Inspect", "Validate", "Inspect" }, backend.Calls);
        Assert.DoesNotContain("Reclaim", backend.Calls);
    }

    [Fact]
    public async Task Preflight_HonorsPreCanceledToken_WithoutAnyWrite()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RunAsync(request, backend, cancelled.Token));

        Assert.DoesNotContain("Reclaim", backend.Calls);
        Assert.DoesNotContain("Initialize", backend.Calls);
    }

    [Fact]
    public async Task Validate_Cancellation_StopsBeforeReclaim()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);
        using var cancelled = new CancellationTokenSource();
        backend.OnValidate = cancelled.Cancel;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RunAsync(request, backend, cancelled.Token));

        Assert.DoesNotContain("Reclaim", backend.Calls);
        Assert.DoesNotContain("Initialize", backend.Calls);
    }

    [Fact]
    public async Task Reclaim_Cancellation_IsIgnoredAndInitializeUsesNone()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot();
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);
        using var cancelled = new CancellationTokenSource();
        backend.OnReclaim = cancelled.Cancel;

        UninstallResult result = await RunAsync(request, backend, cancelled.Token);

        Assert.True(result.Success);
        Assert.Contains("AwaitingFactoryReset", result.Stage.ToString());
        Assert.True(result.DataMayBeErased);
        Assert.Equal("Initialize", backend.Calls.Last());
        Assert.Equal(CancellationToken.None, backend.Tokens.Last());
    }

    [Theory]
    [InlineData(BootloaderState.Unknown)]
    [InlineData(BootloaderState.Locked)]
    public async Task Preflight_AllowsDefinedBootloaderStates(BootloaderState state)
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot(bootloaderState: state);
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);

        UninstallResult result = await RunAsync(request, backend, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains(state.ToString(), backend.Snapshot.Identity.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Preflight_RejectsUndefinedBootloaderState_BeforeAnyCall()
    {
        UserdataUninstallSnapshot snapshot = NewSnapshot(bootloaderState: (BootloaderState)999);
        var backend = new FakeUserdataBackend(snapshot);
        UserdataUninstallRequest request = NewConfirmedRequest(snapshot);

        UninstallResult result = await RunAsync(request, backend, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("Preflight", result.Stage.ToString());
        Assert.NotNull(result.Error);
        Assert.Empty(backend.Calls);
    }

    private static Task<UninstallResult> RunAsync(
        UserdataUninstallRequest request,
        IUserdataUninstallBackend backend,
        CancellationToken token) =>
        UninstallWorkflow.RunAsync(request, backend, progress: null, cancellationToken: token);

    private static UserdataUninstallRequest NewConfirmedRequest(UserdataUninstallSnapshot snapshot)
    {
        var request = new UserdataUninstallRequest(snapshot, PlanFingerprint, string.Empty, true);
        return request with { ConfirmationId = UninstallWorkflow.ConfirmationFor(request) };
    }

    private static UserdataUninstallSnapshot NewSnapshot(
        string tableFingerprint = TableFingerprint,
        string miscFingerprint = MiscFingerprint,
        string installationFingerprint = InstallationFingerprint,
        bool maintenanceValidated = true,
        BootloaderState bootloaderState = BootloaderState.Unlocked)
    {
        var identity = new DeviceIdentity("C001R0001", "TB322FC", bootloaderState);
        return new UserdataUninstallSnapshot(
            identity,
            tableFingerprint,
            miscFingerprint,
            installationFingerprint,
            maintenanceValidated,
            OtaUpdateState.Completed);
    }
}

/// <summary>
/// Minimal in-memory backend: four operations, a mutable snapshot stream and a call trace.
/// It never touches a device, a file or a process.
/// </summary>
internal sealed class FakeUserdataBackend : IUserdataUninstallBackend
{
    public FakeUserdataBackend(UserdataUninstallSnapshot snapshot)
    {
        Snapshot = snapshot;
    }

    public UserdataUninstallSnapshot Snapshot { get; }

    public Queue<UserdataUninstallSnapshot> Inspections { get; } = new();
    public List<string> Calls { get; } = new();
    public List<CancellationToken> Tokens { get; } = new();
    public Action? OnValidate { get; set; }
    public Action? OnReclaim { get; set; }

    public Task<UserdataUninstallSnapshot> InspectAsync(CancellationToken token = default)
    {
        Calls.Add("Inspect");
        Tokens.Add(token);
        token.ThrowIfCancellationRequested();
        return Task.FromResult(Inspections.Count > 0 ? Inspections.Dequeue() : Snapshot);
    }

    public Task ValidateRestoreInputsAsync(CancellationToken token = default)
    {
        Calls.Add("Validate");
        Tokens.Add(token);
        token.ThrowIfCancellationRequested();
        OnValidate?.Invoke();
        token.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task ReclaimAndroidSpaceAsync(CancellationToken token = default)
    {
        Calls.Add("Reclaim");
        Tokens.Add(token);
        token.ThrowIfCancellationRequested();
        OnReclaim?.Invoke();
        return Task.CompletedTask;
    }

    public Task InitializeAndroidAsync(CancellationToken token = default)
    {
        Calls.Add("Initialize");
        Tokens.Add(token);
        token.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}
