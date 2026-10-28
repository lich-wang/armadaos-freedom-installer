using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Pending factory-reset contract. A queued Recovery reset is never Android acceptance: the workflow
/// must stop at <see cref="UninstallStage.AwaitingFactoryReset"/>, must never ask the device adapter to
/// verify a booted Android, and must keep reporting a failing initialise as
/// <see cref="UninstallStage.InitializeAndroid"/>. The call log is pinned through "initialize", so any
/// extra backend call after it - in particular "verifyandroid" - fails the test.
/// </summary>
public sealed class UninstallWorkflowPendingTests
{
    private static readonly string[] CallsThroughInitialize =
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

    [Fact]
    public async Task RunAsync_EndsAtAwaitingFactoryResetWithoutVerifyingAndroid()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot);

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.True(result.DataMayBeErased);
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);

        // The reset is only queued for Recovery: there is no booted Android that could be verified.
        Assert.DoesNotContain("verifyandroid", backend.Calls);
        AssertSequence(CallsThroughInitialize, backend.Calls);
    }

    [Fact]
    public async Task RunAsync_NeverCallsAVerifyAndroidThatWouldThrow()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot) { FailAt = "verifyandroid" };

        var result = await UninstallWorkflow.RunAsync(request, backend);

        // The fake throws whenever "verifyandroid" is reached, so a clean result proves the call is gone.
        Assert.DoesNotContain("verifyandroid", backend.Calls);
        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.True(result.DataMayBeErased);
    }

    [Fact]
    public async Task RunAsync_InitializeFailureStaysInitializeAndroidWithBothSlotsVerified()
    {
        var request = Request();
        var backend = new FakeUninstallBackend(request.Snapshot, request.Snapshot) { FailAt = "initialize" };

        var result = await UninstallWorkflow.RunAsync(request, backend);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.InitializeAndroid, result.Stage);
        Assert.True(result.DataMayBeErased);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        AssertSequence(new[] { "a", "b" }, result.VerifiedSlots);
        Assert.DoesNotContain("verifyandroid", backend.Calls);
    }

    private static void AssertSequence(IEnumerable<string> expected, IEnumerable<string> actual)
        => Assert.Equal(string.Join("|", expected), string.Join("|", actual));

    private static UninstallRequest Request()
    {
        var draft = new UninstallRequest(
            new UninstallSnapshot(
                new DeviceIdentity("S", "TB322FC", BootloaderState.Unlocked),
                "table-1",
                "current-boot-a-b-v1",
                "stock-backup-1",
                "record-1",
                true,
                true,
                OtaUpdateState.Completed),
            "plan-1",
            string.Empty,
            true,
            new[] { "a", "b" });

        return draft with { ConfirmationId = UninstallWorkflow.ConfirmationFor(draft) };
    }
}
