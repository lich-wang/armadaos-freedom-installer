using System;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

// ---------------------------------------------------------------------------------------------
// F4c.a1 -- test-only. Three refusals the real Locked/OEM preparation must make before it ever
// reports Ready or issues a write. Nothing here fabricates a plan, a prepared set, or a check:
// each case drives DirectInstallReadyTestSession.CreateAsync and only observes the honest failure
// the production route produced (message prefix plus the real native/write/reset counts).
// ---------------------------------------------------------------------------------------------

/// <summary>
/// F4c.a1 -- the GBL eligibility refusals. Each one is a legitimate, already-true input state
/// (a legal legacy backup, a self-consistent but wrong parent/child pair, an unknown region), so a
/// generic "environment not compatible" error is not an acceptable outcome for any of them.
/// </summary>
public sealed class GblDirectEligibilityTests
    : IClassFixture<Gen5EdlToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    /// <summary>The confirmed fastboot lock fact: locked, independent of any bootloader read.</summary>
    private const BootloaderState ConfirmedLocked = BootloaderState.Locked;

    private readonly Gen5EdlToolchainFixture _g5;

    private readonly EdlRawSharedInput _raw;

    public GblDirectEligibilityTests(Gen5EdlToolchainFixture g5, EdlRawSharedInput raw)
    {
        _g5 = g5;
        _raw = raw;
    }

    /// <summary>
    /// A legal 48-file legacy backup on a device whose GPT still carries EFI is not malformed input:
    /// it is a valid old backup, and the direct route must refuse GBL rather than silently drop EFI.
    /// </summary>
    [Fact]
    public async Task LockedOem_RequiresCompleteBackupWithEfisp()
    {
        using GblDirectSourceFixture source = new(region: "PRC");

        await AssertRefusedBeforeReadyAsync(
            source,
            omitEfispBackup: true,
            expectedPrefix: "requires-complete-backup-with-efisp:");
    }

    /// <summary>
    /// The parent RSA verifies on its own, but the parent's boot-child principal is not the one the
    /// child chain allows: only the child itself is a legal signer here, so the pair must be refused.
    /// </summary>
    [Fact]
    public async Task LockedOem_RejectsMismatchedParentBootChild()
    {
        using GblDirectSourceFixture source = new(region: "PRC", mismatchParentBootChild: true);

        await AssertRefusedBeforeReadyAsync(
            source,
            omitEfispBackup: false,
            expectedPrefix: "gbl-boot-chain-key-mismatch:");
    }

    /// <summary>
    /// An unknown region is unknown: the fixture builds a structurally complete FDT that simply says
    /// "UNK", so the refusal must come from the region check and not from a default of PRC, a locale,
    /// or any firmware inference.
    /// </summary>
    [Fact]
    public async Task LockedOem_RejectsUnknownSourceRegion()
    {
        using GblDirectSourceFixture source = new(region: "UNK");

        await AssertRefusedBeforeReadyAsync(
            source,
            omitEfispBackup: false,
            expectedPrefix: "gbl-runtime-region-unknown:");
    }

    // -----------------------------------------------------------------------------------------
    // Shared refusal shape
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// Runs the real factory once and proves it refused: a specific InvalidOperationException carrying
    /// the expected prefix, observed through the real callback, before any write or reset; the native
    /// count is deliberately not constrained. A session that unexpectedly becomes Ready is disposed
    /// and never accepted.
    /// </summary>
    private async Task AssertRefusedBeforeReadyAsync(
        GblDirectSourceFixture source,
        bool omitEfispBackup,
        string expectedPrefix)
    {
        DirectInstallReadyTestSession? session = null;
        (int native, int writes, int resets)? counts = null;

        Exception? error;
        try
        {
            error = await Record.ExceptionAsync(async () =>
            {
                session = await DirectInstallReadyTestSession.CreateAsync(
                    _g5.Toolchain,
                    _raw,
                    avbSourceKind: DirectAvbSourceKind.Oem,
                    observedFastbootLockState: ConfirmedLocked,
                    gblSources: source,
                    omitEfispBackup: omitEfispBackup,
                    onPreparationFailure: (native, writes, resets) => counts = (native, writes, resets));
            });
        }
        finally
        {
            session?.Dispose();
        }

        // A null error means the factory reported Ready for this input: that is the defect, not a pass.
        Assert.NotNull(error);
        Assert.True(error!.GetType() == typeof(InvalidOperationException), error.ToString());
        Assert.True(
            error.Message.StartsWith(expectedPrefix, StringComparison.Ordinal),
            $"expected the '{expectedPrefix}' refusal, got: {error}");

        // The callback is the production one; only its real counts are read here. The native count is
        // deliberately not pinned: the child authority check may require a real build first.
        Assert.True(counts.HasValue, "the real preparation failure callback must have run");
        Assert.Equal(0, counts!.Value.writes);
        Assert.Equal(0, counts.Value.resets);
    }
}
