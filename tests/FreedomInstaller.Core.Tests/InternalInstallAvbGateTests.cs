// P2 F3a RED: the bootloader-compatibility gate that must fire BEFORE any named gate and before the
// Linux raw expansion / native pack of the real direct-preparation factory.
// Tests only: no production file, no other test, no fixture, no toolchain and no image is written here.
using System;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The pre-expansion admission policy of the real <see cref="InternalInstallBackend"/> factory:
/// a confirmed Fastboot Unlocked OR a confirmed Fastboot Locked whose authenticated ORIGINAL root AVB
/// key equals the AOSP target pin (ordinal-ignore-case). An OEM source on a confirmed Locked device has
/// no compatibility evidence and must be refused, and the refusal must land before the root artifact is
/// expanded, so no native pack, write or reset can ever be observed.
/// <para>
/// Every case composes the actual factory through <see cref="DirectInstallReadyTestSession"/>; the
/// session's own default keeps the original AOSP metadata, so an OEM transition is always explicit.
/// The refusal is an absence of compatibility evidence, never a claim that all G5 hardware rejects OEM.
/// </para>
/// </summary>
public sealed class InternalInstallAvbGateTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    /// <summary>The stable code the production refusal message must carry, verbatim.</summary>
    private const string CompatibilityErrorCode = "requires-compatible-bootloader";

    private const string SyntheticBuildFingerprint = "Lenovo/synthetic:15/test:user/release-keys";
    private const string SyntheticAndroidRelease = "15";
    private const string SyntheticSecurityPatch = "2026-06-01";

    private readonly EdlClientToolchainFixture _toolchain;
    private readonly EdlRawSharedInput _rawShared;

    public InternalInstallAvbGateTests(
        EdlClientToolchainFixture toolchain,
        EdlRawSharedInput rawShared)
    {
        _toolchain = toolchain;
        _rawShared = rawShared;
    }

    /// <summary>
    /// An OEM original root on a confirmed Locked device is refused even when the whole package is
    /// otherwise valid. The baseline returns a Prepared session here, so this is the RED admission case.
    /// </summary>
    [Fact]
    public async Task LockedOemRootRefusesValidPackage()
    {
        await AssertCompatibilityRefusalAsync(
            avbSourceKind: DirectAvbSourceKind.Oem,
            slotBAvbSourceKind: null,
            lockState: BootloaderState.Locked,
            poisonExpandedRoot: false,
            observedFirmware: null,
            requireCompatibilityCode: true);
    }

    /// <summary>
    /// The same refusal must be decided before the root is expanded: the package carries a truthful
    /// compressed claim but a corrupted expansion, so a gate that runs after expansion would report a
    /// snapshot/digest failure instead of the compatibility code. Baseline reports the snapshot failure,
    /// which makes this the precise ordering RED rather than an environment or invalid-source RED.
    /// </summary>
    [Fact]
    public async Task LockedOemRootRefusesBeforeRootExpansion()
    {
        await AssertCompatibilityRefusalAsync(
            avbSourceKind: DirectAvbSourceKind.Oem,
            slotBAvbSourceKind: null,
            lockState: BootloaderState.Locked,
            poisonExpandedRoot: true,
            observedFirmware: null,
            requireCompatibilityCode: true);
    }

    /// <summary>
    /// The Android-reported Unlocked fact may not override the confirmed Locked fastboot fact: the
    /// compatibility decision is taken from the confirmed source, not from the firmware report.
    /// </summary>
    [Fact]
    public async Task AndroidUnlockedDoesNotOverrideConfirmedLocked()
    {
        var androidUnlocked = new FirmwareSnapshot(
            _toolchain.Toolchain.AndroidBuild,
            SyntheticBuildFingerprint,
            SyntheticAndroidRelease,
            SyntheticSecurityPatch,
            BootloaderState.Unlocked);

        await AssertCompatibilityRefusalAsync(
            avbSourceKind: DirectAvbSourceKind.Oem,
            slotBAvbSourceKind: null,
            lockState: BootloaderState.Locked,
            poisonExpandedRoot: false,
            observedFirmware: androidUnlocked,
            requireCompatibilityCode: true);
    }

    /// <summary>
    /// Every valid slot is gated, not only the current one: an OEM slot B cannot carry a Locked device
    /// past the gate while the current slot A stays AOSP, and it still fails before expansion.
    /// </summary>
    [Fact]
    public async Task OtherValidOemSlotCannotBypassLockedCurrentAosp()
    {
        await AssertCompatibilityRefusalAsync(
            avbSourceKind: DirectAvbSourceKind.Aosp,
            slotBAvbSourceKind: DirectAvbSourceKind.Oem,
            lockState: BootloaderState.Locked,
            poisonExpandedRoot: true,
            observedFirmware: null,
            requireCompatibilityCode: true);
    }

    /// <summary>
    /// A confirmed Unlocked fastboot fact admits the OEM source even though Android reports Locked, and
    /// the admitted preparation writes and resets nothing while the native oracle runs exactly six times.
    /// </summary>
    [Fact]
    public async Task ConfirmedUnlockedAllowsOemDespiteAndroidLocked()
    {
        using DirectInstallReadyTestSession session =
            await DirectInstallReadyTestSession.CreateAsync(
                _toolchain,
                _rawShared,
                observedFastbootLockState: BootloaderState.Unlocked,
                avbSourceKind: DirectAvbSourceKind.Oem);

        InternalInstallPrepared prepared = session.Backend.Prepared;

        Assert.Equal(InternalInstallStage.Prepared, session.Backend.Snapshot.Stage);
        Assert.Equal(BootloaderState.Unlocked, prepared.FastbootLockState);
        Assert.Equal(BootloaderState.Locked, prepared.Firmware.AndroidReportedBootloaderState);
        Assert.Equal(DirectAvbSourceKind.Oem, session.AvbSourceKind);
        Assert.Equal(0, session.EdlRunner.Writes.Count);
        Assert.Equal(0, session.EdlRunner.ResetCount);
        Assert.Equal(6, session.NativeCommandCount);
    }

    /// <summary>
    /// A confirmed Locked device admits the ORIGINAL AOSP root: the session's lowercase original key hash
    /// and the uppercase target pin are the same key, so the comparison must ignore case. Nothing is
    /// written or reset and the native oracle still runs six times. No hardware acceptance is claimed.
    /// </summary>
    [Fact]
    public async Task LockedOriginalAospAllowsMixedCaseKeyHashes()
    {
        using DirectInstallReadyTestSession session =
            await DirectInstallReadyTestSession.CreateAsync(
                _toolchain,
                _rawShared,
                observedFastbootLockState: BootloaderState.Locked,
                avbSourceKind: DirectAvbSourceKind.Aosp);

        InternalInstallPrepared prepared = session.Backend.Prepared;

        Assert.Equal(InternalInstallStage.Prepared, session.Backend.Snapshot.Stage);
        Assert.Equal(BootloaderState.Locked, prepared.FastbootLockState);
        Assert.Equal(BootloaderState.Locked, prepared.Firmware.AndroidReportedBootloaderState);
        Assert.Equal(0, session.EdlRunner.Writes.Count);
        Assert.Equal(0, session.EdlRunner.ResetCount);
        Assert.Equal(6, session.NativeCommandCount);

        string originalRootKeySha256 = session.OriginalRootKeySha256;
        string targetPin = ReadTargetSigningPublicKeySha256();

        // The two sides really differ in case, and they are the same key once case is ignored.
        Assert.Equal(64, originalRootKeySha256.Length);
        Assert.Equal(64, targetPin.Length);
        Assert.Equal(originalRootKeySha256.ToLowerInvariant(), originalRootKeySha256);
        Assert.Equal(targetPin.ToUpperInvariant(), targetPin);
        Assert.Equal(targetPin, originalRootKeySha256, ignoreCase: true);
    }

    /// <summary>
    /// An Unknown confirmed fastboot fact is never treated as Unlocked: Step 1 already fails the
    /// completion, and the factory refuses with an invalid-operation failure while every failure counter
    /// stays at zero and no Prepared session is handed back.
    /// </summary>
    [Fact]
    public async Task UnknownConfirmedFastbootRefuses()
    {
        await AssertCompatibilityRefusalAsync(
            avbSourceKind: DirectAvbSourceKind.Aosp,
            slotBAvbSourceKind: null,
            lockState: BootloaderState.Unknown,
            poisonExpandedRoot: false,
            observedFirmware: null,
            requireCompatibilityCode: false);
    }

    /// <summary>
    /// Runs one real preparation that must be refused before any expansion. The returned session, if the
    /// factory wrongly hands one back, is disposed in <c>finally</c> so a failed RED leaves no leases. The
    /// refusal is always the exact <see cref="InvalidOperationException"/> type with zero native, write and
    /// reset counts; a success is never swallowed as a pass.
    /// </summary>
    private async Task AssertCompatibilityRefusalAsync(
        DirectAvbSourceKind avbSourceKind,
        DirectAvbSourceKind? slotBAvbSourceKind,
        BootloaderState lockState,
        bool poisonExpandedRoot,
        FirmwareSnapshot? observedFirmware,
        bool requireCompatibilityCode)
    {
        var callbackCount = 0;
        var native = -1;
        var writes = -1;
        var resets = -1;
        DirectInstallReadyTestSession? unexpected = null;

        try
        {
            Exception? error = await Record.ExceptionAsync(async () =>
            {
                unexpected = await DirectInstallReadyTestSession.CreateAsync(
                    _toolchain,
                    _rawShared,
                    observedFirmware: observedFirmware,
                    avbSourceKind: avbSourceKind,
                    observedFastbootLockState: lockState,
                    poisonExpandedRoot: poisonExpandedRoot,
                    onPreparationFailure: (nativeCalls, writeCount, resetCount) =>
                    {
                        callbackCount++;
                        native = nativeCalls;
                        writes = writeCount;
                        resets = resetCount;
                    },
                    slotBAvbSourceKind: slotBAvbSourceKind);
            });

            Assert.True(
                error is not null,
                "The factory returned a Prepared session instead of refusing the transition.");
            Assert.True(
                error!.GetType() == typeof(InvalidOperationException),
                "Expected exact InvalidOperationException, observed: " + error.ToString());
            Assert.Null(unexpected);

            if (requireCompatibilityCode)
            {
                Assert.Contains(CompatibilityErrorCode, error!.Message, StringComparison.Ordinal);
            }

            Assert.Equal(1, callbackCount);
            Assert.Equal(0, native);
            Assert.Equal(0, writes);
            Assert.Equal(0, resets);
        }
        finally
        {
            unexpected?.Dispose();
        }
    }

    /// <summary>
    /// Reads the internal AOSP target pin from the production builder by reflection, so this test never
    /// duplicates the pinned value and never binds to a compile-time internal symbol.
    /// </summary>
    private static string ReadTargetSigningPublicKeySha256()
    {
        Type builder = typeof(InternalInstallPrepared).Assembly.GetType(
            "FreedomInstaller.Core.EdlRawBootBuilder",
            throwOnError: false)
            ?? throw new InvalidOperationException(
                "FreedomInstaller.Core.EdlRawBootBuilder is missing from the production assembly.");

        const System.Reflection.BindingFlags Flags =
            System.Reflection.BindingFlags.Public
            | System.Reflection.BindingFlags.NonPublic
            | System.Reflection.BindingFlags.Static
            | System.Reflection.BindingFlags.FlattenHierarchy;

        var field = builder.GetField("SigningPublicKeySha256", Flags);
        if (field is not null)
        {
            object? value = field.GetValue(null);
            if (value is string constant)
            {
                return constant;
            }
        }

        var property = builder.GetProperty("SigningPublicKeySha256", Flags);
        if (property is not null && property.GetMethod is not null)
        {
            if (property.GetValue(null) is string pinned)
            {
                return pinned;
            }
        }

        throw new InvalidOperationException(
            "EdlRawBootBuilder.SigningPublicKeySha256 no longer exposes a static string target pin.");
    }
}
