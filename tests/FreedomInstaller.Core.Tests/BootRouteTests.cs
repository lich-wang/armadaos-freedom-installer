using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Boot route contract tests: the firmware snapshot parsed from one getprop dump, the truthful route
/// decision derived from it, and the two transport touch points that have to carry that snapshot forward.
/// <para>
/// Every device query goes through the local recording runner, so no test starts a real adb or fastboot
/// binary. The assertions are about observable behaviour: parsed values, route statuses and the gate, never
/// about implementation text. The one literal message assertion is the readiness wording that used to
/// instruct a blanket unlock and must not come back.
/// </para>
/// </summary>
public sealed class BootRouteTests
{
    private const long GiB = TestSizes.GiB;

    private const string AdbPath = "/evidence/platform-tools/adb";
    private const string FastbootPath = "/evidence/platform-tools/fastboot";
    private const string Serial = "R58M12345ABC";
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    private const string DisplayId = "TB322FC_ROW_OPEN_USER_Q00031.0_V_ZUI_17.0.230_ST_240105";
    private const string Fingerprint = "Lenovo/TB322FC/elden:14/UP1A.231005.007/20240105:user/release-keys";
    private const string Release = "14";
    private const string SecurityPatch = "2024-01-05";

    // ------------------------------------------------------------- firmware parsing

    [Fact]
    public void Parse_ReadsTheSixProperties_AndConfirmsLockedWhenBothSourcesAgree()
    {
        var snapshot = Parse(
            Line("ro.build.display.id", DisplayId),
            Line("ro.build.fingerprint", Fingerprint),
            Line("ro.build.version.release", Release),
            Line("ro.build.version.security_patch", SecurityPatch),
            Line("ro.boot.flash.locked", "1"),
            Line("ro.boot.vbmeta.device_state", "locked"));

        Assert.Equal(DisplayId, snapshot.DisplayId);
        Assert.Equal(Fingerprint, snapshot.BuildFingerprint);
        Assert.Equal(Release, snapshot.AndroidRelease);
        Assert.Equal(SecurityPatch, snapshot.SecurityPatch);
        Assert.Equal(BootloaderState.Locked, snapshot.AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_MapsFlashLockedBitsAndVbmetaWordsToTheSameTwoStates()
    {
        // Each source alone is already one report.
        Assert.Equal(BootloaderState.Locked, Parse(Line("ro.boot.flash.locked", "1")).AndroidReportedBootloaderState);
        Assert.Equal(BootloaderState.Unlocked, Parse(Line("ro.boot.flash.locked", "0")).AndroidReportedBootloaderState);
        Assert.Equal(BootloaderState.Locked, Parse(Line("ro.boot.vbmeta.device_state", "locked")).AndroidReportedBootloaderState);
        Assert.Equal(BootloaderState.Unlocked, Parse(Line("ro.boot.vbmeta.device_state", "unlocked")).AndroidReportedBootloaderState);

        // And both sources agreeing is still exactly one state.
        Assert.Equal(
            BootloaderState.Unlocked,
            Parse(Line("ro.boot.flash.locked", "0"), Line("ro.boot.vbmeta.device_state", "unlocked"))
                .AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_ContradictingLockSourcesAreUnknown()
    {
        // Different sources disagree: neither may win, and "unlocked" must not survive by luck of order.
        Assert.Equal(
            BootloaderState.Unknown,
            Parse(Line("ro.boot.flash.locked", "0"), Line("ro.boot.vbmeta.device_state", "locked"))
                .AndroidReportedBootloaderState);

        Assert.Equal(
            BootloaderState.Unknown,
            Parse(Line("ro.boot.flash.locked", "1"), Line("ro.boot.vbmeta.device_state", "unlocked"))
                .AndroidReportedBootloaderState);

        // The same source contradicting itself across duplicate lines is the same contradiction.
        Assert.Equal(
            BootloaderState.Unknown,
            Parse(Line("ro.boot.flash.locked", "1"), Line("ro.boot.flash.locked", "0"))
                .AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_UnrecognisedLockValuesAreNotReports()
    {
        // "yes"/"true" are not the documented values of flash.locked, so they prove nothing at all.
        Assert.Equal(BootloaderState.Unknown, Parse(Line("ro.boot.flash.locked", "yes")).AndroidReportedBootloaderState);
        Assert.Equal(BootloaderState.Unknown, Parse(Line("ro.boot.vbmeta.device_state", "green")).AndroidReportedBootloaderState);

        // An unrecognised duplicate cannot contradict a recognised report either.
        Assert.Equal(
            BootloaderState.Locked,
            Parse(Line("ro.boot.flash.locked", "1"), Line("ro.boot.flash.locked", "yes"))
                .AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_ConsistentDuplicatesKeepTheValue_ConflictingDuplicatesClearOnlyThatField()
    {
        var consistent = Parse(
            Line("ro.build.version.release", Release),
            Line("ro.build.version.release", Release),
            Line("ro.build.version.security_patch", SecurityPatch));

        Assert.Equal(Release, consistent.AndroidRelease);
        Assert.Equal(SecurityPatch, consistent.SecurityPatch);

        var conflicting = Parse(
            Line("ro.build.display.id", DisplayId),
            Line("ro.build.display.id", DisplayId + "_OTHER"),
            Line("ro.build.version.release", "14"),
            Line("ro.build.version.release", "15"),
            Line("ro.build.fingerprint", Fingerprint),
            Line("ro.build.fingerprint", "Lenovo/TB322FC/elden:15/AP2A.240605.024/20240605:user/release-keys"),
            Line("ro.build.version.security_patch", SecurityPatch),
            Line("ro.boot.flash.locked", "1"));

        // Only the two fields that actually conflicted become unknown; the rest and the lock state survive.
        Assert.Null(conflicting.DisplayId);
        Assert.Null(conflicting.AndroidRelease);
        Assert.Null(conflicting.BuildFingerprint);
        Assert.Equal(SecurityPatch, conflicting.SecurityPatch);
        Assert.Equal(BootloaderState.Locked, conflicting.AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_IgnoresVerifiedBootStateAndOemUnlockAllowed()
    {
        // verifiedbootstate / OEM-unlock flags are never read as unlock evidence.
        var noLockReport = Parse(
            Line("ro.boot.verifiedbootstate", "orange"),
            Line("ro.oem_unlock_allowed", "1"),
            Line("ro.oem_unlock_supported", "1"));

        Assert.Equal(BootloaderState.Unknown, noLockReport.AndroidReportedBootloaderState);
        Assert.Null(noLockReport.DisplayId);

        // And an optimistic verified boot state cannot overrule an explicit locked report.
        var locked = Parse(
            Line("ro.boot.flash.locked", "1"),
            Line("ro.boot.verifiedbootstate", "green"),
            Line("ro.oem_unlock_allowed", "1"));

        Assert.Equal(BootloaderState.Locked, locked.AndroidReportedBootloaderState);
    }

    [Fact]
    public void Parse_EmptyOrUnparsableDumpReportsNothing()
    {
        foreach (var dump in new[] { string.Empty, "   ", "\t\n", "ERROR: no devices/emulators found", "[ro.build.release]" })
        {
            var snapshot = FirmwareProbe.Parse(dump);

            Assert.Null(snapshot.DisplayId);
            Assert.Null(snapshot.BuildFingerprint);
            Assert.Null(snapshot.AndroidRelease);
            Assert.Null(snapshot.SecurityPatch);
            Assert.Equal(BootloaderState.Unknown, snapshot.AndroidReportedBootloaderState);
        }
    }

    [Fact]
    public void Parse_AcceptsPropertyFileFormAndCrlfLineEndings()
    {
        var snapshot = FirmwareProbe.Parse(
            "ro.build.display.id=" + DisplayId + "\r\n" +
            "ro.boot.flash.locked=0\r\n" +
            "ro.build.version.security_patch=\r\n");

        Assert.Equal(DisplayId, snapshot.DisplayId);
        Assert.Equal(BootloaderState.Unlocked, snapshot.AndroidReportedBootloaderState);

        // An empty value is no value, not an empty string claim.
        Assert.Null(snapshot.SecurityPatch);
    }

    // ---------------------------------------------------------------- route decision

    [Fact]
    public void Evaluate_WithoutAConfirmedDeviceOrSerialIsPendingDevice()
    {
        Assert.Equal(BootRouteStatus.PendingDevice, BootRouteAssessment.Evaluate(null));
        Assert.Equal(
            BootRouteStatus.PendingDevice,
            BootRouteAssessment.Evaluate(new DeviceIdentity("   ", ModelA, BootloaderState.Unlocked)));
    }

    [Theory]
    [InlineData("TB324ZC")]
    [InlineData("TB322FCX")]
    [InlineData("TB323FU_OTHER")]
    [InlineData("")]
    public void Evaluate_OnlyTheTwoTicketModelsAreSupported(string model)
    {
        var identity = new DeviceIdentity(Serial, model, BootloaderState.Unlocked);

        Assert.Equal(BootRouteStatus.UnsupportedModel, BootRouteAssessment.Evaluate(identity));
    }

    [Theory]
    [InlineData(ModelA)]
    [InlineData(ModelB)]
    public void Evaluate_ConfirmedUnlockIsTheOnlyUnlockedRoute(string model)
    {
        var identity = new DeviceIdentity(Serial, model, BootloaderState.Unlocked);

        Assert.Equal(BootRouteStatus.UnlockedRoute, BootRouteAssessment.Evaluate(identity));
    }

    [Fact]
    public void Evaluate_ConfirmedLockSplitsByModel()
    {
        Assert.Equal(BootRouteStatus.LockedEdlCandidate, Evaluate(ModelA, BootloaderState.Locked));
        Assert.Equal(BootRouteStatus.LockedRouteUnsupported, Evaluate(ModelB, BootloaderState.Locked));
    }

    [Fact]
    public void Evaluate_AndroidReportedLockLandsOnTheSameCandidatesAsAConfirmedLock()
    {
        Assert.Equal(BootRouteStatus.LockedEdlCandidate, EvaluateWithReport(ModelA, BootloaderState.Locked));
        Assert.Equal(BootRouteStatus.LockedRouteUnsupported, EvaluateWithReport(ModelB, BootloaderState.Locked));
    }

    [Fact]
    public void Evaluate_AndroidReportedUnlockOnlyAsksForFastbootConfirmation()
    {
        Assert.Equal(BootRouteStatus.FastbootConfirmationRequired, EvaluateWithReport(ModelA, BootloaderState.Unlocked));
        Assert.Equal(BootRouteStatus.FastbootConfirmationRequired, EvaluateWithReport(ModelB, BootloaderState.Unlocked));
    }

    [Fact]
    public void Evaluate_NoUsableAndroidReportIsPendingLockState()
    {
        // No snapshot at all, an explicit Unknown report, an undefined report value: all unconfirmed.
        Assert.Equal(
            BootRouteStatus.PendingLockState,
            BootRouteAssessment.Evaluate(new DeviceIdentity(Serial, ModelA, BootloaderState.Unknown)));

        Assert.Equal(BootRouteStatus.PendingLockState, EvaluateWithReport(ModelA, BootloaderState.Unknown));
        Assert.Equal(BootRouteStatus.PendingLockState, EvaluateWithReport(ModelA, (BootloaderState)99));
    }

    [Fact]
    public void Evaluate_UndefinedConfirmedEnumIsPendingLockStateAndNeverFallsBackToTheAndroidReport()
    {
        // An unvalidated cast is not a confirmed lock state: the Android report may not be used instead.
        var lockedByAndroid = new DeviceIdentity(Serial, ModelA, (BootloaderState)99)
        {
            Firmware = Snapshot(BootloaderState.Locked),
        };

        var unlockedByAndroid = new DeviceIdentity(Serial, ModelB, (BootloaderState)99)
        {
            Firmware = Snapshot(BootloaderState.Unlocked),
        };

        Assert.Equal(BootRouteStatus.PendingLockState, BootRouteAssessment.Evaluate(lockedByAndroid));
        Assert.Equal(BootRouteStatus.PendingLockState, BootRouteAssessment.Evaluate(unlockedByAndroid));
    }

    [Fact]
    public void Evaluate_HasNoFirmwareVersionCutoffAndNoTrustByModel()
    {
        // The same locked unit lands on the same route whatever the build and patch level claim.
        var ancient = new DeviceIdentity(Serial, ModelA, BootloaderState.Locked)
        {
            Firmware = new FirmwareSnapshot("TB322FC_ANCIENT", "old/fingerprint", "12", "2021-01-01", BootloaderState.Unknown),
        };
        var current = new DeviceIdentity(Serial, ModelA, BootloaderState.Locked)
        {
            Firmware = new FirmwareSnapshot("TB322FC_CURRENT", "new/fingerprint", "16", "2026-10-19", BootloaderState.Unknown),
        };

        Assert.Equal(BootRouteStatus.LockedEdlCandidate, BootRouteAssessment.Evaluate(ancient));
        Assert.Equal(BootRouteStatus.LockedEdlCandidate, BootRouteAssessment.Evaluate(current));

        // A supported model string with no lock evidence is still pending, never assumed safe.
        var supportedButSilent = new DeviceIdentity(Serial, ModelB, BootloaderState.Unknown)
        {
            Firmware = new FirmwareSnapshot(null, null, Release, null, BootloaderState.Unknown),
        };

        Assert.Equal(BootRouteStatus.PendingLockState, BootRouteAssessment.Evaluate(supportedButSilent));
    }

    [Fact]
    public void Evaluate_ExposesAStatusOnlyWithoutAnyReadyOrWriteFlag()
    {
        // The decision must stay a route status: no member may be readable as "ready to write".
        Assert.Null(typeof(BootRouteAssessment).GetProperty("CanWrite"));
        Assert.Null(typeof(BootRouteAssessment).GetProperty("Ready"));
        Assert.Null(typeof(BootRouteAssessment).GetMethod("CanWrite"));
        Assert.Empty(typeof(BootRouteAssessment).GetConstructors());

        foreach (var name in Enum.GetNames(typeof(BootRouteStatus)))
        {
            Assert.DoesNotContain("Ready", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("CanWrite", name, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ------------------------------------------------------ transport carries the snapshot

    [Fact]
    public async Task ReadAdbIdentity_FillsFirmwareFromTheSameGetpropDumpButStaysUnknown()
    {
        var runner = new RecordingRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(
                0,
                Line("ro.product.model", ModelA) + "\n" +
                Line("ro.product.vendor.model", ModelA) + "\n" +
                Line("ro.build.display.id", DisplayId) + "\n" +
                Line("ro.build.fingerprint", Fingerprint) + "\n" +
                Line("ro.build.version.release", Release) + "\n" +
                Line("ro.build.version.security_patch", SecurityPatch) + "\n" +
                Line("ro.boot.flash.locked", "1") + "\n" +
                Line("ro.boot.vbmeta.device_state", "locked") + "\n",
                string.Empty));

        var identity = await TransportFor(runner).ReadAdbIdentityAsync(Serial);

        Assert.Equal(Serial, identity.Serial);
        Assert.Equal(ModelA, identity.Model);

        var firmware = Assert.IsType<FirmwareSnapshot>(identity.Firmware);
        Assert.Equal(DisplayId, firmware.DisplayId);
        Assert.Equal(Fingerprint, firmware.BuildFingerprint);
        Assert.Equal(Release, firmware.AndroidRelease);
        Assert.Equal(SecurityPatch, firmware.SecurityPatch);
        Assert.Equal(BootloaderState.Locked, firmware.AndroidReportedBootloaderState);

        // Android reporting a lock is still not the confirmed state, and one getprop dump served both.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAdbIdentity_AndroidReportedUnlock_NeverOpensTheGateOrTheRoute()
    {
        var runner = new RecordingRunner();
        runner.Expect(
            AdbPath,
            new[] { "-s", Serial, "shell", "getprop" },
            new ProcessResult(
                0,
                Line("ro.product.model", ModelA) + "\n" +
                Line("ro.product.vendor.model", ModelA) + "\n" +
                Line("ro.boot.flash.locked", "0") + "\n" +
                Line("ro.boot.vbmeta.device_state", "unlocked") + "\n" +
                Line("ro.boot.verifiedbootstate", "orange") + "\n",
                string.Empty));

        var identity = await TransportFor(runner).ReadAdbIdentityAsync(Serial);

        // The snapshot records what Android claimed, and nothing more.
        Assert.Equal(BootloaderState.Unlocked, identity.Firmware!.AndroidReportedBootloaderState);
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);

        // So the route still needs fastboot confirmation and the readiness gate stays closed.
        Assert.Equal(BootRouteStatus.FastbootConfirmationRequired, BootRouteAssessment.Evaluate(identity));

        var readiness = InstallationReadiness.Evaluate(
            identity,
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.False(readiness.IsReady);
        Assert.NotEmpty(readiness.Reasons);

        // Read-only: the identity came from exactly one getprop query and no other command ran.
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task CheckFastboot_KeepsTheFirmwareSnapshotAndOnlyRewritesTheLockState()
    {
        var runner = new RecordingRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(0, string.Empty, "(bootloader) unlocked: yes\nfinished. total time: 0.002s\n"));

        var original = Snapshot(BootloaderState.Locked);
        var confirmed = new DeviceIdentity(Serial, ModelA, BootloaderState.Unknown) { Firmware = original };

        var identity = await TransportFor(runner).CheckFastbootAsync(confirmed);

        Assert.Equal(Serial, identity.Serial);
        Assert.Equal(ModelA, identity.Model);
        Assert.Equal(BootloaderState.Unlocked, identity.BootloaderState);

        // The snapshot survives the record-with update, values and reported state unchanged.
        Assert.Equal(original, identity.Firmware);
        Assert.Equal(BootloaderState.Locked, identity.Firmware!.AndroidReportedBootloaderState);
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task CheckFastboot_KeepsTheFirmwareSnapshotWhenBothQueriesReportNothing()
    {
        var runner = new RecordingRunner();
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "getvar", "unlocked" },
            new ProcessResult(1, string.Empty, "FAILED (remote: 'GetVar Variable Not found')\n"));
        runner.Expect(
            FastbootPath,
            new[] { "-s", Serial, "oem", "device-info" },
            new ProcessResult(1, string.Empty, "FAILED (remote: 'unknown command')\n"));

        var original = Snapshot(BootloaderState.Unlocked);
        var confirmed = new DeviceIdentity(Serial, ModelB, BootloaderState.Unknown) { Firmware = original };

        var identity = await TransportFor(runner).CheckFastbootAsync(confirmed);

        // No evidence means Unknown, and the adb snapshot is neither dropped nor promoted.
        Assert.Equal(BootloaderState.Unknown, identity.BootloaderState);
        Assert.Equal(original, identity.Firmware);
        Assert.Equal(2, runner.CommandCount);
    }

    // ------------------------------------------------------------ readiness wording

    [Fact]
    public void Evaluate_LockedReasonAsksForAVerifiedNoUnlockRouteInsteadOfABlanketUnlock()
    {
        var readiness = InstallationReadiness.Evaluate(
            new DeviceIdentity(Serial, ModelA, BootloaderState.Locked),
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        // The gate itself must not be loosened: a locked unit is still not ready.
        Assert.False(readiness.IsReady);
        Assert.NotEmpty(readiness.Reasons);

        var lockReasons = readiness.Reasons
            .Where(reason => reason.Contains("锁定", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(lockReasons);
        foreach (var reason in lockReasons)
        {
            Assert.DoesNotContain("先解锁再继续", reason, StringComparison.Ordinal);
            Assert.Contains("无需解锁", reason, StringComparison.Ordinal);
            Assert.Contains("已确认解锁", reason, StringComparison.Ordinal);
            Assert.Contains("执行适配器", reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Evaluate_UnlockedModelStillPassesTheOtherwiseIdenticalGate()
    {
        // Control for the test above: only the bootloader state differs, so the gate is not broken,
        // just still closed for a locked unit.
        var readiness = InstallationReadiness.Evaluate(
            new DeviceIdentity(Serial, ModelA, BootloaderState.Unlocked),
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.True(readiness.IsReady, string.Join("; ", readiness.Reasons));
    }

    // ------------------------------------------------------------------------ helpers

    /// <summary>One getprop line in the format <c>adb shell getprop</c> prints.</summary>
    private static string Line(string key, string value) => "[" + key + "]: [" + value + "]";

    private static FirmwareSnapshot Parse(params string[] lines) => FirmwareProbe.Parse(string.Join('\n', lines) + "\n");

    private static FirmwareSnapshot Snapshot(BootloaderState reported) =>
        new(DisplayId, Fingerprint, Release, SecurityPatch, reported);

    private static BootRouteStatus Evaluate(string model, BootloaderState state) =>
        BootRouteAssessment.Evaluate(new DeviceIdentity(Serial, model, state));

    private static BootRouteStatus EvaluateWithReport(string model, BootloaderState reported) =>
        BootRouteAssessment.Evaluate(new DeviceIdentity(Serial, model, BootloaderState.Unknown) { Firmware = Snapshot(reported) });

    private static DeviceTransport TransportFor(ICommandRunner runner) => new(AdbPath, FastbootPath, runner);

    private static PackageStorage TicketStorage() => new(1 * GiB, 20 * GiB, 2 * GiB, 8 * GiB);

    private static PackageValidationResult ValidPackage() =>
        new(true, Array.Empty<string>(), TicketStorage());

    // Literal snapshot of the expected plan, so this class never depends on the planner.
    private static AllocationPlan ExpectedPlan() => new(
        AndroidBytes: 96 * GiB,
        LinuxBytes: 128 * GiB,
        LinuxBootBytes: 1 * GiB,
        LinuxRootBytes: 127 * GiB,
        EstimatedLinuxDataBytes: 107 * GiB,
        UserdataStartSector: 8_388_608,
        AndroidSectorCount: 201_326_592,
        LinuxBootStartSector: 209_715_200,
        LinuxRootStartSector: 211_812_352,
        EndSectorExclusive: 478_150_656);

    /// <summary>
    /// Recording <see cref="ICommandRunner"/> for the transport boundary: each expected call pins the
    /// executable, the full argument vector in order and a finite positive timeout, and any extra or
    /// mismatching command fails the test instead of silently reaching a device.
    /// </summary>
    private sealed class RecordingRunner : ICommandRunner
    {
        private readonly List<Step> _steps = new();
        private readonly List<ProcessCommand> _commands = new();

        internal int CommandCount => _commands.Count;

        internal void Expect(string executable, string[] arguments, ProcessResult result) =>
            _steps.Add(new Step(executable, arguments, result));

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            _commands.Add(command);

            cancellationToken.ThrowIfCancellationRequested();

            var index = _commands.Count - 1;
            Assert.True(
                index < _steps.Count,
                $"unexpected extra command #{index + 1}: {command.Executable} {string.Join(' ', command.Arguments)}");

            var step = _steps[index];

            Assert.Equal(step.Executable, command.Executable);
            Assert.Equal(step.Arguments, command.Arguments.ToArray());
            Assert.True(command.Timeout > TimeSpan.Zero, "a device query must carry a finite positive timeout");
            Assert.NotEqual(Timeout.InfiniteTimeSpan, command.Timeout);

            return Task.FromResult(step.Result);
        }

        private sealed record Step(string Executable, string[] Arguments, ProcessResult Result);
    }
}
