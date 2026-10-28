namespace FreedomInstaller.Core;

/// <summary>
/// Read-only firmware snapshot parsed from one <c>adb shell getprop</c> dump: the build identity Android
/// reports plus the lock state Android reports about its own boot chain.
/// <para>
/// Every field is nullable and <see cref="AndroidReportedBootloaderState"/> is
/// <see cref="BootloaderState.Unknown"/> whenever the report is missing or contradictory, so a snapshot can
/// only ever describe what Android said. It is never evidence that fastboot will accept writes:
/// <see cref="DeviceIdentity.BootloaderState"/> stays <see cref="BootloaderState.Unknown"/> until
/// <see cref="DeviceTransport.CheckFastbootAsync"/> confirms it.
/// </para>
/// </summary>
/// <param name="DisplayId">Parsed <c>ro.build.display.id</c>, or null when absent or contradictory.</param>
/// <param name="BuildFingerprint">Parsed <c>ro.build.fingerprint</c>, or null when absent or contradictory.</param>
/// <param name="AndroidRelease">Parsed <c>ro.build.version.release</c>, or null when absent or contradictory.</param>
/// <param name="SecurityPatch">Parsed <c>ro.build.version.security_patch</c>, or null when absent or contradictory.</param>
/// <param name="AndroidReportedBootloaderState">
/// Lock state derived from <c>ro.boot.flash.locked</c> and <c>ro.boot.vbmeta.device_state</c> only.
/// </param>
public sealed record FirmwareSnapshot(
    string? DisplayId,
    string? BuildFingerprint,
    string? AndroidRelease,
    string? SecurityPatch,
    BootloaderState AndroidReportedBootloaderState);

/// <summary>
/// Parses the firmware properties of one already captured getprop dump. This type never launches a process,
/// never opens a device handle and never sends a command; it only classifies text that adb already printed.
/// <para>
/// Only six keys are read: <c>ro.build.display.id</c>, <c>ro.build.fingerprint</c>,
/// <c>ro.build.version.release</c>, <c>ro.build.version.security_patch</c>, <c>ro.boot.flash.locked</c> and
/// <c>ro.boot.vbmeta.device_state</c>. Duplicate lines that agree are one value; duplicates that disagree make
/// that field unknown instead of picking a winner. <c>ro.boot.verifiedbootstate</c>, the OEM-unlock flags and
/// every other property are ignored, because none of them proves that the bootloader is unlocked.
/// </para>
/// </summary>
public static class FirmwareProbe
{
    private const string DisplayIdKey = "ro.build.display.id";
    private const string BuildFingerprintKey = "ro.build.fingerprint";
    private const string AndroidReleaseKey = "ro.build.version.release";
    private const string SecurityPatchKey = "ro.build.version.security_patch";
    private const string FlashLockedKey = "ro.boot.flash.locked";
    private const string VbmetaDeviceStateKey = "ro.boot.vbmeta.device_state";

    /// <summary>
    /// Parses <paramref name="getpropOutput"/> into a snapshot. Empty, blank and unparsable input yield a
    /// snapshot with no values and <see cref="BootloaderState.Unknown"/>; this method does not throw for
    /// device text, because a dump that names nothing is a normal answer.
    /// </summary>
    public static FirmwareSnapshot Parse(string? getpropOutput)
    {
        if (string.IsNullOrWhiteSpace(getpropOutput))
        {
            return Empty();
        }

        // One set per field: a value is only kept when every line that names the field agrees on it.
        var displayIds = new SortedSet<string>(StringComparer.Ordinal);
        var fingerprints = new SortedSet<string>(StringComparer.Ordinal);
        var releases = new SortedSet<string>(StringComparer.Ordinal);
        var securityPatches = new SortedSet<string>(StringComparer.Ordinal);

        // Both lock properties report the same two states, so they share one set of reports.
        var lockReports = new HashSet<BootloaderState>();

        foreach (var rawLine in getpropOutput.Split('\n'))
        {
            if (!DeviceProbe.TryReadProperty(rawLine, out var key, out var value) || value.Length == 0)
            {
                // A blank value is no claim at all, so it neither confirms nor contradicts a field.
                continue;
            }

            if (key.Equals(DisplayIdKey, StringComparison.OrdinalIgnoreCase))
            {
                displayIds.Add(value);
            }
            else if (key.Equals(BuildFingerprintKey, StringComparison.OrdinalIgnoreCase))
            {
                fingerprints.Add(value);
            }
            else if (key.Equals(AndroidReleaseKey, StringComparison.OrdinalIgnoreCase))
            {
                releases.Add(value);
            }
            else if (key.Equals(SecurityPatchKey, StringComparison.OrdinalIgnoreCase))
            {
                securityPatches.Add(value);
            }
            else if (key.Equals(FlashLockedKey, StringComparison.OrdinalIgnoreCase))
            {
                AddLockReport(lockReports, MapFlashLocked(value));
            }
            else if (key.Equals(VbmetaDeviceStateKey, StringComparison.OrdinalIgnoreCase))
            {
                AddLockReport(lockReports, MapVbmetaDeviceState(value));
            }
        }

        return new FirmwareSnapshot(
            Single(displayIds),
            Single(fingerprints),
            Single(releases),
            Single(securityPatches),
            lockReports.Count == 1 ? lockReports.First() : BootloaderState.Unknown);
    }

    /// <summary>A snapshot that claims nothing: every value absent and the lock state unknown.</summary>
    private static FirmwareSnapshot Empty() =>
        new(null, null, null, null, BootloaderState.Unknown);

    /// <summary><c>ro.boot.flash.locked</c>: 1 means locked, 0 means unlocked, anything else is no report.</summary>
    private static BootloaderState? MapFlashLocked(string value) => value switch
    {
        "1" => BootloaderState.Locked,
        "0" => BootloaderState.Unlocked,
        _ => null,
    };

    /// <summary><c>ro.boot.vbmeta.device_state</c>: "locked"/"unlocked", anything else is no report.</summary>
    private static BootloaderState? MapVbmetaDeviceState(string value) => value.ToLowerInvariant() switch
    {
        "locked" => BootloaderState.Locked,
        "unlocked" => BootloaderState.Unlocked,
        _ => null,
    };

    private static void AddLockReport(ISet<BootloaderState> reports, BootloaderState? report)
    {
        if (report is not null)
        {
            reports.Add(report.Value);
        }
    }

    /// <summary>The one agreed value of a field, or null when it is missing or reported differently.</summary>
    private static string? Single(SortedSet<string> values) => values.Count == 1 ? values.Min : null;
}

/// <summary>
/// The truthful routing decision for one device: which boot route is actually available, or which piece of
/// evidence is still missing before that can be decided.
/// <para>
/// A status is not a permission. No value of this enum means "ready to write", and none of them is produced
/// by a model name or a firmware version alone.
/// </para>
/// </summary>
public enum BootRouteStatus
{
    /// <summary>No confirmed device identity yet, so no route can be named.</summary>
    PendingDevice = 0,

    /// <summary>The model is not one of the two supported generations.</summary>
    UnsupportedModel = 1,

    /// <summary>The confirmed lock state is unconfirmed and Android reported nothing usable: ask for a lock read.</summary>
    PendingLockState = 2,

    /// <summary>Android reported an unlocked bootloader, which only fastboot may confirm.</summary>
    FastbootConfirmationRequired = 3,

    /// <summary>A confirmed unlocked bootloader on a supported model: the route the installer can execute.</summary>
    UnlockedRoute = 4,

    /// <summary>Locked TB322FC: a locked-device EDL candidate, still requiring its own verified route.</summary>
    LockedEdlCandidate = 5,

    /// <summary>Locked TB323FU: no supported no-unlock route exists for this generation.</summary>
    LockedRouteUnsupported = 6,
}

/// <summary>
/// Decides which boot route a device can take, from already collected evidence only. This type never touches
/// a device, never runs a command and never turns a report into a write permission.
/// <para>
/// The decision is deliberately closed: only the exact models TB322FC / TB323FU are considered, only
/// <see cref="BootloaderState.Unlocked"/> yields <see cref="BootRouteStatus.UnlockedRoute"/>, an undefined
/// enum value is never interpreted as anything but unconfirmed, and an Android report is never used as a
/// substitute for a confirmed lock state. There is no firmware version cutoff and no model-based trust.
/// </para>
/// </summary>
public static class BootRouteAssessment
{
    /// <summary>
    /// Evaluates the route of <paramref name="identity"/>.
    /// <list type="bullet">
    /// <item>no identity (or no serial) yields <see cref="BootRouteStatus.PendingDevice"/>;</item>
    /// <item>any model other than TB322FC / TB323FU yields <see cref="BootRouteStatus.UnsupportedModel"/>;</item>
    /// <item>a confirmed <see cref="BootloaderState.Unlocked"/> yields
    /// <see cref="BootRouteStatus.UnlockedRoute"/>;</item>
    /// <item>a confirmed <see cref="BootloaderState.Locked"/> yields
    /// <see cref="BootRouteStatus.LockedEdlCandidate"/> on TB322FC and
    /// <see cref="BootRouteStatus.LockedRouteUnsupported"/> on TB323FU;</item>
    /// <item><see cref="BootloaderState.Unknown"/> is resolved from the Android report only when that report
    /// is unambiguous: a reported lock lands on the same candidate/unsupported split, a reported unlock yields
    /// <see cref="BootRouteStatus.FastbootConfirmationRequired"/>, and a missing, unknown or undefined report
    /// yields <see cref="BootRouteStatus.PendingLockState"/>;</item>
    /// <item>an undefined enum value in <see cref="DeviceIdentity.BootloaderState"/> yields
    /// <see cref="BootRouteStatus.PendingLockState"/> and is never replaced by the Android report.</item>
    /// </list>
    /// </summary>
    public static BootRouteStatus Evaluate(DeviceIdentity? identity)
    {
        if (identity is null || string.IsNullOrWhiteSpace(identity.Serial))
        {
            // Without a confirmed identity there is no device to route, only a pending question.
            return BootRouteStatus.PendingDevice;
        }

        var model = DeviceProbe.CanonicalModel(identity.Model);
        if (model is null)
        {
            return BootRouteStatus.UnsupportedModel;
        }

        switch (identity.BootloaderState)
        {
            case BootloaderState.Unlocked:
                return BootRouteStatus.UnlockedRoute;
            case BootloaderState.Locked:
                return LockedRouteFor(model);
            case BootloaderState.Unknown:
                break;
            default:
                // An undefined enum value is an unvalidated cast, so it is never a confirmed lock state and
                // the Android report may not stand in for it.
                return BootRouteStatus.PendingLockState;
        }

        var reported = identity.Firmware?.AndroidReportedBootloaderState ?? BootloaderState.Unknown;

        if (reported == BootloaderState.Locked)
        {
            return LockedRouteFor(model);
        }

        if (reported == BootloaderState.Unlocked)
        {
            // Android claiming an unlock is only a reason to ask fastboot, never a route by itself.
            return BootRouteStatus.FastbootConfirmationRequired;
        }

        return BootRouteStatus.PendingLockState;
    }

    /// <summary>A confirmed lock, or an unambiguous Android lock report, splits by generation.</summary>
    private static BootRouteStatus LockedRouteFor(string canonicalModel) =>
        string.Equals(canonicalModel, "TB323FU", StringComparison.Ordinal)
            ? BootRouteStatus.LockedRouteUnsupported
            : BootRouteStatus.LockedEdlCandidate;
}
