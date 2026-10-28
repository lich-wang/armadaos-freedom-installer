using System;
using System.Collections.Generic;
using System.Linq;

namespace FreedomInstaller.Core;

/// <summary>
/// Identity proven by the offline 9008 route: the local trusted profile plus the bus-reported serial of the
/// sole present endpoint. <see cref="AndroidSerial"/> and <see cref="FirmwareDisplayId"/> are null because
/// this route never talks to Android or to the loader.
/// </summary>
public sealed record GlobalEdlIdentity(
    string ProfileId,
    string Model,
    string HardwareId,
    string BusSerialHex,
    string? AndroidSerial = null,
    string? FirmwareDisplayId = null);

/// <summary>
/// Read-only offline binding for global rescue backup/restore. It reads the single currently present
/// <c>VID_05C6/PID_9008</c> instance once and reports the candidate bus serial of that endpoint.
/// <para>
/// A binding produced here is a candidate only: the profile is a known built-in definition and the serial is
/// whatever the current bus reports. Nothing in this class proves the hardware, a loaded loader or a Firehose
/// session; that agreement is established only by a later probe of the running device.
/// </para>
/// <para>
/// No ADB command, reboot, loader upload or client command is issued: only
/// <see cref="IEdlEndpointDiscovery.ReadPresent"/> is called once. Because there is no Android identity on
/// this limited route, the returned <see cref="EdlEntryResult.AndroidIdentity"/> is absent and
/// <see cref="EdlEntryResult.OfflineIdentity"/> is set instead. No Android serial, firmware display id or
/// SoC serial is fabricated from the USB description.
/// </para>
/// </summary>
public static class GlobalEdlBinding
{
    private const string EdlVid = "VID_05C6";
    private const string EdlPid = "PID_9008";
    private const string SnLabel = "SN:";
    private const int SnHexLength = 8;
    private const string ZeroSerial = "00000000";
    private const string BroadcastSerial = "FFFFFFFF";

    /// <summary>
    /// Reads the present endpoints once and returns the candidate offline binding for exactly one physical
    /// 9008 instance of the requested known profile whose every interface description agrees on one nonzero,
    /// non-broadcast 8-digit hex serial.
    /// <para>
    /// This is only a candidate binding of the requested known profile plus the serial the current bus
    /// reports. It does not prove the hardware: hardware agreement (Sahara serial, hardware id and the
    /// loader-started marker) is established only by the subsequent initial Sahara probe, never by this call.
    /// The endpoint-only part is <see cref="ReadEndpoint"/>; this method adds the profile identity and does
    /// not change the endpoint rules.
    /// </para>
    /// </summary>
    /// <param name="profile">Complete profile that must be the exact known registry object for its id.</param>
    /// <param name="discovery">Read-only endpoint source; only <c>ReadPresent</c> is used.</param>
    /// <param name="expectedBusSerialHex">
    /// Optional caller expectation: exactly eight hex digits, never trimmed, and it must equal the observed
    /// value.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="profile"/> or <paramref name="discovery"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The profile, endpoint set or bus serial is not accepted.</exception>
    public static EdlEntryResult Attach(
        EdlDeviceProfile profile,
        IEdlEndpointDiscovery discovery,
        string? expectedBusSerialHex = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(discovery);

        if (!ReferenceEquals(EdlDeviceProfiles.FindById(profile.ProfileId), profile))
        {
            throw new InvalidOperationException(
                $"Offline EDL binding requires a known built-in profile, got '{profile.ProfileId}'.");
        }

        profile.RequireComplete();

        string hardwareId = profile.FullHardwareId ?? string.Empty;
        if (!IsUsableHardwareId(hardwareId))
        {
            throw new InvalidOperationException(
                $"Offline EDL binding requires a non-blank hardware id without whitespace or control " +
                $"characters for profile '{profile.ProfileId}'.");
        }

        (EdlEndpoint endpoint, string busSerial) = ReadEndpoint(discovery, expectedBusSerialHex);

        // AndroidIdentity is deliberately null here: this route has no Android proof to report.
        return new EdlEntryResult(null!, endpoint, busSerial)
        {
            OfflineIdentity = new GlobalEdlIdentity(
                profile.ProfileId,
                profile.Model,
                hardwareId,
                busSerial),
        };
    }

    /// <summary>
    /// Endpoint-only candidate read: enumerates the present endpoints once and returns the sole physical
    /// 9008 instance together with the 8-digit uppercase hex serial every interface of that instance agrees
    /// on.
    /// <para>
    /// This reports a candidate only. It proves that exactly one <c>VID_05C6/PID_9008</c> instance is present
    /// and that its interfaces agree on one addressable bus serial; it proves nothing about the hardware, the
    /// profile, a loaded loader or Firehose readiness.
    /// </para>
    /// <para>
    /// A caller expectation is validated before the single read, so a malformed value never reaches endpoint
    /// enumeration; a well-formed but different value fails after that one read. No command is issued here.
    /// </para>
    /// </summary>
    /// <param name="discovery">Read-only endpoint source; only <c>ReadPresent</c> is used.</param>
    /// <param name="expectedBusSerialHex">
    /// Optional caller expectation: exactly eight hex digits, never trimmed, and it must equal the observed
    /// value.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="discovery"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The endpoint set or bus serial is not accepted.</exception>
    public static (EdlEndpoint Endpoint, string BusSerialHex) ReadEndpoint(
        IEdlEndpointDiscovery discovery,
        string? expectedBusSerialHex = null)
    {
        ArgumentNullException.ThrowIfNull(discovery);

        string? expected = expectedBusSerialHex is null
            ? null
            : NormalizeBusSerial(expectedBusSerialHex, "expected bus serial");

        IReadOnlyList<EdlEndpoint> present = discovery.ReadPresent() ?? Array.Empty<EdlEndpoint>();

        List<EdlEndpoint> candidates = present
            .Where(endpoint => endpoint is not null && IsEdlInstance(endpoint.DeviceInstanceId))
            .ToList();

        List<IGrouping<string, EdlEndpoint>> groups = candidates
            .GroupBy(endpoint => endpoint.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (groups.Count != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one present EDL device instance, found {groups.Count}.");
        }

        List<EdlEndpoint> endpoints = groups[0].ToList();

        string? observed = null;

        foreach (EdlEndpoint endpoint in endpoints)
        {
            string serial = ParseBusSerial(endpoint.BusReportedDeviceDescription);

            if (observed is null)
            {
                observed = serial;
                continue;
            }

            if (!string.Equals(observed, serial, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"The EDL instance reports conflicting bus serials {observed} and {serial}.");
            }
        }

        // The group is built from candidates, so at least one description was parsed.
        string busSerial = observed!;

        if (expected is not null && !string.Equals(expected, busSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The present EDL endpoint reports bus serial {busSerial}, expected {expected}.");
        }

        return (endpoints[0], busSerial);
    }

    private static bool IsEdlInstance(string? deviceInstanceId) =>
        !string.IsNullOrEmpty(deviceInstanceId) &&
        deviceInstanceId.IndexOf(EdlVid, StringComparison.OrdinalIgnoreCase) >= 0 &&
        deviceInstanceId.IndexOf(EdlPid, StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool IsUsableHardwareId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        foreach (char character in value)
        {
            if (char.IsWhiteSpace(character) || char.IsControl(character))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Extracts the bus serial from a description such as <c>QUSB_BULK_CID:045A_SN:C1D2E3F4</c> using the same
    /// underscore-token grammar as <see cref="EdlClient"/>: the description is split on <c>_</c>, exactly one
    /// token must start with the case-insensitive <c>SN:</c> label, and that token's remainder must be exactly
    /// eight hex digits. A missing, duplicated, short, long or non-hex value is unusable and nothing is
    /// trimmed. Zero and broadcast serials are unusable.
    /// </summary>
    private static string ParseBusSerial(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            throw new InvalidOperationException(
                "An EDL endpoint reports no bus description, so the bus serial cannot be proven.");
        }

        string[] tokens = description.Split('_');
        int labels = 0;
        string? value = null;

        foreach (string token in tokens)
        {
            if (token.StartsWith(SnLabel, StringComparison.OrdinalIgnoreCase))
            {
                labels++;
                value = token.Substring(SnLabel.Length);
            }
        }

        if (labels != 1)
        {
            throw new InvalidOperationException(
                $"The EDL bus description '{description}' must contain exactly one {SnLabel} label, found " +
                $"{labels}.");
        }

        if (!IsBusSerialHex(value))
        {
            throw new InvalidOperationException(
                $"The EDL bus description '{description}' does not carry an exactly {SnHexLength}-digit " +
                "hex serial.");
        }

        return NormalizeBusSerial(value, "EDL bus serial");
    }

    /// <summary>Strict 8-hex value: no trimming, and zero or broadcast serials are unusable.</summary>
    private static string NormalizeBusSerial(string? value, string description)
    {
        if (!IsBusSerialHex(value))
        {
            throw new InvalidOperationException(
                $"The {description} '{value ?? "<none>"}' is not exactly {SnHexLength} hex digits.");
        }

        string normalized = value!.ToUpperInvariant();

        if (string.Equals(normalized, ZeroSerial, StringComparison.Ordinal) ||
            string.Equals(normalized, BroadcastSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The {description} '{value}' is not a usable EDL bus serial (zero or broadcast).");
        }

        return normalized;
    }

    private static bool IsBusSerialHex(string? value)
    {
        if (value is null || value.Length != SnHexLength)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHexDigit(char character) =>
        character is >= '0' and <= '9'
            or >= 'a' and <= 'f'
            or >= 'A' and <= 'F';
}
