namespace FreedomInstaller.Core;

/// <summary>
/// Parses text that adb / fastboot / getprop already produced. This type never launches a
/// process, never opens a USB handle and never sends a device command.
/// </summary>
public static class DeviceProbe
{
    private const string FastbootPrefix = "(bootloader)";

    /// <summary>The only models this installer accepts. Anything else is not a supported generation.</summary>
    private static readonly string[] SupportedModels = { "TB322FC", "TB323FU" };

    /// <summary>getprop keys that are allowed to name the device model.</summary>
    private static readonly string[] ModelPropertyKeys =
    {
        "ro.product.model",
        "ro.product.vendor.model",
        "ro.product.name",
    };

    /// <summary>
    /// Parses <c>adb devices</c> output into one entry per device line.
    /// <list type="bullet">
    /// <item>the "List of devices attached" header, blank lines and comment lines are not devices;</item>
    /// <item>state "device" maps to <see cref="ConnectionState.Authorized"/>;</item>
    /// <item>state "unauthorized" maps to <see cref="ConnectionState.Unauthorized"/>;</item>
    /// <item>every other recognised transport state (for example "offline") maps to
    /// <see cref="ConnectionState.Offline"/>, so offline stays distinguishable from unauthorized.</item>
    /// </list>
    /// </summary>
    public static IReadOnlyList<ConnectedDevice> ParseAdbDevices(string adbDevicesOutput)
    {
        if (string.IsNullOrWhiteSpace(adbDevicesOutput))
        {
            return Array.Empty<ConnectedDevice>();
        }

        var devices = new List<ConnectedDevice>();

        foreach (var rawLine in adbDevicesOutput.Split('\n'))
        {
            // Trim() also drops the '\r' of CRLF output.
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            // "* daemon not running; starting now at tcp:5037" and friends are status chatter.
            if (line[0] == '*' || line[0] == '#')
            {
                continue;
            }

            if (line.Contains("List of devices attached", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fields = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2)
            {
                continue;
            }

            var serial = fields[0];
            var stateWord = fields[1];

            // "adb devices -l" appends "product:... model:...", so only the second field is the state.
            if (fields.Length > 2
                && string.Equals(fields[1], "no", StringComparison.OrdinalIgnoreCase)
                && fields[2].StartsWith("permissions", StringComparison.OrdinalIgnoreCase))
            {
                stateWord = "no permissions";
            }

            if (serial.Length == 0 || !TryMapAdbState(stateWord, out var state))
            {
                // Not a device line (server banner, version mismatch warning, ...).
                continue;
            }

            devices.Add(new ConnectedDevice(serial, state));
        }

        return devices;
    }

    /// <summary>
    /// Derives the lock state from fastboot output ("unlocked: yes"/"unlocked: no") or from
    /// getprop output ("Device unlocked: true"/"Device unlocked: false").
    /// Keys that contain "critical" are ignored, so "critical unlocked: true" alone stays
    /// <see cref="BootloaderState.Unknown"/>. Conflicting reports and unparsable text also stay Unknown.
    /// </summary>
    public static BootloaderState ParseBootloaderState(string fastbootOrGetpropOutput)
    {
        if (string.IsNullOrWhiteSpace(fastbootOrGetpropOutput))
        {
            return BootloaderState.Unknown;
        }

        var sawUnlockedReport = false;
        var sawLockedReport = false;

        foreach (var rawLine in fastbootOrGetpropOutput.Split('\n'))
        {
            var text = rawLine.Trim();
            if (text.Length == 0)
            {
                continue;
            }

            if (text.StartsWith(FastbootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                text = text[FastbootPrefix.Length..].Trim();
            }

            var separator = text.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var key = CollapseWhitespace(text[..separator]);
            var value = text[(separator + 1)..].Trim();

            // "critical unlocked" and the "secure" flags say nothing about whether writes are allowed.
            if (key.Contains("critical", StringComparison.OrdinalIgnoreCase)
                || key.Contains("secure", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!IsUnlockKey(key))
            {
                continue;
            }

            switch (value.ToLowerInvariant())
            {
                case "yes":
                case "true":
                case "1":
                    sawUnlockedReport = true;
                    break;
                case "no":
                case "false":
                case "0":
                    sawLockedReport = true;
                    break;
                default:
                    // An unrecognised value is not a report, so it neither confirms nor contradicts.
                    break;
            }
        }

        if (sawUnlockedReport && sawLockedReport)
        {
            return BootloaderState.Unknown;
        }

        if (sawUnlockedReport)
        {
            return BootloaderState.Unlocked;
        }

        return sawLockedReport ? BootloaderState.Locked : BootloaderState.Unknown;
    }

    /// <summary>
    /// Returns the canonical model of the ticket, "TB322FC" or "TB323FU", or null when the output
    /// names no supported model. An optional "Lenovo " prefix and a "_PRC" suffix are normalised away.
    /// Only whole tokens match: "TB324ZC" and "NOTTB322FC" are rejected. Two different supported
    /// models in the same getprop dump are a contradiction and also yield null.
    /// </summary>
    public static string? IdentifyModel(string getpropOutput)
    {
        if (string.IsNullOrWhiteSpace(getpropOutput))
        {
            return null;
        }

        // One entry per distinct model token actually reported by a model property.
        var reportedModels = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in getpropOutput.Split('\n'))
        {
            if (!TryReadProperty(rawLine, out var key, out var value))
            {
                continue;
            }

            if (!ModelPropertyKeys.Contains(key, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            var token = NormalizeModelToken(value);
            if (!IsModelShaped(token))
            {
                // Codename style values ("elden"), empty values and unrelated props are not model claims.
                continue;
            }

            reportedModels.Add(token);
        }

        if (reportedModels.Count != 1)
        {
            // No model claim at all, or several different claims: both are "not identified".
            return null;
        }

        return TryCanonicalizeModel(reportedModels.Min!, out var canonical) ? canonical : null;
    }

    /// <summary>
    /// True when <paramref name="model"/> names one of the supported models, after the same
    /// normalisation <see cref="IdentifyModel"/> applies. Shared with the readiness gate so both
    /// layers agree on what "supported" means.
    /// </summary>
    internal static bool IsSupportedModel(string? model) => CanonicalModel(model) is not null;

    /// <summary>
    /// The canonical model name ("TB322FC" or "TB323FU") after the same normalisation
    /// <see cref="IdentifyModel"/> applies, or null when the value names no supported model. Shared with
    /// <see cref="BootRouteAssessment"/> so a route never decides on a differently normalised model string
    /// than the gate does.
    /// </summary>
    internal static string? CanonicalModel(string? model)
    {
        if (string.IsNullOrWhiteSpace(model))
        {
            return null;
        }

        return TryCanonicalizeModel(NormalizeModelToken(model), out var canonical) ? canonical : null;
    }

    internal static bool TryCanonicalizeModel(string token, out string canonical)
    {
        foreach (var model in SupportedModels)
        {
            if (string.Equals(token, model, StringComparison.OrdinalIgnoreCase))
            {
                canonical = model;
                return true;
            }
        }

        canonical = string.Empty;
        return false;
    }

    private static bool TryMapAdbState(string stateWord, out ConnectionState state)
    {
        switch (stateWord.ToLowerInvariant())
        {
            case "device":
                state = ConnectionState.Authorized;
                return true;
            case "unauthorized":
                state = ConnectionState.Unauthorized;
                return true;
            case "offline":
            case "recovery":
            case "sideload":
            case "bootloader":
            case "rescue":
            case "host":
            case "authorizing":
            case "connecting":
            case "no permissions":
                state = ConnectionState.Offline;
                return true;
            default:
                state = ConnectionState.Offline;
                return false;
        }
    }

    private static bool IsUnlockKey(string key) =>
        key.Equals("unlocked", StringComparison.OrdinalIgnoreCase)
        || key.Equals("device unlocked", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads "[key]: [value]" (getprop) and "key=value" (properties file, older dumps). Shared with
    /// <see cref="FirmwareProbe"/> so both parsers read a getprop dump exactly the same way.
    /// </summary>
    internal static bool TryReadProperty(string rawLine, out string key, out string value)
    {
        key = string.Empty;
        value = string.Empty;

        var text = rawLine.Trim();
        if (text.Length == 0)
        {
            return false;
        }

        if (text[0] == '[')
        {
            var close = text.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            key = text[1..close].Trim();

            var rest = text[(close + 1)..].Trim();
            if (rest.StartsWith(':'))
            {
                rest = rest[1..].Trim();
            }

            if (rest.Length >= 2 && rest[0] == '[' && rest[^1] == ']')
            {
                rest = rest[1..^1];
            }

            value = rest.Trim();
            return key.Length > 0;
        }

        var equals = text.IndexOf('=');
        if (equals > 0)
        {
            key = text[..equals].Trim();
            value = text[(equals + 1)..].Trim();
            return key.Length > 0;
        }

        return false;
    }

    private static string NormalizeModelToken(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var token = CollapseWhitespace(raw);

        const string VendorPrefix = "Lenovo";
        while (token.StartsWith(VendorPrefix, StringComparison.OrdinalIgnoreCase))
        {
            token = token[VendorPrefix.Length..].TrimStart();
        }

        const string RegionSuffix = "_PRC";
        while (token.EndsWith(RegionSuffix, StringComparison.OrdinalIgnoreCase))
        {
            token = token[..^RegionSuffix.Length].TrimEnd();
        }

        return token.Trim();
    }

    /// <summary>Whole-token match only: two leading letters, three digits, optional letter suffix.</summary>
    private static bool IsModelShaped(string token)
    {
        if (token.Length < 5 || token.Length > 8)
        {
            return false;
        }

        if (!char.IsAsciiLetter(token[0]) || !char.IsAsciiLetter(token[1]))
        {
            return false;
        }

        for (var index = 2; index < 5; index++)
        {
            if (!char.IsAsciiDigit(token[index]))
            {
                return false;
            }
        }

        for (var index = 5; index < token.Length; index++)
        {
            if (!char.IsAsciiLetter(token[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static string CollapseWhitespace(string value)
    {
        var parts = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', parts);
    }
}
