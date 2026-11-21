using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FreedomInstaller.Core;

public sealed record OfflineUpdateUsbEndpoint(
    string AdapterId,
    string DeviceInstanceId,
    string Host,
    string LocalAddress);

public static class OfflineUpdateUsbDiscovery
{
    public const string DeviceHost = "172.16.42.1";
    private const int MaxJsonBytes = 1024 * 1024;
    private const int DiagnosticsLimit = 2048;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    // Anchored USB PNP id: VID_1D6B PID_0104|0100, optional REV_XXXX before optional MI_XX, non-empty instance.
    private static readonly Regex UsbGadgetId = new(
        @"\AUSB\\VID_1D6B&PID_(0104|0100)(&REV_[0-9A-F]{4})?(&MI_[0-9A-F]{2})?\\[^\r\n]+\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    private const string QueryScript =
        "$ErrorActionPreference='Stop';" +
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;" +
        "$adapters=Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 -and $_.PNPDeviceID -like 'USB*' };" +
        "$configs=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled };" +
        "$rows=@();" +
        "foreach ($a in $adapters) { $c = $configs | Where-Object { $_.Index -eq $a.Index }; " +
        "if ($null -ne $c) { for ($i = 0; $i -lt $c.IPAddress.Count; $i++) { " +
        "$rows += [pscustomobject]@{ id = [string]$a.GUID; pnpDeviceId = [string]$a.PNPDeviceID; " +
        "address = [string]$c.IPAddress[$i]; mask = [string]$c.IPSubnet[$i] } } } };" +
        "$result = @{ schemaVersion = 1; adapters = $rows };" +
        "[Console]::Out.Write(($result | ConvertTo-Json -Compress -Depth 4))";

    public static ProcessCommand BuildCommand(string? powershellExecutable = null)
    {
        var executable = powershellExecutable;
        if (executable is null)
        {
            if (!OperatingSystem.IsWindows())
                throw new IOException("No default PowerShell executable is available on this platform; supply the absolute path explicitly.");
            executable = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!Path.IsPathFullyQualified(executable))
                throw new IOException("The default PowerShell path could not be resolved to a fully qualified path.");
        }
        else
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(executable);
            if (executable.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                throw new ArgumentException("PowerShell executable must not contain newline or null characters.", nameof(powershellExecutable));
            if (!Path.IsPathFullyQualified(executable))
                throw new ArgumentException("PowerShell executable must be a fully qualified path.", nameof(powershellExecutable));
        }

        return new ProcessCommand(
            executable,
            new[] { "-NoProfile", "-NonInteractive", "-Command", QueryScript },
            QueryTimeout);
    }

    public static IReadOnlyList<OfflineUpdateUsbEndpoint> ParseCandidates(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
            throw new InvalidDataException($"Adapter JSON exceeds the {MaxJsonBytes}-byte limit.");

        using var doc = JsonDocument.Parse(json); // throws JsonException on malformed JSON
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Adapter JSON root must be an object.");
        if (!root.TryGetProperty("schemaVersion", out var schema) ||
            schema.ValueKind != JsonValueKind.Number ||
            !schema.TryGetInt32(out var version) || version != 1)
        {
            throw new InvalidDataException("Adapter JSON envelope must carry schemaVersion 1.");
        }
        if (!root.TryGetProperty("adapters", out var adapters) ||
            adapters.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Adapter JSON envelope must contain an adapters array.");
        }

        var found = new List<OfflineUpdateUsbEndpoint>();
        foreach (var row in adapters.EnumerateArray())
        {
            if (TryParseRow(row, out var endpoint))
                found.Add(endpoint);
        }

        return found
            .GroupBy(e => (e.AdapterId, e.LocalAddress))
            .Select(g => g.First())
            .OrderBy(e => e.AdapterId, StringComparer.Ordinal)
            .ThenBy(e => e.LocalAddress, StringComparer.Ordinal)
            .ToList();
    }

    private static bool TryParseRow(JsonElement row, out OfflineUpdateUsbEndpoint endpoint)
    {
        endpoint = null!;
        if (row.ValueKind != JsonValueKind.Object)
            return false;
        if (!row.TryGetProperty("id", out var idEl) || idEl.ValueKind != JsonValueKind.String)
            return false;
        var id = idEl.GetString()!;
        if (string.IsNullOrWhiteSpace(id) || !Guid.TryParse(id, out var parsedGuid) || parsedGuid == Guid.Empty)
            return false;
        if (!row.TryGetProperty("pnpDeviceId", out var pnpEl) || pnpEl.ValueKind != JsonValueKind.String)
            return false;
        var pnp = pnpEl.GetString()!;
        if (string.IsNullOrEmpty(pnp) || !UsbGadgetId.IsMatch(pnp))
            return false;
        if (!row.TryGetProperty("address", out var addrEl) || addrEl.ValueKind != JsonValueKind.String)
            return false;
        var address = addrEl.GetString()!;
        if (!TryParseUsbIpv4(address, out var parsed))
            return false;
        if (!row.TryGetProperty("mask", out var maskEl) || maskEl.ValueKind != JsonValueKind.String)
            return false;
        if (maskEl.GetString()! != "255.255.255.0")
            return false;

        endpoint = new OfflineUpdateUsbEndpoint(parsedGuid.ToString("D"), pnp, DeviceHost, parsed);
        return true;
    }

    private static bool TryParseUsbIpv4(string input, out string canonical)
    {
        canonical = string.Empty;
        if (input.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0)
            return false;
        if (!IPAddress.TryParse(input, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        canonical = ip.ToString();
        if (!string.Equals(canonical, input, StringComparison.Ordinal))
            return false; // rejects short forms, octal, leading zeros
        var bytes = ip.GetAddressBytes();
        return bytes[0] == 172 && bytes[1] == 16 && bytes[2] == 42 && bytes[3] is >= 2 and <= 254;
    }

    public static async Task<OfflineUpdateUsbEndpoint> FindSingleAsync(
        ICommandRunner runner,
        string? powershellExecutable = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(runner);
        token.ThrowIfCancellationRequested();

        // macOS has no PowerShell/CIM; the I/O Registry gives the same USB-device-to-adapter proof there.
        if (powershellExecutable is null && OperatingSystem.IsMacOS())
            return await OfflineUpdateMacUsbDiscovery.FindSingleAsync(runner, token).ConfigureAwait(false);

        var command = BuildCommand(powershellExecutable);
        var result = await runner.RunAsync(command, token).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            var diagnostics = ((result.StandardError ?? string.Empty) + " " + (result.StandardOutput ?? string.Empty)).Trim();
            if (diagnostics.Length > DiagnosticsLimit)
                diagnostics = diagnostics[^DiagnosticsLimit..];
            throw new IOException(
                $"USB adapter query failed with exit code {result.ExitCode}. {diagnostics}");
        }

        var candidates = ParseCandidates(result.StandardOutput ?? string.Empty);
        return candidates.Count switch
        {
            0 => throw new IOException(
                "No offline-update USB network adapter was detected. Ensure the device is connected via USB with the network gadget enabled."),
            1 => candidates[0],
            _ => throw new IOException(
                $"Multiple ({candidates.Count}) offline-update USB network adapters were detected; exactly one is required. " +
                "Disconnect the extra devices or disambiguate manually."),
        };
    }
}
