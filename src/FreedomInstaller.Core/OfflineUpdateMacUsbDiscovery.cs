using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace FreedomInstaller.Core;

/// <summary>
/// macOS counterpart of <see cref="OfflineUpdateUsbDiscovery"/>: finds the single USB network adapter the
/// tablet's Linux gadget provides. The proof is the same as on Windows, from macOS sources: the I/O Registry
/// (<c>ioreg</c>) ties a network interface's BSD name to its USB device, which must carry the gadget's vendor
/// 0x1D6B and product 0x0104 or 0x0100; the interface must be up with one IPv4 address in 172.16.42.2–254/24.
/// Nothing is configured or written; the tablet itself is always <see cref="OfflineUpdateUsbDiscovery.DeviceHost"/>.
/// </summary>
public static class OfflineUpdateMacUsbDiscovery
{
    private const string IoregExecutable = "/usr/sbin/ioreg";
    private const int GadgetVendor = 0x1D6B;
    private static readonly int[] GadgetProducts = { 0x0104, 0x0100 };
    private const int MaxOutputChars = 16 * 1024 * 1024;
    private const int DiagnosticsLimit = 2048;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    private static readonly Regex NodeLine = new(
        @"^(?<indent>[ |]*)\+-o (?<name>.+?)\s+<class (?<class>[A-Za-z0-9_]+),",
        RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    private static readonly Regex PropertyLine = new(
        "^[ |]*\"(?<key>[^\"]+)\" = (?<value>.*)$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    private static readonly Regex BsdName = new(
        @"\A[a-z]+[0-9]+\z", RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    /// <summary>A gadget USB device and the BSD names of the network interfaces below it.</summary>
    public sealed record GadgetDevice(int ProductId, string? LocationId, IReadOnlyList<string> Interfaces);

    public static ProcessCommand BuildCommand() =>
        new(IoregExecutable, new[] { "-r", "-c", "IOUSBHostDevice", "-l", "-w0" }, QueryTimeout);

    /// <summary>
    /// Parses <c>ioreg -r -c IOUSBHostDevice -l -w0</c>: every USB device with the gadget's vendor and product,
    /// with the BSD names of all interfaces in its subtree. Nodes are nested by the column of their <c>+-o</c>.
    /// </summary>
    public static IReadOnlyList<GadgetDevice> ParseGadgets(string ioregOutput)
    {
        ArgumentNullException.ThrowIfNull(ioregOutput);
        if (ioregOutput.Length > MaxOutputChars)
            throw new InvalidDataException($"ioreg output exceeds the {MaxOutputChars}-character limit.");

        var roots = new List<Node>();
        var stack = new List<Node>();
        foreach (var rawLine in ioregOutput.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var node = NodeLine.Match(line);
            if (node.Success)
            {
                var created = new Node(node.Groups["indent"].Length, node.Groups["class"].Value);
                while (stack.Count > 0 && stack[^1].Column >= created.Column)
                    stack.RemoveAt(stack.Count - 1);
                if (stack.Count == 0)
                    roots.Add(created);
                else
                    stack[^1].Children.Add(created);
                stack.Add(created);
                continue;
            }

            if (stack.Count == 0)
                continue;
            var property = PropertyLine.Match(line);
            if (property.Success)
                stack[^1].Properties.TryAdd(property.Groups["key"].Value, property.Groups["value"].Value.Trim());
        }

        var gadgets = new List<GadgetDevice>();
        foreach (var root in roots)
            CollectGadgets(root, gadgets);
        return gadgets;
    }

    private static void CollectGadgets(Node node, List<GadgetDevice> gadgets)
    {
        if (node.Class == "IOUSBHostDevice"
            && TryInt(node, "idVendor", out var vendor) && vendor == GadgetVendor
            && TryInt(node, "idProduct", out var product) && GadgetProducts.Contains(product))
        {
            var interfaces = new SortedSet<string>(StringComparer.Ordinal);
            CollectInterfaces(node, interfaces);
            node.Properties.TryGetValue("locationID", out var location);
            gadgets.Add(new GadgetDevice(product, location, interfaces.ToList()));
            return;
        }

        foreach (var child in node.Children)
            CollectGadgets(child, gadgets);
    }

    private static void CollectInterfaces(Node node, ISet<string> names)
    {
        if (node.Properties.TryGetValue("BSD Name", out var raw))
        {
            var name = raw.Trim('"');
            if (BsdName.IsMatch(name) && name.StartsWith("en", StringComparison.Ordinal))
                names.Add(name);
        }

        foreach (var child in node.Children)
            CollectInterfaces(child, names);
    }

    private static bool TryInt(Node node, string key, out int value)
    {
        value = 0;
        return node.Properties.TryGetValue(key, out var raw)
            && int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// Pairs gadget interfaces with the host's live interfaces: up, exactly the gadget's BSD name, one IPv4
    /// address in 172.16.42.2–254 with a /24 mask. Same address rule as the Windows discovery.
    /// </summary>
    public static IReadOnlyList<OfflineUpdateUsbEndpoint> MatchEndpoints(
        IReadOnlyList<GadgetDevice> gadgets,
        IEnumerable<(string Name, bool Up, IReadOnlyList<(IPAddress Address, IPAddress Mask)> Ipv4)> interfaces)
    {
        ArgumentNullException.ThrowIfNull(gadgets);
        ArgumentNullException.ThrowIfNull(interfaces);

        var byName = interfaces.ToDictionary(i => i.Name, StringComparer.Ordinal);
        var found = new List<OfflineUpdateUsbEndpoint>();
        foreach (var gadget in gadgets)
        {
            foreach (var name in gadget.Interfaces)
            {
                if (!byName.TryGetValue(name, out var live) || !live.Up)
                    continue;
                foreach (var (address, mask) in live.Ipv4)
                {
                    if (address.AddressFamily != AddressFamily.InterNetwork
                        || !mask.Equals(IPAddress.Parse("255.255.255.0")))
                        continue;
                    var bytes = address.GetAddressBytes();
                    if (bytes[0] != 172 || bytes[1] != 16 || bytes[2] != 42 || bytes[3] is < 2 or > 254)
                        continue;
                    found.Add(new OfflineUpdateUsbEndpoint(
                        name,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"USB\\VID_{GadgetVendor:X4}&PID_{gadget.ProductId:X4}\\{gadget.LocationId ?? name}"),
                        OfflineUpdateUsbDiscovery.DeviceHost,
                        address.ToString()));
                }
            }
        }

        return found
            .GroupBy(e => (e.AdapterId, e.LocalAddress))
            .Select(g => g.First())
            .OrderBy(e => e.AdapterId, StringComparer.Ordinal)
            .ThenBy(e => e.LocalAddress, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>The host's interfaces as the matcher needs them, from the managed network API.</summary>
    public static IReadOnlyList<(string Name, bool Up, IReadOnlyList<(IPAddress Address, IPAddress Mask)> Ipv4)> ReadInterfaces() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Select(nic => (
                nic.Name,
                nic.OperationalStatus == OperationalStatus.Up,
                (IReadOnlyList<(IPAddress, IPAddress)>)nic.GetIPProperties().UnicastAddresses
                    .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && u.IPv4Mask is not null)
                    .Select(u => (u.Address, u.IPv4Mask))
                    .ToList()))
            .ToList();

    /// <summary>Finds exactly one gadget adapter; none or several fail with the same messages as on Windows.</summary>
    public static async Task<OfflineUpdateUsbEndpoint> FindSingleAsync(ICommandRunner runner, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(runner);
        token.ThrowIfCancellationRequested();

        var result = await runner.RunAsync(BuildCommand(), token).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            var diagnostics = ((result.StandardError ?? string.Empty) + " " + (result.StandardOutput ?? string.Empty)).Trim();
            if (diagnostics.Length > DiagnosticsLimit)
                diagnostics = diagnostics[^DiagnosticsLimit..];
            throw new IOException($"USB device query failed with exit code {result.ExitCode}. {diagnostics}");
        }

        var candidates = MatchEndpoints(ParseGadgets(result.StandardOutput ?? string.Empty), ReadInterfaces());
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

    private sealed class Node
    {
        public Node(int column, string @class)
        {
            Column = column;
            Class = @class;
        }

        public int Column { get; }
        public string Class { get; }
        public Dictionary<string, string> Properties { get; } = new(StringComparer.Ordinal);
        public List<Node> Children { get; } = new();
    }
}
