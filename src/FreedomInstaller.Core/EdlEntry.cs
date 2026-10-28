using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One USB endpoint that Windows currently reports for the EDL gadget. The description is the raw
/// bus-reported string, which is the only place the EDL serial can appear.
/// </summary>
public sealed record EdlEndpoint(
    string DeviceInstanceId,
    string? PortName,
    string? BusReportedDeviceDescription);

/// <summary>
/// Read-only source of the EDL endpoints Windows sees. Implementations only enumerate; they never
/// open a device, send a command or touch a COM port.
/// </summary>
public interface IEdlEndpointDiscovery
{
    IReadOnlyList<EdlEndpoint> ReadPresent();
}

/// <summary>
/// Proof that the device reached EDL mode. This says only that a matching endpoint exists; it says
/// nothing about Firehose readiness, a loaded loader or boot validity.
/// </summary>
public sealed record EdlEntryResult(
    AndroidMaintenanceIdentity AndroidIdentity,
    EdlEndpoint Endpoint,
    string BusSerialHex)
{
    /// <summary>
    /// Offline 9008-only identity, set only by <see cref="GlobalEdlBinding.Attach"/>. That limited route has
    /// no Android proof, so <see cref="AndroidIdentity"/> is absent (null) there and no Android serial or
    /// firmware is invented. Every Android route leaves this null.
    /// </summary>
    public GlobalEdlIdentity? OfflineIdentity { get; init; }
}

/// <summary>
/// Enters EDL mode from a caller-supplied Android identity by rebooting once into <c>edl</c> and then
/// polling the present USB endpoints for the matching 9008 gadget.
/// <para>
/// The returned proof is limited to the USB connection itself: the sole present
/// <c>VID_05C6/PID_9008</c> instance must report the same SoC serial that Android reported as an
/// 8-digit hex value, and every duplicate description of that instance must agree. Firehose readiness,
/// a loaded loader and boot validity are outside this class and are never inferred here.
/// </para>
/// </summary>
public sealed class EdlEntry
{
    /// <summary>Timeout of the single <c>adb reboot edl</c> command.</summary>
    public static readonly TimeSpan RebootTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Upper bound for the endpoint discovery window.</summary>
    public static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(90);

    /// <summary>Delay between two endpoint queries.</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private const string SnLabel = "SN:";
    private const int SnHexLength = 8;

    private string AdbPath { get; }

    private ICommandRunner Runner { get; }

    private IEdlEndpointDiscovery EndpointDiscovery { get; }

    private TimeProvider Clock { get; }

    public EdlEntry(
        string adbPath,
        ICommandRunner runner,
        IEdlEndpointDiscovery endpointDiscovery,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adbPath);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(endpointDiscovery);

        AdbPath = adbPath;
        Runner = runner;
        EndpointDiscovery = endpointDiscovery;
        Clock = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Validates the caller's Android identity, issues exactly one <c>adb -s &lt;serial&gt; reboot edl</c>
    /// and then polls the present USB endpoints until the matching 9008 gadget proves the expected SoC serial.
    /// <para>
    /// Input guard failures happen before any command and surface as <see cref="InvalidOperationException"/>.
    /// A non-zero reboot exit surfaces as <see cref="IOException"/> with the captured diagnostic; command
    /// timeouts, provider errors and caller cancellation propagate unchanged, and nothing is retried.
    /// The bootloader lock state is deliberately not inspected: any state that reached Android may enter EDL.
    /// </para>
    /// <para>
    /// While polling, an empty result is bounded by <see cref="DiscoveryTimeout"/> and an endpoint set that
    /// is present but ambiguous or carries an unknown, malformed or mismatching bus serial fails immediately
    /// with <see cref="InvalidOperationException"/>. No second reboot and no fallback route is ever attempted.
    /// </para>
    /// <para>
    /// This route forwards to the exact existing G4 profile, <see cref="EdlDeviceProfiles.Default"/>, so its
    /// behavior is unchanged; callers that hold a trusted profile use the explicit overload instead.
    /// </para>
    /// </summary>
    public Task<EdlEntryResult> EnterAsync(
        AndroidMaintenanceIdentity android,
        CancellationToken token = default) =>
        EnterAsync(android, EdlDeviceProfiles.Default, token);

    /// <summary>
    /// The explicit-profile variant of <see cref="EnterAsync(AndroidMaintenanceIdentity, CancellationToken)"/>.
    /// <para>
    /// The profile is re-resolved from <see cref="EdlDeviceProfiles.FindById"/> and must be that exact
    /// instance, complete, and supporting the caller's identity. All of those checks, plus the serial
    /// checks, run before the reboot command and before any endpoint read, so a null, unknown, incomplete
    /// or non-matching profile can never reach a runner command or a discovery query. The reboot, polling,
    /// correlation and no-retry behavior are identical to the default route.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="android"/> or <paramref name="profile"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The profile or identity is not accepted for this device.</exception>
    public async Task<EdlEntryResult> EnterAsync(
        AndroidMaintenanceIdentity android,
        EdlDeviceProfile profile,
        CancellationToken token = default)
    {
        if (android is null)
        {
            throw new ArgumentNullException(nameof(android));
        }

        ArgumentNullException.ThrowIfNull(profile);

        DeviceIdentity identity = android.Identity
            ?? throw new ArgumentException("Android identity must not be null.", nameof(android));

        string serial = ValidateIdentity(identity, profile);
        string expectedBusSerial = ExpectedBusSerial(android.SocSerial);

        token.ThrowIfCancellationRequested();

        ProcessResult reboot = await Runner
            .RunAsync(
                new ProcessCommand(AdbPath, new[] { "-s", serial, "reboot", "edl" }, RebootTimeout),
                token)
            .ConfigureAwait(false);

        if (reboot.ExitCode != 0)
        {
            throw new IOException(
                $"adb reboot edl for serial {serial} failed with exit code {reboot.ExitCode}: {Describe(reboot)}");
        }

        return await WaitForEndpointAsync(android, serial, expectedBusSerial, token).ConfigureAwait(false);
    }

    /// <summary>
    /// Observes the EDL endpoint that is already present, or that returns after some other component
    /// restarted the device into EDL, without issuing any command of its own. This is the read-only
    /// counterpart of <see cref="EnterAsync"/>: it never sends an ADB command, never reboots, never talks
    /// to the loader and never asserts Firehose readiness.
    /// <para>
    /// The same identity guards apply and the same single-instance/bus-serial proof is required, so a
    /// successful result means only that the sole matching <c>VID_05C6/PID_9008</c> endpoint is bound to
    /// the caller's identity. Nothing about a preceding reboot is fabricated or inferred.
    /// </para>
    /// <para>
    /// Input guard failures surface as <see cref="InvalidOperationException"/> before the first endpoint
    /// read. An empty present set is bounded by <see cref="DiscoveryTimeout"/>, an absent endpoint at the
    /// deadline surfaces as <see cref="TimeoutException"/>, an ambiguous or serial-mismatching present set
    /// fails immediately, and caller cancellation propagates unchanged. Nothing is retried.
    /// </para>
    /// <para>
    /// This route forwards to the exact existing G4 profile, <see cref="EdlDeviceProfiles.Default"/>, so its
    /// behavior is unchanged; callers that hold a trusted profile use the explicit overload instead.
    /// </para>
    /// </summary>
    public Task<EdlEntryResult> WaitForPresentAsync(
        AndroidMaintenanceIdentity android,
        CancellationToken token = default) =>
        WaitForPresentAsync(android, EdlDeviceProfiles.Default, token);

    /// <summary>
    /// The explicit-profile variant of <see cref="WaitForPresentAsync(AndroidMaintenanceIdentity, CancellationToken)"/>.
    /// The same known-instance, completeness and identity checks run before the first endpoint read, and the
    /// route still sends no command of its own: it never reboots and never talks to the loader.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="android"/> or <paramref name="profile"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The profile or identity is not accepted for this device.</exception>
    public async Task<EdlEntryResult> WaitForPresentAsync(
        AndroidMaintenanceIdentity android,
        EdlDeviceProfile profile,
        CancellationToken token = default)
    {
        if (android is null)
        {
            throw new ArgumentNullException(nameof(android));
        }

        ArgumentNullException.ThrowIfNull(profile);

        DeviceIdentity identity = android.Identity
            ?? throw new ArgumentException("Android identity must not be null.", nameof(android));

        string serial = ValidateIdentity(identity, profile);
        string expectedBusSerial = ExpectedBusSerial(android.SocSerial);

        token.ThrowIfCancellationRequested();

        return await WaitForEndpointAsync(android, serial, expectedBusSerial, token).ConfigureAwait(false);
    }

    /// <summary>
    /// The single polling body shared by both public entry routes. It only reads the present endpoints and
    /// never issues a command, so neither route can gain a second transport path from it.
    /// </summary>
    private async Task<EdlEntryResult> WaitForEndpointAsync(
        AndroidMaintenanceIdentity android,
        string serial,
        string expectedBusSerial,
        CancellationToken token)
    {
        long started = Clock.GetTimestamp();
        TimeSpan elapsed = Clock.GetElapsedTime(started);

        // The window is tested before every provider read and again after it returns, so a query that
        // answers at or past the deadline can never be accepted as a positive proof.
        while (elapsed < DiscoveryTimeout)
        {
            token.ThrowIfCancellationRequested();

            IReadOnlyList<EdlEndpoint> present = EndpointDiscovery.ReadPresent();

            // Cancellation can land inside the provider, so it is checked again before the result is used.
            token.ThrowIfCancellationRequested();

            elapsed = Clock.GetElapsedTime(started);
            if (elapsed >= DiscoveryTimeout)
            {
                break;
            }

            IReadOnlyList<EdlEndpoint> candidates = WindowsEdlEndpointDiscovery.FilterCandidates(present);
            if (candidates.Count > 0)
            {
                return ProveEndpoint(android, candidates, expectedBusSerial);
            }

            TimeSpan remaining = DiscoveryTimeout - elapsed;
            TimeSpan delay = remaining < PollInterval ? remaining : PollInterval;

            // The deadline is measured on the injected clock, but the wait itself stays an ordinary
            // cancellation-aware delay so a manual test clock only has to provide timestamps.
            await Task.Delay(delay, token).ConfigureAwait(false);

            elapsed = Clock.GetElapsedTime(started);
        }

        throw new TimeoutException(
            $"No EDL endpoint for serial {serial} appeared within {DiscoveryTimeout.TotalSeconds:0.###} seconds.");
    }

    /// <summary>
    /// Rejects any profile that is not the exact built-in instance selected by its id, any incomplete
    /// profile, and any identity the profile does not support exactly. The serial must also be a single
    /// token without whitespace or control characters. The bootloader lock state is intentionally not part
    /// of the check. Callers run this before any runner command or endpoint discovery.
    /// </summary>
    private static string ValidateIdentity(DeviceIdentity identity, EdlDeviceProfile profile)
    {
        if (!ReferenceEquals(EdlDeviceProfiles.FindById(profile.ProfileId), profile))
        {
            throw new InvalidOperationException(
                $"EDL entry requires a known built-in profile, got '{profile.ProfileId}'.");
        }

        profile.RequireComplete();

        if (!profile.SupportsIdentity(identity))
        {
            throw new InvalidOperationException(
                $"EDL profile '{profile.ProfileId}' requires model '{profile.Model}' and one of its exact " +
                $"display ids, got model '{identity.Model ?? "<none>"}' and display id " +
                $"'{identity.Firmware?.DisplayId ?? "<none>"}'.");
        }

        string serial = identity.Serial ?? string.Empty;
        if (serial.Length == 0)
        {
            throw new InvalidOperationException("EDL entry requires a non-empty Android serial.");
        }

        foreach (char character in serial)
        {
            if (char.IsWhiteSpace(character) || char.IsControl(character))
            {
                throw new InvalidOperationException(
                    "EDL entry requires an Android serial without whitespace or control characters.");
            }
        }

        return serial;
    }

    /// <summary>
    /// Converts the Android SoC serial to the only accepted form: an unsigned 32-bit decimal written as
    /// exactly eight uppercase hex digits. Signs, hex prefixes, whitespace and overflow are rejected.
    /// </summary>
    private static string ExpectedBusSerial(string? socSerial)
    {
        if (!uint.TryParse(socSerial, NumberStyles.None, CultureInfo.InvariantCulture, out uint value))
        {
            throw new InvalidOperationException(
                $"SoC serial '{socSerial ?? "<none>"}' is not an unsigned decimal 32-bit value.");
        }

        return value.ToString("X8", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Proves the single present EDL instance. More than one distinct instance is ambiguous even when the
    /// bus serials agree; within one instance every duplicate description is checked, so one good
    /// description can never hide a conflicting, missing or malformed second one.
    /// </summary>
    private static EdlEntryResult ProveEndpoint(
        AndroidMaintenanceIdentity android,
        IReadOnlyList<EdlEndpoint> candidates,
        string expectedBusSerial)
    {
        var groups = candidates
            .GroupBy(candidate => candidate.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (groups.Count != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one present EDL device instance, found {groups.Count}.");
        }

        List<EdlEndpoint> endpoints = groups[0].ToList();

        string? observedBusSerial = null;

        foreach (EdlEndpoint endpoint in endpoints)
        {
            string busSerial = ParseBusSerial(endpoint.BusReportedDeviceDescription);

            if (!string.Equals(busSerial, expectedBusSerial, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"EDL endpoint {endpoint.DeviceInstanceId} reports bus serial {busSerial}, " +
                    $"expected {expectedBusSerial}.");
            }

            observedBusSerial ??= busSerial;
        }

        // Every description of the sole instance agreed, so the first actual endpoint is the proof and the
        // reported serial is the parsed bus value, never the expected one copied in.
        return new EdlEntryResult(
            android,
            endpoints[0],
            observedBusSerial!);
    }

    /// <summary>
    /// Extracts the bus serial from an underscore-delimited description such as
    /// <c>QUSB_BULK_CID:045A_SN:C1D2E3F4</c>. The number of <c>SN:</c> labels is counted first and must be
    /// exactly one; only then is that single value required to be exactly eight hex digits. A missing,
    /// duplicated, short, long or non-hex serial is unusable, and the expected value is never substituted.
    /// </summary>
    private static string ParseBusSerial(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            throw new InvalidOperationException(
                "EDL endpoint reports no bus description, so the SoC serial cannot be proven.");
        }

        string[] tokens = description.Split('_');

        int labels = 0;
        foreach (string token in tokens)
        {
            if (token.StartsWith(SnLabel, StringComparison.OrdinalIgnoreCase))
            {
                labels++;
            }
        }

        if (labels != 1)
        {
            throw new InvalidOperationException(
                $"EDL bus description '{description}' must contain exactly one {SnLabel} label, found {labels}.");
        }

        string? value = null;
        foreach (string token in tokens)
        {
            if (token.StartsWith(SnLabel, StringComparison.OrdinalIgnoreCase))
            {
                value = token.Substring(SnLabel.Length);
            }
        }

        // labels == 1 guarantees a value, but it is still validated rather than assumed.
        if (value is null || value.Length != SnHexLength)
        {
            throw new InvalidOperationException(
                $"EDL bus description '{description}' does not carry an exactly {SnHexLength}-digit hex serial.");
        }

        foreach (char character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                throw new InvalidOperationException(
                    $"EDL bus description '{description}' carries a non-hex serial.");
            }
        }

        return value.ToUpperInvariant();
    }

    /// <summary>The captured error text if there is any, otherwise whatever the command printed.</summary>
    private static string Describe(ProcessResult result)
    {
        string error = result.StandardError.Trim();
        if (error.Length > 0)
        {
            return error;
        }

        string output = result.StandardOutput.Trim();
        return output.Length > 0 ? output : "the command produced no diagnostic output";
    }
}
