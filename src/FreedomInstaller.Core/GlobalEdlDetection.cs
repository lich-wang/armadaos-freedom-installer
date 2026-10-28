using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Automatic EDL profile detection over the offline 9008 route: one reviewed client command reports the
/// hardware id of the present device, and that id selects exactly one complete built-in profile.
/// <para>
/// The result is a profile candidate, not a device proof. It says that the single present
/// <c>VID_05C6/PID_9008</c> instance kept the same PnP instance id and bus serial across the identify
/// command, that the command exited 0 with the reviewed identity line, and that the reported hardware id is
/// the full hardware id of one built-in profile. It says nothing about Firehose readiness, a loaded loader,
/// firmware or build identity, and no retry or fallback route exists here.
/// </para>
/// <para>
/// Exactly one external command is issued, without any loader argument: no loader, read, write, reset, ADB
/// or Firehose operation is reachable from this class.
/// </para>
/// </summary>
public static class GlobalEdlDetection
{
    /// <summary>The reviewed identity marker; only a line starting with it is considered at all.</summary>
    private const string IdentityMarker = "ARMADA_EDL_IDENTITY_V1";

    private const string ZeroSerial = "00000000";
    private const string BroadcastSerial = "FFFFFFFF";
    private const string ZeroHardwareId = "0000000000000000";
    private const string BroadcastHardwareId = "FFFFFFFFFFFFFFFF";

    /// <summary>The fixed, finite timeout of the single identify command.</summary>
    private static readonly TimeSpan IdentifyTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The complete identity line: the marker, one space, <c>serial=</c> followed by exactly eight hex digits,
    /// one space, <c>hwid=</c> followed by exactly sixteen hex digits, and nothing else on the line.
    /// </summary>
    private static readonly Regex IdentityLineRegex = new(
        @"\AARMADA_EDL_IDENTITY_V1 serial=(?<sn>[0-9A-Fa-f]{8}) hwid=(?<hwid>[0-9A-Fa-f]{16})\z",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// Detects the built-in EDL profile of the single present 9008 device by reading that endpoint, running
    /// exactly one <c>identify</c> command, and mapping the reported full hardware id through
    /// <see cref="EdlDeviceProfiles.Models"/> and <see cref="EdlDeviceProfiles.FindByModel"/>.
    /// <para>
    /// The endpoint is read before the process, so an absent, ambiguous or serial-less device fails without
    /// starting anything, and a caller expectation is enforced at that first read. The command is then the
    /// fixed argv <c>--pid 9008 --loglevel Debug identify</c> with a 30 second timeout, run once in the
    /// client's own directory. Afterwards the endpoint is read again and must still be the same PnP instance
    /// with the same bus serial, which must also equal the serial the command reported.
    /// </para>
    /// <para>
    /// Only standard output is parsed. A single exact identity line is accepted, ordinary tool log lines may
    /// be interleaved, and any duplicated, prefixed, suffixed or otherwise malformed variant is rejected
    /// instead of partially parsed. A non-zero exit code is a failure regardless of what was printed. Zero and
    /// broadcast serials or hardware ids, and a hardware id that matches no profile or more than one, are
    /// rejected; no firmware, CID or loader-based substitute is ever attempted.
    /// </para>
    /// </summary>
    /// <param name="clientPath">
    /// Fully qualified path of the staged EDL client. The file must exist; its content is not read or pinned
    /// here because the caller already loaded it through <see cref="EdlToolchain.LoadAsync"/>.
    /// </param>
    /// <param name="runner">Process boundary; the fake in tests never starts a real client.</param>
    /// <param name="discovery">Read-only endpoint source; <c>ReadPresent</c> is used twice.</param>
    /// <param name="expectedBusSerialHex">
    /// Optional caller expectation: exactly eight hex digits, never trimmed, enforced at the first endpoint
    /// read before any command exists.
    /// </param>
    /// <param name="cancellationToken">
    /// Caller cancellation; it is checked before the first read, before the command and before the second read,
    /// and surfaces as <see cref="OperationCanceledException"/> unchanged.
    /// </param>
    /// <returns>The single complete built-in profile whose full hardware id was reported.</returns>
    /// <exception cref="ArgumentException"><paramref name="clientPath"/> is blank or not fully qualified.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="runner"/> or <paramref name="discovery"/> is null.</exception>
    /// <exception cref="FileNotFoundException">The client file does not exist.</exception>
    /// <exception cref="InvalidOperationException">The endpoint, command result or identity is not accepted.</exception>
    public static async Task<EdlDeviceProfile> DetectAsync(
        string clientPath,
        ICommandRunner runner,
        IEdlEndpointDiscovery discovery,
        string? expectedBusSerialHex = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientPath))
        {
            throw new ArgumentException("A non-blank EDL client path is required.", nameof(clientPath));
        }

        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(discovery);

        if (!Path.IsPathFullyQualified(clientPath))
        {
            throw new ArgumentException(
                $"The EDL client path '{clientPath}' must be fully qualified.", nameof(clientPath));
        }

        if (!File.Exists(clientPath))
        {
            throw new FileNotFoundException(
                $"The EDL client '{clientPath}' does not exist; a staged client file is required.",
                clientPath);
        }

        cancellationToken.ThrowIfCancellationRequested();

        // The endpoint comes first: an absent, ambiguous or serial-less device never starts a process.
        (EdlEndpoint before, string busSerial) = GlobalEdlBinding.ReadEndpoint(discovery, expectedBusSerialHex);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessCommand command = new(
            clientPath,
            new[] { "--pid", "9008", "--loglevel", "Debug", "identify" },
            IdentifyTimeout)
        {
            WorkingDirectory = Path.GetDirectoryName(clientPath),
        };

        ProcessResult result = await runner.RunAsync(command, cancellationToken).ConfigureAwait(false);

        // The exit code is the only failure signal: no failure marker is scanned for and no retry exists.
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The EDL identify command exited with code {result.ExitCode}: {Describe(result)}");
        }

        (string serialHex, string hardwareIdHex) = ReadIdentity(result.StandardOutput);

        // The transport must not have changed under the command, otherwise the identity belongs to nothing.
        (EdlEndpoint after, string afterSerial) = GlobalEdlBinding.ReadEndpoint(discovery);

        if (!string.Equals(after.DeviceInstanceId, before.DeviceInstanceId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The present EDL instance changed from '{before.DeviceInstanceId}' to " +
                $"'{after.DeviceInstanceId}' while the identify command ran.");
        }

        if (!string.Equals(afterSerial, busSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The present EDL bus serial changed from {busSerial} to {afterSerial} while the identify " +
                "command ran.");
        }

        if (!string.Equals(serialHex, afterSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The identify command reported serial {serialHex}, but the present EDL endpoint reports " +
                $"{afterSerial}.");
        }

        return ResolveProfile(hardwareIdHex);
    }

    /// <summary>
    /// Reads the single exact identity line from standard output. Every line containing the marker must be a
    /// complete, well-formed identity line; zero such lines and more than one are both rejected, so a
    /// lookalike cannot stand in for a missing marker and a duplicated line cannot be deduplicated into one.
    /// The serial and hardware id are returned uppercase, the same form <see cref="EdlClient"/> uses.
    /// </summary>
    private static (string SerialHex, string HardwareIdHex) ReadIdentity(string? standardOutput)
    {
        string? serial = null;
        string? hardwareId = null;
        int identities = 0;

        foreach (string rawLine in (standardOutput ?? string.Empty).Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');

            // Ordinary tool log lines are ignored; only a line carrying the marker is judged.
            if (line.IndexOf(IdentityMarker, StringComparison.Ordinal) < 0)
            {
                continue;
            }

            identities++;

            Match match = IdentityLineRegex.Match(line);
            if (!match.Success)
            {
                throw new InvalidOperationException(
                    $"The EDL identify output carries a malformed identity line: '{line}'.");
            }

            if (identities > 1)
            {
                throw new InvalidOperationException(
                    "The EDL identify output reports more than one identity line; exactly one is required.");
            }

            serial = match.Groups["sn"].Value.ToUpperInvariant();
            hardwareId = match.Groups["hwid"].Value.ToUpperInvariant();
        }

        if (identities == 0)
        {
            throw new InvalidOperationException(
                $"The EDL identify command did not report a {IdentityMarker} identity line on standard output.");
        }

        if (string.Equals(serial, ZeroSerial, StringComparison.Ordinal) ||
            string.Equals(serial, BroadcastSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The identify command reported an unusable serial {serial} (zero or broadcast).");
        }

        if (string.Equals(hardwareId, ZeroHardwareId, StringComparison.Ordinal) ||
            string.Equals(hardwareId, BroadcastHardwareId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The identify command reported an unusable hardware id {hardwareId} (zero or broadcast).");
        }

        return (serial!, hardwareId!);
    }

    /// <summary>
    /// Maps the reported full hardware id to the single complete built-in profile that declares it. Only the
    /// exact hardware id is compared (case-insensitively); model, firmware, CID and loader data are never used
    /// to break a tie or to stand in for a missing match.
    /// </summary>
    private static EdlDeviceProfile ResolveProfile(string hardwareIdHex)
    {
        EdlDeviceProfile? matched = null;

        foreach (string model in EdlDeviceProfiles.Models)
        {
            EdlDeviceProfile? candidate = EdlDeviceProfiles.FindByModel(model);
            if (candidate is null || !candidate.IsComplete)
            {
                continue;
            }

            string? fullHardwareId = candidate.FullHardwareId;
            if (string.IsNullOrEmpty(fullHardwareId) ||
                !string.Equals(fullHardwareId, hardwareIdHex, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (matched is not null)
            {
                throw new InvalidOperationException(
                    $"The reported hardware id {hardwareIdHex} matches more than one built-in EDL profile " +
                    $"('{matched.ProfileId}' and '{candidate.ProfileId}'); automatic detection requires exactly one.");
            }

            matched = candidate;
        }

        return matched ?? throw new InvalidOperationException(
            $"The reported hardware id {hardwareIdHex} matches no complete built-in EDL profile.");
    }

    /// <summary>The captured error text if there is any, otherwise whatever the command printed.</summary>
    private static string Describe(ProcessResult result)
    {
        string error = (result.StandardError ?? string.Empty).Trim();
        if (error.Length > 0)
        {
            return error;
        }

        string output = (result.StandardOutput ?? string.Empty).Trim();
        return output.Length > 0 ? output : "the command produced no diagnostic output";
    }
}
