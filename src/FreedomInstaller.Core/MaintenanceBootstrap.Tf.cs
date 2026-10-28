using System;
using System.Formats.Tar;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// TF-card assisted RAM maintenance bootstrap. Prepares a RAM-backed tablet for the
/// <c>armada_tf.py serve</c> helper bound to port 8203: it proves the fresh RAM identity
/// and the fixed TF marker, reuses the generic 8201/USB transport with only the pinned
/// toolbox and the fixed install-support receiver slot, launches the helper inside a
/// strict chroot and hands back a connected <see cref="TfRamMaintenanceSession"/>.
/// </summary>
/// <remarks>
/// This partial never touches the old G4 helper path on port 8202: it never starts the
/// HTTP helper, never uploads the uninstall or AVB scripts and never reads the bundle's
/// boot payload. The caller owns the <see cref="HttpClient"/> and the serial console;
/// the returned runtime closes only what this bootstrap itself created. The caller must
/// dispose the runtime before requesting a manual 9008 return.
/// </remarks>
public sealed partial class MaintenanceBootstrap
{
    private const string TfIdentityBeginMarker = "FREEDOM_TF_ID_V1_BEGIN";
    private const string TfIdentityEndMarker = "FREEDOM_TF_ID_V1_END";
    private const string TfReadyMarker = "FREEDOM_TF_LAUNCH_V1_READY";
    private const string TfCleanupMarker = "FREEDOM_TF_CLEANUP_V1_OK";

    private const string TfTransportProtocol = "tf-card-v1";
    private const string TfEldenPair = "elden-sm8750";
    private const string TfBaldurPair = "baldur-kaanapali";

    private const string TfHelperResourceName = "FreedomInstaller.TfMaintenance.Helper.py";
    private const string TfHelperEntryName = "armada_tf.py";
    private const string TfLauncherEntryName = "launch_tf.sh";

    // Fixed fresh RAM locations owned by this bootstrap alone. None of them is selectable.
    private const string TfSupportDirectory = IncomingDirectory + "/tf-support";
    private const string TfToolsDirectory = "/tmp/armada-tf-tools";
    private const string TfRunDirectory = "/run/freedom-tf";
    private const string TfRunMarkerPath = TfRunDirectory + "/tf-maintenance.json";
    private const string TfRunTokenPath = TfRunDirectory + "/token";
    private const string TfChrootHelperPath = "/tmp/freedom-tf/armada_tf.py";
    private const string TfHelperPidPath = StateDirectory + "/tf-helper.pid";

    // Written only after this run itself created a given fixed directory, so cleanup
    // never removes a path it did not create.
    private const string TfCreatedMarkerPath = StateDirectory + "/tf-created";

    // Written by the shared transport script; read only, never rewritten here.
    private const string TfDhcpPidPath = StateDirectory + "/udhcpd.pid";

    private const string TfDeviceMarkerPath = "/etc/armada/tf-maintenance.json";

    // Exactly what `chroot ... python3 .../armada_tf.py serve` leaves in /proc/<pid>/cmdline
    // once every exec in the chain has replaced its image, including the trailing space
    // produced by translating NUL separators.
    private const string TfHelperCommandLine = "/usr/bin/python3 " + TfChrootHelperPath + " serve";

    private const string TfIdentityFailureMessage =
        "The device did not present a verified TF RAM maintenance identity.";

    private static readonly string[] TfIdentityFields =
    {
        "pair",
        "compatible",
        "socSerial",
        "bootId",
        "rootFstype",
        "tmpFstype",
        "runFstype",
        "gadget",
        "tfMarker64"
    };

    private static readonly TimeSpan TfIdentityTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TfLauncherTimeout = TimeSpan.FromSeconds(300);

    /// <summary>
    /// Brings up a fresh TF-card RAM maintenance session for the tablet the caller expects:
    /// bounded serial identity proof against the expected model, numeric SoC serial and
    /// kernel digest, the generic USB/DHCP transport, only the pinned toolbox upload, the
    /// bearer token, the fixed support archive upload into the existing receiver slot, the
    /// fixed chroot launcher and finally a token-authenticated 8203 session whose boot id
    /// matches the pre-upload serial proof.
    /// </summary>
    /// <remarks>
    /// Only the toolbox role's metadata is read from the bundle and pinned against the
    /// reviewed production pins. The bundle's G4 hardware profile is not required to match
    /// this tablet, and its boot, uninstall and AVB assets are never opened or uploaded.
    /// <paramref name="client"/> stays owned by the caller and is used only to connect the
    /// session; the returned runtime never disposes it.
    /// </remarks>
    /// <exception cref="ArgumentException">An expected identity input is not canonical.</exception>
    /// <exception cref="MaintenanceException">Identity, transport, transfer or launch verification failed.</exception>
    public async Task<TfMaintenanceRuntime> PrepareTfAsync(
        IMaintenanceBundle toolboxBundle,
        string expectedModel,
        ulong expectedSocSerial,
        string expectedKernelSha256,
        HttpClient client,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(toolboxBundle);
        ArgumentNullException.ThrowIfNull(client);
        ValidateTfExpectedInputs(expectedModel, expectedSocSerial, expectedKernelSha256);
        cancellationToken.ThrowIfCancellationRequested();

        var toolboxAsset = toolboxBundle.GetAsset(MaintenanceProfiles.ToolboxRole);
        if (!string.Equals(toolboxAsset.Role, MaintenanceProfiles.ToolboxRole, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.MissingAsset,
                "The bundle returned metadata for a different role than requested.");
        }

        RequirePin(toolboxAsset, MaintenanceProfiles.ToolboxBytes, MaintenanceProfiles.ToolboxSha256);

        var identity = await ProveTfIdentityAsync(
                expectedModel,
                expectedSocSerial,
                expectedKernelSha256,
                cancellationToken)
            .ConfigureAwait(false);

        var transportReady = false;
        string? knownHelperPid = null;
        string? knownDhcpPid = null;
        try
        {
            await PrepareTransportAsync(cancellationToken).ConfigureAwait(false);
            transportReady = true;

            await TransferRoleAsync(
                    toolboxBundle,
                    MaintenanceProfiles.ToolboxRole,
                    toolboxAsset,
                    cancellationToken)
                .ConfigureAwait(false);

            var token = await WriteTokenFileAsync(cancellationToken).ConfigureAwait(false);

            var archive = BuildTfSupportArchive();
            var supportAsset = new MaintenanceAsset(
                InstallSupportRole,
                InstallSupportRemoteFileName,
                archive.LongLength,
                Convert.ToHexString(SHA256.HashData(archive)).ToLowerInvariant());

            await TransferRoleAsync(
                    InstallSupportRole,
                    supportAsset,
                    _ => Task.FromResult<Stream>(new MemoryStream(archive)),
                    disposeContent: true,
                    cancellationToken)
                .ConfigureAwait(false);

            (knownHelperPid, knownDhcpPid) = await StartTfLauncherAsync(cancellationToken).ConfigureAwait(false);

            var session = await TfRamMaintenanceSession
                .ConnectAsync(client, token, expectedModel, expectedSocSerial, expectedKernelSha256, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                if (session.BootId != identity.BootId)
                {
                    throw new MaintenanceException(
                        MaintenanceErrorCode.HandshakeMismatch,
                        "The TF maintenance session did not report the proven boot identity.");
                }

                return new TfMaintenanceRuntime(session, _console, knownHelperPid, knownDhcpPid);
            }
            catch
            {
                await session.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch (Exception failure)
        {
            if (!transportReady)
            {
                throw;
            }

            Exception? cleanupFailure = null;
            try
            {
                await RunTfCleanupAsync(knownHelperPid, knownDhcpPid).ConfigureAwait(false);
            }
            catch (Exception cleanup)
            {
                cleanupFailure = cleanup;
            }

            if (cleanupFailure is null)
            {
                throw;
            }

            throw new AggregateException(
                "TF RAM maintenance startup failed and its cleanup also failed.",
                failure,
                cleanupFailure);
        }
    }

    private static void ValidateTfExpectedInputs(
        string expectedModel,
        ulong expectedSocSerial,
        string expectedKernelSha256)
    {
        if (string.IsNullOrEmpty(expectedModel) || expectedModel.Length > 32)
        {
            throw new ArgumentException(
                "The expected TF tablet model is not a canonical model code.",
                nameof(expectedModel));
        }

        foreach (var character in expectedModel)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character != '-' && character != '_')
            {
                throw new ArgumentException(
                    "The expected TF tablet model is not a canonical model code.",
                    nameof(expectedModel));
            }
        }

        if (expectedSocSerial == 0)
        {
            throw new ArgumentException(
                "The expected TF SoC serial must be a nonzero numeric value.",
                nameof(expectedSocSerial));
        }

        if (!IsSha256Digest(expectedKernelSha256))
        {
            throw new ArgumentException(
                "The expected kernel digest is not a 64-hex SHA-256 value.",
                nameof(expectedKernelSha256));
        }
    }

    private async Task<TfIdentityProof> ProveTfIdentityAsync(
        string expectedModel,
        ulong expectedSocSerial,
        string expectedKernelSha256,
        CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildTfIdentityScript(), TfIdentityEndMarker, TfIdentityTimeout, cancellationToken)
            .ConfigureAwait(false);

        var proof = ParseTfIdentity(transcript);

        // Fixed pair-to-model rule: the canonical elden+sm8750 tablet is the reviewed G4
        // model; every other canonical model must present exactly the baldur+kaanapali
        // pair. A mixed or partial pair (pair=none) is always foreign and rejected.
        var expectedPair = string.Equals(expectedModel, MaintenanceProfiles.Model, StringComparison.Ordinal)
            ? TfEldenPair
            : TfBaldurPair;
        if (!string.Equals(proof.Pair, expectedPair, StringComparison.Ordinal))
        {
            throw TfIdentityFailure();
        }

        if (Array.IndexOf(RamRootFileSystems, proof.RootFstype) < 0 ||
            Array.IndexOf(RamRootFileSystems, proof.TmpFstype) < 0 ||
            Array.IndexOf(RamRootFileSystems, proof.RunFstype) < 0)
        {
            throw TfIdentityFailure();
        }

        if (proof.Gadget.Length == 0 || string.Equals(proof.Gadget, "none", StringComparison.Ordinal))
        {
            throw TfIdentityFailure();
        }

        if (proof.SocSerial != expectedSocSerial)
        {
            throw TfIdentityFailure();
        }

        RequireTfMarkerDocument(proof.Marker64, expectedModel, expectedKernelSha256);
        return proof;
    }

    private static TfIdentityProof ParseTfIdentity(string transcript)
    {
        var lines = SplitLines(transcript);
        var begin = Array.IndexOf(lines, TfIdentityBeginMarker);
        var end = Array.IndexOf(lines, TfIdentityEndMarker);

        // Exactly one begin/end pair frames the only trusted output; any tty echo around
        // it, a repeated frame or a foreign field is never accepted.
        if (begin < 0 ||
            end <= begin ||
            Array.LastIndexOf(lines, TfIdentityBeginMarker) != begin ||
            Array.LastIndexOf(lines, TfIdentityEndMarker) != end)
        {
            throw TfIdentityFailure();
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = begin + 1; index < end; index++)
        {
            var line = lines[index];
            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                throw TfIdentityFailure();
            }

            var key = line.Substring(0, separator);
            if (Array.IndexOf(TfIdentityFields, key) < 0 || !fields.TryAdd(key, line.Substring(separator + 1)))
            {
                throw TfIdentityFailure();
            }
        }

        foreach (var field in TfIdentityFields)
        {
            if (!fields.ContainsKey(field))
            {
                throw TfIdentityFailure();
            }
        }

        if (!TryParseDeviceSocSerial(fields["socSerial"], out var socSerial))
        {
            throw TfIdentityFailure();
        }

        if (!Guid.TryParseExact(fields["bootId"], "D", out var bootId) || bootId == Guid.Empty)
        {
            throw TfIdentityFailure();
        }

        return new TfIdentityProof(
            fields["pair"],
            fields["compatible"],
            socSerial,
            bootId,
            fields["rootFstype"],
            fields["tmpFstype"],
            fields["runFstype"],
            fields["gadget"],
            fields["tfMarker64"]);
    }

    /// <summary>
    /// Parses the actual device SoC serial as decimal, 0x-prefixed hex or bare hex into a
    /// numeric value; anything else, including an overflow, is not a serial.
    /// </summary>
    private static bool TryParseDeviceSocSerial(string value, out ulong serial)
    {
        serial = 0;
        if (value.Length == 0 || value.Length > 20)
        {
            return false;
        }

        var digits = value;
        var style = NumberStyles.None;
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            digits = digits.Substring(2);
            style = NumberStyles.HexNumber;
        }
        else
        {
            foreach (var character in digits)
            {
                if (character is >= 'a' and <= 'f' or >= 'A' and <= 'F')
                {
                    style = NumberStyles.HexNumber;
                    break;
                }
            }
        }

        return ulong.TryParse(digits, style, CultureInfo.InvariantCulture, out serial);
    }

    /// <summary>
    /// Decodes and strictly checks the RAM marker: exactly four fields, schema 1, the
    /// expected model and kernel digest and the fixed tf-card-v1 transport protocol.
    /// </summary>
    private static void RequireTfMarkerDocument(string encoded, string expectedModel, string expectedKernelSha256)
    {
        if (encoded.Length == 0 || encoded.Length > 8192)
        {
            throw TfIdentityFailure();
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            throw TfIdentityFailure();
        }

        if (bytes.Length == 0 || bytes.Length > 4096)
        {
            throw TfIdentityFailure();
        }

        try
        {
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw TfIdentityFailure();
            }

            var seen = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!seen.TryAdd(property.Name, property.Value))
                {
                    throw TfIdentityFailure();
                }
            }

            if (seen.Count != 4 ||
                !seen.TryGetValue("schema", out var schema) ||
                schema.ValueKind != JsonValueKind.Number ||
                !schema.TryGetInt32(out var schemaVersion) ||
                schemaVersion != 1 ||
                !seen.TryGetValue("expectedModel", out var markerModel) ||
                markerModel.ValueKind != JsonValueKind.String ||
                !string.Equals(markerModel.GetString(), expectedModel, StringComparison.Ordinal) ||
                !seen.TryGetValue("kernelSha256", out var markerKernel) ||
                markerKernel.ValueKind != JsonValueKind.String ||
                !string.Equals(markerKernel.GetString(), expectedKernelSha256, StringComparison.Ordinal) ||
                !seen.TryGetValue("transportProtocol", out var transport) ||
                transport.ValueKind != JsonValueKind.String ||
                !string.Equals(transport.GetString(), TfTransportProtocol, StringComparison.Ordinal))
            {
                throw TfIdentityFailure();
            }
        }
        catch (JsonException)
        {
            throw TfIdentityFailure();
        }
    }

    private static MaintenanceException TfIdentityFailure() =>
        new(MaintenanceErrorCode.UnsafeEnvironment, TfIdentityFailureMessage);

    private async Task<(string HelperPid, string DhcpPid)> StartTfLauncherAsync(CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildTfLauncherScript(), TfReadyMarker, TfLauncherTimeout, cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, TfReadyMarker, MaintenanceErrorCode.HandshakeMismatch);
        return (
            ParseTfLauncherPid(transcript, "tfHelperPid="),
            ParseTfLauncherPid(transcript, "tfDhcpPid="));
    }

    private static string ParseTfLauncherPid(string transcript, string prefix)
    {
        string? value = null;
        var matches = 0;
        foreach (var line in SplitLines(transcript))
        {
            if (!line.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            matches++;
            value = line.Substring(prefix.Length);
        }

        if (matches != 1 || value is null || !IsPositivePid(value))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsafeEnvironment,
                "The TF launcher did not prove a live process of its own.");
        }

        return value;
    }

    private async Task RunTfCleanupAsync(string? helperPid, string? dhcpPid)
    {
        await _console
            .RunCommandAsync(
                BuildTfCleanupScript(helperPid, dhcpPid),
                TfCleanupMarker,
                CleanupTimeout,
                CancellationToken.None)
            .ConfigureAwait(false);
    }

    private static string BuildTfIdentityScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "printf '" + TfIdentityBeginMarker + "\\n'",
            "compat_tokens=$(busybox tr '\\000' '\\n' < /proc/device-tree/compatible)",
            "compatible=",
            "for token in $compat_tokens; do compatible=\"$compatible $token\"; done",
            "elden=0",
            "sm8750=0",
            "baldur=0",
            "kaanapali=0",
            "for token in $compat_tokens; do",
            "  case \"$token\" in",
            "    *,elden) elden=1 ;;",
            "    *,sm8750) sm8750=1 ;;",
            "    *,baldur) baldur=1 ;;",
            "    *,kaanapali) kaanapali=1 ;;",
            "  esac",
            "done",
            "pair=none",
            "if [ \"$elden\" = 1 ] && [ \"$sm8750\" = 1 ] && [ \"$baldur\" = 0 ] && [ \"$kaanapali\" = 0 ]; then",
            "  pair=" + TfEldenPair,
            "elif [ \"$baldur\" = 1 ] && [ \"$kaanapali\" = 1 ] && [ \"$elden\" = 0 ] && [ \"$sm8750\" = 0 ]; then",
            "  pair=" + TfBaldurPair,
            "fi",
            "soc_serial=$(busybox tr -d ' \\t\\r\\n' < /sys/devices/soc0/serial_number)",
            "boot_id=$(busybox tr -d ' \\t\\r\\n' < /proc/sys/kernel/random/boot_id)",
            "printf 'pair=%s\\n' \"$pair\"",
            "printf 'compatible=%s\\n' \"${compatible# }\"",
            "printf 'socSerial=%s\\n' \"$soc_serial\"",
            "printf 'bootId=%s\\n' \"$boot_id\"",
            "printf 'rootFstype=%s\\n' \"$(busybox stat -f -c %T /)\"",
            "printf 'tmpFstype=%s\\n' \"$(busybox stat -f -c %T /tmp)\"",
            "printf 'runFstype=%s\\n' \"$(busybox stat -f -c %T /run)\"",
            "gadget=none",
            "for udc in /sys/kernel/config/usb_gadget/*/UDC; do",
            "  if [ -r \"$udc\" ] && [ -n \"$(busybox cat \"$udc\")\" ]; then gadget=$(busybox basename \"$(busybox dirname \"$udc\")\"); fi",
            "done",
            "printf 'gadget=%s\\n' \"$gadget\"",
            "tf_marker64=",
            "if [ -s " + TfDeviceMarkerPath + " ]; then",
            "  tf_marker64=$(busybox base64 " + TfDeviceMarkerPath + " | busybox tr -d '\\n')",
            "fi",
            "printf 'tfMarker64=%s\\n' \"$tf_marker64\"",
            "printf '" + TfIdentityEndMarker + "\\n'"
        });

    /// <summary>
    /// Fixed console launcher: it may only create the fresh support directory, extract the
    /// already verified support archive into it and run its fixed launch_tf.sh. It never
    /// starts the HTTP helper or any configurable command.
    /// </summary>
    private static string BuildTfLauncherScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "support=" + TfSupportDirectory,
            "archive=" + IncomingDirectory + "/" + InstallSupportRemoteFileName,
            "if [ -e \"$support\" ] || [ -h \"$support\" ]; then exit 1; fi",
            "if [ -h \"$archive\" ] || [ ! -f \"$archive\" ]; then exit 1; fi",
            "busybox mkdir \"$support\"",
            "printf 'tf-support\\n' >> " + TfCreatedMarkerPath,
            "busybox tar -xzf \"$archive\" -C \"$support\"",
            "if [ -h \"$support/" + TfLauncherEntryName + "\" ] || [ ! -f \"$support/" + TfLauncherEntryName + "\" ]; then exit 1; fi",
            "busybox sh \"$support/" + TfLauncherEntryName + "\""
        });

    /// <summary>
    /// Fixed launch_tf.sh carried inside the support archive: it proves the RAM paths and
    /// inputs, builds the unique tools chroot from the pinned toolbox, binds exactly its
    /// own mounts plus a fresh tmpfs at the chroot /tmp, stages the helper, publishes the
    /// verified marker and token into the shared RAM directory and starts only the helper
    /// server. It never mounts a block filesystem, never opens an SD/UFS device, never
    /// reboots and never writes a partition.
    /// </summary>
    private static string BuildTfLauncherPayload() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "umask 077",
            "incoming=" + IncomingDirectory,
            "state=" + StateDirectory,
            "tools=" + TfToolsDirectory,
            "rundir=" + TfRunDirectory,
            "helper=$tools" + TfChrootHelperPath,
            "toolbox=$incoming/installer-toolbox198.tar.gz",
            "marker=" + TfDeviceMarkerPath,
            "root_fs=$(busybox stat -f -c %T /)",
            "tmp_fs=$(busybox stat -f -c %T /tmp)",
            "run_fs=$(busybox stat -f -c %T /run)",
            "case \"$root_fs\" in rootfs|ramfs|tmpfs) ;; *) exit 1 ;; esac",
            "case \"$tmp_fs\" in rootfs|ramfs|tmpfs) ;; *) exit 1 ;; esac",
            "case \"$run_fs\" in rootfs|ramfs|tmpfs) ;; *) exit 1 ;; esac",
            "if [ -h \"$tools\" ] || [ -e \"$tools\" ]; then exit 1; fi",
            "if [ -h \"$rundir\" ] || [ -e \"$rundir\" ]; then exit 1; fi",
            "if [ -h \"$marker\" ] || [ ! -s \"$marker\" ]; then exit 1; fi",
            "if [ -h \"$toolbox\" ] || [ ! -s \"$toolbox\" ]; then exit 1; fi",
            "if [ -h \"$incoming/token\" ] || [ ! -s \"$incoming/token\" ]; then exit 1; fi",
            "if [ -h \"" + TfSupportDirectory + "/" + TfHelperEntryName + "\" ] || [ ! -f \"" + TfSupportDirectory + "/" + TfHelperEntryName + "\" ]; then exit 1; fi",
            "busybox mkdir \"$tools\"",
            "printf 'tools\\n' >> " + TfCreatedMarkerPath,
            "busybox mkdir \"$tools/tmp\" \"$tools/dev\" \"$tools/proc\" \"$tools/sys\" \"$tools/run\"",
            "busybox tar -xzf \"$toolbox\" -C \"$tools\"",
            "busybox mount -o bind \"$tools\" \"$tools\"",
            "busybox mount --rbind /dev \"$tools/dev\"",
            "busybox mount -o bind /proc \"$tools/proc\"",
            "busybox mount -o bind /sys \"$tools/sys\"",
            "busybox mount -o bind /run \"$tools/run\"",
            "busybox mount -t tmpfs tmpfs \"$tools/tmp\"",
            "busybox mkdir \"$tools/tmp/freedom-tf\"",
            "busybox cp \"" + TfSupportDirectory + "/" + TfHelperEntryName + "\" \"$helper\"",
            "busybox mkdir \"$rundir\"",
            "printf 'run\\n' >> " + TfCreatedMarkerPath,
            "busybox cp \"$marker\" \"" + TfRunMarkerPath + "\"",
            "busybox cp \"$incoming/token\" \"" + TfRunTokenPath + "\"",
            "busybox chmod 700 \"$rundir\" \"" + TfRunMarkerPath + "\"",
            "busybox chmod 600 \"" + TfRunTokenPath + "\"",
            "busybox nohup busybox chroot \"$tools\" /usr/bin/python3 " + TfChrootHelperPath + " serve < /dev/null > /dev/null 2>&1 &",
            "helper_pid=$!",
            "printf '%s' \"$helper_pid\" > " + TfHelperPidPath,
            "i=0",
            "while [ $i -lt 100 ]; do",
            "  if ! busybox kill -0 \"$helper_pid\" 2>/dev/null; then exit 1; fi",
            "  if busybox grep -F '014DA8C0:200B 00000000:0000 0A' /proc/net/tcp > /dev/null 2>&1; then break; fi",
            "  busybox sleep 0.1",
            "  i=$((i+1))",
            "done",
            "busybox kill -0 \"$helper_pid\" 2>/dev/null || exit 1",
            "busybox grep -F '014DA8C0:200B 00000000:0000 0A' /proc/net/tcp > /dev/null 2>&1 || exit 1",
            "dhcp_pid=$(busybox cat " + TfDhcpPidPath + ")",
            "case \"$dhcp_pid\" in ''|*[!0-9]*) exit 1 ;; esac",
            "[ \"$dhcp_pid\" -gt 1 ] || exit 1",
            "printf 'tfHelperPid=%s\\n' \"$helper_pid\"",
            "printf 'tfDhcpPid=%s\\n' \"$dhcp_pid\"",
            "printf '" + TfReadyMarker + "\\n'"
        });

    /// <summary>
    /// Fixed cleanup in strict fail-fast order: read this run's exact-line creation facts,
    /// verify ownership of every existing fixed directory, verify ownership of every live
    /// helper/DHCP pid, stop only proven-own processes with a bounded wait, unmount only
    /// the own-created tools subtree (child-to-parent, full mountinfo paths), re-verify no
    /// residual mount, then remove only this run's own-created directories. Every failure
    /// exits immediately, keeping all directories, mounts and records; success is printed
    /// only after every phase passed.
    /// </summary>
    internal static string BuildTfCleanupScript(string? helperPid, string? dhcpPid)
    {
        var helperOwnership = string.IsNullOrEmpty(helperPid)
            ? "helper=$(busybox cat " + TfHelperPidPath + " 2>/dev/null || true)"
            : "helper=" + helperPid;
        var dhcpOwnership = string.IsNullOrEmpty(dhcpPid)
            ? "dhcp=$(busybox cat " + TfDhcpPidPath + " 2>/dev/null || true)"
            : "dhcp=" + dhcpPid;
        var tools = TfToolsDirectory;

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                "umask 077",
                helperOwnership,
                dhcpOwnership,
                "case \"$helper\" in 0|1|''|*[!0-9]*) helper= ;; esac",
                "case \"$dhcp\" in 0|1|''|*[!0-9]*) dhcp= ;; esac",
                // Phase 1: exact-line creation facts from this run's marker only.
                "created=$(busybox cat " + TfCreatedMarkerPath + " 2>/dev/null || true)",
                "created_line() { printf '%s\\n' \"$created\" | busybox grep -qx \"$1\" 2>/dev/null; }",
                // Phase 2: existing fixed directories must be owned by this run; a missing
                // directory is skipped, but a present one without this run's fact stops all.
                "if [ -h \"" + TfSupportDirectory + "\" ]; then exit 1; fi",
                "if [ ! -h \"" + TfSupportDirectory + "\" ] && [ -e \"" + TfSupportDirectory + "\" ]; then",
                "  created_line tf-support || exit 1",
                "fi",
                "if [ -h \"" + TfRunDirectory + "\" ]; then exit 1; fi",
                "if [ ! -h \"" + TfRunDirectory + "\" ] && [ -e \"" + TfRunDirectory + "\" ]; then",
                "  created_line run || exit 1",
                "fi",
                "if [ -h \"" + tools + "\" ]; then exit 1; fi",
                "if [ ! -h \"" + tools + "\" ] && [ -e \"" + tools + "\" ]; then",
                "  created_line tools || exit 1",
                "fi",
                // Phase 3: verify ownership of live helper/DHCP pids; anything foreign or
                // mismatched stops everything, keeping processes, mounts and records.
                "helper_alive=0",
                "if [ -n \"$helper\" ] && busybox kill -0 \"$helper\" 2>/dev/null; then helper_alive=1; fi",
                "if [ \"$helper_alive\" = 1 ]; then",
                "  if [ ! -r \"/proc/$helper/root\" ] || [ ! -r \"/proc/$helper/cmdline\" ]; then exit 1; fi",
                "  helper_root=$(busybox readlink \"/proc/$helper/root\" 2>/dev/null || true)",
                "  helper_cmd=$(busybox tr '\\000' ' ' < \"/proc/$helper/cmdline\")",
                "  if [ \"$helper_root\" != \"" + tools + "\" ] || [ \"$helper_cmd\" != \"" + TfHelperCommandLine + " \" ]; then exit 1; fi",
                "fi",
                "dhcp_alive=0",
                "if [ -n \"$dhcp\" ] && busybox kill -0 \"$dhcp\" 2>/dev/null; then dhcp_alive=1; fi",
                "if [ \"$dhcp_alive\" = 1 ]; then",
                "  if [ ! -r \"/proc/$dhcp/cmdline\" ]; then exit 1; fi",
                "  dhcp_cmd=$(busybox tr '\\000' ' ' < \"/proc/$dhcp/cmdline\")",
                "  case \"$dhcp_cmd\" in",
                "    *\"udhcpd " + MaintenanceRoot + "/udhcpd.conf\"*) ;;",
                "    *) exit 1 ;;",
                "  esac",
                "fi",
                // Phase 4: stop only proven-own processes; kill failure or survival past the
                // bounded wait stops everything.
                "if [ \"$helper_alive\" = 1 ]; then",
                "  busybox kill \"$helper\" 2>/dev/null || exit 1",
                "fi",
                "if [ \"$dhcp_alive\" = 1 ]; then",
                "  busybox kill \"$dhcp\" 2>/dev/null || exit 1",
                "fi",
                "i=0",
                "while [ $i -lt 50 ]; do",
                "  if { [ \"$helper_alive\" = 0 ] || ! busybox kill -0 \"$helper\" 2>/dev/null; } && { [ \"$dhcp_alive\" = 0 ] || ! busybox kill -0 \"$dhcp\" 2>/dev/null; }; then",
                "    break",
                "  fi",
                "  busybox sleep 0.1",
                "  i=$((i+1))",
                "done",
                "if [ \"$helper_alive\" = 1 ] && busybox kill -0 \"$helper\" 2>/dev/null; then exit 1; fi",
                "if [ \"$dhcp_alive\" = 1 ] && busybox kill -0 \"$dhcp\" 2>/dev/null; then exit 1; fi",
                // Phase 5: unmount exactly the own-created tools subtree, child-to-parent,
                // from mountinfo full paths. No own-created tools means no mount touching.
                "if created_line tools; then",
                "  escaped=" + tools,
                "  i=0",
                "  while [ $i -lt 20 ]; do",
                "    targets=$(busybox awk -v t=\"$escaped\" '$5 == t || index($5, t \"/\") == 1 { print $5 }' /proc/self/mountinfo | busybox sort -r) || exit 1",
                "    found=0",
                "    for m in $targets; do",
                "      found=1",
                "      busybox umount \"$m\" 2>/dev/null || exit 1",
                "    done",
                "    [ \"$found\" = 0 ] && break",
                "    i=$((i+1))",
                "  done",
                // Phase 6: re-verify mountinfo; any residual mount at or below tools stops.
                "  if busybox awk -v t=\"$escaped\" '$5 == t || index($5, t \"/\") == 1 { exit 1 }' /proc/self/mountinfo 2>/dev/null; then :; else exit 1; fi",
                "fi",
                // Phase 7: remove only this run's own-created fixed directories; the first
                // removal failure stops, keeping every remaining directory and the marker.
                "if created_line tf-support; then",
                "  if [ ! -h \"" + TfSupportDirectory + "\" ] && [ -e \"" + TfSupportDirectory + "\" ]; then",
                "    busybox rm -rf \"" + TfSupportDirectory + "\" || exit 1",
                "  fi",
                "fi",
                "if created_line run; then",
                "  if [ ! -h \"" + TfRunDirectory + "\" ] && [ -e \"" + TfRunDirectory + "\" ]; then",
                "    busybox rm -rf \"" + TfRunDirectory + "\" || exit 1",
                "  fi",
                "fi",
                "if created_line tools; then",
                "  if [ ! -h \"" + tools + "\" ] && [ -e \"" + tools + "\" ]; then",
                "    busybox rm -rf \"" + tools + "\" || exit 1",
                "  fi",
                "fi",
                // Phase 8: only full success removes this run's records and reports success.
                "busybox rm -f \"" + TfHelperPidPath + "\" \"" + TfCreatedMarkerPath + "\" || exit 1",
                "printf '" + TfCleanupMarker + "\\n'"
            });
    }

    /// <summary>
    /// Builds the small deterministic tar.gz support archive in memory: exactly the
    /// embedded armada_tf.py helper and the fixed launch_tf.sh payload, with fixed entry
    /// order, zero ids, an epoch timestamp and no host paths. Returns the compressed
    /// bytes whose length and SHA-256 the caller pins for the transfer.
    /// </summary>
    private static byte[] BuildTfSupportArchive()
    {
        var helper = ReadTfHelperResource();
        var launcher = Encoding.UTF8.GetBytes(BuildTfLauncherPayload());

        using var tar = new MemoryStream();
        using (var writer = new TarWriter(tar, TarEntryFormat.Ustar, leaveOpen: true))
        {
            WriteTfArchiveEntry(writer, TfHelperEntryName, helper, 0x1a4);
            WriteTfArchiveEntry(writer, TfLauncherEntryName, launcher, 0x1ed);
        }

        tar.Position = 0;
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            tar.CopyTo(gzip);
        }

        return compressed.ToArray();
    }

    private static void WriteTfArchiveEntry(TarWriter writer, string name, byte[] content, int mode)
    {
        var entry = new UstarTarEntry(TarEntryType.RegularFile, name)
        {
            Mode = (UnixFileMode)mode,
            Uid = 0,
            Gid = 0,
            UserName = string.Empty,
            GroupName = string.Empty,
            ModificationTime = DateTimeOffset.UnixEpoch,
            DataStream = new MemoryStream(content)
        };
        writer.WriteEntry(entry);
    }

    private static byte[] ReadTfHelperResource()
    {
        using var stream = typeof(MaintenanceBootstrap).Assembly.GetManifestResourceStream(TfHelperResourceName)
            ?? throw new MaintenanceException(
                MaintenanceErrorCode.MissingAsset,
                "The TF maintenance helper script is not embedded in the assembly.");

        using var staged = new MemoryStream();
        stream.CopyTo(staged);
        var bytes = staged.ToArray();
        if (bytes.Length == 0)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.MissingAsset,
                "The embedded TF maintenance helper script is empty.");
        }

        return bytes;
    }

    private sealed record TfIdentityProof(
        string Pair,
        string Compatible,
        ulong SocSerial,
        Guid BootId,
        string RootFstype,
        string TmpFstype,
        string RunFstype,
        string Gadget,
        string Marker64);

    /// <summary>
    /// Lifecycle owner of one live TF RAM maintenance session: the connected 8203 session
    /// plus the exact helper and DHCP processes and fresh RAM directories the bootstrap
    /// created. It has no public constructor and no setters; the caller disposes it before
    /// requesting a manual 9008 return. It never closes the caller's HttpClient or serial
    /// console.
    /// </summary>
    public sealed class TfMaintenanceRuntime : IAsyncDisposable
    {
        private readonly IMaintenanceConsole _console;
        private readonly string _helperPid;
        private readonly string _dhcpPid;
        private bool _disposed;

        internal TfMaintenanceRuntime(
            TfRamMaintenanceSession session,
            IMaintenanceConsole console,
            string helperPid,
            string dhcpPid)
        {
            Session = session;
            _console = console;
            _helperPid = helperPid;
            _dhcpPid = dhcpPid;
        }

        /// <summary>The connected TF RAM maintenance session bound to port 8203.</summary>
        public TfRamMaintenanceSession Session { get; }

        /// <summary>
        /// Closes the session first, then stops exactly the recorded helper and DHCP
        /// processes after verifying their /proc command lines (and the helper chroot root)
        /// against the fresh owned paths, reverses exactly the mounts this bootstrap
        /// created and removes its fixed fresh RAM directories after RAM filesystem and
        /// ownership checks. A mismatched or reused pid is never killed and cleanup
        /// failure is never silently reported as success.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await Session.DisposeAsync().ConfigureAwait(false);
            await _console
                .RunCommandAsync(
                    BuildTfCleanupScript(_helperPid, _dhcpPid),
                    TfCleanupMarker,
                    CleanupTimeout,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
    }
}
