using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Runs fixed, trusted scripts over an explicitly selected COM port.
/// Returns the transcript up to and including the expected marker.
/// Implementations must not log commands or output and must not include secrets in exceptions.
/// </summary>
public interface IMaintenanceConsole
{
    Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Uploads pinned assets to the given host and reads the helper inspect document.
/// The caller owns the provided streams; implementations do not dispose them.
/// </summary>
public interface IMaintenanceTransfer
{
    Task UploadAsync(
        string host,
        int port,
        Stream content,
        long expectedBytes,
        CancellationToken cancellationToken = default);

    /// <summary>Returns the raw inspect JSON; no schema interpretation happens here.</summary>
    Task<string> InspectAsync(
        Uri baseAddress,
        string bearerToken,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Bootstraps a RAM-backed maintenance session for an exact known G4 profile.
/// </summary>
/// <remarks>
/// The C# side owns the read-only identity proof, the USB/DHCP transport, the pinned
/// uploads with serial SHA-256 verification, the bearer token file and the final inspect.
/// The uploaded <c>maintenance_bootstrap.sh</c> keeps ownership of toolbox extraction,
/// self-binding, chroot assembly and the Python helper launch.
/// </remarks>
public sealed partial class MaintenanceBootstrap
{
    private const string TransferHost = "192.168.77.1";
    private const int TransferPort = 8201;

    private const string MaintenanceRoot = "/tmp/freedom-maintenance";
    private const string IncomingDirectory = MaintenanceRoot + "/incoming";
    private const string TokenPath = IncomingDirectory + "/token";
    private const string StateDirectory = "/run/freedom-maintenance";
    private const string LauncherPath = IncomingDirectory + "/maintenance_bootstrap.sh";
    private const string ForeignSessionDirectory = "/tmp/armada-installer-tools";

    // The RAM install bootstrap reuses the same incoming directory but has its own fixed support
    // role, archive name and launcher path. None of them is selectable by a caller.
    private const string InstallSupportRole = "install-support";
    private const string InstallSupportRemoteFileName = "install-support.tar.gz";
    private const string InstallSupportDirectory = IncomingDirectory + "/install-support";
    private const string InstallReadyMarker = "FREEDOM_INSTALL_BOOTSTRAP_READY";

    // Port 8201 is 0x2009; a /proc/net/tcp row in state 0A is a wildcard listener on that port.
    private const string ReceiverListenPattern = ":2009 00000000:0000 0A";

    // /proc/net/tcp6 pads the 128-bit remote address to 32 hex zeros before the port.
    private static readonly string ReceiverListenPattern6 =
        ":2009 " + new string('0', 32) + ":0000 0A";

    private const string IdentityBeginMarker = "FREEDOM_MAINT_ID_V1_BEGIN";
    private const string IdentityEndMarker = "FREEDOM_MAINT_ID_V1_END";
    private const string NetworkReadyMarker = "FREEDOM_MAINT_NET_V1_READY";
    private const string ReceiverReadyMarker = "FREEDOM_MAINT_RECV_V1_READY";
    private const string VerifyMarker = "FREEDOM_MAINT_VERIFY_V1_OK";
    private const string TokenMarker = "FREEDOM_MAINT_TOKEN_V1_OK";
    private const string ReceiverCleanupMarker = "FREEDOM_MAINT_RECV_CLEAN_V1_OK";
    private const string HelperStartedMarker = "FREEDOM_MAINT_HELPER_STARTED";

    private const string IdentityFailureMessage =
        "The device did not present a verified RAM maintenance identity.";

    private const string HandshakeFailureMessage =
        "The maintenance helper did not confirm the verified device identity.";

    private const string InstallSocSerialFailureMessage =
        "The RAM device SoC serial does not match the expected install identity.";

    private const int InspectAttempts = 3;

    private static readonly TimeSpan IdentityTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan NetworkTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReceiverTimeout = TimeSpan.FromSeconds(25);
    private static readonly TimeSpan VerifyTimeout = TimeSpan.FromSeconds(190);
    private static readonly TimeSpan TokenTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LauncherTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan InstallLauncherTimeout = TimeSpan.FromSeconds(300);
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan InspectRetryDelay = TimeSpan.FromMilliseconds(250);

    private static readonly Uri HelperBaseAddress = new("http://192.168.77.1:8202/");

    /// <summary>Roles carried over the wire, in the only permitted upload order.</summary>
    private static readonly string[] TransferRoles =
    {
        MaintenanceProfiles.ToolboxRole,
        MaintenanceProfiles.BootstrapRole,
        MaintenanceProfiles.HelperRole,
        MaintenanceProfiles.AvbRole
    };

    private static readonly string[] IdentityFields =
    {
        "model",
        "soc",
        "socSerial",
        "bootId",
        "ramRoot",
        "rootFstype",
        "compatible",
        "usbGadgetReady"
    };

    private static readonly char[] CompatibleSeparators = { ' ', '\t', '\r', '\n', '|', '\0' };

    private static readonly string[] RamRootFileSystems = { "rootfs", "ramfs", "tmpfs" };

    private readonly IMaintenanceConsole _console;
    private readonly IMaintenanceTransfer _transfer;

    public MaintenanceBootstrap(IMaintenanceConsole console, IMaintenanceTransfer transfer)
    {
        _console = console ?? throw new ArgumentNullException(nameof(console));
        _transfer = transfer ?? throw new ArgumentNullException(nameof(transfer));
    }

    internal IMaintenanceConsole ConsoleTransport => _console;

    internal IMaintenanceTransfer TransferTransport => _transfer;

    /// <summary>
    /// Runs the staged bring-up: RAM identity proof, transport, pinned uploads, token,
    /// helper launch and the identity-checked inspect.
    /// </summary>
    public async Task<MaintenanceSession> StartAsync(
        IMaintenanceBundle bundle,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        cancellationToken.ThrowIfCancellationRequested();

        var assets = ValidateBundle(bundle);

        var identity = await ProveRamIdentityAsync(cancellationToken).ConfigureAwait(false);
        await PrepareTransportAsync(cancellationToken).ConfigureAwait(false);

        foreach (var role in TransferRoles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await TransferRoleAsync(bundle, role, assets[role], cancellationToken).ConfigureAwait(false);
        }

        var token = await WriteTokenFileAsync(cancellationToken).ConfigureAwait(false);
        await StartHelperAsync(cancellationToken).ConfigureAwait(false);
        ValidateInspectDocument(await ReadInspectAsync(token, cancellationToken).ConfigureAwait(false), identity);

        return new MaintenanceSession(
            bundle.Profile.ProfileId,
            identity.Model,
            identity.Soc,
            identity.SocSerial,
            identity.BootId,
            HelperBaseAddress,
            token);
    }

    /// <summary>
    /// Brings up a fresh RAM install session for the exact known profile: identity proof, the same
    /// usb0/DHCP transport, only the toolbox and the caller's verified install-support upload, the
    /// bearer token, and the fixed install launcher.
    /// </summary>
    /// <remarks>
    /// The install session never opens the bundle's boot asset, never uploads the uninstall helper or
    /// the AVB script, never runs the uninstall launcher and never starts the HTTP helper. The bundle
    /// is still validated against the reviewed profile and all its metadata pins before the console is
    /// touched. <paramref name="expectedSocSerial"/> is the Android-observed decimal serial; the fresh
    /// Linux SoC serial is parsed numerically (decimal, <c>0x</c>-prefixed hex or A-F hex) and must
    /// denote the same value before the network is configured or any byte is uploaded.
    /// <para>
    /// <paramref name="support"/> stays owned by the caller: its held file is re-verified immediately
    /// before the upload and is never disposed here.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="expectedSocSerial"/> is not a positive decimal string.</exception>
    /// <exception cref="MaintenanceException">Bundle, identity or transfer verification failed.</exception>
    public async Task<RamInstallSession> PrepareInstallAsync(
        IMaintenanceBundle toolboxBundle,
        RamInstallSupport support,
        string expectedSocSerial,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(toolboxBundle);
        ArgumentNullException.ThrowIfNull(support);
        ArgumentException.ThrowIfNullOrEmpty(expectedSocSerial);
        cancellationToken.ThrowIfCancellationRequested();

        var expectedSerial = ParseExpectedAndroidSocSerial(expectedSocSerial);
        var assets = ValidateBundle(toolboxBundle);

        var identity = await ProveRamIdentityAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(NormalizeDeviceSocSerial(identity.SocSerial), expectedSerial, StringComparison.Ordinal))
        {
            throw InstallSocSerialFailure();
        }

        await PrepareTransportAsync(cancellationToken).ConfigureAwait(false);

        // Only the toolbox role is opened; the boot payload is never read on this path.
        await TransferRoleAsync(
                toolboxBundle,
                MaintenanceProfiles.ToolboxRole,
                assets[MaintenanceProfiles.ToolboxRole],
                cancellationToken)
            .ConfigureAwait(false);

        var supportAsset = new MaintenanceAsset(
            InstallSupportRole,
            InstallSupportRemoteFileName,
            support.Length,
            support.Sha256);

        await TransferRoleAsync(
                InstallSupportRole,
                supportAsset,
                support.OpenVerifiedContentAsync,
                disposeContent: false,
                cancellationToken)
            .ConfigureAwait(false);

        var token = await WriteTokenFileAsync(cancellationToken).ConfigureAwait(false);
        await StartInstallBootstrapAsync(cancellationToken).ConfigureAwait(false);

        return new RamInstallSession(
            identity.Model,
            identity.Soc,
            expectedSerial,
            identity.BootId,
            _console,
            token);
    }

    /// <summary>
    /// Rejects anything that is not the exact reviewed profile with all five roles pinned
    /// before the console or the network is touched. Never opens the boot payload.
    /// </summary>
    private static Dictionary<string, MaintenanceAsset> ValidateBundle(IMaintenanceBundle bundle)
    {
        if (!Equals(bundle.Profile, MaintenanceProfiles.KnownProfile))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsupportedProfile,
                "The bundle profile is not the supported production profile.");
        }

        var assets = new Dictionary<string, MaintenanceAsset>(StringComparer.Ordinal);
        foreach (var role in MaintenanceProfiles.RequiredRoles)
        {
            var asset = bundle.GetAsset(role);
            if (!string.Equals(asset.Role, role, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    "The bundle returned metadata for a different role than requested.");
            }

            if (asset.Bytes <= 0 || !IsSha256Digest(asset.Sha256))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.UnsupportedProfile,
                    "The bundle carries metadata that does not match a reviewed asset pin.");
            }

            assets.Add(role, asset);
        }

        RequirePin(assets[MaintenanceProfiles.BootRole], MaintenanceProfiles.BootBytes, MaintenanceProfiles.BootSha256);
        RequirePin(assets[MaintenanceProfiles.ToolboxRole], MaintenanceProfiles.ToolboxBytes, MaintenanceProfiles.ToolboxSha256);
        return assets;
    }

    private static void RequirePin(MaintenanceAsset asset, long bytes, string sha256)
    {
        if (asset.Bytes != bytes || !string.Equals(asset.Sha256, sha256, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsupportedProfile,
                "The bundle asset does not match the reviewed production pin.");
        }
    }

    private static bool IsSha256Digest(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private async Task<IdentitySnapshot> ProveRamIdentityAsync(CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildIdentityScript(), IdentityEndMarker, IdentityTimeout, cancellationToken)
            .ConfigureAwait(false);

        return ParseIdentity(transcript);
    }

    private static IdentitySnapshot ParseIdentity(string transcript)
    {
        var lines = SplitLines(transcript);
        var begin = Array.IndexOf(lines, IdentityBeginMarker);
        var end = Array.IndexOf(lines, IdentityEndMarker);

        // A single begin/end pair frames the only trusted output; any tty echo around it is ignored.
        if (begin < 0 ||
            end <= begin ||
            Array.LastIndexOf(lines, IdentityBeginMarker) != begin ||
            Array.LastIndexOf(lines, IdentityEndMarker) != end)
        {
            throw IdentityFailure();
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = begin + 1; index < end; index++)
        {
            var line = lines[index];
            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                throw IdentityFailure();
            }

            var key = line.Substring(0, separator);
            if (Array.IndexOf(IdentityFields, key) < 0 || !fields.TryAdd(key, line.Substring(separator + 1)))
            {
                throw IdentityFailure();
            }
        }

        foreach (var field in IdentityFields)
        {
            if (!fields.ContainsKey(field))
            {
                throw IdentityFailure();
            }
        }

        var model = fields["model"];
        var soc = fields["soc"];
        var socSerial = fields["socSerial"];
        var bootId = fields["bootId"];

        if (!string.Equals(model, MaintenanceProfiles.Model, StringComparison.Ordinal) ||
            !string.Equals(soc, MaintenanceProfiles.Soc, StringComparison.Ordinal) ||
            socSerial.Length == 0 ||
            !Guid.TryParseExact(bootId, "D", out _) ||
            !string.Equals(fields["ramRoot"], "true", StringComparison.Ordinal) ||
            Array.IndexOf(RamRootFileSystems, fields["rootFstype"]) < 0 ||
            !string.Equals(fields["usbGadgetReady"], "true", StringComparison.Ordinal) ||
            !HasRequiredCompatibleTokens(fields["compatible"]))
        {
            throw IdentityFailure();
        }

        return new IdentitySnapshot(model, soc, socSerial, bootId);
    }

    private static bool HasRequiredCompatibleTokens(string compatible)
    {
        var tokens = compatible.Split(CompatibleSeparators, StringSplitOptions.RemoveEmptyEntries);
        var platform = false;
        var soc = false;
        foreach (var token in tokens)
        {
            if (string.Equals(token, "lenovo,elden", StringComparison.Ordinal))
            {
                platform = true;
            }
            else if (string.Equals(token, "qcom,sm8750", StringComparison.Ordinal))
            {
                soc = true;
            }
        }

        return platform && soc;
    }

    private static MaintenanceException IdentityFailure() =>
        new(MaintenanceErrorCode.UnsafeEnvironment, IdentityFailureMessage);

    /// <summary>
    /// Accepts only the Android-observed form: ASCII decimal digits denoting a positive value. The
    /// canonical decimal text is returned so it can be compared with the parsed Linux serial.
    /// </summary>
    private static string ParseExpectedAndroidSocSerial(string expectedSocSerial)
    {
        if (!IsDecimalDigits(expectedSocSerial) ||
            !ulong.TryParse(expectedSocSerial, NumberStyles.None, CultureInfo.InvariantCulture, out var serial) ||
            serial == 0)
        {
            throw new ArgumentException(
                "The expected SoC serial must be a positive decimal string.",
                nameof(expectedSocSerial));
        }

        return serial.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Converts the fresh Linux SoC serial to canonical decimal. Digits alone are decimal, while a
    /// <c>0x</c>/<c>0X</c> prefix or any A-F digit is hexadecimal; any other shape is rejected.
    /// </summary>
    private static string NormalizeDeviceSocSerial(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw InstallSocSerialFailure();
        }

        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ParseHexSocSerial(value.Substring(2));
        }

        if (IsDecimalDigits(value) &&
            ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var decimalSerial) &&
            decimalSerial > 0)
        {
            return decimalSerial.ToString(CultureInfo.InvariantCulture);
        }

        return ParseHexSocSerial(value);
    }

    private static string ParseHexSocSerial(string value)
    {
        if (value.Length == 0 ||
            value.Length > 16 ||
            !IsHexDigits(value) ||
            !ulong.TryParse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var serial) ||
            serial == 0)
        {
            throw InstallSocSerialFailure();
        }

        return serial.ToString(CultureInfo.InvariantCulture);
    }

    private static bool IsDecimalDigits(string value)
    {
        if (value.Length == 0 || value.Length > 20)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHexDigits(string value)
    {
        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static MaintenanceException InstallSocSerialFailure() =>
        new(MaintenanceErrorCode.UnsafeEnvironment, InstallSocSerialFailureMessage);

    private async Task PrepareTransportAsync(CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildTransportScript(), NetworkReadyMarker, NetworkTimeout, cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, NetworkReadyMarker, MaintenanceErrorCode.UnsafeEnvironment);
    }

    private Task TransferRoleAsync(
        IMaintenanceBundle bundle,
        string role,
        MaintenanceAsset asset,
        CancellationToken cancellationToken) =>
        TransferRoleAsync(
            role,
            asset,
            _ => Task.FromResult(bundle.OpenAsset(role)),
            disposeContent: true,
            cancellationToken);

    /// <summary>
    /// Starts the role's receiver, uploads whatever <paramref name="openContent"/> yields and proves the
    /// received length and SHA-256 over the serial console. The opener runs once the receiver is ready and
    /// immediately before the upload, so a caller that re-verifies its held bytes does so just before use.
    /// The content stream is disposed here only when the caller transfers that ownership.
    /// </summary>
    private async Task TransferRoleAsync(
        string role,
        MaintenanceAsset asset,
        Func<CancellationToken, Task<Stream>> openContent,
        bool disposeContent,
        CancellationToken cancellationToken)
    {
        string? receiverPid = null;
        try
        {
            receiverPid = await StartReceiverAsync(role, cancellationToken).ConfigureAwait(false);

            var content = await openContent(cancellationToken).ConfigureAwait(false);
            try
            {
                await _transfer
                    .UploadAsync(TransferHost, TransferPort, content, asset.Bytes, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                if (disposeContent)
                {
                    content.Dispose();
                }
            }

            await VerifyUploadedAssetAsync(role, asset, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await StopReceiverAsync(role, receiverPid).ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Serial verification is a hash identity check: an unproven transcript or an unfinished
    /// verification is reported as a hash mismatch, never as a handshake or helper problem.
    /// </summary>
    private async Task VerifyUploadedAssetAsync(
        string role,
        MaintenanceAsset asset,
        CancellationToken cancellationToken)
    {
        string transcript;
        try
        {
            transcript = await _console
                .RunCommandAsync(BuildVerifyScript(role, asset), VerifyMarker, VerifyTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException exception)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetHashMismatch,
                "The serial verification of the uploaded asset did not complete.",
                exception);
        }

        EnsureMarker(transcript, VerifyMarker, MaintenanceErrorCode.AssetHashMismatch);
    }

    /// <summary>
    /// Requires the receiver this call started to report its own decimal pid before any bytes
    /// are uploaded; a missing or implausible pid is never treated as ready.
    /// </summary>
    private async Task<string> StartReceiverAsync(string role, CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildReceiverScript(role), ReceiverReadyMarker, ReceiverTimeout, cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, ReceiverReadyMarker, MaintenanceErrorCode.UnsafeEnvironment);
        return ParseReceiverPid(transcript);
    }

    /// <summary>
    /// Stops only the receiver owned by this call. Ownership is proven on the device through the
    /// role's own pid file, so a lost ready response still cleans up exactly that process.
    /// </summary>
    private async Task StopReceiverAsync(string role, string? receiverPid)
    {
        try
        {
            await _console
                .RunCommandAsync(
                    BuildReceiverCleanupScript(role, receiverPid),
                    ReceiverCleanupMarker,
                    CleanupTimeout,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cleanup is best effort and must never replace the real failure.
        }
    }

    private static string ParseReceiverPid(string transcript)
    {
        const string prefix = "ncPid=";
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
                "The maintenance receiver did not prove a live listening process of its own.");
        }

        return value;
    }

    /// <summary>A real Linux receiver pid is decimal and is never 0 or 1.</summary>
    private static bool IsPositivePid(string value)
    {
        if (value.Length == 0 || value.Length > 9)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) && pid > 1;
    }

    private async Task<string> WriteTokenFileAsync(CancellationToken cancellationToken)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

        var transcript = await _console
            .RunCommandAsync(BuildTokenScript(token), TokenMarker, TokenTimeout, cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, TokenMarker, MaintenanceErrorCode.UnsafeEnvironment);
        return token;
    }

    private async Task StartHelperAsync(CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(BuildLauncherScript(), HelperStartedMarker, LauncherTimeout, cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, HelperStartedMarker, MaintenanceErrorCode.HandshakeMismatch);
    }

    private async Task StartInstallBootstrapAsync(CancellationToken cancellationToken)
    {
        var transcript = await _console
            .RunCommandAsync(
                BuildInstallLauncherScript(),
                InstallReadyMarker,
                InstallLauncherTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        EnsureMarker(transcript, InstallReadyMarker, MaintenanceErrorCode.HandshakeMismatch);
    }

    private async Task<string> ReadInspectAsync(string token, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await _transfer
                    .InspectAsync(HelperBaseAddress, token, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (IsTransportFailure(exception))
            {
                // Only an unreachable listener is retried; a received wrong identity never is.
                if (attempt + 1 >= InspectAttempts)
                {
                    throw HandshakeFailure();
                }

                await Task.Delay(InspectRetryDelay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static bool IsTransportFailure(Exception exception) =>
        exception is HttpRequestException or IOException or SocketException or TimeoutException;

    private static void ValidateInspectDocument(string json, IdentitySnapshot identity)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var schema) ||
                schema.ValueKind != JsonValueKind.Number ||
                !schema.TryGetInt32(out var version) ||
                version != MaintenanceProfiles.ManifestSchemaVersion ||
                !HasExactString(root, "model", identity.Model) ||
                !HasExactString(root, "socSerial", identity.SocSerial) ||
                !HasExactString(root, "bootId", identity.BootId) ||
                !root.TryGetProperty("ramRoot", out var ramRoot) ||
                ramRoot.ValueKind != JsonValueKind.True)
            {
                throw HandshakeFailure();
            }
        }
        catch (JsonException)
        {
            throw HandshakeFailure();
        }
    }

    private static bool HasExactString(JsonElement root, string name, string expected) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        string.Equals(value.GetString(), expected, StringComparison.Ordinal);

    private static MaintenanceException HandshakeFailure() =>
        new(MaintenanceErrorCode.HandshakeMismatch, HandshakeFailureMessage);

    private static void EnsureMarker(string transcript, string marker, MaintenanceErrorCode code)
    {
        foreach (var line in SplitLines(transcript))
        {
            if (string.Equals(line, marker, StringComparison.Ordinal))
            {
                return;
            }
        }

        throw new MaintenanceException(
            code,
            "The maintenance device did not report the expected completion marker.");
    }

    private static string[] SplitLines(string transcript) =>
        transcript.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

    private static string BuildIdentityScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "printf 'FREEDOM_MAINT_ID_V1_BEGIN\\n'",
            "compat_tokens=$(busybox tr '\\000|\\t' '\\n\\n\\n' < /proc/device-tree/compatible)",
            "platform=0",
            "soc_part=0",
            "for token in $compat_tokens; do",
            "  case \"$token\" in",
            "    lenovo,elden) platform=1 ;;",
            "    qcom,sm8750) soc_part=1 ;;",
            "  esac",
            "done",
            "compat_line=",
            "for token in $compat_tokens; do compat_line=\"$compat_line $token\"; done",
            "model=",
            "soc=",
            "if [ \"$platform\" = 1 ] && [ \"$soc_part\" = 1 ]; then",
            "  model=TB322FC",
            "  soc=SM8750",
            "fi",
            "soc_serial=$(busybox tr -d ' \\t\\r\\n' < /sys/devices/soc0/serial_number)",
            "boot_id=$(busybox tr -d ' \\t\\r\\n' < /proc/sys/kernel/random/boot_id)",
            "root_fstype=$(busybox stat -f -c %T /)",
            "case \"$root_fstype\" in",
            "  rootfs|ramfs|tmpfs) ram_root=true ;;",
            "  *) ram_root=false ;;",
            "esac",
            "usb_ready=false",
            "for udc in /sys/kernel/config/usb_gadget/*/UDC; do",
            "  if [ -r \"$udc\" ] && [ -n \"$(busybox cat \"$udc\")\" ]; then usb_ready=true; fi",
            "done",
            "printf 'model=%s\\n' \"$model\"",
            "printf 'soc=%s\\n' \"$soc\"",
            "printf 'socSerial=%s\\n' \"$soc_serial\"",
            "printf 'bootId=%s\\n' \"$boot_id\"",
            "printf 'ramRoot=%s\\n' \"$ram_root\"",
            "printf 'rootFstype=%s\\n' \"$root_fstype\"",
            "printf 'compatible=%s\\n' \"${compat_line# }\"",
            "printf 'usbGadgetReady=%s\\n' \"$usb_ready\"",
            "printf 'FREEDOM_MAINT_ID_V1_END\\n'"
        });

    private static string BuildTransportScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "if [ -e " + MaintenanceRoot + " ] || [ -e " + StateDirectory + " ] || [ -e " + ForeignSessionDirectory + " ]; then",
            "  exit 1",
            "fi",
            "busybox mkdir -p " + IncomingDirectory + " " + MaintenanceRoot + "/state " + StateDirectory,
            "busybox chmod 700 " + MaintenanceRoot + " " + StateDirectory,
            "printf 'start 192.168.77.2\\nend 192.168.77.2\\ninterface usb0\\noption subnet 255.255.255.252\\noption lease 3600\\nlease_file " + StateDirectory + "/udhcpd.leases\\npidfile " + StateDirectory + "/udhcpd.pid\\n' > " + MaintenanceRoot + "/udhcpd.conf",
            "busybox ip link show dev usb0 | busybox grep -F 'UP' > /dev/null 2>&1 || busybox ip link set usb0 up",
            "busybox ip addr show dev usb0 | busybox grep -F '192.168.77.1/30' > /dev/null",
            "busybox udhcpd " + MaintenanceRoot + "/udhcpd.conf",
            "printf 'ready\\n' > " + StateDirectory + "/startup",
            "printf 'FREEDOM_MAINT_NET_V1_READY\\n'"
        });

    private static string BuildReceiverScript(string role)
    {
        var pidPath = StateDirectory + "/" + role + ".pid";
        var statusPath = StateDirectory + "/" + role + ".status";
        var errorPath = StateDirectory + "/" + role + ".err";
        var targetPath = IncomingDirectory + "/" + RemoteFileName(role);

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                "busybox rm -f " + pidPath + " " + statusPath + " " + errorPath,
                "if busybox grep -F '" + ReceiverListenPattern + "' /proc/net/tcp > /dev/null 2>&1; then exit 1; fi",
                "if busybox grep -F '" + ReceiverListenPattern6 + "' /proc/net/tcp6 > /dev/null 2>&1; then exit 1; fi",
                "busybox sh -c 'busybox nohup busybox nc -l -p 8201 > \"$3\" 2> \"$4\" </dev/null & child=$!; printf \"%s\" \"$child\" > \"$1\"; wait \"$child\"; printf \"%s\" \"$?\" > \"$2\"' recv "
                    + pidPath + " " + statusPath + " " + targetPath + " " + errorPath + " > /dev/null 2>&1 &",
                "i=0",
                "while [ ! -s " + pidPath + " ] && [ $i -lt 100 ]; do busybox sleep 0.1; i=$((i+1)); done",
                "[ -s " + pidPath + " ] || exit 1",
                "nc_pid=$(busybox cat " + pidPath + ")",
                "case \"$nc_pid\" in ''|*[!0-9]*) exit 1 ;; esac",
                "[ \"$nc_pid\" -gt 1 ] || exit 1",
                "busybox kill -0 \"$nc_pid\" 2>/dev/null || exit 1",
                "listening=0",
                "i=0",
                "while [ $i -lt 100 ] && [ $listening = 0 ]; do",
                "  if busybox grep -F '" + ReceiverListenPattern + "' /proc/net/tcp > /dev/null 2>&1; then listening=1; fi",
                "  if busybox grep -F '" + ReceiverListenPattern6 + "' /proc/net/tcp6 > /dev/null 2>&1; then listening=1; fi",
                "  busybox sleep 0.1",
                "  i=$((i+1))",
                "done",
                "[ \"$listening\" = 1 ] || exit 1",
                "busybox kill -0 \"$nc_pid\" 2>/dev/null || exit 1",
                "printf 'FREEDOM_MAINT_RECV_V1_BEGIN\\n'",
                "printf 'ncPid=%s\\n' \"$nc_pid\"",
                "printf 'FREEDOM_MAINT_RECV_V1_READY\\n'"
            });
    }

    private static string BuildVerifyScript(string role, MaintenanceAsset asset)
    {
        var statusPath = StateDirectory + "/" + role + ".status";
        var targetPath = IncomingDirectory + "/" + RemoteFileName(role);

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                "i=0",
                "while [ ! -s " + statusPath + " ] && [ $i -lt 1800 ]; do busybox sleep 0.1; i=$((i+1)); done",
                "[ -s " + statusPath + " ] || exit 1",
                "[ \"$(busybox cat " + statusPath + ")\" = \"0\" ] || exit 1",
                "actual_bytes=$(busybox wc -c " + targetPath + " | busybox awk '{print $1}')",
                "[ \"$actual_bytes\" = \"" + asset.Bytes.ToString(CultureInfo.InvariantCulture) + "\" ] || exit 1",
                "actual=$(busybox sha256sum " + targetPath + " | busybox awk '{print $1}')",
                "[ \"$actual\" = \"" + asset.Sha256 + "\" ] || exit 1",
                "printf 'role=%s\\n' " + role,
                "printf 'sha256=%s\\n' \"$actual\"",
                "printf 'FREEDOM_MAINT_VERIFY_V1_OK\\n'"
            });
    }

    /// <summary>
    /// Builds cleanup that kills at most the one positive pid this call can prove it owns: either
    /// the pid it parsed, or the pid recorded in the role's own pid file when the ready response
    /// was lost. A 0/1, malformed, missing or mismatched record is never killed.
    /// </summary>
    private static string BuildReceiverCleanupScript(string role, string? receiverPid)
    {
        var pidPath = StateDirectory + "/" + role + ".pid";
        var statusPath = StateDirectory + "/" + role + ".status";
        var ownership = string.IsNullOrEmpty(receiverPid)
            ? "owned=$(busybox cat " + pidPath + " 2>/dev/null || true)"
            : "owned=" + receiverPid;

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                ownership,
                "case \"$owned\" in 0|1|''|*[!0-9]*) owned= ;; esac",
                "if [ -n \"$owned\" ] && [ \"$owned\" -gt 1 ] && [ ! -s " + statusPath + " ] && [ \"$(busybox cat " + pidPath + " 2>/dev/null || true)\" = \"$owned\" ]; then",
                "  busybox kill \"$owned\" 2>/dev/null || true",
                "fi",
                "busybox rm -f " + pidPath + " " + statusPath,
                "printf 'FREEDOM_MAINT_RECV_CLEAN_V1_OK\\n'"
            });
    }

    /// <summary>
    /// Writes the token through octal escapes so the raw digest never appears in the
    /// recorded command string; the shell's own printf decodes it.
    /// </summary>
    private static string BuildTokenScript(string token)
    {
        var encoded = new StringBuilder(token.Length * 4);
        foreach (var character in token)
        {
            encoded.Append('\\').Append(Convert.ToString((int)character, 8).PadLeft(3, '0'));
        }

        return string.Join(
            "\n",
            new[]
            {
                "set -eu",
                "umask 077",
                "printf '" + encoded + "' > " + TokenPath,
                "busybox chmod 600 " + TokenPath,
                "printf 'FREEDOM_MAINT_TOKEN_V1_OK\\n'"
            });
    }

    private static string BuildLauncherScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "busybox sh " + LauncherPath
        });

    /// <summary>
    /// Fixed install launcher: it may only create the support directory, extract the already verified
    /// support archive into it and run its fixed bootstrap. It never starts the helper, the HTTP service,
    /// a background job or any configurable command.
    /// </summary>
    private static string BuildInstallLauncherScript() => string.Join(
        "\n",
        new[]
        {
            "set -eu",
            "incoming=" + IncomingDirectory,
            "support=" + InstallSupportDirectory,
            "archive=" + IncomingDirectory + "/" + InstallSupportRemoteFileName,
            "if [ -e \"$support\" ] || [ -h \"$support\" ]; then exit 1; fi",
            "if [ -h \"$archive\" ] || [ ! -f \"$archive\" ]; then exit 1; fi",
            "busybox mkdir \"$support\"",
            "busybox tar -xzf \"$archive\" -C \"$support\"",
            "if [ -h \"$support/install_bootstrap.sh\" ] || [ ! -f \"$support/install_bootstrap.sh\" ]; then exit 1; fi",
            "busybox sh \"$support/install_bootstrap.sh\""
        });

    private static string RemoteFileName(string role) => role switch
    {
        MaintenanceProfiles.ToolboxRole => "installer-toolbox198.tar.gz",
        MaintenanceProfiles.BootstrapRole => "maintenance_bootstrap.sh",
        MaintenanceProfiles.HelperRole => "armada_uninstall.py",
        MaintenanceProfiles.AvbRole => "avb_stock.py",
        InstallSupportRole => InstallSupportRemoteFileName,
        _ => throw new MaintenanceException(
            MaintenanceErrorCode.MissingAsset,
            "The requested role has no fixed transport destination.")
    };

    private sealed record IdentitySnapshot(string Model, string Soc, string SocSerial, string BootId);
}

/// <summary>
/// Result of a successful bootstrap. The bearer token is a secret: it must never appear in
/// logs, argv, exceptions, or the string representation.
/// </summary>
public sealed class MaintenanceSession
{
    internal MaintenanceSession(
        string profileId,
        string model,
        string soc,
        string socSerial,
        string bootId,
        Uri baseAddress,
        string bearerToken)
    {
        ProfileId = profileId;
        Model = model;
        Soc = soc;
        SocSerial = socSerial;
        BootId = bootId;
        BaseAddress = baseAddress;
        BearerToken = bearerToken;
    }

    public string ProfileId { get; }

    public string Model { get; }

    public string Soc { get; }

    public string SocSerial { get; }

    public string BootId { get; }

    public Uri BaseAddress { get; }

    public string BearerToken { get; }

    public override string ToString() =>
        nameof(MaintenanceSession)
        + " { ProfileId = " + ProfileId
        + ", Model = " + Model
        + ", Soc = " + Soc
        + ", SocSerial = " + SocSerial
        + ", BootId = " + BootId
        + ", BaseAddress = " + BaseAddress
        + ", BearerToken = [REDACTED] }";
}
