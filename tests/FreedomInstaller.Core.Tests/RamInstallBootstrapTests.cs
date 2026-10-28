using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for <see cref="MaintenanceBootstrap.PrepareInstallAsync"/>: only a fresh RAM
/// identity plus the toolbox and install-support assets may reach the device, the launcher always has
/// the same fixed scope, and nothing on this path touches the uninstall helper, HTTP or a boot payload.
/// </summary>
public sealed class RamInstallBootstrapTests
{
    private const string KnownProfileId = "g4-198-259-acmncm";
    private const string KnownModel = "TB322FC";
    private const string KnownSoc = "SM8750";
    private const string KnownBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    private const string KnownBootId = "3f2b8c1a-5d4e-4a6b-9c7d-8e9f0a1b2c3d";
    private const string ExpectedSocSerial = "3251823604";
    private const string DeviceHexSocSerial = "C1D2E3F4";
    private const string DefaultReceiverPid = "31000";

    private const string BootRole = "boot";
    private const string ToolboxRole = "toolbox";
    private const string BootstrapRole = "bootstrap";
    private const string HelperRole = "helper";
    private const string AvbRole = "avb";

    private const long ToolboxBytes = 171162924L;
    private const string ToolboxSha256 = "79a2d937f2cf566591fde9bb8fc1b594fb9e949176fbde0364e9f09976af14a2";

    private static readonly string[] AllRoles = { BootRole, ToolboxRole, BootstrapRole, HelperRole, AvbRole };

    [Fact]
    public async Task PrepareInstallAsync_UploadsToolboxAndSupportOnlyThenRunsTheFixedInstallLauncher()
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = CreateKnownBundle();
        var console = CreateConsole();
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var session = await bootstrap.PrepareInstallAsync(bundle, support, ExpectedSocSerial);

        Assert.Equal(KnownModel, session.Model);
        Assert.Equal(KnownSoc, session.Soc);
        Assert.Equal(ExpectedSocSerial, session.SocSerial);
        Assert.Equal(KnownBootId, session.BootId);

        Assert.False(support.IsDisposed, "the bootstrap must not dispose the caller-owned support");
        Assert.False(bundle.Disposed, "the bootstrap must not dispose the caller-owned bundle");
        Assert.Equal(new[] { ToolboxRole }, bundle.OpenedRoles);
        Assert.All(bundle.Streams, stream => Assert.True(stream.WasDisposed, "opened bundle streams are disposed"));

        Assert.Empty(transfer.Inspections);
        Assert.Equal(2, transfer.Uploads.Count);

        var toolboxUpload = transfer.Uploads[0];
        Assert.Equal("192.168.77.1", toolboxUpload.Host);
        Assert.Equal(8201, toolboxUpload.Port);
        Assert.Equal(ToolboxBytes, toolboxUpload.ExpectedBytes);

        var supportUpload = transfer.Uploads[1];
        Assert.Equal("192.168.77.1", supportUpload.Host);
        Assert.Equal(8201, supportUpload.Port);
        Assert.Equal((long)supportBytes.Length, supportUpload.ExpectedBytes);
        Assert.Equal((long)supportBytes.Length, supportUpload.ContentBytes);
        Assert.Equal(Sha256Hex(supportBytes), supportUpload.ContentSha256);

        var scripts = AllScripts(console);
        Assert.Contains("udhcpd", scripts);
        Assert.Contains("installer-toolbox198.tar.gz", scripts);
        Assert.Contains("install-support.tar.gz", scripts);
        Assert.Contains("busybox tar -xzf", scripts);
        Assert.DoesNotContain("armada_uninstall.py", scripts);
        Assert.DoesNotContain("avb_stock.py", scripts);
        Assert.DoesNotContain("maintenance_bootstrap.sh", scripts);

        var launcher = console.Calls[console.Calls.Count - 1];
        Assert.Equal("FREEDOM_INSTALL_BOOTSTRAP_READY", launcher.ExpectedMarker);
        Assert.Contains("/tmp/freedom-maintenance/incoming/install-support", launcher.Script);
        Assert.Contains("install_bootstrap.sh", launcher.Script);
        Assert.Contains("busybox sh", launcher.Script);

        // No helper, no HTTP port, no request document, no background job and no target writes.
        Assert.DoesNotContain("serve", launcher.Script);
        Assert.DoesNotContain("--bind", launcher.Script);
        Assert.DoesNotContain("8202", launcher.Script);
        Assert.DoesNotContain("request.json", launcher.Script);
        Assert.DoesNotContain("nohup", launcher.Script);
        Assert.DoesNotContain("state", launcher.Script);
        Assert.DoesNotContain("reboot", launcher.Script);
        Assert.DoesNotContain("mkfs", launcher.Script);
        Assert.DoesNotContain("sfdisk", launcher.Script);
        Assert.DoesNotContain("mount -o", launcher.Script);

        // The support receiver runs on the fixed port and writes to the fixed support name.
        var receiverScripts = console.Calls
            .Where(call => call.ExpectedMarker.Contains("FREEDOM_MAINT_RECV_V1_READY", StringComparison.Ordinal))
            .ToList();
        Assert.Equal(2, receiverScripts.Count);
        Assert.Contains(receiverScripts, call => call.Script.Contains("install-support.tar.gz", StringComparison.Ordinal));
        Assert.Contains(receiverScripts, call => call.Script.Contains("installer-toolbox198.tar.gz", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("3251823604")]
    [InlineData("03251823604")]
    [InlineData("0xC1D2E3F4")]
    [InlineData("0Xc1d2e3f4")]
    [InlineData("C1D2E3F4")]
    [InlineData("c1d2e3f4")]
    public async Task PrepareInstallAsync_AcceptsEquivalentNumericSocSerialForms(string deviceSocSerial)
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var console = CreateConsole(deviceSocSerial);
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var session = await bootstrap.PrepareInstallAsync(CreateKnownBundle(), support, ExpectedSocSerial);

        Assert.Equal(ExpectedSocSerial, session.SocSerial);
        Assert.Equal(2, transfer.Uploads.Count);
    }

    [Theory]
    [InlineData("3823654013")]
    [InlineData("E3E8547D")]
    [InlineData("0x0")]
    [InlineData("")]
    [InlineData("12G4")]
    [InlineData("-3251823604")]
    [InlineData(" 3251823604")]
    public async Task PrepareInstallAsync_RejectsUnusableOrDifferentDeviceSerialBeforeUploadOrNetwork(string deviceSocSerial)
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = CreateKnownBundle();
        var console = CreateConsole(deviceSocSerial);
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => bootstrap.PrepareInstallAsync(bundle, support, ExpectedSocSerial));

        Assert.Equal(MaintenanceErrorCode.UnsafeEnvironment, exception.Code);
        Assert.Single(console.Calls);
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("udhcpd", StringComparison.Ordinal));
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
        Assert.Empty(bundle.OpenedRoles);
        Assert.False(support.IsDisposed);
    }

    [Theory]
    [InlineData("0xC1D2E3F4")]
    [InlineData("3251823604a")]
    [InlineData("-3251823604")]
    [InlineData(" 3251823604")]
    [InlineData("3251823604 ")]
    [InlineData("0")]
    public async Task PrepareInstallAsync_RejectsMalformedExpectedSerialBeforeConsoleOrTransfer(string expectedSocSerial)
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = CreateKnownBundle();
        var console = CreateConsole();
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        await Assert.ThrowsAsync<ArgumentException>(
            () => bootstrap.PrepareInstallAsync(bundle, support, expectedSocSerial));

        Assert.Empty(console.Calls);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
        Assert.Empty(bundle.OpenedRoles);
        Assert.False(support.IsDisposed);
    }

    [Fact]
    public async Task PrepareInstallAsync_RejectsUnsupportedBundleBeforeConsoleOrTransfer()
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = new RamInstallFakeBundle(
            new MaintenanceProfile(KnownProfileId, KnownModel, KnownBuild, KnownSoc),
            new Dictionary<string, (long Bytes, string Sha256)>
            {
                [ToolboxRole] = (123456789L, new string('b', 64)),
            },
            AllRoles);
        var console = CreateConsole();
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => bootstrap.PrepareInstallAsync(bundle, support, ExpectedSocSerial));

        Assert.Equal(MaintenanceErrorCode.UnsupportedProfile, exception.Code);
        Assert.Empty(console.Calls);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(transfer.Uploads);
    }

    [Fact]
    public async Task PrepareInstallAsync_WhenSupportUploadFails_KeepsSupportAliveAndStopsOnlyItsReceiver()
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = CreateKnownBundle();
        var console = CreateConsole();
        var transfer = new RamInstallFakeTransfer
        {
            UploadFailure = new IOException("injected support upload failure"),
            FailOnUploadNumber = 2,
        };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<IOException>(
            () => bootstrap.PrepareInstallAsync(bundle, support, ExpectedSocSerial));

        Assert.Equal("injected support upload failure", exception.Message);
        Assert.Equal(new[] { ToolboxRole }, bundle.OpenedRoles);
        Assert.False(support.IsDisposed);
        Assert.Empty(transfer.Inspections);
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("install_bootstrap.sh", StringComparison.Ordinal));

        var cleanup = console.Calls[console.Calls.Count - 1];
        Assert.Equal("FREEDOM_MAINT_RECV_CLEAN_V1_OK", cleanup.ExpectedMarker);
        Assert.Contains("install-support.pid", cleanup.Script);
        Assert.DoesNotContain("kill 0", cleanup.Script);
        Assert.DoesNotMatch(@"\bkill\s+-9(?:\s|$)", cleanup.Script);
    }

    [Fact]
    public async Task PrepareInstallAsync_WritesOpaqueTokenBeforeTheLauncherAndNeverExposesIt()
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var console = CreateConsole();
        var bootstrap = new MaintenanceBootstrap(console, new RamInstallFakeTransfer());

        var session = await bootstrap.PrepareInstallAsync(CreateKnownBundle(), support, ExpectedSocSerial);

        var token = DecodeToken(console.Calls);
        Assert.Equal(64, token.Length);
        Assert.All(token, character => Assert.True(
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'),
            "token must be lowercase hex"));
        Assert.DoesNotContain(token, session.ToString());
        Assert.DoesNotContain(token, AllScripts(console));
        Assert.DoesNotContain(token, console.Calls[console.Calls.Count - 1].Script);

        var tokenIndex = console.Calls.FindIndex(call => call.Script.Contains(
            "> /tmp/freedom-maintenance/incoming/token",
            StringComparison.Ordinal));
        Assert.True(tokenIndex >= 0, "the bearer token must be written to incoming/token");
        Assert.True(tokenIndex < console.Calls.Count - 1, "the token must exist before the launcher runs");

        // The token and the console stay internal so a client cannot invent or reuse a session.
        Assert.Null(typeof(RamInstallSession).GetProperty("Token", BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(typeof(RamInstallSession).GetProperty("Console", BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(RamInstallSession).GetProperty("Token", BindingFlags.NonPublic | BindingFlags.Instance));
        Assert.NotNull(typeof(RamInstallSession).GetProperty("SocSerial", BindingFlags.Public | BindingFlags.Instance));
    }

    [Theory]
    [InlineData("FREEDOM_MAINT_HELPER_STARTED")]
    [InlineData("")]
    public async Task PrepareInstallAsync_LauncherFailureReportsAHandshakeErrorWithoutTheToken(string transcript)
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var console = new RamInstallFakeConsole((_, marker) =>
            marker == "FREEDOM_INSTALL_BOOTSTRAP_READY"
                ? transcript
                : DefaultResponse(marker, DeviceHexSocSerial));
        var bootstrap = new MaintenanceBootstrap(console, new RamInstallFakeTransfer());

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => bootstrap.PrepareInstallAsync(CreateKnownBundle(), support, ExpectedSocSerial));

        Assert.Equal(MaintenanceErrorCode.HandshakeMismatch, exception.Code);
        var token = DecodeToken(console.Calls);
        Assert.DoesNotContain(token, exception.ToString());
        Assert.DoesNotContain(token, exception.Message);
        Assert.False(support.IsDisposed);
    }

    [Fact]
    public async Task PrepareInstallAsync_WithPreCancelledTokenDoesNotReachConsoleOrTransfer()
    {
        using var temp = new RamInstallBootstrapTempDirectory();
        var supportBytes = WriteSupportFile(temp, out var supportPath);
        using var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(supportPath, supportBytes.Length, Sha256Hex(supportBytes)));

        var bundle = CreateKnownBundle();
        var console = CreateConsole();
        var transfer = new RamInstallFakeTransfer();
        var bootstrap = new MaintenanceBootstrap(console, transfer);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => bootstrap.PrepareInstallAsync(bundle, support, ExpectedSocSerial, cancellation.Token));

        Assert.Empty(console.Calls);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
        Assert.False(support.IsDisposed);
    }

    private static RamInstallFakeBundle CreateKnownBundle() => new(
        new MaintenanceProfile(KnownProfileId, KnownModel, KnownBuild, KnownSoc),
        AllRoles);

    private static RamInstallFakeConsole CreateConsole(string deviceSocSerial = "0x" + DeviceHexSocSerial) =>
        new((script, marker) => DefaultResponse(marker, deviceSocSerial));

    private static string DefaultResponse(string marker, string deviceSocSerial)
    {
        if (marker.Contains("FREEDOM_MAINT_RECV_V1_READY", StringComparison.Ordinal))
        {
            return "FREEDOM_MAINT_RECV_V1_BEGIN\nncPid=" + DefaultReceiverPid + "\nFREEDOM_MAINT_RECV_V1_READY\n";
        }

        return marker == "FREEDOM_MAINT_ID_V1_END"
            ? IdentityTranscript(deviceSocSerial)
            : marker + "\n";
    }

    private static string IdentityTranscript(string deviceSocSerial) =>
        "FREEDOM_MAINT_ID_V1_BEGIN\n"
        + "model=" + KnownModel + "\n"
        + "soc=" + KnownSoc + "\n"
        + "socSerial=" + deviceSocSerial + "\n"
        + "bootId=" + KnownBootId + "\n"
        + "ramRoot=true\n"
        + "rootFstype=ramfs\n"
        + "compatible=lenovo,elden qcom,sm8750\n"
        + "usbGadgetReady=true\n"
        + "FREEDOM_MAINT_ID_V1_END\n";

    private static byte[] WriteSupportFile(RamInstallBootstrapTempDirectory temp, out string path)
    {
        var bytes = new byte[8192];
        new Random(7).NextBytes(bytes);
        path = temp.WriteFile("install-support.tar.gz", bytes);
        return bytes;
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string AllScripts(RamInstallFakeConsole console) =>
        string.Join("\n", console.Calls.Select(call => call.Script));

    private static string DecodeToken(IReadOnlyList<RamInstallCommandRecord> calls)
    {
        var script = calls
            .First(call => call.Script.Contains("> /tmp/freedom-maintenance/incoming/token", StringComparison.Ordinal))
            .Script;
        var token = new StringBuilder();

        for (var index = 0; index + 3 < script.Length; index++)
        {
            if (script[index] != '\\' ||
                !IsOctal(script[index + 1]) ||
                !IsOctal(script[index + 2]) ||
                !IsOctal(script[index + 3]))
            {
                continue;
            }

            token.Append((char)Convert.ToInt32(script.Substring(index + 1, 3), 8));
            index += 3;
        }

        return token.ToString();
    }

    private static bool IsOctal(char character) => character is >= '0' and <= '7';

    private sealed class RamInstallBootstrapTempDirectory : IDisposable
    {
        public RamInstallBootstrapTempDirectory()
        {
            Root = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "rh001-bootstrap-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteFile(string name, byte[] content)
        {
            var path = System.IO.Path.Combine(Root, name);
            File.WriteAllBytes(path, content);
            return path;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed class RamInstallFakeBundle : IMaintenanceBundle
    {
        private const long BootBytes = 100663296L;
        private const string BootSha256 = "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358";

        private readonly Dictionary<string, byte[]> _payloads;
        private readonly Dictionary<string, (long Bytes, string Sha256)> _metadataOverrides;

        public RamInstallFakeBundle(MaintenanceProfile profile, params string[] roles)
            : this(profile, null, roles)
        {
        }

        public RamInstallFakeBundle(
            MaintenanceProfile profile,
            IReadOnlyDictionary<string, (long Bytes, string Sha256)>? metadataOverrides,
            params string[] roles)
        {
            Profile = profile;
            _payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            _metadataOverrides = new Dictionary<string, (long Bytes, string Sha256)>(StringComparer.Ordinal);
            foreach (var role in roles)
            {
                _payloads[role] = new byte[RoleSize(role)];
            }

            if (metadataOverrides is not null)
            {
                foreach (var pair in metadataOverrides)
                {
                    _metadataOverrides[pair.Key] = pair.Value;
                }
            }
        }

        public MaintenanceProfile Profile { get; }

        public bool Disposed { get; private set; }

        public List<string> OpenedRoles { get; } = new();

        public List<RamInstallTrackingStream> Streams { get; } = new();

        public MaintenanceAsset GetAsset(string role)
        {
            EnsureRole(role);
            var metadata = _metadataOverrides.TryGetValue(role, out var pinned)
                ? pinned
                : DefaultMetadata(role);
            return new MaintenanceAsset(role, "/fake-assets/" + role, metadata.Bytes, metadata.Sha256);
        }

        public Stream OpenAsset(string role)
        {
            EnsureRole(role);
            OpenedRoles.Add(role);
            var stream = new RamInstallTrackingStream();
            Streams.Add(stream);
            return stream;
        }

        public void Dispose() => Disposed = true;

        private void EnsureRole(string role)
        {
            if (!_payloads.ContainsKey(role))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    "fake bundle has no asset for role '" + role + "'.");
            }
        }

        private static (long Bytes, string Sha256) DefaultMetadata(string role) => role switch
        {
            BootRole => (BootBytes, BootSha256),
            ToolboxRole => (ToolboxBytes, ToolboxSha256),
            _ => (RoleSize(role), new string('a', 64)),
        };

        private static int RoleSize(string role) => role switch
        {
            BootRole => 512,
            ToolboxRole => 4096,
            BootstrapRole => 1024,
            HelperRole => 2048,
            AvbRole => 256,
            _ => 128,
        };
    }

    private sealed class RamInstallFakeConsole : IMaintenanceConsole
    {
        private readonly Func<string, string, string> _responder;

        public RamInstallFakeConsole(Func<string, string, string> responder)
        {
            _responder = responder;
        }

        public List<RamInstallCommandRecord> Calls { get; } = new();

        public Task<string> RunCommandAsync(
            string script,
            string expectedMarker,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(new RamInstallCommandRecord(script, expectedMarker, timeout));
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<string>(cancellationToken);
            }

            return Task.FromResult(_responder(script, expectedMarker));
        }
    }

    private sealed class RamInstallFakeTransfer : IMaintenanceTransfer
    {
        public List<RamInstallUploadRecord> Uploads { get; } = new();

        public List<string> Inspections { get; } = new();

        public Exception? UploadFailure { get; set; }

        /// <summary>One-based upload number to fail on; any positive value when unset.</summary>
        public int FailOnUploadNumber { get; set; } = -1;

        public Task UploadAsync(
            string host,
            int port,
            Stream content,
            long expectedBytes,
            CancellationToken cancellationToken = default)
        {
            using var copy = new MemoryStream();
            content.CopyTo(copy);
            var bytes = copy.ToArray();
            Uploads.Add(new RamInstallUploadRecord(
                host,
                port,
                expectedBytes,
                bytes.LongLength,
                Sha256Hex(bytes)));

            var shouldFail = UploadFailure is not null &&
                (FailOnUploadNumber < 0 || FailOnUploadNumber == Uploads.Count);
            return shouldFail ? Task.FromException(UploadFailure!) : Task.CompletedTask;
        }

        public Task<string> InspectAsync(
            Uri baseAddress,
            string bearerToken,
            CancellationToken cancellationToken = default)
        {
            Inspections.Add(baseAddress.ToString());
            return Task.FromResult("{}");
        }
    }

    private sealed class RamInstallTrackingStream : MemoryStream
    {
        public bool WasDisposed { get; private set; }

        public override bool CanRead => !WasDisposed && base.CanRead;

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed record RamInstallCommandRecord(string Script, string ExpectedMarker, TimeSpan Timeout);

    private sealed record RamInstallUploadRecord(
        string Host,
        int Port,
        long ExpectedBytes,
        long ContentBytes,
        string ContentSha256);
}
