using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class BootstrapTestMaintenanceBootstrap
{
    private const string KnownProfileId = "g4-198-259-acmncm";
    private const string KnownModel = "TB322FC";
    private const string KnownSoc = "SM8750";
    private const string KnownBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    private const string KnownSocSerial = "SN-BOOTSTRAP-TEST-0001";
    private const string KnownBootId = "3f2b8c1a-5d4e-4a6b-9c7d-8e9f0a1b2c3d";
    private const string CompatibleTokens = "lenovo,elden qcom,sm8750";
    private const string DefaultReceiverPid = "12345";

    private const string BootRole = "boot";
    private const string ToolboxRole = "toolbox";
    private const string BootstrapRole = "bootstrap";
    private const string HelperRole = "helper";
    private const string AvbRole = "avb";

    private static readonly string[] RuntimeRoles = { ToolboxRole, BootstrapRole, HelperRole, AvbRole };
    private static readonly string[] AllRoles = { BootRole, ToolboxRole, BootstrapRole, HelperRole, AvbRole };

    [Fact]
    public async Task StartAsync_HappyPath_ProvesRamIdentityThenUploadsRuntimeAssetsAndStartsHelper()
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var session = await bootstrap.StartAsync(bundle);

        Assert.Equal(KnownProfileId, session.ProfileId);
        Assert.Equal(KnownModel, session.Model);
        Assert.Equal(KnownSoc, session.Soc);
        Assert.Equal(KnownSocSerial, session.SocSerial);
        Assert.Equal(KnownBootId, session.BootId);
        Assert.Equal(new Uri("http://192.168.77.1:8202/"), session.BaseAddress);
        AssertOpaqueToken(session.BearerToken);

        var inspection = Assert.Single(transfer.Inspections);
        Assert.Equal(new Uri("http://192.168.77.1:8202/"), inspection.BaseAddress);
        Assert.Equal(session.BearerToken, inspection.BearerToken);

        Assert.Equal(RuntimeRoles, bundle.OpenedRoles);
        Assert.DoesNotContain(BootRole, bundle.OpenedRoles);
        Assert.Equal(4, transfer.Uploads.Count);
        for (var index = 0; index < RuntimeRoles.Length; index++)
        {
            var upload = transfer.Uploads[index];
            Assert.Equal("192.168.77.1", upload.Host);
            Assert.Equal(8201, upload.Port);
            Assert.Equal(bundle.GetAsset(RuntimeRoles[index]).Bytes, upload.ExpectedBytes);
        }

        Assert.All(bundle.Streams, stream => Assert.True(stream.WasDisposed, "bootstrap owns and disposes each opened asset stream"));
        Assert.False(bundle.Disposed, "bootstrap must not dispose the caller-owned bundle");

        Assert.NotEmpty(console.Calls);
        Assert.Contains("FREEDOM_MAINT_ID_V1_END", console.Calls[0].ExpectedMarker);
        Assert.Equal("console", events[0]);
        var firstUploadIndex = events.IndexOf("upload");
        Assert.True(firstUploadIndex > 0, "no upload may happen before the read-only identity proof");
        Assert.True(events.IndexOf("inspect") > events.LastIndexOf("upload"));

        var commandScripts = string.Join("\n", console.Calls.Select(call => call.Script));
        var loweredScripts = commandScripts.ToLowerInvariant();

        Assert.Contains("192.168.77.1/30", commandScripts);
        Assert.Contains("255.255.255.252", commandScripts);
        Assert.Contains("192.168.77.2", commandScripts);
        Assert.Contains("usb0", commandScripts);
        Assert.Contains("udhcpd", commandScripts);
        Assert.Contains("8201", commandScripts);
        Assert.Contains("armada-installer-tools", commandScripts);
        Assert.Contains("armada_uninstall.py", commandScripts);
        Assert.DoesNotContain("router", loweredScripts);
        Assert.DoesNotContain("dns", loweredScripts);
        Assert.DoesNotContain("fastboot", loweredScripts);
        Assert.DoesNotContain("reboot", loweredScripts);
        Assert.DoesNotContain(session.BearerToken, commandScripts);

        // The token lands where the fixed launcher reads it, under a restrictive umask.
        Assert.Contains("> /tmp/freedom-maintenance/incoming/token", commandScripts);
        Assert.Contains("umask 077", commandScripts);
        Assert.Contains("busybox chmod 600 /tmp/freedom-maintenance/incoming/token", commandScripts);
        Assert.DoesNotContain("> /tmp/freedom-maintenance/token", commandScripts);

        // The fixed usb0 address is read and required, never re-written by guesswork.
        Assert.Contains("busybox ip addr show dev usb0 | busybox grep -F '192.168.77.1/30'", commandScripts);
        Assert.DoesNotContain("ip addr replace", commandScripts);
        Assert.DoesNotContain("ip addr add", commandScripts);
        Assert.Contains("busybox ip link set usb0 up", commandScripts);

        // RAM root proof reads the mounted root filesystem type, not a first mount row.
        Assert.Contains("busybox stat -f -c %T /", commandScripts);
        Assert.DoesNotContain("/proc/mounts", commandScripts);

        // The receiver proves a live listener of its own before any upload.
        Assert.Contains("busybox kill -0 \"$nc_pid\"", commandScripts);
        Assert.Contains("/proc/net/tcp", commandScripts);

        // Serial verification compares the received byte count before the single hash read.
        Assert.Contains("busybox wc -c", commandScripts);
        Assert.Contains("busybox sha256sum", commandScripts);

        var launcher = console.Calls[console.Calls.Count - 1];
        Assert.Contains("maintenance_bootstrap.sh", launcher.Script);
        Assert.Contains("FREEDOM_MAINT_HELPER_STARTED", launcher.ExpectedMarker);
        Assert.Contains(
            console.Calls.Take(console.Calls.Count - 1),
            call => call.Script.Contains("sha256sum", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("rootfs")]
    [InlineData("ramfs")]
    [InlineData("tmpfs")]
    public async Task StartAsync_AcceptsRamBackedRootFileSystems(string rootFstype)
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = new BootstrapTestFakeConsole(
            events,
            (script, marker) => marker.Contains("FREEDOM_MAINT_ID_V1_END", StringComparison.Ordinal)
                ? IdentityTranscript(rootFstype: rootFstype)
                : DefaultResponse(script, marker));
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var session = await bootstrap.StartAsync(bundle);

        Assert.Equal(KnownSocSerial, session.SocSerial);
        Assert.Equal(4, transfer.Uploads.Count);
        Assert.True(transfer.Uploads.TrueForAll(upload => upload.Port == 8201));
    }

    [Theory]
    [InlineData(BootstrapTestIdentityVariant.RamRootFalse)]
    [InlineData(BootstrapTestIdentityVariant.RootFstypeExt4)]
    [InlineData(BootstrapTestIdentityVariant.WrongModel)]
    [InlineData(BootstrapTestIdentityVariant.WrongSoc)]
    [InlineData(BootstrapTestIdentityVariant.MissingCompatibleToken)]
    [InlineData(BootstrapTestIdentityVariant.BlankSocSerial)]
    [InlineData(BootstrapTestIdentityVariant.InvalidBootId)]
    [InlineData(BootstrapTestIdentityVariant.UsbGadgetNotReady)]
    [InlineData(BootstrapTestIdentityVariant.DuplicateModel)]
    [InlineData(BootstrapTestIdentityVariant.MissingSocSerial)]
    public async Task StartAsync_RejectsUnsafeIdentityEnvironment(BootstrapTestIdentityVariant variant)
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = new BootstrapTestFakeConsole(events, (_, _) => IdentityTranscript(variant));
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => bootstrap.StartAsync(bundle));

        Assert.Equal(MaintenanceErrorCode.UnsafeEnvironment, exception.Code);
        Assert.Single(console.Calls);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(bundle.Streams);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
    }

    [Theory]
    [InlineData("g5-tb323fu")]
    [InlineData("unknown-g4")]
    [InlineData("missing-avb")]
    [InlineData("wrong-toolbox-pin")]
    public async Task StartAsync_RejectsUnsupportedOrIncompleteBundleBeforeAnyConsoleOrNetwork(string bundleCase)
    {
        var events = new List<string>();
        var bundle = bundleCase switch
        {
            "g5-tb323fu" => new BootstrapTestFakeBundle(
                new MaintenanceProfile("g5-198-259-acmncm", "TB323FU", "TB323FU_CN_OPEN_USER_Q00041.1", "SM8750"),
                AllRoles),
            "unknown-g4" => new BootstrapTestFakeBundle(
                new MaintenanceProfile("g4-000-000-acmncm", KnownModel, KnownBuild, KnownSoc),
                AllRoles),
            "missing-avb" => new BootstrapTestFakeBundle(
                new MaintenanceProfile(KnownProfileId, KnownModel, KnownBuild, KnownSoc),
                BootRole, ToolboxRole, BootstrapRole, HelperRole),
            "wrong-toolbox-pin" => new BootstrapTestFakeBundle(
                new MaintenanceProfile(KnownProfileId, KnownModel, KnownBuild, KnownSoc),
                new Dictionary<string, (long Bytes, string Sha256)>
                {
                    [ToolboxRole] = (123456789L, new string('b', 64)),
                },
                AllRoles),
            _ => throw new ArgumentOutOfRangeException(nameof(bundleCase)),
        };
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => bootstrap.StartAsync(bundle));

        if (bundleCase == "wrong-toolbox-pin")
        {
            Assert.Equal(MaintenanceErrorCode.UnsupportedProfile, exception.Code);
        }
        else
        {
            Assert.True(
                exception.Code is MaintenanceErrorCode.UnsupportedProfile or MaintenanceErrorCode.MissingAsset,
                "bundle rejection must use a typed profile/asset error, saw " + exception.Code);
        }

        Assert.Empty(console.Calls);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
    }

    [Theory]
    [InlineData(BootstrapTestInspectVariant.SchemaTwo)]
    [InlineData(BootstrapTestInspectVariant.WrongModel)]
    [InlineData(BootstrapTestInspectVariant.WrongSocSerial)]
    [InlineData(BootstrapTestInspectVariant.WrongBootId)]
    [InlineData(BootstrapTestInspectVariant.RamRootFalse)]
    [InlineData(BootstrapTestInspectVariant.MalformedJson)]
    public async Task StartAsync_RejectsInspectIdentityMismatchWithoutLeakingBearerToken(BootstrapTestInspectVariant variant)
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson(variant) };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => bootstrap.StartAsync(bundle));

        Assert.Equal(MaintenanceErrorCode.HandshakeMismatch, exception.Code);
        var inspection = Assert.Single(transfer.Inspections);
        foreach (var current in ExceptionChain(exception))
        {
            Assert.DoesNotContain(inspection.BearerToken, current.ToString());
            Assert.DoesNotContain(inspection.BearerToken, current.Message);
        }
    }

    [Fact]
    public async Task StartAsync_GeneratesOpaqueTokenSharedWithInspectAndFreshPerStart()
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var first = await bootstrap.StartAsync(bundle);
        var second = await bootstrap.StartAsync(bundle);

        AssertOpaqueToken(first.BearerToken);
        AssertOpaqueToken(second.BearerToken);
        Assert.NotEqual(first.BearerToken, second.BearerToken);
        Assert.Equal(first.BearerToken, transfer.Inspections[0].BearerToken);
        Assert.Equal(second.BearerToken, transfer.Inspections[1].BearerToken);
        Assert.Equal(first.SocSerial, second.SocSerial);
    }

    [Fact]
    public async Task SessionToString_RedactsBearerToken()
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var session = await bootstrap.StartAsync(bundle);

        var text = session.ToString();
        Assert.False(string.IsNullOrWhiteSpace(text));
        Assert.DoesNotContain(session.BearerToken, text);
    }

    [Fact]
    public async Task StartAsync_WithPreCancelledToken_DoesNotReachConsoleOrTransfer()
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => bootstrap.StartAsync(bundle, cancellation.Token));

        Assert.Empty(console.Calls);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
    }

    [Theory]
    [InlineData(BootstrapTestSerialFailureVariant.HashMismatch)]
    [InlineData(BootstrapTestSerialFailureVariant.MissingMarker)]
    public async Task StartAsync_StopsBeforeHelperLaunchWhenSerialVerificationFails(BootstrapTestSerialFailureVariant variant)
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = new BootstrapTestFakeConsole(events, (script, marker) =>
        {
            if (script.Contains("sha256", StringComparison.OrdinalIgnoreCase))
            {
                if (variant == BootstrapTestSerialFailureVariant.HashMismatch)
                {
                    throw new MaintenanceException(
                        MaintenanceErrorCode.AssetHashMismatch,
                        "injected serial verification failure");
                }

                return "TRANSCRIPT_WITHOUT_VERIFIED_MARKER\n";
            }

            return DefaultResponse(script, marker);
        });
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => bootstrap.StartAsync(bundle));

        Assert.Equal(MaintenanceErrorCode.AssetHashMismatch, exception.Code);
        Assert.NotEmpty(console.Calls);
        Assert.Contains(console.Calls, call => call.Script.Contains("sha256", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(console.Calls, call => call.Script.Contains("busybox wc -c", StringComparison.Ordinal));

        Assert.Empty(transfer.Inspections);
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("maintenance_bootstrap.sh", StringComparison.Ordinal));
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("serve", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("--token-file", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_WhenUploadFails_StopsOnlyTheReceiverPidOwnedByThisCall()
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = CreateConsole(events);
        var transfer = new BootstrapTestFakeTransfer(events)
        {
            InspectJson = InspectJson(),
            UploadFailure = new IOException("injected upload failure"),
        };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<IOException>(() => bootstrap.StartAsync(bundle));

        Assert.Equal("injected upload failure", exception.Message);
        Assert.Equal(new[] { ToolboxRole }, bundle.OpenedRoles);
        Assert.Single(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("maintenance_bootstrap.sh", StringComparison.Ordinal));
        Assert.Single(console.Calls, call => call.Script.Contains("nc -l -p 8201", StringComparison.Ordinal));

        // Cleanup is the serial step right after the receiver and the failed upload.
        var cleanup = console.Calls[console.Calls.Count - 1];
        Assert.Equal("FREEDOM_MAINT_RECV_CLEAN_V1_OK", cleanup.ExpectedMarker);
        Assert.Contains("owned=" + DefaultReceiverPid, cleanup.Script);
        Assert.Contains("toolbox.pid", cleanup.Script);
        Assert.Contains("[ \"$(busybox cat /run/freedom-maintenance/toolbox.pid", cleanup.Script);
        Assert.DoesNotContain("kill 0", cleanup.Script);
        Assert.DoesNotContain("kill 1 ", cleanup.Script);
        Assert.DoesNotContain("-TERM", cleanup.Script);
        Assert.DoesNotMatch(@"\bkill\s+-9(?:\s|$)", cleanup.Script);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("12a45")]
    public async Task StartAsync_RejectsUnprovenReceiverPidBeforeAnyUpload(string? ncPid)
    {
        var events = new List<string>();
        var bundle = CreateKnownBundle();
        var console = new BootstrapTestFakeConsole(
            events,
            (_, marker) =>
            {
                if (marker.Contains("FREEDOM_MAINT_ID_V1_END", StringComparison.Ordinal))
                {
                    return IdentityTranscript();
                }

                return marker.Contains("FREEDOM_MAINT_RECV_V1_READY", StringComparison.Ordinal)
                    ? ReceiverTranscript(ncPid)
                    : marker + "\n";
            });
        var transfer = new BootstrapTestFakeTransfer(events) { InspectJson = InspectJson() };
        var bootstrap = new MaintenanceBootstrap(console, transfer);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => bootstrap.StartAsync(bundle));

        Assert.Equal(MaintenanceErrorCode.UnsafeEnvironment, exception.Code);
        Assert.Empty(bundle.OpenedRoles);
        Assert.Empty(bundle.Streams);
        Assert.Empty(transfer.Uploads);
        Assert.Empty(transfer.Inspections);
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("maintenance_bootstrap.sh", StringComparison.Ordinal));
        Assert.DoesNotContain(console.Calls, call => call.Script.Contains("sha256", StringComparison.OrdinalIgnoreCase));
    }

    private static BootstrapTestFakeBundle CreateKnownBundle() => new(
        new MaintenanceProfile(KnownProfileId, KnownModel, KnownBuild, KnownSoc),
        AllRoles);

    private static BootstrapTestFakeConsole CreateConsole(List<string> events) =>
        new(events, DefaultResponse);

    /// <summary>
    /// Mirrors the device contract: only the receiver phase reports its own nc pid, every other
    /// phase answers with the bare marker.
    /// </summary>
    private static string DefaultResponse(string script, string marker)
    {
        if (marker.Contains("FREEDOM_MAINT_RECV_V1_READY", StringComparison.Ordinal))
        {
            return ReceiverTranscript(DefaultReceiverPid);
        }

        return marker.Contains("FREEDOM_MAINT_ID_V1_END", StringComparison.Ordinal)
            ? IdentityTranscript()
            : marker + "\n";
    }

    private static string ReceiverTranscript(string? ncPid)
    {
        var lines = new List<string> { "FREEDOM_MAINT_RECV_V1_BEGIN" };
        if (ncPid is not null)
        {
            lines.Add("ncPid=" + ncPid);
        }

        lines.Add("FREEDOM_MAINT_RECV_V1_READY");
        return string.Join("\n", lines) + "\n";
    }

    private static string IdentityTranscript(
        BootstrapTestIdentityVariant variant = BootstrapTestIdentityVariant.Valid,
        string rootFstype = "ramfs")
    {
        var model = KnownModel;
        var soc = KnownSoc;
        var socSerial = KnownSocSerial;
        var bootId = KnownBootId;
        var ramRoot = "true";
        var compatible = CompatibleTokens;
        var usbGadgetReady = "true";
        var includeSocSerial = true;
        var duplicateModel = false;

        switch (variant)
        {
            case BootstrapTestIdentityVariant.Valid:
                break;
            case BootstrapTestIdentityVariant.RamRootFalse:
                ramRoot = "false";
                break;
            case BootstrapTestIdentityVariant.RootFstypeExt4:
                rootFstype = "ext4";
                break;
            case BootstrapTestIdentityVariant.WrongModel:
                model = "TB323FU";
                break;
            case BootstrapTestIdentityVariant.WrongSoc:
                soc = "SM8650";
                break;
            case BootstrapTestIdentityVariant.MissingCompatibleToken:
                compatible = "lenovo,elden";
                break;
            case BootstrapTestIdentityVariant.BlankSocSerial:
                socSerial = string.Empty;
                break;
            case BootstrapTestIdentityVariant.InvalidBootId:
                bootId = "not-a-uuid";
                break;
            case BootstrapTestIdentityVariant.UsbGadgetNotReady:
                usbGadgetReady = "false";
                break;
            case BootstrapTestIdentityVariant.DuplicateModel:
                duplicateModel = true;
                break;
            case BootstrapTestIdentityVariant.MissingSocSerial:
                includeSocSerial = false;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(variant));
        }

        var lines = new List<string>
        {
            "model=" + model,
            "soc=" + soc,
        };
        if (includeSocSerial)
        {
            lines.Add("socSerial=" + socSerial);
        }

        if (duplicateModel)
        {
            lines.Add("model=" + model);
        }

        lines.Add("bootId=" + bootId);
        lines.Add("ramRoot=" + ramRoot);
        lines.Add("rootFstype=" + rootFstype);
        lines.Add("compatible=" + compatible);
        lines.Add("usbGadgetReady=" + usbGadgetReady);

        return "FREEDOM_MAINT_ID_V1_BEGIN\n"
            + string.Join("\n", lines)
            + "\nFREEDOM_MAINT_ID_V1_END\n";
    }

    private static string InspectJson(BootstrapTestInspectVariant variant = BootstrapTestInspectVariant.Valid)
    {
        if (variant == BootstrapTestInspectVariant.MalformedJson)
        {
            return "{ \"schemaVersion\": 1, \"model\": ";
        }

        var schemaVersion = variant == BootstrapTestInspectVariant.SchemaTwo ? "2" : "1";
        var model = variant == BootstrapTestInspectVariant.WrongModel ? "TB323FU" : KnownModel;
        var socSerial = variant == BootstrapTestInspectVariant.WrongSocSerial ? "SN-OTHER-9999" : KnownSocSerial;
        var bootId = variant == BootstrapTestInspectVariant.WrongBootId
            ? "11111111-2222-4333-8444-555555555555"
            : KnownBootId;
        var ramRoot = variant == BootstrapTestInspectVariant.RamRootFalse ? "false" : "true";

        return "{"
            + "\"schemaVersion\":" + schemaVersion + ","
            + "\"model\":\"" + model + "\","
            + "\"socSerial\":\"" + socSerial + "\","
            + "\"bootId\":\"" + bootId + "\","
            + "\"ramRoot\":" + ramRoot + ","
            + "\"storage\":{\"gpt\":true}"
            + "}";
    }

    private static void AssertOpaqueToken(string token)
    {
        Assert.Equal(64, token.Length);
        Assert.All(token, character => Assert.True(IsLowerHex(character), "token must be lowercase hex"));
    }

    private static bool IsLowerHex(char character) =>
        character is (>= '0' and <= '9') or (>= 'a' and <= 'f');

    private static IEnumerable<Exception> ExceptionChain(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }

    public enum BootstrapTestIdentityVariant
    {
        Valid,
        RamRootFalse,
        RootFstypeExt4,
        WrongModel,
        WrongSoc,
        MissingCompatibleToken,
        BlankSocSerial,
        InvalidBootId,
        UsbGadgetNotReady,
        DuplicateModel,
        MissingSocSerial,
    }

    public enum BootstrapTestInspectVariant
    {
        Valid,
        SchemaTwo,
        WrongModel,
        WrongSocSerial,
        WrongBootId,
        RamRootFalse,
        MalformedJson,
    }

    public enum BootstrapTestSerialFailureVariant
    {
        HashMismatch,
        MissingMarker,
    }

    private sealed class BootstrapTestFakeBundle : IMaintenanceBundle
    {
        private const long BootBytes = 100663296L;
        private const string BootSha256 = "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358";
        private const long ToolboxBytes = 171162924L;
        private const string ToolboxSha256 = "79a2d937f2cf566591fde9bb8fc1b594fb9e949176fbde0364e9f09976af14a2";

        private readonly Dictionary<string, byte[]> _payloads;
        private readonly Dictionary<string, (long Bytes, string Sha256)> _metadataOverrides;

        public BootstrapTestFakeBundle(MaintenanceProfile profile, params string[] roles)
            : this(profile, null, roles)
        {
        }

        public BootstrapTestFakeBundle(
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

        public List<BootstrapTestTrackingStream> Streams { get; } = new();

        public MaintenanceAsset GetAsset(string role)
        {
            var metadata = ResolveMetadata(role);
            return new MaintenanceAsset(role, "/fake-assets/" + role, metadata.Bytes, metadata.Sha256);
        }

        public Stream OpenAsset(string role)
        {
            EnsureRole(role);
            OpenedRoles.Add(role);
            var stream = new BootstrapTestTrackingStream();
            Streams.Add(stream);
            return stream;
        }

        public void Dispose() => Disposed = true;

        private (long Bytes, string Sha256) ResolveMetadata(string role)
        {
            EnsureRole(role);
            return _metadataOverrides.TryGetValue(role, out var pinned) ? pinned : DefaultMetadata(role);
        }

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

    private sealed class BootstrapTestFakeConsole : IMaintenanceConsole
    {
        private readonly List<string> _events;
        private readonly Func<string, string, string> _responder;

        public BootstrapTestFakeConsole(List<string> events, Func<string, string, string> responder)
        {
            _events = events;
            _responder = responder;
        }

        public List<BootstrapTestCommandRecord> Calls { get; } = new();

        public Task<string> RunCommandAsync(
            string script,
            string expectedMarker,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(new BootstrapTestCommandRecord(script, expectedMarker, timeout));
            _events.Add("console");
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<string>(cancellationToken);
            }

            return Task.FromResult(_responder(script, expectedMarker));
        }
    }

    private sealed class BootstrapTestFakeTransfer : IMaintenanceTransfer
    {
        private readonly List<string> _events;

        public BootstrapTestFakeTransfer(List<string> events)
        {
            _events = events;
        }

        public List<BootstrapTestUploadRecord> Uploads { get; } = new();

        public List<BootstrapTestInspectRecord> Inspections { get; } = new();

        public string InspectJson { get; set; } = "{}";

        public Exception? UploadFailure { get; set; }

        public Task UploadAsync(
            string host,
            int port,
            Stream content,
            long expectedBytes,
            CancellationToken cancellationToken = default)
        {
            _events.Add("upload");
            Uploads.Add(new BootstrapTestUploadRecord(host, port, expectedBytes, content));
            return UploadFailure is null ? Task.CompletedTask : Task.FromException(UploadFailure);
        }

        public Task<string> InspectAsync(
            Uri baseAddress,
            string bearerToken,
            CancellationToken cancellationToken = default)
        {
            _events.Add("inspect");
            Inspections.Add(new BootstrapTestInspectRecord(baseAddress, bearerToken));
            return Task.FromResult(InspectJson);
        }
    }

    private sealed class BootstrapTestTrackingStream : MemoryStream
    {
        public bool WasDisposed { get; private set; }

        public override bool CanRead => !WasDisposed && base.CanRead;

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed record BootstrapTestCommandRecord(string Script, string ExpectedMarker, TimeSpan Timeout);

    private sealed record BootstrapTestUploadRecord(string Host, int Port, long ExpectedBytes, Stream Content);

    private sealed record BootstrapTestInspectRecord(Uri BaseAddress, string BearerToken);
}
