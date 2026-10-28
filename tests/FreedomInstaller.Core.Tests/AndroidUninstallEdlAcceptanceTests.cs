using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for the EDL acceptance path: <see cref="EdlEntryResult"/> is the entry proof and
/// <see cref="AndroidUninstallAcceptance.VerifyEdlAsync"/> is the independent acceptance decision that must
/// never build a fake binding, never unlock anything and never infer a size or node from the plan.
/// <para>
/// The validated inputs are built through the real GPT/sfdisk fixtures and
/// <see cref="UninstallEvidenceValidator.Validate"/>; the only edited field is the reported device, so all
/// CRCs, GUIDs, geometry, attributes and the restore plan stay the fixture's own bytes. No process, device,
/// artifact directory or network is touched.
/// </para>
/// <para>
/// Until the method is implemented these tests fail with <see cref="NotImplementedException"/>: no assertion
/// in this file treats that exception as a valid pending/rejection outcome.
/// </para>
/// </summary>
public sealed class AndroidUninstallEdlAcceptanceTests
{
    private const string Serial = "TEST0001";
    private const string Model = "TB322FC";
    private const string AdbPath = "/opt/android/platform-tools/adb";
    private const string EdlDevice = "edl:ufs:lun:0";

    /// <summary>Fixture userdata GPT number. Deliberately not 16, which a real device may report.</summary>
    private const int UserdataNumber = 2;

    /// <summary>Restored extent in the 512-byte units sysfs prints; exactly the fixture's plan.</summary>
    private const long RestoredSysfsUnits = 943_190_680L;

    private const string SocDecimal = "3251823604";
    private const string SocHex = "C1D2E3F4";
    private const string EndpointInstanceId = @"USB\VID_05C6&PID_9008\8&19888C89&0&8";
    private const string BusDescription = "QUSB_BULK_CID:045A_SN:C1D2E3F4";
    private const string Fingerprint = "google/fingerprint";
    private const string AndroidVersion = "16";
    private const string PatchLevel = "2026-06-01";

    /// <summary>A 128 GiB filesystem from an older layout; smaller than the restored plan.</summary>
    private const long OldFilesystemBytes = 128L * 1024L * 1024L * 1024L;

    // ------------------------------------------------------------- accepted EDL evidence

    [Theory]
    [InlineData(BootloaderState.Unknown)]
    [InlineData(BootloaderState.Locked)]
    public async Task VerifyEdl_AcceptsReadableRawSizeFilesystemAndActualNode(BootloaderState state)
    {
        var identity = EdlIdentity(state);
        var inputs = EdlInputs(identity: identity);
        var plan = inputs.Plan.RestoredAndroidBytes;
        var filesystem = FilesystemAt98Percent(plan);
        var observation = Observation(plan, filesystem, node: "/dev/block/sda2");
        var probe = EdlAcceptanceLiteralProbe.Reading(observation);

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(identity), probe);

        Assert.True(result.Accepted);
        Assert.False(result.FilesystemOnlyEvidence);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        // Actual read values are preserved verbatim, and the plan is never echoed as an observation.
        Assert.Equal(plan, result.UserdataPartitionBytes);
        Assert.Equal(filesystem, result.DataFilesystemBytes);
        Assert.Equal(GptFixture.RestoredAndroidBytes, plan);

        var request = Assert.Single(probe.Requests);
        Assert.Equal(inputs.Identity.Serial, request.Serial);
        Assert.Equal(AdbAndroidUninstallAcceptanceProbe.ExpectedDiskDeviceId, request.DiskDeviceId);
        Assert.Equal(UserdataNumber, request.UserdataPartitionNumber);
        Assert.NotEqual(16, request.UserdataPartitionNumber);
    }

    [Fact]
    public async Task VerifyEdl_AcceptsTheExplicitPermissionDeniedFilesystemOnlyPath()
    {
        var inputs = EdlInputs();
        var filesystem = FilesystemAt98Percent(inputs.Plan.RestoredAndroidBytes);
        var observation = Observation(
            0,
            filesystem,
            node: "/dev/block/sda2",
            partitionSizePermissionDenied: true);
        var probe = EdlAcceptanceLiteralProbe.Reading(observation);

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        Assert.True(result.Accepted);
        Assert.True(result.FilesystemOnlyEvidence);
        Assert.Null(result.UserdataPartitionBytes);
        Assert.Equal(filesystem, result.DataFilesystemBytes);
        Assert.Single(probe.Requests);
    }

    // ------------------------------------------------------- capacity and size refusals

    [Theory]
    [InlineData(EdlAcceptanceSizeDefect.OldFilesystem)]
    [InlineData(EdlAcceptanceSizeDefect.WrongReadableSizeWithDeniedFlag)]
    [InlineData(EdlAcceptanceSizeDefect.ZeroWithoutDeniedFlag)]
    public async Task VerifyEdl_RejectsUnprovenPartitionOrFilesystemSize(EdlAcceptanceSizeDefect defect)
    {
        var inputs = EdlInputs();
        var plan = inputs.Plan.RestoredAndroidBytes;
        var observation = defect switch
        {
            EdlAcceptanceSizeDefect.OldFilesystem
                => Observation(plan, OldFilesystemBytes, node: "/dev/block/sda2"),
            EdlAcceptanceSizeDefect.WrongReadableSizeWithDeniedFlag
                => Observation(
                    plan - 512L,
                    FilesystemAt98Percent(plan),
                    node: "/dev/block/sda2",
                    partitionSizePermissionDenied: true),
            EdlAcceptanceSizeDefect.ZeroWithoutDeniedFlag
                => Observation(0, FilesystemAt98Percent(plan), node: "/dev/block/sda2"),
            _ => throw new InvalidOperationException("fixture: unknown size defect " + defect),
        };

        var probe = EdlAcceptanceLiteralProbe.Reading(observation);

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        AssertPending(result);
        Assert.False(result.FilesystemOnlyEvidence);
        Assert.Single(probe.Requests);
    }

    // ------------------------------------------------------------- readlink node refusals

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/dev/block/sda3")]
    public async Task VerifyEdl_RejectsAMissingOrWrongActualUserdataNode(string? node)
    {
        var inputs = EdlInputs();
        var plan = inputs.Plan.RestoredAndroidBytes;
        var observation = Observation(plan, FilesystemAt98Percent(plan), node);
        var probe = EdlAcceptanceLiteralProbe.Reading(observation);

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        // Valid byte sizes cannot replace the actual readlink evidence.
        AssertPending(result);
        Assert.Single(probe.Requests);
    }

    // ---------------------------------------------------------- observed Android refusals

    [Theory]
    [InlineData(EdlAcceptanceObservationDefect.WrongModel)]
    [InlineData(EdlAcceptanceObservationDefect.WrongSerial)]
    [InlineData(EdlAcceptanceObservationDefect.BootNotCompleted)]
    [InlineData(EdlAcceptanceObservationDefect.FilesystemUnknown)]
    [InlineData(EdlAcceptanceObservationDefect.FilesystemOverPlan)]
    public async Task VerifyEdl_RejectsObservedAndroidThatDoesNotMatch(
        EdlAcceptanceObservationDefect defect)
    {
        var inputs = EdlInputs();
        var plan = inputs.Plan.RestoredAndroidBytes;
        var filesystem = FilesystemAt98Percent(plan);

        var observation = defect switch
        {
            EdlAcceptanceObservationDefect.WrongModel
                => Observation(plan, filesystem, "/dev/block/sda2", model: "TB999XX"),
            EdlAcceptanceObservationDefect.WrongSerial
                => Observation(plan, filesystem, "/dev/block/sda2", serial: Serial + "9"),
            EdlAcceptanceObservationDefect.BootNotCompleted
                => Observation(plan, filesystem, "/dev/block/sda2", bootCompleted: false),
            EdlAcceptanceObservationDefect.FilesystemUnknown
                => Observation(plan, null, "/dev/block/sda2"),
            EdlAcceptanceObservationDefect.FilesystemOverPlan
                => Observation(plan, plan + 512L, "/dev/block/sda2"),
            _ => throw new InvalidOperationException("fixture: unknown observation defect " + defect),
        };

        var probe = EdlAcceptanceLiteralProbe.Reading(observation);

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        AssertPending(result);
        Assert.Single(probe.Requests);
    }

    // --------------------------------------------------------- binding refusals (no read)

    [Theory]
    [InlineData(EdlAcceptanceBindingDefect.IdentitySerial)]
    [InlineData(EdlAcceptanceBindingDefect.IdentityModel)]
    [InlineData(EdlAcceptanceBindingDefect.WrongBuild)]
    [InlineData(EdlAcceptanceBindingDefect.SocDecimal)]
    [InlineData(EdlAcceptanceBindingDefect.BusSerial)]
    [InlineData(EdlAcceptanceBindingDefect.MissingSn)]
    [InlineData(EdlAcceptanceBindingDefect.DuplicateSn)]
    [InlineData(EdlAcceptanceBindingDefect.ForeignEndpoint)]
    public async Task VerifyEdl_RejectsBindingEvidenceBeforeAnyRead(EdlAcceptanceBindingDefect defect)
    {
        var inputs = EdlInputs();
        var probe = EdlAcceptanceLiteralProbe.Reading(ValidObservation(inputs));

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, BindingWithDefect(inputs, defect), probe);

        AssertPending(result);
        Assert.Empty(probe.Requests);
    }

    // ------------------------------------------------ unsupported profile (identity equality)

    [Theory]
    [InlineData("TB323FU", MaintenanceProfiles.AndroidBuild)]
    [InlineData("TB322FC", "TB322FC_WRONG_BUILD")]
    public async Task VerifyEdl_RejectsUnsupportedProfileEvenWhenBindingIdentityIsIdentical(
        string model,
        string displayId)
    {
        // The inputs and the binding carry the SAME literal identity, so no identity-equality guard can
        // reject this: only the profile check can refuse it, and it must refuse before any read.
        var identity = EdlIdentity(model: model, displayId: displayId);
        var inputs = EdlInputs(identity: identity);
        var probe = EdlAcceptanceLiteralProbe.Reading(ValidObservation(inputs));

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(identity), probe);

        AssertPending(result);
        Assert.Empty(probe.Requests);
    }

    [Theory]
    [InlineData("/dev/sda")]
    [InlineData("edl:ufs:lun:1")]
    public async Task VerifyEdl_RejectsAnotherTransportBeforeAnyRead(string device)
    {
        var inputs = EdlInputs(device);
        var probe = EdlAcceptanceLiteralProbe.Reading(ValidObservation(inputs));

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        AssertPending(result);
        Assert.Empty(probe.Requests);
    }

    // --------------------------------------------------------------------- probe failures

    [Fact]
    public async Task VerifyEdl_ReportsPendingWhenTheProbeCannotRead()
    {
        var inputs = EdlInputs();
        var probe = EdlAcceptanceLiteralProbe.Failing(new IOException("adb: no devices/emulators found"));

        var result = await AndroidUninstallAcceptance.VerifyEdlAsync(
            inputs, EdlBinding(inputs.Identity), probe);

        AssertPending(result);
        Assert.Single(probe.Requests);
    }

    [Fact]
    public async Task VerifyEdl_PropagatesPreCancelledCallerTokenWithoutReading()
    {
        var inputs = EdlInputs();
        var probe = EdlAcceptanceLiteralProbe.Reading(ValidObservation(inputs));

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AndroidUninstallAcceptance.VerifyEdlAsync(
                inputs, EdlBinding(inputs.Identity), probe, cancellation.Token));

        Assert.Empty(probe.Requests);
    }

    // ------------------------------------------------------- real probe evidence contract

    [Fact]
    public async Task Read_WithReadableSizeReadsTheExactNodeAndRecordsIt()
    {
        var plan = GptFixture.RestoredAndroidBytes;
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(EdlAdb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(EdlAdb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(EdlAdb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(EdlAdb("shell", "cat", "/sys/class/block/sda2/size"), RestoredSysfsUnits + "\n")
            .Answer(EdlAdb("shell", "readlink", "-f", "/dev/block/by-name/userdata"), "/dev/block/sda2\n")
            .Answer(EdlAdb("shell", "-T", "df", "-k", "/data"), EdlDataRow(plan / 1024L));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, "/dev/sda", UserdataNumber);

        Assert.Equal(plan, observation.UserdataPartitionBytes);
        Assert.Equal("/dev/block/sda2", observation.UserdataDeviceNode);
        Assert.False(observation.PartitionSizePermissionDenied);

        Assert.Equal(6, runner.Commands.Count);
        AssertCommand(runner.Commands[4], "-s", Serial, "shell", "readlink", "-f", "/dev/block/by-name/userdata");
        AssertCommand(runner.Commands[5], "-s", Serial, "shell", "-T", "df", "-k", "/data");

        // Exactly one readlink call on the readable branch.
        Assert.Equal(
            1,
            runner.Commands.Count(command => command.Arguments.Contains("readlink", StringComparer.Ordinal)));
    }

    [Fact]
    public async Task Read_RefusesAReadlinkTargetForAnotherNode()
    {
        var plan = GptFixture.RestoredAndroidBytes;
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(EdlAdb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(EdlAdb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(EdlAdb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(EdlAdb("shell", "cat", "/sys/class/block/sda2/size"), RestoredSysfsUnits + "\n")
            .Answer(EdlAdb("shell", "readlink", "-f", "/dev/block/by-name/userdata"), "/dev/block/sda3\n")
            .Answer(EdlAdb("shell", "-T", "df", "-k", "/data"), EdlDataRow(plan / 1024L));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => probe.ReadAsync(Serial, "/dev/sda", UserdataNumber));
    }

    [Fact]
    public async Task Read_PermissionDeniedBranchStillRecordsTheActualNodeWithSixQueries()
    {
        var plan = GptFixture.RestoredAndroidBytes;
        var runner = new AndroidAcceptanceCommandRunner()
            .Answer(EdlAdb("shell", "getprop", "ro.product.model"), Model + "\n")
            .Answer(EdlAdb("shell", "getprop", "ro.serialno"), Serial + "\n")
            .Answer(EdlAdb("shell", "getprop", "sys.boot_completed"), "1\n")
            .Answer(
                EdlAdb("shell", "cat", "/sys/class/block/sda2/size"),
                string.Empty,
                exitCode: 1,
                standardError: "cat: /sys/class/block/sda2/size: Permission denied")
            .Answer(EdlAdb("shell", "readlink", "-f", "/dev/block/by-name/userdata"), "/dev/block/sda2\n")
            .Answer(EdlAdb("shell", "-T", "df", "-k", "/data"), EdlDataRow(plan / 1024L));

        var probe = new AdbAndroidUninstallAcceptanceProbe(runner, AdbPath);

        var observation = await probe.ReadAsync(Serial, "/dev/sda", UserdataNumber);

        Assert.True(observation.PartitionSizePermissionDenied);
        Assert.Equal(0L, observation.UserdataPartitionBytes);
        Assert.Equal("/dev/block/sda2", observation.UserdataDeviceNode);
        Assert.Equal(6, runner.Commands.Count);
        AssertCommand(runner.Commands[4], "-s", Serial, "shell", "readlink", "-f", "/dev/block/by-name/userdata");
    }

    // ----------------------------------------------------------------------- fixtures

    /// <summary>
    /// Builds the validated inputs from the real GPT bytes and the sfdisk document, changing only the
    /// reported device (and its partition nodes) so the EDL marker is the table's own device id.
    /// </summary>
    private static ValidatedUninstallInputs EdlInputs(
        string device = EdlDevice,
        DeviceIdentity? identity = null)
    {
        var image = GptFixture.RealLike4096();

        var original = OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);

        var current = UninstallEvidenceValidator.ReadCurrentSfdisk(
            SfdiskForDevice(device),
            GptFixture.DiskBytes4096);

        return UninstallEvidenceValidator.Validate(
            identity ?? EdlIdentity(),
            original,
            current,
            current.SourceFingerprint);
    }

    /// <summary>
    /// Parses the shared sfdisk JSON and relabels the table plus every partition node for the EDL device.
    /// Every other value the fixture carries - CRCs, GUIDs, geometry, sizes, attributes - is untouched.
    /// </summary>
    private static string SfdiskForDevice(string device)
    {
        var json = Sfdisk.Json();
        if (string.Equals(device, Sfdisk.Device, StringComparison.Ordinal))
        {
            return json;
        }

        var root = JsonNode.Parse(json)!;
        var table = root["partitiontable"]!.AsObject();
        table["device"] = device;

        foreach (var partition in table["partitions"]!.AsArray())
        {
            var node = partition!["node"]!.GetValue<string>();
            partition["node"] = device + "p" + node[Sfdisk.Device.Length..];
        }

        return root.ToJsonString();
    }

    private static DeviceIdentity EdlIdentity(
        BootloaderState state = BootloaderState.Unlocked,
        string serial = Serial,
        string model = Model,
        string displayId = MaintenanceProfiles.AndroidBuild)
        => new(serial, model, state)
        {
            Firmware = new FirmwareSnapshot(displayId, Fingerprint, AndroidVersion, PatchLevel, state),
        };

    /// <summary>The fake external EDL entry boundary: the same shape the real entry returns.</summary>
    private static EdlEntryResult EdlBinding(
        DeviceIdentity identity,
        string socSerial = SocDecimal,
        string busSerial = SocHex,
        string instanceId = EndpointInstanceId,
        string? busDescription = BusDescription)
        => new(
            new AndroidMaintenanceIdentity(identity, socSerial),
            new EdlEndpoint(instanceId, "COM7", busDescription),
            busSerial);

    private static EdlEntryResult BindingWithDefect(
        ValidatedUninstallInputs inputs,
        EdlAcceptanceBindingDefect defect)
    {
        // Every fixture keeps the other facts valid, so the named defect is the only difference.
        return defect switch
        {
            EdlAcceptanceBindingDefect.IdentitySerial
                => EdlBinding(EdlIdentity(serial: Serial + "9")),
            EdlAcceptanceBindingDefect.IdentityModel
                => EdlBinding(EdlIdentity(model: "TB323FU")),
            EdlAcceptanceBindingDefect.WrongBuild
                => EdlBinding(EdlIdentity(displayId: "TB322FC_WRONG_BUILD")),
            EdlAcceptanceBindingDefect.SocDecimal
                => EdlBinding(inputs.Identity, socSerial: "3823654013"),
            EdlAcceptanceBindingDefect.BusSerial
                => EdlBinding(inputs.Identity, busSerial: "DEADBEEF"),
            EdlAcceptanceBindingDefect.MissingSn
                => EdlBinding(inputs.Identity, busDescription: "QUSB_BULK_CID:045A"),
            EdlAcceptanceBindingDefect.DuplicateSn
                => EdlBinding(
                    inputs.Identity,
                    busDescription: "QUSB_BULK_CID:045A_SN:C1D2E3F4_SN:C1D2E3F4"),
            EdlAcceptanceBindingDefect.ForeignEndpoint
                => EdlBinding(
                    inputs.Identity,
                    instanceId: @"USB\VID_18D1&PID_4EE0\8&19888C89&0&8"),
            _ => throw new InvalidOperationException("fixture: unknown binding defect " + defect),
        };
    }

    private static AndroidUninstallObservation Observation(
        long rawBytes,
        long? filesystemBytes,
        string? node,
        string model = Model,
        string serial = Serial,
        bool bootCompleted = true,
        bool partitionSizePermissionDenied = false)
        => new(model, serial, bootCompleted, rawBytes)
        {
            DataFilesystemBytes = filesystemBytes,
            UserdataDeviceNode = node,
            PartitionSizePermissionDenied = partitionSizePermissionDenied,
        };

    private static AndroidUninstallObservation ValidObservation(ValidatedUninstallInputs inputs)
    {
        var plan = inputs.Plan.RestoredAndroidBytes;
        return Observation(plan, FilesystemAt98Percent(plan), "/dev/block/sda2");
    }

    private static long FilesystemAt98Percent(long bytes) => bytes * 98L / 100L;

    private static string EdlAdb(params string[] arguments)
        => string.Join(" ", new[] { "-s", Serial }.Concat(arguments));

    private static string EdlDataRow(long totalKBlocks)
        => "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            + "/dev/block/dm-6 " + totalKBlocks + " 1 " + (totalKBlocks - 1L) + " 1% /data\n";

    private static void AssertPending(AndroidUninstallAcceptanceResult result)
    {
        Assert.False(result.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    private static void AssertCommand(ProcessCommand command, params string[] expectedArguments)
    {
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(expectedArguments, command.Arguments.ToArray());
    }
}

/// <summary>Which size fact is wrong while the rest of the observation stays valid.</summary>
public enum EdlAcceptanceSizeDefect
{
    OldFilesystem,
    WrongReadableSizeWithDeniedFlag,
    ZeroWithoutDeniedFlag,
}

/// <summary>Which observed Android fact is wrong while the rest of the observation stays valid.</summary>
public enum EdlAcceptanceObservationDefect
{
    WrongModel,
    WrongSerial,
    BootNotCompleted,
    FilesystemUnknown,
    FilesystemOverPlan,
}

/// <summary>Which external entry fact is wrong while every other binding fact stays valid.</summary>
public enum EdlAcceptanceBindingDefect
{
    IdentitySerial,
    IdentityModel,
    WrongBuild,
    SocDecimal,
    BusSerial,
    MissingSn,
    DuplicateSn,
    ForeignEndpoint,
}

/// <summary>One read request the EDL acceptance check made, kept so a test can prove what was asked for.</summary>
internal sealed record EdlAcceptanceRequest(
    string Serial,
    string DiskDeviceId,
    int UserdataPartitionNumber);

/// <summary>
/// Literal-evidence probe: it returns exactly the observation a test scripted, or exactly the failure it
/// was built with. It never reads a device and never derives a value.
/// </summary>
internal sealed class EdlAcceptanceLiteralProbe : IAndroidUninstallAcceptanceProbe
{
    private readonly AndroidUninstallObservation? _observation;
    private readonly Exception? _failure;

    private EdlAcceptanceLiteralProbe(AndroidUninstallObservation? observation, Exception? failure)
    {
        _observation = observation;
        _failure = failure;
    }

    internal List<EdlAcceptanceRequest> Requests { get; } = new();

    internal static EdlAcceptanceLiteralProbe Reading(AndroidUninstallObservation observation)
        => new(observation, null);

    internal static EdlAcceptanceLiteralProbe Failing(Exception failure)
        => new(null, failure);

    public Task<AndroidUninstallObservation> ReadAsync(
        string serial,
        string diskDeviceId,
        int userdataPartitionNumber,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        Requests.Add(new EdlAcceptanceRequest(serial, diskDeviceId, userdataPartitionNumber));

        if (_failure is not null)
        {
            throw _failure;
        }

        return Task.FromResult(_observation!);
    }
}
