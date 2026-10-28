using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused contract tests for <see cref="InternalInstallAcceptance.CheckAndroidAsync"/>. They drive the real
/// read-only acceptance path through the default <see cref="AdbAndroidUninstallAcceptanceProbe"/> and one
/// stateful fake <see cref="ICommandRunner"/>. Most cases exercise the legacy four-argument route; the last
/// three also cover the trusted <see cref="EdlDeviceProfile"/> overload. Every assertion is about facts the
/// fake actually reported, never about an expected value copied into an observed slot.
/// </summary>
public sealed class InternalInstallAcceptanceTests
{
    private const string Adb = "adb";
    private const string Serial = "HA1B2C3D4";
    private const string Model = "TB322FC";
    private const string DisplayId = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    private const string CurrentFirmware = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
    private const string BuildFingerprint = DisplayId + "/release-keys";
    private const string AndroidRelease = "15";
    private const string SecurityPatch = "2026-06-01";
    private const uint SocSerial = 3251823604u;
    private const int UserdataPartitionNumber = 16;
    private const long ExpectedAndroidBytes = 17179869184L; // 16 GiB
    private const long DataFilesystemBytes = 16642998272L;  // 15.5 GiB
    private const long WrongPartitionBytes = 16000000000L;  // 512-byte multiple
    private const string UserdataSysfsPath = "/sys/class/block/sda16/size";

    private static readonly HashSet<string> ForbiddenVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "reboot", "flash", "flashall", "erase", "format", "push", "pull", "install",
        "uninstall", "sideload", "fastboot", "edl", "wipe", "set_active", "boot",
    };

    [Fact]
    public async Task Normal_verifies_with_actual_partition_filesystem_and_soc()
    {
        var fake = new FakeAdbRunner();
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.True(result.Verified);
        Assert.Equal(InternalAndroidAcceptanceState.Verified, result.State);
        Assert.Equal(ExpectedAndroidBytes, result.UserdataPartitionBytes!.Value);
        Assert.Equal(DataFilesystemBytes, result.DataFilesystemBytes!.Value);
        Assert.False(result.FilesystemOnlyEvidence);
        Assert.NotNull(result.ObservedIdentity);

        var identity = result.ObservedIdentity!;
        var firmware = identity.Identity.Firmware!;
        Assert.Equal(Serial, identity.Identity.Serial);
        Assert.Equal(Model, identity.Identity.Model);
        Assert.Equal(BootloaderState.Unknown, identity.Identity.BootloaderState);
        Assert.Equal(DisplayId, firmware.DisplayId);
        Assert.Equal(BuildFingerprint, firmware.BuildFingerprint);
        Assert.Equal(SocSerial.ToString(CultureInfo.InvariantCulture), identity.SocSerial);

        Assert.Equal("adb devices -l", fake.Commands[0]);
        Assert.DoesNotContain(fake.Commands, IsForbiddenCommand);
    }

    [Fact]
    public async Task Explicit_permission_denial_verifies_with_filesystem_only_evidence()
    {
        var fake = new FakeAdbRunner
        {
            RawSizeExitCode = 1,
            RawSizeStandardError = "cat: " + UserdataSysfsPath + ": Permission denied",
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.True(result.Verified);
        Assert.Null(result.UserdataPartitionBytes);
        Assert.Equal(DataFilesystemBytes, result.DataFilesystemBytes!.Value);
        Assert.True(result.FilesystemOnlyEvidence);
        Assert.DoesNotContain(fake.Commands, IsForbiddenCommand);
    }

    [Fact]
    public async Task Unauthorized_device_waits_for_usb_authorization_without_shell()
    {
        var fake = new FakeAdbRunner { DeviceList = DeviceList("unauthorized") };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.AwaitingUsbAuthorization, result.State);
        Assert.False(result.Verified);
        Assert.Single(fake.Commands);
        Assert.DoesNotContain(fake.Commands, command => command.Contains(" shell ", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("offline")]
    public async Task Missing_or_offline_device_waits_for_android_initialization_without_shell(string mode)
    {
        var fake = new FakeAdbRunner
        {
            DeviceList = mode == "none" ? "List of devices attached\n\n" : DeviceList("offline"),
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.AwaitingAndroidInitialization, result.State);
        Assert.Single(fake.Commands);
        Assert.DoesNotContain(fake.Commands, command => command.Contains(" shell ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Boot_not_completed_waits_before_any_size_query()
    {
        var fake = new FakeAdbRunner { BootCompleted = "0" };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.AwaitingAndroidInitialization, result.State);
        Assert.DoesNotContain(fake.Commands, command => command.Contains(UserdataSysfsPath, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Blank_boot_completed_waits_before_any_identity_or_size_query()
    {
        var fake = new FakeAdbRunner { BootCompleted = "  \t" };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.AwaitingAndroidInitialization, result.State);
        Assert.False(result.Verified);
        Assert.Null(result.ObservedIdentity);
        Assert.Null(result.UserdataPartitionBytes);
        Assert.Null(result.DataFilesystemBytes);
        Assert.False(result.FilesystemOnlyEvidence);

        // Only the device listing and the early boot gate ran; nothing after the gate was queried.
        Assert.Equal(2, fake.Commands.Count);
        Assert.DoesNotContain(fake.Commands, command => command.Contains(UserdataSysfsPath, StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Commands, command => command.Contains("readlink", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Commands, command => command.Contains(" df ", StringComparison.Ordinal));
        Assert.DoesNotContain(
            fake.Commands,
            command => command.Contains("/sys/devices/soc0/serial_number", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Commands, command => command.Contains("ro.boot.slot_suffix", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Commands, command => command.EndsWith(" shell getprop", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Different_actual_serial_is_rejected()
    {
        var fake = new FakeAdbRunner
        {
            SerialNo = "ZZZZ0000",
            BootSerialNo = "ZZZZ0000",
            FullGetprop = BuildFullGetprop(serialNo: "ZZZZ0000", bootSerialNo: "ZZZZ0000"),
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Actual_full_build_fingerprint_drift_is_rejected()
    {
        var fake = new FakeAdbRunner
        {
            FullGetprop = BuildFullGetprop(fingerprint: DisplayId + "/unexpected-release-keys"),
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Actual_soc_serial_drift_is_rejected()
    {
        var fake = new FakeAdbRunner { SocSerialNumber = "1111111111" };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Wrong_actual_partition_size_is_rejected_with_the_observed_bytes()
    {
        var fake = new FakeAdbRunner { RawSectorCount = WrongPartitionBytes / 512 };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        Assert.Equal(WrongPartitionBytes, result.UserdataPartitionBytes!.Value);
        Assert.False(result.Verified);
    }

    [Theory]
    [InlineData(16000000000L)] // below 95% of the 16 GiB baseline
    [InlineData(18000000000L)] // larger than the partition itself
    public async Task Out_of_policy_filesystem_size_is_rejected_with_the_observed_bytes(long filesystemBytes)
    {
        var fake = new FakeAdbRunner { DataFilesystemKib = filesystemBytes / 1024 };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes);

        Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        Assert.Equal(filesystemBytes, result.DataFilesystemBytes!.Value);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Wrong_actual_userdata_readlink_node_throws_invalid_data()
    {
        var fake = new FakeAdbRunner { UserdataNode = "/dev/block/sda15" };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        await Assert.ThrowsAsync<InvalidDataException>(() => acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes));
    }

    [Fact]
    public async Task Raw_size_query_failure_other_than_permission_denial_propagates_io_error()
    {
        var fake = new FakeAdbRunner
        {
            RawSizeExitCode = 1,
            RawSizeStandardError = "error: device offline",
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var error = await Assert.ThrowsAsync<IOException>(() => acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes));

        Assert.IsNotType<InvalidDataException>(error);
        Assert.DoesNotContain(fake.Commands, command => command.Contains("readlink", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Malformed_boot_completed_value_throws_invalid_data()
    {
        var fake = new FakeAdbRunner { BootCompleted = "yes" };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        await Assert.ThrowsAsync<InvalidDataException>(() => acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes));
    }

    [Fact]
    public async Task Caller_cancellation_before_the_call_throws_and_runs_no_command()
    {
        var fake = new FakeAdbRunner();
        var acceptance = new InternalInstallAcceptance(Adb, fake);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => acceptance.CheckAndroidAsync(
            CreateExpectedDevice(), UserdataPartitionNumber, ExpectedAndroidBytes, cancellation.Token));

        Assert.Empty(fake.Commands);
    }

    [Fact]
    public async Task Direct_profile_overload_verifies_from_actual_observed_facts()
    {
        var fake = new FakeAdbRunner();
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(),
            UserdataPartitionNumber,
            ExpectedAndroidBytes,
            EdlDeviceProfiles.Default);

        Assert.True(result.Verified);
        Assert.Equal(InternalAndroidAcceptanceState.Verified, result.State);
        Assert.Equal(ExpectedAndroidBytes, result.UserdataPartitionBytes!.Value);
        Assert.Equal(DataFilesystemBytes, result.DataFilesystemBytes!.Value);
        Assert.False(result.FilesystemOnlyEvidence);
        Assert.NotNull(result.ObservedIdentity);

        var identity = result.ObservedIdentity!;
        Assert.Equal(SocSerial.ToString(CultureInfo.InvariantCulture), identity.SocSerial);
        Assert.Equal(Serial, identity.Identity.Serial);
        Assert.Equal(Model, identity.Identity.Model);
        Assert.Equal(BootloaderState.Unknown, identity.Identity.BootloaderState);
        Assert.Equal(DisplayId, identity.Identity.Firmware!.DisplayId);

        Assert.Equal("adb devices -l", fake.Commands[0]);
        Assert.DoesNotContain(fake.Commands, IsForbiddenCommand);
    }

    [Fact]
    public async Task Synthetic_incomplete_profile_rejects_before_any_runner_command()
    {
        var profile = CreateSyntheticIncompleteProfile();
        Assert.False(profile.IsComplete);
        Assert.Null(EdlDeviceProfiles.FindById(profile.ProfileId));

        var fake = new FakeAdbRunner();
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => acceptance.CheckAndroidAsync(
            CreateExpectedDevice(),
            UserdataPartitionNumber,
            ExpectedAndroidBytes,
            profile));

        Assert.Contains("incomplete", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(fake.Commands);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FW01_Default_profile_uses_actual_firmware_and_rejects_sampling_drift(bool drift)
    {
        var fake = new FakeAdbRunner
        {
            FullGetprop = BuildFullGetprop(displayId: drift ? DisplayId : CurrentFirmware),
        };
        var acceptance = new InternalInstallAcceptance(Adb, fake);

        var result = await acceptance.CheckAndroidAsync(
            CreateExpectedDevice(displayId: CurrentFirmware),
            UserdataPartitionNumber,
            ExpectedAndroidBytes,
            EdlDeviceProfiles.Default);

        // Both outcomes must have compared the sampled identity, never a pre-run allow-list rule.
        Assert.NotEmpty(fake.Commands);
        Assert.DoesNotContain(fake.Commands, IsForbiddenCommand);

        if (drift)
        {
            Assert.False(result.Verified);
            Assert.Equal(InternalAndroidAcceptanceState.Rejected, result.State);
        }
        else
        {
            Assert.True(result.Verified);
            Assert.Equal(InternalAndroidAcceptanceState.Verified, result.State);
            Assert.NotNull(result.ObservedIdentity);
            Assert.Equal(CurrentFirmware, result.ObservedIdentity!.Identity.Firmware!.DisplayId);
        }
    }

    private static EdlDeviceProfile CreateSyntheticIncompleteProfile()
    {
        var constructor = typeof(EdlDeviceProfile)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(candidate => candidate.GetParameters().Length == 10);

        return (EdlDeviceProfile)constructor.Invoke(new object?[]
        {
            "synthetic-incomplete-acceptance",
            Model,
            "synthetic",
            null,
            new[] { DisplayId },
            EdlLoaderKind.Single,
            "synthetic/loader.melf",
            Array.Empty<EdlLoaderMaterial>(),
            null,
            false,
        })!;
    }

    private static InternalDeviceCheckResult CreateExpectedDevice(string currentSlot = "a", string? displayId = null)
    {
        var constructor = typeof(InternalDeviceCheckResult)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Single(candidate => candidate.GetParameters().Length == 10);

        return (InternalDeviceCheckResult)constructor.Invoke(new object?[]
        {
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(Serial, Model, BootloaderState.Unlocked) { Firmware = CreateFirmware(displayId) },
                SocSerial.ToString(CultureInfo.InvariantCulture)),
            Serial,
            Model,
            BootloaderState.Unlocked,
            OtaUpdateState.Completed,
            AndroidReturnState.Verified,
            false,
            null,
            null,
            currentSlot,
        })!;
    }

    private static FirmwareSnapshot CreateFirmware(string? displayId = null)
    {
        var actualDisplayId = displayId ?? DisplayId;

        return new FirmwareSnapshot(
            actualDisplayId,
            actualDisplayId + "/release-keys",
            AndroidRelease,
            SecurityPatch,
            BootloaderState.Unlocked);
    }

    private static bool IsForbiddenCommand(string recordedCommand)
    {
        return recordedCommand
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Any(token => ForbiddenVerbs.Contains(token));
    }

    private static string DeviceList(string state)
    {
        return "List of devices attached\n"
            + Serial + "\t" + state
            + " usb:1-1 product:TB322FC model:TB322FC device:TB322FC transport_id:1\n";
    }

    private static string BuildFullGetprop(
        string? fingerprint = null,
        string? serialNo = null,
        string? bootSerialNo = null,
        string? displayId = null)
    {
        var actualDisplayId = displayId ?? DisplayId;

        return "[ro.product.model]: [" + Model + "]\n"
            + "[ro.product.vendor.model]: [" + Model + "]\n"
            + "[ro.product.name]: [" + Model + "]\n"
            + "[ro.build.display.id]: [" + actualDisplayId + "]\n"
            + "[ro.build.fingerprint]: [" + (fingerprint ?? (actualDisplayId + "/release-keys")) + "]\n"
            + "[ro.build.version.release]: [" + AndroidRelease + "]\n"
            + "[ro.build.version.security_patch]: [" + SecurityPatch + "]\n"
            + "[ro.boot.flash.locked]: [0]\n"
            + "[ro.boot.vbmeta.device_state]: [unlocked]\n"
            + "[ro.serialno]: [" + (serialNo ?? Serial) + "]\n"
            + "[ro.boot.serialno]: [" + (bootSerialNo ?? Serial) + "]\n"
            + "[ro.boot.slot_suffix]: [_a]\n";
    }

    private static string CreateDfOutput(long totalKib)
    {
        var used = Math.Min(100000L, totalKib / 10);
        var available = totalKib - used;

        return "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            + "/dev/block/sda16 " + totalKib.ToString(CultureInfo.InvariantCulture)
            + " " + used.ToString(CultureInfo.InvariantCulture)
            + " " + available.ToString(CultureInfo.InvariantCulture)
            + " 1% /data\n";
    }

    /// <summary>
    /// One stateful adb double: answers only the exact read-only argv the production path may build,
    /// records every command, verifies the selected serial and the fixed 15 second timeout, and refuses
    /// anything unexpected so no test can silently pass on a made-up report.
    /// </summary>
    private sealed class FakeAdbRunner : ICommandRunner
    {
        private readonly List<string> _commands = new();

        public IReadOnlyList<string> Commands => _commands;

        public string DeviceList { get; set; } = InternalInstallAcceptanceTests.DeviceList("device");

        public string FullGetprop { get; set; } = BuildFullGetprop();

        public string BootCompleted { get; set; } = "1";

        public string ProductModel { get; set; } = Model;

        public string SerialNo { get; set; } = Serial;

        public string BootSerialNo { get; set; } = Serial;

        public string SlotSuffix { get; set; } = "_a";

        public string SocSerialNumber { get; set; } = SocSerial.ToString(CultureInfo.InvariantCulture);

        public long RawSectorCount { get; set; } = ExpectedAndroidBytes / 512;

        public int RawSizeExitCode { get; set; }

        public string RawSizeStandardError { get; set; } = string.Empty;

        public string UserdataNode { get; set; } = "/dev/block/sda16";

        public long DataFilesystemKib { get; set; } = DataFilesystemBytes / 1024;

        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!string.Equals(command.Executable, Adb, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Unexpected executable: " + command.Executable);
            }

            if (command.Timeout != TimeSpan.FromSeconds(15))
            {
                throw new InvalidOperationException(
                    "Every acceptance query must carry the fixed 15 second timeout.");
            }

            var arguments = command.Arguments;
            _commands.Add(command.Executable + " " + string.Join(" ", arguments));

            if (arguments.Count == 2
                && string.Equals(arguments[0], "devices", StringComparison.Ordinal)
                && string.Equals(arguments[1], "-l", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(DeviceList));
            }

            if (arguments.Count >= 2
                && !(string.Equals(arguments[0], "-s", StringComparison.Ordinal)
                    && string.Equals(arguments[1], Serial, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    "The acceptance check queried a serial other than the expected one.");
            }

            if (arguments.Count == 4
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "getprop", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(FullGetprop));
            }

            if (arguments.Count == 5
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "getprop", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(arguments[4] switch
                {
                    "sys.boot_completed" => BootCompleted,
                    "ro.product.model" => ProductModel,
                    "ro.serialno" => SerialNo,
                    "ro.boot.serialno" => BootSerialNo,
                    "ro.boot.slot_suffix" => SlotSuffix,
                    _ => throw new InvalidOperationException("Unexpected getprop: " + arguments[4]),
                }));
            }

            if (arguments.Count == 5
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "cat", StringComparison.Ordinal)
                && string.Equals(arguments[4], "/sys/devices/soc0/serial_number", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(SocSerialNumber));
            }

            if (arguments.Count == 5
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "cat", StringComparison.Ordinal)
                && string.Equals(arguments[4], UserdataSysfsPath, StringComparison.Ordinal))
            {
                return Task.FromResult(RawSizeExitCode == 0
                    ? Result(RawSectorCount.ToString(CultureInfo.InvariantCulture))
                    : new ProcessResult(RawSizeExitCode, string.Empty, RawSizeStandardError));
            }

            if (arguments.Count == 6
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "readlink", StringComparison.Ordinal)
                && string.Equals(arguments[4], "-f", StringComparison.Ordinal)
                && string.Equals(arguments[5], "/dev/block/by-name/userdata", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(UserdataNode));
            }

            if (arguments.Count == 7
                && string.Equals(arguments[2], "shell", StringComparison.Ordinal)
                && string.Equals(arguments[3], "-T", StringComparison.Ordinal)
                && string.Equals(arguments[4], "df", StringComparison.Ordinal)
                && string.Equals(arguments[5], "-k", StringComparison.Ordinal)
                && string.Equals(arguments[6], "/data", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(CreateDfOutput(DataFilesystemKib)));
            }

            throw new InvalidOperationException(
                "Unexpected adb command: " + string.Join(" ", arguments));
        }

        private static ProcessResult Result(string output) => new(0, output, string.Empty);
    }
}
