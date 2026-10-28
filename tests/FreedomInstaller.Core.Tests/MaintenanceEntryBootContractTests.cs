using System.Security.Cryptography;
using FreedomInstaller.Core;
using Xunit;
using Xunit.Sdk;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// UI005 boot contract for <see cref="MaintenanceEntry.BootTemporaryAsync"/>: the six ordered
/// adb/fastboot commands, the identity/OTA rejections, and the unsupported temporary-boot rejection.
/// The real pinned TB322FC boot.img (<c>MAINTENANCE_TEST_ASSET_ROOT/boot.img</c>) is mandatory;
/// no synthetic asset is generated and no adb/fastboot process or device is ever touched.
/// </summary>
public sealed class MaintenanceEntryBootContractTests
{
    private const string AdbPath = "adb";
    private const string FastbootPath = "fastboot";
    private const string DeviceSerial = "TEST0001";
    private const string DeviceSocSerial = "3251823604";

    // Reviewed Android identity (reported inside the OS) and the pinned G4.259 fastboot
    // hardware product (reported by the bootloader) are two different values.
    private const string AndroidModel = "TB322FC";
    private const string FastbootProduct = "elden_prc_wifi";
    private const string FirmwareDisplayId = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    private const string SnapshotQuery = "snapshot-update-status";

    private static readonly (string Name, string Value)[] IdentityQueries =
    {
        ("serialno", DeviceSerial),
        ("product", FastbootProduct),
        ("unlocked", "yes"),
        (SnapshotQuery, "none"),
    };

    // ---------------------------------------------------------------- 1) happy path

    [PinnedMaintenanceBootFact]
    public async Task Happy_path_issues_six_ordered_commands_and_reports_unlocked_completed()
    {
        string bootPath = PinnedMaintenanceAsset.ResolveBootImagePath();
        AssertPinnedAsset(bootPath);

        // Pin guards: the literals above must equal the production profile pins.
        Assert.Equal(FirmwareDisplayId, MaintenanceProfiles.AndroidBuild);
        Assert.Equal(AndroidModel, MaintenanceProfiles.Model);

        (AndroidMaintenanceIdentity identity, FirmwareSnapshot firmware) = CreateIdentity();
        var runner = new ScriptedCommandRunner(HappyPathExpectations(bootPath, bootExitCode: 0));
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        MaintenanceEntryResult result =
            await entry.BootTemporaryAsync(identity, bootPath, CancellationToken.None);

        runner.AssertFullyConsumed();
        Assert.Equal(6, runner.Consumed.Count);

        Assert.Equal(AdbPath, runner.Consumed[0].Executable);
        Assert.Equal(new[] { "-s", DeviceSerial, "reboot", "bootloader" }, runner.Consumed[0].Arguments);
        for (int index = 1; index <= 4; index++)
        {
            Assert.Equal(FastbootPath, runner.Consumed[index].Executable);
            Assert.Equal(
                new[] { "-s", DeviceSerial, "getvar", IdentityQueries[index - 1].Name },
                runner.Consumed[index].Arguments);
        }

        Assert.Equal(FastbootPath, runner.Consumed[5].Executable);
        Assert.Equal(
            new[] { "-s", DeviceSerial, "boot", Path.GetFullPath(bootPath) },
            runner.Consumed[5].Arguments);

        Assert.All(runner.Consumed, command =>
        {
            string display = string.Join(' ', command.Arguments);
            Assert.True(
                command.Timeout > TimeSpan.Zero,
                $"'{command.Executable} {display}' must use a finite positive timeout, got {command.Timeout}.");
            Assert.NotEqual(Timeout.InfiniteTimeSpan, command.Timeout);
            Assert.True(
                command.Timeout <= TimeSpan.FromMinutes(30),
                $"'{command.Executable} {display}' timeout is unexpectedly large: {command.Timeout}.");
        });

        Assert.DoesNotContain(runner.Consumed, command => ContainsWriteVerb(command.Arguments));

        Assert.Equal(BootloaderState.Unlocked, result.Identity.BootloaderState);
        Assert.Equal(DeviceSerial, result.Identity.Serial);
        Assert.Equal(AndroidModel, result.Identity.Model);
        Assert.NotNull(result.Identity.Firmware);
        FirmwareSnapshot preservedFirmware = result.Identity.Firmware!;
        Assert.Equal(firmware.DisplayId, preservedFirmware.DisplayId);
        Assert.Equal(firmware.BuildFingerprint, preservedFirmware.BuildFingerprint);
        Assert.Equal(firmware.AndroidRelease, preservedFirmware.AndroidRelease);
        Assert.Equal(firmware.SecurityPatch, preservedFirmware.SecurityPatch);
        Assert.Equal(firmware.AndroidReportedBootloaderState, preservedFirmware.AndroidReportedBootloaderState);
        Assert.Equal(DeviceSocSerial, result.AndroidSocSerial);
        Assert.Equal(DeviceSerial, result.FastbootSerial);
        Assert.Equal(OtaUpdateState.Completed, result.OtaState);
    }

    // ---------------------------------------------------------------- 1b) real hardware product

    [PinnedMaintenanceBootFact]
    public async Task Real_fastboot_hardware_product_preserves_Android_model_and_all_entry_guards()
    {
        string bootPath = PinnedMaintenanceAsset.ResolveBootImagePath();
        AssertPinnedAsset(bootPath);

        // The real device answers fastboot getvar product with its hardware product while the
        // reviewed Android identity (model + full firmware) is unchanged.
        (AndroidMaintenanceIdentity identity, _) = CreateIdentity();

        List<ExpectedCommand> expected = HappyPathExpectations(bootPath, bootExitCode: 0);
        expected[2] = GetVar("product", "elden_prc_wifi");

        var runner = new ScriptedCommandRunner(expected);
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        MaintenanceEntryResult result =
            await entry.BootTemporaryAsync(identity, bootPath, CancellationToken.None);

        runner.AssertFullyConsumed();
        Assert.Equal(6, runner.Consumed.Count);
        Assert.Equal(1, runner.Consumed.Count(IsTemporaryBootCommand));
        Assert.DoesNotContain(runner.Consumed, command => ContainsWriteVerb(command.Arguments));

        Assert.Equal(AndroidModel, result.Identity.Model);
        Assert.Equal(DeviceSerial, result.Identity.Serial);
        Assert.Equal(DeviceSerial, result.FastbootSerial);
        Assert.Equal(DeviceSocSerial, result.AndroidSocSerial);
        Assert.Equal(BootloaderState.Unlocked, result.Identity.BootloaderState);
        Assert.Equal(OtaUpdateState.Completed, result.OtaState);
    }

    // ---------------------------------------------------------------- 2) identity / OTA rejections

    [PinnedMaintenanceBootTheory]
    [InlineData("serialno", "OTHER")]
    [InlineData("product", "TB323FU")]
    [InlineData("product", "TB322FC")]
    [InlineData("product", "elden")]
    [InlineData("product", "elden_prc_wifi_extra")]
    [InlineData("product", "ELDEN_PRC_WIFI")]
    [InlineData("unlocked", "no")]
    [InlineData(SnapshotQuery, "merging")]
    [InlineData(SnapshotQuery, "unknown")]
    public async Task Identity_or_ota_mismatch_rejects_at_the_bad_query_without_boot(string failingQuery, string failingValue)
    {
        string bootPath = PinnedMaintenanceAsset.ResolveBootImagePath();
        (AndroidMaintenanceIdentity identity, _) = CreateIdentity();

        int failingIndex = IndexOfQuery(failingQuery);
        Assert.True(failingIndex >= 0, $"Unknown query under test: {failingQuery}.");

        var expected = new List<ExpectedCommand> { AdbReboot() };
        for (int index = 0; index <= failingIndex; index++)
        {
            // The device answers every query with exit code 0; only the value is unusable.
            string value = index == failingIndex ? failingValue : IdentityQueries[index].Value;
            expected.Add(GetVar(IdentityQueries[index].Name, value));
        }

        var runner = new ScriptedCommandRunner(expected);
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        Exception? exception = await Record.ExceptionAsync(
            () => entry.BootTemporaryAsync(identity, bootPath, CancellationToken.None));

        Assert.True(exception is not null, "BootTemporaryAsync accepted a wrong identity/OTA answer instead of rejecting it.");
        Assert.False(
            exception is XunitException,
            $"Scripted runner saw a command sequence that does not match the contract, so this rejection is not proven: {exception}");
        Assert.IsNotType<NotImplementedException>(exception);
        Assert.True(
            exception is InvalidOperationException or FormatException,
            $"Expected InvalidOperationException or FormatException, got {exception!.GetType().Name}: {exception.Message}");

        runner.AssertFullyConsumed();
        Assert.Equal(expected.Count, runner.Consumed.Count);

        ProcessCommand last = runner.Consumed[^1];
        Assert.Equal(FastbootPath, last.Executable);
        Assert.Equal(new[] { "-s", DeviceSerial, "getvar", failingQuery }, last.Arguments);
        Assert.DoesNotContain(runner.Consumed, IsTemporaryBootCommand);
    }

    // ---------------------------------------------------------------- 3) unsupported temporary boot

    [PinnedMaintenanceBootFact]
    public async Task Rejected_temporary_boot_stops_after_six_commands_without_retry()
    {
        string bootPath = PinnedMaintenanceAsset.ResolveBootImagePath();
        (AndroidMaintenanceIdentity identity, _) = CreateIdentity();

        var runner = new ScriptedCommandRunner(HappyPathExpectations(bootPath, bootExitCode: 1));
        var entry = new MaintenanceEntry(AdbPath, FastbootPath, runner);

        Exception? exception = await Record.ExceptionAsync(
            () => entry.BootTemporaryAsync(identity, bootPath, CancellationToken.None));

        Assert.True(exception is not null, "A failed temporary boot (exit code 1) must surface as a failure.");
        Assert.False(
            exception is XunitException,
            $"Scripted runner saw a command sequence that does not match the contract, so this rejection is not proven: {exception}");
        Assert.IsNotType<NotImplementedException>(exception);
        Assert.IsAssignableFrom<InvalidOperationException>(exception);

        runner.AssertFullyConsumed();
        Assert.Equal(6, runner.Consumed.Count);
        Assert.Equal(1, runner.Consumed.Count(IsTemporaryBootCommand));
        Assert.Equal(
            new[] { "-s", DeviceSerial, "boot", Path.GetFullPath(bootPath) },
            runner.Consumed[5].Arguments);
        Assert.DoesNotContain(runner.Consumed, command => ContainsWriteVerb(command.Arguments));
    }

    // ---------------------------------------------------------------- expectations

    private static (AndroidMaintenanceIdentity Identity, FirmwareSnapshot Firmware) CreateIdentity()
    {
        var firmware = new FirmwareSnapshot(
            DisplayId: FirmwareDisplayId,
            BuildFingerprint: FirmwareDisplayId,
            AndroidRelease: "1.5.10",
            SecurityPatch: null,
            AndroidReportedBootloaderState: BootloaderState.Unknown);
        var device = new DeviceIdentity(DeviceSerial, AndroidModel, BootloaderState.Unknown)
        {
            Firmware = firmware,
        };
        return (new AndroidMaintenanceIdentity(device, DeviceSocSerial), firmware);
    }

    private static List<ExpectedCommand> HappyPathExpectations(string bootPath, int bootExitCode) => new()
    {
        AdbReboot(),
        GetVar("serialno", DeviceSerial),
        GetVar("product", FastbootProduct),
        GetVar("unlocked", "yes"),
        GetVar(SnapshotQuery, "none"),
        Boot(bootPath, bootExitCode),
    };

    private static ExpectedCommand AdbReboot() =>
        new(
            AdbPath,
            new[] { "-s", DeviceSerial, "reboot", "bootloader" },
            new ProcessResult(0, string.Empty, string.Empty));

    // The production parser only accepts fastboot's keyed output, so the scripted stdout always
    // carries the "(bootloader) <name>: <value>" shape; only the value varies per case.
    private static ExpectedCommand GetVar(string name, string value) =>
        new(
            FastbootPath,
            new[] { "-s", DeviceSerial, "getvar", name },
            new ProcessResult(0, $"(bootloader) {name}: {value}", string.Empty));

    private static ExpectedCommand Boot(string bootPath, int exitCode) =>
        new(
            FastbootPath,
            new[] { "-s", DeviceSerial, "boot", Path.GetFullPath(bootPath) },
            new ProcessResult(exitCode, string.Empty, string.Empty));

    private static int IndexOfQuery(string name)
    {
        for (int index = 0; index < IdentityQueries.Length; index++)
        {
            if (string.Equals(IdentityQueries[index].Name, name, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool IsTemporaryBootCommand(ProcessCommand command) =>
        string.Equals(command.Executable, FastbootPath, StringComparison.Ordinal)
        && command.Arguments.Count == 4
        && string.Equals(command.Arguments[0], "-s", StringComparison.Ordinal)
        && string.Equals(command.Arguments[1], DeviceSerial, StringComparison.Ordinal)
        && string.Equals(command.Arguments[2], "boot", StringComparison.Ordinal);

    private static bool ContainsWriteVerb(IReadOnlyList<string> arguments)
    {
        foreach (string token in arguments)
        {
            if (string.Equals(token, "flash", StringComparison.Ordinal)
                || string.Equals(token, "erase", StringComparison.Ordinal)
                || string.Equals(token, "set_active", StringComparison.Ordinal)
                || string.Equals(token, "set-active", StringComparison.Ordinal)
                || string.Equals(token, "--set-active", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static void AssertPinnedAsset(string bootPath)
    {
        var file = new FileInfo(bootPath);
        Assert.True(file.Exists, $"Pinned maintenance asset not found: {bootPath}");
        Assert.Equal(PinnedMaintenanceAsset.BootImageLength, file.Length);

        string actualSha256;
        using (FileStream stream = File.OpenRead(bootPath))
        {
            actualSha256 = Convert.ToHexString(SHA256.HashData(stream));
        }

        Assert.Equal(PinnedMaintenanceAsset.BootImageSha256, actualSha256, ignoreCase: true);
    }

    // ---------------------------------------------------------------- scripted runner

    private sealed record ExpectedCommand(string Executable, IReadOnlyList<string> Arguments, ProcessResult Result);

    /// <summary>
    /// Replays pre-planned outcomes for an exact ordered command list. A divergence throws
    /// <see cref="XunitException"/> (never a production exception type), so a wrong command
    /// sequence fails the test instead of being mistaken for the expected rejection.
    /// </summary>
    private sealed class ScriptedCommandRunner : ICommandRunner
    {
        private readonly Queue<ExpectedCommand> _pending = new();
        private readonly List<ProcessCommand> _consumed = new();

        public ScriptedCommandRunner(IEnumerable<ExpectedCommand> expected)
        {
            foreach (ExpectedCommand command in expected)
            {
                _pending.Enqueue(command);
            }
        }

        public IReadOnlyList<ProcessCommand> Consumed => _consumed;

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int position = _consumed.Count + 1;
            if (_pending.Count == 0)
            {
                throw new XunitException(
                    $"Command #{position} was not expected: {command.Executable} {string.Join(' ', command.Arguments)}");
            }

            ExpectedCommand expected = _pending.Peek();
            bool argumentsMatch = expected.Arguments.Count == command.Arguments.Count
                && expected.Arguments.SequenceEqual(command.Arguments, StringComparer.Ordinal);
            if (!string.Equals(expected.Executable, command.Executable, StringComparison.Ordinal)
                || !argumentsMatch)
            {
                throw new XunitException(
                    $"Command #{position} does not match the boot contract." + Environment.NewLine +
                    $"  expected: {expected.Executable} {string.Join(' ', expected.Arguments)}" + Environment.NewLine +
                    $"  actual:   {command.Executable} {string.Join(' ', command.Arguments)}");
            }

            _pending.Dequeue();
            _consumed.Add(command);
            return Task.FromResult(expected.Result);
        }

        public void AssertFullyConsumed()
        {
            if (_pending.Count == 0)
            {
                return;
            }

            ExpectedCommand next = _pending.Peek();
            throw new XunitException(
                $"{_pending.Count} expected command(s) were never issued; next expected: {next.Executable} {string.Join(' ', next.Arguments)}");
        }
    }
}

/// <summary>
/// The pinned maintenance asset is looked up at discovery time; a missing environment variable or a
/// missing boot.img reports an explicit Skip on generic CI, while a present-but-wrong asset fails.
/// </summary>
internal static class PinnedMaintenanceAsset
{
    internal const string EnvironmentVariable = "MAINTENANCE_TEST_ASSET_ROOT";
    internal const string BootImageFileName = "boot.img";
    internal const long BootImageLength = 100663296L;
    internal const string BootImageSha256 = "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358";

    internal static string? SkipReason
    {
        get
        {
            string? root = Environment.GetEnvironmentVariable(EnvironmentVariable);
            if (string.IsNullOrWhiteSpace(root))
            {
                return $"SKIP: {EnvironmentVariable} is not set, so the real pinned TB322FC boot.img is unavailable. " +
                       "No synthetic asset is ever created: run this contract on the manager host that mounts the pinned asset.";
            }

            string path;
            try
            {
                path = Path.GetFullPath(Path.Combine(root, BootImageFileName));
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return $"SKIP: {EnvironmentVariable} ('{root}') is not a usable asset root: {exception.Message}";
            }

            if (!File.Exists(path))
            {
                return $"SKIP: pinned maintenance asset '{path}' does not exist (the real 96 MiB TB322FC boot.img is required).";
            }

            return null;
        }
    }

    internal static string ResolveBootImagePath()
    {
        string? reason = SkipReason;
        if (reason is not null)
        {
            throw new InvalidOperationException(reason);
        }

        return Path.GetFullPath(
            Path.Combine(Environment.GetEnvironmentVariable(EnvironmentVariable)!, BootImageFileName));
    }
}

/// <summary>Fact that skips (never fakes) when the pinned maintenance asset is unavailable.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class PinnedMaintenanceBootFactAttribute : FactAttribute
{
    public PinnedMaintenanceBootFactAttribute()
    {
        Skip = PinnedMaintenanceAsset.SkipReason;
    }
}

/// <summary>Theory that skips (never fakes) when the pinned maintenance asset is unavailable.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class PinnedMaintenanceBootTheoryAttribute : TheoryAttribute
{
    public PinnedMaintenanceBootTheoryAttribute()
    {
        Skip = PinnedMaintenanceAsset.SkipReason;
    }
}
