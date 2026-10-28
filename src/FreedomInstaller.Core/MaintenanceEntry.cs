using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>Device identity plus the SoC serial read over adb.</summary>
public sealed record AndroidMaintenanceIdentity(DeviceIdentity Identity, string SocSerial);

/// <summary>Outcome of a successful temporary bootloader entry.</summary>
public sealed record MaintenanceEntryResult(
    DeviceIdentity Identity,
    string AndroidSocSerial,
    string FastbootSerial,
    OtaUpdateState OtaState);

/// <summary>
/// Boundary that reads the Android SoC serial and boots a temporary boot image
/// without flashing, erasing or changing slots.
/// </summary>
public sealed class MaintenanceEntry
{
    private static readonly TimeSpan AdbReadTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RebootTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan FastbootPollTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan FastbootGetvarTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan FastbootBootTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan FastbootPollDelay = TimeSpan.FromMilliseconds(500);

    private const int FastbootPollAttempts = 30;

    private const string SocSerialPath = "/sys/devices/soc0/serial_number";
    private const string SnapshotUpdateStatusKey = "snapshot-update-status";
    private const string BootloaderPrefix = "(bootloader)";

    // Pinned G4.259 fastboot hardware product. The bootloader reports this hardware product,
    // which is deliberately distinct from the Android Model reported inside the running OS.
    private const string G4FastbootProduct = "elden_prc_wifi";

    private static readonly Regex TokenPattern = new("^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant);

    private readonly string _adbPath;
    private readonly string _fastbootPath;
    private readonly ICommandRunner _runner;

    public MaintenanceEntry(string adbPath, string fastbootPath, ICommandRunner runner)
    {
        if (string.IsNullOrWhiteSpace(adbPath))
        {
            throw new ArgumentException("adb path must not be empty.", nameof(adbPath));
        }

        if (string.IsNullOrWhiteSpace(fastbootPath))
        {
            throw new ArgumentException("fastboot path must not be empty.", nameof(fastbootPath));
        }

        _adbPath = adbPath;
        _fastbootPath = fastbootPath;
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
    }

    public async Task<AndroidMaintenanceIdentity> ReadAndroidAsync(
        DeviceIdentity identity,
        CancellationToken token = default)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        token.ThrowIfCancellationRequested();

        if (!IsSupportedAndroidModel(identity.Model))
        {
            throw new InvalidOperationException(
                $"Unsupported model '{identity.Model}': expected {MaintenanceProfiles.Model} or TB323FU.");
        }

        string serial = RequireNonEmpty(identity.Serial, "Android serial");

        var command = new ProcessCommand(
            _adbPath,
            new[] { "-s", serial, "shell", "cat", SocSerialPath },
            AdbReadTimeout);

        ProcessResult result = await _runner.RunAsync(command, token).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw Failure("adb cat SoC serial", result);
        }

        string socSerial = ParseSocSerial(result.StandardOutput);
        return new AndroidMaintenanceIdentity(identity, socSerial);
    }

    public async Task<MaintenanceEntryResult> BootTemporaryAsync(
        AndroidMaintenanceIdentity android,
        string bootPath,
        CancellationToken token = default)
    {
        if (android is null)
        {
            throw new ArgumentNullException(nameof(android));
        }

        token.ThrowIfCancellationRequested();

        DeviceIdentity identity = android.Identity
            ?? throw new ArgumentException("Android identity must not be null.", nameof(android));

        if (!string.Equals(identity.Model, MaintenanceProfiles.Model, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Temporary boot requires model {MaintenanceProfiles.Model}, got '{identity.Model}'.");
        }

        string? displayId = identity.Firmware?.DisplayId;
        if (!string.Equals(displayId, MaintenanceProfiles.AndroidBuild, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Build mismatch: expected display id '{MaintenanceProfiles.AndroidBuild}', got '{displayId ?? "<none>"}'.");
        }

        string serial = RequireNonEmpty(identity.Serial, "Android serial");
        string socSerial = ParseSocSerial(android.SocSerial);

        if (string.IsNullOrWhiteSpace(bootPath))
        {
            throw new ArgumentException("Boot image path must not be empty.", nameof(bootPath));
        }

        string fullBootPath = Path.GetFullPath(bootPath);

        // Keep the verified image open (read share only) from hash validation until
        // the fastboot boot command completes so it cannot be replaced in between.
        using FileStream bootImage = OpenVerifiedBootImage(fullBootPath);

        token.ThrowIfCancellationRequested();

        ProcessResult reboot = await _runner.RunAsync(
            new ProcessCommand(
                _adbPath,
                new[] { "-s", serial, "reboot", "bootloader" },
                RebootTimeout),
            token).ConfigureAwait(false);

        if (reboot.ExitCode != 0)
        {
            throw Failure("adb reboot bootloader", reboot);
        }

        string fastbootSerial = await PollFastbootSerialAsync(serial, token).ConfigureAwait(false);

        ProcessResult product = await RunGetvarAsync(fastbootSerial, "product", token).ConfigureAwait(false);
        string productValue = ReadRequiredVariable(product, "product");
        if (!string.Equals(productValue, G4FastbootProduct, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"fastboot product '{productValue}' does not match {G4FastbootProduct}.");
        }

        ProcessResult unlockedResult = await RunGetvarAsync(fastbootSerial, "unlocked", token).ConfigureAwait(false);
        string unlockedValue = ReadRequiredVariable(unlockedResult, "unlocked");
        if (!IsUnlockedValue(unlockedValue))
        {
            throw new InvalidOperationException(
                $"fastboot unlocked state '{unlockedValue}' is not a recognised unlocked value.");
        }

        ProcessResult snapshotResult = await RunGetvarAsync(fastbootSerial, SnapshotUpdateStatusKey, token).ConfigureAwait(false);
        string snapshotValue = ReadRequiredVariable(snapshotResult, SnapshotUpdateStatusKey);
        OtaUpdateState otaState = MapSnapshotState(snapshotValue);
        if (otaState != OtaUpdateState.Completed)
        {
            throw new InvalidOperationException(
                $"fastboot {SnapshotUpdateStatusKey} is '{snapshotValue}', expected 'none'.");
        }

        token.ThrowIfCancellationRequested();

        ProcessResult boot = await _runner.RunAsync(
            new ProcessCommand(
                _fastbootPath,
                new[] { "-s", fastbootSerial, "boot", fullBootPath },
                FastbootBootTimeout),
            token).ConfigureAwait(false);

        if (boot.ExitCode != 0)
        {
            throw Failure("fastboot boot", boot);
        }

        GC.KeepAlive(bootImage);

        DeviceIdentity resultIdentity = new(identity.Serial, identity.Model, BootloaderState.Unlocked)
        {
            Firmware = identity.Firmware,
        };

        return new MaintenanceEntryResult(resultIdentity, socSerial, fastbootSerial, otaState);
    }

    public static string ReadFastbootVariable(string output, string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("Variable name must not be empty.", nameof(key));
        }

        if (output is null)
        {
            throw new FormatException("fastboot output is missing.");
        }

        string? value = null;

        foreach (string rawLine in output.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith(BootloaderPrefix, StringComparison.OrdinalIgnoreCase))
            {
                line = line.Substring(BootloaderPrefix.Length).TrimStart();
            }

            int separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            string name = line.Substring(0, separator).Trim();
            if (!string.Equals(name, key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string candidate = line.Substring(separator + 1).Trim();
            if (candidate.Length == 0)
            {
                throw new FormatException($"fastboot variable '{key}' has an empty value.");
            }

            if (value is null)
            {
                value = candidate;
            }
            else if (!string.Equals(value, candidate, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"fastboot variable '{key}' has contradictory values '{value}' and '{candidate}'.");
            }
        }

        return value
            ?? throw new FormatException($"fastboot output does not contain variable '{key}'.");
    }

    public static OtaUpdateState ParseSnapshotUpdateState(string output)
    {
        string value;
        try
        {
            value = ReadFastbootVariable(output, SnapshotUpdateStatusKey);
        }
        catch (FormatException)
        {
            return OtaUpdateState.Unknown;
        }
        catch (ArgumentException)
        {
            return OtaUpdateState.Unknown;
        }

        return MapSnapshotState(value);
    }

    private async Task<string> PollFastbootSerialAsync(string expectedSerial, CancellationToken token)
    {
        for (int attempt = 1; attempt <= FastbootPollAttempts; attempt++)
        {
            token.ThrowIfCancellationRequested();

            ProcessResult? result = null;
            try
            {
                result = await _runner.RunAsync(
                    new ProcessCommand(
                        _fastbootPath,
                        new[] { "-s", expectedSerial, "getvar", "serialno" },
                        FastbootPollTimeout),
                    token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                // Command-level timeout: retry the query while attempts remain.
            }
            catch (TimeoutException)
            {
                // Command-level timeout: retry the query while attempts remain.
            }

            if (result is not null && result.ExitCode == 0)
            {
                string reported = ReadRequiredVariable(result, "serialno");
                if (!string.Equals(reported, expectedSerial, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"fastboot serialno '{reported}' does not match Android serial '{expectedSerial}'.");
                }

                return reported;
            }

            if (attempt < FastbootPollAttempts)
            {
                await Task.Delay(FastbootPollDelay, token).ConfigureAwait(false);
            }
        }

        throw new TimeoutException(
            $"fastboot did not report a matching serialno within {FastbootPollAttempts} attempts.");
    }

    private async Task<ProcessResult> RunGetvarAsync(string serial, string variable, CancellationToken token)
    {
        ProcessResult result = await _runner.RunAsync(
            new ProcessCommand(
                _fastbootPath,
                new[] { "-s", serial, "getvar", variable },
                FastbootGetvarTimeout),
            token).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw Failure($"fastboot getvar {variable}", result);
        }

        return result;
    }

    private static FileStream OpenVerifiedBootImage(string fullBootPath)
    {
        FileStream? stream = null;
        try
        {
            stream = new FileStream(fullBootPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            if (stream.Length != MaintenanceProfiles.BootBytes)
            {
                throw new InvalidOperationException(
                    $"Boot image '{fullBootPath}' has length {stream.Length}, expected {MaintenanceProfiles.BootBytes}.");
            }

            string sha256;
            using (SHA256 sha = SHA256.Create())
            {
                sha256 = Convert.ToHexString(sha.ComputeHash(stream));
            }

            if (!string.Equals(sha256, MaintenanceProfiles.BootSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Boot image '{fullBootPath}' SHA-256 mismatch: expected {MaintenanceProfiles.BootSha256}, got {sha256}.");
            }

            stream.Position = 0;
            return stream;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            stream?.Dispose();
            throw new InvalidOperationException(
                $"Boot image '{fullBootPath}' cannot be opened for verification: {exception.Message}",
                exception);
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    private static string ParseSocSerial(string value)
    {
        string trimmed = (value ?? string.Empty).Trim();
        if (!TokenPattern.IsMatch(trimmed))
        {
            throw new InvalidOperationException(
                $"SoC serial '{Summarize(value)}' is not a single ASCII alphanumeric/hyphen token of 1..64 characters.");
        }

        return trimmed;
    }

    private static string RequireNonEmpty(string? value, string what)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{what} must not be empty.");
        }

        return value.Trim();
    }

    private static bool IsSupportedAndroidModel(string? model)
        => string.Equals(model, MaintenanceProfiles.Model, StringComparison.OrdinalIgnoreCase)
            || string.Equals(model, "TB323FU", StringComparison.OrdinalIgnoreCase);

    private static bool IsUnlockedValue(string value)
        => string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "1", StringComparison.Ordinal);

    private static OtaUpdateState MapSnapshotState(string value)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "none":
                return OtaUpdateState.Completed;
            case "merging":
                return OtaUpdateState.Merging;
            case "pending":
            case "pending-reboot":
                return OtaUpdateState.PendingReboot;
            case "unconfirmed":
            case "unconfirmed-boot":
                return OtaUpdateState.UnconfirmedBoot;
            case "snapshot":
            case "updating":
                return OtaUpdateState.Updating;
            default:
                return OtaUpdateState.Unknown;
        }
    }

    private static string ReadRequiredVariable(ProcessResult result, string key)
    {
        try
        {
            return ReadFastbootVariable(Combine(result), key);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"fastboot {key} output is unusable: {exception.Message} " +
                $"stdout: {Summarize(result.StandardOutput)} stderr: {Summarize(result.StandardError)}",
                exception);
        }
    }

    private static string Combine(ProcessResult result)
        => result.StandardOutput + "\n" + result.StandardError;

    private static InvalidOperationException Failure(string operation, ProcessResult result)
        => new InvalidOperationException(
            $"{operation} failed with exit code {result.ExitCode}. " +
            $"stdout: {Summarize(result.StandardOutput)} stderr: {Summarize(result.StandardError)}");

    private static string Summarize(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return "<empty>";
        }

        string trimmed = text.Trim();
        return trimmed.Length <= 512 ? trimmed : trimmed.Substring(0, 512) + "...";
    }
}
