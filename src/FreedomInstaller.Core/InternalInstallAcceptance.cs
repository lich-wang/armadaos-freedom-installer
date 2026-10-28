using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Outcome of the Android-only post-install acceptance check. Only <see cref="Verified"/> states that the
/// expected Android device, its build identity, its SoC serial and its restored userdata capacity were
/// actually read and matched; every other value is a waiting or rejected outcome.
/// </summary>
public enum InternalAndroidAcceptanceState
{
    /// <summary>Every Android-side condition was observed and matched.</summary>
    Verified,

    /// <summary>The expected device is not yet visible in a usable adb state.</summary>
    AwaitingAndroidInitialization,

    /// <summary>The expected device is visible but has not authorized the USB debugging key yet.</summary>
    AwaitingUsbAuthorization,

    /// <summary>At least one observed Android fact contradicted the expected device or the restored plan.</summary>
    Rejected,
}

/// <summary>
/// Immutable Android-only acceptance result. It never means that the overall install is complete: the
/// backend still owns the separate Linux first-boot gate, and no Linux acceptance, SSH credential or
/// service probe exists here.
/// <para>
/// Every value is a fact that was actually observed. <see cref="UserdataPartitionBytes"/> is null
/// whenever no actual partition value was read. A filesystem-only <see cref="Verified"/> result is
/// stricter: it requires explicit permission denial plus node evidence, so the expected baseline is
/// never copied into an observed slot.
/// </para>
/// </summary>
public sealed class InternalAndroidAcceptanceResult
{
    internal InternalAndroidAcceptanceResult(
        InternalAndroidAcceptanceState state,
        string diagnostic,
        AndroidMaintenanceIdentity? observedIdentity,
        long? userdataPartitionBytes,
        long? dataFilesystemBytes,
        bool filesystemOnlyEvidence)
    {
        State = state;
        Diagnostic = diagnostic;
        ObservedIdentity = observedIdentity;
        UserdataPartitionBytes = userdataPartitionBytes;
        DataFilesystemBytes = dataFilesystemBytes;
        FilesystemOnlyEvidence = filesystemOnlyEvidence;
    }

    /// <summary>The classified Android acceptance state.</summary>
    public InternalAndroidAcceptanceState State { get; }

    /// <summary>Human-readable explanation of the state; never a positive result by itself.</summary>
    public string Diagnostic { get; }

    /// <summary>
    /// The Android identity actually read from the expected device, or null when no identity was
    /// observed. Its <see cref="DeviceIdentity.BootloaderState"/> stays
    /// <see cref="BootloaderState.Unknown"/> because Android cannot prove a fresh fastboot lock state.
    /// </summary>
    public AndroidMaintenanceIdentity? ObservedIdentity { get; }

    /// <summary>The actual userdata partition size in bytes, or null when no actual value was read.</summary>
    public long? UserdataPartitionBytes { get; }

    /// <summary>The actual mounted <c>/data</c> filesystem size in bytes, or null when it was not read.</summary>
    public long? DataFilesystemBytes { get; }

    /// <summary>True only when the partition size was explicitly denied and the mounted filesystem was used.</summary>
    public bool FilesystemOnlyEvidence { get; }

    /// <summary>True only for <see cref="InternalAndroidAcceptanceState.Verified"/>.</summary>
    public bool Verified => State == InternalAndroidAcceptanceState.Verified;
}

/// <summary>
/// Android post-install acceptance contract. The class reads the expected device, its build identity, its
/// SoC serial and the restored userdata capacity, and reports an Android-only result.
/// <para>
/// This type never accepts a caller-supplied success flag, never takes a <c>bootCompleted</c> input and
/// never treats the RAM bootstrap, a deploy job, a receipt or MTP presence as Linux first-boot proof.
/// There is no verified normal Linux probe here, so the backend keeps its own awaiting-Linux-first-boot
/// state even when this result is <see cref="InternalAndroidAcceptanceState.Verified"/>.
/// </para>
/// </summary>
public sealed class InternalInstallAcceptance
{
    /// <summary>Absolute path of the SoC serial node; one fixed argv entry, never spliced from input.</summary>
    private const string SocSerialPath = "/sys/devices/soc0/serial_number";

    /// <summary>The fixed, finite timeout every read-only query of this check carries.</summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(15);

    private readonly string _adbPath;
    private readonly ICommandRunner _runner;
    private readonly IAndroidUninstallAcceptanceProbe _capacityProbe;

    /// <summary>
    /// Creates the acceptance check. The adb path and the process boundary are required; the capacity
    /// probe defaults to the existing read-only adb probe. Construction performs no I/O.
    /// </summary>
    public InternalInstallAcceptance(
        string adbPath,
        ICommandRunner runner,
        IAndroidUninstallAcceptanceProbe? capacityProbe = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adbPath);
        ArgumentNullException.ThrowIfNull(runner);

        _adbPath = adbPath;
        _runner = runner;
        _capacityProbe = capacityProbe ?? new AdbAndroidUninstallAcceptanceProbe(_runner, _adbPath);
    }

    /// <summary>
    /// Reads and validates the expected Android device against the restored userdata plan and returns an
    /// Android-only result.
    /// <para>
    /// This overload is the legacy four-argument route. The expected context is validated before the
    /// first query: the Step 1 result must be a verified success with an Android identity, an exact
    /// <c>a</c>/<c>b</c> current slot, the supported
    /// <see cref="MaintenanceProfiles.Model"/> / <see cref="MaintenanceProfiles.AndroidBuild"/> profile,
    /// a complete expected build fingerprint, a canonical positive 32-bit SoC serial and a serial of 1..64
    /// ASCII alphanumerics or hyphens. Unsupported or malformed expectations are an
    /// <see cref="ArgumentException"/>, never a fabricated pending result.
    /// </para>
    /// <para>
    /// Every query is one read-only <see cref="ProcessCommand"/> with a separate argument vector and the
    /// fixed 15 second timeout, and every non-zero exit is an <see cref="IOException"/> carrying the actual
    /// diagnostic. A missing or offline row waits for initialization, an unauthorized row waits for USB
    /// authorization without any shell query, and a duplicated serial is rejected. An empty (or
    /// whitespace-only) boot flag reports <c>0</c> semantics and waits, while a non-empty flag other than
    /// <c>0</c>/<c>1</c> or a missing build value is <see cref="InvalidDataException"/>. Actual drift in the
    /// model, build, SoC serial, partition size, filesystem capacity or boot slot is
    /// <see cref="InternalAndroidAcceptanceState.Rejected"/> with the observed values, never a positive
    /// result.
    /// </para>
    /// </summary>
    public Task<InternalAndroidAcceptanceResult> CheckAndroidAsync(
        InternalDeviceCheckResult expectedDevice,
        int userdataPartitionNumber,
        long expectedAndroidBytes,
        CancellationToken ct = default)
    {
        // The legacy route deliberately carries no trusted profile and keeps its MaintenanceProfiles gates.
        return CheckAndroidCoreAsync(
            expectedDevice, userdataPartitionNumber, expectedAndroidBytes, null, ct);
    }

    /// <summary>
    /// Reads and validates the expected Android device against the restored userdata plan using the supplied
    /// trusted <paramref name="profile"/>, and returns an Android-only result.
    /// <para>
    /// A null profile is an <see cref="ArgumentNullException"/>. An incomplete profile fails
    /// <see cref="EdlDeviceProfile.RequireComplete"/> with an <see cref="InvalidOperationException"/>, and an
    /// expected identity the profile does not support is an <see cref="ArgumentException"/>; both happen
    /// before the first adb query, so neither can ever look pending or verified and no query runs. The rest
    /// of the contract is exactly the read-only one of the legacy overload, and no expected value is ever
    /// copied into an observed slot.
    /// </para>
    /// </summary>
    public Task<InternalAndroidAcceptanceResult> CheckAndroidAsync(
        InternalDeviceCheckResult expectedDevice,
        int userdataPartitionNumber,
        long expectedAndroidBytes,
        EdlDeviceProfile profile,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        return CheckAndroidCoreAsync(
            expectedDevice, userdataPartitionNumber, expectedAndroidBytes, profile, ct);
    }

    /// <summary>
    /// The one shared observed-read body. A null <paramref name="profile"/> is the legacy route; a non-null
    /// profile is the trusted Direct route. Nothing else differs, so the observed-read collection is never
    /// duplicated.
    /// </summary>
    private async Task<InternalAndroidAcceptanceResult> CheckAndroidCoreAsync(
        InternalDeviceCheckResult expectedDevice,
        int userdataPartitionNumber,
        long expectedAndroidBytes,
        EdlDeviceProfile? profile,
        CancellationToken ct)
    {
        var expected = ValidateExpected(expectedDevice, userdataPartitionNumber, expectedAndroidBytes, profile);
        ct.ThrowIfCancellationRequested();

        var serial = expected.Serial;

        // The one device listing decides whether any later query may run at all.
        var listing = await QueryAsync(ct, "devices", "-l").ConfigureAwait(false);
        var rows = DeviceProbe.ParseAdbDevices(listing.StandardOutput);

        ConnectedDevice? selected = null;
        var matches = 0;
        foreach (var row in rows)
        {
            if (string.Equals(row.Serial, serial, StringComparison.Ordinal))
            {
                matches++;
                selected = row;
            }
        }

        if (matches > 1)
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"adb reports the expected serial '{serial}' {matches} times, so the device cannot be "
                + "identified uniquely; no shell query was attempted.");
        }

        if (selected is null)
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingAndroidInitialization,
                $"adb does not list the expected serial '{serial}' yet; no shell query was attempted.");
        }

        if (selected.ConnectionState == ConnectionState.Unauthorized)
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingUsbAuthorization,
                $"Device '{serial}' is listed as unauthorized; the USB debugging prompt has not been "
                + "accepted, so no shell query was attempted.");
        }

        if (selected.ConnectionState != ConnectionState.Authorized)
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingAndroidInitialization,
                $"Device '{serial}' is listed as {selected.ConnectionState} instead of authorized; "
                + "Android is not ready, so no shell query was attempted.");
        }

        // Boot gate before any size query: only an exact 1 continues.
        var bootText = (await QueryAsync(ct, "-s", serial, "shell", "getprop", "sys.boot_completed")
                .ConfigureAwait(false))
            .StandardOutput.Trim();

        if (bootText.Length == 0)
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingAndroidInitialization,
                $"Device '{serial}' reported no sys.boot_completed value; Android has not finished "
                + "booting, so no size query was attempted.");
        }

        if (string.Equals(bootText, "0", StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingAndroidInitialization,
                $"Android on '{serial}' reports sys.boot_completed as 0; the system has not finished "
                + "booting, so no size query was attempted.");
        }

        if (!string.Equals(bootText, "1", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Device '{serial}' reported sys.boot_completed '{bootText}', which is neither 0 nor 1.");
        }

        // The full dump is parsed by the pure parsers only; nothing expected is merged into it.
        var dump = (await QueryAsync(ct, "-s", serial, "shell", "getprop").ConfigureAwait(false))
            .StandardOutput;

        var actualModel = DeviceProbe.IdentifyModel(dump);
        if (actualModel is null)
        {
            throw new InvalidDataException(
                $"The full getprop dump of '{serial}' does not name exactly one supported model.");
        }

        var actualFirmware = FirmwareProbe.Parse(dump);
        if (string.IsNullOrWhiteSpace(actualFirmware.DisplayId)
            || string.IsNullOrWhiteSpace(actualFirmware.BuildFingerprint)
            || string.IsNullOrWhiteSpace(actualFirmware.AndroidRelease)
            || string.IsNullOrWhiteSpace(actualFirmware.SecurityPatch))
        {
            throw new InvalidDataException(
                $"Device '{serial}' did not report a complete build identity "
                + "(display id, build fingerprint, Android release and security patch).");
        }

        if (!string.Equals(actualModel, expected.Model, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The device reports model '{actualModel}' instead of '{expected.Model}'.");
        }

        var firmwareProblem = CompareFirmware(actualFirmware, expected.Firmware);
        if (firmwareProblem is not null)
        {
            return Outcome(InternalAndroidAcceptanceState.Rejected, firmwareProblem);
        }

        // The SoC node is a fixed argv entry; only a canonical positive 32-bit decimal is a value.
        var socText = (await QueryAsync(ct, "-s", serial, "shell", "cat", SocSerialPath)
                .ConfigureAwait(false))
            .StandardOutput.Trim();

        if (!TryParseCanonicalSocSerial(socText, out _))
        {
            throw new InvalidDataException(
                $"Device '{serial}' reported SoC serial '{socText}', which is not a positive canonical "
                + "unsigned 32-bit decimal value.");
        }

        if (!string.Equals(socText, expected.SocSerial, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The device reports SoC serial '{socText}' instead of '{expected.SocSerial}'.");
        }

        // One read through the existing probe: partition number, readlink node and df are all its own
        // checked queries. Its errors are deliberately not caught, so a device or parse failure reaches
        // the caller as a failed backend step instead of a pending state.
        var observation = await _capacityProbe
            .ReadAsync(serial, AdbAndroidUninstallAcceptanceProbe.ExpectedDiskDeviceId, userdataPartitionNumber, ct)
            .ConfigureAwait(false);

        if (observation is null)
        {
            throw new InvalidDataException(
                $"The read-only probe returned no observation for device '{serial}'.");
        }

        var expectedNode = "/dev/block/sda"
            + userdataPartitionNumber.ToString(CultureInfo.InvariantCulture);
        if (!string.Equals(observation.UserdataDeviceNode, expectedNode, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The actual userdata readlink target is '{observation.UserdataDeviceNode ?? "<none>"}' "
                + $"instead of '{expectedNode}'; the partition binding is not proven.");
        }

        var observedPartitionBytes = observation.UserdataPartitionBytes;
        if (observedPartitionBytes < 0)
        {
            throw new InvalidDataException(
                $"The probe reported a negative userdata partition size {observedPartitionBytes} bytes.");
        }

        if (observation.PartitionSizePermissionDenied && observedPartitionBytes != 0)
        {
            throw new InvalidDataException(
                "The probe reported an explicit partition-size permission denial together with a readable "
                + $"size of {observedPartitionBytes} bytes, which is contradictory.");
        }

        var filesystemOnly = observation.PartitionSizePermissionDenied;
        if (!filesystemOnly && observedPartitionBytes == 0)
        {
            throw new InvalidDataException(
                "The probe reported no readable userdata partition size without an explicit permission "
                + "denial, so no actual value exists.");
        }

        // Built only from facts actually read: the probe's model and serial, the dump's firmware and the
        // SoC node. Expected values are never copied into an observed slot.
        var observedIdentity = new AndroidMaintenanceIdentity(
            new DeviceIdentity(observation.Serial, observation.Model, BootloaderState.Unknown)
            {
                Firmware = actualFirmware,
            },
            socText);

        var observedPartition = observedPartitionBytes > 0 ? observedPartitionBytes : (long?)null;

        if (!string.Equals(observation.Model, expected.Model, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The probe reports model '{observation.Model}' instead of '{expected.Model}'.",
                observedIdentity,
                observedPartition,
                observation.DataFilesystemBytes);
        }

        if (!string.Equals(observation.Model, actualModel, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The probe reports model '{observation.Model}' while the full getprop dump reports "
                + $"'{actualModel}', so the observations disagree.",
                observedIdentity,
                observedPartition,
                observation.DataFilesystemBytes);
        }

        if (!string.Equals(observation.Serial, serial, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The probe reports serial '{observation.Serial}' instead of '{serial}'.",
                observedIdentity,
                observedPartition,
                observation.DataFilesystemBytes);
        }

        if (!observation.BootCompleted)
        {
            return Outcome(
                InternalAndroidAcceptanceState.AwaitingAndroidInitialization,
                $"The read-only probe did not observe sys.boot_completed as 1 on '{serial}'; Android is "
                + "not fully booted, so acceptance is not verified.",
                observedIdentity,
                observedPartition,
                observation.DataFilesystemBytes);
        }

        // Only an explicit permission denial may use the expected plan as a comparison baseline, and it
        // never turns that baseline into an observed partition value.
        long comparisonBytes;
        if (filesystemOnly)
        {
            comparisonBytes = expectedAndroidBytes;
        }
        else
        {
            if (observedPartitionBytes != expectedAndroidBytes)
            {
                return Outcome(
                    InternalAndroidAcceptanceState.Rejected,
                    $"The userdata partition is {observedPartitionBytes} bytes instead of the expected "
                    + $"{expectedAndroidBytes} bytes.",
                    observedIdentity,
                    observedPartition,
                    observation.DataFilesystemBytes);
            }

            comparisonBytes = observedPartitionBytes;
        }

        var filesystemBytes = observation.DataFilesystemBytes;
        if (filesystemBytes is null)
        {
            throw new InvalidDataException(
                $"Device '{serial}' did not report the mounted /data filesystem capacity.");
        }

        var actualFilesystemBytes = filesystemBytes.Value;
        if (actualFilesystemBytes <= 0)
        {
            throw new InvalidDataException(
                $"The mounted /data filesystem reports {actualFilesystemBytes} bytes, which is not positive.");
        }

        if (actualFilesystemBytes > comparisonBytes)
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The /data filesystem reports {actualFilesystemBytes} bytes, more than the "
                + $"{comparisonBytes} byte comparison baseline.",
                observedIdentity,
                observedPartition,
                actualFilesystemBytes);
        }

        // Decimal division keeps the 95 percent policy exact without an overflow-prone multiplication.
        var ratio = (decimal)actualFilesystemBytes / comparisonBytes;
        if (ratio < 0.95m)
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The /data filesystem reports {actualFilesystemBytes} bytes, only "
                + $"{ratio.ToString("P1", CultureInfo.InvariantCulture)} of the {comparisonBytes} byte "
                + "comparison baseline.",
                observedIdentity,
                observedPartition,
                actualFilesystemBytes);
        }

        // The fresh Android suffix is compared with the prior checked fastboot slot. No fastboot query,
        // reboot or set-active command exists here.
        var slotSuffix = (await QueryAsync(ct, "-s", serial, "shell", "getprop", "ro.boot.slot_suffix")
                .ConfigureAwait(false))
            .StandardOutput.Trim();
        var expectedSuffix = "_" + expected.CurrentSlot;

        if (!string.Equals(slotSuffix, expectedSuffix, StringComparison.Ordinal))
        {
            return Outcome(
                InternalAndroidAcceptanceState.Rejected,
                $"The device reports ro.boot.slot_suffix '{slotSuffix}' instead of '{expectedSuffix}'.",
                observedIdentity,
                observedPartition,
                actualFilesystemBytes);
        }

        ct.ThrowIfCancellationRequested();

        return new InternalAndroidAcceptanceResult(
            InternalAndroidAcceptanceState.Verified,
            filesystemOnly
                ? $"Android verified on '{serial}': model '{observation.Model}', SoC serial {socText}, "
                    + $"build '{actualFirmware.DisplayId}', boot completed, the userdata size node was "
                    + "explicitly permission denied with its node proven, and the mounted /data reports "
                    + $"{actualFilesystemBytes} bytes, at least 95% of the {expectedAndroidBytes} byte "
                    + "expected baseline. The partition size itself was not read."
                : $"Android verified on '{serial}': model '{observation.Model}', SoC serial {socText}, "
                    + $"build '{actualFirmware.DisplayId}', boot completed, a {observedPartitionBytes} byte "
                    + $"userdata partition and a {actualFilesystemBytes} byte /data filesystem.",
            observedIdentity,
            filesystemOnly ? null : observedPartitionBytes,
            actualFilesystemBytes,
            filesystemOnly);
    }

    /// <summary>
    /// Validates the expected context before the first query. Every unsupported or malformed expectation
    /// is an <see cref="ArgumentException"/>, and an incomplete trusted profile is an
    /// <see cref="InvalidOperationException"/> from <see cref="EdlDeviceProfile.RequireComplete"/>, so no
    /// rejection can look like a pending device.
    /// </summary>
    private static ExpectedAndroidContext ValidateExpected(
        InternalDeviceCheckResult expectedDevice,
        int userdataPartitionNumber,
        long expectedAndroidBytes,
        EdlDeviceProfile? profile)
    {
        ArgumentNullException.ThrowIfNull(expectedDevice);

        if (!expectedDevice.Succeeded)
        {
            throw new ArgumentException(
                "The Step 1 device check result is not a fully verified success, so no Android "
                + "acceptance can be expected.",
                nameof(expectedDevice));
        }

        var android = expectedDevice.Android
            ?? throw new ArgumentException(
                "The Step 1 device check result carries no Android identity.",
                nameof(expectedDevice));

        var identity = android.Identity
            ?? throw new ArgumentException(
                "The Step 1 device check result carries no device identity.",
                nameof(expectedDevice));

        if (expectedDevice.CurrentSlot is not ("a" or "b"))
        {
            throw new ArgumentException(
                "The Step 1 current slot must be exactly 'a' or 'b'.",
                nameof(expectedDevice));
        }

        if (profile is null
            && !string.Equals(identity.Model, MaintenanceProfiles.Model, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The expected model must be '{MaintenanceProfiles.Model}', but it is '{identity.Model}'.",
                nameof(expectedDevice));
        }

        var firmware = identity.Firmware;
        if (firmware is null
            || string.IsNullOrWhiteSpace(firmware.DisplayId)
            || string.IsNullOrWhiteSpace(firmware.BuildFingerprint))
        {
            throw new ArgumentException(
                "The expected identity must carry a full display id and build fingerprint.",
                nameof(expectedDevice));
        }

        if (profile is null)
        {
            if (!string.Equals(firmware.DisplayId, MaintenanceProfiles.AndroidBuild, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"The expected display id must be '{MaintenanceProfiles.AndroidBuild}', but it is "
                    + $"'{firmware.DisplayId}'.",
                    nameof(expectedDevice));
            }
        }
        else
        {
            // The trusted profile replaces both legacy MaintenanceProfiles gates: it must be complete and
            // must accept this actual expected identity before any adb query runs.
            profile.RequireComplete();

            if (!profile.SupportsIdentity(identity))
            {
                throw new ArgumentException(
                    $"The expected identity (model '{identity.Model}', display id '{firmware.DisplayId}') is "
                    + $"not supported by the trusted profile '{profile.ProfileId}'.",
                    nameof(expectedDevice));
            }
        }

        if (!IsSerialToken(identity.Serial))
        {
            throw new ArgumentException(
                "The expected serial must be 1..64 ASCII letters, digits or hyphens.",
                nameof(expectedDevice));
        }

        if (!TryParseCanonicalSocSerial(android.SocSerial, out _))
        {
            throw new ArgumentException(
                "The expected SoC serial must be a positive canonical unsigned 32-bit decimal value.",
                nameof(expectedDevice));
        }

        if (userdataPartitionNumber < 1
            || userdataPartitionNumber > AdbAndroidUninstallAcceptanceProbe.MaximumUserdataPartitionNumber)
        {
            throw new ArgumentOutOfRangeException(
                nameof(userdataPartitionNumber),
                userdataPartitionNumber,
                $"The userdata partition number must be between 1 and "
                + $"{AdbAndroidUninstallAcceptanceProbe.MaximumUserdataPartitionNumber}.");
        }

        if (expectedAndroidBytes <= 0
            || expectedAndroidBytes % AdbAndroidUninstallAcceptanceProbe.SysfsUnitBytes != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedAndroidBytes),
                expectedAndroidBytes,
                "The expected Android size must be a positive multiple of 512 bytes.");
        }

        return new ExpectedAndroidContext(identity.Serial, identity.Model, firmware, android.SocSerial, expectedDevice.CurrentSlot!);
    }

    /// <summary>
    /// Compares the actual build snapshot with the expected one and returns a rejection diagnostic, or
    /// null when every expected field agrees. Display id and fingerprint are always compared; the release
    /// and the security patch are compared when the expected identity carries them.
    /// </summary>
    private static string? CompareFirmware(FirmwareSnapshot actual, FirmwareSnapshot expected)
    {
        if (!string.Equals(actual.DisplayId, expected.DisplayId, StringComparison.Ordinal))
        {
            return $"The device reports display id '{actual.DisplayId}' instead of '{expected.DisplayId}'.";
        }

        if (!string.Equals(actual.BuildFingerprint, expected.BuildFingerprint, StringComparison.Ordinal))
        {
            return $"The device reports build fingerprint '{actual.BuildFingerprint}' instead of "
                + $"'{expected.BuildFingerprint}'.";
        }

        if (expected.AndroidRelease is not null
            && !string.Equals(actual.AndroidRelease, expected.AndroidRelease, StringComparison.Ordinal))
        {
            return $"The device reports Android release '{actual.AndroidRelease}' instead of "
                + $"'{expected.AndroidRelease}'.";
        }

        if (expected.SecurityPatch is not null
            && !string.Equals(actual.SecurityPatch, expected.SecurityPatch, StringComparison.Ordinal))
        {
            return $"The device reports security patch '{actual.SecurityPatch}' instead of "
                + $"'{expected.SecurityPatch}'.";
        }

        return null;
    }

    /// <summary>True only for 1..64 ASCII letters, digits or hyphens; no whitespace or control character.</summary>
    private static bool IsSerialToken(string? value)
    {
        if (value is null || value.Length < 1 || value.Length > 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            var accepted = character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-';

            if (!accepted)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// True only for a canonical positive unsigned 32-bit decimal: ASCII digits only, no sign, no leading
    /// zero, no whitespace and within <see cref="uint.MaxValue"/>.
    /// </summary>
    private static bool TryParseCanonicalSocSerial(string? value, out uint serial)
    {
        serial = 0;

        if (string.IsNullOrEmpty(value) || value.Length > 10)
        {
            return false;
        }

        if (value.Length > 1 && value[0] == '0')
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

        return uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out serial)
            && serial > 0;
    }

    /// <summary>
    /// Runs one fixed, read-only argv query with the 15 second timeout and forwards
    /// <paramref name="token"/>. A non-zero exit is an <see cref="IOException"/> that carries the actual
    /// diagnostic; success returns the full result so the caller can read its output.
    /// </summary>
    private async Task<ProcessResult> QueryAsync(CancellationToken token, params string[] arguments)
    {
        var result = await _runner
            .RunAsync(new ProcessCommand(_adbPath, arguments, QueryTimeout), token)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new IOException(
                $"'{_adbPath} {string.Join(' ', arguments)}' exited with code {result.ExitCode}: "
                + Diagnostic(result));
        }

        return result;
    }

    /// <summary>The actual error text of a result, or its output when no error text was printed.</summary>
    private static string Diagnostic(ProcessResult result)
    {
        var error = result.StandardError.Trim();
        if (error.Length > 0)
        {
            return error;
        }

        var output = result.StandardOutput.Trim();
        return output.Length > 0 ? output : "<empty>";
    }

    /// <summary>
    /// A waiting or rejected result. The state is never <see cref="InternalAndroidAcceptanceState.Verified"/>,
    /// so no helper call can produce a positive outcome.
    /// </summary>
    private static InternalAndroidAcceptanceResult Outcome(
        InternalAndroidAcceptanceState state,
        string diagnostic,
        AndroidMaintenanceIdentity? observedIdentity = null,
        long? userdataPartitionBytes = null,
        long? dataFilesystemBytes = null)
    {
        return new InternalAndroidAcceptanceResult(
            state,
            diagnostic,
            observedIdentity,
            userdataPartitionBytes,
            dataFilesystemBytes,
            false);
    }

    /// <summary>The validated expected context; every value comes from the verified Step 1 result.</summary>
    private sealed record ExpectedAndroidContext(
        string Serial,
        string Model,
        FirmwareSnapshot Firmware,
        string SocSerial,
        string CurrentSlot);
}
