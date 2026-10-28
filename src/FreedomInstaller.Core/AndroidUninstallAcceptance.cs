using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One read-only observation of a device that has already rebooted into Android after the uninstall.
/// <para>
/// Every field is a value an external query actually printed on this device: the model and the serial come
/// from getprop, the boot flag from getprop and the size from the sysfs sector count of the userdata block
/// device. Nothing here may be derived from a user interface switch, from the fact that a previous step
/// reported success, or from the package that was installed, because none of those is evidence that Android
/// came up and accepted the new partition layout.
/// </para>
/// </summary>
/// <param name="Model">Trimmed value of <c>getprop ro.product.model</c>, exactly as the device printed it.</param>
/// <param name="Serial">
/// Trimmed value of <c>getprop ro.serialno</c>, or of <c>getprop ro.boot.serialno</c> when the first one is
/// empty. An implementation never falls back to any other source for a serial.
/// </param>
/// <param name="BootCompleted">
/// <c>getprop sys.boot_completed</c> was exactly <c>1</c> after trimming. Any other value - including an
/// empty value, <c>0</c>, <c>true</c> or <c>2</c> - is <c>false</c>, so a partially booted system cannot
/// look finished.
/// </param>
/// <param name="UserdataPartitionBytes">
/// Size of the userdata block device in bytes: the unsigned decimal value of
/// <c>/sys/class/block/sda&lt;N&gt;/size</c> multiplied by 512. sysfs always counts 512-byte units,
/// independent of the 4096-byte sectors the GPT of this tablet uses, so the unit is never taken from the
/// partition table.
/// <para>
/// Zero is an unknown sentinel and never a measurement: it is used only when the size node refused the
/// read with an explicit permission denial, that is, when <see cref="PartitionSizePermissionDenied"/> is
/// true. It does not assert that the hardware reported a zero-sized partition; it says the size was not
/// readable at all, so no byte value is known. Every readable size is reported as read.
/// </para>
/// </param>
public sealed record AndroidUninstallObservation(
    string Model,
    string Serial,
    bool BootCompleted,
    long UserdataPartitionBytes)
{
    /// <summary>
    /// Mounted data filesystem capacity in bytes, read from the exact <c>df -k /data</c> row, or null when
    /// that row was not readable. It is evidence of capacity, not of an OEM format or of erased files; a
    /// value that is too small or unknown is pending capacity evidence, never a restore failure by itself.
    /// </summary>
    public long? DataFilesystemBytes { get; init; }

    /// <summary>
    /// True only when the sysfs size node refused the read with an explicit permission denial and the
    /// device proved, through the exact <c>readlink -f /dev/block/by-name/userdata</c> target, that the
    /// denied node belongs to userdata. The flag never stands in for a size: when it is true,
    /// <see cref="UserdataPartitionBytes"/> is the unknown zero sentinel, not a measured size and not a
    /// claim that the hardware reported zero, and every other read failure leaves the flag false.
    /// </summary>
    public bool PartitionSizePermissionDenied { get; init; }

    /// <summary>
    /// The exact target the device printed for <c>readlink -f /dev/block/by-name/userdata</c>, trimmed, or
    /// null when no such target was read. It is the actual readlink observation, never derived from the
    /// restore plan or from the partition number. The real adb probe collects it on both the readable and
    /// the permission-denied size branch; EDL acceptance specifically refuses a null or different node even
    /// when the byte sizes happen to look correct, while the legacy RAM path keeps accepting observations
    /// that predate this property.
    /// </summary>
    public string? UserdataDeviceNode { get; init; }
}

/// <summary>
/// Outcome of the acceptance check. <see cref="Accepted"/> is true only when a live read proved every
/// condition at once; there is no "assume accepted" path and no default that could be mistaken for one.
/// <para>
/// When <see cref="Accepted"/> is false, <see cref="Message"/> names what is still missing or what was
/// observed instead, so the caller can report pending evidence rather than a failure of the uninstall
/// itself. <see cref="UserdataPartitionBytes"/> carries the size that was actually read, or null when no
/// size was read at all; it is never filled in from the expected value.
/// </para>
/// </summary>
/// <param name="Accepted">True only for a fully proven acceptance; false covers every other outcome.</param>
/// <param name="Message">Readable explanation; never empty, and never a success claim when not accepted.</param>
/// <param name="UserdataPartitionBytes">The observed userdata size, or null when none was read.</param>
public sealed record AndroidUninstallAcceptanceResult(
    bool Accepted,
    string Message,
    long? UserdataPartitionBytes)
{
    /// <summary>
    /// Mounted data filesystem capacity in bytes that was actually read, or null when none was read. It is
    /// the capacity the decision used; it is never the expected partition size and never a computed value.
    /// </summary>
    public long? DataFilesystemBytes { get; init; }

    /// <summary>
    /// True only when acceptance rested on the permission-denied filesystem-only path: the sysfs size was
    /// explicitly refused, the userdata identity was proven by the readlink target, and the mounted capacity
    /// alone was compared with the restored plan. Normal readings leave it false.
    /// </summary>
    public bool FilesystemOnlyEvidence { get; init; }
}

/// <summary>
/// The one way the acceptance check may learn anything about the device. It is separate from
/// <see cref="ICommandRunner"/> on purpose: the caller decides how a device is read, and the acceptance
/// logic can only consume a finished observation.
/// <para>
/// Implementations are read only. They must not write, reboot, install, push, unlock or otherwise change
/// the device, and they must not invent a value they did not read: an unreadable property or an
/// unparseable size is an error, never a default.
/// </para>
/// </summary>
public interface IAndroidUninstallAcceptanceProbe
{
    /// <summary>
    /// Reads the model, serial, boot flag and userdata size of <paramref name="serial"/>.
    /// <para>
    /// <paramref name="diskDeviceId"/> must be exactly <c>/dev/sda</c> and
    /// <paramref name="userdataPartitionNumber"/> a validated positive partition number of at most 128; the
    /// two together address the sysfs node, so neither may be interpolated from untrusted text.
    /// </para>
    /// <para>
    /// A non-zero exit code, a missing property, an unparseable or overflowing size and a failed query
    /// surface as <see cref="System.IO.IOException"/> or <see cref="System.IO.InvalidDataException"/>;
    /// invalid arguments surface as <see cref="ArgumentException"/> before any command runs.
    /// <paramref name="token"/> cancellation surfaces as <see cref="OperationCanceledException"/>.
    /// </para>
    /// </summary>
    Task<AndroidUninstallObservation> ReadAsync(
        string serial,
        string diskDeviceId,
        int userdataPartitionNumber,
        CancellationToken token = default);
}

/// <summary>
/// Read-only adb probe behind <see cref="AndroidUninstallAcceptance.VerifyAsync"/>.
/// <para>
/// Every query is one <see cref="ProcessCommand"/> whose argument vector is separated before it reaches
/// <see cref="ICommandRunner"/>, and exactly these seven command shapes exist, each with a finite 15 second
/// timeout:
/// </para>
/// <list type="number">
/// <item><c>[adb, "-s", serial, "shell", "getprop", "ro.product.model"]</c> - the model.</item>
/// <item><c>[adb, "-s", serial, "shell", "getprop", "ro.serialno"]</c> - the serial.</item>
/// <item><c>[adb, "-s", serial, "shell", "getprop", "ro.boot.serialno"]</c> - only when the previous one
/// printed nothing.</item>
/// <item><c>[adb, "-s", serial, "shell", "getprop", "sys.boot_completed"]</c> - the boot flag.</item>
/// <item><c>[adb, "-s", serial, "shell", "cat", "/sys/class/block/sdaN/size"]</c> - the userdata size, with
/// N the validated partition number.</item>
/// <item><c>[adb, "-s", serial, "shell", "readlink", "-f", "/dev/block/by-name/userdata"]</c> - once on
/// every read, after the size query and before <c>df</c>: after a successful size read to record the
/// actual node, and after an explicit permission denial on that exact path to prove that the denied node
/// is the userdata partition.</item>
/// <item><c>[adb, "-s", serial, "shell", "-T", "df", "-k", "/data"]</c> - the mounted data capacity.</item>
/// </list>
/// <para>
/// The permission branch is deliberately narrow. It runs only for a non-zero result whose error text names
/// both the exact sysfs path and <c>Permission denied</c>; any other non-zero result is an
/// <see cref="System.IO.IOException"/> as before. The readlink answer must exit 0 and be exactly
/// <c>/dev/block/sdaN</c> for the validated N; a different node, a blank or otherwise unusable answer is
/// <see cref="System.IO.InvalidDataException"/>, and a failed command is an
/// <see cref="System.IO.IOException"/>. No <c>su</c>, no alternate path and no other API exists. In that
/// branch the observation carries <c>0</c> as the unknown size sentinel plus
/// <see cref="AndroidUninstallObservation.PartitionSizePermissionDenied"/>, and the mounted capacity is
/// read with the same exact <c>df</c> query as the normal path. On the readable branch the same readlink
/// query runs once after the strict size parse and before <c>df</c>, and its actual target is recorded in
/// <see cref="AndroidUninstallObservation.UserdataDeviceNode"/> as well.
/// </para>
/// <para>
/// There is no shell string concatenation anywhere: the serial is one argv entry, so a serial such as
/// <c>-s all</c> cannot become an option, and the sysfs path is built only from the fixed literal device
/// name <c>sda</c> plus a number that was range checked - the caller supplied <c>/dev/sda</c> is compared,
/// never spliced into a path. A serial that contains whitespace or a control character is refused with
/// <see cref="ArgumentException"/> before the first query runs. No reboot, push, install, write, format,
/// erase or fastboot command exists in this class.
/// </para>
/// <para>
/// The sysfs value is an unsigned decimal sector count in 512-byte units; it must parse without sign,
/// without a fractional part, be greater than zero, and its product with 512 is computed checked. A value
/// of <c>0</c>, a negative or non-numeric value, a missing value or a product that overflows 64 bits is
/// rejected as <see cref="System.IO.InvalidDataException"/> instead of being reported as a size.
/// </para>
/// </summary>
public sealed class AdbAndroidUninstallAcceptanceProbe : IAndroidUninstallAcceptanceProbe
{
    /// <summary>
    /// The only disk the acceptance probe addresses. The value is compared literally and never used as a
    /// path fragment, so no caller supplied text reaches the sysfs path.
    /// </summary>
    public const string ExpectedDiskDeviceId = "/dev/sda";

    /// <summary>Highest GPT partition number this probe accepts; anything above it is a malformed request.</summary>
    public const int MaximumUserdataPartitionNumber = 128;

    /// <summary>
    /// sysfs <c>size</c> attributes always count 512-byte units, regardless of the 4096-byte sectors this
    /// tablet's GPT uses. The conversion therefore never depends on the partition table.
    /// </summary>
    public const long SysfsUnitBytes = 512L;

    /// <summary>
    /// The only device path the permission branch may resolve. It is one fixed argv entry; the caller's
    /// disk value is never spliced into it and no alternative by-name path exists.
    /// </summary>
    public const string UserdataByNamePath = "/dev/block/by-name/userdata";

    /// <summary>
    /// The exact text the kernel-side read prints when the sysfs node refuses access. The permission branch
    /// requires it together with the exact sysfs path, so unrelated adb or shell permission noise cannot
    /// start a fallback.
    /// </summary>
    public const string PermissionDeniedText = "Permission denied";

    /// <summary>
    /// The value <see cref="AndroidUninstallObservation.UserdataPartitionBytes"/> carries when the sysfs
    /// node was denied. It is an unknown sentinel, not a measured size and not a claim about the hardware.
    /// </summary>
    private const long UserdataSizeUnknown = 0L;

    /// <summary>The fixed, finite timeout each of the few read-only queries carries.</summary>
    public static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Creates the probe. Both dependencies are required: an empty executable path or a missing process
    /// boundary would turn every later read into an unrelated failure, so they are rejected here.
    /// </summary>
    public AdbAndroidUninstallAcceptanceProbe(ICommandRunner runner, string adbExecutable)
    {
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentException.ThrowIfNullOrWhiteSpace(adbExecutable);

        Runner = runner;
        AdbExecutable = adbExecutable;
    }

    /// <summary>adb executable every query starts; exactly one argv entry, never a full command line.</summary>
    public string AdbExecutable { get; }

    /// <summary>Process boundary. Tests pass a fake, so no real binary is ever started.</summary>
    internal ICommandRunner Runner { get; }

    /// <inheritdoc />
    public async Task<AndroidUninstallObservation> ReadAsync(
        string serial,
        string diskDeviceId,
        int userdataPartitionNumber,
        CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(serial) || ContainsWhitespaceOrControlCharacter(serial))
        {
            throw new ArgumentException(
                "The serial must be a non-empty value without whitespace or control characters.",
                nameof(serial));
        }

        if (!string.Equals(diskDeviceId, ExpectedDiskDeviceId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The only supported disk device is {ExpectedDiskDeviceId}.",
                nameof(diskDeviceId));
        }

        if (userdataPartitionNumber < 1 || userdataPartitionNumber > MaximumUserdataPartitionNumber)
        {
            throw new ArgumentException(
                $"The userdata partition number must be between 1 and {MaximumUserdataPartitionNumber}.",
                nameof(userdataPartitionNumber));
        }

        token.ThrowIfCancellationRequested();

        var model = (await RunAsync(serial, token, "shell", "getprop", "ro.product.model")
            .ConfigureAwait(false)).StandardOutput.Trim();
        if (model.Length == 0)
        {
            throw new InvalidDataException("The device did not report ro.product.model.");
        }

        var reportedSerial = (await RunAsync(serial, token, "shell", "getprop", "ro.serialno")
            .ConfigureAwait(false)).StandardOutput.Trim();
        if (reportedSerial.Length == 0)
        {
            reportedSerial = (await RunAsync(serial, token, "shell", "getprop", "ro.boot.serialno")
                .ConfigureAwait(false)).StandardOutput.Trim();
        }

        if (reportedSerial.Length == 0)
        {
            throw new InvalidDataException("The device did not report ro.serialno or ro.boot.serialno.");
        }

        var bootText = (await RunAsync(serial, token, "shell", "getprop", "sys.boot_completed")
            .ConfigureAwait(false)).StandardOutput.Trim();
        if (bootText.Length == 0)
        {
            throw new InvalidDataException("The device did not report sys.boot_completed.");
        }

        var sysfsPath = "/sys/class/block/sda"
            + userdataPartitionNumber.ToString(CultureInfo.InvariantCulture)
            + "/size";

        // The one query whose exit code is inspected before it is turned into an error: only an explicit
        // permission denial for this exact path may continue, every other non-zero result still fails.
        var sizeResult = await ExecuteAsync(serial, token, "shell", "cat", sysfsPath)
            .ConfigureAwait(false);

        if (sizeResult.ExitCode != 0)
        {
            if (!IsExplicitPermissionDenial(sizeResult, sysfsPath))
            {
                throw new IOException(
                    $"adb exited with code {sizeResult.ExitCode}: {sizeResult.StandardError.Trim()}");
            }

            // The denied node must be proven to be this userdata partition: exactly one fixed readlink
            // query, whose target has to be the /dev/block/sda{N} node of the validated partition number.
            var permissionNode = await ReadUserdataDeviceNodeAsync(serial, userdataPartitionNumber, token)
                .ConfigureAwait(false);

            var fallbackDataBytes = await ReadDataFilesystemBytesAsync(serial, token).ConfigureAwait(false);

            // Zero is the unknown sentinel, not a measurement: the flag says the size was never readable.
            // The node is the actual readlink target, never the value this method expected.
            return new AndroidUninstallObservation(
                model,
                reportedSerial,
                string.Equals(bootText, "1", StringComparison.Ordinal),
                UserdataSizeUnknown)
            {
                DataFilesystemBytes = fallbackDataBytes,
                PartitionSizePermissionDenied = true,
                UserdataDeviceNode = permissionNode,
            };
        }

        var sizeText = sizeResult.StandardOutput.Trim();
        if (sizeText.Length == 0)
        {
            throw new InvalidDataException($"The device did not report {sysfsPath}.");
        }

        if (!long.TryParse(sizeText, NumberStyles.None, CultureInfo.InvariantCulture, out var unitCount)
            || unitCount <= 0)
        {
            throw new InvalidDataException(
                $"The sysfs size '{sizeText}' is not a positive unsigned decimal sector count.");
        }

        long partitionBytes;
        try
        {
            partitionBytes = checked(unitCount * SysfsUnitBytes);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException(
                $"The sysfs size '{sizeText}' overflows when converted to bytes.");
        }

        var userdataDeviceNode = await ReadUserdataDeviceNodeAsync(serial, userdataPartitionNumber, token)
            .ConfigureAwait(false);

        var dataFilesystemBytes = await ReadDataFilesystemBytesAsync(serial, token).ConfigureAwait(false);

        return new AndroidUninstallObservation(
            model,
            reportedSerial,
            string.Equals(bootText, "1", StringComparison.Ordinal),
            partitionBytes)
        {
            DataFilesystemBytes = dataFilesystemBytes,
            UserdataDeviceNode = userdataDeviceNode,
        };
    }

    /// <summary>
    /// Runs the one fixed <c>readlink -f /dev/block/by-name/userdata</c> query and returns the actual
    /// trimmed target. A non-zero exit surfaces as <see cref="IOException"/>; a target that is not exactly
    /// the <c>/dev/block/sda{N}</c> node of the validated partition number is
    /// <see cref="InvalidDataException"/>. The returned string is what the device printed, never the node
    /// this probe expected.
    /// </summary>
    private async Task<string> ReadUserdataDeviceNodeAsync(
        string serial,
        int userdataPartitionNumber,
        CancellationToken token)
    {
        var readlinkTarget = (await RunAsync(
                serial,
                token,
                "shell",
                "readlink",
                "-f",
                UserdataByNamePath)
            .ConfigureAwait(false)).StandardOutput.Trim();

        var expectedNode = "/dev/block/sda"
            + userdataPartitionNumber.ToString(CultureInfo.InvariantCulture);
        if (!string.Equals(readlinkTarget, expectedNode, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The userdata node is not {expectedNode}; readlink reported '{readlinkTarget}'.");
        }

        return readlinkTarget;
    }

    /// <summary>
    /// True only when a failed query reports both the exact sysfs path that was read and the kernel's
    /// explicit denial text. adb has historically merged the shell streams, so both captured streams are
    /// inspected; the path anchor keeps unrelated permission chatter from starting the fallback.
    /// </summary>
    private static bool IsExplicitPermissionDenial(ProcessResult result, string sysfsPath)
    {
        var diagnostic = result.StandardError + "\n" + result.StandardOutput;
        return diagnostic.Contains(sysfsPath, StringComparison.Ordinal)
            && diagnostic.Contains(PermissionDeniedText, StringComparison.Ordinal);
    }

    /// <summary>
    /// Runs the one exact <c>df -k /data</c> query and returns the mounted capacity of the accepted data
    /// row. Unreadable output is refused instead of being replaced by anything expected.
    /// </summary>
    private async Task<long> ReadDataFilesystemBytesAsync(string serial, CancellationToken token)
    {
        var dfOutput = (await RunAsync(serial, token, "shell", "-T", "df", "-k", "/data")
            .ConfigureAwait(false)).StandardOutput;
        if (!InternalStorageReader.TryParseDataRow(dfOutput, out var totalBytes, out _, out _))
        {
            throw new InvalidDataException("The df output did not contain a readable /data row.");
        }

        return totalBytes;
    }

    private static bool ContainsWhitespaceOrControlCharacter(string value)
    {
        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character) || char.IsControl(character))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<ProcessResult> RunAsync(
        string serial,
        CancellationToken token,
        params string[] arguments)
    {
        var result = await ExecuteAsync(serial, token, arguments).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new IOException(
                $"adb exited with code {result.ExitCode}: {result.StandardError.Trim()}");
        }

        return result;
    }

    /// <summary>
    /// Runs one argv-separated query and returns its full result without judging the exit code. Exactly one
    /// caller inspects the exit code itself; every other query goes through <see cref="RunAsync"/>.
    /// </summary>
    private async Task<ProcessResult> ExecuteAsync(
        string serial,
        CancellationToken token,
        params string[] arguments)
    {
        var argv = new string[arguments.Length + 2];
        argv[0] = "-s";
        argv[1] = serial;
        Array.Copy(arguments, 0, argv, 2, arguments.Length);

        return await Runner
            .RunAsync(new ProcessCommand(AdbExecutable, argv, QueryTimeout), token)
            .ConfigureAwait(false);
    }
}

/// <summary>
/// Decides whether a booted Android really accepted the uninstalled device, from one live read plus the
/// validated uninstall inputs and the device binding.
/// <para>
/// The check is deliberately separate from <see cref="UninstallWorkflow"/> and from
/// <see cref="HttpUninstallBackend"/>: a workflow result, an HTTP transaction state or a user interface
/// switch can never stand in for it. The device has to boot into Android, come up completely, report the
/// model and serial that were confirmed, and expose a userdata partition of exactly the restored size.
/// </para>
/// <para>
/// The userdata partition number is looked up in <see cref="ValidatedUninstallInputs.CurrentTable"/> as the
/// single entry whose <see cref="GptPartition.PartUuid"/> equals
/// <see cref="LinuxInstallationLayout.UserdataPartUuid"/> - never a hardcoded number - and the read is
/// performed for the confirmed serial on the current table's <c>/dev/sda</c> node. The result is accepted
/// only when the observed model and serial are exactly the confirmed ones, the boot flag is true, the
/// observed userdata size equals <see cref="AndroidRestorePlan.RestoredAndroidBytes"/> byte for byte, and
/// the mounted data filesystem reports a positive capacity of at least 95 percent of that partition.
/// The capacity policy exists because formatting metadata legitimately consumes a small part of the
/// partition; it is not an OEM guarantee and it is not proof that any file was erased.
/// </para>
/// <para>
/// One narrow exception exists for a device whose sysfs size node is denied to the shell and whose denial
/// was proven to belong to this userdata node: when the observation carries the unknown zero sentinel with
/// <see cref="AndroidUninstallObservation.PartitionSizePermissionDenied"/>, the mounted capacity is compared
/// with <see cref="AndroidRestorePlan.RestoredAndroidBytes"/> as a baseline only. The plan is never reported
/// as if Android had printed it, the result leaves
/// <see cref="AndroidUninstallAcceptanceResult.UserdataPartitionBytes"/> null, and it sets
/// <see cref="AndroidUninstallAcceptanceResult.FilesystemOnlyEvidence"/>. A readable size must always match
/// the plan exactly, even when the flag is set, and a zero without the flag is still just a wrong size.
/// </para>
/// <para>
/// A failed or impossible read returns <see cref="AndroidUninstallAcceptanceResult"/> with
/// <see cref="AndroidUninstallAcceptanceResult.Accepted"/> false and a message that names the evidence still
/// pending; it never throws for a device problem, because an unplugged device is an expected state and not
/// a failure of the uninstall. Caller cancellation is different and always propagates.
/// </para>
/// </summary>
public static class AndroidUninstallAcceptance
{
    /// <summary>The only device id an EDL evidence set may carry; it maps to the probe's <c>/dev/sda</c>.</summary>
    private const string EdlDeviceId = "edl:ufs:lun:0";

    /// <summary>
    /// Decides whether Android accepted the device after an EDL-based uninstall, using the actual
    /// <paramref name="binding"/> proof produced by entering EDL and one live read-only observation.
    /// <para>
    /// Every EDL precondition runs before the first read: the entry identity must equal the confirmed one,
    /// the confirmed identity must be the supported <see cref="MaintenanceProfiles.Model"/> build, the
    /// current table must address <c>edl:ufs:lun:0</c>, and the entry proof must carry a strict unsigned
    /// decimal SoC serial, the matching eight-hex bus serial and exactly one matching <c>SN:</c> token on an
    /// exact <c>VID_05C6/PID_9008</c> endpoint. A failed precondition yields pending evidence and no probe
    /// call. The bootloader state is not consulted, and the confirmed inputs, table and plan are never
    /// mutated to fabricate an entry.
    /// </para>
    /// </summary>
    public static async Task<AndroidUninstallAcceptanceResult> VerifyEdlAsync(
        ValidatedUninstallInputs inputs,
        EdlEntryResult binding,
        IAndroidUninstallAcceptanceProbe probe,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(probe);
        token.ThrowIfCancellationRequested();

        var bindingProblem = ValidateEdlBinding(inputs, binding);
        if (bindingProblem is not null)
        {
            return Pending(bindingProblem, null);
        }

        var deviceId = inputs.CurrentTable.DeviceId;
        if (!string.Equals(deviceId, EdlDeviceId, StringComparison.Ordinal))
        {
            return Pending(
                $"The current partition table addresses '{deviceId}' instead of '{EdlDeviceId}'; "
                + "no read was attempted.",
                null);
        }

        // The EDL marker is not a device path: the probe policy maps this one known profile to /dev/sda.
        return await ValidateObservedAsync(
                inputs,
                probe,
                AdbAndroidUninstallAcceptanceProbe.ExpectedDiskDeviceId,
                requireUserdataDeviceNode: true,
                token)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the device once through <paramref name="probe"/> and decides whether Android accepted it.
    /// </summary>
    public static async Task<AndroidUninstallAcceptanceResult> VerifyAsync(
        ValidatedUninstallInputs inputs,
        UninstallDeviceBinding binding,
        IAndroidUninstallAcceptanceProbe probe,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(probe);
        token.ThrowIfCancellationRequested();

        var confirmedSerial = inputs.Identity.Serial;

        if (!binding.Identity.Equals(inputs.Identity)
            || !string.Equals(binding.FastbootSerial, confirmedSerial, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(binding.AndroidSocSerial))
        {
            return Pending(
                "The device binding does not match the confirmed device; no read was attempted.",
                null);
        }

        var deviceId = inputs.CurrentTable.DeviceId;
        if (!string.Equals(
                deviceId,
                AdbAndroidUninstallAcceptanceProbe.ExpectedDiskDeviceId,
                StringComparison.Ordinal))
        {
            return Pending(
                $"The current partition table addresses '{deviceId}' instead of "
                + $"'{AdbAndroidUninstallAcceptanceProbe.ExpectedDiskDeviceId}'; no read was attempted.",
                null);
        }

        return await ValidateObservedAsync(
                inputs,
                probe,
                deviceId,
                requireUserdataDeviceNode: false,
                token)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Checks the non-probe facts of an EDL entry proof. Returns a pending message, or null when every
    /// binding fact is present and consistent with the confirmed identity.
    /// </summary>
    private static string? ValidateEdlBinding(ValidatedUninstallInputs inputs, EdlEntryResult binding)
    {
        var android = binding.AndroidIdentity;
        var identity = android?.Identity;
        if (android is null || identity is null)
        {
            return "The EDL entry proof carries no Android identity; no read was attempted.";
        }

        if (!identity.Equals(inputs.Identity))
        {
            return "The EDL entry identity does not match the confirmed device; no read was attempted.";
        }

        if (!string.Equals(inputs.Identity.Model, MaintenanceProfiles.Model, StringComparison.Ordinal)
            || !string.Equals(
                inputs.Identity.Firmware?.DisplayId,
                MaintenanceProfiles.AndroidBuild,
                StringComparison.Ordinal))
        {
            return "The confirmed identity is not the supported "
                + $"{MaintenanceProfiles.Model} / {MaintenanceProfiles.AndroidBuild} profile; "
                + "no read was attempted.";
        }

        if (!uint.TryParse(android.SocSerial, NumberStyles.None, CultureInfo.InvariantCulture, out var soc))
        {
            return "The EDL entry does not carry an unsigned decimal 32-bit SoC serial; no read was attempted.";
        }

        if (!IsEightHexDigits(binding.BusSerialHex))
        {
            return "The EDL entry does not carry an exactly eight-digit hex bus serial; no read was attempted.";
        }

        if (!string.Equals(
                binding.BusSerialHex,
                soc.ToString("X8", CultureInfo.InvariantCulture),
                StringComparison.OrdinalIgnoreCase))
        {
            return "The EDL bus serial does not match the entry SoC serial; no read was attempted.";
        }

        if (binding.Endpoint is null
            || WindowsEdlEndpointDiscovery.FilterCandidates(new[] { binding.Endpoint }).Count != 1)
        {
            return "The EDL entry endpoint is not the exact USB 05C6/9008 gadget; no read was attempted.";
        }

        if (!TryReadSingleSnSerial(binding.Endpoint.BusReportedDeviceDescription, out var reportedBusSerial))
        {
            return "The EDL endpoint description does not carry exactly one eight-digit hex SN token; "
                + "no read was attempted.";
        }

        if (!string.Equals(reportedBusSerial, binding.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            return "The EDL endpoint SN token does not match the entry bus serial; no read was attempted.";
        }

        return null;
    }

    /// <summary>True only for exactly eight ASCII hex digits; signs, prefixes and blanks are refused.</summary>
    private static bool IsEightHexDigits(string? value)
    {
        if (value is null || value.Length != 8)
        {
            return false;
        }

        foreach (var character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Reads the one underscore-delimited <c>SN:</c> token of the bus description. Zero or several labels,
    /// or a value that is not exactly eight hex digits, are unusable; the expected value is never substituted.
    /// </summary>
    private static bool TryReadSingleSnSerial(string? description, out string busSerial)
    {
        busSerial = string.Empty;
        if (string.IsNullOrEmpty(description))
        {
            return false;
        }

        const string SnLabel = "SN:";
        var labels = 0;
        string? value = null;

        foreach (var token in description.Split('_'))
        {
            if (token.StartsWith(SnLabel, StringComparison.OrdinalIgnoreCase))
            {
                labels++;
                value = token.Substring(SnLabel.Length);
            }
        }

        if (labels != 1 || !IsEightHexDigits(value))
        {
            return false;
        }

        busSerial = value!;
        return true;
    }

    /// <summary>
    /// The one shared read and observation check behind both public entry points: resolve the recorded
    /// userdata partition, read once, and apply the same literal comparisons. <paramref name="probeDiskDeviceId"/>
    /// is the caller's private probe policy (the actual table device for RAM, the mapped <c>/dev/sda</c> for
    /// EDL), and <paramref name="requireUserdataDeviceNode"/> only adds the EDL node requirement without
    /// changing any legacy RAM comparison.
    /// </summary>
    private static async Task<AndroidUninstallAcceptanceResult> ValidateObservedAsync(
        ValidatedUninstallInputs inputs,
        IAndroidUninstallAcceptanceProbe probe,
        string probeDiskDeviceId,
        bool requireUserdataDeviceNode,
        CancellationToken token)
    {
        var confirmedSerial = inputs.Identity.Serial;

        GptPartition userdata = default!;
        var matches = 0;
        foreach (var partition in inputs.CurrentTable.Partitions)
        {
            if (string.Equals(
                    partition.PartUuid,
                    inputs.Record.UserdataPartUuid,
                    StringComparison.OrdinalIgnoreCase))
            {
                matches++;
                userdata = partition;
            }
        }

        if (matches != 1)
        {
            return Pending(
                $"The current partition table contains {matches} partitions with the recorded userdata "
                + "PARTUUID instead of exactly one; no read was attempted.",
                null);
        }

        var userdataNumber = userdata.Number;
        if (userdataNumber < 1
            || userdataNumber > AdbAndroidUninstallAcceptanceProbe.MaximumUserdataPartitionNumber)
        {
            return Pending(
                $"The recorded userdata partition number {userdataNumber} is outside the supported range; "
                + "no read was attempted.",
                null);
        }

        AndroidUninstallObservation observation;
        try
        {
            observation = await probe
                .ReadAsync(confirmedSerial, probeDiskDeviceId, userdataNumber, token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or InvalidDataException
            or TimeoutException
            or InvalidOperationException)
        {
            return Pending(
                $"The read-only Android query could not complete: {exception.Message}",
                null);
        }

        var observedBytes = observation.UserdataPartitionBytes;

        // A zero size is unknown only when the probe explicitly proved a permission denial; any other zero
        // is a zero and must still be compared with the plan.
        var filesystemOnly = observedBytes == 0 && observation.PartitionSizePermissionDenied;
        var observedSize = observedBytes > 0 ? observedBytes : (long?)null;

        if (requireUserdataDeviceNode)
        {
            var expectedNode = "/dev/block/sda"
                + userdataNumber.ToString(CultureInfo.InvariantCulture);
            if (!string.Equals(observation.UserdataDeviceNode, expectedNode, StringComparison.Ordinal))
            {
                return Pending(
                    $"EDL acceptance requires the actual readlink target {expectedNode} for the userdata "
                    + $"partition, but the device reported '{observation.UserdataDeviceNode ?? "<none>"}'.",
                    observedSize,
                    observation.DataFilesystemBytes);
            }
        }

        if (!string.Equals(observation.Model, inputs.Identity.Model, StringComparison.Ordinal))
        {
            return Pending(
                $"The device reports model '{observation.Model}' instead of the confirmed "
                + $"'{inputs.Identity.Model}'.",
                observedSize,
                observation.DataFilesystemBytes);
        }

        if (!string.Equals(observation.Serial, confirmedSerial, StringComparison.Ordinal))
        {
            return Pending(
                $"The device reports serial '{observation.Serial}' instead of the confirmed "
                + $"'{confirmedSerial}'.",
                observedSize,
                observation.DataFilesystemBytes);
        }

        if (!observation.BootCompleted)
        {
            return Pending(
                "Android has not reported sys.boot_completed as 1; the system is not fully booted.",
                observedSize,
                observation.DataFilesystemBytes);
        }

        // Only the explicit permission branch may use the restored plan as its comparison baseline, and it
        // never turns that baseline into an observed value. Every readable size is compared exactly.
        long comparisonBytes;
        if (filesystemOnly)
        {
            comparisonBytes = inputs.Plan.RestoredAndroidBytes;
        }
        else
        {
            if (observedBytes != inputs.Plan.RestoredAndroidBytes)
            {
                return Pending(
                    $"The userdata partition is {observedBytes} bytes instead of the restored "
                    + $"{inputs.Plan.RestoredAndroidBytes} bytes.",
                    observedSize,
                    observation.DataFilesystemBytes);
            }

            comparisonBytes = observedBytes;
        }

        var filesystemBytes = observation.DataFilesystemBytes;
        if (filesystemBytes is null || filesystemBytes.Value <= 0)
        {
            return Pending(
                filesystemOnly
                    ? "The userdata size was permission denied, but the mounted /data filesystem capacity "
                        + "was not readable; filesystem-only capacity evidence is still pending."
                    : "The mounted /data filesystem capacity was not readable.",
                observedSize,
                filesystemBytes);
        }

        if (filesystemBytes.Value > comparisonBytes)
        {
            return Pending(
                filesystemOnly
                    ? $"The userdata size was permission denied and the /data filesystem reports "
                        + $"{filesystemBytes.Value} bytes, more than the {comparisonBytes} byte restored "
                        + "plan; filesystem-only capacity evidence is still pending."
                    : $"The /data filesystem reports {filesystemBytes.Value} bytes, more than the "
                        + $"{observedBytes} byte partition.",
                observedSize,
                filesystemBytes);
        }

        var ratio = (decimal)filesystemBytes.Value / comparisonBytes;
        if (ratio < 0.95m)
        {
            return Pending(
                filesystemOnly
                    ? $"The userdata size was permission denied and the /data filesystem reports "
                        + $"{filesystemBytes.Value} bytes, only "
                        + $"{ratio.ToString("P1", CultureInfo.InvariantCulture)} of the {comparisonBytes} "
                        + "byte restored plan; filesystem-only capacity evidence is still pending."
                    : $"The /data filesystem reports {filesystemBytes.Value} bytes, only "
                        + $"{ratio.ToString("P1", CultureInfo.InvariantCulture)} of the {observedBytes} byte "
                        + "partition; capacity evidence is still pending.",
                observedSize,
                filesystemBytes);
        }

        if (filesystemOnly)
        {
            return new AndroidUninstallAcceptanceResult(
                true,
                $"Android accepted the device on filesystem-only capacity evidence: model "
                + $"'{observation.Model}', serial '{observation.Serial}', booted, the sysfs size was "
                + "explicitly permission denied and its node was proven to be the userdata partition, and "
                + $"the mounted /data filesystem reports {filesystemBytes.Value} bytes, at least 95% of "
                + $"the {comparisonBytes} byte restored plan. The partition size itself was not read from "
                + "the device.",
                null)
            {
                DataFilesystemBytes = filesystemBytes,
                FilesystemOnlyEvidence = true,
            };
        }

        return new AndroidUninstallAcceptanceResult(
            true,
            $"Android accepted the device: model '{observation.Model}', serial '{observation.Serial}', "
            + $"booted, {observedBytes} byte userdata partition and a {filesystemBytes.Value} byte "
            + "/data filesystem.",
            observedBytes)
        {
            DataFilesystemBytes = filesystemBytes,
        };
    }

    private static AndroidUninstallAcceptanceResult Pending(
        string message,
        long? observedBytes,
        long? filesystemBytes = null)
    {
        return new AndroidUninstallAcceptanceResult(false, message, observedBytes)
        {
            DataFilesystemBytes = filesystemBytes,
        };
    }
}
