using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The one real backend of the internal Android-to-Linux install: a stateful, single-use object that owns the
/// preparation evidence of exactly one install.
/// <para>
/// A backend instance only ever comes from <see cref="CreatePreparedAsync"/>. There is no public constructor, no
/// ready flag, no mode switch and no injected delegate: the factory either produces a fully verified
/// <see cref="Prepared"/> result or refuses with a stable error code, and the caller can never talk it into a
/// prepared state.
/// </para>
/// <para>
/// Preparation validates cheap guards and cancellation first, then the current slot, the complete Step 1 result,
/// the install profile and the initial Sahara proof, then the bound session identity. Only after that does it open
/// its own independent read leases and re-verify every source: the package snapshot, the three install assets, the
/// own 52-file backup read, the nine prepared artifacts, both slot material analyses, the strict install-package
/// binding, the per-slot raw upper bound and finally the fresh original-device capture.
/// </para>
/// <para>
/// <see cref="Dispose"/> releases only the leases this backend owns through its context: it never deletes
/// evidence, never rewinds the device and never disposes the caller's backup, artifact, package, asset, service,
/// toolchain or client objects. The public <c>ExecuteAsync</c> and <c>CheckAcceptanceAsync</c> entries of the
/// execution partial drive this instance after preparation.
/// </para>
/// </summary>
public sealed partial class InternalInstallBackend : IDisposable
{
    private const string UnsupportedSlotCode = "unsupported-current-slot";

    private const string DeviceCheckIncompleteCode = "device-check-incomplete";

    private const string UnsupportedProfileCode = "unsupported-install-profile";

    private const string InitialProofCode = "edl-initial-proof-required";

    private const string BindingMismatchCode = "install-session-binding-mismatch";

    private const string RequiredModel = "TB322FC";

    private const string RequiredProfileId = "g4-9008-259";

    private const string RequiredHardwareId = "0028D0E100400000";

    private const string RequiredAndroidBuild = MaintenanceProfiles.AndroidBuild;

    private readonly object _gate = new();

    private readonly InternalInstallPreparationContext _context;

    private readonly EdlClient _initialEdl;

    private readonly InternalInstallServices _services;

    private readonly InternalDeviceCheckResult _deviceCheck;

    private InternalInstallSnapshot _snapshot;

    private InternalInstallResult? _lastResult;

    private bool _executionStarted;

    private bool _executing;

    private bool _disposed;

    /// <summary>
    /// Private constructor: an instance exists only as the result of a successful preparation, so no caller can
    /// assemble a backend from its own parts.
    /// </summary>
    private InternalInstallBackend(
        InternalInstallPreparationContext context,
        EdlClient initialEdl,
        InternalInstallServices services,
        InternalDeviceCheckResult deviceCheck,
        InternalInstallPrepared prepared,
        InternalInstallSnapshot snapshot)
    {
        _context = context;
        _initialEdl = initialEdl;
        _services = services;
        _deviceCheck = deviceCheck;
        _snapshot = snapshot;
        Prepared = prepared;
        _lastResult = null;
        _executionStarted = false;
        _executing = false;
        _disposed = false;
    }

    /// <summary>
    /// Verifies every input and produces the prepared state for exactly one install.
    /// <para>
    /// Every refusal is an <see cref="InvalidOperationException"/> whose message starts with the stable code
    /// <c>unsupported-current-slot</c>, <c>device-check-incomplete</c>, <c>unsupported-install-profile</c>,
    /// <c>edl-initial-proof-required</c>, <c>install-session-binding-mismatch</c> or
    /// <c>unsupported-install-package-bound</c>. Missing arguments are rejected as
    /// <see cref="ArgumentNullException"/>, a blank evidence parent as <see cref="ArgumentException"/> and a
    /// pre-cancelled token before anything is read.
    /// </para>
    /// </summary>
    public static async Task<InternalInstallBackend> CreatePreparedAsync(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup,
        InternalArtifactSet artifacts,
        ImportedPackage package,
        InternalInstallAssets installAssets,
        InternalInstallServices services,
        string evidenceParent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceCheck);
        ArgumentNullException.ThrowIfNull(initialEdl);
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(installAssets);
        ArgumentNullException.ThrowIfNull(services);

        if (evidenceParent is null)
        {
            throw new ArgumentNullException(nameof(evidenceParent));
        }

        if (evidenceParent.Trim().Length == 0)
        {
            throw new ArgumentException(
                "An explicit evidence parent directory is required; there is no default location.",
                nameof(evidenceParent));
        }

        // Nothing below this line may run for a caller that already cancelled; no resource is dereferenced first.
        cancellationToken.ThrowIfCancellationRequested();

        RequireSupportedSlot(deviceCheck);
        RequireCompleteDeviceCheck(deviceCheck);
        RequireSupportedProfile(deviceCheck);
        RequireInitialProof(initialEdl);
        RequireBoundSession(deviceCheck, initialEdl, backup);

        InternalInstallPreparationContext context = await InternalInstallPreparationContext
            .PrepareAsync(
                deviceCheck,
                initialEdl,
                backup,
                artifacts,
                package,
                installAssets,
                services,
                evidenceParent,
                cancellationToken)
            .ConfigureAwait(false);

        try
        {
            InternalInstallPrepared.State state = new();
            context.FillPreparedState(state);

            InternalInstallPrepared prepared = new(state);
            InternalInstallSnapshot snapshot = new(
                executionStarted: false,
                InternalInstallStage.Prepared,
                InternalInstallWriteState.NoneIssued,
                outcome: null,
                InternalInstallUserAction.None,
                context.EvidenceDirectory,
                androidDataMayBeErased: false);

            return new InternalInstallBackend(context, initialEdl, services, deviceCheck, prepared, snapshot);
        }
        catch
        {
            context.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The verified preparation data of this instance. Getter-only: the value is fixed when the factory succeeds
    /// and can never be replaced or edited by a caller.
    /// </summary>
    public InternalInstallPrepared Prepared { get; }

    /// <summary>
    /// The authoritative current state of this instance. Getter-only: the backend replaces its own snapshot, a
    /// caller only reads it.
    /// </summary>
    public InternalInstallSnapshot Snapshot
    {
        get
        {
            lock (_gate)
            {
                return _snapshot;
            }
        }
    }

    /// <summary>The result of the last finished execution or acceptance run, or null before any run.</summary>
    public InternalInstallResult? LastResult
    {
        get
        {
            lock (_gate)
            {
                return _lastResult;
            }
        }
    }

    /// <summary>
    /// Releases only the read leases this backend owns. Idempotent, it never deletes evidence, resets a device or
    /// disposes the caller's objects; it refuses while an execution is in progress.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (_executing)
            {
                throw new InvalidOperationException(
                    "The internal install backend cannot be disposed while an execution is running.");
            }

            _disposed = true;
        }

        _context.Dispose();
    }

    // ------------------------------------------------------------------ cheap gates

    private static void RequireSupportedSlot(InternalDeviceCheckResult deviceCheck)
    {
        if (!string.Equals(deviceCheck.CurrentSlot, "a", StringComparison.Ordinal))
        {
            throw Refuse(
                UnsupportedSlotCode,
                "the observed current slot is '" + (deviceCheck.CurrentSlot ?? "<none>") + "'; the internal install "
                + "writes the maintenance boot to slot a only.");
        }
    }

    private static void RequireCompleteDeviceCheck(InternalDeviceCheckResult deviceCheck)
    {
        AndroidMaintenanceIdentity? android = deviceCheck.Android;
        DeviceIdentity? identity = android?.Identity;
        FirmwareSnapshot? firmware = identity?.Firmware;

        bool complete = deviceCheck.Succeeded
            && android is not null
            && identity is not null
            && firmware is not null
            && !string.IsNullOrWhiteSpace(firmware.DisplayId)
            && !string.IsNullOrWhiteSpace(firmware.BuildFingerprint)
            && !string.IsNullOrWhiteSpace(firmware.AndroidRelease)
            && !string.IsNullOrWhiteSpace(firmware.SecurityPatch)
            && (deviceCheck.FastbootLockState == BootloaderState.Locked
                || deviceCheck.FastbootLockState == BootloaderState.Unlocked);

        if (!complete)
        {
            throw Refuse(
                DeviceCheckIncompleteCode,
                "the Step 1 result is not a complete, verified device check with a confirmed lock state and a full "
                + "firmware snapshot.");
        }
    }

    private static void RequireSupportedProfile(InternalDeviceCheckResult deviceCheck)
    {
        DeviceIdentity identity = deviceCheck.Android!.Identity;
        FirmwareSnapshot firmware = identity.Firmware!;

        if (!string.Equals(identity.Model, RequiredModel, StringComparison.Ordinal)
            || !string.Equals(firmware.DisplayId, RequiredAndroidBuild, StringComparison.Ordinal))
        {
            throw Refuse(
                UnsupportedProfileCode,
                "the observed device is model '" + identity.Model + "' build '" + firmware.DisplayId
                + "'; only model " + RequiredModel + " with the exact " + RequiredAndroidBuild
                + " build is supported.");
        }
    }

    private static void RequireInitialProof(EdlClient initialEdl)
    {
        if (!initialEdl.HasInitialSaharaProof)
        {
            throw Refuse(
                InitialProofCode,
                "the EDL session has not proven its initial Sahara loader, so no device metadata can be trusted.");
        }
    }

    // ------------------------------------------------------------------ bound session

    private static void RequireBoundSession(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup) =>
        RequireBoundSessionCore(deviceCheck, initialEdl, backup, RequireLegacyToolchain);

    /// <summary>
    /// The one reviewed G4 toolchain restriction of the legacy RAM/seed install. It stays byte-for-byte the
    /// same set of constants; the direct route supplies its own trusted-profile check instead.
    /// </summary>
    private static void RequireLegacyToolchain(EdlToolchain toolchain)
    {
        if (!string.Equals(toolchain.ProfileId, RequiredProfileId, StringComparison.Ordinal)
            || !string.Equals(toolchain.Model, RequiredModel, StringComparison.Ordinal)
            || !string.Equals(toolchain.AndroidBuild, RequiredAndroidBuild, StringComparison.Ordinal)
            || !string.Equals(toolchain.HardwareId, RequiredHardwareId, StringComparison.Ordinal))
        {
            throw Refuse(
                UnsupportedProfileCode,
                "the loaded EDL toolchain is not the reviewed G4 profile '" + RequiredProfileId + "'.");
        }
    }

    /// <summary>
    /// The identity and backup binding shared by the legacy and direct factories. The caller supplies the
    /// only route-specific part - which trusted toolchain facts are allowed - so the generic bus/identity,
    /// fastboot-serial and backup-session checks cannot drift apart between the two routes.
    /// </summary>
    internal static void RequireBoundSessionCore(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup,
        Action<EdlToolchain> requireToolchain)
    {
        ArgumentNullException.ThrowIfNull(requireToolchain);

        AndroidMaintenanceIdentity android = deviceCheck.Android!;
        DeviceIdentity identity = android.Identity;

        EdlToolchain toolchain = initialEdl.Toolchain
            ?? throw new InvalidOperationException(BindingMismatchCode + ": the EDL client carries no toolchain.");

        requireToolchain(toolchain);

        EdlEntryResult binding = initialEdl.Binding
            ?? throw new InvalidOperationException(BindingMismatchCode + ": the EDL client carries no binding.");

        if (binding.AndroidIdentity is null || binding.AndroidIdentity.Identity is null)
        {
            throw new InvalidOperationException(BindingMismatchCode + ": the EDL binding carries no Android identity.");
        }

        string expectedBusSerial = ExpectedBusSerial(android.SocSerial);

        if (!SameText(binding.BusSerialHex, expectedBusSerial)
            || !SameAndroidIdentity(binding.AndroidIdentity, android))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL binding is not the device the Step 1 check verified.");
        }

        if (!string.Equals(deviceCheck.FastbootSerial, identity.Serial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the fastboot serial does not match the verified Android serial.");
        }

        if (!string.Equals(backup.ProfileId, toolchain.ProfileId, StringComparison.Ordinal)
            || !string.Equals(backup.Model, toolchain.Model, StringComparison.Ordinal)
            || !string.Equals(backup.AndroidBuild, identity.Firmware!.DisplayId, StringComparison.Ordinal)
            || !string.Equals(backup.HardwareId, toolchain.HardwareId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the backup profile is not the loaded EDL toolchain profile.");
        }

        if (backup.Binding is null || !SameBinding(backup.Binding, binding))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the backup was not taken from this exact EDL session.");
        }
    }

    private static bool SameBinding(EdlEntryResult left, EdlEntryResult right) =>
        SameText(left.BusSerialHex, right.BusSerialHex)
        && left.AndroidIdentity is not null
        && right.AndroidIdentity is not null
        && SameAndroidIdentity(left.AndroidIdentity, right.AndroidIdentity);

    private static bool SameAndroidIdentity(
        AndroidMaintenanceIdentity left,
        AndroidMaintenanceIdentity right) =>
        string.Equals(left.SocSerial, right.SocSerial, StringComparison.Ordinal)
        && left.Identity is not null
        && right.Identity is not null
        && string.Equals(left.Identity.Serial, right.Identity.Serial, StringComparison.Ordinal)
        && string.Equals(left.Identity.Model, right.Identity.Model, StringComparison.Ordinal)
        && SameFirmware(left.Identity.Firmware, right.Identity.Firmware);

    private static bool SameFirmware(FirmwareSnapshot? left, FirmwareSnapshot? right) =>
        left is not null
        && right is not null
        && string.Equals(left.DisplayId, right.DisplayId, StringComparison.Ordinal)
        && string.Equals(left.BuildFingerprint, right.BuildFingerprint, StringComparison.Ordinal)
        && string.Equals(left.AndroidRelease, right.AndroidRelease, StringComparison.Ordinal)
        && string.Equals(left.SecurityPatch, right.SecurityPatch, StringComparison.Ordinal)
        && left.AndroidReportedBootloaderState == right.AndroidReportedBootloaderState;

    /// <summary>
    /// The only accepted SoC-to-bus form: an unsigned 32-bit decimal written as exactly eight uppercase hex
    /// digits. Zero and the broadcast value are rejected.
    /// </summary>
    private static string ExpectedBusSerial(string socSerial)
    {
        if (!uint.TryParse(socSerial, NumberStyles.None, CultureInfo.InvariantCulture, out uint value)
            || value == 0
            || value == uint.MaxValue)
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the SoC serial is not a usable unsigned 32-bit decimal value.");
        }

        return value.ToString("X8", CultureInfo.InvariantCulture);
    }

    private static bool SameText(string? left, string? right) =>
        left is not null && right is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static InvalidOperationException Refuse(string code, string detail) => new(code + ": " + detail);
}

/// <summary>
/// The concrete services one internal install uses, wrapped once so the backend depends on a small sealed set
/// instead of ambient state.
/// <para>
/// It holds the real <see cref="EdlEntry"/>, <see cref="ICommandRunner"/>, <see cref="IEdlEndpointDiscovery"/> and
/// the adb path by reference. It adds no behaviour of its own: no mode switch, no simulation branch, no dispose of
/// the objects it was given and no device action. The Windows maintenance console does not exist while the device
/// is prepared in 9008; the execution owner creates the real one after the normal reset, so no console or bootstrap
/// object is carried here.
/// </para>
/// </summary>
public sealed class InternalInstallServices
{
    /// <summary>
    /// Stores the exact references. Only cheap guards run here; nothing is started and no device is touched.
    /// </summary>
    public InternalInstallServices(
        EdlEntry edlEntry,
        ICommandRunner commandRunner,
        IEdlEndpointDiscovery endpointDiscovery,
        string adbPath)
    {
        ArgumentNullException.ThrowIfNull(edlEntry);
        ArgumentNullException.ThrowIfNull(commandRunner);
        ArgumentNullException.ThrowIfNull(endpointDiscovery);
        ArgumentException.ThrowIfNullOrWhiteSpace(adbPath);

        EdlEntry = edlEntry;
        CommandRunner = commandRunner;
        EndpointDiscovery = endpointDiscovery;
        AdbPath = adbPath;
    }

    /// <summary>The EDL entry boundary, exactly as supplied by the caller.</summary>
    public EdlEntry EdlEntry { get; }

    /// <summary>The process boundary every command goes through.</summary>
    public ICommandRunner CommandRunner { get; }

    /// <summary>The read-only EDL endpoint enumeration.</summary>
    public IEdlEndpointDiscovery EndpointDiscovery { get; }

    /// <summary>The adb executable path, non-blank.</summary>
    public string AdbPath { get; }
}
