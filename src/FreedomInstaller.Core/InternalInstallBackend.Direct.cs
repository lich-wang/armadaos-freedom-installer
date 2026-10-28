using System;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public sealed partial class InternalInstallBackend
{
    /// <summary>
    /// The direct EDL raw preparation entry point. It uses the same cheap guards as the legacy factory, then
    /// delegates to the parameterised <see cref="InternalInstallPreparationContext.PrepareDirectAsync"/> body:
    /// one schema-2 raw package snapshot, its own typed tool lease, the actual 52-file backup and nine prepared
    /// artifacts, and a real <see cref="EdlRawBootBuilder"/> result for the observed current slot.
    /// </summary>
    /// <remarks>
    /// The body builds both slot candidates and the actual current slot is observed from the device. This method
    /// only prepares local evidence: it performs no device write, no RAM session and no reset. The one real
    /// execution is the wired direct flow in <see cref="ExecuteAsync"/>.
    /// </remarks>
    public static async Task<InternalInstallBackend> CreatePreparedAsync(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup,
        InternalArtifactSet artifacts,
        ImportedPackage package,
        InternalInstallDirectAssets installAssets,
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

        RequireDirectSlot(deviceCheck);
        RequireCompleteDeviceCheck(deviceCheck);
        RequireDirectDeviceProfile(deviceCheck);
        RequireInitialProof(initialEdl);
        _ = RequireDirectBoundSession(deviceCheck, initialEdl, backup);

        InternalInstallPreparationContext context = await InternalInstallPreparationContext
            .PrepareDirectAsync(
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

    // ------------------------------------------------------------------ direct cheap gates

    /// <summary>
    /// The direct route prepares either observed slot; unlike the legacy maintenance-boot route it has no
    /// fixed slot A. Any other value - including null, empty or an invented slot - is refused with the same
    /// stable slot code before a source is read.
    /// </summary>
    private static void RequireDirectSlot(InternalDeviceCheckResult deviceCheck)
    {
        if (deviceCheck.CurrentSlot is not ("a" or "b"))
        {
            throw Refuse(
                UnsupportedSlotCode,
                "the observed current slot is '" + (deviceCheck.CurrentSlot ?? "<none>")
                + "'; the direct install supports exactly slot a or slot b.");
        }
    }

    /// <summary>
    /// A cheap profile selection gate that precedes the initial proof: the observed model must resolve to a
    /// complete built-in trusted profile that supports this exact identity. The concrete toolchain/profile
    /// reference is re-checked in <see cref="RequireDirectBoundSession"/>.
    /// </summary>
    private static void RequireDirectDeviceProfile(InternalDeviceCheckResult deviceCheck)
    {
        DeviceIdentity identity = deviceCheck.Android!.Identity;
        EdlDeviceProfile? profile = EdlDeviceProfiles.FindByModel(identity.Model);

        if (profile is null || !profile.IsComplete || !profile.SupportsIdentity(identity))
        {
            throw Refuse(
                UnsupportedProfileCode,
                "the observed device model '" + identity.Model + "' build '"
                + (identity.Firmware?.DisplayId ?? "<none>")
                + "' does not select a complete trusted EDL profile.");
        }
    }

    /// <summary>
    /// Binds the session with the shared identity/backup checks, and restricts the toolchain to the one trusted
    /// built-in profile instance. The allowed scalar profile id, model, full hardware id and build all come from
    /// that profile and the actual observed identity; no route constant is restated here.
    /// </summary>
    internal static EdlDeviceProfile RequireDirectBoundSession(
        InternalDeviceCheckResult deviceCheck,
        EdlClient initialEdl,
        InternalBackupSet backup)
    {
        EdlDeviceProfile? trusted = null;

        RequireBoundSessionCore(
            deviceCheck,
            initialEdl,
            backup,
            toolchain =>
            {
                EdlDeviceProfile profile = toolchain.Profile
                    ?? throw new InvalidOperationException(
                        BindingMismatchCode + ": the EDL toolchain carries no trusted profile.");

                EdlDeviceProfile? builtin = EdlDeviceProfiles.FindById(profile.ProfileId);
                if (builtin is null || !ReferenceEquals(profile, builtin))
                {
                    throw Refuse(
                        UnsupportedProfileCode,
                        "the loaded EDL toolchain profile is not the trusted built-in instance.");
                }

                profile.RequireComplete();

                AndroidMaintenanceIdentity android = deviceCheck.Android!;
                DeviceIdentity identity = android.Identity;
                string? fullHardwareId = profile.FullHardwareId;

                if (!profile.SupportsIdentity(identity)
                    || fullHardwareId is null
                    || !string.Equals(toolchain.ProfileId, profile.ProfileId, StringComparison.Ordinal)
                    || !string.Equals(toolchain.Model, profile.Model, StringComparison.Ordinal)
                    || !string.Equals(toolchain.HardwareId, fullHardwareId, StringComparison.Ordinal))
                {
                    throw Refuse(
                        UnsupportedProfileCode,
                        "the loaded EDL toolchain scalars do not match the trusted profile and observed identity.");
                }

                trusted = profile;
            });

        return trusted
            ?? throw new InvalidOperationException(
                UnsupportedProfileCode + ": no trusted EDL profile was selected.");
    }
}
