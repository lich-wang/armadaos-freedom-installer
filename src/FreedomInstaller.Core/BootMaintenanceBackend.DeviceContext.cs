using System;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

// Device-context part of the boot-maintenance backend (H2 EDL route): the immutable MaintenanceDeviceFacts
// origin pair, the EDL-route factory wrapper, the exact per-origin facts validation, the identity-context
// evidence receipt and the small repair fallback target chooser of the UI package filter. Nothing here
// manufactures a current Android check, simulates ADB/fastboot state, forces a probe or claims current
// firmware for the historical route.
public sealed partial class BootMaintenanceBackend
{
    /// <summary>
    /// Immutable origin facts of one preparation: exactly one actual origin - the live Android device check
    /// or the accepted historical backup - plus the identity both routes trust. There is no public
    /// constructor and no valid/ready flag: the two factory routes are the only producers, and the shared
    /// core validation decides everything else from actual facts.
    /// </summary>
    private sealed record MaintenanceDeviceFacts
    {
        internal MaintenanceDeviceFacts(
            AndroidMaintenanceIdentity identity,
            InternalDeviceCheckResult? androidCheck,
            BootMaintenanceHistoricalIdentity? history)
        {
            if ((androidCheck is null) == (history is null))
            {
                throw new ArgumentException(
                    "The maintenance device facts must carry exactly one actual origin: the live Android "
                    + "check or the historical backup, never both and never neither.");
            }

            Identity = identity;
            AndroidCheck = androidCheck;
            History = history;
        }

        /// <summary>The identity the pass reports; the historical adapter on the EDL route.</summary>
        public AndroidMaintenanceIdentity Identity { get; }

        /// <summary>The live Android device check, or null on the EDL route.</summary>
        public InternalDeviceCheckResult? AndroidCheck { get; }

        /// <summary>The accepted historical backup identity, or null on the Android route.</summary>
        public BootMaintenanceHistoricalIdentity? History { get; }
    }

    /// <summary>
    /// EDL-route factory: prepares exactly one BeforeUpdate or RestoreStock pass from an explicitly
    /// accepted historical backup identity instead of a live Android device check. The current slot is the
    /// freshly verified misc control slot, the identity facts are the saved historical ones re-anchored
    /// against the real bound EDL session, and the saved historical firmware is labelled evidence only -
    /// it is never claimed as currently observed and never decides trust, slot or freshness. No current
    /// Android check is manufactured: the actual client session must already carry its initial Sahara
    /// proof and the bound hardware identity.
    /// <para>
    /// The guards, source rules, evidence flow and plan are exactly the shared core of
    /// <see cref="CreatePreparedAsync"/>; <see cref="MaintenanceMode.AfterUpdate"/> is refused before any
    /// I/O with the same stable code.
    /// </para>
    /// </summary>
    public static async Task<BootMaintenanceBackend> CreatePreparedFromEdlAsync(
        MaintenanceMode mode,
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet currentBackup,
        BootMaintenanceSources sources,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(history);

        return await CreatePreparedCoreAsync(
            mode,
            new MaintenanceDeviceFacts(history.Identity, null, history),
            client,
            currentBackup,
            sources,
            runner,
            evidenceParent,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ per-origin facts validation

    /// <summary>
    /// Validates the origin facts of the pass against the actual session. The Android route reuses the
    /// existing complete-check and bound-session guards unchanged; the EDL route re-anchors the historical
    /// backup - the directory must still hash to the accepted manifest SHA-256, the loaded toolchain must
    /// be the exact trusted builtin profile and hardware id, the client must carry its actual initial
    /// Sahara proof, and the bound identity must be the captured device. No synthetic device check result
    /// is ever created, and no historical firmware, lock state or loader-source build is compared to any
    /// current state.
    /// </summary>
    private static async Task RequireDeviceFactsAsync(
        MaintenanceDeviceFacts deviceFacts,
        EdlClient client,
        CancellationToken cancellationToken)
    {
        if (deviceFacts.AndroidCheck is not null)
        {
            RequireCompleteDeviceCheck(deviceFacts.AndroidCheck);
            RequireBoundSession(deviceFacts.AndroidCheck, client);
            return;
        }

        BootMaintenanceHistoricalIdentity history = deviceFacts.History!;

        // Re-read and re-hash the historical anchor: the selected directory must still be exactly the
        // accepted backup this pass was prepared from.
        BootMaintenanceHistoricalIdentity fresh = await ReadHistoricalIdentityAsync(
            history.DirectoryPath, cancellationToken).ConfigureAwait(false);

        if (!string.Equals(fresh.ManifestSha256, history.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the historical backup directory no longer hashes to the accepted "
                + "manifest SHA-256 of this pass.");
        }

        if (!ReferenceEquals(history.Profile, client.Toolchain.Profile))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the loaded EDL profile is not the exact trusted builtin profile "
                + "the historical backup was accepted against.");
        }

        if (!string.Equals(client.Toolchain.HardwareId, history.HardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the loaded toolchain hardware id is not the historical hardware id.");
        }

        if (!client.HasInitialSaharaProof)
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL client carries no initial Sahara proof for this session.");
        }

        EdlEntryResult binding = client.Binding
            ?? throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL client carries no binding.");

        if (binding.AndroidIdentity is null || binding.AndroidIdentity.Identity is null)
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the EDL binding carries no Android identity.");
        }

        DeviceIdentity bound = binding.AndroidIdentity.Identity;

        if (!string.Equals(bound.Serial, history.AndroidSerial, StringComparison.Ordinal)
            || !string.Equals(bound.Model, history.Model, StringComparison.Ordinal)
            || !string.Equals(
                binding.AndroidIdentity.SocSerial, history.SocSerialDecimal, StringComparison.Ordinal)
            || !string.Equals(binding.BusSerialHex, history.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                BindingMismatchCode + ": the bound EDL session is not the device the historical backup "
                + "captured.");
        }
    }

    // ------------------------------------------------------------------ evidence receipts

    /// <summary>
    /// One durable identity-context receipt: the actual origin, the historical path/hash when present, the
    /// currentFirmwareObserved flag (false on the EDL route - the saved firmware is labelled historical
    /// only), the actual misc capture/control hashes and slot, the client's actual Sahara proof state and
    /// the loaded toolchain profile/hardware id. No firmware is ever claimed as current here on the EDL
    /// route.
    /// </summary>
    private static void WriteIdentityContextReceipt(
        string evidenceDirectory,
        MaintenanceDeviceFacts deviceFacts,
        EdlClient client,
        string miscCaptureSha256,
        string miscControlSha256,
        string currentSlot)
    {
        WriteReceipt(evidenceDirectory, "identity-context", writer =>
        {
            writer.WriteString("kind", "identity-context");
            writer.WriteString("identityOrigin",
                deviceFacts.AndroidCheck is not null ? "android-live" : "historical-backup");

            if (deviceFacts.History is not null)
            {
                writer.WriteString("historyDirectoryPath", deviceFacts.History.DirectoryPath);
                writer.WriteString("historyManifestSha256", deviceFacts.History.ManifestSha256);
                writer.WriteString("historicalFirmwareDisplayId",
                    deviceFacts.History.HistoricalFirmware.DisplayId);
            }

            writer.WriteBoolean("currentFirmwareObserved", deviceFacts.History is null);
            writer.WriteString("miscSha256", miscCaptureSha256);
            writer.WriteString("miscControlSha256", miscControlSha256);
            writer.WriteString("currentSlot", currentSlot);
            writer.WriteBoolean("hasInitialSaharaProof", client.HasInitialSaharaProof);
            writer.WriteString("loadedProfileId", client.Toolchain.ProfileId);
            writer.WriteString("loadedHardwareId", client.Toolchain.HardwareId);
        });
    }

    // ------------------------------------------------------------------ repair fallback target

    /// <summary>
    /// Chooses the internal repair fallback target of the UI package filter, or returns null. This is a
    /// pure table scan of the freshly verified current backup - never a readiness, trust or AfterUpdate
    /// claim, never a TF or SD decision and never any I/O. The internal target is returned only when
    /// exactly one ARMADA_BOOT and one ARMADA_ROOT partition exist globally, both in LUN 0, with positive
    /// starts and counts inside the LUN 0 usable range and disk size, agreeing sector sizes, distinct
    /// non-empty partition UUIDs and non-overlapping ranges. Any doubt returns null; overflow returns
    /// null.
    /// </summary>
    public static InstallationTarget? GetRepairFallbackTarget(InternalBackupSet freshCurrentBackup)
    {
        ArgumentNullException.ThrowIfNull(freshCurrentBackup);

        if (!freshCurrentBackup.Geometries.TryGetValue(0, out EdlGeometry geometry)
            || !freshCurrentBackup.Tables.TryGetValue(0, out GptTable lun0Table))
        {
            return null;
        }

        GptPartition? armadaBoot = null;
        GptPartition? armadaRoot = null;

        foreach ((int lun, GptTable table) in freshCurrentBackup.Tables)
        {
            foreach (GptPartition partition in table.Partitions)
            {
                bool isBoot = string.Equals(partition.Name, "ARMADA_BOOT", StringComparison.Ordinal);
                bool isRoot = string.Equals(partition.Name, "ARMADA_ROOT", StringComparison.Ordinal);

                if (!isBoot && !isRoot)
                {
                    continue;
                }

                // Both candidates must live in LUN 0; a name match on any other LUN refuses the fallback.
                if (lun != 0)
                {
                    return null;
                }

                if (isBoot)
                {
                    if (armadaBoot is not null)
                    {
                        return null;
                    }

                    armadaBoot = partition;
                }
                else
                {
                    if (armadaRoot is not null)
                    {
                        return null;
                    }

                    armadaRoot = partition;
                }
            }
        }

        if (armadaBoot is null || armadaRoot is null
            || lun0Table.SectorSize != geometry.SectorSize
            || armadaBoot.StartSector <= 0
            || armadaRoot.StartSector <= 0
            || armadaBoot.SectorCount <= 0
            || armadaRoot.SectorCount <= 0)
        {
            return null;
        }

        // GptPartition.PartUuid is the raw GPT string: both must parse to distinct non-empty UUIDs.
        if (!Guid.TryParse(armadaBoot.PartUuid, out Guid bootUuid)
            || bootUuid == Guid.Empty
            || !Guid.TryParse(armadaRoot.PartUuid, out Guid rootUuid)
            || rootUuid == Guid.Empty
            || bootUuid == rootUuid)
        {
            return null;
        }

        long bootEndSector;
        long rootEndSector;
        try
        {
            checked
            {
                bootEndSector = armadaBoot.StartSector + armadaBoot.SectorCount - 1;
                rootEndSector = armadaRoot.StartSector + armadaRoot.SectorCount - 1;
            }
        }
        catch (OverflowException)
        {
            return null;
        }

        if (armadaBoot.StartSector < lun0Table.FirstUsableSector
            || bootEndSector > lun0Table.LastUsableSector
            || armadaRoot.StartSector < lun0Table.FirstUsableSector
            || rootEndSector > lun0Table.LastUsableSector
            || bootEndSector >= geometry.TotalSectors
            || rootEndSector >= geometry.TotalSectors
            || (armadaBoot.StartSector <= rootEndSector && armadaRoot.StartSector <= bootEndSector))
        {
            return null;
        }

        return InstallationTarget.Internal;
    }
}
