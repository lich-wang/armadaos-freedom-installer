using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// BM02: loading one historical, already verified <b>source</b> backup for boot maintenance.
/// <para>
/// This is the internally reusable counterpart of <see cref="OpenExistingAsync"/> for the original Android
/// capture: the source manifest may legitimately describe an older Android build than the one currently
/// bound, so the saved firmware is never compared with the live firmware and is never replaced by it. What
/// this loader does prove is that the selected directory is a verified capture of <i>this</i> device: the
/// same trusted model, profile, hardware id, serial, SoC serial and normalized EDL bus serial, the same six
/// LUN sector sizes, total sector counts and disk GUIDs as the captured current backup, and - per slot - the
/// exact current extent and, for the boot chain roles, the exact current bytes.
/// </para>
/// <para>
/// It is deliberately not a rollback authorization and not a "Ready" proof. It opens its own read leases on
/// the source manifest, its sidecar and every payload file, compares against the already captured current
/// backup only, and never probes, reads, writes or resets the target. Rechecking the live target against that
/// capture stays the backend's job before any write.
/// </para>
/// </summary>
public static partial class InternalInstallBackup
{
    /// <summary>
    /// Why a historical source is opened. <see cref="StockOriginal"/> is the existing loader that proves the
    /// whole per-slot chain byte-identical to the current capture; <see cref="ProjectTemplate"/> is the
    /// pre-OTA PROJECT template loader that keeps every identity, geometry, extent, presence and own-hash
    /// proof but lets the roles an OTA legitimately rewrote carry their old bytes against a fresh capture.
    /// </summary>
    private enum BootMaintenanceSourcePurpose
    {
        StockOriginal,
        ProjectTemplate,
    }

    /// <summary>The two A/B slots whose maintenance chain is compared role by role.</summary>
    private static readonly string[] BootMaintenanceSlots = { "a", "b" };

    /// <summary>
    /// The maintenance roles that must sit at the exact current target extent: a relocated or resized copy
    /// would be written over a partition it does not belong to.
    /// </summary>
    private static readonly string[] BootMaintenanceExtentRoles =
    {
        "boot", "vendor_boot", "init_boot", "abl", "xbl_config", "vbmeta", "vbmeta_system", "recovery",
    };

    /// <summary>
    /// The boot-chain roles whose source bytes must equal the current capture bytes, so an old source can
    /// never be combined with a changed current slot chain. Boot and the AVB metadata roles are excluded on
    /// purpose: the project install rewrote them, and their stock authenticity is verified by the caller.
    /// </summary>
    private static readonly string[] BootMaintenanceChainRoles =
    {
        "vendor_boot", "init_boot", "abl", "xbl_config", "xbl",
    };

    /// <summary>Chain roles that carry no required maintenance extent of their own.</summary>
    private static readonly string[] BootMaintenanceChainOnlyRoles = { "xbl" };

    /// <summary>
    /// Opens one historical, verified SOURCE backup that belongs to the device of <paramref name="currentBackup"/>.
    /// <para>
    /// <paramref name="backupDirectory"/> must be the absolute, already existing directory that itself holds
    /// <c>backup-manifest.json</c> and <c>backup-manifest.json.sha256</c>; a parent directory is never searched
    /// and nothing is discovered. Nothing is created, rewritten, upgraded or deleted, and no device read,
    /// write, reset or probe is issued: the comparison target is the already captured
    /// <paramref name="currentBackup"/>. The manifest, its sidecar and every payload file are leased read-only
    /// until the returned set is disposed; a failed or cancelled load releases every lease it opened.
    /// </para>
    /// <para>
    /// The source identity must be this device's: <see cref="EdlEntryResult"/> reference identity with the
    /// session, the trusted built-in profile of the loaded toolchain, a complete profile, the same profile id,
    /// model, full hardware id, Android serial, SoC serial decimal and normalized EDL bus serial, and a manifest
    /// that records its initial Sahara proof. The live Android firmware display id is deliberately not pinned to
    /// the profile's loader-source allowlist and is never compared with the saved source firmware.
    /// </para>
    /// <para>
    /// The returned set describes the SOURCE files only - its profile AndroidBuild, regions, tables, LUN0 layout
    /// and manifest hash are the source's - while <see cref="InternalBackupSet.Binding"/> is the actual session
    /// binding. It can therefore never be mistaken for a fresh rollback authorization or for the current
    /// capture itself.
    /// </para>
    /// </summary>
    /// <param name="client">The current EDL session; its exact <see cref="EdlClient.Binding"/> must be the set's binding.</param>
    /// <param name="currentBackup">The already captured current backup of that same binding; never disposed or modified.</param>
    /// <param name="backupDirectory">Absolute existing directory holding the source manifest, sidecar and payload files.</param>
    /// <param name="token">Cancellation; a cancelled load releases every lease it opened and touches nothing.</param>
    /// <returns>The source set, holding read leases on the source files until it is disposed.</returns>
    /// <exception cref="ArgumentNullException">A reference argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The directory is blank, not absolute or missing, or <paramref name="currentBackup"/> belongs to another session.
    /// </exception>
    /// <exception cref="IOException">The manifest, sidecar or a source payload file is missing or unreadable.</exception>
    /// <exception cref="InvalidDataException">The source is inconsistent, changed, or describes another device or chain.</exception>
    /// <exception cref="InvalidOperationException">The profile or the bound identity is not the trusted, complete one.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    internal static Task<InternalBackupSet> OpenBootMaintenanceOriginalAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string backupDirectory,
        CancellationToken token = default)
    {
        return OpenBootMaintenanceSourceAsync(
            client, currentBackup, backupDirectory, BootMaintenanceSourcePurpose.StockOriginal, token);
    }

    /// <summary>
    /// Opens one historical, verified PROJECT TEMPLATE source backup of the device of
    /// <paramref name="currentBackup"/>: the same loader, identity, manifest/sidecar, geometry, disk-GUID,
    /// extent, presence and own-hash proofs as <see cref="OpenBootMaintenanceOriginalAsync"/>, with only the
    /// per-role "source bytes equal current bytes" guard released so an OTA-era template may keep its
    /// legitimate old vendor_boot/init_boot/abl bytes while the current device runs the fresh build.
    /// <para>
    /// The template is never a rollback authorization, never a "Ready" proof and never an OEM source: the
    /// returned set describes the template files only and the caller still has to prove the live target.
    /// </para>
    /// </summary>
    /// <param name="client">The current EDL session; its exact <see cref="EdlClient.Binding"/> must be the set's binding.</param>
    /// <param name="currentBackup">The already captured current backup of that same binding; never disposed or modified.</param>
    /// <param name="backupDirectory">Absolute existing directory holding the template manifest, sidecar and payload files.</param>
    /// <param name="token">Cancellation; a cancelled load releases every lease it opened and touches nothing.</param>
    /// <returns>The template set, holding read leases on the template files until it is disposed.</returns>
    /// <exception cref="ArgumentNullException">A reference argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The directory is blank, not absolute or missing, or <paramref name="currentBackup"/> belongs to another session.
    /// </exception>
    /// <exception cref="IOException">The manifest, sidecar or a template payload file is missing or unreadable.</exception>
    /// <exception cref="InvalidDataException">The template is inconsistent, changed, or describes another device or chain.</exception>
    /// <exception cref="InvalidOperationException">The profile or the bound identity is not the trusted, complete one.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    internal static Task<InternalBackupSet> OpenBootMaintenanceProjectTemplateAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string backupDirectory,
        CancellationToken token = default)
    {
        return OpenBootMaintenanceSourceAsync(
            client, currentBackup, backupDirectory, BootMaintenanceSourcePurpose.ProjectTemplate, token);
    }

    /// <summary>
    /// The shared historical-source loader. Every guard is identical for both purposes except the per-role
    /// chain-byte comparison, which only <see cref="BootMaintenanceSourcePurpose.StockOriginal"/> enforces.
    /// </summary>
    private static async Task<InternalBackupSet> OpenBootMaintenanceSourceAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string backupDirectory,
        BootMaintenanceSourcePurpose purpose,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (currentBackup is null)
        {
            throw new ArgumentNullException(nameof(currentBackup));
        }

        if (backupDirectory is null)
        {
            throw new ArgumentNullException(nameof(backupDirectory));
        }

        // The captured current backup is the only comparison target, so it must be this very session's capture.
        if (!ReferenceEquals(currentBackup.Binding, client.Binding))
        {
            throw new ArgumentException(
                "The current backup does not belong to this EDL session; a historical source is only loaded " +
                "against the capture of the same binding and the same client.",
                nameof(currentBackup));
        }

        if (string.IsNullOrWhiteSpace(backupDirectory))
        {
            throw new ArgumentException(
                "An explicit source backup directory is required; there is no parent or temporary fallback.",
                nameof(backupDirectory));
        }

        if (!Path.IsPathFullyQualified(backupDirectory))
        {
            throw new ArgumentException(
                "The source backup directory must be an absolute path; no working-directory fallback is used.",
                nameof(backupDirectory));
        }

        string directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(backupDirectory));

        if (File.Exists(directory))
        {
            throw new IOException("The selected source backup path is a file, not a directory: '" + directory + "'.");
        }

        if (!Directory.Exists(directory))
        {
            throw new ArgumentException(
                "The selected source backup directory does not exist: '" + directory + "'.", nameof(backupDirectory));
        }

        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                "The selected source backup directory is a reparse point; a symlinked backup is not accepted.");
        }

        token.ThrowIfCancellationRequested();

        (ExistingState state, ExistingManifest manifest) = await Task
            .Run(() => BootMaintenanceLoadAsync(client, currentBackup, directory, purpose, token), token)
            .ConfigureAwait(false);

        try
        {
            // The metadata is the source's own authentic profile and geometry; only the binding is the live one.
            return new InternalBackupSet(
                client.Binding,
                directory,
                state.ManifestPath,
                state.ManifestSha256,
                manifest.ProfileId,
                manifest.Model,
                manifest.AndroidBuild,
                manifest.HardwareId,
                CopyGeometries(state.Geometries),
                CopyTables(state.Tables),
                state.Regions,
                state.Lun0Layout,
                state.Locks);
        }
        catch
        {
            state.DisposeLeases();
            throw;
        }
    }

    // ------------------------------------------------------------------ load and compare

    private static async Task<(ExistingState State, ExistingManifest Manifest)> BootMaintenanceLoadAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string directory,
        BootMaintenanceSourcePurpose purpose,
        CancellationToken token)
    {
        ExistingState state = new();

        try
        {
            token.ThrowIfCancellationRequested();

            // The session guard is proved from the trusted toolchain and binding, never from the manifest.
            string expectedBusSerialHex = BootMaintenanceRequireTrustedSession(client);

            InternalInstallBackupRoles roles = InternalInstallBackupRoles.ForModel(client.Toolchain.Model);

            string manifestPath = Path.Combine(directory, ManifestFileName);
            ExistingRequireRegularFile(manifestPath, "source backup manifest");
            string sidecarPath = manifestPath + SidecarSuffix;
            ExistingRequireRegularFile(sidecarPath, "source backup manifest sidecar");

            token.ThrowIfCancellationRequested();

            (string manifestSha, FileStream manifestStream) = await OpenHashedSharedAsync(manifestPath, token)
                .ConfigureAwait(false);
            state.Locks.Add(manifestStream);
            state.ManifestPath = manifestPath;
            state.ManifestSha256 = manifestSha;

            if (manifestStream.Length <= 0 || manifestStream.Length > ExistingManifestMaxBytes)
            {
                throw new InvalidDataException(
                    "The source backup manifest is " + manifestStream.Length +
                    " bytes; it cannot be the verified manifest.");
            }

            if (!ExistingIsSha256Hex(manifestSha))
            {
                throw new InvalidDataException("The source backup manifest did not hash to a SHA-256 value.");
            }

            FileStream sidecarStream = OpenSidecarVerified(sidecarPath, manifestSha);
            state.Locks.Add(sidecarStream);
            if (sidecarStream.Length <= 0 || sidecarStream.Length > 256)
            {
                throw new InvalidDataException("The source backup manifest sidecar does not carry one SHA-256 line.");
            }

            byte[] manifestBytes = ExistingReadHeld(manifestStream, manifestStream.Length, token);
            using JsonDocument document = ExistingParseJson(manifestBytes);
            ExistingManifest manifest = ExistingParseManifest(document.RootElement, roles, token);

            // The parsed manifest's whole role set selects the exact contract, optional efisp included.
            roles = ExistingSelectRoles(roles, manifest.Files);

            BootMaintenanceValidateSourceIdentity(client, manifest, expectedBusSerialHex);

            ExistingBuildGeometries(manifest, state.Geometries);
            BootMaintenanceRequireSameGeometry(state.Geometries, currentBackup);
            ExistingOpenPayloadLeases(manifest, state, directory, roles, token);

            foreach (int lun in LunOrder)
            {
                token.ThrowIfCancellationRequested();

                ExistingFile primary = state.ByRole["gpt_lun" + lun + "_primary"];
                ExistingFile backup = state.ByRole["gpt_lun" + lun + "_backup"];

                byte[] primaryBytes = ExistingReadHeld(primary.Stream!, primary.Length, token);
                byte[] backupBytes = ExistingReadHeld(backup.Stream!, backup.Length, token);

                state.Tables.Add(lun, ParseTable(primaryBytes, backupBytes, state.Geometries[lun]));
            }

            ExistingValidateDeclaredTables(manifest, state.Tables, state.Geometries);
            BootMaintenanceRequireSameDiskGuids(state.Tables, currentBackup);

            IReadOnlyDictionary<string, PartitionTarget> targets = ResolveTargets(
                state.Tables, state.Geometries, roles);
            state.Regions = ExistingBuildRegions(manifest, targets, state.Geometries, directory, roles);

            token.ThrowIfCancellationRequested();

            // Every source payload is re-hashed against the source manifest exactly as the current loader does.
            InternalInstallArtifacts.VerifyCapturedInputs(
                state.Regions, state.Geometries, state.Tables, client.Toolchain.Model, token);

            BootMaintenanceRequireSameMaintenanceChain(state.Regions, currentBackup, purpose);

            state.Lun0Layout = BuildLun0Layout(state.Tables[0], state.Geometries[0]);
            return (state, manifest);
        }
        catch
        {
            state.DisposeLeases();
            throw;
        }
    }

    // ------------------------------------------------------------------ session and identity guards

    /// <summary>
    /// Proves the live session from the trusted toolchain and binding only, and returns the expected 8-digit
    /// EDL bus serial. The live Android firmware display id is required to be present but is never matched
    /// against the profile's loader-source allowlist, because that list pins the bundled loader archive, not
    /// the build the device currently boots.
    /// </summary>
    private static string BootMaintenanceRequireTrustedSession(EdlClient client)
    {
        EdlDeviceProfile profile = client.Toolchain.Profile;
        if (profile is null)
        {
            throw new InvalidOperationException("The loaded toolchain carries no trusted EDL profile.");
        }

        if (!ReferenceEquals(EdlDeviceProfiles.FindById(profile.ProfileId), profile))
        {
            throw new InvalidOperationException(
                "The loaded EDL profile '" + profile.ProfileId + "' is not the trusted built-in instance.");
        }

        profile.RequireComplete();

        AndroidMaintenanceIdentity? android = client.Binding.AndroidIdentity;
        if (android is null)
        {
            throw new InvalidOperationException("The EDL binding carries no Android maintenance identity.");
        }

        DeviceIdentity? identity = android.Identity;
        if (identity is null)
        {
            throw new InvalidOperationException("The EDL binding carries no Android device identity.");
        }

        ExistingRequireText(identity.Serial, "Android serial");
        ExistingRequireText(identity.Model, "Android model");
        ExistingRequireText(android.SocSerial, "Android SoC serial");
        ExistingRequireText(client.Binding.BusSerialHex, "EDL bus serial");

        if (!profile.SupportsIdentity(identity))
        {
            throw new InvalidOperationException(
                "The trusted EDL profile '" + profile.ProfileId + "' does not support the bound identity.");
        }

        if (!string.Equals(client.Toolchain.ProfileId, profile.ProfileId, StringComparison.Ordinal)
            || !string.Equals(client.Toolchain.Model, profile.Model, StringComparison.Ordinal)
            || !string.Equals(client.Toolchain.Model, identity.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The loaded toolchain profile and the bound identity do not describe the same device.");
        }

        if (!string.Equals(client.Toolchain.HardwareId, profile.FullHardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The loaded toolchain hardware id is not the trusted profile hardware id.");
        }

        if (!client.HasInitialSaharaProof)
        {
            throw new InvalidOperationException(
                "The EDL session has no proven initial Sahara identity; a historical source is only loaded " +
                "for a session that already proved the loader it was entered with.");
        }

        string expectedBusSerial = ExistingExpectedBusSerial(android.SocSerial);
        string? boundBusSerial = BootMaintenanceNormalizeBus(client.Binding.BusSerialHex);
        if (!string.Equals(boundBusSerial, expectedBusSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The bound bus serial does not match the serial derived from the SoC serial.");
        }

        return expectedBusSerial;
    }

    /// <summary>
    /// Compares the manifest's device identity with the live binding strictly and does not compare any firmware
    /// value: a historical source may name an older Android build than the one currently booted, and its own
    /// build string stays the source's fact.
    /// </summary>
    private static void BootMaintenanceValidateSourceIdentity(
        EdlClient client,
        ExistingManifest manifest,
        string expectedBusSerialHex)
    {
        if (!string.Equals(manifest.ProfileId, client.Toolchain.ProfileId, StringComparison.Ordinal)
            || !string.Equals(manifest.Model, client.Toolchain.Model, StringComparison.Ordinal)
            || !string.Equals(manifest.HardwareId, client.Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The saved source profile does not match the currently loaded toolchain profile.");
        }

        AndroidMaintenanceIdentity android = client.Binding.AndroidIdentity!;
        DeviceIdentity identity = android.Identity!;

        if (!string.Equals(manifest.Identity.Model, identity.Model, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved source Android model does not match the current device.");
        }

        if (!string.Equals(manifest.Identity.AndroidSerial, identity.Serial, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved source Android serial does not match the current device.");
        }

        if (!string.Equals(manifest.Identity.SocSerialDecimal, android.SocSerial, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved source SoC serial does not match the current device.");
        }

        string? savedBusSerial = BootMaintenanceNormalizeBus(manifest.Identity.BusSerialHex);
        string? liveBusSerial = BootMaintenanceNormalizeBus(client.Binding.BusSerialHex);
        if (savedBusSerial is null
            || liveBusSerial is null
            || !string.Equals(savedBusSerial, liveBusSerial, StringComparison.Ordinal)
            || !string.Equals(liveBusSerial, expectedBusSerialHex, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved source EDL bus serial does not match the current device.");
        }

        if (!manifest.HasInitialSaharaProof)
        {
            throw new InvalidDataException(
                "The source manifest does not record the initial Sahara proof it was taken with.");
        }
    }

    /// <summary>Canonical 8-digit uppercase bus serial, or null when the value is not an 8-digit hex serial.</summary>
    private static string? BootMaintenanceNormalizeBus(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value!.Length != 8)
        {
            return null;
        }

        foreach (char character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                return null;
            }
        }

        return value.ToUpperInvariant();
    }

    // ------------------------------------------------------------------ source versus current

    private static void BootMaintenanceRequireSameGeometry(
        IReadOnlyDictionary<int, EdlGeometry> sourceGeometries,
        InternalBackupSet currentBackup)
    {
        for (int lun = 0; lun < 6; lun++)
        {
            EdlGeometry source = sourceGeometries[lun];

            if (!currentBackup.Geometries.TryGetValue(lun, out EdlGeometry current))
            {
                throw new InvalidDataException("The current backup does not describe LUN" + lun + ".");
            }

            if (source.SectorSize != current.SectorSize || source.TotalSectors != current.TotalSectors)
            {
                throw new InvalidDataException(
                    "The saved source LUN" + lun + " describes " + source.SectorSize + " byte sectors and " +
                    source.TotalSectors + " sectors, not the current " + current.SectorSize + " byte sectors and " +
                    current.TotalSectors + " sectors.");
            }
        }
    }

    /// <summary>
    /// Compares the six disk GUIDs. The per-LUN source fingerprint and the LUN0 userdata geometry are
    /// deliberately not compared: a historical source may predate the Linux resize.
    /// </summary>
    private static void BootMaintenanceRequireSameDiskGuids(
        IReadOnlyDictionary<int, GptTable> sourceTables,
        InternalBackupSet currentBackup)
    {
        for (int lun = 0; lun < 6; lun++)
        {
            if (!currentBackup.Tables.TryGetValue(lun, out GptTable current))
            {
                throw new InvalidDataException("The current backup does not describe the GPT of LUN" + lun + ".");
            }

            if (!string.Equals(sourceTables[lun].DiskGuid, current.DiskGuid, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The saved source LUN" + lun + " belongs to a different disk than the current backup.");
            }
        }
    }

    /// <summary>
    /// Compares both slots of the maintenance chain against the current capture. Every role must cover the
    /// exact current extent, and for <see cref="BootMaintenanceSourcePurpose.StockOriginal"/> every
    /// boot-chain role must also carry the exact current bytes, so an old source cannot be written over a
    /// changed current slot - including slot B while slot A still matches. The PROJECT template purpose
    /// keeps every extent and presence proof but lets the OTA-rewritten roles keep their historical bytes.
    /// </summary>
    private static void BootMaintenanceRequireSameMaintenanceChain(
        IReadOnlyDictionary<string, EdlCapturedRegion> sourceRegions,
        InternalBackupSet currentBackup,
        BootMaintenanceSourcePurpose purpose)
    {
        foreach (string slot in BootMaintenanceSlots)
        {
            foreach (string stem in BootMaintenanceExtentRoles)
            {
                BootMaintenanceCompareRole(stem + "_" + slot, true, sourceRegions, currentBackup, purpose);
            }

            foreach (string stem in BootMaintenanceChainOnlyRoles)
            {
                BootMaintenanceCompareRole(stem + "_" + slot, false, sourceRegions, currentBackup, purpose);
            }
        }
    }

    private static void BootMaintenanceCompareRole(
        string role,
        bool requireExtent,
        IReadOnlyDictionary<string, EdlCapturedRegion> sourceRegions,
        InternalBackupSet currentBackup,
        BootMaintenanceSourcePurpose purpose)
    {
        if (!sourceRegions.TryGetValue(role, out EdlCapturedRegion source))
        {
            throw new InvalidDataException(
                "The historical source does not carry the required '" + role + "' role.");
        }

        if (!currentBackup.Files.TryGetValue(role, out EdlCapturedRegion current))
        {
            throw new InvalidDataException(
                "The current backup does not carry the required '" + role + "' role.");
        }

        if (requireExtent
            && (source.Lun != current.Lun
                || source.StartSector != current.StartSector
                || source.SectorCount != current.SectorCount
                || source.SectorSize != current.SectorSize
                || source.Length != current.Length
                || !ExistingSameUuid(source.PartUuid, current.PartUuid)))
        {
            throw new InvalidDataException(
                "The historical source role '" + role + "' covers LUN" + source.Lun + " " +
                source.StartSector + "+" + source.SectorCount + " of " + source.SectorSize + " byte " +
                "sectors (" + source.Length + " bytes), not the current LUN" + current.Lun + " " +
                current.StartSector + "+" + current.SectorCount + " of " + current.SectorSize +
                " byte sectors (" + current.Length + " bytes).");
        }

        if (purpose == BootMaintenanceSourcePurpose.StockOriginal
            && Array.IndexOf(BootMaintenanceChainRoles, BootMaintenanceStemOf(role)) >= 0
            && !string.Equals(source.Sha256, current.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The historical source role '" + role + "' carries different bytes than the current " +
                "capture; the boot chain of this slot changed and cannot be restored from this source.");
        }
    }

    /// <summary>The role stem of <c>&lt;stem&gt;_a</c> / <c>&lt;stem&gt;_b</c>, used for the chain-role lookup.</summary>
    private static string BootMaintenanceStemOf(string role)
    {
        int separator = role.LastIndexOf('_');
        return separator > 0 ? role.Substring(0, separator) : role;
    }
}
