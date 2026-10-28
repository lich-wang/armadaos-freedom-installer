using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// EB001: opening an existing, already verified model-specific backup instead of taking a new device capture.
/// <para>
/// The second half of <see cref="InternalInstallBackup"/>. It only reads the directory the user selected: the
/// durable <c>backup-manifest.json</c>, its <c>.sha256</c> sidecar and exactly the payload files the model
/// contract names (52 on TB322FC, 48 on TB323FU). Nothing is created, rewritten, upgraded or deleted, and no
/// device read, write or reset is issued.
/// </para>
/// <para>
/// A successful load is a statement about the selected files, the currently bound Android identity and the
/// currently probed LUN geometry only. It is never an installation approval: the later Context still performs
/// its own fresh reads of the actual GPT, boot and misc content and refuses any mismatch, and a reused PC backup
/// is not a new device capture.
/// </para>
/// </summary>
public static partial class InternalInstallBackup
{
    private const int ExistingManifestMaxBytes = 8 * 1024 * 1024;

    private static readonly string[] ExistingManifestProperties =
    {
        "schemaVersion", "status", "userDataIncluded", "superIncluded", "profile", "identity", "luns", "files",
    };

    private static readonly string[] ExistingProfileProperties =
    {
        "profileId", "model", "androidBuild", "hardwareId",
    };

    private static readonly string[] ExistingIdentityProperties =
    {
        "androidSerial", "socSerialDecimal", "busSerialHex", "model", "firmware", "hasInitialSaharaProof",
    };

    private static readonly string[] ExistingFirmwareProperties =
    {
        "displayId", "buildFingerprint", "androidRelease", "securityPatch", "androidReportedBootloaderState",
    };

    private static readonly string[] ExistingLunProperties =
    {
        "lun", "sectorSize", "totalSectors", "diskGuid", "sourceFingerprint", "partitions",
    };

    private static readonly string[] ExistingPartitionProperties =
    {
        "number", "name", "typeGuid", "partUuid", "startSector", "sectorCount", "attributes",
    };

    private static readonly string[] ExistingFileProperties =
    {
        "role", "lun", "startSector", "sectorCount", "sectorSize", "partUuid", "relativePath", "length", "sha256",
    };

    private static readonly string[] ExistingBootloaderStates =
    {
        "Unknown", "Locked", "Unlocked",
    };

    /// <summary>
    /// Opens one existing, verified, model-specific internal-install backup that the user selected explicitly.
    /// <para>
    /// <paramref name="backupDirectory"/> must be the absolute, already existing directory that itself contains
    /// <c>backup-manifest.json</c> and <c>backup-manifest.json.sha256</c>; a parent directory is never searched and
    /// nothing is discovered. The manifest, its sidecar and every payload file of the model contract are opened
    /// read-only with <see cref="FileShare.Read"/> and stay leased until the returned set is disposed; a failed or
    /// cancelled load releases every lease again. No backup file or manifest is ever created, rewritten or
    /// upgraded, and the client, its toolchain and the device are never disposed or reset here.
    /// </para>
    /// <para>
    /// The load proves only that the selected payload files match their manifest, that the manifest's saved identity
    /// and full firmware match the current binding and loaded trusted profile, that the saved GPT tables match the
    /// raw captured GPT bytes, and that six read-only probes still report the same geometry and bus serial. It is not
    /// an automatic installation approval: the later Context still repeats its own fresh GPT, boot and misc reads
    /// and refuses any mismatch, and a reused PC backup is explicitly not a new device capture.
    /// </para>
    /// <para>
    /// Progress uses only the existing <c>verifying</c> and <c>complete</c> stage keys. <c>complete</c> is reported
    /// once, after every file, table, identity and geometry check succeeded.
    /// </para>
    /// </summary>
    /// <param name="client">The current EDL session; its exact <see cref="EdlClient.Binding"/> becomes the set's binding.</param>
    /// <param name="backupDirectory">Absolute existing directory holding the manifest, sidecar and the model's payload files.</param>
    /// <param name="progress">Optional progress sink; null is allowed.</param>
    /// <param name="token">Cancellation; a cancelled load releases every lease it opened.</param>
    /// <returns>The immutable set, holding read leases on the selected files until it is disposed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="client"/> or <paramref name="backupDirectory"/> is null.</exception>
    /// <exception cref="ArgumentException">The directory is blank, not absolute or does not exist.</exception>
    /// <exception cref="IOException">The manifest, sidecar or a payload file is missing or unreadable.</exception>
    /// <exception cref="InvalidDataException">The backup is inconsistent with the manifest, its own bytes or this device.</exception>
    /// <exception cref="InvalidOperationException">The profile or current binding is not the trusted, complete and matching one.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static async Task<InternalBackupSet> OpenExistingAsync(
        EdlClient client,
        string backupDirectory,
        IProgress<InternalBackupProgress>? progress = null,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (backupDirectory is null)
        {
            throw new ArgumentNullException(nameof(backupDirectory));
        }

        if (string.IsNullOrWhiteSpace(backupDirectory))
        {
            throw new ArgumentException(
                "An explicit backup directory is required; there is no parent or temporary fallback.",
                nameof(backupDirectory));
        }

        if (!Path.IsPathFullyQualified(backupDirectory))
        {
            throw new ArgumentException(
                "The backup directory must be an absolute path; no working-directory fallback is used.",
                nameof(backupDirectory));
        }

        string directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(backupDirectory));

        if (File.Exists(directory))
        {
            throw new IOException("The selected backup path is a file, not a directory: '" + directory + "'.");
        }

        if (!Directory.Exists(directory))
        {
            throw new ArgumentException(
                "The selected backup directory does not exist: '" + directory + "'.", nameof(backupDirectory));
        }

        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                "The selected backup directory is a reparse point; a symlinked backup is not accepted.");
        }

        token.ThrowIfCancellationRequested();

        ExistingState state = await Task
            .Run(() => ExistingLoadAsync(client, directory, progress, token), token)
            .ConfigureAwait(false);

        try
        {
            Dictionary<int, EdlGeometry> geometries = new();

            for (int lun = 0; lun < 6; lun++)
            {
                token.ThrowIfCancellationRequested();

                EdlProbeEvidence probe = await client
                    .ProbeAsync(lun, lun == 0 && !client.HasInitialSaharaProof, token)
                    .ConfigureAwait(false);

                EdlGeometry actual = RequireGeometry(probe, lun);
                EdlGeometry saved = state.Geometries[lun];

                if (actual.SectorSize != saved.SectorSize || actual.TotalSectors != saved.TotalSectors)
                {
                    throw new InvalidDataException(
                        "LUN" + lun + " now reports " + actual.SectorSize + " byte sectors and " +
                        actual.TotalSectors + " sectors, not the saved " + saved.SectorSize + " and " +
                        saved.TotalSectors + ".");
                }

                if (!string.Equals(probe.BusSerialHex, state.ExpectedBusSerialHex, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "The probe of LUN" + lun + " selected bus serial '" + (probe.BusSerialHex ?? "<none>") +
                        "', not the expected '" + state.ExpectedBusSerialHex + "'.");
                }

                geometries.Add(lun, actual);
            }

            InternalBackupSet set = new(
                client.Binding,
                directory,
                state.ManifestPath,
                state.ManifestSha256,
                client.Toolchain.ProfileId,
                client.Toolchain.Model,
                client.Binding.AndroidIdentity.Identity.Firmware!.DisplayId!,
                client.Toolchain.HardwareId,
                CopyGeometries(geometries),
                CopyTables(state.Tables),
                state.Regions,
                BuildLun0Layout(state.Tables[0], geometries[0]),
                state.Locks);

            InternalInstallBackupRoles contract = InternalInstallBackupRoles
                .ForModel(client.Toolchain.Model)
                .ForCapturedRoles(state.Regions.Keys);

            progress?.Report(new InternalBackupProgress(
                CompleteStage,
                null,
                state.TotalBytes,
                state.TotalBytes,
                contract.TotalFileCount,
                contract.TotalFileCount));

            return set;
        }
        catch
        {
            state.DisposeLeases();
            throw;
        }
    }

    // ------------------------------------------------------------------ load and validate

    private static async Task<ExistingState> ExistingLoadAsync(
        EdlClient client,
        string directory,
        IProgress<InternalBackupProgress>? progress,
        CancellationToken token,
        bool requireCurrentFirmware = true)
    {
        ExistingState state = new();

        try
        {
            token.ThrowIfCancellationRequested();

            // The contract is chosen from the trusted loaded toolchain model, never from the manifest.
            InternalInstallBackupRoles roles = InternalInstallBackupRoles.ForModel(client.Toolchain.Model);

            string manifestPath = Path.Combine(directory, ManifestFileName);
            ExistingRequireRegularFile(manifestPath, "backup manifest");
            string sidecarPath = manifestPath + SidecarSuffix;
            ExistingRequireRegularFile(sidecarPath, "backup manifest sidecar");

            token.ThrowIfCancellationRequested();

            (string manifestSha, FileStream manifestStream) = await OpenHashedSharedAsync(manifestPath, token)
                .ConfigureAwait(false);
            state.Locks.Add(manifestStream);
            state.ManifestPath = manifestPath;
            state.ManifestSha256 = manifestSha;

            if (manifestStream.Length <= 0 || manifestStream.Length > ExistingManifestMaxBytes)
            {
                throw new InvalidDataException(
                    "The backup manifest is " + manifestStream.Length + " bytes; it cannot be the verified manifest.");
            }

            if (!ExistingIsSha256Hex(manifestSha))
            {
                throw new InvalidDataException("The backup manifest did not hash to a SHA-256 value.");
            }

            FileStream sidecarStream = OpenSidecarVerified(sidecarPath, manifestSha);
            state.Locks.Add(sidecarStream);
            if (sidecarStream.Length <= 0 || sidecarStream.Length > 256)
            {
                throw new InvalidDataException("The backup manifest sidecar does not carry one SHA-256 line.");
            }

            byte[] manifestBytes = ExistingReadHeld(manifestStream, manifestStream.Length, token);
            using JsonDocument document = ExistingParseJson(manifestBytes);
            ExistingManifest manifest = ExistingParseManifest(document.RootElement, roles, token);

            // The parsed manifest's whole role set selects the exact contract (baseline, or baseline plus the
            // optional efisp), so every later lease, target, region and progress check uses the selected roles.
            roles = ExistingSelectRoles(roles, manifest.Files);

            ExistingValidateProfileAndIdentity(client, manifest, state, requireCurrentFirmware);
            ExistingBuildGeometries(manifest, state.Geometries);
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

            IReadOnlyDictionary<string, PartitionTarget> targets = ResolveTargets(state.Tables, state.Geometries, roles);
            state.Regions = ExistingBuildRegions(manifest, targets, state.Geometries, directory, roles);
            state.TotalBytes = ExistingTotalBytes(manifest);

            progress?.Report(new InternalBackupProgress(
                VerifyingStage, null, 0, state.TotalBytes, 0, roles.TotalFileCount));

            token.ThrowIfCancellationRequested();

            InternalInstallArtifacts.VerifyCapturedInputs(state.Regions, state.Geometries, state.Tables, client.Toolchain.Model, token);

            state.Lun0Layout = BuildLun0Layout(state.Tables[0], state.Geometries[0]);
            return state;
        }
        catch
        {
            state.DisposeLeases();
            throw;
        }
    }

    private static void ExistingOpenPayloadLeases(
        ExistingManifest manifest,
        ExistingState state,
        string directory,
        InternalInstallBackupRoles roles,
        CancellationToken token)
    {
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);

        foreach (ExistingFile file in manifest.Files)
        {
            token.ThrowIfCancellationRequested();

            int expectedLun = ExistingExpectedLun(file.Role, roles);
            if (file.Lun != expectedLun)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' claims LUN" + file.Lun + ", not the required LUN" +
                    expectedLun + ".");
            }

            EdlGeometry geometry = state.Geometries[file.Lun];
            if (file.SectorSize != geometry.SectorSize)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' uses " + file.SectorSize + " byte sectors, not " +
                    geometry.SectorSize + ".");
            }

            if (file.StartSector < 0 || file.SectorCount <= 0)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' declares an empty or negative sector range.");
            }

            long end;
            long expectedLength;
            try
            {
                end = checked(file.StartSector + file.SectorCount);
                expectedLength = checked(file.SectorCount * (long)file.SectorSize);
            }
            catch (OverflowException)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' declares an unrepresentable sector range.");
            }

            if (end > geometry.TotalSectors)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' extends beyond the saved LUN" + file.Lun + ".");
            }

            if (file.Length != expectedLength)
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' declares " + file.Length + " bytes for " +
                    file.SectorCount + " sectors of " + file.SectorSize + " bytes.");
            }

            if (!ExistingIsSha256Hex(file.Sha256))
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' does not declare a SHA-256 value.");
            }

            bool isGpt = file.Role.StartsWith("gpt_lun", StringComparison.Ordinal);
            if (isGpt)
            {
                if (file.SectorCount != GptSectors)
                {
                    throw new InvalidDataException(
                        "The GPT role '" + file.Role + "' must capture exactly " + GptSectors + " sectors.");
                }

                if (file.StartSector != 0 && file.StartSector != geometry.TotalSectors - GptSectors)
                {
                    throw new InvalidDataException(
                        "The GPT role '" + file.Role + "' is not anchored at the head or tail of LUN" + file.Lun + ".");
                }

                if (file.PartUuid is not null)
                {
                    throw new InvalidDataException(
                        "The GPT role '" + file.Role + "' must not claim a partition UUID.");
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(file.PartUuid))
                {
                    throw new InvalidDataException(
                        "The partition role '" + file.Role + "' carries no partition UUID.");
                }
            }

            file.FilePath = ExistingResolvePayloadPath(directory, file.Role, file.RelativePath);
            ExistingRequireRegularFile(file.FilePath, "backup payload '" + file.Role + "'");

            if (!paths.Add(file.FilePath))
            {
                throw new InvalidDataException(
                    "Two backup roles resolve to the same payload path '" + file.FilePath + "'.");
            }

            FileStream stream = new(
                file.FilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                FileBufferBytes,
                FileOptions.SequentialScan);

            state.Locks.Add(stream);

            if (stream.Length != file.Length)
            {
                throw new InvalidDataException(
                    "The payload of role '" + file.Role + "' is " + stream.Length + " bytes, not the declared " +
                    file.Length + ".");
            }

            file.Stream = stream;
            state.ByRole.Add(file.Role, file);
        }

        if (state.ByRole.Count != roles.TotalFileCount)
        {
            throw new InvalidDataException(
                "The backup declares " + state.ByRole.Count + " distinct payload roles; exactly " +
                roles.TotalFileCount + " are required.");
        }

        for (int lun = 0; lun < 6; lun++)
        {
            if (!state.ByRole.ContainsKey("gpt_lun" + lun + "_primary") ||
                !state.ByRole.ContainsKey("gpt_lun" + lun + "_backup"))
            {
                throw new InvalidDataException("The backup is missing the GPT pair of LUN" + lun + ".");
            }
        }

        foreach ((int lun, string name) in roles.Partitions)
        {
            if (!state.ByRole.ContainsKey(name))
            {
                throw new InvalidDataException(
                    "The backup is missing the required '" + name + "' partition of LUN" + lun + ".");
            }
        }
    }

    private static IReadOnlyDictionary<string, EdlCapturedRegion> ExistingBuildRegions(
        ExistingManifest manifest,
        IReadOnlyDictionary<string, PartitionTarget> targets,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        string directory,
        InternalInstallBackupRoles roles)
    {
        List<ManifestFileEntry> entries = new(roles.TotalFileCount);

        foreach (ExistingFile file in manifest.Files)
        {
            int expectedLun;
            long expectedStart;
            long expectedCount;
            string? expectedUuid;

            if (ExistingTryParseGptRole(file.Role, out int gptLun, out bool primary))
            {
                EdlGeometry geometry = geometries[gptLun];
                expectedLun = gptLun;
                expectedStart = primary ? 0 : geometry.TotalSectors - GptSectors;
                expectedCount = GptSectors;
                expectedUuid = null;
            }
            else
            {
                if (!targets.TryGetValue(file.Role, out PartitionTarget target))
                {
                    throw new InvalidDataException(
                        "The backup file '" + file.Role + "' is not one of the required partitions.");
                }

                expectedLun = target.Lun;
                expectedStart = target.Partition.StartSector;
                expectedCount = target.Partition.SectorCount;
                expectedUuid = target.Partition.PartUuid;
            }

            if (file.Lun != expectedLun
                || file.StartSector != expectedStart
                || file.SectorCount != expectedCount
                || !ExistingSameUuid(file.PartUuid, expectedUuid))
            {
                throw new InvalidDataException(
                    "The backup file '" + file.Role + "' does not cover the region its own role names.");
            }

            entries.Add(new ManifestFileEntry(
                file.Role,
                expectedLun,
                expectedStart,
                expectedCount,
                geometries[expectedLun].SectorSize,
                expectedUuid,
                file.RelativePath,
                file.Length,
                file.Sha256));
        }

        IReadOnlyDictionary<string, EdlCapturedRegion> regions = BuildRegions(entries, directory);

        foreach ((int lun, string name) in roles.Partitions)
        {
            if (!regions.ContainsKey(name))
            {
                throw new InvalidDataException(
                    "The backup does not cover the required '" + name + "' partition of LUN" + lun + ".");
            }
        }

        for (int lun = 0; lun < 6; lun++)
        {
            if (!regions.ContainsKey("gpt_lun" + lun + "_primary") ||
                !regions.ContainsKey("gpt_lun" + lun + "_backup"))
            {
                throw new InvalidDataException("The backup does not cover the GPT pair of LUN" + lun + ".");
            }
        }

        return regions;
    }

    private static long ExistingTotalBytes(ExistingManifest manifest)
    {
        long total = 0;
        foreach (ExistingFile file in manifest.Files)
        {
            total = CheckedAdd(total, file.Length, "The existing backup byte total overflows.");
        }

        return total;
    }

    // ------------------------------------------------------------------ identity and profile

    private static void ExistingValidateProfileAndIdentity(
        EdlClient client,
        ExistingManifest manifest,
        ExistingState state,
        bool requireCurrentFirmware = true)
    {
        EdlDeviceProfile profile = client.Toolchain.Profile;
        if (profile is null)
        {
            throw new InvalidOperationException("The loaded toolchain carries no trusted EDL profile.");
        }

        RequireProfile(new ProfileSummary(
            client.Toolchain.ProfileId,
            client.Toolchain.Model,
            client.Binding.AndroidIdentity?.Identity?.Firmware?.DisplayId ?? string.Empty,
            client.Toolchain.HardwareId));

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

        FirmwareSnapshot? firmware = identity.Firmware;
        if (firmware is null)
        {
            throw new InvalidOperationException(
                "The EDL binding carries no full firmware snapshot; the existing backup cannot be bound.");
        }

        ExistingRequireText(identity.Serial, "Android serial");
        ExistingRequireText(identity.Model, "Android model");
        ExistingRequireText(android.SocSerial, "Android SoC serial");
        ExistingRequireText(client.Binding.BusSerialHex, "EDL bus serial");
        ExistingRequireText(firmware.DisplayId, "firmware display id");
        ExistingRequireText(firmware.BuildFingerprint, "firmware build fingerprint");
        ExistingRequireText(firmware.AndroidRelease, "firmware Android release");
        ExistingRequireText(firmware.SecurityPatch, "firmware security patch");

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

        bool allowedBuild = false;
        foreach (string allowed in profile.AllowedDisplayIds)
        {
            if (string.Equals(client.Toolchain.AndroidBuild, allowed, StringComparison.Ordinal))
            {
                allowedBuild = true;
                break;
            }
        }

        if (!allowedBuild)
        {
            throw new InvalidOperationException(
                "The loaded Android build is not an allowed display id of the trusted profile.");
        }

        string expectedBusSerial = ExistingExpectedBusSerial(android.SocSerial);
        if (!string.Equals(client.Binding.BusSerialHex, expectedBusSerial, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The bound bus serial does not match the serial derived from the SoC serial.");
        }

        if (!string.Equals(manifest.ProfileId, client.Toolchain.ProfileId, StringComparison.Ordinal)
            || !string.Equals(manifest.Model, client.Toolchain.Model, StringComparison.Ordinal)
            || !string.Equals(manifest.HardwareId, client.Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase)
            || (requireCurrentFirmware
                && !string.Equals(manifest.AndroidBuild, firmware.DisplayId, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "The saved backup profile does not match the currently loaded toolchain profile.");
        }

        if (!requireCurrentFirmware)
        {
            // The uninstall reader accepts a backup whose firmware is no longer installed, but the saved
            // backup itself must stay internally consistent with a complete saved firmware identity.
            if (!string.Equals(manifest.AndroidBuild, manifest.Identity.Firmware.DisplayId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The saved backup profile does not match its own saved firmware identity.");
            }

            ExistingRequireText(manifest.Identity.Firmware.DisplayId, "saved firmware display id");
            ExistingRequireText(manifest.Identity.Firmware.BuildFingerprint, "saved firmware build fingerprint");
            ExistingRequireText(manifest.Identity.Firmware.AndroidRelease, "saved firmware Android release");
            ExistingRequireText(manifest.Identity.Firmware.SecurityPatch, "saved firmware security patch");
        }

        if (!string.Equals(manifest.Identity.AndroidSerial, identity.Serial, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved Android serial does not match the current device.");
        }

        if (!string.Equals(manifest.Identity.SocSerialDecimal, android.SocSerial, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved SoC serial does not match the current device.");
        }

        if (!string.Equals(manifest.Identity.BusSerialHex, client.Binding.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The saved EDL bus serial does not match the current device.");
        }

        if (!string.Equals(manifest.Identity.Model, identity.Model, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The saved Android model does not match the current device.");
        }

        if (requireCurrentFirmware)
        {
            if (!string.Equals(manifest.Identity.Firmware.DisplayId, firmware.DisplayId, StringComparison.Ordinal)
                || !string.Equals(
                    manifest.Identity.Firmware.BuildFingerprint, firmware.BuildFingerprint, StringComparison.Ordinal)
                || !string.Equals(
                    manifest.Identity.Firmware.AndroidRelease, firmware.AndroidRelease, StringComparison.Ordinal)
                || !string.Equals(
                    manifest.Identity.Firmware.SecurityPatch, firmware.SecurityPatch, StringComparison.Ordinal)
                || !string.Equals(
                    manifest.Identity.Firmware.BootloaderState,
                    firmware.AndroidReportedBootloaderState.ToString(),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The saved full firmware identity does not match the currently bound device firmware.");
            }
        }

        if (!manifest.HasInitialSaharaProof)
        {
            throw new InvalidDataException(
                "The backup manifest does not record the initial Sahara proof it was taken with.");
        }

        state.ExpectedBusSerialHex = expectedBusSerial;
    }

    private static string ExistingExpectedBusSerial(string? socSerial)
    {
        if (!uint.TryParse(socSerial, NumberStyles.None, CultureInfo.InvariantCulture, out uint value))
        {
            throw new InvalidOperationException(
                "The SoC serial '" + (socSerial ?? "<none>") + "' is not an unsigned decimal 32-bit value.");
        }

        if (value == 0 || value == uint.MaxValue)
        {
            throw new InvalidOperationException(
                "The SoC serial '" + socSerial + "' is not a usable EDL bus serial.");
        }

        return value.ToString("X8", CultureInfo.InvariantCulture);
    }

    // ------------------------------------------------------------------ geometry and tables

    private static void ExistingBuildGeometries(ExistingManifest manifest, Dictionary<int, EdlGeometry> geometries)
    {
        if (manifest.Luns.Count != 6)
        {
            throw new InvalidDataException(
                "The backup manifest describes " + manifest.Luns.Count + " LUNs; exactly six are required.");
        }

        foreach (ExistingLun lun in manifest.Luns)
        {
            if (lun.Lun < 0 || lun.Lun > 5)
            {
                throw new InvalidDataException("The backup manifest names the unknown LUN " + lun.Lun + ".");
            }

            if (lun.SectorSize != 512 && lun.SectorSize != 4096)
            {
                throw new InvalidDataException(
                    "LUN" + lun.Lun + " declares the unsupported sector size " + lun.SectorSize + ".");
            }

            if (lun.TotalSectors < MinimumTotalSectors)
            {
                throw new InvalidDataException(
                    "LUN" + lun.Lun + " declares only " + lun.TotalSectors + " sectors.");
            }

            CheckedMultiply(lun.TotalSectors, lun.SectorSize, "The saved LUN" + lun.Lun + " size overflows.");

            if (geometries.ContainsKey(lun.Lun))
            {
                throw new InvalidDataException("The backup manifest repeats LUN" + lun.Lun + ".");
            }

            geometries.Add(lun.Lun, new EdlGeometry(lun.Lun, lun.SectorSize, lun.TotalSectors));
        }

        for (int lun = 0; lun < 6; lun++)
        {
            if (!geometries.ContainsKey(lun))
            {
                throw new InvalidDataException("The backup manifest is missing LUN" + lun + ".");
            }
        }
    }

    private static void ExistingValidateDeclaredTables(
        ExistingManifest manifest,
        IReadOnlyDictionary<int, GptTable> tables,
        IReadOnlyDictionary<int, EdlGeometry> geometries)
    {
        foreach (ExistingLun lun in manifest.Luns)
        {
            GptTable table = tables[lun.Lun];
            EdlGeometry geometry = geometries[lun.Lun];

            if (lun.SectorSize != table.SectorSize
                || lun.TotalSectors != geometry.TotalSectors
                || !string.Equals(lun.DiskGuid, table.DiskGuid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(lun.SourceFingerprint, table.SourceFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The saved LUN" + lun.Lun + " table does not match the raw GPT bytes it describes.");
            }

            if (lun.Partitions.Count != table.Partitions.Count)
            {
                throw new InvalidDataException(
                    "The saved LUN" + lun.Lun + " table lists " + lun.Partitions.Count +
                    " partitions, but the raw GPT carries " + table.Partitions.Count + ".");
            }

            for (int index = 0; index < table.Partitions.Count; index++)
            {
                ExistingPartition declared = lun.Partitions[index];
                GptPartition parsed = table.Partitions[index];

                if (declared.Number != parsed.Number
                    || !string.Equals(declared.Name, parsed.Name, StringComparison.Ordinal)
                    || !string.Equals(declared.TypeGuid, parsed.TypeGuid, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(declared.PartUuid, parsed.PartUuid, StringComparison.OrdinalIgnoreCase)
                    || declared.StartSector != parsed.StartSector
                    || declared.SectorCount != parsed.SectorCount
                    || declared.Attributes != parsed.Attributes)
                {
                    throw new InvalidDataException(
                        "The saved partition '" + declared.Name + "' of LUN" + lun.Lun +
                        " does not match the raw GPT entry at the same index.");
                }
            }
        }
    }

    // ------------------------------------------------------------------ manifest parsing

    private static ExistingManifest ExistingParseManifest(
        JsonElement root,
        InternalInstallBackupRoles roles,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The backup manifest is not a JSON object.");
        }

        ExistingRejectUnknownProperties(root, "backup manifest", ExistingManifestProperties);

        if (ExistingInt64Property(root, "schemaVersion", "backup manifest") != 1)
        {
            throw new InvalidDataException("The backup manifest schemaVersion is not 1.");
        }

        if (!string.Equals(
                ExistingStringProperty(root, "status", "backup manifest"), VerifiedStatus, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The backup manifest status is not the verified status.");
        }

        if (ExistingBoolProperty(root, "userDataIncluded", "backup manifest"))
        {
            throw new InvalidDataException("The backup manifest must not include userdata.");
        }

        if (ExistingBoolProperty(root, "superIncluded", "backup manifest"))
        {
            throw new InvalidDataException("The backup manifest must not include super.");
        }

        JsonElement profileElement = ExistingObjectProperty(root, "profile", "backup manifest");
        ExistingRejectUnknownProperties(profileElement, "manifest profile", ExistingProfileProperties);

        ExistingManifest manifest = new()
        {
            ProfileId = ExistingStringProperty(profileElement, "profileId", "manifest profile"),
            Model = ExistingStringProperty(profileElement, "model", "manifest profile"),
            AndroidBuild = ExistingStringProperty(profileElement, "androidBuild", "manifest profile"),
            HardwareId = ExistingStringProperty(profileElement, "hardwareId", "manifest profile"),
        };

        JsonElement identityElement = ExistingObjectProperty(root, "identity", "backup manifest");
        ExistingRejectUnknownProperties(identityElement, "manifest identity", ExistingIdentityProperties);

        JsonElement firmwareElement = ExistingObjectProperty(identityElement, "firmware", "manifest identity");
        ExistingRejectUnknownProperties(firmwareElement, "manifest firmware", ExistingFirmwareProperties);

        ExistingFirmware firmware = new()
        {
            DisplayId = ExistingStringProperty(firmwareElement, "displayId", "manifest firmware"),
            BuildFingerprint = ExistingStringProperty(firmwareElement, "buildFingerprint", "manifest firmware"),
            AndroidRelease = ExistingStringProperty(firmwareElement, "androidRelease", "manifest firmware"),
            SecurityPatch = ExistingStringProperty(firmwareElement, "securityPatch", "manifest firmware"),
            BootloaderState = ExistingStringProperty(
                firmwareElement, "androidReportedBootloaderState", "manifest firmware"),
        };

        if (Array.IndexOf(ExistingBootloaderStates, firmware.BootloaderState) < 0)
        {
            throw new InvalidDataException(
                "The saved Android bootloader state '" + firmware.BootloaderState + "' is not a known state.");
        }

        manifest.Identity = new ExistingIdentity
        {
            AndroidSerial = ExistingStringProperty(identityElement, "androidSerial", "manifest identity"),
            SocSerialDecimal = ExistingStringProperty(identityElement, "socSerialDecimal", "manifest identity"),
            BusSerialHex = ExistingStringProperty(identityElement, "busSerialHex", "manifest identity"),
            Model = ExistingStringProperty(identityElement, "model", "manifest identity"),
            Firmware = firmware,
        };

        manifest.HasInitialSaharaProof = ExistingBoolProperty(
            identityElement, "hasInitialSaharaProof", "manifest identity");

        JsonElement lunsElement = ExistingProperty(root, "luns", JsonValueKind.Array, "backup manifest");
        foreach (JsonElement lunElement in lunsElement.EnumerateArray())
        {
            token.ThrowIfCancellationRequested();

            if (lunElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("A manifest LUN entry is not a JSON object.");
            }

            ExistingRejectUnknownProperties(lunElement, "manifest LUN", ExistingLunProperties);

            ExistingLun lun = new()
            {
                Lun = ExistingInt32Property(lunElement, "lun", "manifest LUN"),
                SectorSize = ExistingInt32Property(lunElement, "sectorSize", "manifest LUN"),
                TotalSectors = ExistingInt64Property(lunElement, "totalSectors", "manifest LUN"),
                DiskGuid = ExistingStringProperty(lunElement, "diskGuid", "manifest LUN"),
                SourceFingerprint = ExistingStringProperty(lunElement, "sourceFingerprint", "manifest LUN"),
            };

            JsonElement partitionsElement = ExistingProperty(
                lunElement, "partitions", JsonValueKind.Array, "manifest LUN");

            foreach (JsonElement partitionElement in partitionsElement.EnumerateArray())
            {
                if (partitionElement.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("A manifest partition entry is not a JSON object.");
                }

                ExistingRejectUnknownProperties(partitionElement, "manifest partition", ExistingPartitionProperties);

                lun.Partitions.Add(new ExistingPartition
                {
                    Number = ExistingInt32Property(partitionElement, "number", "manifest partition"),
                    Name = ExistingStringProperty(partitionElement, "name", "manifest partition"),
                    TypeGuid = ExistingStringProperty(partitionElement, "typeGuid", "manifest partition"),
                    PartUuid = ExistingStringProperty(partitionElement, "partUuid", "manifest partition"),
                    StartSector = ExistingInt64Property(partitionElement, "startSector", "manifest partition"),
                    SectorCount = ExistingInt64Property(partitionElement, "sectorCount", "manifest partition"),
                    Attributes = ExistingUInt64Property(partitionElement, "attributes", "manifest partition"),
                });
            }

            manifest.Luns.Add(lun);
        }

        if (manifest.Luns.Count != 6)
        {
            throw new InvalidDataException(
                "The backup manifest describes " + manifest.Luns.Count + " LUNs; exactly six are required.");
        }

        HashSet<string> seenRoles = new(StringComparer.Ordinal);
        JsonElement filesElement = ExistingProperty(root, "files", JsonValueKind.Array, "backup manifest");

        foreach (JsonElement fileElement in filesElement.EnumerateArray())
        {
            token.ThrowIfCancellationRequested();

            if (fileElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("A manifest file entry is not a JSON object.");
            }

            ExistingRejectUnknownProperties(fileElement, "manifest file", ExistingFileProperties);

            ExistingFile file = new()
            {
                Role = ExistingStringProperty(fileElement, "role", "manifest file"),
                Lun = ExistingInt32Property(fileElement, "lun", "manifest file"),
                StartSector = ExistingInt64Property(fileElement, "startSector", "manifest file"),
                SectorCount = ExistingInt64Property(fileElement, "sectorCount", "manifest file"),
                SectorSize = ExistingInt32Property(fileElement, "sectorSize", "manifest file"),
                PartUuid = ExistingNullableStringProperty(fileElement, "partUuid", "manifest file"),
                RelativePath = ExistingStringProperty(fileElement, "relativePath", "manifest file"),
                Length = ExistingInt64Property(fileElement, "length", "manifest file"),
                Sha256 = ExistingStringProperty(fileElement, "sha256", "manifest file"),
            };

            if (file.Role.Length == 0)
            {
                throw new InvalidDataException("The backup manifest carries a payload file with an empty role.");
            }

            if (!seenRoles.Add(file.Role))
            {
                throw new InvalidDataException("The backup manifest repeats the role '" + file.Role + "'.");
            }

            if (!ExistingIsKnownRole(file.Role, roles))
            {
                throw new InvalidDataException(
                    "The backup manifest carries the unknown role '" + file.Role + "'.");
            }

            manifest.Files.Add(file);
        }

        ExistingSelectRoles(roles, manifest.Files);

        return manifest;
    }

    /// <summary>
    /// Selects the exact contract of the manifest's whole role set: the baseline contract, or the baseline plus
    /// the single optional <c>efisp</c> at LUN4. Unknown, missing, empty and duplicated roles are rejected and the
    /// selected file count must match exactly, so a manifest that merely has the right number of files is never
    /// enough.
    /// </summary>
    private static InternalInstallBackupRoles ExistingSelectRoles(
        InternalInstallBackupRoles roles,
        List<ExistingFile> files)
    {
        List<string> captured = new(files.Count);

        foreach (ExistingFile file in files)
        {
            captured.Add(file.Role);
        }

        InternalInstallBackupRoles selected = roles.ForCapturedRoles(captured);

        if (files.Count != selected.TotalFileCount)
        {
            throw new InvalidDataException(
                "The backup manifest lists " + files.Count + " payload files; the selected contract requires " +
                selected.TotalFileCount + ".");
        }

        return selected;
    }

    /// <summary>
    /// True when <paramref name="role"/> is one of the contract's GPT roles or partition labels, including the
    /// optional <c>efisp</c> role at LUN4 whether or not it was selected.
    /// <see cref="InternalInstallBackupRoles.TryGetKnownLun"/> is the only role table, so an unknown role is still
    /// rejected exactly as before.
    /// </summary>
    private static bool ExistingIsKnownRole(string role, InternalInstallBackupRoles roles) =>
        roles.TryGetKnownLun(role, out _);

    /// <summary>
    /// The LUN the contract assigns to <paramref name="role"/>, GPT roles and the optional <c>efisp</c> included.
    /// The LUN declared by the manifest is never trusted, and an unknown role is rejected, never guessed.
    /// </summary>
    private static int ExistingExpectedLun(string role, InternalInstallBackupRoles roles)
    {
        if (roles.TryGetKnownLun(role, out int lun))
        {
            return lun;
        }

        throw new InvalidDataException("The backup manifest carries the unknown role '" + role + "'.");
    }

    private static bool ExistingTryParseGptRole(string role, out int lun, out bool primary)
    {
        for (int candidate = 0; candidate < 6; candidate++)
        {
            if (string.Equals(role, "gpt_lun" + candidate + "_primary", StringComparison.Ordinal))
            {
                lun = candidate;
                primary = true;
                return true;
            }

            if (string.Equals(role, "gpt_lun" + candidate + "_backup", StringComparison.Ordinal))
            {
                lun = candidate;
                primary = false;
                return true;
            }
        }

        lun = -1;
        primary = false;
        return false;
    }

    private static string ExistingResolvePayloadPath(string directory, string role, string relativePath)
    {
        if (relativePath.Length == 0
            || relativePath.IndexOf('/') >= 0
            || relativePath.IndexOf('\\') >= 0
            || relativePath.Contains("..", StringComparison.Ordinal)
            || Path.IsPathRooted(relativePath)
            || !string.Equals(relativePath, role + ".bin", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The payload path of role '" + role + "' must be exactly its canonical file name inside the " +
                "selected directory.");
        }

        string full = Path.GetFullPath(Path.Combine(directory, relativePath));
        string prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;

        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The payload path of role '" + role + "' escapes the selected backup directory.");
        }

        return full;
    }

    // ------------------------------------------------------------------ JSON helpers

    private static JsonDocument ExistingParseJson(byte[] bytes)
    {
        try
        {
            return JsonDocument.Parse(bytes);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The backup manifest is not valid JSON.", exception);
        }
    }

    private static void ExistingRejectUnknownProperties(JsonElement element, string what, string[] allowed)
    {
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (Array.IndexOf(allowed, property.Name) < 0)
            {
                throw new InvalidDataException(
                    "The " + what + " carries the unknown property '" + property.Name + "'.");
            }
        }
    }

    private static JsonElement ExistingProperty(
        JsonElement parent, string name, JsonValueKind kind, string what)
    {
        JsonElement found = default;
        int count = 0;

        foreach (JsonProperty property in parent.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                found = property.Value;
                count++;
            }
        }

        if (count == 0)
        {
            throw new InvalidDataException("The " + what + " is missing the property '" + name + "'.");
        }

        if (count > 1)
        {
            throw new InvalidDataException("The " + what + " repeats the property '" + name + "'.");
        }

        if (found.ValueKind != kind)
        {
            throw new InvalidDataException(
                "The " + what + " property '" + name + "' is not a " + kind + " value.");
        }

        return found;
    }

    private static JsonElement ExistingObjectProperty(JsonElement parent, string name, string what) =>
        ExistingProperty(parent, name, JsonValueKind.Object, what);

    private static string ExistingStringProperty(JsonElement parent, string name, string what)
    {
        JsonElement value = ExistingProperty(parent, name, JsonValueKind.String, what);
        return value.GetString()
               ?? throw new InvalidDataException("The " + what + " property '" + name + "' is not text.");
    }

    private static string? ExistingNullableStringProperty(JsonElement parent, string name, string what)
    {
        JsonElement found = default;
        int count = 0;

        foreach (JsonProperty property in parent.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                found = property.Value;
                count++;
            }
        }

        if (count == 0)
        {
            throw new InvalidDataException("The " + what + " is missing the property '" + name + "'.");
        }

        if (count > 1)
        {
            throw new InvalidDataException("The " + what + " repeats the property '" + name + "'.");
        }

        if (found.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (found.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("The " + what + " property '" + name + "' is not text or null.");
        }

        return found.GetString()
               ?? throw new InvalidDataException("The " + what + " property '" + name + "' is not text.");
    }

    private static long ExistingInt64Property(JsonElement parent, string name, string what)
    {
        JsonElement value = ExistingProperty(parent, name, JsonValueKind.Number, what);
        if (!value.TryGetInt64(out long result))
        {
            throw new InvalidDataException("The " + what + " property '" + name + "' is not a 64-bit integer.");
        }

        return result;
    }

    private static int ExistingInt32Property(JsonElement parent, string name, string what)
    {
        JsonElement value = ExistingProperty(parent, name, JsonValueKind.Number, what);
        if (!value.TryGetInt32(out int result))
        {
            throw new InvalidDataException("The " + what + " property '" + name + "' is not a 32-bit integer.");
        }

        return result;
    }

    private static ulong ExistingUInt64Property(JsonElement parent, string name, string what)
    {
        JsonElement value = ExistingProperty(parent, name, JsonValueKind.Number, what);
        if (!value.TryGetUInt64(out ulong result))
        {
            throw new InvalidDataException(
                "The " + what + " property '" + name + "' is not an unsigned 64-bit integer.");
        }

        return result;
    }

    private static bool ExistingBoolProperty(JsonElement parent, string name, string what)
    {
        JsonElement found = default;
        int count = 0;

        foreach (JsonProperty property in parent.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                found = property.Value;
                count++;
            }
        }

        if (count == 0)
        {
            throw new InvalidDataException("The " + what + " is missing the property '" + name + "'.");
        }

        if (count > 1)
        {
            throw new InvalidDataException("The " + what + " repeats the property '" + name + "'.");
        }

        if (found.ValueKind != JsonValueKind.True && found.ValueKind != JsonValueKind.False)
        {
            throw new InvalidDataException("The " + what + " property '" + name + "' is not a boolean.");
        }

        return found.GetBoolean();
    }

    // ------------------------------------------------------------------ small helpers

    private static void ExistingRequireRegularFile(string path, string what)
    {
        FileAttributes attributes;

        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (FileNotFoundException)
        {
            throw new FileNotFoundException("The " + what + " is missing.", path);
        }
        catch (DirectoryNotFoundException)
        {
            throw new FileNotFoundException("The " + what + " is missing.", path);
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException("The " + what + " is a directory, not a file.");
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("The " + what + " is a reparse point, which is not accepted.");
        }
    }

    private static byte[] ExistingReadHeld(FileStream stream, long length, CancellationToken token)
    {
        if (length <= 0 || length > int.MaxValue)
        {
            throw new InvalidDataException(
                "A held backup window of " + length + " bytes cannot be read as one byte array.");
        }

        stream.Position = 0;
        byte[] buffer = new byte[(int)length];
        int offset = 0;

        while (offset < buffer.Length)
        {
            token.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new InvalidDataException("A held backup window ended before its declared length.");
            }

            offset += read;
        }

        return buffer;
    }

    private static void ExistingRequireText(string? value, string what)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException("The bound " + what + " is empty; the backup cannot be bound.");
        }
    }

    private static bool ExistingSameUuid(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ExistingIsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
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

    // ------------------------------------------------------------------ nested state

    private sealed class ExistingState
    {
        internal readonly Dictionary<int, EdlGeometry> Geometries = new();

        internal readonly Dictionary<int, GptTable> Tables = new();

        internal readonly Dictionary<string, ExistingFile> ByRole = new(StringComparer.Ordinal);

        internal readonly List<FileStream> Locks = new();

        internal IReadOnlyDictionary<string, EdlCapturedRegion> Regions = null!;

        internal DiskLayout Lun0Layout = null!;

        internal string ManifestPath = string.Empty;

        internal string ManifestSha256 = string.Empty;

        internal string ExpectedBusSerialHex = string.Empty;

        internal long TotalBytes;

        internal void DisposeLeases()
        {
            foreach (FileStream stream in Locks)
            {
                try
                {
                    stream.Dispose();
                }
                catch (Exception)
                {
                }
            }

            Locks.Clear();
        }
    }

    private sealed class ExistingManifest
    {
        internal string ProfileId = string.Empty;

        internal string Model = string.Empty;

        internal string AndroidBuild = string.Empty;

        internal string HardwareId = string.Empty;

        internal ExistingIdentity Identity = new();

        internal bool HasInitialSaharaProof;

        internal readonly List<ExistingLun> Luns = new();

        internal readonly List<ExistingFile> Files = new();
    }

    private sealed class ExistingIdentity
    {
        internal string AndroidSerial = string.Empty;

        internal string SocSerialDecimal = string.Empty;

        internal string BusSerialHex = string.Empty;

        internal string Model = string.Empty;

        internal ExistingFirmware Firmware = new();
    }

    private sealed class ExistingFirmware
    {
        internal string DisplayId = string.Empty;

        internal string BuildFingerprint = string.Empty;

        internal string AndroidRelease = string.Empty;

        internal string SecurityPatch = string.Empty;

        internal string BootloaderState = string.Empty;
    }

    private sealed class ExistingLun
    {
        internal int Lun;

        internal int SectorSize;

        internal long TotalSectors;

        internal string DiskGuid = string.Empty;

        internal string SourceFingerprint = string.Empty;

        internal readonly List<ExistingPartition> Partitions = new();
    }

    private sealed class ExistingPartition
    {
        internal int Number;

        internal string Name = string.Empty;

        internal string TypeGuid = string.Empty;

        internal string PartUuid = string.Empty;

        internal long StartSector;

        internal long SectorCount;

        internal ulong Attributes;
    }

    private sealed class ExistingFile
    {
        internal string Role = string.Empty;

        internal int Lun;

        internal long StartSector;

        internal long SectorCount;

        internal int SectorSize;

        internal string? PartUuid;

        internal string RelativePath = string.Empty;

        internal long Length;

        internal string Sha256 = string.Empty;

        internal string FilePath = string.Empty;

        internal FileStream? Stream;
    }
}
