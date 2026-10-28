using System;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Immutable historical identity facts of one explicitly selected existing internal-install backup: the
/// saved profile, hardware and serial facts, the full saved firmware observation and the actual manifest
/// SHA-256, accepted only after the manifest and its sidecar verified against the trusted builtin profile.
/// <para>
/// Every value is a SAVED observation of the capture. Nothing here is current Android state, lock state,
/// boot trust, freshness or execution eligibility, and no device session or probe is involved. There is
/// deliberately no valid/ready/compatibility flag: the return value proves only that the accepted historical
/// metadata and manifest hash are internally consistent, never that the payload is valid or usable.
/// </para>
/// </summary>
public sealed class BootMaintenanceHistoricalIdentity
{
    internal BootMaintenanceHistoricalIdentity(
        string directoryPath,
        string manifestSha256,
        EdlDeviceProfile profile,
        string androidSerial,
        string socSerialDecimal,
        string busSerialHex,
        FirmwareSnapshot historicalFirmware)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(historicalFirmware);

        DirectoryPath = directoryPath;
        ManifestSha256 = manifestSha256;
        Profile = profile;
        AndroidSerial = androidSerial;
        SocSerialDecimal = socSerialDecimal;
        BusSerialHex = busSerialHex;
        HistoricalFirmware = historicalFirmware;

        // Historical adapter for the existing WaitForPresentAsync UI path only; the bootloader state is
        // deliberately Unknown so the saved Android report is never mistaken for current state.
        Identity = new AndroidMaintenanceIdentity(
            new DeviceIdentity(androidSerial, profile.Model, BootloaderState.Unknown)
            {
                Firmware = historicalFirmware,
            },
            socSerialDecimal);
    }

    /// <summary>Normalized absolute path of the explicitly selected existing backup directory.</summary>
    public string DirectoryPath { get; }

    /// <summary>The actual manifest SHA-256, hashed from the real bytes by the existing shared helper.</summary>
    public string ManifestSha256 { get; }

    /// <summary>The exact trusted builtin profile the backup was selected and validated against; never a clone.</summary>
    public EdlDeviceProfile Profile { get; }

    /// <summary>The saved profile id; always the selected builtin's id.</summary>
    public string ProfileId => Profile.ProfileId;

    /// <summary>The saved model; always the selected builtin's model.</summary>
    public string Model => Profile.Model;

    /// <summary>The saved full hardware id; always the selected builtin's known hardware id.</summary>
    public string HardwareId => Profile.FullHardwareId!;

    /// <summary>The saved Android serial of the capture.</summary>
    public string AndroidSerial { get; }

    /// <summary>The saved SoC serial in decimal form.</summary>
    public string SocSerialDecimal { get; }

    /// <summary>The saved EDL bus serial in canonical uppercase 8-digit hexadecimal form.</summary>
    public string BusSerialHex { get; }

    /// <summary>The full saved firmware observation; historical evidence, never current Android state.</summary>
    public FirmwareSnapshot HistoricalFirmware { get; }

    /// <summary>
    /// A HISTORICAL adapter over the saved identity for the existing WaitForPresentAsync path only. It is
    /// explicitly not current Android state and grants no readiness; the saved bootloader report stays in
    /// <see cref="HistoricalFirmware"/> while <see cref="DeviceIdentity.Firmware"/> carries the same saved
    /// observation.
    /// </summary>
    public AndroidMaintenanceIdentity Identity { get; }
}

// Additional BootMaintenanceBackend part: historical-identity reading only. No device session, probe,
// payload hash scan, native command or current-slot inference exists here; the later H2 slice owns full
// source validation, the real initial Sahara proof and the fresh cross-checks.
public sealed partial class BootMaintenanceBackend
{
    /// <summary>
    /// Reads the accepted historical identity of one explicitly selected existing internal-install backup.
    /// <para>
    /// The directory must be absolute and already exist and is the only location touched; nothing is
    /// discovered, selected from a parent or modified. The call reads the manifest and its sidecar only and
    /// issues no device command of any kind. A returned value proves only that the saved metadata is
    /// internally consistent and hashes to the verified manifest: it is never payload validity, device
    /// identity, boot trust, freshness or execution eligibility.
    /// </para>
    /// </summary>
    /// <param name="backupDirectory">Absolute existing directory holding the manifest and its sidecar.</param>
    /// <param name="cancellationToken">Cancellation; checked before any filesystem work and propagated unchanged.</param>
    /// <returns>The immutable historical identity facts with the actual manifest SHA-256.</returns>
    public static Task<BootMaintenanceHistoricalIdentity> ReadHistoricalIdentityAsync(
        string backupDirectory,
        CancellationToken cancellationToken = default) =>
        InternalInstallBackup.ReadHistoricalIdentityAsync(backupDirectory, cancellationToken);
}

// Additional InternalInstallBackup part: the internal reader behind
// BootMaintenanceBackend.ReadHistoricalIdentityAsync. It reuses the existing private manifest helpers and
// guard semantics without changing their visibility and never touches a device.
public static partial class InternalInstallBackup
{
    /// <summary>
    /// Reads and validates only the identity facts of the explicitly selected existing backup directory,
    /// reusing the existing explicit directory guards, hashed manifest lease, sidecar verification and
    /// manifest parser. No payload file is opened, no GPT is parsed and no device session exists.
    /// </summary>
    internal static async Task<BootMaintenanceHistoricalIdentity> ReadHistoricalIdentityAsync(
        string backupDirectory,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

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

        string manifestPath = Path.Combine(directory, ManifestFileName);
        ExistingRequireRegularFile(manifestPath, "backup manifest");
        string sidecarPath = manifestPath + SidecarSuffix;
        ExistingRequireRegularFile(sidecarPath, "backup manifest sidecar");

        token.ThrowIfCancellationRequested();

        (string manifestSha256, FileStream manifestStream) = await OpenHashedSharedAsync(manifestPath, token)
            .ConfigureAwait(false);
        FileStream? sidecarStream = null;

        try
        {
            if (manifestStream.Length <= 0 || manifestStream.Length > ExistingManifestMaxBytes)
            {
                throw new InvalidDataException(
                    "The backup manifest is " + manifestStream.Length + " bytes; it cannot be the verified manifest.");
            }

            sidecarStream = OpenSidecarVerified(sidecarPath, manifestSha256);

            if (sidecarStream.Length <= 0 || sidecarStream.Length > 256)
            {
                throw new InvalidDataException("The backup manifest sidecar does not carry one SHA-256 line.");
            }

            byte[] manifestBytes = ExistingReadHeld(manifestStream, manifestStream.Length, token);
            using JsonDocument document = ExistingParseJson(manifestBytes);

            // The trusted profile is selected only from the parsed document's profile id, and only a
            // complete builtin profile can be selected; manifest.model never registers anything.
            JsonElement profileElement = ExistingObjectProperty(document.RootElement, "profile", "backup manifest");
            string requestedProfileId = ExistingStringProperty(profileElement, "profileId", "manifest profile");

            EdlDeviceProfile builtin = EdlDeviceProfiles.FindById(requestedProfileId)
                ?? throw new InvalidDataException(
                    "The backup manifest names the unknown EDL profile '" + requestedProfileId + "'.");

            builtin.RequireComplete();

            if (builtin.FullHardwareId is null)
            {
                throw new InvalidDataException(
                    "The trusted EDL profile '" + builtin.ProfileId + "' has no known full hardware id.");
            }

            ExistingManifest manifest = ExistingParseManifest(
                document.RootElement, InternalInstallBackupRoles.ForModel(builtin.Model), token);

            if (!string.Equals(manifest.ProfileId, builtin.ProfileId, StringComparison.Ordinal) ||
                !string.Equals(manifest.Model, builtin.Model, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The backup manifest names profile '" + manifest.ProfileId + "' model '" + manifest.Model +
                    "', not the selected builtin profile '" + builtin.ProfileId + "' model '" + builtin.Model + "'.");
            }

            if (!string.Equals(manifest.HardwareId, builtin.FullHardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The backup manifest hardware id '" + manifest.HardwareId +
                    "' does not match the trusted profile hardware id.");
            }

            if (!string.Equals(manifest.Identity.Model, builtin.Model, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The saved identity model '" + manifest.Identity.Model +
                    "' does not match the trusted profile model '" + builtin.Model + "'.");
            }

            ExistingRequireText(manifest.Identity.AndroidSerial, "saved Android serial");
            ExistingRequireText(manifest.Identity.SocSerialDecimal, "saved SoC serial");
            ExistingRequireText(manifest.Identity.BusSerialHex, "saved EDL bus serial");

            // Strict form check only: the saved bus serial must itself be the canonical uppercase 8-digit
            // hexadecimal form of the saved decimal SoC serial. No generic serial parsing is used.
            string socBusSerial = ExistingExpectedBusSerial(manifest.Identity.SocSerialDecimal);
            if (!uint.TryParse(
                    manifest.Identity.BusSerialHex,
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out uint busValue) ||
                !string.Equals(
                    manifest.Identity.BusSerialHex,
                    busValue.ToString("X8", CultureInfo.InvariantCulture),
                    StringComparison.Ordinal) ||
                !string.Equals(busValue.ToString("X8", CultureInfo.InvariantCulture), socBusSerial, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The saved EDL bus serial '" + manifest.Identity.BusSerialHex +
                    "' is not the strict 8-digit hexadecimal form of the saved SoC serial " + socBusSerial + ".");
            }

            if (!manifest.HasInitialSaharaProof)
            {
                throw new InvalidDataException("The saved backup does not record the initial Sahara proof.");
            }

            ExistingRequireText(manifest.Identity.Firmware.DisplayId, "saved firmware display id");
            ExistingRequireText(manifest.Identity.Firmware.BuildFingerprint, "saved build fingerprint");
            ExistingRequireText(manifest.Identity.Firmware.AndroidRelease, "saved Android release");
            ExistingRequireText(manifest.Identity.Firmware.SecurityPatch, "saved security patch");

            // Version distinction: the bundled loader source build is never compared here. The manifest's
            // own androidBuild must only match the capture's own saved display id.
            if (!string.Equals(manifest.AndroidBuild, manifest.Identity.Firmware.DisplayId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The saved manifest androidBuild '" + manifest.AndroidBuild +
                    "' does not match the saved firmware display id '" + manifest.Identity.Firmware.DisplayId + "'.");
            }

            if (!Enum.TryParse(manifest.Identity.Firmware.BootloaderState, out BootloaderState savedState) ||
                !Enum.IsDefined(savedState))
            {
                throw new InvalidDataException(
                    "The saved Android bootloader state '" + manifest.Identity.Firmware.BootloaderState +
                    "' is not a known state.");
            }

            return new BootMaintenanceHistoricalIdentity(
                directory,
                manifestSha256,
                builtin,
                manifest.Identity.AndroidSerial,
                manifest.Identity.SocSerialDecimal,
                manifest.Identity.BusSerialHex,
                new FirmwareSnapshot(
                    manifest.Identity.Firmware.DisplayId,
                    manifest.Identity.Firmware.BuildFingerprint,
                    manifest.Identity.Firmware.AndroidRelease,
                    manifest.Identity.Firmware.SecurityPatch,
                    savedState));
        }
        finally
        {
            manifestStream.Dispose();
            sidecarStream?.Dispose();
        }
    }
}
