using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One progress notification of <see cref="InternalInstallBackup.CreateAsync"/>.
/// <para>
/// <see cref="Stage"/> is a stable key the UI translates - <c>reading-gpt</c>, <c>reading-partition</c>,
/// <c>verifying</c> or <c>complete</c> - never a user-facing sentence. <see cref="Role"/> names the contract
/// role being read, or is null for stage-only notifications. The counters count fully verified payload files
/// only: they may be 0 while the tables are still unknown, and become the model's whole file count (51 on
/// TB322FC, 47 on TB323FU, one more when the fresh tables carry efisp) plus the summed byte ranges once the whole
/// plan is known. They are never an estimated percentage.
/// </para>
/// </summary>
public sealed record InternalBackupProgress(
    string Stage,
    string? Role,
    long CompletedBytes,
    long TotalBytes,
    int CompletedFiles,
    int TotalFiles);

/// <summary>
/// Creates the internal-install backup of exactly the partitions an Android-to-Linux install overwrites.
/// <para>
/// The chosen parent must be an existing explicit directory, and the factory creates its own unique
/// per-device directory below it (safe serial plus GUID, no reuse, no overwrite, no temporary fallback).
/// It probes LUN0 first - with the initial loader only while the client has no Sahara proof - then the warm
/// probes of the remaining LUNs, reads the primary 64 sectors at 0 and the backup 64 sectors at
/// <c>TotalSectors - 64</c> of every LUN using that LUN's own geometry, validates all six tables through
/// <see cref="OriginalGptImporter.Parse"/>, resolves the model's required partition labels on their specified
/// LUNs before any partition read, and returns a set only after every planned file (51 on TB322FC, 47 on
/// TB323FU) and the verified manifest are durable.
/// </para>
/// <para>
/// Nothing here writes to the device, resets it, reads userdata/super/rawdump/metadata/modem content or queries
/// RPMB/eFuse. A refusal or cancellation after the first read preserves every partial file and the partial
/// manifest, then throws; a set exists only for a complete, verified backup.
/// </para>
/// </summary>
public static partial class InternalInstallBackup
{
    private const string ManifestFileName = "backup-manifest.json";
    private const string SidecarSuffix = ".sha256";
    private const string PartialStatus = "partial";
    private const string VerifiedStatus = "verified";
    private const string ReadingGptStage = "reading-gpt";
    private const string ReadingPartitionStage = "reading-partition";
    private const string VerifyingStage = "verifying";
    private const string CompleteStage = "complete";
    private const int GptSectors = 64;
    private const int MinimumTotalSectors = 129;
    private const int FileBufferBytes = 64 * 1024;

    private static readonly int[] LunOrder = { 0, 1, 2, 3, 4, 5 };

    /// <summary>
    /// Starts one backup into a new directory below <paramref name="chosenParent"/>.
    /// <para>
    /// The caller owns <paramref name="client"/> (toolchain and binding are never disposed or substituted).
    /// <paramref name="progress"/> may be null. Pre-cancellation is rejected before any command and before any
    /// directory is created.
    /// </para>
    /// </summary>
    /// <returns>The verified set; its <see cref="InternalBackupSet.Dispose"/> only releases the read locks.</returns>
    public static async Task<InternalBackupSet> CreateAsync(
        EdlClient client,
        string chosenParent,
        IProgress<InternalBackupProgress>? progress = null,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException("A chosen parent directory is required.", nameof(chosenParent));
        }

        string parent = Path.GetFullPath(chosenParent);
        if (File.Exists(parent))
        {
            throw new IOException("The chosen parent is a file, not a directory: '" + parent + "'.");
        }

        if (!Directory.Exists(parent))
        {
            throw new IOException("The chosen parent directory does not exist: '" + parent + "'.");
        }

        ProfileSummary profile = new(
            client.Toolchain.ProfileId,
            client.Toolchain.Model,
            client.Binding.AndroidIdentity?.Identity?.Firmware?.DisplayId ?? string.Empty,
            client.Toolchain.HardwareId);
        RequireProfile(profile);

        // The contract originates from the loaded toolchain's model, never from a caller-supplied value.
        InternalInstallBackupRoles roles = InternalInstallBackupRoles.ForModel(profile.Model);

        token.ThrowIfCancellationRequested();

        string directory = Path.Combine(
            parent,
            "internal-backup-" + SafeToken(ReadAndroidSerial(client)) + "-" + Guid.NewGuid().ToString("N"));

        BackupState state = new();
        ManifestIdentity identity = ReadIdentity(client, freshBusSerial: null);
        ProgressReporter reporter = new(progress);
        List<FileStream> locks = new();

        try
        {
            Directory.CreateDirectory(directory);
            UpdatePartial(directory, state, profile, identity);

            Dictionary<int, EdlGeometry> geometries = new();
            Dictionary<int, GptTable> tables = new();

            for (int lun = 0; lun < 6; lun++)
            {
                EdlProbeEvidence probe = await client
                    .ProbeAsync(lun, lun == 0 && !client.HasInitialSaharaProof, token)
                    .ConfigureAwait(false);

                EdlGeometry geometry = RequireGeometry(probe, lun);
                geometries.Add(lun, geometry);

                if (lun == 0)
                {
                    identity = ReadIdentity(client, probe.BusSerialHex);
                }

                reporter.Report(ReadingGptStage, role: null);
            }

            foreach (int lun in LunOrder)
            {
                EdlGeometry geometry = geometries[lun];

                string primaryName = "gpt_lun" + lun + "_primary.bin";
                string primaryRole = "gpt_lun" + lun + "_primary";
                SealedFile primary = await ReadSealedAsync(
                    client,
                    geometry,
                    startSector: 0,
                    sectorCount: GptSectors,
                    Path.Combine(directory, primaryName),
                    locks,
                    token).ConfigureAwait(false);

                state.Files.Add(ToFileEntry(primaryRole, geometry, 0, GptSectors, null, primaryName, primary));
                reporter.Completed(primary.Length);
                reporter.Report(ReadingGptStage, primaryRole);
                UpdatePartial(directory, state, profile, identity);

                long backupStart = geometry.TotalSectors - GptSectors;
                string backupName = "gpt_lun" + lun + "_backup.bin";
                string backupRole = "gpt_lun" + lun + "_backup";
                SealedFile backup = await ReadSealedAsync(
                    client,
                    geometry,
                    backupStart,
                    GptSectors,
                    Path.Combine(directory, backupName),
                    locks,
                    token).ConfigureAwait(false);

                state.Files.Add(ToFileEntry(backupRole, geometry, backupStart, GptSectors, null, backupName, backup));
                reporter.Completed(backup.Length);
                reporter.Report(ReadingGptStage, backupRole);
                UpdatePartial(directory, state, profile, identity);

                byte[] primaryBytes = await ReadHeldAsync(primary.Stream, primary.Length, token)
                    .ConfigureAwait(false);
                byte[] backupBytes = await ReadHeldAsync(backup.Stream, backup.Length, token)
                    .ConfigureAwait(false);

                tables.Add(lun, ParseTable(primaryBytes, backupBytes, geometry));
            }

            state.Luns.Clear();
            foreach (int lun in LunOrder)
            {
                EdlGeometry geometry = geometries[lun];
                GptTable table = tables[lun];
                state.Luns.Add(new ManifestLun(
                    lun,
                    geometry.SectorSize,
                    geometry.TotalSectors,
                    table.DiskGuid,
                    table.SourceFingerprint,
                    table.Partitions));
            }

            UpdatePartial(directory, state, profile, identity);

            // The actual tables alone decide whether this capture also carries efisp: one exact label anywhere
            // in the six tables opts in, and ResolveTargets below still enforces a single copy at LUN4 with a
            // valid range before any partition range is read.
            roles = SelectCaptureRoles(roles, tables);

            IReadOnlyDictionary<string, PartitionTarget> targets = ResolveTargets(tables, geometries, roles);

            long totalBytes = 0;
            foreach (int lun in LunOrder)
            {
                totalBytes = CheckedAdd(
                    totalBytes,
                    CheckedMultiply(2L * GptSectors, geometries[lun].SectorSize, "The GPT pair byte count overflows."),
                    "The planned byte total overflows.");
            }

            foreach (string name in roles.PartitionNames)
            {
                PartitionTarget target = targets[name];
                totalBytes = CheckedAdd(
                    totalBytes,
                    CheckedMultiply(
                        target.Partition.SectorCount,
                        target.Geometry.SectorSize,
                        "The '" + name + "' byte count overflows."),
                    "The planned byte total overflows.");
            }

            reporter.Plan(roles.TotalFileCount, totalBytes);
            reporter.Report(ReadingPartitionStage, role: null);

            foreach (string name in roles.PartitionNames)
            {
                PartitionTarget target = targets[name];
                string fileName = name + ".bin";

                SealedFile sealedFile = await ReadSealedAsync(
                    client,
                    target.Geometry,
                    target.Partition.StartSector,
                    target.Partition.SectorCount,
                    Path.Combine(directory, fileName),
                    locks,
                    token).ConfigureAwait(false);

                state.Files.Add(ToFileEntry(
                    name,
                    target.Geometry,
                    target.Partition.StartSector,
                    target.Partition.SectorCount,
                    target.Partition.PartUuid,
                    fileName,
                    sealedFile));

                reporter.Completed(sealedFile.Length);
                reporter.Report(ReadingPartitionStage, name);
                UpdatePartial(directory, state, profile, identity);
            }

            reporter.Report(VerifyingStage, role: null);

            state.Status = VerifiedStatus;
            byte[] finalBytes = BuildManifest(state, profile, identity);
            string manifestPath = Path.Combine(directory, ManifestFileName);
            WriteDurableAtomic(manifestPath, finalBytes);

            (string manifestSha, FileStream manifestStream) = await OpenHashedSharedAsync(manifestPath, token)
                .ConfigureAwait(false);

            try
            {
                string expectedSha = Convert.ToHexString(SHA256.HashData(finalBytes));
                if (!string.Equals(manifestSha, expectedSha, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException(
                        "The committed manifest does not hash to the bytes that were written.");
                }
            }
            catch
            {
                manifestStream.Dispose();
                throw;
            }

            string sidecarPath = manifestPath + SidecarSuffix;
            FileStream sidecarStream;
            try
            {
                WriteSidecar(sidecarPath, manifestSha);
                sidecarStream = OpenSidecarVerified(sidecarPath, manifestSha);
            }
            catch
            {
                manifestStream.Dispose();
                throw;
            }

            locks.Add(manifestStream);
            locks.Add(sidecarStream);

            InternalBackupSet set = new(
                client.Binding,
                directory,
                manifestPath,
                manifestSha,
                profile.ProfileId,
                profile.Model,
                profile.AndroidBuild,
                profile.HardwareId,
                CopyGeometries(geometries),
                CopyTables(tables),
                BuildRegions(state.Files, directory),
                BuildLun0Layout(tables[0], geometries[0]),
                locks);

            reporter.Complete(totalBytes);
            return set;
        }
        catch (Exception error)
        {
            foreach (FileStream stream in locks)
            {
                try
                {
                    stream.Dispose();
                }
                catch (Exception)
                {
                }
            }

            locks.Clear();

            PreservePartial(directory, state, profile, identity, error);
            throw;
        }
    }

    // ------------------------------------------------------------------ planning and validation

    private static EdlGeometry RequireGeometry(EdlProbeEvidence probe, int lun)
    {
        if (probe.Geometry is null)
        {
            throw new InvalidOperationException("The probe of LUN" + lun + " returned no geometry.");
        }

        EdlGeometry geometry = probe.Geometry;
        if (geometry.Lun != lun)
        {
            throw new InvalidOperationException(
                "The probe returned geometry for LUN" + geometry.Lun + " instead of the requested LUN" + lun + ".");
        }

        if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
        {
            throw new InvalidOperationException(
                "LUN" + lun + " reported an unsupported sector size of " + geometry.SectorSize + " bytes.");
        }

        if (geometry.TotalSectors < MinimumTotalSectors)
        {
            throw new InvalidOperationException(
                "LUN" + lun + " reported only " + geometry.TotalSectors + " sectors, which cannot hold a GPT.");
        }

        CheckedMultiply(geometry.TotalSectors, geometry.SectorSize, "The LUN" + lun + " disk size overflows.");

        return geometry;
    }

    private static GptTable ParseTable(byte[] primaryBytes, byte[] backupBytes, EdlGeometry geometry)
    {
        long diskBytes = CheckedMultiply(
            geometry.TotalSectors, geometry.SectorSize, "The LUN" + geometry.Lun + " disk size overflows.");

        GptTable table = OriginalGptImporter.Parse(primaryBytes, backupBytes, geometry.SectorSize, diskBytes);
        if (table is null)
        {
            throw new InvalidDataException("The GPT of LUN" + geometry.Lun + " could not be parsed.");
        }

        if (table.SectorSize != geometry.SectorSize || table.DiskBytes != diskBytes)
        {
            throw new InvalidDataException(
                "The GPT of LUN" + geometry.Lun + " describes a different disk than the probed geometry.");
        }

        return table;
    }

    /// <summary>
    /// Keeps <paramref name="roles"/> as they are unless one of the six fresh tables carries the exact
    /// <c>efisp</c> label. Presence alone selects the optional role; the LUN4 placement, the single copy and the
    /// range are still enforced afterwards by <see cref="ResolveTargets"/>, before any partition range is read.
    /// </summary>
    private static InternalInstallBackupRoles SelectCaptureRoles(
        InternalInstallBackupRoles roles,
        IReadOnlyDictionary<int, GptTable> tables)
    {
        foreach (int lun in LunOrder)
        {
            foreach (GptPartition partition in tables[lun].Partitions)
            {
                if (string.Equals(partition.Name, InternalInstallBackupRoles.EfispRole, StringComparison.Ordinal))
                {
                    return roles.WithEfisp();
                }
            }
        }

        return roles;
    }

    /// <summary>
    /// Maps every required label of <paramref name="roles"/> onto its single fresh table entry. The whole
    /// six-table set is searched first, so a missing label, a second copy on another LUN and a duplicate inside
    /// one LUN all reject here, before any partition range is read.
    /// </summary>
    private static IReadOnlyDictionary<string, PartitionTarget> ResolveTargets(
        IReadOnlyDictionary<int, GptTable> tables,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        InternalInstallBackupRoles roles)
    {
        HashSet<string> requiredNames = new(StringComparer.Ordinal);
        foreach (string name in roles.PartitionNames)
        {
            requiredNames.Add(name);
        }

        Dictionary<string, List<PartitionTarget>> byName = new(StringComparer.Ordinal);

        foreach (int lun in LunOrder)
        {
            foreach (GptPartition partition in tables[lun].Partitions)
            {
                string name = partition.Name;
                if (string.IsNullOrEmpty(name) || !requiredNames.Contains(name))
                {
                    continue;
                }

                if (!byName.TryGetValue(name, out List<PartitionTarget>? matches))
                {
                    matches = new List<PartitionTarget>();
                    byName.Add(name, matches);
                }

                matches.Add(new PartitionTarget(lun, partition, geometries[lun]));
            }
        }

        Dictionary<string, PartitionTarget> resolved = new(StringComparer.Ordinal);

        foreach ((int lun, string name) in roles.Partitions)
        {
            if (!byName.TryGetValue(name, out List<PartitionTarget>? matches) || matches.Count == 0)
            {
                throw new InvalidOperationException(
                    "The fresh tables do not contain the required '" + name + "' partition.");
            }

            if (matches.Count > 1)
            {
                throw new InvalidOperationException(
                    "The fresh tables contain '" + name + "' " + matches.Count + " times; exactly one is required.");
            }

            PartitionTarget target = matches[0];
            if (target.Lun != lun)
            {
                throw new InvalidOperationException(
                    "'" + name + "' was found on LUN" + target.Lun + " but the contract requires LUN" + lun + ".");
            }

            ValidatePartitionRange(target);
            resolved.Add(name, target);
        }

        return resolved;
    }

    private static void ValidatePartitionRange(PartitionTarget target)
    {
        GptPartition partition = target.Partition;

        if (partition.StartSector < 0 || partition.SectorCount <= 0)
        {
            throw new InvalidOperationException(
                "The '" + partition.Name + "' partition has an empty or unusable sector range.");
        }

        if (string.IsNullOrWhiteSpace(partition.PartUuid))
        {
            throw new InvalidOperationException(
                "The '" + partition.Name + "' partition has no partition UUID.");
        }

        long diskBytes = CheckedMultiply(
            target.Geometry.TotalSectors,
            target.Geometry.SectorSize,
            "The LUN" + target.Lun + " disk size overflows.");
        long offsetBytes = CheckedMultiply(
            partition.StartSector,
            target.Geometry.SectorSize,
            "The '" + partition.Name + "' offset overflows.");
        long lengthBytes = CheckedMultiply(
            partition.SectorCount,
            target.Geometry.SectorSize,
            "The '" + partition.Name + "' length overflows.");

        if (CheckedAdd(offsetBytes, lengthBytes, "The '" + partition.Name + "' range overflows.") > diskBytes)
        {
            throw new InvalidOperationException(
                "The '" + partition.Name + "' partition extends past the end of LUN" + target.Lun + ".");
        }
    }

    // ------------------------------------------------------------------ file reading and sealing

    /// <summary>
    /// Reads one whole range into a new file, makes it durable, then verifies length and SHA-256 on the very
    /// read-only handle that stays open for the lifetime of the returned set.
    /// </summary>
    private static async Task<SealedFile> ReadSealedAsync(
        EdlClient client,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        string path,
        List<FileStream> locks,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        long expectedLength = CheckedMultiply(
            sectorCount, geometry.SectorSize, "The requested range for '" + path + "' overflows.");

        if (expectedLength <= 0)
        {
            throw new InvalidOperationException("The requested range for '" + path + "' is empty.");
        }

        EdlReadEvidence evidence = await client
            .ReadAsync(geometry.Lun, startSector, sectorCount, path, token)
            .ConfigureAwait(false);

        VerifyReadEvidence(evidence, geometry, startSector, sectorCount, expectedLength, path);

        using (FileStream writable = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileBufferBytes))
        {
            if (writable.Length != expectedLength)
            {
                throw new IOException(
                    "The read output file '" + path + "' is " + writable.Length + " bytes instead of " +
                    expectedLength + ".");
            }

            writable.Flush(true);
        }

        FileStream held = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.SequentialScan);

        try
        {
            if (held.Length != expectedLength)
            {
                throw new IOException(
                    "The read output file '" + path + "' changed length to " + held.Length + " bytes.");
            }

            string sha256 = Convert.ToHexString(await SHA256.HashDataAsync(held, token).ConfigureAwait(false));
            if (!string.Equals(sha256, evidence.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "The whole-file SHA-256 of '" + path + "' does not match the read evidence.");
            }

            locks.Add(held);
            return new SealedFile(path, expectedLength, sha256, held);
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    private static void VerifyReadEvidence(
        EdlReadEvidence evidence,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        long expectedLength,
        string path)
    {
        if (evidence is null)
        {
            throw new InvalidOperationException("The read of '" + path + "' returned no evidence.");
        }

        if (evidence.Geometry is null
            || evidence.Geometry.Lun != geometry.Lun
            || evidence.Geometry.SectorSize != geometry.SectorSize
            || evidence.Geometry.TotalSectors != geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a geometry that does not match LUN" + geometry.Lun + ".");
        }

        if (evidence.StartSector != startSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' covered a different sector range than requested.");
        }

        if (evidence.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' returned " + evidence.Length + " bytes instead of " + expectedLength + ".");
        }

        if (!SamePath(evidence.FilePath, path))
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a different output file.");
        }
    }

    private static async Task<byte[]> ReadHeldAsync(FileStream stream, long length, CancellationToken token)
    {
        if (length <= 0 || length > int.MaxValue)
        {
            throw new InvalidOperationException(
                "The GPT window of " + length + " bytes cannot be held as one byte array.");
        }

        stream.Position = 0;
        byte[] buffer = new byte[(int)length];
        int offset = 0;

        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), token).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new IOException("The verified GPT window ended before its declared length.");
            }

            offset += read;
        }

        return buffer;
    }

    // ------------------------------------------------------------------ manifest and durability

    private static ManifestFileEntry ToFileEntry(
        string role,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        string? partUuid,
        string fileName,
        SealedFile file) =>
        new(
            role,
            geometry.Lun,
            startSector,
            sectorCount,
            geometry.SectorSize,
            partUuid,
            fileName,
            file.Length,
            file.Sha256);

    private static void UpdatePartial(
        string directory,
        BackupState state,
        ProfileSummary profile,
        ManifestIdentity identity) =>
        WriteDurableAtomic(Path.Combine(directory, ManifestFileName), BuildManifest(state, profile, identity));

    private static void PreservePartial(
        string directory,
        BackupState state,
        ProfileSummary profile,
        ManifestIdentity identity,
        Exception error)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        try
        {
            state.Status = PartialStatus;
            state.Failure = error.GetType().Name + ": " + error.Message;
            UpdatePartial(directory, state, profile, identity);
        }
        catch (Exception)
        {
        }

        try
        {
            string sidecar = Path.Combine(directory, ManifestFileName) + SidecarSuffix;
            if (File.Exists(sidecar))
            {
                File.Delete(sidecar);
            }
        }
        catch (Exception)
        {
        }
    }

    private static byte[] BuildManifest(
        BackupState state,
        ProfileSummary profile,
        ManifestIdentity identity)
    {
        using MemoryStream buffer = new();

        using (Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("status", state.Status);
            writer.WriteBoolean("userDataIncluded", false);
            writer.WriteBoolean("superIncluded", false);

            writer.WriteStartObject("profile");
            writer.WriteString("profileId", profile.ProfileId);
            writer.WriteString("model", profile.Model);
            writer.WriteString("androidBuild", profile.AndroidBuild);
            writer.WriteString("hardwareId", profile.HardwareId);
            writer.WriteEndObject();

            writer.WriteStartObject("identity");
            writer.WriteString("androidSerial", identity.AndroidSerial);
            writer.WriteString("socSerialDecimal", identity.SocSerialDecimal);
            writer.WriteString("busSerialHex", identity.BusSerialHex);
            writer.WriteString("model", identity.Model);

            writer.WriteStartObject("firmware");
            FirmwareSnapshot? firmware = identity.Firmware;
            writer.WriteString("displayId", firmware?.DisplayId);
            writer.WriteString("buildFingerprint", firmware?.BuildFingerprint);
            writer.WriteString("androidRelease", firmware?.AndroidRelease);
            writer.WriteString("securityPatch", firmware?.SecurityPatch);

            if (firmware is null)
            {
                writer.WriteNull("androidReportedBootloaderState");
            }
            else
            {
                writer.WriteString(
                    "androidReportedBootloaderState",
                    firmware.AndroidReportedBootloaderState.ToString());
            }

            writer.WriteEndObject();
            writer.WriteBoolean("hasInitialSaharaProof", identity.HasInitialSaharaProof);
            writer.WriteEndObject();

            writer.WriteStartArray("luns");
            foreach (ManifestLun lun in state.Luns)
            {
                writer.WriteStartObject();
                writer.WriteNumber("lun", lun.Lun);
                writer.WriteNumber("sectorSize", lun.SectorSize);
                writer.WriteNumber("totalSectors", lun.TotalSectors);
                writer.WriteString("diskGuid", lun.DiskGuid);
                writer.WriteString("sourceFingerprint", lun.SourceFingerprint);

                writer.WriteStartArray("partitions");
                foreach (GptPartition partition in lun.Partitions)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("number", partition.Number);
                    writer.WriteString("name", partition.Name);
                    writer.WriteString("typeGuid", partition.TypeGuid);
                    writer.WriteString("partUuid", partition.PartUuid);
                    writer.WriteNumber("startSector", partition.StartSector);
                    writer.WriteNumber("sectorCount", partition.SectorCount);
                    writer.WriteNumber("attributes", partition.Attributes);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WriteStartArray("files");
            foreach (ManifestFileEntry file in state.Files)
            {
                writer.WriteStartObject();
                writer.WriteString("role", file.Role);
                writer.WriteNumber("lun", file.Lun);
                writer.WriteNumber("startSector", file.StartSector);
                writer.WriteNumber("sectorCount", file.SectorCount);
                writer.WriteNumber("sectorSize", file.SectorSize);

                if (file.PartUuid is null)
                {
                    writer.WriteNull("partUuid");
                }
                else
                {
                    writer.WriteString("partUuid", file.PartUuid);
                }

                writer.WriteString("relativePath", file.RelativePath);
                writer.WriteNumber("length", file.Length);
                writer.WriteString("sha256", file.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            if (state.Failure is not null)
            {
                writer.WriteString("failure", state.Failure);
            }

            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteDurableAtomic(string path, byte[] bytes)
    {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            using (FileStream stream = new(
                temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, FileBufferBytes))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                try
                {
                    File.Delete(temp);
                }
                catch (Exception)
                {
                }
            }
        }
    }

    private static async Task<(string Sha256, FileStream Stream)> OpenHashedSharedAsync(
        string path,
        CancellationToken token)
    {
        FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.SequentialScan);

        try
        {
            byte[] hash = await SHA256.HashDataAsync(stream, token).ConfigureAwait(false);
            return (Convert.ToHexString(hash), stream);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void WriteSidecar(string path, string manifestSha256)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(manifestSha256 + "\n");

        using FileStream stream = new(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, FileBufferBytes);

        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(true);
    }

    private static FileStream OpenSidecarVerified(string path, string expectedSha256)
    {
        FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.SequentialScan);

        try
        {
            using (StreamReader reader = new(
                stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true))
            {
                string text = reader.ReadToEnd().Trim();
                if (!string.Equals(text, expectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException(
                        "The manifest sidecar does not carry the verified manifest SHA-256.");
                }
            }

            stream.Position = 0;
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    // ------------------------------------------------------------------ result construction

    private static IReadOnlyDictionary<int, EdlGeometry> CopyGeometries(
        Dictionary<int, EdlGeometry> geometries) =>
        new ReadOnlyDictionary<int, EdlGeometry>(new Dictionary<int, EdlGeometry>(geometries));

    private static IReadOnlyDictionary<int, GptTable> CopyTables(Dictionary<int, GptTable> tables) =>
        new ReadOnlyDictionary<int, GptTable>(new Dictionary<int, GptTable>(tables));

    private static IReadOnlyDictionary<string, EdlCapturedRegion> BuildRegions(
        List<ManifestFileEntry> entries,
        string directory)
    {
        Dictionary<string, EdlCapturedRegion> regions = new(StringComparer.Ordinal);

        foreach (ManifestFileEntry entry in entries)
        {
            regions.Add(entry.Role, new EdlCapturedRegion(
                entry.Role,
                entry.Lun,
                entry.StartSector,
                entry.SectorCount,
                entry.SectorSize,
                entry.PartUuid,
                Path.Combine(directory, entry.RelativePath),
                entry.Length,
                entry.Sha256));
        }

        return new ReadOnlyDictionary<string, EdlCapturedRegion>(regions);
    }

    private static DiskLayout BuildLun0Layout(GptTable lun0Table, EdlGeometry lun0Geometry)
    {
        List<DiskPartition> partitions = new();

        foreach (GptPartition partition in lun0Table.Partitions)
        {
            partitions.Add(new DiskPartition(
                partition.Number,
                partition.Name,
                partition.StartSector,
                partition.SectorCount,
                partition.TypeGuid,
                partition.PartUuid));
        }

        return new DiskLayout(
            "edl:ufs:lun:0",
            lun0Geometry.SectorSize,
            new ReadOnlyCollection<DiskPartition>(partitions));
    }

    // ------------------------------------------------------------------ identity and small helpers

    private static ManifestIdentity ReadIdentity(EdlClient client, string? freshBusSerial)
    {
        AndroidMaintenanceIdentity? android = client.Binding.AndroidIdentity;
        DeviceIdentity? identity = android?.Identity;

        return new ManifestIdentity(
            identity?.Serial ?? string.Empty,
            android?.SocSerial ?? string.Empty,
            freshBusSerial ?? client.Binding.BusSerialHex,
            identity?.Model ?? client.Toolchain.Model,
            identity?.Firmware,
            client.HasInitialSaharaProof);
    }

    private static string ReadAndroidSerial(EdlClient client)
    {
        string? serial = client.Binding.AndroidIdentity?.Identity?.Serial;
        return string.IsNullOrWhiteSpace(serial) ? client.Binding.BusSerialHex : serial!;
    }

    private static void RequireProfile(ProfileSummary profile)
    {
        if (string.IsNullOrWhiteSpace(profile.ProfileId)
            || string.IsNullOrWhiteSpace(profile.Model)
            || string.IsNullOrWhiteSpace(profile.AndroidBuild)
            || string.IsNullOrWhiteSpace(profile.HardwareId))
        {
            throw new InvalidOperationException(
                "The loaded toolchain profile is incomplete; the backup profile cannot be established.");
        }
    }

    private static string SafeToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        StringBuilder builder = new(value.Length);

        foreach (char character in value)
        {
            builder.Append(char.IsLetterOrDigit(character) ? char.ToUpperInvariant(character) : '-');
        }

        string token = builder.ToString().Trim('-');
        if (token.Length == 0)
        {
            return "unknown";
        }

        return token.Length <= 32 ? token : token.Substring(0, 32);
    }

    private static bool SamePath(string? left, string right)
    {
        if (string.IsNullOrEmpty(left))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static long CheckedAdd(long left, long right, string message)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(message, exception);
        }
    }

    private static long CheckedMultiply(long left, long right, string message)
    {
        try
        {
            return checked(left * right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(message, exception);
        }
    }

    private sealed record ProfileSummary(
        string ProfileId,
        string Model,
        string AndroidBuild,
        string HardwareId);

    private sealed record ManifestIdentity(
        string AndroidSerial,
        string SocSerialDecimal,
        string BusSerialHex,
        string Model,
        FirmwareSnapshot? Firmware,
        bool HasInitialSaharaProof);

    private sealed record ManifestLun(
        int Lun,
        int SectorSize,
        long TotalSectors,
        string DiskGuid,
        string SourceFingerprint,
        IReadOnlyList<GptPartition> Partitions);

    private sealed record ManifestFileEntry(
        string Role,
        int Lun,
        long StartSector,
        long SectorCount,
        int SectorSize,
        string? PartUuid,
        string RelativePath,
        long Length,
        string Sha256);

    private sealed record PartitionTarget(int Lun, GptPartition Partition, EdlGeometry Geometry);

    private sealed record SealedFile(string Path, long Length, string Sha256, FileStream Stream);

    private sealed class BackupState
    {
        internal List<ManifestLun> Luns { get; } = new();

        internal List<ManifestFileEntry> Files { get; } = new();

        internal string Status { get; set; } = PartialStatus;

        internal string? Failure { get; set; }
    }

    private sealed class ProgressReporter
    {
        private readonly IProgress<InternalBackupProgress>? _progress;
        private long _completedBytes;
        private int _completedFiles;
        private long _totalBytes;
        private int _totalFiles;

        internal ProgressReporter(IProgress<InternalBackupProgress>? progress)
        {
            _progress = progress;
        }

        internal void Plan(int totalFiles, long totalBytes)
        {
            _totalFiles = totalFiles;
            _totalBytes = totalBytes;
        }

        internal void Completed(long bytes)
        {
            _completedBytes = CheckedAdd(_completedBytes, bytes, "The completed byte total overflows.");
            _completedFiles++;
        }

        internal void Report(string stage, string? role)
        {
            _progress?.Report(new InternalBackupProgress(
                stage,
                role,
                _completedBytes,
                _totalBytes,
                _completedFiles,
                _totalFiles));
        }

        internal void Complete(long totalBytes)
        {
            if (_totalFiles <= 0
                || _completedFiles != _totalFiles
                || _completedBytes != totalBytes
                || _totalBytes != totalBytes)
            {
                throw new InvalidOperationException(
                    "The backup cannot complete before each of the " + _totalFiles +
                    " planned files is verified with the planned byte total.");
            }

            Report(CompleteStage, role: null);
        }
    }
}

/// <summary>
/// The verified result of one internal-install backup: the exact session binding, the backup directory, the
/// parsed geometry and tables of all six LUNs, and the model's role-indexed captured regions.
/// <para>
/// Roles are exactly <c>gpt_lun0_primary</c> .. <c>gpt_lun5_backup</c> plus the partition labels of the model
/// contract (<see cref="InternalInstallBackupRoles"/>): TB322FC captures 40 labels and 52 files, TB323FU
/// captures 36 labels and 48 files because it carries no proinfo, lenovolock, lenovocust or lenovoraw; a
/// capture whose fresh tables carry efisp adds that one LUN4 label and one file.
/// userdata/super are never part of <see cref="Files"/>.
/// </para>
/// <para>
/// The metadata is immutable and stays readable after <see cref="Dispose"/>; a live set owns only the read
/// locks on the files its own factory created. It never disposes the client, the toolchain or the transport,
/// and never resets the device.
/// </para>
/// </summary>
public sealed class InternalBackupSet : IDisposable
{
    private readonly EdlEntryResult _binding;
    private readonly string _directoryPath;
    private readonly string _manifestPath;
    private readonly string _manifestSha256;
    private readonly string _profileId;
    private readonly string _model;
    private readonly string _androidBuild;
    private readonly string _hardwareId;
    private readonly IReadOnlyDictionary<int, EdlGeometry> _geometries;
    private readonly IReadOnlyDictionary<int, GptTable> _tables;
    private readonly IReadOnlyDictionary<string, EdlCapturedRegion> _files;
    private readonly DiskLayout _lun0Layout;
    private readonly List<FileStream> _locks;
    private int _disposed;

    /// <summary>Factory-only constructor. Callers only ever receive a set from <see cref="InternalInstallBackup.CreateAsync"/>.</summary>
    internal InternalBackupSet(
        EdlEntryResult binding,
        string directoryPath,
        string manifestPath,
        string manifestSha256,
        string profileId,
        string model,
        string androidBuild,
        string hardwareId,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        IReadOnlyDictionary<int, GptTable> tables,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        DiskLayout lun0Layout,
        List<FileStream> locks)
    {
        _binding = binding;
        _directoryPath = directoryPath;
        _manifestPath = manifestPath;
        _manifestSha256 = manifestSha256;
        _profileId = profileId;
        _model = model;
        _androidBuild = androidBuild;
        _hardwareId = hardwareId;
        _geometries = geometries;
        _tables = tables;
        _files = files;
        _lun0Layout = lun0Layout;
        _locks = locks;
    }

    /// <summary>Exact <see cref="EdlClient.Binding"/> of the session the backup was taken from.</summary>
    public EdlEntryResult Binding => _binding;

    /// <summary>Absolute path of the unique backup directory this factory created below the chosen parent.</summary>
    public string DirectoryPath => _directoryPath;

    /// <summary>Path of <c>backup-manifest.json</c> inside <see cref="DirectoryPath"/>.</summary>
    public string ManifestPath => _manifestPath;

    /// <summary>SHA-256 of the manifest file itself, established only after manifest and sidecar are durable.</summary>
    public string ManifestSha256 => _manifestSha256;

    /// <summary>Profile id of the loaded toolchain, for example <c>g4-9008-259</c>.</summary>
    public string ProfileId => _profileId;

    /// <summary>Model of the loaded toolchain, for example <c>TB322FC</c>.</summary>
    public string Model => _model;

    /// <summary>Android build of the loaded toolchain.</summary>
    public string AndroidBuild => _androidBuild;

    /// <summary>Hardware id the initial loader proved.</summary>
    public string HardwareId => _hardwareId;

    /// <summary>Freshly probed geometry of each of the six LUNs, keyed by LUN number.</summary>
    public IReadOnlyDictionary<int, EdlGeometry> Geometries => _geometries;

    /// <summary>Freshly parsed table of each of the six LUNs, keyed by LUN number.</summary>
    public IReadOnlyDictionary<int, GptTable> Tables => _tables;

    /// <summary>The captured regions of the model contract, keyed by role.</summary>
    public IReadOnlyDictionary<string, EdlCapturedRegion> Files => _files;

    /// <summary>
    /// LUN0 layout for the planner, with <see cref="DiskLayout.DeviceId"/> exactly
    /// <c>edl:ufs:lun:0</c>. It describes every freshly parsed LUN0 entry, including userdata, which is
    /// offered to the slider but never backed up.
    /// </summary>
    public DiskLayout Lun0Layout => _lun0Layout;

    /// <summary>
    /// Releases only the read locks this set owns. Idempotent, and it never deletes files, the manifest or
    /// the metadata, never disposes the client/toolchain and never resets the device.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (FileStream stream in _locks)
        {
            stream.Dispose();
        }

        _locks.Clear();
    }
}
