using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Reads a local original-layout global backup with the GPTs of all six UFS LUNs.
/// Schema2 excludes userdata, rawdump and metadata contents on all LUNs.
/// Schema1 retains historical coverage, excluding only <c>userdata</c> on LUN0.
/// No device I/O occurs in this type.
/// <para>
/// A set is only handed out after exhaustive local verification: the manifest hash matches its sidecar, every
/// referenced file is a plain file directly inside the directory, every compressed size and digest matches, each
/// chunk decompresses to exactly its declared length with the declared raw digest, the reconstructed GPT parses,
/// and the captured regions cover the parsed tables exactly. Anything unproven throws; nothing is repaired.
/// </para>
/// </summary>
public static partial class GlobalEdlBackup
{
    /// <summary>Maximum raw bytes of one chunk, and the value the manifest must declare.</summary>
    internal const long ChunkBytes = 67108864L;

    private const int MaxManifestBytes = 16 * 1024 * 1024;
    private const long MaxGptRegionBytes = 16L * 1024 * 1024;
    private const int CopyBufferBytes = 81920;
    private const int DigestChars = 64;

    private const string ManifestFileName = "manifest.json";
    private const string SidecarFileName = "manifest.json.sha256";
    private const string CompleteState = "complete";
    private const string GptPrimaryKind = "gpt-primary";
    private const string GptBackupKind = "gpt-backup";
    private const string PartitionKind = "partition";
    private const string UserdataName = "userdata";
    private const int SchemaVersionLegacy = 1;
    private const int SchemaVersionExclusions = 2;

    // Offsets inside a GPT header sector, exactly as the GPT specification defines them. They are re-read here
    // only after OriginalGptImporter.Parse has accepted the very same bytes, so the CRC validation has already run.
    private const int EntryArrayLbaOffset = 72;
    private const int EntryCountOffset = 80;
    private const int EntrySizeFieldOffset = 84;
    private const int GptEntrySize = 128;

    private const string LinuxRootTypeGuid = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE";
    private const string LinuxSwapTypeGuid = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";

    private const string ModelG4 = "TB322FC";
    private const string ModelG5 = "TB323FU";

    /// <summary>
    /// The one serializer configuration of the manifest: camelCase, indented, no comments or trailing commas, and
    /// unknown members are rejected instead of being silently dropped.
    /// </summary>
    internal static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>
    /// Opens and exhaustively verifies the backup in <paramref name="backupDirectory"/>. On success the returned
    /// set holds read-only leases on every verified file until it is disposed.
    /// </summary>
    /// <exception cref="ArgumentException">The directory is not an absolute path.</exception>
    /// <exception cref="DirectoryNotFoundException">The directory does not exist.</exception>
    /// <exception cref="InvalidOperationException">The directory itself is a reparse point.</exception>
    /// <exception cref="InvalidDataException">
    /// Any part of the set is missing, malformed, incomplete, mismatching or does not describe a coherent original
    /// Android layout, including a manifest above the schema size limit.
    /// </exception>
    public static async Task<GlobalEdlBackupSet> OpenAsync(
        string backupDirectory,
        IProgress<GlobalEdlProgress>? progress = null,
        CancellationToken token = default)
    {
        string directory = RequireDirectory(backupDirectory);
        token.ThrowIfCancellationRequested();

        string manifestPath = Path.Combine(directory, ManifestFileName);
        string sidecarPath = Path.Combine(directory, SidecarFileName);

        List<FileStream> leases = new();
        bool ownershipTransferred = false;

        try
        {
            // Lease the manifest pair before the first read, so no writer can replace the bytes that the
            // returned set later claims. The leases stay open through every verification step.
            leases.Add(OpenLease(manifestPath));
            leases.Add(OpenLease(sidecarPath));

            byte[] manifestBytes = await ReadBoundedFileAsync(manifestPath, MaxManifestBytes, token).ConfigureAwait(false);
            byte[] sidecarBytes = await ReadBoundedFileAsync(sidecarPath, DigestChars, token).ConfigureAwait(false);

            string manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes));
            RequireSidecar(sidecarBytes, manifestHash);

            GlobalEdlManifest manifest = DeserializeManifest(manifestBytes);
            ValidateManifestShape(manifest);
            ValidateIdentity(manifest.Identity);

            Report(progress, "verify-backup", null, null, 0, manifest.RawBytes);

            Dictionary<int, GlobalEdlLun> lunsByIndex = new();
            foreach (GlobalEdlLun lun in manifest.Luns)
            {
                lunsByIndex.Add(lun.Lun, lun);
            }

            // Chunk leases are taken before any chunk is verified, closing the same window there.
            foreach (string fileName in CollectChunkFileNames(manifest))
            {
                leases.Add(OpenLease(ResolveChunkPath(directory, fileName)));
            }

            Dictionary<int, GptTable> tables = new();
            long verifiedRaw = 0;

            for (int lunIndex = 0; lunIndex < manifest.Luns.Count; lunIndex++)
            {
                GlobalEdlLun lun = lunsByIndex[lunIndex];
                GlobalEdlRegion primaryRegion = RequireRegion(manifest, lunIndex, GptPrimaryKind);
                GlobalEdlRegion backupRegion = RequireRegion(manifest, lunIndex, GptBackupKind);

                byte[] primaryBytes = await ReadRegionRawAsync(directory, primaryRegion, token).ConfigureAwait(false);
                byte[] backupBytes = await ReadRegionRawAsync(directory, backupRegion, token).ConfigureAwait(false);

                long diskBytes = checked(lun.TotalSectors * lun.SectorSize);
                GptTable table = OriginalGptImporter.Parse(primaryBytes, backupBytes, lun.SectorSize, diskBytes);

                if (table.SectorSize != lun.SectorSize || table.DiskBytes != diskBytes)
                {
                    throw new InvalidDataException(
                        $"The decoded GPT of LUN{lunIndex} does not carry the declared sector size and disk length.");
                }

                if (!string.Equals(table.DiskGuid, lun.DiskGuid, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"The decoded GPT of LUN{lunIndex} names disk '{table.DiskGuid}', the manifest claims '{lun.DiskGuid}'.");
                }

                ValidateGptSpans(lun, primaryRegion, backupRegion, primaryBytes, backupBytes, table);

                tables.Add(lunIndex, table);

                verifiedRaw = checked(
                    verifiedRaw +
                    (primaryRegion.SectorCount * primaryRegion.SectorSize) +
                    (backupRegion.SectorCount * backupRegion.SectorSize));
                Report(progress, "verify-backup", null, lunIndex, verifiedRaw, manifest.RawBytes);
            }

            ValidateInitialLayout(tables, manifest.Identity.Model);
            ValidateRegionCoverage(manifest, tables);
            ValidateTotals(manifest);

            // A hash-consistent archive can still be useless for restore when Android was mid-update at
            // capture time: the misc virtual_ab_message must prove the merge completed.
            await RequireArchiveVirtualAbCompletedAsync(directory, manifest, token).ConfigureAwait(false);

            long verifiedCompressed = CountGptCompressedBytes(manifest);
            foreach (GlobalEdlRegion region in manifest.Regions)
            {
                if (!string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
                {
                    continue;
                }

                (verifiedCompressed, verifiedRaw) = await VerifyPartitionRegionAsync(
                    directory, region, progress, verifiedCompressed, verifiedRaw, manifest.RawBytes, token).ConfigureAwait(false);
            }

            if (verifiedCompressed != manifest.CompressedBytes)
            {
                throw new InvalidDataException("The verified compressed bytes do not match the manifest total.");
            }

            if (verifiedRaw != manifest.RawBytes)
            {
                throw new InvalidDataException("The verified raw bytes do not match the manifest total.");
            }

            int partitionCount = CountPartitions(manifest);

            GlobalEdlBackupSet set = new(
                directory,
                manifestPath,
                manifestHash,
                manifest,
                tables,
                manifest.RawBytes,
                manifest.CompressedBytes,
                partitionCount,
                leases);

            ownershipTransferred = true;
            return set;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                foreach (FileStream lease in leases)
                {
                    lease.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// Proves that the six captured GPTs still describe an untouched Android layout before any large backup is
    /// attempted: a canonical <c>userdata</c> tail on LUN0, no Linux partition or Linux-only type GUID anywhere, the
    /// per-model mandatory partitions of the initial install, and exactly one <c>super</c> on LUN0.
    /// <para>
    /// The generic Linux data GUID is deliberately not rejected: stock Android uses it for ordinary partitions.
    /// Only the Linux root and Linux swap GUIDs, the Linux/alternative-distribution names and the ARMADA family are
    /// refused.
    /// </para>
    /// </summary>
    internal static void ValidateInitialLayout(IReadOnlyDictionary<int, GptTable> tables, string model)
    {
        ArgumentNullException.ThrowIfNull(tables);

        if (tables.Count != 6)
        {
            throw new InvalidDataException(
                $"A global backup must describe exactly six LUN GPTs, found {tables.Count}.");
        }

        for (int lun = 0; lun < 6; lun++)
        {
            if (!tables.ContainsKey(lun))
            {
                throw new InvalidDataException($"The global backup is missing LUN{lun}.");
            }
        }

        GptPartition? userdata = null;

        foreach (KeyValuePair<int, GptTable> pair in tables)
        {
            foreach (GptPartition partition in pair.Value.Partitions)
            {
                RequireOriginalName(partition.Name, pair.Key);
                RequireOriginalTypeGuid(partition);

                if (!string.Equals(partition.Name, UserdataName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (userdata is not null)
                {
                    throw new InvalidDataException(
                        "More than one userdata partition is present across the six LUNs.");
                }

                if (pair.Key != 0)
                {
                    throw new InvalidDataException(
                        $"The userdata partition must live on LUN0, found it on LUN{pair.Key}.");
                }

                userdata = partition;
            }
        }

        if (userdata is null)
        {
            throw new InvalidDataException("The six GPTs carry no userdata partition on LUN0.");
        }

        if (!string.Equals(userdata.Name, UserdataName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The userdata partition name '{userdata.Name}' is not the canonical lower case name.");
        }

        GptTable lun0 = tables[0];
        long userdataEnd = checked(userdata.StartSector + userdata.SectorCount);

        if (userdataEnd != lun0.LastUsableSector + 1)
        {
            throw new InvalidDataException(
                "The userdata partition does not reach the last usable sector, so the table is not the original layout.");
        }

        foreach (GptPartition partition in lun0.Partitions)
        {
            if (ReferenceEquals(partition, userdata))
            {
                continue;
            }

            long end = checked(partition.StartSector + partition.SectorCount);
            if (end > userdata.StartSector)
            {
                throw new InvalidDataException(
                    $"LUN0 partition '{partition.Name}' extends past the start of userdata.");
            }
        }

        if (string.IsNullOrWhiteSpace(model) ||
            (!string.Equals(model, ModelG4, StringComparison.Ordinal) &&
             !string.Equals(model, ModelG5, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                $"The model '{model}' has no initial-install partition contract.");
        }

        if (!MatchesRoleContract(tables, model))
        {
            throw new InvalidDataException(
                $"The captured tables do not satisfy the initial-install partition contract of model '{model}'.");
        }

        int superCount = 0;
        foreach (GptPartition partition in lun0.Partitions)
        {
            if (string.Equals(partition.Name, "super", StringComparison.OrdinalIgnoreCase))
            {
                superCount++;
            }
        }

        if (superCount != 1)
        {
            throw new InvalidDataException(
                $"LUN0 must carry exactly one super partition, found {superCount}.");
        }
    }

    /// <summary>
    /// Returns the identity already proven by <see cref="EdlClient.Binding"/>: the offline identity when that
    /// binding carries one, otherwise the actual Android identity it reported. The result is validated and must
    /// agree with the client's known toolchain profile; nothing is fabricated.
    /// </summary>
    internal static GlobalEdlIdentity IdentityFor(EdlClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        EdlEntryResult binding = client.Binding;
        GlobalEdlIdentity identity = binding.OfflineIdentity ?? IdentityFromAndroid(binding);

        ValidateIdentity(identity);

        var toolchain = client.Toolchain;
        if (toolchain is null)
        {
            throw new InvalidOperationException("The EDL client carries no toolchain.");
        }

        EdlDeviceProfile profile = toolchain.Profile;
        if (profile is null)
        {
            throw new InvalidOperationException("The EDL toolchain carries no trusted profile.");
        }

        if (!ReferenceEquals(EdlDeviceProfiles.FindById(profile.ProfileId), profile) || !profile.IsComplete)
        {
            throw new InvalidOperationException(
                $"The EDL toolchain profile '{profile.ProfileId}' is not a complete trusted profile.");
        }

        if (!string.Equals(toolchain.ProfileId, identity.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(toolchain.Model, identity.Model, StringComparison.Ordinal) ||
            !string.Equals(toolchain.HardwareId, identity.HardwareId, StringComparison.Ordinal) ||
            !string.Equals(profile.ProfileId, identity.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(profile.Model, identity.Model, StringComparison.Ordinal) ||
            !string.Equals(profile.FullHardwareId, identity.HardwareId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The EDL toolchain does not match the bound device identity.");
        }

        return identity;
    }

    /// <summary>
    /// Verifies one chunk file end to end: exact compressed length and digest, then a full GZip decompression whose
    /// raw length and digest must match, with no trailing bytes after the member. When
    /// <paramref name="rawOutput"/> is not null the raw bytes are written to it; the caller owns that stream and is
    /// responsible for keeping the region bounded in memory.
    /// </summary>
    internal static async Task VerifyChunkAsync(
        string fullPath,
        GlobalEdlChunk chunk,
        Stream? rawOutput,
        CancellationToken token)
    {
        if (string.IsNullOrEmpty(fullPath))
        {
            throw new ArgumentException("A chunk path is required.", nameof(fullPath));
        }

        ArgumentNullException.ThrowIfNull(chunk);

        FileInfo info = new(fullPath);
        if (!info.Exists)
        {
            throw new InvalidDataException($"The backup chunk '{chunk.FileName}' is missing.");
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"The backup chunk '{chunk.FileName}' is a reparse point.");
        }

        if (info.Length != chunk.CompressedBytes)
        {
            throw new InvalidDataException(
                $"Chunk '{chunk.FileName}' is {info.Length} bytes, the manifest declares {chunk.CompressedBytes}.");
        }

        string compressedHash = await HashFileAsync(fullPath, chunk.CompressedBytes, token).ConfigureAwait(false);
        RequireDigest(compressedHash, chunk.CompressedSha256, chunk.FileName, "compressed");

        using FileStream file = new(
            fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);

        using GZipStream gzip = new(file, CompressionMode.Decompress, leaveOpen: true);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = new byte[CopyBufferBytes];
        long total = 0;

        while (true)
        {
            int read = await gzip.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total = checked(total + read);
            if (total > chunk.RawBytes)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' decompresses past its declared {chunk.RawBytes} raw bytes.");
            }

            hash.AppendData(buffer, 0, read);

            if (rawOutput is not null)
            {
                await rawOutput.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            }
        }

        if (total != chunk.RawBytes)
        {
            throw new InvalidDataException(
                $"Chunk '{chunk.FileName}' decompressed to {total} bytes, the manifest declares {chunk.RawBytes}.");
        }

        RequireDigest(Convert.ToHexString(hash.GetHashAndReset()), chunk.RawSha256, chunk.FileName, "raw");

        if (file.Position != file.Length)
        {
            throw new InvalidDataException(
                $"Chunk '{chunk.FileName}' carries {file.Length - file.Position} trailing bytes after its GZip member.");
        }
    }

    /// <summary>
    /// Atomically publishes <c>manifest.json</c> and its digest-only sidecar. Both are written to a fixed
    /// <c>.tmp</c> name next to the target and moved over it, so a reader never sees a half-written manifest and no
    /// temporary file is ever left in an unrelated location. A <c>partial</c> state may be written here, but
    /// <see cref="OpenAsync"/> refuses anything that is not <c>complete</c>.
    /// </summary>
    internal static async Task WriteManifestAsync(
        string directory,
        GlobalEdlManifest manifest,
        CancellationToken token)
    {
        string resolved = RequireDirectory(directory);
        ArgumentNullException.ThrowIfNull(manifest);

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        if (bytes.Length > MaxManifestBytes)
        {
            throw new InvalidOperationException(
                $"The manifest would be {bytes.Length} bytes, above the {MaxManifestBytes} byte schema limit.");
        }

        string manifestPath = Path.Combine(resolved, ManifestFileName);
        await WriteAtomicAsync(manifestPath, bytes, token).ConfigureAwait(false);

        byte[] digestBytes = Encoding.ASCII.GetBytes(Convert.ToHexString(SHA256.HashData(bytes)));
        await WriteAtomicAsync(Path.Combine(resolved, SidecarFileName), digestBytes, token).ConfigureAwait(false);
    }

    /// <summary>
    /// Reports one observation and swallows every exception the observer raises: a progress sink can never change
    /// the verification result.
    /// </summary>
    internal static void Report(
        IProgress<GlobalEdlProgress>? progress,
        string stage,
        string? role,
        int? lun,
        long completed,
        long total)
    {
        if (progress is null)
        {
            return;
        }

        try
        {
            progress.Report(new GlobalEdlProgress(stage, role, lun, completed, total));
        }
        catch (Exception)
        {
            // An observer is not part of the backup contract.
        }
    }

    /// <summary>
    /// Resolves an absolute, existing directory that is not itself a reparse point. A relative, missing or linked
    /// directory is rejected instead of being interpreted against the process working directory.
    /// </summary>
    internal static string RequireDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A backup directory is required.", nameof(path));
        }

        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("The backup directory must be an absolute path.", nameof(path));
        }

        string full = Path.GetFullPath(path);

        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"The backup directory '{full}' does not exist.");
        }

        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException($"The backup directory '{full}' is a reparse point.");
        }

        return full;
    }

    private static GlobalEdlIdentity IdentityFromAndroid(EdlEntryResult entry)
    {
        if (entry.AndroidIdentity is null)
        {
            throw new InvalidDataException("The EDL binding carries neither an offline identity nor an Android identity.");
        }

        DeviceIdentity identity = entry.AndroidIdentity.Identity
            ?? throw new InvalidDataException("The EDL binding carries an Android identity without a device identity.");

        EdlDeviceProfile profile = EdlDeviceProfiles.FindByModel(identity.Model)
            ?? throw new InvalidDataException(
                $"The bound Android model '{identity.Model}' has no trusted EDL profile.");

        string hardwareId = profile.FullHardwareId
            ?? throw new InvalidDataException(
                $"The trusted profile '{profile.ProfileId}' has no full hardware id to record.");

        return new GlobalEdlIdentity(
            profile.ProfileId,
            identity.Model,
            hardwareId,
            entry.BusSerialHex,
            identity.Serial,
            identity.Firmware?.DisplayId);
    }

    private static GlobalEdlManifest DeserializeManifest(byte[] manifestBytes)
    {
        try
        {
            return JsonSerializer.Deserialize<GlobalEdlManifest>(manifestBytes, JsonOptions)
                ?? throw new InvalidDataException("manifest.json is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("manifest.json is not a valid schema 1 manifest.", exception);
        }
    }

    private static void RequireSidecar(byte[] sidecarBytes, string manifestHash)
    {
        if (sidecarBytes.Length != DigestChars)
        {
            throw new InvalidDataException(
                $"The manifest sidecar must be exactly {DigestChars} hex characters, found {sidecarBytes.Length} bytes.");
        }

        string sidecar = Encoding.ASCII.GetString(sidecarBytes);

        if (!IsDigest(sidecar))
        {
            throw new InvalidDataException("The manifest sidecar is not a 64 character hex digest.");
        }

        if (!string.Equals(sidecar, manifestHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("manifest.json does not match its sidecar digest.");
        }
    }

    private static void ValidateIdentity(GlobalEdlIdentity? identity)
    {
        if (identity is null)
        {
            throw new InvalidDataException("The manifest carries no identity.");
        }

        EdlDeviceProfile? profile = EdlDeviceProfiles.FindById(identity.ProfileId);
        if (profile is null || !profile.IsComplete)
        {
            throw new InvalidDataException(
                $"The manifest profile id '{identity.ProfileId}' is not a complete trusted profile.");
        }

        if (!string.Equals(identity.Model, profile.Model, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The manifest model '{identity.Model}' does not match profile '{profile.ProfileId}'.");
        }

        if (profile.FullHardwareId is null ||
            !string.Equals(identity.HardwareId, profile.FullHardwareId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The manifest hardware id does not match profile '{profile.ProfileId}'.");
        }

        if (!IsBusSerial(identity.BusSerialHex))
        {
            throw new InvalidDataException(
                $"The manifest bus serial '{identity.BusSerialHex}' is not a usable 8 digit hex value.");
        }
    }

    private static void ValidateManifestShape(GlobalEdlManifest manifest)
    {
        if (manifest.SchemaVersion != SchemaVersionLegacy &&
            manifest.SchemaVersion != SchemaVersionExclusions)
        {
            throw new InvalidDataException(
                $"Only manifest schema 1 and schema 2 are supported, found {manifest.SchemaVersion}.");
        }

        if (!string.Equals(manifest.State, CompleteState, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The backup state '{manifest.State}' is not complete; an interrupted backup is never opened.");
        }

        if (manifest.Identity is null)
        {
            throw new InvalidDataException("The manifest carries no identity.");
        }

        if (manifest.CreatedUtc == default)
        {
            throw new InvalidDataException("The manifest carries no creation time.");
        }

        if (manifest.ChunkBytes != ChunkBytes)
        {
            throw new InvalidDataException(
                $"The manifest chunk size {manifest.ChunkBytes} is not the supported {ChunkBytes}.");
        }

        if (manifest.RawBytes <= 0 || manifest.CompressedBytes <= 0)
        {
            throw new InvalidDataException("The manifest declares no backup bytes.");
        }

        if (manifest.Luns is null || manifest.Luns.Count != 6)
        {
            throw new InvalidDataException("The manifest must declare exactly six LUNs.");
        }

        if (manifest.Regions is null || manifest.Regions.Count == 0)
        {
            throw new InvalidDataException("The manifest declares no regions.");
        }

        Dictionary<int, GlobalEdlLun> lunsByIndex = new();

        for (int index = 0; index < manifest.Luns.Count; index++)
        {
            GlobalEdlLun? lun = manifest.Luns[index];
            if (lun is null)
            {
                throw new InvalidDataException($"The manifest LUN entry {index} is missing.");
            }

            if (lun.Lun != index)
            {
                throw new InvalidDataException("The manifest LUN list must be ordered 0 through 5.");
            }

            if (lun.SectorSize != 512 && lun.SectorSize != 4096)
            {
                throw new InvalidDataException(
                    $"LUN{lun.Lun} declares an unsupported sector size {lun.SectorSize}.");
            }

            if (lun.TotalSectors <= 129)
            {
                throw new InvalidDataException(
                    $"LUN{lun.Lun} declares too few sectors for a primary and backup GPT: {lun.TotalSectors}.");
            }

            _ = checked(lun.TotalSectors * lun.SectorSize);

            if (!IsCanonicalGuid(lun.DiskGuid))
            {
                throw new InvalidDataException(
                    $"LUN{lun.Lun} declares a non-canonical disk GUID '{lun.DiskGuid}'.");
            }

            // Distinct LUN geometry is authoritative; a vendor may legitimately repeat one disk GUID.
            lunsByIndex.Add(lun.Lun, lun);
        }

        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> fileNames = new(StringComparer.Ordinal);

        foreach (GlobalEdlRegion? region in manifest.Regions)
        {
            if (region is null)
            {
                throw new InvalidDataException("The manifest carries an empty region.");
            }

            if (string.IsNullOrEmpty(region.Role) || !roles.Add(region.Role))
            {
                throw new InvalidDataException($"The region role '{region.Role}' is empty or repeated.");
            }

            if (!lunsByIndex.TryGetValue(region.Lun, out GlobalEdlLun lun))
            {
                throw new InvalidDataException($"The region '{region.Role}' names unknown LUN{region.Lun}.");
            }

            if (region.SectorSize != lun.SectorSize)
            {
                throw new InvalidDataException(
                    $"The region '{region.Role}' declares sector size {region.SectorSize}, LUN{region.Lun} uses {lun.SectorSize}.");
            }

            if (region.SectorCount <= 0 || region.StartSector < 0)
            {
                throw new InvalidDataException($"The region '{region.Role}' has an invalid sector span.");
            }

            long endSector = checked(region.StartSector + region.SectorCount);
            if (endSector > lun.TotalSectors)
            {
                throw new InvalidDataException($"The region '{region.Role}' extends past the end of LUN{region.Lun}.");
            }

            switch (region.Kind)
            {
                case GptPrimaryKind:
                    RequireRole(region, "gpt_lun" + region.Lun + "_primary");
                    RequireNoPartitionFields(region);
                    if (region.StartSector != 0)
                    {
                        throw new InvalidDataException(
                            $"The primary GPT region '{region.Role}' must start at sector 0.");
                    }

                    RequireBoundedGptRegion(region);
                    break;

                case GptBackupKind:
                    RequireRole(region, "gpt_lun" + region.Lun + "_backup");
                    RequireNoPartitionFields(region);
                    RequireBoundedGptRegion(region);
                    break;

                case PartitionKind:
                    if (region.PartitionNumber is null || region.PartitionNumber <= 0)
                    {
                        throw new InvalidDataException(
                            $"The partition region '{region.Role}' carries no partition number.");
                    }

                    if (region.PartitionName is null)
                    {
                        throw new InvalidDataException(
                            $"The partition region '{region.Role}' carries no partition name.");
                    }

                    if (!IsCanonicalGuid(region.PartUuid))
                    {
                        throw new InvalidDataException(
                            $"The partition region '{region.Role}' carries a non-canonical partition GUID.");
                    }

                    RequireRole(region, "lun" + region.Lun + "_part" + region.PartitionNumber.Value);
                    break;

                default:
                    throw new InvalidDataException(
                        $"The region '{region.Role}' declares unknown kind '{region.Kind}'.");
            }

            ValidateChunks(region, fileNames);
        }
    }

    private static void ValidateChunks(GlobalEdlRegion region, HashSet<string> fileNames)
    {
        if (region.Chunks is null || region.Chunks.Count == 0)
        {
            throw new InvalidDataException($"The region '{region.Role}' carries no chunks.");
        }

        long expectedBytes = checked(region.SectorCount * region.SectorSize);
        long offset = 0;

        for (int index = 0; index < region.Chunks.Count; index++)
        {
            GlobalEdlChunk? chunk = region.Chunks[index];
            if (chunk is null)
            {
                throw new InvalidDataException($"The region '{region.Role}' carries an empty chunk.");
            }

            if (!IsSimpleFileName(chunk.FileName) ||
                !chunk.FileName.EndsWith(".gz", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The region '{region.Role}' references a non-simple chunk name '{chunk.FileName}'.");
            }

            if (!fileNames.Add(chunk.FileName))
            {
                throw new InvalidDataException($"The chunk file '{chunk.FileName}' is referenced more than once.");
            }

            if (chunk.OffsetBytes != offset)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' starts at offset {chunk.OffsetBytes}, expected {offset}.");
            }

            if (chunk.RawBytes <= 0 || chunk.RawBytes > ChunkBytes)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' declares {chunk.RawBytes} raw bytes, outside 1..{ChunkBytes}.");
            }

            if (chunk.RawBytes % region.SectorSize != 0)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' is not a whole number of {region.SectorSize} byte sectors.");
            }

            bool isLast = index == region.Chunks.Count - 1;
            if (!isLast && chunk.RawBytes != ChunkBytes)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' is not full although more chunks follow it.");
            }

            if (chunk.CompressedBytes <= 0)
            {
                throw new InvalidDataException($"Chunk '{chunk.FileName}' declares no compressed bytes.");
            }

            if (!IsDigest(chunk.RawSha256) || !IsDigest(chunk.CompressedSha256))
            {
                throw new InvalidDataException($"Chunk '{chunk.FileName}' carries a malformed digest.");
            }

            offset = checked(offset + chunk.RawBytes);
        }

        if (offset != expectedBytes)
        {
            throw new InvalidDataException(
                $"The chunks of '{region.Role}' cover {offset} bytes, the region declares {expectedBytes}.");
        }
    }

    private static void ValidateGptSpans(
        GlobalEdlLun lun,
        GlobalEdlRegion primaryRegion,
        GlobalEdlRegion backupRegion,
        byte[] primaryBytes,
        byte[] backupBytes,
        GptTable table)
    {
        (long arrayLba, long arrayEnd) = ReadPrimaryArraySpan(primaryBytes, lun.SectorSize);
        long backupArrayLba = ReadBackupArrayLba(backupBytes, lun.SectorSize);

        if (primaryRegion.SectorCount != arrayEnd)
        {
            throw new InvalidDataException(
                $"The primary GPT region of LUN{lun.Lun} spans {primaryRegion.SectorCount} sectors, the header array ends at {arrayEnd}.");
        }

        if (backupRegion.StartSector != backupArrayLba)
        {
            throw new InvalidDataException(
                $"The backup GPT region of LUN{lun.Lun} starts at sector {backupRegion.StartSector}, the header array starts at {backupArrayLba}.");
        }

        if (checked(backupArrayLba + backupRegion.SectorCount) != lun.TotalSectors)
        {
            throw new InvalidDataException(
                $"The backup GPT region of LUN{lun.Lun} does not reach the last sector of the LUN.");
        }

        if (arrayEnd > table.FirstUsableSector)
        {
            throw new InvalidDataException(
                $"The primary GPT region of LUN{lun.Lun} reaches into the usable range.");
        }

        if (backupArrayLba <= table.LastUsableSector)
        {
            throw new InvalidDataException(
                $"The backup GPT region of LUN{lun.Lun} starts inside the usable range.");
        }

        foreach (GptPartition partition in table.Partitions)
        {
            long start = partition.StartSector;
            long end = checked(partition.StartSector + partition.SectorCount);
            if (start < arrayEnd || end > backupArrayLba)
            {
                throw new InvalidDataException(
                    $"LUN{lun.Lun} partition '{partition.Name}' overlaps a GPT fragment.");
            }
        }

        if (primaryRegion.SectorSize != lun.SectorSize || backupRegion.SectorSize != lun.SectorSize)
        {
            throw new InvalidDataException($"The GPT regions of LUN{lun.Lun} declare a foreign sector size.");
        }

        if (arrayLba < 2)
        {
            throw new InvalidDataException($"The primary GPT array of LUN{lun.Lun} is not behind the header.");
        }
    }

    private static void ValidateRegionCoverage(
        GlobalEdlManifest manifest,
        IReadOnlyDictionary<int, GptTable> tables)
    {
        bool usePolicy = manifest.SchemaVersion >= SchemaVersionExclusions;

        for (int lunIndex = 0; lunIndex < 6; lunIndex++)
        {
            GptTable table = tables[lunIndex];
            List<GlobalEdlRegion> allRegions = new();
            List<GlobalEdlRegion> partitionRegions = new();

            foreach (GlobalEdlRegion region in manifest.Regions)
            {
                if (region.Lun != lunIndex)
                {
                    continue;
                }

                allRegions.Add(region);

                if (string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
                {
                    partitionRegions.Add(region);
                }
            }

            int expected = 0;

            foreach (GptPartition partition in table.Partitions)
            {
                if (usePolicy)
                {
                    if (BackupPartitionPolicy.IsExcluded(partition.Name))
                    {
                        continue;
                    }
                }
                else if (lunIndex == 0 &&
                         string.Equals(partition.Name, UserdataName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                expected++;

                GlobalEdlRegion? match = null;
                foreach (GlobalEdlRegion region in partitionRegions)
                {
                    if (region.PartitionNumber != partition.Number)
                    {
                        continue;
                    }

                    if (match is not null)
                    {
                        throw new InvalidDataException(
                            $"LUN{lunIndex} partition {partition.Number} is captured more than once.");
                    }

                    match = region;
                }

                if (match is null)
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} partition {partition.Number} ('{partition.Name}') has no captured region.");
                }

                if (!string.Equals(match.Role, "lun" + lunIndex + "_part" + partition.Number, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} partition {partition.Number} carries the wrong region role '{match.Role}'.");
                }

                if (!string.Equals(match.PartitionName, partition.Name, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} partition {partition.Number} is named '{partition.Name}', the manifest says '{match.PartitionName}'.");
                }

                if (!string.Equals(match.PartUuid, partition.PartUuid, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} partition {partition.Number} carries a foreign partition GUID.");
                }

                if (match.StartSector != partition.StartSector ||
                    match.SectorCount != partition.SectorCount ||
                    match.SectorSize != table.SectorSize)
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} partition {partition.Number} does not match the captured extent.");
                }
            }

            if (partitionRegions.Count != expected)
            {
                throw new InvalidDataException(
                    $"LUN{lunIndex} captures {partitionRegions.Count} partitions, the table has {expected} ordinary partitions.");
            }

            allRegions.Sort((left, right) => left.StartSector.CompareTo(right.StartSector));

            for (int index = 1; index < allRegions.Count; index++)
            {
                long previousEnd = checked(allRegions[index - 1].StartSector + allRegions[index - 1].SectorCount);
                if (allRegions[index].StartSector < previousEnd)
                {
                    throw new InvalidDataException(
                        $"LUN{lunIndex} regions '{allRegions[index - 1].Role}' and '{allRegions[index].Role}' overlap.");
                }
            }
        }
    }

    private static async Task<byte[]> ReadRegionRawAsync(
        string directory,
        GlobalEdlRegion region,
        CancellationToken token)
    {
        long bytes = checked(region.SectorCount * region.SectorSize);

        if (bytes <= 0 || bytes > MaxGptRegionBytes)
        {
            throw new InvalidDataException(
                $"The GPT region '{region.Role}' declares {bytes} bytes, above the {MaxGptRegionBytes} byte limit.");
        }

        using MemoryStream buffer = new((int)bytes);

        foreach (GlobalEdlChunk chunk in region.Chunks)
        {
            if (chunk.OffsetBytes != buffer.Length)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' does not start where the region's previous chunk ended.");
            }

            long before = buffer.Length;
            await VerifyChunkAsync(ResolveChunkPath(directory, chunk.FileName), chunk, buffer, token).ConfigureAwait(false);

            if (buffer.Length - before != chunk.RawBytes)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' wrote {buffer.Length - before} bytes, the manifest declares {chunk.RawBytes}.");
            }
        }

        if (buffer.Length != bytes)
        {
            throw new InvalidDataException(
                $"The GPT region '{region.Role}' holds {buffer.Length} bytes, the region declares {bytes}.");
        }

        return buffer.ToArray();
    }

    private static async Task<(long Compressed, long Raw)> VerifyPartitionRegionAsync(
        string directory,
        GlobalEdlRegion region,
        IProgress<GlobalEdlProgress>? progress,
        long verifiedCompressed,
        long verifiedRaw,
        long rawTotal,
        CancellationToken token)
    {
        long regionRaw = checked(region.SectorCount * region.SectorSize);
        long rawInRegion = 0;

        foreach (GlobalEdlChunk chunk in region.Chunks)
        {
            await VerifyChunkAsync(ResolveChunkPath(directory, chunk.FileName), chunk, null, token).ConfigureAwait(false);
            verifiedCompressed = checked(verifiedCompressed + chunk.CompressedBytes);
            verifiedRaw = checked(verifiedRaw + chunk.RawBytes);
            rawInRegion = checked(rawInRegion + chunk.RawBytes);

            // Both counters advance only after the chunk's hash and decompression have fully passed.
            Report(progress, "verify-compression", region.Role, region.Lun, rawInRegion, regionRaw);
            Report(progress, "verify-backup", null, null, verifiedRaw, rawTotal);
        }

        return (verifiedCompressed, verifiedRaw);
    }

    private static GlobalEdlRegion RequireRegion(GlobalEdlManifest manifest, int lun, string kind)
    {
        GlobalEdlRegion? found = null;

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (region.Lun != lun || !string.Equals(region.Kind, kind, StringComparison.Ordinal))
            {
                continue;
            }

            if (found is not null)
            {
                throw new InvalidDataException($"LUN{lun} carries more than one {kind} region.");
            }

            found = region;
        }

        return found ?? throw new InvalidDataException($"LUN{lun} carries no {kind} region.");
    }

    private static IReadOnlyList<string> CollectChunkFileNames(GlobalEdlManifest manifest)
    {
        List<string> names = new();

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            foreach (GlobalEdlChunk chunk in region.Chunks)
            {
                names.Add(chunk.FileName);
            }
        }

        return names;
    }

    private static int CountPartitions(GlobalEdlManifest manifest)
    {
        int count = 0;

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }

    private static void ValidateTotals(GlobalEdlManifest manifest)
    {
        long raw = 0;
        long compressed = 0;

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            foreach (GlobalEdlChunk chunk in region.Chunks)
            {
                raw = checked(raw + chunk.RawBytes);
                compressed = checked(compressed + chunk.CompressedBytes);
            }
        }

        if (raw != manifest.RawBytes)
        {
            throw new InvalidDataException(
                $"The chunks hold {raw} raw bytes, the manifest declares {manifest.RawBytes}.");
        }

        if (compressed != manifest.CompressedBytes)
        {
            throw new InvalidDataException(
                $"The chunks hold {compressed} compressed bytes, the manifest declares {manifest.CompressedBytes}.");
        }
    }

    private static long CountGptCompressedBytes(GlobalEdlManifest manifest)
    {
        long compressed = 0;

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (GlobalEdlChunk chunk in region.Chunks)
            {
                compressed = checked(compressed + chunk.CompressedBytes);
            }
        }

        return compressed;
    }

    private static bool MatchesRoleContract(IReadOnlyDictionary<int, GptTable> tables, string model)
    {
        InternalInstallBackupRoles roles = InternalInstallBackupRoles.ForModel(model);

        foreach ((int lun, string name) in roles.Partitions)
        {
            int count = 0;

            foreach (GptPartition partition in tables[lun].Partitions)
            {
                if (string.Equals(partition.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    count++;
                }
            }

            if (count != 1)
            {
                return false;
            }
        }

        return true;
    }

    private static void RequireOriginalName(string name, int lun)
    {
        if (IsRejectedName(name))
        {
            throw new InvalidDataException(
                $"LUN{lun} carries the Linux partition name '{name}'; this is not the original Android layout.");
        }
    }

    private static bool IsRejectedName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        string[] prefixes = { "armada_", "rocknix", "linux", "rootfs", "swap" };

        foreach (string prefix in prefixes)
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void RequireOriginalTypeGuid(GptPartition partition)
    {
        string typeGuid = partition.TypeGuid;

        // The generic Linux data GUID (0FC63DAF-...) is intentionally accepted: stock Android uses it for
        // ordinary partitions. Only the Linux root and Linux swap GUIDs mark a foreign layout.
        if (string.Equals(typeGuid, LinuxRootTypeGuid, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(typeGuid, LinuxSwapTypeGuid, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Partition '{partition.Name}' uses the Linux type GUID {typeGuid}; this is not the original Android layout.");
        }
    }

    private static void RequireRole(GlobalEdlRegion region, string expected)
    {
        if (!string.Equals(region.Role, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The region role '{region.Role}' is not the expected '{expected}'.");
        }
    }

    private static void RequireNoPartitionFields(GlobalEdlRegion region)
    {
        if (region.PartitionNumber is not null || region.PartitionName is not null || region.PartUuid is not null)
        {
            throw new InvalidDataException(
                $"The GPT region '{region.Role}' carries partition metadata.");
        }
    }

    private static void RequireBoundedGptRegion(GlobalEdlRegion region)
    {
        long bytes = checked(region.SectorCount * region.SectorSize);
        if (bytes > MaxGptRegionBytes)
        {
            throw new InvalidDataException(
                $"The GPT region '{region.Role}' declares {bytes} bytes, above the {MaxGptRegionBytes} byte limit.");
        }
    }

    private static (long ArrayLba, long ArrayEnd) ReadPrimaryArraySpan(byte[] fragment, int sectorSize)
    {
        if (fragment.Length < sectorSize * 2)
        {
            throw new InvalidDataException("The primary GPT fragment does not hold a header sector.");
        }

        return ReadArraySpan(fragment.AsSpan(sectorSize, sectorSize), sectorSize);
    }

    private static long ReadBackupArrayLba(byte[] fragment, int sectorSize)
    {
        if (fragment.Length < sectorSize * 2)
        {
            throw new InvalidDataException("The backup GPT fragment does not hold a header sector.");
        }

        (long arrayLba, _) = ReadArraySpan(fragment.AsSpan(fragment.Length - sectorSize, sectorSize), sectorSize);
        return arrayLba;
    }

    private static (long ArrayLba, long ArrayEnd) ReadArraySpan(ReadOnlySpan<byte> header, int sectorSize)
    {
        ulong lba = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(EntryArrayLbaOffset, 8));
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(EntryCountOffset, 4));
        uint entrySize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(EntrySizeFieldOffset, 4));

        if (lba > long.MaxValue || count == 0 || entrySize != GptEntrySize)
        {
            throw new InvalidDataException("The GPT header does not carry a supported entry array.");
        }

        long arrayBytes = checked((long)count * entrySize);
        long arraySectors = (arrayBytes + sectorSize - 1) / sectorSize;

        return ((long)lba, checked((long)lba + arraySectors));
    }

    private static string ResolveChunkPath(string directory, string fileName)
    {
        if (!IsSimpleFileName(fileName))
        {
            throw new InvalidDataException($"The chunk name '{fileName}' is not a plain file name.");
        }

        string full = Path.Combine(directory, fileName);
        FileInfo info = new(full);

        if (!info.Exists)
        {
            throw new InvalidDataException($"The backup chunk '{fileName}' is missing.");
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"The backup chunk '{fileName}' is a reparse point.");
        }

        return full;
    }

    private static FileStream OpenLease(string path)
    {
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.None);
    }

    private static async Task<byte[]> ReadBoundedFileAsync(string path, int maxBytes, CancellationToken token)
    {
        FileInfo info = new(path);

        if (!info.Exists)
        {
            throw new InvalidDataException($"The backup file '{Path.GetFileName(path)}' is missing.");
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"The backup file '{Path.GetFileName(path)}' is a reparse point.");
        }

        if (info.Length > maxBytes)
        {
            throw new InvalidDataException(
                $"The backup file '{Path.GetFileName(path)}' is {info.Length} bytes, above the {maxBytes} byte limit.");
        }

        byte[] buffer = new byte[info.Length];

        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);

        int offset = 0;

        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), token).ConfigureAwait(false);
            if (read == 0)
            {
                throw new InvalidDataException($"The backup file '{Path.GetFileName(path)}' ended early.");
            }

            offset += read;
        }

        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException($"The backup file '{Path.GetFileName(path)}' grew while it was read.");
        }

        return buffer;
    }

    private static async Task<string> HashFileAsync(string path, long expectedBytes, CancellationToken token)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = new byte[CopyBufferBytes];
        long total = 0;

        while (true)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total = checked(total + read);
            hash.AppendData(buffer, 0, read);
        }

        if (total != expectedBytes)
        {
            throw new InvalidDataException(
                $"'{Path.GetFileName(path)}' is {total} bytes, the manifest declares {expectedBytes}.");
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static async Task WriteAtomicAsync(string targetPath, byte[] bytes, CancellationToken token)
    {
        string temporaryPath = targetPath + ".tmp";

        using (FileStream stream = new(
            temporaryPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            CopyBufferBytes,
            FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporaryPath, targetPath, overwrite: true);
    }

    private static void RequireDigest(string actual, string? expected, string fileName, string kind)
    {
        if (!IsDigest(expected) || !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The {kind} digest of chunk '{fileName}' does not match the manifest.");
        }
    }

    private static bool IsSimpleFileName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 255)
        {
            return false;
        }

        if (!string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            return false;
        }

        if (name == "." || name == "..")
        {
            return false;
        }

        foreach (char character in name)
        {
            if (character == ':' || char.IsControl(character) || character == '/' || character == '\\')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsDigest(string? value)
    {
        if (value is null || value.Length != DigestChars)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBusSerial(string? value)
    {
        if (value is null || value.Length != 8)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!IsHexDigit(character))
            {
                return false;
            }
        }

        string normalized = value.ToUpperInvariant();
        return normalized != "00000000" && normalized != "FFFFFFFF";
    }

    private static bool IsHexDigit(char character) =>
        (character >= '0' && character <= '9') ||
        (character >= 'a' && character <= 'f') ||
        (character >= 'A' && character <= 'F');

    private static bool IsCanonicalGuid(string? value)
    {
        if (string.IsNullOrEmpty(value) || !Guid.TryParse(value, out Guid parsed) || parsed == Guid.Empty)
        {
            return false;
        }

        return string.Equals(
            value,
            parsed.ToString("D", CultureInfo.InvariantCulture).ToUpperInvariant(),
            StringComparison.Ordinal);
    }
}
