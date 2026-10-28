using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Original-layout global capture. Every region is read from the device with explicit, sector-aligned
/// spans, compressed into sequential GZip chunks and proven by a full decompression/hash pass before the
/// manifest advances. Nothing here writes to the device, resets the device or deletes anything outside the
/// work files this run created.
/// </summary>
public static partial class GlobalEdlBackup
{
    private const int CaptureLunCount = 6;
    private const long CaptureMaxGptFragmentBytes = 16L * 1024 * 1024;
    private const long CaptureMaxEntryArrayBytes = 4L * 1024 * 1024;
    private const long CaptureSpaceMarginBytes = 32L * 1024 * 1024;
    private const int CaptureStreamBufferBytes = 128 * 1024;
    private const string CaptureStatePartial = "partial";
    private const string CaptureStateComplete = "complete";
    private const string CaptureKindPartition = "partition";
    private const string CaptureRoleGptPrimary = "gpt-primary";
    private const string CaptureRoleGptBackup = "gpt-backup";

    private static readonly uint[] CaptureCrc32Table = CaptureCreateCrc32Table();

    /// <summary>
    /// Captures a complete original-layout backup of all six LUNs below <paramref name="chosenParent"/>,
    /// publishing <c>manifest.json</c> only as <c>partial</c> until every chunk has been verified and the
    /// backup has been reopened by <see cref="OpenAsync"/>.
    /// </summary>
    /// <param name="client">Connected client; it is only ever read from.</param>
    /// <param name="chosenParent">Absolute, existing directory that will receive the new backup directory.</param>
    /// <param name="progress">Optional progress sink; faults raised by it are ignored.</param>
    /// <param name="token">Cancellation token; cancellation keeps every file produced so far.</param>
    public static async Task<GlobalEdlBackupSet> CreateAsync(
        EdlClient client,
        string chosenParent,
        IProgress<GlobalEdlProgress>? progress = null,
        CancellationToken token = default)
    {
        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        GlobalEdlIdentity identity = IdentityFor(client);
        if (identity is null)
        {
            throw new InvalidOperationException(
                "The connected device has no offline identity, so the global backup scope is unknown.");
        }

        string model = client.Toolchain?.Model ?? string.Empty;
        if (string.IsNullOrWhiteSpace(model))
        {
            throw new InvalidOperationException(
                "The connected device does not report a known model; refusing to capture a global backup with an unknown layout scope.");
        }

        token.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(identity.BusSerialHex))
        {
            throw new InvalidOperationException(
                "The connected device identity carries no verified bus serial, so the global backup cannot be named.");
        }

        string parent = CaptureResolveParent(chosenParent);
        string unique = Guid.NewGuid().ToString("N");
        string directory = Path.Combine(parent, "global-backup-" + identity.BusSerialHex + "-" + unique);
        Directory.CreateDirectory(directory);

        string workDirectory = Path.Combine(directory, "work");
        string logDirectory = Path.Combine(directory, "logs");
        Directory.CreateDirectory(workDirectory);
        Directory.CreateDirectory(logDirectory);
        RequireDirectory(workDirectory);
        RequireDirectory(logDirectory);

        GlobalEdlManifest manifest = new()
        {
            SchemaVersion = 2,
            State = CaptureStatePartial,
            Identity = identity,
            CreatedUtc = DateTimeOffset.UtcNow,
            ChunkBytes = ChunkBytes,
            RawBytes = 0,
            CompressedBytes = 0,
            Luns = new List<GlobalEdlLun>(CaptureLunCount),
            Regions = new List<GlobalEdlRegion>()
        };

        bool completed = false;
        try
        {
            await WriteManifestAsync(directory, manifest, token).ConfigureAwait(false);

            // ---- stage 1: raw geometry of all six LUNs -------------------------------------------
            EdlGeometry[] geometries = new EdlGeometry[CaptureLunCount];

            for (int lun = 0; lun < CaptureLunCount; lun++)
            {
                token.ThrowIfCancellationRequested();

                bool initialLoader = lun == 0 && !client.HasInitialSaharaProof;
                string probeFile = Path.Combine(workDirectory, "probe-lun" + CaptureText(lun) + ".bin");
                CaptureReport(progress, "probe", null, lun, 0, 0);

                EdlProbeEvidence evidence = await client
                    .ProbeRawGeometryAsync(lun, initialLoader, probeFile, token)
                    .ConfigureAwait(false);

                if (evidence is null || evidence.Geometry is null)
                {
                    throw new InvalidDataException("LUN " + CaptureText(lun) + ": raw geometry probe returned no geometry.");
                }

                EdlGeometry geometry = evidence.Geometry;
                if (geometry.Lun != lun)
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": raw geometry probe reported LUN " + CaptureText(geometry.Lun) + ".");
                }

                if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": unsupported sector size " + CaptureText(geometry.SectorSize)
                        + "; only 512 or 4096 is accepted.");
                }

                if (geometry.TotalSectors <= 129)
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": geometry reports only " + CaptureText(geometry.TotalSectors) + " sectors.");
                }

                geometries[lun] = geometry;

                string probeBusSerial = evidence.BusSerialHex;
                if (string.IsNullOrEmpty(probeBusSerial)
                    || !string.Equals(probeBusSerial, identity.BusSerialHex, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": raw geometry probe bus serial does not match the verified device identity.");
                }
            }

            // ---- stage 2: exact GPT metadata of all LUNs before any ordinary partition read -------
            Dictionary<int, GptTable> tables = new(CaptureLunCount);
            Dictionary<int, long> primarySectors = new(CaptureLunCount);
            Dictionary<int, long> backupSectors = new(CaptureLunCount);
            Dictionary<int, string> primaryFiles = new(CaptureLunCount);
            Dictionary<int, string> backupFiles = new(CaptureLunCount);

            CaptureReport(progress, "read-gpt", null, null, 0, 0);

            for (int lun = 0; lun < CaptureLunCount; lun++)
            {
                token.ThrowIfCancellationRequested();

                EdlGeometry geometry = geometries[lun];
                int sectorSize = geometry.SectorSize;
                long totalSectors = geometry.TotalSectors;

                string primaryHeaderFile = Path.Combine(workDirectory, "gpt-lun" + CaptureText(lun) + "-header-primary.bin");
                string backupHeaderFile = Path.Combine(workDirectory, "gpt-lun" + CaptureText(lun) + "-header-backup.bin");

                EdlReadEvidence primaryHeaderRead = await client
                    .ReadAsync(lun, 0, 2, primaryHeaderFile, null, CaptureLogPath(logDirectory, lun, "header-primary"), token)
                    .ConfigureAwait(false);
                CaptureExpectRead(primaryHeaderRead, 2L * sectorSize, "LUN " + CaptureText(lun) + " primary header");

                EdlReadEvidence backupHeaderRead = await client
                    .ReadAsync(lun, totalSectors - 1, 1, backupHeaderFile, null, CaptureLogPath(logDirectory, lun, "header-backup"), token)
                    .ConfigureAwait(false);
                CaptureExpectRead(backupHeaderRead, sectorSize, "LUN " + CaptureText(lun) + " backup header");

                byte[] primaryHeaderBytes = CaptureReadAllBytes(primaryHeaderFile, 2L * sectorSize);
                byte[] backupHeaderBytes = CaptureReadAllBytes(backupHeaderFile, sectorSize);

                CaptureGptHeader primaryHeader = CaptureDecodeHeader(
                    new ReadOnlySpan<byte>(primaryHeaderBytes, sectorSize, sectorSize),
                    sectorSize,
                    primary: true,
                    myLba: 1,
                    altLba: totalSectors - 1,
                    totalSectors: totalSectors);

                CaptureGptHeader backupHeader = CaptureDecodeHeader(
                    new ReadOnlySpan<byte>(backupHeaderBytes, 0, sectorSize),
                    sectorSize,
                    primary: false,
                    myLba: totalSectors - 1,
                    altLba: 1,
                    totalSectors: totalSectors);

                if (primaryHeader.FirstUsable != backupHeader.FirstUsable
                    || primaryHeader.LastUsable != backupHeader.LastUsable
                    || primaryHeader.DiskGuid != backupHeader.DiskGuid)
                {
                    throw new InvalidDataException("LUN " + CaptureText(lun) + ": primary and backup GPT headers disagree.");
                }

                long primaryCount = checked(primaryHeader.EntryLba + primaryHeader.ArraySectors);
                long primaryBytes = checked(primaryCount * sectorSize);
                if (primaryBytes > CaptureMaxGptFragmentBytes)
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": primary GPT fragment of " + CaptureText(primaryBytes) + " bytes exceeds the 16 MiB bound.");
                }

                long backupCount = totalSectors - backupHeader.EntryLba;
                long backupBytes = checked(backupCount * sectorSize);
                if (backupBytes > CaptureMaxGptFragmentBytes)
                {
                    throw new InvalidDataException(
                        "LUN " + CaptureText(lun) + ": backup GPT fragment of " + CaptureText(backupBytes) + " bytes exceeds the 16 MiB bound.");
                }

                string primaryFile = Path.Combine(workDirectory, "gpt-lun" + CaptureText(lun) + "-primary.bin");
                string backupFile = Path.Combine(workDirectory, "gpt-lun" + CaptureText(lun) + "-backup.bin");

                EdlReadEvidence primaryRead = await client
                    .ReadAsync(lun, 0, primaryCount, primaryFile, null, CaptureLogPath(logDirectory, lun, "gpt-primary"), token)
                    .ConfigureAwait(false);
                CaptureExpectRead(primaryRead, primaryBytes, "LUN " + CaptureText(lun) + " primary GPT fragment");

                EdlReadEvidence backupRead = await client
                    .ReadAsync(lun, backupHeader.EntryLba, backupCount, backupFile, null, CaptureLogPath(logDirectory, lun, "gpt-backup"), token)
                    .ConfigureAwait(false);
                CaptureExpectRead(backupRead, backupBytes, "LUN " + CaptureText(lun) + " backup GPT fragment");

                byte[] primaryFragment = CaptureReadAllBytes(primaryFile, primaryBytes);
                byte[] backupFragment = CaptureReadAllBytes(backupFile, backupBytes);

                GptTable table;
                try
                {
                    table = OriginalGptImporter.Parse(
                        primaryFragment,
                        backupFragment,
                        sectorSize,
                        checked(totalSectors * (long)sectorSize));
                }
                catch (Exception ex) when (ex is InvalidDataException or ArgumentException or FormatException)
                {
                    throw new InvalidDataException("LUN " + CaptureText(lun) + ": original GPT import failed: " + ex.Message, ex);
                }

                if (table is null)
                {
                    throw new InvalidDataException("LUN " + CaptureText(lun) + ": original GPT import returned no table.");
                }

                if (string.IsNullOrWhiteSpace(table.DiskGuid))
                {
                    throw new InvalidDataException("LUN " + CaptureText(lun) + ": original GPT table has no disk GUID.");
                }

                tables[lun] = table;
                primarySectors[lun] = primaryCount;
                backupSectors[lun] = backupCount;
                primaryFiles[lun] = primaryFile;
                backupFiles[lun] = backupFile;
            }

            // Rejects any Linux/ARMADA layout, requires userdata to end at LastUsable with no partition after it,
            // and requires the mandatory system roles (super included).
            ValidateInitialLayout(tables, model);

            // The misc probe proves the last Android update is fully merged (virtual A/B Completed) before
            // any manifest region is planned or any large partition is read. COW snapshots can depend on
            // userdata, which this backup deliberately excludes, so an unconfirmed update is not a backup.
            await CaptureRequireCompletedVirtualAbAsync(
                client,
                tables,
                geometries,
                workDirectory,
                logDirectory,
                progress,
                token).ConfigureAwait(false);

            // ---- stage 3: manifest regions and the raw plan --------------------------------------
            List<string?> gptSources = new();
            long plannedRaw = 0;

            for (int lun = 0; lun < CaptureLunCount; lun++)
            {
                EdlGeometry geometry = geometries[lun];
                GptTable table = tables[lun];

                manifest.Luns.Add(new GlobalEdlLun
                {
                    Lun = lun,
                    SectorSize = geometry.SectorSize,
                    TotalSectors = geometry.TotalSectors,
                    DiskGuid = table.DiskGuid
                });

                GlobalEdlRegion primaryRegion = CaptureCreateGptRegion(
                    lun, CaptureRoleGptPrimary, 0, primarySectors[lun], geometry.SectorSize);
                manifest.Regions.Add(primaryRegion);
                gptSources.Add(primaryFiles[lun]);
                plannedRaw = checked(plannedRaw + checked(primaryRegion.SectorCount * geometry.SectorSize));

                long backupStart = geometry.TotalSectors - backupSectors[lun];
                GlobalEdlRegion backupRegion = CaptureCreateGptRegion(
                    lun, CaptureRoleGptBackup, backupStart, backupSectors[lun], geometry.SectorSize);
                manifest.Regions.Add(backupRegion);
                gptSources.Add(backupFiles[lun]);
                plannedRaw = checked(plannedRaw + checked(backupRegion.SectorCount * geometry.SectorSize));

                foreach (GptPartition partition in table.Partitions)
                {
                    token.ThrowIfCancellationRequested();

                    string name = partition.Name ?? string.Empty;
                    if (BackupPartitionPolicy.IsExcluded(name))
                    {
                        // Excluded payloads (userdata, rawdump, metadata, any case) are never read or backed up on
                        // any LUN; only the GPT entry is kept so the layout is still fully captured.
                        continue;
                    }

                    if (partition.SectorCount <= 0)
                    {
                        throw new InvalidDataException(
                            "LUN " + CaptureText(lun) + " partition " + CaptureText(partition.Number) + " has no sectors.");
                    }

                    GlobalEdlRegion region = new()
                    {
                        Role = "lun" + CaptureText(lun) + "_part" + CaptureText(partition.Number),
                        Kind = CaptureKindPartition,
                        Lun = lun,
                        StartSector = partition.StartSector,
                        SectorCount = partition.SectorCount,
                        SectorSize = geometry.SectorSize,
                        PartitionNumber = partition.Number,
                        PartitionName = name.Length == 0 ? null : name,
                        PartUuid = partition.PartUuid,
                        Chunks = new List<GlobalEdlChunk>()
                    };

                    manifest.Regions.Add(region);
                    gptSources.Add(null);
                    plannedRaw = checked(plannedRaw + checked(region.SectorCount * geometry.SectorSize));
                }
            }

            manifest.RawBytes = plannedRaw;
            CaptureReport(progress, "read-gpt", null, null, 0, plannedRaw);

            CaptureEnsureSpace(directory, plannedRaw);

            // ---- stage 4: capture every region in manifest order ---------------------------------
            long regionBaseRaw = 0;
            for (int index = 0; index < manifest.Regions.Count; index++)
            {
                token.ThrowIfCancellationRequested();

                GlobalEdlRegion region = manifest.Regions[index];
                long regionRaw = checked(region.SectorCount * region.SectorSize);

                await CaptureRegionAsync(
                    client,
                    directory,
                    workDirectory,
                    logDirectory,
                    region,
                    gptSources[index],
                    index,
                    manifest,
                    plannedRaw,
                    regionBaseRaw,
                    progress,
                    token).ConfigureAwait(false);

                regionBaseRaw = checked(regionBaseRaw + regionRaw);
            }

            // ---- stage 5: publish and reopen -----------------------------------------------------
            manifest.State = CaptureStateComplete;
            await WriteManifestAsync(directory, manifest, token).ConfigureAwait(false);

            GlobalEdlBackupSet set = await OpenAsync(directory, progress, token).ConfigureAwait(false);
            completed = true;

            CaptureReport(progress, "completed", null, null, manifest.RawBytes, manifest.RawBytes);
            return set;
        }
        catch
        {
            if (!completed)
            {
                manifest.State = CaptureStatePartial;
                try
                {
                    await WriteManifestAsync(directory, manifest, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // Best effort only: never mask the original failure.
                }
            }

            throw;
        }
    }

    private static GlobalEdlRegion CaptureCreateGptRegion(int lun, string role, long startSector, long sectorCount, int sectorSize)
    {
        return new GlobalEdlRegion
        {
            Role = "gpt_lun" + CaptureText(lun)
                + (string.Equals(role, CaptureRoleGptPrimary, StringComparison.Ordinal) ? "_primary" : "_backup"),
            Kind = role,
            Lun = lun,
            StartSector = startSector,
            SectorCount = sectorCount,
            SectorSize = sectorSize,
            PartitionNumber = null,
            PartitionName = null,
            PartUuid = null,
            Chunks = new List<GlobalEdlChunk>()
        };
    }

    private static async Task CaptureRegionAsync(
        EdlClient client,
        string directory,
        string workDirectory,
        string logDirectory,
        GlobalEdlRegion region,
        string? gptSourcePath,
        int regionIndex,
        GlobalEdlManifest manifest,
        long plannedRaw,
        long regionBaseRaw,
        IProgress<GlobalEdlProgress>? progress,
        CancellationToken token)
    {
        int sectorSize = region.SectorSize;
        long chunkSectors = ChunkBytes / sectorSize;
        if (chunkSectors < 1)
        {
            throw new InvalidOperationException("Chunk size is smaller than one sector of " + CaptureText(sectorSize) + " bytes.");
        }

        long chunkCount = (region.SectorCount / chunkSectors) + (region.SectorCount % chunkSectors == 0 ? 0 : 1);

        for (long chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++)
        {
            token.ThrowIfCancellationRequested();

            long offsetSectors = chunkIndex * chunkSectors;
            long sectors = Math.Min(chunkSectors, region.SectorCount - offsetSectors);
            long offsetBytes = checked(offsetSectors * sectorSize);
            long rawBytes = checked(sectors * sectorSize);

            string rawPath = Path.Combine(
                workDirectory,
                "capture-r" + CaptureText(regionIndex) + "-c" + CaptureText(chunkIndex) + ".raw");

            string rawSha;

            if (gptSourcePath is null)
            {
                CaptureTransferProgress adapter = new(
                    progress,
                    "read-partition",
                    region.Role,
                    region.Lun,
                    checked(regionBaseRaw + offsetBytes),
                    plannedRaw);

                EdlReadEvidence evidence = await client
                    .ReadAsync(
                        region.Lun,
                        checked(region.StartSector + offsetSectors),
                        sectors,
                        rawPath,
                        adapter,
                        CaptureLogPath(logDirectory, region.Lun, "r" + CaptureText(regionIndex) + "-c" + CaptureText(chunkIndex)),
                        token)
                    .ConfigureAwait(false);

                CaptureExpectRead(evidence, rawBytes, "LUN " + CaptureText(region.Lun) + " " + region.Role + " chunk " + CaptureText(chunkIndex));
                rawSha = CaptureNormalizeSha(evidence.Sha256, "device read");
            }
            else
            {
                rawSha = await CaptureSliceAsync(gptSourcePath, offsetBytes, rawBytes, rawPath, token).ConfigureAwait(false);
            }

            string baseName = "lun"
                + CaptureText(region.Lun) + "-"
                + CaptureSanitize(region.Role) + "-r"
                + CaptureText(regionIndex) + "-c"
                + CaptureText(chunkIndex) + ".gz";

            string partPath = Path.Combine(directory, baseName + ".part");
            string finalPath = Path.Combine(directory, baseName);

            long compressedLength;
            string compressedSha;

            long chunkStart = checked(regionBaseRaw + offsetBytes);
            long chunkDone = checked(chunkStart + rawBytes);

            CaptureReport(progress, "compress", region.Role, region.Lun, chunkStart, plannedRaw);

            using (FileStream rawStream = new(
                rawPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                CaptureStreamBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                using (FileStream partStream = new(
                    partPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    CaptureStreamBufferBytes,
                    FileOptions.Asynchronous))
                {
                    using (GZipStream gzip = new(partStream, CompressionLevel.Fastest, leaveOpen: true))
                    {
                        await rawStream.CopyToAsync(gzip, CaptureStreamBufferBytes, token).ConfigureAwait(false);
                        await gzip.FlushAsync(token).ConfigureAwait(false);
                    }

                    await partStream.FlushAsync(token).ConfigureAwait(false);
                    partStream.Flush(true);
                }
            }

            CaptureReport(progress, "compress", region.Role, region.Lun, chunkDone, plannedRaw);

            using (FileStream check = new(
                partPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CaptureStreamBufferBytes,
                FileOptions.SequentialScan))
            {
                compressedLength = check.Length;
                compressedSha = Convert.ToHexString(await SHA256.HashDataAsync(check, token).ConfigureAwait(false));
            }

            GlobalEdlChunk chunk = new()
            {
                FileName = baseName,
                OffsetBytes = offsetBytes,
                RawBytes = rawBytes,
                RawSha256 = rawSha,
                CompressedBytes = compressedLength,
                CompressedSha256 = compressedSha
            };

            CaptureReport(progress, "verify-compression", region.Role, region.Lun, chunkStart, plannedRaw);

            await VerifyChunkAsync(partPath, chunk, null, token).ConfigureAwait(false);

            CaptureReport(progress, "verify-compression", region.Role, region.Lun, chunkDone, plannedRaw);

            File.Move(partPath, finalPath);

            region.Chunks.Add(chunk);
            manifest.CompressedBytes = checked(manifest.CompressedBytes + compressedLength);
            await WriteManifestAsync(directory, manifest, token).ConfigureAwait(false);

            // The chunk is compressed, verified and durable in the manifest; the raw work copy is owned by this run
            // and must go, otherwise a failed run keeps growing by a chunk-sized 64 MiB each time.
            File.Delete(rawPath);
        }
    }

    private static async Task<string> CaptureSliceAsync(
        string sourcePath,
        long offset,
        long length,
        string destinationPath,
        CancellationToken token)
    {
        if (length <= 0 || length > CaptureMaxGptFragmentBytes)
        {
            throw new InvalidDataException("GPT work slice of " + CaptureText(length) + " bytes is outside the supported bound.");
        }

        byte[] buffer = new byte[checked((int)length)];

        using (FileStream source = new(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CaptureStreamBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            source.Seek(offset, SeekOrigin.Begin);

            int read = 0;
            while (read < buffer.Length)
            {
                int value = await source
                    .ReadAsync(buffer.AsMemory(read, buffer.Length - read), token)
                    .ConfigureAwait(false);
                if (value <= 0)
                {
                    throw new EndOfStreamException("GPT work file ended before the planned fragment could be sliced.");
                }

                read += value;
            }
        }

        using (FileStream destination = new(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            CaptureStreamBufferBytes,
            FileOptions.Asynchronous))
        {
            await destination.WriteAsync(buffer, token).ConfigureAwait(false);
            await destination.FlushAsync(token).ConfigureAwait(false);
            destination.Flush(true);
        }

        return Convert.ToHexString(SHA256.HashData(buffer));
    }

    private static byte[] CaptureReadAllBytes(string path, long expectedLength)
    {
        if (expectedLength <= 0 || expectedLength > CaptureMaxGptFragmentBytes)
        {
            throw new InvalidDataException("Requested work file length of " + CaptureText(expectedLength) + " bytes is outside the supported bound.");
        }

        using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CaptureStreamBufferBytes,
            FileOptions.SequentialScan);

        if (stream.Length != expectedLength)
        {
            throw new InvalidDataException(
                "Work file " + Path.GetFileName(path) + " holds " + CaptureText(stream.Length) + " bytes, expected " + CaptureText(expectedLength) + ".");
        }

        byte[] buffer = new byte[checked((int)expectedLength)];
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new EndOfStreamException("Work file " + Path.GetFileName(path) + " ended early.");
            }

            offset += read;
        }

        return buffer;
    }

    private static void CaptureExpectRead(EdlReadEvidence evidence, long expectedBytes, string what)
    {
        if (evidence is null)
        {
            throw new InvalidOperationException(what + ": device read returned no evidence.");
        }

        if (evidence.Length != expectedBytes)
        {
            throw new InvalidDataException(what + ": device read produced " + CaptureText(evidence.Length) + " bytes, expected " + CaptureText(expectedBytes) + ".");
        }

        if (string.IsNullOrWhiteSpace(evidence.Sha256))
        {
            throw new InvalidDataException(what + ": device read returned no SHA-256.");
        }
    }

    private static string CaptureNormalizeSha(string? value, string what)
    {
        if (value is null || value.Length != 64)
        {
            throw new InvalidDataException(what + ": SHA-256 is missing or malformed.");
        }

        for (int index = 0; index < value.Length; index++)
        {
            char c = value[index];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex)
            {
                throw new InvalidDataException(what + ": SHA-256 is not hexadecimal.");
            }
        }

        return value.ToUpperInvariant();
    }

    private static CaptureGptHeader CaptureDecodeHeader(
        ReadOnlySpan<byte> sector,
        int sectorSize,
        bool primary,
        long myLba,
        long altLba,
        long totalSectors)
    {
        if (sectorSize < 512 || sector.Length < sectorSize)
        {
            throw new InvalidDataException("GPT header sector is too small.");
        }

        if (!sector.Slice(0, 8).SequenceEqual("EFI PART"u8))
        {
            throw new InvalidDataException("GPT header signature 'EFI PART' is missing.");
        }

        uint revision = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(8, 4));
        if (revision != 0x00010000u)
        {
            throw new InvalidDataException("Unsupported GPT revision 0x" + revision.ToString("X8", CultureInfo.InvariantCulture) + ".");
        }

        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(12, 4));
        if (headerSize < 92u || headerSize > (uint)sectorSize || headerSize > (uint)sector.Length)
        {
            throw new InvalidDataException("GPT header size " + CaptureText(headerSize) + " is outside 92.." + CaptureText(sectorSize) + ".");
        }

        uint reserved = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(20, 4));
        if (reserved != 0u)
        {
            throw new InvalidDataException("GPT header reserved field is not zero.");
        }

        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(16, 4));
        byte[] headerCopy = sector.Slice(0, (int)headerSize).ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(headerCopy.AsSpan(16, 4), 0u);
        if (CaptureCrc32(headerCopy) != storedCrc)
        {
            throw new InvalidDataException("GPT header CRC32 does not match the header bytes.");
        }

        long headerMyLba = CaptureReadU64(sector.Slice(24, 8), "MyLBA");
        long headerAltLba = CaptureReadU64(sector.Slice(32, 8), "AlternateLBA");
        if (headerMyLba != myLba || headerAltLba != altLba)
        {
            throw new InvalidDataException(
                "GPT header points at MyLBA " + CaptureText(headerMyLba) + " / AlternateLBA " + CaptureText(headerAltLba)
                + ", expected " + CaptureText(myLba) + " / " + CaptureText(altLba) + ".");
        }

        long firstUsable = CaptureReadU64(sector.Slice(40, 8), "FirstUsableLBA");
        long lastUsable = CaptureReadU64(sector.Slice(48, 8), "LastUsableLBA");
        if (firstUsable < 2 || lastUsable < firstUsable || lastUsable >= totalSectors)
        {
            throw new InvalidDataException(
                "GPT usable range " + CaptureText(firstUsable) + ".." + CaptureText(lastUsable)
                + " is outside a disk of " + CaptureText(totalSectors) + " sectors.");
        }

        Guid diskGuid = new(sector.Slice(56, 16));
        if (diskGuid == Guid.Empty)
        {
            throw new InvalidDataException("GPT disk GUID is empty.");
        }

        long entryLba = CaptureReadU64(sector.Slice(72, 8), "PartitionEntryLBA");
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(80, 4));
        uint entrySize = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(84, 4));

        if (entryCount == 0u)
        {
            throw new InvalidDataException("GPT partition entry count is zero.");
        }

        if (entrySize != 128u)
        {
            throw new InvalidDataException("GPT partition entry size " + CaptureText(entrySize) + " is not 128.");
        }

        long arrayBytes = checked((long)entryCount * entrySize);
        if (arrayBytes <= 0 || arrayBytes > CaptureMaxEntryArrayBytes)
        {
            throw new InvalidDataException("GPT partition entry array of " + CaptureText(arrayBytes) + " bytes exceeds the 4 MiB bound.");
        }

        long arraySectors = (arrayBytes / sectorSize) + (arrayBytes % sectorSize == 0 ? 0 : 1);
        if (arraySectors <= 0)
        {
            throw new InvalidDataException("GPT partition entry array covers no sector.");
        }

        if (primary)
        {
            if (entryLba < 2)
            {
                throw new InvalidDataException("Primary GPT partition entry array starts at LBA " + CaptureText(entryLba) + ", before LBA 2.");
            }

            if (checked(entryLba + arraySectors) > firstUsable)
            {
                throw new InvalidDataException("Primary GPT partition entry array overlaps the first usable sector.");
            }
        }
        else
        {
            if (entryLba <= lastUsable)
            {
                throw new InvalidDataException("Backup GPT partition entry array starts inside the usable range.");
            }

            if (checked(entryLba + arraySectors) > totalSectors - 1)
            {
                throw new InvalidDataException("Backup GPT partition entry array overlaps the last sector.");
            }
        }

        return new CaptureGptHeader(entryLba, arraySectors, firstUsable, lastUsable, diskGuid);
    }

    private static long CaptureReadU64(ReadOnlySpan<byte> value, string field)
    {
        ulong raw = BinaryPrimitives.ReadUInt64LittleEndian(value);
        if (raw > long.MaxValue)
        {
            throw new InvalidDataException("GPT " + field + " is out of range.");
        }

        return (long)raw;
    }

    private static uint[] CaptureCreateCrc32Table()
    {
        uint[] table = new uint[256];
        for (uint index = 0; index < 256u; index++)
        {
            uint value = index;
            for (int bit = 0; bit < 8; bit++)
            {
                value = (value & 1u) != 0u ? 0xEDB88320u ^ (value >> 1) : value >> 1;
            }

            table[(int)index] = value;
        }

        return table;
    }

    private static uint CaptureCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte value in data)
        {
            crc = CaptureCrc32Table[(int)((crc ^ value) & 0xFFu)] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private static string CaptureResolveParent(string chosenParent)
    {
        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException("The backup parent directory must be supplied.", nameof(chosenParent));
        }

        if (!Path.IsPathFullyQualified(chosenParent))
        {
            throw new ArgumentException("The backup parent directory must be an absolute path.", nameof(chosenParent));
        }

        string full = Path.GetFullPath(chosenParent);
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException("The backup parent directory does not exist: " + full);
        }

        FileAttributes attributes = File.GetAttributes(full);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("The backup parent directory is a reparse point; choose a real directory.");
        }

        if ((attributes & FileAttributes.Directory) == 0)
        {
            throw new InvalidOperationException("The backup parent path is not a directory: " + full);
        }

        return full;
    }

    private static void CaptureEnsureSpace(string directory, long plannedRaw)
    {
        long required;
        try
        {
            required = checked(plannedRaw + (3 * ChunkBytes) + CaptureSpaceMarginBytes);
        }
        catch (OverflowException)
        {
            required = long.MaxValue;
        }

        string? root = Path.GetPathRoot(directory);
        if (string.IsNullOrEmpty(root) || !Path.IsPathFullyQualified(root))
        {
            return;
        }

        long? available = null;
        try
        {
            DriveInfo drive = new(root);
            if (drive.IsReady)
            {
                available = drive.AvailableFreeSpace;
            }
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException
            or System.Security.SecurityException)
        {
            // Network shares and unusual roots do not expose a trustworthy DriveInfo; the space is simply unknown.
            available = null;
        }

        if (available.HasValue && available.Value < required)
        {
            throw new InvalidOperationException(
                "Not enough free space on " + root + ": " + CaptureText(available.Value)
                + " bytes available, at least " + CaptureText(required) + " bytes are required for this capture.");
        }
    }

    private static string CaptureLogPath(string logDirectory, int lun, string suffix)
    {
        return Path.Combine(logDirectory, "lun" + CaptureText(lun) + "-" + suffix);
    }

    private static string CaptureSanitize(string value)
    {
        StringBuilder builder = new(value.Length);
        foreach (char c in value)
        {
            if (c < 128 && char.IsLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
            }
            else
            {
                builder.Append('_');
            }
        }

        string text = builder.ToString();
        if (text.Length == 0)
        {
            return "region";
        }

        return text.Length > 40 ? text.Substring(0, 40) : text;
    }

    private static string CaptureText(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static string CaptureText(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static string CaptureText(uint value) => value.ToString(CultureInfo.InvariantCulture);

    private static void CaptureReport(
        IProgress<GlobalEdlProgress>? progress,
        string stage,
        string? role,
        int? lun,
        long completedBytes,
        long totalBytes)
    {
        if (progress is null)
        {
            return;
        }

        try
        {
            Report(progress, stage, role, lun, completedBytes, totalBytes);
        }
        catch
        {
            // A faulty display callback must never abort a capture.
        }
    }

    private sealed record CaptureGptHeader(
        long EntryLba,
        long ArraySectors,
        long FirstUsable,
        long LastUsable,
        Guid DiskGuid);

    /// <summary>
    /// Forwards approximate device-transfer counters synchronously; no synchronization context is captured and
    /// no value is queued.
    /// </summary>
    private sealed class CaptureTransferProgress : IProgress<EdlTransferProgress>
    {
        private readonly IProgress<GlobalEdlProgress>? _outer;
        private readonly string _stage;
        private readonly string? _role;
        private readonly int _lun;
        private readonly long _baseCompleted;
        private readonly long _total;

        internal CaptureTransferProgress(
            IProgress<GlobalEdlProgress>? outer,
            string stage,
            string? role,
            int lun,
            long baseCompleted,
            long total)
        {
            _outer = outer;
            _stage = stage;
            _role = role;
            _lun = lun;
            _baseCompleted = baseCompleted;
            _total = total;
        }

        public void Report(EdlTransferProgress value)
        {
            long completed = _baseCompleted;
            if (value is not null && value.CompletedBytes > 0)
            {
                completed = value.CompletedBytes > long.MaxValue - _baseCompleted
                    ? long.MaxValue
                    : _baseCompleted + value.CompletedBytes;
            }

            if (_total > 0 && completed > _total)
            {
                completed = _total;
            }

            CaptureReport(_outer, _stage, _role, _lun, completed, _total);
        }
    }
}
