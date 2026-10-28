using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Formats.Tar;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One payload file an artifact preparation plans to write, or has written, below the artifact directory.
/// <para>
/// A region describes a <b>planned output</b>: the bytes this preparation intends to hand to a later EDL write
/// step, together with the exact range they belong to. It is never evidence of anything a device returned -
/// captured device bytes are <see cref="EdlCapturedRegion"/> and stay in the backup set, so a planned file can
/// never be mistaken for a read-back proof. <see cref="FilePath"/> is absolute, <see cref="Length"/> is the
/// byte length of the file and <see cref="Sha256"/> is the SHA-256 of exactly those finished file bytes.
/// </para>
/// </summary>
public sealed record InternalArtifactRegion(
    string Role,
    int Lun,
    long StartSector,
    long SectorCount,
    int SectorSize,
    string FilePath,
    long Length,
    string Sha256);

/// <summary>
/// The complete, verified result of <see cref="InternalInstallArtifacts.PrepareAsync"/>: the artifact directory,
/// the internally recomputed allocation, the expected post-install GPT, the four explicit GPT write files, the
/// two post-GPT capture copies, the prepared installation record, the summary manifest and the fixed-size board
/// recovery archive.
/// <para>
/// The set is immutable and exists only after every file was written, flushed and re-hashed. While it is alive it
/// holds a read lock (<see cref="FileShare.Read"/>) on every output file it created, so no other writer can
/// change a prepared artifact underneath the install. <see cref="Dispose"/> releases only those locks: idempotent,
/// it never deletes or rewrites a file, never touches the backup set, the EDL client or the toolchain, and never
/// resets a device. Everything stays readable after disposal.
/// </para>
/// </summary>
public sealed class InternalArtifactSet : IDisposable
{
    /// <summary>Bag of values the preparation hands to the set; only the factory creates one.</summary>
    internal sealed class State
    {
        internal string DirectoryPath = string.Empty;
        internal InternalAllocationPlan? Allocation;
        internal GptTable? PostGpt;
        internal GptPartition? LinuxBoot;
        internal GptPartition? LinuxRoot;
        internal GptPartition? BackupPartition;
        internal IReadOnlyList<InternalArtifactRegion> GptWriteRegions = Array.Empty<InternalArtifactRegion>();
        internal InternalArtifactRegion? PostGptPrimary;
        internal InternalArtifactRegion? PostGptBackup;
        internal InternalArtifactRegion? BoardSummary;
        internal string InstallationRecordPath = string.Empty;
        internal string PlanSha256 = string.Empty;
        internal string SummaryManifestPath = string.Empty;
        internal string SummaryManifestSha256 = string.Empty;
        internal long SummaryUsedBytes;
        internal Guid InstallationId;
        internal List<FileStream> Locks = new List<FileStream>();
    }

    private readonly string _directoryPath;
    private readonly InternalAllocationPlan _allocation;
    private readonly GptTable _postGpt;
    private readonly GptPartition _linuxBoot;
    private readonly GptPartition _linuxRoot;
    private readonly GptPartition _backupPartition;
    private readonly IReadOnlyList<InternalArtifactRegion> _gptWriteRegions;
    private readonly InternalArtifactRegion _postGptPrimary;
    private readonly InternalArtifactRegion _postGptBackup;
    private readonly InternalArtifactRegion _boardSummary;
    private readonly string _installationRecordPath;
    private readonly string _planSha256;
    private readonly string _summaryManifestPath;
    private readonly string _summaryManifestSha256;
    private readonly long _summaryUsedBytes;
    private readonly Guid _installationId;
    private readonly List<FileStream> _locks;
    private int _disposed;

    /// <summary>Factory-only constructor; callers only ever receive a set from <see cref="InternalInstallArtifacts.PrepareAsync"/>.</summary>
    internal InternalArtifactSet(State state)
    {
        if (state is null)
        {
            throw new ArgumentNullException(nameof(state));
        }

        _directoryPath = state.DirectoryPath;
        _allocation = state.Allocation!;
        _postGpt = state.PostGpt!;
        _linuxBoot = state.LinuxBoot!;
        _linuxRoot = state.LinuxRoot!;
        _backupPartition = state.BackupPartition!;
        _gptWriteRegions = new ReadOnlyCollection<InternalArtifactRegion>(
            new List<InternalArtifactRegion>(state.GptWriteRegions));
        _postGptPrimary = state.PostGptPrimary!;
        _postGptBackup = state.PostGptBackup!;
        _boardSummary = state.BoardSummary!;
        _installationRecordPath = state.InstallationRecordPath;
        _planSha256 = state.PlanSha256;
        _summaryManifestPath = state.SummaryManifestPath;
        _summaryManifestSha256 = state.SummaryManifestSha256;
        _summaryUsedBytes = state.SummaryUsedBytes;
        _installationId = state.InstallationId;
        _locks = new List<FileStream>(state.Locks);
    }

    /// <summary>Absolute path of the unique artifact directory this preparation created.</summary>
    public string DirectoryPath => _directoryPath;

    /// <summary>Allocation recomputed internally from the raw LUN0 table, never accepted from a caller.</summary>
    public InternalAllocationPlan Allocation => _allocation;

    /// <summary>Expected post-install GPT, rebuilt from the original raw fragments and re-parsed before any write.</summary>
    public GptTable PostGpt => _postGpt;

    /// <summary>ARMADA_BOOT entry of <see cref="PostGpt"/>, the exact instance the parser produced.</summary>
    public GptPartition LinuxBoot => _linuxBoot;

    /// <summary>ARMADA_ROOT entry of <see cref="PostGpt"/>, the exact instance the parser produced.</summary>
    public GptPartition LinuxRoot => _linuxRoot;

    /// <summary>ARMADA_BACKUP entry of <see cref="PostGpt"/>, the exact instance the parser produced.</summary>
    public GptPartition BackupPartition => _backupPartition;

    /// <summary>
    /// The four explicit GPT write files in write order: backup entry array, backup header, primary entry array,
    /// primary header. Never the 64 sector captures, never the protective MBR and never any non-GPT sector.
    /// </summary>
    public IReadOnlyList<InternalArtifactRegion> GptWriteRegions => _gptWriteRegions;

    /// <summary>Copy of the whole original LUN0 head capture with the four planned regions overlaid.</summary>
    public InternalArtifactRegion PostGptPrimary => _postGptPrimary;

    /// <summary>Copy of the whole original LUN0 tail capture with the four planned regions overlaid.</summary>
    public InternalArtifactRegion PostGptBackup => _postGptBackup;

    /// <summary>The fixed 2 GiB board recovery image, reported at the backup partition's own extent.</summary>
    public InternalArtifactRegion BoardSummary => _boardSummary;

    /// <summary>Path of <c>installation-record.json</c>; the file whose exact bytes <see cref="PlanSha256"/> covers.</summary>
    public string InstallationRecordPath => _installationRecordPath;

    /// <summary>SHA-256 of exactly the record file bytes; the installation plan identity.</summary>
    public string PlanSha256 => _planSha256;

    /// <summary>Path of <c>board-summary.json</c>, the manifest of the prepared artifact directory itself.</summary>
    public string SummaryManifestPath => _summaryManifestPath;

    /// <summary>SHA-256 of exactly the summary manifest file bytes.</summary>
    public string SummaryManifestSha256 => _summaryManifestSha256;

    /// <summary>Outer header bytes plus the compressed gzip bytes the image actually uses before its zero padding.</summary>
    public long SummaryUsedBytes => _summaryUsedBytes;

    /// <summary>The single installation id stamped into the record, the recovery manifest and the summary.</summary>
    public Guid InstallationId => _installationId;

    /// <summary>
    /// Releases only the read locks this set owns. Idempotent, and it never deletes a file, never rewrites
    /// metadata, never disposes the backup set or the client and never touches a device.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var stream in _locks)
        {
            stream.Dispose();
        }
    }
}

/// <summary>
/// Prepares every local file an internal Android-to-Linux install needs before anything is written to a device:
/// the four explicit GPT write regions, the two expected post-GPT capture copies, the prepared installation
/// record and the fixed 2 GiB board recovery image.
/// <para>
/// Scope: pure local-file preparation. Nothing here talks to a device, opens an EDL session, starts a process,
/// touches the network, resets or reboots anything, or writes outside the one unique directory this preparation
/// creates below the caller's explicit parent. The caller's backup set is read and re-hashed but never disposed,
/// deleted or modified, and no foreign file is ever overwritten.
/// </para>
/// <para>
/// Trust model: the backup set is the only input. Every one of its 52 files is re-hashed while streaming and
/// compared with the SHA-256 the backup recorded, the LUN0 head and tail are re-parsed through
/// <see cref="OriginalGptImporter.Parse"/> and compared with the backup's source fingerprint, the allocation is
/// recomputed with <see cref="InternalPartitionPlanner.Plan"/>, and the post-GPT fragments are re-parsed and
/// compared entry by entry before a byte is written. A changed input fails the preparation; it never produces a
/// success set.
/// </para>
/// </summary>
public static class InternalInstallArtifacts
{
    private const int TarBlockBytes = 512;
    private const int ManifestPayloadBytes = 64 * 1024;
    private const int BoardHeaderBytes = 64 * 1024;
    private const int ArchiveTerminatorBytes = 2 * TarBlockBytes;
    private const long GiB = 1L << 30;
    private const long BoardArchiveBytes = 2L << 30;
    private const int CopyBufferBytes = 64 * 1024;
    private const int GptCaptureSectors = 64;
    private const int GptEntryBytes = 128;
    private const int MaximumEntryArrayBytes = 4 * 1024 * 1024;
    private const string LinuxDataGuidText = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string RecoveryManifestEntryName = "armada-recovery-manifest.json";
    private const string InstallationRecordEntryName = "installation-record.json";
    private const string PostGptPrimaryEntryName = "post-gpt-primary.bin";
    private const string PostGptBackupEntryName = "post-gpt-backup.bin";
    private const string PcManifestEntryName = "pc-backup-manifest.json";
    private const string BoardArchiveFileName = "board-recovery.img";
    private const string BoardArchiveFormat = BootSettingsRegion.Format;
    private const string BoardImageKind = "armada-board-recovery-image";
    private const string SummaryManifestFileName = "board-summary.json";
    private const string RecordFileName = "installation-record.json";
    private const string PostGptPrimaryFileName = "post-gpt-primary.bin";
    private const string PostGptBackupFileName = "post-gpt-backup.bin";

    // GPT on-disk offsets, repeated locally so the rewriting code never has to reach into the importer.
    private const int HeaderSizeFieldOffset = 12;
    private const int HeaderCrcFieldOffset = 16;
    private const int FirstUsableOffset = 40;
    private const int LastUsableOffset = 48;
    private const int EntryArrayLbaOffset = 72;
    private const int EntryCountOffset = 80;
    private const int EntrySizeFieldOffset = 84;
    private const int EntryArrayCrcOffset = 88;
    private const int EntryTypeGuidOffset = 0;
    private const int EntryPartUuidOffset = 16;
    private const int EntryStartOffset = 32;
    private const int EntryEndOffset = 40;
    private const int EntryAttributesOffset = 48;
    private const int EntryNameOffset = 56;
    private const int EntryNameBytes = 72;

    private static readonly byte[] ZeroChunk = new byte[CopyBufferBytes];
    private static readonly char[] Sha256HexChars = "0123456789abcdefABCDEF".ToCharArray();
    private static readonly DateTimeOffset FixedTarTimestamp =
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly string[] MetadataRoles =
    {
        "pc-backup-manifest", "post-gpt-primary", "post-gpt-backup", "installation-record",
    };

    /// <summary>
    /// Prepares the local install artifacts for <paramref name="backup"/> and returns them only after every file
    /// is written, flushed to disk and re-hashed.
    /// </summary>
    /// <param name="backup">A complete, verified 52 file backup; it is read and never disposed.</param>
    /// <param name="androidGiB">Whole GiB handed to Android; the planner decides the accepted range.</param>
    /// <param name="storage">Storage the installation package requires.</param>
    /// <param name="chosenParent">
    /// Explicit absolute existing directory below which the unique artifact directory is created. There is no
    /// default location and no temporary fallback.
    /// </param>
    /// <param name="token">Cancellation; a cancelled preparation creates nothing.</param>
    /// <returns>The verified artifact set, holding read locks on its own files.</returns>
    /// <exception cref="ArgumentException">The parent is missing, relative or not an existing directory, or the GiB count is not positive.</exception>
    /// <exception cref="InvalidDataException">The backup, the original GPT bytes or the planned layout is not trustworthy.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static async Task<InternalArtifactSet> PrepareAsync(
        InternalBackupSet backup,
        long androidGiB,
        PackageStorage storage,
        string chosenParent,
        CancellationToken token = default)
    {
        ValidateArguments(backup, androidGiB, storage, chosenParent, token);

        return await Task.Run(() => Prepare(backup, androidGiB, storage, chosenParent, token), CancellationToken.None)
            .ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ preparation

    private static InternalArtifactSet Prepare(
        InternalBackupSet backup,
        long androidGiB,
        PackageStorage storage,
        string chosenParent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var geometries = backup.Geometries
            ?? throw new InvalidDataException("The backup set reports no LUN geometries.");
        var tables = backup.Tables
            ?? throw new InvalidDataException("The backup set reports no parsed GPT tables.");
        var files = backup.Files
            ?? throw new InvalidDataException("The backup set reports no captured files.");

        IReadOnlyDictionary<string, VerifiedCapture> verifiedCaptures = VerifyCapturedInputs(files, geometries, tables, backup.Model, token);
        VerifyFileHash(backup.ManifestPath, backup.ManifestSha256, "the backup manifest", token);

        // Existing source captures and their manifest are validated in full above; the filtered set below only
        // drives which files are copied into the new archive. Source backups are never mutated or deleted.
        Dictionary<string, VerifiedCapture> captures = new(StringComparer.Ordinal);
        foreach (KeyValuePair<string, VerifiedCapture> pair in verifiedCaptures)
        {
            if (BackupPartitionPolicy.IsExcluded(pair.Key))
            {
                continue;
            }

            captures.Add(pair.Key, pair.Value);
        }

        var lun0Geometry = geometries[0];
        var sectorSize = lun0Geometry.SectorSize;
        long diskBytes;
        try
        {
            diskBytes = checked(lun0Geometry.TotalSectors * (long)sectorSize);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException("The LUN0 geometry does not describe a representable disk length.");
        }

        // The raw LUN0 windows are read again and re-hashed: the fragments that drive the rewrite are the exact
        // bytes the backup vouched for, not bytes read once and trusted for the rest of the run.
        var head = ReadVerifiedFile(captures["gpt_lun0_primary"], token);
        var tail = ReadVerifiedFile(captures["gpt_lun0_backup"], token);
        var original = ReadAndValidateOriginal(
            head, tail, sectorSize, diskBytes, tables[0].SourceFingerprint);

        token.ThrowIfCancellationRequested();

        var allocation = InternalPartitionPlanner.Plan(original, androidGiB, storage)
            ?? throw new InvalidDataException("The partition planner returned no allocation.");
        ValidateAllocation(allocation, original, androidGiB);

        var uuids = CreatePartitionUuids(original);
        var rewrite = BuildGptRewrite(
            head, tail, sectorSize, diskBytes, original, allocation, uuids.Boot, uuids.Root, uuids.Backup);

        var installationId = Guid.NewGuid();
        var recordBytes = BuildInstallationRecord(
            installationId, backup, original, lun0Geometry, allocation, rewrite, uuids);
        var planSha256 = Sha256Hex(recordBytes);

        var payloads = BuildPayloadList(captures, backup, rewrite, recordBytes, planSha256);
        var payloadLengths = new long[payloads.Count];
        for (var index = 0; index < payloads.Count; index++)
        {
            payloadLengths[index] = payloads[index].Length;
        }

        var layout = ComputePayloadLayout(payloadLengths);

        var manifestJson = BuildRecoveryManifestJson(
            installationId,
            planSha256,
            backup.ManifestSha256,
            original.SourceFingerprint,
            rewrite.PostTable.SourceFingerprint,
            uuids,
            payloads,
            layout);

        var requiredBytes = ComputeRequiredArchiveBytes(manifestJson.Length, payloadLengths);
        var manifestPayload = PadManifest(manifestJson);

        token.ThrowIfCancellationRequested();

        // Every decision, including the fit of the archive, is made before the output directory exists.
        var directory = CreateArtifactDirectory(chosenParent, installationId);
        var owned = new List<FileStream>();

        try
        {
            var writeRegions = new List<InternalArtifactRegion>(rewrite.WriteRegions.Count);
            foreach (var descriptor in rewrite.WriteRegions)
            {
                token.ThrowIfCancellationRequested();
                var path = Path.Combine(directory, descriptor.Role + ".bin");
                var stream = CreateNewOutput(path);
                owned.Add(stream);
                var sha256 = WriteAndVerify(stream, descriptor.Bytes);
                if (!string.Equals(sha256, descriptor.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"The GPT write region '{descriptor.Role}' does not hash to its planned value.");
                }

                SealLastOutput(owned, descriptor.Length, descriptor.Sha256, token);

                writeRegions.Add(new InternalArtifactRegion(
                    descriptor.Role,
                    0,
                    descriptor.StartSector,
                    descriptor.SectorCount,
                    descriptor.SectorSize,
                    path,
                    descriptor.Length,
                    sha256));
            }

            var postPrimaryPath = Path.Combine(directory, PostGptPrimaryFileName);
            var postPrimaryStream = CreateNewOutput(postPrimaryPath);
            owned.Add(postPrimaryStream);
            var postPrimarySha = WriteAndVerify(postPrimaryStream, rewrite.PostPrimaryFragment);
            SealLastOutput(owned, rewrite.PostPrimaryFragment.Length, postPrimarySha, token);
            var postPrimary = new InternalArtifactRegion(
                "post-gpt-primary",
                0,
                0,
                rewrite.PostPrimaryFragment.Length / sectorSize,
                sectorSize,
                postPrimaryPath,
                rewrite.PostPrimaryFragment.Length,
                postPrimarySha);

            var postBackupPath = Path.Combine(directory, PostGptBackupFileName);
            var postBackupStream = CreateNewOutput(postBackupPath);
            owned.Add(postBackupStream);
            var postBackupSha = WriteAndVerify(postBackupStream, rewrite.PostBackupFragment);
            SealLastOutput(owned, rewrite.PostBackupFragment.Length, postBackupSha, token);
            var postBackup = new InternalArtifactRegion(
                "post-gpt-backup",
                0,
                lun0Geometry.TotalSectors - (rewrite.PostBackupFragment.Length / sectorSize),
                rewrite.PostBackupFragment.Length / sectorSize,
                sectorSize,
                postBackupPath,
                rewrite.PostBackupFragment.Length,
                postBackupSha);

            var recordPath = Path.Combine(directory, RecordFileName);
            var recordStream = CreateNewOutput(recordPath);
            owned.Add(recordStream);
            var recordSha = WriteAndVerify(recordStream, recordBytes);
            if (!string.Equals(recordSha, planSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The installation record does not hash to the planned plan id.");
            }

            SealLastOutput(owned, recordBytes.Length, planSha256, token);

            var archivePath = Path.Combine(directory, BoardArchiveFileName);
            var archiveStream = CreateNewOutput(archivePath);
            owned.Add(archiveStream);
            token.ThrowIfCancellationRequested();
            var recoveryManifestSha256 = Sha256Hex(manifestPayload);
            var archiveSha = WriteArchive(
                archiveStream,
                installationId,
                Guid.Parse(rewrite.BackupPartition.PartUuid),
                backup.Model,
                planSha256,
                recoveryManifestSha256,
                manifestPayload,
                payloads,
                layout,
                token,
                out var compressedBytes,
                out var uncompressedTarBytes,
                out var compressedSha256);

            if (uncompressedTarBytes != requiredBytes)
            {
                throw new InvalidDataException(
                    $"The gzip stream carries {uncompressedTarBytes} tar bytes, not the prechecked {requiredBytes}.");
            }

            // Re-read what was just finalized exactly as a consumer will, before any lock or success state exists.
            VerifyBoardArchive(archiveStream, backup.Model, token);
            SealLastOutput(owned, BoardArchiveBytes, archiveSha, token);

            var summaryBytes = BuildSummaryManifest(
                installationId,
                planSha256,
                allocation,
                rewrite,
                writeRegions,
                postPrimary,
                postBackup,
                BoardHeaderBytes + compressedBytes,
                compressedBytes,
                compressedSha256,
                uncompressedTarBytes,
                recoveryManifestSha256,
                archivePath,
                archiveSha);

            var summaryPath = Path.Combine(directory, SummaryManifestFileName);
            var summaryStream = CreateNewOutput(summaryPath);
            owned.Add(summaryStream);
            var summarySha = WriteAndVerify(summaryStream, summaryBytes);
            SealLastOutput(owned, summaryBytes.Length, summarySha, token);

            var boardSummary = new InternalArtifactRegion(
                "board-summary",
                0,
                allocation.BackupStartSector,
                allocation.BackupSectorCount,
                sectorSize,
                archivePath,
                BoardArchiveBytes,
                archiveSha);

            var state = new InternalArtifactSet.State
            {
                DirectoryPath = directory,
                Allocation = allocation,
                PostGpt = rewrite.PostTable,
                LinuxBoot = rewrite.LinuxBoot,
                LinuxRoot = rewrite.LinuxRoot,
                BackupPartition = rewrite.BackupPartition,
                GptWriteRegions = writeRegions,
                PostGptPrimary = postPrimary,
                PostGptBackup = postBackup,
                BoardSummary = boardSummary,
                InstallationRecordPath = recordPath,
                PlanSha256 = planSha256,
                SummaryManifestPath = summaryPath,
                SummaryManifestSha256 = summarySha,
                SummaryUsedBytes = BoardHeaderBytes + compressedBytes,
                InstallationId = installationId,
                Locks = owned,
            };

            return new InternalArtifactSet(state);
        }
        catch
        {
            // Partial files stay on disk for diagnosis; only this preparation's locks are released.
            foreach (var stream in owned)
            {
                stream.Dispose();
            }

            throw;
        }
    }

    private static void ValidateArguments(
        InternalBackupSet backup,
        long androidGiB,
        PackageStorage storage,
        string chosenParent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (backup is null)
        {
            throw new ArgumentNullException(nameof(backup));
        }

        if (storage is null)
        {
            throw new ArgumentNullException(nameof(storage));
        }

        if (androidGiB <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(androidGiB), "The Android size must be a positive whole number of GiB.");
        }

        if (chosenParent is null)
        {
            throw new ArgumentNullException(nameof(chosenParent));
        }

        if (chosenParent.Trim().Length == 0)
        {
            throw new ArgumentException(
                "The chosen parent must be an explicit directory; there is no default location.",
                nameof(chosenParent));
        }

        if (!Path.IsPathFullyQualified(chosenParent))
        {
            throw new ArgumentException(
                "The chosen parent must be an absolute path; there is no working-directory or temporary fallback.",
                nameof(chosenParent));
        }

        if (!Directory.Exists(chosenParent))
        {
            throw new ArgumentException(
                "The chosen parent must already exist; the preparation never invents a parent directory.",
                nameof(chosenParent));
        }
    }

    private static void ValidateAllocation(
        InternalAllocationPlan allocation, GptTable original, long androidGiB)
    {
        if (allocation.SectorSize != original.SectorSize)
        {
            throw new InvalidDataException("The planned allocation uses a different sector size.");
        }

        var planned = allocation.OriginalUserdata;
        if (planned is null)
        {
            throw new InvalidDataException("The planned allocation names no original userdata entry.");
        }

        var userdata = FindPartition(original, planned.Number);
        if (userdata is null
            || !string.Equals(userdata.PartUuid, planned.PartUuid, StringComparison.OrdinalIgnoreCase)
            || userdata.StartSector != planned.StartSector
            || userdata.SectorCount != planned.SectorCount)
        {
            throw new InvalidDataException(
                "The planned allocation does not preserve the original userdata entry.");
        }

        long androidBytes;
        long originalEnd;
        try
        {
            androidBytes = checked(androidGiB * GiB);
            originalEnd = checked(userdata.StartSector + userdata.SectorCount);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException("The planned Android window is not representable.");
        }

        if (allocation.AndroidBytes != androidBytes)
        {
            throw new InvalidDataException("The planned Android size does not match the requested GiB count.");
        }

        if (allocation.OriginalUserdataEndSectorExclusive != originalEnd
            || allocation.AndroidSectorCount <= 0
            || allocation.AndroidEndSectorExclusive != userdata.StartSector + allocation.AndroidSectorCount
            || allocation.AndroidEndSectorExclusive > originalEnd)
        {
            throw new InvalidDataException("The planned Android window does not fit inside the original userdata.");
        }

        if (allocation.BackupBytes != BoardArchiveBytes
            || allocation.BackupSectorCount != BoardArchiveBytes / allocation.SectorSize
            || allocation.BackupEndSectorExclusive > originalEnd)
        {
            throw new InvalidDataException("The planned backup tail is not the fixed 2 GiB tail below userdata.");
        }

        if (allocation.LinuxBootSectorCount <= 0
            || allocation.LinuxRootSectorCount <= 0
            || allocation.LinuxBootStartSector < allocation.AndroidEndSectorExclusive
            || allocation.LinuxRootStartSector < allocation.LinuxBootStartSector + allocation.LinuxBootSectorCount
            || allocation.BackupStartSector < allocation.LinuxRootStartSector + allocation.LinuxRootSectorCount)
        {
            throw new InvalidDataException("The planned Linux and backup extents are not ordered behind userdata.");
        }
    }

    // ------------------------------------------------------------- input verification

    /// <summary>
    /// Re-hashes every file of the backup and checks every declared region against its LUN geometry and its
    /// freshly parsed table. Every base role of <paramref name="model"/>'s contract must be present; only the
    /// optional efisp role may be additionally captured, and it is fully checked against its LUN4 GPT, extent and
    /// hash like the base roles, while unknown roles are rejected. Returns the verified evidence,
    /// or throws without creating anything.
    /// </summary>
    internal static IReadOnlyDictionary<string, VerifiedCapture> VerifyCapturedInputs(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        IReadOnlyDictionary<int, GptTable> tables,
        string model,
        CancellationToken token)
    {
        var contract = InternalInstallBackupRoles.ForModel(model);

        if (files is null)
        {
            throw new ArgumentNullException(nameof(files));
        }

        if (geometries is null)
        {
            throw new ArgumentNullException(nameof(geometries));
        }

        if (tables is null)
        {
            throw new ArgumentNullException(nameof(tables));
        }

        // The selected contract follows the capture the caller actually produced: every baseline role plus the
        // optional efisp only when the snapshot carries it. Unknown, missing and duplicated roles are rejected.
        contract = contract.ForCapturedRoles(files.Keys);

        foreach (var role in contract.RequiredRoles)
        {
            if (!files.ContainsKey(role))
            {
                throw new InvalidDataException($"The backup set is missing the required role '{role}'.");
            }
        }

        if (geometries.Count != 6)
        {
            throw new InvalidDataException(
                $"A verified backup probes six LUNs; the set exposes {geometries.Count}.");
        }

        if (tables.Count != 6)
        {
            throw new InvalidDataException(
                $"A verified backup parses six tables; the set exposes {tables.Count}.");
        }

        for (var lun = 0; lun < 6; lun++)
        {
            if (!geometries.TryGetValue(lun, out var geometry) || geometry is null)
            {
                throw new InvalidDataException($"The backup set is missing the geometry of LUN {lun}.");
            }

            if (!tables.TryGetValue(lun, out var table) || table is null)
            {
                throw new InvalidDataException($"The backup set is missing the table of LUN {lun}.");
            }

            if (geometry.Lun != lun)
            {
                throw new InvalidDataException($"The geometry keyed by LUN {lun} reports LUN {geometry.Lun}.");
            }

            if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
            {
                throw new InvalidDataException(
                    $"LUN {lun} reports a sector size of {geometry.SectorSize}; only 512 and 4096 are supported.");
            }

            if (geometry.TotalSectors < GptCaptureSectors * 2)
            {
                throw new InvalidDataException($"LUN {lun} is too small to hold two 64 sector GPT windows.");
            }

            if (table.SectorSize != geometry.SectorSize)
            {
                throw new InvalidDataException($"The table of LUN {lun} was parsed with a different sector size.");
            }

            long tableDiskBytes;
            try
            {
                tableDiskBytes = checked(geometry.TotalSectors * (long)geometry.SectorSize);
            }
            catch (OverflowException)
            {
                throw new InvalidDataException($"The geometry of LUN {lun} is not representable in bytes.");
            }

            if (table.DiskBytes != tableDiskBytes)
            {
                throw new InvalidDataException($"The table of LUN {lun} describes a different disk length.");
            }
        }

        var verified = new Dictionary<string, VerifiedCapture>(StringComparer.Ordinal);

        // Deterministic role order, independent of the caller's dictionary order. Every exposed file is checked;
        // an extra verified role is never silently dropped from the archive.
        var roles = new List<string>(files.Keys);
        roles.Sort(StringComparer.Ordinal);

        foreach (var role in roles)
        {
            token.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(role))
            {
                throw new InvalidDataException("The backup set exposes a file under an empty role.");
            }

            if (!files.TryGetValue(role, out var region) || region is null)
            {
                throw new InvalidDataException($"The backup set exposes no capture for the role '{role}'.");
            }

            if (!string.Equals(region.Role, role, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The captured file keyed as '{role}' reports the role '{region.Role}'.");
            }

            // Only the selected contract authorizes a captured role, so a role it does not name is rejected
            // instead of falling back to whatever LUN the capture claims.
            if (!contract.RoleLuns.TryGetValue(role, out var lun))
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' is not part of the backup contract.");
            }
            else if (region.Lun != lun)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' was read from LUN {region.Lun}, not LUN {lun}.");
            }

            if (!geometries.TryGetValue(lun, out var geometry) || geometry is null)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' names LUN {lun}, which the backup set does not expose.");
            }

            if (!tables.TryGetValue(lun, out var table) || table is null)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' names LUN {lun}, whose table the backup set does not expose.");
            }

            if (region.SectorSize != geometry.SectorSize)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' uses a sector size of {region.SectorSize}, not {geometry.SectorSize}.");
            }

            if (region.StartSector < 0 || region.SectorCount <= 0)
            {
                throw new InvalidDataException($"The captured role '{role}' declares an empty sector range.");
            }

            long end;
            long expectedLength;
            try
            {
                end = checked(region.StartSector + region.SectorCount);
                expectedLength = checked(region.SectorCount * (long)region.SectorSize);
            }
            catch (OverflowException)
            {
                throw new InvalidDataException($"The captured role '{role}' declares an unrepresentable range.");
            }

            if (end > geometry.TotalSectors)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' extends beyond the {geometry.TotalSectors} sectors of LUN {lun}.");
            }

            if (region.Length != expectedLength)
            {
                throw new InvalidDataException(
                    $"The captured role '{role}' declares {region.Length} bytes for {region.SectorCount} sectors.");
            }

            var isGpt = role.StartsWith("gpt_lun", StringComparison.Ordinal);
            if (isGpt)
            {
                if (region.SectorCount != GptCaptureSectors)
                {
                    throw new InvalidDataException(
                        $"The GPT role '{role}' must capture exactly {GptCaptureSectors} sectors.");
                }

                if (region.StartSector != 0 && region.StartSector != geometry.TotalSectors - GptCaptureSectors)
                {
                    throw new InvalidDataException(
                        $"The GPT role '{role}' is not anchored at the head or the tail of LUN {lun}.");
                }

                if (region.PartUuid is not null)
                {
                    throw new InvalidDataException($"The GPT role '{role}' must not claim a partition UUID.");
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(region.PartUuid))
                {
                    throw new InvalidDataException($"The partition role '{role}' carries no partition UUID.");
                }

                var partition = FindPartitionByUuid(table, region.PartUuid!);
                if (partition is null)
                {
                    throw new InvalidDataException(
                        $"The captured role '{role}' names a partition that the fresh LUN {lun} table does not contain.");
                }

                if (!string.Equals(partition.Name, role, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"The captured role '{role}' names the LUN {lun} partition '{partition.Name}'.");
                }

                if (partition.StartSector != region.StartSector || partition.SectorCount != region.SectorCount)
                {
                    throw new InvalidDataException(
                        $"The captured role '{role}' covers {region.StartSector}+{region.SectorCount}, not the partition's own extent.");
                }
            }

            if (string.IsNullOrWhiteSpace(region.FilePath))
            {
                throw new InvalidDataException($"The captured role '{role}' has no file path.");
            }

            var info = new FileInfo(region.FilePath);
            if (!info.Exists)
            {
                throw new FileNotFoundException(
                    $"The captured file of role '{role}' is missing.", region.FilePath);
            }

            if ((info.Attributes & FileAttributes.Directory) != 0)
            {
                throw new InvalidDataException($"The captured path of role '{role}' is a directory, not a file.");
            }

            if (info.Length != region.Length)
            {
                throw new InvalidDataException(
                    $"The captured file of role '{role}' is {info.Length} bytes, not the declared {region.Length}.");
            }

            var sha256 = HashFile(region.FilePath, token, info.Length);
            if (!HexEquals(sha256, region.Sha256))
            {
                throw new InvalidDataException(
                    $"The captured file of role '{role}' changed after the backup verified it.");
            }

            verified.Add(role, new VerifiedCapture
            {
                Role = role,
                FilePath = region.FilePath,
                Length = region.Length,
                Sha256 = sha256,
                Lun = lun,
                StartSector = region.StartSector,
                SectorCount = region.SectorCount,
                SectorSize = region.SectorSize,
                PartUuid = region.PartUuid,
            });
        }

        return verified;
    }

    private static void VerifyFileHash(
        string path, string expectedSha256, string description, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidDataException($"The backup set names no file for {description}.");
        }

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException($"The file for {description} is missing.", path);
        }

        if ((info.Attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException($"The path for {description} is a directory, not a file.");
        }

        var sha256 = HashFile(path, token, info.Length);
        if (!HexEquals(sha256, expectedSha256))
        {
            throw new InvalidDataException($"{description} changed after the backup verified it.");
        }
    }

    private static byte[] ReadVerifiedFile(VerifiedCapture capture, CancellationToken token)
    {
        var bytes = File.ReadAllBytes(capture.FilePath);
        if (bytes.Length != capture.Length)
        {
            throw new InvalidDataException(
                $"The file of role '{capture.Role}' changed length after it was verified.");
        }

        token.ThrowIfCancellationRequested();

        if (!string.Equals(Sha256Hex(bytes), capture.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The file of role '{capture.Role}' changed after it was verified.");
        }

        return bytes;
    }

    // ------------------------------------------------------------------- GPT rewrite

    /// <summary>
    /// Rebuilds the post-install GPT purely from the original raw LUN0 fragments and re-parses it before any byte
    /// is written. Every original byte is preserved except the userdata entry's end LBA, the three new entries and
    /// the two header fields whose checksums must change.
    /// </summary>
    internal static GptRewrite BuildGptRewrite(
        byte[] primaryFragment,
        byte[] backupFragment,
        int sectorSize,
        long diskBytes,
        GptTable original,
        InternalAllocationPlan allocation,
        Guid bootUuid,
        Guid rootUuid,
        Guid backupUuid)
    {
        if (primaryFragment is null)
        {
            throw new ArgumentNullException(nameof(primaryFragment));
        }

        if (backupFragment is null)
        {
            throw new ArgumentNullException(nameof(backupFragment));
        }

        if (original is null)
        {
            throw new ArgumentNullException(nameof(original));
        }

        if (allocation is null)
        {
            throw new ArgumentNullException(nameof(allocation));
        }

        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new ArgumentException("Only 512 and 4096 byte sectors are supported.", nameof(sectorSize));
        }

        if (diskBytes <= 0 || diskBytes % sectorSize != 0)
        {
            throw new ArgumentException(
                "The disk length must be a positive multiple of the sector size.", nameof(diskBytes));
        }

        var totalSectors = diskBytes / sectorSize;
        var lastLba = totalSectors - 1;
        var primaryHeaderOffset = sectorSize;

        if (primaryFragment.Length % sectorSize != 0 || backupFragment.Length % sectorSize != 0)
        {
            throw new InvalidDataException("A GPT capture must be a whole number of sectors.");
        }

        var backupOriginLba = totalSectors - (backupFragment.Length / sectorSize);
        if (backupOriginLba < 0 || backupOriginLba > lastLba)
        {
            throw new InvalidDataException("The backup fragment is longer than the disk.");
        }

        var backupHeaderOffset = checked((int)((lastLba - backupOriginLba) * sectorSize));

        RequireHeaderSector(primaryFragment, primaryHeaderOffset, sectorSize, "primary");
        RequireHeaderSector(backupFragment, backupHeaderOffset, sectorSize, "backup");

        var headerSize = checked((int)ReadUInt32(primaryFragment, primaryHeaderOffset + HeaderSizeFieldOffset));
        if (headerSize < 92 || headerSize > sectorSize)
        {
            throw new InvalidDataException("The primary GPT header size is outside the supported range.");
        }

        var backupHeaderSize = checked((int)ReadUInt32(backupFragment, backupHeaderOffset + HeaderSizeFieldOffset));
        if (backupHeaderSize != headerSize)
        {
            throw new InvalidDataException("The primary and backup GPT headers have different header sizes.");
        }

        var entryCount = checked((int)ReadUInt32(primaryFragment, primaryHeaderOffset + EntryCountOffset));
        if (entryCount <= 0)
        {
            throw new InvalidDataException("The original GPT declares no partition entries.");
        }

        var entrySize = ReadUInt32(primaryFragment, primaryHeaderOffset + EntrySizeFieldOffset);
        if (entrySize != GptEntryBytes)
        {
            throw new InvalidDataException("Only 128 byte GPT entries can be rewritten.");
        }

        if (ReadUInt32(backupFragment, backupHeaderOffset + EntrySizeFieldOffset) != entrySize)
        {
            throw new InvalidDataException("The primary and backup GPT headers declare different entry sizes.");
        }

        if (checked((int)ReadUInt32(backupFragment, backupHeaderOffset + EntryCountOffset)) != entryCount)
        {
            throw new InvalidDataException("The primary and backup GPT headers declare different entry counts.");
        }

        var entryBytes = checked(entryCount * GptEntryBytes);
        if (entryBytes > MaximumEntryArrayBytes)
        {
            throw new InvalidDataException("The declared partition entry array exceeds 4 MiB.");
        }

        var arraySectors = (entryBytes + sectorSize - 1) / sectorSize;
        var arrayLength = checked(arraySectors * sectorSize);

        var primaryArrayLba = ReadInt64(primaryFragment, primaryHeaderOffset + EntryArrayLbaOffset);
        var backupArrayLba = ReadInt64(backupFragment, backupHeaderOffset + EntryArrayLbaOffset);

        var primaryArrayOffset = LocateEntryArray(
            primaryFragment, primaryArrayLba, 0L, arrayLength, sectorSize, "primary");
        var backupArrayOffset = LocateEntryArray(
            backupFragment, backupArrayLba, backupOriginLba, arrayLength, sectorSize, "backup");

        var primaryArray = new byte[arrayLength];
        Buffer.BlockCopy(primaryFragment, primaryArrayOffset, primaryArray, 0, arrayLength);
        var backupArray = new byte[arrayLength];
        Buffer.BlockCopy(backupFragment, backupArrayOffset, backupArray, 0, arrayLength);

        if (!primaryArray.AsSpan(0, entryBytes).SequenceEqual(backupArray.AsSpan(0, entryBytes)))
        {
            throw new InvalidDataException("The primary and backup GPT entry arrays are not identical.");
        }

        var userdata = allocation.OriginalUserdata;
        if (userdata is null || userdata.Number < 1 || userdata.Number > entryCount)
        {
            throw new InvalidDataException("The planned userdata entry is not one of the original entries.");
        }

        var userdataOffset = (userdata.Number - 1) * GptEntryBytes;
        if (IsZeroGuid(primaryArray.AsSpan(userdataOffset + EntryTypeGuidOffset, 16)))
        {
            throw new InvalidDataException("The planned userdata slot is empty in the original table.");
        }

        if ((long)ReadUInt64(primaryArray, userdataOffset + EntryStartOffset) != userdata.StartSector)
        {
            throw new InvalidDataException("The planned userdata start does not match the original entry.");
        }

        var originalEndInclusive = checked(userdata.StartSector + userdata.SectorCount - 1);
        if ((long)ReadUInt64(primaryArray, userdataOffset + EntryEndOffset) != originalEndInclusive)
        {
            throw new InvalidDataException("The planned userdata length does not match the original entry.");
        }

        long androidEndInclusive;
        long firstUsable;
        long lastUsable;
        try
        {
            androidEndInclusive = checked(allocation.AndroidEndSectorExclusive - 1);
            firstUsable = ReadInt64(primaryFragment, primaryHeaderOffset + FirstUsableOffset);
            lastUsable = ReadInt64(primaryFragment, primaryHeaderOffset + LastUsableOffset);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException("The planned Android end is not representable.");
        }

        if (allocation.AndroidSectorCount <= 0
            || androidEndInclusive < userdata.StartSector
            || androidEndInclusive > originalEndInclusive)
        {
            throw new InvalidDataException("The planned Android window does not fit inside the original userdata.");
        }

        var freeSlots = new List<int>();
        var existingUuids = new HashSet<Guid>();
        for (var index = 0; index < entryCount; index++)
        {
            var offset = index * GptEntryBytes;
            var typeGuid = new Guid(primaryArray.AsSpan(offset + EntryTypeGuidOffset, 16));
            if (typeGuid == Guid.Empty)
            {
                freeSlots.Add(index);
                continue;
            }

            existingUuids.Add(new Guid(primaryArray.AsSpan(offset + EntryPartUuidOffset, 16)));

            var name = DecodeName(primaryArray, offset + EntryNameOffset);
            if (name.StartsWith("ARMADA_", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The original table already owns a partition named '{name}'.");
            }
        }

        if (freeSlots.Count < 3)
        {
            throw new InvalidDataException(
                $"The original table has {freeSlots.Count} free entry slots; the rewrite needs three.");
        }

        var newPartitions = new[]
        {
            new NewPartition(0, "ARMADA_BOOT", bootUuid, allocation.LinuxBootStartSector, allocation.LinuxBootSectorCount),
            new NewPartition(0, "ARMADA_ROOT", rootUuid, allocation.LinuxRootStartSector, allocation.LinuxRootSectorCount),
            new NewPartition(0, "ARMADA_BACKUP", backupUuid, allocation.BackupStartSector, allocation.BackupSectorCount),
        };

        var seenUuids = new HashSet<Guid>();
        foreach (var partition in newPartitions)
        {
            if (partition.PartUuid == Guid.Empty)
            {
                throw new ArgumentException("A new partition UUID must not be empty.", nameof(bootUuid));
            }

            if (existingUuids.Contains(partition.PartUuid) || !seenUuids.Add(partition.PartUuid))
            {
                throw new InvalidDataException("A new partition UUID repeats a UUID the table already uses.");
            }

            long end;
            try
            {
                end = checked(partition.StartSector + partition.SectorCount - 1);
            }
            catch (OverflowException)
            {
                throw new InvalidDataException($"The planned extent of '{partition.Name}' is not representable.");
            }

            if (partition.SectorCount <= 0
                || partition.StartSector < firstUsable
                || end > lastUsable)
            {
                throw new InvalidDataException(
                    $"The planned extent of '{partition.Name}' lies outside the usable range.");
            }
        }

        WriteUInt64(primaryArray, userdataOffset + EntryEndOffset, (ulong)androidEndInclusive);
        WriteUInt64(backupArray, userdataOffset + EntryEndOffset, (ulong)androidEndInclusive);

        var linuxType = Guid.Parse(LinuxDataGuidText);
        for (var index = 0; index < newPartitions.Length; index++)
        {
            var slot = freeSlots[index];
            var offset = slot * GptEntryBytes;
            newPartitions[index].Number = slot + 1;

            Array.Clear(primaryArray, offset, GptEntryBytes);
            Array.Clear(backupArray, offset, GptEntryBytes);

            linuxType.TryWriteBytes(primaryArray.AsSpan(offset + EntryTypeGuidOffset, 16));
            linuxType.TryWriteBytes(backupArray.AsSpan(offset + EntryTypeGuidOffset, 16));
            newPartitions[index].PartUuid.TryWriteBytes(primaryArray.AsSpan(offset + EntryPartUuidOffset, 16));
            newPartitions[index].PartUuid.TryWriteBytes(backupArray.AsSpan(offset + EntryPartUuidOffset, 16));
            WriteUInt64(primaryArray, offset + EntryStartOffset, (ulong)newPartitions[index].StartSector);
            WriteUInt64(backupArray, offset + EntryStartOffset, (ulong)newPartitions[index].StartSector);
            WriteUInt64(
                primaryArray,
                offset + EntryEndOffset,
                (ulong)(newPartitions[index].StartSector + newPartitions[index].SectorCount - 1));
            WriteUInt64(
                backupArray,
                offset + EntryEndOffset,
                (ulong)(newPartitions[index].StartSector + newPartitions[index].SectorCount - 1));

            var nameBytes = Encoding.Unicode.GetBytes(newPartitions[index].Name);
            if (nameBytes.Length > EntryNameBytes)
            {
                throw new InvalidDataException($"The partition name '{newPartitions[index].Name}' is too long.");
            }

            nameBytes.CopyTo(primaryArray, offset + EntryNameOffset);
            nameBytes.CopyTo(backupArray, offset + EntryNameOffset);
        }

        var arrayCrc = Crc32(primaryArray.AsSpan(0, entryBytes));
        if (Crc32(backupArray.AsSpan(0, entryBytes)) != arrayCrc)
        {
            throw new InvalidDataException("The rewritten primary and backup entry arrays diverged.");
        }

        var primaryHeader = new byte[sectorSize];
        Buffer.BlockCopy(primaryFragment, primaryHeaderOffset, primaryHeader, 0, sectorSize);
        SealHeader(primaryHeader, headerSize, arrayCrc);

        var backupHeader = new byte[sectorSize];
        Buffer.BlockCopy(backupFragment, backupHeaderOffset, backupHeader, 0, sectorSize);
        SealHeader(backupHeader, headerSize, arrayCrc);

        var postPrimary = (byte[])primaryFragment.Clone();
        Buffer.BlockCopy(primaryHeader, 0, postPrimary, primaryHeaderOffset, sectorSize);
        Buffer.BlockCopy(primaryArray, 0, postPrimary, primaryArrayOffset, arrayLength);

        var postBackup = (byte[])backupFragment.Clone();
        Buffer.BlockCopy(backupHeader, 0, postBackup, backupHeaderOffset, sectorSize);
        Buffer.BlockCopy(backupArray, 0, postBackup, backupArrayOffset, arrayLength);

        var postTable = OriginalGptImporter.Parse(postPrimary, postBackup, sectorSize, diskBytes);
        ConfirmPostTable(original, postTable, allocation, newPartitions);

        var descriptors = new[]
        {
            new GptWriteDescriptor(
                "backup-array", backupArrayLba, arraySectors, sectorSize, backupArray),
            new GptWriteDescriptor("backup-header", lastLba, 1, sectorSize, backupHeader),
            new GptWriteDescriptor(
                "primary-array", primaryArrayLba, arraySectors, sectorSize, primaryArray),
            new GptWriteDescriptor("primary-header", 1L, 1, sectorSize, primaryHeader),
        };

        var boot = FindPartition(postTable, newPartitions[0].Number)
            ?? throw new InvalidDataException("The rebuilt table does not contain ARMADA_BOOT.");
        var root = FindPartition(postTable, newPartitions[1].Number)
            ?? throw new InvalidDataException("The rebuilt table does not contain ARMADA_ROOT.");
        var backup = FindPartition(postTable, newPartitions[2].Number)
            ?? throw new InvalidDataException("The rebuilt table does not contain ARMADA_BACKUP.");

        return new GptRewrite
        {
            WriteRegions = new ReadOnlyCollection<GptWriteDescriptor>(descriptors),
            PostPrimaryFragment = postPrimary,
            PostBackupFragment = postBackup,
            PostTable = postTable,
            NewPartitions = newPartitions,
            LinuxBoot = boot,
            LinuxRoot = root,
            BackupPartition = backup,
            PostGptPrimarySha256 = Sha256Hex(postPrimary),
            PostGptBackupSha256 = Sha256Hex(postBackup),
        };
    }

    /// <summary>Parses the raw LUN0 windows and refuses bytes that no longer match the backup's fingerprint.</summary>
    internal static GptTable ReadAndValidateOriginal(
        byte[] primaryFragment, byte[] backupFragment, int sectorSize, long diskBytes,
        string expectedSourceFingerprint)
    {
        if (string.IsNullOrWhiteSpace(expectedSourceFingerprint))
        {
            throw new ArgumentException(
                "The backup names no source fingerprint for LUN0.", nameof(expectedSourceFingerprint));
        }

        var table = OriginalGptImporter.Parse(primaryFragment, backupFragment, sectorSize, diskBytes);
        if (!string.Equals(table.SourceFingerprint, expectedSourceFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The raw LUN0 GPT bytes no longer match the table the backup verified; the capture changed.");
        }

        return table;
    }

    private static void ConfirmPostTable(
        GptTable original,
        GptTable post,
        InternalAllocationPlan allocation,
        IReadOnlyList<NewPartition> newPartitions)
    {
        if (post.Partitions.Count != original.Partitions.Count + 3)
        {
            throw new InvalidDataException("The rebuilt table does not carry exactly three extra entries.");
        }

        if (!string.Equals(post.DiskGuid, original.DiskGuid, StringComparison.OrdinalIgnoreCase)
            || post.SectorSize != original.SectorSize
            || post.DiskBytes != original.DiskBytes)
        {
            throw new InvalidDataException("The rebuilt table describes a different disk.");
        }

        var userdataNumber = allocation.OriginalUserdata.Number;
        foreach (var before in original.Partitions)
        {
            var after = FindPartition(post, before.Number);
            if (after is null)
            {
                throw new InvalidDataException($"The rebuilt table dropped entry {before.Number}.");
            }

            if (before.Number == userdataNumber)
            {
                if (!string.Equals(after.Name, before.Name, StringComparison.Ordinal)
                    || !string.Equals(after.TypeGuid, before.TypeGuid, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(after.PartUuid, before.PartUuid, StringComparison.OrdinalIgnoreCase)
                    || after.StartSector != before.StartSector
                    || after.SectorCount != allocation.AndroidSectorCount
                    || after.Attributes != before.Attributes)
                {
                    throw new InvalidDataException("The rebuilt userdata entry is not the planned shrink.");
                }

                continue;
            }

            if (!SamePartition(after, before))
            {
                throw new InvalidDataException($"The rebuilt entry {before.Number} is not byte-for-byte the original.");
            }
        }

        foreach (var planned in newPartitions)
        {
            var after = FindPartition(post, planned.Number);
            if (after is null
                || !string.Equals(after.Name, planned.Name, StringComparison.Ordinal)
                || !string.Equals(after.TypeGuid, LinuxDataGuidText, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(after.PartUuid, planned.PartUuid.ToString("D").ToUpperInvariant(), StringComparison.Ordinal)
                || after.StartSector != planned.StartSector
                || after.SectorCount != planned.SectorCount
                || after.Attributes != 0UL)
            {
                throw new InvalidDataException($"The rebuilt table does not carry '{planned.Name}' as planned.");
            }
        }
    }

    private static bool SamePartition(GptPartition left, GptPartition right) =>
        left.Number == right.Number
        && string.Equals(left.Name, right.Name, StringComparison.Ordinal)
        && string.Equals(left.TypeGuid, right.TypeGuid, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.PartUuid, right.PartUuid, StringComparison.OrdinalIgnoreCase)
        && left.StartSector == right.StartSector
        && left.SectorCount == right.SectorCount
        && left.Attributes == right.Attributes;

    private static void SealHeader(Span<byte> header, int headerSize, uint arrayCrc)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(EntryArrayCrcOffset, 4), arrayCrc);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(HeaderCrcFieldOffset, 4), 0u);
        BinaryPrimitives.WriteUInt32LittleEndian(
            header.Slice(HeaderCrcFieldOffset, 4), Crc32(header.Slice(0, headerSize)));
    }

    private static int LocateEntryArray(
        byte[] fragment, long arrayLba, long originLba, int arrayLength, int sectorSize, string what)
    {
        var sectorOffset = arrayLba - originLba;
        if (sectorOffset < 0 || sectorOffset > int.MaxValue / sectorSize)
        {
            throw new InvalidDataException($"The {what} GPT entry array is not inside its capture.");
        }

        var byteOffset = sectorOffset * (long)sectorSize;
        if (byteOffset > fragment.Length - arrayLength)
        {
            throw new InvalidDataException(
                $"The {what} GPT entry array is not fully present in its {GptCaptureSectors} sector capture.");
        }

        return (int)byteOffset;
    }

    private static void RequireHeaderSector(byte[] fragment, int headerOffset, int sectorSize, string what)
    {
        if (headerOffset < 0 || headerOffset > fragment.Length - sectorSize)
        {
            throw new InvalidDataException(
                $"The {what} capture does not contain a full GPT header sector at its expected location.");
        }
    }

    internal static PartitionUuids CreatePartitionUuids(GptTable original)
    {
        var used = new HashSet<Guid>();
        foreach (var partition in original.Partitions)
        {
            if (Guid.TryParse(partition.PartUuid, out var existing))
            {
                used.Add(existing);
            }
        }

        return new PartitionUuids
        {
            Boot = NewUniqueUuid(used),
            Root = NewUniqueUuid(used),
            Backup = NewUniqueUuid(used),
        };
    }

    private static Guid NewUniqueUuid(HashSet<Guid> used)
    {
        while (true)
        {
            var candidate = Guid.NewGuid();
            if (candidate != Guid.Empty && used.Add(candidate))
            {
                return candidate;
            }
        }
    }

    // ------------------------------------------------------------- record and manifest

    private static byte[] BuildInstallationRecord(
        Guid installationId,
        InternalBackupSet backup,
        GptTable original,
        EdlGeometry geometry,
        InternalAllocationPlan allocation,
        GptRewrite rewrite,
        PartitionUuids uuids)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 2);
            json.WriteString("kind", "armada-internal-install");
            json.WriteString("status", "prepared");
            json.WriteString("installationId", installationId.ToString("D"));
            json.WriteString("profileId", backup.ProfileId ?? string.Empty);
            json.WriteString("model", backup.Model ?? string.Empty);
            json.WriteString("androidBuild", backup.AndroidBuild ?? string.Empty);
            json.WriteString("hardwareId", backup.HardwareId ?? string.Empty);
            json.WriteString("backupManifestSha256", backup.ManifestSha256 ?? string.Empty);

            json.WriteStartObject("originalLun0");
            json.WriteNumber("lun", 0);
            json.WriteNumber("sectorSize", geometry.SectorSize);
            json.WriteNumber("totalSectors", geometry.TotalSectors);
            json.WriteString("diskGuid", original.DiskGuid);
            json.WriteString("sourceFingerprint", original.SourceFingerprint);
            json.WriteEndObject();

            json.WriteStartObject("allocation");
            json.WriteStartObject("originalUserdata");
            json.WriteNumber("number", allocation.OriginalUserdata.Number);
            json.WriteString("name", allocation.OriginalUserdata.Name);
            json.WriteString("typeGuid", allocation.OriginalUserdata.TypeGuid);
            json.WriteString("partUuid", allocation.OriginalUserdata.PartUuid);
            json.WriteNumber("startSector", allocation.OriginalUserdata.StartSector);
            json.WriteNumber("sectorCount", allocation.OriginalUserdata.SectorCount);
            json.WriteNumber("attributes", allocation.OriginalUserdata.Attributes);
            json.WriteEndObject();
            json.WriteNumber("sectorSize", allocation.SectorSize);
            json.WriteNumber("originalUserdataEndSectorExclusive", allocation.OriginalUserdataEndSectorExclusive);
            json.WriteNumber("androidBytes", allocation.AndroidBytes);
            json.WriteNumber("androidSectorCount", allocation.AndroidSectorCount);
            json.WriteNumber("androidEndSectorExclusive", allocation.AndroidEndSectorExclusive);
            json.WriteNumber("linuxBytes", allocation.LinuxBytes);
            json.WriteNumber("linuxBootBytes", allocation.LinuxBootBytes);
            json.WriteNumber("linuxRootBytes", allocation.LinuxRootBytes);
            json.WriteNumber("estimatedLinuxDataBytes", allocation.EstimatedLinuxDataBytes);
            json.WriteNumber("linuxBootStartSector", allocation.LinuxBootStartSector);
            json.WriteNumber("linuxBootSectorCount", allocation.LinuxBootSectorCount);
            json.WriteNumber("linuxRootStartSector", allocation.LinuxRootStartSector);
            json.WriteNumber("linuxRootSectorCount", allocation.LinuxRootSectorCount);
            json.WriteNumber("backupBytes", allocation.BackupBytes);
            json.WriteNumber("backupStartSector", allocation.BackupStartSector);
            json.WriteNumber("backupSectorCount", allocation.BackupSectorCount);
            json.WriteNumber("backupEndSectorExclusive", allocation.BackupEndSectorExclusive);
            json.WriteNumber("alignmentGapSectors", allocation.AlignmentGapSectors);
            json.WriteNumber("tailUnallocatedSectors", allocation.TailUnallocatedSectors);
            json.WriteNumber("alignmentLossBytes", allocation.AlignmentLossBytes);
            json.WriteEndObject();

            json.WriteStartArray("newPartitions");
            foreach (var partition in rewrite.NewPartitions)
            {
                json.WriteStartObject();
                json.WriteString("name", partition.Name);
                json.WriteNumber("number", partition.Number);
                json.WriteString("partUuid", partition.PartUuid.ToString("D").ToUpperInvariant());
                json.WriteString("typeGuid", LinuxDataGuidText);
                json.WriteNumber("attributes", 0UL);
                json.WriteNumber("startSector", partition.StartSector);
                json.WriteNumber("sectorCount", partition.SectorCount);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartObject("postGpt");
            json.WriteString("sourceFingerprint", rewrite.PostTable.SourceFingerprint);
            json.WriteString("primaryFileSha256", rewrite.PostGptPrimarySha256);
            json.WriteString("backupFileSha256", rewrite.PostGptBackupSha256);
            json.WriteNumber("primaryStartSector", 0);
            json.WriteNumber("primarySectorCount", rewrite.PostPrimaryFragment.Length / allocation.SectorSize);
            json.WriteNumber(
                "backupStartSector",
                geometry.TotalSectors - (rewrite.PostBackupFragment.Length / allocation.SectorSize));
            json.WriteNumber("backupSectorCount", rewrite.PostBackupFragment.Length / allocation.SectorSize);
            json.WriteEndObject();

            json.WriteStartArray("gptWrites");
            foreach (var descriptor in rewrite.WriteRegions)
            {
                json.WriteStartObject();
                json.WriteString("role", descriptor.Role);
                json.WriteNumber("startSector", descriptor.StartSector);
                json.WriteNumber("sectorCount", descriptor.SectorCount);
                json.WriteNumber("sectorSize", descriptor.SectorSize);
                json.WriteNumber("length", descriptor.Length);
                json.WriteString("sha256", descriptor.Sha256);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartArray("excludedRoles");
            json.WriteEndArray();

            json.WriteString("boardFormat", BoardArchiveFormat);
            json.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static byte[] BuildRecoveryManifestJson(
        Guid installationId,
        string planSha256,
        string pcManifestSha256,
        string originalFingerprint,
        string postFingerprint,
        PartitionUuids uuids,
        IReadOnlyList<ArchivePayload> payloads,
        PayloadLayout layout)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 2);
            json.WriteString("kind", "armada-board-recovery");
            json.WriteString("offsetSpace", "uncompressed-tar");
            json.WriteString("installationId", installationId.ToString("D"));
            json.WriteString("planSha256", planSha256);
            json.WriteString("pcBackupManifestSha256", pcManifestSha256 ?? string.Empty);
            json.WriteString("originalGptSourceFingerprint", originalFingerprint);
            json.WriteString("postGptSourceFingerprint", postFingerprint);

            json.WriteStartArray("ownedPartitionUuids");
            json.WriteStringValue(uuids.Boot.ToString("D").ToUpperInvariant());
            json.WriteStringValue(uuids.Root.ToString("D").ToUpperInvariant());
            json.WriteStringValue(uuids.Backup.ToString("D").ToUpperInvariant());
            json.WriteEndArray();

            json.WriteStartArray("excludedRoles");
            json.WriteEndArray();

            json.WriteStartArray("entries");
            for (var index = 0; index < payloads.Count; index++)
            {
                var payload = payloads[index];
                json.WriteStartObject();
                json.WriteString("role", payload.Role);
                json.WriteString("path", payload.EntryName);
                json.WriteNumber("tarHeaderOffset", layout.HeaderOffsets[index]);
                json.WriteNumber("dataOffset", layout.DataOffsets[index]);
                json.WriteNumber("length", payload.Length);
                json.WriteString("sha256", payload.Sha256);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static byte[] BuildSummaryManifest(
        Guid installationId,
        string planSha256,
        InternalAllocationPlan allocation,
        GptRewrite rewrite,
        IReadOnlyList<InternalArtifactRegion> writeRegions,
        InternalArtifactRegion postPrimary,
        InternalArtifactRegion postBackup,
        long usedBytes,
        long compressedBytes,
        string compressedSha256,
        long uncompressedTarBytes,
        string recoveryManifestSha256,
        string archivePath,
        string archiveSha256)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 2);
            json.WriteString("kind", "armada-install-artifacts");
            json.WriteString("boardFormat", BoardArchiveFormat);
            json.WriteString("installationId", installationId.ToString("D"));
            json.WriteString("planSha256", planSha256);

            json.WriteStartObject("recoveryManifest");
            json.WriteString("fileName", RecoveryManifestEntryName);
            json.WriteNumber("length", ManifestPayloadBytes);
            json.WriteString("sha256", recoveryManifestSha256);
            json.WriteEndObject();

            json.WriteStartObject("boardArchive");
            json.WriteString("fileName", Path.GetFileName(archivePath));
            json.WriteNumber("length", BoardArchiveBytes);
            json.WriteNumber("usedBytes", usedBytes);
            json.WriteString("sha256", archiveSha256);
            json.WriteString("format", BoardArchiveFormat);
            json.WriteNumber("payloadOffset", BoardHeaderBytes);
            json.WriteNumber("compressedBytes", compressedBytes);
            json.WriteString("compressedSha256", compressedSha256);
            json.WriteNumber("uncompressedTarBytes", uncompressedTarBytes);
            json.WriteEndObject();

            json.WriteStartObject("backupPartition");
            json.WriteNumber("number", rewrite.BackupPartition.Number);
            json.WriteString("partUuid", rewrite.BackupPartition.PartUuid);
            json.WriteNumber("startSector", rewrite.BackupPartition.StartSector);
            json.WriteNumber("sectorCount", rewrite.BackupPartition.SectorCount);
            json.WriteEndObject();

            json.WriteStartArray("gptWrites");
            foreach (var region in writeRegions)
            {
                json.WriteStartObject();
                json.WriteString("role", region.Role);
                json.WriteNumber("startSector", region.StartSector);
                json.WriteNumber("sectorCount", region.SectorCount);
                json.WriteNumber("sectorSize", region.SectorSize);
                json.WriteNumber("length", region.Length);
                json.WriteString("sha256", region.Sha256);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            json.WriteStartObject("postGpt");
            WriteRegion(json, "primary", postPrimary);
            WriteRegion(json, "backup", postBackup);
            json.WriteEndObject();

            json.WriteStartArray("excludedRoles");
            json.WriteEndArray();
            json.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteRegion(Utf8JsonWriter json, string name, InternalArtifactRegion region)
    {
        json.WriteStartObject(name);
        json.WriteString("role", region.Role);
        json.WriteNumber("startSector", region.StartSector);
        json.WriteNumber("sectorCount", region.SectorCount);
        json.WriteNumber("sectorSize", region.SectorSize);
        json.WriteNumber("length", region.Length);
        json.WriteString("sha256", region.Sha256);
        json.WriteEndObject();
    }

    private static IReadOnlyList<ArchivePayload> BuildPayloadList(
        IReadOnlyDictionary<string, VerifiedCapture> captures,
        InternalBackupSet backup,
        GptRewrite rewrite,
        byte[] recordBytes,
        string recordSha256)
    {
        var payloads = new List<ArchivePayload>(captures.Count);

        var roles = new List<string>(captures.Keys);
        roles.Sort(StringComparer.Ordinal);

        foreach (var role in roles)
        {
            var capture = captures[role];
            payloads.Add(new ArchivePayload
            {
                Role = role,
                EntryName = role + ".bin",
                Length = capture.Length,
                Sha256 = capture.Sha256,
                FilePath = capture.FilePath,
            });
        }

        var manifestInfo = new FileInfo(backup.ManifestPath);
        payloads.Add(new ArchivePayload
        {
            Role = "pc-backup-manifest",
            EntryName = PcManifestEntryName,
            Length = manifestInfo.Length,
            Sha256 = backup.ManifestSha256,
            FilePath = backup.ManifestPath,
        });

        payloads.Add(new ArchivePayload
        {
            Role = "post-gpt-primary",
            EntryName = PostGptPrimaryEntryName,
            Length = rewrite.PostPrimaryFragment.Length,
            Sha256 = rewrite.PostGptPrimarySha256,
            Bytes = rewrite.PostPrimaryFragment,
        });

        payloads.Add(new ArchivePayload
        {
            Role = "post-gpt-backup",
            EntryName = PostGptBackupEntryName,
            Length = rewrite.PostBackupFragment.Length,
            Sha256 = rewrite.PostGptBackupSha256,
            Bytes = rewrite.PostBackupFragment,
        });

        payloads.Add(new ArchivePayload
        {
            Role = "installation-record",
            EntryName = InstallationRecordEntryName,
            Length = recordBytes.Length,
            Sha256 = recordSha256,
            Bytes = recordBytes,
        });

        return new ReadOnlyCollection<ArchivePayload>(payloads);
    }

    private static byte[] PadManifest(byte[] json)
    {
        var padded = new byte[ManifestPayloadBytes];
        Buffer.BlockCopy(json, 0, padded, 0, json.Length);
        for (var index = json.Length; index < padded.Length; index++)
        {
            padded[index] = (byte)' ';
        }

        return padded;
    }

    // -------------------------------------------------------------------- tar layout

    /// <summary>
    /// Computes the exact Ustar layout of the board archive: every payload header sits on the 512 byte boundary
    /// that follows the previous payload's padded data, and every payload's data starts one block after its
    /// header.
    /// </summary>
    internal static PayloadLayout ComputePayloadLayout(IReadOnlyList<long> payloadLengths)
    {
        if (payloadLengths is null)
        {
            throw new ArgumentNullException(nameof(payloadLengths));
        }

        var headerOffsets = new long[payloadLengths.Count];
        var dataOffsets = new long[payloadLengths.Count];

        long cursor = TarBlockBytes + ManifestPayloadBytes;
        for (var index = 0; index < payloadLengths.Count; index++)
        {
            var length = payloadLengths[index];
            if (length < 0)
            {
                throw new InvalidDataException("A board archive payload has a negative length.");
            }

            headerOffsets[index] = cursor;
            dataOffsets[index] = cursor + TarBlockBytes;
            cursor = checked(dataOffsets[index] + AlignToBlock(length));
        }

        return new PayloadLayout(headerOffsets, dataOffsets, cursor);
    }

    /// <summary>
    /// Returns the exact uncompressed Ustar length: the fixed manifest entry, every payload's header and padded
    /// data, and the two end blocks. It throws only when the manifest cannot fit its 64 KiB slot or the layout
    /// overflows; the raw tar may legitimately exceed the fixed 2 GiB image because compression shrinks it, so
    /// the image fit is decided on the compressed member the writer actually produced.
    /// </summary>
    internal static long ComputeRequiredArchiveBytes(int manifestJsonLength, IReadOnlyList<long> payloadLengths)
    {
        if (manifestJsonLength <= 0 || manifestJsonLength > ManifestPayloadBytes)
        {
            throw new InvalidDataException(
                $"The recovery manifest is {manifestJsonLength} bytes; the fixed first payload holds 1 to {ManifestPayloadBytes}.");
        }

        try
        {
            var layout = ComputePayloadLayout(payloadLengths);
            return checked(layout.End + ArchiveTerminatorBytes);
        }
        catch (OverflowException)
        {
            throw new InvalidDataException("The board recovery archive size does not fit in 64 bits.");
        }
    }

    private static long AlignToBlock(long value) => checked((value + (TarBlockBytes - 1)) / TarBlockBytes * TarBlockBytes);

    // ----------------------------------------------------------------- archive write

    private static string WriteArchive(
        FileStream stream,
        Guid installationId,
        Guid backupPartitionUuid,
        string model,
        string planSha256,
        string recoveryManifestSha256,
        byte[] manifestPayload,
        IReadOnlyList<ArchivePayload> payloads,
        PayloadLayout layout,
        CancellationToken token,
        out long compressedBytes,
        out long uncompressedTarBytes,
        out string compressedSha256)
    {
        // Reserve the fixed outer header; its two length-dependent fields are only known after the gzip member
        // is finalized, so the bytes are stamped at offset zero once the compressed window has been hashed.
        stream.Position = 0;
        for (var reserved = 0; reserved < BoardHeaderBytes; reserved += ZeroChunk.Length)
        {
            stream.Write(ZeroChunk, 0, Math.Min(ZeroChunk.Length, BoardHeaderBytes - reserved));
        }

        stream.Position = BoardHeaderBytes;

        long written;
        using (var gzip = new GZipStream(stream, CompressionLevel.Fastest, leaveOpen: true))
        {
            var counter = new CountingWriteStream(gzip);

            using (var tar = new TarWriter(counter, TarEntryFormat.Ustar, leaveOpen: true))
            {
                using (var manifestStream = new MemoryStream(manifestPayload, writable: false))
                {
                    WriteTarEntry(
                        tar,
                        RecoveryManifestEntryName,
                        manifestStream,
                        manifestPayload.Length,
                        TarBlockBytes + ManifestPayloadBytes,
                        counter,
                        token);
                }

                for (var index = 0; index < payloads.Count; index++)
                {
                    token.ThrowIfCancellationRequested();

                    var payload = payloads[index];
                    var expectedEnd = layout.DataOffsets[index] + AlignToBlock(payload.Length);

                    if (payload.Bytes is not null)
                    {
                        using var data = new MemoryStream(payload.Bytes, writable: false);
                        WriteTarEntry(tar, payload.EntryName, data, payload.Length, expectedEnd, counter, token);
                        continue;
                    }

                    using var source = OpenVerifiedPayload(
                        payload.FilePath!, payload.Length, payload.Sha256);
                    WriteTarEntry(tar, payload.EntryName, source, payload.Length, expectedEnd, counter, token);
                }
            }

            written = counter.BytesWritten;
            if (written == layout.End)
            {
                counter.Write(ZeroChunk, 0, ArchiveTerminatorBytes);
                written += ArchiveTerminatorBytes;
            }
            else if (written != layout.End + ArchiveTerminatorBytes)
            {
                throw new InvalidDataException(
                    $"The tar stream ended at {written} bytes; the planned layout ends at {layout.End} plus {ArchiveTerminatorBytes}.");
            }
        }

        uncompressedTarBytes = written;

        stream.Flush(flushToDisk: true);

        compressedBytes = stream.Position - BoardHeaderBytes;
        if (compressedBytes <= 0 || compressedBytes > BootSettingsRegion.Offset - BoardHeaderBytes)
        {
            throw new InvalidDataException(
                $"The gzip member spans {compressedBytes} bytes; it must fit the {BootSettingsRegion.Offset - BoardHeaderBytes} bytes behind the header.");
        }

        compressedSha256 = HashRange(stream, BoardHeaderBytes, compressedBytes, token);

        var header = BuildBoardHeader(
            installationId,
            backupPartitionUuid,
            model,
            planSha256,
            recoveryManifestSha256,
            compressedBytes,
            compressedSha256,
            uncompressedTarBytes);

        stream.Position = 0;
        stream.Write(header, 0, header.Length);

        stream.Position = BoardHeaderBytes + compressedBytes;
        var remaining = BoardArchiveBytes - (BoardHeaderBytes + compressedBytes);
        while (remaining > 0)
        {
            var chunk = (int)Math.Min(ZeroChunk.Length, remaining);
            stream.Write(ZeroChunk, 0, chunk);
            remaining -= chunk;
        }

        // Only newly prepared images are provisioned. Existing v2 backups are never upgraded in place.
        var descriptor = BootSettingsRegion.CreateDescriptor(
            backupPartitionUuid, installationId, model, BoardHeaderBytes + compressedBytes);
        stream.Position = BootSettingsRegion.Offset;
        stream.Write(descriptor);
        stream.Flush(flushToDisk: true);

        if (stream.Length != BoardArchiveBytes)
        {
            throw new InvalidDataException(
                $"The board recovery image is {stream.Length} bytes, not the fixed {BoardArchiveBytes}.");
        }

        return HashStream(stream);
    }

    private static byte[] BuildBoardHeader(
        Guid installationId,
        Guid backupPartitionUuid,
        string model,
        string planSha256,
        string recoveryManifestSha256,
        long compressedBytes,
        string compressedSha256,
        long uncompressedTarBytes)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 3);
            json.WriteString("kind", BoardImageKind);
            json.WriteNumber("configRegionOffset", BootSettingsRegion.Offset);
            json.WriteNumber("configRegionBytes", BootSettingsRegion.Bytes);
            json.WriteString("configPartitionUuid", backupPartitionUuid.ToString("D"));
            json.WriteNumber("configBoardId", BootSettingsRegion.BoardId(model));
            json.WriteNumber("imageBytes", BoardArchiveBytes);
            json.WriteNumber("headerBytes", BoardHeaderBytes);
            json.WriteNumber("payloadOffset", BoardHeaderBytes);
            json.WriteString("compression", "gzip");
            json.WriteString("tarFormat", "ustar");
            json.WriteNumber("compressedBytes", compressedBytes);
            json.WriteString("compressedSha256", compressedSha256);
            json.WriteNumber("uncompressedTarBytes", uncompressedTarBytes);
            json.WriteString("installationId", installationId.ToString("D"));
            json.WriteString("planSha256", planSha256);
            json.WriteString("recoveryManifestSha256", recoveryManifestSha256);
            json.WriteEndObject();
        }

        var jsonBytes = buffer.ToArray();
        if (jsonBytes.Length > BoardHeaderBytes)
        {
            throw new InvalidDataException(
                $"The board image header needs {jsonBytes.Length} bytes; the fixed slot holds {BoardHeaderBytes}.");
        }

        var padded = new byte[BoardHeaderBytes];
        jsonBytes.CopyTo(padded, 0);
        for (var index = jsonBytes.Length; index < padded.Length; index++)
        {
            padded[index] = (byte)' ';
        }

        return padded;
    }

    private static void WriteTarEntry(
        TarWriter tar,
        string entryName,
        Stream data,
        long expectedLength,
        long expectedEnd,
        CountingWriteStream output,
        CancellationToken token)
    {
        if (data.Length != expectedLength)
        {
            throw new InvalidDataException(
                $"The tar payload '{entryName}' is {data.Length} bytes, not the planned {expectedLength}.");
        }

        var entry = new UstarTarEntry(TarEntryType.RegularFile, entryName)
        {
            DataStream = data,
            ModificationTime = FixedTarTimestamp,
            Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
            Uid = 0,
            Gid = 0,
            UserName = string.Empty,
            GroupName = string.Empty,
        };

        tar.WriteEntry(entry);

        if (output.BytesWritten != expectedEnd)
        {
            throw new InvalidDataException(
                $"The tar entry '{entryName}' ended at {output.BytesWritten} bytes, not the planned {expectedEnd}.");
        }

        token.ThrowIfCancellationRequested();
    }

    /// <summary>
    /// Opens one payload and verifies it while the tar writer streams it, so a source that changed after the
    /// first hash is refused instead of being copied into a "verified" archive.
    /// </summary>
    internal static Stream OpenVerifiedPayload(string filePath, long expectedLength, string expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("A payload needs a file path.", nameof(filePath));
        }

        var info = new FileInfo(filePath);
        if (!info.Exists || (info.Attributes & FileAttributes.Directory) != 0)
        {
            throw new FileNotFoundException("A board archive payload is missing.", filePath);
        }

        if (info.Length != expectedLength)
        {
            throw new InvalidDataException(
                $"The payload '{Path.GetFileName(filePath)}' is {info.Length} bytes, not the verified {expectedLength}.");
        }

        var stream = new FileStream(
            filePath, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);

        return new VerifiedPayloadStream(stream, expectedLength, expectedSha256);
    }

    // ------------------------------------------------------------- board image verify

    /// <summary>
    /// Re-reads a finished board image exactly as a consumer does and returns the validated inner recovery
    /// manifest as a detached clone. Validates the fixed header and bounds, the compressed window's exact
    /// SHA-256, a bounded standard gzip member whose CRC/ISIZE are observed at EOF, the 64 KiB first entry, every
    /// listed Ustar entry in order, the complete tar end and the zero padding. The caller owns
    /// <paramref name="image"/>; it is never closed and its position is left at the end of the image.
    /// </summary>
    /// <exception cref="InvalidDataException">Any physical, identity, ordering or hash check fails.</exception>
    internal static JsonElement VerifyBoardArchive(Stream image, string model, CancellationToken token)
    {
        var contract = InternalInstallBackupRoles.ForModel(model);

        if (image is null)
        {
            throw new ArgumentNullException(nameof(image));
        }

        if (!image.CanRead || !image.CanSeek)
        {
            throw new ArgumentException(
                "The board image must be readable and seekable; the caller owns it.", nameof(image));
        }

        token.ThrowIfCancellationRequested();

        if (image.Length != BoardArchiveBytes)
        {
            throw new InvalidDataException(
                $"The board image is {image.Length} bytes, not the fixed {BoardArchiveBytes}.");
        }

        image.Position = 0;
        var headerBytes = new byte[BoardHeaderBytes];
        ReadExactly(image, headerBytes, 0, headerBytes.Length, "the board image header");

        using var header = ParseJson(headerBytes, "board image header");
        var root = header.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The board image header is not a JSON object.");
        }

        long schemaVersion = RequireInt64(root, "schemaVersion");
        if (schemaVersion is not (2 or 3))
            throw new InvalidDataException("The board image header is not schema version 2 or 3.");
        long payloadLimit = schemaVersion == 3 ? BootSettingsRegion.Offset : BoardArchiveBytes;
        Guid configPartitionUuid = Guid.Empty;
        if (schemaVersion == 3)
        {
            string uuid = RequireString(root, "configPartitionUuid");
            if (RequireInt64(root, "configRegionOffset") != BootSettingsRegion.Offset ||
                RequireInt64(root, "configRegionBytes") != BootSettingsRegion.Bytes ||
                RequireInt64(root, "configBoardId") != BootSettingsRegion.BoardId(model) ||
                !Guid.TryParse(uuid, out configPartitionUuid) || configPartitionUuid == Guid.Empty ||
                uuid != configPartitionUuid.ToString("D"))
                throw new InvalidDataException("The launcher settings region has a different layout or identity.");
        }

        if (!string.Equals(RequireString(root, "kind"), BoardImageKind, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The board image header names a different kind.");
        }

        if (RequireInt64(root, "imageBytes") != BoardArchiveBytes
            || RequireInt64(root, "headerBytes") != BoardHeaderBytes
            || RequireInt64(root, "payloadOffset") != BoardHeaderBytes)
        {
            throw new InvalidDataException("The board image header declares a different fixed geometry.");
        }

        if (!string.Equals(RequireString(root, "compression"), "gzip", StringComparison.Ordinal)
            || !string.Equals(RequireString(root, "tarFormat"), "ustar", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The board image header declares a different compression or tar format.");
        }

        var compressedBytes = RequireInt64(root, "compressedBytes");
        if (compressedBytes <= 0 || compressedBytes > payloadLimit - BoardHeaderBytes)
        {
            throw new InvalidDataException(
                $"The board image declares {compressedBytes} compressed bytes, outside the payload window.");
        }

        var uncompressedTarBytes = RequireInt64(root, "uncompressedTarBytes");
        if (uncompressedTarBytes < ArchiveTerminatorBytes || uncompressedTarBytes % TarBlockBytes != 0)
        {
            throw new InvalidDataException("The board image declares an impossible uncompressed tar length.");
        }

        var installationIdText = RequireString(root, "installationId");
        if (!Guid.TryParse(installationIdText, out var installationId)
            || !string.Equals(installationIdText, installationId.ToString("D"), StringComparison.Ordinal))
        {
            throw new InvalidDataException("The board image header carries no canonical installation id.");
        }

        var planSha256 = RequireString(root, "planSha256");
        RequireSha256(planSha256, "planSha256");
        var manifestSha256 = RequireString(root, "recoveryManifestSha256");
        RequireSha256(manifestSha256, "recoveryManifestSha256");
        var compressedSha256 = RequireString(root, "compressedSha256");
        RequireSha256(compressedSha256, "compressedSha256");

        token.ThrowIfCancellationRequested();

        var actualCompressedSha = HashRange(image, BoardHeaderBytes, compressedBytes, token);
        if (!HexEquals(actualCompressedSha, compressedSha256))
        {
            throw new InvalidDataException(
                "The board image's compressed window does not hash to its declared SHA-256.");
        }

        JsonElement manifestElement;
        long tarBytesSeen;

        using (var bounded = new BoundedReadStream(image, BoardHeaderBytes, compressedBytes))
        using (var gzip = new GZipStream(bounded, CompressionMode.Decompress, leaveOpen: false))
        using (var counted = new CountingReadStream(gzip))
        using (var tar = new TarReader(counted, leaveOpen: true))
        {
            var manifestEntry = tar.GetNextEntry()
                ?? throw new InvalidDataException("The board image carries no recovery manifest entry.");
            var manifestData = manifestEntry.DataStream;
            if (!string.Equals(manifestEntry.Name, RecoveryManifestEntryName, StringComparison.Ordinal)
                || manifestEntry.EntryType != TarEntryType.RegularFile
                || manifestEntry.Length != ManifestPayloadBytes
                || manifestData is null)
            {
                throw new InvalidDataException(
                    "The board image's first tar entry is not the fixed 64 KiB recovery manifest.");
            }

            var manifestBytes = new byte[ManifestPayloadBytes];
            ReadExactly(manifestData, manifestBytes, 0, manifestBytes.Length, "the recovery manifest");
            if (!HexEquals(Sha256Hex(manifestBytes), manifestSha256))
            {
                throw new InvalidDataException("The recovery manifest does not hash to its declared SHA-256.");
            }

            if (counted.BytesRead != TarBlockBytes + ManifestPayloadBytes)
            {
                throw new InvalidDataException("The recovery manifest entry does not occupy its fixed tar slot.");
            }

            using var manifest = ParseJson(manifestBytes, "recovery manifest");
            var inner = manifest.RootElement;
            if (inner.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("The recovery manifest is not a JSON object.");
            }

            if (RequireInt64(inner, "schemaVersion") != 2)
            {
                throw new InvalidDataException("The recovery manifest is not schema version 2.");
            }

            if (!string.Equals(RequireString(inner, "kind"), "armada-board-recovery", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The recovery manifest names a different kind.");
            }

            if (!string.Equals(RequireString(inner, "offsetSpace"), "uncompressed-tar", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The recovery manifest does not address the uncompressed tar coordinate space.");
            }

            if (!string.Equals(RequireString(inner, "installationId"), installationIdText, StringComparison.Ordinal)
                || !string.Equals(RequireString(inner, "planSha256"), planSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The recovery manifest's installation id or plan id differs from the outer header.");
            }

            if (!inner.TryGetProperty("excludedRoles", out var excluded)
                || excluded.ValueKind != JsonValueKind.Array
                || excluded.GetArrayLength() != 0)
            {
                throw new InvalidDataException("The recovery manifest must exclude no role.");
            }

            if (!inner.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException("The recovery manifest lists no entries array.");
            }

            var count = entries.GetArrayLength();
            if (count < MetadataRoles.Length)
            {
                throw new InvalidDataException("The recovery manifest lists fewer entries than its four metadata files.");
            }

            var captureCount = count - MetadataRoles.Length;
            var roles = new string[count];
            var paths = new string[count];
            var lengths = new long[count];
            var headerOffsets = new long[count];
            var dataOffsets = new long[count];
            var hashes = new string[count];
            var seenRoles = new HashSet<string>(StringComparer.Ordinal);
            var seenPaths = new HashSet<string>(StringComparer.Ordinal);

            long cursor = TarBlockBytes + ManifestPayloadBytes;
            for (var index = 0; index < count; index++)
            {
                token.ThrowIfCancellationRequested();

                var item = entries[index];
                if (item.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("A recovery manifest entry is not an object.");
                }

                var role = RequireString(item, "role");
                var path = RequireString(item, "path");
                var length = RequireInt64(item, "length");
                var headerOffset = RequireInt64(item, "tarHeaderOffset");
                var dataOffset = RequireInt64(item, "dataOffset");
                var sha256 = RequireString(item, "sha256");
                RequireSha256(sha256, "entries[].sha256");

                if (role.Length == 0 || !seenRoles.Add(role) || !seenPaths.Add(path))
                {
                    throw new InvalidDataException("The recovery manifest repeats or omits an entry identity.");
                }

                if (length < 0)
                {
                    throw new InvalidDataException("The recovery manifest declares a negative entry length.");
                }

                if (index >= captureCount)
                {
                    var metadataIndex = index - captureCount;
                    if (!string.Equals(role, MetadataRoles[metadataIndex], StringComparison.Ordinal)
                        || !string.Equals(path, MetadataEntryName(role), StringComparison.Ordinal))
                    {
                        throw new InvalidDataException(
                            "The recovery manifest's metadata entries are not the four fixed names in order.");
                    }
                }
                else
                {
                    if (Array.IndexOf(MetadataRoles, role) >= 0
                        || !string.Equals(path, role + ".bin", StringComparison.Ordinal))
                    {
                        throw new InvalidDataException(
                            $"The recovery manifest's capture entry '{role}' has an unexpected name or role.");
                    }

                    if (index > 0 && StringComparer.Ordinal.Compare(roles[index - 1], role) >= 0)
                    {
                        throw new InvalidDataException("The recovery manifest's capture roles are not in ordinal order.");
                    }
                }

                if (headerOffset != cursor || dataOffset != cursor + TarBlockBytes)
                {
                    throw new InvalidDataException(
                        $"The recovery manifest entry '{path}' does not carry its exact Ustar offsets.");
                }

                try
                {
                    cursor = checked(dataOffset + AlignToBlock(length));
                }
                catch (OverflowException)
                {
                    throw new InvalidDataException("The recovery manifest declares an unrepresentable tar layout.");
                }

                if (cursor > uncompressedTarBytes - ArchiveTerminatorBytes)
                {
                    throw new InvalidDataException("The recovery manifest's entries overrun the declared tar length.");
                }

                roles[index] = role;
                paths[index] = path;
                lengths[index] = length;
                headerOffsets[index] = headerOffset;
                dataOffsets[index] = dataOffset;
                hashes[index] = sha256;
            }

            // The manifest's capture entries - never its four metadata entries - select the contract that the
            // mandatory-role loop below enforces. Only the baseline roles plus one optional efisp may appear.
            var capturedRoleNames = new string[captureCount];
            Array.Copy(roles, capturedRoleNames, captureCount);
            contract = contract.ForCapturedRoles(capturedRoleNames);

            foreach (var required in contract.RequiredRoles)
            {
                if (!seenRoles.Contains(required))
                {
                    throw new InvalidDataException(
                        $"The recovery manifest is missing the required captured role '{required}'.");
                }
            }

            if (cursor + ArchiveTerminatorBytes != uncompressedTarBytes)
            {
                throw new InvalidDataException(
                    "The recovery manifest's entries do not account for the declared uncompressed tar length.");
            }

            var buffer = new byte[CopyBufferBytes];
            for (var index = 0; index < count; index++)
            {
                token.ThrowIfCancellationRequested();

                var entry = tar.GetNextEntry()
                    ?? throw new InvalidDataException($"The tar stream ends before the declared entry '{paths[index]}'.");
                var dataStream = entry.DataStream;
                if (!string.Equals(entry.Name, paths[index], StringComparison.Ordinal)
                    || entry.EntryType != TarEntryType.RegularFile
                    || entry.Length != lengths[index]
                    || dataStream is null)
                {
                    throw new InvalidDataException(
                        $"The tar entry '{paths[index]}' is not the declared regular file of the declared length.");
                }

                if (counted.BytesRead != dataOffsets[index])
                {
                    throw new InvalidDataException(
                        $"The tar entry '{paths[index]}' starts at {counted.BytesRead}, not at its declared data offset.");
                }

                using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    var remaining = lengths[index];
                    while (remaining > 0)
                    {
                        var read = dataStream.Read(
                            buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (read <= 0)
                        {
                            throw new InvalidDataException(
                                $"The tar entry '{paths[index]}' ends before its declared length.");
                        }

                        hash.AppendData(buffer, 0, read);
                        remaining -= read;
                        token.ThrowIfCancellationRequested();
                    }

                    if (!HexEquals(Convert.ToHexString(hash.GetHashAndReset()), hashes[index]))
                    {
                        throw new InvalidDataException(
                            $"The tar entry '{paths[index]}' does not hash to its declared SHA-256.");
                    }
                }

                if (counted.BytesRead != dataOffsets[index] + lengths[index])
                {
                    throw new InvalidDataException(
                        $"The tar entry '{paths[index]}' does not occupy its declared data window.");
                }

                if (index == count - 1 && !HexEquals(hashes[index], planSha256))
                {
                    throw new InvalidDataException(
                        "The archived installation record does not hash to the declared plan id.");
                }
            }

            if (tar.GetNextEntry() is not null)
            {
                throw new InvalidDataException("The tar stream carries entries the recovery manifest does not list.");
            }

            long drained = 0;
            int trailing;
            while ((trailing = counted.Read(buffer, 0, buffer.Length)) > 0)
            {
                for (var index = 0; index < trailing; index++)
                {
                    if (buffer[index] != 0)
                    {
                        throw new InvalidDataException("The tar stream's closing blocks are not zero filled.");
                    }
                }

                drained += trailing;
                token.ThrowIfCancellationRequested();
            }

            tarBytesSeen = counted.BytesRead;
            if (tarBytesSeen != uncompressedTarBytes || drained > ArchiveTerminatorBytes)
            {
                throw new InvalidDataException(
                    $"The gzip member carries {tarBytesSeen} tar bytes, not the declared {uncompressedTarBytes}.");
            }

            manifestElement = inner.Clone();
        }

        if (schemaVersion == 3)
        {
            if (!manifestElement.TryGetProperty("ownedPartitionUuids", out var owned) ||
                owned.ValueKind != JsonValueKind.Array || owned.GetArrayLength() != 3 ||
                owned[2].ValueKind != JsonValueKind.String ||
                !Guid.TryParse(owned[2].GetString(), out var backupUuid) || backupUuid != configPartitionUuid)
                throw new InvalidDataException("The settings region is not bound to the recovery backup partition.");
            image.Position = BootSettingsRegion.Offset;
            var region = new byte[BootSettingsRegion.Bytes];
            ReadExactly(image, region, 0, region.Length, "the launcher settings region");
            BootSettingsRegion.VerifyRegion(region, configPartitionUuid, installationId, model,
                BoardHeaderBytes + compressedBytes);
        }
        VerifyZeroPadding(image, BoardHeaderBytes + compressedBytes, payloadLimit, token);

        return manifestElement;
    }

    private static void VerifyZeroPadding(Stream image, long startOffset, long endOffset, CancellationToken token)
    {
        image.Position = startOffset;
        var expected = endOffset - startOffset;
        var buffer = new byte[CopyBufferBytes];
        long scanned = 0;
        while (scanned < expected)
        {
            var read = image.Read(buffer, 0, (int)Math.Min(buffer.Length, expected - scanned));
            if (read <= 0)
            {
                break;
            }

            if (!buffer.AsSpan(0, read).SequenceEqual(ZeroChunk.AsSpan(0, read)))
            {
                throw new InvalidDataException("The board image's zero padding is not zero filled.");
            }

            scanned += read;
            if ((scanned & 0x0FFF_FFFF) == 0)
            {
                token.ThrowIfCancellationRequested();
            }
        }

        if (scanned != expected || image.Position != endOffset)
        {
            throw new InvalidDataException("The board image's zero padding does not reach the declared payload boundary.");
        }
    }

    private static string HashRange(Stream stream, long offset, long count, CancellationToken token)
    {
        stream.Position = offset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[CopyBufferBytes];
        var remaining = count;
        while (remaining > 0)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read <= 0)
            {
                throw new InvalidDataException("The board image window ends before its declared length.");
            }

            hash.AppendData(buffer, 0, read);
            remaining -= read;
            token.ThrowIfCancellationRequested();
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count, string what)
    {
        while (count > 0)
        {
            var read = stream.Read(buffer, offset, count);
            if (read <= 0)
            {
                throw new InvalidDataException($"The board image ends while reading {what}.");
            }

            offset += read;
            count -= read;
        }
    }

    private static JsonDocument ParseJson(byte[] bytes, string what)
    {
        try
        {
            return JsonDocument.Parse(bytes);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"The {what} is not valid JSON.", exception);
        }
    }

    private static long RequireInt64(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt64(out var result))
        {
            throw new InvalidDataException($"The board image JSON field '{name}' is missing or not an integer.");
        }

        return result;
    }

    private static string RequireString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String
            || value.GetString() is not { } text)
        {
            throw new InvalidDataException($"The board image JSON field '{name}' is missing or not a string.");
        }

        return text;
    }

    private static void RequireSha256(string value, string name)
    {
        if (value.Length != 64 || value.AsSpan().IndexOfAnyExcept(Sha256HexChars) >= 0)
        {
            throw new InvalidDataException($"The board image JSON field '{name}' is not a SHA-256.");
        }
    }

    private static string MetadataEntryName(string role)
    {
        return string.Equals(role, "pc-backup-manifest", StringComparison.Ordinal)
            ? PcManifestEntryName
            : string.Equals(role, "post-gpt-primary", StringComparison.Ordinal)
                ? PostGptPrimaryEntryName
                : string.Equals(role, "post-gpt-backup", StringComparison.Ordinal)
                    ? PostGptBackupEntryName
                    : InstallationRecordEntryName;
    }

    // ------------------------------------------------------------------ file helpers

    private static FileStream CreateNewOutput(string path) =>
        new FileStream(
            path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, CopyBufferBytes,
            FileOptions.SequentialScan);

    /// <summary>
    /// Replaces the just-written output with a genuinely read-only handle. The writer is flushed and closed
    /// first, then the same bytes are reopened exactly as a consumer opens them and re-verified, so the handle
    /// the set keeps alive denies writers instead of holding write access itself.
    /// </summary>
    private static void SealLastOutput(
        List<FileStream> owned, long expectedLength, string expectedSha256, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var index = owned.Count - 1;
        var writer = owned[index];
        var path = Path.GetFullPath(writer.Name);

        writer.Flush(flushToDisk: true);
        writer.Dispose();

        var reader = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);
        owned[index] = reader;

        if (reader.Length != expectedLength)
        {
            throw new InvalidDataException(
                $"The sealed output '{Path.GetFileName(path)}' is {reader.Length} bytes, not the verified {expectedLength}.");
        }

        var readBack = HashStream(reader);
        if (!string.Equals(readBack, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The sealed output '{Path.GetFileName(path)}' does not hash to its verified value.");
        }
    }

    private static string WriteAndVerify(FileStream stream, byte[] bytes)
    {
        var expected = Sha256Hex(bytes);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);

        if (stream.Length != bytes.Length)
        {
            throw new InvalidDataException("An output file did not reach its planned length.");
        }

        var readBack = HashStream(stream);
        if (!string.Equals(expected, readBack, StringComparison.Ordinal))
        {
            throw new InvalidDataException("An output file failed its read back verification.");
        }

        return readBack;
    }

    private static string HashStream(FileStream stream)
    {
        stream.Position = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[CopyBufferBytes];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string HashFile(string path, CancellationToken token, long expectedLength)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[CopyBufferBytes];
        long total = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
            total += read;
            if ((total & 0x7F_FFFF) == 0)
            {
                token.ThrowIfCancellationRequested();
            }
        }

        if (total != expectedLength)
        {
            throw new InvalidDataException(
                $"The file '{Path.GetFileName(path)}' is {total} bytes, not the verified {expectedLength}.");
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string CreateArtifactDirectory(string chosenParent, Guid installationId)
    {
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff", CultureInfo.InvariantCulture);

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var name = "armada-internal-install-" + stamp + "-" + installationId.ToString("N");
            if (attempt > 0)
            {
                name += "-" + attempt.ToString(CultureInfo.InvariantCulture);
            }

            var path = Path.Combine(chosenParent, name);
            if (Directory.Exists(path) || File.Exists(path))
            {
                continue;
            }

            Directory.CreateDirectory(path);
            return path;
        }

        throw new IOException("Could not create a unique artifact directory below the chosen parent.");
    }

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private static bool HexEquals(string? left, string? right) =>
        left is not null && right is not null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------- byte helpers

    private static uint ReadUInt32(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));

    private static ulong ReadUInt64(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));

    private static long ReadInt64(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(offset, 8));

    private static void WriteUInt64(byte[] buffer, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);

    private static bool IsZeroGuid(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;

    private static string DecodeName(byte[] array, int offset)
    {
        var characters = new char[EntryNameBytes / 2];
        var length = 0;
        for (var index = 0; index < characters.Length; index++)
        {
            var unit = BinaryPrimitives.ReadUInt16LittleEndian(array.AsSpan(offset + (index * 2), 2));
            if (unit == 0)
            {
                break;
            }

            characters[length++] = (char)unit;
        }

        return new string(characters, 0, length);
    }

    private static GptPartition? FindPartition(GptTable table, int number)
    {
        foreach (var partition in table.Partitions)
        {
            if (partition.Number == number)
            {
                return partition;
            }
        }

        return null;
    }

    private static GptPartition? FindPartitionByUuid(GptTable table, string partUuid)
    {
        foreach (var partition in table.Partitions)
        {
            if (string.Equals(partition.PartUuid, partUuid, StringComparison.OrdinalIgnoreCase))
            {
                return partition;
            }
        }

        return null;
    }

    /// <summary>CRC32 with the reflected IEEE polynomial 0xEDB88320, exactly as the GPT specification requires.</summary>
    internal static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFF_FFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ 0xEDB8_8320u : crc >> 1;
            }
        }

        return ~crc;
    }

    // -------------------------------------------------------------------- nested types

    /// <summary>The verified evidence of one captured input file.</summary>
    internal sealed class VerifiedCapture
    {
        internal string Role = string.Empty;
        internal string FilePath = string.Empty;
        internal long Length;
        internal string Sha256 = string.Empty;
        internal int Lun;
        internal long StartSector;
        internal long SectorCount;
        internal int SectorSize;
        internal string? PartUuid;
    }

    /// <summary>One planned GPT write file: role, disk range and the exact bytes to write.</summary>
    internal sealed class GptWriteDescriptor
    {
        internal GptWriteDescriptor(string role, long startSector, long sectorCount, int sectorSize, byte[] bytes)
        {
            Role = role;
            StartSector = startSector;
            SectorCount = sectorCount;
            SectorSize = sectorSize;
            Bytes = bytes;
            Length = bytes.Length;
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes));
        }

        internal string Role { get; }

        internal long StartSector { get; }

        internal long SectorCount { get; }

        internal int SectorSize { get; }

        internal byte[] Bytes { get; }

        internal long Length { get; }

        internal string Sha256 { get; }
    }

    /// <summary>One ARMADA entry this preparation creates.</summary>
    internal sealed class NewPartition
    {
        internal NewPartition(int number, string name, Guid partUuid, long startSector, long sectorCount)
        {
            Number = number;
            Name = name;
            PartUuid = partUuid;
            StartSector = startSector;
            SectorCount = sectorCount;
        }

        internal int Number { get; set; }

        internal string Name { get; }

        internal Guid PartUuid { get; }

        internal long StartSector { get; }

        internal long SectorCount { get; }
    }

    /// <summary>The three UUIDs the rewrite freezes for the whole artifact set.</summary>
    internal sealed class PartitionUuids
    {
        internal Guid Boot;
        internal Guid Root;
        internal Guid Backup;
    }

    /// <summary>The in-memory result of the GPT rewrite, before anything is written.</summary>
    internal sealed class GptRewrite
    {
        internal IReadOnlyList<GptWriteDescriptor> WriteRegions = Array.Empty<GptWriteDescriptor>();
        internal byte[] PostPrimaryFragment = Array.Empty<byte>();
        internal byte[] PostBackupFragment = Array.Empty<byte>();
        internal GptTable PostTable = null!;
        internal IReadOnlyList<NewPartition> NewPartitions = Array.Empty<NewPartition>();
        internal GptPartition LinuxBoot = null!;
        internal GptPartition LinuxRoot = null!;
        internal GptPartition BackupPartition = null!;
        internal string PostGptPrimarySha256 = string.Empty;
        internal string PostGptBackupSha256 = string.Empty;
    }

    /// <summary>One entry of the board recovery archive.</summary>
    internal sealed class ArchivePayload
    {
        internal string Role = string.Empty;
        internal string EntryName = string.Empty;
        internal long Length;
        internal string Sha256 = string.Empty;
        internal string? FilePath;
        internal byte[]? Bytes;
    }

    /// <summary>The precomputed Ustar positions of every payload.</summary>
    internal sealed class PayloadLayout
    {
        internal PayloadLayout(long[] headerOffsets, long[] dataOffsets, long end)
        {
            HeaderOffsets = headerOffsets;
            DataOffsets = dataOffsets;
            End = end;
        }

        internal long[] HeaderOffsets { get; }

        internal long[] DataOffsets { get; }

        internal long End { get; }
    }

    /// <summary>A write-only stream that counts the uncompressed tar bytes passing through the gzip member.</summary>
    private sealed class CountingWriteStream : Stream
    {
        private readonly Stream _inner;
        private long _written;

        internal CountingWriteStream(Stream inner) => _inner = inner;

        internal long BytesWritten => _written;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _written;

        public override long Position
        {
            get => _written;
            set => throw new NotSupportedException();
        }

        public override void Flush() => _inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            _inner.Write(buffer, offset, count);
            _written += count;
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            _inner.Write(buffer);
            _written += buffer.Length;
        }
    }

    /// <summary>A read-only window over the caller's image; it never reads past the declared compressed bytes.</summary>
    private sealed class BoundedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        internal BoundedReadStream(Stream inner, long offset, long length)
        {
            _inner = inner;
            _inner.Position = offset;
            _remaining = length;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _remaining;

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0 || count <= 0)
            {
                return 0;
            }

            var read = _inner.Read(buffer, offset, (int)Math.Min(count, _remaining));
            _remaining -= read;
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            if (_remaining <= 0 || buffer.Length == 0)
            {
                return 0;
            }

            var read = _inner.Read(buffer.Slice(0, (int)Math.Min(buffer.Length, _remaining)));
            _remaining -= read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    /// <summary>A read-only stream that counts the decompressed bytes delivered to the tar reader.</summary>
    private sealed class CountingReadStream : Stream
    {
        private readonly Stream _inner;
        private long _read;

        internal CountingReadStream(Stream inner) => _inner = inner;

        internal long BytesRead => _read;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            _read += read;
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = _inner.Read(buffer);
            _read += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    /// <summary>A read-only payload stream that refuses bytes differing from the verified hash.</summary>
    private sealed class VerifiedPayloadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _expectedLength;
        private readonly string _expectedSha256;
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long _read;
        private bool _verified;

        internal VerifiedPayloadStream(Stream inner, long expectedLength, string expectedSha256)
        {
            _inner = inner;
            _expectedLength = expectedLength;
            _expectedSha256 = expectedSha256;
        }

        public override bool CanRead => true;

        public override bool CanSeek => _inner.CanSeek;

        public override bool CanWrite => false;

        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            if (read > 0)
            {
                _hash.AppendData(buffer, offset, read);
                _read += read;
            }

            if (_read > _expectedLength)
            {
                throw new InvalidDataException(
                    "A board archive payload grew after it was verified.");
            }

            if (_read == _expectedLength)
            {
                Verify();
            }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        private void Verify()
        {
            if (_verified)
            {
                return;
            }

            _verified = true;

            if (_read != _expectedLength)
            {
                throw new InvalidDataException(
                    "A board archive payload changed length after it was verified.");
            }

            var actual = Convert.ToHexString(_hash.GetHashAndReset());
            if (!string.Equals(actual, _expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "A board archive payload changed after it was verified; its SHA-256 no longer matches.");
            }
        }
    }
}
