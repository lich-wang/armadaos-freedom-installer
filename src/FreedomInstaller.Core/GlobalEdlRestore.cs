using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One immutable copy of a backup chunk as it will be replayed to the device. The copy never aliases the
/// caller's manifest, so a plan cannot be changed by mutating the borrowed backup set.
/// </summary>
internal sealed class GlobalEdlRestoreChunk
{
    internal GlobalEdlRestoreChunk(
        string fileName,
        long offsetBytes,
        long rawBytes,
        string rawSha256,
        long compressedBytes,
        string compressedSha256)
    {
        FileName = fileName;
        OffsetBytes = offsetBytes;
        RawBytes = rawBytes;
        RawSha256 = rawSha256;
        CompressedBytes = compressedBytes;
        CompressedSha256 = compressedSha256;
    }

    internal string FileName { get; }

    internal long OffsetBytes { get; }

    internal long RawBytes { get; }

    internal string RawSha256 { get; }

    internal long CompressedBytes { get; }

    internal string CompressedSha256 { get; }

    internal GlobalEdlChunk ToManifestChunk() => new()
    {
        FileName = FileName,
        OffsetBytes = OffsetBytes,
        RawBytes = RawBytes,
        RawSha256 = RawSha256,
        CompressedBytes = CompressedBytes,
        CompressedSha256 = CompressedSha256,
    };
}

/// <summary>One immutable copy of a captured region: location, extent and the chunks that reproduce it.</summary>
internal sealed class GlobalEdlRestoreRegion
{
    internal GlobalEdlRestoreRegion(
        string role,
        string kind,
        int lun,
        long startSector,
        long sectorCount,
        int sectorSize,
        int? partitionNumber,
        string? partitionName,
        IReadOnlyList<GlobalEdlRestoreChunk> chunks)
    {
        Role = role;
        Kind = kind;
        Lun = lun;
        StartSector = startSector;
        SectorCount = sectorCount;
        SectorSize = sectorSize;
        PartitionNumber = partitionNumber;
        PartitionName = partitionName;
        Chunks = chunks;
    }

    internal string Role { get; }

    internal string Kind { get; }

    internal int Lun { get; }

    internal long StartSector { get; }

    internal long SectorCount { get; }

    internal int SectorSize { get; }

    internal int? PartitionNumber { get; }

    internal string? PartitionName { get; }

    internal IReadOnlyList<GlobalEdlRestoreChunk> Chunks { get; }

    internal long RawBytes => checked(SectorCount * SectorSize);
}

/// <summary>Geometry snapshot of one LUN, proven by a probe and compared on every later probe.</summary>
internal sealed class GlobalEdlRestoreLunGeometry
{
    internal GlobalEdlRestoreLunGeometry(int lun, int sectorSize, long totalSectors, string diskGuid)
    {
        Lun = lun;
        SectorSize = sectorSize;
        TotalSectors = totalSectors;
        DiskGuid = diskGuid;
    }

    internal int Lun { get; }

    internal int SectorSize { get; }

    internal long TotalSectors { get; }

    internal string DiskGuid { get; }

    internal long DiskBytes => checked(TotalSectors * SectorSize);
}

/// <summary>The decoded original table of one LUN, snapshotted so the write phase never re-reads the set.</summary>
internal sealed class GlobalEdlRestoreGptExpectation
{
    internal GlobalEdlRestoreGptExpectation(int lun, string diskGuid, string sourceFingerprint)
    {
        Lun = lun;
        DiskGuid = diskGuid;
        SourceFingerprint = sourceFingerprint;
    }

    internal int Lun { get; }

    internal string DiskGuid { get; }

    internal string SourceFingerprint { get; }
}

/// <summary>
/// One prepared, one-shot disaster restore of a verified original-layout global backup.
/// <para>
/// The plan borrows the caller's <see cref="GlobalEdlBackupSet"/> and the exact <see cref="EdlClient"/>; it
/// never disposes either. It owns only its evidence directory, the immutable region/chunk copies, the
/// prepared BCB write unit and its one-shot guard. Every device-facing value was validated while preparing,
/// and the confirmation id names exactly those values.
/// </para>
/// </summary>
public sealed class GlobalEdlRestorePlan : IDisposable
{
    private int _runState;
    private volatile bool _disposed;

    internal GlobalEdlRestorePlan(
        string confirmationId,
        string evidenceDirectory,
        string logsDirectory,
        string workDirectory,
        string journalPath,
        string manifestSnapshotPath,
        string manifestSha256,
        GlobalEdlIdentity identity,
        GlobalEdlBackupSet backup,
        EdlClient client,
        IReadOnlyList<GlobalEdlRestoreRegion> regions,
        IReadOnlyList<GlobalEdlRestoreLunGeometry> luns,
        IReadOnlyList<GlobalEdlRestoreGptExpectation> gptExpectations,
        GlobalEdlRestoreRegion miscRegion,
        byte[] bcbUnit,
        string bcbOverlayPath,
        string bcbOverlaySha256,
        long androidBytes,
        long writeBytes,
        int regionCount,
        string fingerprint)
    {
        ConfirmationId = confirmationId;
        EvidenceDirectory = evidenceDirectory;
        LogsDirectory = logsDirectory;
        WorkDirectory = workDirectory;
        JournalPath = journalPath;
        ManifestSnapshotPath = manifestSnapshotPath;
        ManifestSha256 = manifestSha256;
        Identity = identity;
        Backup = backup;
        Client = client;
        Regions = regions;
        Luns = luns;
        GptExpectations = gptExpectations;
        MiscRegion = miscRegion;
        BcbUnit = bcbUnit;
        BcbOverlayPath = bcbOverlayPath;
        BcbOverlaySha256 = bcbOverlaySha256;
        AndroidBytes = androidBytes;
        WriteBytes = writeBytes;
        RegionCount = regionCount;
        Fingerprint = fingerprint;
    }

    /// <summary>Stable SHA-256 of the canonical confirmation body; the value a caller must echo to execute.</summary>
    public string ConfirmationId { get; }

    /// <summary>Absolute directory that owns every probe, plan, journal, log and readback file of this run.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>Identity of the backup and of the device that was present while preparing.</summary>
    public GlobalEdlIdentity Identity { get; }

    /// <summary>Raw bytes of the original <c>userdata</c> partition, which is never read or written here.</summary>
    public long AndroidBytes { get; }

    /// <summary>Raw bytes the execute phase writes: every captured region plus the BCB write unit.</summary>
    public long WriteBytes { get; }

    /// <summary>Captured regions plus the final BCB unit.</summary>
    public int RegionCount { get; }

    /// <summary>Borrowed, still leased backup set. Never disposed by this plan.</summary>
    internal GlobalEdlBackupSet Backup { get; }

    /// <summary>Exact client the plan was prepared against. Never disposed by this plan.</summary>
    internal EdlClient Client { get; }

    internal string LogsDirectory { get; }

    internal string WorkDirectory { get; }

    internal string JournalPath { get; }

    internal string ManifestSnapshotPath { get; }

    internal string ManifestSha256 { get; }

    internal IReadOnlyList<GlobalEdlRestoreRegion> Regions { get; }

    internal IReadOnlyList<GlobalEdlRestoreLunGeometry> Luns { get; }

    internal IReadOnlyList<GlobalEdlRestoreGptExpectation> GptExpectations { get; }

    internal GlobalEdlRestoreRegion MiscRegion { get; }

    internal byte[] BcbUnit { get; }

    internal string BcbOverlayPath { get; }

    internal string BcbOverlaySha256 { get; }

    internal string Fingerprint { get; }

    internal void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(GlobalEdlRestorePlan));
        }
    }

    /// <summary>Consumes the single execution slot. The second caller always loses.</summary>
    internal void BeginRun()
    {
        if (Interlocked.CompareExchange(ref _runState, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "This restore plan has already been executed; a plan is a one-shot authorization.");
        }
    }

    /// <summary>
    /// Releases only this plan's own guard. The caller's backup set and client are not touched, and no
    /// evidence, recovery backup or unrelated file is deleted.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
    }
}

/// <summary>The terminal observation of one executed restore.</summary>
public sealed record GlobalEdlRestoreResult(
    bool Success,
    bool AnyWriteStarted,
    IReadOnlyList<string> VerifiedRegions,
    string? Error,
    string EvidenceDirectory);

/// <summary>
/// Disaster restore of an original-layout global backup onto the same tablet: the six LUN GPTs and every
/// ordinary partition except <c>userdata</c>.
/// <para>
/// Restore never trusts the current partition table. Geometry and identity are proven by bounded raw probes,
/// the ordinary partitions are replayed from the verified backup, both GPT fragments of every LUN are written
/// last within their LUN and proven by re-decoding the readback, and a fresh BCB unit is written dead last so
/// the user's own reboot enters Recovery and initializes Android. Nothing here reads or writes
/// <c>userdata</c>, performs a reset, formats, repairs, retries or claims RPMB/eFuse recoverability.
/// </para>
/// </summary>
public static class GlobalEdlRestore
{
    private const long MaxGptRegionBytes = 16L * 1024 * 1024;
    private const int BcbCommandBytes = 32;
    private const int BcbRecoveryOffset = 64;
    private const int BcbRecoveryBytes = 768;
    private const int MaxManifestSnapshotBytes = 16 * 1024 * 1024;
    private const int CopyBufferBytes = 81920;
    private const string BcbRole = "bcb";
    private const string MiscName = "misc";
    private const string UserdataName = "userdata";
    private const string PartitionKind = "partition";
    private const string GptPrimaryKind = "gpt-primary";
    private const string GptBackupKind = "gpt-backup";
    private const string BcbOverlayFileName = "bcb-overlay.bin";
    private const string ManifestSnapshotFileName = "manifest.snapshot.json";
    private const string PlanFileName = "plan.json";
    private const string JournalFileName = "journal.json";

    // The actual ASCII recovery command; the trailing newline is part of the command block format used by
    // this family of devices and is written as real bytes, never as escape text.
    private const string ArmadaRecoveryText =
        "recovery\n--wipe_data\n--reason=armada-global-restore\n";

    /// <summary>
    /// Validates the caller, the backup and the live identity, then probes all six LUNs with a bounded raw
    /// probe and prepares the BCB write unit. No device write, reset or format is issued.
    /// </summary>
    public static async Task<GlobalEdlRestorePlan> PrepareAsync(
        EdlClient client,
        GlobalEdlBackupSet backup,
        string chosenParent,
        IProgress<GlobalEdlProgress>? progress = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(backup);

        string parent = RequireRestoreParent(chosenParent);

        backup.ThrowIfDisposed();

        // The saved identity and the identity the client is actually bound to must name the same tablet.
        GlobalEdlIdentity saved = backup.Manifest.Identity;
        GlobalEdlIdentity actual = GlobalEdlBackup.IdentityFor(client);
        RequireIdentityMatch(saved, actual);

        token.ThrowIfCancellationRequested();

        GlobalEdlManifest manifest = backup.Manifest;
        GlobalEdlRestoreRegion misc = RequireMiscRegion(manifest);
        long androidBytes = ComputeAndroidBytes(backup, manifest);

        string evidenceDirectory = CreateEvidenceDirectory(parent, backup.DirectoryPath, actual.BusSerialHex);
        string logsDirectory = Path.Combine(evidenceDirectory, "logs");
        string workDirectory = Path.Combine(evidenceDirectory, "work");
        Directory.CreateDirectory(logsDirectory);
        Directory.CreateDirectory(workDirectory);

        token.ThrowIfCancellationRequested();

        // Six raw probes, each into its own new file, prove the actual geometry and the bus serial without
        // ever asking the tool for the current GPT. Initial loader upload is requested once, on LUN0.
        for (int lun = 0; lun < 6; lun++)
        {
            token.ThrowIfCancellationRequested();

            bool initialLoader = lun == 0 && !client.HasInitialSaharaProof;
            string probePath = Path.Combine(
                evidenceDirectory,
                "probe-pass-lun" + Invariant(lun) + ".bin");

            EdlProbeEvidence evidence = await client
                .ProbeRawGeometryAsync(lun, initialLoader, probePath, token)
                .ConfigureAwait(false);

            RequireProbe(evidence, RequireManifestLun(manifest, lun), saved, initialLoader);
            GlobalEdlBackup.Report(progress, "probe", "lun" + Invariant(lun), lun, lun + 1, 6);
        }

        backup.ThrowIfDisposed();

        GlobalEdlBackup.Report(progress, "verify-backup", null, null, 0, manifest.RawBytes);

        (byte[] bcbUnit, string bcbOverlayPath, string bcbOverlaySha256) = await PrepareBcbAsync(
                backup, misc, evidenceDirectory, workDirectory, progress, token)
            .ConfigureAwait(false);

        GlobalEdlBackup.Report(progress, "verify-backup", null, null, manifest.RawBytes, manifest.RawBytes);

        List<GlobalEdlRestoreRegion> regions = CopyRegions(manifest);
        List<GlobalEdlRestoreLunGeometry> luns = CopyLuns(manifest);
        List<GlobalEdlRestoreGptExpectation> expectations = CopyExpectations(backup, manifest);

        string fingerprint = ComputeFingerprint(backup.ManifestSha256, saved, luns);
        string confirmationId = ComputeConfirmationId(
            backup.ManifestSha256, saved, luns, regions, bcbOverlaySha256);

        long writeBytes = checked(manifest.RawBytes + bcbUnit.Length);

        string manifestSnapshotPath = Path.Combine(evidenceDirectory, ManifestSnapshotFileName);
        string manifestSha = WriteManifestSnapshot(backup, manifestSnapshotPath, token);

        var receipt = new RestorePlanReceipt
        {
            ConfirmationId = confirmationId,
            ManifestSha256 = manifestSha,
            ProfileId = saved.ProfileId,
            Model = saved.Model,
            HardwareId = saved.HardwareId,
            BusSerialHex = saved.BusSerialHex,
            ClearData = true,
            AndroidBytes = androidBytes,
            WriteBytes = writeBytes,
            RegionCount = checked(regions.Count + 1),
            BcbBytes = bcbUnit.Length,
            BcbOverlaySha256 = bcbOverlaySha256,
            Fingerprint = fingerprint,
            CreatedUtc = DateTimeOffset.UtcNow,
            Luns = luns.Select(lun => new RestorePlanLunReceipt
            {
                Lun = lun.Lun,
                SectorSize = lun.SectorSize,
                TotalSectors = lun.TotalSectors,
                DiskGuid = lun.DiskGuid,
            }).ToList(),
            Regions = regions.Select(region => new RestorePlanRegionReceipt
            {
                Role = region.Role,
                Kind = region.Kind,
                Lun = region.Lun,
                StartSector = region.StartSector,
                SectorCount = region.SectorCount,
                SectorSize = region.SectorSize,
                PartitionNumber = region.PartitionNumber,
                PartitionName = region.PartitionName,
                RawBytes = region.RawBytes,
                Chunks = region.Chunks.Select(chunk => new RestorePlanChunkReceipt
                {
                    FileName = chunk.FileName,
                    OffsetBytes = chunk.OffsetBytes,
                    RawBytes = chunk.RawBytes,
                    RawSha256 = chunk.RawSha256,
                }).ToList(),
            }).ToList(),
        };

        WriteImmutableJson(Path.Combine(evidenceDirectory, PlanFileName), receipt);

        backup.ThrowIfDisposed();

        return new GlobalEdlRestorePlan(
            confirmationId,
            evidenceDirectory,
            logsDirectory,
            workDirectory,
            Path.Combine(evidenceDirectory, JournalFileName),
            manifestSnapshotPath,
            manifestSha,
            saved,
            backup,
            client,
            regions,
            luns,
            expectations,
            misc,
            bcbUnit,
            bcbOverlayPath,
            bcbOverlaySha256,
            androidBytes,
            writeBytes,
            checked(regions.Count + 1),
            fingerprint);
    }

    /// <summary>
    /// Replays the prepared backup. The plan is consumed exactly once, the confirmation must match exactly
    /// and every post-start failure is returned as a result instead of escaping as an exception.
    /// </summary>
    public static async Task<GlobalEdlRestoreResult> ExecuteAsync(
        GlobalEdlRestorePlan plan,
        string confirmationId,
        IProgress<GlobalEdlProgress>? progress = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (string.IsNullOrEmpty(confirmationId))
        {
            throw new ArgumentException("An exact confirmation id is required.", nameof(confirmationId));
        }

        plan.ThrowIfDisposed();

        if (!string.Equals(confirmationId, plan.ConfirmationId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The confirmation id does not match this restore plan; nothing was written.");
        }

        plan.BeginRun();

        var session = new RestoreSession(plan, progress);
        session.Journal = new GlobalEdlRestoreJournal
        {
            State = "running",
            ConfirmationId = plan.ConfirmationId,
            Stage = "probe",
            AnyWriteStarted = false,
            InitializationQueued = false,
            UpdatedUtc = DateTimeOffset.UtcNow,
        };

        try
        {
            plan.Backup.ThrowIfDisposed();

            GlobalEdlIdentity current = GlobalEdlBackup.IdentityFor(plan.Client);
            RequireIdentityMatch(plan.Identity, current);

            // Fresh probes with fresh files: the geometry is proven again from the raw device right before
            // the first write, and the current GPT is never consulted or required to be valid.
            for (int lun = 0; lun < 6; lun++)
            {
                token.ThrowIfCancellationRequested();

                bool initialLoader = lun == 0 && !plan.Client.HasInitialSaharaProof;
                string probePath = Path.Combine(
                    plan.EvidenceDirectory,
                    "probe-exec-lun" + Invariant(lun) + "-pass1.bin");

                EdlProbeEvidence evidence = await plan.Client
                    .ProbeRawGeometryAsync(lun, initialLoader, probePath, token)
                    .ConfigureAwait(false);

                RequireProbe(evidence, plan.Luns[lun], plan.Identity, initialLoader);
                GlobalEdlBackup.Report(progress, "probe", "lun" + Invariant(lun), lun, lun + 1, 6);
            }

            session.Stage = "write-partition";
            SaveJournal(plan.JournalPath, session.Journal);

            List<GlobalEdlRestoreRegion> partitions = plan.Regions
                .Where(region => string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
                .OrderBy(region => region.Lun)
                .ThenBy(region => region.PartitionNumber ?? int.MaxValue)
                .ToList();

            long partitionTotal = partitions.Aggregate(0L, (sum, region) => checked(sum + region.RawBytes));
            long partitionBase = 0;

            foreach (GlobalEdlRestoreRegion region in partitions)
            {
                token.ThrowIfCancellationRequested();

                await WriteAndVerifyRegionAsync(
                        session,
                        region,
                        "write-partition",
                        "readback-partition",
                        partitionTotal,
                        partitionBase,
                        null,
                        token)
                    .ConfigureAwait(false);

                partitionBase = checked(partitionBase + region.RawBytes);
            }

            long gptTotal = plan.Regions
                .Where(region => !string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal))
                .Aggregate(0L, (sum, region) => checked(sum + region.RawBytes));
            long gptBase = 0;

            for (int lun = 0; lun < 6; lun++)
            {
                token.ThrowIfCancellationRequested();

                GlobalEdlRestoreLunGeometry geometry = plan.Luns[lun];
                GlobalEdlRestoreRegion backupRegion = RequireGptRegion(plan.Regions, lun, GptBackupKind);
                GlobalEdlRestoreRegion primaryRegion = RequireGptRegion(plan.Regions, lun, GptPrimaryKind);

                var backupReadbacks = new List<RetainedReadback>();
                var primaryReadbacks = new List<RetainedReadback>();

                await WriteAndVerifyRegionAsync(
                        session,
                        backupRegion,
                        "write-gpt",
                        "readback-gpt",
                        gptTotal,
                        gptBase,
                        backupReadbacks,
                        token)
                    .ConfigureAwait(false);

                gptBase = checked(gptBase + backupRegion.RawBytes);

                await WriteAndVerifyRegionAsync(
                        session,
                        primaryRegion,
                        "write-gpt",
                        "readback-gpt",
                        gptTotal,
                        gptBase,
                        primaryReadbacks,
                        token)
                    .ConfigureAwait(false);

                gptBase = checked(gptBase + primaryRegion.RawBytes);

                ProveGptPair(lun, geometry, plan.GptExpectations[lun], backupReadbacks, primaryReadbacks);

                DeleteRetained(backupReadbacks);
                DeleteRetained(primaryReadbacks);
            }

            // The whole original misc partition has to be verified before the BCB patch is layered on it.
            if (!session.Verified.Contains(plan.MiscRegion.Role, StringComparer.Ordinal))
            {
                throw new InvalidOperationException(
                    "The original misc partition was not verified, so the BCB patch is not written.");
            }

            token.ThrowIfCancellationRequested();

            await WriteAndVerifyBcbAsync(session, token).ConfigureAwait(false);

            session.Journal.State = "complete";
            session.Journal.Stage = "completed";
            session.Journal.Role = null;
            session.Journal.Lun = null;
            session.Journal.Error = null;
            session.Journal.InitializationQueued = true;
            session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
            SaveJournal(plan.JournalPath, session.Journal);

            GlobalEdlBackup.Report(progress, "initialize-android", null, null, 0, 0);
            GlobalEdlBackup.Report(progress, "completed", null, null, plan.WriteBytes, plan.WriteBytes);

            return new GlobalEdlRestoreResult(
                true,
                session.AnyWriteStarted,
                session.Verified.ToArray(),
                null,
                plan.EvidenceDirectory);
        }
        catch (Exception exception)
        {
            session.Journal.State = "failed";
            session.Journal.Stage = session.Stage;
            session.Journal.Role = session.Role;
            session.Journal.Lun = session.Lun;
            session.Journal.AnyWriteStarted = session.AnyWriteStarted;
            session.Journal.InitializationQueued = false;
            session.Journal.Error = exception.Message;
            session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;

            string message =
                "The global restore stopped at stage '" + session.Stage + "'" +
                (session.Role is null ? string.Empty : " for region '" + session.Role + "'") +
                ": " + exception.Message;

            // A durable journal failure must never hide the primary failure or the started-write state.
            try
            {
                SaveJournal(plan.JournalPath, session.Journal);
            }
            catch (Exception journalException)
            {
                message += " The failure journal could not be persisted: " + journalException.Message;
            }

            return new GlobalEdlRestoreResult(
                false,
                session.AnyWriteStarted,
                session.Verified.ToArray(),
                message,
                plan.EvidenceDirectory);
        }
    }

    // ------------------------------------------------------------------ prepare helpers

    private static string RequireRestoreParent(string chosenParent)
    {
        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException("A restore parent directory is required.", nameof(chosenParent));
        }

        if (!Path.IsPathFullyQualified(chosenParent))
        {
            throw new ArgumentException("The restore parent directory must be an absolute path.", nameof(chosenParent));
        }

        string full = Path.GetFullPath(chosenParent);

        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"The restore parent directory '{full}' does not exist.");
        }

        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException($"The restore parent directory '{full}' is a reparse point.");
        }

        return full;
    }

    private static string CreateEvidenceDirectory(string parent, string backupDirectory, string busSerialHex)
    {
        string bus = string.IsNullOrEmpty(busSerialHex) ? "00000000" : busSerialHex.ToUpperInvariant();

        string path = Path.Combine(
            parent,
            "global-restore-" + bus + "-" + Guid.NewGuid().ToString("D"));

        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new IOException($"The restore directory '{path}' already exists.");
        }

        // The selected backup is immutable input; its directory is never written to.
        if (IsSameOrUnder(path, backupDirectory))
        {
            throw new ArgumentException(
                "The restore directory would be created inside the selected backup directory.",
                nameof(parent));
        }

        Directory.CreateDirectory(path);
        return path;
    }

    private static bool IsSameOrUnder(string path, string root)
    {
        string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (string.Equals(full, rootFull, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return full.StartsWith(
            rootFull + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }

    private static GlobalEdlRestoreRegion RequireMiscRegion(GlobalEdlManifest manifest)
    {
        GlobalEdlRestoreRegion? found = null;

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (region.Lun != 0 ||
                !string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal) ||
                !string.Equals(region.PartitionName, MiscName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (found is not null)
            {
                throw new InvalidDataException("Only one misc partition may be restored, found more than one.");
            }

            found = new GlobalEdlRestoreRegion(
                region.Role,
                region.Kind,
                region.Lun,
                region.StartSector,
                region.SectorCount,
                region.SectorSize,
                region.PartitionNumber,
                region.PartitionName,
                CopyChunks(region));
        }

        return found ?? throw new InvalidDataException("The backup carries no misc partition on LUN0.");
    }

    private static GlobalEdlLun RequireManifestLun(GlobalEdlManifest manifest, int lun)
    {
        GlobalEdlLun? found = manifest.Luns.SingleOrDefault(item => item.Lun == lun);

        if (found is null)
        {
            throw new InvalidDataException($"The manifest carries no LUN{lun}.");
        }

        return found;
    }

    private static long ComputeAndroidBytes(GlobalEdlBackupSet backup, GlobalEdlManifest manifest)
    {
        GptPartition? userdata = null;

        foreach (GptPartition partition in backup.Tables[0].Partitions)
        {
            if (!string.Equals(partition.Name, UserdataName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (userdata is not null)
            {
                throw new InvalidDataException("The original layout carries more than one userdata partition.");
            }

            userdata = partition;
        }

        if (userdata is null)
        {
            throw new InvalidDataException("The original layout carries no userdata partition on LUN0.");
        }

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (string.Equals(region.PartitionName, UserdataName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The backup captures userdata; this is not an ordinary-partition global backup.");
            }
        }

        return checked(userdata.SectorCount * RequireManifestLun(manifest, 0).SectorSize);
    }

    private static List<GlobalEdlRestoreRegion> CopyRegions(GlobalEdlManifest manifest)
    {
        var copy = new List<GlobalEdlRestoreRegion>(manifest.Regions.Count);

        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            copy.Add(new GlobalEdlRestoreRegion(
                region.Role,
                region.Kind,
                region.Lun,
                region.StartSector,
                region.SectorCount,
                region.SectorSize,
                region.PartitionNumber,
                region.PartitionName,
                CopyChunks(region)));
        }

        return copy;
    }

    private static IReadOnlyList<GlobalEdlRestoreChunk> CopyChunks(GlobalEdlRegion region)
    {
        var chunks = new List<GlobalEdlRestoreChunk>(region.Chunks.Count);

        foreach (GlobalEdlChunk chunk in region.Chunks)
        {
            chunks.Add(new GlobalEdlRestoreChunk(
                chunk.FileName,
                chunk.OffsetBytes,
                chunk.RawBytes,
                chunk.RawSha256,
                chunk.CompressedBytes,
                chunk.CompressedSha256));
        }

        return chunks;
    }

    private static List<GlobalEdlRestoreLunGeometry> CopyLuns(GlobalEdlManifest manifest)
    {
        var luns = new List<GlobalEdlRestoreLunGeometry>(6);

        for (int lun = 0; lun < 6; lun++)
        {
            GlobalEdlLun source = RequireManifestLun(manifest, lun);
            luns.Add(new GlobalEdlRestoreLunGeometry(
                source.Lun, source.SectorSize, source.TotalSectors, source.DiskGuid));
        }

        return luns;
    }

    private static List<GlobalEdlRestoreGptExpectation> CopyExpectations(
        GlobalEdlBackupSet backup,
        GlobalEdlManifest manifest)
    {
        var expectations = new List<GlobalEdlRestoreGptExpectation>(6);

        for (int lun = 0; lun < 6; lun++)
        {
            GptTable table = backup.Tables[lun];
            expectations.Add(new GlobalEdlRestoreGptExpectation(
                lun, table.DiskGuid, table.SourceFingerprint));
        }

        return expectations;
    }

    private static async Task<(byte[] Unit, string Path, string Sha256)> PrepareBcbAsync(
        GlobalEdlBackupSet backup,
        GlobalEdlRestoreRegion misc,
        string evidenceDirectory,
        string workDirectory,
        IProgress<GlobalEdlProgress>? progress,
        CancellationToken token)
    {
        int sectorSize = misc.SectorSize;
        int unitBytes = CheckedWriteUnitBytes(sectorSize);

        long miscBytes = misc.RawBytes;
        if (miscBytes < unitBytes)
        {
            throw new InvalidDataException(
                "The misc partition is smaller than one BCB write unit.");
        }

        string chunkPath = Path.Combine(workDirectory, "bcb-misc-chunk.raw");
        GlobalEdlRestoreChunk first = misc.Chunks[0];

        if (first.RawBytes < unitBytes)
        {
            throw new InvalidDataException(
                "The first misc chunk does not cover one BCB write unit.");
        }

        GlobalEdlBackup.Report(progress, "prepare-restore", misc.Role, 0, 0, unitBytes);

        // Only one bounded chunk is ever decompressed to disk; the prefix is copied out of it and the chunk
        // is deleted again as soon as the unit has been proven.
        using (FileStream raw = new(
                   chunkPath,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   CopyBufferBytes,
                   FileOptions.SequentialScan))
        {
            await GlobalEdlBackup
                .VerifyChunkAsync(
                    ResolveChunkPath(backup.DirectoryPath, first.FileName),
                    first.ToManifestChunk(),
                    raw,
                    token)
                .ConfigureAwait(false);
        }

        long actualChunkBytes = new FileInfo(chunkPath).Length;
        if (actualChunkBytes != first.RawBytes)
        {
            throw new InvalidDataException(
                "The decompressed misc chunk does not carry its declared length.");
        }

        byte[] prefix = ReadPrefix(chunkPath, unitBytes);
        File.Delete(chunkPath);

        // Only the pending command block and the recovery region are reset; every other prefix byte,
        // including boot_control at 2048 for a 4096-byte sector, is preserved exactly.
        Array.Clear(prefix, 0, BcbCommandBytes);
        Array.Clear(prefix, BcbRecoveryOffset, BcbRecoveryBytes);

        byte[] unit = InternalInstallBackend.BuildInstallBcbWriteUnit(prefix, sectorSize);

        byte[] recovery = Encoding.ASCII.GetBytes(ArmadaRecoveryText);
        if (recovery.Length > BcbRecoveryBytes)
        {
            throw new InvalidOperationException("The recovery command does not fit the BCB recovery region.");
        }

        Array.Clear(unit, BcbRecoveryOffset, BcbRecoveryBytes);
        Buffer.BlockCopy(recovery, 0, unit, BcbRecoveryOffset, recovery.Length);

        string overlayPath = Path.Combine(evidenceDirectory, BcbOverlayFileName);
        using (FileStream overlay = new(
                   overlayPath,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   CopyBufferBytes,
                   FileOptions.WriteThrough))
        {
            overlay.Write(unit, 0, unit.Length);
            overlay.Flush(flushToDisk: true);
        }

        string sha = ComputeFileSha256(overlayPath);
        GlobalEdlBackup.Report(progress, "prepare-restore", misc.Role, 0, unitBytes, unitBytes);

        return (unit, overlayPath, sha);
    }

    private static int CheckedWriteUnitBytes(int sectorSize)
    {
        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new InvalidDataException(
                $"The misc sector size {sectorSize} is not supported for a BCB write unit.");
        }

        return checked((int)((2048L + sectorSize - 1) / sectorSize * sectorSize));
    }

    private static byte[] ReadPrefix(string path, int count)
    {
        byte[] buffer = new byte[count];

        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);

        int offset = 0;
        while (offset < count)
        {
            int read = stream.Read(buffer, offset, count - offset);
            if (read == 0)
            {
                throw new InvalidDataException("The misc chunk ended before one BCB write unit was available.");
            }

            offset += read;
        }

        return buffer;
    }

    private static string WriteManifestSnapshot(
        GlobalEdlBackupSet backup,
        string snapshotPath,
        CancellationToken token)
    {
        FileInfo info = new(backup.ManifestPath);
        if (!info.Exists || info.Length > MaxManifestSnapshotBytes)
        {
            throw new InvalidDataException("The verified manifest is missing or unexpectedly large.");
        }

        byte[] bytes = File.ReadAllBytes(backup.ManifestPath);
        string sha = Convert.ToHexString(SHA256.HashData(bytes));

        if (!string.Equals(sha, backup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The manifest bytes no longer match the verified digest.");
        }

        using (FileStream snapshot = new(
                   snapshotPath,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   CopyBufferBytes,
                   FileOptions.WriteThrough))
        {
            snapshot.Write(bytes, 0, bytes.Length);
            snapshot.Flush(flushToDisk: true);
        }

        token.ThrowIfCancellationRequested();
        return sha;
    }

    private static string ComputeFingerprint(
        string manifestSha256,
        GlobalEdlIdentity identity,
        IReadOnlyList<GlobalEdlRestoreLunGeometry> luns)
    {
        var body = new StringBuilder();
        body.Append("global-edl-restore-fingerprint-v1\n");
        body.Append("manifest=").Append(manifestSha256.ToUpperInvariant()).Append('\n');
        AppendIdentity(body, identity);

        foreach (GlobalEdlRestoreLunGeometry lun in luns)
        {
            body.Append("lun=").Append(Invariant(lun.Lun))
                .Append(";sector=").Append(Invariant(lun.SectorSize))
                .Append(";total=").Append(Invariant(lun.TotalSectors)).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body.ToString())));
    }

    private static string ComputeConfirmationId(
        string manifestSha256,
        GlobalEdlIdentity identity,
        IReadOnlyList<GlobalEdlRestoreLunGeometry> luns,
        IReadOnlyList<GlobalEdlRestoreRegion> regions,
        string bcbOverlaySha256)
    {
        var body = new StringBuilder();
        body.Append("global-edl-restore-v1\n");
        body.Append("manifest=").Append(manifestSha256.ToUpperInvariant()).Append('\n');
        AppendIdentity(body, identity);

        foreach (GlobalEdlRestoreLunGeometry lun in luns)
        {
            body.Append("lun=").Append(Invariant(lun.Lun))
                .Append(";sector=").Append(Invariant(lun.SectorSize))
                .Append(";total=").Append(Invariant(lun.TotalSectors)).Append('\n');
        }

        foreach (GlobalEdlRestoreRegion region in regions)
        {
            body.Append("region=").Append(region.Role)
                .Append(";kind=").Append(region.Kind)
                .Append(";lun=").Append(Invariant(region.Lun))
                .Append(";start=").Append(Invariant(region.StartSector))
                .Append(";count=").Append(Invariant(region.SectorCount))
                .Append(";sector=").Append(Invariant(region.SectorSize)).Append('\n');

            foreach (GlobalEdlRestoreChunk chunk in region.Chunks)
            {
                body.Append("chunk=").Append(chunk.FileName)
                    .Append(";offset=").Append(Invariant(chunk.OffsetBytes))
                    .Append(";bytes=").Append(Invariant(chunk.RawBytes))
                    .Append(";sha=").Append(chunk.RawSha256.ToUpperInvariant()).Append('\n');
            }
        }

        body.Append("bcb=").Append(bcbOverlaySha256.ToUpperInvariant()).Append('\n');
        body.Append("clearData=true\n");

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body.ToString())));
    }

    private static void AppendIdentity(StringBuilder body, GlobalEdlIdentity identity)
    {
        body.Append("profile=").Append(identity.ProfileId).Append('\n');
        body.Append("model=").Append(identity.Model).Append('\n');
        body.Append("hwid=").Append(identity.HardwareId).Append('\n');
        body.Append("bus=").Append(identity.BusSerialHex.ToUpperInvariant()).Append('\n');
    }

    private static void WriteImmutableJson(string path, object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, GlobalEdlBackup.JsonOptions);

        using FileStream stream = new(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            CopyBufferBytes,
            FileOptions.WriteThrough);

        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static void RequireIdentityMatch(GlobalEdlIdentity saved, GlobalEdlIdentity actual)
    {
        if (saved is null || actual is null)
        {
            throw new InvalidDataException("Both the backup identity and the device identity are required.");
        }

        if (!string.Equals(saved.ProfileId, actual.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The backup profile '{saved.ProfileId}' does not match the device profile '{actual.ProfileId}'.");
        }

        if (!string.Equals(saved.Model, actual.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The backup model '{saved.Model}' does not match the device model '{actual.Model}'.");
        }

        if (!string.Equals(saved.HardwareId, actual.HardwareId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The backup hardware id does not match the currently bound hardware id.");
        }

        if (!string.Equals(saved.BusSerialHex, actual.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The backup bus serial '{saved.BusSerialHex}' does not match the present bus serial " +
                $"'{actual.BusSerialHex}'.");
        }

        // Optional historical Android fields are deliberately not compared: a different firmware on the same
        // tablet does not make this backup foreign, and a bootable Android is never required for a restore.
    }

    private static void RequireProbe(
        EdlProbeEvidence evidence,
        GlobalEdlLun expected,
        GlobalEdlIdentity identity,
        bool initialLoader)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        EdlGeometry geometry = evidence.Geometry
            ?? throw new InvalidOperationException("The probe returned no geometry.");

        if (geometry.Lun != expected.Lun)
        {
            throw new InvalidOperationException(
                $"The probe reported LUN{geometry.Lun} instead of LUN{expected.Lun}.");
        }

        if (geometry.SectorSize != expected.SectorSize)
        {
            throw new InvalidOperationException(
                $"LUN{expected.Lun} reports sector size {geometry.SectorSize}, the backup captured {expected.SectorSize}.");
        }

        if (geometry.TotalSectors != expected.TotalSectors)
        {
            throw new InvalidOperationException(
                $"LUN{expected.Lun} reports {geometry.TotalSectors} sectors, the backup captured {expected.TotalSectors}.");
        }

        if (!string.Equals(evidence.BusSerialHex, identity.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"LUN{expected.Lun} was probed on bus serial '{evidence.BusSerialHex}', " +
                $"the backup belongs to '{identity.BusSerialHex}'.");
        }

        if (!initialLoader)
        {
            return;
        }

        if (string.IsNullOrEmpty(evidence.SaharaSerialHex) ||
            !string.Equals(evidence.SaharaSerialHex, identity.BusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The initial raw probe did not prove the expected Sahara serial.");
        }

        if (string.IsNullOrEmpty(evidence.HardwareId) ||
            !string.Equals(evidence.HardwareId, identity.HardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The initial raw probe did not prove the expected hardware id.");
        }
    }

    private static void RequireProbe(
        EdlProbeEvidence evidence,
        GlobalEdlRestoreLunGeometry expected,
        GlobalEdlIdentity identity,
        bool initialLoader)
    {
        RequireProbe(
            evidence,
            new GlobalEdlLun
            {
                Lun = expected.Lun,
                SectorSize = expected.SectorSize,
                TotalSectors = expected.TotalSectors,
                DiskGuid = expected.DiskGuid
            },
            identity,
            initialLoader);
    }

    // ------------------------------------------------------------------ execute helpers

    private static GlobalEdlRestoreRegion RequireGptRegion(
        IReadOnlyList<GlobalEdlRestoreRegion> regions,
        int lun,
        string kind)
    {
        GlobalEdlRestoreRegion? found = null;

        foreach (GlobalEdlRestoreRegion region in regions)
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

    private static async Task WriteAndVerifyRegionAsync(
        RestoreSession session,
        GlobalEdlRestoreRegion region,
        string writeStage,
        string readbackStage,
        long stageTotal,
        long stageBase,
        List<RetainedReadback>? retained,
        CancellationToken token)
    {
        GlobalEdlRestorePlan plan = session.Plan;

        session.Stage = writeStage;
        session.Role = region.Role;
        session.Lun = region.Lun;

        for (int index = 0; index < region.Chunks.Count; index++)
        {
            token.ThrowIfCancellationRequested();

            plan.ThrowIfDisposed();
            plan.Backup.ThrowIfDisposed();
            session.Stage = writeStage;

            GlobalEdlRestoreChunk chunk = region.Chunks[index];

            if (chunk.OffsetBytes % region.SectorSize != 0 ||
                chunk.RawBytes % region.SectorSize != 0)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' is not sector aligned.");
            }

            string suffix = "-c" + index.ToString("D3", CultureInfo.InvariantCulture);
            string rawPath = Path.Combine(plan.WorkDirectory, region.Role + suffix + ".raw");
            string readbackPath = Path.Combine(plan.WorkDirectory, region.Role + suffix + ".readback.bin");

            if (chunk.RawSha256.Length != 64)
            {
                throw new InvalidDataException($"Chunk '{chunk.FileName}' carries a malformed digest.");
            }

            using (FileStream raw = new(
                       rawPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyBufferBytes,
                       FileOptions.SequentialScan))
            {
                await GlobalEdlBackup
                    .VerifyChunkAsync(
                        ResolveChunkPath(plan.Backup.DirectoryPath, chunk.FileName),
                        chunk.ToManifestChunk(),
                        raw,
                        token)
                    .ConfigureAwait(false);

                raw.Flush(flushToDisk: true);
            }

            long rawLength = new FileInfo(rawPath).Length;
            if (rawLength != chunk.RawBytes)
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' produced {rawLength} bytes, expected {chunk.RawBytes}.");
            }

            string rawSha = ComputeFileSha256(rawPath);
            if (!string.Equals(rawSha, chunk.RawSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"Chunk '{chunk.FileName}' does not reproduce its declared raw digest.");
            }

            long startSector = checked(region.StartSector + (chunk.OffsetBytes / region.SectorSize));
            long sectorCount = chunk.RawBytes / region.SectorSize;
            long chunkBase = checked(stageBase + chunk.OffsetBytes);

            var entry = new GlobalEdlRestoreJournalEntry
            {
                Role = region.Role,
                Kind = region.Kind,
                Lun = region.Lun,
                StartSector = startSector,
                SectorCount = sectorCount,
                SectorSize = region.SectorSize,
                ChunkFile = chunk.FileName,
                OffsetBytes = chunk.OffsetBytes,
                RawBytes = chunk.RawBytes,
                RawSha256 = rawSha,
                Phase = "intent",
            };

            session.Journal.Entries.Add(entry);
            session.Journal.AnyWriteStarted = true;
            session.Journal.Stage = writeStage;
            session.Journal.Role = region.Role;
            session.Journal.Lun = region.Lun;
            session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
            SaveJournal(plan.JournalPath, session.Journal);

            // From here on a device write may have happened, whatever the tool later reports.
            session.AnyWriteStarted = true;

            EdlWriteEvidence writeEvidence = await plan.Client
                .WriteAsync(
                    region.Lun,
                    startSector,
                    new VerifiedEdlFile(rawPath, chunk.RawBytes, rawSha),
                    new TransferObserver(plan.LogsDirectory, writeStage, region.Role, region.Lun, chunkBase, stageTotal, session.Progress),
                    BuildLogPrefix(plan.LogsDirectory, region.Role + suffix + "-write"),
                    token)
                .ConfigureAwait(false);

            RequireWriteEvidence(writeEvidence, region, startSector, sectorCount, chunk.RawBytes, rawSha);

            entry.Phase = "acknowledged";
            session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
            SaveJournal(plan.JournalPath, session.Journal);

            // From here the readback is the failing operation if anything goes wrong.
            session.Stage = readbackStage;

            EdlReadEvidence readEvidence = await plan.Client
                .ReadAsync(
                    region.Lun,
                    startSector,
                    sectorCount,
                    readbackPath,
                    new TransferObserver(plan.LogsDirectory, readbackStage, region.Role, region.Lun, chunkBase, stageTotal, session.Progress),
                    BuildLogPrefix(plan.LogsDirectory, region.Role + suffix + "-read"),
                    token)
                .ConfigureAwait(false);

            RequireReadEvidence(
                readEvidence,
                readbackPath,
                region,
                startSector,
                sectorCount,
                chunk.RawBytes,
                rawSha);

            string reopened = ComputeFileSha256(readbackPath);
            if (!string.Equals(reopened, rawSha, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The readback of '{region.Role}' does not hash to the written bytes.");
            }

            entry.Phase = "verified";
            entry.ReadbackSha256 = reopened;
            session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
            SaveJournal(plan.JournalPath, session.Journal);

            DeleteQuietly(rawPath);

            if (retained is null)
            {
                DeleteQuietly(readbackPath);
            }
            else
            {
                retained.Add(new RetainedReadback(chunk, readbackPath));
            }
        }

        if (!session.Verified.Contains(region.Role, StringComparer.Ordinal))
        {
            session.Verified.Add(region.Role);
        }

        GlobalEdlBackup.Report(
            session.Progress, readbackStage, region.Role, region.Lun, checked(stageBase + region.RawBytes), stageTotal);
    }

    private static async Task WriteAndVerifyBcbAsync(
        RestoreSession session,
        CancellationToken token)
    {
        GlobalEdlRestorePlan plan = session.Plan;
        plan.ThrowIfDisposed();
        plan.Backup.ThrowIfDisposed();

        GlobalEdlRestoreRegion misc = plan.MiscRegion;

        session.Stage = "initialize-android";
        session.Role = BcbRole;
        session.Lun = 0;

        FileInfo overlayInfo = new(plan.BcbOverlayPath);
        if (!overlayInfo.Exists || overlayInfo.Length != plan.BcbUnit.Length)
        {
            throw new InvalidDataException("The prepared BCB overlay no longer matches the plan.");
        }

        byte[] overlay = ReadPrefix(plan.BcbOverlayPath, plan.BcbUnit.Length);

        if (!string.Equals(ComputeFileSha256(plan.BcbOverlayPath), plan.BcbOverlaySha256, StringComparison.OrdinalIgnoreCase) ||
            !overlay.AsSpan().SequenceEqual(plan.BcbUnit))
        {
            throw new InvalidDataException("The prepared BCB overlay no longer matches the plan.");
        }

        if (overlay.Length == 0 || overlay.Length % misc.SectorSize != 0)
        {
            throw new InvalidDataException("The BCB overlay is not sector aligned.");
        }

        long sectorCount = overlay.Length / misc.SectorSize;

        if (sectorCount > misc.SectorCount || overlay.Length > misc.RawBytes)
        {
            throw new InvalidDataException("The BCB overlay does not fit inside the misc partition.");
        }

        string readbackPath = Path.Combine(plan.WorkDirectory, "bcb.readback.bin");

        var entry = new GlobalEdlRestoreJournalEntry
        {
            Role = BcbRole,
            Kind = BcbRole,
            Lun = 0,
            StartSector = misc.StartSector,
            SectorCount = sectorCount,
            SectorSize = misc.SectorSize,
            ChunkFile = BcbOverlayFileName,
            OffsetBytes = 0,
            RawBytes = overlay.Length,
            RawSha256 = plan.BcbOverlaySha256,
            Phase = "intent",
        };

        session.Journal.Entries.Add(entry);
        session.Journal.AnyWriteStarted = true;
        session.Journal.Stage = "initialize-android";
        session.Journal.Role = BcbRole;
        session.Journal.Lun = 0;
        session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
        SaveJournal(plan.JournalPath, session.Journal);

        session.AnyWriteStarted = true;

        EdlWriteEvidence writeEvidence = await plan.Client
            .WriteAsync(
                0,
                misc.StartSector,
                new VerifiedEdlFile(plan.BcbOverlayPath, overlay.Length, plan.BcbOverlaySha256),
                new TransferObserver(
                    plan.LogsDirectory, "initialize-android", BcbRole, 0, 0, overlay.Length, session.Progress),
                BuildLogPrefix(plan.LogsDirectory, "bcb-write"),
                token)
            .ConfigureAwait(false);

        RequireBcbWriteEvidence(writeEvidence, misc, sectorCount, overlay.Length, plan.BcbOverlaySha256);

        entry.Phase = "acknowledged";
        session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
        SaveJournal(plan.JournalPath, session.Journal);

        EdlReadEvidence readEvidence = await plan.Client
            .ReadAsync(
                0,
                misc.StartSector,
                sectorCount,
                readbackPath,
                new TransferObserver(
                    plan.LogsDirectory, "initialize-android", BcbRole, 0, 0, overlay.Length, session.Progress),
                BuildLogPrefix(plan.LogsDirectory, "bcb-read"),
                token)
            .ConfigureAwait(false);

        if (readEvidence.Geometry is null ||
            readEvidence.Geometry.Lun != 0 ||
            readEvidence.Geometry.SectorSize != misc.SectorSize ||
            readEvidence.StartSector != misc.StartSector ||
            readEvidence.SectorCount != sectorCount ||
            readEvidence.Length != overlay.Length ||
            !string.Equals(readEvidence.Sha256, plan.BcbOverlaySha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFullPath(readEvidence.FilePath),
                Path.GetFullPath(readbackPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The BCB readback evidence does not describe the written unit.");
        }

        string reopened = ComputeFileSha256(readbackPath);
        if (!string.Equals(reopened, plan.BcbOverlaySha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The BCB readback does not hash to the prepared unit.");
        }

        entry.Phase = "verified";
        entry.ReadbackSha256 = reopened;
        session.Journal.UpdatedUtc = DateTimeOffset.UtcNow;
        SaveJournal(plan.JournalPath, session.Journal);

        DeleteQuietly(readbackPath);

        if (!session.Verified.Contains(BcbRole, StringComparer.Ordinal))
        {
            session.Verified.Add(BcbRole);
        }

        GlobalEdlBackup.Report(
            session.Progress, "initialize-android", BcbRole, 0, overlay.Length, overlay.Length);
    }

    private static void RequireWriteEvidence(
        EdlWriteEvidence evidence,
        GlobalEdlRestoreRegion region,
        long startSector,
        long sectorCount,
        long length,
        string sha256)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        if (evidence.Geometry is null ||
            evidence.Geometry.Lun != region.Lun ||
            evidence.Geometry.SectorSize != region.SectorSize)
        {
            throw new InvalidDataException(
                $"The write evidence of '{region.Role}' does not describe LUN{region.Lun}.");
        }

        if (evidence.StartSector != startSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidDataException(
                $"The write evidence of '{region.Role}' does not describe the requested sector range.");
        }

        if (evidence.Length != length)
        {
            throw new InvalidDataException(
                $"The write evidence of '{region.Role}' reports {evidence.Length} bytes, expected {length}.");
        }

        if (!string.Equals(evidence.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The write evidence of '{region.Role}' reports a foreign digest.");
        }
    }

    private static void RequireBcbWriteEvidence(
        EdlWriteEvidence evidence,
        GlobalEdlRestoreRegion misc,
        long sectorCount,
        long length,
        string sha256)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        if (evidence.Geometry is null ||
            evidence.Geometry.Lun != 0 ||
            evidence.Geometry.SectorSize != misc.SectorSize)
        {
            throw new InvalidDataException("The BCB write evidence does not describe LUN0.");
        }

        if (evidence.StartSector != misc.StartSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidDataException("The BCB write evidence does not describe the requested sector range.");
        }

        if (evidence.Length != length ||
            !string.Equals(evidence.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The BCB write evidence does not describe the prepared unit.");
        }
    }

    private static void RequireReadEvidence(
        EdlReadEvidence evidence,
        string expectedPath,
        GlobalEdlRestoreRegion region,
        long startSector,
        long sectorCount,
        long length,
        string sha256)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        if (evidence.Geometry is null ||
            evidence.Geometry.Lun != region.Lun ||
            evidence.Geometry.SectorSize != region.SectorSize)
        {
            throw new InvalidDataException(
                $"The readback evidence of '{region.Role}' does not describe LUN{region.Lun}.");
        }

        if (evidence.StartSector != startSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidDataException(
                $"The readback evidence of '{region.Role}' does not describe the requested sector range.");
        }

        if (evidence.Length != length ||
            !string.Equals(evidence.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The readback evidence of '{region.Role}' does not describe the written bytes.");
        }

        if (!string.Equals(
                Path.GetFullPath(evidence.FilePath),
                Path.GetFullPath(expectedPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The readback evidence of '{region.Role}' names a foreign output file.");
        }
    }

    private static void ProveGptPair(
        int lun,
        GlobalEdlRestoreLunGeometry geometry,
        GlobalEdlRestoreGptExpectation expectation,
        List<RetainedReadback> backupReadbacks,
        List<RetainedReadback> primaryReadbacks)
    {
        byte[] primaryBytes = ReadRetained(primaryReadbacks);
        byte[] backupBytes = ReadRetained(backupReadbacks);

        GptTable table = OriginalGptImporter.Parse(
            primaryBytes, backupBytes, geometry.SectorSize, geometry.DiskBytes);

        if (table.SectorSize != geometry.SectorSize || table.DiskBytes != geometry.DiskBytes)
        {
            throw new InvalidDataException(
                $"The decoded GPT of LUN{lun} does not carry the proven geometry.");
        }

        if (!string.Equals(table.DiskGuid, expectation.DiskGuid, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The decoded GPT of LUN{lun} names disk '{table.DiskGuid}', expected '{expectation.DiskGuid}'.");
        }

        if (!string.Equals(
                table.SourceFingerprint, expectation.SourceFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"The decoded GPT bytes of LUN{lun} do not reproduce the captured table.");
        }
    }

    private static byte[] ReadRetained(List<RetainedReadback> items)
    {
        long total = 0;

        foreach (RetainedReadback item in items.OrderBy(item => item.Chunk.OffsetBytes))
        {
            total = checked(total + item.Chunk.RawBytes);
        }

        if (total <= 0 || total > MaxGptRegionBytes)
        {
            throw new InvalidDataException(
                $"A GPT readback spans {total} bytes, outside the supported 1..{MaxGptRegionBytes} range.");
        }

        byte[] buffer = new byte[total];
        int offset = 0;

        foreach (RetainedReadback item in items.OrderBy(item => item.Chunk.OffsetBytes))
        {
            byte[] bytes = File.ReadAllBytes(item.Path);

            if (bytes.Length != item.Chunk.RawBytes)
            {
                throw new InvalidDataException("A retained GPT readback changed size.");
            }

            Buffer.BlockCopy(bytes, 0, buffer, offset, bytes.Length);
            offset += bytes.Length;
        }

        return buffer;
    }

    private static void DeleteRetained(List<RetainedReadback> items)
    {
        foreach (RetainedReadback item in items)
        {
            DeleteQuietly(item.Path);
        }
    }

    private static void DeleteQuietly(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Cleanup only; a retained verified file is harmless evidence.
        }
        catch (UnauthorizedAccessException)
        {
            // Cleanup only.
        }
    }

    private static string BuildLogPrefix(string logsDirectory, string name)
    {
        return Path.Combine(logsDirectory, name);
    }

    private static string ResolveChunkPath(string directory, string fileName)
    {
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

    private static string ComputeFileSha256(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes, FileOptions.SequentialScan);

        byte[] hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }

    private static void SaveJournal(string path, GlobalEdlRestoreJournal journal)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(journal, GlobalEdlBackup.JsonOptions);
        string temporary = path + ".tmp";

        using (FileStream stream = new(
                   temporary,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   CopyBufferBytes,
                   FileOptions.WriteThrough))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    private static string Invariant(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static string Invariant(long value) => value.ToString(CultureInfo.InvariantCulture);

    private sealed class TransferObserver : IProgress<EdlTransferProgress>
    {
        private readonly IProgress<GlobalEdlProgress>? _target;
        private readonly string _stage;
        private readonly string? _role;
        private readonly int? _lun;
        private readonly long _base;
        private readonly long _total;

        internal TransferObserver(
            string logsDirectory,
            string stage,
            string? role,
            int? lun,
            long absoluteBase,
            long absoluteTotal,
            IProgress<GlobalEdlProgress>? target)
        {
            _ = logsDirectory;
            _stage = stage;
            _role = role;
            _lun = lun;
            _base = absoluteBase;
            _total = absoluteTotal;
            _target = target;
        }

        public void Report(EdlTransferProgress value)
        {
            long completed = _base;

            if (value is not null)
            {
                long delta = value.CompletedBytes < 0 ? 0 : value.CompletedBytes;

                try
                {
                    completed = checked(_base + delta);
                }
                catch (OverflowException)
                {
                    completed = _total;
                }

                if (completed > _total)
                {
                    completed = _total;
                }
            }

            GlobalEdlBackup.Report(_target, _stage, _role, _lun, completed, _total);
        }
    }

    private sealed class RetainedReadback
    {
        internal RetainedReadback(GlobalEdlRestoreChunk chunk, string path)
        {
            Chunk = chunk;
            Path = path;
        }

        internal GlobalEdlRestoreChunk Chunk { get; }

        internal string Path { get; }
    }

    private sealed class RestoreSession
    {
        internal RestoreSession(GlobalEdlRestorePlan plan, IProgress<GlobalEdlProgress>? progress)
        {
            Plan = plan;
            Progress = progress;
        }

        internal GlobalEdlRestorePlan Plan { get; }

        internal IProgress<GlobalEdlProgress>? Progress { get; }

        internal GlobalEdlRestoreJournal Journal { get; set; } = new();

        internal bool AnyWriteStarted { get; set; }

        internal List<string> Verified { get; } = new();

        internal string Stage { get; set; } = "probe";

        internal string? Role { get; set; }

        internal int? Lun { get; set; }
    }

    private sealed class GlobalEdlRestoreJournal
    {
        public int SchemaVersion { get; set; } = 1;

        public string State { get; set; } = "running";

        public string ConfirmationId { get; set; } = string.Empty;

        public string Stage { get; set; } = "probe";

        public string? Role { get; set; }

        public int? Lun { get; set; }

        public bool AnyWriteStarted { get; set; }

        public bool InitializationQueued { get; set; }

        public string? Error { get; set; }

        public DateTimeOffset UpdatedUtc { get; set; }

        public List<GlobalEdlRestoreJournalEntry> Entries { get; set; } = new();
    }

    private sealed class GlobalEdlRestoreJournalEntry
    {
        public string Role { get; set; } = string.Empty;

        public string Kind { get; set; } = string.Empty;

        public int Lun { get; set; }

        public long StartSector { get; set; }

        public long SectorCount { get; set; }

        public int SectorSize { get; set; }

        public string? ChunkFile { get; set; }

        public long OffsetBytes { get; set; }

        public long RawBytes { get; set; }

        public string RawSha256 { get; set; } = string.Empty;

        public string Phase { get; set; } = "intent";

        public string? ReadbackSha256 { get; set; }
    }

    private sealed class RestorePlanReceipt
    {
        public int SchemaVersion { get; set; } = 1;

        public string ConfirmationId { get; set; } = string.Empty;

        public string ManifestSha256 { get; set; } = string.Empty;

        public string ProfileId { get; set; } = string.Empty;

        public string Model { get; set; } = string.Empty;

        public string HardwareId { get; set; } = string.Empty;

        public string BusSerialHex { get; set; } = string.Empty;

        public bool ClearData { get; set; } = true;

        public long AndroidBytes { get; set; }

        public long WriteBytes { get; set; }

        public int RegionCount { get; set; }

        public long BcbBytes { get; set; }

        public string BcbOverlaySha256 { get; set; } = string.Empty;

        public string Fingerprint { get; set; } = string.Empty;

        public DateTimeOffset CreatedUtc { get; set; }

        public List<RestorePlanLunReceipt> Luns { get; set; } = new();

        public List<RestorePlanRegionReceipt> Regions { get; set; } = new();
    }

    private sealed class RestorePlanLunReceipt
    {
        public int Lun { get; set; }

        public int SectorSize { get; set; }

        public long TotalSectors { get; set; }

        public string DiskGuid { get; set; } = string.Empty;
    }

    private sealed class RestorePlanRegionReceipt
    {
        public string Role { get; set; } = string.Empty;

        public string Kind { get; set; } = string.Empty;

        public int Lun { get; set; }

        public long StartSector { get; set; }

        public long SectorCount { get; set; }

        public int SectorSize { get; set; }

        public int? PartitionNumber { get; set; }

        public string? PartitionName { get; set; }

        public long RawBytes { get; set; }

        public List<RestorePlanChunkReceipt> Chunks { get; set; } = new();
    }

    private sealed class RestorePlanChunkReceipt
    {
        public string FileName { get; set; } = string.Empty;

        public long OffsetBytes { get; set; }

        public long RawBytes { get; set; }

        public string RawSha256 { get; set; } = string.Empty;
    }
}
