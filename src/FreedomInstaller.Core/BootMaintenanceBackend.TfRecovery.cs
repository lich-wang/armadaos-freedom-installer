using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Merely saved file facts parsed back out of a temporary-TF-boot rollback journal.
/// This is an untrusted locator of what was recorded before the temporary boot:
/// it is never a statement about the current device, trust state, or readiness.
/// </summary>
public sealed class TfBootRecoveryHint
{
    internal TfBootRecoveryHint(
        string journalPath,
        string originalBackupDirectory,
        string originalBackupManifestSha256,
        string model,
        string androidSerial,
        string socSerial,
        string currentSlot)
    {
        JournalPath = journalPath;
        OriginalBackupDirectory = originalBackupDirectory;
        OriginalBackupManifestSha256 = originalBackupManifestSha256;
        Model = model;
        AndroidSerial = androidSerial;
        SocSerial = socSerial;
        CurrentSlot = currentSlot;
    }

    public string JournalPath { get; }

    public string OriginalBackupDirectory { get; }

    public string OriginalBackupManifestSha256 { get; }

    public string Model { get; }

    public string AndroidSerial { get; }

    public string SocSerial { get; }

    public string CurrentSlot { get; }
}

public sealed partial class BootMaintenanceBackend
{
    private const string TfRollbackJournalFileName = "tf-rollback.json";
    private const long TfRollbackJournalMaxBytes = 1024 * 1024;
    private const int TfRollbackJournalMaxCaptures = 128;
    private const string TfMiscRole = "misc";
    private const string TfEfiSpRole = "efisp";
    private const string TfReturnEvidencePrefix = "tf-return-";
    private const string TfRestoreReceiptName = "tf-restore-prepare";
    private const int TfBootControlBaseOffset = 2048;

    private static readonly string[] TfSlotWritePrefixes =
    {
        "boot_",
        "recovery_",
        "vbmeta_system_",
        "vbmeta_"
    };

    /// <summary>
    /// Parses and revalidates the bounded rollback journal format from disk and
    /// returns only the saved file facts. No device access happens here; on a
    /// malformed or missing journal this fails rather than fabricating a hint.
    /// The journal is never a ready flag.
    /// </summary>
    public static Task<TfBootRecoveryHint> ReadTfRecoveryHintAsync(string journalPath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(journalPath))
            throw new ArgumentException("Rollback journal path is required.", nameof(journalPath));

        ct.ThrowIfCancellationRequested();

        var journal = OpenTfRollbackJournal(journalPath);
        try
        {
            return Task.FromResult(new TfBootRecoveryHint(
                journal.Claim.Path,
                journal.Data.OriginalBackupDirectory,
                journal.Data.OriginalBackupManifestSha256,
                journal.Data.Model,
                journal.Data.AndroidSerial,
                journal.Data.SocSerial,
                journal.Data.CurrentSlot));
        }
        finally
        {
            journal.Dispose();
        }
    }

    /// <summary>
    /// Builds a real closed-policy backend that restores the original whole
    /// boot/EFI/companion partitions from the recorded pre-RAM capture through a
    /// new physical EDL session. Works after an application restart: no previous
    /// backend object or process-local token is required. The old backup is used
    /// as source only; every current physical region is independently reread and
    /// compared before anything is planned. No ABL/GPT/misc/userdata/SD-card
    /// writes and no active-slot changes happen here; the shared executor owns
    /// the actual write, readback, and single reset.
    /// </summary>
    public static async Task<TfBootBackend> CreateTfRestorePreviousFromEdlAsync(
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet freshBackup,
        string rollbackJournalPath,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(history);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(freshBackup);
        if (string.IsNullOrWhiteSpace(rollbackJournalPath))
            throw new ArgumentException("Rollback journal path is required.", nameof(rollbackJournalPath));
        ArgumentNullException.ThrowIfNull(runner);
        if (string.IsNullOrWhiteSpace(evidenceParent))
            throw new ArgumentException("Evidence parent directory is required.", nameof(evidenceParent));

        cancellationToken.ThrowIfCancellationRequested();

        TfReturnContext? context = null;
        try
        {
            context = await OpenTfReturnContextAsync(
                history,
                client,
                freshBackup,
                rollbackJournalPath,
                runner,
                evidenceParent,
                TfBootOperation.RestorePrevious,
                progress,
                cancellationToken).ConfigureAwait(false);

            var journal = context.Journal;
            var slot = journal.Data.CurrentSlot;

            // Derive candidates ONLY from the reopened original captures. The
            // journal never carries image paths and is never a write authority.
            var orderedWrites = journal.Data.Writes
                .OrderBy(w => TfRestoreWriteOrder(w.Role, slot))
                .ToList();

            var plan = new List<PlannedRegion>(orderedWrites.Count);
            var regions = new List<BootMaintenanceRegionSummary>(orderedWrites.Count);
            foreach (var write in orderedWrites)
            {
                var oldRegion = RequireRegion(context.Original.Files, write.Role, $"tf restore {write.Role} original capture");
                var freshRegion = RequireRegion(context.Current.Files, write.Role, $"tf restore {write.Role} current target");
                RequireRegionMatchesGpt(context.Current, freshRegion, $"tf restore {write.Role} target");

                var oldClaim = RegionClaim(context.Original.Files, write.Role, $"tf restore {write.Role} original claim");
                var willWrite = !IsByteIdentical(oldClaim, freshRegion);

                plan.Add(new PlannedRegion(
                    write.Role,
                    write.Slot,
                    oldRegion.Lun,
                    oldRegion.StartSector,
                    oldRegion.SectorCount,
                    oldRegion.Length,
                    freshRegion.Sha256,
                    willWrite ? oldRegion.FilePath : null,
                    willWrite ? oldRegion.Sha256 : null));

                regions.Add(new BootMaintenanceRegionSummary(
                    write.Role,
                    write.Slot,
                    oldRegion.Lun,
                    oldRegion.StartSector,
                    oldRegion.SectorCount,
                    oldRegion.Length,
                    freshRegion.Sha256,
                    willWrite ? oldRegion.Sha256 : null,
                    willWrite));
            }

            var confirmationSha256 = ComputeTfRestoreConfirmationSha256(
                context.EvidenceNonce,
                journal.Claim.Sha256,
                context.Original.ManifestSha256,
                context.Current.ManifestSha256,
                history.HardwareId,
                client.Binding.BusSerialHex,
                slot,
                context.SlotFacts.ControlSha256,
                plan);

            WriteReceipt(context.EvidenceDirectory, TfRestoreReceiptName, writer =>
            {
                writer.WriteString("operation", "RestorePrevious");
                writer.WriteString("confirmationSha256", confirmationSha256);
                writer.WriteString("journalPath", journal.Claim.Path);
                writer.WriteString("journalSha256", journal.Claim.Sha256);
                writer.WriteString("originalBackupDirectory", context.Original.DirectoryPath);
                writer.WriteString("originalBackupManifestSha256", context.Original.ManifestSha256);
                writer.WriteString("targetBackupDirectory", context.Current.DirectoryPath);
                writer.WriteString("targetBackupManifestSha256", context.Current.ManifestSha256);
                writer.WriteString("profileId", history.ProfileId);
                writer.WriteString("model", history.Model);
                writer.WriteString("hardwareId", history.HardwareId);
                writer.WriteString("androidSerial", history.AndroidSerial);
                writer.WriteString("socSerial", history.SocSerialDecimal);
                writer.WriteString("busSerialHex", client.Binding.BusSerialHex);
                writer.WriteString("currentSlot", slot);
                writer.WriteString("slotControlSha256", context.SlotFacts.ControlSha256);
                writer.WriteBoolean("needsBootloaderAttention", context.SlotFacts.NeedsBootloaderAttention);
                writer.WriteStartArray("regions");
                foreach (var region in plan)
                {
                    writer.WriteStartObject();
                    writer.WriteString("role", region.Role);
                    if (region.Slot is not null)
                    {
                        writer.WriteString("slot", region.Slot);
                    }
                    else
                    {
                        writer.WriteNull("slot");
                    }

                    writer.WriteNumber("lun", region.Lun);
                    writer.WriteNumber("startSector", region.StartSector);
                    writer.WriteNumber("sectorCount", region.SectorCount);
                    writer.WriteNumber("length", region.Length);
                    writer.WriteString("currentSha256", region.CurrentSha256);
                    if (region.CandidateSha256 is not null)
                    {
                        writer.WriteString("candidateSha256", region.CandidateSha256);
                    }
                    else
                    {
                        writer.WriteNull("candidateSha256");
                    }

                    writer.WriteBoolean("willWrite", region.CandidatePath is not null);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            });

            var backend = new BootMaintenanceBackend(
                null,
                context.FactOrigin,
                context.SlotFacts.ControlSha256,
                client,
                runner,
                freshBackup,
                context.Current,
                context.Original,
                plan,
                new List<BootMaintenanceSlotSummary>(),
                slot,
                context.EvidenceDirectory,
                confirmationSha256,
                null,
                context.Leases,
                RegionExecutionPolicy.TfRestorePrevious);

            var prepared = new TfBootPrepared(
                TfBootOperation.RestorePrevious,
                null,
                confirmationSha256,
                history.Model,
                history.AndroidSerial,
                history.SocSerialDecimal,
                slot,
                context.Original.DirectoryPath,
                context.Original.ManifestSha256,
                context.Current.DirectoryPath,
                context.Current.ManifestSha256,
                context.EvidenceDirectory,
                string.Empty,
                journal.Claim.Path,
                regions);

            var result = new TfBootBackend(backend, TfBootOperation.RestorePrevious, prepared, context.Original, journal.Claim);
            context.TransferOwnership();
            return result;
        }
        catch
        {
            context?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Orders possible whole-extent restore writes by closed comparison: global
    /// efisp first; then the INACTIVE slot boot, recovery, vbmeta_system,
    /// vbmeta; then the CURRENT slot boot, recovery, vbmeta_system, vbmeta.
    /// No misc/ABL/GPT/userdata or active-slot writes exist in the whitelist.
    /// </summary>
    private static int TfRestoreWriteOrder(string role, string slot)
    {
        if (string.Equals(role, TfEfiSpRole, StringComparison.Ordinal))
        {
            return 0;
        }

        var inactiveSlot = string.Equals(slot, "a", StringComparison.Ordinal) ? "b" : "a";

        if (string.Equals(role, string.Concat("boot_", inactiveSlot), StringComparison.Ordinal))
        {
            return 1;
        }

        if (string.Equals(role, string.Concat("recovery_", inactiveSlot), StringComparison.Ordinal))
        {
            return 2;
        }

        if (string.Equals(role, string.Concat("vbmeta_system_", inactiveSlot), StringComparison.Ordinal))
        {
            return 3;
        }

        if (string.Equals(role, string.Concat("vbmeta_", inactiveSlot), StringComparison.Ordinal))
        {
            return 4;
        }

        if (string.Equals(role, string.Concat("boot_", slot), StringComparison.Ordinal))
        {
            return 5;
        }

        if (string.Equals(role, string.Concat("recovery_", slot), StringComparison.Ordinal))
        {
            return 6;
        }

        if (string.Equals(role, string.Concat("vbmeta_system_", slot), StringComparison.Ordinal))
        {
            return 7;
        }

        if (string.Equals(role, string.Concat("vbmeta_", slot), StringComparison.Ordinal))
        {
            return 8;
        }

        return int.MaxValue;
    }

    /// <summary>
    /// Fully validated, physical-proof-backed return context shared by this
    /// restore factory and the later temporary-to-Final factory. Everything is
    /// checked before any write plan exists.
    /// </summary>
    private static async Task<TfReturnContext> OpenTfReturnContextAsync(
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet freshBackup,
        string rollbackJournalPath,
        ICommandRunner runner,
        string evidenceParent,
        TfBootOperation operation,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken ct)
    {
        if (operation is not (TfBootOperation.Final or TfBootOperation.RestorePrevious))
            throw new ArgumentOutOfRangeException(nameof(operation), "Only Final or RestorePrevious may open a TF return context.");
        if (!Path.IsPathFullyQualified(evidenceParent))
            throw new ArgumentException("Evidence parent must be an absolute path.", nameof(evidenceParent));
        ct.ThrowIfCancellationRequested();

        if (!Directory.Exists(evidenceParent))
            throw new DirectoryNotFoundException($"Evidence parent directory does not exist: {evidenceParent}");

        var journal = OpenTfRollbackJournal(rollbackJournalPath);
        try
        {
            // 0. The normal-operation Final context validates the RAM→Final path and
            // must only ever see the original Temporary journal; app-restarted Final
            // authority is not accepted. RestorePrevious accepts a validated journal
            // of either operation.
            if (operation == TfBootOperation.Final
                && !string.Equals(journal.Data.Operation, "Temporary", StringComparison.Ordinal))
                throw new InvalidOperationException("TF return context for Final requires a \"Temporary\" rollback journal.");

            // 1. Journal original facts must exactly match the historical identity.
            RequireJournalMatchesHistory(journal.Data, history);

            var facts = new MaintenanceDeviceFacts(history.Identity, null, history);
            await RequireDeviceFactsAsync(facts, client, ct).ConfigureAwait(false);
            RequireTrustedProfile(client);
            RequireCallerBackupBinding(client, freshBackup);

            var evidenceNonce = Guid.NewGuid().ToString("N");
            var evidenceDirectory = Path.Combine(evidenceParent, TfReturnEvidencePrefix + evidenceNonce);
            Directory.CreateDirectory(evidenceDirectory);

            // 2. Prove the fresh physical target; never accept the old backup as current.
            var current = await InternalInstallBackup.OpenExistingAsync(client, freshBackup.DirectoryPath, null, ct).ConfigureAwait(false);
            try
            {
                RequireSameCapture(current, freshBackup);
                await ProbeSixLunsAsync(client, current, ct).ConfigureAwait(false);
                await ReadbackEveryCurrentRegionAsync(client, current, evidenceDirectory, progress, ct).ConfigureAwait(false);

                // 3. Reopen the old pre-RAM capture as source only, strictly, against fresh.
                var original = await InternalInstallBackup.OpenBootMaintenanceProjectTemplateAsync(client, current, journal.Data.OriginalBackupDirectory, ct).ConfigureAwait(false);
                try
                {
                    if (!string.Equals(original.ManifestSha256, journal.Data.OriginalBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Reopened original backup manifest hash differs from the recorded rollback journal.");

                    RequireBackupMatchesJournal(original, journal.Data);
                    RequireBackupMatchesJournal(current, journal.Data);

                    RequireGeometriesMatch(journal.Data, original.Geometries, "original");
                    RequireGeometriesMatch(journal.Data, current.Geometries, "current");

                    // Journal originalCaptures must EXACTLY equal the reopened original files.
                    RequireCapturesMatchFiles(journal.Data, original.Files);

                    if (current.Files.Count != original.Files.Count)
                        throw new InvalidOperationException("Reopened current capture set differs in region count from the original backup.");

                    foreach (var pair in original.Files)
                    {
                        var freshRegion = RequireRegion(current.Files, pair.Key, $"tf return context: region {pair.Key}");
                        var oldRegion = pair.Value;
                        if (oldRegion.Lun != freshRegion.Lun
                            || oldRegion.StartSector != freshRegion.StartSector
                            || oldRegion.SectorCount != freshRegion.SectorCount
                            || oldRegion.SectorSize != freshRegion.SectorSize
                            || oldRegion.Length != freshRegion.Length
                            || !string.Equals(oldRegion.PartUuid, freshRegion.PartUuid, StringComparison.Ordinal))
                            throw new InvalidOperationException($"Reopened current region '{pair.Key}' extent, sector size, or PARTUUID differs from the original backup.");
                    }

                    // 4. Fresh byte comparison across every captured region.
                    var writeRoles = new HashSet<string>(journal.Data.Writes.Select(w => w.Role), StringComparer.Ordinal);
                    foreach (var pair in original.Files)
                    {
                        var role = pair.Key;
                        var freshRegion = RequireRegion(current.Files, role, $"tf return context: region {role}");
                        if (string.Equals(role, TfMiscRole, StringComparison.Ordinal))
                        {
                            // Handled by the narrow misc comparison below.
                            continue;
                        }

                        if (writeRoles.Contains(role))
                        {
                            if (operation == TfBootOperation.Final)
                            {
                                var intent = journal.Data.Writes.Single(w => string.Equals(w.Role, role, StringComparison.Ordinal));
                                if (!string.Equals(freshRegion.Sha256, intent.StagedCandidateSha256, StringComparison.OrdinalIgnoreCase))
                                    throw new InvalidOperationException($"Region '{role}' does not carry the recorded staged candidate on the fresh target.");
                            }
                            else
                            {
                                // RestorePrevious permits any fresh bytes inside the
                                // validated whole extent, including partial writes
                                // matching neither old nor candidate.
                            }

                            continue;
                        }

                        if (!string.Equals(freshRegion.Sha256, pair.Value.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException($"Region '{role}' changed on the fresh target but is not an allowed write intent.");
                    }

                    // 5. Misc narrow comparison with real control parsers.
                    var originalMiscClaim = RegionClaim(original.Files, TfMiscRole, "tf return context: original misc");
                    var freshMiscClaim = RegionClaim(current.Files, TfMiscRole, "tf return context: fresh misc");
                    var originalSlotFacts = await BootSlotControl.ReadAsync(originalMiscClaim, ct).ConfigureAwait(false);
                    var freshSlotFacts = operation == TfBootOperation.Final
                        ? await BootSlotControl.ReadAsync(freshMiscClaim, ct).ConfigureAwait(false)
                        : await BootSlotControl.ReadForRecoveryAsync(freshMiscClaim, ct).ConfigureAwait(false);

                    if (!string.Equals(originalSlotFacts.CurrentSlot, journal.Data.CurrentSlot, StringComparison.Ordinal)
                        || !string.Equals(freshSlotFacts.CurrentSlot, journal.Data.CurrentSlot, StringComparison.Ordinal))
                        throw new InvalidOperationException("Boot control selected slot differs from the recorded rollback journal slot.");

                    var originalVab = await BootVirtualAbControl.ReadAsync(originalMiscClaim, ct).ConfigureAwait(false);
                    var freshVab = await BootVirtualAbControl.ReadAsync(freshMiscClaim, ct).ConfigureAwait(false);
                    if (!originalVab.IsFormatValid || originalVab.State != BootVirtualAbState.Completed
                        || !freshVab.IsFormatValid || freshVab.State != BootVirtualAbState.Completed)
                        throw new InvalidOperationException("Virtual A/B state is not Completed for the original or fresh backup.");

                    var originalMisc = RequireRegion(original.Files, TfMiscRole, "tf return context: original misc region");
                    var freshMisc = RequireRegion(current.Files, TfMiscRole, "tf return context: fresh misc region");
                    CompareMiscWholeBytes(originalMisc.FilePath, freshMisc.FilePath, journal.Data.CurrentSlot, "tf return context", ct);

                    // 6. Rehash the held journal before sealing; retain the readonly lease.
                    await RehashHeldFileAsync(journal.Claim.Path, journal.Claim.Length, journal.Claim.Sha256, "tf return context: journal", ct).ConfigureAwait(false);

                    var leases = new List<IDisposable> { journal };
                    return new TfReturnContext(facts, freshBackup, current, original, journal, evidenceDirectory, evidenceNonce, freshSlotFacts, leases);
                }
                catch
                {
                    original.Dispose();
                    throw;
                }
            }
            catch
            {
                current.Dispose();
                throw;
            }
        }
        catch
        {
            journal.Dispose();
            throw;
        }
    }

    private static void RequireJournalMatchesHistory(TfRollbackJournalData data, BootMaintenanceHistoricalIdentity history)
    {
        if (!SamePath(data.OriginalBackupDirectory, history.DirectoryPath))
            throw new InvalidOperationException("Rollback journal original backup directory differs from the historical identity.");
        if (!string.Equals(data.OriginalBackupManifestSha256, history.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Rollback journal original manifest hash differs from the historical identity.");
        if (!string.Equals(data.ProfileId, history.ProfileId, StringComparison.Ordinal)
            || !string.Equals(data.Model, history.Model, StringComparison.Ordinal)
            || !string.Equals(data.HardwareId, history.HardwareId, StringComparison.Ordinal)
            || !string.Equals(data.AndroidSerial, history.AndroidSerial, StringComparison.Ordinal)
            || !string.Equals(data.SocSerial, history.SocSerialDecimal, StringComparison.Ordinal))
            throw new InvalidOperationException("Rollback journal identity facts differ from the historical identity.");
    }

    private static void RequireBackupMatchesJournal(InternalBackupSet backup, TfRollbackJournalData data)
    {
        if (!string.Equals(backup.ProfileId, data.ProfileId, StringComparison.Ordinal)
            || !string.Equals(backup.Model, data.Model, StringComparison.Ordinal)
            || !string.Equals(backup.HardwareId, data.HardwareId, StringComparison.Ordinal))
            throw new InvalidOperationException("Reopened backup identity differs from the recorded rollback journal.");
    }

    private static void RequireGeometriesMatch(TfRollbackJournalData data, IReadOnlyDictionary<int, EdlGeometry> geometries, string subject)
    {
        if (geometries.Count != data.Geometries.Count)
            throw new InvalidOperationException($"Reopened {subject} backup geometry count differs from the rollback journal.");
        foreach (var journalGeometry in data.Geometries)
        {
            if (!geometries.TryGetValue(journalGeometry.Lun, out var geometry)
                || geometry.Lun != journalGeometry.Lun
                || geometry.SectorSize != journalGeometry.SectorSize
                || geometry.TotalSectors != journalGeometry.TotalSectors)
                throw new InvalidOperationException($"Rollback journal geometry for LUN {journalGeometry.Lun} differs from the reopened {subject} backup.");
        }
    }

    private static void RequireCapturesMatchFiles(TfRollbackJournalData data, IReadOnlyDictionary<string, EdlCapturedRegion> files)
    {
        if (files.Count != data.Captures.Count)
            throw new InvalidOperationException("Rollback journal originalCaptures set does not exactly match the reopened original backup files.");
        foreach (var capture in data.Captures)
        {
            if (!files.TryGetValue(capture.Role, out var region))
                throw new InvalidOperationException($"Rollback journal capture '{capture.Role}' is missing from the reopened original backup.");
            if (region.Lun != capture.Lun
                || region.StartSector != capture.StartSector
                || region.SectorCount != capture.SectorCount
                || region.Length != capture.Length
                || !string.Equals(region.PartUuid, capture.PartUuid, StringComparison.Ordinal)
                || !string.Equals(region.Sha256, capture.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Rollback journal capture '{capture.Role}' differs from the reopened original backup file.");
        }
    }

    /// <summary>
    /// Whole-misc byte comparison. Everything must be byte identical except the
    /// packed selected-slot tries nibble (which may only decrease) and the CRC
    /// field that both real parsers already verified. No misc write is planned.
    /// </summary>
    private static void CompareMiscWholeBytes(string originalPath, string freshPath, string currentSlot, string subject, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var originalStream = new FileStream(originalPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        using var freshStream = new FileStream(freshPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        if (originalStream.Length != freshStream.Length)
            throw new InvalidOperationException($"{subject}: misc lengths differ.");

        var slotByteOffset = TfBootControlBaseOffset + 12 + (string.Equals(currentSlot, "b", StringComparison.Ordinal) ? 2 : 0);
        var crcStart = TfBootControlBaseOffset + 28;
        var crcEnd = TfBootControlBaseOffset + 31;

        var originalBuffer = new byte[64 * 1024];
        var freshBuffer = new byte[64 * 1024];
        long position = 0;
        int read;
        while ((read = originalStream.Read(originalBuffer, 0, originalBuffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            var freshRead = 0;
            while (freshRead < read)
            {
                var n = freshStream.Read(freshBuffer, freshRead, read - freshRead);
                if (n <= 0)
                    throw new InvalidOperationException($"{subject}: misc truncated on the fresh target.");
                freshRead += n;
            }

            for (var i = 0; i < read; i++)
            {
                var originalByte = originalBuffer[i];
                var freshByte = freshBuffer[i];
                if (originalByte == freshByte)
                {
                    continue;
                }

                var absolute = position + i;
                if (absolute == slotByteOffset)
                {
                    if (((originalByte ^ freshByte) & ~0x70) != 0)
                        throw new InvalidOperationException($"{subject}: boot control slot byte changed outside the tries nibble.");
                    var oldTries = (originalByte & 0x70) >> 4;
                    var newTries = (freshByte & 0x70) >> 4;
                    if (newTries > oldTries)
                        throw new InvalidOperationException($"{subject}: boot control tries increased.");
                    continue;
                }

                if (absolute >= crcStart && absolute <= crcEnd)
                {
                    continue;
                }

                throw new InvalidOperationException($"{subject}: misc byte at offset {absolute} differs outside the permitted boot control fields.");
            }

            position += read;
        }
    }

    private static string ComputeTfRestoreConfirmationSha256(
        string evidenceNonce,
        string journalSha256,
        string originalManifestSha256,
        string currentManifestSha256,
        string hardwareId,
        string busSerialHex,
        string currentSlot,
        string slotControlSha256,
        IReadOnlyList<PlannedRegion> plan)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("kind", "tf-restore-previous");
            writer.WriteString("evidenceNonce", evidenceNonce);
            writer.WriteString("operation", "RestorePrevious");
            writer.WriteString("journalSha256", journalSha256);
            writer.WriteString("originalBackupManifestSha256", originalManifestSha256);
            writer.WriteString("currentBackupManifestSha256", currentManifestSha256);
            writer.WriteString("hardwareId", hardwareId);
            writer.WriteString("busSerialHex", busSerialHex);
            writer.WriteString("currentSlot", currentSlot);
            writer.WriteString("slotControlSha256", slotControlSha256);
            writer.WriteStartArray("plan");
            foreach (var region in plan)
            {
                writer.WriteStartObject();
                writer.WriteString("role", region.Role);
                if (region.Slot is not null)
                {
                    writer.WriteString("slot", region.Slot);
                }
                else
                {
                    writer.WriteNull("slot");
                }

                writer.WriteNumber("lun", region.Lun);
                writer.WriteNumber("startSector", region.StartSector);
                writer.WriteNumber("sectorCount", region.SectorCount);
                writer.WriteNumber("length", region.Length);
                writer.WriteString("currentSha256", region.CurrentSha256);
                if (region.CandidateSha256 is not null)
                {
                    writer.WriteString("candidateSha256", region.CandidateSha256);
                }
                else
                {
                    writer.WriteNull("candidateSha256");
                }

                writer.WriteBoolean("willWrite", region.CandidatePath is not null);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Sha256Hex(buffer.ToArray());
    }

    private static string Sha256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
    }

    private static TfRollbackJournal OpenTfRollbackJournal(string journalPath)
    {
        if (string.IsNullOrWhiteSpace(journalPath))
            throw new ArgumentException("Rollback journal path is required.", nameof(journalPath));
        if (!Path.IsPathFullyQualified(journalPath))
            throw new ArgumentException("Rollback journal path must be absolute.", nameof(journalPath));

        var info = new FileInfo(journalPath);
        if (!info.Exists)
            throw new FileNotFoundException("Rollback journal not found.", journalPath);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Rollback journal must be a regular file, not a link or reparse point.");
        if (info.Length <= 0 || info.Length > TfRollbackJournalMaxBytes)
            throw new InvalidOperationException("Rollback journal size is outside the bounded limit.");
        if (!string.Equals(info.Name, TfRollbackJournalFileName, StringComparison.Ordinal))
            throw new InvalidOperationException("Rollback journal file name must be tf-rollback.json.");

        var stream = new FileStream(journalPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        try
        {
            if (stream.Length <= 0 || stream.Length > TfRollbackJournalMaxBytes)
                throw new InvalidOperationException("Rollback journal size is outside the bounded limit.");
            var bytes = new byte[checked((int)stream.Length)];
            ReadExactly(stream, bytes);
            var claim = new VerifiedEdlFile(journalPath, bytes.Length, Sha256Hex(bytes));
            var data = ParseTfRollbackJournal(bytes);
            ValidateTfRollbackJournal(data);
            return new TfRollbackJournal(stream, claim, data);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
                throw new EndOfStreamException("Unexpected end of rollback journal.");
            offset += read;
        }
    }

    private static TfRollbackJournalData ParseTfRollbackJournal(byte[] bytes)
    {
        RequireNoDuplicateJsonProperties(bytes);

        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8
        });

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Rollback journal root must be a JSON object.");

        var data = new TfRollbackJournalData
        {
            Schema = RequireJournalInt32(root, "schema"),
            Operation = RequireJournalString(root, "operation"),
            Nonce = RequireJournalString(root, "nonce"),
            ConfirmationSha256 = RequireJournalString(root, "confirmationSha256"),
            OriginalBackupDirectory = RequireJournalString(root, "originalBackupDirectory"),
            OriginalBackupManifestSha256 = RequireJournalString(root, "originalBackupManifestSha256"),
            ProfileId = RequireJournalString(root, "profileId"),
            Model = RequireJournalString(root, "model"),
            HardwareId = RequireJournalString(root, "hardwareId"),
            AndroidSerial = RequireJournalString(root, "androidSerial"),
            SocSerial = RequireJournalString(root, "socSerial"),
            CurrentSlot = RequireJournalString(root, "currentSlot")
        };

        foreach (var property in root.EnumerateObject())
        {
            switch (property.Name)
            {
                case "schema":
                case "operation":
                case "nonce":
                case "confirmationSha256":
                case "originalBackupDirectory":
                case "originalBackupManifestSha256":
                case "profileId":
                case "model":
                case "hardwareId":
                case "androidSerial":
                case "socSerial":
                case "currentSlot":
                    break;
                case "geometries":
                    foreach (var element in RequireJournalArray(property.Value))
                    {
                        data.Geometries.Add(new TfJournalGeometry(
                            RequireJournalInt32(element, "lun"),
                            RequireJournalInt32(element, "sectorSize"),
                            RequireJournalInt64(element, "totalSectors")));
                    }

                    break;
                case "originalCaptures":
                    foreach (var element in RequireJournalArray(property.Value))
                    {
                        data.Captures.Add(new TfJournalCapture(
                            RequireJournalString(element, "role"),
                            RequireJournalInt32(element, "lun"),
                            RequireJournalInt64(element, "startSector"),
                            RequireJournalInt64(element, "sectorCount"),
                            RequireJournalInt64(element, "length"),
                            RequireOptionalJournalString(element, "partUuid"),
                            RequireJournalString(element, "sha256")));
                    }

                    break;
                case "possibleWrites":
                    foreach (var element in RequireJournalArray(property.Value))
                    {
                        data.Writes.Add(new TfJournalWrite(
                            RequireJournalString(element, "role"),
                            RequireOptionalJournalString(element, "slot"),
                            RequireJournalString(element, "stagedCandidateSha256")));
                    }

                    break;
                default:
                    throw new InvalidOperationException($"Rollback journal contains an unknown property '{property.Name}'.");
            }
        }

        return data;
    }

    private static void RequireNoDuplicateJsonProperties(byte[] bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false
        });

        var scopes = new Stack<HashSet<string>?>();
        HashSet<string>? current = null;
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    scopes.Push(current);
                    current = new HashSet<string>(StringComparer.Ordinal);
                    break;
                case JsonTokenType.EndObject:
                    current = scopes.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    var name = reader.GetString();
                    if (name is null || !current!.Add(name))
                        throw new InvalidOperationException($"Rollback journal has a duplicate or invalid property '{name}'.");
                    break;
            }
        }

        if (reader.CurrentDepth != 0 || current is not null || scopes.Count != 0)
            throw new InvalidOperationException("Rollback journal is not a complete JSON document.");
    }

    private static JsonElement RequireJournalProperty(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out var value))
            throw new InvalidOperationException($"Rollback journal is missing required property '{name}'.");
        return value;
    }

    private static string RequireJournalString(JsonElement parent, string name)
    {
        var value = RequireJournalProperty(parent, name);
        var text = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        if (string.IsNullOrWhiteSpace(text))
            throw new InvalidOperationException($"Rollback journal property '{name}' must be a non-blank string.");
        return text!;
    }

    private static string? RequireOptionalJournalString(JsonElement parent, string name)
    {
        var value = RequireJournalProperty(parent, name);
        if (value.ValueKind == JsonValueKind.Null)
            return null;
        var text = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        if (string.IsNullOrWhiteSpace(text))
            throw new InvalidOperationException($"Rollback journal property '{name}' must be a non-blank string or null.");
        return text;
    }

    private static int RequireJournalInt32(JsonElement parent, string name)
    {
        var value = RequireJournalProperty(parent, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
            throw new InvalidOperationException($"Rollback journal property '{name}' must be an integer.");
        return number;
    }

    private static long RequireJournalInt64(JsonElement parent, string name)
    {
        var value = RequireJournalProperty(parent, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var number))
            throw new InvalidOperationException($"Rollback journal property '{name}' must be an integer.");
        return number;
    }

    private static JsonElement.ArrayEnumerator RequireJournalArray(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("Rollback journal array property must be an array.");
        return value.EnumerateArray();
    }

    private static void ValidateTfRollbackJournal(TfRollbackJournalData data)
    {
        if (data.Schema != 1)
            throw new InvalidOperationException("Rollback journal schema must be 1.");
        if (!string.Equals(data.Operation, "Temporary", StringComparison.Ordinal)
            && !string.Equals(data.Operation, "Final", StringComparison.Ordinal))
            throw new InvalidOperationException("Rollback journal operation must be \"Temporary\" or \"Final\".");
        if (!Guid.TryParseExact(data.Nonce, "N", out _))
            throw new InvalidOperationException("Rollback journal nonce must be a 32 hex digit GUID N value.");
        RequireJournalSha256(data.ConfirmationSha256, "confirmationSha256");
        RequireJournalSha256(data.OriginalBackupManifestSha256, "originalBackupManifestSha256");
        if (!Path.IsPathFullyQualified(data.OriginalBackupDirectory))
            throw new InvalidOperationException("Rollback journal originalBackupDirectory must be an absolute path.");
        if (data.CurrentSlot is not "a" and not "b")
            throw new InvalidOperationException("Rollback journal currentSlot must be \"a\" or \"b\".");
        if (string.IsNullOrWhiteSpace(data.ProfileId)
            || string.IsNullOrWhiteSpace(data.Model)
            || string.IsNullOrWhiteSpace(data.HardwareId)
            || string.IsNullOrWhiteSpace(data.AndroidSerial)
            || string.IsNullOrWhiteSpace(data.SocSerial))
            throw new InvalidOperationException("Rollback journal identity fields must be non-blank.");

        if (data.Geometries.Count != 6)
            throw new InvalidOperationException("Rollback journal must contain exactly six geometries.");
        var luns = new HashSet<int>();
        foreach (var geometry in data.Geometries)
        {
            if (geometry.Lun < 0 || geometry.Lun > 5 || !luns.Add(geometry.Lun))
                throw new InvalidOperationException("Rollback journal geometries must contain six unique LUNs 0..5.");
            if (geometry.SectorSize <= 0 || geometry.TotalSectors <= 0)
                throw new InvalidOperationException("Rollback journal geometry values must be positive.");
        }

        if (data.Captures.Count == 0 || data.Captures.Count > TfRollbackJournalMaxCaptures)
            throw new InvalidOperationException($"Rollback journal must contain between 1 and {TfRollbackJournalMaxCaptures} captures.");
        var captureRoles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capture in data.Captures)
        {
            if (string.IsNullOrWhiteSpace(capture.Role) || !captureRoles.Add(capture.Role))
                throw new InvalidOperationException("Rollback journal originalCaptures must have unique non-blank roles.");
            if (capture.Lun < 0 || capture.Lun > 5 || capture.StartSector < 0 || capture.SectorCount <= 0 || capture.Length <= 0)
                throw new InvalidOperationException($"Rollback journal capture '{capture.Role}' extents must be positive.");
            RequireJournalSha256(capture.Sha256, "sha256");
        }

        ValidateTfRollbackWrites(data);
    }

    private static void ValidateTfRollbackWrites(TfRollbackJournalData data)
    {
        var slot = data.CurrentSlot;
        if (data.Writes.Count == 0)
            throw new InvalidOperationException("Rollback journal must record at least the current boot write intent.");
        var isFinal = string.Equals(data.Operation, "Final", StringComparison.Ordinal);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var bootRole = string.Concat("boot_", slot);
        var sawBoot = false;
        foreach (var write in data.Writes)
        {
            if (string.IsNullOrWhiteSpace(write.Role) || !seen.Add(write.Role))
                throw new InvalidOperationException("Rollback journal possibleWrites must have unique non-blank roles.");

            var allowed = false;
            if (string.Equals(write.Role, TfEfiSpRole, StringComparison.Ordinal))
            {
                allowed = write.Slot is null;
            }
            else if (isFinal)
            {
                // Final journals record the union of the temporary active-slot
                // intents and the actually planned inactive/active writes: only
                // exact role_slot names across BOTH slots are permitted.
                foreach (var prefix in TfSlotWritePrefixes)
                {
                    if (!write.Role.StartsWith(prefix, StringComparison.Ordinal))
                        continue;
                    var suffix = write.Role.Substring(prefix.Length);
                    if (suffix is not "a" and not "b")
                        break;
                    allowed = string.Equals(write.Slot, suffix, StringComparison.Ordinal);
                    break;
                }
            }
            else
            {
                foreach (var prefix in TfSlotWritePrefixes)
                {
                    if (write.Role.StartsWith(prefix, StringComparison.Ordinal)
                        && string.Equals(write.Role.Substring(prefix.Length), slot, StringComparison.Ordinal))
                    {
                        allowed = string.Equals(write.Slot, slot, StringComparison.Ordinal);
                        break;
                    }
                }
            }

            if (!allowed)
                throw new InvalidOperationException($"Rollback journal write intent '{write.Role}' is outside the permitted rollback whitelist.");
            if (string.Equals(write.Role, bootRole, StringComparison.Ordinal))
                sawBoot = true;

            RequireJournalSha256(write.StagedCandidateSha256, "stagedCandidateSha256");

            if (!data.Captures.Any(c => string.Equals(c.Role, write.Role, StringComparison.Ordinal)))
                throw new InvalidOperationException($"Rollback journal write intent '{write.Role}' has no matching original capture.");
        }

        if (!sawBoot)
            throw new InvalidOperationException("Rollback journal must record the current boot write intent.");
    }

    private static void RequireJournalSha256(string value, string field)
    {
        if (value.Length != 64 || !IsHex64(value))
            throw new InvalidOperationException($"Rollback journal {field} must be a SHA-256 hex digest.");
    }

    private static bool IsHex64(string value)
    {
        foreach (var c in value)
        {
            if (c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private sealed class TfRollbackJournalData
    {
        public int Schema { get; set; }

        public string Operation { get; set; } = string.Empty;

        public string Nonce { get; set; } = string.Empty;

        public string ConfirmationSha256 { get; set; } = string.Empty;

        public string OriginalBackupDirectory { get; set; } = string.Empty;

        public string OriginalBackupManifestSha256 { get; set; } = string.Empty;

        public string ProfileId { get; set; } = string.Empty;

        public string Model { get; set; } = string.Empty;

        public string HardwareId { get; set; } = string.Empty;

        public string AndroidSerial { get; set; } = string.Empty;

        public string SocSerial { get; set; } = string.Empty;

        public string CurrentSlot { get; set; } = string.Empty;

        public List<TfJournalGeometry> Geometries { get; } = new();

        public List<TfJournalCapture> Captures { get; } = new();

        public List<TfJournalWrite> Writes { get; } = new();
    }

    private sealed record TfJournalGeometry(int Lun, int SectorSize, long TotalSectors);

    private sealed record TfJournalCapture(string Role, int Lun, long StartSector, long SectorCount, long Length, string? PartUuid, string Sha256);

    private sealed record TfJournalWrite(string Role, string? Slot, string StagedCandidateSha256);

    /// <summary>Held readonly journal lease plus its verified claim and parsed body.</summary>
    private sealed class TfRollbackJournal : IDisposable
    {
        public TfRollbackJournal(Stream lease, VerifiedEdlFile claim, TfRollbackJournalData data)
        {
            Lease = lease;
            Claim = claim;
            Data = data;
        }

        public Stream Lease { get; }

        public VerifiedEdlFile Claim { get; }

        public TfRollbackJournalData Data { get; }

        public void Dispose() => Lease.Dispose();
    }

    /// <summary>
    /// Private, fully validated return context shared by the restore-previous
    /// factory here and the later temporary-to-Final factory. Ownership stays
    /// private until <see cref="TransferOwnership"/> is called after the real
    /// backend construction succeeds. No public ready flag exists.
    /// </summary>
    private sealed class TfReturnContext : IDisposable
    {
        public TfReturnContext(
            MaintenanceDeviceFacts factOrigin,
            InternalBackupSet callerBackup,
            InternalBackupSet current,
            InternalBackupSet original,
            TfRollbackJournal journal,
            string evidenceDirectory,
            string evidenceNonce,
            BootSlotControlFacts slotFacts,
            List<IDisposable> leases)
        {
            FactOrigin = factOrigin;
            CallerBackup = callerBackup;
            Current = current;
            Original = original;
            Journal = journal;
            EvidenceDirectory = evidenceDirectory;
            EvidenceNonce = evidenceNonce;
            SlotFacts = slotFacts;
            Leases = leases;
        }

        public MaintenanceDeviceFacts FactOrigin { get; }

        public InternalBackupSet CallerBackup { get; }

        public InternalBackupSet Current { get; }

        public InternalBackupSet Original { get; }

        public TfRollbackJournal Journal { get; }

        public string EvidenceDirectory { get; }

        public string EvidenceNonce { get; }

        public BootSlotControlFacts SlotFacts { get; }

        public List<IDisposable> Leases { get; }

        private bool _ownershipTransferred;

        /// <summary>Relinquishes disposal after the real backend took ownership.</summary>
        public void TransferOwnership() => _ownershipTransferred = true;

        public void Dispose()
        {
            if (_ownershipTransferred)
            {
                return;
            }

            foreach (var lease in Leases)
            {
                try
                {
                    lease.Dispose();
                }
                catch
                {
                    // Keep closing the remaining owned resources.
                }
            }

            Current.Dispose();
            Original.Dispose();
        }
    }
}
