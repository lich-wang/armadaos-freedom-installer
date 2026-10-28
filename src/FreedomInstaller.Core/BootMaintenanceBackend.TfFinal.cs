using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public sealed partial class BootMaintenanceBackend
{
    /// <summary>
    /// Builds the FINAL A/B TF boot backend after a successful temporary RAM maintenance boot.
    /// Validates the original sealed final plan against the ORIGINAL source capture, then binds
    /// every actual destination to the NEW physical current capture of the fresh EDL session.
    /// Never creates or mutates a <see cref="TfBootPlan"/> and never labels the old source fresh.
    /// Application restarts or unknown/partial temporary outcomes must use RestorePrevious instead.
    /// </summary>
    public static async Task<TfBootBackend> CreateTfFinalFromEdlAsync(
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet freshBackup,
        TfBootBackend temporaryBackend,
        TfBootResult temporaryResult,
        TfBootPlan finalPlan,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // ---- Step 1: argument / temporary outcome validation, before any IO. ----
        if (history is null) throw new ArgumentNullException(nameof(history));
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (freshBackup is null) throw new ArgumentNullException(nameof(freshBackup));
        if (temporaryBackend is null) throw new ArgumentNullException(nameof(temporaryBackend));
        if (temporaryResult is null) throw new ArgumentNullException(nameof(temporaryResult));
        if (finalPlan is null) throw new ArgumentNullException(nameof(finalPlan));
        if (runner is null) throw new ArgumentNullException(nameof(runner));
        if (string.IsNullOrWhiteSpace(evidenceParent)) throw new ArgumentException("Evidence parent directory is required.", nameof(evidenceParent));
        cancellationToken.ThrowIfCancellationRequested();

        if (temporaryBackend.IsDisposed)
            throw new InvalidOperationException("tf-final: temporary backend is disposed; use RestorePrevious after an application restart.");
        var tempPrepared = temporaryBackend.Prepared ?? throw new InvalidOperationException("tf-final: temporary backend has no prepared facts.");
        if (tempPrepared.Operation != TfBootOperation.Temporary)
            throw new InvalidOperationException("tf-final: temporary backend operation must be Temporary.");
        if (tempPrepared.RawPurpose != TfBootPurpose.RamMaintenance)
            throw new InvalidOperationException("tf-final: temporary backend raw purpose must be RamMaintenance.");
        if (!temporaryBackend.OwnsResult(temporaryResult))
            throw new InvalidOperationException("tf-final: temporary result is not owned by the temporary backend.");
        if (temporaryResult.Operation != TfBootOperation.Temporary)
            throw new InvalidOperationException("tf-final: result operation must be Temporary.");
        if (temporaryResult.Outcome != BootMaintenanceOutcome.Completed)
            throw new InvalidOperationException("tf-final: temporary outcome must be Completed (write/readback/reset actually executed).");
        if (temporaryResult.WriteState != InternalInstallWriteState.AllVerified)
            throw new InvalidOperationException("tf-final: temporary write state must be AllVerified.");
        if (temporaryResult.ResetAccepted != true)
            throw new InvalidOperationException("tf-final: temporary reset was not accepted by the device.");
        if (!string.IsNullOrEmpty(temporaryResult.Error))
            throw new InvalidOperationException("tf-final: temporary result carries an error; use RestorePrevious.");
        if (temporaryResult.NeedsBootloaderAttention)
            throw new InvalidOperationException("tf-final: temporary result requires bootloader attention; use RestorePrevious.");

        var expectedRoles = tempPrepared.Regions
            .Where(r => r.WillWrite)
            .Select(r => r.Role)
            .ToHashSet(StringComparer.Ordinal);
        var verifiedSeen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in temporaryResult.VerifiedRegions)
        {
            if (!verifiedSeen.Add(role))
                throw new InvalidOperationException($"tf-final: verified region '{role}' reported more than once.");
        }
        if (!verifiedSeen.SetEquals(expectedRoles))
            throw new InvalidOperationException("tf-final: verified regions do not exactly equal the planned will-write regions.");

        if (!SamePath(temporaryResult.EvidenceDirectory, tempPrepared.EvidenceDirectory))
            throw new InvalidOperationException("tf-final: result evidence directory does not match the temporary prepared evidence directory.");

        // ---- Step 2: validate the sealed FINAL plan prepared from the ORIGINAL source. ----
        if (finalPlan.IsDisposed)
            throw new InvalidOperationException("tf-final: final plan is disposed.");
        if (finalPlan.Purpose != TfBootPurpose.FinalTf)
            throw new InvalidOperationException("tf-final: plan purpose must be FinalTf.");
        await finalPlan.RevalidateAsync(cancellationToken).ConfigureAwait(false);

        if (!string.Equals(finalPlan.Model, tempPrepared.Model, StringComparison.Ordinal))
            throw new InvalidOperationException("tf-final: final plan model differs from the temporary run.");
        if (!string.Equals(finalPlan.CurrentSlot, tempPrepared.CurrentSlot, StringComparison.Ordinal))
            throw new InvalidOperationException("tf-final: final plan current slot differs from the temporary run.");
        if (!string.Equals(finalPlan.PackageManifestFingerprint, tempPrepared.PackageManifestFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: final plan package fingerprint differs from the temporary run.");

        if (!SamePath(finalPlan.SourceBackupDirectory, tempPrepared.SourceBackupDirectory)
            || !string.Equals(finalPlan.SourceBackupManifestSha256, tempPrepared.SourceBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: final plan source backup does not match the temporary original source.");
        if (!SamePath(finalPlan.TargetBackupDirectory, tempPrepared.TargetBackupDirectory)
            || !string.Equals(finalPlan.TargetBackupManifestSha256, tempPrepared.TargetBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: final plan target backup does not match the temporary original target.");
        // The final plan was deliberately constructed before the RAM boot from the SAME original backup.
        if (!SamePath(finalPlan.SourceBackupDirectory, finalPlan.TargetBackupDirectory)
            || !string.Equals(finalPlan.SourceBackupManifestSha256, finalPlan.TargetBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: final plan source and target must originate from the same original backup.");

        // NOTE: cross-session fresh authority is proven by the shared return context; the plan's
        // binding reference is intentionally NOT compared against the new client binding.

        // ---- Step 3: open the shared Final return context from the persisted temporary journal. ----
        var journalPath = tempPrepared.RollbackJournalPath;
        if (string.IsNullOrWhiteSpace(journalPath))
            throw new InvalidOperationException("tf-final: temporary rollback journal path is missing.");
        var tempJournal = temporaryBackend.Journal ?? throw new InvalidOperationException("tf-final: temporary backend holds no journal file.");

        using var ctx = await OpenTfReturnContextAsync(
            history, client, freshBackup, journalPath, runner, evidenceParent,
            TfBootOperation.Final, progress, cancellationToken).ConfigureAwait(false);

        var claim = ctx.Journal.Claim;
        if (!SamePath(claim.Path, tempJournal.Path))
            throw new InvalidOperationException("tf-final: journal claim path differs from the temporary backend journal.");
        if (claim.Length != tempJournal.Length)
            throw new InvalidOperationException("tf-final: journal claim length differs from the temporary backend journal.");
        if (!string.Equals(claim.Sha256, tempJournal.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: journal claim sha256 differs from the temporary backend journal.");
        await RehashHeldFileAsync(tempJournal.Path, tempJournal.Length, tempJournal.Sha256, "tf-final: temporary journal", cancellationToken).ConfigureAwait(false);
        var journalSha = tempJournal.Sha256;

        var tempConfirmationId = tempPrepared.ConfirmationId;
        if (string.IsNullOrWhiteSpace(tempConfirmationId))
            throw new InvalidOperationException("tf-final: temporary confirmation id is missing.");
        if (!string.Equals(ctx.Journal.Data.ConfirmationSha256, tempConfirmationId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: journal confirmation does not match the temporary prepared confirmation id.");

        if (!SamePath(ctx.Journal.Data.OriginalBackupDirectory, finalPlan.SourceBackupDirectory)
            || !string.Equals(ctx.Journal.Data.OriginalBackupManifestSha256, finalPlan.SourceBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: journal original backup identity does not match the final plan.");
        if (!SamePath(ctx.Original.DirectoryPath, finalPlan.SourceBackupDirectory)
            || !string.Equals(ctx.Original.ManifestSha256, finalPlan.SourceBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: opened original source does not match the final plan.");
        if (!SamePath(ctx.Original.DirectoryPath, tempPrepared.SourceBackupDirectory)
            || !string.Equals(ctx.Original.ManifestSha256, tempPrepared.SourceBackupManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: opened original source does not match the temporary prepared source.");
        if (!SamePath(ctx.Current.DirectoryPath, freshBackup.DirectoryPath)
            || !string.Equals(ctx.Current.ManifestSha256, freshBackup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("tf-final: fresh current capture does not match the caller's fresh backup set.");

        var identity = ctx.FactOrigin.Identity.Identity;
        if (!string.Equals(identity.Model, tempPrepared.Model, StringComparison.Ordinal)
            || !string.Equals(identity.Serial, tempPrepared.AndroidSerial, StringComparison.Ordinal)
            || !string.Equals(ctx.FactOrigin.Identity.SocSerial, tempPrepared.SocSerial, StringComparison.Ordinal))
            throw new InvalidOperationException("tf-final: fresh session device identity differs from the temporary run.");

        // ---- Steps 4-9 with failure cleanup. ----
        List<string>? createdFiles = null;
        BootMaintenanceBackend? underlying = null;
        try
        {
            // ---- Step 4: rebuild source rows against the ORIGINAL capture, then bind to fresh current. ----
            var currentSlot = ctx.SlotFacts.CurrentSlot;
            if (!string.Equals(ctx.Journal.Data.CurrentSlot, currentSlot, StringComparison.Ordinal))
                throw new InvalidOperationException("tf-final: journal current slot differs from the fresh session current slot.");
            if (!string.Equals(currentSlot, tempPrepared.CurrentSlot, StringComparison.Ordinal))
                throw new InvalidOperationException("tf-final: fresh current slot differs from the temporary prepared slot.");
            var (sourceRows, _) = BuildTfRegionRows(finalPlan, ctx.Original, currentSlot, TfBootOperation.Final);
            var rows = new List<TfRegionPlan>(sourceRows.Count);
            foreach (var sourceRow in sourceRows)
            {
                var fresh = ctx.Current.Files[sourceRow.Role]
                    ?? throw new InvalidOperationException($"tf-final: fresh current capture is missing role '{sourceRow.Role}'.");
                RequireRegionMatchesGpt(ctx.Current, fresh, $"tf-final: fresh capture {sourceRow.Role}");
                var willWrite = !IsByteIdentical(sourceRow.Candidate, fresh);
                rows.Add(new TfRegionPlan(sourceRow.Role, sourceRow.Slot, fresh, sourceRow.Candidate, willWrite));
            }

            // ---- Step 5: journal-recorded roles omitted by the sealed plan (temporary EFI/AVB changes
            // whose desired bytes equal the ORIGINAL whole partition) must not be left behind. ----
            var rowRoles = rows.Select(r => r.Role).ToHashSet(StringComparer.Ordinal);
            foreach (var record in ctx.Journal.Data.Writes)
            {
                if (rowRoles.Contains(record.Role))
                    continue;
                if (!ctx.Original.Files.TryGetValue(record.Role, out var originalCapture) || originalCapture is null)
                    throw new InvalidOperationException($"tf-final: journal role '{record.Role}' has no original whole captured partition.");
                if (!ctx.Current.Files.TryGetValue(record.Role, out var freshCapture) || freshCapture is null)
                    throw new InvalidOperationException($"tf-final: journal role '{record.Role}' has no fresh current capture.");

                RequireRegionMatchesGpt(ctx.Original, originalCapture, $"tf-final: original whole partition {record.Role}");
                RequireRegionMatchesGpt(ctx.Current, freshCapture, $"tf-final: fresh capture {record.Role}");

                var candidate = new VerifiedEdlFile(originalCapture.FilePath, originalCapture.Length, originalCapture.Sha256);
                var willWrite = !IsByteIdentical(candidate, freshCapture);
                rows.Add(new TfRegionPlan(record.Role, record.Slot, freshCapture, candidate, willWrite));
                rowRoles.Add(record.Role);
            }

            // ---- Step 6: fixed logical order — EFI first, then INACTIVE slot, then CURRENT slot;
            // within a slot: boot, recovery, vbmeta_system, vbmeta. No misc/ABL/GPT/userdata writes. ----
            int RoleRank(string role)
            {
                var r = role.ToLowerInvariant();
                if (r.Contains("efi", StringComparison.Ordinal)) return 0;
                if (r.Contains("recovery", StringComparison.Ordinal)) return 2;
                if (r.Contains("vbmeta_system", StringComparison.Ordinal)) return 3;
                if (r.Contains("vbmeta", StringComparison.Ordinal)) return 4;
                if (r.Contains("boot", StringComparison.Ordinal)) return 1;
                return 5;
            }
            int SlotRank(TfRegionPlan r) => r.Slot is null
                ? 0
                : string.Equals(r.Slot, currentSlot, StringComparison.Ordinal) ? 2 : 1;

            var ordered = rows
                .OrderBy(SlotRank)
                .ThenBy(r => RoleRank(r.Role))
                .ThenBy(r => r.Role, StringComparer.Ordinal)
                .ToList();

            var roleSlotSeen = new HashSet<(string, string?)>();
            foreach (var row in ordered)
            {
                if (!roleSlotSeen.Add((row.Role, row.Slot)))
                    throw new InvalidOperationException($"tf-final: duplicate planned region role '{row.Role}' slot '{row.Slot}'.");
            }
            RequireNoLunOverlap(ordered);

            // ---- Step 7: stage every will-write candidate plus the verification report into evidence. ----
            createdFiles = new List<string>();
            var stagedIndex = 0;
            foreach (var row in ordered)
            {
                if (!row.WillWrite)
                    continue;
                cancellationToken.ThrowIfCancellationRequested();
                var destination = Path.Combine(ctx.EvidenceDirectory, $"tf-final-{stagedIndex:D2}-{SanitizeFileToken(row.Role)}.bin");
                createdFiles.Add(destination);
                var staged = await StageFileAsync(row.Candidate, destination, cancellationToken).ConfigureAwait(false);
                ctx.Leases.Add(staged.Lease);
                row.CandidatePath = staged.Path;
                row.CandidateSha256 = staged.Sha256;
                stagedIndex++;
            }

            var reportDestination = Path.Combine(ctx.EvidenceDirectory, "tf-final-verification-report.staged.json");
            createdFiles.Add(reportDestination);
            var stagedReport = await StageFileAsync(finalPlan.MenuPlan.VerificationReport, reportDestination, cancellationToken).ConfigureAwait(false);
            ctx.Leases.Add(stagedReport.Lease);

            // ---- Step 8: confirmation identity with a fresh nonce, bound to the temporary journal. ----
            var baseConfirmation = ComputeTfConfirmationSha256(
                ctx.EvidenceNonce, TfBootOperation.Final, finalPlan, ctx.FactOrigin,
                ctx.Current, ctx.Original, currentSlot, ctx.SlotFacts.ControlSha256, stagedReport.Sha256, ordered);
            var confirmationId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                string.Concat(baseConfirmation, ":", journalSha, ":", tempConfirmationId))))
                .ToLowerInvariant();

            // ---- Step 8a: persist the full original-bound recovery journal BEFORE any Final
            // write. The old temporary journal only covers the active-slot A intents; the Final
            // executor also writes inactive B/AVB/EFI rows, so recovery needs the UNION of the
            // recorded temporary intents and every actually planned will-write row, bound to
            // the ORIGINAL pre-RAM source. Durable (flushed + renamed) before the shared
            // executor performs its first shared write. ----
            var rowByRole = ordered.ToDictionary(r => r.Role, StringComparer.Ordinal);
            var unionRoles = new List<string>();
            var unionSeen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var record in ctx.Journal.Data.Writes)
            {
                if (unionSeen.Add(record.Role))
                    unionRoles.Add(record.Role);
            }
            foreach (var row in ordered)
            {
                if (row.WillWrite && unionSeen.Add(row.Role))
                    unionRoles.Add(row.Role);
            }
            foreach (var role in unionRoles)
            {
                if (!rowByRole.ContainsKey(role))
                    throw new InvalidOperationException($"tf-final: recovery union role '{role}' has no matching final region row.");
            }

            var rollbackJournalPath = Path.Combine(ctx.EvidenceDirectory, TfRollbackJournalFileName);
            createdFiles.Add(rollbackJournalPath);
            WriteReceipt(ctx.EvidenceDirectory, "tf-rollback", writer =>
            {
                writer.WriteNumber("schema", 1);
                writer.WriteString("operation", "Final");
                writer.WriteString("nonce", ctx.EvidenceNonce);
                writer.WriteString("confirmationSha256", confirmationId);
                writer.WriteString("originalBackupDirectory", ctx.Original.DirectoryPath);
                writer.WriteString("originalBackupManifestSha256", ctx.Original.ManifestSha256);
                writer.WriteString("profileId", ctx.Original.ProfileId);
                writer.WriteString("model", ctx.Original.Model);
                writer.WriteString("hardwareId", ctx.Original.HardwareId);
                writer.WriteString("androidSerial", ctx.FactOrigin.Identity.Identity.Serial);
                writer.WriteString("socSerial", ctx.FactOrigin.Identity.SocSerial);
                writer.WriteString("currentSlot", currentSlot);
                writer.WriteStartArray("geometries");
                foreach (var geometry in ctx.Original.Geometries.OrderBy(g => g.Key))
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("lun", geometry.Value.Lun);
                    writer.WriteNumber("sectorSize", geometry.Value.SectorSize);
                    writer.WriteNumber("totalSectors", geometry.Value.TotalSectors);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteStartArray("originalCaptures");
                foreach (var capture in ctx.Original.Files.OrderBy(f => f.Key, StringComparer.Ordinal))
                {
                    writer.WriteStartObject();
                    writer.WriteString("role", capture.Key);
                    writer.WriteNumber("lun", capture.Value.Lun);
                    writer.WriteNumber("startSector", capture.Value.StartSector);
                    writer.WriteNumber("sectorCount", capture.Value.SectorCount);
                    writer.WriteNumber("length", capture.Value.Length);
                    if (capture.Value.PartUuid is not null)
                    {
                        writer.WriteString("partUuid", capture.Value.PartUuid);
                    }
                    else
                    {
                        writer.WriteNull("partUuid");
                    }

                    writer.WriteString("sha256", capture.Value.Sha256);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteStartArray("possibleWrites");
                foreach (var role in unionRoles)
                {
                    var unionRow = rowByRole[role];
                    writer.WriteStartObject();
                    writer.WriteString("role", unionRow.Role);
                    if (unionRow.Slot is not null)
                    {
                        writer.WriteString("slot", unionRow.Slot);
                    }
                    else
                    {
                        writer.WriteNull("slot");
                    }

                    writer.WriteString("stagedCandidateSha256", unionRow.Candidate.Sha256);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            });

            // Reopen through the real bounded parser (schema/whitelist validated, full hash
            // claimed) and hold it readonly next to the old temporary journal, which is kept
            // untouched for provenance.
            var finalJournal = OpenTfRollbackJournal(rollbackJournalPath);
            ctx.Leases.Add(finalJournal);

            WriteReceipt(ctx.EvidenceDirectory, "tf-final-prepare", writer =>
            {
                writer.WriteString("kind", "tf-final-prepare");
                writer.WriteString("model", tempPrepared.Model);
                writer.WriteString("currentSlot", currentSlot);
                writer.WriteString("nonce", ctx.EvidenceNonce);
                writer.WriteString("packageManifestFingerprint", finalPlan.PackageManifestFingerprint);
                writer.WriteString("sourceBackupDirectory", finalPlan.SourceBackupDirectory);
                writer.WriteString("sourceBackupManifestSha256", finalPlan.SourceBackupManifestSha256);
                writer.WriteString("currentBackupDirectory", ctx.Current.DirectoryPath);
                writer.WriteString("currentBackupManifestSha256", ctx.Current.ManifestSha256);
                writer.WriteString("rollbackJournalPath", finalJournal.Claim.Path);
                writer.WriteString("rollbackJournalSha256", finalJournal.Claim.Sha256);
                writer.WriteString("journalSha256", journalSha);
                writer.WriteString("temporaryConfirmationId", tempConfirmationId);
                writer.WriteString("baseConfirmationSha256", baseConfirmation);
                writer.WriteString("finalConfirmationSha256", confirmationId);
                writer.WriteString("verificationReportSha256", stagedReport.Sha256);
                writer.WriteStartArray("regions");
                foreach (var row in ordered)
                {
                    writer.WriteStartObject();
                    writer.WriteString("role", row.Role);
                    if (row.Slot is not null) writer.WriteString("slot", row.Slot);
                    writer.WriteNumber("lun", row.Lun);
                    writer.WriteNumber("startSector", row.StartSector);
                    writer.WriteNumber("sectorCount", row.SectorCount);
                    writer.WriteNumber("length", row.Length);
                    writer.WriteString("currentSha256", row.CapturedSha256);
                    writer.WriteString("candidateSha256", row.CandidateSha256);
                    writer.WriteBoolean("willWrite", row.WillWrite);
                    if (row.CandidatePath is not null) writer.WriteString("candidatePath", row.CandidatePath);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            });

            // ---- Step 9: planned regions, slot summaries rebuilt from the fresh capture, then the
            // underlying engine (Normal policy) and the final backend wrapper. ----
            var plannedRegions = ordered
                .Select(r => new PlannedRegion(
                    r.Role, r.Slot, r.Lun, r.StartSector, r.SectorCount, r.Length,
                    r.CapturedSha256, r.CandidatePath, r.CandidateSha256))
                .ToList();

            var slotSummaries = new List<BootMaintenanceSlotSummary>();
            foreach (var slot in finalPlan.MenuPlan.Slots)
            {
                var candidate = slot.Candidate ?? throw new InvalidOperationException($"tf-final: menu slot '{slot.Slot}' has no candidate.");
                var row = ordered.FirstOrDefault(r => string.Equals(r.Role, "boot_" + slot.Slot, StringComparison.Ordinal))
                    ?? throw new InvalidOperationException($"tf-final: menu slot '{slot.Slot}' has no planned boot region.");
                slotSummaries.Add(new BootMaintenanceSlotSummary(
                    slot.Slot, slot.SourceSlot, slot.SourceKind,
                    row.CapturedSha256, candidate.Sha256, row.WillWrite));
            }

            var regionSummaries = ordered
                .Select(r => new BootMaintenanceRegionSummary(
                    r.Role, r.Slot, r.Lun, r.StartSector, r.SectorCount, r.Length,
                    r.CapturedSha256, r.CandidateSha256, r.WillWrite))
                .ToList();

            var prepared = new TfBootPrepared(
                TfBootOperation.Final, TfBootPurpose.FinalTf, confirmationId,
                tempPrepared.Model, tempPrepared.AndroidSerial, tempPrepared.SocSerial,
                currentSlot,
                finalPlan.SourceBackupDirectory, finalPlan.SourceBackupManifestSha256,
                ctx.Current.DirectoryPath, ctx.Current.ManifestSha256,
                ctx.EvidenceDirectory, finalPlan.PackageManifestFingerprint,
                finalJournal.Claim.Path, regionSummaries);

            underlying = new BootMaintenanceBackend(
                null, ctx.FactOrigin, ctx.SlotFacts.ControlSha256, client, runner,
                ctx.CallerBackup, ctx.Current, ctx.Original,
                plannedRegions, slotSummaries, currentSlot,
                ctx.EvidenceDirectory, confirmationId,
                null, ctx.Leases, RegionExecutionPolicy.Normal);

            var backend = new TfBootBackend(underlying, TfBootOperation.Final, prepared, ctx.Original, finalJournal.Claim);
            ctx.TransferOwnership();
            return backend;
        }
        catch
        {
            // ---- Step 10: dispose owned leases/backups (via underlying when it exists), then remove
            // only the files this factory created. Evidence directory and logs are retained.
            // Never dispose the caller's freshBackup, client, final plan, or temporary backend. ----
            if (underlying is not null)
            {
                try { underlying.Dispose(); } catch { /* best effort */ }
            }
            else
            {
                try { ctx.Dispose(); } catch { /* best effort */ }
            }
            if (createdFiles is not null)
            {
                foreach (var file in createdFiles)
                {
                    try { File.Delete(file); } catch { /* best effort */ }
                }
            }
            throw;
        }
    }

    private static string SanitizeFileToken(string role)
    {
        var builder = new StringBuilder(role.Length);
        foreach (var c in role)
            builder.Append(char.IsLetterOrDigit(c) ? c : '-');
        return builder.ToString();
    }
}
