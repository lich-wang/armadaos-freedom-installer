// U4a: private current-menu evidence preparation for the uninstall backend.
// The helper binds the verified original GPT backup (asset provenance), the fresh
// full rollback backup set and the already-prepared default-only boot menu into
// one durable, hash-checked evidence set inside the caller's backup directory.
// It reads and stages verified files only: no device I/O, no process command,
// no reset, no system write, and it never disposes the caller's backup or plan.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public sealed partial class EdlUninstallBackend
{
    // The only roles a current-menu write target may ever carry. This keeps
    // efisp source-only and keeps EFI/ABL from ever becoming write targets.
    private static readonly string[] CurrentMenuWritableRoles =
    {
        "boot_a",
        "boot_b",
        "vbmeta_a",
        "vbmeta_b",
        "vbmeta_system_a",
        "vbmeta_system_b",
    };

    private const int GptRangeSectorCount = 64;

    /// <summary>
    /// Binds the original verified GPT backup, the fresh rollback backup set and the
    /// prepared default-only boot menu into durable current-menu evidence. Every fact
    /// is re-verified here by hashing actual bytes; nothing is trusted on claim alone
    /// except the already-validated callers' models. Returns the evidence; all locks
    /// and pins are appended to the caller's lists and cleaned by the caller's
    /// existing try/catch.
    /// </summary>
    private static async Task<CurrentMenuEvidence> PrepareCurrentMenuAsync(
        EdlClient client,
        EdlEntryResult binding,
        UninstallGptAssets assets,
        InternalBackupSet currentBackup,
        CurrentBootMenuPlan menuPlan,
        string actualCurrentSlot,
        EdlUninstallCapture capture,
        string backupDirectory,
        List<FileStream> locks,
        List<PinnedFile> pinned,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(assets);
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(menuPlan);
        ArgumentNullException.ThrowIfNull(capture);
        ArgumentNullException.ThrowIfNull(backupDirectory);
        ArgumentNullException.ThrowIfNull(locks);
        ArgumentNullException.ThrowIfNull(pinned);
        token.ThrowIfCancellationRequested();

        if (!string.Equals(actualCurrentSlot, "a", StringComparison.Ordinal) &&
            !string.Equals(actualCurrentSlot, "b", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The reported current slot '" + actualCurrentSlot + "' is not exactly 'a' or 'b'.");
        }

        if (menuPlan.IsDisposed)
        {
            throw new InvalidOperationException("The current boot menu plan is already disposed.");
        }

        // -----------------------------------------------------------------
        // Provenance and binding facts
        // -----------------------------------------------------------------

        UninstallOriginalGptBackup original = assets.OriginalBackup
            ?? throw new InvalidOperationException(
                "The uninstall assets carry no verified original backup provenance; derive them with " +
                nameof(UninstallGptAssets.FromVerifiedBackup) + ".");

        if (!SamePath(assets.OriginalPrimaryGptPath, original.PrimaryGpt.FilePath) ||
            !SamePath(assets.OriginalBackupGptPath, original.BackupGpt.FilePath))
        {
            throw new InvalidOperationException(
                "The uninstall asset paths do not match the verified original backup provenance.");
        }

        if (!Equals(binding, client.Binding) ||
            !Equals(binding, original.Binding) ||
            !Equals(binding, currentBackup.Binding) ||
            !Equals(binding, menuPlan.Binding))
        {
            throw new InvalidOperationException(
                "The uninstall binding does not equal the client, original, current and menu bindings.");
        }

        if (!string.Equals(client.Toolchain.Model, currentBackup.Model, StringComparison.Ordinal) ||
            !string.Equals(client.Toolchain.HardwareId, currentBackup.HardwareId, StringComparison.Ordinal) ||
            !string.Equals(client.Toolchain.ProfileId, currentBackup.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The loaded toolchain identity does not match the current backup trusted facts.");
        }

        if (!string.Equals(original.Model, client.Toolchain.Model, StringComparison.Ordinal) ||
            !string.Equals(original.HardwareId, client.Toolchain.HardwareId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The original GPT backup model/hardware does not match the trusted toolchain.");
        }

        if (!string.Equals(menuPlan.BackupManifestSha256, currentBackup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The menu plan was prepared against a different backup manifest than the current backup set.");
        }

        // -----------------------------------------------------------------
        // Manifest and GPT claims, hashed against actual bytes and pinned
        // -----------------------------------------------------------------

        RequireHex64(original.ManifestSha256, "original manifest sha256");
        RequireHex64(currentBackup.ManifestSha256, "current manifest sha256");

        if (!string.Equals(HashFile(original.ManifestPath), original.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The original backup manifest does not hash to its recorded value.");
        }

        AddPinned(original.ManifestPath, "source:original-manifest", locks, pinned);

        VerifyRegionFile(original.PrimaryGpt, "original gpt_lun0_primary");
        AddPinned(original.PrimaryGpt.FilePath, "source:gpt_lun0_primary", locks, pinned);
        VerifyRegionFile(original.BackupGpt, "original gpt_lun0_backup");
        AddPinned(original.BackupGpt.FilePath, "source:gpt_lun0_backup", locks, pinned);

        if (!string.Equals(HashFile(currentBackup.ManifestPath), currentBackup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The current backup manifest does not hash to its recorded value.");
        }

        AddPinned(currentBackup.ManifestPath, "current:manifest", locks, pinned);

        // The role contract of the fresh backup set must be exactly the model's contract.
        var selected = InternalInstallBackupRoles.ForModel(currentBackup.Model)
            .ForCapturedRoles(currentBackup.Files.Keys);

        foreach (KeyValuePair<string, EdlCapturedRegion> entry in currentBackup.Files)
        {
            if (!string.Equals(entry.Value.Role, entry.Key, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The current captured role '" + entry.Key + "' carries a mismatching role claim '" +
                    entry.Value.Role + "'.");
            }

            if (entry.Value.Lun != selected.RoleLuns[entry.Key])
            {
                throw new InvalidOperationException(
                    "The current captured role '" + entry.Key + "' is captured from LUN" + entry.Value.Lun +
                    " instead of its contract LUN" + selected.RoleLuns[entry.Key] + ".");
            }

            VerifyRegionFile(entry.Value, "current " + entry.Key);
            AddPinned(entry.Value.FilePath, "current:" + entry.Key, locks, pinned);
        }

        // -----------------------------------------------------------------
        // Geometry, table and captured-range facts
        // -----------------------------------------------------------------

        for (int lun = 0; lun < 6; lun++)
        {
            if (!currentBackup.Geometries.TryGetValue(lun, out EdlGeometry? geometry))
            {
                throw new InvalidOperationException("The current backup is missing the LUN" + lun + " geometry.");
            }

            if (!currentBackup.Tables.ContainsKey(lun))
            {
                throw new InvalidOperationException("The current backup is missing the LUN" + lun + " table.");
            }

            if (!original.Geometries.TryGetValue(lun, out EdlGeometry? originalGeometry))
            {
                throw new InvalidOperationException("The original backup is missing the LUN" + lun + " geometry.");
            }

            CompareGeometry(originalGeometry, geometry, "LUN" + lun + " original versus current geometry");
        }

        EdlGeometry lun0Geometry = currentBackup.Geometries[0];

        CompareGeometry(currentBackup.Geometries[0], capture.Lun0Geometry, "LUN0 fresh capture geometry");
        CompareTable(currentBackup.Tables[0], capture.Lun0Table, "LUN0 fresh capture table");
        VerifyRegionMatches(RequireRegion(currentBackup, "gpt_lun0_primary"), capture.Regions["gpt_lun0_primary"], "gpt_lun0_primary");
        VerifyRegionMatches(RequireRegion(currentBackup, "gpt_lun0_backup"), capture.Regions["gpt_lun0_backup"], "gpt_lun0_backup");
        VerifyRegionMatches(RequireRegion(currentBackup, "misc"), capture.Regions["misc"], "misc");

        RequireGptRange(original.PrimaryGpt, original.Geometries[0], atEnd: false, "original gpt_lun0_primary");
        RequireGptRange(original.BackupGpt, original.Geometries[0], atEnd: true, "original gpt_lun0_backup");

        for (int lun = 0; lun < 6; lun++)
        {
            EdlGeometry geometry = currentBackup.Geometries[lun];
            string primaryRole = "gpt_lun" + lun + "_primary";
            string backupRole = "gpt_lun" + lun + "_backup";
            EdlCapturedRegion primaryRegion = RequireRegion(currentBackup, primaryRole);
            EdlCapturedRegion backupRegion = RequireRegion(currentBackup, backupRole);
            RequireGptRange(primaryRegion, geometry, atEnd: false, primaryRole);
            RequireGptRange(backupRegion, geometry, atEnd: true, backupRole);

            byte[] primaryBytes = await File.ReadAllBytesAsync(primaryRegion.FilePath, token).ConfigureAwait(false);
            byte[] backupBytes = await File.ReadAllBytesAsync(backupRegion.FilePath, token).ConfigureAwait(false);
            GptTable reparsed = OriginalGptImporter.Parse(
                primaryBytes,
                backupBytes,
                geometry.SectorSize,
                checked(geometry.TotalSectors * geometry.SectorSize));
            CompareTable(currentBackup.Tables[lun], reparsed, "current LUN" + lun + " GPT pair");
        }

        foreach (KeyValuePair<string, EdlCapturedRegion> entry in currentBackup.Files)
        {
            if (entry.Key.StartsWith("gpt_lun", StringComparison.Ordinal))
            {
                continue;
            }

            RequireCapturedPartition(currentBackup, entry.Key, entry.Value);
        }

        // Reparse the saved original LUN0 GPT pair from actual bytes and compare it
        // with the saved table; input facts only, no device read.
        long lun0SectorSize = lun0Geometry.SectorSize;
        long lun0DiskBytes = checked(lun0Geometry.TotalSectors * lun0SectorSize);
        byte[] originalPrimaryBytes = await File.ReadAllBytesAsync(original.PrimaryGpt.FilePath, token).ConfigureAwait(false);
        byte[] originalBackupBytes = await File.ReadAllBytesAsync(original.BackupGpt.FilePath, token).ConfigureAwait(false);
        GptTable reparsedOriginal = OriginalGptImporter.Parse(
            originalPrimaryBytes, originalBackupBytes, (int)lun0SectorSize, lun0DiskBytes);
        CompareTable(original.OriginalTable, reparsedOriginal, "reparsed original LUN0 GPT pair");

        // -----------------------------------------------------------------
        // The misc control partition: the sole active-slot authority
        // -----------------------------------------------------------------

        EdlCapturedRegion miscRegion = RequireRegion(currentBackup, "misc");
        var control = await BootSlotControl.ReadAsync(
            new VerifiedEdlFile(miscRegion.FilePath, miscRegion.Length, miscRegion.Sha256),
            token).ConfigureAwait(false);

        if (!string.Equals(control.CurrentSlot, actualCurrentSlot, StringComparison.Ordinal) ||
            !string.Equals(control.CurrentSlot, menuPlan.CurrentSlot, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The misc control slot '" + control.CurrentSlot +
                "' does not match the reported current slot '" + actualCurrentSlot +
                "' and the menu plan slot '" + menuPlan.CurrentSlot + "'.");
        }

        // -----------------------------------------------------------------
        // Slot facts, hashed, staged and kept as immutable evidence
        // -----------------------------------------------------------------

        string menuDirectory = Path.Combine(backupDirectory, "current-menu");
        if (Directory.Exists(menuDirectory))
        {
            throw new IOException("The current-menu directory '" + menuDirectory + "' already exists.");
        }

        Directory.CreateDirectory(menuDirectory);

        if (menuPlan.Slots.Count != 2 ||
            menuPlan.Slots.Count(slot => string.Equals(slot.Slot, "a", StringComparison.Ordinal)) != 1 ||
            menuPlan.Slots.Count(slot => string.Equals(slot.Slot, "b", StringComparison.Ordinal)) != 1)
        {
            throw new InvalidOperationException("The menu plan must hold exactly one slot 'a' and one slot 'b'.");
        }

        var slotFacts = new List<CurrentMenuSlotFacts>();
        var candidatesBySlot = new Dictionary<string, VerifiedEdlFile?>(StringComparer.Ordinal);
        long totalCandidateBytes = 0;

        foreach (CurrentBootMenuSlot slot in menuPlan.Slots)
        {
            token.ThrowIfCancellationRequested();

            if (!string.Equals(slot.SourceSlot, slot.Slot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The menu slot '" + slot.Slot + "' claims material from slot '" + slot.SourceSlot + "'.");
            }

            bool isActive = string.Equals(slot.Slot, actualCurrentSlot, StringComparison.Ordinal);
            if (isActive && slot.SourceKind == BootMaintenanceSourceKind.Empty)
            {
                throw new InvalidOperationException(
                    "The active slot '" + slot.Slot + "' cannot be an empty source slot.");
            }

            string bootRole = "boot_" + slot.Slot;
            EdlCapturedRegion bootRegion = RequireRegion(currentBackup, bootRole);

            if (slot.Original.Length != bootRegion.Length ||
                !string.Equals(slot.Original.Sha256, bootRegion.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The slot '" + slot.Slot + "' original boot claim does not match the fresh role '" +
                    bootRole + "'.");
            }

            if (!string.Equals(HashFile(slot.Original.Path), bootRegion.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The slot '" + slot.Slot + "' original boot file does not hash to its claim.");
            }

            VerifiedEdlFile? stagedCandidate = null;
            if (slot.Candidate is not null)
            {
                if (slot.SourceKind != BootMaintenanceSourceKind.Project)
                {
                    throw new InvalidOperationException(
                        "Only Project slots may carry a candidate; slot '" + slot.Slot + "' is '" +
                        slot.SourceKind + "'.");
                }

                StagedFile staged = Stage(
                    slot.Candidate.Path,
                    Path.Combine(menuDirectory, "current-menu-boot_" + slot.Slot + ".bin"),
                    "current-menu:boot_" + slot.Slot,
                    slot.Candidate.Length,
                    slot.Candidate.Sha256,
                    token);
                AddStaged(staged, locks, pinned);
                stagedCandidate = new VerifiedEdlFile(staged.Path, staged.Length, staged.Sha256);
                totalCandidateBytes = checked(totalCandidateBytes + staged.Length);
            }
            else if (slot.SourceKind == BootMaintenanceSourceKind.Empty)
            {
                RequireAllZeroBytes(bootRegion.FilePath, bootRegion.Length, bootRole, token);
            }

            var companionRoles = new List<string>();
            foreach (CurrentBootMenuCompanion companion in menuPlan.Companions)
            {
                if (string.Equals(companion.Slot, slot.Slot, StringComparison.Ordinal))
                {
                    companionRoles.Add(companion.Role);
                }
            }

            slotFacts.Add(new CurrentMenuSlotFacts(
                slot.Slot,
                slot.SourceSlot,
                slot.SourceKind.ToString(),
                slot.BootTrustMode.ToString(),
                new VerifiedEdlFile(bootRegion.FilePath, bootRegion.Length, bootRegion.Sha256),
                stagedCandidate,
                slot.PayloadSha256,
                slot.OriginalMetadataSha256,
                slot.PayloadDigestMatchesOem,
                companionRoles));
            candidatesBySlot[slot.Slot] = stagedCandidate;
        }

        // -----------------------------------------------------------------
        // Companion metadata candidates
        // -----------------------------------------------------------------

        var stagedCompanions = new List<(string Role, string Slot, VerifiedEdlFile Staged)>();
        var seenCompanionRoles = new HashSet<string>(StringComparer.Ordinal);

        foreach (CurrentBootMenuCompanion companion in menuPlan.Companions)
        {
            token.ThrowIfCancellationRequested();

            if (!CurrentMenuWritableRoles.Contains(companion.Role) ||
                string.Equals(companion.Role, "boot_a", StringComparison.Ordinal) ||
                string.Equals(companion.Role, "boot_b", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The companion role '" + companion.Role + "' is not a vbmeta metadata role.");
            }

            if (!companion.Role.EndsWith("_" + companion.Slot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The companion role '" + companion.Role + "' does not belong to slot '" +
                    companion.Slot + "'.");
            }

            if (!seenCompanionRoles.Add(companion.Role))
            {
                throw new InvalidOperationException(
                    "The companion role '" + companion.Role + "' appears more than once.");
            }

            CurrentMenuSlotFacts slotFact = slotFacts.Single(fact =>
                string.Equals(fact.Slot, companion.Slot, StringComparison.Ordinal));

            if (!string.Equals(slotFact.SourceKind, nameof(BootMaintenanceSourceKind.Project), StringComparison.Ordinal) ||
                slotFact.Candidate is null)
            {
                throw new InvalidOperationException(
                    "The companion '" + companion.Role + "' requires a Project slot with a boot candidate.");
            }

            if (string.Equals(slotFact.BootTrustMode, nameof(BootMaintenanceBootTrust.GblPreserveOem), StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "A GBL-preserve-OEM project slot cannot have metadata companions: '" +
                    companion.Role + "'.");
            }

            EdlCapturedRegion region = RequireRegion(currentBackup, companion.Role);

            if (companion.Original.Length != region.Length ||
                !string.Equals(companion.Original.Sha256, region.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The companion '" + companion.Role + "' original claim does not match the fresh role.");
            }

            if (!string.Equals(HashFile(companion.Original.Path), region.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The companion '" + companion.Role + "' original file does not hash to its claim.");
            }

            if (companion.Candidate.Length != companion.Original.Length)
            {
                throw new InvalidOperationException(
                    "The companion '" + companion.Role + "' candidate length differs from the complete partition.");
            }

            StagedFile staged = Stage(
                companion.Candidate.Path,
                Path.Combine(menuDirectory, "current-menu-" + companion.Role + ".bin"),
                "current-menu:" + companion.Role,
                companion.Candidate.Length,
                companion.Candidate.Sha256,
                token);
            AddStaged(staged, locks, pinned);
            totalCandidateBytes = checked(totalCandidateBytes + staged.Length);
            stagedCompanions.Add((companion.Role, companion.Slot,
                new VerifiedEdlFile(staged.Path, staged.Length, staged.Sha256)));
        }

        // -----------------------------------------------------------------
        // The verification report copy
        // -----------------------------------------------------------------

        StagedFile stagedReport = Stage(
            menuPlan.VerificationReport.Path,
            Path.Combine(menuDirectory, "current-menu-report.json"),
            "current-menu:report",
            menuPlan.VerificationReport.Length,
            menuPlan.VerificationReport.Sha256,
            token);
        AddStaged(stagedReport, locks, pinned);

        // -----------------------------------------------------------------
        // Write targets: extents only from the fresh files and tables
        // -----------------------------------------------------------------

        var writeTargets = new List<MenuWriteTarget>();
        string otherSlot = string.Equals(actualCurrentSlot, "a", StringComparison.Ordinal) ? "b" : "a";
        var orderedSlots = new List<string> { otherSlot, actualCurrentSlot };

        foreach (string slotId in orderedSlots)
        {
            token.ThrowIfCancellationRequested();

            if (candidatesBySlot[slotId] is VerifiedEdlFile bootCandidate)
            {
                AddWriteTarget(writeTargets, currentBackup, "boot_" + slotId, slotId, bootCandidate);
            }

            foreach (string metadataRole in new[] { "vbmeta_system_" + slotId, "vbmeta_" + slotId })
            {
                foreach ((string role, string _, VerifiedEdlFile staged) in stagedCompanions)
                {
                    if (string.Equals(role, metadataRole, StringComparison.Ordinal))
                    {
                        AddWriteTarget(writeTargets, currentBackup, role, slotId, staged);
                        break;
                    }
                }
            }
        }

        foreach (var byLun in writeTargets.GroupBy(target => target.Lun).OrderBy(group => group.Key))
        {
            MenuWriteTarget? previous = null;
            foreach (MenuWriteTarget target in byLun.OrderBy(target => target.StartSector))
            {
                if (previous is not null && target.StartSector < previous.StartSector + previous.SectorCount)
                {
                    throw new InvalidOperationException(
                        "Two current-menu write targets overlap on LUN" + target.Lun + ".");
                }

                previous = target;
            }
        }

        // -----------------------------------------------------------------
        // The durable plan.json manifest
        // -----------------------------------------------------------------

        string planJsonPath = Path.Combine(menuDirectory, "plan.json");
        WriteJson(planJsonPath, writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("kind", "uninstall-android-default");
            writer.WriteString("originalBackupDirectory", original.DirectoryPath);
            writer.WriteString("originalBackupManifestSha256", original.ManifestSha256);
            writer.WriteString("currentBackupDirectory", currentBackup.DirectoryPath);
            writer.WriteString("currentBackupManifestSha256", currentBackup.ManifestSha256);
            writer.WriteString("currentSlot", actualCurrentSlot);
            writer.WriteString("controlSha256", control.ControlSha256);
            writer.WriteNumber("controlCrc32", control.Crc32);

            writer.WriteStartArray("slots");
            foreach (CurrentMenuSlotFacts fact in slotFacts)
            {
                writer.WriteStartObject();
                writer.WriteString("slot", fact.Slot);
                writer.WriteString("sourceSlot", fact.SourceSlot);
                writer.WriteString("sourceKind", fact.SourceKind);
                writer.WriteString("bootTrustMode", fact.BootTrustMode);
                writer.WriteBoolean("noOp", fact.Candidate is null);
                writer.WriteBoolean("empty", fact.IsEmpty);

                writer.WriteStartObject("original");
                writer.WriteString("sha256", fact.Original.Sha256);
                writer.WriteNumber("lengthBytes", fact.Original.Length);
                writer.WriteEndObject();

                if (fact.Candidate is VerifiedEdlFile candidate)
                {
                    writer.WriteStartObject("candidate");
                    writer.WriteString("file", Path.GetFileName(candidate.Path));
                    writer.WriteString("sha256", candidate.Sha256);
                    writer.WriteNumber("lengthBytes", candidate.Length);
                    writer.WriteEndObject();
                }
                else
                {
                    writer.WriteNull("candidate");
                }

                writer.WriteStartObject("payloadSha256");
                foreach (KeyValuePair<string, string> payload in fact.PayloadSha256)
                {
                    writer.WriteString(payload.Key, payload.Value);
                }

                writer.WriteEndObject();

                if (fact.OriginalMetadataSha256 is string metadataSha256)
                {
                    writer.WriteString("originalMetadataSha256", metadataSha256);
                }
                else
                {
                    writer.WriteNull("originalMetadataSha256");
                }

                writer.WriteBoolean("payloadDigestMatchesOem", fact.PayloadDigestMatchesOem);
                writer.WriteStartArray("companionRoles");
                foreach (string companionRole in fact.CompanionRoles)
                {
                    writer.WriteStringValue(companionRole);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WriteStartArray("targets");
            foreach (MenuWriteTarget target in writeTargets)
            {
                writer.WriteStartObject();
                writer.WriteString("role", target.Role);
                writer.WriteString("slot", target.Slot);
                writer.WriteNumber("lun", target.Lun);
                writer.WriteNumber("sectorSize", target.SectorSize);
                writer.WriteString("partUuid", target.PartUuid);
                writer.WriteNumber("startLba", target.StartSector);
                writer.WriteNumber("countLba", target.SectorCount);
                writer.WriteNumber("lengthBytes", checked(target.SectorCount * target.SectorSize));
                writer.WriteString("originalSha256", target.OriginalSha256);

                writer.WriteStartObject("candidate");
                writer.WriteString("file", Path.GetFileName(target.Candidate.Path));
                writer.WriteString("sha256", target.Candidate.Sha256);
                writer.WriteNumber("lengthBytes", target.Candidate.Length);
                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WriteStartObject("verificationReport");
            writer.WriteString("file", Path.GetFileName(stagedReport.Path));
            writer.WriteString("sha256", stagedReport.Sha256);
            writer.WriteNumber("lengthBytes", stagedReport.Length);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }, token);
        AddPinned(planJsonPath, "asset:current-menu:plan", locks, pinned);

        PinnedFile manifestPin = pinned.Single(file => SamePath(file.Path, planJsonPath));

        return new CurrentMenuEvidence(
            manifestPin,
            actualCurrentSlot,
            original.DirectoryPath,
            currentBackup.DirectoryPath,
            new VerifiedEdlFile(stagedReport.Path, stagedReport.Length, stagedReport.Sha256),
            slotFacts,
            writeTargets,
            original.ManifestSha256,
            totalCandidateBytes,
            new ReadOnlyDictionary<int, EdlGeometry>(new Dictionary<int, EdlGeometry>(currentBackup.Geometries)),
            new ReadOnlyDictionary<string, EdlCapturedRegion>(new Dictionary<string, EdlCapturedRegion>(currentBackup.Files, StringComparer.Ordinal)));
    }

    // -----------------------------------------------------------------
    // Private current-menu helpers
    // -----------------------------------------------------------------

    private static EdlCapturedRegion RequireRegion(InternalBackupSet backup, string role)
    {
        if (!backup.Files.TryGetValue(role, out EdlCapturedRegion? region))
        {
            throw new InvalidOperationException(
                "The current backup is missing the captured role '" + role + "'.");
        }

        return region;
    }

    private static void VerifyRegionFile(EdlCapturedRegion region, string what)
    {
        RequireHex64(region.Sha256, what + " sha256");

        var info = new FileInfo(region.FilePath);
        if (!info.Exists || info.Length != region.Length)
        {
            throw new InvalidOperationException(
                "The " + what + " file '" + region.FilePath + "' is missing or does not hold the captured length.");
        }

        if (!string.Equals(HashFile(region.FilePath), region.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The " + what + " file does not hash to its captured claim.");
        }
    }

    private static void VerifyRegionMatches(EdlCapturedRegion current, EdlCapturedRegion fresh, string role)
    {
        if (!string.Equals(current.Role, fresh.Role, StringComparison.Ordinal) ||
            current.Length != fresh.Length ||
            !string.Equals(current.Sha256, fresh.Sha256, StringComparison.OrdinalIgnoreCase) ||
            current.Lun != fresh.Lun ||
            current.SectorSize != fresh.SectorSize ||
            !string.Equals(current.PartUuid, fresh.PartUuid, StringComparison.OrdinalIgnoreCase) ||
            checked((long)current.StartSector) != checked((long)fresh.StartSector) ||
            checked((long)current.SectorCount) != checked((long)fresh.SectorCount))
        {
            throw new InvalidOperationException(
                "The current captured role '" + role + "' does not match the fresh capture claim.");
        }
    }

    private static void RequireGptRange(EdlCapturedRegion region, EdlGeometry geometry, bool atEnd, string role)
    {
        if (region.Lun != geometry.Lun)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' must be captured from LUN" + geometry.Lun + ".");
        }

        if (region.SectorSize != geometry.SectorSize)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' sector size does not match its LUN geometry.");
        }

        if (region.PartUuid is not null)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' is a GPT range and must not carry a partition UUID.");
        }

        long sectorSize = geometry.SectorSize;
        if (checked((long)region.SectorCount) != GptRangeSectorCount)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' must cover exactly " + GptRangeSectorCount + " sectors.");
        }

        long expectedStart = atEnd ? geometry.TotalSectors - GptRangeSectorCount : 0;
        if (checked((long)region.StartSector) != expectedStart)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' must start at LBA " + expectedStart + ".");
        }

        if (region.Length != checked(GptRangeSectorCount * sectorSize))
        {
            throw new InvalidOperationException(
                "The role '" + role + "' byte length does not match the " + GptRangeSectorCount + "-sector range.");
        }
    }

    private static void RequireCapturedPartition(InternalBackupSet backup, string role, EdlCapturedRegion region)
    {
        (int lun, GptPartition partition) = RequireSinglePartition(backup, role);
        EdlGeometry geometry = backup.Geometries[lun];
        long sectorSize = geometry.SectorSize;
        long start = checked((long)partition.StartSector);
        long count = partition.SectorCount;

        if (region.Lun != lun ||
            region.SectorSize != geometry.SectorSize ||
            checked((long)region.StartSector) != start ||
            checked((long)region.SectorCount) != count)
        {
            throw new InvalidOperationException(
                "The captured role '" + role + "' extent does not match its LUN" + lun + " partition.");
        }

        if (!string.Equals(region.PartUuid, partition.PartUuid, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The captured role '" + role + "' partition UUID does not match its LUN" + lun + " partition.");
        }

        if (region.Length != checked(count * sectorSize))
        {
            throw new InvalidOperationException(
                "The captured role '" + role + "' length does not match its complete partition.");
        }
    }

    private static (int Lun, GptPartition Partition) RequireSinglePartition(
        InternalBackupSet backup, string role)
    {
        int foundLun = -1;
        GptPartition foundPartition = null!;

        foreach (KeyValuePair<int, GptTable> table in backup.Tables)
        {
            foreach (GptPartition partition in table.Value.Partitions)
            {
                if (!string.Equals(partition.Name, role, StringComparison.Ordinal))
                {
                    continue;
                }

                if (foundLun >= 0)
                {
                    throw new InvalidOperationException(
                        "The role '" + role + "' matches more than one partition across the six LUNs.");
                }

                foundLun = table.Key;
                foundPartition = partition;
            }
        }

        if (foundLun < 0)
        {
            throw new InvalidOperationException(
                "The role '" + role + "' has no same-name partition on any LUN table.");
        }

        return (foundLun, foundPartition);
    }

    private static void AddWriteTarget(
        List<MenuWriteTarget> targets,
        InternalBackupSet backup,
        string role,
        string slot,
        VerifiedEdlFile candidate)
    {
        if (!CurrentMenuWritableRoles.Contains(role))
        {
            throw new InvalidOperationException(
                "The role '" + role + "' is not an allowed current-menu write target.");
        }

        EdlCapturedRegion region = RequireRegion(backup, role);
        (int lun, GptPartition partition) = RequireSinglePartition(backup, role);
        EdlGeometry geometry = backup.Geometries[lun];
        long sectorSize = geometry.SectorSize;
        long start = checked((long)partition.StartSector);
        long count = partition.SectorCount;
        long lengthBytes = checked(count * sectorSize);

        if (lengthBytes != candidate.Length || lengthBytes != region.Length)
        {
            throw new InvalidOperationException(
                "The candidate for '" + role + "' does not cover the complete partition.");
        }

        targets.Add(new MenuWriteTarget(
            role,
            slot,
            backup.Geometries[lun],
            partition.PartUuid,
            start,
            count,
            region.Sha256,
            candidate));
    }

    private static void RequireAllZeroBytes(string path, long expectedLength, string role, CancellationToken token)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.SequentialScan);
        var buffer = new byte[FileBufferBytes];
        long total = 0;

        while (total < expectedLength)
        {
            token.ThrowIfCancellationRequested();

            int request = (int)Math.Min(buffer.Length, expectedLength - total);
            int read = stream.Read(buffer, 0, request);
            if (read <= 0)
            {
                throw new IOException(
                    "The '" + role + "' fresh boot ended after " + total + " of " + expectedLength + " bytes.");
            }

            for (int index = 0; index < read; index++)
            {
                if (buffer[index] != 0)
                {
                    throw new InvalidOperationException(
                        "The '" + role + "' fresh boot is not all-zero at byte " + (total + index) + ".");
                }
            }

            total += read;
        }
    }

    // -----------------------------------------------------------------
    // Private current-menu state
    // -----------------------------------------------------------------

    /// <summary>One durable write target with its fresh-table extent facts.</summary>
    private sealed class MenuWriteTarget
    {
        internal MenuWriteTarget(
            string role,
            string slot,
            EdlGeometry geometry,
            string partUuid,
            long startLba,
            long countLba,
            string originalSha256,
            VerifiedEdlFile candidate)
        {
            Role = role;
            Slot = slot;
            Geometry = geometry;
            PartUuid = partUuid;
            StartSector = startLba;
            SectorCount = countLba;
            OriginalSha256 = originalSha256;
            Candidate = candidate;
        }

        internal EdlGeometry Geometry { get; }

        internal string Role { get; }

        internal string Slot { get; }

        internal int Lun => Geometry.Lun;

        internal int SectorSize => Geometry.SectorSize;

        internal string PartUuid { get; }

        internal long StartSector { get; }

        internal long SectorCount { get; }

        internal string OriginalSha256 { get; }

        internal VerifiedEdlFile Candidate { get; }
    }

    /// <summary>Read-only factual metadata of one menu slot, kept in the evidence.</summary>
    private sealed class CurrentMenuSlotFacts
    {
        internal CurrentMenuSlotFacts(
            string slot,
            string sourceSlot,
            string sourceKind,
            string bootTrustMode,
            VerifiedEdlFile original,
            VerifiedEdlFile? candidate,
            IReadOnlyDictionary<string, string> payloadSha256,
            string? originalMetadataSha256,
            bool payloadDigestMatchesOem,
            IReadOnlyList<string> companionRoles)
        {
            Slot = slot;
            SourceSlot = sourceSlot;
            SourceKind = sourceKind;
            BootTrustMode = bootTrustMode;
            Original = original;
            Candidate = candidate;
            PayloadSha256 = new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(payloadSha256, StringComparer.Ordinal));
            OriginalMetadataSha256 = originalMetadataSha256;
            PayloadDigestMatchesOem = payloadDigestMatchesOem;
            IsEmpty = string.Equals(sourceKind, nameof(BootMaintenanceSourceKind.Empty), StringComparison.Ordinal);
            CompanionRoles = new ReadOnlyCollection<string>(new List<string>(companionRoles));
        }

        internal string Slot { get; }

        internal string SourceSlot { get; }

        internal string SourceKind { get; }

        internal string BootTrustMode { get; }

        internal VerifiedEdlFile Original { get; }

        internal VerifiedEdlFile? Candidate { get; }

        internal IReadOnlyDictionary<string, string> PayloadSha256 { get; }

        internal string? OriginalMetadataSha256 { get; }

        internal bool PayloadDigestMatchesOem { get; }

        internal bool IsEmpty { get; }

        internal IReadOnlyList<string> CompanionRoles { get; }
    }

    /// <summary>
    /// The verified current-menu evidence: the pinned plan.json manifest, per-slot
    /// read-only facts and the sorted write list. Holds no readiness or trust bool.
    /// </summary>
    private sealed class CurrentMenuEvidence
    {
        internal CurrentMenuEvidence(
            PinnedFile manifest,
            string currentSlot,
            string originalBackupDirectory,
            string currentBackupDirectory,
            VerifiedEdlFile report,
            IReadOnlyList<CurrentMenuSlotFacts> slots,
            IReadOnlyList<MenuWriteTarget> writeTargets,
            string sourceManifestSha256,
            long totalCandidateBytes,
            IReadOnlyDictionary<int, EdlGeometry> geometries,
            IReadOnlyDictionary<string, EdlCapturedRegion> sourceRegions)
        {
            Manifest = manifest;
            CurrentSlot = currentSlot;
            OriginalBackupDirectory = originalBackupDirectory;
            CurrentBackupDirectory = currentBackupDirectory;
            Report = report;
            Slots = new ReadOnlyCollection<CurrentMenuSlotFacts>(new List<CurrentMenuSlotFacts>(slots));
            WriteTargets = new ReadOnlyCollection<MenuWriteTarget>(new List<MenuWriteTarget>(writeTargets));
            SourceManifestSha256 = sourceManifestSha256;
            TotalCandidateBytes = totalCandidateBytes;
            Geometries = new ReadOnlyDictionary<int, EdlGeometry>(
                new Dictionary<int, EdlGeometry>(geometries));
            SourceRegions = new ReadOnlyDictionary<string, EdlCapturedRegion>(
                new Dictionary<string, EdlCapturedRegion>(sourceRegions, StringComparer.Ordinal));
        }

        internal PinnedFile Manifest { get; }

        internal string CurrentSlot { get; }

        internal string OriginalBackupDirectory { get; }

        internal string CurrentBackupDirectory { get; }

        internal VerifiedEdlFile Report { get; }

        internal IReadOnlyList<CurrentMenuSlotFacts> Slots { get; }

        internal IReadOnlyList<MenuWriteTarget> WriteTargets { get; }

        internal string SourceManifestSha256 { get; }

        internal long TotalCandidateBytes { get; }

        internal IReadOnlyDictionary<int, EdlGeometry> Geometries { get; }

        internal IReadOnlyDictionary<string, EdlCapturedRegion> SourceRegions { get; }
    }
}
