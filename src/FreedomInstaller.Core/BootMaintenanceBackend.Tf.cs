using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

public enum TfBootOperation
{
    Temporary,
    Final,
    RestorePrevious
}

public sealed class TfBootPrepared
{
    internal TfBootPrepared(
        TfBootOperation operation,
        TfBootPurpose? rawPurpose,
        string confirmationId,
        string model,
        string androidSerial,
        string socSerial,
        string currentSlot,
        string sourceBackupDirectory,
        string sourceBackupManifestSha256,
        string targetBackupDirectory,
        string targetBackupManifestSha256,
        string evidenceDirectory,
        string packageManifestFingerprint,
        string? rollbackJournalPath,
        IReadOnlyList<BootMaintenanceRegionSummary> regions)
    {
        Operation = operation;
        RawPurpose = rawPurpose;
        ConfirmationId = confirmationId;
        Model = model;
        AndroidSerial = androidSerial;
        SocSerial = socSerial;
        CurrentSlot = currentSlot;
        SourceBackupDirectory = sourceBackupDirectory;
        SourceBackupManifestSha256 = sourceBackupManifestSha256;
        TargetBackupDirectory = targetBackupDirectory;
        TargetBackupManifestSha256 = targetBackupManifestSha256;
        EvidenceDirectory = evidenceDirectory;
        PackageManifestFingerprint = packageManifestFingerprint;
        RollbackJournalPath = rollbackJournalPath;
        Regions = new ReadOnlyCollection<BootMaintenanceRegionSummary>(regions.ToArray());
    }

    public TfBootOperation Operation { get; }

    public TfBootPurpose? RawPurpose { get; }

    public string ConfirmationId { get; }

    public string Model { get; }

    public string AndroidSerial { get; }

    public string SocSerial { get; }

    public string CurrentSlot { get; }

    public string SourceBackupDirectory { get; }

    public string SourceBackupManifestSha256 { get; }

    public string TargetBackupDirectory { get; }

    public string TargetBackupManifestSha256 { get; }

    public string BackupDirectory => TargetBackupDirectory;

    public string EvidenceDirectory { get; }

    public string PackageManifestFingerprint { get; }

    public string? RollbackJournalPath { get; }

    public IReadOnlyList<BootMaintenanceRegionSummary> Regions { get; }
}

public sealed class TfBootResult
{
    internal TfBootResult(
        object ownerToken,
        TfBootOperation operation,
        BootMaintenanceOutcome outcome,
        InternalInstallWriteState writeState,
        IReadOnlyList<string> verifiedRegions,
        string evidenceDirectory,
        string? error,
        bool? resetAccepted,
        bool needsBootloaderAttention)
    {
        OwnerToken = ownerToken;
        Operation = operation;
        Outcome = outcome;
        WriteState = writeState;
        VerifiedRegions = new ReadOnlyCollection<string>(verifiedRegions.ToArray());
        EvidenceDirectory = evidenceDirectory;
        Error = error;
        ResetAccepted = resetAccepted;
        NeedsBootloaderAttention = needsBootloaderAttention;
    }

    internal object OwnerToken { get; }

    public TfBootOperation Operation { get; }

    public BootMaintenanceOutcome Outcome { get; }

    public InternalInstallWriteState WriteState { get; }

    public IReadOnlyList<string> VerifiedRegions { get; }

    public string EvidenceDirectory { get; }

    public string? Error { get; }

    public bool? ResetAccepted { get; }

    public bool NeedsBootloaderAttention { get; }
}

public sealed class TfBootBackend : IDisposable
{
    private readonly object _ownerToken;
    private readonly BootMaintenanceBackend _underlying;
    private readonly TfBootOperation _operation;
    private int _disposed;

    internal TfBootBackend(
        BootMaintenanceBackend underlying,
        TfBootOperation operation,
        TfBootPrepared prepared,
        InternalBackupSet? originalBackup,
        VerifiedEdlFile? journal)
    {
        _underlying = underlying ?? throw new ArgumentNullException(nameof(underlying));
        _operation = operation;
        _ownerToken = new object();
        Prepared = prepared ?? throw new ArgumentNullException(nameof(prepared));
        OriginalBackup = originalBackup;
        Journal = journal;
    }

    public TfBootPrepared Prepared { get; }

    public BootMaintenanceSnapshot Snapshot => _underlying.Snapshot;

    internal BootMaintenanceBackend Underlying => _underlying;

    internal InternalBackupSet? OriginalBackup { get; }

    internal VerifiedEdlFile? Journal { get; }

    internal bool OwnsResult(TfBootResult result)
    {
        return result is not null && ReferenceEquals(result.OwnerToken, _ownerToken);
    }

    internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public async Task<TfBootResult> ExecuteAsync(
        string confirmationId,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(confirmationId);
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TfBootBackend));
        }

        var result = await _underlying
            .ExecuteTfPlanAsync(confirmationId, progress, cancellationToken)
            .ConfigureAwait(false);
        return new TfBootResult(
            _ownerToken,
            _operation,
            result.Outcome,
            result.WriteState,
            result.VerifiedRegions,
            result.EvidenceDirectory,
            result.Error,
            _underlying.ObservedResetAccepted,
            _underlying.ObservedNeedsBootloaderAttention);
    }

    public void Dispose()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _underlying.Dispose();
        Volatile.Write(ref _disposed, 1);
    }
}

public sealed partial class BootMaintenanceBackend
{
    public static async Task<TfBootBackend> CreateTfPreparedAsync(
        InternalDeviceCheckResult deviceCheck,
        EdlClient client,
        InternalBackupSet currentBackup,
        TfBootPlan tfPlan,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceCheck);
        RequireCompleteDeviceCheck(deviceCheck);
        var facts = new MaintenanceDeviceFacts(deviceCheck.Android!, deviceCheck, null);
        return await CreateTfPreparedCoreAsync(
            facts,
            client,
            currentBackup,
            tfPlan,
            runner,
            evidenceParent,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<TfBootBackend> CreateTfPreparedFromEdlAsync(
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet currentBackup,
        TfBootPlan tfPlan,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(history);
        var facts = new MaintenanceDeviceFacts(history.Identity, null, history);
        return await CreateTfPreparedCoreAsync(
            facts,
            client,
            currentBackup,
            tfPlan,
            runner,
            evidenceParent,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<TfBootBackend> CreateTfPreparedCoreAsync(
        MaintenanceDeviceFacts facts,
        EdlClient client,
        InternalBackupSet callerBackup,
        TfBootPlan plan,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(callerBackup);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceParent);
        ObjectDisposedException.ThrowIf(plan.IsDisposed, plan);
        if (plan.Purpose is not (TfBootPurpose.FinalTf or TfBootPurpose.RamMaintenance))
        {
            throw new ArgumentException(
                $"Unknown {nameof(TfBootPurpose)} value '{plan.Purpose}'.",
                nameof(plan));
        }

        ct.ThrowIfCancellationRequested();

        await RequireDeviceFactsAsync(facts, client, ct).ConfigureAwait(false);
        RequireTrustedProfile(client);
        RequireCallerBackupBinding(client, callerBackup);

        if (!Directory.Exists(evidenceParent))
        {
            throw new DirectoryNotFoundException(
                $"Evidence parent directory '{evidenceParent}' does not exist.");
        }

        var operation = plan.Purpose == TfBootPurpose.FinalTf
            ? TfBootOperation.Final
            : TfBootOperation.Temporary;
        var nonce = Guid.NewGuid().ToString("N");
        var evidence = Path.Combine(evidenceParent, $"tf-boot-backend-{nonce}");
        if (Directory.Exists(evidence))
        {
            throw new InvalidOperationException($"Evidence directory '{evidence}' already exists.");
        }

        Directory.CreateDirectory(evidence);

        InternalBackupSet? openedCurrent = null;
        InternalBackupSet? openedSource = null;
        var leases = new List<IDisposable>();
        var createdFiles = new List<string>();
        try
        {
            openedCurrent = await InternalInstallBackup
                .OpenExistingAsync(client, callerBackup.DirectoryPath, null, ct)
                .ConfigureAwait(false);
            if (!string.Equals(
                    openedCurrent.ManifestSha256,
                    callerBackup.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Reopened current backup manifest does not match the caller backup manifest.");
            }

            RequireSameCapture(openedCurrent, callerBackup);

            await ProbeSixLunsAsync(client, openedCurrent, ct).ConfigureAwait(false);
            await ReadbackEveryCurrentRegionAsync(client, openedCurrent, evidence, progress, ct)
                .ConfigureAwait(false);

            var miscClaim = RegionClaim(openedCurrent.Files, "misc", "current misc control capture");
            var slotFacts = await BootSlotControl.ReadAsync(miscClaim, ct).ConfigureAwait(false);
            var vabFacts = await BootVirtualAbControl.ReadAsync(miscClaim, ct).ConfigureAwait(false);
            if (vabFacts.State != BootVirtualAbState.Completed || !vabFacts.IsFormatValid)
            {
                throw new InvalidDataException(
                    $"Virtual AB state '{vabFacts.State}' (format valid: {vabFacts.IsFormatValid}) is not Completed with a valid format; TF boot maintenance refuses to continue.");
            }

            var realSlot = slotFacts.CurrentSlot;
            if (facts.AndroidCheck is { } androidCheck)
            {
                var checkSlot = RequireCurrentSlot(androidCheck);
                if (!string.Equals(checkSlot, realSlot, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"Device check current slot '{checkSlot}' disagrees with the on-device slot control '{realSlot}'.");
                }
            }

            await plan.RevalidateAsync(ct).ConfigureAwait(false);

            var menuPlan = plan.MenuPlan;
            if (!string.Equals(plan.Model, openedCurrent.Model, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Plan model '{plan.Model}' does not match the reopened current backup model '{openedCurrent.Model}'.");
            }

            if (!string.Equals(plan.CurrentSlot, realSlot, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Plan current slot '{plan.CurrentSlot}' does not match the on-device slot '{realSlot}'.");
            }

            if (!ReferenceEquals(plan.TargetBackup.Binding, client.Binding))
            {
                throw new InvalidDataException("Plan target backup binding is not the connected device binding.");
            }

            if (!ReferenceEquals(plan.SourceBackup.Binding, client.Binding))
            {
                throw new InvalidDataException("Plan source backup binding is not the connected device binding.");
            }

            if (!SamePath(plan.TargetBackupDirectory, openedCurrent.DirectoryPath))
            {
                throw new InvalidDataException(
                    "Plan target backup directory does not match the reopened current backup directory.");
            }

            if (!string.Equals(
                    plan.TargetBackupManifestSha256,
                    openedCurrent.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Plan target backup manifest does not match the reopened current backup manifest.");
            }

            if (!ReferenceEquals(menuPlan.Binding, openedCurrent.Binding))
            {
                throw new InvalidDataException("Menu plan binding is not the reopened current backup binding instance.");
            }

            if (!string.Equals(
                    menuPlan.BackupManifestSha256,
                    openedCurrent.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Menu plan backup manifest does not match the reopened current backup manifest.");
            }

            if (!SamePath(plan.SourceBackupDirectory, plan.TargetBackupDirectory))
            {
                throw new InvalidOperationException(
                    $"tf-boot-transition-required: source backup '{plan.SourceBackupDirectory}' differs from target backup '{plan.TargetBackupDirectory}'; that path belongs to the separate return-to-EDL transition.");
            }

            if (!string.Equals(
                    plan.SourceBackupManifestSha256,
                    plan.TargetBackupManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Plan source and target backup manifests disagree on the initial pass.");
            }

            openedSource = await InternalInstallBackup
                .OpenBootMaintenanceProjectTemplateAsync(client, openedCurrent, plan.SourceBackupDirectory, ct)
                .ConfigureAwait(false);
            if (!string.Equals(
                    openedSource.ManifestSha256,
                    plan.SourceBackupManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "Reopened source backup manifest does not match the plan source manifest.");
            }

            var (rows, slotSummaries) = BuildTfRegionRows(plan, openedCurrent, realSlot, operation);

            var stagedByPath = new Dictionary<string, TfStagedFile>(StringComparer.OrdinalIgnoreCase);
            var stagedIndex = 0;
            foreach (var row in rows)
            {
                if (!row.WillWrite)
                {
                    continue;
                }

                if (stagedByPath.TryGetValue(row.Candidate.Path, out var existing))
                {
                    row.CandidatePath = existing.Path;
                    row.CandidateSha256 = existing.Sha256;
                    continue;
                }

                var destination = Path.Combine(
                    evidence,
                    $"{stagedIndex:D2}-{SafeFileName(row.Role)}-candidate.img");
                stagedIndex++;
                createdFiles.Add(destination);
                var stagedFile = await StageFileAsync(row.Candidate, destination, ct).ConfigureAwait(false);
                leases.Add(stagedFile.Lease);
                stagedByPath.Add(row.Candidate.Path, stagedFile);
                row.CandidatePath = destination;
                row.CandidateSha256 = stagedFile.Sha256;
            }

            var report = menuPlan.VerificationReport;
            var reportDestination = Path.Combine(evidence, "tf-menu-verification-report.json");
            createdFiles.Add(reportDestination);
            var stagedReport = await StageFileAsync(report, reportDestination, ct).ConfigureAwait(false);
            leases.Add(stagedReport.Lease);

            var confirmationSha = ComputeTfConfirmationSha256(
                nonce,
                operation,
                plan,
                facts,
                openedCurrent,
                openedSource,
                realSlot,
                slotFacts.ControlSha256,
                stagedReport.Sha256,
                rows);

            WriteReceipt(evidence, "tf-identity", w =>
            {
                w.WriteString("nonce", nonce);
                w.WriteString("operation", operation.ToString());
                w.WriteString("purpose", plan.Purpose.ToString());
                w.WriteString("deviceOrigin", facts.AndroidCheck is null ? "edl-history" : "android-check");
                w.WriteBoolean("currentFirmwareObserved", facts.AndroidCheck is not null);
                w.WriteString("model", facts.Identity.Identity.Model);
                w.WriteString("androidSerial", facts.Identity.Identity.Serial);
                w.WriteString("firmware", facts.Identity.Identity.Firmware?.DisplayId);
                w.WriteString("socSerial", facts.Identity.SocSerial);
                w.WriteString("profileId", openedCurrent.ProfileId);
                w.WriteString("hardwareId", openedCurrent.HardwareId);
                w.WriteString("currentSlot", realSlot);
                w.WriteString("miscControlSha256", slotFacts.ControlSha256);
            });

            WriteReceipt(evidence, "tf-prepare", w =>
            {
                w.WriteString("confirmationId", confirmationSha);
                w.WriteString("operation", operation.ToString());
                w.WriteString("nonce", nonce);
                w.WriteString("sourceBackupDirectory", openedSource.DirectoryPath);
                w.WriteString("sourceBackupManifestSha256", openedSource.ManifestSha256);
                w.WriteString("targetBackupDirectory", openedCurrent.DirectoryPath);
                w.WriteString("targetBackupManifestSha256", openedCurrent.ManifestSha256);
                w.WriteString("packageManifestFingerprint", plan.PackageManifestFingerprint);
                w.WriteString("stagedReportSha256", stagedReport.Sha256);
                w.WriteString("currentSlot", realSlot);
                w.WriteStartArray("regions");
                foreach (var row in rows)
                {
                    w.WriteStartObject();
                    w.WriteString("role", row.Role);
                    if (row.Slot is { } slot)
                    {
                        w.WriteString("slot", slot);
                    }
                    else
                    {
                        w.WriteNull("slot");
                    }

                    w.WriteBoolean("willWrite", row.WillWrite);
                    if (row.CandidatePath is { } candidatePath)
                    {
                        w.WriteString("candidatePath", candidatePath);
                    }
                    else
                    {
                        w.WriteNull("candidatePath");
                    }

                    w.WriteEndObject();
                }

                w.WriteEndArray();
            });

            string? journalPath = null;
            VerifiedEdlFile? journal = null;
            if (operation == TfBootOperation.Temporary)
            {
                journalPath = Path.Combine(evidence, "tf-rollback.json");
                createdFiles.Add(journalPath);
                WriteReceipt(evidence, "tf-rollback", w =>
                {
                    w.WriteNumber("schema", 1);
                    w.WriteString("operation", "Temporary");
                    w.WriteString("nonce", nonce);
                    w.WriteString("confirmationSha256", confirmationSha);
                    w.WriteString("originalBackupDirectory", openedCurrent.DirectoryPath);
                    w.WriteString("originalBackupManifestSha256", openedCurrent.ManifestSha256);
                    w.WriteString("profileId", openedCurrent.ProfileId);
                    w.WriteString("model", openedCurrent.Model);
                    w.WriteString("hardwareId", openedCurrent.HardwareId);
                    w.WriteString("androidSerial", facts.Identity.Identity.Serial);
                    w.WriteString("socSerial", facts.Identity.SocSerial);
                    w.WriteString("currentSlot", realSlot);
                    w.WriteStartArray("geometries");
                    foreach (var pair in openedCurrent.Geometries.OrderBy(pair => pair.Key))
                    {
                        w.WriteStartObject();
                        w.WriteNumber("lun", pair.Value.Lun);
                        w.WriteNumber("sectorSize", pair.Value.SectorSize);
                        w.WriteNumber("totalSectors", pair.Value.TotalSectors);
                        w.WriteEndObject();
                    }

                    w.WriteEndArray();
                    w.WriteStartArray("originalCaptures");
                    foreach (var capture in openedCurrent.Files.Values.OrderBy(capture => capture.Role, StringComparer.Ordinal))
                    {
                        w.WriteStartObject();
                        w.WriteString("role", capture.Role);
                        w.WriteNumber("lun", capture.Lun);
                        w.WriteNumber("startSector", capture.StartSector);
                        w.WriteNumber("sectorCount", capture.SectorCount);
                        w.WriteNumber("length", capture.Length);
                        if (capture.PartUuid is { } partUuid)
                        {
                            w.WriteString("partUuid", partUuid);
                        }
                        else
                        {
                            w.WriteNull("partUuid");
                        }

                        w.WriteString("sha256", capture.Sha256);
                        w.WriteEndObject();
                    }

                    w.WriteEndArray();
                    w.WriteStartArray("possibleWrites");
                    foreach (var row in rows.Where(row => row.WillWrite))
                    {
                        w.WriteStartObject();
                        w.WriteString("role", row.Role);
                        if (row.Slot is { } slot)
                        {
                            w.WriteString("slot", slot);
                        }
                        else
                        {
                            w.WriteNull("slot");
                        }

                        w.WriteString("stagedCandidateSha256", row.CandidateSha256!);
                        w.WriteEndObject();
                    }

                    w.WriteEndArray();
                });

                var journalLease = new FileStream(
                    journalPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    1 << 16,
                    FileOptions.Asynchronous);
                long journalLength;
                string journalSha;
                try
                {
                    journalLength = journalLease.Length;
                    journalSha = Convert.ToHexString(
                        await SHA256.HashDataAsync(journalLease, ct).ConfigureAwait(false));
                    journalLease.Seek(0, SeekOrigin.Begin);
                }
                catch
                {
                    journalLease.Dispose();
                    throw;
                }

                leases.Add(journalLease);
                journal = new VerifiedEdlFile(journalPath, journalLength, journalSha);
            }

            var plannedRegions = rows
                .Select(row => new PlannedRegion(
                    row.Role,
                    row.Slot,
                    row.Lun,
                    row.StartSector,
                    row.SectorCount,
                    row.Length,
                    row.CapturedSha256,
                    row.CandidatePath,
                    row.CandidateSha256))
                .ToList();

            var regionSummaries = rows
                .Select(row => new BootMaintenanceRegionSummary(
                    row.Role,
                    row.Slot,
                    row.Lun,
                    row.StartSector,
                    row.SectorCount,
                    row.Length,
                    row.CapturedSha256,
                    row.CandidateSha256,
                    row.WillWrite))
                .ToList();

            var prepared = new TfBootPrepared(
                operation,
                plan.Purpose,
                confirmationSha,
                plan.Model,
                facts.Identity.Identity.Serial,
                facts.Identity.SocSerial,
                realSlot,
                plan.SourceBackupDirectory,
                plan.SourceBackupManifestSha256,
                plan.TargetBackupDirectory,
                plan.TargetBackupManifestSha256,
                evidence,
                plan.PackageManifestFingerprint,
                journalPath,
                new ReadOnlyCollection<BootMaintenanceRegionSummary>(regionSummaries));

            var backend = new BootMaintenanceBackend(
                null,
                facts,
                slotFacts.ControlSha256,
                client,
                runner,
                callerBackup,
                openedCurrent,
                openedSource,
                plannedRegions,
                slotSummaries,
                realSlot,
                evidence,
                confirmationSha,
                null,
                leases);

            return new TfBootBackend(backend, operation, prepared, openedCurrent, journal);
        }
        catch
        {
            foreach (var lease in leases)
            {
                try
                {
                    lease.Dispose();
                }
                catch
                {
                    // Best-effort lease release; the evidence directory itself is retained.
                }
            }

            foreach (var createdFile in createdFiles)
            {
                try
                {
                    if (File.Exists(createdFile))
                    {
                        File.Delete(createdFile);
                    }
                }
                catch
                {
                    // Partial staged files are removed only when possible; evidence is never wiped.
                }
            }

            openedSource?.Dispose();
            openedCurrent?.Dispose();
            throw;
        }
    }

    private static (List<TfRegionPlan> Rows, List<BootMaintenanceSlotSummary> SlotSummaries) BuildTfRegionRows(
        TfBootPlan plan,
        InternalBackupSet openedCurrent,
        string realSlot,
        TfBootOperation operation)
    {
        var authority = plan.SourceAuthority;
        var menuPlan = plan.MenuPlan;
        var gbl = authority.UsesGbl;

        if (!string.Equals(authority.CurrentSlot, realSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Sealed source authority current slot '{authority.CurrentSlot}' does not match the on-device slot '{realSlot}'.");
        }

        var expectedSlots = operation == TfBootOperation.Final
            ? new[] { "a", "b" }
            : new[] { realSlot };
        var slotsByLetter = new Dictionary<string, CurrentBootMenuSlot>(StringComparer.Ordinal);
        foreach (var menuSlot in menuPlan.Slots)
        {
            var letter = menuSlot.Slot;
            if (letter is null || Array.IndexOf(expectedSlots, letter) < 0)
            {
                throw new InvalidDataException(
                    $"Menu plan slot '{letter ?? "<null>"}' is outside the selected {operation} slot set.");
            }

            if (!slotsByLetter.TryAdd(letter, menuSlot))
            {
                throw new InvalidDataException($"Menu plan contains duplicate slot '{letter}'.");
            }
        }

        foreach (var letter in expectedSlots)
        {
            if (!slotsByLetter.ContainsKey(letter))
            {
                throw new InvalidDataException($"Menu plan is missing selected slot '{letter}'.");
            }
        }

        foreach (var entry in slotsByLetter)
        {
            var letter = entry.Key;
            var menuSlot = entry.Value;
            if (!authority.SourceSlots.TryGetValue(letter, out var actualSource) ||
                !string.Equals(menuSlot.SourceSlot, actualSource, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Menu slot '{letter}' claims source '{menuSlot.SourceSlot}' but the sealed authority says '{(authority.SourceSlots.TryGetValue(letter, out var src) ? src : "<missing>")}'.");
            }
        }

        var companionsByRole = new Dictionary<string, CurrentBootMenuCompanion>(StringComparer.Ordinal);
        foreach (var companion in menuPlan.Companions)
        {
            if (!companionsByRole.TryAdd(companion.Role, companion))
            {
                throw new InvalidDataException($"Menu plan contains duplicate companion role '{companion.Role}'.");
            }
        }

        var allowedCompanionRoles = new HashSet<string>(StringComparer.Ordinal)
        {
            "recovery_a",
            "recovery_b",
            "vbmeta_system_a",
            "vbmeta_system_b",
            "vbmeta_a",
            "vbmeta_b",
            "efisp",
        };
        foreach (var role in companionsByRole.Keys)
        {
            if (!allowedCompanionRoles.Contains(role))
            {
                throw new InvalidDataException($"Companion role '{role}' is not in the sealed whitelist.");
            }
        }

        foreach (var entry in companionsByRole)
        {
            var role = entry.Key;
            var companion = entry.Value;
            if (role == "efisp")
            {
                continue;
            }

            var underscore = role.LastIndexOf('_');
            var slotLetter = role[(underscore + 1)..];
            if (Array.IndexOf(expectedSlots, slotLetter) < 0 ||
                !string.Equals(companion.Slot, slotLetter, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Companion '{role}' is tagged slot '{companion.Slot}' but belongs to no selected slot (selected: {string.Join(',', expectedSlots)}); unused-slot companions are refused.");
            }
        }

        var hasEfisp = companionsByRole.ContainsKey("efisp");
        if (gbl)
        {
            foreach (var provided in companionsByRole.Keys)
            {
                if (provided != "efisp")
                {
                    throw new InvalidDataException(
                        $"GBL mode must not carry AVB companion '{provided}'; real GBL has zero AVB metadata nodes.");
                }
            }

            if (authority.EfispTarget is null || authority.EfispCandidate is null)
            {
                throw new InvalidDataException(
                    "GBL mode requires the sealed authority to carry an efisp target/candidate.");
            }
        }
        else if (hasEfisp)
        {
            throw new InvalidDataException("AOSP mode must not carry an efisp companion.");
        }

        var rows = new List<TfRegionPlan>();
        var seenRoles = new HashSet<string>(StringComparer.Ordinal);

        if (gbl)
        {
            var captured = RequireRegion(openedCurrent.Files, "efisp", "current efisp capture");
            RequireCaptureMatchesCapture(authority.EfispTarget!, captured, "authority efisp target");
            RequireRegionMatchesGpt(openedCurrent, captured, "efisp");
            if (captured.Lun != 4)
            {
                throw new InvalidDataException(
                    $"Efisp capture is on LUN {captured.Lun}; efisp must be LUN 4.");
            }

            var needsEfiWrite = !IsByteIdentical(authority.EfispCandidate!, captured);
            if (authority.EfispCandidate!.Length != captured.Length)
            {
                throw new InvalidDataException(
                    $"Efisp candidate length {authority.EfispCandidate!.Length} does not match captured length {captured.Length}.");
            }

            if (hasEfisp)
            {
                var companion = companionsByRole["efisp"];
                RequireOriginalMatchesCapture(companion.Original, captured, "efisp companion original");
                var candidate = companion.Candidate
                    ?? throw new InvalidDataException("Efisp companion has no candidate image.");
                RequireCandidateMatchesClaim(candidate, authority.EfispCandidate!, "efisp companion candidate");
                if (!seenRoles.Add("efisp"))
                {
                    throw new InvalidDataException("Duplicate write role 'efisp'.");
                }

                rows.Add(new TfRegionPlan("efisp", null, captured, candidate, willWrite: needsEfiWrite));
            }
            else if (needsEfiWrite)
            {
                throw new InvalidDataException(
                    "GBL authority shows the efisp target differs from the fresh capture, but the sealed menu plan carries no efisp companion; refusing to skip a changed EFI region.");
            }
        }

        var orderedSlots = operation == TfBootOperation.Final
            ? string.Equals(realSlot, "a", StringComparison.Ordinal) ? new[] { "b", "a" } : new[] { "a", "b" }
            : new[] { realSlot };

        var expectedAvbNodes = new Dictionary<string, InternalInstallPreparationContext.DirectAvbMetadataNode>(StringComparer.Ordinal);
        if (!gbl)
        {
            foreach (var node in authority.AvbNodes)
            {
                if (Array.IndexOf(expectedSlots, node.Slot) < 0)
                {
                    continue;
                }

                if (node.Role != $"recovery_{node.Slot}" && node.Role != $"vbmeta_system_{node.Slot}" && node.Role != $"vbmeta_{node.Slot}")
                {
                    throw new InvalidDataException(
                        $"Authority AVB node for slot '{node.Slot}' has unexpected role '{node.Role}'.");
                }

                if (!expectedAvbNodes.TryAdd(node.Role, node))
                {
                    throw new InvalidDataException(
                        $"Authority carries duplicate AVB role '{node.Role}' within the selected slot set.");
                }
            }
        }

        var slotSummaries = new List<BootMaintenanceSlotSummary>();
        foreach (var letter in orderedSlots)
        {
            var menuSlot = slotsByLetter[letter];
            var slotRows = new List<TfRegionPlan>();

            var bootRole = $"boot_{letter}";
            var bootCaptured = RequireRegion(openedCurrent.Files, bootRole, $"current {bootRole} capture");
            RequireOriginalMatchesCapture(menuSlot.Original, bootCaptured, $"slot '{letter}' boot original");
            RequireRegionMatchesGpt(openedCurrent, bootCaptured, bootRole);
            var bootCandidate = menuSlot.Candidate
                ?? throw new InvalidDataException($"Slot '{letter}' has no candidate boot image.");
            if (bootCandidate.Length != bootCaptured.Length)
            {
                throw new InvalidDataException(
                    $"Slot '{letter}' candidate boot length {bootCandidate.Length} does not match captured length {bootCaptured.Length}.");
            }

            var bootRow = new TfRegionPlan(bootRole, letter, bootCaptured, bootCandidate, willWrite: true);
            slotRows.Add(bootRow);

            if (!gbl)
            {
                foreach (var nodeRole in new[] { "recovery", "vbmeta_system", "vbmeta" })
                {
                    if (!expectedAvbNodes.TryGetValue($"{nodeRole}_{letter}", out var node))
                    {
                        continue;
                    }

                    var role = $"{nodeRole}_{letter}";
                    var captured = RequireRegion(openedCurrent.Files, role, $"current {role} capture");
                    RequireOriginalMatchesCapture(node.Node.Original, captured, $"AVB node '{role}' original");
                    if (captured.Length != captured.SectorCount * captured.SectorSize)
                    {
                        throw new InvalidDataException(
                            $"AVB node '{role}': captured length {captured.Length} does not match the whole-region extent.");
                    }

                    RequireRegionMatchesGpt(openedCurrent, captured, role);
                    if (node.Node.Candidate.Length != captured.Length)
                    {
                        throw new InvalidDataException(
                            $"AVB node '{role}': candidate length {node.Node.Candidate.Length} does not match captured length {captured.Length}.");
                    }

                    var needsWrite = !IsByteIdentical(node.Node.Candidate, captured);
                    if (companionsByRole.TryGetValue(role, out var companion))
                    {
                        RequireOriginalMatchesCapture(companion.Original, captured, $"companion '{role}' original");
                        var candidate = companion.Candidate
                            ?? throw new InvalidDataException($"Companion '{role}' has no candidate image.");
                        RequireCandidateMatchesClaim(candidate, node.Node.Candidate, $"companion '{role}' candidate");
                        slotRows.Add(new TfRegionPlan(role, letter, captured, candidate, willWrite: needsWrite));
                    }
                    else if (needsWrite)
                    {
                        throw new InvalidDataException(
                            $"Authority shows AVB node '{role}' differs from the fresh capture, but the sealed menu plan carries no companion for it; refusing to skip a changed metadata region.");
                    }
                }

                foreach (var providedRole in companionsByRole.Keys)
                {
                    if (providedRole == "efisp")
                    {
                        continue;
                    }

                    var underscore = providedRole.LastIndexOf('_');
                    if (underscore <= 0)
                    {
                        throw new InvalidDataException(
                            $"Menu plan companion role '{providedRole}' is not a valid slot-suffixed AVB role.");
                    }

                    var providedBase = providedRole[..underscore];
                    if (providedBase is not ("recovery" or "vbmeta_system" or "vbmeta"))
                    {
                        throw new InvalidDataException(
                            $"Menu plan companion '{providedRole}' is not a valid AVB metadata role.");
                    }

                    if (Array.IndexOf(expectedSlots, providedRole[(underscore + 1)..]) >= 0 &&
                        !expectedAvbNodes.ContainsKey(providedRole))
                    {
                        throw new InvalidDataException(
                            $"Menu plan carries companion '{providedRole}' but the sealed authority proves no such AVB metadata node exists; arbitrary companions are refused.");
                    }
                }
            }

            foreach (var row in slotRows)
            {
                row.WillWrite = !IsByteIdentical(row.Candidate, row.Captured);
            }

            slotSummaries.Add(new BootMaintenanceSlotSummary(
                letter,
                menuSlot.SourceSlot,
                menuSlot.SourceKind,
                menuSlot.Original.Sha256,
                menuSlot.Candidate!.Sha256,
                bootRow.WillWrite));

            foreach (var row in slotRows)
            {
                if (!seenRoles.Add(row.Role))
                {
                    throw new InvalidDataException($"Duplicate write role '{row.Role}'.");
                }
            }

            rows.AddRange(slotRows);
        }

        RequireNoLunOverlap(rows);
        return (rows, slotSummaries);
    }

    private static string ComputeTfConfirmationSha256(
        string nonce,
        TfBootOperation operation,
        TfBootPlan plan,
        MaintenanceDeviceFacts facts,
        InternalBackupSet openedCurrent,
        InternalBackupSet openedSource,
        string currentSlot,
        string miscControlSha256,
        string stagedReportSha256,
        IReadOnlyList<TfRegionPlan> rows)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("nonce", nonce);
            writer.WriteString("operation", operation.ToString());
            writer.WriteString("purpose", plan.Purpose.ToString());
            writer.WriteString("model", plan.Model);
            writer.WriteString("androidSerial", facts.Identity.Identity.Serial);
            writer.WriteString("socSerial", facts.Identity.SocSerial);
            writer.WriteString("profileId", openedCurrent.ProfileId);
            writer.WriteString("hardwareId", openedCurrent.HardwareId);
            writer.WriteString("currentSlot", currentSlot);
            writer.WriteString("miscControlSha256", miscControlSha256);
            writer.WriteString("sourceManifestSha256", openedSource.ManifestSha256);
            writer.WriteString("targetManifestSha256", openedCurrent.ManifestSha256);
            writer.WriteString("packageManifestFingerprint", plan.PackageManifestFingerprint);
            writer.WriteString("stagedReportSha256", stagedReportSha256);
            writer.WriteStartArray("regions");
            foreach (var row in rows)
            {
                writer.WriteStartObject();
                writer.WriteString("role", row.Role);
                if (row.Slot is { } slot)
                {
                    writer.WriteString("slot", slot);
                }
                else
                {
                    writer.WriteNull("slot");
                }

                writer.WriteNumber("lun", row.Lun);
                writer.WriteNumber("startSector", row.StartSector);
                writer.WriteNumber("sectorCount", row.SectorCount);
                writer.WriteNumber("length", row.Length);
                if (row.PartUuid is { } partUuid)
                {
                    writer.WriteString("partUuid", partUuid);
                }
                else
                {
                    writer.WriteNull("partUuid");
                }

                writer.WriteString("originalSha256", row.CapturedSha256);
                if (row.CandidateSha256 is { } candidateSha)
                {
                    writer.WriteString("candidateSha256", candidateSha);
                }
                else
                {
                    writer.WriteNull("candidateSha256");
                }

                writer.WriteBoolean("willWrite", row.WillWrite);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Convert.ToHexString(SHA256.HashData(buffer.ToArray()));
    }

    private static async Task<TfStagedFile> StageFileAsync(VerifiedEdlFile claim, string destinationPath, CancellationToken ct)
    {
        await using (var source = new FileStream(
            claim.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1 << 20,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        await using (var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1 << 20,
            FileOptions.Asynchronous))
        {
            await source.CopyToAsync(destination, 1 << 20, ct).ConfigureAwait(false);
            await destination.FlushAsync(ct).ConfigureAwait(false);
            destination.Flush(true);
        }

        string sha256;
        await using (var verify = new FileStream(
            destinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1 << 20,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            if (verify.Length != claim.Length)
            {
                throw new InvalidDataException(
                    $"Staged file '{destinationPath}' length {verify.Length} does not match the claim {claim.Length}.");
            }

            sha256 = Convert.ToHexString(await SHA256.HashDataAsync(verify, ct).ConfigureAwait(false));
        }

        if (!string.Equals(sha256, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Staged file '{destinationPath}' SHA256 does not match the candidate claim.");
        }

        var lease = new FileStream(
            destinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1 << 16,
            FileOptions.Asynchronous);
        return new TfStagedFile(destinationPath, sha256, lease);
    }

    private static bool SamePath(string left, string right)
    {
        return string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    private static string SafeFileName(string role)
    {
        return string.Concat(role.Select(ch =>
            char.IsLetterOrDigit(ch) || ch == '_' || ch == '-' ? ch : '_'));
    }

    private static void RequireOriginalMatchesCapture(VerifiedEdlFile original, EdlCapturedRegion captured, string subject)
    {
        if (!SamePath(original.Path, captured.FilePath) ||
            original.Length != captured.Length ||
            !string.Equals(original.Sha256, captured.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"{subject} does not exactly match the freshly captured region '{captured.Role}'.");
        }
    }

    private static void RequireCaptureMatchesCapture(EdlCapturedRegion expected, EdlCapturedRegion actual, string subject)
    {
        if (!SamePath(expected.FilePath, actual.FilePath) ||
            expected.Lun != actual.Lun ||
            expected.StartSector != actual.StartSector ||
            expected.SectorCount != actual.SectorCount ||
            expected.SectorSize != actual.SectorSize ||
            expected.Length != actual.Length ||
            !string.Equals(expected.PartUuid, actual.PartUuid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Sha256, actual.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"{subject} does not match the freshly captured region '{actual.Role}'.");
        }
    }

    private static void RequireCandidateMatchesClaim(VerifiedEdlFile candidate, VerifiedEdlFile claim, string subject)
    {
        if (!SamePath(candidate.Path, claim.Path) ||
            candidate.Length != claim.Length ||
            !string.Equals(candidate.Sha256, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"{subject} does not match the sealed authority claim.");
        }
    }

    private static bool IsByteIdentical(VerifiedEdlFile candidate, EdlCapturedRegion captured)
    {
        return candidate.Length == captured.Length &&
            string.Equals(candidate.Sha256, captured.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireRegionMatchesGpt(InternalBackupSet openedCurrent, EdlCapturedRegion captured, string subject)
    {
        if (!openedCurrent.Geometries.TryGetValue(captured.Lun, out var geometry))
        {
            throw new InvalidDataException($"{subject}: no geometry captured for LUN {captured.Lun}.");
        }

        if (captured.SectorSize != geometry.SectorSize)
        {
            throw new InvalidDataException(
                $"{subject}: sector size {captured.SectorSize} does not match LUN {captured.Lun} geometry {geometry.SectorSize}.");
        }

        if (captured.Length != captured.SectorCount * captured.SectorSize)
        {
            throw new InvalidDataException(
                $"{subject}: length {captured.Length} does not match the captured extent on LUN {captured.Lun}.");
        }

        if (!openedCurrent.Tables.TryGetValue(captured.Lun, out var table))
        {
            throw new InvalidDataException($"{subject}: no GPT captured for LUN {captured.Lun}.");
        }

        if (string.IsNullOrEmpty(captured.PartUuid))
        {
            throw new InvalidDataException(
                $"{subject}: captured region has no PARTUUID; name-only targeting is refused.");
        }

        var matches = new List<GptPartition>();
        foreach (var partition in table.Partitions)
        {
            if (string.Equals(partition.PartUuid, captured.PartUuid, StringComparison.OrdinalIgnoreCase))
            {
                matches.Add(partition);
            }
        }

        if (matches.Count != 1)
        {
            throw new InvalidDataException(
                $"{subject}: PARTUUID '{captured.PartUuid}' matched {matches.Count} partitions on LUN {captured.Lun}; exactly one is required.");
        }

        var target = matches[0];
        if (!string.Equals(target.Name, captured.Role, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"{subject}: partition name '{target.Name}' does not match captured role '{captured.Role}'.");
        }

        if (target.StartSector != captured.StartSector || target.SectorCount != captured.SectorCount)
        {
            throw new InvalidDataException(
                $"{subject}: partition extent does not match the captured region extent.");
        }
    }

    private static void RequireNoLunOverlap(IReadOnlyList<TfRegionPlan> rows)
    {
        foreach (var group in rows.GroupBy(row => row.Lun).OrderBy(group => group.Key))
        {
            var ordered = group.OrderBy(row => row.StartSector).ToList();
            for (var index = 1; index < ordered.Count; index++)
            {
                var previous = ordered[index - 1];
                var current = ordered[index];
                if (current.StartSector < previous.StartSector + previous.SectorCount)
                {
                    throw new InvalidDataException(
                        $"Regions '{previous.Role}' and '{current.Role}' overlap on LUN {group.Key}.");
                }
            }
        }
    }

    private sealed class TfRegionPlan
    {
        public TfRegionPlan(
            string role,
            string? slot,
            EdlCapturedRegion captured,
            VerifiedEdlFile candidate,
            bool willWrite)
        {
            Role = role;
            Slot = slot;
            Captured = captured;
            Candidate = candidate;
            WillWrite = willWrite;
        }

        public string Role { get; }

        public string? Slot { get; }

        public EdlCapturedRegion Captured { get; }

        public VerifiedEdlFile Candidate { get; }

        public bool WillWrite { get; set; }

        public string? CandidatePath { get; set; }

        public string? CandidateSha256 { get; set; }

        public int Lun => Captured.Lun;

        public long StartSector => Captured.StartSector;

        public long SectorCount => Captured.SectorCount;

        public long Length => Captured.Length;

        public string CapturedSha256 => Captured.Sha256;

        public string? PartUuid => Captured.PartUuid;
    }

    private sealed class TfStagedFile : IDisposable
    {
        public TfStagedFile(string path, string sha256, FileStream lease)
        {
            Path = path;
            Sha256 = sha256;
            Lease = lease;
        }

        public string Path { get; }

        public string Sha256 { get; }

        public FileStream Lease { get; }

        public void Dispose() => Lease.Dispose();
    }
}
