using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace FreedomInstaller.Core;

/// <summary>How the boot candidates of a maintenance pass are trusted.</summary>
public enum BootMaintenanceBootTrust
{
    /// <summary>The untouched stock/original boot image is used as-is.</summary>
    StockOriginal,

    /// <summary>Project boot candidates and their AVB metadata are re-signed with the fixed AOSP key.</summary>
    AospResigned,

    /// <summary>Project boot candidates keep the original OEM-signed AVB metadata and rely on the verified GBL runtime.</summary>
    GblPreserveOem,
}

/// <summary>What one slot's boot image is taken from.</summary>
public enum BootMaintenanceSourceKind
{
    /// <summary>No source image exists for this slot; nothing can be written from it.</summary>
    Empty,

    /// <summary>The slot is prepared from its stock/original boot image.</summary>
    StockOriginal,

    /// <summary>The slot is prepared from a project boot candidate.</summary>
    Project,
}

/// <summary>
/// Outcome of one boot-maintenance pass.
/// <para>
/// <see cref="Completed"/> means every issued write was read back byte for byte and the normal reset was
/// accepted. It never means that an operating system accepted or booted the image.
/// </para>
/// </summary>
public enum BootMaintenanceOutcome
{
    /// <summary>All issued writes carry a full readback and the reset was accepted; OS acceptance is still pending.</summary>
    Completed,

    /// <summary>The pass failed with a known result.</summary>
    Failed,

    /// <summary>The pass was cancelled while its writes were still provable.</summary>
    Cancelled,

    /// <summary>At least one issued write or reset cannot be proven either way.</summary>
    UnknownWriteOutcome,
}

/// <summary>
/// Caller-supplied inputs for a prepare/repair/restore pass.
/// <para>
/// These values are claims and paths to be validated by the backend, never authority: holding one proves
/// nothing about the files, the package or the device. There is deliberately no valid/ready flag.
/// </para>
/// </summary>
/// <param name="ProjectBackupDirectory">
/// Optional absolute path of the pre-update PROJECT menu template backup. It is distinct from
/// <paramref name="OriginalBackupDirectory"/> (the stock original) and from the fresh current rollback
/// backup, and it is never treated as an OEM source or as readiness evidence.
/// </param>
public sealed record BootMaintenanceSources(
    string? OriginalBackupDirectory = null,
    ImportedPackage? RepairPackage = null,
    EdlRawBootTools? BootTools = null,
    string? ProjectBackupDirectory = null);

/// <summary>
/// Immutable facts about one A/B slot of a prepared boot-maintenance pass.
/// <para>
/// <see cref="Slot"/> is the target slot and <see cref="SourceSlot"/> is the slot the source image was taken
/// from; both are exactly <c>a</c> or <c>b</c>. The constructor rejects malformed facts but never grants
/// readiness - only the backend's evidence decides whether a slot may be written.
/// </para>
/// </summary>
public sealed class BootMaintenanceSlotSummary
{
    internal BootMaintenanceSlotSummary(
        string slot,
        string sourceSlot,
        BootMaintenanceSourceKind sourceKind,
        string originalSha256,
        string? candidateSha256,
        bool willWrite)
    {
        RequireSlot(slot, nameof(slot));
        RequireSlot(sourceSlot, nameof(sourceSlot));

        if (!Enum.IsDefined(sourceKind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(sourceKind), sourceKind, "The boot-maintenance source kind is not a known value.");
        }

        ArgumentNullException.ThrowIfNull(originalSha256);

        if (sourceKind == BootMaintenanceSourceKind.Empty)
        {
            if (originalSha256.Length != 0)
            {
                throw new ArgumentException(
                    "An empty source slot carries no original boot SHA-256.", nameof(originalSha256));
            }

            if (candidateSha256 is not null)
            {
                throw new ArgumentException(
                    "An empty source slot cannot carry a candidate boot SHA-256.", nameof(candidateSha256));
            }

            if (willWrite)
            {
                throw new ArgumentException(
                    "An empty source slot has no image to write.", nameof(willWrite));
            }
        }
        else if (string.IsNullOrWhiteSpace(originalSha256))
        {
            throw new ArgumentException(
                "A non-empty source slot requires an original boot SHA-256.", nameof(originalSha256));
        }

        if (candidateSha256 is not null && string.IsNullOrWhiteSpace(candidateSha256))
        {
            throw new ArgumentException(
                "A candidate boot SHA-256 must be a non-empty value when present.", nameof(candidateSha256));
        }

        if (sourceKind == BootMaintenanceSourceKind.Project && candidateSha256 is null)
        {
            throw new ArgumentException(
                "A project source slot requires a candidate boot SHA-256.", nameof(candidateSha256));
        }

        Slot = slot;
        SourceSlot = sourceSlot;
        SourceKind = sourceKind;
        OriginalSha256 = originalSha256;
        CandidateSha256 = candidateSha256;
        WillWrite = willWrite;
    }

    /// <summary>Target slot, exactly <c>a</c> or <c>b</c>.</summary>
    public string Slot { get; }

    /// <summary>Slot the source image was taken from, exactly <c>a</c> or <c>b</c>.</summary>
    public string SourceSlot { get; }

    /// <summary>What the slot's image is taken from.</summary>
    public BootMaintenanceSourceKind SourceKind { get; }

    /// <summary>SHA-256 of the original boot image, empty only for an empty source slot.</summary>
    public string OriginalSha256 { get; }

    /// <summary>SHA-256 of the prepared candidate, or null when nothing was prepared.</summary>
    public string? CandidateSha256 { get; }

    /// <summary>Whether the backend intends to write this slot; it is not evidence that a write happened.</summary>
    public bool WillWrite { get; }

    private static void RequireSlot(string? value, string name)
    {
        if (!string.Equals(value, "a", StringComparison.Ordinal) &&
            !string.Equals(value, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("A boot-maintenance slot must be exactly 'a' or 'b'.", name);
        }
    }
}

/// <summary>
/// Immutable facts about one raw region of a prepared boot-maintenance pass.
/// <para>
/// The geometry is the validated target geometry; an unknown target is never represented as a zero-size
/// region. The constructor rejects unusable geometry and malformed hashes but grants no readiness.
/// </para>
/// </summary>
public sealed class BootMaintenanceRegionSummary
{
    internal BootMaintenanceRegionSummary(
        string role,
        string? slot,
        int lun,
        long startSector,
        long sectorCount,
        long length,
        string originalSha256,
        string? candidateSha256,
        bool willWrite)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("A boot-maintenance region requires a role.", nameof(role));
        }

        if (slot is not null && !IsSlot(slot))
        {
            throw new ArgumentException("A region slot must be exactly 'a' or 'b' when present.", nameof(slot));
        }

        if (lun < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(lun), lun, "A region LUN cannot be negative.");
        }

        if (startSector < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(startSector), startSector, "A region cannot start before sector zero.");
        }

        if (sectorCount <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(sectorCount), sectorCount, "A region must cover at least one sector.");
        }

        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length), length, "A region must have a positive byte length.");
        }

        if (string.IsNullOrWhiteSpace(originalSha256))
        {
            throw new ArgumentException(
                "A region requires an original SHA-256.", nameof(originalSha256));
        }

        if (candidateSha256 is not null && string.IsNullOrWhiteSpace(candidateSha256))
        {
            throw new ArgumentException(
                "A candidate SHA-256 must be a non-empty value when present.", nameof(candidateSha256));
        }

        Role = role;
        Slot = slot;
        Lun = lun;
        StartSector = startSector;
        SectorCount = sectorCount;
        Length = length;
        OriginalSha256 = originalSha256;
        CandidateSha256 = candidateSha256;
        WillWrite = willWrite;
    }

    /// <summary>Contract role of the region.</summary>
    public string Role { get; }

    /// <summary>Slot the region belongs to, or null when the region is not slot scoped.</summary>
    public string? Slot { get; }

    /// <summary>LUN that holds the region.</summary>
    public int Lun { get; }

    /// <summary>First sector of the region.</summary>
    public long StartSector { get; }

    /// <summary>Number of sectors the region covers.</summary>
    public long SectorCount { get; }

    /// <summary>Byte length of the region.</summary>
    public long Length { get; }

    /// <summary>SHA-256 of the original region bytes.</summary>
    public string OriginalSha256 { get; }

    /// <summary>SHA-256 of the prepared candidate bytes, or null when nothing was prepared.</summary>
    public string? CandidateSha256 { get; }

    /// <summary>Whether the backend intends to write this region; it is not evidence that a write happened.</summary>
    public bool WillWrite { get; }

    private static bool IsSlot(string value) =>
        string.Equals(value, "a", StringComparison.Ordinal) ||
        string.Equals(value, "b", StringComparison.Ordinal);
}

/// <summary>
/// Immutable preparation result of a boot-maintenance pass: the confirmed mode, the device facts it was
/// prepared for, and the slot/region facts the UI displays.
/// <para>
/// Every value is retained exactly as the backend established it. The constructor copies both collections into
/// read-only storage, so a caller cannot add, remove or reorder what was confirmed. It does not require active
/// slot A, a particular slot order, or both slots to be present - the backend owns that evidence.
/// </para>
/// <para>
/// There is no public constructor and no setter, and no bool that a caller can set to declare the data ready.
/// </para>
/// </summary>
public sealed class BootMaintenancePrepared
{
    internal BootMaintenancePrepared(
        MaintenanceMode mode,
        string confirmationId,
        string model,
        string androidSerial,
        string socSerial,
        string currentSlot,
        string backupDirectory,
        string evidenceDirectory,
        BootMaintenanceBootTrust bootTrustMode,
        IReadOnlyList<BootMaintenanceSlotSummary> slots,
        IReadOnlyList<BootMaintenanceRegionSummary> regions)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "The maintenance mode is not a known value.");
        }

        if (!Enum.IsDefined(bootTrustMode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(bootTrustMode), bootTrustMode, "The boot trust mode is not a known value.");
        }

        RequireText(confirmationId, nameof(confirmationId));
        RequireText(model, nameof(model));
        RequireText(androidSerial, nameof(androidSerial));
        RequireText(socSerial, nameof(socSerial));
        RequireText(backupDirectory, nameof(backupDirectory));
        RequireText(evidenceDirectory, nameof(evidenceDirectory));

        if (!string.Equals(currentSlot, "a", StringComparison.Ordinal) &&
            !string.Equals(currentSlot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("The current slot must be exactly 'a' or 'b'.", nameof(currentSlot));
        }

        Mode = mode;
        ConfirmationId = confirmationId;
        Model = model;
        AndroidSerial = androidSerial;
        SocSerial = socSerial;
        CurrentSlot = currentSlot;
        BackupDirectory = backupDirectory;
        EvidenceDirectory = evidenceDirectory;
        BootTrustMode = bootTrustMode;
        Slots = Copy(slots, nameof(slots));
        Regions = Copy(regions, nameof(regions));
    }

    /// <summary>The maintenance pass this preparation belongs to.</summary>
    public MaintenanceMode Mode { get; }

    /// <summary>Canonical confirmation the user accepted.</summary>
    public string ConfirmationId { get; }

    /// <summary>Device model the preparation was made for.</summary>
    public string Model { get; }

    /// <summary>Android serial observed on the device.</summary>
    public string AndroidSerial { get; }

    /// <summary>SoC serial observed on the device.</summary>
    public string SocSerial { get; }

    /// <summary>The observed current slot, exactly <c>a</c> or <c>b</c>.</summary>
    public string CurrentSlot { get; }

    /// <summary>Absolute path of the backup directory that was used.</summary>
    public string BackupDirectory { get; }

    /// <summary>Absolute path of the evidence directory this pass writes receipts to.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>How the prepared boot candidates are trusted.</summary>
    public BootMaintenanceBootTrust BootTrustMode { get; }

    /// <summary>Per-slot facts, in the backend's own order; read-only and never caller reorderable.</summary>
    public IReadOnlyList<BootMaintenanceSlotSummary> Slots { get; }

    /// <summary>Per-region facts, in the backend's own order; read-only and never caller reorderable.</summary>
    public IReadOnlyList<BootMaintenanceRegionSummary> Regions { get; }

    private static void RequireText(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A prepared boot-maintenance fact cannot be empty.", name);
        }
    }

    private static ReadOnlyCollection<T> Copy<T>(IReadOnlyList<T> items, string name)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(items, name);

        var copy = new List<T>(items.Count);
        foreach (var item in items)
        {
            if (item is null)
            {
                throw new ArgumentException("The collection cannot contain null entries.", name);
            }

            copy.Add(item);
        }

        return new ReadOnlyCollection<T>(copy);
    }
}

/// <summary>
/// Immutable point-in-time view of a boot-maintenance run.
/// <para>
/// <see cref="Outcome"/> is null while the run is still going. The values are observations, not authority:
/// the write state still says how much of the issued work a readback actually proved.
/// </para>
/// </summary>
public sealed class BootMaintenanceSnapshot
{
    internal BootMaintenanceSnapshot(
        bool executionStarted,
        InternalInstallStage stage,
        InternalInstallWriteState writeState,
        BootMaintenanceOutcome? outcome,
        string? error)
    {
        if (!Enum.IsDefined(stage))
        {
            throw new ArgumentOutOfRangeException(nameof(stage), stage, "The install stage is not a known value.");
        }

        if (!Enum.IsDefined(writeState))
        {
            throw new ArgumentOutOfRangeException(
                nameof(writeState), writeState, "The write state is not a known value.");
        }

        if (outcome is not null && !Enum.IsDefined(outcome.Value))
        {
            throw new ArgumentOutOfRangeException(
                nameof(outcome), outcome, "The boot-maintenance outcome is not a known value.");
        }

        ExecutionStarted = executionStarted;
        Stage = stage;
        WriteState = writeState;
        Outcome = outcome;
        Error = error;
    }

    /// <summary>True once the first write-intent step has begun.</summary>
    public bool ExecutionStarted { get; }

    /// <summary>The stage currently reached.</summary>
    public InternalInstallStage Stage { get; }

    /// <summary>How much of the issued write work is proven by readback.</summary>
    public InternalInstallWriteState WriteState { get; }

    /// <summary>The final outcome once the run ended, or null while it is still running.</summary>
    public BootMaintenanceOutcome? Outcome { get; }

    /// <summary>The reported error, or null when none was reported.</summary>
    public string? Error { get; }
}

/// <summary>
/// Immutable final result of one boot-maintenance pass.
/// <para>
/// <see cref="AwaitingAndroidAcceptance"/> is true only on a <see cref="BootMaintenanceOutcome.Completed"/>
/// pass: it states that Android has not confirmed the new boot, never that it did. A completed pass requires
/// <see cref="InternalInstallWriteState.AllVerified"/>; an
/// <see cref="BootMaintenanceOutcome.UnknownWriteOutcome"/> pass requires
/// <see cref="InternalInstallWriteState.Unknown"/>.
/// </para>
/// <para>
/// The verified region list is copied into read-only storage, so the caller cannot add evidence it did not see.
/// </para>
/// </summary>
public sealed class BootMaintenanceResult
{
    internal BootMaintenanceResult(
        BootMaintenanceOutcome outcome,
        InternalInstallWriteState writeState,
        IReadOnlyList<string> verifiedRegions,
        string evidenceDirectory,
        string? error,
        bool awaitingAndroidAcceptance)
    {
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(
                nameof(outcome), outcome, "The boot-maintenance outcome is not a known value.");
        }

        if (!Enum.IsDefined(writeState))
        {
            throw new ArgumentOutOfRangeException(
                nameof(writeState), writeState, "The write state is not a known value.");
        }

        RequireText(evidenceDirectory, nameof(evidenceDirectory));

        if (outcome == BootMaintenanceOutcome.Completed &&
            writeState != InternalInstallWriteState.AllVerified)
        {
            throw new ArgumentException(
                "A completed boot-maintenance result requires every issued write to be read back and verified.",
                nameof(writeState));
        }

        if (outcome == BootMaintenanceOutcome.UnknownWriteOutcome &&
            writeState != InternalInstallWriteState.Unknown)
        {
            throw new ArgumentException(
                "An unknown write outcome requires the unknown write state.",
                nameof(writeState));
        }

        var completed = outcome == BootMaintenanceOutcome.Completed;
        if (awaitingAndroidAcceptance != completed)
        {
            throw new ArgumentException(
                "Only a completed boot-maintenance result may await Android acceptance.",
                nameof(awaitingAndroidAcceptance));
        }

        Outcome = outcome;
        WriteState = writeState;
        VerifiedRegions = Copy(verifiedRegions, nameof(verifiedRegions));
        EvidenceDirectory = evidenceDirectory;
        Error = error;
        AwaitingAndroidAcceptance = awaitingAndroidAcceptance;
    }

    /// <summary>The overall outcome of the pass.</summary>
    public BootMaintenanceOutcome Outcome { get; }

    /// <summary>How much of the issued write work is proven by readback.</summary>
    public InternalInstallWriteState WriteState { get; }

    /// <summary>The regions actually verified, in the order they were verified.</summary>
    public IReadOnlyList<string> VerifiedRegions { get; }

    /// <summary>Absolute path of the evidence directory of this pass.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>The reported error, or null when none was reported.</summary>
    public string? Error { get; }

    /// <summary>
    /// True only when the pass completed its issued writes and the reset was accepted, and Android still has to
    /// accept the new boot. It is never a claim that Android accepted or booted anything.
    /// </summary>
    public bool AwaitingAndroidAcceptance { get; }

    private static void RequireText(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("The evidence directory cannot be empty.", name);
        }
    }

    private static ReadOnlyCollection<string> Copy(IReadOnlyList<string> regions, string name)
    {
        ArgumentNullException.ThrowIfNull(regions, name);

        var copy = new List<string>(regions.Count);
        foreach (var region in regions)
        {
            if (string.IsNullOrWhiteSpace(region))
            {
                throw new ArgumentException("A verified region must be a non-empty value.", name);
            }

            copy.Add(region);
        }

        return new ReadOnlyCollection<string>(copy);
    }
}
