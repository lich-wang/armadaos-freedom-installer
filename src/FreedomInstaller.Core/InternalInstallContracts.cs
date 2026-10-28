using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace FreedomInstaller.Core;

/// <summary>
/// Stable stage identity of the one internal install. The names are keys the UI translates; they are not
/// sentences and they say nothing about what has been verified. A stage is only ever reported together with
/// <see cref="InternalInstallWriteState"/> and the actual evidence of that step.
/// </summary>
public enum InternalInstallStage
{
    /// <summary>The factory returned verified, immutable preparation data. No device mutation has been issued.</summary>
    Prepared,

    /// <summary>Fresh recheck of the device, original GPT, current boot images and every local input.</summary>
    Revalidating,

    /// <summary>Only the new maintenance boot is written to slot A.</summary>
    WritingMaintenanceBoot,

    /// <summary>The four explicit GPT regions are written after the maintenance boot readback.</summary>
    WritingGpt,

    /// <summary>The exact 2 GiB board recovery archive is written and read back.</summary>
    WritingBoardBackup,

    /// <summary>The RAM install session is being brought up.</summary>
    BootingRam,

    /// <summary>Filesystems are being prepared inside the RAM session.</summary>
    PreparingFilesystems,

    /// <summary>The seed is being transferred.</summary>
    ReceivingSeed,

    /// <summary>The package is being deployed.</summary>
    Deploying,

    /// <summary>Both boot candidates are being built.</summary>
    BuildingCandidates,

    /// <summary>Both boot candidates are being streamed back to the PC.</summary>
    ExportingCandidates,

    /// <summary>The RAM session ends and a fresh EDL session is entered.</summary>
    ReturningEdl,

    /// <summary>Candidate B is written and read back.</summary>
    WritingBootB,

    /// <summary>Candidate A is written and read back.</summary>
    WritingBootA,

    /// <summary>Only the misc BCB overlay is written and read back.</summary>
    WritingMisc,

    /// <summary>Android is being booted.</summary>
    BootingAndroid,

    /// <summary>Android is being checked read-only.</summary>
    CheckingAndroid,

    /// <summary>The read-only Linux first-boot probe is awaited; no positive Linux verdict exists yet.</summary>
    AwaitingLinuxFirstBoot,

    /// <summary>The read-only Linux acceptance check runs.</summary>
    CheckingLinux,

    /// <summary>Only a real Android and a real Linux acceptance both verified end here.</summary>
    Completed,

    /// <summary>The actual expanded Linux boot raw image is written and read back over the initial EDL session.</summary>
    WritingLinuxBoot,

    /// <summary>The actual expanded Linux root raw image is written and read back over the initial EDL session.</summary>
    WritingLinuxRoot,

    /// <summary>
    /// The single normal reset is being requested; this Started report precedes the acknowledgement. It does
    /// not prove that the wipe was executed or that any operating system booted.
    /// </summary>
    Restarting,

    /// <summary>
    /// The direct route ended after proving every issued write/readback and the accepted reset. It says
    /// nothing about an operating-system boot, a wipe execution or an Android/Linux acceptance.
    /// </summary>
    InstallationCompleted,

    /// <summary>
    /// The full AVB metadata partitions of every selected slot (<c>recovery</c>, <c>vbmeta_system</c> and
    /// <c>vbmeta</c>) are written whole and read back over the initial EDL session. It covers only the
    /// metadata write and its own matching readback; it claims no hardware boot and no OS acceptance.
    /// </summary>
    WritingAvbMetadata,

    /// <summary>
    /// The whole efisp (GBL) partition is written and the matching full readback compared byte for byte. It
    /// covers only that write and its own readback; it claims no OS acceptance, no boot of any kind and no AVB
    /// verification outcome.
    /// </summary>
    WritingGblRuntime,
}

/// <summary>
/// Construction of project boot candidates selected by verified preparation. This static mode does not
/// establish runtime acceptance, complete AVB verification, or OS acceptance.
/// </summary>
public enum InternalInstallBootTrustMode
{
    /// <summary>
    /// Project boot candidates and the required AVB metadata are re-signed with the fixed AOSP key; the device
    /// boot chain must support that signing root.
    /// </summary>
    AospResigned = 0,

    /// <summary>
    /// Project boot candidates preserve original OEM-signed AVB metadata exactly while the modified payload
    /// digest differs. The verified GBL runtime is a prerequisite for the content-digest bypass; RSA signature
    /// validity alone does not establish payload acceptance.
    /// </summary>
    GblPreserveOem = 1,
}

/// <summary>
/// How much of the issued write work has been proven by a readback. <see cref="Unknown"/> poisons the run:
/// a started write or reset whose outcome cannot be established is never inferred to have failed or
/// succeeded from a later empty probe or a timeout.
/// </summary>
public enum InternalInstallWriteState
{
    /// <summary>No mutation has been issued.</summary>
    NoneIssued,

    /// <summary>Some issued mutations carry verified receipts, others do not.</summary>
    PartiallyVerified,

    /// <summary>
    /// Every issued raw write carries a full matching readback, and any issued normal reset request was
    /// accepted. It does not prove an operating-system identity or a boot acceptance; those remain separate
    /// stage evidence.
    /// </summary>
    AllVerified,

    /// <summary>At least one issued mutation cannot be proven either way.</summary>
    Unknown,
}

/// <summary>
/// Overall outcome of one install. <see cref="Completed"/> is reserved for a verified Android acceptance
/// plus a verified Linux first boot; no implementation may produce it while the Linux probe is missing.
/// </summary>
public enum InternalInstallOutcome
{
    /// <summary>Android and Linux acceptance were both actually verified.</summary>
    Completed,

    /// <summary>Android is not usable yet; the user may need to let it finish initializing.</summary>
    AwaitingAndroidInitialization,

    /// <summary>Android is present but the USB debugging prompt has not been accepted.</summary>
    AwaitingUsbAuthorization,

    /// <summary>Android verified; the user must select Linux from the normal boot menu.</summary>
    AwaitingLinuxFirstBoot,

    /// <summary>A step failed with a known result.</summary>
    Failed,

    /// <summary>The run was cancelled while its writes were still provable.</summary>
    Cancelled,

    /// <summary>A write or reset was started and its result cannot be proven.</summary>
    UnknownWriteOutcome,

    /// <summary>
    /// The direct route proved every issued write/readback and the accepted normal reset. This is not the
    /// legacy both-OS <see cref="Completed"/>: no Android acceptance, Linux acceptance, wipe execution or
    /// boot was verified.
    /// </summary>
    InstallationCompleted,
}

/// <summary>The one action the user has to perform, or <see cref="None"/>.</summary>
public enum InternalInstallUserAction
{
    /// <summary>Nothing is required from the user.</summary>
    None,

    /// <summary>Let the fresh Android finish its initialization.</summary>
    FinishAndroidInitialization,

    /// <summary>Accept the USB debugging authorization prompt.</summary>
    AuthorizeUsb,

    /// <summary>Select Linux once from the normal boot menu.</summary>
    SelectLinuxFromNormalMenu,
}

/// <summary>
/// Observation-only phase of one EDL I/O operation. These values describe transport activity for display;
/// they are not a verification state and never stand in for the write or readback evidence.
/// </summary>
public enum InternalInstallIoPhase
{
    /// <summary>Local payload bytes are being checked before any transfer is issued.</summary>
    CheckingPayload,

    /// <summary>Payload bytes are being transferred to the device.</summary>
    Writing,

    /// <summary>Device bytes are being transferred back for readback.</summary>
    ReadingBack,

    /// <summary>Local readback bytes are being checked after the transfer.</summary>
    CheckingReadback,
}

/// <summary>
/// What one <see cref="InternalInstallProgress"/> report proves. <see cref="Verified"/> is only reported for
/// bytes actually read back; a started job is always <see cref="Started"/>, never a success.
/// </summary>
public enum InternalInstallProgressKind
{
    /// <summary>A step has begun; nothing about it is proven yet.</summary>
    Started,

    /// <summary>The step's own evidence was observed.</summary>
    Verified,

    /// <summary>The run is waiting for a real user action.</summary>
    WaitingForUser,

    /// <summary>The step failed with a known result.</summary>
    Failed,

    /// <summary>The step stopped on cancellation.</summary>
    Cancelled,

    /// <summary>
    /// An observation-only transport report. It never proves a phase, never advances a stage and never clears
    /// <see cref="InternalInstallWriteState.Unknown"/> or <see cref="InternalInstallWriteState.AllVerified"/>.
    /// </summary>
    Progress,
}

/// <summary>
/// One progress notification. <see cref="CompletedBytes"/> and <see cref="TotalBytes"/> count only work whose
/// own evidence exists, so they are never an estimated percentage, and <see cref="Slot"/> names the slot the
/// step actually applies to (or null when the step is not slot scoped).
/// <para>
/// The optional <see cref="IoPhase"/>, <see cref="IoCompletedBytes"/> and <see cref="IoTotalBytes"/> values
/// are transport observations for display only. They never change the meaning of <see cref="CompletedBytes"/>
/// and <see cref="TotalBytes"/>, which remain the actual phase proof.
/// </para>
/// </summary>
public sealed record InternalInstallProgress(
    InternalInstallStage Stage,
    InternalInstallProgressKind Kind,
    InternalInstallWriteState WriteState,
    string? Slot,
    long CompletedBytes,
    long TotalBytes,
    string? Detail)
{
    /// <summary>
    /// Observation-only I/O phase this report describes, or null when the report is not a transport
    /// observation. A <see cref="InternalInstallProgressKind.Progress"/> report is never proof and never
    /// clears an <see cref="InternalInstallWriteState.Unknown"/> or a verified state.
    /// </summary>
    public InternalInstallIoPhase? IoPhase { get; init; }

    /// <summary>
    /// Approximate transferred byte count as reported natively and rounded to MiB for display only, or null
    /// when no count exists. The hash/check phases (<see cref="InternalInstallIoPhase.CheckingPayload"/> and
    /// <see cref="InternalInstallIoPhase.CheckingReadback"/>) may leave this indeterminate. It is never
    /// evidence that a phase completed.
    /// </summary>
    public long? IoCompletedBytes { get; init; }

    /// <summary>
    /// Exact trusted, already validated length in bytes of the region covered by the observed operation, or
    /// null when that length is unavailable. This is distinct from <see cref="TotalBytes"/>, which remains the
    /// phase proof total; the two are never interchangeable.
    /// </summary>
    public long? IoTotalBytes { get; init; }
}

/// <summary>
/// Immutable public facts about exactly one AVB slot of the prepared install.
/// <para>
/// <see cref="Slot"/> is the target slot the facts are about; <see cref="SourceSlot"/> names the original
/// Android source slot those facts were taken from. The two are distinct on purpose: a fact observed on the
/// source is never silently presented as a fact about the target.
/// </para>
/// <para>
/// <see cref="NonbootableSystem"/> describes only the factory-uninitialized target state: such a slot receives
/// the project boot alone. It is not a claim that a complete Android is present there, and not a claim of an
/// independent working hardware boot.
/// </para>
/// <para>
/// There is no public constructor and no setter, so a caller cannot fabricate or edit slot facts.
/// </para>
/// </summary>
public sealed class InternalInstallAvbSlotFacts
{
    /// <summary>
    /// Internal so only this assembly's factory can produce slot facts from verified evidence.
    /// </summary>
    internal InternalInstallAvbSlotFacts(string slot, string sourceSlot, bool nonbootableSystem)
    {
        ArgumentNullException.ThrowIfNull(slot);
        ArgumentNullException.ThrowIfNull(sourceSlot);

        Slot = slot;
        SourceSlot = sourceSlot;
        NonbootableSystem = nonbootableSystem;
    }

    /// <summary>The target slot these facts apply to.</summary>
    public string Slot { get; }

    /// <summary>The original Android source slot the facts were derived from.</summary>
    public string SourceSlot { get; }

    /// <summary>
    /// True only when the factory-uninitialized target receives the project boot alone. Says nothing about a
    /// complete Android on the target and nothing about an independent hardware boot.
    /// </summary>
    public bool NonbootableSystem { get; }
}

/// <summary>
/// Immutable result of <see cref="InternalInstallBackend.CreatePreparedAsync"/>: everything the caller needs
/// to display and confirm one install.
/// <para>
/// Every value is a fact the factory produced from verified evidence; none of them is authority by itself.
/// The payload snapshots behind these fingerprints stay private backend state, so this type is a summary, not
/// a package framework. <see cref="SlotOrder"/> is fixed to <c>b</c>, <c>a</c> and can never be reordered by a
/// caller.
/// </para>
/// <para>
/// There is no public constructor and no setter: an instance only ever comes from the factory, and a caller
/// cannot promote a partial result into a prepared one. Dictionary values are copied on construction, so the
/// caller can never mutate what was confirmed.
/// </para>
/// </summary>
public sealed class InternalInstallPrepared
{
    /// <summary>The only write order: candidate B first, then candidate A.</summary>
    private static readonly IReadOnlyList<string> FixedSlotOrder = Array.AsReadOnly(new[] { "b", "a" });

    /// <summary>
    /// Internal bag the future factory fills from verified evidence and hands to the constructor. A mutable
    /// bag is fine here because it never leaves the assembly: the constructor copies every collection.
    /// </summary>
    internal sealed class State
    {
        internal string ConfirmationId = string.Empty;

        internal string ProfileId = string.Empty;

        internal string AndroidSerial = string.Empty;

        internal string SocSerial = string.Empty;

        internal string AndroidBuild = string.Empty;

        internal string CurrentSlot = string.Empty;

        internal long AndroidGiB;

        internal long LinuxRootBytes;

        internal long BoardBackupBytes;

        internal string BackupDirectory = string.Empty;

        internal string EvidenceDirectory = string.Empty;

        internal FirmwareSnapshot Firmware = null!;

        internal BootloaderState FastbootLockState = BootloaderState.Unknown;

        internal InternalInstallBootTrustMode BootTrustMode = InternalInstallBootTrustMode.AospResigned;

        internal string PackageFingerprint = string.Empty;

        internal string PackageBindingSha256 = string.Empty;

        internal string BackupManifestSha256 = string.Empty;

        internal string ArtifactPlanSha256 = string.Empty;

        internal string MaintenanceBootSha256 = string.Empty;

        internal string SupportSha256 = string.Empty;

        internal string ToolboxSha256 = string.Empty;

        internal string CurrentMiscSha256 = string.Empty;

        internal IReadOnlyDictionary<int, string> OriginalGptFingerprints =
            new Dictionary<int, string>();

        internal IReadOnlyDictionary<int, EdlGeometry> Geometries = new Dictionary<int, EdlGeometry>();

        internal IReadOnlyDictionary<string, string> CurrentBootSha256 =
            new Dictionary<string, string>(StringComparer.Ordinal);

        internal IReadOnlyDictionary<string, InternalSlotMaterial> SlotMaterials =
            new Dictionary<string, InternalSlotMaterial>(StringComparer.Ordinal);

        internal IReadOnlyDictionary<string, long> RawUpperBoundBytes =
            new Dictionary<string, long>(StringComparer.Ordinal);

        internal IReadOnlyDictionary<string, InternalInstallAvbSlotFacts> AvbSlots =
            new Dictionary<string, InternalInstallAvbSlotFacts>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Copies <paramref name="state"/> into immutable storage. Internal so no caller can build a prepared
    /// result; only the factory of this assembly ever passes a filled bag.
    /// </summary>
    internal InternalInstallPrepared(State state)
    {
        ArgumentNullException.ThrowIfNull(state);

        ConfirmationId = state.ConfirmationId;
        ProfileId = state.ProfileId;
        AndroidSerial = state.AndroidSerial;
        SocSerial = state.SocSerial;
        AndroidBuild = state.AndroidBuild;
        CurrentSlot = state.CurrentSlot;
        AndroidGiB = state.AndroidGiB;
        LinuxRootBytes = state.LinuxRootBytes;
        BoardBackupBytes = state.BoardBackupBytes;
        BackupDirectory = state.BackupDirectory;
        EvidenceDirectory = state.EvidenceDirectory;
        Firmware = state.Firmware;
        FastbootLockState = state.FastbootLockState;
        BootTrustMode = state.BootTrustMode;

        PackageFingerprint = state.PackageFingerprint;
        PackageBindingSha256 = state.PackageBindingSha256;
        BackupManifestSha256 = state.BackupManifestSha256;
        ArtifactPlanSha256 = state.ArtifactPlanSha256;
        MaintenanceBootSha256 = state.MaintenanceBootSha256;
        SupportSha256 = state.SupportSha256;
        ToolboxSha256 = state.ToolboxSha256;
        CurrentMiscSha256 = state.CurrentMiscSha256;

        OriginalGptFingerprints = Copy(state.OriginalGptFingerprints);
        Geometries = Copy(state.Geometries);
        CurrentBootSha256 = Copy(state.CurrentBootSha256);
        SlotMaterials = Copy(state.SlotMaterials);
        RawUpperBoundBytes = Copy(state.RawUpperBoundBytes);
        AvbSlots = Copy(state.AvbSlots);
    }

    /// <summary>Canonical SHA-256 the user confirms. Covers every value below, never a caller claim.</summary>
    public string ConfirmationId { get; }

    /// <summary>Profile id of the verified install profile.</summary>
    public string ProfileId { get; }

    /// <summary>Android serial observed on the expected device.</summary>
    public string AndroidSerial { get; }

    /// <summary>SoC serial observed on the expected device.</summary>
    public string SocSerial { get; }

    /// <summary>Android build of the expected device.</summary>
    public string AndroidBuild { get; }

    /// <summary>The observed current slot; only <c>a</c> can ever be prepared.</summary>
    public string CurrentSlot { get; }

    /// <summary>Android capacity in whole GiB that the plan leaves to Android.</summary>
    public long AndroidGiB { get; }

    /// <summary>Linux root partition size in bytes.</summary>
    public long LinuxRootBytes { get; }

    /// <summary>Board recovery partition size in bytes; exactly 2 GiB.</summary>
    public long BoardBackupBytes { get; }

    /// <summary>Absolute path of the verified PC backup directory.</summary>
    public string BackupDirectory { get; }

    /// <summary>Absolute path of the evidence directory this install writes receipts to.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>Exact firmware snapshot the install is bound to.</summary>
    public FirmwareSnapshot Firmware { get; }

    /// <summary>Bootloader lock state fastboot actually confirmed.</summary>
    public BootloaderState FastbootLockState { get; }

    /// <summary>
    /// Construction of the project boot candidates copied from the verified factory state; no hardware or OS
    /// acceptance is implied.
    /// </summary>
    public InternalInstallBootTrustMode BootTrustMode { get; }

    /// <summary>Fingerprint of the selected package.</summary>
    public string PackageFingerprint { get; }

    /// <summary>Canonical binding of the package to the observed firmware and storage.</summary>
    public string PackageBindingSha256 { get; }

    /// <summary>SHA-256 of the verified backup manifest.</summary>
    public string BackupManifestSha256 { get; }

    /// <summary>Plan SHA-256 of the prepared artifacts.</summary>
    public string ArtifactPlanSha256 { get; }

    /// <summary>SHA-256 of the new maintenance boot image.</summary>
    public string MaintenanceBootSha256 { get; }

    /// <summary>SHA-256 of the verified install-support archive.</summary>
    public string SupportSha256 { get; }

    /// <summary>SHA-256 of the verified toolbox bundle.</summary>
    public string ToolboxSha256 { get; }

    /// <summary>SHA-256 of the currently read misc partition.</summary>
    public string CurrentMiscSha256 { get; }

    /// <summary>Fingerprint of each original LUN's GPT, keyed by LUN number.</summary>
    public IReadOnlyDictionary<int, string> OriginalGptFingerprints { get; }

    /// <summary>Freshly probed geometry of each LUN, keyed by LUN number.</summary>
    public IReadOnlyDictionary<int, EdlGeometry> Geometries { get; }

    /// <summary>SHA-256 of each currently read boot image, keyed by slot.</summary>
    public IReadOnlyDictionary<string, string> CurrentBootSha256 { get; }

    /// <summary>Per-slot Android base material, keyed by slot.</summary>
    public IReadOnlyDictionary<string, InternalSlotMaterial> SlotMaterials { get; }

    /// <summary>Conservative raw upper bound per builder, keyed by its material name.</summary>
    public IReadOnlyDictionary<string, long> RawUpperBoundBytes { get; }

    /// <summary>
    /// Immutable AVB slot facts, keyed by target slot. Empty unless the factory actually supplied them: an
    /// empty dictionary means no slot facts were established, never that a slot is unmodified.
    /// </summary>
    public IReadOnlyDictionary<string, InternalInstallAvbSlotFacts> AvbSlots { get; }

    /// <summary>The only write order: <c>b</c> then <c>a</c>. Never caller reorderable.</summary>
    public IReadOnlyList<string> SlotOrder => FixedSlotOrder;

    private static IReadOnlyDictionary<TKey, TValue> Copy<TKey, TValue>(
        IReadOnlyDictionary<TKey, TValue> source)
        where TKey : notnull
    {
        ArgumentNullException.ThrowIfNull(source);

        // Copied pair by pair so nothing the caller (or the future factory) still holds can be observed later.
        var copy = new Dictionary<TKey, TValue>(source.Count);
        foreach (var pair in source)
        {
            copy.Add(pair.Key, pair.Value);
        }

        return new ReadOnlyDictionary<TKey, TValue>(copy);
    }
}

/// <summary>
/// Immutable, authoritative snapshot of the backend's current state. This is the read point a UI polls, so it
/// carries the phase, the proven write state and the pending user action together instead of a lossy progress
/// stream. There is no setter: only the backend replaces its own snapshot.
/// </summary>
public sealed class InternalInstallSnapshot
{
    internal InternalInstallSnapshot(
        bool executionStarted,
        InternalInstallStage stage,
        InternalInstallWriteState writeState,
        InternalInstallOutcome? outcome,
        InternalInstallUserAction requiredUserAction,
        string evidenceDirectory,
        bool androidDataMayBeErased)
    {
        ArgumentNullException.ThrowIfNull(evidenceDirectory);

        ExecutionStarted = executionStarted;
        Stage = stage;
        WriteState = writeState;
        Outcome = outcome;
        RequiredUserAction = requiredUserAction;
        EvidenceDirectory = evidenceDirectory;
        AndroidDataMayBeErased = androidDataMayBeErased;
    }

    /// <summary>True once the first write-intent step has begun for this backend instance.</summary>
    public bool ExecutionStarted { get; }

    /// <summary>The stage currently reached.</summary>
    public InternalInstallStage Stage { get; }

    /// <summary>How much of the issued write work is proven by readback.</summary>
    public InternalInstallWriteState WriteState { get; }

    /// <summary>The final outcome once the run ended, or null while it is still running.</summary>
    public InternalInstallOutcome? Outcome { get; }

    /// <summary>The action the user must perform, or <see cref="InternalInstallUserAction.None"/>.</summary>
    public InternalInstallUserAction RequiredUserAction { get; }

    /// <summary>Absolute path of the evidence directory of this run.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>True from the moment Android data may have been erased onward; never reset to false.</summary>
    public bool AndroidDataMayBeErased { get; }
}

/// <summary>
/// Immutable result of one execution or acceptance run.
/// <para>
/// <see cref="LinuxAcceptanceVerified"/> has no positive producer yet: no verified normal-Linux probe exists,
/// so no implementation may set it to true, report <see cref="InternalInstallOutcome.Completed"/>, or infer a
/// Linux first boot from a RAM session, a boot flag, a receipt or an MTP presence.
/// </para>
/// <para>
/// <see cref="AndroidAcceptance"/> is the actual Android-side result, or null when none was taken. The
/// verified slots are copied, so the caller cannot add a slot it did not see verified.
/// </para>
/// </summary>
public sealed class InternalInstallResult
{
    internal InternalInstallResult(
        InternalInstallOutcome outcome,
        InternalInstallStage? lastVerifiedStage,
        InternalInstallWriteState writeState,
        IReadOnlyList<string> verifiedSlots,
        InternalAndroidAcceptanceResult? androidAcceptance,
        bool linuxAcceptanceVerified,
        InternalInstallUserAction requiredUserAction,
        string evidenceDirectory,
        string? errorCode,
        string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(verifiedSlots);
        ArgumentNullException.ThrowIfNull(evidenceDirectory);

        Outcome = outcome;
        LastVerifiedStage = lastVerifiedStage;
        WriteState = writeState;
        VerifiedSlots = Array.AsReadOnly(new List<string>(verifiedSlots).ToArray());
        AndroidAcceptance = androidAcceptance;
        LinuxAcceptanceVerified = linuxAcceptanceVerified;
        RequiredUserAction = requiredUserAction;
        EvidenceDirectory = evidenceDirectory;
        ErrorCode = errorCode;
        Diagnostic = diagnostic;
    }

    /// <summary>The overall outcome of the run.</summary>
    public InternalInstallOutcome Outcome { get; }

    /// <summary>The last stage whose own evidence was observed, or null when none was.</summary>
    public InternalInstallStage? LastVerifiedStage { get; }

    /// <summary>How much of the issued write work is proven by readback.</summary>
    public InternalInstallWriteState WriteState { get; }

    /// <summary>The slots actually verified, in the order they were verified.</summary>
    public IReadOnlyList<string> VerifiedSlots { get; }

    /// <summary>The actual Android-side acceptance result, or null when no check ran.</summary>
    public InternalAndroidAcceptanceResult? AndroidAcceptance { get; }

    /// <summary>True only after a real, read-only Linux first-boot verification. No producer exists yet.</summary>
    public bool LinuxAcceptanceVerified { get; }

    /// <summary>The action the user must perform, or <see cref="InternalInstallUserAction.None"/>.</summary>
    public InternalInstallUserAction RequiredUserAction { get; }

    /// <summary>Absolute path of the evidence directory of this run.</summary>
    public string EvidenceDirectory { get; }

    /// <summary>Stable machine-readable error identity, or null.</summary>
    public string? ErrorCode { get; }

    /// <summary>Human-readable diagnostic text; never part of the contract.</summary>
    public string? Diagnostic { get; }
}
