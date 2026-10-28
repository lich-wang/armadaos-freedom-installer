using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The public execution entries of the one real internal install and the mutation-state gates behind them.
/// <para>
/// <see cref="ExecuteAsync"/> runs the fixed observed sequence once, and <see cref="CheckAcceptanceAsync"/>
/// repeats only the read-only Android acceptance of a pending run. Every transition still records just a fact
/// the caller actually observed: a begin marks the intent <see cref="InternalInstallWriteState.Unknown"/>, and
/// only a matching readback or an accepted normal reset restores
/// <see cref="InternalInstallWriteState.AllVerified"/>. No path here can produce
/// <see cref="InternalInstallStage.Completed"/> or a positive Linux verdict.
/// </para>
/// <para>
/// The nested run is private bookkeeping, deliberately not a workflow engine: no retry, no recovery, no
/// transport abstraction and no delegate.
/// </para>
/// </summary>
public sealed partial class InternalInstallBackend
{
    private const string ExecutionCancelledCode = "execution-cancelled";

    private const string ExecutionFailedCode = "execution-failed";

    private const string ExecutionUnknownWriteCode = "execution-write-outcome-unknown";

    private const string AndroidAcceptanceRejectedCode = "android-acceptance-rejected";

    private const string AndroidAcceptanceFailedCode = "android-acceptance-failed";

    private ExecutionRun? _executionRun;

    // ------------------------------------------------------------------ EX004: public execution entries

    /// <summary>
    /// Runs the one fixed internal install after the caller confirmed the exact prepared confirmation id and
    /// the explicit userdata erase. Admission is cheap: a pre-cancelled token, a disposed backend, a wrong
    /// confirmation, a missing erase acknowledgement or a second call all refuse before any device command.
    /// </summary>
    public async Task<InternalInstallResult> ExecuteAsync(
        string confirmationId,
        bool userdataEraseConfirmed,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        ExecutionRun run;

        lock (_gate)
        {
            if (_disposed)
            {
                throw new InvalidOperationException(
                    "The internal install backend is disposed and accepts no execution.");
            }

            ValidateExecutionConfirmation(
                Prepared.ConfirmationId, confirmationId, userdataEraseConfirmed, ct);

            if (_executionStarted || _executing)
            {
                throw new InvalidOperationException(
                    "The internal install backend accepts exactly one execution per prepared instance.");
            }

            _executionStarted = true;
            _executing = true;
            run = new ExecutionRun();
            _executionRun = run;
        }

        var heldExports = new List<FileStream>();

        try
        {
            if (_context.IsDirect)
            {
                return await ExecuteDirectFlowAsync(run, progress, ct).ConfigureAwait(false);
            }

            run.StartStage(InternalInstallStage.Revalidating);
            PublishExecution(run, progress, InternalInstallProgressKind.Started);

            await _context.RevalidateLocalAsync(ct).ConfigureAwait(false);
            await _context.VerifyOriginalDeviceAsync(_initialEdl, "execute", ct).ConfigureAwait(false);

            run.VerifyStage(InternalInstallStage.Revalidating);
            PublishExecution(run, progress, InternalInstallProgressKind.Verified);

            await WriteInitialEdlPhaseAsync(run, progress, ct).ConfigureAwait(false);

            // The one reset of the initial session. The initial client is never used for a device command again.
            await ResetExecutionAsync(_initialEdl, run, InternalInstallStage.BootingRam, progress, ct)
                .ConfigureAwait(false);

            (EdlClient fresh, VerifiedEdlFile bootB, VerifiedEdlFile bootA) = await RunRamAndReturnEdlAsync(
                    run, heldExports, progress, ct)
                .ConfigureAwait(false);

            await WriteExecutionRegionAsync(
                    fresh,
                    run,
                    InternalInstallStage.WritingBootB,
                    "b",
                    MakeExecutionRegion(RequireCapturedRegion("boot_b"), bootB, "boot_b"),
                    mayEraseAndroid: true,
                    progress,
                    ct)
                .ConfigureAwait(false);

            await WriteExecutionRegionAsync(
                    fresh,
                    run,
                    InternalInstallStage.WritingBootA,
                    "a",
                    MakeExecutionRegion(RequireCapturedRegion("boot_a"), bootA, "boot_a"),
                    mayEraseAndroid: true,
                    progress,
                    ct)
                .ConfigureAwait(false);

            await WriteFreshMiscAsync(fresh, run, progress, ct).ConfigureAwait(false);

            await ResetExecutionAsync(fresh, run, InternalInstallStage.BootingAndroid, progress, ct)
                .ConfigureAwait(false);

            return await CheckAndroidAcceptanceAsync(run, progress, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            run.Interrupt();

            InternalInstallOutcome outcome = run.WriteState == InternalInstallWriteState.Unknown
                ? InternalInstallOutcome.UnknownWriteOutcome
                : InternalInstallOutcome.Cancelled;

            return FinishResult(
                run,
                outcome,
                InternalInstallProgressKind.Cancelled,
                progress,
                InternalInstallUserAction.None,
                androidAcceptance: null,
                errorCode: outcome == InternalInstallOutcome.UnknownWriteOutcome
                    ? ExecutionUnknownWriteCode
                    : ExecutionCancelledCode,
                diagnostic: "The execution stopped on cancellation at stage " + run.Stage + ".");
        }
        catch (Exception exception)
        {
            run.Interrupt();

            InternalInstallOutcome outcome = run.WriteState == InternalInstallWriteState.Unknown
                ? InternalInstallOutcome.UnknownWriteOutcome
                : InternalInstallOutcome.Failed;

            string errorCode = exception is ExecutionFailureException failure
                ? failure.Code
                : outcome == InternalInstallOutcome.UnknownWriteOutcome
                    ? ExecutionUnknownWriteCode
                    : ExecutionFailedCode;

            // Only the fixed failure code and text of this assembly, or the stage and exception type.
            string diagnostic = exception is ExecutionFailureException known
                ? known.Message
                : "The execution failed at stage " + run.Stage + " with "
                    + exception.GetType().Name + ".";

            return FinishResult(
                run,
                outcome,
                InternalInstallProgressKind.Failed,
                progress,
                InternalInstallUserAction.None,
                androidAcceptance: null,
                errorCode: errorCode,
                diagnostic: diagnostic);
        }
        finally
        {
            foreach (FileStream lease in heldExports)
            {
                try
                {
                    lease.Dispose();
                }
                catch
                {
                    // Releasing a held export never changes a recorded device fact.
                }
            }

            lock (_gate)
            {
                _executing = false;
            }
        }
    }

    /// <summary>
    /// Repeats only the read-only Android acceptance of a pending run. It never writes, resets, boots RAM or
    /// enters the EDL path, and a run that already verified Android returns that same fact without any adb query.
    /// </summary>
    public async Task<InternalInstallResult> CheckAcceptanceAsync(
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        ExecutionRun run;
        InternalInstallSnapshot previousSnapshot;
        InternalInstallResult previousResult;

        lock (_gate)
        {
            if (_disposed)
            {
                throw new InvalidOperationException(
                    "The internal install backend is disposed and accepts no acceptance check.");
            }

            if (_executing)
            {
                throw new InvalidOperationException(
                    "An internal install step is already running on this backend.");
            }

            ExecutionRun? currentRun = _executionRun;
            InternalInstallResult? last = _lastResult;

            if (!_executionStarted || currentRun is null || last is null)
            {
                throw new InvalidOperationException(
                    "The acceptance check requires a finished, pending execution of this backend.");
            }

            bool pending = last.WriteState == InternalInstallWriteState.AllVerified
                && (last.Outcome == InternalInstallOutcome.AwaitingAndroidInitialization
                    || last.Outcome == InternalInstallOutcome.AwaitingUsbAuthorization
                    || last.Outcome == InternalInstallOutcome.AwaitingLinuxFirstBoot);

            if (!pending)
            {
                throw new InvalidOperationException(
                    "Only a pending execution whose issued mutations are all verified can be re-checked.");
            }

            run = currentRun;
            previousSnapshot = _snapshot;
            previousResult = last;
            _executing = true;
        }

        try
        {
            return await CheckAndroidAcceptanceAsync(run, progress, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The prior pending result stays authoritative; the read-only check never poisons the raw state.
            lock (_gate)
            {
                _lastResult = previousResult;
                _snapshot = previousSnapshot;
            }

            RestoreExecutionStage(run, previousSnapshot.Stage);
            throw;
        }
        catch (Exception exception)
        {
            run.Interrupt();

            InternalInstallOutcome outcome = run.WriteState == InternalInstallWriteState.Unknown
                ? InternalInstallOutcome.UnknownWriteOutcome
                : InternalInstallOutcome.Failed;

            return FinishResult(
                run,
                outcome,
                InternalInstallProgressKind.Failed,
                progress,
                InternalInstallUserAction.None,
                androidAcceptance: null,
                errorCode: outcome == InternalInstallOutcome.UnknownWriteOutcome
                    ? ExecutionUnknownWriteCode
                    : AndroidAcceptanceFailedCode,
                diagnostic: "The read-only Android acceptance check failed at stage " + run.Stage
                    + " with " + exception.GetType().Name + ".");
        }
        finally
        {
            lock (_gate)
            {
                _executing = false;
            }
        }
    }

    /// <summary>
    /// The real Android acceptance of the run: no ADB when this run already verified Android, otherwise the one
    /// read-only probe. A verified probe still ends at <see cref="InternalInstallStage.AwaitingLinuxFirstBoot"/>,
    /// because no positive Linux first-boot probe exists.
    /// </summary>
    private async Task<InternalInstallResult> CheckAndroidAcceptanceAsync(
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(run);

        if (run.AndroidAcceptance is { Verified: true } verified)
        {
            run.StartStage(InternalInstallStage.AwaitingLinuxFirstBoot);

            return FinishResult(
                run,
                InternalInstallOutcome.AwaitingLinuxFirstBoot,
                InternalInstallProgressKind.WaitingForUser,
                progress,
                InternalInstallUserAction.SelectLinuxFromNormalMenu,
                verified,
                errorCode: null,
                diagnostic: null);
        }

        run.StartStage(InternalInstallStage.CheckingAndroid);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        var acceptance = new InternalInstallAcceptance(_services.AdbPath, _services.CommandRunner);

        InternalAndroidAcceptanceResult actual = _context.IsDirect
            ? await acceptance
                .CheckAndroidAsync(
                    _deviceCheck,
                    _context.Allocation.OriginalUserdata.Number,
                    _context.Allocation.AndroidBytes,
                    _initialEdl.Toolchain.Profile,
                    cancellationToken)
                .ConfigureAwait(false)
            : await acceptance
                .CheckAndroidAsync(
                    _deviceCheck,
                    _context.Allocation.OriginalUserdata.Number,
                    _context.Allocation.AndroidBytes,
                    cancellationToken)
                .ConfigureAwait(false);

        switch (actual.State)
        {
            case InternalAndroidAcceptanceState.Verified:
                run.RememberAndroidAcceptance(actual);
                run.VerifyStage(InternalInstallStage.CheckingAndroid);
                PublishExecution(run, progress, InternalInstallProgressKind.Verified);
                run.StartStage(InternalInstallStage.AwaitingLinuxFirstBoot);

                return FinishResult(
                    run,
                    InternalInstallOutcome.AwaitingLinuxFirstBoot,
                    InternalInstallProgressKind.WaitingForUser,
                    progress,
                    InternalInstallUserAction.SelectLinuxFromNormalMenu,
                    actual,
                    errorCode: null,
                    diagnostic: null);

            case InternalAndroidAcceptanceState.AwaitingUsbAuthorization:
                return FinishResult(
                    run,
                    InternalInstallOutcome.AwaitingUsbAuthorization,
                    InternalInstallProgressKind.WaitingForUser,
                    progress,
                    InternalInstallUserAction.AuthorizeUsb,
                    actual,
                    errorCode: null,
                    diagnostic: actual.Diagnostic);

            case InternalAndroidAcceptanceState.AwaitingAndroidInitialization:
                return FinishResult(
                    run,
                    InternalInstallOutcome.AwaitingAndroidInitialization,
                    InternalInstallProgressKind.WaitingForUser,
                    progress,
                    InternalInstallUserAction.FinishAndroidInitialization,
                    actual,
                    errorCode: null,
                    diagnostic: actual.Diagnostic);

            case InternalAndroidAcceptanceState.Rejected:
                return FinishResult(
                    run,
                    InternalInstallOutcome.Failed,
                    InternalInstallProgressKind.Failed,
                    progress,
                    InternalInstallUserAction.None,
                    actual,
                    errorCode: AndroidAcceptanceRejectedCode,
                    diagnostic: actual.Diagnostic);

            default:
                throw new InvalidOperationException(
                    "The Android acceptance check reported a state this backend cannot classify.");
        }
    }

    /// <summary>
    /// The one result constructor: it freezes the run's actual facts into a new immutable result and snapshot
    /// under the gate, writes a compact safe result record and reports one final progress event. A result-file
    /// failure never rewrites a known device fact or conceals a pending outcome.
    /// </summary>
    private InternalInstallResult FinishResult(
        ExecutionRun run,
        InternalInstallOutcome outcome,
        InternalInstallProgressKind progressKind,
        IProgress<InternalInstallProgress>? progress,
        InternalInstallUserAction requiredUserAction,
        InternalAndroidAcceptanceResult? androidAcceptance,
        string? errorCode,
        string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(run);

        InternalInstallResult result;
        InternalInstallStage stage;
        InternalInstallWriteState writeState;

        lock (_gate)
        {
            stage = run.Stage;
            writeState = run.WriteState;

            result = new InternalInstallResult(
                outcome,
                run.LastVerifiedStage,
                writeState,
                run.VerifiedSlots,
                androidAcceptance ?? run.AndroidAcceptance,
                linuxAcceptanceVerified: false,
                requiredUserAction,
                _context.EvidenceDirectory,
                errorCode,
                diagnostic);

            _lastResult = result;
            _snapshot = new InternalInstallSnapshot(
                executionStarted: true,
                stage,
                writeState,
                outcome,
                requiredUserAction,
                _context.EvidenceDirectory,
                run.AndroidDataMayBeErased);
        }

        try
        {
            WriteNewJsonFile(
                NewExecutionEvidencePath("execution-result", ".json"),
                new
                {
                    outcome = outcome.ToString(),
                    stage = stage.ToString(),
                    lastVerifiedStage = result.LastVerifiedStage?.ToString(),
                    writeState = writeState.ToString(),
                    verifiedSlots = result.VerifiedSlots,
                    androidState = result.AndroidAcceptance?.State.ToString(),
                    androidAcceptance = result.AndroidAcceptance,
                    requiredUserAction = requiredUserAction.ToString(),
                    errorCode,
                    diagnostic,
                });
        }
        catch
        {
            // The recorded device facts stay authoritative; only this summary record is missing.
        }

        if (progress is not null)
        {
            try
            {
                progress.Report(new InternalInstallProgress(
                    stage, progressKind, writeState, null, 0, 0, diagnostic));
            }
            catch
            {
                // A progress observer never changes install state.
            }
        }

        return result;
    }

    /// <summary>
    /// The cheap admission guard: cancellation, the explicit erase acknowledgement and the exact prepared
    /// confirmation id, in that order. It consumes nothing and touches no device.
    /// </summary>
    private static void ValidateExecutionConfirmation(
        string expected,
        string? supplied,
        bool userdataEraseConfirmed,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!userdataEraseConfirmed)
        {
            throw new ArgumentException(
                "The userdata erase must be explicitly confirmed before the install can start.",
                nameof(userdataEraseConfirmed));
        }

        if (supplied is null || !string.Equals(supplied, expected, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The supplied confirmation id is not the prepared confirmation.", nameof(supplied));
        }
    }

    private static void RestoreExecutionStage(ExecutionRun run, InternalInstallStage stage)
    {
        if (run.Stage == stage)
        {
            return;
        }

        try
        {
            run.StartStage(stage);
        }
        catch (InvalidOperationException)
        {
            // A poisoned run keeps its own stage; the authoritative snapshot was already restored.
        }
    }

    /// <summary>
    /// The mutation receipts and identity gates of exactly one execution attempt. All state starts at the
    /// prepared factory boundary; no stage is verified and no write has been issued.
    /// </summary>
    internal sealed class ExecutionRun
    {
        /// <summary>What an outstanding mutation is waiting for. Only one can be outstanding at a time.</summary>
        private enum PendingMutation
        {
            None,
            RawWrite,
            RamJob,
            NormalReset,
            Finish,
        }

        private readonly List<string> _verifiedSlots = new();

        private InternalInstallStage _stage = InternalInstallStage.Prepared;
        private InternalInstallStage? _lastVerifiedStage;
        private InternalInstallWriteState _writeState = InternalInstallWriteState.NoneIssued;
        private bool _androidDataMayBeErased;
        private InternalAndroidAcceptanceResult? _androidAcceptance;

        private PendingMutation _pending;
        private InternalInstallStage? _pendingStage;
        private string? _pendingSlot;

        private bool _interrupted;

        private bool _finishAttempted;

        /// <summary>The stage currently reached, verified or not.</summary>
        internal InternalInstallStage Stage => _stage;

        /// <summary>The last stage whose own evidence was actually observed, or null.</summary>
        internal InternalInstallStage? LastVerifiedStage => _lastVerifiedStage;

        /// <summary>How much of the issued mutation work is proven.</summary>
        internal InternalInstallWriteState WriteState => _writeState;

        /// <summary>True from the first write intent that may have erased Android data onward.</summary>
        internal bool AndroidDataMayBeErased => _androidDataMayBeErased;

        /// <summary>True once an unresolved mutation was interrupted; no later transition is accepted.</summary>
        internal bool IsInterrupted => _interrupted;

        /// <summary>
        /// The boot slots whose writes were actually read back, in verification order. Each read returns a
        /// fresh read-only copy, so a caller cannot add a slot it never saw verified.
        /// </summary>
        internal IReadOnlyList<string> VerifiedSlots => Array.AsReadOnly(_verifiedSlots.ToArray());

        /// <summary>The verified Android acceptance cached for this run, or null when none was seen.</summary>
        internal InternalAndroidAcceptanceResult? AndroidAcceptance => _androidAcceptance;

        /// <summary>
        /// Marks a stage as reached without verifying anything. Refused while a mutation is outstanding or
        /// after the run was poisoned.
        /// </summary>
        internal void StartStage(InternalInstallStage stage)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();
            RequireNoPending();

            _stage = stage;
        }

        /// <summary>
        /// Records that <paramref name="stage"/> is the current stage and that its own fresh evidence was
        /// actually observed. It never infers evidence for a stage the run has not reached, and it never
        /// advances a boot identity by itself.
        /// </summary>
        internal void VerifyStage(InternalInstallStage stage)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();
            RequireNoPending();

            if (_stage != stage)
            {
                throw new InvalidOperationException(
                    "Stage " + stage + " is not the current stage " + _stage + ".");
            }

            _lastVerifiedStage = stage;
        }

        /// <summary>
        /// Records the intent to issue one raw partition write. The run becomes
        /// <see cref="InternalInstallWriteState.Unknown"/> before the caller hands the write to the device, so a
        /// started write can never look verified. The boot stages require their own slot, and the slot is
        /// otherwise null, <c>a</c> or <c>b</c>.
        /// </summary>
        internal void BeginRawWrite(InternalInstallStage stage, string? slot, bool mayEraseAndroid)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();
            RequireNoPending();
            RequireMutationStage(stage);
            RequireRawWriteSlot(stage, slot);

            _pending = PendingMutation.RawWrite;
            _pendingStage = stage;
            _pendingSlot = slot;
            _stage = stage;
            _writeState = InternalInstallWriteState.Unknown;
            _androidDataMayBeErased |= mayEraseAndroid;
        }

        /// <summary>
        /// The only completion path of a raw write: the caller states that the full matching readback was
        /// observed. A program acknowledgement has no method here and is not evidence. A non-matching stage or
        /// slot leaves the pending write and <see cref="InternalInstallWriteState.Unknown"/> untouched.
        /// </summary>
        internal void VerifyRawReadback(InternalInstallStage stage, string? slot)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();

            if (_pending != PendingMutation.RawWrite
                || _pendingStage != stage
                || !string.Equals(_pendingSlot, slot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "No raw write for stage " + stage + " and slot " + (slot ?? "<none>")
                    + " is awaiting readback.");
            }

            ClearPending();
            _writeState = InternalInstallWriteState.AllVerified;
            _lastVerifiedStage = stage;

            if (stage == InternalInstallStage.WritingBootB)
            {
                AddVerifiedSlot("b");
            }
            else if (stage == InternalInstallStage.WritingBootA)
            {
                AddVerifiedSlot("a");
            }
        }

        /// <summary>
        /// Records the intent to start one RAM-side mutation (job upload or job launch). The run becomes
        /// <see cref="InternalInstallWriteState.Unknown"/> until the job's own verified result exists; neither
        /// the upload acknowledgement nor the job launch is evidence.
        /// </summary>
        internal void BeginRamMutation(InternalInstallStage stage, bool mayEraseAndroid)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();
            RequireNoPending();
            RequireMutationStage(stage);

            _pending = PendingMutation.RamJob;
            _pendingStage = stage;
            _pendingSlot = null;
            _stage = stage;
            _writeState = InternalInstallWriteState.Unknown;
            _androidDataMayBeErased |= mayEraseAndroid;
        }

        /// <summary>
        /// The only completion path of a RAM mutation: the caller states that the job actually succeeded, was
        /// ready and reported the expected status. It never adds a boot slot.
        /// </summary>
        internal void VerifyRamJob(InternalInstallStage stage)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();

            if (_pending != PendingMutation.RamJob || _pendingStage != stage)
            {
                throw new InvalidOperationException(
                    "No RAM job for stage " + stage + " is awaiting its verified result.");
            }

            ClearPending();
            _writeState = InternalInstallWriteState.AllVerified;
            _lastVerifiedStage = stage;
        }

        /// <summary>
        /// Records the intent to issue the one normal reset. The run becomes
        /// <see cref="InternalInstallWriteState.Unknown"/> until the reset request is actually accepted.
        /// </summary>
        internal void BeginNormalReset(InternalInstallStage stage)
        {
            RequireKnownStage(stage);
            RequireNotInterrupted();
            RequireNoPending();
            RequireMutationStage(stage);

            _pending = PendingMutation.NormalReset;
            _pendingStage = stage;
            _pendingSlot = null;
            _stage = stage;
            _writeState = InternalInstallWriteState.Unknown;
        }

        /// <summary>
        /// Records that the issued normal reset request was accepted. It restores
        /// <see cref="InternalInstallWriteState.AllVerified"/> because every earlier write was read back and the
        /// reset request was accepted, but it does not verify the current stage: a reset command is not a boot
        /// identity and never advances <see cref="LastVerifiedStage"/>.
        /// </summary>
        internal void AcceptNormalReset()
        {
            RequireNotInterrupted();

            if (_pending != PendingMutation.NormalReset)
            {
                throw new InvalidOperationException("No normal reset request is pending.");
            }

            ClearPending();
            _writeState = InternalInstallWriteState.AllVerified;
        }

        /// <summary>
        /// Records the intent to end the RAM session and enter a fresh EDL session, once. The run becomes
        /// <see cref="InternalInstallWriteState.Unknown"/> and stays there until a fresh Sahara plus full post
        /// proof is actually observed. A requested or lost acknowledgement never resolves this pending state.
        /// </summary>
        internal void BeginFinish()
        {
            RequireNotInterrupted();
            RequireNoPending();

            // The finish transition is issued at most once per run. The flag is sticky because a later
            // StartStage may legitimately change _stage, and that must never re-authorize a second finish.
            if (_finishAttempted || _stage == InternalInstallStage.ReturningEdl)
            {
                throw new InvalidOperationException("The finish transition was already issued and is never repeated.");
            }

            _finishAttempted = true;
            _pending = PendingMutation.Finish;
            _pendingStage = InternalInstallStage.ReturningEdl;
            _pendingSlot = null;
            _stage = InternalInstallStage.ReturningEdl;
            _writeState = InternalInstallWriteState.Unknown;
        }

        /// <summary>
        /// Records the explicit restart2-returned result: the RAM session ended without a reset request being
        /// issued. The known failure clears the pending finish and restores
        /// <see cref="InternalInstallWriteState.AllVerified"/>, because no mutation is outstanding, but it is
        /// not a stage verification and leaves <see cref="LastVerifiedStage"/> unchanged.
        /// </summary>
        internal void FinishReturned()
        {
            RequireNotInterrupted();

            if (_pending != PendingMutation.Finish)
            {
                throw new InvalidOperationException("No finish transition is pending.");
            }

            ClearPending();
            _writeState = InternalInstallWriteState.AllVerified;
        }

        /// <summary>
        /// Records that the finish request may have caused a reset but its acknowledgement is lost or was only
        /// requested. The pending finish and <see cref="InternalInstallWriteState.Unknown"/> are retained; this
        /// method creates no evidence and cannot resolve the transition.
        /// </summary>
        internal void FinishMayHaveReset()
        {
            RequireNotInterrupted();

            if (_pending != PendingMutation.Finish)
            {
                throw new InvalidOperationException("No finish transition is pending.");
            }

            // Deliberately no state change: only VerifyFreshEdlTransition may resolve this pending finish.
        }

        /// <summary>
        /// Resolves the pending finish only after the caller observed a genuinely fresh EDL session: a new
        /// Sahara proof plus the full post-partition proof. It is the only finish completion that verifies
        /// <see cref="InternalInstallStage.ReturningEdl"/>.
        /// </summary>
        internal void VerifyFreshEdlTransition()
        {
            RequireNotInterrupted();

            if (_pending != PendingMutation.Finish)
            {
                throw new InvalidOperationException("No finish transition is pending.");
            }

            ClearPending();
            _writeState = InternalInstallWriteState.AllVerified;
            _lastVerifiedStage = InternalInstallStage.ReturningEdl;
        }

        /// <summary>
        /// Stops the run. An outstanding mutation becomes a sticky Unknown poison and every later transition is
        /// refused. Without an outstanding mutation the known receipts stay exactly as they are, so the outer
        /// orchestrator can still report the prior verified slots.
        /// </summary>
        internal void Interrupt()
        {
            if (_pending == PendingMutation.None)
            {
                return;
            }

            _interrupted = true;
            _writeState = InternalInstallWriteState.Unknown;
        }

        /// <summary>
        /// Caches a verified Android acceptance once. Later absent, unauthorized, initialization and rejected
        /// results never downgrade the Android fact, and a non-verified result is never cached as verified.
        /// </summary>
        internal void RememberAndroidAcceptance(InternalAndroidAcceptanceResult? result)
        {
            if (result is null || !result.Verified)
            {
                return;
            }

            _androidAcceptance ??= result;
        }

        private void AddVerifiedSlot(string slot)
        {
            if (!_verifiedSlots.Contains(slot))
            {
                _verifiedSlots.Add(slot);
            }
        }

        private void ClearPending()
        {
            _pending = PendingMutation.None;
            _pendingStage = null;
            _pendingSlot = null;
        }

        private static void RequireKnownStage(InternalInstallStage stage)
        {
            if (!Enum.IsDefined(stage) || stage == InternalInstallStage.Completed)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(stage), stage, "The run never produces an unknown or completed stage.");
            }
        }

        private static void RequireMutationStage(InternalInstallStage stage)
        {
            if (stage == InternalInstallStage.Prepared)
            {
                throw new ArgumentException("Prepared issues no mutation.", nameof(stage));
            }
        }

        private static void RequireRawWriteSlot(InternalInstallStage stage, string? slot)
        {
            if (slot is not null && slot is not ("a" or "b"))
            {
                throw new ArgumentException("A raw write slot is only null, \"a\" or \"b\".", nameof(slot));
            }

            if (stage == InternalInstallStage.WritingBootA && slot != "a")
            {
                throw new ArgumentException("WritingBootA requires slot \"a\".", nameof(slot));
            }

            if (stage == InternalInstallStage.WritingBootB && slot != "b")
            {
                throw new ArgumentException("WritingBootB requires slot \"b\".", nameof(slot));
            }
        }

        private void RequireNotInterrupted()
        {
            if (_interrupted)
            {
                throw new InvalidOperationException(
                    "The run is poisoned by an unresolved mutation and accepts no further transition.");
            }
        }

        private void RequireNoPending()
        {
            if (_pending != PendingMutation.None)
            {
                throw new InvalidOperationException(
                    "A mutation is still pending and must be resolved before the run can continue.");
            }
        }
    }

    // ------------------------------------------------------------------ EX002: actual EDL phases

    private const int BcbCommandBytes = 32;
    private const int BcbRecoveryOffset = 64;
    private const int BcbRecoveryBytes = 768;
    private const int BcbFixedHeaderBytes = 2048;

    private static readonly byte[] InstallBcbCommand = Encoding.ASCII.GetBytes("boot-recovery");

    // Actual newline bytes, never the two-character sequence "\n".
    private static readonly byte[] InstallBcbRecovery =
        Encoding.ASCII.GetBytes("recovery\n--wipe_data\n--reason=armada-internal-install\n");

    private static readonly byte[] AcceptedPendingBcbCommand = Encoding.ASCII.GetBytes("bootonce-bootloader");

    private int _executionFileSequence;

    /// <summary>
    /// Publishes the run's current stage and proven write state as the new immutable snapshot, then reports the
    /// matching progress outside the lock. A throwing observer is ignored because it is not part of the install;
    /// nothing here runs a command, logs or holds a token.
    /// </summary>
    private void PublishExecution(
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        InternalInstallProgressKind kind,
        string? slot = null,
        long completedBytes = 0,
        long totalBytes = 0,
        string? detail = null,
        InternalInstallIoPhase? ioPhase = null,
        long? ioCompletedBytes = null,
        long? ioTotalBytes = null)
    {
        ArgumentNullException.ThrowIfNull(run);

        InternalInstallStage stage;
        InternalInstallWriteState writeState;

        lock (_gate)
        {
            _executionStarted = true;
            stage = run.Stage;
            writeState = run.WriteState;

            _snapshot = new InternalInstallSnapshot(
                true,
                stage,
                writeState,
                null,
                InternalInstallUserAction.None,
                _context.EvidenceDirectory,
                run.AndroidDataMayBeErased);
        }

        if (progress is null)
        {
            return;
        }

        try
        {
            progress.Report(new InternalInstallProgress(
                stage, kind, writeState, slot, completedBytes, totalBytes, detail)
            {
                IoPhase = ioPhase,
                IoCompletedBytes = ioCompletedBytes,
                IoTotalBytes = ioTotalBytes,
            });
        }
        catch
        {
            // A progress observer never changes install state and never turns a step into a failure.
        }
    }

    /// <summary>
    /// Synchronous adapter from the client's transfer observation to the install progress contract. It never
    /// queues or captures a synchronization context, so a report is delivered while the command pump calls it
    /// and cannot outlive the operation.
    /// </summary>
    private sealed class ExecutionEdlProgress : IProgress<EdlTransferProgress>
    {
        private readonly Action<EdlTransferProgress> _report;

        public ExecutionEdlProgress(Action<EdlTransferProgress> report)
        {
            _report = report;
        }

        public void Report(EdlTransferProgress value) => _report(value);
    }

    /// <summary>
    /// The one raw-write path of the initial EDL phase: validate the fixed region, persist the intent, mark the
    /// run Unknown, write exactly once, keep the acknowledged write pending, read the same range into a new
    /// evidence file, prove that file's own length and whole-stream SHA-256, and only then verify the readback.
    /// Any failure after the intent poisons the run through <see cref="ExecutionRun.Interrupt"/> and is
    /// re-thrown; no retry, reset or replay exists here.
    /// </summary>
    private async Task WriteExecutionRegionAsync(
        EdlClient client,
        ExecutionRun run,
        InternalInstallStage stage,
        string? slot,
        InternalArtifactRegion region,
        bool mayEraseAndroid,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(region);

        RequireRegionAgainstGeometry(region);

        string token = ReceiptToken(stage, slot, region.Role);

        WriteExecutionReceipt(
            token + ".intent.json",
            stage,
            slot,
            region,
            phase: "intent",
            acceptedAck: false,
            readbackPath: null,
            observedSha256: null);

        var payload = new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);

        ExecutionEdlProgress? transferProgress = progress is null
            ? null
            : new ExecutionEdlProgress(data =>
            {
                InternalInstallIoPhase? ioPhase = (data.Direction, data.Phase) switch
                {
                    (EdlTransferDirection.Write, EdlTransferPhase.CheckingInput) =>
                        InternalInstallIoPhase.CheckingPayload,
                    (EdlTransferDirection.Write, EdlTransferPhase.Transferring) =>
                        InternalInstallIoPhase.Writing,
                    (EdlTransferDirection.Read, EdlTransferPhase.Transferring) =>
                        InternalInstallIoPhase.ReadingBack,
                    (EdlTransferDirection.Read, EdlTransferPhase.CheckingOutput) =>
                        InternalInstallIoPhase.CheckingReadback,
                    _ => null,
                };

                if (ioPhase is null)
                {
                    return;
                }

                PublishExecution(
                    run,
                    progress,
                    InternalInstallProgressKind.Progress,
                    slot,
                    completedBytes: 0,
                    totalBytes: region.Length,
                    ioPhase: ioPhase,
                    ioCompletedBytes: data.Phase == EdlTransferPhase.Transferring
                        ? (long?)data.CompletedBytes
                        : null,
                    ioTotalBytes: region.Length);
            });

        string writeLogPrefix = NewExecutionEvidencePath(token + "-write", ".transfer");
        string readbackLogPrefix = NewExecutionEvidencePath(token + "-readback", ".transfer");

        try
        {
            // The run must be Unknown before the device command is even constructed, and an acknowledgement
            // alone never clears it.
            run.BeginRawWrite(stage, slot, mayEraseAndroid);
            PublishExecution(
                run,
                progress,
                InternalInstallProgressKind.Started,
                slot,
                completedBytes: 0,
                totalBytes: region.Length);

            EdlWriteEvidence acknowledgement = await client
                .WriteAsync(
                    region.Lun,
                    region.StartSector,
                    payload,
                    transferProgress,
                    writeLogPrefix,
                    cancellationToken)
                .ConfigureAwait(false);

            RequireWriteAcknowledgement(acknowledgement, region);

            WriteExecutionReceipt(
                token + ".ack.json",
                stage,
                slot,
                region,
                phase: "ack",
                acceptedAck: true,
                readbackPath: null,
                observedSha256: null);

            string readbackPath = NewExecutionEvidencePath(token + ".readback", ".bin");

            EdlReadEvidence readback = await client
                .ReadAsync(
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    readbackPath,
                    transferProgress,
                    readbackLogPrefix,
                    cancellationToken)
                .ConfigureAwait(false);

            string observedSha256 = await RequireReadbackAsync(
                    readback, region, readbackPath, cancellationToken)
                .ConfigureAwait(false);

            // The physical readback is already proven at this point; record it before the receipt file, so a
            // receipt-only failure cannot falsely report the write outcome as Unknown.
            run.VerifyRawReadback(stage, slot);

            WriteExecutionReceipt(
                token + ".verified.json",
                stage,
                slot,
                region,
                phase: "verified",
                acceptedAck: true,
                readbackPath: readbackPath,
                observedSha256: observedSha256);

            PublishExecution(
                run,
                progress,
                InternalInstallProgressKind.Verified,
                slot,
                completedBytes: region.Length,
                totalBytes: region.Length);
        }
        catch
        {
            run.Interrupt();
            throw;
        }
    }

    /// <summary>
    /// Binds a captured device region to the exact full-partition payload planned for it. The caller has
    /// already selected the only target; no path, role or geometry can arrive from an RPC or a caller guess.
    /// </summary>
    private static InternalArtifactRegion MakeExecutionRegion(
        EdlCapturedRegion target,
        VerifiedEdlFile payload,
        string role)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(role);

        if (target.StartSector < 0 || target.SectorCount <= 0)
        {
            throw new InvalidOperationException("The captured target region has no usable sector range.");
        }

        long expectedLength = CheckedRegionBytes(target.SectorCount, target.SectorSize);

        if (target.Length != expectedLength || payload.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The payload does not cover exactly the captured full-partition region.");
        }

        if (string.IsNullOrWhiteSpace(payload.Path))
        {
            throw new ArgumentException("The payload must have a non-blank path.", nameof(payload));
        }

        return new InternalArtifactRegion(
            role,
            target.Lun,
            target.StartSector,
            target.SectorCount,
            target.SectorSize,
            payload.Path,
            payload.Length,
            payload.Sha256);
    }

    /// <summary>
    /// Writes and fully reads back the maintenance boot, then the four GPT regions in array order and finally
    /// the fixed 1 GiB board archive. Each region carries its own verified receipt; a later failure leaves the
    /// run Unknown instead of marking the whole GPT stage complete. No reset or revalidation happens here.
    /// </summary>
    private async Task WriteInitialEdlPhaseAsync(
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(run);

        EdlCapturedRegion bootA = RequireCapturedRegion("boot_a");
        InternalArtifactRegion maintenanceBoot = MakeExecutionRegion(
            bootA, _context.Assets.MaintenanceBoot, "boot_a");

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingMaintenanceBoot,
                "a",
                maintenanceBoot,
                false,
                progress,
                cancellationToken)
            .ConfigureAwait(false);

        foreach (InternalArtifactRegion region in _context.GptWriteRegions)
        {
            await WriteExecutionRegionAsync(
                    _initialEdl,
                    run,
                    InternalInstallStage.WritingGpt,
                    null,
                    region,
                    true,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await WriteExecutionRegionAsync(
                _initialEdl,
                run,
                InternalInstallStage.WritingBoardBackup,
                null,
                _context.BoardSummary,
                true,
                progress,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Issues the one normal reset. The reset request must actually be accepted, but an accepted request is
    /// not a boot identity: the stage is reported Started and never Verified. A throwing or non-accepted reset
    /// poisons the pending transition and is re-thrown without a retry.
    /// </summary>
    private async Task ResetExecutionAsync(
        EdlClient client,
        ExecutionRun run,
        InternalInstallStage stage,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(run);

        try
        {
            run.BeginNormalReset(stage);
            PublishExecution(run, progress, InternalInstallProgressKind.Started);

            EdlResetEvidence reset = await client.ResetAsync(cancellationToken).ConfigureAwait(false);

            if (reset is null || !reset.CommandAccepted)
            {
                throw new InvalidOperationException("The normal reset request was not accepted by the device.");
            }

            // The accepted acknowledgement is the known physical fact; record it in the run before the
            // receipt file write, so a later receipt-only failure cannot turn it back into Unknown.
            run.AcceptNormalReset();

            WriteNewJsonFile(
                Path.Combine(_context.EvidenceDirectory, "execution-" + stage + "-reset.accepted.json"),
                new
                {
                    phase = "accepted",
                    stage = stage.ToString(),
                    commandAccepted = true,
                    acceptedAck = true,
                });

            // A reset command is not an operating-system identity, so this stays a Started report.
            PublishExecution(run, progress, InternalInstallProgressKind.Started);
        }
        catch
        {
            run.Interrupt();
            throw;
        }
    }

    /// <summary>
    /// Reads the whole fresh misc partition (its own geometry, its own evidence file) after the RAM session and
    /// overlays only the boot-command block and the recovery bytes of the first rounded 2 KiB write unit.
    /// <para>
    /// The fresh misc bytes are deliberately never compared with the pre-install backup: bootcontrol may have
    /// changed them legitimately. Every non-BCB byte of the write unit - status, stage/reserved, padding and
    /// any suffix - is preserved exactly. The overlay is a new CreateNew file with its own whole-file SHA-256
    /// and is then written and read back only over that unit. No reset happens here.
    /// </para>
    /// </summary>
    private async Task WriteFreshMiscAsync(
        EdlClient freshClient,
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(freshClient);
        ArgumentNullException.ThrowIfNull(run);

        EdlCapturedRegion target = RequireCapturedRegion("misc");

        string freshPath = NewExecutionEvidencePath("fresh-misc", ".bin");

        EdlReadEvidence fresh = await freshClient
            .ReadAsync(target.Lun, target.StartSector, target.SectorCount, freshPath, cancellationToken)
            .ConfigureAwait(false);

        await RequireFreshMiscReadAsync(fresh, target, freshPath, cancellationToken).ConfigureAwait(false);

        int writeUnitBytes = CheckedWriteUnitBytes(target.SectorSize);

        byte[] freshUnit = await ReadFirstExecutionBytesAsync(freshPath, writeUnitBytes, cancellationToken)
            .ConfigureAwait(false);

        byte[] overlay = BuildInstallBcbWriteUnit(freshUnit, target.SectorSize);

        string overlayPath = NewExecutionEvidencePath("misc-bcb", ".bin");
        string overlaySha256 = await WriteNewExecutionBytesAsync(overlayPath, overlay, cancellationToken)
            .ConfigureAwait(false);

        var region = new InternalArtifactRegion(
            "misc",
            target.Lun,
            target.StartSector,
            writeUnitBytes / target.SectorSize,
            target.SectorSize,
            overlayPath,
            overlay.Length,
            overlaySha256);

        await WriteExecutionRegionAsync(
                freshClient,
                run,
                InternalInstallStage.WritingMisc,
                null,
                region,
                true,
                progress,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// The bounded, pure BCB overlay builder for one rounded write unit.
    /// <list type="number">
    /// <item>Only 512- and 4096-byte sectors are supported.</item>
    /// <item>The input must be exactly one unit: <c>ceil(2048 / sectorSize) * sectorSize</c> bytes.</item>
    /// <item>The 32-byte command block must be either all zero or exactly <c>bootonce-bootloader</c> padded
    /// with zeros; any other pending command is refused.</item>
    /// <item>The 768 recovery bytes at offset 64 must be all zero; a foreign pending recovery is refused.</item>
    /// <item>Only bytes 0..32 and 64..832 are replaced; status, stage/reserved, padding and every suffix byte
    /// are preserved exactly.</item>
    /// <item>The input array is never modified; a new array is returned.</item>
    /// </list>
    /// </summary>
    internal static byte[] BuildInstallBcbWriteUnit(byte[] freshWriteUnit, int sectorSize)
    {
        ArgumentNullException.ThrowIfNull(freshWriteUnit);

        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new ArgumentOutOfRangeException(
                nameof(sectorSize), sectorSize, "Only 512- and 4096-byte sectors are supported.");
        }

        int requiredBytes = CheckedWriteUnitBytes(sectorSize);

        if (freshWriteUnit.Length != requiredBytes)
        {
            throw new ArgumentException(
                "The fresh BCB write unit must be exactly one rounded 2048-byte unit.", nameof(freshWriteUnit));
        }

        RequireAcceptedBcbPendingCommand(freshWriteUnit);
        RequireEmptyBcbRecovery(freshWriteUnit);

        byte[] output = (byte[])freshWriteUnit.Clone();

        Array.Clear(output, 0, BcbCommandBytes);
        InstallBcbCommand.CopyTo(output, 0);

        Array.Clear(output, BcbRecoveryOffset, BcbRecoveryBytes);
        InstallBcbRecovery.CopyTo(output, BcbRecoveryOffset);

        return output;
    }

    private void RequireRegionAgainstGeometry(InternalArtifactRegion region)
    {
        if (string.IsNullOrWhiteSpace(region.Role))
        {
            throw new ArgumentException("The region must have a non-blank role.", nameof(region));
        }

        if (string.IsNullOrWhiteSpace(region.FilePath))
        {
            throw new ArgumentException("The region must have a non-blank payload path.", nameof(region));
        }

        if (!IsSha256Text(region.Sha256))
        {
            throw new ArgumentException("The region payload SHA-256 must be 64 hexadecimal characters.", nameof(region));
        }

        if (region.SectorSize < 512 || (region.SectorSize & (region.SectorSize - 1)) != 0)
        {
            throw new ArgumentException("The region sector size is not a supported power of two.", nameof(region));
        }

        if (!_context.Geometries.TryGetValue(region.Lun, out EdlGeometry? geometry) || geometry is null)
        {
            throw new InvalidOperationException(
                "The device geometry of LUN " + region.Lun + " is not part of this preparation.");
        }

        if (geometry.Lun != region.Lun || geometry.SectorSize != region.SectorSize)
        {
            throw new InvalidOperationException(
                "The region sector size does not match the probed geometry of LUN " + region.Lun + ".");
        }

        if (region.StartSector < 0 || region.SectorCount <= 0)
        {
            throw new InvalidOperationException("The region has no usable sector range.");
        }

        long expectedLength = CheckedRegionBytes(region.SectorCount, region.SectorSize);

        if (region.Length != expectedLength || region.Length % region.SectorSize != 0)
        {
            throw new InvalidOperationException(
                "The region length is not exactly its sector count times its sector size.");
        }

        long endSector = CheckedRegionAdd(region.StartSector, region.SectorCount);

        if (endSector > geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                "The region ends at sector " + endSector + ", beyond LUN " + region.Lun + "'s "
                + geometry.TotalSectors + " sectors.");
        }
    }

    private EdlCapturedRegion RequireCapturedRegion(string role)
    {
        if (!_context.BackupFiles.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
        {
            throw new InvalidOperationException("The captured backup set has no '" + role + "' region.");
        }

        if (region.Lun < 0 || region.StartSector < 0 || region.SectorCount <= 0 || region.SectorSize <= 0)
        {
            throw new InvalidOperationException("The captured '" + role + "' region is not usable.");
        }

        return region;
    }

    private static void RequireWriteAcknowledgement(
        EdlWriteEvidence evidence,
        InternalArtifactRegion region)
    {
        if (evidence is null
            || evidence.Geometry is null
            || evidence.Geometry.Lun != region.Lun
            || evidence.Geometry.SectorSize != region.SectorSize
            || evidence.StartSector != region.StartSector
            || evidence.SectorCount != region.SectorCount
            || evidence.Length != region.Length
            || !SameSha256(evidence.Sha256, region.Sha256))
        {
            throw new InvalidOperationException(
                "The acknowledged write does not match the requested region's geometry, range, length or SHA-256.");
        }
    }

    private static async Task<string> RequireReadbackAsync(
        EdlReadEvidence evidence,
        InternalArtifactRegion region,
        string readbackPath,
        CancellationToken cancellationToken)
    {
        if (evidence is null
            || evidence.Geometry is null
            || evidence.Geometry.Lun != region.Lun
            || evidence.Geometry.SectorSize != region.SectorSize
            || evidence.StartSector != region.StartSector
            || evidence.SectorCount != region.SectorCount
            || evidence.Length != region.Length
            || !SameSha256(evidence.Sha256, region.Sha256)
            || !SameEvidencePath(evidence.FilePath, readbackPath))
        {
            throw new InvalidOperationException(
                "The readback does not match the requested region's geometry, range, length, file or SHA-256.");
        }

        long actualLength = new FileInfo(readbackPath) is { Exists: true } info ? info.Length : -1;

        if (actualLength != region.Length)
        {
            throw new InvalidOperationException("The readback evidence file does not have the expected length.");
        }

        string actualSha256;
        using (var stream = new FileStream(
            readbackPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan))
        {
            actualSha256 = Convert.ToHexString(
                await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        }

        if (!SameSha256(actualSha256, evidence.Sha256) || !SameSha256(actualSha256, region.Sha256))
        {
            throw new InvalidOperationException(
                "The readback evidence file's own SHA-256 does not match the written region.");
        }

        return actualSha256;
    }

    private static async Task<string> RequireFreshMiscReadAsync(
        EdlReadEvidence evidence,
        EdlCapturedRegion target,
        string freshPath,
        CancellationToken cancellationToken)
    {
        long expectedLength = CheckedRegionBytes(target.SectorCount, target.SectorSize);

        if (evidence is null
            || evidence.Geometry is null
            || evidence.Geometry.Lun != target.Lun
            || evidence.Geometry.SectorSize != target.SectorSize
            || evidence.StartSector != target.StartSector
            || evidence.SectorCount != target.SectorCount
            || evidence.Length != expectedLength
            || !IsSha256Text(evidence.Sha256)
            || !SameEvidencePath(evidence.FilePath, freshPath))
        {
            throw new InvalidOperationException(
                "The fresh misc read does not match the captured misc geometry and range.");
        }

        long actualLength = new FileInfo(freshPath) is { Exists: true } info ? info.Length : -1;

        if (actualLength != expectedLength)
        {
            throw new InvalidOperationException("The fresh misc evidence file does not have the expected length.");
        }

        string actualSha256;
        using (var stream = new FileStream(
            freshPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan))
        {
            actualSha256 = Convert.ToHexString(
                await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        }

        // Only this fresh evidence is authoritative; the old backup hash is never compared here.
        if (!SameSha256(actualSha256, evidence.Sha256))
        {
            throw new InvalidOperationException(
                "The fresh misc evidence file's own SHA-256 does not match its read evidence.");
        }

        return actualSha256;
    }

    private static async Task<byte[]> ReadFirstExecutionBytesAsync(
        string path,
        int count,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[count];

        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);

        int offset = 0;
        while (offset < count)
        {
            int read = await stream
                .ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                throw new IOException("The fresh misc evidence file is shorter than one write unit.");
            }

            offset += read;
        }

        return buffer;
    }

    private static async Task<string> WriteNewExecutionBytesAsync(
        string path,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await stream.WriteAsync(bytes.AsMemory(0, bytes.Length), cancellationToken).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        using (var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan))
        {
            return Convert.ToHexString(
                await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        }
    }

    private void WriteExecutionReceipt(
        string fileName,
        InternalInstallStage stage,
        string? slot,
        InternalArtifactRegion region,
        string phase,
        bool acceptedAck,
        string? readbackPath,
        string? observedSha256)
    {
        WriteNewJsonFile(
            Path.Combine(_context.EvidenceDirectory, fileName),
            new
            {
                phase,
                stage = stage.ToString(),
                slot,
                lun = region.Lun,
                startSector = region.StartSector,
                sectorCount = region.SectorCount,
                length = region.Length,
                sha256 = region.Sha256,
                path = region.FilePath,
                acceptedAck,
                readbackPath,
                observedSha256,
            });
    }

    private static void WriteNewJsonFile(string path, object content)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(content);

        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private string NewExecutionEvidencePath(string stem, string extension)
    {
        int sequence = Interlocked.Increment(ref _executionFileSequence);
        string name = SanitizeFileToken(stem) + "-"
            + sequence.ToString(CultureInfo.InvariantCulture) + extension;

        return Path.Combine(_context.EvidenceDirectory, name);
    }

    private static string ReceiptToken(InternalInstallStage stage, string? slot, string role)
    {
        string token = "execution-" + stage;

        if (slot is not null)
        {
            token += "-" + slot;
        }

        return SanitizeFileToken(token + "-" + role);
    }

    private static string SanitizeFileToken(string value)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);

        foreach (char character in value)
        {
            builder.Append(Array.IndexOf(invalid, character) >= 0 ? '_' : character);
        }

        return builder.ToString();
    }

    private static int CheckedWriteUnitBytes(int sectorSize)
    {
        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new InvalidOperationException("Only 512- and 4096-byte sectors can carry the BCB overlay.");
        }

        int sectors = (BcbFixedHeaderBytes + sectorSize - 1) / sectorSize;

        return checked(sectors * sectorSize);
    }

    private static void RequireAcceptedBcbPendingCommand(byte[] freshWriteUnit)
    {
        ReadOnlySpan<byte> command = freshWriteUnit.AsSpan(0, BcbCommandBytes);

        if (IsAllZero(command))
        {
            return;
        }

        if (!command.StartsWith(AcceptedPendingBcbCommand)
            || !IsAllZero(command.Slice(AcceptedPendingBcbCommand.Length)))
        {
            throw new InvalidOperationException(
                "The fresh misc command block is neither empty nor exactly 'bootonce-bootloader' with zero padding.");
        }
    }

    private static void RequireEmptyBcbRecovery(byte[] freshWriteUnit)
    {
        ReadOnlySpan<byte> recovery = freshWriteUnit.AsSpan(BcbRecoveryOffset, BcbRecoveryBytes);

        if (!IsAllZero(recovery))
        {
            throw new InvalidOperationException(
                "The fresh misc recovery block is not empty; a foreign pending recovery is refused.");
        }
    }

    private static bool IsAllZero(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSha256Text(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    private static bool SameSha256(string? left, string? right) =>
        !string.IsNullOrEmpty(left)
        && !string.IsNullOrEmpty(right)
        && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool SameEvidencePath(string? left, string right)
    {
        if (string.IsNullOrEmpty(left))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static long CheckedRegionBytes(long sectorCount, int sectorSize)
    {
        try
        {
            long length = checked(sectorCount * sectorSize);

            if (length <= 0)
            {
                throw new InvalidOperationException("The region byte length is not positive.");
            }

            return length;
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException("The region byte length overflows a 64-bit count.", exception);
        }
    }

    private static long CheckedRegionAdd(long startSector, long sectorCount)
    {
        try
        {
            return checked(startSector + sectorCount);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException("The region sector range overflows a 64-bit count.", exception);
        }
    }

    // ------------------------------------------------------------------ EX003: actual RAM session

    private const string Restart2ReturnedCode = "ram-restart2-returned";

    private const int ExecutionCatalogBindings = 10;

    private static readonly string[] ExecutionSourceRoles =
    {
        "currentBoot",
        "vendorBoot",
        "initBoot",
        "abl",
        "xblConfig",
    };

    private static readonly string[] ExecutionSourceKeys =
    {
        "current_boot",
        "vendor_boot",
        "init_boot",
        "abl",
        "xbl_config",
    };

    private static readonly RamInstallExportRole[] ExecutionExportOrder =
    {
        RamInstallExportRole.BootB,
        RamInstallExportRole.BootA,
        RamInstallExportRole.ReportB,
        RamInstallExportRole.ReportA,
    };

    /// <summary>
    /// The fixed RAM request of this install: the full planned post-GPT table, the planned userdata end, the
    /// three ARMADA PARTUUIDs, the frozen seed and the boot block built only from the same captured slots.
    /// </summary>
    private RamInstallRequest CreateExecutionRamRequest(RamInstallSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        GptTable table = _context.PostGpt;
        var partitions = new List<ExpectedPartition>(table.Partitions.Count);

        foreach (GptPartition partition in table.Partitions)
        {
            partitions.Add(new ExpectedPartition(
                partition.Number,
                partition.Name,
                partition.StartSector,
                partition.SectorCount,
                partition.TypeGuid,
                partition.PartUuid));
        }

        var expectedTable = new ExpectedTable(table.SectorSize, table.DiskBytes, table.DiskGuid, partitions);

        return new RamInstallRequest(
            session,
            checked((int)Prepared.AndroidGiB),
            _context.Allocation.OriginalUserdataEndSectorExclusive,
            _context.LinuxBoot.PartUuid,
            _context.LinuxRoot.PartUuid,
            _context.BackupPartition.PartUuid,
            expectedTable,
            _context.Package.Seed,
            CreateExecutionBootConfig());
    }

    private RamInstallBootConfig CreateExecutionBootConfig()
    {
        VerifiedEdlFile runtime = RequireExecutionPayload("runtime");

        return new RamInstallBootConfig(
            CreateExecutionBootSlot("a"),
            CreateExecutionBootSlot("b"),
            new RamInstallFileIdentity(runtime.Length, runtime.Sha256.ToLowerInvariant()),
            new RamInstallLinuxArtifacts(
                CreateExecutionFileIdentity(RequireExecutionPayload("kernel")),
                CreateExecutionFileIdentity(RequireExecutionPayload("dtb")),
                CreateExecutionFileIdentity(RequireExecutionPayload("initramfs"))));
    }

    private static RamInstallFileIdentity CreateExecutionFileIdentity(VerifiedEdlFile file) =>
        new(file.Length, file.Sha256.ToLowerInvariant());

    private RamInstallBootSlot CreateExecutionBootSlot(string slot) => new(
        CreateExecutionMaterial(slot, "boot_" + slot),
        CreateExecutionMaterial(slot, "vendor_boot_" + slot),
        CreateExecutionMaterial(slot, "init_boot_" + slot),
        CreateExecutionMaterial(slot, "abl_" + slot),
        CreateExecutionMaterial(slot, "xbl_config_" + slot));

    private RamInstallPartitionMaterial CreateExecutionMaterial(string slot, string key)
    {
        EdlCapturedRegion capture = RequireCapturedRegion(key);

        if (string.IsNullOrWhiteSpace(capture.PartUuid))
        {
            throw new InvalidOperationException("The captured '" + key + "' region carries no PARTUUID.");
        }

        return new RamInstallPartitionMaterial(
            slot,
            capture.PartUuid,
            capture.Length,
            capture.Sha256.ToLowerInvariant());
    }

    private VerifiedEdlFile RequireExecutionPayload(string role)
    {
        if (!_context.Package.Payloads.TryGetValue(role, out VerifiedEdlFile? file) || file is null)
        {
            throw new InvalidOperationException("The verified package has no '" + role + "' payload.");
        }

        if (string.IsNullOrWhiteSpace(file.Path) || file.Length <= 0)
        {
            throw new InvalidOperationException("The verified '" + role + "' payload is not usable.");
        }

        return file;
    }

    /// <summary>
    /// Binds the client-validated read-only source catalog to this PC's captured slots: the same ten roles,
    /// the same PARTUUID/range/size/length as the 52-file backup, one unique original GPT row per UUID, and a
    /// one-to-one LUN/parent join against the probed geometries. No content hash is claimed here.
    /// </summary>
    private void ValidateExecutionSourceCatalog(JsonElement catalog)
    {
        if (catalog.ValueKind != JsonValueKind.Object
            || !catalog.TryGetProperty("parents", out JsonElement parentsElement)
            || parentsElement.ValueKind != JsonValueKind.Array
            || !catalog.TryGetProperty("bindings", out JsonElement bindingsElement)
            || bindingsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("The RAM source catalog is not a measured parents/bindings document.");
        }

        var parents = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (JsonElement parent in parentsElement.EnumerateArray())
        {
            string device = RequireExecutionString(parent, "device");
            if (!parents.TryAdd(device, parent))
            {
                throw new InvalidOperationException("The RAM source catalog repeats a parent device.");
            }
        }

        var parentByLun = new Dictionary<int, string>();
        var lunByParent = new Dictionary<string, int>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        int count = 0;

        foreach (JsonElement binding in bindingsElement.EnumerateArray())
        {
            count++;
            if (count > ExecutionCatalogBindings || binding.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException("The RAM source catalog carries more than ten bindings.");
            }

            string slot = RequireExecutionString(binding, "slot");
            if (!string.Equals(slot, "a", StringComparison.Ordinal)
                && !string.Equals(slot, "b", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("A RAM source binding names no fixed boot slot.");
            }

            int roleIndex = Array.IndexOf(ExecutionSourceRoles, RequireExecutionString(binding, "role"));
            if (roleIndex < 0)
            {
                throw new InvalidOperationException("A RAM source binding names no fixed boot role.");
            }

            string key = ExecutionKey(slot, roleIndex);
            if (!keys.Add(key))
            {
                throw new InvalidOperationException("The RAM source catalog repeats the '" + key + "' binding.");
            }

            RequireExecutionFalse(binding, "contentRead");

            if (!string.Equals(RequireExecutionString(binding, "label"), key, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The RAM source binding label is not the captured partition name.");
            }

            EdlCapturedRegion capture = RequireCapturedRegion(key);

            // The GPT formatter emits uppercase GUIDs and the catalog keeps the original form, so GUID
            // identity is compared case-insensitively throughout.
            if (!string.Equals(
                    RequireExecutionUuid(binding, "partUuid"),
                    capture.PartUuid,
                    StringComparison.OrdinalIgnoreCase)
                || RequireExecutionLong(binding, "startSector") != capture.StartSector
                || RequireExecutionLong(binding, "sectorCount") != capture.SectorCount
                || RequireExecutionInt(binding, "sectorSize") != capture.SectorSize
                || RequireExecutionLong(binding, "length") != capture.Length)
            {
                throw new InvalidOperationException(
                    "The RAM source binding of '" + key + "' does not match the captured partition.");
            }

            long number = RequireExecutionLong(binding, "number");
            if (!_context.OriginalTables.TryGetValue(capture.Lun, out GptTable? original) || original is null)
            {
                throw new InvalidOperationException("The original table of the '" + key + "' LUN is missing.");
            }

            bool rowFound = false;
            foreach (GptPartition row in original.Partitions)
            {
                if (!string.Equals(row.PartUuid, capture.PartUuid, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (rowFound)
                {
                    throw new InvalidOperationException("The original table repeats the '" + key + "' UUID.");
                }

                rowFound = true;

                if (row.Number != number || !string.Equals(row.Name, key, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The RAM source binding number or label is not the original table row of '" + key + "'.");
                }
            }

            if (!rowFound)
            {
                throw new InvalidOperationException("The original table has no row for the '" + key + "' UUID.");
            }

            string parentDevice = RequireExecutionString(binding, "parentDevice");
            if (!parents.TryGetValue(parentDevice, out JsonElement parent) || parent.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException("A RAM source binding names no observed parent device.");
            }

            if (!_context.Geometries.TryGetValue(capture.Lun, out EdlGeometry? geometry) || geometry is null)
            {
                throw new InvalidOperationException("The probed geometry of the '" + key + "' LUN is missing.");
            }

            long diskBytes = CheckedRegionBytes(geometry.TotalSectors, geometry.SectorSize);

            if (RequireExecutionInt(parent, "sectorSize") != geometry.SectorSize
                || RequireExecutionLong(parent, "diskBytes") != diskBytes)
            {
                throw new InvalidOperationException(
                    "The observed parent of '" + key + "' does not match the probed LUN geometry.");
            }

            if (parentByLun.TryGetValue(capture.Lun, out string? knownParent))
            {
                if (!string.Equals(knownParent, parentDevice, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("One captured LUN maps to more than one observed parent.");
                }
            }
            else
            {
                parentByLun.Add(capture.Lun, parentDevice);
            }

            if (lunByParent.TryGetValue(parentDevice, out int knownLun))
            {
                if (knownLun != capture.Lun)
                {
                    throw new InvalidOperationException("One observed parent maps to more than one captured LUN.");
                }
            }
            else
            {
                lunByParent.Add(parentDevice, capture.Lun);
            }
        }

        if (count != ExecutionCatalogBindings || keys.Count != ExecutionCatalogBindings)
        {
            throw new InvalidOperationException("The RAM source catalog does not carry exactly ten bindings.");
        }

        foreach (string slot in new[] { "a", "b" })
        {
            for (int roleIndex = 0; roleIndex < ExecutionSourceRoles.Length; roleIndex++)
            {
                if (!keys.Contains(ExecutionKey(slot, roleIndex)))
                {
                    throw new InvalidOperationException(
                        "The RAM source catalog is missing the '" + ExecutionKey(slot, roleIndex) + "' binding.");
                }
            }
        }
    }

    /// <summary>
    /// Cross-checks the client's validated build proof against the same slot material the PC prepared. Only
    /// the measured numeric/hash facts are compared; the evidence and formula prose is cross-language text.
    /// </summary>
    private void ValidateExecutionBuiltMaterials(RamInstallBuiltBoots built)
    {
        ArgumentNullException.ThrowIfNull(built);

        ValidateExecutionBuiltSlot("a", built.Slots.A);
        ValidateExecutionBuiltSlot("b", built.Slots.B);
    }

    private void ValidateExecutionBuiltSlot(string slotName, RamInstallBuiltSlot built)
    {
        ArgumentNullException.ThrowIfNull(built);

        if (!string.Equals(built.Slot, slotName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("A built slot does not carry its frozen slot name.");
        }

        if (!_context.SlotMaterials.TryGetValue(slotName, out InternalSlotMaterial? material) || material is null)
        {
            throw new InvalidOperationException("The prepared slot material of '" + slotName + "' is missing.");
        }

        JsonElement stock = RequireExecutionObject(built.BuilderReport, "stock_image");
        if (RequireExecutionLong(stock, "length") != material.BaseImageLength
            || !SameSha256(RequireLowerExecutionHash(stock, "sha256"), material.BaseImageSha256))
        {
            throw new InvalidOperationException("The builder stock image is not the prepared base image.");
        }

        JsonElement slotMaterial = RequireExecutionObject(built.BuilderReport, "slot_material");

        if (!string.Equals(RequireExecutionString(slotMaterial, "slot"), slotName, StringComparison.Ordinal)
            || RequireExecutionBool(slotMaterial, "is_kshim") != material.IsKshim)
        {
            throw new InvalidOperationException("The built slot material identity does not match the prepared slot.");
        }

        JsonElement baseImage = RequireExecutionObject(slotMaterial, "base_image");
        if (RequireExecutionLong(baseImage, "length") != material.BaseImageLength
            || !SameSha256(RequireLowerExecutionHash(baseImage, "sha256"), material.BaseImageSha256))
        {
            throw new InvalidOperationException("The built base image is not the prepared base image.");
        }

        JsonElement ramdisks = RequireExecutionObject(slotMaterial, "ramdisks");
        if (RequireExecutionLong(ramdisks, "boot_ramdisk_size") != material.BootRamdiskSize
            || RequireExecutionLong(ramdisks, "vendor_ramdisk_size") != material.VendorRamdiskSize
            || RequireExecutionLong(ramdisks, "init_ramdisk_size") != material.InitRamdiskSize
            || RequireExecutionLong(ramdisks, "total_ramdisk_size") != material.TotalRamdiskSize
            || RequireExecutionInt(ramdisks, "page_size") != material.PageSize)
        {
            throw new InvalidOperationException("The built ramdisk sizes are not the prepared slot sizes.");
        }

        JsonElement budget = RequireExecutionObject(slotMaterial, "loader_budget");
        if (!string.Equals(
                RequireExecutionString(budget, "profile"),
                material.LoaderBudget.Profile,
                StringComparison.Ordinal)
            || RequireExecutionLong(budget, "max_raw_bytes") != material.LoaderBudget.MaxRawBytes
            || RequireExecutionBool(budget, "known_loader_match") != material.LoaderBudget.KnownLoaderMatch)
        {
            throw new InvalidOperationException("The built loader budget is not the prepared loader budget.");
        }

        JsonElement sourceSha = RequireExecutionObject(slotMaterial, "source_sha256");
        JsonElement sourceLengths = RequireExecutionObject(slotMaterial, "source_lengths");

        foreach (string key in ExecutionSourceKeys)
        {
            if (!material.SourceSha256.TryGetValue(key, out string? expectedSha)
                || !material.SourceLengths.TryGetValue(key, out long expectedLength))
            {
                throw new InvalidOperationException("The prepared slot material lacks the '" + key + "' source fact.");
            }

            if (!string.Equals(RequireLowerExecutionHash(sourceSha, key), expectedSha, StringComparison.Ordinal)
                || RequireExecutionLong(sourceLengths, key) != expectedLength)
            {
                throw new InvalidOperationException("The built source material is not the prepared source material.");
            }
        }
    }

    /// <summary>
    /// Brings up the real RAM session over the sole bounded maintenance serial interface, proves its fresh
    /// identity, initializes the fixed request and validates the measured source catalog. All mutations and
    /// the finish happen inside this scope; the console stays open until the method returns.
    /// </summary>
    private async Task<(EdlClient Client, VerifiedEdlFile BootB, VerifiedEdlFile BootA)> RunRamAndReturnEdlAsync(
        ExecutionRun run,
        List<FileStream> heldExports,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(heldExports);

        if (!OperatingSystem.IsWindows())
        {
            throw new InvalidOperationException("The RAM maintenance session is only available on Windows.");
        }

        run.StartStage(InternalInstallStage.BootingRam);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        try
        {
            using var discovery = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            discovery.CancelAfter(TimeSpan.FromMinutes(3));

            string portName;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                IReadOnlyList<MaintenanceSerialPort> candidates = MaintenanceSerialDiscovery.ReadWindows();
                if (candidates.Count > 1)
                {
                    throw new InvalidOperationException(
                        "More than one maintenance serial interface is present; no port is guessed.");
                }

                if (candidates.Count == 1)
                {
                    portName = candidates[0].PortName;
                    break;
                }

                try
                {
                    await Task.Delay(500, discovery.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        "The maintenance serial interface did not appear within three minutes.");
                }
            }

            await using var console = new WindowsMaintenanceConsole(portName);
            await console.OpenAsync(cancellationToken).ConfigureAwait(false);

            var bootstrap = new MaintenanceBootstrap(console, new TcpMaintenanceTransfer());
            using RamInstallSupport support = await RamInstallSupport
                .LoadAsync(_context.Assets.SupportArchive, cancellationToken)
                .ConfigureAwait(false);

            RamInstallSession session = await bootstrap
                .PrepareInstallAsync(
                    _context.Assets.ToolboxBundle,
                    support,
                    Prepared.SocSerial,
                    cancellationToken)
                .ConfigureAwait(false);

            WriteNewJsonFile(
                NewExecutionEvidencePath("ram-session", ".json"),
                new
                {
                    model = session.Model,
                    soc = session.Soc,
                    socSerial = session.SocSerial,
                    bootId = session.BootId,
                });

            run.VerifyStage(InternalInstallStage.BootingRam);
            PublishExecution(run, progress, InternalInstallProgressKind.Verified);

            RamInstallRequest request = CreateExecutionRamRequest(session);
            var client = new RamInstallClient(session, request);

            _ = await WriteNewExecutionBytesAsync(
                    NewExecutionEvidencePath("ram-request", ".json"),
                    request.CopyRequestBytes(),
                    cancellationToken)
                .ConfigureAwait(false);

            await client.InitializeAsync(cancellationToken).ConfigureAwait(false);

            JsonElement catalog = client.BootSourceCatalog
                ?? throw new InvalidOperationException("The RAM install session produced no source catalog.");

            ValidateExecutionSourceCatalog(catalog);

            _ = await WriteNewExecutionBytesAsync(
                    NewExecutionEvidencePath("ram-source-catalog", ".json"),
                    Encoding.UTF8.GetBytes(catalog.GetRawText()),
                    cancellationToken)
                .ConfigureAwait(false);

            await RunRamPrepareSeedDeployAsync(client, run, progress, cancellationToken).ConfigureAwait(false);

            RamInstallBuiltBoots built = await RunRamBuildAsync(client, run, progress, cancellationToken)
                .ConfigureAwait(false);

            (VerifiedEdlFile bootB, VerifiedEdlFile bootA) = await RunRamExportAsync(
                    client,
                    built,
                    run,
                    heldExports,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);

            return await FinishRamAndReturnEdlAsync(client, run, bootB, bootA, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            run.Interrupt();
            throw;
        }
    }

    /// <summary>
    /// The two filesystem identities the prepare job actually observed and created. They are the only baseline
    /// the later deploy proof repeats; a PARTUUID is never substituted for them.
    /// </summary>
    private readonly struct ExecutionFilesystems
    {
        internal ExecutionFilesystems(string boot, string root)
        {
            Boot = boot;
            Root = root;
        }

        internal string Boot { get; }

        internal string Root { get; }
    }

    /// <summary>
    /// Validates the measured prepare result before the prepare stage is verified: the two PARTUUIDs are the
    /// planned Linux boot and root, and both actual filesystem UUIDs exist.
    /// </summary>
    private ExecutionFilesystems ValidateExecutionPrepareResult(RamInstallJob prepare)
    {
        JsonElement result = prepare.Result
            ?? throw new InvalidOperationException("The prepare job carries no result object.");

        JsonElement boot = RequireExecutionObject(result, "boot");
        JsonElement root = RequireExecutionObject(result, "root");

        if (!string.Equals(
                RequireExecutionUuid(boot, "partuuid"),
                _context.LinuxBoot.PartUuid,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                RequireExecutionUuid(root, "partuuid"),
                _context.LinuxRoot.PartUuid,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The prepare job did not operate on the planned Linux boot and root partitions.");
        }

        return new ExecutionFilesystems(
            RequireExecutionUuid(boot, "filesystem_uuid"),
            RequireExecutionUuid(root, "filesystem_uuid"));
    }

    /// <summary>
    /// Validates the measured deploy result before the deploy stage is verified: the committed seed and both
    /// filesystems are the ones this run actually prepared.
    /// </summary>
    private void ValidateExecutionDeployResult(RamInstallJob deploy, ExecutionFilesystems prepared)
    {
        JsonElement result = deploy.Result
            ?? throw new InvalidOperationException("The deploy job carries no result object.");

        if (!string.Equals(
                RequireLowerExecutionHash(result, "deployment_checksum"),
                _context.Package.Seed.Commit,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The deploy job did not commit the prepared seed.");
        }

        JsonElement filesystems = RequireExecutionObject(result, "filesystem_uuids");

        if (!string.Equals(
                RequireExecutionUuid(filesystems, "boot"),
                prepared.Boot,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                RequireExecutionUuid(filesystems, "root"),
                prepared.Root,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The deploy job did not use the filesystems the prepare job created.");
        }
    }

    /// <summary>
    /// The three independent first RAM jobs. Each begin marks the run Unknown and publishes Started before
    /// the single start; only the authoritative succeeded/exit-0 status may verify the job.
    /// </summary>
    private async Task RunRamPrepareSeedDeployAsync(
        RamInstallClient client,
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        run.BeginRamMutation(InternalInstallStage.PreparingFilesystems, mayEraseAndroid: false);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        await client.StartPrepareAsync(cancellationToken).ConfigureAwait(false);
        RamInstallJob prepare = await client
            .WaitForCompletionAsync(RamInstallAction.Prepare, TimeSpan.FromMinutes(10), cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(prepare, "prepare");
        ExecutionFilesystems filesystems = ValidateExecutionPrepareResult(prepare);
        run.VerifyRamJob(InternalInstallStage.PreparingFilesystems);
        WriteExecutionJobReceipt("ram-prepare", prepare);
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);

        run.BeginRamMutation(InternalInstallStage.ReceivingSeed, mayEraseAndroid: true);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        await client.StartReceiveSeedAsync(cancellationToken).ConfigureAwait(false);

        VerifiedEdlFile seed = RequireExecutionPayload("ostree-seed");
        using (var content = new FileStream(
            seed.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            FileOptions.SequentialScan))
        {
            await client
                .TransferSeedAsync(
                    content,
                    new ExecutionTransferProgress(this, run, progress),
                    TimeSpan.FromHours(2),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        // Read-only single status for the saved receipt; the transfer already proved the authoritative job.
        RamInstallJob received = await client
            .GetStatusAsync(RamInstallAction.ReceiveSeed, cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(received, "receive-seed");
        run.VerifyRamJob(InternalInstallStage.ReceivingSeed);
        WriteExecutionJobReceipt("ram-receive-seed", received);
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);

        run.BeginRamMutation(InternalInstallStage.Deploying, mayEraseAndroid: true);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        await client.StartDeployAsync(cancellationToken).ConfigureAwait(false);
        RamInstallJob deploy = await client
            .WaitForCompletionAsync(RamInstallAction.Deploy, TimeSpan.FromMinutes(30), cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(deploy, "deploy");
        ValidateExecutionDeployResult(deploy, filesystems);
        run.VerifyRamJob(InternalInstallStage.Deploying);
        WriteExecutionJobReceipt("ram-deploy", deploy);
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);
    }

    /// <summary>
    /// The two fixed material uploads and the single build job, verified only after the complete typed proof
    /// matches this PC's prepared slot material.
    /// </summary>
    private async Task<RamInstallBuiltBoots> RunRamBuildAsync(
        RamInstallClient client,
        ExecutionRun run,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        run.BeginRamMutation(InternalInstallStage.BuildingCandidates, mayEraseAndroid: false);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        EdlCapturedRegion bootA = RequireCapturedRegion("boot_a");
        var original = new VerifiedEdlFile(bootA.FilePath, bootA.Length, bootA.Sha256.ToLowerInvariant());
        var transfer = new ExecutionTransferProgress(this, run, progress);

        RamInstallJob originalJob = await client
            .ReceiveOriginalBootAAsync(original, transfer, TimeSpan.FromMinutes(20), cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(originalJob, "receive-original-boot-a");

        RamInstallJob runtimeJob = await client
            .ReceiveRuntimeAsync(
                RequireExecutionPayload("runtime"),
                transfer,
                TimeSpan.FromMinutes(20),
                cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(runtimeJob, "receive-runtime");

        await client.StartBuildBootsAsync(cancellationToken).ConfigureAwait(false);
        RamInstallJob build = await client
            .WaitForCompletionAsync(RamInstallAction.BuildBoots, TimeSpan.FromMinutes(30), cancellationToken)
            .ConfigureAwait(false);

        RequireExecutionJobSucceeded(build, "build-boots");

        RamInstallBuiltBoots built = await client.GetBuiltBootsAsync(cancellationToken).ConfigureAwait(false);
        ValidateExecutionBuiltMaterials(built);
        run.VerifyRamJob(InternalInstallStage.BuildingCandidates);
        WriteExecutionBuiltReceipt(built);

        PublishExecution(run, progress, InternalInstallProgressKind.Verified);
        return built;
    }

    /// <summary>
    /// The four fixed exports in the frozen order. Each actual output is held read-only immediately and its
    /// own length and whole-stream hash are proven before the run advances.
    /// </summary>
    private async Task<(VerifiedEdlFile BootB, VerifiedEdlFile BootA)> RunRamExportAsync(
        RamInstallClient client,
        RamInstallBuiltBoots built,
        ExecutionRun run,
        List<FileStream> heldExports,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(built);

        run.BeginRamMutation(InternalInstallStage.ExportingCandidates, mayEraseAndroid: false);
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        var transfer = new ExecutionTransferProgress(this, run, progress);
        var claims = new Dictionary<RamInstallExportRole, VerifiedEdlFile>();

        foreach (RamInstallExportRole role in ExecutionExportOrder)
        {
            RamInstallBuiltFile artifact = built.GetArtifact(role);
            string path = NewExecutionEvidencePath("ram-export-" + role, ".bin");

            VerifiedEdlFile file = await client
                .ExportAsync(role, path, transfer, TimeSpan.FromMinutes(20), cancellationToken)
                .ConfigureAwait(false);

            if (file.Length != artifact.Length
                || !SameSha256(file.Sha256, artifact.Sha256)
                || !SameEvidencePath(file.Path, path))
            {
                throw new InvalidOperationException(
                    "The export claim does not match the locked build artifact '" + role + "'.");
            }

            var lease = new FileStream(
                file.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                FileOptions.SequentialScan);

            // The lease is owned by the caller's list immediately, so an outer finally always releases it.
            heldExports.Add(lease);
            await RequireExecutionExportLeaseAsync(lease, file, cancellationToken).ConfigureAwait(false);

            claims.Add(role, file);
            WriteNewJsonFile(
                NewExecutionEvidencePath("ram-export-" + role, ".json"),
                new
                {
                    role = role.ToString(),
                    length = file.Length,
                    sha256 = file.Sha256,
                    path = file.Path,
                });
        }

        run.VerifyRamJob(InternalInstallStage.ExportingCandidates);
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);
        return (claims[RamInstallExportRole.BootB], claims[RamInstallExportRole.BootA]);
    }

    private static async Task RequireExecutionExportLeaseAsync(
        FileStream lease,
        VerifiedEdlFile claim,
        CancellationToken cancellationToken)
    {
        if (lease.Length != claim.Length)
        {
            throw new InvalidOperationException("The held export file does not have the claimed length.");
        }

        string actual = Convert.ToHexString(await SHA256.HashDataAsync(lease, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();

        if (!SameSha256(actual, claim.Sha256))
        {
            throw new InvalidOperationException("The held export file does not match the claimed SHA-256.");
        }

        lease.Position = 0;
    }

    /// <summary>
    /// The single finish attempt and the fresh EDL entry it may cause. Only a genuine initial Sahara probe
    /// plus the full post-partition proof resolves the finish; a RESTART2 result is a known failure.
    /// </summary>
    private async Task<(EdlClient Client, VerifiedEdlFile BootB, VerifiedEdlFile BootA)> FinishRamAndReturnEdlAsync(
        RamInstallClient client,
        ExecutionRun run,
        VerifiedEdlFile bootB,
        VerifiedEdlFile bootA,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        run.BeginFinish();
        PublishExecution(run, progress, InternalInstallProgressKind.Started);

        RamInstallFinishAttempt attempt = await client.StartFinishAsync(cancellationToken).ConfigureAwait(false);

        switch (attempt.State)
        {
            case RamInstallFinishAttemptState.Restart2Returned:
                run.FinishReturned();
                throw new ExecutionFailureException(
                    Restart2ReturnedCode,
                    "the RAM helper reported RESTART2 returned (errno "
                    + (attempt.Errno ?? 0).ToString(CultureInfo.InvariantCulture)
                    + ", return code "
                    + (attempt.ReturnCode ?? 0).ToString(CultureInfo.InvariantCulture)
                    + ")");

            case RamInstallFinishAttemptState.Requested:
            case RamInstallFinishAttemptState.AcknowledgementUnknown:
                // Requested or lost acknowledgement both stay Unknown until the fresh EDL proof exists.
                run.FinishMayHaveReset();
                break;

            default:
                throw new InvalidOperationException("The finish attempt reported an unknown state.");
        }

        EdlEntryResult binding = await _services.EdlEntry
            .WaitForPresentAsync(_deviceCheck.Android!, cancellationToken)
            .ConfigureAwait(false);

        var fresh = new EdlClient(
            _initialEdl.Toolchain,
            binding,
            _services.CommandRunner,
            _services.EndpointDiscovery);

        await fresh.ProbeAsync(0, true, cancellationToken).ConfigureAwait(false);
        await _context.VerifyPostPartitionDeviceAsync(fresh, "return-edl", cancellationToken).ConfigureAwait(false);

        run.VerifyFreshEdlTransition();
        PublishExecution(run, progress, InternalInstallProgressKind.Verified);
        return (fresh, bootB, bootA);
    }

    private static void RequireExecutionJobSucceeded(RamInstallJob job, string name)
    {
        if (job.State != RamInstallJobState.Succeeded
            || job.ExitCode != 0
            || job.HasError
            || job.Result is not { } result
            || result.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "The " + name + " job did not succeed with a result object.");
        }
    }

    private void WriteExecutionJobReceipt(string stem, RamInstallJob job)
    {
        WriteNewJsonFile(
            NewExecutionEvidencePath(stem, ".json"),
            new
            {
                action = job.Action,
                state = job.State.ToString(),
                exitCode = job.ExitCode,
                result = job.Result,
            });
    }

    private void WriteExecutionBuiltReceipt(RamInstallBuiltBoots built)
    {
        WriteNewJsonFile(
            NewExecutionEvidencePath("ram-built", ".json"),
            new
            {
                deploymentChecksum = built.DeploymentChecksum,
                bootFilesystemUuid = built.BootFilesystemUuid,
                rootFilesystemUuid = built.RootFilesystemUuid,
                slots = new[]
                {
                    ExecutionBuiltSlotReceipt("a", built.Slots.A),
                    ExecutionBuiltSlotReceipt("b", built.Slots.B),
                },
            });
    }

    private static object ExecutionBuiltSlotReceipt(string slot, RamInstallBuiltSlot built) => new
    {
        slot,
        candidateLength = built.Candidate.Length,
        candidateSha256 = built.Candidate.Sha256,
        reportLength = built.Report.Length,
        reportSha256 = built.Report.Sha256,
        builderReport = built.BuilderReport,
    };

    private static string ExecutionKey(string slot, int roleIndex)
    {
        string prefix = roleIndex switch
        {
            0 => "boot_",
            1 => "vendor_boot_",
            2 => "init_boot_",
            3 => "abl_",
            4 => "xbl_config_",
            _ => throw new ArgumentOutOfRangeException(nameof(roleIndex)),
        };

        return prefix + slot;
    }

    private static string RequireExecutionString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(value.GetString()))
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' is not a string.");
        }

        return value.GetString()!;
    }

    private static long RequireExecutionLong(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt64(out long result))
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' is not an integer.");
        }

        return result;
    }

    private static int RequireExecutionInt(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt32(out var result))
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' is not a 32-bit integer.");
        }

        return result;
    }

    private static bool RequireExecutionBool(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement value)
            || (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' is not a boolean.");
        }

        return value.ValueKind == JsonValueKind.True;
    }

    private static void RequireExecutionFalse(JsonElement element, string name)
    {
        if (RequireExecutionBool(element, name))
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' must be false.");
        }
    }

    private static JsonElement RequireExecutionObject(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("The measured RAM fact '" + name + "' is not an object.");
        }

        return value;
    }

    private static string RequireLowerExecutionHash(JsonElement element, string name)
    {
        string value = RequireExecutionString(element, name);
        if (!RamInstallValidation.IsLowerSha256(value))
        {
            throw new InvalidOperationException("The measured RAM digest '" + name + "' is not lowercase SHA-256.");
        }

        return value;
    }

    private static string RequireExecutionUuid(JsonElement element, string name)
    {
        string value = RequireExecutionString(element, name);
        if (!Guid.TryParseExact(value, "D", out Guid guid) || guid == Guid.Empty)
        {
            throw new InvalidOperationException("The measured RAM identity '" + name + "' is not a non-empty canonical UUID.");
        }

        return guid.ToString("D");
    }

    /// <summary>
    /// Direct synchronous adapter that forwards a transfer's own byte counters as a Started report of the
    /// current stage. Progress only: it never verifies a transfer and never keeps queued state.
    /// </summary>
    private sealed class ExecutionTransferProgress : IProgress<RamInstallSeedProgress>
    {
        private readonly InternalInstallBackend _backend;
        private readonly ExecutionRun _run;
        private readonly IProgress<InternalInstallProgress>? _progress;

        internal ExecutionTransferProgress(
            InternalInstallBackend backend,
            ExecutionRun run,
            IProgress<InternalInstallProgress>? progress)
        {
            _backend = backend;
            _run = run;
            _progress = progress;
        }

        public void Report(RamInstallSeedProgress value)
        {
            if (value is null)
            {
                return;
            }

            try
            {
                _backend.PublishExecution(
                    _run,
                    _progress,
                    InternalInstallProgressKind.Started,
                    completedBytes: value.SentBytes,
                    totalBytes: value.TotalBytes);
            }
            catch
            {
                // A progress observer never changes install state.
            }
        }
    }

    /// <summary>Small fixed diagnostic failure that carries a stable code and no remote text.</summary>
    private sealed class ExecutionFailureException : Exception
    {
        internal ExecutionFailureException(string code, string message)
            : base(code + ": " + message)
        {
            Code = code;
        }

        internal string Code { get; }
    }
}
