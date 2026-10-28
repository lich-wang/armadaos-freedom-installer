using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The single public execution entry of the boot-maintenance backend and the small write-state gates behind it.
/// <para>
/// <see cref="ExecuteAsync"/> runs the privately prepared plan exactly once: it re-hashes every held source and
/// current capture, repeats the fresh six-LUN probe and the full current-region readback, then writes each
/// planned stock candidate whole, reads each region back, and finishes with exactly one accepted normal reset.
/// Every transition records only a fact the backend actually observed: the write state is marked
/// <see cref="InternalInstallWriteState.Unknown"/> immediately before any device invocation, and only a matching
/// readback or an accepted reset restores a proven state. No path here retries, rolls back or claims an
/// operating-system acceptance; the OS first boot stays a user hint, never a success blocker.
/// </para>
/// </summary>
public sealed partial class BootMaintenanceBackend
{
    private const string ExecutionCancelledCode = "execution-cancelled";

    private const string ExecutionFailedCode = "execution-failed";

    private const string ExecutionUnknownWriteCode = "execution-write-outcome-unknown";

    /// <summary>The stage actually being executed; snapshot and error details retain it verbatim.</summary>
    private InternalInstallStage _currentStage = InternalInstallStage.Prepared;

    /// <summary>The reset acceptance actually observed from real reset evidence; null before any reset.</summary>
    private bool? _resetAccepted;

    /// <summary>
    /// Getter-only observed reset fact: null until real reset evidence exists, then the actual
    /// <see cref="EdlResetEvidence.CommandAccepted"/> value — never a guess or parsed error text.
    /// </summary>
    internal bool? ObservedResetAccepted
    {
        get
        {
            lock (_gate)
            {
                return _resetAccepted;
            }
        }
    }

    /// <summary>
    /// The boot-control attention fact actually yielded by the recovery misc reader; false until a
    /// recovery-policy read produces it — never inferred from an error or a public setter.
    /// </summary>
    private bool _needsBootloaderAttention;

    /// <summary>Getter-only observed recovery fact: false until the actual recovery reader yields it.</summary>
    internal bool ObservedNeedsBootloaderAttention
    {
        get
        {
            lock (_gate)
            {
                return _needsBootloaderAttention;
            }
        }
    }

    /// <summary>
    /// Executes the prepared BeforeUpdate/RestoreStock pass once. The exact confirmation id from the prepared
    /// data must be supplied; anything else is rejected before the one-shot is consumed and before any I/O.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The confirmation id is wrong (<c>boot-maintenance-confirmation-mismatch</c>), the backend is already
    /// executing or already executed (<c>boot-maintenance-execution-conflict</c>,
    /// <c>boot-maintenance-already-executed</c>), a freshness check failed
    /// (<c>boot-maintenance-freshness-mismatch</c>) or an issued write/reset outcome cannot be established
    /// (<c>execution-write-outcome-unknown</c>).
    /// </exception>
    public async Task<BootMaintenanceResult> ExecuteAsync(
        string confirmationId,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!_mode.HasValue)
        {
            throw new InvalidOperationException(
                "An internal TF-plan backend instance carries no maintenance pass and cannot run "
                + "through the public maintenance entry.");
        }

        RegionExecutionResult result = await ExecutePlanAsync(
            confirmationId, progress, cancellationToken).ConfigureAwait(false);
        return new BootMaintenanceResult(
            result.Outcome,
            result.WriteState,
            result.VerifiedRegions,
            result.EvidenceDirectory,
            result.Error,
            awaitingAndroidAcceptance: result.Outcome == BootMaintenanceOutcome.Completed);
    }

    /// <summary>
    /// Internal TF execution entry: refuses real maintenance instances before the one-shot is consumed
    /// and before any I/O, otherwise runs the exact same private plan body. It never constructs or
    /// returns a <see cref="BootMaintenanceResult"/>.
    /// </summary>
    internal Task<RegionExecutionResult> ExecuteTfPlanAsync(
        string confirmationId,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (_mode.HasValue)
        {
            throw new InvalidOperationException(
                "A real maintenance backend instance cannot use the internal TF execution entry.");
        }

        return ExecutePlanAsync(confirmationId, progress, cancellationToken);
    }

    private async Task<RegionExecutionResult> ExecutePlanAsync(
        string confirmationId,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (confirmationId is null)
        {
            throw new ArgumentNullException(nameof(confirmationId));
        }

        // A caller that already cancelled is admitted nowhere: the one-shot is not consumed and the backend
        // stays Prepared/NoneIssued exactly as the factory left it.
        cancellationToken.ThrowIfCancellationRequested();

        // The gate and the confirmation check run before anything else; a wrong id never consumes the one-shot
        // and never touches a device or a file.
        lock (_gate)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BootMaintenanceBackend));
            }

            if (_executing)
            {
                throw new InvalidOperationException(
                    ExecutionConflictCode + ": this pass is already executing.");
            }

            if (_hasExecuted)
            {
                throw new InvalidOperationException(
                    AlreadyExecutedCode + ": this boot-maintenance pass already ran once and cannot run again.");
            }

            if (!string.Equals(confirmationId, _confirmationSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    ConfirmationMismatchCode + ": the supplied confirmation does not match the prepared pass.");
            }

            _executing = true;
        }

        var verified = new List<string>();
        var sink = new ProgressSink(progress);
        bool mutationIssued = false;
        long verifiedBytes = 0;
        long plannedWriteBytes = 0;
        foreach (PlannedRegion region in _plan)
        {
            if (region.WillWrite)
            {
                checked
                {
                    plannedWriteBytes += region.Length;
                }
            }
        }

        string? error = null;
        BootMaintenanceOutcome outcome;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            MarkExecutionStarted();

            // ------------------------------------------------------ local revalidation before any write
            sink.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Started,
                InternalInstallWriteState.NoneIssued,
                null,
                0,
                0,
                "revalidating-held-files"));

            await RevalidateHeldFilesAsync(cancellationToken).ConfigureAwait(false);

            await ProbeSixLunsAsync(_client, _ownedCurrent, cancellationToken).ConfigureAwait(false);
            await ReadbackEveryCurrentRegionAsync(
                _client, _ownedCurrent, _evidenceDirectory, sink, cancellationToken).ConfigureAwait(false);

            // The origin facts and the static binding are re-checked, not assumed: the pass must still
            // belong to the verified device it was prepared for. No ADB or fastboot command exists here.
            await RequireDeviceFactsAsync(_deviceFacts, _client, cancellationToken).ConfigureAwait(false);
            RequireSameCapture(_ownedCurrent, _callerBackup);

            // The misc partition was just re-read from the device and hashed back to the held capture
            // above, so its fresh control bytes are actual facts: the pass may only run when the device
            // still sits in the exact slot prepared for and the misc control hash is unchanged. On the
            // Android route the Step-1 slot guard additionally re-verified its own current slot. Any misc
            // change after preparation is refused here, before the first write, as NoneIssued.
            VerifiedEdlFile miscClaim = RegionClaim(_ownedCurrent.Files, "misc", "the current rollback capture");
            Task<BootSlotControlFacts> miscFactsTask = _executionPolicy == RegionExecutionPolicy.TfRestorePrevious
                ? BootSlotControl.ReadForRecoveryAsync(miscClaim, cancellationToken)
                : BootSlotControl.ReadAsync(miscClaim, cancellationToken);
            BootSlotControlFacts miscFacts = await miscFactsTask.ConfigureAwait(false);

            lock (_gate)
            {
                _needsBootloaderAttention = miscFacts.NeedsBootloaderAttention;
            }

            if (!string.Equals(miscFacts.ControlSha256, _miscControlSha256, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(miscFacts.CurrentSlot, _currentSlot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    FreshnessCode + ": the freshly read misc control no longer matches the prepared pass "
                    + "(slot '" + miscFacts.CurrentSlot + "', control sha " + miscFacts.ControlSha256
                    + "); no write or reset may be issued.");
            }

            // Same fresh capture, modern virtual A/B message: the OTA must still be factually Completed
            // at execution time. Gate failure throws before the first write loop iteration, so the existing
            // catch path records NoneIssued and no write or reset is ever issued. SourceSlot is provenance
            // only and never the active slot.
            BootVirtualAbControlFacts virtualAbFacts = await BootVirtualAbControl
                .ReadAsync(
                    RegionClaim(_ownedCurrent.Files, "misc", "the current rollback capture"),
                    cancellationToken)
                .ConfigureAwait(false);

            if (!virtualAbFacts.IsFormatValid || virtualAbFacts.State != BootVirtualAbState.Completed)
            {
                throw new InvalidOperationException(
                    "boot-maintenance-ota-not-completed: the fresh misc virtual A/B state is "
                    + virtualAbFacts.State + " (format valid: " + virtualAbFacts.IsFormatValid
                    + "); no write or reset may be issued before the OTA merge is Completed.");
            }

            if (_deviceFacts.AndroidCheck is not null
                && !string.Equals(
                    RequireCurrentSlot(_deviceFacts.AndroidCheck), _currentSlot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    FreshnessCode + ": the device no longer reports the current slot the pass was prepared for.");
            }

            if (_mode == MaintenanceMode.AfterUpdate)
            {
                await RevalidateAfterInputsAsync(cancellationToken).ConfigureAwait(false);
            }

            // ------------------------------------------------------ writes
            foreach (PlannedRegion region in _plan)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!region.WillWrite)
                {
                    continue;
                }

                if (_writeState == InternalInstallWriteState.Unknown)
                {
                    throw new InvalidOperationException(
                        ExecutionUnknownWriteCode + ": an earlier write outcome is unknown; no later write or "
                        + "reset may be issued.");
                }

                sink.Report(new InternalInstallProgress(
                    RegionStage(region),
                    InternalInstallProgressKind.Started,
                    _snapshot.WriteState,
                    region.Slot,
                    0,
                    region.Length,
                    region.Role));

                // A durable "requested" record is written before the first write API request. A disk failure
                // here is a failure before any mutation: no write was issued and nothing is Unknown.
                WriteRegionReceipt(region, kind: "write-requested", readbackVerified: false, evidence: null);

                // Marked immediately before invocation: an ACK that never arrives can never look like "no write".
                cancellationToken.ThrowIfCancellationRequested();
                SetStateUnknown(RegionStage(region));
                mutationIssued = true;

                // Any exception past this point - including a cancellation surfacing mid-invocation - leaves
                // the outcome unproven and keeps Unknown; it is never downgraded by a late callback.
                IProgress<EdlTransferProgress> transferObserver = CreateTransferObserver(region, sink);

                await _client.WriteAsync(
                    region.Lun,
                    region.StartSector,
                    new VerifiedEdlFile(region.CandidatePath!, region.Length, region.CandidateSha256!),
                    transferObserver,
                    Path.Combine(_evidenceDirectory, "write-" + region.Role + "-cmd"),
                    cancellationToken).ConfigureAwait(false);

                WriteRegionReceipt(region, kind: "write-ack", readbackVerified: false, evidence: null);

                // ACK alone never clears Unknown: only the fresh readback below does. A cancellation during the
                // readback is read-only, but the preceding write stays unproven, so Unknown stands.
                string readbackPath = Path.Combine(
                    _evidenceDirectory,
                    "readback-" + Guid.NewGuid().ToString("N") + "-" + region.Role + ".bin");

                EdlReadEvidence evidence = await ReadbackWrittenRegionAsync(
                    region, readbackPath, transferObserver, cancellationToken).ConfigureAwait(false);

                verified.Add(region.Role);
                checked
                {
                    verifiedBytes += region.Length;
                }
                lock (_gate)
                {
                    _writeState = InternalInstallWriteState.PartiallyVerified;
                    _snapshot = new BootMaintenanceSnapshot(
                        _executionStarted,
                        RegionStage(region),
                        InternalInstallWriteState.PartiallyVerified,
                        _snapshot.Outcome,
                        _snapshot.Error);
                }

                // The known actual state is set before any later receipt I/O.
                WriteRegionReceipt(
                    region, kind: "write-verified", readbackVerified: true, evidence: evidence);

                sink.Report(new InternalInstallProgress(
                    RegionStage(region),
                    InternalInstallProgressKind.Verified,
                    InternalInstallWriteState.PartiallyVerified,
                    region.Slot,
                    region.Length,
                    region.Length,
                    region.Role));
            }

            // ------------------------------------------------------ one normal reset
            sink.Report(new InternalInstallProgress(
                InternalInstallStage.Restarting,
                InternalInstallProgressKind.Started,
                _snapshot.WriteState,
                null,
                verifiedBytes,
                plannedWriteBytes,
                "reset"));

            WriteResetReceipt(kind: "reset-requested", accepted: false);

            // An already cancelled token must not pretend the reset was issued: the check runs before the
            // Unknown mark and before the client call.
            cancellationToken.ThrowIfCancellationRequested();
            SetStateUnknown(InternalInstallStage.Restarting);
            mutationIssued = true;

            EdlResetEvidence reset = await _client.ResetAsync(cancellationToken).ConfigureAwait(false);

            // Fact observed from real reset evidence, recorded before any acceptance decision or receipt.
            lock (_gate)
            {
                _resetAccepted = reset.CommandAccepted;
            }

            if (!reset.CommandAccepted)
            {
                throw new InvalidOperationException(
                    ExecutionFailedCode + ": the reset was not accepted by the device.");
            }

            WriteResetReceipt(kind: "reset-accepted", accepted: true);

            lock (_gate)
            {
                _writeState = InternalInstallWriteState.AllVerified;
                _snapshot = new BootMaintenanceSnapshot(
                    _executionStarted,
                    InternalInstallStage.Restarting,
                    InternalInstallWriteState.AllVerified,
                    _snapshot.Outcome,
                    _snapshot.Error);
            }

            // ------------------------------------------------------ complete
            outcome = BootMaintenanceOutcome.Completed;
            error = null;

            sink.Report(new InternalInstallProgress(
                InternalInstallStage.InstallationCompleted,
                InternalInstallProgressKind.Verified,
                InternalInstallWriteState.AllVerified,
                null,
                verifiedBytes,
                plannedWriteBytes,
                "boot-maintenance-completed-os-acceptance-pending"));
        }
        catch (OperationCanceledException)
        {
            // Before any invocation this is NoneIssued/Cancelled; once a write or reset was issued without
            // proof the state is Unknown and the outcome can never be Cancelled or Failed.
            if (_writeState == InternalInstallWriteState.Unknown)
            {
                outcome = BootMaintenanceOutcome.UnknownWriteOutcome;
                error = ExecutionUnknownWriteCode + " [" + _currentStage + "]"
                    + ": the pass was cancelled while an issued write or reset outcome was still unproven.";
            }
            else
            {
                outcome = BootMaintenanceOutcome.Cancelled;
                error = ExecutionCancelledCode + ": the pass was cancelled before any unproven mutation.";
            }

            sink.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Cancelled,
                _writeState,
                null,
                verifiedBytes,
                plannedWriteBytes,
                error));
        }
        catch (Exception exception)
        {
            string detail = string.IsNullOrWhiteSpace(exception.Message)
                ? exception.GetType().Name
                : exception.Message;

            if (_writeState == InternalInstallWriteState.Unknown)
            {
                outcome = BootMaintenanceOutcome.UnknownWriteOutcome;
                error = ExecutionUnknownWriteCode + " [" + _currentStage + "]: " + detail;
            }
            else
            {
                outcome = BootMaintenanceOutcome.Failed;
                error = ExecutionFailedCode + " [" + _currentStage + "]: " + detail;
            }

            sink.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Failed,
                _writeState,
                null,
                verifiedBytes,
                plannedWriteBytes,
                error));
        }
        finally
        {
            lock (_gate)
            {
                _executing = false;
                _hasExecuted = true;
            }
        }

        InternalInstallWriteState resultState = outcome switch
        {
            BootMaintenanceOutcome.Completed => InternalInstallWriteState.AllVerified,
            BootMaintenanceOutcome.UnknownWriteOutcome => InternalInstallWriteState.Unknown,
            _ => mutationIssued
                ? InternalInstallWriteState.PartiallyVerified
                : InternalInstallWriteState.NoneIssued,
        };

        lock (_gate)
        {
            _writeState = resultState;
            _snapshot = new BootMaintenanceSnapshot(
                executionStarted: _executionStarted,
                StageFor(outcome),
                resultState,
                outcome,
                error);
        }

        WriteExecutionReceipt(outcome, resultState, verified, error);

        return new RegionExecutionResult(
            outcome,
            resultState,
            verified,
            _evidenceDirectory,
            error);
    }

    // ------------------------------------------------------------------ state gates and helpers

    private void MarkExecutionStarted()
    {
        lock (_gate)
        {
            _executionStarted = true;
            _currentStage = InternalInstallStage.Revalidating;
            _snapshot = new BootMaintenanceSnapshot(
                executionStarted: true,
                _currentStage,
                _snapshot.WriteState,
                _snapshot.Outcome,
                _snapshot.Error);
        }
    }

    /// <summary>Marks the intent Unknown before a device invocation; only real evidence clears it.</summary>
    private void SetStateUnknown(InternalInstallStage stage)
    {
        lock (_gate)
        {
            _currentStage = stage;
            _writeState = InternalInstallWriteState.Unknown;
            _snapshot = new BootMaintenanceSnapshot(
                _executionStarted,
                stage,
                InternalInstallWriteState.Unknown,
                _snapshot.Outcome,
                _snapshot.Error);
        }
    }

    private static InternalInstallStage RegionStage(PlannedRegion region) =>
        region.Role switch
        {
            "efisp" => InternalInstallStage.WritingGblRuntime,
            _ => region.Role.StartsWith("boot_", StringComparison.Ordinal)
                ? (region.Slot == "a"
                    ? InternalInstallStage.WritingBootA
                    : InternalInstallStage.WritingBootB)
                : InternalInstallStage.WritingAvbMetadata,
        };

    /// <summary>
    /// Operation-scoped synchronous transfer observer for one planned region: maps the transport phases onto
    /// the display phases (write checking/transferring, read transferring/output), reports the actual region
    /// stage, slot and role with the live snapshot write state, and reuses the sink's callback shielding.
    /// Proof bytes stay 0/total until this region's own readback verifies it; the Io counts stay transport
    /// observations and never prove a phase.
    /// </summary>
    private IProgress<EdlTransferProgress> CreateTransferObserver(PlannedRegion region, ProgressSink sink)
    {
        InternalInstallStage stage = RegionStage(region);
        long totalBytes = region.Length;

        return new SyncProgress<EdlTransferProgress>(value =>
        {
            InternalInstallIoPhase? phase = value.Phase switch
            {
                EdlTransferPhase.CheckingInput when value.Direction == EdlTransferDirection.Write
                    => InternalInstallIoPhase.CheckingPayload,
                EdlTransferPhase.Transferring when value.Direction == EdlTransferDirection.Write
                    => InternalInstallIoPhase.Writing,
                EdlTransferPhase.Transferring => InternalInstallIoPhase.ReadingBack,
                EdlTransferPhase.CheckingOutput when value.Direction == EdlTransferDirection.Read
                    => InternalInstallIoPhase.CheckingReadback,
                _ => null,
            };

            if (phase is null)
            {
                return;
            }

            InternalInstallWriteState writeState;
            lock (_gate)
            {
                writeState = _snapshot.WriteState;
            }

            sink.Report(new InternalInstallProgress(
                stage,
                InternalInstallProgressKind.Progress,
                writeState,
                region.Slot,
                0,
                totalBytes,
                region.Role)
            {
                IoPhase = phase,
                IoCompletedBytes = value.Phase == EdlTransferPhase.Transferring
                    ? value.CompletedBytes
                    : null,
                IoTotalBytes = totalBytes,
            });
        });
    }

    /// <summary>
    /// Reads the exact written range back and compares the whole length and SHA-256 with the candidate claim.
    /// A mismatch after an acknowledged write is a known failed verification, never an automatic retry. The
    /// caller receives the actual read evidence so the durable receipt can record the returned file and hash.
    /// </summary>
    private async Task<EdlReadEvidence> ReadbackWrittenRegionAsync(
        PlannedRegion region,
        string readbackPath,
        IProgress<EdlTransferProgress>? transferProgress,
        CancellationToken cancellationToken)
    {
        EdlReadEvidence evidence = await _client
            .ReadAsync(
                region.Lun,
                region.StartSector,
                region.SectorCount,
                readbackPath,
                transferProgress,
                Path.Combine(
                    _evidenceDirectory,
                    "readback-" + Guid.NewGuid().ToString("N") + "-" + region.Role + "-cmd"),
                cancellationToken)
            .ConfigureAwait(false);

        if (evidence.Geometry is null
            || evidence.Geometry.Lun != region.Lun
            || evidence.Geometry.SectorSize != _ownedCurrent.Geometries[region.Lun].SectorSize
            || evidence.StartSector != region.StartSector
            || evidence.SectorCount != region.SectorCount
            || evidence.Length != region.Length
            || !string.Equals(evidence.Sha256, region.CandidateSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                ExecutionFailedCode + ": the readback of '" + region.Role
                + "' does not match the written stock candidate (read " + evidence.Length + " bytes, sha "
                + evidence.Sha256 + "; expected " + region.Length + ", sha " + region.CandidateSha256
                + "); no retry is attempted.");
        }

        return evidence;
    }

    /// <summary>Re-hashes every held source and current capture file before the first write.</summary>
    private async Task RevalidateHeldFilesAsync(CancellationToken cancellationToken)
    {
        foreach ((string role, EdlCapturedRegion region) in _source.Files)
        {
            await RehashHeldFileAsync(
                region.FilePath, region.Length, region.Sha256, "source region '" + role + "'",
                cancellationToken).ConfigureAwait(false);
        }

        foreach ((string role, EdlCapturedRegion region) in _ownedCurrent.Files)
        {
            await RehashHeldFileAsync(
                region.FilePath, region.Length, region.Sha256, "current region '" + role + "'",
                cancellationToken).ConfigureAwait(false);
        }
    }

    // ------------------------------------------------------------------ execution receipts

    /// <summary>
    /// One durable per-action receipt. <paramref name="kind"/> separates what is actually known: a
    /// <c>write-requested</c> record is written before the first write API call and is never an ACK; only
    /// <c>write-ack</c> and <c>write-verified</c> carry the corresponding facts, and the verified record embeds
    /// the actual returned readback file and hash.
    /// </summary>
    private void WriteRegionReceipt(
        PlannedRegion region,
        string kind,
        bool readbackVerified,
        EdlReadEvidence? evidence)
    {
        try
        {
            WriteReceipt(_evidenceDirectory, kind + "-" + region.Role, writer =>
            {
                writer.WriteString("kind", kind);
                writer.WriteString("role", region.Role);
                writer.WriteString("slot", region.Slot);
                writer.WriteNumber("lun", region.Lun);
                writer.WriteNumber("startSector", region.StartSector);
                writer.WriteNumber("sectorCount", region.SectorCount);
                writer.WriteNumber("length", region.Length);
                writer.WriteString("currentSha256", region.CurrentSha256);
                writer.WriteString("candidateSha256", region.CandidateSha256);
                writer.WriteBoolean("writeAck", kind != "write-requested");
                writer.WriteBoolean("readbackVerified", readbackVerified);

                if (evidence is not null)
                {
                    writer.WriteString("readbackFilePath", evidence.FilePath);
                    writer.WriteString("readbackSha256", evidence.Sha256);
                    writer.WriteNumber("readbackLength", evidence.Length);
                }

                writer.WriteString("confirmationSha256", _confirmationSha256);
            });
        }
        catch (Exception) when (kind != "write-requested")
        {
            // A receipt failure after a verified readback must never corrupt the known actual state. Only
            // the "write-requested" record is mandatory: it must land before any mutation is issued, so its
            // failure propagates and fails the pass before the first write API request.
        }
    }

    private void WriteResetReceipt(string kind, bool accepted)
    {
        try
        {
            WriteReceipt(_evidenceDirectory, kind, writer =>
            {
                writer.WriteString("kind", kind);
                writer.WriteBoolean("accepted", accepted);
                writer.WriteString("confirmationSha256", _confirmationSha256);
            });
        }
        catch (Exception) when (kind != "reset-requested")
        {
            // "reset-requested" must land before the device reset; its failure propagates. Later reset
            // records are best-effort proof and never corrupt a known state.
        }
    }

    private void WriteExecutionReceipt(
        BootMaintenanceOutcome outcome,
        InternalInstallWriteState writeState,
        IReadOnlyList<string> verified,
        string? error)
    {
        try
        {
            WriteReceipt(_evidenceDirectory, "execution", writer =>
            {
                writer.WriteString("kind", "execution");
                writer.WriteString("outcome", outcome.ToString());
                writer.WriteString("writeState", writeState.ToString());
                writer.WriteString("confirmationSha256", _confirmationSha256);
                writer.WriteStartArray("verifiedRegions");
                foreach (string region in verified)
                {
                    writer.WriteStringValue(region);
                }

                writer.WriteEndArray();

                if (error is not null)
                {
                    writer.WriteString("error", error);
                }
            });
        }
        catch (Exception)
        {
        }
    }

    private static InternalInstallStage StageFor(BootMaintenanceOutcome outcome) =>
        outcome == BootMaintenanceOutcome.Completed
            ? InternalInstallStage.InstallationCompleted
            : InternalInstallStage.Revalidating;

    /// <summary>
    /// Shields the caller's progress sink: a callback exception is swallowed so it can never corrupt proof or
    /// trigger a retry. The sink itself is a plain synchronous <see cref="IProgress{InternalInstallProgress}"/>
    /// so the backend can also hand it to the shared revalidation helpers.
    /// </summary>
    private sealed class ProgressSink : IProgress<InternalInstallProgress>
    {
        private readonly IProgress<InternalInstallProgress>? _progress;

        internal ProgressSink(IProgress<InternalInstallProgress>? progress)
        {
            _progress = progress;
        }

        public void Report(InternalInstallProgress value)
        {
            if (_progress is null)
            {
                return;
            }

            try
            {
                _progress.Report(value);
            }
            catch (Exception)
            {
                // A progress callback fault must never corrupt proof or cause a retry.
            }
        }

    }

    /// <summary>
    /// A tiny synchronous progress adapter: reports directly on the calling thread. No queue, no Post, and
    /// no asynchronous callback that could surface after the outcome is already known.
    /// </summary>
    private sealed class SyncProgress<T> : IProgress<T>
    {
        private readonly Action<T> _callback;

        internal SyncProgress(Action<T> callback)
        {
            _callback = callback;
        }

        public void Report(T value)
        {
            _callback(value);
        }
    }
}
