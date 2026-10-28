using System;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core
{
    /// <summary>
    /// Fresh-capture Final / original-state restoration.
    /// Binds the actual frozen EDL-return backend factories; no fake results,
    /// no journal/parser reimplementation, no extra rollback mode.
    /// </summary>
    public sealed partial class TfTabletInstallWorkflow
    {
        private TfBootBackend? _returnBackend;
        private bool _returnExecutionConsumed;

        /// <summary>Actual prepared return operation owned by this partial, or null.</summary>
        public TfBootPrepared? PreparedReturnBoot => _returnBackend?.Prepared;

        /// <summary>
        /// Current authoritative rollback locator. A backend-returned rollback journal
        /// (distinct from the original temporary journal) takes precedence.
        /// </summary>
        public string CurrentRecoveryJournalPath =>
            _returnBackend?.Prepared.RollbackJournalPath ?? Prepared.RecoveryJournalPath;

        // ---------------------------------------------------------------------
        // Final-from-fresh-EDL preparation
        // ---------------------------------------------------------------------

        public async Task<TfBootPrepared> PrepareFinalFromEdlAsync(
            BootMaintenanceHistoricalIdentity history,
            EdlClient client,
            InternalBackupSet freshBackup,
            CancellationToken cancellationToken = default)
        {
            if (history is null) throw new ArgumentNullException(nameof(history));
            if (client is null) throw new ArgumentNullException(nameof(client));
            if (freshBackup is null) throw new ArgumentNullException(nameof(freshBackup));

            ThrowIfDisposed();
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (_busy)
                {
                    throw new InvalidOperationException("Another tablet install operation is in progress.");
                }
                if (_runtime is not null || _console is not null || _transfer is not null)
                {
                    throw new InvalidOperationException("A live RAM maintenance session is active; return preparation is not permitted.");
                }
                if (!_requiresBootRecovery)
                {
                    throw new InvalidOperationException("No pending temporary-boot recovery responsibility.");
                }

                // Temporary boot must be a genuinely completed, fully verified, reset-accepted result.
                if (_tempResult is null
                    || _tempResult.Operation != TfBootOperation.Temporary
                    || _tempResult.Outcome != BootMaintenanceOutcome.Completed
                    || _tempResult.WriteState != InternalInstallWriteState.AllVerified
                    || _tempResult.ResetAccepted != true)
                {
                    throw new InvalidOperationException(
                        "Final preparation requires a completed, fully verified, reset-accepted temporary boot result.");
                }

                // Card must be genuinely fully verified with matching package fingerprint
                // and both declared expanded image hashes. Actual facts only; a persisted
                // JSON boolean is never accepted as proof.
                if (_cardEvidence is null || !_cardEvidence.FullyVerified)
                {
                    throw new InvalidOperationException("Final preparation requires a fully verified card write evidence.");
                }
                var contract = _images.Contract;
                if (!string.Equals(_cardEvidence.ManifestFingerprint, contract.ManifestFingerprint, StringComparison.Ordinal)
                    || !string.Equals(_cardEvidence.BootImageSha256, contract.BootImage.ExpandedSha256, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(_cardEvidence.RootImageSha256, contract.RootImage.ExpandedSha256, StringComparison.OrdinalIgnoreCase)
                    || _cardEvidence.Target is null
                    || _cardEvidence.Layout is null)
                {
                    throw new InvalidOperationException("Card write evidence does not match the current package contract.");
                }

                _busy = true;
                _error = null;
                try
                {
                    // Revalidate our own sealed artifacts before handing them to the factory.
                    await _images.RevalidateAsync(cancellationToken).ConfigureAwait(false);
                    await _finalPlan.RevalidateAsync(cancellationToken).ConfigureAwait(false);

                    // Actual frozen Final factory. The backend reopens/owns its own capture
                    // leases; client/freshBackup/runner/plans remain borrowed.
                    TfBootBackend backend = await BootMaintenanceBackend.CreateTfFinalFromEdlAsync(
                        history,
                        client,
                        freshBackup,
                        _tempBackend,
                        _tempResult,
                        _finalPlan,
                        _runner,
                        _evidenceDirectory,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    try
                    {
                        ValidateReturnBackendPrepared(
                            backend,
                            requiresFinal: true,
                            freshBackup: freshBackup,
                            originalBackup: _originalBackup,
                            contractManifestFingerprint: contract.ManifestFingerprint);
                    }
                    catch
                    {
                        // New backend failed validation; release only it. The prior owned
                        // return backend (if any) keeps its recovery path intact.
                        backend.Dispose();
                        throw;
                    }

                    // Save previous owned refs/state; the previous backend is disposed
                    // only AFTER the new state is durably persisted, never before.
                    TfBootBackend? previous = _returnBackend;
                    bool previousConsumed = _returnExecutionConsumed;
                    TfTabletInstallStage previousStageBefore = _stage;
                    bool previousRecovery = _requiresBootRecovery;
                    string? previousError = _error;

                    // Tentatively install the newly validated backend.
                    _returnBackend = backend;
                    _returnExecutionConsumed = false;

                    _stage = TfTabletInstallStage.PreparedFinalBoot;
                    _requiresBootRecovery = true;
                    try
                    {
                        PersistState();
                    }
                    catch (Exception persistEx)
                    {
                        // Mandatory state save failed: no future Execute may issue writes
                        // from the invalid new prepare. Restore previous refs/state and
                        // dispose only the NEW backend (collect failure, preserve primary).
                        _returnBackend = previous;
                        _returnExecutionConsumed = previousConsumed;
                        _stage = previousStageBefore;
                        _requiresBootRecovery = previousRecovery;
                        _error = previousError;
                        try { backend.Dispose(); }
                        catch (Exception disposeEx)
                        {
                            throw new AggregateException(persistEx.Message, persistEx, disposeEx);
                        }
                        throw;
                    }

                    // Only after successful persist, retire the prior owned backend.
                    previous?.Dispose();

                    return backend.Prepared;
                }
                catch (Exception ex)
                {
                    _error = ex.Message;
                    throw;
                }
                finally
                {
                    _busy = false;
                }
            }
            finally
            {
                _gate.Release();
            }
        }

        // ---------------------------------------------------------------------
        // Restore-previous-from-fresh-EDL preparation
        // ---------------------------------------------------------------------

        public async Task<TfBootPrepared> PrepareRestorePreviousFromEdlAsync(
            BootMaintenanceHistoricalIdentity history,
            EdlClient client,
            InternalBackupSet freshBackup,
            CancellationToken cancellationToken = default)
        {
            if (history is null) throw new ArgumentNullException(nameof(history));
            if (client is null) throw new ArgumentNullException(nameof(client));
            if (freshBackup is null) throw new ArgumentNullException(nameof(freshBackup));

            ThrowIfDisposed();
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (_busy)
                {
                    throw new InvalidOperationException("Another tablet install operation is in progress.");
                }
                if (_runtime is not null || _console is not null || _transfer is not null)
                {
                    throw new InvalidOperationException("A live RAM maintenance session is active; return preparation is not permitted.");
                }
                if (!_requiresBootRecovery)
                {
                    throw new InvalidOperationException("No pending temporary-boot recovery responsibility.");
                }

                // Unlike Final: no temp success, no card proof, and Unknown/partial
                // temporary outcomes are allowed. Only genuine pending responsibility.
                string? journalPath = CurrentRecoveryJournalPath;
                if (string.IsNullOrWhiteSpace(journalPath))
                {
                    throw new InvalidOperationException("No rollback journal path is available for restore preparation.");
                }

                _busy = true;
                _error = null;
                try
                {
                    // Actual frozen Restore factory. It alone validates the saved original
                    // full captures, same-Soc/Sahara/GPT identity, write authority and the
                    // allowed affected-roles set. Not relaxed here; RestoreStock is not used.
                    TfBootBackend backend = await BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                        history,
                        client,
                        freshBackup,
                        journalPath,
                        _runner,
                        _evidenceDirectory,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    try
                    {
                        ValidateReturnBackendPrepared(
                            backend,
                            requiresFinal: false,
                            freshBackup: freshBackup,
                            originalBackup: _originalBackup,
                            contractManifestFingerprint: null);
                    }
                    catch
                    {
                        backend.Dispose();
                        throw;
                    }

                    // Save previous owned refs/state; the previous backend is disposed
                    // only AFTER the new state is durably persisted, never before.
                    TfBootBackend? previous = _returnBackend;
                    bool previousConsumed = _returnExecutionConsumed;
                    TfTabletInstallStage previousStageBefore = _stage;
                    bool previousRecovery = _requiresBootRecovery;
                    string? previousError = _error;

                    // Tentatively install the newly validated backend.
                    _returnBackend = backend;
                    _returnExecutionConsumed = false;

                    _stage = TfTabletInstallStage.PreparedRestorePrevious;
                    _requiresBootRecovery = true;
                    try
                    {
                        PersistState();
                    }
                    catch (Exception persistEx)
                    {
                        // Mandatory state save failed: restore previous refs/state and
                        // dispose only the NEW backend (collect failure, preserve primary).
                        _returnBackend = previous;
                        _returnExecutionConsumed = previousConsumed;
                        _stage = previousStageBefore;
                        _requiresBootRecovery = previousRecovery;
                        _error = previousError;
                        try { backend.Dispose(); }
                        catch (Exception disposeEx)
                        {
                            throw new AggregateException(persistEx.Message, persistEx, disposeEx);
                        }
                        throw;
                    }

                    // Only after successful persist, retire the prior owned backend.
                    previous?.Dispose();

                    // Preparation is not restoration. If the factory produced a distinct
                    // rollback journal, CurrentRecoveryJournalPath now serves that path.
                    return backend.Prepared;
                }
                catch (Exception ex)
                {
                    _error = ex.Message;
                    throw;
                }
                finally
                {
                    _busy = false;
                }
            }
            finally
            {
                _gate.Release();
            }
        }

        // ---------------------------------------------------------------------
        // Single-use return execution
        // ---------------------------------------------------------------------

        public async Task<TfBootResult> ExecuteReturnBootAsync(
            string confirmationId,
            IProgress<InternalInstallProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(confirmationId))
            {
                throw new ArgumentException("A confirmation id is required.", nameof(confirmationId));
            }

            ThrowIfDisposed();
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (_busy)
                {
                    throw new InvalidOperationException("Another tablet install operation is in progress.");
                }
                if (_returnBackend is null)
                {
                    throw new InvalidOperationException("No return boot has been prepared.");
                }
                if (_returnExecutionConsumed)
                {
                    throw new InvalidOperationException("The prepared return boot has already been executed.");
                }

                TfBootBackend backend = _returnBackend;
                TfBootPrepared prepared = backend.Prepared;
                if (!string.Equals(prepared.ConfirmationId, confirmationId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Confirmation id does not match the prepared return boot.");
                }

                // Only closed Final or RestorePrevious operations are ever permitted.
                bool isFinal;
                switch (prepared.Operation)
                {
                    case TfBootOperation.Final:
                        isFinal = true;
                        break;
                    case TfBootOperation.RestorePrevious:
                        isFinal = false;
                        break;
                    default:
                        // Temporary (or any other value) is never executable here.
                        throw new InvalidOperationException("Only Final or RestorePrevious return boots may be executed.");
                }

                if (isFinal)
                {
                    if (_stage != TfTabletInstallStage.PreparedFinalBoot)
                    {
                        throw new InvalidOperationException("The workflow is not in the prepared-final-boot stage.");
                    }
                    // Re-verify real card proof immediately before issuing any write.
                    if (_cardEvidence is null || !_cardEvidence.FullyVerified)
                    {
                        throw new InvalidOperationException("Final execution requires fully verified card write evidence.");
                    }
                    var contract = _images.Contract;
                    if (!string.Equals(_cardEvidence.ManifestFingerprint, contract.ManifestFingerprint, StringComparison.Ordinal)
                        || !string.Equals(_cardEvidence.BootImageSha256, contract.BootImage.ExpandedSha256, StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(_cardEvidence.RootImageSha256, contract.RootImage.ExpandedSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Card write evidence no longer matches the package contract.");
                    }
                }
                else
                {
                    if (_stage != TfTabletInstallStage.PreparedRestorePrevious)
                    {
                        throw new InvalidOperationException("The workflow is not in the prepared-restore-previous stage.");
                    }
                }

                TfTabletInstallStage writingStage = isFinal
                    ? TfTabletInstallStage.WritingFinalBoot
                    : TfTabletInstallStage.RestoringPrevious;
                TfTabletInstallStage previousStage = _stage;

                _busy = true;
                _error = null;
                try
                {
                    _stage = writingStage;
                    _requiresBootRecovery = true;
                    try
                    {
                        // Durable persist BEFORE the delegate; save failure prohibits Execute.
                        PersistState();
                    }
                    catch
                    {
                        _stage = previousStage;
                        throw;
                    }

                    _returnExecutionConsumed = true;
                    TfBootResult result;
                    try
                    {
                        // Actual backend execution. No fake result on throw; on failure the
                        // real snapshot is inspected below. Supplied EdlClient/freshBackup/
                        // runner/plans are borrowed; the backend owns only its own leases.
                        result = await backend.ExecuteAsync(confirmationId, progress, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        BootMaintenanceSnapshot snapshot = backend.Snapshot;
                        BootMaintenanceOutcome? outcome = snapshot.Outcome;
                        if (!snapshot.ExecutionStarted
                            || snapshot.WriteState == InternalInstallWriteState.Unknown
                            || outcome is null
                            || outcome == BootMaintenanceOutcome.UnknownWriteOutcome)
                        {
                            _stage = TfTabletInstallStage.UnknownWriteOutcome;
                        }
                        else if (outcome == BootMaintenanceOutcome.Cancelled)
                        {
                            _stage = TfTabletInstallStage.Cancelled;
                        }
                        else if (outcome == BootMaintenanceOutcome.Failed)
                        {
                            _stage = TfTabletInstallStage.Failed;
                        }
                        else
                        {
                            _stage = TfTabletInstallStage.UnknownWriteOutcome;
                        }

                        // Responsibility is retained: the temporary boot still needs recovery.
                        _requiresBootRecovery = true;
                        _error = snapshot.Error ?? ex.Message;
                        try
                        {
                            PersistState();
                        }
                        catch (Exception persistEx)
                        {
                            // Keep both the real state and the persistence failure visible.
                            _error = $"{_error} (state persist failed: {persistEx.Message})";
                        }
                        throw;
                    }

                    // Genuine result. Persist the physical outcome and proof first; only an
                    // actually matching, fully verified, reset-accepted result closes out.
                    bool finalDone = isFinal
                        && result.Operation == TfBootOperation.Final
                        && result.Outcome == BootMaintenanceOutcome.Completed
                        && result.WriteState == InternalInstallWriteState.AllVerified
                        && result.ResetAccepted == true;
                    bool restoreDone = !isFinal
                        && result.Operation == TfBootOperation.RestorePrevious
                        && result.Outcome == BootMaintenanceOutcome.Completed
                        && result.WriteState == InternalInstallWriteState.AllVerified
                        && result.ResetAccepted == true;

                    if (finalDone)
                    {
                        _finalResult = result;
                        // Both true card proof and true boot proof required; never OS ADB
                        // or USB authorization acceptance.
                        _stage = TfTabletInstallStage.Completed;
                        _requiresBootRecovery = false;
                    }
                    else if (restoreDone)
                    {
                        _restoreResult = result;
                        _stage = TfTabletInstallStage.RestoredPrevious;
                        _requiresBootRecovery = false;
                    }
                    else if (result.Outcome == BootMaintenanceOutcome.UnknownWriteOutcome
                        || result.WriteState == InternalInstallWriteState.Unknown
                        || result.Operation != prepared.Operation
                        || (result.Outcome == BootMaintenanceOutcome.Completed
                            && !(isFinal ? finalDone : restoreDone)))
                    {
                        // A Completed outcome whose operation/state/reset do not satisfy the
                        // real done-proof must stage Unknown with recovery retained, never Failed.
                        _stage = TfTabletInstallStage.UnknownWriteOutcome;
                        _requiresBootRecovery = true;
                        if (isFinal)
                        {
                            _finalResult = result;
                        }
                        else
                        {
                            _restoreResult = result;
                        }
                    }
                    else
                    {
                        // Known Cancelled/Failed preserve those stages and recovery even for
                        // NoneIssued writes, because the temporary boot still needs recovery.
                        if (isFinal)
                        {
                            _finalResult = result;
                        }
                        else
                        {
                            _restoreResult = result;
                        }
                        if (result.Outcome == BootMaintenanceOutcome.Cancelled)
                        {
                            _stage = TfTabletInstallStage.Cancelled;
                        }
                        else
                        {
                            _stage = TfTabletInstallStage.Failed;
                        }
                        _requiresBootRecovery = true;
                    }

                    // Surface the backend's own result error alongside the physical proof.
                    if (!string.IsNullOrEmpty(result.Error))
                    {
                        _error = string.IsNullOrEmpty(_error) ? result.Error : _error + "; " + result.Error;
                    }

                    try
                    {
                        PersistState();
                    }
                    catch (Exception persistEx)
                    {
                        // Preserve the true physical result/proof and surface the error;
                        // never overwrite a real completion with a fictitious write. The
                        // genuine result is returned; post-result persistence failure does
                        // not throw away real completion.
                        _error = $"Return boot state persist failed: {persistEx.Message}";
                    }

                    return result;
                }
                finally
                {
                    _busy = false;
                }
            }
            finally
            {
                _gate.Release();
            }
        }

        // ---------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------

        /// <summary>
        /// Validates the freshly created return backend's actual prepared facts against
        /// the original backup (source) and the NEW fresh capture (target). Keeps the
        /// backend's own confirmation and actual changed regions; never mutates the
        /// sealed plan.
        /// </summary>
        private void ValidateReturnBackendPrepared(
            TfBootBackend backend,
            bool requiresFinal,
            InternalBackupSet freshBackup,
            InternalBackupSet originalBackup,
            string? contractManifestFingerprint)
        {
            TfBootPrepared prepared = backend.Prepared;

            if (requiresFinal)
            {
                if (prepared.Operation != TfBootOperation.Final || prepared.RawPurpose != TfBootPurpose.FinalTf)
                {
                    throw new InvalidOperationException("The backend did not prepare a TF Final operation.");
                }
            }
            else
            {
                if (prepared.Operation != TfBootOperation.RestorePrevious || prepared.RawPurpose is not null)
                {
                    throw new InvalidOperationException("The backend did not prepare a plain RestorePrevious operation.");
                }
            }

            // Model and current slot must match the workflow's actual device facts
            // (the fresh capture and original backup carry the same model).
            if (!string.Equals(prepared.Model, freshBackup.Model, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot model does not match the fresh capture model.");
            }
            if (!string.Equals(prepared.Model, originalBackup.Model, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot model does not match the original backup model.");
            }
            if (!string.Equals(prepared.CurrentSlot, Prepared.CurrentSlot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot current slot does not match the workflow's prepared device slot.");
            }

            // Source must be the ORIGINAL backup path + manifest; never the fresh set,
            // never the temporary boot source.
            if (string.IsNullOrWhiteSpace(prepared.SourceBackupDirectory)
                || !string.Equals(prepared.SourceBackupDirectory, originalBackup.DirectoryPath, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot source must be the original backup.");
            }
            if (string.IsNullOrWhiteSpace(prepared.SourceBackupManifestSha256)
                || !string.Equals(prepared.SourceBackupManifestSha256, originalBackup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Return boot source manifest does not match the original backup.");
            }

            // Target must be the NEW fresh capture path + manifest; never the original
            // snapshot labeled current, never the temporary boot target.
            if (string.IsNullOrWhiteSpace(prepared.TargetBackupDirectory)
                || !string.Equals(prepared.TargetBackupDirectory, freshBackup.DirectoryPath, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot target must be the new fresh capture.");
            }
            if (string.IsNullOrWhiteSpace(prepared.TargetBackupManifestSha256)
                || !string.Equals(prepared.TargetBackupManifestSha256, freshBackup.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Return boot target manifest does not match the fresh capture.");
            }
            if (string.Equals(prepared.TargetBackupDirectory, prepared.SourceBackupDirectory, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot source and target must be distinct backup sets.");
            }

            if (contractManifestFingerprint is not null
                && !string.Equals(prepared.PackageManifestFingerprint, contractManifestFingerprint, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Return boot package fingerprint does not match the contract.");
            }
        }

        private void DisposeReturnBackend()
        {
            TfBootBackend? backend = _returnBackend;
            _returnBackend = null;
            _returnExecutionConsumed = false;
            backend?.Dispose();
        }
    }
}
