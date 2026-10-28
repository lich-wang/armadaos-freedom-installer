using System;
using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core
{
    /// <summary>
    /// Card partial of the tablet install workflow: actual RAM-mode SD card
    /// preparation, raw write with full read-back verification, and the public
    /// pause that leaves the device awaiting a fresh 9008 EDL return.
    /// </summary>
    public sealed partial class TfTabletInstallWorkflow
    {
        private TfTabletCardPrepared? _preparedCard;
        private TfRamCardWriteTarget? _cardTarget;
        private bool _cardWriteAttempted;
        private bool _cardWriterConsumed;

        /// <summary>Immutable result of a successful card preparation, held while awaiting user confirmation.</summary>
        public sealed class TfTabletCardPrepared
        {
            internal TfTabletCardPrepared(
                string confirmationId,
                TfCardTargetIdentity card,
                TfCardLayoutPlan layout,
                TfSpacePlan space,
                string packageManifestFingerprint,
                byte[] nonce)
            {
                ConfirmationId = confirmationId;
                Card = card;
                Layout = layout;
                Space = space;
                PackageManifestFingerprint = packageManifestFingerprint;
                Nonce = nonce;
            }

            public string ConfirmationId { get; }
            public TfCardTargetIdentity Card { get; }
            public TfCardLayoutPlan Layout { get; }
            public TfSpacePlan Space { get; }
            public string PackageManifestFingerprint { get; }

            /// <summary>Secret nonce bound into the confirmation digest; never surfaced publicly.</summary>
            internal byte[] Nonce { get; }
        }

        /// <summary>Prepared card awaiting confirmation, or null.</summary>
        public TfTabletCardPrepared? PreparedCard => _preparedCard;

        /// <summary>
        /// Plans space, opens the actual raw SD target for this RAM session,
        /// revalidates it, computes the confirmation binding, and parks the
        /// open target until confirmation or disposal.
        /// </summary>
        public async Task<TfTabletCardPrepared> PrepareCardAsync(TfCardCandidate card, CancellationToken ct = default)
        {
            if (card is null)
            {
                throw new ArgumentNullException(nameof(card));
            }

            ThrowIfDisposed();

            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (_busy)
                {
                    throw new InvalidOperationException("Another tablet install operation is already in progress.");
                }

                _busy = true;
                try
                {
                    ct.ThrowIfCancellationRequested();

                    var runtime = _runtime;
                    if (runtime is null || runtime.Session is null)
                    {
                        throw new InvalidOperationException("No active RAM maintenance session.");
                    }

                    var temp = _tempResult;
                    if (temp is null
                        || temp.Operation != TfBootOperation.Temporary
                        || temp.Outcome != BootMaintenanceOutcome.Completed
                        || temp.WriteState != InternalInstallWriteState.AllVerified
                        || temp.ResetAccepted != true)
                    {
                        throw new InvalidOperationException("Temporary RAM boot has not completed and been accepted.");
                    }

                    if (!_requiresBootRecovery)
                    {
                        throw new InvalidOperationException("Boot recovery state is not active.");
                    }

                    if (_cardWriterConsumed || _cardWriteAttempted)
                    {
                        throw new InvalidOperationException("The card writer has already been used for this session; images are one-use.");
                    }

                    if (_cardEvidence is not null)
                    {
                        throw new InvalidOperationException("A card write has already completed for this session.");
                    }

                    if (card.Key is null || !card.Key.StartsWith("tablet:sd:", StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Only a tablet SD card candidate (key 'tablet:sd:...') may be prepared; reader keys are rejected.");
                    }

                    // Release only our own previously prepared target before opening a new one.
                    await DisposePreparedCardTargetAsync().ConfigureAwait(false);

                    // Shared strict space policy first — no independent capacity guessing.
                    TfSpacePlan space = TfCardSupport.Plan(card, _images.Contract.Storage);

                    var session = runtime.Session;

                    // Genuine open; the service binds boot id + model + SoC + kernel and
                    // validates real inventory. One open per session, held across confirmation.
                    TfRamCardWriteTarget target = await session.OpenCardAsync(card, ct).ConfigureAwait(false);

                    try
                    {
                        TfCardTargetIdentity identity = target.Identity;
                        ValidateTargetIdentity(identity, card);

                        TfCardTargetIdentity revalidated = await target.RevalidateAsync(ct).ConfigureAwait(false);
                        if (revalidated != identity)
                        {
                            throw new InvalidOperationException("Card target changed between open and revalidation.");
                        }

                        // Park the actual open target; it is held across user confirmation.
                        _cardTarget = target;

                        TfRawPackageContract contract = _images.Contract;
                        long bootBytes = contract.BootImage.ExpandedBytes;
                        long rootBytes = contract.RootImage.ExpandedBytes;
                        long minimumRoot = Math.Max(rootBytes, space.LinuxRootBytes);

                        TfCardLayoutPlan layout = TfCardLayout.Create(
                            identity.SizeBytes,
                            identity.LogicalSectorSize,
                            bootBytes,
                            rootBytes,
                            minimumRoot,
                            Guid.NewGuid(),
                            Guid.NewGuid(),
                            Guid.NewGuid());

                        // Confirmation digest binds full target identity + layout + package + temp boot + session.
                        byte[] nonce = RandomNumberGenerator.GetBytes(32);
                        string confirmationId = ComputeCardConfirmationId(
                            identity,
                            layout,
                            contract.ManifestFingerprint,
                            nonce,
                            session);

                        var prepared = new TfTabletCardPrepared(
                            confirmationId,
                            identity,
                            layout,
                            space,
                            contract.ManifestFingerprint,
                            nonce);

                        _preparedCard = prepared;
                        _stage = TfTabletInstallStage.CardPrepared;
                        PersistState();

                        return prepared;
                    }
                    catch (Exception primary)
                    {
                        // Failure closes only the acquired target; temp recovery responsibility retained.
                        // A mandatory persist/open failure must not leave the attempted
                        // prepared metadata visibly valid; invalidate BEFORE target close
                        // so even a cleanup failure cannot leave ready metadata;
                        // temp recovery is retained.
                        _preparedCard = null;
                        if (_cardTarget == target)
                        {
                            _cardTarget = null;
                        }
                        try
                        {
                            await target.DisposeAsync().ConfigureAwait(false);
                        }
                        catch (Exception cleanup)
                        {
                            throw new AggregateException(primary.Message, primary, cleanup);
                        }
                        throw;
                    }
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

        /// <summary>
        /// Executes the one-use raw card write with full read-back verification
        /// against the held target, then publicly pauses awaiting EDL return.
        /// </summary>
        public async Task<TfCardWriteEvidence> ExecuteCardAsync(
            string confirmationId,
            IProgress<TfCardWriteProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(confirmationId))
            {
                throw new ArgumentException("A card confirmation id is required.", nameof(confirmationId));
            }

            ThrowIfDisposed();

            TfCardWriteEvidence? verifiedEvidence = null;
            bool persistenceFailed = false;
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (_busy)
                {
                    throw new InvalidOperationException("Another tablet install operation is already in progress.");
                }

                _busy = true;
                try
                {
                    ct.ThrowIfCancellationRequested();

                    var prepared = _preparedCard;
                    var target = _cardTarget;
                    if (prepared is null || target is null)
                    {
                        throw new InvalidOperationException("No card is prepared for writing.");
                    }

                    if (_cardWriterConsumed)
                    {
                        throw new InvalidOperationException("The card writer has already been consumed; images are one-use and never retried.");
                    }

                    if (!string.Equals(prepared.ConfirmationId, confirmationId, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Card confirmation id does not match the prepared card.");
                    }

                    var runtime = _runtime;
                    if (runtime is null || runtime.Session is null)
                    {
                        throw new InvalidOperationException("RAM maintenance session is no longer available.");
                    }

                    // Revalidate everything immediately before invoking the writer.
                    await _images.RevalidateAsync(ct).ConfigureAwait(false);

                    TfBootPlan finalPlan = _finalPlan ?? throw new InvalidOperationException("Final boot plan is missing.");
                    await finalPlan.RevalidateAsync(ct).ConfigureAwait(false);

                    var session = runtime.Session;
                    if (session.SocSerial != _socSerial
                        || !string.Equals(session.KernelSha256, _kernelSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("RAM session identity no longer matches the recorded install identity.");
                    }

                    TfCardTargetIdentity identity = await target.RevalidateAsync(ct).ConfigureAwait(false);
                    if (identity != prepared.Card)
                    {
                        throw new InvalidOperationException("Card target changed after preparation; refusing to write.");
                    }

                    TfRawPackageContract contract = _images.Contract;
                    if (!string.Equals(contract.ManifestFingerprint, prepared.PackageManifestFingerprint, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Package manifest changed after preparation; re-prepare the card.");
                    }

                    // The actual images are one-use even if the writer fails in preflight:
                    // mark consumption before entering the writer, never reset.
                    _cardWriterConsumed = true;

                    // Durable pre-write gate: the first physical write may only proceed
                    // after the WritingCard state (card confirmation + identity + layout)
                    // is persisted with the existing state file.
                    var gatedTarget = new CardTargetWriteGate(target, this, prepared);

                    TfCardWriteEvidence evidence;
                    try
                    {
                        evidence = await TfCardRawWriter.WriteAndVerifyAsync(
                            _images,
                            gatedTarget,
                            prepared.Layout,
                            progress,
                            ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        _requiresBootRecovery = true;
                        _stage = _cardWriteAttempted
                            ? TfTabletInstallStage.UnknownWriteOutcome
                            : TfTabletInstallStage.Cancelled;
                        _error = "Card write was cancelled.";
                        try { await DisposePreparedCardTargetAsync().ConfigureAwait(false); }
                        catch (Exception cleanupEx)
                        {
                            _error = $"{_error} Card target cleanup failed: {cleanupEx.Message}";
                        }
                        try { PersistState(); }
                        catch (Exception persistEx)
                        {
                            _error = $"{_error} State persistence failed: {persistEx.Message}";
                        }
                        throw;
                    }
                    catch (Exception ex)
                    {
                        // Preserve the original write exception as primary; cleanup and
                        // persistence errors stay visible but never replace it.
                        _requiresBootRecovery = true;
                        _stage = _cardWriteAttempted
                            ? TfTabletInstallStage.UnknownWriteOutcome
                            : TfTabletInstallStage.Failed;
                        _error = ex.Message;
                        try { await DisposePreparedCardTargetAsync().ConfigureAwait(false); }
                        catch (Exception cleanupEx)
                        {
                            _error = $"{_error} Card target cleanup failed: {cleanupEx.Message}";
                        }
                        try { PersistState(); }
                        catch (Exception persistEx)
                        {
                            _error = $"{_error} State persistence failed: {persistEx.Message}";
                        }
                        throw;
                    }

                    if (!evidence.FullyVerified)
                    {
                        _requiresBootRecovery = true;
                        _stage = TfTabletInstallStage.UnknownWriteOutcome;
                        _error = "Card write did not fully verify; card state is unknown.";
                        PersistState();
                        throw new InvalidOperationException(_error);
                    }

                    // Exact target/layout/package/declared-hash match required.
                    if (evidence.Target != prepared.Card
                        || evidence.Layout != prepared.Layout
                        || !string.Equals(evidence.ManifestFingerprint, contract.ManifestFingerprint, StringComparison.Ordinal)
                        || !string.Equals(evidence.BootImageSha256, contract.BootImage.ExpandedSha256, StringComparison.Ordinal)
                        || !string.Equals(evidence.RootImageSha256, contract.RootImage.ExpandedSha256, StringComparison.Ordinal))
                    {
                        _requiresBootRecovery = true;
                        _stage = TfTabletInstallStage.UnknownWriteOutcome;
                        _error = "Verified card evidence does not match the prepared plan.";
                        PersistState();
                        throw new InvalidOperationException(_error);
                    }

                    // Genuine verified evidence kept in real memory; never fabricate failure-as-unwritten.
                    _cardEvidence = evidence;
                    _requiresBootRecovery = true;

                    try
                    {
                        _stage = TfTabletInstallStage.AwaitingEdlReturn;
                        PersistState();
                    }
                    catch (Exception ex)
                    {
                        // Keep the real evidence and surface the save failure visibly.
                        persistenceFailed = true;
                        _error = "Card write verified, but persisting the AwaitingEdlReturn state failed: " + ex.Message;
                    }

                    // Release our own card target after the verified write; a cleanup
                    // failure must not erase the genuine verified evidence.
                    try
                    {
                        await DisposePreparedCardTargetAsync().ConfigureAwait(false);
                    }
                    catch (Exception cleanupEx)
                    {
                        _error = string.IsNullOrEmpty(_error)
                            ? "Card target cleanup failed: " + cleanupEx.Message
                            : _error + " Card target cleanup failed: " + cleanupEx.Message;
                    }

                    // Hold the genuine evidence locally; the gate is released exactly
                    // once in the outer finally below, and the public pause runs after
                    // that finally, strictly outside the gate.
                    verifiedEvidence = evidence;
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

            if (verifiedEvidence is not null)
            {
                return await ReturnAfterPauseAsync(verifiedEvidence, persistenceFailed).ConfigureAwait(false);
            }

            throw new InvalidOperationException("Card write did not produce a result.");
        }

        /// <summary>
        /// Runs the public EDL-return pause strictly outside the gate (the caller's
        /// finally has already released it exactly once) and returns the genuine
        /// verified evidence even when the pause or post-proof persistence failed.
        /// </summary>
        private async Task<TfCardWriteEvidence> ReturnAfterPauseAsync(TfCardWriteEvidence evidence, bool persistenceFailed)
        {
            try
            {
                // Public pause: close RAM service/console/transfer, persist
                // AwaitingEdlReturn + Recovery, no reboot. Cleanup failure stays
                // visible; original recovery responsibility is not lost.
                await SuspendForEdlReturnAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _error = string.IsNullOrEmpty(_error)
                    ? "Card write verified, but the EDL-return pause failed: " + ex.Message
                    : _error + " EDL-return pause failure: " + ex.Message;
            }

            _ = persistenceFailed;
            // Return the genuine evidence even if only post-proof persistence or
            // pause cleanup failed; the snapshot carries the visible error.
            return evidence;
        }

        private static void ValidateTargetIdentity(TfCardTargetIdentity identity, TfCardCandidate card)
        {
            if (identity.Source != TfCardSource.Tablet)
            {
                throw new InvalidOperationException("Opened card target is not the tablet SD source.");
            }

            if (!string.Equals(identity.Key, card.Key, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Opened card target key does not match the chosen candidate.");
            }

            if (!string.Equals(identity.DevicePath, card.Path, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Opened card target device path does not match the chosen candidate.");
            }

            if (identity.SizeBytes != card.SizeBytes)
            {
                throw new InvalidOperationException("Opened card target size does not match the chosen candidate.");
            }

            if (identity.LogicalSectorSize != card.LogicalSectorSize)
            {
                throw new InvalidOperationException("Opened card target logical sector size does not match the chosen candidate.");
            }
        }

        private string ComputeCardConfirmationId(
            TfCardTargetIdentity identity,
            TfCardLayoutPlan layout,
            string manifestFingerprint,
            byte[] nonce,
            TfRamMaintenanceSession session)
        {
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            AppendField(sha, identity.Source.ToString());
            AppendField(sha, identity.Key);
            AppendField(sha, identity.DevicePath);
            AppendField(sha, identity.SizeBytes.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, identity.LogicalSectorSize.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, identity.BindingSha256);
            AppendField(sha, layout.CardBytes.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.LogicalSectorSize.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.TotalSectors.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.BootStartSector.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.BootSectorCount.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.RootStartSector.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.RootSectorCount.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, layout.DiskGuid.ToString("D"));
            AppendField(sha, layout.BootGuid.ToString("D"));
            AppendField(sha, layout.RootGuid.ToString("D"));
            AppendField(sha, manifestFingerprint);
            AppendField(sha, _tempBackend is null ? string.Empty : _tempBackend.Prepared.ConfirmationId);
            AppendField(sha, _originalBackup is null ? string.Empty : _originalBackup.ManifestSha256);
            AppendField(sha, session.BootId.ToString("D"));
            AppendField(sha, session.SocSerial.ToString(CultureInfo.InvariantCulture));
            AppendField(sha, session.KernelSha256);
            AppendField(sha, Convert.ToHexString(nonce));

            return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
        }

        private static void AppendField(IncrementalHash sha, string value)
        {
            byte[] encoded = Encoding.UTF8.GetBytes(value ?? string.Empty);
            byte[] lengthPrefix = BitConverter.GetBytes(encoded.Length);
            sha.AppendData(lengthPrefix);
            if (encoded.Length > 0)
            {
                sha.AppendData(encoded);
            }
        }

        /// <summary>
        /// Disposes only our own prepared card target, clearing the held reference.
        /// Immutable prepared metadata is retained even after the writer consumed the
        /// target so state persistence after close keeps the real facts; no live
        /// target is retained. One-use <see cref="_cardWriterConsumed"/> stays true.
        /// </summary>
        private async Task DisposePreparedCardTargetAsync()
        {
            TfRamCardWriteTarget? target = _cardTarget;
            _cardTarget = null;
            if (target is not null)
            {
                await target.DisposeAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Forwarding wrapper over the held raw target. The first physical
        /// WriteAsync is only forwarded after the WritingCard stage (card
        /// confirmation + identity + layout) is durably persisted with the
        /// existing state file; a failed save prevents the physical write.
        /// </summary>
        private sealed class CardTargetWriteGate : ITfCardWriteTarget
        {
            private readonly TfRamCardWriteTarget _inner;
            private readonly TfTabletInstallWorkflow _owner;
            private readonly TfTabletCardPrepared _prepared;
            private bool _gateArmed;

            internal CardTargetWriteGate(TfRamCardWriteTarget inner, TfTabletInstallWorkflow owner, TfTabletCardPrepared prepared)
            {
                _inner = inner;
                _owner = owner;
                _prepared = prepared;
            }

            public TfCardTargetIdentity Identity => _inner.Identity;

            public ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken ct)
                => _inner.RevalidateAsync(ct);

            public ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken ct)
                => _inner.ReadExactlyAsync(offset, buffer, ct);

            public ValueTask FlushAsync(CancellationToken ct)
                => _inner.FlushAsync(ct);

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken ct)
            {
                if (!_gateArmed)
                {
                    _owner.ArmWritingCardStage(_prepared);
                    _gateArmed = true;
                    _owner.MarkCardWriteAttempted();
                }

                await _inner.WriteAsync(offset, buffer, ct).ConfigureAwait(false);
            }

            public ValueTask DisposeAsync()
            {
                // The workflow owns the real target; the gate never disposes it.
                return ValueTask.CompletedTask;
            }
        }

        private void ArmWritingCardStage(TfTabletCardPrepared prepared)
        {
            // Persist the durable pre-write state FIRST; a save failure here
            // throws before any physical write is forwarded.
            _stage = TfTabletInstallStage.WritingCard;
            PersistState();
            _ = prepared;
        }

        private void MarkCardWriteAttempted()
        {
            // Only after the durable save succeeded is a physical write attempt recorded.
            _cardWriteAttempted = true;
        }
    }
}
