using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;
using Microsoft.Win32;

namespace FreedomInstaller.App
{
    /// <summary>
    /// UI-TF-TABLET-CONTROLLER-1: Tablet TF-card workflow controller partial.
    /// Temp boot -> RAM serial -> card prepare / explicit erase + full verification ->
    /// manual EDL return -> fresh capture -> real Final or RestorePrevious.
    /// No App Reset, no automatic suspension, no device action outside explicit user stages.
    /// </summary>
    public partial class MainWindow
    {
        private const string TfTabletMarkerFileName = "tf-tablet-pending.json";
        private const int TfTabletMarkerMaxBytes = 16 * 1024;
        private const string TfTabletMarkerType = "tf-tablet-pending";
        private const string TfTabletMarkerSchemaVersion = "1";

        // Additional tiny own fields (no duplicates of Reader fields).
        private bool _tfTabletBackendExecutionBegan;
        private string? _tfTabletOriginalBackupDirectory;
        private readonly HashSet<string> _tfTabletConsumedReturnIds = new(StringComparer.Ordinal);

        private TfTabletInstallWorkflow? _tfTabletWorkflow;
        private TfBootBackend? _tfTabletRecoveryBackend;
        private TfBootResult? _tfTabletRecoveryResult;
        private UiMessage? _tfTabletStatus;
        private bool _tfTabletOperationActive;
        private bool _tfTabletCloseApproved;
        private bool _tfTabletClosePromptActive;
        private bool _tfTabletCompletionShown;
        private bool _tfTabletAcceptProgress;
        private bool _tfTabletMarkerSeen;
        private string? _tfTabletJournalPath;
        private string? _tfTabletEvidenceDirectory;
        private InternalInstallProgress? _tfTabletLastBootProgress;
        private TfCardWriteProgress? _tfTabletLastCardProgress;
        private EdlToolchain? _tfTabletReturnTools;
        private EdlClient? _tfTabletReturnClient;
        private InternalBackupSet? _tfTabletReturnBackup;
        private string? _tfTabletSavedJournalPath;
        private TfCardWriteEvidence? _tfTabletRetainedCardEvidence;

        private sealed record TfTabletPendingMarker(
            string Schema,
            string Type,
            string JournalPath,
            string StatePath,
            string EvidenceDirectory,
            string OriginalBackupDirectory);

        // ------------------------------------------------------------------
        // Public contract properties / gates
        // ------------------------------------------------------------------

        public bool IsModernTfTabletMode =>
            CurrentModeTag() == "install-tf" && _tfSource == TfCardSource.Tablet;

        public bool HasPendingTfTabletRecovery
        {
            get
            {
                // A genuine closed return stays resolved even when marker cleanup failed;
                // the actual successful result is preserved and the cleanup failure logged.
                if (IsTfTabletReturnVerified)
                {
                    return false;
                }

                return _tfTabletMarkerSeen
                    || (_tfTabletWorkflow is not null && _tfTabletWorkflow.Snapshot.RequiresBootRecovery)
                    || (_tfTabletRecoveryBackend is not null && _tfTabletBackendExecutionBegan);
            }
        }

        // HasPendingTfTabletRecovery already covers an actual unresolved backend attempt
        // and a genuine closed return, so no separate backend-term is needed here.
        public bool ProtectedTfTabletState =>
            _tfTabletOperationActive || HasPendingTfTabletRecovery;

        public bool IsCompletedTfTabletInstall
        {
            get
            {
                // Must survive own workflow disposal: the proof is either still live on
                // the workflow snapshot or retained from before the workflow was disposed.
                var final = _tfTabletRecoveryResult;
                if (final is null
                    || final.Operation != TfBootOperation.Final
                    || final.Outcome != BootMaintenanceOutcome.Completed
                    || final.WriteState != InternalInstallWriteState.AllVerified
                    || final.ResetAccepted != true)
                {
                    return false;
                }

                return _tfTabletWorkflow?.Snapshot.CardEvidence is { FullyVerified: true }
                    || _tfTabletRetainedCardEvidence is { FullyVerified: true };
            }
        }

        public bool HasPreparedTfTabletStage =>
            _tfTabletWorkflow is not null || _tfTabletRecoveryBackend is not null;

        public bool IsTfTabletCloseApproved => _tfTabletCloseApproved;

        private bool IsTfTabletReturnVerified
        {
            get
            {
                // Actual retained result first, then the live workflow results; never an
                // externally set bool.
                TfBootResult? result = _tfTabletRecoveryResult
                    ?? _tfTabletWorkflow?.Snapshot.FinalResult
                    ?? _tfTabletWorkflow?.Snapshot.RestoreResult;
                return result is not null
                    && (result.Operation == TfBootOperation.Final
                        || result.Operation == TfBootOperation.RestorePrevious)
                    && result.Outcome == BootMaintenanceOutcome.Completed
                    && result.WriteState == InternalInstallWriteState.AllVerified
                    && result.ResetAccepted == true;
            }
        }


        // ------------------------------------------------------------------
        // Current stage gate (pure; read-only prepared facts, no long lock)
        // ------------------------------------------------------------------

        private bool CanExecuteTfTabletCurrentStage()
        {
            if (!_ready || !EnvironmentIsReady || _closed || _busy || _tfTabletOperationActive || !IsModernTfTabletMode)
            {
                return false;
            }

            if (TfTabletRiskCheck.IsChecked != true)
            {
                return false;
            }

            var workflow = _tfTabletWorkflow;
            var backend = _tfTabletRecoveryBackend;

            if (workflow is not null)
            {
                var snapshot = workflow.Snapshot;
                switch (snapshot.Stage)
                {
                    case TfTabletInstallStage.PreparedTemporary:
                        return workflow.Prepared is not null
                            && snapshot.TemporaryResult is null
                            && !_tfTabletConsumedReturnIds.Contains(workflow.Prepared.ConfirmationId);
                    case TfTabletInstallStage.CardPrepared:
                        // The live selected candidate must be an actual member of the
                        // discovered inventory and match the prepared target by key; the
                        // candidate object is never identity-compared to the target.
                        return workflow.PreparedCard is not null
                            && _tfCard is not null
                            && _tfCards.Contains(_tfCard)
                            && string.Equals(_tfCard.Key, workflow.PreparedCard.Card.Key, StringComparison.Ordinal)
                            && !_tfTabletConsumedReturnIds.Contains(workflow.PreparedCard.ConfirmationId);
                    case TfTabletInstallStage.PreparedFinalBoot:
                    case TfTabletInstallStage.PreparedRestorePrevious:
                        return workflow.PreparedReturnBoot is not null
                            && !_tfTabletConsumedReturnIds.Contains(workflow.PreparedReturnBoot.ConfirmationId);
                    default:
                        return false;
                }
            }

            if (backend is not null)
            {
                var prepared = backend.Prepared;
                return prepared is not null
                    && prepared.Operation != TfBootOperation.Temporary
                    && !_tfTabletConsumedReturnIds.Contains(prepared.ConfirmationId);
            }

            return false;
        }

        // ------------------------------------------------------------------
        // Shared status / diagnostics helpers
        // ------------------------------------------------------------------

        private void SetTfTabletStatus(UiMessage message)
        {
            _tfTabletStatus = message;
            SetTfStatus(message);
        }

        private void TfTabletFail(UiMessage message, Exception? exception)
        {
            SetTfTabletStatus(message);
            if (exception is not null)
            {
                AppendLocalizedLog(M("Dynamic.RawValue", exception.GetType().Name + ": " + exception.Message));
            }

            RefreshTfTabletActions();
        }

        private void TfTabletFail(Exception exception)
        {
            TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), exception);
        }

        private IProgress<InternalInstallProgress> CreateTfTabletBootProgress() =>
            new Progress<InternalInstallProgress>(report =>
            {
                if (!_tfTabletAcceptProgress || _closed)
                {
                    return;
                }

                _tfTabletLastBootProgress = report;
                RenderTfTabletBootProgress(report);
            });

        private IProgress<TfCardWriteProgress> CreateTfTabletCardProgress() =>
            new Progress<TfCardWriteProgress>(report =>
            {
                if (!_tfTabletAcceptProgress || _closed)
                {
                    return;
                }

                _tfTabletLastCardProgress = report;
                RenderTfTabletCardProgress(report);
            });

        private string FormatTfTabletRegions(TfBootPrepared prepared)
        {
            var lines = new List<string>();
            foreach (var region in prepared.Regions)
            {
                lines.Add(region.WillWrite
                    ? T("Dynamic.BootMaintenance.RegionWrite",
                        region.Role, region.Slot, region.Lun,
                        region.StartSector, region.SectorCount, region.Length)
                    : T("Dynamic.BootMaintenance.RegionKeep",
                        region.Role, region.Slot, region.Lun,
                        region.StartSector, region.SectorCount, region.Length));
            }

            return string.Join(Environment.NewLine, lines);
        }

        private MessageBoxResult ShowTfTabletConfirm(string titleKey, string body) =>
            MessageBox.Show(this, body, T(titleKey), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        // ------------------------------------------------------------------
        // Durable pending marker (application cache only)
        // ------------------------------------------------------------------

        private static string GetTfTabletMarkerPath() =>
            Path.Combine(BundledTools.GetCacheRoot(), TfTabletMarkerFileName);

        private TfTabletPendingMarker BuildTfTabletMarker()
        {
            var workflow = _tfTabletWorkflow;
            var backend = _tfTabletRecoveryBackend;

            var journal = workflow?.CurrentRecoveryJournalPath
                ?? backend?.Prepared?.RollbackJournalPath
                ?? _tfTabletJournalPath;
            if (string.IsNullOrWhiteSpace(journal))
            {
                throw new InvalidOperationException("tf-tablet recovery journal path is not available");
            }

            var evidence = workflow?.Prepared?.EvidenceDirectory ?? _tfTabletEvidenceDirectory ?? string.Empty;
            var statePath = workflow?.Prepared?.StatePath ?? string.Empty;
            var originalBackup = workflow?.Prepared?.TemporaryBoot.SourceBackupDirectory
                ?? _tfTabletOriginalBackupDirectory
                ?? string.Empty;

            return new TfTabletPendingMarker(
                TfTabletMarkerSchemaVersion,
                TfTabletMarkerType,
                journal,
                statePath,
                evidence,
                originalBackup);
        }

        private void SaveTfTabletMarker(bool allowRecoveryRebind = false)
        {
            var marker = BuildTfTabletMarker();
            var path = GetTfTabletMarkerPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            if (File.Exists(path))
            {
                TfTabletPendingMarker? existing = null;
                Exception? readFailure = null;
                try
                {
                    existing = TryReadTfTabletMarkerFile();
                }
                catch (JsonException ex)
                {
                    // Only a malformed (null/JsonException) existing record may be treated
                    // as replaceable, and only through the explicit recovery-rebind path
                    // after Browse already validated the real journal + historical identity.
                    readFailure = ex;
                }

                if (existing is null)
                {
                    if (readFailure is not null)
                    {
                        if (!allowRecoveryRebind)
                        {
                            // Default path: a malformed existing record is never silently
                            // overwritten; other access errors are never claimed as format.
                            throw new InvalidOperationException(
                                "refusing to replace a malformed tf-tablet pending marker",
                                readFailure);
                        }
                    }
                    else if (!allowRecoveryRebind)
                    {
                        // Null-schema/oversized records are replaceable only through the
                        // explicit recovery-rebind path; default saves never rebind.
                        throw new InvalidOperationException(
                            "refusing to replace an unreadable tf-tablet pending marker");
                    }
                }
                else if (!string.Equals(existing.JournalPath, marker.JournalPath, StringComparison.OrdinalIgnoreCase))
                {
                    // Owned transition only: the existing marker is exactly the journal this
                    // process last saved successfully for the same validated temp operation.
                    var ownedTransition = !string.IsNullOrEmpty(_tfTabletSavedJournalPath)
                        && string.Equals(existing.JournalPath, _tfTabletSavedJournalPath, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(existing.OriginalBackupDirectory, marker.OriginalBackupDirectory, StringComparison.OrdinalIgnoreCase);
                    if (!ownedTransition && !allowRecoveryRebind)
                    {
                        throw new InvalidOperationException(
                            "refusing to overwrite a different unresolved tf-tablet pending marker: " + existing.JournalPath);
                    }
                }
            }

            var json = JsonSerializer.Serialize(marker, new JsonSerializerOptions { WriteIndented = true });
            var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream))
                {
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(true);
                }

                File.Move(tmp, path, true);
                _tfTabletMarkerSeen = true;
                _tfTabletSavedJournalPath = marker.JournalPath;
            }
            finally
            {
                try
                {
                    if (File.Exists(tmp))
                    {
                        File.Delete(tmp);
                    }
                }
                catch
                {
                    // tmp cleanup is best-effort; the atomic move already committed or not.
                }
            }
        }

        private TfTabletPendingMarker? TryReadTfTabletMarkerFile()
        {
            var path = GetTfTabletMarkerPath();
            if (!File.Exists(path))
            {
                return null;
            }

            var info = new FileInfo(path);
            if (info.Length > TfTabletMarkerMaxBytes)
            {
                return null;
            }

            using var stream = info.OpenRead();
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var marker = JsonSerializer.Deserialize<TfTabletPendingMarker>(json);
            if (marker is null
                || !string.Equals(marker.Schema, TfTabletMarkerSchemaVersion, StringComparison.Ordinal)
                || !string.Equals(marker.Type, TfTabletMarkerType, StringComparison.Ordinal))
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(marker.JournalPath) || !Path.IsPathRooted(marker.JournalPath))
            {
                return null;
            }

            return marker;
        }

        private bool TryDeleteTfTabletMarker(out string? error)
        {
            try
            {
                var path = GetTfTabletMarkerPath();
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                _tfTabletMarkerSeen = false;
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }


        // ------------------------------------------------------------------
        // Stage dispatcher — "execute current stage"
        // ------------------------------------------------------------------

        public async Task ExecuteTfTabletCurrentStageAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            // The pure external gate is evaluated before the own-active flag is set;
            // the inner helpers must not re-run it while the global busy lock is held.
            if (!CanExecuteTfTabletCurrentStage())
            {
                SetTfTabletStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        var workflow = _tfTabletWorkflow;
                        var backend = _tfTabletRecoveryBackend;

                        if (backend is not null && (workflow is null || workflow.PreparedReturnBoot is null))
                        {
                            await ExecuteTfTabletRecoveryStageAsync(ct);
                            return;
                        }

                        if (workflow is null)
                        {
                            TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                            return;
                        }

                        switch (workflow.Snapshot.Stage)
                        {
                            case TfTabletInstallStage.PreparedTemporary:
                                await ExecuteTfTabletTemporaryStageAsync(ct);
                                break;
                            case TfTabletInstallStage.CardPrepared:
                                await ExecuteTfTabletCardStageAsync(ct);
                                break;
                            case TfTabletInstallStage.PreparedFinalBoot:
                            case TfTabletInstallStage.PreparedRestorePrevious:
                                await ExecuteTfTabletReturnStageAsync(ct);
                                break;
                            default:
                                SetTfTabletStatus(M("Dynamic.TfInstall.NeedInputs"));
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        // ------------------------------------------------------------------
        // Stage 2 — temporary boot write
        // ------------------------------------------------------------------

        private async Task ExecuteTfTabletTemporaryStageAsync(CancellationToken ct)
        {
            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Prepared is null || workflow.Snapshot.IsBusy)
            {
                return;
            }

            // No reattempt: any existing temporary result pins the stage.
            if (workflow.Snapshot.TemporaryResult is not null)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.Stage.PreparedTemporary"));
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.RiskTemporary"));
                return;
            }

            var backup = _internalInstallBackup;
            var client = _internalInstallEdlClient;
            var prepared = workflow.Prepared;

            RenderInternalInstallPower();
            var body = T(
                "Dynamic.TfTablet.TempConfirmBody",
                prepared.Model,
                prepared.TemporaryBoot.AndroidSerial,
                prepared.BackupDirectory,
                prepared.EvidenceDirectory,
                FormatTfTabletRegions(prepared.TemporaryBoot),
                InternalInstallPowerText.Text,
                prepared.RecoveryJournalPath);
            if (ShowTfTabletConfirm("Dynamic.TfTablet.TempConfirmTitle", body) != MessageBoxResult.Yes)
            {
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true
                || !ReferenceEquals(_tfTabletWorkflow, workflow)
                || !ReferenceEquals(_internalInstallBackup, backup)
                || !ReferenceEquals(_internalInstallEdlClient, client)
                || workflow.Snapshot.TemporaryResult is not null)
            {
                return;
            }

            if (!EnsureTfTabletHostNetworkDriverAvailable())
            {
                return;
            }

            try
            {
                SaveTfTabletMarker();
            }
            catch (Exception ex)
            {
                TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), ex);
                return;
            }

            // One-shot confirmation consumption right before dispatch; Core stays the authority.
            if (!_tfTabletConsumedReturnIds.Add(prepared.ConfirmationId))
            {
                return;
            }

            // Old stage progress never leaks into a new operation.
            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;

            TfBootResult? result = null;
            _tfTabletAcceptProgress = true;
            try
            {
                result = await workflow.ExecuteTemporaryAsync(
                    prepared.ConfirmationId, CreateTfTabletBootProgress(), ct);
            }
            catch (OperationCanceledException)
            {
                // Pending marker is retained; cancellation never claims zero writes here.
                TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            }
            catch (Exception ex)
            {
                TfTabletFail(ex);
            }
            finally
            {
                _tfTabletAcceptProgress = false;
                TfTabletRiskCheck.IsChecked = false;
            }

            if (result is not null)
            {
                ApplyTfTabletTemporaryResult(result);
            }
        }

        private void ApplyTfTabletTemporaryResult(TfBootResult result)
        {
            var snapshot = _tfTabletWorkflow?.Snapshot;

            var genuinelyNothingWritten = result.WriteState == InternalInstallWriteState.NoneIssued
                && (result.Outcome == BootMaintenanceOutcome.Failed || result.Outcome == BootMaintenanceOutcome.Cancelled)
                && snapshot is not null
                && !snapshot.RequiresBootRecovery;
            if (genuinelyNothingWritten)
            {
                if (TryDeleteTfTabletMarker(out var markerError))
                {
                    TfTabletFail(M("Dynamic.TfInstall.PrepareFailed"), null);
                }
                else
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", markerError!));
                    TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), null);
                }

                return;
            }

            if (result.WriteState == InternalInstallWriteState.AllVerified
                && result.ResetAccepted != true)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.VerifiedRestartUnconfirmed"));
                return;
            }

            if (result.Outcome == BootMaintenanceOutcome.Completed)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.Stage.AwaitingRamConnection"));
                return;
            }

            // Failed / cancelled with possible writes: retain marker and responsibility.
            TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            if (!string.IsNullOrEmpty(result.Error))
            {
                AppendLocalizedLog(M("Dynamic.RawValue", result.Error!));
            }
        }

        // ------------------------------------------------------------------
        // Stage 3 — RAM serial connection and card inventory
        // ------------------------------------------------------------------

        public async Task RefreshTfTabletPortsAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        var ports = await Task.Run(() => MaintenanceSerialDiscovery.ReadWindows(), ct);
                        TfTabletPortsCombo.Items.Clear();
                        foreach (var port in ports)
                        {
                            TfTabletPortsCombo.Items.Add(new ComboBoxItem
                            {
                                Content = T("Dynamic.TfTablet.PortEntry", port.PortName),
                                Tag = port,
                                ToolTip = port.DeviceInstanceId,
                            });
                        }

                        TfTabletPortsCombo.SelectedIndex = -1;
                        SetTfTabletStatus(ports.Count == 0
                            ? M("Dynamic.TfTablet.NoPorts")
                            : M("Dynamic.TfTablet.PortsFound", ports.Count));
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        public async Task ConnectTfTabletRamAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Snapshot.IsBusy
                || workflow.Snapshot.Stage != TfTabletInstallStage.AwaitingRamConnection)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            if (TfTabletPortsCombo.SelectedItem is not ComboBoxItem item || item.Tag is not MaintenanceSerialPort port)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.NeedRamPort"));
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        var cards = await workflow.ConnectRamAsync(port, ct);
                        FillTfTabletCardInventory(cards);
                        _tfCard = null;
                        _tfPlan = null;
                        SetTfTabletStatus(M("Dynamic.TfTablet.Stage.RamConnected"));
                        RenderTfTabletPages();
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        public async Task RefreshTfTabletCardsAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Snapshot.IsBusy
                || workflow.Snapshot.Stage != TfTabletInstallStage.RamConnected)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.NeedRamPort"));
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        var cards = await workflow.DiscoverCardsAsync(ct);
                        FillTfTabletCardInventory(cards);
                        SetTfTabletStatus(M("Dynamic.Tf.Status.Found", cards.Count));
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        /// <summary>Old ReadCards hook: only a live RAM-connected tablet workflow may discover; never stock ADB.</summary>
        public async Task DiscoverTfTabletCardsAsync()
        {
            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Snapshot.IsBusy
                || workflow.Snapshot.Stage != TfTabletInstallStage.RamConnected)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.NeedRamPort"));
                return;
            }

            await RefreshTfTabletCardsAsync();
        }

        private void FillTfTabletCardInventory(IReadOnlyList<TfCardCandidate> cards)
        {
            _tfCards = cards;
            _tfCard = null;
            _tfPlan = null;
            TfCardsCombo.Items.Clear();
            foreach (var card in cards)
            {
                if (!card.Key.StartsWith("tablet:", StringComparison.Ordinal))
                {
                    continue;
                }

                TfCardsCombo.Items.Add(new ComboBoxItem
                {
                    Content = card.DisplayName + " · " + FormatBytes(card.SizeBytes) + " · " + card.Path,
                    Tag = card,
                });
            }

            TfCardsCombo.SelectedIndex = -1;
        }

        // ------------------------------------------------------------------
        // Stage 4 — card prepare, explicit erase + full verification
        // ------------------------------------------------------------------

        public async Task PrepareTfTabletCardAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Snapshot.IsBusy
                || workflow.Snapshot.Stage != TfTabletInstallStage.RamConnected)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            var card = _tfCard;
            if (card is null
                || !_tfCards.Contains(card)
                || !card.Key.StartsWith("tablet:", StringComparison.Ordinal))
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        await workflow.PrepareCardAsync(card, ct);
                        TfTabletRiskCheck.IsChecked = false;
                        SetTfTabletStatus(M("Dynamic.TfTablet.Stage.CardPrepared"));
                        RenderTfTabletPages();
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        private async Task ExecuteTfTabletCardStageAsync(CancellationToken ct)
        {
            var workflow = _tfTabletWorkflow;
            if (workflow is null || workflow.Snapshot.IsBusy || workflow.PreparedCard is null)
            {
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.RiskCard"));
                return;
            }

            var preparedCard = workflow.PreparedCard;
            var prepared = workflow.Prepared;

            // The selected candidate is captured before the modal; the candidate object is
            // never compared against the prepared target identity object.
            TfCardCandidate? selectedCard = _tfCard;
            if (selectedCard is null
                || !string.Equals(selectedCard.Key, preparedCard.Card.Key, StringComparison.Ordinal))
            {
                return;
            }

            RenderInternalInstallPower();
            var body = T(
                "Dynamic.TfTablet.CardConfirmBody",
                preparedCard.Card.DevicePath,
                FormatBytes(preparedCard.Card.SizeBytes),
                prepared.BackupDirectory,
                prepared.EvidenceDirectory);
            if (ShowTfTabletConfirm("Dynamic.TfTablet.CardConfirmTitle", body) != MessageBoxResult.Yes)
            {
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true
                || !ReferenceEquals(_tfTabletWorkflow, workflow)
                || !ReferenceEquals(workflow.PreparedCard, preparedCard)
                || !ReferenceEquals(_tfCard, selectedCard)
                || !string.Equals(selectedCard.Key, preparedCard.Card.Key, StringComparison.Ordinal))
            {
                return;
            }

            try
            {
                SaveTfTabletMarker();
            }
            catch (Exception ex)
            {
                TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), ex);
                return;
            }

            // One-shot confirmation consumption right before dispatch; Core stays the authority.
            if (!_tfTabletConsumedReturnIds.Add(preparedCard.ConfirmationId))
            {
                return;
            }

            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;

            TfCardWriteEvidence? evidence = null;
            _tfTabletAcceptProgress = true;
            try
            {
                evidence = await workflow.ExecuteCardAsync(
                    preparedCard.ConfirmationId, CreateTfTabletCardProgress(), ct);
            }
            catch (OperationCanceledException)
            {
                TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            }
            catch (Exception ex)
            {
                TfTabletFail(ex);
            }
            finally
            {
                _tfTabletAcceptProgress = false;
                TfTabletRiskCheck.IsChecked = false;
            }

            var error = workflow.Snapshot.Error;
            if (evidence is { FullyVerified: true })
            {
                // Core already performed SuspendForEdlReturnAsync after real card success;
                // the app must not suspend again here.
                _tfTabletRetainedCardEvidence ??= evidence;
                SetTfTabletStatus(M("Dynamic.TfTablet.Stage.AwaitingEdlReturn"));
                if (!string.IsNullOrEmpty(error))
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", error!));
                }
            }
            else
            {
                TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
                if (!string.IsNullOrEmpty(error))
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", error!));
                }
            }
        }

        /// <summary>
        /// Explicit manual suspend: only while a real pending workflow exists and the
        /// maintenance RAM session is still live. Never an automatic restart/EDL/sysrq/ADB command.
        /// </summary>
        public async Task SuspendTfTabletForEdlAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            var workflow = _tfTabletWorkflow;
            if (workflow is null || !workflow.Snapshot.RequiresBootRecovery || workflow.Snapshot.IsBusy)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            if (workflow.Snapshot.Stage == TfTabletInstallStage.AwaitingEdlReturn)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.Stage.AwaitingEdlReturn"));
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    try
                    {
                        await workflow.SuspendForEdlReturnAsync(ct);
                        SetTfTabletStatus(M("Dynamic.TfTablet.Stage.AwaitingEdlReturn"));
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        // ------------------------------------------------------------------
        // Stage 5 — return preparation (Final or RestorePrevious) after EDL
        // ------------------------------------------------------------------

        public async Task PrepareTfTabletReturnAsync(bool restorePrevious)
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            if (!HasPendingTfTabletRecovery)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            if (_runner is null || _transport is null)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            _tfTabletOperationActive = true;
            try
            {
                await RunBusyAsync(async ct =>
                {
                    EdlToolchain? newTools = null;
                    InternalBackupSet? newFresh = null;
                    EdlToolchain? oldTools = null;
                    InternalBackupSet? oldBackup = null;
                    var committed = false;
                    try
                    {
                        var workflow = _tfTabletWorkflow;
                        if (!restorePrevious)
                        {
                            // Final requires the live same-process workflow with real card proof
                            // plus an actual successful temporary boot.
                            if (workflow is null)
                            {
                                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                                return;
                            }

                            var snapshot = workflow.Snapshot;
                            if (snapshot.CardEvidence is not { FullyVerified: true }
                                || snapshot.TemporaryResult is not
                                {
                                    Operation: TfBootOperation.Temporary,
                                    Outcome: BootMaintenanceOutcome.Completed,
                                    WriteState: InternalInstallWriteState.AllVerified,
                                    ResetAccepted: true,
                                })
                            {
                                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                                return;
                            }
                        }

                        // Explicit suspend of the live RAM session first, only when the live
                        // pending stage is not already awaiting the EDL return. Never automatic.
                        if (workflow is not null
                            && workflow.Snapshot.RequiresBootRecovery
                            && !workflow.Snapshot.IsBusy
                            && workflow.Snapshot.Stage != TfTabletInstallStage.AwaitingEdlReturn)
                        {
                            await workflow.SuspendForEdlReturnAsync(ct);
                        }

                        SetTfTabletStatus(M("Dynamic.TfTablet.PreparingReturn"));

                        var journalPath = workflow?.CurrentRecoveryJournalPath ?? _tfTabletJournalPath;
                        if (string.IsNullOrWhiteSpace(journalPath))
                        {
                            TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                            return;
                        }

                        var hint = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(journalPath, ct);
                        _tfTabletOriginalBackupDirectory = hint.OriginalBackupDirectory;

                        // Historical anchor only; never locks against the current tablet.
                        var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(hint.OriginalBackupDirectory, ct);
                        if (!history.Profile.IsComplete
                            || !history.Profile.SupportsIdentity(history.Identity.Identity)
                            || string.IsNullOrWhiteSpace(history.Profile.ArchiveLogicalName))
                        {
                            TfTabletFail(M("Dynamic.TfInstall.PackageRejected"), null);
                            return;
                        }

                        var parent = _internalInstallBackupParent;
                        if (string.IsNullOrWhiteSpace(parent))
                        {
                            var folderDialog = new OpenFolderDialog();
                            if (folderDialog.ShowDialog(this) != true)
                            {
                                return;
                            }

                            parent = folderDialog.FolderName;
                        }

                        if (!Directory.Exists(parent!)
                            || !IsInternalInstallBackupParentOutsideExisting(parent!, hint.OriginalBackupDirectory))
                        {
                            TfTabletFail(M("Dynamic.TfInstall.PackageRejected"), null);
                            return;
                        }

                        var workRoot = Path.Combine(BundledTools.GetCacheRoot(), "tf-tablet-return");
                        Directory.CreateDirectory(workRoot);

                        var assembly = typeof(MainWindow).Assembly;
                        using var toolStream = assembly.GetManifestResourceStream(history.Profile.ArchiveLogicalName);
                        if (toolStream is null)
                        {
                            TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                            return;
                        }

                        newTools = await EdlToolchain.LoadAsync(toolStream, workRoot, ct);
                        if (!ReferenceEquals(newTools.Profile, history.Profile))
                        {
                            newTools.Dispose();
                            newTools = null;
                            TfTabletFail(M("Dynamic.TfInstall.PackageRejected"), null);
                            return;
                        }

                        var entryHelper = new EdlEntry(_transport.AdbPath, _runner!, new WindowsEdlEndpointDiscovery());
                        var binding = await entryHelper.WaitForPresentAsync(history.Identity, history.Profile, ct);

                        var newClient = new EdlClient(newTools, binding, _runner!, new WindowsEdlEndpointDiscovery());
                        await newClient.ProbeAsync(0, true, ct);

                        newFresh = await InternalInstallBackup.CreateAsync(
                            newClient, parent!, new Progress<InternalBackupProgress>(RenderInternalInstallBackupProgress), ct);
                        var currentHistory = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(newFresh.DirectoryPath, ct);

                        if (workflow is not null)
                        {
                            if (restorePrevious)
                            {
                                await workflow.PrepareRestorePreviousFromEdlAsync(currentHistory, newClient, newFresh, ct);
                            }
                            else
                            {
                                await workflow.PrepareFinalFromEdlAsync(currentHistory, newClient, newFresh, ct);
                            }
                        }
                        else
                        {
                            if (!restorePrevious)
                            {
                                // Reopened process: Final is unavailable (no fabricated card proof).
                                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                                return;
                            }

                            var backend = await BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                                currentHistory, newClient, newFresh, journalPath, _runner!, parent!,
                                CreateTfTabletBootProgress(), ct);

                            // Retire the replaced chain before adopting the new backend; if
                            // the old chain disposal fails the new backend is released and
                            // rethrown — the factory is never accepted in a dirty state.
                            try
                            {
                                DisposeTfTabletRecoveryBackendChain();
                            }
                            catch
                            {
                                backend.Dispose();
                                throw;
                            }

                            _tfTabletRecoveryBackend = backend;
                        }

                        // Commit the new fields FIRST: the factories already accepted the
                        // new context, so the new borrowed resources must never be killed
                        // by an old-tool Dispose failure.
                        oldTools = _tfTabletReturnTools;
                        _tfTabletReturnTools = newTools;
                        _tfTabletReturnClient = newClient;
                        oldBackup = _tfTabletReturnBackup;
                        _tfTabletReturnBackup = newFresh;
                        newTools = null;
                        newFresh = null;
                        committed = true;

                        _tfTabletJournalPath = workflow?.CurrentRecoveryJournalPath
                            ?? _tfTabletRecoveryBackend?.Prepared?.RollbackJournalPath
                            ?? journalPath;

                        try
                        {
                            SaveTfTabletMarker();
                        }
                        catch (Exception markerEx)
                        {
                            // The workflow/backend already accepted the new context: keep all
                            // new resources alive even though the cache write failed.
                            TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), markerEx);
                            return;
                        }

                        TfTabletRiskCheck.IsChecked = false;
                        _internalInstallStep = 3;
                        SetTfTabletStatus(M(restorePrevious
                            ? "Dynamic.TfTablet.Stage.PreparedRestorePrevious"
                            : "Dynamic.TfTablet.Stage.PreparedFinalBoot"));
                        RenderTfTabletPages();
                    }
                    catch (OperationCanceledException)
                    {
                        TfTabletFail(M("Dynamic.TfInstall.PrepareFailed"), null);
                    }
                    catch (Exception ex)
                    {
                        TfTabletFail(ex);
                    }
                    finally
                    {
                        if (!committed)
                        {
                            // A failed new preparation disposes only pending new resources;
                            // existing recovery backend, evidence and original shared state stay intact.
                            newFresh?.Dispose();
                            newTools?.Dispose();
                        }
                        else
                        {
                            // Old backup retires before old tools; both are best-effort after
                            // the new fields are committed. Cleanup failure is logged and
                            // never discards the new borrowed context.
                            try
                            {
                                oldBackup?.Dispose();
                            }
                            catch (Exception backupEx)
                            {
                                AppendLocalizedLog(M("Dynamic.RawValue", backupEx.GetType().Name + ": " + backupEx.Message));
                            }

                            try
                            {
                                oldTools?.Dispose();
                            }
                            catch (Exception toolsEx)
                            {
                                AppendLocalizedLog(M("Dynamic.RawValue", toolsEx.GetType().Name + ": " + toolsEx.Message));
                            }
                        }
                    }
                });
            }
            finally
            {
                _tfTabletOperationActive = false;
                RenderTfTabletPages();
                RefreshActions();
            }
        }

        private void DisposeTfTabletRecoveryBackendChain()
        {
            if (_tfTabletRecoveryBackend is not null)
            {
                try
                {
                    _tfTabletRecoveryBackend.Dispose();
                    _tfTabletRecoveryBackend = null;
                }
                catch (Exception ex)
                {
                    // Field stays set so a later retry can attempt the dispose again.
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.GetType().Name + ": " + ex.Message));
                }
            }

            // EdlClient is not IDisposable; its reference is dropped when its borrowed
            // tools are released.
            _tfTabletReturnClient = null;

            if (_tfTabletReturnBackup is not null)
            {
                try
                {
                    _tfTabletReturnBackup.Dispose();
                    _tfTabletReturnBackup = null;
                }
                catch (Exception ex)
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.GetType().Name + ": " + ex.Message));
                }
            }

            if (_tfTabletReturnTools is not null)
            {
                try
                {
                    _tfTabletReturnTools.Dispose();
                    _tfTabletReturnTools = null;
                }
                catch (Exception ex)
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.GetType().Name + ": " + ex.Message));
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 6 — return execution (Final or RestorePrevious), never App Reset
        // ------------------------------------------------------------------

        private async Task ExecuteTfTabletReturnStageAsync(CancellationToken ct)
        {
            var workflow = _tfTabletWorkflow;
            var prepared = workflow?.PreparedReturnBoot;
            if (prepared is null)
            {
                var backend = _tfTabletRecoveryBackend;
                prepared = backend?.Prepared;
                if (prepared is not null)
                {
                    await ExecuteTfTabletRecoveryStageAsync(ct);
                    return;
                }

                return;
            }

            if (workflow is null || workflow.Snapshot.IsBusy)
            {
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.RiskBoot"));
                return;
            }

            if (!ConfirmTfTabletReturnOperation(prepared))
            {
                return;
            }

            try
            {
                SaveTfTabletMarker();
            }
            catch (Exception ex)
            {
                TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), ex);
                return;
            }

            if (!_tfTabletConsumedReturnIds.Add(prepared.ConfirmationId))
            {
                return;
            }

            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;

            TfBootResult? result = null;
            _tfTabletAcceptProgress = true;
            try
            {
                result = await workflow.ExecuteReturnBootAsync(prepared.ConfirmationId, CreateTfTabletBootProgress(), ct);
            }
            catch (OperationCanceledException)
            {
                TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            }
            catch (Exception ex)
            {
                TfTabletFail(ex);
            }
            finally
            {
                _tfTabletAcceptProgress = false;
                TfTabletRiskCheck.IsChecked = false;
            }

            if (result is not null)
            {
                ApplyTfTabletReturnResult(result);
            }
        }

        private async Task ExecuteTfTabletRecoveryStageAsync(CancellationToken ct)
        {
            var backend = _tfTabletRecoveryBackend;
            var prepared = backend?.Prepared;
            if (backend is null || prepared is null || prepared.Operation == TfBootOperation.Temporary)
            {
                TfTabletFail(M("Dynamic.TfInstall.NeedInputs"), null);
                return;
            }

            if (TfTabletRiskCheck.IsChecked != true)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.RiskBoot"));
                return;
            }

            if (!ConfirmTfTabletReturnOperation(prepared))
            {
                return;
            }

            try
            {
                SaveTfTabletMarker();
            }
            catch (Exception ex)
            {
                TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), ex);
                return;
            }

            if (!_tfTabletConsumedReturnIds.Add(prepared.ConfirmationId))
            {
                return;
            }

            _tfTabletBackendExecutionBegan = true;
            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;

            TfBootResult? result = null;
            _tfTabletAcceptProgress = true;
            try
            {
                result = await backend.ExecuteAsync(prepared.ConfirmationId, CreateTfTabletBootProgress(), ct);
            }
            catch (OperationCanceledException)
            {
                TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            }
            catch (Exception ex)
            {
                TfTabletFail(ex);
            }
            finally
            {
                _tfTabletAcceptProgress = false;
                TfTabletRiskCheck.IsChecked = false;
            }

            if (result is not null)
            {
                ApplyTfTabletReturnResult(result);
            }
        }

        private bool ConfirmTfTabletReturnOperation(TfBootPrepared prepared)
        {
            RenderInternalInstallPower();
            var localizedOperation = prepared.Operation == TfBootOperation.Final
                ? T("Dynamic.TfTablet.Operation.Final")
                : T("Dynamic.TfTablet.Operation.RestorePrevious");
            var body = T(
                "Dynamic.TfTablet.ReturnConfirmBody",
                prepared.Model,
                prepared.AndroidSerial,
                localizedOperation,
                prepared.SourceBackupDirectory,
                prepared.EvidenceDirectory,
                FormatTfTabletRegions(prepared),
                InternalInstallPowerText.Text);
            return ShowTfTabletConfirm("Dynamic.TfTablet.ReturnConfirmTitle", body) == MessageBoxResult.Yes;
        }

        private void ApplyTfTabletReturnResult(TfBootResult result)
        {
            var genuineFinal = result.Operation == TfBootOperation.Final
                && result.Outcome == BootMaintenanceOutcome.Completed
                && result.WriteState == InternalInstallWriteState.AllVerified
                && result.ResetAccepted == true
                && (_tfTabletWorkflow?.Snapshot.CardEvidence is { FullyVerified: true }
                    || _tfTabletRetainedCardEvidence is { FullyVerified: true });
            var genuineRestore = result.Operation == TfBootOperation.RestorePrevious
                && result.Outcome == BootMaintenanceOutcome.Completed
                && result.WriteState == InternalInstallWriteState.AllVerified
                && result.ResetAccepted == true;

            if (result.Outcome == BootMaintenanceOutcome.Completed
                && result.WriteState == InternalInstallWriteState.AllVerified)
            {
                // Retain every genuine returned result, even an unconfirmed ACK; never a
                // manufactured one.
                _tfTabletRecoveryResult = result;
                if (genuineFinal)
                {
                    _tfTabletRetainedCardEvidence ??= _tfTabletWorkflow?.Snapshot.CardEvidence;
                }
            }

            if (genuineFinal || genuineRestore)
            {
                if (TryDeleteTfTabletMarker(out var markerError))
                {
                    ShowTfTabletCompletedResult(genuineFinal);
                }
                else
                {
                    // The physical result is never erased or hidden behind the marker
                    // failure; the cleanup problem stays a diagnostic log entry only.
                    AppendLocalizedLog(M("Dynamic.RawValue", markerError!));
                    ShowTfTabletCompletedResult(genuineFinal);
                }

                RenderTfTabletPages();
                return;
            }

            if (result.WriteState == InternalInstallWriteState.AllVerified && result.ResetAccepted != true)
            {
                // Verified writes but the restart was never acknowledged: the marker stays
                // and no automatic retry of the reset is attempted.
                SetTfTabletStatus(M("Dynamic.TfTablet.VerifiedRestartUnconfirmed"));
                if (!string.IsNullOrEmpty(result.Error))
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", result.Error!));
                }

                RenderTfTabletPages();
                return;
            }

            TfTabletFail(M("Dynamic.TfTablet.OperationFailed"), null);
            if (!string.IsNullOrEmpty(result.Error))
            {
                AppendLocalizedLog(M("Dynamic.RawValue", result.Error!));
            }

            RenderTfTabletPages();
        }

        private void ShowTfTabletCompletedResult(bool final)
        {
            if (final)
            {
                if (!_tfTabletCompletionShown)
                {
                    _tfTabletCompletionShown = true;
                    MessageBox.Show(
                        this,
                        T("Dynamic.TfInstall.CompletionBody"),
                        T("Dynamic.TfInstall.CompletionTitle"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                SetTfTabletStatus(M("Dynamic.TfInstall.CompletionTitle"));
            }
            else
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.Restored"));
            }
        }

        // ------------------------------------------------------------------
        // Stage 7 — startup recovery, page entry
        // ------------------------------------------------------------------

        public async Task ReadPendingTfTabletRecoveryAsync()
        {
            _tfTabletMarkerSeen = File.Exists(GetTfTabletMarkerPath());
            if (!_tfTabletMarkerSeen)
            {
                return;
            }

            try
            {
                var marker = TryReadTfTabletMarkerFile();
                if (marker is null)
                {
                    SetTfTabletStatus(M("Dynamic.TfTablet.InvalidPending"));
                    return;
                }

                // Locator validation only; never Ready, never a current-device claim.
                // The saved-journal fact comes only from the actual valid existing marker.
                var hint = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(marker.JournalPath, CancellationToken.None);
                _tfTabletSavedJournalPath = marker.JournalPath;
                _tfTabletJournalPath = hint.JournalPath;
                _tfTabletEvidenceDirectory = marker.EvidenceDirectory;
                _tfTabletOriginalBackupDirectory = hint.OriginalBackupDirectory;
                _internalInstallStep = 2;
                SetTfTabletStatus(M("Dynamic.TfTablet.JournalLabel", hint.JournalPath));
            }
            catch (Exception ex)
            {
                // Malformed or missing journal retains the marker and pending state;
                // the user can Browse an actual journal. No device calls.
                TfTabletFail(M("Dynamic.TfTablet.InvalidPending"), ex);
            }
        }

        public void ForceOpenTfTabletRecoveryPage()
        {
            if (!EnvironmentIsReady || _showingEnvironment)
            {
                return;
            }

            _selectedOperation = "install-tf";
            _tfSource = TfCardSource.Tablet;
            _showingHome = false;
            _showingSupport = false;
            _internalInstallStep = 2;
            UpdateModeUi();
            ApplyFunctionView();
            RenderTfTabletPages();
            RefreshActions();
            RefreshTfTabletActions();
        }

        // ------------------------------------------------------------------
        // Stage 8 — browse an actual recovery journal
        // ------------------------------------------------------------------

        public async Task BrowseTfTabletRecoveryAsync()
        {
            if (_closed || _busy || _tfTabletOperationActive)
            {
                return;
            }

            var dialog = new OpenFileDialog
            {
                Title = T("Dynamic.TfTablet.JournalLabel", string.Empty),
                Filter = "tf-rollback.json|tf-rollback.json",
                CheckFileExists = true,
            };
            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                var hint = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(dialog.FileName, CancellationToken.None);
                var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(hint.OriginalBackupDirectory, CancellationToken.None);
                if (!history.Profile.IsComplete || !history.Profile.SupportsIdentity(history.Identity.Identity))
                {
                    TfTabletFail(M("Dynamic.TfInstall.PackageRejected"), null);
                    return;
                }

                var previousJournal = _tfTabletJournalPath;
                _tfTabletJournalPath = hint.JournalPath;
                _tfTabletOriginalBackupDirectory = hint.OriginalBackupDirectory;
                try
                {
                    // A real Core hint plus a historically loadable backup set allows the
                    // recovery rebind of an invalid locator; the default path never does.
                    SaveTfTabletMarker(allowRecoveryRebind: true);
                }
                catch (Exception markerEx)
                {
                    _tfTabletJournalPath = previousJournal;
                    TfTabletFail(M("Dynamic.TfTablet.MarkerFailed"), markerEx);
                    return;
                }

                _internalInstallStep = 2;
                SetTfTabletStatus(M("Dynamic.TfTablet.JournalLabel", hint.JournalPath));
                RenderTfTabletPages();
                RefreshTfTabletActions();
            }
            catch (Exception ex)
            {
                // Original saved record is preserved on error.
                TfTabletFail(ex);
            }
        }

        // ------------------------------------------------------------------
        // Leave / close / disposal integration
        // ------------------------------------------------------------------

        public async Task<bool> ConfirmLeaveTfTabletAsync(bool ask = true)
        {
            if (_tfTabletOperationActive || _busy)
            {
                return false;
            }

            if (HasPendingTfTabletRecovery)
            {
                SetTfTabletStatus(M("Dynamic.TfTablet.Pending"));
                return false;
            }

            try
            {
                await DisposeTfTabletPreparationAsync();
            }
            catch (Exception ex)
            {
                TfTabletFail(ex);
                return false;
            }

            return true;
        }

        public async Task DisposeTfTabletPreparationAsync()
        {
            if (_tfTabletOperationActive || HasPendingTfTabletRecovery)
            {
                return;
            }

            if (_tfTabletWorkflow is not null)
            {
                var workflow = _tfTabletWorkflow;
                _tfTabletRetainedCardEvidence ??= workflow.Snapshot.CardEvidence;
                try
                {
                    await workflow.DisposeAsync();
                    _tfTabletWorkflow = null;
                }
                catch (Exception ex)
                {
                    // Dispose failure holds the resources for a later retry; nothing is
                    // nulled and no ClearReturnedResults is performed here.
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.GetType().Name + ": " + ex.Message));
                }
            }

            DisposeTfTabletRecoveryBackendChain();


            // Genuine held results, retained card evidence, status, journal/evidence facts
            // and the saved journal are kept until ClearResolvedTfTabletUiState.
            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;
            _tfTabletAcceptProgress = false;
        }

        /// <summary>Parent invalidation hook: refuses any pending/active tablet state; no dialog, no reset.</summary>
        public async Task<bool> DisposeTfTabletPrewriteAsync()
        {
            // Only own active/pending state rejects here; the parent calls this inside its
            // own RunBusy scope, so the global busy lock must not reject it.
            if (_tfTabletOperationActive || HasPendingTfTabletRecovery)
            {
                return false;
            }

            try
            {
                await DisposeTfTabletPreparationAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Parent calls this only after a successful leave or a safe reset: it clears the
        /// resolved own UI state but never pending/unknown/cache state from an unknown run.
        /// </summary>
        private void ClearResolvedTfTabletUiState()
        {
            if (_tfTabletOperationActive
                || _busy
                || _tfTabletWorkflow is not null
                || _tfTabletRecoveryBackend is not null
                || HasPendingTfTabletRecovery)
            {
                return;
            }

            // If an owned marker remains after a true closed return, attempt its precise
            // removal; on failure retain the results and log, never pretend a new install
            // is ready.
            if (_tfTabletMarkerSeen || File.Exists(GetTfTabletMarkerPath()))
            {
                if (!TryDeleteTfTabletMarker(out var markerError))
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", markerError!));
                    return;
                }
            }

            _tfTabletRecoveryResult = null;
            _tfTabletRetainedCardEvidence = null;
            _tfTabletStatus = null;
            _tfTabletLastBootProgress = null;
            _tfTabletLastCardProgress = null;
            _tfTabletJournalPath = null;
            _tfTabletEvidenceDirectory = null;
            _tfTabletOriginalBackupDirectory = null;
            _tfTabletSavedJournalPath = null;
            _tfTabletBackendExecutionBegan = false;
            _tfTabletConsumedReturnIds.Clear();
            _tfTabletCloseApproved = false;
            _tfTabletCompletionShown = false;
        }

        public async Task HandleTfTabletClosingAsync()
        {
            if (_busy || _tfTabletOperationActive)
            {
                // Busy must never close.
                return;
            }

            if (HasPendingTfTabletRecovery)
            {
                if (_tfTabletCloseApproved || _tfTabletClosePromptActive)
                {
                    return;
                }

                _tfTabletClosePromptActive = true;
                try
                {
                    var body = T(
                        "Dynamic.TfTablet.ClosePendingBody",
                        _tfTabletJournalPath ?? string.Empty,
                        _tfTabletEvidenceDirectory ?? string.Empty);
                    var choice = MessageBox.Show(
                        this,
                        body,
                        T("Dynamic.TfTablet.ClosePendingTitle"),
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning,
                        MessageBoxResult.No);
                    if (choice == MessageBoxResult.Yes)
                    {
                        _tfTabletCloseApproved = true;
                        Close();
                    }
                }
                finally
                {
                    _tfTabletClosePromptActive = false;
                }

                return;
            }

            try
            {
                if (!await ConfirmLeaveModernTfInstallAsync(ask: false))
                {
                    return;
                }

                await SafeResetModernTfInstallStateAsync();
                _tfTabletCloseApproved = true;
                Close();
            }
            catch (Exception ex)
            {
                AppendLocalizedLog(M("Dynamic.RawValue", ex.GetType().Name + ": " + ex.Message));
            }
        }
    }
}
