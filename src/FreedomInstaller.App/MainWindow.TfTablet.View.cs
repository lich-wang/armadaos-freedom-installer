using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App
{
    /// <summary>
    /// UI-TF-TABLET-VIEW-1: render/refresh/progress painting for the TF tablet mode.
    /// Pure view logic only; all workflow state and mutations live in the controller
    /// partial (MainWindow.TfTablet.cs) and FreedomInstaller.Core.
    /// </summary>
    public partial class MainWindow
    {
        // ------------------------------------------------------------------
        // Render
        // ------------------------------------------------------------------

        private void RenderTfTabletPages()
        {
            if (!_ready || _closed)
            {
                return;
            }

            if (!IsModernTfTabletMode)
            {
                if (TfTabletStagePanel is not null)
                {
                    TfTabletStagePanel.Visibility = Visibility.Collapsed;
                }

                return;
            }

            RestoreInternalInstallNav();

            int step = _internalInstallStep;
            bool pending = HasPendingTfTabletRecovery;
            bool completed = IsCompletedTfTabletInstall;

            // Page visibility: step 0 check, step 1 backup, inputs page for step >= 2 or pending.
            InternalInstallCheckPage.Visibility = step == 0 ? Visibility.Visible : Visibility.Collapsed;
            InternalInstallBackupPage.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
            TfInstallInputsPage.Visibility = step >= 2 || pending ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceConfirmPage.Visibility = Visibility.Collapsed;
            InternalInstallCapacityPage.Visibility = Visibility.Collapsed;
            InternalInstallConfirmPage.Visibility = Visibility.Collapsed;
            BootMaintenanceSourcesPage.Visibility = Visibility.Collapsed;

            // Stage panel: step >= 2 or pending; stays visible when completed so the final
            // success state (with all buttons/risk collapsed) remains on screen.
            TfTabletStagePanel.Visibility = step >= 2 || pending
                ? Visibility.Visible
                : Visibility.Collapsed;

            // Boot entry panel on step 0; repair sources row never used in tablet mode.
            BootMaintenanceEntryPanel.Visibility = step == 0 ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceRepairSourcesRow.Visibility = Visibility.Collapsed;

            // TF always needs a fresh backup: existing-backup shortcut hidden and disabled.
            InternalInstallBackupUseExistingCheck.Visibility = Visibility.Collapsed;
            InternalInstallBackupUseExistingCheck.IsEnabled = false;
            InternalInstallBackupExistingRow.Visibility = Visibility.Collapsed;
            InternalInstallBackupExistingRow.IsEnabled = false;

            // Shared labels follow the localization registry instead of pinned values.
            SharedEdlEntryHintText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.EdlHint");
            SharedEdlOriginalEntryLabel.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.HistorySource");
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Inputs");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Confirm");

            // Historical source controls only for an already-EDL device; no false readiness.
            bool historyVisible = _bootMaintenanceAlreadyEdl;
            BootMaintenanceEntryOriginalBox.Visibility = historyVisible ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceEntryOriginalBrowseButton.Visibility = historyVisible ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceEntryOriginalBrowseButton.IsEnabled = historyVisible;

            // Card discovery host belongs to Reader mode; sections move into the inputs hosts.
            TfCardDiscoveryHost.Visibility = Visibility.Collapsed;
            MoveModernTfElement(TfCardSection, TfInstallCardHost);
            MoveModernTfElement(PackageSection, TfInstallPackageHost);
            TfCardSection.Visibility = Visibility.Visible;
            PackageSection.Visibility = Visibility.Visible;

            PaintTfTabletCardSummary();
            PaintTfTabletStageStatus();
            PaintTfTabletRisk();
            PaintTfTabletJournal();

            // Reapply last real progress without re-logging; otherwise idle bar state.
            if (_tfTabletLastBootProgress is not null)
            {
                PaintTfTabletBootProgress(_tfTabletLastBootProgress, log: false);
            }
            else if (_tfTabletLastCardProgress is not null)
            {
                PaintTfTabletCardProgress(_tfTabletLastCardProgress, log: false);
            }
            else
            {
                bool active = _busy || _tfTabletOperationActive;
                TfTabletProgressBar.IsIndeterminate = active;
                TfTabletProgressBar.Value = 0;
                SetText(TfTabletProgressText, "Dynamic.RawValue", string.Empty);
            }

            // Always actual host driver file facts.
            RenderTfTabletHostDriverStatus();
            RenderBootMaintenanceCheckButton();

            RefreshTfTabletActions();
        }

        // ------------------------------------------------------------------
        // Refresh
        // ------------------------------------------------------------------

        private void RefreshTfTabletActions()
        {
            if (!_ready || _closed || !IsModernTfTabletMode)
            {
                return;
            }

            var workflow = _tfTabletWorkflow;
            var stage = workflow?.Snapshot.Stage;
            bool pending = HasPendingTfTabletRecovery;
            bool idle = !_busy && !_tfTabletOperationActive && !_closed;
            bool returnVerified = IsTfTabletReturnVerified;
            bool completed = IsCompletedTfTabletInstall;

            bool inputsEditable = idle
                && !pending
                && !HasPreparedTfTabletStage
                && !returnVerified;

            // --- Sidebar navigation: blocked while pending except the current step.
            InternalInstallNavCheck.IsEnabled = (!pending || _internalInstallStep == 0) && CanEnterModernTfInstallStep(0);
            InternalInstallNavBackup.IsEnabled = (!pending || _internalInstallStep == 1) && CanEnterModernTfInstallStep(1);
            InternalInstallNavCapacity.IsEnabled = (!pending || _internalInstallStep == 2) && CanEnterModernTfInstallStep(2);
            InternalInstallNavConfirm.IsEnabled = (!pending || _internalInstallStep == 3) && CanEnterModernTfInstallStep(3);

            PrevButton.IsEnabled = !pending
                && _internalInstallStep > 0
                && CanEnterModernTfInstallStep(_internalInstallStep - 1);

            // Pre-temp step 2 keeps the existing Next button as the prepare action.
            bool nextVisible = !pending && !completed && _internalInstallStep < 3;
            NextButton.Visibility = nextVisible ? Visibility.Visible : Visibility.Collapsed;
            NextButton.IsEnabled = nextVisible && (_internalInstallStep switch
            {
                0 => CanEnterModernTfInstallStep(1),
                1 => CanEnterModernTfInstallStep(2),
                2 => false,
                _ => false,
            });

            // --- ActionButton: step 3 dispatch only, same gate as the dedicated execute button.
            ActionButton.Visibility = !pending && _internalInstallStep == 3
                ? Visibility.Visible
                : Visibility.Collapsed;
            ActionButton.IsEnabled = idle && CanExecuteTfTabletCurrentStage();
            SetContent(ActionButton, "Dynamic.TfTablet.Execute");

            // --- Source radios: editable only when inputs are; Reader UAC handling stays in the parent click path.
            TfSourceTabletRadio.IsEnabled = inputsEditable;
            TfSourceReaderRadio.IsEnabled = inputsEditable;

            // --- Package controls: fresh-nonnull + device proof gate; validate on the actual candidate text.
            bool packageEditable = inputsEditable
                && _internalInstallStep == 2
                && _internalInstallBackup is not null
                && HasBootMaintenanceDeviceProof;
            PackagePathBox.IsEnabled = packageEditable;
            BrowsePackageButton.IsEnabled = packageEditable;
            ValidatePackageButton.IsEnabled = packageEditable && TfTabletPathExists(PackagePathBox.Text);

            // --- Backup / detection / history controls: inputs editable with actual prerequisites.
            // Folder choice/edit must work before any folder is selected; only the actual
            // backup start needs a real prerequisite plus an existing parent directory.
            bool backupPrereqEditable = inputsEditable && HasBootMaintenanceBackupPrerequisite;
            bool backupStartEditable = backupPrereqEditable
                && !string.IsNullOrWhiteSpace(_internalInstallBackupParent)
                && Directory.Exists(_internalInstallBackupParent);
            bool backupBrowseEditable = inputsEditable && HasBootMaintenanceBackupPrerequisite;
            InternalInstallBackupFolderBox.IsEnabled = backupBrowseEditable;
            InternalInstallBackupBrowseButton.IsEnabled = backupBrowseEditable;
            InternalInstallBackupButton.IsEnabled = backupStartEditable;

            // --- Detection: never requires an existing backup (that would deadlock the flow);
            // the first device check must work before any backup exists.
            bool detectEnabled = idle
                && !pending
                && !HasPreparedTfTabletStage
                && !HasInternalInstallLiveEdlState
                && _transport is not null;
            bool checkEnabled = detectEnabled;
            InternalInstallCheckButton.IsEnabled = checkEnabled;
            InternalInstallDevicesCombo.IsEnabled = detectEnabled
                && !HasInternalInstallLiveEdlState
                && InternalInstallDevicesCombo.Items.Count > 0;

            // --- Ports: refresh/connect only in the RAM connection phases; the selected
            // item must carry an actual MaintenanceSerialPort record.
            bool portsPhase = stage == TfTabletInstallStage.AwaitingRamConnection
                || stage == TfTabletInstallStage.RamConnected;
            TfTabletPortsCombo.Visibility = portsPhase ? Visibility.Visible : Visibility.Collapsed;
            TfTabletRefreshPortsButton.Visibility = TfTabletPortsCombo.Visibility;
            TfTabletConnectRamButton.Visibility = TfTabletPortsCombo.Visibility;
            TfTabletPortsCombo.IsEnabled = idle && portsPhase;
            TfTabletRefreshPortsButton.IsEnabled = idle && portsPhase;
            TfTabletConnectRamButton.IsEnabled = idle
                && stage == TfTabletInstallStage.AwaitingRamConnection
                && TfTabletPortsCombo.SelectedItem is ComboBoxItem { Tag: MaintenanceSerialPort };

            // --- Cards: discovery and selection only while RAM connected with a real
            // confirmed temporary boot (never on a sealed prepared card).
            bool cardsPhase = stage == TfTabletInstallStage.RamConnected;
            TfCardsCombo.Visibility = cardsPhase ? Visibility.Visible : Visibility.Collapsed;
            ReadTfCardsButton.Visibility = cardsPhase ? Visibility.Visible : Visibility.Collapsed;
            TfTabletPrepareCardButton.Visibility = cardsPhase ? Visibility.Visible : Visibility.Collapsed;
            TfCardsCombo.IsEnabled = idle && cardsPhase && _tfCards.Count > 0;
            ReadTfCardsButton.IsEnabled = idle
                && workflow is not null
                && cardsPhase;
            TfTabletPrepareCardButton.IsEnabled = idle
                && cardsPhase
                && _tfCard is not null
                && IsConfirmedTfBootResult(workflow?.Snapshot.TemporaryResult);

            // --- Suspend: visible only for an actual workflow pending that is not already
            // awaiting the EDL return and not completed/restored.
            bool suspendVisible = workflow is not null
                && pending
                && stage is not (TfTabletInstallStage.AwaitingEdlReturn
                    or TfTabletInstallStage.Completed
                    or TfTabletInstallStage.RestoredPrevious);
            TfTabletSuspendButton.Visibility = suspendVisible ? Visibility.Visible : Visibility.Collapsed;
            TfTabletSuspendButton.IsEnabled = suspendVisible && idle;

            // --- Final: awaiting EDL return with real card proof; Restore: failed/unknown or
            // a valid reopened pending marker.
            bool finalVisible = pending
                && stage == TfTabletInstallStage.AwaitingEdlReturn
                && (workflow?.Snapshot.CardEvidence?.FullyVerified ?? _tfTabletRetainedCardEvidence?.FullyVerified) == true;
            TfTabletPrepareFinalButton.Visibility = finalVisible ? Visibility.Visible : Visibility.Collapsed;
            TfTabletPrepareFinalButton.IsEnabled = finalVisible && idle;

            // Restore is possible both for a reopened process (workflow == null) and for a
            // same-process live workflow whose stage can no longer reach Final on its own
            // (AwaitingEdlReturn / Failed / Cancelled / UnknownWriteOutcome).
            bool restoreStageEligible = workflow is null
                || stage is TfTabletInstallStage.AwaitingEdlReturn
                    or TfTabletInstallStage.Failed
                    or TfTabletInstallStage.Cancelled
                    or TfTabletInstallStage.UnknownWriteOutcome;
            bool restoreVisible = pending
                && !returnVerified
                && restoreStageEligible
                && !string.IsNullOrEmpty(_tfTabletJournalPath)
                && TfTabletPathExists(_tfTabletJournalPath);
            TfTabletPrepareRestoreButton.Visibility = restoreVisible ? Visibility.Visible : Visibility.Collapsed;
            TfTabletPrepareRestoreButton.IsEnabled = restoreVisible && idle;

            // --- Browse recovery: only a pending state with no live workflow whose journal
            // is missing or explicitly invalid.
            bool browseVisible = pending
                && workflow is null
                && (string.IsNullOrEmpty(_tfTabletJournalPath)
                    || !TfTabletPathExists(_tfTabletJournalPath)
                    || _tfTabletStatus?.Key == "Dynamic.TfTablet.InvalidPending");
            TfTabletBrowseRecoveryButton.Visibility = browseVisible ? Visibility.Visible : Visibility.Collapsed;
            TfTabletBrowseRecoveryButton.IsEnabled = browseVisible && idle;

            // --- Execute: visible for a concrete executable stage that has not already had
            // its confirmation consumed (no disabled old execute button lingers after a
            // real attempt); dispatch authority remains the pure gate.
            bool executeVisible = !completed
                && CanExecuteTfTabletCurrentStageGateOnly()
                && !TfTabletCurrentStageConfirmationConsumed();
            TfTabletExecuteButton.Visibility = executeVisible ? Visibility.Visible : Visibility.Collapsed;
            TfTabletExecuteButton.IsEnabled = executeVisible && idle && CanExecuteTfTabletCurrentStage();

            // --- Risk acknowledgement: enabled whenever a concrete prepared stage could be
            // attempted; the checkbox itself must be checkable without being pre-checked.
            bool riskEnabled = idle
                && !completed
                && (stage is TfTabletInstallStage.PreparedTemporary
                    or TfTabletInstallStage.CardPrepared
                    or TfTabletInstallStage.PreparedFinalBoot
                    or TfTabletInstallStage.PreparedRestorePrevious
                    || (workflow is null
                        && _tfTabletRecoveryBackend?.Prepared is not null));
            TfTabletRiskCheck.Visibility = riskEnabled || TfTabletRiskCheck.IsChecked == true
                ? Visibility.Visible
                : Visibility.Collapsed;
            TfTabletRiskCheck.IsEnabled = riskEnabled;

            // --- Generic exit maintenance only for a shared live device outside any pending flow.
            bool exitVisible = !pending
                && !returnVerified
                && HasInternalInstallLiveEdlState;
            InternalInstallExitMaintenancePanel.Visibility = exitVisible
                ? Visibility.Visible
                : Visibility.Collapsed;
            InternalInstallExitMaintenanceButton.IsEnabled = idle && _internalInstallEdlClient is not null;

            // Clear a stale disabled-backend reason so it cannot reappear on refresh.
            SetText(ActionReasonText, "Dynamic.RawValue", string.Empty);

            // Legacy helpers run before the final assignments so they cannot loosen the
            // critical pending/backup/detection gates above.
            UpdateInternalInstallDeviceSelector();
            RefreshSharedAdvancedCheckAvailability();

            // Reassert the critical controls after the legacy helpers; the check button is
            // never gated on backup state, otherwise the first check is impossible.
            TfSourceTabletRadio.IsEnabled = inputsEditable;
            TfSourceReaderRadio.IsEnabled = inputsEditable;
            PackagePathBox.IsEnabled = packageEditable;
            BrowsePackageButton.IsEnabled = packageEditable;
            InternalInstallBackupButton.IsEnabled = backupStartEditable;
            InternalInstallCheckButton.IsEnabled = checkEnabled;
            InternalInstallDevicesCombo.IsEnabled = detectEnabled
                && !HasInternalInstallLiveEdlState
                && InternalInstallDevicesCombo.Items.Count > 0;
            TfTabletRiskCheck.IsEnabled = riskEnabled;
        }

        /// <summary>Visibility-only stage check: no risk-check requirement, no dispatch.</summary>
        private bool CanExecuteTfTabletCurrentStageGateOnly()
        {
            if (!EnvironmentIsReady || _closed || !IsModernTfTabletMode)
            {
                return false;
            }

            var workflow = _tfTabletWorkflow;
            if (workflow is not null)
            {
                switch (workflow.Snapshot.Stage)
                {
                    case TfTabletInstallStage.PreparedTemporary:
                        return workflow.Prepared is not null && workflow.Snapshot.TemporaryResult is null;
                    case TfTabletInstallStage.CardPrepared:
                        return workflow.PreparedCard is not null;
                    case TfTabletInstallStage.PreparedFinalBoot:
                    case TfTabletInstallStage.PreparedRestorePrevious:
                        return workflow.PreparedReturnBoot is not null;
                    default:
                        return false;
                }
            }

            var backend = _tfTabletRecoveryBackend;
            var prepared = backend?.Prepared;
            return prepared is not null && prepared.Operation != TfBootOperation.Temporary;
        }

        /// <summary>
        /// Visibility-only helper: the current stage's confirmation id was already consumed
        /// by an actual attempt, so the execute button must not stay on screen.
        /// </summary>
        private bool TfTabletCurrentStageConfirmationConsumed()
        {
            var workflow = _tfTabletWorkflow;
            if (workflow is not null)
            {
                return workflow.Snapshot.Stage switch
                {
                    TfTabletInstallStage.PreparedTemporary => workflow.Prepared is not null
                        && _tfTabletConsumedReturnIds.Contains(workflow.Prepared.ConfirmationId),
                    TfTabletInstallStage.CardPrepared => workflow.PreparedCard is not null
                        && _tfTabletConsumedReturnIds.Contains(workflow.PreparedCard.ConfirmationId),
                    TfTabletInstallStage.PreparedFinalBoot
                        or TfTabletInstallStage.PreparedRestorePrevious => workflow.PreparedReturnBoot is not null
                        && _tfTabletConsumedReturnIds.Contains(workflow.PreparedReturnBoot.ConfirmationId),
                    _ => false,
                };
            }

            var prepared = _tfTabletRecoveryBackend?.Prepared;
            return prepared is not null
                && prepared.Operation != TfBootOperation.Temporary
                && _tfTabletConsumedReturnIds.Contains(prepared.ConfirmationId);
        }

        // ------------------------------------------------------------------
        // Progress painting
        // ------------------------------------------------------------------

        private void RenderTfTabletBootProgress(InternalInstallProgress report)
        {
            if (!_ready || _closed)
            {
                return;
            }

            _tfTabletLastBootProgress = report;
            _tfTabletLastCardProgress = null;
            PaintTfTabletBootProgress(report, log: true);
        }

        private void RenderTfTabletCardProgress(TfCardWriteProgress report)
        {
            if (!_ready || _closed)
            {
                return;
            }

            _tfTabletLastCardProgress = report;
            _tfTabletLastBootProgress = null;
            PaintTfTabletCardProgress(report, log: true);
        }

        private void PaintTfTabletBootProgress(InternalInstallProgress report, bool log)
        {
            string stageKey = "Dynamic.InternalInstall.Execution.Stage." + report.Stage;

            // The stage stays a nested UiMessage so late language switches recompute; the
            // read/write phase must survive into the byte-counted branch too.
            var stage = M(stageKey);
            UiMessage message;
            if (report.IoPhase is { } ioPhase)
            {
                message = M(
                    "Dynamic.InternalInstall.Execution.Status.IoPhase",
                    stage,
                    M("Dynamic.InternalInstall.Execution.IoPhase." + ioPhase));
            }
            else
            {
                message = stage;
            }

            if (report.IoTotalBytes is long total && total > 0)
            {
                var ioStage = report.IoPhase is { } ioPhaseForBytes
                    ? M(
                        "Dynamic.InternalInstall.Execution.Status.IoPhase",
                        stage,
                        M("Dynamic.InternalInstall.Execution.IoPhase." + ioPhaseForBytes))
                    : stage;
                message = M(
                    "Dynamic.TfInstall.Progress.Bytes",
                    ioStage,
                    FormatBytes(report.IoCompletedBytes ?? 0),
                    FormatBytes(total));

                TfTabletProgressBar.IsIndeterminate = false;
                TfTabletProgressBar.Value = Math.Clamp((double)(report.IoCompletedBytes ?? 0) / total, 0, 1) * 100.0;
            }
            else
            {
                TfTabletProgressBar.IsIndeterminate = _busy || _tfTabletOperationActive;
                TfTabletProgressBar.Value = 0;
            }

            SetText(TfTabletProgressText, message);
            if (log)
            {
                AppendLocalizedLog(message);
            }
        }

        private void PaintTfTabletCardProgress(TfCardWriteProgress report, bool log)
        {
            string stageKey = "Dynamic.TfInstall.CardStage." + report.Stage;

            var stage = M(stageKey);
            UiMessage message;
            if (report.TotalBytes is long total && total > 0)
            {
                message = M(
                    "Dynamic.TfInstall.Progress.Bytes",
                    stage,
                    FormatBytes(report.BytesCompleted ?? 0),
                    FormatBytes(total));

                TfTabletProgressBar.IsIndeterminate = false;
                TfTabletProgressBar.Value = Math.Clamp((double)(report.BytesCompleted ?? 0) / total, 0, 1) * 100.0;
            }
            else
            {
                message = stage;
                TfTabletProgressBar.IsIndeterminate = _busy || _tfTabletOperationActive;
                TfTabletProgressBar.Value = 0;
            }

            SetText(TfTabletProgressText, message);
            if (log)
            {
                // The visible progress text keeps the localized stage; the diagnostic detail
                // is logged once, it never replaces the on-screen progress line.
                AppendLocalizedLog(message);
                if (!string.IsNullOrEmpty(report.Detail))
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", report.Detail));
                }
            }
        }

        // ------------------------------------------------------------------
        // Event handlers
        // ------------------------------------------------------------------

        private async void OnTfTabletRefreshPorts(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await RefreshTfTabletPortsAsync();
        }

        private async void OnTfTabletConnectRam(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await ConnectTfTabletRamAsync();
        }

        private async void OnTfTabletPrepareCard(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await PrepareTfTabletCardAsync();
        }

        private async void OnTfTabletSuspend(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await SuspendTfTabletForEdlAsync();
        }

        private async void OnTfTabletPrepareFinal(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await PrepareTfTabletReturnAsync(false);
        }

        private async void OnTfTabletPrepareRestore(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await PrepareTfTabletReturnAsync(true);
        }

        private async void OnTfTabletExecute(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await ExecuteTfTabletCurrentStageAsync();
        }

        private async void OnTfTabletBrowseRecovery(object sender, RoutedEventArgs e)
        {
            if (!CanHandleTfTabletEvent())
            {
                return;
            }

            await BrowseTfTabletRecoveryAsync();
        }

        private void OnTfTabletRiskChanged(object sender, RoutedEventArgs e)
        {
            // Risk / port-changed repaints run even while the global busy lock is held; the
            // own refresh handles the idle-only parts.
            if (_ready && !_closed && IsModernTfTabletMode)
            {
                RefreshTfTabletActions();
            }
        }

        private void OnTfTabletPortChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_ready && !_closed && IsModernTfTabletMode)
            {
                RefreshTfTabletActions();
            }
        }

        // ------------------------------------------------------------------
        // Paint helpers
        // ------------------------------------------------------------------

        private void PaintTfTabletStageStatus()
        {
            UiMessage message = BuildTfTabletStageStatus();
            SetText(TfTabletStageStatusText, message);
            SetTfStatus(message);
        }

        private UiMessage BuildTfTabletStageStatus()
        {
            // A genuine closed return outranks everything, regardless of whether a backend
            // or workflow object is still present.
            if (IsCompletedTfTabletInstall)
            {
                return M("Dynamic.TfTablet.Stage.Completed");
            }

            if (IsTfTabletReturnVerified)
            {
                return M("Dynamic.TfTablet.Restored");
            }

            var workflow = _tfTabletWorkflow;

            // A held genuine result outranks any stage-derived fallback: Temp with no ACK
            // and a reopened Restore with no ACK both surface here before the stage panel.
            if (_tfTabletRecoveryResult is { } held
                && held.Operation != TfBootOperation.Temporary
                && held.WriteState == InternalInstallWriteState.AllVerified
                && held.ResetAccepted != true)
            {
                return M("Dynamic.TfTablet.VerifiedRestartUnconfirmed");
            }

            if (workflow is not null)
            {
                var snapshot = workflow.Snapshot;
                var stage = snapshot.Stage;

                // Verified writes without the reset ACK come from either result slot.
                if ((snapshot.TemporaryResult is { } temporary
                        && temporary.WriteState == InternalInstallWriteState.AllVerified
                        && temporary.ResetAccepted != true)
                    || (snapshot.FinalResult is { } final
                        && final.WriteState == InternalInstallWriteState.AllVerified
                        && !IsConfirmedTfBootResult(final))
                    || (snapshot.RestoreResult is { } restore
                        && restore.WriteState == InternalInstallWriteState.AllVerified
                        && !IsConfirmedTfBootResult(restore)))
                {
                    return M("Dynamic.TfTablet.VerifiedRestartUnconfirmed");
                }

                if (stage == TfTabletInstallStage.RestoredPrevious
                    && IsConfirmedTfBootResult(snapshot.RestoreResult))
                {
                    return M("Dynamic.TfTablet.Restored");
                }
            }

            // An actual cache-save failure or operation error must not be hidden behind a
            // stale prepared stage; only the genuine closed-result checks above outrank it.
            if (_tfTabletStatus is not null
                && (_tfTabletStatus.Key == "Dynamic.TfTablet.MarkerFailed"
                    || _tfTabletStatus.Key == "Dynamic.TfTablet.OperationFailed"
                    || _tfTabletStatus.Key == "Dynamic.TfTablet.InvalidPending"
                    || _tfTabletStatus.Key == "Dynamic.TfTablet.VerifiedRestartUnconfirmed"))
            {
                return _tfTabletStatus;
            }

            if (workflow is not null)
            {
                return M("Dynamic.TfTablet.Stage." + workflow.Snapshot.Stage);
            }

            if (_tfTabletRecoveryBackend?.Prepared is not null)
            {
                return M("Dynamic.TfTablet.Stage.PreparedRestorePrevious");
            }

            if (_tfTabletStatus is not null)
            {
                return _tfTabletStatus;
            }

            return M(HasPendingTfTabletRecovery
                ? "Dynamic.TfTablet.InvalidPending"
                : "Dynamic.TfInstall.NeedInputs");
        }

        private void PaintTfTabletRisk()
        {
            var stage = _tfTabletWorkflow?.Snapshot.Stage;
            string key = stage switch
            {
                TfTabletInstallStage.PreparedTemporary or TfTabletInstallStage.WritingTemporaryBoot
                    => "Dynamic.TfTablet.RiskTemporary",
                TfTabletInstallStage.CardPrepared or TfTabletInstallStage.WritingCard
                    => "Dynamic.TfTablet.RiskCard",
                _ => "Dynamic.TfTablet.RiskBoot",
            };

            SetContent(TfTabletRiskCheck, key);
        }

        private void PaintTfTabletJournal()
        {
            if (string.IsNullOrEmpty(_tfTabletJournalPath))
            {
                SetText(TfTabletRecoveryJournalText, "Dynamic.TfTablet.JournalLabel", M("Dynamic.RawValue", string.Empty));
                return;
            }

            SetText(TfTabletRecoveryJournalText, "Dynamic.TfTablet.JournalLabel", _tfTabletJournalPath);
        }

        private void PaintTfTabletCardSummary()
        {
            // Real prepared-card space numbers when present; otherwise a valid matching
            // plan preview; otherwise the UnknownValue constant.
            if (_tfTabletWorkflow?.PreparedCard is { } preparedCard)
            {
                var space = preparedCard.Space;
                SetRawText(TfTotalText, FormatBytes(space.TotalBytes));
                SetRawText(TfBootText, FormatBytes(space.LinuxBootBytes));
                SetRawText(TfRootText, FormatBytes(space.LinuxRootBytes));
                SetRawText(TfDataText, FormatBytes(space.EstimatedLinuxDataBytes));
                return;
            }

            if (_tfCard is { } selected)
            {
                SetRawText(TfTotalText, FormatBytes(selected.SizeBytes));
            }
            else
            {
                SetRawText(TfTotalText, UnknownValue);
            }

            if (_tfPlan is { } plan && _tfCard is { } selectedForPlan
                && string.Equals(plan.TargetKey, selectedForPlan.Key, StringComparison.Ordinal))
            {
                SetRawText(TfBootText, FormatBytes(plan.LinuxBootBytes));
                SetRawText(TfRootText, FormatBytes(plan.LinuxRootBytes));
                SetRawText(TfDataText, FormatBytes(plan.EstimatedLinuxDataBytes));
            }
            else
            {
                SetRawText(TfBootText, UnknownValue);
                SetRawText(TfRootText, UnknownValue);
                SetRawText(TfDataText, UnknownValue);
            }
        }

        private void SetRawText(TextBlock target, string value)
        {
            SetText(target, "Dynamic.RawValue", value);
        }

        private bool CanHandleTfTabletEvent()
        {
            return _ready
                && !_closed
                && !_busy
                && !_tfTabletOperationActive
                && IsModernTfTabletMode;
        }

        private static bool IsConfirmedTfBootResult(TfBootResult? result)
        {
            return result is not null
                && result.Outcome == BootMaintenanceOutcome.Completed
                && result.WriteState == InternalInstallWriteState.AllVerified
                && result.ResetAccepted == true;
        }

        private static bool TfTabletPathExists(string? path)
        {
            return !string.IsNullOrWhiteSpace(path)
                && (File.Exists(path) || Directory.Exists(path));
        }
    }
}
