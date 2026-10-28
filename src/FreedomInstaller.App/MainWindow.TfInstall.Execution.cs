using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App
{
    public partial class MainWindow
    {
        private UiMessage? _tfInstallExitStatus;

        private void SetModernTfInstallExitStatus(UiMessage message)
        {
            _tfInstallExitStatus = message;
            SetText(InternalInstallExitMaintenanceStatusText, message);
            SetText(BootMaintenanceConfirmStatusText, message);
        }

        private bool CanExecuteModernTfInstall()
        {
            if (IsModernTfTabletMode)
            {
                return CanExecuteTfTabletCurrentStage();
            }

            if (!_ready || _closed || _busy || _tfInstallOperationActive)
            {
                return false;
            }

            if (!IsModernTfInstallMode)
            {
                return false;
            }

            if (_tfSource != TfCardSource.Reader || _internalInstallBackup == null)
            {
                return false;
            }

            if (_internalInstallStep != 3)
            {
                return false;
            }

            if (_tfInstallExecuteAttempted
                || IsCompletedModernTfInstall
                || HasUnresolvedModernTfInstallState
                || _tfInstallResetAttempted)
            {
                return false;
            }

            if (!HasBootMaintenanceDeviceProof)
            {
                return false;
            }

            if (BootMaintenanceRiskCheck.IsChecked != true)
            {
                return false;
            }

            var workflow = _tfInstallWorkflow;
            var package = _tfInstallPackage;
            var client = _internalInstallEdlClient;
            var entry = _internalInstallEdlEntry;

            if (workflow == null
                || workflow.Prepared == null
                || package == null
                || client == null
                || entry == null)
            {
                return false;
            }

            var selectedCard = _tfCard;
            if (selectedCard == null
                || !string.Equals(workflow.Prepared.Card.Key, selectedCard.Key, StringComparison.Ordinal))
            {
                return false;
            }

            return true;
        }

        private async Task ExecuteModernTfInstallAsync()
        {
            if (IsModernTfTabletMode)
            {
                await ExecuteTfTabletCurrentStageAsync();
                return;
            }

            if (!CanExecuteModernTfInstall())
            {
                return;
            }

            var workflow = _tfInstallWorkflow!;
            var prepared = workflow.Prepared!;
            var client = _internalInstallEdlClient!;
            var entry = _internalInstallEdlEntry!;
            var package = _tfInstallPackage!;
            var backup = _internalInstallBackup!;
            var card = prepared.Card;
            var boot = prepared.Boot;

            var regionLines = new List<string>();
            foreach (var region in boot.Regions)
            {
                regionLines.Add(T(
                    region.WillWrite ? "Dynamic.BootMaintenance.RegionWrite" : "Dynamic.BootMaintenance.RegionKeep",
                    region.Role ?? string.Empty,
                    region.Slot ?? string.Empty,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length));
            }

            RenderInternalInstallPower();
            var powerText = InternalInstallPowerText.Text;

            var choice = MessageBox.Show(
                this,
                T(
                    "Dynamic.TfInstall.ConfirmBody",
                    boot.Model,
                    boot.AndroidSerial,
                    card.DevicePath,
                    FormatBytes(card.SizeBytes),
                    prepared.BackupDirectory,
                    prepared.EvidenceDirectory,
                    powerText,
                    string.Join(Environment.NewLine, regionLines)),
                T("Dynamic.TfInstall.ConfirmTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);

            if (choice != MessageBoxResult.Yes)
            {
                return;
            }

            // Re-verify every captured reference and the surrounding state after the prompt.
            if (_closed
                || _busy
                || _tfInstallOperationActive
                || !IsModernTfInstallMode
                || _tfSource != TfCardSource.Reader
                || !ReferenceEquals(_internalInstallBackup, backup)
                || _internalInstallStep != 3
                || !ReferenceEquals(_tfInstallWorkflow, workflow)
                || !ReferenceEquals(_tfInstallPackage, package)
                || !ReferenceEquals(_internalInstallEdlClient, client)
                || !ReferenceEquals(_internalInstallEdlEntry, entry)
                || workflow.Prepared == null
                || !string.Equals(workflow.Prepared.Card.Key, _tfCard?.Key, StringComparison.Ordinal)
                || BootMaintenanceRiskCheck.IsChecked != true)
            {
                return;
            }

            _tfInstallExecuteAttempted = true;
            _tfInstallOperationActive = true;
            _tfInstallExitStatus = null;
            _tfInstallError = null;
            _tfInstallLastProgress = null;
            RefreshActions();

            var acceptProgress = false;
            var lastLoggedStage = string.Empty;

            var progress = new Progress<TfInstallProgress>(p =>
            {
                if (!acceptProgress || _closed || !_tfInstallOperationActive)
                {
                    return;
                }

                _tfInstallLastProgress = p;
                RenderModernTfInstallRuntimeStatus();

                var message = BuildModernTfInstallProgressMessage(p, out var stageKey);
                if (!string.IsNullOrEmpty(stageKey) && !string.Equals(stageKey, lastLoggedStage, StringComparison.Ordinal))
                {
                    lastLoggedStage = stageKey!;
                    AppendLocalizedLog(message);
                }

                if (!string.IsNullOrEmpty(p.Detail))
                {
                    AppendLocalizedLog(M("Dynamic.TfInstall.Log.Detail", p.Detail));
                }
            });

            try
            {
                try
                {
                    await RunBusyAsync(async token =>
                    {
                        acceptProgress = true;
                        TfInstallResult result;
                        try
                        {
                            result = await workflow.ExecuteAsync(prepared.ConfirmationId, progress, token);
                        }
                        catch (OperationCanceledException)
                        {
                            if (!workflow.Snapshot.ExecutionStarted)
                            {
                                // Cancelled before any physical write intent: prewrite failure surface.
                                _tfInstallExitStatus = M("Dynamic.TfInstall.Status.PrewriteFailed");
                                RenderModernTfInstallRuntimeStatus();
                            }

                            // Physical attempt already started: keep unresolved display, never zero-write it away.
                            return;
                        }
                        catch (Exception ex)
                        {
                            // Raw exception is folded into the log only; never reset protection on a physical attempt.
                            AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
                            RenderModernTfInstallRuntimeStatus();
                            return;
                        }

                        _tfInstallLastResult = result;
                        if (!string.IsNullOrEmpty(result.Error))
                        {
                            AppendLocalizedLog(M("Dynamic.RawValue", result.Error));
                        }

                        RenderModernTfInstallRuntimeStatus();
                    });
                }
                finally
                {
                    acceptProgress = false;
                    _tfInstallOperationActive = false;
                    if (!_closed)
                    {
                        RenderModernTfInstallRuntimeStatus();
                        RefreshActions();
                    }
                }

                if (!_closed && !_tfInstallCompletionShown && IsCompletedModernTfInstall)
                {
                    _tfInstallCompletionShown = true;
                    MessageBox.Show(
                        this,
                        T("Dynamic.TfInstall.CompletionBody"),
                        T("Dynamic.TfInstall.CompletionTitle"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information,
                        MessageBoxResult.OK);
                }
            }
            catch (Exception ex)
            {
                if (!_closed)
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
                    RenderModernTfInstallRuntimeStatus();
                }
            }
        }

        private UiMessage BuildModernTfInstallProgressMessage(TfInstallProgress progress, out string? stageKey)
        {
            stageKey = null;

            if (progress.Card != null)
            {
                var card = progress.Card;
                var stage = M("Dynamic.TfInstall.CardStage." + card.Stage);
                stageKey = "Dynamic.TfInstall.CardStage." + card.Stage;
                if (card.TotalBytes is long total && total > 0)
                {
                    var done = card.BytesCompleted ?? 0;
                    return M("Dynamic.TfInstall.Progress.Bytes", stage, FormatBytes(done), FormatBytes(total));
                }

                return stage;
            }

            if (progress.Boot != null)
            {
                var bootProgress = progress.Boot;
                var stage = M("Dynamic.InternalInstall.Execution.Stage." + bootProgress.Stage);
                stageKey = "Dynamic.InternalInstall.Execution.Stage." + bootProgress.Stage;
                if (bootProgress.IoPhase is { } phase)
                {
                    stageKey += ".IoPhase." + phase;
                    stage = M("Dynamic.InternalInstall.Execution.Status.IoPhase", stage, M("Dynamic.InternalInstall.Execution.IoPhase." + phase));
                }

                if (bootProgress.IoTotalBytes is long ioTotal && ioTotal > 0)
                {
                    return M(
                        "Dynamic.TfInstall.Progress.Bytes",
                        stage,
                        FormatBytes(bootProgress.IoCompletedBytes ?? 0),
                        FormatBytes(ioTotal));
                }

                return stage;
            }

            stageKey = "Dynamic.TfInstall.Stage." + progress.Stage;
            return M("Dynamic.TfInstall.Stage." + progress.Stage);
        }

        private void RenderModernTfInstallRuntimeStatus()
        {
            if (IsModernTfTabletMode)
            {
                RenderTfTabletPages();
                return;
            }

            if (!_ready || _closed || !IsModernTfInstallMode)
            {
                return;
            }

            var result = _tfInstallLastResult;
            UiMessage status;

            if (IsCompletedModernTfInstall)
            {
                status = M("Dynamic.TfInstall.Status.Completed");
                BootMaintenanceProgressBar.IsIndeterminate = false;
                BootMaintenanceProgressBar.Value = 100;
                SetText(BootMaintenanceProgressText, status);
                SetText(BootMaintenanceConfirmStatusText, status);
                return;
            }

            if (result?.CardEvidence != null
                && result.CardEvidence.FullyVerified
                && result.BootResult != null
                && result.BootResult.WriteState == InternalInstallWriteState.AllVerified
                && result.BootResult.ResetAccepted != true)
            {
                status = M("Dynamic.TfInstall.Status.VerifiedRestartUnconfirmed");
            }
            else if (_tfInstallOperationActive)
            {
                var progress = _tfInstallLastProgress;
                if (progress != null)
                {
                    var message = BuildModernTfInstallProgressMessage(progress, out _);

                    double? percent = null;
                    var cardProgress = progress.Card;
                    if (cardProgress?.TotalBytes is long cardTotal && cardTotal > 0)
                    {
                        percent = Math.Clamp(100.0 * (cardProgress.BytesCompleted ?? 0) / cardTotal, 0, 100);
                    }
                    else
                    {
                        var bootProgress = progress.Boot;
                        if (bootProgress != null && bootProgress.IoTotalBytes is long ioTotal && ioTotal > 0)
                        {
                            percent = Math.Clamp(100.0 * (bootProgress.IoCompletedBytes ?? 0) / ioTotal, 0, 100);
                        }
                    }

                    if (percent.HasValue)
                    {
                        BootMaintenanceProgressBar.IsIndeterminate = false;
                        BootMaintenanceProgressBar.Value = percent.Value;
                    }
                    else
                    {
                        // Active with no known total: indeterminate only while active, never a fake global 100.
                        BootMaintenanceProgressBar.IsIndeterminate = true;
                    }

                    SetText(BootMaintenanceProgressText, message);
                    SetText(BootMaintenanceConfirmStatusText, message);
                    return;
                }

                status = M("Dynamic.TfInstall.Status.Wait");
            }
            else if (_tfInstallExitStatus != null)
            {
                status = _tfInstallExitStatus;
            }
            else if (_tfInstallExecuteAttempted)
            {
                status = M("Dynamic.TfInstall.Status.PrewriteFailed");
            }
            else if (_tfInstallError != null)
            {
                status = _tfInstallError;
            }
            else if (_tfInstallWorkflow != null)
            {
                status = M("Dynamic.TfInstall.Status.Prepared");
            }
            else
            {
                return;
            }

            SetText(BootMaintenanceProgressText, status);
            SetText(BootMaintenanceConfirmStatusText, status);
        }

        private async Task<bool> ConfirmLeaveModernTfInstallAsync(bool ask = true)
        {
            if (_busy || _tfInstallOperationActive)
            {
                return false;
            }

            if (IsModernTfTabletMode)
            {
                if (!await ConfirmLeaveTfTabletAsync(ask))
                {
                    return false;
                }

                if (IsTfTabletReturnVerified)
                {
                    await InvalidateModernTfInstallPreparationAsync(clearPackage: true);
                    DisposeInternalInstallResources();
                    return true;
                }
            }

            if (IsCompletedModernTfInstall)
            {
                await InvalidateModernTfInstallPreparationAsync(clearPackage: true);
                DisposeInternalInstallResources();
                return true;
            }

            if (HasUnresolvedModernTfInstallState)
            {
                SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Status.UnresolvedFailure"));
                RenderModernTfInstallRuntimeStatus();
                return false;
            }

            if (_tfInstallResetAttempted && _tfInstallResetAcked)
            {
                await InvalidateModernTfInstallPreparationAsync(clearPackage: true);
                DisposeInternalInstallResources();
                return true;
            }

            if (!HasInternalInstallLiveEdlState)
            {
                await InvalidateModernTfInstallPreparationAsync(clearPackage: true);
                return true;
            }

            var client = _internalInstallEdlClient;
            var entry = _internalInstallEdlEntry;
            if (client == null || entry == null)
            {
                SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.EntryUnknown"));
                return false;
            }

            if (ask)
            {
                var choice = MessageBox.Show(
                    this,
                    T("Dynamic.TfInstall.Exit.ConfirmBody"),
                    T("Dynamic.TfInstall.Exit.ConfirmTitle"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);

                if (choice != MessageBoxResult.Yes)
                {
                    return false;
                }

                if (!ReferenceEquals(_internalInstallEdlClient, client)
                    || !ReferenceEquals(_internalInstallEdlEntry, entry))
                {
                    return false;
                }
            }

            _tfInstallOperationActive = true;
            _busy = true;
            RefreshActions();

            bool acked = false;
            try
            {
                try
                {
                    await client.ProbeAsync(0, !client.HasInitialSaharaProof, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
                    SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.ProbeFailed"));
                    RenderModernTfInstallRuntimeStatus();
                    return false;
                }

                if (_closed
                    || !ReferenceEquals(_internalInstallEdlClient, client)
                    || !ReferenceEquals(_internalInstallEdlEntry, entry)
                    || !IsModernTfInstallMode)
                {
                    return false;
                }

                if (!_tfInstallResetAttempted)
                {
                    _tfInstallResetAttempted = true;
                    SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.Resetting"));
                    RenderModernTfInstallRuntimeStatus();

                    try
                    {
                        var reset = await client.ResetAsync(CancellationToken.None);
                        if (reset.CommandAccepted)
                        {
                            _tfInstallResetAcked = true;
                            SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.ResetAccepted"));
                        }
                        else
                        {
                            SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.ResetUnknown"));
                        }
                    }
                    catch (Exception)
                    {
                        // Attempt retained as unknown; no automatic retry, all protection state preserved.
                        SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Exit.ResetUnknown"));
                    }

                    RenderModernTfInstallRuntimeStatus();
                }

                acked = _tfInstallResetAcked;
            }
            finally
            {
                _tfInstallOperationActive = false;
                _busy = false;
                if (!_closed)
                {
                    RefreshActions();
                }
            }

            if (acked)
            {
                await InvalidateModernTfInstallPreparationAsync(clearPackage: true);
                DisposeInternalInstallResources();
            }

            return acked;
        }

        private async Task HandleModernTfInstallClosingAsync()
        {
            if (IsModernTfTabletMode)
            {
                await HandleTfTabletClosingAsync();
                return;
            }

            if (_tfInstallClosePromptActive || _busy || _tfInstallOperationActive)
            {
                SetModernTfInstallExitStatus(M("Dynamic.TfInstall.Status.Wait"));
                RenderModernTfInstallRuntimeStatus();
                return;
            }

            var client = _internalInstallEdlClient;
            var needsUnconfirmedWarning =
                HasUnresolvedModernTfInstallState
                || (HasInternalInstallLiveEdlState && client == null);

            if (needsUnconfirmedWarning)
            {
                var workflow = _tfInstallWorkflow;
                var evidencePath =
                    workflow?.Prepared?.EvidenceDirectory
                    ?? _tfInstallLastResult?.EvidenceDirectory
                    ?? UnknownValue;

                _tfInstallClosePromptActive = true;
                try
                {
                    var choice = MessageBox.Show(
                        this,
                        T("Dynamic.TfInstall.Exit.CloseUnconfirmedBody", evidencePath),
                        T("Dynamic.TfInstall.Exit.CloseUnconfirmedTitle"),
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning,
                        MessageBoxResult.No);

                    if (choice == MessageBoxResult.Yes)
                    {
                        _tfInstallCloseApproved = true;
                        Close();
                    }
                }
                finally
                {
                    _tfInstallClosePromptActive = false;
                }

                return;
            }

            _tfInstallClosePromptActive = true;
            try
            {
                if (await ConfirmLeaveModernTfInstallAsync())
                {
                    await SafeResetModernTfInstallStateAsync();
                    _tfInstallCloseApproved = true;
                    Close();
                }
            }
            finally
            {
                _tfInstallClosePromptActive = false;
            }
        }
    }
}
