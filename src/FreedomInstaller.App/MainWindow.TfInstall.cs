using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App
{
    public partial class MainWindow
    {
        private TfInstallWorkflow? _tfInstallWorkflow;
        private ImportedPackage? _tfInstallPackage;
        private string? _tfInstallPackageSource;
        private UiMessage? _tfInstallError;
        private bool _tfInstallOperationActive;
        private TfInstallResult? _tfInstallLastResult;
        private TfInstallProgress? _tfInstallLastProgress;
        private bool _tfInstallExecuteAttempted;
        private bool _tfInstallCloseApproved;
        private bool _tfInstallClosePromptActive;
        private bool _tfInstallCompletionShown;
        private bool _tfInstallResetAttempted;
        private bool _tfInstallResetAcked;

        /// <summary>浏览对话框回写路径框时抑制一次 TextChanged，避免与手输路径的作废竞争。</summary>
        private bool _suppressModernTfPackageChange;

        private bool IsModernTfInstallMode => CurrentModeTag() == "install-tf";

        private bool HasAnyPreparedModernTfInstall => _tfInstallWorkflow is not null || HasPreparedTfTabletStage;

        private bool IsCompletedModernTfInstall
        {
            get
            {
                if (IsModernTfTabletMode)
                {
                    return IsCompletedTfTabletInstall;
                }

                var result = _tfInstallLastResult;
                if (result == null)
                {
                    return false;
                }

                if (result.Outcome != TfInstallOutcome.Completed)
                {
                    return false;
                }

                if (result.CardEvidence == null || !result.CardEvidence.FullyVerified)
                {
                    return false;
                }

                var boot = result.BootResult;
                if (boot == null
                    || boot.Outcome != BootMaintenanceOutcome.Completed
                    || boot.WriteState != InternalInstallWriteState.AllVerified
                    || boot.ResetAccepted != true)
                {
                    return false;
                }

                return true;
            }
        }

        private bool HasUnresolvedModernTfInstallState
        {
            get
            {
                if (IsModernTfTabletMode)
                {
                    return ProtectedTfTabletState;
                }

                if (IsCompletedModernTfInstall)
                {
                    return false;
                }

                if (_tfInstallWorkflow?.Snapshot.ExecutionStarted == true)
                {
                    return true;
                }

                if (_tfInstallLastResult?.Outcome == TfInstallOutcome.UnknownWriteOutcome)
                {
                    return true;
                }

                if (_tfInstallResetAttempted && !_tfInstallResetAcked)
                {
                    return true;
                }

                return false;
            }
        }

        private bool ProtectedModernTfInstallState =>
            _tfInstallOperationActive || HasUnresolvedModernTfInstallState;

        private bool CanEnterModernTfInstallStep(int step)
        {
            if (_busy || _tfInstallOperationActive)
            {
                return false;
            }

            if (!IsModernTfInstallMode)
            {
                return false;
            }

            if (step < 0 || step > 3)
            {
                return false;
            }

            if (IsCompletedModernTfInstall || HasUnresolvedModernTfInstallState)
            {
                return step == _internalInstallStep;
            }

            switch (step)
            {
                case 0:
                    return true;
                case 1:
                    return HasBootMaintenanceBackupPrerequisite;
                case 2:
                    return _internalInstallBackup != null && HasBootMaintenanceDeviceProof;
                case 3:
                    return IsModernTfTabletMode
                        ? HasPreparedTfTabletStage
                        : _tfInstallWorkflow != null && !_tfInstallExecuteAttempted;
                default:
                    return false;
            }
        }

        private async Task<bool> InvalidateModernTfInstallPreparationAsync(bool clearPackage = false)
        {
            if (HasUnresolvedModernTfInstallState)
            {
                return false;
            }

            if (!await DisposeTfTabletPrewriteAsync())
            {
                return false;
            }

            var workflow = _tfInstallWorkflow;
            if (workflow != null)
            {
                await workflow.DisposeAsync();
                _tfInstallWorkflow = null;
            }

            _tfInstallLastResult = null;
            _tfInstallLastProgress = null;
            _tfInstallExecuteAttempted = false;
            _tfInstallError = null;
            _tfInstallCompletionShown = false;
            _tfInstallExitStatus = null;
            BootMaintenanceRiskCheck.IsChecked = false;

            if (clearPackage)
            {
                _tfInstallPackage?.Dispose();
                _tfInstallPackage = null;
                _tfInstallPackageSource = null;
                _package = null;
                _tfPlan = null;
            }

            return true;
        }

        private async Task SafeResetModernTfInstallStateAsync()
        {
            if (ProtectedModernTfInstallState || HasInternalInstallLiveEdlState)
            {
                return;
            }

            if (!await InvalidateModernTfInstallPreparationAsync(clearPackage: true))
            {
                return;
            }

            ClearResolvedTfTabletUiState();

            _tfInstallResetAttempted = false;
            _tfInstallResetAcked = false;
            _tfInstallCloseApproved = false;
            _tfInstallClosePromptActive = false;
            _internalInstallStep = 0;

            ResetInternalInstallCheckState(false);
        }

        private async Task NavigateModernTfInstallStepAsync(int step)
        {
            if (_busy || _tfInstallOperationActive)
            {
                return;
            }

            if (!IsModernTfInstallMode || !CanEnterModernTfInstallStep(step))
            {
                return;
            }

            bool leavesPreparedStep = step < 3
                && (_internalInstallStep == 3 || _tfInstallWorkflow != null);
            if (!leavesPreparedStep)
            {
                _internalInstallStep = step;
                RefreshModernTfInstallActions();
                RenderModernTfInstallPages();
                return;
            }

            _tfInstallOperationActive = true;
            bool invalidated = false;
            try
            {
                await RunBusyAsync(async _ =>
                {
                    invalidated = await InvalidateModernTfInstallPreparationAsync(false);
                });
            }
            finally
            {
                _tfInstallOperationActive = false;
                if (invalidated && CanEnterModernTfInstallStep(step))
                {
                    _internalInstallStep = step;
                }

                if (!_closed)
                {
                    RefreshModernTfInstallActions();
                    RenderModernTfInstallPages();
                }
            }
        }

        private async Task ImportModernTfInstallPackageAsync(CancellationToken token)
        {
            if (!IsModernTfInstallMode || HasUnresolvedModernTfInstallState)
            {
                return;
            }

            var parent = _internalInstallBackupParent;
            var fresh = _internalInstallBackup;
            if (fresh == null
                || !HasBootMaintenanceDeviceProof
                || string.IsNullOrWhiteSpace(parent)
                || !Directory.Exists(parent))
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            string source = PackagePathBox.Text?.Trim() ?? string.Empty;
            if (source.Length == 0 || (!Directory.Exists(source) && !File.Exists(source)))
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            string model = fresh.Model;
            if (string.IsNullOrWhiteSpace(model))
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            if (_tfInstallPackage != null
                && string.Equals(_tfInstallPackageSource, source, StringComparison.Ordinal))
            {
                var cached = _tfInstallPackage.Validation;
                if (cached != null
                    && cached.IsValid
                    && !cached.TestOnly
                    && string.Equals(_tfInstallPackage.DeviceModel, model, StringComparison.Ordinal))
                {
                    return;
                }
            }

            if (_tfInstallWorkflow != null)
            {
                if (!await InvalidateModernTfInstallPreparationAsync(false))
                {
                    return;
                }
            }

            if (HasUnresolvedModernTfInstallState)
            {
                return;
            }

            _tfInstallPackage?.Dispose();
            _tfInstallPackage = null;
            _tfInstallPackageSource = null;

            SetTfStatus(M("Dynamic.TfInstall.PackageImporting"));

            string workRoot = Directory.CreateDirectory(
                Path.Combine(parent, ".armada-installer-tf-package")).FullName;

            ImportedPackage? imported = null;
            try
            {
                imported = await PackageImporter.ImportAsync(source, model, InstallationTarget.TfCard, workRoot, token);

                _tfInstallPackage = imported;
                _tfInstallPackageSource = source;
                _package = imported.Validation;

                var validation = imported.Validation;
                bool usable = validation != null
                    && validation.IsValid
                    && !validation.TestOnly
                    && string.Equals(imported.DeviceModel, model, StringComparison.Ordinal);
                if (!usable)
                {
                    SetTfStatus(M("Dynamic.TfInstall.PackageRejected"));
                    if (validation?.Reasons != null)
                    {
                        foreach (var reason in validation.Reasons)
                        {
                            AppendLocalizedLog(M("Dynamic.RawValue", reason));
                        }
                    }

                    return;
                }
            }
            catch (OperationCanceledException)
            {
                SetTfStatus(M("Dynamic.TfInstall.Cancelled"));
                DiscardModernTfInstallImport(imported);
                throw;
            }
            catch (Exception ex)
            {
                SetTfStatus(M("Dynamic.TfInstall.PackageRejected"));
                AppendLocalizedLog(M("Dynamic.RawValue", (ex.GetType().FullName ?? ex.GetType().Name) + ": " + ex.Message));
                DiscardModernTfInstallImport(imported);
            }
        }

        private void DiscardModernTfInstallImport(ImportedPackage? imported)
        {
            imported?.Dispose();
            if (imported != null && ReferenceEquals(_tfInstallPackage, imported))
            {
                _tfInstallPackage = null;
                _tfInstallPackageSource = null;
                _package = null;
            }
        }

        private async Task PrepareModernTfInstallConfirmationAsync()
        {
            if (IsModernTfTabletMode)
            {
                // 自 0.7.2 起禁用新的平板 TF 临时启动准备；已有恢复路径保持不变。
                return;
            }

            if (_busy || _tfInstallOperationActive || !IsModernTfInstallMode || _internalInstallStep != 2)
            {
                return;
            }

            if (HasUnresolvedModernTfInstallState)
            {
                return;
            }

            var client = _internalInstallEdlClient;
            var entry = _internalInstallEdlEntry;
            var fresh = _internalInstallBackup;
            var parent = _internalInstallBackupParent;
            if (client == null
                || entry == null
                || fresh == null
                || !HasBootMaintenanceDeviceProof
                || string.IsNullOrWhiteSpace(parent)
                || !Directory.Exists(parent))
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            if (_tfSource != TfCardSource.Reader)
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedTabletMaintenance"));
                return;
            }

            if (!IsActualWindowsAdmin())
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedAdmin"));
                return;
            }

            var selected = _tfCard;
            if (selected == null)
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            TfCardCandidate? card = null;
            if (_tfCards != null)
            {
                foreach (var candidate in _tfCards)
                {
                    if (ReferenceEquals(candidate, selected))
                    {
                        card = candidate;
                        break;
                    }
                }
            }

            if (card == null)
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            var confirm = MessageBox.Show(
                this,
                T("Dynamic.TfInstall.LockCardConfirmBody", card.Path, FormatBytes(card.SizeBytes)),
                T("Dynamic.TfInstall.LockCardConfirmTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }

            if (_busy
                || _tfInstallOperationActive
                || !IsModernTfInstallMode
                || _internalInstallStep != 2
                || HasUnresolvedModernTfInstallState
                || !ReferenceEquals(_tfCard, card)
                || !ReferenceEquals(_internalInstallBackup, fresh)
                || !ReferenceEquals(_internalInstallEdlClient, client)
                || !ReferenceEquals(_internalInstallEdlEntry, entry))
            {
                return;
            }

            _tfInstallOperationActive = true;
            TfInstallWorkflow? preparedWorkflow = null;
            bool committed = false;
            try
            {
                await RunBusyAsync(async token =>
                {
                    SetTfStatus(M("Dynamic.TfInstall.Preparing"));

                    if (!await InvalidateModernTfInstallPreparationAsync(false))
                    {
                        return;
                    }

                    await ImportModernTfInstallPackageAsync(token);

                    var validation = _tfInstallPackage?.Validation;
                    if (_tfInstallPackage == null
                        || validation == null
                        || !validation.IsValid
                        || validation.TestOnly
                        || !string.Equals(_tfInstallPackage.DeviceModel, fresh.Model, StringComparison.Ordinal)
                        || !string.Equals(_tfInstallPackageSource, PackagePathBox.Text?.Trim(), StringComparison.Ordinal))
                    {
                        SetTfStatus(M("Dynamic.TfInstall.PackageRejected"));
                        return;
                    }

                    var package = _tfInstallPackage;
                    var backup = _internalInstallBackup;
                    if (backup == null)
                    {
                        SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                        return;
                    }

                    await EnsureInternalInstallAssetsAsync(parent, fresh, token);
                    var tools = _internalInstallNativeTools;
                    if (tools == null)
                    {
                        SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                        return;
                    }

                    var protectedPaths = new List<string>
                    {
                        parent,
                        fresh.DirectoryPath,
                        package.SourcePath,
                        package.PackageDirectory,
                        Environment.ProcessPath ?? AppContext.BaseDirectory,
                    };
                    var request = new TfInstallRequest(card, protectedPaths, parent);

                    if (HasCheckedInternalInstallDevice)
                    {
                        preparedWorkflow = await TfInstallWorkflow.PrepareReaderAsync(
                            request, _internalInstallDeviceCheck!, client, backup, package, tools, _runner, token);
                    }
                    else
                    {
                        var history = _bootMaintenanceHistoricalIdentity;
                        if (history == null)
                        {
                            SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                            return;
                        }

                        preparedWorkflow = await TfInstallWorkflow.PrepareReaderFromEdlAsync(
                            request, history, client, backup, package, tools, _runner, token);
                    }

                    if (!IsModernTfInstallMode
                        || _internalInstallStep != 2
                        || !ReferenceEquals(_tfCard, card)
                        || !ReferenceEquals(_internalInstallBackup, fresh)
                        || !ReferenceEquals(_internalInstallEdlClient, client)
                        || !ReferenceEquals(_internalInstallEdlEntry, entry)
                        || !ReferenceEquals(_tfInstallPackage, package))
                    {
                        await preparedWorkflow.DisposeAsync();
                        preparedWorkflow = null;
                        return;
                    }

                    _tfInstallWorkflow = preparedWorkflow;
                    committed = true;
                    BootMaintenanceRiskCheck.IsChecked = false;
                    _internalInstallStep = 3;
                });
            }
            catch (OperationCanceledException)
            {
                _tfInstallError = M("Dynamic.TfInstall.Cancelled");
                SetTfStatus(_tfInstallError);
            }
            catch (Exception ex)
            {
                _tfInstallError = M("Dynamic.TfInstall.PrepareFailed");
                SetTfStatus(_tfInstallError);
                AppendLocalizedLog(M("Dynamic.RawValue", (ex.GetType().FullName ?? ex.GetType().Name) + ": " + ex.Message));
            }
            finally
            {
                if (!committed && preparedWorkflow != null)
                {
                    await preparedWorkflow.DisposeAsync();
                }

                _tfInstallOperationActive = false;
                if (!_closed)
                {
                    RefreshModernTfInstallActions();
                    RenderModernTfInstallPages();
                    RefreshActions();
                }
            }
        }

        /// <summary>
        /// 现代 TF 输入（来源 / 目标卡 / 手输路径）共用的作废入口：空闲且未受保护时，
        /// 在自己的活动旗标下作废未写入的准备（可选连同安装包），然后按真实结果刷新。
        /// 绝不在这里丢弃任何真实的 9008 现场。
        /// </summary>
        private async Task<bool> BeginModernTfInputChangeAsync(bool clearPackage)
        {
            if (!_ready || _busy || ProtectedModernTfInstallState)
            {
                return false;
            }

            _tfInstallOperationActive = true;
            bool success = false;
            try
            {
                await RunBusyAsync(async _ =>
                {
                    success = await InvalidateModernTfInstallPreparationAsync(clearPackage);
                });
            }
            finally
            {
                _tfInstallOperationActive = false;
                if (!_closed)
                {
                    RefreshModernTfInstallActions();
                    RenderModernTfInstallPages();
                }
            }

            return success;
        }

        /// <summary>
        /// 「校验安装包」（TF 卡安装）：守卫通过后在忙碌中执行真实导入；
        /// 校验有效且型号与本机备份一致时登记成功消息并刷新容量预览，失败照实写 _tfInstallError。
        /// </summary>
        private async Task ValidateModernTfInstallPackageAsync()
        {
            if (!_ready
                || _busy
                || _tfInstallOperationActive
                || !IsModernTfInstallMode
                || HasUnresolvedModernTfInstallState)
            {
                return;
            }

            var fresh = _internalInstallBackup;
            var parent = _internalInstallBackupParent;
            if (fresh == null
                || !HasBootMaintenanceDeviceProof
                || string.IsNullOrWhiteSpace(parent)
                || !Directory.Exists(parent))
            {
                SetTfStatus(M("Dynamic.TfInstall.NeedInputs"));
                return;
            }

            _tfInstallOperationActive = true;
            try
            {
                await RunBusyAsync(async token =>
                {
                    await ImportModernTfInstallPackageAsync(token);

                    var validation = _tfInstallPackage?.Validation;
                    if (_tfInstallPackage != null
                        && validation is { IsValid: true, TestOnly: false }
                        && string.Equals(_tfInstallPackage.DeviceModel, fresh.Model, StringComparison.Ordinal))
                    {
                        SetText(PackageStatusText, M("Dynamic.TfInstall.PackageValidated"));
                        _tfInstallError = null;
                        SetTfStatus(M("Dynamic.TfInstall.PackageValidated"));
                        UpdateTfCapacity();
                        return;
                    }

                    _tfInstallError = M("Dynamic.TfInstall.PackageRejected");
                    SetTfStatus(_tfInstallError);
                });
            }
            finally
            {
                _tfInstallOperationActive = false;
                if (!_closed)
                {
                    RefreshModernTfInstallActions();
                    RenderModernTfInstallPages();
                }
            }
        }

        /// <summary>
        /// 「浏览…」（TF 卡安装）：沿用旧版浏览按钮的对话框 Title / Filter；选中后作废输入、
        /// 在抑制标志下回写路径框，再走真实校验。绝不越过新鲜备份 / 设备证明先导入。
        /// </summary>
        private async Task BrowseModernTfInstallPackageAsync()
        {
            if (_busy || _tfInstallOperationActive || ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
            {
                return;
            }

            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = T("Dynamic.Dialog.SelectPackageFile"),
                Filter = T("Dynamic.Dialog.PackageFileFilter"),
                CheckFileExists = true,
                Multiselect = false,
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            if (!await BeginModernTfInputChangeAsync(clearPackage: true))
            {
                return;
            }

            _suppressModernTfPackageChange = true;
            try
            {
                PackagePathBox.Text = dialog.FileName;
            }
            finally
            {
                _suppressModernTfPackageChange = false;
            }

            await ValidateModernTfInstallPackageAsync();
        }
    }
}
