using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// Android -> 全新备份 -> 9008 的引导维护控制器：更新前准备 / 更新后修复 / 恢复原厂引导。
/// 所有设备写入只通过 <see cref="BootMaintenanceBackend"/> 的真实工厂与 ExecuteAsync 发生；
/// 本控制器绝不做手动分区写入、手动复位或 ADB 验收，也绝不虚构任何结果。
/// </summary>
public partial class MainWindow
{
    // 运行时现场：最后一次真实结果、错误与进度；Refresh 重绘时据此恢复，而不是清空。
    private BootMaintenanceResult? _bootMaintenanceLastResult;
    private string? _bootMaintenanceLastError;
    private UiMessage? _bootMaintenanceLastPreparationMessage;
    private InternalInstallProgress? _bootMaintenanceLastProgress;
    private bool _bootMaintenanceProgressTerminal;

    // 已导入并归本窗口所有的修复包；只有无写入现场时才允许释放，绝不释放用户的原始路径。
    private ImportedPackage? _bootMaintenanceRepairPackage;

    // 每个确认号只弹一次完成提示；复位与窗口关闭的显式批准状态。
    private string? _bootMaintenanceCompletedConfirmationId;
    private bool _bootMaintenanceResetAttempted;
    private bool _bootMaintenanceResetAcked;
    private bool _bootMaintenanceCloseApproved;
    private bool _bootMaintenanceExitPromptActive;

    // 进度日志只在阶段 / 槽位 / IO 阶段边界追加，不逐字节刷屏。
    private string? _bootMaintenanceLoggedStage;
    private string? _bootMaintenanceLoggedSlot;
    private string? _bootMaintenanceLoggedIoPhase;

    /// <summary>已发起真实写入但结果不是真实 Completed：功能切换与关闭一律拒绝，现场保留。</summary>
    private bool HasUnconfirmedBootMaintenanceWrite
    {
        get
        {
            InternalInstallWriteState? writeState;
            BootMaintenanceOutcome? outcome;
            if (_bootMaintenanceBackend?.Snapshot is { } snapshot)
            {
                writeState = snapshot.WriteState;
                outcome = snapshot.Outcome;
            }
            else if (_bootMaintenanceLastResult is { } last)
            {
                writeState = last.WriteState;
                outcome = last.Outcome;
            }
            else
            {
                return false;
            }

            return writeState != InternalInstallWriteState.NoneIssued
                && outcome != BootMaintenanceOutcome.Completed;
        }
    }

    /// <summary>复位已尝试但从未收到确认：界面任何清空都不能把这种状态抹掉。</summary>
    private bool HasUnknownBootMaintenanceReset =>
        _bootMaintenanceResetAttempted && !_bootMaintenanceResetAcked;

    // ---------- 导航 ----------

    /// <summary>
    /// 维护四步向导唯一的步骤切换入口。越界、忙碌或未满足 <see cref="CanEnterBootMaintenanceStep"/>
    /// 时直接拒绝并恢复侧栏勾选，绝不允许跳过前面的步骤。
    /// </summary>
    private void NavigateBootMaintenanceStep(int step)
    {
        if (!IsBootMaintenanceMode
            || _busy
            || _bootMaintenanceOperationActive
            || step is < 0 or > 3)
        {
            RestoreInternalInstallNav();
            return;
        }

        if (step != _internalInstallStep && !CanEnterBootMaintenanceStep(step))
        {
            RestoreInternalInstallNav();
            return;
        }

        _internalInstallStep = step;
        RenderBootMaintenancePages();
        RefreshBootMaintenanceActions();
        RefreshBootMaintenanceSharedActions();
    }

    // ---------- 准备（第 2 步 -> 第 3 步） ----------

    /// <summary>
    /// 「下一步」在来源页的真实准备入口：要求真实检查、同一 9008 客户端、全新备份与明确的
    /// 已有备份父目录；更新前 / 恢复原厂还必须已选原厂恢复来源。准备阶段只读，不写任何分区。
    /// </summary>
    private async Task PrepareBootMaintenanceConfirmationAsync()
    {
        var mode = CurrentBootMaintenanceMode;
        if (!IsBootMaintenanceMode
            || _internalInstallStep != 2
            || _busy
            || _bootMaintenanceOperationActive
            || ProtectedBootMaintenanceState
            || HasUnconfirmedBootMaintenanceWrite
            || HasUnknownBootMaintenanceReset)
        {
            return;
        }

        // 路线由真实事实决定：完整检查仍然成立走完整检查工厂；否则（默认 ADB 读取事实，
        // 或勾选 9008 的历史路线）走 FromEdl 工厂。勾选框只是用户进入偏好，不再决定工厂。
        var fromEdl = !HasCheckedInternalInstallDevice;
        var history = _bootMaintenanceHistoricalIdentity;
        var check = _internalInstallDeviceCheck;
        var client = _internalInstallEdlClient;
        var fresh = _internalInstallBackup;
        var parent = _internalInstallBackupParent;
        // 用户选择的安装包只是候选来源：After 永不因缺少它而拒绝尝试准备。
        var packagePath = _bootMaintenancePackagePath;

        if (!HasBootMaintenanceDeviceProof
            || client is null
            || fresh is null
            || (fromEdl ? history is null : !HasCheckedInternalInstallDevice)
            || string.IsNullOrWhiteSpace(parent)
            || !Directory.Exists(parent))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        // 更新前 / 恢复原厂必须已选原厂恢复来源；来源目录绝不作为当前目录传入工厂。
        if (mode != MaintenanceMode.AfterUpdate
            && string.IsNullOrWhiteSpace(_bootMaintenanceOriginalDirectory))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedExistingFolder"));
            return;
        }

        // 备份父目录（以及工具输出目录）绝不能落在已选原厂 / 项目来源目录里面。
        foreach (var source in new[] { _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                continue;
            }

            if (!IsInternalInstallBackupParentOutsideExisting(parent, source!))
            {
                SetInternalInstallBackupStatus(
                    M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        // 先作废旧准备，再标记操作进行中；准备失败时保留全新备份 / 会话 / 来源文件。
        InvalidateBootMaintenancePreparation();
        ClearBootMaintenanceRuntimeState();
        _bootMaintenanceOperationActive = true;
        RefreshBootMaintenanceActions();
        RefreshBootMaintenanceSharedActions();

        BootMaintenanceBackend? backend = null;
        try
        {
            if (_runner is null)
            {
                SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Status.PrepareFailed"));
                return;
            }

            // 所有模式都原样传递用户可选的原始备份目录：Core 自行决定是否用它做模板纪元证明；项目目录不变。
            var sources = new BootMaintenanceSources(
                OriginalBackupDirectory: _bootMaintenanceOriginalDirectory,
                BootTools: _internalInstallNativeTools,
                ProjectBackupDirectory: _bootMaintenanceProjectDirectory,
                RepairPackage: null);
            // 可变引用：AfterUpdate 在真实准备内置工具后按票面刷新 BootTools。

            // 终态一写出 acceptProgress 变 false：排队的迟到进度回调不能再覆盖新界面状态。
            var acceptProgress = true;
            var preparationProgress = new Progress<InternalInstallProgress>(progress =>
            {
                if (!acceptProgress || _closed)
                {
                    return;
                }

                OnBootMaintenancePreparationProgress(progress);
            });
            var runner = _runner;
            var preparationFailure = (Exception?)null;

            // 本地小工厂：绑定本次捕获的全部输入；只在确切的包缺失前缀下做一次导入重试。
            Task<BootMaintenanceBackend> CreateBackendAsync(
                BootMaintenanceSources chosen,
                CancellationToken token)
                => fromEdl
                    ? BootMaintenanceBackend.CreatePreparedFromEdlAsync(
                        mode,
                        history!,
                        client,
                        fresh,
                        chosen,
                        runner,
                        parent,
                        preparationProgress,
                        token)
                    : BootMaintenanceBackend.CreatePreparedAsync(
                        mode,
                        check!,
                        client,
                        fresh,
                        chosen,
                        runner,
                        parent,
                        preparationProgress,
                        token);

            await RunBusyAsync(async token =>
            {
                SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Status.Preparing"));

                try
                {
                    // 更新后修复必须准备内置裸工具（当前 Core 不接受项目引导路径之外的组合），
                    // 准备 / 恢复原厂只要求已有原厂来源，绝不假装项目引导路径已实现。
                    if (mode == MaintenanceMode.AfterUpdate)
                    {
                        await EnsureInternalInstallAssetsAsync(parent, fresh, token);
                        // 工具是刚才才真实准备好的：把捕获的来源记录刷新，保证新工具一定到达 Core。
                        sources = sources with { BootTools = _internalInstallNativeTools };
                    }

                    // 第一次调用永远不带修复包：已验证的项目模板优先，避免过早导入安装包。
                    try
                    {
                        backend = await CreateBackendAsync(sources, token);
                    }
                    catch (InvalidOperationException ex)
                    when (mode == MaintenanceMode.AfterUpdate
                        && ex.Message.StartsWith("boot-maintenance-repair-package-required:", StringComparison.Ordinal))
                    {
                        if (string.IsNullOrWhiteSpace(packagePath))
                        {
                            throw;
                        }

                        var fallback = BootMaintenanceBackend.GetRepairFallbackTarget(fresh);
                        if (fallback is not { } target)
                        {
                            // 有包却推不出目标：绝不猜测 Internal / TF 分区，按模板缺失处理。
                            throw new InvalidOperationException(
                                "boot-maintenance-project-template-required: no fallback target",
                                ex);
                        }

                        // 可见的来源页状态也要显示导入中；隐藏备份状态沿用既有调用。
                        SetText(BootMaintenancePrepareStatusText,
                            M("Dynamic.BootMaintenance.Repair.ImportingPackage"));
                        SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Repair.ImportingPackage"));
                        var imported = await PackageImporter.ImportAsync(packagePath, fresh.Model, target, parent, token);
                        // 导入结果先入字段再校验：无论后续成败，清理路径始终拥有它。
                        _bootMaintenanceRepairPackage = imported;

                        if (!imported.Validation.IsValid || imported.Validation.TestOnly)
                        {
                            foreach (var reason in imported.Validation.Reasons)
                            {
                                AppendLocalizedLog(M("Dynamic.RawValue", reason));
                            }

                            throw new InvalidOperationException(
                                "boot-maintenance-repair-package-rejected: validation failed",
                                ex);
                        }

                        // 只重试一次：包已交 Core 独立校验，绝不递归或循环重试。
                        backend = await CreateBackendAsync(
                            sources with { RepairPackage = imported },
                            token);
                    }
                }
                catch (Exception ex)
                {
                    // RunBusyAsync 会吞掉异常：在委托内部捕获真实失败并呈现到来源页。
                    preparationFailure = ex;
                    backend?.Dispose();
                    backend = null;
                    _bootMaintenanceLastError = ex.Message;
                    AppendLocalizedLog(
                        M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                    SetText(BootMaintenancePrepareStatusText,
                        M("Dynamic.BootMaintenance.Status.PrepareFailed"));
                }
                finally
                {
                    acceptProgress = false;
                }
            });

            if (preparationFailure is not null)
            {
                backend?.Dispose();
                backend = null;
                // 失败时先作废旧准备：作废会清运行时缓存，具体消息在作废之后落字段以便 Refresh 恢复。
                InvalidateBootMaintenancePreparation();
                ReleaseBootMaintenanceRepairPackage();
                var specific = MapBootMaintenancePreparationMessage(preparationFailure);
                _bootMaintenanceLastError = preparationFailure.Message;
                _bootMaintenanceLastPreparationMessage = specific;
                SetInternalInstallBackupStatus(specific);
                SetText(BootMaintenancePrepareStatusText, specific);
                return;
            }

            // 工厂真实返回后复查：同一维护模式、同一输入、窗口仍打开，才允许进入确认页。
            if (backend is null
                || !IsBootMaintenanceMode
                || CurrentBootMaintenanceMode != mode
                || _internalInstallStep != 2
                || _closed
                // 勾选框只是进入偏好，不再参与工厂路线核对；只核对真实事实引用未变。
                || (fromEdl && !ReferenceEquals(_bootMaintenanceHistoricalIdentity, history))
                || (!fromEdl && !ReferenceEquals(_internalInstallDeviceCheck, check))
                || !ReferenceEquals(_internalInstallEdlClient, client)
                || !ReferenceEquals(_internalInstallBackup, fresh)
                || !string.Equals(_internalInstallBackupParent, parent, StringComparison.Ordinal)
                || !string.Equals(_bootMaintenancePackagePath, packagePath, StringComparison.Ordinal))
            {
                backend?.Dispose();
                backend = null;
                // 操作仍只读：丢弃被覆盖输入的后端时同时释放本窗口持有的修复包，避免解包泄漏。
                ReleaseBootMaintenanceRepairPackage();
                return;
            }

            _bootMaintenanceBackend = backend;
            backend = null;
            _bootMaintenanceLastError = null;
            _bootMaintenanceLastPreparationMessage = null;
            _internalInstallStep = 3;
            RenderBootMaintenancePages();
            RefreshBootMaintenanceActions();
            RefreshBootMaintenanceSharedActions();
        }
        catch (OperationCanceledException)
        {
            backend?.Dispose();
            backend = null;
            InvalidateBootMaintenancePreparation();
            ReleaseBootMaintenanceRepairPackage();
            SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Status.PrepareFailed"));
        }
        catch (Exception ex)
        {
            backend?.Dispose();
            backend = null;
            InvalidateBootMaintenancePreparation();
            ReleaseBootMaintenanceRepairPackage();
            var specific = MapBootMaintenancePreparationMessage(ex);
            _bootMaintenanceLastError = ex.Message;
            _bootMaintenanceLastPreparationMessage = specific;
            SetInternalInstallBackupStatus(specific);
            SetText(BootMaintenancePrepareStatusText, specific);
            AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
        }
        finally
        {
            _bootMaintenanceOperationActive = false;
            RefreshBootMaintenanceActions();
            RefreshBootMaintenanceSharedActions();
        }
    }

    // ---------- 准备失败的具体文案映射 ----------

    /// <summary>
    /// 只对三个确切前缀映射到具体文案；其余失败一律回到通用「准备失败」。
    /// 真实异常原文始终保留在折叠诊断日志里，界面上绝不出现内部前缀。
    /// </summary>
    private UiMessage MapBootMaintenancePreparationMessage(Exception failure)
    {
        if (failure is InvalidOperationException ex)
        {
            if (ex.Message.StartsWith("boot-maintenance-project-template-required:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.ProjectTemplateRequired");
            }

            if (ex.Message.StartsWith("boot-maintenance-template-epoch-unproven:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.TemplateEpochUnproven");
            }

            if (ex.Message.StartsWith("boot-maintenance-repair-package-rejected:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.PackageRejected");
            }

            if (ex.Message.StartsWith("boot-maintenance-repair-package-required:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.PackageRequired");
            }
        }

        return M("Dynamic.BootMaintenance.Status.PrepareFailed");
    }

    // ---------- 已导入修复包的释放 ----------

    /// <summary>
    /// 释放本窗口拥有的已导入修复包；用户的原始 ZIP / 目录绝不归本实例所有，不做任何删除。
    /// </summary>
    private void ReleaseBootMaintenanceRepairPackage()
    {
        if (_bootMaintenanceRepairPackage is not { } imported)
        {
            return;
        }

        _bootMaintenanceRepairPackage = null;
        try
        {
            imported.Dispose();
        }
        catch (Exception ex)
        {
            // 清理失败只进诊断日志；窗口仍打开时绝不让释放异常打断界面流程。
            if (!_closed)
            {
                AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            }
        }
    }

    // ---------- 执行 ----------

    /// <summary>准备 / 修复 / 恢复三种模式的执行入口统一收敛到这里；install-tf 接缝不变。</summary>
    private async Task ExecuteBootMaintenanceAsync()
    {
        if (!IsBootMaintenanceMode)
        {
            return;
        }

        var mode = CurrentBootMaintenanceMode;
        if (_internalInstallStep != 3
            || _busy
            || _bootMaintenanceOperationActive
            || _bootMaintenanceExecuteAttempted)
        {
            return;
        }

        if (_bootMaintenanceBackend is not { } backend
            || backend.Prepared is not { } prepared
            || prepared.Mode != mode
            || BootMaintenanceRiskCheck.IsChecked != true)
        {
            return;
        }

        var confirmationId = prepared.ConfirmationId;

        // 确认框：模式 / 型号 / 序列号 / 当前槽位 / 槽位写入明细 / 真实路径；默认「否」。
        var detail = T(
            "Dynamic.BootMaintenance.Confirm.Body",
            ModeMessage(CurrentModeTag()),
            prepared.Model ?? string.Empty,
            prepared.AndroidSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty);
        detail += Environment.NewLine + T("Dynamic.BootMaintenance.Confirm.NoRepartition");
        detail += Environment.NewLine + T(
            "Dynamic.BootMaintenance.BackupLocations",
            _internalInstallBackup?.DirectoryPath ?? prepared.BackupDirectory,
            _bootMaintenanceOriginalDirectory ?? string.Empty,
            _bootMaintenanceProjectDirectory ?? string.Empty,
            prepared.EvidenceDirectory);
        foreach (var slot in prepared.Slots)
        {
            detail += Environment.NewLine + (slot.WillWrite
                ? T(
                    "Dynamic.BootMaintenance.SlotWrite",
                    slot.Slot ?? string.Empty,
                    slot.SourceSlot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind))
                : T(
                    "Dynamic.BootMaintenance.SlotKeep",
                    slot.Slot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind)));
        }

        var answer = MessageBox.Show(
            this,
            detail,
            T("Dynamic.BootMaintenance.ConfirmTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        // 弹窗之后复查：同一后端引用、同一确认号、同一模式、风险仍勾选且仍然空闲。
        if (!ReferenceEquals(_bootMaintenanceBackend, backend)
            || _bootMaintenanceBackend?.Prepared is not { } current
            || !string.Equals(current.ConfirmationId, confirmationId, StringComparison.Ordinal)
            || current.Mode != mode
            || BootMaintenanceRiskCheck.IsChecked != true
            || _busy
            || _bootMaintenanceOperationActive)
        {
            return;
        }

        // 进入真实执行：先立起「已尝试」旗标，再发起唯一一次 ExecuteAsync。
        _bootMaintenanceExecuteAttempted = true;
        _bootMaintenanceOperationActive = true;
        _bootMaintenanceProgressTerminal = false;
        RefreshBootMaintenanceActions();
        RefreshBootMaintenanceSharedActions();

        // 终态一写出 acceptProgress 变 false：排队的迟到进度回调不能再覆盖 Ready / 新操作。
        var acceptProgress = true;
        var executionProgress = new Progress<InternalInstallProgress>(progress =>
        {
            if (!acceptProgress || _closed)
            {
                return;
            }

            OnBootMaintenanceExecutionProgress(progress);
        });

        await RunBusyAsync(async token =>
        {
            try
            {
                var result = await backend.ExecuteAsync(confirmationId, executionProgress, token);
                _bootMaintenanceLastResult = result;
            }
            catch (Exception ex)
            {
                _bootMaintenanceLastError = ex.Message;
                AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            }
            finally
            {
                acceptProgress = false;
                _bootMaintenanceOperationActive = false;
                _bootMaintenanceProgressTerminal = true;
            }

            RenderBootMaintenanceRuntimeStatus();
            RefreshBootMaintenanceActions();
            RefreshBootMaintenanceSharedActions();
        });

        // 完成提示只认真实 Completed + 全部校验通过的结果；busy 结束后才弹；每个确认号只弹一次；
        // 弹过之后绝不再复位 / ADB / 任何设备调用。
        if (_bootMaintenanceLastResult is { } done
            && done.Outcome == BootMaintenanceOutcome.Completed
            && done.WriteState == InternalInstallWriteState.AllVerified
            && !string.Equals(_bootMaintenanceCompletedConfirmationId, confirmationId, StringComparison.Ordinal))
        {
            _bootMaintenanceCompletedConfirmationId = confirmationId;
            MessageBox.Show(
                this,
                T("Dynamic.BootMaintenance.Status.Completed"),
                T("Dynamic.BootMaintenance.Status.CompletedTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Information,
                MessageBoxResult.OK);
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Status.Outcome.Completed"));
        }
    }

    // ---------- 进度（只显示，不作为成功证明） ----------

    private void OnBootMaintenancePreparationProgress(InternalInstallProgress progress)
    {
        OnBootMaintenanceProgress(progress, preparation: true);
    }

    private void OnBootMaintenanceExecutionProgress(InternalInstallProgress progress)
    {
        OnBootMaintenanceProgress(progress, preparation: false);
    }

    private void OnBootMaintenanceProgress(InternalInstallProgress progress, bool preparation)
    {
        if (_bootMaintenanceProgressTerminal)
        {
            return;
        }

        _bootMaintenanceLastProgress = progress;

        var stageName = progress.Stage.ToString();
        var stageKey = "Dynamic.InternalInstall.Execution.Stage." + stageName;
        var text = M(stageKey);

        if (!string.Equals(_bootMaintenanceLoggedStage, stageName, StringComparison.Ordinal))
        {
            _bootMaintenanceLoggedStage = stageName;
            AppendLocalizedLog(M(stageKey));
        }

        if (!string.IsNullOrEmpty(progress.Slot))
        {
            text = M("Dynamic.BootMaintenance.Progress.Slot", text, progress.Slot);
            if (!string.Equals(_bootMaintenanceLoggedSlot, progress.Slot, StringComparison.Ordinal))
            {
                _bootMaintenanceLoggedSlot = progress.Slot;
                AppendLocalizedLog(text);
            }
        }

        if (progress.IoPhase is { } ioPhase)
        {
            var ioName = ioPhase.ToString() ?? string.Empty;
            text = M("Dynamic.InternalInstall.Execution.Status.IoPhase",
                text,
                M("Dynamic.InternalInstall.Execution.IoPhase." + ioName));
            if (!string.Equals(_bootMaintenanceLoggedIoPhase, ioName, StringComparison.Ordinal))
            {
                _bootMaintenanceLoggedIoPhase = ioName;
                AppendLocalizedLog(M("Dynamic.InternalInstall.Execution.IoPhase." + ioName));
            }
        }

        // 只有携带真实 nullable 总量的 IO 进度才显示近似计数；否则保持不确定状态。
        if (progress.IoTotalBytes is { } total && total > 0)
        {
            var done = progress.IoCompletedBytes ?? 0;
            text = M("Dynamic.BootMaintenance.Progress.Io", text, done, total);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = Math.Clamp(done * 100.0 / total, 0, 100);
        }
        else
        {
            BootMaintenanceProgressBar.IsIndeterminate = true;
        }

        if (preparation)
        {
            SetText(BootMaintenancePrepareStatusText, text);
        }
        else
        {
            SetText(BootMaintenanceConfirmStatusText,
                "Dynamic.InternalInstall.Execution.WriteState." + progress.WriteState);
            SetText(BootMaintenanceProgressText, text);
        }
    }

    /// <summary>
    /// 运行时现场重绘：Refresh 时恢复最后一次结果 / 错误 / 进度，而不是清空完成与失败状态。
    /// </summary>
    private void RenderBootMaintenanceRuntimeStatus()
    {
        var progress = _bootMaintenanceLastProgress;
        if (progress is { } saved && _bootMaintenanceExecuteAttempted)
        {
            // 进度文本带上真实 IO 阶段（写入 / 读回校验等），让人看到当前卡在哪一步。
            var stageText = M("Dynamic.InternalInstall.Execution.Stage." + saved.Stage);
            var text = saved.Slot is { } slot && slot.Length > 0
                ? M("Dynamic.BootMaintenance.Progress.Slot", stageText, slot)
                : stageText;
            if (saved.IoPhase is { } ioPhase)
            {
                text = M("Dynamic.InternalInstall.Execution.Status.IoPhase",
                    text,
                    M("Dynamic.InternalInstall.Execution.IoPhase." + ioPhase));
            }

            SetText(BootMaintenanceProgressText, text);
            SetText(BootMaintenanceConfirmStatusText, text);

            if (_bootMaintenanceLastResult is { } done
                && done.Outcome == BootMaintenanceOutcome.Completed
                && done.WriteState == InternalInstallWriteState.AllVerified)
            {
                BootMaintenanceProgressBar.IsIndeterminate = false;
                BootMaintenanceProgressBar.Value = 100;
            }
            else if (saved.IoTotalBytes is { } total && total > 0)
            {
                BootMaintenanceProgressBar.IsIndeterminate = false;
                BootMaintenanceProgressBar.Value =
                    Math.Clamp((saved.IoCompletedBytes ?? 0) * 100.0 / total, 0, 100);
            }
            else
            {
                BootMaintenanceProgressBar.IsIndeterminate =
                    _bootMaintenanceOperationActive && !_bootMaintenanceProgressTerminal;
            }
        }
        else
        {
            SetText(BootMaintenanceProgressText, "Dynamic.RawValue", string.Empty);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 0;
            // 来源页状态也按存储的真实结果 / 错误 / 准备状态重绘，Refresh 时不丢失败信息。
            RenderBootMaintenanceSourcesStatus();
        }

        if (_bootMaintenanceLastResult is { } result)
        {
            if (result.WriteState == InternalInstallWriteState.AllVerified
                && result.Outcome != BootMaintenanceOutcome.Completed)
            {
                SetText(BootMaintenanceConfirmStatusText,
                    "Dynamic.BootMaintenance.Status.VerifiedRestartUnconfirmed");
            }
            else
            {
                SetText(BootMaintenanceConfirmStatusText,
                    "Dynamic.BootMaintenance.Status.Outcome." + result.Outcome);
            }
        }
        else if (_bootMaintenanceLastError is not null)
        {
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Status.PrepareFailed"));
        }
        else
        {
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.RawValue", string.Empty);
        }
    }

    // ---------- 离开 / 退出 / 关闭 ----------

    /// <summary>
    /// 维护模式唯一的离开确认：活动操作直接拒绝；真实 Completed 只释放自己持有的租约并保留
    /// 全部文件；未确认写入拒绝功能切换；预写入阶段存在真实 9008 会话时，先征询（默认「否」），
    /// 确认后补齐 Sahara、只发一次复位；复位结果未知时保留尝试旗标与会话，绝不重发。
    /// </summary>
    private async Task<bool> ConfirmLeaveBootMaintenanceAsync()
    {
        if (!IsBootMaintenanceMode)
        {
            return true;
        }

        if (_busy || _bootMaintenanceOperationActive)
        {
            return false;
        }

        var backend = _bootMaintenanceBackend;

        // 未知复位（尝试过但从未收到确认）：现场与会话全部保留，绝不再发复位，直接拒绝。
        if (HasUnknownBootMaintenanceReset)
        {
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 真实 Completed + 全部校验通过：只释放自己持有的租约与资源，保留全部文件，无任何设备调用。
        if (_bootMaintenanceLastResult is { } result
            && result.Outcome == BootMaintenanceOutcome.Completed
            && result.WriteState == InternalInstallWriteState.AllVerified)
        {
            backend?.Dispose();
            _bootMaintenanceBackend = null;
            DisposeInternalInstallResources();
            return true;
        }

        // 已发起写入但结果不是真实 Completed：拒绝离开并保留现场与证据。
        if (HasUnconfirmedBootMaintenanceWrite)
        {
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 进入 9008 但客户端为空：复位结果无法确认，属于未知状态，绝不能当成功放行或释放现场。
        if (HasInternalInstallLiveEdlState && _internalInstallEdlClient is null)
        {
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 预写入且没有真实 9008 会话：安全释放后端准备，直接放行。
        if (!HasInternalInstallLiveEdlState || _internalInstallEdlClient is not { } client)
        {
            backend?.Dispose();
            _bootMaintenanceBackend = null;
            return true;
        }

        var answer = MessageBox.Show(
            this,
            T("Dynamic.BootMaintenance.Exit.ConfirmBody"),
            T("Dynamic.BootMaintenance.Exit.ConfirmTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return false;
        }

        // 先补齐 Sahara 证明；探针失败就没有任何新鲜证据，绝不发复位，也不立尝试旗标。
        try
        {
            await client.ProbeAsync(0, initialLoader: !client.HasInitialSaharaProof, CancellationToken.None);
        }
        catch (Exception ex)
        {
            AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            return false;
        }

        // 先立起尝试旗标，再只发一次复位；结果未知时旗标与会话全部保留，绝不重发。
        _bootMaintenanceResetAttempted = true;
        try
        {
            await client.ResetAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Status.Outcome.UnknownWriteOutcome"));
            return false;
        }

        // 复位确认已收到：只释放自己持有的对象并清空活跃会话字段，绝不等待 ADB。
        _bootMaintenanceResetAcked = true;
        backend?.Dispose();
        _bootMaintenanceBackend = null;
        DisposeInternalInstallResources();
        _internalInstallEdlClient = null;
        _internalInstallEdlEntry = null;
        _internalInstallEdlTools = null;
        AppendLocalizedLog(M("Dynamic.BootMaintenance.Exit.Restarting"));
        return true;
    }

    /// <summary>退出面板按钮：维护模式自己的「一次复位离开」例程，不走旧安装的 ADB 等待。</summary>
    private async Task ExitBootMaintenanceAsync()
    {
        if (HasUnconfirmedBootMaintenanceWrite || HasUnknownBootMaintenanceReset)
        {
            AppendLocalizedLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return;
        }

        if (await ConfirmLeaveBootMaintenanceAsync())
        {
            ResetBootMaintenanceUiState();
            RenderBootMaintenancePages();
            RefreshBootMaintenanceActions();
            RefreshBootMaintenanceSharedActions();
        }
    }

    /// <summary>
    /// 复位维护自己的界面状态：只在已批准离开后调用；未确认写入与未知复位一律拒绝清空。
    /// </summary>
    private void ResetBootMaintenanceUiState()
    {
        if (_bootMaintenanceOperationActive
            || HasUnconfirmedBootMaintenanceWrite
            || HasUnknownBootMaintenanceReset
            || HasInternalInstallLiveEdlState)
        {
            return;
        }

        ClearBootMaintenanceRuntimeState();
        InvalidateBootMaintenancePreparation();
        // 已通过既有无现场 / 无保护守卫后，才清算上一轮的历史身份绑定。
        _bootMaintenanceHistoricalIdentity = null;
        // 已结束 / 离开的会话不得把旧完整检查带到下一台平板：只作废 UI 与租约，无设备 I/O。
        ResetInternalInstallCheckState(clearSelection: false);
        // 上一会话的复位尝试 / 确认与关闭批准到此清算，为下一个会话回到干净起点。
        _bootMaintenanceResetAttempted = false;
        _bootMaintenanceResetAcked = false;
        _bootMaintenanceCloseApproved = false;
        _internalInstallStep = 0;
    }

    private void ClearBootMaintenanceRuntimeState()
    {
        _bootMaintenanceLastResult = null;
        _bootMaintenanceLastError = null;
        _bootMaintenanceLastPreparationMessage = null;
        _bootMaintenanceLastProgress = null;
        _bootMaintenanceCompletedConfirmationId = null;
        _bootMaintenanceLoggedStage = null;
        _bootMaintenanceLoggedSlot = null;
        _bootMaintenanceLoggedIoPhase = null;
        _bootMaintenanceProgressTerminal = false;
    }

    // ---------- 共享动作刷新 ----------

    /// <summary>维护模式下共享退出面板 / 按钮按真实状态刷新；真实 Completed 后不再提供旧复位入口。</summary>
    private void RefreshBootMaintenanceSharedActions()
    {
        if (!IsBootMaintenanceMode)
        {
            return;
        }

        // 维护模式自己的共享备份刷新；旧安装的退出渲染绝不调用。
        RefreshBootMaintenanceSharedBackupActions();

        var completed = _bootMaintenanceLastResult is { } result
            && result.Outcome == BootMaintenanceOutcome.Completed
            && result.WriteState == InternalInstallWriteState.AllVerified;

        // 只有仍存在真实 9008 现场且未真实完成时才显示退出面板；完成后隐藏。
        var showExit = HasInternalInstallLiveEdlState && !completed;
        InternalInstallExitMaintenancePanel.Visibility = showExit
            ? Visibility.Visible
            : Visibility.Collapsed;

        if (!showExit)
        {
            return;
        }

        // 按钮只在完全空闲时可用；状态文案按真实复位能力陈述，绝不承诺安卓启动。
        var idle = !_busy
            && !_bootMaintenanceOperationActive
            && !_internalInstallOperationActive;
        InternalInstallExitMaintenanceButton.IsEnabled = idle
            && !HasUnknownBootMaintenanceReset
            && !HasUnconfirmedBootMaintenanceWrite
            && _internalInstallEdlClient != null;
        InternalInstallExitMaintenanceButton.SetResourceReference(
            ContentControl.ContentProperty, "Dynamic.BootMaintenance.Exit.Button");

        if (HasUnknownBootMaintenanceReset || HasUnconfirmedBootMaintenanceWrite)
        {
            SetText(InternalInstallExitMaintenanceStatusText,
                M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
        }
        else
        {
            SetText(InternalInstallExitMaintenanceStatusText,
                M("Dynamic.BootMaintenance.Exit.Ready"));
        }
    }

    /// <summary>维护模式只允许全新备份：复用已有备份的控件整体隐藏，全新按钮按真实门槛刷新。</summary>
    private void RefreshBootMaintenanceSharedBackupActions()
    {
        if (!IsBootMaintenanceMode)
        {
            return;
        }

        var idle = !_busy && !_bootMaintenanceOperationActive;
        var protectedState = ProtectedBootMaintenanceState
            || HasUnconfirmedBootMaintenanceWrite
            || HasUnknownBootMaintenanceReset;
        // 备份前置只要求事实门槛：完整维护证明或共享安卓读取事实；不是执行就绪。
        var checkedDevice = HasBootMaintenanceBackupPrerequisite;
        var validParent = !string.IsNullOrWhiteSpace(_internalInstallBackupParent)
            && Directory.Exists(_internalInstallBackupParent);
        var canReuseSession = _internalInstallEdlClient is not null
            && _internalInstallEdlEntry is not null
            && _internalInstallEdlTools is not null;

        InternalInstallBackupBrowseButton.IsEnabled = idle && !protectedState && checkedDevice;
        InternalInstallBackupFolderBox.IsEnabled = idle && !protectedState;
        InternalInstallBackupUseExistingCheck.Visibility = Visibility.Collapsed;
        InternalInstallBackupUseExistingCheck.IsEnabled = false;
        InternalInstallBackupExistingBrowseButton.Visibility = Visibility.Collapsed;
        InternalInstallBackupExistingBrowseButton.IsEnabled = false;
        InternalInstallBackupButton.IsEnabled = idle
            && !protectedState
            && checkedDevice
            && validParent
            && (!HasInternalInstallLiveEdlState || canReuseSession);

        UpdateInternalInstallDeviceSelector();
        InternalInstallDevicesCombo.IsEnabled = idle
            && !protectedState
            && !HasInternalInstallLiveEdlState
            && !_bootMaintenanceAlreadyEdl
            && _internalInstallDeviceChoices.Count > 0;
    }
}
