using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;
using Microsoft.Win32;

namespace FreedomInstaller.App;

// 引导维护视图层（View）：只负责界面状态、可用性和渲染。
// 后端实例只会由后续控制器票据通过真实工厂赋值；本文件不创建任何合成后端、检查或凭据。
public partial class MainWindow
{
    private BootMaintenanceBackend? _bootMaintenanceBackend;
    private bool _bootMaintenanceExecuteAttempted;
    private bool _bootMaintenanceOperationActive;
    private bool _bootMaintenanceAlreadyEdl;
    private string? _bootMaintenanceOriginalDirectory;
    private string? _bootMaintenanceProjectDirectory;
    private string? _bootMaintenancePackagePath;

    private bool IsBootMaintenanceMode =>
        CurrentModeTag() is "prepare" or "repair" or "restore";

    private bool UsesSharedDevicePreparationPages =>
        IsInternalInstallMode || IsBootMaintenanceMode || IsModernUserdataUninstallMode || IsModernTfInstallMode;

    private MaintenanceMode CurrentBootMaintenanceMode
    {
        get
        {
            return CurrentModeTag() switch
            {
                "prepare" => MaintenanceMode.BeforeUpdate,
                "repair" => MaintenanceMode.AfterUpdate,
                "restore" => MaintenanceMode.RestoreStock,
                _ => throw new InvalidOperationException(
                    $"Unknown boot maintenance mode '{CurrentModeTag()}'; no default fallback."),
            };
        }
    }

    // 持久保护状态：正在执行，或后端已有未确认写入 / 未知复位。_busy 只参与控件可用性，不计入保护。
    private bool ProtectedBootMaintenanceState =>
        _bootMaintenanceOperationActive
        || HasUnconfirmedBootMaintenanceWrite
        || HasUnknownBootMaintenanceReset;

    private bool CanEnterBootMaintenanceStep(int step)
    {
        if (!_ready
            || !IsBootMaintenanceMode
            || _busy
            || _bootMaintenanceOperationActive)
        {
            return false;
        }

        if (ProtectedBootMaintenanceState)
        {
            return step == 3;
        }

        switch (step)
        {
            case 0:
                return true;
            case 1:
            {
                // 进入备份页只要求事实门槛：完整证明或共享安卓读取事实；准备 / 执行仍走完整证明。
                return HasBootMaintenanceBackupPrerequisite;
            }
            case 2:
            {
                if (_internalInstallBackup is null || !HasBootMaintenanceDeviceProof)
                {
                    return false;
                }

                return true;
            }
            case 3:
                return _bootMaintenanceBackend is { } backend
                    && backend.Prepared is { } prepared
                    && prepared.Mode == CurrentBootMaintenanceMode
                    && !_bootMaintenanceExecuteAttempted;
            default:
                return false;
        }
    }

    // 共享四步导航的第三/四步文字：内部安装沿用现有静态资源，引导维护使用新的动态键。
    // 只设置这两个具名 TextBlock 的资源引用，不改动任何静态资源本身的值。
    private void RenderSharedWorkflowNavigationLabels()
    {
        if (!UsesSharedDevicePreparationPages)
        {
            return;
        }

        RenderSharedDeviceEntryLead();

        if (IsBootMaintenanceMode)
        {
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.Nav.Sources");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.Nav.Confirm");
        }
        else if (IsModernTfInstallMode)
        {
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Inputs");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Confirm");
        }
        else if (IsModernUserdataUninstallMode)
        {
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.UserdataUninstall.Nav.Sources");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.UserdataUninstall.Nav.Confirm");
        }
        else
        {
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Static.InternalInstall.Nav.Capacity");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Static.InternalInstall.Nav.Confirm");
        }
    }

    private void RenderBootMaintenancePages()
    {
        if (!IsBootMaintenanceMode)
        {
            return;
        }

        RestoreInternalInstallNav();

        BootMaintenanceEntryPanel.Visibility = _internalInstallStep == 0
            ? Visibility.Visible
            : Visibility.Collapsed;

        InternalInstallCheckPage.Visibility = _internalInstallStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallBackupPage.Visibility = _internalInstallStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallCapacityPage.Visibility = Visibility.Collapsed;
        InternalInstallConfirmPage.Visibility = Visibility.Collapsed;

        BootMaintenanceSourcesPage.Visibility = _internalInstallStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        BootMaintenanceConfirmPage.Visibility = _internalInstallStep == 3 ? Visibility.Visible : Visibility.Collapsed;

        // 历史备份的“沿用现有备份”控件对维护模式不适用，避免与固定的原厂/项目来源混淆。
        InternalInstallBackupUseExistingCheck.Visibility = Visibility.Collapsed;
        InternalInstallBackupExistingRow.Visibility = Visibility.Collapsed;

        // 卸载模式可能改写过这三处具名文本与确认标题：维护模式每次渲染都恢复成维护自己的键。
        SharedEdlEntryHintText.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.EdlHint");
        SharedEdlOriginalEntryLabel.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.OriginalSource");
        SharedEdlOriginalSourceLabel.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.OriginalSource");
        BootMaintenanceConfirmTitle.SetResourceReference(TextBlock.TextProperty, "Dynamic.BootMaintenance.ConfirmTitle");

        // 原始目录在入口页与来源页呈现同一真实值。
        BootMaintenanceEntryOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;
        BootMaintenanceOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;
        BootMaintenanceProjectBox.Text = _bootMaintenanceProjectDirectory ?? string.Empty;

        // 来源页按模式呈现：只有修复模式需要项目备份与安装包。
        BootMaintenanceRepairSourcesRow.Visibility = CurrentBootMaintenanceMode == MaintenanceMode.AfterUpdate
            ? Visibility.Visible
            : Visibility.Collapsed;

        SetText(BootMaintenanceSourcesTitle, "Dynamic.BootMaintenance.SourceTitle");
        SetText(BootMaintenanceSourcesLead, "Dynamic.BootMaintenance.SourceLead");

        RenderBootMaintenanceCheckButton();
        RenderBootMaintenanceSourcesStatus();
        RenderBootMaintenanceConfirmPage();

        RefreshBootMaintenanceActions();
    }

    private void RenderBootMaintenanceCheckButton()
    {
        // 9008 路线使用专门的识别文案；非内部模式默认检查是只读安卓读取，使用新默认文案；
        // 完整 Fastboot 核验仍在高级折叠区，不在这里伪造任何检查结果。
        if (_bootMaintenanceAlreadyEdl)
        {
            InternalInstallCheckButton.SetResourceReference(ContentControl.ContentProperty, "Dynamic.BootMaintenance.CheckEdl");
        }
        else if (IsSharedNonInternalDeviceMode)
        {
            InternalInstallCheckButton.SetResourceReference(ContentControl.ContentProperty, "Dynamic.Shared.CheckTablet");
        }
        else
        {
            InternalInstallCheckButton.SetResourceReference(ContentControl.ContentProperty, "Static.InternalInstall.Check.Button");
        }

        RenderSharedDeviceEntryLead();
        RefreshSharedAdvancedCheckAvailability();
    }

    private void RenderBootMaintenanceSourcesStatus()
    {
        var backend = _bootMaintenanceBackend;
        var prepared = backend?.Prepared;
        if (prepared is null)
        {
            // 真实失败必须保留在来源页上：绝不用「未准备」覆盖已存的真实错误。
            if (_bootMaintenanceLastError is not null)
            {
                SetText(BootMaintenancePrepareStatusText,
                    _bootMaintenanceLastPreparationMessage
                    ?? M("Dynamic.BootMaintenance.Status.PrepareFailed"));
                return;
            }

            if (_bootMaintenanceOperationActive)
            {
                SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.Status.Preparing"));
                return;
            }

            SetText(BootMaintenancePrepareStatusText, "Dynamic.BootMaintenance.NotPrepared");
            return;
        }

        SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.PreparedSummary",
            prepared.Model ?? string.Empty,
            prepared.AndroidSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty));
    }

    private void RenderBootMaintenanceConfirmPage()
    {
        var backend = _bootMaintenanceBackend;
        var prepared = backend?.Prepared;

        BootMaintenanceSlotsPanel.Children.Clear();
        BootMaintenanceRegionsHost.Children.Clear();

        if (prepared is null)
        {
            SetText(BootMaintenanceDeviceText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceBackupLocationsText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceRiskText, BootMaintenanceRiskKey(CurrentBootMaintenanceMode));
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.BootMaintenance.NotPrepared");
            SetText(BootMaintenanceProgressText, "Dynamic.RawValue", string.Empty);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 0;
            return;
        }

        // 设备摘要：只陈述真实准备的型号/序列号/当前槽位，不断言系统可启动性或 A/B 双槽完整。
        SetText(BootMaintenanceDeviceText, M("Dynamic.BootMaintenance.DeviceSummary",
            prepared.Model ?? string.Empty,
            prepared.AndroidSerial ?? string.Empty,
            prepared.SocSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty));

        // 备份位置摘要：本次回滚备份 / 原厂来源 / 项目来源 / 证据目录，四者各自独立。
        SetText(BootMaintenanceBackupLocationsText, M("Dynamic.BootMaintenance.BackupLocations",
            _internalInstallBackup?.DirectoryPath ?? prepared.BackupDirectory,
            _bootMaintenanceOriginalDirectory ?? string.Empty,
            _bootMaintenanceProjectDirectory ?? string.Empty,
            prepared.EvidenceDirectory));

        foreach (var slot in prepared.Slots)
        {
            var slotText = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };

            SetText(slotText, slot.WillWrite
                ? M("Dynamic.BootMaintenance.SlotWrite",
                    slot.Slot ?? string.Empty,
                    slot.SourceSlot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind))
                : M("Dynamic.BootMaintenance.SlotKeep",
                    slot.Slot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind)));
            BootMaintenanceSlotsPanel.Children.Add(slotText);
        }

        foreach (var region in prepared.Regions)
        {
            var regionText = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };

            SetText(regionText, region.WillWrite
                ? M("Dynamic.BootMaintenance.RegionWrite",
                    region.Role ?? string.Empty,
                    region.Slot ?? string.Empty,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length)
                : M("Dynamic.BootMaintenance.RegionKeep",
                    region.Role ?? string.Empty,
                    region.Slot ?? string.Empty,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length));
            BootMaintenanceRegionsHost.Children.Add(regionText);
        }

        SetText(BootMaintenanceRiskText, BootMaintenanceRiskKey(CurrentBootMaintenanceMode));
        // Refresh 不得清空运行时现场：控制器持有已保存的结果 / 错误 / 进度时按其重绘。
        RenderBootMaintenanceRuntimeStatus();
    }

    private static string BootMaintenanceRiskKey(MaintenanceMode mode)
    {
        return mode switch
        {
            MaintenanceMode.BeforeUpdate => "Dynamic.BootMaintenance.Risk.BeforeUpdate",
            MaintenanceMode.AfterUpdate => "Dynamic.BootMaintenance.Risk.AfterUpdate",
            MaintenanceMode.RestoreStock => "Dynamic.BootMaintenance.Risk.RestoreStock",
            _ => throw new InvalidOperationException($"Unknown maintenance mode '{mode}'."),
        };
    }

    // SourceKind 的取值按票面为 Empty/StockOriginal/Project，使用 Core 已有枚举类型直接分派。
    private UiMessage DescribeBootMaintenanceSourceKind(BootMaintenanceSourceKind sourceKind)
    {
        return sourceKind switch
        {
            BootMaintenanceSourceKind.Empty => M("Dynamic.BootMaintenance.SourceKind.Empty"),
            BootMaintenanceSourceKind.StockOriginal => M("Dynamic.BootMaintenance.SourceKind.StockOriginal"),
            BootMaintenanceSourceKind.Project => M("Dynamic.BootMaintenance.SourceKind.Project"),
            _ => throw new InvalidOperationException($"Unknown boot maintenance source kind '{sourceKind}'."),
        };
    }

    private void RefreshBootMaintenanceActions()
    {
        if (!IsBootMaintenanceMode)
        {
            return;
        }

        InternalInstallNavCheck.IsEnabled = CanEnterBootMaintenanceStep(0);
        InternalInstallNavBackup.IsEnabled = CanEnterBootMaintenanceStep(1);
        InternalInstallNavCapacity.IsEnabled = CanEnterBootMaintenanceStep(2);
        InternalInstallNavConfirm.IsEnabled = CanEnterBootMaintenanceStep(3);

        PrevButton.IsEnabled = _internalInstallStep > 0 && CanEnterBootMaintenanceStep(_internalInstallStep - 1);

        NextButton.Visibility = _internalInstallStep < 3 ? Visibility.Visible : Visibility.Collapsed;
        NextButton.IsEnabled = CanLeaveBootMaintenanceStep(_internalInstallStep);

        ActionButton.Visibility = _internalInstallStep == 3 ? Visibility.Visible : Visibility.Collapsed;
        ActionButton.IsEnabled = CanExecuteBootMaintenance();

        bool idle = !_busy && !_bootMaintenanceOperationActive;
        bool protectedState = ProtectedBootMaintenanceState;

        BootMaintenanceEntryOriginalBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenanceOriginalBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenanceProjectBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenancePackageBox.IsEnabled = idle && !protectedState;

        // 9008 勾选与检查按钮在繁忙/保护状态下禁用；存在未知进入尝试的活跃 EDL 状态时不允许重开安卓检查。
        BootMaintenanceAlreadyEdlCheck.IsEnabled = _ready && idle && !protectedState && !HasInternalInstallLiveEdlState;
        InternalInstallCheckButton.IsEnabled = _ready && idle && !HasInternalInstallLiveEdlState;
        RefreshSharedAdvancedCheckAvailability();
    }

    // “下一步”在来源页（step 2）的启用条件：只校验真实备份与必填路径；路径仅允许 Prepare，真正校验在后端执行。
    private bool CanLeaveBootMaintenanceStep(int step)
    {
        if (step < 2)
        {
            return CanEnterBootMaintenanceStep(step + 1);
        }

        if (step == 2)
        {
            if (!_ready
                || _busy
                || _bootMaintenanceOperationActive
                || ProtectedBootMaintenanceState)
            {
                return false;
            }

            if (_internalInstallBackup is null
                || !HasBootMaintenanceDeviceProof)
            {
                return false;
            }

            // BeforeUpdate/RestoreStock 必须已选原厂恢复来源；AfterUpdate 允许项目/安装包为空（可能沿用模板）。
            if (CurrentBootMaintenanceMode != MaintenanceMode.AfterUpdate
                && string.IsNullOrWhiteSpace(_bootMaintenanceOriginalDirectory))
            {
                return false;
            }

            return true;
        }

        return false;
    }

    private bool CanExecuteBootMaintenance()
    {
        if (_bootMaintenanceBackend is not { } backend
            || backend.Prepared is not { } prepared
            || prepared.Mode != CurrentBootMaintenanceMode
            || _bootMaintenanceExecuteAttempted
            || _busy
            || _bootMaintenanceOperationActive
            || BootMaintenanceRiskCheck.IsChecked != true)
        {
            return false;
        }

        return true;
    }

    // 丢弃尚未写入的后端准备；受保护状态（已写入未完成）下一律拒绝。
    // 保留本次备份父目录、已选文件与会话；不做任何 IO 或设备重置。
    private void InvalidateBootMaintenancePreparation()
    {
        if (ProtectedBootMaintenanceState)
        {
            return;
        }

        if (_bootMaintenanceBackend is { } backend)
        {
            backend.Dispose();
            _bootMaintenanceBackend = null;
        }

        // 受保护状态早已早退：此处无写入现场，先释放本窗口持有的修复包，再清旗标与运行时缓存。
        ReleaseBootMaintenanceRepairPackage();

        _bootMaintenanceExecuteAttempted = false;
        BootMaintenanceRiskCheck.IsChecked = false;
        // 预写入作废同时清空运行时缓存，避免旧结论被下一次 Refresh 原样恢复。
        ClearBootMaintenanceRuntimeState();
    }

    private void OnBootMaintenanceRiskChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        // 卸载模式优先派发：风险勾选按卸载自己的门槛刷新（执行按钮在 U1 仍禁用）。
        if (IsModernUserdataUninstallMode)
        {
            RefreshModernUserdataUninstallActions();
            return;
        }

        // TF 卡安装优先派发：风险勾选按 TF 自己的动作刷新重算。
        if (IsModernTfInstallMode)
        {
            RefreshModernTfInstallActions();
            return;
        }

        if (!IsBootMaintenanceMode)
        {
            return;
        }

        RefreshBootMaintenanceActions();
    }

    private void OnBrowseBootMaintenanceOriginal(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        // 卸载分支：与维护同构地选择历史来源目录，写共享字段并作废卸载准备。
        if (IsModernUserdataUninstallMode)
        {
            if (_userdataUninstallOperationActive || ProtectedModernUserdataUninstallState)
            {
                return;
            }

            if (PickBootMaintenanceFolder() is not { } uninstallDirectory)
            {
                return; // 用户取消或选择无效：完整保留现有状态。
            }

            _bootMaintenanceOriginalDirectory = uninstallDirectory;
            BootMaintenanceEntryOriginalBox.Text = uninstallDirectory;
            BootMaintenanceOriginalBox.Text = uninstallDirectory;
            InvalidateModernUserdataUninstallPreparation();
            RefreshModernUserdataUninstallActions();
            return;
        }

        // TF 卡安装分支：与维护同构地选择历史来源目录；空闲且无 TF 现场 / 会话时才允许。
        // 这里只登记历史候选，不是任何「已就绪」。
        if (IsModernTfInstallMode)
        {
            if (_tfInstallOperationActive
                || ProtectedModernTfInstallState
                || HasAnyPreparedModernTfInstall
                || HasInternalInstallLiveEdlState)
            {
                return;
            }

            if (PickBootMaintenanceFolder() is not { } tfDirectory)
            {
                return; // 用户取消或选择无效：完整保留现有状态。
            }

            _bootMaintenanceOriginalDirectory = tfDirectory;
            BootMaintenanceEntryOriginalBox.Text = tfDirectory;
            BootMaintenanceOriginalBox.Text = tfDirectory;
            ResetInternalInstallCheckState(clearSelection: false);
            _bootMaintenanceHistoricalIdentity = null;
            RefreshModernTfInstallActions();
            return;
        }

        if (!IsBootMaintenanceMode
            || _bootMaintenanceOperationActive
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        if (PickBootMaintenanceFolder() is not { } directory)
        {
            return; // 用户取消或选择无效：完整保留现有状态。
        }

        _bootMaintenanceOriginalDirectory = directory;
        BootMaintenanceEntryOriginalBox.Text = directory;
        BootMaintenanceOriginalBox.Text = directory;
        InvalidateBootMaintenancePreparation();
        RefreshBootMaintenanceActions();
    }

    private void OnBrowseBootMaintenanceProject(object sender, RoutedEventArgs e)
    {
        if (!_ready
            || !IsBootMaintenanceMode
            || _busy
            || _bootMaintenanceOperationActive
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        if (PickBootMaintenanceFolder() is not { } directory)
        {
            return;
        }

        _bootMaintenanceProjectDirectory = directory;
        BootMaintenanceProjectBox.Text = directory;
        InvalidateBootMaintenancePreparation();
        RefreshBootMaintenanceActions();
    }

    // 包路径允许手贴：既可能是文件也可能是文件夹，此处只存真实文本，不做导入或存在性断言。
    private void OnBootMaintenancePackagePathChanged(object sender, TextChangedEventArgs e)
    {
        if (BootMaintenancePackageBox is null)
        {
            return;
        }

        if (!_ready
            || !IsBootMaintenanceMode
            || _busy
            || _bootMaintenanceOperationActive
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        _bootMaintenancePackagePath = BootMaintenancePackageBox.Text;
        InvalidateBootMaintenancePreparation();
        RefreshBootMaintenanceActions();
    }

    // 勾选只改变路线偏好（下一步走 9008 识别），不改变任何设备证据；
    // 已有真实 9008 会话或未知进入尝试的活跃 EDL 状态、保护状态或繁忙时拒绝并还原勾选。
    private void OnBootMaintenanceEdlRouteChanged(object sender, RoutedEventArgs e)
    {
        if (BootMaintenanceAlreadyEdlCheck is null)
        {
            return;
        }

        bool requested = BootMaintenanceAlreadyEdlCheck.IsChecked == true;
        if (requested == _bootMaintenanceAlreadyEdl)
        {
            return;
        }

        // 卸载分支：与维护同构地切换 9008 路线；空闲时重置只读检查/历史，绝不丢弃真实 9008 现场。
        if (IsModernUserdataUninstallMode)
        {
            if (_busy || _userdataUninstallOperationActive || ProtectedModernUserdataUninstallState || HasInternalInstallLiveEdlState)
            {
                BootMaintenanceAlreadyEdlCheck.IsChecked = _bootMaintenanceAlreadyEdl;
                return;
            }

            ResetInternalInstallCheckState(clearSelection: false);
            _bootMaintenanceHistoricalIdentity = null;
            InvalidateModernUserdataUninstallPreparation();

            _bootMaintenanceAlreadyEdl = requested;
            RefreshModernUserdataUninstallActions();
            return;
        }

        // TF 卡安装分支：与维护 / 卸载同构地切换 9008 路线；空闲时重置只读检查 / 历史，
        // 绝不丢弃真实 9008 现场。
        if (IsModernTfInstallMode)
        {
            if (_busy
                || _tfInstallOperationActive
                || ProtectedModernTfInstallState
                || HasAnyPreparedModernTfInstall
                || HasInternalInstallLiveEdlState)
            {
                BootMaintenanceAlreadyEdlCheck.IsChecked = _bootMaintenanceAlreadyEdl;
                return;
            }

            ResetInternalInstallCheckState(clearSelection: false);
            _bootMaintenanceHistoricalIdentity = null;

            _bootMaintenanceAlreadyEdl = requested;
            RefreshModernTfInstallActions();
            return;
        }

        if (!_ready || _busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState || HasInternalInstallLiveEdlState)
        {
            BootMaintenanceAlreadyEdlCheck.IsChecked = _bootMaintenanceAlreadyEdl;
            return;
        }

        // 路线实际变化前先丢弃未写入的准备，并作废只读检查 / 电量证明；已有真实 9008 现场绝不丢弃。
        ResetInternalInstallCheckState(clearSelection: false);
        _bootMaintenanceHistoricalIdentity = null;

        InvalidateBootMaintenancePreparation();

        _bootMaintenanceAlreadyEdl = requested;
        RenderBootMaintenanceCheckButton();
        RefreshBootMaintenanceActions();
    }

    private string? PickBootMaintenanceFolder()
    {
        var dialog = new OpenFolderDialog
        {
            FolderName = _bootMaintenanceOriginalDirectory ?? string.Empty,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return null;
        }

        var path = dialog.FolderName;
        return Directory.Exists(path) ? path : null;
    }
}
