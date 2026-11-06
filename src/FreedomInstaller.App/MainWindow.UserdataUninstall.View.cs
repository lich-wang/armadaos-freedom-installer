using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载向导视图层：页面可见性、导航渲染、按钮可用性与确认页内容。
/// 复用共享设备准备页与维护的来源/确认页面，只按本模式写入自己的文案；
/// 执行按钮仅在准备与风险确认完成后启用。
/// </summary>
public partial class MainWindow
{
    // ---------- 导航 ----------

    /// <summary>
    /// 程序化重写共享侧栏勾选；卸载隐藏内部第 1 步，勾选只落在 0、2、3。
    /// 序号与文案由共享导航渲染统一设置。
    /// </summary>
    private void RestoreModernUserdataUninstallNav()
    {
        _suppressInternalInstallNav = true;
        try
        {
            InternalInstallNavCheck.IsChecked = _internalInstallStep == 0;
            InternalInstallNavBackup.IsChecked = false;
            InternalInstallNavCapacity.IsChecked = _internalInstallStep == 2;
            InternalInstallNavConfirm.IsChecked = _internalInstallStep == 3;
        }
        finally
        {
            _suppressInternalInstallNav = false;
        }
    }

    /// <summary>卸载向导导航唯一入口：越界、忙碌、隐藏步骤或门槛未满足时拒绝并恢复勾选。</summary>
    private void NavigateModernUserdataUninstallStep(int step)
    {
        if (!IsModernUserdataUninstallMode || _busy || step is < 0 or > 3 || step == 1)
        {
            RestoreModernUserdataUninstallNav();
            return;
        }

        if (step != _internalInstallStep && !CanEnterModernUserdataUninstallStep(step))
        {
            RestoreModernUserdataUninstallNav();
            return;
        }

        _internalInstallStep = step;
        RenderModernUserdataUninstallPages();
        RefreshModernUserdataUninstallActions();
    }

    // ---------- 渲染 ----------

    /// <summary>
    /// 按当前步骤写入共享页面的可见性：第 0 步用安装检查页，第 2 步复用维护来源页，
    /// 第 3 步复用维护确认页；全新备份页、容量页与安装确认页始终隐藏。
    /// </summary>
    private void RenderModernUserdataUninstallPages()
    {
        if (!IsModernUserdataUninstallMode)
        {
            return;
        }

        RestoreModernUserdataUninstallNav();

        InternalInstallCheckPage.Visibility =
            _internalInstallStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallBackupPage.Visibility = Visibility.Collapsed;
        InternalInstallCapacityPage.Visibility = Visibility.Collapsed;
        InternalInstallConfirmPage.Visibility = Visibility.Collapsed;

        BootMaintenanceSourcesPage.Visibility =
            _internalInstallStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        BootMaintenanceConfirmPage.Visibility =
            _internalInstallStep == 3 ? Visibility.Visible : Visibility.Collapsed;

        // 9008 历史路线入口只出现在第 0 步；修复来源行对卸载无意义。
        BootMaintenanceEntryPanel.Visibility =
            _internalInstallStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        BootMaintenanceRepairSourcesRow.Visibility = Visibility.Collapsed;

        // 全新备份是唯一路线：复用已有备份的两行一律隐藏并禁用。
        InternalInstallBackupUseExistingCheck.Visibility = Visibility.Collapsed;
        InternalInstallBackupUseExistingCheck.IsEnabled = false;
        InternalInstallBackupExistingRow.Visibility = Visibility.Collapsed;
        InternalInstallBackupExistingBrowseButton.IsEnabled = false;

        // 第 2/3 步的卸载专属文案：来源页标题/说明/原厂来源说明与确认页标题。
        if (_internalInstallStep == 2)
        {
            SetText(BootMaintenanceSourcesTitle, "Dynamic.UserdataUninstall.SourceTitle");
            SetText(BootMaintenanceSourcesLead, "Dynamic.UserdataUninstall.SourceLead");
            SharedEdlOriginalSourceLabel.SetResourceReference(
                TextBlock.TextProperty,
                "Dynamic.UserdataUninstall.OriginalSource");
        }

        // 原厂引导恢复复选框及其提示仅在卸载模式可见；其他模式由共享导航方法隐藏。
        var stockCheckVisible = IsModernUserdataUninstallMode;
        var stockCheckVisibility = stockCheckVisible ? Visibility.Visible : Visibility.Collapsed;
        BootMaintenanceRestoreStockCheck.Visibility = stockCheckVisibility;
        BootMaintenanceConfirmRestoreStockCheck.Visibility = stockCheckVisibility;
        if (stockCheckVisible)
        {
            SyncUserdataUninstallRestoreStockCheckboxes();
            UpdateUserdataUninstallRestoreStockCheckboxEnabled();
        }

        if (_internalInstallStep == 0)
        {
            SharedEdlEntryHintText.SetResourceReference(
                TextBlock.TextProperty,
                "Dynamic.UserdataUninstall.EdlHint");
            SharedEdlOriginalEntryLabel.SetResourceReference(
                TextBlock.TextProperty,
                "Dynamic.UserdataUninstall.OriginalSource");
        }

        BootMaintenanceEntryOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;
        BootMaintenanceOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;

        RenderModernUserdataUninstallConfirmPage();
        RenderBootMaintenanceCheckButton();
        RenderModernUserdataUninstallRuntimeStatus();
        if (_internalInstallStep == 2) RenderUserdataUninstallPreparationError();
        RefreshModernUserdataUninstallActions();
    }

    /// <summary>
    /// 确认页（第 3 步）：只按真实准备结果显示设备身份、当前与恢复后的容量、槽位方案与删除范围；
    /// 保留备份说明只在 Core 校验的 2 GiB 保留备份真实存在时出现。执行按钮由准备结果和风险勾选共同控制。
    /// </summary>
    private void RenderModernUserdataUninstallConfirmPage()
    {
        BootMaintenanceSlotsPanel.Children.Clear();
        BootMaintenanceRegionsHost.Children.Clear();

        var backend = _userdataUninstallBackend;
        var inputs = backend?.Inputs;
        if (backend is null || inputs is null || !HasPreparedUninstallBootPlan)
        {
            SetText(BootMaintenanceDeviceText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceBackupLocationsText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceRiskText, "Dynamic.UserdataUninstall.Risk.Confirm");
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.UserdataUninstall.NotPrepared");
            SetText(BootMaintenanceConfirmTitle, "Dynamic.UserdataUninstall.ConfirmTitle");
            SetText(BootMaintenanceProgressText, "Dynamic.RawValue", string.Empty);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 0;
            return;
        }

        SetText(BootMaintenanceConfirmTitle, "Dynamic.UserdataUninstall.ConfirmTitle");
        SetText(BootMaintenanceConfirmStatusText, "Dynamic.UserdataUninstall.Status.Prepared");
        SetText(
            BootMaintenanceDeviceText,
            M(
                "Dynamic.UserdataUninstall.DeviceSummary",
                inputs.Identity.Model,
                inputs.Identity.Serial,
                backend.CurrentSlot));

        // 容量摘要：当前安卓分区字节数只来自真实校验输入；恢复后容量来自真实方案。
        // 引导行为作为新增参数传入，不再在文案中硬编码“保留项目引导与EFI”。
        var bootBehavior = UserdataUninstallSelectedBootBehaviorText();
        var currentBytes = CurrentUserdataBytes(inputs);
        SetText(
            BootMaintenanceBackupLocationsText,
            M(
                "Dynamic.UserdataUninstall.CapacitySummary",
                FormatBytesOrPlaceholder(currentBytes),
                FormatBytes(inputs.Plan.RestoredAndroidBytes),
                DeletedPartitionExtents(inputs),
                bootBehavior));

        // 现代尾部 2 GiB 恢复备份区：只在 Core 校验的真实保留备份存在时说明，绝不按名字猜。
        if (inputs.Record.BoardBackupPartUuid is not null)
        {
            var retained = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };
            SetText(retained, M("Dynamic.UserdataUninstall.RetainedBackup"));
            BootMaintenanceSlotsPanel.Children.Add(retained);
        }

        foreach (var slot in _userdataUninstallMenu?.Slots ?? Array.Empty<CurrentBootMenuSlot>())
        {
            var slotText = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };

            // Candidate 为 null 表示该槽位不写入、保留现状；绝不声称两套完整安卓系统都存在。
            // 勾选恢复原厂引导时以原厂方案槽位为准，不再列出相互矛盾的菜单默认槽位。
            if (_userdataUninstallRestoreStockBoot)
            {
                continue;
            }

            SetText(slotText, slot.Candidate is null
                ? M("Dynamic.UserdataUninstall.SlotKeep", slot.Slot)
                : M(
                    "Dynamic.UserdataUninstall.SlotWriteDefault",
                    slot.Slot,
                    slot.SourceSlot ?? string.Empty));
            BootMaintenanceSlotsPanel.Children.Add(slotText);
        }

        foreach (var number in inputs.Plan.RemovedPartitionNumbers)
        {
            var regionText = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };
            SetText(regionText, M("Dynamic.UserdataUninstall.RemovedPartition", number));
            BootMaintenanceRegionsHost.Children.Add(regionText);
        }

        // 勾选恢复原厂引导时：逐槽列出真实的引导恢复方案摘要（含空槽保留与已为原厂的真相）。
        if (_userdataUninstallRestoreStockBoot)
        {
            RenderUserdataUninstallStockPlanSlots(BootMaintenanceSlotsPanel);
        }

        SetText(BootMaintenanceRiskText, "Dynamic.UserdataUninstall.Risk.Confirm");
    }

    /// <summary>准备中的粗粒度中性进度：有真实总量时显示观察字节，否则保持不确定。</summary>
    private void RenderModernUserdataUninstallPrepareProgress(EdlUninstallProgress report)
    {
        if (!_ready
            || _closed
            || !IsModernUserdataUninstallMode
            || !_userdataUninstallOperationActive)
        {
            return;
        }

        if (report.TotalBytes > 0)
        {
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = Math.Clamp(
                (double)report.CompletedBytes / report.TotalBytes * 100d,
                0d,
                100d);
            SetText(
                BootMaintenanceProgressText,
                M(
                    "Dynamic.UserdataUninstall.Progress.Transferring",
                    FormatBytes(report.CompletedBytes),
                    FormatBytes(report.TotalBytes)));
        }
        else
        {
            BootMaintenanceProgressBar.IsIndeterminate = true;
            SetText(BootMaintenanceProgressText, M("Dynamic.UserdataUninstall.Progress.TransferringUnknown"));
        }
    }

    // ---------- 可用性 ----------

    /// <summary>
    /// 卸载向导的底栏与控件可用性。第 2 步「下一步」需要真实设备入口前提与有效的原始来源目录；
    /// 内部第 3 步的执行按钮由执行条件与风险勾选共同控制。
    /// </summary>
    private void RefreshModernUserdataUninstallActions()
    {
        if (!IsModernUserdataUninstallMode)
        {
            return;
        }

        var protectedState = ProtectedModernUserdataUninstallState;

        // 内部第 1 步在卸载中不可见、不可进入；其余步骤按门槛开放。
        InternalInstallNavCheck.IsEnabled = !_busy && CanEnterModernUserdataUninstallStep(0);
        InternalInstallNavBackup.IsEnabled = false;
        InternalInstallNavCapacity.IsEnabled = !_busy && CanEnterModernUserdataUninstallStep(2);
        InternalInstallNavConfirm.IsEnabled = !_busy && CanEnterModernUserdataUninstallStep(3);

        var previousStep = PreviousModernUserdataUninstallStep(_internalInstallStep);
        PrevButton.IsEnabled = !_busy
            && previousStep != _internalInstallStep
            && CanEnterModernUserdataUninstallStep(previousStep);

        NextButton.Visibility = _internalInstallStep < 3 ? Visibility.Visible : Visibility.Collapsed;
        // 已知活动操作期间绝不只凭已选路径开放下一步；第 2 步还需真实设备入口前提。
        NextButton.IsEnabled = !_busy
            && !protectedState
            && _internalInstallStep < 3
            && (_internalInstallStep < 2
                ? CanEnterModernUserdataUninstallStep(NextModernUserdataUninstallStep(_internalInstallStep))
                : HasBootMaintenanceBackupPrerequisite
                    && !string.IsNullOrWhiteSpace(_bootMaintenanceOriginalDirectory)
                    && Directory.Exists(_bootMaintenanceOriginalDirectory));

        UpdateUserdataUninstallRestoreStockCheckboxEnabled();

        // 按钮只按事实谓词开放；文案在卸载模式第 3 步始终使用本地化「执行」键，不只限可用时。
        ActionButton.Visibility = _internalInstallStep == 3 ? Visibility.Visible : Visibility.Collapsed;
        ActionButton.IsEnabled = CanExecuteModernUserdataUninstall();
        if (_internalInstallStep == 3)
        {
            SetContent(ActionButton, "Dynamic.UserdataUninstall.Execute");
        }

        // 直接刷新共享备份控件：维护共享可用性方法对卸载模式立即返回，这里不复用。
        // 卸载完成后所有输入都收口，空闲判定额外要求未完成。
        var idle = !_busy
            && !_userdataUninstallOperationActive
            && !_internalInstallOperationActive
            && !_userdataUninstallCompleted;
        // 浏览 / 开始备份只要求事实门槛；真正的准备与执行（下一步）仍走 HasBootMaintenanceDeviceProof。
        var proof = HasBootMaintenanceBackupPrerequisite;
        var validParent = !string.IsNullOrWhiteSpace(_internalInstallBackupParent)
            && Directory.Exists(_internalInstallBackupParent);
        var sameSession = _internalInstallEdlClient is not null
            && _internalInstallEdlTools is not null
            && _internalInstallEdlEntry is not null;

        InternalInstallBackupBrowseButton.IsEnabled = idle && proof && !protectedState;
        InternalInstallBackupFolderBox.IsEnabled = idle && !protectedState;
        InternalInstallBackupButton.IsEnabled = idle
            && !protectedState
            && proof
            && validParent
            && (!HasInternalInstallLiveEdlState || sameSession);

        // 已有两行一律禁用并保持隐藏（上面 Render 已处理可见性，这里只保禁用）。
        InternalInstallBackupUseExistingCheck.IsEnabled = false;
        InternalInstallBackupExistingBrowseButton.IsEnabled = false;

        UpdateInternalInstallDeviceSelector();
        InternalInstallDevicesCombo.IsEnabled = idle
            && !protectedState
            && !HasInternalInstallLiveEdlState
            && !_bootMaintenanceAlreadyEdl
            && _internalInstallDeviceChoices.Count > 0;

        InternalInstallCheckButton.IsEnabled = _ready
            && idle
            && !protectedState
            && _transport is not null
            && !HasInternalInstallLiveEdlState;

        BootMaintenanceEntryOriginalBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenanceOriginalBrowseButton.IsEnabled = idle && !protectedState;

        // 卸载确认页自己的风险勾选：只在空闲、无保护、未完成，且三个真实对象（非路径）都存在时开放。
        BootMaintenanceRiskCheck.IsEnabled = idle
            && !protectedState
            && !_userdataUninstallCompleted
            && _userdataUninstallBackend is not null
            && HasPreparedUninstallBootPlan
            && _userdataUninstallOriginal is not null;

        // 共享退出面板只在真实 9008 会话存在且尚未完成时可见；按钮按空闲与未解决状态收紧。
        var exitVisible = HasInternalInstallLiveEdlState && !_userdataUninstallCompleted;
        InternalInstallExitMaintenancePanel.Visibility =
            exitVisible ? Visibility.Visible : Visibility.Collapsed;
        if (exitVisible)
        {
            SetContent(InternalInstallExitMaintenanceButton, "Dynamic.UserdataUninstall.Exit.Button");
            SetText(
                InternalInstallExitMaintenanceStatusText,
                _userdataUninstallExitStatus
                    ?? M("Dynamic.UserdataUninstall.Exit.Ready"));
        }

        InternalInstallExitMaintenanceButton.IsEnabled = idle
            && !HasUnresolvedModernUserdataUninstallState
            && _internalInstallEdlClient is not null;

        RefreshSharedAdvancedCheckAvailability();
    }
}
