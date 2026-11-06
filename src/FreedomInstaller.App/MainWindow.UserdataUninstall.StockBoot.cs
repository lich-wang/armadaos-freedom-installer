using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

public partial class MainWindow
{
    private void OnUserdataUninstallRestoreStockChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready || _userdataUninstallStockCheckboxSuppress)
        {
            return;
        }

        if (sender is not CheckBox changed)
        {
            return;
        }

        if (!IsModernUserdataUninstallMode)
        {
            SyncUserdataUninstallRestoreStockCheckboxes();
            return;
        }

        var desired = changed.IsChecked == true;

        if (!CanUserdataUninstallToggleRestoreStock())
        {
            SyncUserdataUninstallRestoreStockCheckboxes();
            return;
        }

        if (_userdataUninstallRestoreStockBoot == desired)
        {
            SyncUserdataUninstallRestoreStockCheckboxes();
            return;
        }

        // 切换即作废上一次未写入的准备；若已在确认页，则退回来来源页避免残留旧确认。
        _userdataUninstallRestoreStockBoot = desired;
        _userdataUninstallStockPlan = null;
        _userdataUninstallStockRestoreResult = null;

        InvalidateModernUserdataUninstallPreparation();

        if (_internalInstallStep >= 3)
        {
            _internalInstallStep = 2;
            SetText(BootMaintenancePrepareStatusText, "Dynamic.UserdataUninstall.RestoreStock.InvalidateHint");
        }

        SyncUserdataUninstallRestoreStockCheckboxes();
        UpdateUserdataUninstallRestoreStockCheckboxEnabled();
        RenderModernUserdataUninstallPages();
        RefreshModernUserdataUninstallActions();
    }

    private bool CanUserdataUninstallToggleRestoreStock()
    {
        return _ready
            && IsModernUserdataUninstallMode
            && !_busy
            && !_userdataUninstallOperationActive
            && !_userdataUninstallExecuteAttempted
            && !_userdataUninstallCompleted;
    }

    private void SyncUserdataUninstallRestoreStockCheckboxes()
    {
        if (!_ready)
        {
            return;
        }

        _userdataUninstallStockCheckboxSuppress = true;
        try
        {
            BootMaintenanceRestoreStockCheck.IsChecked = _userdataUninstallRestoreStockBoot;
            BootMaintenanceConfirmRestoreStockCheck.IsChecked = _userdataUninstallRestoreStockBoot;
            var hintVisibility = _userdataUninstallRestoreStockBoot ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceRestoreStockHint.Visibility = hintVisibility;
            BootMaintenanceConfirmRestoreStockHint.Visibility = hintVisibility;
        }
        finally
        {
            _userdataUninstallStockCheckboxSuppress = false;
        }
    }

    private void UpdateUserdataUninstallRestoreStockCheckboxEnabled()
    {
        if (!_ready)
        {
            return;
        }

        var enabled = CanUserdataUninstallToggleRestoreStock()
            && !ProtectedModernUserdataUninstallState;

        BootMaintenanceRestoreStockCheck.IsEnabled = enabled;
        BootMaintenanceConfirmRestoreStockCheck.IsEnabled = enabled;
    }

    private string UserdataUninstallSelectedBootBehaviorText()
    {
        return _userdataUninstallRestoreStockBoot
            ? T("Dynamic.UserdataUninstall.BootBehavior.RestoreStock")
            : T("Dynamic.UserdataUninstall.BootBehavior.KeepProject");
    }

    private void RenderUserdataUninstallStockPlanSlots(Panel target)
    {
        var plan = _userdataUninstallStockPlan;
        if (plan is null)
        {
            return;
        }

        var header = new TextBlock
        {
            Style = (Style)FindResource("CaptionText"),
            Margin = new Thickness(0, 8, 0, 0),
            TextWrapping = TextWrapping.Wrap,
        };
        SetText(header, M("Dynamic.UserdataUninstall.RestoreStock.PlanHeader"));
        target.Children.Add(header);

        foreach (var line in UserdataUninstallStockPlanSlotLines(plan))
        {
            var slotText = new TextBlock
            {
                Style = (Style)FindResource("CaptionText"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap,
            };
            SetText(slotText, line);
            target.Children.Add(slotText);
        }
    }

    private string UserdataUninstallStockPlanSlotSummary(BootMaintenancePrepared plan)
    {
        var lines = UserdataUninstallStockPlanSlotLines(plan);
        return lines.Count == 0
            ? string.Empty
            : string.Join("\n", lines.Select(_uiText.Format));
    }

    /// <summary>
    /// 逐槽文案：Empty 优先；否则该槽在方案中含 WillWrite 区域才标 Restore；
    /// 否则说明已为原厂无需写入。绝不把有效原厂的无操作误标为空。
    /// </summary>
    private List<UiMessage> UserdataUninstallStockPlanSlotLines(BootMaintenancePrepared plan)
    {
        var lines = new List<UiMessage>();
        foreach (var slot in plan.Slots)
        {
            if (slot.SourceKind == BootMaintenanceSourceKind.Empty)
            {
                lines.Add(M("Dynamic.UserdataUninstall.RestoreStock.SlotEmpty", slot.Slot));
                continue;
            }

            var willWrite = plan.Regions.Any(r =>
                string.Equals(r.Slot, slot.Slot, System.StringComparison.Ordinal)
                && r.WillWrite);

            if (willWrite)
            {
                lines.Add(M(
                    "Dynamic.UserdataUninstall.RestoreStock.SlotRestore",
                    slot.Slot,
                    slot.SourceSlot ?? string.Empty));
            }
            else
            {
                lines.Add(M("Dynamic.UserdataUninstall.RestoreStock.SlotAlreadyStock", slot.Slot));
            }
        }

        return lines;
    }
}
