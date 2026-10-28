using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 六模式执行分发的显式路由表：只按 <c>CurrentModeTag()</c> 精确分派；
/// 六个操作全部接入真实执行入口，未知模式仍走占位汇报入口（fail closed）。
/// </summary>
public partial class MainWindow
{
    private Task DispatchSelectedWorkflowAsync(object sender, RoutedEventArgs e)
    {
        if (!_ready
            || _busy
            || _showingEnvironment
            || !EnvironmentIsReady
            || _showingHome
            || _showingSupport)
        {
            return Task.CompletedTask;
        }

        switch (CurrentModeTag())
        {
            case "install":
                return ExecuteInternalInstallAsync();
            case "uninstall":
                return ExecuteModernUserdataUninstallAsync();
            case "install-tf":
                return ExecuteTfInstallWorkflowAsync();
            case "prepare":
                return ExecutePrepareUpdateWorkflowAsync();
            case "repair":
                return ExecuteRepairAfterUpdateWorkflowAsync();
            case "restore":
                return ExecuteRestoreStockBootWorkflowAsync();
            default:
                return ReportUnpreparedWorkflowAsync();
        }
    }

    private Task ExecuteTfInstallWorkflowAsync()
    {
        return ExecuteModernTfInstallAsync();
    }

    private Task ExecutePrepareUpdateWorkflowAsync()
    {
        return ExecuteBootMaintenanceAsync();
    }

    private Task ExecuteRepairAfterUpdateWorkflowAsync()
    {
        return ExecuteBootMaintenanceAsync();
    }

    private Task ExecuteRestoreStockBootWorkflowAsync()
    {
        return ExecuteBootMaintenanceAsync();
    }

    private Task ReportUnpreparedWorkflowAsync()
    {
        var message = M("Dynamic.Workflow.NotPrepared", ModeMessage(CurrentModeTag()));
        SetText(ProgressStatusText, message);
        SetText(ActionReasonText, message);
        AppendLocalizedLog(message);
        return Task.CompletedTask;
    }

    private bool HasPreparedLegacyUninstall =>
        _uninstallEdlBackend is not null
        && _uninstallInputs is not null
        && _uninstallPhase == UninstallUiPhase.Prepared
        && !_uninstallAttempted
        && !_uninstallEdlResetAttempted;

    private bool CanEnterLegacyWorkflowPage(int page)
    {
        if (!_ready
            || !IsKnownOperation(CurrentModeTag())
            || !EnvironmentIsReady
            || _busy
            || _showingEnvironment
            || _showingHome
            || _showingSupport
            || HasProtectedUninstallState)
        {
            return false;
        }

        if (page == 0)
        {
            return true;
        }

        var mode = CurrentModeTag();
        if (page == 1)
        {
            if (mode == "install-tf")
            {
                return _tfSource == FreedomInstaller.Core.TfCardSource.Reader
                    || (_tfSource == FreedomInstaller.Core.TfCardSource.Tablet
                        && _transport is not null
                        && _identity is not null);
            }

            if (mode == "uninstall")
            {
                return _uninstallEdlResult is not null;
            }

            return false;
        }

        if (page == 2)
        {
            return mode == "uninstall" && HasPreparedLegacyUninstall;
        }

        return false;
    }

    private void RestoreLegacyNavigationSelection()
    {
        _suppressNav = true;
        try
        {
            NavConnect.IsChecked = _page == 0;
            NavCapacity.IsChecked = _page == 1;
            NavConfirm.IsChecked = _page == 2;
        }
        finally
        {
            _suppressNav = false;
        }
    }
}
