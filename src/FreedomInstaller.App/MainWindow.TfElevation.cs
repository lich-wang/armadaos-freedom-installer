using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 电脑读卡器的「同 EXE 管理员重启」门禁：非管理员选择读卡器时，用固定参数
/// <c>--tf-reader</c> 通过 UAC 重新打开本程序；取消或失败时保留原窗口与当前选择。
/// 这里只做进程重启判断与入口切换，从不做读卡、设备、磁盘写入等任何实际操作。
/// </summary>
public partial class MainWindow
{
    /// <summary>已发起 UAC 重启、新窗口尚未接管：期间阻止旧窗口关闭流程的其它确认。</summary>
    private bool _tfReaderElevationPending;

    /// <summary>重启已被接受、旧窗口可以正常关闭。</summary>
    private bool _tfReaderRelaunchApproved;

    /// <summary><c>--tf-reader</c> 启动入口每个进程只处理一次，之后作为普通参数忽略。</summary>
    private bool _tfReaderStartupHandled;

    /// <summary>恢复读卡方式单选状态时抑制 OnTfSourceChanged，避免恢复动作再次触发提升。</summary>
    private bool _suppressTfSourceForElevation;

    // ---------- 实际管理员判定 ----------

    /// <summary>
    /// 用 Windows 身份实际判断当前进程是否以管理员运行；任何异常一律按「非管理员」处理，
    /// 绝不假判为管理员。
    /// </summary>
    private static bool IsActualWindowsAdmin()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity is not null
                && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// 安全重启前提：没有任何进行中的准备、维护、内部安装现场、受保护卸载、TF 安装
    /// 工作流或导入任务。真实备份 / 9008 / 已准备上下文 / TF 受保护状态在场时一律拒绝提升。
    /// </summary>
    private bool CanRelaunchForTfReaderSafely =>
        !_busy
        && !_internalInstallOperationActive
        && !HasInternalInstallLiveEdlState
        && !HasProtectedUninstallState
        && !ProtectedBootMaintenanceState
        && !ProtectedModernTfInstallState
        && !HasAnyPreparedModernTfInstall
        && _internalInstallBackup is null
        && _internalInstallBackend is null
        && _internalInstallArtifacts is null
        && !(_importTask is { IsCompleted: false });

    // ---------- 单选恢复 ----------

    /// <summary>按 <see cref="_tfSource"/> 恢复读卡方式单选；抑制期间不触发切换逻辑。</summary>
    private void RestoreTfSourceChoiceAfterElevation()
    {
        _suppressTfSourceForElevation = true;
        try
        {
            TfSourceReaderRadio.IsChecked = _tfSource == TfCardSource.Reader;
            TfSourceTabletRadio.IsChecked = _tfSource != TfCardSource.Reader;
        }
        finally
        {
            _suppressTfSourceForElevation = false;
        }

        RenderTfTexts();
    }

    // ---------- 同 EXE 提升重启 ----------

    /// <summary>
    /// 以管理员身份重启本程序（固定参数 <c>--tf-reader</c>）。启动被接受后先清掉自己的
    /// 待定 / 忙碌状态再关闭旧窗口；取消或失败时保留旧窗口与全部当前选择。绝不等待、
    /// 取消或终止新窗口进程。
    /// </summary>
    private async Task<bool> TryRelaunchForTfReaderAsync()
    {
        if (!CanRelaunchForTfReaderSafely)
        {
            var blocked = M("Dynamic.TfElevation.BeforeWork");
            AppendLocalizedLog(blocked);
            ShowTfElevationDialog(blocked);
            return false;
        }

        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            var missing = M("Dynamic.TfElevation.Failed");
            AppendLocalizedLog(missing);
            ShowTfElevationDialog(missing);
            return false;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(exePath) ?? exePath,
            WindowStyle = ProcessWindowStyle.Normal,
        };
        startInfo.ArgumentList.Add("--tf-reader");

        _tfReaderElevationPending = true;
        _busy = true;
        RefreshActions();
        Process? process = null;
        try
        {
            process = await Task.Run(() => Process.Start(startInfo));
            if (process is null || process.HasExited)
            {
                var failed = M("Dynamic.TfElevation.Failed");
                AppendLocalizedLog(failed);
                ShowTfElevationDialog(failed);
                return false;
            }

            // 新窗口已启动：先清掉自己的待定 / 忙碌，再关闭，避免旧的关闭闸门把它否决。
            _tfReaderRelaunchApproved = true;
            _tfReaderElevationPending = false;
            _busy = false;
            Close();
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // 1223 = 用户在 UAC 上点了「否」：原窗口保持可用，可再次尝试。
            var cancelled = M("Dynamic.TfElevation.Cancelled");
            AppendLocalizedLog(cancelled);
            ShowTfElevationDialog(cancelled);
            return false;
        }
        catch (Exception ex)
        {
            var failed = M("Dynamic.TfElevation.Failed");
            AppendLocalizedLog(failed);
            AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
            ShowTfElevationDialog(failed);
            return false;
        }
        finally
        {
            _tfReaderElevationPending = false;
            _tfReaderRelaunchApproved = false;
            _busy = false;
            process?.Dispose();
            if (!_closed)
            {
                RefreshActions();
            }
        }
    }

    /// <summary>提升相关的提示：写日志，并以当前语言弹出消息框。</summary>
    private void ShowTfElevationDialog(UiMessage message)
    {
        MessageBox.Show(
            this,
            _uiText.Format(message),
            T("Dynamic.TfElevation.Title"),
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    // ---------- --tf-reader 启动入口 ----------

    /// <summary>
    /// 在环境「继续」时处理 <c>--tf-reader</c> 启动入口：非管理员带参 → 发起同样的提升重启
    /// （取消则照常进首页）；管理员带参 → 直接进入读卡器模式的全新页面。普通无参启动不产生
    /// 任何特殊行为，返回 <c>false</c>。入口参数只表达偏好，不绕过任何环境门禁。
    /// TF 卡安装入口暂时关闭期间，该参数一律按普通启动处理（不提升、不改状态）。
    /// </summary>
    private async Task<bool> TryOpenRequestedTfReaderStartupAsync()
    {
        if (_tfReaderStartupHandled)
        {
            return false;
        }

        _tfReaderStartupHandled = true;

        // TF 卡安装入口暂时关闭：先于命令行解析与 UAC 判断退出，旧参数不再引发提升或状态变化，
        // 后续照常走环境 / 备份 / 首页流程；底层实现与恢复页保留。
        if (!IsSelectableOperation("install-tf"))
        {
            return false;
        }

        bool requested = false;
        string[] args = Environment.GetCommandLineArgs();
        for (int i = 1; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--tf-reader", StringComparison.Ordinal))
            {
                requested = true;
                break;
            }
        }

        if (!requested)
        {
            return false;
        }

        // 只在环境真正就绪时接管入口；否则照常展示，用户之后仍可手动继续。
        if (!_ready || !EnvironmentIsReady)
        {
            return false;
        }

        if (!IsActualWindowsAdmin())
        {
            return await TryRelaunchForTfReaderAsync();
        }

        _selectedOperation = "install-tf";
        _showingHome = false;
        _showingSupport = false;
        _tfSource = TfCardSource.Reader;
        RestoreTfSourceChoiceAfterElevation();
        ResetTfSelection(clearInventory: true);
        UpdateModeUi();
        Navigate(0);
        ApplyFunctionView();
        RefreshActions();
        return true;
    }
}
