using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;
using Microsoft.Win32;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载流程的安卓身份与工作目录（N1）：只读读取安卓 SoC 身份、选择本次专用工作目录。
/// <para>
/// 临时 Fastboot 引导、USB 串口发现与维护会话已整体移除。实际的卸载操作由 9008/EDL
/// 流程承担；平板 TF 的待完成启动恢复是独立路径，不在这里执行卸载。
/// 本文件不进行任何分区、格式化、刷写或卸载写入。
/// </para>
/// <para>
/// 所有面向用户的文字都通过既有 Dynamic 键取得；原始异常文本只作为已本地化文案的参数出现，
/// 不直接拼成句子，也不记录令牌或连接记录。
/// </para>
/// </summary>
public partial class MainWindow
{
    // ---------- 卸载工作目录与只读安卓身份 ----------

    private AndroidMaintenanceIdentity? _uninstallAndroid;

    private string? _uninstallWorkRoot;

    /// <summary>
    /// 通过当前 adb 身份读取安卓 SoC 序列号。只读：不重启、不写入，也不改动设备身份本身。
    /// 读取失败只清除卸载侧的安卓绑定，保留通用设备身份。
    /// </summary>
    private async Task CaptureUninstallAndroidAsync(DeviceIdentity identity, CancellationToken token)
    {
        if (CurrentModeTag() != "uninstall" || _transport is null)
        {
            return;
        }

        try
        {
            var entry = new MaintenanceEntry(_transport.AdbPath, _transport.FastbootPath, _runner);
            _uninstallAndroid = await entry.ReadAndroidAsync(identity, token);
            SetText(
                UninstallEdlStatusText,
                "Dynamic.UninstallFlow.Maintenance.StatusAndroidCaptured");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            // 这是卸载侧的附加身份，不是通用设备身份：读不到时只清掉这里，设备本身仍保持已读取。
            _uninstallAndroid = null;
            SetText(
                UninstallEdlStatusText,
                "Dynamic.UninstallFlow.Maintenance.StatusAndroidReadFailed",
                exception.Message);
            AppendLocalizedLog(M(
                "Dynamic.UninstallFlow.Maintenance.StatusAndroidReadFailed",
                exception.Message));
        }
    }

    // ---------- 工作目录 ----------

    /// <summary>
    /// 选择工作目录：在用户选中的目录下新建本次专用的子目录，并用一个自建探针文件证明可写。
    /// 连接成功后只改变后续保存位置。
    /// </summary>
    private void OnBrowseUninstallWorkRoot(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        if (HasProtectedUninstallState)
        {
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = T("Dynamic.UninstallFlow.Maintenance.Dialog.SelectWorkRoot"),
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        string child = Path.Combine(
            dialog.FolderName,
            "armada-uninstall-" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(child);

            // 只创建并删除本程序自己的探针文件：既不写用户文件，也不依赖系统临时目录。
            string probe = Path.Combine(child, ".armada-write-probe-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
        }
        catch (Exception exception)
        {
            try
            {
                if (Directory.Exists(child))
                {
                    Directory.Delete(child, recursive: false);
                }
            }
            catch (Exception cleanupException) when (cleanupException is IOException or UnauthorizedAccessException)
            {
            }

            SetText(
                UninstallEdlStatusText,
                "Dynamic.UninstallFlow.Maintenance.WorkRootCreateFailed",
                exception.Message);
            AppendLocalizedLog(M(
                "Dynamic.UninstallFlow.Maintenance.WorkRootCreateFailed",
                exception.Message));
            return;
        }

        _uninstallWorkRoot = child;
        RenderUninstallWorkRoot();

        // 只在用户没有选择材料、且所选目录里真实存在 restore-assets 时自动填入；不搜索其他位置。
        if (string.IsNullOrWhiteSpace(StockBackupBox.Text))
        {
            var restoreAssets = Path.Combine(dialog.FolderName, "restore-assets");
            if (Directory.Exists(restoreAssets))
            {
                StockBackupBox.Text = restoreAssets;
                var count = PopulateUninstallMaterialPaths(restoreAssets);
                SetText(
                    UninstallInputNoteText,
                    count > 0
                        ? "Dynamic.UninstallFlow.Materials.Populated"
                        : "Dynamic.UninstallFlow.Materials.None",
                    count);
            }
        }

        InvalidateUninstallPreparedPlan();

        // 可见的 9008 卡片显示工作目录结论。
        var note = M("Dynamic.UninstallFlow.EdlRestore.WorkRootReady", child);
        _uninstallEdlStatus = note;
        SetText(UninstallEdlStatusText, note);

        RefreshUninstallEdlActions();
    }

    /// <summary>把实际工作子目录写进输入框与摘要；没有目录时摘要回到初始文案。</summary>
    private void RenderUninstallWorkRoot()
    {
        UninstallWorkRootBox.Text = _uninstallWorkRoot ?? string.Empty;

        if (string.IsNullOrWhiteSpace(_uninstallWorkRoot))
        {
            SetText(
                UninstallWorkRootSummaryText,
                "Dynamic.UninstallFlow.WorkRoot.SummaryInitial");
            return;
        }

        SetText(
            UninstallWorkRootSummaryText,
            "Dynamic.RawValue",
            _uninstallWorkRoot);
    }

    // ---------- 清理 ----------

    /// <summary>把界面与共享字段一起回到初始状态；不触碰用户选择的还原输入路径。</summary>
    private void ResetUninstallConnectionState()
    {
        _uninstallAndroid = null;
        _uninstallWorkRoot = null;

        RenderUninstallWorkRoot();

        if (_ready)
        {
            RefreshUninstallActions();
        }
    }
}
