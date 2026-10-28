using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 维护模式「平板已在 9008」路线：用历史备份中的保存身份核对当前 9008 连接，只读、不进安卓。
/// 历史身份只用于绑定当前 EDL，绝不代表当前安卓固件 / 锁定状态，也不代表任何安装已就绪。
/// </summary>
public partial class MainWindow
{
    /// <summary>只读核对成功后保存的历史身份；证明只来自真实返回值，绝不手工构造。</summary>
    private BootMaintenanceHistoricalIdentity? _bootMaintenanceHistoricalIdentity;

    /// <summary>
    /// 进入备份相关步骤的共享正面证据：真实安卓检查通过（安装路径），
    /// 或维护 / 卸载模式下已建立真实 9008 只读会话（历史身份已绑定、首次 Sahara 已证明、
    /// entry 与工具齐备）。9008 路线不再要求勾选框；勾选只是用户进入路线的偏好。
    /// </summary>
    private bool HasBootMaintenanceDeviceProof =>
        HasCheckedInternalInstallDevice
        || (IsSharedNonInternalDeviceMode
            && _bootMaintenanceHistoricalIdentity is not null
            && _internalInstallEdlClient is { } client
            && client.HasInitialSaharaProof
            && _internalInstallEdlEntry is not null
            && _internalInstallEdlTools is not null);

    /// <summary>
    /// 「平板已在 9008」路线的只读核对：从历史备份读取保存身份，加载该配置自己的工具归档，
    /// 用 WaitForPresentAsync（不发 adb 命令）等待当前 9008 端点并做首次 Sahara 探测。
    /// 不读安卓、不重启、不写入、不推断锁定状态、不自动重试。
    /// </summary>
    private async Task CheckBootMaintenanceEdlAsync()
    {
        if (!_ready
            || !(IsBootMaintenanceMode || IsModernUserdataUninstallMode || IsModernTfInstallMode)
            || !_bootMaintenanceAlreadyEdl
            || _busy
            || _internalInstallOperationActive
            || ProtectedModernTfInstallState
            || HasAnyPreparedModernTfInstall
            || (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
            || (IsModernUserdataUninstallMode && ProtectedModernUserdataUninstallState)
            || HasInternalInstallLiveEdlState)
        {
            return;
        }

        var transport = _transport;
        if (transport is null || _runner is null)
        {
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.ToolsRequired"));
            return;
        }

        // 历史目录来自用户已选的原厂来源；必须有真实存在的目录作为候选历史，不在此断言载荷资格。
        var selectedDirectory = _bootMaintenanceOriginalDirectory;
        if (string.IsNullOrWhiteSpace(selectedDirectory) || !Directory.Exists(selectedDirectory))
        {
            SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.NeedHistory"));
            return;
        }

        // 尚无有效备份父目录时先选择：必须是已存在的独立目录，且不在来源目录里。
        var parent = _internalInstallBackupParent;
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = T("Dynamic.InternalInstall.Backup.SelectFolderTitle"),
            };

            if (dialog.ShowDialog(this) != true)
            {
                // 取消：一次操作都没发生。
                return;
            }

            var folder = (dialog.FolderName ?? string.Empty).Trim();
            if (folder.Length == 0 || !Directory.Exists(folder))
            {
                SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Backup.NeedFolder"));
                return;
            }

            ApplyInternalInstallBackupParent(folder);
            parent = folder;
        }

        // 无论新选还是沿用已有父目录，都必须在 ResetCheck / 临时工具解包之前落在来源目录之外。
        foreach (var source in new[] { _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source)
                && !IsInternalInstallBackupParentOutsideExisting(parent!, source!))
            {
                SetInternalInstallCheckStatus(
                    M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        // 空闲时清掉上一轮安卓检查结论；已有 9008 会话与工具链不受影响，绝不丢弃真实现场。
        ResetInternalInstallCheckState(clearSelection: false);
        _bootMaintenanceHistoricalIdentity = null;
        _internalInstallOperationActive = true;

        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.Checking"));

                    var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(
                        selectedDirectory!,
                        token);

                    var profile = history.Profile;
                    if (!profile.IsComplete
                        || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName)
                        || !profile.SupportsIdentity(history.Identity.Identity))
                    {
                        SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                        return;
                    }

                    // 只解包所选配置自己的归档，绝不回退固定资源名或固定配置。
                    using var archive = Assembly.GetExecutingAssembly()
                        .GetManifestResourceStream(profile.ArchiveLogicalName!);
                    if (archive is null)
                    {
                        SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.ToolsRequired"));
                        return;
                    }

                    var workRoot = Path.Combine(parent!, ".armada-installer-tools");
                    var pendingTools = await EdlToolchain.LoadAsync(archive, workRoot, token);
                    EdlToolchain? ownedTools = pendingTools;
                    try
                    {
                        if (!ReferenceEquals(pendingTools.Profile, profile))
                        {
                            SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                            return;
                        }

                        // WaitForPresentAsync 自己不发任何 adb 命令：只等待当前 9008 端点出现并比对保存身份。
                        SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Edl.Checking"));
                        var entry = await new EdlEntry(
                                transport.AdbPath,
                                _runner,
                                new WindowsEdlEndpointDiscovery())
                            .WaitForPresentAsync(history.Identity, profile, token);

                        // 只有真实端点结果存在时才接管工具链并记录进入尝试；此前失败由 finally 清理 pendingTools。
                        _internalInstallEdlTools = pendingTools;
                        ownedTools = null;
                        pendingTools = null;
                        _internalInstallEdlEntryAttempted = true;
                        _internalInstallEdlEntry = entry;

                        var client = new EdlClient(
                            _internalInstallEdlTools,
                            entry,
                            _runner,
                            new WindowsEdlEndpointDiscovery());
                        _internalInstallEdlClient = client;

                        await client.ProbeAsync(0, true, token);

                        // 全部只读核对成功后才绑定历史身份；展示的是保存信息，不是当前安卓状态。
                        _bootMaintenanceHistoricalIdentity = history;
                        SetInternalInstallCheckStatus(
                            M(
                                "Dynamic.BootMaintenance.Edl.HistoricalBound",
                                history.Model,
                                history.AndroidSerial,
                                history.HistoricalFirmware.DisplayId));
                    }
                    finally
                    {
                        // 只释放本轮自己 pending 的工具链；已接管的共享现场（client/entry/tools）绝不覆盖或释放。
                        ownedTools?.Dispose();
                    }
                }
                catch (OperationCanceledException ex)
                {
                    SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
                }
                catch (Exception ex)
                {
                    SetInternalInstallCheckStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                }
            });
        }
        finally
        {
            _internalInstallOperationActive = false;
            RenderInternalInstallBackupDetail();
            RefreshInternalInstallActions();
            RefreshBootMaintenanceSharedActions();
        }
    }

    /// <summary>
    /// 「平板已在 9008」路线的全新只读备份：严格复用只读核对建立的同一客户端 / 工具链 / entry，
    /// 只调用 InternalInstallBackup.CreateAsync，绝不 OpenExisting，成功前不保存任何备份集合。
    /// </summary>
    private async Task BackupBootMaintenanceEdlAsync()
    {
        if (!_ready
            || _busy
            || _internalInstallOperationActive
            || !(IsBootMaintenanceMode || IsModernUserdataUninstallMode || IsModernTfInstallMode)
            || !_bootMaintenanceAlreadyEdl
            || !HasBootMaintenanceDeviceProof
            || ProtectedModernTfInstallState
            || HasAnyPreparedModernTfInstall
            || (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
            || (IsModernUserdataUninstallMode && ProtectedModernUserdataUninstallState))
        {
            return;
        }

        var client = _internalInstallEdlClient;
        var tools = _internalInstallEdlTools;
        var entry = _internalInstallEdlEntry;
        var parent = _internalInstallBackupParent;

        if (entry is null || client is null || tools is null
            || string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        // 备份父目录绝不能落在历史目录 / 原厂 / 项目来源目录里面。
        foreach (var source in new[] { _bootMaintenanceHistoricalIdentity?.DirectoryPath, _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source)
                && !IsInternalInstallBackupParentOutsideExisting(parent!, source!))
            {
                SetInternalInstallBackupStatus(
                    M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        // 卸载模式：全新备份开始前先作废卸载准备（与维护同构）。
        if (IsModernUserdataUninstallMode)
        {
            InvalidateModernUserdataUninstallPreparation();
        }

        InvalidateBootMaintenancePreparation();

        // 上一份备份对象先释放；客户端、工具链、entry 与端点文件保持原样。
        ReleaseInternalInstallBackupObject();
        ClearInternalInstallRetainedBackupEvidence();
        RenderInternalInstallBackupDetail();

        _internalInstallOperationActive = true;
        SetInternalInstallBackupProgressIndeterminate(true);
        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.RunningNote"));

        var parentPath = parent!;
        var activeClient = client;

        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.Reading"));

                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderInternalInstallBackupProgress(report);
                        }
                    });

                    // 唯一一次真实调用：维护模式只做全新备份，绝不 OpenExisting。
                    var set = await InternalInstallBackup.CreateAsync(
                        activeClient,
                        parentPath,
                        progress,
                        token);

                    _internalInstallBackup = set;
                    RenderInternalInstallBackupSuccess(set, useExisting: false);
                }
                catch (OperationCanceledException ex)
                {
                    _internalInstallBackup = null;
                    StopInternalInstallBackupProgress();
                    SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendLocalizedLog(M("Dynamic.RawValue", ex.Message));
                }
                catch (Exception ex)
                {
                    _internalInstallBackup = null;
                    StopInternalInstallBackupProgress();
                    SetInternalInstallBackupStatus(M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendLocalizedLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                }
                finally
                {
                    // 终态后迟到的进度回调一律忽略；只认真实返回的备份集合。
                    acceptProgress = false;
                }
            });
        }
        finally
        {
            SetInternalInstallBackupProgressIndeterminate(false);
            _internalInstallOperationActive = false;
            RenderInternalInstallBackupDetail();
            RefreshInternalInstallActions();
            RefreshBootMaintenanceSharedActions();
        }
    }
}
