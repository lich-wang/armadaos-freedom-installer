using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」第 2 步（系统备份）：用户在电脑上显式选择一个已存在的文件夹，校验随附 EDL 工具链，
/// 重新确认同一台平板后只自动进入一次 9008，再用 Core 的 <see cref="InternalInstallBackup"/> 做真实只读备份。
/// <para>
/// 界面只保存工厂实际返回的 <see cref="InternalBackupSet"/>；它只用于打开第 3 步（分配空间），
/// 不参与任何「已完成 / 已校验」的推断。备份成功后客户端、工具链与 9008 入口证据继续保留，
/// 供后续容量分配与安装复用；这里从不重置设备、不删除备份文件，也不自动重试进入 9008。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>最近一次真实返回的只读备份；null 表示没有可用于打开分配页的结果。</summary>
    private InternalBackupSet? _internalInstallBackup;

    /// <summary>本次真实 9008 会话的暂存工具链；成功后一直持有到功能切换或关闭。</summary>
    private EdlToolchain? _internalInstallEdlTools;

    /// <summary>与 <see cref="_internalInstallEdlTools"/> 配对的唯一客户端；同一个会话不重建。</summary>
    private EdlClient? _internalInstallEdlClient;

    /// <summary>唯一一次真实 <see cref="EdlEntry.EnterAsync"/> 返回的 USB 证据。</summary>
    private EdlEntryResult? _internalInstallEdlEntry;

    /// <summary>用户显式选择的电脑文件夹，只作为备份父目录；绝不回退到系统临时目录。</summary>
    private string? _internalInstallBackupParent;

    /// <summary>是否复用用户已有的只读备份目录；只由复选框与浏览按钮写入，不是任何完成证据。</summary>
    private bool _internalInstallBackupUseExisting;

    /// <summary>用户显式选择的已有备份目录；为空表示尚未选择。</summary>
    private string? _internalInstallBackupExistingDirectory;

    /// <summary>
    /// 在真正调用 <see cref="EdlEntry.EnterAsync"/> 之前立刻置位。进入 9008 的结果可能未知，
    /// 因此只要尝试过就禁止第二次自动进入，也禁止把 9008 当成安卓再检查一次。
    /// </summary>
    private bool _internalInstallEdlEntryAttempted;

    /// <summary>真实的 9008 会话或未确认的进入尝试：此时不允许切换功能或正常关闭窗口。</summary>
    private bool HasInternalInstallLiveEdlState =>
        _internalInstallEdlEntryAttempted || _internalInstallEdlEntry is not null;

    // ---------- 第 2 步入口 ----------

    /// <summary>
    /// 「浏览…」：只选择一个已存在的文件夹，不创建目录、不触发备份、不碰设备。
    /// 换目录会作废上一份备份对象（只释放只读锁），已有的 9008 会话与工具链保持不动。
    /// </summary>
    private void OnBrowseInternalInstallBackupFolder(object sender, RoutedEventArgs e)
    {
        // 共享谓词：安装/维护/卸载模式都允许选择备份父目录；保护状态拒绝。
        if (!_ready || _busy || _internalInstallOperationActive || !UsesSharedDevicePreparationPages)
        {
            return;
        }

        if (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
        {
            return;
        }

        if (IsModernUserdataUninstallMode && ProtectedModernUserdataUninstallState)
        {
            return;
        }

        // TF 卡安装受保护状态或仍持有 TF 会话时拒绝选择 / 更换备份父目录。
        if (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
        {
            return;
        }

        if (!(IsBootMaintenanceMode || IsModernUserdataUninstallMode
                ? HasBootMaintenanceBackupPrerequisite
                : HasCheckedInternalInstallDevice))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = T("Dynamic.InternalInstall.Backup.SelectFolderTitle"),
        };

        if (dialog.ShowDialog(this) != true)
        {
            // 取消或关闭对话框：现有选择与备份对象都不变。
            return;
        }

        var folder = (dialog.FolderName ?? string.Empty).Trim();
        if (folder.Length == 0 || !Directory.Exists(folder))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        ApplyInternalInstallBackupParent(folder);
    }

    /// <summary>
    /// 「已有备份」复选框：只切换模式并作废旧备份对象，不创建目录、不读设备。
    /// 被拒绝的切换会立即把勾选状态恢复成字段里的真实值。
    /// </summary>
    private void OnInternalInstallBackupUseExistingChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        var useExisting = InternalInstallBackupUseExistingCheck.IsChecked == true;
        if (useExisting == _internalInstallBackupUseExisting)
        {
            return;
        }

        if (_busy
            || _internalInstallOperationActive
            || HasInternalInstallExecutionStarted
            || !IsInternalInstallMode
            || !HasCheckedInternalInstallDevice)
        {
            SyncInternalInstallBackupModeControls();
            return;
        }

        ApplyInternalInstallBackupMode(useExisting);
    }

    /// <summary>
    /// 「浏览…」（已有备份）：只选择一个已存在的原始备份文件夹，不创建目录、不触设备、不伪造备份对象。
    /// 取消对话框不改变任何状态。
    /// </summary>
    private void OnBrowseInternalInstallBackupExistingFolder(object sender, RoutedEventArgs e)
    {
        if (!_ready
            || _busy
            || _internalInstallOperationActive
            || HasInternalInstallExecutionStarted
            || !IsInternalInstallMode)
        {
            return;
        }

        if (!HasCheckedInternalInstallDevice)
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = T("Dynamic.InternalInstall.Backup.SelectExistingFolderTitle"),
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var folder = (dialog.FolderName ?? string.Empty).Trim();
        if (folder.Length == 0 || !Directory.Exists(folder))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedExistingFolder"));
            return;
        }

        ApplyInternalInstallBackupExistingDirectory(folder);
    }

    /// <summary>
    /// 切换备份模式：只作废上一份真实备份对象与其派生结果，客户端、工具链与 9008 证据原样保留。
    /// 原始备份文件与清单从不删除，也不从路径推断任何已完成结果。
    /// </summary>
    private void ApplyInternalInstallBackupMode(bool useExisting)
    {
        _internalInstallBackupUseExisting = useExisting;

        // 备份对象一换，容量规划与旧确认对象随既有级联一起作废；原始文件保持原样。
        ReleaseInternalInstallBackupObject();
        ClearInternalInstallRetainedBackupEvidence();
        AppendLocalizedLog(
            M(
                useExisting
                    ? "Dynamic.InternalInstall.Backup.ModeChangedExisting"
                    : "Dynamic.InternalInstall.Backup.ModeChangedNew"));

        SyncInternalInstallBackupModeControls();
        RenderInternalInstallBackupDetail();
        SetInternalInstallBackupProgressIndeterminate(false);

        if (useExisting)
        {
            SetInternalInstallBackupStatus(
                string.IsNullOrWhiteSpace(_internalInstallBackupExistingDirectory)
                    ? M("Dynamic.InternalInstall.Backup.NeedExistingFolder")
                    : M(
                        "Dynamic.InternalInstall.Backup.ExistingSelected",
                        _internalInstallBackupExistingDirectory!));
        }
        else
        {
            SetInternalInstallBackupStatus(
                string.IsNullOrWhiteSpace(_internalInstallBackupParent)
                    ? M("Dynamic.InternalInstall.Backup.NeedFolder")
                    : M("Dynamic.InternalInstall.Backup.Selected", _internalInstallBackupParent!));
        }

        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 写入新的已有备份目录；与旧目录不同时只作废备份对象。原始目录只记日志，绝不改写或删除。
    /// </summary>
    private void ApplyInternalInstallBackupExistingDirectory(string folder)
    {
        if (string.Equals(folder, _internalInstallBackupExistingDirectory, StringComparison.Ordinal))
        {
            SyncInternalInstallBackupModeControls();
            return;
        }

        var previousBackup = _internalInstallBackup;
        var previousDirectory = previousBackup?.DirectoryPath;
        var previousManifest = previousBackup?.ManifestPath;
        _internalInstallBackupExistingDirectory = folder;
        ReleaseInternalInstallBackupObject();
        ClearInternalInstallRetainedBackupEvidence();

        if (previousBackup is not null)
        {
            AppendLocalizedLog(
                M(
                    "Dynamic.InternalInstall.Backup.ExistingFolderChanged",
                    folder,
                    previousDirectory ?? UnknownValue,
                    previousManifest ?? UnknownValue));
        }
        else
        {
            AppendLocalizedLog(
                M("Dynamic.InternalInstall.Backup.ExistingFolderChangedNoBackup", folder));
        }

        SyncInternalInstallBackupModeControls();
        RenderInternalInstallBackupDetail();
        SetInternalInstallBackupProgressIndeterminate(false);
        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.ExistingSelected", folder));
        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 把模式字段回写到复选框、目录框与按钮文字；语言 / 主题重绘后仍保持原有选择。
    /// 这里只改界面，不触发任何备份或设备操作。
    /// </summary>
    private void SyncInternalInstallBackupModeControls()
    {
        if (!_ready)
        {
            return;
        }

        var useExisting = _internalInstallBackupUseExisting;
        if (InternalInstallBackupUseExistingCheck.IsChecked != useExisting)
        {
            InternalInstallBackupUseExistingCheck.IsChecked = useExisting;
        }

        InternalInstallBackupExistingRow.Visibility =
            useExisting ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallBackupStartLabel.Visibility =
            useExisting ? Visibility.Collapsed : Visibility.Visible;
        InternalInstallBackupExistingLabel.Visibility =
            useExisting ? Visibility.Visible : Visibility.Collapsed;

        var existing = _internalInstallBackupExistingDirectory ?? string.Empty;
        if (!string.Equals(
            InternalInstallBackupExistingFolderBox.Text,
            existing,
            StringComparison.Ordinal))
        {
            InternalInstallBackupExistingFolderBox.Text = existing;
        }
    }

    /// <summary>
    /// 写入新的父目录；与旧目录不同时只作废备份对象与其派生结果。旧备份的文件与清单保留，
    /// 只把旧位置写进日志，绝不删除用户文件。
    /// </summary>
    private void ApplyInternalInstallBackupParent(string folder)
    {
        if (string.Equals(folder, _internalInstallBackupParent, StringComparison.Ordinal))
        {
            return;
        }

        var previousBackup = _internalInstallBackup;
        var previousDirectory = previousBackup?.DirectoryPath;
        var previousManifest = previousBackup?.ManifestPath;

        // 换父目录属于预写入输入变化：先作废旧维护准备，再释放旧备份对象。
        InvalidateBootMaintenancePreparation();

        _internalInstallBackupParent = folder;

        if (previousBackup is not null)
        {
            // 旧备份的目录与清单只写进日志，绝不删除；释放的只是它自己的只读锁。
            ReleaseInternalInstallBackupObject();
            AppendLocalizedLog(
                M(
                    "Dynamic.InternalInstall.Backup.FolderChanged",
                    folder,
                    previousDirectory ?? UnknownValue,
                    previousManifest ?? UnknownValue));
        }
        else
        {
            AppendLocalizedLog(M("Dynamic.InternalInstall.Backup.FolderChangedNoBackup", folder));
        }

        if (_ready)
        {
            InternalInstallBackupFolderBox.Text = folder;
        }

        RenderInternalInstallBackupDetail();
        SetInternalInstallBackupProgressIndeterminate(false);
        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.Selected", folder));
        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 「开始备份」：真实只读备份的唯一入口。已有 9008 会话时严格复用同一客户端与工具链；
    /// 没有会话时先加载并校验工具链、重新确认同一台平板，然后只自动进入一次 9008。
    /// </summary>
    private async void OnBackupInternalInstall(object sender, RoutedEventArgs e)
    {
        // 共享谓词：安装与维护都从这里发起（全新）备份；维护受保护状态拒绝。
        if (!_ready || _busy || _internalInstallOperationActive || !UsesSharedDevicePreparationPages)
        {
            return;
        }

        if (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
        {
            return;
        }

        if (IsModernUserdataUninstallMode && ProtectedModernUserdataUninstallState)
        {
            return;
        }

        // TF 卡安装受保护状态或仍持有 TF 会话时拒绝开始 / 作废 / 释放备份路径。
        if (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
        {
            return;
        }

        // 维护/卸载模式且已勾选「平板已在 9008」：走真实的 9008 只读备份入口，绝不读安卓。
        // TF 卡安装同构：同一历史 9008 只读备份入口。
        if (IsModernTfInstallMode && _bootMaintenanceAlreadyEdl)
        {
            await BackupBootMaintenanceEdlAsync();
            return;
        }

        if (IsModernUserdataUninstallMode && _bootMaintenanceAlreadyEdl)
        {
            await BackupBootMaintenanceEdlAsync();
            return;
        }

        if (IsBootMaintenanceMode && _bootMaintenanceAlreadyEdl)
        {
            await BackupBootMaintenanceEdlAsync();
            return;
        }

        var transport = _transport;
        // 非内部模式的默认路线没有完整检查对象：使用共享读取的真实安卓身份；
        // 内部安装（或已有完整检查）保持原样。
        var storedAndroid = IsSharedNonInternalDeviceMode && !HasCheckedInternalInstallDevice
            ? CurrentAndroidForBackup
            : _internalInstallDeviceCheck?.Android;
        var parent = _internalInstallBackupParent;

        // 共享模式只允许全新备份：复用已有备份一律内部安装模式专用；TF 卡安装保持全新。
        var useExisting = !IsSharedNonInternalDeviceMode && _internalInstallBackupUseExisting;
        var existingDirectory = _internalInstallBackupExistingDirectory;

        // 非内部模式按共享事实门槛判定；内部安装保持原有完整检查门槛。
        var hasDeviceGate = IsSharedNonInternalDeviceMode
            ? HasBootMaintenanceBackupPrerequisite
            : HasCheckedInternalInstallDevice;
        if (transport is null || storedAndroid is null || !hasDeviceGate)
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        // 共享模式（含 TF 卡安装）：备份父目录绝不能落在已选原厂 / 项目来源目录里面；来源永不作为当前目录。
        if (IsSharedNonInternalDeviceMode)
        {
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

            // 即将开始全新备份：先作废旧准备（卸载优先，再维护）。
            if (IsModernUserdataUninstallMode)
            {
                InvalidateModernUserdataUninstallPreparation();
            }

            InvalidateBootMaintenancePreparation();
        }

        if (useExisting)
        {
            // 复用的前提是一个真实存在的原始备份目录，并且工作目录绝不能落在它里面。
            if (string.IsNullOrWhiteSpace(existingDirectory) || !Directory.Exists(existingDirectory))
            {
                SetInternalInstallBackupStatus(
                    M("Dynamic.InternalInstall.Backup.NeedExistingFolder"));
                return;
            }

            if (!IsInternalInstallBackupParentOutsideExisting(parent, existingDirectory!))
            {
                SetInternalInstallBackupStatus(
                    M(
                        "Dynamic.InternalInstall.Backup.ExistingWorkRootConflict",
                        existingDirectory!));
                return;
            }
        }

        var client = _internalInstallEdlClient;
        var entry = _internalInstallEdlEntry;
        var reuse = client is not null && _internalInstallEdlTools is not null && entry is not null;

        if (!reuse && _internalInstallEdlEntryAttempted)
        {
            // 进入 9008 的结果尚未确认：不允许第二次自动进入，也不允许假装没有发生。
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.EntryUnconfirmed"));
            return;
        }

        // 信任的 EDL 配置只按实际核对到的型号选择：缺失、不完整、不支持这台平板的完整身份，
        // 或还没有随附工具归档时，一律停在安卓，不发设备命令，也不解包任何工具。
        var selectedIdentity = storedAndroid.Identity;
        var profile = EdlDeviceProfiles.FindByModel(selectedIdentity.Model);
        if (profile is null
            || !profile.IsComplete
            || !profile.SupportsIdentity(selectedIdentity)
            || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            SetInternalInstallBackupStatus(
                M(
                    "Dynamic.InternalInstall.Backup.ProfileUnavailable",
                    Placeholder(selectedIdentity.Model),
                    Placeholder(selectedIdentity.Firmware?.DisplayId)));
            return;
        }

        if (reuse && !InternalInstallEntryMatchesCheckedDevice(entry!))
        {
            // 现有会话不是这次检查确认的那台平板：停止，但保留会话与工具，等用户回到第 1 步重查。
            ReleaseInternalInstallBackupObject();
            RenderInternalInstallBackupDetail();
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.BindingChanged"));
            RefreshInternalInstallActions();
            return;
        }

        // 上一份备份对象与其派生结果先作废；客户端、工具链与 9008 证据保持原样。
        ReleaseInternalInstallBackupObject();
        ClearInternalInstallRetainedBackupEvidence();
        RenderInternalInstallBackupDetail();
        SetInternalInstallBackupProgressIndeterminate(true);
        // 正常进行中不得预告失败：这里只写「正在准备并校验」。
        SetInternalInstallBackupVerified(
            useExisting
                ? M("Dynamic.InternalInstall.Backup.ExistingRunningNote")
                : M("Dynamic.InternalInstall.Backup.RunningNote"));
        if (useExisting)
        {
            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.ExistingRunning"));
        }

        var parentPath = parent!;
        var expected = storedAndroid;
        var existingClient = client;

        _internalInstallOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;

                // 本次刚加载、尚未交给字段的工具链；只要还没进入 9008，失败时就释放它自己的暂存目录。
                EdlToolchain? pendingTools = null;

                try
                {
                    EdlClient activeClient;

                    if (existingClient is null)
                    {
                        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.PreparingTools"));

                        // 只解包所选可信配置自己的归档，绝不回退到固定资源名。
                        using var archive = Assembly.GetExecutingAssembly()
                            .GetManifestResourceStream(profile.ArchiveLogicalName!);
                        if (archive is null)
                        {
                            acceptProgress = false;
                            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.ToolsRequired"));
                            return;
                        }

                        // 暂存目录紧跟用户选择的父目录：绝不在系统临时目录或 C: 根部提前解包。
                        var workRoot = Path.Combine(parentPath, ".armada-installer-tools");
                        var loaded = await EdlToolchain.LoadAsync(archive, workRoot, token);
                        pendingTools = loaded;

                        // 加载结果必须仍然引用同一份内置配置，并且该配置确实支持这台平板的完整身份；
                        // 允许的 display id 集合由配置决定，不再比对写死的单一固件。
                        if (!ReferenceEquals(loaded.Profile, profile)
                            || !profile.SupportsIdentity(expected.Identity))
                        {
                            var loadedModel = loaded.Model;
                            var loadedBuild = loaded.AndroidBuild;

                            // 尚未切换到任何模式：释放这份刚加载、没有被使用的工具链。
                            loaded.Dispose();
                            pendingTools = null;
                            acceptProgress = false;
                            SetInternalInstallBackupStatus(
                                M(
                                    "Dynamic.InternalInstall.Backup.ToolchainMismatch",
                                    loadedModel,
                                    loadedBuild));
                            return;
                        }

                        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.Reproving"));

                        // 模式切换前重新读取真实安卓身份与 SoC 序列号，并与第 1 步的结果逐项比对。
                        var freshIdentity = await transport.ReadAdbIdentityAsync(
                            expected.Identity.Serial,
                            token);
                        var maintenance = new MaintenanceEntry(
                            transport.AdbPath,
                            transport.FastbootPath,
                            _runner);
                        var freshAndroid = await maintenance.ReadAndroidAsync(freshIdentity, token);

                        // 除与原检查逐项一致外，重新读到的完整身份也必须仍被所选可信配置支持。
                        if (!InternalInstallAndroidMatches(expected, freshAndroid)
                            || !profile.SupportsIdentity(freshAndroid.Identity))
                        {
                            loaded.Dispose();
                            pendingTools = null;
                            InvalidateInternalInstallCheckFromMismatch();
                            SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
                            acceptProgress = false;
                            return;
                        }

                        // 已有采样时才在进入 9008 之前刷新一次；没有采样就不凭空补一个。
                        if (_internalInstallPower is not null)
                        {
                            _internalInstallPower = await CaptureInternalInstallPowerAsync(
                                transport.AdbPath,
                                freshIdentity.Serial,
                                token);
                            RenderInternalInstallPower();
                        }

                        // 工具链先落到字段：进入 9008 之后即使失败也保留现场供诊断。
                        _internalInstallEdlTools = loaded;
                        pendingTools = null;

                        _internalInstallEdlEntryAttempted = true;
                        SetInternalInstallBackupStatus(M("Dynamic.InternalInstall.Backup.EnteringEdl"));

                        // 整个流程只会在这里真实进入一次 9008，不自动重试、不回退手动 Fastboot；
                        // 显式传入刚加载并核对过的可信配置，绝不使用默认 G4 重载或自行构造配置。
                        var entered = await new EdlEntry(
                                transport.AdbPath,
                                _runner,
                                new WindowsEdlEndpointDiscovery())
                            .EnterAsync(freshAndroid, loaded.Profile, token);

                        _internalInstallEdlEntry = entered;
                        activeClient = new EdlClient(
                            loaded,
                            entered,
                            _runner,
                            new WindowsEdlEndpointDiscovery());
                        _internalInstallEdlClient = activeClient;
                    }
                    else
                    {
                        // 复用同一会话：不重新加载工具链、不再走 adb、也不再进入 9008。
                        activeClient = existingClient;
                    }

                    SetInternalInstallBackupProgressIndeterminate(true);
                    SetInternalInstallBackupStatus(
                        useExisting
                            ? M("Dynamic.InternalInstall.Backup.ExistingRunning")
                            : M("Dynamic.InternalInstall.Backup.Reading"));

                    // 非内部共享路线复用已有会话时，客户端可能还没有首次 Sahara 证明：
                    // 在真正的读取之前只读探测一次，失败照常走异常处理。
                    if (IsSharedNonInternalDeviceMode
                        && activeClient is { } sharedProbeClient
                        && !sharedProbeClient.HasInitialSaharaProof)
                    {
                        await sharedProbeClient.ProbeAsync(0, true, token);
                    }

                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        // 终态一旦写出，迟到的进度回调不允许再覆盖它。
                        if (!acceptProgress)
                        {
                            return;
                        }

                        RenderInternalInstallBackupProgress(report);
                    });

                    // 唯一一次真实调用：已有模式只校验原始目录，正常模式才在父目录下新建子目录。
                    var set = useExisting
                        ? await InternalInstallBackup.OpenExistingAsync(
                            activeClient,
                            existingDirectory!,
                            progress,
                            token)
                        : await InternalInstallBackup.CreateAsync(
                            activeClient,
                            parentPath,
                            progress,
                            token);

                    acceptProgress = false;

                    // 非内部共享路线：备份真实返回后、提交之前，先从备份目录读取真实历史身份。
                    // 源备份租约先保存在局部；读取失败时释放它并按失败处理，文件 / 客户端 / entry / 工具全部保留。
                    if (IsSharedNonInternalDeviceMode && !useExisting)
                    {
                        var pendingSet = set;
                        try
                        {
                            var sharedHistory = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(
                                pendingSet.DirectoryPath,
                                token);

                            // 读取成功才提交真实备份与真实历史；这是当前清单锚点，不是当前 OS / 锁态声明。
                            _internalInstallBackup = pendingSet;
                            _bootMaintenanceHistoricalIdentity = sharedHistory;
                        }
                        catch
                        {
                            pendingSet.Dispose();
                            throw;
                        }
                    }
                    else
                    {
                        _internalInstallBackup = set;
                    }

                    RenderInternalInstallBackupSuccess(useExisting ? set : _internalInstallBackup!, useExisting);
                    RefreshInternalInstallActions();
                }
                catch (OperationCanceledException)
                {
                    acceptProgress = false;
                    _internalInstallBackup = null;
                    StopInternalInstallBackupProgress();
                    // 已有模式从不声称新建了子目录；只说明校验取消、原始目录保持原样。
                    SetInternalInstallBackupStatus(
                        useExisting
                            ? M(
                                "Dynamic.InternalInstall.Backup.ExistingCancelled",
                                existingDirectory!)
                            : M("Dynamic.InternalInstall.Backup.Cancelled", parentPath));
                    SetInternalInstallBackupVerified(
                        useExisting
                            ? M("Dynamic.InternalInstall.Backup.ExistingFailedNote")
                            : M("Dynamic.InternalInstall.Backup.FailedNote"));
                    RenderInternalInstallBackupDetail();
                    throw;
                }
                catch (Exception exception) when (exception is IOException
                    or UnauthorizedAccessException
                    or InvalidDataException
                    or InvalidOperationException
                    or TimeoutException
                    or ArgumentException
                    or NotSupportedException
                    or NotImplementedException)
                {
                    acceptProgress = false;
                    _internalInstallBackup = null;

                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message)
                        ? UnknownValue
                        : exception.Message;
                    var failure = useExisting
                        ? M(
                            "Dynamic.InternalInstall.Backup.ExistingFailed",
                            diagnostic,
                            existingDirectory!)
                        : M(
                            "Dynamic.InternalInstall.Backup.Failed",
                            diagnostic,
                            parentPath);

                    StopInternalInstallBackupProgress();
                    SetInternalInstallBackupStatus(failure);
                    SetInternalInstallBackupVerified(
                        useExisting
                            ? M("Dynamic.InternalInstall.Backup.ExistingFailedNote")
                            : M("Dynamic.InternalInstall.Backup.FailedNote"));
                    RenderInternalInstallBackupDetail();
                    AppendLocalizedLog(failure);
                }
                finally
                {
                    // 本次工作已结束却没有留下完整备份（含工具链 / 身份校验的提前返回）：此刻才把运行提示换成失败提示；
                    // 成功返回的备份已写入 KeepEdl，绝不覆盖。
                    if (_internalInstallBackup is null)
                    {
                        SetInternalInstallBackupVerified(
                            useExisting
                                ? M("Dynamic.InternalInstall.Backup.ExistingFailedNote")
                                : M("Dynamic.InternalInstall.Backup.FailedNote"));
                    }

                    // 从未用于任何设备命令的暂存工具链在失败后释放；已经进入 9008 的那一份由字段保留。
                    if (pendingTools is not null
                        && !ReferenceEquals(pendingTools, _internalInstallEdlTools))
                    {
                        try
                        {
                            pendingTools.Dispose();
                        }
                        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                        {
                        }
                    }
                }
            });
        }
        finally
        {
            // 只有客户端命令确实返回之后才解除保护；进入 9008 的字段与工具链继续保留。
            _internalInstallOperationActive = false;
            RefreshInternalInstallActions();
            UpdateSummary();
        }
    }

    // ---------- 结果渲染 ----------

    /// <summary>按 Core 的四个稳定阶段与真实计数绘制进度；总量未知时只显示「正在确认」，不写 0%。</summary>
    private void RenderInternalInstallBackupProgress(InternalBackupProgress report)
    {
        if (!_ready)
        {
            return;
        }

        var stage = M(InternalInstallBackupStageKey(report.Stage));
        var detail = report.Role is null
            ? stage
            : M("Dynamic.InternalInstall.Backup.Progress.Role", stage, report.Role);

        if (report.TotalBytes <= 0 && report.TotalFiles <= 0)
        {
            // 总数尚未确定：进度条保持不确定状态，绝不填一个编造的百分比。
            InternalInstallBackupProgressBar.IsIndeterminate = true;
            InternalInstallBackupProgressBar.Value = 0;
            SetInternalInstallBackupStatus(
                M("Dynamic.InternalInstall.Backup.Progress.Discovering", detail));
            return;
        }

        var ratio = report.TotalBytes > 0
            ? (double)report.CompletedBytes / report.TotalBytes
            : (double)report.CompletedFiles / report.TotalFiles;

        InternalInstallBackupProgressBar.IsIndeterminate = false;
        InternalInstallBackupProgressBar.Value = Math.Clamp(ratio * 100d, 0d, 100d);

        SetInternalInstallBackupStatus(
            M(
                "Dynamic.InternalInstall.Backup.Progress.Counters",
                detail,
                report.CompletedFiles,
                report.TotalFiles,
                FormatBytes(report.CompletedBytes),
                FormatBytes(report.TotalBytes)));
    }

    private void RenderInternalInstallBackupSuccess(InternalBackupSet set, bool useExisting)
    {
        InternalInstallBackupProgressBar.IsIndeterminate = false;
        InternalInstallBackupProgressBar.Value = 100;

        // 复用模式明确写「已有备份已校验」，其余详情仍只来自真实返回的集合。
        SetInternalInstallBackupStatus(
            useExisting
                ? M("Dynamic.InternalInstall.Backup.ExistingSucceeded", set.Files.Count)
                : M("Dynamic.InternalInstall.Backup.Succeeded", set.Files.Count));
        SetInternalInstallBackupVerified(M("Dynamic.InternalInstall.Backup.KeepEdl"));
        RenderInternalInstallBackupDetail();
        AppendLocalizedLog(
            M(
                useExisting
                    ? "Dynamic.InternalInstall.Backup.ExistingSucceededLog"
                    : "Dynamic.InternalInstall.Backup.SucceededLog",
                set.DirectoryPath,
                set.ManifestSha256));
    }

    /// <summary>
    /// 备份位置详情：目录、清单与清单摘要全部来自实际返回的备份对象；没有结果时写未知，
    /// 不推测路径、不拼一个假的摘要。
    /// </summary>
    private void RenderInternalInstallBackupDetail()
    {
        if (!_ready)
        {
            return;
        }

        // 每次重绘都按字段回写模式控件，语言 / 主题切换不会丢掉用户已有的选择。
        SyncInternalInstallBackupModeControls();

        SetText(InternalInstallBackupDetailTitle, "Dynamic.InternalInstall.Backup.DetailTitle");
        SetText(InternalInstallBackupFolderLabel, "Dynamic.InternalInstall.Backup.DetailDirectoryLabel");
        SetText(InternalInstallBackupManifestLabel, "Dynamic.InternalInstall.Backup.DetailManifestLabel");
        SetText(
            InternalInstallBackupManifestHashLabel,
            "Dynamic.InternalInstall.Backup.DetailManifestHashLabel");

        // 退出维护后只读锁会释放，但已确认的目录、清单与摘要作为证据继续显示，不丢字符串。
        var set = _internalInstallBackup;
        SetText(
            InternalInstallBackupDirectoryText,
            "Dynamic.RawValue",
            set?.DirectoryPath ?? _internalInstallRetainedBackupDirectory ?? UnknownValue);
        SetText(
            InternalInstallBackupManifestText,
            "Dynamic.RawValue",
            set?.ManifestPath ?? _internalInstallRetainedBackupManifest ?? UnknownValue);
        SetText(
            InternalInstallBackupManifestHashText,
            "Dynamic.RawValue",
            set?.ManifestSha256 ?? _internalInstallRetainedBackupManifestHash ?? UnknownValue);
    }

    private void SetInternalInstallBackupStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallBackupStatusText, message);
    }

    private void SetInternalInstallBackupVerified(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallBackupVerifiedText, message);
    }

    private void SetInternalInstallBackupProgressIndeterminate(bool indeterminate, double value = 0d)
    {
        if (!_ready)
        {
            return;
        }

        InternalInstallBackupProgressBar.IsIndeterminate = indeterminate;
        InternalInstallBackupProgressBar.Value = indeterminate ? 0d : Math.Clamp(value, 0d, 100d);
    }

    /// <summary>停止不确定动画，但保留已经实际观察到的比例；失败时绝不把进度补到满格。</summary>
    private void StopInternalInstallBackupProgress()
    {
        if (!_ready)
        {
            return;
        }

        InternalInstallBackupProgressBar.IsIndeterminate = false;
    }

    /// <summary>Core 的四个稳定阶段各自对应的显示文案；未知阶段只写通用说明，不猜进度含义。</summary>
    private static string InternalInstallBackupStageKey(string stage) => stage switch
    {
        "reading-gpt" => "Dynamic.InternalInstall.Backup.Progress.ReadingGpt",
        "reading-partition" => "Dynamic.InternalInstall.Backup.Progress.ReadingPartition",
        "verifying" => "Dynamic.InternalInstall.Backup.Progress.Verifying",
        "complete" => "Dynamic.InternalInstall.Backup.Progress.Complete",
        _ => "Dynamic.InternalInstall.Backup.Progress.Working",
    };

    /// <summary>
    /// 复用已有备份时的工作目录约束：完整路径规范化后，父目录既不能等于原始备份目录，
    /// 也不能位于它内部（Windows 大小写不敏感，并按分隔符边界比较）。同级或上级父目录允许。
    /// </summary>
    private static bool IsInternalInstallBackupParentOutsideExisting(
        string parent,
        string existingDirectory)
    {
        try
        {
            var normalizedParent = NormalizeInternalInstallDirectoryPath(parent);
            var normalizedExisting = NormalizeInternalInstallDirectoryPath(existingDirectory);
            if (normalizedParent.Length == 0 || normalizedExisting.Length == 0)
            {
                return false;
            }

            if (string.Equals(
                normalizedParent,
                normalizedExisting,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var existingPrefix = normalizedExisting.EndsWith(
                Path.DirectorySeparatorChar.ToString(),
                StringComparison.Ordinal)
                ? normalizedExisting
                : normalizedExisting + Path.DirectorySeparatorChar;

            return !normalizedParent.StartsWith(
                existingPrefix,
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException
            or NotSupportedException
            or IOException)
        {
            // 路径无法规范化时一律拒绝复用，由调用方显示同一个本地化原因。
            return false;
        }
    }

    private static string NormalizeInternalInstallDirectoryPath(string path)
    {
        var full = Path.GetFullPath(path);
        return full.Length > 3
            ? full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : full;
    }

    // ---------- 证据比对与失效 ----------

    /// <summary>重新读取到的安卓身份必须与第 1 步完全一致，才允许切换模式。</summary>
    private static bool InternalInstallAndroidMatches(
        AndroidMaintenanceIdentity expected,
        AndroidMaintenanceIdentity actual)
    {
        var left = expected.Identity;
        var right = actual.Identity;
        if (left is null || right is null)
        {
            return false;
        }

        return string.Equals(left.Model, right.Model, StringComparison.OrdinalIgnoreCase)
            && string.Equals(left.Serial, right.Serial, StringComparison.Ordinal)
            && string.Equals(
                left.Firmware?.DisplayId,
                right.Firmware?.DisplayId,
                StringComparison.Ordinal)
            && string.Equals(expected.SocSerial, actual.SocSerial, StringComparison.Ordinal);
    }

    /// <summary>
    /// 现有客户端的绑定必须仍是本次确认（完整检查或共享读取事实）的那台平板；
    /// Core 会在每条命令前重新枚举实际端点。
    /// </summary>
    private bool InternalInstallEntryMatchesCheckedDevice(EdlEntryResult entry)
    {
        var expected = CurrentAndroidForBackup;
        if (expected is null)
        {
            return false;
        }

        return InternalInstallAndroidMatches(expected, entry.AndroidIdentity);
    }

    /// <summary>
    /// 身份不一致时直接作废检查结论与派生界面（不经过会因为「操作进行中」提前返回的清理入口），
    /// 并清掉备份门槛；绝不改写用户已选的目录，也不碰设备。
    /// </summary>
    private void InvalidateInternalInstallCheckFromMismatch()
    {
        _internalInstallDeviceCheck = null;
        _internalInstallPower = null;
        // 身份不一致时共享读取事实同源作废。
        ClearSharedAndroidIdentity();
        ReleaseInternalInstallBackupObject();
        RenderInternalInstallCheckPlaceholders();
        SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
        RenderInternalInstallBackupDetail();
        StopInternalInstallBackupProgress();
        RefreshInternalInstallActions();
    }

    /// <summary>释放备份对象只持有的只读锁；备份文件、清单与元数据一律保留。</summary>
    private void ReleaseInternalInstallBackupObject()
    {
        // 卸载模式优先：方案对象先于备份租约作废（helper 自带保护状态守卫）。
        if (IsModernUserdataUninstallMode)
        {
            InvalidateModernUserdataUninstallPreparation();
        }

        // 备份对象一换，容量规划与旧确认对象都必须作废；有效的系统包可以留到同一型号的下一次备份。
        InvalidateInternalInstallAllocation(clearPackage: false);

        var backup = _internalInstallBackup;
        _internalInstallBackup = null;
        if (backup is null)
        {
            return;
        }

        try
        {
            backup.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ---------- 离开保护与生命周期 ----------

    /// <summary>
    /// 最近一次已校验备份的位置、清单、摘要与文件数。退出维护后只读锁会被释放，
    /// 这些字符串继续用于显示证据；从不清空用户文件，也不参与任何安装门槛。
    /// </summary>
    private string? _internalInstallRetainedBackupDirectory;

    private string? _internalInstallRetainedBackupManifest;

    private string? _internalInstallRetainedBackupManifestHash;

    private int _internalInstallRetainedBackupFileCount;

    /// <summary>把当前真实备份对象的位置与摘要复制成显示证据；不保留任何只读句柄。</summary>
    private void RetainInternalInstallBackupEvidence()
    {
        var set = _internalInstallBackup;
        if (set is null)
        {
            return;
        }

        _internalInstallRetainedBackupDirectory = set.DirectoryPath;
        _internalInstallRetainedBackupManifest = set.ManifestPath;
        _internalInstallRetainedBackupManifestHash = set.ManifestSha256;
        _internalInstallRetainedBackupFileCount = set.Files.Count;
    }

    /// <summary>新一次真实备份开始前清掉上一份显示证据，避免旧目录配在新失败状态旁边。</summary>
    private void ClearInternalInstallRetainedBackupEvidence()
    {
        _internalInstallRetainedBackupDirectory = null;
        _internalInstallRetainedBackupManifest = null;
        _internalInstallRetainedBackupManifestHash = null;
        _internalInstallRetainedBackupFileCount = 0;
    }

    /// <summary>
    /// 只在真实安卓返回已核对通过后调用：保留备份证据并把第 2 步状态改成
    /// 「备份仍在电脑上、维护连接已结束」，绝不声称安卓数据已恢复或安装已完成。
    /// </summary>
    private void RenderInternalInstallBackupAfterVerifiedExit()
    {
        RetainInternalInstallBackupEvidence();

        if (!_ready || _internalInstallRetainedBackupDirectory is null)
        {
            return;
        }

        SetInternalInstallBackupStatus(
            M(
                "Dynamic.InternalInstall.Exit.BackupRetained",
                _internalInstallRetainedBackupDirectory,
                _internalInstallRetainedBackupFileCount,
                _internalInstallRetainedBackupManifestHash ?? UnknownValue));
        SetInternalInstallBackupVerified(M("Dynamic.InternalInstall.Exit.BackupRetainedNote"));
    }

    /// <summary>
    /// 关闭窗口时释放本流程拥有的备份只读锁与暂存工具链。调用方必须已确认没有进行中的操作、
    /// 也没有仍然有效的 9008 会话；这里不删除备份文件，也不处置 runner 或端点发现对象。
    /// </summary>
    private void DisposeInternalInstallResources()
    {
        // 先释放本流程自己生成的方案对象与解包目录，再释放备份只读锁与暂存工具链；
        // 所有文件都保留，这里从不删除备份、方案输出或用户原始包。
        ReleaseInternalInstallArtifacts();
        ReleaseInternalInstallPackage();
        ReleaseInternalInstallBackupObject();

        var tools = _internalInstallEdlTools;
        _internalInstallEdlTools = null;
        _internalInstallEdlClient = null;
        _internalInstallEdlEntry = null;
        _internalInstallEdlEntryAttempted = false;

        if (tools is null)
        {
            return;
        }

        try
        {
            // 只删除工具链自己的 GUID 暂存目录；父目录与备份数据保持原样。
            tools.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
