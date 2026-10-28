using System;
using System.IO;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载（现代四步向导）控制器层：字段、模式谓词、门槛、作废与真实只读准备。
/// <para>
/// 六种功能中的 <c>uninstall</c> 不再走旧三页向导，而是复用共享四步设备准备页：
/// 第 0 步真实安卓自动检查（或历史 9008 只读核对），第 1 步全新只读备份，
/// 第 2 步选择原始预安装 GPT 备份并真实准备恢复方案，第 3 步展示真实计算结果与风险。
/// 本文件绝不写入设备、不创建执行后端之外的可写对象；执行与收尾属于紧随其后的 U2 票。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>真实工厂实际返回的卸载后端；null 表示还没有可执行（U2）的准备结果。</summary>
    private EdlUninstallBackend? _userdataUninstallBackend;

    /// <summary>真实打开的原始预安装 GPT 备份；只读，保持到方案作废或 U2 执行。</summary>
    private UninstallOriginalGptBackup? _userdataUninstallOriginal;

    /// <summary>真实准备完成的默认安卓引导方案；保持到方案作废或 U2 执行。</summary>
    private CurrentBootMenuPlan? _userdataUninstallMenu;

    /// <summary>本次卸载准备操作是否进行中；与维护同名字段同构，只参与保护判定。</summary>
    private bool _userdataUninstallOperationActive;

    /// <summary>最近一次真实准备失败的原始诊断；成功或作废时清空。</summary>
    private string? _userdataUninstallError;

    /// <summary>六种功能中的现代卸载模式；绝不动维护/安装的谓词。</summary>
    private bool IsModernUserdataUninstallMode =>
        string.Equals(CurrentModeTag(), "uninstall", StringComparison.Ordinal);

    /// <summary>
    /// 卸载自身的持久保护状态：U1 的准备操作进行中，加上 U2 的未解决执行状态。
    /// </summary>
    private bool ProtectedModernUserdataUninstallState =>
        _userdataUninstallOperationActive || HasUnresolvedModernUserdataUninstallState;

    /// <summary>
    /// 四步向导唯一前进门槛：第 0 步空闲即可；第 1 步要真实设备证明；
    /// 第 2 步要真实设备证明与全新备份；第 3 步只认真实工厂返回的后端、方案与原始备份。
    /// </summary>
    private bool CanEnterModernUserdataUninstallStep(int step)
    {
        if (!_ready || !IsModernUserdataUninstallMode || _busy || _userdataUninstallOperationActive)
        {
            return false;
        }

        // 已完成或未解决：只允许停留在当前第 3 步确认现场，不再返回任何输入页。
        if ((_userdataUninstallCompleted || HasUnresolvedModernUserdataUninstallState)
            && step != _internalInstallStep)
        {
            return false;
        }

        return step switch
        {
            0 => true,
            // 进入备份页只要求事实门槛；准备（第 2 步）与执行仍走完整设备证明。
            1 => HasBootMaintenanceBackupPrerequisite,
            2 => HasBootMaintenanceDeviceProof && _internalInstallBackup is not null,
            3 => _userdataUninstallBackend is not null
                && _userdataUninstallMenu is not null
                && _userdataUninstallOriginal is not null,
            _ => false,
        };
    }

    // ---------- 作废与复位 ----------

    /// <summary>
    /// 作废当前卸载准备：先释放后端，再释放方案，最后释放原始备份（只释放自己的租约/候选 GUID）。
    /// 绝不释放 fresh 备份、客户端，也绝不删除用户备份文件。
    /// </summary>
    private void InvalidateModernUserdataUninstallPreparation()
    {
        if (ProtectedModernUserdataUninstallState)
        {
            return;
        }

        // 受保护检查通过、确认要释放自有对象时，一并清掉存储的退出状态。
        _userdataUninstallExitStatus = null;

        if (_userdataUninstallBackend is { } backend)
        {
            backend.Dispose();
            _userdataUninstallBackend = null;
        }

        if (_userdataUninstallMenu is { } menu)
        {
            menu.Dispose();
            _userdataUninstallMenu = null;
        }

        if (_userdataUninstallOriginal is { } original)
        {
            original.Dispose();
            _userdataUninstallOriginal = null;
        }

        if (_ready)
        {
            BootMaintenanceRiskCheck.IsChecked = false;
        }

        _userdataUninstallError = null;

        // 未完成（受保护检查已证明无未解决现场）时：清掉真实执行标记，
        // 让真实预检失败可以返回、重新准备并执行一次新的真实后端；复位痕迹在仍有会话时保留。
        if (!_userdataUninstallCompleted)
        {
            _userdataUninstallLastResult = null;
            _userdataUninstallExecuteAttempted = false;
            _userdataUninstallExecutionUnknown = false;
            _userdataUninstallDisplayStage = null;
        }
    }

    /// <summary>
    /// 安全复位卸载向导到第 0 步：只作废准备，保留已选共享路径（历史目录仍可服务其他模式）。
    /// </summary>
    private void SafeResetModernUserdataUninstallState()
    {
        if (ProtectedModernUserdataUninstallState)
        {
            return;
        }

        // 只在没有真实 9008 会话时清空 U2 运行期字段；保留已选原始备份声明（路径仍可服务其他模式）。
        if (!HasInternalInstallLiveEdlState)
        {
            _userdataUninstallLastResult = null;
            _userdataUninstallExecuteAttempted = false;
            _userdataUninstallExecutionUnknown = false;
            _userdataUninstallResetAttempted = false;
            _userdataUninstallResetAcked = false;
            _userdataUninstallCompleted = false;
            _userdataUninstallCloseApproved = false;
            _userdataUninstallCompletionToastShown = false;
            _userdataUninstallDisplayStage = null;
            _userdataUninstallExitStatus = null;
        }

        InvalidateModernUserdataUninstallPreparation();
        _internalInstallStep = 0;

        // 复位后只作废旧的真实检查 UI 证明；没有活动的安装 EDL 现场时才允许，绝不发设备 I/O，
        // 也绝不从这里递归触发安全复位或伪造就绪；未知阶段原样保留。
        if (!HasInternalInstallLiveEdlState)
        {
            ResetInternalInstallCheckState(false);
        }
    }

    // ---------- 真实只读准备 ----------

    /// <summary>
    /// 来源页「下一步」的真实只读准备：打开原始 GPT 备份 → 读真实当前槽位 → 确认资产 →
    /// 准备默认安卓引导方案 → 走标准卸载工厂。只有工厂真实返回且捕获未变、仍在卸载模式、
    /// 仍在同一步骤时才提交字段；失败时保留现场并写真实诊断，绝不禁用保护锁。
    /// </summary>
    private async System.Threading.Tasks.Task PrepareModernUserdataUninstallConfirmationAsync()
    {
        if (!_ready
            || !IsModernUserdataUninstallMode
            || _internalInstallStep != 2
            || _busy
            || _userdataUninstallOperationActive
            || ProtectedModernUserdataUninstallState
            || !HasBootMaintenanceDeviceProof
            || _internalInstallEdlClient is null
            || _internalInstallEdlTools is null
            || _internalInstallEdlEntry is null
            || _internalInstallBackup is null
            || _internalInstallBackupParent is null
            || Directory.Exists(_internalInstallBackupParent) == false
            || _runner is null)
        {
            return;
        }

        var originalDirectory = _bootMaintenanceOriginalDirectory;
        if (string.IsNullOrWhiteSpace(originalDirectory) || !Directory.Exists(originalDirectory))
        {
            SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PrepareNeedOriginal"));
            return;
        }

        if (!IsInternalInstallBackupParentOutsideExisting(_internalInstallBackupParent, originalDirectory))
        {
            SetText(
                BootMaintenancePrepareStatusText,
                M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", originalDirectory));
            return;
        }

        // 精确捕获：只有这些值在工厂返回时仍然一致才允许提交。
        var client = _internalInstallEdlClient;
        var tools = _internalInstallEdlTools;
        var entry = _internalInstallEdlEntry;
        var fresh = _internalInstallBackup;
        var parent = _internalInstallBackupParent;
        var runner = _runner;
        var capturedStep = _internalInstallStep;

        // 先作废上一次未写入的只读准备。
        InvalidateModernUserdataUninstallPreparation();
        _userdataUninstallOperationActive = true;

        try
        {
            await RunBusyAsync(async token =>
            {
                UninstallOriginalGptBackup? original = null;
                BootSlotControlFacts? facts = null;
                EdlRawBootTools? actualTools = null;
                CurrentBootMenuPlan? menu = null;
                EdlUninstallBackend? backend = null;
                var committed = false;
                try
                {
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.OpeningOriginal"));

                    // 1) 只读打开原始预安装 GPT 备份。
                    original = await InternalInstallBackup.OpenOriginalGptForUninstallAsync(
                        client,
                        originalDirectory,
                        progress: null,
                        token);

                    // 2) 从全新备份的 misc 分区读真实当前槽位。
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.ReadingSlot"));
                    if (!fresh.Files.TryGetValue("misc", out var misc)
                        || misc is not EdlCapturedRegion miscRegion)
                    {
                        throw new InvalidOperationException(T("Dynamic.UserdataUninstall.Status.PrepareFailed"));
                    }

                    facts = await BootSlotControl.ReadAsync(
                        new VerifiedEdlFile(miscRegion.FilePath, miscRegion.Length, miscRegion.Sha256),
                        token);

                    // 3) 确认本机原生工具资产（实际 App 现有入口）。
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingAssets"));
                    await EnsureInternalInstallAssetsAsync(parent, fresh, token);
                    actualTools = _internalInstallNativeTools ?? throw new InvalidOperationException("Required boot tools were not prepared.");

                    // 4) 准备默认安卓引导方案（项目 boot/EFI 保留，默认进安卓）。
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingPlan"));
                    menu = await CurrentBootMenuPlanner.PrepareAndroidDefaultAsync(
                        fresh,
                        facts.CurrentSlot,
                        HasCheckedInternalInstallDevice
                            ? _internalInstallDeviceCheck!.Android!.Identity.BootloaderState
                            : BootloaderState.Unknown,
                        actualTools,
                        runner,
                        parent,
                        token);

                    // 5) 标准卸载工厂：参数与票面完全一致，无旧 7 参回退，无原始备份冒充 currentBackup。
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingPlan"));
                    var assets = UninstallGptAssets.FromVerifiedBackup(original);
                    var workRoot = parent;
                    var backendProgress = new Progress<EdlUninstallProgress>(report =>
                    {
                        RenderModernUserdataUninstallPrepareProgress(report);
                    });
                    backend = await EdlUninstallBackend.CreatePreparedAsync(
                        client,
                        tools,
                        entry,
                        assets,
                        fresh,
                        menu,
                        facts.CurrentSlot,
                        workRoot,
                        runner,
                        backendProgress,
                        token);

                    // 全部真实返回后再核对捕获；一致才提交三个自有字段。
                    if (!IsModernUserdataUninstallMode
                        || _closed
                        || !ReferenceEquals(_internalInstallEdlClient, client)
                        || !ReferenceEquals(_internalInstallEdlTools, tools)
                        || !ReferenceEquals(_internalInstallEdlEntry, entry)
                        || !ReferenceEquals(_internalInstallBackup, fresh)
                        || !string.Equals(_internalInstallBackupParent, parent, StringComparison.Ordinal)
                        || !string.Equals(_bootMaintenanceOriginalDirectory, originalDirectory, StringComparison.Ordinal)
                        || _internalInstallStep != capturedStep
                        || _userdataUninstallBackend is not null
                        || _userdataUninstallMenu is not null
                        || _userdataUninstallOriginal is not null)
                    {
                        // 捕获已变：只返回，由 finally 统一释放三个自有局部对象。
                        return;
                    }

                    _userdataUninstallBackend = backend;
                    _userdataUninstallMenu = menu;
                    _userdataUninstallOriginal = original;
                    _userdataUninstallError = null;
                    _internalInstallStep = 3;
                    committed = true;

                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.Prepared"));
                    AppendLocalizedLog(M("Dynamic.UserdataUninstall.Status.PreparedLog"));
                }
                catch (OperationCanceledException)
                {
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PrepareFailed"));
                    AppendLocalizedLog(M("Dynamic.UserdataUninstall.Status.PrepareCancelled"));
                }
                catch (Exception exception)
                {
                    _userdataUninstallError = exception.Message;
                    SetText(BootMaintenancePrepareStatusText, M("Dynamic.UserdataUninstall.Status.PrepareFailed"));
                    AppendLocalizedLog(M(
                        "Dynamic.RawValue",
                        $"{exception.GetType().FullName}: {exception.Message}"));
                }
                finally
                {
                    if (!committed)
                    {
                        backend?.Dispose();
                        menu?.Dispose();
                        original?.Dispose();
                    }
                }
            });
        }
        finally
        {
            _userdataUninstallOperationActive = false;
            RenderModernUserdataUninstallPages();
            RefreshModernUserdataUninstallActions();
        }
    }
}
