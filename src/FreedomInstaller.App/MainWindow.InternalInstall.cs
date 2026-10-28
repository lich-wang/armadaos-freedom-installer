using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」专用的四步向导：连接检测、系统备份、空间分配、确认安装。
/// <para>
/// 第 0 步只有在真实自动检查成功、平板确认返回安卓并且身份信息完整时，才允许进入备份页；
/// 备份页按实际型号与完整固件选择可信配置，匹配后才进入 9008。备份、空间规划、确认与执行
/// 各自只认对应 Core 工厂的真实结果与风险确认，绝不从导航或界面状态推断完成。
/// </para>
/// <para>
/// 另外四种操作（TF 卡安装、更新前准备、更新后修复、恢复原厂 boot）共享本文件的四步
/// 容器：TF 卡安装、卸载与维护各自有真实的四步控制器，更新前准备 / 更新后修复 /
/// 恢复原厂 boot 仍走维护三页向导，本文件不改变它们的页面、步骤标签或导航规则。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>当前四步向导所在的步骤，仅表示界面位置，不代表任何设备结论。</summary>
    private int _internalInstallStep;

    /// <summary>程序化勾选侧栏步骤时抑制 Checked 事件，避免导航处理递归调用。</summary>
    private bool _suppressInternalInstallNav;

    /// <summary>当前操作是否为新版内部存储安装：只有首页的 install 卡片进入四步向导。</summary>
    private bool IsInternalInstallMode =>
        string.Equals(CurrentModeTag(), "install", System.StringComparison.Ordinal);

    /// <summary>
    /// 唯一的前进门槛。第 0 步永远可以进入；第 1 步只认真实检查给出的正面结论
    /// （<see cref="HasCheckedInternalInstallDevice"/>）；第 2 步（分配空间）只认工厂实际返回的
    /// <see cref="InternalBackupSet"/>；第 3 步只认 <see cref="InternalInstallArtifacts.PrepareAsync"/>
    /// 实际返回、与当前系统包和当前整 GiB 选择一致的方案对象，以及真实工厂实际返回的
    /// <see cref="InternalInstallBackend"/>。
    /// </summary>
    private bool CanEnterInternalInstallStep(int step)
    {
        // 真实写入开始后只允许停留在确认页；返回更早的输入页会丢掉执行现场。
        if (HasInternalInstallExecutionStarted)
        {
            return step == 3;
        }

        return step switch
        {
            0 => true,
            1 => HasCheckedInternalInstallDevice,
            2 => _internalInstallBackup is not null && HasCheckedInternalInstallDevice,
            3 => _internalInstallBackend is not null
                && _internalInstallArtifacts is not null
                && _internalInstallBackup is not null
                && HasValidInternalInstallPackage
                && _internalInstallAllocation is not null
                && _internalInstallArtifacts!.Allocation.AndroidBytes == _internalInstallAllocation!.AndroidBytes
                && string.Equals(
                    _internalInstallPackage?.DeviceModel,
                    _internalInstallBackup!.Model,
                    StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    // ---------- 导航 ----------

    private async void OnInternalInstallNavChecked(object sender, RoutedEventArgs e)
    {
        // 共享设备准备页（内部安装 + 引导维护）都由这里驱动；维护分支在下方优先接管。
        if (!_ready || _suppressInternalInstallNav || !UsesSharedDevicePreparationPages)
        {
            return;
        }

        if (sender is not RadioButton radio || radio.Tag is not string tag)
        {
            RestoreInternalInstallNav();
            return;
        }

        var step = tag switch
        {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => -1,
        };

        // 卸载四步导航优先走自己的入口；安装向导保持原语义不变。
        if (IsModernUserdataUninstallMode)
        {
            if (_busy || step < 0 || !CanEnterModernUserdataUninstallStep(step))
            {
                RestoreInternalInstallNav();
                return;
            }

            NavigateModernUserdataUninstallStep(step);
            return;
        }

        // 维护模式的四步导航优先走自己的入口；安装向导保持原语义不变。
        if (IsBootMaintenanceMode)
        {
            if (_busy || step < 0 || !CanEnterBootMaintenanceStep(step))
            {
                RestoreInternalInstallNav();
                return;
            }

            NavigateBootMaintenanceStep(step);
            return;
        }

        // TF 卡安装的四步导航优先走自己的入口；其导航切换是异步的，实际导航由页脚/导航事件等待。
        if (IsModernTfInstallMode)
        {
            if (_busy || step < 0 || !CanEnterModernTfInstallStep(step))
            {
                RestoreInternalInstallNav();
                return;
            }

            await NavigateModernTfInstallStepAsync(step);
            return;
        }

        if (_busy || step < 0 || !CanEnterInternalInstallStep(step))
        {
            // 被拒绝的点击不能留下勾选状态：恢复为当前步骤，页面保持不动。
            RestoreInternalInstallNav();
            return;
        }

        NavigateInternalInstallStep(step);
    }

    /// <summary>
    /// 四步向导唯一的步骤切换入口。越界、忙碌或未满足 <see cref="CanEnterInternalInstallStep"/>
    /// 时直接拒绝，绝不允许跳过前面的步骤。维护模式优先委托给维护控制器。
    /// </summary>
    private void NavigateInternalInstallStep(int step)
    {
        // 卸载四步导航优先委托给卸载控制器。
        if (IsModernUserdataUninstallMode)
        {
            NavigateModernUserdataUninstallStep(step);
            return;
        }

        if (IsBootMaintenanceMode)
        {
            NavigateBootMaintenanceStep(step);
            return;
        }

        // TF 卡安装的真实导航在异步入口完成：同步路径只负责恢复勾选，不发起任何 fire-and-forget 任务。
        if (IsModernTfInstallMode)
        {
            RestoreInternalInstallNav();
            return;
        }

        if (!IsInternalInstallMode || _busy || step is < 0 or > 3)
        {
            RestoreInternalInstallNav();
            return;
        }

        if (step != _internalInstallStep && !CanEnterInternalInstallStep(step))
        {
            RestoreInternalInstallNav();
            return;
        }

        _internalInstallStep = step;
        RenderInternalInstallPages();
        RefreshInternalInstallActions();
    }

    /// <summary>把四页的可见性与四个侧栏勾选一起写成当前步骤；勾选在抑制保护下设置。</summary>
    private void RenderInternalInstallPages()
    {
        // 卸载模式优先委托：页面与面板完全由卸载控制器渲染，安装页整体隐藏。
        if (IsModernUserdataUninstallMode)
        {
            RenderModernUserdataUninstallPages();
            return;
        }

        // 维护模式优先委托：页面与面板完全由维护控制器渲染，安装页整体隐藏。
        if (IsBootMaintenanceMode)
        {
            RenderBootMaintenancePages();
            return;
        }

        // TF 卡安装优先委托：页面与面板完全由 TF 控制器渲染，安装页整体隐藏。
        if (IsModernTfInstallMode)
        {
            RenderModernTfInstallPages();
            return;
        }

        RestoreInternalInstallNav();

        InternalInstallCheckPage.Visibility =
            _internalInstallStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallBackupPage.Visibility =
            _internalInstallStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallCapacityPage.Visibility =
            _internalInstallStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        InternalInstallConfirmPage.Visibility =
            _internalInstallStep == 3 ? Visibility.Visible : Visibility.Collapsed;

        // 安装分支隐藏维护专属的来源 / 确认 / 进入 9008 面板，并恢复复用已有备份的勾选。
        BootMaintenanceSourcesPage.Visibility = Visibility.Collapsed;
        BootMaintenanceConfirmPage.Visibility = Visibility.Collapsed;
        BootMaintenanceEntryPanel.Visibility = Visibility.Collapsed;
        InternalInstallBackupUseExistingCheck.Visibility = Visibility.Visible;
    }

    /// <summary>只重写侧栏勾选，不碰页面；用于程序化渲染与拒绝导航后的状态恢复。</summary>
    private void RestoreInternalInstallNav()
    {
        _suppressInternalInstallNav = true;
        try
        {
            InternalInstallNavCheck.IsChecked = _internalInstallStep == 0;
            InternalInstallNavBackup.IsChecked = _internalInstallStep == 1;
            InternalInstallNavCapacity.IsChecked = _internalInstallStep == 2;
            InternalInstallNavConfirm.IsChecked = _internalInstallStep == 3;
        }
        finally
        {
            _suppressInternalInstallNav = false;
        }
    }

    // ---------- 视图与按钮 ----------

    /// <summary>
    /// 按当前操作在新四步向导与原有三页向导之间切换内部内容。
    /// 这里只改内容分组与共享连接图示的归属，不调用 <see cref="RefreshActions"/>
    /// 或 <see cref="UpdateSummary"/>，避免与父视图刷新互相递归。
    /// </summary>
    private void ApplyInternalInstallView()
    {
        // 共享设备准备页同时服务安装、维护与 TF 卡安装：导航 / 页面可见性 / 连接图示只按这一谓词切换。
        var sharedMode = IsInternalInstallMode || UsesSharedDevicePreparationPages || IsModernTfInstallMode;

        LegacyStepNav.Visibility = sharedMode ? Visibility.Collapsed : Visibility.Visible;
        InternalInstallStepNav.Visibility = sharedMode ? Visibility.Visible : Visibility.Collapsed;

        LegacyWorkflowPages.Visibility = sharedMode ? Visibility.Collapsed : Visibility.Visible;
        InternalInstallPages.Visibility = sharedMode ? Visibility.Visible : Visibility.Collapsed;

        // TF 输入页与读卡器卡片宿主是 TF 专属容器：只在 TF 模式之外显式还原，
        // 其可见性完全交由 TF 渲染器管理，绝不泄漏到其余五种模式。
        if (!IsModernTfInstallMode)
        {
            TfInstallInputsPage.Visibility = Visibility.Collapsed;
            TfCardDiscoveryHost.Visibility = Visibility.Collapsed;
            BootMaintenanceEntryOriginalBox.Visibility = Visibility.Visible;
            BootMaintenanceEntryOriginalBrowseButton.Visibility = Visibility.Visible;
            SharedEdlOriginalEntryLabel.Visibility = Visibility.Visible;
        }

        LegacyStepNav.Visibility = sharedMode ? Visibility.Collapsed : Visibility.Visible;
        InternalInstallStepNav.Visibility = sharedMode ? Visibility.Visible : Visibility.Collapsed;

        LegacyWorkflowPages.Visibility = sharedMode ? Visibility.Collapsed : Visibility.Visible;
        InternalInstallPages.Visibility = sharedMode ? Visibility.Visible : Visibility.Collapsed;

        // TF 入口选择只看当前模式：进入「安装到 TF 卡」立刻可见，先于任何页面切换；
        // 其余模式保持折叠（行高 Auto，不占空间），也不改变新旧容器各自的可见性。
        TfEntrySelectionPanel.Visibility = CurrentModeTag() == "install-tf"
            ? Visibility.Visible
            : Visibility.Collapsed;
        if (TfEntrySelectionPanel.Visibility == Visibility.Visible)
        {
            RenderTfTabletHostDriverStatus();
        }

        MoveSharedConnectionGuide(sharedMode);
        RenderSharedWorkflowNavigationLabels();

        if (IsInternalInstallMode)
        {
            RenderInternalInstallPages();
        }
        else if (IsModernUserdataUninstallMode)
        {
            RenderModernUserdataUninstallPages();
        }
        else if (IsBootMaintenanceMode)
        {
            RenderBootMaintenancePages();
        }
        else if (IsModernTfInstallMode)
        {
            RenderModernTfInstallPages();
        }
    }

    /// <summary>
    /// 连接图示只有 <c>SharedConnectionGuide</c> 一个实例：在新旧容器之间移动，
    /// 不重建控件。已在目标容器时什么都不做；移动前先从已知的旧父容器上摘下。
    /// </summary>
    private void MoveSharedConnectionGuide(bool internalMode)
    {
        Border target = internalMode ? InternalInstallGuideHost : ConnectHelpPanel;
        if (ReferenceEquals(SharedConnectionGuide.Parent, target))
        {
            return;
        }

        if (SharedConnectionGuide.Parent is Border previous && ReferenceEquals(previous.Child, SharedConnectionGuide))
        {
            previous.Child = null;
        }

        target.Child = SharedConnectionGuide;
    }

    /// <summary>
    /// 四步向导的底栏与按钮可用性。第 0 步按真实工具与真实设备列表启用；第 2 步的目录与开始按钮
    /// 只在真实检查通过后启用，进入 9008 之后只允许用同一会话显式重试备份；第 3 步的路径框、校验与滑条
    /// 按本步自己的实现启用，执行按钮始终隐藏并禁用。
    /// </summary>
    private void RefreshInternalInstallActions()
    {
        // 卸载模式优先：刷新卸载自己的动作与共享退出面板，安装/维护侧结论完全不参与。
        if (IsModernUserdataUninstallMode)
        {
            RefreshModernUserdataUninstallActions();
            return;
        }

        // 维护模式优先：刷新维护动作与共享退出面板，安装侧旧结论完全不参与。
        if (IsBootMaintenanceMode)
        {
            RefreshBootMaintenanceActions();
            RefreshBootMaintenanceSharedActions();
            return;
        }

        // TF 卡安装优先：刷新 TF 自己的动作，安装/维护侧旧结论完全不参与。
        if (IsModernTfInstallMode)
        {
            RefreshModernTfInstallActions();
            return;
        }

        if (!IsInternalInstallMode)
        {
            return;
        }

        var edlHeld = HasInternalInstallLiveEdlState;
        var checkedDevice = HasCheckedInternalInstallDevice;
        var hasBackupParent = !string.IsNullOrWhiteSpace(_internalInstallBackupParent)
            && Directory.Exists(_internalInstallBackupParent);
        var useExistingBackup = _internalInstallBackupUseExisting;
        var hasExistingBackupDirectory = !string.IsNullOrWhiteSpace(
                _internalInstallBackupExistingDirectory)
            && Directory.Exists(_internalInstallBackupExistingDirectory);
        var canReuseSession = _internalInstallEdlClient is not null
            && _internalInstallEdlEntry is not null
            && _internalInstallEdlTools is not null;

        InternalInstallNavCheck.IsEnabled = !_busy;
        InternalInstallNavBackup.IsEnabled = !_busy && CanEnterInternalInstallStep(1);
        InternalInstallNavCapacity.IsEnabled = !_busy && CanEnterInternalInstallStep(2);
        InternalInstallNavConfirm.IsEnabled = !_busy && CanEnterInternalInstallStep(3);

        PrevButton.IsEnabled = !_busy && _internalInstallStep > 0;
        NextButton.Visibility =
            _internalInstallStep < 3 ? Visibility.Visible : Visibility.Collapsed;

        // 第 3 步（分配空间）的「下一步」会真正准备主机侧方案，所以它使用与准备入口相同的输入门槛；
        // 其余步骤仍只按各自的既有证明判断。
        NextButton.IsEnabled = !_busy
            && _internalInstallStep < 3
            && (_internalInstallStep == 2
                ? HasInternalInstallAllocationInputs
                : CanEnterInternalInstallStep(_internalInstallStep + 1));
        ActionButton.Visibility = Visibility.Collapsed;
        ActionButton.IsEnabled = false;

        // 第 0 步：只有真实工具目录与空闲状态才能发起检查；进入 9008 之后不能再把平板当成安卓检查。
        InternalInstallCheckButton.IsEnabled =
            !_busy && !_internalInstallOperationActive && _transport is not null && !edlHeld;
        InternalInstallDevicesCombo.IsEnabled =
            !_busy && !edlHeld && _internalInstallDeviceChoices.Count > 0;
        UpdateInternalInstallDeviceSelector();

        // 第 2 步（系统备份）：父目录对两种模式都必填；复用模式还要求一个真实存在的已有备份目录。
        // 目录与模式控件只在检查通过、空闲且没有进行中的操作时可用；开始按钮同样受会话复用门槛约束。
        var backupEditable = !_busy
            && !_internalInstallOperationActive
            && !HasInternalInstallExecutionStarted
            && checkedDevice;

        InternalInstallBackupBrowseButton.IsEnabled = backupEditable;
        InternalInstallBackupUseExistingCheck.IsEnabled = backupEditable;
        InternalInstallBackupExistingBrowseButton.IsEnabled =
            backupEditable && useExistingBackup;
        InternalInstallBackupButton.IsEnabled = !_busy
            && !_internalInstallOperationActive
            && checkedDevice
            && hasBackupParent
            && (!useExistingBackup || hasExistingBackupDirectory)
            && (!edlHeld || canReuseSession);

        // 容量分配的系统包、滑条与校验入口由本步自己的实现管理；这里只刷新它们的最终可用性。
        RenderInternalInstallBackupDetail();
        RefreshInternalInstallExitActions();
        RefreshInternalInstallCapacityActions();

        // 最后一步：执行侧结论覆盖上面的旧底栏赋值（执行按钮、只读复查与冻结状态）。
        RefreshInternalInstallExecutionActions();
    }

    /// <summary>
    /// 回到第 0 步并重绘，同时作废上一台设备的检查结论与真实设备列表。
    /// 只清界面与结果，不删除文件、不碰设备；检查或备份进行中不做任何清理，
    /// 存在真实 9008 会话时也不释放工具链（离开这道状态由功能切换与关闭闸门统一拒绝）。
    /// </summary>
    private void ResetInternalInstallUiState()
    {
        // TF 卡安装受保护状态（未确认写入 / 工作流仍在场）拒绝任何界面清空；
        // 离开 TF 模式时由自己的离开例程先异步释放，再进入全局复位。
        if (IsModernTfInstallMode && (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall))
        {
            return;
        }

        // 维护受保护状态（未确认写入 / 未知复位）拒绝任何界面清空。
        if (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
        {
            return;
        }

        // 写入已开始且尚未真实完成：拒绝任何界面清空，避免把仍在设备上的安装事务丢掉。
        if (HasInternalInstallExecutionStarted && !IsCompletedInternalInstallExecution)
        {
            return;
        }

        if (!_internalInstallOperationActive)
        {
            ResetInternalInstallCheckState(clearSelection: true);
        }

        if (!_internalInstallOperationActive && !_busy && !HasInternalInstallLiveEdlState)
        {
            // 没有任何仍在使用的设备会话：释放本次备份的只读锁与暂存工具链，文件与清单原样保留。
            DisposeInternalInstallResources();
        }

        _internalInstallStep = 0;

        if (!_ready)
        {
            return;
        }

        RenderInternalInstallPages();
    }
}
