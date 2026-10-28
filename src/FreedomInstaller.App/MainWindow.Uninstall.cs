using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;
using Microsoft.Win32;

namespace FreedomInstaller.App;
/// <summary>
/// 卸载写入侧（N2，仅 9008/EDL）：入口来自可见的 9008 卡片，准备、执行与验收全部由
/// MainWindow.Edl.cs 中的只读/写入链路承担；本文件只保留 EDL 接线、
/// 关闭保护、公共文案与外部分区辅助方法。
/// <para>
/// 旧的 RAM 维护会话与 HTTP 事务代码已整体移除；这里不再创建任何临时会话或 HTTP 客户端。
/// </para>
/// </summary>
public partial class MainWindow
{
    private enum UninstallUiPhase
    {
        Idle,
        Prepared,
        Running,
        Uncertain,
        Failed,
        AwaitingFactoryReset,
        Accepted,
    }

    private UninstallUiPhase _uninstallPhase = UninstallUiPhase.Idle;

    private bool _uninstallAttempted;

    private bool _uninstallWritesStarted;

    private ValidatedUninstallInputs? _uninstallInputs;

    private bool _uninstallCloseApproved;
    /// <summary>执行中、结果未知或等待清除数据时，任何会丢掉这次事务的操作都被挡住。
    /// 现代卸载向导自身的保护状态一并计入（递归防护：谓词本身不再引用回本谓词）。</summary>
    private bool HasProtectedUninstallState =>
        (_uninstallPhase is UninstallUiPhase.Running
            or UninstallUiPhase.Uncertain
            or UninstallUiPhase.AwaitingFactoryReset)
        || ProtectedModernUserdataUninstallState;


    // ---------- 状态清理 ----------

    /// <summary>还原输入或工作目录一变，上一次准备的事务就不能再用；受保护阶段不做任何改动。</summary>
    private void InvalidateUninstallPreparedPlan()
    {
        if (HasProtectedUninstallState)
        {
            return;
        }

        ClearPreparedUninstallState();
        RefreshUninstallViews();
    }

    private void ClearPreparedUninstallState()
    {
        ClearPreparedEdlUninstallState();
        _uninstallInputs = null;
        _restorePlan = null;
        _uninstallPhase = UninstallUiPhase.Idle;
        _uninstallAttempted = false;
        _uninstallWritesStarted = false;


        if (_ready && RiskCheck.IsChecked == true)
        {
            RiskCheck.IsChecked = false;
        }

        if (_ready)
        {
            SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.Input.NoteInvalidated");
        }
    }

    private void RefreshUninstallViews()
    {
        if (!_ready)
        {
            return;
        }

        if (CurrentModeTag() == "uninstall")
        {
            UpdateUninstallPanel();
        }

        UpdateSummary();
        RefreshUninstallActions();
    }

    /// <summary>把整个卸载侧（含 9008 状态与原始路径）回到初始状态；执行中的事务不会被丢掉。</summary>
    private void ResetUninstallState()
    {
        if (HasProtectedUninstallState)
        {
            return;
        }

        ResetUninstallEdlState();
        InvalidateUninstallPreparedPlan();
        ResetUninstallConnectionState();

        // 现代卸载向导：已有保护被上方守卫挡住；空闲时安全回零（保留已选路径供复用）。
        SafeResetModernUserdataUninstallState();

        _installationRecord = null;
        _restorePlan = null;
        StockBackupBox.Text = string.Empty;
        InstallationRecordBox.Text = string.Empty;
        OriginalPrimaryGptBox.Text = string.Empty;
        OriginalBackupGptBox.Text = string.Empty;
        StockBootAPathBox.Text = string.Empty;
        StockBootBPathBox.Text = string.Empty;
        VbmetaBaselineBox.Text = string.Empty;

        SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.Input.NoteInitial");
        SetText(UninstallTransactionStatusText, "Dynamic.UninstallFlow.Transaction.StatusInitial");
        SetText(ProgressStatusText, "Dynamic.Progress.Idle");

        if (_ready)
        {
            UpdateUninstallPanel();
            UpdateSummary();
            RefreshUninstallActions();
        }
    }

    /// <summary>关闭窗口时只释放 9008 与卸载共享状态；不删除用户文件或已有备份。</summary>
    private void DisposeUninstallState()
    {
        _uninstallInputs = null;

        DisposeEdlUninstallState();
    }

    /// <summary>Closing 钩子：执行中或结果未知时不允许关闭，等待清除数据时只接受明确的「是」。</summary>
    private void OnUninstallClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_uninstallPhase == UninstallUiPhase.Running)
        {
            e.Cancel = true;
            MessageBox.Show(
                this,
                _uninstallEdlResult != null
                    ? T(
                        "Dynamic.UninstallFlow.Close.EdlRunningBody",
                        _uninstallEdlBackend?.BackupDirectory ?? UnknownValue)
                    : T("Dynamic.UninstallFlow.Close.RunningBody"),
                T("Dynamic.UninstallFlow.Close.RunningTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (_uninstallPhase == UninstallUiPhase.Uncertain)
        {
            e.Cancel = true;
            MessageBox.Show(
                this,
                _uninstallEdlResult != null
                    ? T(
                        "Dynamic.UninstallFlow.Close.EdlRunningBody",
                        _uninstallEdlBackend?.BackupDirectory ?? UnknownValue)
                    : T("Dynamic.UninstallFlow.Close.RunningBody"),
                T("Dynamic.UninstallFlow.Close.RunningTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (_uninstallPhase != UninstallUiPhase.AwaitingFactoryReset)
        {
            return;
        }

        var answer = MessageBox.Show(
            this,
            _uninstallEdlResult != null
                ? T(
                    "Dynamic.UninstallFlow.Close.EdlAwaitingBody",
                    _uninstallEdlBackend?.BackupDirectory ?? UnknownValue)
                : T("Dynamic.UninstallFlow.Close.AwaitingBody"),
            T("Dynamic.UninstallFlow.Close.AwaitingTitle"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            e.Cancel = true;
            return;
        }

        _uninstallCloseApproved = true;
    }

    // ---------- 还原文件与预览 ----------

    private void OnBrowseRestoreAsset(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || HasProtectedUninstallState)
        {
            return;
        }

        if (sender is not Button button || button.Tag is not string tag || RestoreAssetBox(tag) is not { } target)
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = T("Dynamic.UninstallFlow.Asset.DialogTitle"),
            Filter = T("Dynamic.Dialog.AllFileFilter"),
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        target.Text = dialog.FileName;
        InvalidateUninstallPreparedPlan();
        SetText(
            UninstallInputNoteText,
            "Dynamic.UninstallFlow.Asset.Selected",
            T(RestoreAssetLabelKey(tag)),
            Path.GetFileName(dialog.FileName));
        UpdateSummary();
    }

    /// <summary>只清除显式选择的旧版记录；它不能代替原始 GPT 与 AVB 校验。</summary>
    private void OnClearLegacyInstallationRecord(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || HasProtectedUninstallState)
        {
            return;
        }

        InstallationRecordBox.Text = string.Empty;
        _installationRecord = null;
        InvalidateUninstallPreparedPlan();
        SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.Legacy.Cleared");
        UpdateSummary();
        RefreshUninstallActions();
    }

    private TextBox? RestoreAssetBox(string tag) => tag switch
    {
        "primary-gpt" => OriginalPrimaryGptBox,
        "backup-gpt" => OriginalBackupGptBox,
        "boot-a" => StockBootAPathBox,
        "boot-b" => StockBootBPathBox,
        "vbmeta-baseline" => VbmetaBaselineBox,
        _ => null,
    };

    private static string RestoreAssetLabelKey(string tag) => tag switch
    {
        "primary-gpt" => "Dynamic.UninstallFlow.Asset.PrimaryGpt",
        "backup-gpt" => "Dynamic.UninstallFlow.Asset.BackupGpt",
        "boot-a" => "Dynamic.UninstallFlow.Asset.BootA",
        "boot-b" => "Dynamic.UninstallFlow.Asset.BootB",
        _ => "Dynamic.UninstallFlow.Asset.Vbmeta",
    };

    /// <summary>
    /// 选择还原材料目录后，先清掉全部五个旧路径，避免上一次选择的材料残留。
    /// 卸载流程只需要主 GPT 与备份 GPT 两份材料；A/B 启动镜像与 vbmeta 属于独立的原厂启动恢复，
    /// 在卸载模式下不填入也不探测，因此不会被误当成卸载的前置条件。
    /// 非卸载的旧路径仍按五个标准文件名探测，保持原有兼容行为。
    /// </summary>
    private int PopulateUninstallMaterialPaths(string folder)
    {
        OriginalPrimaryGptBox.Text = string.Empty;
        OriginalBackupGptBox.Text = string.Empty;
        StockBootAPathBox.Text = string.Empty;
        StockBootBPathBox.Text = string.Empty;
        VbmetaBaselineBox.Text = string.Empty;

        var count = 0;
        SetIfExists(OriginalPrimaryGptBox, "before-main.bin");
        SetIfExists(OriginalBackupGptBox, "before-backup.bin");

        if (CurrentModeTag() != "uninstall")
        {
            SetIfExists(StockBootAPathBox, "stock_boot_a.img");
            SetIfExists(StockBootBPathBox, "stock_boot_b.img");
            SetIfExists(VbmetaBaselineBox, "vbmeta-baseline.img");
        }

        InvalidateUninstallPreparedPlan();
        return count;

        void SetIfExists(TextBox box, string name)
        {
            var path = Path.Combine(folder, name);
            if (File.Exists(path))
            {
                box.Text = path;
                count++;
            }
        }
    }

    private string[] UninstallAssetPaths() => new[]
    {
        (StockBootAPathBox.Text ?? string.Empty).Trim(),
        (StockBootBPathBox.Text ?? string.Empty).Trim(),
        (OriginalPrimaryGptBox.Text ?? string.Empty).Trim(),
        (OriginalBackupGptBox.Text ?? string.Empty).Trim(),
        (VbmetaBaselineBox.Text ?? string.Empty).Trim(),
    };

    private bool AllUninstallAssetsExist() =>
        UninstallAssetPaths().All(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path));

    private string MissingUninstallAssets()
    {
        var paths = UninstallAssetPaths();
        var keys = new[]
        {
            "Dynamic.UninstallFlow.Asset.BootA",
            "Dynamic.UninstallFlow.Asset.BootB",
            "Dynamic.UninstallFlow.Asset.PrimaryGpt",
            "Dynamic.UninstallFlow.Asset.BackupGpt",
            "Dynamic.UninstallFlow.Asset.Vbmeta",
        };

        var missing = new List<string>();
        for (var index = 0; index < paths.Length; index++)
        {
            if (string.IsNullOrWhiteSpace(paths[index]) || !File.Exists(paths[index]))
            {
                missing.Add(T(keys[index]));
            }
        }

        return string.Join(T("Dynamic.UninstallFlow.Plan.Separator"), missing);
    }

    /// <summary>9008 只读准备只需要两份原始 GPT：主 GPT 在前，备份 GPT 在后。</summary>
    private string[] UninstallGptPaths() => new[]
    {
        (OriginalPrimaryGptBox.Text ?? string.Empty).Trim(),
        (OriginalBackupGptBox.Text ?? string.Empty).Trim(),
    };

    /// <summary>两份 GPT 都必须真实存在；这里绝不隐式查看 A/B 启动镜像或 vbmeta 的隐藏字段。</summary>
    private bool AllUninstallGptAssetsExist() =>
        UninstallGptPaths().All(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path));

    private string MissingUninstallGptAssets()
    {
        var paths = UninstallGptPaths();
        var keys = new[]
        {
            "Dynamic.UninstallFlow.Asset.PrimaryGpt",
            "Dynamic.UninstallFlow.Asset.BackupGpt",
        };

        var missing = new List<string>();
        for (var index = 0; index < paths.Length; index++)
        {
            if (string.IsNullOrWhiteSpace(paths[index]) || !File.Exists(paths[index]))
            {
                missing.Add(T(keys[index]));
            }
        }

        return string.Join(T("Dynamic.UninstallFlow.Plan.Separator"), missing);
    }

    private bool TryRenderPreparedUninstallPanel()
    {
        return TryRenderEdlUninstallPanel();
    }

    private bool TryRenderUninstallSummary()
    {
        return TryRenderEdlUninstallSummary();
    }

    // ---------- 准备（只读事务） ----------

    private async void OnPrepareUninstall(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || HasProtectedUninstallState || CurrentModeTag() != "uninstall")
        {
            return;
        }

        // 9008 入口存在时只走 EDL 只读准备；没有临时 RAM 会话的回落路径。
        if (_uninstallEdlResult is not null)
        {
            await PrepareEdlUninstallAsync();
        }
    }


    private void RequireSameLegacyRecord(LinuxInstallationLayout selected, LinuxInstallationLayout derived)
    {
        var same = string.Equals(selected.DeviceId, derived.DeviceId, StringComparison.Ordinal)
            && SameUuid(selected.UserdataPartUuid, derived.UserdataPartUuid)
            && SameUuid(selected.LinuxBootPartUuid, derived.LinuxBootPartUuid)
            && SameUuid(selected.LinuxRootPartUuid, derived.LinuxRootPartUuid)
            && selected.OriginalUserdataEndSector == derived.OriginalUserdataEndSector;

        if (!same)
        {
            throw new InvalidOperationException(T("Dynamic.UninstallFlow.Input.LegacyRecordMismatch"));
        }
    }

    private static bool SameUuid(string left, string right) =>
        Guid.TryParse(left, out var leftValue) && Guid.TryParse(right, out var rightValue)
            ? leftValue == rightValue
            : string.Equals(left, right, StringComparison.Ordinal);


    // ---------- 执行 ----------

    private async void OnExecuteUninstall(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || CurrentModeTag() != "uninstall")
        {
            return;
        }

        // 只有真实 9008 后端存在时才允许执行；这里没有 RAM/HTTP 回落路径。
        if (_uninstallEdlBackend is not null)
        {
            await ExecuteEdlUninstallAsync();
        }
    }

    // ---------- 查询 ----------

    // ---------- 安卓验收 ----------

    private async void OnVerifyUninstallAndroid(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy)
        {
            return;
        }

        // 9008 流程使用真实入口证据做只读验收，绝不复用 RAM 绑定或设备清单。
        if (_uninstallEdlBackend is not null)
        {
            await VerifyEdlUninstallAndroidAsync();
            return;
        }
        SetText(ProgressStatusText, "Dynamic.UninstallFlow.Verify.OnlyAfterReset");
    }

    // ---------- 可用性 ----------

    /// <summary>在既有 RefreshActions 之后运行：只改卸载相关控件，其他模式的写入按钮保持原样禁用。</summary>
    private void RefreshUninstallActions()
    {
        if (!_ready)
        {
            return;
        }

        var uninstall = CurrentModeTag() == "uninstall";
        var protectedState = HasProtectedUninstallState;

        UninstallPanel.Visibility = uninstall ? Visibility.Visible : Visibility.Collapsed;
        UninstallTransactionSection.Visibility = uninstall ? Visibility.Visible : Visibility.Collapsed;

        // 执行中 / 未知 / 等待清除数据时不允许离开或换功能，否则界面会丢掉仍在设备上的事务。
        BackToFunctionsButton.IsEnabled = !_busy && !protectedState;
        HomeCards.IsEnabled = !_busy && !protectedState;

        var locked = uninstall
            && (_uninstallEdlResult is not null
                || _uninstallEdlEntering
                || protectedState);
        ToolsPathBox.IsEnabled = !_busy && !locked;
        BrowseToolsButton.IsEnabled = !_busy && !locked;
        DetectButton.IsEnabled = !_busy && _transport is not null && !locked;
        DevicesCombo.IsEnabled = !_busy && _devices.Count > 0 && !locked;
        CheckBootloaderButton.IsEnabled = !_busy && _transport is not null && _identity is not null && !locked;
        ReadLayoutButton.IsEnabled = !_busy && _transport is not null && _identity is not null && !locked;

        BrowseStockBackupButton.IsEnabled = !_busy && !protectedState;
        BrowseInstallationRecordButton.IsEnabled = !_busy && !protectedState;
        ClearInstallationRecordButton.IsEnabled = !_busy
            && !protectedState
            && (InstallationRecordBox.Text ?? string.Empty).Trim().Length > 0;
        RestoreAssetsExpander.IsEnabled = !_busy && !protectedState;
        LegacyRecordExpander.IsEnabled = !_busy && !protectedState;
        BrowseUninstallWorkRootButton.IsEnabled = !_busy && !protectedState;
        ChangeUninstallWorkRootButton.IsEnabled = !_busy && !protectedState;

        if (!uninstall)
        {
            return;
        }

        // 卸载分支的最后一步：由 9008 专用入口统一覆盖上面所有赋值。
        RefreshUninstallEdlActions();
    }

    private string ActionReasonKey() => _uninstallPhase switch
    {
        UninstallUiPhase.Prepared when _uninstallAttempted => "Dynamic.UninstallFlow.Action.Attempted",
        UninstallUiPhase.Prepared when RiskCheck.IsChecked != true => "Dynamic.UninstallFlow.Action.RiskRequired",
        UninstallUiPhase.Prepared => "Dynamic.UninstallFlow.Action.Ready",
        UninstallUiPhase.Running => "Dynamic.UninstallFlow.Action.Running",
        UninstallUiPhase.Uncertain => "Dynamic.UninstallFlow.Action.Uncertain",
        UninstallUiPhase.AwaitingFactoryReset => "Dynamic.UninstallFlow.Action.Awaiting",
        UninstallUiPhase.Failed when _uninstallAttempted => "Dynamic.UninstallFlow.Action.Attempted",
        UninstallUiPhase.Accepted => "Dynamic.UninstallFlow.Action.Accepted",
        _ => "Dynamic.UninstallFlow.Action.NeedPrepare",
    };

    // ---------- 文案辅助 ----------

    private static string PhaseKey(UninstallUiPhase phase) => phase switch
    {
        UninstallUiPhase.Prepared => "Dynamic.UninstallFlow.Phase.Prepared",
        UninstallUiPhase.Running => "Dynamic.UninstallFlow.Phase.Running",
        UninstallUiPhase.Uncertain => "Dynamic.UninstallFlow.Phase.Uncertain",
        UninstallUiPhase.Failed => "Dynamic.UninstallFlow.Phase.Failed",
        UninstallUiPhase.AwaitingFactoryReset => "Dynamic.UninstallFlow.Phase.AwaitingFactoryReset",
        UninstallUiPhase.Accepted => "Dynamic.UninstallFlow.Phase.Accepted",
        _ => "Dynamic.UninstallFlow.Phase.Idle",
    };


    private static string StageKey(UninstallStage stage) => stage switch
    {
        UninstallStage.Preflight => "Dynamic.UninstallFlow.Stage.Preflight",
        UninstallStage.ValidateRestoreInputs => "Dynamic.UninstallFlow.Stage.ValidateRestoreInputs",
        UninstallStage.BackupCurrentBoot => "Dynamic.UninstallFlow.Stage.BackupCurrentBoot",
        UninstallStage.PrepareStockBoot => "Dynamic.UninstallFlow.Stage.PrepareStockBoot",
        UninstallStage.RestoreBootA => "Dynamic.UninstallFlow.Stage.RestoreBootA",
        UninstallStage.VerifyBootA => "Dynamic.UninstallFlow.Stage.VerifyBootA",
        UninstallStage.RestoreBootB => "Dynamic.UninstallFlow.Stage.RestoreBootB",
        UninstallStage.VerifyBootB => "Dynamic.UninstallFlow.Stage.VerifyBootB",
        UninstallStage.ReclaimAndroidSpace => "Dynamic.UninstallFlow.Stage.ReclaimAndroidSpace",
        UninstallStage.InitializeAndroid => "Dynamic.UninstallFlow.Stage.InitializeAndroid",
        UninstallStage.VerifyAndroid => "Dynamic.UninstallFlow.Stage.VerifyAndroid",
        UninstallStage.AwaitingAndroidBootAcceptance => "Dynamic.UninstallFlow.Stage.AwaitingAndroidBootAcceptance",
        _ => "Dynamic.UninstallFlow.Stage.AwaitingFactoryReset",
    };


    private string DeletedPartitionExtents(ValidatedUninstallInputs inputs)
    {
        var items = new List<string>();
        foreach (var number in inputs.Plan.RemovedPartitionNumbers)
        {
            var partition = inputs.CurrentTable.Partitions.FirstOrDefault(candidate => candidate.Number == number);
            if (partition is null)
            {
                continue;
            }

            items.Add(T(
                "Dynamic.UninstallFlow.Plan.DeletedItem",
                partition.Number,
                partition.StartSector,
                partition.StartSector + partition.SectorCount - 1));
        }

        return items.Count == 0
            ? T("Dynamic.UninstallFlow.Plan.None")
            : string.Join(T("Dynamic.UninstallFlow.Plan.Separator"), items);
    }

    private static long? CurrentUserdataBytes(ValidatedUninstallInputs inputs)
    {
        var userdata = inputs.CurrentTable.Partitions.FirstOrDefault(partition =>
            string.Equals(
                CanonicalUuid(partition.PartUuid),
                CanonicalUuid(inputs.Record.UserdataPartUuid),
                StringComparison.Ordinal));
        if (userdata is null)
        {
            return null;
        }

        try
        {
            return checked(userdata.SectorCount * inputs.CurrentTable.SectorSize);
        }
        catch (OverflowException)
        {
            return null;
        }
    }


    private static string CanonicalUuid(string value) =>
        Guid.TryParse(value, out var parsed) ? parsed.ToString("D").ToUpperInvariant() : value;
}
