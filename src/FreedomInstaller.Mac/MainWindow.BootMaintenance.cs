using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// The "Android 更新前准备" (prepare) and "Android 更新后修复" (repair) page of the macOS window: the port of the WPF
/// boot-maintenance controller (MainWindow.BootMaintenance*.cs) with the shared Android → fresh backup → 9008 entry
/// it drives (MainWindow.SharedDeviceEntry.cs, the shared-mode branches of MainWindow.InternalInstall.Check.cs /
/// .Backup.cs / .Preparation.cs). The four steps, their gates, the Core calls and their order are the WPF ones;
/// every device write happens only inside <see cref="BootMaintenanceBackend"/>. The page keeps its own state
/// instead of sharing the install wizard's fields (the WPF window resets that shared state whenever the function
/// changes, so the two never carry over there either). Device calls run on a worker thread because the macOS 9008
/// discovery reads ioreg synchronously; their progress still posts back to the UI thread.
/// </summary>
public partial class MainWindow
{
    private const string BootMaintenanceToolchainFolder = ".armada-installer-tools";

    // ---------- 页面 ----------

    private string _bootMaintenanceTag = "prepare";
    private int _bootMaintenanceStep;
    private bool _suppressBootMaintenanceNav;
    private bool _suppressBootMaintenanceDeviceSelection;
    private string? _bootMaintenanceWorkRoot;

    // ---------- 01 检查 ----------

    private IReadOnlyList<ConnectedDevice> _bootMaintenanceDeviceChoices = Array.Empty<ConnectedDevice>();
    private InternalDeviceCheckResult? _bootMaintenanceDeviceCheck;
    private AndroidMaintenanceIdentity? _bootMaintenanceSharedAndroid;
    private PowerSample? _bootMaintenancePower;
    private bool _bootMaintenanceAlreadyEdl;

    /// <summary>A check or backup is running (the WPF <c>_internalInstallOperationActive</c> of the shared pages).</summary>
    private bool _bootMaintenanceDeviceOperationActive;

    // ---------- 02 备份与 9008 会话 ----------

    private EdlToolchain? _bootMaintenanceEdlTools;
    private EdlEntryResult? _bootMaintenanceEdlEntry;
    private EdlClient? _bootMaintenanceEdlClient;
    private bool _bootMaintenanceEntryAttempted;
    private string? _bootMaintenanceBackupParent;
    private InternalBackupSet? _bootMaintenanceBackup;
    private BootMaintenanceHistoricalIdentity? _bootMaintenanceHistoricalIdentity;

    // ---------- 03 来源 ----------

    private string? _bootMaintenanceOriginalDirectory;
    private string? _bootMaintenanceProjectDirectory;
    private string? _bootMaintenancePackagePath;
    private ImportedPackage? _bootMaintenanceRepairPackage;
    private EdlRawBootTools? _bootMaintenanceNativeTools;
    private InternalInstallDirectAssets? _bootMaintenanceAssets;
    // The directory holding only the two staged tool executables; removed when the session releases the tools.
    private string? _bootMaintenanceAssetsDirectory;

    // Set when the last leave stopped because its device probe failed (no reset was sent): closing may then offer the
    // explicit close-only warning instead of repeating the same failing probe on every close.
    private bool _bootMaintenanceLeaveProbeFailed;

    // ---------- 04 确认与执行 ----------

    private BootMaintenanceBackend? _bootMaintenanceBackend;
    private bool _bootMaintenanceExecuteAttempted;
    private bool _bootMaintenanceOperationActive;

    // 运行时现场：最后一次真实结果、错误与进度；重绘时据此恢复，而不是清空。
    private BootMaintenanceResult? _bootMaintenanceLastResult;
    private string? _bootMaintenanceLastError;
    private UiMessage? _bootMaintenanceLastPreparationMessage;
    private InternalInstallProgress? _bootMaintenanceLastProgress;
    private bool _bootMaintenanceProgressTerminal;

    // 每个确认号只弹一次完成提示；复位的显式状态。
    private string? _bootMaintenanceCompletedConfirmationId;
    private bool _bootMaintenanceResetAttempted;
    private bool _bootMaintenanceResetAcked;

    // 进度日志只在阶段 / 槽位 / IO 阶段边界追加，不逐字节刷屏。
    private string? _bootMaintenanceLoggedStage;
    private string? _bootMaintenanceLoggedSlot;
    private string? _bootMaintenanceLoggedIoPhase;

    // ================================================================ 状态谓词（与 WPF 相同）

    private MaintenanceMode CurrentBootMaintenanceMode => _bootMaintenanceTag switch
    {
        "prepare" => MaintenanceMode.BeforeUpdate,
        "repair" => MaintenanceMode.AfterUpdate,
        _ => throw new InvalidOperationException(
            $"Unknown boot maintenance mode '{_bootMaintenanceTag}'; no default fallback."),
    };

    private UiMessage BootMaintenanceModeMessage() =>
        M(_bootMaintenanceTag == "prepare" ? "Dynamic.Mode.Prepare" : "Dynamic.Mode.Repair");

    /// <summary>Per-window work folder under the cache (the WPF window uses its environment work session).</summary>
    private string BootMaintenanceWorkRoot
    {
        get
        {
            _bootMaintenanceWorkRoot ??= Path.Combine(MacCacheRoot, "boot-maintenance-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_bootMaintenanceWorkRoot);
            return _bootMaintenanceWorkRoot;
        }
    }

    /// <summary>已发起真实写入但结果不是真实 Completed：功能切换与关闭一律拒绝，现场保留。</summary>
    private bool HasUnconfirmedBootMaintenanceWrite
    {
        get
        {
            InternalInstallWriteState? writeState;
            BootMaintenanceOutcome? outcome;
            if (_bootMaintenanceBackend?.Snapshot is { } snapshot)
            {
                writeState = snapshot.WriteState;
                outcome = snapshot.Outcome;
            }
            else if (_bootMaintenanceLastResult is { } last)
            {
                writeState = last.WriteState;
                outcome = last.Outcome;
            }
            else
            {
                return false;
            }

            return writeState != InternalInstallWriteState.NoneIssued
                && outcome != BootMaintenanceOutcome.Completed;
        }
    }

    /// <summary>复位已尝试但从未收到确认：界面任何清空都不能把这种状态抹掉。</summary>
    private bool HasUnknownBootMaintenanceReset =>
        _bootMaintenanceResetAttempted && !_bootMaintenanceResetAcked;

    // 持久保护状态：正在执行，或后端已有未确认写入 / 未知复位。_busy 只参与控件可用性，不计入保护。
    /// <summary>A real Completed run whose every write was verified; kept until the session is released.</summary>
    private bool IsBootMaintenanceCompleted =>
        _bootMaintenanceLastResult is { Outcome: BootMaintenanceOutcome.Completed, WriteState: InternalInstallWriteState.AllVerified };

    private bool ProtectedBootMaintenanceState =>
        _bootMaintenanceOperationActive
        || HasUnconfirmedBootMaintenanceWrite
        || HasUnknownBootMaintenanceReset;

    /// <summary>The WPF <c>HasInternalInstallLiveEdlState</c>: an entry was attempted or a 9008 endpoint is bound.</summary>
    private bool HasBootMaintenanceLiveEdlState =>
        _bootMaintenanceEntryAttempted || _bootMaintenanceEdlEntry is not null;

    /// <summary>The tablet is (or may be) in 9008 for this page, or an outcome on it is still unresolved.</summary>
    private bool HasBootMaintenanceDeviceSession =>
        HasBootMaintenanceLiveEdlState
        || _bootMaintenanceEdlClient is not null
        || _bootMaintenanceDeviceOperationActive
        || ProtectedBootMaintenanceState;

    /// <summary>
    /// The full (Fastboot round-trip) check passed and its Android identity is complete; a model whose maintenance
    /// write route is not open (TB710FU) is no proof, exactly as the WPF <c>HasCheckedInternalInstallDevice</c> in a
    /// shared mode.
    /// </summary>
    private bool HasCheckedBootMaintenanceDevice
    {
        get
        {
            var result = _bootMaintenanceDeviceCheck;
            if (result is null
                || !result.Succeeded
                || result.AndroidReturn != AndroidReturnState.Verified
                || result.Android is null)
            {
                return false;
            }

            var android = result.Android;
            var identity = android.Identity;
            if (identity is null)
            {
                return false;
            }

            return !string.IsNullOrWhiteSpace(identity.Model)
                && !DeviceModelRoutes.IsWriteRoutePending(identity.Model)
                && !string.IsNullOrWhiteSpace(identity.Serial)
                && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
                && !string.IsNullOrWhiteSpace(android.SocSerial);
        }
    }

    /// <summary>
    /// 进入备份相关步骤的正面证据：真实完整检查通过，或已建立真实 9008 只读会话（历史身份已绑定、
    /// 首次 Sahara 已证明、entry 与工具齐备）。
    /// </summary>
    private bool HasBootMaintenanceDeviceProof =>
        HasCheckedBootMaintenanceDevice
        || (_bootMaintenanceHistoricalIdentity is not null
            && _bootMaintenanceEdlClient is { } client
            && client.HasInitialSaharaProof
            && _bootMaintenanceEdlEntry is not null
            && _bootMaintenanceEdlTools is not null);

    private static bool IsBootMaintenanceAndroidComplete(AndroidMaintenanceIdentity? android)
    {
        if (android is null)
        {
            return false;
        }

        var identity = android.Identity;
        return identity is not null
            && !string.IsNullOrWhiteSpace(identity.Model)
            && !string.IsNullOrWhiteSpace(identity.Serial)
            && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
            && !string.IsNullOrWhiteSpace(android.SocSerial);
    }

    /// <summary>共享安卓读取事实：当前选中的真实 adb 设备身份已完整读取；不表示锁态或备份就绪。</summary>
    private bool HasBootMaintenanceSharedAndroidProof =>
        !_bootMaintenanceAlreadyEdl
        && IsBootMaintenanceAndroidComplete(_bootMaintenanceSharedAndroid)
        && string.Equals(
            _bootMaintenanceSharedAndroid!.Identity!.Serial,
            SelectedBootMaintenanceDevice()?.Serial,
            StringComparison.Ordinal);

    /// <summary>备份前置门槛：完整维护证明，或共享安卓身份读取事实。</summary>
    private bool HasBootMaintenanceBackupPrerequisite =>
        HasBootMaintenanceDeviceProof || HasBootMaintenanceSharedAndroidProof;

    /// <summary>备份使用的真实安卓对象：完整检查优先；否则共享读取事实。</summary>
    private AndroidMaintenanceIdentity? CurrentBootMaintenanceAndroid =>
        HasCheckedBootMaintenanceDevice
            ? _bootMaintenanceDeviceCheck!.Android
            : IsBootMaintenanceAndroidComplete(_bootMaintenanceSharedAndroid) ? _bootMaintenanceSharedAndroid : null;

    private static bool BootMaintenanceAndroidMatches(AndroidMaintenanceIdentity expected, AndroidMaintenanceIdentity actual)
    {
        var left = expected.Identity;
        var right = actual.Identity;
        if (left is null || right is null)
        {
            return false;
        }

        return string.Equals(left.Model, right.Model, StringComparison.OrdinalIgnoreCase)
            && string.Equals(left.Serial, right.Serial, StringComparison.Ordinal)
            && string.Equals(left.Firmware?.DisplayId, right.Firmware?.DisplayId, StringComparison.Ordinal)
            && string.Equals(expected.SocSerial, actual.SocSerial, StringComparison.Ordinal);
    }

    // ================================================================ 打开 / 离开页面

    /// <summary>
    /// The home card: a different maintenance mode starts from a clean page (the WPF window resets the shared
    /// pages when the function changes); the same mode resumes where it was. Opening the page touches no device.
    /// </summary>
    private void ShowBootMaintenancePage(string tag)
    {
        if (!_environmentReady)
        {
            return;
        }

        if (!string.Equals(tag, _bootMaintenanceTag, StringComparison.Ordinal))
        {
            if (HasBootMaintenanceDeviceSession)
            {
                return;
            }

            _bootMaintenanceTag = tag;
            ResetBootMaintenanceUiState();
        }

        ShowView(BootMaintenancePage);
        RenderBootMaintenancePages();
        BootMaintenancePage.ScrollToHome();
    }

    /// <summary>「← 功能选择」：走维护自己的离开确认（预写入现场一次复位），拒绝时现场原样保留。</summary>
    private async void OnBootMaintenanceBackHome(object? sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        if (!await ConfirmLeaveBootMaintenanceAsync())
        {
            RefreshBootMaintenanceActions();
            return;
        }

        ResetBootMaintenanceUiState();
        ShowView(HomePage);
        RefreshActions();
    }

    // ================================================================ 导航

    private bool CanEnterBootMaintenanceStep(int step)
    {
        if (_busy || _bootMaintenanceOperationActive)
        {
            return false;
        }

        if (ProtectedBootMaintenanceState)
        {
            return step == 3;
        }

        return step switch
        {
            0 => true,
            // 进入备份页只要求事实门槛：完整证明或共享安卓读取事实；准备 / 执行仍走完整证明。
            1 => HasBootMaintenanceBackupPrerequisite,
            2 => _bootMaintenanceBackup is not null && HasBootMaintenanceDeviceProof,
            3 => _bootMaintenanceBackend is { } backend
                && backend.Prepared is { } prepared
                && prepared.Mode == CurrentBootMaintenanceMode
                && !_bootMaintenanceExecuteAttempted,
            _ => false,
        };
    }

    // “下一步”在来源页（step 2）的启用条件：只校验真实备份与必填路径；真正校验在后端执行。
    private bool CanLeaveBootMaintenanceStep(int step)
    {
        if (step < 2)
        {
            return CanEnterBootMaintenanceStep(step + 1);
        }

        if (step != 2 || _busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState)
        {
            return false;
        }

        if (_bootMaintenanceBackup is null || !HasBootMaintenanceDeviceProof)
        {
            return false;
        }

        // BeforeUpdate 必须已选原厂恢复来源；AfterUpdate 允许项目/安装包为空（可能沿用模板）。
        return CurrentBootMaintenanceMode == MaintenanceMode.AfterUpdate
            || !string.IsNullOrWhiteSpace(_bootMaintenanceOriginalDirectory);
    }

    private bool CanExecuteBootMaintenance() =>
        _bootMaintenanceBackend is { } backend
        && backend.Prepared is { } prepared
        && prepared.Mode == CurrentBootMaintenanceMode
        && !_bootMaintenanceExecuteAttempted
        && !_bootMaintenanceResetAttempted
        && !ProtectedBootMaintenanceState
        && !_busy
        && !_bootMaintenanceOperationActive
        && BootMaintenanceRiskCheck.IsChecked == true;

    private void OnBootMaintenanceNavChecked(object? sender, RoutedEventArgs e)
    {
        if (_suppressBootMaintenanceNav || sender is not RadioButton { IsChecked: true, Tag: string tag })
        {
            return;
        }

        NavigateBootMaintenanceStep(int.Parse(tag, CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// 维护四步向导唯一的步骤切换入口。忙碌或未满足 <see cref="CanEnterBootMaintenanceStep"/> 时直接拒绝并
    /// 恢复导航勾选，绝不允许跳过前面的步骤。
    /// </summary>
    private void NavigateBootMaintenanceStep(int step)
    {
        if (_busy || _bootMaintenanceOperationActive || step is < 0 or > 3)
        {
            RestoreBootMaintenanceNav();
            return;
        }

        if (step != _bootMaintenanceStep && !CanEnterBootMaintenanceStep(step))
        {
            RestoreBootMaintenanceNav();
            return;
        }

        _bootMaintenanceStep = step;
        RenderBootMaintenancePages();
        BootMaintenancePage.ScrollToHome();
    }

    private void RestoreBootMaintenanceNav()
    {
        _suppressBootMaintenanceNav = true;
        try
        {
            BootMaintenanceNavCheck.IsChecked = _bootMaintenanceStep == 0;
            BootMaintenanceNavBackup.IsChecked = _bootMaintenanceStep == 1;
            BootMaintenanceNavSources.IsChecked = _bootMaintenanceStep == 2;
            BootMaintenanceNavConfirm.IsChecked = _bootMaintenanceStep == 3;
        }
        finally
        {
            _suppressBootMaintenanceNav = false;
        }
    }

    private void OnBootMaintenancePrevious(object? sender, RoutedEventArgs e)
    {
        if (!_busy && _bootMaintenanceStep > 0)
        {
            NavigateBootMaintenanceStep(_bootMaintenanceStep - 1);
        }
    }

    /// <summary>其他维护步骤纯导航；来源页「下一步」是真实准备。</summary>
    private async void OnBootMaintenanceNext(object? sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        if (_bootMaintenanceStep == 2)
        {
            await PrepareBootMaintenanceConfirmationAsync();
            return;
        }

        NavigateBootMaintenanceStep(_bootMaintenanceStep + 1);
    }

    // ================================================================ 渲染

    private void RenderBootMaintenancePages()
    {
        RestoreBootMaintenanceNav();

        SetText(BootMaintenanceModeTitle, BootMaintenanceModeMessage());
        SetText(BootMaintenanceModeHint, _bootMaintenanceTag == "prepare" ? "Dynamic.ModeHint.Prepare" : "Dynamic.ModeHint.Repair");
        SetText(BootMaintenanceActionButtonText, _bootMaintenanceTag == "prepare" ? "Dynamic.Action.Prepare" : "Dynamic.Action.Repair");

        BootMaintenanceCheckPage.IsVisible = _bootMaintenanceStep == 0;
        BootMaintenanceBackupPage.IsVisible = _bootMaintenanceStep == 1;
        BootMaintenanceSourcesPage.IsVisible = _bootMaintenanceStep == 2;
        BootMaintenanceConfirmPage.IsVisible = _bootMaintenanceStep == 3;

        // 原始目录在入口页与来源页呈现同一真实值。
        BootMaintenanceEntryOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;
        BootMaintenanceOriginalBox.Text = _bootMaintenanceOriginalDirectory ?? string.Empty;
        BootMaintenanceProjectBox.Text = _bootMaintenanceProjectDirectory ?? string.Empty;
        BootMaintenanceBackupFolderBox.Text = _bootMaintenanceBackupParent ?? string.Empty;

        // 只有更新后修复需要项目备份与安装包。
        BootMaintenanceRepairSourcesRow.IsVisible = CurrentBootMaintenanceMode == MaintenanceMode.AfterUpdate;

        SetText(BootMaintenanceSourcesTitle, "Dynamic.BootMaintenance.SourceTitle");
        SetText(BootMaintenanceSourcesLead, "Dynamic.BootMaintenance.SourceLead");
        SetText(BootMaintenanceConfirmTitle, "Dynamic.BootMaintenance.ConfirmTitle");

        RenderBootMaintenanceCheckButton();
        RenderBootMaintenanceSourcesStatus();
        RenderBootMaintenanceConfirmPage();
        RenderBootMaintenancePower();
        RefreshBootMaintenanceActions();
    }

    private void RenderBootMaintenanceCheckButton() =>
        SetText(
            BootMaintenanceCheckButtonText,
            _bootMaintenanceAlreadyEdl ? "Dynamic.BootMaintenance.CheckEdl" : "Dynamic.Shared.CheckTablet");

    private void RenderBootMaintenanceSourcesStatus()
    {
        var prepared = _bootMaintenanceBackend?.Prepared;
        if (prepared is null)
        {
            // 真实失败必须保留在来源页上：绝不用「未准备」覆盖已存的真实错误。
            if (_bootMaintenanceLastError is not null)
            {
                SetText(BootMaintenancePrepareStatusText,
                    _bootMaintenanceLastPreparationMessage ?? M("Dynamic.BootMaintenance.Status.PrepareFailed"));
                return;
            }

            if (_bootMaintenanceOperationActive)
            {
                SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.Status.Preparing"));
                return;
            }

            SetText(BootMaintenancePrepareStatusText, "Dynamic.BootMaintenance.NotPrepared");
            return;
        }

        SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.PreparedSummary",
            UiText.ModelName(prepared.Model),
            prepared.AndroidSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty));
    }

    private void RenderBootMaintenanceConfirmPage()
    {
        var prepared = _bootMaintenanceBackend?.Prepared;

        BootMaintenanceSlotsPanel.Children.Clear();
        BootMaintenanceRegionsHost.Children.Clear();

        if (prepared is null)
        {
            SetText(BootMaintenanceDeviceText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceBackupLocationsText, "Dynamic.RawValue", string.Empty);
            SetText(BootMaintenanceRiskText, BootMaintenanceRiskKey(CurrentBootMaintenanceMode));
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.BootMaintenance.NotPrepared");
            SetText(BootMaintenanceProgressText, "Dynamic.RawValue", string.Empty);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 0;
            return;
        }

        // 设备摘要：只陈述真实准备的型号/序列号/当前槽位，不断言系统可启动性或 A/B 双槽完整。
        SetText(BootMaintenanceDeviceText, M("Dynamic.BootMaintenance.DeviceSummary",
            UiText.ModelName(prepared.Model),
            prepared.AndroidSerial ?? string.Empty,
            prepared.SocSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty));

        // 备份位置摘要：本次回滚备份 / 原厂来源 / 项目来源 / 证据目录，四者各自独立。
        SetText(BootMaintenanceBackupLocationsText, M("Dynamic.BootMaintenance.BackupLocations",
            _bootMaintenanceBackup?.DirectoryPath ?? prepared.BackupDirectory,
            _bootMaintenanceOriginalDirectory ?? string.Empty,
            _bootMaintenanceProjectDirectory ?? string.Empty,
            prepared.EvidenceDirectory));

        foreach (var slot in prepared.Slots)
        {
            var slotText = NewBootMaintenanceCaption();
            SetText(slotText, slot.WillWrite
                ? M("Dynamic.BootMaintenance.SlotWrite",
                    slot.Slot ?? string.Empty,
                    slot.SourceSlot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind))
                : M("Dynamic.BootMaintenance.SlotKeep",
                    slot.Slot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind)));
            BootMaintenanceSlotsPanel.Children.Add(slotText);
        }

        foreach (var region in prepared.Regions)
        {
            var regionText = NewBootMaintenanceCaption();
            SetText(regionText, M(
                region.WillWrite ? "Dynamic.BootMaintenance.RegionWrite" : "Dynamic.BootMaintenance.RegionKeep",
                region.Role ?? string.Empty,
                region.Slot ?? string.Empty,
                region.Lun,
                region.StartSector,
                region.SectorCount,
                region.Length));
            BootMaintenanceRegionsHost.Children.Add(regionText);
        }

        SetText(BootMaintenanceRiskText, prepared.Regions.Any(r => r.WillWrite && (r.Role is "abl_a" or "abl_b"))
            ? "Dynamic.BootMaintenance.Repair.RiskAbl"
            : BootMaintenanceRiskKey(CurrentBootMaintenanceMode));

        // 重绘不得清空运行时现场：已保存的结果 / 错误 / 进度按其重绘。
        RenderBootMaintenanceRuntimeStatus();
    }

    private static TextBlock NewBootMaintenanceCaption() => new()
    {
        Classes = { "CaptionText" },
        Margin = new Avalonia.Thickness(0, 4, 0, 0),
        TextWrapping = Avalonia.Media.TextWrapping.Wrap,
    };

    private static string BootMaintenanceRiskKey(MaintenanceMode mode) => mode switch
    {
        MaintenanceMode.BeforeUpdate => "Dynamic.BootMaintenance.Risk.BeforeUpdate",
        MaintenanceMode.AfterUpdate => "Dynamic.BootMaintenance.Risk.AfterUpdate",
        _ => throw new InvalidOperationException($"Unknown maintenance mode '{mode}'."),
    };

    private static UiMessage DescribeBootMaintenanceSourceKind(BootMaintenanceSourceKind sourceKind) => sourceKind switch
    {
        BootMaintenanceSourceKind.Empty => M("Dynamic.BootMaintenance.SourceKind.Empty"),
        BootMaintenanceSourceKind.StockOriginal => M("Dynamic.BootMaintenance.SourceKind.StockOriginal"),
        BootMaintenanceSourceKind.Project => M("Dynamic.BootMaintenance.SourceKind.Project"),
        _ => throw new InvalidOperationException($"Unknown boot maintenance source kind '{sourceKind}'."),
    };

    private void RenderBootMaintenancePower() =>
        SetText(BootMaintenancePowerText, PowerMessage(_bootMaintenancePower));

    private void RenderBootMaintenanceCheckPlaceholders()
    {
        SetText(BootMaintenanceModelText, "Dynamic.RawValue", UnknownValue);
        SetText(BootMaintenanceSerialText, "Dynamic.RawValue", UnknownValue);
        SetText(BootMaintenanceFirmwareText, "Dynamic.RawValue", UnknownValue);
        SetText(BootMaintenanceBootloaderText, "Dynamic.RawValue", UnknownValue);
        SetText(BootMaintenanceRouteText, "Dynamic.RawValue", UnknownValue);
        SetText(BootMaintenanceCheckProgressText, "Static.InternalInstall.Check.ProgressInitial");
        SetText(BootMaintenanceCheckStatusText, "Static.InternalInstall.Check.StatusInitial");
        RenderBootMaintenancePower();
    }

    private void RenderBootMaintenanceBackupDetail()
    {
        var set = _bootMaintenanceBackup;
        SetText(BootMaintenanceBackupDirectoryText, "Dynamic.RawValue", set?.DirectoryPath ?? UnknownValue);
        SetText(BootMaintenanceBackupManifestText, "Dynamic.RawValue", set?.ManifestPath ?? UnknownValue);
        SetText(BootMaintenanceBackupManifestHashText, "Dynamic.RawValue", set?.ManifestSha256 ?? UnknownValue);
    }

    private void AppendBootMaintenanceLog(UiMessage message)
    {
        var row = _l.AppendLogRow(BootMaintenanceLogList, message, MaxLogRows);
        row.FontSize = 12;
        row.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        row.Margin = new Avalonia.Thickness(0, 0, 0, 4);
        row[!TextBlock.ForegroundProperty] = row.GetResourceObservable("MutedBrush").ToBinding();

        BootMaintenanceLogEmptyText.IsVisible = false;
        BootMaintenanceLogScrollViewer.ScrollToEnd();
    }

    // ================================================================ 可用性

    /// <summary>Enables what the current state allows (the WPF RefreshBootMaintenanceActions + shared actions).</summary>
    private void RefreshBootMaintenanceActions()
    {
        var idle = !_busy && !_bootMaintenanceOperationActive;
        var protectedState = ProtectedBootMaintenanceState;

        BootMaintenanceNavCheck.IsEnabled = CanEnterBootMaintenanceStep(0);
        BootMaintenanceNavBackup.IsEnabled = CanEnterBootMaintenanceStep(1);
        BootMaintenanceNavSources.IsEnabled = CanEnterBootMaintenanceStep(2);
        BootMaintenanceNavConfirm.IsEnabled = CanEnterBootMaintenanceStep(3);

        BootMaintenancePrevButton.IsEnabled = _bootMaintenanceStep > 0 && CanEnterBootMaintenanceStep(_bootMaintenanceStep - 1);
        BootMaintenanceNextButton.IsVisible = _bootMaintenanceStep < 3;
        BootMaintenanceNextButton.IsEnabled = CanLeaveBootMaintenanceStep(_bootMaintenanceStep);
        BootMaintenanceActionButton.IsVisible = _bootMaintenanceStep == 3;
        BootMaintenanceActionButton.IsEnabled = CanExecuteBootMaintenance();
        BootMaintenanceBackButton.IsEnabled = idle && !_bootMaintenanceDeviceOperationActive;

        BootMaintenanceEntryOriginalBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenanceOriginalBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenanceProjectBrowseButton.IsEnabled = idle && !protectedState;
        BootMaintenancePackageBox.IsEnabled = idle && !protectedState;

        // 9008 勾选与检查按钮在繁忙/保护状态下禁用；存在活跃 EDL 状态时不允许重开安卓检查。
        BootMaintenanceAlreadyEdlCheck.IsEnabled = idle && !protectedState && !HasBootMaintenanceLiveEdlState;
        BootMaintenanceCheckButton.IsEnabled = idle && !HasBootMaintenanceLiveEdlState;
        BootMaintenanceFastbootCheckButton.IsEnabled = idle
            && !_bootMaintenanceDeviceOperationActive
            && !protectedState
            && !HasBootMaintenanceLiveEdlState
            && !_bootMaintenanceAlreadyEdl;

        // 维护模式只允许全新备份；全新按钮按真实门槛刷新。
        var checkedDevice = HasBootMaintenanceBackupPrerequisite;
        var validParent = !string.IsNullOrWhiteSpace(_bootMaintenanceBackupParent)
            && Directory.Exists(_bootMaintenanceBackupParent);
        var canReuseSession = _bootMaintenanceEdlClient is not null
            && _bootMaintenanceEdlEntry is not null
            && _bootMaintenanceEdlTools is not null;
        BootMaintenanceBackupBrowseButton.IsEnabled = idle && !protectedState && checkedDevice;
        // A completed session keeps its result and backup on screen until leave, but never starts another backup:
        // its client belongs to a session that has ended and the tablet may already be back in Android.
        BootMaintenanceBackupButton.IsEnabled = idle
            && !protectedState
            && !IsBootMaintenanceCompleted
            && checkedDevice
            && validParent
            && (!HasBootMaintenanceLiveEdlState || canReuseSession);

        var many = _bootMaintenanceDeviceChoices.Count > 0;
        BootMaintenanceDevicesLabel.IsVisible = many;
        BootMaintenanceDevicesCombo.IsVisible = many;
        BootMaintenanceDevicesCombo.IsEnabled = idle
            && !protectedState
            && !HasBootMaintenanceLiveEdlState
            && !_bootMaintenanceAlreadyEdl
            && many;

        // 只有仍存在真实 9008 现场且未真实完成时才显示退出面板；完成后隐藏。
        var completed = _bootMaintenanceLastResult is { } result
            && result.Outcome == BootMaintenanceOutcome.Completed
            && result.WriteState == InternalInstallWriteState.AllVerified;
        var showExit = HasBootMaintenanceLiveEdlState && !completed;
        BootMaintenanceExitPanel.IsVisible = showExit;
        if (showExit)
        {
            BootMaintenanceExitButton.IsEnabled = idle
                && !_bootMaintenanceDeviceOperationActive
                && !HasUnknownBootMaintenanceReset
                && !HasUnconfirmedBootMaintenanceWrite
                && _bootMaintenanceEdlClient != null;
            SetText(
                BootMaintenanceExitStatusText,
                HasUnknownBootMaintenanceReset || HasUnconfirmedBootMaintenanceWrite
                    ? "Dynamic.BootMaintenance.Exit.LeaveBlocked"
                    : "Dynamic.BootMaintenance.Exit.Ready");
        }
    }

    // ================================================================ 01 检查

    private ConnectedDevice? SelectedBootMaintenanceDevice() =>
        BootMaintenanceDevicesCombo.SelectedIndex is int index && index >= 0 && index < _bootMaintenanceDeviceChoices.Count
            ? _bootMaintenanceDeviceChoices[index]
            : null;

    private void PopulateBootMaintenanceDevices(IReadOnlyList<ConnectedDevice> devices, string? previousSerial)
    {
        _bootMaintenanceDeviceChoices = devices;
        _suppressBootMaintenanceDeviceSelection = true;
        try
        {
            BootMaintenanceDevicesCombo.ItemsSource = devices
                .Select(device => $"{device.Serial}  ({_l.T(ConnectionStateKey(device.ConnectionState))})")
                .ToList();
            // 唯一设备直接选中；多台时只恢复用户之前选中的那一台，绝不预选第一项。
            var index = devices.Count == 1 ? 0 : devices.ToList().FindIndex(device => device.Serial == previousSerial);
            BootMaintenanceDevicesCombo.SelectedIndex = index;
        }
        finally
        {
            _suppressBootMaintenanceDeviceSelection = false;
        }
    }

    /// <summary>用户在下拉框里换了设备：上一台设备的一切结论立即作废，并回到第 0 步。</summary>
    private void OnBootMaintenanceDeviceSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (_busy || _suppressBootMaintenanceDeviceSelection || _bootMaintenanceDeviceOperationActive)
        {
            return;
        }

        ResetBootMaintenanceCheckState();
        _bootMaintenanceStep = 0;
        RenderBootMaintenancePages();
    }

    private async void OnCheckBootMaintenanceDevice(object? sender, RoutedEventArgs e) =>
        await CheckBootMaintenanceDeviceAsync(advanced: false);

    private async void OnCheckBootMaintenanceDeviceAdvanced(object? sender, RoutedEventArgs e) =>
        await CheckBootMaintenanceDeviceAsync(advanced: true);

    /// <summary>
    /// 「检查平板」：默认只读安卓身份与 SoC 序列号（不经 Fastboot）；「高级：核验 Bootloader」走完整自动检查；
    /// 已勾选「平板已在 9008」时走历史 9008 只读核对。
    /// </summary>
    private async Task CheckBootMaintenanceDeviceAsync(bool advanced)
    {
        if (_busy || _bootMaintenanceDeviceOperationActive)
        {
            return;
        }

        if (_bootMaintenanceAlreadyEdl && !advanced)
        {
            await CheckBootMaintenanceEdlAsync();
            return;
        }

        // 存在真实 9008 会话：不允许把平板当安卓重新检查，保留现状。
        if (HasBootMaintenanceLiveEdlState)
        {
            SetText(BootMaintenanceCheckStatusText, M("Dynamic.Workflow.NotPrepared", BootMaintenanceModeMessage()));
            return;
        }

        // 任何维护受保护状态（未确认写入 / 未知复位）都不允许发起新的安卓检查。
        if (ProtectedBootMaintenanceState)
        {
            return;
        }

        if (_adbPath is null)
        {
            SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.ToolsRequired");
            return;
        }

        var previousSerial = SelectedBootMaintenanceDevice()?.Serial;

        // 重新检查前先清掉上一轮结论：结果、电量与派生界面一起回到「未检查」。
        ResetBootMaintenanceCheckState();

        _bootMaintenanceDeviceOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Listing");
                    var transport = Transport;
                    var devices = await transport.ListDevicesAsync(token);
                    PopulateBootMaintenanceDevices(devices, previousSerial);

                    if (devices.Count == 0)
                    {
                        SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.NoDevices");
                        return;
                    }

                    // 唯一设备直接用；多台只认用户已经选中的那一台。
                    var target = devices.Count == 1 ? devices[0] : SelectedBootMaintenanceDevice();
                    if (target is null)
                    {
                        SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.MultipleNeedSelection", devices.Count);
                        return;
                    }

                    if (target.ConnectionState != ConnectionState.Authorized)
                    {
                        SetText(
                            BootMaintenanceCheckStatusText,
                            M("Dynamic.InternalInstall.Check.NotAuthorized", target.Serial, M(ConnectionStateKey(target.ConnectionState))));
                        return;
                    }

                    SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.Started", target.Serial);

                    if (!advanced)
                    {
                        await CheckBootMaintenanceSharedAndroidAsync(transport, target.Serial, token);
                        return;
                    }

                    var progress = new Progress<InternalDeviceCheckProgress>(report =>
                    {
                        // 终态一旦写出，迟到的进度回调不允许再覆盖它。
                        if (acceptProgress)
                        {
                            SetText(BootMaintenanceCheckProgressText, CheckStageKey(report.Stage));
                        }
                    });

                    var check = new InternalInstallDeviceCheck(transport.AdbPath, transport.FastbootPath, _runner);
                    var result = await check.CheckAsync(target.Serial, progress, token);
                    acceptProgress = false;
                    _bootMaintenanceDeviceCheck = result;
                    RenderBootMaintenanceDeviceCheck(result);

                    if (!result.Succeeded && !result.Cancelled)
                    {
                        AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Check.FailedStage", M(CheckStageKey(result.FailedStage))));
                        AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Check.Failed", Placeholder(result.Error)));
                    }

                    if (result.Succeeded && result.AndroidReturn == AndroidReturnState.Verified)
                    {
                        _bootMaintenancePower = await CapturePowerAsync(transport.AdbPath, result.Android!.Identity.Serial, token);
                    }

                    RenderBootMaintenancePower();
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    acceptProgress = false;
                    _bootMaintenanceDeviceCheck = null;
                    _bootMaintenancePower = null;
                    RenderBootMaintenanceCheckPlaceholders();
                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message) ? UnknownValue : exception.Message;
                    SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
                    SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
                    AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Check.Failed", diagnostic));
                }
            });
        }
        finally
        {
            _bootMaintenanceDeviceOperationActive = false;
            RefreshActions();
        }
    }

    /// <summary>
    /// 默认检查：只读一次真实身份与 SoC 序列号，按实际型号核对可信配置完整且支持这台平板后，才提交读取事实
    /// 并采样电量。绝不发 Fastboot 命令，也绝不声称已核实 Bootloader 锁态。
    /// </summary>
    private async Task CheckBootMaintenanceSharedAndroidAsync(DeviceTransport transport, string serial, CancellationToken token)
    {
        _bootMaintenanceSharedAndroid = null;
        SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Progress.ReadingAndroid");

        var identity = await transport.ReadAdbIdentityAsync(serial, token);
        var android = await new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner)
            .ReadAndroidAsync(identity, token);

        // 只开放识别与只读检查的型号（TB710FU）：如实说明，不提交读取事实，后续维护入口保持关闭。
        if (DeviceModelRoutes.IsWriteRoutePending(android.Identity?.Model))
        {
            SetText(BootMaintenanceCheckStatusText, M("Dynamic.Model.RoutePending", UiText.ModelName(android.Identity?.Model)));
            return;
        }

        var profile = EdlDeviceProfiles.FindByModel(android.Identity?.Model);
        if (android.Identity is null
            || profile is null
            || !profile.IsComplete
            || !profile.SupportsIdentity(android.Identity)
            || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            SetText(
                BootMaintenanceCheckStatusText,
                M("Dynamic.InternalInstall.Backup.ProfileUnavailable",
                    UiText.ModelName(android.Identity?.Model),
                    Placeholder(android.Identity?.Firmware?.DisplayId)));
            return;
        }

        // 与完整检查同源：只在确认回到安卓后只读采样一次电量；读不到保持未知。
        _bootMaintenancePower = await CapturePowerAsync(transport.AdbPath, serial, token);
        RenderBootMaintenancePower();

        _bootMaintenanceSharedAndroid = android;
        SetText(BootMaintenanceModelText, UiText.ModelName(android.Identity.Model));
        SetText(BootMaintenanceSerialText, "Dynamic.RawValue", Placeholder(android.Identity.Serial));
        SetText(BootMaintenanceFirmwareText, "Dynamic.RawValue", Placeholder(android.Identity.Firmware?.DisplayId));
        SetText(BootMaintenanceBootloaderText, BootStateKey(BootloaderState.Unknown));
        SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Progress.Completed");
        SetText(BootMaintenanceCheckStatusText, M("Dynamic.Shared.IdentityReadStatus"));
    }

    /// <summary>把真实完整检查结果写进字段：型号 / 序列号 / 固件 / 引导锁全部来自返回事实。</summary>
    private void RenderBootMaintenanceDeviceCheck(InternalDeviceCheckResult result)
    {
        var identity = result.Android?.Identity;
        var firmware = identity?.Firmware;
        SetText(BootMaintenanceModelText, UiText.ModelName(identity?.Model));
        SetText(BootMaintenanceSerialText, "Dynamic.RawValue", Placeholder(identity?.Serial ?? result.FastbootSerial));
        SetText(BootMaintenanceFirmwareText, "Dynamic.RawValue", Placeholder(firmware?.DisplayId ?? firmware?.BuildFingerprint));
        SetText(BootMaintenanceBootloaderText, BootStateKey(result.FastbootLockState));

        if (result.Cancelled)
        {
            SetText(BootMaintenanceRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Cancelled");
            SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.Cancelled");
            return;
        }

        if (!result.Succeeded)
        {
            SetText(BootMaintenanceRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(BootMaintenanceCheckProgressText, M("Dynamic.InternalInstall.Check.FailedStage", M(CheckStageKey(result.FailedStage))));
            var error = Placeholder(result.Error);
            SetText(
                BootMaintenanceCheckStatusText,
                result.AndroidReturn == AndroidReturnState.Unconfirmed
                    ? M("Dynamic.InternalInstall.Check.ReturnUnconfirmed", error)
                    : M("Dynamic.InternalInstall.Check.Failed", error));
            return;
        }

        SetText(BootMaintenanceCheckProgressText, "Dynamic.InternalInstall.Check.Progress.Completed");
        if (HasCheckedBootMaintenanceDevice)
        {
            SetText(BootMaintenanceRouteText, "Dynamic.InternalInstall.Check.RoutePassed");
            SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.Passed");
            return;
        }

        // 检查本身通过，但该型号的维护写入路线尚未开放：如实说明，备份门槛保持关闭。
        SetText(BootMaintenanceRouteText, "Dynamic.InternalInstall.Check.RouteUnavailable");
        SetText(
            BootMaintenanceCheckStatusText,
            DeviceModelRoutes.IsWriteRoutePending(identity?.Model)
                ? M("Dynamic.Model.RoutePending", UiText.ModelName(identity?.Model))
                : M("Dynamic.InternalInstall.Check.ProfileUnavailable"));
    }

    /// <summary>
    /// 清空检查结论（WPF ResetInternalInstallCheckState）：操作进行中或受保护时拒绝；维护的预写入准备先作废；
    /// 已有 9008 会话与工具链不受影响。
    /// </summary>
    private void ResetBootMaintenanceCheckState()
    {
        if (_bootMaintenanceDeviceOperationActive || ProtectedBootMaintenanceState)
        {
            return;
        }

        InvalidateBootMaintenancePreparation();
        _bootMaintenanceDeviceCheck = null;
        _bootMaintenancePower = null;
        _bootMaintenanceSharedAndroid = null;
        ReleaseBootMaintenanceBackupObject();
        RenderBootMaintenanceBackupDetail();
        BootMaintenanceBackupProgressBar.IsIndeterminate = false;
        RenderBootMaintenanceCheckPlaceholders();
    }

    // 勾选只改变路线偏好（下一步走 9008 识别），不改变任何设备证据；
    // 已有真实 9008 会话、保护状态或繁忙时拒绝并还原勾选。
    private void OnBootMaintenanceEdlRouteChanged(object? sender, RoutedEventArgs e)
    {
        var requested = BootMaintenanceAlreadyEdlCheck.IsChecked == true;
        if (requested == _bootMaintenanceAlreadyEdl)
        {
            return;
        }

        if (_busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState || HasBootMaintenanceLiveEdlState)
        {
            BootMaintenanceAlreadyEdlCheck.IsChecked = _bootMaintenanceAlreadyEdl;
            return;
        }

        // 路线实际变化前先丢弃未写入的准备，并作废只读检查 / 电量证明；已有真实 9008 现场绝不丢弃。
        ResetBootMaintenanceCheckState();
        _bootMaintenanceHistoricalIdentity = null;
        InvalidateBootMaintenancePreparation();

        _bootMaintenanceAlreadyEdl = requested;
        RenderBootMaintenanceCheckButton();
        RefreshBootMaintenanceActions();
    }

    /// <summary>
    /// 「平板已在 9008」路线的只读核对：从历史备份读取保存身份，加载该配置自己的工具归档，
    /// 用 WaitForPresentAsync（不发 adb 命令）等待当前 9008 端点并做首次 Sahara 探测。
    /// 不读安卓、不重启、不写入、不推断锁定状态、不自动重试。
    /// </summary>
    private async Task CheckBootMaintenanceEdlAsync()
    {
        if (_busy
            || !_bootMaintenanceAlreadyEdl
            || _bootMaintenanceDeviceOperationActive
            || ProtectedBootMaintenanceState
            || HasBootMaintenanceLiveEdlState)
        {
            return;
        }

        if (_adbPath is null)
        {
            SetText(BootMaintenanceCheckStatusText, "Dynamic.InternalInstall.Check.ToolsRequired");
            return;
        }

        // 历史目录来自用户已选的原厂来源；必须有真实存在的目录作为候选历史，不在此断言载荷资格。
        var selectedDirectory = _bootMaintenanceOriginalDirectory;
        if (string.IsNullOrWhiteSpace(selectedDirectory) || !Directory.Exists(selectedDirectory))
        {
            SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.NeedHistory"));
            return;
        }

        // 备份父目录必须是已存在的独立目录，且在 ResetCheck / 临时工具解包之前落在来源目录之外。已保存的目录
        // 不满足时同样重新选择：这条路线在历史核对通过前到不了备份页，没有别处可以换掉它。
        var parent = _bootMaintenanceBackupParent;
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent) || BootMaintenanceParentConflict(parent) is not null)
        {
            var folder = await PickBootMaintenanceFolderAsync("Dynamic.InternalInstall.Backup.SelectFolderTitle");
            if (folder is null)
            {
                // 取消：一次操作都没发生。
                return;
            }

            // 新选的目录先核对，冲突就不保存，下次仍会重新选择。
            if (BootMaintenanceParentConflict(folder) is { } conflict)
            {
                SetText(BootMaintenanceCheckStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", conflict));
                return;
            }

            ApplyBootMaintenanceBackupParent(folder);
            parent = folder;
        }

        // 空闲时清掉上一轮安卓检查结论；已有 9008 会话与工具链不受影响。
        ResetBootMaintenanceCheckState();
        _bootMaintenanceHistoricalIdentity = null;
        _bootMaintenanceDeviceOperationActive = true;

        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.Checking"));

                    var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(selectedDirectory!, token);

                    var profile = history.Profile;
                    if (!profile.IsComplete
                        || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName)
                        || !profile.SupportsIdentity(history.Identity.Identity))
                    {
                        SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                        return;
                    }

                    // 只解包所选配置自己的归档，绝不回退固定资源名或固定配置。
                    EdlToolchain pendingTools;
                    await using (var archive = MacTools.Open(profile.ArchiveLogicalName!))
                    {
                        if (archive is null)
                        {
                            SetText(BootMaintenanceCheckStatusText, M("Dynamic.InternalInstall.Check.ToolsRequired"));
                            return;
                        }

                        pendingTools = await EdlToolchain.LoadAsync(
                            archive, Path.Combine(MacCacheRoot, BootMaintenanceToolchainFolder), token);
                    }

                    EdlToolchain? ownedTools = pendingTools;
                    try
                    {
                        if (!ReferenceEquals(pendingTools.Profile, profile))
                        {
                            SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                            return;
                        }

                        // WaitForPresentAsync 自己不发任何 adb 命令：只等待当前 9008 端点出现并比对保存身份。
                        SetText(BootMaintenanceBackupStatusText, M("Dynamic.BootMaintenance.Edl.Checking"));
                        var transport = Transport;
                        var entry = await Task.Run(
                            () => new EdlEntry(transport.AdbPath, _runner, Discovery)
                                .WaitForPresentAsync(history.Identity, profile, token),
                            token);

                        // 只有真实端点结果存在时才接管工具链并记录进入尝试；此前失败由 finally 清理 pendingTools。
                        _bootMaintenanceEdlTools = pendingTools;
                        ownedTools = null;
                        _bootMaintenanceEntryAttempted = true;
                        _bootMaintenanceEdlEntry = entry;

                        var client = new EdlClient(_bootMaintenanceEdlTools, entry, _runner, Discovery);
                        _bootMaintenanceEdlClient = client;

                        await Task.Run(() => client.ProbeAsync(0, true, token), token);

                        // 全部只读核对成功后才绑定历史身份；展示的是保存信息，不是当前安卓状态。
                        _bootMaintenanceHistoricalIdentity = history;
                        SetText(
                            BootMaintenanceCheckStatusText,
                            M("Dynamic.BootMaintenance.Edl.HistoricalBound",
                                UiText.ModelName(history.Model),
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
                    SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendBootMaintenanceLog(M("Dynamic.RawValue", ex.Message));
                }
                catch (Exception ex) when (DeviceModelRoutes.IsRouteRefusal(ex))
                {
                    // A historical backup of a model whose write routes are not open: refused before any firehose command.
                    SetText(BootMaintenanceCheckStatusText, M("Dynamic.Model.RoutePendingInEdl", UiText.ModelName(DeviceModelRoutes.Tb710fuModel)));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    SetText(BootMaintenanceCheckStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                }
            });
        }
        finally
        {
            _bootMaintenanceDeviceOperationActive = false;
            RenderBootMaintenanceBackupDetail();
            RefreshActions();
        }
    }

    // ================================================================ 02 备份

    private void ApplyBootMaintenanceBackupParent(string folder)
    {
        _bootMaintenanceBackupParent = folder;
        BootMaintenanceBackupFolderBox.Text = folder;
    }

    /// <summary>The selected stock or project source that <paramref name="parent"/> lies inside, or null.</summary>
    private string? BootMaintenanceParentConflict(string parent)
    {
        foreach (var source in new[] { _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source) && !IsGlobalOutputOutsideSource(parent, source!))
            {
                return source;
            }
        }

        return null;
    }

    /// <summary>
    /// 「浏览…」：只选择一个已存在的文件夹，不创建目录、不触发备份、不碰设备。
    /// 换目录会作废上一份备份对象（只释放只读锁），已有的 9008 会话与工具链保持不动。
    /// </summary>
    private async void OnBrowseBootMaintenanceBackupFolder(object? sender, RoutedEventArgs e)
    {
        if (_busy || _bootMaintenanceDeviceOperationActive || ProtectedBootMaintenanceState)
        {
            return;
        }

        var folder = await PickBootMaintenanceFolderAsync("Static.InternalInstall.Backup.FolderLabel");
        if (folder is null || _busy || ProtectedBootMaintenanceState)
        {
            return;
        }

        InvalidateBootMaintenancePreparation();
        ReleaseBootMaintenanceBackupObject();
        ApplyBootMaintenanceBackupParent(folder);
        RenderBootMaintenanceBackupDetail();
        SetText(BootMaintenanceBackupStatusText, "Dynamic.InternalInstall.Backup.Selected", folder);
        RefreshBootMaintenanceActions();
    }

    private async void OnBackupBootMaintenance(object? sender, RoutedEventArgs e) => await BackupBootMaintenanceAsync();

    /// <summary>
    /// 维护模式的全新备份（WPF BackupInternalInstallCoreAsync 的共享路线）：已在 9008 的路线复用只读核对建立的
    /// 同一会话；默认路线重新读取安卓身份、只进入一次 9008，再做只读备份并从新备份读取真实历史身份。
    /// </summary>
    private async Task BackupBootMaintenanceAsync()
    {
        if (_busy || _bootMaintenanceDeviceOperationActive || ProtectedBootMaintenanceState || IsBootMaintenanceCompleted)
        {
            return;
        }

        if (_bootMaintenanceAlreadyEdl)
        {
            await BackupBootMaintenanceEdlAsync();
            return;
        }

        var storedAndroid = CurrentBootMaintenanceAndroid;
        var parent = _bootMaintenanceBackupParent;
        if (storedAndroid is null || !HasBootMaintenanceBackupPrerequisite)
        {
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        // 备份父目录绝不能落在已选原厂 / 项目来源目录里面；来源永不作为当前目录。
        foreach (var source in new[] { _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source) && !IsGlobalOutputOutsideSource(parent, source!))
            {
                SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        // 即将开始全新备份：先作废旧准备。
        InvalidateBootMaintenancePreparation();

        var existingClient = _bootMaintenanceEdlClient;
        var entry = _bootMaintenanceEdlEntry;
        var reuse = existingClient is not null && _bootMaintenanceEdlTools is not null && entry is not null;

        if (!reuse && _bootMaintenanceEntryAttempted)
        {
            // 进入 9008 的结果尚未确认：不允许第二次自动进入，也不允许假装没有发生。
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.EntryUnconfirmed"));
            return;
        }

        var selectedIdentity = storedAndroid.Identity;

        // 维护写入路线尚未开放的型号（TB710FU）：在进入 9008 之前停下。
        if (DeviceModelRoutes.IsWriteRoutePending(selectedIdentity.Model))
        {
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.Model.RoutePending", UiText.ModelName(selectedIdentity.Model)));
            return;
        }

        var profile = EdlDeviceProfiles.FindByModel(selectedIdentity.Model);
        if (profile is null
            || !profile.IsComplete
            || !profile.SupportsIdentity(selectedIdentity)
            || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            SetText(
                BootMaintenanceBackupStatusText,
                M("Dynamic.InternalInstall.Backup.ProfileUnavailable",
                    UiText.ModelName(selectedIdentity.Model),
                    Placeholder(selectedIdentity.Firmware?.DisplayId)));
            return;
        }

        if (reuse && !BootMaintenanceAndroidMatches(storedAndroid, entry!.AndroidIdentity))
        {
            // 现有会话不是这次检查确认的那台平板：停止，但保留会话与工具，等用户回到第 1 步重查。
            ReleaseBootMaintenanceBackupObject();
            RenderBootMaintenanceBackupDetail();
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.BindingChanged"));
            RefreshBootMaintenanceActions();
            return;
        }

        // 上一份备份对象与其派生结果先作废；客户端、工具链与 9008 证据保持原样。
        ReleaseBootMaintenanceBackupObject();
        RenderBootMaintenanceBackupDetail();
        BootMaintenanceBackupProgressBar.Value = 0;
        BootMaintenanceBackupProgressBar.IsIndeterminate = true;
        // 正常进行中不得预告失败：这里只写「正在准备并校验」。
        SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.RunningNote"));

        var expected = storedAndroid;
        var parentPath = parent!;
        var transport = Transport;

        _bootMaintenanceDeviceOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                EdlToolchain? pendingTools = null;
                try
                {
                    EdlClient activeClient;
                    if (existingClient is null)
                    {
                        SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.PreparingTools"));

                        // 只解包所选可信配置自己的归档，绝不回退到固定资源名。
                        await using (var archive = MacTools.Open(profile.ArchiveLogicalName!))
                        {
                            if (archive is null)
                            {
                                acceptProgress = false;
                                SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.ToolsRequired"));
                                return;
                            }

                            pendingTools = await EdlToolchain.LoadAsync(
                                archive, Path.Combine(MacCacheRoot, BootMaintenanceToolchainFolder), token);
                        }

                        var loaded = pendingTools;
                        if (!ReferenceEquals(loaded.Profile, profile) || !profile.SupportsIdentity(expected.Identity))
                        {
                            var loadedModel = UiText.ModelName(loaded.Model);
                            var loadedBuild = loaded.AndroidBuild;
                            loaded.Dispose();
                            pendingTools = null;
                            acceptProgress = false;
                            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.ToolchainMismatch", loadedModel, loadedBuild));
                            return;
                        }

                        SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.Reproving"));

                        // 模式切换前重新读取真实安卓身份与 SoC 序列号，并与第 1 步的结果逐项比对。
                        var freshIdentity = await transport.ReadAdbIdentityAsync(expected.Identity.Serial, token);
                        var freshAndroid = await new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner)
                            .ReadAndroidAsync(freshIdentity, token);

                        if (!BootMaintenanceAndroidMatches(expected, freshAndroid)
                            || !profile.SupportsIdentity(freshAndroid.Identity))
                        {
                            loaded.Dispose();
                            pendingTools = null;
                            acceptProgress = false;
                            InvalidateBootMaintenanceCheckFromMismatch();
                            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
                            return;
                        }

                        // 已有采样时才在进入 9008 之前刷新一次；没有采样就不凭空补一个。
                        if (_bootMaintenancePower is not null)
                        {
                            _bootMaintenancePower = await CapturePowerAsync(transport.AdbPath, freshIdentity.Serial, token);
                            RenderBootMaintenancePower();
                        }

                        // 工具链先落到字段：进入 9008 之后即使失败也保留现场供诊断。
                        _bootMaintenanceEdlTools = loaded;
                        pendingTools = null;

                        _bootMaintenanceEntryAttempted = true;
                        SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.EnteringEdl"));

                        // 整个流程只会在这里真实进入一次 9008，不自动重试；显式传入刚核对过的可信配置。
                        var entered = await Task.Run(
                            () => new EdlEntry(transport.AdbPath, _runner, Discovery).EnterAsync(freshAndroid, loaded.Profile, token),
                            token);

                        _bootMaintenanceEdlEntry = entered;
                        activeClient = new EdlClient(loaded, entered, _runner, Discovery);
                        _bootMaintenanceEdlClient = activeClient;
                        AppendBootMaintenanceLog(M("Dynamic.RawValue", $"9008: {entered.Endpoint.DeviceInstanceId}  SN {entered.BusSerialHex}"));
                    }
                    else
                    {
                        // 复用同一会话：不重新加载工具链、不再走 adb、也不再进入 9008。
                        activeClient = existingClient;
                    }

                    BootMaintenanceBackupProgressBar.IsIndeterminate = true;
                    SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.Reading"));

                    // 复用已有会话时客户端可能还没有首次 Sahara 证明：在读取之前只读探测一次。
                    if (!activeClient.HasInitialSaharaProof)
                    {
                        await Task.Run(() => activeClient.ProbeAsync(0, true, token), token);
                    }

                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderBootMaintenanceBackupProgress(report);
                        }
                    });

                    var set = await Task.Run(
                        () => InternalInstallBackup.CreateAsync(activeClient, parentPath, progress, token),
                        token);
                    acceptProgress = false;

                    // 备份真实返回后、提交之前，先从备份目录读取真实历史身份；失败时释放租约并按失败处理。
                    try
                    {
                        var sharedHistory = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(set.DirectoryPath, token);
                        _bootMaintenanceBackup = set;
                        _bootMaintenanceHistoricalIdentity = sharedHistory;
                    }
                    catch
                    {
                        set.Dispose();
                        throw;
                    }

                    RenderBootMaintenanceBackupSuccess(set);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    acceptProgress = false;
                    _bootMaintenanceBackup = null;
                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message) ? UnknownValue : exception.Message;
                    var failure = exception is OperationCanceledException
                        ? M("Dynamic.InternalInstall.Backup.Cancelled", parentPath)
                        : M("Dynamic.InternalInstall.Backup.Failed", diagnostic, parentPath);
                    BootMaintenanceBackupProgressBar.IsIndeterminate = false;
                    BootMaintenanceBackupProgressBar.Value = 0;
                    SetText(BootMaintenanceBackupStatusText, failure);
                    RenderBootMaintenanceBackupDetail();
                    AppendBootMaintenanceLog(failure);
                }
                finally
                {
                    // 本次工作已结束却没有留下完整备份：此刻才把运行提示换成失败提示；成功的 KeepEdl 绝不覆盖。
                    if (_bootMaintenanceBackup is null)
                    {
                        SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.FailedNote"));
                    }

                    // 从未用于任何设备命令的暂存工具链在失败后释放；已经进入 9008 的那一份由字段保留。
                    if (pendingTools is not null && !ReferenceEquals(pendingTools, _bootMaintenanceEdlTools))
                    {
                        pendingTools.Dispose();
                    }
                }
            });
        }
        finally
        {
            _bootMaintenanceDeviceOperationActive = false;
            BootMaintenanceBackupProgressBar.IsIndeterminate = false;
            RefreshActions();
        }
    }

    /// <summary>
    /// 「平板已在 9008」路线的全新只读备份：严格复用只读核对建立的同一客户端 / 工具链 / entry，
    /// 只调用 InternalInstallBackup.CreateAsync，绝不 OpenExisting，成功前不保存任何备份集合。
    /// </summary>
    private async Task BackupBootMaintenanceEdlAsync()
    {
        if (_busy
            || _bootMaintenanceDeviceOperationActive
            || !_bootMaintenanceAlreadyEdl
            || !HasBootMaintenanceDeviceProof
            || ProtectedBootMaintenanceState
            || IsBootMaintenanceCompleted)
        {
            return;
        }

        var client = _bootMaintenanceEdlClient;
        var tools = _bootMaintenanceEdlTools;
        var entry = _bootMaintenanceEdlEntry;
        var parent = _bootMaintenanceBackupParent;

        if (entry is null || client is null || tools is null
            || string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        // 备份父目录绝不能落在历史目录 / 原厂 / 项目来源目录里面。
        foreach (var source in new[] { _bootMaintenanceHistoricalIdentity?.DirectoryPath, _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source) && !IsGlobalOutputOutsideSource(parent, source!))
            {
                SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        InvalidateBootMaintenancePreparation();

        // 上一份备份对象先释放；客户端、工具链、entry 与端点文件保持原样。
        ReleaseBootMaintenanceBackupObject();
        RenderBootMaintenanceBackupDetail();

        _bootMaintenanceDeviceOperationActive = true;
        // A new attempt starts from nothing: the previous attempt's 100 % and KeepEdl note must not survive a failure
        // that happens before the first progress report (the default route does the same).
        BootMaintenanceBackupProgressBar.Value = 0;
        BootMaintenanceBackupProgressBar.IsIndeterminate = true;
        SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.RunningNote"));
        SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.RunningNote"));

        var parentPath = parent!;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.Reading"));
                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderBootMaintenanceBackupProgress(report);
                        }
                    });

                    var set = await Task.Run(
                        () => InternalInstallBackup.CreateAsync(client, parentPath, progress, token),
                        token);
                    _bootMaintenanceBackup = set;
                    RenderBootMaintenanceBackupSuccess(set);
                }
                catch (OperationCanceledException ex)
                {
                    _bootMaintenanceBackup = null;
                    BootMaintenanceBackupProgressBar.IsIndeterminate = false;
                    BootMaintenanceBackupProgressBar.Value = 0;
                    SetText(BootMaintenanceBackupStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.FailedNote"));
                    AppendBootMaintenanceLog(M("Dynamic.RawValue", ex.Message));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    _bootMaintenanceBackup = null;
                    BootMaintenanceBackupProgressBar.IsIndeterminate = false;
                    BootMaintenanceBackupProgressBar.Value = 0;
                    SetText(BootMaintenanceBackupStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.FailedNote"));
                    AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
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
            BootMaintenanceBackupProgressBar.IsIndeterminate = false;
            _bootMaintenanceDeviceOperationActive = false;
            RenderBootMaintenanceBackupDetail();
            RefreshActions();
        }
    }

    private void RenderBootMaintenanceBackupSuccess(InternalBackupSet set)
    {
        BootMaintenanceBackupProgressBar.IsIndeterminate = false;
        BootMaintenanceBackupProgressBar.Value = 100;
        SetText(BootMaintenanceBackupStatusText, "Dynamic.InternalInstall.Backup.Succeeded", set.Files.Count);
        SetText(BootMaintenanceBackupVerifiedText, "Dynamic.InternalInstall.Backup.KeepEdl");
        RenderBootMaintenanceBackupDetail();
        AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Backup.SucceededLog", set.DirectoryPath, set.ManifestSha256));
    }

    private void RenderBootMaintenanceBackupProgress(InternalBackupProgress report)
    {
        var stage = M(report.Stage switch
        {
            "reading-gpt" => "Dynamic.InternalInstall.Backup.Progress.ReadingGpt",
            "reading-partition" => "Dynamic.InternalInstall.Backup.Progress.ReadingPartition",
            "verifying" => "Dynamic.InternalInstall.Backup.Progress.Verifying",
            "complete" => "Dynamic.InternalInstall.Backup.Progress.Complete",
            _ => "Dynamic.InternalInstall.Backup.Progress.Working",
        });
        var detail = report.Role is null ? stage : M("Dynamic.InternalInstall.Backup.Progress.Role", stage, report.Role);
        if (report.TotalBytes <= 0 && report.TotalFiles <= 0)
        {
            BootMaintenanceBackupProgressBar.IsIndeterminate = true;
            SetText(BootMaintenanceBackupStatusText, "Dynamic.InternalInstall.Backup.Progress.Discovering", detail);
            return;
        }

        var ratio = report.TotalBytes > 0
            ? (double)report.CompletedBytes / report.TotalBytes
            : (double)report.CompletedFiles / report.TotalFiles;
        BootMaintenanceBackupProgressBar.IsIndeterminate = false;
        BootMaintenanceBackupProgressBar.Value = Math.Clamp(ratio * 100d, 0d, 100d);
        SetText(
            BootMaintenanceBackupStatusText,
            "Dynamic.InternalInstall.Backup.Progress.Counters",
            detail,
            report.CompletedFiles,
            report.TotalFiles,
            FormatBytes(report.CompletedBytes),
            FormatBytes(report.TotalBytes));
    }

    /// <summary>
    /// 身份不一致时直接作废检查结论与派生界面并清掉备份门槛；绝不改写用户已选的目录，也不碰设备。
    /// </summary>
    private void InvalidateBootMaintenanceCheckFromMismatch()
    {
        _bootMaintenanceDeviceCheck = null;
        _bootMaintenancePower = null;
        _bootMaintenanceSharedAndroid = null;
        ReleaseBootMaintenanceBackupObject();
        RenderBootMaintenanceCheckPlaceholders();
        SetText(BootMaintenanceCheckStatusText, M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
        RenderBootMaintenanceBackupDetail();
        BootMaintenanceBackupProgressBar.IsIndeterminate = false;
    }

    /// <summary>释放备份对象只持有的只读锁；备份文件、清单与元数据一律保留。</summary>
    private void ReleaseBootMaintenanceBackupObject()
    {
        var set = _bootMaintenanceBackup;
        _bootMaintenanceBackup = null;
        set?.Dispose();
    }

    // ================================================================ 03 来源

    private async void OnBrowseBootMaintenanceOriginal(object? sender, RoutedEventArgs e)
    {
        if (_busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState)
        {
            return;
        }

        if (await PickBootMaintenanceFolderAsync("Dynamic.BootMaintenance.OriginalSource") is not { } directory
            || _busy
            || ProtectedBootMaintenanceState)
        {
            return; // 用户取消或选择无效：完整保留现有状态。
        }

        _bootMaintenanceOriginalDirectory = directory;
        BootMaintenanceEntryOriginalBox.Text = directory;
        BootMaintenanceOriginalBox.Text = directory;
        InvalidateBootMaintenancePreparation();
        RenderBootMaintenanceSourcesStatus();
        RefreshBootMaintenanceActions();
    }

    private async void OnBrowseBootMaintenanceProject(object? sender, RoutedEventArgs e)
    {
        if (_busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState)
        {
            return;
        }

        if (await PickBootMaintenanceFolderAsync("Dynamic.BootMaintenance.ProjectSource") is not { } directory
            || _busy
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        _bootMaintenanceProjectDirectory = directory;
        BootMaintenanceProjectBox.Text = directory;
        InvalidateBootMaintenancePreparation();
        RenderBootMaintenanceSourcesStatus();
        RefreshBootMaintenanceActions();
    }

    // 包路径允许手贴：既可能是文件也可能是文件夹，此处只存真实文本，不做导入或存在性断言。
    private void OnBootMaintenancePackagePathChanged(object? sender, TextChangedEventArgs e)
    {
        if (_busy || _bootMaintenanceOperationActive || ProtectedBootMaintenanceState)
        {
            return;
        }

        var text = BootMaintenancePackageBox.Text;
        if (string.Equals(text ?? string.Empty, _bootMaintenancePackagePath ?? string.Empty, StringComparison.Ordinal))
        {
            return;
        }

        _bootMaintenancePackagePath = text;
        InvalidateBootMaintenancePreparation();
        RenderBootMaintenanceSourcesStatus();
        RefreshBootMaintenanceActions();
    }

    private async Task<string?> PickBootMaintenanceFolderAsync(string titleKey)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = T(titleKey),
            AllowMultiple = false,
        });
        var path = folders.Count == 1 ? folders[0].TryGetLocalPath() : null;
        return !string.IsNullOrWhiteSpace(path) && Directory.Exists(path) ? path : null;
    }

    // ================================================================ 准备（第 3 步 -> 第 4 步）

    /// <summary>
    /// 「下一步」在来源页的真实准备入口：要求真实检查或 9008 历史证明、同一 9008 客户端、全新备份与明确的
    /// 备份父目录；更新前还必须已选原厂恢复来源。准备阶段只读，不写任何分区。
    /// </summary>
    private async Task PrepareBootMaintenanceConfirmationAsync()
    {
        var mode = CurrentBootMaintenanceMode;
        if (_bootMaintenanceStep != 2
            || _busy
            || _bootMaintenanceOperationActive
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        // 路线由真实事实决定：完整检查仍然成立走完整检查工厂；否则走 FromEdl 工厂。
        var fromEdl = !HasCheckedBootMaintenanceDevice;
        var history = _bootMaintenanceHistoricalIdentity;
        var check = _bootMaintenanceDeviceCheck;
        var client = _bootMaintenanceEdlClient;
        var fresh = _bootMaintenanceBackup;
        var parent = _bootMaintenanceBackupParent;
        // 用户选择的安装包只是候选来源：After 永不因缺少它而拒绝尝试准备。
        var packagePath = _bootMaintenancePackagePath;

        if (!HasBootMaintenanceDeviceProof
            || client is null
            || fresh is null
            || (fromEdl ? history is null : !HasCheckedBootMaintenanceDevice)
            || string.IsNullOrWhiteSpace(parent)
            || !Directory.Exists(parent))
        {
            SetText(BootMaintenanceBackupStatusText, M("Dynamic.InternalInstall.Backup.NeedCheck"));
            SetText(BootMaintenancePrepareStatusText, M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        // 更新前必须已选原厂恢复来源；来源目录绝不作为当前目录传入工厂。
        if (mode != MaintenanceMode.AfterUpdate && string.IsNullOrWhiteSpace(_bootMaintenanceOriginalDirectory))
        {
            SetText(BootMaintenancePrepareStatusText, M("Dynamic.InternalInstall.Backup.NeedExistingFolder"));
            return;
        }

        // 备份父目录（以及工具输出目录）绝不能落在已选原厂 / 项目来源目录里面。
        foreach (var source in new[] { _bootMaintenanceOriginalDirectory, _bootMaintenanceProjectDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source) && !IsGlobalOutputOutsideSource(parent!, source!))
            {
                SetText(BootMaintenancePrepareStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        // 已完成的运行先要离开（释放会话）才能重新准备。
        if (IsBootMaintenanceCompleted)
        {
            return;
        }

        // 先作废旧准备，再标记操作进行中；准备失败时保留全新备份 / 会话 / 来源文件。
        InvalidateBootMaintenancePreparation();
        ClearBootMaintenanceRuntimeState();
        _bootMaintenanceOperationActive = true;
        RenderBootMaintenanceSourcesStatus();
        RefreshBootMaintenanceActions();

        BootMaintenanceBackend? backend = null;
        Exception? preparationFailure = null;
        try
        {
            // 所有模式都原样传递用户可选的原始备份目录：Core 自行决定是否用它做模板纪元证明；项目目录不变。
            var sources = new BootMaintenanceSources(
                OriginalBackupDirectory: _bootMaintenanceOriginalDirectory,
                BootTools: _bootMaintenanceNativeTools,
                ProjectBackupDirectory: _bootMaintenanceProjectDirectory,
                RepairPackage: null,
                RepairInstallation: false);

            // 终态一写出 acceptProgress 变 false：排队的迟到进度回调不能再覆盖新界面状态。
            var acceptProgress = true;
            var preparationProgress = new Progress<InternalInstallProgress>(progress =>
            {
                if (acceptProgress)
                {
                    OnBootMaintenanceProgress(progress, preparation: true);
                }
            });
            var runner = _runner;
            // Created inside the caught preparation block below: an unwritable cache root is a preparation failure
            // (backup and session kept), never an exception escaping the async void handler.
            var evidenceParent = string.Empty;

            // 本地小工厂：绑定本次捕获的全部输入；只在确切的包缺失前缀下做一次导入重试。
            Task<BootMaintenanceBackend> CreateBackendAsync(BootMaintenanceSources chosen, CancellationToken token)
                => Task.Run(
                    () => fromEdl
                        ? BootMaintenanceBackend.CreatePreparedFromEdlAsync(
                            mode, history!, client, fresh, chosen, runner, evidenceParent, preparationProgress, token)
                        : BootMaintenanceBackend.CreatePreparedAsync(
                            mode, check!, client, fresh, chosen, runner, evidenceParent, preparationProgress, token),
                    token);

            await RunBusyAsync(async token =>
            {
                SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.Status.Preparing"));
                try
                {
                    evidenceParent = BootMaintenanceWorkRoot;

                    // 更新后修复必须准备内置裸工具；准备原厂只要求已有原厂来源。
                    if (mode == MaintenanceMode.AfterUpdate)
                    {
                        await EnsureBootMaintenanceAssetsAsync(token);
                        // 工具是刚才才真实准备好的：把捕获的来源记录刷新，保证新工具一定到达 Core。
                        sources = sources with { BootTools = _bootMaintenanceNativeTools };
                    }

                    // 第一次调用永远不带修复包：已验证的项目模板优先，避免过早导入安装包。
                    try
                    {
                        backend = await CreateBackendAsync(sources, token);
                    }
                    catch (InvalidOperationException ex)
                    when (mode == MaintenanceMode.AfterUpdate
                        && ex.Message.StartsWith("boot-maintenance-repair-package-required:", StringComparison.Ordinal))
                    {
                        if (string.IsNullOrWhiteSpace(packagePath))
                        {
                            throw;
                        }

                        var fallback = BootMaintenanceBackend.GetRepairFallbackTarget(fresh);
                        if (fallback is not { } target)
                        {
                            // 有包却推不出目标：绝不猜测 Internal / TF 分区，按模板缺失处理。
                            throw new InvalidOperationException(
                                "boot-maintenance-project-template-required: no fallback target",
                                ex);
                        }

                        SetText(BootMaintenancePrepareStatusText, M("Dynamic.BootMaintenance.Repair.ImportingPackage"));
                        var imported = await PackageImporter.ImportAsync(packagePath, fresh.Model, target, evidenceParent, token);
                        // 导入结果先入字段再校验：无论后续成败，清理路径始终拥有它。
                        _bootMaintenanceRepairPackage = imported;

                        if (!imported.Validation.IsValid || imported.Validation.TestOnly)
                        {
                            foreach (var reason in imported.Validation.Reasons)
                            {
                                AppendBootMaintenanceLog(M("Dynamic.RawValue", reason));
                            }

                            throw new InvalidOperationException(
                                "boot-maintenance-repair-package-rejected: validation failed",
                                ex);
                        }

                        // 只重试一次：包已交 Core 独立校验，绝不递归或循环重试。
                        backend = await CreateBackendAsync(sources with { RepairPackage = imported }, token);
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    preparationFailure = ex;
                    backend?.Dispose();
                    backend = null;
                    AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                }
                finally
                {
                    acceptProgress = false;
                }
            });

            if (preparationFailure is not null)
            {
                backend?.Dispose();
                backend = null;
                // 失败时先作废旧准备：作废会清运行时缓存，具体消息在作废之后落字段以便重绘恢复。
                _bootMaintenanceOperationActive = false;
                InvalidateBootMaintenancePreparation();
                var specific = MapBootMaintenancePreparationMessage(preparationFailure);
                _bootMaintenanceLastError = preparationFailure.Message;
                _bootMaintenanceLastPreparationMessage = specific;
                SetText(BootMaintenancePrepareStatusText, specific);
                return;
            }

            // 工厂真实返回后复查：同一维护模式、同一输入、页面仍打开，才允许进入确认页。
            if (backend is null
                || CurrentBootMaintenanceMode != mode
                || _bootMaintenanceStep != 2
                || _closeConfirmed
                || (fromEdl && !ReferenceEquals(_bootMaintenanceHistoricalIdentity, history))
                || (!fromEdl && !ReferenceEquals(_bootMaintenanceDeviceCheck, check))
                || !ReferenceEquals(_bootMaintenanceEdlClient, client)
                || !ReferenceEquals(_bootMaintenanceBackup, fresh)
                || !string.Equals(_bootMaintenanceBackupParent, parent, StringComparison.Ordinal)
                || !string.Equals(_bootMaintenancePackagePath, packagePath, StringComparison.Ordinal))
            {
                backend?.Dispose();
                backend = null;
                // 操作仍只读：丢弃被覆盖输入的后端时同时释放本窗口持有的修复包，避免解包泄漏。
                ReleaseBootMaintenanceRepairPackage();
                return;
            }

            _bootMaintenanceBackend = backend;
            backend = null;
            _bootMaintenanceLastError = null;
            _bootMaintenanceLastPreparationMessage = null;
            _bootMaintenanceStep = 3;
        }
        finally
        {
            backend?.Dispose();
            _bootMaintenanceOperationActive = false;
            RenderBootMaintenancePages();
        }
    }

    /// <summary>
    /// 只对确切前缀映射到具体文案；其余失败一律回到通用「准备失败」。
    /// 真实异常原文始终保留在折叠诊断日志里，界面上绝不出现内部前缀。
    /// </summary>
    private static UiMessage MapBootMaintenancePreparationMessage(Exception failure)
    {
        if (failure is InvalidOperationException ex)
        {
            if (ex.Message.StartsWith("boot-maintenance-project-template-required:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.ProjectTemplateRequired");
            }

            if (ex.Message.StartsWith("boot-maintenance-template-epoch-unproven:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.TemplateEpochUnproven");
            }

            if (ex.Message.StartsWith("boot-maintenance-repair-package-rejected:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.PackageRejected");
            }

            if (ex.Message.StartsWith("boot-maintenance-repair-package-required:", StringComparison.Ordinal))
            {
                return M("Dynamic.BootMaintenance.Repair.PackageRequired");
            }
        }

        return M("Dynamic.BootMaintenance.Status.PrepareFailed");
    }

    /// <summary>
    /// 只在需要时解出两个内置裸工具（WPF EnsureInternalInstallAssetsAsync）。已经成功加载的工具在同一页面的
    /// 重试中复用；失败时释放尚未保存的工具集与工具。Core 用自己的编译期引脚独立复核。
    /// </summary>
    private async Task EnsureBootMaintenanceAssetsAsync(CancellationToken token)
    {
        if (_bootMaintenanceAssets is not null && _bootMaintenanceNativeTools is not null)
        {
            return;
        }

        var materials = Path.Combine(BootMaintenanceWorkRoot, "assets", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(materials);
        EdlRawBootTools? pendingTools = null;
        InternalInstallDirectAssets? pendingAssets = null;
        try
        {
            var packer = await MacTools.StageAsync(MacTools.PackerResource, Path.Combine(materials, "MultiBootKernelPatcher"), token);
            var unpacker = await MacTools.StageAsync(MacTools.UnpackerResource, Path.Combine(materials, "UnpackTool"), token);
            pendingTools = await EdlRawBootTools.LoadAsync(packer, unpacker, token);
            pendingAssets = await InternalInstallDirectAssets.LoadAsync(pendingTools, token);

            _bootMaintenanceNativeTools = pendingTools;
            pendingTools = null;
            _bootMaintenanceAssets = pendingAssets;
            pendingAssets = null;
            _bootMaintenanceAssetsDirectory = materials;
            AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Prepared.MaterialsReady", materials));
        }
        finally
        {
            pendingAssets?.Dispose();
            pendingTools?.Dispose();
            if (!ReferenceEquals(_bootMaintenanceAssetsDirectory, materials))
            {
                DeleteBootMaintenanceAssetsDirectory(materials);
            }
        }
    }

    /// <summary>Removes one staged-tool directory; it holds only the two copied executables, never evidence.</summary>
    private static void DeleteBootMaintenanceAssetsDirectory(string? directory)
    {
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: a leftover copy of the bundled tools is harmless.
        }
    }

    /// <summary>
    /// 丢弃尚未写入的后端准备；受保护状态（已写入未完成）下一律拒绝。
    /// 保留本次备份父目录、已选文件与会话；不做任何 IO 或设备重置。
    /// </summary>
    private void InvalidateBootMaintenancePreparation()
    {
        // A completed run keeps its evidence until DisposeBootMaintenanceSession: changing a source afterwards must not
        // turn the already reset tablet back into a pre-write 9008 session.
        if (ProtectedBootMaintenanceState || IsBootMaintenanceCompleted)
        {
            return;
        }

        if (_bootMaintenanceBackend is { } backend)
        {
            backend.Dispose();
            _bootMaintenanceBackend = null;
        }

        ReleaseBootMaintenanceRepairPackage();

        _bootMaintenanceExecuteAttempted = false;
        BootMaintenanceRiskCheck.IsChecked = false;
        // 预写入作废同时清空运行时缓存，避免旧结论被下一次重绘原样恢复。
        ClearBootMaintenanceRuntimeState();
    }

    /// <summary>释放本窗口拥有的已导入修复包；用户的原始 ZIP / 目录绝不归本实例所有，不做任何删除。</summary>
    private void ReleaseBootMaintenanceRepairPackage()
    {
        if (_bootMaintenanceRepairPackage is not { } imported)
        {
            return;
        }

        _bootMaintenanceRepairPackage = null;
        try
        {
            imported.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (!_closeConfirmed)
            {
                AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            }
        }
    }

    private void ClearBootMaintenanceRuntimeState()
    {
        _bootMaintenanceLastResult = null;
        _bootMaintenanceLastError = null;
        _bootMaintenanceLastPreparationMessage = null;
        _bootMaintenanceLastProgress = null;
        _bootMaintenanceCompletedConfirmationId = null;
        _bootMaintenanceLoggedStage = null;
        _bootMaintenanceLoggedSlot = null;
        _bootMaintenanceLoggedIoPhase = null;
        _bootMaintenanceProgressTerminal = false;
    }

    // ================================================================ 04 执行

    private void OnBootMaintenanceRiskChanged(object? sender, RoutedEventArgs e) => RefreshBootMaintenanceActions();

    private async void OnExecuteBootMaintenance(object? sender, RoutedEventArgs e) => await ExecuteBootMaintenanceAsync();

    /// <summary>准备 / 修复两种模式的执行入口：确认框默认「否」，之后只发起唯一一次 ExecuteAsync。</summary>
    private async Task ExecuteBootMaintenanceAsync()
    {
        var mode = CurrentBootMaintenanceMode;
        // A leave reset was attempted (acknowledged or not): this session is over or unresolved, never executable.
        if (_bootMaintenanceStep != 3
            || _busy
            || _bootMaintenanceOperationActive
            || _bootMaintenanceExecuteAttempted
            || _bootMaintenanceResetAttempted
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        if (_bootMaintenanceBackend is not { } backend
            || backend.Prepared is not { } prepared
            || prepared.Mode != mode
            || BootMaintenanceRiskCheck.IsChecked != true)
        {
            return;
        }

        var confirmationId = prepared.ConfirmationId;

        // 确认框：模式 / 型号 / 序列号 / 当前槽位 / 槽位写入明细 / 真实路径；默认「否」。
        var detail = T(
            "Dynamic.BootMaintenance.Confirm.Body",
            BootMaintenanceModeMessage(),
            UiText.ModelName(prepared.Model),
            prepared.AndroidSerial ?? string.Empty,
            prepared.CurrentSlot ?? string.Empty);
        detail += Environment.NewLine + T("Dynamic.BootMaintenance.Confirm.NoRepartition");
        detail += Environment.NewLine + T(
            "Dynamic.BootMaintenance.BackupLocations",
            _bootMaintenanceBackup?.DirectoryPath ?? prepared.BackupDirectory,
            _bootMaintenanceOriginalDirectory ?? string.Empty,
            _bootMaintenanceProjectDirectory ?? string.Empty,
            prepared.EvidenceDirectory);
        foreach (var slot in prepared.Slots)
        {
            detail += Environment.NewLine + (slot.WillWrite
                ? T("Dynamic.BootMaintenance.SlotWrite",
                    slot.Slot ?? string.Empty,
                    slot.SourceSlot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind))
                : T("Dynamic.BootMaintenance.SlotKeep",
                    slot.Slot ?? string.Empty,
                    DescribeBootMaintenanceSourceKind(slot.SourceKind)));
        }

        var answer = await MessageDialog.AskAsync(
            this,
            T("Dynamic.BootMaintenance.ConfirmTitle"),
            detail,
            T("Dynamic.Mac.Dialog.Yes"),
            T("Dynamic.Mac.Dialog.No"));
        if (!answer)
        {
            return;
        }

        // 弹窗之后复查：同一后端引用、同一确认号、同一模式、风险仍勾选且仍然空闲。
        if (!ReferenceEquals(_bootMaintenanceBackend, backend)
            || _bootMaintenanceBackend?.Prepared is not { } current
            || !string.Equals(current.ConfirmationId, confirmationId, StringComparison.Ordinal)
            || current.Mode != mode
            || BootMaintenanceRiskCheck.IsChecked != true
            || _busy
            || _bootMaintenanceOperationActive
            || _bootMaintenanceResetAttempted
            || ProtectedBootMaintenanceState)
        {
            return;
        }

        // 进入真实执行：先立起「已尝试」旗标，再发起唯一一次 ExecuteAsync。
        _bootMaintenanceExecuteAttempted = true;
        _bootMaintenanceOperationActive = true;
        _bootMaintenanceProgressTerminal = false;
        RefreshBootMaintenanceActions();

        // 终态一写出 acceptProgress 变 false：排队的迟到进度回调不能再覆盖 Ready / 新操作。
        var acceptProgress = true;
        var executionProgress = new Progress<InternalInstallProgress>(progress =>
        {
            if (acceptProgress)
            {
                OnBootMaintenanceProgress(progress, preparation: false);
            }
        });

        await RunBusyAsync(async token =>
        {
            try
            {
                var result = await Task.Run(() => backend.ExecuteAsync(confirmationId, executionProgress, token), token);
                _bootMaintenanceLastResult = result;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _bootMaintenanceLastError = ex.Message;
                AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
            }
            finally
            {
                acceptProgress = false;
                _bootMaintenanceOperationActive = false;
                _bootMaintenanceProgressTerminal = true;
            }

            RenderBootMaintenanceRuntimeStatus();
        });

        RefreshActions();

        // 完成提示只认真实 Completed + 全部校验通过的结果；busy 结束后才弹；每个确认号只弹一次；
        // 弹过之后绝不再复位 / ADB / 任何设备调用。
        if (_bootMaintenanceLastResult is { } done
            && done.Outcome == BootMaintenanceOutcome.Completed
            && done.WriteState == InternalInstallWriteState.AllVerified
            && !string.Equals(_bootMaintenanceCompletedConfirmationId, confirmationId, StringComparison.Ordinal))
        {
            _bootMaintenanceCompletedConfirmationId = confirmationId;
            await MessageDialog.ShowAsync(
                this,
                T("Dynamic.BootMaintenance.Status.CompletedTitle"),
                T("Dynamic.BootMaintenance.Status.Completed"),
                T("Dynamic.Mac.Dialog.Ok"));
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Status.Outcome.Completed"));
        }
    }

    // ---------- 进度（只显示，不作为成功证明） ----------

    private void OnBootMaintenanceProgress(InternalInstallProgress progress, bool preparation)
    {
        if (_bootMaintenanceProgressTerminal)
        {
            return;
        }

        _bootMaintenanceLastProgress = progress;

        var stageName = progress.Stage.ToString();
        var stageKey = "Dynamic.InternalInstall.Execution.Stage." + stageName;
        var text = M(stageKey);

        if (!string.Equals(_bootMaintenanceLoggedStage, stageName, StringComparison.Ordinal))
        {
            _bootMaintenanceLoggedStage = stageName;
            AppendBootMaintenanceLog(M(stageKey));
        }

        if (!string.IsNullOrEmpty(progress.Slot))
        {
            text = M("Dynamic.BootMaintenance.Progress.Slot", text, progress.Slot);
            if (!string.Equals(_bootMaintenanceLoggedSlot, progress.Slot, StringComparison.Ordinal))
            {
                _bootMaintenanceLoggedSlot = progress.Slot;
                AppendBootMaintenanceLog(text);
            }
        }

        if (progress.IoPhase is { } ioPhase)
        {
            var ioName = ioPhase.ToString() ?? string.Empty;
            text = M("Dynamic.InternalInstall.Execution.Status.IoPhase",
                text,
                M("Dynamic.InternalInstall.Execution.IoPhase." + ioName));
            if (!string.Equals(_bootMaintenanceLoggedIoPhase, ioName, StringComparison.Ordinal))
            {
                _bootMaintenanceLoggedIoPhase = ioName;
                AppendBootMaintenanceLog(M("Dynamic.InternalInstall.Execution.IoPhase." + ioName));
            }
        }

        // 只有携带真实 nullable 总量的 IO 进度才显示近似计数；否则保持不确定状态。
        if (progress.IoTotalBytes is { } total && total > 0)
        {
            var done = progress.IoCompletedBytes ?? 0;
            text = M("Dynamic.BootMaintenance.Progress.Io", text, done, total);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = Math.Clamp(done * 100.0 / total, 0, 100);
        }
        else
        {
            BootMaintenanceProgressBar.IsIndeterminate = true;
        }

        if (preparation)
        {
            SetText(BootMaintenancePrepareStatusText, text);
        }
        else
        {
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.InternalInstall.Execution.WriteState." + progress.WriteState);
            SetText(BootMaintenanceProgressText, text);
        }
    }

    /// <summary>运行时现场重绘：恢复最后一次结果 / 错误 / 进度，而不是清空完成与失败状态。</summary>
    private void RenderBootMaintenanceRuntimeStatus()
    {
        var progress = _bootMaintenanceLastProgress;
        if (progress is { } saved && _bootMaintenanceExecuteAttempted)
        {
            // 进度文本带上真实 IO 阶段（写入 / 读回校验等），让人看到当前卡在哪一步。
            var stageText = M("Dynamic.InternalInstall.Execution.Stage." + saved.Stage);
            var text = saved.Slot is { } slot && slot.Length > 0
                ? M("Dynamic.BootMaintenance.Progress.Slot", stageText, slot)
                : stageText;
            if (saved.IoPhase is { } ioPhase)
            {
                text = M("Dynamic.InternalInstall.Execution.Status.IoPhase",
                    text,
                    M("Dynamic.InternalInstall.Execution.IoPhase." + ioPhase));
            }

            SetText(BootMaintenanceProgressText, text);
            SetText(BootMaintenanceConfirmStatusText, text);

            if (_bootMaintenanceLastResult is { } done
                && done.Outcome == BootMaintenanceOutcome.Completed
                && done.WriteState == InternalInstallWriteState.AllVerified)
            {
                BootMaintenanceProgressBar.IsIndeterminate = false;
                BootMaintenanceProgressBar.Value = 100;
            }
            else if (saved.IoTotalBytes is { } total && total > 0)
            {
                BootMaintenanceProgressBar.IsIndeterminate = false;
                BootMaintenanceProgressBar.Value = Math.Clamp((saved.IoCompletedBytes ?? 0) * 100.0 / total, 0, 100);
            }
            else
            {
                BootMaintenanceProgressBar.IsIndeterminate = _bootMaintenanceOperationActive && !_bootMaintenanceProgressTerminal;
            }
        }
        else
        {
            SetText(BootMaintenanceProgressText, "Dynamic.RawValue", string.Empty);
            BootMaintenanceProgressBar.IsIndeterminate = false;
            BootMaintenanceProgressBar.Value = 0;
            // 来源页状态也按存储的真实结果 / 错误 / 准备状态重绘，不丢失败信息。
            RenderBootMaintenanceSourcesStatus();
        }

        if (_bootMaintenanceLastResult is { } result)
        {
            SetText(
                BootMaintenanceConfirmStatusText,
                result.WriteState == InternalInstallWriteState.AllVerified && result.Outcome != BootMaintenanceOutcome.Completed
                    ? "Dynamic.BootMaintenance.Status.VerifiedRestartUnconfirmed"
                    : "Dynamic.BootMaintenance.Status.Outcome." + result.Outcome);
        }
        else if (_bootMaintenanceLastError is not null)
        {
            // An exception from ExecuteAsync is an execution failure, not a preparation one: preparation had already
            // succeeded. When the backend snapshot still holds an unconfirmed write, say so instead of implying that
            // nothing was written.
            SetText(
                BootMaintenanceConfirmStatusText,
                !_bootMaintenanceExecuteAttempted
                    ? M("Dynamic.BootMaintenance.Status.PrepareFailed")
                    : HasUnconfirmedBootMaintenanceWrite
                        ? M("Dynamic.BootMaintenance.Status.Outcome.UnknownWriteOutcome")
                        : M("Dynamic.BootMaintenance.Status.Outcome.Failed"));
        }
        else
        {
            SetText(BootMaintenanceConfirmStatusText, "Dynamic.RawValue", string.Empty);
        }
    }

    // ================================================================ 离开 / 退出 / 关闭

    /// <summary>
    /// 维护模式唯一的离开确认：活动操作直接拒绝；真实 Completed 只释放自己持有的租约并保留全部文件；
    /// 未确认写入拒绝；预写入阶段存在真实 9008 会话时，先征询（默认「否」），确认后补齐 Sahara、只发一次复位；
    /// 复位结果未知时保留尝试旗标与会话，绝不重发。
    /// </summary>
    private async Task<bool> ConfirmLeaveBootMaintenanceAsync()
    {
        if (_busy || _bootMaintenanceOperationActive || _bootMaintenanceDeviceOperationActive)
        {
            return false;
        }

        _bootMaintenanceLeaveProbeFailed = false;

        var backend = _bootMaintenanceBackend;

        // 未知复位（尝试过但从未收到确认）：现场与会话全部保留，绝不再发复位，直接拒绝。
        if (HasUnknownBootMaintenanceReset)
        {
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 真实 Completed + 全部校验通过：只释放自己持有的租约与资源，保留全部文件，无任何设备调用。
        if (_bootMaintenanceLastResult is { } result
            && result.Outcome == BootMaintenanceOutcome.Completed
            && result.WriteState == InternalInstallWriteState.AllVerified)
        {
            backend?.Dispose();
            _bootMaintenanceBackend = null;
            DisposeBootMaintenanceSession();
            return true;
        }

        // 已发起写入但结果不是真实 Completed：拒绝离开并保留现场与证据。
        if (HasUnconfirmedBootMaintenanceWrite)
        {
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 进入 9008 但客户端为空：复位结果无法确认，属于未知状态，绝不能当成功放行或释放现场。
        if (HasBootMaintenanceLiveEdlState && _bootMaintenanceEdlClient is null)
        {
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            SetText(BootMaintenanceConfirmStatusText, M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return false;
        }

        // 预写入且没有真实 9008 会话：安全释放后端准备，直接放行。
        if (!HasBootMaintenanceLiveEdlState || _bootMaintenanceEdlClient is not { } client)
        {
            backend?.Dispose();
            _bootMaintenanceBackend = null;
            return true;
        }

        var answer = await MessageDialog.AskAsync(
            this,
            T("Dynamic.BootMaintenance.Exit.ConfirmTitle"),
            T("Dynamic.BootMaintenance.Exit.ConfirmBody"),
            T("Dynamic.Mac.Dialog.Yes"),
            T("Dynamic.Mac.Dialog.No"));
        if (!answer || _busy || !ReferenceEquals(client, _bootMaintenanceEdlClient))
        {
            return false;
        }

        var left = false;
        await RunBusyAsync(async token =>
        {
            // 先补齐 Sahara 证明；探针失败就没有任何新鲜证据，绝不发复位，也不立尝试旗标。
            try
            {
                await Task.Run(() => client.ProbeAsync(0, initialLoader: !client.HasInitialSaharaProof, CancellationToken.None), token);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                _bootMaintenanceLeaveProbeFailed = true;
                return;
            }

            // 先立起尝试旗标，再只发一次复位；结果未知时旗标与会话全部保留，绝不重发。
            _bootMaintenanceResetAttempted = true;
            try
            {
                await Task.Run(() => client.ResetAsync(CancellationToken.None), token);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                AppendBootMaintenanceLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Status.Outcome.UnknownWriteOutcome"));
                return;
            }

            // 复位确认已收到：只释放自己持有的对象并清空活跃会话字段，绝不等待 ADB。
            _bootMaintenanceResetAcked = true;
            backend?.Dispose();
            _bootMaintenanceBackend = null;
            DisposeBootMaintenanceSession();
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Exit.Restarting"));
            left = true;
        });

        return left;
    }

    /// <summary>退出面板按钮：维护模式自己的「一次复位离开」例程，不走旧安装的 ADB 等待。</summary>
    private async void OnExitBootMaintenance(object? sender, RoutedEventArgs e)
    {
        if (_busy || _bootMaintenanceOperationActive)
        {
            return;
        }

        if (HasUnconfirmedBootMaintenanceWrite || HasUnknownBootMaintenanceReset)
        {
            AppendBootMaintenanceLog(M("Dynamic.BootMaintenance.Exit.LeaveBlocked"));
            return;
        }

        if (await ConfirmLeaveBootMaintenanceAsync())
        {
            ResetBootMaintenanceUiState();
        }

        RenderBootMaintenancePages();
        RefreshActions();
    }

    /// <summary>
    /// 复位维护自己的界面状态：只在已批准离开后调用；未确认写入、未知复位与仍有 9008 现场时一律拒绝清空。
    /// 已选的原厂 / 项目 / 安装包与备份父目录保留。
    /// </summary>
    private void ResetBootMaintenanceUiState()
    {
        if (_bootMaintenanceOperationActive
            || _bootMaintenanceDeviceOperationActive
            || HasUnconfirmedBootMaintenanceWrite
            || HasUnknownBootMaintenanceReset
            || HasBootMaintenanceLiveEdlState)
        {
            return;
        }

        ClearBootMaintenanceRuntimeState();
        InvalidateBootMaintenancePreparation();
        _bootMaintenanceHistoricalIdentity = null;
        ResetBootMaintenanceCheckState();
        _bootMaintenanceResetAttempted = false;
        _bootMaintenanceResetAcked = false;
        _bootMaintenanceStep = 0;
        SetText(BootMaintenanceBackupStatusText, "Static.InternalInstall.Backup.StatusInitial");
        SetText(BootMaintenanceBackupVerifiedText, "Static.InternalInstall.Backup.VerifiedInitial");
        BootMaintenanceBackupProgressBar.Value = 0;
        RenderBootMaintenancePages();
    }

    /// <summary>
    /// Releases this page's 9008 session objects once the session is over (Core reset the tablet, or the one
    /// leave reset was acknowledged): the WPF <c>DisposeInternalInstallResources</c>. Files are never deleted.
    /// </summary>
    private void DisposeBootMaintenanceSession()
    {
        ReleaseBootMaintenanceBackupObject();
        _bootMaintenanceAssets?.Dispose();
        _bootMaintenanceAssets = null;
        _bootMaintenanceNativeTools?.Dispose();
        _bootMaintenanceNativeTools = null;
        DeleteBootMaintenanceAssetsDirectory(_bootMaintenanceAssetsDirectory);
        _bootMaintenanceAssetsDirectory = null;

        var tools = _bootMaintenanceEdlTools;
        _bootMaintenanceEdlTools = null;
        _bootMaintenanceEdlClient = null;
        _bootMaintenanceEdlEntry = null;
        _bootMaintenanceEntryAttempted = false;
        try
        {
            tools?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>Releases managed objects when the window closes; backups, evidence and records stay on disk.</summary>
    private void DisposeBootMaintenanceOnClose()
    {
        if (_bootMaintenanceOperationActive || _bootMaintenanceDeviceOperationActive)
        {
            return;
        }

        _bootMaintenanceBackend?.Dispose();
        _bootMaintenanceBackend = null;
        ReleaseBootMaintenanceRepairPackage();
        DisposeBootMaintenanceSession();
    }

    /// <summary>
    /// The maintenance part of the window's close handler (WPF OnInternalInstallClosing, maintenance branch):
    /// returns true when it handled (and cancelled) this close.
    /// </summary>
    private async Task<bool> OnBootMaintenanceClosingAsync(WindowClosingEventArgs e)
    {
        if (!HasBootMaintenanceDeviceSession)
        {
            return false;
        }

        e.Cancel = true;
        if (_closePromptActive)
        {
            return true;
        }

        _closePromptActive = true;
        try
        {
            // 自己的任何活动操作：一律阻止关闭，等当前操作返回。
            if (_busy || _bootMaintenanceOperationActive || _bootMaintenanceDeviceOperationActive)
            {
                SetText(BootMaintenanceCheckStatusText, M("Dynamic.InternalInstall.Check.WaitForReturn"));
                await MessageDialog.ShowAsync(
                    this,
                    T("Dynamic.Mac.Close.BusyTitle"),
                    T("Dynamic.Mac.Close.BusyBody"),
                    T("Dynamic.Mac.Dialog.Ok"));
                return true;
            }

            // 未知写入 / 未知复位 / 进入 9008 但没有客户端：只有显式警告（默认「否」）才允许仅关闭窗口；
            // 不复位、不释放文件。
            if (HasUnconfirmedBootMaintenanceWrite
                || HasUnknownBootMaintenanceReset
                || (HasBootMaintenanceLiveEdlState && _bootMaintenanceEdlClient is null))
            {
                if (await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.BootMaintenance.Exit.ConfirmTitle"),
                        T("Dynamic.BootMaintenance.Exit.CloseUnconfirmedBody"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No")))
                {
                    _closeConfirmed = true;
                    Close();
                }

                return true;
            }

            // 已完成或预写入：走统一的维护离开确认（默认「否」），批准后放行关闭。
            if (!await ConfirmLeaveBootMaintenanceAsync())
            {
                // The leave's device probe failed (for example the tablet was unplugged): no reset was sent and none
                // can be. Offer the same explicit close-only warning (default "No"), which sends no device command and
                // keeps the backup and evidence files; otherwise every close would repeat the failing probe.
                if (_bootMaintenanceLeaveProbeFailed
                    && await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.Mac.Close.ProbeFailedTitle"),
                        T("Dynamic.Mac.Close.ProbeFailedBody"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No")))
                {
                    // Pre-write session: release what this window owns (imported package extraction, staged tools)
                    // exactly like the normal close path; no device command is sent and evidence stays.
                    _closeConfirmed = true;
                    DisposeBootMaintenanceOnClose();
                    DisposeInternalInstall();
                    Close();
                }

                return true;
            }

            ResetBootMaintenanceUiState();
            _closeConfirmed = true;
            DisposeBootMaintenanceOnClose();
            DisposeInternalInstall();
            Close();
            return true;
        }
        finally
        {
            _closePromptActive = false;
        }
    }
}
