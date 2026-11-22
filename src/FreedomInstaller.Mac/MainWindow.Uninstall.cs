using System.Globalization;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// The "卸载 Linux" (uninstall) page of the macOS window: the port of the WPF modern uninstall wizard
/// (MainWindow.UserdataUninstall*.cs, MainWindow.RecoverySource.cs) together with the uninstall branches of the shared
/// Android -> fresh snapshot -> 9008 pipeline it drives (MainWindow.InternalInstall.Check.cs / .Backup.cs,
/// MainWindow.BootMaintenance.Edl.cs / .View.cs). WPF hides the shared backup step in this mode, so the page has three
/// steps (internal numbers 0, 2, 3, shown as 01 / 02 / 03): check, recovery material and options, confirm. The gates,
/// the Core calls and their order are the WPF ones; every device write happens inside <see cref="UninstallWorkflow"/>,
/// <see cref="UninstallStockBootRestoration"/> or the one reset. The page keeps its own state, like the
/// boot-maintenance page (the WPF window resets the shared pages whenever the function changes). Device calls run on a
/// worker thread because the macOS 9008 discovery reads ioreg synchronously; their progress still posts to the UI thread.
/// </summary>
public partial class MainWindow
{
    // ---------- 页面 ----------

    private int _uninstallStep;
    private bool _suppressUninstallNav;
    private bool _suppressUninstallDeviceSelection;
    private bool _uninstallStockCheckboxSuppress;
    private string? _uninstallWorkRoot;

    // ---------- 01 检查 ----------

    private IReadOnlyList<ConnectedDevice> _uninstallDeviceChoices = Array.Empty<ConnectedDevice>();
    private InternalDeviceCheckResult? _uninstallDeviceCheck;
    private PowerSample? _uninstallPower;
    private bool _uninstallAlreadyEdl;

    /// <summary>A check, the 9008 recovery binding or the snapshot backup is running (WPF <c>_internalInstallOperationActive</c>).</summary>
    private bool _uninstallDeviceOperationActive;

    // ---------- 9008 会话、当前状态快照与恢复资料 ----------

    private EdlToolchain? _uninstallEdlTools;
    private EdlEntryResult? _uninstallEdlEntry;
    private EdlClient? _uninstallEdlClient;
    private bool _uninstallEntryAttempted;
    private string? _uninstallBackupParent;
    private InternalBackupSet? _uninstallBackup;
    private BootMaintenanceHistoricalIdentity? _uninstallHistoricalIdentity;

    private string? _uninstallOriginalDirectory;
    private InternalBackupSet? _uninstallRecoverySource;
    private string? _uninstallBoardRecoveryAttemptManifest;
    private string? _uninstallBoardRecoveryDirectory;
    private EdlRawBootTools? _uninstallNativeTools;
    private InternalInstallDirectAssets? _uninstallAssets;
    // The directory holding only the two staged tool executables; removed when the session releases the tools.
    private string? _uninstallAssetsDirectory;

    // Set when the last leave stopped because its device probe failed (no reset was sent): closing may then offer the
    // explicit close-only warning instead of repeating the same failing probe on every close.
    private bool _uninstallLeaveProbeFailed;

    // ---------- 选项与准备 ----------

    /// <summary>「恢复原厂安卓引导」；默认不勾选，保持项目菜单默认安卓行为。</summary>
    private bool _uninstallRestoreStockBoot;
    private bool _uninstallReclaimBackup = true;
    private EdlUninstallBackend? _uninstallBackend;
    private CurrentBootMenuPlan? _uninstallMenu;
    private UninstallOriginalGptBackup? _uninstallOriginal;
    private BootMaintenancePrepared? _uninstallStockPlan;
    private BootMaintenanceResult? _uninstallStockRestoreResult;
    private bool _uninstallOperationActive;
    private string? _uninstallError;

    // ---------- 执行 ----------

    private UninstallResult? _uninstallLastResult;
    private bool _uninstallExecuteAttempted;
    private bool _uninstallExecutionUnknown;
    private bool _uninstallResetAttempted;
    private bool _uninstallResetAcked;
    private bool _uninstallCompleted;
    private bool _uninstallCompletionToastShown;
    private UninstallStage? _uninstallDisplayStage;
    private UiMessage? _uninstallExitStatus;

    // ================================================================ 状态谓词（与 WPF 相同）

    /// <summary>Per-window work folder under the cache (the WPF window uses its environment work session).</summary>
    private string UninstallWorkRoot
    {
        get
        {
            _uninstallWorkRoot ??= Path.Combine(MacCacheRoot, "uninstall-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_uninstallWorkRoot);
            return _uninstallWorkRoot;
        }
    }

    /// <summary>The WPF <c>DefaultRecoveryOutputDirectory</c>: the cache root's Recovery folder.</summary>
    private static string UninstallRecoveryOutputDirectory()
    {
        var directory = Path.Combine(MacCacheRoot, "Recovery");
        Directory.CreateDirectory(directory);
        return directory;
    }

    /// <summary>结果未知、复位已发起但未确认，或真实结果声明数据可能已被擦除：不允许离开、换功能或清空现场。</summary>
    private bool HasUnresolvedUninstallState =>
        !_uninstallCompleted
        && (_uninstallExecutionUnknown
            || (_uninstallResetAttempted && !_uninstallResetAcked)
            || _uninstallLastResult?.DataMayBeErased == true);

    private bool ProtectedUninstallState => _uninstallOperationActive || HasUnresolvedUninstallState;

    /// <summary>The WPF <c>HasInternalInstallLiveEdlState</c>: an entry was attempted or a 9008 endpoint is bound.</summary>
    private bool HasUninstallLiveEdlState => _uninstallEntryAttempted || _uninstallEdlEntry is not null;

    /// <summary>The tablet is (or may be) in 9008 for this page, a plan holds its leases, or an outcome is unresolved.</summary>
    private bool HasUninstallDeviceSession =>
        HasUninstallLiveEdlState
        || _uninstallEdlClient is not null
        || _uninstallDeviceOperationActive
        || ProtectedUninstallState
        || _uninstallBackend is not null;

    /// <summary>
    /// The full (Fastboot round-trip) check passed and its Android identity is complete; a model whose write route is
    /// not open (TB710FU) is no proof, exactly as the WPF <c>HasCheckedInternalInstallDevice</c> in a shared mode.
    /// </summary>
    private bool HasCheckedUninstallDevice
    {
        get
        {
            var result = _uninstallDeviceCheck;
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

    /// <summary>真实完整检查通过，或已建立真实 9008 只读会话（恢复资料身份已绑定、首次 Sahara 已证明、entry 与工具齐备）。</summary>
    private bool HasUninstallDeviceProof =>
        HasCheckedUninstallDevice
        || (_uninstallHistoricalIdentity is not null
            && _uninstallEdlClient is { } client
            && client.HasInitialSaharaProof
            && _uninstallEdlEntry is not null
            && _uninstallEdlTools is not null);

    /// <summary>
    /// The WPF <c>HasBootMaintenanceBackupPrerequisite</c> in uninstall mode: uninstall never takes the shared read-only
    /// Android route (its default check is the full one), so only the device proof counts.
    /// </summary>
    private bool HasUninstallBackupPrerequisite => HasUninstallDeviceProof;

    private bool HasPreparedUninstallBootPlan => _uninstallRestoreStockBoot
        ? _uninstallStockPlan is not null
        : _uninstallMenu is not null;

    private static bool UninstallAndroidMatches(AndroidMaintenanceIdentity expected, AndroidMaintenanceIdentity actual)
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

    /// <summary>The home card: opening the page touches no device; the page resumes where it was.</summary>
    private void ShowUninstallPage()
    {
        if (!_environmentReady)
        {
            return;
        }

        ShowView(UninstallPage);
        RenderUninstallPages();
        UninstallPage.ScrollToHome();
    }

    /// <summary>「← 功能选择」：走卸载自己的离开确认（预写入现场一次复位），拒绝时现场原样保留。</summary>
    private async void OnUninstallBackHome(object? sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        if (!await ConfirmLeaveUninstallAsync())
        {
            RefreshUninstallActions();
            return;
        }

        SafeResetUninstallState();
        ShowView(HomePage);
        RefreshActions();
    }

    // ================================================================ 导航（内部步骤 0 / 2 / 3）

    private bool CanEnterUninstallStep(int step)
    {
        if (_busy || _uninstallOperationActive)
        {
            return false;
        }

        // 已完成或未解决：只允许停留在当前第 3 步确认现场，不再返回任何输入页。
        if ((_uninstallCompleted || HasUnresolvedUninstallState) && step != _uninstallStep)
        {
            return false;
        }

        return step switch
        {
            0 => true,
            // 卸载不使用内部全新备份页：该步始终不可进入。
            1 => false,
            2 => HasUninstallBackupPrerequisite,
            3 => _uninstallBackend is not null && HasPreparedUninstallBootPlan && _uninstallOriginal is not null,
            _ => false,
        };
    }

    private static int NextUninstallStep(int step) => step == 0 ? 2 : step == 2 ? 3 : step;

    private static int PreviousUninstallStep(int step) => step == 3 ? 2 : step == 2 ? 0 : step;

    private void OnUninstallNavChecked(object? sender, RoutedEventArgs e)
    {
        if (_suppressUninstallNav || sender is not RadioButton { IsChecked: true, Tag: string tag })
        {
            return;
        }

        NavigateUninstallStep(int.Parse(tag, CultureInfo.InvariantCulture));
    }

    /// <summary>卸载向导导航唯一入口：越界、忙碌、隐藏步骤或门槛未满足时拒绝并恢复勾选。</summary>
    private void NavigateUninstallStep(int step)
    {
        if (_busy || step is < 0 or > 3 || step == 1)
        {
            RestoreUninstallNav();
            return;
        }

        if (step != _uninstallStep && !CanEnterUninstallStep(step))
        {
            RestoreUninstallNav();
            return;
        }

        _uninstallStep = step;
        RenderUninstallPages();
        UninstallPage.ScrollToHome();
    }

    private void RestoreUninstallNav()
    {
        _suppressUninstallNav = true;
        try
        {
            UninstallNavCheck.IsChecked = _uninstallStep == 0;
            UninstallNavSources.IsChecked = _uninstallStep == 2;
            UninstallNavConfirm.IsChecked = _uninstallStep == 3;
        }
        finally
        {
            _suppressUninstallNav = false;
        }
    }

    private void OnUninstallPrevious(object? sender, RoutedEventArgs e)
    {
        if (!_busy)
        {
            NavigateUninstallStep(PreviousUninstallStep(_uninstallStep));
        }
    }

    /// <summary>来源页「下一步」是真实只读准备；其他步骤纯导航。</summary>
    private async void OnUninstallNext(object? sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        if (_uninstallStep == 2)
        {
            await PrepareUninstallConfirmationAsync();
            return;
        }

        NavigateUninstallStep(NextUninstallStep(_uninstallStep));
    }

    // ================================================================ 渲染

    private void RenderUninstallPages()
    {
        RestoreUninstallNav();

        UninstallCheckPage.IsVisible = _uninstallStep == 0;
        UninstallSourcesPage.IsVisible = _uninstallStep == 2;
        UninstallConfirmPage.IsVisible = _uninstallStep == 3;

        UninstallOriginalBox.Text = _uninstallOriginalDirectory ?? string.Empty;
        SyncUninstallRestoreStockCheckboxes();

        RenderUninstallConfirmPage();
        RenderUninstallCheckButton();
        RenderUninstallRuntimeStatus();
        if (_uninstallStep == 2)
        {
            RenderUninstallPreparationError();
        }

        RenderUninstallPower();
        RefreshUninstallActions();
    }

    /// <summary>9008 路线使用专门的识别文案；卸载默认走完整自动检查，使用内部自动重启文案。</summary>
    private void RenderUninstallCheckButton() =>
        SetText(
            UninstallCheckButtonText,
            _uninstallAlreadyEdl ? "Dynamic.BootMaintenance.CheckEdl" : "Static.InternalInstall.Check.Button");

    private void RenderUninstallPower() => SetText(UninstallPowerText, PowerMessage(_uninstallPower));

    private void RenderUninstallCheckPlaceholders()
    {
        SetText(UninstallModelText, "Dynamic.RawValue", UnknownValue);
        SetText(UninstallSerialText, "Dynamic.RawValue", UnknownValue);
        SetText(UninstallFirmwareText, "Dynamic.RawValue", UnknownValue);
        SetText(UninstallBootloaderText, "Dynamic.RawValue", UnknownValue);
        SetText(UninstallRouteText, "Dynamic.RawValue", UnknownValue);
        SetText(UninstallCheckProgressText, "Static.InternalInstall.Check.ProgressInitial");
        SetText(UninstallCheckStatusText, "Static.InternalInstall.Check.StatusInitial");
        RenderUninstallPower();
    }

    /// <summary>
    /// 确认页：只按真实准备结果显示设备身份、当前与恢复后的容量、槽位方案与删除范围；
    /// 尾部空间回收说明只在 Core 校验的备份分区真实存在时出现。
    /// </summary>
    private void RenderUninstallConfirmPage()
    {
        UninstallSlotsPanel.Children.Clear();
        UninstallRegionsHost.Children.Clear();

        var backend = _uninstallBackend;
        var inputs = backend?.Inputs;
        if (backend is null || inputs is null || !HasPreparedUninstallBootPlan)
        {
            SetText(UninstallDeviceText, "Dynamic.RawValue", string.Empty);
            SetText(UninstallCapacityText, "Dynamic.RawValue", string.Empty);
            SetText(UninstallConfirmStatusText, "Dynamic.UserdataUninstall.NotPrepared");
            SetText(UninstallProgressText, "Dynamic.RawValue", string.Empty);
            UninstallProgressBar.IsIndeterminate = false;
            UninstallProgressBar.Value = 0;
            return;
        }

        SetText(UninstallConfirmStatusText, "Dynamic.UserdataUninstall.Status.Prepared");
        SetText(UninstallDeviceText, M(
            "Dynamic.UserdataUninstall.DeviceSummary",
            UiText.ModelName(inputs.Identity.Model),
            inputs.Identity.Serial,
            backend.CurrentSlot));

        // 当前安卓分区字节数只来自真实校验输入；恢复后容量来自真实方案。
        SetText(UninstallCapacityText, M(
            "Dynamic.UserdataUninstall.CapacitySummary",
            FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)),
            FormatBytes(inputs.Plan.RestoredAndroidBytes),
            DeletedPartitionExtents(inputs),
            UninstallSelectedBootBehaviorText()));

        if (inputs.Record.BoardBackupPartUuid is not null)
        {
            var retained = NewBootMaintenanceCaption();
            SetText(retained, M(_uninstallReclaimBackup
                ? "Dynamic.UserdataUninstall.RetainedBackup"
                : "Dynamic.UserdataUninstall.KeepBackup"));
            UninstallSlotsPanel.Children.Add(retained);
        }

        // Candidate 为 null 表示该槽位不写入；勾选恢复原厂引导时以原厂方案槽位为准。
        if (!_uninstallRestoreStockBoot)
        {
            foreach (var slot in _uninstallMenu?.Slots ?? Array.Empty<CurrentBootMenuSlot>())
            {
                var slotText = NewBootMaintenanceCaption();
                SetText(slotText, slot.Candidate is null
                    ? M("Dynamic.UserdataUninstall.SlotKeep", slot.Slot)
                    : M("Dynamic.UserdataUninstall.SlotWriteDefault", slot.Slot, slot.SourceSlot ?? string.Empty));
                UninstallSlotsPanel.Children.Add(slotText);
            }
        }

        foreach (var number in inputs.Plan.RemovedPartitionNumbers)
        {
            var regionText = NewBootMaintenanceCaption();
            SetText(regionText, M("Dynamic.UserdataUninstall.RemovedPartition", number));
            UninstallRegionsHost.Children.Add(regionText);
        }

        if (_uninstallRestoreStockBoot)
        {
            RenderUninstallStockPlanSlots();
        }
    }

    /// <summary>准备中的粗粒度中性进度：有真实总量时显示观察字节，否则保持不确定。</summary>
    private void RenderUninstallPrepareProgress(EdlUninstallProgress report)
    {
        if (_closeConfirmed || !_uninstallOperationActive)
        {
            return;
        }

        if (report.TotalBytes > 0)
        {
            UninstallProgressBar.IsIndeterminate = false;
            UninstallProgressBar.Value = Math.Clamp((double)report.CompletedBytes / report.TotalBytes * 100d, 0d, 100d);
            SetText(UninstallProgressText, M(
                "Dynamic.UserdataUninstall.Progress.Transferring",
                FormatBytes(report.CompletedBytes),
                FormatBytes(report.TotalBytes)));
        }
        else
        {
            UninstallProgressBar.IsIndeterminate = true;
            SetText(UninstallProgressText, M("Dynamic.UserdataUninstall.Progress.TransferringUnknown"));
        }
    }

    private void RenderUninstallPreparationError()
    {
        if (string.IsNullOrWhiteSpace(_uninstallError))
        {
            return;
        }

        var message = _uninstallError.StartsWith("requires-current-bootloader-state:", StringComparison.Ordinal)
            ? M("Dynamic.UserdataUninstall.Status.LockCheckRequired")
            : M("Dynamic.UserdataUninstall.Status.PrepareFailureDetail", _uninstallError);
        SetText(UninstallPrepareStatusText, message);
    }

    private void AppendUninstallLog(UiMessage message)
    {
        var row = _l.AppendLogRow(UninstallLogList, message, MaxLogRows);
        row.FontSize = 12;
        row.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        row.Margin = new Avalonia.Thickness(0, 0, 0, 4);
        row[!TextBlock.ForegroundProperty] = row.GetResourceObservable("MutedBrush").ToBinding();

        UninstallLogEmptyText.IsVisible = false;
        UninstallLogScrollViewer.ScrollToEnd();
    }

    // ---------- 容量与删除范围文案（WPF MainWindow.Uninstall.cs） ----------

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

    /// <summary>可空容量：Core 只报告总量时显示占位符，绝不补 0。</summary>
    private static string FormatBytesOrPlaceholder(long? bytes) =>
        bytes is long value && value >= 0 ? FormatBytes(value) : UnknownValue;

    // ================================================================ 可用性

    /// <summary>The WPF RefreshModernUserdataUninstallActions plus the shared check-step controls it refreshes.</summary>
    private void RefreshUninstallActions()
    {
        var protectedState = ProtectedUninstallState;

        UninstallNavCheck.IsEnabled = !_busy && CanEnterUninstallStep(0);
        UninstallNavSources.IsEnabled = !_busy && CanEnterUninstallStep(2);
        UninstallNavConfirm.IsEnabled = !_busy && CanEnterUninstallStep(3);

        var previousStep = PreviousUninstallStep(_uninstallStep);
        UninstallPrevButton.IsEnabled = !_busy
            && previousStep != _uninstallStep
            && CanEnterUninstallStep(previousStep);

        UninstallNextButton.IsVisible = _uninstallStep < 3;
        // 已知活动操作期间绝不只凭已选路径开放下一步；第 2 步还需真实设备入口前提。
        UninstallNextButton.IsEnabled = !_busy
            && !protectedState
            && _uninstallStep < 3
            && (_uninstallStep < 2
                ? CanEnterUninstallStep(NextUninstallStep(_uninstallStep))
                : HasUninstallBackupPrerequisite);

        UpdateUninstallRestoreStockCheckboxEnabled();

        UninstallActionButton.IsVisible = _uninstallStep == 3;
        UninstallActionButton.IsEnabled = CanExecuteUninstall();

        // 卸载完成后所有输入都收口，空闲判定额外要求未完成。
        var idle = !_busy
            && !_uninstallOperationActive
            && !_uninstallDeviceOperationActive
            && !_uninstallCompleted;

        UninstallBackButton.IsEnabled = !_busy && !_uninstallDeviceOperationActive && !protectedState;

        var many = _uninstallDeviceChoices.Count > 0;
        UninstallDevicesLabel.IsVisible = many;
        UninstallDevicesCombo.IsVisible = many;
        UninstallDevicesCombo.IsEnabled = idle
            && !protectedState
            && !HasUninstallLiveEdlState
            && !_uninstallAlreadyEdl
            && many;

        UninstallCheckButton.IsEnabled = idle
            && !protectedState
            && (!HasUninstallLiveEdlState || _uninstallEdlClient?.Binding.OfflineIdentity is not null);
        UninstallFastbootCheckButton.IsEnabled = idle
            && !protectedState
            && !HasUninstallLiveEdlState
            && !_uninstallAlreadyEdl;
        UninstallAlreadyEdlCheck.IsEnabled = idle && !protectedState && !HasUninstallLiveEdlState;

        UninstallOriginalBrowseButton.IsEnabled = idle && !protectedState;

        // 风险勾选：只在空闲、无保护、未完成，且三个真实对象（非路径）都存在时开放。
        UninstallRiskCheck.IsEnabled = idle
            && !protectedState
            && _uninstallBackend is not null
            && HasPreparedUninstallBootPlan
            && _uninstallOriginal is not null;

        // 退出面板只在真实 9008 会话存在且尚未完成时可见；按钮按空闲与未解决状态收紧。
        var exitVisible = HasUninstallLiveEdlState && !_uninstallCompleted;
        UninstallExitPanel.IsVisible = exitVisible;
        if (exitVisible)
        {
            SetText(UninstallExitStatusText, _uninstallExitStatus ?? M("Dynamic.UserdataUninstall.Exit.Ready"));
        }

        UninstallExitButton.IsEnabled = idle
            && !HasUnresolvedUninstallState
            && _uninstallEdlClient is not null;
    }

    /// <summary>执行按钮的唯一事实谓词（WPF CanExecuteModernUserdataUninstall）。</summary>
    private bool CanExecuteUninstall() =>
        _uninstallStep == 3
        && !_busy
        && !_uninstallOperationActive
        && !_uninstallExecuteAttempted
        && !_uninstallCompleted
        && !_uninstallResetAttempted
        && HasUninstallDeviceProof
        && !HasUnresolvedUninstallState
        && UninstallRiskCheck.IsChecked == true
        && (!_uninstallRestoreStockBoot
            || (_uninstallStockPlan is not null && _uninstallStockPlan.Mode == MaintenanceMode.RestoreStock))
        && _uninstallBackend is not null
        && HasPreparedUninstallBootPlan
        && _uninstallOriginal is not null
        && _uninstallBackup is not null
        && _uninstallEdlClient is not null
        && _uninstallEdlEntry is not null
        && !string.IsNullOrWhiteSpace(_uninstallBackupParent);

    private void OnUninstallRiskChanged(object? sender, RoutedEventArgs e) => RefreshUninstallActions();

    // ================================================================ 01 检查

    private ConnectedDevice? SelectedUninstallDevice() =>
        UninstallDevicesCombo.SelectedIndex is int index && index >= 0 && index < _uninstallDeviceChoices.Count
            ? _uninstallDeviceChoices[index]
            : null;

    private void PopulateUninstallDevices(IReadOnlyList<ConnectedDevice> devices, string? previousSerial)
    {
        _uninstallDeviceChoices = devices;
        _suppressUninstallDeviceSelection = true;
        try
        {
            UninstallDevicesCombo.ItemsSource = devices
                .Select(device => $"{device.Serial}  ({_l.T(ConnectionStateKey(device.ConnectionState))})")
                .ToList();
            // 唯一设备直接选中；多台时只恢复用户之前选中的那一台，绝不预选第一项。
            var index = devices.Count == 1 ? 0 : devices.ToList().FindIndex(device => device.Serial == previousSerial);
            UninstallDevicesCombo.SelectedIndex = index;
        }
        finally
        {
            _suppressUninstallDeviceSelection = false;
        }
    }

    /// <summary>用户在下拉框里换了设备：上一台设备的一切结论立即作废，并回到第 0 步。</summary>
    private void OnUninstallDeviceSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (_busy || _suppressUninstallDeviceSelection || _uninstallDeviceOperationActive)
        {
            return;
        }

        ResetUninstallCheckState();
        _uninstallStep = 0;
        RenderUninstallPages();
    }

    private async void OnCheckUninstallDevice(object? sender, RoutedEventArgs e) =>
        await CheckUninstallDeviceAsync(advanced: false);

    private async void OnCheckUninstallDeviceAdvanced(object? sender, RoutedEventArgs e) =>
        await CheckUninstallDeviceAsync(advanced: true);

    /// <summary>
    /// 「检查平板」：卸载需要为保留项目引导取得当前锁状态，默认与「高级：核验 Bootloader」都走完整自动检查
    /// （安卓 -> Fastboot -> 安卓）；已勾选「平板已在 9008」时走恢复资料的 9008 只读核对。
    /// </summary>
    private async Task CheckUninstallDeviceAsync(bool advanced)
    {
        if (_busy || _uninstallDeviceOperationActive || _uninstallOperationActive || ProtectedUninstallState)
        {
            return;
        }

        if (_uninstallAlreadyEdl && !advanced)
        {
            await CheckUninstallBoardRecoveryEdlAsync();
            return;
        }

        // 存在真实 9008 会话：不允许把平板当安卓重新检查，保留现状。
        if (HasUninstallLiveEdlState)
        {
            SetText(UninstallCheckStatusText, M("Dynamic.Workflow.NotPrepared", M("Dynamic.Mode.Uninstall")));
            return;
        }

        if (_adbPath is null)
        {
            SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.ToolsRequired");
            return;
        }

        var previousSerial = SelectedUninstallDevice()?.Serial;

        // 重新检查前先清掉上一轮结论：结果、电量与派生界面一起回到「未检查」。
        ResetUninstallCheckState();

        _uninstallDeviceOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetText(UninstallCheckProgressText, "Dynamic.InternalInstall.Check.Listing");
                    var transport = Transport;
                    var devices = await transport.ListDevicesAsync(token);
                    PopulateUninstallDevices(devices, previousSerial);

                    if (devices.Count == 0)
                    {
                        SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.NoDevices");
                        return;
                    }

                    var target = devices.Count == 1 ? devices[0] : SelectedUninstallDevice();
                    if (target is null)
                    {
                        SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.MultipleNeedSelection", devices.Count);
                        return;
                    }

                    if (target.ConnectionState != ConnectionState.Authorized)
                    {
                        SetText(
                            UninstallCheckStatusText,
                            M("Dynamic.InternalInstall.Check.NotAuthorized", target.Serial, M(ConnectionStateKey(target.ConnectionState))));
                        return;
                    }

                    SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.Started", target.Serial);

                    var progress = new Progress<InternalDeviceCheckProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            SetText(UninstallCheckProgressText, CheckStageKey(report.Stage));
                        }
                    });

                    var check = new InternalInstallDeviceCheck(transport.AdbPath, transport.FastbootPath, _runner);
                    var result = await check.CheckAsync(target.Serial, progress, token);
                    acceptProgress = false;
                    _uninstallDeviceCheck = result;
                    RenderUninstallDeviceCheck(result);

                    if (!result.Succeeded && !result.Cancelled)
                    {
                        AppendUninstallLog(M("Dynamic.InternalInstall.Check.FailedStage", M(CheckStageKey(result.FailedStage))));
                        AppendUninstallLog(M("Dynamic.InternalInstall.Check.Failed", Placeholder(result.Error)));
                    }

                    if (result.Succeeded && result.AndroidReturn == AndroidReturnState.Verified)
                    {
                        _uninstallPower = await CapturePowerAsync(transport.AdbPath, result.Android!.Identity.Serial, token);
                    }

                    RenderUninstallPower();
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    acceptProgress = false;
                    _uninstallDeviceCheck = null;
                    _uninstallPower = null;
                    RenderUninstallCheckPlaceholders();
                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message) ? UnknownValue : exception.Message;
                    SetText(UninstallCheckProgressText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
                    SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
                    AppendUninstallLog(M("Dynamic.InternalInstall.Check.Failed", diagnostic));
                }
            });
        }
        finally
        {
            _uninstallDeviceOperationActive = false;
            RenderUninstallPages();
            RefreshActions();
        }
    }

    /// <summary>把真实完整检查结果写进字段：型号 / 序列号 / 固件 / 引导锁全部来自返回事实。</summary>
    private void RenderUninstallDeviceCheck(InternalDeviceCheckResult result)
    {
        var identity = result.Android?.Identity;
        var firmware = identity?.Firmware;
        SetText(UninstallModelText, UiText.ModelName(identity?.Model));
        SetText(UninstallSerialText, "Dynamic.RawValue", Placeholder(identity?.Serial ?? result.FastbootSerial));
        SetText(UninstallFirmwareText, "Dynamic.RawValue", Placeholder(firmware?.DisplayId ?? firmware?.BuildFingerprint));
        SetText(UninstallBootloaderText, BootStateKey(result.FastbootLockState));

        if (result.Cancelled)
        {
            SetText(UninstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(UninstallCheckProgressText, "Dynamic.InternalInstall.Check.Cancelled");
            SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.Cancelled");
            return;
        }

        if (!result.Succeeded)
        {
            SetText(UninstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(UninstallCheckProgressText, M("Dynamic.InternalInstall.Check.FailedStage", M(CheckStageKey(result.FailedStage))));
            var error = Placeholder(result.Error);
            SetText(
                UninstallCheckStatusText,
                result.AndroidReturn == AndroidReturnState.Unconfirmed
                    ? M("Dynamic.InternalInstall.Check.ReturnUnconfirmed", error)
                    : M("Dynamic.InternalInstall.Check.Failed", error));
            return;
        }

        SetText(UninstallCheckProgressText, "Dynamic.InternalInstall.Check.Progress.Completed");
        if (HasCheckedUninstallDevice)
        {
            SetText(UninstallRouteText, "Dynamic.InternalInstall.Check.RoutePassed");
            SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.Passed");
            return;
        }

        // 检查本身通过，但该型号的写入路线尚未开放：如实说明，后续门槛保持关闭。
        SetText(UninstallRouteText, "Dynamic.InternalInstall.Check.RouteUnavailable");
        SetText(
            UninstallCheckStatusText,
            DeviceModelRoutes.IsWriteRoutePending(identity?.Model)
                ? M("Dynamic.Model.RoutePending", UiText.ModelName(identity?.Model))
                : M("Dynamic.InternalInstall.Check.ProfileUnavailable"));
    }

    /// <summary>
    /// 清空检查结论（WPF ResetInternalInstallCheckState 的卸载分支）：操作进行中或受保护时拒绝；先作废卸载准备并释放
    /// 当前状态快照与恢复资料的只读锁；已有 9008 会话与工具链不受影响。
    /// </summary>
    private void ResetUninstallCheckState()
    {
        if (_uninstallDeviceOperationActive || ProtectedUninstallState)
        {
            return;
        }

        InvalidateUninstallPreparation();
        _uninstallDeviceCheck = null;
        _uninstallPower = null;
        ReleaseUninstallBackupObject();
        RenderUninstallCheckPlaceholders();
    }

    // 勾选只改变路线偏好（下一步走 9008 识别），不改变任何设备证据；已有真实 9008 会话、保护状态或繁忙时拒绝。
    private void OnUninstallEdlRouteChanged(object? sender, RoutedEventArgs e)
    {
        var requested = UninstallAlreadyEdlCheck.IsChecked == true;
        if (requested == _uninstallAlreadyEdl)
        {
            return;
        }

        if (_busy || _uninstallOperationActive || ProtectedUninstallState || HasUninstallLiveEdlState)
        {
            UninstallAlreadyEdlCheck.IsChecked = _uninstallAlreadyEdl;
            return;
        }

        ResetUninstallCheckState();
        _uninstallHistoricalIdentity = null;
        InvalidateUninstallPreparation();

        _uninstallAlreadyEdl = requested;
        RenderUninstallCheckButton();
        RefreshUninstallActions();
    }

    /// <summary>
    /// 「平板已在 9008」路线（WPF CheckUninstallBoardRecoveryEdlAsync）：识别当前 9008 端点的硬件身份并绑定；
    /// 已选电脑原厂备份时用它核对保存身份，否则先读平板内恢复资料，都不可用时再请用户选择电脑备份。
    /// 只读、不进安卓、不写入、不自动重试。
    /// </summary>
    private async Task CheckUninstallBoardRecoveryEdlAsync()
    {
        if (_busy
            || !_uninstallAlreadyEdl
            || _uninstallDeviceOperationActive
            || ProtectedUninstallState
            || (HasUninstallLiveEdlState && _uninstallEdlClient?.Binding.OfflineIdentity is null))
        {
            return;
        }

        if (_adbPath is null)
        {
            SetText(UninstallCheckStatusText, "Dynamic.InternalInstall.Check.ToolsRequired");
            return;
        }

        var parent = _uninstallBackupParent;
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            try
            {
                parent = UninstallRecoveryOutputDirectory();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // 缓存目录不可写：在本流程的状态里报告失败，保留会话，不让异常逃出 async void 处理程序。
                SetText(UninstallCheckStatusText, M("Dynamic.RecoverySource.Failed", error.Message));
                AppendUninstallLog(M("Dynamic.RecoverySource.Failed", error.Message));
                return;
            }
        }

        _uninstallBackupParent = parent;
        _uninstallDeviceOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    var client = _uninstallEdlClient;
                    if (client is null)
                    {
                        _uninstallBoardRecoveryDirectory = null;
                        EdlHardwareIdentity hardware;
                        using (var detector = await LoadGlobalToolsAsync(EdlDeviceProfiles.FindByModel("TB322FC")!, token))
                        {
                            var clientPath = detector.ClientPath;
                            hardware = await Task.Run(
                                () => GlobalEdlDetection.DetectIdentityAsync(clientPath, _runner, Discovery, null, token),
                                token);
                        }

                        var profile = hardware.Profile;
                        if (DeviceModelRoutes.IsWriteRoutePending(profile.Model))
                        {
                            throw new InvalidOperationException(
                                T("Dynamic.Model.RoutePendingInEdl", UiText.ModelName(profile.Model)));
                        }

                        var tools = await LoadGlobalToolsAsync(profile, token);
                        try
                        {
                            var entry = await Task.Run(() => GlobalEdlBinding.Attach(profile, Discovery), token);
                            client = new EdlClient(tools, entry, _runner, Discovery, hardware);
                            _uninstallEdlTools = tools;
                            _uninstallEdlEntry = entry;
                            _uninstallEdlClient = client;
                            _uninstallEntryAttempted = true;
                        }
                        catch
                        {
                            tools.Dispose();
                            throw;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(_uninstallOriginalDirectory))
                    {
                        var chosen = UninstallBackupDirectorySelection.Resolve(_uninstallOriginalDirectory);
                        if (chosen.Kind != UninstallBackupDirectorySelection.SelectionKind.Selected || chosen.DirectoryPath is null)
                        {
                            throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedSpecificOriginal"));
                        }

                        await BindUninstallRecoveryIdentityAsync(client, chosen.DirectoryPath, token);
                        _uninstallOriginalDirectory = chosen.DirectoryPath;
                        AppendUninstallLog(M("Dynamic.RecoverySource.PcReady", chosen.DirectoryPath));
                        return;
                    }

                    AppendUninstallLog(M("Dynamic.RecoverySource.ReadingBoard"));
                    var source = _uninstallBoardRecoveryDirectory;
                    var connected = false;
                    if (source is not null)
                    {
                        try
                        {
                            await BindUninstallRecoveryIdentityAsync(client, source, token);
                            connected = true;
                        }
                        catch (Exception error) when (IsRecoverySourceFailure(error))
                        {
                            source = null;
                            _uninstallBoardRecoveryDirectory = null;
                            AppendUninstallLog(M("Dynamic.RecoverySource.BoardInvalid", error.Message));
                        }
                    }

                    if (!connected)
                    {
                        BoardRecoveryExtraction? extraction = null;
                        try
                        {
                            var readClient = client;
                            var durableParent = parent;
                            var workRoot = UninstallWorkRoot;
                            extraction = await Task.Run(
                                () => BoardRecoveryBackup.ReadDirectoryAsync(readClient, durableParent, workRoot, token),
                                token);
                            if (extraction is not null)
                            {
                                await BindUninstallRecoveryIdentityAsync(client, extraction.DirectoryPath, token);
                                extraction.Retain();
                                source = extraction.DirectoryPath;
                            }
                            else
                            {
                                source = null;
                            }

                            _uninstallBoardRecoveryDirectory = source;
                        }
                        catch (Exception error) when (IsRecoverySourceFailure(error))
                        {
                            source = null;
                            _uninstallBoardRecoveryDirectory = null;
                            AppendUninstallLog(M("Dynamic.RecoverySource.BoardInvalid", error.Message));
                        }
                        finally
                        {
                            // Only a successful bind retained the extraction; every failure has already released the
                            // backup locks inside the bind helper before this lease removes the directory it created.
                            extraction?.Dispose();
                        }
                    }

                    if (source is null)
                    {
                        var selected = _uninstallOriginalDirectory
                            ?? await PickBootMaintenanceFolderAsync("Dynamic.RecoverySource.PickOriginal");
                        if (selected is null)
                        {
                            throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedOriginal"));
                        }

                        var selection = UninstallBackupDirectorySelection.Resolve(selected);
                        source = selection.Kind == UninstallBackupDirectorySelection.SelectionKind.Selected
                            ? selection.DirectoryPath
                            : throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedSpecificOriginal"));
                        await BindUninstallRecoveryIdentityAsync(client, source!, token);
                        _uninstallOriginalDirectory = source;
                    }
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    SetText(UninstallCheckStatusText, M("Dynamic.RecoverySource.Failed", error.Message));
                    AppendUninstallLog(M("Dynamic.RecoverySource.Failed", error.Message));
                }
            });
        }
        finally
        {
            _uninstallDeviceOperationActive = false;
            RenderUninstallPages();
            RefreshActions();
        }
    }

    private static bool IsRecoverySourceFailure(Exception error) =>
        error is IOException
            or InvalidOperationException
            or ArgumentException
            or JsonException
            or FormatException
            or InvalidDataException;

    /// <summary>
    /// 用恢复资料的保存身份把同一 9008 端点重新绑定（WPF BindUninstallRecoveryIdentityAsync）：等待端点出现、
    /// 带保存身份重建客户端并只读打开一次恢复资料核对，成功后才提交客户端、entry 与历史身份。
    /// </summary>
    private async Task BindUninstallRecoveryIdentityAsync(EdlClient client, string source, CancellationToken token)
    {
        var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(source, token);
        if (history.Profile.ProfileId != client.Toolchain.ProfileId)
        {
            throw new InvalidDataException(T("Dynamic.RecoverySource.WrongDevice"));
        }

        var transport = Transport;
        var savedEntry = await Task.Run(
            () => new EdlEntry(transport.AdbPath, _runner, Discovery).WaitForPresentAsync(history.Identity, history.Profile, token),
            token);
        var probeOutput = Path.Combine(UninstallWorkRoot, $"uninstall-recovery-{Guid.NewGuid():N}", "probe.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(probeOutput)!);
        var rebound = await Task.Run(() => client.WithSavedIdentityAsync(savedEntry, probeOutput, token), token);
        using var verified = await Task.Run(
            () => InternalInstallBackup.OpenRecoveryAsync(rebound, source, token: token),
            token);
        _uninstallEdlClient = rebound;
        _uninstallEdlEntry = savedEntry;
        _uninstallHistoricalIdentity = history;
        SetText(UninstallCheckStatusText, M("Dynamic.RecoverySource.Connected", UiText.ModelName(history.Model)));
    }

    // ================================================================ 当前状态快照（WPF 共享全新备份的卸载分支）

    /// <summary>
    /// 准备前自动另存的当前状态回滚快照（WPF BackupInternalInstallCoreAsync 在卸载模式下）：已在 9008 的路线复用
    /// 同一会话；默认路线重新读取安卓身份、只进入一次 9008，再做只读备份并从新备份读取真实历史身份。
    /// </summary>
    private async Task BackupUninstallAsync()
    {
        if (_busy || _uninstallDeviceOperationActive || ProtectedUninstallState)
        {
            return;
        }

        if (_uninstallAlreadyEdl)
        {
            await BackupUninstallEdlAsync();
            return;
        }

        var storedAndroid = HasCheckedUninstallDevice ? _uninstallDeviceCheck!.Android : null;
        var parent = _uninstallBackupParent;
        if (storedAndroid is null || !HasUninstallBackupPrerequisite)
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.NeedCheck"));
            return;
        }

        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        // 快照父目录绝不能落在已选原厂来源目录里面；来源永不作为当前目录。
        if (!string.IsNullOrWhiteSpace(_uninstallOriginalDirectory)
            && !IsGlobalOutputOutsideSource(parent, _uninstallOriginalDirectory!))
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", _uninstallOriginalDirectory!));
            return;
        }

        InvalidateUninstallPreparation();

        var existingClient = _uninstallEdlClient;
        var entry = _uninstallEdlEntry;
        var reuse = existingClient is not null && _uninstallEdlTools is not null && entry is not null;

        if (!reuse && _uninstallEntryAttempted)
        {
            // 进入 9008 的结果尚未确认：不允许第二次自动进入，也不允许假装没有发生。
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.EntryUnconfirmed"));
            return;
        }

        var selectedIdentity = storedAndroid.Identity;

        // 写入路线尚未开放的型号（TB710FU）：在进入 9008 之前停下。
        if (DeviceModelRoutes.IsWriteRoutePending(selectedIdentity.Model))
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.Model.RoutePending", UiText.ModelName(selectedIdentity.Model)));
            return;
        }

        var profile = EdlDeviceProfiles.FindByModel(selectedIdentity.Model);
        if (profile is null
            || !profile.IsComplete
            || !profile.SupportsIdentity(selectedIdentity)
            || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            SetText(
                UninstallPrepareStatusText,
                M("Dynamic.InternalInstall.Backup.ProfileUnavailable",
                    UiText.ModelName(selectedIdentity.Model),
                    Placeholder(selectedIdentity.Firmware?.DisplayId)));
            return;
        }

        if (reuse && !UninstallAndroidMatches(storedAndroid, entry!.AndroidIdentity))
        {
            // 现有会话不是这次检查确认的那台平板：停止，但保留会话与工具，等用户回到第 1 步重查。
            ReleaseUninstallBackupObject();
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.BindingChanged"));
            RefreshUninstallActions();
            return;
        }

        ReleaseUninstallBackupObject();

        var expected = storedAndroid;
        var parentPath = parent!;
        var transport = Transport;

        _uninstallDeviceOperationActive = true;
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
                        SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.PreparingTools"));

                        // 只解包所选可信配置自己的归档，绝不回退到固定资源名。
                        await using (var archive = MacTools.Open(profile.ArchiveLogicalName!))
                        {
                            if (archive is null)
                            {
                                acceptProgress = false;
                                SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.ToolsRequired"));
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
                            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.ToolchainMismatch", loadedModel, loadedBuild));
                            return;
                        }

                        SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.Reproving"));

                        // 模式切换前重新读取真实安卓身份与 SoC 序列号，并与第 1 步的结果逐项比对。
                        var freshIdentity = await transport.ReadAdbIdentityAsync(expected.Identity.Serial, token);
                        var freshAndroid = await new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner)
                            .ReadAndroidAsync(freshIdentity, token);

                        if (!UninstallAndroidMatches(expected, freshAndroid)
                            || !profile.SupportsIdentity(freshAndroid.Identity))
                        {
                            loaded.Dispose();
                            pendingTools = null;
                            acceptProgress = false;
                            InvalidateUninstallCheckFromMismatch();
                            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
                            return;
                        }

                        // 已有采样时才在进入 9008 之前刷新一次；没有采样就不凭空补一个。
                        if (_uninstallPower is not null)
                        {
                            _uninstallPower = await CapturePowerAsync(transport.AdbPath, freshIdentity.Serial, token);
                            RenderUninstallPower();
                        }

                        // 工具链先落到字段：进入 9008 之后即使失败也保留现场供诊断。
                        _uninstallEdlTools = loaded;
                        pendingTools = null;

                        _uninstallEntryAttempted = true;
                        SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.EnteringEdl"));

                        // 整个流程只会在这里真实进入一次 9008，不自动重试；显式传入刚核对过的可信配置。
                        var entered = await Task.Run(
                            () => new EdlEntry(transport.AdbPath, _runner, Discovery).EnterAsync(freshAndroid, loaded.Profile, token),
                            token);

                        _uninstallEdlEntry = entered;
                        activeClient = new EdlClient(loaded, entered, _runner, Discovery);
                        _uninstallEdlClient = activeClient;
                        AppendUninstallLog(M("Dynamic.RawValue", $"9008: {entered.Endpoint.DeviceInstanceId}  SN {entered.BusSerialHex}"));
                    }
                    else
                    {
                        // 复用同一会话：不重新加载工具链、不再走 adb、也不再进入 9008。
                        activeClient = existingClient;
                    }

                    SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.Reading"));

                    // 复用已有会话时客户端可能还没有首次 Sahara 证明：在读取之前只读探测一次。
                    if (!activeClient.HasInitialSaharaProof)
                    {
                        await Task.Run(() => activeClient.ProbeAsync(0, true, token), token);
                    }

                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderUninstallBackupProgress(report);
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
                        _uninstallBackup = set;
                        _uninstallHistoricalIdentity = sharedHistory;
                    }
                    catch
                    {
                        set.Dispose();
                        throw;
                    }

                    RenderUninstallBackupSuccess(set);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    acceptProgress = false;
                    _uninstallBackup = null;
                    var diagnostic = string.IsNullOrWhiteSpace(exception.Message) ? UnknownValue : exception.Message;
                    var failure = exception is OperationCanceledException
                        ? M("Dynamic.InternalInstall.Backup.Cancelled", parentPath)
                        : M("Dynamic.InternalInstall.Backup.Failed", diagnostic, parentPath);
                    SetText(UninstallPrepareStatusText, failure);
                    AppendUninstallLog(failure);
                }
                finally
                {
                    // 从未用于任何设备命令的暂存工具链在失败后释放；已经进入 9008 的那一份由字段保留。
                    if (pendingTools is not null && !ReferenceEquals(pendingTools, _uninstallEdlTools))
                    {
                        pendingTools.Dispose();
                    }
                }
            });
        }
        finally
        {
            _uninstallDeviceOperationActive = false;
            RefreshActions();
        }
    }

    /// <summary>
    /// 「平板已在 9008」路线的全新只读快照：严格复用恢复资料核对建立的同一客户端 / 工具链 / entry，
    /// 只调用 InternalInstallBackup.CreateAsync，成功前不保存任何备份集合。
    /// </summary>
    private async Task BackupUninstallEdlAsync()
    {
        if (_busy
            || _uninstallDeviceOperationActive
            || !_uninstallAlreadyEdl
            || !HasUninstallDeviceProof
            || ProtectedUninstallState)
        {
            return;
        }

        var client = _uninstallEdlClient;
        var tools = _uninstallEdlTools;
        var entry = _uninstallEdlEntry;
        var parent = _uninstallBackupParent;

        if (entry is null || client is null || tools is null
            || string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.NeedFolder"));
            return;
        }

        foreach (var source in new[] { _uninstallHistoricalIdentity?.DirectoryPath, _uninstallOriginalDirectory })
        {
            if (!string.IsNullOrWhiteSpace(source) && !IsGlobalOutputOutsideSource(parent, source!))
            {
                SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.ExistingWorkRootConflict", source!));
                return;
            }
        }

        InvalidateUninstallPreparation();
        ReleaseUninstallBackupObject();

        _uninstallDeviceOperationActive = true;
        SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.RunningNote"));

        var parentPath = parent!;
        try
        {
            await RunBusyAsync(async token =>
            {
                var acceptProgress = true;
                try
                {
                    SetText(UninstallPrepareStatusText, M("Dynamic.InternalInstall.Backup.Reading"));
                    var progress = new Progress<InternalBackupProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderUninstallBackupProgress(report);
                        }
                    });

                    var set = await Task.Run(
                        () => InternalInstallBackup.CreateAsync(client, parentPath, progress, token),
                        token);
                    _uninstallBackup = set;
                    RenderUninstallBackupSuccess(set);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    _uninstallBackup = null;
                    SetText(UninstallPrepareStatusText, M("Dynamic.BootMaintenance.Edl.ReadOnlyFailed"));
                    AppendUninstallLog(M("Dynamic.RawValue", $"{ex.GetType().FullName}: {ex.Message}"));
                }
                finally
                {
                    acceptProgress = false;
                }
            });
        }
        finally
        {
            _uninstallDeviceOperationActive = false;
            RefreshActions();
        }
    }

    private void RenderUninstallBackupSuccess(InternalBackupSet set)
    {
        SetText(UninstallPrepareStatusText, "Dynamic.InternalInstall.Backup.Succeeded", set.Files.Count);
        AppendUninstallLog(M("Dynamic.InternalInstall.Backup.SucceededLog", set.DirectoryPath, set.ManifestSha256));
    }

    /// <summary>WPF 在卸载中隐藏全新备份页，把同一份备份状态镜像到来源页的准备状态栏。</summary>
    private void RenderUninstallBackupProgress(InternalBackupProgress report)
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
            SetText(UninstallPrepareStatusText, "Dynamic.InternalInstall.Backup.Progress.Discovering", detail);
            return;
        }

        SetText(
            UninstallPrepareStatusText,
            "Dynamic.InternalInstall.Backup.Progress.Counters",
            detail,
            report.CompletedFiles,
            report.TotalFiles,
            FormatBytes(report.CompletedBytes),
            FormatBytes(report.TotalBytes));
    }

    /// <summary>身份不一致时直接作废检查结论与派生界面；绝不改写用户已选的目录，也不碰设备。</summary>
    private void InvalidateUninstallCheckFromMismatch()
    {
        _uninstallDeviceCheck = null;
        _uninstallPower = null;
        ReleaseUninstallBackupObject();
        RenderUninstallCheckPlaceholders();
        SetText(UninstallCheckStatusText, M("Dynamic.InternalInstall.Backup.IdentityMismatch"));
    }

    /// <summary>
    /// 释放当前状态快照与恢复资料只持有的只读锁（WPF ReleaseInternalInstallBackupObject 的卸载分支）：
    /// 方案对象先于备份租约作废；备份文件、清单与元数据一律保留。
    /// </summary>
    private void ReleaseUninstallBackupObject()
    {
        InvalidateUninstallPreparation();
        _uninstallRecoverySource?.Dispose();
        _uninstallRecoverySource = null;
        _uninstallBoardRecoveryAttemptManifest = null;

        var backup = _uninstallBackup;
        _uninstallBackup = null;
        try
        {
            backup?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ================================================================ 02 恢复资料与引导选项

    /// <summary>选择电脑原厂恢复备份：同一路径保留已接受来源与快照；只有真正换源才释放旧快照与准备。</summary>
    private async void OnBrowseUninstallOriginal(object? sender, RoutedEventArgs e)
    {
        if (_busy || _uninstallOperationActive || ProtectedUninstallState)
        {
            return;
        }

        if (await PickBootMaintenanceFolderAsync("Dynamic.UserdataUninstall.OriginalSource") is not { } directory
            || _busy
            || _uninstallOperationActive
            || ProtectedUninstallState)
        {
            return; // 用户取消或选择无效：完整保留现有状态。
        }

        if (!string.Equals(directory, _uninstallOriginalDirectory, StringComparison.OrdinalIgnoreCase))
        {
            // 更换来源后，旧来源不能再保持已接受：只释放备份只读对象，绝不释放仍有效的客户端 / 工具链 / 会话。
            ReleaseUninstallBackupObject();
        }

        _uninstallOriginalDirectory = directory;
        UninstallOriginalBox.Text = directory;
        InvalidateUninstallPreparation();
        RefreshUninstallActions();
    }

    /// <summary>「清除电脑备份选择，自动使用板内备份」。</summary>
    private void OnUseBoardUninstallBackup(object? sender, RoutedEventArgs e)
    {
        if (!CanUninstallToggleOptions())
        {
            return;
        }

        InvalidateUninstallPreparation();
        _uninstallOriginalDirectory = null;
        _uninstallRecoverySource?.Dispose();
        _uninstallRecoverySource = null;
        _uninstallBoardRecoveryAttemptManifest = null;
        RenderUninstallPages();
    }

    private void OnUserdataUninstallReclaimBackupChanged(object? sender, RoutedEventArgs e)
    {
        if (_uninstallStockCheckboxSuppress || sender is not CheckBox changed)
        {
            return;
        }

        if (!CanUninstallToggleOptions())
        {
            SyncUninstallRestoreStockCheckboxes();
            return;
        }

        var desired = changed.IsChecked == true;
        if (_uninstallReclaimBackup == desired)
        {
            return;
        }

        _uninstallReclaimBackup = desired;
        InvalidateUninstallPreparation();
        if (_uninstallStep >= 3)
        {
            _uninstallStep = 2;
        }

        RenderUninstallPages();
    }

    private void OnUserdataUninstallRestoreStockChanged(object? sender, RoutedEventArgs e)
    {
        if (_uninstallStockCheckboxSuppress || sender is not CheckBox changed)
        {
            return;
        }

        var desired = changed.IsChecked == true;
        if (!CanUninstallToggleOptions() || _uninstallRestoreStockBoot == desired)
        {
            SyncUninstallRestoreStockCheckboxes();
            return;
        }

        // 切换即作废上一次未写入的准备；若已在确认页，则退回来源页避免残留旧确认。
        _uninstallRestoreStockBoot = desired;
        _uninstallStockPlan = null;
        _uninstallStockRestoreResult = null;

        InvalidateUninstallPreparation();

        if (_uninstallStep >= 3)
        {
            _uninstallStep = 2;
            SetText(UninstallPrepareStatusText, "Dynamic.UserdataUninstall.RestoreStock.InvalidateHint");
        }

        RenderUninstallPages();
    }

    private bool CanUninstallToggleOptions() =>
        !_busy
        && !_uninstallOperationActive
        && !_uninstallExecuteAttempted
        && !_uninstallCompleted;

    private void SyncUninstallRestoreStockCheckboxes()
    {
        _uninstallStockCheckboxSuppress = true;
        try
        {
            UninstallRestoreStockCheck.IsChecked = _uninstallRestoreStockBoot;
            UninstallConfirmRestoreStockCheck.IsChecked = _uninstallRestoreStockBoot;
            UninstallReclaimBackupCheck.IsChecked = _uninstallReclaimBackup;
            UninstallRestoreStockHint.IsVisible = _uninstallRestoreStockBoot;
            UninstallConfirmRestoreStockHint.IsVisible = _uninstallRestoreStockBoot;
        }
        finally
        {
            _uninstallStockCheckboxSuppress = false;
        }
    }

    private void UpdateUninstallRestoreStockCheckboxEnabled()
    {
        var enabled = CanUninstallToggleOptions() && !ProtectedUninstallState;
        UninstallRestoreStockCheck.IsEnabled = enabled;
        UninstallConfirmRestoreStockCheck.IsEnabled = enabled;
        UninstallReclaimBackupCheck.IsEnabled = enabled;
        UninstallUseBoardBackupButton.IsEnabled = enabled;
    }

    private string UninstallSelectedBootBehaviorText() =>
        _uninstallRestoreStockBoot
            ? T("Dynamic.UserdataUninstall.BootBehavior.RestoreStock")
            : T("Dynamic.UserdataUninstall.BootBehavior.KeepProject");

    private void RenderUninstallStockPlanSlots()
    {
        var plan = _uninstallStockPlan;
        if (plan is null)
        {
            return;
        }

        var header = NewBootMaintenanceCaption();
        header.Margin = new Avalonia.Thickness(0, 8, 0, 0);
        SetText(header, M("Dynamic.UserdataUninstall.RestoreStock.PlanHeader"));
        UninstallSlotsPanel.Children.Add(header);

        foreach (var line in UninstallStockPlanSlotLines(plan))
        {
            var slotText = NewBootMaintenanceCaption();
            SetText(slotText, line);
            UninstallSlotsPanel.Children.Add(slotText);
        }
    }

    private string UninstallStockPlanSlotSummary(BootMaintenancePrepared plan)
    {
        var lines = UninstallStockPlanSlotLines(plan);
        return lines.Count == 0 ? string.Empty : string.Join("\n", lines.Select(_l.Format));
    }

    /// <summary>逐槽文案：Empty 优先；否则该槽在方案中含 WillWrite 区域才标 Restore；否则说明已为原厂无需写入。</summary>
    private static List<UiMessage> UninstallStockPlanSlotLines(BootMaintenancePrepared plan)
    {
        var lines = new List<UiMessage>();
        foreach (var slot in plan.Slots)
        {
            if (slot.SourceKind == BootMaintenanceSourceKind.Empty)
            {
                lines.Add(M("Dynamic.UserdataUninstall.RestoreStock.SlotEmpty", slot.Slot));
                continue;
            }

            var willWrite = plan.Regions.Any(region =>
                string.Equals(region.Slot, slot.Slot, StringComparison.Ordinal) && region.WillWrite);
            lines.Add(willWrite
                ? M("Dynamic.UserdataUninstall.RestoreStock.SlotRestore", slot.Slot, slot.SourceSlot ?? string.Empty)
                : M("Dynamic.UserdataUninstall.RestoreStock.SlotAlreadyStock", slot.Slot));
        }

        return lines;
    }

    // ================================================================ 准备（第 2 步 -> 第 3 步）

    /// <summary>
    /// 来源页「下一步」的真实只读准备（WPF PrepareModernUserdataUninstallConfirmationAsync）：推导工作父目录，需要时先
    /// 走同一条 安卓 -> 9008 -> 当前状态快照 流水线，再取恢复资料（电脑备份优先，其次板内）-> 打开原始 GPT ->
    /// 读真实当前槽位 -> 准备引导方案 -> 卸载工厂。只有工厂真实返回且捕获未变时才提交。
    /// </summary>
    private async Task PrepareUninstallConfirmationAsync()
    {
        if (_uninstallStep != 2
            || _busy
            || _uninstallOperationActive
            || _uninstallDeviceOperationActive
            || ProtectedUninstallState
            || !HasUninstallBackupPrerequisite)
        {
            return;
        }

        var runner = _runner;
        var capturedStep = _uninstallStep;
        var capturedRestoreStock = _uninstallRestoreStockBoot;
        var capturedReclaimBackup = _uninstallReclaimBackup;
        var selectedOriginal = _uninstallOriginalDirectory;
        var workParent = _uninstallBackupParent;
        if (string.IsNullOrWhiteSpace(workParent) || !Directory.Exists(workParent))
        {
            if (!string.IsNullOrWhiteSpace(selectedOriginal) && Directory.Exists(selectedOriginal))
            {
                workParent = Directory.GetParent(Path.GetFullPath(selectedOriginal))?.FullName;
            }

            if (string.IsNullOrWhiteSpace(workParent) || !Directory.Exists(workParent))
            {
                try
                {
                    workParent = UninstallRecoveryOutputDirectory();
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    // 同上：按准备失败显示，既有准备与会话保持不变。
                    _uninstallError = error.Message;
                    RenderUninstallPreparationError();
                    AppendUninstallLog(M("Dynamic.RawValue", $"{error.GetType().FullName}: {error.Message}"));
                    return;
                }
            }

            if (string.IsNullOrWhiteSpace(workParent))
            {
                return;
            }
        }

        // 先作废上一次未写入的只读准备；再写入推导出的真实工作父目录。
        InvalidateUninstallPreparation();
        _uninstallBackupParent = workParent;

        // 尚无真实当前状态快照时，先等待与「开始备份」完全同一条流水线（不嵌套任何忙碌范围）。
        if (_uninstallBackup is null)
        {
            SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingSnapshot"));
            await BackupUninstallAsync();

            if (_closeConfirmed
                || _uninstallStep != capturedStep
                || !string.Equals(_uninstallOriginalDirectory, selectedOriginal, StringComparison.Ordinal)
                || _uninstallRestoreStockBoot != capturedRestoreStock
                || _uninstallReclaimBackup != capturedReclaimBackup)
            {
                RenderUninstallPages();
                return;
            }
        }

        // 无条件复核全部前提：任何一项失败都停在来源页，不进入确认。
        if (_closeConfirmed
            || _uninstallStep != capturedStep
            || !string.Equals(_uninstallOriginalDirectory, selectedOriginal, StringComparison.Ordinal)
            || _uninstallRestoreStockBoot != capturedRestoreStock
            || _uninstallReclaimBackup != capturedReclaimBackup
            || !HasUninstallDeviceProof
            || _uninstallEdlClient is null
            || _uninstallEdlTools is null
            || _uninstallEdlEntry is null
            || _uninstallBackup is null
            || _uninstallBackupParent is null
            || !Directory.Exists(_uninstallBackupParent))
        {
            RenderUninstallPages();
            return;
        }

        var client = _uninstallEdlClient;
        var tools = _uninstallEdlTools;
        var entry = _uninstallEdlEntry;
        var fresh = _uninstallBackup;
        var parent = _uninstallBackupParent;
        // Created inside the caught preparation block below: an unwritable cache root is a preparation failure (backup
        // and session kept), never an exception escaping the async void handler.
        var workRoot = string.Empty;
        // The lock state the check proved (the page shows the same value). A check that reads it from the boot
        // properties instead of fastboot (the TB710FU route, once its write route is open) leaves the Android
        // identity at the ADB "Unknown"; the proven value keeps both routes consistent.
        var lockState = HasCheckedUninstallDevice
            ? _uninstallDeviceCheck!.FastbootLockState
            : BootloaderState.Unknown;

        _uninstallOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                UninstallOriginalGptBackup? original = null;
                CurrentBootMenuPlan? menu = null;
                EdlUninstallBackend? backend = null;
                BootMaintenancePrepared? stockPrepared = null;
                var committed = false;
                var acceptProgress = true;
                try
                {
                    workRoot = UninstallWorkRoot;
                    SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.OpeningOriginal"));

                    var recoverySource = await GetUninstallRecoverySourceAsync(fresh, parent, token);
                    var originalDirectory = recoverySource.DirectoryPath;

                    // 1) 只读打开原始预安装 GPT 备份。
                    original = await Task.Run(
                        () => InternalInstallBackup.OpenOriginalGptForUninstallAsync(client, originalDirectory, null, token),
                        token);

                    // 2) 从全新快照的 misc 分区读真实当前槽位。
                    SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.ReadingSlot"));
                    if (!fresh.Files.TryGetValue("misc", out var misc) || misc is not EdlCapturedRegion)
                    {
                        throw new InvalidOperationException(T("Dynamic.UserdataUninstall.Status.PrepareFailed"));
                    }

                    var facts = await Task.Run(() => CurrentBootSlot.ReadAsync(fresh, token), token);

                    // 3) 勾选恢复原厂安卓引导时：先只读准备原厂引导恢复方案，立即释放校验后端，仅保留不可变的 Prepared。
                    if (capturedRestoreStock)
                    {
                        SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingPlan"));
                        var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(fresh.DirectoryPath, token);
                        using var stockValidation = await Task.Run(
                            () => BootMaintenanceBackend.CreatePreparedFromEdlAsync(
                                MaintenanceMode.RestoreStock,
                                history,
                                client,
                                fresh,
                                new BootMaintenanceSources(OriginalBackupDirectory: originalDirectory),
                                runner,
                                workRoot,
                                null,
                                token),
                            token);
                        stockPrepared = stockValidation.Prepared;
                    }

                    SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.PreparingPlan"));
                    var assets = UninstallGptAssets.FromVerifiedBackup(original);
                    var backendProgress = new Progress<EdlUninstallProgress>(report =>
                    {
                        if (acceptProgress)
                        {
                            RenderUninstallPrepareProgress(report);
                        }
                    });

                    if (capturedRestoreStock)
                    {
                        var stock = stockPrepared!;
                        backend = await Task.Run(
                            () => EdlUninstallBackend.CreatePreparedForStockRestoreAsync(
                                client, tools, entry, assets, fresh, stock, workRoot,
                                runner, backendProgress, token, capturedReclaimBackup),
                            token);
                    }
                    else
                    {
                        await EnsureUninstallAssetsAsync(token);
                        var actualTools = _uninstallNativeTools
                            ?? throw new InvalidOperationException("Required boot tools were not prepared.");
                        var currentSlot = facts.CurrentSlot;
                        menu = await Task.Run(
                            () => CurrentBootMenuPlanner.PrepareAndroidDefaultAsync(
                                fresh, currentSlot, lockState, actualTools, runner, workRoot, token),
                            token);
                        var plan = menu;
                        backend = await Task.Run(
                            () => EdlUninstallBackend.CreatePreparedAsync(
                                client, tools, entry, assets, fresh, plan, currentSlot,
                                workRoot, runner, backendProgress, token, capturedReclaimBackup),
                            token);
                    }

                    // 全部真实返回后再核对捕获；一致才提交自有字段。
                    if (_closeConfirmed
                        || !ReferenceEquals(_uninstallEdlClient, client)
                        || !ReferenceEquals(_uninstallEdlTools, tools)
                        || !ReferenceEquals(_uninstallEdlEntry, entry)
                        || !ReferenceEquals(_uninstallBackup, fresh)
                        || !string.Equals(_uninstallBackupParent, parent, StringComparison.Ordinal)
                        || !string.Equals(_uninstallOriginalDirectory, selectedOriginal, StringComparison.Ordinal)
                        || _uninstallRestoreStockBoot != capturedRestoreStock
                        || _uninstallReclaimBackup != capturedReclaimBackup
                        || _uninstallStep != capturedStep
                        || _uninstallBackend is not null
                        || _uninstallMenu is not null
                        || _uninstallOriginal is not null)
                    {
                        return;
                    }

                    _uninstallBackend = backend;
                    _uninstallMenu = menu;
                    _uninstallOriginal = original;
                    _uninstallStockPlan = capturedRestoreStock ? stockPrepared : null;
                    _uninstallStockRestoreResult = null;
                    _uninstallError = null;
                    _uninstallStep = 3;
                    committed = true;

                    acceptProgress = false;
                    SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.Prepared"));
                    AppendUninstallLog(M("Dynamic.UserdataUninstall.Status.PreparedLog"));
                }
                catch (OperationCanceledException)
                {
                    SetText(UninstallPrepareStatusText, M("Dynamic.UserdataUninstall.Status.PrepareFailed"));
                    AppendUninstallLog(M("Dynamic.UserdataUninstall.Status.PrepareCancelled"));
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    acceptProgress = false;
                    _uninstallError = exception.Message;
                    RenderUninstallPreparationError();
                    AppendUninstallLog(M("Dynamic.RawValue", $"{exception.GetType().FullName}: {exception.Message}"));
                }
                finally
                {
                    acceptProgress = false;
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
            _uninstallOperationActive = false;
            SetText(UninstallProgressText, "Dynamic.RawValue", string.Empty);
            UninstallProgressBar.IsIndeterminate = false;
            UninstallProgressBar.Value = _uninstallBackend is not null && HasPreparedUninstallBootPlan ? 100 : 0;
            RenderUninstallPages();
            RefreshActions();
        }
    }

    /// <summary>
    /// 恢复资料来源（WPF GetBoardFirstRecoverySourceAsync 的卸载分支）：已选电脑原厂备份时只用它；否则沿用已校验来源，
    /// 再试平板内恢复资料（同一快照只读一次），都不可用时请用户选择电脑备份。每个来源都先核对与当前快照同源。
    /// </summary>
    private async Task<InternalBackupSet> GetUninstallRecoverySourceAsync(
        InternalBackupSet current, string durableParent, CancellationToken token)
    {
        var workRoot = UninstallWorkRoot;
        if (!string.IsNullOrWhiteSpace(_uninstallOriginalDirectory))
        {
            var selection = UninstallBackupDirectorySelection.Resolve(_uninstallOriginalDirectory);
            if (selection.Kind != UninstallBackupDirectorySelection.SelectionKind.Selected || selection.DirectoryPath is null)
            {
                throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedSpecificOriginal"));
            }

            if (_uninstallRecoverySource is { } explicitCached
                && string.Equals(explicitCached.DirectoryPath, selection.DirectoryPath, StringComparison.OrdinalIgnoreCase))
            {
                BoardRecoveryBackup.ValidateSourceForReuse(current, explicitCached);
                return explicitCached;
            }

            var explicitClient = _uninstallEdlClient!;
            var explicitDirectory = selection.DirectoryPath;
            var explicitSource = await Task.Run(
                () => InternalInstallBackup.OpenRecoveryAsync(explicitClient, explicitDirectory, token: token),
                token);
            try
            {
                BoardRecoveryBackup.ValidateSourceForReuse(current, explicitSource);
            }
            catch
            {
                explicitSource.Dispose();
                throw;
            }

            _uninstallRecoverySource?.Dispose();
            _uninstallRecoverySource = explicitSource;
            AppendUninstallLog(M("Dynamic.RecoverySource.PcReady", explicitSource.DirectoryPath));
            return explicitSource;
        }

        if (_uninstallRecoverySource is { } cached)
        {
            BoardRecoveryBackup.ValidateSourceForReuse(current, cached);
            return cached;
        }

        var client = _uninstallEdlClient ?? throw new InvalidOperationException("No active EDL connection.");
        if (_uninstallBoardRecoveryDirectory is { } discovered)
        {
            _uninstallBoardRecoveryAttemptManifest = current.ManifestSha256;
            try
            {
                var discoveredBackup = await Task.Run(
                    () => InternalInstallBackup.OpenRecoveryAsync(client, discovered, token: token),
                    token);
                try
                {
                    BoardRecoveryBackup.ValidateSourceForReuse(current, discoveredBackup);
                }
                catch
                {
                    discoveredBackup.Dispose();
                    throw;
                }

                _uninstallRecoverySource = discoveredBackup;
                AppendUninstallLog(M("Dynamic.RecoverySource.BoardReady", discoveredBackup.DirectoryPath));
                return discoveredBackup;
            }
            catch (Exception error) when (IsRecoverySourceFailure(error))
            {
                _uninstallBoardRecoveryDirectory = null;
                _uninstallBoardRecoveryAttemptManifest = null;
                AppendUninstallLog(M("Dynamic.RecoverySource.BoardInvalid", error.Message));
            }
        }

        if (_uninstallBoardRecoveryAttemptManifest != current.ManifestSha256)
        {
            _uninstallBoardRecoveryAttemptManifest = current.ManifestSha256;
            AppendUninstallLog(M("Dynamic.RecoverySource.ReadingBoard"));
            try
            {
                var board = await Task.Run(
                    () => BoardRecoveryBackup.ReadAsync(client, current, durableParent, workRoot, token),
                    token);
                if (board is not null)
                {
                    _uninstallRecoverySource = board;
                    AppendUninstallLog(M("Dynamic.RecoverySource.BoardReady", board.DirectoryPath));
                    return board;
                }

                AppendUninstallLog(M("Dynamic.RecoverySource.BoardMissing"));
            }
            catch (Exception error) when (IsRecoverySourceFailure(error))
            {
                AppendUninstallLog(M("Dynamic.RecoverySource.BoardInvalid", error.Message));
            }
        }

        var selected = _uninstallOriginalDirectory;
        if (string.IsNullOrWhiteSpace(selected))
        {
            selected = await PickBootMaintenanceFolderAsync("Dynamic.RecoverySource.PickOriginal");
        }

        token.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(selected))
        {
            throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedOriginal"));
        }

        var resolved = UninstallBackupDirectorySelection.Resolve(selected);
        if (resolved.Kind != UninstallBackupDirectorySelection.SelectionKind.Selected || resolved.DirectoryPath is null)
        {
            throw new InvalidOperationException(T("Dynamic.RecoverySource.NeedSpecificOriginal"));
        }

        var resolvedDirectory = resolved.DirectoryPath;
        var recovery = await Task.Run(
            () => InternalInstallBackup.OpenRecoveryAsync(client, resolvedDirectory, token: token),
            token);
        try
        {
            BoardRecoveryBackup.ValidateSourceForReuse(current, recovery);
        }
        catch
        {
            recovery.Dispose();
            throw;
        }

        _uninstallRecoverySource = recovery;
        AppendUninstallLog(M("Dynamic.RecoverySource.PcReady", recovery.DirectoryPath));
        return recovery;
    }

    /// <summary>
    /// 只在需要时解出两个内置裸工具（WPF EnsureInternalInstallAssetsAsync）。已经成功加载的工具在同一页面的重试中复用；
    /// 失败时释放尚未保存的工具集与工具。Core 用自己的编译期引脚独立复核。
    /// </summary>
    private async Task EnsureUninstallAssetsAsync(CancellationToken token)
    {
        if (_uninstallAssets is not null && _uninstallNativeTools is not null)
        {
            return;
        }

        var materials = Path.Combine(UninstallWorkRoot, "assets", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(materials);
        EdlRawBootTools? pendingTools = null;
        InternalInstallDirectAssets? pendingAssets = null;
        try
        {
            var packer = await MacTools.StageAsync(MacTools.PackerResource, Path.Combine(materials, "MultiBootKernelPatcher"), token);
            var unpacker = await MacTools.StageAsync(MacTools.UnpackerResource, Path.Combine(materials, "UnpackTool"), token);
            pendingTools = await EdlRawBootTools.LoadAsync(packer, unpacker, token);
            pendingAssets = await InternalInstallDirectAssets.LoadAsync(pendingTools, token);

            _uninstallNativeTools = pendingTools;
            pendingTools = null;
            _uninstallAssets = pendingAssets;
            pendingAssets = null;
            _uninstallAssetsDirectory = materials;
            AppendUninstallLog(M("Dynamic.InternalInstall.Prepared.MaterialsReady", materials));
        }
        finally
        {
            pendingAssets?.Dispose();
            pendingTools?.Dispose();
            if (!ReferenceEquals(_uninstallAssetsDirectory, materials))
            {
                DeleteBootMaintenanceAssetsDirectory(materials);
            }
        }
    }

    /// <summary>
    /// 作废当前卸载准备：先释放后端，再释放方案，最后释放原始备份（只释放自己的租约）。
    /// 绝不释放当前状态快照、客户端，也绝不删除用户备份文件；受保护状态下一律拒绝。
    /// </summary>
    private void InvalidateUninstallPreparation()
    {
        if (ProtectedUninstallState)
        {
            return;
        }

        _uninstallExitStatus = null;

        if (_uninstallBackend is { } backend)
        {
            backend.Dispose();
            _uninstallBackend = null;
        }

        if (_uninstallMenu is { } menu)
        {
            menu.Dispose();
            _uninstallMenu = null;
        }

        if (_uninstallOriginal is { } original)
        {
            original.Dispose();
            _uninstallOriginal = null;
        }

        _uninstallStockPlan = null;
        _uninstallStockRestoreResult = null;
        UninstallRiskCheck.IsChecked = false;
        _uninstallError = null;

        // 未完成（受保护检查已证明无未解决现场）时：清掉真实执行标记，让预写入失败可以重新准备并执行一次新的后端。
        if (!_uninstallCompleted)
        {
            _uninstallLastResult = null;
            _uninstallExecuteAttempted = false;
            _uninstallExecutionUnknown = false;
            _uninstallDisplayStage = null;
        }
    }

    // ================================================================ 03 执行

    private async void OnExecuteUninstall(object? sender, RoutedEventArgs e) => await ExecuteUninstallAsync();

    /// <summary>卸载进度阶段的纯显示文案；旧 boot 还原枚举值不属于本流程，一律归入开始阶段。</summary>
    private static string UninstallStageKey(UninstallStage stage) => stage switch
    {
        UninstallStage.ValidateRestoreInputs => "Dynamic.UserdataUninstall.Runtime.Stage.ValidateRestoreInputs",
        UninstallStage.ReclaimAndroidSpace => "Dynamic.UserdataUninstall.Runtime.Stage.ReclaimAndroidSpace",
        UninstallStage.InitializeAndroid => "Dynamic.UserdataUninstall.Runtime.Stage.InitializeAndroid",
        UninstallStage.AwaitingFactoryReset => "Dynamic.UserdataUninstall.Runtime.Stage.AwaitingFactoryReset",
        _ => "Dynamic.UserdataUninstall.Runtime.Stage.Preflight",
    };

    /// <summary>退出状态的唯一写入点：存储文案并同时写入确认页状态与退出卡状态，重绘与换语言后由存储值稳定重放。</summary>
    private void SetUninstallExitStatus(UiMessage message)
    {
        _uninstallExitStatus = message;
        SetText(UninstallExitStatusText, message);
        SetText(UninstallConfirmStatusText, message);
    }

    /// <summary>
    /// 卸载执行入口（WPF ExecuteModernUserdataUninstallAsync）：先展示真实准备结果与电量记录的默认「否」确认，确认后把执行
    /// 交给 Core；成功到达等待复位时，勾选恢复原厂引导走 Core 的恢复助手（自行接受复位），否则只发送一次复位。绝不重试。
    /// </summary>
    private async Task ExecuteUninstallAsync()
    {
        if (!CanExecuteUninstall())
        {
            return;
        }

        _uninstallExitStatus = null;

        var backend = _uninstallBackend!;
        var client = _uninstallEdlClient!;
        var fresh = _uninstallBackup!;
        var entry = _uninstallEdlEntry!;
        var runner = _runner;
        var originalDirectory = _uninstallOriginal!.DirectoryPath;
        var capturedRestoreStock = _uninstallRestoreStockBoot;
        var capturedStockPlan = _uninstallStockPlan;
        var freshDirectory = fresh.DirectoryPath;
        var backendBackupDirectory = backend.BackupDirectory;
        var inputs = backend.Inputs;
        if (inputs is null)
        {
            return;
        }

        // 电量只读已有安卓采样（可能不存在）；9008 下明确说明读不到实时电量。
        RenderUninstallPower();
        var powerLine = _l.Format(PowerMessage(_uninstallPower));

        var retained = inputs.Record.BoardBackupPartUuid is not null
            ? T(_uninstallReclaimBackup ? "Dynamic.UserdataUninstall.RetainedBackup" : "Dynamic.UserdataUninstall.KeepBackup") + "\n"
            : string.Empty;
        var bootBehaviorLine = capturedRestoreStock
            ? T("Dynamic.UserdataUninstall.Runtime.ConfirmBody.BootBehavior.RestoreStock")
            : T("Dynamic.UserdataUninstall.Runtime.ConfirmBody.BootBehavior.KeepProject");

        var body = T(
            "Dynamic.UserdataUninstall.Runtime.ConfirmBody",
            UiText.ModelName(inputs.Identity.Model),
            inputs.Identity.Serial,
            FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)),
            FormatBytes(inputs.Plan.RestoredAndroidBytes),
            DeletedPartitionExtents(inputs),
            retained,
            bootBehaviorLine,
            freshDirectory,
            originalDirectory,
            backendBackupDirectory,
            powerLine);

        // 追加真实分区槽位清单；勾选恢复原厂引导时改由原厂方案摘要输出，避免与实际方案冲突。
        if (!capturedRestoreStock)
        {
            var slotLines = new List<string>();
            foreach (var slot in _uninstallMenu!.Slots)
            {
                slotLines.Add(slot.Candidate is null
                    ? T("Dynamic.UserdataUninstall.SlotKeep", slot.Slot)
                    : T("Dynamic.UserdataUninstall.SlotWriteDefault", slot.Slot, slot.SourceSlot));
            }

            if (slotLines.Count > 0)
            {
                body += "\n" + string.Join("\n", slotLines);
            }
        }

        if (capturedRestoreStock && capturedStockPlan is not null)
        {
            body += "\n" + UninstallStockPlanSlotSummary(capturedStockPlan);
        }

        var answer = await MessageDialog.AskAsync(
            this,
            T("Dynamic.UserdataUninstall.Runtime.ConfirmTitle"),
            body,
            T("Dynamic.Mac.Dialog.Yes"),
            T("Dynamic.Mac.Dialog.No"));
        if (!answer)
        {
            return;
        }

        // 确认后逐项复核捕获：步骤、风险、引用、选项及方案任何变化都放弃执行。
        if (!CanExecuteUninstall()
            || !ReferenceEquals(_uninstallBackend, backend)
            || !ReferenceEquals(_uninstallEdlClient, client)
            || !ReferenceEquals(_uninstallBackup, fresh)
            || !ReferenceEquals(_uninstallEdlEntry, entry)
            || _uninstallRestoreStockBoot != capturedRestoreStock
            || !ReferenceEquals(_uninstallStockPlan, capturedStockPlan))
        {
            return;
        }

        // Resolved before the one-shot attempt flag: an unwritable cache root fails here as a plain pre-write failure,
        // never as an unknown outcome or an exception escaping the async void handler.
        string workRoot;
        try
        {
            workRoot = UninstallWorkRoot;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AppendUninstallLog(M("Dynamic.RawValue", $"{exception.GetType().FullName}: {exception.Message}"));
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
            return;
        }

        _uninstallExecuteAttempted = true;
        _uninstallOperationActive = true;
        UninstallProgressBar.IsIndeterminate = true;

        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    var request = new UserdataUninstallRequest(backend.Snapshot, backend.PlanFingerprint, string.Empty, true);
                    request = request with { ConfirmationId = UninstallWorkflow.ConfirmationFor(request) };

                    var progress = new Progress<UninstallStage>(stage =>
                    {
                        // 迟到的回调在操作结束后被忽略；阶段只写显示，绝不改状态。
                        if (_closeConfirmed || !_uninstallOperationActive)
                        {
                            return;
                        }

                        _uninstallDisplayStage = stage;
                        SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.Active", M(UninstallStageKey(stage))));
                    });

                    SetUninstallExitStatus(
                        M("Dynamic.UserdataUninstall.Runtime.Active", M(UninstallStageKey(UninstallStage.Preflight))));

                    var result = await Task.Run(() => UninstallWorkflow.RunAsync(request, backend, progress, token), token);
                    _uninstallLastResult = result;
                    _uninstallDisplayStage = result.Stage;

                    if (result.Success && result.Stage == UninstallStage.AwaitingFactoryReset)
                    {
                        // 全部写入与读回校验已由 Core 完成：这里才决定复位还是原厂引导恢复。
                        AppendUninstallLog(M("Dynamic.UserdataUninstall.Runtime.LogSuccess"));
                        _uninstallResetAttempted = true;

                        if (capturedRestoreStock)
                        {
                            // 恢复路径由 Core 帮助器完成并自行接受复位，绝不调用 client.ResetAsync；
                            // 帮助器直接抛出的异常由外层 catch 标记为未解决失败。
                            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.RestoringStockBoot"));

                            var stockProgress = new Progress<InternalInstallProgress>(report =>
                            {
                                if (_closeConfirmed || !_uninstallOperationActive)
                                {
                                    return;
                                }

                                SetUninstallExitStatus(M(
                                    "Dynamic.UserdataUninstall.Runtime.RestoringStockBootProgress",
                                    FormatBytes(report.CompletedBytes),
                                    FormatBytes(report.TotalBytes)));
                            });

                            var stockPlan = capturedStockPlan!;
                            var stockResult = await Task.Run(
                                () => UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                                    result,
                                    stockPlan,
                                    client,
                                    originalDirectory,
                                    runner,
                                    workRoot,
                                    stockProgress,
                                    CancellationToken.None),
                                token);

                            _uninstallStockRestoreResult = stockResult;

                            if (stockResult.Outcome == BootMaintenanceOutcome.Completed
                                && stockResult.WriteState == InternalInstallWriteState.AllVerified)
                            {
                                _uninstallResetAcked = true;
                                _uninstallCompleted = true;
                            }
                            else
                            {
                                AppendUninstallLog(M("Dynamic.RawValue", stockResult.Error ?? string.Empty));
                                SetUninstallExitStatus(M(
                                    "Dynamic.UserdataUninstall.Runtime.StockRestoreFailed",
                                    stockResult.Outcome.ToString(),
                                    stockResult.WriteState.ToString(),
                                    string.IsNullOrWhiteSpace(stockResult.Error) ? string.Empty : stockResult.Error));
                            }

                            return;
                        }

                        // 未勾选：发送唯一一次复位。
                        SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.Resetting"));
                        var reset = await Task.Run(() => client.ResetAsync(CancellationToken.None), token);
                        if (reset.CommandAccepted)
                        {
                            _uninstallResetAcked = true;
                            _uninstallCompleted = true;
                        }
                        else
                        {
                            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.ResetUnknown"));
                        }

                        return;
                    }

                    // A failed result that erased nothing is a pre-write failure: replace the startup "active" status,
                    // which the later rendering would otherwise replay as if the run were still going.
                    if (!result.Success && !result.DataMayBeErased)
                    {
                        SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
                    }

                    if (!string.IsNullOrWhiteSpace(result.Error))
                    {
                        AppendUninstallLog(M("Dynamic.RawValue", result.Error));
                    }
                }
                catch (OperationCanceledException) when (!_uninstallResetAttempted)
                {
                    // Core 约定：取消只发生在 Reclaim 之前，属于未开始删除的预写失败。
                    SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    // 其他意外异常：结果未知，保留现场与证据，绝不复位、绝不重试。
                    _uninstallExecutionUnknown = true;
                    AppendUninstallLog(M("Dynamic.RawValue", $"{exception.GetType().FullName}: {exception.Message}"));
                }
            });
        }
        finally
        {
            _uninstallOperationActive = false;
            UninstallProgressBar.IsIndeterminate = false;
            RenderUninstallRuntimeStatus();
            RefreshActions();
        }

        if (_uninstallCompleted && !_uninstallCompletionToastShown)
        {
            _uninstallCompletionToastShown = true;
            await MessageDialog.ShowAsync(
                this,
                T("Dynamic.UserdataUninstall.Runtime.CompletionTitle"),
                T(capturedRestoreStock
                    ? "Dynamic.UserdataUninstall.Runtime.CompletionBodyStock"
                    : "Dynamic.UserdataUninstall.Runtime.CompletionBody"),
                T("Dynamic.Mac.Dialog.Ok"));
        }
    }

    /// <summary>
    /// 运行期状态的纯显示渲染：在「已准备」渲染之后调用，重绘与换语言都不会覆盖真实结局。
    /// 未执行时仍重放已存储的退出状态与未知复位状态，绝不写占位或伪造已准备。
    /// </summary>
    private void RenderUninstallRuntimeStatus()
    {
        if (_closeConfirmed)
        {
            return;
        }

        if (_uninstallOperationActive)
        {
            UninstallProgressBar.IsIndeterminate = true;
            return;
        }

        if (_uninstallCompleted)
        {
            SetUninstallExitStatus(M(_uninstallRestoreStockBoot
                ? "Dynamic.UserdataUninstall.Runtime.StockRestoreCompleted"
                : "Dynamic.UserdataUninstall.Runtime.Completed"));
            UninstallProgressBar.IsIndeterminate = false;
            UninstallProgressBar.Value = 100;
            return;
        }

        // 勾选恢复原厂引导时的失败优先于通用文案：帮助器抛异常（结果未知）……
        if (_uninstallRestoreStockBoot
            && _uninstallResetAttempted
            && _uninstallExecutionUnknown)
        {
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.StockRestoreFailedUnknown"));
            UninstallProgressBar.IsIndeterminate = false;
            return;
        }

        // ……或返回了明确的失败结果。
        if (_uninstallStockRestoreResult is { } stockResult
            && !(stockResult.Outcome == BootMaintenanceOutcome.Completed
                && stockResult.WriteState == InternalInstallWriteState.AllVerified))
        {
            SetUninstallExitStatus(M(
                "Dynamic.UserdataUninstall.Runtime.StockRestoreFailed",
                stockResult.Outcome.ToString(),
                stockResult.WriteState.ToString(),
                string.IsNullOrWhiteSpace(stockResult.Error) ? string.Empty : stockResult.Error));
            UninstallProgressBar.IsIndeterminate = false;
            return;
        }

        var result = _uninstallLastResult;
        if (result is { Success: true, Stage: UninstallStage.AwaitingFactoryReset })
        {
            // 写入校验完成但复位未被确认：如实说明，绝不写成完成。
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.VerifiedUnknownReset"));
            UninstallProgressBar.IsIndeterminate = false;
            UninstallProgressBar.Value = 100;
            return;
        }

        if (_uninstallExecutionUnknown || result?.DataMayBeErased == true)
        {
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.UnresolvedFailure"));
            UninstallProgressBar.IsIndeterminate = false;
            return;
        }

        if (_uninstallResetAttempted && !_uninstallResetAcked && result is null)
        {
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.ResetUnknown"));
            UninstallProgressBar.IsIndeterminate = false;
            return;
        }

        if (_uninstallExitStatus is { } storedStatus)
        {
            SetUninstallExitStatus(storedStatus);
            UninstallProgressBar.IsIndeterminate = false;
            return;
        }

        if (_uninstallExecuteAttempted)
        {
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.PrewriteFailed"));
        }

        UninstallProgressBar.IsIndeterminate = false;
    }

    // ================================================================ 离开 / 退出 / 关闭

    /// <summary>
    /// 离开卸载的唯一入口（WPF ConfirmLeaveModernUserdataUninstallAsync）：完成 / 未解决 / 已确认复位 / 无会话 / 预写入会话
    /// 分别处理。预写入会话先只读核对同一客户端，再发送唯一一次复位；探针失败不复位、不自动重试。
    /// </summary>
    private async Task<bool> ConfirmLeaveUninstallAsync(bool ask = true)
    {
        if (_busy || _uninstallOperationActive || _uninstallDeviceOperationActive)
        {
            return false;
        }

        _uninstallLeaveProbeFailed = false;

        if (_uninstallCompleted)
        {
            // 已完成：只释放自己的计划与会话资源，绝不发送任何设备调用。
            InvalidateUninstallPreparation();
            DisposeUninstallSession();
            return true;
        }

        if (HasUnresolvedUninstallState)
        {
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Runtime.UnresolvedFailure"));
            return false;
        }

        // 预写入离开时复位已被确认接受：只释放计划与会话资源，不发探针 / 复位。
        if (_uninstallResetAttempted && _uninstallResetAcked)
        {
            InvalidateUninstallPreparation();
            DisposeUninstallSession();
            return true;
        }

        if (!HasUninstallLiveEdlState)
        {
            // 没有真实 9008 会话：只释放自己的只读计划。
            InvalidateUninstallPreparation();
            return true;
        }

        var client = _uninstallEdlClient;
        var entry = _uninstallEdlEntry;
        if (client is null)
        {
            // 已进入 9008 却没有客户端：入口未知，不能假装已清理。
            SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.EntryUnknown"));
            return false;
        }

        if (ask && !await MessageDialog.AskAsync(
                this,
                T("Dynamic.UserdataUninstall.Exit.ConfirmTitle"),
                T("Dynamic.UserdataUninstall.Exit.ConfirmBody"),
                T("Dynamic.Mac.Dialog.Yes"),
                T("Dynamic.Mac.Dialog.No")))
        {
            return false;
        }

        if (_busy || !ReferenceEquals(client, _uninstallEdlClient))
        {
            return false;
        }

        // 退出同意后声明自己的活动与忙碌，先全局刷新动作再碰设备。
        _uninstallOperationActive = true;
        var acknowledged = false;
        try
        {
            await RunBusyAsync(async token =>
            {
                SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.Probing"));
                try
                {
                    await Task.Run(() => client.ProbeAsync(0, false, CancellationToken.None), token);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    // 探针失败：记录真实诊断；不复位、不自动重试。
                    AppendUninstallLog(M("Dynamic.RawValue", exception.Message));
                    SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ProbeFailed"));
                    _uninstallLeaveProbeFailed = true;
                    return;
                }

                // 探针通过后核对仍是同一会话、同一入口；变化时放弃离开，不复位。
                if (_closeConfirmed
                    || !ReferenceEquals(_uninstallEdlClient, client)
                    || !ReferenceEquals(_uninstallEdlEntry, entry))
                {
                    return;
                }

                if (_uninstallResetAttempted)
                {
                    // 复位已发起过：绝不重发第二次设备命令。
                    SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
                    return;
                }

                _uninstallResetAttempted = true;
                SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.Resetting"));
                try
                {
                    var reset = await Task.Run(() => client.ResetAsync(CancellationToken.None), token);
                    if (reset.CommandAccepted)
                    {
                        _uninstallResetAcked = true;
                        acknowledged = true;
                        SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetAccepted"));
                    }
                    else
                    {
                        // 设备未接受：结果未知，保留现场，绝不再次发送。
                        SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
                    }
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    AppendUninstallLog(M("Dynamic.RawValue", exception.Message));
                    SetUninstallExitStatus(M("Dynamic.UserdataUninstall.Exit.ResetUnknown"));
                }
            });
        }
        finally
        {
            _uninstallOperationActive = false;
            if (!_closeConfirmed)
            {
                RefreshActions();
            }
        }

        if (!acknowledged)
        {
            RenderUninstallRuntimeStatus();
            RefreshUninstallActions();
            return false;
        }

        // 已知复位被接受：走受保护检查的释放。
        InvalidateUninstallPreparation();
        DisposeUninstallSession();
        return true;
    }

    /// <summary>退出面板按钮：显式退出不再弹第二次确认（ask:false），成功后安全复位并刷新。</summary>
    private async void OnExitUninstall(object? sender, RoutedEventArgs e)
    {
        if (_busy || _uninstallOperationActive)
        {
            return;
        }

        if (await ConfirmLeaveUninstallAsync(ask: false))
        {
            SafeResetUninstallState();
        }

        RenderUninstallPages();
        RefreshActions();
    }

    /// <summary>
    /// 安全复位卸载向导到第 0 步（WPF SafeResetModernUserdataUninstallState）：只作废准备，保留已选原厂目录；
    /// 只有没有真实 9008 会话时才清空执行状态、选项与检查结论。
    /// </summary>
    private void SafeResetUninstallState()
    {
        if (ProtectedUninstallState || _uninstallDeviceOperationActive)
        {
            return;
        }

        if (!HasUninstallLiveEdlState)
        {
            _uninstallRestoreStockBoot = false;
            _uninstallReclaimBackup = true;
            _uninstallStockPlan = null;
            _uninstallStockRestoreResult = null;
            SyncUninstallRestoreStockCheckboxes();

            _uninstallLastResult = null;
            _uninstallExecuteAttempted = false;
            _uninstallExecutionUnknown = false;
            _uninstallResetAttempted = false;
            _uninstallResetAcked = false;
            _uninstallCompleted = false;
            _uninstallCompletionToastShown = false;
            _uninstallDisplayStage = null;
            _uninstallExitStatus = null;
        }

        InvalidateUninstallPreparation();
        _uninstallStep = 0;

        if (!HasUninstallLiveEdlState)
        {
            ResetUninstallCheckState();
        }

        RenderUninstallPages();
    }

    /// <summary>
    /// Releases this page's 9008 session objects once the session is over (completed, or the one leave reset was
    /// acknowledged): the WPF <c>DisposeInternalInstallResources</c>. Files are never deleted.
    /// </summary>
    private void DisposeUninstallSession()
    {
        ReleaseUninstallBackupObject();
        _uninstallAssets?.Dispose();
        _uninstallAssets = null;
        _uninstallNativeTools?.Dispose();
        _uninstallNativeTools = null;
        DeleteBootMaintenanceAssetsDirectory(_uninstallAssetsDirectory);
        _uninstallAssetsDirectory = null;

        var tools = _uninstallEdlTools;
        _uninstallEdlTools = null;
        _uninstallEdlClient = null;
        _uninstallEdlEntry = null;
        _uninstallEntryAttempted = false;
        try
        {
            tools?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>
    /// Releases managed objects when the window closes, only once this page's run is resolved (no activity, no
    /// unresolved outcome, no live 9008 session); backups, evidence and records stay on disk.
    /// </summary>
    private void DisposeUninstallOnClose()
    {
        if (_uninstallOperationActive
            || _uninstallDeviceOperationActive
            || HasUnresolvedUninstallState
            || HasUninstallLiveEdlState)
        {
            return;
        }

        _uninstallBackend?.Dispose();
        _uninstallBackend = null;
        _uninstallMenu?.Dispose();
        _uninstallMenu = null;
        _uninstallOriginal?.Dispose();
        _uninstallOriginal = null;
        DisposeUninstallSession();
    }

    /// <summary>
    /// The explicit pre-write close-only exits (an unproven client, or a leave whose probe failed): nothing was written
    /// and the window is closing, so this page's local resources (plan objects, staged tools, the extracted 9008
    /// toolchain with its Python runtime) are released even though a 9008 session may still be bound. No device
    /// command is sent; backups, evidence and records stay. Active operations and unresolved outcomes keep everything.
    /// </summary>
    private void ReleaseUninstallLocalResourcesForPrewriteClose()
    {
        if (_uninstallOperationActive || _uninstallDeviceOperationActive || HasUnresolvedUninstallState)
        {
            return;
        }

        _uninstallBackend?.Dispose();
        _uninstallBackend = null;
        _uninstallMenu?.Dispose();
        _uninstallMenu = null;
        _uninstallOriginal?.Dispose();
        _uninstallOriginal = null;
        DisposeUninstallSession();
    }

    /// <summary>
    /// The uninstall part of the window's close handler (WPF HandleModernUserdataUninstallClosingAsync): returns true
    /// when it handled (and cancelled) this close.
    /// </summary>
    private async Task<bool> OnUninstallClosingAsync(WindowClosingEventArgs e)
    {
        if (!HasUninstallDeviceSession)
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
            if (_busy || _uninstallOperationActive || _uninstallDeviceOperationActive)
            {
                SetText(UninstallConfirmStatusText, M("Dynamic.UserdataUninstall.Runtime.WaitForReturn"));
                await MessageDialog.ShowAsync(
                    this,
                    T("Dynamic.Mac.Close.BusyTitle"),
                    T("Dynamic.Mac.Close.BusyBody"),
                    T("Dynamic.Mac.Dialog.Ok"));
                return true;
            }

            // 未解决写入 / 未知复位 / 进入 9008 却没有客户端，或客户端从未取得初始 Sahara 证明（离开的热探针必然被
            // 拒绝，离开无法完成）：只提供「仅关闭窗口」的默认「否」警告，不发任何设备命令，保留全部现场。
            // A completed uninstall (or an acknowledged leave reset) keeps its client, whose proof the reset cleared: it
            // goes to the completed cleanup below, never to this warning.
            bool sessionOver = _uninstallCompleted || (_uninstallResetAttempted && _uninstallResetAcked);
            if (HasUnresolvedUninstallState
                || (HasUninstallLiveEdlState && _uninstallEdlClient is null)
                || (!sessionOver && _uninstallEdlClient is { HasInitialSaharaProof: false }))
            {
                // An unproven client is a pre-write session whose initial probe failed: say so instead of claiming
                // an unconfirmed write.
                bool unproven = !HasUnresolvedUninstallState && !sessionOver
                    && _uninstallEdlClient is { HasInitialSaharaProof: false };
                if (await MessageDialog.AskAsync(
                        this,
                        T(unproven ? "Dynamic.Mac.Close.ProbeFailedTitle" : "Dynamic.UserdataUninstall.Exit.CloseUnconfirmedTitle"),
                        T(unproven ? "Dynamic.Mac.Close.ProbeFailedBody" : "Dynamic.UserdataUninstall.Exit.CloseUnconfirmedBody"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No")))
                {
                    _closeConfirmed = true;
                    if (unproven)
                    {
                        // Pre-write: release what this window owns; no device command.
                        ReleaseUninstallLocalResourcesForPrewriteClose();
                        DisposeInternalInstall();
                    }

                    Close();
                }

                return true;
            }

            // 已完成或预写入：先走统一离开（完成时不发任何设备调用），再批准关闭。
            if (!await ConfirmLeaveUninstallAsync())
            {
                // The leave's device probe failed (for example the tablet was unplugged): offer the same explicit
                // close-only warning, which sends no device command and keeps every file.
                if (_uninstallLeaveProbeFailed
                    && await MessageDialog.AskAsync(
                        this,
                        T("Dynamic.Mac.Close.ProbeFailedTitle"),
                        T("Dynamic.Mac.Close.ProbeFailedBody"),
                        T("Dynamic.Mac.Dialog.Yes"),
                        T("Dynamic.Mac.Dialog.No")))
                {
                    // Pre-write: release what this window owns; no device command.
                    _closeConfirmed = true;
                    ReleaseUninstallLocalResourcesForPrewriteClose();
                    DisposeInternalInstall();
                    Close();
                }

                return true;
            }

            SafeResetUninstallState();
            _closeConfirmed = true;
            DisposeUninstallOnClose();
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
