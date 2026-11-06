using System.Globalization;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// The four internal install pages (check, backup, capacity, confirm) and the 9008 exit card. The Core calls,
/// their order and the gates between the steps are those of the WPF pages (MainWindow.InternalInstall.*.cs);
/// status lines use the same Dynamic.InternalInstall.* texts. Only the platform services differ: libusb 9008
/// discovery through IOKit, tools from MacTools, Avalonia pickers and dialogs.
/// </summary>
public partial class MainWindow
{
    private const string DirectPackageDeploymentKind = "edl-raw-v1";

    private int _internalInstallStep;
    private bool _suppressNav;

    // 01 检查
    private IReadOnlyList<ConnectedDevice> _deviceChoices = Array.Empty<ConnectedDevice>();
    private InternalDeviceCheckResult? _internalInstallDeviceCheck;
    private PowerSample? _internalInstallPower;

    // 02 备份
    private string? _internalInstallBackupParent;
    private EdlToolchain? _internalInstallTools;
    private EdlClient? _internalInstallClient;
    private InternalBackupSet? _internalInstallBackup;
    private bool _internalInstallExitVerified;
    private bool _internalInstallResetSent;

    // 03 空间
    private ImportedPackage? _internalInstallPackage;
    private AndroidAllocationRange? _internalInstallRange;
    private InternalAllocationPlan? _internalInstallAllocation;
    private long _internalInstallAndroidGiB;
    private bool _suppressCapacitySync;

    // 04 确认与写入
    private InternalArtifactSet? _internalInstallArtifacts;
    private EdlRawBootTools? _internalInstallNativeTools;
    private InternalInstallDirectAssets? _internalInstallAssets;
    private InternalInstallBackend? _internalInstallBackend;
    private bool _internalInstallExecutionActive;
    private bool _internalInstallExecuteAttempted;
    private string? _internalInstallExecutionError;
    private string? _lastProgressLog;

    private sealed record PowerSample(int? Percentage, bool? ExternalPower, DateTimeOffset CapturedAt);

    private DeviceTransport Transport => new(_adbPath ?? "adb", _fastbootPath ?? "fastboot", _runner);

    private static IEdlEndpointDiscovery Discovery { get; } = new MacEdlEndpointDiscovery();

    private bool HasCheckedDevice
    {
        get
        {
            var result = _internalInstallDeviceCheck;
            var identity = result?.Android?.Identity;
            return result is { Succeeded: true, AndroidReturn: AndroidReturnState.Verified }
                && identity is not null
                && !string.IsNullOrWhiteSpace(identity.Model)
                && !DeviceModelRoutes.IsInstallRoutePending(identity.Model)
                && !string.IsNullOrWhiteSpace(identity.Serial)
                && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
                && !string.IsNullOrWhiteSpace(result.Android?.SocSerial);
        }
    }

    private bool HasBackup => _internalInstallBackup is not null && _internalInstallClient is not null;

    private bool HasAllocation =>
        HasBackup && _internalInstallPackage?.Validation.Storage is not null && _internalInstallAllocation is not null;

    private bool HasPrepared => _internalInstallBackend is not null && _internalInstallArtifacts is not null;

    /// <summary>
    /// Whether the current backend has issued a write. <c>ExecutionStarted</c> is set as soon as an execution is
    /// admitted, even when the read-only revalidation then refuses it, so only a write state past
    /// <c>NoneIssued</c> proves a write; from then on the backend owns the 9008 session and its reset.
    /// </summary>
    private bool HasInternalInstallWriteIssued
    {
        get
        {
            var snapshot = _internalInstallBackend?.Snapshot;
            return snapshot is { ExecutionStarted: true }
                && snapshot.WriteState != InternalInstallWriteState.NoneIssued;
        }
    }

    /// <summary>A backend that issued no write can be released and prepared again; one that wrote is kept.</summary>
    private bool CanReleaseInternalInstallBackend => !_internalInstallExecutionActive && !HasInternalInstallWriteIssued;

    // ================================================================ 导航

    private bool CanEnterStep(int step) => step switch
    {
        0 => true,
        1 => HasCheckedDevice,
        2 => HasBackup,
        3 => HasPrepared,
        _ => false,
    };

    private void OnInternalInstallNavChecked(object? sender, RoutedEventArgs e)
    {
        if (_suppressNav || sender is not RadioButton { IsChecked: true, Tag: string tag })
        {
            return;
        }

        var step = int.Parse(tag, CultureInfo.InvariantCulture);
        if (_busy || !CanEnterStep(step))
        {
            RestoreNav();
            return;
        }

        NavigateInternalInstallStep(step);
    }

    private void NavigateInternalInstallStep(int step)
    {
        _internalInstallStep = step;
        InternalInstallCheckPage.IsVisible = step == 0;
        InternalInstallBackupPage.IsVisible = step == 1;
        InternalInstallCapacityPage.IsVisible = step == 2;
        InternalInstallConfirmPage.IsVisible = step == 3;
        RestoreNav();
        RefreshActions();
        WorkflowScrollViewer.ScrollToHome();
    }

    private void RestoreNav()
    {
        _suppressNav = true;
        try
        {
            InternalInstallNavCheck.IsChecked = _internalInstallStep == 0;
            InternalInstallNavBackup.IsChecked = _internalInstallStep == 1;
            InternalInstallNavCapacity.IsChecked = _internalInstallStep == 2;
            InternalInstallNavConfirm.IsChecked = _internalInstallStep == 3;
        }
        finally
        {
            _suppressNav = false;
        }
    }

    private void OnPreviousPage(object? sender, RoutedEventArgs e)
    {
        if (!_busy && _internalInstallStep > 0)
        {
            NavigateInternalInstallStep(_internalInstallStep - 1);
        }
    }

    private async void OnNextPage(object? sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // 第 3 步的「下一步」才发起真实准备（生成方案、打包 boot、核对全部输入，不写设备）。
        if (_internalInstallStep == 2)
        {
            await PrepareConfirmationAsync();
            return;
        }

        if (CanEnterStep(_internalInstallStep + 1))
        {
            NavigateInternalInstallStep(_internalInstallStep + 1);
        }
    }

    /// <summary>Enables what the current state allows; every gate is a real result, never a guess.</summary>
    private void RefreshActions()
    {
        var idle = !_busy;
        InternalInstallNavBackup.IsEnabled = idle && CanEnterStep(1);
        InternalInstallNavCapacity.IsEnabled = idle && CanEnterStep(2);
        InternalInstallNavConfirm.IsEnabled = idle && CanEnterStep(3);
        InternalInstallNavCheck.IsEnabled = idle;
        BackToFunctionsButton.IsEnabled = idle;
        SupportProjectButton.IsEnabled = idle;
        HomeEnvironmentButton.IsEnabled = idle;

        var noLiveSession = _internalInstallClient is null || _internalInstallExitVerified;
        InternalInstallCheckButton.IsEnabled = idle && noLiveSession;
        InternalInstallDevicesCombo.IsEnabled = idle && noLiveSession && _deviceChoices.Count > 1;

        InternalInstallBackupBrowseButton.IsEnabled = idle && HasCheckedDevice && _internalInstallBackup is null;
        InternalInstallBackupButton.IsEnabled = idle
            && HasCheckedDevice
            && _internalInstallBackup is null
            && !string.IsNullOrWhiteSpace(_internalInstallBackupParent);

        var packageEditable = idle && HasBackup && CanReleaseInternalInstallBackend;
        InternalInstallPackageBox.IsEnabled = packageEditable;
        InternalInstallPackageBrowseButton.IsEnabled = packageEditable;
        InternalInstallPackageValidateButton.IsEnabled = packageEditable
            && !string.IsNullOrWhiteSpace(InternalInstallPackageBox.Text);
        InternalInstallCapacitySlider.IsEnabled = packageEditable && _internalInstallRange is not null;

        PrevButton.IsEnabled = idle && _internalInstallStep > 0 && !_internalInstallExecutionActive;
        var onConfirm = _internalInstallStep == 3;
        NextButton.IsVisible = !onConfirm;
        ActionButton.IsVisible = onConfirm;
        NextButton.IsEnabled = idle && _internalInstallStep switch
        {
            0 => HasCheckedDevice,
            1 => HasBackup,
            2 => HasAllocation,
            _ => false,
        };
        ActionButton.IsEnabled = idle
            && onConfirm
            && HasPrepared
            && !_internalInstallExecuteAttempted
            && InternalInstallEraseRiskCheck.IsChecked == true;

        // Once a write has been issued the backend owns the 9008 session (and resets the tablet itself), so the
        // exit card is no longer offered; after a refused pre-write revalidation it is offered again.
        InternalInstallExitMaintenancePanel.IsVisible = _internalInstallClient is not null
            && !_internalInstallExitVerified
            && CanReleaseInternalInstallBackend;
        InternalInstallExitMaintenanceButton.IsEnabled = idle;
    }

    private async Task RunBusyAsync(Func<CancellationToken, Task> work)
    {
        _busy = true;
        RefreshActions();
        try
        {
            await work(CancellationToken.None);
        }
        finally
        {
            _busy = false;
            RefreshActions();
        }
    }

    // ================================================================ 01 检查平板

    private void RenderInternalInstallPlaceholders()
    {
        SetText(InternalInstallModelText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallSerialText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallFirmwareText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallBootloaderText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
        RenderPower();
        RefreshActions();
    }

    private ConnectedDevice? SelectedDevice() =>
        InternalInstallDevicesCombo.SelectedIndex is int index && index >= 0 && index < _deviceChoices.Count
            ? _deviceChoices[index]
            : null;

    private void OnInternalInstallDeviceSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // 换了设备：上一台设备的结论立即作废。
        _internalInstallDeviceCheck = null;
        _internalInstallPower = null;
        RenderInternalInstallPlaceholders();
    }

    private async void OnCheckInternalInstallDevice(object? sender, RoutedEventArgs e)
    {
        if (_busy || (_internalInstallClient is not null && !_internalInstallExitVerified))
        {
            return;
        }

        if (_adbPath is null)
        {
            SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.ToolsRequired");
            return;
        }

        ResetAfterCheck();
        var previousSerial = SelectedDevice()?.Serial;
        await RunBusyAsync(async token =>
        {
            var acceptProgress = true;
            try
            {
                SetText(InternalInstallCheckProgressText, "Dynamic.InternalInstall.Check.Listing");
                var transport = Transport;
                var devices = await transport.ListDevicesAsync(token);
                PopulateDevices(devices, previousSerial);
                if (devices.Count == 0)
                {
                    // A tablet sitting in 9008 has no adb; say so instead of "no device". The check reads the
                    // lock state and slot from Android, so it cannot run from 9008.
                    var edl = Discovery.ReadPresent();
                    SetText(
                        InternalInstallCheckStatusText,
                        edl.Count > 0 ? "Dynamic.Mac.Check.InEdl" : "Dynamic.InternalInstall.Check.NoDevices",
                        edl.Count > 0 ? EdlSerialText(edl[0]) : string.Empty);
                    return;
                }

                var target = devices.Count == 1 ? devices[0] : SelectedDevice();
                if (target is null)
                {
                    SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.MultipleNeedSelection", devices.Count);
                    return;
                }

                if (target.ConnectionState != ConnectionState.Authorized)
                {
                    SetText(
                        InternalInstallCheckStatusText,
                        M("Dynamic.InternalInstall.Check.NotAuthorized", target.Serial, M(ConnectionStateKey(target.ConnectionState))));
                    return;
                }

                SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.Started", target.Serial);
                var progress = new Progress<InternalDeviceCheckProgress>(report =>
                {
                    if (acceptProgress)
                    {
                        SetText(InternalInstallCheckProgressText, CheckStageKey(report.Stage));
                    }
                });
                var check = new InternalInstallDeviceCheck(transport.AdbPath, transport.FastbootPath, _runner);
                var result = await check.CheckAsync(target.Serial, progress, token);
                acceptProgress = false;
                _internalInstallDeviceCheck = result;
                RenderDeviceCheck(result);
                if (result.Succeeded && result.AndroidReturn == AndroidReturnState.Verified)
                {
                    _internalInstallPower = await CapturePowerAsync(transport.AdbPath, result.Android!.Identity.Serial, token);
                }

                RenderPower();
                AppendLog(M("Dynamic.InternalInstall.Check.Started", target.Serial));
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                acceptProgress = false;
                _internalInstallDeviceCheck = null;
                _internalInstallPower = null;
                var diagnostic = string.IsNullOrWhiteSpace(exception.Message) ? UnknownValue : exception.Message;
                SetText(InternalInstallCheckProgressText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
                SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.Failed", diagnostic);
            }
        });
    }

    private void PopulateDevices(IReadOnlyList<ConnectedDevice> devices, string? previousSerial)
    {
        _deviceChoices = devices;
        _suppressNav = true;
        try
        {
            InternalInstallDevicesCombo.ItemsSource = devices
                .Select(device => $"{device.Serial}  ({_l.T(ConnectionStateKey(device.ConnectionState))})")
                .ToList();
            var index = devices.ToList().FindIndex(device => device.Serial == previousSerial);
            InternalInstallDevicesCombo.SelectedIndex = devices.Count == 1 ? 0 : index;
        }
        finally
        {
            _suppressNav = false;
        }

        var many = devices.Count > 1;
        InternalInstallDevicesLabel.IsVisible = many;
        InternalInstallDevicesCombo.IsVisible = many;
    }

    private void RenderDeviceCheck(InternalDeviceCheckResult result)
    {
        var identity = result.Android?.Identity;
        var firmware = identity?.Firmware;
        SetText(InternalInstallModelText, "Dynamic.RawValue", Placeholder(identity?.Model));
        SetText(InternalInstallSerialText, "Dynamic.RawValue", Placeholder(identity?.Serial ?? result.FastbootSerial));
        SetText(InternalInstallFirmwareText, "Dynamic.RawValue", Placeholder(firmware?.DisplayId ?? firmware?.BuildFingerprint));
        SetText(InternalInstallBootloaderText, BootStateKey(result.FastbootLockState));

        if (result.Cancelled)
        {
            SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(InternalInstallCheckProgressText, "Dynamic.InternalInstall.Check.Cancelled");
            SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.Cancelled");
            return;
        }

        if (!result.Succeeded)
        {
            SetText(InternalInstallRouteText, "Dynamic.RawValue", UnknownValue);
            SetText(
                InternalInstallCheckProgressText,
                M("Dynamic.InternalInstall.Check.FailedStage", M(CheckStageKey(result.FailedStage))));
            var error = Placeholder(result.Error);
            SetText(
                InternalInstallCheckStatusText,
                result.AndroidReturn == AndroidReturnState.Unconfirmed
                    ? M("Dynamic.InternalInstall.Check.ReturnUnconfirmed", error)
                    : M("Dynamic.InternalInstall.Check.Failed", error));
            return;
        }

        SetText(InternalInstallCheckProgressText, "Dynamic.InternalInstall.Check.Progress.Completed");
        if (HasCheckedDevice)
        {
            SetText(InternalInstallRouteText, "Dynamic.InternalInstall.Check.RoutePassed");
            SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Check.Passed");
            return;
        }

        SetText(InternalInstallRouteText, "Dynamic.InternalInstall.Check.RouteUnavailable");
        SetText(
            InternalInstallCheckStatusText,
            DeviceModelRoutes.IsInstallRoutePending(identity?.Model)
                ? M("Dynamic.Model.RoutePending", Placeholder(identity?.Model))
                : M("Dynamic.InternalInstall.Check.ProfileUnavailable"));
    }

    /// <summary>A new check drops every later result; a live 9008 session never reaches here.</summary>
    private void ResetAfterCheck()
    {
        DisposeInternalInstall();
        _internalInstallDeviceCheck = null;
        _internalInstallPower = null;
        _internalInstallExitVerified = false;
        _internalInstallResetSent = false;
        _internalInstallExecuteAttempted = false;
        _internalInstallExecutionError = null;
        InternalInstallBackupProgressBar.Value = 0;
        SetText(InternalInstallBackupStatusText, "Static.InternalInstall.Backup.StatusInitial");
        SetText(InternalInstallBackupVerifiedText, "Static.InternalInstall.Backup.VerifiedInitial");
        SetText(InternalInstallBackupDirectoryText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallBackupManifestText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallBackupManifestHashText, "Dynamic.RawValue", UnknownValue);
        ResetCapacity();
        ResetConfirmation();
        RenderInternalInstallPlaceholders();
    }

    private async Task<PowerSample?> CapturePowerAsync(string adbPath, string serial, CancellationToken token)
    {
        try
        {
            var command = new ProcessCommand(adbPath, new[] { "-s", serial, "shell", "dumpsys", "battery" }, TimeSpan.FromSeconds(10));
            var result = await _runner.RunAsync(command, token);
            return result.ExitCode == 0 ? ParsePower(result.StandardOutput) : new PowerSample(null, null, default);
        }
        catch (Exception exception) when (exception is not OperationCanceledException and not OutOfMemoryException)
        {
            return new PowerSample(null, null, default);
        }
    }

    private static PowerSample ParsePower(string output)
    {
        int? level = null, scale = null;
        bool? ac = null, usb = null, wireless = null;
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            switch (key)
            {
                case "level" when int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l):
                    level = l;
                    break;
                case "scale" when int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var s):
                    scale = s;
                    break;
                case "AC powered":
                    ac = bool.TryParse(value, out var a) ? a : null;
                    break;
                case "USB powered":
                    usb = bool.TryParse(value, out var u) ? u : null;
                    break;
                case "Wireless powered":
                    wireless = bool.TryParse(value, out var w) ? w : null;
                    break;
            }
        }

        int? percentage = level is int lv && scale is int sc && sc > 0 && lv >= 0 && lv <= sc
            ? (int)Math.Round(lv * 100.0 / sc, MidpointRounding.AwayFromZero)
            : null;
        bool? external = ac == true || usb == true || wireless == true ? true
            : ac == false && usb == false && wireless == false ? false
            : null;
        return new PowerSample(percentage, external, DateTimeOffset.UtcNow);
    }

    private UiMessage PowerMessage()
    {
        var sample = _internalInstallPower;
        if (sample is null)
        {
            return M("Dynamic.InternalInstall.Power.Unknown");
        }

        object percent = sample.Percentage is int value
            ? string.Format(CultureInfo.CurrentCulture, "{0}%", value)
            : M("Dynamic.InternalInstall.Power.PercentUnknown");
        object external = sample.ExternalPower switch
        {
            true => M("Dynamic.UninstallFlow.Common.Yes"),
            false => M("Dynamic.UninstallFlow.Common.No"),
            _ => M("Dynamic.InternalInstall.Power.ExternalUnknown"),
        };
        object time = sample.CapturedAt == default
            ? M("Dynamic.InternalInstall.Power.TimeUnknown")
            : sample.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
        return M("Dynamic.InternalInstall.Power.Sample", percent, external, time);
    }

    private void RenderPower() => SetText(InternalInstallPowerText, PowerMessage());

    private static string CheckStageKey(InternalDeviceCheckStage? stage) => stage switch
    {
        InternalDeviceCheckStage.ReadingAndroid => "Dynamic.InternalInstall.Check.Progress.ReadingAndroid",
        InternalDeviceCheckStage.EnteringFastboot => "Dynamic.InternalInstall.Check.Progress.EnteringFastboot",
        InternalDeviceCheckStage.WaitingFastboot => "Dynamic.InternalInstall.Check.Progress.WaitingFastboot",
        InternalDeviceCheckStage.CheckingBootloader => "Dynamic.InternalInstall.Check.Progress.CheckingBootloader",
        InternalDeviceCheckStage.ReturningAndroid => "Dynamic.InternalInstall.Check.Progress.ReturningAndroid",
        InternalDeviceCheckStage.WaitingAndroid => "Dynamic.InternalInstall.Check.Progress.WaitingAndroid",
        InternalDeviceCheckStage.WaitingUsbAuthorization => "Dynamic.InternalInstall.Check.Progress.WaitingUsbAuthorization",
        InternalDeviceCheckStage.VerifyingAndroid => "Dynamic.InternalInstall.Check.Progress.VerifyingAndroid",
        _ => "Dynamic.InternalInstall.Check.Progress.Completed",
    };

    private static string BootStateKey(BootloaderState state) => state switch
    {
        BootloaderState.Unlocked => "Dynamic.BootState.Unlocked",
        BootloaderState.Locked => "Dynamic.BootState.Locked",
        _ => "Dynamic.BootState.Unknown",
    };

    private static string ConnectionStateKey(ConnectionState state) => state switch
    {
        ConnectionState.Authorized => "Dynamic.ConnectionState.Authorized",
        ConnectionState.Unauthorized => "Dynamic.ConnectionState.Unauthorized",
        _ => "Dynamic.ConnectionState.Offline",
    };

    // ================================================================ 02 备份

    private async void OnBrowseInternalInstallBackupFolder(object? sender, RoutedEventArgs e)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = T("Static.InternalInstall.Backup.FolderLabel"),
            AllowMultiple = false,
        });
        var path = folders.Count == 1 ? folders[0].TryGetLocalPath() : null;
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _internalInstallBackupParent = path;
        InternalInstallBackupFolderBox.Text = path;
        SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.Selected", path);
        RefreshActions();
    }

    /// <summary>
    /// Step 2 of the WPF page: this model's trusted profile and 9008 archive, a fresh Android read that must
    /// still match step 1, the single 9008 entry and the read-only install backup.
    /// </summary>
    private async void OnBackupInternalInstall(object? sender, RoutedEventArgs e)
    {
        if (_busy || !HasCheckedDevice || _internalInstallBackup is not null)
        {
            return;
        }

        var parent = _internalInstallBackupParent;
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.NeedFolder");
            return;
        }

        var expected = _internalInstallDeviceCheck!.Android!;
        SetText(InternalInstallBackupVerifiedText, "Dynamic.InternalInstall.Backup.RunningNote");
        await RunBusyAsync(async token =>
        {
            EdlToolchain? pendingTools = null;
            try
            {
                var profile = EdlDeviceProfiles.FindByModel(expected.Identity.Model);
                if (profile is null || !profile.IsComplete || !profile.SupportsIdentity(expected.Identity)
                    || profile.ArchiveLogicalName is null)
                {
                    SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Check.ProfileUnavailable");
                    return;
                }

                SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.PreparingTools");
                await using (var archive = MacTools.Open(profile.ArchiveLogicalName))
                {
                    if (archive is null)
                    {
                        SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.ToolsRequired");
                        return;
                    }

                    pendingTools = await EdlToolchain.LoadAsync(archive, Path.Combine(parent, ".armada-installer-tools"), token);
                }

                if (!ReferenceEquals(pendingTools.Profile, profile))
                {
                    SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.ToolchainMismatch", pendingTools.Model, pendingTools.AndroidBuild);
                    return;
                }

                var transport = Transport;
                EdlEntryResult entered;
                if (Discovery.ReadPresent().Count > 0)
                {
                    // The tablet is already in 9008 (for example after an earlier attempt failed once it had
                    // rebooted). Android cannot be asked again, so the 9008 endpoint itself is the proof: its
                    // USB serial must equal the SoC serial the device check read from Android. No command is
                    // sent here; a different or ambiguous endpoint fails at once.
                    SetText(InternalInstallBackupStatusText, "Dynamic.Mac.Backup.AlreadyInEdl", expected.SocSerial);
                    InternalInstallBackupProgressBar.IsIndeterminate = true;
                    entered = await new EdlEntry(transport.AdbPath, _runner, Discovery)
                        .WaitForPresentAsync(expected, pendingTools.Profile, token);
                    AppendLog(M("Dynamic.Mac.Backup.AlreadyInEdlLog", entered.BusSerialHex));
                }
                else
                {
                    SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.Reproving");
                    var freshIdentity = await transport.ReadAdbIdentityAsync(expected.Identity.Serial, token);
                    var fresh = await new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner)
                        .ReadAndroidAsync(freshIdentity, token);
                    if (!SameAndroid(expected, fresh) || !profile.SupportsIdentity(fresh.Identity))
                    {
                        SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.IdentityMismatch");
                        return;
                    }

                    SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.EnteringEdl");
                    InternalInstallBackupProgressBar.IsIndeterminate = true;
                    entered = await new EdlEntry(transport.AdbPath, _runner, Discovery).EnterAsync(fresh, pendingTools.Profile, token);
                }

                _internalInstallTools = pendingTools;
                pendingTools = null;
                _internalInstallClient = new EdlClient(_internalInstallTools, entered, _runner, Discovery);
                AppendLog(M("Dynamic.RawValue", $"9008: {entered.Endpoint.DeviceInstanceId}  SN {entered.BusSerialHex}"));

                SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.Reading");
                var progress = new Progress<InternalBackupProgress>(RenderBackupProgress);
                var set = await InternalInstallBackup.CreateAsync(_internalInstallClient, parent, progress, token);
                _internalInstallBackup = set;
                InternalInstallBackupProgressBar.IsIndeterminate = false;
                InternalInstallBackupProgressBar.Value = 100;
                SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.Succeeded", set.Files.Count);
                SetText(InternalInstallBackupVerifiedText, "Dynamic.InternalInstall.Backup.KeepEdl");
                SetText(InternalInstallBackupDirectoryText, "Dynamic.RawValue", set.DirectoryPath);
                SetText(InternalInstallBackupManifestText, "Dynamic.RawValue", set.ManifestPath);
                SetText(InternalInstallBackupManifestHashText, "Dynamic.RawValue", set.ManifestSha256);
                AppendLog(M("Dynamic.InternalInstall.Backup.SucceededLog", set.DirectoryPath, set.ManifestSha256));
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                InternalInstallBackupProgressBar.IsIndeterminate = false;
                SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Check.Failed", exception.Message);
                SetText(InternalInstallBackupVerifiedText, "Dynamic.InternalInstall.Backup.FailedNote");
                AppendLog(M("Dynamic.InternalInstall.Check.Failed", exception.Message));
            }
            finally
            {
                pendingTools?.Dispose();
            }
        });
    }

    private void RenderBackupProgress(InternalBackupProgress report)
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
            InternalInstallBackupProgressBar.IsIndeterminate = true;
            SetText(InternalInstallBackupStatusText, "Dynamic.InternalInstall.Backup.Progress.Discovering", detail);
            return;
        }

        var ratio = report.TotalBytes > 0
            ? (double)report.CompletedBytes / report.TotalBytes
            : (double)report.CompletedFiles / report.TotalFiles;
        InternalInstallBackupProgressBar.IsIndeterminate = false;
        InternalInstallBackupProgressBar.Value = Math.Clamp(ratio * 100d, 0d, 100d);
        SetText(
            InternalInstallBackupStatusText,
            "Dynamic.InternalInstall.Backup.Progress.Counters",
            detail,
            report.CompletedFiles,
            report.TotalFiles,
            FormatBytes(report.CompletedBytes),
            FormatBytes(report.TotalBytes));
    }

    private static string EdlSerialText(EdlEndpoint endpoint)
    {
        var description = endpoint.BusReportedDeviceDescription ?? string.Empty;
        var at = description.IndexOf("SN:", StringComparison.OrdinalIgnoreCase);
        return at < 0 ? "?" : description.Substring(at + 3).Split(' ', '_')[0];
    }

    private static bool SameAndroid(AndroidMaintenanceIdentity expected, AndroidMaintenanceIdentity fresh) =>
        string.Equals(expected.Identity.Serial, fresh.Identity.Serial, StringComparison.Ordinal)
        && string.Equals(expected.Identity.Model, fresh.Identity.Model, StringComparison.Ordinal)
        && string.Equals(expected.Identity.Firmware?.DisplayId, fresh.Identity.Firmware?.DisplayId, StringComparison.Ordinal)
        && string.Equals(expected.SocSerial, fresh.SocSerial, StringComparison.OrdinalIgnoreCase);

    // ================================================================ 03 分配空间

    private async void OnBrowseInternalInstallPackage(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = T("Static.InternalInstall.Capacity.PackageLabel"),
            AllowMultiple = false,
        });
        var path = files.Count == 1 ? files[0].TryGetLocalPath() : null;
        if (!string.IsNullOrWhiteSpace(path))
        {
            InternalInstallPackageBox.Text = path;
            await ImportPackageAsync();
        }
    }

    private async void OnValidateInternalInstallPackage(object? sender, RoutedEventArgs e) => await ImportPackageAsync();

    private void OnInternalInstallPackagePathChanged(object? sender, TextChangedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // 换了路径：已校验的包与方案作废，等待重新校验。
        if (_internalInstallPackage is not null)
        {
            ResetCapacity();
            ResetConfirmation();
        }

        RefreshActions();
    }

    private async Task ImportPackageAsync()
    {
        var path = InternalInstallPackageBox.Text?.Trim();
        var backup = _internalInstallBackup;
        if (_busy || backup is null || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        ResetCapacity();
        ResetConfirmation();
        InternalInstallPackageBox.Text = path;
        await RunBusyAsync(async token =>
        {
            try
            {
                SetText(InternalInstallPackageStatusText, "Dynamic.InternalInstall.Capacity.Validating");
                var packageWork = Path.Combine(_internalInstallBackupParent!, "package");
                Directory.CreateDirectory(packageWork);
                var imported = await PackageImporter.ImportAsync(path, backup.Model, InstallationTarget.Internal, packageWork, token);
                var validation = imported.Validation;
                if (!validation.IsValid || validation.Storage is null)
                {
                    var reasons = validation.Storage is null && validation.IsValid
                        ? T("Dynamic.InternalInstall.Capacity.StorageMissing")
                        : string.Join(T("Dynamic.Package.ReasonSeparator"), validation.Reasons);
                    SetText(InternalInstallPackageStatusText, "Dynamic.InternalInstall.Capacity.Invalid", reasons);
                    imported.Dispose();
                    return;
                }

                if (!string.Equals(validation.DeploymentKind, DirectPackageDeploymentKind, StringComparison.Ordinal))
                {
                    SetText(InternalInstallPackageStatusText, "Dynamic.InternalInstall.Capacity.RequiresDirectPackage");
                    imported.Dispose();
                    return;
                }

                _internalInstallPackage = imported;
                SetText(
                    InternalInstallPackageStatusText,
                    validation.TestOnly ? "Dynamic.InternalInstall.Capacity.TestOnly" : "Dynamic.InternalInstall.Capacity.Valid",
                    imported.DeviceModel,
                    validation.PackageId,
                    validation.Version,
                    validation.ManifestFingerprint);
                AppendLog(M("Dynamic.RawValue", $"{validation.PackageId} {validation.Version} {validation.ManifestFingerprint}"));
                EnsureCapacityRange();
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                SetText(InternalInstallPackageStatusText, "Dynamic.InternalInstall.Capacity.Invalid", exception.Message);
            }
        });
    }

    private void EnsureCapacityRange()
    {
        var backup = _internalInstallBackup;
        var storage = _internalInstallPackage?.Validation.Storage;
        if (backup is null || storage is null)
        {
            return;
        }

        var table = backup.Tables[0];
        AndroidAllocationRange range;
        try
        {
            range = InternalPartitionPlanner.GetAndroidRange(table, storage);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Capacity.RangeFailed", exception.Message);
            return;
        }

        _internalInstallRange = range;
        long userdataBytes = table.Partitions
            .Where(partition => string.Equals(partition.Name, "userdata", StringComparison.OrdinalIgnoreCase))
            .Select(partition => partition.SectorCount * (long)table.SectorSize)
            .FirstOrDefault();
        var proposal = Math.Clamp(userdataBytes / Gibibyte / 2, range.MinimumGiB, range.MaximumGiB);
        var chosen = _internalInstallAndroidGiB >= range.MinimumGiB && _internalInstallAndroidGiB <= range.MaximumGiB
            ? _internalInstallAndroidGiB
            : proposal;

        _suppressCapacitySync = true;
        try
        {
            InternalInstallCapacitySlider.Minimum = range.MinimumGiB;
            InternalInstallCapacitySlider.Maximum = range.MaximumGiB;
            InternalInstallCapacitySlider.Value = chosen;
        }
        finally
        {
            _suppressCapacitySync = false;
        }

        ApplyCapacityPlan(chosen);
    }

    private void OnInternalInstallCapacityChanged(object? sender, RangeBaseValueChangedEventArgs e)
    {
        if (_suppressCapacitySync || _busy || _internalInstallBackup is null || _internalInstallPackage is null)
        {
            return;
        }

        var value = (long)Math.Round(e.NewValue, MidpointRounding.AwayFromZero);
        if (value == _internalInstallAndroidGiB && _internalInstallAllocation is not null)
        {
            return;
        }

        ResetConfirmation();
        ApplyCapacityPlan(value);
        RefreshActions();
    }

    private void ApplyCapacityPlan(long androidGiB)
    {
        var backup = _internalInstallBackup;
        var storage = _internalInstallPackage?.Validation.Storage;
        if (backup is null || storage is null)
        {
            return;
        }

        try
        {
            var plan = InternalPartitionPlanner.Plan(backup.Tables[0], androidGiB, storage);
            var totalBytes = plan.OriginalUserdata.SectorCount * (long)plan.SectorSize;
            _internalInstallAllocation = plan;
            _internalInstallAndroidGiB = androidGiB;
            SetText(InternalInstallCapacityTotalText, "Dynamic.RawValue", totalBytes > 0 ? FormatBytes(totalBytes) : UnknownValue);
            SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", FormatBytes(plan.AndroidBytes));
            SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", FormatBytes(plan.LinuxBytes));
            SetText(
                InternalInstallCapacityStatusText,
                "Dynamic.InternalInstall.Capacity.PlanReady",
                (long)InternalInstallCapacitySlider.Minimum,
                (long)InternalInstallCapacitySlider.Maximum,
                FormatBytes(plan.LinuxBootBytes));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            _internalInstallAllocation = null;
            _internalInstallAndroidGiB = 0;
            SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Capacity.PlanFailed", exception.Message);
        }
    }

    private void ResetCapacity()
    {
        _internalInstallPackage?.Dispose();
        _internalInstallPackage = null;
        _internalInstallRange = null;
        _internalInstallAllocation = null;
        SetText(InternalInstallPackageStatusText, "Static.InternalInstall.Capacity.PackageStatusInitial");
        SetText(InternalInstallCapacityTotalText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityStatusText, "Static.InternalInstall.Capacity.StatusWaiting");
    }

    // ================================================================ 04 准备与确认

    /// <summary>
    /// The WPF capacity page's Next: plan artifacts, load the boot packers and build the prepared backend.
    /// Nothing is written to the tablet here.
    /// </summary>
    private async Task PrepareConfirmationAsync()
    {
        var backup = _internalInstallBackup;
        var package = _internalInstallPackage;
        var storage = package?.Validation.Storage;
        var client = _internalInstallClient;
        var check = _internalInstallDeviceCheck;
        var parent = _internalInstallBackupParent;
        if (backup is null || package is null || storage is null || client is null || check is null
            || _internalInstallAllocation is null || _internalInstallAndroidGiB <= 0)
        {
            SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Prepared.NeedInputs");
            return;
        }

        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Prepared.NeedParent");
            return;
        }

        // A backend whose execution was admitted is single use; after a pre-write failure prepare a fresh one.
        if (HasPrepared
            && !_internalInstallExecuteAttempted
            && _internalInstallArtifacts!.Allocation.AndroidBytes == _internalInstallAllocation.AndroidBytes)
        {
            NavigateInternalInstallStep(3);
            return;
        }

        var rendered = false;
        SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Prepared.Preparing");
        await RunBusyAsync(async token =>
        {
            try
            {
                ResetConfirmation();
                SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Prepared.PreparingArtifacts");
                _internalInstallArtifacts = await InternalInstallArtifacts.PrepareAsync(backup, _internalInstallAndroidGiB, storage, parent, token);

                SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Prepared.LoadingComponents");
                var materials = Path.Combine(parent, ".armada-installer-assets", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(materials);
                var packer = await MacTools.StageAsync(MacTools.PackerResource, Path.Combine(materials, "MultiBootKernelPatcher"), token);
                var unpacker = await MacTools.StageAsync(MacTools.UnpackerResource, Path.Combine(materials, "UnpackTool"), token);
                _internalInstallNativeTools = await EdlRawBootTools.LoadAsync(packer, unpacker, token);
                _internalInstallAssets = await InternalInstallDirectAssets.LoadAsync(_internalInstallNativeTools, token);
                AppendLog(M("Dynamic.InternalInstall.Prepared.MaterialsReady", materials));

                var transport = Transport;
                var services = new InternalInstallServices(
                    new EdlEntry(transport.AdbPath, _runner, Discovery), _runner, Discovery, transport.AdbPath);
                _internalInstallBackend = await InternalInstallBackend.CreatePreparedAsync(
                    check, client, backup, _internalInstallArtifacts, package, _internalInstallAssets, services, parent, token);
                RenderPreparedSummary(_internalInstallArtifacts, _internalInstallBackend.Prepared);
                rendered = true;
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                ResetConfirmation();
                var key = exception.Message switch
                {
                    var m when m.StartsWith("requires-complete-backup-with-efisp:", StringComparison.Ordinal) =>
                        M("Dynamic.InternalInstall.Prepared.CompleteBackupWithEfispRequired"),
                    var m when m.StartsWith("requires-compatible-bootloader:", StringComparison.Ordinal) =>
                        M("Dynamic.InternalInstall.Prepared.CompatibilityRequired"),
                    _ => M("Dynamic.InternalInstall.Prepared.Failed", exception.Message),
                };
                SetText(InternalInstallCapacityStatusText, key);
                AppendLog(key);
            }
        });

        if (rendered && HasPrepared)
        {
            NavigateInternalInstallStep(3);
        }
    }

    private void RenderPreparedSummary(InternalArtifactSet set, InternalInstallPrepared prepared)
    {
        var backup = _internalInstallBackup;
        var validation = _internalInstallPackage?.Validation;
        var model = backup?.Model ?? UnknownValue;
        object bootloader = M(BootStateKey(prepared.FastbootLockState));
        var androidBytes = checked(prepared.AndroidGiB * Gibibyte);
        var linuxBytes = checked(prepared.LinuxRootBytes + set.Allocation.LinuxBootBytes);

        SetText(InternalInstallConfirmDeviceModelText, "Dynamic.InternalInstall.Confirm.Value", model);
        SetText(InternalInstallConfirmDeviceSerialText, "Dynamic.InternalInstall.Confirm.Value", prepared.AndroidSerial);
        SetText(InternalInstallConfirmDeviceFirmwareText, "Dynamic.InternalInstall.Confirm.Value", prepared.AndroidBuild);
        SetText(InternalInstallConfirmDeviceBootloaderText, "Dynamic.InternalInstall.Confirm.Value", bootloader);
        SetText(InternalInstallConfirmPackageVersionText, "Dynamic.InternalInstall.Confirm.Value", validation?.Version ?? UnknownValue);
        SetText(InternalInstallConfirmPackageIdText, "Dynamic.InternalInstall.Confirm.Value", validation?.PackageId ?? UnknownValue);
        SetText(InternalInstallConfirmAndroidText, "Dynamic.InternalInstall.Confirm.Value", FormatBytes(androidBytes));
        SetText(InternalInstallConfirmLinuxText, "Dynamic.InternalInstall.Confirm.Value", FormatBytes(linuxBytes));
        SetText(InternalInstallConfirmRecoveryText, "Dynamic.InternalInstall.Confirm.Value", FormatBytes(prepared.BoardBackupBytes));
        SetText(InternalInstallConfirmBackupPathText, "Dynamic.InternalInstall.Confirm.Value", prepared.BackupDirectory);
        SetText(InternalInstallConfirmPowerText, "Dynamic.InternalInstall.Confirm.PowerRecord", PowerMessage());

        UiMessage? inactiveWarning = null;
        foreach (var facts in prepared.AvbSlots.Values.Where(facts => facts.NonbootableSystem).OrderBy(facts => facts.Slot, StringComparer.Ordinal))
        {
            var warning = M("Dynamic.InternalInstall.Prepared.InactiveSystemUnavailable", facts.Slot.ToUpperInvariant(), facts.SourceSlot.ToUpperInvariant());
            inactiveWarning = inactiveWarning is null ? warning : M("Dynamic.InternalInstall.Execution.WithFailureDetails", inactiveWarning, warning);
        }

        var bootBackedUp = backup is not null
            && backup.Files.ContainsKey("boot_a")
            && backup.Files.ContainsKey("boot_b")
            && prepared.SlotMaterials.ContainsKey("a")
            && prepared.SlotMaterials.ContainsKey("b");
        var bootMessage = M(bootBackedUp ? "Dynamic.InternalInstall.Confirm.BootBackedUp" : "Dynamic.InternalInstall.Confirm.BootPending");
        SetText(
            InternalInstallConfirmBootBackupText,
            inactiveWarning is null ? bootMessage : M("Dynamic.InternalInstall.Execution.WithFailureDetails", bootMessage, inactiveWarning));

        InternalInstallVerificationDetails.IsExpanded = false;
        InternalInstallEraseRiskCheck.IsChecked = false;
        InternalInstallEraseRiskCheck.IsEnabled = backup is not null && validation is { IsValid: true };

        var recoveryImageUsedMiB = (set.SummaryUsedBytes / 1024d / 1024d).ToString("0.0", CultureInfo.CurrentCulture) + " MiB";
        var summary = M(
            "Dynamic.InternalInstall.Prepared.Summary",
            model,
            prepared.AndroidSerial,
            prepared.AndroidBuild,
            bootloader,
            PowerMessage(),
            prepared.BackupDirectory,
            prepared.BackupManifestSha256,
            validation?.PackageId ?? UnknownValue,
            validation?.Version ?? UnknownValue,
            prepared.PackageFingerprint,
            FormatBytes(androidBytes),
            FormatBytes(linuxBytes),
            FormatBytes(set.Allocation.LinuxBootBytes),
            FormatBytes(prepared.BoardBackupBytes),
            recoveryImageUsedMiB,
            FormatBytes(set.BoardSummary.Length),
            prepared.ArtifactPlanSha256,
            set.DirectoryPath);
        summary = prepared.BootTrustMode switch
        {
            InternalInstallBootTrustMode.GblPreserveOem =>
                M("Dynamic.InternalInstall.Execution.WithFailureDetails", summary, M("Dynamic.InternalInstall.Prepared.GblInstallMode")),
            InternalInstallBootTrustMode.AospPreserved =>
                M("Dynamic.InternalInstall.Execution.WithFailureDetails", summary, M("Dynamic.InternalInstall.Prepared.AospPreservedInstallMode")),
            _ => summary,
        };
        SetText(
            InternalInstallSummaryText,
            inactiveWarning is null ? summary : M("Dynamic.InternalInstall.Execution.WithFailureDetails", summary, inactiveWarning));

        AppendLog(M("Dynamic.InternalInstall.Prepared.RecoveryImageLog", recoveryImageUsedMiB, FormatBytes(set.BoardSummary.Length)));
        AppendLog(M(
            "Dynamic.InternalInstall.Prepared.DirectEvidenceLog",
            prepared.ConfirmationId,
            prepared.ArtifactPlanSha256,
            prepared.BackupManifestSha256,
            prepared.PackageFingerprint,
            prepared.PackageBindingSha256,
            prepared.EvidenceDirectory,
            UnknownValue));
        SetText(InternalInstallCapacityStatusText, "Dynamic.InternalInstall.Prepared.StatusReady");
        SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Prepared.StatusReady");
        SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Ready");
        SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.NotStarted");
    }

    /// <summary>Drops the prepared plan while nothing was written; files on disk are kept.</summary>
    private void ResetConfirmation()
    {
        if (!CanReleaseInternalInstallBackend)
        {
            return;
        }

        ClearConfirmation();
    }

    private void ClearConfirmation()
    {
        _internalInstallExecuteAttempted = false;
        _internalInstallExecutionError = null;
        _internalInstallBackend?.Dispose();
        _internalInstallBackend = null;
        _internalInstallAssets?.Dispose();
        _internalInstallAssets = null;
        _internalInstallNativeTools?.Dispose();
        _internalInstallNativeTools = null;
        _internalInstallArtifacts?.Dispose();
        _internalInstallArtifacts = null;
        InternalInstallEraseRiskCheck.IsChecked = false;
        InternalInstallEraseRiskCheck.IsEnabled = false;
        foreach (var text in new[]
                 {
                     InternalInstallConfirmDeviceModelText, InternalInstallConfirmDeviceSerialText,
                     InternalInstallConfirmDeviceFirmwareText, InternalInstallConfirmDeviceBootloaderText,
                     InternalInstallConfirmPackageVersionText, InternalInstallConfirmPackageIdText,
                     InternalInstallConfirmAndroidText, InternalInstallConfirmLinuxText,
                     InternalInstallConfirmRecoveryText, InternalInstallConfirmBackupPathText,
                 })
        {
            SetText(text, "Dynamic.RawValue", UnknownValue);
        }

        SetText(InternalInstallConfirmBootBackupText, "Dynamic.InternalInstall.Confirm.BootPending");
        SetText(InternalInstallConfirmPowerText, "Dynamic.InternalInstall.Power.Unknown");
        SetText(InternalInstallSummaryText, "Static.InternalInstall.Confirm.SummaryInitial");
        SetText(InternalInstallConfirmStatusText, "Static.InternalInstall.Confirm.StatusWaiting");
        SetText(InternalInstallAcceptanceStatusText, "Static.InternalInstall.Confirm.AcceptanceInitial");
    }

    private void OnInternalInstallEraseRiskChanged(object? sender, RoutedEventArgs e) => RefreshActions();

    // ================================================================ 写入

    private async void OnExecuteSelectedWorkflow(object? sender, RoutedEventArgs e)
    {
        var backend = _internalInstallBackend;
        if (_busy || backend is null || _internalInstallExecuteAttempted
            || InternalInstallEraseRiskCheck.IsChecked != true || backend.Snapshot.ExecutionStarted)
        {
            return;
        }

        var prepared = backend.Prepared;
        if (string.IsNullOrWhiteSpace(prepared.ConfirmationId))
        {
            return;
        }

        // 与 Windows 版相同的二次确认：列出型号、序列号、两边空间与备份位置，默认「否」。
        var linuxTotal = checked(prepared.LinuxRootBytes + (_internalInstallArtifacts?.Allocation.LinuxBootBytes ?? 0L));
        var answer = await MessageDialog.AskAsync(
            this,
            T("Dynamic.InternalInstall.Execution.Dialog.Title"),
            T("Dynamic.InternalInstall.Execution.Dialog.Body",
                _internalInstallBackup!.Model,
                prepared.AndroidSerial,
                FormatExecutionBytes(prepared.AndroidGiB * Gibibyte),
                FormatExecutionBytes(linuxTotal),
                FormatExecutionBytes(prepared.BoardBackupBytes),
                InternalInstallConfirmPowerText.Text ?? T("Dynamic.InternalInstall.Power.Unknown"),
                prepared.BackupDirectory),
            T("Dynamic.Mac.Dialog.Yes"),
            T("Dynamic.Mac.Dialog.No"));
        if (!answer || !ReferenceEquals(backend, _internalInstallBackend) || InternalInstallEraseRiskCheck.IsChecked != true)
        {
            return;
        }

        _internalInstallExecuteAttempted = true;
        _internalInstallExecutionActive = true;
        _internalInstallExecutionError = null;
        _lastProgressLog = null;
        InternalInstallEraseRiskCheck.IsEnabled = false;
        RenderExecutionState();
        await RunBusyAsync(async token =>
        {
            using var pump = new ProgressPump(RenderInstallProgress);
            try
            {
                await backend.ExecuteAsync(prepared.ConfirmationId, userdataEraseConfirmed: true, pump, token);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                if (backend.Snapshot.WriteState == InternalInstallWriteState.NoneIssued)
                {
                    _internalInstallExecutionError = exception.Message;
                }

                AppendLog(M("Dynamic.InternalInstall.Execution.Log.Exception", exception.Message));
            }
            finally
            {
                pump.Flush();
                var result = backend.LastResult;
                if (result is not null)
                {
                    if (backend.Snapshot.WriteState == InternalInstallWriteState.NoneIssued
                        && result.Outcome is InternalInstallOutcome.Failed or InternalInstallOutcome.Cancelled)
                    {
                        _internalInstallExecutionError ??= result.Diagnostic ?? result.ErrorCode;
                    }

                    AppendLog(M(
                        "Dynamic.InternalInstall.Execution.Log.Result",
                        M("Dynamic.InternalInstall.Execution.Outcome." + result.Outcome),
                        M("Dynamic.InternalInstall.Execution.WriteState." + result.WriteState),
                        result.LastVerifiedStage is null ? "—" : M("Dynamic.InternalInstall.Execution.Stage." + result.LastVerifiedStage.Value),
                        result.VerifiedSlots.Count,
                        result.EvidenceDirectory));
                    if (!string.IsNullOrWhiteSpace(result.ErrorCode) || !string.IsNullOrWhiteSpace(result.Diagnostic))
                    {
                        AppendLog(M(
                            "Dynamic.InternalInstall.Execution.Log.Diagnostic",
                            string.IsNullOrWhiteSpace(result.ErrorCode) ? "—" : result.ErrorCode,
                            string.IsNullOrWhiteSpace(result.Diagnostic) ? "—" : result.Diagnostic));
                    }
                }

                _internalInstallExecutionActive = false;
                RenderExecutionState();
            }
        });

        if (backend.Snapshot.Outcome == InternalInstallOutcome.InstallationCompleted)
        {
            // 写入成功后平板已由后端复位，9008 会话随之结束。
            _internalInstallExitVerified = true;
            RefreshActions();
            await MessageDialog.ShowAsync(
                this,
                T("Dynamic.InternalInstall.Execution.Completion.Title"),
                T("Dynamic.InternalInstall.Execution.Completion.Body"),
                T("Dynamic.Mac.Dialog.Ok"));
        }
    }

    private void RenderExecutionState()
    {
        InternalInstallConfirmProgressBar.IsVisible = _internalInstallExecutionActive;
        if (_internalInstallExecutionActive)
        {
            InternalInstallConfirmProgressBar.IsIndeterminate = true;
        }

        var backend = _internalInstallBackend;
        var snapshot = backend?.Snapshot;
        if (snapshot is null || !snapshot.ExecutionStarted || snapshot.WriteState == InternalInstallWriteState.NoneIssued)
        {
            SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Ready");
            if (_internalInstallExecutionActive)
            {
                SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Execution.Status.Starting");
            }
            else if (!string.IsNullOrWhiteSpace(_internalInstallExecutionError))
            {
                SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Execution.PrewriteFailed", _internalInstallExecutionError);
            }

            SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.NotStarted");
            return;
        }

        var stage = M("Dynamic.InternalInstall.Execution.Stage." + snapshot.Stage);
        var writeState = M("Dynamic.InternalInstall.Execution.WriteState." + snapshot.WriteState);
        if (!_internalInstallExecutionActive)
        {
            SetText(InternalInstallConfirmStatusText, "Dynamic.InternalInstall.Execution.Status.Snapshot", stage, writeState);
        }

        if (snapshot.Outcome is null)
        {
            SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Running");
            SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.Running");
            return;
        }

        var evidence = snapshot.EvidenceDirectory;
        var details = FailureDetails(snapshot, backend?.LastResult);
        switch (snapshot.Outcome.Value)
        {
            case InternalInstallOutcome.InstallationCompleted:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.InstallationCompleted");
                SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.InstallationCompleted");
                break;
            case InternalInstallOutcome.Completed:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Completed");
                SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.Completed");
                break;
            case InternalInstallOutcome.AwaitingAndroidInitialization:
            case InternalInstallOutcome.AwaitingUsbAuthorization:
            case InternalInstallOutcome.AwaitingLinuxFirstBoot:
                var verified = snapshot.WriteState == InternalInstallWriteState.AllVerified;
                SetText(InternalInstallConfirmLeadText, verified ? "Dynamic.InternalInstall.Execution.Lead.Pending" : "Dynamic.InternalInstall.Execution.Lead.PendingUnverified");
                SetText(InternalInstallAcceptanceStatusText, verified ? PendingAcceptanceKey(snapshot.Outcome.Value) : "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified");
                break;
            case InternalInstallOutcome.Failed:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Terminal");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M("Dynamic.InternalInstall.Execution.WithFailureDetails",
                        M("Dynamic.InternalInstall.Execution.Acceptance.Failed", backend?.LastResult?.ErrorCode ?? "—", evidence),
                        details));
                break;
            case InternalInstallOutcome.Cancelled:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Terminal");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M("Dynamic.InternalInstall.Execution.WithFailureDetails", M("Dynamic.InternalInstall.Execution.Acceptance.Cancelled", evidence), details));
                break;
            case InternalInstallOutcome.UnknownWriteOutcome:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.Unknown");
                SetText(
                    InternalInstallAcceptanceStatusText,
                    M("Dynamic.InternalInstall.Execution.WithFailureDetails", M("Dynamic.InternalInstall.Execution.Acceptance.Unknown", evidence), details));
                break;
            default:
                SetText(InternalInstallConfirmLeadText, "Dynamic.InternalInstall.Execution.Lead.PendingUnverified");
                SetText(InternalInstallAcceptanceStatusText, "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified");
                break;
        }
    }

    private UiMessage FailureDetails(InternalInstallSnapshot snapshot, InternalInstallResult? result)
    {
        object diagnostic = !string.IsNullOrWhiteSpace(result?.Diagnostic) ? result!.Diagnostic!
            : !string.IsNullOrWhiteSpace(_internalInstallExecutionError) ? _internalInstallExecutionError!
            : M("Dynamic.InternalInstall.Execution.NoDiagnostic");
        return M(
            "Dynamic.InternalInstall.Execution.FailureDetails",
            M("Dynamic.InternalInstall.Execution.Stage." + snapshot.Stage),
            result?.LastVerifiedStage is { } verifiedStage
                ? M("Dynamic.InternalInstall.Execution.Stage." + verifiedStage)
                : M("Dynamic.InternalInstall.Execution.NoVerifiedStage"),
            M("Dynamic.InternalInstall.Execution.WriteState." + snapshot.WriteState),
            diagnostic,
            string.IsNullOrWhiteSpace(result?.ErrorCode) ? "—" : result!.ErrorCode!,
            !string.IsNullOrWhiteSpace(snapshot.EvidenceDirectory) ? snapshot.EvidenceDirectory : result?.EvidenceDirectory ?? "—");
    }

    private static string PendingAcceptanceKey(InternalInstallOutcome outcome) => outcome switch
    {
        InternalInstallOutcome.AwaitingAndroidInitialization => "Dynamic.InternalInstall.Execution.Acceptance.WaitAndroid",
        InternalInstallOutcome.AwaitingUsbAuthorization => "Dynamic.InternalInstall.Execution.Acceptance.AuthorizeUsb",
        InternalInstallOutcome.AwaitingLinuxFirstBoot => "Dynamic.InternalInstall.Execution.Acceptance.WaitLinux",
        _ => "Dynamic.InternalInstall.Execution.Acceptance.PendingUnverified",
    };

    private void RenderInstallProgress(InternalInstallProgress progress)
    {
        if (!_internalInstallExecutionActive)
        {
            return;
        }

        var stage = M("Dynamic.InternalInstall.Execution.Stage." + progress.Stage);
        var hasSlot = !string.IsNullOrWhiteSpace(progress.Slot);
        string fingerprint;
        if (progress.IoPhase is { } ioPhase && progress.Kind == InternalInstallProgressKind.Progress)
        {
            var phase = M((progress.Stage == InternalInstallStage.WritingBoardBackup
                ? "Dynamic.InternalInstall.Execution.BoardIoPhase."
                : "Dynamic.InternalInstall.Execution.IoPhase.") + ioPhase);
            var done = progress.IoCompletedBytes.GetValueOrDefault();
            var total = progress.IoTotalBytes.GetValueOrDefault();
            var hasTotal = progress.IoCompletedBytes is not null && progress.IoTotalBytes is > 0;
            SetText(
                InternalInstallConfirmStatusText,
                hasTotal
                    ? hasSlot
                        ? M("Dynamic.InternalInstall.Execution.Status.IoSlot", stage, progress.Slot!, phase, FormatExecutionBytes(done), FormatExecutionBytes(total))
                        : M("Dynamic.InternalInstall.Execution.Status.Io", stage, phase, FormatExecutionBytes(done), FormatExecutionBytes(total))
                    : hasSlot
                        ? M("Dynamic.InternalInstall.Execution.Status.IoPhaseSlot", stage, progress.Slot!, phase)
                        : M("Dynamic.InternalInstall.Execution.Status.IoPhase", stage, phase));
            SetProgress(hasTotal ? done / (double)total : null);
            fingerprint = string.Join("|", progress.Stage, "Io", ioPhase, progress.Slot);
            if (fingerprint != _lastProgressLog)
            {
                _lastProgressLog = fingerprint;
                AppendLog(M(
                    "Dynamic.InternalInstall.Execution.Log.Io",
                    stage,
                    phase,
                    hasSlot ? progress.Slot! : "—",
                    progress.IoCompletedBytes is null ? "—" : FormatExecutionBytes(done),
                    hasTotal ? FormatExecutionBytes(total) : "—",
                    string.IsNullOrWhiteSpace(progress.Detail) ? "—" : progress.Detail));
            }

            return;
        }

        var kind = M("Dynamic.InternalInstall.Execution.Kind." + progress.Kind);
        var hasBytes = progress.TotalBytes > 0;
        SetText(
            InternalInstallConfirmStatusText,
            hasSlot && hasBytes
                ? M("Dynamic.InternalInstall.Execution.Status.ProgressSlotBytes", stage, progress.Slot!, kind, FormatExecutionBytes(progress.CompletedBytes), FormatExecutionBytes(progress.TotalBytes))
                : hasSlot
                    ? M("Dynamic.InternalInstall.Execution.Status.ProgressSlot", stage, progress.Slot!, kind)
                    : hasBytes
                        ? M("Dynamic.InternalInstall.Execution.Status.ProgressBytes", stage, kind, FormatExecutionBytes(progress.CompletedBytes), FormatExecutionBytes(progress.TotalBytes))
                        : M("Dynamic.InternalInstall.Execution.Status.Progress", stage, kind));
        SetProgress(hasBytes ? progress.CompletedBytes / (double)progress.TotalBytes : null);
        fingerprint = string.Join("|", progress.Stage, progress.Kind, progress.Slot, progress.CompletedBytes, progress.TotalBytes, progress.Detail);
        if (progress.Kind == InternalInstallProgressKind.Progress && fingerprint == _lastProgressLog)
        {
            return;
        }

        _lastProgressLog = fingerprint;
        AppendLog(M(
            "Dynamic.InternalInstall.Execution.Log.Progress",
            stage,
            kind,
            hasSlot ? progress.Slot! : "—",
            FormatExecutionBytes(progress.CompletedBytes),
            hasBytes ? FormatExecutionBytes(progress.TotalBytes) : "—",
            string.IsNullOrWhiteSpace(progress.Detail) ? "—" : progress.Detail));
    }

    private void SetProgress(double? ratio)
    {
        InternalInstallConfirmProgressBar.IsVisible = true;
        InternalInstallConfirmProgressBar.IsIndeterminate = ratio is null;
        InternalInstallConfirmProgressBar.Value = ratio is double value ? Math.Clamp(value * 100d, 0d, 100d) : 0;
    }

    /// <summary>
    /// Delivers install progress to the window like the WPF pump: discrete events in order, consecutive
    /// Progress reports of the same stage collapsed to the newest, drained every 200 ms on the UI thread.
    /// </summary>
    private sealed class ProgressPump : IProgress<InternalInstallProgress>, IDisposable
    {
        private readonly object _gate = new();
        private readonly Queue<InternalInstallProgress> _queue = new();
        private readonly Action<InternalInstallProgress> _render;
        private readonly DispatcherTimer _timer;

        internal ProgressPump(Action<InternalInstallProgress> render)
        {
            _render = render;
            _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(200), DispatcherPriority.Background, (_, _) => Drain());
            _timer.Start();
        }

        public void Report(InternalInstallProgress value)
        {
            lock (_gate)
            {
                if (value.Kind == InternalInstallProgressKind.Progress
                    && _queue.Count > 0
                    && _queue.Last() is { Kind: InternalInstallProgressKind.Progress } last
                    && last.Stage == value.Stage
                    && last.IoPhase == value.IoPhase
                    && last.Slot == value.Slot)
                {
                    var rest = _queue.ToArray()[..^1];
                    _queue.Clear();
                    foreach (var item in rest)
                    {
                        _queue.Enqueue(item);
                    }
                }

                _queue.Enqueue(value);
            }
        }

        internal void Flush()
        {
            _timer.Stop();
            Drain();
        }

        public void Dispose() => _timer.Stop();

        private void Drain()
        {
            InternalInstallProgress[] batch;
            lock (_gate)
            {
                batch = _queue.ToArray();
                _queue.Clear();
            }

            foreach (var item in batch)
            {
                _render(item);
            }
        }
    }

    // ================================================================ 退出 9008

    /// <summary>
    /// The exit card of the WPF window: one reset request, then a read-only wait for the same tablet to come
    /// back in Android. The computer backup is kept.
    /// </summary>
    private async void OnExitInternalInstallMaintenance(object? sender, RoutedEventArgs e)
    {
        var client = _internalInstallClient;
        var expected = _internalInstallDeviceCheck?.Android;
        if (_busy || client is null || !CanReleaseInternalInstallBackend)
        {
            return;
        }

        if (expected is null)
        {
            SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.NeedIdentity");
            return;
        }

        var confirmed = await MessageDialog.AskAsync(
            this,
            T("Dynamic.InternalInstall.Exit.ConfirmTitle"),
            T("Dynamic.InternalInstall.Exit.ConfirmBody"),
            T("Dynamic.Mac.Dialog.Yes"),
            T("Dynamic.Mac.Dialog.No"));
        if (!confirmed)
        {
            return;
        }

        await RunBusyAsync(async token =>
        {
            if (!_internalInstallResetSent)
            {
                _internalInstallResetSent = true;
                SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.Resetting");
                try
                {
                    await client.ResetAsync(token);
                    SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.ResetAccepted");
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.ResetUnknown", exception.Message);
                }
            }
            else
            {
                SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.CheckingAgain");
            }

            var transport = Transport;
            var deadline = DateTime.UtcNow.AddMinutes(4);
            string? lastError = null;
            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromSeconds(3), token);
                try
                {
                    var device = (await transport.ListDevicesAsync(token))
                        .FirstOrDefault(candidate => candidate.Serial == expected.Identity.Serial);
                    if (device is null)
                    {
                        SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.WaitingAndroid");
                        continue;
                    }

                    if (device.ConnectionState != ConnectionState.Authorized)
                    {
                        SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.WaitingAuthorization");
                        continue;
                    }

                    SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.Verifying");
                    var identity = await transport.ReadAdbIdentityAsync(device.Serial, token);
                    var fresh = await new MaintenanceEntry(transport.AdbPath, transport.FastbootPath, _runner).ReadAndroidAsync(identity, token);
                    if (!SameAndroid(expected, fresh))
                    {
                        SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.Mismatch");
                        return;
                    }

                    _internalInstallExitVerified = true;
                    SetText(
                        InternalInstallExitMaintenanceStatusText,
                        "Dynamic.InternalInstall.Exit.Verified",
                        fresh.Identity.Model,
                        fresh.Identity.Serial,
                        fresh.Identity.Firmware?.DisplayId ?? UnknownValue);
                    if (_internalInstallBackup is { } backup)
                    {
                        AppendLog(M("Dynamic.InternalInstall.Exit.BackupRetainedLog", backup.DirectoryPath, backup.ManifestPath, backup.ManifestSha256));
                    }

                    SetText(InternalInstallCheckStatusText, "Dynamic.InternalInstall.Exit.VerifiedState");
                    return;
                }
                catch (Exception exception) when (exception is not OperationCanceledException and not OutOfMemoryException)
                {
                    lastError = exception.Message;
                    SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.Retrying", lastError);
                }
            }

            SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.InternalInstall.Exit.ReturnUnconfirmed", lastError ?? UnknownValue);
        });
    }

    /// <summary>Releases read locks and staged tools; backups, plans and evidence on disk are never deleted.</summary>
    private void DisposeInternalInstall()
    {
        if (_internalInstallExecutionActive)
        {
            return;
        }

        ClearConfirmation();
        ResetCapacity();
        _internalInstallBackup?.Dispose();
        _internalInstallBackup = null;
        _internalInstallClient = null;
        _internalInstallTools?.Dispose();
        _internalInstallTools = null;
    }
}
