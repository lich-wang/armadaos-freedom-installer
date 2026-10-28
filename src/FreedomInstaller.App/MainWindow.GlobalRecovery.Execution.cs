using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 全局救援页的设备侧执行：一次显式连接、一次只读备份、一次只读准备与唯一一次确认后的还原。
/// <para>
/// 工具链 / 入口 / 客户端只在真实入口返回后接管；任何写入都先落「已尝试」标记，
/// 结果不确定时本会话不再自动重试，也不发送任何自动重置。
/// </para>
/// </summary>
public partial class MainWindow
{
    private const string GlobalToolchainFolder = ".armada-installer-tools";

    /// <summary>本次会话独立的探针证据目录；新连接换新目录，复探沿用原目录。</summary>
    private string? _globalSessionDirectory;

    /// <summary>在本次会话目录下创建一个全新的探针文件名；目录在探针前创建，绝不覆盖。</summary>
    private string NewGlobalProbePath()
    {
        if (string.IsNullOrEmpty(_globalSessionDirectory))
        {
            if (string.IsNullOrWhiteSpace(_globalOutputParent))
            {
                throw new InvalidOperationException(T("Dynamic.Global.Error.OutputRequired"));
            }

            _globalSessionDirectory = Path.Combine(
                _globalOutputParent!,
                "global-edl-session-" + Guid.NewGuid().ToString("N"));
        }

        Directory.CreateDirectory(_globalSessionDirectory);
        return Path.Combine(
            _globalSessionDirectory,
            "probe-lun0-" + Guid.NewGuid().ToString("N") + ".bin");
    }

    // ---------- 连接 ----------

    private async void OnGlobalConnect(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || _globalOperationActive
            || _globalRestoreUncertain || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        // 入口已尝试但未留下客户端：绝不自动重跑安卓命令，必须人工重新连接 / 关闭窗口。
        if (_globalEdlTools is not null && _globalEdlClient is null)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BlockedBySession");
            return;
        }

        if (string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            OnGlobalBrowseBackup(sender, e);
            if (string.IsNullOrWhiteSpace(_globalOutputParent))
            {
                SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputRequired");
                return;
            }
        }

        // 已有会话：只核对同一配置与同一总线序列，缺失证明时最多补一次显式探针。
        if (_globalEdlClient is not null)
        {
            // 复用路径必须针对真实连接过的配置；_globalProfile 只表示实际连接的配置。
            if (_globalProfile is null)
            {
                SetText(GlobalProgressStatusText, "Dynamic.Global.Status.NeedVerifiedConnection");
                return;
            }

            var profile = _globalProfile;
            _globalOperationActive = true;
            var reuseProgress = BeginGlobalProgress();
            try
            {
                await RunBusyAsync(async token =>
                {
                    try
                    {
                        bool verified = await EnsureGlobalConnectionAsync(profile, ExpectedGlobalBusSerial(), token);
                        RenderGlobalConnection();
                        SetText(
                            GlobalProgressStatusText,
                            verified
                                ? "Dynamic.Global.Status.Connected"
                                : "Dynamic.Global.Status.NeedVerifiedConnection");
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception exception)
                    {
                        RenderGlobalConnection();
                        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ConnectFailed", exception.Message);
                    }
                });
            }
            catch (OperationCanceledException)
            {
                SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Canceled");
            }
            finally
            {
                EndGlobalProgress();
                _globalOperationActive = false;
                RefreshGlobalRecoveryActions();
            }

            return;
        }

        // 明确告知：安卓路线会重启到 9008；已有 9008 不会重启。
        MessageBoxResult answer = MessageBox.Show(
            this,
            T("Dynamic.Global.Dialog.ConnectWarning"),
            T("Dynamic.Global.Dialog.Title"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Information,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        _globalOperationActive = true;
        var progress = BeginGlobalProgress();
        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    // 只有还原视图才核对备份来源；备份视图绝不复用陈旧的还原状态。
                    EdlDeviceProfile? expectedProfile = null;
                    string? expectedBus = null;
                    if (_globalRecoveryMode == GlobalRecoveryMode.Restore)
                    {
                        if (_globalRestoreSet is null && !string.IsNullOrWhiteSpace(_globalRestoreSource))
                        {
                            // 备份来源必须先完成本地完整校验，之后的任何重启都只针对已核实的身份。
                            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.VerifyingRestoreSource");
                            _globalRestoreSet = await GlobalEdlBackup.OpenAsync(
                                _globalRestoreSource!,
                                progress,
                                token);
                        }

                        GlobalEdlIdentity? verifiedIdentity = _globalRestoreSet?.Identity;
                        if (verifiedIdentity is not null)
                        {
                            expectedProfile = EdlDeviceProfiles.FindById(verifiedIdentity.ProfileId);
                            if (expectedProfile is null || !expectedProfile.IsComplete)
                            {
                                throw new InvalidOperationException(
                                    T("Dynamic.Global.Error.RestoreProfileUnsupported", verifiedIdentity.Model));
                            }

                            expectedBus = verifiedIdentity.BusSerialHex;
                        }
                    }

                    await ConnectGlobalCoreAsync(expectedProfile, expectedBus, token);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    RenderGlobalConnection();
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ConnectFailed", exception.Message);
                }
            });
        }
        catch (OperationCanceledException)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Canceled");
        }
        finally
        {
            EndGlobalProgress();
            _globalOperationActive = false;
            RefreshGlobalRecoveryActions();
        }
    }

    /// <summary>只有还原视图下已本地校验的备份来源才给出期望总线序列；备份视图恒为 null。</summary>
    private string? ExpectedGlobalBusSerial() =>
        _globalRecoveryMode == GlobalRecoveryMode.Restore
            ? _globalRestoreSet?.Identity.BusSerialHex
            : null;

    /// <summary>复用已核实会话；配置或总线序列不一致时直接拒绝，绝不静默换设备。</summary>
    private async Task<bool> EnsureGlobalConnectionAsync(
        EdlDeviceProfile profile,
        string? expectedBusSerialHex,
        CancellationToken token)
    {
        if (_globalEdlClient is null)
        {
            await ConnectGlobalCoreAsync(profile, expectedBusSerialHex, token);
            return _globalEdlClient?.HasInitialSaharaProof == true;
        }

        if (!string.Equals(_globalProfile?.ProfileId, profile.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.ConnectionProfileMismatch"));
        }

        if (expectedBusSerialHex is not null
            && !string.Equals(_globalEdlEntry?.BusSerialHex, expectedBusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                T("Dynamic.Global.Error.ConnectionBusMismatch", _globalEdlEntry?.BusSerialHex ?? UnknownValue));
        }

        // 客户端证明缺失时，只允许一次显式探针，不重新执行入口；复探沿用当前会话目录。
        if (!_globalEdlClient.HasInitialSaharaProof)
        {
            await _globalEdlClient.ProbeRawGeometryAsync(
                0,
                !_globalEdlClient.HasInitialSaharaProof,
                NewGlobalProbePath(),
                token);
        }

        return _globalEdlClient.HasInitialSaharaProof;
    }

    /// <summary>一次连接：优先接管唯一现有 9008 并自动识别；否则走唯一已授权的安卓设备并重启一次。</summary>
    private async Task ConnectGlobalCoreAsync(
        EdlDeviceProfile? expectedProfile,
        string? expectedBusSerialHex,
        CancellationToken token)
    {
        // 入口未知且没有客户端时，工具链残留不得被新连接静默复用。
        if (_globalEdlTools is not null && _globalEdlClient is null)
        {
            throw new InvalidOperationException(T("Dynamic.Global.Status.BlockedBySession"));
        }

        if (string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.OutputRequired"));
        }

        token.ThrowIfCancellationRequested();

        var discovery = new WindowsEdlEndpointDiscovery();
        bool anyPresentEdl = discovery.ReadPresent()
            .Any(endpoint => endpoint is not null && IsGlobalEdlInstance(endpoint.DeviceInstanceId));

        if (anyPresentEdl)
        {
            // 真实 9008 在场：先做只读识别，再加载真正的工具链；识别只用共享客户端，绝不触碰 Firehose 或探针。
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BindingExistingEdl");

            EdlDeviceProfile detectedProfile;
            using (EdlToolchain identificationTools = await LoadGlobalToolsAsync(
                EdlDeviceProfiles.FindByModel("TB322FC")!, token))
            {
                detectedProfile = await GlobalEdlDetection.DetectAsync(
                    identificationTools.ClientPath,
                    _runner,
                    discovery,
                    expectedBusSerialHex,
                    token);
            }

            if (expectedProfile is not null
                && !string.Equals(expectedProfile.ProfileId, detectedProfile.ProfileId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(T("Dynamic.Global.Error.RestoreProfileMismatch"));
            }

            EdlEntryResult entry = GlobalEdlBinding.Attach(detectedProfile, discovery, expectedBusSerialHex);

            EdlToolchain tools = await LoadGlobalToolsAsync(detectedProfile, token);
            _globalProfile = detectedProfile;
            _globalEdlTools = tools;
            _globalEntryAttempted = true;
            _globalEdlEntry = entry;
            _globalPower = null;

            var client = new EdlClient(tools, entry, _runner, new WindowsEdlEndpointDiscovery());
            _globalEdlClient = client;
            await client.ProbeRawGeometryAsync(
                0,
                !client.HasInitialSaharaProof,
                NewGlobalProbePath(),
                token);

            RenderGlobalConnection();
            RenderGlobalPower();
            AppendLocalizedLog(M("Dynamic.Global.Log.ConnectedEdl", detectedProfile.Model, entry.BusSerialHex));
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Connected");
            return;
        }

        DeviceTransport transport = _transport
            ?? throw new InvalidOperationException(T("Dynamic.Global.Error.TransportUnavailable"));

        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ReadingAndroid");
        var devices = await transport.ListDevicesAsync(token);
        if (devices.Count == 0)
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.NoAdbDevice"));
        }

        if (devices.Count > 1)
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.MultipleAdbDevices"));
        }

        ConnectedDevice device = devices[0];
        if (device.ConnectionState != ConnectionState.Authorized)
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.UnauthorizedAdb"));
        }

        DeviceIdentity identity = await transport.ReadAdbIdentityAsync(device.Serial, token);

        // 自动识别：按安卓身份解析唯一配置并要求完整；与期望配置的核对必须在重启 / 加载之前完成。
        EdlDeviceProfile? resolved = EdlDeviceProfiles.FindByModel(identity.Model);
        if (resolved is null || !resolved.IsComplete)
        {
            throw new InvalidOperationException(
                T("Dynamic.Global.Error.RestoreProfileUnsupported", identity.Model));
        }

        EdlDeviceProfile profile = resolved;
        if (expectedProfile is not null
            && !string.Equals(expectedProfile.ProfileId, profile.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.RestoreProfileMismatch"));
        }

        AndroidMaintenanceIdentity android = await new MaintenanceEntry(
                transport.AdbPath,
                transport.FastbootPath,
                _runner)
            .ReadAndroidAsync(identity, token);

        // 还原来源选中时，身份必须在重启前核对；绝不重启错误的设备。
        if (expectedBusSerialHex is not null
            && !AndroidSocMatchesBus(android.SocSerial, expectedBusSerialHex))
        {
            throw new InvalidOperationException(
                T("Dynamic.Global.Error.SocSerialMismatch", android.SocSerial, expectedBusSerialHex));
        }

        _globalPower = await CaptureInternalInstallPowerAsync(transport.AdbPath, identity.Serial, token);
        RenderGlobalPower();

        EdlToolchain pendingTools = await LoadGlobalToolsAsync(profile, token);
        _globalProfile = profile;
        _globalEdlTools = pendingTools;
        _globalEntryAttempted = true;

        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.EnteringEdl");
        EdlEntryResult entered = await new EdlEntry(
                transport.AdbPath,
                _runner,
                discovery)
            .EnterAsync(android, profile, token);

        if (expectedBusSerialHex is not null
            && !string.Equals(entered.BusSerialHex, expectedBusSerialHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                T("Dynamic.Global.Error.EntryBusMismatch", entered.BusSerialHex, expectedBusSerialHex));
        }

        _globalEdlEntry = entered;
        var enteredClient = new EdlClient(
            _globalEdlTools,
            entered,
            _runner,
            new WindowsEdlEndpointDiscovery());
        _globalEdlClient = enteredClient;
        await enteredClient.ProbeRawGeometryAsync(
            0,
            !enteredClient.HasInitialSaharaProof,
            NewGlobalProbePath(),
            token);

        RenderGlobalConnection();
        RenderGlobalPower();
        AppendLocalizedLog(M("Dynamic.Global.Log.Connected", profile.Model, entered.BusSerialHex));
        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Connected");
    }

    private static bool IsGlobalEdlInstance(string? deviceInstanceId) =>
        !string.IsNullOrEmpty(deviceInstanceId)
        && deviceInstanceId.IndexOf("VID_05C6", StringComparison.OrdinalIgnoreCase) >= 0
        && deviceInstanceId.IndexOf("PID_9008", StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool AndroidSocMatchesBus(string socSerial, string expectedBusSerialHex)
    {
        if (string.IsNullOrWhiteSpace(socSerial)
            || !uint.TryParse(socSerial, NumberStyles.None, CultureInfo.InvariantCulture, out uint value))
        {
            return false;
        }

        return string.Equals(
            value.ToString("X8", CultureInfo.InvariantCulture),
            expectedBusSerialHex,
            StringComparison.OrdinalIgnoreCase);
    }

    private async Task<EdlToolchain> LoadGlobalToolsAsync(EdlDeviceProfile profile, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.OutputRequired"));
        }

        if (!profile.IsComplete || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.ProfileIncomplete"));
        }

        using Stream? archive = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream(profile.ArchiveLogicalName!);
        if (archive is null)
        {
            throw new InvalidOperationException(T("Dynamic.Global.Error.ToolsMissing"));
        }

        string workRoot = Path.Combine(_globalOutputParent!, GlobalToolchainFolder);
        EdlToolchain tools = await EdlToolchain.LoadAsync(archive, workRoot, token);
        if (!ReferenceEquals(tools.Profile, profile))
        {
            tools.Dispose();
            throw new InvalidOperationException(T("Dynamic.Global.Error.ToolsProfileMismatch"));
        }

        return tools;
    }

    // ---------- 只读备份 ----------

    private async void OnGlobalBackup(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || _globalOperationActive
            || _globalRestoreUncertain || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        // 只读备份只属于备份视图；执行层再兜底一次，即便 UI 包装层已经挡过。
        if (_globalRecoveryMode != GlobalRecoveryMode.Backup)
        {
            return;
        }

        if (_globalEdlClient?.HasInitialSaharaProof != true)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.NeedVerifiedConnection");
            return;
        }

        if (string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputRequired");
            return;
        }

        // 新一轮只读备份必然让旧还原准备失效。
        InvalidateGlobalRestorePreparation();
        SetText(GlobalRestoreSummaryText, "Dynamic.Global.Restore.NotPrepared");

        _globalOperationActive = true;
        var progress = BeginGlobalProgress();
        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BackupRunning");
                    GlobalEdlBackupSet set = await GlobalEdlBackup.CreateAsync(
                        _globalEdlClient!,
                        _globalOutputParent!,
                        progress,
                        token);

                    // 备份真实完成：进度条定格为完成，随后再显示完成消息。
                    if (GlobalProgressBar is not null)
                    {
                        GlobalProgressBar.IsIndeterminate = false;
                        GlobalProgressBar.Maximum = 100;
                        GlobalProgressBar.Value = 100;
                    }

                    try
                    {
                        SetText(
                            GlobalBackupSummaryText,
                            "Dynamic.Global.Backup.Summary",
                            set.DirectoryPath,
                            set.PartitionCount,
                            FormatGlobalBytes(set.RawBytes),
                            FormatGlobalBytes(set.CompressedBytes));
                        AppendLocalizedLog(M(
                            "Dynamic.Global.Log.BackupComplete",
                            set.PartitionCount,
                            FormatGlobalBytes(set.RawBytes)));
                        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BackupComplete");
                    }
                    finally
                    {
                        // 只释放托管对象；备份目录里的文件原样保留。
                        set.Dispose();
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    SetText(GlobalProgressStatusText, GlobalBackupFailureMessage(exception));
                    AppendLocalizedLog(M("Dynamic.Global.Log.BackupFailed", exception.ToString()));
                }
            });
        }
        catch (OperationCanceledException)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Canceled");
        }
        finally
        {
            EndGlobalProgress();
            _globalOperationActive = false;
            RefreshGlobalRecoveryActions();
        }
    }

    private UiMessage GlobalBackupFailureMessage(Exception exception)
    {
        var message = exception.Message ?? string.Empty;
        const string virtualAbPrefix = "global-backup-android-update-unconfirmed:";
        const string linuxSuffix = "; this is not the original Android layout.";

        if (message.StartsWith(virtualAbPrefix, StringComparison.Ordinal))
        {
            return M("Dynamic.Global.Error.AndroidUpdateUnconfirmed");
        }

        var linuxPartitionName = message.StartsWith("LUN", StringComparison.Ordinal)
            && message.Contains(" carries the Linux partition name '")
            && message.EndsWith(linuxSuffix, StringComparison.Ordinal);
        var linuxTypeGuid = message.StartsWith("Partition '", StringComparison.Ordinal)
            && message.Contains(" uses the Linux type GUID ")
            && message.EndsWith(linuxSuffix, StringComparison.Ordinal);
        if (linuxPartitionName || linuxTypeGuid)
        {
            return M("Dynamic.Global.Error.LinuxAlreadyInstalled");
        }

        return M("Dynamic.Global.Status.BackupFailed", exception.Message);
    }

    // ---------- 只读准备 ----------

    private async void OnGlobalPrepareRestore(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || _globalOperationActive
            || _globalRestoreUncertain || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        // 只读准备只属于还原视图；执行层再兜底一次，即便 UI 包装层已经挡过。
        if (_globalRecoveryMode != GlobalRecoveryMode.Restore)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_globalRestoreSource))
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.RestoreSourceRequired");
            return;
        }

        if (string.IsNullOrWhiteSpace(_globalOutputParent))
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputRequired");
            return;
        }

        if (!GlobalRestoreDirectoriesValid())
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Error.OutputInsideRestoreSource");
            return;
        }

        // 准备阶段会对未连接的设备隐式建立连接：明确告知一次，覆盖安卓重启到 9008 与纯 9008 接管两种情形。
        // 复用已有连接时不再重复询问；最终写入仍有它自己的破坏性确认。
        if (_globalEdlClient is null)
        {
            MessageBoxResult connectAnswer = MessageBox.Show(
                this,
                T("Dynamic.Global.Dialog.ConnectWarning"),
                T("Dynamic.Global.Dialog.Title"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Information,
                MessageBoxResult.No);

            if (connectAnswer != MessageBoxResult.Yes)
            {
                return;
            }
        }

        _globalOperationActive = true;
        var progress = BeginGlobalProgress();
        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    InvalidateGlobalRestorePreparation();

                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.VerifyingRestoreSource");
                    GlobalEdlBackupSet set = await GlobalEdlBackup.OpenAsync(
                        _globalRestoreSource!,
                        progress,
                        token);
                    _globalRestoreSet = set;

                    GlobalEdlIdentity identity = set.Identity;
                    EdlDeviceProfile? profile = _globalEdlClient is not null
                        ? _globalProfile
                        : EdlDeviceProfiles.FindByModel(identity.Model);

                    if (profile is null || !profile.IsComplete)
                    {
                        throw new InvalidOperationException(
                            T("Dynamic.Global.Error.RestoreProfileUnsupported", identity.Model));
                    }

                    if (!string.Equals(profile.ProfileId, identity.ProfileId, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            T("Dynamic.Global.Error.RestoreProfileMismatch"));
                    }

                    if (_globalEdlClient is null)
                    {
                        // 未连接时按备份身份自动选中配置项；不产生任何设备 IO。
                        SelectGlobalProfileFromIdentity(identity);
                        RefreshGlobalRecoveryActions();
                    }

                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ConnectingForRestore");
                    if (!await EnsureGlobalConnectionAsync(profile, identity.BusSerialHex, token))
                    {
                        // 没有初始 Sahara 证明时绝不允许进入准备阶段。
                        throw new InvalidOperationException(
                            T("Dynamic.Global.Status.NeedVerifiedConnection"));
                    }

                    if (!string.Equals(_globalProfile?.ProfileId, identity.ProfileId, StringComparison.Ordinal)
                        || !string.Equals(
                            _globalEdlEntry?.BusSerialHex,
                            identity.BusSerialHex,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            T("Dynamic.Global.Error.ConnectionBusMismatch",
                                _globalEdlEntry?.BusSerialHex ?? UnknownValue));
                    }

                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.PreparingRestore");
                    GlobalEdlRestorePlan plan = await GlobalEdlRestore.PrepareAsync(
                        _globalEdlClient!,
                        set,
                        _globalOutputParent!,
                        progress,
                        token);

                    _globalRestorePlan = plan;
                    if (GlobalRestoreConfirmCheck is not null)
                    {
                        GlobalRestoreConfirmCheck.IsChecked = false;
                    }

                    SetText(
                        GlobalRestoreSummaryText,
                        "Dynamic.Global.Restore.Summary",
                        plan.Identity.Model,
                        plan.Identity.BusSerialHex,
                        plan.RegionCount,
                        FormatGlobalBytes(plan.WriteBytes),
                        FormatGlobalGiB(plan.AndroidBytes),
                        plan.EvidenceDirectory);
                    AppendLocalizedLog(M(
                        "Dynamic.Global.Log.RestorePrepared",
                        plan.RegionCount,
                        FormatGlobalBytes(plan.WriteBytes)));
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.RestorePrepared");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    DisposeGlobalRestorePlanOnly();
                    SetText(GlobalRestoreSummaryText, "Dynamic.Global.Restore.NotPrepared");
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.RestorePrepareFailed", exception.Message);
                }
            });
        }
        catch (OperationCanceledException)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Canceled");
        }
        finally
        {
            EndGlobalProgress();
            _globalOperationActive = false;
            RefreshGlobalRecoveryActions();
        }
    }

    private void DisposeGlobalRestorePlanOnly()
    {
        _globalRestorePlan?.Dispose();
        _globalRestorePlan = null;

        if (_ready && GlobalRestoreConfirmCheck is not null)
        {
            GlobalRestoreConfirmCheck.IsChecked = false;
        }
    }

    // ---------- 唯一一次还原 ----------

    private async void OnGlobalRestore(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || _globalOperationActive
            || _globalRestoreUncertain || _globalResetUnknown || _globalRestoreWriteAttempted)
        {
            return;
        }

        // 唯一一次写入只属于还原视图；执行层再兜底一次，最终破坏性确认保持不变。
        if (_globalRecoveryMode != GlobalRecoveryMode.Restore)
        {
            return;
        }

        GlobalEdlRestorePlan? plan = _globalRestorePlan;
        if (plan is null
            || GlobalRestoreConfirmCheck?.IsChecked != true
            || _globalEdlClient?.HasInitialSaharaProof != true)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.NeedVerifiedConnection");
            return;
        }

        MessageBoxResult answer = MessageBox.Show(
            this,
            T(
                "Dynamic.Global.Dialog.ConfirmRestore",
                plan.Identity.Model,
                plan.Identity.BusSerialHex,
                plan.RegionCount,
                FormatGlobalBytes(plan.WriteBytes),
                FormatGlobalGiB(plan.AndroidBytes),
                plan.EvidenceDirectory,
                FormatGlobalPowerForDialog()),
            T("Dynamic.Global.Dialog.Title"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        _globalOperationActive = true;
        var progress = BeginGlobalProgress();
        try
        {
            await RunBusyAsync(async token =>
            {
                // 命令发起前先落标记：之后任何异常都按「可能已写入」处理。
                _globalRestoreWriteAttempted = true;

                try
                {
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.RestoreRunning");
                    var result = await GlobalEdlRestore.ExecuteAsync(
                        plan,
                        plan.ConfirmationId,
                        progress,
                        token);

                    if (result.Success)
                    {
                        // 还原真实成功：进度条定格为完成，随后再显示完成消息。
                        if (GlobalProgressBar is not null)
                        {
                            GlobalProgressBar.IsIndeterminate = false;
                            GlobalProgressBar.Maximum = 100;
                            GlobalProgressBar.Value = 100;
                        }

                        _globalRestoreSucceeded = true;
                        SetText(
                            GlobalRestoreSummaryText,
                            "Dynamic.Global.Restore.Succeeded",
                            plan.Identity.Model,
                            plan.Identity.BusSerialHex,
                            plan.RegionCount,
                            FormatGlobalBytes(plan.WriteBytes),
                            plan.EvidenceDirectory);
                        AppendLocalizedLog(M(
                            "Dynamic.Global.Log.RestoreSucceeded",
                            result.VerifiedRegions.Count,
                            plan.EvidenceDirectory));
                        SetText(GlobalProgressStatusText, "Dynamic.Global.Status.RestoreSucceeded");
                        return;
                    }

                    if (result.AnyWriteStarted)
                    {
                        MarkGlobalRestoreUncertain(result.Error);
                        return;
                    }

                    // 明确没有开始写入：清掉本次尝试，允许用户重新准备。
                    _globalRestoreWriteAttempted = false;
                    DisposeGlobalRestorePlanOnly();
                    SetText(GlobalRestoreSummaryText, "Dynamic.Global.Restore.NotPrepared");
                    SetText(
                        GlobalProgressStatusText,
                        "Dynamic.Global.Status.RestoreNotStarted",
                        result.Error ?? T("Dynamic.Global.Error.Unknown"));
                }
                catch (Exception exception)
                {
                    // 已经调用过执行，异常一律按「写入可能已开始」处理，绝不自动重试。
                    MarkGlobalRestoreUncertain(exception.Message);
                }
            });
        }
        catch (OperationCanceledException)
        {
            MarkGlobalRestoreUncertain(T("Dynamic.Global.Status.Canceled"));
        }
        finally
        {
            EndGlobalProgress();
            _globalOperationActive = false;
            RefreshGlobalRecoveryActions();
        }
    }

    private void MarkGlobalRestoreUncertain(string? detail)
    {
        _globalRestoreUncertain = true;
        _globalRestoreWriteAttempted = true;
        AppendLocalizedLog(M(
            "Dynamic.Global.Log.RestoreUncertain",
            string.IsNullOrWhiteSpace(detail) ? T("Dynamic.Global.Error.Unknown") : detail!));
        SetText(
            GlobalProgressStatusText,
            "Dynamic.Global.Status.RestoreUncertain",
            string.IsNullOrWhiteSpace(detail) ? T("Dynamic.Global.Error.Unknown") : detail!);
    }

    // ---------- 显式重启 ----------

    private async void OnGlobalRestart(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closed || _globalOperationActive
            || _globalResetAttempted || _globalResetUnknown || _globalRestoreUncertain)
        {
            return;
        }

        if (_globalRestoreWriteAttempted && !_globalRestoreSucceeded)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.BlockedBySession");
            return;
        }

        if (_globalEdlClient?.HasInitialSaharaProof != true)
        {
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.NeedVerifiedConnection");
            return;
        }

        _globalOperationActive = true;
        var progress = BeginGlobalProgress();
        try
        {
            await RunBusyAsync(async token =>
            {
                // 重置只允许一次：调用前先落标记。
                _globalResetAttempted = true;
                SetText(GlobalProgressStatusText, "Dynamic.Global.Status.Resetting");

                EdlResetEvidence evidence;
                try
                {
                    evidence = await _globalEdlClient!.ResetAsync(token);
                }
                catch (Exception exception)
                {
                    _globalResetUnknown = true;
                    AppendLocalizedLog(M("Dynamic.Global.Log.ResetUnknown", exception.Message));
                    SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ResetUnknown", exception.Message);
                    return;
                }

                if (!evidence.CommandAccepted)
                {
                    _globalResetUnknown = true;
                    SetText(
                        GlobalProgressStatusText,
                        "Dynamic.Global.Status.ResetUnknown",
                        T("Dynamic.Global.Error.ResetNotAccepted"));
                    return;
                }

                ReleaseGlobalSessionAfterReset();
                AppendLocalizedLog(M("Dynamic.Global.Log.ResetSent"));
                SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ResetSent");
            });
        }
        catch (OperationCanceledException)
        {
            // 已发起过的重置取消同样属于未知结果。
            _globalResetUnknown = true;
            SetText(GlobalProgressStatusText, "Dynamic.Global.Status.ResetUnknown", T("Dynamic.Global.Status.Canceled"));
        }
        finally
        {
            EndGlobalProgress();
            _globalOperationActive = false;
            RenderGlobalConnection();
            RenderGlobalPower();
            RefreshGlobalRecoveryActions();
        }
    }

    /// <summary>重置被接受后只释放本页会话；备份目录与证据目录原样保留。</summary>
    private void ReleaseGlobalSessionAfterReset()
    {
        _globalEdlClient = null;
        _globalEdlEntry = null;
        _globalProfile = null;
        _globalEntryAttempted = false;
        _globalEdlTools?.Dispose();
        _globalEdlTools = null;

        // 只释放托管句柄；备份目录、证据目录与探针文件原样保留。
        _globalRestorePlan?.Dispose();
        _globalRestorePlan = null;
        _globalRestoreSet?.Dispose();
        _globalRestoreSet = null;

        _globalResetAttempted = false;
        _globalResetUnknown = false;
        _globalRestoreWriteAttempted = false;
        _globalRestoreUncertain = false;
        _globalRestoreSucceeded = false;
        _globalCloseConfirmed = false;

        // 下一次连接必须换用全新的探针目录；旧目录里的文件绝不删除。
        _globalSessionDirectory = null;

        if (_ready && GlobalRestoreConfirmCheck is not null)
        {
            GlobalRestoreConfirmCheck.IsChecked = false;
        }

        RenderGlobalConnection();
        RenderGlobalPower();
    }
}
