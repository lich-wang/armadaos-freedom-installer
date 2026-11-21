using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// The offline upgrade page of the macOS window: the port of the WPF <c>MainWindow.OfflineUpgrade.cs</c> (the
/// pairing half lives in MainWindow.OfflinePairing.cs, like on Windows). The page drives the same Core calls in
/// the same order and gates its buttons through the same shared helpers (OfflineUpdateUiState,
/// OfflineUpdateConnectionUiState, OfflineUpdateSessionCatalog, OfflineUpdateRecoveryCatalog are linked from the
/// WPF project). The method bodies follow the WPF ones line for line so the two can be diffed; only the window
/// plumbing differs: the WPF UserControl's controls carry an "Offline" prefix here, MessageBox is MessageDialog,
/// OpenFileDialog is the storage provider, and the records and package work folders live under the Mac cache
/// root because this window has no work directory of its own.
/// </summary>
public partial class MainWindow
{
    private bool _offlineUpgradeInitialized;
    private bool _offlineUpgradeActive;
    private bool _offlineUpgradeCloseInProgress;
    private bool _suppressOfflineSessionSelectionChanged;
    private bool _offlineWindowClosed;

    // The WPF window cancels the page's work through the window-wide RunBusyAsync token; the Mac RunBusyAsync has
    // none, so the page keeps its own token source and completion for "Stop waiting" and for closing the window.
    private CancellationTokenSource? _offlineCts;
    private TaskCompletionSource? _offlineWorkCompletion;

    // Targets whose one automatic factory-credential attempt was actually
    // rejected: a Wi-Fi host/port, or a USB device instance on its
    // endpoint. Only a real authentication rejection is recorded, so a
    // cancelled host-key prompt or a network failure can retry.
    private readonly HashSet<string> _offlineDefaultCredentialRejected =
        new(StringComparer.OrdinalIgnoreCase);
    private IOfflineUpdateConnection? _offlineSsh;
    private OfflineUpdateTransfer? _offlineTransfer;
    private ImportedUpdatePackage? _offlinePackage;
    private string? _offlineDescriptorSha256;
    private string? _offlineConnectedModel;
    private string? _offlineActualSlot;
    private string? _offlineRecoveryPartUuid;
    private IReadOnlyList<OfflineUpdateSession> _offlineSessions = Array.Empty<OfflineUpdateSession>();
    // Records that exist for the connected device but cannot be read. They
    // are reported and skipped; they never remove a valid session or an
    // imported package, and they are never rewritten.
    private IReadOnlyList<OfflineDamagedSessionRecord> _offlineDamagedSessionRecords =
        Array.Empty<OfflineDamagedSessionRecord>();
    // The records location itself could not be resolved or read. It is kept
    // apart from an empty device and from damaged records so an unreadable
    // location is never presented as "no saved session", never lets a new
    // session begin beside records nobody could inspect, and is cleared again
    // only by a fresh readable scan.
    private string? _offlineSavedSessionsUnavailableReason;
    private OfflineUpdateSession? _offlineSelectedSession;
    private SavedOfflineUpdateRecovery? _offlineSavedRecovery;
    private JsonElement? _offlineLastReceipt;
    private bool _offlineReceiptLive;
    private string? _offlineLastLoggedPhase;
    private string? _offlineLastCompletionState;
    // The read-only preflight is bound to this exact package and this exact
    // tablet connection. It is recorded only after the device returns the
    // exact success schema and is cleared by every package/device change.
    private bool _offlinePreflightPassed;
    // The mutating upgrade contract recorded from the authenticated info:
    // both physical A/B candidates boot the same Linux deployment and the
    // helper never controls Android's active/selected/successful slot.
    private bool _offlineBootPolicySupported;
    private string? _offlinePreflightError;
    private long _offlineOperationGeneration;
    // Set when the panel itself moved the user to the custom account, so the
    // password field receives focus once the busy state releases it.
    private bool _offlineFocusPasswordOnIdle;
    private readonly List<UiMessage> _offlineLogEntries = new();

    /// <summary>The page holds a connection, an imported package or a running exchange.</summary>
    private bool HasOfflineUpgradeState => _offlineUpgradeActive || _offlineSsh != null || _offlinePackage != null;

    private void InitializeOfflineUpgradeView()
    {
        if (_offlineUpgradeInitialized)
            return;

        _offlineUpgradeInitialized = true;
        // WPF: SessionCombo.DisplayMemberPath = SessionId. Event handlers are wired in MainWindow.axaml.
        OfflineSessionCombo.DisplayMemberBinding = new Binding(nameof(OfflineUpdateSession.SessionId));
        Closed += (_, _) => _offlineWindowClosed = true;
        RefreshOfflineUpgradeActions();
    }

    // ================================================================ navigation

    /// <summary>
    /// Opens the page from its home card. Like the WPF guard, the page stays closed while another page holds the
    /// tablet in (or possibly in) 9008; the WPF-only TF, uninstall and boot-maintenance states do not exist here.
    /// </summary>
    private void ShowOfflineUpgradePage()
    {
        if (!_environmentReady || _busy || !HomePage.IsVisible || HasLiveDeviceSession)
            return;

        ShowView(OfflineUpgradePage);
        RefreshActions();
        OfflineUpgradePage.ScrollToHome();
    }

    private void RefreshOfflineUpgradeActions()
    {
        if (!_offlineUpgradeInitialized)
            return;

        bool connected = _offlineSsh != null && !string.IsNullOrEmpty(_offlineConnectedModel);
        bool imported = _offlinePackage != null && !string.IsNullOrEmpty(_offlineDescriptorSha256);
        // Closing or an older helper still gets read-only info/status; only
        // the mutating prepare/execute/restart actions need the policy.
        bool bootPolicySupported = connected && _offlineBootPolicySupported;
        // 关闭等待期间同样按忙碌处理：按钮全部禁用，直到清理完成。
        bool busy = _busy || _offlineUpgradeCloseInProgress;
        bool preparedReady = bootPolicySupported &&
            OfflineUpdateUiState.CanExecute(_offlineLastReceipt, _offlineSavedRecovery != null, _offlinePreflightPassed);

        OfflineBackButton.IsEnabled = !busy;
        var transport = SelectedOfflineTransport;
        var credential = SelectedOfflineCredential;
        var fields = OfflineUpdateConnectionUiState.Fields(transport, credential);
        bool fieldsEnabled = !busy && !connected;
        OfflineTransportCombo.IsEnabled = fieldsEnabled;
        OfflineCredentialCombo.IsEnabled = fieldsEnabled;
        OfflineUsbAddressHint.IsVisible = !fields.ShowWifiAddress;
        OfflineWifiAddressPanel.IsVisible = fields.ShowWifiAddress;
        OfflineHostBox.IsEnabled = fieldsEnabled && fields.ShowWifiAddress;
        OfflinePortBox.IsEnabled = fieldsEnabled && fields.ShowWifiAddress;
        OfflineDefaultAccountText.IsVisible = fields.ShowDefaultAccount;
        OfflineManualUserNamePanel.IsVisible = fields.ShowManualUserName;
        OfflineUserBox.IsEnabled = fieldsEnabled && fields.ShowManualUserName;
        OfflineCustomPasswordPanel.IsVisible = fields.ShowCustomPassword;
        OfflinePasswordBox.IsEnabled = fieldsEnabled && fields.ShowCustomPassword;
        OfflineKeyFieldsPanel.IsVisible = fields.ShowKeyFields;
        OfflineUsbKeyEnrollmentHint.IsVisible = fields.ShowKeyFields && transport == OfflineUpdateTransport.Usb;
        OfflineWifiKeyEnrollmentHint.IsVisible = fields.ShowKeyFields && transport == OfflineUpdateTransport.Wifi;
        OfflineKeyPathBox.IsEnabled = fieldsEnabled && fields.ShowKeyFields;
        OfflineKnownHostsBox.IsEnabled = fieldsEnabled && fields.ShowKeyFields;
        OfflineBrowseKeyButton.IsEnabled = fieldsEnabled && fields.ShowKeyFields;
        OfflineBrowseHostsButton.IsEnabled = fieldsEnabled && fields.ShowKeyFields;
        OfflineConnectButton.IsEnabled = fieldsEnabled;
        bool pairingPending = _offlinePairingCandidate != null && _offlinePairingIdentity != null;
        OfflineCopyPairingCommandButton.IsEnabled = !busy && !connected && pairingPending;
        OfflineConfirmPairingButton.IsEnabled = !busy && !connected && pairingPending && !string.IsNullOrWhiteSpace(OfflinePairingReceiptBox.Text);
        OfflinePairingReceiptBox.IsReadOnly = busy || connected || !pairingPending;
        OfflineDisconnectButton.IsEnabled = !busy && connected;

        OfflineBrowsePackageButton.IsEnabled = !busy && connected;
        OfflineValidatePackageButton.IsEnabled = !busy && connected && !string.IsNullOrWhiteSpace(OfflinePackagePathBox.Text);
        // Saved sessions come from the device-bound records, so they can be
        // listed and queried without importing the package. Preparing,
        // executing and saving recovery still require a validated package;
        // preparing may start with no session because it creates the first
        // one, while executing also needs the selected session.
        OfflineSessionCombo.IsEnabled = !busy && connected && _offlineSessions.Count > 0;

        // A records location that cannot be read is reported, not treated
        // as an empty device: no new session may begin while the saved
        // records are invisible.
        bool catalogAvailable = _offlineSavedSessionsUnavailableReason == null;

        bool canPrepare = !busy && bootPolicySupported && catalogAvailable &&
            OfflineUpdateUiState.CanPrepareSession(connected, imported, _offlinePreflightPassed,
            _offlineLastReceipt, _offlineSessions.Count > 0, _offlineSelectedSession != null);
        // A session the tablet already prepared reaches the recovery export
        // through the same Plan action; export is read-only, so the boot
        // policy is not part of this gate.
        bool canExportRecovery = !busy && catalogAvailable && OfflineUpdateUiState.CanExportRecoverySession(
            connected, imported, _offlinePreflightPassed, _offlineSelectedSession != null,
            _offlineLastReceipt, _offlineSavedRecovery != null);
        OfflinePrepareButton.IsEnabled = canPrepare || canExportRecovery;
        // Starting a replacement session is a separate, explicitly confirmed
        // action, offered only for a live, fully verified failed preparation
        // of the selected record. It never retries that record, and it never
        // enables Execute or Restart.
        bool failedPrepareSelected =
            OfflineUpdateUiState.IsBoundForReplacement(_offlineLastReceipt, _offlineSelectedSession,
                _offlineConnectedModel, _offlineRecoveryPartUuid, _offlineDescriptorSha256);
        bool canStartReplacement = !busy && bootPolicySupported &&
            OfflineUpdateUiState.CanStartReplacementSession(connected, imported,
                catalogAvailable, _offlineReceiptLive, _offlineSelectedSession != null, failedPrepareSelected);
        OfflineStartReplacementSessionButton.IsVisible = failedPrepareSelected && _offlineReceiptLive;
        OfflineStartReplacementSessionButton.IsEnabled = canStartReplacement;
        // A saved session's status is read with only a selection; without a
        // session the same button retries only the read-only preflight, and an
        // unreadable records location keeps Refresh offered to re-read it.
        bool catalogRetryable = connected && _offlineSavedSessionsUnavailableReason != null;
        OfflineRefreshButton.IsEnabled = !busy &&
            (OfflineUpdateUiState.CanRefreshStatus(connected, _offlineSelectedSession != null) ||
             OfflineUpdateUiState.CanRetryPreflightWithoutSession(connected, imported, _offlineSessions.Count > 0) ||
             catalogRetryable);

        OfflineConfirmCheck.IsEnabled = !busy && OfflineUpdateUiState.CanMutateSession(connected, imported, _offlineSelectedSession != null) && preparedReady;
        OfflineExecuteButton.IsEnabled = !busy && OfflineUpdateUiState.CanMutateSession(connected, imported, _offlineSelectedSession != null) && preparedReady && OfflineConfirmCheck.IsChecked == true;
        OfflineStopWaitingButton.IsEnabled = busy && _offlineUpgradeActive;
        // Only a receipt read live from this tablet in this connection may
        // offer the restart action; a locally saved receipt is informative.
        OfflineRestartToVerifyButton.IsEnabled = !busy && connected && bootPolicySupported &&
            _offlineReceiptLive && _offlineSelectedSession != null &&
            OfflineUpdateUiState.CanRestartToVerify(_offlineLastReceipt);
    }

    /// <summary>The log box is plain text, so a language switch renders every remembered message again.</summary>
    private void RerenderOfflineUpgradeLog()
    {
        if (!_offlineUpgradeInitialized)
            return;

        var lines = new List<string>(_offlineLogEntries.Count);
        foreach (var msg in _offlineLogEntries)
            lines.Add(_l.Format(msg));
        var text = string.Join(Environment.NewLine, lines);
        OfflineLogText.Text = text;
        OfflineLogText.CaretIndex = text.Length;
    }

    private void AppendOfflineLog(string key, params object?[] args)
    {
        if (_offlineLogEntries.Count >= 200)
            _offlineLogEntries.RemoveAt(0);
        _offlineLogEntries.Add(M(key, args));
        RerenderOfflineUpgradeLog();
    }

    /// <summary>
    /// The WPF window resolves the records location from its cache root and its chosen work directory. This
    /// window has no work directory, so the Mac cache root stands in for both: the first resolve pins
    /// <c>records/offline-upgrades</c> below it, and Core keeps refusing a pinned location that went missing.
    /// </summary>
    private static string GetPersistentRecordsRoot() =>
        OfflineUpdateRecordsDirectory.Resolve(MacCacheRoot, MacCacheRoot);

    /// <summary>
    /// Best-effort records root for read-only status work. A store that is
    /// invalid or missing returns null with the reason already used for the
    /// saved-sessions diagnostic.
    /// </summary>
    private static string? TryGetPersistentRecordsRoot(out string? unavailableReason)
    {
        try
        {
            unavailableReason = null;
            return GetPersistentRecordsRoot();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            unavailableReason = ex.Message;
            return null;
        }
    }

    /// <summary>Where Core stages an imported offline package (the WPF window uses its work session folder).</summary>
    private static string OfflineTemporaryWorkRoot
    {
        get
        {
            var root = Path.Combine(MacCacheRoot, "offline-upgrade-work");
            Directory.CreateDirectory(root);
            return root;
        }
    }

    private async Task RunOfflineUpgradeAsync(Func<long, CancellationToken, Task> action)
    {
        if (_busy || _offlineUpgradeCloseInProgress || _offlineWindowClosed)
            return;

        long gen = Interlocked.Increment(ref _offlineOperationGeneration);
        _offlineUpgradeActive = true;
        _offlineLastLoggedPhase = null;
        OfflineTransferProgress.Value = 0;
        SetOfflineIndeterminateProgress(true);

        using var cts = new CancellationTokenSource();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _offlineCts = cts;
        _offlineWorkCompletion = completion;
        try
        {
            await RunBusyAsync(async _ =>
            {
                var ct = cts.Token;
                try
                {
                    await action(gen, ct);
                }
                catch (OperationCanceledException)
                {
                    ClearOfflineActionEligibility();
                    _offlineLastReceipt = null;
                    _offlineReceiptLive = false;
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateStoppedWaiting");
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogStoppedWaiting");

                    // A cancel that interrupted an already sent request leaves
                    // this request/response stream in an unknown state; only the
                    // transport is released then.
                    if (_offlineSsh != null && _offlineSsh.Rpc.IsPoisoned)
                        await ReleasePoisonedOfflineConnectionAsync();
                }
                catch (OfflineUpdateTransferException tex)
                {
                    ClearOfflineActionEligibility();
                    if (tex.Receipt.HasValue)
                    {
                        JsonElement receipt = tex.Receipt.Value;
                        if (OfflineUpdateUiState.BelongsToSession(receipt, _offlineSelectedSession))
                        {
                            _offlineLastReceipt = receipt.Clone();
                            // Live evidence only for the exact attachment the
                            // live-gated actions require (see the WPF page).
                            _offlineReceiptLive = OfflineUpdateUiState.IsBoundForReplacement(
                                _offlineLastReceipt, _offlineSelectedSession,
                                _offlineConnectedModel, _offlineRecoveryPartUuid, _offlineDescriptorSha256);
                            await TryPersistReceiptAsync(_offlineSelectedSession, _offlineLastReceipt.Value);
                            UpdateDetailsWithReceipt(_offlineLastReceipt.Value, tex.Message);
                        }
                        else
                        {
                            // A receipt for another session is not evidence for
                            // the selected record; keep it only as isolated
                            // local diagnostics.
                            await TryPersistUnmatchedReceiptAsync(receipt);
                            SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", tex.Message);
                        }
                    }
                    else
                    {
                        // 无回执的传输失败不能沿用上一次的旧回执，否则旧状态会继续驱动按钮。
                        _offlineLastReceipt = null;
                        _offlineReceiptLive = false;
                        SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", tex.Message);
                    }
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateFailed", tex.Message);
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogError", tex.Message);
                }
                catch (Exception ex)
                {
                    ClearOfflineActionEligibility();
                    _offlineLastReceipt = null;
                    _offlineReceiptLive = false;
                    SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", ex.Message);
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateFailed", ex.Message);
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogError", ex.Message);
                }
                finally
                {
                    Interlocked.Increment(ref _offlineOperationGeneration);
                    _offlineUpgradeActive = false;
                    SetOfflineIndeterminateProgress(false);
                    // 每次操作结束都检查一次：只释放传输层，已导入的包和
                    // 持久化的会话记录都保留，操作员可以重连后继续同一会话。
                    if (_offlineSsh != null && _offlineSsh.Rpc.IsPoisoned)
                        await ReleasePoisonedOfflineConnectionAsync();
                    RefreshActions();
                }
            });
        }
        finally
        {
            _offlineCts = null;
            _offlineWorkCompletion = null;
            completion.TrySetResult();
        }
    }

    private void SetOfflineIndeterminateProgress(bool active)
    {
        OfflineTransferProgress.IsIndeterminate = active;
    }

    private IProgress<OfflineUpdateTransferProgress> CreateOfflineProgress(long generation)
    {
        return new Progress<OfflineUpdateTransferProgress>(p =>
        {
            if (Interlocked.Read(ref _offlineOperationGeneration) != generation || !_offlineUpgradeActive || _offlineWindowClosed)
                return;

            if (!string.IsNullOrWhiteSpace(p.Phase) && !string.Equals(_offlineLastLoggedPhase, p.Phase, StringComparison.Ordinal))
            {
                _offlineLastLoggedPhase = p.Phase;
                AppendOfflineLog("Dynamic.OfflineUpdate.LogPhase", LocalizePhase(p.Phase));
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePhase", LocalizePhase(p.Phase));
            }

            if (p.TotalBytes.HasValue && p.TotalBytes.Value > 0 && p.BytesCompleted.HasValue)
            {
                OfflineTransferProgress.IsIndeterminate = false;
                double pct = Math.Clamp((double)p.BytesCompleted.Value * 100.0 / p.TotalBytes.Value, 0.0, 100.0);
                OfflineTransferProgress.Value = pct;
                SetText(OfflineProgressText, "Dynamic.OfflineUpdate.Value", $"{pct:F0}% ({p.BytesCompleted.Value / 1024.0:F1} KiB / {p.TotalBytes.Value / 1024.0:F1} KiB)");
            }
            else
            {
                OfflineTransferProgress.IsIndeterminate = true;
                SetText(OfflineProgressText, LocalizePhase(p.Phase));
            }
        });
    }

    private static UiMessage LocalizePhase(string? phase) => phase switch
    {
        "uploading" => M("Dynamic.OfflineUpdate.Phase.Uploading"),
        "uploaded" => M("Dynamic.OfflineUpdate.Phase.Uploaded"),
        "prepare_queued" => M("Dynamic.OfflineUpdate.Phase.PrepareQueued"),
        "preparing" => M("Dynamic.OfflineUpdate.Phase.Preparing"),
        "awaiting_recovery_export" => M("Dynamic.OfflineUpdate.Phase.AwaitingRecoveryExport"),
        "saving_recovery_metadata" => M("Dynamic.OfflineUpdate.Phase.SavingRecoveryMetadata"),
        "saving_recovery" => M("Dynamic.OfflineUpdate.Phase.SavingRecovery"),
        "prepared" => M("Dynamic.OfflineUpdate.Phase.Prepared"),
        "up_to_date" => M("Dynamic.OfflineUpdate.Phase.UpToDate"),
        "execute_queued" => M("Dynamic.OfflineUpdate.Phase.ExecuteQueued"),
        "executing" => M("Dynamic.OfflineUpdate.Phase.Executing"),
        "awaiting_reboot" => M("Dynamic.OfflineUpdate.Phase.AwaitingReboot"),
        "failed" => M("Dynamic.OfflineUpdate.Phase.Failed"),
        _ => string.IsNullOrWhiteSpace(phase) ? M("Dynamic.OfflineUpdate.Phase.Working") : M("Dynamic.OfflineUpdate.Value", phase!)
    };

    private async Task<string?> PickOfflineFileAsync(IReadOnlyList<FilePickerFileType>? filters = null)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = T("Static.OfflineUpdate.Title"),
            AllowMultiple = false,
            FileTypeFilter = filters,
        });
        var path = files.Count == 1 ? files[0].TryGetLocalPath() : null;
        return !string.IsNullOrWhiteSpace(path) && File.Exists(path) ? path : null;
    }

    private async void OnBrowseOfflineKey(object? sender, RoutedEventArgs e)
    {
        if (await PickOfflineFileAsync() is { } path)
            OfflineKeyPathBox.Text = path;
    }

    private async void OnBrowseOfflineKnownHosts(object? sender, RoutedEventArgs e)
    {
        if (await PickOfflineFileAsync() is { } path)
            OfflineKnownHostsBox.Text = path;
    }

    private async void OnBrowseOfflinePackage(object? sender, RoutedEventArgs e)
    {
        if (_busy)
            return;

        var chosen = await PickOfflineFileAsync(new[]
        {
            new FilePickerFileType("Update Packages (*.zip;*.001)") { Patterns = new[] { "*.zip", "*.001" } },
            FilePickerFileTypes.All,
        });
        if (chosen != null && !string.Equals(OfflinePackagePathBox.Text, chosen, StringComparison.Ordinal))
        {
            await RunOfflineUpgradeAsync((_, _) =>
            {
                DisposeImportedPackageAndInvalidate();
                OfflinePackagePathBox.Text = chosen;
                RefreshActions();
                return Task.CompletedTask;
            });
        }
    }

    private OfflineUpdateTransport SelectedOfflineTransport =>
        OfflineUpdateConnectionUiState.TransportFromIndex(
            _offlineUpgradeInitialized ? OfflineTransportCombo.SelectedIndex : OfflineUpdateConnectionUiState.UsbTransportIndex);

    private OfflineUpdateCredentialMode SelectedOfflineCredential =>
        OfflineUpdateConnectionUiState.CredentialFromIndex(
            _offlineUpgradeInitialized ? OfflineCredentialCombo.SelectedIndex : OfflineUpdateConnectionUiState.DefaultCredentialIndex);

    private void OnOfflineConnectionSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // Avalonia raises this while the window is still loading its controls.
        if (!_offlineUpgradeInitialized)
            return;

        // A pending key-pairing prompt belongs to one connection attempt, and
        // a secret typed for another selection is cleared instead of lingering
        // in a hidden field. The Wi-Fi address stays exactly as typed.
        ClearOfflinePairing();
        OfflinePasswordBox.Text = string.Empty;
        RefreshOfflineUpgradeActions();
    }

    private static string GetOfflineHostTrustDirectory() =>
        Path.Combine(MacCacheRoot, "connections", "offline-upgrade", "trusted-hosts");

    private async Task<OfflineUpdateUsbEndpoint> FindOfflineUsbEndpointAsync(CancellationToken ct)
    {
        try
        {
            // No PowerShell path: Core takes its ioreg-based macOS discovery.
            return await OfflineUpdateUsbDiscovery.FindSingleAsync(_runner, token: ct);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorUsbConnection", ex.Message));
        }
    }

    /// <summary>
    /// One connect action. The explicitly selected transport decides between
    /// USB discovery and the typed Wi-Fi address, then the explicitly
    /// selected credential source decides between the factory account, a
    /// custom account and an SSH key.
    /// </summary>
    private async void OnConnectOfflineTabletAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy || _offlineSsh != null)
            return;

        var transport = SelectedOfflineTransport;
        var credential = SelectedOfflineCredential;
        await RunOfflineUpgradeAsync(async (_, ct) =>
        {
            string typedUser = (OfflineUserBox.Text ?? string.Empty).Trim();
            string typedPassword = OfflinePasswordBox.Text ?? string.Empty;
            string keyPath = (OfflineKeyPathBox.Text ?? string.Empty).Trim();
            string hostsPath = (OfflineKnownHostsBox.Text ?? string.Empty).Trim();

            if (OfflineUpdateConnectionUiState.IsWifiAddressMissing(transport, OfflineHostBox.Text))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorWifiAddressRequired"));

            int port = OfflineUpdateConnectionUiState.UsbSshPort;
            string host = string.Empty;
            // Only a validated USB discovery result sets this; the Wi-Fi
            // route keeps its typed host/port identity.
            string? usbDeviceInstanceId = null;
            if (OfflineUpdateConnectionUiState.UsesWifiAddress(transport))
            {
                if (!OfflineUpdateConnectionUiState.TryParsePort(OfflinePortBox.Text, out port))
                    throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorWifiPortInvalid"));
                host = (OfflineHostBox.Text ?? string.Empty).Trim();
            }

            if (credential == OfflineUpdateCredentialMode.CustomAccount &&
                OfflineUpdateConnectionUiState.IsCustomCredentialIncomplete(typedUser, typedPassword))
            {
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorCustomCredentialsRequired"));
            }

            if (credential == OfflineUpdateCredentialMode.PublicKey &&
                OfflineUpdateConnectionUiState.IsExplicitKeyIncomplete(transport, credential, typedUser, keyPath, hostsPath))
            {
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorKeyCredentialsRequired"));
            }

            if (credential == OfflineUpdateCredentialMode.PublicKey)
            {
                if (OfflineUpdateConnectionUiState.IsUsbKeyEnrollment(transport, credential, keyPath, hostsPath))
                {
                    await BeginOfflineUsbKeyEnrollmentAsync(ct);
                    return;
                }

                string? keyBindAddress = null;
                if (OfflineUpdateConnectionUiState.UsesUsbDiscovery(transport))
                {
                    var endpoint = await FindOfflineUsbEndpointAsync(ct);
                    host = endpoint.Host;
                    keyBindAddress = endpoint.LocalAddress;
                }

                var keyOptions = new OfflineUpdateSshOptions(host, port, typedUser, keyPath, hostsPath, BindAddress: keyBindAddress);
                ClearOfflinePairing();
                await ConnectOfflineOptionsAsync(keyOptions, ct);
                return;
            }

            var defaultCredential = OfflineUpdateSshDefaultCredentials.Instance;
            if (!OfflineUpdateConnectionUiState.TryResolvePasswordCredential(
                    credential, typedUser, typedPassword,
                    defaultCredential.UserName, defaultCredential.Password,
                    out string userName, out string password))
            {
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorCustomCredentialsRequired"));
            }

            string? bindAddress = null;
            if (OfflineUpdateConnectionUiState.UsesUsbDiscovery(transport))
            {
                var endpoint = await FindOfflineUsbEndpointAsync(ct);
                host = endpoint.Host;
                bindAddress = endpoint.LocalAddress;
                usbDeviceInstanceId = endpoint.DeviceInstanceId;
            }

            string rejectionKey = OfflineUpdateSshAuthPolicy.DefaultCredentialRejectionKey(host, port, usbDeviceInstanceId);
            bool defaultAccount = credential == OfflineUpdateCredentialMode.DefaultAccount;
            bool usingDefault = defaultAccount &&
                OfflineUpdateSshAuthPolicy.ShouldAttemptDefaultCredential(
                    OfflineUpdateSshAuthMode.Password,
                    credentialsSuppliedByUser: false,
                    defaultAlreadyAttempted: _offlineDefaultCredentialRejected.Contains(rejectionKey));

            // The automatic factory attempt is limited to once per target;
            // afterwards the same selection asks for the password instead.
            if (defaultAccount && !usingDefault)
            {
                ShowOfflinePasswordEntry("Dynamic.OfflineUpdate.DefaultCredentialRejected");
                return;
            }

            var options = new OfflineUpdateSshPasswordOptions(
                host,
                port,
                userName,
                password,
                GetOfflineHostTrustDirectory(),
                bindAddress)
            {
                ApproveHostKey = ApproveOfflineSshHostKeyAsync,
            };

            // Only a user-entered secret is cleared; the public factory
            // credential is product configuration, not a stored user secret.
            if (!defaultAccount)
                OfflinePasswordBox.Text = string.Empty;
            ClearOfflinePairing();
            try
            {
                await ConnectOfflinePasswordAsync(options, ct);
            }
            catch (InvalidOperationException ex) when (usingDefault && IsOfflinePasswordRejection(ex))
            {
                // Only a real authentication rejection consumes the single
                // automatic attempt for this exact target.
                _offlineDefaultCredentialRejected.Add(rejectionKey);
                ShowOfflinePasswordEntry("Dynamic.OfflineUpdate.DefaultCredentialRejected");
            }
        });

        FocusOfflinePasswordIfPending();
    }

    /// <summary>
    /// The rejection path clears and shows the custom password field while
    /// the window is still busy, so focus is applied once the fields are
    /// enabled again.
    /// </summary>
    private void FocusOfflinePasswordIfPending()
    {
        if (!_offlineFocusPasswordOnIdle)
            return;
        _offlineFocusPasswordOnIdle = false;
        if (_busy || _offlineSsh != null)
            return;
        OfflinePasswordBox.Focus();
    }

    private async void OnDisconnectOfflineSshAsync(object? sender, RoutedEventArgs e)
    {
        await RunOfflineUpgradeAsync(async (_, _) =>
        {
            await DisconnectAndCleanupStageAsync();
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateDisconnected");
            AppendOfflineLog("Dynamic.OfflineUpdate.LogDisconnected");
        });
    }

    private async void OnOfflineUpgradeBackAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy)
            return;

        if (_offlineSsh != null || _offlinePackage != null)
        {
            await RunOfflineUpgradeAsync(async (_, _) =>
            {
                await DisconnectAndCleanupStageAsync();
            });
        }

        if (!_busy && _offlineSsh == null && _offlinePackage == null)
        {
            ClearOfflinePairing();
            ShowView(HomePage);
            RefreshActions();
        }
    }

    private async Task DisconnectAndCleanupStageAsync()
    {
        ClearOfflinePairing();
        ClearOfflinePasswordEntry();
        var ssh = _offlineSsh;
        try
        {
            DisposeImportedPackageAndInvalidate(disconnecting: true);
        }
        finally
        {
            _offlineSsh = null;
            _offlineTransfer = null;
            _offlineConnectedModel = null;
            _offlineActualSlot = null;
            _offlineRecoveryPartUuid = null;
            _offlineBootPolicySupported = false;
            ClearOfflinePreflightState();
            SetText(OfflineDeviceText, "Static.OfflineUpdate.DevicePending");
            SetText(OfflineDetailsText, "Static.OfflineUpdate.DetailsPending");
            if (ssh != null)
                await ssh.DisposeAsync();
        }
    }

    private void ClearOfflinePasswordEntry()
    {
        // The rejected-target set is intentionally kept: the automatic
        // attempt is limited per target, not reset by a disconnect.
        OfflinePasswordBox.Text = string.Empty;
    }

    private void DisposeImportedPackageAndInvalidate(bool disconnecting = false)
    {
        ClearOfflinePreflightState();
        ClearOfflineSelectionState();
        _suppressOfflineSessionSelectionChanged = true;
        OfflineSessionCombo.ItemsSource = null;
        _suppressOfflineSessionSelectionChanged = false;
        _offlineSessions = Array.Empty<OfflineUpdateSession>();
        _offlineDescriptorSha256 = null;
        var pkg = _offlinePackage;
        _offlinePackage = null;
        pkg?.Dispose();
        SetText(OfflinePackageText, "Static.OfflineUpdate.PackagePending");
        if (!disconnecting && _offlineSsh != null)
            LoadSavedOfflineSessionsForDevice();
    }

    private void ClearOfflineSelectionState()
    {
        _offlineSelectedSession = null;
        _offlineLastReceipt = null;
        _offlineReceiptLive = false;
        _offlineLastCompletionState = null;
        ClearOfflineActionEligibility();
        SetText(OfflineRecoveryPathText, "Static.OfflineUpdate.RecoveryPending");
    }

    private void ClearOfflineActionEligibility()
    {
        _offlineSavedRecovery = null;
        OfflineConfirmCheck.IsChecked = false;
    }

    /// <summary>
    /// The read-only preflight only covers the package and device it was
    /// run against. Any package change, disconnect or invalidation drops
    /// the pass so Prepare cannot run on stale evidence.
    /// </summary>
    private void ClearOfflinePreflightState()
    {
        _offlinePreflightPassed = false;
        _offlinePreflightError = null;
    }

    private void MarkOfflinePreflightFailed(string reason)
    {
        _offlinePreflightPassed = false;
        _offlinePreflightError = reason;
        SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreflightFailed", reason);
        AppendOfflineLog("Dynamic.OfflineUpdate.LogPreflightFailed", reason);
    }

    private async void OnValidateOfflinePackageAsync(object? sender, RoutedEventArgs e)
    {
        await RunOfflineUpgradeAsync(async (_, ct) =>
        {
            if (_offlineSsh == null || string.IsNullOrEmpty(_offlineConnectedModel) || string.IsNullOrEmpty(_offlineRecoveryPartUuid))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNotConnected"));

            ClearOfflinePreflightState();
            string path = (OfflinePackagePathBox.Text ?? string.Empty).Trim();
            if (string.IsNullOrEmpty(path))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNoPackagePath"));

            DisposeImportedPackageAndInvalidate();
            string installerVer = GetThreePartInstallerVersion();
            var imported = await PackageImporter.ImportOfflineUpdateAsync(path, _offlineConnectedModel, installerVer, OfflineTemporaryWorkRoot, ct);
            try
            {
                byte[] descBytes = await File.ReadAllBytesAsync(imported.DescriptorPath, ct);
                string descSha = Convert.ToHexString(SHA256.HashData(descBytes)).ToLowerInvariant();

                _offlinePackage = imported;
                _offlineDescriptorSha256 = descSha;

                SetText(OfflinePackageText, "Dynamic.OfflineUpdate.PackageValidated", imported.Descriptor.Version, imported.Descriptor.ReleaseId);
                AppendOfflineLog("Dynamic.OfflineUpdate.LogPackageValidated", imported.Descriptor.Version, imported.Descriptor.ReleaseId);

                // Sessions are matched one record at a time; an unrelated
                // damaged record is reported and skipped.
                ApplyFilteredOfflineSessions(LoadSavedOfflineSessions());
                ReportSavedOfflineSessionIssues();

                // Read-only preflight. It never creates a session, prepares
                // a candidate or writes a slot. Only the exact success
                // schema unlocks Prepare.
                await RunOfflinePreflightAsync(_offlineSelectedSession, ct);
            }
            catch
            {
                if (_offlinePackage == null)
                    imported.Dispose();
                throw;
            }
        });
    }

    /// <summary>
    /// Install the matched sessions, dropping the older package's receipt,
    /// live flag, completion and recovery. The explicit
    /// <paramref name="previousSelection"/> is used only by the readable
    /// retry: that record is kept only when the refreshed store still holds
    /// the exact same value record.
    /// </summary>
    private void ApplyFilteredOfflineSessions(
        IReadOnlyList<OfflineUpdateSession> sessions,
        OfflineUpdateSession? previousSelection = null)
    {
        bool hadSelection = previousSelection != null;
        OfflineUpdateSession? selection =
            OfflineUpdateSessionCatalog.SelectAfterRefresh(previousSelection, sessions);

        ClearOfflineSelectionState();
        _offlineSessions = sessions;

        _suppressOfflineSessionSelectionChanged = true;
        try
        {
            OfflineSessionCombo.ItemsSource = _offlineSessions;
            OfflineSessionCombo.SelectedItem = selection;
            _offlineSelectedSession = selection;
            if (selection != null)
            {
                _offlineLastReceipt = TryLoadPersistedOfflineReceipt(selection);
                if (_offlineLastReceipt.HasValue)
                {
                    UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
                    ShowPersistedOfflineResult(_offlineLastReceipt.Value);
                }
                else
                {
                    SetText(OfflineStateText,
                        hadSelection
                            ? "Dynamic.OfflineUpdate.StateSessionSelected"
                            : "Dynamic.OfflineUpdate.StateSingleSessionMatched",
                        selection.SessionId);
                }
            }
            else if (_offlineSessions.Count > 0)
            {
                // Records exist, but none is the record that was selected
                // before, or nothing was selected and there are several.
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateMultipleSessionsFound", _offlineSessions.Count);
            }
            else
            {
                bool hasPackage = _offlinePackage != null && !string.IsNullOrEmpty(_offlineDescriptorSha256);
                SetText(OfflineStateText,
                    hasPackage
                        ? "Dynamic.OfflineUpdate.StateReadyToPrepareNew"
                        : "Dynamic.OfflineUpdate.StateConnected");
            }
        }
        finally
        {
            _suppressOfflineSessionSelectionChanged = false;
        }
    }

    private void OnOfflineSessionSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_offlineUpgradeInitialized || _suppressOfflineSessionSelectionChanged)
            return;

        // Preflight evidence belongs to the session it was run for; another
        // selection always has to earn its own read-only pass.
        ClearOfflinePreflightState();
        ClearOfflineSelectionState();
        _offlineSelectedSession = OfflineSessionCombo.SelectedItem as OfflineUpdateSession;
        if (_offlineSelectedSession != null)
        {
            // After an app restart the last persisted result is shown from
            // local records without contacting the tablet or re-uploading.
            _offlineLastReceipt = TryLoadPersistedOfflineReceipt(_offlineSelectedSession);
            if (_offlineLastReceipt.HasValue)
            {
                UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
                ShowPersistedOfflineResult(_offlineLastReceipt.Value);
            }
            else
            {
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateSessionSelected", _offlineSelectedSession.SessionId);
            }
        }
        RefreshActions();
    }

    private void OnOfflineConfirmChanged(object? sender, RoutedEventArgs e)
    {
        if (_offlineUpgradeInitialized && !_busy)
            RefreshOfflineUpgradeActions();
    }

    private async void OnPrepareOfflineUpgradeAsync(object? sender, RoutedEventArgs e)
    {
        await RunOfflineUpgradeAsync(async (gen, ct) =>
        {
            EnsureReadyForSessionWork(requireSelectedSession: _offlineSessions.Count > 0);
            // A store nobody can enumerate is not an empty device.
            EnsureOfflineCatalogAvailable();
            // A session the tablet already prepared reaches the export step
            // instead of failing the prepare gate; it is never prepared a
            // second time. Export is read-only, so it is the only branch that
            // does not need the write-side boot policy.
            bool exportRecoveryOnly =
                OfflineUpdateUiState.NeedsRecoveryExport(_offlineLastReceipt) && _offlineSavedRecovery == null;
            if (exportRecoveryOnly && _offlineSelectedSession == null)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorSessionNotSelected"));
            if (!exportRecoveryOnly && !_offlineBootPolicySupported)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorBootPolicyRequired"));
            if (!_offlinePreflightPassed)
                throw new InvalidOperationException(string.IsNullOrEmpty(_offlinePreflightError)
                    ? T("Dynamic.OfflineUpdate.ErrorPreflightRequired")
                    : _offlinePreflightError!);
            if (!exportRecoveryOnly &&
                !OfflineUpdateUiState.CanPrepare(_offlineLastReceipt, _offlineSessions.Count > 0, _offlineSelectedSession != null))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorStateNotActionable", _l.Format(LocalizePhase(GetReceiptState(_offlineLastReceipt)))));
            ClearOfflineActionEligibility();
            string recordsRoot = GetPersistentRecordsRoot();
            var session = _offlineSelectedSession;

            if (session == null)
            {
                session = await _offlineTransfer!.CreateSessionAsync(_offlinePackage!, (s, token) =>
                {
                    PackageImporter.SaveOfflineUpdateSession(recordsRoot, s, token);
                    return Task.CompletedTask;
                }, ct);

                _offlineSessions = new[] { session };
                _suppressOfflineSessionSelectionChanged = true;
                OfflineSessionCombo.ItemsSource = _offlineSessions;
                OfflineSessionCombo.SelectedItem = session;
                _suppressOfflineSessionSelectionChanged = false;
                _offlineSelectedSession = session;
                AppendOfflineLog("Dynamic.OfflineUpdate.LogSessionCreated", session.SessionId);
            }

            string sessionRoot = Path.Combine(recordsRoot, session.SessionId);
            Directory.CreateDirectory(sessionRoot);

            if (exportRecoveryOnly)
            {
                // The tablet already prepared this session; resume at the
                // only remaining local step, the verified recovery bundle.
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRecoveryExportResumed", session.SessionId);
                JsonElement preparedReceipt = _offlineLastReceipt ?? throw new InvalidOperationException(
                    T("Dynamic.OfflineUpdate.ErrorStateNotActionable",
                        _l.Format(LocalizePhase(GetReceiptState(_offlineLastReceipt)))));
                await EnsureOfflineRecoveryAsync(session, preparedReceipt, sessionRoot, gen, ct);
            }
            else
            {
                JsonElement prepared = await PrepareOfflineSessionAsync(session, sessionRoot, gen, ct);
                if (GetReceiptState(prepared) == "up_to_date")
                    return;
            }

            await FinishOfflineSessionAsync(session, sessionRoot, ct);
        });
    }

    /// <summary>
    /// Start a replacement session for the selected record whose preparation
    /// failed before any boot write. A separate, explicitly confirmed action:
    /// the failed record and its saved receipt are kept untouched, a fresh
    /// read-only preflight runs first and only the new session is prepared.
    /// </summary>
    private async void OnStartReplacementOfflineSessionAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy || _offlineSsh == null || _offlineTransfer == null || _offlinePackage == null ||
            _offlineSelectedSession == null || !_offlineBootPolicySupported || !_offlineReceiptLive ||
            !OfflineSelectionIsVerifiedFailedPrepare())
            return;

        if (!await MessageDialog.AskAsync(
                this,
                T("Static.OfflineUpdate.Title"),
                T("Dynamic.OfflineUpdate.ConfirmStartReplacementSessionPrompt", _offlineSelectedSession.SessionId),
                T("Dynamic.Mac.Dialog.Yes"),
                T("Dynamic.Mac.Dialog.No")))
            return;

        await RunOfflineUpgradeAsync(async (gen, ct) =>
        {
            EnsureReadyForSessionWork(requireSelectedSession: true);
            EnsureOfflineCatalogAvailable();
            if (!_offlineBootPolicySupported)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorBootPolicyRequired"));
            // Repeated here so the action rests on this exact live receipt,
            // this device and this package even if the panel changed while
            // the confirmation was open.
            if (!_offlineReceiptLive || !OfflineSelectionIsVerifiedFailedPrepare())
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorReplacementNotEligible"));

            var failed = _offlineSelectedSession!;

            // The new attempt never inherits the pass the failed attempt
            // ran under: it re-earns a fresh read-only preflight.
            ClearOfflinePreflightState();
            bool freshPreflightPassed = await RunOfflinePreflightAsync(null, ct);

            // Everything is checked again immediately before the only write.
            EnsureOfflineCatalogAvailable();
            EnsureReadyForSessionWork(requireSelectedSession: true);
            string? selectedSessionId = _offlineSelectedSession?.SessionId;
            bool stillSameFailedPrepare = selectedSessionId != null &&
                string.Equals(selectedSessionId, failed.SessionId, StringComparison.Ordinal) &&
                OfflineSelectionIsVerifiedFailedPrepare();
            if (!OfflineUpdateUiState.CanBeginReplacementSession(freshPreflightPassed,
                    _offlineReceiptLive, selectedSessionId != null, stillSameFailedPrepare))
            {
                // A denied fresh check has already rendered and logged its
                // own rejection; any other refusal is thrown so nothing is
                // created.
                if (!freshPreflightPassed)
                    return;

                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorReplacementNotEligible"));
            }

            ClearOfflineActionEligibility();
            string recordsRoot = GetPersistentRecordsRoot();
            AppendOfflineLog("Dynamic.OfflineUpdate.LogReplacementSessionStarted", failed.SessionId);

            var replacement = await _offlineTransfer!.CreateSessionAsync(_offlinePackage!, (s, token) =>
            {
                PackageImporter.SaveOfflineUpdateSession(recordsRoot, s, token);
                return Task.CompletedTask;
            }, ct);
            KeepOfflineSessionsAndSelect(replacement);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogSessionCreated", replacement.SessionId);

            string sessionRoot = Path.Combine(recordsRoot, replacement.SessionId);
            Directory.CreateDirectory(sessionRoot);
            JsonElement prepared = await PrepareOfflineSessionAsync(replacement, sessionRoot, gen, ct);
            if (GetReceiptState(prepared) == "up_to_date")
                return;

            await FinishOfflineSessionAsync(replacement, sessionRoot, ct);
        });
    }

    /// <summary>
    /// Upload, seal and prepare one session, persist the tablet's receipt
    /// and produce the local recovery bundle execution will acknowledge.
    /// </summary>
    private async Task<JsonElement> PrepareOfflineSessionAsync(
        OfflineUpdateSession session, string sessionRoot, long gen, CancellationToken ct)
    {
        var progress = CreateOfflineProgress(gen);
        JsonElement receipt = await _offlineTransfer!.PrepareAsync(_offlinePackage!, session, progress, ct);
        _offlineReceiptLive = true;
        _offlineLastReceipt = receipt.Clone();
        await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
        UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);

        string state = GetReceiptState(_offlineLastReceipt) ?? string.Empty;
        if (state == "up_to_date")
        {
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateUpToDate");
            AppendOfflineLog("Dynamic.OfflineUpdate.LogUpToDate");
            return _offlineLastReceipt.Value;
        }

        EnsureNoBlockingReceiptFlags(_offlineLastReceipt.Value);
        await EnsureOfflineRecoveryAsync(session, _offlineLastReceipt.Value, sessionRoot, gen, ct);
        return _offlineLastReceipt.Value;
    }

    /// <summary>
    /// Read the tablet's own verdict for the session that was just prepared,
    /// and render it. A read-only status query.
    /// </summary>
    private async Task FinishOfflineSessionAsync(
        OfflineUpdateSession session, string sessionRoot, CancellationToken ct)
    {
        Interlocked.Increment(ref _offlineOperationGeneration);
        JsonElement status = await _offlineTransfer!.QueryStatusAsync(_offlinePackage!, session, ct);
        _offlineReceiptLive = true;
        _offlineLastReceipt = status.Clone();
        await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
        UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
        await ApplyQueriedReceiptState(_offlineLastReceipt.Value, sessionRoot, ct, allowLoadRecovery: true);
    }

    /// <summary>
    /// Add the replacement session to the selector and select it, leaving
    /// every earlier record exactly where it is.
    /// </summary>
    private void KeepOfflineSessionsAndSelect(OfflineUpdateSession replacement)
    {
        var sessions = new List<OfflineUpdateSession>(_offlineSessions.Count + 1);
        foreach (var existing in _offlineSessions)
        {
            if (!string.Equals(existing.SessionId, replacement.SessionId, StringComparison.Ordinal))
                sessions.Add(existing);
        }
        sessions.Add(replacement);

        _suppressOfflineSessionSelectionChanged = true;
        try
        {
            ClearOfflineSelectionState();
            _offlineSessions = sessions;
            OfflineSessionCombo.ItemsSource = _offlineSessions;
            OfflineSessionCombo.SelectedItem = replacement;
            _offlineSelectedSession = replacement;
        }
        finally
        {
            _suppressOfflineSessionSelectionChanged = false;
        }
    }

    private bool OfflineSelectionIsVerifiedFailedPrepare() =>
        OfflineUpdateUiState.IsBoundForReplacement(_offlineLastReceipt, _offlineSelectedSession,
            _offlineConnectedModel, _offlineRecoveryPartUuid, _offlineDescriptorSha256);

    /// <summary>
    /// Refuse to begin a session while the saved records cannot be read.
    /// </summary>
    private void EnsureOfflineCatalogAvailable()
    {
        if (_offlineSavedSessionsUnavailableReason == null)
            return;

        throw new InvalidOperationException(
            T("Dynamic.OfflineUpdate.ErrorSavedSessionsUnavailable", _offlineSavedSessionsUnavailableReason));
    }

    /// <summary>
    /// Produce the verified local recovery bundle for a session the tablet
    /// already prepared, and hold the exact bytes execution returns as its
    /// acknowledgement. It exports only: no prepare, no execute, no slot write.
    /// </summary>
    private async Task<SavedOfflineUpdateRecovery> EnsureOfflineRecoveryAsync(
        OfflineUpdateSession session, JsonElement receipt, string sessionRoot,
        long generation, CancellationToken ct)
    {
        if (_offlineSsh == null || _offlineTransfer == null || string.IsNullOrEmpty(_offlineConnectedModel))
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNotConnected"));
        if (_offlinePackage == null || string.IsNullOrEmpty(_offlineDescriptorSha256))
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorPackageNotValidated"));

        OfflineUpdateRecoveryContext? context = TryExtractRecoveryContext(receipt, _offlineConnectedModel!);
        SavedOfflineUpdateRecovery? existing = null;
        if (context != null)
        {
            var scan = await Task.Run(
                () => OfflineUpdateRecoveryCatalog.Scan(sessionRoot, context, _offlineDescriptorSha256!, ct), ct);
            ReportSkippedOfflineRecoveryBundles(scan.Skipped);
            existing = scan.Recovery;
        }

        if (existing == null)
        {
            existing = await _offlineTransfer.SaveRecoveryAsync(
                _offlinePackage!, session, sessionRoot, CreateOfflineProgress(generation), ct);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogRecoverySaved", existing.DirectoryPath);
        }
        else
        {
            AppendOfflineLog("Dynamic.OfflineUpdate.LogRecoveryReused", existing.DirectoryPath);
        }

        // Execution may only start with the validated acknowledgement that
        // belongs to this transaction; a bundle without it is not evidence.
        if (existing.Acknowledgement is not { Length: > 0 })
            throw new InvalidDataException(T("Dynamic.OfflineUpdate.ErrorRecoveryMissing"));

        _offlineSavedRecovery = existing;
        SetText(OfflineRecoveryPathText, "Dynamic.OfflineUpdate.Value", existing.DirectoryPath);
        return existing;
    }

    private async void OnRefreshOfflineStatusAsync(object? sender, RoutedEventArgs e)
    {
        // A refresh re-establishes readiness from scratch: any earlier pass
        // is dropped before the asynchronous work starts.
        if (_offlinePackage != null && !string.IsNullOrEmpty(_offlineDescriptorSha256))
            ClearOfflinePreflightState();

        await RunOfflineUpgradeAsync(async (gen, ct) =>
        {
            if (_offlineSsh == null || _offlineTransfer == null || string.IsNullOrEmpty(_offlineConnectedModel))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNotConnected"));

            // Refresh retries the local, read-only records scan first when
            // the location was unreadable.
            bool catalogRetried = _offlineSavedSessionsUnavailableReason != null;
            bool catalogRecovered = catalogRetried && RetrySavedOfflineSessionsOnRefresh();
            bool catalogUnavailable = _offlineSavedSessionsUnavailableReason != null;
            if (catalogUnavailable && _offlineSelectedSession != null)
                ReportSavedOfflineSessionIssues();

            bool hasPackage = _offlinePackage != null && !string.IsNullOrEmpty(_offlineDescriptorSha256);
            if (_offlineSelectedSession == null)
            {
                if (_offlineSessions.Count > 0)
                {
                    // The retry above just listed the records; the choice
                    // stays the operator's.
                    if (catalogRecovered)
                        return;

                    throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorSessionNotSelected"));
                }

                // No session exists yet, so the only read-only work left is
                // the preflight that failed after the package was imported.
                if (!hasPackage)
                {
                    if (catalogRetried)
                    {
                        if (catalogUnavailable)
                            ReportSavedOfflineSessionIssues();
                        return;
                    }

                    throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorPackageNotValidated"));
                }

                ClearOfflineActionEligibility();
                if (await RunOfflinePreflightAsync(null, ct))
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreflightPassed");
                if (catalogUnavailable)
                    ReportSavedOfflineSessionIssues();
                return;
            }

            ClearOfflineActionEligibility();
            var session = _offlineSelectedSession!;

            // Read-only. The remote exchange runs first and on its own: the
            // records location is local state and never hides the tablet's
            // own status.
            var receipt = hasPackage
                ? await _offlineTransfer!.QueryStatusAsync(_offlinePackage!, session, ct)
                : await _offlineTransfer!.QuerySessionStatusAsync(session, ct);
            _offlineReceiptLive = true;
            if (GetReceiptState(receipt) != "execute_queued" && GetReceiptState(receipt) != "executing")
                Interlocked.Increment(ref _offlineOperationGeneration);
            _offlineLastReceipt = receipt.Clone();
            await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
            UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);

            string? state = GetReceiptState(_offlineLastReceipt);
            if ((state == "execute_queued" || state == "executing") && hasPackage)
            {
                AppendOfflineLog("Dynamic.OfflineUpdate.LogObservingExecution", session.SessionId);
                var observed = await _offlineTransfer.ObserveExecutionAsync(_offlinePackage!, session, CreateOfflineProgress(gen), ct);
                Interlocked.Increment(ref _offlineOperationGeneration);
                _offlineLastReceipt = observed.Clone();
                await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
                UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
            }

            // Local recovery bookkeeping is best effort here.
            string? recordsRoot = TryGetPersistentRecordsRoot(out string? recordsUnavailableReason);
            string? sessionRoot = recordsRoot == null
                ? null
                : Path.Combine(recordsRoot, session.SessionId);
            if (recordsUnavailableReason != null)
                AppendOfflineLog("Dynamic.OfflineUpdate.LogSavedSessionsUnavailable", recordsUnavailableReason);

            await ApplyQueriedReceiptState(_offlineLastReceipt.Value, sessionRoot, ct, allowLoadRecovery: hasPackage, recordsUnavailableReason: recordsUnavailableReason);

            // The status above stays visible even if this read-only
            // preflight fails.
            string? refreshed = GetReceiptState(_offlineLastReceipt);
            bool preflightable = OfflineUpdateUiState.ShouldRefreshPreflight(refreshed);
            if (hasPackage && preflightable)
                await RunOfflinePreflightAsync(session, ct);
        });
    }

    /// <summary>
    /// Re-read the saved records location from the explicit Refresh action.
    /// Returns true when the store became readable.
    /// </summary>
    private bool RetrySavedOfflineSessionsOnRefresh()
    {
        if (_offlineSavedSessionsUnavailableReason == null)
            return false;

        var sessions = LoadSavedOfflineSessions();
        if (_offlineSavedSessionsUnavailableReason != null)
            return false;

        ApplyFilteredOfflineSessions(sessions, _offlineSelectedSession);
        ReportDamagedOfflineSessionRecords();
        return true;
    }

    /// <summary>
    /// The one read-only preflight exchange, shared by package validation and
    /// the status refresh. It never throws: it records the exact pass or the
    /// actionable rejection and returns whether it passed.
    /// </summary>
    private async Task<bool> RunOfflinePreflightAsync(OfflineUpdateSession? session, CancellationToken ct)
    {
        if (_offlineSsh == null || _offlineTransfer == null || _offlinePackage == null)
            return false;

        var deviceInfo = _offlineSsh.DeviceInfo;
        if (!OfflineUpdateUiState.IsUpdaterVersionAtLeast(deviceInfo, "0.8.0"))
        {
            MarkOfflinePreflightFailed(T("Dynamic.OfflineUpdate.ErrorPreflightUnsupportedUpdater",
                GetJsonString(deviceInfo, "updaterVersion") ?? "?"));
            return false;
        }

        try
        {
            var preflight = await _offlineTransfer.PreflightAsync(_offlinePackage, session, ct);
            if (!OfflineUpdateUiState.PreflightPassed(preflight))
            {
                MarkOfflinePreflightFailed(T("Dynamic.OfflineUpdate.ErrorPreflightInvalidResponse",
                    OfflineUpdateUiState.PreflightPhase(preflight) ?? "?"));
                return false;
            }

            _offlinePreflightPassed = true;
            _offlinePreflightError = null;
            AppendOfflineLog("Dynamic.OfflineUpdate.LogPreflightPassed",
                OfflineUpdateUiState.PreflightDeployment(preflight) ?? "?",
                OfflineUpdateUiState.PreflightPhase(preflight) ?? "?");
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or TimeoutException or ObjectDisposedException or OfflineUpdateTransferException)
        {
            // The device-side code (for example operation_failed) names the
            // rejected check; keep it next to its cause.
            string detail = ex is OfflineUpdateRemoteException remote
                ? $"{remote.Code}: {remote.Message}"
                : ex.Message;
            MarkOfflinePreflightFailed(T("Dynamic.OfflineUpdate.ErrorPreflightFailed", detail));
            return false;
        }
    }

    private async void OnExecuteOfflineUpgradeAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy || _offlineSsh == null || _offlinePackage == null || _offlineSelectedSession == null ||
            !_offlineBootPolicySupported ||
            !OfflineUpdateUiState.CanExecute(_offlineLastReceipt, _offlineSavedRecovery != null, _offlinePreflightPassed) || OfflineConfirmCheck.IsChecked != true)
            return;

        UiMessage modelName = LocalizeModelName(_offlineConnectedModel ?? string.Empty);
        string msg = T("Dynamic.OfflineUpdate.ConfirmExecutePrompt", modelName, _offlinePackage.Descriptor.Version, _offlinePackage.Descriptor.ReleaseId);
        if (!await MessageDialog.AskAsync(this, T("Static.OfflineUpdate.Title"), msg, T("Dynamic.Mac.Dialog.Yes"), T("Dynamic.Mac.Dialog.No")))
            return;

        await RunOfflineUpgradeAsync(async (gen, ct) =>
        {
            EnsureReadyForSessionWork(requireSelectedSession: true);
            if (!_offlineBootPolicySupported)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorBootPolicyRequired"));
            if (!_offlinePreflightPassed)
                throw new InvalidOperationException(string.IsNullOrEmpty(_offlinePreflightError)
                    ? T("Dynamic.OfflineUpdate.ErrorPreflightRequired")
                    : _offlinePreflightError!);
            if (!OfflineUpdateUiState.CanExecute(_offlineLastReceipt, _offlineSavedRecovery != null, _offlinePreflightPassed))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorRecoveryMissing"));
            if (_offlineSavedRecovery == null)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorRecoveryMissing"));

            var session = _offlineSelectedSession!;
            string recordsRoot = GetPersistentRecordsRoot();
            string sessionRoot = Path.Combine(recordsRoot, session.SessionId);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogExecuting", session.SessionId);

            var receipt = await _offlineTransfer!.ExecuteAsync(_offlinePackage!, session, _offlineSavedRecovery, CreateOfflineProgress(gen), ct);
            Interlocked.Increment(ref _offlineOperationGeneration);
            _offlineReceiptLive = true;
            _offlineLastReceipt = receipt.Clone();
            await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
            UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
            await ApplyQueriedReceiptState(_offlineLastReceipt.Value, sessionRoot, ct, allowLoadRecovery: false);
        });
    }

    private void OnStopWaitingOfflineUpgrade(object? sender, RoutedEventArgs e)
    {
        if (!_busy || !_offlineUpgradeActive)
            return;
        _offlineCts?.Cancel();
    }

    /// <summary>
    /// The WPF <c>OnOfflineUpgradeClosing</c>, called first by the window's single close handler. While the page
    /// holds a connection, an imported package or a running exchange, closing cancels the exchange, waits for it,
    /// disconnects and releases the package (saved session records are kept), then closes the window. Returns true
    /// when this page took over the close.
    /// </summary>
    private async Task<bool> OnOfflineUpgradeClosingAsync(WindowClosingEventArgs e)
    {
        if (_offlineUpgradeCloseInProgress)
        {
            e.Cancel = true;
            return true;
        }

        if (!HasOfflineUpgradeState)
            return false;

        e.Cancel = true;
        _offlineUpgradeCloseInProgress = true;
        // 先在等待清理期间禁用全部按钮，再开始取消 / 断开流程。
        RefreshActions();
        try
        {
            if (_offlineUpgradeActive)
            {
                _offlineCts?.Cancel();
                if (_offlineWorkCompletion != null)
                    await _offlineWorkCompletion.Task;
            }

            await DisconnectAndCleanupStageAsync();
        }
        catch (Exception ex)
        {
            SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", ex.Message);
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateFailed", ex.Message);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogError", ex.Message);
            return true;
        }
        finally
        {
            _offlineUpgradeCloseInProgress = false;
            RefreshActions();
        }

        _closeConfirmed = true;
        DisposeGlobalRecoveryOnClose();
        DisposeInternalInstall();
        Dispatcher.UIThread.Post(Close);
        return true;
    }

    private async Task ApplyQueriedReceiptState(
        JsonElement receipt, string? sessionRoot, CancellationToken ct,
        bool allowLoadRecovery, string? recordsUnavailableReason = null)
    {
        string state = GetReceiptState(receipt) ?? "unknown";
        if (state == "failed")
        {
            // The tablet's own failure result is kept as the receipt so the
            // operator can read it; only a separately confirmed replacement
            // begin may follow.
            string detail = GetJsonString(receipt, "error") ??
                GetJsonString(receipt, "message") ?? string.Empty;
            ClearOfflineActionEligibility();
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateFailed", detail);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogError", detail);
            return;
        }

        EnsureNoBlockingReceiptFlags(receipt);

        switch (state)
        {
            case "prepared":
                if (allowLoadRecovery && _offlineSavedRecovery == null && sessionRoot != null && Directory.Exists(sessionRoot))
                {
                    // Only a receipt whose export metadata agrees with the
                    // Core precedence may name the local recovery bundle.
                    var ctx = TryExtractRecoveryContext(receipt, _offlineConnectedModel!);
                    if (ctx != null)
                    {
                        var scan = await Task.Run(
                            () => OfflineUpdateRecoveryCatalog.Scan(sessionRoot, ctx, _offlineDescriptorSha256!, ct), ct);
                        ReportSkippedOfflineRecoveryBundles(scan.Skipped);
                        if (scan.Recovery != null)
                        {
                            _offlineSavedRecovery = scan.Recovery;
                            SetText(OfflineRecoveryPathText, "Dynamic.OfflineUpdate.Value", scan.Recovery.DirectoryPath);
                        }
                    }
                    else
                    {
                        AppendOfflineLog("Dynamic.OfflineUpdate.LogRecoveryIgnored",
                            T("Dynamic.OfflineUpdate.ErrorInvalidRecoveryContext"));
                    }
                }
                if (_offlineSavedRecovery != null)
                {
                    if (_offlineBootPolicySupported)
                    {
                        SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreparedReady");
                        AppendOfflineLog("Dynamic.OfflineUpdate.LogPreparedReady");
                    }
                    else
                    {
                        // The read-only export produced the bundle, but this
                        // helper never declared the no-slot-control policy.
                        SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateBootPolicyReadOnly");
                    }
                }
                else if (allowLoadRecovery && recordsUnavailableReason != null)
                {
                    ClearOfflineActionEligibility();
                    SetText(OfflineStateText,
                        "Dynamic.OfflineUpdate.StateSavedSessionsUnavailable", recordsUnavailableReason);
                }
                else if (string.IsNullOrEmpty(_offlineDescriptorSha256))
                {
                    ClearOfflineActionEligibility();
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreparedNeedsPackage");
                }
                else
                {
                    ClearOfflineActionEligibility();
                    SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreparedMissingRecovery");
                }
                break;

            case "up_to_date":
                ClearOfflineActionEligibility();
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateUpToDate");
                break;

            case "awaiting_reboot":
                ClearOfflineActionEligibility();
                ShowOfflineCompletion(receipt, log: true);
                break;

            case "uploading":
            case "uploaded":
            case "prepare_queued":
            case "preparing":
            case "execute_queued":
            case "executing":
                ClearOfflineActionEligibility();
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePhase", LocalizePhase(state));
                break;

            default:
                ClearOfflineActionEligibility();
                _offlineLastReceipt = null;
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorStateNotActionable", LocalizePhase(state)));
        }
    }

    /// <summary>
    /// Render the durable tablet verdict carried by the receipt's
    /// <c>completion</c> block; never upgraded to "confirmed" on its own.
    /// </summary>
    private void ShowOfflineCompletion(JsonElement receipt, bool log)
    {
        JsonElement? completionValue = OfflineUpdateUiState.Completion(receipt);
        JsonElement completion = completionValue ?? default;
        string? completionState = OfflineUpdateUiState.CompletionState(receipt);
        string? restartState = OfflineUpdateUiState.RestartState(receipt);

        string key;
        string? detail = null;
        switch (completionState)
        {
            case null:
                key = "Dynamic.OfflineUpdate.StateAwaitingReboot";
                break;
            case "awaiting_reboot":
                key = restartState switch
                {
                    "dispatched" => "Dynamic.OfflineUpdate.StateRestartDispatched",
                    "dispatching" => "Dynamic.OfflineUpdate.StateRestartPending",
                    "uncertain" => "Dynamic.OfflineUpdate.StateRestartUncertain",
                    _ => "Dynamic.OfflineUpdate.StateCompletionAwaitingReboot"
                };
                break;
            case "awaiting_confirmation":
                key = "Dynamic.OfflineUpdate.StateCompletionAwaitingConfirmation";
                break;
            case "finalizing":
                key = "Dynamic.OfflineUpdate.StateCompletionFinalizing";
                break;
            case "confirmed":
                key = "Dynamic.OfflineUpdate.StateCompletionConfirmed";
                break;
            case "rolled_back":
                key = "Dynamic.OfflineUpdate.StateCompletionRolledBack";
                break;
            case "failed":
                key = "Dynamic.OfflineUpdate.StateCompletionFailed";
                detail = GetJsonString(completion, "error") ?? GetJsonString(completion, "reason");
                break;
            case "mismatch":
                key = "Dynamic.OfflineUpdate.StateCompletionMismatch";
                detail = GetJsonString(completion, "error");
                break;
            default:
                key = "Dynamic.OfflineUpdate.StateCompletionUnverified";
                detail = GetJsonString(completion, "error") ?? GetJsonString(completion, "reason");
                break;
        }

        SetText(OfflineStateText, key, detail ?? string.Empty);
        if (!log)
        {
            _offlineLastCompletionState = null;
            return;
        }

        string signature = key + "|" + (detail ?? string.Empty);
        if (!string.Equals(_offlineLastCompletionState, signature, StringComparison.Ordinal))
        {
            _offlineLastCompletionState = signature;
            AppendOfflineLog(key, detail ?? string.Empty);
        }
    }

    private void ShowPersistedOfflineResult(JsonElement receipt)
    {
        // A receipt read from disk is informational only: it never enables
        // an action that needs live device evidence.
        _offlineReceiptLive = false;
        string? state = GetReceiptState(receipt);
        if (OfflineUpdateUiState.Completion(receipt) != null || state == "awaiting_reboot")
        {
            ShowOfflineCompletion(receipt, log: false);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogPersistedNeedsRefresh");
            return;
        }

        _offlineLastCompletionState = null;
        switch (state)
        {
            case "prepared":
                ClearOfflineActionEligibility();
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePreparedMissingRecovery");
                break;
            case "up_to_date":
                ClearOfflineActionEligibility();
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateUpToDate");
                break;
            case "failed":
                ClearOfflineActionEligibility();
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateFailed",
                    GetJsonString(receipt, "error") ?? string.Empty);
                break;
            default:
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StatePersistedResult",
                    LocalizePhase(state));
                break;
        }
        AppendOfflineLog("Dynamic.OfflineUpdate.LogPersistedResult", LocalizePhase(state));
    }

    private static JsonElement? TryLoadPersistedOfflineReceipt(OfflineUpdateSession session)
    {
        try
        {
            string path = Path.Combine(GetPersistentRecordsRoot(), session.SessionId, "last-receipt.json");
            var info = new FileInfo(path);
            if (!info.Exists || info.LinkTarget != null || info.Length <= 0 || info.Length > 8L * 1024 * 1024)
                return null;
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !string.Equals(GetJsonString(root, "sessionId"), session.SessionId, StringComparison.Ordinal) ||
                string.IsNullOrEmpty(GetJsonString(root, "state")))
                return null;
            return root.Clone();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Rebuild the session selector from the device-bound records on
    /// connect, before any package is imported.
    /// </summary>
    private void LoadSavedOfflineSessionsForDevice()
    {
        _offlineSessions = LoadSavedOfflineSessions();
        ClearOfflineSelectionState();
        _suppressOfflineSessionSelectionChanged = true;
        OfflineSessionCombo.ItemsSource = _offlineSessions;
        OfflineSessionCombo.SelectedIndex = _offlineSessions.Count == 1 ? 0 : -1;
        _suppressOfflineSessionSelectionChanged = false;
        if (_offlineSessions.Count == 0)
        {
            // No readable session is left, so the damaged record or the
            // unavailable location is the only thing worth showing.
            ReportSavedOfflineSessionIssues();
            return;
        }

        AppendOfflineLog("Dynamic.OfflineUpdate.LogSavedSessionsFound", _offlineSessions.Count);
        if (_offlineSessions.Count > 1)
        {
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateMultipleSessionsFound", _offlineSessions.Count);
        }
        else
        {
            _offlineSelectedSession = _offlineSessions[0];
            _offlineLastReceipt = TryLoadPersistedOfflineReceipt(_offlineSelectedSession);
            if (_offlineLastReceipt.HasValue)
            {
                UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
                ShowPersistedOfflineResult(_offlineLastReceipt.Value);
            }
            else
            {
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateSessionSelected", _offlineSelectedSession.SessionId);
            }
        }

        // Intact and damaged records together: the damage is reported after
        // the intact sessions were listed and selected.
        ReportDamagedOfflineSessionRecords();
    }

    /// <summary>
    /// The saved sessions of this exact device, read one record at a time.
    /// An unreadable location is remembered separately from a device without
    /// sessions; a readable scan clears that reason again.
    /// </summary>
    private IReadOnlyList<OfflineUpdateSession> LoadSavedOfflineSessions()
    {
        try
        {
            OfflineSessionRecordScan scan = OfflineUpdateSessionCatalog.Load(
                GetPersistentRecordsRoot(), _offlineConnectedModel, _offlineRecoveryPartUuid, _offlineDescriptorSha256);
            _offlineSavedSessionsUnavailableReason = scan.UnavailableReason;
            _offlineDamagedSessionRecords = scan.Damaged;
            return scan.Sessions;
        }
        catch (Exception ex)
        {
            // The store is unavailable, not empty. Nothing on disk is touched.
            _offlineSavedSessionsUnavailableReason = ex.Message;
            _offlineDamagedSessionRecords = Array.Empty<OfflineDamagedSessionRecord>();
            return Array.Empty<OfflineUpdateSession>();
        }
    }

    /// <summary>
    /// Report why no session could be listed. An unavailable records location
    /// takes precedence over per-record damage.
    /// </summary>
    private void ReportSavedOfflineSessionIssues()
    {
        if (_offlineSavedSessionsUnavailableReason != null)
        {
            SetText(OfflineStateText,
                "Dynamic.OfflineUpdate.StateSavedSessionsUnavailable", _offlineSavedSessionsUnavailableReason);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogSavedSessionsUnavailable", _offlineSavedSessionsUnavailableReason);
            return;
        }

        ReportDamagedOfflineSessionRecords();
    }

    /// <summary>
    /// Name every damaged record, so a record that cannot be read is visible
    /// instead of silently missing from the session list.
    /// </summary>
    private void ReportDamagedOfflineSessionRecords()
    {
        if (_offlineDamagedSessionRecords.Count == 0)
            return;

        foreach (var damaged in _offlineDamagedSessionRecords)
            AppendOfflineLog("Dynamic.OfflineUpdate.LogDamagedSessionRecord", damaged.RecordName, damaged.Reason);

        var first = _offlineDamagedSessionRecords[0];
        SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateDamagedSessionRecord",
            _offlineDamagedSessionRecords.Count, first.RecordName, first.Reason);
    }

    private async void OnRestartToVerifyOfflineUpgradeAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy || _offlineSsh == null || _offlineTransfer == null || _offlineSelectedSession == null ||
            !_offlineBootPolicySupported || !_offlineReceiptLive ||
            !OfflineUpdateUiState.CanRestartToVerify(_offlineLastReceipt))
            return;

        if (!await MessageDialog.AskAsync(
                this,
                T("Static.OfflineUpdate.Title"),
                T("Dynamic.OfflineUpdate.ConfirmRestartToVerifyPrompt"),
                T("Dynamic.Mac.Dialog.Yes"),
                T("Dynamic.Mac.Dialog.No")))
            return;

        await RunOfflineUpgradeAsync(async (_, ct) =>
        {
            // The restart only needs the connected session: it neither
            // re-uploads nor re-validates the package.
            if (_offlineSsh == null || _offlineTransfer == null ||
                string.IsNullOrEmpty(_offlineConnectedModel))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNotConnected"));
            if (_offlineSelectedSession == null)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorSessionNotSelected"));
            if (!_offlineBootPolicySupported)
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorBootPolicyRequired"));
            if (!_offlineReceiptLive || !OfflineUpdateUiState.CanRestartToVerify(_offlineLastReceipt))
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorRestartNotEligible"));

            var session = _offlineSelectedSession!;
            AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartRequested", session.SessionId);

            JsonElement result;
            try
            {
                result = await _offlineTransfer!.RestartToVerifyAsync(session, ct);
            }
            catch (OfflineUpdateRemoteException ex)
            {
                // The tablet answered this request and refused it; the
                // transport stays healthy and no restart is retried
                // automatically.
                _offlineLastReceipt = null;
                _offlineReceiptLive = false;
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartRejected", ex.Code, ex.Message);
                await TryRefreshOfflineStatusAfterRestartRejectionAsync(session, ct);
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateRestartRejected",
                    ex.Code, ex.Message);
                return;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or ObjectDisposedException)
            {
                // The request may have reached the tablet. This is pending or
                // unknown, never a failed upgrade, and never retried
                // automatically: the next read-only refresh decides.
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateRestartUnknown");
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartUnknown", ex.Message);
                _offlineReceiptLive = false;
                await DropOfflineConnectionKeepPackageAsync();
                return;
            }

            string restartState = result.TryGetProperty("restart", out JsonElement restart) &&
                restart.ValueKind == JsonValueKind.Object
                ? GetJsonString(restart, "state") ?? string.Empty
                : string.Empty;
            if (restartState == "dispatched")
            {
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateRestartDispatched");
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartDispatched");
            }
            else if (restartState == "dispatching")
            {
                // A previous request from another client is still inside the
                // reboot window; it is pending, not a new request.
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateRestartPending");
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartPending");
            }
            else
            {
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateRestartUncertain");
                AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartUnknown", string.Empty);
            }
            _offlineReceiptLive = false;
            await DropOfflineConnectionKeepPackageAsync();
        });
    }

    /// <summary>
    /// Read-only follow-up after the tablet explicitly refused a restart, on
    /// the same connection; it never sends the restart again.
    /// </summary>
    private async Task TryRefreshOfflineStatusAfterRestartRejectionAsync(
        OfflineUpdateSession session, CancellationToken ct)
    {
        var transfer = _offlineTransfer;
        if (transfer == null)
            return;

        try
        {
            var receipt = await transfer.QuerySessionStatusAsync(session, ct);
            _offlineLastReceipt = receipt.Clone();
            _offlineReceiptLive = true;
            await TryPersistReceiptAsync(session, _offlineLastReceipt.Value);
            UpdateDetailsWithReceipt(_offlineLastReceipt.Value, null);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or TimeoutException or ObjectDisposedException or OfflineUpdateTransferException)
        {
            _offlineLastReceipt = null;
            _offlineReceiptLive = false;
            SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", ex.Message);
            AppendOfflineLog("Dynamic.OfflineUpdate.LogRestartStatusRefreshFailed", ex.Message);
        }
    }

    /// <summary>
    /// The cancel hit a request that had already been sent, so the stream
    /// can no longer be trusted. Release only the transport.
    /// </summary>
    private async Task ReleasePoisonedOfflineConnectionAsync()
    {
        AppendOfflineLog("Dynamic.OfflineUpdate.LogPoisonedConnectionReleased");
        try
        {
            await DropOfflineConnectionKeepPackageAsync();
        }
        catch (Exception ex)
        {
            // Releasing a poisoned transport must not turn the user's
            // cancel into a failed operation.
            _offlineSsh = null;
            _offlineTransfer = null;
            AppendOfflineLog("Dynamic.OfflineUpdate.LogError", ex.Message);
        }
    }

    private async Task DropOfflineConnectionKeepPackageAsync()
    {
        var ssh = _offlineSsh;
        _offlineSsh = null;
        _offlineTransfer = null;
        _offlineConnectedModel = null;
        _offlineActualSlot = null;
        _offlineRecoveryPartUuid = null;
        _offlineBootPolicySupported = false;
        _offlineReceiptLive = false;
        ClearOfflinePreflightState();
        ClearOfflinePairing();
        ClearOfflinePasswordEntry();
        SetText(OfflineDeviceText, "Static.OfflineUpdate.DevicePending");
        if (ssh != null)
            await ssh.DisposeAsync();
        AppendOfflineLog("Dynamic.OfflineUpdate.LogDisconnected");
    }

    /// <summary>
    /// Report every bundle the scan refused. A refused bundle stays on disk
    /// untouched.
    /// </summary>
    private void ReportSkippedOfflineRecoveryBundles(IReadOnlyList<OfflineSkippedRecoveryBundle> skipped)
    {
        foreach (var bundle in skipped)
            AppendOfflineLog("Dynamic.OfflineUpdate.LogRecoveryIgnored", bundle.Reason);
    }

    /// <summary>
    /// The recovery context follows the Core precedence exactly; a receipt the
    /// Core would reject yields no context.
    /// </summary>
    private static OfflineUpdateRecoveryContext? TryExtractRecoveryContext(JsonElement receipt, string model) =>
        OfflineUpdateUiState.TryGetRecoveryMetadata(receipt,
            out string? transactionId, out string? planSha256, out string? recoveryManifestSha256)
            ? new OfflineUpdateRecoveryContext(transactionId!, model, planSha256!, recoveryManifestSha256!)
            : null;

    private void EnsureReadyForSessionWork(bool requireSelectedSession)
    {
        if (_offlineSsh == null || _offlineTransfer == null || string.IsNullOrEmpty(_offlineConnectedModel))
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorNotConnected"));
        if (_offlinePackage == null || string.IsNullOrEmpty(_offlineDescriptorSha256))
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorPackageNotValidated"));
        if (requireSelectedSession && _offlineSelectedSession == null)
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorSessionNotSelected"));
    }

    private void EnsureNoBlockingReceiptFlags(JsonElement receipt)
    {
        if (GetJsonBool(receipt, "jobInterrupted") || GetJsonBool(receipt, "attentionRequired") || GetReceiptState(receipt) == "failed")
        {
            string reason = GetJsonString(receipt, "message") ?? GetJsonString(receipt, "error") ?? _l.Format(LocalizePhase(GetReceiptState(receipt)));
            throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorReceiptFlagBlocked", reason));
        }
    }

    private static string? GetReceiptState(JsonElement? receipt) =>
        OfflineUpdateUiState.State(receipt);

    private static string? GetJsonString(JsonElement el, string prop)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(prop, out JsonElement val) && val.ValueKind == JsonValueKind.String)
            return val.GetString();
        return null;
    }

    private static bool GetJsonBool(JsonElement el, string prop)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(prop, out JsonElement val) && (val.ValueKind == JsonValueKind.True || val.ValueKind == JsonValueKind.False))
            return val.GetBoolean();
        return false;
    }

    private static UiMessage LocalizeModelName(string model) => model.ToUpperInvariant() switch
    {
        "TB322FC" => M("Static.ModelName.Tb322fc"),
        "TB323FU" => M("Static.ModelName.Tb323fu"),
        "TB710FU" => M("Static.ModelName.Tb710fu"),
        _ => M("Dynamic.OfflineUpdate.Value", string.IsNullOrWhiteSpace(model) ? "?" : model)
    };

    private static string GetThreePartInstallerVersion()
    {
        Version? v = Assembly.GetExecutingAssembly().GetName().Version;
        if (v == null)
            return "1.0.0";
        return $"{Math.Max(0, v.Major)}.{Math.Max(0, v.Minor)}.{Math.Max(0, v.Build)}";
    }

    private static readonly JsonSerializerOptions OfflineJsonIndented = new() { WriteIndented = true };

    private static string FormatJson(JsonElement el)
    {
        return JsonSerializer.Serialize(el, OfflineJsonIndented);
    }

    private void UpdateDetailsWithReceipt(JsonElement receipt, string? error)
    {
        string json = FormatJson(receipt);
        SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", string.IsNullOrWhiteSpace(error) ? json : $"{error}{Environment.NewLine}{Environment.NewLine}{json}");
    }

    private async Task TryPersistReceiptAsync(OfflineUpdateSession? session, JsonElement receipt)
    {
        // A per-session record only ever holds that exact session's own
        // receipt.
        if (session == null || !OfflineUpdateUiState.BelongsToSession(receipt, session))
            return;
        try
        {
            string recordsRoot = GetPersistentRecordsRoot();
            string sessionDir = Path.Combine(recordsRoot, session.SessionId);
            Directory.CreateDirectory(sessionDir);
            string finalPath = Path.Combine(sessionDir, "last-receipt.json");
            string tempPath = Path.Combine(sessionDir, $"last-receipt.{Guid.NewGuid():N}.tmp");
            await File.WriteAllTextAsync(tempPath, FormatJson(receipt));
            File.Move(tempPath, finalPath, overwrite: true);
        }
        catch (Exception ex)
        {
            AppendOfflineLog("Dynamic.OfflineUpdate.LogError", ex.Message);
        }
    }

    /// <summary>
    /// Preserve a receipt the tablet returned for a session other than the
    /// selected record, under a fixed local name; it is never read back as
    /// the selected session's result.
    /// </summary>
    private async Task TryPersistUnmatchedReceiptAsync(JsonElement receipt)
    {
        try
        {
            string recordsRoot = GetPersistentRecordsRoot();
            string finalPath = Path.Combine(recordsRoot, "unmatched-receipt.json");
            string tempPath = Path.Combine(recordsRoot, $"unmatched-receipt.{Guid.NewGuid():N}.tmp");
            await File.WriteAllTextAsync(tempPath, FormatJson(receipt));
            File.Move(tempPath, finalPath, overwrite: true);
        }
        catch (Exception ex)
        {
            AppendOfflineLog("Dynamic.OfflineUpdate.LogError", ex.Message);
        }
    }
}
