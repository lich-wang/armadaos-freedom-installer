using System.Globalization;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using FreedomInstaller.App;
using FreedomInstaller.Core;

namespace FreedomInstaller.Mac;

/// <summary>
/// The connection half of the offline upgrade page: the port of the WPF <c>MainWindow.OfflinePairing.cs</c>
/// (USB key pairing, the key and password routes, adopting the authenticated transport, the host-key prompt).
/// </summary>
public partial class MainWindow
{
    private OfflineUpdateSshIdentity? _offlinePairingIdentity;
    private OfflineUpdateSshHostCandidate? _offlinePairingCandidate;

    /// <summary>
    /// Which route produced the authenticated transport that
    /// <see cref="FinishOfflineConnectionAsync"/> is about to adopt. Only the
    /// key route may still offer the managed password route as its install
    /// fallback.
    /// </summary>
    private enum OfflineConnectRoute
    {
        Key,
        PasswordWithBootstrap,
        PasswordWithoutBootstrap
    }

    /// <summary>The SSH key the page enrols, kept beside the trusted host keys under the Mac cache root.</summary>
    private static string OfflineConnectionsDirectory =>
        Path.Combine(MacCacheRoot, "connections", "offline-upgrade");

    private void ClearOfflinePairing()
    {
        _offlinePairingIdentity = null;
        _offlinePairingCandidate = null;
        if (!_offlineUpgradeInitialized)
            return;
        OfflinePairingPanel.IsVisible = false;
        OfflinePairingCommandBox.Text = string.Empty;
        OfflinePairingReceiptBox.Text = string.Empty;
        SetText(OfflinePairingHostText, "Dynamic.OfflineUpdate.Value", "");
    }

    private void OnOfflinePairingReceiptChanged(object? sender, TextChangedEventArgs e) =>
        RefreshOfflineUpgradeActions();

    /// <summary>
    /// The USB SSH-key route with no manual key files: discover the exact USB
    /// endpoint, then reuse the existing one-time public-key pairing flow.
    /// </summary>
    private async Task BeginOfflineUsbKeyEnrollmentAsync(CancellationToken ct)
    {
        ClearOfflinePairing();

        // Host-key discovery runs ssh-keyscan (on macOS the system /usr/bin one), so it belongs only to the key flow.
        var candidate = await OfflineUpdateSshEnrollment.DiscoverUsbHostAsync(_runner, token: ct);

        // Existing one-time public-key pairing stays available unchanged.
        var identity = await OfflineUpdateSshIdentityStore.EnsureAsync(OfflineConnectionsDirectory, _runner, token: ct);
        var keyOptions = OfflineUpdateSshTrustStore.TryLoadUsbHost(candidate, identity);
        if (keyOptions == null)
        {
            _offlinePairingCandidate = candidate;
            _offlinePairingIdentity = identity;
            OfflinePairingPanel.IsVisible = true;
            OfflinePairingCommandBox.Text =
                OfflineUpdateSshEnrollment.BuildAuthorizationCommand(identity.PublicKey.PublicKey);
            SetText(OfflinePairingHostText, "Dynamic.OfflineUpdate.PairingFingerprints",
                candidate.HostKey.Fingerprint, identity.PublicKey.Fingerprint);
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.PairingNeeded");
            AppendOfflineLog("Dynamic.OfflineUpdate.PairingNeeded");
            RefreshOfflineUpgradeActions();
            return;
        }

        await ConnectOfflineOptionsAsync(keyOptions, ct);
    }

    private async void OnConfirmOfflinePairingAsync(object? sender, RoutedEventArgs e)
    {
        if (_busy || _offlineSsh != null || _offlinePairingCandidate == null || _offlinePairingIdentity == null)
            return;
        string receipt = OfflinePairingReceiptBox.Text ?? string.Empty;
        if (string.IsNullOrWhiteSpace(receipt))
            return;
        var capturedCandidate = _offlinePairingCandidate;
        var capturedIdentity = _offlinePairingIdentity;
        await RunOfflineUpgradeAsync(async (_, ct) =>
        {
            var candidate = await OfflineUpdateSshEnrollment.DiscoverUsbHostAsync(_runner, token: ct);
            var identity = await OfflineUpdateSshIdentityStore.EnsureAsync(OfflineConnectionsDirectory, _runner, token: ct);
            if (candidate.HostKey.PublicKey != capturedCandidate.HostKey.PublicKey ||
                identity.PublicKey.PublicKey != capturedIdentity.PublicKey.PublicKey)
            {
                ClearOfflinePairing();
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.PairingChanged"));
            }
            ct.ThrowIfCancellationRequested();
            var options = OfflineUpdateSshTrustStore.TrustUsbHost(candidate, identity, receipt);
            await ConnectOfflineOptionsAsync(options, ct);
        });

        FocusOfflinePasswordIfPending();
    }

    private async void OnCopyOfflinePairingCommand(object? sender, RoutedEventArgs e)
    {
        if (_offlinePairingCandidate == null)
            return;
        try
        {
            if (Clipboard is not { } clipboard)
                throw new InvalidOperationException("Clipboard unavailable.");
            await clipboard.SetTextAsync(OfflinePairingCommandBox.Text ?? string.Empty);
            AppendOfflineLog("Dynamic.OfflineUpdate.PairingCopied");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            await MessageDialog.ShowAsync(this, T("Static.OfflineUpdate.Title"),
                T("Dynamic.OfflineUpdate.PairingCopyFailed", ex.Message), T("Dynamic.Mac.Dialog.Ok"));
        }
    }

    private async Task ConnectOfflineOptionsAsync(OfflineUpdateSshOptions opts, CancellationToken ct)
    {
        AppendOfflineLog("Dynamic.OfflineUpdate.LogConnecting", opts.Host, opts.Port);
        var conn = await OfflineUpdateSshConnection.ConnectAsync(opts, null, ct);
        await FinishOfflineConnectionAsync(conn, OfflineConnectRoute.Key, ct);
    }

    private async Task ConnectOfflinePasswordAsync(OfflineUpdateSshPasswordOptions options, CancellationToken ct)
    {
        AppendOfflineLog("Dynamic.OfflineUpdate.LogConnecting", options.Host, options.Port);

        // The bootstrap assistant is build-supplied; a normal build omits it,
        // so the finish hook has to distinguish that from a real install attempt.
        bool bootstrapAttempted = false;
        if (OfflineBootstrapAssets.TryCreate(
                new Progress<OfflineUpdateBootstrapProgress>(p =>
                {
                    if (_offlineWindowClosed)
                        return;
                    string key = p.Phase switch
                    {
                        OfflineUpdateBootstrapCoordinator.ProbingPhase => "Dynamic.OfflineUpdate.BootstrapProbing",
                        OfflineUpdateBootstrapCoordinator.DeployingPhase => "Dynamic.OfflineUpdate.BootstrapDeploying",
                        OfflineUpdateBootstrapCoordinator.VerifyingPhase => "Dynamic.OfflineUpdate.BootstrapVerifying",
                        _ => "Dynamic.OfflineUpdate.BootstrapReady",
                    };
                    if (p.Phase != OfflineUpdateBootstrapCoordinator.ReadyPhase)
                        SetText(OfflineStateText, key);
                    AppendOfflineLog(key);
                }),
                useSudoForInstall: !string.Equals(options.UserName, "root", StringComparison.Ordinal))
            is { } bootstrap)
        {
            bootstrapAttempted = true;
            options.PrepareSessionAsync = (session, token) => bootstrap.EnsureAsync(session, token);
        }

        IOfflineUpdateConnection conn;
        try
        {
            conn = await OfflineUpdateSshManagedConnection.ConnectAsync(options, null, ct);
        }
        catch (OfflineUpdateSshManagedException ex)
        {
            throw new InvalidOperationException(T(OfflineManagedFailureKey(ex.Reason), ex.Message), ex);
        }
        finally
        {
            // Authenticated or not, this attempt no longer needs the secret.
            options.ClearPassword();
        }

        await FinishOfflineConnectionAsync(conn,
            bootstrapAttempted
                ? OfflineConnectRoute.PasswordWithBootstrap
                : OfflineConnectRoute.PasswordWithoutBootstrap,
            ct);
    }

    /// <summary>
    /// The single point where an authenticated transport becomes the page's
    /// connection, shared by the key route and the password route. A device
    /// that does not advertise the preflight-session capability is refused
    /// here; one that advertises it but not the no-slot-control boot policy
    /// still connects read-only.
    /// </summary>
    private async Task FinishOfflineConnectionAsync(
        IOfflineUpdateConnection conn, OfflineConnectRoute route, CancellationToken ct)
    {
        if (!OfflineUpdateUiState.SupportsPreflightSession(conn.DeviceInfo))
        {
            // This transport was never adopted by the page, so releasing it
            // here is the only disposal on this path.
            await conn.DisposeAsync();
            ClearOfflinePairing();
            if (route == OfflineConnectRoute.Key)
            {
                // The public-key route cannot deploy or verify the service
                // itself, so its one explicit fallback stays the managed
                // password route.
                await ShowOfflineUpdaterInstallPromptAsync();
            }
            else
            {
                // The managed password route was already tried; asking for
                // the same password again cannot help.
                await ShowOfflineUpdaterComponentsGuidanceAsync(
                    route == OfflineConnectRoute.PasswordWithBootstrap);
            }
            return;
        }

        try
        {
            string model = GetJsonString(conn.DeviceInfo, "model") ?? string.Empty;
            if (!UpdatePackageDescriptor.SupportsOfflineUpgrade(model))
            {
                throw new InvalidOperationException(T("Dynamic.OfflineUpdate.ErrorUnsupportedModel", LocalizeModelName(model)));
            }
            _offlineSsh = conn;
            _offlineTransfer = new OfflineUpdateTransfer(conn.Rpc);
            _offlineConnectedModel = model.ToUpperInvariant();
            bool legacyController = OfflineUpdateUiState.IsLegacyController(conn.DeviceInfo);
            // selectedSlot is never presented as a proven actual slot.
            _offlineActualSlot = legacyController ? null : GetJsonString(conn.DeviceInfo, "actualSlot");
            _offlineRecoveryPartUuid = GetJsonString(conn.DeviceInfo, "recoveryPartUuid") ?? string.Empty;
            // prepare, execute and restart are gated until the no-slot-control
            // boot policy is advertised.
            _offlineBootPolicySupported =
                OfflineUpdateUiState.SupportsNoSlotControlBootPolicy(conn.DeviceInfo);
            ClearOfflinePairing();
            if (legacyController)
            {
                SetText(OfflineDeviceText, "Dynamic.OfflineUpdate.LegacyDeviceConnected", LocalizeModelName(_offlineConnectedModel));
                AppendOfflineLog("Dynamic.OfflineUpdate.LogLegacyConnected", LocalizeModelName(_offlineConnectedModel));
            }
            else
            {
                string role = _offlineActualSlot ?? "?";
                SetText(OfflineDeviceText, "Dynamic.OfflineUpdate.DeviceConnected", LocalizeModelName(_offlineConnectedModel), role);
                AppendOfflineLog("Dynamic.OfflineUpdate.LogConnected", LocalizeModelName(_offlineConnectedModel), role);
            }
            SetText(OfflineDetailsText, "Dynamic.OfflineUpdate.Value", FormatJson(conn.DeviceInfo));
            SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateConnected");
            if (!_offlineBootPolicySupported)
            {
                AppendOfflineLog("Dynamic.OfflineUpdate.LogBootPolicyMissing");
                SetText(OfflineStateText, "Dynamic.OfflineUpdate.StateBootPolicyReadOnly");
            }
            // Sessions saved by an earlier run are bound to this device and
            // can be queried read-only without importing the package again.
            LoadSavedOfflineSessionsForDevice();
        }
        catch
        {
            if (_offlineSsh == null)
                await conn.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Called by the managed transport during key exchange, on a background
    /// thread, before any password is sent. The answer is a plain explicit
    /// user decision; a changed key is approved only by answering again.
    /// </summary>
    private Task<bool> ApproveOfflineSshHostKeyAsync(OfflineUpdateSshHostKeyPrompt prompt, CancellationToken token)
    {
        if (_offlineWindowClosed || token.IsCancellationRequested)
            return Task.FromResult(false);

        return Dispatcher.UIThread.InvokeAsync(async () =>
        {
            if (_offlineWindowClosed || token.IsCancellationRequested)
                return false;

            string key = prompt.Status == OfflineUpdateSshHostTrustStatus.Changed
                ? "Dynamic.OfflineUpdate.HostKeyChangedPrompt"
                : "Dynamic.OfflineUpdate.HostKeyNewPrompt";

            string message = T(
                key,
                prompt.Host,
                prompt.Port.ToString(CultureInfo.InvariantCulture),
                prompt.Fingerprint,
                prompt.StoredFingerprint ?? string.Empty);

            return await MessageDialog.AskAsync(
                this,
                T("Static.OfflineUpdate.Title"),
                message,
                T("Dynamic.Mac.Dialog.Yes"),
                T("Dynamic.Mac.Dialog.No"));
        });
    }

    /// <summary>
    /// The tablet answered <c>info</c> but does not advertise the
    /// preflight-session capability; only the key route is offered the
    /// password fallback. Nothing is retried or downgraded automatically.
    /// </summary>
    private async Task ShowOfflineUpdaterInstallPromptAsync()
    {
        string message = T("Dynamic.OfflineUpdate.PublicKeyUpdaterInstallRequired");
        await MessageDialog.ShowAsync(this, T("Static.OfflineUpdate.Title"), message, T("Dynamic.Mac.Dialog.Ok"));

        // The password route is the only one allowed to install or verify
        // the updater, so the custom account is selected explicitly.
        OfflineCredentialCombo.SelectedIndex = OfflineUpdateConnectionUiState.CustomCredentialIndex;
        ShowOfflinePasswordEntry("Dynamic.OfflineUpdate.PublicKeyUpdaterInstallRequired");
    }

    /// <summary>
    /// The managed password route already ran and the tablet still does not
    /// advertise the capability; the operator is told what actually can
    /// install the components. The password is not selected again.
    /// </summary>
    private async Task ShowOfflineUpdaterComponentsGuidanceAsync(bool bootstrapAttempted)
    {
        string key = bootstrapAttempted
            ? "Dynamic.OfflineUpdate.UpdaterComponentsStillUnsupported"
            : "Dynamic.OfflineUpdate.UpdaterComponentsMissing";
        await MessageDialog.ShowAsync(this, T("Static.OfflineUpdate.Title"), T(key), T("Dynamic.Mac.Dialog.Ok"));
        SetText(OfflineStateText, key);
        AppendOfflineLog(key);
        RefreshOfflineUpgradeActions();
    }

    /// <summary>
    /// Selects the custom account explicitly, clears only the secret field
    /// and asks the user to enter it. The factory account name is prefilled
    /// only when the field is empty. Focus is applied once the busy state
    /// releases the fields.
    /// </summary>
    private void ShowOfflinePasswordEntry(string messageKey)
    {
        OfflinePasswordBox.Text = string.Empty;
        OfflineCredentialCombo.SelectedIndex = OfflineUpdateConnectionUiState.CustomCredentialIndex;
        if (string.IsNullOrEmpty(OfflineUserBox.Text))
            OfflineUserBox.Text = OfflineUpdateSshDefaultCredentials.Instance.UserName;
        _offlineFocusPasswordOnIdle = true;
        SetText(OfflineStateText, messageKey);
        AppendOfflineLog(messageKey);
        RefreshOfflineUpgradeActions();
    }

    private static bool IsOfflinePasswordRejection(InvalidOperationException exception) =>
        exception.InnerException is OfflineUpdateSshManagedException
        {
            Reason: OfflineUpdateSshManagedFailure.Authentication
        };

    private static string OfflineManagedFailureKey(OfflineUpdateSshManagedFailure reason) => reason switch
    {
        OfflineUpdateSshManagedFailure.Authentication => "Dynamic.OfflineUpdate.ErrorPasswordAuthRejected",
        OfflineUpdateSshManagedFailure.HostKeyRejected => "Dynamic.OfflineUpdate.ErrorHostKeyRejected",
        OfflineUpdateSshManagedFailure.SudoUnavailable => "Dynamic.OfflineUpdate.ErrorSudoUnavailable",
        OfflineUpdateSshManagedFailure.UpdaterUnavailable => "Dynamic.OfflineUpdate.ErrorUpdateComponentsMissing",
        OfflineUpdateSshManagedFailure.Bootstrap => "Dynamic.OfflineUpdate.ErrorBootstrapFailed",
        OfflineUpdateSshManagedFailure.Timeout => "Dynamic.OfflineUpdate.ErrorConnectTimeout",
        _ => "Dynamic.OfflineUpdate.ErrorConnectFailed",
    };
}
