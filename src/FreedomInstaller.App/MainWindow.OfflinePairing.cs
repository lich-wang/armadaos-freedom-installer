using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App
{
    public partial class MainWindow
    {
        private OfflineUpdateSshIdentity? _offlinePairingIdentity;
        private OfflineUpdateSshHostCandidate? _offlinePairingCandidate;

        /// <summary>
        /// Which route produced the authenticated transport that
        /// <see cref="FinishOfflineConnectionAsync"/> is about to adopt. Only
        /// the key route may still offer the managed password route as its
        /// install fallback; the managed route itself cannot offer a retry
        /// once the capability is still missing.
        /// </summary>
        private enum OfflineConnectRoute
        {
            Key,
            PasswordWithBootstrap,
            PasswordWithoutBootstrap
        }

        private void ClearOfflinePairing()
        {
            _offlinePairingIdentity = null;
            _offlinePairingCandidate = null;
            if (OfflineUpgradePanel == null)
                return;
            OfflineUpgradePanel.PairingPanel.Visibility = Visibility.Collapsed;
            OfflineUpgradePanel.PairingCommandBox.Clear();
            OfflineUpgradePanel.PairingReceiptBox.Clear();
            SetText(OfflineUpgradePanel.PairingHostText, "Dynamic.OfflineUpdate.Value", "");
        }

        private void OnOfflinePairingReceiptChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
            RefreshOfflineUpgradeActions();

        /// <summary>
        /// The USB SSH-key route with no manual key files: discover the exact USB
        /// endpoint, then reuse the existing one-time public-key pairing flow.
        /// Supplying key files instead is an explicit key connection and never
        /// reaches this method.
        /// </summary>
        private async Task BeginOfflineUsbKeyEnrollmentAsync(CancellationToken ct)
        {
            ClearOfflinePairing();

            // Host-key discovery runs ssh-keyscan, so it belongs only to the key
            // flow; the password flow must work on Windows hosts without OpenSSH.
            var candidate = await OfflineUpdateSshEnrollment.DiscoverUsbHostAsync(_runner, token: ct);

            // Existing one-time public-key pairing stays available unchanged.
            var identity = await OfflineUpdateSshIdentityStore.EnsureAsync(
                Path.Combine(BundledTools.GetCacheRoot(), "connections", "offline-upgrade"), _runner, token: ct);
            var keyOptions = OfflineUpdateSshTrustStore.TryLoadUsbHost(candidate, identity);
            if (keyOptions == null)
            {
                _offlinePairingCandidate = candidate;
                _offlinePairingIdentity = identity;
                OfflineUpgradePanel.PairingPanel.Visibility = Visibility.Visible;
                OfflineUpgradePanel.PairingCommandBox.Text =
                    OfflineUpdateSshEnrollment.BuildAuthorizationCommand(identity.PublicKey.PublicKey);
                SetText(OfflineUpgradePanel.PairingHostText, "Dynamic.OfflineUpdate.PairingFingerprints",
                    candidate.HostKey.Fingerprint, identity.PublicKey.Fingerprint);
                SetText(OfflineUpgradePanel.StateText, "Dynamic.OfflineUpdate.PairingNeeded");
                AppendOfflineLog("Dynamic.OfflineUpdate.PairingNeeded");
                RefreshOfflineUpgradeActions();
                return;
            }

            await ConnectOfflineOptionsAsync(keyOptions, ct);
        }

        private async void OnConfirmOfflinePairingAsync(object sender, RoutedEventArgs e)
        {
            if (_busy || _offlineSsh != null || _offlinePairingCandidate == null || _offlinePairingIdentity == null)
                return;
            string receipt = OfflineUpgradePanel.PairingReceiptBox.Text;
            if (string.IsNullOrWhiteSpace(receipt))
                return;
            var capturedCandidate = _offlinePairingCandidate;
            var capturedIdentity = _offlinePairingIdentity;
            await RunOfflineUpgradeAsync(async (_, ct) =>
            {
                var candidate = await OfflineUpdateSshEnrollment.DiscoverUsbHostAsync(_runner, token: ct);
                var identity = await OfflineUpdateSshIdentityStore.EnsureAsync(
                    Path.Combine(BundledTools.GetCacheRoot(), "connections", "offline-upgrade"), _runner, token: ct);
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

        private void OnCopyOfflinePairingCommand(object sender, RoutedEventArgs e)
        {
            if (_offlinePairingCandidate == null)
                return;
            try
            {
                Clipboard.SetText(OfflineUpgradePanel.PairingCommandBox.Text);
                AppendOfflineLog("Dynamic.OfflineUpdate.PairingCopied");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, T("Dynamic.OfflineUpdate.PairingCopyFailed", ex.Message),
                    T("Static.OfflineUpdate.Title"), MessageBoxButton.OK, MessageBoxImage.Error);
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

            // The bootstrap assistant is build-supplied. When it is present,
            // run it after SSH trust/authentication and before the updater.info
            // query; it only probes/installs the service and never prepares or
            // executes an upgrade. A source build may omit it entirely, so the
            // finish hook has to distinguish that from a real install attempt.
            bool bootstrapAttempted = false;
            if (OfflineBootstrapAssets.TryCreate(
                    new Progress<OfflineUpdateBootstrapProgress>(p =>
                    {
                        if (_closed || OfflineUpgradePanel == null)
                            return;
                        string key = p.Phase switch
                        {
                            OfflineUpdateBootstrapCoordinator.ProbingPhase => "Dynamic.OfflineUpdate.BootstrapProbing",
                            OfflineUpdateBootstrapCoordinator.DeployingPhase => "Dynamic.OfflineUpdate.BootstrapDeploying",
                            OfflineUpdateBootstrapCoordinator.VerifyingPhase => "Dynamic.OfflineUpdate.BootstrapVerifying",
                            _ => "Dynamic.OfflineUpdate.BootstrapReady",
                        };
                        if (p.Phase != OfflineUpdateBootstrapCoordinator.ReadyPhase)
                            SetText(OfflineUpgradePanel.StateText, key);
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
        /// The single point where an authenticated transport becomes the
        /// panel's connection, shared by the key route and the password route.
        ///
        /// The authenticated info must prove the installed updater accepts the
        /// preflight session parameter before this connection is ever
        /// presented as usable. Neither route may install or repair the
        /// updater through the key connection (the pairing key may be a forced
        /// command that can neither upload nor run sudo), so a device that
        /// does not advertise the capability is refused here instead of
        /// failing later in preflight or being accepted on its version alone.
        /// A device that advertises it but not the no-slot-control boot policy
        /// still connects read-only; that policy only gates prepare, execute
        /// and restart.
        /// </summary>
        private async Task FinishOfflineConnectionAsync(
            IOfflineUpdateConnection conn, OfflineConnectRoute route, CancellationToken ct)
        {
            if (!OfflineUpdateUiState.SupportsPreflightSession(conn.DeviceInfo))
            {
                // This transport was never adopted by the panel, so releasing it
                // here is the only disposal on this path.
                await conn.DisposeAsync();
                ClearOfflinePairing();
                if (route == OfflineConnectRoute.Key)
                {
                    // The public-key route cannot deploy or verify the service
                    // itself, so its one explicit fallback stays the managed
                    // password route.
                    ShowOfflineUpdaterInstallPrompt();
                }
                else
                {
                    // The managed password route was already tried. Whether
                    // this build carried the bootstrap assets or none at all,
                    // asking for the same password again cannot make the
                    // installed service advertise the capability.
                    ShowOfflineUpdaterComponentsGuidance(
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
                // A helper that does not declare the no-slot-control boot
                // policy may still write Android slot metadata. The connection
                // and every read-only action stay available; prepare, execute
                // and restart are gated until the policy is advertised.
                _offlineBootPolicySupported =
                    OfflineUpdateUiState.SupportsNoSlotControlBootPolicy(conn.DeviceInfo);
                ClearOfflinePairing();
                if (legacyController)
                {
                    SetText(OfflineUpgradePanel.DeviceText, "Dynamic.OfflineUpdate.LegacyDeviceConnected", LocalizeModelName(_offlineConnectedModel));
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogLegacyConnected", LocalizeModelName(_offlineConnectedModel));
                }
                else
                {
                    string role = _offlineActualSlot ?? "?";
                    SetText(OfflineUpgradePanel.DeviceText, "Dynamic.OfflineUpdate.DeviceConnected", LocalizeModelName(_offlineConnectedModel), role);
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogConnected", LocalizeModelName(_offlineConnectedModel), role);
                }
                SetText(OfflineUpgradePanel.DetailsText, "Dynamic.OfflineUpdate.Value", FormatJson(conn.DeviceInfo));
                SetText(OfflineUpgradePanel.StateText, "Dynamic.OfflineUpdate.StateConnected");
                if (!_offlineBootPolicySupported)
                {
                    AppendOfflineLog("Dynamic.OfflineUpdate.LogBootPolicyMissing");
                    SetText(OfflineUpgradePanel.StateText, "Dynamic.OfflineUpdate.StateBootPolicyReadOnly");
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
            if (_closed || token.IsCancellationRequested)
                return Task.FromResult(false);

            return Dispatcher.InvokeAsync(() =>
            {
                if (_closed || token.IsCancellationRequested)
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

                return MessageBox.Show(
                    this,
                    message,
                    T("Static.OfflineUpdate.Title"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No) == MessageBoxResult.Yes;
            }).Task;
        }

        /// <summary>
        /// The tablet answered <c>info</c> but does not advertise the
        /// preflight-session capability this installer requires, so its
        /// installed updater is older than the gates below assume. The
        /// public-key route cannot deploy or verify it, so only that route is
        /// offered the password fallback; the password route reports what can
        /// actually install the components instead. Nothing is retried or
        /// downgraded automatically.
        /// </summary>
        private void ShowOfflineUpdaterInstallPrompt()
        {
            if (OfflineUpgradePanel == null)
                return;

            string message = T("Dynamic.OfflineUpdate.PublicKeyUpdaterInstallRequired");
            MessageBox.Show(
                this,
                message,
                T("Static.OfflineUpdate.Title"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            // The password route is the only one allowed to install or verify
            // the updater, so the custom account is selected explicitly instead
            // of leaving the key inputs in place. The existing password
            // workflow and its single host-key decision stay unchanged.
            OfflineUpgradePanel.CredentialCombo.SelectedIndex = OfflineUpdateConnectionUiState.CustomCredentialIndex;
            ShowOfflinePasswordEntry("Dynamic.OfflineUpdate.PublicKeyUpdaterInstallRequired");
        }

        /// <summary>
        /// The managed password route already ran and the tablet still does not
        /// advertise the preflight-session capability this installer requires.
        /// Neither the same password nor the other route can install a newer
        /// service from here, so the operator is told what actually can: an
        /// installer built with the offline update components, or those
        /// components installed on the tablet separately. The password is not
        /// selected, cleared or focused again because retrying it cannot help.
        /// </summary>
        private void ShowOfflineUpdaterComponentsGuidance(bool bootstrapAttempted)
        {
            if (OfflineUpgradePanel == null)
                return;

            string key = bootstrapAttempted
                ? "Dynamic.OfflineUpdate.UpdaterComponentsStillUnsupported"
                : "Dynamic.OfflineUpdate.UpdaterComponentsMissing";
            MessageBox.Show(
                this,
                T(key),
                T("Static.OfflineUpdate.Title"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            SetText(OfflineUpgradePanel.StateText, key);
            AppendOfflineLog(key);
            RefreshOfflineUpgradeActions();
        }

        /// <summary>
        /// Selects the custom account explicitly, clears only the secret field
        /// and asks the user to enter it. The factory account name is prefilled
        /// only when the field is empty; a name the user typed is never
        /// overwritten. Focus is applied once the busy state releases the
        /// fields, so the visible password box is the next input.
        /// </summary>
        private void ShowOfflinePasswordEntry(string messageKey)
        {
            if (OfflineUpgradePanel == null)
                return;

            OfflineUpgradePanel.PasswordBox.Clear();
            OfflineUpgradePanel.CredentialCombo.SelectedIndex = OfflineUpdateConnectionUiState.CustomCredentialIndex;
            if (string.IsNullOrEmpty(OfflineUpgradePanel.UserBox.Text))
                OfflineUpgradePanel.UserBox.Text = OfflineUpdateSshDefaultCredentials.Instance.UserName;
            _offlineFocusPasswordOnIdle = true;
            SetText(OfflineUpgradePanel.StateText, messageKey);
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
}
