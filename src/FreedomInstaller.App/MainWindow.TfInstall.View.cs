using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App
{
    public partial class MainWindow
    {
        private void RenderModernTfInstallPages()
        {
            if (IsModernTfTabletMode)
            {
                RenderTfTabletPages();
                return;
            }

            if (!IsModernTfInstallMode)
            {
                return;
            }

            RestoreInternalInstallNav();

            var step = _internalInstallStep;

            InternalInstallCheckPage.Visibility = step == 0 ? Visibility.Visible : Visibility.Collapsed;
            InternalInstallBackupPage.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
            TfInstallInputsPage.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceConfirmPage.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;
            InternalInstallCapacityPage.Visibility = Visibility.Collapsed;
            InternalInstallConfirmPage.Visibility = Visibility.Collapsed;
            BootMaintenanceSourcesPage.Visibility = Visibility.Collapsed;

            BootMaintenanceEntryPanel.Visibility = step == 0 ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceRepairSourcesRow.Visibility = Visibility.Collapsed;

            // TF install always requires a fresh capture; the existing-backup shortcut is unavailable.
            InternalInstallBackupUseExistingCheck.Visibility = Visibility.Collapsed;
            InternalInstallBackupUseExistingCheck.IsEnabled = false;
            InternalInstallBackupExistingRow.Visibility = Visibility.Collapsed;
            InternalInstallBackupExistingRow.IsEnabled = false;

            // Shared labels are resource-only; registering the resource reference keeps language
            // switching consistent and prevents stale TF UiMessage values from pinning the text.
            SharedEdlEntryHintText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.EdlHint");
            SharedEdlOriginalEntryLabel.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.HistorySource");
            SharedWorkflowThirdStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Inputs");
            SharedWorkflowConfirmStepText.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.Nav.Confirm");
            BootMaintenanceConfirmTitle.SetResourceReference(TextBlock.TextProperty, "Dynamic.TfInstall.ConfirmTitle");

            var alreadyEdl = _bootMaintenanceAlreadyEdl;
            BootMaintenanceEntryOriginalBox.Visibility = alreadyEdl ? Visibility.Visible : Visibility.Collapsed;
            BootMaintenanceEntryOriginalBrowseButton.Visibility = alreadyEdl ? Visibility.Visible : Visibility.Collapsed;
            SharedEdlOriginalEntryLabel.Visibility = alreadyEdl ? Visibility.Visible : Visibility.Collapsed;

            var readerSource = _tfSource == TfCardSource.Reader;
            TfCardDiscoveryHost.Visibility = step == 0 && readerSource ? Visibility.Visible : Visibility.Collapsed;
            if (step == 0 && readerSource)
            {
                MoveModernTfElement(TfCardSection, TfCardDiscoveryHost);
            }
            else
            {
                MoveModernTfElement(TfCardSection, TfInstallCardHost);
            }

            MoveModernTfElement(PackageSection, TfInstallPackageHost);

            RenderModernTfInstallConfirmPage();
            RenderBootMaintenanceCheckButton();
            RenderModernTfInstallRuntimeStatus();

            RefreshModernTfInstallActions();
        }

        private static void MoveModernTfElement(FrameworkElement element, Border host)
        {
            if (element.Parent is Panel parentPanel)
            {
                if (!ReferenceEquals(element, host.Child))
                {
                    parentPanel.Children.Remove(element);
                }
            }
            else if (element.Parent is Border parentBorder)
            {
                if (ReferenceEquals(parentBorder.Child, element))
                {
                    parentBorder.Child = null;
                }
            }
            else if (element.Parent != null)
            {
                throw new InvalidOperationException(
                    $"Unexpected parent for TF install element {element.Name}: {element.Parent.GetType().Name}");
            }

            if (!ReferenceEquals(host.Child, element))
            {
                host.Child = element;
            }

            element.Visibility = Visibility.Visible;
        }

        private void RenderModernTfInstallConfirmPage()
        {
            BootMaintenanceSlotsPanel.Children.Clear();
            BootMaintenanceRegionsHost.Children.Clear();

            var workflow = _tfInstallWorkflow;
            if (workflow == null || workflow.Prepared == null)
            {
                SetText(BootMaintenanceDeviceText, M("Dynamic.RawValue", UnknownValue));
                SetText(BootMaintenanceBackupLocationsText, M("Dynamic.RawValue", UnknownValue));

                // 没有工作流时不得每次刷新都清掉有效的卡片容量预览：总数读真实读到的卡，
                // 计划与当前卡匹配时给出真实预览数字（只读展示，不代表 Ready）。
                SetText(TfTotalText, M("Dynamic.RawValue",
                    _tfCard != null ? FormatBytes(_tfCard.SizeBytes) : UnknownValue));
                if (_tfPlan != null && _tfCard != null && _tfPlan.TargetKey == _tfCard.Key)
                {
                    SetText(TfBootText, M("Dynamic.RawValue", FormatBytes(_tfPlan.LinuxBootBytes)));
                    SetText(TfRootText, M("Dynamic.RawValue", FormatBytes(_tfPlan.LinuxRootBytes)));
                    SetText(TfDataText, M("Dynamic.RawValue", FormatBytes(_tfPlan.EstimatedLinuxDataBytes)));
                }
                else
                {
                    SetText(TfBootText, M("Dynamic.RawValue", UnknownValue));
                    SetText(TfRootText, M("Dynamic.RawValue", UnknownValue));
                    SetText(TfDataText, M("Dynamic.RawValue", UnknownValue));
                }

                SetText(BootMaintenanceProgressText, M("Dynamic.RawValue", string.Empty));
                BootMaintenanceProgressBar.Value = 0;

                if (_tfInstallError != null)
                {
                    SetText(BootMaintenanceConfirmStatusText, _tfInstallError);
                }
                else
                {
                    SetText(BootMaintenanceConfirmStatusText, "Dynamic.TfInstall.NeedInputs");
                }

                SetText(BootMaintenanceRiskText, "Dynamic.TfInstall.Risk");
                return;
            }

            var prepared = workflow.Prepared;
            var card = prepared.Card;
            var boot = prepared.Boot;
            var space = prepared.Space;

            SetText(BootMaintenanceDeviceText, M(
                "Dynamic.TfInstall.PreparedSummary",
                boot.Model,
                boot.AndroidSerial,
                boot.CurrentSlot,
                card.DevicePath,
                FormatBytes(card.SizeBytes)));

            SetText(BootMaintenanceBackupLocationsText, M(
                "Dynamic.TfInstall.BackupLocations",
                prepared.BackupDirectory,
                prepared.EvidenceDirectory));

            SetText(TfTotalText, M("Dynamic.RawValue", FormatBytes(space.TotalBytes)));
            SetText(TfBootText, M("Dynamic.RawValue", FormatBytes(space.LinuxBootBytes)));
            SetText(TfRootText, M("Dynamic.RawValue", FormatBytes(space.LinuxRootBytes)));
            SetText(TfDataText, M("Dynamic.RawValue", FormatBytes(space.EstimatedLinuxDataBytes)));

            foreach (var region in boot.Regions)
            {
                var caption = new TextBlock
                {
                    Style = TryFindResource("CaptionText") as Style,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(4)
                };

                SetText(
                    caption,
                    region.WillWrite ? "Dynamic.BootMaintenance.RegionWrite" : "Dynamic.BootMaintenance.RegionKeep",
                    region.Role ?? string.Empty,
                    region.Slot ?? string.Empty,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length);

                BootMaintenanceRegionsHost.Children.Add(caption);
            }

            SetText(BootMaintenanceConfirmStatusText, "Dynamic.TfInstall.Status.Prepared");
        }

        private void RefreshModernTfInstallActions()
        {
            if (IsModernTfTabletMode)
            {
                RefreshTfTabletActions();
                return;
            }

            if (!IsModernTfInstallMode)
            {
                return;
            }

            var step = _internalInstallStep;
            var busy = _busy;
            var idle = !busy && !_tfInstallOperationActive && !_internalInstallOperationActive;
            var protectedState = ProtectedModernTfInstallState;
            var completed = IsCompletedModernTfInstall;
            var live = HasInternalInstallLiveEdlState;
            var fresh = _internalInstallBackup;
            var hasProof = HasBootMaintenanceDeviceProof;
            var backupPrereq = HasBootMaintenanceBackupPrerequisite;
            var readerSource = _tfSource == TfCardSource.Reader;
            var alreadyEdl = _bootMaintenanceAlreadyEdl;
            var workflow = _tfInstallWorkflow;
            var editable = idle && !protectedState && !completed && workflow == null;

            InternalInstallNavCheck.IsEnabled = CanEnterModernTfInstallStep(0);
            InternalInstallNavBackup.IsEnabled = CanEnterModernTfInstallStep(1);
            InternalInstallNavCapacity.IsEnabled = CanEnterModernTfInstallStep(2);
            InternalInstallNavConfirm.IsEnabled = CanEnterModernTfInstallStep(3);

            PrevButton.IsEnabled = step > 0 && CanEnterModernTfInstallStep(step - 1);

            NextButton.Visibility = step < 3 ? Visibility.Visible : Visibility.Collapsed;
            NextButton.IsEnabled = step < 3
                && idle
                && !protectedState
                && !completed
                && CanEnterModernTfInstallStep(step + 1);

            var packagePath = PackagePathBox.Text;
            var packagePathExists = false;
            if (!string.IsNullOrWhiteSpace(packagePath))
            {
                try
                {
                    packagePathExists = File.Exists(packagePath) || Directory.Exists(packagePath);
                }
                catch (IOException)
                {
                    packagePathExists = false;
                }
            }

            if (step == 2)
            {
                // Reader mode only, path-only gate: this prepares the workflow, it never
                // confirms or executes anything.
                NextButton.IsEnabled = readerSource
                    && idle
                    && !protectedState
                    && !completed
                    && fresh != null
                    && hasProof
                    && _tfCard != null
                    && packagePathExists;
            }

            ActionButton.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;
            SetContent(ActionButton, "Dynamic.TfInstall.Execute");
            ActionButton.IsEnabled = step == 3 && CanExecuteModernTfInstall();

            TfSourceTabletRadio.IsEnabled = editable;
            TfSourceReaderRadio.IsEnabled = editable;
            ReadTfCardsButton.IsEnabled = editable && readerSource;
            TfCardsCombo.IsEnabled = editable && _tfCards != null && _tfCards.Count > 0;

            var packageControlsEnabled = editable && step == 2 && fresh != null && hasProof;
            PackagePathBox.IsEnabled = packageControlsEnabled;
            BrowsePackageButton.IsEnabled = packageControlsEnabled;
            ValidatePackageButton.IsEnabled = packageControlsEnabled && packagePathExists;

            var backupStartEnabled = editable
                && backupPrereq
                && _internalInstallBackupParent != null
                && Directory.Exists(_internalInstallBackupParent)
                && (!live
                    || (_internalInstallEdlClient != null
                        && _internalInstallEdlEntry != null
                        && _internalInstallEdlTools != null));
            InternalInstallBackupBrowseButton.IsEnabled = editable && backupPrereq;
            InternalInstallBackupFolderBox.IsEnabled = editable && backupPrereq;
            InternalInstallBackupButton.IsEnabled = backupStartEnabled;

            InternalInstallDevicesCombo.IsEnabled = idle
                && !protectedState
                && !live
                && !alreadyEdl
                && _internalInstallDeviceChoices != null
                && _internalInstallDeviceChoices.Count > 0;
            InternalInstallCheckButton.IsEnabled = idle
                && !protectedState
                && !live
                && _transport != null;

            BootMaintenanceAlreadyEdlCheck.IsEnabled = editable && !live;
            BootMaintenanceEntryOriginalBrowseButton.IsEnabled = editable && !live;

            BootMaintenanceRiskCheck.IsEnabled = idle
                && !protectedState
                && !completed
                && workflow != null
                && _tfInstallPackage != null
                && fresh != null;

            InternalInstallExitMaintenancePanel.Visibility = live && !completed ? Visibility.Visible : Visibility.Collapsed;
            if (live && !completed)
            {
                if (_tfInstallExitStatus != null)
                {
                    SetText(InternalInstallExitMaintenanceStatusText, _tfInstallExitStatus);
                }
                else
                {
                    SetText(InternalInstallExitMaintenanceStatusText, "Dynamic.TfInstall.Exit.Ready");
                }
            }

            // 面板自身持有可见性；按钮只按真实现场条件启停，不再自行设置 Visibility。
            InternalInstallExitMaintenanceButton.IsEnabled = idle
                && !completed
                && !HasUnresolvedModernTfInstallState
                && _internalInstallEdlClient != null;
            SetContent(InternalInstallExitMaintenanceButton, "Dynamic.TfInstall.Exit.Button");

            // 已准备的 TF 模式下状态行必须反映真实状态：旧的「功能禁用」文案不再残留。
            SetText(ActionReasonText, "Dynamic.RawValue", string.Empty);

            // 真实存在的主机驱动事实渲染；绝不写任何虚构控件。
            RenderTfTabletHostDriverStatus();

            UpdateInternalInstallDeviceSelector();
            RefreshSharedAdvancedCheckAvailability();
            RenderModernTfInstallRuntimeStatus();
        }
    }
}
