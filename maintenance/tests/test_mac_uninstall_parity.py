"""The macOS window's uninstall page must match the WPF window's "卸载 Linux" flow.

On Windows, "卸载 Linux" (tag "uninstall") runs in the shared four-step pages of MainWindow.xaml with the internal
backup step hidden (check, recovery material and options, confirm), driven by MainWindow.UserdataUninstall*.cs and
MainWindow.RecoverySource.cs plus the uninstall branches of the shared Android -> fresh snapshot -> 9008 pipeline
(MainWindow.InternalInstall.Check.cs / .Backup.cs / .Preparation.cs, MainWindow.BootMaintenance.Edl.cs / .View.cs).
The Mac window shows the same three steps on its own page (UninstallPage) with Uninstall-prefixed controls. This test
compares the controls the WPF uninstall code drives, their handlers, the strings the markup shows, the messages the
code can show and the Core calls the code makes. When the WPF flow changes, it fails until the Mac page follows.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "src" / "FreedomInstaller.App"
MAC = ROOT / "src" / "FreedomInstaller.Mac"
WPF_XAML = APP / "MainWindow.xaml"
# The uninstall controller itself.
WPF_UNINSTALL = [
    APP / "MainWindow.UserdataUninstall.cs",
    APP / "MainWindow.UserdataUninstall.Execution.cs",
    APP / "MainWindow.UserdataUninstall.View.cs",
    APP / "MainWindow.UserdataUninstall.StockBoot.cs",
    APP / "MainWindow.RecoverySource.cs",
]
# The shared pipeline whose uninstall branches the Mac page carries its own copy of.
WPF_SHARED = [
    APP / "MainWindow.Uninstall.cs",
    APP / "MainWindow.InternalInstall.Check.cs",
    APP / "MainWindow.InternalInstall.Backup.cs",
    APP / "MainWindow.InternalInstall.Preparation.cs",
    APP / "MainWindow.BootMaintenance.Edl.cs",
    APP / "MainWindow.BootMaintenance.View.cs",
]
MAC_XAML = MAC / "MainWindow.axaml"
MAC_CODE = [MAC / "MainWindow.Uninstall.cs"]
MAC_PAGE = "UninstallPage"

# WPF control the uninstall code drives -> the Mac page's control for it.
_CONTROL_MAP = {
    "BootMaintenanceAlreadyEdlCheck": "UninstallAlreadyEdlCheck",
    "InternalInstallCheckButton": "UninstallCheckButton",
    "SharedFastbootCheckButton": "UninstallFastbootCheckButton",
    "InternalInstallDevicesCombo": "UninstallDevicesCombo",
    "InternalInstallPowerText": "UninstallPowerText",
    "InternalInstallCheckPage": "UninstallCheckPage",
    "BootMaintenanceSourcesPage": "UninstallSourcesPage",
    "BootMaintenanceConfirmPage": "UninstallConfirmPage",
    "InternalInstallNavCheck": "UninstallNavCheck",
    "InternalInstallNavCapacity": "UninstallNavSources",
    "InternalInstallNavConfirm": "UninstallNavConfirm",
    "BootMaintenanceOriginalBox": "UninstallOriginalBox",
    "BootMaintenanceOriginalBrowseButton": "UninstallOriginalBrowseButton",
    "UninstallUseBoardBackupButton": "UninstallUseBoardBackupButton",
    "UninstallReclaimBackupCheck": "UninstallReclaimBackupCheck",
    "BootMaintenanceRestoreStockCheck": "UninstallRestoreStockCheck",
    "BootMaintenanceRestoreStockHint": "UninstallRestoreStockHint",
    "BootMaintenancePrepareStatusText": "UninstallPrepareStatusText",
    "BootMaintenanceDeviceText": "UninstallDeviceText",
    "BootMaintenanceBackupLocationsText": "UninstallCapacityText",
    "BootMaintenanceSlotsPanel": "UninstallSlotsPanel",
    "BootMaintenanceRegionsHost": "UninstallRegionsHost",
    "BootMaintenanceConfirmRestoreStockCheck": "UninstallConfirmRestoreStockCheck",
    "BootMaintenanceConfirmRestoreStockHint": "UninstallConfirmRestoreStockHint",
    "BootMaintenanceRiskCheck": "UninstallRiskCheck",
    "BootMaintenanceConfirmStatusText": "UninstallConfirmStatusText",
    "BootMaintenanceProgressText": "UninstallProgressText",
    "BootMaintenanceProgressBar": "UninstallProgressBar",
    "PrevButton": "UninstallPrevButton",
    "NextButton": "UninstallNextButton",
    "ActionButton": "UninstallActionButton",
    "InternalInstallExitMaintenancePanel": "UninstallExitPanel",
    "InternalInstallExitMaintenanceButton": "UninstallExitButton",
    "InternalInstallExitMaintenanceStatusText": "UninstallExitStatusText",
}

# Intentional differences, each with its reason:
# - WPF reuses the shared pages and hides what does not belong to uninstall; the Mac page simply does not have it:
#   the internal backup page and its controls, the capacity / install confirm pages, the hidden "02 backup" nav item,
#   the repair-only sources row, and the 9008 entry's history hint and original-folder row (WPF collapses them in
#   uninstall: hideOriginalEntry).
# - Titles / leads / risk text that WPF sets from code on the shared controls are fixed texts in the Mac markup
#   (the page belongs to uninstall only), so those controls need no name.
# - The legacy three-page RiskCheck is only named in a WPF comment ("绝不使用旧三页的隐藏 RiskCheck").
_WPF_ONLY_CONTROLS = {
    "InternalInstallBackupPage",
    "InternalInstallBackupBrowseButton",
    "InternalInstallBackupButton",
    "InternalInstallBackupFolderBox",
    "InternalInstallBackupUseExistingCheck",
    "InternalInstallBackupExistingRow",
    "InternalInstallBackupExistingBrowseButton",
    "InternalInstallCapacityPage",
    "InternalInstallConfirmPage",
    "InternalInstallNavBackup",
    "BootMaintenanceRepairSourcesRow",
    "BootMaintenanceEntryPanel",
    "BootMaintenanceEntryOriginalBox",
    "BootMaintenanceEntryOriginalBrowseButton",
    "SharedEdlEntryHintText",
    "SharedEdlOriginalEntryLabel",
    "SharedEdlOriginalSourceLabel",
    "BootMaintenanceSourcesTitle",
    "BootMaintenanceSourcesLead",
    "BootMaintenanceConfirmTitle",
    "BootMaintenanceRiskText",
    "RiskCheck",
}
# - Texts the WPF code sets on hidden controls or uses only in other modes: the 9008 history hint is collapsed in
#   uninstall, and RecoverySource.cs's repair-install branch ("修复安装") has no card on either home page reachable
#   on Mac.
_WPF_ONLY_MESSAGES = {
    "Dynamic.UserdataUninstall.EdlHint",
    "Dynamic.BootMaintenance.Repair.NeedAndroidIdentity",
}
# - The uninstall handlers keep their WPF names; the frame handlers (check, nav, browse, risk, next, execute, exit)
#   are Uninstall-named because WPF shares them with the other modes.
_UNINSTALL_HANDLERS = {
    "OnUserdataUninstallRestoreStockChanged",
    "OnUserdataUninstallReclaimBackupChanged",
    "OnUseBoardUninstallBackup",
}
# - Not differences in behaviour, listed so they are not mistaken for one:
#   * the folder for the current-state snapshot is never asked for: like WPF it is the earlier one, else the
#     parent of the selected original backup, else the cache root's Recovery folder (WPF: BundledTools cache root);
#     the Mac page does not inherit a folder picked in another function (it keeps its own state);
#   * work files (tool staging, recovery probes, evidence, plans) go under the Mac cache root's uninstall-<guid>
#     folder; WPF uses the environment page's work session;
#   * device calls run on a worker thread (macOS 9008 discovery reads ioreg synchronously); the leave probe + reset
#     runs as busy work; cancellation never happens (the Mac busy runner passes no token), so an OperationCanceled
#     from Core is reported like any other failure instead of being rethrown into an async void handler;
#   * while an operation runs, closing shows the Mac busy dialog in addition to WPF's status line;
#   * WPF wires Checked and Unchecked to one handler; Avalonia has one IsCheckedChanged event for both.


def _mac_page():
    text = MAC_XAML.read_text(encoding="utf-8")
    start = text.index('x:Name="%s"' % MAC_PAGE)
    end = text.index("<!-- =================", start)
    return text[start:end]


def _code(paths):
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _keys(markup, prefix):
    return {key for key in re.findall(r"\{DynamicResource ([A-Za-z0-9_.]+)\}", markup) if key.startswith(prefix)}


def _messages(paths, prefixes):
    pattern = r'"((?:%s)\.[A-Za-z0-9_.]*[A-Za-z0-9_])"' % "|".join(re.escape(p) for p in prefixes)
    return set(re.findall(pattern, _code(paths)))


def _core_calls(text):
    calls = set(re.findall(
        r"(?<![.\w])((?:EdlUninstallBackend|UninstallWorkflow|UninstallStockBootRestoration|CurrentBootSlot"
        r"|CurrentBootMenuPlanner|InternalInstallBackup|BoardRecoveryBackup|UninstallBackupDirectorySelection"
        r"|UninstallGptAssets|BootMaintenanceBackend|GlobalEdlDetection|GlobalEdlBinding|DeviceModelRoutes"
        r"|EdlDeviceProfiles|EdlToolchain|EdlRawBootTools|InternalInstallDirectAssets)\.\w+)",
        text))
    calls |= {"." + name for name in re.findall(
        r"\.(WithSavedIdentityAsync|WaitForPresentAsync|EnterAsync|ProbeAsync|ResetAsync|ReadAndroidAsync"
        r"|ReadAdbIdentityAsync|CheckAsync|ListDevicesAsync)\(", text)}
    calls |= {"new " + name for name in re.findall(
        r"new (EdlEntry|EdlClient|MaintenanceEntry|InternalInstallDeviceCheck)\(", text)}
    return calls


def _wpf_names():
    return set(re.findall(r'x:Name="([A-Za-z0-9_]+)"', WPF_XAML.read_text(encoding="utf-8")))



# WPF wires a check box's Checked and Unchecked to one handler; Avalonia has one IsCheckedChanged event for both.
_EVENTS = {"Click": "Click", "Checked": "CheckedChanged", "Unchecked": "CheckedChanged",
           "IsCheckedChanged": "CheckedChanged"}


def _bindings(markup):
    """(control name, normalized event, handler) for every element that wires an event."""
    bindings = set()
    for tag in re.findall(r"<[A-Za-z][\w:.]*\b[^>]*>", markup):
        name = re.search(r'x:Name="([A-Za-z0-9_]+)"', tag)
        for event, handler in re.findall(r'(?<![A-Za-z])(Click|Checked|Unchecked|IsCheckedChanged)="(On[A-Za-z0-9_]+)"', tag):
            bindings.add((name.group(1) if name else None, _EVENTS[event], handler))
    return bindings

class MacUninstallParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mac = _mac_page()
        cls.mac_names = set(re.findall(r'x:Name="([A-Za-z0-9_]+)"', cls.mac))

    def test_every_driven_control_is_mapped(self):
        # Every WPF control the uninstall code touches is either on the Mac page (under its mapped name) or listed
        # above as intentionally absent.
        wpf_names = _wpf_names()
        text = _code(WPF_UNINSTALL)
        driven = {name for name in wpf_names if re.search(r"\b%s\b" % re.escape(name), text)}
        self.assertEqual(set(), driven - set(_CONTROL_MAP) - _WPF_ONLY_CONTROLS)
        self.assertLessEqual(set(_CONTROL_MAP), wpf_names)
        self.assertLessEqual(set(_CONTROL_MAP.values()), self.mac_names)

    def test_mac_names_are_prefixed(self):
        self.assertEqual(set(), {name for name in self.mac_names if not name.startswith("Uninstall")})

    def test_uninstall_handlers_match(self):
        wpf = {b for b in _bindings(WPF_XAML.read_text(encoding="utf-8")) if b[2] in _UNINSTALL_HANDLERS}
        self.assertEqual(_UNINSTALL_HANDLERS, {handler for _name, _event, handler in wpf})
        mac = _bindings(self.mac)
        self.assertLessEqual(_UNINSTALL_HANDLERS, {handler for _name, _event, handler in mac})
        # Per control and event: every WPF binding of a mapped control is on its Mac counterpart, so two controls
        # that swap handlers are caught.
        mapped = {(_CONTROL_MAP[name], event, handler) for name, event, handler in wpf if name in _CONTROL_MAP}
        self.assertTrue(mapped)
        self.assertLessEqual(mapped, mac)

    def test_markup_keys_match(self):
        # The uninstall texts WPF shows in markup or sets from code on visible controls are on the Mac page.
        wpf = _keys(WPF_XAML.read_text(encoding="utf-8"), "Dynamic.UserdataUninstall.")
        shown = _keys(self.mac, "Dynamic.UserdataUninstall.") | _messages(MAC_CODE, ["Dynamic.UserdataUninstall"])
        self.assertEqual(set(), wpf - shown)

    def test_code_shows_the_same_messages(self):
        prefixes = ["Dynamic.UserdataUninstall", "Dynamic.RecoverySource", "Dynamic.Model", "Dynamic.BootMaintenance"]
        wpf = _messages(WPF_UNINSTALL, prefixes) - _WPF_ONLY_MESSAGES
        mac_shown = _messages(MAC_CODE, prefixes) | _keys(self.mac, "Dynamic.")
        self.assertEqual(set(), wpf - mac_shown)
        # Anything else the Mac code shows comes from the shared WPF pipeline or the WPF markup.
        prefixes += ["Dynamic.InternalInstall", "Dynamic.Shared", "Dynamic.UninstallFlow"]
        extra = _messages(MAC_CODE, prefixes) - _messages(WPF_UNINSTALL, prefixes)
        allowed = _messages(WPF_SHARED, prefixes) | _keys(WPF_XAML.read_text(encoding="utf-8"), "Dynamic.")
        self.assertEqual(set(), extra - allowed)

    def test_code_makes_the_same_core_calls(self):
        wpf = _core_calls(_code(WPF_UNINSTALL))
        mac = _core_calls(_code(MAC_CODE))
        self.assertLessEqual(wpf, mac)
        # The rest are the shared check / snapshot / tool calls the WPF uninstall mode makes through the shared
        # pipeline; no Mac-only Core call.
        self.assertEqual(set(), (mac - wpf) - _core_calls(_code(WPF_SHARED)))
        for call in ("InternalInstallBackup.CreateAsync", "new InternalInstallDeviceCheck", ".EnterAsync",
                     "EdlRawBootTools.LoadAsync"):
            self.assertIn(call, mac)

    def test_core_call_order(self):
        # Prepare: recovery source -> original GPT -> current slot -> (stock plan) -> menu / backend factory;
        # execute: workflow, then the one reset or the stock restoration.
        mac = _code(MAC_CODE)
        prepare = mac[mac.index("private async Task PrepareUninstallConfirmationAsync"):]
        order = [
            "GetUninstallRecoverySourceAsync(",
            "InternalInstallBackup.OpenOriginalGptForUninstallAsync(",
            "CurrentBootSlot.ReadAsync(",
            "BootMaintenanceBackend.CreatePreparedFromEdlAsync(",
            "EdlUninstallBackend.CreatePreparedForStockRestoreAsync(",
            "CurrentBootMenuPlanner.PrepareAndroidDefaultAsync(",
            "EdlUninstallBackend.CreatePreparedAsync(",
        ]
        positions = [prepare.index(name) for name in order]
        self.assertEqual(positions, sorted(positions))
        execute = mac[mac.index("private async Task ExecuteUninstallAsync"):]
        positions = [execute.index(name) for name in (
            "UninstallWorkflow.ConfirmationFor(",
            "UninstallWorkflow.RunAsync(",
            "UninstallStockBootRestoration.RestoreAfterUninstallAsync(",
            "client.ResetAsync(",
        )]
        self.assertEqual(positions, sorted(positions))

    def test_write_route_gate_is_the_wpf_one(self):
        # TB710FU stays held back by Core's write-route gate at the same entry points; no Mac-only gate.
        mac = _code(MAC_CODE)
        self.assertGreaterEqual(mac.count("DeviceModelRoutes.IsWriteRoutePending("), 3)
        self.assertIn("Dynamic.Model.RoutePendingInEdl", mac)
        self.assertNotIn("IsInstallRoutePending", mac)
        self.assertNotIn('"TB710FU"', mac)

    def test_preparation_failure_codes_match(self):
        pattern = r'"(requires-[a-z-]+):'
        self.assertEqual(set(re.findall(pattern, _code(WPF_UNINSTALL))), set(re.findall(pattern, _code(MAC_CODE))))

    def test_stage_keys_match(self):
        pattern = r'"(Dynamic\.UserdataUninstall\.Runtime\.Stage\.[A-Za-z]+)"'
        self.assertEqual(set(re.findall(pattern, _code(WPF_UNINSTALL))), set(re.findall(pattern, _code(MAC_CODE))))

    def test_home_card_opens_the_page(self):
        text = MAC_XAML.read_text(encoding="utf-8")
        card = re.search(
            r'<Button Tag="uninstall" Click="OnSelectOperation"[^>]*>.*?Static\.Function\.Uninstall\.Title.*?</Button>',
            text,
            re.S,
        )
        self.assertIsNotNone(card)
        self.assertNotIn("Static.Mac.WindowsOnly", card.group(0))
        # No home card is Windows-only any more.
        self.assertNotIn("Static.Mac.WindowsOnly", text)
        dispatch = (MAC / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertRegex(dispatch, r'case "uninstall"[^:]*:\s*ShowUninstallPage\(\);')

    def test_other_pages_respect_the_session(self):
        shell = _code([MAC / "MainWindow.axaml.cs", MAC / "MainWindow.Install.cs"])
        self.assertIn("|| HasUninstallDeviceSession;", shell)
        self.assertGreaterEqual(shell.count("!HasUninstallDeviceSession"), 4)
        self.assertIn("RefreshUninstallActions();", shell)

    def test_close_handler_covers_the_page(self):
        closing = (MAC / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertIn("await OnUninstallClosingAsync(e)", closing)
        self.assertIn("DisposeUninstallOnClose();", closing)
        self.assertLess(closing.index("await OnBootMaintenanceClosingAsync(e)"), closing.index("await OnUninstallClosingAsync(e)"))

    def test_close_offers_close_only_when_the_leave_cannot_complete(self):
        # A retained client without initial Sahara proof cannot pass the leave's warm probe, and a leave whose probe
        # failed sent no reset: both must reach the explicit close-only warning instead of cancelling every close.
        code = MAC_CODE[0].read_text(encoding="utf-8")
        closing = code[code.index("private async Task<bool> OnUninstallClosingAsync"):]
        close_only = closing[:closing.index("await ConfirmLeaveUninstallAsync()")]
        self.assertIn("_uninstallEdlClient is { HasInitialSaharaProof: false }", close_only)
        fallback = closing[closing.index("await ConfirmLeaveUninstallAsync()"):]
        self.assertIn("_uninstallLeaveProbeFailed", fallback[:fallback.index("SafeResetUninstallState();")])
        self.assertIn("_uninstallLeaveProbeFailed = true;", code)

    def test_completed_session_never_reaches_the_unproven_warning(self):
        # An accepted reset clears the client's proof: a completed uninstall must reach the completed cleanup instead.
        code = MAC_CODE[0].read_text(encoding="utf-8")
        closing = code[code.index("private async Task<bool> OnUninstallClosingAsync"):]
        close_only = closing[:closing.index("await ConfirmLeaveUninstallAsync()")]
        self.assertIn("bool sessionOver = _uninstallCompleted", close_only)
        self.assertIn("(!sessionOver && _uninstallEdlClient is { HasInitialSaharaProof: false })", close_only)

    def test_prewrite_close_only_releases_local_resources(self):
        # The normal close release skips a live 9008 session; the explicit pre-write close-only exits must still
        # free the staged toolchain, without a device command.
        code = MAC_CODE[0].read_text(encoding="utf-8")
        closing = code[code.index("private async Task<bool> OnUninstallClosingAsync"):]
        self.assertEqual(2, closing.count("ReleaseUninstallLocalResourcesForPrewriteClose();"))
        release = code[code.index("private void ReleaseUninstallLocalResourcesForPrewriteClose"):]
        release = release[:release.index("\n    }\n")]
        self.assertNotIn("HasUninstallLiveEdlState", release)
        self.assertIn("HasUnresolvedUninstallState", release)
        self.assertNotIn("ResetAsync", release)
        self.assertNotIn("ProbeAsync", release)

    def test_default_preparation_uses_the_proven_lock_state(self):
        code = MAC_CODE[0].read_text(encoding="utf-8")
        self.assertIn("_uninstallDeviceCheck!.FastbootLockState", code)
        self.assertNotIn("_uninstallDeviceCheck!.Android!.Identity.BootloaderState", code)


if __name__ == "__main__":
    unittest.main()
