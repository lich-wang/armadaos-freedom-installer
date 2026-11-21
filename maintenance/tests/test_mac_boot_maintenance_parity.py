"""The macOS window's boot-maintenance page must match the WPF window's prepare / repair flow.

On Windows, "Android 更新前准备" (tag "prepare") and "Android 更新后修复" (tag "repair") run in the shared four-step
pages of MainWindow.xaml (check, backup, sources, confirm) driven by MainWindow.BootMaintenance*.cs and the shared
Android -> fresh backup -> 9008 entry (MainWindow.SharedDeviceEntry.cs and the shared-mode branches of
MainWindow.InternalInstall.*.cs). The Mac window shows the same four steps on its own page (BootMaintenancePage)
with BootMaintenance-prefixed controls. This test compares the maintenance controls, their handlers, the strings
the markup shows, the Dynamic.BootMaintenance / Shared / Model messages the code can show and the Core calls the
code makes. When the WPF flow changes, it fails until the Mac page follows.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "src" / "FreedomInstaller.App"
MAC = ROOT / "src" / "FreedomInstaller.Mac"
WPF_XAML = APP / "MainWindow.xaml"
WPF_CODE = [
    APP / "MainWindow.BootMaintenance.cs",
    APP / "MainWindow.BootMaintenance.Edl.cs",
    APP / "MainWindow.BootMaintenance.View.cs",
    APP / "MainWindow.SharedDeviceEntry.cs",
    APP / "MainWindow.InternalInstall.Check.cs",
    APP / "MainWindow.InternalInstall.Backup.cs",
    APP / "MainWindow.InternalInstall.Preparation.cs",
]
MAC_XAML = MAC / "MainWindow.axaml"
MAC_CODE = [MAC / "MainWindow.BootMaintenance.cs"]
MAC_PAGE = "BootMaintenancePage"

# Intentional differences, each with its reason:
# - Uninstall-only controls in the shared WPF pages (restore-stock check boxes and hints): uninstall has its own Mac
#   page (UninstallPage, checked by test_mac_uninstall_parity.py), so the maintenance page does not show them.
# - The package browse button: WPF shows it only in the "repair-install" mode, which has no home card (on either
#   window's home page reachable on Mac); in "repair" WPF hides it and the path is pasted, so the Mac page omits it
#   and its handler (OnBrowseBootMaintenancePackage returns at once outside repair-install).
_WPF_ONLY_NAMES = {
    "BootMaintenanceRestoreStockCheck",
    "BootMaintenanceRestoreStockText",
    "BootMaintenanceRestoreStockHint",
    "BootMaintenanceConfirmRestoreStockCheck",
    "BootMaintenanceConfirmRestoreStockText",
    "BootMaintenanceConfirmRestoreStockHint",
    "BootMaintenancePackageBrowseButton",
}
_WPF_ONLY_HANDLERS = {"OnBrowseBootMaintenancePackage"}
# - The WPF shared pages carry the uninstall restore-stock labels too (shown on the Mac uninstall page).
_WPF_ONLY_KEYS = {"Dynamic.UserdataUninstall.RestoreStock.Label", "Dynamic.UserdataUninstall.RestoreStock.Hint"}
# - Messages of the repair-install mode ("修复安装"; it reads the on-board recovery backup) only: that mode has no
#   card on the Mac home page.
_WPF_ONLY_MESSAGES = {
    "Dynamic.BootMaintenance.Repair.BackupCoverage",
    "Dynamic.BootMaintenance.Repair.BackupWarning",
    "Dynamic.BootMaintenance.Repair.BoardMissingCapture",
    "Dynamic.BootMaintenance.Repair.CheckLead",
    "Dynamic.BootMaintenance.Repair.CheckPassed",
    "Dynamic.BootMaintenance.Repair.ConfirmTitle",
    "Dynamic.BootMaintenance.Repair.FreshBackup",
    "Dynamic.BootMaintenance.Repair.SourceLead",
    "Dynamic.BootMaintenance.Repair.Succeeded",
    "Dynamic.BootMaintenance.Repair.BackupKeepEdl",
}
# - Core calls of paths the Mac page does not offer: the internal install's "reuse an existing backup" and board
#   backup (OpenExisting / OpenRecovery / preparation snapshot / board recovery read) and repair-install's board
#   recovery capture. Maintenance always takes a fresh backup, on both windows.
_WPF_ONLY_CALLS = {
    "BoardRecoveryBackup.ReadDirectoryAsync",
    "InternalInstallBackup.CreatePreparationSnapshotAsync",
    "InternalInstallBackup.OpenExistingAsync",
    "InternalInstallBackup.OpenRecoveryAsync",
    # The shared WPF check also serves the internal install, whose gate is the install route; the maintenance page
    # only ever applies the write route (IsCurrentModeRoutePending in a shared mode).
    "DeviceModelRoutes.IsInstallRoutePending",
    # The shared WPF check also probes for an on-board backup after the Android return; only the internal
    # install's automatic backup reads that result, so the maintenance page has no use for the probe.
    "BoardRecoveryBackup.DetectAdbAsync",
}
# - Core calls the shared WPF backup reaches only on the internal install's automatic branch
#   (`internalAutoBranch`, which is `IsInternalInstallMode`): the maintenance modes never take them, so they are not
#   part of the boot-maintenance path. test_install_only_calls_stay_on_the_install_branch keeps that true.
_WPF_INSTALL_ONLY_CALLS = {
    "InternalInstallBackup.CreateForFirstInstallAsync",
}
# - WPF wires Checked and Unchecked to one handler; Avalonia has one IsCheckedChanged event for both.


def _mac_page():
    text = MAC_XAML.read_text(encoding="utf-8")
    start = text.index('x:Name="%s"' % MAC_PAGE)
    end = text.index("<!-- =================", start)
    return text[start:end]


def _wpf_maintenance_xaml():
    """The WPF markup of the shared pages that belongs to boot maintenance: entry panel, sources and confirm pages."""
    text = WPF_XAML.read_text(encoding="utf-8")
    parts = []
    for name, end_marker in (
        ("BootMaintenanceEntryPanel", 'x:Name="InternalInstallCheckProgressText"'),
        ("BootMaintenanceSourcesPage", 'x:Name="InternalInstallExitMaintenancePanel"'),
    ):
        start = text.index('x:Name="%s"' % name)
        parts.append(text[start:text.index(end_marker, start)])
    return "\n".join(parts)


def _code(paths):
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _keys(markup, prefix):
    return {key for key in re.findall(r"\{DynamicResource ([A-Za-z0-9_.]+)\}", markup) if key.startswith(prefix)}


def _names(markup):
    return set(re.findall(r'x:Name="(BootMaintenance[A-Za-z0-9_]+)"', markup))


_EVENTS = {"Click": "Click", "Checked": "CheckedChanged", "Unchecked": "CheckedChanged",
           "IsCheckedChanged": "CheckedChanged", "TextChanged": "TextChanged"}


def _handlers(markup):
    """(control name, normalized event, handler) for the maintenance handlers, so swapped bindings are caught.

    Only the maintenance handlers: the shared WPF markup also wires uninstall handlers and the shared check
    button (the Mac page has its own BootMaintenance-named check handlers for the same two buttons).
    """
    bindings = set()
    for tag in re.findall(r"<[A-Za-z][\w:.]*\b[^>]*>", markup):
        name = re.search(r'x:Name="([A-Za-z0-9_]+)"', tag)
        for event, handler in re.findall(
                r'(?<![A-Za-z])(Click|Checked|Unchecked|IsCheckedChanged|TextChanged)="(On[A-Za-z0-9_]+)"', tag):
            if "BootMaintenance" in handler:
                bindings.add((name.group(1) if name else None, _EVENTS[event], handler))
    return bindings


def _messages(paths, prefixes):
    pattern = r'"((?:%s)\.[A-Za-z0-9_.]*[A-Za-z0-9_])"' % "|".join(re.escape(p) for p in prefixes)
    return set(re.findall(pattern, _code(paths)))


def _core_calls(text):
    calls = set(re.findall(
        r"(?<![.\w])((?:BootMaintenanceBackend|InternalInstallBackup|PackageImporter|EdlToolchain|EdlRawBootTools"
        r"|InternalInstallDirectAssets|DeviceModelRoutes|EdlDeviceProfiles|BoardRecoveryBackup)\.\w+)",
        text))
    calls |= {"." + name for name in re.findall(
        r"\.(WaitForPresentAsync|EnterAsync|ProbeAsync|ResetAsync|ExecuteAsync|ReadAndroidAsync"
        r"|ReadAdbIdentityAsync|CheckAsync|ListDevicesAsync)\(", text)}
    calls |= {"new " + name for name in re.findall(
        r"new (EdlEntry|EdlClient|MaintenanceEntry|InternalInstallDeviceCheck)\(", text)}
    return calls


class MacBootMaintenanceParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wpf = _wpf_maintenance_xaml()
        cls.mac = _mac_page()

    def test_named_controls_match(self):
        # Every WPF maintenance control exists on the Mac page under the same name; the Mac page adds its own
        # frame (step tabs, buttons, check / backup copies of the shared pages), all BootMaintenance-prefixed.
        self.assertLessEqual(_names(self.wpf) - _WPF_ONLY_NAMES, _names(self.mac))
        self.assertEqual(set(), _names(self.mac) & _WPF_ONLY_NAMES)

    def test_mac_names_are_prefixed(self):
        names = set(re.findall(r'x:Name="([A-Za-z0-9_]+)"', self.mac))
        self.assertEqual(set(), {name for name in names if not name.startswith("BootMaintenance")})

    def test_handlers_match(self):
        wpf = {binding for binding in _handlers(self.wpf) if binding[2] not in _WPF_ONLY_HANDLERS}
        self.assertTrue(wpf)
        self.assertLessEqual(wpf, _handlers(self.mac))

    def test_markup_keys_match(self):
        for prefix in ("Dynamic.BootMaintenance.", "Dynamic.Shared."):
            wpf = _keys(self.wpf, prefix) - _WPF_ONLY_KEYS
            self.assertLessEqual(wpf, _keys(self.mac, prefix) | _messages(MAC_CODE, [prefix.rstrip(".")]), prefix)

    def test_code_shows_the_same_messages(self):
        prefixes = ["Dynamic.BootMaintenance", "Dynamic.Shared", "Dynamic.Model"]
        wpf = _messages(WPF_CODE, prefixes) - _WPF_ONLY_MESSAGES
        mac_shown = _messages(MAC_CODE, prefixes) | _keys(self.mac, "Dynamic.")
        self.assertEqual(set(), wpf - mac_shown)
        # Anything the Mac code shows beyond the WPF code is a text the WPF markup shows (e.g. a picker title), or a
        # result text the WPF code reaches by concatenation ("...Status.Outcome." + result.Outcome).
        extra = _messages(MAC_CODE, prefixes) - _messages(WPF_CODE, prefixes)
        outcome = "Dynamic.BootMaintenance.Status.Outcome."
        wpf_code = "\n".join(path.read_text(encoding="utf-8") for path in WPF_CODE)
        if f'"{outcome}" + result.Outcome' in wpf_code:
            extra = {key for key in extra if not key.startswith(outcome)}
        self.assertEqual(set(), extra - _keys(WPF_XAML.read_text(encoding="utf-8"), "Dynamic."))

    def test_code_makes_the_same_core_calls(self):
        wpf = _core_calls(_code(WPF_CODE)) - _WPF_ONLY_CALLS - _WPF_INSTALL_ONLY_CALLS
        self.assertEqual(wpf, _core_calls(_code(MAC_CODE)))

    def test_install_only_calls_stay_on_the_install_branch(self):
        # The calls left out of the boot-maintenance comparison above must stay behind the internal install's
        # automatic branch in the shared WPF backup; if one moves onto a path the maintenance modes take, this fails.
        backup = (APP / "MainWindow.InternalInstall.Backup.cs").read_text(encoding="utf-8")
        self.assertRegex(backup, r"\bvar internalAutoBranch = IsInternalInstallMode;")
        wpf = _code(WPF_CODE)
        for call in sorted(_WPF_INSTALL_ONLY_CALLS):
            sites = [m.start() for m in re.finditer(r"(?<![.\w])" + re.escape(call) + r"\(", wpf)]
            self.assertTrue(sites, call)
            for site in sites:
                guard = wpf[max(0, site - 200):site]
                self.assertRegex(guard, r"internalAutoBranch\s*&&[^;]*\?\s*await\s*$", call)
            self.assertNotIn(call, _code(MAC_CODE))

    def test_write_route_gate_is_the_wpf_one(self):
        # TB710FU stays held back by Core's write-route gate at the same entry points; no Mac-only gate.
        mac = _code(MAC_CODE)
        self.assertGreaterEqual(mac.count("DeviceModelRoutes.IsWriteRoutePending("), 3)
        self.assertIn("DeviceModelRoutes.IsRouteRefusal(", mac)
        self.assertNotIn("IsInstallRoutePending", mac)
        self.assertNotIn('"TB710FU"', mac)

    def test_preparation_failure_codes_match(self):
        pattern = r'"(boot-maintenance-[a-z-]+):'
        self.assertEqual(
            set(re.findall(pattern, (APP / "MainWindow.BootMaintenance.cs").read_text(encoding="utf-8"))),
            set(re.findall(pattern, _code(MAC_CODE))))

    def test_home_cards_open_the_page(self):
        text = MAC_XAML.read_text(encoding="utf-8")
        for tag, title in (("prepare", "Prepare"), ("repair", "Repair")):
            card = re.search(
                r'<Button Tag="%s" Click="OnSelectOperation"[^>]*>.*?Static\.Function\.%s\.Title.*?</Button>'
                % (tag, title),
                text,
                re.S,
            )
            self.assertIsNotNone(card, tag)
            self.assertNotIn("Static.Mac.WindowsOnly", card.group(0))
        dispatch = (MAC / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertRegex(dispatch, r'case "prepare" or "repair"[^:]*:\s*ShowBootMaintenancePage\(')

    def test_close_handler_covers_the_page(self):
        closing = (MAC / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertIn("await OnBootMaintenanceClosingAsync(e)", closing)
        self.assertIn("DisposeBootMaintenanceOnClose();", closing)

    def test_close_offers_close_only_when_the_leave_probe_failed(self):
        # A leave whose device probe failed sent no reset: closing must reach the explicit close-only warning instead
        # of cancelling every close with the same failing probe.
        code = _code(MAC_CODE)
        closing = code[code.index("private async Task<bool> OnBootMaintenanceClosingAsync"):]
        fallback = closing[closing.index("await ConfirmLeaveBootMaintenanceAsync()"):]
        refused = fallback[:fallback.index("ResetBootMaintenanceUiState();")]
        # The failed probe must guard the close-only warning itself: an early "return true" on the flag would still
        # mention it, but would leave the user with no way to close.
        guarded = re.search(
            r"if \(_bootMaintenanceLeaveProbeFailed\s*&& await MessageDialog\.AskAsync\(\s*this,\s*"
            r'T\("Dynamic\.Mac\.Close\.ProbeFailedTitle"\),\s*T\("Dynamic\.Mac\.Close\.ProbeFailedBody"\),'
            r"[^)]*\)[^)]*\)\)\)\s*\{(?P<body>.*?)\}\s*return true;",
            refused,
            re.S,
        )
        self.assertIsNotNone(guarded, "the failed leave probe does not offer the close-only warning")
        body = guarded.group("body")
        # Approving the warning reaches the same cleanup as a normal close, in this order, then really closes; nothing
        # in the approved branch may leave it before Close().
        steps = ("_closeConfirmed = true;", "DisposeBootMaintenanceOnClose();", "DisposeInternalInstall();", "Close();")
        self.assertNotRegex(body, r"\breturn\b", "the approved close-only branch returns before closing")
        # Every statement of the approved branch is one of the expected steps, so nothing else can intervene.
        statements = [line.strip() for line in body.splitlines() if line.strip() and not line.strip().startswith("//")]
        self.assertEqual(list(steps), statements)
        self.assertNotRegex(refused[:refused.index("_bootMaintenanceLeaveProbeFailed")], r"\breturn true;")
        self.assertIn("_bootMaintenanceLeaveProbeFailed = true;", code)

    def test_a_completed_session_starts_no_new_backup(self):
        code = _code(MAC_CODE)
        gate = code[code.index("BootMaintenanceBackupButton.IsEnabled = idle"):]
        self.assertIn("!IsBootMaintenanceCompleted", gate[:gate.index(";")])
        for entry in ("private async Task BackupBootMaintenanceAsync()", "private async Task BackupBootMaintenanceEdlAsync()"):
            body = code[code.index(entry):]
            self.assertIn("IsBootMaintenanceCompleted", body[:body.index("return;")])

    def test_the_9008_route_replaces_a_conflicting_backup_folder(self):
        code = _code(MAC_CODE)
        check = code[code.index('"Dynamic.BootMaintenance.Edl.NeedHistory"'):]
        check = check[:check.index("ResetBootMaintenanceCheckState();")]
        # A saved folder inside a source reopens the picker, and a newly picked folder is checked before it is saved.
        self.assertRegex(check, r"BootMaintenanceParentConflict\(parent\) is not null\)\s*\{\s*var folder = await PickBootMaintenanceFolderAsync")
        self.assertLess(check.index("BootMaintenanceParentConflict(folder)"), check.index("ApplyBootMaintenanceBackupParent(folder);"))

    def test_an_edl_backup_attempt_clears_the_previous_result(self):
        code = _code(MAC_CODE)
        edl = code[code.index("private async Task BackupBootMaintenanceEdlAsync()"):]
        start = edl[edl.index("ReleaseBootMaintenanceBackupObject();"):edl.index("await RunBusyAsync(")]
        self.assertIn("BootMaintenanceBackupProgressBar.Value = 0;", start)
        self.assertIn('SetText(BootMaintenanceBackupVerifiedText, M("Dynamic.InternalInstall.Backup.RunningNote"));', start)
        failures = edl[edl.index("await RunBusyAsync("):edl.index("private void RenderBootMaintenanceBackupSuccess")]
        self.assertEqual(failures.count('"Dynamic.InternalInstall.Backup.FailedNote"'), 2)

    def test_an_execution_exception_is_not_reported_as_a_preparation_failure(self):
        code = _code(MAC_CODE)
        render = code[code.index("private void RenderBootMaintenanceRuntimeStatus"):]
        error = render[render.index("else if (_bootMaintenanceLastError is not null)"):]
        error = error[:error.index("else\n")] if "else\n" in error else error[:600]
        self.assertIn("_bootMaintenanceExecuteAttempted", error)
        self.assertIn("HasUnconfirmedBootMaintenanceWrite", error)
        self.assertIn('"Dynamic.BootMaintenance.Status.Outcome.UnknownWriteOutcome"', error)
        self.assertIn('"Dynamic.BootMaintenance.Status.Outcome.Failed"', error)

    def test_completed_run_is_kept_until_the_session_is_released(self):
        code = _code(MAC_CODE)
        invalidate = code[code.index("private void InvalidateBootMaintenancePreparation"):]
        self.assertIn("IsBootMaintenanceCompleted", invalidate[:invalidate.index("_bootMaintenanceBackend")])


if __name__ == "__main__":
    unittest.main()
