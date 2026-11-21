"""The macOS window's offline upgrade page must match the WPF window's.

The WPF page is its own UserControl (OfflineUpgradeView.xaml) whose handlers are wired in code
(InitializeOfflineUpgradeView); the Mac page is a section of MainWindow.axaml whose controls carry an "Offline"
prefix (one name scope with the rest of the window) and whose handlers are wired in the markup. This test
compares what each page shows and does: the static string keys, the named controls, the event wiring (control,
event, handler), the Dynamic/Static OfflineUpdate messages the code can show, the shared state helpers and Core
calls the code makes, and the models the connection accepts. When the WPF page or its code changes, it fails
until the Mac page follows.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WPF_XAML = ROOT / "src" / "FreedomInstaller.App" / "OfflineUpgradeView.xaml"
WPF_CODE = [
    ROOT / "src" / "FreedomInstaller.App" / "MainWindow.OfflineUpgrade.cs",
    ROOT / "src" / "FreedomInstaller.App" / "MainWindow.OfflinePairing.cs",
]
MAC_XAML = ROOT / "src" / "FreedomInstaller.Mac" / "MainWindow.axaml"
MAC_CODE = [
    ROOT / "src" / "FreedomInstaller.Mac" / "MainWindow.OfflineUpgrade.cs",
    ROOT / "src" / "FreedomInstaller.Mac" / "MainWindow.OfflinePairing.cs",
]
MAC_PREFIX = "Offline"
MAC_PAGE = "OfflineUpgradePage"

# Intentional differences, each with its reason:
# - The WPF window resolves the records location from a work directory chosen on its environment page and refuses
#   with ErrorWorkDirNotReady until that check has passed. The Mac window has no work directory: its records live
#   under the Mac cache root, which always exists, so this refusal cannot occur there.
_WPF_ONLY_MESSAGES = {"Dynamic.OfflineUpdate.ErrorWorkDirNotReady"}
# - WPF wires Checked and Unchecked to one handler; Avalonia has one IsCheckedChanged event for both.
_EVENT_MAP = {"Checked": "IsCheckedChanged", "Unchecked": "IsCheckedChanged"}


def _mac_page():
    text = MAC_XAML.read_text(encoding="utf-8")
    start = text.index('x:Name="%s"' % MAC_PAGE)
    end = text.index("<!-- =================", start)
    return text[start:end]


def _keys(page, prefix):
    return {key for key in re.findall(r"\{DynamicResource ([A-Za-z0-9_.]+)\}", page) if key.startswith(prefix)}


def _wpf_names(page):
    # The PasswordBox template in UserControl.Resources names its own parts (Chrome, PART_ContentHost); the Mac
    # page masks a TextBox instead and needs no template, so only the page body is compared.
    body = page[page.index("</UserControl.Resources>"):]
    return set(re.findall(r'x:Name="([A-Za-z0-9_]+)"', body))


def _mac_names(page):
    names = set(re.findall(r'x:Name="([A-Za-z0-9_]+)"', page)) - {MAC_PAGE}
    unprefixed = {name for name in names if not name.startswith(MAC_PREFIX)}
    assert not unprefixed, unprefixed
    return {name[len(MAC_PREFIX):] for name in names}


def _wpf_wiring():
    text = "\n".join(path.read_text(encoding="utf-8") for path in WPF_CODE)
    wiring = set()
    for control, event, handler in re.findall(r"OfflineUpgradePanel\.(\w+)\.(\w+) \+= (\w+);", text):
        wiring.add((control, _EVENT_MAP.get(event, event), handler))
    return wiring


def _mac_wiring(page):
    wiring = set()
    for element in re.findall(r"<[A-Za-z]+\s[^>]*>", page, re.S):
        name = re.search(r'x:Name="%s([A-Za-z0-9_]+)"' % MAC_PREFIX, element)
        if name is None:
            continue
        for event, handler in re.findall(r'\b([A-Za-z]+)="(On[A-Za-z0-9_]+)"', element):
            wiring.add((name.group(1), event, handler))
    return wiring


def _code(paths):
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def _messages(paths):
    return set(re.findall(r'"((?:Dynamic|Static)\.OfflineUpdate\.[A-Za-z0-9_.]+)"', _code(paths)))


def _shared_calls(paths):
    """Calls into Core and into the shared state helpers: the decisions the page delegates."""
    text = _code(paths)
    calls = set(re.findall(r"(?<![.\w])((?:OfflineUpdate\w*|OfflineBootstrapAssets|PackageImporter)\.\w+)", text))
    calls |= {"transfer." + name for name in re.findall(r"_offlineTransfer!?\.(\w+)", text)}
    calls |= {"transfer." + name for name in re.findall(r"\btransfer\.(\w+)", text)}
    return calls


class MacOfflineUpgradeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wpf = WPF_XAML.read_text(encoding="utf-8")
        cls.mac = _mac_page()

    def test_static_keys_match(self):
        self.assertEqual(_keys(self.wpf, "Static."), _keys(self.mac, "Static."))

    def test_initial_dynamic_texts_match(self):
        self.assertEqual(_keys(self.wpf, "Dynamic."), _keys(self.mac, "Dynamic."))

    def test_named_controls_match(self):
        self.assertEqual(_wpf_names(self.wpf), _mac_names(self.mac))

    def test_event_wiring_matches(self):
        wpf = _wpf_wiring()
        self.assertGreater(len(wpf), 15)
        self.assertEqual(wpf, _mac_wiring(self.mac))

    def test_code_shows_the_same_messages(self):
        wpf = _messages(WPF_CODE) - _WPF_ONLY_MESSAGES
        mac = _messages(MAC_CODE)
        self.assertEqual(wpf, mac)

    def test_code_makes_the_same_core_and_state_calls(self):
        self.assertEqual(_shared_calls(WPF_CODE), _shared_calls(MAC_CODE))

    def test_accepted_models_match(self):
        # The model gate lives in the page code on both sides (Core does not route offline upgrades by model).
        pattern = r'string\.Equals\(model, "([A-Z0-9]+)"'
        self.assertEqual(set(re.findall(pattern, _code(WPF_CODE))), set(re.findall(pattern, _code(MAC_CODE))))

    def test_updater_version_floor_matches(self):
        pattern = r'IsUpdaterVersionAtLeast\(deviceInfo, "([0-9.]+)"\)'
        self.assertEqual(re.findall(pattern, _code(WPF_CODE)), re.findall(pattern, _code(MAC_CODE)))

    def test_home_card_opens_the_page(self):
        text = MAC_XAML.read_text(encoding="utf-8")
        card = re.search(
            r'<Button Tag="offline-upgrade" Click="OnSelectOperation"[^>]*>.*?Static\.Function\.OfflineUpdate\.Title.*?</Button>',
            text,
            re.S,
        )
        self.assertIsNotNone(card)
        self.assertNotIn("Static.Mac.WindowsOnly", card.group(0))
        dispatch = (ROOT / "src" / "FreedomInstaller.Mac" / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertRegex(dispatch, r'case "offline-upgrade"[^:]*:\s*ShowOfflineUpgradePage\(\);')

    def test_close_handler_releases_the_page(self):
        # The WPF window registers OnOfflineUpgradeClosing; the Mac window's single close handler calls the port.
        closing = (ROOT / "src" / "FreedomInstaller.Mac" / "MainWindow.axaml.cs").read_text(encoding="utf-8")
        self.assertIn("await OnOfflineUpgradeClosingAsync(e)", closing)


if __name__ == "__main__":
    unittest.main()
