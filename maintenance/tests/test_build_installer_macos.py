"""Tests for build_installer_macos.py: the macOS window build reuses the shared checks and
packages every EDL toolchain for macos-arm64 with the freshly generated pins."""

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

import build_installer  # noqa: E402
import build_installer_macos  # noqa: E402
import fetch_build_inputs  # noqa: E402
import test_build_installer as shared  # noqa: E402

DYLIB = b"libusb-dylib-arm64"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _nupkg():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("runtimes/win-x64/native/libusb-1.0.dll", b"libusb-dll")
        zf.writestr("runtimes/osx-arm64/native/libusb-1.0.dylib", DYLIB)
    return buf.getvalue()


def _fetch(manifest, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for dl in manifest["downloads"]:
        data = _nupkg() if dl["id"] == "libusbPackage" else (
            b"libusb license text\n" if dl["id"] == "libusbLicense" else f"{dl['id']}\n".encode())
        path = out / dl["name"]
        path.write_bytes(data)
        files[dl["id"]] = str(path.resolve())
    return files


def _compile(argv, cwd, env, phase):
    joined = " ".join(str(a) for a in argv)
    if "build-edl-ng.sh" in joined:
        assert argv[-1] == "osx-arm64", argv
        out = Path(argv[2])
        out.mkdir(parents=True, exist_ok=True)
        (out / "edl-ng").write_bytes(b"fresh-mac-client")
        return
    if "build-boot-packers-macos.sh" in joined:
        out = Path(argv[3])
        out.mkdir(parents=True, exist_ok=True)
        (out / "MultiBootKernelPatcher").write_bytes(b"fresh-mac-packer")
        (out / "UnpackTool").write_bytes(b"fresh-mac-unpacker")
        return
    raise AssertionError(f"unexpected _run: {argv}")


class MacPrepareTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="bim ")
        root = Path(self._tmp.name)
        self.repo_root, manifest = shared._build_fixture_repo(root / "repo")
        for dl in manifest["downloads"]:
            if dl["id"] == "libusbPackage":
                dl["extractMacos"] = {
                    "path": "runtimes/osx-arm64/native/libusb-1.0.dylib",
                    "bytes": len(DYLIB),
                    "sha256": _sha(DYLIB),
                }
        self.manifest_path = self.repo_root / "maintenance" / "build-inputs.json"
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        self.work_dir = root / "work"

    def tearDown(self):
        self._tmp.cleanup()

    def _prepare(self):
        calls = []

        def fake_package(ns):
            calls.append(ns)
            Path(ns.output).write_bytes(b"zip")
            return {"profile": ns.profile}

        with mock.patch.object(fetch_build_inputs, "fetch_all", side_effect=_fetch), \
             mock.patch.object(build_installer, "_run", side_effect=_compile), \
             mock.patch.object(build_installer_macos.package_edl, "package", side_effect=fake_package):
            record = build_installer_macos.prepare(self.repo_root, self.work_dir, manifest_path=self.manifest_path)
        return record, calls

    def test_packages_every_profile_for_macos_with_fresh_pins(self):
        record, calls = self._prepare()
        self.assertEqual([ns.profile for ns in calls], ["tb322fc", "tb323fu", "tb710fu"])
        for ns in calls:
            self.assertEqual(ns.platform, "macos-arm64")
            self.assertIsNone(ns.python)
            self.assertEqual(Path(ns.build_pins_json), Path(record["toolPinsJson"]))
            self.assertEqual(Path(ns.usbLibrary).read_bytes(), DYLIB)
        pins = json.loads(Path(record["toolPinsJson"]).read_text(encoding="utf-8"))
        self.assertEqual(pins["tools"]["client"]["sha256"], _sha(b"fresh-mac-client"))
        self.assertEqual(pins["tools"]["packer"]["sha256"], _sha(b"fresh-mac-packer"))
        cs = Path(record["toolPinsSource"]).read_text(encoding="utf-8")
        self.assertIn(_sha(b"fresh-mac-unpacker"), cs)

    def test_props_name_the_pins_source_and_every_input(self):
        record, _ = self._prepare()
        props = Path(record["propsPath"]).read_text(encoding="utf-8")
        self.assertIn("<BundledToolPinsSource>", props)
        for prop in build_installer_macos._PROPERTY_NAMES:
            self.assertIn(f"<{prop}>", props)
        self.assertNotIn("BundledPlatformToolsArchive", props)

    def test_props_forward_the_fetched_gbl_efi_files(self):
        record, _ = self._prepare()
        for prop, dl_id in (("BundledGblPrcEfi", "gblPrc"), ("BundledGblRowEfi", "gblRow")):
            path = Path(record["inputs"][prop])
            self.assertEqual(path.read_bytes(), f"{dl_id}\n".encode())
            props = Path(record["propsPath"]).read_text(encoding="utf-8")
            self.assertIn(f"<{prop}>{build_installer._xml_escape(str(path))}</{prop}>", props)

    def test_missing_macos_libusb_entry_fails(self):
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        for dl in manifest["downloads"]:
            dl.pop("extractMacos", None)
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(SystemExit):
            self._prepare()


if __name__ == "__main__":
    unittest.main()
