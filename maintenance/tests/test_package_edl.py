#!/usr/bin/env python3
"""Packaging behaviour tests for package_edl.py using real hashing/streaming."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_MAINT = os.path.dirname(_HERE)
_spec = importlib.util.spec_from_file_location("package_edl", os.path.join(_MAINT, "package_edl.py"))
edl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edl)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def _common_fixtures(root: str) -> dict[str, str]:
    files: dict[str, str] = {}
    for role, _flag, _help in edl.COMMON_FLAGS:
        files[role] = _write(os.path.join(root, "common", role + ".bin"), ("common-" + role).encode())
    return files


def _material_fixtures(root: str, profile: dict) -> dict[str, str]:
    files: dict[str, str] = {}
    for role, arcname, _size, _digest in profile["materials"]:
        files[role] = _write(os.path.join(root, "materials", role + ".bin"), ("mat-" + role).encode())
    return files


def _patched_pins(files: dict[str, str], profile: dict) -> dict[str, tuple[int, str]]:
    pins: dict[str, tuple[int, str]] = {}
    for role, path in files.items():
        with open(path, "rb") as handle:
            data = handle.read()
        pins[role] = (len(data), _sha(data))
    for role, _arcname, _size, _digest in profile["materials"]:
        path = files[role]
        with open(path, "rb") as handle:
            data = handle.read()
        pins[role] = (len(data), _sha(data))
    return pins


def _replace_profile_pins(profile: dict, pins: dict[str, tuple[int, str]]) -> dict:
    materials = tuple(
        (role, arcname, pins[role][0], pins[role][1])
        for role, arcname, _size, _digest in profile["materials"]
    )
    clone = dict(profile)
    clone["materials"] = materials
    return clone


def _args(files: dict[str, str], output: str, profile: str, **extra) -> argparse.Namespace:
    ns = argparse.Namespace(profile=profile, output=output)
    for role, _flag, _help in edl.COMMON_FLAGS:
        setattr(ns, role, files.get(role))
    ns.firehose = None
    ns.loader_root = None
    for key, value in extra.items():
        setattr(ns, key, value)
    return ns


class PackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.out = os.path.join(self.root, "dist", "bundle.zip")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_current_client_pin(self) -> None:
        self.assertEqual(
            edl.FIXED_PINS["client"],
            (12015022, "655530e926b57d70f1c690869c495253a6eaae28746f370d5b9dbf921d4a4b3b"),
        )

    def _roundtrip(self, profile_key: str, profile: dict) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, profile)
        pins = _patched_pins({**common, **materials}, profile)
        new_profile = _replace_profile_pins(profile, pins)
        extra = {}
        if profile in edl.SINGLE_FIREHOSE_PROFILES:
            extra["firehose"] = materials["firehose"]
        else:
            loader = os.path.join(self.root, "loader")
            for role, arcname, _s, _h in profile["materials"]:
                src = materials[role]
                with open(src, "rb") as handle:
                    data = handle.read()
                _write(os.path.join(loader, arcname.rsplit("/", 1)[-1]), data)
            extra["loader_root"] = loader
        args = _args(common, self.out, profile_key, **extra)
        with mock.patch.dict(profile, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            report = edl.package(args)
        self.assertTrue(os.path.isfile(self.out))
        with zipfile.ZipFile(self.out) as archive:
            names = archive.namelist()
            self.assertEqual(names[0], "manifest.json")
            for info in archive.infolist():
                self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)
            manifest_bytes = archive.read("manifest.json")
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest["profileId"], profile["profileId"])
            entries = {e["role"]: e for e in manifest["entries"]}
            expected_roles = {r for r, *_ in edl.COMMON_ROLES} | {r for r, *_ in profile["materials"]}
            self.assertEqual(set(entries), expected_roles)
            for role, arcname, _size, _digest in profile["materials"]:
                self.assertIn(arcname, names)
            for role, arcname, *_rest in edl.COMMON_ROLES:
                self.assertIn(arcname, names)
            for role, entry in entries.items():
                data = archive.read(entry["path"])
                self.assertEqual(len(data), entry["bytes"])
                self.assertEqual(_sha(data), entry["sha256"])
            with open(self.out + ".manifest.json", "rb") as handle:
                self.assertEqual(handle.read(), manifest_bytes)
            with open(self.out + ".sha256", "rb") as handle:
                line = handle.read().decode()
            self.assertEqual(line, f"{report['sha256']}  {os.path.basename(self.out)}\n")
            with open(self.out, "rb") as handle:
                self.assertEqual(_sha(handle.read()), report["sha256"])

    def test_roundtrip_g4(self) -> None:
        self._roundtrip("tb322fc", edl.G4_PROFILE)

    def _macos_args(self, with_pins: bool) -> argparse.Namespace:
        common = _common_fixtures(self.root)
        common.pop("python")
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"], platform="macos-arm64")
        self._material_pins = _patched_pins(materials, edl.G4_PROFILE)
        if with_pins:
            with open(common["client"], "rb") as handle:
                client = handle.read()
            pins_path = os.path.join(self.root, "tool-pins.json")
            with open(pins_path, "w", encoding="utf-8") as handle:
                json.dump({"schemaVersion": 1, "tools": {"client": {"bytes": len(client), "sha256": _sha(client)}}}, handle)
            args.build_pins_json = pins_path
        else:
            args.build_pins_json = None
        return args

    def test_macos_requires_build_pins(self) -> None:
        args = self._macos_args(with_pins=False)
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("--build-pins-json", str(ctx.exception))
        self.assertFalse(os.path.exists(self.out))

    def test_macos_roundtrip_has_no_python_and_names_the_platform(self) -> None:
        args = self._macos_args(with_pins=True)
        new_profile = _replace_profile_pins(edl.G4_PROFILE, self._material_pins)
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True):
            edl.package(args)
        with zipfile.ZipFile(self.out) as archive:
            names = archive.namelist()
            manifest = json.loads(archive.read("manifest.json"))
        self.assertEqual(manifest["platform"], "macos-arm64")
        self.assertIn("tools/edl-ng", names)
        self.assertIn("tools/libusb-1.0.dylib", names)
        self.assertFalse(any(name.startswith("python/") for name in names))

    def test_roundtrip_g5(self) -> None:
        self._roundtrip("tb323fu", edl.G5_PROFILE)

    def test_roundtrip_tb710fu(self) -> None:
        self._roundtrip("tb710fu", edl.TB710FU_PROFILE)

    def test_g4_rejects_wrong_firehose_material(self) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G4_PROFILE)
        new_profile = _replace_profile_pins(edl.G4_PROFILE, pins)
        wrong = _write(os.path.join(self.root, "wrong.bin"), b"not the firehose")
        args = _args(common, self.out, "tb322fc", firehose=wrong)
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            with self.assertRaises(edl.PackagingError) as ctx:
                edl.package(args)
        self.assertIn("firehose", str(ctx.exception))
        self.assertFalse(os.path.exists(self.out))

    def test_g5_corruption_after_pin_capture(self) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G5_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G5_PROFILE)
        new_profile = _replace_profile_pins(edl.G5_PROFILE, pins)
        loader = os.path.join(self.root, "loader")
        for role, arcname, _s, _h in edl.G5_PROFILE["materials"]:
            with open(materials[role], "rb") as handle:
                _write(os.path.join(loader, arcname.rsplit("/", 1)[-1]), handle.read())
        target_role = "image36"
        target_arc = next(a for r, a, *_ in edl.G5_PROFILE["materials"] if r == target_role)
        target_name = target_arc.rsplit("/", 1)[-1]
        with open(os.path.join(loader, target_name), "ab") as handle:
            handle.write(b"corrupt")
        args = _args(common, self.out, "tb323fu", loader_root=loader)
        with mock.patch.dict(edl.G5_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            with self.assertRaises(edl.PackagingError) as ctx:
                edl.package(args)
        self.assertIn(target_role, str(ctx.exception))
        self.assertFalse(os.path.exists(self.out))

    def test_old_client_rejected_before_output(self) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G4_PROFILE)
        real_client = edl.FIXED_PINS["client"]
        wrong_client = (len(b"old"), _sha(b"old"))
        pins["client"] = wrong_client
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"])
        with mock.patch.dict(edl.G4_PROFILE, _replace_profile_pins(edl.G4_PROFILE, pins), clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            with self.assertRaises(edl.PackagingError) as ctx:
                edl.package(args)
        self.assertIn("client", str(ctx.exception))
        self.assertNotEqual(wrong_client, real_client)
        self.assertFalse(os.path.exists(self.out))

    def test_missing_loader_root(self) -> None:
        common = _common_fixtures(self.root)
        args = _args(common, self.out, "tb323fu")
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("loader-root", str(ctx.exception))

    def test_missing_material(self) -> None:
        common = _common_fixtures(self.root)
        loader = os.path.join(self.root, "loader")
        for _role, arcname, _s, _h in edl.G5_PROFILE["materials"][1:]:
            _write(os.path.join(loader, arcname.rsplit("/", 1)[-1]), b"x")
        args = _args(common, self.out, "tb323fu", loader_root=loader)
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("firehose", str(ctx.exception))

    def test_missing_g4_firehose(self) -> None:
        common = _common_fixtures(self.root)
        args = _args(common, self.out, "tb322fc")
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("--firehose", str(ctx.exception))

    def test_missing_tb710fu_firehose(self) -> None:
        common = _common_fixtures(self.root)
        args = _args(common, self.out, "tb710fu")
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("--firehose", str(ctx.exception))

    def test_unknown_profile(self) -> None:
        common = _common_fixtures(self.root)
        args = _args(common, self.out, "nope", firehose=None)
        with self.assertRaises(edl.PackagingError) as ctx:
            edl.package(args)
        self.assertIn("unknown profile", str(ctx.exception))

    def _rebuilt_client_fixtures(self) -> tuple[dict[str, str], dict[str, tuple[int, str]], str]:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G4_PROFILE)
        # Replace the client source with a fresh build and pin it explicitly.
        rebuilt = _write(os.path.join(self.root, "common", "client-rebuilt.bin"), b"rebuilt-client-bytes")
        common["client"] = rebuilt
        pins["client"] = (len(b"rebuilt-client-bytes"), _sha(b"rebuilt-client-bytes"))
        pins_path = os.path.join(self.root, "build-pins.json")
        with open(pins_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schemaVersion": 1,
                    "tools": {
                        "client": {"bytes": pins["client"][0], "sha256": pins["client"][1]},
                        "packer": {"bytes": 1, "sha256": "0" * 64},
                        "unpacker": {"bytes": 1, "sha256": "0" * 64},
                    },
                },
                handle,
            )
        return common, pins, pins_path

    def test_rebuilt_client_accepted_with_provided_record(self) -> None:
        common, pins, pins_path = self._rebuilt_client_fixtures()
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        new_profile = _replace_profile_pins(edl.G4_PROFILE, pins)
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"])
        args.build_pins_json = pins_path
        # Deliberately pin the client to a DIFFERENT value inside the patch so a
        # successful package proves the explicit build pin overrides FIXED_PINS.
        default_client_pin = edl.FIXED_PINS["client"]
        override_pins = dict(pins)
        override_pins["client"] = default_client_pin
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, override_pins, clear=True):
            frozen_inside_before = edl.FIXED_PINS["client"]
            self.assertEqual(frozen_inside_before, default_client_pin)
            self.assertNotEqual(frozen_inside_before, pins["client"])
            report = edl.package(args)
            self.assertEqual(edl.FIXED_PINS["client"], frozen_inside_before)
        self.assertTrue(os.path.isfile(self.out))
        # Global FIXED_PINS unchanged by the call.
        self.assertEqual(edl.FIXED_PINS["client"], default_client_pin)
        with zipfile.ZipFile(self.out) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        entry = next(e for e in manifest["entries"] if e["role"] == "client")
        self.assertEqual(entry["sha256"], _sha(b"rebuilt-client-bytes"))
        self.assertIsNotNone(report)

    def test_rebuilt_client_rejected_when_record_mismatches(self) -> None:
        common, pins, pins_path = self._rebuilt_client_fixtures()
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        new_profile = _replace_profile_pins(edl.G4_PROFILE, pins)
        with open(pins_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data["tools"]["client"]["sha256"] = "1" * 64
        with open(pins_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"])
        args.build_pins_json = pins_path
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            with self.assertRaises(edl.PackagingError) as ctx:
                edl.package(args)
        self.assertIn("client", str(ctx.exception).lower())
        self.assertFalse(os.path.exists(self.out))

    def test_rebuilt_client_rejected_without_record(self) -> None:
        common, pins, _pins_path = self._rebuilt_client_fixtures()
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        # Re-pin all OTHER roles via FIXED_PINS but leave the frozen client pin intact
        # by only overriding the frozen value for the old bytes.
        frozen_client = edl.FIXED_PINS["client"]
        materials_only = {k: v for k, v in pins.items() if k != "client"}
        new_profile = _replace_profile_pins(edl.G4_PROFILE, {**materials_only, "client": frozen_client})
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"])
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, {**materials_only, "client": frozen_client}, clear=True):
            with self.assertRaises(edl.PackagingError) as ctx:
                edl.package(args)
        self.assertIn("client", str(ctx.exception).lower())
        self.assertFalse(os.path.exists(self.out))

    def test_malformed_client_pin_refused(self) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G4_PROFILE)
        new_profile = _replace_profile_pins(edl.G4_PROFILE, pins)
        pins_path = os.path.join(self.root, "bad-pins.json")
        with open(pins_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        args = _args(common, self.out, "tb322fc", firehose=materials["firehose"])
        args.build_pins_json = pins_path
        with mock.patch.dict(edl.G4_PROFILE, new_profile, clear=True), \
             mock.patch.dict(edl.FIXED_PINS, pins, clear=True):
            with self.assertRaises(edl.PackagingError):
                edl.package(args)
        self.assertFalse(os.path.exists(self.out))

    def test_cli_old_args_parse(self) -> None:
        common = _common_fixtures(self.root)
        materials = _material_fixtures(self.root, edl.G4_PROFILE)
        pins = _patched_pins({**common, **materials}, edl.G4_PROFILE)
        argv = ["--output", self.out, "--firehose", materials["firehose"]]
        for role, flag, _help in edl.COMMON_FLAGS:
            argv.extend([flag, common[role]])
        captured: dict[str, object] = {}
        sentinel = {"profileId": "g4-9008-259"}

        def fake_package(ns):
            captured["args"] = ns
            return sentinel

        with mock.patch.object(edl, "package", side_effect=fake_package):
            rc = edl.main(argv)
        self.assertEqual(rc, 0)
        ns = captured["args"]
        self.assertEqual(ns.profile, "tb322fc")
        self.assertEqual(ns.output, self.out)
        self.assertEqual(ns.firehose, materials["firehose"])
        for role, _flag, _help in edl.COMMON_FLAGS:
            self.assertEqual(getattr(ns, role), common[role])
        # Old Namespace without build_pins_json must still be accepted.
        self.assertIsNone(getattr(ns, "build_pins_json", None))


if __name__ == "__main__":
    unittest.main()
