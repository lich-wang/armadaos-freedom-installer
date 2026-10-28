"""S008 focused RED tests for the AVB stock-boot JSON CLI contract.

Exactly seven unittest methods, stdlib only. These tests describe the frozen
contract only; they do not exercise or duplicate the 43 frozen crypto tests.

At stub stage ``avb_stock_cli.main`` raises ``NotImplementedError`` on purpose,
so the boundary/integration methods are expected to fail (RED). Failure is the
signal that S009 still has to implement the bridge; no test here swallows
``NotImplementedError`` or treats it as a valid response.
"""

import contextlib
import inspect
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_TEST_DIR = pathlib.Path(__file__).resolve().parent
# Supports both layouts: canonical tests/ subdir (module in its parent) and the
# sibling cli-generated layout (module next to this file).
_SEARCH_DIRS = (_TEST_DIR, _TEST_DIR.parent)
for _candidate in _SEARCH_DIRS:
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

import avb_stock_cli  # noqa: E402  (path bootstrap above must run first)

CLI_PATH = pathlib.Path(avb_stock_cli.__file__).resolve()

ASSET_ROOT_ENV = "AVB_TEST_ASSET_ROOT"

STOCK_BOOT_A = "stock_boot_a.img"
VBMETA_A = "vbmeta_a.img"
CURRENT_BOOT_A = "current_boot_a.img"

EXPECTED_STOCK_SHA256 = (
    "b428a31dadc5db3f91620c1f4114f5ee7702e34e0789ed9bf84a878a49898f20"
)
EXPECTED_FINGERPRINT = (
    "Lenovo/TB322FC_PRC/TB322FC:16/BQ2A.250610.001-BP2A.250605.031.A3/"
    "ZUXOS_1.5.10.259_260611_PRC:user/release-keys"
)

EVIDENCE_FIELDS = (
    "slot",
    "stock_sha256",
    "fingerprint",
    "os_version",
    "security_patch",
    "root_key_sha256",
    "chain_key_sha256",
    "boot_rollback_index",
    "boot_rollback_index_location",
    "slot_vbmeta_rollback_index",
    "slot_vbmeta_rollback_index_location",
    "hardware_rollback_verified",
    "proof",
)


def _asset_root():
    """Return the AVB asset root, or None when the environment is unset."""
    raw = os.environ.get(ASSET_ROOT_ENV, "").strip()
    if not raw:
        return None
    return pathlib.Path(raw)


def _base_request():
    """Schema-version-1 request template using paths that are never opened."""
    return {
        "schemaVersion": 1,
        "stockBootPath": "dummy-stock-boot.img",
        "currentBootPath": "dummy-current-boot.img",
        "slotVbmetaPath": "dummy-vbmeta.img",
        "trustedBaselinePath": "dummy-baseline.img",
        "slot": "a",
        "model": "TB322FC",
        "partitionSizeBytes": 100663296,
    }


class AvbStockCliContractTest(unittest.TestCase):
    # ------------------------------------------------------------------ helpers
    def _subprocess_env(self):
        env = os.environ.copy()
        search = [str(path) for path in _SEARCH_DIRS]
        existing = env.get("PYTHONPATH")
        if existing:
            search.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(search)
        return env

    def _run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI_PATH), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._subprocess_env(),
        )

    def _invoke_main(self, argv):
        """Call main in-process, capturing the stdout/stderr boundary."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = avb_stock_cli.main(list(argv))
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _parse_single_json(self, stdout):
        text = stdout.strip()
        self.assertTrue(text, "stdout must carry exactly one JSON document")
        self.assertNotIn("Traceback", stdout)
        decoder = json.JSONDecoder()
        payload, end = decoder.raw_decode(text)
        self.assertEqual(
            text[end:].strip(), "", "stdout must hold one JSON value and nothing else"
        )
        return payload

    def _assert_error(self, stdout, expected_kind, expected_exit, exit_code):
        self.assertIs(type(exit_code), int)
        self.assertEqual(exit_code, expected_exit)
        payload = self._parse_single_json(stdout)
        self.assertIsInstance(payload, dict)
        self.assertEqual(set(payload), {"schemaVersion", "ok", "error"})
        self.assertIs(type(payload["schemaVersion"]), int)
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertIs(payload["ok"], False)
        error = payload["error"]
        self.assertIsInstance(error, dict)
        self.assertEqual(set(error), {"kind", "message"})
        self.assertEqual(error["kind"], expected_kind)
        self.assertIsInstance(error["message"], str)
        self.assertTrue(error["message"].strip(), "error.message must be nonempty")

    # -------------------------------------------------------------- test 1
    def test_import_is_inert_and_main_is_callable(self):
        self.assertTrue(callable(avb_stock_cli.main))
        parameters = list(inspect.signature(avb_stock_cli.main).parameters.values())
        self.assertEqual([parameter.name for parameter in parameters], ["argv"])
        self.assertIsNone(parameters[0].default)

        completed = subprocess.run(
            [sys.executable, "-c", "import avb_stock_cli"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._subprocess_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "")
        self.assertNotIn("Traceback", completed.stderr)

    # -------------------------------------------------------------- test 2
    def test_actual_assets_success_integration(self):
        asset_root = _asset_root()
        if asset_root is None:
            self.skipTest("%s not set; real AVB assets unavailable" % ASSET_ROOT_ENV)

        stock_boot = asset_root / STOCK_BOOT_A
        slot_vbmeta = asset_root / VBMETA_A
        current_boot = asset_root / CURRENT_BOOT_A
        for asset in (stock_boot, slot_vbmeta, current_boot):
            self.assertTrue(
                asset.is_file(), "required AVB test asset missing: %s" % asset
            )

        request = {
            "schemaVersion": 1,
            "stockBootPath": str(stock_boot),
            "currentBootPath": str(current_boot),
            "slotVbmetaPath": str(slot_vbmeta),
            "trustedBaselinePath": str(slot_vbmeta),
            "slot": "a",
            "model": "TB322FC",
            "partitionSizeBytes": 100663296,
        }

        with tempfile.TemporaryDirectory(prefix="s008 成功 a1-") as temp_dir:
            request_path = pathlib.Path(temp_dir) / "请求 payload a.json"
            request_path.write_text(
                json.dumps(request, ensure_ascii=False), encoding="utf-8"
            )
            completed = self._run_cli(str(request_path))

        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual(
            completed.returncode, 0, "expected exit 0; stderr=%r" % completed.stderr
        )

        payload = self._parse_single_json(completed.stdout)
        self.assertEqual(set(payload), {"schemaVersion", "ok", "evidence"})
        self.assertIs(type(payload["schemaVersion"]), int)
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertIs(payload["ok"], True)

        evidence = payload["evidence"]
        self.assertIsInstance(evidence, dict)
        for field in EVIDENCE_FIELDS:
            self.assertIn(field, evidence)
        self.assertEqual(evidence["slot"], "a")
        self.assertEqual(evidence["stock_sha256"], EXPECTED_STOCK_SHA256)
        self.assertEqual(evidence["fingerprint"], EXPECTED_FINGERPRINT)
        self.assertEqual(evidence["proof"], "saved-baseline-pair")
        self.assertIs(evidence["hardware_rollback_verified"], False)

    # -------------------------------------------------------------- test 3
    def test_actual_assets_full_stock_padding_tamper_is_validation_error(self):
        asset_root = _asset_root()
        if asset_root is None:
            self.skipTest("%s not set; real AVB assets unavailable" % ASSET_ROOT_ENV)

        stock_boot = asset_root / STOCK_BOOT_A
        slot_vbmeta = asset_root / VBMETA_A
        current_boot = asset_root / CURRENT_BOOT_A
        for asset in (stock_boot, slot_vbmeta, current_boot):
            self.assertTrue(
                asset.is_file(), "required AVB test asset missing: %s" % asset
            )

        with tempfile.TemporaryDirectory(prefix="s008 篡改 a1-") as temp_dir:
            tampered = pathlib.Path(temp_dir) / "stock tampered copy.img"
            shutil.copyfile(stock_boot, tampered)

            size = tampered.stat().st_size
            offset = size - 65
            self.assertGreater(offset, 0, "stock image too small for padding tamper")
            with open(tampered, "r+b") as handle:
                handle.seek(offset)
                original = handle.read(1)
                self.assertEqual(len(original), 1)
                flipped = bytes([original[0] ^ 0xFF])
                handle.seek(offset)
                handle.write(flipped)

            request = {
                "schemaVersion": 1,
                "stockBootPath": str(tampered),
                "currentBootPath": str(current_boot),
                "slotVbmetaPath": str(slot_vbmeta),
                "trustedBaselinePath": str(slot_vbmeta),
                "slot": "a",
                "model": "TB322FC",
                "partitionSizeBytes": 100663296,
            }
            request_path = pathlib.Path(temp_dir) / "请求 tamper a.json"
            request_path.write_text(
                json.dumps(request, ensure_ascii=False), encoding="utf-8"
            )
            exit_code, stdout, stderr = self._invoke_main([str(request_path)])

        self.assertNotIn("Traceback", stderr)
        self._assert_error(stdout, "validation", 2, exit_code)

    # -------------------------------------------------------------- test 4
    def test_invalid_requests_are_input_errors(self):
        cases = []
        cases.append(("malformed-json", "{not json"))
        cases.append(("non-object-json", "[1, 2, 3]"))

        for label, value in (
            ("schemaVersion-true", True),
            ("schemaVersion-two", 2),
            ("schemaVersion-string", "1"),
        ):
            request = _base_request()
            request["schemaVersion"] = value
            cases.append((label, request))

        missing_field = _base_request()
        del missing_field["model"]
        cases.append(("missing-field", missing_field))

        for label, value in (
            ("size-bool", True),
            ("size-zero", 0),
            ("size-negative", -1),
        ):
            request = _base_request()
            request["partitionSizeBytes"] = value
            cases.append((label, request))

        for label, value in (
            ("slot-uppercase", "A"),
            ("slot-empty", ""),
            ("slot-both", "ab"),
        ):
            request = _base_request()
            request["slot"] = value
            cases.append((label, request))

        caller_fingerprint = _base_request()
        caller_fingerprint["expectedFingerprint"] = "0" * 64
        cases.append(("caller-expected-fingerprint", caller_fingerprint))

        with tempfile.TemporaryDirectory(prefix="s008 无效 req-") as temp_dir:
            temp_path = pathlib.Path(temp_dir)
            for label, case in cases:
                with self.subTest(case=label):
                    request_path = temp_path / ("request-%s.json" % label)
                    if isinstance(case, str):
                        request_path.write_text(case, encoding="utf-8")
                    else:
                        request_path.write_text(
                            json.dumps(case, ensure_ascii=False), encoding="utf-8"
                        )
                    exit_code, stdout, stderr = self._invoke_main(
                        [str(request_path)]
                    )
                    self.assertNotIn("Traceback", stderr)
                    self._assert_error(stdout, "input", 3, exit_code)

    # -------------------------------------------------------------- test 5
    def test_missing_io_inputs_are_io_errors(self):
        with tempfile.TemporaryDirectory(prefix="s008 缺失 io-") as temp_dir:
            temp_path = pathlib.Path(temp_dir)

            with self.subTest(case="missing-request-file"):
                absent_request = temp_path / "absent-request.json"
                exit_code, stdout, stderr = self._invoke_main([str(absent_request)])
                self.assertNotIn("Traceback", stderr)
                self._assert_error(stdout, "io", 4, exit_code)

            with self.subTest(case="missing-image-files"):
                request = {
                    "schemaVersion": 1,
                    "stockBootPath": str(temp_path / "no-stock-boot.img"),
                    "currentBootPath": str(temp_path / "no-current-boot.img"),
                    "slotVbmetaPath": str(temp_path / "no-vbmeta.img"),
                    "trustedBaselinePath": str(temp_path / "no-vbmeta.img"),
                    "slot": "a",
                    "model": "TB322FC",
                    "partitionSizeBytes": 100663296,
                }
                present_request = temp_path / "request-missing-images.json"
                present_request.write_text(
                    json.dumps(request, ensure_ascii=False), encoding="utf-8"
                )
                exit_code, stdout, stderr = self._invoke_main([str(present_request)])
                self.assertNotIn("Traceback", stderr)
                self._assert_error(stdout, "io", 4, exit_code)

    # -------------------------------------------------------------- test 6
    def test_no_arguments_is_input_error(self):
        exit_code, stdout, stderr = self._invoke_main([])
        self.assertNotIn("Traceback", stderr)
        self._assert_error(stdout, "input", 3, exit_code)

    # -------------------------------------------------------------- test 7
    def test_extra_arguments_is_input_error(self):
        exit_code, stdout, stderr = self._invoke_main(["first.json", "second.json"])
        self.assertNotIn("Traceback", stderr)
        self._assert_error(stdout, "input", 3, exit_code)


if __name__ == "__main__":
    unittest.main()
