"""Offline synthetic tests for the RAM-only TF-card service (armada_tf).

Everything runs on synthetic filesystem fixtures under a temporary directory.
Only the block-device boundary (open/fstat/flock) is mocked so the selected
synthetic SD node routes to a small temporary sparse regular image; all
production S_ISBLK/major:minor/RAM-root guards stay active. No real /dev,
no root requirement, no network beyond a loopback test server.
"""

from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import armada_tf

MODEL_ELDER = "TB322FC"
COMPATIBLE_ELDER = b"lenovo,elden\x00qcom,sm8750\x00"
MODEL_BALDUR = "TB323FU"
COMPATIBLE_BALDUR = b"lenovo,baldur\x00qcom,kaanapali\x00"
BOOT_ID = "0f3d2a1b-8c4e-4d5f-9a6b-7c8d9e0f1a2b"
BOOT_ID_OTHER = "1f3d2a1b-8c4e-4d5f-9a6b-7c8d9e0f1a2c"
KERNEL_SHA = "ab" * 32
CID = "0123456789abcdef0123456789abcdef"
CID_OTHER = "0123456789abcdef0123456789abcdee"
TOKEN = "c1" * 32
SERIAL = "0x1a2b3c4d"
CARD_SECTORS = 4096
CARD_BYTES = CARD_SECTORS * 512
CARD_DEV = "8:16"
PARTITION_DEV = "8:17"
FILL = b"\xab"


def marker_document(model=MODEL_ELDER, kernel_sha=KERNEL_SHA,
                    protocol="tf-card-v1", schema=1, drop=None, extra=None):
    document = {
        "schema": schema,
        "expectedModel": model,
        "kernelSha256": kernel_sha,
        "transportProtocol": protocol,
    }
    if drop:
        document.pop(drop, None)
    if extra:
        document.update(extra)
    return document


class _FakeStat:
    def __init__(self, mode, rdev=0):
        self.st_mode = mode
        self.st_rdev = rdev


class CardHarness:
    """Routes the synthetic SD node to a temporary sparse regular image."""

    def __init__(self, image_path, node, major=8, minor=16):
        self.image = Path(image_path)
        self.node = node
        self.major = major
        self.minor = minor
        self.fd = None
        self.fail_open = False
        self.fail_flock = False
        self.fstat_regular = False
        self.fstat_wrong_rdev = False
        self.flock_calls = 0
        self._patches = []

    def start(self, testcase):
        real_open = os.open
        real_fstat = os.fstat
        real_flock = fcntl.flock
        harness = self

        def fake_open(path, flags, mode=0o777):
            if isinstance(path, str) and path == harness.node:
                if harness.fail_open:
                    raise OSError(16, "synthetic open failure")
                harness.fd = real_open(str(harness.image), flags, mode)
                return harness.fd
            return real_open(path, flags, mode)

        def fake_fstat(fd):
            if harness.fd is not None and fd == harness.fd:
                if harness.fstat_regular:
                    return _FakeStat(stat.S_IFREG | 0o600)
                rdev = os.makedev(harness.major, harness.minor)
                if harness.fstat_wrong_rdev:
                    rdev = os.makedev(harness.major, harness.minor + 40)
                return _FakeStat(stat.S_IFBLK | 0o660, rdev=rdev)
            return real_fstat(fd)

        def fake_flock(fd, operation):
            if harness.fd is not None and fd == harness.fd:
                harness.flock_calls += 1
                if harness.fail_flock:
                    raise OSError(11, "synthetic lock failure")
                return None
            return real_flock(fd, operation)

        for patcher in (
            mock.patch.object(os, "open", fake_open),
            mock.patch.object(os, "fstat", fake_fstat),
            mock.patch.object(fcntl, "flock", fake_flock),
        ):
            patcher.start()
            self._patches.append(patcher)
        testcase.addCleanup(self.stop)

    def stop(self):
        for patcher in reversed(self._patches):
            patcher.stop()
        self._patches = []
        self.fd = None


class ServiceTestBase(unittest.TestCase):
    """Builds the synthetic RAM runtime and one valid synthetic SD card."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.run_dir = self.root / "run" / "freedom-tf"
        self.run_dir.mkdir(parents=True)
        self.sys_block = self.root / "sys" / "class" / "block"
        self.dev_dir = self.root / "dev"
        self.dev_dir.mkdir()
        self.proc_dir = self.root / "proc"
        (self.proc_dir / "self").mkdir(parents=True)
        (self.proc_dir / "sys" / "kernel" / "random").mkdir(parents=True)
        (self.root / "sys" / "firmware" / "devicetree" / "base").mkdir(
            parents=True)
        (self.root / "sys" / "devices" / "soc0").mkdir(parents=True)
        self.images = self.root / "images"
        self.images.mkdir()
        (self.sys_block).mkdir(parents=True)

        self.token_path = self.run_dir / "token"
        self.marker_path = self.run_dir / "tf-maintenance.json"
        self.compatible_path = (
            self.root / "sys" / "firmware" / "devicetree" / "base" / "compatible")
        self.serial_path = self.root / "sys" / "devices" / "soc0" / "serial_number"
        self.boot_id_path = (
            self.proc_dir / "sys" / "kernel" / "random" / "boot_id")
        self.mountinfo_path = self.proc_dir / "self" / "mountinfo"
        self.swaps_path = self.proc_dir / "swaps"

        self.write_token(TOKEN)
        self.write_marker()
        self.write_compatible(COMPATIBLE_ELDER)
        self.write_serial(SERIAL)
        self.write_boot_id(BOOT_ID)
        self.write_swaps("")
        self.write_mountinfo(self.ram_mountinfo())
        self.add_card("mmcblk1", CID, dev=CARD_DEV)
        self.card_node = str(self.dev_dir / "mmcblk1")

    # -- fixture writers ---------------------------------------------------
    def attr(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="ascii")

    def write_token(self, text: str) -> None:
        self.token_path.write_text(text + "\n", encoding="ascii")

    def write_marker(self, **kwargs) -> None:
        self.marker_path.write_text(
            json.dumps(marker_document(**kwargs)), encoding="ascii")

    def write_compatible(self, raw: bytes) -> None:
        self.compatible_path.write_bytes(raw)

    def write_serial(self, text: str) -> None:
        self.serial_path.write_text(text + "\n", encoding="ascii")

    def write_boot_id(self, text: str) -> None:
        self.boot_id_path.write_text(text + "\n", encoding="ascii")

    def write_mountinfo(self, text: str) -> None:
        self.mountinfo_path.write_text(text, encoding="ascii")

    def write_swaps(self, text: str) -> None:
        self.swaps_path.write_text(text, encoding="ascii")

    def ram_mountinfo(self, root_fstype: str = "rootfs", extra: str = "") -> str:
        lines = []
        for target, fstype in (("/", root_fstype),
                               ("/tmp", "tmpfs"),
                               ("/run", "tmpfs")):
            try:
                dev = os.stat(target).st_dev
            except OSError:
                dev = os.stat("/").st_dev
            lines.append(
                f"11 0 {os.major(dev)}:{os.minor(dev)} / {target} rw "
                f"- {fstype} /dev/src rw")
        return "\n".join(lines) + "\n" + extra

    def add_card(self, name: str, cid: str, *, dev: str = "8:32",
                 ro: str = "0", removable: str = "1", devtype: str = "SD",
                 sectors: str = str(CARD_SECTORS), lbs: str = "512") -> Path:
        base = self.sys_block / name
        self.attr(base / "dev", dev)
        self.attr(base / "size", sectors)
        self.attr(base / "ro", ro)
        self.attr(base / "removable", removable)
        if devtype is not None:
            self.attr(base / "device" / "type", devtype)
        if cid is not None:
            self.attr(base / "device" / "cid", cid)
        self.attr(base / "queue" / "logical_block_size", lbs)
        (base / "holders").mkdir(parents=True, exist_ok=True)
        return base

    def add_partition(self, name: str, dev: str) -> None:
        base = self.sys_block / name
        self.attr(base / "partition", "1")
        self.attr(base / "dev", dev)
        self.attr(base / "start", "2048")
        self.attr(base / "size", "1024")

    def make_image(self, name: str, fill: bytes = FILL) -> Path:
        path = self.images / name
        path.write_bytes(fill * CARD_BYTES)
        return path

    def make_service(self, **overrides) -> "armada_tf.TfService":
        kwargs = dict(
            sys_block=self.sys_block,
            dt_compatible=self.compatible_path,
            soc_serial=self.serial_path,
            boot_id=self.boot_id_path,
            self_mountinfo=self.mountinfo_path,
            proc_swaps=self.swaps_path,
            dev_root=self.dev_dir,
            token_path=self.token_path,
            marker_path=self.marker_path,
        )
        kwargs.update(overrides)
        service = armada_tf.TfService(**kwargs)
        self.addCleanup(service.close_all)
        return service

    def loaded_service(self, **overrides) -> "armada_tf.TfService":
        service = self.make_service(**overrides)
        service.load_runtime()
        return service

    def opened(self, service, image=None, cid: str = CID) -> tuple:
        harness = CardHarness(
            image or self.make_image("card1.img"),
            node=str(self.dev_dir / "mmcblk1"))
        harness.start(self)
        result = service.open_card(
            "tablet:sd:" + cid, path=str(self.dev_dir / "mmcblk1"),
            size_bytes=CARD_BYTES, sector_size=512)
        return result["cardSessionId"], harness

    def full_key(self, cid: str = CID) -> str:
        return "tablet:sd:" + cid

    def assert_tf_error(self, callable_obj, *args, code: str, **kwargs) -> None:
        with self.assertRaises(armada_tf.TfError) as caught:
            callable_obj(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class RamEnvironmentTests(ServiceTestBase):
    def test_valid_runtime_identity(self):
        service = self.make_service()
        identity = service.load_runtime()
        self.assertEqual(identity.model, MODEL_ELDER)
        self.assertEqual(identity.soc, "sm8750")
        self.assertEqual(identity.soc_serial, SERIAL)
        self.assertEqual(identity.boot_id, BOOT_ID)
        self.assertEqual(identity.kernel_sha256, KERNEL_SHA)
        self.assertIn("lenovo,elden", identity.compatible)
        self.assertIn("qcom,sm8750", identity.compatible)

    def test_valid_runtime_second_model(self):
        self.write_marker(model=MODEL_BALDUR)
        self.write_compatible(COMPATIBLE_BALDUR)
        identity = self.make_service().load_runtime()
        self.assertEqual(identity.model, MODEL_BALDUR)
        self.assertEqual(identity.soc, "kaanapali")

    def test_ext4_root_rejected(self):
        self.write_mountinfo(self.ram_mountinfo(root_fstype="ext4"))
        self.assert_tf_error(
            self.make_service().load_runtime, code="not-ram-root")

    def test_btrfs_root_rejected(self):
        self.write_mountinfo(self.ram_mountinfo(root_fstype="btrfs"))
        self.assert_tf_error(
            self.make_service().load_runtime, code="not-ram-root")

    def test_missing_tmp_mount_rejected(self):
        lines = self.ram_mountinfo().splitlines()
        self.write_mountinfo(lines[0] + "\n")
        self.assert_tf_error(
            self.make_service().load_runtime, code="ram-root-unverified")

    def test_marker_rejections(self):
        cases = [
            {"schema": 2},
            {"schema": True},
            {"drop": "kernelSha256"},
            {"extra": {"surprise": 1}},
            {"kernel_sha": "ab" * 31},
            {"kernel_sha": "AB" * 32},
            {"protocol": "tf-card-v2"},
            {"model": "TB999XX"},
        ]
        for kwargs in cases:
            with self.subTest(**kwargs):
                self.write_marker(**kwargs)
                self.assert_tf_error(
                    self.make_service().load_runtime, code="marker-invalid")

    def test_marker_file_missing(self):
        self.marker_path.unlink()
        self.assert_tf_error(
            self.make_service().load_runtime, code="marker-unreadable")

    def test_marker_alone_is_not_kernel_proof(self):
        # A perfectly valid marker with a foreign device tree must fail.
        self.write_compatible(COMPATIBLE_BALDUR)
        self.assert_tf_error(
            self.make_service().load_runtime, code="unknown-device")

    def test_empty_serial_rejected(self):
        self.write_serial("   ")
        self.assert_tf_error(
            self.make_service().load_runtime, code="soc-serial-invalid")

    def test_serial_file_missing(self):
        self.serial_path.unlink()
        self.assert_tf_error(
            self.make_service().load_runtime, code="soc-serial-unreadable")

    def test_zero_boot_id_rejected(self):
        self.write_boot_id("00000000-0000-0000-0000-000000000000")
        self.assert_tf_error(
            self.make_service().load_runtime, code="boot-id-invalid")

    def test_noncanonical_boot_id_rejected(self):
        self.write_boot_id(BOOT_ID.upper())
        self.assert_tf_error(
            self.make_service().load_runtime, code="boot-id-invalid")

    def test_malformed_boot_id_rejected(self):
        self.write_boot_id("not-a-uuid")
        self.assert_tf_error(
            self.make_service().load_runtime, code="boot-id-invalid")

    def test_token_missing(self):
        self.token_path.unlink()
        self.assert_tf_error(
            armada_tf.load_token, self.token_path, code="token-unreadable")

    def test_token_symlink_rejected(self):
        link = self.run_dir / "token-link"
        link.symlink_to(self.token_path)
        self.assert_tf_error(
            armada_tf.load_token, link, code="token-unreadable")

    def test_token_short_rejected(self):
        self.write_token("a" * 63)
        self.assert_tf_error(
            armada_tf.load_token, self.token_path, code="token-invalid")

    def test_token_uppercase_rejected(self):
        self.write_token("C1" * 32)
        self.assert_tf_error(
            armada_tf.load_token, self.token_path, code="token-invalid")

    def test_token_valid_value_roundtrip(self):
        self.assertEqual(armada_tf.load_token(self.token_path), TOKEN)


class InventoryTests(ServiceTestBase):
    def test_inventory_lists_only_the_valid_sd(self):
        self.add_card("mmcblk0", CID_OTHER, devtype="MMC", dev="8:48")
        self.add_card("mmcblk2", CID_OTHER, ro="1", dev="8:56")
        self.add_card("mmcblk3", "zz-not-hex", dev="8:64")
        self.add_card("mmcblk4", CID_OTHER, removable="0", dev="8:72")
        self.add_partition("mmcblk1p1", PARTITION_DEV)
        service = self.loaded_service()
        document = service.inspect()

        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(document["source"], "tablet")
        self.assertEqual(document["protocol"], "tf-card-v1")
        self.assertEqual(document["model"], MODEL_ELDER)
        self.assertEqual(document["soc"], "sm8750")
        self.assertEqual(document["socSerial"], SERIAL)
        self.assertEqual(document["bootId"], BOOT_ID)
        self.assertEqual(document["kernelSha256"], KERNEL_SHA)
        self.assertTrue(document["ramOnly"])

        self.assertEqual(len(document["media"]), 1)
        media = document["media"][0]
        self.assertEqual(media["key"], "sd:" + CID)
        self.assertEqual(media["path"], self.card_node)
        self.assertEqual(media["displayName"], "SD card")
        self.assertEqual(media["sizeBytes"], CARD_BYTES)
        self.assertEqual(media["logicalSectorSize"], 512)
        self.assertEqual(media["mediumEvidence"], "SD")
        self.assertFalse(media["readOnly"])
        self.assertFalse(media["isSystemDisk"])
        self.assertFalse(media["isOffline"])
        self.assertFalse(media["mounted"])
        self.assertEqual(media["androidUsage"], "unknown")

    def test_duplicate_cid_rejected(self):
        self.add_card("mmcblk5", CID, dev="8:80")
        service = self.loaded_service()
        self.assert_tf_error(service.discover_cards, code="duplicate-card")

    def test_inspect_requires_runtime(self):
        self.assert_tf_error(
            self.make_service().inspect, code="not-started")


class OpenSessionTests(ServiceTestBase):
    def open_args(self, cid=CID, path=None, size=CARD_BYTES, sector=512):
        return (self.full_key(cid),
                {"path": path or self.card_node,
                 "size_bytes": size, "sector_size": sector})

    def test_open_rejects_holder(self):
        (self.sys_block / "mmcblk1" / "holders" / "dm-0").write_text("")
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="card-busy", **kwargs)
        self.assertIsNone(harness.fd)

    def test_open_rejects_mounted(self):
        extra = f"12 0 {CARD_DEV} / /mnt/card rw - ext4 /dev/mmcblk1 rw\n"
        self.write_mountinfo(self.ram_mountinfo(extra=extra))
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="card-busy", **kwargs)
        self.assertIsNone(harness.fd)

    def test_open_rejects_swap(self):
        node = self.card_node
        real_stat = os.stat

        def fake_stat(path, *args, **kwargs):
            if str(path) == node:
                return _FakeStat(stat.S_IFBLK, rdev=os.makedev(8, 16))
            return real_stat(path, *args, **kwargs)

        self.write_swaps(
            "Filename Type Size Used Priority\n"
            f"{node} partition 2048 0 -2\n")
        service = self.loaded_service(stat_fn=fake_stat)
        harness = CardHarness(self.make_image("card1.img"), node=node)
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="card-busy", **kwargs)
        self.assertIsNone(harness.fd)

    def test_open_rejects_partition_held(self):
        self.add_partition("mmcblk1p1", PARTITION_DEV)
        extra = f"12 0 {PARTITION_DEV} / /mnt/part rw - vfat /dev/mmcblk1p1 rw\n"
        self.write_mountinfo(self.ram_mountinfo(extra=extra))
        service = self.loaded_service()
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="card-busy", **kwargs)

    def test_open_rejects_unknown_key(self):
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.start(self)
        key, kwargs = self.open_args(cid=CID_OTHER)
        self.assert_tf_error(
            service.open_card, key, code="card-unknown", **kwargs)
        self.assertIsNone(harness.fd)

    def test_open_rejects_malformed_key(self):
        service = self.loaded_service()
        with self.assertRaises(armada_tf.TfError) as caught:
            service.open_card("sd:" + CID, path=self.card_node,
                              size_bytes=CARD_BYTES, sector_size=512)
        self.assertEqual(caught.exception.code, "key-invalid")

    def test_open_rejects_changed_path(self):
        service = self.loaded_service()
        key, kwargs = self.open_args(path="/dev/other")
        self.assert_tf_error(
            service.open_card, key, code="card-changed", **kwargs)

    def test_open_rejects_changed_size(self):
        service = self.loaded_service()
        key, kwargs = self.open_args(size=CARD_BYTES + 512)
        self.assert_tf_error(
            service.open_card, key, code="card-changed", **kwargs)

    def test_open_rejects_changed_sector(self):
        service = self.loaded_service()
        key, kwargs = self.open_args(sector=4096)
        self.assert_tf_error(
            service.open_card, key, code="card-changed", **kwargs)

    def test_open_rejects_second_session(self):
        service = self.loaded_service()
        first, _ = self.opened(service)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="session-active", **kwargs)

    def test_open_rejects_open_failure(self):
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.fail_open = True
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="device-open-failed", **kwargs)

    def test_open_rejects_flock_failure(self):
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.fail_flock = True
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="device-locked", **kwargs)

    def test_open_rejects_regular_file_stat(self):
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.fstat_regular = True
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="not-block-device", **kwargs)

    def test_open_rejects_wrong_rdev(self):
        service = self.loaded_service()
        harness = CardHarness(self.make_image("card1.img"), node=self.card_node)
        harness.fstat_wrong_rdev = True
        harness.start(self)
        key, kwargs = self.open_args()
        self.assert_tf_error(
            service.open_card, key, code="device-identity-mismatch", **kwargs)


class SessionIoTests(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.service = self.loaded_service()
        self.image = self.make_image("card1.img")
        self.session_id, self.harness = self.opened(self.service, self.image)

    def image_bytes(self) -> bytes:
        return self.image.read_bytes()

    def test_write_read_flush_roundtrip_with_sentinels(self):
        pattern = bytes(range(256)) * 2
        self.service.card_write(self.session_id, 1024, pattern)
        self.assertEqual(
            self.service.card_read(self.session_id, 1024, 512), pattern)
        data = self.image_bytes()
        self.assertEqual(data[:1024], FILL * 1024)
        self.assertEqual(data[1536:], FILL * (CARD_BYTES - 1536))
        self.assertEqual(data[1024:1536], pattern)

        calls = []
        real_fsync = os.fsync

        def recording_fsync(fd):
            calls.append(fd)
            return real_fsync(fd)

        with mock.patch.object(os, "fsync", recording_fsync):
            self.service.card_flush(self.session_id)
        self.assertEqual(calls, [self.harness.fd])

    def test_other_image_untouched(self):
        other = self.make_image("other.img", fill=b"\xcd")
        pattern = b"\x55" * 512
        self.service.card_write(self.session_id, 1024, pattern)
        self.assertEqual(other.read_bytes(), b"\xcd" * CARD_BYTES)

    def test_misaligned_and_overflow_requests_write_nothing(self):
        before = self.image_bytes()
        pattern = b"\x55" * 512
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1025, pattern,
            code="range-invalid")
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 100,
            code="range-invalid")
        self.assert_tf_error(
            self.service.card_write, self.session_id, CARD_BYTES - 512,
            b"\x55" * 1024, code="range-invalid")
        self.assert_tf_error(
            self.service.card_write, "f" * 32, 1024, pattern,
            code="unknown-session")
        self.assertEqual(self.image_bytes(), before)

    def test_empty_payload_rejected(self):
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"",
            code="range-invalid")

    def test_read_range_rejections(self):
        self.assert_tf_error(
            self.service.card_read, self.session_id, CARD_BYTES, 512,
            code="range-invalid")
        self.assert_tf_error(
            self.service.card_read, self.session_id, 1024, 0,
            code="range-invalid")
        self.assert_tf_error(
            self.service.card_read, self.session_id, 1022, 512,
            code="range-invalid")
        self.assert_tf_error(
            self.service.card_read, self.session_id, 0,
            armada_tf.BINARY_MAX_BYTES + 512, code="range-invalid")
        self.assert_tf_error(
            self.service.card_read, "f" * 32, 0, 512,
            code="unknown-session")

    def test_short_read_latches_session(self):
        with self.image.open("r+b") as handle:
            handle.truncate(1 << 20)
        self.assert_tf_error(
            self.service.card_read, self.session_id, 1 << 20, 512,
            code="short-read")
        before = self.image_bytes()
        self.assert_tf_error(
            self.service.card_write, self.session_id, 0, b"\x55" * 512,
            code="short-read")
        self.assertEqual(self.image_bytes(), before)

    def test_transient_revalidation_error_latches_session(self):
        for target, code in (
            ("discover_cards", "card-changed"),
            ("_read_boot_id", "device-io-failed"),
        ):
            with self.subTest(target=target):
                service = self.loaded_service()
                image = self.make_image(f"latch-{target}.img")
                session_id, _ = self.opened(service, image)
                before = image.read_bytes()
                injected = armada_tf.TfError(code, "injected")
                with mock.patch.object(service, target, side_effect=injected):
                    self.assert_tf_error(
                        service.card_identity, session_id, code=code)
                self.assert_tf_error(
                    service.card_identity, session_id, code=code)
                self.assert_tf_error(
                    service.card_write, session_id, 0, b"\x55" * 512,
                    code=code)
                self.assertEqual(image.read_bytes(), before)

    def test_pwrite_failure_latches_session(self):
        real_pwrite = os.pwrite
        harness = self.harness

        def failing_pwrite(fd, data, offset):
            if fd == harness.fd:
                raise OSError(5, "synthetic write failure")
            return real_pwrite(fd, data, offset)

        before = self.image_bytes()
        with mock.patch.object(os, "pwrite", failing_pwrite):
            self.assert_tf_error(
                self.service.card_write, self.session_id, 1024, b"\x55" * 512,
                code="device-io-failed")
        self.assertEqual(self.image_bytes(), before)
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="device-io-failed")
        result = self.service.card_close(self.session_id)
        self.assertTrue(result["closed"])

    def test_fsync_failure_latches_session(self):
        def failing_fsync(fd):
            raise OSError(5, "synthetic fsync failure")

        with mock.patch.object(os, "fsync", failing_fsync):
            self.assert_tf_error(
                self.service.card_flush, self.session_id, code="flush-failed")
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="flush-failed")

    def test_cid_change_latches_session(self):
        self.attr(self.sys_block / "mmcblk1" / "device" / "cid", CID_OTHER)
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="card-changed")
        self.assert_tf_error(
            self.service.card_read, self.session_id, 1024, 512,
            code="card-changed")

    def test_boot_id_change_latches_session(self):
        self.write_boot_id(BOOT_ID_OTHER)
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="card-changed")

    def test_geometry_change_latches_session(self):
        self.attr(self.sys_block / "mmcblk1" / "size", str(CARD_SECTORS * 2))
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="card-changed")

    def test_device_number_change_latches_session(self):
        self.attr(self.sys_block / "mmcblk1" / "dev", "8:99")
        self.assert_tf_error(
            self.service.card_write, self.session_id, 1024, b"\x55" * 512,
            code="card-changed")

    def test_identity_query_uses_fresh_facts_and_rejects_change(self):
        document = self.service.card_identity(self.session_id)
        identity = document["identity"]
        self.assertEqual(identity["source"], "tablet")
        self.assertEqual(identity["key"], "tablet:sd:" + CID)
        self.assertEqual(identity["path"], self.card_node)
        self.assertEqual(identity["sizeBytes"], CARD_BYTES)
        self.assertEqual(identity["logicalSectorSize"], 512)
        self.assertEqual(
            identity["bindingSha256"],
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 16, self.card_node, CARD_BYTES, 512))

        self.attr(self.sys_block / "mmcblk1" / "device" / "cid", CID_OTHER)
        self.assert_tf_error(
            self.service.card_identity, self.session_id, code="card-changed")

    def test_close_rejects_stale_ids_and_allows_reopen(self):
        result = self.service.card_close(self.session_id)
        self.assertEqual(
            result, {"schemaVersion": 1, "closed": True})
        self.assert_tf_error(
            self.service.card_read, self.session_id, 0, 512,
            code="unknown-session")
        self.assert_tf_error(
            self.service.card_close, self.session_id, code="unknown-session")
        new_id, _ = self.opened(self.service, self.image)
        self.assertNotEqual(new_id, self.session_id)
        self.service.card_write(new_id, 0, b"\x55" * 512)

    def test_unknown_session_shapes(self):
        for bad in ("", "xyz", "A" * 32, "a" * 31):
            with self.subTest(bad=bad):
                self.assert_tf_error(
                    self.service.card_read, bad, 0, 512,
                    code="unknown-session")

    def test_binding_varies_with_facts(self):
        base = armada_tf.binding_sha256(
            BOOT_ID, CID, 8, 16, "/dev/mmcblk1", CARD_BYTES, 512)
        variants = (
            armada_tf.binding_sha256(
                BOOT_ID_OTHER, CID, 8, 16, "/dev/mmcblk1", CARD_BYTES, 512),
            armada_tf.binding_sha256(
                BOOT_ID, CID_OTHER, 8, 16, "/dev/mmcblk1", CARD_BYTES, 512),
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 17, "/dev/mmcblk1", CARD_BYTES, 512),
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 16, "/dev/mmcblk2", CARD_BYTES, 512),
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 16, "/dev/mmcblk1", CARD_BYTES + 512, 512),
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 16, "/dev/mmcblk1", CARD_BYTES, 4096),
        )
        for variant in variants:
            self.assertNotEqual(base, variant)


class HttpProtocolTests(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.service = self.loaded_service()
        self.image = self.make_image("card1.img")
        self.harness = CardHarness(self.image, node=self.card_node)
        self.harness.start(self)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            armada_tf.make_http_handler(
                self.service, TOKEN, peer_host="127.0.0.1"))
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def request(self, method, path, body=None, headers=None, auth=True):
        sent = dict(headers or {})
        if auth:
            sent["Authorization"] = "Bearer " + TOKEN
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=sent)
            response = conn.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            conn.close()

    def open_session(self):
        body = json.dumps({
            "key": "tablet:sd:" + CID,
            "path": self.card_node,
            "sizeBytes": CARD_BYTES,
            "logicalSectorSize": 512,
        }).encode("ascii")
        status, _, data = self.request(
            "POST", "/v1/card/open", body=body,
            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        document = json.loads(data)
        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(document["identity"]["source"], "tablet")
        self.assertEqual(document["identity"]["key"], "tablet:sd:" + CID)
        self.assertEqual(document["identity"]["path"], self.card_node)
        self.assertEqual(document["identity"]["sizeBytes"], CARD_BYTES)
        self.assertEqual(document["identity"]["logicalSectorSize"], 512)
        self.assertTrue(document["identity"]["bindingSha256"])
        return document["cardSessionId"]

    def test_inspect_over_http(self):
        status, headers, data = self.request("GET", "/v1/inspect")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        document = json.loads(data)
        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(document["source"], "tablet")
        self.assertEqual(len(document["media"]), 1)
        self.assertEqual(document["media"][0]["key"], "sd:" + CID)

    def test_full_cycle_over_http(self):
        session = self.open_session()
        pattern = bytes(range(256)) * 2
        digest = hashlib.sha256(pattern).hexdigest()

        status, headers, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=1024", body=pattern,
            headers={"Content-Type": "application/octet-stream",
                     "X-Content-SHA256": digest})
        self.assertEqual(status, 200)
        document = json.loads(data)
        self.assertEqual(document, {
            "schemaVersion": 1, "writtenBytes": 512, "sha256": digest})

        status, headers, data = self.request(
            "GET", f"/v1/card/{session}/read?offset=1024&bytes=512")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
        self.assertEqual(int(headers["Content-Length"]), 512)
        self.assertEqual(headers["X-Content-SHA256"], digest)
        self.assertEqual(data, pattern)

        status, _, data = self.request("POST", f"/v1/card/{session}/flush")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(data), {"schemaVersion": 1, "flushed": True})

        status, _, data = self.request("DELETE", f"/v1/card/{session}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"schemaVersion": 1, "closed": True})

        stored = self.image.read_bytes()
        self.assertEqual(stored[1024:1536], pattern)
        self.assertEqual(stored[:1024], FILL * 1024)

    def test_identity_route_over_http(self):
        session = self.open_session()
        status, _, data = self.request("GET", f"/v1/card/{session}/identity")
        self.assertEqual(status, 200)
        document = json.loads(data)
        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(document["identity"]["key"], "tablet:sd:" + CID)
        self.assertEqual(
            document["identity"]["bindingSha256"],
            armada_tf.binding_sha256(
                BOOT_ID, CID, 8, 16, self.card_node, CARD_BYTES, 512))

    def test_wrong_hash_writes_nothing(self):
        session = self.open_session()
        before = self.image.read_bytes()
        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=1024",
            body=b"\x55" * 512,
            headers={"Content-Type": "application/octet-stream",
                     "X-Content-SHA256": "ff" * 32})
        self.assertEqual(status, 400)
        document = json.loads(data)
        self.assertEqual(document["error"]["code"], "hash-mismatch")
        self.assertEqual(self.image.read_bytes(), before)

    def test_missing_hash_header_writes_nothing(self):
        session = self.open_session()
        before = self.image.read_bytes()
        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=1024",
            body=b"\x55" * 512,
            headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "hash-invalid")
        self.assertEqual(self.image.read_bytes(), before)

    def test_unauthorized_rejected_before_body_or_io(self):
        status, _, data = self.request("GET", "/v1/inspect", auth=False)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(data)["error"]["code"], "unauthorized")

        before = self.image.read_bytes()
        pattern = b"\x55" * 512
        status, _, data = self.request(
            "POST", "/v1/card/deadbeef/write?offset=1024", body=pattern,
            auth=False,
            headers={"Content-Type": "application/octet-stream",
                     "X-Content-SHA256": hashlib.sha256(pattern).hexdigest()})
        self.assertEqual(status, 401)
        self.assertEqual(self.image.read_bytes(), before)

    def test_wrong_token_rejected(self):
        status, _, data = self.request(
            "GET", "/v1/inspect",
            auth=False,
            headers={"Authorization": "Bearer " + "ff" * 32})
        self.assertEqual(status, 401)

    def test_foreign_peer_rejected(self):
        handler = armada_tf.make_http_handler(self.service, TOKEN)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request(
                    "GET", "/v1/inspect",
                    headers={"Authorization": "Bearer " + TOKEN})
                response = conn.getresponse()
                data = response.read()
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    json.loads(data)["error"]["code"], "peer-forbidden")
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_chunked_transfer_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("POST", "/v1/card/open")
            conn.putheader("Authorization", "Bearer " + TOKEN)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            conn.send(b"2\r\n{}\r\n0\r\n\r\n")
            response = conn.getresponse()
            data = response.read()
            self.assertEqual(response.status, 400)
            self.assertEqual(
                json.loads(data)["error"]["code"], "length-invalid")
        finally:
            conn.close()

    def test_oversize_json_rejected(self):
        body = json.dumps({
            "key": "tablet:sd:" + CID,
            "path": self.card_node,
            "sizeBytes": CARD_BYTES,
            "logicalSectorSize": 512,
            "pad": "x" * (armada_tf.JSON_MAX_BYTES + 1),
        }).encode("ascii")
        status, _, data = self.request(
            "POST", "/v1/card/open", body=body,
            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(data)["error"]["code"], "body-too-large")

    def test_oversize_binary_rejected(self):
        session = self.open_session()
        body = b"\x00" * (armada_tf.BINARY_MAX_BYTES + 512)
        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=0", body=body,
            headers={"Content-Type": "application/octet-stream",
                     "X-Content-SHA256": hashlib.sha256(body).hexdigest()})
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(data)["error"]["code"], "body-too-large")

    def test_unknown_paths_and_queries(self):
        status, _, data = self.request("GET", "/v1/nothing")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data)["error"]["code"], "not-found")

        status, _, data = self.request("GET", "/v1/inspect?extra=1")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "query-invalid")

        status, _, data = self.request(
            "GET", f"/v1/card/{'f' * 32}/identity")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data)["error"]["code"], "unknown-session")

        status, _, data = self.request(
            "GET", "/v1/card/x/read?offset=0&bytes=512")
        self.assertEqual(status, 404)

    def test_write_requires_exact_query(self):
        session = self.open_session()
        pattern = b"\x55" * 512
        digest = hashlib.sha256(pattern).hexdigest()
        headers = {"Content-Type": "application/octet-stream",
                   "X-Content-SHA256": digest}
        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=1024&extra=1",
            body=pattern, headers=headers)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "query-invalid")

        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset=nope",
            body=pattern, headers=headers)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "query-invalid")

    def test_out_of_range_write_via_http_rejected(self):
        session = self.open_session()
        pattern = b"\x55" * 512
        digest = hashlib.sha256(pattern).hexdigest()
        before = self.image.read_bytes()
        status, _, data = self.request(
            "POST", f"/v1/card/{session}/write?offset={CARD_BYTES}",
            body=pattern,
            headers={"Content-Type": "application/octet-stream",
                     "X-Content-SHA256": digest})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "range-invalid")
        self.assertEqual(self.image.read_bytes(), before)

    def test_open_rejects_extra_fields(self):
        body = json.dumps({
            "key": "tablet:sd:" + CID,
            "path": self.card_node,
            "sizeBytes": CARD_BYTES,
            "logicalSectorSize": 512,
            "extra": True,
        }).encode("ascii")
        status, _, data = self.request(
            "POST", "/v1/card/open", body=body,
            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data)["error"]["code"], "payload-invalid")

    def test_shutdown_closes_owned_descriptor(self):
        session = self.open_session()
        self.assertIsNotNone(self.harness.fd)
        self.service.close_all()
        self.assertIsNone(self.service._session)


class ProductionBindTests(unittest.TestCase):
    def test_bind_is_fixed(self):
        self.assertEqual(armada_tf.BIND_HOST, "192.168.77.1")
        self.assertEqual(armada_tf.BIND_PORT, 8203)

    def test_cli_rejects_other_arguments(self):
        self.assertEqual(armada_tf.main([]), 2)
        self.assertEqual(armada_tf.main(["inspect"]), 2)
        self.assertEqual(armada_tf.main(["serve", "--port", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
