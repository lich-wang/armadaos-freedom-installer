"""P001 contract tests for portable GPT planning.

Stdlib-only.  These tests are the RED half of the stub round: the production
modules intentionally raise ``NotImplementedError`` until implementation.
Assets are supplied by the parent Docker runner through
``EDL_GPT_TEST_ASSET_ROOT`` or ``AVB_TEST_ASSET_ROOT``.  Importing this test
module never reads assets and performs no Linux, device or CPU-heavy work.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path

_MAINTENANCE_DIR = Path(__file__).resolve().parents[1]
if str(_MAINTENANCE_DIR) not in sys.path:
    sys.path.insert(0, str(_MAINTENANCE_DIR))

import edl_gpt_cli  # noqa: E402
import portable_gpt  # noqa: E402

SECTOR_SIZE = 4096
GPT_HEADER_OFFSET = 4096
ENTRY_COUNT = 32
ENTRY_SIZE = 128
BCB_SIZE = 2048
USERDATA_BYTES = 482913628160

_ASSET_FILENAMES = {
    "originalPrimary": "before-main.bin",
    "originalBackup": "before-backup.bin",
    "currentPrimary": "after-main.bin",
    "currentBackup": "after-backup.bin",
}

_INPUT_FIELDS = (
    "currentPrimary",
    "currentBackup",
    "originalPrimary",
    "originalBackup",
    "misc",
)

_RECOVERY_TEXT = b"recovery\n--wipe_data\n--reason=armada-uninstall\n"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def _u64(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def _asset_paths() -> dict[str, Path]:
    candidates = [
        os.environ.get("EDL_GPT_TEST_ASSET_ROOT"),
        os.environ.get("AVB_TEST_ASSET_ROOT"),
    ]
    tried: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        base = Path(candidate)
        tried.append(str(base))
        paths = {key: base / name for key, name in _ASSET_FILENAMES.items()}
        if all(path.is_file() for path in paths.values()):
            return paths
    raise unittest.SkipTest(
        "real GPT assets unavailable; set EDL_GPT_TEST_ASSET_ROOT or "
        "AVB_TEST_ASSET_ROOT with before-main.bin, before-backup.bin, "
        "after-main.bin and after-backup.bin (tried: %s)" % (tried or "no env"),
    )


def _disk_bytes_from_primary(primary: bytes) -> int:
    if len(primary) < GPT_HEADER_OFFSET + SECTOR_SIZE:
        raise AssertionError("current primary capture is too short for a GPT header")
    header = primary[GPT_HEADER_OFFSET : GPT_HEADER_OFFSET + SECTOR_SIZE]
    backup_lba = _u64(header, 32)
    return (backup_lba + 1) * SECTOR_SIZE


def _uuid_for_name(disk: portable_gpt.GptDisk, name: str) -> str:
    matches = [entry for entry in disk.entries if entry.name == name]
    if not matches:
        matches = [
            entry for entry in disk.entries if entry.name.upper() == name.upper()
        ]
    if not matches:
        raise AssertionError("partition name not found: %s" % name)
    return matches[0].part_uuid


def _expected_entries(
    base: bytes,
    userdata_number: int,
    last_lba: int,
    removed_numbers: tuple[int, ...],
) -> bytes:
    if len(base) != ENTRY_COUNT * ENTRY_SIZE:
        raise AssertionError("unexpected current entry array length")
    expected = bytearray(base)
    for number in removed_numbers:
        start = (number - 1) * ENTRY_SIZE
        expected[start : start + ENTRY_SIZE] = bytes(ENTRY_SIZE)
    struct.pack_into(
        "<Q", expected, (userdata_number - 1) * ENTRY_SIZE + 40, last_lba
    )
    return bytes(expected)


def _finalize_header(header: bytes, entries_crc: int) -> bytes:
    finalized = bytearray(header)
    struct.pack_into("<I", finalized, 88, entries_crc & 0xFFFFFFFF)
    header_size = _u32(finalized, 12)
    if not 92 <= header_size <= len(finalized):
        raise AssertionError("bad GPT header size")
    struct.pack_into("<I", finalized, 16, 0)
    crc = zlib.crc32(bytes(finalized[:header_size])) & 0xFFFFFFFF
    struct.pack_into("<I", finalized, 16, crc)
    return bytes(finalized)


def _ab_message(
    version: int = 2,
    magic: int = 0x56740AB0,
    merge_status: int = 0,
    source_slot: int = 0,
    length: int = 64,
) -> bytes:
    message = bytearray(length)
    if length:
        message[0] = version & 0xFF
    if length >= 5:
        struct.pack_into("<I", message, 1, magic & 0xFFFFFFFF)
    if length >= 6:
        message[5] = merge_status & 0xFF
    if length >= 7:
        message[6] = source_slot & 0xFF
    for index in range(7, length):
        message[index] = (index * 29 + 3) & 0xFF
    return bytes(message)


def _synthetic_misc() -> bytes:
    misc = bytearray(65536)
    for index in range(len(misc)):
        misc[index] = (index * 13 + 7) & 0xFF
    misc[0:32] = bytes(32)
    misc[64:832] = bytes(768)
    misc[2048:4096] = b"\xc3" * 2048
    misc[32768 : 32768 + 64] = _ab_message(merge_status=0)
    return bytes(misc)


def _make_request(tmp: Path, paths: dict[str, Path]) -> tuple[dict, dict]:
    inputs = tmp / "inputs"
    inputs.mkdir()
    local: dict[str, Path] = {}
    filenames = {
        "currentPrimary": "current-primary.bin",
        "currentBackup": "current-backup.bin",
        "originalPrimary": "original-primary.bin",
        "originalBackup": "original-backup.bin",
    }
    for key, filename in filenames.items():
        destination = inputs / filename
        shutil.copyfile(paths[key], destination)
        local[key] = destination

    misc_bytes = _synthetic_misc()
    misc_path = inputs / "misc.bin"
    misc_path.write_bytes(misc_bytes)
    local["misc"] = misc_path

    current_primary = local["currentPrimary"].read_bytes()
    current_backup = local["currentBackup"].read_bytes()
    disk_bytes = _disk_bytes_from_primary(current_primary)
    current = portable_gpt.read_gpt(
        portable_gpt.GptImageReader(current_primary, current_backup, disk_bytes),
        SECTOR_SIZE,
        disk_bytes,
    )

    request = {
        "schemaVersion": 1,
        "sectorSize": SECTOR_SIZE,
        "diskBytes": disk_bytes,
        "currentPrimary": {
            "path": str(local["currentPrimary"]),
            "sha256": _sha256_file(local["currentPrimary"]),
        },
        "currentBackup": {
            "path": str(local["currentBackup"]),
            "sha256": _sha256_file(local["currentBackup"]),
        },
        "originalPrimary": {
            "path": str(local["originalPrimary"]),
            "sha256": _sha256_file(local["originalPrimary"]),
        },
        "originalBackup": {
            "path": str(local["originalBackup"]),
            "sha256": _sha256_file(local["originalBackup"]),
        },
        "misc": {"path": str(local["misc"]), "sha256": _sha256_file(local["misc"])},
        "owned": {
            "userdataPartUuid": _uuid_for_name(current, "userdata"),
            "linuxBootPartUuid": _uuid_for_name(current, "ARMADA_BOOT"),
            "linuxRootPartUuid": _uuid_for_name(current, "ARMADA_ROOT"),
        },
        "outputDirectory": str(tmp / "out"),
    }
    meta = {
        "inputs": local,
        "miscBytes": misc_bytes,
        "currentPrimary": current_primary,
        "currentBackup": current_backup,
        "disk": current,
        "diskBytes": disk_bytes,
    }
    return request, meta


def _synthetic_512_request(tmp: Path) -> tuple[dict, dict]:
    sector_size = 512
    entry_count = ENTRY_COUNT
    entry_size = ENTRY_SIZE
    array_bytes = entry_count * entry_size
    array_sectors = array_bytes // sector_size
    disk_bytes = 128 * 1024 ** 3
    total_sectors = disk_bytes // sector_size
    last_lba = total_sectors - 1
    primary_header_lba = 1
    primary_array_lba = 2
    first_usable_lba = 10
    backup_header_lba = last_lba
    backup_array_lba = last_lba - array_sectors
    last_usable_lba = backup_array_lba - 1

    disk_guid = "01234567-89ab-cdef-0123-456789abcdef"
    userdata_type = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    linux_type = "0fc63daf-8483-4772-8e79-3d69d8477de4"
    userdata_uuid = "11111111-2222-3333-4444-555555555555"
    boot_uuid = "22222222-3333-4444-5555-666666666666"
    root_uuid = "33333333-4444-5555-6666-777777777777"

    def entry(
        type_guid: str,
        part_uuid: str,
        first_lba: int,
        last_entry_lba: int,
        name: str,
    ) -> bytes:
        name_bytes = name.encode("utf-16-le")
        if len(name_bytes) > 72:
            raise AssertionError("synthetic partition name is too long")
        return (
            uuid.UUID(type_guid).bytes_le
            + uuid.UUID(part_uuid).bytes_le
            + struct.pack("<QQQ", first_lba, last_entry_lba, 0)
            + name_bytes.ljust(72, b"\x00")
        )

    def table(by_number: dict[int, bytes]) -> bytes:
        raw = bytearray(entry_count * entry_size)
        for number, blob in by_number.items():
            start = (number - 1) * entry_size
            raw[start : start + entry_size] = blob
        return bytes(raw)

    def header(
        current_lba: int,
        other_lba: int,
        entries_lba: int,
        entries: bytes,
    ) -> bytes:
        entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
        raw = bytearray(sector_size)
        struct.pack_into(
            "<8sIIIIQQQQ16sQIII",
            raw,
            0,
            b"EFI PART",
            0x00010000,
            92,
            0,
            0,
            current_lba,
            other_lba,
            first_usable_lba,
            last_usable_lba,
            uuid.UUID(disk_guid).bytes_le,
            entries_lba,
            entry_count,
            entry_size,
            entries_crc,
        )
        crc = zlib.crc32(bytes(raw[:92])) & 0xFFFFFFFF
        struct.pack_into("<I", raw, 16, crc)
        return bytes(raw)

    userdata_start = 2048
    userdata_end = userdata_start + (16 * 1024 ** 3) // sector_size
    userdata_last = userdata_end - 1
    boot_start = -(-userdata_end // 2048) * 2048
    boot_last = boot_start + (1 * 1024 ** 3) // sector_size - 1
    root_start = boot_last + 1
    root_last = last_usable_lba
    if root_last - root_start + 1 <= (32 * 1024 ** 3) // sector_size:
        raise AssertionError("synthetic root partition should exceed 32GiB")

    original_table = table(
        {
            16: entry(
                userdata_type,
                userdata_uuid,
                userdata_start,
                last_usable_lba,
                "userdata",
            )
        }
    )
    current_table = table(
        {
            16: entry(
                userdata_type,
                userdata_uuid,
                userdata_start,
                userdata_last,
                "userdata",
            ),
            17: entry(linux_type, boot_uuid, boot_start, boot_last, "ARMADA_BOOT"),
            18: entry(linux_type, root_uuid, root_start, root_last, "ARMADA_ROOT"),
        }
    )

    sentinel = b"P001f-512-SYNTHETIC-MBR-SENTINEL"
    mbr = sentinel.ljust(sector_size, b"\x00")

    original_primary = (
        mbr
        + header(
            primary_header_lba,
            backup_header_lba,
            primary_array_lba,
            original_table,
        )
        + original_table
    )
    original_backup = original_table + header(
        backup_header_lba, primary_header_lba, backup_array_lba, original_table
    )
    current_primary = (
        mbr
        + header(
            primary_header_lba,
            backup_header_lba,
            primary_array_lba,
            current_table,
        )
        + current_table
    )
    current_backup = current_table + header(
        backup_header_lba, primary_header_lba, backup_array_lba, current_table
    )

    inputs = tmp / "inputs"
    inputs.mkdir()
    blobs = {
        "currentPrimary": current_primary,
        "currentBackup": current_backup,
        "originalPrimary": original_primary,
        "originalBackup": original_backup,
    }
    filenames = {
        "currentPrimary": "current-primary.bin",
        "currentBackup": "current-backup.bin",
        "originalPrimary": "original-primary.bin",
        "originalBackup": "original-backup.bin",
    }
    local: dict[str, Path] = {}
    for key, data in blobs.items():
        destination = inputs / filenames[key]
        destination.write_bytes(data)
        local[key] = destination

    misc_bytes = _synthetic_misc()
    misc_path = inputs / "misc.bin"
    misc_path.write_bytes(misc_bytes)
    local["misc"] = misc_path

    request = {
        "schemaVersion": 1,
        "sectorSize": sector_size,
        "diskBytes": disk_bytes,
        "currentPrimary": {
            "path": str(local["currentPrimary"]),
            "sha256": _sha256_file(local["currentPrimary"]),
        },
        "currentBackup": {
            "path": str(local["currentBackup"]),
            "sha256": _sha256_file(local["currentBackup"]),
        },
        "originalPrimary": {
            "path": str(local["originalPrimary"]),
            "sha256": _sha256_file(local["originalPrimary"]),
        },
        "originalBackup": {
            "path": str(local["originalBackup"]),
            "sha256": _sha256_file(local["originalBackup"]),
        },
        "misc": {"path": str(local["misc"]), "sha256": _sha256_file(local["misc"])},
        "owned": {
            "userdataPartUuid": userdata_uuid,
            "linuxBootPartUuid": boot_uuid,
            "linuxRootPartUuid": root_uuid,
        },
        "outputDirectory": str(tmp / "out"),
    }
    meta = {
        "inputs": local,
        "miscBytes": misc_bytes,
        "currentPrimary": current_primary,
        "currentBackup": current_backup,
        "diskBytes": disk_bytes,
        "mbr": mbr,
        "sentinel": sentinel,
        "primaryArrayOffset": primary_array_lba * sector_size,
        "primaryHeaderOffset": primary_header_lba * sector_size,
        "backupArrayOffset": backup_array_lba * sector_size,
        "backupHeaderOffset": backup_header_lba * sector_size,
        "userdataStartLba": userdata_start,
        "userdataEndLbaExclusive": last_usable_lba + 1,
    }
    return request, meta


def _overlay_capture(
    capture: bytes,
    capture_offset: int,
    regions: list[dict],
) -> bytes:
    overlaid = bytearray(capture)
    for region in regions:
        relative = int(region["byteOffset"]) - capture_offset
        size = int(region["bytes"])
        if relative < 0 or relative + size > len(overlaid):
            continue
        data = Path(region["path"]).read_bytes()
        overlaid[relative : relative + size] = data
    return bytes(overlaid)


def _single_json(text: str) -> dict:
    stripped = text.strip()
    if not stripped:
        raise AssertionError("stdout was empty")
    decoder = json.JSONDecoder()
    value, end = decoder.raw_decode(stripped)
    if stripped[end:].strip():
        raise AssertionError("stdout contained more than one JSON value")
    if not isinstance(value, dict):
        raise AssertionError("stdout JSON was not an object")
    return value


def _run_main(args: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = edl_gpt_cli.main(args)
    return code, stdout.getvalue(), stderr.getvalue()


class PortableGptContractTests(unittest.TestCase):
    maxDiff = None

    def test_01_real_four_raw_read_and_plan(self) -> None:
        paths = _asset_paths()
        current_primary = paths["currentPrimary"].read_bytes()
        current_backup = paths["currentBackup"].read_bytes()
        original_primary = paths["originalPrimary"].read_bytes()
        original_backup = paths["originalBackup"].read_bytes()

        header = current_primary[
            GPT_HEADER_OFFSET : GPT_HEADER_OFFSET + SECTOR_SIZE
        ]
        disk_bytes = (_u64(header, 32) + 1) * SECTOR_SIZE
        self.assertEqual(_u32(header, 80), ENTRY_COUNT)
        self.assertEqual(_u32(header, 84), ENTRY_SIZE)
        self.assertEqual(disk_bytes % SECTOR_SIZE, 0)

        current = portable_gpt.read_gpt(
            portable_gpt.GptImageReader(
                current_primary, current_backup, disk_bytes
            ),
            SECTOR_SIZE,
            disk_bytes,
        )
        original = portable_gpt.read_gpt(
            portable_gpt.GptImageReader(
                original_primary, original_backup, disk_bytes
            ),
            SECTOR_SIZE,
            disk_bytes,
        )
        self.assertEqual(current.entry_count, ENTRY_COUNT)
        self.assertEqual(current.entry_size, ENTRY_SIZE)

        userdata_matches = [
            entry for entry in current.entries if entry.name == "userdata"
        ]
        self.assertEqual(len(userdata_matches), 1)
        userdata = userdata_matches[0]
        self.assertEqual(
            (userdata.last_lba - userdata.first_lba + 1) * SECTOR_SIZE,
            128 * 1024 ** 3,
        )
        boot_uuid = _uuid_for_name(current, "ARMADA_BOOT")
        root_uuid = _uuid_for_name(current, "ARMADA_ROOT")

        plan = portable_gpt.plan_restore(
            current,
            original,
            userdata.part_uuid,
            boot_uuid,
            root_uuid,
        )
        self.assertEqual(plan.restored_userdata_bytes, USERDATA_BYTES)
        self.assertEqual(plan.restored_userdata_bytes % SECTOR_SIZE, 0)
        self.assertEqual(tuple(plan.removed_partition_numbers), (17, 18))
        self.assertEqual(plan.userdata_start_lba, userdata.first_lba)
        self.assertEqual(
            plan.userdata_end_lba_exclusive - plan.userdata_start_lba,
            USERDATA_BYTES // SECTOR_SIZE,
        )

        removed = tuple(plan.removed_partition_numbers)
        expected_primary = _expected_entries(
            current.primary_entries,
            userdata.number,
            plan.userdata_end_lba_exclusive - 1,
            removed,
        )
        expected_backup = _expected_entries(
            current.backup_entries,
            userdata.number,
            plan.userdata_end_lba_exclusive - 1,
            removed,
        )

        regions = tuple(plan.write_regions)
        self.assertEqual(len(regions), 4)
        expected_offsets = (
            current.backup_entries_lba * SECTOR_SIZE,
            disk_bytes - SECTOR_SIZE,
            current.primary_entries_lba * SECTOR_SIZE,
            SECTOR_SIZE,
        )
        self.assertEqual(tuple(region.offset for region in regions), expected_offsets)
        for region in regions:
            self.assertIsInstance(region, portable_gpt.WriteRegion)
            self.assertEqual(region.offset % SECTOR_SIZE, 0)
            self.assertEqual(len(region.data) % SECTOR_SIZE, 0)

        self.assertEqual(regions[0].data, expected_backup)
        self.assertEqual(regions[2].data, expected_primary)

        for skipped in (userdata.number,) + removed:
            self.assertGreaterEqual(skipped, 1)
            self.assertLessEqual(skipped, ENTRY_COUNT)
        for base, expected in (
            (current.primary_entries, expected_primary),
            (current.backup_entries, expected_backup),
        ):
            for index in range(ENTRY_COUNT):
                number = index + 1
                if number == userdata.number or number in removed:
                    continue
                start = index * ENTRY_SIZE
                self.assertEqual(
                    expected[start : start + ENTRY_SIZE],
                    base[start : start + ENTRY_SIZE],
                )

        primary_header_sector = current_primary[
            GPT_HEADER_OFFSET : GPT_HEADER_OFFSET + SECTOR_SIZE
        ]
        backup_header_sector = current_backup[-SECTOR_SIZE:]
        expected_headers = (
            _finalize_header(
                backup_header_sector,
                zlib.crc32(expected_backup) & 0xFFFFFFFF,
            ),
            _finalize_header(
                primary_header_sector,
                zlib.crc32(expected_primary) & 0xFFFFFFFF,
            ),
        )
        self.assertEqual(regions[1].data, expected_headers[0])
        self.assertEqual(regions[3].data, expected_headers[1])

        for header_data, expected_array in (
            (regions[1].data, expected_backup),
            (regions[3].data, expected_primary),
        ):
            header_size = _u32(header_data, 12)
            self.assertGreaterEqual(header_size, 92)
            self.assertLessEqual(header_size, len(header_data))
            self.assertEqual(
                _u32(header_data, 88),
                zlib.crc32(expected_array) & 0xFFFFFFFF,
            )
            zeroed = bytearray(header_data[:header_size])
            struct.pack_into("<I", zeroed, 16, 0)
            self.assertEqual(
                _u32(header_data, 16),
                zlib.crc32(bytes(zeroed)) & 0xFFFFFFFF,
            )

    def test_02_bcb_invariance_and_rejection(self) -> None:
        existing = bytearray((index * 37 + 11) & 0xFF for index in range(BCB_SIZE))
        existing[0:32] = bytes(32)
        existing[64:832] = bytes(768)
        existing[32] = 0x5A
        existing[832] = 0xA5
        existing[BCB_SIZE - 1] = 0x7E
        source = bytes(existing)

        result = portable_gpt.make_factory_reset_bcb(source)
        self.assertEqual(source, bytes(existing))
        self.assertEqual(len(result), BCB_SIZE)
        self.assertEqual(result[0:32], b"boot-recovery".ljust(32, b"\x00"))
        self.assertEqual(result[64:832], _RECOVERY_TEXT.ljust(768, b"\x00"))
        self.assertEqual(result[32:64], source[32:64])
        self.assertEqual(result[832:], source[832:])

        bootonce_source = bytearray(source)
        bootonce_source[0:32] = b"bootonce-bootloader".ljust(32, b"\x00")
        bootonce_bytes = bytes(bootonce_source)
        bootonce_buffer = bytearray(bootonce_source)
        bootonce_result = portable_gpt.make_factory_reset_bcb(bootonce_buffer)
        self.assertEqual(bytes(bootonce_buffer), bootonce_bytes)
        self.assertEqual(
            portable_gpt.make_factory_reset_bcb(bootonce_bytes),
            bootonce_result,
        )
        self.assertEqual(len(bootonce_result), BCB_SIZE)
        self.assertEqual(
            bootonce_result[0:32], b"boot-recovery".ljust(32, b"\x00")
        )
        self.assertEqual(
            bootonce_result[64:832], _RECOVERY_TEXT.ljust(768, b"\x00")
        )
        self.assertEqual(bootonce_result[32:64], bootonce_bytes[32:64])
        self.assertEqual(bootonce_result[832:], bootonce_bytes[832:])

        pending_command = bytearray(source)
        pending_command[0:32] = b"boot-recovery".ljust(32, b"\x00")
        pending_recovery = bytearray(source)
        pending_recovery[64:832] = _RECOVERY_TEXT.ljust(768, b"\x00")
        bootonce_with_recovery = bytearray(bootonce_bytes)
        bootonce_with_recovery[64:832] = _RECOVERY_TEXT.ljust(768, b"\x00")
        unknown_command = bytearray(source)
        unknown_command[0:32] = b"boot-fastboot".ljust(32, b"\x00")
        malformed_bootonce = bytearray(bootonce_bytes)
        malformed_bootonce[31] = 0x21

        cases = {
            "pending-command": bytes(pending_command),
            "pending-recovery": bytes(pending_recovery),
            "too-short": source[:-1],
            "too-long": source + b"\x00",
            "bootonce-with-recovery": bytes(bootonce_with_recovery),
            "unknown-command": bytes(unknown_command),
            "malformed-bootonce": bytes(malformed_bootonce),
        }
        for label, candidate in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(portable_gpt.GptError):
                    portable_gpt.make_factory_reset_bcb(candidate)

    def test_03_ota_message_safety(self) -> None:
        completed_map = (
            (0, "completed"),
            (1, "unknown"),
            (2, "snapshotted"),
            (3, "merging"),
            (4, "cancelled"),
        )
        for merge_status, expected_state in completed_map:
            with self.subTest(merge_status=merge_status):
                message = _ab_message(merge_status=merge_status)
                parsed = portable_gpt.parse_virtual_ab_message(message)
                self.assertEqual(
                    set(parsed),
                    {"state", "version", "mergeStatus", "sourceSlot", "evidence"},
                )
                self.assertEqual(parsed["state"], expected_state)
                self.assertEqual(parsed["version"], 2)
                self.assertEqual(parsed["mergeStatus"], merge_status)
                self.assertEqual(parsed["sourceSlot"], 0)
                self.assertEqual(parsed["evidence"], message.hex())

        invalid_cases = {
            "version-1": _ab_message(version=1),
            "version-3": _ab_message(version=3),
            "magic-low": _ab_message(magic=0x56740AB1),
            "magic-high": _ab_message(magic=0x12345678),
            "slot-2": _ab_message(source_slot=2),
            "slot-255": _ab_message(source_slot=255),
            "length-63": _ab_message(length=63),
            "length-65": _ab_message(length=65),
        }
        for label, message in invalid_cases.items():
            with self.subTest(case=label):
                parsed = portable_gpt.parse_virtual_ab_message(message)
                self.assertEqual(
                    set(parsed),
                    {"state", "version", "mergeStatus", "sourceSlot", "evidence"},
                )
                self.assertEqual(parsed["state"], "unknown")
                self.assertNotEqual(parsed["state"], "completed")
                self.assertIsNone(parsed["version"])
                self.assertIsNone(parsed["mergeStatus"])
                self.assertIsNone(parsed["sourceSlot"])
                self.assertEqual(parsed["evidence"], message.hex())

    def test_04_prepare_plan_real_assets_happy_path(self) -> None:
        paths = _asset_paths()
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _make_request(tmp, paths)
            output_directory = Path(request["outputDirectory"])
            self.assertFalse(output_directory.exists())
            baseline = {
                field: _sha256_file(Path(request[field]["path"]))
                for field in _INPUT_FIELDS
            }

            plan = edl_gpt_cli.prepare_plan(request)
            self.assertEqual(
                set(plan),
                {
                    "currentRawTableFingerprint",
                    "userdataStartLba",
                    "userdataEndLbaExclusive",
                    "restoredBytes",
                    "removedPartitionNumbers",
                    "regions",
                    "miscRegion",
                    "miscBeforeSha256",
                    "miscAfterSha256",
                    "postPrimary",
                    "postBackup",
                },
            )
            self.assertRegex(plan["currentRawTableFingerprint"], r"^[0-9a-f]{64}$")
            self.assertEqual(plan["restoredBytes"], USERDATA_BYTES)
            self.assertEqual(
                plan["userdataEndLbaExclusive"] - plan["userdataStartLba"],
                USERDATA_BYTES // SECTOR_SIZE,
            )
            self.assertEqual(list(plan["removedPartitionNumbers"]), [17, 18])

            regions = list(plan["regions"])
            self.assertEqual(
                [region["role"] for region in regions],
                ["backup-array", "backup-header", "primary-array", "primary-header"],
            )
            disk = meta["disk"]
            disk_bytes = meta["diskBytes"]
            expected_offsets = (
                disk.backup_entries_lba * SECTOR_SIZE,
                disk_bytes - SECTOR_SIZE,
                disk.primary_entries_lba * SECTOR_SIZE,
                SECTOR_SIZE,
            )
            output_paths: list[Path] = []
            for region, expected_offset in zip(regions, expected_offsets):
                self.assertEqual(
                    set(region),
                    {
                        "role",
                        "byteOffset",
                        "startSector",
                        "sectorCount",
                        "bytes",
                        "sha256",
                        "path",
                    },
                )
                self.assertEqual(region["byteOffset"], expected_offset)
                self.assertEqual(region["byteOffset"] % SECTOR_SIZE, 0)
                self.assertEqual(
                    region["startSector"] * SECTOR_SIZE, region["byteOffset"]
                )
                self.assertEqual(
                    region["sectorCount"] * SECTOR_SIZE, region["bytes"]
                )
                self.assertGreater(region["bytes"], 0)
                if region["role"] in ("backup-array", "primary-array"):
                    self.assertEqual(region["bytes"], ENTRY_COUNT * ENTRY_SIZE)
                else:
                    self.assertEqual(region["bytes"], SECTOR_SIZE)
                region_path = Path(region["path"])
                self.assertEqual(region_path.parent.resolve(), output_directory.resolve())
                data = region_path.read_bytes()
                self.assertEqual(len(data), region["bytes"])
                self.assertEqual(_sha256_bytes(data), region["sha256"])
                output_paths.append(region_path)

            post_primary = plan["postPrimary"]
            post_backup = plan["postBackup"]
            for post in (post_primary, post_backup):
                self.assertEqual(set(post), {"byteOffset", "bytes", "sha256", "path"})
            self.assertEqual(post_primary["byteOffset"], 0)
            self.assertEqual(post_primary["bytes"], len(meta["currentPrimary"]))
            self.assertEqual(
                post_backup["byteOffset"],
                disk_bytes - len(meta["currentBackup"]),
            )
            self.assertEqual(post_backup["bytes"], len(meta["currentBackup"]))

            primary_expected = _overlay_capture(
                meta["currentPrimary"], 0, regions
            )
            backup_expected = _overlay_capture(
                meta["currentBackup"],
                disk_bytes - len(meta["currentBackup"]),
                regions,
            )
            primary_path = Path(post_primary["path"])
            backup_path = Path(post_backup["path"])
            self.assertEqual(primary_path.parent.resolve(), output_directory.resolve())
            self.assertEqual(backup_path.parent.resolve(), output_directory.resolve())
            primary_written = primary_path.read_bytes()
            backup_written = backup_path.read_bytes()
            self.assertEqual(primary_written, primary_expected)
            self.assertEqual(backup_written, backup_expected)
            self.assertEqual(_sha256_bytes(primary_written), post_primary["sha256"])
            self.assertEqual(_sha256_bytes(backup_written), post_backup["sha256"])
            self.assertEqual(
                primary_written[:512], meta["currentPrimary"][:512]
            )
            output_paths.extend((primary_path, backup_path))

            misc_region = plan["miscRegion"]
            self.assertEqual(
                set(misc_region),
                {
                    "role",
                    "relativeMiscOffset",
                    "byteOffset",
                    "startSector",
                    "sectorCount",
                    "bytes",
                    "sha256",
                    "path",
                },
            )
            self.assertEqual(misc_region["role"], "misc-bcb")
            self.assertEqual(misc_region["relativeMiscOffset"], 0)
            self.assertEqual(misc_region["byteOffset"], 0)
            self.assertEqual(misc_region["startSector"], 0)
            self.assertEqual(misc_region["bytes"], SECTOR_SIZE)
            self.assertEqual(misc_region["sectorCount"], 1)
            misc_path = Path(misc_region["path"])
            self.assertEqual(misc_path.parent.resolve(), output_directory.resolve())
            misc_written = misc_path.read_bytes()
            self.assertEqual(len(misc_written), SECTOR_SIZE)
            self.assertEqual(_sha256_bytes(misc_written), misc_region["sha256"])
            output_paths.append(misc_path)

            original_misc = meta["miscBytes"]
            bcb = portable_gpt.make_factory_reset_bcb(original_misc[:BCB_SIZE])
            expected_misc_after = bcb + original_misc[BCB_SIZE:]
            self.assertEqual(
                plan["miscBeforeSha256"], _sha256_bytes(original_misc)
            )
            self.assertEqual(
                plan["miscAfterSha256"], _sha256_bytes(expected_misc_after)
            )
            self.assertEqual(misc_written[BCB_SIZE:], original_misc[BCB_SIZE:SECTOR_SIZE])
            self.assertEqual(
                misc_written, expected_misc_after[:SECTOR_SIZE]
            )
            self.assertEqual(len(output_paths), len(set(output_paths)))

            for field in _INPUT_FIELDS:
                self.assertEqual(
                    _sha256_file(Path(request[field]["path"])),
                    baseline[field],
                )

    def test_05_file_and_ota_rejections(self) -> None:
        paths = _asset_paths()
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _make_request(tmp, paths)
            baseline = {
                field: _sha256_file(Path(request[field]["path"]))
                for field in _INPUT_FIELDS
            }

            for field in _INPUT_FIELDS:
                with self.subTest(rejection="sha-" + field):
                    invalid = copy.deepcopy(request)
                    invalid[field]["sha256"] = "0" * 64
                    output = tmp / ("invalid-sha-" + field)
                    invalid["outputDirectory"] = str(output)
                    with self.assertRaises(portable_gpt.GptError):
                        edl_gpt_cli.prepare_plan(invalid)
                    self.assertFalse(output.exists())
                    for check in _INPUT_FIELDS:
                        self.assertEqual(
                            _sha256_file(Path(request[check]["path"])),
                            baseline[check],
                        )

            for merge_status in (1, 2, 3, 4):
                with self.subTest(rejection="ota-status", merge_status=merge_status):
                    misc_bytes = bytearray(meta["miscBytes"])
                    misc_bytes[32768 : 32768 + 64] = _ab_message(
                        merge_status=merge_status
                    )
                    modified_misc = tmp / ("misc-status-%d.bin" % merge_status)
                    modified_misc.write_bytes(bytes(misc_bytes))
                    invalid = copy.deepcopy(request)
                    invalid["misc"] = {
                        "path": str(modified_misc),
                        "sha256": _sha256_bytes(bytes(misc_bytes)),
                    }
                    output = tmp / ("invalid-ota-%d" % merge_status)
                    invalid["outputDirectory"] = str(output)
                    with self.assertRaises(portable_gpt.GptError):
                        edl_gpt_cli.prepare_plan(invalid)
                    self.assertFalse(output.exists())
                    self.assertEqual(
                        _sha256_file(modified_misc), _sha256_bytes(bytes(misc_bytes))
                    )
                    for check in _INPUT_FIELDS:
                        self.assertEqual(
                            _sha256_file(Path(request[check]["path"])),
                            baseline[check],
                        )

            with self.subTest(rejection="ota-bad-envelope"):
                misc_bytes = bytearray(meta["miscBytes"])
                misc_bytes[32768 : 32768 + 64] = _ab_message(magic=0x12345678)
                modified_misc = tmp / "misc-bad-envelope.bin"
                modified_misc.write_bytes(bytes(misc_bytes))
                invalid = copy.deepcopy(request)
                invalid["misc"] = {
                    "path": str(modified_misc),
                    "sha256": _sha256_bytes(bytes(misc_bytes)),
                }
                output = tmp / "invalid-ota-envelope"
                invalid["outputDirectory"] = str(output)
                with self.assertRaises(portable_gpt.GptError):
                    edl_gpt_cli.prepare_plan(invalid)
                self.assertFalse(output.exists())
                self.assertEqual(
                    _sha256_file(modified_misc), _sha256_bytes(bytes(misc_bytes))
                )

            existing_output = tmp / "already-exists"
            existing_output.mkdir()
            inputs_directory = Path(request["currentPrimary"]["path"]).parent
            existing_cases = (
                ("fresh-existing-directory", existing_output),
                ("input-directory", inputs_directory),
            )
            for label, output in existing_cases:
                with self.subTest(rejection=label):
                    before_names = sorted(path.name for path in output.iterdir())
                    invalid = copy.deepcopy(request)
                    invalid["outputDirectory"] = str(output)
                    with self.assertRaises(portable_gpt.GptError):
                        edl_gpt_cli.prepare_plan(invalid)
                    self.assertTrue(output.is_dir())
                    self.assertEqual(
                        sorted(path.name for path in output.iterdir()),
                        before_names,
                    )
                    for check in _INPUT_FIELDS:
                        self.assertEqual(
                            _sha256_file(Path(request[check]["path"])),
                            baseline[check],
                        )

    def test_06_main_json_envelope_and_argv(self) -> None:
        paths = _asset_paths()
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, _meta = _make_request(tmp, paths)
            request_path = tmp / "request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")

            code, stdout, stderr = _run_main([str(request_path)])
            self.assertEqual(code, 0)
            self.assertNotIn("Traceback", stdout)
            self.assertNotIn("Traceback", stderr)
            envelope = _single_json(stdout)
            self.assertEqual(
                set(envelope), {"schemaVersion", "ok", "plan"}
            )
            self.assertEqual(envelope["schemaVersion"], 1)
            self.assertIs(envelope["ok"], True)
            self.assertIsInstance(envelope["plan"], dict)
            self.assertIn("regions", envelope["plan"])

            malformed = copy.deepcopy(request)
            malformed["currentPrimary"]["sha256"] = "0" * 64
            malformed_path = tmp / "malformed.json"
            malformed_path.write_text(json.dumps(malformed), encoding="utf-8")
            code, stdout, stderr = _run_main([str(malformed_path)])
            self.assertNotEqual(code, 0)
            self.assertNotIn("Traceback", stdout)
            self.assertNotIn("Traceback", stderr)
            envelope = _single_json(stdout)
            self.assertEqual(
                set(envelope), {"schemaVersion", "ok", "error"}
            )
            self.assertEqual(envelope["schemaVersion"], 1)
            self.assertIs(envelope["ok"], False)
            self.assertIsInstance(envelope["error"], dict)
            self.assertEqual(set(envelope["error"]), {"code", "message"})
            self.assertTrue(str(envelope["error"]["code"]))
            self.assertTrue(str(envelope["error"]["message"]))

            for label, argv in (
                ("missing-argument", []),
                ("extra-argument", [str(request_path), "extra"]),
            ):
                with self.subTest(argv=label):
                    code, stdout, stderr = _run_main(argv)
                    self.assertNotEqual(code, 0)
                    self.assertNotIn("Traceback", stdout)
                    self.assertNotIn("Traceback", stderr)
                    envelope = _single_json(stdout)
                    self.assertEqual(
                        set(envelope), {"schemaVersion", "ok", "error"}
                    )
                    self.assertEqual(envelope["schemaVersion"], 1)
                    self.assertIs(envelope["ok"], False)
                    self.assertEqual(
                        set(envelope["error"]), {"code", "message"}
                    )
                    self.assertTrue(str(envelope["error"]["code"]))
                    self.assertTrue(str(envelope["error"]["message"]))

    def test_07_512_sector_misc_write_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _synthetic_512_request(tmp)
            sector_size = request["sectorSize"]
            self.assertEqual(sector_size, 512)
            self.assertEqual(meta["currentPrimary"][:512], meta["mbr"])
            self.assertEqual(len(meta["currentPrimary"]), 512 + 512 + 4096)
            self.assertEqual(len(meta["currentBackup"]), 4096 + 512)
            baseline = {
                field: _sha256_file(Path(request[field]["path"]))
                for field in _INPUT_FIELDS
            }

            plan = edl_gpt_cli.prepare_plan(request)

            regions = list(plan["regions"])
            self.assertEqual(len(regions), 4)
            self.assertEqual(
                [region["role"] for region in regions],
                [
                    "backup-array",
                    "backup-header",
                    "primary-array",
                    "primary-header",
                ],
            )
            expected_offsets = (
                meta["backupArrayOffset"],
                meta["backupHeaderOffset"],
                meta["primaryArrayOffset"],
                meta["primaryHeaderOffset"],
            )
            for region, expected_offset in zip(regions, expected_offsets):
                self.assertEqual(region["byteOffset"], expected_offset)
                self.assertEqual(region["byteOffset"] % sector_size, 0)
                self.assertEqual(region["bytes"] % sector_size, 0)
                self.assertEqual(
                    region["startSector"] * sector_size, region["byteOffset"]
                )
                self.assertEqual(
                    region["sectorCount"] * sector_size, region["bytes"]
                )
                if region["role"].endswith("array"):
                    self.assertEqual(region["bytes"], ENTRY_COUNT * ENTRY_SIZE)
                else:
                    self.assertEqual(region["bytes"], sector_size)
                region_data = Path(region["path"]).read_bytes()
                self.assertEqual(len(region_data), region["bytes"])
                self.assertEqual(_sha256_bytes(region_data), region["sha256"])

            self.assertEqual(
                plan["userdataStartLba"], meta["userdataStartLba"]
            )
            self.assertEqual(
                plan["userdataEndLbaExclusive"],
                meta["userdataEndLbaExclusive"],
            )

            misc_region = plan["miscRegion"]
            self.assertEqual(
                set(misc_region),
                {
                    "role",
                    "relativeMiscOffset",
                    "byteOffset",
                    "startSector",
                    "sectorCount",
                    "bytes",
                    "sha256",
                    "path",
                },
            )
            self.assertEqual(misc_region["role"], "misc-bcb")
            self.assertEqual(misc_region["relativeMiscOffset"], 0)
            self.assertEqual(misc_region["byteOffset"], 0)
            self.assertEqual(misc_region["startSector"], 0)
            self.assertEqual(misc_region["bytes"], BCB_SIZE)
            self.assertEqual(misc_region["sectorCount"], BCB_SIZE // sector_size)
            self.assertEqual(misc_region["sectorCount"], 4)
            misc_written = Path(misc_region["path"]).read_bytes()

            original_misc = meta["miscBytes"]
            bcb = portable_gpt.make_factory_reset_bcb(original_misc[:BCB_SIZE])
            expected_misc_after = bcb + original_misc[BCB_SIZE:]
            self.assertEqual(len(misc_written), BCB_SIZE)
            self.assertEqual(misc_written, expected_misc_after[:BCB_SIZE])
            self.assertEqual(_sha256_bytes(misc_written), misc_region["sha256"])
            self.assertEqual(
                plan["miscBeforeSha256"], _sha256_bytes(original_misc)
            )
            self.assertEqual(
                plan["miscAfterSha256"], _sha256_bytes(expected_misc_after)
            )

            post_primary = plan["postPrimary"]
            post_backup = plan["postBackup"]
            disk_bytes = meta["diskBytes"]
            self.assertEqual(post_primary["byteOffset"], 0)
            self.assertEqual(post_primary["bytes"], len(meta["currentPrimary"]))
            self.assertEqual(
                post_backup["byteOffset"],
                disk_bytes - len(meta["currentBackup"]),
            )
            self.assertEqual(post_backup["bytes"], len(meta["currentBackup"]))

            primary_written = Path(post_primary["path"]).read_bytes()
            backup_written = Path(post_backup["path"]).read_bytes()
            self.assertEqual(
                primary_written,
                _overlay_capture(meta["currentPrimary"], 0, regions),
            )
            self.assertEqual(
                backup_written,
                _overlay_capture(
                    meta["currentBackup"],
                    disk_bytes - len(meta["currentBackup"]),
                    regions,
                ),
            )
            self.assertEqual(primary_written[:sector_size], meta["mbr"])
            self.assertIn(meta["sentinel"], primary_written[:sector_size])
            self.assertEqual(_sha256_bytes(primary_written), post_primary["sha256"])
            self.assertEqual(_sha256_bytes(backup_written), post_backup["sha256"])

            for field in _INPUT_FIELDS:
                self.assertEqual(
                    _sha256_file(Path(request[field]["path"])),
                    baseline[field],
                )


if __name__ == "__main__":
    unittest.main()
