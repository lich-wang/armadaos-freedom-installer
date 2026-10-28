"""L001 RED-phase contract tests for maintenance/armada_uninstall.py.

The module is imported by absolute file path; the fixtures below build real
GPT headers and entry arrays with struct/zlib independently of the module
under test, so a passing implementation cannot rely on test-side helpers.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import http.client
import importlib.util
import io
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import uuid
import zlib
from dataclasses import dataclass, replace
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "armada_uninstall.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("armada_uninstall", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the defining module through sys.modules.
    sys.modules["armada_uninstall"] = module
    spec.loader.exec_module(module)
    return module


au = _load_module()

PAGE = 4096

TYPE_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
TYPE_BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
TYPE_LINUX_FS = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"

DISK_GUID = "8F3A1C4E-77B2-4E0D-9A61-2C5B0D8E4F17"
OTHER_DISK_GUID = "11111111-2222-3333-4444-555555555555"

ESP_UUID = "A1B2C3D4-0001-4A01-9001-000000000001"
SYSTEM_UUID = "A1B2C3D4-0002-4A01-9002-000000000002"
USERDATA_UUID = "A1B2C3D4-0003-4A01-9003-000000000003"
BOOT_UUID = "A1B2C3D4-0004-4A01-9004-000000000004"
ROOT_UUID = "A1B2C3D4-0005-4A01-9005-000000000005"
WRONG_UUID = "A1B2C3D4-00FF-4A01-90FF-0000000000FF"

# Real Gen4 geometry (4Kn).
GEN4_SECTOR = 4096
GEN4_TOTAL_LBAS = 123871232
GEN4_DISK_BYTES = GEN4_TOTAL_LBAS * GEN4_SECTOR
GEN4_FIRST_USABLE = 6
GEN4_LAST_USABLE = 123871226
GEN4_ENTRY_COUNT = 32
GEN4_ENTRY_SIZE = 128

USERDATA_START = 5972392
USERDATA_SECTORS = 33554432
BOOT_START = 39526912
BOOT_SECTORS = 262144
ROOT_START = 39789056
ROOT_END_EXCL = 123871227

CURRENT_USERDATA_END_EXCL = BOOT_START - 88  # 88-sector alignment gap
RESTORED_USERDATA_BYTES = (ROOT_END_EXCL - 1 - USERDATA_START + 1) * GEN4_SECTOR

BCB_COMMAND = b"boot-recovery"
BCB_RECOVERY = b"recovery\n--wipe_data\n--reason=armada-uninstall\n"


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


class SparseDisk:
    """Tiny sparse seek/read/write BinaryIO: only touched pages are kept."""

    def __init__(self, size: int):
        self.size = size
        self._pages: dict[int, bytearray] = {}
        self._pos = 0
        self.bytes_read = 0
        self.max_read_request = 0
        self.writes: list[tuple[int, int]] = []

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = self.size + offset
        else:
            raise ValueError("invalid whence")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self._pos = new_pos
        return self._pos

    def tell(self) -> int:
        return self._pos

    def write(self, data: bytes) -> int:
        start = self._pos
        remaining = len(data)
        src = 0
        while remaining:
            page_index = self._pos // PAGE
            page_offset = self._pos % PAGE
            take = min(remaining, PAGE - page_offset)
            page = self._pages.get(page_index)
            if page is None:
                page = bytearray(PAGE)
                self._pages[page_index] = page
            page[page_offset:page_offset + take] = data[src:src + take]
            self._pos += take
            src += take
            remaining -= take
        self.writes.append((start, len(data)))
        return len(data)

    def write_at(self, offset: int, data: bytes) -> None:
        self.seek(offset)
        self.write(data)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.size - self._pos
        size = max(0, min(size, self.size - self._pos))
        self.max_read_request = max(self.max_read_request, size)
        out = bytearray(size)
        got = 0
        while got < size:
            page_index = self._pos // PAGE
            page_offset = self._pos % PAGE
            take = min(size - got, PAGE - page_offset)
            page = self._pages.get(page_index)
            if page is not None:
                out[got:got + take] = page[page_offset:page_offset + take]
            self._pos += take
            got += take
        self.bytes_read += got
        return bytes(out)


def make_entry(number, type_guid, part_uuid, first_lba, last_lba, attrs, name,
               entry_size=128):
    raw = bytearray(entry_size)
    struct.pack_into(
        "<16s16sQQQ72s",
        raw,
        0,
        uuid.UUID(type_guid).bytes_le,
        uuid.UUID(part_uuid).bytes_le,
        first_lba,
        last_lba,
        attrs,
        name.encode("utf-16-le"),
    )
    return {
        "number": number,
        "type_guid": type_guid,
        "part_uuid": part_uuid,
        "first_lba": first_lba,
        "last_lba": last_lba,
        "attrs": attrs,
        "name": name,
        "raw": bytes(raw),
    }


def _entries_blob(active, entry_count, entry_size):
    slots = [b"\x00" * entry_size for _ in range(entry_count)]
    for entry in active:
        slots[entry["number"] - 1] = entry["raw"]
    return b"".join(slots)


def _build_header(sector_size, current_lba, backup_lba, first_usable,
                  last_usable, disk_guid, entries_lba, entry_count,
                  entry_size, entries_crc):
    header = bytearray(92)
    struct.pack_into(
        "<8sIIIIQQQQ16sQIII",
        header,
        0,
        b"EFI PART",
        0x00010000,
        92,
        0,  # checksum field zeroed while computing the CRC
        0,
        current_lba,
        backup_lba,
        first_usable,
        last_usable,
        uuid.UUID(disk_guid).bytes_le,
        entries_lba,
        entry_count,
        entry_size,
        entries_crc,
    )
    struct.pack_into("<I", header, 16, _crc32(bytes(header)))
    return bytes(header) + b"\x00" * (sector_size - 92)


def build_gpt_disk(*, disk_size_bytes, sector_size, disk_guid, first_usable_lba,
                   last_usable_lba, entry_count, entry_size, active,
                   backup_active=None, primary_entries_lba=2):
    total_lbas = disk_size_bytes // sector_size
    backup_header_lba = total_lbas - 1
    array_bytes = entry_count * entry_size
    array_sectors = (array_bytes + sector_size - 1) // sector_size
    backup_entries_lba = backup_header_lba - array_sectors

    primary_raw = _entries_blob(active, entry_count, entry_size)
    backup_raw = primary_raw if backup_active is None else _entries_blob(
        backup_active, entry_count, entry_size
    )
    pad = array_sectors * sector_size - array_bytes
    primary_padded = primary_raw + b"\x00" * pad
    backup_padded = backup_raw + b"\x00" * pad

    primary_header = _build_header(
        sector_size, 1, backup_header_lba, first_usable_lba, last_usable_lba,
        disk_guid, primary_entries_lba, entry_count, entry_size,
        _crc32(primary_raw),
    )
    backup_header = _build_header(
        sector_size, backup_header_lba, 1, first_usable_lba, last_usable_lba,
        disk_guid, backup_entries_lba, entry_count, entry_size,
        _crc32(backup_raw),
    )

    disk = SparseDisk(disk_size_bytes)
    disk.write_at(primary_entries_lba * sector_size, primary_padded)
    disk.write_at(backup_entries_lba * sector_size, backup_padded)
    disk.write_at(1 * sector_size, primary_header)
    disk.write_at(backup_header_lba * sector_size, backup_header)

    layout = {
        "backup_header_lba": backup_header_lba,
        "backup_entries_lba": backup_entries_lba,
        "primary_entries_lba": primary_entries_lba,
        "array_sectors": array_sectors,
    }
    return disk, layout


def compact_disk(*, attrs=0x8000000000000005):
    """Small 512-byte-sector GPT; slot 2 inactive so numbering is exercised."""
    sectors = 204800
    active = [
        make_entry(1, TYPE_ESP, ESP_UUID, 34, 2047, 0, "EFI"),
        make_entry(3, TYPE_LINUX_FS, USERDATA_UUID, 2048, 204766, attrs,
                   "userdata"),
    ]
    disk, layout = build_gpt_disk(
        disk_size_bytes=sectors * 512,
        sector_size=512,
        disk_guid=DISK_GUID,
        first_usable_lba=34,
        last_usable_lba=204766,
        entry_count=8,
        entry_size=128,
        active=active,
    )
    layout["sectors"] = sectors
    return disk, layout, active


def gen4_current_disk():
    active = [
        make_entry(1, TYPE_ESP, ESP_UUID, 6, 204805, 0x8000000000000000,
                   "EFI"),
        make_entry(2, TYPE_BASIC_DATA, SYSTEM_UUID, 204806, USERDATA_START - 1,
                   0x8000000000000001, "SYSTEM"),
        make_entry(3, TYPE_LINUX_FS, USERDATA_UUID, USERDATA_START,
                   CURRENT_USERDATA_END_EXCL - 1, 0x8000000000000002,
                   "userdata"),
        make_entry(4, TYPE_LINUX_FS, BOOT_UUID, BOOT_START,
                   BOOT_START + BOOT_SECTORS - 1, 0x8000000000000003,
                   "ARMADA_BOOT"),
        make_entry(5, TYPE_LINUX_FS, ROOT_UUID, ROOT_START,
                   ROOT_END_EXCL - 1, 0x8000000000000004, "ARMADA_ROOT"),
    ]
    disk, layout = build_gpt_disk(
        disk_size_bytes=GEN4_DISK_BYTES,
        sector_size=GEN4_SECTOR,
        disk_guid=DISK_GUID,
        first_usable_lba=GEN4_FIRST_USABLE,
        last_usable_lba=GEN4_LAST_USABLE,
        entry_count=GEN4_ENTRY_COUNT,
        entry_size=GEN4_ENTRY_SIZE,
        active=active,
    )
    return disk, layout, active


def gen4_original_disk():
    active = [
        make_entry(1, TYPE_ESP, ESP_UUID, 6, 204805, 0, "EFI"),
        make_entry(2, TYPE_BASIC_DATA, SYSTEM_UUID, 204806, USERDATA_START - 1,
                   0, "SYSTEM"),
        make_entry(3, TYPE_LINUX_FS, USERDATA_UUID, USERDATA_START,
                   ROOT_END_EXCL - 1, 0, "userdata"),
    ]
    disk, layout = build_gpt_disk(
        disk_size_bytes=GEN4_DISK_BYTES,
        sector_size=GEN4_SECTOR,
        disk_guid=DISK_GUID,
        first_usable_lba=GEN4_FIRST_USABLE,
        last_usable_lba=GEN4_LAST_USABLE,
        entry_count=GEN4_ENTRY_COUNT,
        entry_size=GEN4_ENTRY_SIZE,
        active=active,
    )
    return disk, layout, active


def bcb_buffer(command=b"", recovery=b"", status=None, reserved=None):
    buf = bytearray(2048)
    buf[0:32] = command.ljust(32, b"\x00")[:32]
    buf[64:832] = recovery.ljust(768, b"\x00")[:768]
    if status is not None:
        buf[32:64] = status
    if reserved is not None:
        buf[832:2048] = reserved
    return bytes(buf)


class GptParseTests(unittest.TestCase):
    def test_01_valid_primary_and_backup_parse_512(self):
        disk, layout, active = compact_disk()
        gpt = au.read_gpt(disk, 512, layout["sectors"] * 512)

        self.assertEqual(gpt.sector_size, 512)
        self.assertEqual(gpt.disk_size_bytes, layout["sectors"] * 512)
        self.assertEqual(gpt.disk_guid, DISK_GUID)
        self.assertEqual(gpt.first_usable_lba, 34)
        self.assertEqual(gpt.last_usable_lba, 204766)
        self.assertEqual(gpt.entry_count, 8)
        self.assertEqual(gpt.entry_size, 128)
        self.assertEqual(gpt.primary_entries_lba, 2)
        self.assertEqual(gpt.backup_entries_lba, layout["backup_entries_lba"])

        self.assertEqual(len(gpt.primary_header), 512)
        self.assertEqual(len(gpt.backup_header), 512)
        self.assertEqual(len(gpt.primary_entries), 1024)
        self.assertEqual(len(gpt.backup_entries), 1024)
        self.assertEqual(gpt.primary_entries, gpt.backup_entries)

        self.assertEqual([e.number for e in gpt.entries], [1, 3])
        first, second = gpt.entries
        self.assertEqual(first.type_guid, TYPE_ESP)
        self.assertEqual(first.part_uuid, ESP_UUID)
        self.assertEqual((first.first_lba, first.last_lba), (34, 2047))
        self.assertEqual(first.name, "EFI")
        self.assertEqual(first.raw, active[0]["raw"])

        self.assertEqual(second.type_guid, TYPE_LINUX_FS)
        self.assertEqual(second.part_uuid, USERDATA_UUID)
        self.assertEqual((second.first_lba, second.last_lba), (2048, 204766))
        self.assertEqual(second.attrs, 0x8000000000000005)
        self.assertEqual(second.name, "userdata")
        self.assertEqual(second.raw, active[1]["raw"])

        self.assertIsInstance(gpt.fingerprint, str)
        self.assertTrue(gpt.fingerprint)

    def test_02_valid_4kn_gen4_geometry(self):
        disk, layout, active = gen4_current_disk()
        gpt = au.read_gpt(disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        self.assertEqual(gpt.sector_size, 4096)
        self.assertEqual(gpt.first_usable_lba, 6)
        self.assertEqual(gpt.last_usable_lba, GEN4_LAST_USABLE)
        self.assertEqual(gpt.entry_count, 32)
        self.assertEqual(gpt.entry_size, 128)
        self.assertEqual(len(gpt.primary_header), 4096)
        self.assertEqual(len(gpt.backup_header), 4096)
        self.assertEqual(len(gpt.primary_entries), 4096)
        self.assertEqual(len(gpt.backup_entries), 4096)
        self.assertEqual(gpt.backup_entries_lba,
                         layout["backup_header_lba"] - 1)

        userdata = [e for e in gpt.entries if e.name == "userdata"][0]
        self.assertEqual(userdata.first_lba, USERDATA_START)
        self.assertEqual(userdata.last_lba, CURRENT_USERDATA_END_EXCL - 1)
        self.assertNotEqual(userdata.first_lba % 256, 0)  # not 1 MiB aligned
        self.assertEqual(userdata.attrs, 0x8000000000000002)
        self.assertEqual(userdata.raw, active[2]["raw"])

        boot = [e for e in gpt.entries if e.name == "ARMADA_BOOT"][0]
        self.assertEqual(boot.first_lba - (userdata.last_lba + 1), 88)

        root = [e for e in gpt.entries if e.name == "ARMADA_ROOT"][0]
        self.assertEqual(root.last_lba, GEN4_LAST_USABLE)

    def test_03_primary_header_crc_corruption_rejected(self):
        disk, layout, _ = compact_disk()
        disk.seek(512 + 16)
        stored_crc = struct.unpack("<I", disk.read(4))[0]
        disk.write_at(512 + 16, struct.pack("<I", stored_crc ^ 0xFFFFFFFF))

        with self.assertRaises(au.GptError):
            au.read_gpt(disk, 512, layout["sectors"] * 512)

    def test_04_backup_array_corruption_rejected(self):
        disk, layout, _ = compact_disk()
        offset = layout["backup_entries_lba"] * 512 + 5
        disk.seek(offset)
        original = disk.read(1)
        disk.write_at(offset, bytes([original[0] ^ 0xFF]))

        with self.assertRaises(au.GptError):
            au.read_gpt(disk, 512, layout["sectors"] * 512)

    def test_05_selfconsistent_conflicting_backup_array_rejected(self):
        # Backup array has different attrs for slot 1, with its own valid
        # array CRC and a valid backup header CRC. Primary/backup disagree.
        backup_active = [
            make_entry(1, TYPE_ESP, ESP_UUID, 34, 2047, 0x42, "EFI"),
            make_entry(3, TYPE_LINUX_FS, USERDATA_UUID, 2048, 204766,
                       0x8000000000000005, "userdata"),
        ]
        disk, layout = build_gpt_disk(
            disk_size_bytes=204800 * 512,
            sector_size=512,
            disk_guid=DISK_GUID,
            first_usable_lba=34,
            last_usable_lba=204766,
            entry_count=8,
            entry_size=128,
            active=[
                make_entry(1, TYPE_ESP, ESP_UUID, 34, 2047, 0, "EFI"),
                make_entry(3, TYPE_LINUX_FS, USERDATA_UUID, 2048, 204766,
                           0x8000000000000005, "userdata"),
            ],
            backup_active=backup_active,
        )

        # Sanity: both headers carry their own correct 92-byte header CRC.
        for lba in (1, layout["backup_header_lba"]):
            disk.seek(lba * 512)
            header = disk.read(512)
            zeroed = header[:16] + b"\x00\x00\x00\x00" + header[20:92]
            self.assertEqual(struct.unpack_from("<I", header, 16)[0],
                             _crc32(zeroed))

        with self.assertRaises(au.GptError):
            au.read_gpt(disk, 512, 204800 * 512)


class GptRestorePlanTests(unittest.TestCase):
    def _plan(self):
        current_disk, current_layout, _ = gen4_current_disk()
        original_disk, original_layout, _ = gen4_original_disk()
        current = au.read_gpt(current_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        plan = au.plan_restore(current, original, USERDATA_UUID, BOOT_UUID,
                               ROOT_UUID)
        return current_disk, current_layout, current, original, plan

    def test_06_restore_plan_preserves_untouched_entries(self):
        disk, layout, current, original, plan = self._plan()

        self.assertNotEqual(current.entries[0].attrs, original.entries[0].attrs)
        self.assertEqual(current.entries[0].first_lba,
                         original.entries[0].first_lba)

        self.assertEqual(len(plan.write_regions), 4)
        self.assertEqual([r.offset for r in plan.write_regions], [
            layout["backup_entries_lba"] * GEN4_SECTOR,
            layout["backup_header_lba"] * GEN4_SECTOR,
            layout["primary_entries_lba"] * GEN4_SECTOR,
            1 * GEN4_SECTOR,
        ])
        self.assertEqual([len(r.data) for r in plan.write_regions],
                         [4096, 4096, 4096, 4096])
        self.assertLessEqual(sum(len(r.data) for r in plan.write_regions),
                             64 * 1024)

        self.assertEqual(plan.userdata_start_lba, USERDATA_START)
        self.assertEqual(plan.userdata_end_lba_exclusive, ROOT_END_EXCL)
        self.assertEqual(plan.restored_userdata_bytes, 482913628160)
        self.assertEqual(plan.restored_userdata_bytes,
                         RESTORED_USERDATA_BYTES)
        self.assertEqual(plan.removed_partition_numbers, (4, 5))

        userdata_bytes = (USERDATA_START * GEN4_SECTOR,
                          CURRENT_USERDATA_END_EXCL * GEN4_SECTOR)
        for region in plan.write_regions:
            end = region.offset + len(region.data)
            self.assertNotEqual(region.offset, 0)
            self.assertGreaterEqual(region.offset, GEN4_SECTOR)
            self.assertFalse(region.offset < userdata_bytes[1]
                             and end > userdata_bytes[0])

        for region in plan.write_regions:
            disk.write_at(region.offset, region.data)

        disk.seek(0)
        restored = au.read_gpt(disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        self.assertEqual([e.number for e in restored.entries], [1, 2, 3])
        for index in (0, 1):
            self.assertEqual(restored.entries[index].raw,
                             current.entries[index].raw)

        expected_userdata = (
            current.entries[2].raw[:40]
            + struct.pack("<Q", ROOT_END_EXCL - 1)
            + current.entries[2].raw[48:]
        )
        self.assertEqual(restored.entries[2].raw, expected_userdata)
        self.assertEqual(restored.entries[2].first_lba, USERDATA_START)
        self.assertEqual(restored.entries[2].last_lba, ROOT_END_EXCL - 1)
        self.assertEqual(restored.entries[2].attrs, current.entries[2].attrs)
        self.assertEqual(restored.entries[2].name, "userdata")

        slot_span = GEN4_ENTRY_SIZE * 3, GEN4_ENTRY_SIZE * 5
        self.assertEqual(restored.primary_entries[slot_span[0]:slot_span[1]],
                         b"\x00" * (slot_span[1] - slot_span[0]))
        self.assertEqual(restored.backup_entries[slot_span[0]:slot_span[1]],
                         b"\x00" * (slot_span[1] - slot_span[0]))

        self.assertLess(disk.bytes_read, 1_000_000)
        self.assertLessEqual(disk.max_read_request, 16 * 1024)

    def test_07_original_disk_guid_mismatch_rejected(self):
        current_disk, _, _ = gen4_current_disk()
        original_disk, _, _ = gen4_original_disk()
        current = au.read_gpt(current_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        with self.assertRaises(au.GptError):
            au.plan_restore(current, replace(original, disk_guid=OTHER_DISK_GUID),
                            USERDATA_UUID, BOOT_UUID, ROOT_UUID)

    def test_08_wrong_owned_partuuid_rejected(self):
        current_disk, _, _ = gen4_current_disk()
        original_disk, _, _ = gen4_original_disk()
        current = au.read_gpt(current_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        variants = {
            "userdata": (WRONG_UUID, BOOT_UUID, ROOT_UUID),
            "boot": (USERDATA_UUID, WRONG_UUID, ROOT_UUID),
            "root": (USERDATA_UUID, BOOT_UUID, WRONG_UUID),
        }
        for label, uuids in variants.items():
            with self.subTest(partition=label):
                with self.assertRaises(au.GptError):
                    au.plan_restore(current, original, *uuids)

    def test_11_duplicate_userdata_label_rejected(self):
        _, _, current_active = gen4_current_disk()
        _, _, original_active = gen4_original_disk()

        def rename_efi_to_userdata(active):
            renamed = []
            for entry in active:
                if entry["name"] == "EFI":
                    renamed.append(make_entry(
                        entry["number"], entry["type_guid"],
                        entry["part_uuid"], entry["first_lba"],
                        entry["last_lba"], entry["attrs"], "userdata",
                    ))
                else:
                    renamed.append(entry)
            return renamed

        renamed_current = rename_efi_to_userdata(current_active)
        renamed_original = rename_efi_to_userdata(original_active)

        current_disk, _ = build_gpt_disk(
            disk_size_bytes=GEN4_DISK_BYTES,
            sector_size=GEN4_SECTOR,
            disk_guid=DISK_GUID,
            first_usable_lba=GEN4_FIRST_USABLE,
            last_usable_lba=GEN4_LAST_USABLE,
            entry_count=GEN4_ENTRY_COUNT,
            entry_size=GEN4_ENTRY_SIZE,
            active=renamed_current,
        )
        original_disk, _ = build_gpt_disk(
            disk_size_bytes=GEN4_DISK_BYTES,
            sector_size=GEN4_SECTOR,
            disk_guid=DISK_GUID,
            first_usable_lba=GEN4_FIRST_USABLE,
            last_usable_lba=GEN4_LAST_USABLE,
            entry_count=GEN4_ENTRY_COUNT,
            entry_size=GEN4_ENTRY_SIZE,
            active=renamed_original,
        )

        current = au.read_gpt(current_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        self.assertEqual(
            [e.number for e in current.entries if e.name == "userdata"],
            [1, 3],
        )
        self.assertEqual(
            [e.number for e in original.entries if e.name == "userdata"],
            [1, 3],
        )

        with self.assertRaises(au.GptError):
            au.plan_restore(current, original, USERDATA_UUID, BOOT_UUID,
                            ROOT_UUID)

    def test_12_wrong_linux_type_rejected(self):
        # Only the selected entry's type GUID changes; every other field and
        # the rest of the table are preserved, so the GPT stays self-consistent
        # with valid CRCs and the rejection must be driven by the type check.
        _, _, current_active = gen4_current_disk()
        original_disk, _, _ = gen4_original_disk()
        original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        for label in ("ARMADA_BOOT", "ARMADA_ROOT"):
            with self.subTest(partition=label):
                source = [e for e in current_active if e["name"] == label][0]
                mutated = []
                for entry in current_active:
                    if entry["number"] == source["number"]:
                        mutated.append(make_entry(
                            entry["number"], TYPE_BASIC_DATA,
                            entry["part_uuid"], entry["first_lba"],
                            entry["last_lba"], entry["attrs"], entry["name"],
                        ))
                    else:
                        mutated.append(entry)

                current_disk, _ = build_gpt_disk(
                    disk_size_bytes=GEN4_DISK_BYTES,
                    sector_size=GEN4_SECTOR,
                    disk_guid=DISK_GUID,
                    first_usable_lba=GEN4_FIRST_USABLE,
                    last_usable_lba=GEN4_LAST_USABLE,
                    entry_count=GEN4_ENTRY_COUNT,
                    entry_size=GEN4_ENTRY_SIZE,
                    active=mutated,
                )
                current = au.read_gpt(current_disk, GEN4_SECTOR, GEN4_DISK_BYTES)

                selected = [e for e in current.entries if e.name == label][0]
                self.assertEqual(selected.type_guid, TYPE_BASIC_DATA)
                self.assertEqual(selected.number, source["number"])
                self.assertEqual(selected.part_uuid, source["part_uuid"])
                self.assertEqual((selected.first_lba, selected.last_lba),
                                 (source["first_lba"], source["last_lba"]))
                self.assertEqual(selected.attrs, source["attrs"])
                self.assertEqual(len(current.entries), len(current_active))

                with self.assertRaises(au.GptError):
                    au.plan_restore(current, original, USERDATA_UUID, BOOT_UUID,
                                    ROOT_UUID)


class BcbTests(unittest.TestCase):
    def test_09_bcb_payload_and_unrelated_bytes(self):
        status = bytes([0xA5]) * 32
        reserved = bytes((index * 7 + 3) % 256 for index in range(1216))
        existing = bcb_buffer(status=status, reserved=reserved)

        result = au.make_factory_reset_bcb(existing)

        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 2048)
        self.assertEqual(result[0:32], BCB_COMMAND.ljust(32, b"\x00"))
        self.assertEqual(result[64:832], BCB_RECOVERY.ljust(768, b"\x00"))
        self.assertEqual(result[32:64], status)
        self.assertEqual(result[832:2048], reserved)
        self.assertEqual(result[2040:2048], reserved[-8:])
        self.assertEqual(result[48:64], status[16:32])
        self.assertEqual(existing, bcb_buffer(status=status, reserved=reserved))

    def test_10_bcb_pending_request_and_size_validation(self):
        pending_cases = {
            "command": bcb_buffer(command=b"bootonce-bootloader"),
            "recovery": bcb_buffer(recovery=b"--wipe_data\n"),
            "command_garbage_tail": bcb_buffer(command=b"boot-recoveryX"),
        }
        for label, existing in pending_cases.items():
            with self.subTest(pending=label):
                with self.assertRaises(au.GptError):
                    au.make_factory_reset_bcb(existing)

        for size in (0, 2047, 2049, 4096):
            with self.subTest(size=size):
                with self.assertRaises(au.GptError):
                    au.make_factory_reset_bcb(b"\x00" * size)


# ---------------------------------------------------------------------------
# L004: runtime contracts and failing behaviour tests
#
# These tests pin the contract of the runtime/backend symbols. They are
# expected to be RED: every runtime entry point is still a stub.
# ---------------------------------------------------------------------------

BOOT_IMAGE_BYTES = 512
MISC_IMAGE_BYTES = 65536
OTA_OFFSET = 32768
PRIMARY_GPT_REGION_BYTES = 24576
BACKUP_GPT_REGION_BYTES = 20480
MISC_UUID = "A1B2C3D4-0006-4A01-9006-000000000006"
FAKE_BOOT_ID = "0F1E2D3C-4B5A-4F78-8796-A5B4C3D2E1F0"
NEXT_BOOT_ID = "9A8B7C6D-5E4F-4A3B-8C2D-1E0F9A8B7C6D"
TXID = "7c788122-1d2b-431d-a730-593e8cc12e44"
RESTORED_ANDROID_BYTES = 482913628160
BASELINE_BYTES = b"trusted-vbmeta-baseline" * 2

# Android A/B boot slots are independent devices with their own synthetic
# PARTUUIDs; they are not the ARMADA_BOOT Linux partition of the fixture.
BOOT_SLOT_PATHS = {"a": "/dev/sde12", "b": "/dev/sde45"}
BOOT_SLOT_UUIDS = {
    "a": "5C1D9E30-7A48-4B62-9F13-08D7C2A46B91",
    "b": "E42B7F68-1C05-4D8A-B3E9-6A2047D8F5C3",
}
MISC_PARTITION_PATH = "/dev/block/by-name/misc"
DISK_DEVICE_PATH = "/dev/sda"


def node_name(disk_path: str, number: int) -> str:
    """sfdisk node naming: ``p`` separator only for digit-ending devices."""
    if disk_path and disk_path[-1].isdigit():
        return f"{disk_path}p{number}"
    return f"{disk_path}{number}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ota_message(*, version=2, magic=0x56740AB0, merge_status=0, source_slot=0,
                size=64):
    """Build a packed virtual A/B message of ``size`` bytes."""
    buffer = bytearray(size)
    if size >= 1:
        buffer[0] = version
    if size >= 5:
        struct.pack_into("<I", buffer, 1, magic)
    if size >= 6:
        buffer[5] = merge_status
    if size >= 7:
        buffer[6] = source_slot
    return bytes(buffer)


def original_gpt_regions():
    """Return the finite primary and backup GPT regions of the original disk."""
    disk, _, _ = gen4_original_disk()
    disk.seek(0)
    primary = disk.read(PRIMARY_GPT_REGION_BYTES)
    disk.seek(GEN4_DISK_BYTES - BACKUP_GPT_REGION_BYTES)
    backup = disk.read(BACKUP_GPT_REGION_BYTES)
    return primary, backup


@dataclass(frozen=True)
class FakeEvidence:
    """Shape of the evidence object returned by avb_stock in production."""

    slot: str
    stock_sha256: str
    fingerprint: str
    root_key_sha256: str
    chain_key_sha256: str
    hardware_rollback_verified: bool
    proof: str


class FakeRestoreValidator:
    """Explicit fake callback: no AVB logic, no pins, no private fixtures."""

    def __init__(self, fail_slots=()):
        self.calls = []
        self.fail_slots = set(fail_slots)

    def __call__(self, stock_boot, current_boot, slot_vbmeta, baseline, slot,
                 model, partition_size):
        stock_bytes = stock_boot.read()
        current_bytes = current_boot.read()
        vbmeta = bytes(slot_vbmeta)
        self.calls.append({
            "slot": slot,
            "model": model,
            "partition_size": partition_size,
            "stock_sha256": _sha256(stock_bytes),
            "current_sha256": _sha256(current_bytes),
            "stock_bytes": stock_bytes,
            "current_bytes": current_bytes,
            "vbmeta": vbmeta,
            "baseline": bytes(baseline),
        })
        if slot in self.fail_slots:
            raise au.MaintenanceError("validator-rejected", f"slot {slot} rejected")
        return FakeEvidence(
            slot=slot,
            stock_sha256=_sha256(stock_bytes),
            fingerprint=f"{slot}-firmware",
            root_key_sha256=_sha256(b"root-key:" + vbmeta),
            chain_key_sha256=_sha256(b"chain-key:" + vbmeta),
            hardware_rollback_verified=False,
            proof=_sha256(b"proof:" + stock_bytes + current_bytes),
        )


class FakePlatform:
    """Stdlib-only stand-in for LinuxBlockBackend. Never touches a device."""

    def __init__(self, root, *, gate=None, restore_error=None):
        self.root = Path(root)
        self.disk_path = DISK_DEVICE_PATH
        self.sector_size = GEN4_SECTOR
        self.disk_bytes = GEN4_DISK_BYTES
        self.model = "TB322FC"
        self.soc_serial = "SOC-TB322FC-0001"
        self.boot_id = FAKE_BOOT_ID
        self.ram_root = True
        self.root_fstype = "rootfs"
        self.compatible = ["lenovo,elden", "qcom,sm8750"]

        self.disk, _, _ = gen4_current_disk()
        self.original_disk, _, _ = gen4_original_disk()

        # Each fake boot slot is a 512-byte device so stock candidates stay
        # small; slot paths/UUIDs are independent of the ARMADA_BOOT fixture.
        self.current = {
            "a": b"CURRENT-A".ljust(BOOT_IMAGE_BYTES, b"\x00"),
            "b": b"CURRENT-B".ljust(BOOT_IMAGE_BYTES, b"\x00"),
        }
        self.stock = {
            "a": b"STOCK-A".ljust(BOOT_IMAGE_BYTES, b"\x00"),
            "b": b"STOCK-B".ljust(BOOT_IMAGE_BYTES, b"\x00"),
        }
        self.vbmeta = {"a": bytes(range(64)), "b": bytes(range(64, 128))}
        self.boot_sha = {slot: _sha256(self.current[slot]) for slot in ("a", "b")}
        self.misc = bytearray(MISC_IMAGE_BYTES)
        self.misc[OTA_OFFSET:OTA_OFFSET + 64] = ota_message()

        self.gate = gate
        self.restore_error = restore_error
        self.restore_calls = []
        self.verify_calls = []
        self.reclaim_calls = []
        self.bcb_calls = []
        self.entity_writes = []

        backup_dir = self.root / "device-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        self.backups = {}
        for role, data in (
            ("boot_a", self.current["a"]),
            ("boot_b", self.current["b"]),
            ("misc", bytes(self.misc)),
        ):
            path = backup_dir / f"{role}.bin"
            path.write_bytes(data)
            self.backups[role] = path

    # -- facts ---------------------------------------------------------
    def table_fingerprint(self):
        return au.read_gpt(self.disk, GEN4_SECTOR, GEN4_DISK_BYTES).fingerprint

    def misc_sha(self):
        return _sha256(bytes(self.misc))

    def misc_fingerprint(self):
        # The misc fingerprint is the full misc SHA256 itself, never a second
        # invented hash of the same image.
        return self.misc_sha()

    def vbmeta_sha(self, slot):
        return _sha256(self.vbmeta[slot])

    def backup_sha(self, role):
        return _sha256(self.backups[role].read_bytes())

    def facts(self):
        slots = {}
        for slot in ("a", "b"):
            vbmeta_sha = self.vbmeta_sha(slot)
            slots[slot] = {
                "partitionPath": BOOT_SLOT_PATHS[slot],
                "partUuid": BOOT_SLOT_UUIDS[slot],
                "bytes": BOOT_IMAGE_BYTES,
                "sha256": self.boot_sha[slot],
                "vbmetaSha256": vbmeta_sha,
                "slotFingerprint": _sha256(
                    f"slot:{slot}:{self.boot_sha[slot]}:{vbmeta_sha}"
                    .encode("ascii")
                ),
            }
        message = bytes(self.misc[OTA_OFFSET:OTA_OFFSET + 64])
        return {
            "schemaVersion": 1,
            "model": self.model,
            "socSerial": self.soc_serial,
            "bootId": self.boot_id,
            "ramRoot": self.ram_root,
            "rootFstype": self.root_fstype,
            "compatible": self.compatible,
            "diskPath": self.disk_path,
            "diskBytes": self.disk_bytes,
            "sectorSize": self.sector_size,
            "tableFingerprint": self.table_fingerprint(),
            "primaryGptValid": True,
            "backupGptValid": True,
            "bootSlots": slots,
            "currentBootFingerprint": au.boot_state_fingerprint(
                {slot: self.boot_sha[slot] for slot in ("a", "b")},
                {slot: self.vbmeta_sha(slot) for slot in ("a", "b")},
            ),
            "misc": {
                "partitionPath": MISC_PARTITION_PATH,
                "partUuid": MISC_UUID,
                "bytes": MISC_IMAGE_BYTES,
                "sha256": self.misc_sha(),
                "bcbPending": any(self.misc[0:32]),
            },
            "miscFingerprint": self.misc_fingerprint(),
            "busy": {
                "rootOnTarget": False,
                "mountedPartitions": [],
                "swapPartitions": [],
                "holderPartitions": [],
            },
            "ota": {"state": "completed", "evidence": message.hex()},
            # This fake is RAM-backed, idle and OTA-complete, so maintenance is
            # validated; no stock-validity list is hardcoded here.
            "maintenanceValidated": True,
        }

    # -- platform contract --------------------------------------------
    def capture(self):
        return au.RuntimeCapture(
            snapshot=self.facts(),
            gpt=au.read_gpt(self.disk, GEN4_SECTOR, GEN4_DISK_BYTES),
            backups=dict(self.backups),
            slot_vbmeta={slot: bytes(self.vbmeta[slot]) for slot in ("a", "b")},
        )

    def current_state(self):
        return self.facts()

    @staticmethod
    def _slot_expectations(by_slot, label):
        """Validate a phase expectation map, so no slot is silently skipped."""
        if not isinstance(by_slot, dict) or set(by_slot) != {"a", "b"}:
            raise au.MaintenanceError(
                f"{label}-invalid", f"{label} must map slots a and b",
            )
        return by_slot

    def assert_ready(self, expected):
        facts = self.facts()
        if not facts["ramRoot"]:
            raise au.MaintenanceError("not-ram-root", "root is not RAM-backed")
        busy = facts["busy"]
        if any(busy[key] for key in
               ("mountedPartitions", "swapPartitions", "holderPartitions")):
            raise au.MaintenanceError("busy", "disk is busy")
        if facts["ota"]["state"] != "completed":
            raise au.MaintenanceError("ota-incomplete", "OTA is not complete")
        for key, value in expected.items():
            if key in facts and facts[key] != value:
                raise au.MaintenanceError(f"{key}-mismatch", f"{key} changed")

        boot_expected = expected.get("bootSha256")
        if boot_expected is not None:
            for slot, digest in self._slot_expectations(
                    boot_expected, "bootSha256").items():
                if facts["bootSlots"][slot]["sha256"] != digest:
                    raise au.MaintenanceError(
                        "boot-sha256-mismatch", f"slot {slot} boot changed",
                    )
        vbmeta_expected = expected.get("vbmetaSha256")
        if vbmeta_expected is not None:
            for slot, digest in self._slot_expectations(
                    vbmeta_expected, "vbmetaSha256").items():
                if facts["bootSlots"][slot]["vbmetaSha256"] != digest:
                    raise au.MaintenanceError(
                        "vbmeta-sha256-mismatch", f"slot {slot} vbmeta changed",
                    )
        misc_expected = expected.get("miscSha256")
        if misc_expected is not None and facts["misc"]["sha256"] != misc_expected:
            raise au.MaintenanceError("misc-sha256-mismatch", "misc changed")
        return facts

    def restore_boot(self, slot, image_path, expected_current_sha256,
                     expected_stock_sha256):
        self.restore_calls.append({
            "slot": slot,
            "image_path": str(image_path),
            "expected_current_sha256": expected_current_sha256,
            "expected_stock_sha256": expected_stock_sha256,
        })
        if self.gate is not None:
            self.gate.wait(5)
        if self.boot_sha[slot] != expected_current_sha256:
            raise au.MaintenanceError(
                "current-sha256-mismatch", f"slot {slot} changed since capture",
            )
        if self.restore_error is not None:
            raise self.restore_error
        digest = _sha256(Path(image_path).read_bytes())
        if digest != expected_stock_sha256:
            raise au.MaintenanceError("image-hash-mismatch", "candidate changed")
        self.boot_sha[slot] = digest
        self.entity_writes.append(("restore_boot", slot))
        return digest

    def verify_boot(self, slot, expected_sha256):
        self.verify_calls.append({"slot": slot, "expected_sha256": expected_sha256})
        if self.boot_sha[slot] != expected_sha256:
            raise au.MaintenanceError("verify-mismatch", f"slot {slot} mismatch")

    def reclaim_space(self, plan, expected_table_fingerprint):
        self.reclaim_calls.append({
            "fingerprint": expected_table_fingerprint,
            "userdata_start_sector": plan.userdata_start_lba,
            "userdata_end_sector_exclusive": plan.userdata_end_lba_exclusive,
            "removed": tuple(plan.removed_partition_numbers),
        })
        if self.table_fingerprint() != expected_table_fingerprint:
            raise au.MaintenanceError("table-changed", "GPT changed since prepare")
        for region in plan.write_regions:
            self.disk.write_at(region.offset, region.data)
        self.entity_writes.append(("reclaim_space", len(plan.write_regions)))
        return self.table_fingerprint()

    def queue_factory_reset(self, expected_misc_sha256):
        self.bcb_calls.append(expected_misc_sha256)
        if self.misc_sha() != expected_misc_sha256:
            raise au.MaintenanceError("misc-changed", "misc changed since prepare")
        bcb = au.make_factory_reset_bcb(bytes(self.misc[0:2048]))
        self.misc[0:2048] = bcb
        if bytes(self.misc[0:32]).rstrip(b"\x00") != BCB_COMMAND:
            raise au.MaintenanceError("bcb-verify-failed", "readback mismatch")
        self.entity_writes.append(("queue_factory_reset", 2048))
        return self.misc_sha()


class MaintenanceScenario:
    """Uploads, prepare payload, ack payload and step driver for one test."""

    def __init__(self, root, *, gate=None, restore_error=None, validator=None):
        self.platform = FakePlatform(root, gate=gate, restore_error=restore_error)
        self.validator = (validator if validator is not None
                          else FakeRestoreValidator())
        self.state_dir = Path(root) / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.runtime = au.MaintenanceRuntime(
            self.platform, self.state_dir, restore_validator=self.validator,
        )
        primary, backup = original_gpt_regions()
        self.asset_data = {
            "stock_boot_a": bytes(self.platform.stock["a"]),
            "stock_boot_b": bytes(self.platform.stock["b"]),
            "original_primary_gpt": primary,
            "original_backup_gpt": backup,
            "trusted_vbmeta_baseline": BASELINE_BYTES,
        }
        self.assets = {}

    def upload_all(self):
        for role in au.ASSET_ROLES:
            data = self.asset_data[role]
            result = self.runtime.put_asset(role, io.BytesIO(data), len(data))
            if (result["role"] != role or result["bytes"] != len(data)
                    or result["sha256"] != _sha256(data)):
                raise AssertionError(f"bad put_asset result for {role}: {result!r}")
            self.assets[role] = {
                "role": role, "bytes": len(data), "sha256": _sha256(data),
            }
        return list(self.assets.values())

    def expected(self, extra=None):
        facts = self.platform.facts()
        expected = {
            "model": self.platform.model,
            "socSerial": self.platform.soc_serial,
            "bootId": self.platform.boot_id,
            "diskPath": self.platform.disk_path,
            "diskBytes": self.platform.disk_bytes,
            "sectorSize": self.platform.sector_size,
            "tableFingerprint": facts["tableFingerprint"],
            "currentBootFingerprint": facts["currentBootFingerprint"],
            "miscFingerprint": facts["miscFingerprint"],
        }
        if extra:
            expected.update(extra)
        return expected

    def prepare(self, extra_expected=None):
        payload = {
            "transactionId": TXID,
            "expected": self.expected(extra_expected),
            "ownedPartitions": {
                "userdataPartUuid": USERDATA_UUID,
                "linuxBootPartUuid": BOOT_UUID,
                "linuxRootPartUuid": ROOT_UUID,
            },
            "assets": list(self.assets.values()),
        }
        return self.runtime.prepare(payload), payload

    def backup_entries(self):
        entries = []
        for role in ("boot_a", "boot_b", "misc"):
            data = self.platform.backups[role].read_bytes()
            entries.append({
                "role": role, "bytes": len(data), "sha256": _sha256(data),
            })
        return entries

    def ack_payload(self, backups=None):
        return {
            "transactionId": TXID,
            "bootId": self.platform.boot_id,
            "socSerial": self.platform.soc_serial,
            "backups": self.backup_entries() if backups is None else backups,
        }

    def ack(self, backups=None):
        return self.runtime.ack_backups(self.ack_payload(backups))

    def step(self, name, token, boot_id=None):
        return self.runtime.step(TXID, {
            "step": name,
            "bootId": self.platform.boot_id if boot_id is None else boot_id,
            "confirmationToken": token,
            "wipeConfirmed": True,
        })

    def wait_for_restore_call(self, timeout=5):
        deadline = time.time() + timeout
        while not self.platform.restore_calls and time.time() < deadline:
            time.sleep(0.01)
        return bool(self.platform.restore_calls)

    def prepared(self):
        self.upload_all()
        status, _ = self.prepare()
        return status["confirmationToken"]


class RuntimePrimitiveTests(unittest.TestCase):
    """Pure primitive contracts: no devices, no runtime transaction."""

    def test_13_parse_virtual_ab_completed_and_status_map(self):
        cases = {
            0: "completed",
            1: "unknown",
            2: "snapshotted",
            3: "merging",
            4: "cancelled",
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                message = ota_message(merge_status=status)
                self.assertEqual(len(message), 64)
                parsed = au.parse_virtual_ab_message(message)
                self.assertEqual(parsed["state"], expected)
                self.assertEqual(parsed["version"], 2)
                self.assertEqual(parsed["mergeStatus"], status)
                self.assertEqual(parsed["sourceSlot"], 0)
                self.assertEqual(parsed["evidence"], message.hex())

        with self.subTest(source_slot=1):
            message = ota_message(source_slot=1, merge_status=2)
            parsed = au.parse_virtual_ab_message(message)
            self.assertEqual(parsed["sourceSlot"], 1)
            self.assertEqual(parsed["state"], "snapshotted")

    def test_14_parse_virtual_ab_invalid_never_completes(self):
        valid = ota_message()
        cases = {
            "empty": b"",
            "short": valid[:63],
            "long": valid + b"\x00",
            "version1": ota_message(version=1),
            "version3": ota_message(version=3),
            "bigendian-magic": valid[:1] + struct.pack(">I", 0x56740AB0) + valid[5:],
            "wrong-magic": ota_message(magic=0x0AB05674),
            "source2": ota_message(source_slot=2),
            "status5": ota_message(merge_status=5),
        }
        for label, message in cases.items():
            with self.subTest(case=label):
                parsed = au.parse_virtual_ab_message(message)
                self.assertEqual(parsed["state"], "unknown")
                self.assertNotEqual(parsed["state"], "completed")
                self.assertEqual(parsed["evidence"], message.hex())
                self.assertIsNone(parsed["version"])
                self.assertIsNone(parsed["mergeStatus"])
                self.assertIsNone(parsed["sourceSlot"])

    def test_15_sfdisk_json_preserves_current_table(self):
        disk, _layout, _active = gen4_current_disk()
        gpt = au.read_gpt(disk, GEN4_SECTOR, GEN4_DISK_BYTES)

        raw = au.gpt_to_sfdisk_json(gpt, DISK_DEVICE_PATH)
        self.assertIsInstance(raw, str)
        table = json.loads(raw)["partitiontable"]

        self.assertEqual(table["label"], "gpt")
        self.assertEqual(table["id"], DISK_GUID)
        self.assertEqual(table["device"], DISK_DEVICE_PATH)
        self.assertEqual(table["unit"], "sectors")
        self.assertEqual(table["firstlba"], GEN4_FIRST_USABLE)
        self.assertEqual(table["lastlba"], GEN4_LAST_USABLE)
        self.assertEqual(table["sectorsize"], GEN4_SECTOR)
        # Standard sfdisk reports the partition slot count here, not the
        # entry array length in sectors (which is 1 for this table).
        self.assertEqual(table["table-length"], GEN4_ENTRY_COUNT)

        expected_attrs = {
            0x8000000000000000: "GUID:63",
            0x8000000000000001: "GUID:0,63",
            0x8000000000000002: "GUID:1,63",
            0x8000000000000003: "GUID:0,1,63",
            0x8000000000000004: "GUID:2,63",
        }
        partitions = table["partitions"]
        self.assertEqual(len(partitions), len(gpt.entries))
        for part, entry in zip(partitions, gpt.entries):
            self.assertEqual(part["node"], node_name(DISK_DEVICE_PATH,
                                                    entry.number))
            self.assertEqual(part["start"], entry.first_lba)
            self.assertEqual(part["size"], entry.last_lba - entry.first_lba + 1)
            self.assertEqual(part["type"], entry.type_guid)
            self.assertEqual(part["uuid"], entry.part_uuid)
            self.assertEqual(part["name"], entry.name)
            self.assertEqual(part["attrs"], expected_attrs[entry.attrs])

        zero_disk, _, _ = gen4_original_disk()
        zero_gpt = au.read_gpt(zero_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        zero_parts = json.loads(
            au.gpt_to_sfdisk_json(zero_gpt, DISK_DEVICE_PATH)
        )["partitiontable"]["partitions"]
        self.assertEqual(len(zero_parts), len(zero_gpt.entries))
        self.assertEqual(
            [part["node"] for part in zero_parts],
            [node_name(DISK_DEVICE_PATH, entry.number)
             for entry in zero_gpt.entries],
        )
        for part in zero_parts:
            self.assertNotIn("attrs", part)

        # A digit-ending kernel device name needs the ``p`` separator.
        digit_parts = json.loads(
            au.gpt_to_sfdisk_json(zero_gpt, "/dev/nvme0n1")
        )["partitiontable"]["partitions"]
        self.assertEqual(
            [part["node"] for part in digit_parts],
            [f"/dev/nvme0n1p{entry.number}" for entry in zero_gpt.entries],
        )

        self.assertNotIn("subprocess", au.__dict__)

    def test_16_sysfs_extents_multiply_both_numbers_by_512(self):
        cases = {
            "gen4-userdata": ("5972392", "8388608"),
            "single-sector": ("6", "1"),
            "zero-start": ("0", "8"),
        }
        for label, (start, size) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(
                    au._kernel_extent_bytes(start, size),
                    (int(start) * 512, int(size) * 512),
                )
        self.assertEqual(
            au._kernel_extent_bytes("5972392", "8388608"),
            (3057864704, 4294967296),
        )

    def test_17_exact_pread_and_pwrite_retry_short_io(self):
        with mock.patch.object(au.os, "pread", side_effect=[b"ab", b"cd"]) as pread:
            self.assertEqual(au._pread_exact_fd(9, 4, 100), b"abcd")
        self.assertEqual([entry.args for entry in pread.call_args_list],
                         [(9, 4, 100), (9, 2, 102)])

        with mock.patch.object(au.os, "pread", side_effect=[b"ab", b""]):
            with self.assertRaises(au.MaintenanceError) as context:
                au._pread_exact_fd(9, 4, 100)
        self.assertEqual(context.exception.code, "short-read")

        with mock.patch.object(au.os, "pwrite", side_effect=[2, 2]) as pwrite:
            self.assertIsNone(au._pwrite_all_fd(9, b"abcd", 100))
        self.assertEqual([entry.args for entry in pwrite.call_args_list],
                         [(9, b"abcd", 100), (9, b"cd", 102)])

        with mock.patch.object(au.os, "pwrite", side_effect=[2, 0]):
            with self.assertRaises(au.MaintenanceError) as context:
                au._pwrite_all_fd(9, b"abcd", 100)
        self.assertEqual(context.exception.code, "short-write")

    def test_18_flush_sequence_and_readback_mismatch(self):
        expected = "a" * 64
        calls = mock.Mock()
        # The readback mock must return the expected digest, otherwise the
        # happy path assertion below can never hold.
        calls.hash_fd.return_value = expected
        with mock.patch.object(au.os, "fsync", calls.fsync), \
                mock.patch.object(au.fcntl, "ioctl", calls.ioctl), \
                mock.patch.object(au, "_hash_fd", calls.hash_fd):
            self.assertIsNone(au._flush_and_verify_fd(7, 4096, expected))

        self.assertEqual([entry[0] for entry in calls.mock_calls],
                         ["fsync", "ioctl", "hash_fd"])
        self.assertEqual(calls.fsync.call_args, mock.call(7))
        self.assertEqual(calls.ioctl.call_args, mock.call(7, au._BLKFLSBUF))
        self.assertEqual(calls.hash_fd.call_args.args[:2], (7, 4096))

        with mock.patch.object(au.os, "fsync"), \
                mock.patch.object(au.fcntl, "ioctl"), \
                mock.patch.object(au, "_hash_fd", return_value="deadbeef"):
            with self.assertRaises(au.MaintenanceError) as context:
                au._flush_and_verify_fd(7, 4096, expected)
        self.assertEqual(context.exception.code, "flush-verify-mismatch")


class RuntimeBehaviourTests(unittest.TestCase):
    """Transaction behaviour against FakePlatform in a manager TMPDIR."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="l004-")
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _scenario(self, **kwargs):
        return MaintenanceScenario(self.root, **kwargs)

    def test_19_inspect_and_prepare_are_read_only(self):
        scenario = self._scenario()
        disk_writes = len(scenario.platform.disk.writes)

        facts = scenario.runtime.inspect()
        self.assertEqual(facts["schemaVersion"], 1)
        self.assertEqual(facts["model"], "TB322FC")
        self.assertEqual(facts["socSerial"], scenario.platform.soc_serial)
        self.assertEqual(facts["bootId"], FAKE_BOOT_ID)
        self.assertEqual(facts["diskBytes"], GEN4_DISK_BYTES)
        self.assertEqual(facts["sectorSize"], GEN4_SECTOR)
        self.assertEqual(facts["diskPath"], DISK_DEVICE_PATH)
        self.assertTrue(facts["ramRoot"])
        self.assertEqual(facts["tableFingerprint"],
                         scenario.platform.facts()["tableFingerprint"])
        self.assertIn("layout", facts)
        self.assertEqual(
            json.loads(facts["sfdiskJson"])["partitiontable"]["label"], "gpt")

        scenario.upload_all()
        status, _payload = scenario.prepare(
            extra_expected={"expectedFingerprint": "f" * 64})

        self.assertEqual(status["schemaVersion"], 1)
        self.assertEqual(status["transactionId"], TXID)
        self.assertEqual(status["bootId"], FAKE_BOOT_ID)
        self.assertEqual(status["state"], "prepared")
        self.assertIsNone(status["activeStep"])
        self.assertEqual(list(status["completedSteps"]), [])
        self.assertEqual(status["nextStep"], "restore-boot-a")
        self.assertTrue(status["confirmationToken"])
        self.assertTrue(status["bothStockBootsValid"])
        self.assertFalse(status["backupAcknowledged"])
        self.assertEqual(status["restoredAndroidBytes"], RESTORED_ANDROID_BYTES)
        self.assertEqual(status["restoredAndroidBytes"], 482913628160)
        self.assertEqual(status["userdataStartSector"], USERDATA_START)
        self.assertEqual(status["userdataEndSectorExclusive"], ROOT_END_EXCL)
        self.assertEqual(list(status["removedPartitionNumbers"]), [4, 5])
        self.assertRegex(status["planFingerprint"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["stockFingerprint"], r"^[0-9a-f]{64}$")
        self.assertIsNone(status["error"])

        for slot, role in (("a", "stock_boot_a"), ("b", "stock_boot_b")):
            evidence = status["slotEvidence"][slot]
            self.assertEqual(evidence["slot"], slot)
            self.assertEqual(evidence["fingerprint"], f"{slot}-firmware")
            self.assertEqual(evidence["sha256"], scenario.assets[role]["sha256"])
            self.assertFalse(evidence["hardwareRollbackVerified"])
        self.assertEqual(
            status["slotEvidence"]["a"]["rootKeySha256"],
            _sha256(b"root-key:" + scenario.platform.vbmeta["a"]),
        )
        self.assertEqual(
            status["slotEvidence"]["b"]["bootKeySha256"],
            _sha256(b"chain-key:" + scenario.platform.vbmeta["b"]),
        )

        # The callback saw the real streams and never a host fingerprint.
        self.assertEqual([call["slot"] for call in scenario.validator.calls],
                         ["a", "b"])
        for call in scenario.validator.calls:
            slot = call["slot"]
            self.assertNotIn("expectedFingerprint", call)
            self.assertEqual(call["model"], "TB322FC")
            self.assertEqual(call["partition_size"], BOOT_IMAGE_BYTES)
            self.assertEqual(call["current_sha256"],
                             scenario.platform.boot_sha[slot])
            self.assertEqual(call["current_bytes"], scenario.platform.current[slot])
            self.assertEqual(call["stock_bytes"], scenario.platform.stock[slot])
            self.assertEqual(call["vbmeta"], scenario.platform.vbmeta[slot])
            self.assertEqual(call["baseline"], BASELINE_BYTES)
            self.assertEqual(
                call["stock_sha256"],
                scenario.assets[f"stock_boot_{slot}"]["sha256"],
            )

        # Nothing was written to the entity by inspect/prepare.
        self.assertEqual(scenario.platform.entity_writes, [])
        self.assertEqual(scenario.platform.restore_calls, [])
        self.assertEqual(len(scenario.platform.disk.writes), disk_writes)
        self.assertFalse(scenario.platform.facts()["misc"]["bcbPending"])

    def test_20_upload_rejects_bad_assets_and_keeps_none(self):
        scenario = self._scenario()
        runtime = scenario.runtime
        cases = {
            "unsupported-role": dict(role="stock_boot_c",
                                     reader=io.BytesIO(b"x"), length=1),
            "zero-length": dict(role="stock_boot_a",
                                reader=io.BytesIO(b""), length=0),
            "oversize-stock": dict(role="stock_boot_a",
                                   reader=io.BytesIO(b"x"),
                                   length=BOOT_IMAGE_BYTES + 1),
            "oversize-gpt": dict(role="original_primary_gpt",
                                 reader=io.BytesIO(b"x"),
                                 length=(16 << 20) + 1),
            "oversize-baseline": dict(role="trusted_vbmeta_baseline",
                                      reader=io.BytesIO(b"x"),
                                      length=(1 << 20) + 1),
            "short-body": dict(role="stock_boot_a",
                               reader=io.BytesIO(b"short"),
                               length=BOOT_IMAGE_BYTES),
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(au.MaintenanceError) as context:
                    runtime.put_asset(**kwargs)
                self.assertLess(context.exception.http_status, 500)
                asset_path = scenario.state_dir / "assets" / f"{kwargs['role']}.bin"
                self.assertFalse(asset_path.exists())
                self.assertNotIn(kwargs["role"], scenario.assets)

        # A rejected upload cannot be smuggled into prepare either.
        with self.assertRaises(au.MaintenanceError):
            scenario.prepare()

    def test_21_prepared_assets_are_immutable(self):
        scenario = self._scenario()
        scenario.upload_all()
        scenario.prepare()

        path = scenario.state_dir / "assets" / "stock_boot_a.bin"
        original = path.read_bytes()
        self.assertEqual(_sha256(original),
                         scenario.assets["stock_boot_a"]["sha256"])

        with self.assertRaises(au.MaintenanceError):
            scenario.runtime.put_asset("stock_boot_a", io.BytesIO(b"NEW"), 3)
        self.assertEqual(path.read_bytes(), original)

        with self.assertRaises(au.MaintenanceError):
            scenario.runtime.put_asset(
                "stock_boot_b", io.BytesIO(b"NEW".ljust(BOOT_IMAGE_BYTES, b"\x00")),
                BOOT_IMAGE_BYTES,
            )
        self.assertEqual(
            (scenario.state_dir / "assets" / "stock_boot_b.bin").read_bytes(),
            scenario.asset_data["stock_boot_b"],
        )

    def test_22_backup_ack_requires_exact_three_snapshots(self):
        scenario = self._scenario()
        token = scenario.prepared()

        with self.assertRaises(au.MaintenanceError) as context:
            scenario.step("restore-boot-a", token)
        self.assertEqual(context.exception.http_status, 409)
        self.assertEqual(scenario.platform.restore_calls, [])
        self.assertEqual(scenario.platform.entity_writes, [])

        good = scenario.backup_entries()
        rejected = {
            "missing-third": good[:2],
            "wrong-sha": [good[0], good[1], dict(good[2], sha256="0" * 64)],
            "wrong-role": [good[0], good[1], dict(good[2], role="boot_a")],
            "extra-entry": good + [dict(good[0])],
        }
        for label, entries in rejected.items():
            with self.subTest(case=label):
                with self.assertRaises(au.MaintenanceError):
                    scenario.ack(entries)
                self.assertFalse(scenario.runtime.status(TXID)["backupAcknowledged"])

        ack = scenario.ack()
        self.assertTrue(ack["acknowledged"])
        self.assertTrue(ack["backupAckId"])
        self.assertTrue(scenario.runtime.status(TXID)["backupAcknowledged"])

        # Wrong boot identity is rejected even with correct snapshots.
        with self.assertRaises(au.MaintenanceError):
            scenario.runtime.ack_backups({
                "transactionId": TXID,
                "bootId": NEXT_BOOT_ID,
                "socSerial": scenario.platform.soc_serial,
                "backups": good,
            })

    def test_23_six_step_sequence_reaches_awaiting_factory_reset(self):
        scenario = self._scenario()
        token = scenario.prepared()
        scenario.ack()

        table_before = scenario.platform.table_fingerprint()
        misc_before = scenario.platform.misc_sha()
        plan_fingerprint = scenario.runtime.status(TXID)["planFingerprint"]
        stock_fingerprint = scenario.runtime.status(TXID)["stockFingerprint"]

        # The five restoration steps leave the transaction ``prepared``.
        for name in au.RESTORE_STEPS[:-1]:
            scenario.step(name, token)
            self.assertTrue(scenario.runtime.wait_idle(5))
            status = scenario.runtime.status(TXID)
            self.assertEqual(status["state"], "prepared")
            self.assertIsNone(status["activeStep"])
            self.assertIn(name, status["completedSteps"])
            self.assertEqual(status["planFingerprint"], plan_fingerprint)
            self.assertEqual(status["stockFingerprint"], stock_fingerprint)

        # Queueing the BCB is the terminal step and flips the state.
        self.assertEqual(au.RESTORE_STEPS[-1], "queue-factory-reset")
        scenario.step(au.RESTORE_STEPS[-1], token)
        self.assertTrue(scenario.runtime.wait_idle(5))
        queued = scenario.runtime.status(TXID)
        self.assertEqual(queued["state"], "awaitingFactoryReset")
        self.assertIsNone(queued["activeStep"])
        self.assertIn("queue-factory-reset", queued["completedSteps"])
        self.assertEqual(queued["planFingerprint"], plan_fingerprint)
        self.assertEqual(queued["stockFingerprint"], stock_fingerprint)

        final = scenario.runtime.status(TXID)
        self.assertEqual(final["state"], "awaitingFactoryReset")
        self.assertEqual(final["stage"], "AwaitingFactoryReset")
        self.assertIsNone(final["nextStep"])
        self.assertIsNone(final["activeStep"])
        self.assertEqual(list(final["completedSteps"]), list(au.RESTORE_STEPS))
        self.assertTrue(final["backupAcknowledged"])
        self.assertTrue(final["bothStockBootsValid"])
        self.assertIsNone(final["error"])

        self.assertEqual([call["slot"] for call in scenario.platform.restore_calls],
                         ["a", "b"])
        self.assertEqual([call["slot"] for call in scenario.platform.verify_calls],
                         ["a", "b"])
        self.assertEqual(
            scenario.platform.restore_calls[0]["expected_current_sha256"],
            _sha256(scenario.platform.current["a"]),
        )
        self.assertEqual(
            scenario.platform.restore_calls[0]["expected_stock_sha256"],
            scenario.assets["stock_boot_a"]["sha256"],
        )
        self.assertEqual(
            scenario.platform.restore_calls[1]["expected_current_sha256"],
            _sha256(scenario.platform.current["b"]),
        )
        self.assertEqual(
            [call["expected_sha256"] for call in scenario.platform.verify_calls],
            [scenario.assets["stock_boot_a"]["sha256"],
             scenario.assets["stock_boot_b"]["sha256"]],
        )

        self.assertEqual(len(scenario.platform.reclaim_calls), 1)
        self.assertEqual(scenario.platform.reclaim_calls[0]["fingerprint"],
                         table_before)
        self.assertEqual(scenario.platform.reclaim_calls[0]["removed"], (4, 5))
        self.assertEqual(
            scenario.platform.reclaim_calls[0]["userdata_start_sector"],
            USERDATA_START,
        )
        self.assertEqual(
            scenario.platform.reclaim_calls[0]["userdata_end_sector_exclusive"],
            ROOT_END_EXCL,
        )
        self.assertNotEqual(scenario.platform.table_fingerprint(), table_before)

        self.assertEqual(scenario.platform.bcb_calls, [misc_before])
        self.assertNotEqual(scenario.platform.misc_sha(), misc_before)
        self.assertTrue(scenario.platform.facts()["misc"]["bcbPending"])
        self.assertEqual(bytes(scenario.platform.misc[0:32]).rstrip(b"\x00"),
                         BCB_COMMAND)

        persisted = scenario.state_dir / "transactions" / TXID / "status.json"
        self.assertTrue(persisted.exists())
        on_disk = json.loads(persisted.read_text(encoding="utf-8"))
        self.assertEqual(on_disk["state"], "awaitingFactoryReset")
        self.assertEqual(on_disk["stage"], "AwaitingFactoryReset")
        self.assertEqual(on_disk["planFingerprint"], plan_fingerprint)
        self.assertEqual(on_disk["transactionId"], TXID)

        # The runtime never reboots or formats.
        self.assertFalse(hasattr(scenario.platform, "reboot"))
        self.assertFalse(hasattr(scenario.platform, "format"))
        self.assertFalse(hasattr(scenario.runtime, "reboot"))

    def test_24_duplicate_step_writes_once_and_worker_is_detached(self):
        gate = threading.Event()
        scenario = self._scenario(gate=gate)
        token = scenario.prepared()
        scenario.ack()

        first = scenario.step("restore-boot-a", token)
        self.assertEqual(first["state"], "running")
        self.assertEqual(first["activeStep"], "restore-boot-a")
        self.assertTrue(scenario.wait_for_restore_call())
        self.assertEqual(len(scenario.platform.restore_calls), 1)

        duplicate = scenario.step("restore-boot-a", token)
        self.assertEqual(duplicate["activeStep"], "restore-boot-a")
        self.assertEqual(len(scenario.platform.restore_calls), 1)

        gate.set()
        self.assertTrue(scenario.runtime.wait_idle(5))
        self.assertEqual(len(scenario.platform.restore_calls), 1)

        status = scenario.runtime.status(TXID)
        self.assertIn("restore-boot-a", status["completedSteps"])
        self.assertEqual(status["nextStep"], "verify-boot-a")

        again = scenario.step("restore-boot-a", token)
        self.assertIn("restore-boot-a", again["completedSteps"])
        self.assertEqual(len(scenario.platform.restore_calls), 1)

        with self.assertRaises(au.MaintenanceError) as context:
            scenario.step("verify-boot-b", token)
        self.assertEqual(context.exception.http_status, 409)
        self.assertEqual(len(scenario.platform.restore_calls), 1)
        self.assertEqual(scenario.platform.verify_calls, [])

    def test_25_changed_boot_id_blocks_steps(self):
        scenario = self._scenario()
        token = scenario.prepared()
        scenario.ack()
        scenario.step("restore-boot-a", token)
        self.assertTrue(scenario.runtime.wait_idle(5))
        writes = list(scenario.platform.entity_writes)

        scenario.platform.boot_id = NEXT_BOOT_ID
        with self.assertRaises(au.MaintenanceError) as context:
            scenario.step("verify-boot-a", token)
        self.assertEqual(context.exception.http_status, 409)
        self.assertEqual(scenario.platform.entity_writes, writes)
        self.assertEqual(scenario.platform.verify_calls, [])
        self.assertNotIn("verify-boot-a",
                         scenario.runtime.status(TXID)["completedSteps"])

        with self.assertRaises(au.MaintenanceError):
            scenario.step("verify-boot-a", token, boot_id=NEXT_BOOT_ID)
        self.assertEqual(scenario.platform.entity_writes, writes)

    def test_26_tampered_candidate_fails_before_any_write(self):
        scenario = self._scenario()
        token = scenario.prepared()
        scenario.ack()

        asset = scenario.state_dir / "assets" / "stock_boot_a.bin"
        asset.write_bytes(b"X" * BOOT_IMAGE_BYTES)

        try:
            scenario.step("restore-boot-a", token)
        except au.MaintenanceError as exc:
            self.assertEqual(exc.http_status, 409)
        scenario.runtime.wait_idle(5)
        status = scenario.runtime.status(TXID)

        self.assertEqual(status["state"], "failed")
        self.assertIsNotNone(status["error"])
        self.assertEqual(scenario.platform.restore_calls, [])
        self.assertEqual(scenario.platform.entity_writes, [])
        self.assertEqual(list(status["completedSteps"]), [])

        try:
            retry = scenario.step("restore-boot-a", token)
        except au.MaintenanceError as exc:
            self.assertEqual(exc.http_status, 409)
        else:
            self.assertEqual(retry["state"], "failed")
        self.assertEqual(scenario.platform.restore_calls, [])
        self.assertEqual(scenario.platform.entity_writes, [])
        self.assertEqual(scenario.runtime.status(TXID)["state"], "failed")

    def test_27_restore_error_is_terminal_and_status_is_read_only(self):
        failure = au.MaintenanceError("write-failed", "device rejected the write",
                                      500)
        scenario = self._scenario(restore_error=failure)
        token = scenario.prepared()
        scenario.ack()

        scenario.step("restore-boot-a", token)
        scenario.runtime.wait_idle(5)
        status = scenario.runtime.status(TXID)

        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["error"]["code"], "write-failed")
        self.assertEqual(len(scenario.platform.restore_calls), 1)
        self.assertEqual(scenario.platform.verify_calls, [])
        self.assertEqual(scenario.platform.reclaim_calls, [])
        self.assertEqual(scenario.platform.bcb_calls, [])
        self.assertEqual(scenario.platform.entity_writes, [])

        snapshot = json.dumps(scenario.runtime.status(TXID), sort_keys=True)
        scenario.runtime.status(TXID)
        self.assertEqual(
            json.dumps(scenario.runtime.status(TXID), sort_keys=True), snapshot)
        self.assertEqual(scenario.platform.entity_writes, [])
        self.assertEqual(len(scenario.platform.restore_calls), 1)

        try:
            scenario.step("verify-boot-a", token)
        except au.MaintenanceError as exc:
            self.assertEqual(exc.http_status, 409)
        self.assertEqual(scenario.platform.verify_calls, [])
        self.assertEqual(scenario.runtime.status(TXID)["state"], "failed")

    def test_28_validator_failure_fails_prepare_without_writes(self):
        validator = FakeRestoreValidator(fail_slots={"b"})
        scenario = self._scenario(validator=validator)
        disk_writes = len(scenario.platform.disk.writes)
        scenario.upload_all()

        with self.assertRaises(au.MaintenanceError) as context:
            scenario.prepare()
        self.assertEqual(context.exception.http_status, 409)
        self.assertEqual([call["slot"] for call in validator.calls], ["a", "b"])
        self.assertEqual(scenario.platform.entity_writes, [])
        self.assertEqual(len(scenario.platform.disk.writes), disk_writes)

        try:
            status = scenario.runtime.status(TXID)
        except au.MaintenanceError:
            pass
        else:
            self.assertFalse(status["bothStockBootsValid"])
            self.assertEqual(status["state"], "failed")


# ---------------------------------------------------------------------------
# L005b: LinuxBlockBackend syscall-boundary RED tests
#
# Every case calls a real public backend method. Only the module-level
# os/fcntl/Path/time references are replaced, by one fixed block-device
# boundary, so no /dev or /sys node can be reached by accident and there is
# no test flag and no alternate device-path argument. The private entry
# points are still stubs, so every case below is expected to be RED.
# ---------------------------------------------------------------------------

BLKGETSIZE64 = 0x80081272
BLKSSZGET = 0x1268
BLKRRPART = 0x125F
MISC_BYTES = 65536
BOOT_SLOT_BYTES = 512
STOCK_BOOT_A = b"STOCK-A".ljust(BOOT_SLOT_BYTES, b"\x00")
SYSFS_NODES = {
    "userdata": "/sys/class/block/sda3",
    "ARMADA_BOOT": "/sys/class/block/sda4",
    "ARMADA_ROOT": "/sys/class/block/sda5",
}
KERNEL_SLOTS = {"userdata": 3, "ARMADA_BOOT": 4, "ARMADA_ROOT": 5}

_REAL_OPEN = os.open
_REAL_CLOSE = os.close
_REAL_FSTAT = os.fstat
_REAL_PREAD = os.pread
_REAL_PWRITE = os.pwrite
_REAL_FSYNC = os.fsync
_REAL_READ_TEXT = Path.read_text
_REAL_EXISTS = Path.exists


class BlockClock:
    """Virtual monotonic clock: sleeps advance time instead of blocking."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        # Progress on every read, so even a sleep-free poll terminates.
        self.now += 0.001
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        # Even a zero sleep advances the clock, so a deadline always ends.
        self.now += max(0.001, float(seconds))


class BlockHarness:
    """Synthetic block-device boundary plus a fixture-built backend.

    ``_bindings``/``_identity``/``_current_gpt`` are populated directly, so
    these cases exercise the write guards and handle identity only: sysfs
    discovery, mount probing and the real constructor are out of scope.
    ``current_state`` is replaced by a fresh read-only probe over the same
    fixture, while ``assert_ready``, ``_open_target``, ``read_gpt``,
    ``plan_restore`` and the fd primitives stay the real code.
    """

    def __init__(self, root):
        self.root = Path(root)
        self.disk, self.layout, _ = gen4_current_disk()
        self.table = au.read_gpt(self.disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        original_disk, _, _ = gen4_original_disk()
        self.original = au.read_gpt(original_disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        self.plan = au.plan_restore(self.table, self.original, USERDATA_UUID,
                                    BOOT_UUID, ROOT_UUID)
        self.bindings = self._make_bindings()
        self.by_node = {item.node: item for item in self.bindings.values()}
        self.identity = {
            "model": "TB322FC",
            "socSerial": "SOC-TB322FC-0001",
            "bootId": FAKE_BOOT_ID,
            "diskPath": DISK_DEVICE_PATH,
            "diskBytes": GEN4_DISK_BYTES,
            "sectorSize": GEN4_SECTOR,
        }
        self.boot = {
            "a": bytearray(b"CURRENT-A".ljust(BOOT_SLOT_BYTES, b"\x00")),
            "b": bytearray(b"CURRENT-B".ljust(BOOT_SLOT_BYTES, b"\x00")),
        }
        self.buffers = {
            "boot_a": self.boot["a"],
            "boot_b": self.boot["b"],
            "misc": bytearray(MISC_BYTES),
            "boot_disk": bytearray(1 << 21),
        }
        self.misc = self.buffers["misc"]
        self.misc[OTA_OFFSET:OTA_OFFSET + 64] = ota_message()
        self.overrides = {}
        self.events = []
        self.clock = BlockClock()
        self.rrpart_error = None
        self.stale_sysfs = False
        self.flip_boot_readback = False
        self.misc_flip_offset = None
        self.write_rdev_override = {}
        self._fds = {}
        self._next_fd = 900
        self._flushed = False
        self._flipped = False
        self._kernel_cache = None
        self.backend = self._make_backend()

    def _make_bindings(self):
        disk = DISK_DEVICE_PATH

        def bind(label, node, major, minor, size, sector, part_uuid, number,
                 start, type_guid, parent=disk):
            if number == 0:
                parent = node
            return au._BlockBinding(label, node, major, minor, size, sector,
                                    part_uuid, parent, number, start, type_guid)

        return {
            "disk": bind("disk", disk, 8, 0, GEN4_DISK_BYTES, GEN4_SECTOR, "",
                         0, 0, ""),
            # Geometry-only whole-disk binding: discovery is not exercised.
            "boot_disk": bind("boot_disk", "/dev/sde", 8, 64, 1 << 21, 512, "",
                              0, 0, ""),
            "userdata": bind(
                "userdata", "/dev/sda3", 259, 3,
                (CURRENT_USERDATA_END_EXCL - USERDATA_START) * GEN4_SECTOR,
                GEN4_SECTOR, USERDATA_UUID, 3,
                USERDATA_START * GEN4_SECTOR, TYPE_LINUX_FS),
            "ARMADA_BOOT": bind(
                "ARMADA_BOOT", "/dev/sda4", 259, 4,
                BOOT_SECTORS * GEN4_SECTOR, GEN4_SECTOR, BOOT_UUID, 4,
                BOOT_START * GEN4_SECTOR, TYPE_LINUX_FS),
            "ARMADA_ROOT": bind(
                "ARMADA_ROOT", "/dev/sda5", 259, 5,
                (ROOT_END_EXCL - ROOT_START) * GEN4_SECTOR, GEN4_SECTOR,
                ROOT_UUID, 5, ROOT_START * GEN4_SECTOR, TYPE_LINUX_FS),
            # The A/B slots and misc are independent of the GPT fixture; the
            # offsets stay synthetic because discovery is not exercised.
            "boot_a": bind("boot_a", BOOT_SLOT_PATHS["a"], 8, 12, 512, 512,
                           BOOT_SLOT_UUIDS["a"], 12, 0, TYPE_LINUX_FS,
                           parent="/dev/sde"),
            "boot_b": bind("boot_b", BOOT_SLOT_PATHS["b"], 8, 45, 512, 512,
                           BOOT_SLOT_UUIDS["b"], 45, 0, TYPE_LINUX_FS,
                           parent="/dev/sde"),
            "misc": bind("misc", "/dev/sda6", 259, 6, MISC_BYTES,
                         GEN4_SECTOR, MISC_UUID, 6, 0, TYPE_LINUX_FS),
        }

    def _make_backend(self):
        backend = au.LinuxBlockBackend.__new__(au.LinuxBlockBackend)
        backend.state_dir = self.root
        backend.state_dir.mkdir(parents=True, exist_ok=True)
        backend._bindings = dict(self.bindings)
        backend._identity = dict(self.identity)
        backend._current_gpt = self.table
        backend.current_state = self.facts
        return backend

    def facts(self):
        """Fresh read-only probe in the shape assert_ready already uses."""
        gpt = au.read_gpt(self.disk, GEN4_SECTOR, GEN4_DISK_BYTES)
        slots = {}
        for slot in ("a", "b"):
            digest = _sha256(bytes(self.boot[slot]))
            vbmeta = _sha256(b"vbmeta-" + slot.encode("ascii"))
            slots[slot] = {
                "partitionPath": BOOT_SLOT_PATHS[slot],
                "partUuid": BOOT_SLOT_UUIDS[slot],
                "bytes": BOOT_SLOT_BYTES,
                "sha256": digest,
                "vbmetaSha256": vbmeta,
                "slotFingerprint": _sha256(f"{slot}:{digest}:{vbmeta}".encode()),
            }
        misc_sha = _sha256(bytes(self.misc))
        facts = {
            "schemaVersion": 1,
            "model": self.identity["model"],
            "socSerial": self.identity["socSerial"],
            "bootId": self.identity["bootId"],
            "ramRoot": True,
            "rootFstype": "rootfs",
            "compatible": ["lenovo,elden", "qcom,sm8750"],
            "diskPath": self.identity["diskPath"],
            "diskBytes": self.identity["diskBytes"],
            "sectorSize": self.identity["sectorSize"],
            "tableFingerprint": gpt.fingerprint,
            "primaryGptValid": True,
            "backupGptValid": True,
            "bootSlots": slots,
            "currentBootFingerprint": au.boot_state_fingerprint(
                {slot: slots[slot]["sha256"] for slot in ("a", "b")},
                {slot: slots[slot]["vbmetaSha256"] for slot in ("a", "b")}),
            "misc": {
                "partitionPath": self.bindings["misc"].node,
                "partUuid": MISC_UUID,
                "bytes": MISC_BYTES,
                "sha256": misc_sha,
                "bcbPending": any(self.misc[0:32]),
            },
            "miscFingerprint": misc_sha,
            "busy": {"rootOnTarget": False, "mountedPartitions": [],
                     "swapPartitions": [], "holderPartitions": []},
            "ota": {"state": "completed",
                    "evidence": bytes(
                        self.misc[OTA_OFFSET:OTA_OFFSET + 64]).hex()},
            "maintenanceValidated": True,
        }
        facts.update(self.overrides)
        return facts

    # -- syscall boundary ------------------------------------------------
    def _info(self, fd):
        try:
            return self._fds[fd]
        except KeyError:
            raise AssertionError(f"unknown file descriptor {fd}") from None

    def _open(self, path, flags, *args, **kwargs):
        text = str(path)
        write = bool(flags & (os.O_WRONLY | os.O_RDWR))
        if text.startswith(str(self.root)):
            fd = _REAL_OPEN(path, flags, *args, **kwargs)
            self._fds[fd] = ("tmp", text, write)
            self.events.append(("open", "tmp", text, write, fd))
            return fd
        binding = self.by_node.get(text)
        if binding is None:
            raise AssertionError(f"unexpected device path {text!r}")
        fd = self._next_fd
        self._next_fd += 1
        self._fds[fd] = (binding.label, text, write)
        self.events.append(("open", binding.label, text, write, fd))
        return fd

    def _close(self, fd):
        label = self._info(fd)[0]
        self._fds.pop(fd)
        self.events.append(("close", label))
        if label == "tmp":
            return _REAL_CLOSE(fd)
        return None

    def _fstat(self, fd):
        label, _node, write = self._info(fd)
        if label == "tmp":
            return _REAL_FSTAT(fd)
        binding = self.bindings[label]
        if write:
            major, minor = self.write_rdev_override.get(
                label, (binding.major, binding.minor))
        else:
            major, minor = binding.major, binding.minor
        self.events.append(("fstat", label, write))
        # A real block device reports st_size == 0; geometry comes from
        # BLKGETSIZE64/BLKSSZGET only.
        return mock.Mock(st_mode=stat.S_IFBLK | 0o660,
                         st_rdev=os.makedev(major, minor),
                         st_size=0)

    def _flock(self, fd, operation):
        self.events.append(("flock", self._info(fd)[0], operation))
        return None

    def _pread(self, fd, length, offset):
        label = self._info(fd)[0]
        self.events.append(("pread", label, offset, length))
        if label == "tmp":
            return _REAL_PREAD(fd, length, offset)
        chunk = self._read(label, offset, length)
        if (self._flushed and not self._flipped and label == "boot_a"
                and self.flip_boot_readback and chunk):
            chunk = bytearray(chunk)
            chunk[-1] ^= 0xFF
            self._flipped = True
            chunk = bytes(chunk)
        if (self._flushed and not self._flipped and label == "misc"
                and self.misc_flip_offset is not None
                and offset <= self.misc_flip_offset < offset + len(chunk)):
            chunk = bytearray(chunk)
            chunk[self.misc_flip_offset - offset] ^= 0xFF
            self._flipped = True
            chunk = bytes(chunk)
        return chunk

    def _pwrite(self, fd, data, offset):
        label, _node, write = self._info(fd)
        if not write:
            raise AssertionError(f"write on read-only handle {label}")
        payload = bytes(data)
        self.events.append(("pwrite", label, offset, len(payload)))
        if label == "tmp":
            return _REAL_PWRITE(fd, payload, offset)
        self._store(label, offset, payload)
        return len(payload)

    def _fsync(self, fd):
        label = self._info(fd)[0]
        self.events.append(("fsync", label))
        if label == "tmp":
            return _REAL_FSYNC(fd)
        return None

    def _read(self, label, offset, length):
        if label == "disk":
            return self._disk_bytes(offset, length)
        if label in ("userdata", "ARMADA_BOOT", "ARMADA_ROOT"):
            return self._disk_bytes(
                self.bindings[label].start_bytes + offset, length)
        if label in self.buffers:
            return bytes(self.buffers[label][offset:offset + length])
        raise AssertionError(f"unexpected read target {label}")

    def _store(self, label, offset, payload):
        if label == "disk":
            self.disk.write_at(offset, payload)
        elif label in ("userdata", "ARMADA_BOOT", "ARMADA_ROOT"):
            self.disk.write_at(
                self.bindings[label].start_bytes + offset, payload)
        elif label in self.buffers:
            self.buffers[label][offset:offset + len(payload)] = payload
        else:
            raise AssertionError(f"unexpected write target {label}")

    def _disk_bytes(self, offset, length):
        self.disk.seek(offset)
        return self.disk.read(length)

    def _ioctl(self, fd, request, argument=0, *rest):
        label = self._info(fd)[0]
        self.events.append(("ioctl", label, request))
        if request == au._BLKFLSBUF:
            self._flushed = True
            return 0
        if request == BLKRRPART:
            if self.rrpart_error is not None:
                raise self.rrpart_error
            return 0
        if label not in self.bindings:
            raise AssertionError(f"ioctl 0x{request:x} on {label}")
        binding = self.bindings[label]
        if request == BLKGETSIZE64:
            fmt, value = "<Q", binding.size_bytes
        elif request == BLKSSZGET:
            fmt, value = "<I", binding.sector_size
        else:
            raise AssertionError(f"unexpected ioctl 0x{request:x} on {label}")
        packed = struct.pack(fmt, value)
        if isinstance(argument, (bytearray, memoryview)):
            argument[:len(packed)] = packed
            return 0
        if isinstance(argument, bytes):
            return packed.ljust(len(argument), b"\x00")
        if isinstance(argument, int) and argument == 0:
            return value
        raise AssertionError(f"unsupported ioctl argument {argument!r}")

    # -- kernel remap and patch stack ------------------------------------
    def _kernel_view(self, gpt):
        values, present = {}, {}
        for node in SYSFS_NODES.values():
            present[node] = False
        for entry in gpt.entries:
            for name, number in KERNEL_SLOTS.items():
                if entry.number != number:
                    continue
                node = SYSFS_NODES[name]
                values[node + "/start"] = str(
                    entry.first_lba * (GEN4_SECTOR // 512))
                values[node + "/size"] = str(
                    (entry.last_lba - entry.first_lba + 1)
                    * (GEN4_SECTOR // 512))
                present[node] = True
        return values, present

    def _kernel(self):
        if self._kernel_cache is None:
            gpt = self.table if self.stale_sysfs else au.read_gpt(
                self.disk, GEN4_SECTOR, GEN4_DISK_BYTES)
            self._kernel_cache = self._kernel_view(gpt)
        return self._kernel_cache

    def _read_text(self, path_obj, *args, **kwargs):
        text = str(path_obj)
        if text.startswith(str(self.root)):
            return _REAL_READ_TEXT(path_obj, *args, **kwargs)
        values = self._kernel()[0]
        if text not in values:
            raise AssertionError(f"unexpected sysfs read {text!r}")
        return values[text]

    def _exists(self, path_obj):
        text = str(path_obj)
        if text.startswith(str(self.root)):
            return _REAL_EXISTS(path_obj)
        present = self._kernel()[1]
        if text not in present:
            raise AssertionError(f"unexpected sysfs stat {text!r}")
        return present[text]

    def enter(self, stack):
        def read_text(path_obj, *args, **kwargs):
            return self._read_text(path_obj, *args, **kwargs)

        def exists(path_obj):
            return self._exists(path_obj)

        for name in ("open", "close", "fstat", "pread", "pwrite", "fsync"):
            stack.enter_context(
                mock.patch.object(au.os, name, getattr(self, "_" + name)))
        stack.enter_context(mock.patch.object(au.fcntl, "ioctl", self._ioctl))
        stack.enter_context(mock.patch.object(au.fcntl, "flock", self._flock))
        stack.enter_context(mock.patch.object(Path, "read_text", read_text))
        stack.enter_context(mock.patch.object(Path, "exists", exists))
        stack.enter_context(
            mock.patch.object(au, "time", self.clock, create=True))


class LinuxAdapterTests(unittest.TestCase):
    """Backend syscall boundary: real public methods, fake kernel only."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="l005b-")
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _assert_reclaim_stream(self, harness, plan):
        events = harness.events
        writes = [event for event in events if event[0] == "pwrite"]
        self.assertEqual(
            [(event[1], event[2], event[3]) for event in writes],
            [("disk", region.offset, len(region.data))
             for region in plan.write_regions],
            "table writes must follow the plan region order exactly",
        )
        for index, event in enumerate(events):
            if event[0] != "pwrite":
                continue
            self.assertLess(index + 1, len(events))
            self.assertEqual(events[index + 1][0], "fsync",
                             "each table write needs an immediate fsync")
        userdata_span = (USERDATA_START * GEN4_SECTOR,
                         CURRENT_USERDATA_END_EXCL * GEN4_SECTOR)
        for event in writes:
            self.assertGreaterEqual(event[2], GEN4_SECTOR)
            self.assertFalse(event[2] < userdata_span[1]
                             and event[2] + event[3] > userdata_span[0])
        self.assertEqual({event[1] for event in writes}, {"disk"})
        flushes = [index for index, event in enumerate(events)
                   if event[0] == "ioctl" and event[2] == au._BLKFLSBUF]
        rereads = [index for index, event in enumerate(events)
                   if event[0] == "ioctl" and event[2] == BLKRRPART]
        self.assertTrue(flushes)
        self.assertTrue(rereads)
        self.assertLess(max(index for index, event in enumerate(events)
                            if event[0] == "pwrite"), flushes[-1])
        self.assertLess(flushes[-1], rereads[0])
        self.assertNotIn("misc", {event[1] for event in events
                                  if event[0] == "open"})

    def test_29_unready_or_wrong_handle_identity_never_writes(self):
        busy = {"rootOnTarget": False, "mountedPartitions": ["/dev/sda3"],
                "swapPartitions": [], "holderPartitions": []}
        cases = {
            "ram-root": {"ramRoot": False},
            "root-fstype": {"rootFstype": "btrfs"},
            "mounted": {"busy": busy},
            "holder": {"busy": dict(busy, mountedPartitions=[],
                                    holderPartitions=["/dev/sda3"])},
            "wrong-rdev": {},
        }
        for label, override in cases.items():
            with self.subTest(case=label):
                harness = BlockHarness(self.root)
                candidate = self.root / f"stock-a-{label}.bin"
                candidate.write_bytes(STOCK_BOOT_A)
                current_sha = _sha256(bytes(harness.boot["a"]))
                if label == "wrong-rdev":
                    harness.write_rdev_override["boot_a"] = (8, 99)
                else:
                    harness.overrides.update(override)
                with contextlib.ExitStack() as stack:
                    harness.enter(stack)
                    with self.assertRaises(au.MaintenanceError):
                        harness.backend.restore_boot(
                            "a", candidate, current_sha,
                            _sha256(STOCK_BOOT_A))
                    events = harness.events
                    self.assertEqual(
                        [event for event in events if event[0] == "pwrite"], [])
                    self.assertEqual(
                        [event for event in events
                         if event[0] == "ioctl"
                         and event[2] in (au._BLKFLSBUF, BLKRRPART)], [])
                    write_opens = [event for event in events
                                   if event[0] == "open" and event[3]]
                    if label == "wrong-rdev":
                        # The write handle was opened, its identity was
                        # checked, and it was closed again without a write.
                        self.assertEqual([event[1] for event in write_opens],
                                         ["boot_a"])
                        self.assertIn(("fstat", "boot_a", True), events)
                        self.assertIn(("close", "boot_a"), events)
                    else:
                        self.assertEqual(write_opens, [])

    def test_30_reclaim_exact_order_and_reread_failure(self):
        for label in ("rrpart-busy", "stale-mapping"):
            with self.subTest(case=label):
                harness = BlockHarness(self.root)
                plan = harness.plan
                fingerprint = harness.table.fingerprint
                if label == "rrpart-busy":
                    harness.rrpart_error = OSError(errno.EBUSY, "device busy")
                else:
                    harness.stale_sysfs = True
                with contextlib.ExitStack() as stack:
                    harness.enter(stack)
                    with self.assertRaises(au.MaintenanceError):
                        harness.backend.reclaim_space(plan, fingerprint)
                    self._assert_reclaim_stream(harness, plan)
                    if label == "stale-mapping":
                        # The poll must give up on the virtual clock.
                        self.assertTrue(harness.clock.sleeps)
                        self.assertLessEqual(len(harness.clock.sleeps), 1000)
                restored = au.read_gpt(harness.disk, GEN4_SECTOR,
                                       GEN4_DISK_BYTES)
                self.assertEqual([entry.number for entry in restored.entries],
                                 [1, 2, 3])
                self.assertEqual(restored.entries[2].first_lba, USERDATA_START)
                self.assertEqual(restored.entries[2].last_lba,
                                 ROOT_END_EXCL - 1)
                for index in (0, 1):
                    self.assertEqual(restored.entries[index].raw,
                                     harness.table.entries[index].raw)

    def test_31_misc_preserves_entire_partition_and_detects_outside_corruption(
            self):
        for label in ("clean", "outside-flip"):
            with self.subTest(case=label):
                harness = BlockHarness(self.root)
                misc = harness.misc
                misc[32:64] = bytes((index * 11 + 7) % 256
                                    for index in range(32))
                misc[832:2048] = bytes((index * 13 + 5) % 256
                                       for index in range(1216))
                misc[2048:MISC_BYTES] = bytes(
                    (index * 17 + 3) % 256
                    for index in range(MISC_BYTES - 2048))
                misc[OTA_OFFSET:OTA_OFFSET + 64] = ota_message()
                self.assertEqual(bytes(misc[0:32]), b"\x00" * 32)
                self.assertEqual(bytes(misc[64:832]), b"\x00" * 768)

                expected = bytearray(misc)
                expected[0:32] = BCB_COMMAND.ljust(32, b"\x00")
                expected[64:832] = BCB_RECOVERY.ljust(768, b"\x00")
                original_sha = _sha256(bytes(misc))
                if label == "outside-flip":
                    # A single flipped byte at 4096 sits outside the BCB but
                    # inside the partition that must be verified.
                    harness.misc_flip_offset = 4096
                with contextlib.ExitStack() as stack:
                    harness.enter(stack)
                    if label == "clean":
                        digest = harness.backend.queue_factory_reset(
                            original_sha)
                        self.assertEqual(digest, _sha256(bytes(expected)))
                    else:
                        with self.assertRaises(au.MaintenanceError):
                            harness.backend.queue_factory_reset(original_sha)
                    writes = [event for event in harness.events
                              if event[0] == "pwrite"]
                    self.assertTrue(writes)
                    self.assertEqual({event[1] for event in writes}, {"misc"})
                    self.assertEqual(min(event[2] for event in writes), 0)
                    for event in writes:
                        self.assertLessEqual(event[2] + event[3], 2048)
                self.assertEqual(bytes(misc), bytes(expected))
                self.assertEqual(bytes(misc[32:64]), bytes(expected[32:64]))
                self.assertEqual(bytes(misc[832:2048]),
                                 bytes(expected[832:2048]))
                self.assertEqual(bytes(misc[OTA_OFFSET:OTA_OFFSET + 64]),
                                 ota_message())

    def test_32_boot_a_readback_failure_does_not_return_success(self):
        harness = BlockHarness(self.root)
        candidate = self.root / "stock-boot-a.bin"
        candidate.write_bytes(STOCK_BOOT_A)
        current_sha = _sha256(bytes(harness.boot["a"]))
        harness.flip_boot_readback = True
        with contextlib.ExitStack() as stack:
            harness.enter(stack)
            # Runtime failure mapping is covered by test_27; this case only
            # pins that a bad read-back never returns success.
            with self.assertRaises(au.MaintenanceError):
                harness.backend.restore_boot("a", candidate, current_sha,
                                             _sha256(STOCK_BOOT_A))
            events = harness.events
            writes = [event for event in events if event[0] == "pwrite"]
            self.assertTrue(writes)
            self.assertEqual({event[1] for event in writes}, {"boot_a"})
            self.assertEqual(writes[0][2], 0)
            self.assertEqual(sum(event[3] for event in writes), BOOT_SLOT_BYTES)
            self.assertEqual(bytes(harness.boot["a"]), STOCK_BOOT_A)
            self.assertIn(("fsync", "boot_a"), events)
            flushes = [index for index, event in enumerate(events)
                       if event[0] == "ioctl" and event[2] == au._BLKFLSBUF]
            self.assertTrue(flushes)
            last_write = max(index for index, event in enumerate(events)
                             if event[0] == "pwrite")
            self.assertLess(last_write, flushes[-1])
            self.assertFalse([event for event in events[flushes[-1]:]
                              if event[0] == "pwrite"])


# ---------------------------------------------------------------------------
# L007: HTTP wire and CLI entry RED tests
#
# The handler factory is a stub, so every case fails at construction time
# before any socket is opened. The doubles below are tiny and deterministic;
# only test 35 uses the real MaintenanceRuntime over a real job.
# ---------------------------------------------------------------------------

SESSION_TOKEN = "0123456789abcdef" * 4
SESSION_TOKEN_UPPER = "0123456789ABCDEF" * 4
FIXED_BIND = "192.168.77.1"
FIXED_PORT = 8202


def auth_header(token=SESSION_TOKEN):
    return {"Authorization": f"Bearer {token}"}


def _decode_headers(lines):
    headers = {}
    for line in lines:
        if not line:
            continue
        key, _, value = line.partition(b":")
        headers[key.strip().decode("latin-1").lower()] = (
            value.strip().decode("latin-1")
        )
    return headers


def raw_http(port, method, path, *, body=None, headers=None, timeout=4.0):
    """Send one Connection: close request and return (status, headers, body)."""

    request = [
        f"{method} {path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Connection: close",
    ]
    for key, value in (headers or {}).items():
        request.append(f"{key}: {value}")
    payload = ("\r\n".join(request) + "\r\n\r\n").encode("ascii")
    if body is not None:
        payload += body

    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(payload)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)

    head, _, response_body = b"".join(chunks).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    return status, _decode_headers(lines[1:]), response_body


def send_and_disconnect(port, method, path, *, body=b"", headers=None,
                        timeout=5.0):
    """Send a complete request and close without ever reading the response."""

    request = [
        f"{method} {path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Connection: close",
    ]
    for key, value in (headers or {}).items():
        request.append(f"{key}: {value}")
    payload = ("\r\n".join(request) + "\r\n\r\n").encode("ascii") + body
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(payload)
    finally:
        sock.close()


class FakeRuntime:
    """Deterministic runtime double: records calls, never touches a device."""

    def __init__(self, root, *, boot_bytes=512):
        self.root = Path(root)
        self.boot_bytes = boot_bytes
        self.calls = []
        self.runtime_reads = 0
        self.fail = None
        self.fail_methods = set()
        self.backup_payload = {
            "a": b"BOOT-A\x00\xff" * 8,
            "b": b"BOOT-B\x00\xfe" * 8,
            "misc": b"MISC\x00\x01\x02" * 8,
        }
        self.status_doc = {
            "schemaVersion": 1,
            "transactionId": TXID,
            "state": "prepared",
            "stage": "Prepared",
            "nextStep": "restore-boot-a",
            "activeStep": None,
            "completedSteps": [],
            "error": None,
        }

    def _maybe_fail(self, name):
        if name in self.fail_methods and self.fail is not None:
            raise self.fail

    def inspect(self):
        self.calls.append(("inspect",))
        self._maybe_fail("inspect")
        return {
            "schemaVersion": 1,
            "model": "TB322FC",
            "device": "测试设备",
            "footnote": "仅限离线维护",
            "bootSlots": {
                "a": {"bytes": self.boot_bytes},
                "b": {"bytes": self.boot_bytes},
            },
        }

    def backup_file(self, role):
        self.calls.append(("backup_file", role))
        self._maybe_fail("backup_file")
        data = self.backup_payload[role]
        path = self.root / f"{role}.img"
        path.write_bytes(data)
        return path, {"role": role, "bytes": len(data),
                      "sha256": _sha256(data)}

    def put_asset(self, role, reader, length):
        self.calls.append(("put_asset", role, length))
        self._maybe_fail("put_asset")
        data = reader.read(length)
        self.runtime_reads += len(data)
        return {"role": role, "bytes": len(data), "sha256": _sha256(data)}

    def prepare(self, payload):
        self.calls.append(("prepare", payload))
        self._maybe_fail("prepare")
        return dict(self.status_doc, state="prepared", error=None)

    def ack_backups(self, payload):
        self.calls.append(("ack_backups", payload))
        self._maybe_fail("ack_backups")
        return {"acknowledged": True, "backupAckId": "f" * 64}

    def step(self, transaction_id, payload):
        self.calls.append(("step", transaction_id, payload))
        self._maybe_fail("step")
        return dict(self.status_doc, state="running",
                    activeStep=payload.get("step"),
                    nextStep=payload.get("step"))

    def status(self, transaction_id):
        self.calls.append(("status", transaction_id))
        self._maybe_fail("status")
        return dict(self.status_doc)


class HttpWireTests(unittest.TestCase):
    """Real loopback HTTP against a test-only ThreadingHTTPServer."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="l007-")
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    @contextlib.contextmanager
    def _http_server(self, runtime, token=None):
        handler = au.make_http_handler(
            runtime, SESSION_TOKEN if token is None else token
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_33_auth_inspect_and_backup_routes(self):
        runtime = FakeRuntime(self.root)
        with self._http_server(runtime) as port:
            for label, headers in (
                ("missing", {}),
                ("wrong", {"Authorization": "Bearer " + "f" * 64}),
            ):
                with self.subTest(auth=label):
                    status, _headers, body = raw_http(
                        port, "GET", "/v1/inspect", headers=headers
                    )
                    self.assertEqual(status, 401)
                    self.assertNotIn(SESSION_TOKEN.encode("ascii"), body)
                    document = json.loads(body.decode("utf-8"))
                    self.assertIn("code", document["error"])
                    self.assertIn("message", document["error"])

            # Neither rejected request reached the runtime.
            self.assertEqual(runtime.calls, [])

            status, headers, body = raw_http(
                port, "GET", "/v1/inspect", headers=auth_header()
            )
            self.assertEqual(status, 200)
            document = json.loads(body.decode("utf-8"))
            self.assertEqual(document["device"], "测试设备")
            self.assertEqual(int(headers["content-length"]), len(body))
            self.assertEqual(headers.get("connection", "").lower(), "close")

            for role in ("a", "b", "misc"):
                with self.subTest(boot=role):
                    status, headers, body = raw_http(
                        port, "GET", f"/v1/boot/{role}", headers=auth_header()
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(body, runtime.backup_payload[role])
                    self.assertEqual(headers["x-content-sha256"], _sha256(body))
                    self.assertEqual(int(headers["content-length"]), len(body))

            before = [call for call in runtime.calls
                      if call[0] == "backup_file"]
            for path in ("/v1/unknown", "/v1/boot/default",
                         "/v1/boot/../../etc/passwd"):
                with self.subTest(path=path):
                    status, _headers, _body = raw_http(
                        port, "GET", path, headers=auth_header()
                    )
                    self.assertEqual(status, 404)
            self.assertEqual(
                [call for call in runtime.calls if call[0] == "backup_file"],
                before,
            )

    def test_34_uploads_json_errors_and_routes(self):
        runtime = FakeRuntime(self.root)
        with self._http_server(runtime) as port:
            for index, role in enumerate(au.ASSET_ROLES):
                data = bytes([index + 1]) * 16
                with self.subTest(upload=role):
                    status, _headers, body = raw_http(
                        port, "PUT", f"/v1/assets/{role}", body=data,
                        headers=dict(auth_header(),
                                     **{"Content-Length": str(len(data))}),
                    )
                    self.assertEqual(status, 200)
                    document = json.loads(body.decode("utf-8"))
                    self.assertEqual(document["role"], role)
                    self.assertEqual(document["bytes"], len(data))
                    self.assertEqual(document["sha256"], _sha256(data))

            # An exact-length ordinary request returns while the client is
            # still waiting: a handler read past Content-Length would block.
            connection = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=2
            )
            try:
                connection.request(
                    "PUT", "/v1/assets/trusted_vbmeta_baseline",
                    body=b"y" * 32,
                    headers=dict(auth_header(),
                                 **{"Content-Length": "32"}),
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 200)
            finally:
                connection.close()

            status, _headers, _body = raw_http(
                port, "PUT", "/v1/assets/stock_boot_a", headers=auth_header()
            )
            self.assertEqual(status, 411)

            for label, value in (("invalid", "abc"), ("negative", "-1")):
                with self.subTest(length=label):
                    status, _headers, _body = raw_http(
                        port, "PUT", "/v1/assets/stock_boot_a",
                        headers=dict(auth_header(),
                                     **{"Content-Length": value}),
                    )
                    self.assertEqual(status, 400)

            status, _headers, _body = raw_http(
                port, "PUT", "/v1/assets/not-a-role", body=b"abcd",
                headers=dict(auth_header(), **{"Content-Length": "4"}),
            )
            self.assertEqual(status, 404)

            before_reads = runtime.runtime_reads
            before_puts = [call for call in runtime.calls
                           if call[0] == "put_asset"]
            oversize = {
                "stock_boot_a": 512 + 1,
                "original_primary_gpt": (16 << 20) + 1,
                "trusted_vbmeta_baseline": (1 << 20) + 1,
            }
            for role, length in oversize.items():
                with self.subTest(oversize=role):
                    status, _headers, _body = raw_http(
                        port, "PUT", f"/v1/assets/{role}",
                        headers=dict(auth_header(),
                                     **{"Content-Length": str(length)}),
                    )
                    self.assertEqual(status, 413)
            self.assertEqual(runtime.runtime_reads, before_reads)
            self.assertEqual(
                [call for call in runtime.calls if call[0] == "put_asset"],
                before_puts,
            )

            prepare_body = json.dumps({"transactionId": TXID}).encode("utf-8")
            status, _headers, body = raw_http(
                port, "POST", "/v1/prepare", body=prepare_body,
                headers=dict(auth_header(),
                             **{"Content-Length": str(len(prepare_body))}),
            )
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body.decode("utf-8"))["error"])

            ack_body = json.dumps({"transactionId": TXID}).encode("utf-8")
            status, _headers, body = raw_http(
                port, "POST", "/v1/ack-backups", body=ack_body,
                headers=dict(auth_header(),
                             **{"Content-Length": str(len(ack_body))}),
            )
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body.decode("utf-8"))["acknowledged"])

            step_body = json.dumps({
                "step": "restore-boot-a",
                "bootId": FAKE_BOOT_ID,
                "confirmationToken": "c" * 64,
                "wipeConfirmed": True,
            }).encode("utf-8")
            status, _headers, body = raw_http(
                port, "POST", f"/v1/transactions/{TXID}/step", body=step_body,
                headers=dict(auth_header(),
                             **{"Content-Length": str(len(step_body))}),
            )
            self.assertEqual(status, 202)
            document = json.loads(body.decode("utf-8"))
            self.assertEqual(document["state"], "running")
            self.assertEqual(document["activeStep"], "restore-boot-a")
            self.assertIsNone(document["error"])

            status, _headers, body = raw_http(
                port, "GET", f"/v1/transactions/{TXID}/status",
                headers=auth_header(),
            )
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body.decode("utf-8"))["error"])

            bad_json = b"{"
            status, _headers, _body = raw_http(
                port, "POST", "/v1/prepare", body=bad_json,
                headers=dict(auth_header(),
                             **{"Content-Length": str(len(bad_json))}),
            )
            self.assertEqual(status, 400)

            status, _headers, _body = raw_http(
                port, "POST", "/v1/prepare",
                headers=dict(auth_header(),
                             **{"Content-Length": str((1 << 20) + 1)}),
            )
            self.assertEqual(status, 413)

            status, _headers, _body = raw_http(
                port, "POST", "/v1/prepare", headers=auth_header()
            )
            self.assertEqual(status, 411)

            failure = au.MaintenanceError("step-conflict", "boom", 409)
            failure.stage = "Step"
            runtime.fail = failure
            runtime.fail_methods = {"step"}
            status, _headers, body = raw_http(
                port, "POST", f"/v1/transactions/{TXID}/step", body=step_body,
                headers=dict(auth_header(),
                             **{"Content-Length": str(len(step_body))}),
            )
            self.assertEqual(status, 409)
            document = json.loads(body.decode("utf-8"))
            self.assertEqual(document["error"]["code"], "step-conflict")
            self.assertEqual(document["error"]["message"], "boom")
            self.assertEqual(document["error"]["stage"], "Step")

            missing = au.MaintenanceError("transaction-unknown", "unknown", 404)
            runtime.fail = missing
            runtime.fail_methods = {"status"}
            status, _headers, body = raw_http(
                port, "GET", f"/v1/transactions/{TXID}/status",
                headers=auth_header(),
            )
            self.assertEqual(status, 404)
            self.assertEqual(
                json.loads(body.decode("utf-8"))["error"]["code"],
                "transaction-unknown",
            )

    def test_35_disconnect_does_not_cancel_the_job(self):
        gate = threading.Event()
        scenario = MaintenanceScenario(self.root / "scenario", gate=gate)
        try:
            confirmation = scenario.prepared()
            scenario.ack()

            step_body = json.dumps({
                "step": "restore-boot-a",
                "bootId": FAKE_BOOT_ID,
                "confirmationToken": confirmation,
                "wipeConfirmed": True,
            }).encode("utf-8")

            with self._http_server(scenario.runtime) as port:
                send_and_disconnect(
                    port, "POST", f"/v1/transactions/{TXID}/step",
                    body=step_body,
                    headers=dict(auth_header(),
                                 **{"Content-Length": str(len(step_body))}),
                )

                deadline = time.time() + 5
                document = None
                while time.time() < deadline:
                    status, _headers, body = raw_http(
                        port, "GET", f"/v1/transactions/{TXID}/status",
                        headers=auth_header(),
                    )
                    if status == 200:
                        document = json.loads(body.decode("utf-8"))
                        if (document.get("state") == "running"
                                and scenario.platform.restore_calls):
                            break
                    time.sleep(0.02)

                self.assertIsNotNone(document)
                self.assertEqual(document["state"], "running")
                self.assertEqual(document["activeStep"], "restore-boot-a")
                self.assertEqual(document["nextStep"], "restore-boot-a")
                self.assertTrue(scenario.platform.restore_calls)

                gate.set()
                self.assertTrue(scenario.runtime.wait_idle(5))

                status, _headers, body = raw_http(
                    port, "GET", f"/v1/transactions/{TXID}/status",
                    headers=auth_header(),
                )
                self.assertEqual(status, 200)
                document = json.loads(body.decode("utf-8"))
                self.assertEqual(list(document["completedSteps"]),
                                 ["restore-boot-a"])
                self.assertEqual(document["nextStep"], "verify-boot-a")
                self.assertEqual(len(scenario.platform.restore_calls), 1)

                status, _headers, body = raw_http(
                    port, "GET", "/v1/inspect", headers=auth_header()
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    json.loads(body.decode("utf-8"))["model"], "TB322FC"
                )

                status, _headers, _body = raw_http(
                    port, "GET", f"/v1/transactions/{TXID}/status",
                    headers=auth_header(),
                )
                self.assertEqual(status, 200)
        finally:
            gate.set()
            scenario.runtime.wait_idle(5)


class HttpEntryTests(unittest.TestCase):
    """Token file and CLI entry contracts; no sockets, no devices."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="l007-entry-")
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _token_file(self, name, data, mode=0o600):
        path = self.root / name
        path.write_bytes(data)
        os.chmod(path, mode)
        return path

    def test_36_token_file_strict_reader(self):
        cases = {
            "lower": (SESSION_TOKEN.encode("ascii"), SESSION_TOKEN),
            "upper": (SESSION_TOKEN_UPPER.encode("ascii"), SESSION_TOKEN_UPPER),
            "lf": (SESSION_TOKEN.encode("ascii") + b"\n", SESSION_TOKEN),
            "crlf": (SESSION_TOKEN_UPPER.encode("ascii") + b"\r\n",
                     SESSION_TOKEN_UPPER),
        }
        for label, (data, expected) in cases.items():
            with self.subTest(case=label):
                path = self._token_file(f"{label}.token", data)
                self.assertEqual(au.load_session_token(path), expected)

        rejected = {
            "short": SESSION_TOKEN[:63].encode("ascii"),
            "long": (SESSION_TOKEN + "0").encode("ascii"),
            "non-hex": b"g" * 64,
            "two-lines": (SESSION_TOKEN + "\n" + SESSION_TOKEN_UPPER
                          + "\n").encode("ascii"),
            "bare-cr": SESSION_TOKEN.encode("ascii") + b"\r",
            "double-lf": SESSION_TOKEN.encode("ascii") + b"\n\n",
        }
        for label, data in rejected.items():
            with self.subTest(case=label):
                path = self._token_file(f"{label}.token", data)
                with self.assertRaises(au.MaintenanceError) as context:
                    au.load_session_token(path)
                self.assertNotIn(SESSION_TOKEN, str(context.exception))

        target = self._token_file("target.token",
                                  SESSION_TOKEN.encode("ascii"))
        link = self.root / "link.token"
        link.symlink_to(target)
        with self.assertRaises(au.MaintenanceError) as context:
            au.load_session_token(link)
        self.assertNotIn(SESSION_TOKEN, str(context.exception))

        for label, mode in (("group-readable", 0o640),
                            ("world-readable", 0o644)):
            with self.subTest(case=label):
                path = self._token_file(f"{label}.token",
                                        SESSION_TOKEN.encode("ascii"), mode)
                with self.assertRaises(au.MaintenanceError) as context:
                    au.load_session_token(path)
                self.assertNotIn(SESSION_TOKEN, str(context.exception))

    def _token_path(self):
        return self._token_file("session.token",
                                SESSION_TOKEN.encode("ascii"))

    def _invoke(self, argv):
        try:
            return au.main(argv)
        except SystemExit as exc:
            return exc.code

    def test_37_cli_fixed_serve_and_inspect(self):
        token_path = self._token_path()
        state_dir = self.root / "state"

        bad_arguments = {
            "bind": ["serve", "--state-dir", str(state_dir),
                     "--token-file", str(token_path),
                     "--bind", "127.0.0.1"],
            "port": ["serve", "--state-dir", str(state_dir),
                     "--token-file", str(token_path),
                     "--port", "0"],
        }
        for label, argv in bad_arguments.items():
            with self.subTest(case=label):
                with mock.patch.object(au, "LinuxBlockBackend") as backend, \
                        mock.patch.object(au, "serve_runtime") as serve:
                    self.assertEqual(self._invoke(argv), 2)
                backend.assert_not_called()
                serve.assert_not_called()

        with mock.patch.object(au, "LinuxBlockBackend") as backend, \
                mock.patch.object(au, "serve_runtime") as serve, \
                mock.patch.object(
                    au, "load_session_token",
                    side_effect=au.MaintenanceError(
                        "token-invalid", "token file rejected")):
            code = self._invoke([
                "serve", "--state-dir", str(state_dir),
                "--token-file", str(token_path),
            ])
        self.assertEqual(code, 2)
        backend.assert_not_called()
        serve.assert_not_called()

        fake_backend = mock.Mock()
        fake_backend.model = None
        fake_backend.ram_root = True
        fake_backend.root_fstype = "rootfs"
        with mock.patch.object(
                au, "LinuxBlockBackend", return_value=fake_backend) as backend, \
                mock.patch.object(au, "serve_runtime") as serve, \
                mock.patch.object(
                    au, "load_session_token", return_value=SESSION_TOKEN):
            code = self._invoke([
                "serve", "--state-dir", str(state_dir),
                "--token-file", str(token_path),
            ])
        self.assertEqual(code, 0)
        backend.assert_called_once()
        self.assertEqual(str(backend.call_args.args[0]), str(state_dir))
        serve.assert_called_once()
        call = serve.call_args
        values = list(call.args) + list(call.kwargs.values())
        self.assertIn(SESSION_TOKEN, values)
        self.assertIn(FIXED_BIND, values)
        self.assertIn(FIXED_PORT, values)
        self.assertTrue(hasattr(call.args[0], "inspect"))

        facts = {
            "schemaVersion": 1,
            "model": "TB322FC",
            "device": "测试设备",
        }
        fake_backend = mock.Mock()
        fake_backend.model = None
        fake_backend.ram_root = True
        fake_backend.root_fstype = "rootfs"
        fake_backend.current_state.return_value = facts
        output = io.StringIO()
        with mock.patch.object(
                au, "LinuxBlockBackend", return_value=fake_backend), \
                mock.patch.object(au, "serve_runtime") as serve, \
                contextlib.redirect_stdout(output):
            code = self._invoke(["inspect", "--state-dir", str(state_dir)])
        self.assertEqual(code, 0)
        serve.assert_not_called()
        document = json.loads(output.getvalue())
        self.assertEqual(document["device"], "测试设备")

        for flag in ("--reboot", "--wipe", "--format", "--auto-reboot"):
            with self.subTest(case=flag):
                with mock.patch.object(au, "LinuxBlockBackend") as backend:
                    self.assertEqual(
                        self._invoke(["inspect", "--state-dir",
                                      str(state_dir), flag]), 2)
                backend.assert_not_called()


class RealGptIntegrationTests(unittest.TestCase):
    """Real before/after GPT captures mounted under ``AVB_TEST_ASSET_ROOT``.

    The captures are read only after the environment variable is set and all
    four files exist; otherwise the integration is formally skipped. No
    header, entry array or UUID is ever synthesized, so a missing or
    malformed capture cannot turn into a passing check.
    """

    _BASENAMES = (
        "before-main.bin",
        "before-backup.bin",
        "after-main.bin",
        "after-backup.bin",
    )

    def test_real_before_after_preserves_current_attributes(self):
        asset_root = os.environ.get("AVB_TEST_ASSET_ROOT")
        if not asset_root:
            self.skipTest(
                "AVB_TEST_ASSET_ROOT is not set; real GPT captures unavailable"
            )
        paths = {name: Path(asset_root) / name for name in self._BASENAMES}
        missing = [name for name, path in paths.items() if not path.is_file()]
        if missing:
            self.skipTest(
                "AVB_TEST_ASSET_ROOT lacks required captures: "
                + ", ".join(missing)
            )

        before_main = paths["before-main.bin"].read_bytes()
        before_backup = paths["before-backup.bin"].read_bytes()
        after_main = paths["after-main.bin"].read_bytes()
        after_backup = paths["after-backup.bin"].read_bytes()

        def total_bytes(main):
            # Primary header backup-LBA field: LBA 1 + offset 32.
            backup_lba = struct.unpack_from("<Q", main, PAGE + 32)[0]
            return (backup_lba + 1) * PAGE

        before_bytes = total_bytes(before_main)
        after_bytes = total_bytes(after_main)
        self.assertEqual(before_bytes, after_bytes)

        def whole_disk(main, backup):
            disk = SparseDisk(before_bytes)
            disk.write_at(0, main)
            disk.write_at(before_bytes - len(backup), backup)
            return disk

        current_disk = whole_disk(after_main, after_backup)
        original_disk = whole_disk(before_main, before_backup)
        current = au.read_gpt(current_disk, PAGE, before_bytes)
        original = au.read_gpt(original_disk, PAGE, before_bytes)

        self.assertEqual(current.sector_size, 4096)
        self.assertEqual(original.sector_size, 4096)
        self.assertEqual(current.entry_count, 32)
        self.assertEqual(current.entry_size, 128)

        for name in ("userdata", "ARMADA_BOOT", "ARMADA_ROOT"):
            self.assertEqual(
                sum(1 for entry in current.entries if entry.name == name), 1
            )
        by_name = {entry.name: entry for entry in current.entries}
        uuidroles = {
            name: by_name[name].part_uuid
            for name in ("userdata", "ARMADA_BOOT", "ARMADA_ROOT")
        }

        userdata = by_name["userdata"]
        self.assertEqual(
            (userdata.last_lba - userdata.first_lba + 1) * 4096,
            128 * 1024 ** 3,
        )

        original_userdata = [
            entry for entry in original.entries if entry.name == "userdata"
        ]
        self.assertEqual(len(original_userdata), 1)
        original_userdata = original_userdata[0]

        plan = au.plan_restore(
            current,
            original,
            uuidroles["userdata"],
            uuidroles["ARMADA_BOOT"],
            uuidroles["ARMADA_ROOT"],
        )
        self.assertEqual(plan.restored_userdata_bytes, 482913628160)
        self.assertEqual(plan.removed_partition_numbers, (17, 18))

        self.assertEqual(len(plan.write_regions), 4)
        for region in plan.write_regions:
            current_disk.write_at(region.offset, region.data)

        restored = au.read_gpt(current_disk, PAGE, before_bytes)

        removed = set(plan.removed_partition_numbers)
        expected_array = bytearray(current.primary_entries)
        userdata_offset = (userdata.number - 1) * current.entry_size
        struct.pack_into("<Q", expected_array, userdata_offset + 40,
                         original_userdata.last_lba)
        for number in plan.removed_partition_numbers:
            offset = (number - 1) * current.entry_size
            expected_array[offset:offset + current.entry_size] = (
                b"\x00" * current.entry_size
            )

        self.assertEqual(restored.primary_entries, bytes(expected_array))
        self.assertEqual(restored.backup_entries, bytes(expected_array))

        restored_by_number = {entry.number: entry for entry in restored.entries}
        for entry in current.entries:
            if entry.number == userdata.number:
                expected = (
                    entry.raw[:40]
                    + struct.pack("<Q", original_userdata.last_lba)
                    + entry.raw[48:]
                )
                self.assertEqual(restored_by_number[entry.number].raw, expected)
                self.assertEqual(entry.raw[:40], expected[:40])
                self.assertEqual(entry.raw[48:], expected[48:])
                self.assertNotEqual(entry.raw[40:48], expected[40:48])
                self.assertEqual(restored_by_number[entry.number].attrs,
                                 entry.attrs)
                self.assertEqual(restored_by_number[entry.number].name,
                                 entry.name)
            elif entry.number in removed:
                self.assertNotIn(entry.number, restored_by_number)
            else:
                # Every other current entry stays byte-identical, including
                # its attrs and the extension bytes past the name field.
                self.assertEqual(restored_by_number[entry.number].raw,
                                 entry.raw)

        self.assertEqual(restored_by_number[userdata.number].first_lba,
                         userdata.first_lba)
        self.assertEqual(restored_by_number[userdata.number].last_lba,
                         original_userdata.last_lba)

        array_bytes = current.entry_count * current.entry_size
        for header, array in (
                (restored.primary_header, restored.primary_entries),
                (restored.backup_header, restored.backup_entries)):
            self.assertEqual(
                struct.unpack_from("<I", header, 88)[0],
                _crc32(array[:array_bytes]),
            )
            header_size = struct.unpack_from("<I", header, 12)[0]
            zeroed = header[:16] + b"\x00" * 4 + header[20:header_size]
            self.assertEqual(
                struct.unpack_from("<I", header, 16)[0],
                _crc32(zeroed),
            )


if __name__ == "__main__":
    unittest.main()
