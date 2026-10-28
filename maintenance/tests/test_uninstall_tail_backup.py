"""Regression contract for the CURRENT uninstall tail layout (TEST ONLY).

The installer now splits the factory ``userdata`` extent into the shrunk
``userdata``, ``ARMADA_BOOT`` (exactly 1 GiB), ``ARMADA_ROOT`` (shortened by
exactly the fixed 2 GiB the backup occupies) and ``ARMADA_BACKUP`` (exactly
2 GiB) immediately after the root, ending on the factory userdata end.
Uninstall keeps the recovery copy: only ARMADA_BOOT and ARMADA_ROOT are
removed, ARMADA_BACKUP is preserved with its exact extent, PARTUUID, type,
name, attributes and content, and userdata is enlarged to the backup's first
sector.  The legacy two-Linux-partition layout must keep working.

Every GPT pair below starts from the synthetic 512-byte fixture of
``test_portable_gpt`` (same directory import) and is re-finished with that
module's standard ``_finalize_header`` / ``zlib.crc32`` helpers, so
``portable_gpt.read_gpt`` accepts each fixture *before* any planning assertion
runs.  Nothing here reads a device asset, an environment variable or a
subprocess, and nothing mocks the GPT parser.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))
# The maintenance module itself is importable only from its own directory.
if str(_TESTS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR.parent))

import edl_gpt_cli  # noqa: E402
import portable_gpt  # noqa: E402

from test_portable_gpt import (  # noqa: E402
    ENTRY_COUNT,
    ENTRY_SIZE,
    _finalize_header,
    _synthetic_512_request,
)

# Synthetic fixture PARTUUID for the 2 GiB backup; not a value the installer fixes globally.
BACKUP_UUID = "9abf724f-5ce5-4adc-8b71-c16040a2dfe3"
# Distinct UUIDs used only by negative fixtures.
OTHER_BACKUP_UUID = "7c1d3b52-0f4a-4d6e-9b28-5e6c1a0d9f34"
WRONG_BACKUP_UUID = "44444444-5555-4666-8777-888888888888"
EXTRA_TAIL_UUID = "5d0e5f21-3c4b-4a99-8f60-2b7d1c6e4a10"
# A vendor slot that exists in both the factory and the installed table.
VENDOR_TYPE = "cccccccc-dddd-eeee-ffff-000000000000"
VENDOR_UUID = "99999999-8888-4777-8666-555555555555"
VENDOR_FIRST_LBA = 1024
VENDOR_SECTORS = 512

LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
USERDATA_TYPE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

TWO_GIB = 2 * 1024 ** 3
ONE_GIB = 1 * 1024 ** 3


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(
    type_guid: str, part_uuid: str, first_lba: int, last_lba: int, name: str
) -> bytes:
    """One 128-byte GPT entry, written from the UEFI layout."""

    name_bytes = name.encode("utf-16-le")
    if len(name_bytes) > 72:
        raise AssertionError("synthetic partition name is too long")
    return (
        uuid.UUID(type_guid).bytes_le
        + uuid.UUID(part_uuid).bytes_le
        + struct.pack("<QQQ", first_lba, last_lba, 0)
        + name_bytes.ljust(72, b"\x00")
    )


def _patch(array: bytearray, number: int, blob: bytes) -> None:
    offset = (number - 1) * ENTRY_SIZE
    array[offset:offset + ENTRY_SIZE] = blob


def _rebuild_pair(
    primary: bytes, backup: bytes, sector: int, meta: dict, table: bytes
) -> tuple[bytes, bytes]:
    """Rewrite both capture blobs around ``table`` with fresh array and header CRCs."""

    entries_crc = zlib.crc32(table) & 0xFFFFFFFF
    primary_header = _finalize_header(
        primary[meta["primaryHeaderOffset"]:meta["primaryHeaderOffset"] + sector],
        entries_crc,
    )
    backup_header = _finalize_header(backup[-sector:], entries_crc)
    return meta["mbr"] + primary_header + table, table + backup_header


def _read_gpt(request: dict, meta: dict) -> portable_gpt.GptDisk:
    return portable_gpt.read_gpt(
        portable_gpt.GptImageReader(
            meta["currentPrimary"], meta["currentBackup"], meta["diskBytes"]
        ),
        request["sectorSize"],
        meta["diskBytes"],
    )


def _new_layout(
    tmp: Path,
    *,
    backup_bytes: int | None = None,
    backup_sectors: int | None = None,
    backup_type: str = LINUX_TYPE,
    gap_sectors: int = 0,
    extra_tail_sectors: int = 0,
    duplicate_backup: bool = False,
    with_backup_owned: bool = True,
) -> tuple[dict, dict]:
    """Build the 128 GiB pair whose tail is userdata, boot, root and the new backup.

    The factory table gains the same vendor slot the installed table keeps, so a
    successful restore can be checked for "userdata plus the original vendor"
    rather than for userdata alone.
    """

    if gap_sectors and extra_tail_sectors:
        raise AssertionError("gap and extra tail fixtures are exclusive")
    if duplicate_backup and (gap_sectors or extra_tail_sectors):
        raise AssertionError("duplicate label fixture takes no gap or extra tail")

    request, meta = _synthetic_512_request(tmp)
    sector = request["sectorSize"]
    array_bytes = ENTRY_COUNT * ENTRY_SIZE

    if backup_bytes is not None and backup_sectors is not None:
        raise AssertionError("give the backup a size in bytes or in sectors, not both")
    if backup_bytes is not None:
        if backup_bytes % sector:
            raise AssertionError("backup size must be a whole number of sectors")
        backup_sectors = backup_bytes // sector
    if backup_sectors is None:
        backup_sectors = TWO_GIB // sector
    if backup_sectors <= 0:
        raise AssertionError("backup must have a positive sector count")

    # ``userdataEndLbaExclusive - 1`` is the last usable LBA, which is also the
    # end of the factory userdata partition in this fixture.
    factory_end = meta["userdataEndLbaExclusive"] - 1

    primary = meta["currentPrimary"]
    backup = meta["currentBackup"]
    original_primary = meta["inputs"]["originalPrimary"].read_bytes()
    original_backup = meta["inputs"]["originalBackup"].read_bytes()

    current_array = bytearray(
        primary[meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes]
    )
    original_array = bytearray(
        original_primary[
            meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes
        ]
    )

    vendor = _entry(
        VENDOR_TYPE,
        VENDOR_UUID,
        VENDOR_FIRST_LBA,
        VENDOR_FIRST_LBA + VENDOR_SECTORS - 1,
        "proinfo",
    )
    _patch(current_array, 15, vendor)
    _patch(original_array, 15, vendor)

    if duplicate_backup:
        root_last = factory_end - backup_sectors
        first = backup_sectors // 2
        tails = [
            (BACKUP_UUID, root_last + 1, root_last + first, "ARMADA_BACKUP"),
            (
                OTHER_BACKUP_UUID,
                root_last + first + 1,
                factory_end,
                "ARMADA_BACKUP",
            ),
        ]
    elif extra_tail_sectors:
        root_last = factory_end - backup_sectors - extra_tail_sectors
        backup_last = root_last + backup_sectors
        tails = [
            (BACKUP_UUID, root_last + 1, backup_last, "ARMADA_BACKUP"),
            (EXTRA_TAIL_UUID, backup_last + 1, factory_end, "vendor_extra"),
        ]
    else:
        root_last = factory_end - backup_sectors - gap_sectors
        tails = [
            (BACKUP_UUID, root_last + 1 + gap_sectors, factory_end, "ARMADA_BACKUP"),
        ]

    # Slot 18 is ARMADA_ROOT; the tails start at slot 19.
    struct.pack_into("<Q", current_array, (18 - 1) * ENTRY_SIZE + 40, root_last)
    for index, (part_uuid, first_lba, last_lba, name) in enumerate(tails):
        entry_type = backup_type if name == "ARMADA_BACKUP" else LINUX_TYPE
        _patch(
            current_array,
            19 + index,
            _entry(entry_type, part_uuid, first_lba, last_lba, name),
        )

    new_original_primary, new_original_backup = _rebuild_pair(
        original_primary, original_backup, sector, meta, bytes(original_array)
    )
    new_current_primary, new_current_backup = _rebuild_pair(
        primary, backup, sector, meta, bytes(current_array)
    )

    blobs = {
        "originalPrimary": new_original_primary,
        "originalBackup": new_original_backup,
        "currentPrimary": new_current_primary,
        "currentBackup": new_current_backup,
    }
    for field, data in blobs.items():
        path = meta["inputs"][field]
        path.write_bytes(data)
        request[field] = {"path": str(path), "sha256": _sha256_bytes(data)}

    meta["originalPrimary"] = new_original_primary
    meta["originalBackup"] = new_original_backup
    meta["currentPrimary"] = new_current_primary
    meta["currentBackup"] = new_current_backup

    if with_backup_owned:
        request["owned"]["boardBackupPartUuid"] = BACKUP_UUID

    return request, meta


class UninstallTailBackupRegressionTests(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------ accepted layouts

    def test_new_layout_plan_preserves_backup_and_restores_boot_root_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp)
            sector = request["sectorSize"]

            disk = _read_gpt(request, meta)
            self.assertEqual(
                [entry.name for entry in disk.entries],
                [
                    "proinfo",
                    "userdata",
                    "ARMADA_BOOT",
                    "ARMADA_ROOT",
                    "ARMADA_BACKUP",
                ],
            )
            self.assertEqual(
                [entry.number for entry in disk.entries], [15, 16, 17, 18, 19]
            )

            plan = edl_gpt_cli.prepare_plan(request)

            # Exactly the two owned boot/root slots go; the backup is retained.
            self.assertEqual(sorted(plan["removedPartitionNumbers"]), [17, 18])
            self.assertEqual(plan["userdataStartLba"], meta["userdataStartLba"])
            self.assertEqual(
                plan["userdataEndLbaExclusive"],
                meta["userdataEndLbaExclusive"] - TWO_GIB // sector,
            )
            self.assertEqual(
                plan["restoredBytes"],
                (
                    meta["userdataEndLbaExclusive"]
                    - TWO_GIB // sector
                    - meta["userdataStartLba"]
                )
                * sector,
            )

            regions = list(plan["regions"])
            self.assertEqual(
                [region["role"] for region in regions],
                [
                    "backup-array",
                    "backup-header",
                    "primary-array",
                    "primary-header",
                ],
            )
            for region in regions:
                self.assertEqual(region["byteOffset"] % sector, 0)
                self.assertEqual(region["bytes"] % sector, 0)

            post_primary = Path(plan["postPrimary"]["path"]).read_bytes()
            post_backup = Path(plan["postBackup"]["path"]).read_bytes()
            rebuilt = portable_gpt.read_gpt(
                portable_gpt.GptImageReader(
                    post_primary, post_backup, meta["diskBytes"]
                ),
                sector,
                meta["diskBytes"],
            )

            # Exactly the three retained partitions remain: proinfo, the enlarged userdata and
            # the untouched backup.
            self.assertEqual(
                sorted(entry.name for entry in rebuilt.entries),
                ["ARMADA_BACKUP", "proinfo", "userdata"],
            )
            self.assertEqual(
                sorted(entry.number for entry in rebuilt.entries), [15, 16, 19]
            )

            pre_backup = [
                entry
                for entry in disk.entries
                if entry.name == "ARMADA_BACKUP"
            ]
            self.assertEqual(len(pre_backup), 1)
            pre_entry = pre_backup[0]

            post_names = [entry.name for entry in rebuilt.entries]
            self.assertEqual(post_names.count("ARMADA_BACKUP"), 1)
            post_entry = [
                entry
                for entry in rebuilt.entries
                if entry.name == "ARMADA_BACKUP"
            ][0]
            self.assertEqual(post_entry.number, 19)
            self.assertEqual(post_entry.type_guid, pre_entry.type_guid)
            self.assertEqual(post_entry.part_uuid, pre_entry.part_uuid)
            self.assertEqual(post_entry.first_lba, pre_entry.first_lba)
            self.assertEqual(post_entry.last_lba, pre_entry.last_lba)
            self.assertEqual(post_entry.raw, pre_entry.raw)

            userdata = [
                entry for entry in rebuilt.entries if entry.name == "userdata"
            ]
            self.assertEqual(len(userdata), 1)
            self.assertEqual(
                userdata[0].last_lba, pre_entry.first_lba - 1
            )

    def test_legacy_two_tail_request_still_plans_only_boot_and_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _synthetic_512_request(tmp)

            # The legacy contract stays exactly the three documented UUIDs.
            self.assertEqual(
                set(request["owned"]),
                {
                    "userdataPartUuid",
                    "linuxBootPartUuid",
                    "linuxRootPartUuid",
                },
            )

            plan = edl_gpt_cli.prepare_plan(request)

            self.assertEqual(sorted(plan["removedPartitionNumbers"]), [17, 18])
            self.assertEqual(
                plan["userdataEndLbaExclusive"],
                meta["userdataEndLbaExclusive"],
            )
            self.assertEqual(
                plan["restoredBytes"],
                (meta["userdataEndLbaExclusive"] - meta["userdataStartLba"])
                * request["sectorSize"],
            )

    # ------------------------------------------------------------ rejected layouts

    def test_missing_backup_uuid_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, with_backup_owned=False)

            names = [entry.name for entry in _read_gpt(request, meta).entries]
            self.assertIn("ARMADA_BACKUP", names)
            self.assertNotIn("boardBackupPartUuid", request["owned"])

            self._assert_rejected(tmp, request)

    def test_wrong_backup_uuid_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, with_backup_owned=False)
            request["owned"]["boardBackupPartUuid"] = WRONG_BACKUP_UUID

            self.assertIn(
                "ARMADA_BACKUP",
                [entry.name for entry in _read_gpt(request, meta).entries],
            )

            self._assert_rejected(tmp, request)

    def test_backup_of_the_wrong_size_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, backup_bytes=ONE_GIB)
            sector = request["sectorSize"]

            # The 1 GiB backup still ends on the factory end and still touches the root, so the fixture is
            # a coherent GPT; only the fixed 2 GiB size is wrong.
            backup = [
                entry
                for entry in _read_gpt(request, meta).entries
                if entry.name == "ARMADA_BACKUP"
            ]
            self.assertEqual(len(backup), 1)
            self.assertEqual(
                (backup[0].last_lba - backup[0].first_lba + 1) * sector, ONE_GIB
            )
            self.assertEqual(
                backup[0].last_lba, meta["userdataEndLbaExclusive"] - 1
            )

            self._assert_rejected(tmp, request)

    def test_backup_with_the_wrong_type_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, backup_type=USERDATA_TYPE)

            disk = _read_gpt(request, meta)
            backup = [e for e in disk.entries if e.name == "ARMADA_BACKUP"]
            self.assertEqual(len(backup), 1)
            self.assertEqual(backup[0].type_guid, USERDATA_TYPE.upper())

            self._assert_rejected(tmp, request)

    def test_one_sector_gap_before_the_backup_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, gap_sectors=1)
            sector = request["sectorSize"]

            disk = _read_gpt(request, meta)
            root = [e for e in disk.entries if e.name == "ARMADA_ROOT"][0]
            backup = [e for e in disk.entries if e.name == "ARMADA_BACKUP"][0]
            self.assertEqual(backup.first_lba, root.last_lba + 2)
            self.assertEqual(backup.last_lba, meta["userdataEndLbaExclusive"] - 1)
            self.assertEqual(
                backup.last_lba - backup.first_lba + 1, TWO_GIB // sector
            )

            self._assert_rejected(tmp, request)

    def test_unknown_fourth_tail_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp, extra_tail_sectors=1024)

            names = [entry.name for entry in _read_gpt(request, meta).entries]
            self.assertIn("ARMADA_BACKUP", names)
            self.assertIn("vendor_extra", names)
            self.assertEqual(len(names), 6)

            self._assert_rejected(tmp, request)

    def test_truncated_factory_tail_in_original_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _synthetic_512_request(tmp)
            sector = request["sectorSize"]
            array_bytes = ENTRY_COUNT * ENTRY_SIZE

            original_array = bytearray(
                meta["inputs"]["originalPrimary"].read_bytes()[
                    meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes
                ]
            )
            current_array = bytearray(
                meta["currentPrimary"][
                    meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes
                ]
            )

            # Truncate the factory userdata tail; shorten the current root by the same
            # amount so the legacy "root ends at the original userdata end" guard would
            # still accept this coherent-but-truncated factory source.  The header's
            # last usable LBA stays at the factory end.
            shrink = 2048
            original_userdata_last = struct.unpack_from(
                "<Q", original_array, (16 - 1) * ENTRY_SIZE + 40
            )[0]
            current_root_last = struct.unpack_from(
                "<Q", current_array, (18 - 1) * ENTRY_SIZE + 40
            )[0]
            struct.pack_into(
                "<Q",
                original_array,
                (16 - 1) * ENTRY_SIZE + 40,
                original_userdata_last - shrink,
            )
            struct.pack_into(
                "<Q",
                current_array,
                (18 - 1) * ENTRY_SIZE + 40,
                current_root_last - shrink,
            )

            new_original_primary, new_original_backup = _rebuild_pair(
                meta["inputs"]["originalPrimary"].read_bytes(),
                meta["inputs"]["originalBackup"].read_bytes(),
                sector,
                meta,
                bytes(original_array),
            )
            new_current_primary, new_current_backup = _rebuild_pair(
                meta["currentPrimary"],
                meta["currentBackup"],
                sector,
                meta,
                bytes(current_array),
            )

            blobs = {
                "originalPrimary": new_original_primary,
                "originalBackup": new_original_backup,
                "currentPrimary": new_current_primary,
                "currentBackup": new_current_backup,
            }
            for field, data in blobs.items():
                path = meta["inputs"][field]
                path.write_bytes(data)
                request[field] = {"path": str(path), "sha256": _sha256_bytes(data)}
                meta[field] = data

            # Both pairs must parse as real GPTs before the planner runs.
            original_disk = portable_gpt.read_gpt(
                portable_gpt.GptImageReader(
                    meta["originalPrimary"], meta["originalBackup"], meta["diskBytes"]
                ),
                sector,
                meta["diskBytes"],
            )
            disk = _read_gpt(request, meta)
            original_userdata = [
                entry for entry in original_disk.entries if entry.name == "userdata"
            ]
            self.assertEqual(len(original_userdata), 1)
            root = [entry for entry in disk.entries if entry.number == 18]
            self.assertEqual(len(root), 1)
            self.assertLess(
                original_userdata[0].last_lba, original_disk.last_usable_lba
            )
            self.assertEqual(root[0].last_lba, original_userdata[0].last_lba)

            self._assert_rejected(tmp, request)

    def test_lowercase_armada_prefix_in_original_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            request, meta = _new_layout(tmp)
            sector = request["sectorSize"]
            array_bytes = ENTRY_COUNT * ENTRY_SIZE

            original_array = bytearray(
                meta["originalPrimary"][
                    meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes
                ]
            )
            current_array = bytearray(
                meta["currentPrimary"][
                    meta["primaryArrayOffset"]:meta["primaryArrayOffset"] + array_bytes
                ]
            )

            # Rename only the vendor slot (entry 15) in BOTH tables to a lowercase
            # ARMADA_ prefix, keeping every GUID, range, type and attribute; the old
            # case-sensitive guard missed this factory source.
            name_offset = (15 - 1) * ENTRY_SIZE + 56
            lowercase = "armada_saved".encode("utf-16-le").ljust(72, b"\x00")
            original_array[name_offset:name_offset + 72] = lowercase
            current_array[name_offset:name_offset + 72] = lowercase

            new_original_primary, new_original_backup = _rebuild_pair(
                meta["originalPrimary"],
                meta["originalBackup"],
                sector,
                meta,
                bytes(original_array),
            )
            new_current_primary, new_current_backup = _rebuild_pair(
                meta["currentPrimary"],
                meta["currentBackup"],
                sector,
                meta,
                bytes(current_array),
            )

            blobs = {
                "originalPrimary": new_original_primary,
                "originalBackup": new_original_backup,
                "currentPrimary": new_current_primary,
                "currentBackup": new_current_backup,
            }
            for field, data in blobs.items():
                path = meta["inputs"][field]
                path.write_bytes(data)
                request[field] = {"path": str(path), "sha256": _sha256_bytes(data)}
                meta[field] = data

            # Both pairs must parse as real GPTs before the planner runs.
            original_disk = portable_gpt.read_gpt(
                portable_gpt.GptImageReader(
                    meta["originalPrimary"], meta["originalBackup"], meta["diskBytes"]
                ),
                sector,
                meta["diskBytes"],
            )
            disk = _read_gpt(request, meta)
            # Both vendor labels really carry the lowercase prefix and the rest of
            # the installed layout is untouched, so only the label guard can fire.
            self.assertEqual(original_disk.entries[0].name, "armada_saved")
            self.assertEqual(disk.entries[0].name, "armada_saved")
            self.assertTrue(original_disk.entries[0].name.startswith("armada_"))
            self.assertEqual(
                [entry.name for entry in disk.entries],
                [
                    "armada_saved",
                    "userdata",
                    "ARMADA_BOOT",
                    "ARMADA_ROOT",
                    "ARMADA_BACKUP",
                ],
            )
            self.assertEqual(
                [entry.number for entry in original_disk.entries],
                [15, 16],
            )
            self.assertEqual(
                [entry.number for entry in disk.entries],
                [15, 16, 17, 18, 19],
            )

            self._assert_rejected(tmp, request)

    # ------------------------------------------------------------------ helpers

    def _assert_rejected(self, tmp: Path, request: dict) -> None:
        """Requires a bridge rejection and proves nothing was written."""

        output = Path(request["outputDirectory"])
        self.assertFalse(output.exists())

        with self.assertRaises(portable_gpt.GptError):
            edl_gpt_cli.prepare_plan(request)

        self.assertFalse(output.exists())
        self.assertEqual([child.name for child in tmp.iterdir()], ["inputs"])


if __name__ == "__main__":
    unittest.main()
