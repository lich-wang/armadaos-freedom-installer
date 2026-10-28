"""Offline GPT / BCB helpers for the ArmadaOS uninstall flow.

Pure stdlib helpers over caller-supplied data:

* :func:`read_gpt` validates the primary and backup GPT with bounded
  ``seek``/``read`` calls and returns the raw regions plus parsed entries.
* :func:`plan_restore` validates a parsed current/original GPT pair and
  returns the byte-exact GPT regions that restore the original userdata
  extent while removing the ArmadaOS boot and root partitions.
* :func:`make_factory_reset_bcb` queues a one-shot factory-reset request in
  an existing 2048-byte BCB buffer.

The pure helpers are side-effect free and operate only on caller-supplied
data. The guarded :class:`LinuxBlockBackend` at the end of the module is the
only code that reads sysfs and opens block devices, and it does so only after
the RAM-root, device-tree and geometry checks have passed.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import hmac
import importlib
import json
import os
import secrets
import stat
import struct
import sys
import threading
import time
import urllib.parse
import uuid
import zlib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Tuple


class GptError(ValueError):
    """Raised when a GPT image, restore plan input, or BCB buffer is invalid."""


@dataclass(frozen=True)
class GptEntry:
    """One active GPT partition entry.

    ``first_lba`` and ``last_lba`` are inclusive. ``number`` is the 1-based
    slot in the raw entry array; inactive slots are not represented.
    ``raw`` is the full raw entry bytes (including any bytes past the name
    field) so callers can rewrite the entry without re-encoding it.
    """

    number: int
    type_guid: str
    part_uuid: str
    first_lba: int
    last_lba: int
    attrs: int
    name: str
    raw: bytes


@dataclass(frozen=True)
class GptDisk:
    """A parsed GPT disk.

    The four raw blobs are exactly what lives on disk:

    * ``primary_header`` / ``backup_header`` are entire logical sectors
      (LBA 1 and the last physical LBA).
    * ``primary_entries`` / ``backup_entries`` are the entry arrays rounded up
      to logical sectors, padding included.

    ``fingerprint`` is a stable digest of the parsed GPT state.
    """

    sector_size: int
    disk_size_bytes: int
    disk_guid: str
    first_usable_lba: int
    last_usable_lba: int
    entry_count: int
    entry_size: int
    primary_entries_lba: int
    backup_entries_lba: int
    primary_header: bytes
    backup_header: bytes
    primary_entries: bytes
    backup_entries: bytes
    entries: Tuple[GptEntry, ...]
    fingerprint: str


@dataclass(frozen=True)
class WriteRegion:
    """A single absolute byte range to write back to the disk."""

    offset: int
    data: bytes


@dataclass(frozen=True)
class GptRestorePlan:
    """Byte-exact restore plan for a factory reset.

    ``userdata_end_lba_exclusive`` is the first LBA after the restored
    userdata partition. ``removed_partition_numbers`` lists the 1-based raw
    slots that are zeroed (boot then root).
    """

    write_regions: Tuple[WriteRegion, ...]
    userdata_start_lba: int
    userdata_end_lba_exclusive: int
    restored_userdata_bytes: int
    removed_partition_numbers: Tuple[int, ...]


_SECTOR_SIZES = (512, 4096)
_HEADER_STRUCT = struct.Struct("<8sIIIIQQQQ16sQIII")
_HEADER_MIN_SIZE = 92
_ENTRY_STRUCT = struct.Struct("<16s16sQQQ72s")
_ENTRY_MIN_SIZE = 128
_ENTRY_ALIGN = 128
_NAME_BYTES = 72
_ZERO_GUID = b"\x00" * 16
_MAX_ARRAY_BYTES = 16 * 1024 * 1024
_LINUX_FS_TYPE_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"

_BCB_SIZE = 2048
_BCB_COMMAND = b"boot-recovery"
_BCB_RECOVERY = b"recovery\n--wipe_data\n--reason=armada-uninstall\n"


def _require_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GptError(f"{label} must be an integer")
    return value


def _read_exact(source: BinaryIO, offset: int, length: int,
                disk_size_bytes: int, label: str) -> bytes:
    """Seek to ``offset`` and read exactly ``length`` bytes, or fail."""

    if length <= 0:
        raise GptError(f"{label}: read length must be positive")
    if offset < 0 or offset + length > disk_size_bytes:
        raise GptError(f"{label}: read outside the disk")
    try:
        source.seek(offset)
        data = source.read(length)
    except (OSError, ValueError) as exc:
        raise GptError(f"{label}: seek/read failed") from exc
    if not isinstance(data, (bytes, bytearray)) or len(data) != length:
        raise GptError(f"{label}: short read")
    return bytes(data)


def _parse_header(sector: bytes, sector_size: int, backup_header_lba: int,
                  expected_current_lba: int, label: str) -> dict:
    """Validate one GPT header sector and return its parsed fields."""

    if len(sector) != sector_size:
        raise GptError(f"{label}: header is not one full sector")

    (signature, revision, header_size, header_crc, reserved, current_lba,
     backup_lba, first_usable, last_usable, disk_guid_bytes, entries_lba,
     entry_count, entry_size, entries_crc) = _HEADER_STRUCT.unpack_from(
        sector, 0
    )

    if signature != b"EFI PART":
        raise GptError(f"{label}: bad signature")
    if revision != 0x00010000:
        raise GptError(f"{label}: unsupported revision")
    if not _HEADER_MIN_SIZE <= header_size <= sector_size:
        raise GptError(f"{label}: bad header size")
    if reserved != 0:
        raise GptError(f"{label}: reserved field is not zero")

    zeroed = sector[:16] + b"\x00\x00\x00\x00" + sector[20:header_size]
    if zlib.crc32(zeroed) & 0xFFFFFFFF != header_crc:
        raise GptError(f"{label}: header CRC mismatch")

    if current_lba != expected_current_lba:
        raise GptError(f"{label}: current LBA pointer mismatch")
    if backup_lba != (1 if expected_current_lba == backup_header_lba
                      else backup_header_lba):
        raise GptError(f"{label}: backup LBA pointer mismatch")
    if disk_guid_bytes == _ZERO_GUID:
        raise GptError(f"{label}: zero disk GUID")

    if first_usable <= 1:
        raise GptError(f"{label}: first usable LBA too small")
    if first_usable > last_usable:
        raise GptError(f"{label}: usable range is inverted")
    if last_usable >= backup_header_lba:
        raise GptError(f"{label}: last usable LBA overlaps the backup header")

    return {
        "disk_guid_bytes": disk_guid_bytes,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "entries_lba": entries_lba,
        "entry_count": entry_count,
        "entry_size": entry_size,
        "entries_crc": entries_crc,
    }


def _check_entry_geometry(entry_count: int, entry_size: int) -> int:
    """Validate count/size and return the unpadded array byte length."""

    if entry_count <= 0:
        raise GptError("entry count must be positive")
    if entry_size < _ENTRY_MIN_SIZE or entry_size % _ENTRY_ALIGN:
        raise GptError("entry size must be a multiple of 128 and >= 128")
    array_bytes = entry_count * entry_size
    if array_bytes > _MAX_ARRAY_BYTES:
        raise GptError("entry array exceeds the 16 MiB parser bound")
    return array_bytes


def _decode_name(name_bytes: bytes) -> str:
    """Decode a 72-byte UTF-16LE name, stopping at the first NUL unit."""

    for index in range(0, _NAME_BYTES, 2):
        if name_bytes[index] == 0 and name_bytes[index + 1] == 0:
            name_bytes = name_bytes[:index]
            break
    try:
        return name_bytes.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise GptError("partition name is not valid UTF-16LE") from exc


def _parse_entries(array: bytes, entry_count: int, entry_size: int,
                   first_usable: int, last_usable: int) -> Tuple[GptEntry, ...]:
    """Parse the active slots of one entry array."""

    entries = []
    seen_uuids = set()
    for index in range(entry_count):
        start = index * entry_size
        raw = array[start:start + entry_size]
        if len(raw) != entry_size:
            raise GptError("entry array is truncated")

        (type_bytes, uuid_bytes, first_lba, last_lba, attrs,
         name_bytes) = _ENTRY_STRUCT.unpack_from(raw, 0)
        if type_bytes == _ZERO_GUID:
            continue
        if uuid_bytes == _ZERO_GUID:
            raise GptError("active entry has a zero partition UUID")

        type_guid = str(uuid.UUID(bytes_le=type_bytes)).upper()
        part_uuid = str(uuid.UUID(bytes_le=uuid_bytes)).upper()
        if part_uuid in seen_uuids:
            raise GptError("duplicate partition UUID")
        seen_uuids.add(part_uuid)

        if first_lba < first_usable or last_lba > last_usable:
            raise GptError("partition extent is outside the usable range")
        if first_lba > last_lba:
            raise GptError("partition extent is inverted")

        entries.append(GptEntry(
            number=index + 1,
            type_guid=type_guid,
            part_uuid=part_uuid,
            first_lba=first_lba,
            last_lba=last_lba,
            attrs=attrs,
            name=_decode_name(name_bytes),
            raw=raw,
        ))

    ordered = sorted(entries, key=lambda entry: entry.first_lba)
    for left, right in zip(ordered, ordered[1:]):
        if right.first_lba <= left.last_lba:
            raise GptError("active partitions overlap")

    return tuple(entries)


def _fingerprint(sector_size: int, disk_size_bytes: int,
                 regions: Tuple[Tuple[int, bytes], ...]) -> str:
    """SHA256 over geometry and each raw region with offset+length prefixes."""

    digest = hashlib.sha256()
    digest.update(struct.pack("<QQ", sector_size, disk_size_bytes))
    for offset, data in regions:
        digest.update(struct.pack("<QQ", offset, len(data)))
        digest.update(data)
    return digest.hexdigest()


def read_gpt(source: BinaryIO, sector_size: int, disk_size_bytes: int) -> GptDisk:
    """Read and validate the GPT of ``source`` without scanning the disk.

    Reads LBA 1, the last physical LBA and both entry arrays with explicit
    bounded reads. Both headers and arrays must pass their own CRC checks and
    agree byte-for-byte; every active entry is validated. Any inconsistency
    raises :class:`GptError`.
    """

    sector_size = _require_int(sector_size, "sector_size")
    disk_size_bytes = _require_int(disk_size_bytes, "disk_size_bytes")
    if sector_size not in _SECTOR_SIZES:
        raise GptError("sector_size must be 512 or 4096")
    if disk_size_bytes <= 0 or disk_size_bytes % sector_size:
        raise GptError("disk_size_bytes must be positive and sector aligned")

    total_lbas = disk_size_bytes // sector_size
    if total_lbas < 3:
        raise GptError("disk is too small to hold a GPT")
    backup_header_lba = total_lbas - 1

    primary_header = _read_exact(
        source, sector_size, sector_size, disk_size_bytes, "primary header"
    )
    backup_header = _read_exact(
        source, backup_header_lba * sector_size, sector_size, disk_size_bytes,
        "backup header",
    )

    primary = _parse_header(
        primary_header, sector_size, backup_header_lba, 1, "primary header"
    )
    backup = _parse_header(
        backup_header, sector_size, backup_header_lba, backup_header_lba,
        "backup header",
    )

    if primary["disk_guid_bytes"] != backup["disk_guid_bytes"]:
        raise GptError("primary and backup disk GUIDs differ")
    if primary["first_usable"] != backup["first_usable"]:
        raise GptError("primary and backup first usable LBAs differ")
    if primary["last_usable"] != backup["last_usable"]:
        raise GptError("primary and backup last usable LBAs differ")
    if primary["entry_count"] != backup["entry_count"]:
        raise GptError("primary and backup entry counts differ")
    if primary["entry_size"] != backup["entry_size"]:
        raise GptError("primary and backup entry sizes differ")

    entry_count = primary["entry_count"]
    entry_size = primary["entry_size"]
    array_bytes = _check_entry_geometry(entry_count, entry_size)
    array_sectors = (array_bytes + sector_size - 1) // sector_size
    array_read_bytes = array_sectors * sector_size

    primary_entries_lba = primary["entries_lba"]
    if primary_entries_lba < 2:
        raise GptError("primary entry array overlaps the protective MBR")
    if primary_entries_lba + array_sectors > primary["first_usable"]:
        raise GptError("primary entry array overlaps the usable range")

    backup_entries_lba = backup["entries_lba"]
    if backup_entries_lba <= backup["last_usable"]:
        raise GptError("backup entry array overlaps the usable range")
    if backup_entries_lba + array_sectors > backup_header_lba:
        raise GptError("backup entry array overlaps the backup header")
    if backup_entries_lba < 2:
        raise GptError("backup entry array is out of range")

    primary_entries = _read_exact(
        source, primary_entries_lba * sector_size, array_read_bytes,
        disk_size_bytes, "primary entry array",
    )
    backup_entries = _read_exact(
        source, backup_entries_lba * sector_size, array_read_bytes,
        disk_size_bytes, "backup entry array",
    )

    primary_array_crc = zlib.crc32(primary_entries[:array_bytes]) & 0xFFFFFFFF
    if primary_array_crc != primary["entries_crc"]:
        raise GptError("primary entry array CRC mismatch")
    backup_array_crc = zlib.crc32(backup_entries[:array_bytes]) & 0xFFFFFFFF
    if backup_array_crc != backup["entries_crc"]:
        raise GptError("backup entry array CRC mismatch")

    if primary_entries != backup_entries:
        raise GptError("primary and backup entry arrays differ")

    entries = _parse_entries(
        primary_entries, entry_count, entry_size,
        primary["first_usable"], primary["last_usable"],
    )

    disk_guid = str(uuid.UUID(bytes_le=primary["disk_guid_bytes"])).upper()
    fingerprint = _fingerprint(
        sector_size,
        disk_size_bytes,
        (
            (sector_size, primary_header),
            (primary_entries_lba * sector_size, primary_entries),
            (backup_entries_lba * sector_size, backup_entries),
            (backup_header_lba * sector_size, backup_header),
        ),
    )

    return GptDisk(
        sector_size=sector_size,
        disk_size_bytes=disk_size_bytes,
        disk_guid=disk_guid,
        first_usable_lba=primary["first_usable"],
        last_usable_lba=primary["last_usable"],
        entry_count=entry_count,
        entry_size=entry_size,
        primary_entries_lba=primary_entries_lba,
        backup_entries_lba=backup_entries_lba,
        primary_header=primary_header,
        backup_header=backup_header,
        primary_entries=primary_entries,
        backup_entries=backup_entries,
        entries=entries,
        fingerprint=fingerprint,
    )


def _uuid_text(value: object, label: str) -> str:
    """Normalize a supplied UUID string, rejecting invalid and zero values."""

    if not isinstance(value, str):
        raise GptError(f"{label} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise GptError(f"{label} is not a valid UUID") from exc
    if parsed.int == 0:
        raise GptError(f"{label} must not be the zero UUID")
    return str(parsed).upper()


def _one_entry(entries: Tuple[GptEntry, ...], part_uuid: str,
               label: str) -> GptEntry:
    """Return the single entry whose partition UUID matches ``part_uuid``."""

    matches = [entry for entry in entries
               if entry.part_uuid.upper() == part_uuid]
    if len(matches) != 1:
        raise GptError(f"{label} partition UUID must appear exactly once")
    return matches[0]


def _rewrite_header(header: bytes, sector_size: int,
                    entries_crc: int) -> bytes:
    """Return a full header sector with a new array CRC and header CRC."""

    if len(header) != sector_size:
        raise GptError("current header is not one full sector")
    data = bytearray(header)
    header_size = struct.unpack_from("<I", data, 12)[0]
    if not _HEADER_MIN_SIZE <= header_size <= sector_size:
        raise GptError("current header size is invalid")

    struct.pack_into("<I", data, 88, entries_crc)
    struct.pack_into("<I", data, 16, 0)
    header_crc = zlib.crc32(bytes(data[:header_size])) & 0xFFFFFFFF
    struct.pack_into("<I", data, 16, header_crc)
    return bytes(data)


def plan_restore(
    current: GptDisk,
    original: GptDisk,
    userdata_uuid: str,
    boot_uuid: str,
    root_uuid: str,
) -> GptRestorePlan:
    """Plan the GPT portion of a factory reset.

    Both inputs must be parsed GPTs of the same physical disk. The current
    GPT must contain exactly one userdata, ``ARMADA_BOOT`` and
    ``ARMADA_ROOT`` partition with the supplied UUIDs, and every other
    current entry must match the original GPT by slot, UUID, type, name and
    extent (userdata may only be shorter). The original GPT must contain a
    longer userdata partition and no ArmadaOS boot/root partition.

    The returned plan rewrites both entry arrays from the current primary
    array with only the userdata end LBA restored and the boot/root slots
    zeroed, then rebuilds both header sectors. No device or filesystem
    access, formatting, or disk scan is performed.
    """

    if not isinstance(current, GptDisk) or not isinstance(original, GptDisk):
        raise GptError("plan_restore requires parsed GptDisk inputs")

    userdata_uuid = _uuid_text(userdata_uuid, "userdata_uuid")
    boot_uuid = _uuid_text(boot_uuid, "boot_uuid")
    root_uuid = _uuid_text(root_uuid, "root_uuid")
    if len({userdata_uuid, boot_uuid, root_uuid}) != 3:
        raise GptError("userdata, boot and root UUIDs must be distinct")

    if current.disk_size_bytes != original.disk_size_bytes:
        raise GptError("current and original physical disk sizes differ")
    if current.sector_size != original.sector_size:
        raise GptError("current and original logical sector sizes differ")
    if current.sector_size not in _SECTOR_SIZES:
        raise GptError("current sector size is not supported")
    if current.disk_guid.upper() != original.disk_guid.upper():
        raise GptError("current and original disk GUIDs differ")
    if current.first_usable_lba != original.first_usable_lba:
        raise GptError("current and original first usable LBAs differ")
    if current.last_usable_lba != original.last_usable_lba:
        raise GptError("current and original last usable LBAs differ")
    if current.entry_count != original.entry_count:
        raise GptError("current and original entry counts differ")
    if current.entry_size != original.entry_size:
        raise GptError("current and original entry sizes differ")

    sector = current.sector_size
    current_label_counts = {}
    for entry in current.entries:
        current_label_counts[entry.name] = (
            current_label_counts.get(entry.name, 0) + 1
        )
    for label in ("userdata", "ARMADA_BOOT", "ARMADA_ROOT"):
        if current_label_counts.get(label, 0) != 1:
            raise GptError(
                f"current GPT must have exactly one {label} partition"
            )
    if sum(1 for entry in original.entries
           if entry.name == "userdata") != 1:
        raise GptError("original GPT must have exactly one userdata partition")

    userdata = _one_entry(current.entries, userdata_uuid, "current userdata")
    boot = _one_entry(current.entries, boot_uuid, "current boot")
    root = _one_entry(current.entries, root_uuid, "current root")
    if userdata.name != "userdata":
        raise GptError("current userdata partition has the wrong name")
    if boot.name != "ARMADA_BOOT":
        raise GptError("current boot partition has the wrong name")
    if root.name != "ARMADA_ROOT":
        raise GptError("current root partition has the wrong name")
    for entry, label in ((boot, "boot"), (root, "root")):
        if entry.type_guid.upper() != _LINUX_FS_TYPE_GUID:
            raise GptError(
                f"current {label} partition is not a Linux filesystem"
            )
    for entry in (userdata, boot, root):
        if not 1 <= entry.number <= current.entry_count:
            raise GptError("current owned partition number is out of range")
    if boot.number == root.number:
        raise GptError("current boot and root slots must differ")

    original_userdata = _one_entry(
        original.entries, userdata_uuid, "original userdata"
    )
    if original_userdata.name != "userdata":
        raise GptError("original userdata partition has the wrong name")
    if original_userdata.number != userdata.number:
        raise GptError("current and original userdata slots differ")
    if original_userdata.type_guid.upper() != userdata.type_guid.upper():
        raise GptError("current and original userdata types differ")
    if original_userdata.first_lba != userdata.first_lba:
        raise GptError("current and original userdata starts differ")
    if original_userdata.last_lba <= userdata.last_lba:
        raise GptError("original userdata is not longer than current userdata")

    for entry in original.entries:
        if entry.part_uuid.upper() in (boot_uuid, root_uuid):
            raise GptError("original GPT still has an ArmadaOS partition UUID")
        if entry.name in ("ARMADA_BOOT", "ARMADA_ROOT"):
            raise GptError("original GPT still has an ArmadaOS partition label")

    original_by_number = {entry.number: entry for entry in original.entries}
    matched = set()
    for entry in current.entries:
        if entry.number in (boot.number, root.number):
            continue
        other = original_by_number.get(entry.number)
        if other is None:
            raise GptError("current partition has no original counterpart")
        if other.part_uuid.upper() != entry.part_uuid.upper():
            raise GptError("current and original partition UUIDs differ")
        if other.type_guid.upper() != entry.type_guid.upper():
            raise GptError("current and original partition types differ")
        if other.name != entry.name:
            raise GptError("current and original partition names differ")
        if other.first_lba != entry.first_lba:
            raise GptError("current and original partition starts differ")
        if entry.number == userdata.number:
            if entry.last_lba > other.last_lba:
                raise GptError("current userdata extends past the original")
        elif entry.last_lba != other.last_lba:
            raise GptError("current and original partition ends differ")
        matched.add(entry.number)
    if len(matched) != len(original.entries):
        raise GptError("original GPT has partitions missing from current GPT")

    for entry in current.entries:
        if entry.number in (userdata.number, boot.number, root.number):
            continue
        if entry.last_lba >= userdata.first_lba:
            raise GptError("current partition follows or overlaps userdata")
    for entry in original.entries:
        if entry.number == original_userdata.number:
            continue
        if entry.last_lba >= original_userdata.first_lba:
            raise GptError("original partition follows or overlaps userdata")

    if userdata.first_lba > userdata.last_lba:
        raise GptError("current userdata extent is inverted")
    if userdata.last_lba >= boot.first_lba:
        raise GptError("current boot partition overlaps userdata")
    if boot.last_lba + 1 != root.first_lba:
        raise GptError("current boot and root partitions are not contiguous")
    if root.last_lba != original_userdata.last_lba:
        raise GptError("current root does not end at the original userdata end")
    for entry, label in ((userdata, "userdata"), (boot, "boot"),
                         (root, "root")):
        if (entry.first_lba < original_userdata.first_lba
                or entry.last_lba > original_userdata.last_lba):
            raise GptError(f"current {label} extent leaves original userdata")

    mib_sectors = (1 << 20) // sector
    expected_boot_start = (
        (userdata.last_lba + 1 + mib_sectors - 1) // mib_sectors
    ) * mib_sectors
    if boot.first_lba != expected_boot_start:
        raise GptError("current boot partition is not at the normal gap")
    if boot.last_lba - boot.first_lba + 1 != (1 << 30) // sector:
        raise GptError("current boot partition is not exactly 1 GiB")
    if root.last_lba - root.first_lba + 1 < (32 << 30) // sector:
        raise GptError("current root partition is smaller than 32 GiB")

    entry_size = current.entry_size
    array_bytes = current.entry_count * entry_size
    if (len(current.primary_entries) != len(current.backup_entries)
            or len(current.primary_entries) < array_bytes):
        raise GptError("current entry arrays have inconsistent lengths")

    new_entries = bytearray(current.primary_entries)
    userdata_offset = (userdata.number - 1) * entry_size
    struct.pack_into("<Q", new_entries, userdata_offset + 40,
                     original_userdata.last_lba)
    for number in (boot.number, root.number):
        offset = (number - 1) * entry_size
        new_entries[offset:offset + entry_size] = b"\x00" * entry_size
    entries_crc = zlib.crc32(bytes(new_entries[:array_bytes])) & 0xFFFFFFFF
    new_array = bytes(new_entries)

    primary_header = _rewrite_header(
        current.primary_header, sector, entries_crc
    )
    backup_header = _rewrite_header(
        current.backup_header, sector, entries_crc
    )

    return GptRestorePlan(
        write_regions=(
            WriteRegion(current.backup_entries_lba * sector, new_array),
            WriteRegion(current.disk_size_bytes - sector, backup_header),
            WriteRegion(current.primary_entries_lba * sector, new_array),
            WriteRegion(sector, primary_header),
        ),
        userdata_start_lba=userdata.first_lba,
        userdata_end_lba_exclusive=original_userdata.last_lba + 1,
        restored_userdata_bytes=(
            original_userdata.last_lba + 1 - userdata.first_lba
        ) * sector,
        removed_partition_numbers=(boot.number, root.number),
    )


def make_factory_reset_bcb(existing: bytes) -> bytes:
    """Return a 2048-byte BCB that queues a one-shot factory reset.

    ``existing`` must be exactly 2048 bytes with NUL bytes throughout
    ``command[0:32]`` and ``recovery[64:832]``; otherwise
    :class:`GptError` is raised. The input is not mutated. Only the command
    and recovery payload are written; ``status`` and ``reserved`` are
    preserved. No reboot or device write is performed.
    """

    if not isinstance(existing, (bytes, bytearray, memoryview)):
        raise GptError("BCB must be bytes-like")
    data = bytes(existing)
    if len(data) != _BCB_SIZE:
        raise GptError("BCB must be exactly 2048 bytes")
    if any(data[0:32]) or any(data[64:832]):
        raise GptError("a boot command or recovery request is already pending")

    buffer = bytearray(data)
    buffer[0:32] = _BCB_COMMAND.ljust(32, b"\x00")
    buffer[64:832] = _BCB_RECOVERY.ljust(768, b"\x00")
    return bytes(buffer)


# ---------------------------------------------------------------------------
# Runtime contracts and file-descriptor primitives
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1

ASSET_ROLES: Tuple[str, ...] = (
    "stock_boot_a",
    "stock_boot_b",
    "original_primary_gpt",
    "original_backup_gpt",
    "trusted_vbmeta_baseline",
)

RESTORE_STEPS: Tuple[str, ...] = (
    "restore-boot-a",
    "verify-boot-a",
    "restore-boot-b",
    "verify-boot-b",
    "reclaim-space",
    "queue-factory-reset",
)

_OTA_MESSAGE_BYTES = 64
_OTA_PACKED_VERSION = 2
_OTA_MAGIC = 0x56740AB0
_OTA_STATE_BY_STATUS = {
    0: "completed",
    1: "unknown",
    2: "snapshotted",
    3: "merging",
    4: "cancelled",
}
_BLKFLSBUF = 0x1261


class MaintenanceError(RuntimeError):
    """A rejected maintenance request.

    ``code`` is a stable machine-readable identifier and ``http_status`` the
    status the API layer must map it to (409 for contract violations). The
    human readable text is carried by ``RuntimeError`` itself. Nothing is
    logged or persisted here.
    """

    def __init__(self, code: str, message: str, http_status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


@dataclass(frozen=True)
class RuntimeCapture:
    """One immutable platform capture.

    ``snapshot`` holds the observed facts, ``gpt`` the parsed on-disk GPT,
    ``backups`` the captured snapshot files keyed ``boot_a``/``boot_b``/
    ``misc`` (``Path`` values) and ``slot_vbmeta`` the raw vbmeta bytes keyed
    ``a``/``b``. The whole capture is RAM-only and never rewritten.
    """

    snapshot: dict
    gpt: GptDisk
    backups: dict
    slot_vbmeta: dict


def boot_state_fingerprint(boot_sha256: dict, vbmeta_sha256: dict) -> str:
    """Canonical digest of the A/B boot slots.

    Both the platform facts and the runtime's per-phase expectations use this
    single rule, so the transaction can prove that the slot it is about to
    write the counterpart of is still the one it captured: SHA256 over
    ``boot_<slot>=<sha>;vbmeta_<slot>=<sha>;`` for ``a`` then ``b``.
    """

    digest = hashlib.sha256()
    for slot in ("a", "b"):
        digest.update(f"boot_{slot}={boot_sha256[slot]};".encode("ascii"))
        digest.update(f"vbmeta_{slot}={vbmeta_sha256[slot]};".encode("ascii"))
    return digest.hexdigest()


def parse_virtual_ab_message(message: bytes) -> dict:
    """Decode the 64-byte virtual A/B ``merge_status`` message.

    Anything that is not a version-2, correct-magic, slot 0/1, known-status
    envelope is reported as ``unknown`` with the parsed fields cleared.
    """

    try:
        raw = bytes(message)
    except (TypeError, ValueError) as exc:
        raise MaintenanceError(
            "invalid-message", "virtual A/B message must be bytes-like"
        ) from exc

    evidence = raw.hex()
    rejected = {
        "state": "unknown",
        "version": None,
        "mergeStatus": None,
        "sourceSlot": None,
        "evidence": evidence,
    }
    if len(raw) != _OTA_MESSAGE_BYTES:
        return rejected

    version = raw[0]
    magic = struct.unpack_from("<I", raw, 1)[0]
    merge_status = raw[5]
    source_slot = raw[6]
    if version != _OTA_PACKED_VERSION or magic != _OTA_MAGIC:
        return rejected
    if merge_status not in _OTA_STATE_BY_STATUS or source_slot not in (0, 1):
        return rejected

    return {
        "state": _OTA_STATE_BY_STATUS[merge_status],
        "version": version,
        "mergeStatus": merge_status,
        "sourceSlot": source_slot,
        "evidence": evidence,
    }


def gpt_to_sfdisk_json(gpt: GptDisk, disk_path: str) -> str:
    """Render ``gpt`` as a standard ``sfdisk --json`` partition table."""

    separator = "p" if disk_path[-1:].isdigit() else ""
    partitions = []
    for entry in gpt.entries:
        partition = {
            "node": f"{disk_path}{separator}{entry.number}",
            "start": entry.first_lba,
            "size": entry.last_lba - entry.first_lba + 1,
            "type": entry.type_guid,
            "uuid": entry.part_uuid,
            "name": entry.name,
        }
        if entry.attrs:
            bits = ",".join(
                str(bit) for bit in range(64) if entry.attrs >> bit & 1
            )
            partition["attrs"] = f"GUID:{bits}"
        partitions.append(partition)

    return json.dumps({
        "partitiontable": {
            "label": "gpt",
            "id": gpt.disk_guid,
            "device": disk_path,
            "unit": "sectors",
            "firstlba": gpt.first_usable_lba,
            "lastlba": gpt.last_usable_lba,
            "sectorsize": gpt.sector_size,
            "table-length": gpt.entry_count,
            "partitions": partitions,
        }
    })


def _pread_exact_fd(fd: int, length: int, offset: int) -> bytes:
    """Read exactly ``length`` bytes at ``offset``, retrying short chunks."""

    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise MaintenanceError(
            "short-read", f"read length must be a positive integer: {length!r}"
        )
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise MaintenanceError(
            "short-read", f"read offset must be non-negative: {offset!r}"
        )

    chunks = []
    done = 0
    while done < length:
        remaining = length - done
        chunk = os.pread(fd, remaining, offset + done)
        if not isinstance(chunk, (bytes, bytearray)):
            raise MaintenanceError("short-read", "pread returned no bytes object")
        if not chunk:
            raise MaintenanceError(
                "short-read", f"pread returned nothing at offset {offset + done}"
            )
        if len(chunk) > remaining:
            raise MaintenanceError("short-read", "pread returned too many bytes")
        chunks.append(bytes(chunk))
        done += len(chunk)
    return b"".join(chunks)


def _pwrite_all_fd(fd: int, data: bytes, offset: int) -> None:
    """Write all of ``data`` at ``offset``, retrying short writes."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MaintenanceError("short-write", "write payload must be bytes-like")
    payload = bytes(data)
    if not payload:
        raise MaintenanceError("short-write", "write payload must not be empty")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise MaintenanceError(
            "short-write", f"write offset must be non-negative: {offset!r}"
        )

    done = 0
    total = len(payload)
    while done < total:
        remaining = total - done
        written = os.pwrite(fd, payload[done:], offset + done)
        if isinstance(written, bool) or not isinstance(written, int):
            raise MaintenanceError("short-write", "pwrite returned no count")
        if written <= 0:
            raise MaintenanceError(
                "short-write", f"pwrite wrote nothing at offset {offset + done}"
            )
        if written > remaining:
            raise MaintenanceError("short-write", "pwrite wrote too many bytes")
        done += written


def _hash_fd(fd: int, length: int) -> str:
    """Return the lowercase SHA256 hex of ``length`` bytes read from offset 0."""

    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise MaintenanceError(
            "invalid-length", f"hash length must be a positive integer: {length!r}"
        )

    chunk_size = 1 << 20
    digest = hashlib.sha256()
    done = 0
    while done < length:
        piece = _pread_exact_fd(fd, min(chunk_size, length - done), done)
        digest.update(piece)
        done += len(piece)
    return digest.hexdigest()


def _flush_and_verify_fd(fd: int, length: int, expected_sha256: str) -> None:
    """Flush ``fd``, drop the page cache and verify the full read-back digest."""

    try:
        os.fsync(fd)
    except OSError as exc:
        raise MaintenanceError("flush-failed", f"fsync failed: {exc}") from exc
    try:
        fcntl.ioctl(fd, _BLKFLSBUF)
    except OSError as exc:
        raise MaintenanceError(
            "flush-failed", f"block device cache flush failed: {exc}"
        ) from exc

    actual = _hash_fd(fd, length)
    if not isinstance(expected_sha256, str):
        raise MaintenanceError(
            "flush-verify-mismatch", "expected digest must be a hex string"
        )
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise MaintenanceError(
            "flush-verify-mismatch",
            f"read-back digest {actual} does not match {expected_sha256}",
        )


def _kernel_extent_bytes(start_text: str, size_text: str) -> tuple:
    """Convert the 512-byte-unit sysfs ``start``/``size`` pair to bytes."""

    def parse_number(text: object, label: str, allow_zero: bool) -> int:
        if not isinstance(text, str) or not text.isdigit():
            raise MaintenanceError(
                "invalid-extent",
                f"sysfs {label} must be a non-negative decimal integer",
            )
        value = int(text, 10)
        if not allow_zero and value == 0:
            raise MaintenanceError(
                "invalid-extent", f"sysfs {label} must be positive"
            )
        return value

    start = parse_number(start_text, "start", True)
    size = parse_number(size_text, "size", False)
    return start * 512, size * 512



@dataclass(frozen=True)
class _BlockBinding:
    """Frozen discovery facts for one validated block-device binding.

    ``size_bytes`` and ``sector_size`` are the kernel geometry the opened
    node must report; ``start_bytes`` is the partition offset inside
    ``parent``. Whole-disk bindings use ``number=0``, ``start_bytes=0``, empty
    ``part_uuid``/``type_guid`` and ``parent`` equal to their own ``node``.
    """

    label: str
    node: str
    major: int
    minor: int
    size_bytes: int
    sector_size: int
    part_uuid: str
    parent: str
    number: int
    start_bytes: int
    type_guid: str


_RAM_FSTYPES = ("rootfs", "ramfs", "tmpfs")
_MODEL = "TB322FC"
_COMPATIBLE_REQUIRED = ("lenovo,elden", "qcom,sm8750")
_TARGET_DISK = "/dev/sda"
_BOOT_DISK = "/dev/sde"
_STATE_BACKUP_DIR = "backups"
_COPY_CHUNK = 1 << 20
_MISC_MAX_BYTES = 16 << 20
_VBMETA_MAX_BYTES = 1 << 20
_OTA_OFFSET = 32768
_BLKGETSIZE64 = 0x80081272
_BLKSSZGET = 0x1268
_BLKRRPART = 0x125F
_KERNEL_POLL_SECONDS = 5.0
_KERNEL_POLL_INTERVAL = 0.05
_SYS_BLOCK = Path("/sys/class/block")
_DT_COMPATIBLE = Path("/sys/firmware/devicetree/base/compatible")
_SOC_SERIAL = Path("/sys/devices/soc0/serial_number")
_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
_SELF_MOUNTINFO = Path("/proc/self/mountinfo")
_PID1_MOUNTINFO = Path("/proc/1/mountinfo")
_PROC_SWAPS = Path("/proc/swaps")

_BOOT_SLOT_LABELS = ("boot_a", "boot_b")
_VBMETA_LABELS = ("vbmeta_a", "vbmeta_b")
_REQUIRED_LABELS = ("userdata", "misc") + _BOOT_SLOT_LABELS + _VBMETA_LABELS
_OPTIONAL_LABELS = ("ARMADA_BOOT", "ARMADA_ROOT")
_GPT_LABELS = _REQUIRED_LABELS + _OPTIONAL_LABELS
_LABEL_PARENT = {
    "userdata": _TARGET_DISK,
    "misc": _TARGET_DISK,
    "ARMADA_BOOT": _TARGET_DISK,
    "ARMADA_ROOT": _TARGET_DISK,
    "boot_a": _BOOT_DISK,
    "boot_b": _BOOT_DISK,
    "vbmeta_a": _BOOT_DISK,
    "vbmeta_b": _BOOT_DISK,
}
_BASELINE_IDENTITY_KEYS = (
    "model",
    "socSerial",
    "bootId",
    "diskPath",
    "diskBytes",
    "sectorSize",
)
_IDENTITY_KEYS = (
    "model",
    "socSerial",
    "bootId",
    "diskPath",
    "diskBytes",
    "sectorSize",
    "tableFingerprint",
    "currentBootFingerprint",
    "miscFingerprint",
)
_BUSY_LISTS = ("mountedPartitions", "swapPartitions", "holderPartitions")


def _unescape_mount_field(text: str) -> str:
    """Decode the octal escapes mountinfo uses for spaces and backslashes."""

    raw = text.encode("utf-8", "surrogateescape")
    out = bytearray()
    index = 0
    while index < len(raw):
        if (raw[index] == 0x5C and index + 3 < len(raw)
                and all(0x30 <= item <= 0x37
                        for item in raw[index + 1:index + 4])):
            out.append(int(raw[index + 1:index + 4].decode("ascii"), 8))
            index += 4
            continue
        out.append(raw[index])
        index += 1
    return out.decode("utf-8", "surrogateescape")


def _ioctl_uint(fd: int, request: int, width: int) -> int:
    """Run a ``long``/``int`` output ioctl and return the little-endian value."""

    buffer = bytearray(width)
    try:
        fcntl.ioctl(fd, request, buffer, True)
    except OSError as exc:
        raise MaintenanceError(
            "device-ioctl-failed", f"ioctl 0x{request:x} failed: {exc}"
        ) from exc
    return int.from_bytes(buffer, "little")


def _normalize_digest(value: object, label: str) -> str:
    """Return a validated lowercase SHA256 hex digest."""

    if not isinstance(value, str) or len(value) != 64:
        raise MaintenanceError("invalid-digest", f"{label} must be a SHA256 hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise MaintenanceError(
            "invalid-digest", f"{label} must be a SHA256 hex digest"
        ) from exc
    return value.lower()


class _FdReader:
    """Bounded seek/read adapter over ``os.pread`` for :func:`read_gpt`."""

    __slots__ = ("_fd", "_pos")

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._pos = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._pos + offset
        else:
            raise ValueError("only absolute and relative seeks are supported")
        if position < 0:
            raise ValueError("negative seek position")
        self._pos = position
        return position

    def read(self, length: int = -1) -> bytes:
        if length is None or length < 0:
            raise ValueError("bounded reads only")
        data = _pread_exact_fd(self._fd, length, self._pos)
        self._pos += len(data)
        return data


class LinuxBlockBackend:
    """Real Linux block backend for the ArmadaOS uninstall flow.

    Every node is discovered from sysfs, bound to a validated GPT entry and
    reopened with ``O_NOFOLLOW`` before use; the descriptor must report the
    cached ``st_rdev`` and ``BLKGETSIZE64``/``BLKSSZGET`` geometry. The
    constructor refuses to run without root, a RAM-backed root filesystem and
    the verified TB322FC device tree. There is no path, flag or environment
    override, and the backend never reboots or formats anything.
    """

    def __init__(self, state_dir: Path) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise MaintenanceError("not-root", "maintenance requires root")
        self.state_dir = Path(os.path.abspath(str(state_dir)))
        self._bindings = {}
        self._identity = {}
        self._current_gpt = None
        self._lock_fd = None

        root = self._prove_ram_root()
        self._prepare_state_dir(root)
        self._bindings = self._discover_bindings()
        identity = self._probe_identity()
        disk = self._bindings["disk"]
        identity.update({
            "diskPath": disk.node,
            "diskBytes": disk.size_bytes,
            "sectorSize": disk.sector_size,
        })
        self._identity = identity

        fd = self._open_target("disk")
        try:
            self._current_gpt = self._read_gpt_fd(fd, disk)
        finally:
            os.close(fd)

    # -- discovery and identity ------------------------------------------
    def _read_text(self, path: Path, code: str) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MaintenanceError(code, f"cannot read {path}: {exc}") from exc

    def _read_mountinfo(self, path: Path) -> list:
        text = self._read_text(path, "mountinfo-unreadable")
        entries = []
        for line in text.splitlines():
            if not line.strip():
                continue
            fields = line.split(" ")
            try:
                separator = fields.index("-")
                major_text, minor_text = fields[2].split(":")
                major = int(major_text, 10)
                minor = int(minor_text, 10)
            except (ValueError, IndexError) as exc:
                raise MaintenanceError(
                    "mountinfo-invalid", f"malformed mountinfo line: {line!r}"
                ) from exc
            if separator < 6 or len(fields) <= separator + 2:
                raise MaintenanceError(
                    "mountinfo-invalid", f"malformed mountinfo line: {line!r}"
                )
            entries.append({
                "dev": (major, minor),
                "mount_point": _unescape_mount_field(fields[4]),
                "fstype": fields[separator + 1],
                "source": _unescape_mount_field(fields[separator + 2]),
            })
        return entries

    def _prove_ram_root(self) -> dict:
        try:
            root_stat = os.stat("/")
        except OSError as exc:
            raise MaintenanceError(
                "ram-root-unverified", f"cannot stat /: {exc}"
            ) from exc
        root_dev = (os.major(root_stat.st_dev), os.minor(root_stat.st_dev))
        mounts = self._read_mountinfo(_SELF_MOUNTINFO)
        match = None
        for entry in mounts:
            if entry["mount_point"] == "/" and entry["dev"] == root_dev:
                match = entry
                break
        if match is None:
            raise MaintenanceError(
                "ram-root-unverified", "no mountinfo entry backs the root mount"
            )
        if match["dev"][0] != 0:
            raise MaintenanceError(
                "not-ram-root", f"root mount has block major {match['dev'][0]}"
            )
        if match["fstype"] not in _RAM_FSTYPES:
            raise MaintenanceError(
                "not-ram-root",
                f"root filesystem {match['fstype']} is not RAM-backed",
            )
        return {
            "fstype": match["fstype"],
            "dev": root_dev,
            "mounts": mounts,
            "st_dev": root_stat.st_dev,
        }

    def _prepare_state_dir(self, root: dict) -> None:
        path = self.state_dir
        nearest = None
        nearest_dev = None
        for candidate in (path, *path.parents):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise MaintenanceError(
                    "state-dir-unverified", f"cannot stat {candidate}: {exc}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise MaintenanceError(
                    "state-dir-symlink",
                    f"state path component {candidate} is a symlink",
                )
            if nearest is None:
                nearest = candidate
                nearest_dev = (os.major(info.st_dev), os.minor(info.st_dev))
        if nearest is None or nearest_dev is None:
            raise MaintenanceError(
                "state-dir-unverified", "no existing ancestor for the state dir"
            )

        mount = None
        for entry in root["mounts"]:
            if entry["dev"] == nearest_dev:
                mount = entry
                break
        if (mount is None or mount["dev"][0] != 0
                or mount["fstype"] not in _RAM_FSTYPES):
            raise MaintenanceError(
                "state-dir-not-ram",
                f"state dir ancestor {nearest} is not on a RAM mount",
            )

        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.makedirs(path / _STATE_BACKUP_DIR, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise MaintenanceError(
                "state-dir-create-failed", f"cannot create {path}: {exc}"
            ) from exc

        try:
            created = os.stat(path)
        except OSError as exc:
            raise MaintenanceError(
                "state-dir-unverified", f"cannot stat {path}: {exc}"
            ) from exc
        if (os.major(created.st_dev), os.minor(created.st_dev)) != nearest_dev:
            raise MaintenanceError(
                "state-dir-moved", "state dir is not on the validated RAM mount"
            )

        lock_path = path / ".lock"
        try:
            fd = os.open(str(lock_path),
                         os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600)
        except OSError as exc:
            raise MaintenanceError(
                "state-lock-failed", f"cannot open {lock_path}: {exc}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise MaintenanceError(
                    "state-lock-failed", f"{lock_path} is not a regular file"
                )
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except MaintenanceError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise MaintenanceError(
                "state-lock-busy", f"another backend holds {lock_path}: {exc}"
            ) from exc
        self._lock_fd = fd

    def _read_compatible(self) -> list:
        raw = self._read_text(_DT_COMPATIBLE, "device-tree-unreadable")
        compatible = [part.strip() for part in raw.split("\x00") if part.strip()]
        for required in _COMPATIBLE_REQUIRED:
            if required not in compatible:
                raise MaintenanceError(
                    "unknown-device",
                    f"device tree does not list {required!r}; refusing to guess",
                )
        return compatible

    def _probe_identity(self) -> dict:
        compatible = self._read_compatible()
        soc_serial = self._read_text(_SOC_SERIAL, "soc-serial-unreadable").strip()
        if not soc_serial:
            raise MaintenanceError("soc-serial-unreadable", "empty SoC serial")
        # Bootstrap compares the raw /proc boot_id text exactly, so only the
        # trailing newline is stripped here; the UUID is validated but the
        # original spelling is preserved.
        boot_raw = self._read_text(_BOOT_ID, "boot-id-unreadable").strip()
        try:
            uuid.UUID(boot_raw)
        except (AttributeError, TypeError, ValueError) as exc:
            raise MaintenanceError("boot-id-invalid", f"bad boot id {boot_raw!r}") from exc
        return {
            "model": _MODEL,
            "socSerial": soc_serial,
            "bootId": boot_raw,
            "compatible": compatible,
        }

    def _read_uevent(self, path: Path) -> dict:
        text = self._read_text(path / "uevent", "sysfs-uevent-unreadable")
        values = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    @staticmethod
    def _uevent_dev(uevent: dict, path: Path) -> tuple:
        try:
            return int(uevent["MAJOR"], 10), int(uevent["MINOR"], 10)
        except (KeyError, ValueError) as exc:
            raise MaintenanceError(
                "sysfs-uevent-invalid", f"missing MAJOR/MINOR for {path}"
            ) from exc

    def _partition_number(self, path: Path, devname: str, parent: str) -> int:
        try:
            text = self._read_text(path / "partition", "partition-number-unreadable")
            return int(text.strip(), 10)
        except MaintenanceError:
            suffix = devname[len(parent):]
            if suffix.isdigit():
                return int(suffix, 10)
            raise
        except ValueError as exc:
            raise MaintenanceError(
                "partition-number-unreadable", f"bad partition number for {path}"
            ) from exc

    def _open_block_node(self, node: str, major: int, minor: int,
                         write: bool) -> int:
        flags = (os.O_RDWR if write else os.O_RDONLY)
        flags |= os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(node, flags)
        except OSError as exc:
            raise MaintenanceError(
                "device-open-failed", f"cannot open {node}: {exc}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISBLK(info.st_mode):
                raise MaintenanceError(
                    "not-block-device", f"{node} is not a block device"
                )
            if info.st_rdev != os.makedev(major, minor):
                raise MaintenanceError(
                    "device-identity-mismatch",
                    f"{node} does not match kernel {major}:{minor}",
                )
            if write:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise MaintenanceError(
                        "device-locked", f"cannot lock {node}: {exc}"
                    ) from exc
            return fd
        except OSError as exc:
            os.close(fd)
            raise MaintenanceError(
                "device-io-failed", f"cannot inspect {node}: {exc}"
            ) from exc
        except BaseException:
            os.close(fd)
            raise

    def _probe_node(self, node: str, major: int, minor: int) -> tuple:
        fd = self._open_block_node(node, major, minor, write=False)
        try:
            size = _ioctl_uint(fd, _BLKGETSIZE64, 8)
            sector = _ioctl_uint(fd, _BLKSSZGET, 4)
        finally:
            os.close(fd)
        if sector not in (512, 4096):
            raise MaintenanceError(
                "unsupported-sector-size", f"{node} reports sector {sector}"
            )
        return size, sector

    def _discover_bindings(self) -> dict:
        try:
            names = sorted(item.name for item in _SYS_BLOCK.iterdir())
        except OSError as exc:
            raise MaintenanceError(
                "sysfs-unreadable", f"cannot list {_SYS_BLOCK}: {exc}"
            ) from exc

        disks = {}
        partitions = {}
        for name in names:
            path = _SYS_BLOCK / name
            uevent = self._read_uevent(path)
            devname = uevent.get("DEVNAME") or name
            device_type = uevent.get("DEVTYPE")
            if device_type == "disk":
                major, minor = self._uevent_dev(uevent, path)
                disks[devname] = {
                    "node": f"/dev/{devname}",
                    "major": major,
                    "minor": minor,
                    "sysfs": path,
                }
                continue
            if device_type != "partition":
                continue
            label = uevent.get("PARTNAME")
            part_uuid = (uevent.get("PARTUUID") or "").upper()
            if not label or not part_uuid:
                # Only labelled, UUID-bearing partitions can be bound; a
                # required label that is absent still fails closed later.
                continue
            major, minor = self._uevent_dev(uevent, path)
            try:
                parent = path.resolve().parent.name
            except OSError as exc:
                raise MaintenanceError(
                    "sysfs-unreadable", f"cannot resolve {path}: {exc}"
                ) from exc
            number = self._partition_number(path, devname, parent)
            start_text = self._read_text(
                path / "start", "partition-extent-unreadable"
            ).strip()
            size_text = self._read_text(
                path / "size", "partition-extent-unreadable"
            ).strip()
            start_bytes, size_bytes = _kernel_extent_bytes(start_text, size_text)
            partitions.setdefault(label, []).append({
                "label": label,
                "node": f"/dev/{devname}",
                "major": major,
                "minor": minor,
                "parent": f"/dev/{parent}",
                "number": number,
                "part_uuid": part_uuid,
                "start_bytes": start_bytes,
                "size_bytes": size_bytes,
            })

        for required in ("sda", "sde"):
            if required not in disks:
                raise MaintenanceError(
                    "disk-missing", f"kernel disk {required} is not present"
                )

        disk_gpt = self._read_disk_gpt(disks["sda"], "disk")
        boot_gpt = self._read_disk_gpt(disks["sde"], "boot_disk")
        gpts = {_TARGET_DISK: disk_gpt, _BOOT_DISK: boot_gpt}

        bindings = {
            "disk": self._whole_disk_binding("disk", disks["sda"], disk_gpt),
            "boot_disk": self._whole_disk_binding(
                "boot_disk", disks["sde"], boot_gpt
            ),
        }

        for label in _GPT_LABELS:
            found = partitions.get(label) or []
            optional = label in _OPTIONAL_LABELS
            if not found:
                if optional:
                    continue
                raise MaintenanceError(
                    "partition-label-missing",
                    f"partition label {label} is not present",
                )
            if len(found) != 1:
                raise MaintenanceError(
                    "partition-label-ambiguous",
                    f"partition label {label} must be unique",
                )
            info = found[0]
            expected_parent = _LABEL_PARENT[label]
            if info["parent"] != expected_parent:
                raise MaintenanceError(
                    "partition-parent-mismatch",
                    f"{label} is not a child of {expected_parent}",
                )
            bindings[label] = self._partition_binding(
                info, gpts[expected_parent], expected_parent
            )
        return bindings

    @staticmethod
    def _unique_gpt_entry(gpt: GptDisk, label: str) -> GptEntry:
        matches = [entry for entry in gpt.entries if entry.name == label]
        if len(matches) != 1:
            raise MaintenanceError(
                "gpt-label-mismatch",
                f"GPT must contain exactly one {label} partition",
            )
        return matches[0]

    def _partition_binding(self, info: dict, gpt: GptDisk,
                           parent: str) -> _BlockBinding:
        entry = self._unique_gpt_entry(gpt, info["label"])
        if info["part_uuid"].upper() != entry.part_uuid.upper():
            raise MaintenanceError(
                "partuuid-mismatch",
                f"{info['label']} PARTUUID does not match the GPT",
            )
        if info["number"] != entry.number:
            raise MaintenanceError(
                "partition-number-mismatch",
                f"{info['label']} kernel number does not match the GPT slot",
            )
        sector = gpt.sector_size
        expected_start = entry.first_lba * sector
        expected_size = (entry.last_lba - entry.first_lba + 1) * sector
        if info["start_bytes"] != expected_start:
            raise MaintenanceError(
                "partition-extent-mismatch",
                f"{info['label']} sysfs start does not match the GPT",
            )
        if info["size_bytes"] != expected_size:
            raise MaintenanceError(
                "partition-extent-mismatch",
                f"{info['label']} sysfs size does not match the GPT",
            )
        size, node_sector = self._probe_node(
            info["node"], info["major"], info["minor"]
        )
        if size != expected_size or node_sector != sector:
            raise MaintenanceError(
                "partition-geometry-mismatch",
                f"{info['label']} kernel geometry does not match the GPT",
            )
        return _BlockBinding(
            label=info["label"],
            node=info["node"],
            major=info["major"],
            minor=info["minor"],
            size_bytes=size,
            sector_size=node_sector,
            part_uuid=entry.part_uuid,
            parent=parent,
            number=entry.number,
            start_bytes=info["start_bytes"],
            type_guid=entry.type_guid,
        )

    def _whole_disk_binding(self, label: str, info: dict,
                            gpt: GptDisk) -> _BlockBinding:
        size, sector = self._probe_node(
            info["node"], info["major"], info["minor"]
        )
        if sector != gpt.sector_size or size != gpt.disk_size_bytes:
            raise MaintenanceError(
                "disk-geometry-mismatch",
                f"{info['node']} kernel geometry does not match its GPT",
            )
        return _BlockBinding(
            label=label,
            node=info["node"],
            major=info["major"],
            minor=info["minor"],
            size_bytes=size,
            sector_size=sector,
            part_uuid="",
            parent=info["node"],
            number=0,
            start_bytes=0,
            type_guid="",
        )

    def _read_disk_gpt(self, info: dict, label: str) -> GptDisk:
        size, sector = self._probe_node(
            info["node"], info["major"], info["minor"]
        )
        fd = self._open_block_node(
            info["node"], info["major"], info["minor"], write=False
        )
        try:
            return self._read_gpt_fd(fd, _BlockBinding(
                label=label,
                node=info["node"],
                major=info["major"],
                minor=info["minor"],
                size_bytes=size,
                sector_size=sector,
                part_uuid="",
                parent=info["node"],
                number=0,
                start_bytes=0,
                type_guid="",
            ))
        finally:
            os.close(fd)

    # -- device handles ---------------------------------------------------
    def _open_target(self, label: str, write: bool = False) -> int:
        """Open the concrete node cached for ``label`` and re-check identity."""

        binding = self._bindings.get(label)
        if binding is None:
            raise MaintenanceError(
                "unknown-target", f"no validated binding for {label}"
            )
        fd = self._open_block_node(
            binding.node, binding.major, binding.minor, write=write
        )
        try:
            size = _ioctl_uint(fd, _BLKGETSIZE64, 8)
            sector = _ioctl_uint(fd, _BLKSSZGET, 4)
            if size != binding.size_bytes or sector != binding.sector_size:
                raise MaintenanceError(
                    "device-geometry-mismatch",
                    f"{label} geometry changed since discovery",
                )
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _read_gpt_fd(self, fd: int, binding: _BlockBinding) -> GptDisk:
        try:
            return read_gpt(_FdReader(fd), binding.sector_size,
                            binding.size_bytes)
        except GptError as exc:
            raise MaintenanceError("gpt-invalid", str(exc)) from exc

    # -- read-only inspection --------------------------------------------
    def _assert_bindings_stable(self, fresh: dict) -> None:
        cached = self._bindings
        if set(cached) != set(fresh):
            raise MaintenanceError(
                "binding-changed", "the set of validated block bindings changed"
            )
        for label in sorted(cached):
            if fresh[label] != cached[label]:
                raise MaintenanceError(
                    "binding-changed", f"{label} binding drifted from discovery"
                )

    def _block_catalog(self) -> dict:
        """Read every disk/partition entry under ``/sys/class/block``.

        The returned mapping is keyed by kernel ``DEVNAME`` and carries the
        kernel MAJOR/MINOR, the ``/dev`` node and the resolved parent name.
        Required facts that cannot be read are rejected, never skipped.
        """

        try:
            names = sorted(item.name for item in _SYS_BLOCK.iterdir())
        except OSError as exc:
            raise MaintenanceError(
                "sysfs-unreadable", f"cannot list {_SYS_BLOCK}: {exc}"
            ) from exc

        catalog = {}
        for name in names:
            path = _SYS_BLOCK / name
            uevent = self._read_uevent(path)
            device_type = uevent.get("DEVTYPE")
            if device_type not in ("disk", "partition"):
                continue
            devname = uevent.get("DEVNAME") or name
            major, minor = self._uevent_dev(uevent, path)
            try:
                parent = path.resolve().parent.name
            except OSError as exc:
                raise MaintenanceError(
                    "sysfs-unreadable", f"cannot resolve {path}: {exc}"
                ) from exc
            catalog[devname] = {
                "node": f"/dev/{devname}",
                "major": major,
                "minor": minor,
                "devtype": device_type,
                "parent": parent,
            }
        return catalog

    def _collect_busy_targets(self) -> dict:
        """Return ``{kernel_rdev: node}`` for every node a GPT rewrite touches.

        That is the whole target disk and *every* partition whose sysfs parent
        is the target disk, plus boot_a/boot_b/misc and the whole boot disk.
        Partition rdevs always come from each partition's own uevent; they are
        never derived from the whole-disk major/minor.
        """

        catalog = self._block_catalog()
        target_name = os.path.basename(_TARGET_DISK)
        disk_info = catalog.get(target_name)
        if disk_info is None or disk_info["devtype"] != "disk":
            raise MaintenanceError(
                "disk-missing", f"kernel disk {target_name} is not present"
            )
        targets = {
            os.makedev(disk_info["major"], disk_info["minor"]): disk_info["node"]
        }
        for info in catalog.values():
            if (info["devtype"] == "partition"
                    and info["parent"] == target_name):
                targets[os.makedev(info["major"], info["minor"])] = info["node"]

        for label in ("boot_a", "boot_b", "misc"):
            binding = self._bindings.get(label)
            if binding is None:
                raise MaintenanceError(
                    "unknown-target", f"no validated binding for {label}"
                )
            info = catalog.get(os.path.basename(binding.node))
            if info is None or info["devtype"] != "partition":
                raise MaintenanceError(
                    "device-missing", f"kernel node for {label} is absent"
                )
            if (info["major"], info["minor"]) != (binding.major, binding.minor):
                raise MaintenanceError(
                    "device-identity-mismatch",
                    f"{label} kernel identity changed",
                )
            targets[os.makedev(info["major"], info["minor"])] = info["node"]

        boot_binding = self._bindings.get("boot_disk")
        if boot_binding is None:
            raise MaintenanceError(
                "unknown-target", "no validated binding for boot_disk"
            )
        boot_info = catalog.get(os.path.basename(boot_binding.node))
        if boot_info is None or boot_info["devtype"] != "disk":
            raise MaintenanceError(
                "device-missing", "boot disk kernel node is absent"
            )
        if ((boot_info["major"], boot_info["minor"])
                != (boot_binding.major, boot_binding.minor)):
            raise MaintenanceError(
                "device-identity-mismatch", "boot disk kernel identity changed"
            )
        targets[os.makedev(boot_info["major"], boot_info["minor"])] = (
            boot_info["node"]
        )
        return targets

    def _busy_facts(self) -> dict:
        mounts = self._read_mountinfo(_SELF_MOUNTINFO)
        mounts += self._read_mountinfo(_PID1_MOUNTINFO)

        targets = self._collect_busy_targets()

        mounted = set()
        root_on_target = False
        mount_entry_devs = set()
        try:
            root_stat = os.stat("/")
        except OSError as exc:
            raise MaintenanceError(
                "mountinfo-unreadable", f"cannot stat /: {exc}"
            ) from exc
        root_rdev = os.makedev(
            os.major(root_stat.st_dev), os.minor(root_stat.st_dev)
        )
        if root_rdev in targets:
            root_on_target = True

        for entry in mounts:
            rdev = os.makedev(entry["dev"][0], entry["dev"][1])
            if rdev in targets:
                mounted.add(targets[rdev])
                if entry["mount_point"] == "/":
                    root_on_target = True
            source = entry["source"]
            if not source.startswith("/"):
                continue
            try:
                info = os.stat(source)
            except OSError as exc:
                raise MaintenanceError(
                    "mount-source-unverified",
                    f"cannot verify mount source {source}: {exc}",
                ) from exc
            if stat.S_ISBLK(info.st_mode):
                if info.st_rdev in targets:
                    mounted.add(targets[info.st_rdev])
                    mount_entry_devs.add(rdev)
                    if entry["mount_point"] == "/":
                        root_on_target = True
            else:
                backing = os.makedev(
                    os.major(info.st_dev), os.minor(info.st_dev)
                )
                if backing in targets:
                    mounted.add(targets[backing])
                    mount_entry_devs.add(rdev)
                    if entry["mount_point"] == "/":
                        root_on_target = True

        swaps = set()
        text = self._read_text(_PROC_SWAPS, "swapinfo-unreadable")
        for line in text.splitlines()[1:]:
            fields = line.split()
            if not fields:
                continue
            source = _unescape_mount_field(fields[0])
            try:
                info = os.stat(source)
            except OSError as exc:
                raise MaintenanceError(
                    "swapinfo-unreadable",
                    f"cannot stat swap source {source}: {exc}",
                ) from exc
            if stat.S_ISBLK(info.st_mode):
                if info.st_rdev in targets:
                    swaps.add(targets[info.st_rdev])
            else:
                backing = os.makedev(
                    os.major(info.st_dev), os.minor(info.st_dev)
                )
                if backing in targets or backing in mount_entry_devs:
                    swaps.add(source)

        holders = []
        for node in sorted(set(targets.values())):
            directory = _SYS_BLOCK / os.path.basename(node) / "holders"
            try:
                entries = sorted(item.name for item in directory.iterdir())
            except OSError as exc:
                raise MaintenanceError(
                    "sysfs-holders-unreadable",
                    f"cannot read holders of {node}: {exc}",
                ) from exc
            for name in entries:
                holders.append(
                    f"/sys/class/block/{os.path.basename(node)}/holders/{name}"
                )

        return {
            "rootOnTarget": root_on_target,
            "mountedPartitions": sorted(mounted),
            "swapPartitions": sorted(swaps),
            "holderPartitions": sorted(holders),
        }

    def current_state(self) -> dict:
        fresh = self._discover_bindings()
        self._assert_bindings_stable(fresh)
        identity = self._probe_identity()
        disk = self._bindings["disk"]

        fd = self._open_target("disk")
        try:
            gpt = self._read_gpt_fd(fd, disk)
        finally:
            os.close(fd)

        cached_gpt = self._current_gpt
        if cached_gpt is None:
            raise MaintenanceError("gpt-invalid", "no validated GPT is cached")
        for attribute in ("disk_guid", "disk_size_bytes", "sector_size",
                          "entry_count", "entry_size", "first_usable_lba",
                          "last_usable_lba"):
            if getattr(gpt, attribute) != getattr(cached_gpt, attribute):
                raise MaintenanceError(
                    "gpt-geometry-changed",
                    f"fresh GPT {attribute} differs from the cached table",
                )

        vbmeta = {}
        for label in _VBMETA_LABELS:
            binding = self._bindings.get(label)
            if binding is None:
                raise MaintenanceError(
                    "vbmeta-missing", f"{label} is not bound"
                )
            if binding.size_bytes > _VBMETA_MAX_BYTES:
                raise MaintenanceError(
                    "vbmeta-too-large",
                    f"{label} exceeds the 1 MiB vbmeta bound",
                )
            fd = self._open_target(label)
            try:
                vbmeta[label[-1]] = _hash_fd(fd, binding.size_bytes)
            finally:
                os.close(fd)

        slots = {}
        for slot in ("a", "b"):
            label = f"boot_{slot}"
            binding = self._bindings.get(label)
            if binding is None:
                raise MaintenanceError("boot-slot-missing", f"{label} is not bound")
            fd = self._open_target(label)
            try:
                digest = _hash_fd(fd, binding.size_bytes)
            finally:
                os.close(fd)
            slot_fingerprint = hashlib.sha256(
                f"slot|{slot}|{binding.node}|{binding.part_uuid}|"
                f"{binding.size_bytes}|{digest}|{vbmeta[slot]}".encode("ascii")
            ).hexdigest()
            slots[slot] = {
                "partitionPath": binding.node,
                "partUuid": binding.part_uuid,
                "bytes": binding.size_bytes,
                "sha256": digest,
                "vbmetaSha256": vbmeta[slot],
                "slotFingerprint": slot_fingerprint,
            }

        misc_binding = self._bindings.get("misc")
        if misc_binding is None:
            raise MaintenanceError("misc-missing", "misc is not bound")
        if misc_binding.size_bytes > _MISC_MAX_BYTES:
            raise MaintenanceError(
                "misc-too-large", "misc partition exceeds the 16 MiB bound"
            )
        fd = self._open_target("misc")
        try:
            misc_bytes = _pread_exact_fd(fd, misc_binding.size_bytes, 0)
        finally:
            os.close(fd)
        misc_sha = hashlib.sha256(misc_bytes).hexdigest()
        bcb_pending = any(misc_bytes[0:32]) or any(misc_bytes[64:832])
        message = misc_bytes[_OTA_OFFSET:_OTA_OFFSET + _OTA_MESSAGE_BYTES]
        ota = parse_virtual_ab_message(message)

        busy = self._busy_facts()
        root = self._prove_ram_root()
        ready = (
            not busy["rootOnTarget"]
            and not any(busy[key] for key in _BUSY_LISTS)
            and ota["state"] == "completed"
            and not bcb_pending
        )
        layout = {
            "device": disk.node,
            "sectorSize": gpt.sector_size,
            "tableFingerprint": gpt.fingerprint,
            "partitions": [
                {
                    "number": entry.number,
                    "name": entry.name,
                    "startSector": entry.first_lba,
                    "sectorCount": entry.last_lba - entry.first_lba + 1,
                    "typeGuid": entry.type_guid,
                    "partUuid": entry.part_uuid,
                }
                for entry in gpt.entries
            ],
        }
        return {
            "schemaVersion": SCHEMA_VERSION,
            "model": identity["model"],
            "socSerial": identity["socSerial"],
            "bootId": identity["bootId"],
            "ramRoot": True,
            "rootFstype": root["fstype"],
            "compatible": identity["compatible"],
            "diskPath": disk.node,
            "diskBytes": disk.size_bytes,
            "sectorSize": disk.sector_size,
            "tableFingerprint": gpt.fingerprint,
            "layout": layout,
            "sfdiskJson": gpt_to_sfdisk_json(gpt, disk.node),
            "primaryGptValid": True,
            "backupGptValid": True,
            "bothStockBootsValid": False,
            "bootSlots": slots,
            "currentBootFingerprint": boot_state_fingerprint(
                {slot: slots[slot]["sha256"] for slot in ("a", "b")},
                {slot: slots[slot]["vbmetaSha256"] for slot in ("a", "b")},
            ),
            "misc": {
                "partitionPath": misc_binding.node,
                "partUuid": misc_binding.part_uuid,
                "bytes": misc_binding.size_bytes,
                "sha256": misc_sha,
                "bcbPending": bcb_pending,
            },
            "miscFingerprint": misc_sha,
            "busy": busy,
            "ota": ota,
            "maintenanceValidated": ready,
        }

    # -- capture ----------------------------------------------------------
    @staticmethod
    def _require_ready(facts: dict) -> None:
        if not facts.get("ramRoot"):
            raise MaintenanceError("not-ram-root", "root is not RAM-backed")
        if facts.get("rootFstype") not in _RAM_FSTYPES:
            raise MaintenanceError(
                "not-ram-root",
                f"root filesystem {facts.get('rootFstype')} is not RAM-backed",
            )
        busy = facts.get("busy") or {}
        if busy.get("rootOnTarget"):
            raise MaintenanceError("busy", "target disk holds the root filesystem")
        for key in _BUSY_LISTS:
            if busy.get(key):
                raise MaintenanceError("busy", f"target disk is busy: {key}")
        ota = facts.get("ota") or {}
        if ota.get("state") != "completed":
            raise MaintenanceError(
                "ota-incomplete",
                f"virtual A/B state is {ota.get('state')!r}",
            )
        misc = facts.get("misc") or {}
        if misc.get("bcbPending"):
            raise MaintenanceError(
                "bcb-pending", "a boot command is already pending"
            )
        if facts.get("primaryGptValid") is not True:
            raise MaintenanceError("gpt-invalid", "primary GPT is not validated")
        if facts.get("backupGptValid") is not True:
            raise MaintenanceError("gpt-invalid", "backup GPT is not validated")
        if facts.get("maintenanceValidated") is not True:
            raise MaintenanceError(
                "not-validated", "maintenance preconditions are not satisfied"
            )

    def _capture_device(self, label: str, destination: Path) -> str:
        binding = self._bindings.get(label)
        if binding is None:
            raise MaintenanceError("unknown-target", f"no binding for {label}")
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_fd = self._open_target(label)
        try:
            try:
                dest_fd = os.open(str(destination), flags, 0o600)
            except OSError as exc:
                raise MaintenanceError(
                    "backup-create-failed",
                    f"cannot create {destination}: {exc}",
                ) from exc
            digest = hashlib.sha256()
            done = 0
            try:
                while done < binding.size_bytes:
                    chunk = _pread_exact_fd(
                        source_fd,
                        min(_COPY_CHUNK, binding.size_bytes - done),
                        done,
                    )
                    _pwrite_all_fd(dest_fd, chunk, done)
                    digest.update(chunk)
                    done += len(chunk)
                try:
                    os.fsync(dest_fd)
                except OSError as exc:
                    raise MaintenanceError(
                        "backup-fsync-failed", f"cannot flush {destination}: {exc}"
                    ) from exc
            except BaseException:
                os.close(dest_fd)
                try:
                    os.unlink(destination)
                except OSError:
                    pass
                raise
            os.close(dest_fd)

            saved = digest.hexdigest()
            physical = _hash_fd(source_fd, binding.size_bytes)
            if not hmac.compare_digest(saved, physical):
                raise MaintenanceError(
                    "capture-verify-failed",
                    f"{label} changed while it was captured",
                )

            verify_fd = os.open(
                str(destination), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                info = os.fstat(verify_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != binding.size_bytes:
                    raise MaintenanceError(
                        "capture-verify-failed",
                        f"{destination} is not the captured image",
                    )
                if not hmac.compare_digest(_hash_fd(verify_fd, binding.size_bytes),
                                           saved):
                    raise MaintenanceError(
                        "capture-verify-failed",
                        f"{destination} does not match the device",
                    )
            finally:
                os.close(verify_fd)
            return saved
        except OSError as exc:
            raise MaintenanceError(
                "device-io-failed", f"cannot capture {label}: {exc}"
            ) from exc
        finally:
            os.close(source_fd)

    def capture(self) -> RuntimeCapture:
        facts = self.current_state()
        self._require_ready(facts)
        disk = self._bindings["disk"]
        fd = self._open_target("disk")
        try:
            gpt = self._read_gpt_fd(fd, disk)
        finally:
            os.close(fd)
        if gpt.fingerprint != facts["tableFingerprint"]:
            raise MaintenanceError(
                "capture-mismatch", "GPT changed since the fresh inspection"
            )

        expected = {
            "boot_a": facts["bootSlots"]["a"]["sha256"],
            "boot_b": facts["bootSlots"]["b"]["sha256"],
            "misc": facts["misc"]["sha256"],
        }
        backups = {}
        for role in ("boot_a", "boot_b", "misc"):
            destination = self.state_dir / _STATE_BACKUP_DIR / f"{role}.img"
            digest = self._capture_device(role, destination)
            if not hmac.compare_digest(digest, expected[role]):
                raise MaintenanceError(
                    "capture-mismatch", f"{role} differs from the fresh inspection"
                )
            backups[role] = destination

        slot_vbmeta = {}
        for slot in ("a", "b"):
            label = f"vbmeta_{slot}"
            binding = self._bindings.get(label)
            if binding is None:
                raise MaintenanceError("vbmeta-missing", f"{label} is not bound")
            if binding.size_bytes > _VBMETA_MAX_BYTES:
                raise MaintenanceError(
                    "vbmeta-too-large",
                    f"{label} exceeds the 1 MiB vbmeta bound",
                )
            fd = self._open_target(label)
            try:
                raw = _pread_exact_fd(fd, binding.size_bytes, 0)
            finally:
                os.close(fd)
            digest = hashlib.sha256(raw).hexdigest()
            if not hmac.compare_digest(
                    digest, facts["bootSlots"][slot]["vbmetaSha256"]):
                raise MaintenanceError(
                    "capture-mismatch",
                    f"{label} differs from the fresh inspection",
                )
            slot_vbmeta[slot] = raw
        return RuntimeCapture(
            snapshot=facts, gpt=gpt, backups=backups, slot_vbmeta=slot_vbmeta
        )

    # -- readiness --------------------------------------------------------
    @staticmethod
    def _slot_map(value: object, label: str) -> dict:
        if not isinstance(value, dict) or set(value) != {"a", "b"}:
            raise MaintenanceError(
                f"{label}-invalid", f"{label} must map slots a and b"
            )
        return value

    def _check_static_bindings(self, facts: dict) -> None:
        disk = self._bindings.get("disk")
        if disk is None:
            raise MaintenanceError("disk-binding-missing", "disk is not bound")
        if (facts.get("diskPath") != disk.node
                or facts.get("diskBytes") != disk.size_bytes
                or facts.get("sectorSize") != disk.sector_size):
            raise MaintenanceError(
                "disk-binding-changed", "target disk identity changed"
            )
        slots = facts.get("bootSlots") or {}
        for slot in ("a", "b"):
            binding = self._bindings.get(f"boot_{slot}")
            data = slots.get(slot) or {}
            if (binding is None
                    or data.get("partitionPath") != binding.node
                    or (data.get("partUuid") or "").upper()
                    != binding.part_uuid.upper()
                    or data.get("bytes") != binding.size_bytes):
                raise MaintenanceError(
                    "partition-binding-changed",
                    f"boot slot {slot} binding changed",
                )
        misc = self._bindings.get("misc")
        misc_facts = facts.get("misc") or {}
        if (misc is None
                or misc_facts.get("partitionPath") != misc.node
                or (misc_facts.get("partUuid") or "").upper()
                != misc.part_uuid.upper()
                or misc_facts.get("bytes") != misc.size_bytes):
            raise MaintenanceError(
                "partition-binding-changed", "misc binding changed"
            )
        gpt = self._current_gpt
        if gpt is None:
            raise MaintenanceError("gpt-invalid", "no validated GPT is cached")
        for label in ("userdata",) + _OPTIONAL_LABELS:
            binding = self._bindings.get(label)
            if binding is None:
                continue
            entry = self._unique_gpt_entry(gpt, label)
            if (entry.part_uuid.upper() != binding.part_uuid.upper()
                    or entry.number != binding.number
                    or entry.first_lba * gpt.sector_size != binding.start_bytes
                    or (entry.last_lba - entry.first_lba + 1) * gpt.sector_size
                    != binding.size_bytes):
                raise MaintenanceError(
                    "partition-binding-changed", f"{label} binding changed"
                )

    def assert_ready(self, expected: dict) -> dict:
        """Re-probe every fact and refuse when anything drifted."""

        if not isinstance(expected, dict):
            raise MaintenanceError(
                "expected-invalid", "expected facts must be a mapping"
            )
        facts = self.current_state()
        self._require_ready(facts)

        for key in _BASELINE_IDENTITY_KEYS:
            if facts.get(key) != self._identity.get(key):
                raise MaintenanceError(f"{key}-mismatch", f"{key} changed")

        for key in _IDENTITY_KEYS:
            if key in expected and facts.get(key) != expected[key]:
                raise MaintenanceError(f"{key}-mismatch", f"{key} changed")

        if "miscSha256" in expected:
            if facts["misc"]["sha256"] != expected["miscSha256"]:
                raise MaintenanceError("misc-sha256-mismatch", "misc changed")
        if "bootSha256" in expected:
            for slot, digest in self._slot_map(
                    expected["bootSha256"], "bootSha256").items():
                if facts["bootSlots"][slot]["sha256"] != digest:
                    raise MaintenanceError(
                        "boot-sha256-mismatch", f"slot {slot} boot changed"
                    )
        if "vbmetaSha256" in expected:
            for slot, digest in self._slot_map(
                    expected["vbmetaSha256"], "vbmetaSha256").items():
                if facts["bootSlots"][slot]["vbmetaSha256"] != digest:
                    raise MaintenanceError(
                        "vbmeta-sha256-mismatch", f"slot {slot} vbmeta changed"
                    )

        self._check_static_bindings(facts)
        return facts

    # -- boot writes ------------------------------------------------------
    def _open_candidate(self, image_path: Path, expected_bytes: int,
                        expected_sha256: str) -> int:
        try:
            path = os.path.abspath(str(Path(image_path)))
        except (TypeError, ValueError) as exc:
            raise MaintenanceError(
                "candidate-invalid", f"invalid candidate path: {image_path!r}"
            ) from exc
        prefix = str(self.state_dir) + os.sep
        if not path.startswith(prefix):
            raise MaintenanceError(
                "candidate-outside-state",
                "candidate must live inside the validated RAM state dir",
            )
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise MaintenanceError(
                "candidate-open-failed", f"cannot open {path}: {exc}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise MaintenanceError(
                    "candidate-not-regular", "candidate is not a regular file"
                )
            if info.st_size != expected_bytes:
                raise MaintenanceError(
                    "candidate-size-mismatch",
                    f"candidate is {info.st_size} bytes, expected {expected_bytes}",
                )
            digest = _hash_fd(fd, expected_bytes)
            if not hmac.compare_digest(digest, expected_sha256):
                raise MaintenanceError(
                    "candidate-sha256-mismatch",
                    "candidate does not match the validated stock digest",
                )
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _boot_binding(self, slot: str, facts: dict) -> _BlockBinding:
        label = f"boot_{slot}"
        binding = self._bindings.get(label)
        data = (facts.get("bootSlots") or {}).get(slot) or {}
        if binding is None:
            raise MaintenanceError("boot-slot-missing", f"{label} is not bound")
        if (data.get("partitionPath") != binding.node
                or data.get("bytes") != binding.size_bytes
                or (data.get("partUuid") or "").upper()
                != binding.part_uuid.upper()):
            raise MaintenanceError(
                "partition-binding-changed", f"boot slot {slot} binding changed"
            )
        return binding

    def restore_boot(self, slot: str, image_path: Path,
                     expected_current_sha256: str,
                     expected_stock_sha256: str) -> str:
        """Overwrite one boot slot with a validated RAM stock image."""

        if slot not in ("a", "b"):
            raise MaintenanceError("unknown-slot", f"unknown boot slot {slot!r}")
        current_expected = _normalize_digest(
            expected_current_sha256, "expected current digest"
        )
        stock_expected = _normalize_digest(
            expected_stock_sha256, "expected stock digest"
        )

        facts = self.assert_ready({})
        binding = self._boot_binding(slot, facts)

        fd = self._open_target(f"boot_{slot}", write=True)
        try:
            actual = _hash_fd(fd, binding.size_bytes)
            if not hmac.compare_digest(actual, current_expected):
                raise MaintenanceError(
                    "current-sha256-mismatch",
                    f"slot {slot} changed since capture",
                )
            candidate = self._open_candidate(
                image_path, binding.size_bytes, stock_expected
            )
            try:
                done = 0
                while done < binding.size_bytes:
                    chunk = _pread_exact_fd(
                        candidate,
                        min(_COPY_CHUNK, binding.size_bytes - done),
                        done,
                    )
                    _pwrite_all_fd(fd, chunk, done)
                    done += len(chunk)
            finally:
                os.close(candidate)
            _flush_and_verify_fd(fd, binding.size_bytes, stock_expected)
        except OSError as exc:
            raise MaintenanceError(
                "device-io-failed", f"slot {slot} I/O failed: {exc}"
            ) from exc
        finally:
            os.close(fd)
        return stock_expected

    def verify_boot(self, slot: str, expected_sha256: str) -> None:
        """Re-read one boot slot and compare its full digest."""

        if slot not in ("a", "b"):
            raise MaintenanceError("unknown-slot", f"unknown boot slot {slot!r}")
        expected = _normalize_digest(expected_sha256, "expected digest")
        facts = self.assert_ready({})
        binding = self._boot_binding(slot, facts)
        fd = self._open_target(f"boot_{slot}")
        try:
            actual = _hash_fd(fd, binding.size_bytes)
        except OSError as exc:
            raise MaintenanceError(
                "device-io-failed", f"slot {slot} I/O failed: {exc}"
            ) from exc
        finally:
            os.close(fd)
        if not hmac.compare_digest(actual, expected):
            raise MaintenanceError(
                "verify-mismatch", f"slot {slot} does not match {expected}"
            )

    # -- GPT reclaim ------------------------------------------------------
    def _validate_restore_plan(self, plan: GptRestorePlan,
                               gpt: GptDisk) -> tuple:
        if not isinstance(plan, GptRestorePlan):
            raise MaintenanceError("plan-invalid", "a GptRestorePlan is required")
        sector = gpt.sector_size
        expected_offsets = (
            gpt.backup_entries_lba * sector,
            gpt.disk_size_bytes - sector,
            gpt.primary_entries_lba * sector,
            sector,
        )
        expected_lengths = (
            len(gpt.backup_entries),
            sector,
            len(gpt.primary_entries),
            sector,
        )
        if len(plan.write_regions) != 4:
            raise MaintenanceError("plan-invalid", "the plan must have four regions")
        for region, offset, length in zip(
                plan.write_regions, expected_offsets, expected_lengths):
            if region.offset != offset or len(region.data) != length:
                raise MaintenanceError(
                    "plan-mismatch",
                    "plan region does not match the validated GPT layout",
                )
        if len(plan.removed_partition_numbers) != 2:
            raise MaintenanceError(
                "plan-invalid", "exactly two owned partitions must be removed"
            )

        userdata = self._unique_gpt_entry(gpt, "userdata")
        if plan.userdata_start_lba != userdata.first_lba:
            raise MaintenanceError(
                "plan-mismatch", "plan userdata start differs from the GPT"
            )
        if plan.userdata_end_lba_exclusive <= userdata.last_lba + 1:
            raise MaintenanceError(
                "plan-mismatch", "plan userdata end does not grow the partition"
            )
        if plan.userdata_end_lba_exclusive > gpt.last_usable_lba + 1:
            raise MaintenanceError(
                "plan-mismatch", "plan userdata end leaves the usable range"
            )
        expected_bytes = (
            plan.userdata_end_lba_exclusive - plan.userdata_start_lba
        ) * sector
        if plan.restored_userdata_bytes != expected_bytes:
            raise MaintenanceError(
                "plan-mismatch", "plan userdata byte count is inconsistent"
            )

        owned = {}
        for number in plan.removed_partition_numbers:
            matches = [entry for entry in gpt.entries if entry.number == number]
            if len(matches) != 1 or matches[0].name not in _OPTIONAL_LABELS:
                raise MaintenanceError(
                    "plan-mismatch", "plan removes a foreign GPT slot"
                )
            owned[number] = matches[0]

        userdata_span = (
            plan.userdata_start_lba * sector,
            (userdata.last_lba + 1) * sector,
        )
        for region in plan.write_regions:
            if region.offset < sector:
                raise MaintenanceError(
                    "plan-mismatch", "plan writes over the protective MBR"
                )
            end = region.offset + len(region.data)
            if region.offset < userdata_span[1] and end > userdata_span[0]:
                raise MaintenanceError(
                    "plan-mismatch", "plan writes inside the userdata extent"
                )
        return owned, userdata

    def _wait_for_kernel_remap(self, disk: _BlockBinding,
                               userdata: _BlockBinding,
                               start_bytes: int, size_bytes: int,
                               removed_numbers: tuple) -> None:
        directory = _SYS_BLOCK / os.path.basename(userdata.node)
        removed_nodes = [
            _SYS_BLOCK / f"{os.path.basename(disk.node)}{number}"
            for number in removed_numbers
        ]
        deadline = time.monotonic() + _KERNEL_POLL_SECONDS
        while True:
            if time.monotonic() >= deadline:
                raise MaintenanceError(
                    "partition-table-not-reloaded",
                    "kernel partition mapping did not follow BLKRRPART",
                )
            ready = False
            try:
                start_text = (directory / "start").read_text().strip()
                size_text = (directory / "size").read_text().strip()
                kernel_start, kernel_size = _kernel_extent_bytes(
                    start_text, size_text
                )
                stale = [node for node in removed_nodes if node.exists()]
                ready = (
                    not stale
                    and kernel_start == start_bytes
                    and kernel_size == size_bytes
                )
            except (OSError, UnicodeDecodeError):
                # A node can disappear for a moment while the kernel
                # re-reads the table; keep polling until the deadline.
                ready = False
            if ready:
                return
            time.sleep(_KERNEL_POLL_INTERVAL)

    def reclaim_space(self, plan: GptRestorePlan,
                      expected_table_fingerprint: str) -> str:
        """Apply the GPT-only reclaim plan and force a kernel re-read."""

        if not isinstance(expected_table_fingerprint, str) or not expected_table_fingerprint:
            raise MaintenanceError(
                "fingerprint-invalid", "expected table fingerprint is required"
            )
        self.assert_ready({})
        disk = self._bindings.get("disk")
        if disk is None or disk.number != 0 or disk.parent != disk.node:
            raise MaintenanceError("disk-binding-missing", "disk is not bound")
        if disk.node != _TARGET_DISK:
            raise MaintenanceError("disk-binding-changed", "unexpected target disk")

        fd = self._open_target("disk", write=True)
        try:
            gpt = self._read_gpt_fd(fd, disk)
            if gpt.fingerprint != expected_table_fingerprint:
                raise MaintenanceError(
                    "table-changed", "GPT changed since prepare"
                )
            cached = self._current_gpt
            if cached is None or cached.fingerprint != expected_table_fingerprint:
                raise MaintenanceError(
                    "table-changed", "cached GPT is not the prepared table"
                )

            owned, userdata = self._validate_restore_plan(plan, gpt)
            sector = gpt.sector_size
            new_start_bytes = plan.userdata_start_lba * sector
            new_size_bytes = (
                plan.userdata_end_lba_exclusive - plan.userdata_start_lba
            ) * sector

            for region in plan.write_regions:
                _pwrite_all_fd(fd, region.data, region.offset)
                try:
                    os.fsync(fd)
                except OSError as exc:
                    raise MaintenanceError(
                        "flush-failed", f"fsync after GPT write failed: {exc}"
                    ) from exc
            try:
                fcntl.ioctl(fd, _BLKFLSBUF)
            except OSError as exc:
                raise MaintenanceError(
                    "flush-failed", f"block cache flush failed: {exc}"
                ) from exc

            for region in plan.write_regions:
                actual = _pread_exact_fd(fd, len(region.data), region.offset)
                if actual != region.data:
                    raise MaintenanceError(
                        "gpt-readback-mismatch",
                        f"GPT region at {region.offset} did not read back "
                        "byte-exactly",
                    )

            restored = self._read_gpt_fd(fd, disk)
            numbers = {entry.number for entry in restored.entries}
            for number in plan.removed_partition_numbers:
                if number in numbers:
                    raise MaintenanceError(
                        "reclaim-incomplete",
                        f"owned partition {number} is still present",
                    )
            for entry in restored.entries:
                if entry.name in _OPTIONAL_LABELS:
                    raise MaintenanceError(
                        "reclaim-incomplete",
                        f"own partition label {entry.name} is still present",
                    )
            userdata_entries = [
                entry for entry in restored.entries if entry.name == "userdata"
            ]
            if (len(userdata_entries) != 1
                    or userdata_entries[0].first_lba != plan.userdata_start_lba
                    or userdata_entries[0].last_lba + 1
                    != plan.userdata_end_lba_exclusive):
                raise MaintenanceError(
                    "reclaim-incomplete", "userdata extent was not restored"
                )
            before = {entry.number: entry for entry in gpt.entries}
            for entry in restored.entries:
                if entry.number in plan.removed_partition_numbers:
                    continue
                if entry.number == userdata.number:
                    continue
                previous = before.get(entry.number)
                if previous is None or previous.raw != entry.raw:
                    raise MaintenanceError(
                        "reclaim-foreign-change",
                        f"partition {entry.number} was not preserved",
                    )

            try:
                fcntl.ioctl(fd, _BLKRRPART)
            except OSError as exc:
                raise MaintenanceError(
                    "partition-reread-failed",
                    f"kernel could not re-read the partition table: {exc}",
                ) from exc

            self._wait_for_kernel_remap(
                disk, self._bindings["userdata"], new_start_bytes,
                new_size_bytes, tuple(plan.removed_partition_numbers),
            )

            current = self._bindings.get("userdata")
            if current is not None:
                self._bindings["userdata"] = _BlockBinding(
                    label=current.label,
                    node=current.node,
                    major=current.major,
                    minor=current.minor,
                    size_bytes=new_size_bytes,
                    sector_size=current.sector_size,
                    part_uuid=userdata.part_uuid,
                    parent=current.parent,
                    number=userdata.number,
                    start_bytes=new_start_bytes,
                    type_guid=userdata.type_guid,
                )
            for label in _OPTIONAL_LABELS:
                self._bindings.pop(label, None)
            self._current_gpt = restored
            return restored.fingerprint
        except OSError as exc:
            raise MaintenanceError(
                "device-io-failed", f"target disk I/O failed: {exc}"
            ) from exc
        finally:
            os.close(fd)

    # -- BCB --------------------------------------------------------------
    def queue_factory_reset(self, expected_misc_sha256: str) -> str:
        """Write only the BCB command/recovery fields and verify the result."""

        expected = _normalize_digest(expected_misc_sha256, "expected misc digest")
        facts = self.assert_ready({})
        binding = self._bindings.get("misc")
        misc_facts = facts.get("misc") or {}
        if binding is None:
            raise MaintenanceError("misc-missing", "misc is not bound")
        if (misc_facts.get("partitionPath") != binding.node
                or misc_facts.get("bytes") != binding.size_bytes
                or (misc_facts.get("partUuid") or "").upper()
                != binding.part_uuid.upper()):
            raise MaintenanceError(
                "partition-binding-changed", "misc binding changed"
            )
        if binding.size_bytes > _MISC_MAX_BYTES:
            raise MaintenanceError(
                "misc-too-large", "misc partition exceeds the 16 MiB bound"
            )

        fd = self._open_target("misc", write=True)
        try:
            current = _pread_exact_fd(fd, binding.size_bytes, 0)
            digest = hashlib.sha256(current).hexdigest()
            if not hmac.compare_digest(digest, expected):
                raise MaintenanceError("misc-changed", "misc changed since prepare")
            if any(current[0:32]) or any(current[64:832]):
                raise MaintenanceError(
                    "bcb-pending", "a boot command is already pending"
                )
            try:
                bcb = make_factory_reset_bcb(current[:_BCB_SIZE])
            except GptError as exc:
                raise MaintenanceError("bcb-invalid", str(exc)) from exc

            _pwrite_all_fd(fd, bcb[0:32], 0)
            _pwrite_all_fd(fd, bcb[64:832], 64)

            expected_full = bytearray(current)
            expected_full[:_BCB_SIZE] = bcb
            expected_sha = hashlib.sha256(bytes(expected_full)).hexdigest()
            _flush_and_verify_fd(fd, binding.size_bytes, expected_sha)
        except OSError as exc:
            raise MaintenanceError(
                "device-io-failed", f"misc I/O failed: {exc}"
            ) from exc
        finally:
            os.close(fd)
        return expected_sha


_ASSET_CHUNK = 1 << 20
_BACKUP_ROLES = ("boot_a", "boot_b", "misc")
_TERMINAL_STATES = ("awaitingFactoryReset", "failed")


class _GptImageReader:
    """Finite seek/read view of the two real original GPT assets."""

    __slots__ = ("_primary", "_backup", "_disk", "_pos")

    def __init__(self, primary: bytes, backup: bytes, disk_bytes: int) -> None:
        self._primary = primary
        self._backup = backup
        self._disk = disk_bytes
        self._pos = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._pos + offset
        elif whence == 2:
            position = self._disk + offset
        else:
            raise ValueError("invalid whence")
        if position < 0:
            raise ValueError("negative seek position")
        self._pos = position
        return position

    def read(self, length: int = -1) -> bytes:
        if length is None or length < 0:
            raise ValueError("bounded reads only")
        end = self._pos + length
        if end > self._disk:
            raise ValueError("read past the virtual disk")
        primary_end = len(self._primary)
        backup_start = self._disk - len(self._backup)
        if end <= primary_end:
            data = self._primary[self._pos:end]
        elif self._pos >= backup_start and end <= self._disk:
            data = self._backup[self._pos - backup_start:end - backup_start]
        else:
            raise ValueError("read is not backed by a captured GPT region")
        self._pos = end
        return data


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _require_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MaintenanceError("invalid-value", f"{label} must be a positive integer")
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MaintenanceError("invalid-value", f"{label} must be a non-empty string")
    return value


def _tx_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise MaintenanceError("transaction-id-invalid", "transactionId must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise MaintenanceError(
            "transaction-id-invalid", "transactionId must be a UUID"
        ) from exc
    return str(parsed)


class MaintenanceRuntime:
    """Six-step uninstall transaction over one validated platform capture.

    The object owns the upload slots, the prepared plan, the backup
    acknowledgement gate and the background worker. Every state transition is
    persisted atomically; no method reboots, formats or erases metadata.
    """

    def __init__(self, platform, state_dir: Path, *,
                 restore_validator=None) -> None:
        model = getattr(platform, "model", None)
        if model is not None and model != _MODEL:
            raise MaintenanceError("unknown-device", "unsupported device model")
        if getattr(platform, "ram_root", True) is False:
            raise MaintenanceError("not-ram-root", "root is not RAM-backed")
        fstype = getattr(platform, "root_fstype", None)
        if fstype is not None and fstype not in _RAM_FSTYPES:
            raise MaintenanceError("not-ram-root", "root is not RAM-backed")

        self.platform = platform
        self.state_dir = Path(state_dir)
        self.restore_validator = restore_validator
        self._lock = threading.RLock()
        self._capture = None
        self._asset_meta = {}
        self._tx = None
        self._saved = {}
        self._worker = None
        self._load_saved_status()

    # -- persistence ------------------------------------------------------
    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC
                         | getattr(os, "O_DIRECTORY", 0))
        except OSError as exc:
            raise MaintenanceError(
                "persist-failed", f"cannot open {path}: {exc}", 500
            ) from exc
        try:
            os.fsync(fd)
        except OSError as exc:
            raise MaintenanceError(
                "persist-failed", f"cannot flush {path}: {exc}", 500
            ) from exc
        finally:
            os.close(fd)

    def _persist_document(self, transaction_id: str, document: dict) -> None:
        directory = self.state_dir / "transactions" / transaction_id
        try:
            os.makedirs(str(directory), mode=0o700, exist_ok=True)
        except OSError as exc:
            raise MaintenanceError(
                "persist-failed", f"cannot create {directory}: {exc}", 500
            ) from exc
        payload = _canonical_json(document).encode("ascii")
        temporary = directory / f".status.{uuid.uuid4().hex}.tmp"
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fd = os.open(str(temporary), flags, 0o600)
        except OSError as exc:
            raise MaintenanceError(
                "persist-failed", f"cannot create {temporary}: {exc}", 500
            ) from exc
        try:
            _pwrite_all_fd(fd, payload, 0)
            try:
                os.fsync(fd)
            except OSError as exc:
                raise MaintenanceError(
                    "persist-failed", f"cannot flush {temporary}: {exc}", 500
                ) from exc
        except BaseException:
            os.close(fd)
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        os.close(fd)
        try:
            os.replace(str(temporary), str(directory / "status.json"))
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise MaintenanceError(
                "persist-failed", f"cannot publish status: {exc}", 500
            ) from exc
        self._fsync_dir(directory)

    def _persist(self, record: dict) -> None:
        self._persist_document(record["id"], record["status"])

    def _load_saved_status(self) -> None:
        root = self.state_dir / "transactions"
        try:
            names = sorted(item.name for item in root.iterdir())
        except OSError:
            return
        for name in names:
            path = root / name / "status.json"
            try:
                text = path.read_text(encoding="utf-8")
                document = json.loads(text)
            except (OSError, UnicodeDecodeError, ValueError):
                continue
            if not isinstance(document, dict):
                continue
            try:
                transaction_id = _tx_uuid(document.get("transactionId"))
            except MaintenanceError:
                continue
            if transaction_id != name:
                continue
            if document.get("state") not in _TERMINAL_STATES:
                document["state"] = "failed"
                document["stage"] = "Interrupted"
                document["activeStep"] = None
                document["error"] = {
                    "code": "interrupted",
                    "message": "runtime restarted before the step completed",
                    "stage": "startup",
                }
                try:
                    self._persist_document(transaction_id, document)
                except MaintenanceError:
                    pass
            self._saved[transaction_id] = document

    # -- read helpers -----------------------------------------------------
    @staticmethod
    def _verify_file(path: Path, length: int, digest: str,
                     label: str) -> None:
        try:
            fd = os.open(str(path),
                         os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise MaintenanceError(
                "file-unavailable", f"{label} cannot be opened: {exc}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise MaintenanceError("file-invalid", f"{label} is not a regular file")
            if info.st_size != length:
                raise MaintenanceError(
                    "file-changed", f"{label} length differs from the snapshot"
                )
            actual = _hash_fd(fd, length)
        finally:
            os.close(fd)
        if not hmac.compare_digest(actual, digest):
            raise MaintenanceError("file-changed", f"{label} content changed")

    @staticmethod
    def _open_verified(path: Path, length: int, digest: str,
                       label: str) -> int:
        try:
            fd = os.open(str(path),
                         os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise MaintenanceError(
                "file-unavailable", f"{label} cannot be opened: {exc}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise MaintenanceError("file-invalid", f"{label} is not a regular file")
            if info.st_size != length:
                raise MaintenanceError(
                    "file-changed", f"{label} length differs from the snapshot"
                )
            if not hmac.compare_digest(_hash_fd(fd, length), digest):
                raise MaintenanceError("file-changed", f"{label} content changed")
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _read_verified(path: Path, length: int, digest: str,
                       label: str) -> bytes:
        fd = MaintenanceRuntime._open_verified(path, length, digest, label)
        try:
            return _pread_exact_fd(fd, length, 0)
        finally:
            os.close(fd)

    def _asset_path(self, role: str) -> Path:
        return self.state_dir / "assets" / f"{role}.bin"

    def _ensure_capture(self) -> RuntimeCapture:
        with self._lock:
            if self._capture is None:
                capture = self.platform.capture()
                if not isinstance(capture, RuntimeCapture):
                    raise MaintenanceError(
                        "capture-invalid", "platform capture has an invalid shape"
                    )
                self._capture = capture
            return self._capture

    def _ready_facts(self) -> dict:
        facts = self.platform.current_state()
        if not isinstance(facts, dict):
            raise MaintenanceError("state-invalid", "platform state must be a mapping")
        if facts.get("maintenanceValidated") is not True:
            raise MaintenanceError(
                "not-validated", "maintenance preconditions are not satisfied"
            )
        return facts

    def _backup_snapshot(self, capture: RuntimeCapture) -> list:
        entries = []
        for slot, role in (("a", "boot_a"), ("b", "boot_b")):
            data = capture.snapshot["bootSlots"][slot]
            entries.append({
                "role": role,
                "bytes": data["bytes"],
                "sha256": data["sha256"],
            })
        entries.append({
            "role": "misc",
            "bytes": capture.snapshot["misc"]["bytes"],
            "sha256": capture.snapshot["misc"]["sha256"],
        })
        return entries

    def _verify_backups(self, record: dict) -> None:
        for entry in record["backupEntries"]:
            path = record["capture"].backups[entry["role"]]
            self._verify_file(path, entry["bytes"], entry["sha256"],
                              f"backup {entry['role']}")

    def _rehash_assets(self, record: dict) -> None:
        for role in ASSET_ROLES:
            meta = record["assets"].get(role)
            if not meta:
                raise MaintenanceError("asset-missing", f"asset {role} is missing")
            self._verify_file(self._asset_path(role), meta["bytes"],
                              meta["sha256"], f"asset {role}")

    # -- inspection -------------------------------------------------------
    def inspect(self) -> dict:
        facts = self.platform.current_state()
        if not isinstance(facts, dict):
            raise MaintenanceError("state-invalid", "platform state must be a mapping")
        document = copy.deepcopy(facts)
        document.setdefault("schemaVersion", SCHEMA_VERSION)
        prepared = bool(self._tx and self._tx["status"]["bothStockBootsValid"])
        document["bothStockBootsValid"] = prepared
        if facts.get("maintenanceValidated") is not True:
            return document

        capture = self._ensure_capture()
        disk_path = document.get("diskPath") or capture.snapshot.get("diskPath")
        if not document.get("layout"):
            document["layout"] = {
                "device": disk_path,
                "sectorSize": capture.gpt.sector_size,
                "tableFingerprint": capture.gpt.fingerprint,
                "partitions": [
                    {
                        "number": entry.number,
                        "name": entry.name,
                        "startSector": entry.first_lba,
                        "sectorCount": entry.last_lba - entry.first_lba + 1,
                        "typeGuid": entry.type_guid,
                        "partUuid": entry.part_uuid,
                    }
                    for entry in capture.gpt.entries
                ],
            }
        if not document.get("sfdiskJson"):
            document["sfdiskJson"] = gpt_to_sfdisk_json(capture.gpt, disk_path)
        return document

    # -- uploads ----------------------------------------------------------
    def put_asset(self, role: str, reader, length: int) -> dict:
        if not isinstance(role, str) or role not in ASSET_ROLES:
            raise MaintenanceError("unsupported-role", f"unsupported asset role {role!r}")
        length = _require_positive_int(length, "asset length")
        if role in ("original_primary_gpt", "original_backup_gpt"):
            if length > 16 << 20:
                raise MaintenanceError("asset-too-large", "GPT asset exceeds 16 MiB")
        elif role == "trusted_vbmeta_baseline":
            if length > 1 << 20:
                raise MaintenanceError("asset-too-large", "baseline exceeds 1 MiB")
        else:
            slot = role[-1]
            self._ready_facts()
            capture = self._ensure_capture()
            limit = capture.snapshot["bootSlots"][slot]["bytes"]
            if length > limit:
                raise MaintenanceError(
                    "asset-too-large", "stock boot image exceeds its partition"
                )

        if role not in ("stock_boot_a", "stock_boot_b"):
            self._ready_facts()
            self._ensure_capture()

        assets_dir = self.state_dir / "assets"
        try:
            os.makedirs(str(assets_dir), mode=0o700, exist_ok=True)
        except OSError as exc:
            raise MaintenanceError(
                "asset-store-failed", f"cannot create {assets_dir}: {exc}", 500
            ) from exc

        temporary = assets_dir / f".{role}.{uuid.uuid4().hex}.tmp"
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fd = os.open(str(temporary), flags, 0o600)
        except OSError as exc:
            raise MaintenanceError(
                "asset-store-failed", f"cannot create upload: {exc}", 500
            ) from exc

        digest = hashlib.sha256()
        done = 0
        try:
            while done < length:
                wanted = min(_ASSET_CHUNK, length - done)
                chunk = reader.read(wanted)
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise MaintenanceError("short-read", "asset upload returned no bytes")
                data = bytes(chunk)
                if not data:
                    raise MaintenanceError("short-read", "asset upload ended early")
                if len(data) > wanted:
                    raise MaintenanceError("short-read", "asset upload returned extra bytes")
                _pwrite_all_fd(fd, data, done)
                digest.update(data)
                done += len(data)
            try:
                os.fsync(fd)
            except OSError as exc:
                raise MaintenanceError(
                    "asset-store-failed", f"cannot flush upload: {exc}", 500
                ) from exc
        except BaseException:
            os.close(fd)
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        os.close(fd)

        sha256 = digest.hexdigest()
        final = self._asset_path(role)
        try:
            with self._lock:
                if self._tx is not None:
                    existing = self._tx["assets"].get(role)
                    if existing is None:
                        raise MaintenanceError(
                            "assets-immutable", "prepared transaction is immutable"
                        )
                    self._verify_file(final, existing["bytes"],
                                      existing["sha256"], f"asset {role}")
                    if (existing["bytes"] != length
                            or not hmac.compare_digest(existing["sha256"], sha256)):
                        raise MaintenanceError(
                            "assets-immutable", "prepared asset cannot be replaced"
                        )
                    os.unlink(temporary)
                    return dict(existing)
                os.replace(str(temporary), str(final))
                self._fsync_dir(assets_dir)
                meta = {"role": role, "bytes": length, "sha256": sha256}
                self._asset_meta[role] = meta
                return dict(meta)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    # -- backups ----------------------------------------------------------
    def backup_file(self, role: str) -> tuple:
        aliases = {
            "a": "boot_a", "boot_a": "boot_a",
            "b": "boot_b", "boot_b": "boot_b",
            "misc": "misc",
        }
        if not isinstance(role, str) or role not in aliases:
            raise MaintenanceError("unsupported-role", f"unsupported backup role {role!r}")
        key = aliases[role]
        self._ready_facts()
        capture = self._ensure_capture()
        if key == "misc":
            expected = capture.snapshot["misc"]
        else:
            expected = capture.snapshot["bootSlots"][key[-1]]
        path = Path(capture.backups[key])
        length = expected["bytes"]
        sha256 = expected["sha256"]
        self._verify_file(path, length, sha256, f"backup {key}")
        return path, {"role": key, "bytes": length, "sha256": sha256}

    # -- prepare ----------------------------------------------------------
    @staticmethod
    def _parse_prepare(payload: object) -> dict:
        if not isinstance(payload, dict):
            raise MaintenanceError("payload-invalid", "prepare payload must be a mapping")
        transaction_id = _tx_uuid(payload.get("transactionId"))

        expected_raw = payload.get("expected")
        if not isinstance(expected_raw, dict):
            raise MaintenanceError("expected-invalid", "expected must be a mapping")
        expected = {}
        for key in ("model", "socSerial", "bootId", "diskPath"):
            expected[key] = _require_text(expected_raw.get(key), key)
        for key in ("diskBytes", "sectorSize"):
            expected[key] = _require_positive_int(expected_raw.get(key), key)
        for key in ("tableFingerprint", "currentBootFingerprint", "miscFingerprint"):
            value = expected_raw.get(key)
            if not isinstance(value, str):
                raise MaintenanceError("expected-invalid", f"{key} must be a digest")
            expected[key] = _normalize_digest(value, key)

        ownership_raw = payload.get("ownedPartitions")
        if not isinstance(ownership_raw, dict):
            raise MaintenanceError("ownership-invalid", "ownedPartitions must be a mapping")
        ownership = {}
        for key in ("userdataPartUuid", "linuxBootPartUuid", "linuxRootPartUuid"):
            try:
                ownership[key] = _uuid_text(ownership_raw.get(key), key)
            except GptError as exc:
                raise MaintenanceError("ownership-invalid", str(exc)) from exc
        if len(set(ownership.values())) != 3:
            raise MaintenanceError(
                "ownership-invalid", "owned partition UUIDs must be distinct"
            )

        assets_raw = payload.get("assets")
        if not isinstance(assets_raw, list) or len(assets_raw) != len(ASSET_ROLES):
            raise MaintenanceError(
                "assets-invalid", "exactly five assets must be declared"
            )
        assets = {}
        for item in assets_raw:
            if not isinstance(item, dict):
                raise MaintenanceError("assets-invalid", "asset entries must be mappings")
            role = item.get("role")
            if not isinstance(role, str) or role not in ASSET_ROLES:
                raise MaintenanceError("unsupported-role", f"unsupported role {role!r}")
            if role in assets:
                raise MaintenanceError("assets-invalid", f"duplicate role {role}")
            length = _require_positive_int(item.get("bytes"), f"{role} bytes")
            digest = item.get("sha256")
            if not isinstance(digest, str):
                raise MaintenanceError("assets-invalid", f"{role} digest is missing")
            assets[role] = {
                "role": role,
                "bytes": length,
                "sha256": _normalize_digest(digest, f"{role} digest"),
            }
        if set(assets) != set(ASSET_ROLES):
            raise MaintenanceError("assets-invalid", "all five asset roles are required")

        canonical = _canonical_sha({
            "transactionId": transaction_id,
            "expected": expected,
            "ownership": ownership,
            "assets": [assets[role] for role in ASSET_ROLES],
        })
        return {
            "transactionId": transaction_id,
            "expected": expected,
            "ownership": ownership,
            "assets": assets,
            "canonical": canonical,
        }

    def _load_validator(self):
        if self.restore_validator is not None:
            return self.restore_validator
        for name in ("avb_stock", "maintenance.avb_stock"):
            try:
                module = importlib.import_module(name)
            except ImportError:
                continue
            validator = getattr(module, "validate_restore_candidate", None)
            if callable(validator):
                return validator
        raise MaintenanceError(
            "validator-unavailable", "no stock restore validator is available"
        )

    @staticmethod
    def _evidence_field(evidence: object, name: str):
        if isinstance(evidence, dict):
            return evidence.get(name)
        return getattr(evidence, name, None)

    def _slot_evidence(self, slot: str, evidence: object,
                       expected_sha: str) -> dict:
        if evidence is None:
            raise MaintenanceError("stock-invalid", "validator returned no evidence")
        reported_slot = self._evidence_field(evidence, "slot")
        if reported_slot is not None and reported_slot != slot:
            raise MaintenanceError("stock-invalid", "validator returned the wrong slot")
        digest = self._evidence_field(evidence, "stock_sha256")
        if not isinstance(digest, str):
            raise MaintenanceError("stock-invalid", "validator did not bind the stock digest")
        digest = _normalize_digest(digest, "evidence stock digest")
        if not hmac.compare_digest(digest, expected_sha):
            raise MaintenanceError(
                "stock-invalid", "validator stock digest does not match the upload"
            )
        fingerprint = self._evidence_field(evidence, "fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise MaintenanceError("stock-invalid", "validator returned no fingerprint")
        root_key = self._evidence_field(evidence, "root_key_sha256")
        chain_key = self._evidence_field(evidence, "chain_key_sha256")
        if not isinstance(root_key, str) or not isinstance(chain_key, str):
            raise MaintenanceError("stock-invalid", "validator omitted key digests")
        root_key = _normalize_digest(root_key, "root key digest")
        chain_key = _normalize_digest(chain_key, "chain key digest")
        rollback = self._evidence_field(evidence, "hardware_rollback_verified")
        if rollback is not False:
            raise MaintenanceError(
                "stock-invalid", "hardware rollback verification is not supported"
            )
        proof = self._evidence_field(evidence, "proof")
        if not isinstance(proof, str) or not proof:
            raise MaintenanceError("stock-invalid", "validator returned no proof")
        result = {
            "slot": slot,
            "sha256": digest,
            "fingerprint": fingerprint,
            "rootKeySha256": root_key,
            "bootKeySha256": chain_key,
            "hardwareRollbackVerified": False,
            "proof": proof,
        }
        for source, target in (
            ("os_version", "osVersion"),
            ("security_patch", "securityPatch"),
            ("boot_rollback_index", "bootRollbackIndex"),
            ("boot_rollback_index_location", "bootRollbackIndexLocation"),
            ("slot_vbmeta_rollback_index", "slotVbmetaRollbackIndex"),
            ("slot_vbmeta_rollback_index_location",
             "slotVbmetaRollbackIndexLocation"),
        ):
            value = self._evidence_field(evidence, source)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                result[target] = value
        return result

    def _validate_stock(self, record: dict, capture: RuntimeCapture) -> dict:
        validator = self._load_validator()
        model = record["expected"]["model"]
        baseline_meta = record["assets"]["trusted_vbmeta_baseline"]
        baseline = self._read_verified(
            self._asset_path("trusted_vbmeta_baseline"),
            baseline_meta["bytes"], baseline_meta["sha256"], "vbmeta baseline",
        )
        evidence = {}
        for slot in ("a", "b"):
            role = f"stock_boot_{slot}"
            meta = record["assets"][role]
            partition_size = capture.snapshot["bootSlots"][slot]["bytes"]
            if meta["bytes"] != partition_size:
                raise MaintenanceError(
                    "stock-size-mismatch",
                    f"slot {slot} stock image does not fill its partition",
                )
            candidate_fd = self._open_verified(
                self._asset_path(role), meta["bytes"], meta["sha256"],
                f"stock slot {slot}",
            )
            backup = capture.backups[f"boot_{slot}"]
            backup_meta = capture.snapshot["bootSlots"][slot]
            try:
                current_fd = self._open_verified(
                    backup, backup_meta["bytes"], backup_meta["sha256"],
                    f"backup slot {slot}",
                )
            except BaseException:
                os.close(candidate_fd)
                raise
            candidate = os.fdopen(candidate_fd, "rb")
            current = os.fdopen(current_fd, "rb")
            try:
                try:
                    result = validator(
                        candidate, current, capture.slot_vbmeta[slot], baseline,
                        slot, model, partition_size,
                    )
                except MaintenanceError as exc:
                    raise MaintenanceError(
                        "stock-validation-failed", str(exc)
                    ) from exc
                except Exception as exc:
                    raise MaintenanceError(
                        "stock-validation-failed", f"slot {slot} rejected"
                    ) from exc
            finally:
                candidate.close()
                current.close()
            evidence[slot] = self._slot_evidence(
                slot, result, meta["sha256"]
            )
        return evidence

    def _validate_plan(self, plan: object, gpt: GptDisk) -> None:
        if not isinstance(plan, GptRestorePlan):
            raise MaintenanceError("plan-invalid", "a restore plan is required")
        if len(plan.write_regions) != 4:
            raise MaintenanceError("plan-invalid", "the plan must have four regions")
        sector = gpt.sector_size
        for region in plan.write_regions:
            if region.offset < sector or region.offset + len(region.data) > gpt.disk_size_bytes:
                raise MaintenanceError("plan-invalid", "plan region leaves the disk")
        if len(plan.removed_partition_numbers) != 2:
            raise MaintenanceError("plan-invalid", "exactly two slots must be removed")
        userdata = {entry.name: entry for entry in gpt.entries}.get("userdata")
        if userdata is None:
            raise MaintenanceError("plan-invalid", "current GPT has no userdata")
        if plan.userdata_start_lba != userdata.first_lba:
            raise MaintenanceError("plan-invalid", "plan userdata start drifted")
        if plan.userdata_end_lba_exclusive > gpt.last_usable_lba + 1:
            raise MaintenanceError("plan-invalid", "plan userdata end leaves the disk")

    def prepare(self, payload: dict) -> dict:
        parsed = self._parse_prepare(payload)
        transaction_id = parsed["transactionId"]

        with self._lock:
            if transaction_id in self._saved:
                raise MaintenanceError(
                    "transaction-readonly",
                    "saved transactions cannot resume",
                    409,
                )
            if self._tx is not None:
                if (self._tx["id"] != transaction_id
                        or self._tx["canonical"] != parsed["canonical"]):
                    raise MaintenanceError(
                        "transaction-conflict",
                        "a different transaction is already prepared",
                    )
                return copy.deepcopy(self._tx["status"])

        capture = self._ensure_capture()
        self.platform.assert_ready(dict(parsed["expected"]))
        for key in _IDENTITY_KEYS:
            if capture.snapshot.get(key) != parsed["expected"][key]:
                raise MaintenanceError(
                    f"{key}-mismatch", f"{key} changed during prepare"
                )
        if capture.gpt.fingerprint != parsed["expected"]["tableFingerprint"]:
            raise MaintenanceError("table-changed", "capture GPT fingerprint changed")

        assets = {}
        for role in ASSET_ROLES:
            declared = parsed["assets"][role]
            stored = self._asset_meta.get(role)
            if (not stored or stored["bytes"] != declared["bytes"]
                    or not hmac.compare_digest(stored["sha256"], declared["sha256"])):
                raise MaintenanceError(
                    "assets-invalid", f"declared asset {role} was not uploaded"
                )
            self._verify_file(self._asset_path(role), declared["bytes"],
                              declared["sha256"], f"asset {role}")
            assets[role] = dict(declared)

        backup_entries = self._backup_snapshot(capture)
        for entry in backup_entries:
            self._verify_file(capture.backups[entry["role"]], entry["bytes"],
                              entry["sha256"], f"backup {entry['role']}")

        primary = self._read_verified(
            self._asset_path("original_primary_gpt"),
            assets["original_primary_gpt"]["bytes"],
            assets["original_primary_gpt"]["sha256"], "original primary GPT",
        )
        backup = self._read_verified(
            self._asset_path("original_backup_gpt"),
            assets["original_backup_gpt"]["bytes"],
            assets["original_backup_gpt"]["sha256"], "original backup GPT",
        )
        try:
            original = read_gpt(
                _GptImageReader(primary, backup, parsed["expected"]["diskBytes"]),
                parsed["expected"]["sectorSize"],
                parsed["expected"]["diskBytes"],
            )
        except (GptError, ValueError) as exc:
            raise MaintenanceError("gpt-asset-invalid", str(exc)) from exc

        ownership = parsed["ownership"]
        try:
            plan = plan_restore(
                capture.gpt, original,
                ownership["userdataPartUuid"],
                ownership["linuxBootPartUuid"],
                ownership["linuxRootPartUuid"],
            )
        except GptError as exc:
            raise MaintenanceError("plan-invalid", str(exc)) from exc
        self._validate_plan(plan, capture.gpt)

        record = {
            "id": transaction_id,
            "canonical": parsed["canonical"],
            "expected": parsed["expected"],
            "ownership": ownership,
            "assets": assets,
            "capture": capture,
            "plan": plan,
            "backupEntries": backup_entries,
            "ack": None,
            "phase": {
                "tableFingerprint": parsed["expected"]["tableFingerprint"],
                "bootSha256": {
                    slot: capture.snapshot["bootSlots"][slot]["sha256"]
                    for slot in ("a", "b")
                },
                "vbmetaSha256": {
                    slot: capture.snapshot["bootSlots"][slot]["vbmetaSha256"]
                    for slot in ("a", "b")
                },
                "miscSha256": capture.snapshot["misc"]["sha256"],
            },
        }
        evidence = self._validate_stock(record, capture)

        plan_signature = {
            "geometry": {
                "diskBytes": parsed["expected"]["diskBytes"],
                "sectorSize": parsed["expected"]["sectorSize"],
                "tableFingerprint": parsed["expected"]["tableFingerprint"],
            },
            "regions": [
                {
                    "offset": region.offset,
                    "bytes": len(region.data),
                    "sha256": hashlib.sha256(region.data).hexdigest(),
                }
                for region in plan.write_regions
            ],
            "userdataStartSector": plan.userdata_start_lba,
            "userdataEndSectorExclusive": plan.userdata_end_lba_exclusive,
            "removedPartitionNumbers": list(plan.removed_partition_numbers),
        }
        input_signature = {
            "identity": parsed["expected"],
            "ownership": ownership,
            "assets": [assets[role] for role in ASSET_ROLES],
            "slotEvidence": evidence,
        }
        plan_fingerprint = _canonical_sha({
            "plan": plan_signature, "input": input_signature,
        })
        stock_fingerprint = _canonical_sha({
            "slotEvidence": evidence,
            "assets": [assets[role] for role in ASSET_ROLES],
            "model": parsed["expected"]["model"],
        })

        status = {
            "schemaVersion": SCHEMA_VERSION,
            "transactionId": transaction_id,
            "bootId": parsed["expected"]["bootId"],
            "state": "prepared",
            "stage": "Prepared",
            "nextStep": RESTORE_STEPS[0],
            "activeStep": None,
            "completedSteps": [],
            "planFingerprint": plan_fingerprint,
            "stockFingerprint": stock_fingerprint,
            "slotEvidence": evidence,
            "backupAcknowledged": False,
            "confirmationToken": secrets.token_hex(32),
            "bothStockBootsValid": True,
            "restoredAndroidBytes": plan.restored_userdata_bytes,
            "userdataStartSector": plan.userdata_start_lba,
            "userdataEndSectorExclusive": plan.userdata_end_lba_exclusive,
            "removedPartitionNumbers": list(plan.removed_partition_numbers),
            "error": None,
        }
        record["status"] = status
        with self._lock:
            if self._tx is not None:
                if (self._tx["id"] == transaction_id
                        and self._tx["canonical"] == parsed["canonical"]):
                    return copy.deepcopy(self._tx["status"])
                raise MaintenanceError(
                    "transaction-conflict", "a transaction appeared during prepare"
                )
            self._persist(record)
            self._tx = record
        return copy.deepcopy(status)

    # -- acknowledgement --------------------------------------------------
    def ack_backups(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise MaintenanceError("payload-invalid", "ack payload must be a mapping")
        transaction_id = _tx_uuid(payload.get("transactionId"))
        with self._lock:
            record = self._tx
            if record is None or record["id"] != transaction_id:
                raise MaintenanceError("transaction-unknown", "unknown transaction", 404)
            if payload.get("bootId") != record["status"]["bootId"]:
                raise MaintenanceError("boot-id-mismatch", "bootId changed")
            if payload.get("socSerial") != record["expected"]["socSerial"]:
                raise MaintenanceError("soc-serial-mismatch", "socSerial changed")
            if record["status"]["state"] != "prepared":
                raise MaintenanceError(
                    "transaction-state",
                    "backups can only be acknowledged while prepared",
                    409,
                )
            self._phase_assert(record)

            declared = payload.get("backups")
            if not isinstance(declared, list) or len(declared) != 3:
                raise MaintenanceError(
                    "backup-invalid", "exactly three backups must be acknowledged"
                )
            parsed = []
            for item in declared:
                if not isinstance(item, dict):
                    raise MaintenanceError("backup-invalid", "backup entries must be mappings")
                role = item.get("role")
                if role not in _BACKUP_ROLES:
                    raise MaintenanceError("backup-invalid", f"unexpected role {role!r}")
                length = _require_positive_int(item.get("bytes"), f"{role} bytes")
                digest = item.get("sha256")
                if not isinstance(digest, str):
                    raise MaintenanceError("backup-invalid", f"{role} digest is missing")
                parsed.append({
                    "role": role,
                    "bytes": length,
                    "sha256": _normalize_digest(digest, f"{role} digest"),
                })
            if {item["role"] for item in parsed} != set(_BACKUP_ROLES):
                raise MaintenanceError("backup-invalid", "backup roles must be unique")
            by_role = {item["role"]: item for item in parsed}
            for expected in record["backupEntries"]:
                item = by_role[expected["role"]]
                if (item["bytes"] != expected["bytes"]
                        or not hmac.compare_digest(item["sha256"], expected["sha256"])):
                    raise MaintenanceError(
                        "backup-mismatch", f"backup {expected['role']} differs"
                    )
                self._verify_file(
                    record["capture"].backups[expected["role"]],
                    expected["bytes"], expected["sha256"],
                    f"backup {expected['role']}",
                )
            if record["ack"] is None:
                record["ack"] = {
                    "acknowledged": True,
                    "backupAckId": secrets.token_hex(32),
                }
                record["status"]["backupAcknowledged"] = True
                self._persist(record)
            return copy.deepcopy(record["ack"])

    # -- steps ------------------------------------------------------------
    @staticmethod
    def _identity(record: dict) -> dict:
        return {key: record["expected"][key] for key in _BASELINE_IDENTITY_KEYS}

    def _phase_assert(self, record: dict) -> None:
        expected = self._identity(record)
        phase = record["phase"]
        expected["tableFingerprint"] = phase["tableFingerprint"]
        expected["bootSha256"] = dict(phase["bootSha256"])
        expected["vbmetaSha256"] = dict(phase["vbmetaSha256"])
        expected["miscSha256"] = phase["miscSha256"]
        self.platform.assert_ready(expected)

    def _predicted_misc_digest(self, record: dict) -> str:
        misc = record["capture"].snapshot["misc"]
        data = self._read_verified(
            record["capture"].backups["misc"], misc["bytes"], misc["sha256"],
            "backup misc",
        )
        try:
            bcb = make_factory_reset_bcb(data[:_BCB_SIZE])
        except GptError as exc:
            raise MaintenanceError("bcb-invalid", str(exc)) from exc
        updated = bytearray(data)
        updated[:_BCB_SIZE] = bcb
        return hashlib.sha256(bytes(updated)).hexdigest()

    def _run_step(self, record: dict, step: str) -> None:
        try:
            self._rehash_assets(record)
            self._verify_backups(record)
            if record["ack"] is None:
                raise MaintenanceError(
                    "backup-not-acknowledged", "backups were not acknowledged"
                )
            self._phase_assert(record)

            if step == "restore-boot-a":
                self._restore(record, "a")
            elif step == "verify-boot-a":
                self._verify_boot(record, "a")
            elif step == "restore-boot-b":
                self._restore(record, "b")
            elif step == "verify-boot-b":
                self._verify_boot(record, "b")
            elif step == "reclaim-space":
                self._reclaim(record)
            elif step == "queue-factory-reset":
                self._queue_reset(record)
            else:
                raise MaintenanceError("unknown-step", f"unknown step {step!r}")
        except BaseException as exc:
            self._finish_failure(record, step, exc)
            return
        try:
            self._finish_success(record, step)
        except BaseException as exc:
            self._finish_failure(record, step, exc)

    def _restore(self, record: dict, slot: str) -> None:
        role = f"stock_boot_{slot}"
        stock = record["assets"][role]["sha256"]
        current = record["phase"]["bootSha256"][slot]
        result = self.platform.restore_boot(
            slot, self._asset_path(role), current, stock
        )
        if result != stock:
            raise MaintenanceError(
                "restore-verify-failed", f"slot {slot} did not report the stock digest"
            )
        record["phase"]["bootSha256"][slot] = stock

    def _verify_boot(self, record: dict, slot: str) -> None:
        stock = record["assets"][f"stock_boot_{slot}"]["sha256"]
        self.platform.verify_boot(slot, stock)

    def _reclaim(self, record: dict) -> None:
        previous = record["phase"]["tableFingerprint"]
        result = self.platform.reclaim_space(record["plan"], previous)
        if not isinstance(result, str) or len(result) != 64:
            raise MaintenanceError("reclaim-verify-failed", "no new table fingerprint")
        if hmac.compare_digest(result, previous):
            raise MaintenanceError("reclaim-verify-failed", "table did not change")
        facts = self.platform.current_state()
        if facts.get("tableFingerprint") != result:
            raise MaintenanceError(
                "reclaim-verify-failed", "fresh table fingerprint differs"
            )
        record["phase"]["tableFingerprint"] = result

    def _queue_reset(self, record: dict) -> None:
        expected = record["phase"]["miscSha256"]
        predicted = self._predicted_misc_digest(record)
        result = self.platform.queue_factory_reset(expected)
        if result != predicted:
            raise MaintenanceError(
                "bcb-verify-failed", "misc digest did not match the queued BCB"
            )
        record["phase"]["miscSha256"] = predicted

    def _finish_success(self, record: dict, step: str) -> None:
        with self._lock:
            status = record["status"]
            if step == status["nextStep"]:
                status["completedSteps"].append(step)
            index = RESTORE_STEPS.index(step)
            if index == len(RESTORE_STEPS) - 1:
                status["state"] = "awaitingFactoryReset"
                status["stage"] = "AwaitingFactoryReset"
                status["nextStep"] = None
            else:
                status["state"] = "prepared"
                status["stage"] = "Prepared"
                status["nextStep"] = RESTORE_STEPS[index + 1]
            status["activeStep"] = None
            status["error"] = None
            self._persist(record)

    def _finish_failure(self, record: dict, step: str,
                        error: BaseException) -> None:
        with self._lock:
            status = record["status"]
            status["state"] = "failed"
            status["stage"] = "Failed"
            status["activeStep"] = None
            status["error"] = {
                "code": getattr(error, "code", "step-failed"),
                "message": str(error) or "step failed",
                "stage": step,
            }
            self._persist(record)

    def step(self, transaction_id: str, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise MaintenanceError("payload-invalid", "step payload must be a mapping")
        transaction_id = _tx_uuid(transaction_id)
        step = payload.get("step")
        if not isinstance(step, str) or step not in RESTORE_STEPS:
            raise MaintenanceError("unknown-step", f"unknown step {step!r}")
        if payload.get("wipeConfirmed") is not True:
            raise MaintenanceError("wipe-not-confirmed", "wipe must be confirmed")
        boot_id = payload.get("bootId")
        token = payload.get("confirmationToken")
        if not isinstance(boot_id, str) or not isinstance(token, str):
            raise MaintenanceError("step-invalid", "bootId and token are required")

        with self._lock:
            record = self._tx
            if record is None or record["id"] != transaction_id:
                raise MaintenanceError("transaction-unknown", "unknown transaction", 404)
            status = record["status"]
            if status["state"] == "failed":
                raise MaintenanceError(
                    "transaction-failed", "a failed transaction cannot be resumed"
                )
            if not hmac.compare_digest(boot_id, record["expected"]["bootId"]):
                raise MaintenanceError("boot-id-mismatch", "bootId changed")
            if not hmac.compare_digest(token, status["confirmationToken"]):
                raise MaintenanceError("confirmation-invalid", "confirmation token rejected")

            if status["state"] == "running":
                if status["activeStep"] == step:
                    return copy.deepcopy(status)
                raise MaintenanceError(
                    "step-in-progress", "a different step is already running"
                )
            if step in status["completedSteps"]:
                return copy.deepcopy(status)
            if status["state"] == "awaitingFactoryReset":
                raise MaintenanceError(
                    "transaction-complete", "the transaction is already complete"
                )
            if step != status["nextStep"]:
                raise MaintenanceError(
                    "step-order", f"the next step is {status['nextStep']!r}"
                )
            if not status["backupAcknowledged"]:
                raise MaintenanceError(
                    "backup-not-acknowledged", "backups must be acknowledged first"
                )

        facts = self.platform.current_state()
        for key in _BASELINE_IDENTITY_KEYS:
            if facts.get(key) != record["expected"][key]:
                raise MaintenanceError(
                    f"{key}-mismatch", f"{key} changed since prepare"
                )

        with self._lock:
            status = record["status"]
            if status["state"] == "running" and status["activeStep"] == step:
                return copy.deepcopy(status)
            if step in status["completedSteps"]:
                return copy.deepcopy(status)
            if status["state"] != "prepared" or status["nextStep"] != step:
                raise MaintenanceError("step-conflict", "transaction state changed")
            status["state"] = "running"
            status["stage"] = "Running"
            status["activeStep"] = step
            self._persist(record)
            worker = threading.Thread(
                target=self._run_step, args=(record, step),
                name=f"maintenance-{step}", daemon=False,
            )
            self._worker = worker
            worker.start()
            return copy.deepcopy(status)

    def status(self, transaction_id: str) -> dict:
        transaction_id = _tx_uuid(transaction_id)
        with self._lock:
            if self._tx is not None and self._tx["id"] == transaction_id:
                return copy.deepcopy(self._tx["status"])
            saved = self._saved.get(transaction_id)
            if saved is not None:
                return copy.deepcopy(saved)
        raise MaintenanceError("transaction-unknown", "unknown transaction", 404)

    def wait_idle(self, timeout: float = 5) -> bool:
        with self._lock:
            worker = self._worker
        if worker is None:
            return True
        if threading.current_thread() is worker:
            return False
        worker.join(timeout)
        return not worker.is_alive()


# ---------------------------------------------------------------------------
# HTTP/CLI entry points
# ---------------------------------------------------------------------------

_FIXED_BIND = "192.168.77.1"
_FIXED_PORT = 8202
_JSON_MAX_BYTES = 1 << 20
_GPT_ASSET_MAX_BYTES = 16 << 20
_BASELINE_MAX_BYTES = 1 << 20
_STREAM_CHUNK = 1 << 20
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_HTTP_BACKUP_ROLES = ("a", "b", "misc")


def load_session_token(token_file: Path) -> str:
    """Read the API session token from ``token_file``.

    The file must be a regular, non-symlink, mode-0600 file that holds
    exactly 64 ASCII hex characters plus at most one trailing LF or CRLF.
    The exact spelling is preserved and the value is never logged or echoed.
    """
    try:
        fd = os.open(str(token_file),
                     os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise MaintenanceError(
            "token-unreadable", "session token file cannot be opened"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise MaintenanceError(
                "token-invalid", "session token file is not a regular file"
            )
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise MaintenanceError(
                "token-invalid", "session token file must be mode 0600"
            )
        raw = os.read(fd, 67)
    except OSError as exc:
        raise MaintenanceError(
            "token-unreadable", "session token file cannot be read"
        ) from exc
    finally:
        os.close(fd)

    if raw.endswith(b"\r\n"):
        body = raw[:-2]
    elif raw.endswith(b"\n"):
        body = raw[:-1]
    else:
        body = raw
    if len(body) != 64:
        raise MaintenanceError("token-invalid", "session token file is invalid")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MaintenanceError(
            "token-invalid", "session token file is invalid"
        ) from exc
    if any(character not in _HEX_DIGITS for character in text):
        raise MaintenanceError("token-invalid", "session token file is invalid")
    return text


class _BodyReader:
    """Bounded reader that never consumes past the declared request length."""

    __slots__ = ("_stream", "_remaining")

    def __init__(self, stream, length: int) -> None:
        self._stream = stream
        self._remaining = length

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size is None or size < 0:
            size = self._remaining
        wanted = min(size, self._remaining)
        if wanted <= 0:
            return b""
        chunk = self._stream.read(wanted)
        if not chunk:
            raise MaintenanceError(
                "short-read", "request body ended early", 400
            )
        data = bytes(chunk)
        if len(data) > wanted:
            raise MaintenanceError(
                "short-read", "request body exceeded its length", 400
            )
        self._remaining -= len(data)
        return data


def make_http_handler(runtime, session_token: str) -> type:
    """Return the ``BaseHTTPRequestHandler`` subclass serving ``runtime``."""

    expected_auth = ("Bearer " + session_token).encode("ascii")

    class _MaintenanceHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "armada-maintenance"
        sys_version = ""

        def log_message(self, format, *args):
            return

        def handle_one_request(self):
            try:
                super().handle_one_request()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def do_GET(self):
            self._handle("GET")

        def do_PUT(self):
            self._handle("PUT")

        def do_POST(self):
            self._handle("POST")

        def do_HEAD(self):
            self._handle("HEAD")

        def do_DELETE(self):
            self._handle("DELETE")

        def do_PATCH(self):
            self._handle("PATCH")

        def do_OPTIONS(self):
            self._handle("OPTIONS")

        # -- response helpers -------------------------------------------
        def _sanitize(self, text: str) -> str:
            if session_token:
                return text.replace(session_token, "***")
            return text

        def _send_json(self, status: int, document: dict) -> None:
            body = json.dumps(document, ensure_ascii=False).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _send_maintenance_error(self, error: MaintenanceError) -> None:
            status = getattr(error, "http_status", 500)
            if not isinstance(status, int) or not 400 <= status <= 599:
                status = 500
            document = {
                "error": {
                    "code": str(error.code),
                    "message": self._sanitize(str(error) or "request rejected"),
                }
            }
            stage = getattr(error, "stage", None)
            if isinstance(stage, str) and stage:
                document["error"]["stage"] = stage
            self._send_json(status, document)

        def send_error(self, code, message=None, explain=None):
            status = code if isinstance(code, int) and 400 <= code <= 599 else 400
            try:
                self._send_json(status, {
                    "error": {
                        "code": "http-error",
                        "message": "invalid HTTP request",
                    }
                })
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        # -- request plumbing -------------------------------------------
        def _handle(self, method: str) -> None:
            self.close_connection = True
            try:
                if method not in ("GET", "PUT", "POST"):
                    self._send_json(405, {
                        "error": {
                            "code": "method-not-allowed",
                            "message": "method not allowed",
                        }
                    })
                    return
                supplied = self.headers.get("Authorization", "")
                supplied_bytes = supplied.encode("latin-1", "replace")
                if not hmac.compare_digest(supplied_bytes, expected_auth):
                    self._send_json(401, {
                        "error": {
                            "code": "unauthorized",
                            "message": "authentication required",
                        }
                    })
                    return
                try:
                    if method == "GET":
                        self._do_get()
                    elif method == "PUT":
                        self._do_put()
                    else:
                        self._do_post()
                except MaintenanceError as error:
                    self._send_maintenance_error(error)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except Exception:
                    self._send_json(500, {
                        "error": {
                            "code": "internal-error",
                            "message": "internal error",
                        }
                    })
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def _path_parts(self):
            return urllib.parse.urlsplit(self.path).path.split("/")

        def _content_length(self) -> int:
            if self.headers.get("Transfer-Encoding") is not None:
                raise MaintenanceError(
                    "length-invalid", "Transfer-Encoding is not supported", 400
                )
            values = self.headers.get_all("Content-Length")
            if not values:
                raise MaintenanceError(
                    "length-required", "Content-Length is required", 411
                )
            if len(values) != 1:
                raise MaintenanceError(
                    "length-invalid", "exactly one Content-Length is required", 400
                )
            value = values[0]
            if (not value or not value.isascii() or not value.isdigit()
                    or len(value) > 20):
                raise MaintenanceError(
                    "length-invalid", "Content-Length is invalid", 400
                )
            return int(value, 10)

        def _read_body(self, length: int) -> bytes:
            chunks = []
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, _STREAM_CHUNK))
                if not chunk:
                    raise MaintenanceError(
                        "body-invalid", "request body ended early", 400
                    )
                data = bytes(chunk)
                chunks.append(data)
                remaining -= len(data)
            return b"".join(chunks)

        def _read_json_object(self) -> dict:
            length = self._content_length()
            if length > _JSON_MAX_BYTES:
                raise MaintenanceError(
                    "body-too-large", "request body exceeds 1 MiB", 413
                )
            raw = self._read_body(length)
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise MaintenanceError(
                    "body-invalid", "request body is not valid JSON", 400
                ) from exc
            if not isinstance(document, dict):
                raise MaintenanceError(
                    "body-invalid", "request body must be a JSON object", 400
                )
            return document

        def _asset_limit(self, role: str) -> int:
            if role in ("original_primary_gpt", "original_backup_gpt"):
                return _GPT_ASSET_MAX_BYTES
            if role == "trusted_vbmeta_baseline":
                return _BASELINE_MAX_BYTES
            document = runtime.inspect()
            try:
                return int(document["bootSlots"][role[-1]]["bytes"])
            except (KeyError, TypeError, ValueError) as exc:
                raise MaintenanceError(
                    "state-invalid", "boot slot size is unavailable", 500
                ) from exc

        # -- routes ------------------------------------------------------
        def _do_get(self) -> None:
            parts = self._path_parts()
            if parts == ["", "v1", "inspect"]:
                self._send_json(200, runtime.inspect())
                return
            if (len(parts) == 4 and parts[1] == "v1" and parts[2] == "boot"
                    and parts[3] in _HTTP_BACKUP_ROLES):
                self._send_backup(parts[3])
                return
            if (len(parts) == 5 and parts[1] == "v1"
                    and parts[2] == "transactions" and parts[3]
                    and parts[4] == "status"):
                self._send_json(200, runtime.status(parts[3]))
                return
            self._not_found()

        def _send_backup(self, role: str) -> None:
            path, meta = runtime.backup_file(role)
            try:
                fd = os.open(str(path),
                             os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except OSError as exc:
                raise MaintenanceError(
                    "file-unavailable", "backup file cannot be opened", 500
                ) from exc
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise MaintenanceError(
                        "file-invalid", "backup is not a regular file", 500
                    )
                length = meta.get("bytes")
                digest = meta.get("sha256")
                if (not isinstance(length, int) or isinstance(length, bool)
                        or length <= 0 or info.st_size != length
                        or not isinstance(digest, str)):
                    raise MaintenanceError(
                        "file-changed", "backup length changed", 500
                    )
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(length))
                self.send_header("X-Content-SHA256", digest)
                self.send_header("Connection", "close")
                self.end_headers()
                sent = 0
                while sent < length:
                    chunk = os.read(fd, min(_STREAM_CHUNK, length - sent))
                    if not chunk:
                        raise MaintenanceError(
                            "file-changed", "backup ended early", 500
                        )
                    self.wfile.write(chunk)
                    sent += len(chunk)
            finally:
                os.close(fd)

        def _do_put(self) -> None:
            parts = self._path_parts()
            if (len(parts) != 4 or parts[1] != "v1" or parts[2] != "assets"
                    or parts[3] not in ASSET_ROLES):
                self._not_found()
                return
            role = parts[3]
            length = self._content_length()
            if length > self._asset_limit(role):
                raise MaintenanceError(
                    "asset-too-large", "upload exceeds its role limit", 413
                )
            reader = _BodyReader(self.rfile, length)
            self._send_json(200, runtime.put_asset(role, reader, length))

        def _do_post(self) -> None:
            parts = self._path_parts()
            if parts == ["", "v1", "prepare"]:
                self._send_json(200, runtime.prepare(self._read_json_object()))
                return
            if parts == ["", "v1", "ack-backups"]:
                self._send_json(200, runtime.ack_backups(self._read_json_object()))
                return
            if (len(parts) == 5 and parts[1] == "v1"
                    and parts[2] == "transactions" and parts[3]
                    and parts[4] == "step"):
                payload = self._read_json_object()
                self._send_json(202, runtime.step(parts[3], payload))
                return
            self._not_found()

        def _not_found(self) -> None:
            raise MaintenanceError("not-found", "unknown path", 404)

    return _MaintenanceHandler


def serve_runtime(runtime, session_token: str,
                  bind: str = _FIXED_BIND, port: int = _FIXED_PORT) -> None:
    """Serve the API on the fixed USB address until the process is stopped."""
    if bind != _FIXED_BIND or port != _FIXED_PORT:
        raise MaintenanceError(
            "bind-invalid", "the API is bound to its fixed address", 400
        )
    handler = make_http_handler(runtime, session_token)
    server = ThreadingHTTPServer((bind, port), handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv=None) -> int:
    """CLI entry point: serve the API or print one read-only inspection."""
    parser = argparse.ArgumentParser(prog="armada_uninstall")
    commands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = commands.add_parser("inspect")
    inspect_parser.add_argument("--state-dir", required=True, type=Path)

    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--state-dir", required=True, type=Path)
    serve_parser.add_argument("--token-file", required=True, type=Path)
    serve_parser.add_argument("--bind", default=_FIXED_BIND)
    serve_parser.add_argument("--port", default=_FIXED_PORT, type=int)

    arguments = parser.parse_args(argv)

    if arguments.command == "serve":
        if arguments.bind != _FIXED_BIND or arguments.port != _FIXED_PORT:
            print("the API can only bind to its fixed address", file=sys.stderr)
            return 2
        try:
            token = load_session_token(arguments.token_file)
        except MaintenanceError:
            print("the session token file was rejected", file=sys.stderr)
            return 2

    try:
        backend = LinuxBlockBackend(Path(arguments.state_dir))
        runtime = MaintenanceRuntime(backend, Path(arguments.state_dir))
    except MaintenanceError:
        print("maintenance startup was rejected", file=sys.stderr)
        return 2

    if arguments.command == "inspect":
        print(json.dumps(runtime.inspect(), ensure_ascii=False, indent=2))
        return 0

    serve_runtime(runtime, token, bind=_FIXED_BIND, port=_FIXED_PORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
