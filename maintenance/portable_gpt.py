"""Portable, dependency-free GPT / BCB planning helpers.

Pure stdlib helpers over caller-supplied data:

* :func:`read_gpt` validates the primary and backup GPT with bounded
  ``seek``/``read`` calls and returns the raw regions plus parsed entries.
* :func:`plan_restore` validates a parsed current/original GPT pair and
  returns the byte-exact GPT regions that restore the original userdata
  extent while removing the ArmadaOS boot and root partitions.
* :func:`make_factory_reset_bcb` queues a one-shot factory-reset request in
  an existing 2048-byte BCB buffer.

The helpers are side-effect free and operate only on caller-supplied data.
No device, sysfs, process, socket or filesystem access is performed here.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
import zlib
from dataclasses import dataclass
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
    board_backup_uuid: str | None = None,
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

    When ``board_backup_uuid`` is supplied, the current GPT must also hold
    exactly one ``ARMADA_BACKUP`` Linux filesystem partition with that
    UUID: exactly 2 GiB, contiguous after root, ending at the original
    userdata end. That slot is preserved byte-for-byte and never deleted,
    and the restored userdata then ends at root's end instead of the
    original userdata end.
    """

    if not isinstance(current, GptDisk) or not isinstance(original, GptDisk):
        raise GptError("plan_restore requires parsed GptDisk inputs")

    userdata_uuid = _uuid_text(userdata_uuid, "userdata_uuid")
    boot_uuid = _uuid_text(boot_uuid, "boot_uuid")
    root_uuid = _uuid_text(root_uuid, "root_uuid")
    if board_backup_uuid is not None:
        board_backup_uuid = _uuid_text(
            board_backup_uuid, "board_backup_uuid"
        )
    if len({userdata_uuid, boot_uuid, root_uuid}) != 3:
        raise GptError("userdata, boot and root UUIDs must be distinct")
    if board_backup_uuid is not None and board_backup_uuid in (
        userdata_uuid, boot_uuid, root_uuid
    ):
        raise GptError(
            "board_backup_uuid must differ from the other owned UUIDs"
        )

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

    backup = None
    if board_backup_uuid is not None:
        if sum(1 for entry in current.entries
               if entry.name == "ARMADA_BACKUP") != 1:
            raise GptError(
                "current GPT must have exactly one ARMADA_BACKUP partition"
            )
        backup = _one_entry(
            current.entries, board_backup_uuid, "current backup"
        )
        if backup.name != "ARMADA_BACKUP":
            raise GptError("current backup partition has the wrong name")
        if backup.type_guid.upper() != _LINUX_FS_TYPE_GUID:
            raise GptError(
                "current backup partition is not a Linux filesystem"
            )
        if not 1 <= backup.number <= current.entry_count:
            raise GptError("current owned partition number is out of range")
        if backup.number in (boot.number, root.number):
            raise GptError(
                "current backup slot must differ from boot and root"
            )

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
    if original_userdata.last_lba != original.last_usable_lba:
        raise GptError("original userdata does not cover the full factory tail")

    for entry in original.entries:
        rejected_uuids = (boot_uuid, root_uuid) if backup is None else (
            boot_uuid, root_uuid, board_backup_uuid
        )
        if entry.part_uuid.upper() in rejected_uuids:
            raise GptError("original GPT still has an ArmadaOS partition UUID")
        if entry.name in ("ARMADA_BOOT", "ARMADA_ROOT"):
            raise GptError("original GPT still has an ArmadaOS partition label")
        if entry.name.upper().startswith("ARMADA_"):
            raise GptError("original GPT still has an ArmadaOS partition label")

    original_by_number = {entry.number: entry for entry in original.entries}
    preserved_numbers = {boot.number, root.number}
    if backup is not None:
        preserved_numbers.add(backup.number)
    matched = set()
    for entry in current.entries:
        if entry.number in preserved_numbers:
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
        if entry.number in preserved_numbers:
            continue
        if entry.number == userdata.number:
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
    if backup is None:
        if root.last_lba != original_userdata.last_lba:
            raise GptError(
                "current root does not end at the original userdata end"
            )
    else:
        if root.last_lba + 1 != backup.first_lba:
            raise GptError(
                "current backup partition does not start right after root"
            )
        if backup.last_lba != original_userdata.last_lba:
            raise GptError(
                "current backup partition does not end at the original "
                "userdata end"
            )
        if backup.last_lba - backup.first_lba + 1 != (2 << 30) // sector:
            raise GptError("current backup partition is not exactly 2 GiB")
        if (backup.first_lba < original_userdata.first_lba
                or backup.last_lba > original_userdata.last_lba):
            raise GptError("current backup extent leaves original userdata")
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
                     root.last_lba)
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
        userdata_end_lba_exclusive=root.last_lba + 1,
        restored_userdata_bytes=(
            root.last_lba + 1 - userdata.first_lba
        ) * sector,
        removed_partition_numbers=(boot.number, root.number),
    )


def make_factory_reset_bcb(existing: bytes) -> bytes:
    """Return a 2048-byte BCB that queues a one-shot factory reset.

    ``existing`` must be exactly 2048 bytes whose ``command[0:32]`` is
    either empty (all NUL) or the exact canonical ``bootonce-bootloader``
    command, and whose ``recovery[64:832]`` is empty; otherwise
    :class:`GptError` is raised. The input is not mutated. Only the command
    and recovery payload are written; ``status`` and ``reserved`` are
    preserved. No reboot or device write is performed.
    """

    if not isinstance(existing, (bytes, bytearray, memoryview)):
        raise GptError("BCB must be bytes-like")
    data = bytes(existing)
    if len(data) != _BCB_SIZE:
        raise GptError("BCB must be exactly 2048 bytes")
    command = data[0:32]
    if command not in (bytes(32), b"bootonce-bootloader".ljust(32, b"\x00")):
        raise GptError("a boot command or recovery request is already pending")
    if any(data[64:832]):
        raise GptError("a boot command or recovery request is already pending")

    buffer = bytearray(data)
    buffer[0:32] = _BCB_COMMAND.ljust(32, b"\x00")
    buffer[64:832] = _BCB_RECOVERY.ljust(768, b"\x00")
    return bytes(buffer)


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


class GptImageReader:
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
