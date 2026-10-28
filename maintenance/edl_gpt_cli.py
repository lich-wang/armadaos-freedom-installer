"""Single-request JSON bridge for portable GPT planning.

Only one command-line argument is accepted: the path to a request JSON file.

This module is a local capture-to-plan file adapter.  It snapshots caller
supplied capture files once, validates them with the pure helpers in
:mod:`portable_gpt`, and writes byte-exact restore buffers into a brand new
output directory.  It never touches a device, USB path, network endpoint,
process, mount or Linux-specific metadata: all EDL I/O stays with the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from typing import Any

import portable_gpt

_SCHEMA_VERSION = 1
_SECTOR_SIZES = (512, 4096)
_BCB_SIZE = 2048
_OTA_OFFSET = 32768
_OTA_BYTES = 64

_INPUT_FIELDS = (
    "currentPrimary",
    "currentBackup",
    "originalPrimary",
    "originalBackup",
    "misc",
)
_OWNED_FIELDS = (
    "userdataPartUuid",
    "linuxBootPartUuid",
    "linuxRootPartUuid",
)
_REQUEST_FIELDS = frozenset(
    ("schemaVersion", "sectorSize", "diskBytes", "owned", "outputDirectory")
    + _INPUT_FIELDS
)

_SHA256_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")

# Fixed output order and deterministic exclusive file names.  The roles match
# the order returned by portable_gpt.plan_restore().
_REGION_OUTPUTS = (
    ("backup-array", "backup-array.bin"),
    ("backup-header", "backup-header.bin"),
    ("primary-array", "primary-array.bin"),
    ("primary-header", "primary-header.bin"),
)
_MISC_OUTPUT = "misc-bcb.bin"
_POST_PRIMARY_OUTPUT = "post-primary.bin"
_POST_BACKUP_OUTPUT = "post-backup.bin"


class _BridgeError(portable_gpt.GptError):
    """A rejected request that also carries a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(message: str, code: str = "invalid-request") -> None:
    raise _BridgeError(code, message)


def _require_int(value: object, label: str) -> int:
    """Return ``value`` as an int, rejecting bool and non-int values."""

    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{label} must be an integer")
    return value


def _require_object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _require_exact_fields(mapping: dict, expected: frozenset, label: str) -> None:
    keys = set(mapping)
    if keys == expected:
        return
    parts = []
    missing = sorted(expected - keys)
    extra = sorted(keys - expected)
    if missing:
        parts.append("missing " + ", ".join(missing))
    if extra:
        parts.append("unexpected " + ", ".join(extra))
    _fail(f"{label} fields are invalid: {'; '.join(parts)}")


def _validate_request(
    request: object,
) -> tuple[int, int, dict[str, tuple[str, str]], dict[str, str], str]:
    """Validate the request envelope and return its normalized values."""

    mapping = _require_object(request, "request")
    _require_exact_fields(mapping, _REQUEST_FIELDS, "request")

    if _require_int(mapping["schemaVersion"], "schemaVersion") != _SCHEMA_VERSION:
        _fail("schemaVersion must be 1")

    sector_size = _require_int(mapping["sectorSize"], "sectorSize")
    if sector_size not in _SECTOR_SIZES:
        _fail("sectorSize must be 512 or 4096")

    disk_bytes = _require_int(mapping["diskBytes"], "diskBytes")
    if disk_bytes <= 0 or disk_bytes % sector_size:
        _fail("diskBytes must be positive and sector aligned")

    descriptors: dict[str, tuple[str, str]] = {}
    for field in _INPUT_FIELDS:
        descriptor = _require_object(mapping[field], field)
        _require_exact_fields(descriptor, frozenset(("path", "sha256")), field)
        path = descriptor["path"]
        if not isinstance(path, str) or not path:
            _fail(f"{field}.path must be a non-empty string")
        digest = descriptor["sha256"]
        if not isinstance(digest, str) or not _SHA256_RE.match(digest):
            _fail(f"{field}.sha256 must be 64 hexadecimal characters")
        descriptors[field] = (path, digest.lower())

    owned_mapping = _require_object(mapping["owned"], "owned")
    allowed_owned = frozenset(_OWNED_FIELDS + ("boardBackupPartUuid",))
    if frozenset(owned_mapping) not in (
        frozenset(_OWNED_FIELDS), allowed_owned
    ):
        _require_exact_fields(owned_mapping, allowed_owned, "owned")
    owned: dict[str, str] = {}
    for field in _OWNED_FIELDS + ("boardBackupPartUuid",):
        if field not in owned_mapping:
            continue
        value = owned_mapping[field]
        if not isinstance(value, str) or not value.strip():
            _fail(f"owned.{field} must be a non-empty UUID string")
        owned[field] = value

    output_directory = mapping["outputDirectory"]
    if not isinstance(output_directory, str) or not output_directory:
        _fail("outputDirectory must be a non-empty string")

    return sector_size, disk_bytes, descriptors, owned, output_directory


def _read_snapshot(path_text: str, label: str) -> bytes:
    """Read one whole regular local file once and return its bytes."""

    try:
        info = os.stat(path_text)
    except OSError as exc:
        raise _BridgeError(
            "input-io-error",
            f"{label} cannot be read: {exc.strerror or exc}",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        _fail(f"{label} is not a regular file")
    try:
        with open(path_text, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise _BridgeError(
            "input-io-error",
            f"{label} cannot be read: {exc.strerror or exc}",
        ) from exc
    if not isinstance(data, bytes):
        _fail(f"{label} could not be read as bytes")
    return data


def _snapshot_inputs(
    descriptors: dict[str, tuple[str, str]],
) -> dict[str, bytes]:
    """Snapshot and hash-verify every input exactly once."""

    snapshots: dict[str, bytes] = {}
    for field in _INPUT_FIELDS:
        path_text, expected = descriptors[field]
        data = _read_snapshot(path_text, field)
        if hashlib.sha256(data).hexdigest() != expected:
            _fail(f"{field} content does not match its sha256")
        snapshots[field] = data
    return snapshots


def _check_capture_pair(
    primary: bytes, backup: bytes, disk_bytes: int, label: str
) -> None:
    """Require a primary prefix and a tail capture that cannot shadow each other."""

    if not primary:
        _fail(f"{label} primary capture is empty")
    if not backup:
        _fail(f"{label} backup capture is empty")
    if len(primary) > disk_bytes:
        _fail(f"{label} primary capture is larger than the disk")
    if len(backup) > disk_bytes:
        _fail(f"{label} backup capture is larger than the disk")
    if len(primary) + len(backup) > disk_bytes:
        _fail(f"{label} primary and tail captures overlap or exceed the disk")


def _write_unit_bytes(sector_size: int) -> int:
    """Return the misc write unit: 2048 bytes rounded up to whole sectors."""

    return ((_BCB_SIZE + sector_size - 1) // sector_size) * sector_size


def _write_exclusive(path: str, data: bytes) -> None:
    """Create ``path`` exclusively and write ``data`` with flush plus fsync."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise _BridgeError(
            "output-io-error",
            f"cannot create {os.path.basename(path)}: {exc.strerror or exc}",
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            written = handle.write(data)
            if written != len(data):
                raise _BridgeError(
                    "output-io-error",
                    f"short write for {os.path.basename(path)}",
                )
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise _BridgeError(
            "output-io-error",
            f"cannot write {os.path.basename(path)}: {exc.strerror or exc}",
        ) from exc


def prepare_plan(request: dict[str, Any]) -> dict[str, Any]:
    """Validate ``request`` and materialize the restore plan and buffers."""

    sector_size, disk_bytes, descriptors, owned, output_directory = (
        _validate_request(request)
    )

    snapshots = _snapshot_inputs(descriptors)
    current_primary = snapshots["currentPrimary"]
    current_backup = snapshots["currentBackup"]
    original_primary = snapshots["originalPrimary"]
    original_backup = snapshots["originalBackup"]
    misc_bytes = snapshots["misc"]

    current = portable_gpt.read_gpt(
        portable_gpt.GptImageReader(current_primary, current_backup, disk_bytes),
        sector_size,
        disk_bytes,
    )
    original = portable_gpt.read_gpt(
        portable_gpt.GptImageReader(original_primary, original_backup, disk_bytes),
        sector_size,
        disk_bytes,
    )

    _check_capture_pair(current_primary, current_backup, disk_bytes, "current")
    _check_capture_pair(original_primary, original_backup, disk_bytes, "original")

    ota = portable_gpt.parse_virtual_ab_message(
        misc_bytes[_OTA_OFFSET:_OTA_OFFSET + _OTA_BYTES]
    )
    if ota["state"] != "completed":
        _fail(
            "misc virtual A/B merge state is not completed "
            f"(state={ota['state']})"
        )

    restore = portable_gpt.plan_restore(
        current,
        original,
        owned["userdataPartUuid"],
        owned["linuxBootPartUuid"],
        owned["linuxRootPartUuid"],
        owned.get("boardBackupPartUuid"),
    )

    write_unit = _write_unit_bytes(sector_size)
    if len(misc_bytes) % sector_size:
        _fail("misc capture length must be sector aligned")
    if len(misc_bytes) < _OTA_OFFSET + _OTA_BYTES:
        _fail("misc capture is too short to carry the OTA state message")
    if len(misc_bytes) < write_unit:
        _fail("misc capture is shorter than one BCB write unit")

    new_bcb = portable_gpt.make_factory_reset_bcb(misc_bytes[:_BCB_SIZE])
    misc_written = new_bcb + misc_bytes[_BCB_SIZE:write_unit]
    misc_before_sha = hashlib.sha256(misc_bytes).hexdigest()
    misc_after_sha = hashlib.sha256(
        new_bcb + misc_bytes[_BCB_SIZE:]
    ).hexdigest()

    write_regions = tuple(restore.write_regions)
    if len(write_regions) != len(_REGION_OUTPUTS):
        _fail("restore plan did not return the four expected write regions")

    out_directory = os.path.abspath(output_directory)
    backup_capture_start = disk_bytes - len(current_backup)
    post_primary = bytearray(current_primary)
    post_backup = bytearray(current_backup)

    region_entries: list[dict[str, Any]] = []
    outputs: list[tuple[str, bytes]] = []
    for (role, filename), region in zip(_REGION_OUTPUTS, write_regions):
        offset = int(region.offset)
        data = bytes(region.data)
        if offset < 0 or offset % sector_size:
            _fail(f"{role} offset must be a non-negative sector multiple")
        if not data or len(data) % sector_size:
            _fail(f"{role} length must be a positive sector multiple")
        if offset + len(data) > disk_bytes:
            _fail(f"{role} lies outside the disk")

        in_primary = offset + len(data) <= len(current_primary)
        in_backup = (
            offset >= backup_capture_start
            and offset + len(data) <= disk_bytes
        )
        if in_primary:
            post_primary[offset:offset + len(data)] = data
        elif in_backup:
            relative = offset - backup_capture_start
            post_backup[relative:relative + len(data)] = data
        else:
            _fail(f"{role} is not fully covered by one current capture")

        region_entries.append({
            "role": role,
            "byteOffset": offset,
            "startSector": offset // sector_size,
            "sectorCount": len(data) // sector_size,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "path": os.path.join(out_directory, filename),
        })
        outputs.append((filename, data))

    post_primary_bytes = bytes(post_primary)
    post_backup_bytes = bytes(post_backup)

    # Reparse the combined expected captures through the pure reader: the
    # overlay must yield a self-consistent GPT before any output is created.
    portable_gpt.read_gpt(
        portable_gpt.GptImageReader(
            post_primary_bytes, post_backup_bytes, disk_bytes
        ),
        sector_size,
        disk_bytes,
    )

    misc_entry = {
        "role": "misc-bcb",
        "relativeMiscOffset": 0,
        "byteOffset": 0,
        "startSector": 0,
        "sectorCount": write_unit // sector_size,
        "bytes": write_unit,
        "sha256": hashlib.sha256(misc_written).hexdigest(),
        "path": os.path.join(out_directory, _MISC_OUTPUT),
    }
    post_primary_entry = {
        "byteOffset": 0,
        "bytes": len(post_primary_bytes),
        "sha256": hashlib.sha256(post_primary_bytes).hexdigest(),
        "path": os.path.join(out_directory, _POST_PRIMARY_OUTPUT),
    }
    post_backup_entry = {
        "byteOffset": backup_capture_start,
        "bytes": len(post_backup_bytes),
        "sha256": hashlib.sha256(post_backup_bytes).hexdigest(),
        "path": os.path.join(out_directory, _POST_BACKUP_OUTPUT),
    }

    outputs.append((_MISC_OUTPUT, misc_written))
    outputs.append((_POST_PRIMARY_OUTPUT, post_primary_bytes))
    outputs.append((_POST_BACKUP_OUTPUT, post_backup_bytes))

    if os.path.lexists(out_directory):
        _fail("outputDirectory already exists")

    input_paths = {
        os.path.abspath(descriptors[field][0]) for field in _INPUT_FIELDS
    }
    for filename, _data in outputs:
        if os.path.abspath(os.path.join(out_directory, filename)) in input_paths:
            _fail("an output file would overwrite an input file")

    try:
        os.mkdir(out_directory)
    except OSError as exc:
        raise _BridgeError(
            "output-io-error",
            f"cannot create outputDirectory: {exc.strerror or exc}",
        ) from exc

    for filename, data in outputs:
        _write_exclusive(os.path.join(out_directory, filename), data)

    return {
        "currentRawTableFingerprint": current.fingerprint,
        "userdataStartLba": restore.userdata_start_lba,
        "userdataEndLbaExclusive": restore.userdata_end_lba_exclusive,
        "restoredBytes": restore.restored_userdata_bytes,
        "removedPartitionNumbers": list(restore.removed_partition_numbers),
        "regions": region_entries,
        "miscRegion": misc_entry,
        "miscBeforeSha256": misc_before_sha,
        "miscAfterSha256": misc_after_sha,
        "postPrimary": post_primary_entry,
        "postBackup": post_backup_entry,
    }


def _load_request_file(path_text: str) -> dict:
    """Read the one request file as UTF-8 JSON (optional BOM) and return it."""

    if not isinstance(path_text, str) or not path_text:
        raise _BridgeError(
            "invalid-arguments", "request path must be a non-empty string"
        )
    try:
        info = os.stat(path_text)
    except OSError as exc:
        raise _BridgeError(
            "io-error", f"cannot read request file: {exc.strerror or exc}"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise _BridgeError(
            "invalid-arguments", "request path is not a regular file"
        )
    try:
        with open(path_text, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise _BridgeError(
            "io-error", f"cannot read request file: {exc.strerror or exc}"
        ) from exc

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _BridgeError(
            "invalid-json", "request file is not valid UTF-8"
        ) from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _BridgeError(
            "invalid-json", f"request file is not valid JSON: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise _BridgeError("invalid-request", "request JSON must be an object")
    return value


def _emit(envelope: dict) -> None:
    """Write exactly one ASCII-escaped JSON object and a newline to stdout."""

    sys.stdout.write(
        json.dumps(envelope, ensure_ascii=True, separators=(",", ":")) + "\n"
    )


def _emit_error(code: str, message: str) -> None:
    _emit({
        "schemaVersion": _SCHEMA_VERSION,
        "ok": False,
        "error": {
            "code": code if code else "invalid-request",
            "message": message if message else "request rejected",
        },
    })


def main(argv: list[str] | None = None) -> int:
    """Run the one-argument request JSON entry point and return an exit code."""

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        _emit_error(
            "invalid-arguments",
            "exactly one request JSON file path is required",
        )
        return 2

    try:
        request = _load_request_file(args[0])
        plan = prepare_plan(request)
    except _BridgeError as exc:
        _emit_error(exc.code, str(exc))
        return 1
    except portable_gpt.GptError as exc:
        _emit_error("invalid-request", str(exc))
        return 1
    except OSError as exc:
        _emit_error("io-error", str(exc))
        return 1
    except Exception as exc:  # pragma: no cover - defensive, never printed raw
        _emit_error("internal-error", f"unexpected failure: {type(exc).__name__}")
        return 1

    _emit({"schemaVersion": _SCHEMA_VERSION, "ok": True, "plan": plan})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
