"""Authenticated RAM-only TF-card block service for the freedom installer.

This service runs ONLY inside the separately confirmed, same-model temporary
RAM boot of the two supported tablets. The verified C# bootstrap uploads it
into the existing generic ARM64 RAM toolbox and starts it explicitly; no OS
boot path or default service ever starts it. It binds one fixed USB-link
address, authenticates exactly one fixed peer with the RAM bearer token, and
exposes a narrow inspect/open/read/write/flush/close surface over at most one
whole SD (TF) card.

It never mounts or reads Android/UFS filesystems, never loads a boot image,
never writes misc/GPT/UFS/EFI/AVB, never reboots and never runs external
commands. Bearer tokens and binary payloads are never logged. State stays in
the confirmed RAM directory /run/freedom-tf.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import threading
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

SCHEMA_VERSION = 1
PROTOCOL = "tf-card-v1"
BIND_HOST = "192.168.77.1"
BIND_PORT = 8203
PEER_HOST = "192.168.77.2"

RUN_DIR = "/run/freedom-tf"
TOKEN_PATH = RUN_DIR + "/token"
MARKER_PATH = RUN_DIR + "/tf-maintenance.json"

JSON_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 1 << 20
MOUNTINFO_MAX_BYTES = 1 << 20
SWAPS_MAX_BYTES = 1 << 16
ATTR_MAX_BYTES = 4096
MARKER_MAX_BYTES = 4096
TOKEN_MAX_BYTES = 68
MOUNTINFO_MAX_LINES = 4096
MOUNTINFO_MAX_OPTIONAL_FIELDS = 12

RAM_FSTYPES = frozenset(("rootfs", "ramfs", "tmpfs"))
MODEL_DEVICES = {
    "TB322FC": ("lenovo,elden", "qcom,sm8750"),
    "TB323FU": ("lenovo,baldur", "qcom,kaanapali"),
}
MARKER_FIELDS = frozenset(
    ("schema", "expectedModel", "kernelSha256", "transportProtocol")
)
OPEN_FIELDS = frozenset(("key", "path", "sizeBytes", "logicalSectorSize"))
SECTOR_SIZES = (512, 4096)
INT64_MAX = (1 << 63) - 1

_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX32_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_CARD_NAME_RE = re.compile(r"\Ammcblk[0-9]+\Z")
_DECIMAL_RE = re.compile(r"\A[0-9]{1,20}\Z")
_FULL_KEY_RE = re.compile(r"\Atablet:sd:([0-9a-f]{32})\Z")
_BINDING_PREFIX = "armada-tf-binding-v1"
_BODY_CHUNK = 1 << 16


class TfError(Exception):
    """One rejected request: stable code, short neutral message, HTTP status."""

    def __init__(self, code: str, message: str, http_status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------

def _unescape_mount_field(text: str) -> str:
    """Decode the octal escapes mountinfo uses for spaces and backslashes."""

    raw = text.encode("utf-8", "surrogateescape")
    out = bytearray()
    index = 0
    while index < len(raw):
        if (raw[index] == 0x5C and index + 3 < len(raw)
                and all(0x30 <= item <= 0x37 for item in raw[index + 1:index + 4])):
            out.append(int(raw[index + 1:index + 4].decode("ascii"), 8))
            index += 4
            continue
        out.append(raw[index])
        index += 1
    return out.decode("utf-8", "surrogateescape")


def parse_mountinfo_text(text: str) -> list:
    """Boundedly parse mountinfo text into dev/mount_point/fstype entries."""

    lines = text.splitlines()
    if len(lines) > MOUNTINFO_MAX_LINES:
        raise TfError("mountinfo-too-large", "mountinfo exceeds the line bound")
    entries = []
    for line in lines:
        if not line.strip():
            continue
        fields = line.split(" ")
        try:
            separator = fields.index("-")
            major_text, minor_text = fields[2].split(":")
            major = int(major_text, 10)
            minor = int(minor_text, 10)
        except (ValueError, IndexError) as exc:
            raise TfError(
                "mountinfo-invalid", "malformed mountinfo line"
            ) from exc
        if (separator < 6 or separator > MOUNTINFO_MAX_OPTIONAL_FIELDS + 6
                or len(fields) <= separator + 2):
            raise TfError("mountinfo-invalid", "malformed mountinfo line")
        entries.append({
            "dev": (major, minor),
            "mount_point": _unescape_mount_field(fields[4]),
            "fstype": fields[separator + 1],
        })
    return entries


def _read_bounded(path, max_bytes: int, code: str) -> bytes:
    """Open a regular path with O_NOFOLLOW and read at most max_bytes."""

    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise TfError(code, f"cannot read {path}") from exc
    try:
        return os.read(fd, max_bytes)
    except OSError as exc:
        raise TfError(code, f"cannot read {path}") from exc
    finally:
        os.close(fd)


def _read_text(path, max_bytes: int, code: str) -> str:
    data = _read_bounded(path, max_bytes, code)
    try:
        return data.decode("utf-8", "surrogateescape")
    except UnicodeDecodeError as exc:  # pragma: no cover - decode is lossless
        raise TfError(code, f"cannot decode {path}") from exc


def parse_marker(raw: bytes) -> "MaintenanceMarker":
    """Boundedly parse the copied RAM maintenance marker.

    The marker is metadata copied by the verified bootstrap from the RAM
    initrd. It is never treated as live kernel proof; the host compares the
    reported digest against the temporary boot it programmed.
    """

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TfError(
            "marker-invalid", "the maintenance marker is not valid JSON"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != MARKER_FIELDS:
        raise TfError("marker-invalid", "the maintenance marker fields are wrong")
    schema = payload["schema"]
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SCHEMA_VERSION:
        raise TfError("marker-invalid", "the maintenance marker schema must be 1")
    model = payload["expectedModel"]
    if not isinstance(model, str) or model not in MODEL_DEVICES:
        raise TfError("marker-invalid", "the maintenance marker model is unsupported")
    kernel_sha = payload["kernelSha256"]
    if not isinstance(kernel_sha, str) or not _HEX64_RE.match(kernel_sha):
        raise TfError(
            "marker-invalid", "the maintenance marker kernel digest is invalid"
        )
    if payload["transportProtocol"] != PROTOCOL:
        raise TfError("marker-invalid", "the maintenance marker transport is wrong")
    return MaintenanceMarker(expected_model=model, kernel_sha256=kernel_sha)


def load_token(path) -> str:
    """Read the fixed bearer token: regular, non-symlink, 64 lowercase hex.

    The value is never logged or echoed. One trailing LF or CRLF is tolerated
    to match the existing bootstrap token convention.
    """

    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise TfError("token-unreadable", "the token file cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise TfError("token-invalid", "the token file is not a regular file")
        raw = os.read(fd, TOKEN_MAX_BYTES)
    except OSError as exc:
        raise TfError("token-unreadable", "the token file cannot be read") from exc
    finally:
        os.close(fd)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TfError("token-invalid", "the token file is invalid") from exc
    if not _HEX64_RE.match(text):
        raise TfError(
            "token-invalid", "the token must be exactly 64 lowercase hex digits"
        )
    return text


def binding_sha256(boot_id: str, cid: str, major: int, minor: int, node: str,
                   size_bytes: int, sector_size: int) -> str:
    """Stable digest of the unambiguous boot/card facts, never of the GPT."""

    payload = "|".join((
        _BINDING_PREFIX,
        boot_id,
        cid,
        f"{major}:{minor}",
        node,
        str(size_bytes),
        str(sector_size),
    ))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _decimal(text: str, label: str) -> int:
    if not isinstance(text, str) or not _DECIMAL_RE.match(text):
        raise TfError("query-invalid", f"{label} must be a decimal integer", 400)
    return int(text, 10)


# ---------------------------------------------------------------------------
# Runtime facts and the card service
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MaintenanceMarker:
    expected_model: str
    kernel_sha256: str


@dataclass(frozen=True)
class RuntimeIdentity:
    model: str
    soc: str
    soc_serial: str
    boot_id: str
    kernel_sha256: str
    compatible: tuple


@dataclass(frozen=True)
class CardFacts:
    name: str
    node: str
    cid: str
    major: int
    minor: int
    size_bytes: int
    sector_size: int

    @property
    def key(self) -> str:
        return f"sd:{self.cid}"


@dataclass
class _CardSession:
    session_id: str
    facts: CardFacts
    fd: int
    boot_id: str
    binding_sha256: str
    failed: TfError | None = None


class TfService:
    """One RAM runtime serving at most one exclusive SD-card session.

    Filesystem roots are constructor-injectable so offline tests can build
    synthetic trees; the production CLI always constructs this with the real
    hardcoded roots and there is no runtime override of any fact.
    """

    def __init__(self, *, sys_block="/sys/class/block",
                 dt_compatible="/sys/firmware/devicetree/base/compatible",
                 soc_serial="/sys/devices/soc0/serial_number",
                 boot_id="/proc/sys/kernel/random/boot_id",
                 self_mountinfo="/proc/self/mountinfo",
                 proc_swaps="/proc/swaps",
                 dev_root="/dev",
                 token_path=TOKEN_PATH,
                 marker_path=MARKER_PATH,
                 stat_fn=os.stat):
        self.sys_block = Path(sys_block)
        self.dt_compatible = Path(dt_compatible)
        self.soc_serial_path = Path(soc_serial)
        self.boot_id_path = Path(boot_id)
        self.self_mountinfo = Path(self_mountinfo)
        self.proc_swaps = Path(proc_swaps)
        self.dev_root = Path(dev_root)
        self.token_path = Path(token_path)
        self.marker_path = Path(marker_path)
        self._stat_fn = stat_fn
        self._lock = threading.RLock()
        self._identity = None
        self._session = None

    # -- startup facts -----------------------------------------------------
    def _read_mountinfo(self) -> list:
        data = _read_bounded(
            self.self_mountinfo, MOUNTINFO_MAX_BYTES, "mountinfo-unreadable"
        )
        if len(data) >= MOUNTINFO_MAX_BYTES:
            raise TfError("mountinfo-too-large", "mountinfo exceeds the byte bound")
        return parse_mountinfo_text(data.decode("utf-8", "surrogateescape"))

    def prove_ram_mounts(self) -> dict:
        """Require /, /tmp and /run to be actual rootfs/ramfs/tmpfs mounts."""

        mounts = self._read_mountinfo()
        proven = {}
        for target in ("/", "/tmp", "/run"):
            try:
                info = os.stat(target)
            except OSError as exc:
                raise TfError(
                    "ram-root-unverified", f"cannot stat {target}"
                ) from exc
            dev = (os.major(info.st_dev), os.minor(info.st_dev))
            match = None
            for entry in mounts:
                if entry["mount_point"] == target and entry["dev"] == dev:
                    match = entry
                    break
            if match is None:
                raise TfError(
                    "ram-root-unverified", f"no mountinfo entry backs {target}"
                )
            if match["fstype"] not in RAM_FSTYPES:
                raise TfError(
                    "not-ram-root",
                    f"{target} is on {match['fstype']}, not a RAM filesystem",
                )
            proven[target] = match["fstype"]
        return proven

    def _read_boot_id(self) -> str:
        text = _read_text(self.boot_id_path, ATTR_MAX_BYTES, "boot-id-unreadable").strip()
        try:
            parsed = uuid.UUID(text)
        except (AttributeError, TypeError, ValueError) as exc:
            raise TfError("boot-id-invalid", "the boot id is not a UUID") from exc
        if parsed.int == 0 or str(parsed) != text:
            raise TfError(
                "boot-id-invalid", "the boot id must be canonical and nonzero"
            )
        return text

    def load_runtime(self) -> RuntimeIdentity:
        """Prove the RAM environment, marker, device tree and boot identity."""

        mounts = self.prove_ram_mounts()
        marker = parse_marker(
            _read_bounded(self.marker_path, MARKER_MAX_BYTES, "marker-unreadable")
        )
        raw = _read_bounded(
            self.dt_compatible, ATTR_MAX_BYTES, "device-tree-unreadable"
        )
        try:
            compatible = tuple(
                part.decode("ascii").strip()
                for part in raw.split(b"\x00")
                if part.strip()
            )
        except UnicodeDecodeError as exc:
            raise TfError(
                "device-tree-unreadable", "compatible is not ASCII"
            ) from exc
        device_comp, soc_comp = MODEL_DEVICES[marker.expected_model]
        if device_comp not in compatible or soc_comp not in compatible:
            raise TfError(
                "unknown-device",
                "the device tree does not match the maintenance model",
            )
        serial = _read_text(
            self.soc_serial_path, ATTR_MAX_BYTES, "soc-serial-unreadable"
        ).strip()
        if not serial:
            raise TfError("soc-serial-invalid", "the SoC serial is empty")
        boot_id = self._read_boot_id()
        identity = RuntimeIdentity(
            model=marker.expected_model,
            soc=soc_comp.split(",", 1)[1],
            soc_serial=serial,
            boot_id=boot_id,
            kernel_sha256=marker.kernel_sha256,
            compatible=compatible,
        )
        with self._lock:
            self._identity = identity
        return identity

    @property
    def identity(self) -> RuntimeIdentity:
        if self._identity is None:
            raise TfError("not-started", "the runtime identity is not loaded", 500)
        return self._identity

    # -- sysfs card discovery ---------------------------------------------
    def _attr(self, *parts) -> str:
        return _read_text(
            Path(self.sys_block, *parts), ATTR_MAX_BYTES, "sysfs-unreadable"
        ).strip()

    def discover_cards(self) -> tuple:
        """Discover only whole removable SD mmcblk disks with valid CIDs.

        Everything else (MMC, UFS/sdX, loop/dm, partitions, nonremovable,
        read-only, unusable identity) is excluded. Unreadable required facts
        fail closed; an unusable candidate is skipped, never guessed.
        """

        try:
            names = sorted(os.listdir(self.sys_block))
        except OSError as exc:
            raise TfError("sysfs-unreadable", "cannot list the block devices") from exc
        cards = []
        seen = set()
        for name in names:
            if not _CARD_NAME_RE.match(name):
                continue
            base = self.sys_block / name
            if (base / "partition").exists():
                continue
            if self._attr(base, "removable") != "1":
                continue
            if self._attr(base, "device", "type") != "SD":
                continue
            cid = self._attr(base, "device", "cid").lower()
            if not _HEX32_RE.match(cid) or cid == "0" * 32:
                continue
            if self._attr(base, "ro") == "1":
                continue
            size_text = self._attr(base, "size")
            lbs_text = self._attr(base, "queue", "logical_block_size")
            dev_text = self._attr(base, "dev")
            if not _DECIMAL_RE.match(size_text):
                raise TfError("card-geometry-invalid", f"{name} has an invalid size")
            sectors = int(size_text, 10)
            size_bytes = sectors * 512
            if sectors <= 0 or size_bytes > INT64_MAX:
                raise TfError("card-geometry-invalid", f"{name} size is out of range")
            if lbs_text not in ("512", "4096"):
                raise TfError(
                    "card-geometry-invalid",
                    f"{name} has an unsupported logical block size",
                )
            sector_size = int(lbs_text, 10)
            if size_bytes % sector_size:
                raise TfError(
                    "card-geometry-invalid", f"{name} capacity is not sector aligned"
                )
            dev_parts = dev_text.split(":")
            if (len(dev_parts) != 2
                    or not _DECIMAL_RE.match(dev_parts[0])
                    or not _DECIMAL_RE.match(dev_parts[1])):
                raise TfError("card-geometry-invalid", f"{name} has an invalid dev")
            major, minor = int(dev_parts[0], 10), int(dev_parts[1], 10)
            if cid in seen:
                raise TfError("duplicate-card", "two cards report the same CID")
            seen.add(cid)
            cards.append(CardFacts(
                name=name,
                node=str(self.dev_root / name),
                cid=cid,
                major=major,
                minor=minor,
                size_bytes=size_bytes,
                sector_size=sector_size,
            ))
        return tuple(cards)

    def _swap_sources(self) -> list:
        text = _read_text(self.proc_swaps, SWAPS_MAX_BYTES, "swapinfo-unreadable")
        sources = []
        for line in text.splitlines()[1:]:
            fields = line.split()
            if fields:
                sources.append(_unescape_mount_field(fields[0]))
        return sources

    def busy_reasons(self, facts: CardFacts) -> tuple:
        """Holder/mount/swap evidence that must reject opening the card."""

        reasons = []
        dev_set = {(facts.major, facts.minor)}
        partition_re = re.compile(rf"\A{re.escape(facts.name)}p[0-9]+\Z")
        try:
            names = sorted(os.listdir(self.sys_block))
            holders = sorted(os.listdir(self.sys_block / facts.name / "holders"))
        except OSError as exc:
            raise TfError("sysfs-unreadable", "cannot inspect the card") from exc
        for name in names:
            if not partition_re.match(name):
                continue
            dev_text = self._attr(name, "dev")
            parts = dev_text.split(":")
            if (len(parts) != 2
                    or not _DECIMAL_RE.match(parts[0])
                    or not _DECIMAL_RE.match(parts[1])):
                raise TfError("sysfs-unreadable", "a partition dev is invalid")
            dev_set.add((int(parts[0], 10), int(parts[1], 10)))
        for holder in holders:
            reasons.append(f"holder:{holder}")
        for entry in self._read_mountinfo():
            if entry["dev"] in dev_set:
                reasons.append(f"mounted:{entry['mount_point']}")
        for source in self._swap_sources():
            try:
                info = self._stat_fn(source)
            except OSError as exc:
                raise TfError("swap-unverified", "cannot verify a swap source") from exc
            if stat.S_ISBLK(info.st_mode) and (
                    os.major(info.st_rdev), os.minor(info.st_rdev)) in dev_set:
                reasons.append(f"swap:{source}")
        return tuple(reasons)

    # -- session handling --------------------------------------------------
    def _identity_document(self, facts: CardFacts,
                           binding: str | None = None) -> dict:
        if binding is None:
            binding = binding_sha256(
                self.identity.boot_id,
                facts.cid,
                facts.major,
                facts.minor,
                facts.node,
                facts.size_bytes,
                facts.sector_size,
            )
        return {
            "source": "tablet",
            "key": "tablet:" + facts.key,
            "path": facts.node,
            "sizeBytes": facts.size_bytes,
            "logicalSectorSize": facts.sector_size,
            "bindingSha256": binding,
        }

    def open_card(self, key: str, path: str, size_bytes: int,
                  sector_size: int) -> dict:
        match = _FULL_KEY_RE.match(key if isinstance(key, str) else "")
        if not match:
            raise TfError("key-invalid", "card key must be tablet:sd:<32hex>", 400)
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) \
                or size_bytes <= 0:
            raise TfError("payload-invalid", "sizeBytes must be a positive integer", 400)
        if sector_size not in SECTOR_SIZES:
            raise TfError(
                "payload-invalid", "logicalSectorSize must be 512 or 4096", 400
            )
        if not isinstance(path, str) or not path:
            raise TfError("payload-invalid", "path must be a non-empty string", 400)
        identity = self.identity
        with self._lock:
            if self._session is not None:
                raise TfError(
                    "session-active", "one card session is already active", 409
                )
            cid = match.group(1)
            matches = [facts for facts in self.discover_cards() if facts.cid == cid]
            if not matches:
                raise TfError("card-unknown", "no such card is present", 404)
            facts = matches[0]
            if (path != facts.node or size_bytes != facts.size_bytes
                    or sector_size != facts.sector_size):
                raise TfError(
                    "card-changed", "open facts do not match the fresh card facts"
                )
            reasons = self.busy_reasons(facts)
            if reasons:
                raise TfError("card-busy", "card is in use: " + ", ".join(reasons))
            flags = os.O_RDWR | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                fd = os.open(facts.node, flags)
            except OSError as exc:
                raise TfError("device-open-failed", "cannot open the card") from exc
            try:
                info = os.fstat(fd)
                if not stat.S_ISBLK(info.st_mode):
                    raise TfError("not-block-device", "the node is not a block device")
                if info.st_rdev != os.makedev(facts.major, facts.minor):
                    raise TfError(
                        "device-identity-mismatch",
                        "the opened node does not match sysfs",
                    )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise TfError("device-locked", "cannot lock the card") from exc
            except BaseException:
                os.close(fd)
                raise
            session_id = secrets.token_hex(16)
            binding = binding_sha256(
                identity.boot_id, facts.cid, facts.major, facts.minor,
                facts.node, facts.size_bytes, facts.sector_size,
            )
            session = _CardSession(
                session_id=session_id,
                facts=facts,
                fd=fd,
                boot_id=identity.boot_id,
                binding_sha256=binding,
            )
            self._session = session
            return {
                "schemaVersion": SCHEMA_VERSION,
                "cardSessionId": session_id,
                "identity": self._identity_document(facts, binding),
            }

    def _lookup_session(self, session_id: str) -> _CardSession:
        if not _HEX32_RE.match(session_id or ""):
            raise TfError("unknown-session", "unknown card session", 404)
        session = self._session
        if session is None or session.session_id != session_id:
            raise TfError("unknown-session", "unknown card session", 404)
        return session

    def _fail(self, session: _CardSession, code: str, message: str) -> None:
        """Latch the first truthful failure and always raise it afterwards."""

        if session.failed is None:
            session.failed = TfError(code, message)
        raise session.failed

    def _revalidate(self, session: _CardSession) -> CardFacts:
        """Re-prove boot/CID/dev/geometry before any IO or identity claim."""

        if session.failed is not None:
            raise session.failed
        try:
            matches = [
                facts for facts in self.discover_cards()
                if facts.key == session.facts.key and facts.node == session.facts.node
            ]
            if len(matches) != 1:
                self._fail(session, "card-changed", "the card is gone or ambiguous")
            fresh = matches[0]
            if fresh != session.facts:
                self._fail(session, "card-changed", "card identity or geometry changed")
            if self._read_boot_id() != session.boot_id:
                self._fail(session, "card-changed", "the RAM boot identity changed")
            try:
                info = os.fstat(session.fd)
            except OSError:
                self._fail(session, "device-io-failed", "the card descriptor is gone")
            if (not stat.S_ISBLK(info.st_mode)
                    or info.st_rdev != os.makedev(fresh.major, fresh.minor)):
                self._fail(
                    session, "device-identity-mismatch", "the opened node changed"
                )
        except TfError as exc:
            if session.failed is None:
                session.failed = exc
            raise session.failed
        return fresh

    def card_identity(self, session_id: str) -> dict:
        with self._lock:
            session = self._lookup_session(session_id)
            fresh = self._revalidate(session)
            return {
                "schemaVersion": 1,
                "identity": self._identity_document(fresh, session.binding_sha256),
            }

    def card_write(self, session_id: str, offset: int, data: bytes) -> int:
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise TfError("range-invalid", "the write payload must not be empty", 400)
        total = len(data)
        with self._lock:
            session = self._lookup_session(session_id)
            facts = self._revalidate(session)
            sector = facts.sector_size
            if (isinstance(offset, bool) or not isinstance(offset, int)
                    or offset < 0 or offset % sector or total % sector):
                raise TfError(
                    "range-invalid", "the write range must be sector aligned", 400
                )
            if offset + total > facts.size_bytes:
                raise TfError("range-invalid", "the write range leaves the card", 400)
            done = 0
            try:
                while done < total:
                    written = os.pwrite(session.fd, data[done:], offset + done)
                    if not isinstance(written, int) or written <= 0:
                        self._fail(session, "short-write", "pwrite made no progress")
                    if written > total - done:
                        self._fail(session, "short-write", "pwrite wrote too much")
                    done += written
            except OSError as exc:
                self._fail(session, "device-io-failed", "the card write failed")
            return done

    def card_read(self, session_id: str, offset: int, length: int) -> bytes:
        with self._lock:
            session = self._lookup_session(session_id)
            facts = self._revalidate(session)
            sector = facts.sector_size
            if (isinstance(offset, bool) or not isinstance(offset, int)
                    or isinstance(length, bool) or not isinstance(length, int)
                    or length <= 0 or length > BINARY_MAX_BYTES
                    or offset < 0 or offset % sector or length % sector):
                raise TfError(
                    "range-invalid",
                    "the read range must be positive, aligned and bounded",
                    400,
                )
            if offset + length > facts.size_bytes:
                raise TfError("range-invalid", "the read range leaves the card", 400)
            chunks = []
            done = 0
            try:
                while done < length:
                    chunk = os.pread(session.fd, length - done, offset + done)
                    if not chunk:
                        self._fail(session, "short-read", "the card read ended early")
                    if len(chunk) > length - done:
                        self._fail(session, "short-read", "the card read overrun")
                    chunks.append(bytes(chunk))
                    done += len(chunk)
            except OSError:
                self._fail(session, "device-io-failed", "the card read failed")
            return b"".join(chunks)

    def card_flush(self, session_id: str) -> dict:
        with self._lock:
            session = self._lookup_session(session_id)
            self._revalidate(session)
            try:
                os.fsync(session.fd)
            except OSError:
                self._fail(session, "flush-failed", "the card flush failed")
            return {"schemaVersion": SCHEMA_VERSION, "flushed": True}

    def card_close(self, session_id: str) -> dict:
        with self._lock:
            session = self._lookup_session(session_id)
            self._session = None
            try:
                # Closing the descriptor releases the flock regardless, so an
                # explicit unlock failure is not a data-integrity failure.
                fcntl.flock(session.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(session.fd)
            except OSError as exc:
                raise TfError("close-failed", "the card close failed", 500) from exc
            return {"schemaVersion": SCHEMA_VERSION, "closed": True}

    def close_all(self) -> None:
        """Server shutdown: close only the owned descriptor, write nothing."""

        with self._lock:
            session = self._session
            self._session = None
        if session is not None:
            try:
                os.close(session.fd)
            except OSError:
                pass

    # -- inventory ---------------------------------------------------------
    def inspect(self) -> dict:
        identity = self.identity
        media = []
        for facts in self.discover_cards():
            media.append({
                "key": facts.key,
                "path": facts.node,
                "displayName": "SD card",
                "sizeBytes": facts.size_bytes,
                "logicalSectorSize": facts.sector_size,
                "mediumEvidence": "SD",
                "readOnly": False,
                "isSystemDisk": False,
                "isOffline": False,
                "mounted": False,
                "androidUsage": "unknown",
            })
        return {
            "schemaVersion": SCHEMA_VERSION,
            "source": "tablet",
            "protocol": PROTOCOL,
            "model": identity.model,
            "soc": identity.soc,
            "socSerial": identity.soc_serial,
            "bootId": identity.boot_id,
            "kernelSha256": identity.kernel_sha256,
            "ramOnly": True,
            "media": media,
        }


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

def parse_open_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != OPEN_FIELDS:
        raise TfError("payload-invalid", "open payload fields are wrong", 400)
    key = payload["key"]
    path = payload["path"]
    size_bytes = payload["sizeBytes"]
    sector_size = payload["logicalSectorSize"]
    if not isinstance(key, str) or not key:
        raise TfError("payload-invalid", "key must be a non-empty string", 400)
    if not isinstance(path, str) or not path:
        raise TfError("payload-invalid", "path must be a non-empty string", 400)
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) \
            or size_bytes <= 0 or size_bytes > INT64_MAX:
        raise TfError("payload-invalid", "sizeBytes must be a positive integer", 400)
    if isinstance(sector_size, bool) or sector_size not in SECTOR_SIZES:
        raise TfError(
            "payload-invalid", "logicalSectorSize must be 512 or 4096", 400
        )
    return {
        "key": key,
        "path": path,
        "size_bytes": size_bytes,
        "sector_size": sector_size,
    }


def make_http_handler(service: TfService, session_token: str,
                      peer_host: str = PEER_HOST) -> type:
    """Return the BaseHTTPRequestHandler subclass serving ``service``.

    Production always passes the fixed peer 192.168.77.2; the parameter
    exists only so the offline loopback test harness can be reached.
    """

    expected_auth = ("Bearer " + session_token).encode("ascii")

    class _TfHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "armada-tf"
        sys_version = ""

        # -- plumbing ------------------------------------------------------
        def log_message(self, format, *args):
            return

        def handle_one_request(self):
            try:
                super().handle_one_request()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_DELETE(self):
            self._handle("DELETE")

        def send_error(self, code, message=None, explain=None):
            status = code if isinstance(code, int) and 400 <= code <= 599 else 400
            try:
                self._send_error("http-error", "invalid HTTP request", status)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        # -- responses -----------------------------------------------------
        def _send_json(self, status: int, document: dict) -> None:
            body = json.dumps(document, ensure_ascii=False).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _send_error(self, code: str, message: str, status: int) -> None:
            self._send_json(status, {
                "schemaVersion": SCHEMA_VERSION,
                "error": {"code": code, "message": message},
            })

        def _send_tf_error(self, error: TfError) -> None:
            status = error.http_status
            if not isinstance(status, int) or not 400 <= status <= 599:
                status = 500
            self._send_error(
                str(error.code), str(error) or "request rejected", status
            )

        def _send_binary(self, data: bytes) -> None:
            digest = hashlib.sha256(data).hexdigest()
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-SHA256", digest)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        # -- request checks ------------------------------------------------
        def _check_no_transfer_encoding(self) -> None:
            if self.headers.get("Transfer-Encoding") is not None:
                raise TfError(
                    "length-invalid", "Transfer-Encoding is not supported", 400
                )

        def _content_length(self) -> int:
            self._check_no_transfer_encoding()
            values = self.headers.get_all("Content-Length")
            if not values:
                raise TfError("length-invalid", "Content-Length is required", 400)
            if len(values) != 1:
                raise TfError(
                    "length-invalid", "exactly one Content-Length is required", 400
                )
            value = values[0]
            if not value or not _DECIMAL_RE.match(value):
                raise TfError("length-invalid", "Content-Length is invalid", 400)
            return int(value, 10)

        def _optional_zero_length(self) -> None:
            self._check_no_transfer_encoding()
            values = self.headers.get_all("Content-Length")
            if not values:
                return
            if len(values) != 1:
                raise TfError(
                    "length-invalid", "exactly one Content-Length is required", 400
                )
            value = values[0]
            if not _DECIMAL_RE.match(value or "") or int(value, 10) != 0:
                raise TfError("length-invalid", "this route takes no body", 400)

        def _read_exact_body(self, length: int) -> bytes:
            chunks = []
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, _BODY_CHUNK))
                if not chunk:
                    raise TfError("body-invalid", "request body ended early", 400)
                data = bytes(chunk)
                if len(data) > remaining:
                    raise TfError(
                        "body-invalid", "request body exceeded its length", 400
                    )
                chunks.append(data)
                remaining -= len(data)
            return b"".join(chunks)

        def _require_media_type(self, expected: str) -> None:
            raw = self.headers.get("Content-Type", "")
            media = raw.split(";", 1)[0].strip().lower()
            if media != expected:
                raise TfError(
                    "content-type-invalid",
                    f"{expected} content type is required",
                    400,
                )

        def _read_json_object(self) -> dict:
            length = self._content_length()
            if length > JSON_MAX_BYTES:
                raise TfError("body-too-large", "JSON body exceeds 16 KiB", 413)
            self._require_media_type("application/json")
            raw = self._read_exact_body(length)
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise TfError(
                    "body-invalid", "request body is not valid JSON", 400
                ) from exc
            if not isinstance(document, dict):
                raise TfError(
                    "body-invalid", "request body must be a JSON object", 400
                )
            return document

        def _content_sha256(self) -> str:
            value = self.headers.get("X-Content-SHA256", "")
            if not _HEX64_RE.match(value):
                raise TfError(
                    "hash-invalid",
                    "X-Content-SHA256 must be 64 lowercase hex digits",
                    400,
                )
            return value

        def _query(self, query_text: str, allowed: tuple) -> dict:
            pairs = parse_qsl(query_text, keep_blank_values=True)
            if len(pairs) != len(allowed) or {key for key, _ in pairs} != set(allowed):
                raise TfError("query-invalid", "the query parameters are wrong", 400)
            parsed = {}
            for key, value in pairs:
                if not _DECIMAL_RE.match(value):
                    raise TfError(
                        "query-invalid", f"{key} must be a decimal integer", 400
                    )
                parsed[key] = int(value, 10)
            return parsed

        def _reject_query(self, query_text: str) -> None:
            if query_text:
                raise TfError("query-invalid", "this route takes no query", 400)

        def _session_id(self, text: str) -> str:
            if not _HEX32_RE.match(text or ""):
                raise TfError("unknown-session", "unknown card session", 404)
            return text

        # -- dispatch ------------------------------------------------------
        def _handle(self, method: str) -> None:
            self.close_connection = True
            try:
                if self.client_address[0] != peer_host:
                    self._send_error(
                        "peer-forbidden", "request rejected", 403
                    )
                    return
                supplied = self.headers.get("Authorization", "")
                supplied_bytes = supplied.encode("latin-1", "replace")
                if not hmac.compare_digest(supplied_bytes, expected_auth):
                    self._send_error(
                        "unauthorized", "authentication required", 401
                    )
                    return
                self._route(method, urlsplit(self.path))
            except TfError as error:
                self._send_tf_error(error)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            except Exception:
                self._send_error("internal-error", "internal error", 500)

        def _route(self, method: str, split) -> None:
            parts = [part for part in split.path.split("/") if part]
            if method == "GET":
                self._route_get(parts, split.query)
            elif method == "POST":
                self._route_post(parts, split.query)
            else:
                self._route_delete(parts, split.query)

        def _route_get(self, parts: list, query: str) -> None:
            if parts == ["v1", "inspect"]:
                self._reject_query(query)
                self._optional_zero_length()
                self._send_json(200, service.inspect())
                return
            if (len(parts) == 4 and parts[0] == "v1" and parts[1] == "card"
                    and parts[3] == "identity"):
                self._reject_query(query)
                self._optional_zero_length()
                session_id = self._session_id(parts[2])
                self._send_json(200, service.card_identity(session_id))
                return
            if (len(parts) == 4 and parts[0] == "v1" and parts[1] == "card"
                    and parts[3] == "read"):
                session_id = self._session_id(parts[2])
                params = self._query(query, ("offset", "bytes"))
                self._optional_zero_length()
                data = service.card_read(
                    session_id, params["offset"], params["bytes"]
                )
                self._send_binary(data)
                return
            raise TfError("not-found", "unknown path", 404)

        def _route_post(self, parts: list, query: str) -> None:
            if parts == ["v1", "card", "open"]:
                self._reject_query(query)
                request = parse_open_payload(self._read_json_object())
                self._send_json(200, service.open_card(**request))
                return
            if (len(parts) == 4 and parts[0] == "v1" and parts[1] == "card"
                    and parts[3] == "write"):
                session_id = self._session_id(parts[2])
                params = self._query(query, ("offset",))
                offset = params["offset"]
                length = self._content_length()
                if length > BINARY_MAX_BYTES:
                    raise TfError("body-too-large", "body exceeds 1 MiB", 413)
                self._require_media_type("application/octet-stream")
                expected = self._content_sha256()
                body = self._read_exact_body(length)
                actual = hashlib.sha256(body).hexdigest()
                if not hmac.compare_digest(actual, expected):
                    raise TfError(
                        "hash-mismatch",
                        "the body digest does not match X-Content-SHA256",
                        400,
                    )
                written = service.card_write(session_id, offset, body)
                self._send_json(200, {
                    "schemaVersion": SCHEMA_VERSION,
                    "writtenBytes": written,
                    "sha256": actual,
                })
                return
            if (len(parts) == 4 and parts[0] == "v1" and parts[1] == "card"
                    and parts[3] == "flush"):
                self._reject_query(query)
                self._optional_zero_length()
                session_id = self._session_id(parts[2])
                self._send_json(200, service.card_flush(session_id))
                return
            raise TfError("not-found", "unknown path", 404)

        def _route_delete(self, parts: list, query: str) -> None:
            if (len(parts) == 3 and parts[0] == "v1" and parts[1] == "card"):
                self._reject_query(query)
                self._optional_zero_length()
                session_id = self._session_id(parts[2])
                self._send_json(200, service.card_close(session_id))
                return
            raise TfError("not-found", "unknown path", 404)

    return _TfHandler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def serve() -> int:
    """Run the fixed service until stopped. CLI contract: armada_tf.py serve."""

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("armada-tf: root privileges are required", file=sys.stderr)
        return 2
    service = TfService()
    try:
        service.load_runtime()
        token = load_token(TOKEN_PATH)
    except TfError as exc:
        print(f"armada-tf: startup rejected ({exc.code})", file=sys.stderr)
        return 2
    handler = make_http_handler(service, token)
    try:
        server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), handler)
    except OSError:
        print(f"armada-tf: cannot bind {BIND_HOST}:{BIND_PORT}", file=sys.stderr)
        return 2
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.close_all()
        server.server_close()
    return 0


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["serve"]:
        print("usage: armada_tf.py serve", file=sys.stderr)
        return 2
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
