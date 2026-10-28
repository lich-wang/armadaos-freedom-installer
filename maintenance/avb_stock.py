"""AVB stock-boot validation API (stage 1: implemented stock validator).

This module defines the contract used to decide whether a device still carries
its factory (``stock``) boot chain before the device is treated as eligible for
an uninstall flow.  The public surface is unchanged from the RED stage; the
body of :func:`validate_stock_boot` now performs the authentication described
below with the standard library only.

Trust model notes
-----------------
``BASELINE_VBMETA_SHA256`` pins the SHA-256 of a ``vbmeta`` image saved from the
very same physical device during an earlier collection run (the
``..._1.5.10.259_...`` build).  That saved copy is an *operational local trust
anchor*: it is compared against the caller-supplied ``trusted_baseline`` bytes
so that a swapped or corrupted baseline is rejected.  It is **not** an
independently authenticated Lenovo root of trust, and this module makes no
statement about Lenovo key provenance beyond "the bytes match the saved local
copy and the embedded signatures verify under the key carried in that copy".

Hardware rollback indexes are **not** verified by this API.  The rollback
values reported in :class:`StockBootEvidence` are the values read out of the
authenticated structures; no hardware fuses, RPMB counters, or device-side
anti-rollback state are consulted.  Callers must not treat
``hardware_rollback_verified`` as proof of anti-rollback protection.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, replace
from typing import BinaryIO, Iterator, Optional, Tuple


__all__ = [
    "BASELINE_VBMETA_SHA256",
    "SignedBootMetadata",
    "StockBootEvidence",
    "StockBootValidationError",
    "inspect_signed_boot_metadata",
    "validate_restore_candidate",
    "validate_stock_boot",
]


#: SHA-256 of the saved same-device ``vbmeta`` baseline (build 1.5.10.259).
BASELINE_VBMETA_SHA256 = (
    "55929c1580d437ad9d5f43e897c37f0d6aa1f1469ffb8ede5928f4b43387f387"
)

#: Saved-pair pins for the local build-1.5.10.259 restore candidate.  The
#: ``slot_vbmeta`` pin is the same saved copy as the baseline anchor above.
_SAVED_PAIR_MODEL = "TB322FC"
_SAVED_PAIR_FINGERPRINT = (
    "Lenovo/TB322FC_PRC/TB322FC:16/BQ2A.250610.001-BP2A.250605.031.A3/"
    "ZUXOS_1.5.10.259_260611_PRC:user/release-keys"
)
_SAVED_PAIR_STOCK_SHA256 = (
    "b428a31dadc5db3f91620c1f4114f5ee7702e34e0789ed9bf84a878a49898f20"
)

_PROOF_SAVED_BASELINE_PAIR = "saved-baseline-pair"
_PROOF_SIGNED_CURRENT = "signed-current"

_AVB_MAGIC = b"AVB0"
_AVB_FOOTER_MAGIC = b"AVBf"
_AVB_HEADER_SIZE = 256
_AVB_FOOTER_SIZE = 64
_AVB_BLOCK_ALIGNMENT = 64
_AVB_SUPPORTED_MAJOR = 1
_AVB_MAX_MINOR = 3

_ANDROID_MAGIC = b"ANDROID!"
_ANDROID_HEADER_SIZE = 1584
_ANDROID_HEADER_VERSION = 4
_ANDROID_KERNEL_SIZE_OFFSET = 8
_ANDROID_RAMDISK_SIZE_OFFSET = 12
_ANDROID_HEADER_SIZE_OFFSET = 20
_ANDROID_HEADER_VERSION_OFFSET = 40
_ANDROID_SIGNATURE_SIZE_OFFSET = 1580
_BOOT_PAGE_SIZE = 4096

_DESCRIPTOR_HEADER_SIZE = 16
_DESCRIPTOR_ALIGNMENT = 8
_TAG_PROPERTY = 0
_TAG_HASH = 2
_TAG_CHAIN_PARTITION = 4

_CHAIN_DESCRIPTOR_FIXED_SIZE = 92
_HASH_DESCRIPTOR_FIXED_SIZE = 132
_PROPERTY_DESCRIPTOR_FIXED_SIZE = 32

_BOOT_PARTITION_NAME = "boot"

_PROPERTY_FINGERPRINT = "com.android.build.boot.fingerprint"
_PROPERTY_OS_VERSION = "com.android.build.boot.os_version"
_PROPERTY_SECURITY_PATCH = "com.android.build.boot.security_patch"
_REQUIRED_PROPERTIES = (
    _PROPERTY_FINGERPRINT,
    _PROPERTY_OS_VERSION,
    _PROPERTY_SECURITY_PATCH,
)

#: AVB algorithm id -> (RSA modulus bits, hash digest size in bytes).
_RSA_ALGORITHMS = {
    1: (2048, 32),
    2: (4096, 32),
    3: (8192, 32),
    4: (2048, 64),
    5: (4096, 64),
    6: (8192, 64),
}

#: Exponent used by every AVB RSA key (fixed, never read from the key blob).
_RSA_PUBLIC_EXPONENT = 65537
_KEY_BLOB_OVERHEAD = 8
_KEY_BLOB_BITS = {
    _KEY_BLOB_OVERHEAD + 2 * (bits // 8): bits
    for bits, _digest in _RSA_ALGORITHMS.values()
}

#: PKCS#1 v1.5 DigestInfo prefixes for the two AVB digests.
_DIGEST_INFO_PREFIX = {
    32: bytes.fromhex("3031300d060960864801650304020105000420"),
    64: bytes.fromhex("3051300d060960864801650304020305000440"),
}
_HASH_NAMES = {32: "sha256", 64: "sha512"}
_HASH_DESCRIPTOR_ALGORITHMS = {"sha256": 32, "sha512": 64}
_MIN_SIGNATURE_PADDING = 8
_HASH_CHUNK_SIZE = 1024 * 1024


class StockBootValidationError(ValueError):
    """Raised when stock boot evidence cannot be authenticated or trusted.

    Every rejection path of :func:`validate_stock_boot` uses this single
    exception type; callers are expected to treat it as "not stock" rather than
    branching on messages, which are not part of the contract.
    """


@dataclass(frozen=True)
class StockBootEvidence:
    """Authenticated facts about a device's stock boot chain.

    ``hardware_rollback_verified`` is always ``False`` in this API version:
    rollback indexes are reported, never verified against hardware state.
    ``proof`` is empty by default and names the authentication route that
    produced the evidence when :func:`validate_restore_candidate` returns it.
    """

    slot: str
    stock_sha256: str
    fingerprint: str
    os_version: str
    security_patch: str
    root_key_sha256: str
    chain_key_sha256: str
    boot_rollback_index: int
    boot_rollback_index_location: int
    slot_vbmeta_rollback_index: int
    slot_vbmeta_rollback_index_location: int
    hardware_rollback_verified: bool = False
    proof: str = ""


def _reject(message: str) -> None:
    """Raise the single public rejection type."""
    raise StockBootValidationError(message)


# ---------------------------------------------------------------------------
# Primitive field readers
# ---------------------------------------------------------------------------


def _u32be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        _reject("truncated 32-bit big-endian field at offset %d" % offset)
    return int.from_bytes(data[offset:offset + 4], "big")


def _u64be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        _reject("truncated 64-bit big-endian field at offset %d" % offset)
    return int.from_bytes(data[offset:offset + 8], "big")


def _u32le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        _reject("truncated 32-bit little-endian field at offset %d" % offset)
    return int.from_bytes(data[offset:offset + 4], "little")


def _round_up(value: int, unit: int) -> int:
    return (value + unit - 1) // unit * unit


def _decode_text(raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StockBootValidationError(
            "%s is not valid UTF-8: %s" % (what, exc)
        ) from exc


# ---------------------------------------------------------------------------
# AVB vbmeta header
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _VbmetaHeader:
    """Decoded fixed-size AVB header (all integer fields big-endian)."""

    major: int
    minor: int
    auth_size: int
    aux_size: int
    algorithm: int
    hash_offset: int
    hash_size: int
    signature_offset: int
    signature_size: int
    key_offset: int
    key_size: int
    key_metadata_offset: int
    key_metadata_size: int
    descriptors_offset: int
    descriptors_size: int
    rollback_index: int
    flags: int
    rollback_location: int

    @property
    def aux_start(self) -> int:
        return _AVB_HEADER_SIZE + self.auth_size

    @property
    def total_size(self) -> int:
        return _AVB_HEADER_SIZE + self.auth_size + self.aux_size


@dataclass(frozen=True)
class _Vbmeta:
    """An authenticated vbmeta image with its signed auxiliary block."""

    header: _VbmetaHeader
    aux: bytes
    key_blob: bytes
    total_size: int


def _parse_header(data: bytes, where: str) -> _VbmetaHeader:
    """Decode and sanity-check the fixed AVB header at the start of ``data``."""
    if len(data) < _AVB_HEADER_SIZE:
        _reject("%s: AVB header is shorter than 256 bytes" % where)
    if data[0:4] != _AVB_MAGIC:
        _reject("%s: bad AVB magic" % where)

    major = _u32be(data, 4)
    minor = _u32be(data, 8)
    if major != _AVB_SUPPORTED_MAJOR or minor > _AVB_MAX_MINOR:
        _reject("%s: unsupported AVB version %d.%d" % (where, major, minor))

    auth_size = _u64be(data, 12)
    aux_size = _u64be(data, 20)
    algorithm = _u32be(data, 28)
    hash_offset = _u64be(data, 32)
    hash_size = _u64be(data, 40)
    signature_offset = _u64be(data, 48)
    signature_size = _u64be(data, 56)
    key_offset = _u64be(data, 64)
    key_size = _u64be(data, 72)
    key_metadata_offset = _u64be(data, 80)
    key_metadata_size = _u64be(data, 88)
    descriptors_offset = _u64be(data, 96)
    descriptors_size = _u64be(data, 104)
    rollback_index = _u64be(data, 112)
    flags = _u32be(data, 120)
    rollback_location = _u32be(data, 124)

    if auth_size == 0 or aux_size == 0:
        _reject("%s: empty authentication or auxiliary block" % where)
    if auth_size % _AVB_BLOCK_ALIGNMENT or aux_size % _AVB_BLOCK_ALIGNMENT:
        _reject("%s: authentication or auxiliary block is not 64-byte aligned"
                % where)
    if algorithm not in _RSA_ALGORITHMS:
        _reject("%s: unsupported or NONE AVB algorithm %d" % (where, algorithm))
    if flags != 0:
        _reject("%s: AVB header flags are not zero" % where)

    return _VbmetaHeader(
        major=major,
        minor=minor,
        auth_size=auth_size,
        aux_size=aux_size,
        algorithm=algorithm,
        hash_offset=hash_offset,
        hash_size=hash_size,
        signature_offset=signature_offset,
        signature_size=signature_size,
        key_offset=key_offset,
        key_size=key_size,
        key_metadata_offset=key_metadata_offset,
        key_metadata_size=key_metadata_size,
        descriptors_offset=descriptors_offset,
        descriptors_size=descriptors_size,
        rollback_index=rollback_index,
        flags=flags,
        rollback_location=rollback_location,
    )


def _check_region(offset: int, size: int, region_size: int, what: str) -> None:
    """Require ``[offset, offset + size)`` to fit inside a signed region."""
    if offset > region_size or size > region_size - offset:
        _reject("%s: field range lies outside its signed region" % what)


def _validate_layout(header: _VbmetaHeader, where: str) -> None:
    """Cross-check the header's regions against the declared algorithm."""
    bits, digest_size = _RSA_ALGORITHMS[header.algorithm]
    key_bytes = bits // 8

    if header.hash_size != digest_size:
        _reject("%s: authentication hash size does not match the algorithm"
                % where)
    if header.signature_size != key_bytes:
        _reject("%s: signature size does not match the algorithm" % where)
    if header.key_size != _KEY_BLOB_OVERHEAD + 2 * key_bytes:
        _reject("%s: public key size does not match the algorithm" % where)
    if header.descriptors_size % _DESCRIPTOR_ALIGNMENT:
        _reject("%s: descriptors block is not 8-byte aligned" % where)

    _check_region(header.hash_offset, header.hash_size, header.auth_size,
                  "%s: authentication hash" % where)
    _check_region(header.signature_offset, header.signature_size,
                  header.auth_size, "%s: authentication signature" % where)
    _check_region(header.key_offset, header.key_size, header.aux_size,
                  "%s: public key" % where)
    _check_region(header.key_metadata_offset, header.key_metadata_size,
                  header.aux_size, "%s: public key metadata" % where)
    _check_region(header.descriptors_offset, header.descriptors_size,
                  header.aux_size, "%s: descriptors" % where)


# ---------------------------------------------------------------------------
# RSA key blobs and PKCS#1 v1.5 signatures
# ---------------------------------------------------------------------------


def _key_bits_for_blob_length(length: int, where: str) -> int:
    bits = _KEY_BLOB_BITS.get(length)
    if bits is None:
        _reject("%s: unsupported public key blob length %d" % (where, length))
    return bits


def _parse_key_blob(blob: bytes, bits: int, where: str) -> int:
    """Validate an AVB ``RSAPublicKey`` blob and return its modulus.

    Layout: ``num_bits`` (u32 big-endian), ``n0inv`` (u32 big-endian),
    ``modulus`` (``bits / 8`` bytes) and ``rr`` (``bits / 8`` bytes).
    """
    key_bytes = bits // 8
    if len(blob) != _KEY_BLOB_OVERHEAD + 2 * key_bytes:
        _reject("%s: public key blob length does not match its algorithm"
                % where)
    if _u32be(blob, 0) != bits:
        _reject("%s: public key declares a different modulus size" % where)
    modulus = int.from_bytes(blob[8:8 + key_bytes], "big")
    if modulus <= 0 or modulus % 2 == 0:
        _reject("%s: RSA modulus is not a positive odd integer" % where)
    if modulus.bit_length() != bits:
        _reject("%s: RSA modulus is shorter than expected" % where)
    return modulus


def _verify_auth_block(blob: bytes, header: _VbmetaHeader, modulus: int,
                       where: str) -> None:
    """Verify the signed digest and the RSA PKCS#1 v1.5 signature."""
    digest_size = _RSA_ALGORITHMS[header.algorithm][1]
    key_bytes = _RSA_ALGORITHMS[header.algorithm][0] // 8
    hash_name = _HASH_NAMES[digest_size]

    auth_start = _AVB_HEADER_SIZE
    stored_hash = blob[auth_start + header.hash_offset:
                       auth_start + header.hash_offset + header.hash_size]
    signed_bytes = (blob[0:_AVB_HEADER_SIZE]
                    + blob[header.aux_start:header.aux_start + header.aux_size])
    computed_hash = hashlib.new(hash_name, signed_bytes).digest()
    if not hmac.compare_digest(stored_hash, computed_hash):
        _reject("%s: signed digest does not match header and aux data" % where)

    signature = blob[auth_start + header.signature_offset:
                     auth_start + header.signature_offset
                     + header.signature_size]
    signature_value = int.from_bytes(signature, "big")
    if not 0 < signature_value < modulus:
        _reject("%s: signature value is out of range" % where)

    encoded = pow(signature_value, _RSA_PUBLIC_EXPONENT, modulus)
    encoded_bytes = encoded.to_bytes(key_bytes, "big")

    prefix = _DIGEST_INFO_PREFIX[digest_size]
    padding_size = key_bytes - len(prefix) - digest_size - 3
    if padding_size < _MIN_SIGNATURE_PADDING:
        _reject("%s: encoded signature block is too small" % where)
    expected = (b"\x00\x01" + b"\xff" * padding_size + b"\x00"
                + prefix + computed_hash)
    if not hmac.compare_digest(encoded_bytes, expected):
        _reject("%s: RSA signature does not verify" % where)


def _authenticate_vbmeta(blob: bytes, required_key: Optional[bytes],
                         where: str) -> _Vbmeta:
    """Parse, constrain and cryptographically verify one vbmeta image."""
    header = _parse_header(blob, where)
    _validate_layout(header, where)
    if len(blob) < header.total_size:
        _reject("%s: vbmeta data is shorter than its declared blocks" % where)

    aux = blob[header.aux_start:header.aux_start + header.aux_size]
    key_blob = aux[header.key_offset:header.key_offset + header.key_size]
    if required_key is not None and not hmac.compare_digest(key_blob,
                                                            required_key):
        _reject("%s: public key is not the authorised chain key" % where)

    bits = _RSA_ALGORITHMS[header.algorithm][0]
    modulus = _parse_key_blob(key_blob, bits, where)
    _verify_auth_block(blob, header, modulus, where)

    return _Vbmeta(header=header, aux=aux, key_blob=key_blob,
                   total_size=header.total_size)


# ---------------------------------------------------------------------------
# AVB descriptors
# ---------------------------------------------------------------------------


def _walk_descriptors(vbmeta: _Vbmeta,
                      where: str) -> Iterator[Tuple[int, bytes]]:
    """Yield ``(tag, descriptor_bytes)`` and consume the block exactly."""
    header = vbmeta.header
    aux = vbmeta.aux
    position = header.descriptors_offset
    end = position + header.descriptors_size

    while position < end:
        remaining = end - position
        if remaining < _DESCRIPTOR_HEADER_SIZE:
            _reject("%s: truncated descriptor header" % where)
        tag = int.from_bytes(aux[position:position + 8], "big")
        following = int.from_bytes(aux[position + 8:position + 16], "big")
        total = _DESCRIPTOR_HEADER_SIZE + following
        if total > remaining:
            _reject("%s: descriptor overruns the signed descriptors block"
                    % where)
        if total % _DESCRIPTOR_ALIGNMENT:
            _reject("%s: descriptor is not 8-byte aligned" % where)
        yield tag, aux[position:position + total]
        position += total


def _parse_property_descriptor(body: bytes,
                               where: str) -> Tuple[str, str]:
    if len(body) < _PROPERTY_DESCRIPTOR_FIXED_SIZE:
        _reject("%s: truncated property descriptor" % where)
    key_length = _u64be(body, 16)
    value_length = _u64be(body, 24)

    key_start = _PROPERTY_DESCRIPTOR_FIXED_SIZE
    value_start = key_start + key_length + 1
    expected = value_start + value_length + 1
    padded = _round_up(expected, _DESCRIPTOR_ALIGNMENT)
    if len(body) != padded:
        _reject("%s: property descriptor length is inconsistent" % where)

    key_bytes = body[key_start:key_start + key_length]
    if key_length == 0 or body[key_start + key_length] != 0:
        _reject("%s: property key is empty or unterminated" % where)
    value_bytes = body[value_start:value_start + value_length]
    if body[value_start + value_length] != 0:
        _reject("%s: property value is unterminated" % where)
    if any(body[expected:]):
        _reject("%s: property descriptor has non-zero padding" % where)

    return (_decode_text(key_bytes, "%s: property key" % where),
            _decode_text(value_bytes, "%s: property value" % where))


def _parse_chain_descriptor(
        body: bytes, where: str) -> Tuple[str, int, int, bytes]:
    if len(body) < _CHAIN_DESCRIPTOR_FIXED_SIZE:
        _reject("%s: truncated chain partition descriptor" % where)
    rollback_location = _u32be(body, 16)
    name_length = _u32be(body, 20)
    key_length = _u32be(body, 24)
    flags = _u32be(body, 28)
    if any(body[32:_CHAIN_DESCRIPTOR_FIXED_SIZE]):
        _reject("%s: chain descriptor reserved bytes are not zero" % where)

    name_start = _CHAIN_DESCRIPTOR_FIXED_SIZE
    key_start = name_start + name_length
    expected = key_start + key_length
    padded = _round_up(expected, _DESCRIPTOR_ALIGNMENT)
    if len(body) != padded:
        _reject("%s: chain descriptor length is inconsistent" % where)
    if any(body[expected:]):
        _reject("%s: chain descriptor has non-zero padding" % where)

    name = _decode_text(body[name_start:key_start],
                        "%s: chain partition name" % where)
    if not name:
        _reject("%s: chain partition name is empty" % where)
    key_blob = body[key_start:expected]
    bits = _key_bits_for_blob_length(len(key_blob), where)
    _parse_key_blob(key_blob, bits, where)
    return name, flags, rollback_location, key_blob


def _parse_hash_descriptor(body: bytes, where: str) -> dict:
    if len(body) < _HASH_DESCRIPTOR_FIXED_SIZE:
        _reject("%s: truncated hash descriptor" % where)
    image_size = _u64be(body, 16)
    algorithm_field = body[24:56]
    name_length = _u32be(body, 56)
    salt_length = _u32be(body, 60)
    digest_length = _u32be(body, 64)
    flags = _u32be(body, 68)
    if any(body[72:_HASH_DESCRIPTOR_FIXED_SIZE]):
        _reject("%s: hash descriptor reserved bytes are not zero" % where)

    trimmed = algorithm_field.rstrip(b"\x00")
    if not trimmed or b"\x00" in trimmed:
        _reject("%s: malformed hash descriptor algorithm name" % where)
    try:
        algorithm_name = trimmed.decode("ascii")
    except UnicodeDecodeError as exc:
        raise StockBootValidationError(
            "%s: hash descriptor algorithm is not ASCII" % where
        ) from exc
    if algorithm_name not in _HASH_DESCRIPTOR_ALGORITHMS:
        _reject("%s: unsupported hash descriptor algorithm %r"
                % (where, algorithm_name))
    if digest_length != _HASH_DESCRIPTOR_ALGORITHMS[algorithm_name]:
        _reject("%s: hash descriptor digest length does not match its algorithm"
                % where)

    name_start = _HASH_DESCRIPTOR_FIXED_SIZE
    salt_start = name_start + name_length
    digest_start = salt_start + salt_length
    expected = digest_start + digest_length
    padded = _round_up(expected, _DESCRIPTOR_ALIGNMENT)
    if len(body) != padded:
        _reject("%s: hash descriptor length is inconsistent" % where)
    if any(body[expected:]):
        _reject("%s: hash descriptor has non-zero padding" % where)

    name = _decode_text(body[name_start:salt_start],
                        "%s: hash descriptor name" % where)
    if not name:
        _reject("%s: hash descriptor name is empty" % where)
    return {
        "name": name,
        "flags": flags,
        "image_size": image_size,
        "algorithm": algorithm_name,
        "salt": body[salt_start:digest_start],
        "digest": body[digest_start:expected],
    }


def _select_boot_chain(vbmeta: _Vbmeta,
                       where: str) -> Tuple[int, bytes]:
    """Return ``(rollback_location, chain_key_blob)`` for the boot partition."""
    found: Optional[Tuple[int, bytes]] = None
    for tag, body in _walk_descriptors(vbmeta, where):
        if tag != _TAG_CHAIN_PARTITION:
            continue
        name, flags, rollback_location, key_blob = _parse_chain_descriptor(
            body, where)
        if name != _BOOT_PARTITION_NAME:
            continue
        if found is not None:
            _reject("%s: duplicate boot chain partition descriptors" % where)
        if flags != 0:
            _reject("%s: boot chain descriptor flags are not zero" % where)
        found = (rollback_location, key_blob)
    if found is None:
        _reject("%s: boot chain partition descriptor is missing" % where)
    return found


def _select_boot_hash(vbmeta: _Vbmeta, where: str) -> dict:
    found: Optional[dict] = None
    for tag, body in _walk_descriptors(vbmeta, where):
        if tag != _TAG_HASH:
            continue
        descriptor = _parse_hash_descriptor(body, where)
        if descriptor["name"] != _BOOT_PARTITION_NAME:
            continue
        if found is not None:
            _reject("%s: duplicate boot hash descriptors" % where)
        if descriptor["flags"] != 0:
            _reject("%s: boot hash descriptor flags are not zero" % where)
        found = descriptor
    if found is None:
        _reject("%s: boot hash descriptor is missing" % where)
    return found


def _select_required_properties(vbmeta: _Vbmeta, where: str) -> dict:
    found: dict = {}
    for tag, body in _walk_descriptors(vbmeta, where):
        if tag != _TAG_PROPERTY:
            continue
        key, value = _parse_property_descriptor(body, where)
        if key not in _REQUIRED_PROPERTIES:
            continue
        if key in found:
            _reject("%s: duplicate %s property" % (where, key))
        if not value:
            _reject("%s: %s property is empty" % (where, key))
        found[key] = value
    missing = [key for key in _REQUIRED_PROPERTIES if key not in found]
    if missing:
        _reject("%s: missing required boot properties: %s"
                % (where, ", ".join(missing)))
    return found


def _model_from_fingerprint(fingerprint: str, where: str) -> str:
    """Return the model component of an ``a/b/model:release/...`` fingerprint."""
    parts = fingerprint.split("/")
    if len(parts) < 3 or ":" not in parts[2]:
        _reject("%s: fingerprint is not a build fingerprint" % where)
    model = parts[2].split(":", 1)[0]
    if not model:
        _reject("%s: fingerprint carries an empty model" % where)
    return model


# ---------------------------------------------------------------------------
# Raw boot stream
# ---------------------------------------------------------------------------


def _stream_size(boot: BinaryIO, where: str) -> int:
    try:
        boot.seek(0, os.SEEK_END)
        size = boot.tell()
    except Exception as exc:  # noqa: BLE001 - stream contract violation
        raise StockBootValidationError(
            "%s: boot stream is not seekable: %s" % (where, exc)
        ) from exc
    if not isinstance(size, int) or size < 0:
        _reject("%s: boot stream reports an invalid size" % where)
    return size


def _read_exact(boot: BinaryIO, offset: int, length: int, where: str) -> bytes:
    """Read exactly ``length`` bytes at ``offset``; short reads are fatal."""
    if length <= 0:
        _reject("%s: zero-length read requested" % where)
    try:
        boot.seek(offset)
    except Exception as exc:  # noqa: BLE001 - stream contract violation
        raise StockBootValidationError(
            "%s: boot stream is not seekable: %s" % (where, exc)
        ) from exc

    chunks = []
    remaining = length
    while remaining:
        try:
            chunk = boot.read(remaining)
        except Exception as exc:  # noqa: BLE001 - stream contract violation
            raise StockBootValidationError(
                "%s: boot stream read failed: %s" % (where, exc)
            ) from exc
        if not chunk:
            _reject("%s: boot stream ended before %d bytes could be read"
                    % (where, offset + length))
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_android_header(data: bytes, where: str) -> int:
    """Validate the Android boot header and return the body extent."""
    if len(data) < _ANDROID_HEADER_SIZE:
        _reject("%s: Android boot header is truncated" % where)
    if data[0:8] != _ANDROID_MAGIC:
        _reject("%s: bad Android boot magic" % where)

    kernel_size = _u32le(data, _ANDROID_KERNEL_SIZE_OFFSET)
    ramdisk_size = _u32le(data, _ANDROID_RAMDISK_SIZE_OFFSET)
    header_size = _u32le(data, _ANDROID_HEADER_SIZE_OFFSET)
    header_version = _u32le(data, _ANDROID_HEADER_VERSION_OFFSET)
    signature_size = _u32le(data, _ANDROID_SIGNATURE_SIZE_OFFSET)

    if header_size != _ANDROID_HEADER_SIZE:
        _reject("%s: unexpected Android header size %d" % (where, header_size))
    if header_version != _ANDROID_HEADER_VERSION:
        _reject("%s: unsupported Android header version %d"
                % (where, header_version))
    if kernel_size == 0:
        _reject("%s: Android kernel payload is empty" % where)

    return (_BOOT_PAGE_SIZE
            + _round_up(kernel_size, _BOOT_PAGE_SIZE)
            + _round_up(ramdisk_size, _BOOT_PAGE_SIZE)
            + signature_size)


@dataclass(frozen=True)
class _AvbFooter:
    original_image_size: int
    vbmeta_offset: int
    vbmeta_size: int


def _parse_footer(data: bytes, raw_size: int, where: str) -> _AvbFooter:
    if len(data) != _AVB_FOOTER_SIZE:
        _reject("%s: AVB footer is truncated" % where)
    if data[0:4] != _AVB_FOOTER_MAGIC:
        _reject("%s: bad AVB footer magic" % where)
    major = _u32be(data, 4)
    minor = _u32be(data, 8)
    if major != _AVB_SUPPORTED_MAJOR or minor != 0:
        _reject("%s: unsupported AVB footer version %d.%d"
                % (where, major, minor))
    if any(data[36:_AVB_FOOTER_SIZE]):
        _reject("%s: AVB footer reserved bytes are not zero" % where)

    original_size = _u64be(data, 12)
    vbmeta_offset = _u64be(data, 20)
    vbmeta_size = _u64be(data, 28)

    if original_size <= 0 or original_size > vbmeta_offset:
        _reject("%s: AVB footer image bounds are inconsistent" % where)
    if vbmeta_size < _AVB_HEADER_SIZE:
        _reject("%s: AVB footer declares a truncated vbmeta" % where)
    if vbmeta_offset + vbmeta_size > raw_size - _AVB_FOOTER_SIZE:
        _reject("%s: AVB footer vbmeta range leaves the partition" % where)

    return _AvbFooter(original_image_size=original_size,
                      vbmeta_offset=vbmeta_offset,
                      vbmeta_size=vbmeta_size)


def _load_embedded_vbmeta(boot: BinaryIO, footer: _AvbFooter, raw_size: int,
                          chain_key: bytes) -> _Vbmeta:
    """Read the bounded embedded vbmeta and authenticate it with ``chain_key``."""
    where = "embedded vbmeta"
    prefix = _read_exact(boot, footer.vbmeta_offset, _AVB_HEADER_SIZE, where)
    header = _parse_header(prefix, where)
    _validate_layout(header, where)

    actual_size = header.total_size
    if actual_size != footer.vbmeta_size:
        _reject("%s: size does not match the AVB footer declaration" % where)
    if footer.vbmeta_offset + actual_size > raw_size - _AVB_FOOTER_SIZE:
        _reject("%s: range overlaps the AVB footer" % where)

    blob = _read_exact(boot, footer.vbmeta_offset, actual_size, where)
    return _authenticate_vbmeta(blob, chain_key, where)


def _hash_partition(boot: BinaryIO, partition_size: int, image_size: int,
                    salt: bytes, hash_name: str) -> Tuple[str, bytes]:
    """Return the partition SHA-256 hex and the salted boot payload digest."""
    salted = hashlib.new(hash_name)
    salted.update(salt)
    overall = hashlib.sha256()

    position = 0
    while position < partition_size:
        take = min(_HASH_CHUNK_SIZE, partition_size - position)
        block = _read_exact(boot, position, take, "boot partition")
        overall.update(block)
        if position < image_size:
            used = min(take, image_size - position)
            salted.update(block[:used])
        position += take

    return overall.hexdigest(), salted.digest()


def _stream_sha256(boot: BinaryIO, size: int, where: str) -> str:
    """Return the whole-stream SHA-256 without materialising the data."""
    digest = hashlib.sha256()
    position = 0
    while position < size:
        take = min(_HASH_CHUNK_SIZE, size - position)
        digest.update(_read_exact(boot, position, take, where))
        position += take
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def _validate_slot(slot: object) -> str:
    if not isinstance(slot, str) or slot not in ("a", "b"):
        _reject("slot must be 'a' or 'b'")
    return slot


def _require_text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        _reject("%s must be a non-empty string" % what)
    if value.strip() != value:
        _reject("%s must not carry surrounding whitespace" % what)
    return value


def _require_bytes(value: object, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        _reject("%s must be bytes-like" % what)
    data = bytes(value)
    if not data:
        _reject("%s must not be empty" % what)
    return data


def _validate_request(slot, expected_model, expected_fingerprint,
                      partition_size, slot_vbmeta, trusted_baseline):
    slot = _validate_slot(slot)
    expected_model = _require_text(expected_model, "expected_model")
    expected_fingerprint = _require_text(expected_fingerprint,
                                         "expected_fingerprint")
    _model_from_fingerprint(expected_fingerprint, "expected_fingerprint")

    if isinstance(partition_size, bool) or not isinstance(partition_size, int):
        _reject("partition_size must be an integer")
    if partition_size <= 0:
        _reject("partition_size must be positive")

    return (slot, expected_model, expected_fingerprint, partition_size,
            _require_bytes(slot_vbmeta, "slot_vbmeta"),
            _require_bytes(trusted_baseline, "trusted_baseline"))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _validate_chain(boot: BinaryIO, slot_vbmeta: bytes,
                    trusted_baseline: bytes, slot: str, expected_model: str,
                    expected_fingerprint: str,
                    partition_size: int) -> StockBootEvidence:
    baseline_digest = hashlib.sha256(trusted_baseline).hexdigest()
    if not hmac.compare_digest(baseline_digest, BASELINE_VBMETA_SHA256):
        _reject("trusted baseline does not match the pinned device SHA-256")

    root = _authenticate_vbmeta(trusted_baseline, None, "trusted baseline")
    slot_image = _authenticate_vbmeta(slot_vbmeta, root.key_blob,
                                      "slot vbmeta")
    chain_location, chain_key = _select_boot_chain(slot_image, "slot vbmeta")

    raw_size = _stream_size(boot, "boot partition")
    if raw_size != partition_size:
        _reject("boot partition size %d does not match the expected %d"
                % (raw_size, partition_size))

    android_header = _read_exact(boot, 0, _ANDROID_HEADER_SIZE, "boot image")
    body_extent = _parse_android_header(android_header, "boot image")

    footer = _parse_footer(_read_exact(boot, raw_size - _AVB_FOOTER_SIZE,
                                       _AVB_FOOTER_SIZE, "boot footer"),
                           raw_size, "boot footer")
    if body_extent > footer.original_image_size:
        _reject("Android boot body overruns the signed image size")
    if body_extent > raw_size:
        _reject("Android boot body overruns the raw partition")

    embedded = _load_embedded_vbmeta(boot, footer, raw_size, chain_key)

    hash_descriptor = _select_boot_hash(embedded, "embedded vbmeta")
    if hash_descriptor["image_size"] != footer.original_image_size:
        _reject("boot hash descriptor image size disagrees with the footer")
    if hash_descriptor["image_size"] > raw_size:
        _reject("boot hash descriptor image overruns the raw partition")

    stock_sha256, salted_digest = _hash_partition(
        boot,
        partition_size,
        hash_descriptor["image_size"],
        hash_descriptor["salt"],
        hash_descriptor["algorithm"],
    )
    if not hmac.compare_digest(salted_digest, hash_descriptor["digest"]):
        _reject("boot payload does not match the signed salted hash")

    properties = _select_required_properties(embedded, "embedded vbmeta")
    fingerprint = properties[_PROPERTY_FINGERPRINT]
    os_version = properties[_PROPERTY_OS_VERSION]
    security_patch = properties[_PROPERTY_SECURITY_PATCH]

    if fingerprint != expected_fingerprint:
        _reject("signed fingerprint does not match the expected fingerprint")
    signed_model = _model_from_fingerprint(fingerprint, "signed fingerprint")
    if signed_model != expected_model:
        _reject("signed fingerprint model %r is not the expected model"
                % signed_model)

    return StockBootEvidence(
        slot=slot,
        stock_sha256=stock_sha256,
        fingerprint=fingerprint,
        os_version=os_version,
        security_patch=security_patch,
        root_key_sha256=hashlib.sha256(root.key_blob).hexdigest(),
        chain_key_sha256=hashlib.sha256(chain_key).hexdigest(),
        boot_rollback_index=embedded.header.rollback_index,
        boot_rollback_index_location=chain_location,
        slot_vbmeta_rollback_index=slot_image.header.rollback_index,
        slot_vbmeta_rollback_index_location=slot_image.header.rollback_location,
    )


def validate_stock_boot(
    boot: BinaryIO,
    slot_vbmeta: bytes,
    trusted_baseline: bytes,
    slot: str,
    expected_model: str,
    expected_fingerprint: str,
    partition_size: int,
) -> StockBootEvidence:
    """Validate a stock boot chain and return the authenticated evidence.

    Parameters
    ----------
    boot:
        Readable, seekable binary stream over the full raw boot partition.
        Ownership stays with the caller: the implementation must not close it
        and restores the original stream position when it can.
    slot_vbmeta:
        Raw bytes of the slot ``vbmeta`` image to authenticate.
    trusted_baseline:
        Raw bytes of the saved same-device baseline ``vbmeta`` copy; its
        SHA-256 must equal :data:`BASELINE_VBMETA_SHA256`.
    slot:
        Slot suffix under test (``"a"`` or ``"b"``).
    expected_model:
        Device model that the signed boot chain must carry.
    expected_fingerprint:
        Exact build fingerprint the signed boot chain must carry.
    partition_size:
        Expected size in bytes of the raw boot partition.

    Returns
    -------
    StockBootEvidence
        Only returned when the whole chain authenticates; every other outcome
        raises :class:`StockBootValidationError`.

    Raises
    ------
    StockBootValidationError
        For invalid requests, unauthenticated metadata, broken signatures,
        missing counterpart-slot evidence, or mismatched model, fingerprint or
        partition size.

    Notes
    -----
    Validation order: baseline SHA-256 pin, baseline signature and root key,
    slot ``vbmeta`` signature under that same key, the unique signed boot chain
    descriptor, raw boot header/footer bounds, the embedded ``vbmeta`` signature
    under the chain key, the salted boot hash, the signed boot properties, and
    finally the whole-partition SHA-256 reported as evidence.  Descriptor names
    are the slot-less AVB names (``boot``); ``slot`` is only echoed into the
    evidence, because binding a physical slot to a snapshot happens elsewhere.
    """
    (slot, expected_model, expected_fingerprint, partition_size,
     slot_vbmeta, trusted_baseline) = _validate_request(
        slot, expected_model, expected_fingerprint, partition_size,
        slot_vbmeta, trusted_baseline)

    try:
        start_position: Optional[int] = boot.tell()
    except Exception:  # noqa: BLE001 - position preservation is best effort
        start_position = None

    try:
        try:
            return _validate_chain(boot, slot_vbmeta, trusted_baseline, slot,
                                   expected_model, expected_fingerprint,
                                   partition_size)
        except StockBootValidationError:
            raise
        except Exception as exc:  # noqa: BLE001 - map to the public contract
            raise StockBootValidationError(
                "stock boot validation failed: %s" % exc
            ) from exc
    finally:
        if start_position is not None:
            try:
                boot.seek(start_position)
            except Exception:  # noqa: BLE001 - position restoration is optional
                pass


@dataclass(frozen=True)
class SignedBootMetadata:
    """Signed metadata facts about the boot chain.

    ``body_hash_verified`` is always ``False`` in this API version: the
    embedded signature and signed properties are inspected, but the patched
    boot payload hash is intentionally not authenticated here.
    ``hardware_rollback_verified`` is likewise always ``False``: rollback
    indexes are reported, never checked against hardware state.
    """

    fingerprint: str
    os_version: str
    security_patch: str
    root_key_sha256: str
    chain_key_sha256: str
    boot_rollback_index: int
    boot_rollback_index_location: int
    slot_vbmeta_rollback_index: int
    slot_vbmeta_rollback_index_location: int
    hardware_rollback_verified: bool = False
    body_hash_verified: bool = False


def _inspect_metadata(current_boot: BinaryIO, slot_vbmeta: bytes,
                      trusted_baseline: bytes) -> SignedBootMetadata:
    """Authenticate the signed layers and read the boot properties."""
    baseline_digest = hashlib.sha256(trusted_baseline).hexdigest()
    if not hmac.compare_digest(baseline_digest, BASELINE_VBMETA_SHA256):
        _reject("trusted baseline does not match the pinned device SHA-256")

    root = _authenticate_vbmeta(trusted_baseline, None, "trusted baseline")
    slot_image = _authenticate_vbmeta(slot_vbmeta, root.key_blob,
                                      "slot vbmeta")
    chain_location, chain_key = _select_boot_chain(slot_image, "slot vbmeta")

    raw_size = _stream_size(current_boot, "boot partition")
    if raw_size < _ANDROID_HEADER_SIZE + _AVB_FOOTER_SIZE:
        _reject("boot partition is too small for an Android header and "
                "footer")

    android_header = _read_exact(current_boot, 0, _ANDROID_HEADER_SIZE,
                                 "boot image")
    body_extent = _parse_android_header(android_header, "boot image")
    if body_extent > raw_size:
        _reject("Android boot body overruns the raw partition")

    footer = _parse_footer(
        _read_exact(current_boot, raw_size - _AVB_FOOTER_SIZE,
                    _AVB_FOOTER_SIZE, "boot footer"),
        raw_size, "boot footer")

    embedded = _load_embedded_vbmeta(current_boot, footer, raw_size, chain_key)

    hash_descriptor = _select_boot_hash(embedded, "embedded vbmeta")
    if hash_descriptor["image_size"] != footer.original_image_size:
        _reject("boot hash descriptor image size disagrees with the footer")
    if hash_descriptor["image_size"] > raw_size:
        _reject("boot hash descriptor image overruns the raw partition")

    properties = _select_required_properties(embedded, "embedded vbmeta")
    fingerprint = properties[_PROPERTY_FINGERPRINT]
    _model_from_fingerprint(fingerprint, "signed fingerprint")

    return SignedBootMetadata(
        fingerprint=fingerprint,
        os_version=properties[_PROPERTY_OS_VERSION],
        security_patch=properties[_PROPERTY_SECURITY_PATCH],
        root_key_sha256=hashlib.sha256(root.key_blob).hexdigest(),
        chain_key_sha256=hashlib.sha256(chain_key).hexdigest(),
        boot_rollback_index=embedded.header.rollback_index,
        boot_rollback_index_location=chain_location,
        slot_vbmeta_rollback_index=slot_image.header.rollback_index,
        slot_vbmeta_rollback_index_location=slot_image.header.rollback_location,
        hardware_rollback_verified=False,
        body_hash_verified=False,
    )


def inspect_signed_boot_metadata(
    current_boot: BinaryIO,
    slot_vbmeta: bytes,
    trusted_baseline: bytes,
) -> SignedBootMetadata:
    """Inspect signed boot metadata without authenticating the boot body.

    Authentication covers the fixed local baseline pin, the root key, the
    boot delegation descriptor, and the embedded signature and signed
    properties.  The patched body hash is intentionally **not** authenticated,
    so a ``body_hash_verified`` value of ``True`` is never produced.  A
    fingerprint cannot be derived from an embedded ``vbmeta`` whose algorithm
    is ``NONE``: unsigned properties are not trusted evidence.

    The caller owns ``current_boot``; this function must not close it and may
    consume it.  Binding the stream to a physical slot is exclusively the
    caller's responsibility, because slot metadata is not carried by the
    signed structures.  Hardware rollback counters are not verified.
    """
    slot_vbmeta = _require_bytes(slot_vbmeta, "slot_vbmeta")
    trusted_baseline = _require_bytes(trusted_baseline, "trusted_baseline")

    try:
        start_position: Optional[int] = current_boot.tell()
    except Exception:  # noqa: BLE001 - position preservation is best effort
        start_position = None

    try:
        try:
            return _inspect_metadata(current_boot, slot_vbmeta,
                                     trusted_baseline)
        except StockBootValidationError:
            raise
        except Exception as exc:  # noqa: BLE001 - map to the public contract
            raise StockBootValidationError(
                "signed boot metadata inspection failed: %s" % exc
            ) from exc
    finally:
        if start_position is not None:
            try:
                current_boot.seek(start_position)
            except Exception:  # noqa: BLE001 - restoration is optional
                pass


def _restore_position(stream: BinaryIO, position: Optional[int]) -> None:
    if position is None:
        return
    try:
        stream.seek(position)
    except Exception:  # noqa: BLE001 - position restoration is optional
        pass


def _validate_restore_candidate_body(
    stock_boot: BinaryIO,
    current_boot: BinaryIO,
    slot_vbmeta: bytes,
    trusted_baseline: bytes,
    slot: str,
    model: str,
    partition_size: int,
) -> StockBootEvidence:
    slot = _validate_slot(slot)
    model = _require_text(model, "model")
    if isinstance(partition_size, bool) or not isinstance(partition_size, int):
        _reject("partition_size must be an integer")
    if partition_size <= 0:
        _reject("partition_size must be positive")
    slot_vbmeta = _require_bytes(slot_vbmeta, "slot_vbmeta")
    trusted_baseline = _require_bytes(trusted_baseline, "trusted_baseline")

    baseline_digest = hashlib.sha256(trusted_baseline).hexdigest()
    if not hmac.compare_digest(baseline_digest, BASELINE_VBMETA_SHA256):
        _reject("trusted baseline does not match the pinned device SHA-256")

    # Pair candidacy is decided from the model and the whole saved root copy
    # before the multi-megabyte candidate stream is touched at all.
    if (model == _SAVED_PAIR_MODEL
            and hmac.compare_digest(hashlib.sha256(slot_vbmeta).hexdigest(),
                                    BASELINE_VBMETA_SHA256)):
        raw_size = _stream_size(stock_boot, "boot partition")
        if raw_size == partition_size:
            candidate_digest = _stream_sha256(stock_boot, partition_size,
                                              "boot partition")
            if hmac.compare_digest(candidate_digest,
                                   _SAVED_PAIR_STOCK_SHA256):
                evidence = validate_stock_boot(
                    stock_boot,
                    slot_vbmeta,
                    trusted_baseline,
                    slot,
                    model,
                    _SAVED_PAIR_FINGERPRINT,
                    partition_size,
                )
                if not hmac.compare_digest(evidence.stock_sha256,
                                           _SAVED_PAIR_STOCK_SHA256):
                    _reject("candidate stream changed after it was hashed")
                return replace(evidence,
                               proof=_PROOF_SAVED_BASELINE_PAIR)

    metadata = inspect_signed_boot_metadata(
        current_boot, slot_vbmeta, trusted_baseline)

    evidence = validate_stock_boot(
        stock_boot,
        slot_vbmeta,
        trusted_baseline,
        slot,
        model,
        metadata.fingerprint,
        partition_size,
    )
    return replace(evidence, proof=_PROOF_SIGNED_CURRENT)


def validate_restore_candidate(
    stock_boot: BinaryIO,
    current_boot: BinaryIO,
    slot_vbmeta: bytes,
    trusted_baseline: bytes,
    slot: str,
    model: str,
    partition_size: int,
) -> StockBootEvidence:
    """Validate a candidate stock boot image for the restore flow.

    Exactly two authentication routes exist, and both run the full
    :func:`validate_stock_boot` check over ``stock_boot``; neither can return
    evidence without it.

    ``saved-baseline-pair``
        The saved same-device build-1.5.10.259 pair.  ``model`` must be the
        pinned model, the whole ``slot_vbmeta`` and the whole candidate stream
        must match their saved SHA-256 pins, and the baseline pin must pass.
        The candidate stream size must equal ``partition_size``.  The full
        validation then runs against the fixed saved fingerprint, and the
        evidence hash must still equal the saved candidate pin, so a stream
        that changes between the pre-hash and the validator is rejected.

    ``signed-current``
        Used whenever any pair condition does not hold.
        :func:`inspect_signed_boot_metadata` first authenticates the signed
        layers of ``current_boot`` under the same baseline, root and chain
        keys; its fingerprint then drives the full validation of
        ``stock_boot``.  An embedded ``vbmeta`` with algorithm ``NONE`` is
        unsigned, so it is rejected instead of contributing a fingerprint.

    No caller-supplied or host-derived fingerprint is accepted, and a failed
    pair match never weakens the fallback: the metadata inspector must
    authenticate, and a candidate that fails full validation is rejected
    rather than reported as successful.  ``hardware_rollback_verified`` stays
    ``False``.  Both streams belong to the caller: neither is closed, and both
    positions are restored.
    """
    try:
        stock_position: Optional[int] = stock_boot.tell()
    except Exception:  # noqa: BLE001 - position preservation is best effort
        stock_position = None
    try:
        current_position: Optional[int] = current_boot.tell()
    except Exception:  # noqa: BLE001 - position preservation is best effort
        current_position = None

    try:
        try:
            return _validate_restore_candidate_body(
                stock_boot,
                current_boot,
                slot_vbmeta,
                trusted_baseline,
                slot,
                model,
                partition_size,
            )
        except StockBootValidationError:
            raise
        except Exception as exc:  # noqa: BLE001 - map to the public contract
            raise StockBootValidationError(
                "restore candidate validation failed: %s" % exc
            ) from exc
    finally:
        _restore_position(stock_boot, stock_position)
        _restore_position(current_boot, current_position)
