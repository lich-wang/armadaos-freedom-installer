"""Regression suite for the AVB stock-boot validation API (stage 1, RED run).

The suite is written against the public contract of :mod:`avb_stock` only.
Invalid-request cases need no assets and must raise ``StockBootValidationError``
once the implementation lands; while the stage-1 stub is in place they surface
as meaningful ``NotImplementedError`` test *errors* (never as passes and never
as syntax/import problems).

Image-dependent cases are skipped unless ``AVB_TEST_ASSET_ROOT`` points at a
directory containing ``vbmeta_a.img`` and ``stock_boot_a.img``.  No image bytes,
public-key bytes, or private material are embedded here.
"""

from __future__ import annotations

import dataclasses
import inspect
import io
import os
import re
import sys
import unittest


_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _candidate in (_HERE, _PARENT):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

import avb_stock  # noqa: E402  (path bootstrap must run first)


EXPECTED_BASELINE_SHA256 = (
    "55929c1580d437ad9d5f43e897c37f0d6aa1f1469ffb8ede5928f4b43387f387"
)
EXPECTED_STOCK_BOOT_SHA256 = (
    "b428a31dadc5db3f91620c1f4114f5ee7702e34e0789ed9bf84a878a49898f20"
)
EXPECTED_PARTITION_SIZE = 100663296
EXPECTED_MODEL = "TB322FC"
EXPECTED_FINGERPRINT = (
    "Lenovo/TB322FC_PRC/TB322FC:16/BQ2A.250610.001-BP2A.250605.031.A3/"
    "ZUXOS_1.5.10.259_260611_PRC:user/release-keys"
)
OTHER_FINGERPRINT = (
    "Lenovo/TB322FC_PRC/TB322FC:16/BQ2A.250610.001-BP2A.250605.031.A3/"
    "ZUXOS_1.5.10.229_260611_PRC:user/release-keys"
)
OTHER_MODEL = "TB323FU"
SLOT_A = "a"
SLOT_B = "b"

VBMETA_ASSET_NAME = "vbmeta_a.img"
BOOT_ASSET_NAME = "stock_boot_a.img"

#: AVB0 header field offsets used by the mutation helpers below.
#: ``authentication_data_block_size`` and ``public_key_offset`` are uint64;
#: ``algorithm_type`` and ``flags`` are uint32.
OFFSET_ALGORITHM = 28
OFFSET_FLAGS = 120
OFFSET_AUTH_SIZE = 12
OFFSET_PUBLIC_KEY_OFFSET = 64
OFFSET_AUTH_BLOCK = 256
OFFSET_SIGNATURE_BYTE = 288
MODULUS_BYTE_IN_KEY = 8
EXPECTED_KEY_START = 7744
EXPECTED_MODULUS_BYTE = 7752

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

#: Additional official AVB field offsets used by the restore-candidate cases.
OFFSET_AUX_SIZE = 20
FOOTER_SIZE = 64
FOOTER_ORIGINAL_IMAGE_SIZE = 12
FOOTER_VBMETA_OFFSET = 20
FOOTER_VBMETA_SIZE = 28

#: Values of ``StockBootEvidence.proof`` for the two eventual routes.
PROOF_SAVED_BASELINE_PAIR = "saved-baseline-pair"
PROOF_SIGNED_CURRENT = "signed-current"

#: Exact positional parameter names of the restore-candidate API.
RESTORE_CANDIDATE_PARAMETERS = [
    "stock_boot",
    "current_boot",
    "slot_vbmeta",
    "trusted_baseline",
    "slot",
    "model",
    "partition_size",
]


def _asset_path(name):
    """Return the absolute asset path, or ``None`` when unavailable."""
    root = os.environ.get("AVB_TEST_ASSET_ROOT", "")
    if not root:
        return None
    candidate = os.path.join(root, name)
    return candidate if os.path.isfile(candidate) else None


_ASSET_VBMETA = _asset_path(VBMETA_ASSET_NAME)
_ASSET_BOOT = _asset_path(BOOT_ASSET_NAME)
_ASSETS_AVAILABLE = _ASSET_VBMETA is not None and _ASSET_BOOT is not None
_SKIP_REASON = (
    "AVB_TEST_ASSET_ROOT must name a directory containing "
    "vbmeta_a.img and stock_boot_a.img"
)


def _read_file(path):
    with open(path, "rb") as handle:
        return handle.read()


def _get_u64_be(blob, offset):
    """Read a big-endian uint64 header field (auth size, public key offset)."""
    field = blob[offset:offset + 8]
    if len(field) != 8:
        raise ValueError("uint64 field at offset %d is truncated" % offset)
    return int.from_bytes(field, "big")


def _set_u32_be(blob, offset, value):
    data = bytearray(blob)
    data[offset:offset + 4] = value.to_bytes(4, "big")
    return bytes(data)


def _flip_byte(blob, offset):
    data = bytearray(blob)
    data[offset] ^= 0xFF
    return bytes(data)


def _mutated_root_padding(blob):
    """Flip the last unsigned padding byte of a ``vbmeta`` partition image.

    The used region is the fixed 256-byte AVB header followed by the
    authentication block (``authentication_data_block_size`` at byte 12) and
    the auxiliary block (``auxiliary_data_block_size`` at byte 20).  Every byte
    after that total is partition padding: it is outside the signed digest, the
    RSA signature, the public key blob and the chain descriptors, so the
    embedded root material and the chain stay valid while the whole-file
    SHA-256 changes.
    """
    used = (OFFSET_AUTH_BLOCK + _get_u64_be(blob, OFFSET_AUTH_SIZE)
            + _get_u64_be(blob, OFFSET_AUX_SIZE))
    last = len(blob) - 1
    if last < used:
        raise AssertionError(
            "fixture has no unsigned padding byte at or after offset %d" % used)
    return _flip_byte(blob, last)


def _stock_padding_mutation(path):
    """Return ``(offset, replacement)`` for one unsigned stock padding byte.

    Only the official footer layout is read: the last 64 bytes are the AVB
    footer, ``original_image_size`` lives at footer offset 12,
    ``vbmeta_offset`` at 20 and ``vbmeta_size`` at 28.  The chosen byte is the
    one immediately before the footer, asserted to lie outside both the signed
    image payload and the embedded ``vbmeta`` blob, so it authenticates nothing
    and is not covered by the footer while still counting towards the
    whole-partition SHA-256.
    """
    with open(path, "rb") as raw:
        raw.seek(0, os.SEEK_END)
        file_size = raw.tell()
        if file_size < FOOTER_SIZE + 1:
            raise AssertionError("boot fixture is too small for footer padding")
        raw.seek(file_size - FOOTER_SIZE)
        footer = raw.read(FOOTER_SIZE)
        if len(footer) != FOOTER_SIZE:
            raise AssertionError("AVB footer is truncated")
        original_size = _get_u64_be(footer, FOOTER_ORIGINAL_IMAGE_SIZE)
        vbmeta_offset = _get_u64_be(footer, FOOTER_VBMETA_OFFSET)
        vbmeta_size = _get_u64_be(footer, FOOTER_VBMETA_SIZE)
        offset = file_size - FOOTER_SIZE - 1
        if offset < vbmeta_offset + vbmeta_size:
            raise AssertionError(
                "byte before the footer overlaps the embedded vbmeta blob")
        if offset < original_size:
            raise AssertionError(
                "byte before the footer overlaps the signed image payload")
        raw.seek(offset)
        original = raw.read(1)
        if len(original) != 1:
            raise AssertionError("stock tail padding byte is unreadable")
    return offset, original[0] ^ 0xFF


class _ByteOverlayStream:
    """Read-only BinaryIO overlay that substitutes one byte at an absolute offset.

    The wrapped stream is used as-is for positioning and bulk reads, so seek,
    tell and short/zero-length read behaviour stay identical to the file.  Only
    the byte at ``offset`` is different in the returned data, and the underlying
    file is never written.
    """

    def __init__(self, raw, offset, replacement):
        if offset < 0:
            raise ValueError("overlay offset must be non-negative")
        if not 0 <= replacement <= 0xFF:
            raise ValueError("overlay replacement must be a byte value")
        self._raw = raw
        self._offset = offset
        self._replacement = bytes((replacement,))

    def readable(self):
        return True

    def writable(self):
        return False

    def seekable(self):
        return True

    def tell(self):
        return self._raw.tell()

    def seek(self, pos, whence=os.SEEK_SET):
        return self._raw.seek(pos, whence)

    def read(self, size=-1):
        start = self._raw.tell()
        chunk = self._raw.read(size)
        if not chunk:
            return chunk
        end = start + len(chunk)
        if start <= self._offset < end:
            index = self._offset - start
            return chunk[:index] + self._replacement + chunk[index + 1:]
        return chunk

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)


class ApiSurfaceTests(unittest.TestCase):
    """Checks the exported contract that the implementation must honour."""

    def test_error_is_a_value_error(self):
        self.assertTrue(issubclass(avb_stock.StockBootValidationError, ValueError))

    def test_baseline_pin_is_the_saved_device_copy(self):
        self.assertEqual(avb_stock.BASELINE_VBMETA_SHA256, EXPECTED_BASELINE_SHA256)
        self.assertEqual(avb_stock.BASELINE_VBMETA_SHA256.lower(),
                         avb_stock.BASELINE_VBMETA_SHA256)

    def test_evidence_is_frozen_and_rollback_unverified_by_default(self):
        evidence = avb_stock.StockBootEvidence(
            slot=SLOT_A,
            stock_sha256=EXPECTED_STOCK_BOOT_SHA256,
            fingerprint=EXPECTED_FINGERPRINT,
            os_version="16",
            security_patch="2026-06-05",
            root_key_sha256="0" * 64,
            chain_key_sha256="1" * 64,
            boot_rollback_index=0,
            boot_rollback_index_location=0,
            slot_vbmeta_rollback_index=0,
            slot_vbmeta_rollback_index_location=3,
        )
        self.assertIs(evidence.hardware_rollback_verified, False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence.slot = SLOT_B


class InvalidRequestTests(unittest.TestCase):
    """Request validation cases: these need no image assets at all."""

    def _call(self, **overrides):
        kwargs = dict(
            boot=io.BytesIO(b""),
            slot_vbmeta=b"",
            trusted_baseline=b"",
            slot=SLOT_A,
            expected_model=EXPECTED_MODEL,
            expected_fingerprint=EXPECTED_FINGERPRINT,
            partition_size=EXPECTED_PARTITION_SIZE,
        )
        kwargs.update(overrides)
        return avb_stock.validate_stock_boot(**kwargs)

    def test_rejects_empty_slot(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(slot="", trusted_baseline=b"\x00" * 64,
                       slot_vbmeta=b"\x00" * 512)

    def test_rejects_slot_with_leading_underscore(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(slot="_a", trusted_baseline=b"\x00" * 64,
                       slot_vbmeta=b"\x00" * 512)

    def test_rejects_unknown_slot_letter(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(slot="c", trusted_baseline=b"\x00" * 64,
                       slot_vbmeta=b"\x00" * 512)

    def test_rejects_empty_baseline(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(trusted_baseline=b"", slot_vbmeta=b"\x00" * 512)

    def test_rejects_untrusted_baseline_bytes(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(trusted_baseline=b"\x00" * 64, slot_vbmeta=b"\x00" * 512)

    def test_rejects_zero_partition_size(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(partition_size=0, trusted_baseline=b"\x00" * 64,
                       slot_vbmeta=b"\x00" * 512)

    def test_rejects_negative_partition_size(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(partition_size=-1, trusted_baseline=b"\x00" * 64,
                       slot_vbmeta=b"\x00" * 512)

    def test_rejects_missing_slot_vbmeta(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(trusted_baseline=b"\x00" * 64, slot_vbmeta=b"")


class OverlayStreamTests(unittest.TestCase):
    """The overlay helper itself, exercised without any image assets."""

    def test_substitution_respects_offsets_and_zero_length_reads(self):
        raw = io.BytesIO(bytes(range(16)))
        stream = _ByteOverlayStream(raw, 8, 0xFF)

        self.assertEqual(stream.read(0), b"")
        self.assertEqual(stream.tell(), 0)

        stream.seek(4)
        self.assertEqual(stream.read(8), bytes([4, 5, 6, 7, 0xFF, 9, 10, 11]))
        self.assertEqual(stream.tell(), 12)
        self.assertEqual(stream.read(8), bytes([12, 13, 14, 15]))

        stream.seek(-1, os.SEEK_END)
        self.assertEqual(stream.read(4), bytes([15]))


@unittest.skipUnless(_ASSETS_AVAILABLE, _SKIP_REASON)
class StockBootIntegrationTests(unittest.TestCase):
    """Full-image cases against the manager-provided verified asset copies."""

    def _vbmeta_bytes(self):
        return _read_file(_asset_path(VBMETA_ASSET_NAME))

    def _baseline_bytes(self):
        # The saved same-device copy of the slot vbmeta is the local baseline.
        return _read_file(_asset_path(VBMETA_ASSET_NAME))

    def _assert_rejected(self, *, slot_vbmeta=None, trusted_baseline=None,
                         slot=SLOT_A, expected_model=EXPECTED_MODEL,
                         expected_fingerprint=EXPECTED_FINGERPRINT,
                         partition_size=EXPECTED_PARTITION_SIZE):
        if slot_vbmeta is None:
            slot_vbmeta = self._vbmeta_bytes()
        if trusted_baseline is None:
            trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as boot:
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.validate_stock_boot(
                    boot,
                    slot_vbmeta,
                    trusted_baseline,
                    slot,
                    expected_model,
                    expected_fingerprint,
                    partition_size,
                )

    def test_full_size_positive_evidence(self):
        slot_vbmeta = self._vbmeta_bytes()
        trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as boot:
            evidence = avb_stock.validate_stock_boot(
                boot,
                slot_vbmeta,
                trusted_baseline,
                SLOT_A,
                EXPECTED_MODEL,
                EXPECTED_FINGERPRINT,
                EXPECTED_PARTITION_SIZE,
            )
            self.assertFalse(boot.closed, "caller keeps ownership of the stream")

        self.assertIsInstance(evidence, avb_stock.StockBootEvidence)
        self.assertEqual(evidence.slot, SLOT_A)
        self.assertEqual(evidence.stock_sha256, EXPECTED_STOCK_BOOT_SHA256)
        self.assertEqual(evidence.fingerprint, EXPECTED_FINGERPRINT)
        self.assertTrue(evidence.os_version)
        self.assertTrue(evidence.security_patch)
        for digest in (evidence.root_key_sha256, evidence.chain_key_sha256):
            self.assertRegex(digest, HEX64)
        self.assertGreaterEqual(evidence.boot_rollback_index, 0)
        self.assertEqual(evidence.boot_rollback_index_location, 3)
        self.assertGreaterEqual(evidence.slot_vbmeta_rollback_index, 0)
        self.assertEqual(evidence.slot_vbmeta_rollback_index_location, 0)
        self.assertIs(evidence.hardware_rollback_verified, False)

    def test_rejects_corrupted_baseline_byte(self):
        self._assert_rejected(trusted_baseline=_flip_byte(self._baseline_bytes(), 0))

    def test_rejects_algorithm_none(self):
        mutated = _set_u32_be(self._vbmeta_bytes(), OFFSET_ALGORITHM, 0)
        self._assert_rejected(slot_vbmeta=mutated)

    def test_rejects_verification_disabled_flag(self):
        mutated = _set_u32_be(self._vbmeta_bytes(), OFFSET_FLAGS, 2)
        self._assert_rejected(slot_vbmeta=mutated)

    def test_rejects_corrupted_auth_signature_byte(self):
        vbmeta = self._vbmeta_bytes()
        self.assertGreater(len(vbmeta), OFFSET_SIGNATURE_BYTE)
        self._assert_rejected(
            slot_vbmeta=_flip_byte(vbmeta, OFFSET_SIGNATURE_BYTE)
        )

    def test_rejects_corrupted_root_public_key_byte(self):
        vbmeta = self._vbmeta_bytes()
        auth_size = _get_u64_be(vbmeta, OFFSET_AUTH_SIZE)
        public_key_offset = _get_u64_be(vbmeta, OFFSET_PUBLIC_KEY_OFFSET)
        key_start = OFFSET_AUTH_BLOCK + auth_size + public_key_offset
        self.assertEqual(key_start, EXPECTED_KEY_START,
                         "public key blob must start where the .259 header says")
        modulus_byte = key_start + MODULUS_BYTE_IN_KEY
        self.assertEqual(modulus_byte, EXPECTED_MODULUS_BYTE)
        self.assertLess(modulus_byte, len(vbmeta))
        self._assert_rejected(slot_vbmeta=_flip_byte(vbmeta, modulus_byte))

    def test_rejects_missing_slot_b_vbmeta(self):
        self._assert_rejected(slot_vbmeta=b"", slot=SLOT_B)

    def test_rejects_mismatched_fingerprint(self):
        self._assert_rejected(expected_fingerprint=OTHER_FINGERPRINT)

    def test_rejects_mismatched_model(self):
        self._assert_rejected(expected_model=OTHER_MODEL)

    def test_rejects_mismatched_partition_size(self):
        self._assert_rejected(partition_size=EXPECTED_PARTITION_SIZE - 1)


@unittest.skipUnless(_ASSETS_AVAILABLE, _SKIP_REASON)
class BootStreamOverlayTests(unittest.TestCase):
    """Boot-image mutations applied through the overlay, never on disk."""

    def _assert_boot_rejected(self, offset):
        path = _asset_path(BOOT_ASSET_NAME)
        with open(path, "rb") as raw:
            raw.seek(offset)
            original_bytes = raw.read(1)
        self.assertEqual(len(original_bytes), 1,
                         "fixture is too small to mutate offset %d" % offset)
        replacement = original_bytes[0] ^ 0xFF

        with open(path, "rb") as raw:
            stream = _ByteOverlayStream(raw, offset, replacement)
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.validate_stock_boot(
                    stream,
                    _read_file(_asset_path(VBMETA_ASSET_NAME)),
                    _read_file(_asset_path(VBMETA_ASSET_NAME)),
                    SLOT_A,
                    EXPECTED_MODEL,
                    EXPECTED_FINGERPRINT,
                    EXPECTED_PARTITION_SIZE,
                )

        with open(path, "rb") as raw:
            raw.seek(offset)
            self.assertEqual(raw.read(1), original_bytes,
                             "the underlying fixture must stay unchanged")

    def test_rejects_invalid_android_magic(self):
        self._assert_boot_rejected(0)

    def test_rejects_changed_kernel_payload_byte(self):
        self._assert_boot_rejected(4096)


CURRENT_BOOT_ASSET_NAME = "current_boot_a.img"


def _embedded_signature_mutation(path):
    """Return ``(offset, replacement)`` for the embedded signature byte.

    Only the official AVB footer and header field offsets are used: the last
    64 bytes hold the footer, ``vbmeta_offset`` lives at footer bytes 20:28,
    the embedded 256-byte header starts there, and ``signature_offset`` lives
    at header bytes 48:56.  The resulting byte is bounds-checked and read, and
    the caller receives the XOR-0xFF replacement for a read-only overlay.
    """
    with open(path, "rb") as raw:
        raw.seek(0, os.SEEK_END)
        file_size = raw.tell()
        if file_size < 64:
            raise AssertionError("boot fixture is too small for an AVB footer")
        raw.seek(file_size - 64)
        footer = raw.read(64)
        if len(footer) != 64:
            raise AssertionError("AVB footer is truncated")
        vbmeta_offset = int.from_bytes(footer[20:28], "big")
        raw.seek(vbmeta_offset)
        header = raw.read(256)
        if len(header) != 256:
            raise AssertionError("embedded vbmeta header is truncated")
        signature_offset = int.from_bytes(header[48:56], "big")
        position = vbmeta_offset + 256 + signature_offset
        if not 0 <= position < file_size:
            raise AssertionError(
                "embedded signature byte offset is outside the image")
        raw.seek(position)
        original = raw.read(1)
        if len(original) != 1:
            raise AssertionError("embedded signature byte is unreadable")
    return position, original[0] ^ 0xFF


_CURRENT_BOOT_ASSET = _asset_path(CURRENT_BOOT_ASSET_NAME)


class SignedMetadataSurfaceTests(unittest.TestCase):
    """The metadata dataclass contract, exercised without image assets."""

    def test_signed_metadata_is_frozen_with_unverified_defaults(self):
        self.assertTrue(dataclasses.is_dataclass(avb_stock.SignedBootMetadata))
        metadata = avb_stock.SignedBootMetadata(
            fingerprint=EXPECTED_FINGERPRINT,
            os_version="16",
            security_patch="2026-06-05",
            root_key_sha256="0" * 64,
            chain_key_sha256="1" * 64,
            boot_rollback_index=0,
            boot_rollback_index_location=3,
            slot_vbmeta_rollback_index=0,
            slot_vbmeta_rollback_index_location=0,
        )
        self.assertIs(metadata.hardware_rollback_verified, False)
        self.assertIs(metadata.body_hash_verified, False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            metadata.fingerprint = OTHER_FINGERPRINT


@unittest.skipUnless(_ASSETS_AVAILABLE, _SKIP_REASON)
class EmbeddedSignatureLayerTests(unittest.TestCase):
    """The full validator must reject a changed embedded signature byte."""

    def test_rejects_changed_embedded_vbmeta_signature_byte(self):
        path = _asset_path(BOOT_ASSET_NAME)
        offset, replacement = _embedded_signature_mutation(path)
        with open(path, "rb") as raw:
            stream = _ByteOverlayStream(raw, offset, replacement)
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.validate_stock_boot(
                    stream,
                    _read_file(_asset_path(VBMETA_ASSET_NAME)),
                    _read_file(_asset_path(VBMETA_ASSET_NAME)),
                    SLOT_A,
                    EXPECTED_MODEL,
                    EXPECTED_FINGERPRINT,
                    EXPECTED_PARTITION_SIZE,
                )


class SignedMetadataInvalidRequestTests(unittest.TestCase):
    """Request validation for the metadata API: no image assets needed."""

    def test_rejects_untrusted_baseline_without_assets(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            avb_stock.inspect_signed_boot_metadata(
                io.BytesIO(b""), b"bad", b"bad")


@unittest.skipUnless(_ASSETS_AVAILABLE, _SKIP_REASON)
class SignedMetadataInspectionTests(unittest.TestCase):
    """Metadata inspection contract against the manager-provided assets."""

    def test_inspects_original_stock_metadata(self):
        slot_vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as boot:
            metadata = avb_stock.inspect_signed_boot_metadata(
                boot, slot_vbmeta, trusted_baseline)
            self.assertFalse(boot.closed, "caller keeps ownership of the stream")

        self.assertIsInstance(metadata, avb_stock.SignedBootMetadata)
        self.assertEqual(metadata.fingerprint, EXPECTED_FINGERPRINT)
        self.assertTrue(metadata.os_version)
        self.assertTrue(metadata.security_patch)
        for digest in (metadata.root_key_sha256, metadata.chain_key_sha256):
            self.assertRegex(digest, HEX64)
        self.assertEqual(metadata.boot_rollback_index_location, 3)
        self.assertEqual(metadata.slot_vbmeta_rollback_index_location, 0)
        self.assertIs(metadata.hardware_rollback_verified, False)
        self.assertIs(metadata.body_hash_verified, False)
        self.assertFalse(hasattr(metadata, "stock_sha256"))

    def test_payload_byte_does_not_change_signed_metadata(self):
        path = _asset_path(BOOT_ASSET_NAME)
        with open(path, "rb") as raw:
            raw.seek(4096)
            original = raw.read(1)
        self.assertEqual(len(original), 1,
                         "fixture is too small to mutate offset 4096")

        slot_vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(path, "rb") as raw:
            stream = _ByteOverlayStream(raw, 4096, original[0] ^ 0xFF)
            metadata = avb_stock.inspect_signed_boot_metadata(
                stream, slot_vbmeta, trusted_baseline)
            self.assertFalse(raw.closed, "caller keeps ownership of the stream")

        self.assertEqual(metadata.fingerprint, EXPECTED_FINGERPRINT)
        self.assertIs(metadata.body_hash_verified, False)

    @unittest.skipIf(_CURRENT_BOOT_ASSET is None,
                     "current_boot_a.img is not mounted")
    def test_rejects_current_boot_with_unsigned_embedded_avb(self):
        slot_vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(_CURRENT_BOOT_ASSET, "rb") as boot:
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.inspect_signed_boot_metadata(
                    boot, slot_vbmeta, trusted_baseline)

    def test_rejects_corrupted_footer_magic(self):
        path = _asset_path(BOOT_ASSET_NAME)
        with open(path, "rb") as raw:
            raw.seek(0, os.SEEK_END)
            size = raw.tell()
            self.assertGreaterEqual(size, 64)
            offset = size - 64
            raw.seek(offset)
            original = raw.read(1)
        self.assertEqual(len(original), 1, "AVB footer magic is unreadable")

        slot_vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(path, "rb") as raw:
            stream = _ByteOverlayStream(raw, offset, original[0] ^ 0xFF)
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.inspect_signed_boot_metadata(
                    stream, slot_vbmeta, trusted_baseline)

    def test_rejects_changed_embedded_signature_byte(self):
        path = _asset_path(BOOT_ASSET_NAME)
        offset, replacement = _embedded_signature_mutation(path)
        slot_vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(path, "rb") as raw:
            stream = _ByteOverlayStream(raw, offset, replacement)
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.inspect_signed_boot_metadata(
                    stream, slot_vbmeta, trusted_baseline)

    def test_rejects_corrupted_slot_root_signature(self):
        vbmeta = _read_file(_asset_path(VBMETA_ASSET_NAME))
        self.assertGreater(len(vbmeta), OFFSET_SIGNATURE_BYTE)
        slot_vbmeta = _flip_byte(vbmeta, OFFSET_SIGNATURE_BYTE)
        trusted_baseline = _read_file(_asset_path(VBMETA_ASSET_NAME))
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as boot:
            with self.assertRaises(avb_stock.StockBootValidationError):
                avb_stock.inspect_signed_boot_metadata(
                    boot, slot_vbmeta, trusted_baseline)


class RestoreCandidateSurfaceTests(unittest.TestCase):
    """The restore-candidate surface that must be observable before the body."""

    def test_restore_candidate_signature_is_exact(self):
        self.assertIn("validate_restore_candidate", avb_stock.__all__)
        signature = inspect.signature(avb_stock.validate_restore_candidate)
        self.assertEqual(list(signature.parameters),
                         RESTORE_CANDIDATE_PARAMETERS)
        self.assertNotIn("expected_fingerprint", signature.parameters)

    def test_proof_defaults_to_empty_and_stays_last(self):
        fields = dataclasses.fields(avb_stock.StockBootEvidence)
        self.assertEqual(fields[-1].name, "proof")
        self.assertEqual(fields[-1].default, "")

        evidence = avb_stock.StockBootEvidence(
            slot=SLOT_A,
            stock_sha256=EXPECTED_STOCK_BOOT_SHA256,
            fingerprint=EXPECTED_FINGERPRINT,
            os_version="16",
            security_patch="2026-06-05",
            root_key_sha256="0" * 64,
            chain_key_sha256="1" * 64,
            boot_rollback_index=0,
            boot_rollback_index_location=3,
            slot_vbmeta_rollback_index=0,
            slot_vbmeta_rollback_index_location=0,
        )
        self.assertEqual(evidence.proof, "")


class RestoreCandidateInvalidRequestTests(unittest.TestCase):
    """Request rejects that need no image assets at all."""

    def _call(self, **overrides):
        kwargs = dict(
            stock_boot=io.BytesIO(b""),
            current_boot=io.BytesIO(b""),
            slot_vbmeta=b"\x00" * 512,
            trusted_baseline=b"\x00" * 64,
            slot=SLOT_A,
            model=EXPECTED_MODEL,
            partition_size=EXPECTED_PARTITION_SIZE,
        )
        kwargs.update(overrides)
        return avb_stock.validate_restore_candidate(**kwargs)

    def test_rejects_unknown_slot_letter(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(slot="c")

    def test_rejects_untrusted_baseline_bytes(self):
        with self.assertRaises(avb_stock.StockBootValidationError):
            self._call(trusted_baseline=b"bad")


_CURRENT_BOOT_SKIP_REASON = "current_boot_a.img is not mounted"


@unittest.skipUnless(_ASSETS_AVAILABLE, _SKIP_REASON)
class RestoreCandidateIntegrationTests(unittest.TestCase):
    """The two eventual routes, exercised against the manager assets."""

    def _vbmeta_bytes(self):
        return _read_file(_asset_path(VBMETA_ASSET_NAME))

    def _baseline_bytes(self):
        return _read_file(_asset_path(VBMETA_ASSET_NAME))

    @unittest.skipIf(_CURRENT_BOOT_ASSET is None, _CURRENT_BOOT_SKIP_REASON)
    def test_saved_pair_positive_evidence(self):
        slot_vbmeta = self._vbmeta_bytes()
        trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as stock:
            with open(_CURRENT_BOOT_ASSET, "rb") as current:
                evidence = avb_stock.validate_restore_candidate(
                    stock,
                    current,
                    slot_vbmeta,
                    trusted_baseline,
                    SLOT_A,
                    EXPECTED_MODEL,
                    EXPECTED_PARTITION_SIZE,
                )
                self.assertFalse(stock.closed, "caller keeps the stock stream")
                self.assertFalse(current.closed,
                                 "caller keeps the current stream")

        self.assertIsInstance(evidence, avb_stock.StockBootEvidence)
        self.assertEqual(evidence.slot, SLOT_A)
        self.assertEqual(evidence.stock_sha256, EXPECTED_STOCK_BOOT_SHA256)
        self.assertEqual(evidence.fingerprint, EXPECTED_FINGERPRINT)
        self.assertEqual(evidence.proof, PROOF_SAVED_BASELINE_PAIR)
        self.assertIs(evidence.hardware_rollback_verified, False)

    @unittest.skipIf(_CURRENT_BOOT_ASSET is None, _CURRENT_BOOT_SKIP_REASON)
    def test_rejects_root_padding_change_with_unsigned_current(self):
        slot_vbmeta = _mutated_root_padding(self._vbmeta_bytes())
        trusted_baseline = self._baseline_bytes()
        self.assertNotEqual(slot_vbmeta, trusted_baseline,
                            "the whole root file SHA-256 must have changed")
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as stock:
            with open(_CURRENT_BOOT_ASSET, "rb") as current:
                with self.assertRaises(avb_stock.StockBootValidationError):
                    avb_stock.validate_restore_candidate(
                        stock,
                        current,
                        slot_vbmeta,
                        trusted_baseline,
                        SLOT_A,
                        EXPECTED_MODEL,
                        EXPECTED_PARTITION_SIZE,
                    )

    @unittest.skipIf(_CURRENT_BOOT_ASSET is None, _CURRENT_BOOT_SKIP_REASON)
    def test_rejects_unsigned_stock_padding_change_with_unsigned_current(self):
        offset, replacement = _stock_padding_mutation(
            _asset_path(BOOT_ASSET_NAME))
        slot_vbmeta = self._vbmeta_bytes()
        trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as raw:
            stock = _ByteOverlayStream(raw, offset, replacement)
            with open(_CURRENT_BOOT_ASSET, "rb") as current:
                with self.assertRaises(avb_stock.StockBootValidationError):
                    avb_stock.validate_restore_candidate(
                        stock,
                        current,
                        slot_vbmeta,
                        trusted_baseline,
                        SLOT_A,
                        EXPECTED_MODEL,
                        EXPECTED_PARTITION_SIZE,
                    )
            self.assertFalse(raw.closed, "caller keeps the stock stream")

    @unittest.skipIf(_CURRENT_BOOT_ASSET is None, _CURRENT_BOOT_SKIP_REASON)
    def test_rejects_wrong_model_with_unsigned_current(self):
        slot_vbmeta = self._vbmeta_bytes()
        trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as stock:
            with open(_CURRENT_BOOT_ASSET, "rb") as current:
                with self.assertRaises(avb_stock.StockBootValidationError):
                    avb_stock.validate_restore_candidate(
                        stock,
                        current,
                        slot_vbmeta,
                        trusted_baseline,
                        SLOT_A,
                        OTHER_MODEL,
                        EXPECTED_PARTITION_SIZE,
                    )

    def test_signed_current_route_accepts_unchanged_root_key(self):
        slot_vbmeta = _mutated_root_padding(self._vbmeta_bytes())
        trusted_baseline = self._baseline_bytes()
        with open(_asset_path(BOOT_ASSET_NAME), "rb") as stock:
            with open(_asset_path(BOOT_ASSET_NAME), "rb") as current:
                evidence = avb_stock.validate_restore_candidate(
                    stock,
                    current,
                    slot_vbmeta,
                    trusted_baseline,
                    SLOT_A,
                    EXPECTED_MODEL,
                    EXPECTED_PARTITION_SIZE,
                )
                self.assertFalse(stock.closed, "caller keeps the stock stream")
                self.assertFalse(current.closed,
                                 "caller keeps the current stream")

        self.assertIsInstance(evidence, avb_stock.StockBootEvidence)
        self.assertEqual(evidence.slot, SLOT_A)
        self.assertEqual(evidence.stock_sha256, EXPECTED_STOCK_BOOT_SHA256)
        self.assertEqual(evidence.fingerprint, EXPECTED_FINGERPRINT)
        self.assertEqual(evidence.proof, PROOF_SIGNED_CURRENT)
        self.assertIs(evidence.hardware_rollback_verified, False)

    def test_signed_current_route_rejects_changed_candidate_payload(self):
        slot_vbmeta = _mutated_root_padding(self._vbmeta_bytes())
        trusted_baseline = self._baseline_bytes()
        path = _asset_path(BOOT_ASSET_NAME)
        with open(path, "rb") as raw:
            raw.seek(4096)
            original = raw.read(1)
        self.assertEqual(len(original), 1,
                         "fixture is too small to mutate offset 4096")

        with open(path, "rb") as raw:
            stock = _ByteOverlayStream(raw, 4096, original[0] ^ 0xFF)
            with open(path, "rb") as current:
                with self.assertRaises(avb_stock.StockBootValidationError):
                    avb_stock.validate_restore_candidate(
                        stock,
                        current,
                        slot_vbmeta,
                        trusted_baseline,
                        SLOT_A,
                        EXPECTED_MODEL,
                        EXPECTED_PARTITION_SIZE,
                    )
            self.assertFalse(raw.closed, "caller keeps the stock stream")


if __name__ == "__main__":
    unittest.main()
