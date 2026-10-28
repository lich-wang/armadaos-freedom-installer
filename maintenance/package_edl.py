#!/usr/bin/env python3
"""EDL003/a1 - native stdlib EDL toolchain packager (schemaVersion 1)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile

SCHEMA_VERSION = 1
PROFILE_ID = "g4-9008-259"
MODEL = "TB322FC"
ANDROID_BUILD = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611"
HARDWARE_ID = "0028D0E100400000"

ROLES = (
    ("client", "tools/edl-ng.exe"),
    ("usbLibrary", "tools/libusb-1.0.dll"),
    ("firehose", "tools/firehose.melf"),
    ("license", "tools/LICENSE.txt"),
    ("python", "python/python-3.14.8-embed-amd64.zip"),
    ("avb", "scripts/avb_stock.py"),
    ("avbCli", "scripts/avb_stock_cli.py"),
    ("gpt", "scripts/portable_gpt.py"),
    ("gptCli", "scripts/edl_gpt_cli.py"),
)

FLAGS = (
    ("client", "--client", "edl-ng.exe source path"),
    ("usbLibrary", "--usb-library", "libusb-1.0.dll source path"),
    ("firehose", "--firehose", "approved firehose .melf source path"),
    ("license", "--license", "edl-ng LICENSE source path"),
    ("python", "--python-zip", "official embeddable Python ZIP source path"),
    ("avb", "--avb", "avb_stock.py source path"),
    ("avbCli", "--avb-cli", "avb_stock_cli.py source path"),
    ("gpt", "--gpt", "portable_gpt.py source path"),
    ("gptCli", "--gpt-cli", "edl_gpt_cli.py source path"),
)

PINS = {
    "client": (7080448, "41ada68410a434eaf157211b68aeec287c6bd0b648ca161c75badf84d8bf045e"),
    "firehose": (1697740, "a38993803139d881f47adfa66309f8d5e545c2e33eb4576d0a585afae9cd3da0"),
    "python": (12601679, "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"),
}

CHUNK = 1024 * 1024


class PackagingError(Exception):
    """Concise, user-facing failure."""


def _hash_file(path: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _open_exclusive(path: str):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    return os.fdopen(fd, "w+b")


def _write_atomic(path: str, payload: bytes, owned: list[str]) -> None:
    part = path + ".part"
    with _open_exclusive(part) as handle:
        owned.append(part)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(part, path)
    owned.remove(part)


def _check_arcnames() -> None:
    seen: set[str] = set()
    for role, arcname in ROLES:
        parts = arcname.split("/")
        if (
            arcname.startswith("/")
            or "\\" in arcname
            or any(part in ("", ".", "..") for part in parts)
            or arcname.lower() in seen
        ):
            raise PackagingError(f"unsafe package path for {role}: {arcname}")
        seen.add(arcname.lower())


def _resolve_input(role: str, path: str) -> str:
    try:
        info = os.lstat(path)
    except OSError:
        raise PackagingError(f"{role} source not accessible: {path}") from None
    if stat.S_ISLNK(info.st_mode):
        raise PackagingError(f"{role} source is a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise PackagingError(f"{role} source is not a regular file: {path}")
    if info.st_size <= 0:
        raise PackagingError(f"{role} source is empty: {path}")
    return os.path.realpath(path)


def _resolve_output(path: str, sources: dict[str, str]) -> str:
    output = os.path.abspath(path)
    if not os.path.basename(output):
        raise PackagingError(f"invalid output path: {path}")
    if os.path.isdir(output):
        raise PackagingError(f"output path is a directory: {output}")
    destinations = (
        ("output", output),
        ("manifest report", output + ".manifest.json"),
        ("SHA report", output + ".sha256"),
    )
    for label, destination in destinations:
        resolved = os.path.realpath(destination)
        for role, source in sources.items():
            if source == resolved:
                raise PackagingError(f"{label} path resolves to the {role} input: {destination}")
    return output


def _write_zip(
    part: str, manifest_bytes: bytes, sources: dict[str, str], sizes: dict[str, int], owned: list[str]
) -> None:
    with _open_exclusive(part) as raw:
        owned.append(part)
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            head = zipfile.ZipInfo("manifest.json")
            head.compress_type = zipfile.ZIP_STORED
            archive.writestr(head, manifest_bytes)
            for role, arcname in ROLES:
                info = zipfile.ZipInfo(arcname)
                info.compress_type = zipfile.ZIP_STORED
                copied = 0
                with archive.open(info, "w", force_zip64=True) as target, open(sources[role], "rb") as source:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        target.write(chunk)
                        copied += len(chunk)
                if copied != sizes[role]:
                    raise PackagingError(f"{role} source changed while packaging")
        raw.flush()
        os.fsync(raw.fileno())


def package(args: argparse.Namespace) -> dict:
    _check_arcnames()

    sources: dict[str, str] = {}
    for role, _flag, _help in FLAGS:
        sources[role] = _resolve_input(role, getattr(args, role))
    if len(set(sources.values())) != len(ROLES):
        raise PackagingError("each of the nine roles must be a distinct source file")
    output = _resolve_output(args.output, sources)

    sizes: dict[str, int] = {}
    hashes: dict[str, str] = {}
    for role, _arcname in ROLES:
        size, digest = _hash_file(sources[role])
        if size <= 0:
            raise PackagingError(f"{role} source is empty: {sources[role]}")
        if role in PINS:
            want_size, want_sha = PINS[role]
            if size != want_size or digest != want_sha:
                raise PackagingError(
                    f"{role} pin mismatch: got {size} bytes/{digest}, "
                    f"expected {want_size} bytes/{want_sha}"
                )
        sizes[role] = size
        hashes[role] = digest

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "profileId": PROFILE_ID,
        "model": MODEL,
        "androidBuild": ANDROID_BUILD,
        "hardwareId": HARDWARE_ID,
        "entries": [
            {"role": role, "path": arcname, "bytes": sizes[role], "sha256": hashes[role]}
            for role, arcname in ROLES
        ],
    }
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"

    parent = os.path.dirname(output)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        raise PackagingError(f"cannot create output parent: {parent}") from None

    part = output + ".part"
    owned: list[str] = []
    try:
        _write_zip(part, manifest_bytes, sources, sizes, owned)
        zip_bytes, zip_sha = _hash_file(part)
        os.replace(part, output)
        owned.remove(part)

        manifest_report = output + ".manifest.json"
        checksum_report = output + ".sha256"
        _write_atomic(manifest_report, manifest_bytes, owned)
        checksum_line = f"{zip_sha}  {os.path.basename(output)}\n".encode("utf-8")
        _write_atomic(checksum_report, checksum_line, owned)
    except BaseException:
        for leftover in owned:
            try:
                os.remove(leftover)
            except OSError:
                pass
        raise

    return {
        "profileId": PROFILE_ID,
        "output": output,
        "bytes": zip_bytes,
        "sha256": zip_sha,
        "roleCount": len(ROLES),
        "manifestReport": manifest_report,
        "checksumReport": checksum_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="package_edl.py",
        description="Build the EDL003/a1 EDL toolchain ZIP from nine explicit files.",
    )
    for role, flag, help_text in FLAGS:
        parser.add_argument(flag, dest=role, required=True, metavar="PATH", help=help_text)
    parser.add_argument("--output", required=True, metavar="PATH", help="bundle ZIP output path")
    args = parser.parse_args(argv)
    try:
        report = package(args)
    except PackagingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc.strerror or exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # no traceback, no content dump
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
