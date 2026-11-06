#!/usr/bin/env python3
"""Package the pinned G4, G5 or TB710FU EDL toolchain."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile

SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CHUNK = 1024 * 1024


class PackagingError(Exception):
    """Concise, user-facing failure."""


COMMON_ROLES = (
    ("client", "tools/edl-ng.exe"),
    ("usbLibrary", "tools/libusb-1.0.dll"),
    ("license", "tools/LICENSE.txt"),
    ("python", "python/python-3.14.8-embed-amd64.zip"),
    ("avb", "scripts/avb_stock.py"),
    ("avbCli", "scripts/avb_stock_cli.py"),
    ("gpt", "scripts/portable_gpt.py"),
    ("gptCli", "scripts/edl_gpt_cli.py"),
)

COMMON_FLAGS = (
    ("client", "--client", "edl-ng.exe source path"),
    ("usbLibrary", "--usb-library", "libusb-1.0.dll source path"),
    ("license", "--license", "edl-ng LICENSE source path"),
    ("python", "--python-zip", "official embeddable Python ZIP source path"),
    ("avb", "--avb", "avb_stock.py source path"),
    ("avbCli", "--avb-cli", "avb_stock_cli.py source path"),
    ("gpt", "--gpt", "portable_gpt.py source path"),
    ("gptCli", "--gpt-cli", "edl_gpt_cli.py source path"),
)

FIXED_PINS = {
    "client": (12015022, "655530e926b57d70f1c690869c495253a6eaae28746f370d5b9dbf921d4a4b3b"),
    "python": (12601679, "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"),
}

# macOS (Apple silicon) toolchain: the same modified edl-ng built for osx-arm64 with its libusb dylib and
# no Python runtime (the install route does not use it). Must match EdlToolchain.MacOSPlatform.
MACOS_ROLES = (
    ("client", "tools/edl-ng"),
    ("usbLibrary", "tools/libusb-1.0.dylib"),
    ("license", "tools/LICENSE.txt"),
    ("avb", "scripts/avb_stock.py"),
    ("avbCli", "scripts/avb_stock_cli.py"),
    ("gpt", "scripts/portable_gpt.py"),
    ("gptCli", "scripts/edl_gpt_cli.py"),
)

# The macOS client has no frozen pin: it is always the osx-arm64 edl-ng of the same build, passed with
# --build-pins-json.
MACOS_PINS: dict[str, tuple[int, str]] = {}

# Toolchain platforms: the manifest "platform" field is omitted for Windows, the original format.
PLATFORMS = {
    "windows-x64": {"roles": COMMON_ROLES, "pins": FIXED_PINS, "manifest": None},
    "macos-arm64": {"roles": MACOS_ROLES, "pins": MACOS_PINS, "manifest": "macos-arm64"},
}

G4_PROFILE = {
    "profileId": "g4-9008-259",
    "model": "TB322FC",
    "androidBuild": "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611",
    "hardwareId": "0028D0E100400000",
    "materials": (
        ("firehose", "tools/firehose.melf", 1697740,
         "a38993803139d881f47adfa66309f8d5e545c2e33eb4576d0a585afae9cd3da0"),
    ),
}

G5_PROFILE = {
    "profileId": "g5-9008-y7005",
    "model": "TB323FU",
    "androidBuild": "QCTool-2026.3.21-1/lenovo/devprg_legion-y700-5",
    "hardwareId": "002B40E100400000",
    "materials": (
        ("firehose", "tools/g5/qsahara_device_programmer.xml", 564,
         "433749ae084aa0f1b4016b29619b0b0c377d4b2cd22d8a48b423ca6d9cbc83ca"),
        ("image36", "tools/g5/multi_image_qti.mbn", 12088,
         "a98c7ae167f5d0daf947dc707e3c3679ea438f30ea6ebc510edf15655a14d223"),
        ("image37", "tools/g5/multi_image.mbn", 12088,
         "9dd679f3b38e59af6a7e22598ed85a1918cad41a0af84eac2c33e1b02d6166f8"),
        ("image21", "tools/g5/xbl_sc.elf", 1174496,
         "5d277384cac8fb1512562028ca30c67b2314810ad26b2546a6c8653119a056d4"),
        ("image60", "tools/g5/signed_firmware_soc_view.elf", 203840,
         "dbfdf2602cadb02fe8272abbce55f3f804ad1e98a8481586bf40fa1cbe2960e3"),
        ("image59", "tools/g5/sequencer_ram.elf", 4864,
         "d7dc67ddd77332e558d14b7acb82bc42e1be66a07786403c96b655f46d019636"),
        ("image61", "tools/g5/tme_config.elf", 43760,
         "91f17966306617d1a47336ada238865d4faea014a12edc92f08ea79a773e667a"),
        ("image13", "tools/g5/prog_firehose_ddr.elf", 315384,
         "109338f05b2597b1238f8b724f400f6753a393f6d84c5c534ff36294bbc2da3e"),
        ("image38", "tools/g5/xbl_config_devprg.elf", 180928,
         "199e60752d9f0db398bbc3524839a627f3ae32ab47fb58b90df124b3e0affbbb"),
    ),
}

TB710FU_PROFILE = {
    "profileId": "tb710fu-9008-495",
    "model": "TB710FU",
    "androidBuild": "TB710FU/ZUXOS_1.5.04.495_WITHOUT_UBL/EDL/xbl_s_devprg_ns.melf",
    "hardwareId": "003050E100400000",
    "materials": (
        ("firehose", "tools/tb710fu/firehose.melf", 1573224,
         "ad4689b1c52458250d46829ee46a89ec974e69f8e82eee8d4950427919e0b9eb"),
    ),
}

PROFILES = {
    "g4": G4_PROFILE,
    "tb322fc": G4_PROFILE,
    "g5": G5_PROFILE,
    "tb323fu": G5_PROFILE,
    "tb710fu": TB710FU_PROFILE,
}

# Profiles whose only material is one firehose passed with --firehose.
SINGLE_FIREHOSE_PROFILES = (G4_PROFILE, TB710FU_PROFILE)

G5_ONLY_ROLES = tuple(role for role, *_ in G5_PROFILE["materials"])


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


def _check_arcnames(roles) -> None:
    seen: set[str] = set()
    for role, arcname, *_rest in roles:
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
    part: str, manifest_bytes: bytes, sources: dict[str, str], sizes: dict[str, int],
    roles, owned: list[str]
) -> None:
    with _open_exclusive(part) as raw:
        owned.append(part)
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            head = zipfile.ZipInfo("manifest.json")
            head.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(head, manifest_bytes)
            for role, arcname, *_rest in roles:
                info = zipfile.ZipInfo(arcname)
                info.compress_type = zipfile.ZIP_DEFLATED
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


def _profile_key(profile: str) -> str:
    key = profile.lower()
    if key not in PROFILES:
        raise PackagingError(
            f"unknown profile: {profile} (expected one of tb322fc, tb323fu, tb710fu)"
        )
    return key


def _select_profile(args: argparse.Namespace) -> dict:
    profile = getattr(args, "profile", None) or "tb322fc"
    key = _profile_key(profile)
    return PROFILES[key]


def _resolve_g5_materials(profile: dict, args: argparse.Namespace) -> dict[str, str]:
    loader_root = getattr(args, "loader_root", None)
    if not loader_root:
        raise PackagingError("g5 profile requires --loader-root PATH")
    if not os.path.isdir(loader_root):
        raise PackagingError(f"loader root not a directory: {loader_root}")
    sources: dict[str, str] = {}
    for role, arcname, _size, _sha in profile["materials"]:
        # Use the basename of the archive path as the file name under loader-root.
        name = arcname.rsplit("/", 1)[-1]
        candidate = os.path.join(loader_root, name)
        sources[role] = _resolve_input(role, candidate)
    return sources


def _effective_pins(args: argparse.Namespace, platform: dict) -> dict[str, tuple[int, str]]:
    """Merge build-time client pin (if supplied) over the platform's frozen pins.

    Only the `client` entry may be overridden by --build-pins-json; every other
    pin (python and all G4/G5/TB710FU material pins via the profile) is preserved.
    Without the flag the frozen client pin of the platform is used unchanged; a
    platform without one (macos-arm64) requires the flag.
    """
    pins = dict(platform["pins"])
    build_pins_path = getattr(args, "build_pins_json", None)
    if not build_pins_path:
        if "client" not in pins:
            raise PackagingError("this platform requires --build-pins-json for the client pin")
        return pins
    try:
        with open(build_pins_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagingError(
            f"cannot read build pins JSON {build_pins_path!r}: {exc}"
        ) from None
    if not isinstance(data, dict) or data.get("schemaVersion") != 1:
        raise PackagingError("build pins JSON requires schemaVersion=1")
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise PackagingError("build pins JSON missing 'tools' object")
    client = tools.get("client")
    if not isinstance(client, dict):
        raise PackagingError("build pins JSON missing 'client' record")
    size = client.get("bytes")
    digest = client.get("sha256")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise PackagingError(f"build pins JSON client.bytes invalid: {size!r}")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise PackagingError(f"build pins JSON client.sha256 invalid: {digest!r}")
    pins["client"] = (size, digest)
    return pins


def package(args: argparse.Namespace) -> dict:
    profile = _select_profile(args)
    platform = PLATFORMS[getattr(args, "platform", None) or "windows-x64"]
    effective_pins = _effective_pins(args, platform)
    platform_roles = platform["roles"]
    platform_role_names = {role for role, _arcname in platform_roles}
    flag_by_role = {role: flag for role, flag, _help in COMMON_FLAGS}

    common_sources: dict[str, str] = {}
    for role, _arcname in platform_roles:
        value = getattr(args, role, None)
        if not value:
            raise PackagingError(f"{flag_by_role[role]} is required for this platform")
        common_sources[role] = _resolve_input(role, value)
    for role, flag, _help in COMMON_FLAGS:
        if role not in platform_role_names and getattr(args, role, None):
            raise PackagingError(f"{flag} is not part of this platform's toolchain")

    # Material roles derived from the selected profile.
    material_roles = tuple(profile["materials"])
    material_sources: dict[str, str] = {}
    if any(profile is single for single in SINGLE_FIREHOSE_PROFILES):
        firehose = getattr(args, "firehose", None)
        if not firehose:
            raise PackagingError(f"{profile['model']} profile requires --firehose")
        material_sources["firehose"] = _resolve_input("firehose", firehose)
    else:
        material_sources = _resolve_g5_materials(profile, args)

    if set(material_sources.keys()) != {r for r, *_ in material_roles}:
        raise PackagingError("material role coverage mismatch for selected profile")

    # Combined input set and arcname table for the selected profile.
    roles: list[tuple[str, str, int, str]] = []
    for role, arcname in platform_roles:
        roles.append((role, arcname, 0, ""))
    for role, arcname, size, sha in material_roles:
        roles.append((role, arcname, size, sha))

    # Exactness: no role duplicated.
    if len({r[0] for r in roles}) != len(roles):
        raise PackagingError("duplicate role in package layout")

    _check_arcnames(roles)

    sources: dict[str, str] = {}
    sources.update(common_sources)
    sources.update(material_sources)

    if len(set(sources.values())) != len(sources):
        raise PackagingError(f"each of the {len(sources)} roles must be a distinct source file")

    output = _resolve_output(args.output, sources)

    sizes: dict[str, int] = {}
    hashes: dict[str, str] = {}
    # Validate pins: common fixed pins plus per-profile material pins.
    material_pins = {role: (size, sha) for role, _arcname, size, sha in material_roles}
    for role, _arcname, *_rest in roles:
        size, digest = _hash_file(sources[role])
        if size <= 0:
            raise PackagingError(f"{role} source is empty: {sources[role]}")
        if role in effective_pins:
            want_size, want_sha = effective_pins[role]
            if size != want_size or digest != want_sha:
                raise PackagingError(
                    f"{role} pin mismatch: got {size} bytes/{digest}, "
                    f"expected {want_size} bytes/{want_sha}"
                )
        if role in material_pins:
            want_size, want_sha = material_pins[role]
            if size != want_size or digest != want_sha:
                raise PackagingError(
                    f"{role} pin mismatch: got {size} bytes/{digest}, "
                    f"expected {want_size} bytes/{want_sha}"
                )
        sizes[role] = size
        hashes[role] = digest

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "profileId": profile["profileId"],
        "model": profile["model"],
        "androidBuild": profile["androidBuild"],
        "hardwareId": profile["hardwareId"],
    }
    if platform["manifest"] is not None:
        manifest["platform"] = platform["manifest"]
    manifest["entries"] = [
        {"role": role, "path": arcname, "bytes": sizes[role], "sha256": hashes[role]}
        for role, arcname, *_rest in roles
    ]
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"

    parent = os.path.dirname(output)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        raise PackagingError(f"cannot create output parent: {parent}") from None

    part = output + ".part"
    owned: list[str] = []
    try:
        _write_zip(part, manifest_bytes, sources, sizes, roles, owned)
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
        "profileId": profile["profileId"],
        "output": output,
        "bytes": zip_bytes,
        "sha256": zip_sha,
        "roleCount": len(roles),
        "manifestReport": manifest_report,
        "checksumReport": checksum_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="package_edl.py",
        description="Build a pinned G4, G5 or TB710FU EDL toolchain ZIP from explicit files.",
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        default="tb322fc",
        metavar="NAME",
        help="trusted profile: tb322fc (G4, default), tb323fu (G5) or tb710fu",
    )
    parser.add_argument(
        "--platform",
        dest="platform",
        default="windows-x64",
        choices=sorted(PLATFORMS),
        help="toolchain platform: windows-x64 (default) or macos-arm64 (no --python-zip)",
    )
    for role, flag, help_text in COMMON_FLAGS:
        parser.add_argument(flag, dest=role, metavar="PATH", help=help_text)
    parser.add_argument(
        "--firehose",
        dest="firehose",
        metavar="PATH",
        default=None,
        help="approved firehose .melf source path (required for G4 and TB710FU)",
    )
    parser.add_argument(
        "--loader-root",
        dest="loader_root",
        metavar="PATH",
        default=None,
        help="directory holding the nine G5 loader materials (required for G5)",
    )
    parser.add_argument("--output", required=True, metavar="PATH", help="bundle ZIP output path")
    parser.add_argument(
        "--build-pins-json",
        dest="build_pins_json",
        metavar="PATH",
        default=None,
        help="optional schemaVersion=1 build-time pins JSON providing the client pin",
    )
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
