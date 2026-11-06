#!/usr/bin/env python3
"""Source build of the macOS (Apple silicon) installer window.

The macOS counterpart of build_installer.py. It reuses that script's manifest,
vendor and download checks and its pin generator, and runs on a Mac with the
.NET SDK and the Xcode command line tools:

1. manifest load + strict vendor file validation;
2. official input fetch (the same pinned downloads);
3. compile edl-ng for osx-arm64 and the universal boot packers from the
   checked-in sources;
4. take the osx-arm64 libusb dylib out of the same pinned LibUsbDotNet package
   (libusbPackage.extractMacos), combine the licenses, hash the fresh tools and
   generate CompiledToolPins;
5. package the G4, G5 and TB710FU EDL toolchains with --platform macos-arm64;
6. emit MSBuild props + build record, then (unless --prepare-only) publish
   FreedomInstaller.Mac for osx-arm64 and wrap it in an .app bundle.

The bundle is not signed or notarized. Stdlib only.
"""

import argparse
import json
import platform
import shutil
import sys
import uuid
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import build_installer as bi  # noqa: E402
import fetch_build_inputs  # noqa: E402
import package_edl  # noqa: E402


SCHEMA_VERSION = 1
RUNTIME = "osx-arm64"
PLATFORM = "macos-arm64"
APP_NAME = "ArmadaOS Freedom Installer"
BUNDLE_ID = "io.github.mydanyi.armadaos-freedom-installer"

_PROPERTY_NAMES = (
    "BundledEdlArchive",
    "BundledEdlG5Archive",
    "BundledEdlTb710fuArchive",
    "BundledEdlRawPacker",
    "BundledEdlRawUnpacker",
    "BundledAvbSigningKey",
)

# (profile, archive file name, MSBuild property)
_PROFILES = (
    ("tb322fc", "freedom-tb322fc-macos.zip", "BundledEdlArchive"),
    ("tb323fu", "freedom-tb323fu-macos.zip", "BundledEdlG5Archive"),
    ("tb710fu", "freedom-tb710fu-macos.zip", "BundledEdlTb710fuArchive"),
)


def _write_props(inputs, pins_source):
    lines = ["<Project>", "  <PropertyGroup>"]
    lines.append(f"    <BundledToolPinsSource>{bi._xml_escape(str(Path(pins_source).resolve()))}</BundledToolPinsSource>")
    for prop in _PROPERTY_NAMES:
        if prop not in inputs:
            raise SystemExit(f"props error: missing input property {prop}")
        lines.append(f"    <{prop}>{bi._xml_escape(str(Path(inputs[prop]).resolve()))}</{prop}>")
    lines.append("  </PropertyGroup>")
    lines.append("</Project>")
    lines.append("")
    return "\n".join(lines)


def prepare(repo_root, work_dir, manifest_path=None):
    """Build every input of the macOS window and return the build record."""
    repo_root = Path(repo_root).resolve()
    work_dir = Path(work_dir).resolve()
    if manifest_path is None:
        manifest_path = repo_root / "maintenance" / "build-inputs.json"

    # --- Phase 1: manifest + vendor validation ----------------------------
    manifest = fetch_build_inputs.load_manifest(str(manifest_path))
    bi._validate_vendor_files(repo_root, manifest)

    work_dir.mkdir(parents=True, exist_ok=True)
    downloads_root = work_dir / "downloads"
    downloads_root.mkdir(parents=True, exist_ok=True)
    runs_root = work_dir / "runs-macos"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_dir = runs_root / uuid.uuid4().hex
    run_dir.mkdir(parents=False, exist_ok=False)
    materials_dir = run_dir / "materials"
    materials_dir.mkdir()
    build_dir = run_dir / "build"
    build_dir.mkdir()
    env = bi._make_controlled_env(work_dir)

    # --- Phase 2: official inputs -----------------------------------------
    fetched = fetch_build_inputs.fetch_all(manifest, str(downloads_root))
    for dl_id in ("libusbPackage", "libusbLicense"):
        if dl_id not in fetched:
            raise SystemExit(f"fetch error: missing download id {dl_id!r}")

    # --- Phase 3: compile -------------------------------------------------
    edl_out = build_dir / "edl-ng"
    edl_out.mkdir()
    bi._run(["sh", str(repo_root / "tools" / "build-edl-ng.sh"), str(edl_out), RUNTIME],
            cwd=repo_root, env=env, phase="compile")
    packers_build = build_dir / "boot-packers"
    packers_build.mkdir()
    packers_out = build_dir / "boot-packers-out"
    packers_out.mkdir()
    bi._run(["sh", str(repo_root / "tools" / "build-boot-packers-macos.sh"), str(packers_build), str(packers_out)],
            cwd=repo_root, env=env, phase="compile")

    client = edl_out / "edl-ng"
    packer = packers_out / "MultiBootKernelPatcher"
    unpacker = packers_out / "UnpackTool"
    for label, path in (("client", client), ("packer", packer), ("unpacker", unpacker)):
        if not path.is_file():
            raise SystemExit(f"compile error: {label} executable missing at {path}")

    # --- Phase 4: libusb, license, pins -------------------------------------
    libusb_entry = next((dl for dl in manifest["downloads"] if dl.get("id") == "libusbPackage"), None)
    if libusb_entry is None or not isinstance(libusb_entry.get("extractMacos"), dict):
        raise SystemExit("manifest error: libusbPackage.extractMacos missing")
    dylib = materials_dir / "libusb-1.0.dylib"
    bi._atomic_write_bytes(dylib, bi._extract_libusb(fetched["libusbPackage"], libusb_entry["extractMacos"]))
    license_out = materials_dir / "LICENSE.txt"
    bi._atomic_write_text(license_out, bi._combine_license(repo_root, fetched["libusbLicense"]))

    tools = {}
    tool_paths = {}
    for name, path in (("client", client), ("packer", packer), ("unpacker", unpacker)):
        size, sha = bi._hash_file(path)
        tools[name] = {"bytes": size, "sha256": sha}
        tool_paths[name] = str(path.resolve())
    tool_pins = {"schemaVersion": SCHEMA_VERSION, "tools": tools}
    pins_json = run_dir / "tool-pins.json"
    bi._atomic_write_json(pins_json, tool_pins)
    pins_cs = run_dir / "CompiledToolPins.g.cs"
    bi._atomic_write_text(pins_cs, bi._generate_tool_pins_cs(tool_pins))

    # --- Phase 5: EDL toolchains --------------------------------------------
    scripts = {
        "avb": repo_root / "maintenance" / "avb_stock.py",
        "avbCli": repo_root / "maintenance" / "avb_stock_cli.py",
        "gpt": repo_root / "maintenance" / "portable_gpt.py",
        "gptCli": repo_root / "maintenance" / "edl_gpt_cli.py",
    }
    loaders = {
        "tb322fc": {"firehose": repo_root / "vendor" / "qualcomm" / "g4" / "firehose.melf"},
        "tb323fu": {"loader_root": repo_root / "vendor" / "qualcomm" / "g5"},
        "tb710fu": {"firehose": repo_root / "vendor" / "qualcomm" / "tb710fu" / "firehose.melf"},
    }
    packages_dir = run_dir / "packages"
    packages_dir.mkdir()
    inputs = {
        "BundledEdlRawPacker": str(packer.resolve()),
        "BundledEdlRawUnpacker": str(unpacker.resolve()),
        "BundledAvbSigningKey": str((repo_root / "vendor" / "aosp" / "testkey_rsa4096.pem").resolve()),
    }
    packages = {}
    for profile, archive_name, prop in _PROFILES:
        output = packages_dir / archive_name
        loader = loaders[profile]
        ns = argparse.Namespace(
            profile=profile,
            platform=PLATFORM,
            client=str(client.resolve()),
            usbLibrary=str(dylib.resolve()),
            license=str(license_out.resolve()),
            python=None,
            output=str(output.resolve()),
            build_pins_json=str(pins_json.resolve()),
            firehose=str(loader["firehose"].resolve()) if "firehose" in loader else None,
            loader_root=str(loader["loader_root"].resolve()) if "loader_root" in loader else None,
            **{role: str(path.resolve()) for role, path in scripts.items()},
        )
        package_edl.package(ns)
        inputs[prop] = str(output.resolve())
        packages[profile] = str(output.resolve())

    # --- Phase 6: props + record -------------------------------------------
    props_path = work_dir / "build-inputs-macos.props"
    record_path = work_dir / "build-record-macos.json"
    record = {
        "schemaVersion": SCHEMA_VERSION,
        "platform": PLATFORM,
        "runDirectory": str(run_dir.resolve()),
        "tools": tools,
        "toolPaths": tool_paths,
        "inputs": inputs,
        "toolPinsJson": str(pins_json.resolve()),
        "toolPinsSource": str(pins_cs.resolve()),
        "propsPath": str(props_path.resolve()),
        "packages": packages,
        "sourceFiles": bi._source_digest(repo_root, manifest),
    }
    bi._atomic_write_text(props_path, _write_props(inputs, pins_cs))
    bi._atomic_write_json(record_path, record)
    return record


def _info_plist(version):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>{APP_NAME}</string>
    <key>CFBundleDisplayName</key><string>ArmadaOS Freedom 安装助手</string>
    <key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>
    <key>CFBundleExecutable</key><string>FreedomInstaller.Mac</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>{version}</string>
    <key>CFBundleVersion</key><string>{version}</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
"""


def publish(repo_root, record, output_dir, env):
    """dotnet publish FreedomInstaller.Mac for osx-arm64, then lay out the .app bundle."""
    repo_root = Path(repo_root).resolve()
    output_dir = Path(output_dir).resolve()
    publish_dir = output_dir / "publish"
    app = output_dir / f"{APP_NAME}.app"
    for stale in (publish_dir, app):
        if stale.exists():
            raise SystemExit(f"publish error: output already exists, choose an empty --output-dir: {stale}")
    project = repo_root / "src" / "FreedomInstaller.Mac" / "FreedomInstaller.Mac.csproj"
    bi._run(
        ["dotnet", "publish", str(project), "-c", "Release", "-r", RUNTIME, "--self-contained", "true",
         "-p:UseSharedCompilation=false", f"-p:BundledBuildInputsProps={record['propsPath']}", "-o", str(publish_dir)],
        cwd=repo_root, env=env, phase="publish")
    version = None
    for line in project.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("<Version>") and line.endswith("</Version>"):
            version = line[len("<Version>"):-len("</Version>")]
            break
    if not version:
        raise SystemExit("publish error: FreedomInstaller.Mac.csproj declares no <Version>")
    (app / "Contents" / "Resources").mkdir(parents=True)
    shutil.copytree(publish_dir, app / "Contents" / "MacOS")
    bi._atomic_write_text(app / "Contents" / "Info.plist", _info_plist(version))
    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="Source build of the macOS installer window.")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.prepare_only and not args.output_dir:
        parser.error("--output-dir is required unless --prepare-only is set")
    if sys.platform != "darwin" or platform.machine() != "arm64":
        parser.error("run this on macOS on Apple silicon (it compiles with the Xcode command line tools)")

    repo_root = Path(_HERE).resolve().parent
    work_dir = Path(args.work_dir).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else None
    record = prepare(repo_root, work_dir, manifest_path=manifest_path)
    print(f"prepare complete: {record['propsPath']}", flush=True)
    if args.prepare_only:
        print(json.dumps(record, indent=2))
        return 0
    app = publish(repo_root, record, args.output_dir, bi._make_controlled_env(work_dir))
    print(f"publish complete: {app}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
