#!/usr/bin/env python3
"""Unified source build entrypoint for the Freedom Installer (win-x64).

Phases
------
1. manifest load + strict vendor file validation (before any download/compile)
2. official input fetch into a real cache, per-run isolated directories
3. compile all three tools from checked-in source
4. extract libusb + combined LICENSE, hash fresh tool outputs, generate pins
5. build Qualcomm driver ZIP
6. package the G4, G5 and TB710FU EDL toolchains via package_edl
7. emit MSBuild props + build record (atomic last-success pointers)

After prepare(), the CLI optionally runs `dotnet publish` of the WPF app against
the freshly generated props file.

Stdlib only. No GitHub API, no auth, no devices, no broad cleanup.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import fetch_build_inputs  # noqa: E402
import package_edl  # noqa: E402


SCHEMA_VERSION = 1

_PROPERTY_NAMES = (
    "BundledPlatformToolsArchive",
    "BundledEdlArchive",
    "BundledEdlG5Archive",
    "BundledEdlTb710fuArchive",
    "BundledQualcommDriverArchive",
    "BundledEdlRawPacker",
    "BundledEdlRawUnpacker",
    "BundledAvbSigningKey",
    "BundledGblPrcEfi",
    "BundledGblRowEfi",
)

_TOOL_NAMES = ("client", "packer", "unpacker")

_EXCLUDE_SOURCE_DIRS = {".git", "bin", "obj", "__pycache__"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _log(phase, msg):
    print(f"[{phase}] {msg}", flush=True)


def _hash_file(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _atomic_write_bytes(target, data):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_text(target, text):
    _atomic_write_bytes(target, text.encode("utf-8"))


def _atomic_write_json(target, obj):
    _atomic_write_text(target, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _xml_escape(text):
    s = str(text)
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&apos;")
    return s


def _validate_vendor_files(repo_root, manifest):
    """Validate every vendor file (exact bytes + SHA) BEFORE any download or
    compilation.  Also ensure the relative path stays inside the repo."""
    repo_root = Path(repo_root).resolve()
    entries = manifest.get("vendorFiles")
    if not isinstance(entries, list) or not entries:
        raise SystemExit("manifest error: vendorFiles is empty or missing")
    results = {}
    for entry in entries:
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel:
            raise SystemExit("manifest error: vendorFiles entry missing path")
        # Containment check: no traversal, no absolute.
        if os.path.isabs(rel):
            raise SystemExit(f"vendor error: absolute path in vendorFiles: {rel!r}")
        parts = Path(rel).parts
        if any(p == ".." for p in parts):
            raise SystemExit(f"vendor error: path traversal in vendorFiles: {rel!r}")
        resolved = (repo_root / rel).resolve()
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            raise SystemExit(f"vendor error: path escapes repo: {rel!r}")
        if not resolved.is_file():
            raise SystemExit(f"vendor error: missing required file: {rel} ({resolved})")
        want_bytes = entry.get("bytes")
        want_sha = entry.get("sha256")
        if not isinstance(want_bytes, int) or want_bytes < 0:
            raise SystemExit(f"manifest error: bad bytes for {rel!r}")
        if not isinstance(want_sha, str) or len(want_sha) != 64:
            raise SystemExit(f"manifest error: bad sha256 for {rel!r}")
        got_bytes, got_sha = _hash_file(resolved)
        if got_bytes != want_bytes:
            raise SystemExit(
                f"vendor mismatch: {rel} size {got_bytes} != expected {want_bytes}"
            )
        if got_sha.lower() != want_sha.lower():
            raise SystemExit(
                f"vendor mismatch: {rel} sha256 {got_sha} != expected {want_sha}"
            )
        results[rel] = resolved
    return results


def _make_controlled_env(work_dir):
    env = dict(os.environ)
    work_dir = Path(work_dir)
    tmp = work_dir / "tmp"
    dotnet_home = work_dir / "dotnet"
    nuget = work_dir / "nuget"
    tmp.mkdir(parents=True, exist_ok=True)
    dotnet_home.mkdir(parents=True, exist_ok=True)
    nuget.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    env["TEMP"] = str(tmp)
    env["TMP"] = str(tmp)
    env.setdefault("DOTNET_CLI_HOME", str(dotnet_home))
    env.setdefault("NUGET_PACKAGES", str(nuget))
    env["DOTNET_NOLOGO"] = "1"
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    return env


def _run(argv, cwd, env, phase):
    _log(phase, "run: " + " ".join(str(a) for a in argv))
    try:
        subprocess.run([str(a) for a in argv], cwd=str(cwd), env=env, check=True)
    except FileNotFoundError as exc:
        raise SystemExit(f"[{phase}] executable not found: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"[{phase}] command failed with exit code {exc.returncode}: "
            + " ".join(str(a) for a in argv)
        ) from exc


def _extract_libusb(nupkg_path, extract_spec):
    """Read ONLY the one declared native DLL out of the checked .nupkg."""
    inner = extract_spec.get("path")
    want_bytes = extract_spec.get("bytes")
    want_sha = extract_spec.get("sha256")
    if not inner or not isinstance(want_bytes, int) or not isinstance(want_sha, str):
        raise SystemExit("manifest error: libusbPackage.extract incomplete")
    with zipfile.ZipFile(nupkg_path, "r") as zf:
        try:
            data = zf.read(inner)
        except KeyError:
            raise SystemExit(
                f"libusb package missing declared member {inner!r}"
            )
    if len(data) != want_bytes:
        raise SystemExit(
            f"libusb DLL size {len(data)} != expected {want_bytes}"
        )
    got_sha = hashlib.sha256(data).hexdigest()
    if got_sha.lower() != want_sha.lower():
        raise SystemExit(
            f"libusb DLL sha256 {got_sha} != expected {want_sha}"
        )
    return data


def _combine_license(repo_root, libusb_license_path):
    edl_license = Path(repo_root) / "tools" / "edl-ng" / "LICENSE"
    if not edl_license.is_file():
        raise SystemExit(f"missing required license file: {edl_license}")
    parts = []
    parts.append("==== LICENSE (tools/edl-ng) ====\n")
    parts.append(edl_license.read_text(encoding="utf-8", errors="replace"))
    parts.append("\n\n==== LICENSE (libusb) ====\n")
    parts.append(Path(libusb_license_path).read_text(encoding="utf-8", errors="replace"))
    return "".join(parts)


def _generate_tool_pins_cs(tool_pins):
    tools = tool_pins["tools"]
    lines = [
        "// <auto-generated> by maintenance/build_installer.py — do not edit.",
        "namespace FreedomInstaller.Core",
        "{",
        "    internal static class CompiledToolPins",
        "    {",
    ]
    for name, label in (
        ("client", "Client"),
        ("packer", "Packer"),
        ("unpacker", "Unpacker"),
    ):
        info = tools[name]
        lines.append(f"        internal const long {label}Bytes = {int(info['bytes'])};")
    for name, label in (
        ("client", "Client"),
        ("packer", "Packer"),
        ("unpacker", "Unpacker"),
    ):
        info = tools[name]
        lines.append(
            f'        internal const string {label}Sha256 = "{info["sha256"]}";'
        )
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _build_driver_zip(repo_root, out_path):
    driver_root = Path(repo_root) / "vendor" / "qualcomm" / "driver"
    members = [
        (driver_root / "qcser.inf", "qcser.inf"),
        (driver_root / "qcser.cat", "qcser.cat"),
        (driver_root / "serial" / "amd64" / "qcusbser.sys", "serial/amd64/qcusbser.sys"),
    ]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for src, arc in members:
            if not src.is_file():
                raise SystemExit(f"driver zip: missing source file {src}")
            zf.write(src, arc)
    return out_path


def _source_digest(repo_root, manifest):
    """Sorted list of {path,bytes,sha256} for every checked-in source path and
    build script declared in the manifest."""
    repo_root = Path(repo_root).resolve()
    seen = set()
    entries = []

    def _add_hash(rel):
        if rel in seen:
            return
        seen.add(rel)
        p = repo_root / rel
        n, sha = _hash_file(p)
        entries.append({"path": rel, "bytes": n, "sha256": sha})

    def _walk(rel):
        p = repo_root / rel
        if p.is_file():
            _add_hash(rel)
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in _EXCLUDE_SOURCE_DIRS)
                for fn in sorted(files):
                    full = Path(root) / fn
                    relpath = full.relative_to(repo_root).as_posix()
                    _add_hash(relpath)
        else:
            raise SystemExit(f"source error: missing manifest source {rel!r}")

    for src in manifest.get("sources", []):
        if "path" in src:
            _walk(src["path"])
        if "paths" in src:
            for rel in src["paths"]:
                _walk(rel)
        build_script = src.get("buildScript")
        if isinstance(build_script, str) and build_script:
            _walk(build_script)
    entries.sort(key=lambda e: e["path"])
    return entries


def _write_props(path, inputs):
    lines = ["<Project>", "  <PropertyGroup>"]
    for prop in _PROPERTY_NAMES:
        if prop not in inputs:
            raise SystemExit(f"props error: missing input property {prop}")
        value = str(Path(inputs[prop]).resolve())
        lines.append(f"    <{prop}>{_xml_escape(value)}</{prop}>")
    lines.append("  </PropertyGroup>")
    lines.append("</Project>")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# public: prepare
# ---------------------------------------------------------------------------


def prepare(repo_root, work_dir, manifest_path=None):
    """Run the source build input preparation.

    Returns a record dict describing every generated artefact.
    """
    repo_root = Path(repo_root).resolve()
    work_dir = Path(work_dir).resolve()
    if manifest_path is None:
        manifest_path = repo_root / "maintenance" / "build-inputs.json"
    manifest_path = Path(manifest_path)

    # --- Phase 1a: manifest load -----------------------------------------
    _log("manifest", f"loading {manifest_path}")
    manifest = fetch_build_inputs.load_manifest(str(manifest_path))

    # --- Phase 1b: strict vendor validation BEFORE any download/compile ---
    _log("vendor", "validating checked-in vendor files")
    vendor_map = _validate_vendor_files(repo_root, manifest)
    _log("vendor", f"{len(vendor_map)} vendor files OK")

    # --- Phase 1c: work directories, per-run isolation --------------------
    work_dir.mkdir(parents=True, exist_ok=True)
    downloads_root = work_dir / "downloads"
    downloads_root.mkdir(parents=True, exist_ok=True)
    runs_root = work_dir / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=False, exist_ok=False)
    materials_dir = run_dir / "materials"
    materials_dir.mkdir()
    run_build_dir = run_dir / "build"
    run_build_dir.mkdir()

    env = _make_controlled_env(work_dir)

    # --- Phase 2: fetch official inputs -----------------------------------
    _log("fetch", f"fetching official inputs -> {downloads_root}")
    fetched = fetch_build_inputs.fetch_all(manifest, str(downloads_root))
    for dl_id in ("platformTools", "python", "libusbPackage", "libusbLicense", "gblPrc", "gblRow"):
        if dl_id not in fetched:
            raise SystemExit(f"fetch error: missing download id {dl_id!r}")
    _log("fetch", "official inputs ready")

    # --- Phase 3: compile the three tools --------------------------------
    _log("compile", "building edl-ng")
    edl_out = run_build_dir / "edl-ng"
    edl_out.mkdir()
    _run(
        ["sh", str(repo_root / "tools" / "build-edl-ng.sh"), str(edl_out)],
        cwd=repo_root,
        env=env,
        phase="compile",
    )

    _log("compile", "building boot packers")
    packers_build = run_build_dir / "boot-packers"
    packers_build.mkdir()
    packers_out = run_build_dir / "boot-packers-out"
    packers_out.mkdir()
    _run(
        [
            "sh",
            str(repo_root / "tools" / "build-boot-packers.sh"),
            str(packers_build),
            str(packers_out),
        ],
        cwd=repo_root,
        env=env,
        phase="compile",
    )

    client_exe = edl_out / "edl-ng.exe"
    packer_exe = packers_out / "MultiBootKernelPatcher.exe"
    unpacker_exe = packers_out / "UnpackTool.exe"
    for label, p in (
        ("client", client_exe),
        ("packer", packer_exe),
        ("unpacker", unpacker_exe),
    ):
        if not p.is_file():
            raise SystemExit(f"compile error: {label} executable missing at {p}")
    _log("compile", "three tools built")

    # --- Phase 4: libusb + license + pins --------------------------------
    _log("libusb", "extracting declared native DLL from .nupkg")
    libusb_entry = None
    for dl in manifest["downloads"]:
        if dl.get("id") == "libusbPackage":
            libusb_entry = dl
            break
    if libusb_entry is None:
        raise SystemExit("manifest error: libusbPackage download missing")
    extract_spec = libusb_entry.get("extract") or {}
    libusb_data = _extract_libusb(fetched["libusbPackage"], extract_spec)
    libusb_dll_out = materials_dir / "libusb-1.0.dll"
    _atomic_write_bytes(libusb_dll_out, libusb_data)

    _log("license", "combining edl-ng + libusb licenses")
    license_text = _combine_license(repo_root, fetched["libusbLicense"])
    license_out = materials_dir / "LICENSE.txt"
    _atomic_write_text(license_out, license_text)

    _log("pins", "hashing freshly built tools")
    tools = {}
    tool_paths = {}
    for name, path in (
        ("client", client_exe),
        ("packer", packer_exe),
        ("unpacker", unpacker_exe),
    ):
        n, sha = _hash_file(path)
        tools[name] = {"bytes": n, "sha256": sha}
        tool_paths[name] = str(path.resolve())
    tool_pins = {"schemaVersion": SCHEMA_VERSION, "tools": tools}
    tool_pins_json_path = run_dir / "tool-pins.json"
    _atomic_write_json(tool_pins_json_path, tool_pins)

    pins_cs = _generate_tool_pins_cs(tool_pins)
    pins_cs_path = run_dir / "CompiledToolPins.g.cs"
    _atomic_write_text(pins_cs_path, pins_cs)

    # --- Phase 5: driver ZIP ---------------------------------------------
    _log("driver", "building Qualcomm driver ZIP")
    driver_zip = run_dir / "qualcomm-driver.zip"
    _build_driver_zip(repo_root, driver_zip)

    # --- Phase 6: package G4 / G5 / TB710FU -------------------------------
    python_zip = fetched["python"]
    avb = repo_root / "maintenance" / "avb_stock.py"
    avb_cli = repo_root / "maintenance" / "avb_stock_cli.py"
    gpt = repo_root / "maintenance" / "portable_gpt.py"
    gpt_cli = repo_root / "maintenance" / "edl_gpt_cli.py"
    for label, p in (
        ("avb_stock.py", avb),
        ("avb_stock_cli.py", avb_cli),
        ("portable_gpt.py", gpt),
        ("edl_gpt_cli.py", gpt_cli),
    ):
        if not p.is_file():
            raise SystemExit(f"package error: missing repository script {p}")

    firehose_melf = repo_root / "vendor" / "qualcomm" / "g4" / "firehose.melf"
    g5_root = repo_root / "vendor" / "qualcomm" / "g5"
    tb710fu_firehose = repo_root / "vendor" / "qualcomm" / "tb710fu" / "firehose.melf"
    if not firehose_melf.is_file():
        raise SystemExit(f"package error: missing G4 firehose {firehose_melf}")
    if not g5_root.is_dir():
        raise SystemExit(f"package error: missing G5 loader root {g5_root}")
    if not tb710fu_firehose.is_file():
        raise SystemExit(f"package error: missing TB710FU firehose {tb710fu_firehose}")

    packages_dir = run_dir / "packages"
    packages_dir.mkdir()

    def _package(profile, output):
        ns = {
            "profile": profile,
            "client": str(client_exe.resolve()),
            "usbLibrary": str(libusb_dll_out.resolve()),
            "license": str(license_out.resolve()),
            "python": str(Path(python_zip).resolve()),
            "avb": str(avb.resolve()),
            "avbCli": str(avb_cli.resolve()),
            "gpt": str(gpt.resolve()),
            "gptCli": str(gpt_cli.resolve()),
            "firehose": (
                str(firehose_melf.resolve()) if profile == "tb322fc"
                else str(tb710fu_firehose.resolve()) if profile == "tb710fu"
                else None
            ),
            "loader_root": str(g5_root.resolve()) if profile == "tb323fu" else None,
            "output": str(Path(output).resolve()),
            "build_pins_json": str(tool_pins_json_path.resolve()),
        }
        _log("package", f"{profile} -> {output}")
        return package_edl.package(argparse.Namespace(**ns))

    g4_out = packages_dir / "freedom-tb322fc.zip"
    g5_out = packages_dir / "freedom-tb323fu.zip"
    g4_report = _package("tb322fc", g4_out)
    g5_report = _package("tb323fu", g5_out)
    tb710fu_out = packages_dir / "freedom-tb710fu.zip"
    tb710fu_report = _package("tb710fu", tb710fu_out)

    # --- Phase 7: props + record ----------------------------------------
    inputs = {
        "BundledPlatformToolsArchive": str(Path(fetched["platformTools"]).resolve()),
        "BundledEdlArchive": str(g4_out.resolve()),
        "BundledEdlG5Archive": str(g5_out.resolve()),
        "BundledEdlTb710fuArchive": str(tb710fu_out.resolve()),
        "BundledQualcommDriverArchive": str(driver_zip.resolve()),
        "BundledEdlRawPacker": str(packer_exe.resolve()),
        "BundledEdlRawUnpacker": str(unpacker_exe.resolve()),
        "BundledAvbSigningKey": str(
            (repo_root / "vendor" / "aosp" / "testkey_rsa4096.pem").resolve()
        ),
        "BundledGblPrcEfi": str(Path(fetched["gblPrc"]).resolve()),
        "BundledGblRowEfi": str(Path(fetched["gblRow"]).resolve()),
    }
    for prop, path_str in inputs.items():
        if not Path(path_str).is_file():
            raise SystemExit(f"props error: missing input for {prop}: {path_str}")

    props_xml = _write_props(None, inputs)
    marker = "  <PropertyGroup>\n"
    extra = f"    <BundledToolPinsSource>{_xml_escape(str(pins_cs_path.resolve()))}</BundledToolPinsSource>\n"
    if marker not in props_xml:
        raise SystemExit("props error: could not locate PropertyGroup marker")
    props_xml = props_xml.replace(marker, marker + extra, 1)

    props_path = work_dir / "build-inputs.props"
    record_path = work_dir / "build-record.json"

    # --- source digest ---------------------------------------------------
    _log("record", "computing source digest")
    source_digest = _source_digest(repo_root, manifest)
    sources_meta = []
    for src in manifest.get("sources", []):
        item = {k: v for k, v in src.items() if k not in ("path", "paths")}
        if "path" in src:
            item["path"] = src["path"]
        if "paths" in src:
            item["paths"] = list(src["paths"])
        sources_meta.append(item)

    record = {
        "schemaVersion": SCHEMA_VERSION,
        "runDirectory": str(run_dir.resolve()),
        "tools": {name: dict(tools[name]) for name in _TOOL_NAMES},
        "toolPaths": tool_paths,
        "inputs": {k: str(Path(v).resolve()) for k, v in inputs.items()},
        "toolPinsJson": str(tool_pins_json_path.resolve()),
        "toolPinsSource": str(pins_cs_path.resolve()),
        "propsPath": str(props_path.resolve()),
        "packages": {
            "tb322fc": str(g4_out.resolve()),
            "tb323fu": str(g5_out.resolve()),
            "tb710fu": str(tb710fu_out.resolve()),
        },
        "sources": sources_meta,
        "sourceFiles": source_digest,
    }

    # Write props before record so a reader sees a record only after props exists.
    _atomic_write_text(props_path, props_xml)
    _atomic_write_json(record_path, record)
    _log("done", f"props -> {props_path}")
    _log("done", f"record -> {record_path}")
    return record


# ---------------------------------------------------------------------------
# CLI: prepare + dotnet publish
# ---------------------------------------------------------------------------


def _default_publish(record, output_dir, env):
    props = record["propsPath"]
    repo_root = Path(_HERE).resolve().parent
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "dotnet",
        "publish",
        str(repo_root / "src" / "FreedomInstaller.App" / "FreedomInstaller.App.csproj"),
        "-c",
        "Release",
        "-r",
        "win-x64",
        "--self-contained",
        "true",
        "-p:UseSharedCompilation=false",
        f"-p:BundledBuildInputsProps={props}",
        "-o",
        str(output_dir),
    ]
    _run(argv, cwd=repo_root, env=env, phase="publish")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Unified source build entrypoint for the Freedom Installer."
    )
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)

    if not args.prepare_only and not args.output_dir:
        parser.error("--output-dir is required unless --prepare-only is set")

    repo_root = Path(_HERE).resolve().parent
    work_dir = Path(args.work_dir).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else None

    record = prepare(repo_root, work_dir, manifest_path=manifest_path)
    print(f"prepare complete: {record['propsPath']}", flush=True)

    if args.prepare_only:
        print(json.dumps({"propsPath": record["propsPath"], "record": record}, indent=2))
        return 0

    env = _make_controlled_env(work_dir)
    _default_publish(record, args.output_dir, env)
    print(f"publish complete: {Path(args.output_dir).resolve()}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
