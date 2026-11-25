#!/usr/bin/env python3
"""Build, package, and test one native release without signing or publishing."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
RUST = "1.100.0"
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-musl", "x86_64-pc-windows-msvc")
# The only non-native build: a static musl executable from a glibc host.
CROSS = {"x86_64-unknown-linux-gnu": "x86_64-unknown-linux-musl"}
# The musl release in Rust 1.100's self-contained x86_64-unknown-linux-musl libc.a.
MUSL = "1.2.5"
SOURCE_FILES = (
    "Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "RELEASING.md",
    "THIRD-PARTY-NOTICES.txt", "scripts/release.py", "scripts/release-audit.sh",
    ".github/workflows/release.yml", ".github/workflows/native-tests.yml",
    ".github/scripts/core-wallet.sh", ".github/scripts/windows-file-access.ps1",
    "src/main.rs", "src/keccak2.rs", "src/output.rs", "src/output/file_access_tests.rs",
    "src/pattern.rs", "src/preview.rs", "src/protocol.rs", "tests/cli.rs",
    "tests/core_descriptor.py", "tests/data/COPYING", "tests/data/core-legacy-falcon512.txt",
    f"licenses/musl-{MUSL}/COPYRIGHT",
)
RUST_NOTICES = (
    "COPYRIGHT-library.html", "licenses/Apache-2.0.txt", "licenses/BSD-2-Clause.txt",
    "licenses/CC-BY-SA-4.0.txt", "licenses/GCC-exception-3.1.txt", "licenses/GPL-2.0-only.txt",
    "licenses/GPL-3.0-or-later.txt", "licenses/ISC.txt", "licenses/LLVM-exception.txt",
    "licenses/MIT.txt", "licenses/NCSA.txt", "licenses/OFL-1.1.txt", "licenses/Unicode-3.0.txt",
)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
ZIP_DATE = (1980, 1, 1, 0, 0, 0)
VENDOR_CONFIG = '''[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, encoding="utf-8", **kwargs).strip()


def sha256(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def version():
    package = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]
    require(package["name"] == "tdc-vanity", "Unexpected Cargo package name")
    semver = package["version"]
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", semver),
            "Cargo version cannot be used in an asset name")
    return semver


def check_tag():
    require(os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_REF_TYPE") == "tag"
            and os.environ.get("GITHUB_REF_PROTECTED") == "true", "Release requires a protected tag push")
    expected = "v" + version()
    require(os.environ.get("GITHUB_REF") == "refs/tags/" + expected,
            f"Release tag must match Cargo.toml ({expected})")
    event_commit = command("git", "rev-parse", "--verify", os.environ["GITHUB_SHA"] + "^{commit}", cwd=ROOT)
    require(command("git", "rev-parse", "HEAD", cwd=ROOT) == event_commit,
            "Checkout does not match the tagged event commit")


def input_env(rustc):
    # Ignore ambient compiler/target overrides. Explicitly select the toolchain for Cargo.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("RUST", "CARGO_")) or key in ("CARGO_HOME", "RUSTUP_HOME")}
    env.update(RUSTC=str(rustc), CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
               SOURCE_DATE_EPOCH="315532800", TZ="UTC")
    env["PATH"] = str(rustc.parent) + os.pathsep + env["PATH"]
    if sys.platform == "darwin":
        env["DYLD_LIBRARY_PATH"] = str(rustc.parent.parent / "lib")
    return env


def native_tools(target, env):
    if target.endswith("darwin"):
        env["SDKROOT"] = command("xcrun", "--sdk", "macosx", "--show-sdk-path", env=env)
        env["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
        sdk = command("xcodebuild", "-version", env=env) + "\nSDK " + command(
            "xcrun", "--sdk", "macosx", "--show-sdk-version", env=env)
        driver = command("xcrun", "--find", "clang", env=env)
        linker = command("xcrun", "--find", "ld", env=env)
        flags = [f"-Clinker={driver}", f"-Clink-arg=--ld-path={linker}",
                 "-Clink-arg=-Wl,-no_adhoc_codesign"]
        linker_version = command(linker, "-v", env=env, stderr=subprocess.STDOUT)
    elif "linux" in target:
        driver = "/usr/bin/gcc-13"
        linker = "/usr/bin/ld.bfd"
        sdk = command("getconf", "GNU_LIBC_VERSION") + "\n" + command(
            "dpkg-query", "-W", "libc6-dev", "linux-libc-dev")
        flags = [f"-Clinker={driver}", "-Clink-arg=-fuse-ld=bfd"]
        if target.endswith("musl"):
            # Rust's self-contained musl libc and startup files replace the host's.
            flags.append("-Clink-self-contained=yes")
            sdk += f"\nmusl {MUSL} (Rust self-contained)"
        else:
            flags.insert(1, "-Clinker-features=-lld")
        linker_version = command(linker, "--version", env=env)
    else:
        require(env.get("VSCMD_ARG_TGT_ARCH") == "x64" and env.get("WINDOWSSDKVERSION"),
                "Run from an x64 MSVC developer shell with a selected Windows SDK")
        linker = str(Path(env["VCTOOLSINSTALLDIR"]) / "bin/Hostx64/x64/link.exe")
        driver = linker
        sdk = env["WINDOWSSDKVERSION"].rstrip("\\/") + " (VC tools " + env["VCTOOLSVERSION"] + ")"
        # LINK and _LINK_ can inject flags independently of rustc.
        env.pop("LINK", None)
        env.pop("_LINK_", None)
        flags = [f"-Clinker={linker}", "-Clink-arg=/Brepro", "-Clink-arg=/INCREMENTAL:NO"]
        linker_version = command(linker, "/?", env=env).splitlines()[0]
    driver_version = linker_version if driver == linker else command(driver, "--version", env=env)
    report = {"sdk": sdk, "driver": driver, "driver_version": driver_version,
              "driver_sha256": sha256(Path(driver)), "linker": linker,
              "linker_version": linker_version, "linker_sha256": sha256(Path(linker))}
    return flags, report


def copy_allowlist(source, mode):
    for name in SOURCE_FILES:
        dest = source / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if mode == "tag":
            # Read Git blob bytes directly, including on CRLF-configured checkouts.
            dest.write_bytes(subprocess.check_output(["git", "show", f"HEAD:{name}"], cwd=ROOT))
        else:
            original = ROOT / name
            require(original.is_file() and not original.is_symlink(), f"Expected a regular source file: {name}")
            shutil.copyfile(original, dest)


def vendor_allowlist(source, locked):
    names = set()
    for package in locked:
        require(package["source"] == REGISTRY, "Release supports crates.io dependencies only")
        stem = f'{package["name"]}-{package["version"]}'
        folder = source / "vendor" / stem
        manifest = folder / ".cargo-checksum.json"
        index = json.loads(manifest.read_bytes())
        require(index["package"] == package["checksum"], f"Cargo.lock checksum mismatch for {stem}")
        names.add(f"vendor/{stem}/.cargo-checksum.json")
        for filename, checksum in index["files"].items():
            path = PurePosixPath(filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in filename,
                    f"Invalid vendored path in {stem}")
            item = folder / filename
            require(item.is_file() and not item.is_symlink() and sha256(item) == checksum,
                    f"Vendored file failed checksum: {stem}/{filename}")
            names.add(f"vendor/{stem}/{filename}")
    # Cargo builds and the source archive must see the same vendored inputs.
    actual = {item.relative_to(source).as_posix() for item in (source / "vendor").rglob("*")
              if item.is_file() or item.is_symlink()}
    require(names == actual, "Vendor directory differs from the locked package manifests")
    return names


def sbom_and_notices(metadata, locked, target, source):
    root = metadata["resolve"]["root"]
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    archive_hashes = {(p["name"], p["version"]): p["checksum"] for p in locked}
    graph = {}
    pending = [root]
    while pending:
        current = pending.pop()
        if current in graph:
            continue
        graph[current] = {dep["pkg"] for dep in nodes[current]["deps"]
                          if any(kind["kind"] != "dev" for kind in dep["dep_kinds"])}
        pending.extend(graph[current])

    components = {}
    licenses = {}
    notices = (source / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8").rstrip()
    if target.endswith("musl"):
        musl = f"licenses/musl-{MUSL}/COPYRIGHT"
        licenses[musl] = source / musl
        notices += (f"\n\nThe Linux executable statically links musl libc {MUSL} and its startup files\n"
                    f"(MIT; {musl}). Rust also links LLVM libunwind and crtbegin/crtend\n"
                    "objects (Apache-2.0 WITH LLVM-exception; see rust-notices/licenses).")
    notices += f"\n\nCargo dependency notices for {target}\n\n"
    for package_id in sorted(graph, key=lambda key: (packages[key]["name"], packages[key]["version"])):
        item = packages[package_id]
        name, release = item["name"], item["version"]
        purl = f"pkg:cargo/{name}@{release}"
        component = {"type": "application" if package_id == root else "library",
                     "name": name, "version": release,
                     "bom-ref": f"{name}:{release}" if package_id == root else purl}
        if package_id != root:
            component["purl"] = purl
            checksum = archive_hashes[name, release]
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
            if item["license"]:
                # Cargo's deprecated slash syntax means OR in an SPDX expression.
                component["licenses"] = [{"expression": item["license"].replace("/", " OR ")}]
            stem = f"{name}-{release}"
            folder = source / "vendor" / stem
            files = {p.relative_to(folder).as_posix() for p in folder.iterdir() if p.is_file()
                     and p.name.lower().startswith(("license", "copying", "copyright", "notice", "unlicense"))}
            if item["license_file"]:
                files.add(item["license_file"])
            require(files, f"Missing license text for {stem}")
            notices += f'{stem} — {item["license"] or "See license file"}\n'
            for filename in sorted(files):
                path = PurePosixPath(filename)
                require(not path.is_absolute() and ".." not in path.parts and (folder / filename).is_file(),
                        f"Missing notice {stem}/{filename}")
                licenses[f"licenses/{stem}/{path}"] = folder / filename
                notices += f"  licenses/{stem}/{path}\n"
        components[package_id] = component

    if target.endswith("musl"):
        purl = f"pkg:generic/musl@{MUSL}"
        components["musl"] = {"type": "library", "name": "musl", "version": MUSL, "bom-ref": purl,
                              "purl": purl, "licenses": [{"expression": "MIT"}]}
    refs = {key: value["bom-ref"] for key, value in components.items()}
    sbom = {"$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": components[root],
                         "properties": [{"name": "tdc-vanity:target", "value": target}]},
            "components": [component for key, component in components.items() if key != root],
            "dependencies": [{"ref": refs[key], "dependsOn": sorted(refs[dep] for dep in deps)}
                             for key, deps in sorted(graph.items(), key=lambda pair: refs[pair[0]])]}
    return json_bytes(sbom), notices.encode(), licenses


def compare(first, second, output, label):
    one, two = first.read_bytes(), second.read_bytes()
    first_hash, second_hash = hashlib.sha256(one).hexdigest(), hashlib.sha256(two).hexdigest()
    print(f"{label} A {len(one)} bytes SHA-256 {first_hash}")
    print(f"{label} B {len(two)} bytes SHA-256 {second_hash}")
    if one != two:
        offset = next((i for i, pair in enumerate(zip(one, two)) if pair[0] != pair[1]), min(len(one), len(two)))
        diagnostics = output / "diagnostics"
        diagnostics.mkdir(exist_ok=True)
        shutil.copyfile(first, diagnostics / f"A-{first.name}")
        shutil.copyfile(second, diagnostics / f"B-{second.name}")
        message = f"Unexplained {label} difference at file offset {offset}; SHA-256 A {first_hash}, B {second_hash}"
        (diagnostics / "difference.txt").write_text(message + "\n", encoding="utf-8")
        raise ValueError(message)
    return first_hash


def normalize_macho_uuid(binary):
    """Replace the linker-supplied UUID in an unsigned, thin arm64 executable."""
    mach_header = struct.Struct("<8I")
    load_header = struct.Struct("<2I")
    data = bytearray(binary.read_bytes())
    require(len(data) >= mach_header.size, "Truncated Mach-O header")
    magic, cpu, _, file_type, ncmds, size, _, _ = mach_header.unpack_from(data)
    require((magic, cpu, file_type) == (0xFEEDFACF, 0x0100000C, 2), "Expected an arm64 Mach-O executable")
    offset, limit = mach_header.size, mach_header.size + size
    require(limit <= len(data), "Truncated Mach-O load commands")
    uuid_at = None
    for _ in range(ncmds):
        require(offset + load_header.size <= limit, "Truncated Mach-O load command")
        kind, length = load_header.unpack_from(data, offset)
        require(length >= load_header.size and length % 8 == 0 and offset + length <= limit,
                "Invalid Mach-O load command size")
        require(kind != 0x1D, "Expected Mach-O without an LC_CODE_SIGNATURE")
        if kind == 0x1B:  # LC_UUID
            require(length == 24 and uuid_at is None, "Invalid or duplicate Mach-O UUID command")
            uuid_at = offset + load_header.size
        offset += length
    require(offset == limit and uuid_at is not None, "Missing Mach-O UUID command")
    original = data[uuid_at:uuid_at + 16].hex()
    data[uuid_at:uuid_at + 16] = bytes(16)
    derived = bytearray(hashlib.sha256(data).digest()[:16])
    derived[6] = (derived[6] & 0x0F) | 0x80  # RFC 9562 custom UUID version 8.
    derived[8] = (derived[8] & 0x3F) | 0x80  # RFC 9562 variant.
    data[uuid_at:uuid_at + 16] = derived
    binary.write_bytes(data)
    print(f"Mach-O LC_UUID {original} -> {derived.hex()} (SHA-256 of unsigned image with UUID zeroed)")


def archive_name(release, target, mode):
    part = "-rehearsal" if mode == "rehearsal" else ""
    return f"tdc-vanity-v{release}{part}-{target}.zip"


def write_archive(path, assets, executable):
    with zipfile.ZipFile(path, "x") as archive:
        for name, data in sorted(assets.items()):
            entry = zipfile.ZipInfo(name, ZIP_DATE)
            entry.create_system = 3  # Unix mode bits on every host.
            entry.external_attr = (stat.S_IFREG | (0o755 if name == executable else 0o644)) << 16
            archive.writestr(entry, data.read_bytes() if isinstance(data, Path) else data,
                             compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def check_archive(archive, assets, executable):
    require(archive.namelist() == sorted(assets), "ZIP contents differ from the allowlist")
    for item in archive.infolist():
        expected_mode = stat.S_IFREG | (0o755 if item.filename == executable else 0o644)
        require(item.date_time == ZIP_DATE and item.create_system == 3
                and item.external_attr >> 16 == expected_mode, f"ZIP metadata drift: {item.filename}")
    require(archive.testzip() is None, "ZIP CRC check failed")


def require_static_elf(binary):
    """Reject an x86-64 ELF that needs a program interpreter or shared libraries."""
    data = binary.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 62,
            "Expected a little-endian x86-64 ELF executable")
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<2H", data, 54)
    require(phentsize == 56 and phoff + phnum * 56 <= len(data), "Invalid ELF program headers")
    for index in range(phnum):
        kind, _, offset, _, _, size = struct.unpack_from("<2I4Q", data, phoff + index * 56)
        require(kind != 3, "ELF executable requests a program interpreter (PT_INTERP)")
        if kind == 2:  # PT_DYNAMIC: static-pie keeps one for self-relocation.
            require(offset + size <= len(data) and size % 16 == 0, "Invalid ELF dynamic section")
            tags = [struct.unpack_from("<q", data, at)[0] for at in range(offset, offset + size, 16)]
            require(1 not in tags[:tags.index(0) if 0 in tags else None],
                    "ELF executable needs shared libraries (DT_NEEDED)")
    print("PASS ELF has no PT_INTERP and no DT_NEEDED entries (statically linked)")


def smoke_archive(path, assets, executable, target, version_string, expected_hash, work):
    unpacked = work / "unpacked"
    unpacked.mkdir()
    with zipfile.ZipFile(path) as archive:
        check_archive(archive, assets, executable)
        if os.name == "nt":
            archive.extractall(unpacked)
    if os.name != "nt":
        subprocess.run(["unzip", "-q", str(path), "-d", str(unpacked)], check=True)
    binary = unpacked / executable
    require(sha256(binary) == expected_hash, "Extracted executable differs from the verified build")
    if "linux" in target:
        require_static_elf(binary)
    if sys.platform == "darwin":
        subprocess.run(["codesign", "--verify", "--strict", binary], check=True, timeout=30)
    require(b"--out" in subprocess.check_output([binary, "--help"], timeout=30), "Extracted help failed")
    require(command(binary, "--version", timeout=30) == f"tdc-vanity {version_string}",
            "Extracted executable version differs from Cargo.toml")
    with tempfile.TemporaryDirectory(prefix="smoke-", dir=work) as secret_dir:
        output = Path(secret_dir) / "disposable.wif"
        args = [binary, "--prefix=T", "--workers=1", "--out", output]
        first = subprocess.run(args, capture_output=True, timeout=60)
        require(first.returncode == 0 and output.is_file(), "Extracted executable could not mine and export")
        record = output.read_bytes()
        address, sep, wif = record.rstrip(b"\n").partition(b":")
        require(sep and wif and address.startswith(b"T") and first.stdout == address + b"\n"
                and wif not in first.stderr, "Extracted executable produced invalid output")
        second = subprocess.run(args, capture_output=True, timeout=30)
        require(second.returncode != 0 and record == output.read_bytes(), "Extracted executable overwrote a key")
    print("PASS extracted binary help, version, disposable export, and no-overwrite")


def build(args):
    release = version()
    if args.mode == "tag":
        check_tag()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    require(not any(output.iterdir()), "Output directory must be empty")
    rustc = Path(command("rustup", "which", "--toolchain", RUST, "rustc"))
    cargo = rustc.with_name("cargo.exe" if os.name == "nt" else "cargo")
    env = input_env(rustc)
    rust = command(rustc, "-vV", env=env)
    host = next(line.split(": ", 1)[1] for line in rust.splitlines() if line.startswith("host: "))
    target = args.target or CROSS.get(host, host)
    require(target in TARGETS and target in (host, CROSS.get(host)), f"Unsupported build: {host} -> {target}")
    flags, sdk = native_tools(target, env)
    if target.endswith("musl"):
        # The notices name this musl release; refuse a toolchain that bundles another.
        libc = rustc.parent.parent / "lib/rustlib" / target / "lib/self-contained/libc.a"
        require(f"\0{MUSL}\0".encode() in libc.read_bytes(), f"Rust's bundled libc.a is not musl {MUSL}")
    has_git = (ROOT / ".git").exists()
    report = {"host": host, "target": target, "commit": command("git", "rev-parse", "HEAD", cwd=ROOT)
              if has_git else None, "mode": args.mode, "os": platform.platform(),
              "uses_working_tree_sources": args.mode == "rehearsal",
              "runner_label": os.environ.get("TDC_IMAGE"),
              "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
              "rustc": rust, "cargo": command(cargo, "-V", env=env), "native_tools": sdk,
              "python": platform.python_version(), "zlib": zlib.ZLIB_RUNTIME_VERSION}
    print(json_bytes(report).decode(), flush=True)
    with tempfile.TemporaryDirectory(prefix="tdc-release-") as directory:
        work = Path(directory).resolve()
        source = work / "inputs"
        copy_allowlist(source, args.mode)
        locked = [pkg for pkg in tomllib.loads((source / "Cargo.lock").read_text())["package"] if "source" in pkg]
        # The corresponding source can run the same helper using its included vendor cache.
        if args.mode == "rehearsal" and (ROOT / "vendor").is_dir() and (ROOT / ".cargo/config.toml").is_file():
            shutil.copytree(ROOT / "vendor", source / "vendor", symlinks=True)
        else:
            subprocess.run([cargo, "vendor", "--locked", "--versioned-dirs", str(source / "vendor"),
                            *(["--offline"] if args.offline else [])], cwd=source, env=env, check=True,
                           stdout=subprocess.DEVNULL)
        names = vendor_allowlist(source, locked) | set(SOURCE_FILES) | {".cargo/config.toml"}
        (source / ".cargo").mkdir()
        (source / ".cargo/config.toml").write_bytes(VENDOR_CONFIG.encode())
        report["source_sha256"] = {name: sha256(source / name) for name in sorted(SOURCE_FILES)}
        report["rustflags"] = [*flags, "-Cstrip=symbols", "--remap-path-prefix=<build>=/tdc-vanity"]

        builds = [work / "a", work / "second-build"]
        # Identical flags for both invocations keep Cargo's crate hashes stable.
        remaps = sorted({p for path in builds for p in (str(path), path.as_posix())})
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([*flags, "-Cstrip=symbols", *(
            f"--remap-path-prefix={prefix}=/tdc-vanity" for prefix in remaps)])
        binary_name = "tdc-vanity.exe" if os.name == "nt" else "tdc-vanity"
        binaries = []
        for location in builds:
            tree = location / "source"
            shutil.copytree(source, tree)
            build_env = dict(env, CARGO_HOME=str(location / "cargo"), CARGO_TARGET_DIR=str(location / "target"))
            subprocess.run([cargo, "build", "--release", "--locked", "--offline", "--target", target],
                           cwd=tree, env=build_env, check=True)
            binaries.append(location / "target" / target / "release" / binary_name)

        if target.endswith("darwin"):
            for binary in binaries:
                normalize_macho_uuid(binary)
            report["normalized_unsigned_macho_sha256"] = compare(*binaries, output, "unsigned Mach-O")
            for binary in binaries:
                subprocess.run(["codesign", "--sign", "-", "--timestamp=none", "--identifier", "tdc-vanity", binary],
                               check=True, timeout=30)
        binary_hash = compare(*binaries, output, "executable")
        report["pre_distribution_executable_sha256"] = binary_hash
        graph = json.loads(command(cargo, "metadata", "--format-version", "1", "--locked", "--offline",
                                   "--filter-platform", target, cwd=tree, env=build_env))
        sbom, notices, licenses = sbom_and_notices(graph, locked, target, source)
        executable = f"bin/{binary_name}"
        assets = dict(licenses)
        rust_docs = rustc.parent.parent / "share/doc/rust"
        assets.update({f"rust-notices/{name}": rust_docs / name for name in RUST_NOTICES})
        assets.update({executable: binaries[0], "README.md": source / "README.md", "LICENSE": source / "LICENSE",
                       "RELEASING.md": source / "RELEASING.md", "THIRD-PARTY-NOTICES.txt": notices,
                       "sbom.cdx.json": sbom, "build-info.json": json_bytes(report)})
        name = archive_name(release, target, args.mode)
        first, second = [location / name for location in builds]
        write_archive(first, assets, executable)
        assets[executable] = binaries[1]
        write_archive(second, assets, executable)
        compare(first, second, output, "ZIP archive")
        smoke_archive(first, assets, executable, target, release, binary_hash, work)
        shutil.copyfile(first, output / name)
        if args.source_archive:
            # Pack each build's copy of the inputs: the tree Cargo actually built from.
            name = archive_name(release, "source", args.mode)
            first, second = [location / name for location in builds]
            for location, archive in zip(builds, (first, second)):
                write_archive(archive, {f"source/{item}": location / "source" / item for item in names}, None)
            compare(first, second, output, "source ZIP archive")
            with zipfile.ZipFile(first) as archive:
                check_archive(archive, {f"source/{item}": None for item in names}, None)
            shutil.copyfile(first, output / name)
            print(f"PASS source archive {name}: {len(names)} files")


def checksums(args):
    release = version()
    if args.mode == "tag":
        check_tag()
        require(args.target is None, "A tagged release must contain all native targets")
    targets = [args.target] if args.target else TARGETS
    expected = {archive_name(release, target, args.mode) for target in (*targets, "source")}
    expected.add("dependency-audit.json")
    folder = args.directory.resolve()
    available = {path.name for path in folder.iterdir() if path.is_file() and not path.is_symlink()}
    require(expected == available and len(list(folder.iterdir())) == len(expected),
            f"Unexpected release asset set (expected {sorted(expected)}, found {sorted(available)})")
    audit = json.loads((folder / "dependency-audit.json").read_bytes())
    require(audit["exit_status"] == 0 and audit["rustsec"] is not None
            and audit["cargo_lock_sha256"] == sha256(ROOT / "Cargo.lock"),
            "Advisory report does not record a successful scan of this Cargo.lock")
    with (folder / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as manifest:
        for name in sorted(expected):
            manifest.write(f"{sha256(folder / name)}  {name}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("version")
    sub.add_parser("rust-version")
    sub.add_parser("check-tag")
    builder = sub.add_parser("build")
    builder.add_argument("--target", choices=TARGETS)
    builder.add_argument("--output", type=Path, required=True)
    builder.add_argument("--mode", choices=("rehearsal", "tag"), default="rehearsal")
    builder.add_argument("--offline", action="store_true", help="use previously cached crates for vendoring")
    builder.add_argument("--source-archive", action="store_true",
                         help="also pack the corresponding source of this build")
    naming = sub.add_parser("archive-name")
    naming.add_argument("--target", choices=(*TARGETS, "source"), required=True)
    naming.add_argument("--mode", choices=("rehearsal", "tag"), required=True)
    manifest = sub.add_parser("checksums")
    manifest.add_argument("--target", choices=TARGETS, help="single-target local rehearsal")
    manifest.add_argument("--directory", type=Path, required=True)
    manifest.add_argument("--mode", choices=("rehearsal", "tag"), default="rehearsal")
    args = parser.parse_args()
    try:
        if args.action == "version":
            print(version())
        elif args.action == "rust-version":
            print(RUST)
        elif args.action == "check-tag":
            check_tag()
        elif args.action == "archive-name":
            print(archive_name(version(), args.target, args.mode))
        elif args.action == "checksums":
            checksums(args)
        else:
            build(args)
    except subprocess.TimeoutExpired:
        parser.exit(1, "Release check timed out\n")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release check failed: {error}\n")


if __name__ == "__main__":
    main()
