from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import tarfile
import tomllib
import urllib.request

try:
    from .common import atomic_download, clean_environment, deterministic_file_manifest, download_json, run, sha256_file
except ImportError:  # direct-script execution
    from common import atomic_download, clean_environment, deterministic_file_manifest, download_json, run, sha256_file

HOST = "x86_64-unknown-linux-gnu"
ESPUP_ASSET = f"espup-{HOST}"


def _download_rustup(output: Path, version: str) -> Path:
    base = f"https://static.rust-lang.org/rustup/archive/{version}/{HOST}/rustup-init"
    binary = output / "downloads/rustup-init"
    checksum_file = output / "downloads/rustup-init.sha256"
    if binary.is_file() and checksum_file.is_file():
        expected = checksum_file.read_text().strip().split()[0]
        if len(expected) == 64 and sha256_file(binary) == expected:
            print("  reusing SHA-256-verified cached rustup-init")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            return binary
    atomic_download(base, binary)
    atomic_download(base + ".sha256", checksum_file)
    expected = checksum_file.read_text().strip().split()[0]
    actual = sha256_file(binary)
    if expected != actual:
        raise RuntimeError(f"rustup-init SHA-256 mismatch: expected {expected}, got {actual}")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def _download_espup(output: Path, version: str) -> tuple[Path, str]:
    binary = output / "downloads/espup"
    digest_file = output / "downloads/espup.sha256"
    if binary.is_file() and digest_file.is_file():
        digest = digest_file.read_text().strip()
        if digest.startswith("sha256:") and len(digest) == 71:
            actual = "sha256:" + sha256_file(binary)
            if actual == digest:
                print("  reusing SHA-256-verified cached espup")
                binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
                return binary, digest

    release = download_json(f"https://api.github.com/repos/esp-rs/espup/releases/tags/v{version}")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("espup GitHub release did not contain an asset list")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == ESPUP_ASSET]
    if len(matches) != 1:
        raise RuntimeError(f"espup v{version} did not contain exactly one {ESPUP_ASSET} asset")
    asset = matches[0]
    digest = asset.get("digest")
    url = asset.get("browser_download_url")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError("espup release asset has no published SHA-256 digest")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RuntimeError("espup release asset has no HTTPS download URL")
    atomic_download(url, binary)
    actual = "sha256:" + sha256_file(binary)
    if actual != digest:
        raise RuntimeError(f"espup SHA-256 mismatch: expected {digest}, got {actual}")
    digest_file.write_text(digest + "\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary, digest


def _tool_env(home: Path) -> dict[str, str]:
    env = clean_environment(home)
    env["PATH"] = f"{home / '.cargo/bin'}:{os.environ.get('PATH', '')}"
    return env


def _rustup_init_env(home: Path) -> dict[str, str]:
    """Use isolated Rust homes without triggering rustup's HOME/euid warning."""
    env = _tool_env(home)
    # rustup-init compares HOME to the passwd entry for the effective uid.
    # CARGO_HOME/RUSTUP_HOME remain isolated below the reproducible prefetch
    # root, so using the real passwd HOME here does not pollute the user setup.
    env["HOME"] = pwd.getpwuid(os.geteuid()).pw_dir
    # The isolated CARGO_HOME/RUSTUP_HOME above are intentional even when the
    # host also has a system Rust installation.  Suppress rustup-init's generic
    # PATH-conflict warning without weakening any pinned-toolchain checks.
    env["RUSTUP_INIT_SKIP_PATH_CHECK"] = "yes"
    return env


def _rewrite_export(export_file: Path, home: Path) -> None:
    source = export_file.read_text()
    export_file.write_text(source.replace(str(home), "/root"))


def _normalize_esp_clang_symlink(home: Path) -> Path:
    """Make espup's libclang convenience link valid and relocatable.

    espup creates ``~/.espup/esp-clang`` as a convenience symlink into the
    installed ``esp`` Rust toolchain.  Some installs leave that link absolute
    (and, after toolchain layout changes, potentially dangling).  The
    reproducible-build context is intentionally relocated from the host
    prefetch tree into Docker, so an absolute host path must never be retained.

    Resolve the actual installed libclang directory from the pinned ESP
    toolchain, require it to be unambiguous, and rewrite the convenience link
    as a relative symlink.  This preserves espup's expected interface while
    making the isolated home tree safe to relocate.
    """
    esp_toolchain = home / ".rustup/toolchains/esp"
    if not esp_toolchain.is_dir():
        raise RuntimeError(f"esp Rust toolchain directory is missing after espup install: {esp_toolchain}")

    library_names = ("libclang.so", "libclang.so.*")
    candidates: set[Path] = set()
    for pattern in library_names:
        for library in esp_toolchain.rglob(pattern):
            if library.is_file():
                candidates.add(library.parent.resolve())

    if len(candidates) != 1:
        rendered = ", ".join(str(path) for path in sorted(candidates)) or "none"
        raise RuntimeError(
            "pinned ESP toolchain must contain exactly one libclang directory; "
            f"found {len(candidates)}: {rendered}"
        )

    target = next(iter(candidates))
    link = home / ".espup/esp-clang"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        if link.is_dir() and not link.is_symlink():
            raise RuntimeError(f"espup clang convenience path unexpectedly became a real directory: {link}")
        link.unlink()
    relative_target = os.path.relpath(target, start=link.parent)
    link.symlink_to(relative_target, target_is_directory=True)
    resolved = link.resolve(strict=True)
    if resolved != target:
        raise RuntimeError(f"failed to normalize espup clang symlink: {link} -> {resolved}, expected {target}")
    return target



ESP_ROM_SYS_PATCH_PACKAGE = "esp-rom-sys"
ESP_ROM_SYS_PATCH_VERSION = "0.1.3"
ESP_ROM_SYS_BAD_STRCASECMP = (
    "let val = (*s1_i).to_ascii_lowercase() as i32 - "
    "(*s2_i).to_ascii_lowercase() as i32;"
)
ESP_ROM_SYS_FIXED_STRCASECMP = (
    "let val = ((*s1_i) as u8).to_ascii_lowercase() as i32 - "
    "((*s2_i) as u8).to_ascii_lowercase() as i32;"
)
ESP_ROM_SYS_BAD_FUNCTION_CAST = "not_implemented as usize"
ESP_ROM_SYS_FIXED_FUNCTION_CAST = "not_implemented as *const () as usize"
ESP_ROM_SYS_FUNCTION_CAST_OCCURRENCES = 37


def _firmware_locked_registry_package(root: Path, name: str, version: str) -> dict[str, object]:
    lock = root / "apps/signer-firmware/Cargo.lock"
    data = tomllib.loads(lock.read_text())
    matches = [
        package
        for package in data.get("package", [])
        if package.get("name") == name and package.get("version") == version
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"firmware lock must contain exactly one {name} {version}; found {len(matches)}"
        )
    package = matches[0]
    source = package.get("source")
    checksum = package.get("checksum")
    if not isinstance(source, str) or not source.startswith("registry+"):
        raise RuntimeError(f"{name} {version} must remain a registry dependency before the reproducible override")
    if not isinstance(checksum, str) or len(checksum) != 64:
        raise RuntimeError(f"{name} {version} has no canonical registry SHA-256 in the firmware lock")
    return package


def _safe_extract_crate(archive: Path, destination: Path, expected_root: str) -> Path:
    """Extract one Cargo .crate archive without permitting path/link escapes."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise RuntimeError(f"empty Cargo crate archive: {archive}")
        for member in members:
            pure = Path(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != expected_root:
                raise RuntimeError(f"unsafe member in Cargo crate archive {archive}: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                raise RuntimeError(f"unsupported link/device member in Cargo crate archive {archive}: {member.name}")
        bundle.extractall(destination, filter="data")
    root = destination / expected_root
    if not root.is_dir():
        raise RuntimeError(f"Cargo crate archive did not contain expected root {expected_root}")
    return root


def _install_esp_rom_sys_xtensa_patch(root: Path, home: Path) -> dict[str, str]:
    """Install a reproducible source-only override for esp-rom-sys on Xtensa.

    esp-rom-sys 0.1.3 implements ``__strcasecmp`` over ``core::ffi::c_char``
    but invokes the u8/char ASCII helper directly on c_char. On ESP32-S3
    Xtensa, c_char is signed (i8), so the published source does not compile.
    Preserve the byte pattern explicitly as u8 before ASCII case folding.

    The official registry archive remains the trust anchor: verify its SHA-256
    against Cargo.lock, extract that exact archive, require one exact source
    needle, and use Cargo's same-graph ``paths`` override. No dependency edges,
    package version, linker scripts, or ROM symbols are changed.
    """
    locked = _firmware_locked_registry_package(root, ESP_ROM_SYS_PATCH_PACKAGE, ESP_ROM_SYS_PATCH_VERSION)
    expected_sha = str(locked["checksum"])
    archive_name = f"{ESP_ROM_SYS_PATCH_PACKAGE}-{ESP_ROM_SYS_PATCH_VERSION}.crate"
    archives = sorted((home / ".cargo/registry/cache").glob(f"*/{archive_name}"))
    if len(archives) != 1:
        raise RuntimeError(
            f"expected exactly one cached {archive_name} after cargo fetch; found {len(archives)}"
        )
    archive = archives[0]
    actual_sha = sha256_file(archive)
    if actual_sha != expected_sha:
        raise RuntimeError(
            f"{archive_name} SHA-256 mismatch before patching: expected {expected_sha}, got {actual_sha}"
        )

    patch_parent = home / ".kassigner-patches"
    patch_root = patch_parent / f"{ESP_ROM_SYS_PATCH_PACKAGE}-{ESP_ROM_SYS_PATCH_VERSION}"
    if patch_parent.exists():
        shutil.rmtree(patch_parent)
    temp = patch_parent.with_name(patch_parent.name + ".tmp")
    shutil.rmtree(temp, ignore_errors=True)
    try:
        extracted = _safe_extract_crate(
            archive,
            temp,
            f"{ESP_ROM_SYS_PATCH_PACKAGE}-{ESP_ROM_SYS_PATCH_VERSION}",
        )
        source = extracted / "src/lib.rs"
        text = source.read_text()
        occurrences = text.count(ESP_ROM_SYS_BAD_STRCASECMP)
        if occurrences != 1:
            raise RuntimeError(
                "esp-rom-sys Xtensa compatibility patch expected exactly one canonical "
                f"__strcasecmp source expression, found {occurrences}"
            )
        source.write_text(
            text.replace(ESP_ROM_SYS_BAD_STRCASECMP, ESP_ROM_SYS_FIXED_STRCASECMP, 1),
            encoding="utf-8",
        )
        syscall = extracted / "src/syscall/mod.rs"
        syscall_text = syscall.read_text(encoding="utf-8")
        function_cast_occurrences = syscall_text.count(ESP_ROM_SYS_BAD_FUNCTION_CAST)
        if function_cast_occurrences != ESP_ROM_SYS_FUNCTION_CAST_OCCURRENCES:
            raise RuntimeError(
                "esp-rom-sys warning cleanup expected exactly "
                f"{ESP_ROM_SYS_FUNCTION_CAST_OCCURRENCES} canonical function-item casts, "
                f"found {function_cast_occurrences}"
            )
        syscall.write_text(
            syscall_text.replace(ESP_ROM_SYS_BAD_FUNCTION_CAST, ESP_ROM_SYS_FIXED_FUNCTION_CAST),
            encoding="utf-8",
        )
        provenance = {
            "package": ESP_ROM_SYS_PATCH_PACKAGE,
            "version": ESP_ROM_SYS_PATCH_VERSION,
            "registry_sha256": expected_sha,
            "patch": "xtensa-c-char-and-function-pointer-compatibility-v2",
        }
        (extracted / "KASSIGNER-PATCH.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n"
        )
        patch_parent.mkdir(parents=True, exist_ok=True)
        extracted.rename(patch_root)
    finally:
        shutil.rmtree(temp, ignore_errors=True)

    source = patch_root / "src/lib.rs"
    cargo_config = home / ".cargo/config.toml"
    override = f'.kassigner-patches/{ESP_ROM_SYS_PATCH_PACKAGE}-{ESP_ROM_SYS_PATCH_VERSION}'
    existing = cargo_config.read_text() if cargo_config.is_file() else ""
    if existing:
        parsed = tomllib.loads(existing)
        existing_paths = parsed.get("paths")
        if existing_paths not in (None, [override]):
            raise RuntimeError(f"unexpected pre-existing Cargo path overrides in isolated home: {existing_paths}")
    if f'paths = ["{override}"]' not in existing:
        cargo_config.parent.mkdir(parents=True, exist_ok=True)
        cargo_config.write_text(f'paths = ["{override}"]\n' + existing)

    if ESP_ROM_SYS_BAD_STRCASECMP in source.read_text(encoding="utf-8"):
        raise RuntimeError("esp-rom-sys Xtensa compatibility patch did not remove the invalid c_char expression")
    syscall = patch_root / "src/syscall/mod.rs"
    if ESP_ROM_SYS_BAD_FUNCTION_CAST in syscall.read_text(encoding="utf-8"):
        raise RuntimeError("esp-rom-sys Xtensa compatibility patch did not normalize function-item pointer casts")
    print(
        "  installed verified esp-rom-sys 0.1.3 Xtensa c_char compatibility override "
        f"(registry sha256 {expected_sha})"
    )
    return provenance


def _prefetch_esp_firmware_build_std(root: Path, output: Path, home: Path, export_file: Path) -> None:
    """Seed and verify the pinned ESP build-std dependency closure.

    Cargo ``fetch`` for the application workspaces does not resolve crates that
    belong to the ESP Rust sysroot (for example ``dlmalloc`` used while
    rebuilding ``core``/``alloc``).  The release Docker build is intentionally
    networkless, so resolve that target-specific closure once on the host with
    the pinned ESP toolchain, then prove the exact same representative firmware
    build succeeds with ``--offline --locked``.
    """
    target_dir = output / "firmware-build-std-prefetch-target"
    shutil.rmtree(target_dir, ignore_errors=True)
    env = _tool_env(home)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["CARGO_NET_RETRY"] = "5"
    cargo = home / ".cargo/bin/cargo"
    # Cargo discovers .cargo/config.toml from the process working directory,
    # not from --manifest-path. The firmware target/build-std configuration is
    # intentionally scoped to apps/signer-firmware/.cargo/config.toml, so the
    # representative prefetch build must execute from that directory exactly
    # like the release Docker convergence build does. Running from the repo
    # root silently selects the host target; esp-sync then sees the ESP32-S3
    # chip cfg without Cargo activating its target-specific xtensa-lx edge.
    firmware_root = root / "apps/signer-firmware"
    base = [
        str(cargo), "+esp", "build", "--locked", "--release",
        "--no-default-features", "--features", "waveshare,production",
    ]
    shell = 'set -euo pipefail; source "$1"; shift; exec "$@"'
    try:
        print("  prefetching ESP build-std/sysroot crate closure with pinned +esp toolchain")
        run(["/bin/bash", "-lc", shell, "bash", str(export_file), *base], cwd=firmware_root, env=env)
        print("  verifying ESP build-std/sysroot crate closure with networking disabled")
        offline = base.copy()
        offline.insert(3, "--offline")
        run(["/bin/bash", "-lc", shell, "bash", str(export_file), *offline], cwd=firmware_root, env=env)
    finally:
        shutil.rmtree(target_dir, ignore_errors=True)

def prefetch_toolchains(root: Path, output: Path, pins: dict[str, str]) -> dict[str, object]:
    home = output / "root-home"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    downloads = output / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)

    # Resolve and verify the pinned espup release before installing the much
    # larger Rust/ESP toolchains. A transient GitHub/API outage therefore
    # retries up front instead of wasting a completed Rust installation first.
    rustup = _download_rustup(output, pins["KASSIGNER_RUSTUP_VERSION"])
    espup, espup_digest = _download_espup(output, pins["KASSIGNER_ESPUP_VERSION"])
    env = _tool_env(home)
    run(
        [
            str(rustup), "-y", "--no-modify-path", "--profile", "minimal",
            "--default-toolchain", pins["KASSIGNER_REPRO_HOST_RUST"],
        ],
        env=_rustup_init_env(home),
    )
    cargo = home / ".cargo/bin/cargo"
    rustup_cmd = home / ".cargo/bin/rustup"
    run([str(rustup_cmd), "target", "add", "wasm32-unknown-unknown", "--toolchain", pins["KASSIGNER_REPRO_HOST_RUST"]], env=env)

    export_file = home / "esp-env.sh"
    run(
        [str(espup), "install", "--toolchain-version", pins["KASSIGNER_ESP_RUST"], "--export-file", str(export_file)],
        env=env,
    )
    _normalize_esp_clang_symlink(home)

    manifests = [
        root / "Cargo.toml",
        root / "apps/signer-firmware/Cargo.toml",
        root / "apps/kassee-web/Cargo.toml",
        root / "tools/Cargo.toml",
    ]
    for manifest in manifests:
        run([str(cargo), f"+{pins['KASSIGNER_REPRO_HOST_RUST']}", "fetch", "--locked", "--manifest-path", str(manifest)], cwd=root, env=env)

    # esp-rom-sys 0.1.3 has a target-specific source bug on Xtensa: c_char is
    # signed i8 there, while its __strcasecmp shim calls a u8-only ASCII helper.
    # Install a source-only same-graph override from the exact Cargo.lock-bound
    # registry archive before any ESP firmware compilation.
    esp_rom_sys_patch = _install_esp_rom_sys_xtensa_patch(root, home)

    # Cargo fetch for repository manifests does not include crates used only by
    # the ESP Rust sysroot while build-std rebuilds core/alloc. Seed that exact
    # target-specific closure with one representative firmware build, then
    # prove it is complete in offline mode before Docker is allowed to start.
    _prefetch_esp_firmware_build_std(root, output, home, export_file)
    _rewrite_export(export_file, home)

    # Populate the isolated Cargo cache with the pinned espflash source and all
    # transitive dependencies. The produced host binary is discarded; the
    # actual release environment compiles espflash again offline inside Docker.
    scratch_root = output / "espflash-host-prefetch"
    if scratch_root.exists():
        shutil.rmtree(scratch_root)
    run(
        [
            str(cargo), f"+{pins['KASSIGNER_REPRO_HOST_RUST']}", "install", "espflash",
            "--version", pins["KASSIGNER_ESPFLASH_VERSION"], "--locked", "--root", str(scratch_root),
        ],
        env=env,
    )
    shutil.rmtree(scratch_root, ignore_errors=True)

    toolchain_manifest = output / "TOOLCHAIN-SHA256SUMS"
    deterministic_file_manifest(home, toolchain_manifest)
    metadata = {
        "rustup_version": pins["KASSIGNER_RUSTUP_VERSION"],
        "host_rust": pins["KASSIGNER_REPRO_HOST_RUST"],
        "esp_rust": pins["KASSIGNER_ESP_RUST"],
        "espup_version": pins["KASSIGNER_ESPUP_VERSION"],
        "espup_sha256": espup_digest,
        "espflash_version": pins["KASSIGNER_ESPFLASH_VERSION"],
        "third_party_patches": [esp_rom_sys_patch],
    }
    (output / "toolchain-inputs.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata
