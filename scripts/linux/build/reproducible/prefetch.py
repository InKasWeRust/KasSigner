#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

try:
    from .common import deterministic_file_manifest, load_env, sha256_file, verify_file_manifest
    from .toolchains import prefetch_toolchains
    from .ubuntu import prefetch_base, prefetch_debs
except ImportError:  # direct-script execution
    from common import deterministic_file_manifest, load_env, sha256_file, verify_file_manifest
    from toolchains import prefetch_toolchains
    from ubuntu import prefetch_base, prefetch_debs


def _hardlink_context_file(source: str, destination: str) -> str:
    """Materialize immutable context files without duplicating disk blocks.

    ``context`` and its source trees are deliberately siblings below one
    prefetch root, so they are on the same filesystem.  Refuse to fall back to
    a byte-for-byte copy: silently duplicating the multi-gigabyte ESP/Rust home
    is exactly what exhausted disk space in the old runner.  Symlinked files
    are dereferenced to preserve the previous Docker-context semantics.
    """
    source_path = Path(source)
    if source_path.is_symlink():
        try:
            link_source = source_path.resolve(strict=True)
        except (FileNotFoundError, RuntimeError) as error:
            raise RuntimeError(
                f"reproducible-build context encountered a dangling or cyclic symlink: {source_path}"
            ) from error
        if link_source.is_dir():
            raise RuntimeError(
                "reproducible-build context directory symlink reached the regular-file hardlink path; "
                f"source={source_path} target={link_source}"
            )
    else:
        link_source = source_path
    try:
        os.link(link_source, destination)
    except OSError as error:
        raise RuntimeError(
            "reproducible-build context must support same-filesystem hard links; "
            f"failed to link {source_path}: {error}"
        ) from error
    return destination


def _materialize_context_tree(source: Path, destination: Path) -> None:
    # Keep directory-symlink behavior compatible with shutil.copytree's
    # historical default (dereference), but hard-link every resulting regular
    # file so the multi-gigabyte ESP/Rust toolchain is not stored twice.
    shutil.copytree(source, destination, copy_function=_hardlink_context_file)



def finalize_context_manifests(context: Path) -> None:
    """Re-inventory the exact hardlinked context immediately before Docker.

    The host MSRV/WASM preflight intentionally reuses the isolated prefetched
    Cargo/Rust home.  Because the Docker context hard-links that tree to avoid
    a multi-gigabyte duplicate, Cargo cache bookkeeping performed by the host
    preflight can change the bytes visible through existing context hardlinks.
    Rebuild both manifests from the *actual context tree* after that preflight
    so Docker verifies exactly the bytes it receives.
    """
    if not context.is_dir():
        raise RuntimeError(f"reproducible-build context is missing: {context}")
    root_home = context / "root-home"
    if not root_home.is_dir():
        raise RuntimeError(f"reproducible-build context root-home is missing: {root_home}")

    toolchain_manifest = context / "TOOLCHAIN-SHA256SUMS"
    deterministic_file_manifest(root_home, toolchain_manifest)
    verify_file_manifest(root_home, toolchain_manifest)

    build_manifest = context / "BUILD-INPUT-SHA256SUMS"
    deterministic_file_manifest(
        context,
        build_manifest,
        exclude={Path("BUILD-INPUT-SHA256SUMS")},
    )
    verify_file_manifest(context, build_manifest)

def package_pins(pins: dict[str, str]) -> list[str]:
    keys = (
        "KASSIGNER_UBUNTU_CA_CERTIFICATES",
        "KASSIGNER_UBUNTU_CURL",
        "KASSIGNER_UBUNTU_GCC",
        "KASSIGNER_UBUNTU_GXX",
        "KASSIGNER_UBUNTU_LIBSSL_DEV",
        "KASSIGNER_UBUNTU_LIBUDEV_DEV",
        "KASSIGNER_UBUNTU_LIBUSB_DEV",
        "KASSIGNER_UBUNTU_PKG_CONFIG",
        "KASSIGNER_UBUNTU_PYTHON3",
    )
    return [pins[key] for key in keys]


def policy_digest(root: Path) -> str:
    digest = hashlib.sha256()
    platform_repro = Path(__file__).resolve().parent.relative_to(root).as_posix()
    for relative in (
        "qa/config/toolchains.env",
        "Cargo.lock",
        "apps/signer-firmware/Cargo.lock",
        "apps/kassee-web/Cargo.lock",
        "tools/Cargo.lock",
        # Cache validity depends on the exact offline-build materialization
        # contract as well as dependency locks. Including these files prevents
        # an old context from surviving a prefetch/Dockerfile layout change.
        "Dockerfile.base",
        f"{platform_repro}/common.py",
        f"{platform_repro}/prefetch.py",
        f"{platform_repro}/toolchains.py",
        f"{platform_repro}/ubuntu.py",
    ):
        path = root / relative
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def cached_context_is_valid(output: Path, expected_policy: str) -> bool:
    context = output / "context"
    policy_file = output / "prefetch-policy.sha256"
    manifest = context / "BUILD-INPUT-SHA256SUMS"
    layer = output / "ubuntu-rootfs-layer.tar.gz"
    if not (policy_file.is_file() and manifest.is_file() and layer.is_file()):
        return False
    if policy_file.read_text().strip() != expected_policy:
        return False
    try:
        verify_file_manifest(context, manifest)
        ubuntu = json.loads((output / "ubuntu-oci.json").read_text())
        expected_layer = str(ubuntu["layer_digest"]).removeprefix("sha256:")
        return sha256_file(layer) == expected_layer
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--finalize-context-manifests", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output.resolve()

    if args.finalize_context_manifests:
        finalize_context_manifests(output / "context")
        print("==> Re-finalized SHA-256 manifests for the exact post-preflight Docker context")
        return 0

    pins = load_env(root / "qa/config/toolchains.env")
    expected_policy = policy_digest(root)

    if not args.refresh and cached_context_is_valid(output, expected_policy):
        print("==> Reusing SHA-256-verified host-prefetched reproducible-build inputs")
        print(f"Input context: {output / 'context'}")
        return 0

    policy_file = output / "prefetch-policy.sha256"
    same_partial_policy = (
        output.exists()
        and policy_file.is_file()
        and policy_file.read_text().strip() == expected_policy
    )
    if output.exists() and not same_partial_policy:
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    # Mark this partial cache with the exact policy before network work begins.
    # A retry of the same source/pins may then reuse individually verified
    # downloads; any policy change deletes the partial cache above.
    policy_file.write_text(expected_policy + "\n")
    context = output / "context"
    if context.exists():
        shutil.rmtree(context)
    context.mkdir()
    (context / "qa/config").mkdir(parents=True)
    shutil.copy2(root / "qa/config/toolchains.env", context / "qa/config/toolchains.env")

    print("==> Host prefetch: pinned Ubuntu rootfs")
    layer, ubuntu = prefetch_base(output, pins["KASSIGNER_UBUNTU_BASE_DIGEST"])
    print("==> Host prefetch: pinned Ubuntu package closure")
    apt = prefetch_debs(
        output,
        layer,
        pins["KASSIGNER_UBUNTU_SNAPSHOT"],
        package_pins(pins),
    )
    print("==> Host prefetch: pinned Rust/ESP toolchains and Cargo caches")
    toolchains = prefetch_toolchains(root, output, pins)
    deterministic_file_manifest(output / "downloads", output / "DOWNLOAD-SHA256SUMS")
    (output / "UBUNTU-ROOTFS-SHA256SUM").write_text(
        f"{sha256_file(layer)}  ubuntu-rootfs-layer.tar.gz\n"
    )

    for name in (
        "debs", "root-home", "Packages", "DEBS-SHA256SUMS", "TOOLCHAIN-SHA256SUMS",
        "DOWNLOAD-SHA256SUMS", "UBUNTU-ROOTFS-SHA256SUM",
        "toolchain-inputs.json", "ubuntu-oci.json",
    ):
        source = output / name
        destination = context / name
        if source.is_dir():
            _materialize_context_tree(source, destination)
        else:
            shutil.copy2(source, destination)

    # Docker must not receive the host's snapshot URL package indexes.  It gets
    # only the local file:// source declaration plus the deterministic Packages
    # index above, making external APT resolution structurally impossible.
    (context / "apt-state").mkdir()
    shutil.copy2(
        output / "apt-state/sources.container.list",
        context / "apt-state/sources.container.list",
    )

    document = {
        "schema_version": 1,
        "ubuntu": ubuntu,
        "apt": apt,
        "toolchains": toolchains,
    }
    (context / "BUILD-INPUT-MANIFEST.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    finalize_context_manifests(context)
    (output / "prefetch-policy.sha256").write_text(expected_policy + "\n")
    print("==> Host prefetch complete; every Docker build input is local and SHA-256 inventoried")
    print(f"Ubuntu layer: {sha256_file(layer)}")
    print(f"Input context: {context}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: reproducible-build prefetch failed: {error}", file=sys.stderr)
        raise SystemExit(1)
