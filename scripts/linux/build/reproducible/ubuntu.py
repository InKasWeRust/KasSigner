from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.parse
import urllib.request

try:
    from .common import atomic_download, require_command, run, sha256_file
except ImportError:  # direct-script execution
    from common import atomic_download, require_command, run, sha256_file

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token"
REPOSITORY = "library/ubuntu"
LOCAL_BASE_TAG = "kassigner-ubuntu-rootfs:v1"
TARGET_OS = "linux"
TARGET_ARCH = "amd64"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT_MANIFESTS = ", ".join((OCI_INDEX, DOCKER_INDEX, OCI_MANIFEST, DOCKER_MANIFEST))
IMAGE_MANIFEST_TYPES = {OCI_MANIFEST, DOCKER_MANIFEST}
INDEX_TYPES = {OCI_INDEX, DOCKER_INDEX}


def _registry_token() -> str:
    query = urllib.parse.urlencode(
        {"service": "registry.docker.io", "scope": f"repository:{REPOSITORY}:pull"}
    )
    request = urllib.request.Request(f"{AUTH}?{query}", headers={"User-Agent": "KasSigner-reproducible-prefetch/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        document = json.load(response)
    token = document.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Docker registry authentication did not return a bearer token")
    return token


def _validate_digest(digest: str, *, label: str) -> None:
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise RuntimeError(f"invalid {label} SHA-256 digest: {digest}")


def _fetch_manifest(token: str, digest: str) -> bytes:
    _validate_digest(digest, label="Ubuntu OCI")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": ACCEPT_MANIFESTS,
        "User-Agent": "KasSigner-reproducible-prefetch/1",
    }
    url = f"{REGISTRY}/v2/{REPOSITORY}/manifests/{digest}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=120) as response:
        body = response.read()
    actual = "sha256:" + hashlib.sha256(body).hexdigest()
    if actual != digest:
        raise RuntimeError(f"Ubuntu OCI manifest digest mismatch: expected {digest}, got {actual}")
    return body


def _decode_manifest(body: bytes, *, digest: str) -> dict[str, object]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Ubuntu OCI object {digest} is not valid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"Ubuntu OCI object {digest} is not a JSON object")
    return value


def _select_linux_amd64(index: dict[str, object]) -> dict[str, object]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise RuntimeError("Ubuntu OCI image index has no manifests array")

    candidates: list[dict[str, object]] = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            continue
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            continue
        if platform.get("os") != TARGET_OS or platform.get("architecture") != TARGET_ARCH:
            continue
        media_type = descriptor.get("mediaType")
        if media_type is not None and media_type not in IMAGE_MANIFEST_TYPES:
            # Skip platform-labelled non-image artifacts/attestations.
            continue
        candidates.append(descriptor)

    if len(candidates) != 1:
        raise RuntimeError(
            f"pinned Ubuntu image index must contain exactly one {TARGET_OS}/{TARGET_ARCH} image manifest, found {len(candidates)}"
        )
    return candidates[0]


def _resolve_image_manifest(token: str, digest: str) -> tuple[bytes, dict[str, object], bytes | None, str]:
    """Resolve a pinned manifest or image index to the linux/amd64 image manifest.

    The caller pins the top-level digest. If it is an image index, the child
    digest is taken only from that verified index and the child bytes are then
    independently verified against that digest. This preserves content-addressed
    reproducibility while correctly handling Docker Hub multi-platform images.
    """
    root_bytes = _fetch_manifest(token, digest)
    root = _decode_manifest(root_bytes, digest=digest)
    media_type = root.get("mediaType")

    if media_type in IMAGE_MANIFEST_TYPES or isinstance(root.get("layers"), list):
        return root_bytes, root, None, digest

    if media_type in INDEX_TYPES or isinstance(root.get("manifests"), list):
        descriptor = _select_linux_amd64(root)
        child_digest = descriptor.get("digest")
        if not isinstance(child_digest, str):
            raise RuntimeError(f"Ubuntu {TARGET_OS}/{TARGET_ARCH} image descriptor has no digest")
        _validate_digest(child_digest, label=f"Ubuntu {TARGET_OS}/{TARGET_ARCH} child")
        child_bytes = _fetch_manifest(token, child_digest)
        expected_size = descriptor.get("size")
        if isinstance(expected_size, int) and expected_size >= 0 and len(child_bytes) != expected_size:
            raise RuntimeError(
                f"Ubuntu {TARGET_OS}/{TARGET_ARCH} child manifest size mismatch: expected {expected_size}, got {len(child_bytes)}"
            )
        child = _decode_manifest(child_bytes, digest=child_digest)
        child_type = child.get("mediaType")
        if child_type not in IMAGE_MANIFEST_TYPES and not isinstance(child.get("layers"), list):
            raise RuntimeError(
                f"Ubuntu {TARGET_OS}/{TARGET_ARCH} descriptor did not resolve to an image manifest"
            )
        return child_bytes, child, root_bytes, child_digest

    raise RuntimeError(
        f"pinned Ubuntu OCI object is neither an image manifest nor image index (mediaType={media_type!r})"
    )


def prefetch_base(output: Path, digest: str) -> tuple[Path, dict[str, object]]:
    _validate_digest(digest, label="pinned Ubuntu OCI")
    token = _registry_token()
    manifest_bytes, manifest, index_bytes, manifest_digest = _resolve_image_manifest(token, digest)

    layers = manifest.get("layers", [])
    if not isinstance(layers, list) or len(layers) != 1:
        raise RuntimeError(
            f"pinned Ubuntu {TARGET_OS}/{TARGET_ARCH} image manifest must contain exactly one rootfs layer, "
            f"found {len(layers) if isinstance(layers, list) else 'invalid'}"
        )
    layer = layers[0]
    layer_digest = layer.get("digest") if isinstance(layer, dict) else None
    if not isinstance(layer_digest, str):
        raise RuntimeError("Ubuntu OCI image manifest has no rootfs layer digest")
    _validate_digest(layer_digest, label="Ubuntu rootfs layer")

    output.mkdir(parents=True, exist_ok=True)
    if index_bytes is not None:
        # Retain the exact verified pinned index bytes for auditability. The
        # selected platform image manifest is written separately below.
        index_path = output / "ubuntu-index.json"
        index_path.write_bytes(index_bytes)
    manifest_path = output / "ubuntu-manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    layer_path = output / "ubuntu-rootfs-layer.tar.gz"
    atomic_download(
        f"{REGISTRY}/v2/{REPOSITORY}/blobs/{layer_digest}",
        layer_path,
        headers={"Authorization": f"Bearer {token}", "User-Agent": "KasSigner-reproducible-prefetch/1"},
    )
    actual_layer = "sha256:" + sha256_file(layer_path)
    if actual_layer != layer_digest:
        raise RuntimeError(f"Ubuntu rootfs layer digest mismatch: expected {layer_digest}, got {actual_layer}")

    metadata: dict[str, object] = {
        "source_digest": digest,
        "manifest_digest": manifest_digest,
        "layer_digest": layer_digest,
        "platform": f"{TARGET_OS}/{TARGET_ARCH}",
        "local_tag": LOCAL_BASE_TAG,
    }
    if index_bytes is not None:
        metadata["index_digest"] = digest
    (output / "ubuntu-oci.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return layer_path, metadata


def _extract_member(layer: Path, suffix: str, destination: Path) -> None:
    with tarfile.open(layer, "r:*") as archive:
        matches = [member for member in archive.getmembers() if member.name.lstrip("./") == suffix]
        if len(matches) != 1:
            raise RuntimeError(f"Ubuntu rootfs layer is missing required {suffix}")
        source = archive.extractfile(matches[0])
        if source is None:
            raise RuntimeError(f"Ubuntu rootfs member is not a file: {suffix}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read())


def _write_local_apt_packages(debs: list[Path], destination: Path) -> None:
    """Write a deterministic APT Packages index for the prefetched closure.

    ``dpkg-deb --field`` reads only the already-downloaded package metadata.
    Filename/Size/SHA256 bind each stanza to the exact local archive that is
    independently checked by DEBS-SHA256SUMS inside Docker.
    """
    require_command("dpkg-deb")
    stanzas: list[str] = []
    for deb in sorted(debs, key=lambda path: path.name):
        result = subprocess.run(
            ["dpkg-deb", "--field", str(deb)],
            check=True,
            capture_output=True,
            text=True,
        )
        control = result.stdout.rstrip("\n")
        if not control:
            raise RuntimeError(f"empty Debian control metadata: {deb.name}")
        stanzas.append(
            control
            + f"\nFilename: debs/{deb.name}"
            + f"\nSize: {deb.stat().st_size}"
            + f"\nSHA256: {sha256_file(deb)}\n"
        )
    destination.write_text("\n".join(stanzas) + "\n")


def prefetch_debs(output: Path, layer: Path, snapshot: str, packages: list[str]) -> dict[str, object]:
    require_command("apt-get")
    apt_root = output / "apt-state"
    lists = apt_root / "lists"
    archives = output / "debs"
    lists.mkdir(parents=True, exist_ok=True)
    (lists / "partial").mkdir(exist_ok=True)
    archives.mkdir(parents=True, exist_ok=True)
    (archives / "partial").mkdir(exist_ok=True)
    status = apt_root / "status"
    keyring = apt_root / "ubuntu-archive-keyring.gpg"
    _extract_member(layer, "var/lib/dpkg/status", status)
    _extract_member(layer, "usr/share/keyrings/ubuntu-archive-keyring.gpg", keyring)
    sources = apt_root / "sources.list"
    container_sources = apt_root / "sources.container.list"
    base = f"https://snapshot.ubuntu.com/ubuntu/{snapshot}"
    suites = ("noble", "noble-updates", "noble-security")
    sources.write_text(
        "\n".join(
            f"deb [arch=amd64 signed-by={keyring}] {base} {suite} main universe"
            for suite in suites
        ) + "\n"
    )
    # Docker is network-disabled.  Give its APT solver exactly one repository:
    # the SHA-256-inventoried local closure in the build context.  This avoids
    # selecting a snapshot candidate that is not physically present while
    # still letting APT order/configure dependencies correctly.
    container_sources.write_text(
        "deb [trusted=yes] file:/opt/kassigner/input ./\n"
    )
    pkgcache = apt_root / "pkgcache.bin"
    srcpkgcache = apt_root / "srcpkgcache.bin"
    common = [
        "apt-get",
        "-o", f"Dir::Etc::sourcelist={sources}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::status={status}",
        "-o", f"Dir::State::lists={lists}",
        "-o", f"Dir::Cache::archives={archives}",
        "-o", f"Dir::Cache::pkgcache={pkgcache}",
        "-o", f"Dir::Cache::srcpkgcache={srcpkgcache}",
        "-o", "APT::Architecture=amd64",
        "-o", "Acquire::Languages=none",
        "-o", "Acquire::Retries=3",
    ]
    run(common + ["update"])
    run(common + ["--download-only", "--no-install-recommends", "-y", "install", *packages])
    debs = sorted(archives.glob("*.deb"))
    if not debs:
        raise RuntimeError("Ubuntu snapshot prefetch produced no .deb packages")
    checksums = output / "DEBS-SHA256SUMS"
    checksums.write_text("".join(f"{sha256_file(path)}  debs/{path.name}\n" for path in debs))
    _write_local_apt_packages(debs, output / "Packages")

    # Prove on the host, before Docker starts, that the exact local closure can
    # satisfy installation against the pinned base-image dpkg status without
    # consulting any network repository. This mirrors Docker's file:// solver
    # and turns a missing dependency into a prefetch error instead of a late
    # Dockerfile failure.
    local_lists = apt_root / "local-lists"
    local_lists.mkdir(parents=True, exist_ok=True)
    (local_lists / "partial").mkdir(exist_ok=True)
    local_sources = apt_root / "sources.local.list"
    local_sources.write_text(f"deb [trusted=yes] {output.as_uri()} ./\n")
    local_pkgcache = apt_root / "local-pkgcache.bin"
    local_srcpkgcache = apt_root / "local-srcpkgcache.bin"
    local_common = [
        "apt-get",
        "-o", f"Dir::Etc::sourcelist={local_sources}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::status={status}",
        "-o", f"Dir::State::lists={local_lists}",
        "-o", f"Dir::Cache::archives={archives}",
        "-o", f"Dir::Cache::pkgcache={local_pkgcache}",
        "-o", f"Dir::Cache::srcpkgcache={local_srcpkgcache}",
        "-o", "APT::Architecture=amd64",
        "-o", "Acquire::Languages=none",
    ]
    run(local_common + ["update"])
    run(local_common + ["--simulate", "--no-install-recommends", "-y", "install", *map(str, debs)])

    return {
        "snapshot": snapshot,
        "requested_packages": packages,
        "downloaded_debs": len(debs),
        "local_packages_sha256": sha256_file(output / "Packages"),
    }


def import_local_base(layer: Path) -> None:
    require_command("docker")
    result = subprocess.run(["docker", "image", "inspect", LOCAL_BASE_TAG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        subprocess.run(["docker", "image", "rm", "--force", LOCAL_BASE_TAG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["docker", "import", str(layer), LOCAL_BASE_TAG])
