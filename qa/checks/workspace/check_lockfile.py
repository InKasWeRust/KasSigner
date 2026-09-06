#!/usr/bin/env python3
from collections import defaultdict
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[3]

WORKSPACES = {
    ROOT / "Cargo.lock": {
        "local": {"kassigner-protocol", "kassigner-sdk", "offline-signer", "online-watcher", "shared-signer", "signer-firmware-core"},
        "forbidden": {"firmware-tools", "kassee-web", "kassigner-firmware", "kassigner-qa", "minifb"},
    },
    ROOT / "apps/signer-firmware/Cargo.lock": {
        "local": {"kassigner-firmware", "kassigner-protocol", "offline-signer", "rqrr", "serde_yaml", "shared-signer", "signer-firmware-core"},
        "forbidden": {"firmware-tools", "kassee-web", "online-watcher", "kassigner-qa", "minifb"},
    },
    ROOT / "apps/kassee-web/Cargo.lock": {
        "local": {"kassee-web", "kassigner-protocol", "kassigner-sdk", "online-watcher", "shared-signer"},
        # Cargo may retain a transitive path package's dev-only package in a
        # reconciled lock depending on resolver context. Cargo-native --locked
        # verification is authoritative; the static checker permits either
        # form but does not permit unrelated local packages.
        "optional_local": {"offline-signer"},
        "forbidden": {"firmware-tools", "kassigner-firmware", "rqrr", "kassigner-qa", "minifb", "signer-firmware-core"},
    },
    ROOT / "external/rqrr-nostd/Cargo.lock": {
        "local": {"rqrr"},
        "forbidden": {"firmware-tools", "kassee-web", "kassigner-firmware", "kassigner-qa", "kassigner-protocol", "kassigner-sdk", "offline-signer", "online-watcher", "shared-signer", "signer-firmware-core"},
    },
    ROOT / "tools/Cargo.lock": {
        "local": {"firmware-tools", "kassigner-protocol", "offline-signer", "shared-signer", "signer-firmware-core"},
        "forbidden": {"kassee-web", "kassigner-firmware", "online-watcher", "rqrr", "kassigner-qa"},
    },
    ROOT / "qa/Cargo.lock": {
        "local": {"firmware-tools", "kassigner-protocol", "kassigner-qa", "kassigner-sdk", "offline-signer", "shared-signer", "signer-firmware-core"},
        "forbidden": {"kassee-web", "kassigner-firmware", "online-watcher", "rqrr"},
    },
}


def parse_dependency(value: str) -> tuple[str, str | None, str | None]:
    source = None
    if value.endswith(")") and " (" in value:
        value, source = value.rsplit(" (", 1)
        source = source[:-1]
    parts = value.rsplit(" ", 1)
    if len(parts) == 2 and re.match(r"^\d", parts[1]):
        return parts[0], parts[1], source
    return value, None, source


def cargo_compatibility_key(version: str) -> tuple[int | str, ...]:
    """Return Cargo's caret-compatible version family for stable releases."""
    core = version.split("+", 1)[0]
    if "-" in core:
        return ("prerelease", core)
    parts = core.split(".")
    try:
        major, minor, patch = (int(parts[index]) if index < len(parts) else 0 for index in range(3))
    except ValueError:
        return ("unparsed", core)
    if major > 0:
        return (major,)
    if minor > 0:
        return (0, minor)
    return (0, 0, patch)


def validate_compatible_duplicates(label: str, packages: list[dict]) -> list[str]:
    """Reject parallel lock entries Cargo would normally unify."""
    families: dict[tuple[str, str | None, tuple[int | str, ...]], set[str]] = defaultdict(set)
    for package in packages:
        source = package.get("source")
        if source is None:
            continue
        family = cargo_compatibility_key(package["version"])
        families[(package["name"], source, family)].add(package["version"])

    errors: list[str] = []
    for (name, _source, _family), versions in sorted(families.items()):
        if len(versions) > 1:
            errors.append(
                f"{label}: Cargo-compatible versions of {name} are locked in parallel: "
                f"{sorted(versions)}"
            )
    return errors


def validate_dependency_edges(label: str, packages: list[dict]) -> list[str]:
    """Require every Cargo.lock dependency edge to resolve to one package record."""
    errors: list[str] = []
    by_name: dict[str, list[tuple[str, str, str | None]]] = defaultdict(list)
    for package in packages:
        key = (package["name"], package["version"], package.get("source"))
        by_name[key[0]].append(key)

    for package in packages:
        owner = f"{package['name']} {package['version']}"
        for dependency in package.get("dependencies", []):
            name, version, source = parse_dependency(dependency)
            candidates = by_name.get(name, [])
            if version is not None:
                candidates = [candidate for candidate in candidates if candidate[1] == version]
            if source is not None:
                candidates = [candidate for candidate in candidates if candidate[2] == source]
            if len(candidates) != 1:
                errors.append(
                    f"{label}: {owner} dependency {dependency!r} resolves to {candidates}"
                )
    return errors


def validate_reachability(label: str, packages: list[dict]) -> list[str]:
    """Reject registry records that are disconnected from all local workspace packages.

    Cargo prunes unreachable package records when it rewrites a lockfile. A disconnected
    record is therefore a high-signal indication that authored dependency edges were lost
    or the lock snapshot is stale.
    """
    by_name: dict[str, list[int]] = defaultdict(list)
    for index, package in enumerate(packages):
        by_name[package["name"]].append(index)

    def resolve(value: str) -> int | None:
        name, version, source = parse_dependency(value)
        candidates = list(by_name.get(name, []))
        if version is not None:
            candidates = [index for index in candidates if packages[index]["version"] == version]
        if source is not None:
            candidates = [index for index in candidates if packages[index].get("source") == source]
        return candidates[0] if len(candidates) == 1 else None

    reachable = {index for index, package in enumerate(packages) if "source" not in package}
    pending = list(reachable)
    while pending:
        index = pending.pop()
        for dependency in packages[index].get("dependencies", []):
            target = resolve(dependency)
            if target is not None and target not in reachable:
                reachable.add(target)
                pending.append(target)

    unreachable = [
        f"{package['name']} {package['version']}"
        for index, package in enumerate(packages)
        if index not in reachable
    ]
    if not unreachable:
        return []
    return [f"{label}: unreachable lockfile package records: {unreachable}"]


BASE_SIGNER_FEATURE_SCOPE = {
    ("k256", "0.13.4"): {"cfg-if", "ecdsa", "elliptic-curve", "sha2", "signature"},
    ("ecdsa", "0.16.9"): {"der", "digest", "elliptic-curve", "rfc6979", "signature"},
    ("elliptic-curve", "0.13.8"): {
        "base16ct", "crypto-bigint", "digest", "ff", "generic-array", "group",
        "rand_core", "sec1", "subtle", "zeroize",
    },
    ("sec1", "0.7.3"): {"base16ct", "der", "generic-array", "subtle", "zeroize"},
    ("zeroize", "1.8.2"): {"zeroize_derive"},
}

LOCK_FEATURE_SCOPES = {
    ROOT / "apps/signer-firmware/Cargo.lock": {
        **BASE_SIGNER_FEATURE_SCOPE,
        ("rand_core", "0.6.4"): set(),
        ("futures-util", "0.3.32"): {"futures-core", "futures-task", "pin-project-lite"},
    },
    ROOT / "tools/Cargo.lock": {
        **BASE_SIGNER_FEATURE_SCOPE,
        ("rand_core", "0.6.4"): {"getrandom"},
        ("getrandom", "0.2.17"): {"cfg-if", "libc", "wasi"},
        ("hashbrown", "0.15.5"): {"foldhash"},
        ("kassigner-protocol", "2.0.0"): {"shared-signer"},
    },
    ROOT / "qa/Cargo.lock": {
        **BASE_SIGNER_FEATURE_SCOPE,
        ("rand_core", "0.6.4"): {"getrandom"},
        ("getrandom", "0.2.17"): {"cfg-if", "js-sys", "libc", "wasi", "wasm-bindgen"},
        ("hashbrown", "0.15.5"): {"foldhash"},
        ("kassigner-protocol", "2.0.0"): {
            "blake2b_simd", "hex", "hmac", "k256", "serde", "serde_json",
            "sha2", "shared-signer",
        },
        ("kassigner-sdk", "2.0.0"): {
            "getrandom", "hex", "js-sys", "kassigner-protocol", "serde",
            "serde_json", "wasm-bindgen",
        },
    },
}


def validate_feature_scope(path: Path, packages: list[dict]) -> list[str]:
    expected_scope = LOCK_FEATURE_SCOPES.get(path)
    if expected_scope is None:
        return []
    errors: list[str] = []
    by_key = {(package["name"], package["version"]): package for package in packages}
    for key, expected in expected_scope.items():
        package = by_key.get(key)
        if package is None:
            errors.append(f"{path.relative_to(ROOT)} is missing pinned feature-scope package {key[0]} {key[1]}")
            continue
        actual = {parse_dependency(value)[0] for value in package.get("dependencies", [])}
        if actual != expected:
            errors.append(
                f"{path.relative_to(ROOT)} feature-scope drift for {key[0]} {key[1]}: "
                f"expected {sorted(expected)}, got {sorted(actual)}"
            )
    return errors

def validate_lock(path: Path, policy: dict[str, set[str]]) -> list[str]:
    errors: list[str] = []
    if not path.is_file():
        return [f"workspace lockfile is missing: {path.relative_to(ROOT)}"]
    try:
        data = tomllib.loads(path.read_text())
    except Exception as error:
        return [f"{path.relative_to(ROOT)} is not valid TOML: {error}"]
    if data.get("version") != 4:
        errors.append(f"{path.relative_to(ROOT)} must use lockfile format 4")

    packages = data.get("package", [])
    keys = [(p["name"], p["version"], p.get("source")) for p in packages]
    if len(keys) != len(set(keys)):
        errors.append(f"{path.relative_to(ROOT)} contains duplicate package records")

    label = str(path.relative_to(ROOT))
    errors.extend(validate_compatible_duplicates(label, packages))
    errors.extend(validate_dependency_edges(label, packages))
    errors.extend(validate_reachability(label, packages))
    errors.extend(validate_feature_scope(path, packages))

    local = {p["name"] for p in packages if "source" not in p}
    required_local = policy["local"]
    optional_local = policy.get("optional_local", set())
    if not required_local.issubset(local) or not local.issubset(required_local | optional_local):
        errors.append(
            f"{path.relative_to(ROOT)} local package set mismatch: "
            f"required {sorted(required_local)}, optional {sorted(optional_local)}, "
            f"got {sorted(local)}"
        )
    names = {p["name"] for p in packages}
    leaked = names & policy["forbidden"]
    if leaked:
        errors.append(
            f"{path.relative_to(ROOT)} contains cross-workspace packages: {sorted(leaked)}"
        )
    return errors


MANIFEST_LOCK_PAIRS = (
    (ROOT / "Cargo.lock", ROOT / "crates/kassigner-protocol/Cargo.toml", True),
    (ROOT / "Cargo.lock", ROOT / "crates/kassigner-sdk/Cargo.toml", True),
    (ROOT / "Cargo.lock", ROOT / "crates/offline-signer/Cargo.toml", True),
    (ROOT / "Cargo.lock", ROOT / "crates/online-watcher/Cargo.toml", True),
    (ROOT / "Cargo.lock", ROOT / "crates/shared-signer/Cargo.toml", True),
    (ROOT / "Cargo.lock", ROOT / "crates/signer-firmware-core/Cargo.toml", True),
    (ROOT / "external/rqrr-nostd/Cargo.lock", ROOT / "external/rqrr-nostd/Cargo.toml", True),
    (ROOT / "apps/signer-firmware/Cargo.lock", ROOT / "apps/signer-firmware/Cargo.toml", True),
    (ROOT / "apps/kassee-web/Cargo.lock", ROOT / "apps/kassee-web/Cargo.toml", True),
    (ROOT / "apps/kassee-web/Cargo.lock", ROOT / "crates/kassigner-sdk/Cargo.toml", False),
    (ROOT / "apps/kassee-web/Cargo.lock", ROOT / "crates/kassigner-protocol/Cargo.toml", False),
    # These are transitive path dependencies of the independent KasSee
    # workspace. Their normal/build dependencies must be represented, while a
    # dev-only edge may or may not be retained by Cargo's lock reconciliation.
    (ROOT / "apps/kassee-web/Cargo.lock", ROOT / "crates/online-watcher/Cargo.toml", False),
    (ROOT / "apps/kassee-web/Cargo.lock", ROOT / "crates/shared-signer/Cargo.toml", False),
    (ROOT / "tools/Cargo.lock", ROOT / "tools/Cargo.toml", True),
    (ROOT / "qa/Cargo.lock", ROOT / "qa/Cargo.toml", True),
)


def manifest_dependency_names(data: dict, *, include_dev: bool) -> tuple[set[str], set[str]]:
    required: set[str] = set()
    optional_in_lock: set[str] = set()
    for section in ("dependencies", "build-dependencies"):
        required.update(data.get(section, {}))

    dev_only = set(data.get("dev-dependencies", {}))
    if include_dev:
        required.update(dev_only)
    else:
        optional_in_lock.update(dev_only)

    # This generic manifest/lock alignment helper is also used for crates that
    # appear transitively inside independent workspaces. Treat target-specific
    # edges as allowed here; Cargo-native `--locked` checks remain authoritative
    # for each workspace, while dedicated root-workspace regression tests enforce
    # the all-feature/all-target edges required for root workspace members.
    for target in data.get("target", {}).values():
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            optional_in_lock.update(target.get(section, {}))
    return required, optional_in_lock


def validate_manifest_lock_alignment() -> list[str]:
    errors: list[str] = []
    lock_cache: dict[Path, dict] = {}
    for lock_path, manifest_path, include_dev in MANIFEST_LOCK_PAIRS:
        manifest = tomllib.loads(manifest_path.read_text())
        package_name = manifest["package"]["name"]
        required, optional_dev = manifest_dependency_names(manifest, include_dev=include_dev)
        lock = lock_cache.setdefault(lock_path, tomllib.loads(lock_path.read_text()))
        candidates = [
            package for package in lock.get("package", [])
            if package["name"] == package_name and "source" not in package
        ]
        if len(candidates) != 1:
            errors.append(
                f"{lock_path.relative_to(ROOT)} must contain exactly one local "
                f"package record for {package_name}"
            )
            continue
        actual = {parse_dependency(value)[0] for value in candidates[0].get("dependencies", [])}
        missing = required - actual
        unexpected = actual - required - optional_dev
        if missing or unexpected:
            errors.append(
                f"manifest/lock dependency mismatch for {manifest_path.relative_to(ROOT)}: "
                f"missing {sorted(missing)}, stale {sorted(unexpected)}"
            )
    return errors


def validate_workspace_manifests() -> list[str]:
    errors: list[str] = []
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    workspace = root.get("workspace", {})
    expected_members = {
        "crates/kassigner-protocol",
        "crates/kassigner-sdk",
        "crates/offline-signer",
        "crates/online-watcher",
        "crates/shared-signer",
        "crates/signer-firmware-core",
    }
    expected_excludes = {
        "apps/signer-firmware",
        "apps/kassee-web",
        "tools",
        "qa",
        "qa/fuzz",
        "external/rqrr-nostd",
    }
    if set(workspace.get("members", [])) != expected_members:
        errors.append("root workspace members do not match the shared-library boundary")
    if set(workspace.get("exclude", [])) != expected_excludes:
        errors.append("root workspace excludes do not match the independent deliverables")

    for manifest in (
        ROOT / "apps/signer-firmware/Cargo.toml",
        ROOT / "apps/kassee-web/Cargo.toml",
        ROOT / "tools/Cargo.toml",
        ROOT / "qa/Cargo.toml",
        ROOT / "qa/fuzz/Cargo.toml",
        ROOT / "external/rqrr-nostd/Cargo.toml",
    ):
        data = tomllib.loads(manifest.read_text())
        if "workspace" not in data:
            errors.append(f"independent workspace marker missing: {manifest.relative_to(ROOT)}")
    return errors


def main() -> int:
    errors = [*validate_workspace_manifests(), *validate_manifest_lock_alignment()]
    package_counts: list[str] = []
    for lock, policy in WORKSPACES.items():
        errors.extend(validate_lock(lock, policy))
        if lock.is_file():
            package_counts.append(
                f"{lock.relative_to(ROOT)}="
                f"{len(tomllib.loads(lock.read_text()).get('package', []))}"
            )

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("PASS: independent workspace lock graphs (" + ", ".join(package_counts) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
