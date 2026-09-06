#!/usr/bin/env python3
"""Regression tests for Cargo lockfile graph validation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from workspace.check_lockfile import (  # noqa: E402
    WORKSPACES,
    validate_compatible_duplicates,
    validate_dependency_edges,
    validate_feature_scope,
    validate_reachability,
    validate_lock,
    validate_manifest_lock_alignment,
)


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class LockfilePolicyTests(unittest.TestCase):
    def test_rejects_parallel_cargo_compatible_versions(self) -> None:
        packages = [
            {
                "name": "generic-array",
                "version": "0.14.7",
                "source": REGISTRY,
            },
            {
                "name": "generic-array",
                "version": "0.14.9",
                "source": REGISTRY,
            },
        ]
        errors = validate_compatible_duplicates("fixture", packages)
        self.assertEqual(len(errors), 1)
        self.assertIn("Cargo-compatible versions", errors[0])

    def test_allows_semver_incompatible_parallel_versions(self) -> None:
        packages = [
            {
                "name": "generic-array",
                "version": "0.14.7",
                "source": REGISTRY,
            },
            {
                "name": "generic-array",
                "version": "0.15.0",
                "source": REGISTRY,
            },
        ]
        self.assertEqual(validate_compatible_duplicates("fixture", packages), [])

    def test_rejects_ambiguous_unversioned_edge(self) -> None:
        packages = [
            {
                "name": "root",
                "version": "1.0.0",
                "dependencies": ["generic-array"],
            },
            {
                "name": "generic-array",
                "version": "0.14.7",
                "source": REGISTRY,
            },
            {
                "name": "generic-array",
                "version": "0.14.9",
                "source": REGISTRY,
            },
        ]
        errors = validate_dependency_edges("fixture", packages)
        self.assertEqual(len(errors), 1)
        self.assertIn("resolves to", errors[0])


    def test_rejects_unreachable_registry_package_records(self) -> None:
        packages = [
            {"name": "root", "version": "1.0.0", "dependencies": []},
            {"name": "orphan", "version": "1.2.3", "source": REGISTRY},
        ]
        errors = validate_reachability("fixture", packages)
        self.assertEqual(len(errors), 1)
        self.assertIn("orphan 1.2.3", errors[0])

    def test_accepts_fully_reachable_lock_graph(self) -> None:
        packages = [
            {"name": "root", "version": "1.0.0", "dependencies": ["dep"]},
            {"name": "dep", "version": "1.2.3", "source": REGISTRY},
        ]
        self.assertEqual(validate_reachability("fixture", packages), [])

    def test_rejects_tools_feature_scope_drift(self) -> None:
        import tomllib

        lock = tomllib.loads((ROOT / "tools/Cargo.lock").read_text())
        packages = [dict(package) for package in lock["package"]]
        k256 = next(package for package in packages if package["name"] == "k256")
        k256["dependencies"] = [*k256["dependencies"], "once_cell"]
        errors = validate_feature_scope(ROOT / "tools/Cargo.lock", packages)
        self.assertTrue(any("feature-scope drift for k256 0.13.4" in error for error in errors))

    def test_rejects_qa_sdk_target_dependency_drift(self) -> None:
        import tomllib

        lock = tomllib.loads((ROOT / "qa/Cargo.lock").read_text())
        packages = [dict(package) for package in lock["package"]]
        sdk = next(package for package in packages if package["name"] == "kassigner-sdk")
        sdk["dependencies"] = [
            dependency for dependency in sdk["dependencies"] if not dependency.startswith("js-sys")
        ]
        errors = validate_feature_scope(ROOT / "qa/Cargo.lock", packages)
        self.assertTrue(any("feature-scope drift for kassigner-sdk 2.0.0" in error for error in errors))

    def test_kassee_lock_policy_allows_cargo_resolved_dev_edge_shape(self) -> None:
        import tomllib

        lock = tomllib.loads((ROOT / "apps/kassee-web/Cargo.lock").read_text())
        online = next(
            package
            for package in lock["package"]
            if package["name"] == "online-watcher" and "source" not in package
        )
        dependency_names = {value.split()[0] for value in online.get("dependencies", [])}
        self.assertIn("shared-signer", dependency_names)
        self.assertTrue(dependency_names <= {
            "ark-bn254", "ark-groth16", "ark-relations", "ark-serialize",
            "ark-snark", "ark-std", "blake2b_simd", "blake3", "getrandom",
            "hex", "hmac", "js-sys", "k256", "kassigner-protocol", "offline-signer", "qrcode",
            "serde", "serde_json", "sha2", "shared-signer", "wasm-bindgen",
            "wasm-bindgen-futures", "web-sys",
        })

    def test_kassee_qrcode_does_not_enable_unused_image_stack(self) -> None:
        import tomllib

        manifest = tomllib.loads((ROOT / "crates/online-watcher/Cargo.toml").read_text())
        qrcode = manifest["dependencies"]["qrcode"]
        self.assertEqual(qrcode["version"], "0.14.1")
        self.assertFalse(qrcode["default-features"])

        for relative in ("Cargo.lock", "apps/kassee-web/Cargo.lock"):
            lock = tomllib.loads((ROOT / relative).read_text())
            packages = lock["package"]
            qrcode_package = next(package for package in packages if package["name"] == "qrcode")
            self.assertNotIn("image", {value.split()[0] for value in qrcode_package.get("dependencies", [])})
            self.assertNotIn("image", {package["name"] for package in packages})

    def test_repository_lockfiles_have_unambiguous_dependency_edges(self) -> None:
        errors: list[str] = []
        for lock, policy in WORKSPACES.items():
            errors.extend(validate_lock(lock, policy))
        self.assertEqual(errors, [])

    def test_repository_lockfiles_match_authored_manifests(self) -> None:
        self.assertEqual(validate_manifest_lock_alignment(), [])


if __name__ == "__main__":
    unittest.main()
