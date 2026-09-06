import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE = ROOT / "qa/checks/release/release_readiness.py"
SHA_SOURCE = "1" * 64
SHA_RELEASE = "2" * 64


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def descriptor(path: pathlib.Path, root: pathlib.Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": digest(path),
        "bytes": path.stat().st_size,
    }


class EvidenceFixture:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir()
        self.keys = root / "trust" / "keys"
        self.keys.mkdir(parents=True)
        self.private_a, self.public_a = self._key("a")
        self.private_b, self.public_b = self._key("b")
        self.final_manifest = root / "ARTIFACT-MANIFEST.json"
        artifacts = []
        for name, content in (
            ("kassigner-waveshare-unsigned.bin", b"waveshare-unsigned"),
            ("kassigner-m5stack-unsigned.bin", b"m5stack-unsigned"),
            ("kassigner-waveshare.bin", b"waveshare-signed"),
        ):
            artifact = root / name
            artifact.write_bytes(content)
            artifacts.append({"file": name, "sha256": digest(artifact), "size": len(content)})
        self.final_manifest.write_text(json.dumps({
            "artifacts": artifacts,
            "format_version": 1,
        }, sort_keys=True) + "\n")
        self.final_manifest_sha = digest(self.final_manifest)
        self._write_all_evidence()
        self.trust_policy = root / "trust" / "policy.json"
        names = self._required_names()
        policy = {
            "schema": 1,
            "keys": {
                "key-a": {"public_key": "keys/a.pub.pem", "sha256": digest(self.public_a)},
                "key-b": {"public_key": "keys/b.pub.pem", "sha256": digest(self.public_b)},
            },
            "evidence": {name: (["key-b"] if name == "independent_builder_b.json" else ["key-a"]) for name in names},
        }
        self.trust_policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")

    def _key(self, name: str) -> tuple[pathlib.Path, pathlib.Path]:
        private = self.keys / f"{name}.key.pem"
        public = self.keys / f"{name}.pub.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        return private, public

    @staticmethod
    def _required_names() -> tuple[str, ...]:
        self_check = ROOT / "qa/checks/release/readiness/model.py"
        namespace: dict[str, object] = {}
        exec(compile(self_check.read_text(), str(self_check), "exec"), namespace)
        return tuple(namespace["REQUIRED_EVIDENCE"].keys())

    def _sign(self, path: pathlib.Path, private: pathlib.Path) -> None:
        subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin",
            "-in", str(path), "-out", str(path) + ".sig",
        ], check=True, capture_output=True)

    def _base(self, signer: str = "key-a") -> dict[str, object]:
        return {
            "schema": 2,
            "status": "pass",
            "source_sha256": SHA_SOURCE,
            "release_artifact_sha256": SHA_RELEASE,
            "signer_key_id": signer,
        }

    def _write_generic(self, name: str, extra: dict[str, object] | None = None) -> None:
        report = self.evidence / "reports" / (name.removesuffix(".json") + ".txt")
        report.parent.mkdir(exist_ok=True)
        report.write_text(f"evidence report for {name}\n")
        document = self._base()
        document["report"] = descriptor(report, self.evidence)
        if extra:
            document.update(extra)
        path = self.evidence / name
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        self._sign(path, self.private_a)

    def _write_builder(self, name: str, signer: str, private: pathlib.Path, builder_id: str) -> None:
        manifest = self.evidence / "builders" / f"{builder_id}.json"
        manifest.parent.mkdir(exist_ok=True)
        manifest.write_bytes(self.final_manifest.read_bytes())
        document = self._base(signer)
        document.update({
            "builder_id": builder_id,
            "release_manifest_sha256": self.final_manifest_sha,
            "manifest": descriptor(manifest, self.evidence),
            "unsigned_artifact_hashes": {
                item["file"]: item["sha256"]
                for item in json.loads(self.final_manifest.read_text())["artifacts"]
                if "-unsigned" in item["file"]
            },
        })
        path = self.evidence / name
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        self._sign(path, private)

    def _write_software(self) -> None:
        software = self.evidence / "software"
        software.mkdir()
        files: dict[str, object] = {}
        for name in ("cargo-deny.txt", "sbom.cdx.json", "osv.json"):
            path = software / name
            path.write_text(f"verified {name}\n")
            files[name] = descriptor(path, self.evidence)
        lockfiles: dict[str, object] = {}
        for relative in (
            "Cargo.lock",
            "apps/kassee-web/Cargo.lock",
            "apps/signer-firmware/Cargo.lock",
            "external/rqrr-nostd/Cargo.lock",
            "qa/Cargo.lock",
            "tools/Cargo.lock",
        ):
            lock = software / relative.replace("/", "__")
            lock.write_text(f"# pinned {relative}\n")
            lockfiles[relative] = descriptor(lock, self.evidence)
        document = self._base()
        document.update({
            "tool_versions": {"cargo-deny": "cargo-deny 1", "syft": "syft 1", "osv-scanner": "osv-scanner 1"},
            "files": files,
            "lockfiles": lockfiles,
        })
        path = self.evidence / "software_assurance.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        self._sign(path, self.private_a)

    def _write_all_evidence(self) -> None:
        self._write_builder("independent_builder_a.json", "key-a", self.private_a, "builder-a")
        self._write_builder("independent_builder_b.json", "key-b", self.private_b, "builder-b")
        self._write_software()
        self._write_generic("independent_security_audit.json", {
            "independent_organization": "Independent Security Lab",
            "self_review": False,
            "unresolved_critical": 0,
            "unresolved_high": 0,
        })
        self._write_generic("signing_key_custody.json", {
            "dual_control": True, "key_exportable": False, "storage": "offline-hsm",
        })
        self._write_generic("m5stack_owner_authority.json", {
            "vendor_digest_slot": 0,
            "owner_digest_slot": 1,
            "unused_digest_slot": 2,
            "unused_digest_revoked": True,
            "trusted_revoke_write_protected": True,
            "development_efuse_writes": False,
            "enrollment_before_pop_it": "pass",
            "enrollment_after_pop_it_rejected": "pass",
            "vendor_firmware_boot": "pass",
            "owner_firmware_boot": "pass",
            "unrelated_owner_key_rejected": "pass",
            "owner_downgrade_rejected": "pass",
            "failed_owner_install_preserves_previous_ota": "pass",
            "pop_it_without_owner_closes_enrollment": "pass",
        })
        ios_build = {
            "platform": "ios", "configuration": "release", "signed_build": True,
            "mobile_artifact_sha256": "3" * 64, "embedded_runtime_sha256": "4" * 64,
            "toolchain_version": "Xcode 18",
        }
        android_build = {
            "platform": "android", "configuration": "release", "signed_build": True,
            "mobile_artifact_sha256": "5" * 64, "embedded_runtime_sha256": "6" * 64,
            "toolchain_version": "Android Gradle Plugin 9",
        }
        smoke = {
            "launch": "pass", "runtime_integrity": "pass", "navigation_confinement": "pass",
            "qr_import": "pass", "file_import_export": "pass", "app_lock_privacy": "pass",
            "background_foreground": "pass", "node_connectivity": "pass",
        }
        self._write_generic("ios_release_build.json", ios_build)
        self._write_generic("android_release_build.json", android_build)
        self._write_generic("ios_hil_smoke.json", {
            "platform": "ios", "configuration": "release", "physical_device": True,
            "device_model": "iPhone", "os_version": "iOS 20", "smoke_tests": smoke,
        })
        self._write_generic("android_hil_smoke.json", {
            "platform": "android", "configuration": "release", "physical_device": True,
            "device_model": "Pixel", "os_version": "Android 17",
            "smoke_tests": {**smoke, "process_death_restore": "pass"},
        })
        specialized = {
            "independent_builder_a.json", "independent_builder_b.json", "software_assurance.json",
            "independent_security_audit.json", "signing_key_custody.json", "m5stack_owner_authority.json",
            "ios_release_build.json", "android_release_build.json", "ios_hil_smoke.json", "android_hil_smoke.json",
        }
        for name in self._required_names():
            if name not in specialized:
                self._write_generic(name)

    def run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([
            "python3", str(GATE),
            "--evidence-dir", str(self.evidence),
            "--source-sha256", SHA_SOURCE,
            "--release-artifact-sha256", SHA_RELEASE,
            "--release-manifest", str(self.final_manifest),
            "--trust-policy", str(self.trust_policy),
            "--trust-policy-sha256", digest(self.trust_policy),
        ], text=True, capture_output=True, check=False)


class ReleaseReadinessGate(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], EvidenceFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, EvidenceFixture(pathlib.Path(temporary.name))

    def test_complete_signed_candidate_bound_evidence_passes(self) -> None:
        temporary, fixture = self.fixture()
        try:
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("report-hash verified", result.stdout)
        finally:
            temporary.cleanup()

    def test_tampered_report_fails_even_when_attestation_signature_is_valid(self) -> None:
        temporary, fixture = self.fixture()
        try:
            report = fixture.evidence / "reports" / "hil_waveshare.txt"
            report.write_text("tampered after attestation\n")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 does not match the signed descriptor", result.stdout)
        finally:
            temporary.cleanup()

    def test_tampered_attestation_signature_fails(self) -> None:
        temporary, fixture = self.fixture()
        try:
            path = fixture.evidence / "credential_timing.json"
            document = json.loads(path.read_text())
            document["status"] = "fail"
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("signature verification failed", result.stdout)
        finally:
            temporary.cleanup()

    def test_final_release_artifact_bytes_must_match_manifest(self) -> None:
        temporary, fixture = self.fixture()
        try:
            (fixture.root / "kassigner-waveshare-unsigned.bin").write_bytes(b"tampered-release-bytes")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("final release artifact SHA-256 mismatch", result.stdout)
        finally:
            temporary.cleanup()

    def test_builder_manifest_must_match_final_release_manifest(self) -> None:
        temporary, fixture = self.fixture()
        try:
            path = fixture.evidence / "builders" / "builder-a.json"
            document = json.loads(path.read_text())
            document["artifacts"][0]["sha256"] = "d" * 64
            path.write_text(json.dumps(document, sort_keys=True) + "\n")
            builder = fixture.evidence / "independent_builder_a.json"
            attestation = json.loads(builder.read_text())
            attestation["manifest"] = descriptor(path, fixture.evidence)
            builder.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n")
            fixture._sign(builder, fixture.private_a)
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not match the final release manifest", result.stdout)
        finally:
            temporary.cleanup()

    def test_trust_policy_is_operator_hash_anchored(self) -> None:
        temporary, fixture = self.fixture()
        try:
            original_hash = digest(fixture.trust_policy)
            policy = json.loads(fixture.trust_policy.read_text())
            policy["evidence"]["hil_waveshare.json"] = ["key-b"]
            fixture.trust_policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
            result = subprocess.run([
                "python3", str(GATE),
                "--evidence-dir", str(fixture.evidence),
                "--source-sha256", SHA_SOURCE,
                "--release-artifact-sha256", SHA_RELEASE,
                "--release-manifest", str(fixture.final_manifest),
                "--trust-policy", str(fixture.trust_policy),
                "--trust-policy-sha256", original_hash,
            ], text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("operator-supplied anchor", result.stdout)
        finally:
            temporary.cleanup()

    def test_software_assurance_file_hashes_are_verified(self) -> None:
        temporary, fixture = self.fixture()
        try:
            (fixture.evidence / "software" / "sbom.cdx.json").write_text("tampered sbom\n")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("software_assurance.json: sbom.cdx.json: SHA-256 does not match", result.stdout)
        finally:
            temporary.cleanup()

    def test_independent_builders_require_distinct_trusted_signing_keys(self) -> None:
        temporary, fixture = self.fixture()
        try:
            builder = fixture.evidence / "independent_builder_b.json"
            document = json.loads(builder.read_text())
            document["signer_key_id"] = "key-a"
            builder.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            fixture._sign(builder, fixture.private_a)
            policy = json.loads(fixture.trust_policy.read_text())
            policy["evidence"]["independent_builder_b.json"] = ["key-a", "key-b"]
            fixture.trust_policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("distinct trusted attester keys", result.stdout)
        finally:
            temporary.cleanup()

    def test_software_assurance_requires_every_release_lockfile(self) -> None:
        temporary, fixture = self.fixture()
        try:
            path = fixture.evidence / "software_assurance.json"
            document = json.loads(path.read_text())
            document["lockfiles"].pop("apps/signer-firmware/Cargo.lock")
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            fixture._sign(path, fixture.private_a)
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing release lockfiles", result.stdout)
        finally:
            temporary.cleanup()

    def test_report_path_cannot_escape_evidence_directory(self) -> None:
        temporary, fixture = self.fixture()
        try:
            path = fixture.evidence / "secure_boot_fault.json"
            document = json.loads(path.read_text())
            document["report"]["path"] = "../outside.txt"
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            fixture._sign(path, fixture.private_a)
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("path must stay inside the evidence directory", result.stdout)
        finally:
            temporary.cleanup()

    def test_mobile_hil_requires_physical_release_device(self) -> None:
        temporary, fixture = self.fixture()
        try:
            path = fixture.evidence / "ios_hil_smoke.json"
            document = json.loads(path.read_text())
            document["physical_device"] = False
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            fixture._sign(path, fixture.private_a)
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("physical_device must be true", result.stdout)
        finally:
            temporary.cleanup()

    def test_software_assurance_generator_is_candidate_bound_and_canonical(self) -> None:
        linux = (ROOT / "qa/linux/release/generate_software_assurance.sh").read_text()
        windows = (ROOT / "qa/windows/release/generate_software_assurance.ps1").read_text()
        generator = (ROOT / "qa/checks/release/generate_software_assurance.py").read_text()
        for source in (linux, windows):
            self.assertIn("KASSIGNER_SOURCE_SHA256", source)
            self.assertIn("KASSIGNER_RELEASE_ARTIFACT_SHA256", source)
            self.assertIn("KASSIGNER_RELEASE_EVIDENCE_SIGNING_KEY", source)
        self.assertIn('"software_assurance.json"', generator)
        self.assertIn("LOCKFILES", generator)
        self.assertNotIn("software-assurance.json", generator)


if __name__ == "__main__":
    unittest.main()
