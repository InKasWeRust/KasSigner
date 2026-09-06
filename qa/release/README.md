[KasSigner](../../README.md) › [Documentation](../../docs/README.md) › [Reproducible Builds](../../docs/development/REPRODUCIBLE_BUILD.md) › Release evidence

# Release-readiness evidence

`run-all.sh`, mutation testing, reproducible builds, and internal source-security controls cannot prove physical, organizational, or independently attested claims. A production release therefore also runs `qa/linux/run-release-readiness.sh` (or the Windows equivalent) against evidence kept outside the source tree.

## Trust and provenance model

Release evidence is **not trusted merely because a JSON file says `"status": "pass"`**. Every required evidence JSON document uses schema 2, binds the exact release source SHA-256 and final release-artifact SHA-256, identifies a trusted signer key, and is accompanied by a detached Ed25519 signature named `<evidence>.json.sig`. The gate verifies that signature with OpenSSL against an **external trust policy** whose own SHA-256 is supplied independently by the release operator.

The trust policy is deliberately not generated or accepted from the evidence directory. `KASSIGNER_RELEASE_TRUST_POLICY` points to the operator-controlled policy and `KASSIGNER_RELEASE_TRUST_POLICY_SHA256` supplies its expected digest. The policy maps each evidence class to allowed key IDs and maps those IDs to hashed Ed25519 public-key PEM files. This prevents an evidence bundle from introducing a new key and self-signing its own claims.

For ordinary evidence classes, the signed JSON must also contain a `report` descriptor:

```json
{
  "schema": 2,
  "status": "pass",
  "source_sha256": "<exact release source SHA-256>",
  "release_artifact_sha256": "<exact final release SHA-256>",
  "signer_key_id": "<trusted external key id>",
  "report": {
    "path": "reports/example-report.pdf",
    "sha256": "<SHA-256 of the actual report>",
    "bytes": 12345
  }
}
```

The path must remain inside the evidence directory. The gate opens the referenced report, verifies its exact byte length and SHA-256, and verifies the detached Ed25519 signature over the **exact evidence JSON bytes**. Editing either the attestation metadata or the underlying report after signing causes the gate to fail.

A minimal external trust policy has this shape:

```json
{
  "schema": 1,
  "keys": {
    "example-auditor-2026": {
      "public_key": "keys/example-auditor-2026.pem",
      "sha256": "<SHA-256 of that PEM file>"
    }
  },
  "evidence": {
    "independent_security_audit.json": ["example-auditor-2026"]
  }
}
```

The example is structural documentation only; the repository intentionally contains no production trust policy, external public keys, signatures, or placeholder `PASS` attestations.

## Required evidence classes

The gate requires signed, source/artifact-bound evidence for:

- an independent professional security/cryptography audit;
- two distinct clean reproducible builders;
- dependency/advisory, CycloneDX SBOM, license-policy, and release-lockfile evidence;
- non-exportable offline production-signing custody with dual control;
- HIL plus production signed/fused smoke on Waveshare, Waveshare-AF, and M5Stack;
- M5Stack CoreS3 Flash Encryption **Release Mode** evidence, including `DIS_DOWNLOAD_MANUAL_ENCRYPT` and write-protected flash-encryption state;
- M5Stack CoreS3 Secure Boot v2 evidence tied to the checked-in production bootloader profile and fused RSA-3072 public-key digest;
- M5Stack CoreS3 dual-authority evidence proving vendor digest 0 + owner digest 1 coexistence when enrolled, slot 2 closure, trusted-key revoke protection, development/pre-Pop no-eFuse behavior, official- and owner-signed application boot, unrelated-key/downgrade rejection, and failed-install OTA preservation;
- M5Stack CoreS3 owner-only parity evidence proving owner digest 0 is the sole live Secure Boot authority, digest slots 1/2 are revoked, Pop It cannot bypass owner enrollment, vendor-only images are rejected after enforcement, and owner-signed application updates work through digest 0;
- M5Stack CoreS3 anti-rollback negative evidence showing the second-stage bootloader rejects a correctly signed image whose application `secure_version` is below the fused `SECURE_VERSION`;
- M5Stack CoreS3 signed-update-manifest negative tests covering field tampering, trailing bytes, wrong board/channel/layout, image-size/hash mismatch, and security-version downgrade;
- M5Stack CoreS3 linker/map evidence showing `APP_DATA` and outgoing secret QR state in internal SRAM rather than PSRAM;
- physical entropy characterization;
- eFuse HMAC provisioning/read protection;
- Secure Boot fault/modified-image testing;
- update power-loss testing;
- credential timing;
- physical fault-injection testing;
- an iOS signed **Release** build and physical-device Release/HIL smoke;
- an Android signed **release** build and physical-device release/HIL smoke.

The iOS/Android smoke records must exercise runtime-integrity checking, navigation confinement, QR/file mediation, privacy/app-lock behavior, lifecycle recovery, and node connectivity. Android additionally requires process-death restoration evidence.

For CoreS3, `qa/linux/run-m5stack-security-hil.sh` is a **read-only** collector for eFuse/security-state reports on an already provisioned device. It never burns eFuses or writes flash. Anti-rollback rejection is intentionally a separate destructive HIL fixture because a production Flash Encryption Release device should not depend on UART plaintext reflashing.

Any developer-side command that permanently burns/locks eFuses or production security state must be executed through `qa/checks/release/irreversible_action_ack.py`, which requires an interactive exact irreversibility phrase and an exact target-device retype before it substitutes the confirmed device into the command. This is separate from, and does not weaken or bypass, the signed CoreS3 firmware's typed on-device **Pop It!** consent for its permanent Secure Boot transition. Repository hardening enforces both contracts.

## Independent builder binding

`KASSIGNER_RELEASE_MANIFEST` must point to the `ARTIFACT-MANIFEST.json` from the final reproducible release output. Before comparing builders, the gate opens every artifact named by that final manifest and verifies its recorded size and SHA-256. Each independently signed builder record must reference and hash its own actual artifact manifest, report an exact `release_manifest_sha256`, and derive its claimed `unsigned_artifact_hashes` from that manifest. The gate parses all three manifests and requires:

1. builder A and builder B use distinct builder IDs;
2. they are signed by distinct trusted attester keys;
3. each builder's declared unsigned hashes exactly match its referenced manifest;
4. both builder manifests converge on the same unsigned artifact set; and
5. that unsigned set exactly matches the final release manifest supplied to the gate.

Because each builder JSON is itself signature-protected and also binds the final `release_artifact_sha256`, the reproducibility claim is tied to the exact final release artifact rather than to an arbitrary mutually matching artifact set.

## Software assurance

`software_assurance.json` is no longer exempt from exact source/artifact binding. `qa/linux/release/generate_software_assurance.sh` and its Windows counterpart require:

- `KASSIGNER_SOURCE_SHA256`;
- `KASSIGNER_RELEASE_ARTIFACT_SHA256`;
- `KASSIGNER_RELEASE_EVIDENCE_SIGNER_KEY_ID`; and
- `KASSIGNER_RELEASE_EVIDENCE_SIGNING_KEY`.

The generator runs `cargo-deny`, `syft`, and `osv-scanner`, records their real version strings, hashes and byte-counts the actual scanner outputs, copies and hashes every release-source Cargo lockfile, writes canonical `software_assurance.json`, and signs that JSON with Ed25519. The release gate re-opens every referenced file and rejects missing, substituted, or modified evidence.
When `KASSIGNER_RELEASE_EVIDENCE_DIR` is not set, the generation helper writes ephemeral/local evidence under `target/qa/release/evidence`; release-readiness itself still requires an explicit evidence root and source/artifact bindings.

## Running the gate

`make release` only builds and manifest-verifies reproducible artifacts. It intentionally does not fail merely because external audit/HIL/signing-custody evidence has not been supplied. Once the candidate artifact and evidence bundle exist, run the fail-closed gate explicitly:

```bash
make release-readiness
```

The release operator supplies all external roots explicitly:

```text
KASSIGNER_RELEASE_EVIDENCE_DIR
KASSIGNER_SOURCE_SHA256
KASSIGNER_RELEASE_ARTIFACT_SHA256
KASSIGNER_RELEASE_MANIFEST
KASSIGNER_RELEASE_TRUST_POLICY
KASSIGNER_RELEASE_TRUST_POLICY_SHA256
```

OpenSSL is required for Ed25519 signature verification. Source-controlled placeholder `PASS` attestations are intentionally not provided.

Mobile mutation reports mean 100% kill of the **enumerated supported mutation sites** in the configured Kotlin/Swift domain and infrastructure layers. They are not a claim of exhaustive AST mutation or formal verification.
