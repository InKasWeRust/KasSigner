from __future__ import annotations

from pathlib import Path
import tomllib


SDK_CRATES = ("kassigner-protocol", "kassigner-sdk")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    for sdk_name in SDK_CRATES:
        errors.extend(_check_sdk_crate(root, sdk_name))
    errors.extend(_check_dependency_direction(root))
    errors.extend(_check_protocol_boundaries(root))
    errors.extend(_check_licensing_boundaries(root))
    errors.extend(_check_wallet_policy_boundary(root))
    errors.extend(_check_public_release_contract(root))
    errors.extend(_check_crate_inventory(root))
    return errors


def _manifest(root: Path, name: str) -> dict:
    return tomllib.loads((root / "crates" / name / "Cargo.toml").read_text())


def _check_sdk_crate(root: Path, sdk_name: str) -> list[str]:
    errors: list[str] = []
    sdk_root = root / "crates" / sdk_name
    manifest_path = sdk_root / "Cargo.toml"
    if not manifest_path.is_file():
        return [f"official Rust/WASM SDK manifest is missing: crates/{sdk_name}/Cargo.toml"]
    manifest = tomllib.loads(manifest_path.read_text())
    if set(manifest.get("lib", {}).get("crate-type", [])) != {"rlib"}:
        errors.append(f"{sdk_name} manifest must remain Rust rlib-only; WASM cdylib is requested by the dedicated build pipeline")
    if (sdk_root / "javascript").exists():
        errors.append(f"{sdk_name} must not contain an authored JavaScript SDK layer")
    authored_js = [path for path in sdk_root.rglob("*.js") if "pkg" not in path.relative_to(sdk_root).parts]
    if authored_js:
        errors.append(f"{sdk_name} implementation must remain Rust/WASM; authored JavaScript found")
    for required in (
        sdk_root / "src/lib.rs",
        sdk_root / "src/wasm/mod.rs",
        sdk_root / "README.md",
        sdk_root / "build.sh",
        sdk_root / "build.ps1",
    ):
        if not required.is_file():
            errors.append(f"required Rust/WASM SDK path is missing: {required.relative_to(root)}")
    return errors


def _check_dependency_direction(root: Path) -> list[str]:
    errors: list[str] = []
    protocol_deps = _manifest(root, "kassigner-protocol").get("dependencies", {})
    sdk_deps = _manifest(root, "kassigner-sdk").get("dependencies", {})
    online_deps = _manifest(root, "online-watcher").get("dependencies", {})
    if "online-watcher" in protocol_deps:
        errors.append("kassigner-protocol must not depend on KasSee/online-watcher")
    if "signer-firmware-core" in protocol_deps:
        errors.append("kassigner-protocol must not depend on GPL/device-policy signer-firmware-core")
    if "kassigner-protocol" not in sdk_deps or "online-watcher" in sdk_deps:
        errors.append("kassigner-sdk must depend on kassigner-protocol and not online-watcher")
    if "signer-firmware-core" in sdk_deps:
        errors.append("kassigner-sdk must not expose signer-firmware-core in the public SDK dependency graph")
    if "kassigner-protocol" not in online_deps:
        errors.append("KasSee/online-watcher must consume kassigner-protocol rather than own reusable relay logic")
    return errors


def _check_protocol_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    protocol_root = root / "crates/kassigner-protocol/src"
    source = "\n".join(path.read_text() for path in protocol_root.rglob("*.rs"))
    if "svg:" in source or "qrcode::" in source:
        errors.append("kassigner-protocol QR frames must expose raw payloads, not rendered SVG/UI")
    if "thread_local!" in source:
        errors.append("kassigner-protocol QR/session state must be instance-owned, not thread-global")
    if '_ => "kaspa"' in source:
        errors.append("kassigner-protocol network parsing must never fall back to mainnet")
    pairing = (protocol_root / "pairing/mod.rs").read_text()
    for marker in ("nonce", "account_fingerprint", "DerivedAddress"):
        if marker not in pairing:
            errors.append(f"privacy pairing binding is missing {marker}")

    descriptor = (protocol_root / "wire/multisig_descriptor.rs").read_text()
    for marker in (
        "pub const MAX_DESCRIPTOR_PARTICIPANTS",
        "pub fn parse_multisig_descriptor",
        "multi_hd45(",
        "multi_hd(",
        "multi(",
        "DuplicateParticipant",
    ):
        if marker not in descriptor:
            errors.append(f"canonical multisig descriptor parser is missing {marker}")
    watcher_descriptor = (root / "crates/online-watcher/src/multisig/descriptor.rs").read_text()
    if "parse_multisig_descriptor(value.as_bytes())" not in watcher_descriptor:
        errors.append("KasSee multisig descriptor facade must delegate syntax parsing to kassigner-protocol")
    for duplicate_parser in ("fn parse_hd44", "fn parse_hd45", "fn parse_static", "fn decode_legacy_kpub"):
        if duplicate_parser in watcher_descriptor:
            errors.append(f"KasSee must not re-own canonical descriptor grammar: {duplicate_parser}")
    firmware_descriptor = (root / "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/descriptor.rs").read_text()
    sd_descriptor = (root / "apps/signer-firmware/src/runtime/interactions/sd/common/shared.rs").read_text()
    if "kassigner_protocol::wire::multisig_descriptor::parse_multisig_descriptor" not in firmware_descriptor:
        errors.append("firmware camera descriptor import must use the canonical kassigner-protocol parser")
    if "kassigner_protocol::wire::multisig_descriptor::parse_multisig_descriptor" not in sd_descriptor:
        errors.append("firmware SD descriptor import must use the canonical kassigner-protocol parser")

    watcher_qr = (root / "crates/online-watcher/src/protocol/qr.rs").read_text()
    for marker in ("kassigner_protocol::qr::{encode_frames, QrDecoder}", ".accept(&payload)", ".progress()"):
        if marker not in watcher_qr:
            errors.append(f"KasSee QR facade must delegate to canonical kassigner-protocol QR state: {marker}")
    for duplicate in (
        "struct DecoderState",
        "fn accept_session",
        "shared_signer::qr_frame::encode_frame",
        "shared_signer::qr_frame::verify_session",
        "shared_signer::qr_frame::session_id",
    ):
        if duplicate in watcher_qr:
            errors.append(f"KasSee must not re-own canonical QR framing/session logic: {duplicate}")
    return errors



def _check_licensing_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    permissive = ("shared-signer", "kassigner-protocol", "kassigner-sdk")
    for crate_name in permissive:
        crate_root = root / "crates" / crate_name / "src"
        for path in crate_root.rglob("*.rs"):
            header = "\n".join(path.read_text(errors="ignore").splitlines()[:14])
            if "License: GPL" in header or "GNU General Public License" in header:
                errors.append(
                    f"permissive SDK source carries a GPL-only source header: {path.relative_to(root)}"
                )

    shared_lib = (root / "crates/shared-signer/src/lib.rs").read_text()
    for retired in ("persistent_credential", "qr_payload"):
        if f"pub mod {retired};" in shared_lib or (root / f"crates/shared-signer/src/{retired}.rs").exists():
            errors.append(f"shared-signer must not retain non-shared/permissive ownership of {retired}")

    qr_payload = root / "crates/kassigner-protocol/src/wire/qr_payload.rs"
    if not qr_payload.is_file():
        errors.append("canonical public raw QR envelope must live in kassigner-protocol::wire::qr_payload")
    else:
        text = qr_payload.read_text(errors="ignore")
        if "MIT OR Apache-2.0" not in text or "moved from" not in text:
            errors.append("QR payload ownership/relicensing provenance must remain explicit")

    credential_meta = root / "crates/offline-signer/src/crypto/credential.rs"
    credential_policy = root / "crates/signer-firmware-core/src/security/credential.rs"
    if not credential_meta.is_file() or "pub enum CredentialKind" not in credential_meta.read_text(errors="ignore"):
        errors.append("encrypted-storage credential metadata must live in offline-signer")
    if not credential_policy.is_file() or "pub fn validate" not in credential_policy.read_text(errors="ignore"):
        errors.append("PIN/password acceptance and retry policy must live in signer-firmware-core")

    contributing = (root / "CONTRIBUTING.md").read_text(errors="ignore")
    for marker in ("shared-signer", "kassigner-protocol", "kassigner-sdk", "MIT OR Apache-2.0", "GPL-3.0-only"):
        if marker not in contributing:
            errors.append(f"contribution licensing policy is missing per-crate marker: {marker}")

    bip32 = (root / "crates/kassigner-protocol/src/account/bip32.rs").read_text(errors="ignore")
    if "intentionally dual-licensed" not in bip32 or "project-owned" not in bip32:
        errors.append("permissive BIP32 provenance must state intentional project-owned relicensing")
    return errors

def _check_wallet_policy_boundary(root: Path) -> list[str]:
    source = (root / "crates/kassigner-sdk/src/lib.rs").read_text()
    forbidden = (
        "pub fn create_transaction", "pub fn prepare_send", "pub fn broadcast",
        "pub fn send_tx", "pub struct CreateTransaction", "pub struct SpendUtxo",
        "available_utxos", "selected_utxos", "fee_policy",
        "pub change_address:", "change_address: &str",
    )
    return [
        f"kassigner-sdk must leave transaction policy to host wallets: {marker}"
        for marker in forbidden if marker in source.lower()
    ]


def _check_crate_inventory(root: Path) -> list[str]:
    expected = {"kassigner-protocol", "kassigner-sdk", "offline-signer", "online-watcher", "shared-signer", "signer-firmware-core"}
    actual = {path.name for path in (root / "crates").iterdir() if path.is_dir()}
    if actual == expected:
        return []
    return [f"crates/ must contain exactly {sorted(expected)}, got {sorted(actual)}"]


def _check_public_release_contract(root: Path) -> list[str]:
    errors: list[str] = []
    manifests = {name: _manifest(root, name) for name in ("shared-signer", "kassigner-protocol", "kassigner-sdk")}
    for name, manifest in manifests.items():
        if manifest.get("package", {}).get("license") != "MIT OR Apache-2.0":
            errors.append(f"{name} must keep the public SDK dependency graph dual MIT/Apache-2.0")
        for license_name in ("LICENSE-MIT", "LICENSE-APACHE"):
            if not (root / "crates" / name / license_name).is_file():
                errors.append(f"{name} is missing {license_name}")
    protocol = manifests["kassigner-protocol"]
    host_features = set(protocol.get("features", {}).get("host", []))
    if any("wasm-bindgen" in feature or "js-sys" in feature for feature in host_features):
        errors.append("kassigner-protocol host feature must not pull WASM-only dependencies")
    if "wasm" not in protocol.get("features", {}):
        errors.append("kassigner-protocol must expose an explicit wasm feature")
    sdk = manifests["kassigner-sdk"]
    if "wasm" not in sdk.get("features", {}):
        errors.append("kassigner-sdk must expose an explicit wasm feature")
    if "wasm-bindgen" in sdk.get("dependencies", {}):
        errors.append("kassigner-sdk native dependencies must not unconditionally include wasm-bindgen")
    linux_wasm_build = (root / "scripts/linux/lib/rust-wasm-sdk.sh").read_text()
    windows_wasm_build = (root / "scripts/windows/lib/rust-wasm-sdk.ps1").read_text()
    if (
        "cargo rustc" not in linux_wasm_build
        or "--crate-type=cdylib" not in linux_wasm_build
        or "-- --crate-type=cdylib" in linux_wasm_build
    ):
        errors.append("Linux SDK WASM packaging must pass cdylib to cargo rustc, not directly to rustc")
    if (
        "'cargo','rustc'" not in windows_wasm_build
        or "'wasm','--crate-type=cdylib'" not in windows_wasm_build
        or "'--','--crate-type=cdylib'" in windows_wasm_build
    ):
        errors.append("Windows SDK WASM packaging must pass cdylib to cargo rustc, not directly to rustc")
    sdk_source = (root / "crates/kassigner-sdk/src/lib.rs").read_text()
    protocol_errors = (root / "crates/kassigner-protocol/src/error/mod.rs").read_text()
    sdk_errors = (root / "crates/kassigner-sdk/src/error/mod.rs").read_text()
    network = (root / "crates/kassigner-protocol/src/network/mod.rs").read_text()
    if "SdkResult<" not in sdk_source or "SdkErrorKind" not in sdk_errors:
        errors.append("kassigner-sdk public API must expose typed stable errors")
    for marker in ("WrongNetwork", "TransactionMismatch", "PairingMismatch", "Qr", "Finalization"):
        if marker not in protocol_errors:
            errors.append(f"kassigner-protocol public error categories are missing {marker}")
    if "#[non_exhaustive]" not in network:
        errors.append("public Network must remain future-extensible without a major version bump")
    kspt_root = root / "crates/offline-signer/src/transaction/kspt"
    if (kspt_root / "codec").exists() or not (kspt_root / "wire_adapter.rs").is_file():
        errors.append("offline-signer must expose a KSPT wire adapter, not a second codec tree")
    return errors
