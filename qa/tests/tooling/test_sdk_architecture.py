from pathlib import Path
import os
import re
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]


class KasSignerSdkArchitectureTests(unittest.TestCase):
    def test_two_rust_wasm_layers_have_clear_names(self):
        self.assertFalse((ROOT / 'crates/kassigner-wallet').exists())
        for crate in ('kassigner-protocol', 'kassigner-sdk'):
            root = ROOT / 'crates' / crate
            manifest = (root / 'Cargo.toml').read_text()
            self.assertIn('crate-type = ["rlib"]', manifest)
            self.assertTrue((root / 'src/wasm/mod.rs').is_file())
            self.assertEqual([path for path in root.rglob('*.js') if 'pkg' not in path.parts], [])

    def test_no_std_protocol_is_rlib_only_and_owns_no_panic_runtime(self):
        manifest = tomllib.loads((ROOT / 'crates/kassigner-protocol/Cargo.toml').read_text())
        self.assertEqual(manifest['lib']['crate-type'], ['rlib'])
        offline = tomllib.loads((ROOT / 'crates/offline-signer/Cargo.toml').read_text())
        protocol_dep = offline['dependencies']['kassigner-protocol']
        self.assertFalse(protocol_dep['default-features'])
        protocol_lib = (ROOT / 'crates/kassigner-protocol/src/lib.rs').read_text()
        self.assertIn('#![cfg_attr(not(feature = "host"), no_std)]', protocol_lib)
        self.assertNotIn('#[panic_handler]', protocol_lib)

    def test_dependency_direction_points_up_from_protocol(self):
        protocol = tomllib.loads((ROOT / 'crates/kassigner-protocol/Cargo.toml').read_text())
        sdk = tomllib.loads((ROOT / 'crates/kassigner-sdk/Cargo.toml').read_text())
        online = tomllib.loads((ROOT / 'crates/online-watcher/Cargo.toml').read_text())
        self.assertNotIn('online-watcher', protocol['dependencies'])
        self.assertIn('kassigner-protocol', sdk['dependencies'])
        self.assertNotIn('online-watcher', sdk['dependencies'])
        self.assertIn('kassigner-protocol', online['dependencies'])
        self.assertFalse((ROOT / 'crates/online-watcher/src/sdk_support').exists())

    def test_protocol_qr_network_and_privacy_boundaries_are_strict(self):
        qr = (ROOT / 'crates/kassigner-protocol/src/qr/mod.rs').read_text()
        network = (ROOT / 'crates/kassigner-protocol/src/network/mod.rs').read_text()
        pairing = (ROOT / 'crates/kassigner-protocol/src/pairing/mod.rs').read_text()
        self.assertIn('pub payload: Vec<u8>', qr)
        self.assertNotIn('svg:', qr)
        self.assertNotIn('thread_local!', qr)
        self.assertIn('pub struct QrDecoder', qr)
        self.assertIn('pub enum Network', network)
        self.assertIn('unsupported Kaspa network', network)
        self.assertNotIn('_ => "kaspa"', network)
        self.assertIn('nonce_hex', pairing)
        self.assertIn('account_fingerprint', pairing)
        self.assertIn('Vec<DerivedAddress>', pairing)

    def test_friendly_sdk_reexports_protocol_request_and_owns_no_transaction_policy(self):
        source = (ROOT / 'crates/kassigner-sdk/src/lib.rs').read_text()
        self.assertIn('pub use kassigner_protocol', source)
        self.assertNotIn('pub struct SigningRequest', source)
        self.assertIn('pub struct KasSigner', source)
        self.assertIn('decoder: QrDecoder', source)
        for operation in ('pair_normal', 'pair_privacy', 'prepare', 'complete', 'finalize'):
            self.assertRegex(source, rf'pub fn {operation}\b')
        lowered = source.lower()
        for forbidden in (
            'pub fn prepare_send', 'pub fn broadcast', 'pub fn send_tx',
            'available_utxos', 'selected_utxos', 'fee_policy',
            'pub change_address:', 'change_address: &str',
        ):
            self.assertNotIn(forbidden, lowered)

    def test_kassee_reference_consumer_keeps_coin_selection_outside_sdk(self):
        manifest = (ROOT / 'apps/kassee-web/Cargo.toml').read_text()
        self.assertIn('kassigner-sdk = { version = "=2.0.0", path = "../../crates/kassigner-sdk" }', manifest)
        planner = (ROOT / 'apps/kassee-web/web/js/features/transactions/send/compose/planners/standard.js').read_text()
        self.assertIn('create_send_pskb_with_utxos', planner)
        self.assertNotRegex(planner, r'kassigner_(?:sdk|wallet)_.*create_transaction')
        relay = (ROOT / 'apps/kassee-web/web/js/features/transactions/pskt_multisig/review_relay.js').read_text()
        response = (ROOT / 'apps/kassee-web/web/js/features/transactions/send/broadcast.js').read_text()
        self.assertIn('kassigner_sdk_prepare', relay)
        self.assertIn('kassigner_sdk_complete', response)

    def test_generated_package_names_are_wasm_bindgen_artifacts(self):
        protocol_build = (ROOT / 'crates/kassigner-protocol/build.sh').read_text()
        sdk_build = (ROOT / 'crates/kassigner-sdk/build.sh').read_text()
        shared_build = (ROOT / 'scripts/linux/lib/rust-wasm-sdk.sh').read_text()
        self.assertIn('@kassigner/protocol', protocol_build)
        self.assertIn('@kassigner/sdk', sdk_build)
        self.assertIn('wasm-bindgen', shared_build)
        self.assertIn('cargo rustc', shared_build)
        self.assertIn('--crate-type=cdylib', shared_build)
        self.assertNotIn('-- --crate-type=cdylib', shared_build)
        self.assertIn('scripts/linux/lib/cargo_locks.sh', shared_build)
        self.assertIn('kassigner_reconcile_one_host_lock "$ROOT_DIR" "Root workspace" "Cargo.toml" "Cargo.lock"', shared_build)
        windows_build = (ROOT / 'scripts/windows/lib/rust-wasm-sdk.ps1').read_text()
        self.assertIn("'cargo','rustc'", windows_build)
        self.assertIn("'wasm','--crate-type=cdylib'", windows_build)
        self.assertNotIn("'--','--crate-type=cdylib'", windows_build)
        self.assertIn("scripts/windows/lib/cargo_locks.ps1", windows_build)
        self.assertIn("Repair-KasSignerOneHostLock $Root 'Root workspace' 'Cargo.toml' 'Cargo.lock'", windows_build)
        self.assertRegex(shared_build, re.compile(r'package\.json'))


    @unittest.skipUnless(os.name == "posix", "Linux WASM helper execution is POSIX-specific")
    def test_linux_wasm_helper_passes_crate_type_to_cargo_not_rustc(self):
        helper_source = (ROOT / 'scripts/linux/lib/rust-wasm-sdk.sh').read_text()
        toolchains = (ROOT / 'qa/config/toolchains.env').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / 'scripts/linux/lib/rust-wasm-sdk.sh'
            helper.parent.mkdir(parents=True)
            helper.write_text(helper_source)
            helper.chmod(0o755)
            config = root / 'qa/config/toolchains.env'
            config.parent.mkdir(parents=True)
            config.write_text(toolchains)
            for relative in ('scripts/linux/lib/cargo_locks.sh', 'scripts/linux/lib/rustup_bootstrap.sh'):
                source = ROOT / relative
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source.read_text())
            crate = root / 'crates/kassigner-sdk'
            crate.mkdir(parents=True)
            for license_name in ('LICENSE-MIT', 'LICENSE-APACHE'):
                (crate / license_name).write_text(license_name)

            # The production helper deliberately prepends $HOME/.cargo/bin to PATH.
            # Give this regression an isolated HOME and put the fake rustup there so
            # a developer's real ~/.cargo/bin/rustup can never escape the test sandbox.
            fake_home = root / 'home'
            fake_cargo_bin = fake_home / '.cargo/bin'
            fake_cargo_bin.mkdir(parents=True)
            fake_bin = root / 'fake-bin'
            fake_bin.mkdir()
            rustup = fake_cargo_bin / 'rustup'
            rustup.write_text('''#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >> "${FAKE_RUSTUP_LOG}"
if [[ "${1:-}" == target && "${2:-}" == list ]]; then
    printf '%s\n' wasm32-unknown-unknown
    exit 0
fi
if [[ "${1:-}" == run && " $* " == *" cargo metadata "* ]]; then
    exit 0
fi
if [[ "${1:-}" == run ]]; then
    [[ " $* " == *" --crate-type=cdylib "* ]] || exit 41
    [[ " $* " != *" -- --crate-type=cdylib "* ]] || exit 42
    mkdir -p "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release"
    printf wasm > "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/kassigner_sdk.wasm"
    exit 0
fi
exit 43
''')
            rustup.chmod(0o755)

            cache = root / 'tool-cache'
            wasm_bindgen = cache / 'wasm-bindgen-cli-0.2.117/bin/wasm-bindgen'
            wasm_bindgen.parent.mkdir(parents=True)
            wasm_bindgen.write_text('''#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == --version ]]; then
    printf '%s\n' 'wasm-bindgen 0.2.117'
    exit 0
fi
out_dir=''
out_name=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) out_dir="$2"; shift 2 ;;
        --out-name) out_name="$2"; shift 2 ;;
        *) shift ;;
    esac
done
mkdir -p "${out_dir}"
printf js > "${out_dir}/${out_name}.js"
printf dts > "${out_dir}/${out_name}.d.ts"
printf wasm > "${out_dir}/${out_name}_bg.wasm"
printf dts > "${out_dir}/${out_name}_bg.wasm.d.ts"
''')
            wasm_bindgen.chmod(0o755)

            output = root / 'sdk-output/pkg'
            log = root / 'rustup.log'
            env = os.environ.copy()
            env.update({
                'HOME': str(fake_home),
                'PATH': f'{fake_cargo_bin}:{fake_bin}:{env.get("PATH", "")}',
                'KASSIGNER_TOOL_CACHE_DIR': str(cache),
                'FAKE_RUSTUP_LOG': str(log),
            })
            subprocess.run(
                [str(helper), 'kassigner-sdk', 'kassigner_sdk', str(output), 'SDK test', '@kassigner/sdk'],
                check=True,
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            invocation = log.read_text()
            self.assertIn('cargo metadata', invocation)
            self.assertLess(invocation.index('cargo metadata'), invocation.index('cargo rustc'))
            self.assertIn('cargo rustc', invocation)
            self.assertIn('--crate-type=cdylib', invocation)
            self.assertNotIn('-- --crate-type=cdylib', invocation)
            self.assertTrue((output / 'kassigner_sdk_bg.wasm').is_file())

    def test_public_make_sdk_builds_only_standalone_sdk_wasm(self):
        makefile = (ROOT / 'Makefile').read_text()
        helper = (ROOT / 'scripts/common/lib/make_tasks.py').read_text()
        linux = (ROOT / 'scripts/linux/build/sdk-build.sh').read_text()
        windows = (ROOT / 'scripts/windows/build/sdk-build.ps1').read_text()
        help_text = (ROOT / 'scripts/common/lib/make_help.txt').read_text()
        self.assertIn('sdk:', makefile)
        self.assertIn('$(MAKE_TASK) entrypoint sdk-build', makefile)
        self.assertIn('"sdk-build": "build/sdk-build"', helper)
        self.assertIn('crates/kassigner-sdk/build.sh', linux)
        self.assertNotIn('kassigner-protocol/build.sh', linux)
        self.assertIn('crates/kassigner-sdk/build.ps1', windows)
        self.assertIn('make sdk', help_text)
        self.assertIn('target/sdk/kassigner-sdk/pkg', help_text)

    def test_release_docs_and_conformance_vectors_exist(self):
        guide = ROOT / 'docs/integration/WALLET_INTEGRATION.md'
        vectors = ROOT / 'docs/integration/vectors/kassigner_sdk_v2.json'
        self.assertTrue(guide.is_file())
        self.assertTrue(vectors.is_file())
        text = guide.read_text()
        self.assertIn('kassigner-sdk', text)
        self.assertIn('kassigner-protocol', text)
        self.assertIn('coin selection', text.lower())

    def test_security_conformance_and_offline_signer_e2e_are_registered(self):
        sdk_tests = (ROOT / 'crates/kassigner-sdk/src/unit_tests/mod.rs').read_text()
        for contract in (
            'privacy_pairing_replay_is_rejected_after_success',
            'privacy_pairing_rejects_a_different_account_on_later_batch',
            'kas_signer_decoders_are_instance_owned',
        ):
            self.assertIn(contract, sdk_tests)

        integration_mod = (ROOT / 'qa/tests/integration/mod.rs').read_text()
        e2e = (ROOT / 'qa/tests/integration/sdk_round_trip.rs').read_text()
        self.assertIn('mod sdk_round_trip;', integration_mod)
        self.assertIn('offline_signer', e2e)
        for contract in (
            'sdk_round_trip_uses_actual_offline_signer_at_high_derivation_index',
            'sdk_offline_signer_rejects_wrong_derivation_hint',
            'sdk_offline_signer_rejects_right_index_for_wrong_pubkey',
            'sdk_complete_rejects_response_from_different_transaction',
        ):
            self.assertIn(contract, e2e)

        conformance = (ROOT / 'qa/tests/conformance/protocol_vectors.rs').read_text()
        vector_path = ROOT / 'docs/integration/vectors/kassigner_sdk_v2.json'
        self.assertIn('kassigner_privacy_pairing_vector_is_wire_exact', conformance)
        self.assertIn('kassigner_kspt_v4_vector_locks_metadata_order', conformance)
        self.assertTrue(vector_path.is_file())

    def test_distribution_checks_verify_packaged_crates_and_generated_wasm(self):
        linux = (ROOT / 'scripts/linux/build/sdk-distribution-check.sh').read_text()
        windows = (ROOT / 'scripts/windows/build/sdk-distribution-check.ps1').read_text()
        for source in (linux, windows):
            self.assertIn('shared-signer', source)
            self.assertIn('kassigner-protocol', source)
            self.assertIn('kassigner-sdk', source)
            self.assertIn('2.0.0', source)
            self.assertIn('package', source.lower())
            self.assertIn('npm', source.lower())
            self.assertIn('dry-run', source.lower())
        self.assertIn('packaged crates compile as an external consumer graph', linux)
        self.assertIn('packaged crates compile as an external consumer graph', windows)

    def test_public_sdk_errors_networks_features_and_licenses_are_stable(self):
        protocol = tomllib.loads((ROOT / 'crates/kassigner-protocol/Cargo.toml').read_text())
        sdk = tomllib.loads((ROOT / 'crates/kassigner-sdk/Cargo.toml').read_text())
        shared = tomllib.loads((ROOT / 'crates/shared-signer/Cargo.toml').read_text())
        for name, manifest in (('shared-signer', shared), ('kassigner-protocol', protocol), ('kassigner-sdk', sdk)):
            self.assertEqual(manifest['package']['license'], 'MIT OR Apache-2.0', name)
            crate_root = ROOT / 'crates' / name
            self.assertTrue((crate_root / 'LICENSE-MIT').is_file(), name)
            self.assertTrue((crate_root / 'LICENSE-APACHE').is_file(), name)
        self.assertNotIn('wasm-bindgen', protocol['features']['host'])
        self.assertIn('wasm', protocol['features'])
        self.assertIn('wasm', sdk['features'])
        self.assertNotIn('wasm-bindgen', sdk['dependencies'])
        protocol_error = (ROOT / 'crates/kassigner-protocol/src/error/mod.rs').read_text()
        sdk_error = (ROOT / 'crates/kassigner-sdk/src/error/mod.rs').read_text()
        network = (ROOT / 'crates/kassigner-protocol/src/network/mod.rs').read_text()
        for marker in ('WrongNetwork', 'TransactionMismatch', 'PairingMismatch', 'Qr', 'Finalization'):
            self.assertIn(marker, protocol_error)
        for marker in ('PairingReplay', 'RandomnessUnavailable', 'TransactionMismatch'):
            self.assertIn(marker, sdk_error)
        self.assertIn('#[non_exhaustive]', network)

    def test_offline_signer_names_adapter_not_second_codec(self):
        root = ROOT / 'crates/offline-signer/src/transaction/kspt'
        self.assertTrue((root / 'wire_adapter.rs').is_file())
        self.assertTrue((root / 'kssn_io.rs').is_file())
        self.assertFalse((root / 'codec').exists())
        adapter = (root / 'wire_adapter.rs').read_text()
        self.assertIn('kassigner_protocol::wire::kspt', adapter)
        self.assertIn('DecodeLimits::new', adapter)
        self.assertIn('decode_with_limits', adapter)
        self.assertIn('Hardware transaction-model adapter', adapter)
        self.assertIn('use super::{', adapter)
        self.assertNotIn('use super::super::{\n    error::PsktError', adapter)
        self.assertIn('KSSN-only', (root / 'kssn_io.rs').read_text())


if __name__ == '__main__':
    unittest.main()
