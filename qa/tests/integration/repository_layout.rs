use crate::common::workspace_root;

#[test]
fn workspaces_and_qa_layout_are_present() {
    let root = workspace_root();
    for relative in [
        "Cargo.lock",
        "apps/signer-firmware/Cargo.lock",
        "apps/signer-firmware/rust-toolchain.toml",
        "apps/kassee-web/Cargo.lock",
        "external/rqrr-nostd/Cargo.lock",
        "tools/Cargo.lock",
        "qa/Cargo.lock",
        "qa/tests/common",
        "qa/tests/conformance",
        "qa/tests/integration",
        "qa/tests/fixtures",
        "qa/benches",
        "qa/config/toolchains.env",
        "qa/fuzz/Cargo.toml",
        "qa/fuzz/unwrap_qr_payload.rs",
    ] {
        assert!(root.join(relative).exists(), "missing {relative}");
    }

    assert!(
        !root.join("qa/fuzz/rust-toolchain.toml").exists(),
        "qa/fuzz/rust-toolchain.toml must not duplicate the central nightly pin",
    );
}

#[test]
fn only_the_two_business_facades_exist() {
    let root = workspace_root();
    let expected = [
        root.join("crates/offline-signer/src/facade.rs"),
        root.join("crates/online-watcher/src/facade.rs"),
    ];

    for facade in expected {
        assert!(facade.is_file(), "missing {}", facade.display());
    }
}

#[test]
fn removed_wrapper_layers_do_not_return() {
    let root = workspace_root();
    for relative in ["src", "tests", "benches", "fuzz", "platforms", "vendor", "hardware"] {
        assert!(!root.join(relative).exists(), "unexpected top-level {relative}");
    }
}
