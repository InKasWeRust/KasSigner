// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::{env, fs, path::Path, process::Command};

fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rustc-link-arg=-u");
    println!("cargo:rustc-link-arg=esp_app_desc");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=release-policy.env");
    println!("cargo:rerun-if-env-changed=KASSIGNER_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=KASSIGNER_WORKFLOW_E2E_FROM");
    emit_build_commit();
    emit_release_policy();
    emit_workflow_resume();
}

fn emit_build_commit() {
    let commit = env::var("KASSIGNER_GIT_COMMIT")
        .ok()
        .filter(|value| valid_commit(value))
        .or_else(git_commit)
        .unwrap_or_else(|| "source-archive".to_owned());
    println!("cargo:rustc-env=KASSIGNER_BUILD_COMMIT={commit}");
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim().to_owned();
    valid_commit(&commit).then_some(commit)
}

fn valid_commit(value: &str) -> bool {
    (7..=40).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}


fn emit_release_policy() {
    let path = Path::new("release-policy.env");
    let source = fs::read_to_string(path).expect("release-policy.env must be readable");
    for key in [
        "KASSIGNER_SECURITY_VERSION",
        "KASSIGNER_ESPTOOL_VERSION",
    ] {
        let value = policy_value(&source, key)
            .unwrap_or_else(|| panic!("release-policy.env missing {key}"));
        if !value.bytes().all(|byte| byte.is_ascii_digit() || (key == "KASSIGNER_ESPTOOL_VERSION" && byte == b'.')) {
            panic!("release-policy.env contains invalid {key}");
        }
        println!("cargo:rustc-env={key}={value}");
    }
}

fn policy_value<'a>(source: &'a str, key: &str) -> Option<&'a str> {
    source.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then_some(value.trim())
    })
}

fn emit_workflow_resume() {
    let value = env::var("KASSIGNER_WORKFLOW_E2E_FROM").unwrap_or_else(|_| "1".to_owned());
    let valid = value.parse::<usize>().is_ok_and(|index| (1..=10).contains(&index));
    if !valid {
        panic!("KASSIGNER_WORKFLOW_E2E_FROM must be an integer from 1 through 10");
    }
    println!("cargo:rustc-env=KASSIGNER_WORKFLOW_E2E_FROM={value}");
}
