// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Whatever the camera reads, into a unit with a seed in use, fuzzed
//! (`testkit/mutate.rs`).
//!
//! Each parser has its own target in its crate; this one is the path they
//! sit on. Bytes are handed to the flow as a scan hands them, then read,
//! checked, planned and reviewed, every page turned, and a request that
//! gets that far signed and its reply written. The unit must never panic or
//! halt, and must come back home with the same seed in use, neither wiped
//! nor swapped without a tap.
//!
//! An input's first byte says how it arrived (a payload of frames, a single
//! code, or opaque frames); the rest is what arrived.
//!
//! One unit, seeded once, serves the whole run: in a test build, opening a
//! wallet takes longer than a hundred inputs.

use std::cell::RefCell;

use super::*;

#[path = "../../../../testkit/mutate.rs"]
mod mutate;
#[path = "../../../../testkit/vectors.rs"]
mod vectors;

/// The run's unit, its memory leaked so the flow borrowing it lives as long
/// as the run.
struct Unit {
    flow: Flow<'static, 1>,
    fingerprint: Option<[u8; 4]>,
}

impl Unit {
    fn new() -> Self {
        let memory: &'static mut Memory = Box::leak(Box::new(Memory::new()));
        let flow = seeded(memory);
        let fingerprint = flow.fingerprint();
        Self { flow, fingerprint }
    }
}

thread_local! {
    static UNIT: RefCell<Option<Unit>> = const { RefCell::new(None) };
}

/// How an input arrived: its first byte, and the rest.
fn arrived(data: &[u8]) -> Option<Event<'_>> {
    let (&how, bytes) = data.split_first()?;
    Some(match how % 3 {
        0 => Event::Payload(bytes),
        1 => Event::Code(bytes),
        _ => Event::Opaque(bytes),
    })
}

/// `bytes`, arrived as `how` says.
fn as_arrived(how: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![how];
    out.extend_from_slice(bytes);
    out
}

/// The tick after a step whose work waits for it.
fn tick<const N: usize>(f: &mut Flow<'_, N>) {
    let now_us = f.now_us();
    f.step(Event::Tick { now_us }, &mut Live);
}

/// Every page of the review turned, then CONFIRM, then the reply put up.
fn sign<const N: usize>(f: &mut Flow<'_, N>) {
    let (x, y) = point(RIGHT);
    for _ in 0..64 {
        if f.state() != State::Reviewing {
            break;
        }
        f.step(Event::Press { x, y }, &mut Live);
        f.step(RIGHT, &mut Live);
        tick(f);
    }
    if f.state() != State::Confirming {
        return;
    }
    f.touch(on_confirm(review::Target::Confirm));
    tick(f);
    if f.state() == State::ReplyFormat {
        f.step(reply_card(Card::Wallet), &mut Live);
        if f.state() == State::ReplyMode {
            f.touch(answer(dialog::Target::Cancel));
        }
    }
}

/// Back to the home grid, past any timed screen, by home, back or cancel;
/// whether it got there.
fn home<const N: usize>(f: &mut Flow<'_, N>) -> bool {
    let ways = [home_button(), back_button(), answer(dialog::Target::Cancel)];
    for i in 0..24 {
        if f.state() == State::Home {
            return true;
        }
        let now_us = f.now_us() + ERROR_US;
        f.step(Event::Tick { now_us }, &mut Live);
        if f.state() == State::Home {
            return true;
        }
        f.touch(ways[i % ways.len()]);
    }
    f.state() == State::Home
}

fn scanned(data: &[u8]) {
    let Some(event) = arrived(data) else {
        return;
    };
    UNIT.with(|cell| {
        let mut held = cell.borrow_mut();
        let unit = held.get_or_insert_with(Unit::new);
        let f = &mut unit.flow;
        f.step(scan(), &mut Live);
        assert_eq!(f.state(), State::Scanning, "the scanner from the home grid");
        f.step(event, &mut Live);
        // CHECKING's work is done on the tick after it.
        tick(f);
        if f.state() == State::Reviewing {
            sign(f);
        }
        assert!(
            !matches!(f.state(), State::Halted(_)),
            "a scan that halted the unit: {:?}",
            f.state()
        );
        assert!(
            home(f),
            "a scan the unit did not come back from: {:?}",
            f.state()
        );
        assert_eq!(
            f.fingerprint(),
            unit.fingerprint,
            "a scan that dropped or changed the seed in use"
        );
    });
}

/// The fuzz corpus: requests ours to sign, KSPT and bundle, edges
/// included; another seed's request; a SeedQR, a kpub, a signed message, a
/// card's backup line and seed words.
#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn whatever_the_camera_reads() {
    let spk = p2pk(&x_only(&wallet()));
    let max = kassigner_kaspa::constants::MAX_SOMPI;
    let words: Vec<&str> = (0..mnemonic().len())
        .map(|i| mnemonic().word(i).unwrap())
        .collect();
    // Ours, each a different review: several inputs, as many outputs as
    // pages show and one more, no fee, a spend past its inputs, dust, and
    // the supply's edges, which the parser refuses.
    let outputs = |n: usize, each: u64| vec![(each, &spk[..]); n];
    let tail = [0, 0, 0];
    let mut seeds = vec![
        as_arrived(0, &ours()),
        as_arrived(
            0,
            &request_of(
                VERSION,
                0,
                &tail,
                &outputs(3, 100_000),
                &outputs(1, 250_000),
            ),
        ),
        as_arrived(
            0,
            &request_of(
                VERSION,
                0,
                &tail,
                &outputs(8, 100_000_000),
                &outputs(2, 300_000_000),
            ),
        ),
        as_arrived(0, &request(100_000, &spk, &outputs(19, 1_000))),
        as_arrived(0, &request(100_000, &spk, &outputs(21, 1_000))),
        as_arrived(0, &request(100_000, &spk, &outputs(1, 100_000))),
        as_arrived(0, &request(100_000, &spk, &outputs(1, 100_001))),
        as_arrived(0, &request(600, &spk, &outputs(1, 1))),
        as_arrived(
            0,
            &request_of(
                VERSION,
                0,
                &tail,
                &[(max, &spk), (max, &spk), (1, &spk)],
                &outputs(2, max),
            ),
        ),
        as_arrived(0, &request(u64::MAX, &spk, &outputs(1, u64::MAX))),
        as_arrived(
            0,
            &bundle_request(100_000, &spk, &[(60_000, &spk), (30_000, &spk)]),
        ),
        as_arrived(0, &bundle_request(100_000, &spk, &outputs(1, 99_000))),
        as_arrived(
            0,
            &vectors::files("v110/sdk", &["single.request"]).remove(0),
        ),
        as_arrived(
            0,
            &vectors::files("v107/site", &["kspt_send_1in.bin"]).remove(0),
        ),
        as_arrived(1, &seedqr()),
        as_arrived(
            1,
            vectors::files("v107/cards", &["KP000001.TXT"])
                .remove(0)
                .trim_ascii(),
        ),
        as_arrived(
            1,
            &vectors::files("v110/sdk", &["message.record"]).remove(0),
        ),
        as_arrived(
            1,
            &vectors::files("v110/sdk", &["savings.backup"]).remove(0),
        ),
        as_arrived(2, words.join(" ").as_bytes()),
    ];
    seeds.retain(|s| s.len() > 1);
    mutate::run("scanned", 3000, seeds, scanned);
}
