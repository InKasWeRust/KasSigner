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

//! The decoder trait, with two fakes: one that decodes inside `submit`, and
//! one that finishes only after a few polls, as the core-1 workers do. One
//! loop must drive both, so no unit-specific choice reaches this crate.

use kassigner_hal::decoder::{Attempt, Decoder, Error, Outcome};

/// Decodes inside `submit`.
struct Synchronous {
    result: Option<(Outcome, Vec<u8>)>,
    payload: Vec<u8>,
    frame_bytes: usize,
}

impl Decoder for Synchronous {
    fn submit(&mut self, frame: &[u8], _attempt: Attempt) -> Result<(), Error> {
        if frame.len() != self.frame_bytes {
            return Err(Error::WrongLength {
                expected: self.frame_bytes,
                got: frame.len(),
            });
        }
        self.result = if self.payload.is_empty() {
            Some((Outcome::NotFound, Vec::new()))
        } else {
            Some((
                Outcome::Found {
                    len: self.payload.len(),
                },
                self.payload.clone(),
            ))
        };
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.result.is_some()
    }

    fn poll(&mut self, out: &mut [u8]) -> Result<Option<Outcome>, Error> {
        let Some((outcome, bytes)) = self.result.take() else {
            return Ok(None);
        };
        if let Outcome::Found { len } = outcome {
            if out.len() < len {
                return Err(Error::WrongLength {
                    expected: len,
                    got: out.len(),
                });
            }
            out[..len].copy_from_slice(&bytes);
        }
        Ok(Some(outcome))
    }

    fn cancel(&mut self) {
        self.result = None;
    }
}

/// Finishes only after several polls, as a core-1 worker does.
struct Asynchronous {
    in_flight: Option<Vec<u8>>,
    polls_needed: u8,
    polls: u8,
    payload: Vec<u8>,
    frame_bytes: usize,
}

impl Decoder for Asynchronous {
    fn submit(&mut self, frame: &[u8], _attempt: Attempt) -> Result<(), Error> {
        if self.in_flight.is_some() {
            return Err(Error::Busy);
        }
        if frame.len() != self.frame_bytes {
            return Err(Error::WrongLength {
                expected: self.frame_bytes,
                got: frame.len(),
            });
        }
        // A real worker copies what it needs into its own job buffer too.
        self.in_flight = Some(frame.to_vec());
        self.polls = 0;
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.in_flight.is_some() && self.polls >= self.polls_needed
    }

    fn poll(&mut self, out: &mut [u8]) -> Result<Option<Outcome>, Error> {
        if self.in_flight.is_none() {
            return Ok(None);
        }
        if self.polls < self.polls_needed {
            self.polls += 1;
            return Ok(None);
        }
        self.in_flight = None;
        if self.payload.is_empty() {
            return Ok(Some(Outcome::NotFound));
        }
        let len = self.payload.len();
        if out.len() < len {
            return Err(Error::WrongLength {
                expected: len,
                got: out.len(),
            });
        }
        out[..len].copy_from_slice(&self.payload);
        Ok(Some(Outcome::Found { len }))
    }

    fn cancel(&mut self) {
        self.in_flight = None;
        self.polls = 0;
    }

    fn is_asynchronous(&self) -> bool {
        true
    }
}

/// One loop drives both: the property the trait exists for.
#[test]
fn one_loop_drives_both_units() {
    fn scan<D: Decoder>(d: &mut D, frame: &[u8]) -> Option<Vec<u8>> {
        d.submit(frame, Attempt::Fast).expect("submit");
        let mut out = vec![0u8; 64];
        for _ in 0..16 {
            match d.poll(&mut out).expect("poll") {
                Some(Outcome::Found { len }) => return Some(out[..len].to_vec()),
                Some(_) => return None,
                None => continue,
            }
        }
        None
    }

    let frame = vec![0u8; 100];
    let payload = b"KSPT payload".to_vec();

    let mut sync = Synchronous {
        result: None,
        payload: payload.clone(),
        frame_bytes: 100,
    };
    let mut async_ = Asynchronous {
        in_flight: None,
        polls_needed: 5,
        polls: 0,
        payload: payload.clone(),
        frame_bytes: 100,
    };

    assert_eq!(scan(&mut sync, &frame), Some(payload.clone()));
    assert_eq!(scan(&mut async_, &frame), Some(payload));
}

/// A synchronous decoder is ready the moment `submit` returns.
#[test]
fn a_synchronous_decoder_is_ready_at_once() {
    let mut d = Synchronous {
        result: None,
        payload: b"x".to_vec(),
        frame_bytes: 4,
    };
    assert!(!d.is_asynchronous());
    assert!(!d.is_ready());

    d.submit(&[0u8; 4], Attempt::Fast).expect("submit");
    assert!(d.is_ready(), "no waiting");
}

/// Submitting while busy is refused as `Busy`, its own variant, so a caller
/// polls rather than retries or drops the frame.
#[test]
fn submitting_while_busy_says_so() {
    let mut d = Asynchronous {
        in_flight: None,
        polls_needed: 3,
        polls: 0,
        payload: b"y".to_vec(),
        frame_bytes: 4,
    };

    d.submit(&[0u8; 4], Attempt::Fast).expect("first");
    assert_eq!(d.submit(&[0u8; 4], Attempt::Fast).err(), Some(Error::Busy));

    // Polling to completion frees it.
    let mut out = [0u8; 8];
    while d.poll(&mut out).expect("poll").is_none() {}
    assert!(d.submit(&[0u8; 4], Attempt::Fast).is_ok());
}

/// Cancelling throws away a result in flight: one arriving after the
/// scanner is left would act on a code no longer aimed at.
#[test]
fn cancelling_discards_what_is_in_flight() {
    let mut d = Asynchronous {
        in_flight: None,
        polls_needed: 2,
        polls: 0,
        payload: b"stale".to_vec(),
        frame_bytes: 4,
    };

    d.submit(&[0u8; 4], Attempt::Fast).expect("submit");
    d.cancel();

    assert!(!d.is_ready());
    let mut out = [0u8; 8];
    assert_eq!(
        d.poll(&mut out).expect("poll"),
        None,
        "nothing arrives later"
    );

    // And the decoder is usable again.
    assert!(d.submit(&[0u8; 4], Attempt::Fast).is_ok());
}

/// Nothing found is an outcome, not an error.
#[test]
fn nothing_found_is_not_a_failure() {
    let mut d = Synchronous {
        result: None,
        payload: Vec::new(),
        frame_bytes: 4,
    };
    d.submit(&[0u8; 4], Attempt::Fast).expect("submit");

    let mut out = [0u8; 8];
    assert_eq!(d.poll(&mut out).expect("poll"), Some(Outcome::NotFound));
}

/// A found code that will not fit is reported rather than truncated.
#[test]
fn a_result_too_large_for_the_buffer_is_reported() {
    let mut d = Synchronous {
        result: None,
        payload: vec![0xAAu8; 40],
        frame_bytes: 4,
    };
    d.submit(&[0u8; 4], Attempt::Fast).expect("submit");

    let mut small = [0u8; 8];
    assert_eq!(
        d.poll(&mut small).err(),
        Some(Error::WrongLength {
            expected: 40,
            got: 8
        })
    );
}

/// A frame of the wrong size is refused.
#[test]
fn a_wrong_sized_frame_is_refused() {
    let mut d = Synchronous {
        result: None,
        payload: b"z".to_vec(),
        frame_bytes: 100,
    };
    assert_eq!(
        d.submit(&[0u8; 99], Attempt::Fast).err(),
        Some(Error::WrongLength {
            expected: 100,
            got: 99
        })
    );
}

/// The two attempts are distinct: `Thorough` follows a `Fast` that missed.
/// What each means is the unit's; on the S3 units `Thorough` is one pass at
/// the other binarisation window.
#[test]
fn attempts_are_an_escalation_not_a_setting() {
    assert_ne!(Attempt::Fast, Attempt::Thorough);

    let mut d = Synchronous {
        result: None,
        payload: b"q".to_vec(),
        frame_bytes: 4,
    };
    d.submit(&[0u8; 4], Attempt::Fast).expect("fast");
    let mut out = [0u8; 8];
    d.poll(&mut out).expect("poll");

    d.submit(&[0u8; 4], Attempt::Thorough).expect("thorough");
    assert!(d.is_ready());
}
