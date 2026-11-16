# rqrr, as forked for KasSigner

A fork of **rqrr 0.10.1**, a QR code finder and decoder, used by
`kassigner-qr`. Not this project's code: it keeps upstream's licences and
stays outside the workspace.

## Where it came from

- The crate `rqrr` 0.10.1 from crates.io; upstream's repository is
  <https://github.com/WanzenBug/rqrr>.
- SHA-256 of the `.crate` file, as the crates.io index records it:
  `ffbe87d9e8db95652c25ded2418150e00b08c2fde09e23ec15896d2c470c6631`.
- Licence, unchanged: `(MIT OR Apache-2.0) AND ISC`. `LICENSE-MIT`,
  `LICENSE-APACHE` and `LICENSE-ISC` are upstream's files, byte for byte; the
  ISC licence is that of quirc, the C library rqrr ports, as upstream ships
  it.
- Only the version is renamed: `0.10.1-nostd`.

## Seeing the whole difference

For the exact difference in `src`, run this from an empty directory outside
this repository, with `KASSIGNER` set to the repository's path (`~/.cargo`
is `$CARGO_HOME` where that is set):

```
cargo init --lib --name rqrr_upstream
cargo add rqrr@=0.10.1 --no-default-features
cargo fetch
diff -ru ~/.cargo/registry/src/*/rqrr-0.10.1/src "$KASSIGNER/vendor/rqrr/src"
```

Comments starting `KASSIGNER:` mark several changes in the source; the rest
are described where they are made.

## What changed, by file

Unchanged: `src/version_db.rs`, `src/identify/mod.rs`, the licences. Not
carried: upstream's `README.md`, its test images (`src/test_data`) and its
tests, except those in `src/geometry.rs`.

- **`Cargo.toml`**: `g2p`, `lru` and the `img` feature's `image` are gone;
  `zeroize` 1.9.0 is the one dependency.
- **`Cargo.lock`**: regenerated for the one dependency, `zeroize` 1.9.0.
- **`src/lib.rs`**: `no_std` with `alloc`, `unsafe` forbidden; a small
  `Write` trait for `std::io::Write`; no `std::error::Error` or
  `FromUtf8Error` conversions, no `img` example or `write_grid_to`.
  `decode`, `decode_to` and `get_raw_data` work in buffers the caller lends
  (`Scratch`, a `MAX_PAYLOAD_SIZE` array). Four clippy `allow`s, explained
  where set.
- **`src/galois.rs`** (new): GF(2^8) and GF(2^4) arithmetic with upstream's
  moduli (`0x11D` and `0x13`), replacing the `g2p` crate.
- **`src/decode.rs`**: works in the lent buffers and leaves them wiped, as
  one code it reads is a SeedQR.
- **`src/prepare.rs`**: a fixed-size LRU of upstream's 251 entries for the
  `lru` crate; `BorrowedImageBuffer`, an image over the caller's pixels; a
  `denom` for the threshold window, rounded to a power of two so the
  binarizer shifts instead of dividing (its thresholds differ slightly from
  upstream's), with a contiguous-row path bit for bit the generic one and
  its row accumulator in the caller's `Scratch`; the first plausible
  capstone group taken unvalidated; a new region's flood fill capped at
  5,000 pixels.
- **`src/detect.rs`**: at most `MAX_CAPSTONES` (256) finder patterns a frame;
  finder runs checked without rounding.
- **`src/geometry.rs`**: `f32` for upstream's `f64`; a point is rounded
  without upstream's range asserts.
- **`src/identify/grid.rs`**: `f32`; a grid outside 21 to 69 modules a side
  (versions 1 to 13) is refused; two upstream panics, an `expect` turning a
  capstone and an assert on the timing pattern, are refusals; the
  alignment-pattern search has its arithmetic, its band and its reach
  bounded. Tests of its own.
- **`src/identify/match_capstones.rs`**: `f32`; each finder pattern's list
  of neighbours bounded to 32, the closest kept. Tests of its own.
- **`rust-toolchain.toml`** (new): pins this crate's clippy to 1.85.0, and
  says why.

A panic here wipes and halts the device: where upstream asserts on what a
frame can contain, this fork refuses the frame.
