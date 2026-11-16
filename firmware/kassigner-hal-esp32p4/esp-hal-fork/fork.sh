#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# Makes the esp-hal fork for the ESP32-P4 units (rev1.3 silicon, ROM ECO2),
# which upstream esp-hal refuses (`min-chip-revision` 300) and mis-serves in
# five places. Fetches the six crates the root `[patch.crates-io]` names,
# refuses any whose SHA-256 differs from the crates.io index's, unpacks them
# here, applies `eco2-fix.patch` and two I2S `sed` edits, and checks every
# fix. The checksums make the gitignored folders the same on every machine,
# as the lock file does for other crates.
#
# Run it once after a clone, before any cargo command (the Docker build
# does): the patch table covers the whole workspace, so nothing resolves
# until then. A rerun rebuilds the folders from scratch.
#
#   sh firmware/kassigner-hal-esp32p4/esp-hal-fork/fork.sh
#
# The five fixes:
#   esp-sync/src/raw.rs                   `csrrw 0x347` (mintthresh) traps on
#                                         ECO2: skipped, and its restore too
#   esp-rom-sys/ld/esp32p4/rom-functions.x  the ECO5 ROM tables are wrong on
#                                         ECO2: the jump table is swapped for
#                                         esp32p4.rom.ld, and libgcc/rvfp
#                                         dropped for software (u64/u64
#                                         returned `sum - count`)
#   esp-hal/ld/esp32p4/memory.x           the top 128 KB of L2MEM is unbacked
#                                         on ECO2: ceiling 0x4FFA0000, and
#                                         `dram2_seg`, wholly inside it, given
#                                         no length
#   esp-hal/src/i2s/hp_sys_clkrst.rs      I2S clock source XTAL, as ESP-IDF
#                                         below rev 3.0; the default is a pin
#                                         nobody wired (first `sed`)
#   esp-hal/src/soc/esp32p4/mod.rs        I2S dividers from XTAL's 40 MHz,
#                                         not PLL_F160M's (second `sed`)
#   esp-hal/src/soc/esp32p4/clocks.rs     a 360 MHz preset (CPLL 360, APB 90)
#   esp-hal/src/clock/mod.rs              as ESP-IDF sets below rev 3.0, and
#                                         `max()` returns it: v3's 400 runs
#                                         past ECO2's rating
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PATCH="$HERE/eco2-fix.patch"

# name version sha256, the checksums from the crates.io index.
CRATES='
esp-hal                1.2.2  c9e3dfd511fed638fe41fdb4595f8c7f0cbb488d0f0cf2bbc063d76d805057cf
esp-rom-sys            0.1.5  e933ff78374b763b65998b64ad671b4890ed4ba13a80deff9f53afe95ede289d
esp-config             0.8.0  fcd577a122ec917691f6820a3df54388ecebc750f071b060f5e83707bc415512
esp-sync               0.3.0  064fd57eed12b5cbb669b3935e1f647fd6945b89938116d61153fb45fd703422
esp-metadata-generated 0.5.2  302e17a70ea13688fc2aba60b9c4a42855aff6ca53e77dd76570e144b90a07f5
esp-riscv-rt           0.15.0 626c6b1477224c46fb27919d53ac5bf4ef6f7f70344ee26a720373761aaef531
'

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "$CRATES" | while read -r name version want; do
    [ -n "$name" ] || continue
    file="$TMP/$name-$version.crate"
    curl -sfL "https://static.crates.io/crates/$name/$name-$version.crate" -o "$file"
    got="$(sha256 "$file")"
    if [ "$got" != "$want" ]; then
        echo "fork.sh: $name $version: sha256 $got, crates.io says $want" >&2
        exit 1
    fi
    rm -rf "${HERE:?}/$name"
    mkdir -p "$HERE/$name"
    tar xzf "$file" --strip-components=1 -C "$HERE/$name"
    echo "  $name $version: checksum matches crates.io, unpacked"
done

# The hunks are written against the published crates: `a/esp-hal/...`.
patch -s -p1 -d "$HERE" < "$PATCH"
rm -f "$HERE/esp-sync/src/raw.rs.orig" \
      "$HERE/esp-rom-sys/ld/esp32p4/rom-functions.x.orig" \
      "$HERE/esp-hal/ld/esp32p4/memory.x.orig" \
      "$HERE/esp-hal/src/soc/esp32p4/clocks.rs.orig" \
      "$HERE/esp-hal/src/clock/mod.rs.orig"

# A `sed`, not a hunk, so it is identical on every host and its count can be
# checked: two lines, TX and RX.
I2S_FILE="esp-hal/src/i2s/hp_sys_clkrst.rs"
I2S_FROM='let clock_source = property!("i2s.default_clock_source");'
I2S_TO='let clock_source = 0u8; // KASSIGNER ECO2: XTAL. esp-hal picks 2 (EXTERNAL); PLL_160M is rev3+ only.'
sed -i.bak "s|$I2S_FROM|$I2S_TO|" "$HERE/$I2S_FILE"
rm -f "$HERE/$I2S_FILE.bak"

# The I2S dividers, from XTAL's 40 MHz: computed from PLL_F160M's 160 MHz, as
# esp-hal assumes, every rate is a quarter of the one asked (48 kHz runs at
# 12 kHz).
SCLK_FILE="esp-hal/src/soc/esp32p4/mod.rs"
SCLK_FROM='    clocks::pll_f160m_frequency()'
SCLK_TO='    40_000_000 // KASSIGNER ECO2: I2S runs on XTAL, see i2s/hp_sys_clkrst.rs'
sed -i.bak "s|$SCLK_FROM|$SCLK_TO|" "$HERE/$SCLK_FILE"
rm -f "$HERE/$SCLK_FILE.bak"

check() {
    n=$(grep -c "$2" "$HERE/$1" || true)
    if [ "$n" -lt "$3" ]; then
        echo "fork.sh: $1: expected at least $3 of '$2', found $n" >&2
        exit 1
    fi
}
check esp-sync/src/raw.rs                    skip_mintthresh             3
check esp-rom-sys/ld/esp32p4/rom-functions.x "KASSIGNER ECO2 FIX"        2
# The table by name: the check above passes with the note in place and the
# wrong table still linked.
check esp-rom-sys/ld/esp32p4/rom-functions.x 'INCLUDE "rom/esp32p4.rom.ld"'  1
check esp-hal/ld/esp32p4/memory.x            "KASSIGNER ECO2 FIX"        2
check "$I2S_FILE"                            "KASSIGNER ECO2: XTAL"      2
check "$SCLK_FILE"                           "I2S runs on XTAL"          1
check esp-hal/src/soc/esp32p4/clocks.rs      "KASSIGNER ECO2"            2
check esp-hal/src/clock/mod.rs               "KASSIGNER ECO2"            1
if find "$HERE" -name '*.rej' | grep -q .; then
    echo "fork.sh: a hunk was rejected" >&2
    exit 1
fi

echo "fork ready in $HERE: six crates from crates.io, five fixes in place"
