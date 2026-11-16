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

//! The tables in `src/ui/gen/`, made from `assets/`.
//!
//! ```text
//! UI_REGENERATE=1 cargo +esp195 test -p kassigner-fw --test ui_assets
//! ```
//!
//! writes them; without it the test fails if the committed tables differ
//! from what `assets/` makes, catching a hand edit or a stale table.
//!
//! Fonts are rasterised by `fontdue` with its SIMD paths off, and icons
//! (Iconoir's regular SVGs) sampled eight by eight a pixel against their
//! flattened strokes with plain arithmetic, so every machine makes the same
//! bytes. Coverage is four bits. Iconoir's caps and joins are round, so a
//! point is inside within half the stroke width of the path. `floppy-disk`
//! and `apple-wallet` name no caps or joins, which in SVG means square ones,
//! and are drawn round too: floppy-disk's two sharp corners differ by under
//! a quarter of a pixel's coverage at these sizes, and apple-wallet's line
//! ends lie hidden in its frame's stroke. A path command Iconoir does not
//! use fails the test.
//!
//! The logo's table keeps, from a 320 by 240 frame almost all black, the
//! smallest rectangle holding every pixel that is not black, and where it
//! sat.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Every font the UI draws with: static name, TTF, size in pixels. Four
/// for a 320 by 240 panel, the same at four thirds for 480 by 320, then the
/// keyboard's Lato 22 and a large word's Rubik Bold 26 at both.
///
/// `Rubik-Bold.ttf` is Google Fonts' variable Rubik (`ofl/rubik`, OFL)
/// instanced at weight 700: `fonttools varLib.instancer 'Rubik[wght].ttf'
/// wght=700`.
const FONTS: &[(&str, &str, f32)] = &[
    ("LATO_12", "Lato-Regular.ttf", 12.0),
    ("LATO_15", "Lato-Regular.ttf", 15.0),
    ("LATO_BOLD_18", "Lato-Bold.ttf", 18.0),
    ("OSWALD_BOLD_22", "Oswald-Bold.ttf", 22.0),
    ("LATO_16", "Lato-Regular.ttf", 16.0),
    ("LATO_20", "Lato-Regular.ttf", 20.0),
    ("LATO_BOLD_24", "Lato-Bold.ttf", 24.0),
    ("OSWALD_BOLD_29", "Oswald-Bold.ttf", 29.0),
    ("LATO_22", "Lato-Regular.ttf", 22.0),
    ("LATO_29", "Lato-Regular.ttf", 29.0),
    ("RUBIK_BOLD_26", "Rubik-Bold.ttf", 26.0),
    ("RUBIK_BOLD_35", "Rubik-Bold.ttf", 35.0),
];

/// Every icon: its file in `assets/icons/` and its `Icon` variant.
const ICONS: &[(&str, &str)] = &[
    ("add-folder", "AddFolder"),
    ("apple-wallet", "AppleWallet"),
    ("arrow-left", "ArrowLeft"),
    ("arrow-right", "ArrowRight"),
    ("camera", "Camera"),
    ("coin", "Coin"),
    ("edit-pencil", "EditPencil"),
    ("eye-empty", "EyeEmpty"),
    ("eye-off", "EyeOff"),
    ("fingerprint", "Fingerprint"),
    ("download", "Download"),
    ("floppy-disk", "FloppyDisk"),
    ("git-fork", "GitFork"),
    ("group", "Group"),
    ("help-circle", "HelpCircle"),
    ("laptop", "Laptop"),
    ("leaf", "Leaf"),
    ("lock", "Lock"),
    ("numbered-list-right", "NumberedListRight"),
    ("open-new-window", "OpenNewWindow"),
    ("page", "Page"),
    ("password-cursor", "PasswordCursor"),
    ("qr-code", "QrCode"),
    ("shield-check", "ShieldCheck"),
    ("sound-high", "SoundHigh"),
    ("upload", "Upload"),
    ("upload-square", "UploadSquare"),
];

/// Icon sizes in pixels: Iconoir's own 24 for a 320 by 240 panel, four
/// thirds of it for a 480 by 320 one.
const ICON_SIDES: &[usize] = &[24, 32];

/// The licence block every source file in the tree starts with.
const HEADER: &str = "\
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
";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// One font: its declaration for `mod.rs` and its bitmap file.
fn font(&(name, ttf, px): &(&str, &str, f32)) -> (String, (String, Vec<u8>)) {
    let path = root().join("assets/fonts").join(ttf);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let settings = fontdue::FontSettings {
        scale: px,
        ..Default::default()
    };
    let face = fontdue::Font::from_bytes(data, settings).expect("a TTF fontdue reads");

    let mut bits = Vec::new();
    let mut rows = String::new();
    let (mut ascent, mut descent) = (0i32, 0i32);
    for byte in 0x20u8..=0x7E {
        let (m, cover) = face.rasterize(char::from(byte), px);
        let (w, h) = (m.width, m.height);
        let top = m.ymin + h as i32;
        ascent = ascent.max(top);
        descent = descent.max(-m.ymin);
        let advance = m.advance_width.round() as i32;
        let offset = bits.len();
        for row in cover.chunks(w.max(1)).take(h) {
            for pair in row.chunks(2) {
                let level = |v: u8| ((u32::from(v) * 15 + 127) / 255) as u8;
                let hi = level(pair[0]);
                let lo = pair.get(1).map_or(0, |&v| level(v));
                bits.push((hi << 4) | lo);
            }
        }
        let fits =
            |v: i32, lo: i32, hi: i32| assert!((lo..=hi).contains(&v), "{name} {byte:#x}: {v}");
        fits(advance, 0, 255);
        fits(m.xmin, -128, 127);
        fits(top, -128, 127);
        fits(w as i32, 0, 255);
        fits(h as i32, 0, 255);
        writeln!(
            rows,
            "        Glyph::new({advance}, {}, {top}, {w}, {h}, {offset}),",
            m.xmin
        )
        .unwrap();
    }

    let file = format!("{}.bin", name.to_lowercase());
    let decl = format!(
        "/// {ttf} at {px} pixels.\n\
         pub static {name}: Font = Font {{\n    \
         ascent: {ascent},\n    \
         descent: {descent},\n    \
         glyphs: &[\n{rows}    ],\n    \
         bits: include_bytes!(\"{file}\"),\n}};\n",
        ttf = ttf.trim_end_matches(".ttf"),
    );
    (decl, (file, bits))
}

/// The logo, cut out of its frame.
fn logo() -> (String, (String, Vec<u8>)) {
    const W: usize = 320;
    const H: usize = 240;
    let path = root().join("assets/images/logo_320x240.raw");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(raw.len(), W * H * 2, "a 320 by 240 RGB565 frame");
    let px =
        |x: usize, y: usize| u16::from_le_bytes([raw[(y * W + x) * 2], raw[(y * W + x) * 2 + 1]]);

    let (mut x0, mut y0, mut x1, mut y1) = (W, H, 0, 0);
    for y in 0..H {
        for x in 0..W {
            if px(x, y) != 0 {
                (x0, y0) = (x0.min(x), y0.min(y));
                (x1, y1) = (x1.max(x + 1), y1.max(y + 1));
            }
        }
    }
    assert!(x0 < x1 && y0 < y1, "the logo frame is all black");

    let mut bits = Vec::with_capacity((x1 - x0) * (y1 - y0) * 2);
    for y in y0..y1 {
        for x in x0..x1 {
            bits.extend_from_slice(&px(x, y).to_le_bytes());
        }
    }
    let decl = format!(
        "/// The KasSigner logo, cut from `logo_320x240.raw`.\n\
         pub static LOGO: Image = Image::new({w}, {h}, include_bytes!(\"logo.bin\"));\n\
         \n\
         /// Where [`LOGO`] sat in its 320 by 240 frame.\n\
         pub const LOGO_AT: (u16, u16) = ({x0}, {y0});\n",
        w = x1 - x0,
        h = y1 - y0,
    );
    (decl, ("logo.bin".into(), bits))
}

/// Pictures drawn as they are, full colour: the static's name, its file in
/// `assets/images/`, its width and height. The keyboard's delete and shift
/// keys.
const IMAGES: &[(&str, &str, usize, usize)] = &[
    ("KEY_DELETE", "icon_del_28x20.raw", 28, 20),
    ("KEY_SHIFT", "icon_shift_24x24.raw", 24, 24),
];

/// A picture from `assets/images/`, RGB565, whole: included from there, so
/// `src/ui/gen/` keeps no copy.
fn image(&(name, file, w, h): &(&str, &str, usize, usize)) -> String {
    let path = root().join("assets/images").join(file);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(raw.len(), w * h * 2, "{file}: a {w} by {h} RGB565 picture");
    format!(
        "/// `{file}`, as it is.\n\
         pub static {name}: Image = Image::new(\n    \
         {w},\n    \
         {h},\n    \
         include_bytes!(\"../../../assets/images/{file}\"),\n\
         );\n"
    )
}

/// A segment, `[x0, y0, x1, y1]`, in the icon's 24-unit box.
type Segment = [f64; 4];

/// The value of an attribute in a tag, if it has it.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let at = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    tag[at..].split('"').next()
}

/// The numbers in a path's data, and its commands, in order.
enum Token {
    Command(char),
    Number(f64),
}

fn tokens(d: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let b = d.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if c.is_ascii_alphabetic() && c != 'e' && c != 'E' {
            out.push(Token::Command(c));
            i += 1;
        } else if c == '-' || c == '+' || c == '.' || c.is_ascii_digit() {
            // A number: a sign, digits, one point, an exponent. A second
            // point starts the next number, as SVG allows.
            let start = i;
            i += 1;
            let mut point = c == '.';
            while i < b.len() {
                let c = b[i] as char;
                if c.is_ascii_digit() {
                    i += 1;
                } else if c == '.' && !point {
                    point = true;
                    i += 1;
                } else if (c == 'e' || c == 'E') && i + 1 < b.len() {
                    i += 1;
                    if b[i] == b'-' || b[i] == b'+' {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            let n = d[start..i]
                .parse()
                .unwrap_or_else(|e| panic!("{:?}: {e}", &d[start..i]));
            out.push(Token::Number(n));
        } else {
            i += 1;
        }
    }
    out
}

/// A path's data as segments: `M`, `L`, `H`, `V`, `C` and `Z`, absolute or
/// relative, the curves cut into sixteen.
fn path(d: &str, out: &mut Vec<Segment>) {
    let toks = tokens(d);
    let mut i = 0;
    let (mut x, mut y, mut sx, mut sy) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let mut cmd = ' ';
    let take = |i: &mut usize| match toks.get(*i) {
        Some(Token::Number(n)) => {
            *i += 1;
            *n
        }
        _ => panic!("a number was expected in {d:?}"),
    };
    while i < toks.len() {
        if let Token::Command(c) = toks[i] {
            cmd = c;
            i += 1;
        }
        let rel = cmd.is_ascii_lowercase();
        let (ox, oy) = if rel { (x, y) } else { (0.0, 0.0) };
        match cmd.to_ascii_uppercase() {
            'M' => {
                (x, y) = (ox + take(&mut i), oy + take(&mut i));
                (sx, sy) = (x, y);
                // Pairs after a move are lines.
                cmd = if rel { 'l' } else { 'L' };
            }
            'L' => {
                let (nx, ny) = (ox + take(&mut i), oy + take(&mut i));
                out.push([x, y, nx, ny]);
                (x, y) = (nx, ny);
            }
            'H' => {
                let nx = ox + take(&mut i);
                out.push([x, y, nx, y]);
                x = nx;
            }
            'V' => {
                let ny = oy + take(&mut i);
                out.push([x, y, x, ny]);
                y = ny;
            }
            'C' => {
                let (x1, y1) = (ox + take(&mut i), oy + take(&mut i));
                let (x2, y2) = (ox + take(&mut i), oy + take(&mut i));
                let (x3, y3) = (ox + take(&mut i), oy + take(&mut i));
                let (mut px, mut py) = (x, y);
                for k in 1..=16 {
                    let t = f64::from(k) / 16.0;
                    let u = 1.0 - t;
                    let (a, b, c, e) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
                    let nx = a * x + b * x1 + c * x2 + e * x3;
                    let ny = a * y + b * y1 + c * y2 + e * y3;
                    out.push([px, py, nx, ny]);
                    (px, py) = (nx, ny);
                }
                (x, y) = (x3, y3);
            }
            'Z' => {
                out.push([x, y, sx, sy]);
                (x, y) = (sx, sy);
                if matches!(toks.get(i), Some(Token::Number(_))) {
                    panic!("numbers after Z in {d:?}");
                }
            }
            other => panic!("path command {other:?} is not drawn: {d:?}"),
        }
    }
}

/// An icon's strokes: half the stroke width, and its segments.
fn strokes(name: &str) -> (f64, Vec<Segment>) {
    let file = root().join("assets/icons").join(format!("{name}.svg"));
    let svg = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let root_tag = svg.split('>').next().unwrap_or_default();
    assert_eq!(attribute(root_tag, "viewBox"), Some("0 0 24 24"), "{name}");
    assert_eq!(attribute(root_tag, "fill"), Some("none"), "{name}");
    let width: f64 = attribute(root_tag, "stroke-width")
        .expect("a stroke width")
        .parse()
        .unwrap();
    let mut segments = Vec::new();
    for tag in svg.split('<').filter(|t| t.starts_with("path ")) {
        // Strokes, not fills, at the icon's one width: what the sampling
        // below draws.
        assert!(attribute(tag, "fill").is_none(), "{name}: a filled path");
        if let Some(w) = attribute(tag, "stroke-width") {
            assert_eq!(w.parse::<f64>().ok(), Some(width), "{name}: a second width");
        }
        // Round ends and corners, or none named (drawn round anyway: see the
        // module doc).
        for a in ["stroke-linecap", "stroke-linejoin"] {
            let v = attribute(tag, a);
            assert!(v.is_none() || v == Some("round"), "{name}: {a} {v:?}");
        }
        path(attribute(tag, "d").expect("path data"), &mut segments);
    }
    assert!(!segments.is_empty(), "{name}: no paths");
    (width / 2.0, segments)
}

/// Whether a point is within `half` of a segment, compared squared.
fn near(px: f64, py: f64, s: &Segment, half: f64) -> bool {
    let (dx, dy) = (s[2] - s[0], s[3] - s[1]);
    let len = dx * dx + dy * dy;
    let t = if len == 0.0 {
        0.0
    } else {
        (((px - s[0]) * dx + (py - s[1]) * dy) / len).clamp(0.0, 1.0)
    };
    let (ex, ey) = (s[0] + t * dx - px, s[1] + t * dy - py);
    ex * ex + ey * ey <= half * half
}

/// An icon as a `side` by `side` mask, four bits a pixel, packed as fonts
/// are.
fn icon_mask(half: f64, segments: &[Segment], side: usize, bits: &mut Vec<u8>) {
    let unit = 24.0 / side as f64;
    let mut row = vec![0u8; side];
    for py in 0..side {
        for (px, level) in row.iter_mut().enumerate() {
            // Only the segments whose box, grown by the stroke, meets this
            // pixel's.
            let (x0, y0) = (px as f64 * unit, py as f64 * unit);
            let (x1, y1) = (x0 + unit, y0 + unit);
            let close: Vec<&Segment> = segments
                .iter()
                .filter(|s| {
                    s[0].min(s[2]) - half <= x1
                        && s[0].max(s[2]) + half >= x0
                        && s[1].min(s[3]) - half <= y1
                        && s[1].max(s[3]) + half >= y0
                })
                .collect();
            let mut inside = 0u32;
            for sy in 0..8 {
                for sx in 0..8 {
                    let x = x0 + (f64::from(sx) + 0.5) * unit / 8.0;
                    let y = y0 + (f64::from(sy) + 0.5) * unit / 8.0;
                    if close.iter().any(|s| near(x, y, s, half)) {
                        inside += 1;
                    }
                }
            }
            *level = ((inside * 15 + 32) / 64) as u8;
        }
        for pair in row.chunks(2) {
            bits.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
        }
    }
}

/// The icons: the `Icon` enum, and a sheet per size.
fn icons() -> (String, Vec<(String, Vec<u8>)>) {
    let mut decl = String::from(
        "/// An icon, from Iconoir's regular set, named for its file in\n\
         /// `assets/icons/`.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
         pub enum Icon {\n",
    );
    for (_, variant) in ICONS {
        writeln!(decl, "    {variant},").unwrap();
    }
    decl.push_str("}\n");
    let shapes: Vec<_> = ICONS.iter().map(|(file, _)| strokes(file)).collect();
    let mut files = Vec::new();
    for &side in ICON_SIDES {
        let mut bits = Vec::new();
        for (half, segments) in &shapes {
            icon_mask(*half, segments, side, &mut bits);
        }
        let file = format!("icons_{side}.bin");
        write!(
            decl,
            "\n/// Every [`Icon`] at {side} pixels.\n\
             pub static ICONS_{side}: Sheet = Sheet::new({side}, {count}, include_bytes!(\"{file}\"));\n",
            count = ICONS.len(),
        )
        .unwrap();
        files.push((file, bits));
    }
    (decl, files)
}

/// Every file `src/ui/gen/` should hold, and its contents.
fn tables() -> Vec<(PathBuf, Vec<u8>)> {
    let dir = root().join("src/ui/gen");
    let mut module = String::from(HEADER);
    module.push_str(
        "\n\
         //! Font and picture tables, generated by `tests/ui_assets.rs` from\n\
         //! `assets/`. Never edited by hand:\n\
         //!\n\
         //! ```text\n\
         //! UI_REGENERATE=1 cargo +esp195 test -p kassigner-fw --test ui_assets\n\
         //! ```\n\
         \n\
         use super::font::{Font, Glyph};\n\
         use super::image::{Image, Sheet};\n",
    );
    let mut files = Vec::new();
    let parts = FONTS.iter().map(font).chain(std::iter::once(logo()));
    for (decl, (file, bits)) in parts {
        module.push('\n');
        module.push_str(&decl);
        files.push((dir.join(file), bits));
    }
    for decl in IMAGES.iter().map(image) {
        module.push('\n');
        module.push_str(&decl);
    }
    let (decl, sheets) = icons();
    module.push('\n');
    module.push_str(&decl);
    for (file, bits) in sheets {
        files.push((dir.join(file), bits));
    }
    files.push((dir.join("mod.rs"), module.into_bytes()));
    files
}

#[test]
fn ui_tables_match_assets() {
    let files = tables();
    if std::env::var_os("UI_REGENERATE").is_some() {
        for (path, bytes) in &files {
            std::fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
        return;
    }
    let stale: Vec<String> = files
        .iter()
        .filter(|(path, bytes)| std::fs::read(path).ok().as_ref() != Some(bytes))
        .map(|(path, _)| path.display().to_string())
        .collect();
    assert!(
        stale.is_empty(),
        "not what assets/ makes, regenerate with \
         UI_REGENERATE=1 cargo +esp195 test -p kassigner-fw --test ui_assets: {stale:?}"
    );
}
