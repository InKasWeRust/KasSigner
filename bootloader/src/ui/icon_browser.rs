// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// ui/icon_browser.rs — Test screen: browse all Iconoir 24px icons
//
// Paginated grid: 8 icons per page (4×2), category label at top,
// nav arrows at bottom. Feature-gated behind `icon-browser`.

use embedded_graphics::prelude::*;
use embedded_graphics::image::Image;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle, RoundedRectangle, CornerRadii};
use embedded_iconoir::prelude::*;
use embedded_iconoir::icons::size24px;
use crate::hw::display::*;

/// Total number of icons in the browser
pub const ICON_COUNT: u16 = 160;

/// Icons per page (4 columns × 2 rows)
const COLS: u16 = 4;
const ROWS: u16 = 2;
const PER_PAGE: u16 = COLS * ROWS;

/// Grid layout
const CELL_W: i32 = 76;  // 320 / 4 = 80, with margin
const CELL_H: i32 = 70;
const GRID_X0: i32 = 4;
const GRID_Y0: i32 = 42;
const ICON_OX: i32 = 26; // center icon in cell
const ICON_OY: i32 = 6;
const LABEL_OY: i32 = 38;

/// One entry in the icon catalog
struct IconEntry {
    name: &'static str,
    cat: &'static str,
}

/// Draw an icon by index at (x,y)
fn draw_icon_at(d: &mut impl DrawTarget<Color = Rgb565>, idx: u16, x: i32, y: i32) {
    let color = KASPA_TEAL;
    macro_rules! icon {
        ($cat:ident :: $name:ident) => {{
            let i = size24px::$cat::$name::new(color);
            Image::new(&i, Point::new(x, y)).draw(d).ok();
        }};
    }
    match idx {
        // ── actions ──
        0 => icon!(actions::Download),
        1 => icon!(actions::Upload),
        2 => icon!(actions::UploadSquare),
        3 => icon!(actions::HelpCircle),
        4 => icon!(actions::OpenNewWindow),
        5 => icon!(actions::Trash),
        6 => icon!(actions::EyeOff),
        7 => icon!(design_tools::Copy),
        8 => icon!(design_tools::Cut),
        9 => icon!(actions::ShareAndroid),
        10 => icon!(actions::Undo),
        11 => icon!(actions::Redo),
        12 => icon!(actions::Refresh),
        13 => icon!(organization::Search),
        14 => icon!(actions::Plus),
        15 => icon!(actions::Minus),
        // ── arrows ──
        16 => icon!(navigation::ArrowUp),
        17 => icon!(navigation::ArrowDown),
        18 => icon!(navigation::ArrowLeft),
        19 => icon!(navigation::ArrowRight),
        20 => icon!(navigation::LongArrowUpLeft),
        21 => icon!(navigation::LongArrowDownRight),
        22 => icon!(actions::Undo),
        23 => icon!(actions::Redo),
        // ── security ──
        24 => icon!(security::Lock),
        25 => icon!(security::Lock),
        26 => icon!(security::PasswordCursor),
        27 => icon!(security::Shield),
        28 => icon!(security::ShieldCheck),
        29 => icon!(identity::Fingerprint),
        30 => icon!(actions::EyeOff),
        31 => icon!(security::PasswordCursor),
        // ── docs ──
        32 => icon!(docs::Page),
        33 => icon!(docs::Folder),
        34 => icon!(docs::AddFolder),
        35 => icon!(activities::Book),
        36 => icon!(docs::Journal),
        37 => icon!(other::Notes),
        38 => icon!(actions::ClipboardCheck),
        39 => icon!(docs::EmptyPage),
        // ── editor ──
        40 => icon!(editor::EditPencil),
        41 => icon!(editor::NumberedListRight),
        42 => icon!(editor::AlignLeft),
        43 => icon!(editor::AlignCenter),
        44 => icon!(editor::AlignRight),
        45 => icon!(editor::TextSize),
        46 => icon!(editor::Bold),
        47 => icon!(editor::Italic),
        // ── devices ──
        48 => icon!(devices::Laptop),
        49 => icon!(devices::SaveFloppyDisk),
        50 => icon!(devices::Laptop),
        51 => icon!(devices::Printer),
        52 => icon!(connectivity::Wifi),
        53 => icon!(connectivity::WifiOff),
        54 => icon!(system::BatteryFull),
        55 => icon!(system::BatteryFull),
        // ── photos_and_videos ──
        56 => icon!(photos_and_videos::Camera),
        57 => icon!(photos_and_videos::MediaImage),
        58 => icon!(photos_and_videos::Camera),
        59 => icon!(photos_and_videos::Camera),
        60 => icon!(photos_and_videos::MediaImage),
        61 => icon!(photos_and_videos::MediaImage),
        62 => icon!(photos_and_videos::MediaImage),
        63 => icon!(photos_and_videos::Camera),
        // ── users ──
        64 => icon!(users::User),
        65 => icon!(users::UserCircle),
        66 => icon!(users::Group),
        67 => icon!(users::AddUser),
        68 => icon!(users::RemoveUser),
        69 => icon!(users::Community),
        70 => icon!(users::UserStar),
        71 => icon!(users::ProfileCircle),
        // ── finance ──
        72 => icon!(finance::AppleWallet),
        73 => icon!(finance::Coins),
        74 => icon!(finance::Coins),
        75 => icon!(finance::CreditCard),
        76 => icon!(finance::Wallet),
        77 => icon!(finance::AppleWallet),
        78 => icon!(buildings::Shop),
        79 => icon!(shopping::Cart),
        // ── gaming ──
        80 => icon!(gaming::DiceFive),
        81 => icon!(gaming::DiceOne),
        82 => icon!(gaming::DiceTwo),
        83 => icon!(gaming::DiceThree),
        84 => icon!(gaming::DiceFour),
        85 => icon!(gaming::DiceSix),
        86 => icon!(development::Puzzle),
        87 => icon!(activities::Trophy),
        // ── git ──
        88 => icon!(git::GitFork),
        89 => icon!(git::GitBranch),
        90 => icon!(git::GitCommit),
        91 => icon!(git::GitMerge),
        92 => icon!(git::GitPullRequest),
        93 => icon!(git::GitCompare),
        94 => icon!(git::Repository),
        95 => icon!(other::QrCode),
        // ── identity ──
        96 => icon!(identity::Fingerprint),
        97 => icon!(identity::Fingerprint),
        98 => icon!(identity::FaceId),
        99 => icon!(identity::FaceId),
        100 => icon!(identity::FaceId),
        101 => icon!(gaming::Crown),
        102 => icon!(organization::Label),
        103 => icon!(gaming::Crown),
        // ── audio ──
        104 => icon!(audio::SoundHigh),
        105 => icon!(audio::SoundOff),
        106 => icon!(audio::SoundLow),
        107 => icon!(audio::SoundHigh),
        108 => icon!(audio::SoundOff),
        109 => icon!(music::MusicNote),
        110 => icon!(music::MusicNote),
        111 => icon!(audio::SoundLow),
        // ── other ──
        112 => icon!(other::QrCode),
        113 => icon!(science::Magnet),
        114 => icon!(activities::MathBook),
        115 => icon!(development::Puzzle),
        116 => icon!(photos_and_videos::FlashOff),
        117 => icon!(photos_and_videos::Flash),
        118 => icon!(gaming::BrightStar),
        119 => icon!(other::HalfMoon),
        // ── development ──
        120 => icon!(development::CodeBracketsSquare),
        121 => icon!(development::Code),
        122 => icon!(system::Terminal),
        123 => icon!(development::Code),
        124 => icon!(system::Cpu),
        125 => icon!(development::Code),
        126 => icon!(weather::Cloud),
        127 => icon!(cloud::CloudCheck),
        // ── communication ──
        128 => icon!(communication::Mail),
        129 => icon!(communication::Mail),
        130 => icon!(communication::Phone),
        131 => icon!(communication::Send),
        132 => icon!(docs::Attachment),
        133 => icon!(actions::ShareAndroid),
        134 => icon!(other::Link),
        135 => icon!(communication::Mail),
        // ── navigation ──
        136 => icon!(home::Home),
        137 => icon!(home::HomeSimple),
        138 => icon!(actions::Menu),
        139 => icon!(actions::Menu),
        140 => icon!(navigation::MoreVert),
        141 => icon!(navigation::NavArrowDown),
        142 => icon!(navigation::NavArrowUp),
        143 => icon!(navigation::NavArrowDown),
        // ── maps ──
        144 => icon!(maps::Map),
        145 => icon!(maps::Map),
        146 => icon!(navigation::Compass),
        147 => icon!(communication::Globe),
        148 => icon!(maps::PinAlt),
        149 => icon!(maps::Navigator),
        150 => icon!(maps::Map),
        151 => icon!(maps::PinAlt),
        // ── layout ──
        152 => icon!(layout::ViewGrid),
        153 => icon!(layout::ViewColumnsTwo),
        154 => icon!(layout::ViewGrid),
        155 => icon!(system::DashboardDots),
        156 => icon!(layout::Table),
        157 => icon!(layout::ViewGrid),
        158 => icon!(layout::ViewColumnsTwo),
        159 => icon!(layout::Table),

        _ => {}
    }
}

/// Get the icon name for display
fn icon_name(idx: u16) -> &'static str {
    match idx {
        0 => "Download", 1 => "Upload", 2 => "UploadSq", 3 => "HelpCirc",
        4 => "OpenNew", 5 => "Trash", 6 => "EyeOff", 7 => "Copy",
        8 => "Cut", 9 => "Share", 10 => "Undo", 11 => "Redo",
        12 => "Refresh", 13 => "Search", 14 => "Plus", 15 => "Minus",

        16 => "ArrowUp", 17 => "ArrowDn", 18 => "ArrowL", 19 => "ArrowR",
        20 => "LngArUL", 21 => "LngArDR", 22 => "Undo", 23 => "Redo",

        24 => "Lock", 25 => "Unlock", 26 => "Key", 27 => "Shield",
        28 => "ShldChk", 29 => "Fprint", 30 => "EyeSol", 31 => "PwdCurs",

        32 => "Page", 33 => "Folder", 34 => "AddFld", 35 => "Book",
        36 => "Journal", 37 => "Notes", 38 => "ClipChk", 39 => "EmptyPg",

        40 => "Pencil", 41 => "NumList", 42 => "AlignL", 43 => "AlignC",
        44 => "AlignR", 45 => "TextSz", 46 => "Bold", 47 => "Italic",

        48 => "Laptop", 49 => "Floppy", 50 => "Phone", 51 => "Printer",
        52 => "Wifi", 53 => "WifiOff", 54 => "Bat50", 55 => "BatFull",

        56 => "Camera", 57 => "Image", 58 => "Film", 59 => "Apertur",
        60 => "Landscp", 61 => "PhotoM-", 62 => "Photo+", 63 => "Focus",

        64 => "User", 65 => "UserCir", 66 => "Group", 67 => "AddUser",
        68 => "RemUser", 69 => "Commun", 70 => "UsrStar", 71 => "Profile",

        72 => "Wallet", 73 => "Bitcoin", 74 => "Coins", 75 => "CrdCard",
        76 => "Wallet2", 77 => "Receipt", 78 => "Shop", 79 => "Cart",

        80 => "Dice5", 81 => "Dice1", 82 => "Dice2", 83 => "Dice3",
        84 => "Dice4", 85 => "Dice6", 86 => "Puzzle", 87 => "Trophy",

        88 => "Fork", 89 => "Branch", 90 => "Commit", 91 => "Merge",
        92 => "PR", 93 => "Compare", 94 => "Repo", 95 => "Hash",

        96 => "Fprint2", 97 => "IdCard", 98 => "FaceId", 99 => "Passprt",
        100 => "Badge", 101 => "Crown", 102 => "Label", 103 => "Star",

        104 => "SndHi", 105 => "SndOff", 106 => "SndLow", 107 => "Mic",
        108 => "MicMute", 109 => "Note", 110 => "NoteDb", 111 => "Headphn",

        112 => "QrCode", 113 => "Magnet", 114 => "MathBk", 115 => "Puzzle",
        116 => "FlshOff", 117 => "Flash", 118 => "BrStar", 119 => "Moon",

        120 => "Bracket", 121 => "Code", 122 => "Term", 123 => "Bug",
        124 => "Cpu", 125 => "DB", 126 => "Cloud", 127 => "CldChk",

        128 => "Mail", 129 => "Chat", 130 => "Phone", 131 => "Send",
        132 => "Attach", 133 => "ShareA", 134 => "Link", 135 => "At",

        136 => "Home", 137 => "HomeSim", 138 => "Menu", 139 => "MoreH",
        140 => "MoreV", 141 => "Close", 142 => "NavUp", 143 => "NavDn",

        144 => "MapPin", 145 => "Map", 146 => "Compas", 147 => "Globe",
        148 => "PinAlt", 149 => "Navig", 150 => "DirR", 151 => "Flag",

        152 => "Grid", 153 => "Cols2", 154 => "Sidebar", 155 => "Dash",
        156 => "Table", 157 => "App", 158 => "Columns", 159 => "Layout",

        _ => "?",
    }
}

/// Category name for a page
fn category_for_page(page: u16) -> &'static str {
    match page {
        0 | 1 => "actions",
        2 | 3 => "arrows",
        4 | 5 => "security",
        6 | 7 => "docs",
        8 | 9 => "editor",
        10 | 11 => "devices",
        12 | 13 => "photos",
        14 | 15 => "users",
        16 | 17 => "finance",
        18 | 19 => "gaming",
        _ => {
            let cat_idx = page / 2;
            match cat_idx {
                10 => "git",
                11 => "identity",
                12 => "audio",
                13 => "other",
                14 => "development",
                15 => "communication",
                16 => "navigation",
                17 => "maps",
                18 | 19 => "layout",
                _ => "misc",
            }
        }
    }
}

/// Draw the icon browser page.
/// `page` starts at 0. Total pages = ceil(ICON_COUNT / PER_PAGE).
pub fn draw_icon_page(d: &mut impl DrawTarget<Color = Rgb565>, page: u16) {
    let total_pages = (ICON_COUNT + PER_PAGE - 1) / PER_PAGE;
    let cat = category_for_page(page);

    // Header: "ICONS: category  (page/total)"
    let mut hdr: heapless::String<40> = heapless::String::new();
    core::fmt::Write::write_fmt(&mut hdr,
        format_args!("ICONS: {}", cat)).ok();
    let hw = measure_header(hdr.as_str());
    draw_oswald_header(d, &hdr, (320 - hw) / 2, 22, COLOR_TEXT);

    // Page counter
    let mut pg: heapless::String<12> = heapless::String::new();
    core::fmt::Write::write_fmt(&mut pg,
        format_args!("{}/{}", page + 1, total_pages)).ok();
    let pgw = measure_hint(pg.as_str());
    draw_lato_hint(d, &pg, 320 - pgw - 6, 22, COLOR_TEXT_DIM);

    // Teal line
    embedded_graphics::primitives::Line::new(
        Point::new(10, 30),
        Point::new(310, 30),
    ).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
        .draw(d).ok();

    // Icon grid: 4×2
    let start = page * PER_PAGE;
    for row in 0..ROWS {
        for col in 0..COLS {
            let idx = start + row * COLS + col;
            if idx >= ICON_COUNT { continue; }
            let cx = GRID_X0 + col as i32 * CELL_W;
            let cy = GRID_Y0 + row as i32 * CELL_H;

            // Cell background
            let cell = Rectangle::new(Point::new(cx, cy), Size::new(CELL_W as u32 - 4, CELL_H as u32 - 4));
            let cc = CornerRadii::new(Size::new(4, 4));
            RoundedRectangle::new(cell, cc)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(d).ok();
            RoundedRectangle::new(cell, cc)
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(d).ok();

            // Icon
            draw_icon_at(d, idx, cx + ICON_OX, cy + ICON_OY);

            // Label
            let name = icon_name(idx);
            let nw = measure_hint(name);
            draw_lato_hint(d, name, cx + ((CELL_W - 4) as i32 - nw) / 2, cy + LABEL_OY + 14, COLOR_TEXT_DIM);

            // Index number (small)
            let mut ibuf: heapless::String<4> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut ibuf, format_args!("{}", idx)).ok();
            draw_lato_hint(d, &ibuf, cx + 4, cy + 10, COLOR_HINT);
        }
    }

    // Nav bar at bottom: [◄ PREV] ────── [NEXT ►]
    let nav_y = 190i32;
    let btn_corner = CornerRadii::new(Size::new(6, 6));

    // Previous
    if page > 0 {
        let prev_rect = Rectangle::new(Point::new(4, nav_y), Size::new(80, 28));
        RoundedRectangle::new(prev_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(d).ok();
        RoundedRectangle::new(prev_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(d).ok();
        let pw = measure_body("< PREV");
        draw_lato_body(d, "< PREV", 4 + (80 - pw) / 2, nav_y + 20, KASPA_TEAL);
    }

    // Next
    if (page + 1) * PER_PAGE < ICON_COUNT {
        let next_rect = Rectangle::new(Point::new(236, nav_y), Size::new(80, 28));
        RoundedRectangle::new(next_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(d).ok();
        RoundedRectangle::new(next_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(d).ok();
        let nw = measure_body("NEXT >");
        draw_lato_body(d, "NEXT >", 236 + (80 - nw) / 2, nav_y + 20, KASPA_TEAL);
    }
}

/// Hit-test the icon browser nav buttons.
/// Returns: -1 = prev, +1 = next, 0 = miss
pub fn hit_nav(x: u16, y: u16) -> i16 {
    let nav_y = 190u16;
    if y >= nav_y && y < nav_y + 28 {
        if (4..84).contains(&x) { return -1; }
        if (236..316).contains(&x) { return 1; }
    }
    0
}
