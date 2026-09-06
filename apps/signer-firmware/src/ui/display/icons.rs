// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

mod classification;
mod drawing;

use embedded_graphics::{pixelcolor::Rgb565, prelude::*};

use classification::classify_menu_icon;
use drawing::draw_classified_icon;

#[derive(Clone, Copy)]
enum TransactionMenuIcon {
    #[cfg(feature = "waveshare")]
    Coin,
    #[cfg(feature = "m5stack")]
    Download,
}

#[derive(Clone, Copy)]
struct MenuIconProfile {
    transaction: TransactionMenuIcon,
    audio: bool,
}

#[derive(Clone, Copy)]
enum MenuIcon {
    Action(ActionIcon),
    Audio(AudioIcon),
    Custom(CustomIcon),
    Devices(DeviceIcon),
    Docs(DocsIcon),
    Editor(EditorIcon),
    Finance(FinanceIcon),
    Git(GitIcon),
    Media(MediaIcon),
    Other(OtherIcon),
    Security(SecurityIcon),
    Users(UsersIcon),
}

#[derive(Clone, Copy)]
enum ActionIcon {
    Download,
    EyeEmpty,
    EyeOff,
    HelpCircle,
    OpenNewWindow,
    Upload,
    UploadSquare,
}

#[derive(Clone, Copy)]
enum AudioIcon {
    SoundHigh,
}

#[derive(Clone, Copy)]
enum CustomIcon {
    Dice,
    Fallback,
}

#[derive(Clone, Copy)]
enum DeviceIcon {
    Laptop,
    SaveFloppyDisk,
}

#[derive(Clone, Copy)]
enum DocsIcon {
    AddFolder,
    Page,
}

#[derive(Clone, Copy)]
enum EditorIcon {
    EditPencil,
    NumberedListRight,
}

#[derive(Clone, Copy)]
enum FinanceIcon {
    AppleWallet,
    #[cfg(feature = "waveshare")]
    Coin,
}

#[derive(Clone, Copy)]
enum GitIcon {
    Fork,
}

#[derive(Clone, Copy)]
enum MediaIcon {
    Camera,
}

#[derive(Clone, Copy)]
enum OtherIcon {
    QrCode,
}

#[derive(Clone, Copy)]
enum SecurityIcon {
    Lock,
    PasswordCursor,
    ShieldCheck,
}

#[derive(Clone, Copy)]
enum UsersIcon {
    Group,
}

#[cfg(feature = "waveshare")]
const MENU_ICON_PROFILE: MenuIconProfile = MenuIconProfile {
    transaction: TransactionMenuIcon::Coin,
    audio: false,
};

#[cfg(feature = "m5stack")]
const MENU_ICON_PROFILE: MenuIconProfile = MenuIconProfile {
    transaction: TransactionMenuIcon::Download,
    audio: true,
};

pub(crate) fn draw_menu_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    label: &str,
    position: Point,
) {
    draw_menu_icon_with_profile(display, label, position, MENU_ICON_PROFILE);
}

fn draw_menu_icon_with_profile<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    label: &str,
    position: Point,
    profile: MenuIconProfile,
) {
    draw_classified_icon(display, position, classify_menu_icon(label, profile));
}
