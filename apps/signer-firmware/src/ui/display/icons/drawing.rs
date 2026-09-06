use embedded_graphics::{
    image::Image,
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Circle, CornerRadii, PrimitiveStyle, Rectangle, RoundedRectangle},
};
use embedded_iconoir::{icons::size24px, prelude::*};

use super::{
    ActionIcon, AudioIcon, CustomIcon, DeviceIcon, DocsIcon, EditorIcon, FinanceIcon, GitIcon,
    MediaIcon, MenuIcon, OtherIcon, SecurityIcon, UsersIcon,
};
use crate::ui::display::{COLOR_BG, KASPA_TEAL};

macro_rules! draw_embedded_icon {
    ($display:expr, $position:expr, $icon_type:ty) => {{
        let icon = <$icon_type>::new(KASPA_TEAL);
        Image::new(&icon, $position).draw($display).ok();
    }};
}

pub(super) fn draw_classified_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: MenuIcon,
) {
    match icon {
        MenuIcon::Action(icon) => draw_action_icon(display, position, icon),
        MenuIcon::Audio(icon) => draw_audio_icon(display, position, icon),
        MenuIcon::Custom(icon) => draw_custom_icon(display, position, icon),
        MenuIcon::Devices(icon) => draw_device_icon(display, position, icon),
        MenuIcon::Docs(icon) => draw_docs_icon(display, position, icon),
        MenuIcon::Editor(icon) => draw_editor_icon(display, position, icon),
        MenuIcon::Finance(icon) => draw_finance_icon(display, position, icon),
        MenuIcon::Git(icon) => draw_git_icon(display, position, icon),
        MenuIcon::Media(icon) => draw_media_icon(display, position, icon),
        MenuIcon::Other(icon) => draw_other_icon(display, position, icon),
        MenuIcon::Security(icon) => draw_security_icon(display, position, icon),
        MenuIcon::Users(icon) => draw_users_icon(display, position, icon),
    }
}

fn draw_action_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: ActionIcon,
) {
    match icon {
        ActionIcon::Download => draw_embedded_icon!(display, position, size24px::actions::Download),
        ActionIcon::EyeEmpty => draw_embedded_icon!(display, position, size24px::actions::EyeEmpty),
        ActionIcon::EyeOff => draw_embedded_icon!(display, position, size24px::actions::EyeOff),
        ActionIcon::HelpCircle => {
            draw_embedded_icon!(display, position, size24px::actions::HelpCircle)
        }
        ActionIcon::OpenNewWindow => {
            draw_embedded_icon!(display, position, size24px::actions::OpenNewWindow)
        }
        ActionIcon::Upload => draw_embedded_icon!(display, position, size24px::actions::Upload),
        ActionIcon::UploadSquare => {
            draw_embedded_icon!(display, position, size24px::actions::UploadSquare)
        }
    }
}

fn draw_audio_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: AudioIcon,
) {
    match icon {
        AudioIcon::SoundHigh => draw_embedded_icon!(display, position, size24px::audio::SoundHigh),
    }
}

fn draw_custom_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: CustomIcon,
) {
    match icon {
        CustomIcon::Dice => draw_dice_icon(display, position),
        CustomIcon::Fallback => draw_fallback_icon(display, position),
    }
}

fn draw_device_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: DeviceIcon,
) {
    match icon {
        DeviceIcon::Laptop => draw_embedded_icon!(display, position, size24px::devices::Laptop),
        DeviceIcon::SaveFloppyDisk => {
            draw_embedded_icon!(display, position, size24px::devices::SaveFloppyDisk)
        }
    }
}

fn draw_docs_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: DocsIcon,
) {
    match icon {
        DocsIcon::AddFolder => draw_embedded_icon!(display, position, size24px::docs::AddFolder),
        DocsIcon::Page => draw_embedded_icon!(display, position, size24px::docs::Page),
    }
}

fn draw_editor_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: EditorIcon,
) {
    match icon {
        EditorIcon::EditPencil => {
            draw_embedded_icon!(display, position, size24px::editor::EditPencil)
        }
        EditorIcon::NumberedListRight => {
            draw_embedded_icon!(display, position, size24px::editor::NumberedListRight)
        }
    }
}

fn draw_finance_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: FinanceIcon,
) {
    match icon {
        FinanceIcon::AppleWallet => {
            draw_embedded_icon!(display, position, size24px::finance::AppleWallet)
        }
        #[cfg(feature = "waveshare")]
        FinanceIcon::Coin => draw_embedded_icon!(display, position, size24px::finance::Coin),
    }
}

fn draw_git_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: GitIcon,
) {
    match icon {
        GitIcon::Fork => draw_embedded_icon!(display, position, size24px::git::GitFork),
    }
}

fn draw_media_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: MediaIcon,
) {
    match icon {
        MediaIcon::Camera => {
            draw_embedded_icon!(display, position, size24px::photos_and_videos::Camera)
        }
    }
}

fn draw_other_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: OtherIcon,
) {
    match icon {
        OtherIcon::QrCode => draw_embedded_icon!(display, position, size24px::other::QrCode),
    }
}

fn draw_security_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: SecurityIcon,
) {
    match icon {
        SecurityIcon::Lock => draw_embedded_icon!(display, position, size24px::security::Lock),
        SecurityIcon::PasswordCursor => {
            draw_embedded_icon!(display, position, size24px::security::PasswordCursor)
        }
        SecurityIcon::ShieldCheck => {
            draw_embedded_icon!(display, position, size24px::security::ShieldCheck)
        }
    }
}

fn draw_users_icon<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    position: Point,
    icon: UsersIcon,
) {
    match icon {
        UsersIcon::Group => draw_embedded_icon!(display, position, size24px::users::Group),
    }
}

fn draw_dice_icon<D: DrawTarget<Color = Rgb565>>(display: &mut D, position: Point) {
    const SIZE: u32 = 24;
    const RADIUS: u32 = 2;
    let corner = CornerRadii::new(embedded_graphics::geometry::Size::new(4, 4));
    RoundedRectangle::new(
        Rectangle::new(
            position,
            embedded_graphics::geometry::Size::new(SIZE, SIZE),
        ),
        corner,
    )
    .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
    .draw(display)
    .ok();

    let center_x = position.x + SIZE as i32 / 2;
    let center_y = position.y + SIZE as i32 / 2;
    let delta = SIZE as i32 / 4;
    for &(x, y) in &[
        (center_x - delta, center_y - delta),
        (center_x + delta, center_y - delta),
        (center_x, center_y),
        (center_x - delta, center_y + delta),
        (center_x + delta, center_y + delta),
    ] {
        draw_die_pip(display, x, y, RADIUS);
    }
}

fn draw_die_pip<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    x: i32,
    y: i32,
    radius: u32,
) {
    Circle::new(
        Point::new(x - radius as i32, y - radius as i32),
        radius * 2 + 1,
    )
    .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
    .draw(display)
    .ok();
}

fn draw_fallback_icon<D: DrawTarget<Color = Rgb565>>(display: &mut D, position: Point) {
    Circle::new(position + Point::new(4, 4), 16)
        .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
        .draw(display)
        .ok();
}
