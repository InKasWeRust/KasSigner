use super::{
    ActionIcon, AudioIcon, CustomIcon, DeviceIcon, DocsIcon, EditorIcon, FinanceIcon, GitIcon,
    MediaIcon, MenuIcon, MenuIconProfile, OtherIcon, SecurityIcon, TransactionMenuIcon, UsersIcon,
};

const PREFIX_ICONS: &[(&str, MenuIcon)] = &[
    ("Dice", MenuIcon::Custom(CustomIcon::Dice)),
    ("Import Words", MenuIcon::Action(ActionIcon::Download)),
    ("Calc Last", MenuIcon::Editor(EditorIcon::NumberedListRight)),
    ("BIP85", MenuIcon::Git(GitIcon::Fork)),
    ("Import Key", MenuIcon::Security(SecurityIcon::Lock)),
    ("Import Raw", MenuIcon::Security(SecurityIcon::Lock)),
    ("Import from", MenuIcon::Docs(DocsIcon::AddFolder)),
    ("Import / ", MenuIcon::Action(ActionIcon::UploadSquare)),
    ("Create Multi", MenuIcon::Users(UsersIcon::Group)),
    ("Stego Imp", MenuIcon::Action(ActionIcon::EyeOff)),
    ("Sign TX", MenuIcon::Editor(EditorIcon::EditPencil)),
    ("Sign Mess", MenuIcon::Docs(DocsIcon::Page)),
    ("Commit Sec", MenuIcon::Security(SecurityIcon::Lock)),
    ("Decrypt Se", MenuIcon::Action(ActionIcon::EyeEmpty)),
    ("Seed Tools", MenuIcon::Git(GitIcon::Fork)),
    ("Single Sig", MenuIcon::Security(SecurityIcon::PasswordCursor)),
    ("Multisig", MenuIcon::Users(UsersIcon::Group)),
    ("Show Seed", MenuIcon::Action(ActionIcon::OpenNewWindow)),
    ("Show as QR", MenuIcon::Other(OtherIcon::QrCode)),
    ("Encrypt to", MenuIcon::Action(ActionIcon::UploadSquare)),
    ("CompactSeed", MenuIcon::Other(OtherIcon::QrCode)),
    ("Standard Seed", MenuIcon::Other(OtherIcon::QrCode)),
    ("Plain Text", MenuIcon::Other(OtherIcon::QrCode)),
    ("QR Export", MenuIcon::Other(OtherIcon::QrCode)),
    ("kpub as", MenuIcon::Other(OtherIcon::QrCode)),
    ("kpub to", MenuIcon::Finance(FinanceIcon::AppleWallet)),
    ("kpub", MenuIcon::Action(ActionIcon::EyeEmpty)),
    ("xprv", MenuIcon::Security(SecurityIcon::Lock)),
    ("Seed Backup", MenuIcon::Action(ActionIcon::Upload)),
    ("Watch-Only", MenuIcon::Action(ActionIcon::EyeEmpty)),
    ("Signing Key", MenuIcon::Editor(EditorIcon::EditPencil)),
    ("Steganogra", MenuIcon::Action(ActionIcon::EyeOff)),
    ("Backup to", MenuIcon::Devices(DeviceIcon::SaveFloppyDisk)),
    ("Private Key", MenuIcon::Security(SecurityIcon::PasswordCursor)),
    ("Multisig A", MenuIcon::Other(OtherIcon::QrCode)),
    ("Multisig D", MenuIcon::Docs(DocsIcon::Page)),
    ("XPrv Backup", MenuIcon::Action(ActionIcon::UploadSquare)),
    ("JPEG Stego", MenuIcon::Action(ActionIcon::EyeOff)),
    ("Display", MenuIcon::Devices(DeviceIcon::Laptop)),
    ("Camera", MenuIcon::Media(MediaIcon::Camera)),
    ("SD Card", MenuIcon::Devices(DeviceIcon::SaveFloppyDisk)),
    ("About", MenuIcon::Action(ActionIcon::HelpCircle)),
    ("Covenant", MenuIcon::Security(SecurityIcon::ShieldCheck)),
];

pub(super) fn classify_menu_icon(label: &str, profile: MenuIconProfile) -> MenuIcon {
    if label.starts_with("New Seed") && !label.contains("Dice") {
        return MenuIcon::Media(MediaIcon::Camera);
    }
    if label == "Address" {
        return MenuIcon::Finance(FinanceIcon::AppleWallet);
    }
    if label.starts_with("Transaction") {
        return transaction_icon(profile.transaction);
    }
    if profile.audio && label.starts_with("Audio") {
        return MenuIcon::Audio(AudioIcon::SoundHigh);
    }
    PREFIX_ICONS
        .iter()
        .find_map(|(prefix, icon)| label.starts_with(prefix).then_some(*icon))
        .unwrap_or(MenuIcon::Custom(CustomIcon::Fallback))
}

fn transaction_icon(icon: TransactionMenuIcon) -> MenuIcon {
    match icon {
        #[cfg(feature = "waveshare")]
        TransactionMenuIcon::Coin => MenuIcon::Finance(FinanceIcon::Coin),
        #[cfg(feature = "m5stack")]
        TransactionMenuIcon::Download => MenuIcon::Action(ActionIcon::Download),
    }
}
