//! Declarative catalog of every user-facing firmware workflow.

use crate::runtime::{data::DeviceStorageIntent, input::{AppState, Menu}};

mod onboarding;
mod seeds;
mod signing;
mod export;
mod storage;
mod stego;
mod multisig;
mod settings;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum WorkflowCategory {
    WalletSetup = 0,
    Seeds = 1,
    Signing = 2,
    ExportBackup = 3,
    StorageSd = 4,
    Steganography = 5,
    Multisig = 6,
    SettingsSecurity = 7,
}

impl WorkflowCategory {
    pub(crate) const ALL: [Self; 8] = [
        Self::WalletSetup, Self::Seeds, Self::Signing, Self::ExportBackup,
        Self::StorageSd, Self::Steganography, Self::Multisig, Self::SettingsSecurity,
    ];

    pub(crate) const fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::WalletSetup), 1 => Some(Self::Seeds), 2 => Some(Self::Signing),
            3 => Some(Self::ExportBackup), 4 => Some(Self::StorageSd), 5 => Some(Self::Steganography),
            6 => Some(Self::Multisig), 7 => Some(Self::SettingsSecurity), _ => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::WalletSetup => "Wallet Setup",
            Self::Seeds => "Seeds",
            Self::Signing => "Signing",
            Self::ExportBackup => "Export / Backup",
            Self::StorageSd => "Storage / SD",
            Self::Steganography => "Steganography",
            Self::Multisig => "Multisig",
            Self::SettingsSecurity => "Settings / Security",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowFixtures(u16);

impl WorkflowFixtures {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const SEED: Self = Self(1 << 0);
    pub(crate) const CAMERA_QR: Self = Self(1 << 1);
    pub(crate) const SD_CARD: Self = Self(1 << 2);
    pub(crate) const SAVED_WALLET: Self = Self(1 << 3);
    #[cfg(feature = "m5stack")] pub(crate) const RTC: Self = Self(1 << 4);
    #[cfg(feature = "m5stack")] pub(crate) const AUDIO: Self = Self(1 << 5);
    #[cfg(feature = "waveshare")]
    pub(crate) const CAMERA_TUNING: Self = Self(1 << 6);

    pub(crate) const fn union(self, other: Self) -> Self { Self(self.0 | other.0) }
    pub(crate) const fn bits(self) -> u16 { self.0 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowTerminal {
    Ordinary,
    OnboardingComplete,
}

pub(crate) struct WorkflowSpec {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) intent: DeviceStorageIntent,
    pub(crate) fixtures: WorkflowFixtures,
    pub(crate) terminal: WorkflowTerminal,
    pub(crate) states: &'static [AppState],
}

const GROUPS: [&[WorkflowSpec]; 8] = [
    onboarding::WORKFLOWS,
    seeds::WORKFLOWS,
    signing::WORKFLOWS,
    export::WORKFLOWS,
    storage::WORKFLOWS,
    stego::WORKFLOWS,
    multisig::WORKFLOWS,
    settings::WORKFLOWS,
];

pub(crate) const fn category_labels() -> [&'static str; 9] {
    [
        "Run All",
        "Wallet Setup",
        "Seeds",
        "Signing",
        "Export / Backup",
        "Storage / SD",
        "Steganography",
        "Multisig",
        "Settings / Security",
    ]
}

pub(crate) const fn category_from_menu_index(index: u8) -> Option<WorkflowCategory> {
    match index {
        1 => Some(WorkflowCategory::WalletSetup),
        2 => Some(WorkflowCategory::Seeds),
        3 => Some(WorkflowCategory::Signing),
        4 => Some(WorkflowCategory::ExportBackup),
        5 => Some(WorkflowCategory::StorageSd),
        6 => Some(WorkflowCategory::Steganography),
        7 => Some(WorkflowCategory::Multisig),
        8 => Some(WorkflowCategory::SettingsSecurity),
        _ => None,
    }
}

pub(crate) fn category_menu(category: WorkflowCategory) -> Menu {
    let workflows = workflows(category);
    let mut menu = Menu::new();
    menu.items[0] = "Run Category";
    let capacity = signer_firmware_core::input::navigation::MAX_MENU_ITEMS.saturating_sub(1);
    let count = workflows.len().min(capacity);
    for (index, workflow) in workflows.iter().take(count).enumerate() {
        menu.items[index + 1] = workflow.label;
    }
    menu.count = (count + 1) as u8;
    menu
}

pub(crate) fn workflow_at(category: WorkflowCategory, menu_index: u8) -> Option<&'static WorkflowSpec> {
    let workflow_index = menu_index.checked_sub(1)?;
    workflows(category).get(usize::from(workflow_index))
}

pub(crate) fn workflows(category: WorkflowCategory) -> &'static [WorkflowSpec] {
    GROUPS[category as usize]
}

