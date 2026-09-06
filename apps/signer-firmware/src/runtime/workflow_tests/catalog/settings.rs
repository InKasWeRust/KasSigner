use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal::Ordinary};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec{id:"settings-display",label:"Display Settings",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[MainMenu,SettingsMenu,DisplaySettings,SettingsMenu,MainMenu]},
    #[cfg(feature="m5stack")]
    WorkflowSpec{id:"settings-audio",label:"Audio Settings",intent:DeviceStorageIntent::None,fixtures:F::AUDIO,terminal:Ordinary,states:&[MainMenu,SettingsMenu,AudioSettings,SettingsMenu,MainMenu]},
    #[cfg(feature="waveshare")]
    WorkflowSpec{id:"settings-camera",label:"Camera Settings",intent:DeviceStorageIntent::None,fixtures:F::CAMERA_TUNING,terminal:Ordinary,states:&[MainMenu,SettingsMenu,CameraSettings,SettingsMenu,MainMenu]},
    WorkflowSpec{id:"settings-security",label:"Security",intent:DeviceStorageIntent::None,fixtures:F::SAVED_WALLET,terminal:Ordinary,states:&[SettingsMenu,AdvancedFeatures,SettingsMenu]},
    WorkflowSpec{id:"settings-advanced",label:"Advanced",intent:DeviceStorageIntent::None,fixtures:F::SEED,terminal:Ordinary,states:&[SettingsMenu,AdvancedMenu,ScanQR]},
    WorkflowSpec{id:"settings-factory-reset",label:"Factory Reset",intent:DeviceStorageIntent::None,fixtures:F::SAVED_WALLET,terminal:Ordinary,states:&[AdvancedMenu,FactoryResetWarning,FactoryResetConfirm,AdvancedMenu]},
    WorkflowSpec{id:"settings-owner-authority",label:"Owner Firmware",intent:DeviceStorageIntent::None,fixtures:F::SD_CARD,terminal:Ordinary,states:&[AdvancedMenu,OwnerFirmwareMenu,OwnerKeyWarning,OwnerKeyConfirm,OwnerFirmwareMenu,OwnerInstallWarning,OwnerInstallConfirm,OwnerFirmwareMenu,AdvancedMenu]},
    WorkflowSpec{id:"settings-about",label:"About",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[MainMenu,SettingsMenu,About,SettingsMenu,MainMenu]},
    WorkflowSpec{id:"advanced-duress",label:"Duress Credential",intent:DeviceStorageIntent::None,fixtures:F::SAVED_WALLET,terminal:Ordinary,states:&[AdvancedFeatures,AdvancedDuressWarning,AdvancedDuressEntry,AdvancedDuressConfirm,AdvancedFeatures]},
    #[cfg(feature="m5stack")]
    WorkflowSpec{id:"advanced-rtc",label:"RTC Setup",intent:DeviceStorageIntent::None,fixtures:F::RTC,terminal:Ordinary,states:&[AdvancedFeatures,AdvancedRtcEntry,AdvancedFeatures]},
    #[cfg(feature="m5stack")]
    WorkflowSpec{id:"advanced-timelock",label:"No-Sign Until",intent:DeviceStorageIntent::None,fixtures:F::RTC.union(F::SAVED_WALLET),terminal:Ordinary,states:&[AdvancedFeatures,AdvancedTimeLockWarning,AdvancedTimeLockEntry,AdvancedTimeLockConfirm,AdvancedFeatures]},
    #[cfg(feature="m5stack")]
    WorkflowSpec{id:"advanced-weekly",label:"Weekly Windows",intent:DeviceStorageIntent::None,fixtures:F::RTC.union(F::SAVED_WALLET),terminal:Ordinary,states:&[AdvancedFeatures,AdvancedWeeklyWarning,AdvancedWeeklyEntry,AdvancedWeeklyConfirm,AdvancedFeatures]},
    WorkflowSpec{id:"settings-pop-it-explain",label:"Pop It Explain",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[AdvancedMenu,PopItPrompt,PopItExplain,PopItPrompt,AdvancedMenu]},
    WorkflowSpec{id:"settings-pop-it-confirm",label:"Pop It Confirm",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[AdvancedMenu,PopItPrompt,PopItConfirm,AdvancedMenu]},
    #[cfg(feature="developer-ui")]
    WorkflowSpec{id:"developer-menu",label:"Developer Menu",intent:DeviceStorageIntent::None,fixtures:F::NONE,terminal:Ordinary,states:&[SettingsMenu,DeveloperMenu,DiagnosticInfo,DeveloperMenu,NetworkMenu,DeveloperMenu,SettingsMenu]},
];
