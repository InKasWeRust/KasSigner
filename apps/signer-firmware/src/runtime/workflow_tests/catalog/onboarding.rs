use super::{WorkflowFixtures as F, WorkflowSpec, WorkflowTerminal};
use crate::runtime::{data::DeviceStorageIntent, input::AppState::*};

pub(super) const WORKFLOWS: &[WorkflowSpec] = &[
    WorkflowSpec { id:"fresh-create-12", label:"Create 12-Word Wallet", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedWordCountChoice{action:0}, StorageSeedDiceChoice,
        StorageSeedTouchChoice, PassphraseChoice, SeedBackup{word_idx:0},
        StorageRecoveryAcknowledgement, StorageFinalizeChoice, MainMenu,
    ]},
    WorkflowSpec { id:"fresh-create-24-additive", label:"Create 24 + Dice/Touch", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedWordCountChoice{action:0}, StorageSeedDiceChoice,
        StorageSeedDiceCountChoice, DiceRoll, StorageSeedTouchChoice, TouchEntropy,
        PassphraseChoice, PassphraseEntry, SeedBackup{word_idx:0},
        StorageRecoveryAcknowledgement, StorageFinalizeChoice, MainMenu,
    ]},
    WorkflowSpec { id:"camera-entropy-retry", label:"Camera Entropy Retry", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::Ordinary, states:&[
        StorageSeedWordCountChoice{action:0}, SeedEntropyUnavailable{word_count:12}, StorageSeedDiceChoice,
    ]},
    WorkflowSpec { id:"camera-entropy-cancel", label:"Camera Entropy Cancel", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::Ordinary, states:&[
        StorageSeedWordCountChoice{action:0}, SeedEntropyUnavailable{word_count:12}, StorageSeedWordCountChoice{action:0},
    ]},
    WorkflowSpec { id:"restore-words-12", label:"Restore Recovery Words 12", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedSourceChoice,
        RestoreWord{word_idx:0}, RestoreWord{word_idx:1}, RestoreWord{word_idx:2}, RestoreWord{word_idx:3},
        RestoreWord{word_idx:4}, RestoreWord{word_idx:5}, RestoreWord{word_idx:6}, RestoreWord{word_idx:7},
        RestoreWord{word_idx:8}, RestoreWord{word_idx:9}, RestoreWord{word_idx:10}, RestoreWord{word_idx:11},
        RestoreWord12Detected, PassphraseChoice, WalletNameEntry{purpose:3},
        StorageFinalizeChoice, MainMenu,
    ]},
    WorkflowSpec { id:"restore-words-24", label:"Restore Recovery Words 24", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedSourceChoice,
        RestoreWord{word_idx:0}, RestoreWord{word_idx:1}, RestoreWord{word_idx:2}, RestoreWord{word_idx:3},
        RestoreWord{word_idx:4}, RestoreWord{word_idx:5}, RestoreWord{word_idx:6}, RestoreWord{word_idx:7},
        RestoreWord{word_idx:8}, RestoreWord{word_idx:9}, RestoreWord{word_idx:10}, RestoreWord{word_idx:11},
        RestoreWord12Detected,
        RestoreWord{word_idx:12}, RestoreWord{word_idx:13}, RestoreWord{word_idx:14}, RestoreWord{word_idx:15},
        RestoreWord{word_idx:16}, RestoreWord{word_idx:17}, RestoreWord{word_idx:18}, RestoreWord{word_idx:19},
        RestoreWord{word_idx:20}, RestoreWord{word_idx:21}, RestoreWord{word_idx:22}, RestoreWord{word_idx:23},
        PassphraseChoice, PassphraseEntry, WalletNameEntry{purpose:3},
        StorageFinalizeChoice, MainMenu,
    ]},
    WorkflowSpec { id:"restore-advanced", label:"Advanced Restore", intent:DeviceStorageIntent::StartFresh, fixtures:F::NONE, terminal:WorkflowTerminal::Ordinary, states:&[
        StorageModeChoice, StorageSeedSourceChoice, AdvancedRestoreMenu, ImportPrivKey,
    ]},
    WorkflowSpec { id:"bound-create-pin", label:"Save Device Wallet PIN", intent:DeviceStorageIntent::CreateInternal, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedWordCountChoice{action:0}, StorageSeedDiceChoice,
        StorageSeedTouchChoice, PassphraseChoice, SeedBackup{word_idx:0},
        StorageRecoveryAcknowledgement, StorageFinalizeChoice, StorageCredentialType,
        StoragePinEntry, StoragePinConfirm, MainMenu,
    ]},
    WorkflowSpec { id:"bound-create-password", label:"Save Device Wallet Password", intent:DeviceStorageIntent::CreateInternal, fixtures:F::NONE, terminal:WorkflowTerminal::OnboardingComplete, states:&[
        StorageModeChoice, StorageSeedWordCountChoice{action:0}, StorageSeedDiceChoice,
        StorageSeedTouchChoice, PassphraseChoice, SeedBackup{word_idx:0},
        StorageRecoveryAcknowledgement, StorageFinalizeChoice, StorageCredentialType,
        StoragePasswordEntry, StoragePasswordConfirm, MainMenu,
    ]},
    WorkflowSpec { id:"unlock-pin", label:"Unlock PIN", intent:DeviceStorageIntent::None, fixtures:F::SAVED_WALLET, terminal:WorkflowTerminal::Ordinary, states:&[StorageUnlockPin, MainMenu] },
    WorkflowSpec { id:"unlock-password", label:"Unlock Password", intent:DeviceStorageIntent::None, fixtures:F::SAVED_WALLET, terminal:WorkflowTerminal::Ordinary, states:&[StorageUnlockPassword, MainMenu] },
    WorkflowSpec { id:"sd-fail-closed", label:"SD Failure Gate", intent:DeviceStorageIntent::EnableSd, fixtures:F::SAVED_WALLET.union(F::SD_CARD), terminal:WorkflowTerminal::Ordinary, states:&[SettingsMenu, StorageSdFailure] },
];
