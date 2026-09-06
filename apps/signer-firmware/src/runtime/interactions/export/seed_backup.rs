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

// Seed word backup navigation.

use crate::runtime::data::AppData;

pub(crate) fn handle(ad: &mut AppData, is_back: bool) -> Option<bool> {
    match ad.navigation.app.state {
        crate::runtime::input::AppState::SeedBackup { word_idx } => {
            if is_back {
                if ad.wallet.seeds.has_pending_add_wallet() {
                    if word_idx > 0 {
                        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackup {
                            word_idx: word_idx - 1,
                        }));
                    } else {
                        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
                    }
                } else if ad.storage.persistence.device_storage_intent.is_seed_onboarding()
                {
                    if word_idx > 0 {
                        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackup {
                            word_idx: word_idx - 1,
                        }));
                    } else {
                        // Back is one-step navigation, not cancellation. The mnemonic
                        // must remain staged so the user can revise the BIP39 passphrase
                        // decision. Remove only the just-created active slot and its
                        // derived caches before returning to PassphraseChoice.
                        rewind_staged_onboarding_seed(ad);
                        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice,));
                    }
                } else {
                    // Back during ordinary word display → return to where we came from.
                    let _ = crate::runtime::effects::return_to(
                        ad,
                        crate::runtime::navigation::ReturnScope::SeedBackup,
                    );
                }
            } else {
                let next = word_idx + 1;
                if next < ad.wallet.seeds.word_count {
                    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackup { word_idx: next }));
                } else if ad.wallet.seeds.has_pending_add_wallet() {
                    ad.storage.persistence.recovery_words_acknowledged = false;
                    crate::runtime::effects::route(
                        ad,
                        crate::runtime::navigation::route!(StorageRecoveryAcknowledgement),
                    );
                } else {
                    // Onboarding completion is driven by its authoritative intent,
                    // never by a generic return target left over from another menu.
                    match ad.storage.persistence.device_storage_intent {
                        crate::runtime::data::DeviceStorageIntent::StartFresh
                        | crate::runtime::data::DeviceStorageIntent::CreateInternal => {
                            // Generated onboarding mnemonics must always stop at the
                            // explicit backup acknowledgement before either RAM-only
                            // activation or device-bound credential setup can finish.
                            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageRecoveryAcknowledgement));
                        }
                        _ if crate::runtime::navigation::return_target(
                            ad, crate::runtime::navigation::ReturnScope::SeedBackup,
                        ) == Some(crate::runtime::input::AppState::SeedToolsMenu) => {
                            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
                        }
                        _ => {
                            let _ = crate::runtime::effects::return_to(
                                ad, crate::runtime::navigation::ReturnScope::SeedBackup,
                            );
                        }
                    }
                }
            }
            Some(true)
        }
        _ => None,
    }
}

fn rewind_staged_onboarding_seed(ad: &mut AppData) {
    let active = usize::from(ad.wallet.seeds.seed_mgr.active);
    if active < ad.wallet.seeds.seed_mgr.slots.len() {
        ad.wallet.seeds.seed_mgr.delete(active);
    }
    crate::services::wallet_session::reset_derived_state(ad);
    ad.wallet.seeds.active_source = crate::wallet::seed_manager::WalletSource::Empty;
    ad.wallet.seeds.seed_loaded = false;
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.recovery_words_acknowledged = false;
}
