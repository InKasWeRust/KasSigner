use alloc::{boxed::Box, vec::Vec};

use crate::derivation::bip32;

const MAX_SEED_SLOTS: usize = 8;

#[derive(Clone, Copy)]
pub(super) struct SigningKeyMaterial {
    pub(super) private_key: [u8; 32],
    pub(super) compressed_public_key: [u8; 33],
}

pub(super) struct SigningContext {
    num_seeds: usize,
    account_keys: [Option<bip32::ExtendedPrivKey>; MAX_SEED_SLOTS],
    account_xonly: [Option<[u8; 32]>; MAX_SEED_SLOTS],
    account_compressed: [Option<[u8; 33]>; MAX_SEED_SLOTS],
    address_tables: [Option<Box<[bip32::AddrPubkeyTable]>>; MAX_SEED_SLOTS],
    ms45_account_keys: [Option<bip32::ExtendedPrivKey>; MAX_SEED_SLOTS],
}

impl SigningContext {
    fn empty(num_seeds: usize) -> Self {
        Self {
            num_seeds: num_seeds.min(MAX_SEED_SLOTS),
            account_keys: [None, None, None, None, None, None, None, None],
            account_xonly: [None, None, None, None, None, None, None, None],
            account_compressed: [None, None, None, None, None, None, None, None],
            address_tables: [None, None, None, None, None, None, None, None],
            ms45_account_keys: [None, None, None, None, None, None, None, None],
        }
    }

    fn install_account(&mut self, index: usize, account: bip32::ExtendedPrivKey) {
        if index >= self.num_seeds {
            return;
        }
        if let Ok(compressed) = account.public_key_compressed() {
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&compressed[1..]);
            self.account_xonly[index] = Some(xonly);
            self.account_compressed[index] = Some(compressed);
            self.account_keys[index] = Some(account);
        }
    }

    pub(super) fn from_seeds(seeds: &[([u8; 64], bool)]) -> Self {
        let mut context = Self::empty(seeds.len());
        for (index, (seed, present)) in seeds.iter().take(MAX_SEED_SLOTS).enumerate() {
            if !*present {
                continue;
            }
            if let Ok(account) = bip32::derive_account_key(seed) {
                context.install_account(index, account);
            }
            if let Ok(account) = bip32::derive_multisig_account_key(seed, 0) {
                context.ms45_account_keys[index] = Some(account);
            }
        }
        context
    }

    pub(super) fn from_account_raw(accounts: &[([u8; 65], bool)]) -> Self {
        let mut context = Self::empty(accounts.len());
        for (index, (raw, present)) in accounts.iter().take(MAX_SEED_SLOTS).enumerate() {
            if *present {
                context.install_account(index, bip32::ExtendedPrivKey::from_raw(raw));
            }
        }
        context
    }

    pub(super) fn from_account_sets(
        accounts: &[([u8; 65], bool)],
        ms45_accounts: &[([u8; 65], bool)],
    ) -> Self {
        let mut context = Self::from_account_raw(accounts);
        for (index, (raw, present)) in ms45_accounts.iter().take(MAX_SEED_SLOTS).enumerate() {
            if !*present {
                continue;
            }
            if index >= context.num_seeds {
                continue;
            }
            context.ms45_account_keys[index] = Some(bip32::ExtendedPrivKey::from_raw(raw));
        }
        context
    }

    pub(super) const fn seed_count(&self) -> usize {
        self.num_seeds
    }

    pub(super) fn account_xonly(&self, seed_index: usize) -> Option<[u8; 32]> {
        self.account_xonly.get(seed_index).copied().flatten()
    }

    pub(super) fn ms45_material(
        &self,
        seed_index: usize,
        hint: &crate::transaction::model::Ms45Hint,
    ) -> Option<SigningKeyMaterial> {
        if !hint.present || hint.chain > 1 {
            return None;
        }
        let account = self.ms45_account_keys.get(seed_index)?.as_ref()?;
        let child =
            bip32::derive_multisig_address_key(account, hint.cosigner, hint.chain, hint.index)
                .ok()?;
        Some(SigningKeyMaterial {
            private_key: *child.private_key_bytes(),
            compressed_public_key: child.public_key_compressed().ok()?,
        })
    }

    pub(super) fn account_material(&self, seed_index: usize) -> Option<SigningKeyMaterial> {
        let account = self.account_keys.get(seed_index)?.as_ref()?;
        Some(SigningKeyMaterial {
            private_key: *account.private_key_bytes(),
            compressed_public_key: self.account_compressed.get(seed_index).copied().flatten()?,
        })
    }

    /// Derive a child key using the wider on-demand address scan.
    pub(super) fn direct_address_material(
        &self,
        seed_index: usize,
        target_xonly: &[u8; 32],
    ) -> Option<SigningKeyMaterial> {
        let account = self.account_keys.get(seed_index)?.as_ref()?;
        let (address_index, is_change) =
            bip32::find_address_index_for_pubkey(account, target_xonly)?;
        let key = if is_change {
            bip32::derive_change_key(account, u32::from(address_index)).ok()?
        } else {
            bip32::derive_address_key(account, u32::from(address_index)).ok()?
        };
        Some(SigningKeyMaterial {
            private_key: *key.private_key_bytes(),
            compressed_public_key: key.public_key_compressed().ok()?,
        })
    }

    /// Derive a child key using the lazily built fixed-size multisig cache.
    pub(super) fn cached_address_material(
        &mut self,
        seed_index: usize,
        target_xonly: &[u8; 32],
    ) -> Option<SigningKeyMaterial> {
        let mut no_checkpoint = || {};
        self.cached_address_material_with_checkpoint(seed_index, target_xonly, &mut no_checkpoint)
    }

    pub(super) fn cached_address_material_with_checkpoint(
        &mut self,
        seed_index: usize,
        target_xonly: &[u8; 32],
        checkpoint: &mut (impl FnMut() + ?Sized),
    ) -> Option<SigningKeyMaterial> {
        self.ensure_address_table_with_checkpoint(seed_index, checkpoint)?;
        let table = self.address_tables[seed_index].as_ref()?.first()?;
        let (address_index, is_change) = table.find_by_pubkey(target_xonly)?;
        checkpoint();
        let material = self.derived_address_material(seed_index, address_index, is_change);
        checkpoint();
        material
    }

    fn ensure_address_table_with_checkpoint(
        &mut self,
        seed_index: usize,
        checkpoint: &mut (impl FnMut() + ?Sized),
    ) -> Option<()> {
        if seed_index >= self.num_seeds {
            return None;
        }
        if self.address_tables[seed_index].is_none() {
            let account = self.account_keys[seed_index].as_ref()?;
            let mut tables = Vec::new();
            tables.try_reserve_exact(1).ok()?;
            tables.push(bip32::AddrPubkeyTable::build_with_checkpoint(
                account, checkpoint,
            ));
            self.address_tables[seed_index] = Some(tables.into_boxed_slice());
        }
        Some(())
    }

    fn derived_address_material(
        &self,
        seed_index: usize,
        address_index: u16,
        is_change: bool,
    ) -> Option<SigningKeyMaterial> {
        let account = self.account_keys[seed_index].as_ref()?;
        let key = if is_change {
            bip32::derive_change_key(account, u32::from(address_index)).ok()?
        } else {
            bip32::derive_address_key(account, u32::from(address_index)).ok()?
        };
        Some(SigningKeyMaterial {
            private_key: *key.private_key_bytes(),
            compressed_public_key: key.public_key_compressed().ok()?,
        })
    }
    #[cfg(test)]
    pub(super) fn matching_material(
        &mut self,
        target_xonly: &[u8; 32],
    ) -> Option<SigningKeyMaterial> {
        let mut no_checkpoint = || {};
        self.matching_material_with_checkpoint(target_xonly, &mut no_checkpoint)
    }

    pub(super) fn matching_material_with_checkpoint(
        &mut self,
        target_xonly: &[u8; 32],
        checkpoint: &mut (impl FnMut() + ?Sized),
    ) -> Option<SigningKeyMaterial> {
        for seed_index in 0..self.seed_count() {
            checkpoint();
            if self.account_xonly(seed_index) == Some(*target_xonly) {
                return self.account_material(seed_index);
            }
            if let Some(material) =
                self.cached_address_material_with_checkpoint(seed_index, target_xonly, checkpoint)
            {
                return Some(material);
            }
        }
        None
    }
}
