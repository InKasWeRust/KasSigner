use crate::runtime::data::AppData;
use shared_signer::bytes::zeroize_bytes;

fn derive_child_indices(ad: &mut AppData, word_count: u8, liveness: &mut dyn FnMut()) -> Result<[u16; 24], ()> {
    let mut seed = crate::runtime::signing::derive_active_seed_with_checkpoint(ad, liveness).map_err(|_| ())?;
    let index = u32::from(ad.wallet.seeds.bip85_index);
    let result = if word_count == 12 {
        offline_signer::derivation::bip85::derive_mnemonic_12(&seed.bytes, index).map(|child| {
            let mut indices = [0u16; 24];
            indices[..12].copy_from_slice(&child.indices);
            indices
        })
    } else {
        offline_signer::derivation::bip85::derive_mnemonic_24(&seed.bytes, index)
            .map(|child| child.indices)
    };
    zeroize_bytes(&mut seed.bytes);
    result.map_err(|_| ())
}

fn install_child(ad: &mut AppData, indices: [u16; 24], word_count: u8) -> Result<(), ()> {
    ad.wallet.seeds.bip85_child_indices = indices;
    let slot = ad
        .wallet
        .seeds
        .seed_mgr
        .store(&ad.wallet.seeds.bip85_child_indices, word_count, b"", 0)
        .ok_or(())?;
    crate::services::wallet_session::activate_slot(ad, slot)
    .map_err(|_| ())?;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(Bip85ShowWord {
        word_idx: 0,
        word_count,
    }));
    Ok(())
}

pub(super) fn derive_and_install(ad: &mut AppData, word_count: u8, liveness: &mut dyn FnMut()) -> Result<(), ()> {
    let indices = derive_child_indices(ad, word_count, liveness)?;
    install_child(ad, indices, word_count)
}
