use crate::runtime::data::AppData;
use shared_signer::bytes::zeroize_u16;

pub(super) fn advance_word(ad: &mut AppData, word_idx: u8, word_count: u8, is_back: bool) {
    if is_back || word_idx + 1 >= word_count {
        zeroize_u16(&mut ad.wallet.seeds.bip85_child_indices);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
        return;
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(Bip85ShowWord {
        word_idx: word_idx + 1,
        word_count,
    }));
}
