use super::*;
use crate::derivation::bip32::{derive_account_key, derive_address_key, derive_change_key};

#[test]
fn hinted_derivation_checks_branch_and_index_boundaries_independently() {
    let account = derive_account_key(&[0x31; 64]).expect("account");
    let receive = derive_address_key(&account, 0)
        .expect("receive")
        .public_key_x_only()
        .unwrap();
    let change = derive_change_key(&account, 0)
        .expect("change")
        .public_key_x_only()
        .unwrap();
    let mut checkpoints = 0usize;
    let mut checkpoint = || checkpoints += 1;

    assert!(
        derive_hinted_input_key(&account, 1, 0, &change, &mut checkpoint)
            .unwrap()
            .is_some()
    );
    assert!(
        derive_hinted_input_key(&account, 2, 0, &receive, &mut checkpoint)
            .unwrap()
            .is_none()
    );
    assert!(derive_hinted_input_key(
        &account,
        0,
        shared_signer::pairing::SOFT_INDEX_LIMIT,
        &receive,
        &mut checkpoint,
    )
    .unwrap()
    .is_none());
}
