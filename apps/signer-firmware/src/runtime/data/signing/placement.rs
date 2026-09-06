//! Stack-bounded in-place construction of `SigningState`.

use super::{
    AntiKleptoSigningState, CommitRevealState, CovenantSigningState, MessageSigningState,
    MultisigState, PrivateSwapState, SigningState, TransactionSigningState,
};

#[inline(never)]
unsafe fn place_transaction(
    target: *mut TransactionSigningState,
    transaction: TransactionSigningState,
) {
    target.write(transaction);
}

#[inline(never)]
unsafe fn place_multisig(target: *mut MultisigState) {
    target.write(MultisigState::new());
}

#[inline(never)]
unsafe fn place_message(target: *mut MessageSigningState) {
    target.write(MessageSigningState::new());
}

#[inline(never)]
unsafe fn place_commit_reveal(target: *mut CommitRevealState) {
    target.write(CommitRevealState::new());
}

#[inline(never)]
unsafe fn place_covenant(target: *mut CovenantSigningState) {
    target.write(CovenantSigningState::new());
}

#[inline(never)]
unsafe fn place_private_swap(target: *mut PrivateSwapState) {
    target.write(PrivateSwapState::new());
}

#[inline(never)]
unsafe fn place_anti_klepto(target: *mut AntiKleptoSigningState) {
    target.write(AntiKleptoSigningState::new());
}

#[inline(never)]
pub(super) fn try_prepare_transaction() -> Result<TransactionSigningState, ()> {
    TransactionSigningState::try_new()
}

#[inline(never)]
pub(super) unsafe fn initialize_in_place(
    target: *mut SigningState,
    transaction: TransactionSigningState,
) {
    place_transaction(core::ptr::addr_of_mut!((*target).transaction), transaction);
    place_multisig(core::ptr::addr_of_mut!((*target).multisig));
    place_message(core::ptr::addr_of_mut!((*target).message));
    place_commit_reveal(core::ptr::addr_of_mut!((*target).commit_reveal));
    place_covenant(core::ptr::addr_of_mut!((*target).covenant));
    place_private_swap(core::ptr::addr_of_mut!((*target).private_swap));
    place_anti_klepto(core::ptr::addr_of_mut!((*target).anti_klepto));
}
