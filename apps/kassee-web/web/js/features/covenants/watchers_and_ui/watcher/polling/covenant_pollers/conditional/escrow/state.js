import { covenantState } from '../../../../../../../../app/state/index.js';
import { covSaveActive } from '../../../../../../recovery/active.js';

function activeRecord() {
    const address = covenantState.lastCovenantResult.address;
    return covenantState.activeCovenants.find(record => record.address === address);
}

export function resolveEscrowCycle() {
    const result = covenantState.lastCovenantResult;
    result._escrowResolved = true;
    result._escrowFirstTxId = null;
    result._escrowPayloadChecked = null;
    result._escrowDisputed = false;
    result._escrowDisputeRole = null;
    const active = activeRecord();
    if (active) {
        active._escrowResolved = true;
        active._escrowDisputed = false;
        active._escrowDisputeRole = null;
        covSaveActive();
    }
}

export function beginEscrowCycle(transactionId) {
    const result = covenantState.lastCovenantResult;
    if (result._escrowResolved) {
        result._escrowResolved = false;
        const active = activeRecord();
        if (active) {
            active._escrowResolved = false;
            covSaveActive();
        }
    }
    if (!result._escrowFirstTxId && transactionId) result._escrowFirstTxId = transactionId;
}

export function shouldCheckDispute(transactionId) {
    const result = covenantState.lastCovenantResult;
    return !result._escrowDisputed
        && !!result._escrowFirstTxId
        && !!transactionId
        && transactionId !== result._escrowFirstTxId
        && result._escrowPayloadChecked !== transactionId;
}

export function saveEscrowDispute(transactionId, role) {
    const result = covenantState.lastCovenantResult;
    result._escrowPayloadChecked = transactionId;
    if (!role) return;
    result._escrowDisputed = true;
    result._escrowDisputeRole = role;
    const active = activeRecord();
    if (active) {
        active._escrowDisputed = true;
        active._escrowDisputeRole = role;
        covSaveActive();
    }
}
