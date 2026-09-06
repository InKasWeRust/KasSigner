import { covenantState, covenantWatcherState } from '../../../../../../../../app/state/index.js';
import { ensureEscrowParams } from '../../../../../ui/metadata.js';
import { fetchEscrowDispute } from './fetch.js';
import { renderEscrowEmpty, renderEscrowFunded, renderEscrowResolved } from './render.js';
import { beginEscrowCycle, resolveEscrowCycle, saveEscrowDispute, shouldCheckDispute } from './state.js';

export async function pollEscrow(state) {
    const { total, kas, st: status, utxos } = state;
    ensureEscrowParams(covenantState.lastCovenantResult);

    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null && covenantWatcherState._covWatcherLastBalance > 0n) {
        resolveEscrowCycle();
        renderEscrowResolved(status);
        return false;
    }
    if (total === 0n) {
        renderEscrowEmpty(status);
        return false;
    }

    const transactionId = utxos[0]?.tx_id || '';
    beginEscrowCycle(transactionId);
    if (shouldCheckDispute(transactionId)) {
        saveEscrowDispute(transactionId, await fetchEscrowDispute(transactionId));
    }
    renderEscrowFunded(status, kas);
    return false;
}
