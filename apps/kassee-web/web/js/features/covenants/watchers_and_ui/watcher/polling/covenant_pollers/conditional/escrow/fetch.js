import { kaspaRestApiBase } from '../../../../../../../../core/config/network.js';
import { networkState } from '../../../../../../../../app/state/index.js';

function apiBase() {
    return kaspaRestApiBase(networkState.network);
}

export async function fetchEscrowDispute(transactionId) {
    try {
        const response = await fetch(`${apiBase()}/transactions/${transactionId}`, {
            signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) return null;
        const payload = (await response.json()).payload || '';
        if (!payload.startsWith('4553434400')) return null;
        return payload.slice(10, 12) === '01' ? 'buyer' : 'seller';
    } catch (_) {
        return null;
    }
}
