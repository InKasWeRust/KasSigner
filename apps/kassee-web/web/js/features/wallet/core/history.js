import { networkState, walletSession, walletState } from '../../../app/state/index.js';
import { kaspaRestApiBase } from '../../../core/config/network.js';

export async function fetchAddressHistory() {
    if (!walletSession.hasWallet()) return;
    const wallet = walletSession.current();

    // Custom REST server path (user-configured, optional)
    if (walletState.addressHistoryEnabled && networkState.customRestUrl) {
        await fetchAddressHistoryCustom(wallet);
        return;
    }

    // Default path: api.kaspa.org /transactions-count
    const apiBase = kaspaRestApiBase(networkState.network);

    const check = async (addr, i, targetSet) => {
        try {
            const r = await fetch(`${apiBase}/addresses/${addr}/transactions-count`, { signal: AbortSignal.timeout(5000) });
            if (r.ok) {
                const d = await r.json();
                if (d.total > 0) targetSet.add(i);
            }
        } catch (_) {}
    };

    try {
        const promises = [
            ...wallet.receive_addresses.map((addr, i) => check(addr, i, walletState.usedReceiveIndices)),
            ...wallet.change_addresses.map((addr, i) => check(addr, i, walletState.usedChangeIndices)),
        ];
        await Promise.all(promises);
    } catch (e) {
        console.log('[KasSee] address history (default):', e);
    }
}

async function fetchAddressHistoryCustom(wallet) {
    try {
        const testUrl = `${networkState.customRestUrl}/addresses/${wallet.receive_addresses[0]}/full`;
        const probe = await fetch(testUrl, { signal: AbortSignal.timeout(5000) });
        const useFull = probe.ok;

        const check = async (addr, i, targetSet) => {
            try {
                if (useFull) {
                    const r = await fetch(`${networkState.customRestUrl}/addresses/${addr}/full`, { signal: AbortSignal.timeout(5000) });
                    if (r.ok) {
                        const d = await r.json();
                        if (d.tx_count > 0 || (d.transactions && d.transactions.length > 0)) targetSet.add(i);
                    }
                } else {
                    const r = await fetch(`${networkState.customRestUrl}/addresses/${addr}/transactions?limit=1`, { signal: AbortSignal.timeout(5000) });
                    if (r.ok) {
                        const d = await r.json();
                        const hasData = Array.isArray(d) ? d.length > 0 : (d.transactions && d.transactions.length > 0);
                        if (hasData) targetSet.add(i);
                    }
                }
            } catch (_) {}
        };

        const promises = [
            ...wallet.receive_addresses.map((addr, i) => check(addr, i, walletState.usedReceiveIndices)),
            ...wallet.change_addresses.map((addr, i) => check(addr, i, walletState.usedChangeIndices)),
        ];
        await Promise.all(promises);
    } catch (e) {
        console.log('[KasSee] address history (custom):', e);
    }
}
