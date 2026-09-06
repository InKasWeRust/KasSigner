import { networkState } from '../../app/state/index.js';
import { get_virtual_daa_score } from '../../wasm/api.js';
import { exactUnsigned } from '../exact.js';
import { resolveNodeUrl } from './resolver.js';

export function estimateCurrentDaaFromUtxos() {
    if (!networkState.utxoSnapshot?.length) return 0n;
    let maximum = 0n;
    for (const utxo of networkState.utxoSnapshot) {
        const daa = exactUnsigned(utxo.block_daa_score ?? 0n, 'block DAA score');
        if (daa > maximum) maximum = daa;
    }
    return maximum;
}

export async function fetchCurrentDaa() {
    try {
        const value = exactUnsigned(await get_virtual_daa_score(await resolveNodeUrl()), 'virtual DAA score');
        if (value > 0n) return value;
    } catch (error) {
        console.log('[KasSee] DAA RPC failed:', error, '- falling back to UTXO estimate');
    }
    return estimateCurrentDaaFromUtxos();
}
