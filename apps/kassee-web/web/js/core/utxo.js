import { exactUnsigned } from './exact.js';

export function utxoTransactionId(utxo) {
    return utxo.tx_id
        ?? utxo.transactionId
        ?? utxo.outpoint?.transactionId
        ?? utxo.previousOutpoint?.transactionId
        ?? null;
}

export function normalizeUtxo(utxo) {
    return {
        ...utxo,
        amount: exactUnsigned(utxo.amount, 'UTXO amount'),
        block_daa_score: exactUnsigned(utxo.block_daa_score ?? 0, 'UTXO DAA score'),
    };
}

export function normalizeUtxos(utxos) {
    return utxos.map(normalizeUtxo);
}

export function parseUtxosJson(json) {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) throw new Error('UTXO response must be an array');
    return normalizeUtxos(parsed);
}

export function sortUtxosLargestFirst(utxos) {
    utxos.sort((left, right) => {
        const leftAmount = exactUnsigned(left.amount, 'UTXO amount');
        const rightAmount = exactUnsigned(right.amount, 'UTXO amount');
        if (leftAmount === rightAmount) {
            const txOrder = String(left.tx_id ?? '').localeCompare(String(right.tx_id ?? ''));
            return txOrder || Number(left.index ?? 0) - Number(right.index ?? 0);
        }
        return leftAmount > rightAmount ? -1 : 1;
    });
    return utxos;
}
