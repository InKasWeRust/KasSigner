// Canonical identity helpers for send coin control. Selection follows outpoints,
// never presentation indexes, so sorting/re-rendering cannot change what is spent.
export function utxoId(utxo) {
    return `${utxo.tx_id}:${utxo.index}`;
}

export function selectedUtxos(utxos, selectedIds) {
    if (!selectedIds?.length || !utxos) return [];
    const wanted = new Set(selectedIds);
    return utxos.filter(utxo => wanted.has(utxoId(utxo)));
}

export function selectedUtxoIndices(utxos, selectedIds) {
    if (!selectedIds?.length || !utxos) return [];
    const wanted = new Set(selectedIds);
    const indices = [];
    utxos.forEach((utxo, index) => { if (wanted.has(utxoId(utxo))) indices.push(index); });
    return indices;
}
