
export function pickThread(utxos, expectedG) {
    const list = Array.isArray(utxos) ? utxos : [];
    const isTagged = (u) => u && u.covenant_id && !/^0+$/.test(String(u.covenant_id));
    const g = (expectedG && !/^0+$/.test(String(expectedG))) ? String(expectedG).toLowerCase() : '';
    let thread = null;
    let ambiguous = false;
    if (g) {
        // Known thread id: the thread is the UTXO tagged with exactly this G.
        thread = list.find(u => isTagged(u) && String(u.covenant_id).toLowerCase() === g) || null;
    } else {
        // No known G: the lone tagged UTXO is the thread. More than one tagged and
        // no G to match is ambiguous, so do not guess (G is recomputable, an
        // attacker could plant a tagged decoy).
        const tagged = list.filter(isTagged);
        if (tagged.length === 1) thread = tagged[0];
        else if (tagged.length > 1) ambiguous = true;
    }
    const external = list.filter(u => u !== thread);
    const externalSompi = external.reduce((s, u) => s + BigInt(u.amount || 0), 0n);
    return { thread, external, externalSompi, ambiguous };
}
