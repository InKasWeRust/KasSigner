import { networkState } from '../../../../../app/state/index.js';
import { resolveFutureDaa } from '../../../../../core/node/future_daa.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covenant_commit_reveal } from '../../../../../wasm/api.js';
// commit-reveal covenant builder.

import { byId } from '../../../../../core/dom.js';
import { exactUnsigned } from '../../../../../core/exact.js';
export async function buildCommitReveal(ownerPk) {
    let resultJson;
    const extra = {};
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    const hashRaw = byId('cov-cr-hash-display').textContent.trim();
    const hashDisplay = hashRaw.startsWith('BLAKE2B: ') ? hashRaw.slice(9) : hashRaw;
    if (!hashDisplay || hashDisplay.length !== 64) { toast('Scan commitment from KasSigner first', 'error'); return; }
    let locktime = byId('cov-cr-locktime').value.trim();
    const crDatetime = byId('cov-cr-datetime') ? byId('cov-cr-datetime').value : '';
    if (crDatetime && !locktime) {
        try {
            locktime = String((await resolveFutureDaa(crDatetime)).daa);
            byId('cov-cr-locktime').value = locktime;
        } catch (error) {
            toast(error.message, 'error'); return;
        }
    }
    let locktimeDaa;
    try { locktimeDaa = exactUnsigned(locktime, 'refund timeout DAA'); } catch (_) { locktimeDaa = 0n; }
    if (locktimeDaa <= 0n) { toast('Pick a refund timeout date', 'error'); return; }
    resultJson = covenant_commit_reveal(ownerPk, hashDisplay, locktimeDaa, networkState.network);
    extra.commit_hash = hashDisplay;
    // Store ECIES ciphertext only (parts are never persisted in browser)
    const ctHex = byId('cov-cr-ciphertext-hex') ? byId('cov-cr-ciphertext-hex').value : '';
    if (ctHex) extra.cr_ciphertext_hex = ctHex;
    if (crDatetime) extra.locktime_date_iso = new Date(crDatetime).toISOString();
    return { resultJson, extra };
}
