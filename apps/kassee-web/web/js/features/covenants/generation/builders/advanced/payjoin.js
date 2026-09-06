import { networkState } from '../../../../../app/state/index.js';
import { resolveFutureDaa } from '../../../../../core/node/future_daa.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covenant_payjoin } from '../../../../../wasm/api.js';
// payjoin covenant builder.

import { byId } from '../../../../../core/dom.js';
import { exactUnsigned } from '../../../../../core/exact.js';
import { addressToXOnly } from '../../../../../core/address.js';
export async function buildPayjoin(ownerPk) {
    let resultJson;
    const extra = {};
    const benePk = addressToXOnly(byId('cov-payjoin-bene-pk').value);
    let locktime = byId('cov-payjoin-locktime').value.trim();
    const pjDatetime = byId('cov-payjoin-datetime') ? byId('cov-payjoin-datetime').value : '';
    if (pjDatetime && !locktime) {
        try {
            locktime = String((await resolveFutureDaa(pjDatetime)).daa);
            byId('cov-payjoin-locktime').value = locktime;
        } catch (error) {
            toast(error.message, 'error');
            return;
        }
    }
    const minInputs = byId('cov-payjoin-min-inputs').value.trim() || '2';
    const minOutputs = byId('cov-payjoin-min-outputs').value.trim() || '2';
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    if (!benePk || benePk.length !== 64) { toast('Enter beneficiary pubkey (64 hex chars)', 'error'); return; }
    let locktimeDaa;
    try { locktimeDaa = exactUnsigned(locktime, 'refund timeout DAA'); } catch (_) { locktimeDaa = 0n; }
    if (locktimeDaa <= 0n) { toast('Pick a refund timeout date', 'error'); return; }
    resultJson = covenant_payjoin(ownerPk, benePk, locktimeDaa, BigInt(minInputs), BigInt(minOutputs), networkState.network);
    extra.beneficiary_pubkey_hex = benePk;
    extra.min_inputs = parseInt(minInputs);
    extra.min_outputs = parseInt(minOutputs);
    if (pjDatetime) extra.locktime_date_iso = new Date(pjDatetime).toISOString();
    return { resultJson, extra };
}
