import { networkState } from '../../../../../app/state/index.js';
import { resolveFutureDaa } from '../../../../../core/node/future_daa.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covenant_merkle_whitelist, merkle_root_from_addresses } from '../../../../../wasm/api.js';
// merkle-whitelist covenant builder.

import { byId } from '../../../../../core/dom.js';
import { exactUnsigned } from '../../../../../core/exact.js';
export async function buildMerkleWhitelist(ownerPk) {
    let resultJson;
    const extra = {};
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    // Compute the merkle root inline from the whitelist (no separate button).
    const mwText = byId('cov-mw-addresses').value.trim();
    if (!mwText) { toast('Enter whitelisted addresses', 'error'); return; }
    const mwAddrList = mwText.split('\n').map(a => a.trim()).filter(a => a.length > 0);
    if (mwAddrList.length < 2) { toast('Need at least 2 whitelisted addresses', 'error'); return; }
    let rootInfo;
    try {
        rootInfo = JSON.parse(merkle_root_from_addresses(JSON.stringify(mwAddrList)));
    } catch (e) {
        toast('Merkle root failed: ' + e, 'error');
        return;
    }
    // Datetime-to-DAA conversion
    let locktime = byId('cov-mw-locktime').value.trim();
    const mwDatetimeEl = byId('cov-mw-datetime');
    const mwDatetimeVal = mwDatetimeEl ? mwDatetimeEl.value : '';
    if (mwDatetimeVal && !locktime) {
        try {
            locktime = String((await resolveFutureDaa(mwDatetimeVal)).daa);
            byId('cov-mw-locktime').value = locktime;
        } catch (error) {
            toast(error.message, 'error');
            return;
        }
    }
    let locktimeDaa;
    try { locktimeDaa = exactUnsigned(locktime, 'refund timeout DAA'); } catch (_) { locktimeDaa = 0n; }
    if (locktimeDaa <= 0n) { toast('Pick a refund timeout date', 'error'); return; }
    resultJson = covenant_merkle_whitelist(ownerPk, rootInfo.root, rootInfo.depth, locktimeDaa, networkState.network);
    // Capture whitelist addresses for payload backup and proof generation
    const mwAddrs = byId('cov-mw-addresses').value.trim().split('\n').map(a => a.trim()).filter(a => a.length > 0);
    const mwResult = JSON.parse(resultJson);
    mwResult.merkle_addresses_json = JSON.stringify(mwAddrs);
    mwResult.merkle_root = rootInfo.root;
    mwResult.merkle_depth = rootInfo.depth;
    if (mwDatetimeVal) mwResult.locktime_date_iso = new Date(mwDatetimeVal).toISOString();
    resultJson = JSON.stringify(mwResult);
    return { resultJson, extra };
}
