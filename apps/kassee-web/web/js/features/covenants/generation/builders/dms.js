import { networkState } from '../../../../app/state/index.js';
import { toast } from '../../../../core/ui/toast.js';
import { covenant_dms, decode_address } from '../../../../wasm/api.js';
// dms covenant builders.

import { byId } from '../../../../core/dom.js';
import { exactJsonStringify, exactUnsigned } from '../../../../core/exact.js';
export async function buildDms(ownerPk) {
    let resultJson;
    let extra = {};
    let heirPk = byId('cov-dms2-heir-pk').value.trim();
    // Heir is given as a single Kaspa address. Decode it to the x-only
    // pubkey that the ELSE branch's CHECKSIG needs.
    if (heirPk.startsWith('kpub1:')) {
        toast('Paste the heir address, not a kpub', 'error'); return;
    }
    if (heirPk.startsWith('kaspa:') || heirPk.startsWith('kaspatest:')) {
        try {
            const decoded = JSON.parse(decode_address(heirPk));
            if (decoded.version !== 0) {
                toast('Heir must be a standard address (P2PK), not a script address', 'error'); return;
            }
            if (!decoded.payload || decoded.payload.length !== 64) {
                toast('Could not read pubkey from that address', 'error'); return;
            }
            heirPk = decoded.payload;
            byId('cov-dms2-heir-pk').value = heirPk;
        } catch (e) {
            toast('Invalid address: ' + e, 'error'); return;
        }
    }
    // Convert duration to DAA units (10 BPS)
    let durationSec;
    try { durationSec = exactUnsigned(byId('cov-dms2-duration').value.trim() || '0', 'inactivity seconds'); }
    catch (_) { durationSec = 0n; }
    if (durationSec <= 0n) { toast('Set an inactivity period', 'error'); return; }
    const inactivityDaa = durationSec * 10n;
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    if (!heirPk || heirPk.length !== 64) { toast('Enter the heir Kaspa address', 'error'); return; }
    resultJson = covenant_dms(ownerPk, heirPk, inactivityDaa, networkState.network);
    // Inject inactivity_daa into result for storage
    const dmsResult = JSON.parse(resultJson);
    dmsResult.inactivity_daa = inactivityDaa;
    resultJson = exactJsonStringify(dmsResult);
    extra.heir_pubkey_hex = heirPk;
    return { resultJson, extra };
}
