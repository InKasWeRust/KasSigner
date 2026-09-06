import { networkState } from '../../../../app/state/index.js';
import { resolveFutureDaa } from '../../../../core/node/future_daa.js';
import { toast } from '../../../../core/ui/toast.js';
import { covenant_additive_address, covenant_timelocked_savings, decode_address } from '../../../../wasm/api.js';
// savings covenant builders.

import { byId } from '../../../../core/dom.js';
import { kasToSompi } from '../../../../core/amounts.js';
import { exactUnsigned } from '../../../../core/exact.js';
export async function buildAdditive(ownerPk) {
    let resultJson;
    let extra = {};
    const goalStr = byId('cov-piggy-goal').value.trim();
    let sompi = 0n;
    if (goalStr) {
        try {
            sompi = kasToSompi(goalStr);
            if (sompi <= 0n) throw new Error('Goal must be positive');
        } catch (_) {
            toast('Enter a valid positive savings goal in KAS', 'error');
            return;
        }
    }
    // Deadline: date picker to DAA
    let deadlineDaa = 0n;
    const dateVal = byId('cov-piggy-deadline') ? byId('cov-piggy-deadline').value : '';
    if (dateVal) {
        try {
            deadlineDaa = (await resolveFutureDaa(dateVal)).daa;
        } catch (error) {
            toast(error.message, 'error');
            return;
        }
    }
    resultJson = covenant_additive_address(ownerPk, sompi, deadlineDaa, networkState.network);
    if (dateVal) extra.deadline_date_iso = new Date(dateVal).toISOString();
    return { resultJson, extra };
}

export async function buildTimelockedSavings(ownerPk) {
    let resultJson;
    let extra = {};
    // Deposit-and-lock savings. wallet1 = the loaded wallet (primary).
    // wallet2 = optional independent recovery wallet; blank reuses wallet1
    // (no separate backup). No owner-spend-anytime branch: frozen for
    // everyone until the date, then 1-of-2 claim with a single signature.
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    let recoveryPk = byId('cov-savings-recovery-pk') ? byId('cov-savings-recovery-pk').value.trim() : '';
    if (!recoveryPk) {
        recoveryPk = ownerPk; // no separate recovery key
    } else if (recoveryPk.startsWith('kpub1:')) {
        toast('Paste the recovery wallet address, not a kpub', 'error'); return;
    } else if (recoveryPk.startsWith('kaspa:') || recoveryPk.startsWith('kaspatest:')) {
        try {
            const decoded = JSON.parse(decode_address(recoveryPk));
            if (decoded.version !== 0) { toast('Recovery wallet must be a standard address (P2PK)', 'error'); return; }
            if (!decoded.payload || decoded.payload.length !== 64) { toast('Could not read pubkey from that address', 'error'); return; }
            recoveryPk = decoded.payload;
            byId('cov-savings-recovery-pk').value = recoveryPk;
        } catch (e) { toast('Invalid address: ' + e, 'error'); return; }
    }
    if (recoveryPk.length !== 64) { toast('Recovery wallet pubkey must be 64 hex chars (or leave blank)', 'error'); return; }
    // Datetime-to-DAA (10 BPS), same conversion as the vault.
    let locktime = byId('cov-savings-locktime') ? byId('cov-savings-locktime').value.trim() : '';
    const sDtEl = byId('cov-savings-datetime');
    const sDtVal = sDtEl ? sDtEl.value : '';
    if (sDtVal && !locktime) {
        try {
            locktime = String((await resolveFutureDaa(sDtVal)).daa);
            if (byId('cov-savings-locktime')) byId('cov-savings-locktime').value = locktime;
        } catch (error) {
            toast(error.message, 'error');
            return;
        }
    }
    let locktimeDaa;
    try { locktimeDaa = exactUnsigned(locktime, 'unlock DAA'); } catch (_) { locktimeDaa = 0n; }
    if (locktimeDaa <= 0n) { toast('Set an unlock date (or DAA score)', 'error'); return; }
    resultJson = covenant_timelocked_savings(ownerPk, recoveryPk, locktimeDaa, networkState.network);
    extra.wallet1_pubkey_hex = ownerPk;
    extra.wallet2_pubkey_hex = recoveryPk;
    if (sDtVal) extra.locktime_date_iso = new Date(sDtVal).toISOString();
    return { resultJson, extra };
}
