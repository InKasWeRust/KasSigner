import { hexToBytes } from '../../../../core/bytes.js';
import { covenantRecoveryState, covenantState } from '../../../state/index.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel, walletMatchesPk } from '../../../../features/covenants/generation/ui_and_keys.js';
import { covAddActive } from '../../../../features/covenants/recovery/active.js';
import { covRenderMetaLine, ensureAllowanceParams, ensureEscrowParams } from '../../../../features/covenants/watchers_and_ui/ui/metadata.js';
import { covUpdateResultButtons } from '../../../../features/covenants/watchers_and_ui/ui/result_buttons.js';
import { byId } from '../../../../core/dom.js';

export function bindLoadSubmissionAction() {
    byId('btn-cov-load-submit').onclick = () => {
        const addr = byId('cov-load-addr').value.trim();
        const script = byId('cov-load-script').value.trim();
        const type = byId('cov-load-type').value;
        if (!addr) { toast('Enter covenant address', 'error'); return; }
        if (!script) { toast('Enter redeem script hex', 'error'); return; }
        // Auto-extract locktime from redeem script (find push before 0xb0=CLTV or 0xb1=CSV)
        let locktime = null;
        try {
            const bytes = hexToBytes(script);
            let lastPush = 0n;
            let i = 0;
            while (i < bytes.length) {
                const op = bytes[i];
                if (op === 0xb0 || op === 0xb1) { locktime = lastPush; break; }
                if (op === 0x00) { lastPush = 0n; i++; }
                else if (op >= 0x51 && op <= 0x60) { lastPush = BigInt(op - 0x50); i++; }
                else if (op >= 0x01 && op <= 0x4b) {
                    const len = op;
                    if (i + 1 + len <= bytes.length) {
                        let val = 0n;
                        for (let j = 0; j < len; j++) val |= BigInt(bytes[i + 1 + j]) << BigInt(j * 8);
                        lastPush = val;
                    }
                    i += 1 + len;
                } else if (op === 0x4c) {
                    const len = bytes[i + 1] || 0;
                    i += 2 + len;
                } else { i++; }
            }
        } catch (_) {}
        const result = {
            address: addr,
            redeem_script_hex: script,
            locktime_daa: locktime,
            type: type,
            loaded: true,
            role: covenantRecoveryState._covLoadedFromInvite ? 'beneficiary' : undefined,
        };
        if (covenantRecoveryState._covLoadedInactivityDaa) result.inactivity_daa = covenantRecoveryState._covLoadedInactivityDaa;
        // Restore locktime ISO date from invite (ldi field)
        if (covenantRecoveryState._covLoadedLdi) { result.locktime_date_iso = covenantRecoveryState._covLoadedLdi; covenantRecoveryState._covLoadedLdi = null; }
        covenantRecoveryState._covLoadedFromInvite = false;
        covenantRecoveryState._covLoadedInactivityDaa = null;
        // Escrow: detect role from script pubkeys vs loaded wallet
        if (result.type === 'escrow' && result.role === 'beneficiary') {
            ensureEscrowParams(result);
            const matchesPk = (target) => walletMatchesPk(target);
            if (matchesPk(result.arbiter_pk)) {
                result.role = 'arbiter';
            } else if (matchesPk(result.alice_pk)) {
                result.role = 'owner';
            }
        }
        covenantState.lastCovenantResult = result;
        ensureAllowanceParams(covenantState.lastCovenantResult);
        try { sessionStorage.setItem('lastCovenantResult', JSON.stringify(covenantState.lastCovenantResult)); } catch (_) {}
        covAddActive(type, result);
        covShowPanel('result');
        covUpdateResultButtons(type);
        byId('cov-result-addr').textContent = result.address;
        byId('cov-result-script').textContent = result.redeem_script_hex;
        covRenderMetaLine(result);
        byId('cov-result-balance').style.display = 'none';
        toast('Covenant loaded' + (locktime ? ' (locktime: DAA ' + locktime + ')' : ''), 'ok', 2000);
    };

}
