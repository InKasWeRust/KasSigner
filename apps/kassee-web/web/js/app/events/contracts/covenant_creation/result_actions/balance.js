import { covenantState } from '../../../../state/index.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { fetch_utxos_for_address_js } from '../../../../../wasm/api.js';
// KasSee Web — focused covenant result action registration.

import { byId } from '../../../../../core/dom.js';
import { sompiToKasString } from '../../../../../core/amounts.js';
export function registerBalanceAction() {
    byId('btn-cov-res-balance').onclick = async () => {
        if (!covenantState.lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        const balEl = byId('cov-result-balance');
        balEl.style.display = 'block';
        balEl.textContent = 'Loading...';
        try {
            const wsUrl = await resolveNodeUrl();
            const utxosJson = await fetch_utxos_for_address_js(covenantState.lastCovenantResult.address, wsUrl);
            const utxos = JSON.parse(utxosJson);
            const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
            const kasStr = sompiToKasString(total);
            balEl.textContent = kasStr + ' KAS (' + utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ')';
            // Piggy bank: toggle Deposit vs Add Funds on fundBtn based on UTXO count
            if (covenantState.lastCovenantResult.type === 'additive') {
                const fundBtnP = byId('btn-cov-fund');
                if (fundBtnP) {
                    if (utxos.length === 0) {
                        fundBtnP.textContent = 'Covenant Deposit';
                        fundBtnP.dataset.piggyMode = 'deposit';
                    } else {
                        fundBtnP.textContent = 'Add Funds';
                        fundBtnP.dataset.piggyMode = 'add';
                    }
                }
            }
        } catch (e) {
            balEl.textContent = 'Error: ' + e;
        }
    };
}
