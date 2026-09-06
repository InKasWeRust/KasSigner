import { covenantState } from '../../../state/index.js';
import { hideLoading, showLoading } from '../../../navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { covScanAddress, covScanAddressAppend } from '../../../../features/covenants/scanning_and_swap.js';
import { handleCovMwSpend, mwMaxSompi } from '../../../../features/covenants/spending/advanced.js';
import { byId } from '../../../../core/dom.js';
import { sompiToKasString } from '../../../../core/amounts.js';

export function bindMerkleWhitelistEvents() {
    // Merkle whitelist panel wiring
    if (byId('btn-cov-mw-never')) byId('btn-cov-mw-never').onclick = () => {
        const d = new Date();
        d.setFullYear(d.getFullYear() + 100);
        const pad = (n) => String(n).padStart(2, '0');
        const v = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        if (byId('cov-mw-datetime')) byId('cov-mw-datetime').value = v;
        if (byId('cov-mw-locktime')) byId('cov-mw-locktime').value = ''; // force recompute from the new far-future date
        toast('Refund blocked ~100 years out. Whitelist is now permanent.', 'ok', 2500);
    };
    if (byId('btn-cov-mw-spend')) byId('btn-cov-mw-spend').onclick = async () => {
        // Pre-fill spend panel from active covenant data
        if (covenantState.lastCovenantResult) {
            byId('cov-mw-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-mw-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
            // Restore whitelist addresses from active entry
            const activeEntry = covenantState.activeCovenants.find(c => c.address === covenantState.lastCovenantResult.address);
            const addrJson = (activeEntry && activeEntry.merkle_addresses_json) || covenantState.lastCovenantResult.merkle_addresses_json || '';
            if (addrJson) {
                try { byId('cov-mw-spend-addresses').value = JSON.parse(addrJson).join('\n'); } catch (_) {}
            }
        }
        covShowPanel('mw-spend');
        // Show the spendable max as the grayed placeholder (matches what Max fills).
        byId('cov-mw-amount').placeholder = 'Computing max...';
        try {
            const m = await mwMaxSompi();
            byId('cov-mw-amount').placeholder = m ? (sompiToKasString(m) + ' max') : 'e.g. 5.0';
        } catch (_) { byId('cov-mw-amount').placeholder = 'e.g. 5.0'; }
    };
    byId('btn-cov-mw-spend-back').onclick = () => covShowPanel('result');
    byId('btn-cov-mw-spend-create').onclick = () => handleCovMwSpend();
    if (byId('btn-cov-mw-max')) byId('btn-cov-mw-max').onclick = async () => {
        showLoading('Computing max...');
        try {
            const m = await mwMaxSompi();
            hideLoading();
            if (!m) { toast('No spendable balance', 'error'); return; }
            byId('cov-mw-amount').value = sompiToKasString(m);
        } catch (e) { hideLoading(); toast('Max failed: ' + e, 'error'); }
    };
    if (byId('btn-cov-scan-mw-addr')) byId('btn-cov-scan-mw-addr').onclick = () => covScanAddress('cov-mw-addr', 'Scan covenant address');
    byId('btn-cov-scan-mw-dest').onclick = () => covScanAddress('cov-mw-dest', 'Scan destination');
    if (byId('btn-cov-scan-mw-add')) byId('btn-cov-scan-mw-add').onclick = () => covScanAddressAppend('cov-mw-addresses', 'Scan whitelist address');
}
