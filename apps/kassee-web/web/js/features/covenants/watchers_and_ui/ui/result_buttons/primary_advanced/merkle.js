import { covenantState } from '../../../../../../app/state/index.js';
import { byId } from '../../../../../../core/dom.js';
import { covShowPanel } from '../../../../generation/ui_and_keys.js';

export function configureMerkleActions({ beneBtn, ownerBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    ownerBtn.textContent = 'Owner Refund';
    beneBtn.textContent = 'Whitelisted Spend';
    beneBtn.style.display = '';
    beneBtn.onclick = () => {
        const result = covenantState.lastCovenantResult;
        if (result) {
            byId('cov-mw-addr').value = result.address || '';
            byId('cov-mw-script').value = result.redeem_script_hex || '';
            const active = covenantState.activeCovenants.find(item => item.address === result.address);
            const addressesJson = active?.merkle_addresses_json || result.merkle_addresses_json || '';
            if (addressesJson) {
                try { byId('cov-mw-spend-addresses').value = JSON.parse(addressesJson).join('\n'); } catch (_) {}
            }
        }
        covShowPanel('mw-spend');
    };
}
