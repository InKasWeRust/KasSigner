import { covenantState, walletSession } from '../../../../../../app/state/index.js';
import { byId } from '../../../../../../core/dom.js';
import { covShowPanel } from '../../../../generation/ui_and_keys.js';

export function configurePayjoinActions({ beneBtn, ownerBtn, fundBtn, isBeneficiary }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    ownerBtn.textContent = 'Owner Refund';
    beneBtn.textContent = 'PayJoin Claim';
    ownerBtn.style.display = isBeneficiary ? 'none' : '';
    if (fundBtn) fundBtn.style.display = isBeneficiary ? 'none' : '';
    beneBtn.style.display = isBeneficiary ? '' : 'none';
    beneBtn.onclick = () => {
        const result = covenantState.lastCovenantResult;
        if (result) {
            byId('cov-payjoin-claim-addr').value = result.address || '';
            byId('cov-payjoin-claim-script').value = result.redeem_script_hex || '';
        }
        const address = walletSession.primaryReceiveAddress();
        if (address) byId('cov-payjoin-claim-mix-addr').value = address;
        covShowPanel('payjoin-claim');
    };
}
