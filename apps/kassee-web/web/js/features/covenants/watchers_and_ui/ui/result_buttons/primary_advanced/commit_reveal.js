import { commitRevealState, covenantState } from '../../../../../../app/state/index.js';
import { hexToBytes } from '../../../../../../core/bytes.js';
import { toast } from '../../../../../../core/ui/toast.js';
import { byId } from '../../../../../../core/dom.js';
import { covShowPanel } from '../../../../generation/ui_and_keys.js';

export function configureCommitRevealActions({ beneBtn, ownerBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    ownerBtn.textContent = 'Owner Refund';
    beneBtn.textContent = 'Reveal & Spend';
    beneBtn.style.display = '';
    beneBtn.onclick = () => {
        const result = covenantState.lastCovenantResult;
        if (!result) return;
        const ciphertext = result.cr_ciphertext_hex || '';
        if (!ciphertext) {
            toast('No ciphertext found. Recover from backup file first.', 'error', 4000);
            return;
        }
        byId('cov-cr-addr').value = result.address || '';
        byId('cov-cr-script').value = result.redeem_script_hex || '';
        commitRevealState._crDecryptCtBytes = hexToBytes(ciphertext);
        covShowPanel('cr-reveal');
    };
}
