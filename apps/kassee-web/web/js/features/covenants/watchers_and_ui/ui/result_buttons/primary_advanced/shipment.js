import { covenantState } from '../../../../../../app/state/index.js';
import { byId } from '../../../../../../core/dom.js';
import { covShowPanel } from '../../../../generation/ui_and_keys.js';

function shipmentButton() {
    let button = byId('btn-cov-ship-open');
    if (button) return button;
    button = document.createElement('button');
    button.id = 'btn-cov-ship-open';
    button.className = 'btn btn-outline shipment-result-action';
    button.textContent = 'Operate Shipment Escrow';
    const backButton = byId('btn-cov-result-back');
    if (backButton) backButton.parentElement.insertBefore(button, backButton);
    return button;
}

export function configureShipmentActions({ beneBtn, ownerBtn, fundBtn, isLoaded }) {
    const isCreator = covenantState.lastCovenantResult?.is_creator || !isLoaded;
    if (fundBtn) {
        fundBtn.textContent = 'Fund Covenant (total)';
        fundBtn.style.display = isCreator ? '' : 'none';
    }
    ownerBtn.style.display = 'none';
    beneBtn.style.display = 'none';
    const button = shipmentButton();
    button.style.display = '';
    button.onclick = () => {
        const result = covenantState.lastCovenantResult;
        if (result) {
            byId('cov-ship-addr').value = result.address || '';
            byId('cov-ship-script').value = result.redeem_script_hex || '';
        }
        covShowPanel('ship');
    };
}
