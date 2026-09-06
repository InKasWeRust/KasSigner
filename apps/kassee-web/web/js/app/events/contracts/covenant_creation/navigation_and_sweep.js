import { covenantState } from '../../../state/index.js';
import { covShowPanel, covTypeChanged } from '../../../../features/covenants/generation/ui_and_keys.js';
// KasSee Web — app/events/contracts/covenant_creation/navigation_and_sweep
import { byId } from '../../../../core/dom.js';


export function covSelectType(type) {
    const advancedTypes = ['commit-reveal', 'merkle-whitelist'];
    if (advancedTypes.includes(type)) {
        byId('cov-type').value = type;
        covTypeChanged();
        covShowPanel('create');
        return;
    }
    byId('cov-type').value = type;
    covTypeChanged();
    covShowPanel('create');
}

function registerCovenantNavigation() {
    // Covenant++ navigation: card-based type selection

    // Event delegation for covenant category toggles and type cards
    document.addEventListener('click', function(e) {
        // Covenant fee level buttons
        const feeBtn = e.target.closest('.cov-fee-btn');
        if (feeBtn) {
            covenantState.covFeeLevel = feeBtn.dataset.covFee || 'normal';
            feeBtn.parentElement.querySelectorAll('.cov-fee-btn').forEach(b => b.classList.remove('cov-fee-active'));
            feeBtn.classList.add('cov-fee-active');
            return;
        }
        // Category header toggle
        const catHeader = e.target.closest('.cov-cat-header');
        if (catHeader) {
            catHeader.parentElement.classList.toggle('collapsed');
            return;
        }
        // Covenant type card selection
        const card = e.target.closest('[data-cov-type]');
        if (card) {
            covSelectType(card.dataset.covType);
            return;
        }
        // Panel shortcut cards (e.g. Private Swap hub)
        const panelCard = e.target.closest('[data-cov-panel]');
        if (panelCard) {
            covShowPanel(panelCard.dataset.covPanel);
            return;
        }
    });

    byId('btn-cov-create-back').onclick = () => covShowPanel('menu');
    byId('btn-cov-result-back').onclick = () => covShowPanel('menu');


}



export function registerNavigationAndSweep() {
    registerCovenantNavigation();
}
