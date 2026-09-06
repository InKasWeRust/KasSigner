import { covenantState } from '../../../../app/state/index.js';
// KasSee Web — covenant result-button façade.
import { byId } from '../../../../core/dom.js';
import { configurePrimaryCoreActions } from './result_buttons/primary_core.js';
import { configurePrimaryAdvancedActions } from './result_buttons/primary_advanced.js';
import { configureAuxiliaryResultActions } from './result_buttons/auxiliary.js';


function configurePrimaryResultActions(state) {
    if (!configurePrimaryCoreActions(state)) {
        configurePrimaryAdvancedActions(state);
    }
}

export function covUpdateResultButtons(type) {
    const beneBtn = byId('btn-cov-res-bene');
    const ownerBtn = byId('btn-cov-res-owner');
    const consolBtn = byId('btn-cov-res-consolidate');
    const fundBtn = byId('btn-cov-fund');
    if (!beneBtn) return;
    byId('btn-cov-res-oracle-v1-attest')?.classList.add('hidden');
    byId('btn-cov-res-oracle-v1-bind')?.classList.add('hidden');
    byId('btn-cov-res-oracle-v1-scan-binding')?.classList.add('hidden');
    byId('crowdfund-result-panel')?.classList.add('hidden');
    if (fundBtn) fundBtn.style.display = '';
    beneBtn.style.display = '';
    ownerBtn.style.display = '';
    if (consolBtn) consolBtn.style.display = 'none';

    const isLoaded = covenantState.lastCovenantResult && covenantState.lastCovenantResult.loaded;
    const covRole = covenantState.lastCovenantResult && covenantState.lastCovenantResult.role;
    const isBeneficiary = isLoaded && covRole === 'beneficiary';
    const hasTimelockType = ['dms', 'escrow', 'timelocked-escrow', 'global-allowance'].includes(type);
    if (isBeneficiary && hasTimelockType) {
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
    }

    const state = { type, beneBtn, ownerBtn, consolBtn, fundBtn, isLoaded, covRole, isBeneficiary };
    configurePrimaryResultActions(state);
    configureAuxiliaryResultActions(state);
}
