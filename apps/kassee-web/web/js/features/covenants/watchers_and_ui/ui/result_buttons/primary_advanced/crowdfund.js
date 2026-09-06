import { byId } from '../../../../../../core/dom.js';
import { renderCrowdfundResult } from '../../../../crowdfund/sweep.js';

export function configureCrowdfundActions({ beneBtn, ownerBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Contribution Deposit';
    beneBtn.style.display = 'none';
    ownerBtn.style.display = '';
    ownerBtn.textContent = 'Timeout Refund';
    byId('btn-cov-res-share-cov')?.style.setProperty('display', 'none');
    renderCrowdfundResult();
}
