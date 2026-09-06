import { covenantState } from '../../../../../../app/state/index.js';
import { byId } from '../../../../../../core/dom.js';

export function configureOracleV1({ beneBtn, ownerBtn, fundBtn, isLoaded, covRole }) {
    const attestBtn = byId('btn-cov-res-oracle-v1-attest');
    const bindBtn = byId('btn-cov-res-oracle-v1-bind');
    const scanBindingBtn = byId('btn-cov-res-oracle-v1-scan-binding');
    const result = covenantState.lastCovenantResult || {};
    const bound = /^[0-9a-f]{64}$/.test(result.oracle_covenant_binding_token_hex || '');
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    beneBtn.textContent = 'Claim with Oracle Attestation';
    ownerBtn.textContent = 'Owner Refund (after timeout)';
    beneBtn.style.display = 'none';
    ownerBtn.style.display = '';
    if (attestBtn) attestBtn.classList.add('hidden');
    bindBtn?.classList.add('hidden');
    scanBindingBtn?.classList.add('hidden');

    if (!bound) {
        if (fundBtn) fundBtn.style.display = 'none';
        if (!isLoaded) {
            bindBtn?.classList.remove('hidden');
            scanBindingBtn?.classList.remove('hidden');
        }
        return;
    }

    if (!isLoaded) return;
    if (covRole === 'beneficiary') {
        beneBtn.style.display = '';
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
    } else if (covRole === 'oracle' || covRole === 'observer') {
        beneBtn.style.display = 'none';
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
        if (attestBtn) attestBtn.classList.remove('hidden');
    } else if (covRole !== 'owner') {
        beneBtn.style.display = 'none';
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
        if (attestBtn) attestBtn.classList.remove('hidden');
    }
}
