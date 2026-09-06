import { setSafeMarkup } from '../../../../../../../../core/security/safe_html.js';
import { covenantState } from '../../../../../../../../app/state/index.js';

export function renderEscrowResolved(status) {
    status.innerHTML = '<span class="u-text-teal">✅ Escrow resolved. Funds released.</span>';
    status.style.display = '';
}

export function renderEscrowEmpty(status) {
    if (covenantState.lastCovenantResult._escrowResolved) {
        renderEscrowResolved(status);
    } else {
        status.textContent = '⚖️ Awaiting deposit.';
        status.style.color = '';
    }
}

export function renderEscrowFunded(status, kas) {
    if (covenantState.lastCovenantResult._escrowDisputed) {
        const role = covenantState.lastCovenantResult._escrowDisputeRole || 'party';
        setSafeMarkup(status, `<span class="u-text-warning">⚖️ Arbitration requested by ${role}. ${kas.toFixed(2)} KAS locked.</span>`);
    } else {
        status.textContent = `⚖️ ${kas.toFixed(2)} KAS locked. Awaiting resolution.`;
        status.style.color = '';
    }
    status.style.display = '';
}
