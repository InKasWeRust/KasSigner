import { byId } from '../../../../../../core/dom.js';

const SHAREABLE_TYPES = new Set([
    'additive', 'dms', 'timelocked-savings', 'escrow', 'timelocked-escrow',
    'global-allowance', 'treasury', 'payjoin', 'oracle-v1',
]);

export function configureInviteSharing({ type, covRole, isBeneficiary }) {
    const button = byId('btn-cov-res-share-cov');
    if (!button) return;
    const hidden = isBeneficiary
        || (type === 'escrow' && covRole && covRole !== 'owner')
        || (type === 'oracle-v1' && covRole && covRole !== 'owner');
    button.style.display = SHAREABLE_TYPES.has(type) && !hidden ? '' : 'none';
    button.textContent = type === 'additive'
        ? '📤 Share Piggy Bank Address'
        : type === 'oracle-v1' ? '📤 Share with Beneficiary / Oracle'
            : '📤 Share Covenant Invite QR';
}
