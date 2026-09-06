import { toast } from '../../../../../core/ui/toast.js';
const TYPE_LABELS = {
    dms: 'DMS',
    'timelocked-savings': 'Time-Locked Savings',
    'global-allowance': 'Global Allowance',
    additive: 'Piggy Bank',
    'commit-reveal': 'Commit-Reveal',
};

export function notifyCovenantSpend(_context, type, path) {
    const label = TYPE_LABELS[type] || type;
    const message = path === 'heir'
        ? heirMessage(type, label)
        : path === 'owner'
            ? ownerMessage(type, label)
            : `${label}: Funds spent on chain`;
    if (!message) return;
    toast(message, 'ok', path === 'heir' ? 5000 : 3000);
}

function heirMessage(type, label) {
    if (type === 'dms') return `${label}: Heir claimed (inactivity timeout)`;
    if (type === 'global-allowance') return `${label}: Beneficiary withdrew`;
    if (type === 'additive') return `${label}: Piggy bank broken!`;
    if (type === 'commit-reveal') return `${label}: Secret revealed and spent!`;
    if (type === 'escrow') return null;
    return `${label}: Beneficiary claimed the funds!`;
}

function ownerMessage(type, label) {
    if (type === 'dms') return `${label}: Owner heartbeat or withdrawal`;
    if (type === 'global-spending-limit' || type === 'global-allowance') return null;
    if (type === 'additive') return `${label}: Owner broke the piggy bank`;
    if (type === 'commit-reveal') return `${label}: Owner refunded (no reveal)`;
    if (type === 'escrow') return null;
    return `${label}: Owner reclaimed`;
}
