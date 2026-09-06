import { setSafeMarkup } from '../../../../../../core/security/safe_html.js';
import { covenantWatcherState } from '../../../../../../app/state/index.js';
import { formatDaaDuration } from '../../../../../../core/format.js';

export async function pollTimedBalance(state, labels) {
    const { total, kas, st, locktime, currentDaa } = state;
    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null && covenantWatcherState._covWatcherLastBalance > 0n) {
        const spender = covenantWatcherState._covWatcherSpendPath || 'unknown';
        setSafeMarkup(st, '<span class="u-text-teal">✅ ' + labels.spent(spender) + '</span>');
        if (labels.onSpent) labels.onSpent();
        if (st) st.style.display = '';
        return true;
    }
    if (total === 0n) {
        st.textContent = '👁 0 KAS | Not funded';
        st.style.color = '';
    } else if (locktime > 0n && currentDaa > 0n && currentDaa >= locktime + 300n) {
        setSafeMarkup(st, '<span class="' + labels.availableClass + '">' + labels.available(kas) + '</span>');
    } else if (locktime > 0n && currentDaa > 0n && currentDaa >= locktime) {
        setSafeMarkup(st, '<span class="' + labels.unlockingClass + '">' + labels.unlocking(kas) + '</span>');
    } else if (locktime > 0n && currentDaa > 0n) {
        st.textContent = labels.locked(kas, formatDaaDuration(locktime - currentDaa));
        st.style.color = '';
    } else {
        st.textContent = labels.watching(kas);
        st.style.color = '';
    }
    if (st) st.style.display = '';
    return false;
}

function claimLabels({ ownerSpent, claimSpent, claimAvailable, refundAvailable }) {
    return {
        spent: spender => spender === 'owner' ? ownerSpent : claimSpent,
        availableClass: 'u-text-warning',
        available: refundAvailable,
        unlockingClass: 'u-text-warning',
        unlocking: kas => '⏳ ' + kas + ' KAS | Timeout passing...',
        locked: (kas, timeStr) => '👁 ' + kas + ' KAS | Refund in ~' + timeStr + ' | ' + claimAvailable,
        watching: kas => '👁 ' + kas + ' KAS | Watching...',
    };
}

export async function pollMerkleWhitelist(state) {
    return pollTimedBalance(state, claimLabels({
        ownerSpent: 'Owner refunded.',
        claimSpent: 'Spent to whitelisted address.',
        claimAvailable: 'Whitelisted spend available now',
        refundAvailable: kas => '✅ ' + kas + ' KAS | Refund available now',
    }));
}

export async function pollPayjoin(state) {
    return pollTimedBalance(state, claimLabels({
        ownerSpent: 'Owner refunded.',
        claimSpent: 'PayJoin claimed.',
        claimAvailable: 'Claim available now',
        refundAvailable: kas => '⚠ ' + kas + ' KAS | Refund available. Claim still open.',
    }));
}

export async function pollCommitReveal(state) {
    return pollTimedBalance(state, claimLabels({
        ownerSpent: 'Owner refunded.',
        claimSpent: 'Preimage revealed. Funds spent.',
        claimAvailable: 'Reveal available',
        refundAvailable: kas => '⚠ ' + kas + ' KAS | Refund available. Reveal still open.',
    }));
}
