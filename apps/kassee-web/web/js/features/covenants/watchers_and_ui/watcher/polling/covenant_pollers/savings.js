import { setSafeMarkup } from '../../../../../../core/security/safe_html.js';
import { covenantState, covenantWatcherState } from '../../../../../../app/state/index.js';
import { exactUnsigned } from '../../../../../../core/exact.js';
import { formatDaaDuration } from '../../../../../../core/format.js';
import { sompiToKasString } from '../../../../../../core/amounts.js';
import { covWatcherStop } from '../lifecycle.js';
import { pollTimedBalance } from './timed.js';

export async function pollTimelockedSavings(state) {
    return pollTimedBalance(state, {
        spent: () => 'Claimed.',
        onSpent: covWatcherStop,
        availableClass: 'u-text-teal',
        available: kas => `✅ Unlocked. ${kas} KAS claimable.`,
        unlockingClass: 'u-text-warning',
        unlocking: kas => `⏳ Unlocking... claim available shortly. ${kas} KAS`,
        locked: (kas, timeStr) => `👁 ${kas} KAS | Locked, unlocks in ~${timeStr}`,
        watching: kas => `👁 ${kas} KAS | Watching...`,
    });
}

export async function pollDms(state) {
    const { total, kas, st, currentDaa, utxos } = state;
    const inactivity = exactUnsigned(covenantState.lastCovenantResult.inactivity_daa ?? 0n, 'inactivity DAA');
    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null && covenantWatcherState._covWatcherLastBalance > 0n) {
        const spender = covenantWatcherState._covWatcherSpendPath || 'unknown';
        if (spender === 'heir') {
            st.innerHTML = '<span class="u-text-warning">\u26a0 Heir claimed the funds.</span>';
            covWatcherStop();
            if (st) st.style.display = '';
            return true;
        }
        if (spender === 'owner') {
            st.innerHTML = '<span class="u-text-text-muted">\u23f3 Owner spent. Checking...</span>';
            return true;
        }
        st.textContent = '\uD83D\uDC41 Funds spent (0 KAS)';
        return true;
    }

    if (total === 0n) {
        st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
        st.style.color = '';
    } else if (inactivity > 0n && currentDaa > 0n) {
        let newestDaa = 0n;
        for (const utxo of utxos) {
            const daa = exactUnsigned(utxo.block_daa_score ?? 0n, 'UTXO DAA score');
            if (daa > newestDaa) newestDaa = daa;
        }
        const remaining = newestDaa + inactivity - currentDaa;
        if (remaining <= -300n) {
            setSafeMarkup(st, `<span class="u-text-warning">\u26a0 Inactivity period passed. Heir can claim. ${kas} KAS</span>`);
        } else if (remaining <= 0n) {
            setSafeMarkup(st, `<span class="u-text-warning">\u23f3 Inactivity period ending... Heir claim available shortly. ${kas} KAS</span>`);
        } else {
            st.textContent = `\uD83D\uDC41 ${kas} KAS | ~${formatDaaDuration(remaining)} until heir can claim`;
            st.style.color = '';
        }
    } else {
        st.textContent = `\uD83D\uDC41 ${kas} KAS | Watching...`;
        st.style.color = '';
    }
    return false;
}

export async function pollAdditive(state) {
    const { total, kas, st, currentDaa } = state;
    const result = covenantState.lastCovenantResult;
    const threshold = exactUnsigned(result.threshold_sompi ?? 0n, 'savings threshold');
    const deadlineDaa = exactUnsigned(result.deadline_daa ?? 0n, 'deadline DAA');

    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null && covenantWatcherState._covWatcherLastBalance > 0n) {
        st.innerHTML = '<span class="u-text-teal">\u2705 Piggy bank broken! Funds withdrawn.</span>';
        covWatcherStop();
        if (st) st.style.display = '';
        return true;
    }

    if (total === 0n) {
        st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
        st.style.color = '';
        return false;
    }

    const statusParts = [];
    if (threshold > 0n) {
        const roundedPercent = (total * 100n + threshold / 2n) / threshold;
        const percent = roundedPercent > 100n ? 100n : roundedPercent;
        statusParts.push(`${kas} / ${sompiToKasString(threshold)} KAS (${percent}%)`);
        if (total >= threshold) statusParts.push('\u2705 Goal reached!');
    } else {
        statusParts.push(`${kas} KAS`);
    }

    if (deadlineDaa > 0n && currentDaa > 0n) {
        if (currentDaa >= deadlineDaa) statusParts.push('\u23F0 Deadline passed');
        else statusParts.push(`~${formatDaaDuration(deadlineDaa - currentDaa)} until deadline`);
    }

    const canBreakGoal = threshold > 0n && total >= threshold;
    const canBreakTime = deadlineDaa > 0n && currentDaa > 0n && currentDaa >= deadlineDaa;
    const noConditions = threshold === 0n && deadlineDaa === 0n;
    if (canBreakGoal || canBreakTime || noConditions) {
        setSafeMarkup(st, `<span class="u-text-teal">\uD83D\uDC41 ${statusParts.join(' | ')}</span>`);
    } else {
        st.textContent = `\uD83D\uDC41 ${statusParts.join(' | ')}`;
        st.style.color = '';
    }
    return false;
}
