import { setSafeMarkup } from '../../../../../../core/security/safe_html.js';
import { covenantState, covenantWatcherState } from '../../../../../../app/state/index.js';
import { exactUnsigned } from '../../../../../../core/exact.js';
import { formatDaaDuration } from '../../../../../../core/format.js';
import { sompiToKasFixed, sompiToKasString } from '../../../../../../core/amounts.js';
import { pickThread } from '../../../../spending/standard/thread_and_claims.js';
import { ensureAllowanceParams } from '../../../ui/metadata.js';
import { covWatcherStop } from '../lifecycle.js';

function governedThreadState(utxos) {
    const picked = pickThread(
        utxos,
        covenantState.lastCovenantResult?.covenant_id_hex,
    );
    const threadSompi = picked.thread ? exactUnsigned(picked.thread.amount, 'thread amount') : 0n;
    const threadDaa = picked.thread
        ? exactUnsigned(picked.thread.block_daa_score ?? 0n, 'thread DAA score')
        : 0n;
    return { picked, threadSompi, threadDaa };
}

function externalFundsNote(sompi, disposition) {
    const exact = exactUnsigned(sompi ?? 0n, 'external amount');
    return exact > 0n
        ? ` <span class="u-text-warning">(+${sompiToKasFixed(exact, 2)} KAS external, ${disposition})</span>`
        : '';
}

function withdrawalLimitLabel(maxSompi, canDrain) {
    if (canDrain) return ' (full drain)';
    return maxSompi > 0n ? ` (max ${sompiToKasString(maxSompi)} KAS)` : '';
}

export async function pollGlobalSpendingLimit(state) {
    const { st, currentDaa, utxos } = state;
    ensureAllowanceParams(covenantState.lastCovenantResult);
    const cooldown = exactUnsigned(covenantState.lastCovenantResult.cooldown_daa ?? 0n, 'cooldown DAA');
    const maxSompi = exactUnsigned(covenantState.lastCovenantResult.max_withdraw_sompi ?? 0n, 'withdrawal limit');
    const { picked, threadSompi, threadDaa } = governedThreadState(utxos);
    const mature = !!picked.thread && (cooldown === 0n || currentDaa === 0n || currentDaa >= threadDaa + cooldown);
    const matureSompi = mature ? threadSompi : 0n;
    const canDrain = maxSompi > 0n && matureSompi > 0n && matureSompi <= maxSompi;
    const maxStr = withdrawalLimitLabel(maxSompi, canDrain);
    const extNote = externalFundsNote(picked.externalSompi, 'stuck');
    const governedKas = sompiToKasFixed(threadSompi, 2);

    st.style.color = '';
    if (threadSompi === 0n) {
        setSafeMarkup(st, '\uD83D\uDC41 0 KAS | Not funded' + extNote);
    } else if (matureSompi > 0n) {
        setSafeMarkup(st, canDrain
            ? `<span class="u-text-teal">\u2705 Ready to drain all ${governedKas} KAS</span>${extNote}`
            : `<span class="u-text-teal">\u2705 Ready to withdraw${maxStr}</span>${extNote}`);
    } else if (cooldown > 0n && currentDaa > 0n) {
        const remaining = threadDaa + cooldown - currentDaa;
        setSafeMarkup(st, remaining <= 0n
            ? `<span class="u-text-teal">\u2705 Ready to withdraw${maxStr}</span>${extNote}`
            : `\uD83D\uDC41 ~${formatDaaDuration(remaining)} until next withdraw${maxStr}${extNote}`);
    } else {
        setSafeMarkup(st, `\uD83D\uDC41 ${governedKas} KAS | Watching...${maxStr}${extNote}`);
    }
    return false;
}

export async function pollGlobalAllowance(state) {
    const { total, st, currentDaa, utxos } = state;
    ensureAllowanceParams(covenantState.lastCovenantResult);
    const result = covenantState.lastCovenantResult;
    const iAmOwner = result.role !== 'beneficiary';
    const cooldown = exactUnsigned(result.cooldown_daa ?? result.min_sequence ?? 0n, 'cooldown DAA');
    const maxSompi = exactUnsigned(result.max_withdraw_sompi ?? 0n, 'withdrawal limit');
    const startDaa = exactUnsigned(result.start_daa ?? 0n, 'start DAA');
    const { picked, threadSompi, threadDaa } = governedThreadState(utxos);
    const canDrain = maxSompi > 0n && threadSompi > 0n && threadSompi <= maxSompi;
    const maxStr = withdrawalLimitLabel(maxSompi, canDrain);
    const extNote = externalFundsNote(picked.externalSompi, 'owner-reclaimable');
    const governedKas = sompiToKasFixed(threadSompi, 2);

    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null && covenantWatcherState._covWatcherLastBalance > 0n) {
        const spender = covenantWatcherState._covWatcherSpendPath || 'unknown';
        if (spender === 'heir') st.innerHTML = '<span class="u-text-teal">\u2705 Beneficiary withdrew.</span>';
        else if (spender === 'owner') st.innerHTML = '<span class="u-text-warning">\u26a0 Owner reclaimed all funds.</span>';
        else st.textContent = '\uD83D\uDC41 Funds spent (0 KAS)';
        covWatcherStop();
        if (st) st.style.display = '';
        return true;
    }

    st.style.color = '';
    if (threadSompi === 0n) {
        setSafeMarkup(st, '\uD83D\uDC41 0 KAS | Not funded' + extNote);
    } else if (iAmOwner) {
        setSafeMarkup(st, `\uD83D\uDC41 ${governedKas} KAS | Owner can reclaim anytime${extNote}`);
    } else if (startDaa > 0n && currentDaa > 0n && currentDaa < startDaa) {
        setSafeMarkup(st, `\uD83D\uDC41 ${governedKas} KAS | Locked, ~${formatDaaDuration(startDaa - currentDaa)} until start${extNote}`);
    } else if (cooldown > 0n && currentDaa > 0n) {
        const remaining = threadDaa + cooldown - currentDaa;
        if (remaining <= 0n) {
            setSafeMarkup(st, canDrain
                ? `<span class="u-text-teal">\u2705 Ready to drain all ${governedKas} KAS</span>${extNote}`
                : `<span class="u-text-teal">\u2705 Ready to withdraw${maxStr}</span>${extNote}`);
        } else {
            setSafeMarkup(st, `\uD83D\uDC41 ~${formatDaaDuration(remaining)} until next withdraw${maxStr}${extNote}`);
        }
    } else {
        setSafeMarkup(st, `\uD83D\uDC41 ${governedKas} KAS | Watching...${maxStr}${extNote}`);
    }
    return false;
}
