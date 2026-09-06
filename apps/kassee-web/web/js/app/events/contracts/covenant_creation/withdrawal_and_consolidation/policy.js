import { covenantState } from '../../../../state/index.js';
import { formatDaaDuration } from '../../../../../core/format.js';
import { sompiToKasFixed, sompiToKasString } from '../../../../../core/amounts.js';
import { exactUnsigned } from '../../../../../core/exact.js';
import { fetchCurrentDaa } from '../../../../../core/node/daa.js';

export class CovenantSpendPolicyError extends Error {
    constructor(message, duration = 5000) {
        super(message);
        this.name = 'CovenantSpendPolicyError';
        this.duration = duration;
    }
}

function lastKnownDaa() {
    return exactUnsigned(covenantState._lastKnownDaa ?? 0n, 'last known DAA');
}

async function currentDaa() {
    try {
        const current = await fetchCurrentDaa();
        return current || lastKnownDaa();
    } catch (_) {
        return lastKnownDaa();
    }
}

export async function ownerSpendBranch({ isConsolidate, selected, fee }) {
    const result = covenantState.lastCovenantResult;
    if (isConsolidate || result.type !== 'additive') return '';

    const threshold = exactUnsigned(result.threshold_sompi ?? 0n, 'threshold sompi');
    const deadline = exactUnsigned(result.deadline_daa ?? 0n, 'deadline DAA');
    if (threshold === 0n && deadline === 0n) return '';

    const total = selected.reduce((sum, utxo) => sum + BigInt(utxo.amount), 0n);
    const daa = await currentDaa();
    const goalMet = threshold > 0n && total - fee >= threshold;
    const deadlinePassed = deadline > 0n && daa > 0n && daa >= deadline;
    if (goalMet) return '';
    if (deadlinePassed) return 'owner-time';

    const have = sompiToKasFixed(total, 4);
    const eta = daa > 0n && deadline > daa
        ? formatDaaDuration(deadline - daa)
        : 'the deadline';
    if (threshold > 0n && deadline > 0n) {
        throw new CovenantSpendPolicyError(
            `This selection is ${have} KAS, below the goal of ${sompiToKasString(threshold)} KAS, and the deadline has not passed (~${eta}). Select enough UTXOs to reach the goal, or wait for the deadline.`,
            7500,
        );
    }
    if (threshold > 0n) {
        throw new CovenantSpendPolicyError(
            `This selection is ${have} KAS, below the goal of ${sompiToKasString(threshold)} KAS. Select enough UTXOs to reach the goal.`,
            7500,
        );
    }
    throw new CovenantSpendPolicyError(
        `The deadline has not passed (~${eta}). A deadline-only piggy cannot be broken until then.`,
        7500,
    );
}

export function beneficiaryClaim() {
    return covenantState._pickerBeneClaim;
}

export function assertBeneficiaryClaimUnlocked(type, locktime) {
    if (type !== 'timelocked-savings' || locktime <= 0n) return;
    const daa = lastKnownDaa();
    if (daa > 0n && daa < locktime) {
        const eta = formatDaaDuration(locktime - daa);
        throw new CovenantSpendPolicyError(
            `Still locked. Unlocks in ~${eta}. An early claim is rejected by the node.`,
        );
    }
}
