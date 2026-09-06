import { rebuildAdditive, rebuildDms, rebuildGlobalAllowance, rebuildGlobalSpendingLimit } from './basic.js';
import { rebuildEscrow, rebuildTimelockedSavings } from './participants.js';
import { rebuildOracleV1 } from './oracle.js';
import { rebuildCrowdfund } from './crowdfund.js';
import { rebuildPrivateSwap } from './private_swap.js';

const REBUILDERS = {
    dms: rebuildDms,
    additive: rebuildAdditive,
    'global-spending-limit': rebuildGlobalSpendingLimit,
    'global-allowance': rebuildGlobalAllowance,
    'timelocked-savings': rebuildTimelockedSavings,
    escrow: rebuildEscrow,
    'oracle-v1': rebuildOracleV1,
    crowdfund: rebuildCrowdfund,
    'private-swap': rebuildPrivateSwap,
};

export function rebuildPrimaryRecoveredCovenant(typeName, params, ownerPk) {
    const rebuild = REBUILDERS[typeName];
    return rebuild ? rebuild(typeName, params, ownerPk) : undefined;
}
