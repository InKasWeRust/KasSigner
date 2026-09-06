// Covenant polling registry façade.

import { pollTimelockedSavings, pollDms, pollAdditive } from './covenant_pollers/savings.js';
import { pollGlobalSpendingLimit, pollGlobalAllowance } from './covenant_pollers/limits.js';
import { pollEscrow } from './covenant_pollers/conditional.js';
import { pollMerkleWhitelist, pollPayjoin, pollCommitReveal } from './covenant_pollers/timed.js';
import { pollOracleV1 } from './covenant_pollers/oracle_v1.js';

const POLLERS = Object.freeze({
    'timelocked-savings': pollTimelockedSavings,
    dms: pollDms,
    'global-spending-limit': pollGlobalSpendingLimit,
    'global-allowance': pollGlobalAllowance,
    additive: pollAdditive,
    escrow: pollEscrow,
    'merkle-whitelist': pollMerkleWhitelist,
    payjoin: pollPayjoin,
    'commit-reveal': pollCommitReveal,
    'oracle-v1': pollOracleV1,
});

export async function pollCovenantType(state) {
    const poller = POLLERS[state.t];
    return poller ? poller(state) : false;
}
