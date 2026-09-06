import { buildDms } from './dms.js';
import { buildEscrow, buildShipEscrow } from './escrow.js';
import { buildGlobalSpendingLimit, buildGlobalAllowance } from './limits.js';
import { buildAdditive, buildTimelockedSavings } from './savings.js';
import { buildAdvancedCovenant } from './advanced/index.js';

export async function buildCovenant(type, ownerPk) {
    switch (type) {
        case 'additive': return buildAdditive(ownerPk);
        case 'timelocked-savings': return buildTimelockedSavings(ownerPk);
        case 'global-spending-limit': return buildGlobalSpendingLimit(ownerPk);
        case 'global-allowance': return buildGlobalAllowance(ownerPk);
        case 'escrow': return buildEscrow(ownerPk);
        case 'ship-escrow': return buildShipEscrow(ownerPk);
        case 'dms': return buildDms(ownerPk);
        default: return buildAdvancedCovenant(type, ownerPk);
    }
}
