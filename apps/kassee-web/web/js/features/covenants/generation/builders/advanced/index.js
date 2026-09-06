import { buildPayjoin } from './payjoin.js';
import { buildCommitReveal } from './commit_reveal.js';
import { buildMerkleWhitelist } from './merkle_whitelist.js';
import { buildOracleV1 } from './oracle_v1.js';
import { buildCrowdfund } from '../../../crowdfund/campaign.js';

export async function buildAdvancedCovenant(type, ownerPk) {
    switch (type) {
        case 'payjoin': return buildPayjoin(ownerPk);
        case 'commit-reveal': return buildCommitReveal(ownerPk);
        case 'merkle-whitelist': return buildMerkleWhitelist(ownerPk);
        case 'oracle-v1': return buildOracleV1(ownerPk);
        case 'crowdfund': return buildCrowdfund(ownerPk);
        default: return null;
    }
}
