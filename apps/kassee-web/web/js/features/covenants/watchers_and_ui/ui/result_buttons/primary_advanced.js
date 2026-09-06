import { configureCommitRevealActions } from './primary_advanced/commit_reveal.js';
import { configureDefaultActions } from './primary_advanced/defaults.js';
import { configureMerkleActions } from './primary_advanced/merkle.js';
import { configurePayjoinActions } from './primary_advanced/payjoin.js';
import { configureShipmentActions } from './primary_advanced/shipment.js';
import { configureCrowdfundActions } from './primary_advanced/crowdfund.js';

const CONFIGURERS = Object.freeze({
    'commit-reveal': configureCommitRevealActions,
    'merkle-whitelist': configureMerkleActions,
    payjoin: configurePayjoinActions,
    'ship-escrow': configureShipmentActions,
    crowdfund: configureCrowdfundActions,
});

export function configurePrimaryAdvancedActions(state) {
    (CONFIGURERS[state.type] || configureDefaultActions)(state);
}
