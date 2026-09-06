// Specialized covenant-family event façade.
import { bindCommitRevealEvents } from './covenant_specialized/commit_reveal.js';
import { bindMerkleWhitelistEvents } from './covenant_specialized/merkle_whitelist.js';
import { bindShipmentEscrowEvents } from './covenant_specialized/shipment.js';
import { bindCrowdfundEvents } from './covenant_specialized/crowdfund.js';
import { bindPrivateSwapEvents } from './covenant_specialized/private_swap.js';


export function bindCovenantSpecializedEvents() {
    bindShipmentEscrowEvents();
    bindCommitRevealEvents();
    bindMerkleWhitelistEvents();
    bindCrowdfundEvents();
    bindPrivateSwapEvents();
}
