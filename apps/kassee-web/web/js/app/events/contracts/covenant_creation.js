// Stable covenant_creation event composition.
import { registerNavigationAndSweep } from './covenant_creation/navigation_and_sweep.js';
import { registerSharingAndClaims } from './covenant_creation/sharing_and_claims.js';
import { registerCreationOptions } from './covenant_creation/creation_options.js';
import { registerResultActions } from './covenant_creation/result_actions.js';
import { registerWithdrawalAndConsolidation } from './covenant_creation/withdrawal_and_consolidation.js';

export function bindCovenantCreationEvents() {
    registerNavigationAndSweep();
    registerSharingAndClaims();
    registerCreationOptions();
    registerResultActions();
    registerWithdrawalAndConsolidation();
}
