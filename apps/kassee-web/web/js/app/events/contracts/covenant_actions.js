// KasSee Web — covenant action event façade.

import { bindAllowanceActions } from './covenant_actions/allowance.js';
import { bindCovenantScansAndClaims } from './covenant_actions/claims.js';

export function bindCovenantActionsEvents() {
    bindCovenantScansAndClaims();
    bindAllowanceActions();
}
