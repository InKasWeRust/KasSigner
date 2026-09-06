// KasSee Web — covenant result-action facade.
import { registerBalanceAction } from './result_actions/balance.js';
import { registerOwnerAction } from './result_actions/owner.js';
import { registerBeneficiaryAction } from './result_actions/beneficiary.js';
import { createPiggyHelpers } from './result_actions/piggy.js';


export const { piggyBreakStatus, piggyStatusBanner } = createPiggyHelpers();

export function registerResultActions() {
    registerBalanceAction();
    registerOwnerAction();
    registerBeneficiaryAction();
}
