// Covenant-loading event façade.
import { bindInviteLoadingActions } from './covenant_loading/invites.js';
import { bindLoadSubmissionAction } from './covenant_loading/submission.js';
import { bindSwapAndUtilityActions } from './covenant_loading/utilities.js';


export function bindCovenantLoadingEvents() {
    bindInviteLoadingActions();
    bindLoadSubmissionAction();
    bindSwapAndUtilityActions();
}
