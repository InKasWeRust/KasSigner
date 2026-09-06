import { bindCovenantRecoveryEvents } from './covenant_recovery.js';
import { bindTaggedVaultOnline } from './tagged_vault/online.js';
import { createTaggedVaultSession } from './tagged_vault/session.js';


export function bindTaggedVaultAndRecoveryEvents() {
    const { state, log } = createTaggedVaultSession();
    bindTaggedVaultOnline(state, log);
    bindCovenantRecoveryEvents();
}
