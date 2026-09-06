import { ensureAllowanceParams, ensureEscrowParams, ensurePiggyParams } from '../../watchers_and_ui/ui/metadata.js';

// Normalize current covenant invite fields into the active record shape.
export function normalizeRecoveredInvite(entry, invite) {
    if (invite.ldi && (entry.type === 'payjoin' || entry.type === 'timelocked-savings' || entry.type === 'oracle-v1')) {
        entry.locktime_date_iso = invite.ldi;
    }
    if (entry.type === 'timelocked-savings') {
        if (invite.w1) entry.wallet1_pubkey_hex = invite.w1;
        if (invite.w2) entry.wallet2_pubkey_hex = invite.w2;
    }

    if (entry.type === 'global-allowance') ensureAllowanceParams(entry);
    if (entry.type === 'additive') ensurePiggyParams(entry);
    if (entry.type === 'escrow') ensureEscrowParams(entry);
    return entry;
}
