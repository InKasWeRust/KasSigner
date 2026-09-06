import { covenantState } from '../../../../app/state/index.js';
import { showScreen } from '../../../../app/navigation.js';
import { hexToBytes } from '../../../../core/bytes.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel, walletMatchesPk } from '../../generation/ui_and_keys.js';
import { covAddActive, covRenderActive, covSaveActive } from '../active.js';
import { normalizeRecoveredInvite } from './invite_normalization.js';
import { normalizeCovenantExactFields } from '../../model/exact_fields.js';
import { exactUnsigned } from '../../../../core/exact.js';

function decodeInvite(hex) {
    const jsonBytes = hexToBytes(hex.slice(8));
    return JSON.parse(new TextDecoder().decode(jsonBytes));
}

function inferRole(entry) {
    if (entry.type === 'oracle-v1') {
        if (walletMatchesPk(entry.beneficiary_pubkey_hex)) return 'beneficiary';
        if (walletMatchesPk(entry.owner_pubkey_hex)) return 'owner';
        return 'observer';
    }
    if (entry.type === 'escrow') {
        if (walletMatchesPk(entry.alice_pk)) return 'owner';
        if (walletMatchesPk(entry.bob_pk)) return 'beneficiary';
        if (walletMatchesPk(entry.arbiter_pk)) return 'arbiter';
        return 'beneficiary';
    }
    if (entry.type === 'additive') return 'owner';
    return entry.role;
}

function buildInviteEntry(invite) {
    if (invite.t !== 'cov-invite' || !invite.addr || !invite.rs) {
        throw new Error('Invalid invite format');
    }
    const entry = {
        type: invite.ct || 'unknown',
        address: invite.addr,
        redeem_script_hex: invite.rs,
        locktime_daa: exactUnsigned(invite.d ?? 0n, 'locktime DAA'),
        loaded: true,
        role: 'beneficiary',
    };
    if (invite.id) entry.inactivity_daa = exactUnsigned(invite.id, 'inactivity DAA');
    if (invite.bpk) entry.beneficiary_pubkey_hex = invite.bpk;
    if (invite.own) entry.owner_pubkey_hex = invite.own;
    if (invite.opk) entry.oracle_pubkey_hex = invite.opk;
    if (invite.okid) entry.oracle_covenant_key_id_hex = invite.okid;
    if (invite.obt) entry.oracle_covenant_binding_token_hex = invite.obt;
    if (invite.oas) entry.attestation_statement = invite.oas;
    if (invite.omc) entry.message_commitment_hex = invite.omc;
    if (invite.mw) entry.max_withdraw_sompi = exactUnsigned(invite.mw, 'withdrawal limit');
    if (invite.cd) entry.cooldown_daa = exactUnsigned(invite.cd, 'cooldown DAA');
    if (invite.sd) entry.start_daa = exactUnsigned(invite.sd, 'start DAA');
    if (invite.sdi) entry.start_date_iso = invite.sdi;

    if (entry.type === 'oracle-v1' && (!/^[0-9a-f]{64}$/.test(entry.oracle_covenant_key_id_hex || '')
        || !/^[0-9a-f]{64}$/.test(entry.oracle_covenant_binding_token_hex || ''))) {
        throw new Error('Oracle-v1 invite is missing its covenant key binding record');
    }
    normalizeRecoveredInvite(entry, invite);
    normalizeCovenantExactFields(entry);
    entry.role = inferRole(entry);
    return entry;
}

export function importCovenantInvite(hex) {
    const invite = decodeInvite(hex);
    const entry = buildInviteEntry(invite);
    const alreadyActive = covenantState.activeCovenants.some(covenant => covenant.address === entry.address);
    if (!alreadyActive) {
        covAddActive(entry.type, entry);
        covSaveActive();
        covRenderActive();
    }
    showScreen('covenant');
    covShowPanel('menu');
    toast(alreadyActive ? 'Covenant already active' : 'Covenant invite restored', 'ok', alreadyActive ? 2000 : 3000);
    return !alreadyActive;
}
