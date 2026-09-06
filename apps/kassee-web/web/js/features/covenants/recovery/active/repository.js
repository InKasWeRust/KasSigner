import { covenantState } from '../../../../app/state/index.js';
import { normalizeCovenantExactFields, stringifyCovenantJson } from '../../model/exact_fields.js';

if (!covenantState.activeCovenants) covenantState.activeCovenants = [];

const TYPE_NAMES = {
    'timelocked-savings': 'Savings',
    'global-spending-limit': 'GLimit',
    'global-allowance': 'GAllow',
    vesting: 'Vest',
    additive: 'Piggy',
    escrow: 'D.Channel',
    'timelocked-escrow': 'T-Escrow',
    'private-swap': 'Private Swap',
    payjoin: 'PayJoin',
    treasury: 'Treasury',
    'merkle-whitelist': 'Merkle',
    'commit-reveal': 'C-R',
    dms: 'DMS',
    'oracle-v1': 'Oracle',
    crowdfund: 'Crowdfund',
};

export const ACTIVE_METADATA_FIELDS = [
    'heir_address', 'beneficiary_pubkey_hex', 'owner_pubkey_hex', 'oracle_pubkey_hex', 'oracle_covenant_key_id_hex', 'oracle_covenant_binding_token_hex',
    'attestation_statement', 'message_commitment_hex',
    'oracle_attestation_signature', 'oracle_attestation_commitment', 'oracle_attestation_text', 'oracle_attestation_txid', '_oracle_v1_checked_txid',
    'locktime_date_iso', 'counterparty_pk',
    'max_withdraw_sompi', 'cooldown_daa', 'start_daa', 'start_date_iso',
    'heir_pubkey_hex', 'threshold_sompi', 'deadline_daa', 'deadline_date_iso',
    'merkle_root', 'merkle_depth', 'merkle_addresses_json', 'role', 'inactivity_daa',
    'commit_hash', 'cr_ciphertext_hex', '_escrowDisputed',
    'crowdfund_role', 'campaign_name', 'organizer_address', 'goal_sompi', 'vk_hex', 'campaign_id',
    'crowdfund_pk_hex', 'crowdfund_salt_hex', 'contributor_pubkey_hex', 'crowdfund_contributions_json',
    'private_swap_recovery_json',
];

export function activeCovenants() {
    return covenantState.activeCovenants;
}

export function loadActiveRecords() {
    try {
        const saved = sessionStorage.getItem('activeCovenants')
            || localStorage.getItem('activeCovenants');
        if (saved) covenantState.activeCovenants = JSON.parse(saved).map(normalizeCovenantExactFields);
    } catch (_) {
        covenantState.activeCovenants = [];
    }
}

export function saveActiveRecords() {
    const serialized = stringifyCovenantJson(covenantState.activeCovenants);
    try { sessionStorage.setItem('activeCovenants', serialized); } catch (_) {}
    try { localStorage.setItem('activeCovenants', serialized); } catch (_) {}
}

export function addActiveRecord(type, result) {
    const entry = {
        type,
        label: TYPE_NAMES[type] || type,
        address: result.address,
        redeem_script_hex: result.redeem_script_hex,
        locktime_daa: result.locktime_daa || null,
        loaded: result.loaded || false,
        created: Date.now(),
    };
    copyDefinedFields(result, entry, ACTIVE_METADATA_FIELDS);
    if (result.covenant_id_hex && !/^0+$/.test(result.covenant_id_hex)) {
        entry.covenant_id_hex = result.covenant_id_hex;
    }
    covenantState.activeCovenants = covenantState.activeCovenants
        .filter((item) => item.address !== entry.address);
    normalizeCovenantExactFields(entry);
    covenantState.activeCovenants.unshift(entry);
}

export function removeActiveRecord(index) {
    covenantState.activeCovenants.splice(index, 1);
}

export function copyDefinedFields(source, destination, fields) {
    for (const field of fields) {
        if (source[field] !== undefined && source[field] !== null && source[field] !== '') {
            destination[field] = source[field];
        }
    }
}
