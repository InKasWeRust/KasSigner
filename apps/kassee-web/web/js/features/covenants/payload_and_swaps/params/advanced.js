import { pubkeyHex as pk, u64LeHex as u64, variableHex as vhex, variableString as vstr } from './primitives.js';

export const advancedSerializers = Object.freeze({
    'private-swap': (result) => vhex(result.redeem_script_hex) + vstr(result.private_swap_recovery_json),
    crowdfund: (result) => vhex(result.redeem_script_hex)
        + pk(result.contributor_pubkey_hex) + vhex(result.crowdfund_salt_hex)
        + u64(result.goal_sompi) + u64(result.locktime_daa)
        + vstr(result.organizer_address) + vstr(result.campaign_name)
        + vhex(result.vk_hex) + vhex(result.crowdfund_pk_hex) + pk(result.campaign_id)
        + vstr(result.crowdfund_role) + vstr(result.crowdfund_contributions_json)
        + vstr(result.locktime_date_iso),
    'oracle-v1': (result) => vhex(result.redeem_script_hex)
        + pk(result.oracle_pubkey_hex) + pk(result.oracle_covenant_key_id_hex) + pk(result.oracle_covenant_binding_token_hex)
        + pk(result.beneficiary_pubkey_hex) + pk(result.owner_pubkey_hex) + pk(result.message_commitment_hex) + u64(result.locktime_daa)
        + vstr(result.attestation_statement) + vstr(result.locktime_date_iso),
    'merkle-whitelist': (result) => vhex(result.redeem_script_hex) + pk(result.merkle_root)
        + (result.merkle_depth || 0).toString(16).padStart(2, '0')
        + u64(result.locktime_daa) + vstr(result.merkle_addresses_json),
    additive: (result) => vhex(result.redeem_script_hex)
        + u64(result.threshold_sompi) + u64(result.deadline_daa || result.locktime_daa),
    payjoin: (result) => pk(result.beneficiary_pubkey_hex) + u64(result.locktime_daa)
        + u64(result.min_inputs || 2) + u64(result.min_outputs || 2)
        + vhex(result.redeem_script_hex) + vstr(result.locktime_date_iso),
    'commit-reveal': (result) => pk(result.commit_hash || result.committed_hash)
        + u64(result.locktime_daa) + vhex(result.redeem_script_hex)
        + vhex(result.cr_ciphertext_hex),
});
