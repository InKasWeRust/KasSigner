import { bytesToHex } from '../../../../core/bytes.js';
import { exactDecimalString } from '../../../../core/exact.js';

function decimal(value, field) {
    return exactDecimalString(value ?? 0n, field);
}

export function buildBeneficiaryExport(covenant) {
    const invite = {
        v: 1,
        t: 'cov-invite',
        ct: covenant.type || '',
        addr: covenant.address || '',
        rs: covenant.redeem_script_hex || '',
        d: decimal(covenant.locktime_daa, 'locktime DAA'),
    };
    copyTypeSpecificFields(invite, covenant);

    const jsonBytes = new TextEncoder().encode(JSON.stringify(invite));
    const bytes = new Uint8Array(4 + jsonBytes.length);
    bytes.set(new TextEncoder().encode('COVI'), 0);
    bytes.set(jsonBytes, 4);
    return Object.freeze({ bytes, hex: bytesToHex(bytes), encrypted: false, extension: '.cov' });
}

function copyTypeSpecificFields(invite, covenant) {
    if (covenant.type === 'dms' && covenant.inactivity_daa) invite.id = decimal(covenant.inactivity_daa, 'inactivity DAA');

    if (covenant.type === 'global-allowance') {
        if (covenant.max_withdraw_sompi) invite.mw = decimal(covenant.max_withdraw_sompi, 'withdrawal limit');
        if (covenant.cooldown_daa) invite.cd = decimal(covenant.cooldown_daa, 'cooldown DAA');
        if (covenant.start_daa) invite.sd = decimal(covenant.start_daa, 'start DAA');
        if (covenant.start_date_iso) invite.sdi = covenant.start_date_iso;
    }
    if (covenant.type === 'oracle-v1') {
        if (covenant.oracle_pubkey_hex) invite.opk = covenant.oracle_pubkey_hex;
        if (covenant.oracle_covenant_key_id_hex) invite.okid = covenant.oracle_covenant_key_id_hex;
        if (covenant.oracle_covenant_binding_token_hex) invite.obt = covenant.oracle_covenant_binding_token_hex;
        if (covenant.beneficiary_pubkey_hex) invite.bpk = covenant.beneficiary_pubkey_hex;
        if (covenant.owner_pubkey_hex) invite.own = covenant.owner_pubkey_hex;
        if (covenant.attestation_statement) invite.oas = covenant.attestation_statement;
        if (covenant.message_commitment_hex) invite.omc = covenant.message_commitment_hex;
    }
    if (covenant.locktime_date_iso) invite.ldi = covenant.locktime_date_iso;
    if (covenant.wallet1_pubkey_hex) invite.w1 = covenant.wallet1_pubkey_hex;
    if (covenant.wallet2_pubkey_hex) invite.w2 = covenant.wallet2_pubkey_hex;
}
