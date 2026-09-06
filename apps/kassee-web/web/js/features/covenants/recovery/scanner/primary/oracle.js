import { hexToBytes } from '../../../../../core/bytes.js';
import { walletMatchesPk } from '../../../generation/ui_and_keys.js';
import { readU64, readVstr } from '../payload_reader.js';
import { baseRecoveredRecord, readStoredScript } from './common.js';

export function rebuildOracleV1(type, params) {
    const { redeemScriptHex, offset } = readStoredScript(params);
    const oraclePubkeyHex = params.slice(offset, offset + 64);
    const oracleKeyIdHex = params.slice(offset + 64, offset + 128);
    const bindingTokenHex = params.slice(offset + 128, offset + 192);
    const beneficiaryPubkeyHex = params.slice(offset + 192, offset + 256);
    const ownerPubkeyHex = params.slice(offset + 256, offset + 320);
    const messageCommitmentHex = params.slice(offset + 320, offset + 384);
    if ([oraclePubkeyHex, oracleKeyIdHex, bindingTokenHex, beneficiaryPubkeyHex, ownerPubkeyHex, messageCommitmentHex]
        .some(value => value.length !== 64) || /^0+$/.test(bindingTokenHex)) {
        throw new Error('Recovered Oracle-v1 binding/participant/commitment field is invalid');
    }
    const locktimeDaa = readU64(params, offset + 384);
    const statementField = readVstr(params, offset + 400, hexToBytes);
    const dateField = readVstr(params, statementField.endOff, hexToBytes);
    if (dateField.endOff !== params.length) throw new Error('Recovered Oracle-v1 payload has trailing data');
    let role = 'observer';
    if (walletMatchesPk(beneficiaryPubkeyHex)) role = 'beneficiary';
    else if (walletMatchesPk(ownerPubkeyHex)) role = 'owner';
    return {
        ...baseRecoveredRecord(type, redeemScriptHex, role),
        oracle_pubkey_hex: oraclePubkeyHex,
        oracle_covenant_key_id_hex: oracleKeyIdHex,
        oracle_covenant_binding_token_hex: bindingTokenHex,
        beneficiary_pubkey_hex: beneficiaryPubkeyHex,
        owner_pubkey_hex: ownerPubkeyHex,
        message_commitment_hex: messageCommitmentHex,
        attestation_statement: statementField.str,
        locktime_daa: locktimeDaa,
        ...(dateField.str ? { locktime_date_iso: dateField.str } : {}),
    };
}
