import { networkState } from '../../../../../app/state/index.js';
import { covenant_dms } from '../../../../../wasm/api.js';
import { readU64 } from '../payload_reader.js';
import { baseRecoveredRecord, normalizedCovenantId, readStoredScript } from './common.js';

export function rebuildDms(type, params, ownerPk) {
    const heirPubkeyHex = params.slice(0, 64);
    const inactivityDaa = readU64(params, 64);
    const result = JSON.parse(covenant_dms(ownerPk, heirPubkeyHex, inactivityDaa, networkState.network));
    return {
        type,
        address: result.address,
        redeem_script_hex: result.redeem_script_hex,
        inactivity_daa: inactivityDaa,
        heir_pubkey_hex: heirPubkeyHex,
        loaded: true,
        role: 'owner',
    };
}

export function rebuildAdditive(type, params) {
    const { redeemScriptHex, offset } = readStoredScript(params);
    const threshold = readU64(params, offset);
    const deadline = readU64(params, offset + 16);
    return {
        ...baseRecoveredRecord(type, redeemScriptHex),
        threshold_sompi: threshold,
        deadline_daa: deadline,
    };
}

export function rebuildGlobalSpendingLimit(type, params) {
    const { redeemScriptHex, offset } = readStoredScript(params);
    const maxWithdraw = readU64(params, offset);
    const cooldownDaa = readU64(params, offset + 16);
    const covenantIdHex = params.slice(offset + 32, offset + 96);
    return {
        ...baseRecoveredRecord(type, redeemScriptHex),
        max_withdraw_sompi: maxWithdraw,
        cooldown_daa: cooldownDaa,
        covenant_id_hex: normalizedCovenantId(covenantIdHex),
    };
}

export function rebuildGlobalAllowance(type, params) {
    const { redeemScriptHex, offset } = readStoredScript(params);
    const maxWithdraw = readU64(params, offset);
    const cooldownDaa = readU64(params, offset + 16);
    const startDaa = readU64(params, offset + 32);
    const beneficiaryPubkeyHex = params.slice(offset + 48, offset + 112);
    const covenantIdHex = params.slice(offset + 112, offset + 176);
    return {
        ...baseRecoveredRecord(type, redeemScriptHex),
        max_withdraw_sompi: maxWithdraw,
        cooldown_daa: cooldownDaa,
        start_daa: startDaa,
        beneficiary_pubkey_hex: beneficiaryPubkeyHex,
        covenant_id_hex: normalizedCovenantId(covenantIdHex),
    };
}
