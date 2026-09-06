import { networkState } from '../../../../../app/state/index.js';
import { blake2b_hash, encode_p2sh_address } from '../../../../../wasm/api.js';
import { readLen } from '../payload_reader.js';

export function readStoredScript(params) {
    const { len, endOff } = readLen(params, 0);
    const redeemScriptHex = params.slice(endOff, endOff + len * 2);
    if (!redeemScriptHex) throw new Error('Recovered covenant has an empty redeem script');
    return { redeemScriptHex, offset: endOff + len * 2 };
}

function addressForScript(redeemScriptHex) {
    return encode_p2sh_address(blake2b_hash(redeemScriptHex), networkState.network);
}

export function baseRecoveredRecord(type, redeemScriptHex, role = 'owner') {
    return {
        type,
        address: addressForScript(redeemScriptHex),
        redeem_script_hex: redeemScriptHex,
        loaded: true,
        role,
    };
}

export function normalizedCovenantId(value) {
    return value && !/^0+$/.test(value) ? value : '';
}
