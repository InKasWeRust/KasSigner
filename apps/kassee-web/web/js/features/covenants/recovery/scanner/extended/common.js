import { blake2b_hash, encode_p2sh_address } from '../../../../../wasm/api.js';

export function recoveredFromRedeem(type, redeemScriptHex, network, fields = {}) {
    if (!redeemScriptHex) return null;
    return {
        type,
        address: encode_p2sh_address(blake2b_hash(redeemScriptHex), network),
        redeem_script_hex: redeemScriptHex,
        loaded: true,
        ...fields,
    };
}
