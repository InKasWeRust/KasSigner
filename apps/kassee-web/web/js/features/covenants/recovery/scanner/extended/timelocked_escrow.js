import { covenant_timelocked_escrow, encode_p2pk_address } from '../../../../../wasm/api.js';
import { readU64 } from '../payload_reader.js';

export function decodeTimelockedEscrow(params, network, ownerPublicKey) {
    const beneficiaryPublicKey = params.substring(0, 64);
    const locktime = readU64(params, 64);
    try {
        const ownerAddress = encode_p2pk_address(ownerPublicKey, network);
        const beneficiaryAddress = encode_p2pk_address(beneficiaryPublicKey, network);
        const rebuilt = JSON.parse(covenant_timelocked_escrow(
            ownerPublicKey,
            beneficiaryPublicKey,
            ownerAddress,
            beneficiaryAddress,
            locktime,
            network,
        ));
        return {
            type: 'timelocked-escrow',
            address: rebuilt.address,
            redeem_script_hex: rebuilt.redeem_script_hex,
            locktime_daa: locktime,
            beneficiary_pubkey_hex: beneficiaryPublicKey,
            loaded: true,
            role: 'owner',
        };
    } catch (error) {
        console.log('[KasSee] Recovery: timelocked-escrow rebuild failed, missing addresses:', error);
        return false;
    }
}
