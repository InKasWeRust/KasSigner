import { hexToBytes } from '../../../../core/bytes.js';
import { walkScriptPushes } from '../../../../core/script_pushes.js';

// Pure covenant redeem-script metadata parsers.

export function parseAllowanceScript(hexStr) {
    const result = { max_withdraw_sompi: 0n, cooldown_daa: 0n, start_daa: 0n };
    try {
        walkScriptPushes(hexToBytes(hexStr), ({ opcode, lastInteger }) => {
            if (opcode === 0x94) result.max_withdraw_sompi = lastInteger; // OP_SUB
            if (opcode === 0xb1) result.cooldown_daa = lastInteger; // OP_CSV
            if (opcode === 0xb0) result.start_daa = lastInteger; // OP_CLTV
            return true;
        });
    } catch (_) {}
    return result;
}

export function parseEscrowScript(hexStr) {
    const result = { alice_pk: '', bob_pk: '', arbiter_pk: '', alice_spk_hex: '', bob_spk_hex: '', salt: '' };
    try {
        const h = hexStr;
        // Script starts with: 08 <8B salt> 75(OP_DROP) 63(OP_IF) 20(PUSH32)
        // Salt prefix = 20 hex chars. Then OP_IF at hex offset 20, PUSH32 at 22.
        const S = 20; // salt prefix offset
        if (h.substring(S, S + 4) !== '6320') return result;
        result.salt = h.substring(2, 18); // 8 bytes salt at hex[2..18]
        // Alice pubkey at hex offset S+4..S+68
        result.alice_pk = h.substring(S + 4, S + 68);
        // bob_dest_pk at hex offset S+82
        result.bob_spk_hex = h.substring(S + 82, S + 82 + 64);
        // Path 2 starts at hex S+152: 67 63 20 (ELSE IF PUSH32)
        const path2Start = S + 152;
        if (h.substring(path2Start, path2Start + 6) !== '676320') return result;
        result.bob_pk = h.substring(path2Start + 6, path2Start + 6 + 64);
        // alice_dest_pk at path2Start + 84
        result.alice_spk_hex = h.substring(path2Start + 84, path2Start + 84 + 64);
        // arbiter_pk at path2Start + 84 + 64 + 12 = path2Start + 160
        const arbiterOffset = path2Start + 84 + 64 + 12;
        if (h.substring(arbiterOffset - 2, arbiterOffset) !== '20') {
            return result;
        }
        result.arbiter_pk = h.substring(arbiterOffset, arbiterOffset + 64);
    } catch (_) {}
    return result;
}

export function parsePiggyScript(hexStr) {
    const result = { threshold_sompi: 0n, deadline_daa: 0n };
    let foundFirstGte = false;
    try {
        walkScriptPushes(hexToBytes(hexStr), ({ opcode, lastInteger }) => {
            if (opcode === 0xa5 && !foundFirstGte) {
                result.threshold_sompi = lastInteger;
                foundFirstGte = true;
            }
            if (opcode === 0xb0) result.deadline_daa = lastInteger;
            return true;
        });
    } catch (_) {}
    return result;
}
