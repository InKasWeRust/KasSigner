// Shared opcode-aware script push traversal.

function decodeLittleEndianInteger(bytes, start, length) {
    if (start < 0 || length < 0 || start + length > bytes.length) return null;
    let value = 0n;
    for (let offset = 0; offset < length; offset++) {
        value |= BigInt(bytes[start + offset]) << BigInt(offset * 8);
    }
    return value;
}

/**
 * Walk script opcodes while tracking the most recently pushed integer.
 *
 * The visitor runs before the current opcode changes `lastInteger`, matching
 * covenant patterns that consume the preceding push. Return `false` to stop.
 */
export function walkScriptPushes(bytes, visitor) {
    let lastInteger = 0n;
    let offset = 0;

    while (offset < bytes.length) {
        const opcode = bytes[offset];
        if (visitor({ opcode, offset, lastInteger }) === false) return;

        if (opcode === 0x00) {
            lastInteger = 0n;
            offset += 1;
            continue;
        }

        if (opcode >= 0x51 && opcode <= 0x60) {
            lastInteger = BigInt(opcode - 0x50);
            offset += 1;
            continue;
        }

        if (opcode >= 0x01 && opcode <= 0x4b) {
            const length = opcode;
            const value = decodeLittleEndianInteger(bytes, offset + 1, length);
            if (value !== null) lastInteger = value;
            offset += 1 + length;
            continue;
        }

        if (opcode === 0x4c) {
            if (offset + 1 >= bytes.length) return;
            const length = bytes[offset + 1];
            const value = decodeLittleEndianInteger(bytes, offset + 2, length);
            if (value !== null) lastInteger = value;
            offset += 2 + length;
            continue;
        }

        offset += 1;
    }
}
