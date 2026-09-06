import { hexToBytes } from '../../../../../core/bytes.js';

function readLength(bytes, offset) {
    if (offset >= bytes.length) throw new Error('Unexpected end of signature script');
    const opcode = bytes[offset];
    if (opcode === 0x00) return { length: 0, dataOffset: offset + 1 };
    if (opcode <= 75) return { length: opcode, dataOffset: offset + 1 };
    if (opcode === 0x4c) {
        if (offset + 1 >= bytes.length) throw new Error('Truncated OP_PUSHDATA1');
        return { length: bytes[offset + 1], dataOffset: offset + 2 };
    }
    if (opcode === 0x4d) {
        if (offset + 2 >= bytes.length) throw new Error('Truncated OP_PUSHDATA2');
        return {
            length: bytes[offset + 1] | (bytes[offset + 2] << 8),
            dataOffset: offset + 3,
        };
    }
    throw new Error('Unsupported signature-script push opcode');
}

export function readPush(bytes, offset) {
    const { length, dataOffset } = readLength(bytes, offset);
    const end = dataOffset + length;
    if (end > bytes.length) throw new Error('Truncated signature-script push');
    return { data: bytes.slice(dataOffset, end), nextOffset: end };
}

export function parseCommitRevealSignatureScript(signatureScriptHex) {
    const bytes = hexToBytes(signatureScriptHex);
    let offset = 0;
    const partA = readPush(bytes, offset);
    offset = partA.nextOffset;
    const partB = readPush(bytes, offset);
    offset = partB.nextOffset;
    const signature = readPush(bytes, offset);
    offset = signature.nextOffset;
    if (bytes[offset] !== 0x00) throw new Error('Missing commit-reveal branch selector');
    offset += 1;
    const redeem = readPush(bytes, offset);
    return { partA: partA.data, partB: partB.data, redeemScript: redeem.data };
}
