import { hexToBytes } from '../../../core/bytes.js';

// Pure compact-KSPT v4 signature-state inspection.

function u16le(bytes, offset) {
    return bytes[offset] | (bytes[offset + 1] << 8);
}

function u32le(bytes, offset) {
    return (bytes[offset]
        | (bytes[offset + 1] << 8)
        | (bytes[offset + 2] << 16)
        | (bytes[offset + 3] << 24)) >>> 0;
}

function compactLength(bytes, offset) {
    if (offset >= bytes.length) return null;
    if (bytes[offset] !== 0xff) return { length: bytes[offset], next: offset + 1 };
    if (offset + 2 >= bytes.length) return null;
    return { length: u16le(bytes, offset + 1), next: offset + 3 };
}

function header(bytes, version) {
    if (version !== 0x04 || bytes.length < 51) return null;
    const payloadLength = u16le(bytes, 49);
    return { inputCount: u32le(bytes, 8), offset: 51 + payloadLength };
}

function skipInput(bytes, offset) {
    const fixedEnd = offset + 32 + 4 + 8 + 8 + 1 + 2;
    if (fixedEnd > bytes.length) return null;
    const script = compactLength(bytes, fixedEnd);
    if (!script) return null;
    let cursor = script.next + script.length;
    if (cursor >= bytes.length) return null;
    const signatureCount = bytes[cursor];
    cursor += 1;
    if (signatureCount > 0 && signatureCount < 0xff) {
        return { status: 'partial', offset: cursor };
    }
    const encodedSignatureCount = signatureCount === 0xff ? 0 : signatureCount;
    cursor += encodedSignatureCount * 66;
    if (cursor + 2 > bytes.length) return null;
    const redeemLength = u16le(bytes, cursor);
    cursor += 2 + redeemLength;
    return cursor <= bytes.length ? { status: 'unsigned', offset: cursor } : null;
}

export function inspectKsptSignatureStatus(hex) {
    if (hex.length < 12 || hex.substring(0, 8) !== '4b535054') return 'unknown';
    const version = Number.parseInt(hex.substring(8, 10), 16);
    const flags = Number.parseInt(hex.substring(10, 12), 16);
    if ((flags & 0x01) === 0x01) return 'signed';
    if (flags !== 0x00) return 'unknown';
    if (version !== 0x04) return 'unsupported';

    try {
        const bytes = hexToBytes(hex);
        const parsed = header(bytes, version);
        if (!parsed || parsed.offset > bytes.length) return 'unknown';
        let offset = parsed.offset;
        for (let index = 0; index < parsed.inputCount; index += 1) {
            const input = skipInput(bytes, offset);
            if (!input) return 'unknown';
            if (input.status === 'partial') return 'partial';
            offset = input.offset;
        }
        return 'unsigned';
    } catch (_) {
        return 'unknown';
    }
}
