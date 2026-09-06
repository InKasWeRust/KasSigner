import { bytesToHex } from '../../../../core/bytes.js';

const COVB_HEX = '434f5642';
const COVI_HEX = '434f5649';

export function normalizeScanBytes(data) {
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'string') return new TextEncoder().encode(data.trim());
    if (data?.data instanceof ArrayBuffer) return new Uint8Array(data.data);
    if (ArrayBuffer.isView(data?.data)) {
        return new Uint8Array(data.data.buffer, data.data.byteOffset, data.data.byteLength);
    }
    if (Array.isArray(data?.data)) return Uint8Array.from(data.data);
    throw new Error('Unrecognized QR data');
}

export function covenantHexFromBytes(raw) {
    if (raw.length < 4) return null;

    const binaryHex = bytesToHex(raw);
    if (hasCovenantHeader(binaryHex)) return binaryHex;

    const text = new TextDecoder().decode(raw).trim();
    if (/^[0-9a-f]+$/i.test(text) && text.length % 2 === 0 && hasCovenantHeader(text)) {
        return text.toLowerCase();
    }
    return null;
}

function hasCovenantHeader(hex) {
    const header = hex.slice(0, 8).toLowerCase();
    return header === COVB_HEX || header === COVI_HEX;
}

export function covenantKind(hex) {
    const header = hex.slice(0, 8).toLowerCase();
    if (header === COVB_HEX) return 'backup';
    if (header === COVI_HEX) return 'invite';
    return null;
}
