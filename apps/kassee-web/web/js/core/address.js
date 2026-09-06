import { decode_address } from '../wasm/api.js';

export function addressToScriptPublicKeyHex(address) {
    const decoded = JSON.parse(decode_address(address));
    if (decoded.version === 0) return `20${decoded.payload}ac`;
    if (decoded.version === 8) return `aa20${decoded.payload}87`;
    throw new Error(`Unknown address version: ${decoded.version}`);
}

export function addressToXOnly(value) {
    const normalized = (value || '').trim();
    if (!normalized.startsWith('kaspa:') && !normalized.startsWith('kaspatest:')) {
        return normalized;
    }
    try {
        const decoded = JSON.parse(decode_address(normalized));
        return decoded.payload && decoded.payload.length === 64 ? decoded.payload : '';
    } catch (_) {
        return '';
    }
}
