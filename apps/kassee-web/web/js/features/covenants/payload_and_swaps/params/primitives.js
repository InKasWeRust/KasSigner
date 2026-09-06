import { bytesToHex } from '../../../../core/bytes.js';

export const pubkeyHex = (value) => (value || '').padEnd(64, '0').substring(0, 64);

export function u64LeHex(value) {
    const number = BigInt(value || 0);
    let hex = '';
    for (let index = 0; index < 8; index++) {
        hex += ((number >> BigInt(index * 8)) & 0xffn).toString(16).padStart(2, '0');
    }
    return hex;
}

export function variableHex(value) {
    const hex = value || '';
    const length = hex.length / 2;
    return (length & 0xff).toString(16).padStart(2, '0')
        + ((length >> 8) & 0xff).toString(16).padStart(2, '0')
        + hex;
}

export function variableString(value) {
    const bytes = new TextEncoder().encode(value || '');
    const length = bytes.length;
    return (length & 0xff).toString(16).padStart(2, '0')
        + ((length >> 8) & 0xff).toString(16).padStart(2, '0')
        + bytesToHex(bytes);
}
