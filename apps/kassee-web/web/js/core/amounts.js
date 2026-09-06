// Pure, lossless Kaspa amount conversions.

import { exactUnsigned } from './exact.js';

export const SOMPI_PER_KAS = 100000000n;

export function kasToSompi(value) {
    const text = String(value).trim();
    if (!/^\d+(\.\d{1,8})?$/.test(text)) {
        throw new Error('Invalid KAS amount: ' + text);
    }
    const [whole, fraction = ''] = text.split('.');
    const paddedFraction = (fraction + '00000000').slice(0, 8);
    return BigInt(whole) * SOMPI_PER_KAS + BigInt(paddedFraction);
}

export function sompiToKasString(sompi) {
    const value = exactUnsigned(sompi, 'sompi');
    const digits = value.toString().padStart(9, '0');
    const whole = digits.slice(0, -8);
    const fraction = digits.slice(-8).replace(/0+$/, '');
    return fraction ? `${whole}.${fraction}` : whole;
}

export function sompiToKasFixed(sompi, fractionDigits = 8) {
    if (!Number.isInteger(fractionDigits) || fractionDigits < 0 || fractionDigits > 8) {
        throw new Error('fractionDigits must be 0..8');
    }
    const value = exactUnsigned(sompi, 'sompi');
    const whole = value / SOMPI_PER_KAS;
    if (fractionDigits === 0) return whole.toString();
    const fraction = (value % SOMPI_PER_KAS).toString().padStart(8, '0').slice(0, fractionDigits);
    return `${whole}.${fraction}`;
}
