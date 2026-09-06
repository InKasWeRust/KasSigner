import { kasToSompi, SOMPI_PER_KAS, sompiToKasString } from '../../core/amounts.js';
import { exactUnsigned } from '../../core/exact.js';

export const MICRO_USD_PER_USD = 1_000_000n;

function normalizeDecimalText(value, field) {
    const text = String(value ?? '').trim();
    if (!/^\d+(?:\.\d+)?$/.test(text)) throw new Error(`${field} must be a non-negative decimal`);
    return text;
}

export function decimalToScaled(value, scaleDigits, field = 'decimal') {
    const text = normalizeDecimalText(value, field);
    const [whole, fraction = ''] = text.split('.');
    if (fraction.length > scaleDigits) throw new Error(`${field} supports at most ${scaleDigits} decimal places`);
    const scale = 10n ** BigInt(scaleDigits);
    const padded = (fraction + '0'.repeat(scaleDigits)).slice(0, scaleDigits);
    return BigInt(whole) * scale + BigInt(padded || '0');
}

export function usdToMicro(value, field = 'USD value') {
    return decimalToScaled(value, 6, field);
}

export function microToUsd(value, digits = 2) {
    const amount = exactUnsigned(value, 'micro USD');
    const whole = amount / MICRO_USD_PER_USD;
    if (digits === 0) return whole.toString();
    const fraction = (amount % MICRO_USD_PER_USD).toString().padStart(6, '0').slice(0, digits);
    return `${whole}.${fraction}`;
}

export function formatUsd(value, digits = 2) {
    const text = microToUsd(value, digits);
    const [whole, fraction] = text.split('.');
    const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return `$${fraction === undefined ? grouped : `${grouped}.${fraction}`}`;
}

export function formatKas(sompi, maxFractionDigits = 8) {
    const text = sompiToKasString(exactUnsigned(sompi, 'portfolio sompi'));
    if (!text.includes('.')) return text;
    const [whole, fraction] = text.split('.');
    return `${whole}.${fraction.slice(0, maxFractionDigits)}`.replace(/\.0+$/, '');
}

export function parseKas(value) {
    return kasToSompi(normalizeDecimalText(value, 'KAS amount'));
}

export function kasValueMicro(sompi, priceMicro) {
    const amount = exactUnsigned(sompi, 'portfolio sompi');
    const price = exactUnsigned(priceMicro, 'portfolio USD price');
    return (amount * price) / SOMPI_PER_KAS;
}

export function proportionalCost(costMicro, disposedSompi, heldSompi) {
    const cost = exactUnsigned(costMicro, 'cost basis');
    const disposed = exactUnsigned(disposedSompi, 'disposed sompi');
    const held = exactUnsigned(heldSompi, 'held sompi');
    if (held === 0n || disposed === 0n) return 0n;
    return (cost * disposed) / held;
}
