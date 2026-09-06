// Exact conversion from advisory decimal fee rates to integral sompi fees.
// Fee rates may arrive from the node as JSON numbers, but once represented as
// their decimal text all multiplication, markup, rounding, and floors use BigInt.

import { exactUnsigned } from './exact.js';

function decimalRatio(value, field = 'decimal rate') {
    const text = String(value ?? '').trim().toLowerCase();
    const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/.exec(text);
    if (!match) throw new Error(`${field} must be a non-negative decimal`);

    const fraction = match[2] || '';
    const exponent = Number.parseInt(match[3] || '0', 10);
    let numerator = BigInt(match[1] + fraction);
    let denominator = 10n ** BigInt(fraction.length);
    if (exponent > 0) numerator *= 10n ** BigInt(exponent);
    else if (exponent < 0) denominator *= 10n ** BigInt(-exponent);
    return { numerator, denominator };
}

function positiveRatio(value, field) {
    const ratio = decimalRatio(value, field);
    if (ratio.numerator === 0n) return { numerator: 1n, denominator: 1n };
    return ratio;
}

export function roundFeeFromRate(rate, mass, floorSompi = 0n) {
    const { numerator, denominator } = positiveRatio(rate, 'fee rate');
    const exactMass = exactUnsigned(mass, 'transaction mass');
    const floor = exactUnsigned(floorSompi, 'fee floor');
    const product = numerator * exactMass;
    const rounded = (2n * product + denominator) / (2n * denominator);
    return rounded > floor ? rounded : floor;
}

export function ceilFeeFromRate(rate, mass, floorSompi = 0n, markupNumerator = 1n, markupDenominator = 1n) {
    const { numerator, denominator } = positiveRatio(rate, 'fee rate');
    const exactMass = exactUnsigned(mass, 'transaction mass');
    const floor = exactUnsigned(floorSompi, 'fee floor');
    const markupNum = exactUnsigned(markupNumerator, 'fee markup numerator');
    const markupDen = exactUnsigned(markupDenominator, 'fee markup denominator');
    if (markupDen === 0n) throw new Error('fee markup denominator must be non-zero');
    const scaledNumerator = numerator * exactMass * markupNum;
    const scaledDenominator = denominator * markupDen;
    const roundedUp = (scaledNumerator + scaledDenominator - 1n) / scaledDenominator;
    return roundedUp > floor ? roundedUp : floor;
}

export function ceilRateToInteger(rate) {
    const { numerator, denominator } = positiveRatio(rate, 'fee rate');
    return (numerator + denominator - 1n) / denominator;
}
