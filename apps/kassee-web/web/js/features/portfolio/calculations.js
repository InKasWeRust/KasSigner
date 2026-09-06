import { exactUnsigned } from '../../core/exact.js';
import { kasValueMicro, proportionalCost } from './exact_money.js';

const INFLOW_TYPES = new Set(['Buy', 'Transfer In']);
const OUTFLOW_TYPES = new Set(['Sell', 'Transfer Out']);

function ordered(entries) {
    return [...entries].sort((left, right) => left.timestampMs - right.timestampMs || left.createdAt - right.createdAt);
}

function applyInflow(summary, entry) {
    const amount = exactUnsigned(entry.kasSompi, 'portfolio transaction amount');
    summary.holdings += amount;
    if (entry.type === 'Buy') {
        const acquisition = kasValueMicro(amount, entry.priceMicroUsd);
        summary.lifetimeBuyCost += acquisition;
        summary.remainingCostBasis += acquisition;
        summary.totalBought += amount;
    } else {
        summary.totalTransferredIn += amount;
    }
}

function applyOutflow(summary, entry) {
    const requested = exactUnsigned(entry.kasSompi, 'portfolio transaction amount');
    const disposed = requested < summary.holdings ? requested : summary.holdings;
    const releasedCost = proportionalCost(summary.remainingCostBasis, disposed, summary.holdings);
    summary.holdings -= disposed;
    summary.remainingCostBasis -= releasedCost;
    if (entry.type === 'Sell') summary.totalSold += requested;
    else summary.totalTransferredOut += requested;
}

export function holdingSummary(entries) {
    const summary = {
        holdings: 0n,
        lifetimeBuyCost: 0n,
        remainingCostBasis: 0n,
        totalBought: 0n,
        totalSold: 0n,
        totalTransferredIn: 0n,
        totalTransferredOut: 0n,
    };
    for (const entry of ordered(entries)) {
        if (INFLOW_TYPES.has(entry.type)) applyInflow(summary, entry);
        else if (OUTFLOW_TYPES.has(entry.type)) applyOutflow(summary, entry);
    }
    return summary;
}

export function holdingsAt(entries, timestampMs) {
    return holdingSummary(entries.filter(entry => entry.timestampMs <= timestampMs)).holdings;
}

export function portfolioValueMicro(entries, priceMicroUsd) {
    return kasValueMicro(holdingSummary(entries).holdings, priceMicroUsd);
}

export function chartValues(entries, prices) {
    return prices.map(point => ({
        timestampMs: point.timestampMs,
        valueMicroUsd: kasValueMicro(holdingsAt(entries, point.timestampMs), point.priceMicroUsd),
    }));
}
