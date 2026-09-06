import { exactUnsigned } from '../exact.js';
import { fetchCurrentDaa } from './daa.js';

const DAA_PER_SECOND = 10n;

class FutureDaaError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'FutureDaaError';
        this.code = code;
    }
}

function futureSeconds(datetimeValue, nowMs = Date.now()) {
    const targetMs = new Date(datetimeValue).getTime();
    if (!Number.isFinite(targetMs)) {
        throw new FutureDaaError('invalid-date', 'Enter a valid future date and time');
    }
    if (targetMs <= nowMs) {
        throw new FutureDaaError('past-date', 'Pick a future date and time');
    }
    return Math.ceil((targetMs - nowMs) / 1000);
}

export async function resolveFutureDaa(datetimeValue) {
    const secondsUntil = futureSeconds(datetimeValue);
    const currentDaa = exactUnsigned(await fetchCurrentDaa(), 'current DAA score');
    if (currentDaa === 0n) {
        throw new FutureDaaError('daa-unavailable', 'Could not fetch DAA score. Check node connection.');
    }
    return {
        currentDaa,
        secondsUntil,
        daa: currentDaa + BigInt(secondsUntil) * DAA_PER_SECOND,
    };
}
