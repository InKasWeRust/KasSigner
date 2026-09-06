import { exactJsonStringify, exactUnsigned } from '../../../core/exact.js';

export const EXACT_COVENANT_FIELDS = Object.freeze([
    'locktime_daa',
    'inactivity_daa',
    'goal_sompi',
    'threshold_sompi',
    'deadline_daa',
    'max_withdraw_sompi',
    'cooldown_daa',
    'min_sequence',
    'start_daa',
]);

export function normalizeCovenantExactFields(record) {
    if (!record || typeof record !== 'object') return record;
    for (const field of EXACT_COVENANT_FIELDS) {
        const value = record[field];
        if (value !== undefined && value !== null && value !== '') {
            record[field] = exactUnsigned(value, field);
        }
    }
    return record;
}

export function parseCovenantJson(json) {
    return normalizeCovenantExactFields(JSON.parse(json));
}

export function stringifyCovenantJson(value) {
    return exactJsonStringify(value);
}
