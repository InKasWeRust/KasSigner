// Covenant families supported by the generic live watcher.

const WATCHED_COVENANT_TYPES = Object.freeze([
    'dms',
    'timelocked-savings',
    'global-spending-limit',
    'global-allowance',
    'additive',
    'escrow',
    'merkle-whitelist',
    'payjoin',
    'commit-reveal',
    'oracle-v1',
]);

export function isWatchedCovenantType(type) {
    return WATCHED_COVENANT_TYPES.includes(type);
}
