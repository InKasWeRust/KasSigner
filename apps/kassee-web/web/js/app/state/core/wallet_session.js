// Parsed wallet session. JSON serialization is confined to WASM and persistence boundaries.
let walletJson = null;
let walletSnapshot = null;
let walletProfile = null;

function cloneWallet(value) {
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
}

function parseWallet(value) {
    if (typeof value === 'string') {
        const snapshot = JSON.parse(value);
        return { json: value, snapshot: cloneWallet(snapshot) };
    }
    if (value && typeof value === 'object') {
        const snapshot = cloneWallet(value);
        return { json: JSON.stringify(snapshot), snapshot };
    }
    throw new TypeError('wallet payload must be a JSON string or object');
}

export function bestEffortScrubMutable(value, seen = new WeakSet()) {
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (ArrayBuffer.isView(value) && typeof value.fill === 'function') {
        try { value.fill(0); } catch (_) {}
        return;
    }
    if (value instanceof ArrayBuffer) {
        try { new Uint8Array(value).fill(0); } catch (_) {}
        return;
    }
    if (value instanceof Set || value instanceof Map) {
        value.clear();
        return;
    }
    for (const key of Object.keys(value)) {
        const current = value[key];
        if (current && typeof current === 'object') bestEffortScrubMutable(current, seen);
        try {
            if (typeof current === 'string') value[key] = '';
            else if (typeof current === 'bigint') value[key] = 0n;
            else if (typeof current === 'number') value[key] = 0;
            else if (typeof current === 'boolean') value[key] = false;
            else if (current && typeof current === 'object') value[key] = null;
        } catch (_) {}
    }
    if (Array.isArray(value)) value.length = 0;
}

export const walletSession = Object.freeze({
    hasWallet() {
        return walletSnapshot !== null;
    },
    current() {
        return walletSnapshot === null ? null : cloneWallet(walletSnapshot);
    },
    json() {
        return walletJson;
    },
    kpub() {
        return walletSnapshot?.kpub || '';
    },
    replace(value) {
        const parsed = parseWallet(value);
        walletJson = parsed.json;
        walletSnapshot = parsed.snapshot;
        return cloneWallet(walletSnapshot);
    },
    profile() {
        return walletProfile === null ? null : { ...walletProfile };
    },
    setProfile(profile) {
        if (profile === null || profile === undefined) {
            walletProfile = null;
            return null;
        }
        const id = String(profile.id || '').trim();
        const name = String(profile.name || '').trim();
        walletProfile = id && name ? { id, name } : null;
        return walletProfile === null ? null : { ...walletProfile };
    },
    clear() {
        bestEffortScrubMutable(walletSnapshot);
        bestEffortScrubMutable(walletProfile);
        walletJson = '';
        walletSnapshot = null;
        walletProfile = null;
    },
    primaryReceiveAddress() {
        return walletSnapshot?.receive_addresses?.[0] || '';
    },
});
