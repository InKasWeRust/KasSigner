const STORAGE_KEY = 'kassee-kpub-manager-v1';
const STORE_VERSION = 1;
const MAX_NAME_LENGTH = 64;
const SUPPORTED_NETWORKS = new Set(['mainnet', 'testnet-10', 'testnet-12']);

function clone(value) {
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
}

function emptyStore() {
    return { version: STORE_VERSION, entries: [], autoLoadId: null };
}

function cleanName(name) {
    return String(name || '').trim().replace(/\s+/g, ' ');
}

function normalizeName(name) {
    const normalized = cleanName(name);
    if (!normalized) throw new Error('Enter a friendly name.');
    if (normalized.length > MAX_NAME_LENGTH) {
        throw new Error(`Friendly names must be ${MAX_NAME_LENGTH} characters or fewer.`);
    }
    return normalized;
}

function nextDefaultName(entries) {
    const used = new Set(entries.map(entry => entry.name.toLocaleLowerCase()));
    let index = 1;
    while (used.has(`wallet ${index}`)) index += 1;
    return `Wallet ${index}`;
}

function normalizeNetwork(network) {
    const normalized = String(network || '').trim();
    if (!SUPPORTED_NETWORKS.has(normalized)) throw new Error('Unsupported Kaspa network.');
    return normalized;
}

function normalizeKpub(kpub) {
    const normalized = String(kpub || '').trim();
    if (!normalized) throw new Error('Enter an account public key.');
    return normalized;
}

function normalizeEntry(value) {
    if (!value || typeof value !== 'object') return null;
    try {
        const id = String(value.id || '').trim();
        if (!id) return null;
        return {
            id,
            name: normalizeName(value.name),
            kpub: normalizeKpub(value.kpub),
            network: normalizeNetwork(value.network || 'mainnet'),
            createdAt: Number.isFinite(value.createdAt) ? value.createdAt : Date.now(),
            updatedAt: Number.isFinite(value.updatedAt) ? value.updatedAt : Date.now(),
        };
    } catch (_) {
        return null;
    }
}

function normalizeStore(value) {
    if (!value || typeof value !== 'object') return emptyStore();
    const entries = Array.isArray(value.entries)
        ? value.entries.map(normalizeEntry).filter(Boolean)
        : [];
    const ids = new Set(entries.map(entry => entry.id));
    const autoLoadId = ids.has(value.autoLoadId) ? value.autoLoadId : null;
    return { version: STORE_VERSION, entries, autoLoadId };
}

function defaultIdFactory() {
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    return `kpub-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function createKpubRepository(storage = globalThis.localStorage, idFactory = defaultIdFactory) {
    function read() {
        if (!storage) return emptyStore();
        try {
            const serialized = storage.getItem(STORAGE_KEY);
            if (!serialized) return emptyStore();
            return normalizeStore(JSON.parse(serialized));
        } catch (_) {
            return emptyStore();
        }
    }

    function write(store) {
        if (!storage) throw new Error('Browser storage is unavailable.');
        const normalized = normalizeStore(store);
        try {
            storage.setItem(STORAGE_KEY, JSON.stringify(normalized));
        } catch (_) {
            throw new Error('KasSee could not save kpubs in this browser.');
        }
        return normalized;
    }

    function list() {
        return clone(read().entries.sort((a, b) => a.name.localeCompare(b.name)));
    }

    function get(id) {
        const entry = read().entries.find(item => item.id === id);
        return entry ? clone(entry) : null;
    }

    function save({ name, kpub, network }) {
        const normalizedKpub = normalizeKpub(kpub);
        const normalizedNetwork = normalizeNetwork(network);
        const store = read();
        let entry = store.entries.find(item =>
            item.kpub === normalizedKpub && item.network === normalizedNetwork);
        const requestedName = cleanName(name);
        const normalizedName = requestedName
            ? normalizeName(requestedName)
            : entry?.name || nextDefaultName(store.entries);
        const duplicateName = store.entries.find(entry =>
            entry.name.toLocaleLowerCase() === normalizedName.toLocaleLowerCase()
            && !(entry.kpub === normalizedKpub && entry.network === normalizedNetwork));
        if (duplicateName) throw new Error('A saved kpub already uses that friendly name.');

        const now = Date.now();
        if (entry) {
            entry.name = normalizedName;
            entry.updatedAt = now;
        } else {
            entry = {
                id: idFactory(),
                name: normalizedName,
                kpub: normalizedKpub,
                network: normalizedNetwork,
                createdAt: now,
                updatedAt: now,
            };
            store.entries.push(entry);
        }
        write(store);
        return clone(entry);
    }

    function rename(id, name) {
        const normalizedName = normalizeName(name);
        const store = read();
        const entry = store.entries.find(item => item.id === id);
        if (!entry) throw new Error('Saved kpub not found.');
        const duplicate = store.entries.find(item =>
            item.id !== id && item.name.toLocaleLowerCase() === normalizedName.toLocaleLowerCase());
        if (duplicate) throw new Error('A saved kpub already uses that friendly name.');
        entry.name = normalizedName;
        entry.updatedAt = Date.now();
        write(store);
        return clone(entry);
    }

    function remove(id) {
        const store = read();
        const entry = store.entries.find(item => item.id === id);
        if (!entry) return null;
        store.entries = store.entries.filter(item => item.id !== id);
        if (store.autoLoadId === id) store.autoLoadId = null;
        write(store);
        return clone(entry);
    }

    function setAutoLoad(id) {
        const store = read();
        if (id !== null && !store.entries.some(entry => entry.id === id)) {
            throw new Error('Saved kpub not found.');
        }
        store.autoLoadId = id;
        write(store);
        return id;
    }

    function autoLoadId() {
        return read().autoLoadId;
    }

    function autoLoadEntry() {
        const store = read();
        const entry = store.entries.find(item => item.id === store.autoLoadId);
        return entry ? clone(entry) : null;
    }

    return Object.freeze({ list, get, save, rename, remove, setAutoLoad, autoLoadId, autoLoadEntry });
}

export const kpubRepository = createKpubRepository();
