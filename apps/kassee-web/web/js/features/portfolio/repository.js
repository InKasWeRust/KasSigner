const STORAGE_KEY = 'kassee-portfolio-v1';
const EMPTY_STORE = Object.freeze({ schema: 1, accounts: [], transactions: [] });

function cloneEmptyStore() {
    return { schema: EMPTY_STORE.schema, accounts: [], transactions: [] };
}

function validArray(value) {
    return Array.isArray(value) ? value : [];
}

function normalizeStore(raw) {
    if (!raw || raw.schema !== 1) return cloneEmptyStore();
    return { schema: 1, accounts: validArray(raw.accounts), transactions: validArray(raw.transactions) };
}

export function loadPortfolioStore() {
    try {
        return normalizeStore(JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'));
    } catch (_) {
        return cloneEmptyStore();
    }
}

export function savePortfolioStore(store) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(normalizeStore(store)));
}

export function newId() {
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    const bytes = new Uint8Array(16);
    globalThis.crypto?.getRandomValues?.(bytes);
    return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function createAccount(store, name) {
    const trimmed = String(name ?? '').trim();
    if (!trimmed) throw new Error('Portfolio name is required');
    const account = { id: newId(), name: trimmed.slice(0, 64), createdAt: Date.now() };
    store.accounts.push(account);
    savePortfolioStore(store);
    return account;
}

export function renameAccount(store, accountId, name) {
    const account = store.accounts.find(candidate => candidate.id === accountId);
    if (!account) throw new Error('Portfolio not found');
    const trimmed = String(name ?? '').trim();
    if (!trimmed) throw new Error('Portfolio name is required');
    account.name = trimmed.slice(0, 64);
    savePortfolioStore(store);
    return account;
}

export function deleteAccount(store, accountId) {
    store.accounts = store.accounts.filter(account => account.id !== accountId);
    store.transactions = store.transactions.filter(entry => entry.portfolioId !== accountId);
    savePortfolioStore(store);
}

export function upsertTransaction(store, transaction) {
    const index = store.transactions.findIndex(entry => entry.id === transaction.id);
    if (index >= 0) store.transactions[index] = transaction;
    else store.transactions.push(transaction);
    savePortfolioStore(store);
    return transaction;
}

export function deleteTransaction(store, transactionId) {
    store.transactions = store.transactions.filter(entry => entry.id !== transactionId);
    savePortfolioStore(store);
}

export function importedTxIds(store, accountId) {
    return new Set(store.transactions.filter(entry => entry.portfolioId === accountId && entry.sourceTxId).map(entry => entry.sourceTxId));
}
