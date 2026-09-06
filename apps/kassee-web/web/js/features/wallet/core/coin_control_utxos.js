import { networkState, walletSession } from '../../../app/state/index.js';
import { kaspaRestApiBase } from '../../../core/config/network.js';
import { exactUnsigned } from '../../../core/exact.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { fetch_utxos_complete } from '../../../wasm/api.js';

const REST_BATCH_ADDRESSES = 8;
const REST_TIMEOUT_MS = 8_000;
const TXID_RE = /^[0-9a-fA-F]{64}$/;
const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

function walletAddresses(wallet) {
    return [...(wallet?.receive_addresses || []), ...(wallet?.change_addresses || [])]
        .map(value => String(value || '').trim())
        .filter(Boolean);
}

function restBase() {
    const configured = String(networkState.customRestUrl || '').trim();
    return (configured || kaspaRestApiBase(networkState.network)).replace(/\/+$/, '');
}

function restSignal() {
    return typeof globalThis.AbortSignal?.timeout === 'function'
        ? globalThis.AbortSignal.timeout(REST_TIMEOUT_MS)
        : undefined;
}

function restScriptHex(entry) {
    const value = entry?.utxoEntry?.scriptPublicKey?.scriptPublicKey;
    if (typeof value !== 'string' || !HEX_RE.test(value)) {
        throw new Error('REST UTXO scriptPublicKey must be non-empty even-length hex');
    }
    return value.toLowerCase();
}

function restUtxo(entry, requested) {
    const address = String(entry?.address || '');
    if (!requested.has(address)) throw new Error('REST UTXO belongs to an unrequested address');
    const txId = String(entry?.outpoint?.transactionId || '');
    if (!TXID_RE.test(txId)) throw new Error('REST UTXO transactionId must be 32-byte hex');
    const index = Number(entry?.outpoint?.index);
    if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff) {
        throw new Error('REST UTXO index must fit u32');
    }
    const amountValue = entry?.utxoEntry?.amount;
    const daaValue = entry?.utxoEntry?.blockDaaScore;
    if (typeof amountValue !== 'string' || typeof daaValue !== 'string') {
        throw new Error('REST UTXO consensus integers must be decimal strings');
    }
    const amount = exactUnsigned(amountValue, 'REST UTXO amount').toString();
    const blockDaaScore = exactUnsigned(daaValue, 'REST UTXO DAA score').toString();
    return {
        tx_id: txId.toLowerCase(),
        index,
        amount,
        script_public_key: restScriptHex(entry),
        block_daa_score: blockDaaScore,
        covenant_id: null,
        address,
    };
}

function sameUtxo(left, right) {
    return left.amount === right.amount
        && left.script_public_key === right.script_public_key
        && left.block_daa_score === right.block_daa_score
        && left.address === right.address;
}

function appendRestEntries(destination, seen, rawEntries, requested) {
    if (!Array.isArray(rawEntries)) throw new Error('REST UTXO response must be an array');
    for (const raw of rawEntries) {
        const entry = restUtxo(raw, requested);
        const key = `${entry.tx_id}:${entry.index}`;
        const previous = seen.get(key);
        if (previous && !sameUtxo(previous, entry)) {
            throw new Error(`REST returned conflicting data for UTXO ${key}`);
        }
        if (!previous) {
            seen.set(key, entry);
            destination.push(entry);
        }
    }
}

async function fetchRestBatch(base, addresses) {
    const response = await fetch(`${base}/addresses/utxos`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ addresses }),
        signal: restSignal(),
    });
    if (!response?.ok) throw new Error(`REST UTXO query failed with HTTP ${response?.status ?? 'unknown'}`);
    return response.json();
}

export async function fetchRestCoinControlUtxos(wallet = walletSession.current()) {
    const addresses = walletAddresses(wallet);
    if (!addresses.length) return { utxos: [], scannedAddresses: 0, source: 'REST' };
    const base = restBase();
    const complete = [];
    const seen = new Map();
    for (let offset = 0; offset < addresses.length; offset += REST_BATCH_ADDRESSES) {
        const batch = addresses.slice(offset, offset + REST_BATCH_ADDRESSES);
        const raw = await fetchRestBatch(base, batch);
        appendRestEntries(complete, seen, raw, new Set(batch));
    }
    return { utxos: complete, scannedAddresses: addresses.length, source: 'REST' };
}

export async function fetchCoinControlUtxos({ wsUrl = null } = {}) {
    const wallet = walletSession.current();
    if (!wallet) throw new Error('No wallet loaded');
    try {
        return await fetchRestCoinControlUtxos(wallet);
    } catch (restError) {
        console.warn('[KasSee] Complete REST UTXO scan failed; falling back to wRPC:', restError);
        const endpoint = wsUrl || await resolveNodeUrl();
        const parsed = JSON.parse(await fetch_utxos_complete(walletSession.json(), endpoint));
        if (!Array.isArray(parsed)) throw new Error('wRPC UTXO response must be an array');
        return {
            utxos: parsed,
            scannedAddresses: walletAddresses(wallet).length,
            source: 'wRPC fallback',
        };
    }
}
