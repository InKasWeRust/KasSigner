import { networkState, scannerState, walletSession } from '../../../app/state/index.js';
import { hideLoading, showScreen } from '../../../app/navigation.js';
import { isWasmReady, wasmRuntimeStatus } from '../../../wasm/runtime.js';
import { refreshBalance } from './balance.js';
import { syncWalletUnloadAction } from '../reset.js';
import { isSupportedKpubText, normalizeKpubText } from './kpub_qr_payload.js';
import { import_kpub, import_kpub_raw } from '../../../wasm/api.js';

const INVALID_KPUB_MESSAGE = 'Invalid account key — expected canonical kpub1 text, an original Base58Check kpub, or an account-level xpub';
const COMPACT_ACCOUNT_KEY_LENGTH = 79;
const COMPACT_ACCOUNT_KEY_VERSION = 0x01;
const RAW_ACCOUNT_KEY_LENGTH = 78;

function runtimeUnavailableMessage() {
    const status = wasmRuntimeStatus();
    return status.state === 'failed'
        ? 'KasSee WebAssembly is unavailable. Run `make kassee`, reload the page, and try again.'
        : 'KasSee is still initializing. Wait for the ready message and try again.';
}

function parseWalletData(walletData) {
    return typeof walletData === 'string' ? JSON.parse(walletData) : walletData;
}

function derivedWalletResult(walletData, fallbackKpub = '') {
    const wallet = parseWalletData(walletData);
    return {
        normalizedKpub: wallet?.kpub || fallbackKpub,
        walletData,
        wallet,
    };
}

function asBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) return Uint8Array.from(value);
    return new Uint8Array();
}

function finishWalletImport(walletData, options = {}) {
    walletSession.replace(walletData);
    walletSession.setProfile(options.profile || null);
    syncWalletUnloadAction();
    hideLoading();


    showScreen(options.successScreen || 'dashboard');
    scannerState.refreshing = false;
    options.onImported?.(walletSession.current());
    setTimeout(() => { refreshBalance(); }, 50);
    setTimeout(() => { refreshBalance(); }, 5000);
}

function ensureWasmReady() {
    if (!isWasmReady()) throw new Error(runtimeUnavailableMessage());
}

export function deriveKpubWallet(kpubText, network = networkState.network) {
    const normalizedKpub = normalizeKpubText(kpubText);
    if (!isSupportedKpubText(normalizedKpub)) throw new Error(INVALID_KPUB_MESSAGE);
    ensureWasmReady();
    return derivedWalletResult(import_kpub(normalizedKpub, network), normalizedKpub);
}

export function deriveRawKpubWallet(rawPayload, network = networkState.network) {
    const bytes = asBytes(rawPayload);
    if (bytes.length !== RAW_ACCOUNT_KEY_LENGTH) {
        throw new Error(`Invalid compact account-key payload — expected ${RAW_ACCOUNT_KEY_LENGTH} bytes`);
    }
    ensureWasmReady();
    return derivedWalletResult(import_kpub_raw(bytes, network));
}

export function deriveKpubQrWallet(data, network = networkState.network) {
    const bytes = asBytes(data);
    if (bytes.length === COMPACT_ACCOUNT_KEY_LENGTH && bytes[0] === COMPACT_ACCOUNT_KEY_VERSION) {
        return deriveRawKpubWallet(bytes.slice(1), network);
    }

    const text = typeof data === 'string'
        ? normalizeKpubText(data)
        : normalizeKpubText(new TextDecoder().decode(bytes));
    return deriveKpubWallet(text, network);
}

export function activateKpubWallet(walletData, options = {}) {
    finishWalletImport(walletData, options);
    return true;
}
