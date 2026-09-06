import {
    commitRevealState,
    covenantRecoveryState,
    covenantState,
    covenantWatcherState,
    navigationState,
    networkState,
    oracleState,
    scannerState,
    stealthState,
    transactionState,
    uiState,
    walletSession,
    walletState,
} from '../../app/state/index.js';
import { bestEffortScrubMutable } from '../../app/state/core/wallet_session.js';
import { byId } from '../../core/dom.js';
import { reset_qr_decoder } from '../../wasm/api.js';
import { oracleMbAmbientStop } from '../oracle/model_b/controller.js';
import { stopOracleMbCountdown } from '../oracle/model_b/controller/proving/countdown.js';
import { covActiveWatcherStop } from '../covenants/recovery/active.js';
import { stopCrowdfundWatcher } from '../covenants/crowdfund/sweep.js';
import { stopPrivateSwapWatcher } from '../covenants/private_swap/watcher.js';
import { covWatcherStop } from '../covenants/watchers_and_ui/watcher/polling/lifecycle.js';
import { stopStealthScan } from '../stealth/index/scanning/live_controls/lifecycle.js';
import { hideOracleProvingScreen } from '../transactions/pskt_multisig/review_overlay.js';
import { clearAntiKleptoSession } from '../transactions/anti_klepto/session.js';
import { resetSignedQrImageImportSession } from '../transactions/send/signed_qr_image_import.js';
import { stopQrCycle } from '../transactions/send/review.js';
import { clearStandardChangeReservations } from './core/address_state.js';
import { stopAutoRefresh } from './core/refresh.js';

const SKIP_AUTOLOAD_ONCE_KEY = '__kassee_skip_autoload_once_v1';

function stopWalletRuntimeServices() {
    stopAutoRefresh();
    stopQrCycle();
    resetSignedQrImageImportSession();
    clearAntiKleptoSession();
    hideOracleProvingScreen();
    try { stopStealthScan(); } catch (_) {}
    try { covWatcherStop(); } catch (_) {}
    try { covActiveWatcherStop(); } catch (_) {}
    try { oracleMbAmbientStop(); } catch (_) {}
    try { stopOracleMbCountdown(); } catch (_) {}
    try { stopCrowdfundWatcher(); } catch (_) {}
    try { stopPrivateSwapWatcher(); } catch (_) {}
    try { reset_qr_decoder(); } catch (_) {}
    if (scannerState.scanAnimFrame) {
        cancelAnimationFrame(scannerState.scanAnimFrame);
        scannerState.scanAnimFrame = null;
    }
    if (scannerState.scanStream) {
        try { scannerState.scanStream.getTracks().forEach(track => track.stop()); } catch (_) {}
        scannerState.scanStream = null;
    }
    if (uiState.toastTimer) {
        clearTimeout(uiState.toastTimer);
        uiState.toastTimer = null;
    }
}

function clearTransientStateObjects() {
    for (const value of [
        covenantState.lastCovenantResult,
        oracleState._oracleMbState,
        stealthState._stealthResults,
        scannerState.qrFrames,
    ]) bestEffortScrubMutable(value);

    transactionState._currentKsptHex = undefined;
    transactionState._psktReviewHex = undefined;
    transactionState._lastKasSignerKsptHex = null;
    transactionState._lastBroadcastTime = undefined;
    transactionState._lastPsktSummary = undefined;
    transactionState._psktReviewContext = null;
    transactionState._standardChangeReservationIndex = null;
    transactionState.consolidateSelection = undefined;
    transactionState.selectedUtxoIds = null;
    transactionState.msSelectedUtxoIds = null;

    scannerState._covbFrames = null;
    scannerState._covbImporting = false;
    scannerState.qrFrameIdx = 0;
    scannerState.qrFrames = null;
    scannerState.refreshing = false;
    scannerState.scanCallback = null;
    scannerState._stlrFrames = null;
    scannerState._scannerReturnPanel = undefined;
    scannerState._scannerReturnScreen = undefined;



    commitRevealState._crDecryptCtBytes = undefined;
    commitRevealState._crRevealPartA = undefined;
    commitRevealState._crRevealPartB = undefined;
    covenantRecoveryState._covLoadedFromInvite = undefined;
    covenantRecoveryState._covLoadedInactivityDaa = undefined;
    covenantRecoveryState._covLoadedLdi = undefined;
    covenantState._covPayloadHex = undefined;
    covenantState._lastKnownDaa = undefined;
    covenantState.lastCovenantResult = null;
    covenantState._pickerBeneClaim = null;
    covenantState._kasFreezePathCPostBroadcast = undefined;
    covenantWatcherState._covWatcherLastBalance = null;
    covenantWatcherState._covWatcherOutpoint = null;
    covenantWatcherState._covWatcherSpendPath = undefined;
    covenantWatcherState._covWatcherTimer = null;
    covenantWatcherState._covActiveWatcherTimer = null;

    oracleState._oracleMbState = undefined;
    oracleState._oracleMbAgeTimer = null;
    oracleState._oracleMbPollTimer = null;
    oracleState._oracleMbPriceTs = undefined;
    oracleState._oracleMbProveDeadline = undefined;
    oracleState._oracleMbAskBusy = undefined;
    oracleState._oracleMbAutoBroadcast = undefined;
    oracleState._oracleMbPreSignAwaiting = undefined;
    oracleState._oracleMbRoll = undefined;
    oracleState._oracleMbRollActive = undefined;
    oracleState._oracleMbReturn = undefined;

    if (stealthState._stealthScanWs) {
        try { stealthState._stealthScanWs.close(); } catch (_) {}
    }
    stealthState._stealthScanWs = undefined;
    stealthState._stealthSendEntropy = undefined;
    stealthState._stealthSendMeta = undefined;
    stealthState._stealthResults = [];
    stealthState.stealthAnnouncementsR = [];
    stealthState._stealthScanActive = false;
    stealthState._stealthCatchupRunning = false;

    navigationState.screenHistory.length = 0;
    navigationState._broadcastReturnScreen = null;
    navigationState.settingsReturnScreen = undefined;
    navigationState.kpubManagerReturnScreen = undefined;
    navigationState.addressesReturnScreen = undefined;
}

function clearTransientDom() {
    const screenIds = [
        'screen-send', 'screen-qr-display', 'screen-broadcast', 'screen-pskt-review',
        'screen-multisig', 'screen-covenant', 'screen-stealth', 'screen-receive',
    ];
    for (const id of screenIds) {
        const screen = document.getElementById(id);
        if (!screen) continue;
        for (const element of screen.querySelectorAll('input, textarea')) {
            if (element.type === 'checkbox' || element.type === 'radio') element.checked = false;
            else element.value = '';
        }
    }
    for (const id of ['qr-container', 'qr-frame-info', 'qr-tx-info', 'broadcast-image-status']) {
        const element = document.getElementById(id);
        if (element) element.textContent = '';
    }
}

/** Clear wallet-derived state while preserving saved kpubs and persistent user settings. */
export function clearWalletSession() {
    walletSession.clear();
    networkState.lastFeeEstimate = null;
    networkState.cachedUtxos = null;
    networkState.msCachedUtxos = null;
    networkState.utxoSnapshot = null;
    walletState.historyEntries = [];
    walletState.fundedReceiveIndices = [];
    walletState.fundedChangeIndices = [];
    walletState.usedReceiveIndices = new Set();
    walletState.usedChangeIndices = new Set();
    clearStandardChangeReservations();
    const balanceKas = byId('balance-kas');
    if (balanceKas) balanceKas.textContent = '—';
    const balanceSompi = byId('balance-sompi');
    if (balanceSompi) balanceSompi.textContent = '';
    const balanceInfo = byId('balance-info');
    if (balanceInfo) balanceInfo.textContent = '';
    const balanceDaa = byId('balance-daa');
    if (balanceDaa) balanceDaa.textContent = '';
}

/**
 * Best-effort hardened wallet/session cleanup for browser-managed memory.
 * JavaScript strings cannot be guaranteed to be physically overwritten, so callers
 * that unload a wallet should additionally discard the current JS/WASM realm.
 */
export function hardenedWalletCleanup() {
    stopWalletRuntimeServices();
    clearTransientStateObjects();
    clearTransientDom();
    clearWalletSession();
    try { sessionStorage.clear(); } catch (_) {}
}

export function markSkipAutoLoadOnce() {
    try { localStorage.setItem(SKIP_AUTOLOAD_ONCE_KEY, '1'); } catch (_) {}
}

export function consumeSkipAutoLoadOnce() {
    try {
        const skip = localStorage.getItem(SKIP_AUTOLOAD_ONCE_KEY) === '1';
        if (skip) localStorage.removeItem(SKIP_AUTOLOAD_ONCE_KEY);
        return skip;
    } catch (_) {
        return false;
    }
}

export function requestWalletRuntimeReset() {
    markSkipAutoLoadOnce();
    let handledByHost = false;
    try {
        const event = new CustomEvent('kassee:request-runtime-reset', { cancelable: true });
        handledByHost = !globalThis.dispatchEvent(event);
    } catch (_) {}
    if (!handledByHost) globalThis.location.reload();
}
