import { covenantState, navigationState, networkState, transactionState, walletSession } from '../../../../app/state/index.js';
import { showScreen } from '../../../../app/navigation.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { toast } from '../../../../core/ui/toast.js';
import { get_fee_estimate } from '../../../../wasm/api.js';
import { fetchCoinControlUtxos } from '../../../wallet/core/coin_control_utxos.js';
// KasSee Web — features/transactions/send/compose/send_form
import { byId } from '../../../../core/dom.js';

import { formatSeconds } from '../../../../core/format.js';
import { exactUnsigned } from '../../../../core/exact.js';
import { roundFeeFromRate } from '../../../../core/fee_math.js';
import { sompiToKasString } from '../../../../core/amounts.js';
import { addressPrefix } from '../../../../core/network.js';
import { normalizeUtxos, sortUtxosLargestFirst } from '../../../../core/utxo.js';
import { balanceSendMaximumKas, selectedSendMaximumSompi } from './send_max.js';
import { normalizeUtxoSortMode, renderUtxoSelector } from '../../shared/utxo_selector.js';
import { selectedUtxos, utxoId } from '../../shared/utxo_selection.js';
import { signerMaxInputs } from '../../shared/signer_limits.js';

// ─── Send ───

const DEFAULT_UTXO_SELECTION_LIMIT = 8;

function normalizeUtxoSelectionLimit(value) {
    const maximum = signerMaxInputs();
    const parsed = Number.parseInt(String(value), 10);
    return Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= maximum
        ? parsed
        : DEFAULT_UTXO_SELECTION_LIMIT;
}

export function limitKasAmountPrecision(input) {
    if (!input) return;
    const raw = String(input.value ?? '');
    let cleaned = raw.replace(/[^0-9.]/g, '');
    const dot = cleaned.indexOf('.');
    if (dot >= 0) {
        cleaned = cleaned.slice(0, dot + 1) + cleaned.slice(dot + 1).replace(/\./g, '').slice(0, 8);
    } else {
        cleaned = cleaned.replace(/\./g, '');
    }
    if (cleaned !== raw) input.value = cleaned;
}


async function openSendScreenWithOptions({ selectedUtxoIds = null, revealCoinControl = false } = {}) {
    transactionState.selectedUtxoIds = selectedUtxoIds?.length ? [...selectedUtxoIds] : null;
    networkState.cachedUtxos = null;
    // Only reset _broadcastReturnScreen if not pre-set by covenant deposit
    if (navigationState._broadcastReturnScreen !== 'covenant') navigationState._broadcastReturnScreen = null;
    const utxoList = byId('send-utxo-list');
    utxoList.innerHTML = '';
    byId('send-utxo-advanced').classList.add('hidden');
    byId('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
    const maxInputs = signerMaxInputs();
    const limitInput = byId('send-utxo-limit');
    limitInput.max = String(maxInputs);
    transactionState.utxoSelectionLimit = normalizeUtxoSelectionLimit(transactionState.utxoSelectionLimit || DEFAULT_UTXO_SELECTION_LIMIT);
    limitInput.value = String(transactionState.utxoSelectionLimit);
    transactionState.utxoSort = normalizeUtxoSortMode(transactionState.utxoSort);
    byId('send-utxo-sort').value = transactionState.utxoSort;
    byId('input-dest').value = '';
    byId('input-amount').value = '';
    // Shared screen: always restore the amount field by default. Thread-covenant
    // deposits hide it again (handleCovFund), since they full-spend the chosen UTXOs.
    const _amtWrap = byId('send-amount-wrap');
    if (_amtWrap) _amtWrap.style.display = '';

    // Show current balance on send screen
    const balText = byId('balance-kas').textContent;
    const ref = byId('send-balance-ref');
    if (balText && balText !== '—') {
        ref.textContent = 'Available: ' + balText;
    } else {
        ref.textContent = '';
    }

    // Update placeholder for current network
    const prefix = addressPrefix(networkState.network);
    byId('input-dest').placeholder = prefix + '...';

    showScreen('send');
    try {
        // Brief delay after broadcast to let the node process the TX
        if (transactionState._lastBroadcastTime && Date.now() - transactionState._lastBroadcastTime < 5000) {
            const ref3 = byId('send-balance-ref');
            if (ref3) ref3.textContent = 'Refreshing balance...';
            await new Promise(r => setTimeout(r, 2000));
        }
        const wsUrl = await resolveNodeUrl();
        const resultJson = await get_fee_estimate(wsUrl);
        networkState.lastFeeEstimate = JSON.parse(resultJson);
        const isCov = (navigationState._broadcastReturnScreen === 'covenant');
        const suggestedFee = exactUnsigned(networkState.lastFeeEstimate.suggested_fee, 'suggested fee');
        const initialFee = isCov && suggestedFee < 400000n ? 400000n : suggestedFee;
        byId('input-fee').value = initialFee.toString();
        updateFeeCardAmounts();
        // Reset to Normal active
        document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
        byId('btn-fee-normal').classList.add('fee-card-active');
        const coinControl = await fetchCoinControlUtxos({ wsUrl });
        networkState.cachedUtxos = normalizeUtxos(coinControl.utxos);
        // Deterministic amount-desc / outpoint-asc order shared with Rust selection.
        sortUtxosLargestFirst(networkState.cachedUtxos);
        if (transactionState.selectedUtxoIds?.length) {
            const liveIds = new Set(networkState.cachedUtxos.map(utxoId));
            transactionState.selectedUtxoIds = transactionState.selectedUtxoIds.filter(id => liveIds.has(id));
            if (!transactionState.selectedUtxoIds.length) {
                transactionState.selectedUtxoIds = null;
                toast('Previously selected UTXOs are no longer available', 'info', 2600);
            }
        }
        // Update available balance from fresh UTXOs
        const freshTotal = networkState.cachedUtxos.reduce((s, u) => s + u.amount, 0n);
        const ref2 = byId('send-balance-ref');
        if (ref2) ref2.textContent = 'Available: ' + sompiToKasString(freshTotal) + ' KAS';
        if (revealCoinControl && transactionState.selectedUtxoIds?.length) toggleSendUtxos();
    } catch (e) {
        console.log('[KasSee] Fee/UTXO fetch:', e);
    }
}

export async function openSendScreen() {
    return openSendScreenWithOptions();
}

export async function openSendScreenWithSelectedUtxos(selectedUtxoIds) {
    if (!selectedUtxoIds?.length) {
        toast('Select at least one UTXO first', 'info', 1800);
        return;
    }
    return openSendScreenWithOptions({ selectedUtxoIds, revealCoinControl: true });
}
function _isThreadDepositScreen() {
    return navigationState._broadcastReturnScreen === 'covenant' && covenantState.lastCovenantResult &&
        (covenantState.lastCovenantResult.type === 'global-allowance' || covenantState.lastCovenantResult.type === 'global-spending-limit');
}
// amount field is hidden. Mirror the selected-UTXO total into the hidden amount
// so the >0 validation passes and fee math stays consistent. Idempotent.
export function syncThreadDepositAmount() {
    if (!_isThreadDepositScreen()) return;
    // Genesis funding shows the amount field and is user-driven (honor the typed
    // amount, emit change). Only a TOP-UP hides the amount field and full-spends the
    // selected UTXO(s) into the thread, so the selection-mirror applies there alone.
    const _aw = byId('send-amount-wrap');
    if (_aw && _aw.style.display !== 'none') return; // visible => genesis, leave the typed amount
    const selected = selectedUtxos(networkState.cachedUtxos, transactionState.selectedUtxoIds);
    const sum = selected.reduce((total, utxo) => total + utxo.amount, 0n);
    const amtEl = byId('input-amount');
    if (amtEl) amtEl.value = sum > 0n ? sompiToKasString(sum) : '';
    updateFeeCardAmounts();
}
export function toggleSendUtxos() {
    const panel = byId('send-utxo-advanced');
    if (!panel.classList.contains('hidden')) {
        panel.classList.add('hidden');
        byId('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
        return;
    }
    if (!networkState.cachedUtxos?.length) { toast('No UTXOs available', 'error'); return; }
    panel.classList.remove('hidden');
    byId('btn-toggle-utxos').textContent = 'Select UTXOs manually ▾';

    const refresh = () => {
        const limitInput = byId('send-utxo-limit');
        const maximum = signerMaxInputs();
        const parsedLimit = Number.parseInt(limitInput.value, 10);
        const validLimit = Number.isSafeInteger(parsedLimit) && parsedLimit >= 1 && parsedLimit <= maximum;
        transactionState.utxoSelectionLimit = validLimit ? parsedLimit : DEFAULT_UTXO_SELECTION_LIMIT;
        if (!validLimit) {
            limitInput.value = String(DEFAULT_UTXO_SELECTION_LIMIT);
            toast(`UTXO limit must be between 1 and ${maximum} for this KasSigner`, 'error', 2600);
        }
        transactionState.utxoSort = normalizeUtxoSortMode(byId('send-utxo-sort').value);
        const selected = selectedUtxos(networkState.cachedUtxos, transactionState.selectedUtxoIds);
        if (selected.length > transactionState.utxoSelectionLimit) {
            transactionState.selectedUtxoIds = selected.slice(0, transactionState.utxoSelectionLimit).map(utxo => `${utxo.tx_id}:${utxo.index}`);
        }
        const current = selectedUtxos(networkState.cachedUtxos, transactionState.selectedUtxoIds);
        const total = current.reduce((sum, utxo) => sum + utxo.amount, 0n);
        byId('send-utxo-summary').textContent = current.length > 0
            ? `${current.length} manually selected / ${networkState.cachedUtxos.length} available · ${sompiToKasString(total)} KAS`
            : `0 manually selected / ${networkState.cachedUtxos.length} available · automatic selection will be used`;
        renderUtxoSelector(
            byId('send-utxo-list'), networkState.cachedUtxos, transactionState.selectedUtxoIds,
            { limit: transactionState.utxoSelectionLimit, sort: transactionState.utxoSort },
            ids => { transactionState.selectedUtxoIds = ids; syncThreadDepositAmount(); refresh(); },
        );
    };
    byId('send-utxo-limit').onchange = refresh;
    byId('send-utxo-sort').onchange = refresh;
    refresh();
}
export function setFeeLevel(level) {
    if (!networkState.lastFeeEstimate) return;
    const isCovDeposit = (navigationState._broadcastReturnScreen === 'covenant');
    const mass = isCovDeposit ? 3500n : 2300n;
    let feerate, minFee;
    if (level === 'low') {
        feerate = networkState.lastFeeEstimate.low_sompi_per_gram;
        minFee = isCovDeposit ? 400000n : 2500n;
    } else if (level === 'priority') {
        feerate = networkState.lastFeeEstimate.priority_sompi_per_gram;
        minFee = isCovDeposit ? 500000n : 300000n;
    } else {
        feerate = networkState.lastFeeEstimate.normal_sompi_per_gram;
        minFee = isCovDeposit ? 400000n : 5000n;
    }
    byId('input-fee').value = roundFeeFromRate(feerate, mass, minFee).toString();

    // Update active card visual
    document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
    byId('btn-fee-' + level).classList.add('fee-card-active');
}
export function updateFeeCardAmounts() {
    if (!networkState.lastFeeEstimate) return;
    const isCovDeposit = (navigationState._broadcastReturnScreen === 'covenant');
    const mass = isCovDeposit ? 3500n : 2300n;
    const low = roundFeeFromRate(networkState.lastFeeEstimate.low_sompi_per_gram, mass, isCovDeposit ? 400000n : 2500n);
    const normal = roundFeeFromRate(networkState.lastFeeEstimate.normal_sompi_per_gram, mass, isCovDeposit ? 400000n : 5000n);
    const priority = roundFeeFromRate(networkState.lastFeeEstimate.priority_sompi_per_gram, mass, isCovDeposit ? 500000n : 300000n);
    byId('fee-low-amount').textContent = low.toLocaleString();
    byId('fee-normal-amount').textContent = normal.toLocaleString();
    byId('fee-priority-amount').textContent = priority.toLocaleString();

    // Show estimated time if available from node
    const lowTime = byId('fee-low-time');
    const normalTime = byId('fee-normal-time');
    const priorityTime = byId('fee-priority-time');
    if (lowTime && networkState.lastFeeEstimate.low_seconds != null) {
        lowTime.textContent = formatSeconds(networkState.lastFeeEstimate.low_seconds);
    }
    if (normalTime && networkState.lastFeeEstimate.normal_seconds != null) {
        normalTime.textContent = formatSeconds(networkState.lastFeeEstimate.normal_seconds);
    }
    if (priorityTime && networkState.lastFeeEstimate.priority_seconds != null) {
        priorityTime.textContent = formatSeconds(networkState.lastFeeEstimate.priority_seconds);
    }
}
export function handleSendMax() {
    if (!walletSession.hasWallet()) return;
    const defaultFeeSompi = (navigationState._broadcastReturnScreen === 'covenant') ? 400000n : 300000n;
    const feeText = byId('input-fee').value.trim();
    let feeSompi = defaultFeeSompi;
    try {
        if (feeText) feeSompi = exactUnsigned(feeText, 'fee');
    } catch (_) {
        // Keep the conservative default if the field is not an exact integer.
    }

    const selected = selectedUtxos(networkState.cachedUtxos, transactionState.selectedUtxoIds);
    if (selected.length > 0) {
        const selectedTotal = selected.reduce((sum, utxo) => sum + exactUnsigned(utxo.amount, 'UTXO amount'), 0n);
        const maximumSompi = selectedSendMaximumSompi(
            selectedTotal,
            selected.length,
            feeSompi,
        );
        byId('input-amount').value = sompiToKasString(maximumSompi);
        return;
    }

    const balText = byId('balance-kas').textContent;
    const match = balText.match(/([\d.]+)/);
    if (!match) { toast('Refresh balance first', 'info'); return; }
    byId('input-amount').value = balanceSendMaximumKas(match[1], feeSompi);
}
