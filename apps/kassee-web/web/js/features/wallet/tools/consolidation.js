import { networkState, transactionState, walletSession, walletState } from '../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { openPsktReview } from '../../transactions/pskt_multisig/review.js';
import { getNextReceiveIndex, walletWithFreshIndices, withNodeRetry } from '../core.js';
import { consolidationFee } from '../../transactions/send/compose/fees.js';
import { create_consolidate_pskb, create_send_pskb_selected, decode_address } from '../../../wasm/api.js';
import { openSendScreenWithSelectedUtxos } from '../../transactions/send/compose/send_form.js';
import { utxoId } from '../../transactions/shared/utxo_selection.js';

import { hexToBytes } from '../../../core/bytes.js';
import { byId } from '../../../core/dom.js';
import { exactUnsigned } from '../../../core/exact.js';
transactionState.consolidateSelection = new Set();
export function updateConsolidateButtons(totalCount) {
    const n = transactionState.consolidateSelection.size;
    const btnAll = byId('btn-consolidate');
    const btnSel = byId('btn-consolidate-selected');
    const btnSend = byId('btn-send-selected-utxos');
    btnSend.style.display = totalCount >= 1 ? 'block' : 'none';
    btnSend.textContent = n >= 1 ? `Send with ${n} Selected` : 'Select UTXOs for Send';
    if (totalCount <= 1) {
        btnAll.style.display = 'none';
        btnSel.style.display = 'none';
    } else if (n >= 2) {
        btnAll.style.display = 'none';
        btnSel.style.display = '';
        btnSel.textContent = `Consolidate ${n} Selected`;
    } else {
        btnAll.style.display = '';
        btnSel.style.display = 'none';
    }
}

export async function handleSendSelectedUtxos() {
    if (!walletSession.hasWallet()) return;
    if (transactionState.consolidateSelection.size < 1) {
        toast('Tap one or more UTXOs below to choose the exact inputs for this send', 'info', 2800);
        return;
    }
    const ids = [...transactionState.consolidateSelection]
        .sort((a, b) => a - b)
        .map(index => networkState.cachedUtxos?.[index])
        .filter(Boolean)
        .map(utxoId);
    if (!ids.length) {
        toast('Selected UTXOs are no longer available', 'error');
        return;
    }
    await openSendScreenWithSelectedUtxos(ids);
}

export async function handleConsolidate() {
    if (!walletSession.hasWallet()) return;
    // Builder takes up to 5 largest UTXOs; size the fee to that actual count.
    const fee = consolidationFee(Math.min(5, (networkState.cachedUtxos && networkState.cachedUtxos.length) || 5));

    showLoading('Building consolidation TX...');
    try {
        const pskbHex = await withNodeRetry(wsUrl =>
            create_consolidate_pskb(walletWithFreshIndices(), fee, wsUrl)
        );
        hideLoading();
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Consolidation failed: ' + e, 'error', 5000);
    }
}

export async function handleConsolidateSelected() {
    if (!walletSession.hasWallet() || transactionState.consolidateSelection.size < 2) return;
    const wallet = walletSession.current();
    const fee = consolidationFee(transactionState.consolidateSelection.size);
    const indices = [...transactionState.consolidateSelection].sort((a, b) => a - b);
    const indicesCsv = indices.join(',');

    // Calculate total of selected UTXOs
    let totalSelected = 0n;
    for (const idx of indices) {
        if (networkState.cachedUtxos && idx < networkState.cachedUtxos.length) {
            totalSelected += exactUnsigned(networkState.cachedUtxos[idx].amount, 'UTXO amount');
        }
    }
    const sendSompi = totalSelected - fee;
    if (sendSompi <= 0n) {
        toast('Selected UTXOs too small to cover fee', 'error');
        return;
    }

    showLoading(`Consolidating ${indices.length} UTXOs...`);
    try {
        const destAddr = wallet.receive_addresses[getNextReceiveIndex()];
        const pskbHex = await withNodeRetry(wsUrl =>
            create_send_pskb_selected(walletWithFreshIndices(), destAddr, sendSompi, fee, indicesCsv, wsUrl)
        );
        hideLoading();
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Consolidation failed: ' + e, 'error', 5000);
    }
}

export function trackUtxoChangesAndUsed(currentUtxos) {
    const now = Date.now();

    if (!networkState.utxoSnapshot) {
        // First snapshot — record all existing UTXOs as initial balance
        for (const u of currentUtxos) {
            walletState.historyEntries.push({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
        if (walletState.historyEntries.length > 100) walletState.historyEntries.length = 100;
        networkState.utxoSnapshot = currentUtxos;
        return;
    }

    const prevKeys = new Set(networkState.utxoSnapshot.map(u => u.tx_id + ':' + u.index));
    const currKeys = new Set(currentUtxos.map(u => u.tx_id + ':' + u.index));

    // New UTXOs = incoming
    for (const u of currentUtxos) {
        const key = u.tx_id + ':' + u.index;
        if (!prevKeys.has(key)) {
            walletState.historyEntries.unshift({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
    }

    // Gone UTXOs = spent (outgoing) — also mark the address as "used"
    if (walletSession.hasWallet()) {
        const wallet = walletSession.current();
        for (const u of networkState.utxoSnapshot) {
            const key = u.tx_id + ':' + u.index;
            if (!currKeys.has(key)) {
                walletState.historyEntries.unshift({
                    type: 'out',
                    amount: u.amount,
                    tx_id: u.tx_id,
                    index: u.index,
                    time: now,
                });
                // Match spent UTXO script to an address index
                const spkJson = JSON.stringify(u.script_public_key);
                for (let i = 0; i < wallet.receive_addresses.length; i++) {
                    try {
                        const decoded = JSON.parse(decode_address(wallet.receive_addresses[i]));
                        // P2PK script: [0x20, ...32 bytes..., 0xAC]
                        const spk = [0x20, ...Array.from(hexToBytes(decoded.payload)), 0xAC];
                        if (JSON.stringify(spk) === spkJson) { walletState.usedReceiveIndices.add(i); break; }
                    } catch (_) {}
                }
                for (let i = 0; i < wallet.change_addresses.length; i++) {
                    try {
                        const decoded = JSON.parse(decode_address(wallet.change_addresses[i]));
                        const spk = [0x20, ...Array.from(hexToBytes(decoded.payload)), 0xAC];
                        if (JSON.stringify(spk) === spkJson) { walletState.usedChangeIndices.add(i); break; }
                    } catch (_) {}
                }
            }
        }
    } else {
        for (const u of networkState.utxoSnapshot) {
            const key = u.tx_id + ':' + u.index;
            if (!currKeys.has(key)) {
                walletState.historyEntries.unshift({
                    type: 'out',
                    amount: u.amount,
                    tx_id: u.tx_id,
                    index: u.index,
                    time: now,
                });
            }
        }
    }

    if (walletState.historyEntries.length > 100) walletState.historyEntries.length = 100;
    networkState.utxoSnapshot = currentUtxos;
}
