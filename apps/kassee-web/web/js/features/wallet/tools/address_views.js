import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { navigationState, networkState, transactionState, walletSession, walletState } from '../../../app/state/index.js';
import { hideLoading, showLoading, showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { updateConsolidateButtons } from './consolidation.js';
import { explorerAddressUrl } from '../../../core/explorer.js';
import { generate_qr_frames } from '../../../wasm/api.js';
import { fetchCoinControlUtxos } from '../core/coin_control_utxos.js';

import { utf8ToHex } from '../../../core/bytes.js';
import { byId } from '../../../core/dom.js';
import { sompiToKasFixed } from '../../../core/amounts.js';
import { normalizeUtxos, sortUtxosLargestFirst } from '../../../core/utxo.js';
import { signerMaxInputs } from '../../transactions/shared/signer_limits.js';

navigationState.addressesReturnScreen = 'dashboard';
export function showAddresses() {
    if (!walletSession.hasWallet()) return;
    navigationState.addressesReturnScreen = (navigationState.currentScreenName && navigationState.currentScreenName !== 'addresses') ? navigationState.currentScreenName : 'dashboard';
    const wallet = walletSession.current();
    const rcvFunded = new Set(walletState.fundedReceiveIndices);
    const chgFunded = new Set(walletState.fundedChangeIndices);
    let html = '<div class="addr-section-title">Receive (m/44\'/111111\'/0\'/0)</div>';
    wallet.receive_addresses.forEach((addr, i) => {
        const funded = rcvFunded.has(i);
        const used = !funded && walletState.usedReceiveIndices.has(i);
        const dimmed = funded || used;
        html += `<div class="addr-item${dimmed ? ' addr-used' : ''}" data-addr="${i}-r">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            ${funded ? '<span class="addr-badge">funded</span>' : ''}
            ${used ? '<span class="addr-badge used">used</span>' : ''}
            <a class="addr-explore" href="${explorerAddressUrl(networkState.network, addr)}" target="_blank" rel="noopener" title="View in explorer">↗</a>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    html += '<div class="addr-section-title">Change (m/44\'/111111\'/0\'/1)</div>';
    wallet.change_addresses.forEach((addr, i) => {
        const funded = chgFunded.has(i);
        const used = !funded && walletState.usedChangeIndices.has(i);
        const dimmed = funded || used;
        html += `<div class="addr-item${dimmed ? ' addr-used' : ''}" data-addr="${i}-c">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            ${funded ? '<span class="addr-badge">funded</span>' : ''}
            ${used ? '<span class="addr-badge used">used</span>' : ''}
            <a class="addr-explore" href="${explorerAddressUrl(networkState.network, addr)}" target="_blank" rel="noopener" title="View in explorer">↗</a>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    setSafeMarkup(byId('address-list'), html);

    // Prevent explorer link click from triggering the row's onclick
    document.querySelectorAll('.addr-explore').forEach(link => {
        link.onclick = (e) => e.stopPropagation();
    });

    document.querySelectorAll('.addr-item').forEach(item => {
        const da = item.dataset.addr;
        const isChange = da.endsWith('-c');
        const idx = parseInt(da);

        const copyIcon = item.querySelector('.copy-icon');
        if (copyIcon) {
            copyIcon.onclick = (e) => {
                e.stopPropagation();
                const addr = item.querySelector('.addr-val').textContent.trim();
                navigator.clipboard.writeText(addr);
                copyIcon.textContent = '✓';
                setTimeout(() => { copyIcon.textContent = '⧉'; }, 800);
                toast('Address copied', 'ok', 1000);
            };
        }

        item.onclick = () => {
            const addr = item.querySelector('.addr-val').textContent.trim();
            showVerify(addr, idx, isChange);
        };
    });
    showScreen('addresses');
}

function showVerify(addr, index, isChange) {
    const path = isChange
        ? `m/44'/111111'/0'/1/${index}`
        : `m/44'/111111'/0'/0/${index}`;
    byId('verify-path').textContent = path;
    byId('verify-address').textContent = addr;

    try {
        const frames = JSON.parse(generate_qr_frames(utf8ToHex(addr)));
        setSafeMarkup(byId('verify-qr'), frames[0].svg);
    } catch (e) {
        byId('verify-qr').innerHTML = '';
    }

    // Explorer link
    const link = byId('btn-verify-explore');
    if (link) {
        link.href = explorerAddressUrl(networkState.network, addr);
    }
    showScreen('verify');
}

export async function showUtxos() {
    if (!walletSession.hasWallet()) return;
    showLoading('Fetching UTXOs...');
    transactionState.consolidateSelection = new Set();

    try {
        const coinControl = await fetchCoinControlUtxos();
        const utxos = normalizeUtxos(coinControl.utxos);
        hideLoading();
        networkState.cachedUtxos = utxos;

        const totalSompi = utxos.reduce((s, u) => s + u.amount, 0n);
        byId('utxo-summary').textContent = `${utxos.length} current UTXO${utxos.length !== 1 ? 's' : ''} · ${sompiToKasFixed(totalSompi)} KAS · ${coinControl.scannedAddresses} addresses scanned · ${coinControl.source}`;

        if (utxos.length === 0) {
            byId('utxo-list').innerHTML = '<div class="u-align-text-center-text-text-muted-padding-20px">No UTXOs found</div>';
            byId('btn-consolidate').style.display = 'none';
            byId('btn-consolidate-selected').style.display = 'none';
            byId('btn-send-selected-utxos').style.display = 'none';
        } else {
            sortUtxosLargestFirst(utxos);
            let html = '';
            utxos.forEach((u, i) => {
                const kas = sompiToKasFixed(u.amount);
                html += `<div class="utxo-item utxo-selectable" data-utxo-idx="${i}">
                    <div class="utxo-check">${transactionState.consolidateSelection.has(i) ? '☑' : '☐'}</div>
                    <div class="utxo-info">
                        <div class="utxo-amount">${kas} KAS</div>
                        <div class="utxo-detail">${u.tx_id.slice(0, 16)}…:${u.index}</div>
                    </div>
                </div>`;
            });
            setSafeMarkup(byId('utxo-list'), html);

            // Tap to toggle selection
            document.querySelectorAll('.utxo-selectable').forEach(item => {
                item.onclick = () => {
                    const idx = parseInt(item.dataset.utxoIdx);
                    if (transactionState.consolidateSelection.has(idx)) {
                        transactionState.consolidateSelection.delete(idx);
                    } else if (transactionState.consolidateSelection.size < signerMaxInputs()) {
                        transactionState.consolidateSelection.add(idx);
                    } else {
                        toast(`KasSigner supports at most ${signerMaxInputs()} selected inputs`, 'info', 1800);
                        return;
                    }
                    // Update checkbox visual
                    const chk = item.querySelector('.utxo-check');
                    chk.textContent = transactionState.consolidateSelection.has(idx) ? '☑' : '☐';
                    item.style.borderColor = transactionState.consolidateSelection.has(idx) ? 'var(--teal)' : '';
                    updateConsolidateButtons(utxos.length);
                };
            });

            updateConsolidateButtons(utxos.length);
        }

        showScreen('utxos');
    } catch (e) {
        hideLoading();
        toast('Failed to fetch UTXOs: ' + e, 'error', 5000);
    }
}
