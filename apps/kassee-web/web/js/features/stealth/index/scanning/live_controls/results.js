import { setSafeMarkup } from '../../../../../core/security/safe_html.js';
import { networkState, stealthState, walletSession } from '../../../../../app/state/index.js';
import { showScreen } from '../../../../../app/navigation.js';
import { bytesToHex } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';
import { detectWalletNetwork } from '../../../../../core/network.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { encode_p2pk_address, fetch_utxos_for_address_js } from '../../../../../wasm/api.js';
import { stopScanner } from '../../camera.js';
import { stealthFeePrepare, stealthFeeSetLevel, stealthShowPanel } from '../../send.js';
import { handleStealthSpend } from '../../spend.js';
import { clearStealthQrTimer } from './lifecycle.js';
import { sompiToKasFixed } from '../../../../../core/amounts.js';

function collectDeviceResults(raw) {
    const count = raw[4];
    stealthState._stealthResults ||= [];
    for (let index = 0; index < count; index++) {
        const offset = 5 + index * 64;
        const pubkey = bytesToHex(raw.slice(offset, offset + 32));
        const tweak = bytesToHex(raw.slice(offset + 32, offset + 64));
        if (/^0+$/.test(pubkey)) continue;
        if (stealthState._stealthResults.some(result => result.pubkey === pubkey)) continue;
        stealthState._stealthResults.push({ pubkey, tweak });
    }
    return count;
}

async function findFundedResults() {
    const network = detectWalletNetwork(walletSession.json(), networkState.network);
    const websocketUrl = await resolveNodeUrl();
    const funded = [];
    for (const result of stealthState._stealthResults) {
        let address = '';
        try { address = encode_p2pk_address(result.pubkey, network); } catch (_) {}
        if (!address) continue;
        try {
            const utxos = JSON.parse(await fetch_utxos_for_address_js(address, websocketUrl));
            const total = utxos.reduce((sum, utxo) => sum + BigInt(utxo.amount), 0n);
            if (total > 0n) funded.push({ ...result, address, total });
        } catch (_) {}
    }
    return funded;
}

function renderFundedResults(funded) {
    const list = byId('stealth-found-list');
    if (funded.length === 0) {
        list.innerHTML = 'No funded payments for this wallet.';
        return;
    }
    let html = '<label class="input-label">Fee</label><div class="fee-cards">'
        + '<button class="fee-card" id="btn-spf-low"><div class="fee-card-label">Low</div><div class="fee-card-amount" id="spf-low-amount">2,500</div><div class="fee-card-time" id="spf-low-time"></div></button>'
        + '<button class="fee-card fee-card-active" id="btn-spf-normal"><div class="fee-card-label">Normal</div><div class="fee-card-amount" id="spf-normal-amount">5,000</div><div class="fee-card-time" id="spf-normal-time"></div></button>'
        + '<button class="fee-card" id="btn-spf-priority"><div class="fee-card-label">Priority</div><div class="fee-card-amount" id="spf-priority-amount">10,000</div><div class="fee-card-time" id="spf-priority-time"></div></button>'
        + '</div><input type="number" id="input-spf-fee" class="input-text " value="5000" step="1" min="1">';
    funded.forEach((result, index) => {
        html += `<div class="stealth-payment-card"><div class="stealth-payment-title"><span class="u-text-accent-teal">Payment ${index + 1}</span> · <span class="u-text-accent-teal">${sompiToKasFixed(result.total, 2)} KAS</span></div><div class="stealth-payment-address">${result.address}</div><button class="btn btn-primary stealth-spend-btn stealth-spend-btn-wide" data-pubkey="${result.pubkey}" data-tweak="${result.tweak}">Spend This Payment</button></div>`;
    });
    setSafeMarkup(list, html);
    list.querySelectorAll('.stealth-spend-btn').forEach(button => {
        button.addEventListener('click', () => handleStealthSpend(button.dataset.pubkey, button.dataset.tweak));
    });
    ['low', 'normal', 'priority'].forEach(level => {
        const button = byId(`btn-spf-${level}`);
        if (button) button.onclick = () => stealthFeeSetLevel('spf', 'spend', level);
    });
    stealthFeePrepare('spf', 'spend');
}

export async function processStealthResult(raw) {
    const count = collectDeviceResults(raw);
    stopScanner();
    clearStealthQrTimer();
    showScreen('stealth');
    stealthShowPanel('scan');
    byId('stealth-found-list').innerHTML = 'Checking balances...';
    byId('stealth-scan-results').classList.remove('hidden');
    try {
        renderFundedResults(await findFundedResults());
    } catch (_) {
        byId('stealth-found-list').innerHTML = 'Node unavailable, cannot check balances.';
    }

    stealthState._stealthBatchStart = (stealthState._stealthBatchStart || 0) + count;
    const remaining = stealthState.stealthAnnouncementsR.length - stealthState._stealthBatchStart;
    if (remaining > 0) {
        setSafeMarkup(byId('stealth-scan-status'), `<strong>${remaining} more R to check.</strong> Tap "Show Scan QR" for the next batch.`);
    }
    toast(`Scanned ${count} result(s)${remaining > 0 ? `, ${remaining} R left` : ''}`, 'ok', 2000);
}
