import { covenantWatcherState, navigationState } from '../../../../app/state/index.js';
import { byId } from '../../../../core/dom.js';
import { sompiToKasString } from '../../../../core/amounts.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { fetch_utxos_for_address_js } from '../../../../wasm/api.js';
import { activeCovenants } from './repository.js';

export async function fetchActiveBalances() {
    const wsUrl = await resolveNodeWithRetry();
    if (!wsUrl) return;
    const covenants = activeCovenants();
    for (let index = 0; index < covenants.length; index++) {
        const covenant = covenants[index];
        await updateCovenantBalance(covenant, wsUrl);
        updateBalanceElement(covenant, index);
    }
}

async function resolveNodeWithRetry() {
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            return await resolveNodeUrl();
        } catch (_) {
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }
    return null;
}

async function updateCovenantBalance(covenant, wsUrl) {
    try {
        const utxos = JSON.parse(await fetch_utxos_for_address_js(covenant.address, wsUrl));
        const total = utxos.reduce((sum, utxo) => sum + BigInt(utxo.amount), 0n);
        covenant._balText = `${sompiToKasString(total)} KAS`;
        covenant._empty = utxos.length === 0;
    } catch (_) {
        covenant._balText = '?';
        covenant._empty = false;
    }
}

function updateBalanceElement(covenant, index) {
    const balance = document.querySelector(`[data-cov-bal-idx="${index}"]`);
    if (!balance) return;
    balance.textContent = covenant._balText;
    const row = balance.closest('.cov-active-item');
    if (row) row.style.opacity = covenant._empty ? '0.45' : '';
}

export function startActiveWatcher() {
    if (covenantWatcherState._covActiveWatcherTimer || !activeCovenants().length) return;
    covenantWatcherState._covActiveWatcherTimer = setInterval(() => {
        const menu = byId('cov-menu');
        const onMenu = navigationState.currentScreenName === 'covenant'
            && menu && !menu.classList.contains('hidden');
        if (!onMenu || !activeCovenants().length) {
            stopActiveWatcher();
            return;
        }
        fetchActiveBalances();
    }, 5000);
}

export function stopActiveWatcher() {
    if (!covenantWatcherState._covActiveWatcherTimer) return;
    clearInterval(covenantWatcherState._covActiveWatcherTimer);
    covenantWatcherState._covActiveWatcherTimer = null;
}
