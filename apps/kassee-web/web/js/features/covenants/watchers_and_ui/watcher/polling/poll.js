import { covenantState, covenantWatcherState } from '../../../../../app/state/index.js';
import { sompiToKasFixed, sompiToKasString } from '../../../../../core/amounts.js';
import { exactUnsigned } from '../../../../../core/exact.js';
import { fetchCurrentDaa } from '../../../../../core/node/daa.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { covSaveActive } from '../../../recovery/active.js';
import { pickThread } from '../../../spending/standard/thread_and_claims.js';
import { covWatcherStop } from './lifecycle.js';
import { isWatchedCovenantType } from '../types.js';
import { fetch_utxos_for_address_js } from '../../../../../wasm/api.js';
import { byId } from '../../../../../core/dom.js';
import { pollCovenantType } from './covenant_pollers.js';

function captureThreadIdentity(t, utxos) {
    if ((t === 'global-spending-limit' || t === 'global-allowance')
        && !(covenantState.lastCovenantResult.covenant_id_hex && !/^0+$/.test(covenantState.lastCovenantResult.covenant_id_hex))) {
        const tagged = utxos.filter(u => u && u.covenant_id && !/^0+$/.test(String(u.covenant_id)));
        if (tagged.length === 1) {
            const covenantId = String(tagged[0].covenant_id);
            covenantState.lastCovenantResult.covenant_id_hex = covenantId;
            const entry = covenantState.activeCovenants.find(c => c.address === covenantState.lastCovenantResult.address);
            if (entry && entry.covenant_id_hex !== covenantId) {
                entry.covenant_id_hex = covenantId;
                covSaveActive();
            }
        }
    }
}

function updateWatcherBalance(type, utxos, total) {
    const balance = byId('cov-result-balance');
    if (!balance) return;
    balance.textContent = sompiToKasString(total) + ' KAS (' + utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ')';
    if (type === 'global-spending-limit' || type === 'global-allowance') {
        const picked = pickThread(utxos, covenantState.lastCovenantResult?.covenant_id_hex);
        const governed = picked.thread ? exactUnsigned(picked.thread.amount, 'thread amount') : 0n;
        balance.textContent = sompiToKasString(governed) + ' KAS';
        if (picked.externalSompi > 0n) {
            const word = type === 'global-spending-limit' ? 'stuck' : 'owner-reclaimable';
            balance.textContent += ' (+' + sompiToKasString(picked.externalSompi) + ' KAS external, ' + word + ')';
        }
    }
    balance.style.display = '';
}

export async function covWatcherPoll() {
    if (!covenantState.lastCovenantResult) { covWatcherStop(); return; }
    const type = covenantState.lastCovenantResult.type || '';
    if (!isWatchedCovenantType(type)) { covWatcherStop(); return; }

    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(covenantState.lastCovenantResult.address, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((sum, utxo) => sum + exactUnsigned(utxo.amount, 'UTXO amount'), 0n);
        captureThreadIdentity(type, utxos);
        updateWatcherBalance(type, utxos, total);

        const status = byId('cov-watcher-status');
        if (!status || !covenantWatcherState._covWatcherTimer) return;
        const locktime = exactUnsigned(covenantState.lastCovenantResult.locktime_daa ?? 0n, 'locktime DAA');
        const currentDaa = await fetchCurrentDaa();
        if (currentDaa > 0n) covenantState._lastKnownDaa = currentDaa;

        const state = { t: type, total, kas: sompiToKasFixed(total, 2), st: status, locktime, currentDaa, utxos };
        if (await pollCovenantType(state)) return;

        if (covenantWatcherState._covWatcherLastBalance === null && utxos.length > 0 && utxos[0].tx_id) {
            covenantWatcherState._covWatcherOutpoint = { txid: utxos[0].tx_id, index: utxos[0].index || 0 };
        }
        covenantWatcherState._covWatcherLastBalance = total;
    } catch (_) {
        // Best-effort watcher poll. The next interval retries.
    }
}
