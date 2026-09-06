import { covenantState, covenantWatcherState, oracleState } from '../../../app/state/index.js';
import { toast } from '../../../core/ui/toast.js';
import { covShowPanel } from '../generation/ui_and_keys.js';
import { covRenderMetaLine, ensureAllowanceParams } from '../watchers_and_ui/ui/metadata.js';
import { covUpdateResultButtons } from '../watchers_and_ui/ui/result_buttons.js';
import { covWatcherStart, covWatcherStop } from '../watchers_and_ui/watcher/polling/lifecycle.js';
import { isWatchedCovenantType } from '../watchers_and_ui/watcher/types.js';

import { byId } from '../../../core/dom.js';

export function covReturnAfterBroadcast() {
    if (oracleState._oracleMbReturn) { oracleState._oracleMbReturn = false; covShowPanel('oracle-mb'); return; }   // oracle roll: re-open a LIVE card; covShowPanel -> oracleMbCardOpen restarts the 1s age tick, the 12s poll, and the block watcher
    if (covenantState.lastCovenantResult) {
        const broadcastTxid = byId('broadcast-result-txid')?.textContent?.trim() || '';
        // Generic covenant watcher: store outpoint for BlockAdded spend detection
        if (broadcastTxid && broadcastTxid.length === 64 && !covenantWatcherState._covWatcherOutpoint && isWatchedCovenantType(covenantState.lastCovenantResult.type)) {
            covenantWatcherState._covWatcherOutpoint = { txid: broadcastTxid, index: 0 };
            console.log('[KasSee] Stored covenant outpoint from broadcast:', broadcastTxid);
        }
        covShowPanel('result');
        covUpdateResultButtons(covenantState.lastCovenantResult.type || '');
        // Repopulate the result panel fields. Otherwise this leaves them
        // stale/empty (briefly shows "0 KAS, not funded" if the user
        // landed here right after broadcast). Mirrors what the
        // active-list click handler does when loading a covenant.
        const c = covenantState.lastCovenantResult;
        ensureAllowanceParams(c);
        if (byId('cov-result-addr')) byId('cov-result-addr').textContent = c.address || '';
        if (byId('cov-result-script')) byId('cov-result-script').textContent = c.redeem_script_hex || '';
        if (byId('cov-result-txid') && broadcastTxid && broadcastTxid.length === 64) {
            byId('cov-result-txid').textContent = broadcastTxid;
            byId('cov-result-txid').onclick = () => { navigator.clipboard.writeText(broadcastTxid); toast('TX ID copied', 'ok'); };
            if (byId('cov-result-txid-wrap')) byId('cov-result-txid-wrap').style.display = '';
        }
        if (byId('cov-result-extra')) {
            covRenderMetaLine(c);
        }
        if (byId('cov-result-balance')) {
            byId('cov-result-balance').textContent = 'Loading...';
            byId('cov-result-balance').style.display = '';
        }
        setTimeout(() => { if (byId('btn-cov-res-balance')) byId('btn-cov-res-balance').click(); }, 500);
        // Restart watcher to pick up new UTXO state after broadcast
        covWatcherStop();
        covenantWatcherState._covWatcherOutpoint = null;
        covWatcherStart();
    } else {
        covShowPanel('menu');
    }
}
