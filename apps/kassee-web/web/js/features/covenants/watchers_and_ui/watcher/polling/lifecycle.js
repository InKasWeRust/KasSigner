import { covenantState, covenantWatcherState } from '../../../../../app/state/index.js';
import { covWatcherPoll } from './poll.js';
import { covSubscriptionStart, covSubscriptionStop } from '../subscription_and_time.js';
import { isWatchedCovenantType } from '../types.js';
// KasSee Web — features/covenants/watchers_and_ui/watcher/polling/lifecycle
import { byId } from '../../../../../core/dom.js';


// ─── Generic Covenant Watcher (DMS, Allowance, Spending Limit, etc.) ───

export function covWatcherStart() {
    if (covenantWatcherState._covWatcherTimer) return;
    if (!covenantState.lastCovenantResult) return;
    const t = covenantState.lastCovenantResult.type || '';
    if (!isWatchedCovenantType(t)) return;

    covenantWatcherState._covWatcherSpendPath = null;

    console.log('[KasSee] Covenant watcher started for ' + t + ': ' + covenantState.lastCovenantResult.address);
    const st = byId('cov-watcher-status');
    if (st) { st.textContent = '\uD83D\uDC41 Watching...'; st.style.display = ''; }
    covenantWatcherState._covWatcherTimer = setInterval(() => covWatcherPoll(), 3000);
    covWatcherPoll();
    covSubscriptionStart();
}
export function covWatcherStop() {
    if (covenantWatcherState._covWatcherTimer) {
        clearInterval(covenantWatcherState._covWatcherTimer);
        covenantWatcherState._covWatcherTimer = null;
        console.log('[KasSee] Covenant watcher stopped');
    }
    covSubscriptionStop();
    covenantWatcherState._covWatcherLastBalance = null;
    const st = byId('cov-watcher-status');
    if (st) st.style.display = 'none';
}
