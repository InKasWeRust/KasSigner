import { byId } from '../../../../core/dom.js';
import { oracleMbAmbientStop, oracleMbCardOpen } from '../../../oracle/model_b/controller.js';
import { covActiveWatcherStart, covActiveWatcherStop, covFetchBalances } from '../../recovery/active.js';
import { renderPrivateSwap } from '../../private_swap/controller.js';
import { shipPanelRefresh } from '../../spending/standard/shipment.js';
import { covWatcherStart, covWatcherStop } from '../../watchers_and_ui/watcher/polling/lifecycle.js';

const PANEL_IDS = {
    menu: 'cov-menu',
    create: 'cov-create-panel',
    result: 'cov-result-panel',
    owner: 'cov-owner-panel',
    borrower: 'cov-borrower-panel',
    beneficiary: 'cov-beneficiary-panel',
    timeout: 'cov-timeout-panel',
    balance: 'cov-balance-panel',
    'payjoin-claim': 'cov-payjoin-claim-panel',
    consolidate: 'cov-consolidate-panel',
    'cr-reveal': 'cov-cr-reveal-panel',
    'cr-verify': 'cov-cr-verify-panel',
    'mw-spend': 'cov-mw-spend-panel',
    'tagged-vault': 'cov-tagged-vault-panel',
    load: 'cov-load-panel',
    ship: 'cov-ship-panel',
    'oracle-mb': 'cov-oracle-mb-panel',
    'oracle-v1-claim': 'cov-oracle-v1-claim-panel',
    'oracle-v1-attest': 'cov-oracle-v1-attest-panel',
    'private-swap': 'cov-private-swap-panel',
};

export function showCovenantPanel(panel) {
    hideTransientStatus();
    hideAllPanels();
    stopPanelServices();
    const panelId = PANEL_IDS[panel];
    if (!panelId) throw new Error(`Unknown covenant panel: ${panel}`);
    byId(panelId).classList.remove('hidden');
    enterPanel(panel);
}

function hideTransientStatus() {
    byId('cov-piggy-status-banner')?.classList.add('hidden');
}

function hideAllPanels() {
    for (const panelId of Object.values(PANEL_IDS)) {
        byId(panelId)?.classList.add('hidden');
    }
}

function stopPanelServices() {
    covActiveWatcherStop();
    oracleMbAmbientStop();
}

function enterPanel(panel) {
    switch (panel) {
        case 'menu':
            covFetchBalances();
            covWatcherStop();
            covActiveWatcherStart();
            break;
        case 'result':
            byId('cov-result-txid-wrap')?.style.setProperty('display', 'none');
            covWatcherStart();
            break;
        case 'ship':
            shipPanelRefresh();
            break;
        case 'oracle-mb':
            oracleMbCardOpen();
            break;
        case 'private-swap':
            renderPrivateSwap();
            break;
        default:
            break;
    }
}
