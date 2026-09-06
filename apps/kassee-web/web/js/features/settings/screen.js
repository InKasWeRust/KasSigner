import { navigationState, networkState, stealthState, walletSession, walletState } from '../../app/state/index.js';
import { navigateBack, showScreen } from '../../app/navigation.js';
import { renderBrowserConnectivity } from '../../core/ui/connectivity_status.js';
import { setScreenReturn, takeScreenReturn, visibleScreenName } from '../../core/ui/screen_dom.js';
import { toast } from '../../core/ui/toast.js';
import { byId } from '../../core/dom.js';
import { hardenedWalletCleanup } from '../wallet/state_reset.js';
import { fetchAddressHistory, refreshBalance } from '../wallet/core.js';


export function showSettings(returnScreen) {
    const fallback = walletSession.hasWallet() ? 'dashboard' : 'welcome';
    const source = returnScreen || visibleScreenName(fallback);
    if (source !== 'settings') {
        navigationState.settingsReturnScreen = source;
        setScreenReturn('settings', source);
    }
    byId('input-node-url').value = networkState.customNodeUrl || '';
    byId('select-network').value = networkState.network;
    byId('chk-addr-history').checked = walletState.addressHistoryEnabled;
    byId('input-rest-url').value = networkState.customRestUrl || '';
    byId('chk-stealth-indexer').checked = stealthState.stealthIndexerEnabled;
    showScreen('settings');
}

export function clearCustomNode() {
    networkState.customNodeUrl = null;
    console.log('[KasSee] Using public nodes');
}


export function saveSettings() {
    const nodeUrl = byId('input-node-url').value.trim();
    networkState.customNodeUrl = nodeUrl || null;
    const wasHistoryEnabled = walletState.addressHistoryEnabled;
    walletState.addressHistoryEnabled = byId('chk-addr-history').checked;
    networkState.customRestUrl = byId('input-rest-url').value.trim() || null;
    if (walletState.addressHistoryEnabled && !networkState.customRestUrl) {
        walletState.addressHistoryEnabled = false;
        byId('chk-addr-history').checked = false;
        toast('Address history requires a REST URL', 'info', 2500);
    } else if (walletState.addressHistoryEnabled && !wasHistoryEnabled) {
        fetchAddressHistory();
    }
    stealthState.stealthIndexerEnabled = byId('chk-stealth-indexer').checked;
    localStorage.setItem('kassee-stealth-indexer', stealthState.stealthIndexerEnabled ? '1' : '0');

    const newNetwork = byId('select-network').value;
    if (newNetwork !== networkState.network) {
        networkState.network = newNetwork;
        hardenedWalletCleanup();
        renderBrowserConnectivity();
        toast('Network changed — import your kpub again', 'info', 3000);
        showScreen('welcome');
        return;
    }
    exitSettings();
}

export function exitSettings() {
    const fallback = walletSession.hasWallet() ? 'dashboard' : 'welcome';
    const remembered = takeScreenReturn(
        'settings',
        navigationState.settingsReturnScreen || fallback,
    );
    navigationState.settingsReturnScreen = undefined;
    const safeTarget = ['send', 'qr-display', 'pskt-review', 'settings'].includes(remembered)
        ? fallback
        : remembered;
    navigateBack(safeTarget);
    if (safeTarget === 'dashboard' && walletSession.hasWallet()) refreshBalance();
}
