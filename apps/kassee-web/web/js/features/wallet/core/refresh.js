import { navigationState, scannerState, uiState, walletSession } from '../../../app/state/index.js';
import { AUTO_REFRESH_INTERVAL } from '../../../core/config/network.js';
import { refreshBalance } from './balance.js';

export function startAutoRefresh() {
    stopAutoRefresh();
    uiState.autoRefreshTimer = setInterval(() => {
        if (navigationState.currentScreenName === 'dashboard' && walletSession.hasWallet() && !scannerState.refreshing) {
            refreshBalance();
        }
    }, AUTO_REFRESH_INTERVAL);
}

export function stopAutoRefresh() {
    if (uiState.autoRefreshTimer) { clearInterval(uiState.autoRefreshTimer); uiState.autoRefreshTimer = null; }
}
