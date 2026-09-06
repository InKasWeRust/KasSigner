import { navigationState, walletSession } from '../../state/index.js';
import { showScreen } from '../../navigation.js';
import { covReturnAfterBroadcast } from '../../../features/covenants/scanning_and_swap.js';

export function takeTransactionReturnScreen() {
    const screen = navigationState._broadcastReturnScreen;
    navigationState._broadcastReturnScreen = null;
    return screen;
}

export function showTransactionReturnScreen(screen, { restoreCovenant = true } = {}) {
    showScreen(screen);
    if (restoreCovenant && screen === 'covenant') covReturnAfterBroadcast();
    return screen;
}

export function returnFromTransaction({
    defaultScreen = 'dashboard',
    restoreCovenant = true,
} = {}) {
    return showTransactionReturnScreen(
        takeTransactionReturnScreen() || defaultScreen,
        { restoreCovenant },
    );
}

export function walletAwareDefaultScreen() {
    return walletSession.hasWallet() ? 'dashboard' : 'welcome';
}
