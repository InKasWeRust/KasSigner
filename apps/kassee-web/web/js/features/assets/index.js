import { networkState, walletSession } from '../../app/state/index.js';
import { hideLoading, showLoading, showScreen } from '../../app/navigation.js';
import { toast } from '../../core/ui/toast.js';
import { fetchWalletAssets } from './client.js';
import { renderWalletAssets } from './render.js';


export async function showTokens() {
    if (!walletSession.hasWallet()) {
        toast('Import kpub first', 'info');
        return;
    }
    showLoading('Fetching tokens & NFTs...');
    try {
        const assets = await fetchWalletAssets(walletSession.current(), networkState.network);
        renderWalletAssets(assets);
        showScreen('tokens');
    } finally {
        hideLoading();
    }
}
