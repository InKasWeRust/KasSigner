import { walletSession } from '../../app/state/index.js';
import { byId } from '../../core/dom.js';
import { hardenedWalletCleanup, requestWalletRuntimeReset } from './state_reset.js';

export function oneTimeWalletActive() {
    return walletSession.hasWallet() && walletSession.profile() === null;
}

export function syncWalletUnloadAction() {
    const button = byId('btn-reset-wallet');
    if (!button) return;
    const oneTime = oneTimeWalletActive();
    button.textContent = oneTime ? 'Unload one-time kpub' : 'Reset Wallet';
    button.title = oneTime
        ? 'Unload this temporary watch-only wallet without deleting saved kpubs'
        : 'Unload the current wallet without deleting saved kpubs';
}

export function resetWallet() {
    if (!walletSession.hasWallet()) return false;
    const oneTime = oneTimeWalletActive();
    const prompt = oneTime
        ? 'Unload this one-time kpub? The temporary watch-only wallet and any in-progress transaction/session state will be discarded.'
        : 'Unload the current wallet? Saved kpubs will remain available under the settings cog.';
    if (!confirm(prompt)) return false;
    hardenedWalletCleanup();
    requestWalletRuntimeReset();
    return true;
}
