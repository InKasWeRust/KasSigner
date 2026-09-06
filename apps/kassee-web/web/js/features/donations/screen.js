import { navigationState, walletSession } from '../../app/state/index.js';
import { showScreen } from '../../app/navigation.js';
import { DONATE_ADDRESS } from '../../core/config/donations.js';
import { byId } from '../../core/dom.js';
import { toast } from '../../core/ui/toast.js';

let returnScreen = null;

function visibleScreenName() {
    const active = document.querySelector('.screen.active');
    return active?.id?.replace(/^screen-/, '') || navigationState.currentScreenName || defaultReturnScreen();
}

function donationIsVisible() {
    return byId('screen-donate')?.classList.contains('active') === true;
}

function defaultReturnScreen() {
    return walletSession.hasWallet() ? 'dashboard' : 'welcome';
}

export function handleLogoTap() {
    toggleDonateScreen();
}

export function toggleDonateScreen() {
    if (donationIsVisible()) {
        closeDonateScreen();
        return;
    }
    showDonateScreen();
}

export function showDonateScreen() {
    if (donationIsVisible()) return;
    returnScreen = visibleScreenName();
    byId('donate-address').textContent = DONATE_ADDRESS;
    showScreen('donate');
}

export function closeDonateScreen() {
    const target = returnScreen && returnScreen !== 'donate'
        ? returnScreen
        : defaultReturnScreen();
    returnScreen = null;
    showScreen(target);
}

export async function copyDonationAddress() {
    try {
        await navigator.clipboard.writeText(DONATE_ADDRESS);
        toast('Address copied', 'ok', 1500);
    } catch (error) {
        toast('Could not copy address: ' + error.message, 'error', 3000);
    }
}
