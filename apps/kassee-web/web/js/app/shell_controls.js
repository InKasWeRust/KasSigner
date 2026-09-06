import { DONATE_ADDRESS } from '../core/config/donations.js';
import { bindBrowserConnectivity } from '../core/ui/connectivity_status.js';
import { setScreenReturn, takeScreenReturn, visibleScreenName } from '../core/ui/screen_dom.js';
import { showScreen } from './navigation.js';

function byId(id) {
    return document.getElementById(id);
}

function closeGearMenu() {
    byId('gear-menu')?.classList.remove('visible');
    byId('btn-header-settings')?.classList.remove('active');
}

function toggleGearMenu() {
    const menu = byId('gear-menu');
    const button = byId('btn-header-settings');
    if (!menu || !button) return;
    const opening = !menu.classList.contains('visible');
    menu.classList.toggle('visible', opening);
    button.classList.toggle('active', opening);
}

function showManagedKpubs(openImport = false) {
    closeGearMenu();
    setScreenReturn('kpub-manager', visibleScreenName());
    byId('kpub-import-form')?.classList.toggle('hidden', !openImport);
    showScreen('kpub-manager');
}

function donationReturnScreen() {
    return byId('screen-donate')?.dataset.returnScreen || 'welcome';
}

function closeDonation() {
    const target = donationReturnScreen();
    const screen = byId('screen-donate');
    if (screen) delete screen.dataset.returnScreen;
    showScreen(target === 'donate' ? 'welcome' : target, { recordHistory: false });
}

function toggleDonation() {
    if (visibleScreenName() === 'donate') {
        closeDonation();
        return;
    }
    const screen = byId('screen-donate');
    if (screen) screen.dataset.returnScreen = visibleScreenName();
    const address = byId('donate-address');
    if (address) address.textContent = DONATE_ADDRESS;
    showScreen('donate');
}

function shellToast(message) {
    const toast = byId('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 1500);
}

async function copyDonationAddress() {
    try {
        await navigator.clipboard.writeText(DONATE_ADDRESS);
        shellToast('Address copied');
    } catch (_) {
        shellToast('Copy failed');
    }
}

function bindCopyTarget(element) {
    if (!element) return;
    element.onclick = () => { void copyDonationAddress(); };
    element.onkeydown = event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        void copyDonationAddress();
    };
}

export function bindShellControls() {
    bindBrowserConnectivity();
    const settings = byId('btn-header-settings');
    if (settings) settings.onclick = toggleGearMenu;

    document.querySelectorAll('.gear-tab').forEach(tab => {
        tab.onclick = () => {
            const target = tab.dataset.target;
            if (!target) return;
            if (target === 'settings') setScreenReturn('settings', visibleScreenName());
            if (target === 'kpub-manager') {
                showManagedKpubs(false);
                return;
            }
            closeGearMenu();
            showScreen(target);
        };
    });

    const closeSettings = () => showScreen(takeScreenReturn('settings', 'welcome'), { recordHistory: false });
    const closeKpubManager = () => showScreen(takeScreenReturn('kpub-manager', 'welcome'), { recordHistory: false });
    const settingsBack = byId('btn-settings-back');
    const settingsBackTop = byId('btn-settings-back-top');
    if (settingsBack) settingsBack.onclick = closeSettings;
    if (settingsBackTop) settingsBackTop.onclick = closeSettings;
    const kpubManagerBack = byId('btn-kpub-manager-back');
    const kpubManagerBackTop = byId('btn-kpub-manager-back-top');
    if (kpubManagerBack) kpubManagerBack.onclick = closeKpubManager;
    if (kpubManagerBackTop) kpubManagerBackTop.onclick = closeKpubManager;

    const loadKpub = byId('btn-scan-kpub');
    if (loadKpub) loadKpub.onclick = () => showManagedKpubs(true);

    const logo = byId('btn-logo');
    if (logo) {
        logo.onclick = toggleDonation;
        logo.onkeydown = event => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            toggleDonation();
        };
    }
    const close = byId('btn-donate-skip');
    if (close) close.onclick = closeDonation;

    bindCopyTarget(byId('btn-copy-donate'));
    bindCopyTarget(byId('donate-address'));
    bindCopyTarget(byId('donate-qr'));
}
