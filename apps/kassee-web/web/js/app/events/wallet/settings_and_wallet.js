import { navigationState, walletSession } from '../../state/index.js';
import { closeGearMenu, navigateBack, showScreen, toggleGearMenu } from '../../navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { visibleScreenName } from '../../../core/ui/screen_dom.js';
import { showTokens } from '../../../features/assets/index.js';
import { clearCustomNode, exitSettings, saveSettings, showSettings } from '../../../features/settings/screen.js';
import {
    closeKpubImport,
    openKpubImport,
    saveManagedKpub,
    scanManagedKpub,
    showKpubManager,
    uploadManagedKpubImage,
    useKpubOnce,
} from '../../../features/wallet/kpub_manager/index.js';
import { closeDonateScreen, copyDonationAddress } from '../../../features/donations/screen.js';
import { clearHistory, handleConsolidate, handleConsolidateSelected, handleSendSelectedUtxos, showAddresses, showHistory, showUtxos } from '../../../features/wallet/tools.js';
import { showPortfolio } from '../../../features/portfolio/index.js';
// KasSee Web — app/events/settings and wallet
// Binds settings, wallet-history, address, UTXO, and consolidation events.

import { byId } from '../../../core/dom.js';


export function bindSettingsAndWalletEvents() {
    byId('btn-header-settings').onclick = () => toggleGearMenu();
    byId('btn-save-settings').onclick = () => saveSettings();
    byId('btn-use-public').onclick = () => { clearCustomNode(); exitSettings(); };
    byId('btn-settings-back').onclick = () => navigateBack();
    byId('btn-settings-back-top').onclick = () => navigateBack();
    byId('btn-kpub-manager-back').onclick = () => navigateBack();
    byId('btn-kpub-manager-back-top').onclick = () => navigateBack();
    byId('btn-open-kpub-import').onclick = () => openKpubImport();
    byId('btn-close-kpub-import').onclick = () => closeKpubImport();
    byId('btn-scan-managed-kpub').onclick = () => scanManagedKpub();
    const managedImageInput = byId('input-managed-kpub-image');
    byId('btn-upload-managed-kpub').onclick = () => managedImageInput.click();
    managedImageInput.onchange = async () => {
        const [file] = managedImageInput.files || [];
        await uploadManagedKpubImage(file);
        managedImageInput.value = '';
    };
    byId('btn-save-managed-kpub').onclick = () => saveManagedKpub();
    byId('btn-use-current-kpub').onclick = () => useKpubOnce();
    byId('input-kpub-friendly-name').onkeydown = event => {
        if (event.key === 'Enter') saveManagedKpub();
    };

    // Gear menu tabs
    document.querySelectorAll('.gear-tab').forEach(tab => {
        tab.onclick = () => {
            const target = tab.dataset.target;
            document.querySelectorAll('.gear-tab').forEach(item => item.classList.remove('active'));
            tab.classList.add('active');
            closeGearMenu();
            const returnScreen = visibleScreenName(navigationState.currentScreenName || 'dashboard');
            if (target === 'settings') navigationState.settingsReturnScreen = returnScreen;
            if (['addresses', 'utxos', 'tokens', 'history'].includes(target)) {
                showScreen(target);
                if (!walletSession.hasWallet()) {
                    toast('Load kpub first', 'info');
                    return;
                }
            }
            if (target === 'kpub-manager') showKpubManager(returnScreen);
            else if (target === 'addresses') showAddresses();
            else if (target === 'utxos') showUtxos();
            else if (target === 'tokens') showTokens();
            else if (target === 'history') showHistory();
            else if (target === 'portfolio') showPortfolio();
            else if (target === 'settings') showSettings(returnScreen);
        };
    });
    byId('btn-addresses-back').onclick = () => navigateBack(navigationState.addressesReturnScreen);
    byId('btn-addresses-back-top').onclick = () => navigateBack(navigationState.addressesReturnScreen);
    byId('btn-tokens-back').onclick = () => navigateBack();
    byId('btn-tokens-back-top').onclick = () => navigateBack();
    byId('btn-verify-copy').onclick = () => {
        navigator.clipboard.writeText(byId('verify-address').textContent.trim());
        toast('Address copied', 'ok', 1200);
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    byId('btn-verify-back').onclick = () => {
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    byId('btn-utxos-back').onclick = () => navigateBack();
    byId('btn-utxos-back-top').onclick = () => navigateBack();
    byId('btn-consolidate').onclick = () => handleConsolidate();
    byId('btn-consolidate-selected').onclick = () => handleConsolidateSelected();
    byId('btn-send-selected-utxos').onclick = () => handleSendSelectedUtxos();
    byId('btn-history-back').onclick = () => navigateBack();
    byId('btn-history-back-top').onclick = () => navigateBack();
    byId('btn-portfolio-back').onclick = () => navigateBack();
    byId('btn-portfolio-back-top').onclick = () => navigateBack();
    byId('btn-clear-history').onclick = () => clearHistory();
    byId('btn-donate-skip').onclick = () => closeDonateScreen();
    const copyDonation = () => { void copyDonationAddress(); };
    byId('btn-copy-donate').onclick = copyDonation;
    for (const target of [byId('donate-address'), byId('donate-qr')]) {
        target.onclick = copyDonation;
        target.onkeydown = event => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            copyDonation();
        };
    }
}
