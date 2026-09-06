import { walletSession } from '../../state/index.js';
import { navigateBack, showScreen } from '../../navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { handleLogoTap } from '../../../features/donations/screen.js';
import { startScanner, stopScanner } from '../../../features/stealth/index/camera.js';
import { discoverMultisigBranch, handleDescriptorScan, handleMsMax, handleMultisigCreate, toggleMsUtxos } from '../../../features/transactions/pskt_multisig/multisig.js';
import { hideBroadcastResult } from '../../../features/transactions/send/broadcast.js';
import { openSendScreen } from '../../../features/transactions/send/compose/send_form.js';
import { showReceive } from '../../../features/transactions/send/receive.js';
import { showKpubManager } from '../../../features/wallet/kpub_manager/index.js';
// KasSee Web — app/events/system/core
// Binds application-wide scanner and primary navigation events.

import { byId } from '../../../core/dom.js';


export function bindCoreEvents() {
    byId('btn-scan-kpub').onclick = () => showKpubManager('welcome', { openImport: true });
    byId('btn-logo').onclick = () => handleLogoTap();
    byId('btn-multisig-welcome').onclick = () => showScreen('multisig');
    byId('btn-broadcast-welcome').onclick = () => { hideBroadcastResult(); showScreen('broadcast'); };
    byId('btn-send').onclick = () => openSendScreen();
    byId('btn-receive').onclick = () => showReceive();
    byId('btn-broadcast').onclick = () => { hideBroadcastResult(); showScreen('broadcast'); };
    byId('btn-multisig-spend').onclick = () => showScreen('multisig');
    byId('btn-ms-back').onclick = () => navigateBack(walletSession.hasWallet() ? 'dashboard' : 'welcome');
    byId('btn-ms-create').onclick = () => handleMultisigCreate();
    byId('btn-ms-max').onclick = () => handleMsMax();
    byId('btn-toggle-ms-utxos').onclick = () => toggleMsUtxos();
    byId('btn-ms-discover').onclick = () => discoverMultisigBranch();
    byId('btn-scan-ms-source').onclick = () => startScanner('Scan P2SH address', data => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:')) {
            stopScanner();
            byId('input-ms-source').value = addr;
            showScreen('multisig');
            toast('Address scanned', 'ok', 1500);
        }
    });
    byId('btn-scan-ms-dest').onclick = () => startScanner('Scan destination', data => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:') || addr.endsWith('.kas')) {
            stopScanner();
            byId('input-ms-dest').value = addr;
            showScreen('multisig');
            toast('Address scanned', 'ok', 1500);
        }
    });
    byId('btn-scan-ms-descriptor').onclick = () => startScanner('Scan descriptor QR', handleDescriptorScan);
}
