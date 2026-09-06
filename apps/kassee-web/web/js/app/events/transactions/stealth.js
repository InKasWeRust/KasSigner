import { bytesToHex } from '../../../core/bytes.js';
import { walletSession } from '../../state/index.js';
import { handleStealthScanResultQR, handleStealthShowScanQR, stealthScanStop } from '../../../features/stealth/index/scanning/live.js';
import { navigateBack, showScreen } from '../../navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { startScanner, stopScanner } from '../../../features/stealth/index/camera.js';
import { handleStealthFetchAnnouncements } from '../../../features/stealth/index/scanning/live.js';
import { handleStealthMeta, handleStealthSendGenerate, handleStealthSendPay, stealthFeeSetLevel, stealthShowPanel } from '../../../features/stealth/index/send.js';
// KasSee Web — app/events/transactions/stealth
// Binds stealth-address generation, scanning, and payment events.

import { byId } from '../../../core/dom.js';


export function bindStealthEvents() {
    // Stealth
    byId('btn-stealth').onclick = () => { stealthShowPanel('menu'); showScreen('stealth'); };
    byId('btn-stealth-back').onclick = () => { stealthScanStop(); navigateBack(walletSession.hasWallet() ? 'dashboard' : 'welcome'); };
    byId('btn-stealth-meta').onclick = () => handleStealthMeta();
    byId('btn-stealth-meta-back').onclick = () => stealthShowPanel('menu');
    byId('btn-stealth-meta-copy').onclick = () => {
        const hex = byId('stealth-meta-hex').textContent;
        navigator.clipboard.writeText(hex).then(() => toast('Copied', 'ok', 1500));
    };
    byId('btn-stealth-send').onclick = () => stealthShowPanel('send');
    byId('btn-stealth-send-back').onclick = () => stealthShowPanel('menu');
    byId('btn-stealth-send-go').onclick = () => handleStealthSendGenerate();
    byId('btn-stealth-send-pay').onclick = () => handleStealthSendPay();
    byId('btn-sf-low').onclick = () => stealthFeeSetLevel('sf', 'send', 'low');
    byId('btn-sf-normal').onclick = () => stealthFeeSetLevel('sf', 'send', 'normal');
    byId('btn-sf-priority').onclick = () => stealthFeeSetLevel('sf', 'send', 'priority');
    byId('btn-stealth-scan').onclick = () => stealthShowPanel('scan');
    byId('btn-stealth-scan-back').onclick = () => stealthShowPanel('menu');
    byId('btn-stealth-fetch-announcements').onclick = () => handleStealthFetchAnnouncements();
    byId('btn-stealth-show-scan-qr').onclick = () => handleStealthShowScanQR();
    byId('btn-stealth-scan-result-qr').onclick = () => handleStealthScanResultQR();
    byId('btn-stealth-scan-meta').onclick = () => startScanner('Scan Stealth Meta-Address', (data) => {
        const bytes = new Uint8Array(data);
        let text = new TextDecoder().decode(bytes).trim();
        // Fallback: a meta QR encoded as 64 raw bytes -> hex-encode to 128 hex.
        if (!/^[0-9a-fA-F]{128}$/.test(text) && bytes.length === 64) {
            text = bytesToHex(bytes);
        }
        if (/^[0-9a-fA-F]{128}$/.test(text)) {
            stopScanner();
            byId('stealth-send-meta').value = text;
            showScreen('stealth');
            stealthShowPanel('send');
            toast('Meta-address scanned', 'ok', 1500);
        }
    });
}
