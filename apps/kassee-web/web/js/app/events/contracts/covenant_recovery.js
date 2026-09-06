import { byId } from '../../../core/dom.js';
import { covShowPanel } from '../../../features/covenants/generation/ui_and_keys.js';
import { handleCovbScan } from '../../../features/covenants/recovery/import.js';
import { recoverCovenants } from '../../../features/covenants/recovery/scanner.js';
import { startScanner } from '../../../features/stealth/index/camera.js';

export function bindCovenantRecoveryEvents() {
    byId('btn-cov-load-existing').onclick = () => {
        covShowPanel('load');
        const type = byId('cov-load-type');
        if (!type) return;
        type.style.display = '';
        const label = type.previousElementSibling;
        if (label?.classList.contains('input-label')) label.style.display = '';
    };
    const recoverButton = byId('btn-cov-recover-chain');
    if (recoverButton) recoverButton.onclick = () => recoverCovenants();
    const scanButton = byId('btn-cov-import-scan');
    if (scanButton) {
        scanButton.onclick = () => startScanner('Scan Covenant Backup QR', handleCovbScan, 'menu');
    }
}
