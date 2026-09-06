import { covenantState } from '../../../state/index.js';
import { showScreen } from '../../../navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { handleCovCheckBalance } from '../../../../features/covenants/spending/advanced.js';
import { startScanner, stopScanner } from '../../../../features/stealth/index/camera.js';
import { byId } from '../../../../core/dom.js';

export function bindSwapAndUtilityActions() {
    byId('cov-result-addr').onclick = () => { navigator.clipboard.writeText(byId('cov-result-addr').textContent); toast('Address copied', 'ok', 1200); };
    byId('cov-result-script').onclick = () => { navigator.clipboard.writeText(byId('cov-result-script').textContent); toast('Redeem script copied', 'ok', 1200); };
    if (byId('btn-cov-scan-owner-addr')) byId('btn-cov-scan-owner-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); byId('cov-owner-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });
    byId('btn-cov-scan-owner-dest').onclick = () => startScanner('Scan destination', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); byId('cov-owner-dest').value = addr; showScreen('covenant'); covShowPanel('owner'); toast('Address scanned', 'ok', 1500); }
    });
    byId('btn-consol-scan-dest').onclick = () => startScanner('Scan destination', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); byId('cov-consol-dest').value = addr; showScreen('covenant'); covShowPanel('consolidate'); toast('Address scanned', 'ok', 1500); }
    });
    byId('btn-cov-scan-borrower-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); byId('cov-borrower-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });
    // Balance checker
    byId('btn-cov-check-balance').onclick = () => {
        covShowPanel('balance');
        if (covenantState.lastCovenantResult) {
            byId('cov-balance-addr').value = covenantState.lastCovenantResult.address || '';
        }
        byId('cov-balance-result').classList.add('hidden');
    };
    byId('btn-cov-owner-reclaim').onclick = () => {
        covShowPanel('owner');
        if (covenantState.lastCovenantResult) {
            byId('cov-owner-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-owner-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
        }
    };
    byId('btn-cov-balance-back').onclick = () => covShowPanel('menu');
    byId('btn-cov-balance-check').onclick = () => handleCovCheckBalance();
    byId('btn-cov-scan-balance-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); byId('cov-balance-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });
}
