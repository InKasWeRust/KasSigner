import { networkState } from '../../../../state/index.js';
import { hideLoading, showLoading, showScreen } from '../../../../navigation.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../../features/covenants/generation/ui_and_keys.js';
import { startScanner, stopScanner } from '../../../../../features/stealth/index/camera.js';
import { byId } from '../../../../../core/dom.js';
import { fetchCommitRevealTransaction } from './transaction_fetch.js';
import { verifyCommitRevealTransaction } from './verification.js';
import { clearVerificationResult, renderVerificationResult } from './rendering.js';

export function bindCommitRevealVerificationEvents() {
    const back = byId('btn-cov-cr-verify-back');
    if (back) back.onclick = () => covShowPanel('result');
    const clear = byId('btn-cov-cr-verify-clear');
    if (clear) clear.onclick = () => { clearVerificationResult(); toast('Revelation cleared', 'ok'); };
    const scan = byId('btn-cov-scan-cr-verify-txid');
    if (scan) scan.onclick = () => startScanner('Scan TX ID', data => {
        stopScanner();
        byId('cov-cr-verify-txid').value = (data instanceof Uint8Array ? new TextDecoder().decode(data) : String(data)).trim();
        showScreen('covenant');
    });
    const verify = byId('btn-cov-cr-verify');
    if (verify) verify.onclick = async () => {
        const txid = byId('cov-cr-verify-txid').value.trim();
        if (txid.length !== 64) return toast('Enter a valid 64-char TX ID', 'error');
        showLoading('Fetching TX...');
        try {
            const transaction = await fetchCommitRevealTransaction(txid, networkState.network);
            hideLoading();
            renderVerificationResult(verifyCommitRevealTransaction(transaction));
        } catch (error) {
            hideLoading();
            toast('Verification failed: ' + error.message, 'error', 5000);
        }
    };
}
