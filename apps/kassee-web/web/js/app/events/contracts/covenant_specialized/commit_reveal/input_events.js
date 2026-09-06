import { setSafeMarkup } from '../../../../../core/security/safe_html.js';
import { commitRevealState } from '../../../../state/index.js';
import { showScreen } from '../../../../navigation.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../../features/covenants/generation/ui_and_keys.js';
import { covScanAddress } from '../../../../../features/covenants/scanning_and_swap.js';
import { handleCovCrReveal } from '../../../../../features/covenants/spending/advanced.js';
import { startScanner, stopScanner } from '../../../../../features/stealth/index/camera.js';
import { generate_qr_svg_text } from '../../../../../wasm/api.js';
import { bytesToHex } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';

function bindDateInvalidation() {
    const pairs = [
        ['cov-cr-datetime', 'cov-cr-locktime'], ['cov-mw-datetime', 'cov-mw-locktime'],
        ['cov-payjoin-datetime', 'cov-payjoin-locktime'],
        ['cov-savings-datetime', 'cov-savings-locktime'],
    ];
    for (const [dateId, locktimeId] of pairs) {
        const date = byId(dateId);
        if (date) date.addEventListener('input', () => {
            const locktime = byId(locktimeId);
            if (locktime) locktime.value = '';
        });
    }
}

function showCiphertextQr() {
    const bytes = commitRevealState._crDecryptCtBytes;
    if (!bytes || bytes.length < 61) return toast('No ciphertext available', 'error');
    try {
        const overlay = document.createElement('div');
        overlay.id = 'cr-ct-overlay';
        overlay.classList.add('commit-reveal-decrypt-overlay');
        setSafeMarkup(overlay, '<p class="commit-reveal-decrypt-title">Scan on KasSigner: Decrypt Secret</p>' +
            '<div class="commit-reveal-decrypt-qr">' + generate_qr_svg_text(bytesToHex(bytes)) + '</div>' +
            '<p class="" id="cr-ct-close">Tap here to close</p>');
        document.body.appendChild(overlay);
        setTimeout(() => {
            const close = byId('cr-ct-close');
            if (close) close.onclick = () => overlay.remove();
            overlay.onclick = event => { if (event.target === overlay) overlay.remove(); };
        }, 300);
    } catch (error) {
        toast('QR generation failed: ' + error, 'error');
    }
}

export function bindCommitRevealInputEvents() {
    const scanCommitment = byId('btn-cov-cr-scan-commitment');
    if (scanCommitment) scanCommitment.onclick = () => startScanner('Scan Commitment QR', data => {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        if (bytes.length < 93) {
            stopScanner(); showScreen('covenant'); toast('Invalid commitment QR (too short)', 'error'); return;
        }
        stopScanner();
        const hashHex = bytesToHex(bytes.slice(0, 32));
        byId('cov-cr-hash-display').textContent = 'BLAKE2B: ' + hashHex;
        byId('cov-cr-ciphertext-hex').value = bytesToHex(bytes.slice(32));
        showScreen('covenant');
        toast('Commitment scanned. Hash: ' + hashHex.slice(0, 8) + '...', 'ok', 2000);
    });
    bindDateInvalidation();
    const reveal = byId('btn-cov-cr-reveal');
    if (reveal) reveal.onclick = () => covShowPanel('cr-reveal');
    byId('btn-cov-cr-reveal-back').onclick = () => { commitRevealState._crDecryptCtBytes = null; covShowPanel('result'); };
    byId('btn-cov-cr-reveal-create').onclick = () => handleCovCrReveal();
    const showQr = byId('btn-cov-cr-show-ct-qr');
    if (showQr) showQr.onclick = showCiphertextQr;
    const scanPreimage = byId('btn-cov-cr-scan-preimage');
    if (scanPreimage) scanPreimage.onclick = () => startScanner('Scan Decrypted Preimage', data => {
        stopScanner();
        const text = data instanceof Uint8Array || data instanceof ArrayBuffer
            ? new TextDecoder().decode(new Uint8Array(data)) : String(data);
        const hex = text.trim();
        if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length < 2) {
            showScreen('covenant'); toast('Invalid preimage hex', 'error'); return;
        }
        commitRevealState._crRevealPartA = hex;
        commitRevealState._crRevealPartB = '';
        const status = byId('cov-cr-preimage-status');
        if (status) status.textContent = 'Preimage received (' + (hex.length / 2) + ' bytes)';
        showScreen('covenant'); toast('Preimage scanned', 'ok', 1500);
    });
    const scanAddress = byId('btn-cov-scan-cr-addr');
    if (scanAddress) scanAddress.onclick = () => covScanAddress('cov-cr-addr', 'Scan covenant address');
    byId('btn-cov-scan-cr-dest').onclick = () => covScanAddress('cov-cr-dest', 'Scan destination');
}
