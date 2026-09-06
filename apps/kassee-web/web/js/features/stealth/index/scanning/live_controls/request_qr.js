import { setSafeMarkup } from '../../../../../core/security/safe_html.js';
import { stealthState } from '../../../../../app/state/index.js';
import { bytesToHex, hexToBytes } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';
import { toast } from '../../../../../core/ui/toast.js';
import { generate_qr_frames } from '../../../../../wasm/api.js';
import { clearStealthQrTimer } from './lifecycle.js';

function buildScanRequest(start, count) {
    const payload = new Uint8Array(5 + count * 32);
    payload.set([0x53, 0x54, 0x4c, 0x48, count], 0);
    for (let index = 0; index < count; index++) {
        payload.set(hexToBytes(stealthState.stealthAnnouncementsR[start + index]), 5 + index * 32);
    }
    return payload;
}

function renderQrFrames(frames, qrBox) {
    if (frames.length <= 1) {
        qrBox.innerHTML = frames[0].svg;
        return;
    }
    let frameIndex = 0;
    const render = () => {
        qrBox.innerHTML = `${frames[frameIndex].svg}<div class="stealth-scan-frame">Frame ${frameIndex + 1}/${frames.length}</div>`;
    };
    render();
    stealthState._stealthQrTimer = setInterval(() => {
        frameIndex = (frameIndex + 1) % frames.length;
        render();
    }, 600);
}

export function showStealthScanQr() {
    if (stealthState._stealthCatchupRunning) {
        byId('stealth-scan-status').textContent = 'Lane scan still running. Wait for it to finish before scanning to your device, so no payment is missed.';
        toast('Lane scan still running, please wait', 'error');
        return;
    }
    if (stealthState.stealthAnnouncementsR.length === 0) {
        toast('No R values to scan', 'error');
        return;
    }

    let start = stealthState._stealthBatchStart || 0;
    if (start >= stealthState.stealthAnnouncementsR.length) {
        start = 0;
        stealthState._stealthBatchStart = 0;
    }
    const count = Math.min(stealthState.stealthAnnouncementsR.length - start, 64);
    const payload = buildScanRequest(start, count);
    clearStealthQrTimer();

    try {
        const frames = JSON.parse(generate_qr_frames(bytesToHex(payload)));
        document.getElementById('stealth-scan-qr-display')?.remove();
        const qrBox = document.createElement('div');
        qrBox.id = 'stealth-scan-qr-display';
        qrBox.classList.add('stealth-scan-qr');
        byId('stealth-scan-panel').insertBefore(qrBox, byId('btn-stealth-scan-result-qr'));
        renderQrFrames(frames, qrBox);

        const range = `<strong>Scanning R ${start + 1}–${start + count} of ${stealthState.stealthAnnouncementsR.length}.</strong> `;
        setSafeMarkup(byId('stealth-scan-status'), frames.length <= 1
            ? `${range}Point the device camera at this QR, then scan the response back.`
            : `${range}Hold the device camera on this animated QR (${frames.length} frames) until all are captured, then scan the response back.`);
        byId('btn-stealth-scan-result-qr').classList.remove('hidden');
    } catch (error) {
        toast(`QR generation failed: ${error}`, 'error', 3000);
        console.error('[KasSee] QR gen error:', error);
    }
}
