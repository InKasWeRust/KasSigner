import { scannerState, stealthState } from '../../../../../app/state/index.js';
import { byId } from '../../../../../core/dom.js';
import { stopScanner } from '../../camera.js';

function removeElement(id) {
    const element = byId(id);
    if (element?.parentNode) element.parentNode.removeChild(element);
}

function stopQrTimer() {
    if (!stealthState._stealthQrTimer) return;
    clearInterval(stealthState._stealthQrTimer);
    stealthState._stealthQrTimer = null;
}

export function pauseStealthScan() {
    stopQrTimer();
    if (scannerState.scanStream) stopScanner();
    removeElement('stealth-scan-qr-display');
}

export function stopStealthScan() {
    stealthState._stealthScanActive = false;
    removeElement('stealth-live-status');
    if (stealthState._stealthScanWs) {
        stealthState._stealthScanWs.close();
        stealthState._stealthScanWs = null;
    }
    stopQrTimer();
    if (scannerState.scanStream) stopScanner();
    removeElement('stealth-scan-qr-display');

    stealthState.stealthAnnouncementsR = [];
    stealthState._stealthResults = [];
    stealthState._stealthBatchStart = 0;
    stealthState._stealthCatchupRunning = false;

    const status = byId('stealth-scan-status');
    if (status) status.textContent = '';
    const found = byId('stealth-found-list');
    if (found) found.innerHTML = '';
    byId('stealth-scan-results')?.classList.add('hidden');
    const rList = byId('stealth-r-list');
    if (rList) rList.textContent = '';
    const manual = byId('stealth-manual-r-input');
    if (manual) manual.value = '';
    byId('btn-stealth-show-scan-qr')?.classList.add('hidden');
    byId('btn-stealth-scan-result-qr')?.classList.add('hidden');
    console.log('[KasSee] Stealth scan: stopped and reset');
}

export function clearStealthQrTimer() {
    stopQrTimer();
}
