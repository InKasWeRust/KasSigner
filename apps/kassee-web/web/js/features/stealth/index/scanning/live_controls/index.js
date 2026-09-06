import { pauseStealthScan, stopStealthScan } from './lifecycle.js';
import { ensureStealthManualRSection } from './manual.js';
import { showStealthScanQr } from './request_qr.js';
import { scanStealthResultQr } from './response_scanner.js';

export function createStealthScanControls() {
    return {
        stealthScanPause: pauseStealthScan,
        stealthScanStop: stopStealthScan,
        ensureStealthManualRSection,
        handleStealthShowScanQR: showStealthScanQr,
        handleStealthScanResultQR: scanStealthResultQr,
    };
}
