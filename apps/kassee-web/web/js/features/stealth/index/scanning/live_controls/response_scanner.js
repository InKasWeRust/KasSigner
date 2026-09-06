import { setSafeMarkup } from '../../../../../core/security/safe_html.js';
import { scannerState } from '../../../../../app/state/index.js';
import { byId } from '../../../../../core/dom.js';
import { toast } from '../../../../../core/ui/toast.js';
import { startScanner } from '../../camera.js';
import { processStealthResult } from './results.js';

function isStlr(payload) {
    return payload.length >= 69
        && payload[0] === 0x53
        && payload[1] === 0x54
        && payload[2] === 0x4c
        && payload[3] === 0x52;
}

function collectFragment(raw) {
    if (raw.length < 4 || raw[1] < 2 || raw[2] === 0 || raw[2] + 3 > raw.length) return null;
    const [frameIndex, totalFrames, fragmentLength] = raw;
    if (!scannerState._stlrFrames || scannerState._stlrFrames.total !== totalFrames) {
        scannerState._stlrFrames = {
            total: totalFrames,
            received: new Set(),
            buffers: new Array(totalFrames),
        };
    }
    const fragments = scannerState._stlrFrames;
    if (frameIndex >= totalFrames) return null;
    if (!fragments.received.has(frameIndex)) {
        fragments.received.add(frameIndex);
        fragments.buffers[frameIndex] = raw.slice(3, 3 + fragmentLength);
        setSafeMarkup(byId('stealth-scan-status'), `<strong>Receiving response ${fragments.received.size}/${totalFrames}.</strong> Keep the camera on the device QR.`);
    }
    if (fragments.received.size < totalFrames) return null;
    if (fragments.buffers.some(buffer => !buffer)) return null;
    const totalLength = fragments.buffers.reduce((sum, buffer) => sum + buffer.length, 0);
    const assembled = new Uint8Array(totalLength);
    let offset = 0;
    for (const buffer of fragments.buffers) {
        assembled.set(buffer, offset);
        offset += buffer.length;
    }
    scannerState._stlrFrames = null;
    return assembled;
}

function dispatchResult(payload) {
    void processStealthResult(payload).catch(error => {
        console.error('[KasSee] Stealth result processing failed:', error);
        toast(`Stealth result processing failed: ${error}`, 'error', 4000);
    });
}

export function scanStealthResultQr() {
    scannerState._stlrFrames = null;
    startScanner('Scan Device Stealth Response', data => {
        const raw = new Uint8Array(data);
        if (isStlr(raw)) {
            dispatchResult(raw);
            return;
        }
        const assembled = collectFragment(raw);
        if (assembled && isStlr(assembled)) dispatchResult(assembled);
    });
}
