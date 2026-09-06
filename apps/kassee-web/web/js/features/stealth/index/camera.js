import { navigationState, scannerState, walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { covShowPanel } from '../../covenants/generation/ui_and_keys.js';
import { resumeQrCycleIfPossible } from '../../transactions/send/review.js';
import { reset_qr_decoder } from '../../../wasm/api.js';
// KasSee Web — features/stealth/index/camera
import { byId } from '../../../core/dom.js';


// ─── Camera QR scanner ───

const SCAN_INTERVAL_MS = 80; // ~12.5 fps: enough for QR acquisition without full-frame decode every display frame.
let lastDecodeAt = 0;
let scannerGeneration = 0;

scannerState._scannerReturnScreen = null;

scannerState._scannerReturnPanel = null;

function cameraErrorMessage(err) {
    if (!err) return 'Camera unavailable';
    return err.message || err.name || String(err);
}

function modernCameraRequest() {
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
        return null;
    }
    const request = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    const preferred = {
        audio: false,
        video: { facingMode: 'environment', width: { ideal: 720 }, height: { ideal: 720 } }
    };
    return request(preferred).catch(err => {
        // Old Chromium/WebView builds often implement mediaDevices but reject
        // modern constraint dictionaries. Retry only constraint/API failures;
        // never turn a permission denial into a second permission prompt.
        const name = err && err.name ? err.name : '';
        if (name !== 'OverconstrainedError'
            && name !== 'ConstraintNotSatisfiedError'
            && name !== 'TypeError') {
            throw err;
        }
        return request({ audio: false, video: true });
    });
}

function legacyCameraRequest() {
    const legacy = navigator.getUserMedia
        || navigator.webkitGetUserMedia
        || navigator.mozGetUserMedia;
    if (typeof legacy !== 'function') {
        return Promise.reject(new Error('Camera capture is not supported by this browser'));
    }
    return new Promise((resolve, reject) => {
        legacy.call(navigator, { audio: false, video: true }, resolve, reject);
    });
}

function requestCameraStream() {
    const modern = modernCameraRequest();
    return modern || legacyCameraRequest();
}

function stopStream(stream) {
    if (!stream || typeof stream.getTracks !== 'function') return;
    stream.getTracks().forEach(track => track.stop());
}

function teardownScannerResources() {
    if (scannerState.scanAnimFrame) {
        cancelAnimationFrame(scannerState.scanAnimFrame);
        scannerState.scanAnimFrame = null;
    }
    if (scannerState.scanStream) {
        stopStream(scannerState.scanStream);
        scannerState.scanStream = null;
    }
    lastDecodeAt = 0;
}

function attachCameraStream(video, stream) {
    scannerState.scanStream = stream;
    if ('srcObject' in video) {
        video.srcObject = stream;
    } else {
        if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
            throw new Error('This browser cannot attach a camera stream to video');
        }
        video.src = URL.createObjectURL(stream);
    }
    const playback = video.play();
    if (playback && typeof playback.catch === 'function') {
        return playback;
    }
    return Promise.resolve();
}

export function startScanner(title, callback, returnPanel) {
    const generation = ++scannerGeneration;
    teardownScannerResources();
    scannerState.scanCallback = callback;
    const currentScreen = navigationState.currentScreenName || 'dashboard';
    if (currentScreen !== 'scanner' || !scannerState._scannerReturnScreen) {
        scannerState._scannerReturnScreen = currentScreen;
    }
    if (returnPanel !== undefined) scannerState._scannerReturnPanel = returnPanel;
    byId('scanner-title').textContent = title;
    byId('scanner-status').textContent = 'Starting camera...';
    showScreen('scanner');
    try { reset_qr_decoder(); } catch (_) {}

    lastDecodeAt = 0;
    const video = byId('scanner-video');
    const canvas = byId('scanner-canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    requestCameraStream().then(stream => {
        if (generation !== scannerGeneration) {
            stopStream(stream);
            return null;
        }
        return attachCameraStream(video, stream).then(() => stream);
    }).then(stream => {
        if (!stream || generation !== scannerGeneration) {
            stopStream(stream);
            return;
        }
        byId('scanner-status').textContent = 'Point at QR code';
        scanLoop(video, canvas, ctx, performance.now(), generation);
    }).catch(err => {
        if (generation !== scannerGeneration) return;
        teardownScannerResources();
        byId('scanner-status').textContent = 'Camera error: ' + cameraErrorMessage(err);
    });
}
function scanLoop(video, canvas, ctx, now = performance.now(), generation = scannerGeneration) {
    if (generation !== scannerGeneration || !scannerState.scanStream) return;
    const due = now - lastDecodeAt >= SCAN_INTERVAL_MS;
    if (due && video.readyState === video.HAVE_ENOUGH_DATA && video.videoWidth > 0 && video.videoHeight > 0) {
        lastDecodeAt = now;
        if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
        }
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
        if (code && code.binaryData && code.binaryData.length > 0) {
            if (scannerState.scanCallback) scannerState.scanCallback(new Uint8Array(code.binaryData));
        }
    }
    scannerState.scanAnimFrame = requestAnimationFrame(timestamp => scanLoop(video, canvas, ctx, timestamp, generation));
}
export function stopScanner() {
    ++scannerGeneration;
    teardownScannerResources();
    scannerState.scanCallback = null;
    const returnScreen = scannerState._scannerReturnScreen || (walletSession.hasWallet() ? 'dashboard' : 'welcome');
    const returnPanel = scannerState._scannerReturnPanel;
    scannerState._scannerReturnScreen = null;
    scannerState._scannerReturnPanel = null;
    showScreen(returnScreen);
    if (returnPanel) covShowPanel(returnPanel);
    // If we paused a QR cycle to open the scanner and the user cancelled
    // back to the QR display, resume the animation so they aren't stuck
    // on a frozen frame with non-functional play/pause controls.
    if (returnScreen === 'qr-display') resumeQrCycleIfPossible();
}
