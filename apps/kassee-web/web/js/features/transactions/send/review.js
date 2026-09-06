import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { covenantState, networkState, scannerState, transactionState, walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { sompiToKasString } from '../../../core/amounts.js';
import { encode_p2pk_address, encode_p2sh_address, generate_qr_frames } from '../../../wasm/api.js';
// KasSee Web — features/transactions/send/review
import { bytesToHex, hexToBytes } from '../../../core/bytes.js';
import { byId } from '../../../core/dom.js';


// ─── TX info under QR display for verification ───

function appendText(parent, tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = String(text);
    parent.appendChild(node);
    return node;
}

function appendAddress(parent, addr, label, labelClasses) {
    const row = document.createElement('div');
    row.className = 'tx-review-address';
    if (!addr) {
        appendText(row, 'span', 'u-text-text-muted', '(unknown)');
    } else {
        appendText(row, 'span', '', addr);
        if (label) appendText(row, 'span', `tx-review-tag ${labelClasses[label] || ''}`, label);
    }
    parent.appendChild(row);
}

function renderQrTxInfo() {
    const box = byId('qr-tx-info');
    if (!box) return;
    box.replaceChildren();
    if (!transactionState._lastPsktSummary) { box.style.display = 'none'; return; }
    const s = transactionState._lastPsktSummary;

    function scriptAddr(scriptHex, kind) {
        try {
            if ((kind === 'p2pk' || kind === 'p2pk-schnorr') && scriptHex.length === 68)
                return encode_p2pk_address(scriptHex.substring(2, 66), networkState.network);
            if ((kind === 'p2sh' || kind === 'p2sh-multisig' || kind === 'p2sh-covenant') && scriptHex.length === 70)
                return encode_p2sh_address(scriptHex.substring(4, 68), networkState.network);
        } catch (_) {}
        return null;
    }

    function addrLabel(addr) {
        if (!addr || !walletSession.hasWallet()) return '';
        let w; try { w = walletSession.current(); } catch (_) { return ''; }
        if (w.receive_addresses && w.receive_addresses.includes(addr)) return 'OWN';
        if (w.change_addresses && w.change_addresses.includes(addr)) return 'CHANGE';
        return '';
    }

    const labelClasses = Object.freeze({
        CHANGE: 'tx-review-tag-change', OWN: 'tx-review-tag-own',
        DESTINATION: 'tx-review-tag-destination', COVENANT: 'tx-review-tag-covenant',
    });
    const summary = document.createElement('div');
    summary.className = 'tx-review-summary';
    appendText(summary, 'div', 'tx-review-heading', 'TX Verification');
    appendText(summary, 'div', 'tx-review-fee', `Fee: ${sompiToKasString(s.fee_sompi)} KAS`);
    appendText(summary, 'div', 'tx-review-outputs-title', 'Outputs');

    s.outputs.forEach((out, i) => {
        const addr = out.address || scriptAddr(out.script_hex, out.script_kind);
        const cls = addrLabel(addr);
        const label = cls || (out.script_kind === 'p2sh' ? 'COVENANT' : (addr ? 'DESTINATION' : ''));
        const card = document.createElement('div');
        card.className = 'u-mb-8px-padding-6px-8px-bg-bg-border-1px-solid-border';
        appendText(card, 'span', 'u-text-text-muted', `#${i} ${String(out.script_kind).toUpperCase()}`);
        appendText(card, 'span', 'u-text-text', `${sompiToKasString(out.amount_sompi)} KAS`);
        appendAddress(card, addr, label, labelClasses);
        summary.appendChild(card);
    });

    appendText(summary, 'div', 'tx-review-inputs-title', 'Inputs');
    s.inputs.forEach((inp, i) => {
        let addr = scriptAddr(inp.script_hex, inp.script_kind);
        if (!addr && (inp.script_kind === 'p2sh' || inp.script_kind === 'p2sh-covenant') && covenantState.lastCovenantResult?.address) {
            addr = covenantState.lastCovenantResult.address;
        }
        const cls = addrLabel(addr);
        const label = cls || (((inp.script_kind === 'p2sh' || inp.script_kind === 'p2sh-covenant') && inp.redeem_script_hex) ? 'COVENANT' : '');
        const card = document.createElement('div');
        card.className = 'u-mb-8px-padding-6px-8px-bg-bg-border-1px-solid-border';
        appendText(card, 'span', 'u-text-text-muted', `#${i} ${String(inp.script_kind).toUpperCase()}`);
        appendText(card, 'span', 'u-text-text', `${sompiToKasString(inp.amount_sompi)} KAS`);
        appendAddress(card, addr, label, labelClasses);
        if (inp.redeem_script_hex) {
            const toggle = appendText(card, 'button', 'tx-review-redeem-toggle', 'Redeem Script ▼');
            toggle.type = 'button';
            const redeem = appendText(card, 'div', 'tx-review-redeem-script', inp.redeem_script_hex);
            redeem.style.display = 'none';
            toggle.addEventListener('click', () => {
                redeem.style.display = redeem.style.display === 'none' ? '' : 'none';
            });
        }
        summary.appendChild(card);
    });

    if (covenantState._covPayloadHex) {
        const plDiv = appendText(summary, 'div', '', '');
        plDiv.id = 'qrtx-pl-hash';
        crypto.subtle.digest('SHA-256', hexToBytes(covenantState._covPayloadHex).buffer).then(hashBuf => {
            plDiv.textContent = 'PL ' + bytesToHex(new Uint8Array(hashBuf).slice(0, 8));
        });
    }
    box.appendChild(summary);
    box.style.display = '';
}

export function displayKsptQr(ksptHex, title, options = {}) {
    // Clear any stale QR cycle from a previous display
    if (scannerState.qrCycleTimer) { clearInterval(scannerState.qrCycleTimer); scannerState.qrCycleTimer = null; }
    // Render TX verification info below QR
    renderQrTxInfo();
    try {
        const frames = JSON.parse(generate_qr_frames(ksptHex));
        scannerState.qrFrames = frames;
        scannerState.qrFrameIdx = 0;
        byId('qr-display-title').textContent = title || 'Scan QR Code';

        const mode = options.mode || 'standard';
        const isRelay = mode === 'relay' || (mode === 'standard' && title && title.includes('Relay'));
        const antiKleptoStep = mode === 'anti-klepto-request' || mode === 'anti-klepto-reveal';
        const nextSignatureButton = byId('btn-scan-next-sig');
        const primaryScanButton = byId('btn-qr-scan-signed');
        const instruction = byId('qr-display-instruction');
        nextSignatureButton.style.display = antiKleptoStep ? 'none' : (isRelay ? 'block' : 'none');
        nextSignatureButton.textContent = 'Scan Next Signature';
        primaryScanButton.style.display = '';
        primaryScanButton.textContent = options.primaryScanLabel || 'Scan Signed QR';
        primaryScanButton.dataset.scanTitle = options.scannerTitle || 'Scan signed QR';
        instruction.textContent = options.instruction || '';
        instruction.style.display = options.instruction ? '' : 'none';
        byId('btn-copy-kspt').style.display = 'none'; // hidden until advanced tab
        transactionState._currentKsptHex = ksptHex;

        if (frames.length === 1) {
            byId('qr-container').innerHTML = frames[0].svg;
            byId('qr-frame-info').innerHTML = '';
        } else {
            let dots = '<div class="frame-dots">';
            for (let i = 0; i < frames.length; i++) {
                dots += `<span class="frame-dot${i === 0 ? ' active' : ''}" id="fdot-${i}"></span>`;
            }
            dots += '</div>';
            dots += '<div class="frame-controls">';
            dots += '<button class="btn-frame" id="btn-frame-prev">\u23EA</button>';
            dots += '<button class="btn-frame" id="btn-frame-pause" title="Pause/Play">\u23F8</button>';
            dots += '<button class="btn-frame" id="btn-frame-next">\u23E9</button>';
            dots += '</div>';
            setSafeMarkup(byId('qr-frame-info'), dots);
            renderQrFrame(0);
            scannerState.qrCycleTimer = setInterval(() => {
                scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
                renderQrFrame(scannerState.qrFrameIdx);
            }, 1600);
            byId('btn-frame-prev').onclick = () => {
                scannerState.qrFrameIdx = (scannerState.qrFrameIdx - 1 + scannerState.qrFrames.length) % scannerState.qrFrames.length;
                renderQrFrame(scannerState.qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (scannerState.qrCycleTimer) {
                    clearInterval(scannerState.qrCycleTimer);
                    scannerState.qrCycleTimer = setInterval(() => {
                        scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
                        renderQrFrame(scannerState.qrFrameIdx);
                    }, 1600);
                }
            };
            byId('btn-frame-next').onclick = () => {
                scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
                renderQrFrame(scannerState.qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (scannerState.qrCycleTimer) {
                    clearInterval(scannerState.qrCycleTimer);
                    scannerState.qrCycleTimer = setInterval(() => {
                        scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
                        renderQrFrame(scannerState.qrFrameIdx);
                    }, 1600);
                }
            };
            byId('btn-frame-pause').onclick = () => {
                if (scannerState.qrCycleTimer) {
                    clearInterval(scannerState.qrCycleTimer);
                    scannerState.qrCycleTimer = null;
                    byId('btn-frame-pause').textContent = '\u25B6';
                } else {
                    scannerState.qrCycleTimer = setInterval(() => {
                        scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
                        renderQrFrame(scannerState.qrFrameIdx);
                    }, 1600);
                    byId('btn-frame-pause').textContent = '\u23F8';
                }
            };
        }
        showScreen('qr-display');
    } catch (e) {
        toast('QR generation failed: ' + e, 'error', 5000);
    }
}
function renderQrFrame(idx) {
    if (!scannerState.qrFrames || idx >= scannerState.qrFrames.length) return;
    byId('qr-container').innerHTML = scannerState.qrFrames[idx].svg;
    for (let i = 0; i < scannerState.qrFrames.length; i++) {
        const dot = document.getElementById(`fdot-${i}`);
        if (dot) dot.className = `frame-dot${i === idx ? ' active' : ''}`;
    }
    const c = byId('qr-container');
    c.style.opacity = '0.7';
    setTimeout(() => { c.style.opacity = '1'; }, 100);
}
export function stopQrCycle() {
    if (scannerState.qrCycleTimer) { clearInterval(scannerState.qrCycleTimer); scannerState.qrCycleTimer = null; }
    scannerState.qrFrames = null;
}
// briefly leaves the QR display (e.g. taps Scan Signed QR, then cancels
// the scanner) so we can resume animation on their return instead of
// leaving them stuck on a frozen QR with non-functional play/pause.
export function pauseQrCycle() {
    if (scannerState.qrCycleTimer) { clearInterval(scannerState.qrCycleTimer); scannerState.qrCycleTimer = null; }
}
// Idempotent: safe to call when already running.
export function resumeQrCycleIfPossible() {
    if (!scannerState.qrFrames || scannerState.qrFrames.length <= 1) return;
    if (scannerState.qrCycleTimer) return;
    scannerState.qrCycleTimer = setInterval(() => {
        scannerState.qrFrameIdx = (scannerState.qrFrameIdx + 1) % scannerState.qrFrames.length;
        renderQrFrame(scannerState.qrFrameIdx);
    }, 1600);
    // Re-sync pause-button icon to the play state
    const pb = byId('btn-frame-pause');
    if (pb) pb.textContent = '\u23F8';
}
