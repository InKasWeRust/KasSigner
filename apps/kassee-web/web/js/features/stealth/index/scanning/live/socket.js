import { stealthState } from '../../../../../app/state/index.js';
import { STEALTH_MAX_R } from '../../config.js';
import { bytesToHex } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';
const RECONNECT_DELAY_MS = 3000;
const KSTL_PAYLOAD_LENGTH = 0x22;

export function startLiveSocket(wsUrl, subscribeRequest) {
    const connect = () => {
        const socket = new WebSocket(wsUrl);
        socket.binaryType = 'arraybuffer';
        stealthState._stealthScanWs = socket;
        socket.onopen = () => handleOpen(socket, subscribeRequest);
        socket.onmessage = event => handleMessage(event);
        socket.onerror = () => console.log('[KasSee] Stealth live WS error');
        socket.onclose = () => handleClose(socket, connect);
    };
    connect();
}

function handleOpen(socket, subscribeRequest) {
    socket.send(subscribeRequest);
    const status = liveStatusElement();
    status.style.color = 'var(--accent, #4caf50)';
    status.textContent = 'LIVE scan: connected — watching new blocks.';
    byId('stealth-scan-status').textContent =
        'Live scan running. Watching new blocks for stealth payments... (' +
        stealthState.stealthAnnouncementsR.length + ' R found)';
}

function handleMessage(event) {
    const data = new Uint8Array(event.data);
    if (!isBlockAddedNotification(data)) return;
    const candidates = extractCandidates(data);
    const added = appendCandidates(candidates);
    if (added === 0) return;

    byId('stealth-scan-status').textContent =
        'Live scan running. ' + stealthState.stealthAnnouncementsR.length +
        ' candidate R found. Tap "Show Scan QR" to check on your device.';
    updateCandidateControls();
    console.log('[KasSee] Stealth scan: +' + added + ' R (total ' +
        stealthState.stealthAnnouncementsR.length + ')');
}

function handleClose(socket, reconnect) {
    if (stealthState._stealthScanWs !== socket) return;
    stealthState._stealthScanWs = null;
    const status = liveStatusElement();
    status.style.color = 'var(--error, #f44336)';
    status.textContent =
        'LIVE scan: DOWN — new payments are NOT being watched. Reconnecting…';
    console.log('[KasSee] Stealth live WS closed, reconnecting in 3s');
    setTimeout(() => {
        if (stealthState._stealthScanActive && stealthState._stealthScanWs === null) reconnect();
    }, RECONNECT_DELAY_MS);
}

function liveStatusElement(_context) {
    let element = byId('stealth-live-status');
    if (element) return element;
    element = document.createElement('div');
    element.id = 'stealth-live-status';
    element.classList.add('stealth-live-status');
    const scanStatus = byId('stealth-scan-status');
    if (scanStatus && scanStatus.parentNode) {
        scanStatus.parentNode.insertBefore(element, scanStatus.nextSibling);
    }
    return element;
}

function isBlockAddedNotification(data) {
    if (data.length < 4) return false;
    const position = data[0] === 0x01 ? 9 : 1;
    return position < data.length && data[position] === 0xFF && data[position + 2] === 0x3C;
}

function extractCandidates(data) {
    const candidates = [];
    for (let offset = 0; offset + 66 <= data.length; offset++) {
        if (!hasKstlSubnetwork(data, offset) || !hasAnnouncementPayload(data, offset)) continue;
        const candidate = bytesToHex(data.slice(offset + 33, offset + 65));
        if (!/^0+$/.test(candidate)) candidates.push(candidate);
    }
    return candidates;
}

function hasKstlSubnetwork(data, offset) {
    if (data[offset] !== 0x4b || data[offset + 1] !== 0x53 ||
        data[offset + 2] !== 0x54 || data[offset + 3] !== 0x4c) return false;
    for (let index = 4; index < 20; index++) {
        if (data[offset + index] !== 0) return false;
    }
    return true;
}

function hasAnnouncementPayload(data, offset) {
    return data[offset + 28] === KSTL_PAYLOAD_LENGTH &&
        data[offset + 29] === 0 && data[offset + 30] === 0 && data[offset + 31] === 0 &&
        data[offset + 32] === 0x01;
}

function appendCandidates(candidates) {
    let added = 0;
    for (const candidate of candidates) {
        if (stealthState.stealthAnnouncementsR.includes(candidate)) continue;
        if (stealthState.stealthAnnouncementsR.length >= STEALTH_MAX_R) {
            byId('stealth-scan-status').textContent =
                'R list full (' + STEALTH_MAX_R +
                '). New payments are NOT being recorded — process the current batch first.';
            break;
        }
        stealthState.stealthAnnouncementsR.push(candidate);
        added++;
    }
    return added;
}

function updateCandidateControls() {
    const list = byId('stealth-r-list');
    if (list) list.textContent = stealthState.stealthAnnouncementsR.length + ' R value(s) loaded';
    byId('btn-stealth-show-scan-qr').classList.remove('hidden');
}
