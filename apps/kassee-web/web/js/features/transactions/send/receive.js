import { walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { getNextReceiveIndex } from '../../wallet/core.js';
import { generate_qr_frames } from '../../../wasm/api.js';
// KasSee Web — features/transactions/send/receive
import { utf8ToHex } from '../../../core/bytes.js';
import { byId } from '../../../core/dom.js';


// ─── Receive ───

export function showReceive() {
    if (!walletSession.hasWallet()) return;
    const wallet = walletSession.current();

    const addrIdx = getNextReceiveIndex();

    const addr = wallet.receive_addresses[addrIdx];
    try {
        const frames = JSON.parse(generate_qr_frames(utf8ToHex(addr)));
        byId('receive-qr').innerHTML = frames[0].svg;
    } catch (e) {
        byId('receive-qr').innerHTML = '';
    }
    byId('receive-address').textContent = addr;
    showScreen('receive');
}
export function copyAddress() {
    const addr = byId('receive-address').textContent;
    navigator.clipboard.writeText(addr).then(() => {
        byId('btn-copy-address').textContent = 'Copied!';
        setTimeout(() => { byId('btn-copy-address').textContent = 'Copy Address'; }, 1600);
    });
}
