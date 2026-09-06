import { networkState } from '../../../app/state/index.js';
import { addressPrefix } from '../../../core/network.js';
import { showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { startScanner, stopScanner } from '../../stealth/index/camera.js';
import { decode_address, encode_p2pk_address, import_kpub } from '../../../wasm/api.js';

import { byId } from '../../../core/dom.js';

function isActiveNetworkAddress(address) {
    const prefix = addressPrefix(networkState.network);
    return Boolean(prefix) && address.startsWith(prefix);
}

function rejectWrongNetworkAddress(address) {
    if (!address.startsWith('kaspa')) return false;
    if (isActiveNetworkAddress(address)) return false;
    stopScanner();
    showScreen('covenant');
    toast('Address is for a different network than the active wallet', 'error', 3000);
    return true;
}


export function covScanPubkey(fieldId, label, rejectKpub) {
    startScanner(label || 'Scan address or kpub for pubkey', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data)).trim();
        // Resolve the QR to an x-only pubkey, then display it as a network
        // address so the user can verify it against the KasSigner display.
        const finish = (xonly, note) => {
            stopScanner();
            try {
                byId(fieldId).value = encode_p2pk_address(xonly, networkState.network);
            } catch (e) {
                byId(fieldId).value = xonly;
            }
            showScreen('covenant');
            toast(note || 'Address scanned. Verify it matches KasSigner.', 'ok', 1800);
        };
        if (text.startsWith('kaspa')) {
            try {
                const decoded = JSON.parse(decode_address(text));
                if (decoded.payload && decoded.payload.length === 64) {
                    finish(decoded.payload, 'Address scanned. Verify it matches KasSigner.');
                } else {
                    stopScanner(); showScreen('covenant'); toast('Could not extract pubkey', 'error');
                }
            } catch (e) {
                stopScanner(); showScreen('covenant'); toast('Invalid address: ' + e, 'error');
            }
        } else if (text.startsWith('kpub1:')) {
            if (rejectKpub) {
                stopScanner(); showScreen('covenant');
                toast('Scan a single address or x-only, not a kpub', 'error');
                return;
            }
            try {
                const importResult = JSON.parse(import_kpub(text, networkState.network));
                const firstAddr = importResult.receive_addresses[0];
                const decoded = JSON.parse(decode_address(firstAddr));
                if (decoded.payload && decoded.payload.length === 64) {
                    finish(decoded.payload, 'Address from kpub (/0/0). Verify it matches KasSigner.');
                } else {
                    stopScanner(); showScreen('covenant'); toast('Could not derive pubkey from kpub', 'error');
                }
            } catch (e) {
                stopScanner(); showScreen('covenant'); toast('Invalid kpub: ' + e, 'error');
            }
        } else if (/^[0-9a-fA-F]{64}$/.test(text)) {
            // Raw x-only pubkey hex QR: show its address for verification.
            finish(text, 'Address scanned. Verify it matches KasSigner.');
        }
    });
}

export function covScanAddress(fieldId, label, rejectKpub) {
    startScanner(label || 'Scan address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (rejectKpub && addr.startsWith('kpub1:')) {
            stopScanner(); showScreen('covenant');
            toast('Scan an address, not a kpub', 'error');
            return;
        }
        if (!addr.startsWith('kaspa')) {
            stopScanner(); showScreen('covenant');
            toast('Scan a Kaspa address', 'error');
            return;
        }
        if (rejectWrongNetworkAddress(addr)) return;
        try {
            const decoded = JSON.parse(decode_address(addr));
            if (!decoded.payload) throw new Error('Address payload missing');
        } catch (error) {
            stopScanner(); showScreen('covenant');
            toast('Could not decode address', 'error');
            return;
        }
        stopScanner();
        byId(fieldId).value = addr;
        showScreen('covenant');
        toast('Address scanned', 'ok', 1500);
    });
}

export function covScanAddressAppend(textareaId, label) {
    startScanner(label || 'Scan address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (!addr.startsWith('kaspa')) {
            stopScanner(); showScreen('covenant');
            toast('Scan a Kaspa address', 'error');
            return;
        }
        if (rejectWrongNetworkAddress(addr)) return;
        try {
            const decoded = JSON.parse(decode_address(addr));
            if (!decoded.payload) throw new Error('Address payload missing');
        } catch (error) {
            stopScanner(); showScreen('covenant');
            toast('Could not decode address', 'error');
            return;
        }
        stopScanner();
        const ta = byId(textareaId);
        const lines = (ta.value || '').split('\n').map(s => s.trim()).filter(Boolean);
        if (lines.includes(addr)) {
            showScreen('covenant');
            toast('Address already in list', 'ok', 1500);
            return;
        }
        lines.push(addr);
        ta.value = lines.join('\n');
        showScreen('covenant');
        toast('Address added (' + lines.length + ' total)', 'ok', 1500);
    });
}
