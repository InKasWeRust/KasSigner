import { decodeQrImageFile } from '../../../core/qr/image_file.js';
import { byId } from '../../../core/dom.js';
import { toast } from '../../../core/ui/toast.js';
import { reset_qr_decoder } from '../../../wasm/api.js';
import { handleSignedScan } from './broadcast.js';

let imageDecoderSessionActive = false;

function qrPayloadBytes(code) {
    if (!code) throw new Error('No QR code was found in the selected image');
    if (code.binaryData && code.binaryData.length > 0) {
        return new Uint8Array(code.binaryData);
    }
    if (typeof code.data === 'string' && code.data.length > 0) {
        return new TextEncoder().encode(code.data);
    }
    throw new Error('The QR image has no readable payload');
}

function resetDecoder() {
    try { reset_qr_decoder(); } catch (_) {}
}

export function resetSignedQrImageImportSession() {
    imageDecoderSessionActive = false;
    resetDecoder();
    const status = byId('broadcast-image-status');
    if (status) status.textContent = '';
}

export async function importSignedQrImage(file) {
    const status = byId('broadcast-image-status');
    try {
        if (!imageDecoderSessionActive) {
            resetDecoder();
            imageDecoderSessionActive = true;
        }
        if (status) status.textContent = 'Reading QR image...';
        const code = await decodeQrImageFile(file);
        const complete = handleSignedScan(qrPayloadBytes(code), {
            progressTargetId: 'broadcast-image-status',
            stopCamera: false,
            showDecodeErrors: true,
        });
        if (complete !== false) {
            imageDecoderSessionActive = false;
            resetDecoder();
        }
        return complete;
    } catch (error) {
        imageDecoderSessionActive = false;
        resetDecoder();
        if (status) status.textContent = 'QR image import failed';
        toast('Signed QR image import failed: ' + error.message, 'error', 5000);
        return null;
    }
}
