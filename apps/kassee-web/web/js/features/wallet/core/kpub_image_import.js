import { decodeQrImageFile } from '../../../core/qr/image_file.js';
import { classifyKpubQrCode } from './kpub_qr_payload.js';

export async function decodeKpubQrImage(file) {
    return classifyKpubQrCode(await decodeQrImageFile(file));
}
