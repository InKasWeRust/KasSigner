import { scannerState, walletSession } from '../../../../app/state/index.js';
import { toast } from '../../../../core/ui/toast.js';
import { stopScanner } from '../../../stealth/index/camera.js';
import { covenantHexFromBytes, covenantKind, normalizeScanBytes } from './formats.js';
import { addCovenantFrame, parseCovenantFrame } from './frames.js';
import { importCovenantInvite } from './invite.js';
import { importOwnerBackup } from './owner_backup.js';

async function processCovenantHex(hex) {
    if (!walletSession.hasWallet()) throw new Error('Load wallet first');
    const kind = covenantKind(hex);
    if (kind === 'invite') return importCovenantInvite(hex);
    if (kind === 'backup') return importOwnerBackup(hex);
    throw new Error('Not a covenant backup QR');
}

async function scanCovenantData(data) {
    const raw = normalizeScanBytes(data);
    const directHex = covenantHexFromBytes(raw);
    if (directHex) {
        stopScanner();
        return processCovenantHex(directHex);
    }

    const frame = parseCovenantFrame(raw);
    if (!frame) throw new Error('Not a covenant backup QR');
    const { state, assembled } = addCovenantFrame(scannerState._covbFrames, frame);
    scannerState._covbFrames = state;
    if (!assembled) return false;

    const assembledHex = covenantHexFromBytes(assembled);
    if (!assembledHex) throw new Error('Assembled covenant backup has an invalid header');
    stopScanner();
    return processCovenantHex(assembledHex);
}

export async function handleCovenantScan(data) {
    if (scannerState._covbImporting) return false;
    scannerState._covbImporting = true;
    try {
        return await scanCovenantData(data);
    } catch (error) {
        scannerState._covbFrames = null;
        const message = error instanceof Error ? error.message : String(error);
        toast(message, 'error');
        console.error('[KasSee] Covenant import failed:', error);
        return false;
    } finally {
        scannerState._covbImporting = false;
    }
}
