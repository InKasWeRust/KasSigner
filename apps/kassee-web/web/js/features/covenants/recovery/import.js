import { scannerState } from '../../../app/state/index.js';
// Covenant backup import façade.
import { handleCovenantScan } from './import/controller.js';

scannerState._covbFrames = null;
scannerState._covbImporting = false;

export function handleCovbScan(data) {
    return handleCovenantScan(data);
}
