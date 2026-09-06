import { showScreen } from '../../../../app/navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel, getAccountPubkeyHex } from '../../generation/ui_and_keys.js';
import { decryptCovenantPayload } from '../../payload_and_swaps/payload.js';
import { covRenderActive, covSaveActive } from '../active.js';
import { rebuildCovenant } from '../scanner.js';

export async function importOwnerBackup(hex) {
    const decrypted = await decryptCovenantPayload(hex.slice(8));
    if (!decrypted) throw new Error('Decrypt failed. wrong wallet?');

    const rebuilt = await rebuildCovenant(decrypted, getAccountPubkeyHex());
    showScreen('covenant');
    covShowPanel('menu');
    covSaveActive();
    covRenderActive();
    toast(rebuilt ? 'Covenant restored' : 'Covenant already active', 'ok', rebuilt ? 3000 : 2000);
    return rebuilt;
}
