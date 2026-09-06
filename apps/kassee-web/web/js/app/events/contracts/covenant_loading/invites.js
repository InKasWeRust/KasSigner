import { covenantRecoveryState } from '../../../state/index.js';
import { showScreen } from '../../../navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { handleCovbScan } from '../../../../features/covenants/recovery/import.js';
import { startScanner, stopScanner } from '../../../../features/stealth/index/camera.js';
import { byId } from '../../../../core/dom.js';

export function bindInviteLoadingActions() {
    byId('btn-cov-load-back').onclick = () => covShowPanel('menu');
    // Scan covenant invite QR on Load Existing panel
    if (byId('btn-cov-load-scan')) {
        byId('btn-cov-load-scan').onclick = () => {
            startScanner('Scan Covenant Invite QR', async (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || (invite.t !== 'cov-invite' && invite.t !== 'swap-invite')) {
                        toast('Not a covenant invite QR', 'error'); return;
                    }
                    // Fill the load form
                    if (invite.addr) byId('cov-load-addr').value = invite.addr;
                    if (invite.rs) byId('cov-load-script').value = invite.rs;
                    if (invite.ct) byId('cov-load-type').value = invite.ct;
                    stopScanner();


                    showScreen('covenant');
                    covShowPanel('load');
                    covenantRecoveryState._covLoadedFromInvite = true;
                    if (invite.id) covenantRecoveryState._covLoadedInactivityDaa = invite.id;
                    if (invite.ldi) covenantRecoveryState._covLoadedLdi = invite.ldi;
                    toast('Invite scanned. Tap Load Covenant.', 'ok', 2000);
                } catch (e) {
                    toast('Invalid invite QR: ' + e, 'error');
                }
            }, 'load');
        };
    }
    // Load covenant from backup file (.covb or .cov)
    if (byId('btn-cov-load-file')) {
        byId('btn-cov-load-file').onclick = () => byId('cov-load-file-input').click();
        byId('cov-load-file-input').onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            try {
                const buf = await file.arrayBuffer();
                const bytes = new Uint8Array(buf);
                await handleCovbScan(bytes);
            } catch (err) {
                toast('File import failed: ' + (err.message || err), 'error');
            }
            e.target.value = ''; // reset so same file can be re-imported
        };
    }
}
