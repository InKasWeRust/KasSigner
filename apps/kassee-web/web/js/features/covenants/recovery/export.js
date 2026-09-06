import { covenantState, walletSession } from '../../../app/state/index.js';
import { toast } from '../../../core/ui/toast.js';
import { buildBeneficiaryExport } from './export/beneficiary_payload.js';
import { buildOwnerExport } from './export/owner_payload.js';
import { showCovenantExportModal } from './export/modal.js';


export async function covExportSingle(index) {
    const covenant = covenantState.activeCovenants[index];
    if (!covenant) return toast('Covenant not found', 'error');
    if (!walletSession.hasWallet()) return toast('Load wallet first', 'error');
    if (covenant.role !== 'owner' && covenant.role !== 'beneficiary') {
        return toast('Covenant role is missing; re-import the current backup format', 'error');
    }

    try {
        const payload = covenant.role === 'owner'
            ? await buildOwnerExport(covenant, walletSession.kpub())
            : buildBeneficiaryExport(covenant);
        console.log(`[KasSee] Covenant export: ${payload.bytes.length} bytes, type: ${covenant.type}`);
        showCovenantExportModal(covenant, payload);
    } catch (error) {
        toast(`Export failed: ${error.message}`, 'error');
        console.error('[KasSee] Export error:', error);
    }
}
