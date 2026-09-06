import { covenantState, navigationState } from '../../../../state/index.js';
import { byId } from '../../../../../core/dom.js';
import { toast } from '../../../../../core/ui/toast.js';
import { hideLoading, showLoading, showScreen } from '../../../../navigation.js';
import { covShowPanel } from '../../../../../features/covenants/generation/ui_and_keys.js';
import { getCovFee, ownerReceiveAddr } from '../../../../../features/covenants/payload_and_swaps/state.js';
import { handleEscrowSpend } from '../../../../../features/covenants/spending/standard/shipment.js';
import { handleCovOwnerSpend } from '../../../../../features/covenants/spending/standard/thread_and_claims.js';
import { openPsktReview } from '../../../../../features/transactions/pskt_multisig/review.js';
import { openUtxoPicker, updateConsolSummary } from '../utxo_picker.js';
import { buildSelectedSpend } from './build.js';
import { CovenantSpendPolicyError, ownerSpendBranch } from './policy.js';
import { selectedUtxos, setAllSelected } from './selection.js';

function ownerDestination() {
    return (byId('cov-owner-dest')?.value.trim() || '') || ownerReceiveAddr();
}

function openResultPanel() {
    showScreen('covenant');
    covShowPanel('result');
}

async function openResultActionPicker() {
    const result = covenantState.lastCovenantResult;
    if (result?.type === 'escrow') {
        const branch = result.role === 'beneficiary' ? 'seller-dispute' : 'buyer-dispute';
        await handleEscrowSpend(branch);
        return;
    }
    openUtxoPicker(result?.address || '');
}

async function createSelectedSpend() {
    const result = covenantState.lastCovenantResult;
    if (!result) {
        toast('No covenant loaded', 'error');
        return;
    }

    const selected = selectedUtxos();
    if (selected.length < 1) {
        toast('Select at least 1 UTXO', 'error');
        return;
    }
    const destination = byId('cov-consol-dest').value.trim();
    if (!destination) {
        toast('Enter a destination address', 'error');
        return;
    }
    const isConsolidate = destination === result.address;
    if (isConsolidate && selected.length < 2) {
        toast('Select at least 2 UTXOs to consolidate', 'error');
        return;
    }

    const operation = isConsolidate ? 'Consolidation' : 'Withdrawal';
    showLoading(`Building ${operation.toLowerCase()} TX...`);
    try {
        covenantState._covPayloadHex = '';
        const fee = getCovFee(selected.length);
        const ownerBranch = await ownerSpendBranch({ isConsolidate, selected, fee });
        const pskbHex = buildSelectedSpend({ destination, selected, fee, ownerBranch });
        hideLoading();
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
        showScreen('pskt-review');
    } catch (error) {
        hideLoading();
        if (error instanceof CovenantSpendPolicyError) {
            toast(error.message, 'error', error.duration);
        } else {
            toast(`${operation} error: ${error}`, 'error', 5000);
        }
    }
}

export function registerWithdrawalAndConsolidation() {
    const ownerCreate = byId('btn-cov-owner-create');
    if (ownerCreate) ownerCreate.onclick = () => handleCovOwnerSpend();

    const ownerConsolidate = byId('btn-cov-owner-consolidate');
    if (ownerConsolidate) ownerConsolidate.onclick = () => openUtxoPicker(ownerDestination());

    const resultConsolidate = byId('btn-cov-res-consolidate');
    if (resultConsolidate) resultConsolidate.onclick = () => openResultActionPicker();

    byId('btn-consol-select-all').onclick = () => { setAllSelected(true); updateConsolSummary(); };
    byId('btn-consol-select-none').onclick = () => { setAllSelected(false); updateConsolSummary(); };
    byId('btn-consol-back').onclick = openResultPanel;
    byId('btn-consol-create').onclick = () => createSelectedSpend();
}
