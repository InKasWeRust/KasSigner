import { covenantState, navigationState, networkState } from '../../../app/state/index.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import { openSendScreen, setFeeLevel, toggleSendUtxos, updateFeeCardAmounts } from '../../transactions/send/compose/send_form.js';
import { fetch_utxos_for_address_js } from '../../../wasm/api.js';
// KasSee Web — features/covenants/generation/fund
import { byId } from '../../../core/dom.js';


export async function handleCovFund() {
    if (!covenantState.lastCovenantResult) { toast('No covenant address', 'error'); return; }
    if (covenantState.lastCovenantResult.type === 'oracle-v1'
        && !/^[0-9a-f]{64}$/.test(covenantState.lastCovenantResult.oracle_covenant_binding_token_hex || '')) {
        toast('Bind the isolated Oracle covenant key to this exact script before funding', 'error', 4500);
        return;
    }
    // Piggy bank "Add Funds" routes through the same funding (Send) screen as the
    // first deposit: UTXO picker + amount + a send fee that scales with inputs.
    // (The old borrower-merge panel had no picker and a flat fee that under-paid
    // multi-input merges.) A plain deposit adds another covenant UTXO; the additive
    // script breaks a multi-UTXO piggy fine (the goal check reads output[0], the
    // swept total, for any input count). So Add Funds falls through to openSendScreen.
    navigationState._broadcastReturnScreen = 'covenant';
    await openSendScreen();
    byId('input-dest').value = covenantState.lastCovenantResult.address;
    updateFeeCardAmounts();
    setFeeLevel('normal');
    // Thread covenants (single-thread, covenant_id-bound) full-spend the chosen
    // wallet UTXO(s) into the thread: the amount is bypassed, the whole UTXO is
    // used. So drop the misleading amount field and surface the UTXO picker so
    // the user just chooses which UTXO(s) to fund/fold in.
    const _ft = covenantState.lastCovenantResult.type;
    const _isThreadType = (_ft === 'global-allowance' || _ft === 'global-spending-limit');
    // Only a TOP-UP (the covenant address already holds the thread) needs the
    // whole-UTXO fold. Initial funding (genesis, empty address) behaves like a
    // normal covenant deposit: amount field + optional picker + change.
    let _isThreadTopup = false;
    if (_isThreadType) {
        try {
            const _wsTF = await resolveNodeUrl();
            const _covTF = JSON.parse(await fetch_utxos_for_address_js(covenantState.lastCovenantResult.address, _wsTF));
            _isThreadTopup = Array.isArray(_covTF) && _covTF.length > 0;
        } catch (_) { _isThreadTopup = false; }
    }
    if (_isThreadType && _isThreadTopup) {
        const aw = byId('send-amount-wrap');
        if (aw) aw.style.display = 'none';
        const list = byId('send-utxo-list');
        if (list && list.style.display === 'none' && networkState.cachedUtxos && networkState.cachedUtxos.length) {
            toggleSendUtxos(); // expand the picker now that UTXOs are loaded
        }
        const tg = byId('btn-toggle-utxos');
        if (tg) tg.textContent = 'Select UTXO(s) to fold into the thread ▾';
        toast('Top-up: pick the UTXO(s) to fold into the thread (whole UTXOs, no change).', 'info', 4000);
    } else if (_ft === 'additive' || _ft === 'timelocked-savings' || _ft === 'dms' || _isThreadType) {
        // Piggy / savings / DMS deposit: keep the amount field (partial deposits
        // allowed) and leave the UTXO picker collapsed on load. The user opens it to
        // pick which UTXOs to deposit from; a dust-sized change folds into the deposit
        // (KIP-9 safe). For savings and DMS, picking UTXOs also engages the
        // payload-aware deposit fee (the deposit carries the encrypted recovery
        // payload, which the plain send fee does not price in).
        // Initial funding of a thread covenant (genesis) also lands here. Only then
        // force the amount field visible (a prior top-up render may have hidden it);
        // savings/DMS funding is left exactly as before.
        if (_isThreadType) { const aw = byId('send-amount-wrap'); if (aw) aw.style.display = ''; }
        const list = byId('send-utxo-list');
        if (list && list.style.display !== 'none') {
            toggleSendUtxos(); // collapse if a prior state left it open
        }
        const tg = byId('btn-toggle-utxos');
        if (tg) tg.textContent = 'Select UTXO(s) to deposit ▸';
        toast('Open the UTXO picker and choose what to deposit. A dust-sized change is folded into the deposit.', 'info', 4000);
    } else {
        toast('Sending to covenant address', 'info', 2000);
    }
}
