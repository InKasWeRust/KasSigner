import { covenantState, navigationState, networkState, transactionState, walletSession } from '../../../../../app/state/index.js';
import { COVENANT_TYPE_CODES } from '../../../../covenants/payload_and_swaps/types.js';
import { hideLoading } from '../../../../../app/navigation.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { encryptCovenantPayload } from '../../../../covenants/payload_and_swaps/payload.js';
import { pickThread } from '../../../../covenants/spending/standard/thread_and_claims.js';
import { openPsktReview } from '../../../pskt_multisig/review.js';
import { withNodeRetry } from '../../../../wallet/core.js';
import {
    create_covenant_pskb,
    create_covenant_pskb_with_payload,
    create_global_allowance_topup,
    create_global_spending_limit_topup,
    estimate_covenant_fee,
    fetch_utxos_for_address_js,
} from '../../../../../wasm/api.js';
import { kasToSompi } from '../../../../../core/amounts.js';
import { exactJsonStringify, exactUnsigned } from '../../../../../core/exact.js';
import { normalizeUtxos } from '../../../../../core/utxo.js';
import { selectedUtxoIndices } from '../../../shared/utxo_selection.js';

// Browser adapter only: covenant monetary policy and fee arithmetic live in
// transaction_builder::covenant. This module supplies UI intent, selected UTXO
// indices, node data and presentation routing.

function selectedIndices() {
    return selectedUtxoIndices(networkState.cachedUtxos || [], transactionState.selectedUtxoIds);
}

function threadRedeemScript(destination) {
    const stored = covenantState.activeCovenants.find(covenant => covenant.address === destination);
    return stored?.redeem_script_hex || covenantState.lastCovenantResult.redeem_script_hex || '';
}

function coreFee({p2pkInputs = 0, redeemBytes = 0, payloadBytes = 0, bindingBytes = 0} = {}) {
    return estimate_covenant_fee(p2pkInputs, redeemBytes, payloadBytes, bindingBytes);
}

async function buildThreadTopUp(destination, covenantUtxos) {
    const indices = selectedIndices();
    if (!indices.length) {
        hideLoading();
        toast('Pick the wallet UTXOs to add, then Deposit. Top-up folds whole UTXOs into the thread (no change).', 'error', 5000);
        return null;
    }
    const selected = pickThread(covenantUtxos, covenantState.lastCovenantResult?.covenant_id_hex);
    if (!selected.thread) {
        hideLoading();
        toast(
            selected.ambiguous
                ? 'Multiple covenant-tagged UTXOs and no known thread id, cannot safely pick the thread.'
                : 'Thread covenant_id unavailable from the node (need version-2 UTXO entries).',
            'error',
            6500,
        );
        return null;
    }
    const isAllowance = covenantState.lastCovenantResult.type === 'global-allowance';
    const redeem = threadRedeemScript(destination);
    const fee = coreFee({p2pkInputs: indices.length, redeemBytes: redeem.length / 2, bindingBytes: 32});
    const pskbHex = await withNodeRetry(wsUrl => {
        const request = JSON.stringify({
            wallet_json: walletSession.json(),
            covenant_address: destination,
            redeem_script_hex: redeem,
            covenant_id_hex: selected.thread.covenant_id || '',
            thread_utxo_json: exactJsonStringify(selected.thread),
            fee,
            utxo_indices_csv: indices.join(','),
            ws_url: wsUrl,
        });
        return isAllowance
            ? create_global_allowance_topup(request)
            : create_global_spending_limit_topup(request);
    });
    hideLoading();
    console.log(`[KasSee] ${isAllowance ? 'Global allowance' : 'Global limit'} TOP-UP: folding ${indices.length} wallet UTXO(s) into the thread, pskb=${pskbHex.length} chars`);
    covenantState._covPayloadHex = '';
    navigationState._broadcastReturnScreen = 'covenant';
    openPsktReview(pskbHex);
    return {pskbHex: null, completed: true};
}

async function routeGlobalThread(destination, initialAmount) {
    const covenantType = covenantState.lastCovenantResult.type || '';
    if (!['global-spending-limit', 'global-allowance'].includes(covenantType)) {
        return {amountSompi: initialAmount, completed: false};
    }
    const wsUrl = await resolveNodeUrl();
    const covenantUtxos = normalizeUtxos(JSON.parse(await fetch_utxos_for_address_js(destination, wsUrl)));
    if (covenantUtxos.length) {
        return {result: await buildThreadTopUp(destination, covenantUtxos), completed: true};
    }
    return {amountSompi: initialAmount, completed: false};
}

async function encryptedRecoveryPayload() {
    const covenantType = covenantState.lastCovenantResult.type || 'unknown';
    try {
        if (COVENANT_TYPE_CODES[covenantType]) {
            const payload = await encryptCovenantPayload(covenantType, covenantState.lastCovenantResult);
            console.log(`[KasSee] Encrypted covenant payload: ${payload.length / 2} bytes for type ${covenantType}`);
            return payload;
        }
    } catch (error) {
        console.warn('[KasSee] Covenant payload encryption failed, proceeding without:', error);
    }
    return '';
}

async function createDepositPskb(options) {
    const {destination, amountSompi, fee, changeAddress, utxoCsv, payloadHex} = options;
    const covenantType = covenantState.lastCovenantResult.type || '';
    const tagGenesis = ['global-spending-limit', 'global-allowance'].includes(covenantType);
    const request = {
        wallet_json: walletSession.json(),
        covenant_address: destination,
        covenant_type: covenantType,
        send_amount: amountSompi.toString(),
        fee: exactUnsigned(fee, 'fee').toString(),
        change_address: changeAddress,
        utxo_indices_csv: utxoCsv,
    };
    if (payloadHex) {
        return withNodeRetry(wsUrl => create_covenant_pskb_with_payload(JSON.stringify({
            ...request,
            payload_hex: payloadHex,
            ws_url: wsUrl,
            tag_genesis: tagGenesis,
        })));
    }
    return withNodeRetry(wsUrl => create_covenant_pskb(JSON.stringify({...request, ws_url: wsUrl})));
}

export async function planCovenant(destination, amountString, fee) {
    const wallet = walletSession.current();
    const changeAddress = wallet.change_addresses[wallet.next_change_index || 0];
    const indices = selectedIndices();
    if (!indices.length) {
        hideLoading();
        toast('Pick the wallet UTXOs to fund this covenant, then Deposit.', 'error', 5000);
        return null;
    }
    const utxoCsv = indices.length ? indices.join(',') : '';
    const amountSompi = kasToSompi(amountString);

    const thread = await routeGlobalThread(destination, amountSompi);
    if (thread.completed) return thread.result;

    const payloadHex = await encryptedRecoveryPayload();
    covenantState._covPayloadHex = payloadHex;
    const pskbHex = await createDepositPskb({
        destination,
        amountSompi: thread.amountSompi,
        fee,
        changeAddress,
        utxoCsv,
        payloadHex,
    });
    return {pskbHex, completed: false};
}
