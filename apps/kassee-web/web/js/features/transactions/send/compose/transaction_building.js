import { networkState, transactionState } from '../../../../app/state/index.js';
import { KNS_LOOKUP } from '../../../../core/config/services.js';
import { hideLoading, showLoading, showScreen } from '../../../../app/navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { stopScanner } from '../../../stealth/index/camera.js';
import { openPsktReview } from '../../pskt_multisig/review.js';
import { syncThreadDepositAmount } from './send_form.js';
import { reserveStandardChangeFromSummary, walletWithFreshIndices } from '../../../wallet/core.js';
// KasSee Web — features/transactions/send/compose/transaction_building
import { byId } from '../../../../core/dom.js';
import { kasToSompi } from '../../../../core/amounts.js';
import { exactUnsigned } from '../../../../core/exact.js';
import { addressPrefix } from '../../../../core/network.js';
import { planTransaction } from './planners/index.js';




export function assertStandardSendIntent(summary, walletJson, destination, amountSompi, feeSompi) {
    let wallet;
    try { wallet = JSON.parse(walletJson); } catch (_) { throw new Error('Wallet state could not be verified'); }
    const outputs = summary?.outputs || [];
    const amount = exactUnsigned(amountSompi, 'send amount');
    const fee = exactUnsigned(feeSompi, 'send fee');
    const totalIn = exactUnsigned(summary?.total_in_sompi, 'transaction input total');
    const summaryFee = exactUnsigned(summary?.fee_sompi, 'transaction fee');
    if (summaryFee !== fee) throw new Error('Built transaction fee does not match the requested fee');

    const destinationOutputs = outputs.filter(output => {
        const branch = output.derivation_branch === null || output.derivation_branch === undefined
            ? null : Number(output.derivation_branch);
        return output.address === destination
            && exactUnsigned(output.amount_sompi, 'destination amount') === amount
            && branch !== 1;
    });
    if (destinationOutputs.length !== 1) {
        throw new Error('Built transaction does not contain the exact requested destination payment');
    }

    const expectedChange = totalIn - amount - fee;
    if (expectedChange < 0n) throw new Error('Built transaction spends more than its inputs');
    const changeIndex = Number(wallet?.next_change_index);
    const changeAddress = wallet?.change_addresses?.[changeIndex];
    const changeOutputs = outputs.filter(output => Number(output.derivation_branch) === 1);
    if (expectedChange === 0n) {
        if (changeOutputs.length !== 0 || outputs.length !== 1) {
            throw new Error('Built transaction contains an unexpected change output');
        }
        return;
    }
    if (!Number.isSafeInteger(changeIndex) || changeIndex < 0 || !changeAddress) {
        throw new Error('Expected change address is unavailable');
    }
    const exactChange = changeOutputs.filter(output =>
        Number(output.derivation_index) === changeIndex
        && output.address === changeAddress
        && exactUnsigned(output.amount_sompi, 'change amount') === expectedChange
    );
    if (exactChange.length !== 1 || changeOutputs.length !== 1 || outputs.length !== 2) {
        throw new Error('Built transaction change does not match the reserved wallet address');
    }
}

// ─── Destination QR scan ───

export function handleDestScan(data) {
    const text = typeof data === 'string' ? data : new TextDecoder().decode(new Uint8Array(data));
    const addr = text.trim();
    const expectedPrefix = addressPrefix(networkState.network);
    if ((expectedPrefix && addr.startsWith(expectedPrefix)) || addr.endsWith('.kas')) {
        stopScanner();
        byId('input-dest').value = addr;
        showScreen('send');
        toast('Address scanned', 'ok', 1500);
        return;
    }
    if (/^kaspa(test|dev|sim)?:/.test(addr)) {
        toast(`Address is for a different network. Expected ${expectedPrefix}`, 'error', 3500);
    }
}
// Number / Math.round(x*1e8) loses a sompi on many decimals and all precision
// above ~2^53 sompi. wasm-bindgen marshals the returned BigInt to a Rust u64.
export async function handleCreateTx() {
    let dest = byId('input-dest').value.trim();
    // Thread-covenant deposit: amount field is hidden; ensure it reflects the
    // selected UTXO total before the >0 check (also covers any picker desync).
    syncThreadDepositAmount();
    const amountStr = byId('input-amount').value.trim();
    const feeStr = byId('input-fee').value.trim();

    // KNS resolution: if ends with .kas, look up address
    if (dest.endsWith('.kas')) {
        const resolved = KNS_LOOKUP[dest.toLowerCase()];
        if (resolved) {
            dest = resolved;
            toast('Resolved ' + byId('input-dest').value.trim() + ' → address', 'ok', 2000);
        } else {
            toast('Unknown .kas domain: ' + dest, 'error'); return;
        }
    }

    const expectedPrefix = addressPrefix(networkState.network);
    if (!dest || !dest.startsWith(expectedPrefix)) {
        toast('Enter a valid ' + expectedPrefix + ' address or .kas domain', 'error'); return;
    }
    let amountSompi;
    try { amountSompi = kasToSompi(amountStr); } catch (_) {
        toast('Enter a valid amount with at most 8 decimal places', 'error'); return;
    }
    if (amountSompi <= 0n) {
        toast('Enter an amount > 0', 'error'); return;
    }

    let requestedFee;
    try { requestedFee = exactUnsigned(feeStr || '0', 'fee'); } catch (_) { requestedFee = 0n; }
    const fee = requestedFee < 300000n ? 300000n : requestedFee;
    if (fee.toString() !== feeStr) byId('input-fee').value = fee.toString();
    showLoading('Creating transaction...');
    try {
        const freshWallet = walletWithFreshIndices();

        const plan = await planTransaction({
            destination: dest,
            amountString: amountStr,
            fee,
            freshWallet,
        });
        if (!plan || plan.completed) return;
        const pskbHex = plan.pskbHex;

        hideLoading();
        console.log(`[KasSee] PSKB created: ${pskbHex.length} hex chars`);
        // Route through the existing PSKT review screen — same flow as
        // multisig: Review → Relay (standard PSKB or compact KSPT v4
        // for KasSigner) → Finalize & Broadcast.
        const summary = openPsktReview(pskbHex);
        if (plan.kind === 'standard' && summary) {
            try {
                assertStandardSendIntent(summary, freshWallet, dest, amountSompi, fee);
            } catch (error) {
                transactionState._psktReviewHex = null;
                transactionState._lastPsktSummary = null;
                showScreen('send');
                throw new Error(`Transaction safety check failed: ${error.message || error}`);
            }
            transactionState._standardChangeReservationIndex = reserveStandardChangeFromSummary(
                freshWallet, summary,
            );
            if (exactUnsigned(summary.total_in_sompi, 'transaction input total')
                - amountSompi - fee > 0n
                && !Number.isSafeInteger(transactionState._standardChangeReservationIndex)) {
                transactionState._psktReviewHex = null;
                transactionState._lastPsktSummary = null;
                showScreen('send');
                throw new Error('Transaction safety check failed: change could not be reserved');
            }
        }

    } catch (e) {
        hideLoading();
        toast('TX creation failed: ' + e, 'error', 5000);
        console.error('TX creation failed:', e);
    }
}
