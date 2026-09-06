import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { covenantState, networkState, oracleState, transactionState, walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { sompiToKasString } from '../../../core/amounts.js';
import { exactUnsigned } from '../../../core/exact.js';
import { pskt_summary } from '../../../wasm/api.js';
// KasSee Web — features/transactions/pskt_multisig/review
import { bytesToHex, hexToBytes } from '../../../core/bytes.js';
import { byId } from '../../../core/dom.js';
import { createPsktReviewActions } from './review_actions.js';
import { releasePendingStandardChange, standardChangeReservationMatchesSummary } from '../../wallet/core.js';

import { emphasizeAddress, shortenHex } from '../../../core/format.js';

export const {
    openRelayModal,
    closeRelayModal,
    handlePsktRelay,
    handlePsktRelayKasSignerStandard,
    handlePsktRelayCompact,
    handlePsktFinalize,
} = createPsktReviewActions();

// ─── PSKT / PSKB Review ───
//
// When a scan or paste yields a PSKB/PSKT envelope, we open a review
// screen showing inputs, outputs, fee, and multisig progress (M/N).
// From there the user can:
//   - Relay to next signer  (re-emit identical QR for the next device)
//   - Finalize + broadcast  (when all inputs meet their sig threshold)

// Stash the hex for the current review so both buttons can access it
// without re-parsing.
transactionState._psktReviewHex = null;

transactionState._lastPsktSummary = null;
transactionState._psktReviewContext = null;

function psktBodyKey(summary) {
    return JSON.stringify({
        txVersion: summary.tx_version,
        inputs: (summary.inputs || []).map(input => [
            input.prev_tx_id,
            input.prev_index,
            String(input.amount_sompi),
            input.script_hex || '',
        ]),
        outputs: (summary.outputs || []).map(output => [
            String(output.amount_sompi),
            output.script_hex || '',
            output.address || '',
        ]),
    });
}

function resolveReviewContext(summary, requestedContext) {
    const bodyKey = psktBodyKey(summary);
    if (requestedContext) {
        const context = { ...requestedContext, bodyKey };
        transactionState._psktReviewContext = context;
        return context;
    }
    const context = transactionState._psktReviewContext;
    if (context?.bodyKey === bodyKey) return context;
    transactionState._psktReviewContext = null;
    return null;
}

function classifyWalletOutput(output, reviewContext) {
    const address = output?.address || '';
    if (reviewContext?.kind === 'multisig-send') {
        if (address && address === reviewContext.destinationAddress) return 'DESTINATION';
        return 'MULTISIG CHANGE';
    }
    if (!address || !walletSession.hasWallet()) return 'DESTINATION';
    const wallet = walletSession.current();
    if (wallet.change_addresses?.includes(address)) return 'CHANGE';
    if (wallet.receive_addresses?.includes(address)) return 'OWN RECEIVE';
    return 'DESTINATION';
}

function reviewOwnershipTotals(outputs, reviewContext) {
    let external = 0n;
    let change = 0n;
    let ownReceive = 0n;
    for (const output of outputs) {
        const amount = exactUnsigned(output.amount_sompi, 'review output amount');
        const ownership = classifyWalletOutput(output, reviewContext);
        if (ownership === 'CHANGE' || ownership === 'MULTISIG CHANGE') change += amount;
        else if (ownership === 'OWN RECEIVE') ownReceive += amount;
        else external += amount;
    }
    return { external, change, ownReceive };
}

export function openPsktReview(wireHex, requestedContext = null) {
    transactionState._psktReviewHex = wireHex;
    // A newly opened canonical PSKT/PSKB has no device-returned relay payload yet.
    // The signed-scan merge path sets this immediately after a successful merge.
    transactionState._lastKasSignerKsptHex = null;
    oracleState._oracleMbRollActive = false;   // cleared on every load; the oracle path re-arms it right after this call
    oracleState._oracleMbReturn = false;       // clear any stale "return to oracle card" flag; only a roll's success path re-sets it

    let summary;
    try {
        summary = JSON.parse(pskt_summary(wireHex, networkState.network));
    } catch (e) {
        console.error('[KasSee] PSKT parse error:', e);
        toast('Could not parse PSKT: ' + e, 'error', 5000);
        return;
    }

    console.log('[KasSee] PSKT summary:', summary);
    const reservedIndex = transactionState._standardChangeReservationIndex;
    if (Number.isSafeInteger(reservedIndex)
        && !standardChangeReservationMatchesSummary(reservedIndex, summary)) {
        releasePendingStandardChange(reservedIndex);
        transactionState._standardChangeReservationIndex = null;
    }
    transactionState._lastPsktSummary = summary;
    const reviewContext = resolveReviewContext(summary, requestedContext);

    // Render header
    byId('pskt-format').textContent = summary.format.toUpperCase();
    byId('pskt-tx-version').textContent = summary.tx_version;
    byId('pskt-in-count').textContent = summary.input_count;
    byId('pskt-out-count').textContent = summary.output_count;
    byId('pskt-fee').textContent = sompiToKasString(summary.fee_sompi);
    byId('pskt-total-in').textContent = sompiToKasString(summary.total_in_sompi);
    byId('pskt-total-out').textContent = sompiToKasString(summary.total_out_sompi);
    const outputs = summary.outputs || [];
    const ownershipTotals = reviewOwnershipTotals(outputs, reviewContext);
    byId('pskt-send-total').textContent = sompiToKasString(ownershipTotals.external);
    byId('pskt-change-total').textContent = sompiToKasString(ownershipTotals.change);

    const externalOutputs = outputs.filter(output => classifyWalletOutput(output, reviewContext) === 'DESTINATION');
    const toAddressEl = byId('pskt-to-address');
    if (externalOutputs.length === 1 && externalOutputs[0].address) {
        toAddressEl.textContent = externalOutputs[0].address;
    } else if (externalOutputs.length > 1) {
        toAddressEl.textContent = `${externalOutputs.length} destinations — Inspect to view`;
    } else {
        toAddressEl.textContent = 'No external address — Inspect to view';
    }

    const inspectButton = byId('btn-pskt-inspect');
    const inspectDetails = byId('pskt-inspect-details');
    inspectDetails.classList.add('hidden');
    inspectButton.textContent = 'Inspect';
    inspectButton.setAttribute('aria-expanded', 'false');
    inspectButton.onclick = () => {
        const opening = inspectDetails.classList.contains('hidden');
        inspectDetails.classList.toggle('hidden', !opening);
        inspectButton.textContent = opening ? 'Hide details' : 'Inspect';
        inspectButton.setAttribute('aria-expanded', opening ? 'true' : 'false');
    };

    // Payload verification hash: if covenant payload exists, show SHA-256[..8]
    // User compares this with KasSigner's "PL xxxxxxxx" on its review screen.
    const plHashEl = byId('pskt-payload-hash');
    if (plHashEl) {
        if (covenantState._covPayloadHex && covenantState._covPayloadHex.length > 0) {
            const plBytes = hexToBytes(covenantState._covPayloadHex);
            crypto.subtle.digest('SHA-256', plBytes.buffer).then(hashBuf => {
                const h = bytesToHex(new Uint8Array(hashBuf).slice(0, 8));
                plHashEl.textContent = 'PL ' + h;
                plHashEl.style.display = '';
            });
        } else {
            plHashEl.textContent = '';
            plHashEl.style.display = 'none';
        }
    }

    // Inputs list
    const inputsEl = byId('pskt-inputs');
    inputsEl.innerHTML = '';
    summary.inputs.forEach((inp, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        let sigLabel;
        if (inp.multisig_m !== null && inp.multisig_m !== undefined) {
            const ok = inp.sigs_present >= inp.multisig_m;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present}/${inp.multisig_m}-of-${inp.multisig_n}</span>`;
        } else {
            const ok = inp.sigs_present >= 1;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present} sig${inp.sigs_present === 1 ? '' : 's'}</span>`;
        }
        setSafeMarkup(row, `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${inp.script_kind.toUpperCase()}</span>
                ${sigLabel}
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${sompiToKasString(inp.amount_sompi)} KAS</div>
                <div class="pskt-label">Prev TX</div>
                <div class="pskt-value pskt-mono">${shortenHex(inp.prev_tx_id)}:${inp.prev_index}</div>
            </div>
        `);
        inputsEl.appendChild(row);
    });

    // Outputs list
    const outputsEl = byId('pskt-outputs');
    outputsEl.innerHTML = '';
    summary.outputs.forEach((out, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        const ownership = classifyWalletOutput(out, reviewContext);
        setSafeMarkup(row, `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${ownership} · ${out.script_kind.toUpperCase()}</span>
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${sompiToKasString(out.amount_sompi)} KAS</div>
                <div class="pskt-label">To</div>
                <div class="pskt-value pskt-mono">${out.address ? emphasizeAddress(out.address) : '(unrecognized script)'}</div>
            </div>
        `);
        outputsEl.appendChild(row);
    });

    // Enable/disable Finalize button based on readiness
    const btnFinalize = byId('btn-pskt-finalize');
    btnFinalize.disabled = !summary.finalize_ready;
    btnFinalize.textContent = summary.finalize_ready
        ? 'Finalize + broadcast'
        : 'Needs more signatures';

    showScreen('pskt-review');
    return summary;
}
/// PSKB (any wallet) or compact KSPT v4 (KasSigner devices only).
