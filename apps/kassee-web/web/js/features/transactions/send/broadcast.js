import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { bytesToHex } from '../../../core/bytes.js';
import { covenantState, networkState, oracleState, transactionState } from '../../../app/state/index.js';
import { BROADCAST_ENABLED } from '../../../core/config/runtime.js';
import { oracleMbCardRefresh } from '../../oracle/model_b/controller.js';
import { hideLoading, showLoading, showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { stopScanner } from '../../stealth/index/camera.js';
import { openPsktReview } from '../pskt_multisig/review.js';
import { displayKsptQr } from './review.js';
import { markStandardChangeBroadcast, withNodeRetry } from '../../wallet/core.js';
import { inspectKsptSignatureStatus } from './kspt_status.js';
import { broadcast_signed, decode_qr_frame, decoder_progress, kassigner_sdk_complete, pskt_detect, reset_qr_decoder } from '../../../wasm/api.js';
// KasSee Web — features/transactions/send/broadcast
import { byId } from '../../../core/dom.js';
import { ANTI_KLEPTO_KEEP_SCANNING, processAntiKleptoResponse } from '../anti_klepto/response.js';


// ─── Broadcast ───

export function hideBroadcastResult() {
    const card = byId('broadcast-result');
    card.classList.add('hidden');
    card.className = 'result-card hidden';
    byId('input-signed-hex').value = '';
    // Re-show the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = '';
}
export function showBroadcastSuccess(txId) {
    const reservedIndex = transactionState._standardChangeReservationIndex;
    if (Number.isSafeInteger(reservedIndex)) {
        markStandardChangeBroadcast(reservedIndex);
        transactionState._standardChangeReservationIndex = null;
    }
    oracleState._oracleMbRollActive = false;
    oracleState._oracleMbPreSignAwaiting = false;
    oracleState._oracleMbAutoBroadcast = false;
    const card = byId('broadcast-result');
    card.className = 'result-card success';
    card.classList.remove('hidden');
    byId('broadcast-result-icon').textContent = '';
    byId('broadcast-result-msg').textContent = 'Transaction broadcast!';
    byId('broadcast-result-txid').textContent = txId;
    byId('btn-copy-txid').style.display = 'block';
    byId('btn-broadcast-done').style.display = 'block';
    // Hide the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = 'none';

    // Path C post-broadcast hook: capture tx_id and trigger TX2
    if (covenantState._kasFreezePathCPostBroadcast) {
        const cb = covenantState._kasFreezePathCPostBroadcast;
        covenantState._kasFreezePathCPostBroadcast = null;
        cb(txId);
    }
}
export function showBroadcastError(err) {
    const es = String(err);
    oracleState._oracleMbPreSignAwaiting = false;
    oracleState._oracleMbAutoBroadcast = false;
    // Oracle roll lost the race: someone rolled the singleton first, so the node rejects ours
    // (the oracle/heartbeat UTXOs are already spent, or our tx is an orphan). No funds moved and
    // no fee was charged. Show the free-rider outcome instead of a scary error, and refresh the card.
    if (oracleState._oracleMbRollActive && /already spent|orphan|disallow|already .*mempool/i.test(es)) {
        oracleState._oracleMbRollActive = false;
        showScreen('broadcast');   // the finalize error path does not navigate; make the card visible
        const c = byId('broadcast-result');
        c.className = 'result-card success';
        c.classList.remove('hidden');
        byId('broadcast-result-icon').textContent = '';
        byId('broadcast-result-msg').textContent = 'Someone rolled it first';
        byId('broadcast-result-txid').textContent = "You're now on the fresh price. No fee charged.";
        byId('btn-copy-txid').style.display = 'none';
        byId('btn-broadcast-done').style.display = 'block';
        const formCard = document.querySelector('#screen-broadcast .card');
        if (formCard) formCard.style.display = 'none';
        try { oracleMbCardRefresh(); } catch (_) {}
        return;
    }
    oracleState._oracleMbRollActive = false;
    const card = byId('broadcast-result');
    card.className = 'result-card error';
    card.classList.remove('hidden');
    byId('broadcast-result-icon').textContent = '';
    byId('broadcast-result-msg').textContent = 'Broadcast failed';
    byId('broadcast-result-txid').textContent = es;
    byId('btn-copy-txid').style.display = 'none';
    byId('btn-broadcast-done').style.display = 'block';
}
export function handleSignedScan(data, options = {}) {
    const hexStr = bytesToHex(new Uint8Array(data));
    try {
        let result = decode_qr_frame(hexStr);
        if (result && result.length > 0) {
            const progressTarget = byId(options.progressTargetId || 'scanner-status');
            if (progressTarget) progressTarget.textContent = '';
            console.log('[KasSee] Scan complete: ' + result.length / 2 + ' bytes');

            try {
                result = processAntiKleptoResponse(result);
                if (result === ANTI_KLEPTO_KEEP_SCANNING) {
                    try { reset_qr_decoder(); } catch (_) {}
                    if (progressTarget) progressTarget.textContent = 'Commitment already received — waiting for final KasSigner QR';
                    return false;
                }
                if (options.stopCamera !== false) stopScanner();
                if (result === null) return true;
            } catch (error) {
                if (options.stopCamera !== false) stopScanner();
                console.error('[KasSee] anti-klepto response rejected:', error);
                toast('Anti-klepto verification failed — transaction rejected: ' + error, 'error', 6000);
                return null;
            }

            // First, check for a PSKT or PSKB envelope. Compact KSPT is
            // handled separately below.
            const psktFormat = pskt_detect(result);
            if (psktFormat === 'pskb' || psktFormat === 'pskt') {
                console.log('[KasSee] ' + psktFormat.toUpperCase() + ' detected — opening review');
                openPsktReview(result);
                return true;
            }

            const sigStatus = inspectKsptSignatureStatus(result);

            // Compact-relay return path: if we sent a KSPT v4 to the
            // device via handlePsktRelayCompact, _psktReviewHex still
            // holds the canonical PSKB. Merge the new partial sigs
            // from the KSPT v4 back into the PSKB and re-open review.
            if ((sigStatus === 'partial' || sigStatus === 'signed') && transactionState._psktReviewHex) {
                console.log('[KasSee] KSPT v4 return with canonical PSKB held — merging');
                try {
                    const signed = JSON.parse(kassigner_sdk_complete(
                        transactionState._psktReviewHex,
                        result,
                        networkState.network,
                    ));
                    const mergedSummary = openPsktReview(signed.psktHex);
                    // Preserve the exact compact KSPT emitted by the signer. For the
                    // next KasSigner cosigner, relay these exact bytes instead of
                    // rebuilding a compact transaction from the merged PSKB. This
                    // keeps every firmware-authored partial-signature field and
                    // trailer byte intact across signer handoff.
                    transactionState._lastKasSignerKsptHex = result;
                    if (mergedSummary?.finalize_ready) {
                        toast('Final signature verified — ready to Finalize + broadcast', 'ok', 3500);
                    } else {
                        toast('Signature verified and merged — another signer is still required', 'ok', 3500);
                    }
                    return true;
                } catch (e) {
                    console.error('[KasSee] merge failed:', e);
                    toast('Merge failed: ' + e, 'error', 5000);
                    return null;
                }
            }

            if (sigStatus === 'partial') {
                console.log('[KasSee] Partial signature — relay to next signer');
                toast('Partial signature — scan with next device', 'info', 3000);
                displayKsptQr(result, 'Relay to next signer');
            } else {
                byId('input-signed-hex').value = result;
                showScreen('broadcast');
            }
            return true;
        } else {
            const prog = JSON.parse(decoder_progress());
            if (prog.total > 0) {
                let dots = '';
                for (let i = 0; i < prog.total; i++) {
                    dots += `<span class="scanner-progress-dot${prog.bits[i] ? ' scanner-progress-dot-active' : ''}"></span>`;
                }
                const progressTarget = byId(options.progressTargetId || 'scanner-status');
                if (progressTarget) {
                    setSafeMarkup(progressTarget, dots + `<div class="u-mt-6px-text-12px">${prog.count} / ${prog.total} frames</div>`);
                }
            }
            return false;
        }
    } catch (e) {
        const progressTarget = byId(options.progressTargetId || 'scanner-status');
        if (progressTarget) progressTarget.textContent = 'QR decode failed';
        if (options.showDecodeErrors === true) {
            toast('Signed QR decode failed: ' + e, 'error', 5000);
        } else {
            console.error('Decode error:', e);
        }
        return null;
    }
}
export async function handleBroadcastHex() {
    let hex = byId('input-signed-hex').value.trim();
    if (!hex) { toast('Paste a signed KSPT hex string', 'error'); return; }

    try {
        hex = processAntiKleptoResponse(hex);
        if (hex === null) return;
    } catch (error) {
        console.error('[KasSee] anti-klepto pasted response rejected:', error);
        toast('Anti-klepto verification failed — transaction rejected: ' + error, 'error', 6000);
        return;
    }

    // If someone pasted a PSKB/PSKT hex, route through the PSKT review.
    const psktFormat = pskt_detect(hex);
    if (psktFormat === 'pskb' || psktFormat === 'pskt') {
        openPsktReview(hex);
        return;
    }

    const sigStatus = inspectKsptSignatureStatus(hex);
    if (sigStatus === 'unsupported') {
        toast('Unsupported KSPT generation — only KSPT v4 is accepted', 'error', 5000);
        return;
    }
    if (sigStatus === 'unsigned') {
        // Signature-state inspection is advisory; WASM finalization performs the
        // authoritative v4 transaction/signature validation before broadcast.
        toast('Warning: KSPT appears unsigned. If KasSigner showed signed QR, press Broadcast.', 'error', 5000);
    }

    if (!BROADCAST_ENABLED) {
        toast('Broadcast disabled in this version — testing only', 'error', 5000);
        return;
    }

    showLoading('Broadcasting...');
    try {
        const txId = await withNodeRetry(wsUrl => broadcast_signed(hex, wsUrl));
        hideLoading();
        showBroadcastSuccess(txId);
    } catch (e) {
        hideLoading();
        showBroadcastError(e);
        console.error('Broadcast failed:', e);
    }
}
