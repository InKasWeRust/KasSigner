import { covenantState, navigationState, networkState } from '../../../../../app/state/index.js';
import { piggyBreakStatus, piggyStatusBanner } from '../../../../../app/events/contracts/covenant_creation/result_actions.js';
import { hideLoading, showLoading } from '../../../../../app/navigation.js';
import { fetchCurrentDaa } from '../../../../../core/node/daa.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { getCovFee } from '../../../payload_and_swaps/state.js';
import { pickThread } from '../thread_and_claims.js';
import { openPsktReview } from '../../../../transactions/pskt_multisig/review.js';
import { addressToScriptPublicKeyHex } from '../../../../../core/address.js';
import { create_covenant_owner_spend, create_global_spending_limit_withdraw, fetch_utxos_for_address_js } from '../../../../../wasm/api.js';

import { bytesToHex } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';
import { formatDaaDuration } from '../../../../../core/format.js';
import { kasToSompi, sompiToKasString } from '../../../../../core/amounts.js';
import { exactJsonStringify, exactUnsigned } from '../../../../../core/exact.js';
import { ceilRateToInteger } from '../../../../../core/fee_math.js';
async function buildGlobalSpendingLimitOwnerSpend(request) {
    const { covAddr, redeemHex, destAddr, amountStr, isPartial, wsUrl } = request;
    // Single-thread global limit. Empty amount = sweep/close the whole thread
    // (allowed only when balance <= cap, enforced on-chain by the script's ELSE
    // branch); otherwise a capped partial withdrawal leaving a continuation.
    // The continuation reuses the thread's own covenant id (G), read from the node.
    const threadRaw = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
    if (!threadRaw.length) { toast('No UTXO at the covenant address', 'error'); hideLoading(); return; }
    const _pick = pickThread(threadRaw, covenantState.lastCovenantResult && covenantState.lastCovenantResult.covenant_id_hex);
    const thread = _pick.thread; // the tagged thread, selected by covenant_id (not size)
    if (!thread) {
        const _gKnown = !!(covenantState.lastCovenantResult && covenantState.lastCovenantResult.covenant_id_hex && !/^0+$/.test(covenantState.lastCovenantResult.covenant_id_hex));
        const _msg = _pick.ambiguous
            ? 'Multiple covenant-tagged UTXOs at this address and no known thread id, cannot safely pick the thread.'
            : (_gKnown
                ? 'Thread closed. The remaining ' + sompiToKasString(_pick.externalSompi) + ' KAS is external and cannot be spent through the limit.'
                : 'Thread covenant_id unavailable from the node. The continuation must reuse the thread id; the node must serve version-2 UTXO entries.');
        toast(_msg, 'error', 6500);
        hideLoading(); return;
    }
    const threadAmt = BigInt(thread.amount);
    const gId = thread.covenant_id || ''; // thread's own covenant id (G)
    // CSV cooldown: the thread UTXO must age past the cooldown before it can be
    // spent again (a top-up or prior withdrawal reset its age). Block an early
    // withdrawal here so the user is not sent into a CSV-rejected TX.
    const _cd = exactUnsigned(covenantState.lastCovenantResult?.cooldown_daa ?? 0n, 'cooldown DAA');
    if (_cd > 0n) {
        const _threadDaa = exactUnsigned(thread.block_daa_score ?? 0n, 'thread DAA');
        if (_threadDaa > 0n) {
            const _curDaa = await fetchCurrentDaa();
            const _matureDaa = _threadDaa + _cd;
            if (_curDaa > 0n && _curDaa < _matureDaa) {
                hideLoading();
                const _eta = formatDaaDuration(_matureDaa - _curDaa);
                toast('Cooldown not elapsed. Next withdrawal in ~' + _eta + '. An early spend is rejected by the node.', 'error', 5000);
                return;
            }
        }
    }
    // Empty -> sweep the whole balance (close); otherwise the entered amount.
    const withdrawSompi = isPartial ? kasToSompi(amountStr) : threadAmt;
    const capSompi = (covenantState.lastCovenantResult && covenantState.lastCovenantResult.max_withdraw_sompi) ? BigInt(covenantState.lastCovenantResult.max_withdraw_sompi) : 0n;
    if (withdrawSompi > threadAmt) {
        toast('Amount exceeds the thread balance (' + sompiToKasString(threadAmt) + ' KAS).', 'error');
        hideLoading(); return;
    }
    if (capSompi > 0n && withdrawSompi > capSompi) {
        // Over the per-spend cap. A partial withdrawal must be <= cap; a sweep-all
        // (close) is valid only when the whole balance is <= cap. So once the
        // balance exceeds the cap, the only legal spend is a capped partial.
        const _capK = sompiToKasString(capSompi);
        const _msg = (withdrawSompi >= threadAmt)
            ? 'Balance (' + sompiToKasString(threadAmt) + ' KAS) is over the per-spend cap of ' + _capK + ' KAS, so it cannot be swept in one TX. Withdraw ' + _capK + ' KAS or less.'
            : 'Per-spend cap is ' + _capK + ' KAS. Withdraw that or less.';
        toast(_msg, 'error', 5000);
        hideLoading(); return;
    }
    const baseFee = 300000n;
    let glFee = baseFee;
    const returnEst = threadAmt - withdrawSompi - baseFee;
    if (returnEst > 0n && withdrawSompi > 0n) {
        const C = 1000000000000n, MAX_SM = 500000n;
        const hMean = (2n * returnEst * withdrawSompi) / (returnEst + withdrawSompi);
        const storageMass = hMean > 0n ? C / hMean : 0n;
        if (storageMass > MAX_SM) {
            toast('That withdrawal leaves too small a remainder (storage mass). Pick a different amount.', 'error');
            hideLoading(); return;
        }
        const computeMass = 2500n;
        const totalMass = storageMass > computeMass ? storageMass : computeMass;
        const feeRate = networkState.lastFeeEstimate ? ceilRateToInteger(networkState.lastFeeEstimate.normal_sompi_per_gram || 1) : 1n;
        glFee = totalMass * feeRate;
        if (glFee < baseFee) glFee = baseFee;
    }
    console.log('[KasSee] Global limit withdraw: thread ' + thread.tx_id.substring(0, 16) + ':' + thread.index + ' = ' + sompiToKasString(threadAmt) + ' KAS, withdraw=' + sompiToKasString(withdrawSompi) + ' KAS, fee=' + glFee.toString());
    return await create_global_spending_limit_withdraw(covAddr, destAddr, redeemHex, gId, withdrawSompi, glFee, exactJsonStringify([thread]));
}

async function buildOwnerSweep(request) {
    const { covAddr, redeemHex, destAddr, covType, fee, wsUrl } = request;
    // Sweep all — use existing WASM function. Scale the fee to the UTXO
    // count so a multi-UTXO sweep (e.g. a vault/DMS funded several times)
    // is not rejected for compute mass.
    let branch = '';
    // CLTV-only covenant owner paths must stamp the script locktime.
    if (covType === 'payjoin' || covType === 'merkle-whitelist' || covType === 'commit-reveal' || covType === 'oracle-v1') branch = 'owner-time';
    // CLTV-only owner reclaim gate: for these types the owner path IS
    // the timelock branch — before it matures the node rejects the TX
    // as not finalized. Block the doomed TX with a banner instead.
    const _cltvOwnerTypes = { 'merkle-whitelist': 'only whitelisted spends are valid',
                              'commit-reveal': 'only the reveal path is valid',
                              'payjoin': 'only the joint-spend path is valid',
                              'oracle-v1': 'only an oracle-attested beneficiary claim is valid' };
    if (_cltvOwnerTypes[covType] && exactUnsigned(covenantState.lastCovenantResult?.locktime_daa ?? 0n, 'owner locktime DAA') > 0n) {
        let _mwDaa = 0n;
        try { _mwDaa = await fetchCurrentDaa(); } catch (_) {}
        if (_mwDaa === 0n && typeof covenantState._lastKnownDaa !== 'undefined') _mwDaa = exactUnsigned(covenantState._lastKnownDaa ?? 0n, 'last known DAA');
        const _mwLt = exactUnsigned(covenantState.lastCovenantResult.locktime_daa, 'owner locktime DAA');
        if (_mwDaa > 0n && _mwDaa < _mwLt) {
            const _mwEta = formatDaaDuration(_mwLt - _mwDaa);
            try {
                piggyStatusBanner({
                    text: 'Owner reclaim NOT available yet: timelock matures in ~' + _mwEta +
                          '. Until then ' + _cltvOwnerTypes[covType] + ' — a reclaim TX would be rejected on-chain.',
                    color: 'var(--error, #f44336)'
                });
            } catch (_) {}
            hideLoading();
            toast('Owner reclaim is timelocked for ~' + _mwEta + ' more. The node would reject this TX.', 'error', 7500);
            return;
        }
    }
    let sweepFee = fee;
    try {
        const wsCheck = await resolveNodeUrl();
        const utxosCheck = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsCheck));
        sweepFee = getCovFee(utxosCheck.length || 1);
        // Piggy break gate: refuse to build a TX that cannot pass
        // on-chain. Goal path needs (total - fee) >= threshold;
        // deadline path needs the CLTV to have matured. If neither
        // holds, a broadcast is guaranteed to fail — block it here.
        if (covType === 'additive' && covenantState.lastCovenantResult) {
            const totalCheck = utxosCheck.reduce((s, u) => s + BigInt(u.amount), 0n);
            const st = await piggyBreakStatus(totalCheck, sweepFee);
            try { piggyStatusBanner(st); } catch (_) {}
            if (!st.canBreak) {
                hideLoading();
                toast(st.text, 'error', 7500);
                return;
            }
            if (!st.goalMet && st.deadlinePassed) {
                branch = 'owner-time';
                console.log('[KasSee] Piggy break: using deadline (time) path');
            }
        }
    } catch (_) {}
    return await create_covenant_owner_spend(covAddr, destAddr, redeemHex, sweepFee, wsUrl, branch);
}

async function buildPartialOwnerSpend(request) {
    const { covAddr, redeemHex, destAddr, amountStr, fee, wsUrl } = request;
    // Partial spend — build PSKB in JS with change back to covenant
    const sendSompi = kasToSompi(amountStr);
    const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
    const utxos = JSON.parse(utxosJson);
    if (!utxos.length) throw 'No UTXOs at covenant address';

    const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
    if (total < sendSompi + fee) throw 'Balance too low: ' + sompiToKasString(total) + ' KAS available';

    const change = total - sendSompi - fee;
    const covSpkHex = '0000' + addressToScriptPublicKeyHex(covAddr);
    const destSpkHex = '0000' + addressToScriptPublicKeyHex(destAddr);

    const inputs = utxos.map(u => ({
        previousOutpoint: { transactionId: u.tx_id, index: u.index },
        sequence: 0, sigOpCount: 1,
        utxoEntry: { amount: exactUnsigned(u.amount, 'owner input sompi'), scriptPublicKey: covSpkHex, blockDaaScore: exactUnsigned(u.block_daa_score ?? 0n, 'owner input DAA'), isCoinbase: false },
        redeemScript: redeemHex, partialSigs: {}, minimumSignatures: 1,
        bip32Derivations: [], proprietaries: [], finalScriptSig: null, minTime: 0
    }));

    const outputs = [{ amount: sendSompi, scriptPublicKey: destSpkHex, bip32Derivations: [], proprietaries: [] }];
    if (change > 0n) {
        outputs.push({ amount: change, scriptPublicKey: covSpkHex, bip32Derivations: [], proprietaries: [] });
    }

    // Partial owner reclaim always spends the immediate branch (the
    // time-locked owner break is full-sweep only), so the TX must be
    // final: locktime 0. The script's CLTV lives in the beneficiary
    // branch; stamping it here would make the node reject the TX as
    // "input #0 is not finalized" before the timeout.
    const pskt = {
        global: {
            txVersion: 0, fallbackLockTime: 0n,
            inputsModifiableFlag: false, outputsModifiableFlag: false,
            inputCount: inputs.length, outputCount: outputs.length,
            bip32Derivations: [], proprietaries: []
        },
        inputs, outputs
    };

    const jsonStr = exactJsonStringify([pskt]);
    const jsonHex = bytesToHex(new TextEncoder().encode(jsonStr));
    const wireBytes = new TextEncoder().encode('PSKB');
    const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
    wireFull.set(wireBytes);
    wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
    return bytesToHex(wireFull);
}


export async function handleCovOwnerSpend() {
    covenantState._covPayloadHex = '';
    const covAddr = byId('cov-owner-addr').value.trim();
    const redeemHex = byId('cov-owner-script').value.trim();
    const destAddr = byId('cov-owner-dest').value.trim();
    const amountStr = byId('cov-owner-amount').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    let isPartial = false;
    if (amountStr) {
        try { isPartial = kasToSompi(amountStr) > 0n; } catch (_) { toast('Enter a valid KAS amount with at most 8 decimal places', 'error'); return; }
    }
    const covType = byId('cov-owner-panel') ? (byId('cov-owner-panel').dataset.covOwnerType || '') : '';
    if (covType === 'commit-reveal' && isPartial) {
        toast('Commit-Reveal owner refund is full-only. Clear the amount to refund the whole commitment. A partial refund would leave a remainder that breaks the reveal and refund paths.', 'error', 8000);
        return;
    }
    if (covType === 'oracle-v1' && isPartial) {
        toast('Oracle owner refund is full-only after the timeout. Clear the amount to refund the whole covenant balance.', 'error', 8000);
        return;
    }

    showLoading('Building owner-spend PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const request = { covAddr, redeemHex, destAddr, amountStr, isPartial, covType, fee, wsUrl };
        let pskbHex;
        if (covType === 'global-spending-limit') {
            pskbHex = await buildGlobalSpendingLimitOwnerSpend(request);
        } else if (!isPartial) {
            pskbHex = await buildOwnerSweep(request);
        } else {
            pskbHex = await buildPartialOwnerSpend(request);
        }
        if (!pskbHex) return;

        hideLoading();
        console.log('[KasSee] Covenant owner-spend PSKB: ' + pskbHex.length + ' hex chars' + (isPartial ? ' (partial)' : ' (sweep)'));
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Owner spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Owner spend error:', e);
    }
}
