import { covenantState, navigationState, networkState, walletSession } from '../../../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../../../app/navigation.js';
import { fetchCurrentDaa } from '../../../../../core/node/daa.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { getCovFee } from '../../../payload_and_swaps/state.js';
import { pickThread } from '../thread_and_claims.js';
import { openPsktReview } from '../../../../transactions/pskt_multisig/review.js';
import { create_covenant_beneficiary_spend, create_covenant_borrower_spend, create_covenant_borrower_withdraw, create_covenant_timelocked_savings_claim, create_covenant_timeout_refund, create_global_allowance_withdraw, fetch_utxos_for_address_js } from '../../../../../wasm/api.js';

import { byId } from '../../../../../core/dom.js';
import { formatDaaDuration } from '../../../../../core/format.js';
import { kasToSompi, sompiToKasString } from '../../../../../core/amounts.js';
import { exactJsonStringify, exactUnsigned } from '../../../../../core/exact.js';
import { ceilRateToInteger } from '../../../../../core/fee_math.js';
import { runCovenantClaim } from './claim_controller.js';

export async function handleCovBorrowerSpend() {
    if (!walletSession.hasWallet()) { toast('Load wallet first', 'error'); return; }
    const covAddr = byId('cov-borrower-addr').value.trim();
    const redeemHex = byId('cov-borrower-script').value.trim();
    const amountStr = byId('cov-borrower-amount').value.trim();
    const mode = byId('cov-borrower-mode').value;

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    let sompi;
    try { sompi = kasToSompi(amountStr); } catch (_) { toast('Enter a valid amount with at most 8 decimal places', 'error'); return; }
    if (sompi <= 0n) { toast('Enter amount', 'error'); return; }

    showLoading(mode === 'withdraw' ? 'Building borrower withdraw PSKB...' : 'Building borrower spend PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        let pskbHex;
        if (mode === 'withdraw') {
            pskbHex = await create_covenant_borrower_withdraw(walletSession.json(), covAddr, redeemHex, sompi, fee, wsUrl);
        } else {
            pskbHex = await create_covenant_borrower_spend(walletSession.json(), covAddr, redeemHex, sompi, fee, wsUrl);
        }
        hideLoading();
        console.log('[KasSee] Covenant borrower PSKB: ' + pskbHex.length + ' hex chars');
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Borrower TX failed: ' + e, 'error', 5000);
        console.error('[KasSee] Borrower TX error:', e);
    }
}

function readBeneficiaryFields() {
    const fields = {
        type: byId('cov-beneficiary-panel').dataset.covBeneType || '',
        covenantAddress: byId('cov-bene-addr').value.trim(),
        redeemScriptHex: byId('cov-bene-script').value.trim(),
        destinationAddress: byId('cov-bene-dest').value.trim(),
    };
    if (!fields.covenantAddress) throw new Error('Enter covenant P2SH address');
    if (!fields.redeemScriptHex) throw new Error('Enter redeem script hex');
    if (!fields.destinationAddress) throw new Error('Enter destination address');
    return fields;
}

function selectAllowanceThread(utxos) {
    const knownId = covenantState.lastCovenantResult?.covenant_id_hex;
    const selection = pickThread(utxos, knownId);
    if (selection.thread) return selection.thread;
    const hasKnownId = !!(knownId && !/^0+$/.test(knownId));
    if (selection.ambiguous) {
        throw new Error('Multiple covenant-tagged UTXOs and no known thread id, cannot safely pick the thread.');
    }
    if (hasKnownId) {
        throw new Error('Thread closed. The remaining ' + sompiToKasString(selection.externalSompi) +
            ' KAS is external; the owner can reclaim it, the beneficiary cannot withdraw it.');
    }
    throw new Error('Thread covenant_id unavailable from the node (need version-2 UTXO entries).');
}

async function enforceAllowanceTiming(thread) {
    const startDaa = exactUnsigned(covenantState.lastCovenantResult?.start_daa ?? 0n, 'start DAA');
    const cooldownDaa = exactUnsigned(covenantState.lastCovenantResult?.cooldown_daa ?? 0n, 'cooldown DAA');
    if (startDaa === 0n && cooldownDaa === 0n) return;
    const currentDaa = await fetchCurrentDaa();
    if (currentDaa <= 0n) return;
    if (startDaa > 0n && currentDaa < startDaa) {
        const eta = formatDaaDuration(startDaa - currentDaa);
        throw new Error('Not started yet. Withdrawals begin in ~' + eta + '. An early spend is rejected by the node.');
    }
    const threadDaa = exactUnsigned(thread.block_daa_score ?? 0n, 'thread DAA');
    if (cooldownDaa > 0n && threadDaa > 0n && currentDaa < threadDaa + cooldownDaa) {
        const eta = formatDaaDuration(threadDaa + cooldownDaa - currentDaa);
        throw new Error('Cooldown not elapsed. Next withdrawal in ~' + eta + '. An early spend is rejected by the node.');
    }
}

function calculateAllowanceWithdrawal(threadAmount) {
    const amountText = byId('cov-bene-amount')?.value.trim() || '';
    let withdrawSompi = threadAmount;
    if (amountText) {
        withdrawSompi = kasToSompi(amountText);
        if (withdrawSompi <= 0n) throw new Error('Enter a positive amount');
    }
    const capSompi = BigInt(covenantState.lastCovenantResult?.max_withdraw_sompi || 0);
    if (withdrawSompi > threadAmount) {
        throw new Error('Amount exceeds the thread balance (' + sompiToKasString(threadAmount) + ' KAS).');
    }
    if (capSompi > 0n && withdrawSompi > capSompi) {
        const capKas = sompiToKasString(capSompi);
        const message = withdrawSompi >= threadAmount
            ? 'Balance (' + sompiToKasString(threadAmount) + ' KAS) is over the per-spend cap of ' +
                capKas + ' KAS, so it cannot be swept in one TX. Withdraw ' + capKas + ' KAS or less.'
            : 'Per-spend cap is ' + capKas + ' KAS. Withdraw that or less.';
        throw new Error(message);
    }
    return withdrawSompi;
}

function calculateAllowanceFee(threadAmount, withdrawSompi) {
    const baseFee = 300000n;
    const remainder = threadAmount - withdrawSompi - baseFee;
    if (remainder <= 0n || withdrawSompi <= 0n) return baseFee;
    const harmonicMean = (2n * remainder * withdrawSompi) / (remainder + withdrawSompi);
    const storageMass = harmonicMean > 0n ? 1000000000000n / harmonicMean : 0n;
    if (storageMass > 500000n) {
        throw new Error('That withdrawal leaves too small a remainder (storage mass). Pick a different amount.');
    }
    const totalMass = storageMass > 2500n ? storageMass : 2500n;
    const feeRate = ceilRateToInteger(networkState.lastFeeEstimate?.normal_sompi_per_gram || 1);
    const calculated = totalMass * feeRate;
    return calculated > baseFee ? calculated : baseFee;
}

async function handleGlobalAllowanceWithdrawal(fields) {
    showLoading('Building global allowance withdraw PSKB...');
    try {
        const websocketUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(fields.covenantAddress, websocketUrl));
        if (!utxos.length) throw new Error('No UTXO at the covenant address');
        const thread = selectAllowanceThread(utxos);
        await enforceAllowanceTiming(thread);
        const threadAmount = BigInt(thread.amount);
        const withdrawSompi = calculateAllowanceWithdrawal(threadAmount);
        const fee = calculateAllowanceFee(threadAmount, withdrawSompi);
        const pskbHex = await create_global_allowance_withdraw(
            fields.covenantAddress,
            fields.destinationAddress,
            fields.redeemScriptHex,
            thread.covenant_id || '',
            withdrawSompi,
            fee,
            exactJsonStringify([thread]),
        );
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (error) {
        toast('Global allowance withdraw failed: ' + error, 'error', 5000);
    } finally {
        hideLoading();
    }
}

async function ensureStandardClaimUnlocked(type, locktime, utxos) {
    const currentDaa = await fetchCurrentDaa();
    if (currentDaa <= 0n) return;
    if (type === 'timelocked-savings') {
        const unlockDaa = exactUnsigned(locktime || '0', 'claim locktime DAA');
        if (unlockDaa > 0n && currentDaa < unlockDaa) {
            const eta = formatDaaDuration(unlockDaa - currentDaa);
            throw new Error('Still locked. Unlocks in ~' + eta + '. An early claim is rejected by the node.');
        }
        return;
    }
    if (covenantState.lastCovenantResult?.type !== 'dms') return;
    const inactivityDaa = exactUnsigned(covenantState.lastCovenantResult.inactivity_daa ?? 0n, 'inactivity DAA');
    if (inactivityDaa === 0n || !utxos.length) return;
    const newestDaa = utxos.reduce((latest, utxo) => {
        const daa = exactUnsigned(utxo.block_daa_score ?? 0n, 'UTXO DAA');
        return daa > latest ? daa : latest;
    }, 0n);
    const unlockDaa = newestDaa + inactivityDaa;
    if (currentDaa < unlockDaa) {
        const eta = formatDaaDuration(unlockDaa - currentDaa);
        throw new Error('Still locked. The inactivity period has not elapsed for all vault UTXOs. ' +
            'The heir can sweep everything in ~' + eta + '. An early claim is rejected by the node.');
    }
}

async function handleStandardBeneficiarySpend(fields) {
    const locktime = byId('cov-bene-locktime').value.trim();
    const isDms = covenantState.lastCovenantResult?.type === 'dms';
    if (!isDms && (!/^\d+$/.test(locktime) || exactUnsigned(locktime, 'claim locktime DAA') === 0n)) {
        throw new Error('Enter locktime DAA score');
    }
    showLoading('Building beneficiary-spend PSKB...');
    try {
        const websocketUrl = await resolveNodeUrl();
        let utxos = [];
        try {
            utxos = JSON.parse(await fetch_utxos_for_address_js(fields.covenantAddress, websocketUrl));
        } catch (_) {}
        const fee = getCovFee(utxos.length || 1);
        await ensureStandardClaimUnlocked(fields.type, locktime, utxos);
        const pskbHex = fields.type === 'timelocked-savings'
            ? await create_covenant_timelocked_savings_claim(
                fields.covenantAddress,
                fields.destinationAddress,
                fields.redeemScriptHex,
                BigInt(locktime),
                fee,
                websocketUrl,
            )
            : await create_covenant_beneficiary_spend(
                fields.covenantAddress,
                fields.destinationAddress,
                fields.redeemScriptHex,
                BigInt(locktime),
                fee,
                websocketUrl,
            );
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } finally {
        hideLoading();
    }
}

export async function handleCovBeneficiarySpend() {
    covenantState._covPayloadHex = '';
    let fields;
    try {
        fields = readBeneficiaryFields();
    } catch (error) {
        toast(error.message, 'error');
        return;
    }
    if (fields.type === 'global-allowance') {
        await handleGlobalAllowanceWithdrawal(fields);
        return;
    }
    try {
        await handleStandardBeneficiarySpend(fields);
    } catch (error) {
        toast('Beneficiary spend failed: ' + error, 'error', 5000);
        console.error('[KasSee] Beneficiary spend error:', error);
    }
}

export async function handleCovTimeoutRefund() {
    const covenantAddress = byId('cov-timeout-addr').value.trim();
    const redeemScriptHex = byId('cov-timeout-script').value.trim();
    const locktime = byId('cov-timeout-locktime').value.trim();
    const destinationAddress = byId('cov-timeout-dest').value.trim();

    if (!covenantAddress) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemScriptHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!/^\d+$/.test(locktime) || exactUnsigned(locktime, 'timeout locktime DAA') === 0n) { toast('Enter locktime DAA score', 'error'); return; }
    if (!destinationAddress) { toast('Enter refund destination address', 'error'); return; }

    const fee = getCovFee();
    await runCovenantClaim({
        loadingMessage: 'Building timeout-refund PSKB...',
        errorLabel: 'Timeout refund failed',
        logLabel: 'Timeout-refund PSKB',
        build: websocketUrl => create_covenant_timeout_refund(
            covenantAddress,
            destinationAddress,
            redeemScriptHex,
            BigInt(locktime),
            fee,
            websocketUrl,
        ),
    });
}
