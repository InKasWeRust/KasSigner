import { commitRevealState, covenantState, navigationState } from '../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../app/navigation.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import { openPsktReview } from '../../transactions/pskt_multisig/review.js';
import { create_commit_reveal_spend, create_merkle_whitelist_spend, fetch_utxos_for_address_js, merkle_proof_for_address } from '../../../wasm/api.js';
// KasSee Web — features/covenants/spending/advanced
import { byId } from '../../../core/dom.js';

import { kasToSompi, sompiToKasString } from '../../../core/amounts.js';
import { sortUtxosLargestFirst } from '../../../core/utxo.js';

// ─── ZK Proof Covenant Handlers ───




// ─── Merkle Whitelist Vault Handlers ───

// Sompi -> KAS decimal string, exact (no float; the value feeds back into kasToSompi).
// Max spendable for a merkle whitelist claim. Mirrors create_merkle_whitelist_spend:
// cap at the 4 largest UTXOs, depth-aware mass fee, 300k floor. Returns sompi or null.
// NOTE: the fee formula MUST stay in sync with create_merkle_whitelist_spend in lib.rs.
export async function mwMaxSompi() {
    const covAddr = byId('cov-mw-addr').value.trim();
    if (!covAddr) return null;
    const wsUrl = await resolveNodeUrl();
    const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
    if (!utxos.length) return null;
    sortUtxosLargestFirst(utxos);
    const capped = utxos.slice(0, 4); // MAX_COV_INPUTS
    const total = capped.reduce((s, u) => s + BigInt(u.amount), 0n);
    const addrCount = byId('cov-mw-spend-addresses').value.trim().split('\n').filter(a => a.trim()).length;
    const depth = Math.max(1, Math.ceil(Math.log2(Math.max(2, addrCount))));
    const perInput = 270n + 40n * BigInt(depth) + 1000n;
    const computeMass = 46n + BigInt(capped.length) * perInput + 43n + 2n * 340n;
    const estimatedFee = computeMass * 115n;
    const fee = estimatedFee > 300000n ? estimatedFee : 300000n;
    const maxSompi = total - fee;
    return maxSompi > 0n ? maxSompi : null;
}
export async function handleCovMwSpend() {
    const covAddr = byId('cov-mw-addr').value.trim();
    const redeemHex = byId('cov-mw-script').value.trim();
    const destAddr = byId('cov-mw-dest').value.trim();
    const addrText = byId('cov-mw-spend-addresses').value.trim();

    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination (must be in whitelist)', 'error'); return; }
    if (!addrText) { toast('Enter the same whitelist used for creation', 'error'); return; }
    let sendSompi;
    try { sendSompi = kasToSompi(byId('cov-mw-amount').value); } catch (_) { toast('Enter amount to send', 'error'); return; }
    if (sendSompi === 0n) { toast('Enter amount to send', 'error'); return; }
    const addresses = addrText.split('\n').map(a => a.trim()).filter(a => a.length > 0);

    showLoading('Computing merkle proof...');
    try {
        const addrJson = JSON.stringify(addresses);
        const proofResult = merkle_proof_for_address(addrJson, destAddr);
        const proofInfo = JSON.parse(proofResult);
        console.log('[KasSee] Merkle proof:', proofInfo.proof.length, 'levels, leaf_index:', proofInfo.leaf_index);

        const fee = BigInt(300000);
        const wsUrl = await resolveNodeUrl();
        const proofStr = JSON.stringify(proofInfo.proof);
        const pskbHex = await create_merkle_whitelist_spend(
            covAddr, destAddr, redeemHex, proofStr, sendSompi, fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Merkle whitelist PSKB: ' + pskbHex.length + ' hex chars');
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Merkle spend failed: ' + e, 'error', 5000);
    }
}





// ─── KIP-21 ZK Rollup Handlers ───





// ─── Rollup Deposit (L1->L2) Handlers ───




// ─── Commit-Reveal Handlers ───

export async function handleCovCrReveal() {
    const covAddr = byId('cov-cr-addr').value.trim();
    const redeemHex = byId('cov-cr-script').value.trim();
    const destAddr = byId('cov-cr-dest').value.trim();

    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    // Get preimage from decrypt scan (stored as part_A, part_B is empty)
    const partA = commitRevealState._crRevealPartA || '';
    const partB = commitRevealState._crRevealPartB || '';
    if (!partA) {
        toast('Scan decrypted preimage from KasSigner first (step 2)', 'error');
        return;
    }

    showLoading('Building reveal PSKB...');
    try {
        const fee = BigInt(300000);
        const wsUrl = await resolveNodeUrl();

        // Build CR01 payload: "CR01" (4 bytes) + committed_hash (32 bytes)
        const commitHash = covenantState.lastCovenantResult ? (covenantState.lastCovenantResult.commit_hash || '') : '';
        let cr01Hex = '43523031'; // "CR01"
        if (commitHash.length === 64) cr01Hex += commitHash;
        covenantState._covPayloadHex = cr01Hex;

        const pskbHex = await create_commit_reveal_spend(JSON.stringify({
            covenant_address: covAddr,
            dest_address: destAddr,
            redeem_script_hex: redeemHex,
            part_a_hex: partA,
            part_b_hex: partB,
            payload_hex: cr01Hex,
            fee: fee.toString(),
            ws_url: wsUrl,
        }));
        hideLoading();
        // Clear preimage from memory immediately after PSKB build
        commitRevealState._crRevealPartA = null;
        commitRevealState._crRevealPartB = null;
        commitRevealState._crDecryptCtBytes = null;
        console.log('[KasSee] Commit-reveal PSKB built, CR01 payload: ' + cr01Hex.length/2 + ' bytes');
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Reveal failed: ' + e, 'error', 5000);
    }
}



// ─── RISC0 Succinct ZK Covenant Handlers ───



export async function handleCovCheckBalance() {
    const covAddr = byId('cov-balance-addr').value.trim();
    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }

    showLoading('Checking balance...');
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
        const utxos = JSON.parse(utxosJson);
        hideLoading();

        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        const kasStr = sompiToKasString(total);

        byId('cov-balance-kas').textContent = kasStr + ' KAS';
        byId('cov-balance-utxos').textContent = utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ' · ' + total.toString() + ' sompi';
        byId('cov-balance-result').classList.remove('hidden');

        if (utxos.length === 0) {
            toast('No UTXOs at this address', 'info', 2000);
        }
    } catch (e) {
        hideLoading();
        toast('Balance check failed: ' + e, 'error', 5000);
        console.error('[KasSee] Balance check error:', e);
    }
}
