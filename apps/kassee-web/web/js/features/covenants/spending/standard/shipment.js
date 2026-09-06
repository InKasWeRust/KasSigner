import { setSafeMarkup } from '../../../../core/security/safe_html.js';
import { covenantState, navigationState, networkState } from '../../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../../app/navigation.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { toast } from '../../../../core/ui/toast.js';
import { getCovFee } from '../../payload_and_swaps/state.js';
import { ensureEscrowParams } from '../../watchers_and_ui/ui/metadata.js';
import { openPsktReview } from '../../../transactions/pskt_multisig/review.js';
import { addressToScriptPublicKeyHex } from '../../../../core/address.js';
import { encode_p2pk_address, fetch_utxos_for_address_js } from '../../../../wasm/api.js';
// KasSee Web — features/covenants/spending/standard/shipment
import { bytesToHex, hexToBytes } from '../../../../core/bytes.js';
import { byId } from '../../../../core/dom.js';
import { exactJsonStringify, exactUnsigned } from '../../../../core/exact.js';
import { sompiToKasString } from '../../../../core/amounts.js';


// ── Shipment-escrow covenant: parse params from redeem, refresh panel, spend ──

// Recover amounts and payout addresses from the redeem script. The layout is
// fixed (see build_ship_escrow_script): the multi-byte integer pushes appear in
// order total, rem, cltv1, rem, fee, cltv2; the 36-byte SPK data pushes appear
// in order seller, buyer, seller, deliverer, buyer. This lets a second device
// operate from just the address + redeem hex (no shared metadata needed).
function parseShipEscrowParams(redeemHex) {
    const b = hexToBytes(redeemHex);
    const n = b.length;
    let off = 0;
    if (b[0] === 0x08) off = 1 + 8 + 1; // skip salt push + OP_DROP
    const ints = [], spks = [];
    const decLE = (arr) => { let v = 0n; for (let k = arr.length - 1; k >= 0; k--) v = (v << 8n) | BigInt(arr[k]); return v; };
    while (off < n) {
        const op = b[off];
        if (op >= 0x01 && op <= 0x4b) {
            const len = op, data = b.slice(off + 1, off + 1 + len);
            if (len === 36) spks.push(data);
            else if (len !== 32) ints.push(decLE(data)); // 32 = pubkey push, skip
            off += 1 + len;
        } else if (op === 0x4c) { off += 2 + (b[off + 1] || 0); }
        else if (op === 0x4d) { off += 3 + ((b[off + 1] || 0) | ((b[off + 2] || 0) << 8)); }
        else { off += 1; }
    }
    const spkToAddr = (spk) => {
        // spk = 00 00 20 <32B key> ac  → key at bytes [3..35)
        const keyHex = bytesToHex(spk.slice(3, 35));
        return encode_p2pk_address(keyHex, networkState.network);
    };
    if (ints.length < 6 || spks.length < 5) throw 'unrecognized ship-escrow redeem';
    return {
        total: ints[0], rem: ints[1], cltv1: ints[2], fee: ints[4], cltv2: ints[5],
        sellerAddr: spkToAddr(spks[0]), buyerAddr: spkToAddr(spks[1]), delivererAddr: spkToAddr(spks[3]),
    };
}


// Prefer in-session metadata (exact, from create); fall back to parsing the redeem.
function getShipParams(covAddr, redeemHex) {
    const L = covenantState.lastCovenantResult;
    if (L && L.type === 'ship-escrow' && L.address === covAddr && L.total_sompi != null) {
        return {
            total: BigInt(L.total_sompi), rem: BigInt(L.rem_sompi), fee: BigInt(L.fee_sompi),
            cltv1: BigInt(L.cltv1_deadline), cltv2: BigInt(L.cltv2_deadline),
            sellerAddr: L.seller_addr, delivererAddr: L.deliverer_addr, buyerAddr: L.buyer_addr,
        };
    }
    return parseShipEscrowParams(redeemHex);
}


export async function shipPanelRefresh() {
    const stateEl = byId('cov-ship-state');
    const s0 = byId('cov-ship-s0-actions'), s1 = byId('cov-ship-s1-actions');
    if (covenantState.lastCovenantResult && covenantState.lastCovenantResult.type === 'ship-escrow') {
        if (byId('cov-ship-addr') && !byId('cov-ship-addr').value.trim()) byId('cov-ship-addr').value = covenantState.lastCovenantResult.address || '';
        if (byId('cov-ship-script') && !byId('cov-ship-script').value.trim()) byId('cov-ship-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
    }
    const covAddr = byId('cov-ship-addr') ? byId('cov-ship-addr').value.trim() : '';
    const redeemHex = byId('cov-ship-script') ? byId('cov-ship-script').value.trim() : '';
    if (s0) s0.style.display = 'none';
    if (s1) s1.style.display = 'none';
    if (!covAddr || !redeemHex) { if (stateEl) stateEl.textContent = 'Enter covenant address and redeem script.'; return; }
    let P;
    try { P = getShipParams(covAddr, redeemHex); } catch (e) { if (stateEl) stateEl.textContent = 'Parse error: ' + e; return; }
    if (stateEl) stateEl.textContent = 'Loading state...';
    try {
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
        const fmt = (s) => sompiToKasString(s);
        if (!utxos.length) {
            if (stateEl) setSafeMarkup(stateEl, '<span class="u-text-text-dim">Not funded. Fund with ' + fmt(P.total) + ' KAS (product + fee) to start.</span>');
            return;
        }
        const amt = BigInt(utxos[0].amount);
        if (amt === P.total) {
            if (s0) s0.style.display = '';
            if (stateEl) setSafeMarkup(stateEl, '<span class="u-text-teal">State 0: funded (' + fmt(P.total) + ' KAS), awaiting pickup.</span><br>'
                + '<span class="u-text-11px-text-text-dim">Pickup releases ' + fmt(P.total - P.rem) + ' KAS to seller, continues at ' + fmt(P.rem) + ' KAS.</span>');
        } else if (amt === P.rem) {
            if (s1) s1.style.display = '';
            if (stateEl) setSafeMarkup(stateEl, '<span class="u-text-teal">State 1: in transit (' + fmt(P.rem) + ' KAS), awaiting delivery.</span><br>'
                + '<span class="u-text-11px-text-text-dim">Delivery pays deliverer ' + fmt(P.fee) + ' KAS, the rest to seller.</span>');
        } else {
            if (stateEl) setSafeMarkup(stateEl, '<span class="u-text-text-dim">UTXO ' + fmt(amt) + ' KAS matches neither state 0 (' + fmt(P.total) + ') nor state 1 (' + fmt(P.rem) + ').</span>');
        }
    } catch (e) { if (stateEl) stateEl.textContent = 'Error loading state: ' + e; }
}
export async function handleShipEscrowSpend(branch) {
    const covAddr = byId('cov-ship-addr').value.trim();
    const redeemHex = byId('cov-ship-script').value.trim();
    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    let P;
    try { P = getShipParams(covAddr, redeemHex); } catch (e) { toast('Could not parse covenant: ' + e, 'error'); return; }
    if (!P.sellerAddr || !P.delivererAddr || !P.buyerAddr) { toast('Could not derive payout addresses', 'error'); return; }

    const isState0 = (branch === 'pickup' || branch === 'state0-arb-refund' || branch === 'state0-timeout');
    const expectAmt = isState0 ? P.total : P.rem;

    showLoading('Building ship-escrow ' + branch + ' TX...');
    try {
        const txfee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
        if (!utxos.length) throw 'No UTXOs at covenant address';
        const u = utxos.find(x => BigInt(x.amount) === expectAmt) || utxos[0];
        const inAmt = BigInt(u.amount);
        if (inAmt !== expectAmt) {
            throw 'UTXO ' + sompiToKasString(inAmt) + ' KAS does not match the ' + (isState0 ? 'state-0 total' : 'state-1') + ' amount ' + sompiToKasString(expectAmt) + ' KAS for this branch';
        }
        const covSpkHex = '0000' + addressToScriptPublicKeyHex(covAddr);
        const sellerSpk = '0000' + addressToScriptPublicKeyHex(P.sellerAddr);
        const delivSpk = '0000' + addressToScriptPublicKeyHex(P.delivererAddr);
        const buyerSpk = '0000' + addressToScriptPublicKeyHex(P.buyerAddr);
        const mkOut = (amt, spk) => ({ amount: exactUnsigned(amt, 'output sompi'), scriptPublicKey: spk, bip32Derivations: [], proprietaries: [] });

        let outputs, minSig = 1, locktime = 0n;
        if (branch === 'pickup') {
            const sellerAmt = inAmt - P.rem - txfee;
            if (sellerAmt <= 0n) throw 'Fee too high for pickup';
            outputs = [mkOut(P.rem, covSpkHex), mkOut(sellerAmt, sellerSpk)]; // out0 continues @ rem (exact)
        } else if (branch === 'delivery' || branch === 'state1-arb-award' || branch === 'state1-timeout') {
            const sellerAmt = inAmt - P.fee - txfee;
            if (sellerAmt <= 0n) throw 'Fee too high for delivery';
            outputs = [mkOut(sellerAmt, sellerSpk), mkOut(P.fee, delivSpk)]; // out1 = deliverer fee (exact)
            if (branch === 'state1-timeout') { minSig = 0; locktime = exactUnsigned(P.cltv2, 'ship escrow CLTV2'); }
        } else if (branch === 'state0-arb-refund' || branch === 'state0-timeout' || branch === 'state1-arb-refund') {
            const buyerAmt = inAmt - txfee;
            if (buyerAmt <= 0n) throw 'Fee too high for refund';
            outputs = [mkOut(buyerAmt, buyerSpk)];
            if (branch === 'state0-timeout') { minSig = 0; locktime = exactUnsigned(P.cltv1, 'ship escrow CLTV1'); }
        } else {
            throw 'Unknown branch ' + branch;
        }

        const inputs = [{
            previousOutpoint: { transactionId: u.tx_id, index: u.index },
            // sigOpCount buys script compute budget on tx v1 (1 sigop = 10
            // budget units = 100K script units on top of the 9,999 free).
            // 0 here made every signed branch blow the free allowance:
            // "script units exceeded ... used=100763, limit=9999".
            sequence: 0, sigOpCount: minSig,
            utxoEntry: { amount: inAmt, scriptPublicKey: covSpkHex, blockDaaScore: 0n, isCoinbase: false },
            redeemScript: redeemHex, partialSigs: {}, minimumSignatures: minSig,
            bip32Derivations: [], proprietaries: {}, finalScriptSig: null, minTime: 0
        }];

        const pskt = {
            global: {
                txVersion: 1,
                fallbackLockTime: locktime > 0n ? locktime : null,
                inputsModifiableFlag: false, outputsModifiableFlag: false,
                inputCount: 1, outputCount: outputs.length,
                bip32Derivations: [],
                proprietaries: { shipBranch: branch }
            },
            inputs, outputs
        };

        const jsonStr = exactJsonStringify([pskt]);
        const jsonHex = bytesToHex(new TextEncoder().encode(jsonStr));
        const wireBytes = new TextEncoder().encode('PSKB');
        const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
        wireFull.set(wireBytes);
        wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
        const pskbHex = bytesToHex(wireFull);

        hideLoading();
        console.log('[KasSee] ShipEscrow ' + branch + ' PSKB: ' + pskbHex.length + ' hex chars, minSig=' + minSig + ', locktime=' + locktime);
        covenantState._covPayloadHex = '';
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Ship-escrow ' + branch + ' failed: ' + e, 'error', 5000);
        console.error('[KasSee] Ship-escrow spend error:', e);
    }
}
export async function handleEscrowSpend(branch) {
    if (!covenantState.lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
    const covAddr = covenantState.lastCovenantResult.address;
    const redeemHex = covenantState.lastCovenantResult.redeem_script_hex;
    if (!covAddr || !redeemHex) { toast('Missing covenant data', 'error'); return; }

    // Parse script to get destination addresses
    ensureEscrowParams(covenantState.lastCovenantResult);
    const alicePk = covenantState.lastCovenantResult.alice_spk_hex || covenantState.lastCovenantResult.alice_pk;
    const bobPk = covenantState.lastCovenantResult.bob_spk_hex || covenantState.lastCovenantResult.bob_pk;
    if (!alicePk || !bobPk) { toast('Could not parse escrow destinations from script', 'error'); return; }

    // Determine destination based on branch
    let destAddr;
    const isDispute = (branch === 'buyer-dispute' || branch === 'seller-dispute');
    if (isDispute) {
        destAddr = covAddr; // send back to same escrow address
    } else if (branch === 'buyer-release' || branch === 'arbiter-award-seller') {
        destAddr = encode_p2pk_address(bobPk, networkState.network); // funds go to seller
    } else {
        destAddr = encode_p2pk_address(alicePk, networkState.network); // funds go to buyer
    }

    showLoading('Building escrow ' + branch + ' TX...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
        const utxos = JSON.parse(utxosJson);
        if (!utxos.length) throw 'No UTXOs at escrow address';

        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        if (total <= fee) throw 'Balance too low: ' + sompiToKasString(total) + ' KAS';

        const sendAmount = total - fee;
        const covSpkHex = '0000' + addressToScriptPublicKeyHex(covAddr);
        const destSpkHex = '0000' + addressToScriptPublicKeyHex(destAddr);

        const inputs = utxos.map(u => ({
            previousOutpoint: { transactionId: u.tx_id, index: u.index },
            // Every escrow branch verifies exactly one signature; sigOpCount 1
            // commits compute_budget 10 (109,999 units) on tx v1. 0 capped the
            // input at the 9,999 free units and the node rejected the spend.
            sequence: 0, sigOpCount: 1,
            utxoEntry: { amount: exactUnsigned(u.amount, 'escrow input sompi'), scriptPublicKey: covSpkHex, blockDaaScore: exactUnsigned(u.block_daa_score ?? 0n, 'escrow input DAA'), isCoinbase: false },
            redeemScript: redeemHex, partialSigs: {}, minimumSignatures: 1,
            bip32Derivations: [],
            proprietaries: {},
            finalScriptSig: null, minTime: 0
        }));

        const outputs = [{ amount: sendAmount, scriptPublicKey: destSpkHex, bip32Derivations: [], proprietaries: [] }];

        // Dispute heartbeat: attach "ESCD" + role payload so all watchers detect it
        let txPayload = '';
        if (isDispute) {
            const roleByte = (branch === 'buyer-dispute') ? '01' : '02';
            txPayload = '4553434400' + roleByte; // "ESCD\0" + role (6 bytes)
        }

        // tx_version 1 for covenant introspection on TN10
        const pskt = {
            global: {
                txVersion: 1, fallbackLockTime: null,
                inputsModifiableFlag: false, outputsModifiableFlag: false,
                inputCount: inputs.length, outputCount: outputs.length,
                bip32Derivations: [],
                proprietaries: { escrowBranch: branch },
                txPayload: txPayload || undefined
            },
            inputs, outputs
        };

        const jsonStr = exactJsonStringify([pskt]);
        const jsonHex = bytesToHex(new TextEncoder().encode(jsonStr));
        const wireBytes = new TextEncoder().encode('PSKB');
        const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
        wireFull.set(wireBytes);
        wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
        const pskbHex = bytesToHex(wireFull);

        hideLoading();
        console.log('[KasSee] Escrow ' + branch + ' PSKB: ' + pskbHex.length + ' hex chars, dest=' + destAddr);
        covenantState._covPayloadHex = ''; // Clear stale deposit payload
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Escrow spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Escrow spend error:', e);
    }
}
