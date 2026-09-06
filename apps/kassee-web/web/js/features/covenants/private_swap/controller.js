import { covenantState, navigationState, networkState, walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { byId } from '../../../core/dom.js';
import { kasToSompi, sompiToKasString } from '../../../core/amounts.js';
import { exactUnsigned } from '../../../core/exact.js';
import { resolveFutureDaa } from '../../../core/node/future_daa.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import { getOwnerPubkeyHex, covShowPanel } from '../generation/ui_and_keys.js';
import { handleCovFund } from '../generation/fund.js';
import { getCovFee, ownerReceiveAddr } from '../payload_and_swaps/state.js';
import { covAddActive, covRenderActive, covSaveActive } from '../recovery/active.js';
import { startScanner, stopScanner } from '../../stealth/index/camera.js';
import {
    create_private_swap_claim, fetch_utxos_for_address_js,
    private_swap_claim_sighash, private_swap_complete_public, private_swap_extract_secret,
    private_swap_insert_completed_signature, private_swap_verify_completed, private_swap_verify_presignature,
    pskt_finalize_and_broadcast, pskt_relay_to_kspt,
} from '../../../wasm/api.js';
import {
    acceptPrivateSwapBindingResponse, acceptPrivateSwapCompletedResponse, acceptPrivateSwapKeyResponse,
    acceptPrivateSwapPreSignResponse, clearPrivateSwapDeviceFlow, pendingPrivateSwapDeviceAction,
    privateSwapBindingRequest, privateSwapCompleteRequest, privateSwapKeyRequest, privateSwapPreSignRequest,
} from './device_flow.js';
import {
    assertCovenantMatches, assertRefundOrdering, buildCanonicalCovenant, makeAlicePreSignaturePackage,
    makeFinal, makeOffer, makeReadyPackage, makeResponse, parseAlicePreSignaturePackage, parseFinal,
    parseOffer, parseReadyPackage, parseResponse, randomHex, sha256Hex,
} from './protocol.js';
import {
    clearPrivateSwapState, loadPrivateSwapState, privateSwapState, resetPrivateSwapState, savePrivateSwapState,
} from './state.js';
import { startPrivateSwapWatcher, stopPrivateSwapWatcher } from './watcher.js';
import {
    renderPrivateSwapUi, showPrivateSwapJsonQr as showJsonQr,
    showPrivateSwapProtocolQr as showProtocolQr, showPrivateSwapSection as showSection,
} from './ui.js';

const PRIVATE_SWAP_MAX_FEE_SOMPI = 500_000_000n;

export function openPrivateSwap() {
    loadPrivateSwapState();
    covShowPanel('private-swap');
    showSection(privateSwapState.role ? 'dashboard' : 'hub');
    renderPrivateSwap();
    maybeStartBobWatcher();
}

export function beginPrivateSwapCreate() {
    requireWallet(); resetPrivateSwapState(); clearPrivateSwapDeviceFlow();
    privateSwapState.role = 'alice'; privateSwapState.network = networkState.network; privateSwapState.swapId = randomHex(16);
    privateSwapState.myDestination = ownerReceiveAddr(); privateSwapState.myOwnerPubkey = requireOwnerPubkey();
    privateSwapState.stage = 'alice-setup'; savePrivateSwapState();
    showSection('create'); renderPrivateSwap();
}

export function beginPrivateSwapJoin() {
    requireWallet(); resetPrivateSwapState(); clearPrivateSwapDeviceFlow();
    startScanner('Scan Private Swap Offer', raw => {
        try {
            const offer = parseOffer(raw); stopScanner(); showScreen('covenant'); covShowPanel('private-swap');
            privateSwapState.role = 'bob'; privateSwapState.network = networkState.network; privateSwapState.swapId = offer.swapId;
            applyCounterparty(offer.alice); privateSwapState.adaptorPoint = offer.alice.adaptorPoint;
            privateSwapState.myDestination = ownerReceiveAddr(); privateSwapState.myOwnerPubkey = requireOwnerPubkey();
            privateSwapState.stage = 'bob-offer'; savePrivateSwapState(); showSection('join'); renderPrivateSwap();
            toast('Private Swap offer verified. Choose your amount and earlier refund time.', 'ok', 3000);
        } catch (error) { toast('Invalid Private Swap offer: ' + error.message, 'error', 5000); }
    });
}

export async function requestAliceSwapKey() {
    try {
        const amount = kasToSompi(byId('private-swap-create-amount').value.trim());
        if (amount === 0n) throw new Error('Enter an amount');
        const date = byId('private-swap-create-datetime').value;
        if (!date) throw new Error('Choose your refund time');
        const daa = exactUnsigned((await resolveFutureDaa(date)).daa, 'Alice refund DAA');
        privateSwapState.myAmountSompi = amount.toString(); privateSwapState.myTimeoutDaa = daa.toString();
        privateSwapState.stage = 'alice-key-request'; savePrivateSwapState();
        showProtocolQr(privateSwapKeyRequest(), 'Private Swap Key', 'KasSigner: Single Signature → Private Swap. A dedicated swap-only key is allocated.');
    } catch (error) { toast(error.message || String(error), 'error', 4500); }
}

export async function requestBobSwapKey() {
    try {
        const amount = kasToSompi(byId('private-swap-join-amount').value.trim());
        if (amount === 0n) throw new Error('Enter an amount');
        const date = byId('private-swap-join-datetime').value;
        if (!date) throw new Error('Choose your refund time');
        const daa = exactUnsigned((await resolveFutureDaa(date)).daa, 'Bob refund DAA');
        assertRefundOrdering(privateSwapState.counterTimeoutDaa, daa);
        privateSwapState.myAmountSompi = amount.toString(); privateSwapState.myTimeoutDaa = daa.toString();
        privateSwapState.stage = 'bob-key-request'; savePrivateSwapState();
        showProtocolQr(privateSwapKeyRequest(), 'Private Swap Key', 'KasSigner allocates Bob’s isolated swap-only claim key.');
    } catch (error) { toast(error.message || String(error), 'error', 4500); }
}

export function sharePrivateSwapOffer() { showJsonQr(makeOffer(privateSwapState), 'Private Swap Offer', 'Bob scans this offer. No secret or preimage is included.'); }
export function sharePrivateSwapResponse() { showJsonQr(makeResponse(privateSwapState), 'Private Swap Response', 'Alice scans Bob’s key and Bob-funded covenant.'); }
export function sharePrivateSwapFinal() { showJsonQr(makeFinal(privateSwapState), 'Private Swap Final Handshake', 'Bob scans Alice’s funded-side covenant, then binds his claim key to it.'); }

export function scanPrivateSwapResponse() {
    startScanner('Scan Bob Private Swap Response', raw => {
        try { void acceptBobResponse(raw); } catch (error) { toast(error.message || String(error), 'error', 5000); }
    });
}

export function scanPrivateSwapFinal() {
    startScanner('Scan Alice Private Swap Final', raw => {
        try { void acceptAliceFinal(raw); } catch (error) { toast(error.message || String(error), 'error', 5000); }
    });
}

export function requestPrivateSwapBinding() {
    try { showProtocolQr(privateSwapBindingRequest(privateSwapState), 'Bind Private Swap Key', 'KasSigner verifies the exact counterparty covenant before binding this swap-only key.'); }
    catch (error) { toast(error.message || String(error), 'error', 4500); }
}

export function scanPrivateSwapDeviceResponse() {
    const action = pendingPrivateSwapDeviceAction();
    if (!action) { toast('No pending KasSigner Private Swap request', 'error'); return; }
    startScanner('Scan KasSigner Private Swap Response', raw => { void handleDeviceResponse(action, raw); });
}

export async function fundPrivateSwapSide() {
    try {
        if (!privateSwapState.myAddress || !privateSwapState.myRedeem) throw new Error('Complete the swap handshake first');
        if (privateSwapState.role === 'bob') {
            if (!privateSwapState.myPreSignature) throw new Error('Bob must prepare his exact claim pre-signature before funding');
            await expectedFunding(privateSwapState.counterAddress, privateSwapState.counterAmountSompi, 'Alice');
        }
        const result = ownCovenantRecord();
        covenantState.lastCovenantResult = result; covAddActive('private-swap', result); covSaveActive(); covRenderActive();
        navigationState._broadcastReturnScreen = 'covenant';
        await handleCovFund();
        const amountInput = byId('input-amount'); if (amountInput) amountInput.value = sompiToKasString(BigInt(privateSwapState.myAmountSompi));
        toast(`Fund exactly ${sompiToKasString(BigInt(privateSwapState.myAmountSompi))} KAS for this swap side.`, 'info', 5000);
    } catch (error) { toast(error.message || String(error), 'error', 5000); }
}

export async function preparePrivateSwapPreSignature() {
    try {
        if (!privateSwapState.myBindingToken) throw new Error('Bind the isolated claim key first');
        if (privateSwapState.role === 'alice') await expectedFunding(privateSwapState.myAddress, privateSwapState.myAmountSompi, 'Alice');
        const claim = await buildMyClaim();
        Object.assign(privateSwapState, claim); savePrivateSwapState();
        showProtocolQr(privateSwapPreSignRequest(privateSwapState), 'Private Swap Pre-Signature', 'KasSigner independently parses this exact claim transaction before producing an adaptor pre-signature.');
    } catch (error) { toast(error.message || String(error), 'error', 5000); }
}

export function shareAlicePreSignature() {
    if (privateSwapState.role !== 'alice' || !privateSwapState.myPreSignature) { toast('Alice pre-signature is not ready', 'error'); return; }
    showJsonQr(makeAlicePreSignaturePackage(privateSwapState), 'Alice Adaptor Pre-Signature', 'Bob independently reconstructs Alice’s exact claim before accepting this pre-signature.');
}

export function scanAlicePreSignature() {
    if (privateSwapState.role !== 'bob') { toast('Only Bob imports Alice’s pre-signature', 'error'); return; }
    startScanner('Scan Alice Private Swap Pre-Signature', raw => { void acceptAlicePreSignature(raw); });
}

export async function shareBobReady() {
    try {
        if (privateSwapState.role !== 'bob' || !privateSwapState.myPreSignature || !privateSwapState.counterPreSignature) throw new Error('Bob must hold both verified adaptor pre-signatures first');
        showJsonQr(await makeReadyPackage(privateSwapState), 'Bob Ready Acknowledgement', 'Alice verifies Bob’s exact claim pre-signature before revealing the adaptor secret on-chain.');
    } catch (error) { toast(error.message || String(error), 'error', 5000); }
}

export function scanBobReady() {
    if (privateSwapState.role !== 'alice') { toast('Only Alice scans Bob’s ready acknowledgement', 'error'); return; }
    startScanner('Scan Bob Private Swap Ready', raw => { void acceptBobReady(raw); });
}

export async function completeAlicePrivateSwap() {
    if (privateSwapState.role !== 'alice' || !privateSwapState.readyAckHash) { toast('Verify Bob’s ready acknowledgement first', 'error'); return; }
    try {
        await ensureMyClaimTransaction();
        showProtocolQr(privateSwapCompleteRequest(privateSwapState), 'Complete Private Swap Claim', 'KasSigner completes Alice’s adaptor pre-signature. The final on-chain signature is ordinary BIP340.');
    } catch (error) { toast(error.message || String(error), 'error', 5000); }
}

export async function bobClaimPrivateSwap() {
    if (privateSwapState.role !== 'bob' || !privateSwapState.counterCompletedSignature) { toast('Alice’s completed signature has not been observed on-chain yet', 'error'); return; }
    let extracted = '';
    try {
        await ensureMyClaimTransaction();
        extracted = private_swap_extract_secret(privateSwapState.counterPreSignature, Boolean(privateSwapState.counterPreSignatureNegated), privateSwapState.counterCompletedSignature);
        const completed = private_swap_complete_public(privateSwapState.myPreSignature, Boolean(privateSwapState.myPreSignatureNegated), extracted);
        if (!private_swap_verify_completed(privateSwapState.myClaimPubkey, privateSwapState.myClaimSighash, completed)) throw new Error('Completed Bob signature failed exact-transaction BIP340 verification');
        await broadcastCompletedClaim(privateSwapState.myClaimPskb, privateSwapState.myClaimPubkey, completed);
        privateSwapState.completed = true; savePrivateSwapState(); renderPrivateSwap();
        toast('Private Swap complete. Bob claimed Alice’s covenant with the extracted adaptor secret.', 'ok', 7000);
    } catch (error) { toast('Bob claim failed: ' + (error.message || error), 'error', 6000); }
    finally { extracted = ''; }
}

export function openPrivateSwapRefund() {
    if (!privateSwapState.myAddress || !privateSwapState.myRedeem) { toast('No funded-side covenant to refund', 'error'); return; }
    covShowPanel('timeout');
    byId('cov-timeout-addr').value = privateSwapState.myAddress;
    byId('cov-timeout-script').value = privateSwapState.myRedeem;
    byId('cov-timeout-locktime').value = privateSwapState.myTimeoutDaa;
    byId('cov-timeout-dest').value = privateSwapState.myDestination;
}

export function clearPrivateSwap() { stopPrivateSwapWatcher(); clearPrivateSwapDeviceFlow(); clearPrivateSwapState(); showSection('hub'); renderPrivateSwap(); }
export function privateSwapBackToHub() { showSection('hub'); renderPrivateSwap(); }

export function renderPrivateSwap() { renderPrivateSwapUi(privateSwapState, pendingPrivateSwapDeviceAction()); }

async function acceptBobResponse(raw) {
    const parsed = parseResponse(raw, privateSwapState.swapId);
    assertRefundOrdering(privateSwapState.myTimeoutDaa, parsed.bob.timeoutDaa);
    const expectedBob = buildCanonicalCovenant({ ownerPubkey: parsed.bob.ownerPubkey, claimerPubkey: privateSwapState.myClaimPubkey, destination: privateSwapState.myDestination, timeoutDaa: parsed.bob.timeoutDaa, salt: parsed.covenant.salt });
    assertCovenantMatches(parsed.covenant, expectedBob);
    applyCounterparty(parsed.bob); privateSwapState.counterSalt = parsed.covenant.salt;
    privateSwapState.counterAddress = parsed.covenant.address; privateSwapState.counterRedeem = parsed.covenant.redeemScript;
    privateSwapState.mySalt = randomHex(16);
    const aliceCovenant = buildCanonicalCovenant({ ownerPubkey: privateSwapState.myOwnerPubkey, claimerPubkey: privateSwapState.counterClaimPubkey, destination: privateSwapState.counterDestination, timeoutDaa: privateSwapState.myTimeoutDaa, salt: privateSwapState.mySalt });
    privateSwapState.myAddress = aliceCovenant.address; privateSwapState.myRedeem = aliceCovenant.redeem_script_hex;
    privateSwapState.stage = 'alice-needs-binding'; savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    toast('Bob response and covenant verified. Bind Alice’s swap-only claim key to Bob’s exact covenant.', 'ok', 3500);
}

async function acceptAliceFinal(raw) {
    const parsed = parseFinal(raw, privateSwapState.swapId);
    const expectedAlice = buildCanonicalCovenant({ ownerPubkey: privateSwapState.counterOwnerPubkey, claimerPubkey: privateSwapState.myClaimPubkey, destination: privateSwapState.myDestination, timeoutDaa: privateSwapState.counterTimeoutDaa, salt: parsed.salt });
    assertCovenantMatches(parsed, expectedAlice);
    privateSwapState.counterSalt = parsed.salt; privateSwapState.counterAddress = parsed.address; privateSwapState.counterRedeem = parsed.redeemScript;
    privateSwapState.stage = 'bob-needs-binding'; savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    toast('Alice covenant verified. Bind Bob’s swap-only claim key before proceeding.', 'ok', 3500);
}

async function handleDeviceResponse(action, raw) {
    try {
        if (action === 'key') await handleKeyResponse(raw);
        else if (action === 'binding') await handleBindingResponse(raw);
        else if (action === 'presign-nonce' || action === 'presign-final') await handlePreSignResponse(raw);
        else if (action === 'complete') await handleCompletedResponse(raw);
        else throw new Error('Unknown pending Private Swap device action');
    } catch (error) { toast(error.message || String(error), 'error', 5500); }
}

async function handleKeyResponse(raw) {
    const response = acceptPrivateSwapKeyResponse(raw);
    privateSwapState.myKeyId = response.key_id; privateSwapState.myClaimPubkey = response.claim_pubkey;
    privateSwapState.myOwnAdaptorPoint = response.adaptor_point;
    if (privateSwapState.role === 'alice') {
        privateSwapState.adaptorPoint = response.adaptor_point; privateSwapState.stage = 'alice-offer-ready';
    } else {
        privateSwapState.mySalt = randomHex(16);
        const bobCovenant = buildCanonicalCovenant({ ownerPubkey: privateSwapState.myOwnerPubkey, claimerPubkey: privateSwapState.counterClaimPubkey, destination: privateSwapState.counterDestination, timeoutDaa: privateSwapState.myTimeoutDaa, salt: privateSwapState.mySalt });
        privateSwapState.myAddress = bobCovenant.address; privateSwapState.myRedeem = bobCovenant.redeem_script_hex; privateSwapState.stage = 'bob-response-ready';
    }
    savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    toast('KasSigner swap-only key loaded', 'ok', 2200);
}

async function handleBindingResponse(raw) {
    const response = await acceptPrivateSwapBindingResponse(raw, privateSwapState);
    privateSwapState.myBindingToken = response.binding_token;
    privateSwapState.stage = privateSwapState.role === 'alice' ? 'alice-bound' : 'bob-bound';
    savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    toast('Swap claim key bound to the exact counterparty covenant', 'ok', 2500);
}

async function handlePreSignResponse(raw) {
    const result = acceptPrivateSwapPreSignResponse(raw, privateSwapState);
    if (result.kind === 'reveal') {
        stopScanner(); showProtocolQr(result.payload, 'Private Swap Nonce Reveal', 'KasSigner verifies the committed host nonce contribution, then returns the adaptor pre-signature.');
        return;
    }
    privateSwapState.myPreSignature = result.response.signature; privateSwapState.myPreSignatureNegated = Boolean(result.response.negated);
    privateSwapState.stage = privateSwapState.role === 'alice' ? 'alice-presigned' : 'bob-presigned';
    savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    if (privateSwapState.role === 'bob') toast('Bob claim pre-signature is safely stored. Verify Alice funding, then fund Bob’s side.', 'ok', 4000);
    else toast('Alice exact-transaction pre-signature is ready to share with Bob.', 'ok', 3500);
}

async function handleCompletedResponse(raw) {
    const response = acceptPrivateSwapCompletedResponse(raw, privateSwapState);
    if (!private_swap_verify_completed(privateSwapState.myClaimPubkey, privateSwapState.myClaimSighash, response.signature)) throw new Error('KasSigner completed signature failed exact-transaction verification');
    await broadcastCompletedClaim(privateSwapState.myClaimPskb, privateSwapState.myClaimPubkey, response.signature);
    privateSwapState.completed = true; savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
    toast('Alice claim broadcast. Bob can extract the adaptor secret from this ordinary Schnorr signature.', 'ok', 7000);
}

async function buildMyClaim() {
    const utxo = await expectedFunding(privateSwapState.counterAddress, privateSwapState.counterAmountSompi, 'counterparty');
    const fee = getCovFee(1); if (fee > PRIVATE_SWAP_MAX_FEE_SOMPI) throw new Error('Current claim fee exceeds the Private Swap covenant hard ceiling');
    if (fee >= BigInt(privateSwapState.counterAmountSompi)) throw new Error('Swap amount is too small for the claim fee');
    const pskb = await create_private_swap_claim(privateSwapState.counterAddress, privateSwapState.myDestination, privateSwapState.counterRedeem, JSON.stringify([utxo]), fee);
    const kspt = pskt_relay_to_kspt(pskb, networkState.network);
    const sighash = private_swap_claim_sighash(kspt);
    return {
        counterOutpoint: { txid: String(utxo.tx_id).toLowerCase(), index: Number(utxo.index || 0) },
        myClaimPskb: pskb, myClaimKspt: kspt, myClaimSighash: sighash, myClaimFeeSompi: fee.toString(),
    };
}

async function ensureMyClaimTransaction() {
    if (privateSwapState.myClaimPskb && privateSwapState.myClaimKspt) {
        const current = private_swap_claim_sighash(privateSwapState.myClaimKspt);
        if (current !== privateSwapState.myClaimSighash) throw new Error('Stored Private Swap claim no longer matches its reviewed sighash');
        return;
    }
    if (!privateSwapState.counterOutpoint || !privateSwapState.myClaimFeeSompi || !privateSwapState.myClaimSighash) {
        throw new Error('Recovered Private Swap is missing the exact claim transcript');
    }
    const utxo = await expectedFunding(privateSwapState.counterAddress, privateSwapState.counterAmountSompi, 'counterparty');
    assertOutpoint(privateSwapState.counterOutpoint, utxo);
    const fee = exactUnsigned(privateSwapState.myClaimFeeSompi, 'stored Private Swap claim fee');
    if (fee > PRIVATE_SWAP_MAX_FEE_SOMPI || fee >= BigInt(privateSwapState.counterAmountSompi)) {
        throw new Error('Recovered Private Swap claim fee violates the covenant policy');
    }
    const pskb = await create_private_swap_claim(
        privateSwapState.counterAddress, privateSwapState.myDestination, privateSwapState.counterRedeem,
        JSON.stringify([utxo]), fee,
    );
    const kspt = pskt_relay_to_kspt(pskb, networkState.network);
    const sighash = private_swap_claim_sighash(kspt);
    if (sighash !== privateSwapState.myClaimSighash) {
        throw new Error('Recovered Private Swap claim rebuild changed the reviewed transaction sighash');
    }
    privateSwapState.myClaimPskb = pskb;
    privateSwapState.myClaimKspt = kspt;
    savePrivateSwapState();
}

async function acceptAlicePreSignature(raw) {
    try {
        const pkg = parseAlicePreSignaturePackage(raw, privateSwapState.swapId);
        const ownFunding = await expectedFunding(privateSwapState.myAddress, privateSwapState.myAmountSompi, 'Bob');
        assertOutpoint(pkg.outpoint, ownFunding);
        const expectedPskb = await create_private_swap_claim(privateSwapState.myAddress, privateSwapState.counterDestination, privateSwapState.myRedeem, JSON.stringify([ownFunding]), pkg.feeSompi);
        const expectedKspt = pskt_relay_to_kspt(expectedPskb, networkState.network);
        const expectedSighash = private_swap_claim_sighash(expectedKspt);
        if (expectedSighash !== pkg.sighash) throw new Error('Alice pre-signature is not bound to Bob’s exact funded claim transaction');
        if (!private_swap_verify_presignature(privateSwapState.counterClaimPubkey, pkg.sighash, pkg.presignature, pkg.negated, privateSwapState.adaptorPoint)) throw new Error('Alice adaptor pre-signature is invalid');
        privateSwapState.counterPreSignature = pkg.presignature; privateSwapState.counterPreSignatureNegated = pkg.negated;
        privateSwapState.counterClaimSighash = pkg.sighash; privateSwapState.counterClaimKspt = expectedKspt; privateSwapState.counterClaimFeeSompi = pkg.feeSompi.toString();
        privateSwapState.myOutpoint = { txid: String(ownFunding.tx_id).toLowerCase(), index: Number(ownFunding.index || 0) };
        privateSwapState.stage = 'bob-alice-presig-verified'; savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap(); maybeStartBobWatcher();
        toast('Alice pre-signature independently verified against Bob’s exact funded UTXO.', 'ok', 4500);
    } catch (error) { toast('Alice pre-signature rejected: ' + (error.message || error), 'error', 6000); }
}

async function acceptBobReady(raw) {
    try {
        const pkg = parseReadyPackage(raw, privateSwapState.swapId);
        const ownHash = await sha256Hex(privateSwapState.myPreSignature);
        if (pkg.alicePresigHash !== ownHash) throw new Error('Bob did not acknowledge Alice’s exact pre-signature');
        const aliceFunding = await expectedFunding(privateSwapState.myAddress, privateSwapState.myAmountSompi, 'Alice');
        assertOutpoint(pkg.outpoint, aliceFunding);
        const expectedPskb = await create_private_swap_claim(privateSwapState.myAddress, privateSwapState.counterDestination, privateSwapState.myRedeem, JSON.stringify([aliceFunding]), pkg.feeSompi);
        const expectedKspt = pskt_relay_to_kspt(expectedPskb, networkState.network);
        const expectedSighash = private_swap_claim_sighash(expectedKspt);
        if (expectedSighash !== pkg.sighash) throw new Error('Bob ready acknowledgement is not bound to Alice’s exact funded UTXO');
        if (!private_swap_verify_presignature(privateSwapState.counterClaimPubkey, pkg.sighash, pkg.presignature, pkg.negated, privateSwapState.adaptorPoint)) throw new Error('Bob adaptor pre-signature is invalid');
        privateSwapState.readyAckHash = pkg.alicePresigHash; privateSwapState.counterPreSignature = pkg.presignature; privateSwapState.counterPreSignatureNegated = pkg.negated;
        privateSwapState.stage = 'alice-bob-ready'; savePrivateSwapState(); stopScanner(); showScreen('covenant'); covShowPanel('private-swap'); showSection('dashboard'); renderPrivateSwap();
        toast('Bob readiness verified cryptographically. Alice may now complete the swap.', 'ok', 4500);
    } catch (error) { toast('Bob ready acknowledgement rejected: ' + (error.message || error), 'error', 6000); }
}

async function broadcastCompletedClaim(pskb, pubkey, signature) {
    const sealed = private_swap_insert_completed_signature(pskb, pubkey, signature);
    const wsUrl = await resolveNodeUrl();
    const txid = await pskt_finalize_and_broadcast(sealed, wsUrl);
    console.log('[KasSee] Private Swap claim broadcast:', txid);
    return txid;
}

async function expectedFunding(address, amountText, who) {
    if (!address || !amountText) throw new Error(`${who} covenant is not ready`);
    const wsUrl = await resolveNodeUrl();
    const utxos = JSON.parse(await fetch_utxos_for_address_js(address, wsUrl));
    const expected = exactUnsigned(amountText, `${who} expected funding`);
    const matches = Array.isArray(utxos) ? utxos.filter(utxo => exactUnsigned(utxo.amount, `${who} UTXO amount`) === expected) : [];
    if (matches.length !== 1) throw new Error(`${who} must have exactly one funding UTXO of ${sompiToKasString(expected)} KAS before this step`);
    return matches[0];
}

function ownCovenantRecord() {
    return {
        type: 'private-swap', address: privateSwapState.myAddress, redeem_script_hex: privateSwapState.myRedeem,
        locktime_daa: privateSwapState.myTimeoutDaa, role: privateSwapState.role,
        private_swap_recovery_json: JSON.stringify(publicRecoveryState()),
    };
}

function publicRecoveryState() {
    const omit = new Set(['myClaimPskb', 'myClaimKspt', 'counterClaimKspt', 'counterCompletedSignature']);
    const out = {};
    for (const key of Object.keys(privateSwapState)) {
        if (omit.has(key) || key.toLowerCase().includes('secret')) continue;
        out[key] = privateSwapState[key];
    }
    return out;
}

function applyCounterparty(person) {
    privateSwapState.counterKeyId = person.keyId; privateSwapState.counterClaimPubkey = person.claimPubkey;
    privateSwapState.counterOwnerPubkey = person.ownerPubkey; privateSwapState.counterDestination = person.destination;
    privateSwapState.counterAmountSompi = person.amountSompi; privateSwapState.counterTimeoutDaa = person.timeoutDaa;
}

function assertOutpoint(expected, utxo) {
    if (expected.txid !== String(utxo.tx_id).toLowerCase() || expected.index !== Number(utxo.index || 0)) throw new Error('Funding outpoint changed');
}

function requireWallet() { if (!walletSession.hasWallet()) throw new Error('Load a watch-only wallet first'); }
function requireOwnerPubkey() { const value = getOwnerPubkeyHex(); if (!value) throw new Error('Could not derive wallet owner public key'); return value; }

function maybeStartBobWatcher() {
    if (privateSwapState.role === 'bob' && privateSwapState.myPreSignature && privateSwapState.counterPreSignature) {
        startPrivateSwapWatcher(() => { toast('Alice claim detected. Adaptor secret can now be extracted.', 'ok', 6000); renderPrivateSwap(); });
    }
}
