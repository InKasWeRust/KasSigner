import { covenantState, navigationState, walletSession } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { byId } from '../../../core/dom.js';
import { bytesToHex } from '../../../core/bytes.js';
import { toast } from '../../../core/ui/toast.js';
import { covShowPanel } from '../../covenants/generation/ui_and_keys.js';
import { covRenderActive, covSaveActive } from '../../covenants/recovery/active.js';
import { stringifyCovenantJson } from '../../covenants/model/exact_fields.js';
import { getCovFee, ownerReceiveAddr } from '../../covenants/payload_and_swaps/state.js';
import { runCovenantClaim } from '../../covenants/spending/standard/thread_and_claims/claim_controller.js';
import {
    CovenantKnownScheme, covenantBindRequestHex, covenantKeyRequestHex, covenantKnownRequestHex, covenantRevealHex,
    covenantScriptFingerprint, covenantSignatureResponseHex, createCovenantSigningChallenge, parseCovenantResponse,
} from '../../covenants/signing/protocol.js';
import { startScanner, stopScanner } from '../../stealth/index/camera.js';
import { pauseQrCycle } from '../../transactions/send/review.js';
import {
    create_covenant_oracle_v1_claim,
    create_covenant_pskb_with_payload,
    generate_qr_svg_text,
    verify_oracle_v1_attestation, verify_covenant_anti_klepto,
} from '../../../wasm/api.js';
import { oracleV1MessageCommitment, parseOracleV1Attestation, verifyOracleV1Attestation } from './attestation.js';

const state = { signature: '', commitment: '', statement: '', keyId: '', pubkey: '', bindingToken: '', sessionId: '', noncePoint: '', hostSecret: '' };
const ORACLE_V1_BEACON_DEPOSIT_SOMPI = 10_000_000n;

function currentOracle() {
    const result = covenantState.lastCovenantResult;
    if (!result || result.type !== 'oracle-v1') throw new Error('No Oracle-v1 covenant loaded');
    return result;
}

function setAttestation(parsed, statement) {
    state.signature = parsed.signature;
    state.commitment = parsed.commitment;
    state.keyId = parsed.keyId || '';
    state.pubkey = parsed.pubkey || '';
    state.bindingToken = parsed.bindingToken || '';
    state.sessionId = parsed.sessionId || state.sessionId || '';
    state.noncePoint = parsed.noncePoint || state.noncePoint || '';
    state.statement = statement;
}

function showProtocolQr(payloadHex, title, info, returnScreen = 'covenant') {
    pauseQrCycle();
    byId('qr-container').innerHTML = generate_qr_svg_text(payloadHex);
    byId('qr-frame-info').textContent = info;
    byId('qr-display-title').textContent = title;
    ['btn-scan-next-sig', 'btn-copy-kspt', 'btn-qr-scan-signed'].forEach(id => byId(id)?.style.setProperty('display', 'none'));
    byId('qr-tx-info')?.style.setProperty('display', 'none');
    navigationState._broadcastReturnScreen = returnScreen;
    showScreen('qr-display');
}

export function showOracleV1KeyRequest() {
    byId('cov-oracle-v1-key-id').value = '';
    byId('cov-oracle-v1-pubkey').value = '';
    const request = covenantKeyRequestHex();
    showProtocolQr(request, 'Allocate Oracle Covenant Key', 'Oracle scans: Single Signature → Covenant Sign. KasSigner chooses a fresh covenant instance ID.');
}

export function scanOracleV1KeyResponse() {
    startScanner('Scan Oracle covenant-key response', raw => {
        try {
            const response = parseCovenantResponse(raw);
            if (response.kind !== 'key') throw new Error('Expected covenant-key response');
            byId('cov-oracle-v1-key-id').value = response.keyId;
            byId('cov-oracle-v1-pubkey').value = response.pubkey;
            stopScanner(); showScreen('covenant'); covShowPanel('create');
            toast('Fresh isolated oracle covenant key loaded', 'ok', 1800);
        } catch (error) { toast(String(error.message || error), 'error', 4000); }
    });
}

export function showOracleV1BindingRequest() {
    const result = currentOracle();
    if (/^[0-9a-f]{64}$/.test(result.oracle_covenant_binding_token_hex || '')) {
        toast('Oracle covenant key is already bound to this exact script', 'ok', 2200); return;
    }
    const request = covenantBindRequestHex({
        keyIdHex: result.oracle_covenant_key_id_hex || '',
        commitmentHex: result.message_commitment_hex || '',
        scriptHex: result.redeem_script_hex || '',
        context: result.attestation_statement || '',
        scheme: CovenantKnownScheme.ORACLE_V1,
    });
    showProtocolQr(request, 'Bind Oracle Covenant Key', 'Oracle reviews the exact statement and script binding before funding.');
}

export function scanOracleV1BindingResponse() {
    startScanner('Scan Oracle covenant-key binding response', async raw => {
        try {
            const result = currentOracle();
            const response = parseCovenantResponse(raw);
            if (response.kind !== 'binding') throw new Error('Expected covenant binding response');
            if (response.keyId !== (result.oracle_covenant_key_id_hex || '').toLowerCase()) throw new Error('Binding response used a different covenant key instance');
            if (response.pubkey !== (result.oracle_pubkey_hex || '').toLowerCase()) throw new Error('Binding response came from a different covenant key');
            const expectedScriptHash = await covenantScriptFingerprint(result.redeem_script_hex || '');
            if (response.commitment !== expectedScriptHash) throw new Error('Binding response belongs to a different covenant script');
            persistOracleBinding(result, response.bindingToken);
            stopScanner(); showScreen('covenant'); covShowPanel('result');
            toast('Oracle covenant key bound to this exact script', 'ok', 2400);
        } catch (error) { toast(String(error.message || error), 'error', 4500); }
    });
}

function persistOracleBinding(result, bindingToken) {
    if (!/^[0-9a-f]{64}$/.test(bindingToken || '')) throw new Error('Invalid covenant binding record');
    result.oracle_covenant_binding_token_hex = bindingToken.toLowerCase();
    try { sessionStorage.setItem('lastCovenantResult', stringifyCovenantJson(result)); } catch (_) {}
    const active = covenantState.activeCovenants?.find(item => item.address === result.address);
    if (active) active.oracle_covenant_binding_token_hex = result.oracle_covenant_binding_token_hex;
    covSaveActive(); covRenderActive();
    byId('btn-cov-res-oracle-v1-bind')?.classList.add('hidden');
    byId('btn-cov-res-oracle-v1-scan-binding')?.classList.add('hidden');
    const fund = byId('btn-cov-fund'); if (fund) fund.style.display = '';
}

async function acceptScannedAttestation(raw, textField, statusField) {
    const parsed = parseOracleV1Attestation(raw);
    const statement = textField.value;
    const result = currentOracle();
    await verifyOracleV1Attestation(parsed, statement);
    if (parsed.keyId !== (result.oracle_covenant_key_id_hex || '').toLowerCase()) {
        throw new Error('Signature used a different covenant key instance');
    }
    if (parsed.pubkey !== (result.oracle_pubkey_hex || '').toLowerCase()) {
        throw new Error('Signature came from a different covenant key');
    }
    if ((result.oracle_covenant_binding_token_hex || '').toLowerCase() !== parsed.bindingToken) {
        throw new Error('Signature used a different covenant binding record');
    }
    if ((result.message_commitment_hex || '').toLowerCase() !== parsed.commitment) {
        throw new Error('Attestation belongs to a different Oracle covenant');
    }
    if (!verify_oracle_v1_attestation(result.oracle_pubkey_hex || '', parsed.signature, parsed.commitment)) {
        throw new Error('Oracle signature is invalid for this covenant key');
    }
    setAttestation(parsed, statement);
    if (statusField) statusField.textContent = '✓ Covenant signature matches this exact statement and isolated key.';
    return parsed;
}

export function openOracleV1Claim() {
    const result = currentOracle();
    covShowPanel('oracle-v1-claim');
    byId('cov-oracle-v1-claim-addr').value = result.address || '';
    byId('cov-oracle-v1-claim-script').value = result.redeem_script_hex || '';
    byId('cov-oracle-v1-claim-dest').value = ownerReceiveAddr() || '';
    byId('cov-oracle-v1-claim-text').value = result.attestation_statement || '';
    const savedSignature = result.oracle_attestation_signature || '';
    const savedCommitment = result.oracle_attestation_commitment || '';
    byId('cov-oracle-v1-claim-sig').value = savedSignature;
    byId('cov-oracle-v1-claim-commitment').value = savedCommitment;
    byId('cov-oracle-v1-claim-status').textContent = savedSignature
        ? 'Saved oracle beacon found. It will be verified again before claim creation.'
        : 'Scan the oracle COVENANT SIGN response, or wait for an on-chain oracle beacon.';
    state.signature = savedSignature;
    state.commitment = savedCommitment;
    state.statement = result.attestation_statement || '';
    state.keyId = result.oracle_covenant_key_id_hex || '';
    state.pubkey = result.oracle_pubkey_hex || '';
    state.bindingToken = result.oracle_covenant_binding_token_hex || '';
}

export function openOracleV1Attest() {
    const result = currentOracle();
    state.hostSecret = ''; state.sessionId = ''; state.noncePoint = '';
    covShowPanel('oracle-v1-attest');
    byId('cov-oracle-v1-attest-text').value = result.attestation_statement || '';
    byId('cov-oracle-v1-attest-status').textContent = 'Show the COVENANT SIGN request, review it on KasSigner, then complete the nonce/reveal QR exchange.';
    byId('btn-cov-oracle-v1-beacon').classList.add('hidden');
    byId('btn-cov-oracle-v1-share').classList.add('hidden');
    setAttestation({ signature: '', commitment: '', keyId: result.oracle_covenant_key_id_hex || '', pubkey: result.oracle_pubkey_hex || '', bindingToken: result.oracle_covenant_binding_token_hex || '' }, '');
}

export async function showOracleV1SignRequest() {
    const result = currentOracle();
    if (!/^[0-9a-f]{64}$/.test(result.oracle_covenant_binding_token_hex || '')) {
        toast('This Oracle covenant is missing its KasSigner key binding record', 'error', 4500); return;
    }
    const challenge = await createCovenantSigningChallenge();
    state.hostSecret = challenge.hostSecret;
    state.sessionId = challenge.sessionId;
    state.noncePoint = '';
    const request = covenantKnownRequestHex({
        sessionIdHex: challenge.sessionId, hostCommitmentHex: challenge.hostCommitment,
        keyIdHex: result.oracle_covenant_key_id_hex || '',
        bindingTokenHex: result.oracle_covenant_binding_token_hex || '',
        commitmentHex: result.message_commitment_hex || '',
        scriptHex: result.redeem_script_hex || '',
        context: result.attestation_statement || '',
        scheme: CovenantKnownScheme.ORACLE_V1,
    });
    showProtocolQr(request, 'Oracle Covenant Sign', 'Oracle scans this exact known-covenant request.');
}

export function scanOracleV1ClaimAttestation() {
    startScanner('Scan Oracle covenant signature', async raw => {
        try {
            const textField = byId('cov-oracle-v1-claim-text');
            const parsed = await acceptScannedAttestation(raw, textField, byId('cov-oracle-v1-claim-status'));
            byId('cov-oracle-v1-claim-sig').value = parsed.signature;
            byId('cov-oracle-v1-claim-commitment').value = parsed.commitment;
            stopScanner(); showScreen('covenant'); covShowPanel('oracle-v1-claim');
            toast('Oracle covenant signature verified', 'ok', 1800);
        } catch (error) { toast(String(error.message || error), 'error', 4500); }
    });
}

export function scanOracleV1CovenantSignResponse() {
    startScanner('Scan KasSigner COVENANT SIGN response', async raw => {
        try {
            const result = currentOracle();
            const response = parseCovenantResponse(raw);
            if (response.kind !== 'nonce' && response.kind !== 'signature') {
                throw new Error('Expected nonce or final covenant-sign response');
            }
            validateOracleTranscriptIdentity(response, result);
            if (response.kind === 'nonce') {
                state.noncePoint = response.noncePoint;
                const reveal = covenantRevealHex({
                    sessionId: state.sessionId, keyId: response.keyId,
                    commitment: response.commitment, hostSecret: state.hostSecret,
                });
                stopScanner();
                byId('cov-oracle-v1-attest-status').textContent = 'Nonce committed. Scan the reveal on KasSigner, then scan its final response.';
                showProtocolQr(reveal, 'Covenant Nonce Reveal', 'Oracle scans this reveal to complete anti-klepto signing.');
                return;
            }
            if (!state.hostSecret || !state.noncePoint) throw new Error('Covenant signing session is missing; restart the request');
            const antiKleptoOk = verify_covenant_anti_klepto(
                response.pubkey, response.commitment, response.noncePoint, response.signature,
                response.sessionId, state.hostSecret,
            );
            if (!antiKleptoOk) throw new Error('Covenant signature failed host nonce verification');
            const textField = byId('cov-oracle-v1-attest-text');
            const parsed = await acceptScannedAttestation(raw, textField, byId('cov-oracle-v1-attest-status'));
            stopScanner(); showScreen('covenant'); covShowPanel('oracle-v1-attest');
            byId('btn-cov-oracle-v1-beacon').classList.remove('hidden');
            byId('btn-cov-oracle-v1-share').classList.remove('hidden');
            setAttestation(parsed, textField.value);
            toast('Covenant commitment signature + host nonce verified', 'ok', 2200);
        } catch (error) { toast(String(error.message || error), 'error', 4500); }
    });
}

function validateOracleTranscriptIdentity(response, result) {
    if (!state.sessionId || response.sessionId !== state.sessionId) throw new Error('Response belongs to a different covenant signing session');
    if (response.keyId !== (result.oracle_covenant_key_id_hex || '').toLowerCase()) throw new Error('Response used a different covenant key instance');
    if (response.pubkey !== (result.oracle_pubkey_hex || '').toLowerCase()) throw new Error('Response came from a different covenant key');
    if (response.bindingToken !== (result.oracle_covenant_binding_token_hex || '').toLowerCase()) throw new Error('Response used a different covenant binding record');
    if (response.commitment !== (result.message_commitment_hex || '').toLowerCase()) throw new Error('Response belongs to a different Oracle covenant');
    if (state.noncePoint && response.kind === 'signature' && response.noncePoint !== state.noncePoint) throw new Error('Final response changed the committed nonce');
}

export async function buildOracleV1Claim() {
    const result = currentOracle();
    const statement = byId('cov-oracle-v1-claim-text').value;
    const signature = byId('cov-oracle-v1-claim-sig').value || state.signature;
    const commitment = byId('cov-oracle-v1-claim-commitment').value || state.commitment;
    const destination = byId('cov-oracle-v1-claim-dest').value.trim();
    if (!destination) { toast('Enter a claim destination', 'error'); return; }
    try {
        await verifyOracleV1Attestation({ signature, commitment }, statement);
        if (!verify_oracle_v1_attestation(result.oracle_pubkey_hex || '', signature, commitment)) {
            throw new Error('Oracle signature is not valid for this covenant key');
        }
    } catch (error) { toast(String(error.message || error), 'error'); return; }
    await runCovenantClaim({
        loadingMessage: 'Building oracle-attested claim PSKB...',
        errorLabel: 'Oracle claim failed', logLabel: 'Oracle-v1 claim PSKB',
        build: websocketUrl => create_covenant_oracle_v1_claim(
            result.address, destination, result.redeem_script_hex,
            result.oracle_pubkey_hex || '', signature, commitment, getCovFee(), websocketUrl,
        ),
    });
}

export async function publishOracleV1Beacon() {
    const result = currentOracle();
    try {
        if (!walletSession.hasWallet()) {
            throw new Error('Load any funding wallet in the oracle session to publish the signed beacon');
        }
        await verifyOracleV1Attestation(state, state.statement);
        if (state.keyId !== (result.oracle_covenant_key_id_hex || '').toLowerCase()
            || state.pubkey !== (result.oracle_pubkey_hex || '').toLowerCase()
            || state.bindingToken !== (result.oracle_covenant_binding_token_hex || '').toLowerCase()) {
            throw new Error('Loaded attestation belongs to a different covenant key');
        }
        if (!verify_oracle_v1_attestation(result.oracle_pubkey_hex || '', state.signature, state.commitment)) {
            throw new Error('Oracle signature is not valid for this covenant key');
        }
    } catch (error) { toast(String(error.message || error), 'error'); return; }

    const payloadHex = '4f525631' + state.signature + state.commitment
        + bytesToHex(new TextEncoder().encode(state.statement));
    const wallet = walletSession.current();
    const changeAddress = wallet.change_addresses?.[wallet.next_change_index || 0]
        || wallet.receive_addresses?.[0] || '';
    if (!changeAddress) { toast('Funding wallet has no change address', 'error'); return; }
    await runCovenantClaim({
        loadingMessage: 'Building oracle attestation beacon PSKB...', errorLabel: 'Oracle beacon failed',
        logLabel: 'Oracle-v1 beacon deposit PSKB',
        build: websocketUrl => create_covenant_pskb_with_payload(JSON.stringify({
            wallet_json: walletSession.json(), covenant_address: result.address,
            send_amount: ORACLE_V1_BEACON_DEPOSIT_SOMPI.toString(), fee: getCovFee(1).toString(),
            change_address: changeAddress, payload_hex: payloadHex, utxo_indices_csv: '',
            ws_url: websocketUrl, tag_genesis: false,
        })),
    });
}

export function showOracleV1AttestationQr() {
    if (!state.signature || !state.commitment || !state.keyId || !state.pubkey) {
        toast('Scan the covenant signature first', 'error'); return;
    }
    if (!state.sessionId || !state.noncePoint) { toast('Anti-klepto transcript is unavailable; sign again before sharing', 'error'); return; }
    const payload = covenantSignatureResponseHex({
        sessionId: state.sessionId, keyId: state.keyId, pubkey: state.pubkey, bindingToken: state.bindingToken,
        commitment: state.commitment, noncePoint: state.noncePoint, signature: state.signature,
    });
    showProtocolQr(payload, 'Oracle Attestation QR', 'Beneficiary scans this signed covenant response.');
}

export async function statementCommitmentForTest(text) {
    return oracleV1MessageCommitment(text);
}

