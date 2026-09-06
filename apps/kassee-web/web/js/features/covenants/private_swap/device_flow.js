import { bytesToHex } from '../../../core/bytes.js';
import {
    private_swap_bind_request,
    private_swap_complete_request,
    private_swap_key_request,
    private_swap_parse_response,
    private_swap_presign_request,
    private_swap_reveal_request,
    private_swap_verify_host_relation,
} from '../../../wasm/api.js';
import { covenantScriptFingerprint } from '../signing/protocol.js';
import { randomHex } from './protocol.js';

const responseKind = Object.freeze({ KEY: 0, BINDING: 1, NONCE: 2, PRESIG: 3, COMPLETED: 4 });
const flow = { mode: '', hostSecret: '', sessionId: '', sighash: '', noncePoint: '', keyId: '' };

export function privateSwapKeyRequest() {
    resetFlow('key');
    return private_swap_key_request();
}

export function acceptPrivateSwapKeyResponse(raw) {
    const response = parseResponse(raw);
    if (response.kind !== responseKind.KEY) throw new Error('Expected Private Swap key response');
    if (!isHex(response.key_id, 32) || !isHex(response.claim_pubkey, 32) || !isHex(response.adaptor_point, 32)) {
        throw new Error('KasSigner returned invalid Private Swap key material');
    }
    resetFlow('');
    return response;
}

export function privateSwapBindingRequest(state) {
    if (!state.counterRedeem) throw new Error('Counterparty covenant is not available yet');
    resetFlow('binding');
    flow.keyId = state.myKeyId;
    return private_swap_bind_request(state.myKeyId, state.myOwnAdaptorPoint, state.counterRedeem);
}

export async function acceptPrivateSwapBindingResponse(raw, state) {
    const response = parseResponse(raw);
    if (response.kind !== responseKind.BINDING) throw new Error('Expected Private Swap binding response');
    assertIdentity(response, state);
    if (response.adaptor_point !== state.myOwnAdaptorPoint) throw new Error('Binding response changed the device-derived adaptor point');
    const expected = await covenantScriptFingerprint(state.counterRedeem);
    if (response.commitment !== expected) throw new Error('Binding response belongs to a different covenant script');
    if (!isHex(response.binding_token, 32)) throw new Error('Private Swap binding token is invalid');
    resetFlow('');
    return response;
}

export function privateSwapPreSignRequest(state) {
    if (!state.myClaimKspt || !state.myClaimSighash) throw new Error('Build the exact counterparty claim first');
    const hostSecret = randomHex(32);
    const prepared = JSON.parse(private_swap_presign_request(
        state.myKeyId, state.myBindingToken, state.adaptorPoint, state.myClaimKspt, hostSecret,
    ));
    flow.mode = 'presign-nonce'; flow.hostSecret = hostSecret; flow.sessionId = prepared.session_id;
    flow.sighash = state.myClaimSighash; flow.noncePoint = ''; flow.keyId = state.myKeyId;
    return prepared.request_hex;
}

export function acceptPrivateSwapPreSignResponse(raw, state) {
    const response = parseResponse(raw);
    assertIdentity(response, state);
    if (response.adaptor_point !== state.adaptorPoint) throw new Error('Private Swap response changed Alice adaptor point');
    if (response.commitment !== flow.sighash || response.session_id !== flow.sessionId) throw new Error('Private Swap response belongs to another exact transaction/session');
    if (flow.mode === 'presign-nonce') {
        if (response.kind !== responseKind.NONCE || !isHex(response.nonce_point, 33)) throw new Error('Expected Private Swap nonce response');
        flow.noncePoint = response.nonce_point; flow.mode = 'presign-final';
        return { kind: 'reveal', payload: private_swap_reveal_request(flow.sessionId, flow.keyId, flow.sighash, flow.hostSecret) };
    }
    if (flow.mode !== 'presign-final' || response.kind !== responseKind.PRESIG) throw new Error('Expected final Private Swap pre-signature response');
    if (response.nonce_point !== flow.noncePoint || !isHex(response.signature, 64)) throw new Error('Private Swap final response changed the committed nonce');
    const ok = private_swap_verify_host_relation(
        response.claim_pubkey, response.commitment, response.adaptor_point, response.session_id,
        flow.hostSecret, response.nonce_point, response.signature, Boolean(response.negated),
    );
    if (!ok) throw new Error('Private Swap anti-klepto nonce relation failed');
    resetFlow('');
    return { kind: 'presignature', response };
}

export function privateSwapCompleteRequest(state) {
    if (!state.myClaimKspt || !state.myPreSignature) throw new Error('Alice pre-signature/claim transaction is missing');
    resetFlow('complete'); flow.keyId = state.myKeyId; flow.sighash = state.myClaimSighash;
    return private_swap_complete_request(
        state.myKeyId, state.myBindingToken, state.adaptorPoint, state.myClaimKspt,
        state.myPreSignature, Boolean(state.myPreSignatureNegated),
    );
}

export function acceptPrivateSwapCompletedResponse(raw, state) {
    const response = parseResponse(raw);
    if (response.kind !== responseKind.COMPLETED) throw new Error('Expected completed Private Swap signature');
    assertIdentity(response, state);
    if (response.adaptor_point !== state.adaptorPoint || response.commitment !== state.myClaimSighash || !isHex(response.signature, 64)) {
        throw new Error('Completed signature belongs to another Private Swap claim');
    }
    resetFlow('');
    return response;
}

export function pendingPrivateSwapDeviceAction() { return flow.mode; }
export function clearPrivateSwapDeviceFlow() { resetFlow(''); }

function assertIdentity(response, state) {
    if (response.key_id !== state.myKeyId || response.claim_pubkey !== state.myClaimPubkey) {
        throw new Error('KasSigner response used a different isolated Private Swap key');
    }
    if (state.myBindingToken && response.binding_token !== state.myBindingToken) {
        throw new Error('KasSigner response used a different Private Swap binding record');
    }
}

function parseResponse(raw) {
    return JSON.parse(private_swap_parse_response(toHex(raw)));
}

function toHex(raw) {
    if (typeof raw === 'string') return /^[0-9a-f]+$/i.test(raw.trim()) ? raw.trim() : bytesToHex(new TextEncoder().encode(raw));
    const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    const text = new TextDecoder().decode(bytes).trim();
    return /^[0-9a-f]+$/i.test(text) && text.length % 2 === 0 ? text : bytesToHex(bytes);
}

function isHex(value, bytes) { return new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(String(value || '')) && !/^0+$/.test(value); }
function resetFlow(mode) { Object.assign(flow, { mode, hostSecret: '', sessionId: '', sighash: '', noncePoint: '', keyId: '' }); }
