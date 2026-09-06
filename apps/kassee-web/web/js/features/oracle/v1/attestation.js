import { parseCovenantResponse, sha256Commitment } from '../../covenants/signing/protocol.js';

const MAX_TEXT_BYTES = 256;

export async function oracleV1MessageCommitment(text) {
    const message = new TextEncoder().encode(text);
    if (message.length === 0) throw new Error('Enter the exact attestation statement');
    if (message.length > MAX_TEXT_BYTES) throw new Error('Attestation statement exceeds 256 UTF-8 bytes');
    return sha256Commitment(message);
}

export function parseOracleV1Attestation(raw) {
    const parsed = parseCovenantResponse(raw);
    if (parsed.kind !== 'signature') throw new Error('Expected a covenant-signature response');
    return {
        signature: parsed.signature,
        commitment: parsed.commitment,
        keyId: parsed.keyId,
        pubkey: parsed.pubkey,
        bindingToken: parsed.bindingToken,
        sessionId: parsed.sessionId,
        noncePoint: parsed.noncePoint,
        text: '',
    };
}

export async function verifyOracleV1Attestation(attestation, statement) {
    if (!/^[0-9a-f]{128}$/.test(attestation.signature || '')) throw new Error('Oracle signature must be 64 bytes');
    if (!/^[0-9a-f]{64}$/.test(attestation.commitment || '')) throw new Error('Oracle commitment must be 32 bytes');
    const expected = await oracleV1MessageCommitment(statement);
    if (expected !== attestation.commitment) {
        throw new Error('Attestation does not match the exact statement shown');
    }
    return attestation;
}
