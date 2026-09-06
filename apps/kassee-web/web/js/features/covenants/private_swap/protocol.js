import { bytesToHex } from '../../../core/bytes.js';
import { exactUnsigned } from '../../../core/exact.js';
import { networkState } from '../../../app/state/index.js';
import { covenant_private_swap, decode_address, sha256_hash } from '../../../wasm/api.js';

export const PRIVATE_SWAP_WIRE_VERSION = 2;
export const MIN_REFUND_GAP_DAA = 18_000n;

export function randomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    if (bytes.every(byte => byte === 0)) bytes[0] = 1;
    return bytesToHex(bytes);
}

export function requireHex(value, bytes, label) {
    const text = String(value || '').toLowerCase();
    if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text) || /^0+$/.test(text)) {
        throw new Error(`${label} is invalid`);
    }
    return text;
}

export function requireAddress(value, label) {
    const address = String(value || '').trim();
    const decoded = JSON.parse(decode_address(address));
    if (!decoded?.payload || !address.startsWith('kaspa')) throw new Error(`${label} is invalid`);
    return address;
}

export function makeOffer(state) {
    return {
        v: PRIVATE_SWAP_WIRE_VERSION, t: 'private-swap-offer', swap_id: state.swapId, network: state.network,
        alice: participant(state),
    };
}

export function parseOffer(raw) {
    const value = parseJson(raw);
    if (value?.v !== PRIVATE_SWAP_WIRE_VERSION || value?.t !== 'private-swap-offer') throw new Error('Not a current Private Swap offer');
    if (value.network !== networkState.network) throw new Error('Private Swap offer is for a different network');
    return { swapId: requireHex(value.swap_id, 16, 'swap id'), alice: normalizeParticipant(value.alice, 'Alice') };
}

export function makeResponse(state) {
    return {
        v: PRIVATE_SWAP_WIRE_VERSION, t: 'private-swap-response', swap_id: state.swapId, network: state.network,
        bob: participant(state),
        bob_covenant: { address: state.myAddress, redeem_script_hex: state.myRedeem, salt: state.mySalt },
    };
}

export function parseResponse(raw, expectedSwapId) {
    const value = parseJson(raw);
    if (value?.v !== PRIVATE_SWAP_WIRE_VERSION || value?.t !== 'private-swap-response') throw new Error('Not a current Private Swap response');
    if (value.network !== networkState.network || requireHex(value.swap_id, 16, 'swap id') !== expectedSwapId) throw new Error('Private Swap response belongs to another session/network');
    return { bob: normalizeParticipant(value.bob, 'Bob'), covenant: normalizeCovenant(value.bob_covenant, 'Bob covenant') };
}

export function makeFinal(state) {
    return {
        v: PRIVATE_SWAP_WIRE_VERSION, t: 'private-swap-final', swap_id: state.swapId, network: state.network,
        alice_covenant: { address: state.myAddress, redeem_script_hex: state.myRedeem, salt: state.mySalt },
    };
}

export function parseFinal(raw, expectedSwapId) {
    const value = parseJson(raw);
    if (value?.v !== PRIVATE_SWAP_WIRE_VERSION || value?.t !== 'private-swap-final') throw new Error('Not a current Private Swap final handshake');
    if (value.network !== networkState.network || requireHex(value.swap_id, 16, 'swap id') !== expectedSwapId) throw new Error('Private Swap final belongs to another session/network');
    return normalizeCovenant(value.alice_covenant, 'Alice covenant');
}

export function makeAlicePreSignaturePackage(state) {
    if (!state.counterOutpoint) throw new Error('Bob funding outpoint is unavailable');
    return {
        v: PRIVATE_SWAP_WIRE_VERSION, t: 'private-swap-alice-presig', swap_id: state.swapId, network: state.network,
        outpoint: { txid: state.counterOutpoint.txid, index: state.counterOutpoint.index },
        fee_sompi: state.myClaimFeeSompi, sighash: state.myClaimSighash,
        presignature: state.myPreSignature, negated: Boolean(state.myPreSignatureNegated),
    };
}

export function parseAlicePreSignaturePackage(raw, expectedSwapId) {
    const value = parseJson(raw);
    if (value?.v !== PRIVATE_SWAP_WIRE_VERSION || value?.t !== 'private-swap-alice-presig') throw new Error('Not a current Alice Private Swap pre-signature');
    if (value.network !== networkState.network || requireHex(value.swap_id, 16, 'swap id') !== expectedSwapId) throw new Error('Pre-signature belongs to another swap/network');
    const index = Number(value.outpoint?.index);
    if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff) throw new Error('Funding outpoint index is invalid');
    return {
        outpoint: { txid: requireHex(value.outpoint?.txid, 32, 'funding transaction id'), index },
        feeSompi: exactUnsigned(value.fee_sompi, 'Private Swap claim fee'),
        sighash: requireHex(value.sighash, 32, 'claim sighash'),
        presignature: requireHex(value.presignature, 64, 'adaptor pre-signature'),
        negated: value.negated === true,
    };
}

export async function makeReadyPackage(state) {
    if (!state.counterPreSignature || !state.myPreSignature || !state.counterOutpoint) throw new Error('Both verified adaptor pre-signatures are required');
    return {
        v: PRIVATE_SWAP_WIRE_VERSION, t: 'private-swap-ready', swap_id: state.swapId, network: state.network,
        alice_presig_hash: await sha256Hex(state.counterPreSignature),
        outpoint: { txid: state.counterOutpoint.txid, index: state.counterOutpoint.index },
        fee_sompi: state.myClaimFeeSompi, sighash: state.myClaimSighash,
        presignature: state.myPreSignature, negated: Boolean(state.myPreSignatureNegated),
    };
}

export function parseReadyPackage(raw, expectedSwapId) {
    const value = parseJson(raw);
    if (value?.v !== PRIVATE_SWAP_WIRE_VERSION || value?.t !== 'private-swap-ready') throw new Error('Not a current Private Swap ready acknowledgement');
    if (value.network !== networkState.network || requireHex(value.swap_id, 16, 'swap id') !== expectedSwapId) throw new Error('Ready acknowledgement belongs to another swap/network');
    const index = Number(value.outpoint?.index);
    if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff) throw new Error('Ready outpoint index is invalid');
    return {
        alicePresigHash: requireHex(value.alice_presig_hash, 32, 'Alice pre-signature hash'),
        outpoint: { txid: requireHex(value.outpoint?.txid, 32, 'funding transaction id'), index },
        feeSompi: exactUnsigned(value.fee_sompi, 'Bob claim fee'),
        sighash: requireHex(value.sighash, 32, 'Bob claim sighash'),
        presignature: requireHex(value.presignature, 64, 'Bob adaptor pre-signature'),
        negated: value.negated === true,
    };
}

export async function sha256Hex(hex) {
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2) throw new Error('Hash input is invalid');
    return sha256_hash(hex.toLowerCase());
}

export function buildCanonicalCovenant({ ownerPubkey, claimerPubkey, destination, timeoutDaa, salt }) {
    const parsed = JSON.parse(covenant_private_swap(
        requireHex(ownerPubkey, 32, 'owner key'), requireHex(claimerPubkey, 32, 'claim key'),
        requireAddress(destination, 'claim destination'), exactUnsigned(timeoutDaa, 'refund DAA'),
        requireHex(salt, 16, 'covenant salt'), networkState.network,
    ));
    return parsed;
}

export function assertCovenantMatches(actual, expected) {
    if (actual.address !== expected.address || actual.redeemScript !== expected.redeem_script_hex.toLowerCase()) {
        throw new Error(`${actual.label} does not match the negotiated participants/timeout/destination`);
    }
}

export function assertRefundOrdering(aliceTimeout, bobTimeout) {
    const alice = exactUnsigned(aliceTimeout, 'Alice refund DAA');
    const bob = exactUnsigned(bobTimeout, 'Bob refund DAA');
    if (alice <= bob || alice - bob < MIN_REFUND_GAP_DAA) {
        throw new Error('Alice refund must be at least 30 minutes later than Bob refund');
    }
}

function participant(state) {
    return {
        key_id: state.myKeyId,
        claim_pubkey: state.myClaimPubkey,
        adaptor_point: state.myOwnAdaptorPoint,
        owner_pubkey: state.myOwnerPubkey,
        destination: state.myDestination,
        amount_sompi: state.myAmountSompi,
        refund_daa: state.myTimeoutDaa,
    };
}

function normalizeParticipant(value, label) {
    return {
        keyId: requireHex(value?.key_id, 32, `${label} key id`),
        claimPubkey: requireHex(value?.claim_pubkey, 32, `${label} claim key`),
        adaptorPoint: requireHex(value?.adaptor_point, 32, `${label} adaptor point`),
        ownerPubkey: requireHex(value?.owner_pubkey, 32, `${label} owner key`),
        destination: requireAddress(value?.destination, `${label} destination`),
        amountSompi: exactUnsigned(value?.amount_sompi, `${label} amount`).toString(),
        timeoutDaa: exactUnsigned(value?.refund_daa, `${label} refund DAA`).toString(),
    };
}

function normalizeCovenant(value, label) {
    const address = requireAddress(value?.address, `${label} address`);
    const redeemScript = String(value?.redeem_script_hex || '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(redeemScript) || redeemScript.length < 20 || redeemScript.length % 2) throw new Error(`${label} redeem script is invalid`);
    return { label, address, redeemScript, salt: requireHex(value?.salt, 16, `${label} salt`) };
}

function parseJson(raw) {
    const text = typeof raw === 'string' ? raw : new TextDecoder().decode(new Uint8Array(raw));
    return JSON.parse(text);
}
