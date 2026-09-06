import { hexToBytes } from '../../../../../core/bytes.js';
import { buildCanonicalCovenant, assertCovenantMatches } from '../../../private_swap/protocol.js';
import { readVstr } from '../payload_reader.js';
import { baseRecoveredRecord, readStoredScript } from './common.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const MAX_RECOVERY_JSON_BYTES = 16 * 1024;
const TRANSIENT_FIELDS = new Set(['myClaimPskb', 'myClaimKspt', 'counterClaimKspt', 'counterCompletedSignature']);

function requireHex(value, regex, label) {
    if (!regex.test(value || '')) throw new Error(`Recovered Private Swap ${label} is invalid`);
}

function assertRecoveryObjectSafe(value, depth = 0) {
    if (depth > 6) throw new Error('Recovered Private Swap state is too deeply nested');
    if (value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
        for (const item of value) assertRecoveryObjectSafe(item, depth + 1);
        return;
    }
    for (const [key, child] of Object.entries(value)) {
        if (key.toLowerCase().includes('secret') || TRANSIENT_FIELDS.has(key)) {
            throw new Error('Recovered Private Swap contains forbidden transient or secret material');
        }
        assertRecoveryObjectSafe(child, depth + 1);
    }
}

export function rebuildPrivateSwap(type, params) {
    const stored = readStoredScript(params);
    const recovery = readVstr(params, stored.offset, hexToBytes);
    if (recovery.endOff !== params.length) throw new Error('Recovered Private Swap payload has trailing data');
    if (recovery.endOff - stored.offset > 4 + MAX_RECOVERY_JSON_BYTES * 2) throw new Error('Recovered Private Swap transcript is too large');
    const state = JSON.parse(recovery.str || '{}');
    assertRecoveryObjectSafe(state);
    if (state.role !== 'alice' && state.role !== 'bob') throw new Error('Recovered Private Swap role is invalid');
    requireHex(state.swapId, HEX32, 'swap ID');
    requireHex(state.myKeyId, HEX64, 'key ID');
    requireHex(state.myClaimPubkey, HEX64, 'claim key');
    requireHex(state.myBindingToken, HEX64, 'binding token');
    requireHex(state.adaptorPoint, HEX64, 'adaptor point');
    if (!state.myAddress || !state.myRedeem || !state.counterAddress || !state.counterRedeem) throw new Error('Recovered Private Swap covenant pair is incomplete');
    const mine = buildCanonicalCovenant({
        ownerPubkey: state.myOwnerPubkey,
        claimerPubkey: state.counterClaimPubkey,
        destination: state.counterDestination,
        timeoutDaa: state.myTimeoutDaa,
        salt: state.mySalt,
    });
    assertCovenantMatches({ address: state.myAddress, redeemScript: state.myRedeem }, mine);
    if (stored.redeemScriptHex !== state.myRedeem) throw new Error('Recovered Private Swap stored script does not match transcript');
    const theirs = buildCanonicalCovenant({
        ownerPubkey: state.counterOwnerPubkey,
        claimerPubkey: state.myClaimPubkey,
        destination: state.myDestination,
        timeoutDaa: state.counterTimeoutDaa,
        salt: state.counterSalt,
    });
    assertCovenantMatches({ address: state.counterAddress, redeemScript: state.counterRedeem }, theirs);
    return {
        ...baseRecoveredRecord(type, state.myRedeem, state.role),
        locktime_daa: BigInt(state.myTimeoutDaa),
        private_swap_recovery_json: JSON.stringify(state),
    };
}
