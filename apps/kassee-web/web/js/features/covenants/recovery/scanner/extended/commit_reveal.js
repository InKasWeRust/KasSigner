import { readLen, readU64 } from '../payload_reader.js';
import { recoveredFromRedeem } from './common.js';

export function decodeCommitReveal(params, network) {
    const commitHash = params.substring(0, 64);
    const locktime = readU64(params, 64);
    const { len, endOff } = readLen(params, 80);
    const redeem = params.substring(endOff, endOff + len * 2);
    const cipherPosition = endOff + len * 2;
    let ciphertext = '';
    try {
        const field = readLen(params, cipherPosition);
        ciphertext = params.substring(field.endOff, field.endOff + field.len * 2);
    } catch (_) {}
    return recoveredFromRedeem('commit-reveal', redeem, network, {
        locktime_daa: locktime,
        commit_hash: commitHash,
        cr_ciphertext_hex: ciphertext,
        role: 'owner',
    });
}
