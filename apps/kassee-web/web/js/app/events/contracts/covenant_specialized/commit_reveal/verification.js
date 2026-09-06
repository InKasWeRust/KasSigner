import { bytesToHex } from '../../../../../core/bytes.js';
import { blake2b_hash } from '../../../../../wasm/api.js';
import { parseCommitRevealSignatureScript } from './pushdata.js';

export function verifyCommitRevealTransaction(transaction) {
    const input = transaction.inputs?.[0];
    const signatureScriptHex = input?.signature_script || '';
    if (signatureScriptHex.length < 10) throw new Error('No sig_script in TX');

    const parsed = parseCommitRevealSignatureScript(signatureScriptHex);
    const fullPreimage = new Uint8Array(parsed.partA.length + parsed.partB.length);
    fullPreimage.set(parsed.partA, 0);
    fullPreimage.set(parsed.partB, parsed.partA.length);
    if (fullPreimage.length <= 8) {
        throw new Error('Commit-reveal preimage is missing its 8-byte salt');
    }

    const fullPreimageHex = bytesToHex(fullPreimage);
    const displayBytes = fullPreimage.slice(8);
    let preimageText;
    try { preimageText = new TextDecoder().decode(displayBytes); }
    catch { preimageText = fullPreimageHex; }

    const redeemHex = bytesToHex(parsed.redeemScript);
    const catBlake2bIndex = redeemHex.indexOf('7eaa20');
    if (catBlake2bIndex < 0) {
        throw new Error('Commit-reveal script is missing the current hash sequence');
    }
    const committedHash = redeemHex.substring(catBlake2bIndex + 6, catBlake2bIndex + 70);
    const computedHash = blake2b_hash(fullPreimageHex);
    return {
        preimageText,
        committedHash,
        computedHash,
        matches: committedHash === computedHash,
        timestamp: transaction.block_time
            ? new Date(transaction.block_time).toLocaleString()
            : 'DAA: ' + (input?.previous_outpoint_resolved_daa_score || 'unknown'),
    };
}
