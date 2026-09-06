import { bytesToHex } from '../../../core/bytes.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { fetch_utxos_for_address_js } from '../../../wasm/api.js';
import { createBlockAddedSubscription } from '../blockchain/block_added_subscription.js';
import { readFirstPush } from '../blockchain/outpoint_parser.js';
import { privateSwapState, savePrivateSwapState } from './state.js';

let pollTimer = null;
let subscription = null;
let signatureCallback = null;

export function startPrivateSwapWatcher(onSignature) {
    signatureCallback = onSignature || signatureCallback;
    if (!watchIsActive()) return;
    if (!pollTimer) pollTimer = setInterval(() => { void pollPrivateSwapFunding(); }, 4000);
    void pollPrivateSwapFunding();
    if (privateSwapState.myOutpoint) startSubscription();
}

export function stopPrivateSwapWatcher() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    subscription?.stop();
    subscription = null;
}

async function pollPrivateSwapFunding() {
    if (!watchIsActive()) { stopPrivateSwapWatcher(); return; }
    try {
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(privateSwapState.myAddress, wsUrl));
        const expected = String(privateSwapState.myAmountSompi || '');
        const matching = Array.isArray(utxos) ? utxos.find(utxo => String(utxo.amount) === expected) : null;
        if (matching?.tx_id && !privateSwapState.myOutpoint) {
            privateSwapState.myOutpoint = { txid: String(matching.tx_id).toLowerCase(), index: Number(matching.index || 0) };
            savePrivateSwapState();
            startSubscription();
        }
    } catch (_) {}
}

function startSubscription() {
    if (subscription || !privateSwapState.myOutpoint?.txid) return;
    const candidate = createBlockAddedSubscription({
        label: 'Private Swap watcher',
        isActive: watchIsActive,
        getOutpoint: () => privateSwapState.myOutpoint,
        signatureBounds: { minLength: 67, maxLength: 3000 },
        onSignatureScript: inspectSignatureScript,
    });
    subscription = candidate;
    void candidate.start();
}

function inspectSignatureScript(script) {
    const firstPush = readFirstPush(script, 65);
    if (!firstPush || firstPush.length !== 65 || firstPush[64] !== 0x01) return;
    // The canonical completed claim is PUSH65(signature+sighash) OP_TRUE PUSH(redeem).
    // Ignore the owner refund branch (OP_FALSE) so Bob never treats his own refund
    // signature as Alice's adaptor-secret-revealing claim signature.
    if (script[0] !== 65 || script.length <= 66 || script[66] !== 0x51) return;
    const completed = bytesToHex(firstPush.slice(0, 64));
    privateSwapState.counterCompletedSignature = completed;
    savePrivateSwapState();
    stopPrivateSwapWatcher();
    signatureCallback?.(completed);
}

function watchIsActive() {
    return privateSwapState.role === 'bob'
        && Boolean(privateSwapState.myAddress)
        && !privateSwapState.counterCompletedSignature;
}
