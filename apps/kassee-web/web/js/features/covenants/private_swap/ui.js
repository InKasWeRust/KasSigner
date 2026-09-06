import { navigationState } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { byId } from '../../../core/dom.js';
import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { generate_qr_svg_text } from '../../../wasm/api.js';
import { pauseQrCycle } from '../../transactions/send/review.js';

export function showPrivateSwapProtocolQr(payload, title, info) {
    pauseQrCycle();
    setSafeMarkup(byId('qr-container'), generate_qr_svg_text(payload));
    byId('qr-frame-info').textContent = info || '';
    byId('qr-display-title').textContent = title;
    ['btn-scan-next-sig', 'btn-copy-kspt', 'btn-qr-scan-signed']
        .forEach(id => byId(id)?.style.setProperty('display', 'none'));
    byId('qr-tx-info')?.style.setProperty('display', 'none');
    navigationState._broadcastReturnScreen = 'covenant';
    showScreen('qr-display');
}

export function showPrivateSwapJsonQr(value, title, info) {
    showPrivateSwapProtocolQr(JSON.stringify(value), title, info);
}

export function showPrivateSwapSection(section) {
    ['hub', 'create', 'join', 'dashboard']
        .forEach(name => byId(`private-swap-${name}`)?.classList.toggle('hidden', name !== section));
}

export function renderPrivateSwapUi(state, pendingDeviceAction) {
    byId('btn-private-swap-resume')?.classList.toggle('hidden', !state.role);
    if (!state.role) return;
    byId('private-swap-role').textContent = state.role === 'alice' ? 'ALICE' : 'BOB';
    byId('private-swap-my-address').textContent = state.myAddress || 'Not built yet';
    byId('private-swap-counter-address').textContent = state.counterAddress || 'Not received yet';
    byId('private-swap-status').textContent = statusText(state);
    byId('private-swap-actions')?.querySelectorAll('button').forEach(button => button.classList.add('hidden'));
    for (const id of actionIds(state)) byId(id)?.classList.remove('hidden');
    if (pendingDeviceAction) byId('btn-private-swap-scan-device')?.classList.remove('hidden');
}

function actionIds(state) {
    const ids = [];
    if (state.role === 'alice' && state.stage === 'alice-offer-ready') ids.push('btn-private-swap-share-offer', 'btn-private-swap-scan-response');
    if (state.role === 'bob' && state.stage === 'bob-response-ready') ids.push('btn-private-swap-share-response', 'btn-private-swap-scan-final');
    if (state.stage === 'alice-needs-binding' || state.stage === 'bob-needs-binding') ids.push('btn-private-swap-bind');
    if (state.role === 'alice' && state.stage === 'alice-bound') ids.push('btn-private-swap-share-final', 'btn-private-swap-fund');
    if (state.role === 'bob' && state.myBindingToken && !state.myPreSignature) ids.push('btn-private-swap-presign');
    if (state.role === 'bob' && state.myPreSignature) ids.push('btn-private-swap-fund', 'btn-private-swap-scan-presig');
    if (state.role === 'alice' && state.myBindingToken && state.myAddress && !state.myPreSignature) ids.push('btn-private-swap-fund', 'btn-private-swap-presign');
    if (state.role === 'alice' && state.myPreSignature && !state.readyAckHash) ids.push('btn-private-swap-share-presig', 'btn-private-swap-scan-ready');
    if (state.role === 'bob' && state.myPreSignature && state.counterPreSignature) ids.push('btn-private-swap-share-ready');
    if (state.role === 'alice' && state.readyAckHash && !state.completed) ids.push('btn-private-swap-complete');
    if (state.role === 'bob' && state.counterCompletedSignature && !state.completed) ids.push('btn-private-swap-bob-claim');
    if (state.myAddress && !state.completed) ids.push('btn-private-swap-refund');
    return [...new Set(ids)];
}

function statusText(state) {
    if (state.completed) return '✓ Private Swap completed.';
    const map = {
        'alice-offer-ready': 'Share the offer with Bob, then scan his response.',
        'bob-response-ready': 'Share Bob’s response with Alice, then scan her final handshake.',
        'alice-needs-binding': 'Bind Alice’s isolated claim key to Bob’s exact covenant.',
        'bob-needs-binding': 'Bind Bob’s isolated claim key to Alice’s exact covenant.',
        'alice-bound': 'Share the final handshake, then fund Alice’s long-timeout side first.',
        'bob-bound': 'Wait for Alice funding; prepare Bob’s exact claim pre-signature before funding Bob’s side.',
        'bob-presigned': 'Bob claim pre-signature is safe. After verifying Alice funding, fund Bob’s short-timeout side.',
        'alice-presigned': 'Share Alice’s exact claim pre-signature with Bob and wait for his cryptographic ready acknowledgement.',
        'bob-alice-presig-verified': 'Alice pre-signature verified. Send Bob’s ready acknowledgement; watcher will extract the secret after Alice claims.',
        'alice-bob-ready': 'Bob’s claim pre-signature is verified. Alice can safely complete and claim Bob’s side.',
    };
    return map[state.stage || 'idle'] || 'Follow the numbered Private Swap steps. Claim signatures are exact transaction sighashes; no preimage is used.';
}
