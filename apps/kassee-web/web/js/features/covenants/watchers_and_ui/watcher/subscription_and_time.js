import { covenantState, covenantWatcherState } from '../../../../app/state/index.js';
import { createBlockAddedSubscription } from '../../blockchain/block_added_subscription.js';
import { isWatchedCovenantType } from './types.js';
import { detectSpendPath } from './subscription/message.js';
import { notifyCovenantSpend } from './subscription/notifications.js';

let subscription = null;

covenantWatcherState._covWatcherSpendPath = null;
covenantState._lastKnownDaa = 0;

export async function covSubscriptionStart() {
    covSubscriptionStop();
    const subscribed = currentSubscription();
    if (!subscribed) return;

    const candidate = createBlockAddedSubscription({
        label: 'Covenant watcher',
        isActive: () => Boolean(
            covenantWatcherState._covWatcherTimer
            && covenantState.lastCovenantResult?.address === subscribed.address
        ),
        getOutpoint: () => covenantWatcherState._covWatcherOutpoint,
        signatureBounds: { minLength: 2, maxLength: 2000 },
        onSignatureScript: script => handleSignatureScript(script, subscribed),
    });
    subscription = candidate;
    await candidate.start();
}

function currentSubscription() {
    const result = covenantState.lastCovenantResult;
    if (!result?.address || !isWatchedCovenantType(result.type || '')) return null;
    return { type: result.type || '', address: result.address };
}

function handleSignatureScript(signature, subscribed) {
    const result = covenantState.lastCovenantResult;
    if (!result || result.address !== subscribed.address) {
        console.log('[KasSee] BlockAdded: ignoring stale subscription (covenant switched)');
        covSubscriptionStop();
        return;
    }

    const path = detectSpendPath(signature, result.redeem_script_hex || '');
    if (!path) return;
    console.log(`[KasSee] Covenant spend detected via BlockAdded. Path: ${path}`);
    covenantWatcherState._covWatcherSpendPath = path;
    notifyCovenantSpend(subscribed.type, path);
    covSubscriptionStop();
}

export function covSubscriptionStop() {
    subscription?.stop();
    subscription = null;
}
