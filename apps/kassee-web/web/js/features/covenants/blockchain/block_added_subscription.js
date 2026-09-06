import { createBlockAddedTransport } from '../../../core/node/block_added_transport.js';
import { findSpendingSignatureScript } from './outpoint_parser.js';

export function createBlockAddedSubscription(options) {
    return createBlockAddedTransport({
        label: options.label,
        isActive: () => Boolean(options.getOutpoint()?.txid) && options.isActive(),
        reconnectDelay: options.reconnectDelay,
        retryDelay: options.retryDelay,
        onPayload(payload) {
            const script = findSpendingSignatureScript(
                payload,
                options.getOutpoint(),
                options.signatureBounds,
            );
            if (script) options.onSignatureScript(script);
        },
    });
}
