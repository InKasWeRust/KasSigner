import { networkState, transactionState } from '../../../../../app/state/index.js';
import { withNodeRetry } from '../../../../wallet/core.js';
import { create_send_pskb, create_send_pskb_limited, create_send_pskb_with_utxos } from '../../../../../wasm/api.js';
// Standard wallet transaction planners.

import { kasToSompi } from '../../../../../core/amounts.js';
import { exactJsonStringify, exactUnsigned } from '../../../../../core/exact.js';
import { selectedUtxos } from '../../../shared/utxo_selection.js';
export async function planSelected(freshWallet, destination, amountString, fee) {
    // Pass the actual cached UTXO objects to avoid stale-index bugs
    const chosenUtxos = selectedUtxos(networkState.cachedUtxos, transactionState.selectedUtxoIds);
    if (chosenUtxos.length === 0) {
        throw 'Selected UTXOs no longer available. Refresh and try again.';
    }
    // Coin control remains KasSee wallet policy. Pass the exact selected UTXO
    // objects to the watcher builder; the KasSigner SDK sees only the finished PSKT.
    const utxosJson = exactJsonStringify(chosenUtxos);
    const pskbHex = await create_send_pskb_with_utxos(
        freshWallet,
        destination,
        kasToSompi(amountString),
        exactUnsigned(fee, 'fee'),
        utxosJson
    );
    return { pskbHex, completed: false };
}

export async function planAutomatic(freshWallet, destination, amountString, fee) {
    const limit = transactionState.utxoSelectionLimit || 8;
    const pskbHex = await withNodeRetry(wsUrl => limit === 8
        ? create_send_pskb(
            freshWallet, destination, kasToSompi(amountString), exactUnsigned(fee, 'fee'), wsUrl,
        )
        : create_send_pskb_limited(
            freshWallet, destination, kasToSompi(amountString), exactUnsigned(fee, 'fee'), limit, wsUrl,
        )
    );
    return { pskbHex, completed: false };
}
