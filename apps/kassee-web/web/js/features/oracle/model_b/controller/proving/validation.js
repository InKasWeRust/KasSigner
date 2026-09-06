import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { utxoTransactionId } from '../../../../../core/utxo.js';
import { fetch_utxos_for_address_js } from '../../../../../wasm/api.js';

export function validateOracleQuote(quote, protocol) {
    if (!quote.ok || !quote.body) return `Quote failed (HTTP ${quote.status}).`;
    const body = quote.body;
    if (body.error) return `Quote error: ${body.error}`;
    if (!body.acc || body.price == null || body.publish_time == null) return 'Quote incomplete, try again.';
    if ((body.set_root || '').toLowerCase() !== protocol.setRootHex.toLowerCase()) {
        return 'Quote set_root mismatch, aborting (guardian-set drift?).';
    }
    if (body.fee_address && body.fee_address !== protocol.feeAddress) {
        return 'Quote fee address changed, refusing (update KasSee first).';
    }
    return null;
}

export async function oracleAlreadyMoved(currentState, heartbeatAddress) {
    if (!currentState?.rollTxid || !heartbeatAddress) return false;
    try {
        const wsUrl = await resolveNodeUrl();
        const heartbeatUtxos = JSON.parse(await fetch_utxos_for_address_js(heartbeatAddress, wsUrl));
        const liveRollTxid = heartbeatUtxos.length ? utxoTransactionId(heartbeatUtxos[0]) : '';
        return Boolean(liveRollTxid)
            && liveRollTxid.toLowerCase() !== String(currentState.rollTxid).toLowerCase();
    } catch (_) {
        return false;
    }
}
