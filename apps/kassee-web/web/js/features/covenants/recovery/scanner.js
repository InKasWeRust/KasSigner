import { networkState, walletSession } from '../../../app/state/index.js';
import { kaspaRestApiBase } from '../../../core/config/network.js';
import { toast } from '../../../core/ui/toast.js';
import { getAccountPubkeyHex } from '../generation/ui_and_keys.js';
import { decryptCovenantPayload } from '../payload_and_swaps/payload.js';
import { covRenderActive, covSaveActive } from './active.js';
// KasSee Web — features/covenants/recovery/scanner
import { rebuildCovenant } from './scanner/rebuild.js';
export { rebuildCovenant } from './scanner/rebuild.js';


// ─── Covenant Recovery Scanner ───
// Scans TX history for all wallet addresses, finds TXs with payloads,
// decrypts with kpub-derived key, rebuilds covenant addresses, checks balances.

export async function recoverCovenants() {
    if (!walletSession.hasWallet()) { toast('Load wallet first', 'error'); return; }
    const wallet = walletSession.current();
    let apiBase;
    try { apiBase = kaspaRestApiBase(networkState.network); }
    catch (error) { toast(error.message, 'error'); return; }

    const ownerPk = getAccountPubkeyHex();
    const allAddresses = [...(wallet.receive_addresses || []), ...(wallet.change_addresses || [])];

    toast('Scanning chain for covenant payloads...', 'info', 3000);
    console.log('[KasSee] Recovery: scanning', allAddresses.length, 'addresses');

    let found = 0;
    let scanned = 0;
    const seenTxIds = new Set();

    for (const addr of allAddresses) {
        try {
            const r = await fetch(
                `${apiBase}/addresses/${addr}/full-transactions?resolve_previous_outpoints=light&limit=50`,
                { signal: AbortSignal.timeout(10000) }
            );
            if (!r.ok) continue;
            const txs = await r.json();
            if (!Array.isArray(txs)) continue;

            for (const tx of txs) {
                if (seenTxIds.has(tx.transaction_id)) continue;
                seenTxIds.add(tx.transaction_id);
                scanned++;

                // TN10 API doesn't reliably populate previous_outpoint_address,
                // so we skip the fromUs check and rely on decrypt failure as the
                // filter: only payloads encrypted with our key will decrypt.

                // Get payload. full-transactions may not include it, so fetch individual TX.
                let payloadHex = tx.payload;
                if (!payloadHex || payloadHex === '0000000000000000') {
                    try {
                        const txr = await fetch(
                            `${apiBase}/transactions/${tx.transaction_id}`,
                            { signal: AbortSignal.timeout(5000) }
                        );
                        if (txr.ok) {
                            const txData = await txr.json();
                            payloadHex = txData.payload;
                        }
                    } catch (_) {}
                }
                if (!payloadHex || payloadHex.length < 60) continue; // min 30 bytes = 60 hex

                // Try to decrypt
                const decrypted = await decryptCovenantPayload(payloadHex);
                if (!decrypted) continue;

                const rebuilt = await rebuildCovenant(decrypted, ownerPk);
                if (rebuilt) found++;
            }
        } catch (e) {
            console.log('[KasSee] Recovery: error scanning', addr, e);
        }
    }

    console.log('[KasSee] Recovery complete:', scanned, 'TXs scanned,', found, 'covenants recovered');
    if (found > 0) {
        toast('Recovered ' + found + ' covenant(s) from chain', 'ok', 4000);
        covSaveActive();
        covRenderActive();
    } else {
        toast('No covenant payloads found on chain', 'info', 3000);
    }
}
