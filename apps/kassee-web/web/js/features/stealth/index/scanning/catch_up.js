import { stealthState } from '../../../../app/state/index.js';
// KasSee Web — features/stealth/index/scanning/catch_up
import { byId } from '../../../../core/dom.js';
import { exactUnsignedJsonField } from '../../../../core/exact.js';
import { KSTL_SUBNET_HEX, STEALTH_LOOKBACK_BLUE_SCORE, STEALTH_MAX_WINDOWS } from '../config.js';


// ─── Stealth REST catch-up (indexer-backed, survives pruning) ───
// Current tip blue score via the indexer: /info/blockdag gives the sink hash,
// /blocks/{sink} gives header.blueScore. (virtualDaaScore is NOT the blue score.)
async function stealthGetTipBlueScore(apiBase) {
    // One GET: virtual selected-parent (sink) blue score -> {"blueScore": N}.
    try {
        const response = await fetch(apiBase + '/info/virtual-chain-blue-score',
            { signal: AbortSignal.timeout(10000) });
        const raw = await response.text();
        const bs = exactUnsignedJsonField(raw, 'blueScore', 'virtual-chain blueScore');
        if (bs > 0n) return bs;
    } catch (e) { console.log('[KasSee] vc-blue-score failed, falling back to sink block:', e); }
    // Fallback: sink hash from /info/blockdag -> block header blueScore.
    const dag = await (await fetch(apiBase + '/info/blockdag', { signal: AbortSignal.timeout(10000) })).json();
    const sink = dag && dag.sink;
    if (!sink) throw new Error('no sink in /info/blockdag');
    const blockResponse = await fetch(apiBase + '/blocks/' + sink, { signal: AbortSignal.timeout(10000) });
    const blockRaw = await blockResponse.text();
    const bs2 = exactUnsignedJsonField(blockRaw, 'blueScore', 'sink blueScore');
    if (bs2 === 0n) throw new Error('no blueScore for sink block');
    return bs2;
}
// No self-hosted indexer: the public api-tn10 endpoint caps each range at 100
// blue score (TX_SEARCH_BS_LIMIT) and returns accepted txs with subnetwork_id +
// payload inline. Keep only KSTL-subnetwork txs and read R from the payload.
// Survives node pruning. Returns a deduped 64-hex R list.
export async function stealthRestCatchUp(apiBase) {
    const tip = await stealthGetTipBlueScore(apiBase);
    const startBs = tip > STEALTH_LOOKBACK_BLUE_SCORE ? tip - STEALTH_LOOKBACK_BLUE_SCORE : 0n;
    // subnetwork_id MUST be in fields= or the lane filter has nothing to match.
    const searchUrl = apiBase +
        '/transactions/search?fields=transaction_id,subnetwork_id,payload,accepting_block_blue_score&resolve_previous_outpoints=no';
    // Build 100-wide [gte, lt) windows up to the cap, NEWEST FIRST so a recent
    // announcement lands in the first batch instead of after the whole walk.
    const wins = [];
    for (let hi = tip + 1n; hi > startBs && wins.length < STEALTH_MAX_WINDOWS; hi -= 100n) {
        const lo = hi - 100n > startBs ? hi - 100n : startBs;
        wins.push([lo, hi]);
    }
    console.log('[KasSee] REST catch-up: tip=' + tip + ' start=' + startBs +
        ' windows=' + wins.length);
    const foundR = [];
    const seen = new Set();
    let done = 0, firstErr = false;
    const CONC = 3; // low concurrency: reliable on the public endpoint, not a hammer
    const sleep = ms => new Promise(res => setTimeout(res, ms));
    // Retry a throttled window instead of silently dropping it. 429 (and 503)
    // are transient: back off and retry a few times. A dropped window means a
    // missed R, so we spend a little wall time rather than lose a payment.
    async function runOne(gte, lt) {
        const MAX_RETRY = 4;
        for (let attempt = 0; attempt <= MAX_RETRY; attempt++) {
            try {
                const r = await fetch(searchUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    // Build the JSON integer literals from decimal BigInt strings instead of
                    // routing consensus blue scores through JavaScript Number.
                    body: `{"acceptingBlueScores":{"gte":${gte.toString()},"lt":${lt.toString()}}}`,
                    signal: AbortSignal.timeout(15000)
                });
                if (r.status === 429 || r.status === 503) {
                    if (attempt < MAX_RETRY) {
                        // Honor Retry-After if the server sends it, else exponential
                        // backoff with jitter: ~0.5s, 1s, 2s, 4s (+ up to 250ms).
                        const ra = parseInt(r.headers.get('retry-after') || '0', 10);
                        const backoff = ra > 0
                            ? ra * 1000
                            : (500 * Math.pow(2, attempt)) + Math.floor(Math.random() * 250);
                        await sleep(backoff);
                        continue;
                    }
                    if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search throttled (HTTP ' + r.status + ') at gte=' + gte + ' after ' + MAX_RETRY + ' retries'); }
                    return;
                }
                if (!r.ok) {
                    if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search HTTP ' + r.status + ' at gte=' + gte); }
                    return;
                }
                const txs = await r.json();
                if (Array.isArray(txs)) {
                    for (const tx of txs) {
                        if ((tx.subnetwork_id || '').toLowerCase() !== KSTL_SUBNET_HEX) continue;
                        let pl = (tx.payload || '').toLowerCase();
                        if (pl.startsWith('0x')) pl = pl.slice(2);
                        // lane payload = ver(0x01) || R(32) || view_tag(1) => 68 hex, R at offset 1 byte
                        if (pl.length < 68 || pl.slice(0, 2) !== '01') continue;
                        const rHex = pl.slice(2, 66);
                        if (!/^0+$/.test(rHex) && !seen.has(rHex)) { seen.add(rHex); foundR.push(rHex); }
                    }
                }
                break; // success: leave the retry loop
            } catch (e) {
                if (attempt < MAX_RETRY) { await sleep(500 * Math.pow(2, attempt)); continue; }
                if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search fetch failed at gte=' + gte + ':', e); }
            }
        }
        done++;
    }
    for (let i = 0; i < wins.length; i += CONC) {
        await Promise.all(wins.slice(i, i + CONC).map(function (w) { return runOne(w[0], w[1]); }));
        // Small gap between batches so a steady scan stays well under the
        // endpoint's rate limit even when no 429 has fired yet.
        if (i + CONC < wins.length) { await sleep(150); }
        try {
            byId('stealth-scan-status').textContent =
                'Scanning lane\u2026 ' + done + '/' + wins.length + ' windows, ' + foundR.length + ' R';
        } catch (_) {}
        // Surface R as soon as a batch finds it: push new ones to the global
        // list and reveal the device-QR button, so the user can proceed without
        // waiting for the whole walk to finish.
        if (foundR.length) {
            let added = false;
            for (const rHex of foundR) {
                if (rHex.length === 64 && stealthState.stealthAnnouncementsR.indexOf(rHex) === -1 && stealthState.stealthAnnouncementsR.length < 64) {
                    stealthState.stealthAnnouncementsR.push(rHex); added = true;
                }
            }
            if (added) {
                try {
                    const list = byId('stealth-r-list');
                    if (list) list.textContent = stealthState.stealthAnnouncementsR.length + ' R value(s) loaded';
                    const qrBtn = byId('btn-stealth-show-scan-qr');
                    if (qrBtn) qrBtn.classList.remove('hidden');
                } catch (_) {}
            }
        }
    }
    console.log('[KasSee] REST catch-up done: ' + wins.length + ' windows, found ' + foundR.length + ' R');
    return foundR;
}
