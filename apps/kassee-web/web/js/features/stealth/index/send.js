import { bytesToHex } from '../../../core/bytes.js';
import { navigationState, networkState, stealthState, walletSession } from '../../../app/state/index.js';
import { stealthScanPause } from './scanning/live.js';
import { hideLoading, showLoading } from '../../../app/navigation.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import { openPsktReview } from '../../transactions/pskt_multisig/review.js';
import { detectWalletNetwork } from '../../../core/network.js';
import { generate_qr_svg_text, get_fee_estimate, stealth_announcement_address, stealth_create_payment_lane, stealth_generate_payment, stealth_meta_from_kpub } from '../../../wasm/api.js';
// KasSee Web — features/stealth/index/send
import { byId } from '../../../core/dom.js';

import { formatSeconds } from '../../../core/format.js';
import { kasToSompi } from '../../../core/amounts.js';
import { exactUnsigned } from '../../../core/exact.js';
import { roundFeeFromRate } from '../../../core/fee_math.js';

// ─── Stealth Addresses ───

stealthState.stealthAnnouncementsR = [];
 // Array of 32-byte hex R values from announcements

// ── Stealth fee selector (low / normal / priority). Mirrors the main send's
// fee-card flow (node feerate x representative mass, clamped to a floor) but on
// the stealth screens, with its own ids so it never collides with the main
// send's cards. `prefix` is the id stem ('sf' = stealth send, 'spf' = stealth
// spend); `ctx` selects the mass tier. `lastFeeEstimate` is the shared node
// estimate, so the rates adapt to live congestion.
function stealthFeeMass(ctx) { return ctx === 'spend' ? 2000n : 2500n; }
 // 1-in-1-out vs 1-in-2-out + payload
function stealthFeeFloor(level) {
    if (level === 'low') return 2500n;
    if (level === 'priority') return 300000n;
    return 5000n;
}

function stealthFeeCompute(level, ctx) {
    if (!networkState.lastFeeEstimate) return null;
    let feerate;
    if (level === 'low') feerate = networkState.lastFeeEstimate.low_sompi_per_gram;
    else if (level === 'priority') feerate = networkState.lastFeeEstimate.priority_sompi_per_gram;
    else feerate = networkState.lastFeeEstimate.normal_sompi_per_gram;
    return roundFeeFromRate(feerate || 1, stealthFeeMass(ctx), stealthFeeFloor(level));
}
function stealthFeeRenderCards(prefix, ctx) {
    if (!networkState.lastFeeEstimate) return;
    ['low', 'normal', 'priority'].forEach(lvl => {
        const amt = stealthFeeCompute(lvl, ctx);
        const a = byId(prefix + '-' + lvl + '-amount');
        if (a && amt != null) a.textContent = amt.toLocaleString();
        const t = byId(prefix + '-' + lvl + '-time');
        const secs = networkState.lastFeeEstimate[lvl + '_seconds'];
        if (t && secs != null) t.textContent = formatSeconds(secs);
    });
}
export function stealthFeeSetLevel(prefix, ctx, level) {
    const amt = stealthFeeCompute(level, ctx);
    if (amt != null) { const inp = byId('input-' + prefix + '-fee'); if (inp) inp.value = amt.toString(); }
    ['low', 'normal', 'priority'].forEach(lvl => {
        const b = byId('btn-' + prefix + '-' + lvl);
        if (b) b.classList.toggle('fee-card-active', lvl === level);
    });
}
export function stealthFeeValue(prefix, ctx) {
    const inp = byId('input-' + prefix + '-fee');
    if (inp && inp.value) { try { const v = exactUnsigned(inp.value.trim(), 'stealth fee sompi'); if (v > 0n) return v; } catch (_) {} }
    const amt = stealthFeeCompute('normal', ctx);
    return amt != null ? amt : stealthFeeFloor('normal');
}
export async function stealthFeePrepare(prefix, ctx) {
    try {
        const wsUrl = await resolveNodeUrl();
        networkState.lastFeeEstimate = JSON.parse(await get_fee_estimate(wsUrl));
    } catch (e) { console.log('[KasSee] stealth fee estimate:', e); }
    stealthFeeRenderCards(prefix, ctx);
    stealthFeeSetLevel(prefix, ctx, 'normal');
}
export function stealthShowPanel(panel) {
    // Leaving the scan panel pauses only the panel-local visuals (device-QR
    // cycler + inserted QR box). The live BlockAdded watcher and the
    // accumulated R list stay alive across panel switches so payments made
    // from the send panel (or received while browsing) are still caught.
    // Full teardown happens only on leaving the stealth screen or on a
    // fresh Fetch (both call stealthScanStop()).
    if (panel !== 'scan') stealthScanPause();
    ['stealth-menu', 'stealth-meta-panel', 'stealth-send-panel', 'stealth-scan-panel'].forEach(id => {
        byId(id).classList.add('hidden');
    });
    if (panel === 'menu') byId('stealth-menu').classList.remove('hidden');
    if (panel === 'meta') byId('stealth-meta-panel').classList.remove('hidden');
    if (panel === 'send') { byId('stealth-send-panel').classList.remove('hidden'); byId('stealth-send-result').classList.add('hidden'); }
    if (panel === 'scan') byId('stealth-scan-panel').classList.remove('hidden');
}
export function handleStealthMeta() {
    if (!walletSession.hasWallet()) { toast('Load wallet first', 'error'); return; }
    const wallet = walletSession.current();
    try {
        const result = JSON.parse(stealth_meta_from_kpub(wallet.kpub));
        byId('stealth-meta-hex').textContent = result.meta_address;

        // Generate QR for the meta-address as PLAIN TEXT (the 128-hex string),
        // not the hex-decoded/framed binary form, so the meta scanner decodes it
        // directly via TextDecoder and matches /^[0-9a-fA-F]{128}$/.
        const qrContainer = byId('stealth-meta-qr');
        qrContainer.innerHTML = '';
        try {
            qrContainer.innerHTML = generate_qr_svg_text(result.meta_address);
        } catch (e) {
            qrContainer.textContent = result.meta_address;
        }

        // Show announcement address
        const network = detectWalletNetwork(walletSession.json(), networkState.network);
        byId('stealth-announce-addr').textContent = stealth_announcement_address(network);

        stealthShowPanel('meta');
    } catch (e) {
        toast('Error: ' + e, 'error', 3000);
    }
}
export function handleStealthSendGenerate() {
    const metaHex = byId('stealth-send-meta').value.trim();
    if (!metaHex || metaHex.length !== 128) { toast('Enter 128-hex stealth meta-address', 'error'); return; }

    // Generate 32 bytes of entropy
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    const entropyHex = bytesToHex(entropy);

    const network = detectWalletNetwork(walletSession.json(), networkState.network);
    try {
        const result = JSON.parse(stealth_generate_payment(metaHex, entropyHex, network));
        byId('stealth-send-addr').textContent = result.address;
        byId('stealth-send-r').textContent = result.ephemeral_r;
        byId('stealth-send-result').classList.remove('hidden');
        stealthFeePrepare('sf', 'send'); // populate low/normal/priority from the node

        // Remember the entropy so "Send Payment" reuses the SAME R that was
        // previewed (otherwise the broadcast R would differ from what's shown).
        stealthState._stealthSendEntropy = entropyHex;
        stealthState._stealthSendMeta = metaHex;

        console.log('[KasSee] Stealth payment generated:',
            'address=' + result.address,
            'R=' + result.ephemeral_r,
            'index=' + result.stealth_index);
    } catch (e) {
        toast('Error: ' + e, 'error', 3000);
    }
}
// in the TX payload, then hand the PSKB to the standard review/sign/broadcast
// flow. The receiver's live scan picks up R from the payment's payload.
export async function handleStealthSendPay() {
    if (!walletSession.hasWallet()) { toast('Load wallet first', 'error'); return; }
    const metaHex = byId('stealth-send-meta').value.trim();
    if (!metaHex || metaHex.length !== 128) { toast('Enter 128-hex stealth meta-address', 'error'); return; }
    let amountSompi;
    try { amountSompi = kasToSompi(byId('stealth-send-amount').value.trim()); } catch (_) { toast('Enter a valid amount with at most 8 decimal places', 'error'); return; }
    if (amountSompi <= 0n) { toast('Enter a valid amount', 'error'); return; }

    // Reuse the previewed entropy if it matches this meta-address; else fresh.
    let entropyHex = stealthState._stealthSendEntropy;
    if (!entropyHex || stealthState._stealthSendMeta !== metaHex) {
        const entropy = new Uint8Array(32);
        crypto.getRandomValues(entropy);
        entropyHex = bytesToHex(entropy);
    }

    const network = detectWalletNetwork(walletSession.json(), networkState.network);
    showLoading('Building stealth payment...');
    try {
        const wsUrl = await resolveNodeUrl();
        // Lane send on KSTL (device-signed). Fee from the low/normal/priority
        // selector (node feerate x mass), honoring a manual edit of the field.
        const resJson = await stealth_create_payment_lane(
            walletSession.json(), metaHex, amountSompi, stealthFeeValue('sf', 'send'), entropyHex, wsUrl, network
        );
        const res = JSON.parse(resJson);
        hideLoading();
        console.log('[KasSee] Stealth LANE payment PSKB:',
            'address=' + res.address, 'R=' + res.ephemeral_r, 'view_tag=' + res.view_tag);
        stealthState._stealthSendEntropy = null; // consume
        stealthState._stealthSendMeta = null;
        navigationState._broadcastReturnScreen = 'stealth';
        openPsktReview(res.pskb_wire);
    } catch (e) {
        hideLoading();
        toast('Stealth payment failed: ' + e, 'error', 5000);
        console.error('[KasSee] Stealth payment error:', e);
    }
}
