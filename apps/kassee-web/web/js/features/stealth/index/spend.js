import { navigationState, networkState, walletSession } from '../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../app/navigation.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import { stealthFeeValue } from './send.js';
import { openPsktReview } from '../../transactions/pskt_multisig/review.js';
import { detectWalletNetwork } from '../../../core/network.js';
import { create_stealth_spend } from '../../../wasm/api.js';
// KasSee Web — features/stealth/index/spend


// ─── Stealth Spend ───

export async function handleStealthSpend(pubkeyHex, tweakHex) {
    if (!walletSession.hasWallet()) { toast('Load wallet first', 'error'); return; }

    const network = detectWalletNetwork(walletSession.json(), networkState.network);

    // Build a normal P2PK spend but with stealthTweak in proprietaries
    showLoading('Building stealth spend...');
    try {
        const wsUrl = await resolveNodeUrl();
        const wallet = walletSession.current();

        // Derive the one-time address from the pubkey
        // P2PK address = encode_p2pk(pubkeyHex)
        // We need a dest address — use Bob's first receive address
        const destAddr = wallet.receive_addresses[0];

        // Spend fee from the low/normal/priority selector (node feerate x mass).
        const pskbHex = await create_stealth_spend(
            pubkeyHex, tweakHex, destAddr, stealthFeeValue('spf', 'spend'), wsUrl, network
        );

        hideLoading();
        console.log('[KasSee] Stealth spend PSKB:', pskbHex.length, 'hex chars');
        navigationState._broadcastReturnScreen = 'stealth';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Stealth spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Stealth spend error:', e);
    }
}
