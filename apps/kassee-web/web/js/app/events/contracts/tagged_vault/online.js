import { networkState, walletSession } from '../../../state/index.js';
import { kasToSompi } from '../../../../core/amounts.js';
import { byId } from '../../../../core/dom.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { openPsktReview } from '../../../../features/transactions/pskt_multisig/review.js';
import {
    decode_address,
    split_vault_genesis_pskb,
    split_vault_spend_pskb,
    tagged_vault_genesis_pskb,
    tagged_vault_spend_pskb,
} from '../../../../wasm/api.js';

const COMPUTE_MASS_FEE = 300000n;

export function bindTaggedVaultOnline(state, log) {
    bindBackButton();
    bindWatchOnlyIdentity(state, log);
    bindGenesis(state, log);
    bindSpend(state, log);
    bindSplit(state, log);
}

function bindBackButton() {
    const button = byId('btn-tv-back');
    if (button) button.onclick = () => covShowPanel('menu');
}

function requireWatchOnlyOwner(state) {
    if (!walletSession.hasWallet()) throw new Error('Load a kpub/xpub watch-only wallet first');
    const wallet = walletSession.current();
    const address = wallet?.receive_addresses?.[0] || '';
    if (!address) throw new Error('Watch-only wallet has no receive address');
    const ownerPubkey = JSON.parse(decode_address(address)).payload;
    if (!/^[0-9a-f]{64}$/.test(ownerPubkey)) throw new Error('Could not derive owner public key from kpub/xpub wallet');
    state.pk = ownerPubkey;
    state.addr = address;
    return { ownerPubkey, address };
}

function bindWatchOnlyIdentity(state, log) {
    const button = byId('btn-tv-keygen');
    if (!button) return;
    button.onclick = () => {
        try {
            const identity = requireWatchOnlyOwner(state);
            byId('tv-eph-address').textContent = identity.address;
            byId('tv-eph-pubkey').textContent = identity.ownerPubkey;
            byId('tv-keygen-result').classList.remove('hidden');
            log(`Watch-only owner loaded: ${identity.address}`);
            toast('Using kpub/xpub watch-only account. Signing stays on KasSigner.', 'ok', 3500);
        } catch (error) {
            toast(`Watch-only account required: ${error}`, 'error');
        }
    };
}

function bindGenesis(state, log) {
    const button = byId('btn-tv-genesis');
    if (!button) return;
    button.onclick = async () => {
        const amount = readAmount('tv-amount');
        if (!amount) return;
        try {
            const { ownerPubkey } = requireWatchOnlyOwner(state);
            log(`Genesis PSKB: ${amount.kas} KAS to tagged vault...`);
            const result = JSON.parse(await tagged_vault_genesis_pskb(
                walletSession.json(), ownerPubkey, amount.sompi, COMPUTE_MASS_FEE,
                networkState.network, await resolveNodeUrl(),
            ));
            Object.assign(state, {
                covId: result.covenant_id_hex,
                covAddr: result.covenant_address,
                redeemHex: result.redeem_script_hex,
            });
            renderGenesis(result);
            log(`Genesis PSKB ready; covenant ID: ${result.covenant_id_hex}`);
            openPsktReview(result.pskb_hex);
            toast('Genesis PSKB ready. Scan and sign it on KasSigner.', 'ok', 4000);
        } catch (error) {
            reportFailure('Genesis PSKB', error, log);
        }
    };
}

function bindSpend(state, log) {
    const button = byId('btn-tv-spend');
    if (!button) return;
    button.onclick = async () => {
        if (!state.covId || !state.covAddr) {
            toast('Prepare and broadcast the hardware-signed genesis first', 'error');
            return;
        }
        try {
            const { ownerPubkey } = requireWatchOnlyOwner(state);
            const result = JSON.parse(await tagged_vault_spend_pskb(
                state.covAddr, ownerPubkey, state.covId, COMPUTE_MASS_FEE,
                networkState.network, await resolveNodeUrl(),
            ));
            log(`Continuation PSKB ready; covenant ID remains ${result.covenant_id_hex}`);
            byId('tv-spend-covid').textContent = result.covenant_id_hex;
            byId('tv-spend-txid').textContent = 'Pending KasSigner signature';
            byId('tv-spend-result').classList.remove('hidden');
            openPsktReview(result.pskb_hex);
            toast('Continuation PSKB ready. Sign it on KasSigner.', 'ok', 4000);
        } catch (error) {
            reportFailure('Continuation PSKB', error, log);
        }
    };
}

function bindSplit(state, log) {
    const button = byId('btn-tv-split');
    if (!button) return;
    button.onclick = async () => {
        try {
            const { ownerPubkey } = requireWatchOnlyOwner(state);
            const wsUrl = await resolveNodeUrl();
            if (!state.splitCovId || !state.splitCovAddr) {
                const genesis = JSON.parse(await split_vault_genesis_pskb(
                    walletSession.json(), ownerPubkey, 300000000n, COMPUTE_MASS_FEE,
                    networkState.network, wsUrl,
                ));
                state.splitCovId = genesis.covenant_id_hex;
                state.splitCovAddr = genesis.covenant_address;
                state.splitRedeemHex = genesis.redeem_script_hex;
                log(`Split-vault genesis PSKB ready: ${genesis.covenant_id_hex}`);
                button.textContent = '4. Build Hardware-Signed Split Spend';
                openPsktReview(genesis.pskb_hex);
                toast('Split genesis PSKB ready. Sign/broadcast it, then tap Split again.', 'ok', 5000);
                return;
            }
            const result = JSON.parse(await split_vault_spend_pskb(
                state.splitCovAddr, ownerPubkey, state.splitCovId, COMPUTE_MASS_FEE,
                networkState.network, wsUrl,
            ));
            renderSplit(result);
            log(`Split PSKB ready: ${result.amount_a} / ${result.amount_b} sompi`);
            openPsktReview(result.pskb_hex);
            toast('Split PSKB ready. Sign it on KasSigner.', 'ok', 4000);
        } catch (error) {
            reportFailure('Split PSKB', error, log);
        }
    };
}

function readAmount(inputId) {
    const input = byId(inputId).value.trim();
    try {
        const sompi = kasToSompi(input);
        if (sompi < 10_000_000n) throw new Error('below minimum');
        return { kas: input, sompi };
    } catch (_) {
        toast('Enter an amount >= 0.1 KAS (up to 8 decimals)', 'error');
        return null;
    }
}

function renderGenesis(result) {
    byId('tv-genesis-txid').textContent = 'Pending KasSigner signature';
    byId('tv-covenant-id').textContent = result.covenant_id_hex;
    byId('tv-covenant-addr').textContent = result.covenant_address;
    byId('tv-genesis-result').classList.remove('hidden');
}

function renderSplit(result) {
    byId('tv-split-txid').textContent = 'Pending KasSigner signature';
    byId('tv-split-covid').textContent = result.covenant_id_hex;
    byId('tv-split-amounts').textContent = `${result.amount_a} / ${result.amount_b} sompi`;
    byId('tv-split-result').classList.remove('hidden');
}

function reportFailure(operation, error, log) {
    log(`ERROR: ${error}`);
    toast(`${operation} failed: ${error}`, 'error');
}
