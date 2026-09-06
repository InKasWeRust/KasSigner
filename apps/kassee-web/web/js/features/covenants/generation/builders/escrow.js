import { networkState, walletSession } from '../../../../app/state/index.js';
import { toast } from '../../../../core/ui/toast.js';
import { covenant_escrow, covenant_ship_escrow, encode_p2pk_address } from '../../../../wasm/api.js';
// escrow covenant builders.

import { byId } from '../../../../core/dom.js';
import { addressToXOnly } from '../../../../core/address.js';
import { kasToSompi } from '../../../../core/amounts.js';
export async function buildEscrow(ownerPk) {
    let resultJson;
    let extra = {};
    const theirPk = addressToXOnly(byId('cov-escrow-pk').value);
    const arbiterPk = addressToXOnly(byId('cov-escrow-arbiter-pk').value);
    if (!ownerPk) { toast('Load wallet first', 'error'); return; }
    if (!theirPk || theirPk.length !== 64) { toast('Enter seller pubkey (64 hex chars)', 'error'); return; }
    if (!arbiterPk || arbiterPk.length !== 64) { toast('Enter arbiter pubkey (64 hex chars)', 'error'); return; }
    // Derive addresses from pubkeys. Use /0/0 receive address for buyer (matches wallet tracking).
    const w = walletSession.current();
    const myAddr = w.receive_addresses && w.receive_addresses[0] ? w.receive_addresses[0] : encode_p2pk_address(ownerPk, networkState.network);
    const theirAddr = encode_p2pk_address(theirPk, networkState.network);
    resultJson = covenant_escrow(ownerPk, theirPk, arbiterPk, myAddr, theirAddr, networkState.network);
    extra.bob_pk = theirPk;
    extra.arbiter_pk = arbiterPk;
    return { resultJson, extra };
}

export async function buildShipEscrow(ownerPk) {
    let resultJson;
    let extra = {};
    const sellerPk = addressToXOnly(byId('cov-ship-seller-pk').value);
    const delivPk = addressToXOnly(byId('cov-ship-deliverer-pk').value);
    const arbPk = addressToXOnly(byId('cov-ship-arbiter-pk').value);
    if (!ownerPk) { toast('Load wallet first (you are the buyer)', 'error'); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(sellerPk)) { toast('Enter seller pubkey (64 hex chars)', 'error'); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(delivPk)) { toast('Enter deliverer pubkey (64 hex chars)', 'error'); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(arbPk)) { toast('Enter arbiter pubkey (64 hex chars)', 'error'); return; }
    let productSompi, feeSompi;
    try { productSompi = kasToSompi(byId('cov-ship-product').value.trim()); } catch (_) { toast('Enter product price in KAS (up to 8 decimals)', 'error'); return; }
    try { feeSompi = kasToSompi(byId('cov-ship-fee').value.trim()); } catch (_) { toast('Enter delivery fee in KAS (up to 8 decimals)', 'error'); return; }
    if (productSompi <= 0n) { toast('Enter product price in KAS', 'error'); return; }
    if (feeSompi <= 0n) { toast('Enter delivery fee in KAS', 'error'); return; }
    const cltv1 = BigInt(byId('cov-ship-cltv1').value.trim() || '0');
    const cltv2 = BigInt(byId('cov-ship-cltv2').value.trim() || '0');
    if (cltv1 <= 0n || cltv2 <= 0n) { toast('Set both deadlines (DAA score)', 'error'); return; }
    resultJson = covenant_ship_escrow(JSON.stringify({
        seller_pubkey_hex: sellerPk,
        deliverer_pubkey_hex: delivPk,
        buyer_pubkey_hex: ownerPk,
        arbiter_pubkey_hex: arbPk,
        product_sompi: productSompi.toString(),
        fee_sompi: feeSompi.toString(),
        cltv1_deadline: cltv1.toString(),
        cltv2_deadline: cltv2.toString(),
        network: networkState.network,
    }));
    extra.seller_pk = sellerPk;
    extra.deliverer_pk = delivPk;
    extra.buyer_pk = ownerPk;
    extra.arbiter_pk = arbPk;
    extra.seller_addr = encode_p2pk_address(sellerPk, networkState.network);
    extra.deliverer_addr = encode_p2pk_address(delivPk, networkState.network);
    extra.buyer_addr = encode_p2pk_address(ownerPk, networkState.network);
    return { resultJson, extra };
}
