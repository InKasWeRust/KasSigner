import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { covScanAddress, covScanPubkey } from '../../../../features/covenants/scanning_and_swap.js';
import { handleShipEscrowSpend } from '../../../../features/covenants/spending/standard/shipment.js';
import { byId } from '../../../../core/dom.js';

export function bindShipmentEscrowEvents() {
    // Shipment-escrow operate + create scan buttons
    if (byId('btn-cov-ship-back')) byId('btn-cov-ship-back').onclick = () => covShowPanel('result');
    if (byId('btn-cov-ship-pickup')) byId('btn-cov-ship-pickup').onclick = () => handleShipEscrowSpend('pickup');
    if (byId('btn-cov-ship-s0-arb')) byId('btn-cov-ship-s0-arb').onclick = () => handleShipEscrowSpend('state0-arb-refund');
    if (byId('btn-cov-ship-s0-timeout')) byId('btn-cov-ship-s0-timeout').onclick = () => handleShipEscrowSpend('state0-timeout');
    if (byId('btn-cov-ship-delivery')) byId('btn-cov-ship-delivery').onclick = () => handleShipEscrowSpend('delivery');
    if (byId('btn-cov-ship-s1-award')) byId('btn-cov-ship-s1-award').onclick = () => handleShipEscrowSpend('state1-arb-award');
    if (byId('btn-cov-ship-s1-arb-refund')) byId('btn-cov-ship-s1-arb-refund').onclick = () => handleShipEscrowSpend('state1-arb-refund');
    if (byId('btn-cov-ship-s1-timeout')) byId('btn-cov-ship-s1-timeout').onclick = () => handleShipEscrowSpend('state1-timeout');
    if (byId('btn-cov-scan-ship-seller')) byId('btn-cov-scan-ship-seller').onclick = () => covScanPubkey('cov-ship-seller-pk', 'Scan seller pubkey');
    if (byId('btn-cov-scan-ship-deliverer')) byId('btn-cov-scan-ship-deliverer').onclick = () => covScanPubkey('cov-ship-deliverer-pk', 'Scan deliverer pubkey');
    if (byId('btn-cov-scan-ship-arbiter')) byId('btn-cov-scan-ship-arbiter').onclick = () => covScanPubkey('cov-ship-arbiter-pk', 'Scan arbiter pubkey');
    if (byId('btn-cov-scan-ship-addr')) byId('btn-cov-scan-ship-addr').onclick = () => covScanAddress('cov-ship-addr', 'Scan covenant address');
}
