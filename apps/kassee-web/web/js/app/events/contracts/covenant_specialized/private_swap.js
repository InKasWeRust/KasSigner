import { byId } from '../../../../core/dom.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import {
    beginPrivateSwapCreate,
    beginPrivateSwapJoin,
    clearPrivateSwap,
    completeAlicePrivateSwap,
    fundPrivateSwapSide,
    openPrivateSwapRefund,
    preparePrivateSwapPreSignature,
    privateSwapBackToHub,
    requestAliceSwapKey,
    requestBobSwapKey,
    requestPrivateSwapBinding,
    scanAlicePreSignature,
    scanBobReady,
    scanPrivateSwapDeviceResponse,
    scanPrivateSwapFinal,
    scanPrivateSwapResponse,
    shareAlicePreSignature,
    shareBobReady,
    sharePrivateSwapFinal,
    sharePrivateSwapOffer,
    sharePrivateSwapResponse,
    bobClaimPrivateSwap,
} from '../../../../features/covenants/private_swap/controller.js';

function on(id, handler) {
    byId(id)?.addEventListener('click', event => {
        event.preventDefault();
        const result = handler();
        if (result && typeof result.catch === 'function') result.catch(() => {});
    });
}

export function bindPrivateSwapEvents() {
    on('btn-private-swap-create', beginPrivateSwapCreate);
    on('btn-private-swap-join', beginPrivateSwapJoin);
    on('btn-private-swap-resume', () => covShowPanel('private-swap'));
    on('btn-private-swap-back', () => covShowPanel('menu'));
    on('btn-private-swap-create-back', privateSwapBackToHub);
    on('btn-private-swap-join-back', privateSwapBackToHub);
    on('btn-private-swap-dashboard-back', privateSwapBackToHub);
    on('btn-private-swap-create-key', requestAliceSwapKey);
    on('btn-private-swap-join-key', requestBobSwapKey);
    on('btn-private-swap-share-offer', sharePrivateSwapOffer);
    on('btn-private-swap-scan-response', scanPrivateSwapResponse);
    on('btn-private-swap-share-response', sharePrivateSwapResponse);
    on('btn-private-swap-scan-final', scanPrivateSwapFinal);
    on('btn-private-swap-bind', requestPrivateSwapBinding);
    on('btn-private-swap-share-final', sharePrivateSwapFinal);
    on('btn-private-swap-scan-device', scanPrivateSwapDeviceResponse);
    on('btn-private-swap-fund', fundPrivateSwapSide);
    on('btn-private-swap-presign', preparePrivateSwapPreSignature);
    on('btn-private-swap-share-presig', shareAlicePreSignature);
    on('btn-private-swap-scan-presig', scanAlicePreSignature);
    on('btn-private-swap-share-ready', shareBobReady);
    on('btn-private-swap-scan-ready', scanBobReady);
    on('btn-private-swap-complete', completeAlicePrivateSwap);
    on('btn-private-swap-bob-claim', bobClaimPrivateSwap);
    on('btn-private-swap-refund', openPrivateSwapRefund);
    on('btn-private-swap-clear', clearPrivateSwap);
}
