import { navigationState } from '../../../../../app/state/index.js';
import { hideLoading, showLoading } from '../../../../../app/navigation.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { toast } from '../../../../../core/ui/toast.js';
import { openPsktReview } from '../../../../transactions/pskt_multisig/review.js';

/** Build a covenant claim, open review, and own loading/error lifecycle. */
export async function runCovenantClaim({
    loadingMessage,
    errorLabel,
    logLabel,
    build,
}) {
    showLoading(loadingMessage);
    try {
        const websocketUrl = await resolveNodeUrl();
        const pskbHex = await build(websocketUrl);
        console.log(`[KasSee] ${logLabel}: ${pskbHex.length} hex chars`);
        navigationState._broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
        return pskbHex;
    } catch (error) {
        toast(`${errorLabel}: ${error}`, 'error', 5000);
        console.error(`[KasSee] ${errorLabel}:`, error);
        return null;
    } finally {
        hideLoading();
    }
}
