import { stealthState } from '../../../../app/state/index.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { build_vcc_subscribe_request } from '../../../../wasm/api.js';
// KasSee Web — features/stealth/index/scanning/live
import { byId } from '../../../../core/dom.js';
import { runHistoricalCatchUp } from './live/catch_up_session.js';
import { startLiveSocket } from './live/socket.js';
import { createStealthScanControls } from './live_controls.js';


export const {
    stealthScanPause,
    stealthScanStop,
    ensureStealthManualRSection,
    handleStealthShowScanQR,
    handleStealthScanResultQR,
} = createStealthScanControls();

export async function handleStealthFetchAnnouncements() {
    resetScanSession();
    try {
        const wsUrl = await resolveNodeUrl();
        const request = new Uint8Array(build_vcc_subscribe_request(44n));
        stealthState._stealthScanActive = true;
        startLiveSocket(wsUrl, request);
        await runHistoricalCatchUp();
    } catch (error) {
        byId('stealth-scan-status').textContent = 'Error: ' + error;
    }
}

function resetScanSession() {
    stealthScanStop();
    ensureStealthManualRSection();
    stealthState.stealthAnnouncementsR = [];
    stealthState._stealthBatchStart = 0;
    stealthState._stealthResults = [];
    byId('stealth-scan-status').textContent =
        'Connecting to node for on-chain stealth scan...';
}
