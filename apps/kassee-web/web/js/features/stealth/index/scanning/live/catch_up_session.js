import { networkState, stealthState } from '../../../../../app/state/index.js';
import { STEALTH_LOOKBACK_BLUE_SCORE, STEALTH_MAX_R } from '../../config.js';
import { kaspaRestApiBase } from '../../../../../core/config/network.js';
import { STEALTH_INDEXER_URL } from '../../../../../core/config/services.js';
import { stealthRestCatchUp } from '../catch_up.js';
import { byId } from '../../../../../core/dom.js';
export async function runHistoricalCatchUp() {
    stealthState._stealthCatchupRunning = true;
    try {
        const apiBase = kaspaRestApiBase(networkState.network);
        byId('stealth-scan-status').textContent =
            'Scanning recent blocks via indexer… (live also running)';
        const recent = await fetchCandidates(apiBase);
        const result = mergeCandidates(recent);
        showResult(result.added, result.capHit);
    } catch (error) {
        console.log('[KasSee] Stealth REST catch-up skipped:', error);
    } finally {
        stealthState._stealthCatchupRunning = false;
    }
}

async function fetchCandidates(apiBase) {
    if (!stealthState.stealthIndexerEnabled) return stealthRestCatchUp(apiBase);
    try {
        byId('stealth-scan-status').textContent =
            'Fetching R from stealth indexer… (live also running)';
        const response = await fetch(STEALTH_INDEXER_URL + '/r?since=0', {
            signal: AbortSignal.timeout(10000)
        });
        if (!response.ok) throw new Error('indexer HTTP ' + response.status);
        const candidates = await response.json();
        if (!Array.isArray(candidates)) throw new Error('indexer returned non-array');
        console.log('[KasSee] stealth indexer returned ' + candidates.length + ' R');
        return candidates;
    } catch (error) {
        console.log('[KasSee] stealth indexer unreachable, falling back to in-browser scan:', error);
        byId('stealth-scan-status').textContent =
            'Indexer unreachable, scanning in-browser… (live also running)';
        return stealthRestCatchUp(apiBase);
    }
}

function mergeCandidates(candidates) {
    let added = 0;
    let capHit = false;
    for (const candidate of candidates) {
        if (typeof candidate !== 'string' || candidate.length !== 64) continue;
        if (stealthState.stealthAnnouncementsR.includes(candidate)) continue;
        if (stealthState.stealthAnnouncementsR.length >= STEALTH_MAX_R) {
            capHit = true;
            break;
        }
        stealthState.stealthAnnouncementsR.push(candidate);
        added++;
    }
    return { added, capHit };
}

function showResult(added, capHit) {
    if (capHit) {
        console.log('[KasSee] Stealth catch-up hit STEALTH_MAX_R cap (' +
            STEALTH_MAX_R + ')');
    }
    if (stealthState.stealthAnnouncementsR.length > 0) {
        const list = byId('stealth-r-list');
        if (list) list.textContent = stealthState.stealthAnnouncementsR.length + ' R value(s) loaded';
        byId('btn-stealth-show-scan-qr').classList.remove('hidden');
        byId('stealth-scan-status').textContent =
            'Found ' + stealthState.stealthAnnouncementsR.length +
            ' candidate R (lane + live). Tap "Show QR for Device".';
    } else {
        const approximateMinutes = Number(STEALTH_LOOKBACK_BLUE_SCORE / 10n / 60n);
        byId('stealth-scan-status').textContent =
            'No payments in the last ~' + approximateMinutes +
            ' min. Live scan now watching for new ones while this stays open…';
    }
    console.log('[KasSee] Stealth REST catch-up: +' + added + ' R (total ' +
        stealthState.stealthAnnouncementsR.length + ')');
}
