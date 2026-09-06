import { networkState } from '../../app/state/index.js';
import { RESOLVERS } from '../config/network.js';

function resolverSecurity() {
    return globalThis.location?.protocol === 'https:' ? 'tls' : 'any';
}

function isAllowedResolvedUrl(url, security) {
    if (typeof url !== 'string') return false;
    if (security === 'tls') return url.startsWith('wss://');
    return url.startsWith('ws://') || url.startsWith('wss://');
}

function resolverFailureDetail(error) {
    if (error instanceof Error && error.message) return error.message;
    return String(error);
}

export async function resolveNodeUrl() {
    if (networkState.customNodeUrl) return networkState.customNodeUrl;
    return resolvePublicNode();
}

export async function resolvePublicNode() {
    const security = resolverSecurity();
    const shuffled = [...RESOLVERS].sort(() => Math.random() - 0.5);
    const failures = [];
    for (const resolver of shuffled) {
        const url = `${resolver}/v2/kaspa/${networkState.network}/${security}/wrpc/borsh`;
        try {
            const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
            if (!response.ok) {
                failures.push(`${resolver}: HTTP ${response.status}`);
                continue;
            }
            const data = await response.json();
            if (isAllowedResolvedUrl(data.url, security)) {
                console.log(`[KasSee] Resolved ${networkState.network} node: ${data.url} (via ${resolver}, ${security})`);
                return data.url;
            }
            failures.push(`${resolver}: invalid ${security} wRPC URL`);
        } catch (error) {
            failures.push(`${resolver}: ${resolverFailureDetail(error)}`);
        }
    }
    throw new Error(
        `All resolvers failed for ${networkState.network} (${security}): ${failures.join(' | ')}`,
    );
}
