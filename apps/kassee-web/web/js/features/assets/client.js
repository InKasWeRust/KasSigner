import { KASPLEX_API, KNS_LOOKUP, KRC721_API } from '../../core/config/services.js';
import { exactUnsigned } from '../../core/exact.js';

async function fetchJson(url) {
    const response = await fetch(url, { signal: AbortSignal.timeout(8000) });
    return response.ok ? response.json() : null;
}

async function collectKrc20(addresses, network) {
    const base = KASPLEX_API[network];
    const tokens = new Map();
    if (!base) return tokens;
    for (const address of addresses) {
        try {
            const data = await fetchJson(`${base}/krc20/address/${address}/tokenlist`);
            for (const token of data?.result || []) {
                const tick = token.tick || token.ticker || '';
                const balance = exactUnsigned(token.balance ?? '0', 'KRC20 balance');
                const decimalValue = exactUnsigned(token.dec ?? '8', 'KRC20 decimals');
                if (decimalValue > 255n) throw new Error('KRC20 decimals exceed supported range');
                const decimals = Number(decimalValue);
                if (!tick || balance === 0n) continue;
                const current = tokens.get(tick) || { balance: 0n, decimals };
                if (current.decimals !== decimals) throw new Error(`KRC20 ${tick} decimals changed across addresses`);
                current.balance += balance;
                tokens.set(tick, current);
            }
        } catch (_) {}
    }
    return tokens;
}

async function collectKrc721(addresses, network) {
    const base = KRC721_API[network];
    const nfts = [];
    if (!base) return nfts;
    const collectionBuri = new Map();
    for (const address of addresses) {
        try {
            const data = await fetchJson(`${base}/address/${address}`);
            for (const nft of data?.result || []) {
                const tick = nft.tick || '';
                const tokenId = nft.tokenId || nft.token_id || '';
                if (!tick || !tokenId) continue;
                if (!collectionBuri.has(tick)) {
                    try {
                        const collection = await fetchJson(`${base}/nfts/${tick}`);
                        collectionBuri.set(tick, collection?.result?.buri || '');
                    } catch (_) {
                        collectionBuri.set(tick, '');
                    }
                }
                const buri = collectionBuri.get(tick);
                nfts.push({ tick, tokenId, metadataUrl: buri ? `${buri}/${tokenId}.json` : '' });
            }
        } catch (_) {}
    }
    return nfts;
}

function collectKns(addresses) {
    const addressSet = new Set(addresses);
    return Object.entries(KNS_LOOKUP)
        .filter(([, address]) => addressSet.has(address))
        .map(([domain]) => domain);
}

export async function fetchWalletAssets(wallet, network) {
    const addresses = [...wallet.receive_addresses, ...wallet.change_addresses];
    const [tokens, nfts] = await Promise.all([
        collectKrc20(addresses, network),
        collectKrc721(addresses, network),
    ]);
    return { tokens, nfts, domains: collectKns(addresses) };
}
