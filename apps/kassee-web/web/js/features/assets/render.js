import { byId } from '../../core/dom.js';
import { exactUnsigned } from '../../core/exact.js';

export function formatTokenBalance(balance, decimals) {
    const value = exactUnsigned(balance, 'KRC20 balance');
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
        throw new Error('KRC20 decimals must be an integer in 0..255');
    }
    if (decimals === 0) return value.toString();
    const digits = value.toString().padStart(decimals + 1, '0');
    const whole = digits.slice(0, -decimals);
    const fraction = digits.slice(-decimals);
    return `${whole}.${fraction}`;
}

function textElement(tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = String(text);
    return element;
}

function tokenItem(name, balance) {
    const item = document.createElement('div');
    item.className = 'token-item';
    item.append(
        textElement('div', 'token-tick', name),
        textElement('div', 'token-balance', balance),
    );
    return item;
}

function renderTokens(tokens) {
    if (!tokens.size) return [];
    const nodes = [textElement('div', 'tokens-section-label', 'KRC-20 Tokens')];
    for (const [tick, token] of [...tokens.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        nodes.push(tokenItem(tick, formatTokenBalance(token.balance, token.decimals)));
    }
    return nodes;
}

function renderNfts(nfts) {
    if (!nfts.length) return [];
    return [
        textElement('div', 'tokens-section-label u-mt-12px', 'KRC-721 NFTs'),
        ...nfts.map((nft) => tokenItem(nft.tick, `#${nft.tokenId}`)),
    ];
}

function renderDomains(domains) {
    if (!domains.length) return [];
    return [
        textElement('div', 'tokens-section-label u-mt-12px', 'KNS Domains'),
        ...domains.map((domain) => {
            const item = document.createElement('div');
            item.className = 'token-item';
            item.append(textElement('div', 'token-tick', domain));
            return item;
        }),
    ];
}

export function renderWalletAssets({ tokens, nfts, domains }) {
    const total = tokens.size + nfts.length + domains.length;
    const list = byId('tokens-list');
    if (!total) {
        byId('tokens-summary').textContent = 'No tokens, NFTs, or domains found';
        list.replaceChildren(textElement(
            'div',
            'u-align-text-center-text-text-muted-padding-20px',
            'Your addresses have no KRC-20 tokens, KRC-721 NFTs, or KNS domains',
        ));
        return;
    }
    const summary = [];
    if (tokens.size) summary.push(`${tokens.size} token${tokens.size === 1 ? '' : 's'}`);
    if (nfts.length) summary.push(`${nfts.length} NFT${nfts.length === 1 ? '' : 's'}`);
    if (domains.length) summary.push(`${domains.length} domain${domains.length === 1 ? '' : 's'}`);
    byId('tokens-summary').textContent = `${summary.join(', ')} found`;
    list.replaceChildren(...renderTokens(tokens), ...renderNfts(nfts), ...renderDomains(domains));
}
