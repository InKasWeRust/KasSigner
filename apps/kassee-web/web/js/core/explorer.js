const EXPLORERS = Object.freeze({
    mainnet: 'https://explorer.kaspa.org',
    'testnet-10': 'https://explorer-tn10.kaspa.org',
    'testnet-11': 'https://explorer-tn11.kaspa.org',
    'testnet-12': 'https://explorer-tn12.kaspa.org',
});

export function explorerBase(network) {
    const base = EXPLORERS[network];
    if (!base) throw new Error(`No block explorer configured for ${network}`);
    return base;
}

export function explorerAddressUrl(network, address) {
    const base = explorerBase(network);
    return `${base}/addresses/${encodeURIComponent(address)}`;
}

export function explorerTransactionUrl(network, transactionId) {
    const base = explorerBase(network);
    return `${base}/txs/${encodeURIComponent(transactionId)}`;
}
