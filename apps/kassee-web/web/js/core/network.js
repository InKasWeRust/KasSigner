// Pure network selection derived from wallet addresses and the selected node network.

export function detectWalletNetwork(walletJson, selectedNetwork = 'mainnet') {
    if (!walletJson) return 'mainnet';
    const wallet = typeof walletJson === 'string' ? JSON.parse(walletJson) : walletJson;
    const address = wallet.receive_addresses?.[0] || '';
    if (address.startsWith('kaspatest:')) {
        return selectedNetwork.startsWith('testnet') ? selectedNetwork : 'testnet-10';
    }
    if (address.startsWith('kaspasim:')) return 'simnet';
    if (address.startsWith('kaspadev:')) return 'devnet';
    return 'mainnet';
}

export function addressPrefix(network = 'mainnet') {
    if (network === 'mainnet') return 'kaspa:';
    if (network === 'devnet') return 'kaspadev:';
    if (network === 'simnet') return 'kaspasim:';
    if (network.startsWith('testnet')) return 'kaspatest:';
    return '';
}
