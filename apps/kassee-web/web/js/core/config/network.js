export const AUTO_REFRESH_INTERVAL = 30_000;
export const GAP_EXPAND_RECEIVE = 10;
export const GAP_EXPAND_CHANGE = 5;

export const RESOLVERS = Object.freeze([
    'https://maxim.kaspa.stream',
    'https://troy.kaspa.stream',
    'https://sean.kaspa.stream',
    'https://eric.kaspa.stream',
    'https://jake.kaspa.green',
    'https://mark.kaspa.green',
    'https://adam.kaspa.green',
    'https://liam.kaspa.green',
    'https://noah.kaspa.blue',
    'https://ryan.kaspa.blue',
    'https://jack.kaspa.blue',
    'https://luke.kaspa.blue',
    'https://john.kaspa.red',
    'https://mike.kaspa.red',
    'https://paul.kaspa.red',
    'https://alex.kaspa.red',
]);

export function kaspaRestApiBase(network) {
    const endpoints = Object.freeze({
        mainnet: 'https://api.kaspa.org',
        'testnet-10': 'https://api-tn10.kaspa.org',
        'testnet-12': 'https://api-tn12.kaspa.org',
    });
    const endpoint = endpoints[network];
    if (!endpoint) throw new Error(`No public Kaspa REST endpoint configured for ${network}`);
    return endpoint;
}
