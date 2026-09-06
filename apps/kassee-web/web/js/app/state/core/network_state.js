// Explicit networkState shape. Complex behavior belongs in domain facades; this object holds simple session state.
export const networkState = Object.seal({
    'network': 'mainnet',
    'customNodeUrl': null,
    'customRestUrl': undefined,
    'utxoSnapshot': undefined,
    'lastFeeEstimate': null,
    'cachedUtxos': null,
    'msCachedUtxos': null,
    'msBranchScan': null,
});
