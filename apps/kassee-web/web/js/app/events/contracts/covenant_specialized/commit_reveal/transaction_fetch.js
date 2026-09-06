import { kaspaRestApiBase } from '../../../../../core/config/network.js';
export async function fetchCommitRevealTransaction(txid, network) {
    const apiBase = kaspaRestApiBase(network);
    const response = await fetch(apiBase + '/transactions/' + txid);
    if (!response.ok) throw new Error('TX not found (HTTP ' + response.status + ')');
    return response.json();
}
