import { networkState } from '../../../../app/state/index.js';
import { decodeCommitReveal } from './extended/commit_reveal.js';
import { decodeGeneric } from './extended/generic.js';
import { decodeMerkleWhitelist } from './extended/merkle.js';
import { decodePayjoin } from './extended/payjoin.js';
import { decodeTimelockedEscrow } from './extended/timelocked_escrow.js';

const DECODERS = Object.freeze({
    'merkle-whitelist': (params, network) => decodeMerkleWhitelist(params, network),
    'timelocked-escrow': (params, network, ownerPublicKey) => decodeTimelockedEscrow(params, network, ownerPublicKey),
    payjoin: (params, network) => decodePayjoin(params, network),
    'commit-reveal': (params, network) => decodeCommitReveal(params, network),
});

export function rebuildExtendedRecoveredCovenant(type, params, ownerPublicKey) {
    const decoder = DECODERS[type];
    return decoder
        ? decoder(params, networkState.network, ownerPublicKey)
        : decodeGeneric(type, params, networkState.network);
}
