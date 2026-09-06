import { configureCommitRevealVerification } from './auxiliary/commit_reveal.js';
import { configureInviteSharing } from './auxiliary/invite.js';

export function configureAuxiliaryResultActions(state) {
    configureCommitRevealVerification(state.type);
    configureInviteSharing(state);
}
