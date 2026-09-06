import { bindCommitRevealInputEvents } from './commit_reveal/input_events.js';
import { bindCommitRevealVerificationEvents } from './commit_reveal/verification_events.js';

export function bindCommitRevealEvents() {
    bindCommitRevealInputEvents();
    bindCommitRevealVerificationEvents();
}
