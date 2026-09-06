import { createPsktFinalizer } from './review_finalize.js';
import { createPsktRelayActions } from './review_relay.js';

export function createPsktReviewActions() {
  return {
    ...createPsktRelayActions(),
    handlePsktFinalize: createPsktFinalizer(),
  };
}
