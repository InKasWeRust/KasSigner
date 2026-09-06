import { start } from './navigation.js';
// Ordered application composition.
import '../features/covenants/payload_and_swaps.js';
import '../core/state/session.js';
import '../features/covenants/recovery.js';
import './navigation.js';
import '../features/wallet/core.js';
import '../features/transactions/send.js';
import '../features/transactions/pskt_multisig.js';
import '../features/covenants/scanning_and_swap.js';
import '../features/covenants/watchers_and_ui.js';
import '../features/covenants/generation.js';
import '../features/covenants/spending.js';
import '../features/stealth/index.js';
import '../features/wallet/tools.js';
import '../features/assets/index.js';
import '../features/donations/screen.js';
import '../features/settings/screen.js';
import '../features/wallet/reset.js';
import '../features/oracle/model_b.js';
export async function startApplication() {
    return start();
}
