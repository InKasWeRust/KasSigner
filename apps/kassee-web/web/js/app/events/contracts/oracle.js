import { walletSession } from '../../state/index.js';
import { oracleMbAskForNew, oracleMbSetFee } from '../../../features/oracle/model_b/controller.js';
import { navigateBack, showScreen } from '../../navigation.js';
import { covShowPanel } from '../../../features/covenants/generation/ui_and_keys.js';
import { covScanAddress } from '../../../features/covenants/scanning/pubkeys.js';
import {
    buildOracleV1Claim, openOracleV1Attest, publishOracleV1Beacon,
    scanOracleV1BindingResponse, scanOracleV1ClaimAttestation, scanOracleV1KeyResponse, scanOracleV1CovenantSignResponse,
    showOracleV1AttestationQr, showOracleV1BindingRequest, showOracleV1KeyRequest, showOracleV1SignRequest,
} from '../../../features/oracle/v1/controller.js';
// KasSee Web — app/events/contracts/oracle
// Binds covenant navigation and oracle-model-B controls.

import { byId } from '../../../core/dom.js';


export function bindOracleEvents() {

    // ─── Covenant++ handlers ───
    byId('btn-covenant').onclick = () => { covShowPanel('menu'); showScreen('covenant'); };
    byId('btn-cov-back').onclick = () => navigateBack(walletSession.hasWallet() ? 'dashboard' : 'welcome');
    if (byId('btn-oracle-mb-back')) byId('btn-oracle-mb-back').onclick = () => covShowPanel('menu');
    if (byId('btn-oracle-mb-ask')) byId('btn-oracle-mb-ask').onclick = () => oracleMbAskForNew();
    // Oracle roll fee selector: presets (1/2/3 KAS) + a custom amount (min 1). The chosen total is the
    // miner fee plus the 0.3 service fee; a bigger total raises the feerate so the roll clears a busy mempool.
    document.querySelectorAll('.omb-fee-btn').forEach(b => {
        b.onclick = () => { const ci = byId('input-omb-fee-custom'); if (ci) ci.value = ''; oracleMbSetFee(b.getAttribute('data-omb-fee'), false); };
    });
    { const ci = byId('input-omb-fee-custom'); if (ci) ci.oninput = () => {
        const v = ci.value.trim();
        if (v === '') { oracleMbSetFee(1, false); return; }
        oracleMbSetFee(v, true);
    }; }
    oracleMbSetFee(1, false);

    if (byId('btn-cov-scan-oracle-v1-bene')) byId('btn-cov-scan-oracle-v1-bene').onclick = () => covScanAddress('cov-oracle-v1-bene', 'Scan beneficiary address', true);
    if (byId('btn-cov-oracle-v1-key-request')) byId('btn-cov-oracle-v1-key-request').onclick = () => showOracleV1KeyRequest();
    if (byId('btn-cov-scan-oracle-v1-key')) byId('btn-cov-scan-oracle-v1-key').onclick = () => scanOracleV1KeyResponse();
    if (byId('btn-cov-res-oracle-v1-bind')) byId('btn-cov-res-oracle-v1-bind').onclick = () => showOracleV1BindingRequest();
    if (byId('btn-cov-res-oracle-v1-scan-binding')) byId('btn-cov-res-oracle-v1-scan-binding').onclick = () => scanOracleV1BindingResponse();
    if (byId('btn-cov-res-oracle-v1-attest')) byId('btn-cov-res-oracle-v1-attest').onclick = () => openOracleV1Attest();
    if (byId('btn-cov-oracle-v1-scan-attestation')) byId('btn-cov-oracle-v1-scan-attestation').onclick = () => scanOracleV1ClaimAttestation();
    if (byId('btn-cov-scan-oracle-v1-claim-dest')) byId('btn-cov-scan-oracle-v1-claim-dest').onclick = () => covScanAddress('cov-oracle-v1-claim-dest', 'Scan claim destination', true);
    if (byId('btn-cov-oracle-v1-claim-create')) byId('btn-cov-oracle-v1-claim-create').onclick = () => buildOracleV1Claim();
    if (byId('btn-cov-oracle-v1-claim-back')) byId('btn-cov-oracle-v1-claim-back').onclick = () => covShowPanel('result');
    if (byId('btn-cov-oracle-v1-sign-request')) byId('btn-cov-oracle-v1-sign-request').onclick = () => showOracleV1SignRequest();
    if (byId('btn-cov-oracle-v1-scan-signed')) byId('btn-cov-oracle-v1-scan-signed').onclick = () => scanOracleV1CovenantSignResponse();
    if (byId('btn-cov-oracle-v1-beacon')) byId('btn-cov-oracle-v1-beacon').onclick = () => publishOracleV1Beacon();
    if (byId('btn-cov-oracle-v1-share')) byId('btn-cov-oracle-v1-share').onclick = () => showOracleV1AttestationQr();
    if (byId('btn-cov-oracle-v1-attest-back')) byId('btn-cov-oracle-v1-attest-back').onclick = () => covShowPanel('result');
}
