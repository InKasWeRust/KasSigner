import { covenantState } from '../../../../app/state/index.js';
import { byId } from '../../../../core/dom.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel, walletMatchesPk } from '../../generation/ui_and_keys.js';
import {
    covRenderMetaLine,
    ensureAllowanceParams,
    ensureEscrowParams,
    ensurePiggyParams,
} from '../../watchers_and_ui/ui/metadata.js';
import { covUpdateResultButtons } from '../../watchers_and_ui/ui/result_buttons.js';
import { ACTIVE_METADATA_FIELDS, copyDefinedFields, saveActiveRecords } from './repository.js';
import { stringifyCovenantJson } from '../../model/exact_fields.js';
import { restorePrivateSwapState } from '../../private_swap/state.js';

export function openActiveCovenant(covenant) {
    covenantState.lastCovenantResult = restoreActiveResult(covenant);
    hydrateCovenantParameters(covenant);
    detectStoredRole(covenant);
    persistLastResult();
    showResultPanel(covenant);
}

function restoreActiveResult(covenant) {
    const result = {
        address: covenant.address,
        redeem_script_hex: covenant.redeem_script_hex,
        locktime_daa: covenant.locktime_daa,
        type: covenant.type,
        loaded: covenant.loaded || false,
    };
    copyDefinedFields(covenant, result, ACTIVE_METADATA_FIELDS);
    if (covenant.covenant_id_hex) result.covenant_id_hex = covenant.covenant_id_hex;
    return result;
}

function hydrateCovenantParameters(covenant) {
    ensureAllowanceParams(covenantState.lastCovenantResult);
    ensureAllowanceParams(covenant);
    ensurePiggyParams(covenantState.lastCovenantResult);
    ensurePiggyParams(covenant);
    if (covenant.type === 'oracle-v1') {
        return matchingRole([
            ['beneficiary', covenantState.lastCovenantResult.beneficiary_pubkey_hex],
            ['owner', covenantState.lastCovenantResult.owner_pubkey_hex],
        ]);
    }
    if (covenant.type === 'escrow') {
        ensureEscrowParams(covenantState.lastCovenantResult);
        ensureEscrowParams(covenant);
    }
}

function detectStoredRole(covenant) {
    const role = roleForCovenant(covenant);
    if (!role) return;
    covenantState.lastCovenantResult.role = role;
    covenant.role = role;
    saveActiveRecords();
}

function roleForCovenant(covenant) {
    if (covenant.type === 'oracle-v1') {
        return matchingRole([
            ['beneficiary', covenantState.lastCovenantResult.beneficiary_pubkey_hex],
            ['owner', covenantState.lastCovenantResult.owner_pubkey_hex],
        ]);
    }
    if (covenant.type === 'escrow') {
        return matchingRole([
            ['owner', covenantState.lastCovenantResult.alice_pk],
            ['beneficiary', covenantState.lastCovenantResult.bob_pk],
            ['arbiter', covenantState.lastCovenantResult.arbiter_pk],
        ]);
    }
    return null;
}

function matchingRole(candidates) {
    const match = candidates.find(([, publicKey]) => publicKey && walletMatchesPk(publicKey));
    return match ? match[0] : null;
}

function persistLastResult() {
    try {
        sessionStorage.setItem('lastCovenantResult', stringifyCovenantJson(covenantState.lastCovenantResult));
    } catch (_) {
        // Session persistence is optional.
    }
}

function showResultPanel(covenant) {
    if (covenant.type === 'private-swap') {
        if (!covenant.private_swap_recovery_json) throw new Error('Private Swap recovery transcript is missing');
        restorePrivateSwapState(covenant.private_swap_recovery_json);
        covShowPanel('private-swap');
        toast('Loaded Private Swap protocol state', 'ok', 1500);
        return;
    }
    covShowPanel('result');
    covUpdateResultButtons(covenant.type);
    byId('cov-result-addr').textContent = covenant.address;
    byId('cov-result-script').textContent = covenant.redeem_script_hex;
    covRenderMetaLine(covenant);
    const balance = byId('cov-result-balance');
    balance.textContent = 'Loading...';
    balance.style.display = '';
    toast(`Loaded: ${covenant.label} covenant`, 'ok', 1500);
    setTimeout(() => byId('btn-cov-res-balance')?.click(), 300);
}
