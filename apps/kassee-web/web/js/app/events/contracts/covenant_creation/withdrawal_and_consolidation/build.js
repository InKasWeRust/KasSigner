import { covenantState } from '../../../../state/index.js';
import {
    create_covenant_beneficiary_spend_selected,
    create_covenant_owner_spend_selected,
    create_covenant_timelocked_savings_claim_selected,
} from '../../../../../wasm/api.js';
import { assertBeneficiaryClaimUnlocked, beneficiaryClaim } from './policy.js';
import { selectedUtxosJson } from './selection.js';

export function buildSelectedSpend({ destination, selected, fee, ownerBranch }) {
    const result = covenantState.lastCovenantResult;
    const covenantAddress = result.address;
    const redeemScript = result.redeem_script_hex;
    const utxos = selectedUtxosJson(selected);
    const claim = beneficiaryClaim();

    if (!claim) {
        return create_covenant_owner_spend_selected(
            covenantAddress,
            destination,
            redeemScript,
            utxos,
            fee,
            ownerBranch,
        );
    }

    const locktime = BigInt(claim.locktime || 0);
    const type = result.type || '';
    assertBeneficiaryClaimUnlocked(type, locktime);
    return type === 'timelocked-savings'
        ? create_covenant_timelocked_savings_claim_selected(
            covenantAddress,
            destination,
            redeemScript,
            locktime,
            utxos,
            fee,
        )
        : create_covenant_beneficiary_spend_selected(
            covenantAddress,
            destination,
            redeemScript,
            locktime,
            utxos,
            fee,
        );
}
