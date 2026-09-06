import { networkState } from '../../../../../app/state/index.js';
import { addressToXOnly } from '../../../../../core/address.js';
import { byId } from '../../../../../core/dom.js';
import { exactUnsigned } from '../../../../../core/exact.js';
import { resolveFutureDaa } from '../../../../../core/node/future_daa.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covenant_oracle_v1 } from '../../../../../wasm/api.js';

export async function buildOracleV1(ownerPk) {
    const beneficiaryPk = addressToXOnly(byId('cov-oracle-v1-bene').value);
    const oraclePk = byId('cov-oracle-v1-pubkey').value.trim().toLowerCase();
    const oracleKeyId = byId('cov-oracle-v1-key-id').value.trim().toLowerCase();
    const statement = byId('cov-oracle-v1-statement').value.trim();
    const date = byId('cov-oracle-v1-datetime').value;
    if (!beneficiaryPk || beneficiaryPk.length !== 64) {
        toast('Enter or scan the beneficiary address', 'error'); return;
    }
    if (!/^[0-9a-f]{64}$/.test(oraclePk) || !/^[0-9a-f]{64}$/.test(oracleKeyId)) {
        toast('Generate an oracle Covenant Key request and scan its KasSigner response', 'error'); return;
    }
    if (!statement) { toast('Enter the exact release statement the oracle will sign', 'error'); return; }
    if (!date) { toast('Pick an owner refund date', 'error'); return; }
    let locktimeDaa;
    try {
        locktimeDaa = exactUnsigned((await resolveFutureDaa(date)).daa, 'oracle refund DAA');
    } catch (error) {
        toast(error.message, 'error'); return;
    }
    if (locktimeDaa === 0n) { toast('Refund date must be in the future', 'error'); return; }
    byId('cov-oracle-v1-locktime').value = String(locktimeDaa);
    const resultJson = covenant_oracle_v1(
        ownerPk, beneficiaryPk, oraclePk, oracleKeyId, statement, locktimeDaa, networkState.network,
    );
    return {
        resultJson,
        extra: {
            owner_pubkey_hex: ownerPk,
            beneficiary_pubkey_hex: beneficiaryPk,
            oracle_pubkey_hex: oraclePk,
            oracle_covenant_key_id_hex: oracleKeyId,
            locktime_date_iso: new Date(date).toISOString(),
        },
    };
}
