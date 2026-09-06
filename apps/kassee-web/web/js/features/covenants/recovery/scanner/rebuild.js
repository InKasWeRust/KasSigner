import { covenantState } from '../../../../app/state/index.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { covAddActive } from '../active.js';
import { fetch_utxos_for_address_js } from '../../../../wasm/api.js';
import { rebuildPrimaryRecoveredCovenant } from './primary.js';
import { rebuildExtendedRecoveredCovenant } from './extended.js';
import { sompiToKasString } from '../../../../core/amounts.js';


export async function rebuildCovenant(decrypted, ownerPk) {
    const typeName = decrypted.covenant_type_name;
    const params = decrypted.params_hex;
    if (!typeName || typeName === 'unknown') return false;

    let result = null;
    try {
        result = rebuildPrimaryRecoveredCovenant(typeName, params, ownerPk);
        if (result === undefined) {
            result = rebuildExtendedRecoveredCovenant(typeName, params, ownerPk);
        }
    } catch (e) {
        console.log('[KasSee] Recovery: failed to rebuild', typeName, e);
        return false;
    }

    if (!result) return false;

    // Check if already in active covenants
    if (covenantState.activeCovenants.some(c => c.address === result.address)) {
        console.log('[KasSee] Recovery: already active:', result.address);
        return false;
    }

    // Check balance. If empty, still add (user may want to re-fund or track).
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(result.address, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        result._balance = sompiToKasString(total);
    } catch (_) {
        result._balance = '0';
    }

    console.log('[KasSee] Recovery: found', typeName, 'at', result.address, 'balance:', result._balance, 'KAS');
    covAddActive(typeName, result);
    return true;
}
