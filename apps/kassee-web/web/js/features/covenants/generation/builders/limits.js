import { networkState } from '../../../../app/state/index.js';
import { kasToSompi } from '../../../../core/amounts.js';
import { byId } from '../../../../core/dom.js';
import { resolveFutureDaa } from '../../../../core/node/future_daa.js';
import { toast } from '../../../../core/ui/toast.js';
import { covenant_global_allowance, covenant_global_spending_limit, decode_address } from '../../../../wasm/api.js';

function positiveSeconds(inputId, message) {
    const text = byId(inputId).value.trim();
    if (!/^\d+$/.test(text) || BigInt(text) === 0n) {
        toast(message, 'error');
        return null;
    }
    return BigInt(text);
}

function positiveSompi(inputId, message) {
    try {
        const value = kasToSompi(byId(inputId).value);
        if (value === 0n) throw new Error('zero');
        return value;
    } catch (_) {
        toast(message, 'error');
        return null;
    }
}

export async function buildGlobalSpendingLimit(ownerPk) {
    const sompi = positiveSompi('cov-splimit-max', 'Enter max withdrawal in KAS');
    if (sompi === null) return;
    const cooldownSeconds = positiveSeconds('cov-splimit-cooldown', 'Set a cooldown period');
    if (cooldownSeconds === null) return;
    const cooldownDaa = cooldownSeconds * 10n;
    const resultJson = covenant_global_spending_limit(ownerPk, sompi, cooldownDaa, networkState.network);
    return { resultJson, extra: { max_withdraw_sompi: sompi, cooldown_daa: cooldownDaa } };
}

export async function buildGlobalAllowance(ownerPk) {
    const benePk = byId('cov-allowance-bene-pk').value.trim();
    if (!benePk || benePk.length < 32) {
        toast('Scan or paste the beneficiary address or x-only pubkey', 'error');
        return;
    }
    let benePkHex = benePk;
    if (benePk.startsWith('kpub1:')) {
        toast('Use the beneficiary single address or x-only pubkey, not a kpub. A kpub would expose their whole account.', 'error', 6500);
        return;
    }
    if (benePk.startsWith('kaspa') || benePk.startsWith('kaspatest')) {
        try {
            benePkHex = JSON.parse(decode_address(benePk)).payload;
        } catch (error) {
            toast('Invalid address: ' + error, 'error');
            return;
        }
    }
    if (!benePkHex || benePkHex.length !== 64) {
        toast('Beneficiary pubkey must be 64 hex chars', 'error');
        return;
    }

    const sompi = positiveSompi('cov-allowance-max', 'Enter max withdrawal in KAS');
    if (sompi === null) return;

    const periodValue = byId('cov-allowance-period').value;
    let cooldownSeconds;
    if (periodValue === 'custom') {
        cooldownSeconds = positiveSeconds('cov-allowance-seq', 'Set a custom cooldown time');
        if (cooldownSeconds === null) return;
    } else {
        if (!/^\d+$/.test(periodValue) || BigInt(periodValue) === 0n) {
            toast('Set a cooldown time', 'error');
            return;
        }
        cooldownSeconds = BigInt(periodValue);
    }
    const cooldownDaa = cooldownSeconds * 10n;

    let startDaa = 0n;
    const startValue = byId('cov-allowance-start')?.value || '';
    if (startValue) {
        try {
            startDaa = (await resolveFutureDaa(startValue)).daa;
        } catch (error) {
            toast(error.message, 'error');
            return;
        }
    }

    const resultJson = covenant_global_allowance(
        ownerPk,
        benePkHex,
        sompi,
        cooldownDaa,
        startDaa,
        networkState.network,
    );
    const extra = {
        beneficiary_pubkey_hex: benePkHex,
        max_withdraw_sompi: sompi,
        cooldown_daa: cooldownDaa,
        start_daa: startDaa,
    };
    if (startValue) extra.start_date_iso = new Date(startValue).toISOString();
    return { resultJson, extra };
}
