import { covenantState } from '../../../state/index.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { toast } from '../../../../core/ui/toast.js';
import { fetch_utxos_for_address_js } from '../../../../wasm/api.js';
import { byId } from '../../../../core/dom.js';
import { durationPartsToSeconds, formatDuration } from '../../../../core/format.js';
import { sompiToKasString } from '../../../../core/amounts.js';
const MIN_RETURN = 10_000_000n;
const STORAGE_MASS_CONSTANT = 1_000_000_000_000n;
const MAX_STORAGE_MASS = 500_000n;


function calculatePartialMaximum(balance, numInputs, maxAllowed) {
    const baseFee = 300_000n * numInputs;
    let low = 0n;
    let high = balance - MIN_RETURN - baseFee;
    if (high < 0n) high = 0n;
    if (high > maxAllowed) high = maxAllowed;

    let bestWithdraw = 0n;
    for (let iteration = 0; iteration < 40 && low <= high; iteration++) {
        const candidate = (low + high) / 2n;
        let fee = baseFee;
        const estimatedReturn = balance - candidate - fee;
        if (estimatedReturn > 0n && candidate > 0n) {
            const harmonicMean = 2n * estimatedReturn * candidate / (estimatedReturn + candidate);
            const storageMass = harmonicMean > 0n ? STORAGE_MASS_CONSTANT / harmonicMean : 0n;
            if (storageMass > MAX_STORAGE_MASS) {
                high = candidate - 1n;
                continue;
            }
            if (storageMass > fee) fee = storageMass;
        }
        if (balance - candidate - fee >= MIN_RETURN) {
            bestWithdraw = candidate;
            low = candidate + 1n;
        } else {
            high = candidate - 1n;
        }
    }
    return bestWithdraw;
}

async function fillMaximumBeneficiaryWithdrawal() {
    if (!covenantState.lastCovenantResult) {
        toast('No covenant loaded', 'error');
        return;
    }
    try {
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(
            covenantState.lastCovenantResult.address,
            wsUrl,
        ));
        if (!utxos.length) {
            toast('No UTXOs at covenant', 'error');
            return;
        }
        const balance = utxos.reduce((sum, utxo) => sum + BigInt(utxo.amount), 0n);
        const maxAllowed = covenantState.lastCovenantResult.max_withdraw_sompi
            ? BigInt(covenantState.lastCovenantResult.max_withdraw_sompi)
            : balance;
        const amount = maxAllowed > 0n && balance <= maxAllowed
            ? balance
            : calculatePartialMaximum(balance, BigInt(utxos.length), maxAllowed);
        if (amount <= 0n) {
            toast('Balance too low to withdraw', 'error');
            return;
        }
        const formatted = sompiToKasString(amount);
        byId('cov-bene-amount').value = formatted;
        const closesThread = amount === balance;
        toast(
            closesThread ? `Full drain: ${formatted} KAS (closes the thread)` : `Max: ${formatted} KAS`,
            'ok',
            closesThread ? 2000 : 1500,
        );
    } catch (error) {
        toast('Error: ' + error, 'error');
    }
}

function bindAllowancePeriod() {
    const periodSelect = byId('cov-allowance-period');
    if (!periodSelect) return;
    const labels = {'3600':'1 hour','21600':'6 hours','43200':'12 hours','86400':'24 hours','604800':'7 days','2592000':'30 days'};
    const updateSummary = () => {
        const value = periodSelect.value;
        const kas = byId('cov-allowance-max').value || '?';
        const seconds = parseInt(byId('cov-allowance-seq').value) || 0;
        const period = value === 'custom'
            ? (seconds > 0 ? formatDuration(seconds) : 'custom period')
            : (labels[value] || value + 's');
        const summary = byId('cov-allowance-summary');
        if (summary) summary.textContent = `Withdraw up to ${kas} KAS every ${period}. Uses OP_CHECKSEQUENCEVERIFY.`;
    };
    const recalculateSeconds = () => {
        const values = ['years', 'months', 'days', 'hours', 'mins'].map(
            part => parseInt(byId(`cov-allow-${part}`).value) || 0,
        );
        const [years, months, days, hours, minutes] = values;
        const total = durationPartsToSeconds({ years, months, days, hours, minutes });
        byId('cov-allowance-seq').value = total > 0 ? total : '';
        updateSummary();
    };
    periodSelect.onchange = () => {
        const custom = periodSelect.value === 'custom';
        const customWrap = byId('cov-allowance-custom-wrap');
        if (customWrap) customWrap.classList.toggle('hidden', !custom);
        if (!custom) byId('cov-allowance-seq').value = periodSelect.value;
        updateSummary();
    };
    ['years', 'months', 'days', 'hours', 'mins'].forEach(part => {
        const input = byId(`cov-allow-${part}`);
        if (input) input.oninput = recalculateSeconds;
    });
    const maximum = byId('cov-allowance-max');
    if (maximum) maximum.oninput = updateSummary;
}

export function bindAllowanceActions() {
    const maximum = byId('btn-cov-bene-max');
    if (maximum) maximum.onclick = () => fillMaximumBeneficiaryWithdrawal();
    bindAllowancePeriod();
}
