import { covenantState } from '../../../../state/index.js';
import { toast } from '../../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../../features/covenants/generation/ui_and_keys.js';
import { ownerReceiveAddr } from '../../../../../features/covenants/payload_and_swaps/state.js';
import { handleEscrowSpend } from '../../../../../features/covenants/spending/standard/shipment.js';
import { openOracleV1Claim } from '../../../../../features/oracle/v1/controller.js';
// KasSee Web — focused covenant result action registration.

import { byId } from '../../../../../core/dom.js';
import { formatDaaDuration, formatStartDate } from '../../../../../core/format.js';
import { sompiToKasString } from '../../../../../core/amounts.js';
import { exactUnsigned } from '../../../../../core/exact.js';

function populateBeneficiaryPanel(result, type) {
    covShowPanel('beneficiary');
    byId('cov-bene-addr').value = result.address || '';
    byId('cov-bene-script').value = result.redeem_script_hex || '';
    byId('cov-beneficiary-panel').dataset.covBeneType = type;
    const destination = ownerReceiveAddr();
    if (destination) byId('cov-bene-dest').value = destination;
}

function showDmsOwnerWithdrawal(result) {
    covShowPanel('owner');
    byId('cov-owner-addr').value = result.address || '';
    byId('cov-owner-script').value = result.redeem_script_hex || '';
    const panel = byId('cov-owner-panel');
    if (panel) {
        panel.dataset.covOwnerType = 'dms';
        panel.dataset.covOwnerMode = 'withdraw';
    }
    const amount = byId('cov-owner-amount');
    const label = amount?.previousElementSibling;
    if (amount) {
        amount.style.display = '';
        amount.value = '';
    }
    if (label?.tagName === 'LABEL') {
        label.style.display = '';
        label.textContent = 'Amount (KAS) — leave empty to sweep all';
    }
    byId('cov-owner-dest').value = ownerReceiveAddr();
    byId('cov-owner-dest').readOnly = false;
    const help = byId('cov-owner-help');
    if (help) {
        help.textContent = 'Withdraw funds from the DMS covenant. Sends to a personal address. Requires owner signature from your KasSigner.';
        help.style.display = '';
    }
    const create = byId('btn-cov-owner-create');
    if (create) create.textContent = 'Create Withdrawal TX';
    const picker = byId('btn-cov-owner-consolidate');
    if (picker) {
        picker.style.display = '';
        picker.textContent = 'Select UTXO(s) to withdraw';
    }
}

function showAllowanceWithdrawal(result) {
    populateBeneficiaryPanel(result, 'global-allowance');
    byId('cov-bene-locktime-wrap')?.style.setProperty('display', 'none');
    byId('cov-bene-locktime').value = '0';
    byId('cov-bene-amount-wrap')?.style.setProperty('display', '');
    byId('btn-cov-bene-pick')?.style.setProperty('display', 'none');

    const help = byId('cov-bene-help');
    if (help) {
        const capSompi = exactUnsigned(result.max_withdraw_sompi ?? 0n, 'withdrawal cap sompi');
        const capKas = capSompi > 0n ? sompiToKasString(capSompi) : '';
        const cooldownDaa = exactUnsigned(result.cooldown_daa ?? 0n, 'cooldown DAA');
        const cooldown = cooldownDaa > 0n ? formatDaaDuration(cooldownDaa) : 'none';
        help.textContent = 'Withdraw up to ' + (capKas ? capKas + ' KAS' : 'the cap') +
            ' per spend, with a ' + cooldown + ' cooldown between withdrawals. ' +
            'The whole balance sits in one thread; leave the amount empty to close it ' +
            '(allowed only when the balance is at or under the cap). Requires beneficiary signature from your KasSigner.';
        help.style.display = '';
    }
    const create = byId('btn-cov-bene-create');
    if (create) create.textContent = 'Create Withdrawal TX';
}

function showTimelockedSavingsClaim(result) {
    populateBeneficiaryPanel(result, 'timelocked-savings');
    byId('cov-bene-locktime-wrap')?.style.setProperty('display', 'none');
    if (result.locktime_daa) byId('cov-bene-locktime').value = String(result.locktime_daa);
    byId('cov-bene-amount-wrap')?.style.setProperty('display', 'none');
    byId('btn-cov-bene-pick')?.style.setProperty('display', '');

    const help = byId('cov-bene-help');
    if (help) {
        const unlock = formatStartDate(
            { locktime_daa: result.locktime_daa, start_date_iso: result.locktime_date_iso },
            covenantState._lastKnownDaa,
        );
        help.textContent = 'Claim once the unlock time has passed (' + unlock +
            '). Sign with either your primary or recovery wallet. Sweeps all funds to the destination.';
        help.style.display = '';
    }
    const create = byId('btn-cov-bene-create');
    if (create) create.textContent = 'Claim Funds';
}

function showStandardBeneficiaryClaim(result) {
    populateBeneficiaryPanel(result, '');
    const isDms = result.type === 'dms';
    byId('cov-bene-locktime-wrap').style.display = isDms ? 'none' : '';
    byId('cov-bene-locktime').value = isDms ? '0' : String(result.locktime_daa || '');
    byId('cov-bene-amount-wrap').style.display = 'none';

    const help = byId('cov-bene-help');
    if (help) {
        const inactivityDaa = exactUnsigned(result.inactivity_daa ?? 0n, 'inactivity DAA');
        help.textContent = isDms
            ? 'Claim inheritance. The inactivity period (' +
                (inactivityDaa > 0n ? formatDaaDuration(inactivityDaa) : 'unknown') +
                ') must have elapsed since the last owner heartbeat. Requires heir signature from your KasSigner.'
            : '';
        help.style.display = isDms ? '' : 'none';
    }
    const create = byId('btn-cov-bene-create');
    if (create) create.textContent = isDms ? 'Claim Inheritance' : 'Create Release TX';
    byId('btn-cov-bene-pick')?.style.setProperty('display', isDms ? '' : 'none');
}

async function openBeneficiaryAction() {
    const result = covenantState.lastCovenantResult;
    if (!result) {
        toast('No covenant loaded', 'error');
        return;
    }
    if (result.type === 'oracle-v1') {
        openOracleV1Claim();
    } else if (result.type === 'escrow') {
        await handleEscrowSpend(result.role === 'arbiter' ? 'arbiter-refund-buyer' : 'seller-refund');
    } else if (result.type === 'dms' && result.role !== 'beneficiary') {
        showDmsOwnerWithdrawal(result);
    } else if (result.type === 'global-allowance') {
        showAllowanceWithdrawal(result);
    } else if (result.type === 'timelocked-savings') {
        showTimelockedSavingsClaim(result);
    } else {
        showStandardBeneficiaryClaim(result);
    }
}

export function registerBeneficiaryAction() {
    byId('btn-cov-res-bene').onclick = () => openBeneficiaryAction();
}
