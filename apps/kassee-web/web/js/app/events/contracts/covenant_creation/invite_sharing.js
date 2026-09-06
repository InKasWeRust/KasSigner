import { setSafeMarkup } from '../../../../core/security/safe_html.js';
import { covenantState, navigationState } from '../../../state/index.js';
import { showScreen } from '../../../navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { pauseQrCycle } from '../../../../features/transactions/send/review.js';
import { generate_qr_svg_text } from '../../../../wasm/api.js';
// Focused covenant invite sharing event registration.

import { byId } from '../../../../core/dom.js';
import { exactDecimalString } from '../../../../core/exact.js';
function showInviteQr(payload, title, details = '') {
    pauseQrCycle();
    byId('qr-container').innerHTML = generate_qr_svg_text(payload);
    setSafeMarkup(byId('qr-frame-info'), details);
    byId('qr-display-title').textContent = title;
    ['btn-scan-next-sig', 'btn-copy-kspt', 'btn-qr-scan-signed'].forEach(id => {
        const button = byId(id);
        if (button) button.style.display = 'none';
    });
    const transactionInfo = byId('qr-tx-info');
    if (transactionInfo) transactionInfo.style.display = 'none';
    navigationState._broadcastReturnScreen = 'covenant';
    showScreen('qr-display');
}

function buildCovenantInvite(result) {
    const type = result.type || '';
    const invite = {
        v: 1,
        t: 'cov-invite',
        ct: type,
        addr: result.address || '',
        rs: result.redeem_script_hex || '',
        d: exactDecimalString(result.locktime_daa ?? 0n, 'locktime DAA'),
    };
    if (type === 'dms' && result.inactivity_daa) invite.id = exactDecimalString(result.inactivity_daa, 'inactivity DAA');
    if (type === 'timelocked-savings') {
        if (result.wallet1_pubkey_hex) invite.w1 = result.wallet1_pubkey_hex;
        if (result.wallet2_pubkey_hex) invite.w2 = result.wallet2_pubkey_hex;
        if (result.locktime_date_iso) invite.ldi = result.locktime_date_iso;
    }
    if (type === 'global-allowance') {
        if (result.max_withdraw_sompi) invite.mw = exactDecimalString(result.max_withdraw_sompi, 'withdrawal limit');
        invite.cd = exactDecimalString(result.cooldown_daa ?? result.min_sequence ?? 0n, 'cooldown DAA');
        if (result.start_daa) invite.sd = exactDecimalString(result.start_daa, 'start DAA');
        if (result.start_date_iso) invite.sdi = result.start_date_iso;
    }
    if (type === 'oracle-v1') {
        if (!/^[0-9a-f]{64}$/.test(result.oracle_covenant_binding_token_hex || '')) {
            throw new Error('Bind the Oracle covenant key before sharing this covenant');
        }
        if (result.oracle_pubkey_hex) invite.opk = result.oracle_pubkey_hex;
        if (result.oracle_covenant_key_id_hex) invite.okid = result.oracle_covenant_key_id_hex;
        invite.obt = result.oracle_covenant_binding_token_hex;
        if (result.beneficiary_pubkey_hex) invite.bpk = result.beneficiary_pubkey_hex;
        if (result.owner_pubkey_hex) invite.own = result.owner_pubkey_hex;
        if (result.locktime_date_iso) invite.ldi = result.locktime_date_iso;
        if (result.attestation_statement) invite.oas = result.attestation_statement;
        if (result.message_commitment_hex) invite.omc = result.message_commitment_hex;
    }
    return invite;
}

function registerCovenantInviteShare() {
    const button = byId('btn-cov-res-share-cov');
    if (!button) return;
    button.onclick = () => {
        const result = covenantState.lastCovenantResult;
        if (!result) return;
        try {
            if (result.type === 'additive') {
                const address = result.address || '';
                const details = '<div class="covenant-invite-details">' +
                    'Piggy Bank Address<br><span class="u-text-10px-break-all">' + address + '</span>' +
                    '<br><span class="u-text-10px-text-text-muted">Anyone can send KAS to this address</span></div>';
                showInviteQr(address, 'Share Piggy Bank Address', details);
                return;
            }
            showInviteQr(JSON.stringify(buildCovenantInvite(result)), 'Covenant Invite QR');
        } catch (error) {
            toast('QR generation failed: ' + error, 'error');
        }
    };
}

function registerGenericInviteActions() {
    registerCovenantInviteShare();
}

export function registerInviteSharingActions() {
    registerGenericInviteActions();
}
