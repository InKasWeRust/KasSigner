import { covenantState, networkState } from '../../../state/index.js';
import { fetchCurrentDaa } from '../../../../core/node/daa.js';
import { resolveNodeUrl } from '../../../../core/node/resolver.js';
import { toast } from '../../../../core/ui/toast.js';
import { covShowPanel } from '../../../../features/covenants/generation/ui_and_keys.js';
import { ownerReceiveAddr } from '../../../../features/covenants/payload_and_swaps/state.js';
import { covScanAddress } from '../../../../features/covenants/scanning_and_swap.js';
import { handleCovBeneficiarySpend, handleCovTimeoutRefund } from '../../../../features/covenants/spending/standard/thread_and_claims.js';
import { parseEscrowScript } from '../../../../features/covenants/watchers_and_ui/ui/script_metadata.js';
import { encode_p2pk_address, fetch_utxos_for_address_js } from '../../../../wasm/api.js';
// KasSee Web — app/events/contracts/covenant_creation/sharing_and_claims
import { byId } from '../../../../core/dom.js';
import { bindDurationInputs } from '../../../../core/forms/duration.js';
import { openUtxoPicker } from './utxo_picker.js';
import { registerInviteSharingActions } from './invite_sharing.js';

import { formatDaaDuration } from '../../../../core/format.js';
import { exactUnsigned } from '../../../../core/exact.js';








function registerSpendPanelActions() {
    if (byId('btn-cov-owner-spend')) byId('btn-cov-owner-spend').onclick = () => {
        covShowPanel('owner');
        if (covenantState.lastCovenantResult) {
            byId('cov-owner-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-owner-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
            // DMS heartbeat: send back to same covenant address to reset CSV timer
            if (covenantState.lastCovenantResult.type === 'dms') {
                byId('cov-owner-dest').value = covenantState.lastCovenantResult.address || '';
            }
        }
    };
    byId('btn-cov-owner-back').onclick = () => {
        covShowPanel(covenantState.lastCovenantResult ? 'result' : 'menu');
    };
    if (byId('btn-cov-borrower-spend')) byId('btn-cov-borrower-spend').onclick = () => {
        covShowPanel('borrower');
        if (covenantState.lastCovenantResult) {
            byId('cov-borrower-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-borrower-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
        }
    };
    byId('btn-cov-borrower-back').onclick = () => covShowPanel(covenantState.lastCovenantResult ? 'result' : 'menu');
    if (byId('btn-cov-beneficiary-spend')) byId('btn-cov-beneficiary-spend').onclick = () => {
        covShowPanel('beneficiary');
        if (covenantState.lastCovenantResult) {
            byId('cov-bene-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-bene-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
            if (covenantState.lastCovenantResult.locktime_daa) {
                byId('cov-bene-locktime').value = covenantState.lastCovenantResult.locktime_daa;
            }
            // For escrow: auto-fill destination from parsed script.
            try {
                const rs = covenantState.lastCovenantResult.redeem_script_hex || '';
                if (rs.length > 200) {
                    const parsed = parseEscrowScript(rs);
                    // Bob (seller) claiming: destination is alice's address
                    if (parsed.alice_spk_hex) {
                        const aliceAddr = encode_p2pk_address(parsed.alice_spk_hex, networkState.network);
                        byId('cov-bene-dest').value = aliceAddr;
                    }
                }
            } catch (e) {
                console.log('[KasSee] Could not auto-fill escrow destination:', e);
            }
        }
    };
    byId('btn-cov-bene-back').onclick = () => covShowPanel('menu');
    byId('btn-cov-bene-create').onclick = () => handleCovBeneficiarySpend();
    if (byId('btn-cov-bene-pick')) {
        byId('btn-cov-bene-pick').onclick = async () => {
            // Claim only the selected UTXOs (batched). Dest is the claiming wallet's
            // address; locktime comes from the claim setup.
            const dest = (byId('cov-bene-dest') ? byId('cov-bene-dest').value.trim() : '') || ownerReceiveAddr();
            const lt = byId('cov-bene-locktime') ? (byId('cov-bene-locktime').value.trim() || '0') : '0';
            // Savings pre-flight: block before opening the picker if still locked,
            // using a LIVE DAA fetch (the picker confirm is sync, so the cached
            // _lastKnownDaa is unreliable there). The node rejects an early claim.
            if ((covenantState.lastCovenantResult && covenantState.lastCovenantResult.type) === 'timelocked-savings') {
                const lockN = exactUnsigned(lt || '0', 'savings locktime DAA');
                if (lockN > 0n) {
                    const curDaa = await fetchCurrentDaa();
                    if (curDaa > 0n && curDaa < lockN) {
                        const eta = formatDaaDuration(lockN - curDaa);
                        toast('Still locked. Unlocks in ~' + eta + '. An early claim is rejected by the node.', 'error', 5000);
                        return;
                    }
                }
            } else if ((covenantState.lastCovenantResult && covenantState.lastCovenantResult.type) === 'dms') {
                // DMS heir claim is gated by CSV (per-UTXO age). The OLDEST UTXO ages
                // first, so block only when not even that one has cleared the inactivity
                // period (nothing is claimable yet). Once at least one has aged, allow
                // the heir to batch-claim the aged UTXOs in the picker.
                const _inact = exactUnsigned(covenantState.lastCovenantResult.inactivity_daa ?? 0n, 'inactivity DAA');
                if (_inact > 0n) {
                    const curDaa = await fetchCurrentDaa();
                    let _utxos = [];
                    try { _utxos = JSON.parse(await fetch_utxos_for_address_js(covenantState.lastCovenantResult.address, await resolveNodeUrl())); } catch (_) {}
                    if (curDaa > 0n && _utxos.length) {
                        let _oldest = null;
                        for (const u of _utxos) {
                            const d = exactUnsigned(u.block_daa_score ?? 0n, 'UTXO DAA');
                            if (d > 0n && (_oldest === null || d < _oldest)) _oldest = d;
                        }
                        if (_oldest !== null && curDaa < _oldest + _inact) {
                            const eta = formatDaaDuration(_oldest + _inact - curDaa);
                            toast('Still locked. No vault UTXO has aged past the inactivity period yet. The heir can claim in ~' + eta + '. The node rejects an early claim.', 'error', 6000);
                            return;
                        }
                    }
                }
            }
            openUtxoPicker(dest, { locktime: lt });
        };
    }
}

function registerClaimAndPresetActions() {
    if (byId('btn-cov-timeout-refund')) byId('btn-cov-timeout-refund').onclick = () => {
        covShowPanel('timeout');
        if (covenantState.lastCovenantResult) {
            byId('cov-timeout-addr').value = covenantState.lastCovenantResult.address || '';
            byId('cov-timeout-script').value = covenantState.lastCovenantResult.redeem_script_hex || '';
            if (covenantState.lastCovenantResult.locktime_daa) {
                byId('cov-timeout-locktime').value = covenantState.lastCovenantResult.locktime_daa;
            }
        }
    };
    byId('btn-cov-timeout-back').onclick = () => covShowPanel('menu');
    byId('btn-cov-timeout-create').onclick = () => handleCovTimeoutRefund();
    if (byId('btn-cov-scan-dms2-heir')) byId('btn-cov-scan-dms2-heir').onclick = () => covScanAddress('cov-dms2-heir-pk', 'Scan heir address', true);
    if (byId('cov-dms2-preset')) {
        bindDurationInputs({ prefix: 'cov-dms2', outputId: 'cov-dms2-duration' });
        byId('cov-dms2-preset').onchange = () => {
            const v = byId('cov-dms2-preset').value;
            const customWrap = byId('cov-dms2-custom-wrap');
            if (customWrap) customWrap.classList.toggle('hidden', v !== 'custom');
            if (v !== 'custom') byId('cov-dms2-duration').value = v;
        };
        // Custom is default; no duration pre-fill. User picks a preset or opens Custom rolling inputs.
        if (byId('cov-dms2-preset').value !== 'custom') {
            byId('cov-dms2-duration').value = byId('cov-dms2-preset').value;
        }
    }
}

export function registerSharingAndClaims() {
    registerInviteSharingActions();
    registerSpendPanelActions();
    registerClaimAndPresetActions();
}
