import { covenantState, covenantWatcherState } from '../../../app/state/index.js';
import { toast } from '../../../core/ui/toast.js';
import { covShowPanel, getAccountPubkeyHex } from './ui_and_keys.js';
import { covAddActive } from '../recovery/active.js';
import { covRenderMetaLine } from '../watchers_and_ui/ui/metadata.js';
import { covUpdateResultButtons } from '../watchers_and_ui/ui/result_buttons.js';
// KasSee Web — features/covenants/generation/create
import { byId } from '../../../core/dom.js';
import { buildCovenant } from './builders/index.js';
import { normalizeCovenantExactFields, parseCovenantJson, stringifyCovenantJson } from '../model/exact_fields.js';
import { contributionFromResult, contributionJson, hydrateCrowdfundState } from '../crowdfund/model.js';





export async function handleCovGenerate() {
    const t = byId('cov-type').value;
    let ownerPk = getAccountPubkeyHex();
    if (!ownerPk && t !== 'escrow') {
        toast('Load a wallet first (kpub)', 'error'); return;
    }

    try {
        const built = await buildCovenant(t, ownerPk);
        if (!built) return;
        const { resultJson, extra: _covExtra } = built;


        const result = parseCovenantJson(resultJson);
        result.type = t;

        // Merge counterparty keys for encrypted payload recovery
        Object.assign(result, _covExtra);
        normalizeCovenantExactFields(result);
        if (t === 'crowdfund') {
            result.crowdfund_contributions_json = contributionJson([contributionFromResult(result)]);
            hydrateCrowdfundState(result);
        }

        // Normalize allowance field names (WASM returns min_sequence, we store cooldown_daa)
        if (result.min_sequence && !result.cooldown_daa) result.cooldown_daa = result.min_sequence;

        covenantState.lastCovenantResult = result;
        covenantWatcherState._covWatcherSpendPath = null;
        covenantWatcherState._covWatcherOutpoint = null;
        covenantWatcherState._covWatcherLastBalance = null;
        try { sessionStorage.setItem('lastCovenantResult', stringifyCovenantJson(result)); } catch (_) {}
        console.log('[KasSee] Covenant created:', result);

        // Add to active covenants list
        covAddActive(t, result);

        // Clear creation form so re-entering doesn't regenerate same covenant
        const formFields = {
            'timelocked-savings': ['cov-savings-recovery-pk', 'cov-savings-locktime', 'cov-savings-datetime'],
            'dms': ['cov-dms2-heir-pk', 'cov-dms2-duration'],
            'global-allowance': ['cov-allowance-bene-pk', 'cov-allowance-max', 'cov-allowance-seq', 'cov-allowance-start'],
            'global-spending-limit': ['cov-splimit-max', 'cov-splimit-cooldown'],
            'additive': ['cov-piggy-goal', 'cov-piggy-deadline'],
            'merkle-whitelist': ['cov-mw-addresses', 'cov-mw-locktime', 'cov-mw-datetime'],
            'oracle-v1': ['cov-oracle-v1-bene', 'cov-oracle-v1-pubkey', 'cov-oracle-v1-key-id', 'cov-oracle-v1-statement', 'cov-oracle-v1-locktime', 'cov-oracle-v1-datetime'],
            crowdfund: ['cov-crowdfund-name', 'cov-crowdfund-goal', 'cov-crowdfund-organizer-address', 'cov-crowdfund-locktime', 'cov-crowdfund-datetime'],
        };
        if (formFields[t]) formFields[t].forEach(id => { if (byId(id)) byId(id).value = ''; });


        byId('cov-result-addr').textContent = result.address;
        byId('cov-result-script').textContent = result.redeem_script_hex;
        covRenderMetaLine(result);

        covShowPanel('result');
        covUpdateResultButtons(t);
        toast('Covenant address generated', 'ok', 2000);
    } catch (e) {
        toast('Covenant error: ' + e, 'error', 5000);
        console.error('[KasSee] Covenant generate error:', e);
    }
}
