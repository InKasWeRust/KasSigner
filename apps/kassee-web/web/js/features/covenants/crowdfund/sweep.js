import { covenantState, crowdfundState } from '../../../app/state/index.js';
import { sompiToKasString } from '../../../core/amounts.js';
import { byId } from '../../../core/dom.js';
import { exactUnsigned } from '../../../core/exact.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { toast } from '../../../core/ui/toast.js';
import {
    create_crowdfund_sweep,
    inspect_crowdfund_contributions,
    zk_crowdfund_prove,
} from '../../../wasm/api.js';
import { contributionList, hydrateCrowdfundState } from './model.js';

const DEFAULT_REQUESTED_FEE = 400_000n;

export function renderCrowdfundResult() {
    const result = covenantState.lastCovenantResult;
    const panel = byId('crowdfund-result-panel');
    if (!panel) return;
    const active = result?.type === 'crowdfund';
    panel.classList.toggle('hidden', !active);
    if (!active) { stopCrowdfundWatcher(); return; }
    hydrateCrowdfundState(result);
    const organizer = result.crowdfund_role === 'organizer';
    byId('btn-crowdfund-share-campaign')?.classList.toggle('hidden', !organizer);
    byId('btn-crowdfund-scan-contribution')?.classList.toggle('hidden', !organizer);
    byId('btn-crowdfund-refresh')?.classList.toggle('hidden', !organizer);
    byId('btn-crowdfund-sweep')?.classList.toggle('hidden', !organizer);
    const info = byId('crowdfund-campaign-info');
    if (info) info.textContent = `${result.campaign_name || 'Crowdfunding campaign'} | Goal ${sompiToKasString(result.goal_sompi ?? 0n)} KAS | ${organizer ? 'Organizer' : 'Contributor'}`;
    renderContributionList();
    if (organizer) startCrowdfundWatcher(); else stopCrowdfundWatcher();
}

export function renderContributionList() {
    const node = byId('crowdfund-contribution-list');
    if (!node) return;
    const entries = contributionList(crowdfundState.contributions || []);
    node.textContent = entries.length
        ? `${entries.length}/8 contribution address${entries.length === 1 ? '' : 'es'} tracked for this campaign.`
        : 'No contribution addresses tracked yet.';
}

export async function refreshCrowdfundTotals() {
    const result = requireOrganizerResult();
    if (!result) return null;
    const status = byId('crowdfund-watcher-status');
    try {
        const contributions = contributionList(crowdfundState.contributions);
        if (!contributions.length) throw new Error('No contribution addresses are tracked');
        if (status) status.textContent = 'Checking contributor UTXOs...';
        const wsUrl = await resolveNodeUrl();
        const inspected = JSON.parse(await inspect_crowdfund_contributions(JSON.stringify(contributions), wsUrl));
        const total = exactUnsigned(inspected.total_sompi, 'crowdfunding total');
        const goal = exactUnsigned(result.goal_sompi, 'crowdfunding goal');
        if (status) status.textContent = `Total ${sompiToKasString(total)} / ${sompiToKasString(goal)} KAS | ${inspected.input_count} UTXOs`;
        return { inspected, total, goal, wsUrl };
    } catch (error) {
        if (status) status.textContent = '';
        toast('Crowdfunding refresh failed: ' + error.message, 'error', 5000);
        return null;
    }
}

export async function sweepCrowdfund() {
    const result = requireOrganizerResult();
    if (!result) return;
    const status = byId('crowdfund-sweep-status');
    try {
        const pk = String(result.crowdfund_pk_hex || '');
        const vk = String(result.vk_hex || '');
        if (!pk || !vk) throw new Error('Organizer proving material is unavailable; restore the organizer backup');
        const refreshed = await refreshCrowdfundTotals();
        if (!refreshed) return;
        if (refreshed.total < refreshed.goal) throw new Error('Campaign goal has not been reached');
        const amounts = refreshed.inspected.contributions.map(entry => String(exactUnsigned(entry.amount_sompi, 'contribution amount')));
        if (status) status.textContent = 'Generating and locally verifying Groth16 proof...';
        const proof = JSON.parse(zk_crowdfund_prove(pk, vk, JSON.stringify(amounts)));
        if (proof.verified !== true) throw new Error('Local Groth16 proof verification failed');
        if (exactUnsigned(proof.total_sompi, 'proof total') !== refreshed.total) {
            throw new Error('Proof total does not match the fetched contribution total');
        }
        if (status) status.textContent = 'Broadcasting campaign-constrained sweep...';
        const txid = await create_crowdfund_sweep(
            JSON.stringify(contributionList(crowdfundState.contributions)),
            result.organizer_address,
            exactUnsigned(result.goal_sompi, 'crowdfunding goal'),
            exactUnsigned(result.locktime_daa, 'crowdfunding locktime DAA'),
            vk,
            proof.proof_hex,
            proof.public_input_hex,
            DEFAULT_REQUESTED_FEE,
            refreshed.wsUrl,
        );
        if (status) status.textContent = `Sweep broadcast: ${txid}`;
        const txNode = byId('cov-result-txid');
        const wrap = byId('cov-result-txid-wrap');
        if (txNode) txNode.textContent = txid;
        if (wrap) wrap.style.display = '';
        toast('Crowdfunding sweep broadcast', 'ok', 4000);
    } catch (error) {
        if (status) status.textContent = '';
        toast('Crowdfunding sweep failed: ' + error.message, 'error', 6000);
    }
}

function requireOrganizerResult() {
    const result = covenantState.lastCovenantResult;
    if (!result || result.type !== 'crowdfund' || result.crowdfund_role !== 'organizer') {
        toast('Load the organizer crowdfunding record first', 'error');
        return null;
    }
    return result;
}

function startCrowdfundWatcher() {
    stopCrowdfundWatcher();
    crowdfundState.watcherTimer = setInterval(() => { void refreshCrowdfundTotals(); }, 15_000);
}

export function stopCrowdfundWatcher() {
    if (crowdfundState.watcherTimer !== null) {
        clearInterval(crowdfundState.watcherTimer);
        crowdfundState.watcherTimer = null;
    }
}
