import { crowdfundState, networkState, walletSession } from '../../../app/state/index.js';
import { kasToSompi, sompiToKasString } from '../../../core/amounts.js';
import { byId } from '../../../core/dom.js';
import { exactUnsigned } from '../../../core/exact.js';
import { resolveFutureDaa } from '../../../core/node/future_daa.js';
import { toast } from '../../../core/ui/toast.js';
import { crowdfund_campaign_id, covenant_crowdfund, zk_crowdfund_setup } from '../../../wasm/api.js';
import { normalizeCampaign } from './model.js';

export function setCrowdfundRole(role) {
    if (role !== 'organizer' && role !== 'contributor') throw new Error('Unknown crowdfunding role');
    crowdfundState.role = role;
    byId('crowdfund-organizer-fields')?.classList.toggle('hidden', role !== 'organizer');
    byId('crowdfund-contributor-fields')?.classList.toggle('hidden', role !== 'contributor');
    const organizer = byId('btn-crowdfund-role-organizer');
    const contributor = byId('btn-crowdfund-role-contributor');
    if (organizer) organizer.className = role === 'organizer' ? 'btn btn-primary u-grow' : 'btn btn-outline u-grow';
    if (contributor) contributor.className = role === 'contributor' ? 'btn btn-primary u-grow' : 'btn btn-outline u-grow';
    if (role === 'organizer') populateOrganizerDestination();
    renderImportedCampaign();
}

export function populateOrganizerDestination() {
    const input = byId('cov-crowdfund-organizer-address');
    if (!input || input.value.trim() || !walletSession.hasWallet()) return;
    const addresses = walletSession.current().receive_addresses || [];
    if (addresses[0]) input.value = addresses[0];
}

export async function runCrowdfundSetup() {
    const status = byId('crowdfund-setup-status');
    if (status) status.textContent = 'Generating campaign proving/verifying keys...';
    try {
        const result = JSON.parse(zk_crowdfund_setup());
        if (!result.pk_hex || !result.vk_hex || !/^[0-9a-f]{64}$/.test(result.vk_hash_hex || '')) {
            throw new Error('Trusted setup returned invalid campaign material');
        }
        crowdfundState.setup = Object.freeze(result);
        if (status) status.textContent = `Setup ready. Verifier ${result.vk_hash_hex.slice(0, 12)}…`;
        toast('Crowdfunding ZK setup ready', 'ok', 2000);
    } catch (error) {
        if (status) status.textContent = '';
        toast('Crowdfunding setup failed: ' + error.message, 'error', 5000);
    }
}

export function importCrowdfundCampaign(value) {
    const campaign = normalizeCampaign(value);
    const expectedId = crowdfund_campaign_id(campaign.organizer, campaign.goal, campaign.daa, campaign.vk);
    if (expectedId !== campaign.id) {
        throw new Error('Crowdfunding campaign ID does not match its campaign parameters');
    }
    crowdfundState.importedCampaign = campaign;
    setCrowdfundRole('contributor');
    renderImportedCampaign();
    return campaign;
}

export function renderImportedCampaign() {
    const summary = byId('crowdfund-contributor-summary');
    if (!summary) return;
    const campaign = crowdfundState.importedCampaign;
    if (!campaign) {
        summary.textContent = 'Scan the organizer\'s campaign invite before generating your contribution address.';
        return;
    }
    summary.textContent = `${campaign.name || 'Crowdfunding campaign'} | Goal ${sompiToKasString(campaign.goal)} KAS | Organizer ${campaign.organizer}`;
}

export async function buildCrowdfund(ownerPk) {
    const campaign = crowdfundState.role === 'organizer'
        ? await organizerCampaignFromForm()
        : crowdfundState.importedCampaign;
    if (!campaign) {
        if (crowdfundState.role !== 'organizer') toast('Scan a crowdfunding campaign invite first', 'error');
        return null;
    }
    const resultJson = covenant_crowdfund(
        ownerPk,
        campaign.organizer,
        campaign.goal,
        campaign.daa,
        campaign.vk,
        networkState.network,
    );
    const built = JSON.parse(resultJson);
    if (built.campaign_id !== campaign.id) {
        throw new Error('Crowdfunding covenant campaign identity mismatch');
    }
    const role = crowdfundState.role;
    const setup = role === 'organizer' ? crowdfundState.setup : null;
    return {
        resultJson,
        extra: {
            role: 'owner',
            crowdfund_role: role,
            campaign_name: campaign.name,
            organizer_address: campaign.organizer,
            goal_sompi: campaign.goal,
            locktime_daa: campaign.daa,
            locktime_date_iso: campaign.date || '',
            vk_hex: campaign.vk,
            campaign_id: built.campaign_id,
            crowdfund_pk_hex: setup?.pk_hex || '',
        },
    };
}

async function organizerCampaignFromForm() {
    const setup = crowdfundState.setup;
    if (!setup?.pk_hex || !setup?.vk_hex || !/^[0-9a-f]{64}$/.test(setup.vk_hash_hex || '')) {
        toast('Run ZK Trusted Setup first', 'error'); return null;
    }
    const name = byId('cov-crowdfund-name').value.trim();
    const organizer = byId('cov-crowdfund-organizer-address').value.trim();
    const date = byId('cov-crowdfund-datetime').value;
    let goal;
    try { goal = kasToSompi(byId('cov-crowdfund-goal').value.trim()); }
    catch (_) { toast('Enter a valid crowdfunding goal with at most 8 decimals', 'error'); return null; }
    if (goal === 0n) { toast('Crowdfunding goal must be greater than zero', 'error'); return null; }
    if (!organizer.includes(':')) { toast('Enter a valid organizer destination', 'error'); return null; }
    if (!date) { toast('Choose a contributor refund deadline', 'error'); return null; }
    let daa;
    try { daa = exactUnsigned((await resolveFutureDaa(date)).daa, 'crowdfunding refund DAA'); }
    catch (error) { toast(error.message, 'error'); return null; }
    if (daa === 0n) { toast('Refund deadline must be in the future', 'error'); return null; }
    byId('cov-crowdfund-locktime').value = String(daa);
    const campaignId = crowdfund_campaign_id(organizer, goal, daa, setup.vk_hex);
    return normalizeCampaign({
        v: 2, t: 'crowdfund-campaign', name, goal: String(goal), daa: String(daa),
        organizer, vk: setup.vk_hex, id: campaignId, date: new Date(date).toISOString(),
    });
}
