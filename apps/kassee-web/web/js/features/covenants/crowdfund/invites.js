import { covenantState, navigationState } from '../../../app/state/index.js';
import { showScreen } from '../../../app/navigation.js';
import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { toast } from '../../../core/ui/toast.js';
import { byId } from '../../../core/dom.js';
import { generate_qr_svg_text } from '../../../wasm/api.js';
import { pauseQrCycle } from '../../transactions/send/review.js';
import { addContribution, campaignFromResult, contributionFromResult, normalizeCampaign, validateContribution } from './model.js';
import { persistContributions } from './persistence.js';
import { renderContributionList } from './sweep.js';

export function shareCrowdfundCampaign() {
    const result = organizerResult();
    if (!result) return;
    const campaign = campaignFromResult(result);
    showQr(JSON.stringify({
        ...campaign,
        goal: campaign.goal.toString(),
        daa: campaign.daa.toString(),
    }), 'Crowdfunding Campaign Invite');
}

export function shareCrowdfundContribution() {
    const result = covenantState.lastCovenantResult;
    if (!result || result.type !== 'crowdfund') return;
    const contribution = contributionFromResult(result);
    const payload = {
        v: 2,
        t: 'crowdfund-contribution',
        campaign_id: result.campaign_id,
        contribution,
    };
    showQr(JSON.stringify(payload), 'Crowdfunding Contribution Invite');
}

export function importCrowdfundContribution(raw) {
    const invite = decodeJson(raw);
    if (invite?.v !== 2 || invite?.t !== 'crowdfund-contribution') throw new Error('Not a current crowdfunding contribution invite');
    const result = organizerResult();
    if (!result) throw new Error('Load the organizer crowdfunding record first');
    if (String(invite.campaign_id || '').toLowerCase() !== String(result.campaign_id || '').toLowerCase()) {
        throw new Error('Contribution belongs to a different crowdfunding campaign');
    }
    validateContribution(invite.contribution);
    const list = addContribution(invite.contribution);
    persistContributions(list);
    renderContributionList();
    toast('Contributor address added', 'ok', 2000);
}

export function parseCrowdfundCampaign(raw) {
    return normalizeCampaign(decodeJson(raw));
}

function decodeJson(raw) {
    const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    return JSON.parse(new TextDecoder().decode(bytes));
}

function showQr(payload, title) {
    pauseQrCycle();
    const container = byId('qr-container');
    setSafeMarkup(container, generate_qr_svg_text(payload));
    const info = byId('qr-frame-info');
    if (info) info.replaceChildren();
    byId('qr-display-title').textContent = title;
    ['btn-scan-next-sig', 'btn-copy-kspt', 'btn-qr-scan-signed'].forEach(id => {
        const button = byId(id);
        if (button) button.style.display = 'none';
    });
    const txInfo = byId('qr-tx-info');
    if (txInfo) txInfo.style.display = 'none';
    navigationState._broadcastReturnScreen = 'covenant';
    showScreen('qr-display');
}

function organizerResult() {
    const result = covenantState.lastCovenantResult;
    if (!result || result.type !== 'crowdfund' || result.crowdfund_role !== 'organizer') {
        toast('Load the organizer crowdfunding record first', 'error');
        return null;
    }
    return result;
}
