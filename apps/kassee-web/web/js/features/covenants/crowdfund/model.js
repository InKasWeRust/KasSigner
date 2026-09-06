import { crowdfundState } from '../../../app/state/index.js';
import { exactDecimalString, exactUnsigned } from '../../../core/exact.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{16}$/;

export function contributionFromResult(result) {
    const contribution = {
        address: String(result.address || ''),
        contributor_pubkey_hex: String(result.contributor_pubkey_hex || '').toLowerCase(),
        redeem_script_hex: String(result.redeem_script_hex || '').toLowerCase(),
        crowdfund_salt_hex: String(result.crowdfund_salt_hex || '').toLowerCase(),
    };
    validateContribution(contribution);
    return Object.freeze(contribution);
}

export function validateContribution(value) {
    if (!value || typeof value !== 'object') throw new Error('Crowdfunding contribution is missing');
    if (!String(value.address || '').includes(':')) throw new Error('Crowdfunding contribution address is invalid');
    if (!HEX64.test(String(value.contributor_pubkey_hex || '').toLowerCase())) throw new Error('Crowdfunding contributor key is invalid');
    if (!/^[0-9a-f]+$/.test(String(value.redeem_script_hex || '').toLowerCase())) throw new Error('Crowdfunding redeem script is invalid');
    if (!HEX16.test(String(value.crowdfund_salt_hex || '').toLowerCase())) throw new Error('Crowdfunding salt is invalid');
    return value;
}

export function contributionList(value) {
    let parsed = value;
    if (typeof value === 'string') parsed = value ? JSON.parse(value) : [];
    if (!Array.isArray(parsed)) throw new Error('Crowdfunding contribution list is invalid');
    const unique = new Map();
    for (const item of parsed) {
        validateContribution(item);
        unique.set(item.address, {
            address: item.address,
            contributor_pubkey_hex: item.contributor_pubkey_hex.toLowerCase(),
            redeem_script_hex: item.redeem_script_hex.toLowerCase(),
            crowdfund_salt_hex: item.crowdfund_salt_hex.toLowerCase(),
        });
    }
    if (unique.size > 8) throw new Error('Crowdfunding supports at most 8 contribution addresses per sweep');
    return [...unique.values()];
}

export function contributionJson(value) {
    return JSON.stringify(contributionList(value));
}

export function addContribution(value) {
    const next = contributionList([...crowdfundState.contributions, value]);
    crowdfundState.contributions = next;
    return next;
}

export function hydrateCrowdfundState(result) {
    if (!result || result.type !== 'crowdfund') return;
    const existing = contributionList(result.crowdfund_contributions_json || []);
    crowdfundState.contributions = existing;
    const campaign = campaignFromResult(result);
    if (result.crowdfund_role === 'organizer') {
        crowdfundState.role = 'organizer';
        crowdfundState.setup = {
            pk_hex: result.crowdfund_pk_hex || '',
            vk_hex: result.vk_hex || '',
            vk_hash_hex: result.campaign_id || result.vk_hash_hex || '',
        };
    } else {
        crowdfundState.role = 'contributor';
        crowdfundState.importedCampaign = campaign;
    }
}

export function campaignFromResult(result) {
    return normalizeCampaign({
        v: 2,
        t: 'crowdfund-campaign',
        name: result.campaign_name || '',
        goal: exactDecimalString(result.goal_sompi ?? 0n, 'crowdfunding goal'),
        daa: exactDecimalString(result.locktime_daa ?? 0n, 'crowdfunding locktime DAA'),
        organizer: result.organizer_address || '',
        vk: result.vk_hex || '',
        id: result.campaign_id || result.vk_hash_hex || '',
        date: result.locktime_date_iso || '',
    });
}

export function normalizeCampaign(value) {
    if (!value || value.t !== 'crowdfund-campaign' || value.v !== 2) throw new Error('Not a current crowdfunding campaign invite');
    const goal = exactUnsigned(value.goal, 'crowdfunding goal');
    const daa = exactUnsigned(value.daa, 'crowdfunding locktime DAA');
    const vk = String(value.vk || '').trim().toLowerCase();
    const id = String(value.id || '').trim().toLowerCase();
    const organizer = String(value.organizer || '').trim();
    const name = String(value.name || '').trim().slice(0, 64);
    if (goal === 0n) throw new Error('Crowdfunding goal must be greater than zero');
    if (daa === 0n) throw new Error('Crowdfunding refund DAA is missing');
    if (!organizer.includes(':')) throw new Error('Crowdfunding organizer destination is invalid');
    if (!/^[0-9a-f]+$/.test(vk) || vk.length < 2 || vk.length > 32768) throw new Error('Crowdfunding verifying key is invalid');
    if (!HEX64.test(id)) throw new Error('Crowdfunding campaign ID is invalid');
    return Object.freeze({ v: 2, t: 'crowdfund-campaign', name, goal, daa, organizer, vk, id, date: String(value.date || '') });
}
