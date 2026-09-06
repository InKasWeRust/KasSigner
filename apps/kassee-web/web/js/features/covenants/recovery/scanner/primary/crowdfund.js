import { crowdfund_campaign_id } from '../../../../../wasm/api.js';
import { hexToBytes } from '../../../../../core/bytes.js';
import { readLen, readU64, readVstr } from '../payload_reader.js';
import { contributionJson } from '../../../crowdfund/model.js';
import { baseRecoveredRecord, readStoredScript } from './common.js';

function readVhex(hex, offset) {
    const { len, endOff } = readLen(hex, offset);
    const value = hex.slice(endOff, endOff + len * 2);
    if (value.length !== len * 2) throw new Error('Recovered crowdfunding field is truncated');
    return { value, endOff: endOff + len * 2 };
}

export function rebuildCrowdfund(type, params) {
    const stored = readStoredScript(params);
    let offset = stored.offset;
    const contributorPubkeyHex = params.slice(offset, offset + 64); offset += 64;
    const salt = readVhex(params, offset); offset = salt.endOff;
    const goalSompi = readU64(params, offset); offset += 16;
    const locktimeDaa = readU64(params, offset); offset += 16;
    const organizer = readVstr(params, offset, hexToBytes); offset = organizer.endOff;
    const name = readVstr(params, offset, hexToBytes); offset = name.endOff;
    const vk = readVhex(params, offset); offset = vk.endOff;
    const provingKey = readVhex(params, offset); offset = provingKey.endOff;
    const campaignId = params.slice(offset, offset + 64); offset += 64;
    const role = readVstr(params, offset, hexToBytes); offset = role.endOff;
    const contributions = readVstr(params, offset, hexToBytes); offset = contributions.endOff;
    const date = readVstr(params, offset, hexToBytes); offset = date.endOff;
    if (offset !== params.length) throw new Error('Recovered crowdfunding payload has trailing data');
    if (!/^[0-9a-f]{64}$/.test(contributorPubkeyHex)) throw new Error('Recovered crowdfunding contributor key is invalid');
    if (!/^[0-9a-f]{16}$/.test(salt.value)) throw new Error('Recovered crowdfunding salt is invalid');
    if (goalSompi === 0n || locktimeDaa === 0n) throw new Error('Recovered crowdfunding goal/deadline is invalid');
    if (!organizer.str.includes(':')) throw new Error('Recovered crowdfunding organizer destination is invalid');
    if (!vk.value || vk.value.length > 32768
        || crowdfund_campaign_id(organizer.str, goalSompi, locktimeDaa, vk.value) !== campaignId) {
        throw new Error('Recovered crowdfunding verifying key/campaign identity is invalid');
    }
    if (role.str !== 'organizer' && role.str !== 'contributor') throw new Error('Recovered crowdfunding role is invalid');
    const contributionSet = contributionJson(contributions.str || '[]');
    return {
        ...baseRecoveredRecord(type, stored.redeemScriptHex, 'owner'),
        contributor_pubkey_hex: contributorPubkeyHex,
        crowdfund_salt_hex: salt.value,
        goal_sompi: goalSompi,
        locktime_daa: locktimeDaa,
        organizer_address: organizer.str,
        campaign_name: name.str,
        vk_hex: vk.value,
        crowdfund_pk_hex: provingKey.value,
        campaign_id: campaignId,
        crowdfund_role: role.str,
        crowdfund_contributions_json: contributionSet,
        ...(date.str ? { locktime_date_iso: date.str } : {}),
    };
}
