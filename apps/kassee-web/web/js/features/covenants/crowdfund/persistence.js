import { covenantState, crowdfundState } from '../../../app/state/index.js';
import { covSaveActive } from '../recovery/active.js';
import { contributionJson, contributionList } from './model.js';

export function persistContributions(items) {
    const normalized = contributionList(items);
    crowdfundState.contributions = normalized;
    const json = contributionJson(normalized);
    const result = covenantState.lastCovenantResult;
    if (result?.type === 'crowdfund') result.crowdfund_contributions_json = json;
    const active = covenantState.activeCovenants || [];
    const target = active.find(entry => entry.type === 'crowdfund' && entry.address === result?.address);
    if (target) {
        target.crowdfund_contributions_json = json;
        covSaveActive();
    }
    return normalized;
}
