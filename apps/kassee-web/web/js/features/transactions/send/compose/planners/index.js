import { covenantState, navigationState, transactionState } from '../../../../../app/state/index.js';
import { planCovenant } from './covenant.js';
import { planAutomatic, planSelected } from './standard.js';

export async function planTransaction(request) {
    const { destination, amountString, fee, freshWallet } = request;
    if (navigationState._broadcastReturnScreen === 'covenant'
        && covenantState.lastCovenantResult
        && destination === covenantState.lastCovenantResult.address) {
        return planCovenant(destination, amountString, fee);
    }
    const standardPlan = transactionState.selectedUtxoIds && transactionState.selectedUtxoIds.length > 0
        ? await planSelected(freshWallet, destination, amountString, fee)
        : await planAutomatic(freshWallet, destination, amountString, fee);
    return { ...standardPlan, kind: 'standard' };
}
