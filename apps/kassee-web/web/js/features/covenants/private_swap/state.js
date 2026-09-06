import { exactJsonStringify } from '../../../core/exact.js';

const STORAGE_KEY = 'kassee_private_swap_v2';

export const privateSwapState = Object.seal({
    role: '', stage: 'idle', swapId: '', network: '',
    myKeyId: '', myClaimPubkey: '', myOwnAdaptorPoint: '', myBindingToken: '',
    adaptorPoint: '',
    myDestination: '', myOwnerPubkey: '', mySalt: '', myAmountSompi: '', myTimeoutDaa: '',
    counterKeyId: '', counterClaimPubkey: '', counterDestination: '', counterOwnerPubkey: '', counterSalt: '', counterAmountSompi: '', counterTimeoutDaa: '',
    myAddress: '', myRedeem: '', counterAddress: '', counterRedeem: '',
    myOutpoint: null, counterOutpoint: null,
    myClaimPskb: '', myClaimKspt: '', myClaimSighash: '', myClaimFeeSompi: '',
    myPreSignature: '', myPreSignatureNegated: false,
    counterClaimKspt: '', counterClaimSighash: '', counterClaimFeeSompi: '',
    counterPreSignature: '', counterPreSignatureNegated: false,
    counterCompletedSignature: '', readyAckHash: '', completed: false,
});

export function resetPrivateSwapState() {
    Object.assign(privateSwapState, {
        role: '', stage: 'idle', swapId: '', network: '',
        myKeyId: '', myClaimPubkey: '', myOwnAdaptorPoint: '', myBindingToken: '', adaptorPoint: '',
        myDestination: '', myOwnerPubkey: '', mySalt: '', myAmountSompi: '', myTimeoutDaa: '',
        counterKeyId: '', counterClaimPubkey: '', counterDestination: '', counterOwnerPubkey: '', counterSalt: '', counterAmountSompi: '', counterTimeoutDaa: '',
        myAddress: '', myRedeem: '', counterAddress: '', counterRedeem: '',
        myOutpoint: null, counterOutpoint: null,
        myClaimPskb: '', myClaimKspt: '', myClaimSighash: '', myClaimFeeSompi: '',
        myPreSignature: '', myPreSignatureNegated: false,
        counterClaimKspt: '', counterClaimSighash: '', counterClaimFeeSompi: '',
        counterPreSignature: '', counterPreSignatureNegated: false,
        counterCompletedSignature: '', readyAckHash: '', completed: false,
    });
    savePrivateSwapState();
}

export function savePrivateSwapState() {
    try { sessionStorage.setItem(STORAGE_KEY, exactJsonStringify(privateSwapState)); } catch (_) {}
}

export function loadPrivateSwapState() {
    try {
        const raw = sessionStorage.getItem(STORAGE_KEY);
        if (!raw) return privateSwapState;
        const parsed = JSON.parse(raw);
        for (const key of Object.keys(privateSwapState)) {
            if (Object.prototype.hasOwnProperty.call(parsed, key)) privateSwapState[key] = parsed[key];
        }
    } catch (_) {}
    return privateSwapState;
}

export function restorePrivateSwapState(value) {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Private Swap recovery state is invalid');
    if (parsed.role !== 'alice' && parsed.role !== 'bob') throw new Error('Private Swap recovery role is invalid');
    if (!/^[0-9a-f]{32}$/.test(parsed.swapId || '')) throw new Error('Private Swap recovery ID is invalid');
    const forbidden = Object.keys(parsed).find(key => key.toLowerCase().includes('secret') || ['myClaimPskb','myClaimKspt','counterClaimKspt'].includes(key));
    if (forbidden) throw new Error('Private Swap recovery contains forbidden transient or secret material');
    resetPrivateSwapState();
    for (const key of Object.keys(privateSwapState)) {
        if (Object.prototype.hasOwnProperty.call(parsed, key)) privateSwapState[key] = parsed[key];
    }
    savePrivateSwapState();
    return privateSwapState;
}

export function clearPrivateSwapState() {
    resetPrivateSwapState();
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (_) {}
}

loadPrivateSwapState();
