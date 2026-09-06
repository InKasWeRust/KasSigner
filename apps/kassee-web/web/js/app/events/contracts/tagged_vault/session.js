import { byId } from '../../../../core/dom.js';

export function createTaggedVaultSession() {
    const state = {
        pk: null,
        addr: null,
        covId: null,
        covAddr: null,
        redeemHex: null,
        splitCovId: null,
        splitCovAddr: null,
        splitRedeemHex: null,
    };
    return { state, log: createTaggedVaultLogger() };
}

function createTaggedVaultLogger() {
    return (message) => {
        const output = byId('tv-log');
        if (output) {
            output.style.display = 'block';
            output.textContent += `${output.textContent ? '\n' : ''}${message}`;
            output.scrollTop = output.scrollHeight;
        }
        console.log(`[TaggedVault] ${message}`);
    };
}
