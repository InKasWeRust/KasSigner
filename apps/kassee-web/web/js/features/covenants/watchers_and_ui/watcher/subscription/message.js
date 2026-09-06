export function detectSpendPath(signature, redeemScriptHex) {
    if (isSinglePathCovenant(redeemScriptHex)) {
        console.log('[KasSee] Covenant spend: single-path (no selector) => owner');
        return 'owner';
    }
    const selectorPosition = branchSelectorPosition(signature, redeemScriptHex.length / 2);
    if (selectorPosition < 0) return 'unknown';
    const selector = signature[selectorPosition];
    const path = selector === 0x51 ? 'owner' : 'heir';
    console.log(`[KasSee] Branch selector byte: 0x${selector.toString(16)} at pos ${selectorPosition} => ${path}`);
    return path;
}

function isSinglePathCovenant(redeemScriptHex) {
    if (redeemScriptHex.length < 70) return false;
    const first = parseInt(redeemScriptHex.slice(0, 2), 16);
    const bodyOffset = first === 0x08 && parseInt(redeemScriptHex.slice(18, 20), 16) === 0x75
        ? 10
        : 0;
    return parseInt(redeemScriptHex.slice(bodyOffset * 2, bodyOffset * 2 + 2), 16) === 0x20
        && parseInt(redeemScriptHex.slice((bodyOffset + 33) * 2, (bodyOffset + 33) * 2 + 2), 16) === 0xad;
}

function branchSelectorPosition(signature, redeemLength) {
    if (!redeemLength) return -1;
    const pushData2 = signature.length - redeemLength - 3;
    if (pushData2 > 0 && signature[pushData2] === 0x4D) return pushData2 - 1;
    const pushData1 = signature.length - redeemLength - 2;
    if (pushData1 > 0 && signature[pushData1] === 0x4C) return pushData1 - 1;
    const direct = signature.length - redeemLength - 1;
    if (direct > 0 && signature[direct] <= 0x4B) return direct - 1;
    return -1;
}
