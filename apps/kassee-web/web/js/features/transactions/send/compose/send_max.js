import { exactUnsigned } from '../../../../core/exact.js';
import { kasToSompi, sompiToKasString } from '../../../../core/amounts.js';

export function selectedSendMaximumSompi(selectedTotalSompi, inputCount, requestedFeeSompi) {
    const computeMass = 800n * BigInt(Math.max(0, inputCount | 0)) + 2000n;
    const massFeeSompi = computeMass * 110n;
    const requestedFee = exactUnsigned(requestedFeeSompi, 'fee');
    const fee = massFeeSompi > requestedFee ? massFeeSompi : requestedFee;
    const total = exactUnsigned(selectedTotalSompi, 'selected UTXO total');
    return total > fee ? total - fee : 0n;
}

export function balanceSendMaximumKas(totalKas, feeSompi) {
    const total = kasToSompi(totalKas);
    const fee = exactUnsigned(feeSompi, 'fee');
    return sompiToKasString(total > fee ? total - fee : 0n);
}
