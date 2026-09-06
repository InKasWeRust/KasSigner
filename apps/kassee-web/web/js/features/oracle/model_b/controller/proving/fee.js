import { oracleState } from '../../../../../app/state/index.js';
import { bytesToHex, hexToBytes } from '../../../../../core/bytes.js';
import { byId } from '../../../../../core/dom.js';
import { kasToSompi, sompiToKasString } from '../../../../../core/amounts.js';

export function spliceOracleServiceFee(wireHex, protocol) {
    const wireBytes = hexToBytes(wireHex);
    if (wireBytes.length < 4 || String.fromCharCode(...wireBytes.slice(0, 4)) !== 'PSKB') {
        throw new Error('not a PSKB envelope');
    }
    const encodedJson = new TextDecoder().decode(wireBytes.slice(4));
    const bundle = JSON.parse(new TextDecoder().decode(hexToBytes(encodedJson)));
    const pskt = Array.isArray(bundle) ? bundle[0] : bundle;
    if (!Array.isArray(pskt?.outputs) || !pskt.outputs.length) {
        throw new Error('roll PSKB has no outputs to splice the fee into');
    }
    pskt.outputs.push({
        amount: protocol.feeSompi.toString(),
        scriptPublicKey: protocol.feeSpk,
        proprietaries: {},
    });
    const jsonHex = bytesToHex(new TextEncoder().encode(JSON.stringify(bundle)));
    return bytesToHex(new TextEncoder().encode(`PSKB${jsonHex}`));
}

export function setOracleFee(totalKas, fromCustom) {
    let sompi;
    try { sompi = kasToSompi(String(totalKas).trim()); } catch (_) { return; }
    if (sompi < 100000000n) return;
    const value = sompiToKasString(sompi);
    oracleState._oracleMbFeeTotalKas = value;
    document.querySelectorAll('.omb-fee-btn').forEach((button) => {
        const selected = !fromCustom && button.getAttribute('data-omb-fee') === value;
        button.style.background = selected ? 'var(--teal)' : 'var(--bg)';
        button.style.color = selected ? '#0a0a0a' : 'var(--text)';
        button.style.borderColor = selected ? 'var(--teal)' : 'var(--border)';
    });
    const button = byId('btn-oracle-mb-ask');
    if (button) button.textContent = `Ask for new price (≈${value} KAS)`;
}
