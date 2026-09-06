import { oracleState } from '../../../../../app/state/index.js';
// Oracle Model B card presentation.
import { byId } from '../../../../../core/dom.js';
import { formatAge, formatPrice, shorten } from './format.js';

export function createOracleRendering() {
    function oracleMbRenderAge() {
        const age = byId('oracle-mb-age');
        if (!age || !oracleState._oracleMbState) return;
        const formatted = formatAge(oracleState._oracleMbState.t);
        age.textContent = formatted.txt;
        age.style.color = formatted.stale ? '#ffd600' : 'var(--teal)';
    }

    function oracleMbRenderState() {
        if (!oracleState._oracleMbState) return;
        const price = byId('oracle-mb-price');
        if (price) price.textContent = formatPrice(oracleState._oracleMbState.price);
        const address = byId('oracle-mb-addr');
        if (address) address.textContent = shorten(oracleState._oracleMbState.addr);
        const roll = byId('oracle-mb-rolltx');
        if (roll) roll.textContent = shorten(oracleState._oracleMbState.rollTxid);
        oracleMbRenderAge();
    }

    return { oracleMbRenderAge, oracleMbRenderState };
}
