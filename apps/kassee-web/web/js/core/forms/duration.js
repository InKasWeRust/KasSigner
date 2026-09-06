import { byId } from '../dom.js';
import { durationPartsToSeconds } from '../format.js';

export function bindDurationInputs({ prefix, outputId }) {
    const ids = {
        years: `${prefix}-years`,
        months: `${prefix}-months`,
        days: `${prefix}-days`,
        hours: `${prefix}-hours`,
        minutes: `${prefix}-mins`,
    };
    const recalculate = () => {
        const parts = Object.fromEntries(Object.entries(ids).map(([name, id]) => [
            name,
            Number.parseInt(byId(id)?.value || '0', 10) || 0,
        ]));
        const total = durationPartsToSeconds(parts);
        byId(outputId).value = total > 0 ? total : '';
    };
    Object.values(ids).forEach((id) => {
        const input = byId(id);
        if (input) input.oninput = recalculate;
    });
    return recalculate;
}
