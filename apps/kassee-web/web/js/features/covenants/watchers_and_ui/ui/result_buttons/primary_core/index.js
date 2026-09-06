import { configureAdditive } from './additive.js';
import { configureAllowance } from './allowance.js';
import { configureEscrow } from './escrow.js';
import { configureDeadManSwitch, configureTimelockedSavings } from './timed.js';
import { configureOracleV1 } from './oracle_v1.js';

const CONFIGURERS = Object.freeze({
    additive: configureAdditive,
    'global-allowance': configureAllowance,
    dms: configureDeadManSwitch,
    'timelocked-savings': configureTimelockedSavings,
    escrow: configureEscrow,
    'oracle-v1': configureOracleV1,
});

export function configurePrimaryCoreActions(state) {
    const configure = CONFIGURERS[state.type];
    if (!configure) return false;
    configure(state);
    return true;
}
