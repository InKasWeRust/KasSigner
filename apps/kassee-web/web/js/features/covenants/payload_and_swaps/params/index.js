import { variableHex } from './primitives.js';
import { standardSerializers } from './standard.js';
import { advancedSerializers } from './advanced.js';

const SERIALIZERS = Object.freeze({ ...standardSerializers, ...advancedSerializers });

export function buildCovenantParamsHex(result) {
    return (SERIALIZERS[result.type] || ((value) => variableHex(value.redeem_script_hex)))(result);
}
