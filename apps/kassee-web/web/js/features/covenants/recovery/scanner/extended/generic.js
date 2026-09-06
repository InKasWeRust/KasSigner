import { readLen } from '../payload_reader.js';
import { recoveredFromRedeem } from './common.js';

export function decodeGeneric(type, params, network) {
    if (params.length < 4) return null;
    const { len, endOff } = readLen(params, 0);
    return recoveredFromRedeem(type, params.substring(endOff, endOff + len * 2), network);
}
