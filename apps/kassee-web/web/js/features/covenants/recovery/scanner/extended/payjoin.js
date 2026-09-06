import { readLen, readU64 } from '../payload_reader.js';
import { readOptionalDate } from '../optional_date.js';
import { recoveredFromRedeem } from './common.js';

export function decodePayjoin(params, network) {
    const beneficiaryPublicKey = params.substring(0, 64);
    const locktime = readU64(params, 64);
    const minimumInputs = readU64(params, 80);
    const minimumOutputs = readU64(params, 96);
    const { len, endOff } = readLen(params, 112);
    const redeem = params.substring(endOff, endOff + len * 2);
    const date = readOptionalDate(params, endOff + len * 2);
    const result = recoveredFromRedeem('payjoin', redeem, network, {
        locktime_daa: locktime,
        beneficiary_pubkey_hex: beneficiaryPublicKey,
        min_inputs: Number(minimumInputs),
        min_outputs: Number(minimumOutputs),
        role: 'owner',
    });
    if (result && date) result.locktime_date_iso = date;
    return result;
}
