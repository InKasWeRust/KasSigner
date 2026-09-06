import { hexToBytes } from '../../../../../core/bytes.js';
import { readLen, readU64, readVstr } from '../payload_reader.js';
import { recoveredFromRedeem } from './common.js';

export function decodeMerkleWhitelist(params, network) {
    const { len, endOff } = readLen(params, 0);
    const redeem = params.substring(endOff, endOff + len * 2);
    let position = endOff + len * 2;
    const root = params.substring(position, position + 64); position += 64;
    const depth = Number.parseInt(params.substring(position, position + 2), 16); position += 2;
    const locktime = readU64(params, position); position += 16;
    let addresses = '';
    try { addresses = readVstr(params, position, hexToBytes).str; } catch (_) {}
    return recoveredFromRedeem('merkle-whitelist', redeem, network, {
        locktime_daa: locktime,
        merkle_root: root,
        merkle_depth: depth,
        merkle_addresses_json: addresses,
        role: 'owner',
    });
}
