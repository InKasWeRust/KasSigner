import { hexToBytes } from '../../../../core/bytes.js';
import { readVstr } from './payload_reader.js';

export function readOptionalDate(params, offset) {
    if (offset >= params.length) return '';
    try {
        return readVstr(params, offset, hexToBytes).str || '';
    } catch (_) {
        return '';
    }
}
