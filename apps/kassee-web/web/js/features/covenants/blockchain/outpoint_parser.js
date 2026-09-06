// Pure BlockAdded-notification parsing helpers.
import { hexToBytes } from '../../../core/bytes.js';

function matchesOutpoint(data, offset, txidBytes, outputIndex) {
    if (offset + 41 > data.length) return false;
    if (data[offset] !== 37 || data[offset + 1] !== 0 || data[offset + 2] !== 0 || data[offset + 3] !== 0) return false;
    if (data[offset + 4] !== 0x01) return false;
    for (let index = 0; index < txidBytes.length; index++) {
        if (data[offset + 5 + index] !== txidBytes[index]) return false;
    }
    const indexOffset = offset + 37;
    const encodedIndex = (
        data[indexOffset]
        | (data[indexOffset + 1] << 8)
        | (data[indexOffset + 2] << 16)
        | (data[indexOffset + 3] << 24)
    ) >>> 0;
    return encodedIndex === (Number(outputIndex || 0) >>> 0);
}

export function findSpendingSignatureScript(data, outpoint, bounds) {
    if (!(data instanceof Uint8Array) || data.length < 4 || !outpoint) return null;
    const envelopeOffset = data[0] === 0x01 ? 9 : 1;
    if (envelopeOffset + 2 >= data.length || data[envelopeOffset] !== 0xFF) return null;
    if (data[envelopeOffset + 2] !== 0x3C) return null;

    if (typeof outpoint.txid !== 'string' || !/^[0-9a-f]{64}$/i.test(outpoint.txid)) return null;
    const txidBytes = hexToBytes(outpoint.txid);
    const minLength = bounds?.minLength ?? 1;
    const maxLength = bounds?.maxLength ?? 2000;

    for (let offset = 4; offset + 45 <= data.length; offset++) {
        if (!matchesOutpoint(data, offset, txidBytes, outpoint.index)) continue;
        const lengthOffset = offset + 41;
        if (lengthOffset + 4 > data.length) continue;
        const scriptLength = (
            data[lengthOffset]
            | (data[lengthOffset + 1] << 8)
            | (data[lengthOffset + 2] << 16)
            | (data[lengthOffset + 3] << 24)
        ) >>> 0;
        if (scriptLength < minLength || scriptLength > maxLength) continue;
        const scriptOffset = lengthOffset + 4;
        if (scriptOffset + scriptLength > data.length) continue;
        return data.slice(scriptOffset, scriptOffset + scriptLength);
    }
    return null;
}

export function readFirstPush(script, maxLength = 200) {
    if (!(script instanceof Uint8Array) || script.length === 0) return null;
    const opcode = script[0];
    let dataOffset;
    let dataLength;
    if (opcode >= 1 && opcode <= 0x4B) {
        dataOffset = 1;
        dataLength = opcode;
    } else if (opcode === 0x4C && script.length >= 2) {
        dataOffset = 2;
        dataLength = script[1];
    } else {
        return null;
    }
    if (dataLength === 0 || dataLength > maxLength || dataOffset + dataLength > script.length) return null;
    return script.slice(dataOffset, dataOffset + dataLength);
}
