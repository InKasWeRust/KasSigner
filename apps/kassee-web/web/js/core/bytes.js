/** Convert a byte-oriented value to lowercase hexadecimal. */
export function bytesToHex(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let output = '';
    for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
    return output;
}

/** Decode validated hexadecimal into a Uint8Array. */
export function hexToBytes(value) {
    if (typeof value !== 'string') throw new TypeError('hex value must be a string');
    const hex = value.trim();
    if (hex.length % 2 !== 0) throw new RangeError('hex value must contain an even number of characters');
    if (!/^[0-9a-f]*$/i.test(hex)) throw new RangeError('hex value contains non-hexadecimal characters');
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < hex.length; index += 2) {
        bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
    }
    return bytes;
}

/** Encode UTF-8 text as lowercase hexadecimal. */
export function utf8ToHex(value) {
    return bytesToHex(new TextEncoder().encode(String(value)));
}

export function littleEndianHexToU64(hex) {
    if (!/^[0-9a-fA-F]{16}$/.test(hex)) {
        throw new Error('expected exactly 8 bytes of hexadecimal data');
    }
    let value = 0n;
    for (let index = 0; index < 8; index += 1) {
        const byte = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
        value |= BigInt(byte) << BigInt(index * 8);
    }
    return value;
}

export function u64ToLittleEndianHex(value) {
    let remaining = BigInt(value);
    if (remaining < 0n || remaining > 0xffffffffffffffffn) {
        throw new RangeError('value must fit in an unsigned 64-bit integer');
    }
    let encoded = '';
    for (let index = 0; index < 8; index += 1) {
        encoded += Number(remaining & 0xffn).toString(16).padStart(2, '0');
        remaining >>= 8n;
    }
    return encoded;
}
