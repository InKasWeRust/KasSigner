// Pure covenant payload readers.

// Helper: read 8-byte LE u64 from hex at offset (in hex chars)
export const readU64 = (hex, off) => {
    let n = 0n;
    for (let i = 0; i < 8; i++) {
        const byte = parseInt(hex.substring(off + i * 2, off + i * 2 + 2), 16);
        n |= BigInt(byte) << BigInt(i * 8);
    }
    return n;
};
// Helper: read 2-byte LE length from hex at offset, returns { len, endOff }
export const readLen = (hex, off) => {
    const lo = parseInt(hex.substring(off, off + 2), 16);
    const hi = parseInt(hex.substring(off + 2, off + 4), 16);
    return { len: lo | (hi << 8), endOff: off + 4 };
};
// Helper: read variable-length string (2-byte LE len + UTF-8 bytes)
export const readVstr = (hex, off, hexToBytes) => {
    const { len, endOff } = readLen(hex, off);
    const strHex = hex.substring(endOff, endOff + len * 2);
    const bytes = hexToBytes(strHex);
    return { str: new TextDecoder().decode(bytes), endOff: endOff + len * 2 };
};
