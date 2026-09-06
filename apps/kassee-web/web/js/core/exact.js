// Lossless helpers for consensus integers crossing the Rust/WASM/JSON boundary.

export function exactUnsigned(value, field = 'integer') {
    if (typeof value === 'bigint') {
        if (value < 0n) throw new Error(`${field} must be unsigned`);
        return value;
    }
    if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) return BigInt(value);
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
    throw new Error(`${field} must be an exact unsigned decimal integer`);
}

export function exactUnsignedJsonField(rawJson, fieldName, field = fieldName) {
    if (typeof rawJson !== 'string' || typeof fieldName !== 'string' || !fieldName) {
        throw new Error(`${field} must come from JSON text`);
    }
    const escaped = fieldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`"${escaped}"\\s*:\\s*(?:"(0|[1-9]\\d*)"|(0|[1-9]\\d*))(?=\\s*[,}])`, 'g');
    const matches = [...rawJson.matchAll(pattern)];
    if (matches.length !== 1) throw new Error(`${field} must appear exactly once as an unsigned decimal integer`);
    return BigInt(matches[0][1] ?? matches[0][2]);
}

export function exactDecimalString(value, field = 'integer') {
    return exactUnsigned(value, field).toString();
}

export function exactJsonStringify(value) {
    return JSON.stringify(value, (_key, entry) => typeof entry === 'bigint' ? entry.toString() : entry);
}

export function compareExactDescending(left, right) {
    const a = exactUnsigned(left);
    const b = exactUnsigned(right);
    return a === b ? 0 : (a > b ? -1 : 1);
}

export function nonNegativeDifference(minuend, ...subtrahends) {
    let value = exactUnsigned(minuend);
    for (const entry of subtrahends) value -= exactUnsigned(entry);
    return value > 0n ? value : 0n;
}
