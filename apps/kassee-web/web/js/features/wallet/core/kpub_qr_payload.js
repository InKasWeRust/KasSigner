const ACCOUNT_KEY_TEXT_RE = /^kpub1:[0-9a-f]{156}$/;
const LEGACY_ACCOUNT_KEY_RE = /^kpub[1-9A-HJ-NP-Za-km-z]+$/;
const BIP32_XPUB_RE = /^xpub[1-9A-HJ-NP-Za-km-z]+$/;
const COMPACT_ACCOUNT_KEY_LENGTH = 79;
const COMPACT_ACCOUNT_KEY_VERSION = 0x01;

function asBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) return Uint8Array.from(value);
    return new Uint8Array();
}

export function normalizeKpubText(value) {
    const text = String(value || '').trim();
    if (text.length >= 2) {
        const first = text[0];
        const last = text[text.length - 1];
        if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
            return text.slice(1, -1).trim();
        }
    }
    return text;
}

export function isCanonicalKpubText(value) {
    return ACCOUNT_KEY_TEXT_RE.test(normalizeKpubText(value));
}

export function isLegacyKpubText(value) {
    return LEGACY_ACCOUNT_KEY_RE.test(normalizeKpubText(value));
}

export function isBip32XpubText(value) {
    return BIP32_XPUB_RE.test(normalizeKpubText(value));
}

export function isSupportedKpubText(value) {
    const text = normalizeKpubText(value);
    return isCanonicalKpubText(text)
        || isLegacyKpubText(text)
        || isBip32XpubText(text);
}

export function classifyKpubQrCode(code) {
    if (!code) throw new Error('No QR code was found in the selected image');

    const bytes = asBytes(code.binaryData);
    if (bytes.length === COMPACT_ACCOUNT_KEY_LENGTH && bytes[0] === COMPACT_ACCOUNT_KEY_VERSION) {
        return { kind: 'compact', payload: bytes };
    }

    let text = typeof code.data === 'string' ? normalizeKpubText(code.data) : '';
    if (!text && bytes.length > 0) text = normalizeKpubText(new TextDecoder().decode(bytes));
    if (isSupportedKpubText(text)) return { kind: 'text', payload: text };

    throw new Error('The QR image does not contain a valid KasSigner kpub');
}
