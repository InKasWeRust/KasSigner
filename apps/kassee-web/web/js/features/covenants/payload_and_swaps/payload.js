import { walletSession } from '../../../app/state/index.js';
import { build_covenant_payload, derive_covenant_payload_key, parse_covenant_payload } from '../../../wasm/api.js';
// KasSee Web — features/covenants/payload_and_swaps/payload
import { bytesToHex, hexToBytes } from '../../../core/bytes.js';

import { buildCovenantParamsHex } from './params.js';
import { COVENANT_TYPE_CODES, COVENANT_TYPES_BY_CODE } from './types.js';

// ─── Encrypted Covenant Payload Standard ───
// Every covenant funding TX carries encrypted reconstruction params in TX payload.
// Chain becomes the backup. Recovery = seed -> kpub -> chain scan -> decrypt.
// Format: [nonce:12][ciphertext:variable][authTag:16]
// Plaintext: [version:1][type:1][params:variable] (built by WASM build_covenant_payload)

// Build reconstruction params hex for each covenant type.
// These are the external parameters that can't be re-derived from seed alone.





// Encrypt covenant params using AES-256-GCM via SubtleCrypto.
// Returns hex string: [nonce:12][ciphertext:N][authTag:16]
export async function encryptCovenantPayload(covenantType, covResult) {
    if (!walletSession.hasWallet()) throw new Error('No wallet loaded');
    const wallet = walletSession.current();
    const keyHex = derive_covenant_payload_key(wallet.kpub);
    const paramsHex = buildCovenantParamsHex(covResult);
    const typeByte = COVENANT_TYPE_CODES[covenantType] || 0xFF;
    const plaintextHex = build_covenant_payload(typeByte, paramsHex);
    const plaintext = hexToBytes(plaintextHex);

    // Import AES-256-GCM key
    const keyBytes = hexToBytes(keyHex);
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes.buffer, { name: 'AES-GCM' }, false, ['encrypt']
    );

    // Generate 12-byte random nonce
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    // Encrypt (ciphertext includes auth tag appended by WebCrypto)
    const cipherBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        cryptoKey, plaintext.buffer
    );
    const cipher = new Uint8Array(cipherBuf);

    // Wire format: nonce(12) + ciphertext_with_tag(N+16)
    const payload = new Uint8Array(12 + cipher.length);
    payload.set(nonce, 0);
    payload.set(cipher, 12);

    console.log('[KasSee] Encrypted covenant payload:', payload.length, 'bytes, type:', covenantType);
    return bytesToHex(payload);
}
export async function decryptCovenantPayload(payloadHex) {
    if (!walletSession.hasWallet()) return null;
    try {
        const wallet = walletSession.current();
        const keyHex = derive_covenant_payload_key(wallet.kpub);
        const keyBytes = hexToBytes(keyHex);
        const payload = hexToBytes(payloadHex);

        if (payload.length < 30) return null; // nonce(12) + version(1) + type(1) + tag(16) = 30 min

        const nonce = payload.slice(0, 12);
        const cipherWithTag = payload.slice(12);

        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes.buffer, { name: 'AES-GCM' }, false, ['decrypt']
        );

        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey, cipherWithTag.buffer
        );
        const plaintextHex = bytesToHex(new Uint8Array(plainBuf));
        const parsed = JSON.parse(parse_covenant_payload(plaintextHex));
        parsed.covenant_type_name = COVENANT_TYPES_BY_CODE[parsed.covenant_type] || 'unknown';
        return parsed;
    } catch (e) {
        // Not our payload (different key, corrupted, or not a covenant payload)
        console.log('[KasSee] Payload decrypt failed (not ours?):', e.message || e);
        return null;
    }
}
