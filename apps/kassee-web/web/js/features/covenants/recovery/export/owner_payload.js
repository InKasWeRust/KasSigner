import { COVENANT_TYPE_CODES } from '../../payload_and_swaps/types.js';
import { buildCovenantParamsHex } from '../../payload_and_swaps/params.js';
import { build_covenant_payload, derive_covenant_payload_key } from '../../../../wasm/api.js';
import { bytesToHex, hexToBytes } from '../../../../core/bytes.js';

export async function buildOwnerExport(covenant, kpub) {
    const result = ownerCovenantResult(covenant);
    const type = covenant.type || 'unknown';
    const typeByte = COVENANT_TYPE_CODES[type] || 0xFF;
    const plaintext = hexToBytes(build_covenant_payload(typeByte, buildCovenantParamsHex(result)));
    if (!kpub) throw new Error('Wallet kpub is unavailable');
    const keyBytes = hexToBytes(derive_covenant_payload_key(kpub));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const cipher = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        plaintext,
    ));
    const bytes = new Uint8Array(16 + cipher.length);
    bytes.set(new TextEncoder().encode('COVB'), 0);
    bytes.set(nonce, 4);
    bytes.set(cipher, 16);
    return Object.freeze({ bytes, hex: bytesToHex(bytes), encrypted: true, extension: '.covb' });
}

function ownerCovenantResult(covenant) {
    const fields = [
        'type', 'address', 'redeem_script_hex', 'locktime_daa', 'inactivity_daa',
        'heir_address', 'heir_pubkey_hex', 'beneficiary_pubkey_hex',
        'owner_pubkey_hex', 'counterparty_pk',
        'threshold_sompi', 'deadline_daa', 'merkle_root', 'merkle_depth',
        'merkle_addresses_json', 'max_withdraw_sompi', 'cooldown_daa', 'start_daa',
        'commit_hash', 'cr_ciphertext_hex', 'wallet1_pubkey_hex', 'wallet2_pubkey_hex',
        'locktime_date_iso',
        'crowdfund_role', 'campaign_name', 'organizer_address', 'goal_sompi', 'vk_hex',
        'campaign_id', 'crowdfund_pk_hex', 'crowdfund_salt_hex', 'contributor_pubkey_hex',
        'crowdfund_contributions_json', 'private_swap_recovery_json',
    ];
    return Object.fromEntries(fields.map(field => [field, covenant[field]]));
}
