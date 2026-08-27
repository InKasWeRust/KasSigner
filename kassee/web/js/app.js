// KasSee Web — Main application logic
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// JS handles: UI, camera, resolver query (fetch), persistence
// WASM handles: BIP32, address encoding, KSPT format, QR gen, Borsh wRPC

import init, {
    version,
    import_kpub,
    import_kpub_raw,
    fetch_balance,
    fetch_utxos,
    get_fee_estimate,
    create_send_kspt,
    create_consolidate_kspt,
    create_send_kspt_selected,
    create_compound_kspt,
    create_send_pskb,
    create_consolidate_pskb,
    create_send_pskb_selected,
    create_send_pskb_with_utxos,
    create_compound_pskb,
    broadcast_signed,
    generate_qr_frames,
    decode_qr_frame,
    reset_qr_decoder,
    decoder_progress,
    create_multisig_kspt,
    fetch_utxos_for_address_js,
    fetch_utxos_for_addresses_js,
    scan_multisig_branch_js,
    multisig_address_at_js,
    create_multisig_pskb_multi_js,
    pskt_detect,
    pskt_summary,
    pskt_finalize_to_kspt,
    pskt_finalize_and_broadcast,
    pskt_relay_to_kspt_v2,
    pskt_merge_signed_kspt_v2,
    create_multisig_pskb,
    create_multisig_pskb_selected,
    decode_address,
    encode_p2pk_address,
    encode_p2sh_address,
    extend_addresses,
    covenant_additive_address,
    covenant_escrow,
    covenant_ship_escrow,
    covenant_global_spending_limit,
    create_global_spending_limit_withdraw,
    create_global_spending_limit_topup,
    covenant_global_allowance,
    create_global_allowance_withdraw,
    create_global_allowance_topup,
    covenant_timelocked_savings,
    create_covenant_timelocked_savings_claim,
    covenant_timelocked_escrow,
    covenant_dms,
    covenant_treasury,
    covenant_atomic_swap,
    covenant_oracle,
    covenant_payjoin,
    create_covenant_owner_spend,
    create_covenant_owner_spend_selected,
    create_covenant_borrower_spend,
    create_covenant_borrower_withdraw,
    create_covenant_beneficiary_spend,
    create_covenant_beneficiary_spend_selected,
    create_covenant_timelocked_savings_claim_selected,
    create_covenant_timeout_refund,
    create_covenant_atomic_claim,
    create_covenant_oracle_claim,
    create_oracle_heartbeat,
    create_covenant_payjoin_claim,
    stealth_meta_from_kpub,
    stealth_generate_payment,
    stealth_scan_announcement,
    stealth_announcement_address,
    create_stealth_spend,
    stealth_create_payment,
    stealth_create_payment_lane,
    stealth_scan_recent_blocks,
    stealth_announce_lane_probe,
    blake2b_hash,
    sha256_hash,
    parse_kpub,
    get_virtual_daa_score,
    get_seq_commit_lane_proof,
    seq_commit_lane_key,
    coinbase_lane_key,
    commit_hash,
    covenant_commit_reveal,
    create_commit_reveal_spend,
    merkle_root_from_addresses,
    merkle_proof_for_address,
    covenant_merkle_whitelist,
    create_merkle_whitelist_spend,
    covenant_crowdfund,
    zk_crowdfund_setup,
    zk_crowdfund_prove,
    create_crowdfund_sweep,
    adaptor_generate_secret,
    adaptor_generate_keypair,
    adaptor_swap_address,
    adaptor_create_sig,
    adaptor_verify_sig,
    adaptor_complete_sig,
    adaptor_extract_secret,
    adaptor_negate_scalar,
    adaptor_bip340_sign,
    adaptor_bip340_verify,
    adaptor_build_sig_script,
    adaptor_swap_commitment,
    adaptor_broadcast_claim,
    generate_qr_svg_text,
    covenant_tagged_vault,
    tagged_vault_keygen,
    tagged_vault_genesis,
    tagged_vault_spend,
    tagged_vault_covenant_id,
    covenant_split_vault,
    split_vault_genesis,
    split_vault_spend,
    create_covenant_pskb,
    create_covenant_pskb_with_payload,
    schnorr_derive_pubkey,
    schnorr_sign_with_key,
    schnorr_sign_ephemeral,
    derive_covenant_payload_key,
    build_covenant_payload,
    parse_covenant_payload,
    build_vcc_subscribe_request, // misnamed: actually builds BlockAdded subscribe (scope variant 0)
    covenant_oracle_mb,
    covenant_oracle_mb_heartbeat,
    covenant_oracle_mb_test_consumer,
    create_oracle_mb_publish,
    create_oracle_mb_heartbeat_roll,
    create_oracle_mb_consume,
} from '../pkg/kassee_web.js';

// ─── Encrypted Covenant Payload Standard ───
// Every covenant funding TX carries encrypted reconstruction params in TX payload.
// Chain becomes the backup. Recovery = seed -> kpub -> chain scan -> decrypt.
// Format: [nonce:12][ciphertext:variable][authTag:16]
// Plaintext: [version:1][type:1][params:variable] (built by WASM build_covenant_payload)

// Covenant type bytes for payload tagging
const COV_TYPE = {
    
    'additive':         0x06, // Piggy Bank
    'escrow':           0x07,
    'timelocked-escrow':0x08,
    'oracle':           0x09,
    'atomic-swap':      0x0A,
    'adaptor-swap':     0x0B,
    'crowdfund':        0x0C,
    'merkle-whitelist': 0x0D,
    'payjoin':          0x0F,
    'treasury':         0x10,
    'deposit':          0x11,
    'commit-reveal':    0x14,
    'dms':              0x18,
    'global-spending-limit': 0x19,
    'global-allowance': 0x1A,
    'timelocked-savings': 0x1B,
};
const COV_TYPE_REV = Object.fromEntries(Object.entries(COV_TYPE).map(([k,v]) => [v, k]));

// Build reconstruction params hex for each covenant type.
// These are the external parameters that can't be re-derived from seed alone.
function buildCovenantParamsHex(covResult) {
    const t = covResult.type;
    let hex = '';
    // Helper: 32-byte pubkey hex (64 chars). Pad/truncate to 64.
    const pk = (h) => (h || '').padEnd(64, '0').substring(0, 64);
    // Helper: 8-byte u64 locktime as little-endian hex
    const lt = (v) => {
        const n = BigInt(v || 0);
        let h = '';
        for (let i = 0; i < 8; i++) h += ((n >> BigInt(i * 8)) & 0xFFn).toString(16).padStart(2, '0');
        return h;
    };
    // Helper: variable-length hex with 2-byte LE length prefix
    const vhex = (h) => {
        const len = (h || '').length / 2;
        const lo = (len & 0xFF).toString(16).padStart(2, '0');
        const hi = ((len >> 8) & 0xFF).toString(16).padStart(2, '0');
        return lo + hi + (h || '');
    };

    // Helper: encode a string as hex bytes with 2-byte LE length prefix
    const vstr = (s) => {
        const bytes = new TextEncoder().encode(s || '');
        const len = bytes.length;
        const lo = (len & 0xFF).toString(16).padStart(2, '0');
        const hi = ((len >> 8) & 0xFF).toString(16).padStart(2, '0');
        return lo + hi + bytesToHex(bytes);
    };

    switch (t) {
        case 'timelocked-savings':
            // Full redeem script (data + any salt) + wallet1_pk(32) + wallet2_pk(32) + locktime(8) + date_iso(vstr).
            // The script is stored whole so recovery is exact regardless of script-format
            // changes; the two pubkeys and locktime are the data used for role detection
            // and display when the covenant is rebuilt from chain. date_iso is the absolute
            // unlock date the user picked, stored so a recovered instance shows that exact
            // date instead of re-estimating it from the DAA score (estimates drift by minutes).
            hex = vhex(covResult.redeem_script_hex || '')
                + pk(covResult.wallet1_pubkey_hex || '')
                + pk(covResult.wallet2_pubkey_hex || '')
                + lt(covResult.locktime_daa)
                + vstr(covResult.locktime_date_iso || '');
            break;
        case 'dms':
            // heir_pk(32) + inactivity_daa(8) = 40 bytes
            hex = pk(covResult.heir_pubkey_hex || covResult.beneficiary_pubkey_hex || '') + lt(covResult.inactivity_daa);
            break;
        case 'global-spending-limit':
            // Full redeem script (salt) + max(8) + cooldown(8) + covenant_id(32).
            // covenant_id is empty (zeros) until the genesis funds the thread.
            hex = vhex(covResult.redeem_script_hex || '') + lt(covResult.max_withdraw_sompi || 0) + lt(covResult.cooldown_daa || 0) + pk(covResult.covenant_id_hex || '');
            break;
        case 'global-allowance':
            // Full redeem script (salt) + max(8) + cooldown(8) + start(8) + bene_pk(32) + covenant_id(32).
            // covenant_id is empty (zeros) until the genesis funds the thread.
            hex = vhex(covResult.redeem_script_hex || '') + lt(covResult.max_withdraw_sompi || 0) + lt(covResult.cooldown_daa || 0) + lt(covResult.start_daa || 0) + pk(covResult.beneficiary_pubkey_hex || '') + pk(covResult.covenant_id_hex || '');
            break;
        case 'escrow':
            // Store full redeem script for exact recovery (salt makes rebuild impossible)
            hex = vhex(covResult.redeem_script_hex || '');
            break;
        case 'timelocked-escrow':
            // beneficiary_pk(32) + locktime(8) = 40 bytes
            hex = pk(covResult.beneficiary_pubkey_hex || '') + lt(covResult.locktime_daa);
            break;
        case 'oracle':
            // Full redeem script (salt) + oracle_pk(32) + beneficiary_pk(32) +
            // locktime(8) + refund_date_iso(vstr). The full script is stored so the
            // random salt survives reload and on-chain payload recovery; rebuilding
            // from params would mint a new salt and a different address. The ISO date
            // is stored so a COVB restore shows the exact refund time instead of
            // re-estimating from DAA (which drifts on every reload).
            hex = vhex(covResult.redeem_script_hex || '') + pk(covResult.oracle_pubkey_hex) + pk(covResult.beneficiary_pubkey_hex) + lt(covResult.locktime_daa) + vstr(covResult.locktime_date_iso || '');
            break;
        case 'adaptor-swap':
            // redeem_script(var) + locktime(8) + secret_key(32) + my_adaptor_sig(var)
            // + counter_addr(var) + counter_redeem(var) + counter_adaptor_sig(var,64B) + T_hex(32) + my_pk(32)
            hex = vhex(covResult.redeem_script_hex || '') + lt(covResult.locktime_daa)
                + pk(covResult._swap_secret_key || '')
                + vhex(covResult._swap_adaptor_sig || '')
                + vstr(covResult._swap_counter_addr || '')
                + vhex(covResult._swap_counter_redeem || '')
                + vhex(covResult._swap_counter_adaptor_sig || '')
                + pk(covResult._swap_T_hex || '')
                + pk(covResult._swap_my_pk || '');
            break;
        case 'crowdfund': {
            // organizer_pk(32) + vk_hash(32) + locktime(8) + goal_sompi(8) = 80 bytes
            const goalSompi = covResult.goal_sompi || kasToSompi(covResult.goal_kas || '0');
            const vkHash = covResult.vk_hash || (covResult.campaign_id || '');
            hex = pk(covResult.organizer_pk || '') + pk(vkHash) + lt(covResult.locktime_daa) + lt(goalSompi);
            break;
        }
        case 'merkle-whitelist':
            // redeem_script(var) + merkle_root(32) + depth(1) + locktime(8) + addresses_json(var)
            hex = vhex(covResult.redeem_script_hex || '') + pk(covResult.merkle_root || '') + (covResult.merkle_depth || 0).toString(16).padStart(2, '0') + lt(covResult.locktime_daa) + vstr(covResult.merkle_addresses_json || '');
            break;
        case 'additive':
            // Full redeem script (salt) + threshold(8) + deadline(8). The full
            // script is stored so the random salt survives reload and on-chain
            // payload recovery; rebuilding from params would mint a new salt and
            // a different address.
            hex = vhex(covResult.redeem_script_hex || '') + lt(covResult.threshold_sompi || 0) + lt(covResult.deadline_daa || covResult.locktime_daa || 0);
            break;
        case 'payjoin':
            // beneficiary_pk(32) + locktime(8) + min_inputs(8) + min_outputs(8) + redeem(var) + date_iso(vstr, optional).
            // date_iso is the absolute refund date the user picked, stored so a recovered
            // instance shows that exact date instead of re-estimating from DAA (drifts each reload).
            hex = pk(covResult.beneficiary_pubkey_hex || '') + lt(covResult.locktime_daa || 0)
                + lt(covResult.min_inputs || 2) + lt(covResult.min_outputs || 2)
                + vhex(covResult.redeem_script_hex || '')
                + vstr(covResult.locktime_date_iso || '');
            break;
        case 'commit-reveal':
            // commit_hash(32) + locktime(8) + redeem(var) + ciphertext(var)
            hex = pk(covResult.commit_hash || covResult.committed_hash || '') + lt(covResult.locktime_daa || 0)
                + vhex(covResult.redeem_script_hex || '')
                + vhex(covResult.cr_ciphertext_hex || '');
            break;
        default:
            // Generic fallback: just store the redeem script (variable length)
            hex = vhex(covResult.redeem_script_hex || '');
            break;
    }
    return hex;
}

// Resolve heir pubkey hex from KasFreeze result (may have address only)
function resolveHeirPk(covResult) {
    if (covResult.heir_pubkey_hex) return covResult.heir_pubkey_hex;
    // If we have heir_address, decode it to get the SPK payload
    if (covResult.heir_address) {
        try {
            const decoded = JSON.parse(decode_address(covResult.heir_address));
            return decoded.payload || '';
        } catch (_) {}
    }
    return '';
}

// Encrypt covenant params using AES-256-GCM via SubtleCrypto.
// Returns hex string: [nonce:12][ciphertext:N][authTag:16]
async function encryptCovenantPayload(covenantType, covResult) {
    if (!walletData) throw new Error('No wallet loaded');
    const wallet = JSON.parse(walletData);
    const keyHex = derive_covenant_payload_key(wallet.kpub);
    const paramsHex = buildCovenantParamsHex(covResult);
    const typeByte = COV_TYPE[covenantType] || 0xFF;
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

// Decrypt covenant payload. Returns { covenant_type: string, params_hex: string } or null.
async function decryptCovenantPayload(payloadHex) {
    if (!walletData) return null;
    try {
        const wallet = JSON.parse(walletData);
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
        parsed.covenant_type_name = COV_TYPE_REV[parsed.covenant_type] || 'unknown';
        return parsed;
    } catch (e) {
        // Not our payload (different key, corrupted, or not a covenant payload)
        console.log('[KasSee] Payload decrypt failed (not ours?):', e.message || e);
        return null;
    }
}

// Hex helpers (complement existing hexToBytes if not yet defined)
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Payload verification token (M-12) ───
//
// SHA-256(payload)[..8] rendered as "xxxxxxxx xxxxxxxx", to be compared by
// eye against the "PL" line on KasSigner's TX review screen.
//
// Was 4 bytes. The token's whole job is to detect a substituted payload, and
// 32 bits is grindable in seconds to minutes, so the adversary it was aimed
// at could choose a payload that produced the token the user had already
// been shown. 64 bits closes that. Grouped in fours because a person is
// doing the comparing.
//
// Defined once because there are two render sites, the pre-signing review
// and the signed-QR view, and they must produce byte-identical strings; a
// literal `slice(0, 4)` in each was how they could silently diverge.
// KasSigner's `ui/screens.rs` must stay in step with this: if one side is
// widened alone, every comparison mismatches and the check reads as an
// attack.
const PL_TOKEN_BYTES = 8;

async function payloadToken(payloadHex) {
    const plBytes = hexToBytes(payloadHex);
    const hashBuf = await crypto.subtle.digest('SHA-256', plBytes.buffer);
    const h = new Uint8Array(hashBuf);
    return bytesToHex(h.slice(0, 4)) + ' ' + bytesToHex(h.slice(4, PL_TOKEN_BYTES));
}

// ─── State ───

let walletData = null;
// L-13: pending KSPT hex for the copy button. Top-level `let`, deliberately
// NOT a `window` property: its only consumer is the copy-KSPT click handler
// in this file. It previously sat on `window._currentKsptHex`, advertising
// the full pending transaction to any script in the page.
let _currentKsptHex = null;
// Our own tx id between broadcasting a covenant spend and the balance
// dropping; see the note at the broadcast site.
let _covSpendBroadcastTx = null;
let customNodeUrl = null;
let lastFeeEstimate = null;
let covFeeLevel = 'normal';

function getCovFee(numInputs = 1, sigOpsPerInput = 1) {
    // Owner sweeps spend P2SH covenant inputs that each carry a redeem script
    // (sig + redeem + pushes), so they are heavier than plain P2PK inputs and the
    // node's compute mass scales with input count. The old 1400 gram/input estimate
    // plus a 400000 floor under-paid 3+ input sweeps (a 3-input tx needs ~450000),
    // which the node rejects as "fees under the required amount for compute mass".
    // Model per-input bytes + sig-op mass at 100 sompi/gram with a 1.15 margin, the
    // same basis as covDepositFee.
    //
    // `sigOpsPerInput` defaults to 1, which is correct for every covenant caller:
    // a covenant input declares one sigop. It is NOT correct for multisig, which
    // declares sig_op_count = N (the total cosigner count, not the threshold M).
    // That is a consensus requirement, not a choice: `consume_sig_op_cost` fires
    // on every signature ATTEMPT, and the attempt count depends on where the
    // signing cosigners sit in the sorted key order, so only N is safe for every
    // combination. Confirmed by Maksim Biriukov, 20 Apr 2026: m <= sigopcount <= n.
    //
    // Until 2026-08-14 the multisig send path called this with no arguments at
    // all, so it priced an N-of-M spend as one input carrying one sigop. A 2-of-3
    // paid 400,000 and needed 413,200; a 3-of-5 needed 626,400; a 2-of-3 over
    // three inputs needed 1,071,200. Everything from N=3 up was refused at relay
    // AFTER the user had signed it on the device and carried it back.
    const n = numInputs > 0 ? numInputs : 1;
    const sigops = sigOpsPerInput > 0 ? sigOpsPerInput : 1;
    const perInputMass = 300 + 1000 * sigops;        // ~300B input + sig_op_count*1000
    const mass = 46 + n * perInputMass + 43 + 340;   // base + inputs + one swept output (+spk)
    const minFee = Math.max(400000, Math.ceil(mass * 100 * 1.15));
    if (!lastFeeEstimate) return BigInt(minFee);
    let feerate;
    if (covFeeLevel === 'low') {
        feerate = lastFeeEstimate.low_sompi_per_gram || 1;
    } else if (covFeeLevel === 'priority') {
        feerate = lastFeeEstimate.priority_sompi_per_gram || 1;
    } else {
        feerate = lastFeeEstimate.normal_sompi_per_gram || 1;
    }
    return BigInt(Math.max(minFee, Math.ceil(feerate * mass * 1.15)));
}

// Cosigner count N from a multisig descriptor, for the sigop term in getCovFee.
//
// Format per `kspt.rs::parse_descriptor`: `multi_hd(M,key,key,...)`, threshold
// first and one entry per cosigner after it, so N is the entry count minus one.
// Written tolerantly on the prefix so a future `multi_hd45(` still counts
// correctly here even though the builder cannot yet consume it.
//
// Returns 0 when the descriptor is unparseable. Callers treat 0 as "unknown"
// and must NOT silently fall back to 1: pricing an unknown multisig at one
// sigop is exactly the bug this exists to prevent.
function msCosignerCount(descriptor) {
    if (!descriptor) return 0;
    const d = descriptor.trim();
    const open = d.indexOf('(');
    if (open < 0 || !d.startsWith('multi') || !d.endsWith(')')) return 0;
    const parts = d.slice(open + 1, -1).split(',');
    return parts.length >= 2 ? parts.length - 1 : 0;
}
// walletData is a JSON string; parse it to read the owner's first receive
// address. (Bare walletData.receive_addresses is undefined on a string, which
// is why owner-spend destinations were silently left blank / fell back to the
// covenant address.)
function ownerReceiveAddr() {
    try {
        const w = JSON.parse(walletData);
        return (w && w.receive_addresses && w.receive_addresses[0]) || '';
    } catch (_) { return ''; }
}
let selectedUtxoIndices = null; // null = auto-select, array = manual
// When set ({locktime}), the UTXO picker confirm builds a beneficiary timeout
// claim (selected sweep) instead of an owner sweep. Cleared on each picker open.
let _pickerBeneClaim = null;
let cachedUtxos = null;
let msSelectedUtxoIndices = null; // multisig UTXO picker: null = auto, array = manual
let msCachedUtxos = null;

// ─── Crowdfund Contributor Watcher ───
let _crowdfundWatcherTimer = null;
let _crowdfundKnownAddrs = new Set();

function crowdfundWatcherStart(campaignId) {
    crowdfundWatcherStop();
    _crowdfundKnownAddrs.clear();
    if (lastCovenantResult && lastCovenantResult.address) {
        _crowdfundKnownAddrs.add(lastCovenantResult.address);
    }
    const statusEl = el('crowdfund-watcher-status');
    if (statusEl) statusEl.textContent = 'Watcher active. Scanning for contributors...';
    console.log('[KasSee] Crowdfund watcher started, campaign_id:', campaignId.substring(0, 16) + '...');

    const poll = async () => {
        try {
            let redeemMap = {};
            try { redeemMap = JSON.parse(localStorage.getItem('crowdfundRedeemMap') || '{}'); } catch (_) {}
            const ta = el('crowdfund-sweep-addrs');
            if (!ta) return;
            // Get current campaign's VK hash for filtering
            const vkHex = lastCovenantResult ? lastCovenantResult.vk_hex : (window._crowdfundVk || '');
            let vkHash = '';
            if (vkHex) {
                try { vkHash = blake2b_hash(vkHex); } catch (_) {}
            }
            let changed = false;
            const mapKeys = Object.keys(redeemMap);
            for (const addr of mapKeys) {
                if (_crowdfundKnownAddrs.has(addr)) continue;
                // Filter: only add if redeem script contains this campaign's VK hash
                if (vkHash && redeemMap[addr]) {
                    if (!redeemMap[addr].includes(vkHash)) {
                        continue; // different campaign
                    }
                }
                _crowdfundKnownAddrs.add(addr);
                if (!ta.value.includes(addr)) {
                    ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + addr;
                    changed = true;
                    console.log('[KasSee] Watcher added:', addr.substring(0, 30) + '...');
                }
            }
            if (changed) {
                const count = ta.value.trim().split('\n').filter(a => a.trim()).length;
                if (statusEl) statusEl.textContent = 'Found ' + count + ' contributor address' + (count !== 1 ? 'es' : '');
                toast(count + ' contributor address' + (count !== 1 ? 'es' : '') + ' in sweep list', 'ok', 2000);
            }
        } catch (e) {
            console.log('[KasSee] Watcher poll error:', e);
        }
    };

    poll();
    _crowdfundWatcherTimer = setInterval(poll, 5000);
}

function crowdfundWatcherStop() {
    if (_crowdfundWatcherTimer) {
        clearInterval(_crowdfundWatcherTimer);
        _crowdfundWatcherTimer = null;
    }
}
let scanCallback = null;
let scanStream = null;
let scanAnimFrame = null;
let qrFrames = null;
let qrFrameIdx = 0;
// Sender frame period for animated multi-frame QRs. Default 850ms — field
// value that reads first-pass on the M5Stack (synchronous SRAM decoder,
// ~400-480ms cycle with a symbol in view) with comfortable margin, and
// effortless on the Waveshare. The Waveshare dual-core f32 decoder can go
// much lower (~450ms); use the speed slider to drop it live per board.
let qrFrameMs = 850;
let qrCycleTimer = null;
let refreshing = false; // debounce guard
let network = 'mainnet';
let lastCovenantResult = null; // { address, redeem_script_hex, ... } from last generate
let _broadcastReturnScreen = null; // set by covenant fund flow to return to covenant after broadcast
let _swapCounterpartyInvite = null; // stored from invite scan: { addr, rs, pk, h, a, d }
let _swapWatcherTimer = null; // polls Bob's HTLC for claim detection
let _swapLastBalance = null; // last known balance of Bob's HTLC
let _swapUtxoOutpoint = null; // { txid, index } of Bob's HTLC UTXO for preimage extraction
let _swapSubscriptionWs = null; // persistent WebSocket for UTXO change subscription
let _swapRecentBlockHashes = []; // rolling buffer of block count for status display

// Generic covenant watcher (DMS, Allowance, Spending Limit, etc.)
let _covWatcherTimer = null;
let _covWatcherLastBalance = null;
let _covWatcherOutpoint = null; // { txid, index } for BlockAdded spend detection
let _covActiveWatcherTimer = null; // periodic balance refresh for the active-list (cov menu)
let _covSubscriptionWs = null;

// Adaptor swap state (private swap)
let _adaptorState = null; // { role, t_hex, T_hex, mySecretKey, myAddr, myRedeem, myPk, myAmount, counterAddr, counterRedeem, counterPk, counterAmount, counterAdaptorSig, myAdaptorSig, commitment, completed }
let _adaptorResultReturn = null; // adaptor-result Back target: 'menu' (entered from main active-covenants card) or null (from create/join -> swap menu)
let _adaptorSubscriptionWs = null;
let _adaptorWatcherTimer = null;
let _adaptorResultPollTimer = null;

function adaptorStateSave() {
    try { if (_adaptorState) sessionStorage.setItem('kassee_adaptor_state', JSON.stringify(_adaptorState)); } catch (_) {}
}
function adaptorStateLoad() {
    try {
        const s = sessionStorage.getItem('kassee_adaptor_state');
        if (s) _adaptorState = JSON.parse(s);
    } catch (_) {}
}
function adaptorStateClear() {
    _adaptorState = null;
    _adaptorResultReturn = null;
    adaptorSubscriptionStop();
    if (_adaptorWatcherTimer) { clearInterval(_adaptorWatcherTimer); _adaptorWatcherTimer = null; }
    if (_adaptorResultPollTimer) { clearInterval(_adaptorResultPollTimer); _adaptorResultPollTimer = null; }
    try { sessionStorage.removeItem('kassee_adaptor_state'); } catch (_) {}
}

// ─── Adaptor Swap: Bob's BlockAdded Watcher ───
// Bob monitors his UTXO for Alice's claim. When spent, extracts her completed sig.

function adaptorWatcherStart() {
    if (_adaptorWatcherTimer) return;
    if (!_adaptorState || _adaptorState.role !== 'bob') return;
    if (!_adaptorState.myAddr) return;
    if (_adaptorState.counterCompletedSig) return; // already have it

    console.log('[KasSee] Adaptor watcher started for Bob UTXO: ' + _adaptorState.myAddr);
    _adaptorWatcherTimer = setInterval(() => adaptorWatcherPoll(), 4000);
    adaptorWatcherPoll();
    adaptorSubscriptionStart();
}

function adaptorWatcherStop() {
    if (_adaptorWatcherTimer) {
        clearInterval(_adaptorWatcherTimer);
        _adaptorWatcherTimer = null;
    }
    adaptorSubscriptionStop();
}

// Live balance + timeout update for result panel
async function adaptorResultPoll() {
    if (!_adaptorState || !_adaptorState.myAddr) return;
    try {
        const wsUrl = await resolveNodeUrl();
        // My UTXO balance
        const myUtxos = await fetch_utxos_for_address_js(_adaptorState.myAddr, wsUrl);
        const myBal = JSON.parse(myUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);
        const myKas = (Number(myBal) / 1e8).toFixed(4).replace(/\.?0+$/, '');
        const balEl = el('adaptor-result-balance');
        const fundBtn = el('btn-adaptor-fund');
        if (balEl) {
            if (myBal > 0n) {
                balEl.textContent = myKas + ' KAS';
                _adaptorState._myWasFunded = true;
                if (fundBtn) fundBtn.style.display = 'none';
            } else if (_adaptorState._myWasFunded || _adaptorState.completed) {
                balEl.textContent = _adaptorState.completed ? 'Claimed' : '0 KAS (spent)';
                if (fundBtn) fundBtn.style.display = 'none';
            } else {
                balEl.textContent = 'Not funded (' + (_adaptorState.myAmount / 1e8) + ' KAS to lock)';
                if (fundBtn) fundBtn.style.display = '';
            }
        }

        // Counterparty UTXO balance
        let cBal = 0n;
        if (_adaptorState.counterAddr) {
            const cUtxos = await fetch_utxos_for_address_js(_adaptorState.counterAddr, wsUrl);
            cBal = JSON.parse(cUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);
            const cKas = (Number(cBal) / 1e8).toFixed(4).replace(/\.?0+$/, '');
            const cBalEl = el('adaptor-result-counter-balance');
            if (cBalEl) {
                if (cBal > 0n) {
                    cBalEl.textContent = cKas + ' KAS';
                    _adaptorState._counterWasFunded = true;
                } else {
                    cBalEl.textContent = _adaptorState._counterWasFunded ? '0 KAS (claimed)' : 'Not funded (' + (_adaptorState.counterAmount / 1e8) + ' KAS expected)';
                }
            }
        }

        // Detect swap complete: both UTXOs spent
        const _bothSpent = _adaptorState._myWasFunded && myBal === 0n && _adaptorState._counterWasFunded && cBal === 0n;

        // Timeout countdown (skip if swap complete)
        const timeoutDaa = _adaptorState.role === 'alice' ? _adaptorState.myTimeoutDaa : (_adaptorState.myTimeoutDaa || 0);
        if (timeoutDaa && !_bothSpent) {
            const currentDaa = await fetchCurrentDaa();
            if (currentDaa) {
                const remaining = timeoutDaa - currentDaa;
                const timeoutEl = el('adaptor-result-timeout');
                if (timeoutEl) {
                    if (remaining > 0) {
                        const secs = Math.round(remaining / 10);
                        const targetDate = new Date(Date.now() + secs * 1000);
                        const timeStr = targetDate.toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit' });
                        const mins = Math.floor(secs / 60);
                        const s = secs % 60;
                        timeoutEl.textContent = 'Refund at ~' + timeStr + ' (' + mins + 'm ' + s + 's)';
                        timeoutEl.style.color = 'var(--text-muted)';
                    } else {
                        timeoutEl.textContent = 'Timeout reached. Refund available.';
                        timeoutEl.style.color = 'var(--warning)';
                    }
                }
            }
        } else if (_bothSpent) {
            const timeoutEl = el('adaptor-result-timeout');
            if (timeoutEl) { timeoutEl.textContent = ''; }
        }

        // Dynamic status text
        const statusEl = el('adaptor-result-status');
        if (statusEl && !statusEl.innerHTML.includes('TXID:') && !statusEl.innerHTML.includes('explorer')) {
            const role = _adaptorState.role;
            const myFunded = myBal > 0n || _adaptorState._myWasFunded;
            const counterFunded = cBal > 0n;
            const counterSpent = _adaptorState._counterWasFunded && cBal === 0n;
            const mySpent = _adaptorState._myWasFunded && myBal === 0n;

            if (_bothSpent) {
                statusEl.innerHTML = '<span style="color:var(--teal)">Swap complete. Both parties claimed.</span>';
            } else if (!_adaptorState.completed) {
                if (role === 'alice') {
                    if (myFunded && counterFunded) {
                        statusEl.textContent = 'Both funded. Claim counterparty funds now.';
                        statusEl.style.color = 'var(--teal)';
                    } else if (myFunded && !counterFunded && !_adaptorState._counterWasFunded) {
                        statusEl.textContent = 'Your address funded. Waiting for counterparty to fund.';
                        statusEl.style.color = 'var(--text-muted)';
                    } else if (!myFunded && !_adaptorState._myWasFunded && counterFunded) {
                        statusEl.textContent = 'Counterparty funded. Fund your address to proceed.';
                        statusEl.style.color = 'var(--warning)';
                    }
                } else if (role === 'bob') {
                    if ((mySpent || counterSpent) && _adaptorState.counterCompletedSig) {
                        statusEl.textContent = 'Secret extracted. Tap Claim to complete the swap.';
                        statusEl.style.color = 'var(--teal)';
                    } else if (mySpent) {
                        statusEl.textContent = 'Counterparty claimed your UTXO. Extracting secret...';
                        statusEl.style.color = 'var(--warning)';
                    } else if (myFunded && counterFunded) {
                        statusEl.textContent = 'Both funded. Waiting for counterparty to claim first.';
                        statusEl.style.color = 'var(--text-muted)';
                    } else if (myFunded && !counterFunded && !_adaptorState._counterWasFunded) {
                        statusEl.textContent = 'Your address funded. Waiting for counterparty to fund.';
                        statusEl.style.color = 'var(--text-muted)';
                    } else if (!myFunded && !_adaptorState._myWasFunded && counterFunded) {
                        statusEl.textContent = 'Counterparty funded. Fund your address to proceed.';
                        statusEl.style.color = 'var(--warning)';
                    }
                }
            }
        }
    } catch (_) {}
}

async function adaptorWatcherPoll() {
    if (!_adaptorState || _adaptorState.role !== 'bob' || !_adaptorState.myAddr) return;
    if (_adaptorState.counterCompletedSig) { adaptorWatcherStop(); return; }
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(_adaptorState.myAddr, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);

        // Store outpoint for BlockAdded detection on first funded poll
        if (total > 0n && !_adaptorState.myOutpoint && utxos[0].tx_id) {
            _adaptorState.myOutpoint = { txid: utxos[0].tx_id, index: utxos[0].index || 0 };
            adaptorStateSave();
            // Restart subscription with outpoint
            adaptorSubscriptionStop();
            adaptorSubscriptionStart();
        }

        const hubStatus = el('adaptor-hub-status');
        if (hubStatus) {
            if (total === 0n && _adaptorState.myOutpoint) {
                hubStatus.innerHTML = '<span style="color:var(--warning)">Alice claimed your UTXO. Extracting secret...</span>';
            } else if (total > 0n) {
                hubStatus.textContent = 'Your UTXO: ' + (Number(total) / 1e8).toFixed(2) + ' KAS. Waiting for Alice to claim...';
            }
        }
    } catch (e) {
        // silent
    }
}

async function adaptorSubscriptionStart() {
    adaptorSubscriptionStop();
    if (!_adaptorState || _adaptorState.role !== 'bob') return;
    if (!_adaptorState.myOutpoint || !_adaptorState.myOutpoint.txid) return;
    if (_adaptorState.counterCompletedSig) return;

    try {
        const wsUrl = await resolveNodeUrl();
        const blockAddedReq = new Uint8Array(build_vcc_subscribe_request(43n));

        const ws = new WebSocket(wsUrl);
        ws.binaryType = 'arraybuffer';
        _adaptorSubscriptionWs = ws;

        ws.onopen = () => { ws.send(blockAddedReq); };

        ws.onmessage = (evt) => {
            const data = new Uint8Array(evt.data);
            if (data.length < 4) return;
            let pos = (data[0] === 0x01) ? 9 : 1;
            if (pos >= data.length || data[pos] !== 0xFF) return;
            const notifOp = data[pos + 2];
            if (notifOp !== 0x3C) return;
            if (!_adaptorState || !_adaptorState.myOutpoint) return;

            const txidHex = _adaptorState.myOutpoint.txid;
            const txidBytes = new Uint8Array(32);
            for (let j = 0; j < 32; j++) txidBytes[j] = parseInt(txidHex.substr(j * 2, 2), 16);

            // Scan for outpoint pattern: u32(37) + 0x01 + txid
            for (let k = 4; k < data.length - 40; k++) {
                if (data[k] !== 37 || data[k+1] !== 0 || data[k+2] !== 0 || data[k+3] !== 0) continue;
                if (data[k+4] !== 0x01) continue;
                let match = true;
                for (let j = 0; j < 32; j++) { if (data[k+5+j] !== txidBytes[j]) { match = false; break; } }
                if (!match) continue;

                // Found our outpoint being spent. Extract sig_script.
                const afterOutpoint = k + 5 + 32 + 4; // txid(32) + index(4)
                if (afterOutpoint + 4 > data.length) continue;
                const sigLen = data[afterOutpoint] | (data[afterOutpoint+1] << 8) | (data[afterOutpoint+2] << 16) | (data[afterOutpoint+3] << 24);
                if (sigLen < 98 || sigLen > 2000) continue; // min: 1+64+1+32 = 98
                const sigStart = afterOutpoint + 4;
                if (sigStart + sigLen > data.length) continue;

                // sig_script layout: 0x40 <sig_64> 0x20 <msg_32> <push_redeem> <redeem>
                if (data[sigStart] !== 0x40) continue; // push-64 opcode
                const completedSigBytes = data.slice(sigStart + 1, sigStart + 1 + 64);
                const completedSigHex = Array.from(completedSigBytes).map(b => b.toString(16).padStart(2, '0')).join('');

                console.log('[KasSee] Adaptor: extracted completed sig from chain: ' + completedSigHex.substring(0, 32) + '...');

                _adaptorState.counterCompletedSig = completedSigHex;
                adaptorStateSave();
                adaptorWatcherStop();

                toast('Secret extracted from chain! Tap Complete Claim.', 'ok', 8000);

                const hubStatus = el('adaptor-hub-status');
                if (hubStatus) {
                    hubStatus.innerHTML = '<span style="color:var(--teal)">\u2705 Secret extracted. Ready to claim.</span>';
                }
                break;
            }
        };

        ws.onerror = () => {};
        ws.onclose = () => {
            if (_adaptorSubscriptionWs === ws) {
                _adaptorSubscriptionWs = null;
                if (_adaptorWatcherTimer) {
                    setTimeout(() => adaptorSubscriptionStart(), 3000);
                }
            }
        };
    } catch (e) {
        console.warn('[KasSee] Adaptor subscription failed:', e);
        if (_adaptorWatcherTimer) setTimeout(() => adaptorSubscriptionStart(), 5000);
    }
}

function adaptorSubscriptionStop() {
    if (_adaptorSubscriptionWs) {
        try { _adaptorSubscriptionWs.close(); } catch (_) {}
        _adaptorSubscriptionWs = null;
    }
}

// ─── Swap State Persistence ───
function swapStateSave() {
    try {
        const state = {
            covenant: lastCovenantResult,
            invite: _swapCounterpartyInvite,
            outpoint: _swapUtxoOutpoint,
            preimage: window._extractedPreimage || null,
        };
        sessionStorage.setItem('kassee_swap_state', JSON.stringify(state));
    } catch (_) {}
}

function swapStateLoad() {
    try {
        const raw = sessionStorage.getItem('kassee_swap_state');
        if (!raw) return;
        const state = JSON.parse(raw);
        if (state.covenant && state.covenant.type === 'atomic-swap') {
            lastCovenantResult = state.covenant;
            console.log('[KasSee] Swap state restored: covenant', lastCovenantResult.address);
        }
        if (state.invite) {
            _swapCounterpartyInvite = state.invite;
            console.log('[KasSee] Swap state restored: counterparty invite');
        }
        if (state.outpoint) {
            _swapUtxoOutpoint = state.outpoint;
            console.log('[KasSee] Swap state restored: outpoint', _swapUtxoOutpoint.txid.substring(0, 16));
        }
        if (state.preimage) {
            window._extractedPreimage = state.preimage;
            console.log('[KasSee] Swap state restored: preimage', state.preimage);
        }
    } catch (_) {}
}

function swapStateClear() {
    try { sessionStorage.removeItem('kassee_swap_state'); } catch (_) {}
}

function swapHubRefresh() {
    const hub = el('swap-hub-active');
    if (!hub) return;
    if (lastCovenantResult && lastCovenantResult.type === 'atomic-swap') {
        hub.classList.remove('hidden');
        const addrEl = el('swap-hub-active-addr');
        if (addrEl) addrEl.textContent = lastCovenantResult.address || '';
        const balEl = el('swap-hub-active-balance');
        if (balEl) {
            if (_swapLastBalance !== null) {
                balEl.textContent = (Number(_swapLastBalance) / 1e8).toFixed(2) + ' KAS';
            } else {
                balEl.textContent = 'Checking...';
            }
        }
        const wsEl = el('swap-hub-watcher-status');
        if (wsEl) {
            const hasInvite = !!_swapCounterpartyInvite;
            const wsOpen = _swapSubscriptionWs && _swapSubscriptionWs.readyState === 1;
            if (hasInvite && wsOpen) wsEl.textContent = 'Subscription active. Watching for claim.';
            else if (hasInvite) wsEl.textContent = 'Counterparty invite loaded.';
            else wsEl.textContent = 'No counterparty invite yet.';
        }
    } else {
        hub.classList.add('hidden');
    }
}
let zkSetupData = null; // { pk_hex, vk_hex } from trusted setup
let zkProofData = null; // { proof_hex, public_input_hex } from proof generation
let risc0TestData = null; // { seal, claim, controlId, ... } from test vectors
let bridgeSetupData = null; // { pk_hex, vk_hex } from bridge trusted setup
let bridgeProofData = null; // { proof_hex, commitment_hex } from bridge proof generation
window.bridgeSetupData = null;
window.bridgeProofData = null;
let rollupSetupData = null; // { pk_hex, vk_hex }
let rollupState = null;     // { balances: [u64;4], root_hex }
window.rollupSetupData = null;
window.rollupState = null;
window.getAccountPubkeyHex = getAccountPubkeyHex;   // account-level (covenant owner)
window.getOwnerPubkeyHex = getOwnerPubkeyHex;       // /0/0 address-level (for comparison)
window.create_covenant_timeout_refund = create_covenant_timeout_refund;
window.covenant_oracle_mb = covenant_oracle_mb;
window.covenant_oracle_mb_heartbeat = covenant_oracle_mb_heartbeat;
window.covenant_oracle_mb_test_consumer = covenant_oracle_mb_test_consumer;
window.create_oracle_mb_publish = create_oracle_mb_publish;
window.create_oracle_mb_heartbeat_roll = create_oracle_mb_heartbeat_roll;
window.create_oracle_mb_consume = create_oracle_mb_consume;

// #3: passive oracle-read helpers. Expose the WASM node-RPC primitives on window so the
// KasSee price card (and the console) read the live DAA and an address's UTXOs straight
// from the node, with no REST /info/blockdag round-trip. The bare functions take an
// explicit node URL; the oracle* wrappers auto-resolve it via resolveNodeUrl().
window.get_virtual_daa_score = get_virtual_daa_score;            // (nodeUrl) -> DAA string
window.get_seq_commit_lane_proof = get_seq_commit_lane_proof;    // (nodeUrl, blockHashHexOrEmpty, laneKeyHex) -> proof obj
window.seq_commit_lane_key = seq_commit_lane_key;                // (subnetworkIdHex20) -> laneKeyHex
window.coinbase_lane_key = coinbase_lane_key;                    // () -> coinbase laneKeyHex
window.stealth_announce_lane_probe = stealth_announce_lane_probe; // (nodeUrl, senderSecretHex, fundTxid, fundIndex, fundAmount, metaHex, amount, fee, entropyHex, network) -> {txid, one_time_address, ephemeral_r, view_tag, subnetwork_hex, lane_key}
window.stealth_meta_from_kpub = stealth_meta_from_kpub;          // (kpubStr) -> {scan_pubkey, spend_pubkey, meta_address}
window.stealth_scan_announcement = stealth_scan_announcement;    // (scanPrivHex, spendPubHex, ephemeralRHex, network) -> {one_time_pubkey, address, stealth_index, tweak}
window.fetch_utxos_for_address_js = fetch_utxos_for_address_js;  // (addr, nodeUrl) -> UTXOs JSON
window.fetch_utxos_for_addresses_js = fetch_utxos_for_addresses_js; // (addrsJson, nodeUrl) -> UTXOs JSON, ONE call
window.oracleVirtualDaa = async () => get_virtual_daa_score(await resolveNodeUrl());
window.oracleUtxos = async (addr) => JSON.parse(await fetch_utxos_for_address_js(addr, await resolveNodeUrl()));

// Console helper: fund a covenant_id-bound genesis (oracle heartbeat / oracle / any
// tagged thread that has no UI card). Builds the version-1 tagged-genesis funding
// (output[0] bound with G derived from input[0] on the version-1 tx), no recovery
// payload, then opens the standard Review -> Finalize -> Broadcast flow. Read G off
// the funded UTXO afterward (the node serves it as a version-2 entry).
//   fundCovenantGenesis("kaspatest:...", 5)   // 5 KAS into the thread
async function fundCovenantGenesis(address, amountKas) {
    if (!walletData) { toast('Unlock the wallet first', 'error'); return; }
    if (!address || typeof amountKas !== 'number' || !(amountKas > 0)) {
        console.error('usage: fundCovenantGenesis("kaspatest:...", <amountKas as a number>)');
        return;
    }
    const wallet = JSON.parse(walletData);
    const changeAddr = wallet.change_addresses[wallet.next_change_index || 0];
    const amountSompi = BigInt(Math.round(amountKas * 1e8));
    let fee = covDepositFee({ p2pkInputs: 3, payloadBytes: 0 });
    if (fee < 1000000n) fee = 1000000n;             // generous flat floor for a small funding tx
    showLoading('Building genesis funding...');
    try {
        const pskbHex = await withNodeRetry(wsUrl =>
            // empty utxoCsv => auto-select; '' payload; tagGenesis=true => bind G on output[0]
            create_covenant_pskb_with_payload(walletData, address, amountSompi, fee, changeAddr, '', '', wsUrl, true)
        );
        hideLoading();
        window._covPayloadHex = '';
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Genesis funding failed: ' + e, 'error', 5000);
        console.error('fundCovenantGenesis failed:', e);
    }
}
window.fundCovenantGenesis = fundCovenantGenesis;
window.pskt_finalize_and_broadcast = pskt_finalize_and_broadcast;
window.broadcast_signed = broadcast_signed;
window.parse_kpub = parse_kpub;
window.covenant_additive_address = covenant_additive_address;
window.create_covenant_borrower_spend = create_covenant_borrower_spend;
// L-13: `window.getWalletData` removed. It handed any page script the kpub,
// every derived address and the UTXO set in one call. Its single consumer
// (oracleMbOpenSkeletonForSigning) reads the `walletData` variable directly;
// nothing outside this file ever called it.
window.derive_covenant_payload_key = derive_covenant_payload_key;
window.build_covenant_payload = build_covenant_payload;
window.parse_covenant_payload = parse_covenant_payload;
window.openPsktReview = openPsktReview; // route a KCC20 PSKB into the normal sign+broadcast UI
window.handlePsktRelay = handlePsktRelay; // STANDARD PSKB relay (no 255B SPK cap; needed for covenant SPKs)
window.schnorr_derive_pubkey = schnorr_derive_pubkey;
window.schnorr_sign_with_key = schnorr_sign_with_key;
window.encryptCovenantPayload = encryptCovenantPayload;
window.decryptCovenantPayload = decryptCovenantPayload;
window.recoverCovenants = recoverCovenants;
window.covenant_timelocked_savings = covenant_timelocked_savings;
window.create_covenant_timelocked_savings_claim = create_covenant_timelocked_savings_claim;
window.create_covenant_timelocked_savings_claim_selected = create_covenant_timelocked_savings_claim_selected;

// No localStorage — all state lives in memory only. Session ends on tab close.
let historyEntries = [];
let utxoSnapshot = null;
let fundedReceiveIndices = [];
let fundedChangeIndices = [];
let usedReceiveIndices = new Set();
let usedChangeIndices = new Set();
let addressHistoryEnabled = false;
let customRestUrl = null;
// Stealth indexer (keeper): pull R's from the always-on Linode keeper instead of
// walking the lane in-browser. Toggle persists; URL is fixed.
let stealthIndexerEnabled = localStorage.getItem('kassee-stealth-indexer') === '1';
const STEALTH_INDEXER_URL = 'https://keeper.kassigner.org/keeper';
let autoRefreshTimer = null;
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds

// Broadcast enabled
const BROADCAST_ENABLED = true;

// Donation address
const DONATE_ADDRESS = 'kaspa:qqz0xdq9tu92hgraa89rcmae23f8h09zzzsy4f4agvasmsw3958cza0mv7x86';
const DONATE_KNS = 'kassigner.kns';

// Kasplex API for KRC20 token balances
const KASPLEX_API = {
    'mainnet': 'https://api.kasplex.org/v1',
    'testnet-10': 'https://tn10api.kasplex.org/v1',
};

// KNS domain → address lookup (hardcoded until KNS provides a public API)
const KNS_LOOKUP = {
    'kassigner.kas': 'kaspa:qqz0xdq9tu92hgraa89rcmae23f8h09zzzsy4f4agvasmsw3958cza0mv7x86',
    'inkaswerust.kas': 'kaspa:qqz0xdq9tu92hgraa89rcmae23f8h09zzzsy4f4agvasmsw3958cza0mv7x86',
};

// KRC721 NFT indexer API
const KRC721_API = {
    'mainnet': 'https://mainnet.krc721.stream/api/v1/krc721/mainnet',
    'testnet-10': 'https://testnet-10.krc721.stream/api/v1/krc721/testnet-10',
};

// Resolver URLs (from Kaspa SDK Resolvers.toml)
const RESOLVERS = [
    'https://maxim.kaspa.stream',
    'https://troy.kaspa.stream',
    'https://sean.kaspa.stream',
    'https://eric.kaspa.stream',
    'https://jake.kaspa.green',
    'https://mark.kaspa.green',
    'https://adam.kaspa.green',
    'https://liam.kaspa.green',
    'https://noah.kaspa.blue',
    'https://ryan.kaspa.blue',
    'https://jack.kaspa.blue',
    'https://luke.kaspa.blue',
    'https://john.kaspa.red',
    'https://mike.kaspa.red',
    'https://paul.kaspa.red',
    'https://alex.kaspa.red',
];

// ─── Toast notification system ───

let toastTimer = null;

function toast(msg, type = 'info', duration = 3000) {
    const t = el('toast');
    t.textContent = msg;
    t.className = `toast toast-${type} visible`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        t.classList.remove('visible');
        toastTimer = null;
    }, duration);
}

// ─── Resolver: get a public node wss:// URL ───

// Resolved node, held for the session.
//
// Every call used to re-resolve from a freshly SHUFFLED resolver list, so each
// request landed on a different node: the console filled with "Resolved mainnet
// node: wss://ella...", then vivi, luna, iris, ivy. Nothing could be reused -
// not the WebSocket, which is pooled per URL, and not the resolver, which is a
// cross-origin fetch and the actual source of the CORS flood.
//
// The resolvers are also unreliable in ways that repeat: 500 from one, a 308
// redirect from another, 204 with no body from a third, and several that send no
// Access-Control-Allow-Origin at all, which a browser reports as CORS with the
// real status hidden. Retrying those every call is pure noise.
let _resolvedNodeUrl = null;
let _resolvedNodeNetwork = null;
const _deadResolvers = new Set();

/// Forget the cached node. Called when a connection to it actually fails, so
/// the next call picks a new one rather than retrying a dead endpoint.
function invalidateResolvedNode() {
    if (_resolvedNodeUrl) {
        console.log('[KasSee] dropping node ' + _resolvedNodeUrl);
    }
    _resolvedNodeUrl = null;
    _resolvedNodeNetwork = null;
}
window.invalidateResolvedNode = invalidateResolvedNode;

async function resolveNodeUrl() {
    if (customNodeUrl) return customNodeUrl;
    // Reuse across calls, but not across a network switch.
    if (_resolvedNodeUrl && _resolvedNodeNetwork === network) return _resolvedNodeUrl;
    const url = await resolvePublicNode();
    _resolvedNodeUrl = url;
    _resolvedNodeNetwork = network;
    return url;
}

async function resolvePublicNode() {
    // Skip resolvers already known to fail this session. If every one has
    // failed, clear the set and try again rather than giving up forever - a
    // resolver that was down may have come back.
    let candidates = RESOLVERS.filter(r => !_deadResolvers.has(r));
    if (candidates.length === 0) {
        _deadResolvers.clear();
        candidates = [...RESOLVERS];
    }
    // Shuffled for load spreading, but only among resolvers that still work.
    candidates = candidates.sort(() => Math.random() - 0.5);

    for (const resolver of candidates) {
        try {
            const resp = await fetch(`${resolver}/v2/kaspa/${network}/any/wrpc/borsh`, { signal: AbortSignal.timeout(5000) });
            if (!resp.ok) {
                // 500, 308, 204 and friends: this resolver is not serving us.
                _deadResolvers.add(resolver);
                continue;
            }
            const data = await resp.json();
            if (data.url) {
                console.log(`[KasSee] Resolved ${network} node: ${data.url} (via ${resolver})`);
                return data.url;
            }
            _deadResolvers.add(resolver);
        } catch (e) {
            // Network error, timeout, or a CORS block - the browser hides the
            // status, so the only signal is that it threw. Same treatment.
            _deadResolvers.add(resolver);
        }
    }
    throw new Error('All resolvers failed. Check internet connection.');
}

// Estimate current DAA score from the highest block_daa_score in loaded UTXOs.
// Not exact (lags by a few seconds) but sufficient for locktime calculations
// that are days or months in the future.
function estimateCurrentDaaFromUtxos() {
    if (!utxoSnapshot || !utxoSnapshot.length) return 0;
    let maxDaa = 0;
    for (const u of utxoSnapshot) {
        if (u.block_daa_score && u.block_daa_score > maxDaa) maxDaa = u.block_daa_score;
    }
    return maxDaa;
}

// Fetch current virtual DAA score directly from the node
async function fetchCurrentDaa() {
    try {
        const nodeUrl = await resolveNodeUrl();
        const daaStr = await get_virtual_daa_score(nodeUrl);
        const daa = parseInt(daaStr);
        if (daa > 0) return daa;
    } catch (e) {
        console.log('[KasSee] DAA RPC failed:', e, '- falling back to UTXO estimate');
    }
    return estimateCurrentDaaFromUtxos();
}

let kasFreezeState = null; // { address, redeem_script_hex, heir_address, locktime_daa }
try { kasFreezeState = JSON.parse(localStorage.getItem('kasFreezeState')); } catch (_) {}

// ────────────────────────────────────────────────────────────────────
// KasFreeze multi-session model
// ────────────────────────────────────────────────────────────────────
//
// `kasFreezeSessions` is an array of in-progress (or recently completed)
// KasFreezes. Each entry mirrors the singleton fields of `kasFreezeState`
// plus a stage marker. The hub UI lists these entries with status badges
// and Resume / delete actions. After a successful auto-release the
// session can stay listed briefly (so the user sees the outcome) and
// be removed on the next hub render or explicit delete.
//
// Session shape:
//   {
//     id: string,             // unique, used for DOM keys
//     stage: 'created' | 'funded' | 'released',
//     address: string,
//     redeem_script_hex: string,
//     owner_pubkey_hex: string,
//     heir_address: string,
//     heir_display: string,
//     locktime_daa: number,
//     date_display: string,
//     beacon: { epoch, ... } | null,
//     funding_txid: string | null,
//     created: number,        // Date.now() at create
//     funded_at: number | null,
//     released_at: number | null,
//   }

const KASFREEZE_SESSIONS_KEY = 'kasFreezeSessions';

function kfsList() {
    try { return JSON.parse(localStorage.getItem(KASFREEZE_SESSIONS_KEY) || '[]'); }
    catch (_) { return []; }
}

function kfsSave(sessions) {
    try { localStorage.setItem(KASFREEZE_SESSIONS_KEY, JSON.stringify(sessions)); }
    catch (_) {}
}

function kfsAdd(session) {
    const sessions = kfsList();
    if (sessions.find(s => s.address === session.address)) return; // dedupe
    sessions.push(session);
    kfsSave(sessions);
}

function kfsUpdate(address, patch) {
    const sessions = kfsList();
    const i = sessions.findIndex(s => s.address === address);
    if (i < 0) return false;
    sessions[i] = Object.assign({}, sessions[i], patch);
    kfsSave(sessions);
    return true;
}

function kfsRemove(address) {
    const sessions = kfsList().filter(s => s.address !== address);
    kfsSave(sessions);
    // Also strip any matching vault entries so Phase 1 doesn't keep
    // retrying a release the user explicitly deleted.
    try {
        const vault = JSON.parse(localStorage.getItem('kasFreezeVault') || '[]');
        const filtered = vault.filter(e => e.covenant_address !== address);
        localStorage.setItem('kasFreezeVault', JSON.stringify(filtered));
    } catch (_) {}
}

// One-time migration: if a legacy singleton kasFreezeState exists and
// it's not already represented in the sessions list, fold it in so the
// user doesn't lose visibility of in-progress freezes from before the
// hub redesign.
(function migrateLegacyKasFreezeState() {
    if (!kasFreezeState || !kasFreezeState.address) return;
    const sessions = kfsList();
    if (sessions.find(s => s.address === kasFreezeState.address)) return;
    sessions.push({
        id: 'legacy-' + Date.now(),
        stage: 'created', // best-effort guess; user can resume to verify
        address: kasFreezeState.address,
        redeem_script_hex: kasFreezeState.redeem_script_hex,
        owner_pubkey_hex: kasFreezeState.owner_pubkey_hex,
        heir_address: kasFreezeState.heir_address,
        heir_display: kasFreezeState.heir_display || kasFreezeState.heir_address,
        locktime_daa: kasFreezeState.locktime_daa,
        date_display: kasFreezeState.date_display || ('DAA ' + kasFreezeState.locktime_daa),
        beacon: kasFreezeState.beacon || null,
        funding_txid: null,
        created: Date.now(),
        funded_at: null,
        released_at: null,
    });
    kfsSave(sessions);
})();

// Render the hub: active sessions list + (handled by HTML) Create button

// Resume a session: restore kasFreezeState from the entry, route to the
// right sub-screen based on stage.


// Hub Create button: clean any stale state, route to the fields panel



// Path A: standard covenant deposit with encrypted recovery payload

// Path C: two TXs (pure UTXO relay)
// TX1: tag + owner chunks. After broadcast, capture tx_id, build TX2.

// Global callback for Path C post-broadcast hook
let _kasFreezePathCPostBroadcast = null;


// Heir-sweep flow when triggered from the active-list result panel.
// Builds a ready-to-broadcast frozen TX (ELSE branch, no signature) using
// the heir_address persisted in the active covenants entry, then broadcasts.
// Refuses to broadcast before locktime: the node would reject it anyway, and
// telling the user up front is a better UX than a cryptic mempool error.

// ─── Active Covenants List ───

let activeCovenants = [];

function covLoadActive() {
    try {
        // Prefer sessionStorage (survives reload), fall back to localStorage (survives tab close)
        let saved = sessionStorage.getItem('activeCovenants');
        if (!saved) saved = localStorage.getItem('activeCovenants');
        if (saved) activeCovenants = JSON.parse(saved);
    } catch (_) {}
    covRenderActive();
}

function covSaveActive() {
    try { sessionStorage.setItem('activeCovenants', JSON.stringify(activeCovenants)); } catch (_) {}
    try { localStorage.setItem('activeCovenants', JSON.stringify(activeCovenants)); } catch (_) {}
}

function covAddActive(type, result) {
    // Friendly type names
    const names = {
        'timelocked-savings': 'Savings', 'global-spending-limit': 'GLimit',
        'global-allowance': 'GAllow',
        'vesting': 'Vest', 'additive': 'Piggy',
        'escrow': 'D.Channel', 'timelocked-escrow': 'T-Escrow', 'oracle': 'Oracle',
        'atomic-swap': 'HTLC', 'payjoin': 'PayJoin', 'treasury': 'Treasury',
        'merkle-whitelist': 'Merkle',
        'commit-reveal': 'C-R', 'crowdfund': 'Crowdfund',
        'adaptor-swap': 'Private',
        'dms': 'DMS'
    };
    const entry = {
        type: type,
        label: names[type] || type,
        address: result.address,
        redeem_script_hex: result.redeem_script_hex,
        locktime_daa: result.locktime_daa || null,
        loaded: result.loaded || false,
        created: Date.now()
    };
    // Persist heir_address for kasfreeze so the active-list heir sweep can reach it
    if (result.heir_address) entry.heir_address = result.heir_address;
    // Persist oracle-specific fields for invite QR generation and claim flow
    if (result.oracle_pubkey_hex) entry.oracle_pubkey_hex = result.oracle_pubkey_hex;
    if (result.beneficiary_pubkey_hex) entry.beneficiary_pubkey_hex = result.beneficiary_pubkey_hex;
    if (result.owner_pubkey_hex) entry.owner_pubkey_hex = result.owner_pubkey_hex;
    if (result.locktime_date_iso) entry.locktime_date_iso = result.locktime_date_iso;
    // Persist crowdfund-specific fields so loading from list shows correct UI
    if (result.crowdfund_role) entry.crowdfund_role = result.crowdfund_role;
    if (result.campaign_name) entry.campaign_name = result.campaign_name;
    if (result.goal_kas) entry.goal_kas = result.goal_kas;
    if (result.campaign_id) entry.campaign_id = result.campaign_id;
    if (result.organizer_pk) entry.organizer_pk = result.organizer_pk;
    if (result.vk_hash) entry.vk_hash = result.vk_hash;
    if (result.goal_sompi) entry.goal_sompi = result.goal_sompi;
    // Persist adaptor swap fields
    if (result.counterparty_pk) entry.counterparty_pk = result.counterparty_pk;
    if (result.adaptor_point) entry.adaptor_point = result.adaptor_point;
    // Persist spending-limit max withdrawal and cooldown
    if (result.max_withdraw_sompi) entry.max_withdraw_sompi = result.max_withdraw_sompi;
    if (result.cooldown_daa) entry.cooldown_daa = result.cooldown_daa;
    // Persist allowance start date
    if (result.start_daa) entry.start_daa = result.start_daa;
    if (result.start_date_iso) entry.start_date_iso = result.start_date_iso;
    // Persist the thread covenant id (G) once known so reloads pick the thread by exact match
    if (result.covenant_id_hex && !/^0+$/.test(result.covenant_id_hex)) entry.covenant_id_hex = result.covenant_id_hex;
    // Persist DMS heir pubkey
    if (result.heir_pubkey_hex) entry.heir_pubkey_hex = result.heir_pubkey_hex;
    // Persist additive/piggy fields
    if (result.threshold_sompi) entry.threshold_sompi = result.threshold_sompi;
    if (result.deadline_daa) entry.deadline_daa = result.deadline_daa;
    if (result.deadline_date_iso) entry.deadline_date_iso = result.deadline_date_iso;
    // Persist merkle-whitelist fields
    if (result.merkle_root) entry.merkle_root = result.merkle_root;
    if (result.merkle_depth !== undefined) entry.merkle_depth = result.merkle_depth;
    if (result.merkle_addresses_json) entry.merkle_addresses_json = result.merkle_addresses_json;
    // Persist role (owner vs beneficiary) for correct button visibility
    if (result.role) entry.role = result.role;
    // Persist DMS CSV inactivity period
    if (result.inactivity_daa) entry.inactivity_daa = result.inactivity_daa;
    // Persist commit-reveal fields
    if (result.commit_hash) entry.commit_hash = result.commit_hash;
    if (result.cr_ciphertext_hex) entry.cr_ciphertext_hex = result.cr_ciphertext_hex;
    // Avoid duplicates by address
    activeCovenants = activeCovenants.filter(c => c.address !== entry.address);
    activeCovenants.unshift(entry);
    covSaveActive();
    covRenderActive();
}

function covRenderActive() {
    const list = el('cov-active-list');
    const items = el('cov-active-items');
    const count = el('cov-active-count');
    if (!list || !items || !count) return;
    if (activeCovenants.length === 0) {
        list.classList.add('hidden');
        return;
    }
    list.classList.remove('hidden');
    count.textContent = activeCovenants.length;
    items.innerHTML = '';
    for (let idx = 0; idx < activeCovenants.length; idx++) {
        const c = activeCovenants[idx];
        const div = document.createElement('div');
        div.className = 'cov-active-item';
        if (c._empty) div.style.opacity = '0.45';
        const shortAddr = c.address.length > 24
            ? c.address.substring(0, 16) + '...' + c.address.substring(c.address.length - 6)
            : c.address;
        // Show campaign name for crowdfund, or locktime hint for timed covenants
        let subtitle = shortAddr;
        if (c.type === 'crowdfund' && c.campaign_name) {
            subtitle = c.campaign_name + (c.crowdfund_role === 'contributor' ? ' (contrib)' : ' (org)');
        }
        div.innerHTML =
            '<span class="cov-type-badge">' + c.label + '</span>' +
            '<span class="cov-addr">' + subtitle + '</span>' +
            '<span class="cov-bal" data-cov-bal-idx="' + idx + '">' + (c._balText || '...') + '</span>' +
            '<span class="cov-export" data-cov-export-idx="' + idx + '" title="Export backup" style="cursor:pointer;font-size:11px;color:#4ecdc4;background:rgba(78,205,196,0.12);border:1px solid rgba(78,205,196,0.3);border-radius:6px;padding:4px 7px;margin-left:4px;line-height:1">&#x21E9;</span>' +
            '<span class="cov-del" data-cov-del-idx="' + idx + '" title="Remove" style="cursor:pointer;font-size:11px;color:#ff4d4d;background:rgba(255,77,77,0.12);border:1px solid rgba(255,77,77,0.3);border-radius:6px;padding:4px 7px;margin-left:4px;line-height:1">&#x2715;</span>';
        div.addEventListener('click', function(e) {
            // Ignore if trash or export icon was clicked
            if (e.target.classList.contains('cov-del') || e.target.classList.contains('cov-export')) return;
            lastCovenantResult = {
                address: c.address,
                redeem_script_hex: c.redeem_script_hex,
                locktime_daa: c.locktime_daa,
                type: c.type,
                loaded: c.loaded || false
            };
            if (c.heir_address) lastCovenantResult.heir_address = c.heir_address;
            if (c.oracle_pubkey_hex) lastCovenantResult.oracle_pubkey_hex = c.oracle_pubkey_hex;
            if (c.beneficiary_pubkey_hex) lastCovenantResult.beneficiary_pubkey_hex = c.beneficiary_pubkey_hex;
            if (c.owner_pubkey_hex) lastCovenantResult.owner_pubkey_hex = c.owner_pubkey_hex;
            if (c.locktime_date_iso) lastCovenantResult.locktime_date_iso = c.locktime_date_iso;
            // Restore crowdfund metadata
            if (c.crowdfund_role) lastCovenantResult.crowdfund_role = c.crowdfund_role;
            if (c.campaign_name) lastCovenantResult.campaign_name = c.campaign_name;
            if (c.goal_kas) lastCovenantResult.goal_kas = c.goal_kas;
            if (c.campaign_id) lastCovenantResult.campaign_id = c.campaign_id;
            if (c.organizer_pk) lastCovenantResult.organizer_pk = c.organizer_pk;
            if (c.vk_hash) lastCovenantResult.vk_hash = c.vk_hash;
            if (c.goal_sompi) lastCovenantResult.goal_sompi = c.goal_sompi;
            // Restore adaptor swap metadata
            if (c.counterparty_pk) lastCovenantResult.counterparty_pk = c.counterparty_pk;
            if (c.adaptor_point) lastCovenantResult.adaptor_point = c.adaptor_point;
            // Restore role
            if (c.role) lastCovenantResult.role = c.role;
            // Restore escrow dispute flag
            if (c._escrowDisputed) lastCovenantResult._escrowDisputed = true;
            // Restore DMS CSV inactivity period
            if (c.inactivity_daa) lastCovenantResult.inactivity_daa = c.inactivity_daa;
            if (c.cooldown_daa) lastCovenantResult.cooldown_daa = c.cooldown_daa;
            if (c.max_withdraw_sompi) lastCovenantResult.max_withdraw_sompi = c.max_withdraw_sompi;
            if (c.start_daa) lastCovenantResult.start_daa = c.start_daa;
            if (c.start_date_iso) lastCovenantResult.start_date_iso = c.start_date_iso;
            if (c.covenant_id_hex) lastCovenantResult.covenant_id_hex = c.covenant_id_hex;
            // Restore additive/piggy fields
            if (c.threshold_sompi) lastCovenantResult.threshold_sompi = c.threshold_sompi;
            if (c.deadline_daa) lastCovenantResult.deadline_daa = c.deadline_daa;
            if (c.deadline_date_iso) lastCovenantResult.deadline_date_iso = c.deadline_date_iso;
            // Restore merkle-whitelist fields
            if (c.merkle_root) lastCovenantResult.merkle_root = c.merkle_root;
            if (c.merkle_depth !== undefined) lastCovenantResult.merkle_depth = c.merkle_depth;
            if (c.merkle_addresses_json) lastCovenantResult.merkle_addresses_json = c.merkle_addresses_json;
            // Restore commit-reveal fields
            if (c.commit_hash) lastCovenantResult.commit_hash = c.commit_hash;
            if (c.cr_ciphertext_hex) lastCovenantResult.cr_ciphertext_hex = c.cr_ciphertext_hex;
            // Ensure allowance params are available (parse from script if missing)
            ensureAllowanceParams(lastCovenantResult);
            ensureAllowanceParams(c);
            ensurePiggyParams(lastCovenantResult);
            ensurePiggyParams(c);
            // Escrow: re-detect role from script pubkeys vs loaded wallet
            if (c.type === 'escrow') {
                ensureEscrowParams(lastCovenantResult);
                ensureEscrowParams(c);
                const myAcctPk = getAccountPubkeyHex() || '';
                const myDerivedPk = getOwnerPubkeyHex() || '';
                // console.log('[KasSee] Escrow role detect: acct=' + myAcctPk.substring(0,16) + '... derived=' + myDerivedPk.substring(0,16) + '... alice=' + (lastCovenantResult.alice_pk||'').substring(0,16) + '... bob=' + (lastCovenantResult.bob_pk||'').substring(0,16) + '... arbiter=' + (lastCovenantResult.arbiter_pk||'').substring(0,16) + '...');
                const matchesPk = (target) => walletMatchesPk(target);
                if (matchesPk(lastCovenantResult.alice_pk)) {
                    lastCovenantResult.role = 'owner'; c.role = 'owner';
                } else if (matchesPk(lastCovenantResult.bob_pk)) {
                    lastCovenantResult.role = 'beneficiary'; c.role = 'beneficiary';
                } else if (matchesPk(lastCovenantResult.arbiter_pk)) {
                    lastCovenantResult.role = 'arbiter'; c.role = 'arbiter';
                } else {
                    console.log('[KasSee] Escrow role: NO MATCH, keeping role=' + (lastCovenantResult.role || 'none'));
                }
                covSaveActive();
            }
            // Oracle: re-detect role from pubkeys vs loaded wallet
            if (c.type === 'oracle' && c.oracle_pubkey_hex) {
                const myAcctPk = getAccountPubkeyHex() || '';
                const myAddrPk = getOwnerPubkeyHex() || '';
                const matchesPkO = (target) => walletMatchesPk(target);
                if (matchesPkO(c.oracle_pubkey_hex)) {
                    lastCovenantResult.role = 'oracle'; c.role = 'oracle';
                } else if (matchesPkO(c.beneficiary_pubkey_hex)) {
                    lastCovenantResult.role = 'beneficiary'; c.role = 'beneficiary';
                } else if (matchesPkO(c.owner_pubkey_hex)) {
                    lastCovenantResult.role = 'owner'; c.role = 'owner';
                }
                covSaveActive();
            }
            try { sessionStorage.setItem('lastCovenantResult', JSON.stringify(lastCovenantResult)); } catch (_) {}
            // Private Swap: open the rich adaptor-result panel directly and make its
            // Back return to this main screen. Falls through to the generic result
            // panel only when live swap state can't be matched to this entry (cold
            // reload, or a second concurrent swap), where Owner Refund still works.
            if (c.type === 'adaptor-swap') {
                adaptorStateLoad();
                if (_adaptorState && _adaptorState.myAddr === c.address) {
                    _adaptorResultReturn = 'menu';
                    covShowPanel('adaptor-result');
                    return;
                }
            }
            covShowPanel('result');
            covUpdateResultButtons(c.type);
            el('cov-result-addr').textContent = c.address;
            el('cov-result-script').textContent = c.redeem_script_hex;
            covRenderMetaLine(c);
            el('cov-result-balance').textContent = 'Loading...';
            el('cov-result-balance').style.display = '';
            toast('Loaded: ' + c.label + ' covenant', 'ok', 1500);
            // Auto-fetch balance
            setTimeout(() => { if (el('btn-cov-res-balance')) el('btn-cov-res-balance').click(); }, 300);
        });
        items.appendChild(div);
    }
    // Wire delete buttons
    items.querySelectorAll('.cov-del').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const i = parseInt(this.dataset.covDelIdx);
            const c = activeCovenants[i];
            if (!confirm('Remove ' + c.label + ' covenant?\n' + c.address.substring(0, 24) + '...')) return;
            activeCovenants.splice(i, 1);
            covSaveActive();
            covRenderActive();
        });
    });
    // Export handler: show QR or download encrypted backup for a single covenant
    items.querySelectorAll('.cov-export').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const i = parseInt(this.dataset.covExportIdx);
            covExportSingle(i);
        });
    });
    // Fetch balances in background
    covFetchBalances();
}

async function covFetchBalances() {
    let wsUrl;
    // Retry up to 3 times with short delays if node isn't ready
    for (let attempt = 0; attempt < 3; attempt++) {
        try { wsUrl = await resolveNodeUrl(); break; } catch (_) {
            await new Promise(r => setTimeout(r, 1000));
        }
    }
    if (!wsUrl) return;
    for (let i = 0; i < activeCovenants.length; i++) {
        const c = activeCovenants[i];
        try {
            const utxosJson = await fetch_utxos_for_address_js(c.address, wsUrl);
            const utxos = JSON.parse(utxosJson);
            const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
            const kas = Number(total) / 1e8;
            const kasStr = kas === 0 ? '0' : kas.toFixed(8).replace(/\.?0+$/, '');
            c._balText = kasStr + ' KAS';
            c._empty = (utxos.length === 0);
        } catch (_) {
            c._balText = '?';
            c._empty = false;
        }
        // Update the DOM element directly
        const balEl = document.querySelector('[data-cov-bal-idx="' + i + '"]');
        if (balEl) {
            balEl.textContent = c._balText;
            const row = balEl.closest('.cov-active-item');
            if (row) row.style.opacity = c._empty ? '0.45' : '';
        }
    }
}

// Auto-refresh the active-list balances while the cov++ landing (menu) is
// shown, so a spend/claim by another party (e.g. a beneficiary claim) updates
// the owner's list without a manual refresh. Started by covShowPanel on the
// 'menu' panel, stopped on every other panel transition. The tick self-stops
// if the user leaves the covenant screen entirely (covShowPanel won't fire in
// that case), so it never polls in the background.
function covActiveWatcherStart() {
    if (_covActiveWatcherTimer) return;
    if (!activeCovenants.length) return;
    _covActiveWatcherTimer = setInterval(() => {
        const onMenu = currentScreenName === 'covenant'
            && el('cov-menu') && !el('cov-menu').classList.contains('hidden');
        if (!onMenu || !activeCovenants.length) { covActiveWatcherStop(); return; }
        covFetchBalances();
    }, 5000);
}

function covActiveWatcherStop() {
    if (_covActiveWatcherTimer) {
        clearInterval(_covActiveWatcherTimer);
        _covActiveWatcherTimer = null;
    }
}

// ─── Covenant Export (single entry) ───
// Owner: encrypts reconstruction data with chain-code key (COVB format).
// Beneficiary: exports plaintext invite JSON (address + redeem script).
// Detection: if owner's /0/0 pubkey appears in the redeem script, user is owner.

async function covExportSingle(idx) {
    const c = activeCovenants[idx];
    if (!c) { toast('Covenant not found', 'error'); return; }
    if (!walletData) { toast('Load wallet first', 'error'); return; }

    // Detect owner vs beneficiary:
    // If role is set, use it. Otherwise fall back to loaded flag for legacy entries.
    const isOwner = c.role ? c.role === 'owner' : !c.loaded;

    if (!isOwner) {
        // Beneficiary export: plaintext invite JSON (same format as Share button)
        const invite = {
            v: 1, t: 'cov-invite', ct: c.type || '',
            addr: c.address || '',
            rs: c.redeem_script_hex || '',
            d: c.locktime_daa ? Number(c.locktime_daa) : 0
        };
        if (c.type === 'dms' && c.inactivity_daa) invite.id = Number(c.inactivity_daa);
        if (c.oracle_pubkey_hex) invite.opk = c.oracle_pubkey_hex;
        if (c.campaign_name) invite.name = c.campaign_name;
        if (c.goal_kas) invite.goal = c.goal_kas;
        if (c.organizer_pk) invite.opk = c.organizer_pk;
        // Allowance: include max withdrawal and cooldown
        if (c.type === 'global-allowance') {
            if (c.max_withdraw_sompi) invite.mw = String(c.max_withdraw_sompi);
            if (c.cooldown_daa) invite.cd = Number(c.cooldown_daa);
            if (c.start_daa) invite.sd = Number(c.start_daa);
            if (c.start_date_iso) invite.sdi = c.start_date_iso;
        }
        // Oracle: carry both counterparty pubkeys so a re-imported self-backup
        // round-trips through the COVI oracle branch (which gates on bpk+own) and
        // restores the role and bene/owner keys, matching the Share-invite QR.
        if (c.type === 'oracle') {
            if (c.beneficiary_pubkey_hex) invite.bpk = c.beneficiary_pubkey_hex;
            if (c.owner_pubkey_hex) invite.own = c.owner_pubkey_hex;
        }
        // Timelocked types: carry the absolute unlock date so a re-imported file shows
        // the exact date instead of re-estimating from DAA (which drifts each reload).
        if (c.locktime_date_iso) invite.ldi = c.locktime_date_iso;
        // Savings: the two signer pubkeys for role detection on the receiving side.
        if (c.wallet1_pubkey_hex) invite.w1 = c.wallet1_pubkey_hex;
        if (c.wallet2_pubkey_hex) invite.w2 = c.wallet2_pubkey_hex;
        const inviteJson = JSON.stringify(invite);
        const inviteJsonBytes = new TextEncoder().encode(inviteJson);
        // Wrap with COVI header so KasSigner recognizes and stores it
        const coviHeader = new TextEncoder().encode('COVI');
        const inviteBytes = new Uint8Array(4 + inviteJsonBytes.length);
        inviteBytes.set(coviHeader, 0);
        inviteBytes.set(inviteJsonBytes, 4);
        const inviteHex = bytesToHex(inviteBytes);
        console.log('[KasSee] COVI export: idx=' + idx + ', type=' + c.type + ', addr=' + (c.address || '').substring(0, 30) + '..., invite_len=' + inviteJson.length);
        covShowExportModal(c, inviteHex, inviteBytes, false);
        return;
    }

    // Owner export: encrypted COVB
    try {
        // Build the covenant result object for params serialization
        const covResult = {
            type: c.type,
            address: c.address,
            redeem_script_hex: c.redeem_script_hex,
            locktime_daa: c.locktime_daa,
            inactivity_daa: c.inactivity_daa,
            heir_address: c.heir_address,
            heir_pubkey_hex: c.heir_pubkey_hex,
            beneficiary_pubkey_hex: c.beneficiary_pubkey_hex,
            oracle_pubkey_hex: c.oracle_pubkey_hex,
            owner_pubkey_hex: c.owner_pubkey_hex,
            organizer_pk: c.organizer_pk,
            vk_hash: c.vk_hash,
            campaign_id: c.campaign_id,
            campaign_name: c.campaign_name,
            goal_kas: c.goal_kas,
            goal_sompi: c.goal_sompi,
            crowdfund_role: c.crowdfund_role,
            counterparty_pk: c.counterparty_pk,
            adaptor_point: c.adaptor_point,
            threshold_sompi: c.threshold_sompi,
            deadline_daa: c.deadline_daa,
            merkle_root: c.merkle_root,
            merkle_depth: c.merkle_depth,
            merkle_addresses_json: c.merkle_addresses_json,
            max_withdraw_sompi: c.max_withdraw_sompi,
            cooldown_daa: c.cooldown_daa,
            start_daa: c.start_daa,
            commit_hash: c.commit_hash,
            cr_ciphertext_hex: c.cr_ciphertext_hex,
            // Time-Locked Savings: the two signer pubkeys (for role detection on
            // restore) and the absolute unlock date (so a restored backup shows the
            // exact date instead of re-estimating it from DAA, which drifts).
            wallet1_pubkey_hex: c.wallet1_pubkey_hex,
            wallet2_pubkey_hex: c.wallet2_pubkey_hex,
            locktime_date_iso: c.locktime_date_iso,
        };

        const covType = c.type || 'unknown';
        const typeByte = COV_TYPE[covType] || 0xFF;
        const paramsHex = buildCovenantParamsHex(covResult);
        const plaintextHex = build_covenant_payload(typeByte, paramsHex);
        const plaintext = hexToBytes(plaintextHex);

        // Encrypt with AES-256-GCM
        const wallet = JSON.parse(walletData);
        const keyHex = derive_covenant_payload_key(wallet.kpub);
        const keyBytes = hexToBytes(keyHex);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes.buffer, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const nonce = new Uint8Array(12);
        crypto.getRandomValues(nonce);
        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey, plaintext.buffer
        );
        const cipher = new Uint8Array(cipherBuf);

        // Wire format: "COVB" (4 bytes) + nonce(12) + ciphertext_with_tag(N+16)
        const header = new TextEncoder().encode('COVB');
        const blob = new Uint8Array(4 + 12 + cipher.length);
        blob.set(header, 0);
        blob.set(nonce, 4);
        blob.set(cipher, 16);
        const blobHex = bytesToHex(blob);

        console.log('[KasSee] Covenant export: ' + blob.length + ' bytes, type: ' + covType);

        // Show export options modal
        covShowExportModal(c, blobHex, blob, true);
    } catch (e) {
        toast('Export failed: ' + e.message, 'error');
        console.error('[KasSee] Export error:', e);
    }
}

function covShowExportModal(cov, blobHex, blobBytes, isEncrypted) {
    // isEncrypted: true = owner COVB (encrypted), false/undefined = beneficiary invite (plaintext)
    const encrypted = isEncrypted !== false;
    // Remove existing modal if any
    const old = document.getElementById('cov-export-modal');
    if (old) old.remove();

    const shortAddr = cov.address.length > 30
        ? cov.address.substring(0, 18) + '...' + cov.address.substring(cov.address.length - 6)
        : cov.address;

    const roleLabel = encrypted ? 'Owner Backup' : 'Beneficiary Backup';
    const sizeLabel = encrypted
        ? blobBytes.length + ' bytes encrypted'
        : blobBytes.length + ' bytes (invite)';
    const qrLabel = '&#x1F4F1; Show QR for KasSigner';
    const fileExt = encrypted ? '.covb' : '.cov';
    const fileLabel = '&#x1F4BE; Download ' + fileExt + ' file';

    const modal = document.createElement('div');
    modal.id = 'cov-export-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
    modal.innerHTML =
        '<div style="background:#1a2332;border:1px solid rgba(78,205,196,0.3);border-radius:16px;padding:24px;max-width:400px;width:100%;text-align:center">' +
            '<div style="font-size:14px;color:#8892a4;margin-bottom:4px">' + (cov.label || cov.type) + ' &mdash; ' + roleLabel + '</div>' +
            '<div style="font-size:11px;color:#556;margin-bottom:16px;word-break:break-all">' + shortAddr + '</div>' +
            '<div style="font-size:12px;color:#4ecdc4;margin-bottom:20px">' + sizeLabel + '</div>' +
            '<div id="cov-export-qr-area" style="margin-bottom:16px"></div>' +
            '<button id="btn-cov-export-qr" style="width:100%;padding:12px;margin-bottom:8px;background:transparent;border:1px solid rgba(78,205,196,0.5);border-radius:10px;color:#4ecdc4;font-size:13px;cursor:pointer">' +
                qrLabel +
            '</button>' +
            '<button id="btn-cov-export-file" style="width:100%;padding:12px;margin-bottom:8px;background:transparent;border:1px solid rgba(78,205,196,0.5);border-radius:10px;color:#4ecdc4;font-size:13px;cursor:pointer">' +
                fileLabel +
            '</button>' +
            '<button id="btn-cov-export-close" style="width:100%;padding:12px;background:transparent;border:1px solid rgba(255,255,255,0.15);border-radius:10px;color:#8892a4;font-size:13px;cursor:pointer">' +
                'Close' +
            '</button>' +
        '</div>';

    document.body.appendChild(modal);

    // QR button
    document.getElementById('btn-cov-export-qr').addEventListener('click', function() {
        const useMultiFrame = blobHex.length > 268; // 268 hex chars = 134 bytes = V6 max on firmware
        if (!useMultiFrame) {
            try {
                const svg = generate_qr_svg_text(blobHex);
                const area = document.getElementById('cov-export-qr-area');
                area.innerHTML = '<div style="background:#fff;border-radius:8px;padding:8px;display:inline-block;width:220px;height:220px">' + svg + '</div>' +
                    '<div style="font-size:10px;color:#556;margin-top:6px">Scan with KasSigner to store on SD</div>';
                this.style.display = 'none';
            } catch (e) {
                toast('QR generation failed: ' + e.message, 'error');
            }
        } else {
            // Multi-frame for large data (COVI invites, etc.)
            try {
                const frames = JSON.parse(generate_qr_frames(blobHex));
                const area = document.getElementById('cov-export-qr-area');
                let frameIdx = 0;
                let playing = true;
                function renderFrame() {
                    area.innerHTML = '<div style="background:#fff;border-radius:8px;padding:8px;display:inline-block;width:220px;height:220px">' + frames[frameIdx].svg + '</div>' +
                        '<div style="font-size:10px;color:#556;margin-top:6px">Frame ' + (frameIdx + 1) + '/' + frames.length + '</div>' +
                        '<div style="display:flex;justify-content:center;gap:12px;margin-top:8px">' +
                            '<button id="cov-qr-prev" style="background:transparent;border:1px solid rgba(78,205,196,0.4);border-radius:6px;color:#4ecdc4;padding:6px 14px;cursor:pointer;font-size:16px">\u25C0\u25C0</button>' +
                            '<button id="cov-qr-play" style="background:transparent;border:1px solid rgba(78,205,196,0.4);border-radius:6px;color:#4ecdc4;padding:6px 14px;cursor:pointer;font-size:14px">' + (playing ? '\u23F8' : '\u25B6') + '</button>' +
                            '<button id="cov-qr-next" style="background:transparent;border:1px solid rgba(78,205,196,0.4);border-radius:6px;color:#4ecdc4;padding:6px 14px;cursor:pointer;font-size:16px">\u25B6\u25B6</button>' +
                        '</div>';
                    document.getElementById('cov-qr-prev').onclick = () => { frameIdx = (frameIdx - 1 + frames.length) % frames.length; renderFrame(); };
                    document.getElementById('cov-qr-next').onclick = () => { frameIdx = (frameIdx + 1) % frames.length; renderFrame(); };
                    document.getElementById('cov-qr-play').onclick = () => { playing = !playing; renderFrame(); };
                }
                function autoAdvance() {
                    if (playing) { frameIdx = (frameIdx + 1) % frames.length; renderFrame(); }
                }
                renderFrame();
                const timer = setInterval(autoAdvance, qrFrameMs);
                modal._qrTimer = timer;
                this.style.display = 'none';
            } catch (e2) {
                toast('QR generation failed: ' + e2.message, 'error');
            }
        }
    });

    // File download button
    document.getElementById('btn-cov-export-file').addEventListener('click', function() {
        const fileBlob = new Blob([blobBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(fileBlob);
        const a = document.createElement('a');
        const typeName = (cov.type || 'covenant').replace(/[^a-z0-9-]/g, '');
        a.href = url;
        a.download = 'cov-' + typeName + '-' + cov.address.substring(cov.address.length - 8) + fileExt;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast('Saved ' + a.download, 'ok', 2000);
    });

    // Close button
    document.getElementById('btn-cov-export-close').addEventListener('click', function() {
        if (modal._qrTimer) clearInterval(modal._qrTimer);
        modal.remove();
    });

    // Click outside to close
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            if (modal._qrTimer) clearInterval(modal._qrTimer);
            modal.remove();
        }
    });
}

// ─── Covenant Import from KasSigner ───
// Handles COVB QR scanned from KasSigner's restore screen.
// The QR contains hex-encoded COVB blob (possibly multi-frame).
// Format: hex of [COVB header:4][nonce:12][ciphertext+tag:N+16]

// Multi-frame COVB accumulator
let _covbFrames = null; // { total, received: Set, bufs: [] }
let _covbImporting = false; // guard against re-entry during async import

async function handleCovbScan(data) {
    if (_covbImporting) return;
    _covbImporting = true; // set immediately before any async work
    let raw;
    if (data instanceof Uint8Array) {
        raw = data;
    } else if (typeof data === 'string') {
        raw = new TextEncoder().encode(data);
    } else if (data && data.data) {
        raw = new Uint8Array(data.data);
    } else {
        toast('Unrecognized QR data', 'error');
        return;
    }

    console.log('[KasSee] COVB scan: ' + raw.length + ' bytes, first4: ' +
        String.fromCharCode(raw[0] || 0, raw[1] || 0, raw[2] || 0, raw[3] || 0));

    // Check for raw binary COVB/COVI header (from KasSigner restore QR, no hex encoding)
    const hdr = String.fromCharCode(raw[0] || 0, raw[1] || 0, raw[2] || 0, raw[3] || 0);
    if (hdr === 'COVB' || hdr === 'COVI') {
        stopScanner();
        const payloadBytes = raw.slice(4);
        const payloadHex = bytesToHex(payloadBytes);
        const headerHex = bytesToHex(raw.slice(0, 4));
        // Debug: decode COVI payload to show type and address
        if (hdr === 'COVI') {
            try {
                const jsonStr = new TextDecoder().decode(payloadBytes);
                const inv = JSON.parse(jsonStr);
                console.log('[KasSee] COVI import: type=' + (inv.ct || '?') + ', addr=' + (inv.addr || '').substring(0, 30) + '...');
            } catch (_) { console.log('[KasSee] COVI import: could not decode JSON'); }
        }
        await processCovbHex(headerHex + payloadHex);
        return;
    }

    // Check for hex-encoded COVB/COVI (from KasSee export QR)
    const hex = bytesToHex(raw);
    if (hex.startsWith('434f5642') || hex.startsWith('434f5649')) {
        stopScanner();
        // Debug: decode COVI if hex-encoded
        if (hex.startsWith('434f5649')) {
            try {
                const jsonHex2 = hex.substring(8);
                const jsonBytes2 = hexToBytes(jsonHex2);
                const jsonStr2 = new TextDecoder().decode(jsonBytes2);
                const inv2 = JSON.parse(jsonStr2);
                console.log('[KasSee] COVI import (hex): type=' + (inv2.ct || '?') + ', addr=' + (inv2.addr || '').substring(0, 30) + '...');
            } catch (_) { console.log('[KasSee] COVI import (hex): could not decode'); }
        }
        await processCovbHex(hex);
        return;
    }

    // Check for multi-frame fragment: [idx][total][frag_len][payload]
    if (raw.length >= 4 && raw[1] >= 2 && raw[2] > 0 && raw[2] + 3 <= raw.length) {
        const frameIdx = raw[0];
        const totalFrames = raw[1];
        const fragLen = raw[2];
        const payload = raw.slice(3, 3 + fragLen);

        if (!_covbFrames || _covbFrames.total !== totalFrames) {
            _covbFrames = { total: totalFrames, received: new Set(), bufs: new Array(totalFrames) };
        }
        if (!_covbFrames.received.has(frameIdx)) {
            _covbFrames.received.add(frameIdx);
            _covbFrames.bufs[frameIdx] = payload;
            console.log('[KasSee] COVB frame ' + (frameIdx + 1) + '/' + totalFrames + ' (' + fragLen + 'B)');
        }
        if (_covbFrames.received.size < totalFrames) { _covbImporting = false; return; }

        let totalLen = 0;
        for (let i = 0; i < totalFrames; i++) totalLen += _covbFrames.bufs[i].length;
        const assembled = new Uint8Array(totalLen);
        let off = 0;
        for (let i = 0; i < totalFrames; i++) {
            assembled.set(_covbFrames.bufs[i], off);
            off += _covbFrames.bufs[i].length;
        }
        _covbFrames = null;

        // Assembled could be hex text or raw binary
        const asmHdr = String.fromCharCode(assembled[0] || 0, assembled[1] || 0, assembled[2] || 0, assembled[3] || 0);
        console.log('[KasSee] COVB assembled: ' + assembled.length + ' bytes, hdr: ' + asmHdr);
        stopScanner();
        if (asmHdr === 'COVB' || asmHdr === 'COVI') {
            const h = bytesToHex(assembled);
            await processCovbHex(h);
        } else {
            const asmHex = new TextDecoder().decode(assembled);
            await processCovbHex(asmHex);
        }
        return;
    }

    toast('Not a covenant backup QR', 'error');
    _covbImporting = false;
}

async function processCovbHex(hex) {
    const isCovb = hex.startsWith('434f5642') || hex.startsWith('434F5642');
    const isCovi = hex.startsWith('434f5649') || hex.startsWith('434F5649');

    if (!isCovb && !isCovi) {
        toast('Not a covenant backup QR', 'error');
        _covbImporting = false;
        return;
    }

    if (!walletData) { toast('Load wallet first', 'error'); _covbImporting = false; return; }

    if (isCovi) {
        // Beneficiary invite: strip COVI header (8 hex = 4 bytes), decode JSON
        try {
            const jsonHex = hex.substring(8);
            const jsonBytes = hexToBytes(jsonHex);
            const jsonStr = new TextDecoder().decode(jsonBytes);
            const invite = JSON.parse(jsonStr);
            if (invite.t === 'cov-invite' && invite.addr && invite.rs) {
                // Load as existing covenant
                const entry = {
                    type: invite.ct || 'unknown',
                    address: invite.addr,
                    redeem_script_hex: invite.rs,
                    locktime_daa: invite.d || 0,
                    loaded: true,
                    role: 'beneficiary',
                };
                // DMS: store inactivity period for watcher countdown
                if (invite.id) entry.inactivity_daa = invite.id;
                if (invite.opk) entry.oracle_pubkey_hex = invite.opk;
                // Oracle: carry the absolute refund date so the timeout shows the exact
                // time instead of re-estimating from DAA (which drifts on every reload).
                // Read it independently of bpk/own so an older backup that lacks the
                // counterparty pubkeys still stops drifting. The QR-invite path does
                // the same at the oracle-invite handler (oi.ldi).
                if (invite.ct === 'oracle' && invite.ldi) entry.locktime_date_iso = invite.ldi;
                // PayJoin: carry the absolute refund date so the timeout shows the exact
                // time instead of re-estimating from DAA (which drifts on every reload).
                if (invite.ct === 'payjoin' && invite.ldi) entry.locktime_date_iso = invite.ldi;
                // Oracle: auto-detect role by comparing wallet kpub against the three pubkeys
                if (invite.ct === 'oracle' && invite.bpk && invite.own) {
                    entry.beneficiary_pubkey_hex = invite.bpk;
                    entry.owner_pubkey_hex = invite.own;
                    const myAcctPk = getAccountPubkeyHex();
                    const myAddrPk = getOwnerPubkeyHex(); // /0/0 address-level
                    const matchOracle = walletMatchesPk(invite.opk);
                    const matchBene = walletMatchesPk(invite.bpk);
                    if (matchOracle) {
                        entry.role = 'oracle';
                    } else if (matchBene) {
                        entry.role = 'beneficiary';
                    } else {
                        entry.role = 'beneficiary'; // default fallback
                    }
                }
                if (invite.name) entry.campaign_name = invite.name;
                // Savings: carry the unlock date and both wallet pubkeys for display.
                if (invite.ct === 'timelocked-savings') {
                    if (invite.ldi) entry.locktime_date_iso = invite.ldi;
                    if (invite.w1) entry.wallet1_pubkey_hex = invite.w1;
                    if (invite.w2) entry.wallet2_pubkey_hex = invite.w2;
                }
                if (invite.goal) entry.goal_kas = invite.goal;
                // Allowance: max withdrawal and cooldown for beneficiary UX + watcher
                if (invite.mw) entry.max_withdraw_sompi = invite.mw;
                if (invite.cd) entry.cooldown_daa = invite.cd;
                if (invite.sd) entry.start_daa = invite.sd;
                if (invite.sdi) entry.start_date_iso = invite.sdi;
                // Parse allowance params from script if not in invite (old format)
                ensureAllowanceParams(entry);
                // Piggy bank: single-party, set owner role and parse params from script
                if (entry.type === 'additive') {
                    entry.role = 'owner';
                    ensurePiggyParams(entry);
                }
                // Escrow: detect role from script pubkeys vs loaded wallet
                if (entry.type === 'escrow') {
                    ensureEscrowParams(entry);
                    const myAcctPk = getAccountPubkeyHex() || '';
                    const myDerivedPk = getOwnerPubkeyHex() || '';
                    const matchesPk = (target) => walletMatchesPk(target);
                    if (matchesPk(entry.alice_pk)) {
                        entry.role = 'owner';
                    } else if (matchesPk(entry.bob_pk)) {
                        entry.role = 'beneficiary'; // seller
                    } else if (matchesPk(entry.arbiter_pk)) {
                        entry.role = 'arbiter';
                    } else {
                        entry.role = 'beneficiary'; // default if no match
                    }
                }
                // Check not already active
                if (!activeCovenants.some(c => c.address === entry.address)) {
                    covAddActive(entry.type, entry);
                    stopScanner();
                    showScreen('covenant');
                    covShowPanel('menu');
                    toast('Covenant invite restored', 'ok', 3000);
                    covSaveActive();
                    covRenderActive();
                } else {
                    stopScanner();
                    showScreen('covenant');
                    covShowPanel('menu');
                    toast('Covenant already active', 'ok', 2000);
                }
            } else {
                toast('Invalid invite format', 'error');
            }
        } catch (e) {
            toast('Import failed: ' + (e.message || e), 'error');
        }
        _covbImporting = false;
        return;
    }

    // COVB: encrypted owner backup
    const payloadHex = hex.substring(8); // strip COVB header

    if (!walletData) { toast('Load wallet first', 'error'); return; }

    try {
        const decrypted = await decryptCovenantPayload(payloadHex);
        if (!decrypted) {
            toast('Decrypt failed. wrong wallet?', 'error');
            _covbImporting = false;
            return;
        }

        const ownerPk = getAccountPubkeyHex();
        const rebuilt = await rebuildCovenant(decrypted, ownerPk, {});
        showScreen('covenant');
        covShowPanel('menu');
        if (rebuilt) {
            toast('Covenant restored', 'ok', 3000);
        } else {
            // rebuilt=false could mean already active or genuine failure
            toast('Covenant already active', 'ok', 2000);
        }
        covSaveActive();
        covRenderActive();
    } catch (e) {
        toast('Import failed: ' + (e.message || e), 'error');
        console.error('[KasSee] COVB import error:', e);
    }
    _covbImporting = false;
}

// ─── Multisig: load, then branch by scheme ───
//
// Loading is the ONLY way in. Both schemes need a descriptor and one address,
// and nothing reaches the spend form without them - which is what lets the
// spend form hide those two fields instead of showing what was just scanned.
//
// The address identifies the branch. A descriptor describes N branches, one per
// participant, and KasSee holds no seed, so it rebuilds candidates until one
// matches: every branch, both chains, indices 0-99. That search is LOCAL - it
// sends nothing. The network scan that follows queries only the branch it found,
// because naming other participants' addresses to a node is their exposure, not
// ours to spend.
// Where Back goes from the shared UTXOs screen. `let` at module scope, beside
// the other view state: declared inside the file it would sit AFTER the button
// wiring that reads it, and a `let` used before its declaration throws.
let utxosReturnScreen = 'dashboard';
/// True while a multisig branch is the ACTIVE wallet.
///
/// The shared tabs used to test `currentScreenName` against a list of multisig
/// screen names, which breaks the moment you switch tab to tab: from
/// `addresses` the name is not in the list, so the tab fell through to the
/// single-sig path and did nothing. Context is sticky, not positional.
let msActive = false;
/// Outpoints chosen in the picker: `[{address, tx_id, index, amount}]`.
///
/// Replaces the single source address for 45' sends. Each entry names an
/// outpoint, and the builder derives that address's own redeem script and
/// derivation path from it - which is what makes spending several addresses in
/// one transaction possible.
let msPicked = [];
const MS_PICK_MAX = 32;
/// Selection state for the multisig UTXOs view.
let msConsolidateSel = new Set();
let msConsolidateList = [];

/// Close the UTXO dropdown and clear the selection.
///
/// The panel is toggled open and nothing closed it, so returning to the send
/// screen showed it still open with the previous inputs ticked - inputs the
/// transaction just built may already spend. A stale selection is worse than
/// none: it would be priced and signed.
///
/// Called from the places a reset is WANTED, not from `showScreen`: consolidate
/// navigates to the send screen with a selection deliberately in hand, and a
/// blanket hook there would wipe it.
function resetMsUtxoSelection() {
    const ul = document.getElementById('ms-utxo-list');
    if (ul) { ul.classList.add('hidden'); ul.innerHTML = ''; }
    const tb = document.getElementById('btn-toggle-ms-utxos');
    if (tb) tb.textContent = 'Select UTXOs manually \u25b8';
    msPicked = [];
    msSelectedUtxoIndices = null;
}
/// Where a tab-bar screen should return to.
///
/// The tab bar sits above every screen, so Tokens and History are reachable
/// from the multisig wallet too. Hardcoding the dashboard there discards the
/// loaded branch, which is the same fault fixed in addresses, utxos, receive
/// and broadcast.
function tabReturnScreen() {
    return (msActive && msBranch) ? 'ms-wallet' : 'dashboard';
}
let msBranch = null; // { descriptor, address, cosigner, chain, index, next_receive_index }
// The receive screen is shared with single-sig, so Back has to know who sent it
// there. Null means the single-sig dashboard.
let msReceiveReturn = null;

function msStripHeader(text) {
    let t = String(text || '').trim();
    while (t.startsWith('#')) { const nl = t.indexOf('\n'); t = nl < 0 ? '' : t.slice(nl + 1).trim(); }
    return t;
}

/// Is a 45' branch loaded?
///
/// The spend screen used to ask `msActive`, a flag set at load and cleared when
/// the load screen is backed out of (`btn-msl-back`). That clear leaves
/// `msBranch` in place, so the two can disagree, and when they do this screen
/// is unusable: the summary still names the branch, the source field stays
/// hidden because a 45' branch has no single source address, and the guards
/// demand the address the screen has hidden. Asking the descriptor instead
/// cannot drift, because it is the same fact the screen was laid out from.
///
/// 44' is deliberately excluded: it really does spend from one address, its
/// source field is shown, and those paths are unchanged.
function msIs45Loaded() {
    return !!(msBranch && msStripHeader(msBranch.descriptor).startsWith('multi_hd45('));
}

async function handleMsLoad() {
    const rawDesc = el('input-msl-descriptor').value.trim();
    const addr = el('input-msl-address').value.trim();
    const status = el('msl-status');
    const fail = (m) => { status.textContent = m; status.style.color = 'var(--error,#f44336)'; };

    if (!rawDesc) return fail('Descriptor required');
    if (!addr) return fail('Address required');

    const d = msStripHeader(rawDesc);
    // Parse check with no network: deriving one address either works or it does not.
    try { multisig_address_at_js(d, 0, 0, 0); }
    catch (e) { return fail('Descriptor did not parse: ' + e); }

    status.style.color = '';
    status.textContent = 'Matching address against the descriptor…';

    const n = msCosignerCount(d) || 2;
    let found = null;
    for (let cos = 0; cos < n && !found; cos++) {
        for (let chain = 0; chain < 2 && !found; chain++) {
            for (let idx = 0; idx < 100; idx++) {
                let a;
                try { a = multisig_address_at_js(d, idx, cos, chain); } catch (_) { break; }
                if (a === addr) { found = { cosigner: cos, chain: chain, index: idx }; break; }
            }
        }
    }
    if (!found) {
        return fail('That address is not produced by this descriptor (' + n
            + ' branch(es), both chains, indices 0-99). Wrong address, or wrong descriptor.');
    }

    msBranch = { descriptor: d, address: addr, cosigner: found.cosigner,
                 chain: found.chain, index: found.index, next_receive_index: null };
    msActive = true;
    status.textContent = '';

    // The spend form is shared by both schemes. Fill it and hide what was just
    // entered; a summary line replaces it so the values are still checkable.
    el('input-ms-descriptor').value = d;
    el('input-ms-source').value = addr;
    el('ms-desc-block').classList.add('hidden');
    el('ms-source-block').classList.add('hidden');
    const sum = el('ms-loaded-summary');
    sum.classList.remove('hidden');

    const is45 = msStripHeader(d).startsWith('multi_hd45(');
    if (is45) {
        // NOT "From <address>".
        //
        // The address given at load identifies the branch; it is not where the
        // inputs come from - those are chosen per outpoint and may span several
        // addresses. Writing "From <that address>" was simply false, and it
        // survived into the consolidate route, which reaches this screen without
        // going through Send.
        //
        // Set once, here, so every route in shows the same true thing.
        sum.innerHTML = '<span style="color:var(--text-dim,#888)">Branch S'
            + found.cosigner + '</span>';
    } else {
        // 44': the branch address IS the source and already sits in the hidden
        // source field; repeating it here was noise, the same conclusion the
        // 45' branch above reached for its own line. Name the scheme instead,
        // the one fact this screen does not show anywhere else.
        const mMatch = msStripHeader(d).match(/^multi(?:_hd)?\((\d+),/);
        const mOf = (mMatch ? mMatch[1] + '-of-' : '') + n;
        sum.innerHTML = '<span style="color:var(--text-dim,#888)">' + mOf
            + " multisig \u00b7 44'</span>";
    }

    if (!is45) {
        // 44': one address family, spend only. Nothing to show as a wallet.
        showScreen('multisig');
        return;
    }
    showScreen('ms-wallet');
    await refreshMsWallet();
}

/// Which indices of the loaded branch have EVER been used, funded or not.
///
/// The UTXO scan can only see money that is still there, so an address that was
/// funded and then spent looks identical to one never used. That is wrong twice
/// over: the address list shows it as fresh, and `next_change_index` hands it
/// back out, so rotation silently stops rotating after one round.
///
/// Same REST path and same discipline as the single-sig scan: sequential with
/// spacing, stop after a run of unused addresses, give up on a 429 rather than
/// hammering. Bounded by the gap rule, so a young wallet costs a handful of
/// requests rather than eighty.
async function msScanUsed(depth) {
    const apiBase = KASPA_REST_API[network];
    if (!apiBase || !msBranch) return { receive: new Set(), change: new Set() };
    const GAP_STOP = 20;
    const SPACING_MS = 250;
    let rateLimited = false;

    const scan = async (chain) => {
        const used = new Set();
        let unusedRun = 0;
        for (let i = 0; i < depth; i++) {
            if (rateLimited) break;
            let addr;
            try { addr = multisig_address_at_js(msBranch.descriptor, i, msBranch.cosigner, chain); }
            catch (_) { break; }
            try {
                const r = await fetch(`${apiBase}/addresses/${addr}/transactions-count`,
                                      { signal: AbortSignal.timeout(5000) });
                if (r.status === 429) { rateLimited = true; break; }
                if (r.ok) {
                    const d = await r.json();
                    if (d.total > 0) { used.add(i); unusedRun = 0; }
                    else { unusedRun++; }
                }
            } catch (_) { /* transient: treat as unknown, not as unused */ }
            if (unusedRun >= GAP_STOP) break;
            await new Promise(res => setTimeout(res, SPACING_MS));
        }
        return used;
    };

    const receive = await scan(0);
    const change = await scan(1);
    if (rateLimited) console.log('[KasSee] multisig history scan stopped: rate-limited');
    return { receive: receive, change: change, partial: rateLimited };
}

/// Consolidate: send the selection to the branch's next unused receive address.
///
/// No destination to enter - the point is to merge outputs, not move value out.
function startMsConsolidate() {
    const idx = msBranch.next_receive_index != null ? msBranch.next_receive_index : 0;
    let dest;
    try { dest = multisig_address_at_js(msBranch.descriptor, idx, msBranch.cosigner, 0); }
    catch (e) { toast('Could not derive destination', 'error'); return; }
    const total = msPicked.reduce((a, p) => a + BigInt(p.amount), 0n);
    // Amount is the total MINUS the fee.
    //
    // The create path treats this field as the destination amount and adds the
    // fee on top, so putting the full total here asks for total + fee and fails
    // with "Selected X but need X + fee". Same arithmetic as MAX, because
    // consolidation IS a max-send to one of your own addresses.
    const nCosigners = msCosignerCount(msBranch.descriptor);
    if (nCosigners === 0) {
        toast('Could not read the cosigner count from the descriptor', 'error', 4000);
        return;
    }
    const fee = getCovFee(msPicked.length, nCosigners);
    if (total <= fee) {
        toast('Selection does not cover the fee (' + sompiToKasStr(fee) + ' KAS)',
              'error', 4000);
        return;
    }
    el('input-ms-dest').value = dest;
    el('input-ms-amount').value = sompiToKasStr(total - fee);
    el('btn-toggle-ms-utxos').textContent = msPicked.length + ' input(s) → C0 #' + idx
        + ' · ' + sompiToKasStr(total - fee) + ' KAS ▸';
    toast('Review and send to consolidate', 'info', 2000);
    showScreen('multisig');
}

// `light` refreshes balance and UTXOs over the node WebSocket only and keeps
// the used-address sets from the last full scan. The full scan adds
// `msScanUsed(40)`: 80 REST calls to api.kaspa.org spaced 250 ms apart, about
// 20 s. That is fine on entry and on the Refresh button; it is not something
// to run every 30 s or after every broadcast, which is what `light` is for.
let msRefreshing = false;
async function refreshMsWallet(light = false) {
    if (!msBranch) return;
    if (msRefreshing) return;
    msRefreshing = true;
    try { await _refreshMsWalletInner(light); } finally { msRefreshing = false; }
}
async function _refreshMsWalletInner(light) {
    const n = msCosignerCount(msBranch.descriptor) || '?';
    el('msw-subtitle').textContent = 'Branch S' + msBranch.cosigner + ' of ' + n;
    el('msw-balance').textContent = '…';
    el('msw-meta').textContent = '';
    // The indicator was only ever set by `refreshBalance`, which needs
    // `walletData` - the SINGLE-SIG wallet. A multisig branch scan talks to the
    // node just as much, so the header sat on "Offline" throughout.
    setStatus('connecting', 'Connecting');
    try {
        const wsUrl = await resolveNodeUrl();
        const r = JSON.parse(await scan_multisig_branch_js(
            msBranch.descriptor, msBranch.cosigner, 40, wsUrl));
        setStatus('online', 'Connected');
        el('msw-balance').textContent = (Number(r.balance_sompi) / 1e8).toFixed(8) + ' KAS';
        el('msw-sompi').textContent = Number(r.balance_sompi).toLocaleString() + ' sompi';
        el('msw-meta').textContent = r.utxo_count + ' UTXO(s) across ' + r.funded.length
            + ' address(es) · next receive #' + r.next_receive_index
            + ' · next change #' + r.next_change_index;
        msBranch.funded = r.funded;
        msBranch.utxos = r.utxos || [];

        // History, not just UTXOs. The scan above cannot see a spent-empty
        // address; this can, and both the next indices and the address list
        // depend on knowing the difference. A light refresh reuses the sets
        // from the last full scan instead of hitting the REST API again.
        const usedSets = light && msBranch.usedReceive
            ? { receive: msBranch.usedReceive, change: msBranch.usedChange, partial: false }
            : await msScanUsed(40);
        msBranch.usedReceive = usedSets.receive;
        msBranch.usedChange = usedSets.change;
        const fundedR = new Set(r.funded.filter(f => f.chain === 0).map(f => f.index));
        const fundedC = new Set(r.funded.filter(f => f.chain === 1).map(f => f.index));
        const firstFree = (used, funded) => {
            for (let i = 0; i < 40; i++) if (!used.has(i) && !funded.has(i)) return i;
            return 40;
        };
        msBranch.next_receive_index = firstFree(usedSets.receive, fundedR);
        msBranch.next_change_index = firstFree(usedSets.change, fundedC);
        el('msw-meta').textContent = r.utxo_count + ' UTXO(s) across ' + r.funded.length
            + ' address(es) · next receive #' + msBranch.next_receive_index
            + ' · next change #' + msBranch.next_change_index
            + (usedSets.partial ? ' (history scan incomplete)' : '');
        // No UTXO list on the wallet screen; that is what the UTXOs tab is for.
        //
        // This used to assign `r.funded` here, clobbering the real outpoints set
        // above. `funded` aggregates per address and has no `tx_id`, so the
        // picker threw on `u.tx_id.slice(...)`. Left over from an earlier edit.
    } catch (e) {
        setStatus('offline', 'Offline');
        el('msw-balance').textContent = '—';
        el('msw-meta').textContent = 'Scan failed: ' + e;
    }
}

window.handleCovbScan = handleCovbScan;

// ─── Covenant Recovery Scanner ───
// Scans TX history for all wallet addresses, finds TXs with payloads,
// decrypts with kpub-derived key, rebuilds covenant addresses, checks balances.

async function recoverCovenants() {
    if (!walletData) { toast('Load wallet first', 'error'); return; }
    const wallet = JSON.parse(walletData);
    const apiBase = KASPA_REST_API[network];
    if (!apiBase) { toast('No REST API for ' + network, 'error'); return; }

    const ownerPk = getAccountPubkeyHex();
    const allAddresses = [...(wallet.receive_addresses || []), ...(wallet.change_addresses || [])];
    const myAddressSet = new Set(allAddresses);

    toast('Scanning chain for covenant payloads...', 'info', 3000);
    console.log('[KasSee] Recovery: scanning', allAddresses.length, 'addresses');

    let found = 0;
    let scanned = 0;
    const seenTxIds = new Set();

    for (const addr of allAddresses) {
        try {
            const r = await fetch(
                `${apiBase}/addresses/${addr}/full-transactions?resolve_previous_outpoints=light&limit=50`,
                { signal: AbortSignal.timeout(10000) }
            );
            if (!r.ok) continue;
            const txs = await r.json();
            if (!Array.isArray(txs)) continue;

            for (const tx of txs) {
                if (seenTxIds.has(tx.transaction_id)) continue;
                seenTxIds.add(tx.transaction_id);
                scanned++;

                // TN10 API doesn't reliably populate previous_outpoint_address,
                // so we skip the fromUs check and rely on decrypt failure as the
                // filter: only payloads encrypted with our key will decrypt.

                // Get payload. full-transactions may not include it, so fetch individual TX.
                let payloadHex = tx.payload;
                if (!payloadHex || payloadHex === '0000000000000000') {
                    try {
                        const txr = await fetch(
                            `${apiBase}/transactions/${tx.transaction_id}`,
                            { signal: AbortSignal.timeout(5000) }
                        );
                        if (txr.ok) {
                            const txData = await txr.json();
                            payloadHex = txData.payload;
                        }
                    } catch (_) {}
                }
                if (!payloadHex || payloadHex.length < 60) continue; // min 30 bytes = 60 hex

                // Try to decrypt
                const decrypted = await decryptCovenantPayload(payloadHex);
                if (!decrypted) {
                    // Might be a crowdfund with dual payload: [enc_len:2 LE][enc][discovery]
                    if (payloadHex.length > 64) {
                        const encLen = parseInt(payloadHex.substring(2, 4) + payloadHex.substring(0, 2), 16);
                        if (encLen > 30 && encLen * 2 + 4 <= payloadHex.length) {
                            const encPart = payloadHex.substring(4, 4 + encLen * 2);
                            const dec2 = await decryptCovenantPayload(encPart);
                            if (dec2) {
                                const rebuilt = await rebuildCovenant(dec2, ownerPk, tx);
                                if (rebuilt) found++;
                            }
                        }
                    }
                    continue;
                }

                const rebuilt = await rebuildCovenant(decrypted, ownerPk, tx);
                if (rebuilt) found++;
            }
        } catch (e) {
            console.log('[KasSee] Recovery: error scanning', addr, e);
        }
    }

    console.log('[KasSee] Recovery complete:', scanned, 'TXs scanned,', found, 'covenants recovered');
    if (found > 0) {
        toast('Recovered ' + found + ' covenant(s) from chain', 'ok', 4000);
        covSaveActive();
        covRenderActive();
    } else {
        toast('No covenant payloads found on chain', 'info', 3000);
    }
}

// Rebuild a single covenant from decrypted payload params
async function rebuildCovenant(decrypted, ownerPk, tx) {
    const typeName = decrypted.covenant_type_name;
    const params = decrypted.params_hex;
    if (!typeName || typeName === 'unknown') return false;

    // Helper: read 8-byte LE u64 from hex at offset (in hex chars)
    const readU64 = (hex, off) => {
        let n = 0n;
        for (let i = 0; i < 8; i++) {
            const byte = parseInt(hex.substring(off + i * 2, off + i * 2 + 2), 16);
            n |= BigInt(byte) << BigInt(i * 8);
        }
        return n;
    };
    // Helper: read 2-byte LE length from hex at offset, returns { len, endOff }
    const readLen = (hex, off) => {
        const lo = parseInt(hex.substring(off, off + 2), 16);
        const hi = parseInt(hex.substring(off + 2, off + 4), 16);
        return { len: lo | (hi << 8), endOff: off + 4 };
    };
    // Helper: read variable-length string (2-byte LE len + UTF-8 bytes)
    const readVstr = (hex, off) => {
        const { len, endOff } = readLen(hex, off);
        const strHex = hex.substring(endOff, endOff + len * 2);
        const bytes = hexToBytes(strHex);
        return { str: new TextDecoder().decode(bytes), endOff: endOff + len * 2 };
    };

    let result = null;
    try {
        switch (typeName) {
            case 'dms': {
                const heirPk = params.substring(0, 64);
                const inactivityDaa = readU64(params, 64);
                const res = JSON.parse(covenant_dms(ownerPk, heirPk, inactivityDaa, network));
                result = {
                    type: typeName, address: res.address, redeem_script_hex: res.redeem_script_hex,
                    inactivity_daa: Number(inactivityDaa), heir_pubkey_hex: heirPk, loaded: true, role: 'owner',
                };
                break;
            }
            case 'oracle': {
                // Stored as full redeem script (salt) + oracle_pk(32) + bene_pk(32)
                // + locktime(8). Derive the address from the stored script so the
                // salt is preserved (rebuilding via covenant_oracle would mint a new
                // salt and a different address).
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const oraclePk = params.substring(pos, pos + 64); pos += 64;
                const benePk = params.substring(pos, pos + 64); pos += 64;
                const locktime = readU64(params, pos); pos += 16;
                // Optional absolute refund date (newer COVB only). Older backups end
                // at the locktime, so guard before reading and fall back to DAA
                // estimation (which drifts on every reload). Mirrors the savings case.
                let oracleDateIso = '';
                if (pos < params.length) {
                    try { const v = readVstr(params, pos); oracleDateIso = v.str || ''; } catch (_) {}
                }
                // owner_pk lives inside the redeem: 10-byte salt prefix (0x08<8>0x75)
                // + OP_IF + OP_DATA_32, so bytes [12..44] = hex [24..88]. Set it so
                // the role detector can match the owner; without it a fresh COVB/SD
                // load on another device has no owner key and falls through to
                // beneficiary. A COVB blob is owner-encrypted, so the decryptor is
                // the owner: default role to owner, but still match all three keys.
                const ownerPkFromRedeem = redeemHex.substring(24, 88);
                const myAcctPkO = getAccountPubkeyHex() || '';
                const myAddrPkO = getOwnerPubkeyHex() || '';
                const matchOraclePk = (t) => walletMatchesPk(t);
                let oracleRole = 'owner';
                if (matchOraclePk(oraclePk)) oracleRole = 'oracle';
                else if (matchOraclePk(benePk)) oracleRole = 'beneficiary';
                else if (matchOraclePk(ownerPkFromRedeem)) oracleRole = 'owner';
                const scriptHash = blake2b_hash(redeemHex);
                const address = encode_p2sh_address(scriptHash, network);
                result = {
                    type: typeName, address: address, redeem_script_hex: redeemHex,
                    locktime_daa: Number(locktime), oracle_pubkey_hex: oraclePk,
                    beneficiary_pubkey_hex: benePk, owner_pubkey_hex: ownerPkFromRedeem,
                    loaded: true, role: oracleRole,
                };
                if (oracleDateIso) result.locktime_date_iso = oracleDateIso;
                break;
            }
            case 'additive': {
                // Stored as full redeem script (salt) + threshold(8) + deadline(8).
                // Derive the address from the stored script so the salt is preserved
                // (rebuilding via covenant_additive_address would mint a new salt).
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const threshold = readU64(params, pos); pos += 16;
                const deadline = readU64(params, pos);
                const scriptHash = blake2b_hash(redeemHex);
                const address = encode_p2sh_address(scriptHash, network);
                result = {
                    type: typeName, address: address, redeem_script_hex: redeemHex,
                    threshold_sompi: threshold.toString(), deadline_daa: Number(deadline), loaded: true, role: 'owner',
                };
                break;
            }
            case 'global-spending-limit': {
                // Stored as full redeem script (salt) + max(8) + cooldown(8) + covenant_id(32).
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const maxWithdraw = readU64(params, pos); pos += 16;
                const cooldownDaa = readU64(params, pos); pos += 16;
                const covIdHex = params.substring(pos, pos + 64);
                const scriptHash = blake2b_hash(redeemHex);
                const address = encode_p2sh_address(scriptHash, network);
                result = {
                    type: typeName, address: address, redeem_script_hex: redeemHex,
                    max_withdraw_sompi: maxWithdraw.toString(), cooldown_daa: Number(cooldownDaa),
                    covenant_id_hex: (covIdHex && !/^0+$/.test(covIdHex)) ? covIdHex : '',
                    loaded: true, role: 'owner',
                };
                break;
            }
            case 'global-allowance': {
                // Stored as full redeem script (salt) + max(8) + cooldown(8) + start(8) + bene_pk(32) + covenant_id(32).
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const maxWithdraw = readU64(params, pos); pos += 16;
                const cooldownDaa = readU64(params, pos); pos += 16;
                const startDaa = readU64(params, pos); pos += 16;
                const benePk = params.substring(pos, pos + 64); pos += 64;
                const covIdHex = params.substring(pos, pos + 64);
                const scriptHash = blake2b_hash(redeemHex);
                const address = encode_p2sh_address(scriptHash, network);
                result = {
                    type: typeName, address: address, redeem_script_hex: redeemHex,
                    max_withdraw_sompi: maxWithdraw.toString(), cooldown_daa: Number(cooldownDaa),
                    start_daa: Number(startDaa), beneficiary_pubkey_hex: benePk,
                    covenant_id_hex: (covIdHex && !/^0+$/.test(covIdHex)) ? covIdHex : '',
                    loaded: true, role: 'owner',
                };
                break;
            }
            case 'timelocked-savings': {
                // Params: vhex(redeem) + wallet1_pk(32) + wallet2_pk(32) + locktime(8) + date_iso(vstr, optional).
                // Rebuild the P2SH address from the stored script (no salt to recompute);
                // recovers the vault with no local list and no invite.
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const w1 = params.substring(pos, pos + 64); pos += 64;
                const w2 = params.substring(pos, pos + 64); pos += 64;
                const locktime = readU64(params, pos); pos += 16;
                // Optional absolute unlock date (newer payloads only). Older deposits
                // end here, so guard before reading and fall back to DAA estimation.
                let dateIso = '';
                if (pos < params.length) {
                    try { const v = readVstr(params, pos); dateIso = v.str || ''; } catch (_) {}
                }
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    const isRecovery = !!(ownerPk && w2 && ownerPk === w2 && ownerPk !== w1);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        wallet1_pubkey_hex: w1, wallet2_pubkey_hex: w2,
                        locktime_daa: Number(locktime),
                        loaded: true, role: isRecovery ? 'beneficiary' : 'owner',
                    };
                    if (dateIso) result.locktime_date_iso = dateIso;
                }
                break;
            }
            case 'escrow': {
                // Params: vhex(redeem_script)
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        loaded: true, role: 'owner',
                    };
                    ensureEscrowParams(result);
                }
                break;
            }
            case 'adaptor-swap': {
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const locktime = readU64(params, pos); pos += 16;
                const secretKey = params.substring(pos, pos + 64); pos += 64;
                let adaptorSig = '', counterAddr = '', counterRedeem = '';
                let counterAdaptorSig = '', T_hex = '', myPk = '';
                try {
                    const { len: asLen, endOff: asOff } = readLen(params, pos);
                    adaptorSig = params.substring(asOff, asOff + asLen * 2); pos = asOff + asLen * 2;
                    const ca = readVstr(params, pos); counterAddr = ca.str || ''; pos = ca.endOff;
                    const { len: crLen, endOff: crOff } = readLen(params, pos);
                    counterRedeem = params.substring(crOff, crOff + crLen * 2); pos = crOff + crLen * 2;
                    const { len: casLen, endOff: casOff } = readLen(params, pos);
                    counterAdaptorSig = params.substring(casOff, casOff + casLen * 2); pos = casOff + casLen * 2;
                    T_hex = params.substring(pos, pos + 64); pos += 64;
                    myPk = params.substring(pos, pos + 64);
                } catch (_) {}
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        locktime_daa: Number(locktime), loaded: true,
                    };
                    if (secretKey && secretKey.length === 64) {
                        const recovery = {
                            mySecretKey: secretKey,
                            myAdaptorSig: adaptorSig,
                            myPk: myPk,
                            counterAddr: counterAddr,
                            counterRedeem: counterRedeem,
                            counterAdaptorSig: counterAdaptorSig,
                            T_hex: T_hex,
                            myAddr: address,
                            myRedeem: redeemHex,
                            myTimeoutDaa: Number(locktime),
                        };
                        try { sessionStorage.setItem('kassee_adaptor_recovery_' + address, JSON.stringify(recovery)); } catch (_) {}
                        console.log('[KasSee] Adaptor swap recovery data restored from COVB');
                    }
                }
                break;
            }
            case 'merkle-whitelist': {
                // redeem_script(var) + merkle_root(32) + depth(1) + locktime(8) + addresses_json(var)
                const { len: rsLen, endOff: rsOff } = readLen(params, 0);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                const mRoot = params.substring(pos, pos + 64); pos += 64;
                const mDepth = parseInt(params.substring(pos, pos + 2), 16); pos += 2;
                const locktime = readU64(params, pos); pos += 16;
                let addrJson = '';
                try { const r = readVstr(params, pos); addrJson = r.str; } catch (_) {}
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        locktime_daa: Number(locktime), merkle_root: mRoot, merkle_depth: mDepth,
                        merkle_addresses_json: addrJson || '', loaded: true, role: 'owner',
                    };
                }
                break;
            }
            case 'timelocked-escrow': {
                // beneficiary_pk(32) + locktime(8) = 40 bytes
                const benePk = params.substring(0, 64);
                const locktime = readU64(params, 64);
                // Timelocked escrow needs both alice/bob addresses for script rebuild.
                // We have ownerPk and benePk but need addresses. Use generic redeem fallback.
                // For full recovery, the covenant should store redeem script in the payload.
                // Attempt rebuild via covenant_timelocked_escrow if the addresses can be derived.
                // Fallback: store as generic with redeem script if available.
                result = {
                    type: typeName, locktime_daa: Number(locktime),
                    beneficiary_pubkey_hex: benePk, loaded: true, role: 'owner',
                };
                // Try to rebuild using the WASM function
                try {
                    const ownerAddr = encode_p2pk_address(ownerPk, network);
                    const beneAddr = encode_p2pk_address(benePk, network);
                    const res = JSON.parse(covenant_timelocked_escrow(ownerPk, benePk, ownerAddr, beneAddr, locktime, network));
                    result.address = res.address;
                    result.redeem_script_hex = res.redeem_script_hex;
                } catch (e) {
                    console.log('[KasSee] Recovery: timelocked-escrow rebuild failed, missing addresses:', e);
                    return false;
                }
                break;
            }
            case 'payjoin': {
                // beneficiary_pk(32) + locktime(8) + min_inputs(8) + min_outputs(8) + redeem(var) + date_iso(vstr, optional).
                const benePk = params.substring(0, 64);
                const locktime = readU64(params, 64);
                const minInputs = readU64(params, 80);
                const minOutputs = readU64(params, 96);
                const { len: rsLen, endOff: rsOff } = readLen(params, 112);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                let pos = rsOff + rsLen * 2;
                // Optional absolute refund date (newer payloads only). Older backups end
                // at the redeem, so guard before reading and fall back to DAA estimation.
                let dateIso = '';
                if (pos < params.length) {
                    try { const v = readVstr(params, pos); dateIso = v.str || ''; } catch (_) {}
                }
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        locktime_daa: Number(locktime), beneficiary_pubkey_hex: benePk,
                        min_inputs: Number(minInputs), min_outputs: Number(minOutputs),
                        loaded: true, role: 'owner',
                    };
                    if (dateIso) result.locktime_date_iso = dateIso;
                }
                break;
            }
            case 'commit-reveal': {
                // commit_hash(32) + locktime(8) + redeem(var) + ciphertext(var)
                const commitHash = params.substring(0, 64);
                const locktime = readU64(params, 64);
                let pos = 80;
                const { len: rsLen, endOff: rsOff } = readLen(params, pos);
                const redeemHex = params.substring(rsOff, rsOff + rsLen * 2);
                pos = rsOff + rsLen * 2;
                let ctHex = '';
                try {
                    const ct = readLen(params, pos);
                    ctHex = params.substring(ct.endOff, ct.endOff + ct.len * 2);
                } catch (_) {}
                if (redeemHex.length > 0) {
                    const scriptHash = blake2b_hash(redeemHex);
                    const address = encode_p2sh_address(scriptHash, network);
                    result = {
                        type: typeName, address: address, redeem_script_hex: redeemHex,
                        locktime_daa: Number(locktime), commit_hash: commitHash,
                        cr_ciphertext_hex: ctHex,
                        loaded: true, role: 'owner',
                    };
                }
                break;
            }
            case 'crowdfund': {
                // organizer_pk(32) + vk_hash(32) + locktime(8) + goal_sompi(8) = 80 bytes
                const orgPk = params.substring(0, 64);
                const vkHash = params.substring(64, 128);
                const locktime = readU64(params, 128);
                const goalSompi = readU64(params, 144);
                // Crowdfund rebuild requires vk_hex (not just hash). We only have the hash.
                // Store partial recovery data. Full rebuild needs VK from organizer invite.
                result = {
                    type: typeName, locktime_daa: Number(locktime),
                    organizer_pk: orgPk, vk_hash: vkHash,
                    goal_sompi: goalSompi.toString(),
                    goal_kas: (Number(goalSompi) / 1e8).toString(),
                    loaded: true, crowdfund_role: 'contributor',
                };
                // Without VK hex we can't rebuild the script. Mark as partial recovery.
                console.log('[KasSee] Recovery: crowdfund partial (VK hash only, needs invite for full rebuild)');
                break;
            }
            default: {
                // Generic: redeem script stored directly
                if (params.length >= 4) {
                    const { len, endOff } = readLen(params, 0);
                    const redeemHex = params.substring(endOff, endOff + len * 2);
                    if (redeemHex.length > 0) {
                        const scriptHash = blake2b_hash(redeemHex);
                        const address = encode_p2sh_address(scriptHash, network);
                        result = {
                            type: typeName, address: address, redeem_script_hex: redeemHex, loaded: true,
                        };
                    }
                }
                break;
            }
        }
    } catch (e) {
        console.log('[KasSee] Recovery: failed to rebuild', typeName, e);
        return false;
    }

    if (!result) return false;

    // Check if already in active covenants
    if (activeCovenants.some(c => c.address === result.address)) {
        console.log('[KasSee] Recovery: already active:', result.address);
        return false;
    }

    // Check balance. If empty, still add (user may want to re-fund or track).
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(result.address, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        result._balance = Number(total) / 1e8;
    } catch (_) {
        result._balance = 0;
    }

    console.log('[KasSee] Recovery: found', typeName, 'at', result.address, 'balance:', result._balance, 'KAS');
    covAddActive(typeName, result);
    return true;
}

// ─── Init ───

async function start() {
    await init();
    console.log(version());

    // Restore covenant context from sessionStorage (survives reload, dies on tab close)
    try {
        const saved = sessionStorage.getItem('lastCovenantResult');
        if (saved) lastCovenantResult = JSON.parse(saved);
    } catch (_) {}
    swapStateLoad();
    adaptorStateLoad();
    covLoadActive();
    // Restore crowdfund PK/VK from localStorage
    try {
        const pk = localStorage.getItem('crowdfundPk');
        const vk = localStorage.getItem('crowdfundVk');
        if (pk) window._crowdfundPk = pk;
        if (vk) window._crowdfundVk = vk;
        // Organizer pk is derived from wallet, set after kpub is loaded
    } catch (_) {}

    showScreen('welcome');
    bindEvents();
}

// ─── Screen navigation ───

let currentScreenName = 'welcome';
function showScreen(name) {
    currentScreenName = name;
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const screen = document.getElementById(`screen-${name}`);
    if (screen) screen.classList.add('active');
    // Auto-refresh on the dashboard and on the multisig wallet screen
    if ((name === 'dashboard' && walletData) || (name === 'ms-wallet' && msBranch)) {
        startAutoRefresh();
    } else {
        stopAutoRefresh();
    }
}

function showLoading(msg) {
    el('loading-msg').textContent = msg || 'Loading...';
    el('loading').classList.remove('hidden');
}

function hideLoading() {
    el('loading').classList.add('hidden');
}

function setStatus(state, label) {
    const dot = document.querySelector('#status-dot .dot');
    const lbl = document.querySelector('#status-dot .label');
    dot.className = `dot ${state}`;
    const netTag = network !== 'mainnet' ? ` [${network.toUpperCase()}]` : '';
    lbl.textContent = label + netTag;
}

function toggleGearMenu() {
    const menu = el('gear-menu');
    const btn = el('btn-header-settings');
    if (menu.classList.contains('visible')) {
        menu.classList.remove('visible');
        btn.classList.remove('active');
    } else {
        menu.classList.add('visible');
        btn.classList.add('active');
    }
}

function closeGearMenu() {
    el('gear-menu').classList.remove('visible');
    el('btn-header-settings').classList.remove('active');
}

// ─── Event binding ───

function bindEvents() {
    el('btn-scan-kpub').onclick = () => startScanner('Scan kpub QR', handleKpubScan);
    el('btn-logo').onclick = () => handleLogoTap();
    el('btn-import-kpub').onclick = () => handleKpubImport(el('input-kpub').value.trim());
    el('btn-multisig-welcome').onclick = () => showScreen('ms-load');
    el('btn-broadcast-welcome').onclick = () => { hideBroadcastResult(); showScreen('broadcast'); };
    el('btn-send').onclick = () => openSendScreen();
    el('btn-receive').onclick = () => showReceive();
    el('btn-broadcast').onclick = () => { hideBroadcastResult(); showScreen('broadcast'); };
    el('btn-multisig-spend').onclick = () => showScreen('ms-load');

    // ── Multisig load ──
    el('btn-msl-load').onclick = () => handleMsLoad();
    el('btn-msl-back').onclick = () => {
        msActive = false;   // leaving the multisig flow: tabs revert to single-sig
        showScreen(walletData ? 'dashboard' : 'welcome');
    };
    // Descriptors arrive as MULTI-FRAME BINARY, same protocol as KSPT: the
    // scanner hands over a Uint8Array per frame and `decode_qr_frame`
    // reassembles them, returning hex that decodes to the text. Treating the
    // frame as text or as a hex string both fail silently.
    el('btn-scan-msl-descriptor').onclick = () => startScanner('Scan descriptor QR', (data) => {
        const hexStr = Array.from(new Uint8Array(data))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        try {
            const result = decode_qr_frame(hexStr);
            if (result && result.length > 0) {
                const bytes = [];
                for (let i = 0; i < result.length; i += 2) bytes.push(parseInt(result.substr(i, 2), 16));
                const text = msStripHeader(new TextDecoder().decode(new Uint8Array(bytes)).trim());
                if (text.startsWith('multi(') || text.startsWith('multi_hd(')
                    || text.startsWith('multi_hd45(')) {
                    stopScanner();
                    el('input-msl-descriptor').value = text;
                    showScreen('ms-load');
                    toast('Descriptor scanned', 'ok', 1500);
                } else {
                    stopScanner();
                    toast('Not a valid descriptor', 'error');
                }
            }
        } catch (_) { /* more frames needed */ }
    });
    // A single-frame address: plain bytes, no reassembly.
    el('btn-scan-msl-address').onclick = () => startScanner('Scan address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa:')) {
            stopScanner();
            el('input-msl-address').value = addr;
            showScreen('ms-load');
            toast('Address scanned', 'ok', 1500);
        }
    });

    // ── Multisig wallet (45' only) ──
    el('btn-msw-refresh').onclick = () => refreshMsWallet();
    el('btn-msw-back').onclick = () => showScreen('ms-load');
    el('btn-msw-broadcast').onclick = () => {
        // `_broadcastReturnScreen` already exists for exactly this - the
        // covenant and stealth flows both set it. Not setting it meant Back
        // fell through to the dashboard and dropped the loaded branch.
        _broadcastReturnScreen = 'ms-wallet';
        showScreen('broadcast');
    };
    // Send carries nothing but the loaded wallet: destination and amount are
    // entered on the spend screen like any normal send.
    el('btn-msw-send').onclick = () => {
        if (!msBranch) return;
        // Descriptor yes, SOURCE no.
        //
        // The address given at load identified the branch; it is not
        // necessarily the address you want to spend from, and prefilling it
        // silently chooses one. The builder takes a single source address, so
        // that choice is the user's - the funded list on the wallet screen
        // shows what there is to choose from.
        el('input-ms-descriptor').value = msBranch.descriptor;
        el('input-ms-source').value = '';
        el('input-ms-dest').value = '';
        el('input-ms-amount').value = '';
        // Descriptor stays HIDDEN - it came from the load screen and showing it
        // again is the noise we removed. Only the source needs choosing, so the
        // summary line carries the branch and the source field is revealed on
        // its own.
        // No source address at all.
        //
        // The picker names the addresses, so asking for one separately is both
        // redundant and a restriction: a source field can only hold one, which
        // is exactly the limit being removed.
        resetMsUtxoSelection();
        el('ms-desc-block').classList.add('hidden');
        el('ms-source-block').classList.add('hidden');
        // Summary is set at LOAD time and is already correct for every route in,
        // including consolidate, which does not pass through here.
        showScreen('multisig');
    };
    el('btn-msw-receive').onclick = () => {
        if (!msBranch) return;
        // The SHARED receive screen, as single-sig uses. An inline panel that
        // appears under the buttons and stays there is not how any other
        // receive works here.
        const idx = msBranch.next_receive_index != null ? msBranch.next_receive_index : 0;
        let a;
        try { a = multisig_address_at_js(msBranch.descriptor, idx, msBranch.cosigner, 0); }
        catch (e) { toast('Could not derive address', 'error'); return; }
        const qr = el('receive-qr');
        qr.innerHTML = '';
        try { qr.innerHTML = generate_qr_svg_text(a); } catch (_) {}
        el('receive-address').textContent = a;
        // Remember the caller, same rule as the address and UTXO lists.
        msReceiveReturn = (currentScreenName && currentScreenName !== 'receive')
            ? currentScreenName : 'ms-wallet';
        showScreen('receive');
    };
    el('btn-ms-back').onclick = () => {
        // Back out of the wallet, not out of KasSee.
        //
        // This always went to the dashboard, so leaving the spend screen threw
        // away the loaded branch and the descriptor and address had to be
        // entered again. With a 45' wallet loaded it belongs one level up.
        // A 44' branch has no wallet screen: ms-wallet is never populated
        // for it, so routing there lands on an empty shell. "One level up"
        // for 44' is the load screen it came from.
        if (msIs45Loaded()) { showScreen('ms-wallet'); return; }
        if (msBranch) { showScreen('ms-load'); return; }
        showScreen(walletData ? 'dashboard' : 'welcome');
    };
    el('btn-ms-create').onclick = () => handleMultisigCreate();
    el('btn-ms-max').onclick = () => handleMsMax();
    el('btn-toggle-ms-utxos').onclick = () => toggleMsUtxos();
    el('btn-scan-ms-source').onclick = () => startScanner('Scan P2SH address', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:')) { stopScanner(); el('input-ms-source').value = addr; showScreen('multisig'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-scan-ms-dest').onclick = () => startScanner('Scan destination', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:') || addr.endsWith('.kas')) { stopScanner(); el('input-ms-dest').value = addr; showScreen('multisig'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-scan-ms-descriptor').onclick = () => startScanner('Scan descriptor QR', handleDescriptorScan);

    // ─── Covenant++ handlers ───
    el('btn-covenant').onclick = () => { covShowPanel('menu'); showScreen('covenant'); };
    el('btn-cov-back').onclick = () => showScreen(walletData ? 'dashboard' : 'welcome');
    if (el('btn-oracle-mb-back')) el('btn-oracle-mb-back').onclick = () => covShowPanel('menu');
    if (el('btn-oracle-mb-ask')) el('btn-oracle-mb-ask').onclick = () => oracleMbAskForNew();
    // Oracle roll fee selector: presets (1/2/3 KAS) + a custom amount (min 1). The chosen total is the
    // miner fee plus the 0.3 service fee; a bigger total raises the feerate so the roll clears a busy mempool.
    document.querySelectorAll('.omb-fee-btn').forEach(b => {
        b.onclick = () => { const ci = el('input-omb-fee-custom'); if (ci) ci.value = ''; oracleMbSetFee(Number(b.getAttribute('data-omb-fee')), false); };
    });
    { const ci = el('input-omb-fee-custom'); if (ci) ci.oninput = () => {
        const v = ci.value.trim();
        if (v === '') { oracleMbSetFee(1, false); return; }
        const n = Number(v);
        if (Number.isFinite(n) && n >= 1) oracleMbSetFee(n, true);
    }; }
    oracleMbSetFee(1, false);
    // Stealth
    el('btn-stealth').onclick = () => { stealthShowPanel('menu'); showScreen('stealth'); };
    el('btn-stealth-back').onclick = () => { stealthScanStop(); showScreen(walletData ? 'dashboard' : 'welcome'); };
    el('btn-stealth-meta').onclick = () => handleStealthMeta();
    el('btn-stealth-meta-back').onclick = () => stealthShowPanel('menu');
    el('btn-stealth-meta-copy').onclick = () => {
        const hex = el('stealth-meta-hex').textContent;
        navigator.clipboard.writeText(hex).then(() => toast('Copied', 'ok', 1500));
    };
    el('btn-stealth-send').onclick = () => stealthShowPanel('send');
    el('btn-stealth-send-back').onclick = () => stealthShowPanel('menu');
    el('btn-stealth-send-go').onclick = () => handleStealthSendGenerate();
    el('btn-stealth-send-pay').onclick = () => handleStealthSendPay();
    el('btn-sf-low').onclick = () => stealthFeeSetLevel('sf', 'send', 'low');
    el('btn-sf-normal').onclick = () => stealthFeeSetLevel('sf', 'send', 'normal');
    el('btn-sf-priority').onclick = () => stealthFeeSetLevel('sf', 'send', 'priority');
    el('btn-stealth-scan').onclick = () => stealthShowPanel('scan');
    el('btn-stealth-scan-back').onclick = () => stealthShowPanel('menu');
    el('btn-stealth-fetch-announcements').onclick = () => handleStealthFetchAnnouncements();
    el('btn-stealth-show-scan-qr').onclick = () => handleStealthShowScanQR();
    el('btn-stealth-scan-result-qr').onclick = () => handleStealthScanResultQR();
    el('btn-stealth-scan-meta').onclick = () => startScanner('Scan Stealth Meta-Address', (data) => {
        const bytes = new Uint8Array(data);
        let text = new TextDecoder().decode(bytes).trim();
        // Fallback: a meta QR encoded as 64 raw bytes -> hex-encode to 128 hex.
        if (!/^[0-9a-fA-F]{128}$/.test(text) && bytes.length === 64) {
            text = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        if (/^[0-9a-fA-F]{128}$/.test(text)) {
            stopScanner();
            el('stealth-send-meta').value = text;
            showScreen('stealth');
            stealthShowPanel('send');
            toast('Meta-address scanned', 'ok', 1500);
        }
    });
    // Covenant++ navigation: card-based type selection
    window.covSelectType = function(type) {
        const advancedTypes = ['commit-reveal', 'merkle-whitelist'];
        if (advancedTypes.includes(type)) {
            el('cov-type').value = type;
            covTypeChanged();
            covShowPanel('create');
            return;
        }
        el('cov-type').value = type;
        covTypeChanged();
        covShowPanel('create');
    };

    // Event delegation for covenant category toggles and type cards
    document.addEventListener('click', function(e) {
        // Covenant fee level buttons
        const feeBtn = e.target.closest('.cov-fee-btn');
        if (feeBtn) {
            covFeeLevel = feeBtn.dataset.covFee || 'normal';
            feeBtn.parentElement.querySelectorAll('.cov-fee-btn').forEach(b => b.classList.remove('cov-fee-active'));
            feeBtn.classList.add('cov-fee-active');
            return;
        }
        // Category header toggle
        const catHeader = e.target.closest('.cov-cat-header');
        if (catHeader) {
            catHeader.parentElement.classList.toggle('collapsed');
            return;
        }
        // Covenant type card selection
        const card = e.target.closest('[data-cov-type]');
        if (card) {
            covSelectType(card.dataset.covType);
            return;
        }
        // Panel shortcut cards (e.g. Atomic Swap hub)
        const panelCard = e.target.closest('[data-cov-panel]');
        if (panelCard) {
            covShowPanel(panelCard.dataset.covPanel);
            return;
        }
    });

    // Legacy button bindings (guarded for new card-based UI)
    if (el('btn-cov-create')) el('btn-cov-create').onclick = () => covShowPanel('create');
    el('btn-cov-create-back').onclick = () => covShowPanel('menu');
    el('btn-cov-result-back').onclick = () => {
        if (lastCovenantResult && lastCovenantResult.type === 'atomic-swap') covShowPanel('menu');
        else if (lastCovenantResult && lastCovenantResult.type === 'adaptor-swap') {
            if (_adaptorState && _adaptorState.role === 'alice') covShowPanel('adaptor-result');
            else if (_adaptorState && _adaptorState.role === 'bob') covShowPanel('adaptor-result');
            else covShowPanel('adaptor');
        }
        else covShowPanel('menu');
    };

    // ─── Crowdfund Sweep Handler ───
    if (el('btn-crowdfund-sweep')) {
        el('btn-crowdfund-sweep').onclick = async () => {
            const statusEl = el('crowdfund-sweep-status');
            statusEl.style.display = '';
            statusEl.textContent = 'Generating ZK proof...';

            try {
                const addrsText = el('crowdfund-sweep-addrs').value.trim();
                const dest = el('crowdfund-sweep-dest').value.trim();
                if (!addrsText) { toast('Enter contributor addresses', 'error'); return; }
                if (!dest) { toast('Enter sweep destination', 'error'); return; }

                const addrs = addrsText.split('\n').map(a => a.trim()).filter(a => a.length > 0);
                const wsUrl = await resolveNodeUrl();

                // Auto-add organizer's own covenant address
                if (lastCovenantResult && lastCovenantResult.address && !addrs.includes(lastCovenantResult.address)) {
                    addrs.unshift(lastCovenantResult.address);
                }

                // Fetch balance of each contributor P2SH
                const amounts = [];
                for (const addr of addrs) {
                    const utxosJson = await fetch_utxos_for_address_js(addr, wsUrl);
                    const utxos = JSON.parse(utxosJson);
                    const total = utxos.reduce((s, u) => s + BigInt(u.amount || 0), 0n);
                    amounts.push(total);
                    statusEl.textContent = 'Fetched ' + amounts.length + '/' + addrs.length + ' balances...';
                }

                const totalSompi = amounts.reduce((s, a) => s + a, 0n);
                statusEl.textContent = 'Total: ' + (Number(totalSompi) / 1e8).toFixed(4) + ' KAS. Generating proof...';

                if (!window._crowdfundPk || !window._crowdfundVk) {
                    toast('Run ZK Trusted Setup first', 'error'); return;
                }

                // Hand-built integer literals: JSON.stringify throws on BigInt,
                // and serde's Vec<u64> on the wasm side reads unquoted integer
                // literals exactly to u64. Identical wire format below 2^53,
                // exact above it, where Number() used to round.
                const amountsJson = '[' + amounts.map(a => a.toString()).join(',') + ']';
                const proofResult = JSON.parse(zk_crowdfund_prove(window._crowdfundPk, window._crowdfundVk, amountsJson));

                if (!proofResult.verified) {
                    toast('ZK proof verification failed locally', 'error'); return;
                }

                statusEl.textContent = 'Proof OK. Building commitment for KaSigner...';

                // Build commitment message: blake2b(destination + totalSompi + campaign_vk_hash)
                const commitmentParts = dest + ':' + totalSompi.toString() + ':' + (window._crowdfundVk || '').substring(0, 64);
                const commitmentHex = Array.from(new TextEncoder().encode(commitmentParts), b => b.toString(16).padStart(2, '0')).join('');
                let commitmentMsgHex;
                try {
                    commitmentMsgHex = blake2b_hash(commitmentHex);
                } catch (e) {
                    toast('Failed to hash commitment: ' + e, 'error'); return;
                }
                console.log('[KasSee] Sweep commitment msg:', commitmentMsgHex);

                // Get commitment signature from KaSigner
                statusEl.textContent = 'Show this QR to KaSigner for signing...';

                // Display commitment hash as QR for KaSigner to scan
                const qrContainer = el('qr-container');
                // NOTE: single-frame QR, no stopQrCycle() here. Same stale multi-frame bleed risk the adaptor invite/response had (fixed). Add stopQrCycle() if it recurs.
                const qrSvg = generate_qr_svg_text(commitmentMsgHex);
                qrContainer.innerHTML = qrSvg;
                el('qr-frame-info').innerHTML = '<span style="color:var(--teal);font-size:12px">Show this QR to KaSigner. Tap SIGN HASH on device.</span>';
                showScreen('qr-display');
                // Hide existing buttons that don't apply here
                const existingBtns = document.querySelectorAll('#screen-qr-display .btn');
                existingBtns.forEach(b => { if (b.id !== 'btn-crowdfund-scan-sig') b.style.display = 'none'; });
                // Add scan button
                const btnArea = el('qr-frame-info');
                btnArea.innerHTML += '<div style="margin-top:16px;text-align:center">' +
                    '<button id="btn-crowdfund-scan-sig" class="btn btn-primary" style="width:90%;max-width:340px;font-size:15px;padding:14px;margin:0 auto;display:block">' +
                    'Scan Signature from KaSigner</button></div>';

                // Wait for user to scan the signature QR back from KaSigner
                const commitmentSigHex = await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        reject('Signature scan timeout (120s)');
                    }, 120000);

                    el('btn-crowdfund-scan-sig').onclick = () => {
                        startScanner('Scan KaSigner Signature QR', (data) => {
                            const raw = new Uint8Array(data);
                            if (raw.length === 96) {
                                // 64 bytes sig + 32 bytes hash (same as oracle attestation)
                                const sig = Array.from(raw.slice(0, 64)).map(b => b.toString(16).padStart(2, '0')).join('');
                                const hash = Array.from(raw.slice(64, 96)).map(b => b.toString(16).padStart(2, '0')).join('');
                                if (hash === commitmentMsgHex) {
                                    clearTimeout(timeout);
                                    stopScanner();
                                    resolve(sig);
                                } else {
                                    toast('Hash mismatch. Wrong signature.', 'error');
                                }
                            } else {
                                // Try hex string format
                                const text = new TextDecoder().decode(raw).trim();
                                if (text.length === 128) {
                                    clearTimeout(timeout);
                                    stopScanner();
                                    resolve(text);
                                }
                            }
                        });
                    };
                });

                console.log('[KasSee] Commitment sig from KaSigner:', commitmentSigHex.substring(0, 20) + '...');
                // Restore hidden QR display buttons
                document.querySelectorAll('#screen-qr-display .btn').forEach(b => b.style.display = '');
                showScreen('covenant');

                statusEl.textContent = 'Sweeping ' + addrs.length + ' contributors...';

                // Load redeem script map for multi-contributor support
                let redeemMap = {};
                try { redeemMap = JSON.parse(localStorage.getItem('crowdfundRedeemMap') || '{}'); } catch (_) {}

                let successCount = 0;
                for (let i = 0; i < addrs.length; i++) {
                    statusEl.textContent = 'Sweeping ' + (i + 1) + '/' + addrs.length + '...';
                    // Per-address redeem script: check map first, fallback to organizer's own
                    const redeemHex = redeemMap[addrs[i]]
                        || (lastCovenantResult && lastCovenantResult.redeem_script_hex)
                        || '';
                    if (!redeemHex) {
                        console.log('[KasSee] No redeem script for', addrs[i]);
                        continue;
                    }
                    try {
                        const result = await create_crowdfund_sweep(
                            addrs[i], dest,
                            redeemHex,
                            proofResult.proof_hex,
                            proofResult.public_input_hex,
                            window._crowdfundVk,
                            commitmentSigHex,
                            commitmentMsgHex,
                            BigInt(400000),
                            wsUrl,
                        );
                        successCount++;
                        console.log('[KasSee] Sweep OK for', addrs[i].substring(0, 25));
                    } catch (e) {
                        console.log('[KasSee] Sweep failed for', addrs[i], '' + e);
                    }
                }

                statusEl.textContent = 'Done: ' + successCount + '/' + addrs.length + ' swept. ' + (totalSompi / 1e8).toFixed(4) + ' KAS';
                toast('Crowdfund sweep: ' + successCount + '/' + addrs.length, 'ok', 5000);
                // Refresh covenant balance after sweep
                setTimeout(() => { if (el('btn-cov-res-balance')) el('btn-cov-res-balance').click(); }, 1000);

            } catch (e) {
                statusEl.textContent = 'Failed: ' + e;
                toast('Sweep failed: ' + e, 'error');
            }
        };
    }

    // ─── Atomic Swap QR Invite ───
    if (el('btn-cov-res-share-swap')) {
        el('btn-cov-res-share-swap').onclick = () => {
            if (!lastCovenantResult || lastCovenantResult.type !== 'atomic-swap') return;
            const r = lastCovenantResult;
            const ownerPk = getOwnerPubkeyHex();
            const invite = JSON.stringify({
                v: 1, t: 'swap-invite',
                pk: ownerPk,
                h: r.expected_hash || '',
                a: r.hash_algo || 'blake2b',
                d: r.locktime_daa ? Number(r.locktime_daa) : 0,
                addr: r.address || '',
                rs: r.redeem_script_hex || ''
            });
            try {
                // NOTE: single-frame QR, no stopQrCycle() here. Same stale multi-frame bleed risk the adaptor invite/response had (fixed). Add stopQrCycle() if it recurs.
                const svg = generate_qr_svg_text(invite);
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Swap Invite \u2014 counterparty scans this';
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                _broadcastReturnScreen = 'covenant';
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
            } catch (e) {
                toast('QR generation failed: ' + e, 'error');
            }
        };
    }
    if (el('btn-cov-res-scan-swap')) {
        el('btn-cov-res-scan-swap').onclick = () => {
            startScanner('Scan Counterparty Swap Invite', (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || invite.t !== 'swap-invite') { toast('Not a swap invite QR', 'error'); return; }
                    stopScanner();
                    // Store counterparty info for claim
                    _swapCounterpartyInvite = invite;
                    swapStateSave();
                    if (lastCovenantResult) {
                        lastCovenantResult._counterparty_addr = invite.addr || '';
                        lastCovenantResult._counterparty_pk = invite.pk || '';
                    }
                    // Pre-fill claim panel with counterparty's covenant address
                    if (invite.addr) el('cov-claim-addr').value = invite.addr;
                    // Fill counterparty's redeem script (not our own)
                    if (invite.rs) {
                        el('cov-claim-script').value = invite.rs;
                    }
                    // Pre-fill destination with user's receive address
                    if (el('cov-claim-dest') && walletData && walletData.receive_addresses && walletData.receive_addresses.length > 0) {
                        // Destination address left empty for user to fill
                    }
                    // Navigate to covenant screen and open claim panel
                    showScreen('covenant');
                    covShowPanel('atomic-claim');
                    // Trigger balance auto-fetch
                    if (el('cov-claim-addr')) el('cov-claim-addr').dispatchEvent(new Event('input'));
                    toast('Counterparty invite loaded. Enter your preimage to claim.', 'ok', 3000);
                    console.log('[KasSee] Scanned counterparty swap invite:', invite);
                } catch (e) {
                    toast('Invalid swap invite QR: ' + e, 'error');
                }
            });
        };
    }
    // Generic covenant invite share (DMS, Vault, Escrow, etc.)
    if (el('btn-cov-res-share-cov')) {
        el('btn-cov-res-share-cov').onclick = () => {
            if (!lastCovenantResult) return;
            const r = lastCovenantResult;
            const ct = r.type || '';
            // Piggy bank: share just the covenant address as a simple QR
            if (ct === 'additive') {
                try {
                    pauseQrCycle();
                    const svg = generate_qr_svg_text(r.address || '');
                    el('qr-container').innerHTML = svg;
                    el('qr-frame-info').innerHTML = '<div style="text-align:center;font-size:12px;color:var(--text-dim);margin:8px 0">'
                        + 'Piggy Bank Address<br><span style="font-size:10px;word-break:break-all">' + (r.address || '') + '</span>'
                        + '<br><span style="font-size:10px;color:var(--text-muted)">Anyone can send KAS to this address</span></div>';
                    if (el('qr-display-title')) el('qr-display-title').textContent = 'Share Piggy Bank Address';
                    if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                    if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = 'none';
                    if (el('btn-copy-kspt')) el('btn-copy-kspt').style.display = 'none';
                    if (el('btn-scan-next-sig')) el('btn-scan-next-sig').style.display = 'none';
                    _broadcastReturnScreen = 'covenant';
                    showScreen('qr-display');
                } catch (e) { toast('QR error: ' + e, 'error'); }
                return;
            }
            const invite = {
                v: 1, t: 'cov-invite', ct: ct,
                addr: r.address || '',
                rs: r.redeem_script_hex || '',
                d: r.locktime_daa ? Number(r.locktime_daa) : 0
            };
            // DMS: include inactivity period so heir's watcher can show countdown
            if (ct === 'dms' && r.inactivity_daa) invite.id = Number(r.inactivity_daa);
            // Savings: include both wallet pubkeys (rs already encodes them) and the
            // unlock date for nicer display on the receiving (recovery) wallet.
            if (ct === 'timelocked-savings') {
                if (r.wallet1_pubkey_hex) invite.w1 = r.wallet1_pubkey_hex;
                if (r.wallet2_pubkey_hex) invite.w2 = r.wallet2_pubkey_hex;
                if (r.locktime_date_iso) invite.ldi = r.locktime_date_iso;
            }
            // Allowance: include max withdrawal and cooldown for beneficiary UX
            if (ct === 'global-allowance') {
                if (r.max_withdraw_sompi) invite.mw = String(r.max_withdraw_sompi);
                invite.cd = Number(r.cooldown_daa || r.min_sequence || 0);
                if (r.start_daa) invite.sd = Number(r.start_daa);
                if (r.start_date_iso) invite.sdi = r.start_date_iso;
            }
            // Oracle: include all three pubkeys so receiver auto-detects role from kpub
            if (ct === 'oracle') {
                if (r.oracle_pubkey_hex) invite.opk = r.oracle_pubkey_hex;
                if (r.beneficiary_pubkey_hex) invite.bpk = r.beneficiary_pubkey_hex;
                if (r.owner_pubkey_hex) invite.own = r.owner_pubkey_hex;
                if (r.locktime_date_iso) invite.ldi = r.locktime_date_iso;
            }
            // Crowdfund: compact invite with campaign TXID, organizer pubkey, and name
            if (ct === 'crowdfund') {
                invite.goal = r.goal_kas || '';
                if (r.campaign_txid) invite.tx = r.campaign_txid;
                if (r.organizer_pk) invite.opk = r.organizer_pk;
                if (r.campaign_name) invite.name = r.campaign_name;
            }
            try {
                pauseQrCycle();
                const svg = generate_qr_svg_text(JSON.stringify(invite));
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Covenant Invite QR';
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = 'none';
                _broadcastReturnScreen = 'covenant';
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
            } catch (e) {
                toast('QR generation failed: ' + e, 'error');
            }
        };
    }
    // Oracle: share request with oracle (different invite type)
    if (el('btn-cov-res-share-oracle')) {
        el('btn-cov-res-share-oracle').onclick = () => {
            if (!lastCovenantResult) return;
            const r = lastCovenantResult;
            if (r.type !== 'oracle') return;
            const request = {
                v: 1, t: 'cov-invite', ct: 'oracle',
                addr: r.address || '',
                rs: r.redeem_script_hex || '',
                d: r.locktime_daa ? Number(r.locktime_daa) : 0,
                opk: r.oracle_pubkey_hex || '',
                bpk: r.beneficiary_pubkey_hex || '',
                own: r.owner_pubkey_hex || ''
            };
            try {
                pauseQrCycle();
                const svg = generate_qr_svg_text(JSON.stringify(request));
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Oracle Request \u2014 oracle scans this';
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                _broadcastReturnScreen = 'covenant';
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
            } catch (e) {
                toast('QR generation failed: ' + e, 'error');
            }
        };
    }
    // Scan Swap Invite on creation form (Bob scans Alice's invite)
    if (el('btn-cov-scan-swap-invite')) {
        el('btn-cov-scan-swap-invite').onclick = () => {
            startScanner('Scan Swap Invite from counterparty', (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || invite.t !== 'swap-invite') { toast('Not a swap invite QR', 'error'); return; }
                    stopScanner();
                    showScreen('covenant');
                    covShowPanel('create');
                    // Make sure atomic-swap fields are visible
                    if (el('cov-type')) el('cov-type').value = 'atomic-swap';
                    document.querySelectorAll('[id^="cov-fields-"]').forEach(f => f.classList.add('hidden'));
                    if (el('cov-fields-atomic-swap')) el('cov-fields-atomic-swap').classList.remove('hidden');
                    _swapCounterpartyInvite = invite;
                    swapStateSave();
                    // Fill in counterparty pubkey
                    if (invite.pk) el('cov-swap-pk').value = invite.pk;
                    // Fill in hash and algo
                    if (invite.h) el('cov-swap-hash').value = invite.h;
                    if (invite.a && el('cov-swap-hash-algo')) el('cov-swap-hash-algo').value = invite.a;
                    // Suggest a shorter timeout (half of Alice's remaining time from now)
                    if (invite.d && invite.d > 0) {
                        const currentDaa = estimateCurrentDaaFromUtxos();
                        if (currentDaa > 0) {
                            const remaining = invite.d - currentDaa;
                            const halfRemaining = Math.floor(remaining / 2);
                            if (halfRemaining > 0) {
                                const suggestedDaa = currentDaa + halfRemaining;
                                el('cov-swap-locktime').value = String(suggestedDaa);
                                // Also set the datetime picker roughly
                                const secondsFromNow = halfRemaining / 10;
                                const targetDate = new Date(Date.now() + secondsFromNow * 1000);
                                const localIso = targetDate.getFullYear() + '-' + String(targetDate.getMonth()+1).padStart(2,'0') + '-' + String(targetDate.getDate()).padStart(2,'0') + 'T' + String(targetDate.getHours()).padStart(2,'0') + ':' + String(targetDate.getMinutes()).padStart(2,'0');
                                el('cov-swap-datetime').value = localIso;
                                if (el('cov-swap-daa-preview')) el('cov-swap-daa-preview').textContent = 'DAA ~' + suggestedDaa.toLocaleString() + ' (half of counterparty)';
                            }
                        }
                    }
                    // Disable preimage field (Bob doesn't know it, only the hash)
                    el('cov-swap-preimage').value = '';
                    el('cov-swap-preimage').placeholder = 'Not needed — you will learn it when counterparty claims';
                    toast('Swap invite loaded. Hash + counterparty filled.', 'ok', 3000);
                    console.log('[KasSee] Loaded swap invite on creation form:', invite);
                } catch (e) {
                    toast('Invalid swap invite QR: ' + e, 'error');
                }
            });
        };
    }
    if (el('btn-cov-owner-spend')) el('btn-cov-owner-spend').onclick = () => {
        covShowPanel('owner');
        if (lastCovenantResult) {
            el('cov-owner-addr').value = lastCovenantResult.address || '';
            el('cov-owner-script').value = lastCovenantResult.redeem_script_hex || '';
            // DMS heartbeat: send back to same covenant address to reset CSV timer
            if (lastCovenantResult.type === 'dms') {
                el('cov-owner-dest').value = lastCovenantResult.address || '';
            }
        }
    };
    el('btn-cov-owner-back').onclick = () => {
        if (lastCovenantResult && lastCovenantResult.type === 'adaptor-swap' && _adaptorState) {
            covShowPanel('adaptor-result');
        } else if (lastCovenantResult) {
            covShowPanel('result');
        } else {
            covShowPanel('menu');
        }
    };
    if (el('btn-cov-borrower-spend')) el('btn-cov-borrower-spend').onclick = () => {
        covShowPanel('borrower');
        if (lastCovenantResult) {
            el('cov-borrower-addr').value = lastCovenantResult.address || '';
            el('cov-borrower-script').value = lastCovenantResult.redeem_script_hex || '';
        }
    };
    el('btn-cov-borrower-back').onclick = () => covShowPanel(lastCovenantResult ? 'result' : 'menu');
    if (el('btn-cov-beneficiary-spend')) el('btn-cov-beneficiary-spend').onclick = () => {
        covShowPanel('beneficiary');
        if (lastCovenantResult) {
            el('cov-bene-addr').value = lastCovenantResult.address || '';
            el('cov-bene-script').value = lastCovenantResult.redeem_script_hex || '';
            if (lastCovenantResult.locktime_daa) {
                el('cov-bene-locktime').value = lastCovenantResult.locktime_daa;
            }
            // For escrow: auto-fill destination from parsed script.
            try {
                const rs = lastCovenantResult.redeem_script_hex || '';
                if (rs.length > 200) {
                    const parsed = parseEscrowScript(rs);
                    // Bob (seller) claiming: destination is alice's address
                    if (parsed.alice_spk_hex) {
                        const aliceAddr = encode_p2pk_address(parsed.alice_spk_hex, network);
                        el('cov-bene-dest').value = aliceAddr;
                    }
                }
            } catch (e) {
                console.log('[KasSee] Could not auto-fill escrow destination:', e);
            }
        }
    };
    el('btn-cov-bene-back').onclick = () => covShowPanel('menu');
    el('btn-cov-bene-create').onclick = () => handleCovBeneficiarySpend();
    if (el('btn-cov-bene-pick')) {
        el('btn-cov-bene-pick').onclick = async () => {
            // Claim only the selected UTXOs (batched). Dest is the claiming wallet's
            // address; locktime comes from the claim setup.
            const dest = (el('cov-bene-dest') ? el('cov-bene-dest').value.trim() : '') || ownerReceiveAddr();
            const lt = el('cov-bene-locktime') ? (el('cov-bene-locktime').value.trim() || '0') : '0';
            // Savings pre-flight: block before opening the picker if still locked,
            // using a LIVE DAA fetch (the picker confirm is sync, so the cached
            // _lastKnownDaa is unreliable there). The node rejects an early claim.
            if ((lastCovenantResult && lastCovenantResult.type) === 'timelocked-savings') {
                const lockN = parseInt(lt || '0');
                if (lockN > 0) {
                    const curDaa = await fetchCurrentDaa();
                    if (curDaa > 0 && curDaa < lockN) {
                        const eta = formatDuration(Math.floor((lockN - curDaa) / 10));
                        toast('Still locked. Unlocks in ~' + eta + '. An early claim is rejected by the node.', 'error', 5000);
                        return;
                    }
                }
            } else if ((lastCovenantResult && lastCovenantResult.type) === 'dms') {
                // DMS heir claim is gated by CSV (per-UTXO age). The OLDEST UTXO ages
                // first, so block only when not even that one has cleared the inactivity
                // period (nothing is claimable yet). Once at least one has aged, allow
                // the heir to batch-claim the aged UTXOs in the picker.
                const _inact = lastCovenantResult.inactivity_daa ? Number(lastCovenantResult.inactivity_daa) : 0;
                if (_inact > 0) {
                    const curDaa = await fetchCurrentDaa();
                    let _utxos = [];
                    try { _utxos = JSON.parse(await fetch_utxos_for_address_js(lastCovenantResult.address, await resolveNodeUrl())); } catch (_) {}
                    if (curDaa > 0 && _utxos.length) {
                        let _oldest = Infinity;
                        for (const u of _utxos) { const d = Number(u.block_daa_score || 0); if (d > 0 && d < _oldest) _oldest = d; }
                        if (_oldest !== Infinity && curDaa < _oldest + _inact) {
                            const eta = formatDuration(Math.floor((_oldest + _inact - curDaa) / 10));
                            toast('Still locked. No vault UTXO has aged past the inactivity period yet. The heir can claim in ~' + eta + '. The node rejects an early claim.', 'error', 6000);
                            return;
                        }
                    }
                }
            }
            openUtxoPicker(dest, { locktime: lt });
        };
    }
    if (el('btn-cov-timeout-refund')) el('btn-cov-timeout-refund').onclick = () => {
        covShowPanel('timeout');
        if (lastCovenantResult) {
            el('cov-timeout-addr').value = lastCovenantResult.address || '';
            el('cov-timeout-script').value = lastCovenantResult.redeem_script_hex || '';
            if (lastCovenantResult.locktime_daa) {
                el('cov-timeout-locktime').value = lastCovenantResult.locktime_daa;
            }
        }
    };
    el('btn-cov-timeout-back').onclick = () => covShowPanel('menu');
    el('btn-cov-timeout-create').onclick = () => handleCovTimeoutRefund();
    if (el('btn-cov-atomic-claim')) el('btn-cov-atomic-claim').onclick = () => covShowPanel('atomic-claim');
    el('btn-cov-claim-back').onclick = () => {
        if (lastCovenantResult && lastCovenantResult.type === 'atomic-swap') covShowPanel('result');
        else if (lastCovenantResult) covShowPanel('result');
        else covShowPanel('menu');
    };
    el('btn-cov-claim-create').onclick = () => handleCovAtomicClaim();
    // Scan preimage QR (from counterparty's broadcast screen)
    if (el('btn-cov-scan-preimage')) {
        el('btn-cov-scan-preimage').onclick = () => {
            startScanner('Scan Preimage QR', (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    let preimage = '';
                    try {
                        const obj = JSON.parse(text);
                        if (obj && obj.t === 'swap-preimage' && obj.p) {
                            preimage = obj.p;
                        }
                    } catch (_) {
                        preimage = text;
                    }
                    if (preimage) {
                        stopScanner();
                        showScreen('covenant');
                        covShowPanel('atomic-claim');
                        el('cov-claim-preimage').value = preimage;
                        toast('Preimage scanned: ' + preimage, 'ok', 3000);
                    } else {
                        toast('Not a preimage QR', 'error');
                    }
                } catch (e) {
                    toast('Scan error: ' + e, 'error');
                }
            });
        };
    }
    // Claim panel fee picker
    document.querySelectorAll('.cov-fee-btn[data-panel="claim"]').forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.cov-fee-btn[data-panel="claim"]').forEach(b => b.classList.remove('cov-fee-active'));
            btn.classList.add('cov-fee-active');
            if (el('cov-claim-fee')) el('cov-claim-fee').value = btn.dataset.fee;
        };
    });
    // Auto-fetch balance when claim address changes
    if (el('cov-claim-addr')) {
        let claimBalTimer = null;
        el('cov-claim-addr').oninput = () => {
            clearTimeout(claimBalTimer);
            claimBalTimer = setTimeout(async () => {
                const addr = el('cov-claim-addr').value.trim();
                const balEl = el('cov-claim-balance');
                if (!balEl) return;
                if (!addr || (!addr.startsWith('kaspa:') && !addr.startsWith('kaspatest:'))) { balEl.style.display = 'none'; return; }
                try {
                    const wsUrl = await resolveNodeUrl();
                    const utxosJson = await fetch_utxos_for_address_js(addr, wsUrl);
                    const utxos = JSON.parse(utxosJson);
                    const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
                    balEl.textContent = 'Balance: ' + (Number(total) / 1e8).toFixed(4) + ' KAS (' + utxos.length + ' UTXOs)';
                    balEl.style.display = '';
                } catch (_) { balEl.style.display = 'none'; }
            }, 600);
        };
    }
    el('btn-cov-scan-claim-addr').onclick = () => covScanAddress('cov-claim-addr', 'Scan covenant address');
    el('btn-cov-scan-claim-dest').onclick = () => covScanAddress('cov-claim-dest', 'Scan destination');
    if (el('btn-cov-scan-dms2-heir')) el('btn-cov-scan-dms2-heir').onclick = () => covScanAddress('cov-dms2-heir-pk', 'Scan heir address', true);
    if (el('cov-dms2-preset')) {
        const dms2RecalcCustom = () => {
            const y = parseInt(el('cov-dms2-years').value) || 0;
            const mo = parseInt(el('cov-dms2-months').value) || 0;
            const d = parseInt(el('cov-dms2-days').value) || 0;
            const h = parseInt(el('cov-dms2-hours').value) || 0;
            const mi = parseInt(el('cov-dms2-mins').value) || 0;
            const total = y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60;
            el('cov-dms2-duration').value = total > 0 ? total : '';
        };
        el('cov-dms2-preset').onchange = () => {
            const v = el('cov-dms2-preset').value;
            const customWrap = el('cov-dms2-custom-wrap');
            if (customWrap) customWrap.classList.toggle('hidden', v !== 'custom');
            if (v !== 'custom') el('cov-dms2-duration').value = v;
        };
        ['cov-dms2-years','cov-dms2-months','cov-dms2-days','cov-dms2-hours','cov-dms2-mins'].forEach(id => {
            if (el(id)) el(id).oninput = dms2RecalcCustom;
        });
        // Custom is default; no duration pre-fill. User picks a preset or opens Custom rolling inputs.
        if (el('cov-dms2-preset').value !== 'custom') {
            el('cov-dms2-duration').value = el('cov-dms2-preset').value;
        }
    }
    // Spending-limit cooldown preset + custom timer
    if (el('cov-splimit-preset')) {
        const splimitRecalcCustom = () => {
            const y = parseInt(el('cov-splimit-years').value) || 0;
            const mo = parseInt(el('cov-splimit-months').value) || 0;
            const d = parseInt(el('cov-splimit-days').value) || 0;
            const h = parseInt(el('cov-splimit-hours').value) || 0;
            const mi = parseInt(el('cov-splimit-mins').value) || 0;
            const total = y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60;
            el('cov-splimit-cooldown').value = total > 0 ? total : '';
        };
        el('cov-splimit-preset').onchange = () => {
            const v = el('cov-splimit-preset').value;
            const customWrap = el('cov-splimit-custom-wrap');
            if (customWrap) customWrap.classList.toggle('hidden', v !== 'custom');
            if (v !== 'custom') el('cov-splimit-cooldown').value = v;
        };
        ['cov-splimit-years','cov-splimit-months','cov-splimit-days','cov-splimit-hours','cov-splimit-mins'].forEach(id => {
            if (el(id)) el(id).oninput = splimitRecalcCustom;
        });
    }
    if (el('btn-cov-scan-bene-addr')) el('btn-cov-scan-bene-addr').onclick = () => covScanAddress('cov-bene-addr', 'Scan covenant address');
    if (el('btn-cov-scan-bene-dest')) el('btn-cov-scan-bene-dest').onclick = () => covScanAddress('cov-bene-dest', 'Scan destination');
    el('btn-cov-generate').onclick = () => handleCovGenerate();
    el('btn-cov-fund').onclick = () => handleCovFund();

    // Crowdfund role tabs
    if (el('btn-crowdfund-role-organizer')) {
        el('btn-crowdfund-role-organizer').onclick = () => {
            el('crowdfund-organizer-fields').style.display = '';
            el('crowdfund-contributor-fields').style.display = 'none';
            el('btn-crowdfund-role-organizer').className = 'btn btn-primary';
            el('btn-crowdfund-role-contributor').className = 'btn btn-outline';
        };
        el('btn-crowdfund-role-contributor').onclick = () => {
            el('crowdfund-organizer-fields').style.display = 'none';
            el('crowdfund-contributor-fields').style.display = '';
            el('btn-crowdfund-role-organizer').className = 'btn btn-outline';
            el('btn-crowdfund-role-contributor').className = 'btn btn-primary';
            // Auto-fill VK if available from setup or localStorage
            if (window._crowdfundVk && el('cov-crowdfund-vk') && !el('cov-crowdfund-vk').value) {
                el('cov-crowdfund-vk').value = window._crowdfundVk;
            }
            // Auto-fill locktime from organizer's hidden field on same device
            const orgLocktime = el('cov-crowdfund-locktime') ? el('cov-crowdfund-locktime').value : '';
            if (orgLocktime && el('cov-crowdfund-contrib-locktime') && !el('cov-crowdfund-contrib-locktime').value) {
                el('cov-crowdfund-contrib-locktime').value = orgLocktime;
            }
        };
    }
    // Crowdfund ZK trusted setup
    if (el('btn-crowdfund-setup')) {
        el('btn-crowdfund-setup').onclick = async () => {
            const statusEl = el('crowdfund-setup-status');
            statusEl.textContent = 'Running trusted setup...';
            statusEl.style.display = '';
            try {
                const resultJson = zk_crowdfund_setup();
                const result = JSON.parse(resultJson);
                window._crowdfundPk = result.pk_hex;
                window._crowdfundVk = result.vk_hex;
                try { localStorage.setItem('crowdfundPk', result.pk_hex); } catch (_) {}
                try { localStorage.setItem('crowdfundVk', result.vk_hex); } catch (_) {}
                // Organizer pubkey for dual-gate CHECKSIGFROMSTACK
                // Use the account-level pubkey (matches KaSigner's signing key)
                const orgPk = getAccountPubkeyHex();
                if (orgPk) {
                    window._crowdfundOrganizerPk = orgPk;
                    console.log('[KasSee] Organizer pk (account key):', orgPk);
                } else {
                    console.log('[KasSee] No wallet loaded, organizer pk not set');
                }
                statusEl.innerHTML = 'Setup complete. VK length: ' + result.vk_len + ' bytes<br>' +
                    '<textarea id="crowdfund-vk-display" readonly rows="3" style="width:100%;font-size:9px;margin:4px 0;background:var(--surface);color:var(--teal);border:1px solid var(--border);padding:4px;resize:none">' +
                    result.vk_hex + '</textarea>' +
                    '<button id="btn-crowdfund-copy-vk" class="btn btn-outline" style="font-size:11px;width:100%;margin:2px 0">Copy VK to clipboard</button>' +
                    '<button id="btn-crowdfund-copy-params" class="btn btn-outline" style="font-size:11px;width:100%;margin:2px 0">Copy all campaign params (VK + locktime)</button>';
                el('btn-crowdfund-copy-vk').onclick = () => {
                    navigator.clipboard.writeText(result.vk_hex).then(() => toast('VK copied', 'ok', 2000));
                };
                el('btn-crowdfund-copy-params').onclick = () => {
                    const locktime = el('cov-crowdfund-locktime').value || '(set deadline first)';
                    const goal = el('cov-crowdfund-goal').value || '(set goal first)';
                    const params = JSON.stringify({ vk: result.vk_hex, locktime_daa: locktime, goal_kas: goal });
                    navigator.clipboard.writeText(params).then(() => toast('Campaign params copied as JSON', 'ok', 2000));
                };
                toast('ZK crowdfund setup done. Share VK with contributors.', 'ok', 3000);
            } catch (e) {
                statusEl.textContent = 'Setup failed: ' + e;
                toast('Setup failed: ' + e, 'error');
            }
        };
    }
    el('btn-cov-res-balance').onclick = async () => {
        if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        const balEl = el('cov-result-balance');
        balEl.style.display = 'block';
        balEl.textContent = 'Loading...';
        try {
            const wsUrl = await resolveNodeUrl();
            const utxosJson = await fetch_utxos_for_address_js(lastCovenantResult.address, wsUrl);
            const utxos = JSON.parse(utxosJson);
            const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
            const kas = Number(total) / 1e8;
            const kasStr = kas === 0 ? '0' : kas.toFixed(8).replace(/\.?0+$/, '');
            balEl.textContent = kasStr + ' KAS (' + utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ')';
            // Piggy bank: toggle Deposit vs Add Funds on fundBtn based on UTXO count
            if (lastCovenantResult.type === 'additive') {
                const fundBtnP = el('btn-cov-fund');
                if (fundBtnP) {
                    if (utxos.length === 0) {
                        fundBtnP.textContent = 'Covenant Deposit';
                        fundBtnP.dataset.piggyMode = 'deposit';
                    } else {
                        fundBtnP.textContent = 'Add Funds';
                        fundBtnP.dataset.piggyMode = 'add';
                    }
                }
            }
        } catch (e) {
            balEl.textContent = 'Error: ' + e;
        }
    };
    el('btn-cov-res-owner').onclick = async () => {
        if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        const t = lastCovenantResult.type || '';
        // Escrow: buyer releases to seller, or arbiter awards to seller
        if (t === 'escrow') {
            const role = lastCovenantResult.role || '';
            const branch = (role === 'arbiter') ? 'arbiter-award-seller' : 'buyer-release';
            await handleEscrowSpend(branch);
            return;
        }
        // Deposit Account and Piggy Bank: use UTXO picker for withdrawals
        if (t === 'additive') {
            // Piggy bank with 1 UTXO: skip picker, go straight to owner sweep
            if (t === 'additive') {
                try {
                    const wsUrl = await resolveNodeUrl();
                    const utxosJson = await fetch_utxos_for_address_js(lastCovenantResult.address, wsUrl);
                    const utxos = JSON.parse(utxosJson);
                    if (utxos.length <= 1) {
                        covShowPanel('owner');
                        el('cov-owner-addr').value = lastCovenantResult.address || '';
                        el('cov-owner-script').value = lastCovenantResult.redeem_script_hex || '';
                        if (el('cov-owner-panel')) el('cov-owner-panel').dataset.covOwnerType = t;
                        // Live break-status banner: green if breakable now, red
                        // with the concrete reason(s) if neither condition holds.
                        try {
                            const _tot = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
                            const _f = getCovFee(utxos.length || 1);
                            const _st = await window.piggyBreakStatus(_tot, _f);
                            window.piggyStatusBanner(_st);
                        } catch (_) {}
                        const ownerHelpP = el('cov-owner-help');
                        if (ownerHelpP) {
                            const hasGoal = lastCovenantResult.threshold_sompi > 0;
                            const hasDeadline = lastCovenantResult.deadline_daa > 0;
                            if (hasGoal && hasDeadline) ownerHelpP.textContent = 'Break the piggy bank. Requires goal (' + (lastCovenantResult.threshold_sompi / 1e8) + ' KAS) to be reached OR the deadline to have passed.';
                            else if (hasGoal) ownerHelpP.textContent = 'Break the piggy bank. Requires goal (' + (lastCovenantResult.threshold_sompi / 1e8) + ' KAS) to be reached.';
                            else if (hasDeadline) ownerHelpP.textContent = 'Break the piggy bank. Requires the deadline to have passed.';
                            else ownerHelpP.textContent = 'Break the piggy bank. No conditions set. Can break anytime.';
                            ownerHelpP.style.display = '';
                        }
                        const createBtnP = el('btn-cov-owner-create');
                        if (createBtnP) createBtnP.textContent = 'Break Piggy Bank';
                        if (el('cov-owner-panel')) el('cov-owner-panel').dataset.covOwnerMode = '';
                        // Hide amount (always sweep), pre-fill dest
                        const amountRowP = el('cov-owner-amount');
                        const amountLabelP = amountRowP ? amountRowP.previousElementSibling : null;
                        if (amountRowP) { amountRowP.style.display = 'none'; amountRowP.value = ''; }
                        if (amountLabelP && amountLabelP.tagName === 'LABEL') amountLabelP.style.display = 'none';
                        const _ownAddr1 = ownerReceiveAddr();
                        if (_ownAddr1) el('cov-owner-dest').value = _ownAddr1;
                        el('cov-owner-dest').readOnly = false;
                        return;
                    }
                } catch (_) {}
            }
            const personalAddr = ownerReceiveAddr();
            openUtxoPicker(personalAddr);
            return;
        }
        covShowPanel('owner');
        el('cov-owner-addr').value = lastCovenantResult.address || '';
        el('cov-owner-script').value = lastCovenantResult.redeem_script_hex || '';
        if (el('cov-owner-panel')) el('cov-owner-panel').dataset.covOwnerType = t;
        // Show help text
        const ownerHelp = el('cov-owner-help');
        const createBtn = el('btn-cov-owner-create');
        if (ownerHelp) {
            const _cltvBannerTypes = { 'merkle-whitelist': 'only whitelisted spends are valid',
                                       'commit-reveal': 'only the reveal path is valid',
                                       'oracle': 'only the oracle-attested claim is valid',
                                       'payjoin': 'only the joint-spend path is valid',
                                       'adaptor-swap': 'only the counterparty claim is valid' };
            if (_cltvBannerTypes[t] && lastCovenantResult && lastCovenantResult.locktime_daa > 0) {
                // Owner reclaim on these types is CLTV-gated. Show the live
                // state up front so the user never builds a doomed TX.
                (async () => {
                    try {
                        let d = 0;
                        try { d = await fetchCurrentDaa(); } catch (_) {}
                        if (!d && typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) d = _lastKnownDaa;
                        const lt = Number(lastCovenantResult.locktime_daa);
                        if (d > 0 && d < lt) {
                            window.piggyStatusBanner({
                                text: 'Owner reclaim NOT available yet: timelock matures in ~' +
                                      formatDuration(Math.floor((lt - d) / 10)) +
                                      '. Until then ' + _cltvBannerTypes[t] + '.',
                                color: 'var(--error, #f44336)'
                            });
                        } else if (d > 0) {
                            window.piggyStatusBanner({
                                text: 'Timelock matured — owner reclaim available now.',
                                color: 'var(--accent, #4caf50)'
                            });
                        }
                    } catch (_) {}
                })();
            }
            if (t === 'global-allowance') {
                ownerHelp.textContent = 'Owner reclaim. Sweeps the whole thread back to your address via the free owner path (uncapped). To add funds, use Deposit and pick the wallet UTXOs to fold into the thread. Requires owner signature from your KasSigner.';
                ownerHelp.style.display = '';
            } else if (t === 'global-spending-limit') {
                const _capK = (lastCovenantResult && lastCovenantResult.max_withdraw_sompi) ? sompiToKasStr(lastCovenantResult.max_withdraw_sompi) : '0';
                ownerHelp.textContent = 'Withdraw up to the per-spend cap of ' + _capK + ' KAS from the single thread. Leave the amount empty to sweep all, which is allowed only when the balance is at or below the cap. To add funds, use Deposit and pick the wallet UTXOs to fold in (top-up merges whole UTXOs into the thread).';
                ownerHelp.style.display = '';
            } else if (t === 'dms') {
                ownerHelp.textContent = 'Heartbeat. Sends funds back to the same covenant address, resetting the CSV inactivity timer. Only costs a network fee.';
                ownerHelp.style.display = '';
            } else if (t === 'additive') {
                const hasGoal = lastCovenantResult && lastCovenantResult.threshold_sompi > 0;
                const hasDeadline = lastCovenantResult && lastCovenantResult.deadline_daa > 0;
                if (hasGoal && hasDeadline) {
                    ownerHelp.textContent = 'Break the piggy bank. Requires goal (' + (lastCovenantResult.threshold_sompi / 1e8) + ' KAS) to be reached OR the deadline to have passed.';
                } else if (hasGoal) {
                    ownerHelp.textContent = 'Break the piggy bank. Requires goal (' + (lastCovenantResult.threshold_sompi / 1e8) + ' KAS) to be reached.';
                } else if (hasDeadline) {
                    ownerHelp.textContent = 'Break the piggy bank. Requires the deadline to have passed.';
                } else {
                    ownerHelp.textContent = 'Break the piggy bank. No conditions set. Can break anytime.';
                }
                ownerHelp.style.display = '';
            } else {
                ownerHelp.style.display = 'none';
            }
        }
        // Dynamic button label (fix #14)
        if (createBtn) {
            if (t === 'dms') createBtn.textContent = 'Create Heartbeat TX';
            else if (t === 'additive') createBtn.textContent = 'Break Piggy Bank';
            else createBtn.textContent = 'Create Owner Spend TX';
        }
        // Track owner mode for DMS
        if (el('cov-owner-panel')) el('cov-owner-panel').dataset.covOwnerMode = (t === 'dms') ? 'heartbeat' : '';
        // Hide amount field for types that always sweep
        const amountRow = el('cov-owner-amount');
        const amountLabel = amountRow ? amountRow.previousElementSibling : null;
        if (t === 'additive' || t === 'global-allowance') {
            if (amountRow) amountRow.style.display = 'none';
            if (amountLabel && amountLabel.tagName === 'LABEL') amountLabel.style.display = 'none';
            if (amountRow) amountRow.value = '';
        } else {
            if (amountRow) amountRow.style.display = '';
            if (amountLabel && amountLabel.tagName === 'LABEL') { amountLabel.style.display = ''; amountLabel.textContent = 'Amount (KAS) \u2014 leave empty to sweep all'; }
            // Surface the per-spend cap in the placeholder for capped thread spends.
            if (amountRow) {
                amountRow.placeholder = (t === 'global-spending-limit' && lastCovenantResult && lastCovenantResult.max_withdraw_sompi)
                    ? 'Max ' + sompiToKasStr(lastCovenantResult.max_withdraw_sompi) + ' KAS, empty = sweep all'
                    : 'Empty = sweep all';
            }
        }
        // Optional UTXO picker on the owner reclaim screen: full-sweep types
        // (vault, DMS, vesting) sweep every UTXO by default, but a many-UTXO sweep
        // can make too large a QR for KasSigner or hit a forming/fee issue, so this
        // lets the user pick a subset / batch. Single-thread types use dedicated
        // thread builders and stay sweep-all.
        const ownerConsolBtn = el('btn-cov-owner-consolidate');
        if (ownerConsolBtn) {
            const _showPicker = (t === 'dms');
            ownerConsolBtn.style.display = _showPicker ? '' : 'none';
            if (_showPicker) ownerConsolBtn.textContent = (t === 'dms')
                ? 'Consolidate UTXOs (batched heartbeat)'
                : 'Select UTXO(s) to sweep (advanced)';
        }
        // Pre-fill destination for types where owner is the recipient
        if (t === 'additive' || t === 'global-allowance') {
            const _own = ownerReceiveAddr();
            if (_own) el('cov-owner-dest').value = _own;
        }
        // DMS heartbeat: send back to same covenant address, hide amount field, make dest read-only
        if (t === 'dms') {
            el('cov-owner-dest').value = lastCovenantResult.address || '';
            el('cov-owner-dest').readOnly = true;
            if (amountRow) amountRow.style.display = 'none';
            if (amountLabel && amountLabel.tagName === 'LABEL') amountLabel.style.display = 'none';
            if (amountRow) amountRow.value = '';
        } else {
            el('cov-owner-dest').readOnly = false;
        }
    };
    el('btn-cov-res-bene').onclick = async () => {
        if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        const t = lastCovenantResult.type || '';
        // Escrow: seller refunds to buyer, or arbiter refunds to buyer
        if (t === 'escrow') {
            const role = lastCovenantResult.role || '';
            const branch = (role === 'arbiter') ? 'arbiter-refund-buyer' : 'seller-refund';
            await handleEscrowSpend(branch);
            return;
        }
        // DMS owner withdraw: opens owner panel with personal destination, amount visible
        if (t === 'dms' && lastCovenantResult.role !== 'beneficiary') {
            covShowPanel('owner');
            el('cov-owner-addr').value = lastCovenantResult.address || '';
            el('cov-owner-script').value = lastCovenantResult.redeem_script_hex || '';
            if (el('cov-owner-panel')) {
                el('cov-owner-panel').dataset.covOwnerType = t;
                el('cov-owner-panel').dataset.covOwnerMode = 'withdraw';
            }
            const amountRow = el('cov-owner-amount');
            const amountLabel = amountRow ? amountRow.previousElementSibling : null;
            if (amountRow) { amountRow.style.display = ''; amountRow.value = ''; }
            if (amountLabel && amountLabel.tagName === 'LABEL') { amountLabel.style.display = ''; amountLabel.textContent = 'Amount (KAS) \u2014 leave empty to sweep all'; }
            // Pre-fill destination with personal address
            el('cov-owner-dest').value = ownerReceiveAddr();
            el('cov-owner-dest').readOnly = false;
            const ownerHelp = el('cov-owner-help');
            if (ownerHelp) {
                ownerHelp.textContent = 'Withdraw funds from the DMS covenant. Sends to a personal address. Requires owner signature from your KasSigner.';
                ownerHelp.style.display = '';
            }
            const createBtn = el('btn-cov-owner-create');
            if (createBtn) createBtn.textContent = 'Create Withdrawal TX';
            // The advanced picker on this screen is a batched WITHDRAW (cov-owner-dest
            // is the owner's personal address), so label it that way. On the heartbeat
            // screen the same button is the batched consolidation heartbeat.
            const consolBtn = el('btn-cov-owner-consolidate');
            if (consolBtn) { consolBtn.style.display = ''; consolBtn.textContent = 'Select UTXO(s) to withdraw'; }
            return;
        }
        if (t === 'oracle') {
            covShowPanel('oracle-claim');
            el('cov-oracle-claim-addr').value = lastCovenantResult.address || '';
            el('cov-oracle-claim-script').value = lastCovenantResult.redeem_script_hex || '';
            el('cov-oracle-claim-sig').value = '';
            el('cov-oracle-claim-hash').value = '';
            el('cov-oracle-claim-dest').value = '';
            const attTextEl = el('cov-oracle-claim-attest-text');
            if (attTextEl) { attTextEl.textContent = ''; attTextEl.style.display = 'none'; }
            // Restore saved attestation from localStorage
            try {
                const attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]');
                const saved = attestations.find(a => a.covenant_address === lastCovenantResult.address);
                if (saved) {
                    el('cov-oracle-claim-sig').value = saved.sig;
                    el('cov-oracle-claim-hash').value = saved.hash;
                    if (saved.text && attTextEl) {
                        attTextEl.textContent = 'Oracle attested: ' + saved.text;
                        attTextEl.style.display = '';
                    }
                }
            } catch (_) {}
        } else if (t === 'global-allowance') {
            // Capped beneficiary withdrawal. Sets the panel type so
            // handleCovBeneficiarySpend takes the right branch, shows the amount
            // field, and hides the manual locktime (allowance uses CSV cooldown;
            // global-allowance bakes the optional CLTV start into the script and
            // the withdraw builder sets the TX locktime from it).
            covShowPanel('beneficiary');
            el('cov-bene-addr').value = lastCovenantResult.address || '';
            el('cov-bene-script').value = lastCovenantResult.redeem_script_hex || '';
            if (el('cov-bene-locktime-wrap')) el('cov-bene-locktime-wrap').style.display = 'none';
            if (el('cov-bene-locktime')) el('cov-bene-locktime').value = '0';
            if (el('cov-bene-amount-wrap')) el('cov-bene-amount-wrap').style.display = '';
            el('cov-beneficiary-panel').dataset.covBeneType = t;
            if (el('btn-cov-bene-pick')) el('btn-cov-bene-pick').style.display = 'none'; // capped withdraw: no full-sweep picker
            // Pre-fill destination with the beneficiary's own address if available.
            const _bene = ownerReceiveAddr();
            if (_bene) el('cov-bene-dest').value = _bene;
            const beneHelpA = el('cov-bene-help');
            if (beneHelpA) {
                const capKas = lastCovenantResult.max_withdraw_sompi ? sompiToKasStr(lastCovenantResult.max_withdraw_sompi) : '0';
                const cdSecs = lastCovenantResult.cooldown_daa ? Math.floor(Number(lastCovenantResult.cooldown_daa) / 10) : 0;
                const cdStr = cdSecs > 0 ? formatDuration(cdSecs) : 'none';
                const threadNote = (t === 'global-allowance')
                    ? ' The whole balance sits in one thread; leave the amount empty to close it (allowed only when the balance is at or under the cap).'
                    : '';
                beneHelpA.textContent = 'Withdraw up to ' + (capKas !== '0' ? capKas + ' KAS' : 'the cap') + ' per spend, with a ' + cdStr + ' cooldown between withdrawals.' + threadNote + ' Requires beneficiary signature from your KasSigner.';
                beneHelpA.style.display = '';
            }
            const beneCreateBtnA = el('btn-cov-bene-create');
            if (beneCreateBtnA) beneCreateBtnA.textContent = 'Create Withdrawal TX';
        } else if (t === 'timelocked-savings') {
            // Claim after the unlock date. 1-of-2: sign with EITHER the primary
            // or the recovery wallet; the finalizer auto-detects the branch by
            // the signer's pubkey. Full sweep, locktime auto-filled from the
            // covenant. covBeneType routes handleCovBeneficiarySpend to the
            // savings claim builder.
            covShowPanel('beneficiary');
            el('cov-bene-addr').value = lastCovenantResult.address || '';
            el('cov-bene-script').value = lastCovenantResult.redeem_script_hex || '';
            if (el('cov-bene-locktime-wrap')) el('cov-bene-locktime-wrap').style.display = 'none';
            if (lastCovenantResult.locktime_daa) el('cov-bene-locktime').value = String(lastCovenantResult.locktime_daa);
            if (el('cov-bene-amount-wrap')) el('cov-bene-amount-wrap').style.display = 'none';
            el('cov-beneficiary-panel').dataset.covBeneType = 'timelocked-savings';
            const _sDest = ownerReceiveAddr();
            if (_sDest) el('cov-bene-dest').value = _sDest;
            const beneHelpS = el('cov-bene-help');
            if (beneHelpS) {
                const unlockStr = formatStartDate({ locktime_daa: lastCovenantResult.locktime_daa, start_date_iso: lastCovenantResult.locktime_date_iso });
                beneHelpS.textContent = 'Claim once the unlock time has passed (' + unlockStr + '). Sign with either your primary or recovery wallet. Sweeps all funds to the destination.';
                beneHelpS.style.display = '';
            }
            const beneCreateBtnS = el('btn-cov-bene-create');
            if (beneCreateBtnS) beneCreateBtnS.textContent = 'Claim Funds';
            if (el('btn-cov-bene-pick')) el('btn-cov-bene-pick').style.display = ''; // batched claim: pick a subset if there are many UTXOs
        } else {
            // Signature-based types (vault, DMS, escrow, etc.)
            covShowPanel('beneficiary');
            el('cov-bene-addr').value = lastCovenantResult.address || '';
            el('cov-bene-script').value = lastCovenantResult.redeem_script_hex || '';
            // CSV-based DMS: locktime is 0 (CSV handles timing via script). Watcher shows countdown.
            if (lastCovenantResult.type === 'dms') {
                el('cov-bene-locktime-wrap').style.display = 'none';
                el('cov-bene-locktime').value = '0';
            } else {
                el('cov-bene-locktime-wrap').style.display = '';
                if (lastCovenantResult.locktime_daa) el('cov-bene-locktime').value = String(lastCovenantResult.locktime_daa);
            }
            el('cov-bene-amount-wrap').style.display = 'none';
            el('cov-beneficiary-panel').dataset.covBeneType = '';
            // Help text per type
            const beneHelp = el('cov-bene-help');
            if (beneHelp) {
                if (lastCovenantResult.type === 'dms') {
                    const inactDaa = lastCovenantResult.inactivity_daa ? Number(lastCovenantResult.inactivity_daa) : 0;
                    const inactSecs = Math.floor(inactDaa / 10);
                    const inactStr = inactSecs > 0 ? formatDuration(inactSecs) : 'unknown';
                    beneHelp.textContent = 'Claim inheritance. The inactivity period (' + inactStr + ') must have elapsed since the last owner heartbeat. Requires heir signature from your KasSigner.';
                    beneHelp.style.display = '';
                } else {
                    beneHelp.style.display = 'none';
                }
            }
            // Dynamic button label
            const beneCreateBtn = el('btn-cov-bene-create');
            if (beneCreateBtn) {
                if (lastCovenantResult.type === 'dms') beneCreateBtn.textContent = 'Claim Inheritance';
                else beneCreateBtn.textContent = 'Create Release TX';
            }
            // Optional UTXO picker for the full-sweep claim (vault/DMS), mirroring the
            // owner reclaim: lets the heir/beneficiary batch a many-UTXO claim if a
            // full sweep makes too large a QR for KasSigner.
            const benePickBtn = el('btn-cov-bene-pick');
            if (benePickBtn) {
                const _showBenePick = (lastCovenantResult.type === 'dms');
                benePickBtn.style.display = _showBenePick ? '' : 'none';
            }
        }
    };
// Evaluate whether a piggy (additive) can be broken RIGHT NOW.
// totalSompi/feeSompi as BigInt. Returns {canBreak, goalMet, deadlinePassed,
// text, color}: goalMet checks output[0] (total - fee) >= threshold; the
// deadline path needs current DAA >= deadline. No conditions set = breakable.
window.piggyBreakStatus = async function (totalSompi, feeSompi) {
    const thr = lastCovenantResult.threshold_sompi ? BigInt(lastCovenantResult.threshold_sompi) : 0n;
    const dl = lastCovenantResult.deadline_daa ? BigInt(lastCovenantResult.deadline_daa) : 0n;
    if (thr === 0n && dl === 0n) {
        return { canBreak: true, goalMet: true, deadlinePassed: true,
                 text: 'No conditions set — breakable anytime.', color: 'var(--accent, #4caf50)' };
    }
    let curDaa = 0;
    try { curDaa = await fetchCurrentDaa(); } catch (_) {}
    if (!curDaa && typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) curDaa = _lastKnownDaa;
    const goalMet = thr > 0n && (totalSompi - feeSompi) >= thr;
    const deadlinePassed = dl > 0n && curDaa > 0 && BigInt(curDaa) >= dl;
    if (goalMet || deadlinePassed) {
        const why = goalMet ? 'goal reached' : 'deadline passed';
        return { canBreak: true, goalMet, deadlinePassed,
                 text: 'Breakable now (' + why + ').', color: 'var(--accent, #4caf50)' };
    }
    const parts = [];
    if (thr > 0n) parts.push('goal ' + (Number(thr) / 1e8) + ' KAS not reached (have ' +
        (Number(totalSompi) / 1e8).toFixed(4) + ')');
    if (dl > 0n) {
        const eta = (curDaa > 0 && dl > BigInt(curDaa))
            ? '~' + formatDuration(Math.floor((Number(dl) - curDaa) / 10)) : 'unknown';
        parts.push('deadline not passed (' + eta + ' left)');
    }
    return { canBreak: false, goalMet, deadlinePassed,
             text: 'NOT breakable yet: ' + parts.join(' and ') + '. A break TX would be rejected on-chain.',
             color: 'var(--error, #f44336)' };
};

// Insert/update the piggy status banner above the owner help text.
window.piggyStatusBanner = function (status) {
    let b = el('cov-piggy-status-banner');
    if (!b) {
        b = document.createElement('div');
        b.id = 'cov-piggy-status-banner';
        b.style.cssText = 'font-size:13px;padding:8px 10px;border:1px solid;border-radius:6px;margin:6px 0';
        const help = el('cov-owner-help');
        if (help && help.parentNode) help.parentNode.insertBefore(b, help);
    }
    b.style.color = status.color;
    b.style.borderColor = status.color;
    b.textContent = status.text;
    b.classList.remove('hidden');
    return b;
};

el('btn-cov-owner-create') && (el('btn-cov-owner-create').onclick = () => handleCovOwnerSpend());
    if (el('btn-cov-owner-consolidate')) {
        el('btn-cov-owner-consolidate').onclick = () => {
            // The advanced picker inherits the screen's current destination so it
            // follows the mode. On the heartbeat screen cov-owner-dest is the covenant
            // address, so the picked batch consolidates back into the vault (one fresh
            // UTXO, CSV age reset). On the withdraw screen it is the owner's personal
            // address, so the picked batch withdraws. Both operations can hit the
            // many-UTXO ceiling, so both need the batched picker, with opposite
            // destinations. The picker's isConsolidate test (dest === covAddr) then
            // routes each correctly.
            const dest = (el('cov-owner-dest') ? el('cov-owner-dest').value.trim() : '') || ownerReceiveAddr();
            openUtxoPicker(dest);
        };
    }
    async function openUtxoPicker(defaultDest, beneClaim = null) {
        if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        _pickerBeneClaim = beneClaim || null; // beneficiary timeout claim vs owner sweep
        const covAddr = lastCovenantResult.address;
        const listEl = el('cov-consol-list');
        listEl.innerHTML = '<div style="color:var(--text-dim);font-size:12px">Loading UTXOs...</div>';
        el('cov-consol-dest').value = defaultDest || covAddr;
        // Additive piggy break: this is a withdrawal (sweep to your address), not a
        // consolidation. Default-select all, and explain that deselecting lets you
        // break in smaller batches if a full sweep makes too large a QR for KasSigner.
        const _isPiggyBreak = (lastCovenantResult.type === 'additive') && defaultDest && defaultDest !== covAddr;
        const _titleEl = el('cov-consol-title');
        const _descEl = el('cov-consol-desc');
        if (_isPiggyBreak) {
            if (_titleEl) _titleEl.textContent = 'Break Piggy Bank';
            if (_descEl) _descEl.textContent = 'Sweep the piggy to your address. All UTXOs are selected. Deselect some to break in smaller batches if the QR is too large for your KasSigner. Owner signature required.';
        } else {
            if (_titleEl) _titleEl.textContent = 'Select UTXOs';
            if (_descEl) _descEl.textContent = 'Select UTXOs to consolidate or withdraw. Owner signature required.';
        }
        covShowPanel('consolidate');
        try {
            const wsUrl = await resolveNodeUrl();
            const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
            const utxos = JSON.parse(utxosJson);
            if (utxos.length < 1) { toast('No UTXOs at covenant address', 'error'); covShowPanel('result'); return; }
            listEl.innerHTML = '';
            utxos.sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
            utxos.forEach((u, i) => {
                const kas = (Number(BigInt(u.amount)) / 1e8).toFixed(4);
                const txShort = u.tx_id.substring(0, 8) + '...' + u.tx_id.substring(u.tx_id.length - 6);
                const row = document.createElement('label');
                row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px;margin-bottom:4px;background:var(--bg-card);border-radius:8px;cursor:pointer;font-size:13px';
                row.innerHTML = '<input type="checkbox" checked data-utxo-idx="' + i + '" style="width:18px;height:18px;flex-shrink:0">' +
                    '<div style="flex:1"><div style="color:var(--text-primary)">' + kas + ' KAS</div>' +
                    '<div style="color:var(--text-dim);font-size:10px">' + txShort + ':' + u.index + '</div></div>';
                listEl.appendChild(row);
            });
            listEl.dataset.utxos = JSON.stringify(utxos);
            updateConsolSummary();
            listEl.addEventListener('change', updateConsolSummary);
        } catch (e) {
            toast('Error loading UTXOs: ' + e, 'error');
            covShowPanel('result');
        }
    }
    el('btn-cov-res-consolidate').onclick = async () => {
        // Escrow: Request Arbitration (dispute heartbeat)
        if (lastCovenantResult && lastCovenantResult.type === 'escrow') {
            const role = lastCovenantResult.role || '';
            const branch = (role === 'beneficiary') ? 'seller-dispute' : 'buyer-dispute';
            await handleEscrowSpend(branch);
            return;
        }
        openUtxoPicker(lastCovenantResult ? lastCovenantResult.address : '');
    };
    function updateConsolSummary() {
        const listEl = el('cov-consol-list');
        const checks = listEl.querySelectorAll('input[type="checkbox"]');
        let count = 0, total = 0n;
        const utxos = JSON.parse(listEl.dataset.utxos || '[]');
        checks.forEach(cb => {
            if (cb.checked) {
                count++;
                const idx = parseInt(cb.dataset.utxoIdx);
                total += BigInt(utxos[idx].amount);
            }
        });
        // Cap selection at the KasSigner input ceiling (MAX_INPUTS=32). A
        // flooded covenant is drained in batches of 32 by repeating the claim;
        // without this cap a larger selection builds a TX the device can't sign
        // ("too many inputs"). Uncheck the overflow and tell the user.
        if (count > 32) {
            let seen = 0;
            checks.forEach(cb => {
                if (cb.checked) {
                    seen++;
                    if (seen > 32) {
                        cb.checked = false;
                        const idx = parseInt(cb.dataset.utxoIdx);
                        total -= BigInt(utxos[idx].amount);
                    }
                }
            });
            count = 32;
            toast('Max 32 UTXOs per claim — drain a flooded covenant in batches', 'info', 1800);
        }
        const kas = (Number(total) / 1e8).toFixed(4);
        el('cov-consol-summary').textContent = count + ' UTXO' + (count !== 1 ? 's' : '') + ' selected: ' + kas + ' KAS';
    }
    el('btn-consol-select-all').onclick = () => {
        // Respect the 32-input ceiling: check at most the first 32.
        let n = 0;
        el('cov-consol-list').querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.checked = n < 32;
            if (cb.checked) n++;
        });
        updateConsolSummary();
    };
    el('btn-consol-select-none').onclick = () => {
        el('cov-consol-list').querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        updateConsolSummary();
    };
    el('btn-consol-back').onclick = () => { showScreen('covenant'); covShowPanel('result'); };
    el('btn-consol-create').onclick = async () => {
        if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
        const listEl = el('cov-consol-list');
        const utxos = JSON.parse(listEl.dataset.utxos || '[]');
        const checks = listEl.querySelectorAll('input[type="checkbox"]');
        const selected = [];
        checks.forEach(cb => { if (cb.checked) selected.push(utxos[parseInt(cb.dataset.utxoIdx)]); });
        if (selected.length < 1) { toast('Select at least 1 UTXO', 'error'); return; }
        if (selected.length > 32) { toast('Max 32 UTXOs per claim — the KasSigner signs up to 32 inputs', 'error'); return; }
        const destAddr = el('cov-consol-dest').value.trim();
        if (!destAddr) { toast('Enter a destination address', 'error'); return; }
        const covAddr = lastCovenantResult.address;
        const isConsolidate = destAddr === covAddr;
        if (isConsolidate && selected.length < 2) { toast('Select at least 2 UTXOs to consolidate', 'error'); return; }
        showLoading(isConsolidate ? 'Building consolidation TX...' : 'Building withdrawal TX...');
        try {
            window._covPayloadHex = ''; // spend/claim/consolidation carry no TX payload (PL must not show)
            const fee = getCovFee(selected.length);
            const redeemHex = lastCovenantResult.redeem_script_hex;
            // Piggy withdrawal (break) on a deadline piggy must take the time
            // branch — the amount branch is OP_FALSE there. Consolidation back to
            // the covenant keeps the default branch.
            let ownerBranch = '';
            if (!isConsolidate && lastCovenantResult.type === 'additive') {
                const thr = lastCovenantResult.threshold_sompi ? BigInt(lastCovenantResult.threshold_sompi) : 0n;
                const dl = lastCovenantResult.deadline_daa ? BigInt(lastCovenantResult.deadline_daa) : 0n;
                if (thr > 0n || dl > 0n) {
                    const selTotal = selected.reduce((s, u) => s + BigInt(u.amount), 0n);
                    let curDaa = 0;
                    try { curDaa = await fetchCurrentDaa(); } catch (_) {}
                    if (!curDaa && typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) curDaa = _lastKnownDaa;
                    const deadlinePassed = dl > 0n && curDaa > 0 && BigInt(curDaa) >= dl;
                    // Goal (amount) path needs the swept output[0] to reach the threshold,
                    // i.e. the SELECTED total (not the whole piggy) must clear it. The
                    // deadline (time) path is only valid once the deadline has passed; a
                    // locktimed TX built early is rejected by the node as not finalized.
                    const goalMetBySelection = thr > 0n && (selTotal - fee) >= thr;
                    if (goalMetBySelection) {
                        ownerBranch = '';
                    } else if (deadlinePassed) {
                        ownerBranch = 'owner-time';
                    } else {
                        hideLoading();
                        const have = (Number(selTotal) / 1e8).toFixed(4);
                        const eta = (curDaa > 0 && dl > BigInt(curDaa)) ? formatDuration(Math.floor((Number(dl) - curDaa) / 10)) : 'the deadline';
                        if (thr > 0n && dl > 0n) {
                            toast('This selection is ' + have + ' KAS, below the goal of ' + (Number(thr) / 1e8) + ' KAS, and the deadline has not passed (~' + eta + '). Select enough UTXOs to reach the goal, or wait for the deadline.', 'error', 7500);
                        } else if (thr > 0n) {
                            toast('This selection is ' + have + ' KAS, below the goal of ' + (Number(thr) / 1e8) + ' KAS. Select enough UTXOs to reach the goal.', 'error', 7500);
                        } else {
                            toast('The deadline has not passed (~' + eta + '). A deadline-only piggy cannot be broken until then.', 'error', 7500);
                        }
                        return;
                    }
                }
            }
            // psktToJson, not JSON.stringify: these amounts are read on the
            // Rust side with as_u64() and land in the sighash, so a rounded
            // value above 2^53 sompi produces a signature the node rejects.
            const utxosStr = psktToJson(selected.map(u => ({
                tx_id: u.tx_id, index: u.index, amount: BigInt(u.amount)
            })));
            let pskbHex;
            if (_pickerBeneClaim) {
                // Beneficiary timeout claim of the selected UTXOs (vault/DMS).
                const lt = BigInt(_pickerBeneClaim.locktime || 0);
                const _claimT = (lastCovenantResult && lastCovenantResult.type) || '';
                if (_claimT === 'timelocked-savings' && lt > 0n) {
                    const _curDaaP = (typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) ? _lastKnownDaa : (window._lastKnownDaa || 0);
                    if (_curDaaP > 0 && BigInt(_curDaaP) < lt) {
                        hideLoading();
                        const _etaP = formatDuration(Math.floor((Number(lt) - _curDaaP) / 10));
                        toast('Still locked. Unlocks in ~' + _etaP + '. An early claim is rejected by the node.', 'error', 5000);
                        return;
                    }
                }
                pskbHex = (_claimT === 'timelocked-savings')
                    ? create_covenant_timelocked_savings_claim_selected(covAddr, destAddr, redeemHex, lt, utxosStr, fee)
                    : create_covenant_beneficiary_spend_selected(covAddr, destAddr, redeemHex, lt, utxosStr, fee);
                console.log('[KasSee] Beneficiary claim (selected): ' + selected.length + ' inputs, wire ' + pskbHex.length + ' chars');
            } else {
                pskbHex = create_covenant_owner_spend_selected(covAddr, destAddr, redeemHex, utxosStr, fee, ownerBranch);
                console.log('[KasSee] ' + (isConsolidate ? 'Consolidation' : 'Withdrawal') + ' PSKB: ' + selected.length + ' inputs, wire ' + pskbHex.length + ' chars');
            }
            hideLoading();
            _broadcastReturnScreen = 'covenant'; // PSKT review Back returns to the covenant, not the dashboard
            openPsktReview(pskbHex);
            showScreen('pskt-review');
        } catch (e) {
            hideLoading();
            toast((isConsolidate ? 'Consolidation' : 'Withdrawal') + ' error: ' + e, 'error', 5000);
        }
    };
    el('btn-cov-borrower-create').onclick = () => handleCovBorrowerSpend();
    el('cov-type').onchange = () => covTypeChanged();
    if (el('btn-cov-scan-savings-recovery')) el('btn-cov-scan-savings-recovery').onclick = () => covScanPubkey('cov-savings-recovery-pk', 'Scan backup wallet address or x-only (not a kpub)', true);
    // Escrow scan buttons (2-of-3 with arbiter)
    el('btn-cov-scan-escrow-pk').onclick = () => covScanPubkey('cov-escrow-pk', 'Scan seller pubkey');
    el('btn-cov-scan-escrow-arbiter').onclick = () => covScanPubkey('cov-escrow-arbiter-pk', 'Scan arbiter pubkey');
    // Time-locked escrow scan buttons
    if (el('btn-cov-scan-tl-escrow-pk')) el('btn-cov-scan-tl-escrow-pk').onclick = () => covScanPubkey('cov-tl-escrow-pk', 'Scan counterparty address');
    if (el('btn-cov-scan-tl-escrow-my')) el('btn-cov-scan-tl-escrow-my').onclick = () => covScanAddress('cov-tl-escrow-my-addr', 'Scan your address');
    if (el('btn-cov-scan-tl-escrow-their')) el('btn-cov-scan-tl-escrow-their').onclick = () => covScanAddress('cov-tl-escrow-their-addr', 'Scan counterparty address');
    // Vesting scan buttons

    // Allowance scan buttons
    el('btn-cov-scan-allowance-bene').onclick = () => covScanPubkey('cov-allowance-bene-pk', 'Scan beneficiary address or x-only (not a kpub)', true);

    // Beneficiary Max withdraw button
    if (el('btn-cov-bene-max')) {
        el('btn-cov-bene-max').onclick = async () => {
            if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
            try {
                const wsUrl = await resolveNodeUrl();
                const utxosJson = await fetch_utxos_for_address_js(lastCovenantResult.address, wsUrl);
                const utxos = JSON.parse(utxosJson);
                if (!utxos.length) { toast('No UTXOs at covenant', 'error'); return; }
                const balance = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
                const numInputs = BigInt(utxos.length);
                const minReturn = 10_000_000n; // 0.1 KAS min covenant return (avoids storage mass cap)
                const baseFee = 300_000n * numInputs; // TN10 covenant compute mass per input
                const C = 1_000_000_000_000n;
                const MAX_STORAGE_MASS = 500_000n;
                const maxAllowed = lastCovenantResult.max_withdraw_sompi ? BigInt(lastCovenantResult.max_withdraw_sompi) : balance;
                // Drain-eligible: when the whole balance fits under the cap, "Max"
                // means CLOSE the thread (withdraw everything, no continuation).
                // Setting the field to the full balance trips the builder's
                // is_close branch (withdrawSompi >= total). Only when balance > cap
                // (a close is impossible) do we compute the partial max that must
                // leave a >=0.1 KAS continuation.
                if (maxAllowed > 0n && balance <= maxAllowed) {
                    el('cov-bene-amount').value = sompiToKasStr(balance);
                    toast('Full drain: ' + el('cov-bene-amount').value + ' KAS (closes the thread)', 'ok', 2000);
                    return;
                }
                let lo = 0n, hi = balance - minReturn - baseFee;
                if (hi < 0n) hi = 0n;
                if (hi > maxAllowed) hi = maxAllowed;
                let bestWithdraw = 0n;
                for (let i = 0; i < 40 && lo <= hi; i++) {
                    const mid = (lo + hi) / 2n;
                    // Estimate fee first, then check if return is viable
                    let fee = baseFee;
                    const retEst = balance - mid - fee;
                    if (retEst > 0n && mid > 0n) {
                        const hMean = 2n * retEst * mid / (retEst + mid);
                        const sm = hMean > 0n ? C / hMean : 0n;
                        if (sm > MAX_STORAGE_MASS) {
                            // Storage mass exceeds cap, withdraw is too large
                            hi = mid - 1n;
                            continue;
                        }
                        if (sm > fee) fee = sm;
                    }
                    const actualReturn = balance - mid - fee;
                    if (actualReturn >= minReturn) {
                        bestWithdraw = mid;
                        lo = mid + 1n;
                    } else {
                        hi = mid - 1n;
                    }
                }
                if (bestWithdraw <= 0n) { toast('Balance too low to withdraw', 'error'); return; }
                el('cov-bene-amount').value = sompiToKasStr(bestWithdraw);
                toast('Max: ' + el('cov-bene-amount').value + ' KAS', 'ok', 1500);
            } catch (e) {
                toast('Error: ' + e, 'error');
            }
        };
    }

    // Allowance period dropdown + custom time picker
    if (el('cov-allowance-period')) {
        const recalcCustomSeconds = () => {
            const y = parseInt(el('cov-allow-years').value) || 0;
            const mo = parseInt(el('cov-allow-months').value) || 0;
            const d = parseInt(el('cov-allow-days').value) || 0;
            const h = parseInt(el('cov-allow-hours').value) || 0;
            const mi = parseInt(el('cov-allow-mins').value) || 0;
            const total = y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60;
            el('cov-allowance-seq').value = total > 0 ? total : '';
            updateAllowanceSummary();
        };
        const updateAllowanceSummary = () => {
            const v = el('cov-allowance-period').value;
            const kas = el('cov-allowance-max').value || '?';
            const labels = {'3600':'1 hour','21600':'6 hours','43200':'12 hours','86400':'24 hours','604800':'7 days','2592000':'30 days'};
            let period;
            if (v === 'custom') {
                const secs = parseInt(el('cov-allowance-seq').value) || 0;
                period = secs > 0 ? formatDuration(secs) : 'custom period';
            } else {
                period = labels[v] || v + 's';
            }
            const summary = el('cov-allowance-summary');
            if (summary) summary.textContent = 'Withdraw up to ' + kas + ' KAS every ' + period + '. Uses OP_CHECKSEQUENCEVERIFY.';
        };
        el('cov-allowance-period').onchange = () => {
            const v = el('cov-allowance-period').value;
            const customWrap = el('cov-allowance-custom-wrap');
            if (customWrap) customWrap.classList.toggle('hidden', v !== 'custom');
            if (v !== 'custom') el('cov-allowance-seq').value = v;
            updateAllowanceSummary();
        };
        ['cov-allow-years','cov-allow-months','cov-allow-days','cov-allow-hours','cov-allow-mins'].forEach(id => {
            if (el(id)) el(id).oninput = recalcCustomSeconds;
        });
        if (el('cov-allowance-max')) el('cov-allowance-max').oninput = updateAllowanceSummary;
    }
    // Atomic swap scan buttons
    if (el('btn-cov-scan-swap-pk')) el('btn-cov-scan-swap-pk').onclick = () => covScanPubkey('cov-swap-pk', 'Scan counterparty address');
    // Oracle scan buttons
    el('btn-cov-scan-oracle-bene').onclick = () => covScanPubkey('cov-oracle-bene-pk', 'Scan beneficiary address');
    el('btn-cov-scan-oracle-pk').onclick = () => covScanPubkey('cov-oracle-pk', 'Scan oracle KPUB (account-level)');
    // PayJoin scan buttons
    el('btn-cov-scan-payjoin-bene').onclick = () => covScanPubkey('cov-payjoin-bene-pk', 'Scan beneficiary address');
    // PayJoin claim panel wiring
    if (el('btn-cov-payjoin-claim')) el('btn-cov-payjoin-claim').onclick = () => covShowPanel('payjoin-claim');
    el('btn-cov-payjoin-claim-back').onclick = () => covShowPanel('menu');
    el('btn-cov-payjoin-claim-create').onclick = () => handleCovPayjoinClaim();
    if (el('btn-cov-scan-payjoin-claim-addr')) el('btn-cov-scan-payjoin-claim-addr').onclick = () => covScanAddress('cov-payjoin-claim-addr', 'Scan covenant address');
    if (el('btn-cov-scan-payjoin-mix-addr')) el('btn-cov-scan-payjoin-mix-addr').onclick = () => covScanAddress('cov-payjoin-claim-mix-addr', 'Scan mixing address');
    el('btn-cov-scan-payjoin-claim-dest').onclick = () => covScanAddress('cov-payjoin-claim-dest', 'Scan destination');
    // Oracle claim panel wiring
    if (el('btn-cov-oracle-claim')) el('btn-cov-oracle-claim').onclick = () => covShowPanel('oracle-claim');
    el('btn-cov-oracle-claim-back').onclick = () => covShowPanel('result');
    el('btn-cov-oracle-claim-create').onclick = () => handleCovOracleClaim();
    el('btn-cov-scan-oracle-claim-addr').onclick = () => covScanAddress('cov-oracle-claim-addr', 'Scan covenant address');
    el('btn-cov-scan-oracle-claim-dest').onclick = () => covScanAddress('cov-oracle-claim-dest', 'Scan destination');
    // Oracle Attest panel wiring
    if (el('btn-cov-res-oracle-attest')) {
        el('btn-cov-res-oracle-attest').onclick = () => covShowPanel('oracle-attest');
    }
    // Owner/anyone: scan attestation QR from result panel
    if (el('btn-cov-res-scan-attestation')) {
        el('btn-cov-res-scan-attestation').onclick = () => {
            startScanner('Scan Oracle Attestation QR', (data) => {
                const raw = new Uint8Array(data);
                let sig = '', hash = '', text = '';
                if (raw.length === 96) {
                    sig = Array.from(raw.slice(0, 64)).map(b => b.toString(16).padStart(2, '0')).join('');
                    hash = Array.from(raw.slice(64, 96)).map(b => b.toString(16).padStart(2, '0')).join('');
                } else {
                    try {
                        const obj = JSON.parse(new TextDecoder().decode(raw).trim());
                        if (obj && obj.t === 'oracle-attest') {
                            sig = obj.sig || '';
                            hash = obj.hash || '';
                            text = obj.text || '';
                        }
                    } catch (_) {}
                }
                if (sig && hash) {
                    stopScanner();
                    // Save to localStorage
                    try {
                        const covAddr = lastCovenantResult ? lastCovenantResult.address : '';
                        if (covAddr) {
                            let attestations = [];
                            try { attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]'); } catch (_) {}
                            attestations = attestations.filter(a => a.covenant_address !== covAddr);
                            attestations.unshift({ covenant_address: covAddr, sig, hash, text, scanned_at: new Date().toISOString() });
                            localStorage.setItem('oracleAttestations', JSON.stringify(attestations));
                        }
                    } catch (_) {}
                    showScreen('covenant');
                    // Update the text display
                    const resAttText = el('cov-res-attest-text');
                    if (resAttText && text) {
                        resAttText.textContent = 'Oracle attested: ' + text;
                        resAttText.style.display = '';
                    }
                    toast('Attestation saved', 'ok', 2000);
                }
            });
        };
    }
    if (el('btn-cov-oracle-attest-back')) {
        el('btn-cov-oracle-attest-back').onclick = () => covShowPanel('result');
    }
    if (el('btn-cov-oracle-gen-hash-qr')) {
        el('btn-cov-oracle-gen-hash-qr').onclick = () => {
            const text = el('cov-oracle-attest-text').value.trim();
            if (!text) { toast('Enter attestation text', 'error'); return; }
            const textByteLen = new TextEncoder().encode(text).length;
            if (textByteLen > 28) { toast('Attestation text too long (' + textByteLen + '/28 bytes). Shorten it.', 'error'); return; }
            // SHA256 of the text
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            crypto.subtle.digest('SHA-256', data).then(hashBuf => {
                const hashArr = new Uint8Array(hashBuf);
                const hashHex = Array.from(hashArr).map(b => b.toString(16).padStart(2, '0')).join('');
                el('cov-oracle-attest-hash').textContent = 'SHA256: ' + hashHex;
                el('cov-oracle-attest-hash').style.display = '';
                // Store for later
                window._oracleAttestHash = hashHex;
                window._oracleAttestText = text;
                // Generate QR with the 64-char hex hash
                try {
                    pauseQrCycle();
                    const svg = generate_qr_svg_text(hashHex);
                    el('qr-container').innerHTML = svg;
                    el('qr-frame-info').innerHTML = '';
                    el('qr-display-title').textContent = 'Hash QR \u2014 scan with KasSigner';
                    el('btn-scan-next-sig').style.display = 'none';
                    el('btn-copy-kspt').style.display = 'none';
                    if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = 'none';
                    _broadcastReturnScreen = 'covenant';
                    window._oracleAttestQrReturn = true;
                    if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                    showScreen('qr-display');
                    // Show step 2 button
                    el('btn-cov-oracle-scan-sig').style.display = '';
                } catch (e) {
                    toast('QR generation failed: ' + e, 'error');
                }
            });
        };
    }
    if (el('btn-cov-oracle-scan-sig')) {
        el('btn-cov-oracle-scan-sig').onclick = () => {
            startScanner('Scan Attestation from KasSigner', (data) => {
                const raw = new Uint8Array(data);
                if (raw.length === 96) {
                    const sigHex = Array.from(raw.slice(0, 64)).map(b => b.toString(16).padStart(2, '0')).join('');
                    const hashHex = Array.from(raw.slice(64, 96)).map(b => b.toString(16).padStart(2, '0')).join('');
                    stopScanner();
                    window._oracleAttestSig = sigHex;
                    window._oracleAttestScanHash = hashHex;
                    showScreen('covenant');
                    covShowPanel('oracle-attest');
                    el('cov-oracle-attest-status').textContent = 'Attestation signed. Ready to share.';
                    el('cov-oracle-attest-status').style.display = '';
                    if (el('btn-cov-oracle-beacon')) el('btn-cov-oracle-beacon').style.display = '';
                    toast('Attestation scanned from KasSigner', 'ok', 2000);
                }
            });
        };
    }
    if (el('btn-cov-oracle-share-attest')) {
        el('btn-cov-oracle-share-attest').onclick = () => {
            if (!window._oracleAttestSig || !window._oracleAttestScanHash) {
                toast('Sign the hash on KasSigner first', 'error'); return;
            }
            const attestation = JSON.stringify({
                v: 1, t: 'oracle-attest',
                sig: window._oracleAttestSig,
                hash: window._oracleAttestScanHash,
                text: window._oracleAttestText || ''
            });
            try {
                pauseQrCycle();
                const svg = generate_qr_svg_text(attestation);
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Full Attestation \u2014 beneficiary scans this';
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                _broadcastReturnScreen = 'covenant';
                window._oracleAttestQrReturn = true;
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
            } catch (e) {
                toast('QR generation failed: ' + e, 'error');
            }
        };
    }
    if (el('btn-cov-oracle-beacon')) {
        el('btn-cov-oracle-beacon').onclick = async () => {
            if (!window._oracleAttestSig || !window._oracleAttestScanHash) {
                toast('Sign the hash on KasSigner first', 'error'); return;
            }
            if (!lastCovenantResult || !lastCovenantResult.address || !lastCovenantResult.redeem_script_hex) {
                toast('No covenant loaded', 'error'); return;
            }
            showLoading('Building attestation beacon TX...');
            try {
                const fee = getCovFee();
                const wsUrl = await resolveNodeUrl();
                const pskbHex = await create_oracle_heartbeat(
                    lastCovenantResult.address,
                    lastCovenantResult.redeem_script_hex,
                    window._oracleAttestSig,
                    window._oracleAttestScanHash,
                    window._oracleAttestText || '',
                    fee,
                    wsUrl
                );
                hideLoading();
                console.log('[KasSee] Oracle beacon PSKB: ' + pskbHex.length + ' hex chars');
                // Save attestation text to localStorage for display on result panel
                try {
                    let attestations = [];
                    try { attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]'); } catch (_) {}
                    attestations = attestations.filter(a => a.covenant_address !== lastCovenantResult.address);
                    attestations.unshift({
                        covenant_address: lastCovenantResult.address,
                        sig: window._oracleAttestSig,
                        hash: window._oracleAttestScanHash,
                        text: window._oracleAttestText || '',
                        scanned_at: new Date().toISOString(),
                        source: 'oracle-local'
                    });
                    localStorage.setItem('oracleAttestations', JSON.stringify(attestations));
                } catch (_) {}
                // Reset attest panel for next round
                window._oracleAttestSig = null;
                window._oracleAttestScanHash = null;
                window._oracleAttestText = null;
                el('cov-oracle-attest-text').value = '';
                el('cov-oracle-attest-hash').textContent = '';
                el('cov-oracle-attest-hash').style.display = 'none';
                el('cov-oracle-attest-status').textContent = '';
                el('cov-oracle-attest-status').style.display = 'none';
                if (el('btn-cov-oracle-scan-sig')) el('btn-cov-oracle-scan-sig').style.display = 'none';
                if (el('btn-cov-oracle-beacon')) el('btn-cov-oracle-beacon').style.display = 'none';
                window._covPayloadHex = '';
                _broadcastReturnScreen = 'covenant';
                openPsktReview(pskbHex);
            } catch (e) {
                hideLoading();
                toast('Beacon failed: ' + e, 'error', 5000);
                console.error('[KasSee] Oracle beacon error:', e);
            }
        };
    }
    // Shipment-escrow operate + create scan buttons
    if (el('btn-cov-ship-back')) el('btn-cov-ship-back').onclick = () => covShowPanel('result');
    if (el('btn-cov-ship-pickup')) el('btn-cov-ship-pickup').onclick = () => handleShipEscrowSpend('pickup');
    if (el('btn-cov-ship-s0-arb')) el('btn-cov-ship-s0-arb').onclick = () => handleShipEscrowSpend('state0-arb-refund');
    if (el('btn-cov-ship-s0-timeout')) el('btn-cov-ship-s0-timeout').onclick = () => handleShipEscrowSpend('state0-timeout');
    if (el('btn-cov-ship-delivery')) el('btn-cov-ship-delivery').onclick = () => handleShipEscrowSpend('delivery');
    if (el('btn-cov-ship-s1-award')) el('btn-cov-ship-s1-award').onclick = () => handleShipEscrowSpend('state1-arb-award');
    if (el('btn-cov-ship-s1-arb-refund')) el('btn-cov-ship-s1-arb-refund').onclick = () => handleShipEscrowSpend('state1-arb-refund');
    if (el('btn-cov-ship-s1-timeout')) el('btn-cov-ship-s1-timeout').onclick = () => handleShipEscrowSpend('state1-timeout');
    if (el('btn-cov-scan-ship-seller')) el('btn-cov-scan-ship-seller').onclick = () => covScanPubkey('cov-ship-seller-pk', 'Scan seller pubkey');
    if (el('btn-cov-scan-ship-deliverer')) el('btn-cov-scan-ship-deliverer').onclick = () => covScanPubkey('cov-ship-deliverer-pk', 'Scan deliverer pubkey');
    if (el('btn-cov-scan-ship-arbiter')) el('btn-cov-scan-ship-arbiter').onclick = () => covScanPubkey('cov-ship-arbiter-pk', 'Scan arbiter pubkey');
    if (el('btn-cov-scan-ship-addr')) el('btn-cov-scan-ship-addr').onclick = () => covScanAddress('cov-ship-addr', 'Scan covenant address');
    // Commit-reveal panel wiring
    if (el('btn-cov-cr-hash')) el('btn-cov-cr-hash').onclick = () => handleCrHash();
    if (el('btn-cov-cr-scan-commitment')) el('btn-cov-cr-scan-commitment').onclick = () => {
        startScanner('Scan Commitment QR', (data) => {
            // Binary QR from KasSigner: hash(32) + ciphertext(61+N)
            const bytes = (data instanceof Uint8Array) ? data : new Uint8Array(data);
            if (bytes.length < 93) { // 32 hash + 61 min ciphertext
                stopScanner();
                showScreen('covenant');
                toast('Invalid commitment QR (too short)', 'error');
                return;
            }
            stopScanner();
            const toHex = (arr) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
            const hashHex = toHex(bytes.slice(0, 32));
            const ctHex = toHex(bytes.slice(32));

            el('cov-cr-hash-display').textContent = 'BLAKE2B: ' + hashHex;
            el('cov-cr-ciphertext-hex').value = ctHex;
            showScreen('covenant');
            toast('Commitment scanned. Hash: ' + hashHex.slice(0, 8) + '...', 'ok', 2000);
        });
    };
    // Datetime → locktime staleness fix: the create flows compute the DAA
    // locktime from the datetime only when the locktime field is EMPTY, and
    // then write the computed value back into it. On a second create with a
    // changed datetime the stale DAA silently won — same script, same
    // covenant address ("changing the time doesn't change the address").
    // Editing a datetime now clears its paired auto-filled locktime field.
    [['cov-cr-datetime', 'cov-cr-locktime'],
     ['cov-mw-datetime', 'cov-mw-locktime'],
     ['cov-payjoin-datetime', 'cov-payjoin-locktime'],
     ['cov-oracle-datetime', 'cov-oracle-locktime'],
     ['cov-savings-datetime', 'cov-savings-locktime'],
     ['cov-swap-datetime', 'cov-swap-locktime'],
     ['cov-crowdfund-datetime', 'cov-crowdfund-locktime']].forEach(([dt, lt]) => {
        const d = el(dt);
        if (d) d.addEventListener('input', () => { const l = el(lt); if (l) l.value = ''; });
    });
    if (el('btn-cov-cr-reveal')) el('btn-cov-cr-reveal').onclick = () => covShowPanel('cr-reveal');
    el('btn-cov-cr-reveal-back').onclick = () => { window._crDecryptCtBytes = null; covShowPanel('result'); };
    el('btn-cov-cr-reveal-create').onclick = () => handleCovCrReveal();
    // Step 1: Show ciphertext as QR for KasSigner to scan
    if (el('btn-cov-cr-show-ct-qr')) el('btn-cov-cr-show-ct-qr').onclick = () => {
        const ctBytes = window._crDecryptCtBytes;
        if (!ctBytes || ctBytes.length < 61) {
            toast('No ciphertext available', 'error');
            return;
        }
        const ctHex = Array.from(ctBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        try {
            const svg = generate_qr_svg_text(ctHex);
            const overlay = document.createElement('div');
            overlay.id = 'cr-ct-overlay';
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.92);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center';
            overlay.innerHTML = '<p style="color:var(--teal);font-size:14px;margin-bottom:12px">Scan on KasSigner: Decrypt Secret</p>' +
                '<div style="background:#fff;border-radius:8px;padding:12px;display:inline-block;width:240px;height:240px">' + svg + '</div>' +
                '<p style="color:var(--text-dim);font-size:12px;margin-top:16px;cursor:pointer" id="cr-ct-close">Tap here to close</p>';
            document.body.appendChild(overlay);
            // Delay attaching close handler to prevent click bubble from button
            setTimeout(() => {
                const closeEl = document.getElementById('cr-ct-close');
                if (closeEl) closeEl.onclick = () => { const o = document.getElementById('cr-ct-overlay'); if (o) o.remove(); };
                overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
            }, 300);
        } catch (e) {
            toast('QR generation failed: ' + e, 'error');
        }
    };
    // Step 2: Scan decrypted preimage hex QR from KasSigner
    if (el('btn-cov-cr-scan-preimage')) el('btn-cov-cr-scan-preimage').onclick = () => {
        startScanner('Scan Decrypted Preimage', (data) => {
            stopScanner();
            // KasSigner exports preimage as ASCII hex bytes
            let hexStr;
            if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
                const bytes = new Uint8Array(data);
                hexStr = new TextDecoder().decode(bytes);
            } else {
                hexStr = String(data);
            }
            hexStr = hexStr.trim();
            if (!/^[0-9a-fA-F]+$/.test(hexStr) || hexStr.length < 2) {
                showScreen('covenant');
                toast('Invalid preimage hex', 'error');
                return;
            }
            // Store as part_A (full preimage), part_B empty. CAT(full, empty) = full.
            window._crRevealPartA = hexStr;
            window._crRevealPartB = '';
            const statusEl = el('cov-cr-preimage-status');
            if (statusEl) statusEl.textContent = 'Preimage received (' + (hexStr.length / 2) + ' bytes)';
            showScreen('covenant');
            toast('Preimage scanned', 'ok', 1500);
        });
    };
    if (el('btn-cov-scan-cr-addr')) el('btn-cov-scan-cr-addr').onclick = () => covScanAddress('cov-cr-addr', 'Scan covenant address');
    el('btn-cov-scan-cr-dest').onclick = () => covScanAddress('cov-cr-dest', 'Scan destination');
    // Verify revelation panel
    if (el('btn-cov-cr-verify-back')) el('btn-cov-cr-verify-back').onclick = () => covShowPanel('result');
    if (el('btn-cov-cr-verify-clear')) el('btn-cov-cr-verify-clear').onclick = () => {
        ['cov-cr-verify-preimage','cov-cr-verify-hash','cov-cr-verify-computed','cov-cr-verify-match','cov-cr-verify-time'].forEach(id => { if (el(id)) el(id).textContent = ''; });
        if (el('cov-cr-verify-result')) el('cov-cr-verify-result').style.display = 'none';
        if (el('cov-cr-verify-txid')) el('cov-cr-verify-txid').value = '';
        toast('Revelation cleared', 'ok');
    };
    if (el('btn-cov-scan-cr-verify-txid')) el('btn-cov-scan-cr-verify-txid').onclick = () => {
        startScanner('Scan TX ID', (data) => {
            stopScanner();
            const txt = (data instanceof Uint8Array) ? new TextDecoder().decode(data) : String(data);
            el('cov-cr-verify-txid').value = txt.trim();
            showScreen('covenant');
        });
    };
    if (el('btn-cov-cr-verify')) el('btn-cov-cr-verify').onclick = async () => {
        const txid = el('cov-cr-verify-txid').value.trim();
        if (!txid || txid.length !== 64) { toast('Enter a valid 64-char TX ID', 'error'); return; }
        showLoading('Fetching TX...');
        try {
            const apiBase = network.includes('test') ? 'https://api-tn10.kaspa.org' : 'https://api.kaspa.org';
            const resp = await fetch(apiBase + '/transactions/' + txid);
            if (!resp.ok) throw new Error('TX not found (HTTP ' + resp.status + ')');
            const tx = await resp.json();
            hideLoading();

            // Parse sig_script from first input
            const sigScriptHex = tx.inputs && tx.inputs[0] ? tx.inputs[0].signature_script : '';
            if (!sigScriptHex || sigScriptHex.length < 10) throw new Error('No sig_script in TX');

            // Parse sig_script: <part_a_push> <part_b_push> <sig_push> OP_FALSE <redeem_push>
            // The preimage parts are the first data pushes. Redeem script is the last push.
            let pos = 0;
            const ss = sigScriptHex;
            function readPush() {
                let len = parseInt(ss.substring(pos, pos+2), 16);
                pos += 2;
                if (len === 0x4c) { // OP_PUSHDATA1
                    len = parseInt(ss.substring(pos, pos+2), 16);
                    pos += 2;
                } else if (len === 0x4d) { // OP_PUSHDATA2
                    len = parseInt(ss.substring(pos, pos+4).match(/../g).reverse().join(''), 16);
                    pos += 4;
                }
                const data = ss.substring(pos, pos + len*2);
                pos += len*2;
                return data;
            }

            // Part A (preimage or first part)
            const partAHex = readPush();
            // Part B (second part, may be empty = 0x00 byte)
            let partBHex = '';
            const nextByte = parseInt(ss.substring(pos, pos+2), 16);
            if (nextByte === 0x00) {
                pos += 2; // OP_0 = empty
            } else {
                partBHex = readPush();
            }
            // Signature (skip)
            readPush();
            // OP_FALSE (0x00)
            if (parseInt(ss.substring(pos, pos+2), 16) === 0x00) pos += 2;
            // Redeem script
            const redeemHex = readPush();

            // Full preimage = part_a + part_b
            const fullPreimageHex = partAHex + partBHex;
            // Decode preimage to text. Salted (v2) preimages are
            // salt(8) || secret — the salt is entropy, not text, so strip it
            // for display when the first 8 bytes contain non-printables.
            // Legacy unsalted preimages are pure text and pass through whole.
            // The hash below is always computed over the FULL preimage.
            const preimageBytes = new Uint8Array(fullPreimageHex.match(/.{2}/g).map(b => parseInt(b, 16)));
            let displayBytes = preimageBytes;
            if (preimageBytes.length > 8 &&
                Array.from(preimageBytes.slice(0, 8)).some(b => b < 0x20 || b > 0x7e)) {
                displayBytes = preimageBytes.slice(8);
            }
            let preimageText;
            try { preimageText = new TextDecoder().decode(displayBytes); } catch (_) { preimageText = fullPreimageHex; }

            // Extract committed hash from redeem script
            // The script has OP_CAT(7e) OP_BLAKE2B(aa) then 20-byte push of the hash
            const catBlake2bIdx = redeemHex.indexOf('7eaa20');
            let committedHash = '';
            if (catBlake2bIdx >= 0) {
                committedHash = redeemHex.substring(catBlake2bIdx + 6, catBlake2bIdx + 6 + 64);
            } else {
                // Legacy: just OP_BLAKE2B without OP_CAT
                const blake2bIdx = redeemHex.indexOf('aa20');
                if (blake2bIdx >= 0) {
                    committedHash = redeemHex.substring(blake2bIdx + 4, blake2bIdx + 4 + 64);
                }
            }

            // Compute BLAKE2B of preimage
            const computedHash = blake2b_hash(fullPreimageHex);

            // Display results
            const resultDiv = el('cov-cr-verify-result');
            resultDiv.style.display = '';
            el('cov-cr-verify-preimage').textContent = preimageText;
            el('cov-cr-verify-hash').textContent = committedHash;
            el('cov-cr-verify-computed').textContent = computedHash;

            const matchDiv = el('cov-cr-verify-match');
            if (committedHash && computedHash && committedHash === computedHash) {
                matchDiv.textContent = '\u2705 HASH MATCH \u2014 Commitment verified';
                matchDiv.style.background = 'rgba(78,205,196,0.15)';
                matchDiv.style.color = 'var(--teal)';
            } else {
                matchDiv.textContent = '\u274c HASH MISMATCH \u2014 Invalid revelation';
                matchDiv.style.background = 'rgba(255,82,82,0.15)';
                matchDiv.style.color = '#ff5252';
            }

            // Timestamp from TX
            const timeDiv = el('cov-cr-verify-time');
            if (tx.block_time) {
                timeDiv.textContent = new Date(tx.block_time).toLocaleString();
            } else {
                timeDiv.textContent = 'DAA: ' + (tx.inputs[0].previous_outpoint_resolved_daa_score || 'unknown');
            }
        } catch (e) {
            hideLoading();
            toast('Verification failed: ' + e.message, 'error', 5000);
        }
    };
    // Merkle whitelist panel wiring
    if (el('btn-cov-mw-never')) el('btn-cov-mw-never').onclick = () => {
        const d = new Date();
        d.setFullYear(d.getFullYear() + 100);
        const pad = (n) => String(n).padStart(2, '0');
        const v = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        if (el('cov-mw-datetime')) el('cov-mw-datetime').value = v;
        if (el('cov-mw-locktime')) el('cov-mw-locktime').value = ''; // force recompute from the new far-future date
        toast('Refund blocked ~100 years out. Whitelist is now permanent.', 'ok', 2500);
    };
    if (el('btn-cov-mw-spend')) el('btn-cov-mw-spend').onclick = async () => {
        // Pre-fill spend panel from active covenant data
        if (lastCovenantResult) {
            el('cov-mw-addr').value = lastCovenantResult.address || '';
            el('cov-mw-script').value = lastCovenantResult.redeem_script_hex || '';
            // Restore whitelist addresses from active entry
            const activeEntry = activeCovenants.find(c => c.address === lastCovenantResult.address);
            const addrJson = (activeEntry && activeEntry.merkle_addresses_json) || lastCovenantResult.merkle_addresses_json || '';
            if (addrJson) {
                try { el('cov-mw-spend-addresses').value = JSON.parse(addrJson).join('\n'); } catch (_) {}
            }
        }
        covShowPanel('mw-spend');
        // Show the spendable max as the grayed placeholder (matches what Max fills).
        el('cov-mw-amount').placeholder = 'Computing max...';
        try {
            const m = await mwMaxSompi();
            el('cov-mw-amount').placeholder = m ? (sompiToKasStr(m) + ' max') : 'e.g. 5.0';
        } catch (_) { el('cov-mw-amount').placeholder = 'e.g. 5.0'; }
    };
    el('btn-cov-mw-spend-back').onclick = () => covShowPanel('result');
    el('btn-cov-mw-spend-create').onclick = () => handleCovMwSpend();
    if (el('btn-cov-mw-max')) el('btn-cov-mw-max').onclick = async () => {
        showLoading('Computing max...');
        try {
            const m = await mwMaxSompi();
            hideLoading();
            if (!m) { toast('No spendable balance', 'error'); return; }
            el('cov-mw-amount').value = sompiToKasStr(m);
        } catch (e) { hideLoading(); toast('Max failed: ' + e, 'error'); }
    };
    if (el('btn-cov-scan-mw-addr')) el('btn-cov-scan-mw-addr').onclick = () => covScanAddress('cov-mw-addr', 'Scan covenant address');
    el('btn-cov-scan-mw-dest').onclick = () => covScanAddress('cov-mw-dest', 'Scan destination');
    if (el('btn-cov-scan-mw-add')) el('btn-cov-scan-mw-add').onclick = () => covScanAddressAppend('cov-mw-addresses', 'Scan whitelist address');

    // ─── Tagged Vault (KIP-20 PoC) ───
    let _tvState = { sk: null, pk: null, addr: null, covId: null, covAddr: null, redeemHex: null };

    function tvLog(msg) {
        const log = el('tv-log');
        if (log) {
            log.style.display = 'block';
            log.textContent += (log.textContent ? '\n' : '') + msg;
            log.scrollTop = log.scrollHeight;
        }
        console.log('[TaggedVault] ' + msg);
    }

    if (el('btn-tv-back')) el('btn-tv-back').onclick = () => covShowPanel('menu');

    if (el('btn-tv-keygen')) el('btn-tv-keygen').onclick = () => {
        try {
            const kg = JSON.parse(tagged_vault_keygen(network));
            _tvState.sk = kg.secret_key_hex;
            _tvState.pk = kg.pubkey_hex;
            _tvState.addr = kg.address;
            el('tv-eph-address').textContent = kg.address;
            el('tv-eph-pubkey').textContent = kg.pubkey_hex;
            el('tv-keygen-result').classList.remove('hidden');
            tvLog('Keygen OK: ' + kg.address);
        } catch (e) {
            toast('Keygen failed: ' + e, 'error');
        }
    };

    if (el('btn-tv-genesis')) el('btn-tv-genesis').onclick = async () => {
        if (!_tvState.sk || !_tvState.addr) {
            toast('Generate ephemeral key first (step 1)', 'error');
            return;
        }
        const amountKas = parseFloat(el('tv-amount').value);
        if (!amountKas || amountKas < 0.1) {
            toast('Enter an amount >= 0.1 KAS', 'error');
            return;
        }
        const amountSompi = kasToSompi(el('tv-amount').value);
        const fee = 300000n; // TN10 compute mass

        tvLog('Genesis: ' + amountKas + ' KAS to tagged vault...');
        try {
            const wsUrl = await resolveNodeUrl();
            const result = JSON.parse(await tagged_vault_genesis(
                _tvState.addr,
                _tvState.sk,
                _tvState.pk,
                amountSompi,
                fee,
                network,
                wsUrl
            ));
            _tvState.covId = result.covenant_id_hex;
            _tvState.covAddr = result.covenant_address;
            _tvState.redeemHex = result.redeem_script_hex;
            el('tv-genesis-txid').textContent = result.txid;
            el('tv-covenant-id').textContent = result.covenant_id_hex;
            el('tv-covenant-addr').textContent = result.covenant_address;
            el('tv-genesis-result').classList.remove('hidden');
            tvLog('Genesis TX: ' + result.txid);
            tvLog('Covenant ID: ' + result.covenant_id_hex);
            toast('Genesis broadcast OK', 'ok', 3000);
        } catch (e) {
            tvLog('ERROR: ' + e);
            toast('Genesis failed: ' + e, 'error');
        }
    };

    if (el('btn-tv-spend')) el('btn-tv-spend').onclick = async () => {
        if (!_tvState.covId || !_tvState.covAddr) {
            toast('Create genesis first (step 2)', 'error');
            return;
        }
        tvLog('Spend: continuity TX from ' + _tvState.covAddr.slice(0, 20) + '...');
        try {
            const wsUrl = await resolveNodeUrl();
            const result = JSON.parse(await tagged_vault_spend(
                _tvState.covAddr,
                _tvState.sk,
                _tvState.pk,
                _tvState.covId,
                300000n, // TN10 compute mass
                network,
                wsUrl
            ));
            el('tv-spend-txid').textContent = result.txid;
            el('tv-spend-covid').textContent = result.covenant_id_hex;
            el('tv-spend-result').classList.remove('hidden');
            tvLog('Continuation TX: ' + result.txid);
            tvLog('Covenant ID (same): ' + result.covenant_id_hex);
            toast('Continuity spend OK! KIP-20 confirmed.', 'ok', 5000);
        } catch (e) {
            tvLog('ERROR: ' + e);
            toast('Spend failed: ' + e, 'error');
        }
    };

    if (el('btn-tv-split')) el('btn-tv-split').onclick = async () => {
        if (!_tvState.sk || !_tvState.addr) {
            toast('Generate ephemeral key first (step 1)', 'error');
            return;
        }
        tvLog('Split: genesis + split from ephemeral key...');
        try {
            const wsUrl = await resolveNodeUrl();

            // Step A: Create split vault genesis (fund from ephemeral)
            tvLog('Split step A: genesis...');
            const genResult = JSON.parse(await split_vault_genesis(
                _tvState.addr,
                _tvState.sk,
                _tvState.pk,
                300000000n, // 3 KAS
                300000n,
                network,
                wsUrl
            ));
            tvLog('Split genesis TX: ' + genResult.txid);
            tvLog('Split covenant addr: ' + genResult.covenant_address);
            tvLog('Split covenant ID: ' + genResult.covenant_id_hex);

            // Step B: Wait a moment for confirmation, then split
            tvLog('Split step B: splitting (2s delay)...');
            await new Promise(r => setTimeout(r, 2000));

            const splitResult = JSON.parse(await split_vault_spend(
                genResult.covenant_address,
                _tvState.sk,
                _tvState.pk,
                genResult.covenant_id_hex,
                300000n,
                network,
                wsUrl
            ));

            el('tv-split-txid').textContent = splitResult.txid;
            el('tv-split-covid').textContent = splitResult.covenant_id_hex;
            el('tv-split-amounts').textContent = splitResult.amount_a + ' / ' + splitResult.amount_b + ' sompi';
            el('tv-split-result').classList.remove('hidden');
            tvLog('Split TX: ' + splitResult.txid);
            tvLog('Output A: ' + splitResult.amount_a + ', Output B: ' + splitResult.amount_b);
            toast('Split confirmed! 5 KIP-20 opcodes exercised.', 'ok', 5000);
        } catch (e) {
            tvLog('ERROR: ' + e);
            toast('Split failed: ' + e, 'error');
        }
    };

    if (el('btn-tv-airgap')) el('btn-tv-airgap').onclick = async () => {
        if (!walletData) {
            toast('Load a wallet first (import kpub on the main screen)', 'error');
            return;
        }
        const amountKas = parseFloat(el('tv-airgap-amount').value);
        if (!amountKas || amountKas < 0.1) {
            toast('Enter an amount >= 0.1 KAS', 'error');
            return;
        }
        const amountSompi = kasToSompi(el('tv-airgap-amount').value);
        const fee = 300000n; // TN10 compute mass

        tvLog('Air-gap: building covenant PSKB...');
        try {
            const wsUrl = await resolveNodeUrl();
            const wallet = JSON.parse(walletData);

            // Extract owner pubkey from first receive address
            const firstAddr = wallet.receive_addresses[0];
            const addrInfo = JSON.parse(decode_address(firstAddr));
            const ownerPk = addrInfo.payload; // 32-byte hex from P2PK address
            const covInfo = JSON.parse(covenant_tagged_vault(ownerPk, network));
            tvLog('Covenant address: ' + covInfo.address);

            // Compute covenant_id. We need the UTXO outpoint that will fund it.
            // The PSKB builder selects UTXOs internally, so we need to pre-compute.
            // For now, pass the covenant_id_hex as empty and let the PSKB builder
            // compute it. Actually, create_covenant_pskb needs the covenant_id.
            // The covenant_id depends on the selected UTXO's outpoint + the output.
            // This is a chicken-and-egg: we need to select UTXOs first, then compute.
            // The WASM function handles this internally.

            // Actually, looking at the WASM export, it takes covenant_id_hex as input.
            // We need to compute it before calling. Let's fetch UTXOs first.
            const utxosJson = await fetch_utxos(walletData, wsUrl);
            const utxos = JSON.parse(utxosJson);
            if (!utxos || utxos.length === 0) {
                toast('No UTXOs in wallet', 'error');
                return;
            }

            // Select first UTXO(s) to cover amount + fee
            let selectedTotal = 0n;
            let selectedUtxo = null;
            for (const u of utxos) {
                if (BigInt(u.amount) >= amountSompi + fee) {
                    selectedUtxo = u;
                    selectedTotal = BigInt(u.amount);
                    break;
                }
            }
            if (!selectedUtxo) {
                // Try accumulating
                for (const u of utxos) {
                    selectedUtxo = u; // use first for outpoint
                    selectedTotal += BigInt(u.amount);
                    if (selectedTotal >= amountSompi + fee) break;
                }
            }
            if (!selectedUtxo || selectedTotal < amountSompi + fee) {
                toast('Insufficient funds', 'error');
                return;
            }

            // Compute covenant_id from the first UTXO's outpoint
            const covSpk = addrToSpkHex(covInfo.address);
            const cidResult = JSON.parse(tagged_vault_covenant_id(
                selectedUtxo.tx_id,
                selectedUtxo.index,  // u32 = Number
                amountSompi,          // u64 = BigInt
                covSpk
            ));
            const covIdHex = cidResult.covenant_id_hex;
            tvLog('Covenant ID: ' + covIdHex);

            // Get change address
            const changeAddr = wallet.change_addresses[0];

            // Build PSKB
            const pskbHex = await create_covenant_pskb(
                walletData,
                covInfo.address,
                amountSompi,
                fee,
                changeAddr,
                covIdHex,
                '',
                wsUrl
            );

            tvLog('PSKB ready: ' + pskbHex.length + ' chars');

            el('tv-airgap-addr').textContent = covInfo.address;
            el('tv-airgap-covid').textContent = covIdHex;
            el('tv-airgap-result').classList.remove('hidden');

            // Open the standard PSKT review screen (relay to KasSigner, sign, broadcast)
            openPsktReview(pskbHex);

        } catch (e) {
            tvLog('ERROR: ' + e);
            toast('Air-gap PSKB failed: ' + e, 'error');
        }
    };

    // Load existing covenant
    el('btn-cov-load-existing').onclick = () => {
        covShowPanel('load');
        if (el('cov-load-type')) {
            el('cov-load-type').style.display = '';
            const lbl = el('cov-load-type').previousElementSibling;
            if (lbl && lbl.classList.contains('input-label')) lbl.style.display = '';
        }
    };
    if (el('btn-cov-recover-chain')) {
        el('btn-cov-recover-chain').onclick = () => recoverCovenants();
    };
    if (el('btn-cov-import-scan')) {
        el('btn-cov-import-scan').onclick = () => {
            startScanner('Scan Covenant Backup QR', handleCovbScan, 'menu');
        };
    };
    // Swap hub buttons
    if (el('btn-swap-back')) el('btn-swap-back').onclick = () => covShowPanel('menu');
    if (el('btn-swap-create-new')) {
        el('btn-swap-create-new').onclick = () => {
            covSelectType('atomic-swap');
        };
    }
    if (el('btn-swap-join')) {
        el('btn-swap-join').onclick = () => {
            _scannerReturnPanel = 'swap';
            startScanner('Scan Swap Invite from counterparty', (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || invite.t !== 'swap-invite') { toast('Not a swap invite QR', 'error'); return; }
                    stopScanner();
                    showScreen('covenant');
                    covSelectType('atomic-swap');
                    _swapCounterpartyInvite = invite;
                    swapStateSave();
                    if (invite.pk) el('cov-swap-pk').value = invite.pk;
                    if (invite.h) el('cov-swap-hash').value = invite.h;
                    if (invite.a && el('cov-swap-hash-algo')) el('cov-swap-hash-algo').value = invite.a;
                    if (invite.d && !isNaN(Number(invite.d))) {
                        const theirDaa = Number(invite.d);
                        const currentDaa = estimateCurrentDaaFromUtxos();
                        let suggestedDaa;
                        if (currentDaa > 0 && theirDaa > currentDaa) {
                            // Halfway between now and their timeout
                            suggestedDaa = Math.floor(currentDaa + (theirDaa - currentDaa) / 2);
                        } else {
                            suggestedDaa = theirDaa;
                        }
                        if (el('cov-swap-locktime')) el('cov-swap-locktime').value = String(suggestedDaa);
                        // Also set the datetime picker to reflect the suggested time
                        const secondsFromNow = Math.floor((suggestedDaa - currentDaa) / 10);
                        if (secondsFromNow > 0 && el('cov-swap-datetime')) {
                            const targetDate = new Date(Date.now() + secondsFromNow * 1000);
                            const localIso = targetDate.getFullYear() + '-' + String(targetDate.getMonth()+1).padStart(2,'0') + '-' + String(targetDate.getDate()).padStart(2,'0') + 'T' + String(targetDate.getHours()).padStart(2,'0') + ':' + String(targetDate.getMinutes()).padStart(2,'0');
                            el('cov-swap-datetime').value = localIso;
                        }
                        if (el('cov-swap-daa-preview')) el('cov-swap-daa-preview').textContent = 'DAA ~' + suggestedDaa.toLocaleString() + ' (half of counterparty window)';
                    }
                    toast('Invite scanned. Review fields and generate.', 'ok', 3000);
                } catch (e) {
                    toast('Invalid swap invite QR: ' + e, 'error');
                }
            });
        };
    }
    if (el('btn-swap-manual-claim')) {
        el('btn-swap-manual-claim').onclick = () => {
            covShowPanel('atomic-claim');
            if (_swapCounterpartyInvite) {
                if (_swapCounterpartyInvite.addr) el('cov-claim-addr').value = _swapCounterpartyInvite.addr;
                if (_swapCounterpartyInvite.rs) el('cov-claim-script').value = _swapCounterpartyInvite.rs;
            }
            if (window._extractedPreimage) {
                el('cov-claim-preimage').value = window._extractedPreimage;
            }
            if (el('cov-claim-dest') && walletData && walletData.receive_addresses && walletData.receive_addresses.length > 0) {
                // Destination address left empty for user to fill
            }
            if (el('cov-claim-addr')) el('cov-claim-addr').dispatchEvent(new Event('input'));
        };
    }
    if (el('btn-swap-load')) {
        el('btn-swap-load').onclick = () => {
            covShowPanel('load');
            if (el('cov-load-type')) {
                el('cov-load-type').value = 'atomic-swap';
                el('cov-load-type').style.display = 'none';
                const lbl = el('cov-load-type').previousElementSibling;
                if (lbl && lbl.classList.contains('input-label')) lbl.style.display = 'none';
            }
        };
    }
    if (el('btn-swap-hub-resume')) {
        el('btn-swap-hub-resume').onclick = () => {
            if (lastCovenantResult && lastCovenantResult.type === 'atomic-swap') {
                covShowPanel('result');
            }
        };
    }
    if (el('btn-swap-hub-dismiss')) {
        el('btn-swap-hub-dismiss').onclick = () => {
            swapStateClear();
            _swapCounterpartyInvite = null;
            _swapUtxoOutpoint = null;
            _swapLastBalance = null;
            window._extractedPreimage = '';
            window._extractedPreimageHex = '';
            window._preimageFromChain = false;
            window._swapClaimBroadcasted = false;
            swapWatcherStop();
            if (lastCovenantResult && lastCovenantResult.type === 'atomic-swap') {
                lastCovenantResult = null;
                try { sessionStorage.removeItem('lastCovenantResult'); } catch (_) {}
            }
            swapHubRefresh();
            toast('Swap state cleared', 'ok', 1500);
        };
    }
    // ─── Adaptor Swap (Private) Button Handlers ───
    if (el('btn-adaptor-swap')) {
        el('btn-adaptor-swap').onclick = () => covShowPanel('adaptor');
    }
    if (el('btn-adaptor-back')) {
        el('btn-adaptor-back').onclick = () => covShowPanel('menu');
    }
    if (el('btn-adaptor-create')) {
        el('btn-adaptor-create').onclick = () => {
            adaptorStateClear(); // clear any old state
            covShowPanel('adaptor-create');
        };
    }
    if (el('btn-adaptor-create-back')) {
        el('btn-adaptor-create-back').onclick = () => covShowPanel('adaptor');
    }
    if (el('btn-adaptor-result-back')) {
        el('btn-adaptor-result-back').onclick = () => {
            const ret = _adaptorResultReturn;
            _adaptorResultReturn = null;
            covShowPanel(ret === 'menu' ? 'menu' : 'adaptor');
        };
    }
    if (el('btn-adaptor-join-back')) {
        el('btn-adaptor-join-back').onclick = () => {
            if (_adaptorState && _adaptorState.role === 'bob' && _adaptorState.myAddr && _adaptorState.myAdaptorSig) {
                covShowPanel('adaptor-result');
            } else {
                covShowPanel('adaptor');
            }
        };
    }
    // Alice: Generate Secret & Address
    if (el('btn-adaptor-create-go')) {
        el('btn-adaptor-create-go').onclick = async () => {
            _adaptorResultReturn = null; // fresh create session: Back from result -> swap menu
            if (!walletData) { toast('Load wallet first', 'error'); return; }
            const amountKas = parseFloat(el('adaptor-create-amount').value);
            if (!amountKas || amountKas <= 0) { toast('Enter an amount', 'error'); return; }

            // Compute timeout DAA from datetime input
            const dtVal = el('adaptor-create-datetime').value;
            if (!dtVal) { toast('Set a timeout', 'error'); return; }
            const targetDate = new Date(dtVal);
            const nowMs = Date.now();
            if (targetDate.getTime() <= nowMs) { toast('Timeout must be in the future', 'error'); return; }
            const currentDaa = await fetchCurrentDaa();
            if (!currentDaa) { toast('Cannot fetch current DAA', 'error'); return; }
            const deltaSec = (targetDate.getTime() - nowMs) / 1000;
            const aliceTimeoutDaa = currentDaa + Math.round(deltaSec * 10); // ~10 BPS on TN12
            // Bob's timeout will be shorter (half of Alice's delta, minimum 5 min gap)
            const bobDeltaSec = Math.max(deltaSec / 2, 300);
            const bobTimeoutDaa = currentDaa + Math.round(bobDeltaSec * 10);
            console.log('[KasSee] Adaptor swap timeouts: currentDaa=' + currentDaa + ', deltaSec=' + Math.round(deltaSec) + ', aliceDaa=' + aliceTimeoutDaa + ', bobDaa=' + bobTimeoutDaa);

            try {
                el('adaptor-create-status').textContent = 'Generating secret and keypair...';
                const secretJson = JSON.parse(adaptor_generate_secret());
                const keypairJson = JSON.parse(adaptor_generate_keypair());
                const ownerPk = getAccountPubkeyHex() || keypairJson.pubkey_hex;
                const w = walletData ? JSON.parse(walletData) : null;
                const myDestAddr = w && w.receive_addresses && w.receive_addresses[0] ? w.receive_addresses[0] : '';
                if (!myDestAddr) { toast('Load wallet first', 'error'); return; }
                _adaptorState = {
                    role: 'alice',
                    t_hex: secretJson.t_hex,
                    T_hex: secretJson.T_hex,
                    mySecretKey: keypairJson.secret_hex,
                    myPk: keypairJson.pubkey_hex,
                    myOwnerPk: ownerPk,
                    myDestAddr: myDestAddr,
                    myAmount: Math.round(amountKas * 1e8),
                    myTimeoutDaa: aliceTimeoutDaa,
                    bobTimeoutDaa: bobTimeoutDaa,
                    myAddr: null,
                    myRedeem: null,
                    counterPk: null,
                    counterOwnerPk: null,
                    counterAddr: null,
                    counterRedeem: null,
                    counterAmount: null,
                    counterAdaptorSig: null,
                    myAdaptorSig: null,
                    commitment: null,
                    completed: false,
                };
                adaptorStateSave();
                covShowPanel('adaptor-result');
            } catch (e) {
                el('adaptor-create-status').textContent = 'Error: ' + e;
                toast('Failed: ' + e, 'error');
            }
        };
    }
    // Alice: Share invite QR (now includes her pre-computed adaptor sig)
    if (el('btn-adaptor-share-invite')) {
        el('btn-adaptor-share-invite').onclick = () => {
            if (!_adaptorState) { toast('Create a swap first', 'error'); return; }
            // Pre-compute commitment from T (both sides can derive this after QR 1)
            if (!_adaptorState.myAdaptorSig) {
                const commitment = adaptor_swap_commitment(
                    _adaptorState.T_hex, _adaptorState.T_hex,
                    BigInt(0), BigInt(0)
                );
                _adaptorState.commitment = commitment;
                const adaptorResult = JSON.parse(adaptor_create_sig(
                    _adaptorState.mySecretKey, commitment, _adaptorState.T_hex
                ));
                _adaptorState.myAdaptorSig = adaptorResult.adaptor_sig_hex;
                adaptorStateSave();
            }
            const invite = JSON.stringify({
                v: 1, t: 'adaptor-invite',
                pk: _adaptorState.myPk,
                opk: _adaptorState.myOwnerPk,
                da: _adaptorState.myDestAddr,
                T: _adaptorState.T_hex,
                a: _adaptorState.myAmount,
                at: _adaptorState.myTimeoutDaa,
                bt: _adaptorState.bobTimeoutDaa,
                as: _adaptorState.myAdaptorSig,
            });
            try {
                stopQrCycle(); // stale multi-frame animation must not overwrite this single-frame invite QR
                const svg = generate_qr_svg_text(invite);
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Private Swap Invite \u2014 counterparty scans this';
                window._adaptorQrReturn = true;
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = 'none'; // pure publish screen: counterparty scans this, nothing to scan back here (scan happens via btn-adaptor-scan-response)
                _broadcastReturnScreen = 'covenant';
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
            } catch (e) {
                toast('QR failed: ' + e, 'error');
            }
        };
    }
    // Bob: Join Private Swap (scan Alice's invite)
    if (el('btn-adaptor-join')) {
        el('btn-adaptor-join').onclick = () => {
            adaptorStateClear(); // clear any old state
            startScanner('Scan Private Swap Invite', async (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || invite.t !== 'adaptor-invite') {
                        toast('Not a private swap invite', 'error'); return;
                    }
                    stopScanner();
                    const bobKeypair = JSON.parse(adaptor_generate_keypair());
                    const bobOwnerPk = getAccountPubkeyHex() || bobKeypair.pubkey_hex;
                    const bw = walletData ? JSON.parse(walletData) : null;
                    const bobDestAddr = bw && bw.receive_addresses && bw.receive_addresses[0] ? bw.receive_addresses[0] : '';
                    _adaptorState = {
                        role: 'bob',
                        t_hex: null,
                        T_hex: invite.T,
                        mySecretKey: bobKeypair.secret_hex,
                        myPk: bobKeypair.pubkey_hex,
                        myOwnerPk: bobOwnerPk,
                        myDestAddr: bobDestAddr,
                        myAmount: null,
                        myTimeoutDaa: invite.bt || 0,
                        counterPk: invite.pk,
                        counterOwnerPk: invite.opk || invite.pk,
                        counterDestAddr: invite.da || '',
                        counterAddr: null,
                        counterRedeem: null,
                        counterAmount: invite.a,
                        counterTimeoutDaa: invite.at || 0,
                        counterAdaptorSig: invite.as || null,
                        myAdaptorSig: null,
                        commitment: null,
                        completed: false,
                    };
                    showScreen('covenant');
                    covShowPanel('adaptor-join');
                    el('adaptor-join-info').classList.remove('hidden');
                    el('adaptor-join-alice-amount').textContent = (invite.a / 1e8).toFixed(8).replace(/\.?0+$/, '') + ' KAS';
                    if (invite.bt) {
                        const bobDaa = invite.bt;
                        const nowDaa = await fetchCurrentDaa();
                        if (nowDaa) {
                            const deltaSec = (bobDaa - nowDaa) / 10;
                            const targetDate = new Date(Date.now() + deltaSec * 1000);
                            const timeStr = targetDate.toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
                            el('adaptor-join-timeout').textContent = 'Your refund after ' + timeStr;
                        } else {
                            el('adaptor-join-timeout').textContent = 'DAA ' + bobDaa;
                        }
                    }
                    el('btn-adaptor-join-create').style.display = '';
                    adaptorStateSave();
                    toast('Invite scanned.', 'ok', 2000);
                } catch (e) {
                    toast('Invalid invite: ' + e, 'error');
                }
            });
        };
    }
    // Bob: Create UTXO & adaptor
    if (el('btn-adaptor-join-create')) {
        el('btn-adaptor-join-create').onclick = async () => {
            if (!walletData || !_adaptorState || _adaptorState.role !== 'bob') {
                toast('Load wallet and scan invite first', 'error'); return;
            }
            const amountKas = parseFloat(el('adaptor-join-amount').value);
            if (!amountKas || amountKas <= 0) { toast('Enter your amount', 'error'); return; }
            try {
                _adaptorState.myAmount = Math.round(amountKas * 1e8);
                const net = network;
                // Bob's UTXO is locked to Alice's pubkey (Alice claims it)
                const addrJson = JSON.parse(adaptor_swap_address(
                    _adaptorState.counterPk, _adaptorState.myOwnerPk,
                    _adaptorState.counterDestAddr || '',
                    BigInt(String(_adaptorState.myTimeoutDaa || 0)), net
                ));
                _adaptorState.myAddr = addrJson.address;
                _adaptorState.myRedeem = addrJson.redeem_script_hex;

                // Compute counterparty (Alice's) address so Bob can recover claim path
                try {
                    const counterAddrJson = JSON.parse(adaptor_swap_address(
                        _adaptorState.myPk, _adaptorState.counterOwnerPk || _adaptorState.counterPk,
                        _adaptorState.myDestAddr || '',
                        BigInt(String(_adaptorState.counterTimeoutDaa || 0)), net
                    ));
                    _adaptorState.counterAddr = counterAddrJson.address;
                    _adaptorState.counterRedeem = counterAddrJson.redeem_script_hex;
                } catch (e) { console.warn('[KasSee] Could not compute counter address:', e); }

                // Compute commitment
                const commitment = adaptor_swap_commitment(
                    _adaptorState.T_hex, _adaptorState.T_hex, BigInt(0), BigInt(0)
                );
                _adaptorState.commitment = commitment;

                // Create adaptor sig
                const adaptorResult = JSON.parse(adaptor_create_sig(
                    _adaptorState.mySecretKey, commitment, _adaptorState.T_hex
                ));
                _adaptorState.myAdaptorSig = adaptorResult.adaptor_sig_hex;
                adaptorStateSave();

                // Show response QR immediately
                const response = JSON.stringify({
                    v: 1, t: 'adaptor-response',
                    pk: _adaptorState.myPk,
                    opk: _adaptorState.myOwnerPk,
                    da: _adaptorState.myDestAddr,
                    addr: _adaptorState.myAddr,
                    rs: _adaptorState.myRedeem,
                    a: _adaptorState.myAmount,
                    as: _adaptorState.myAdaptorSig,
                });
                stopQrCycle(); // stale multi-frame animation must not overwrite this single-frame response QR
                const svg = generate_qr_svg_text(response);
                el('qr-container').innerHTML = svg;
                el('qr-frame-info').innerHTML = '';
                el('qr-display-title').textContent = 'Response QR \u2014 counterparty scans this';
                window._adaptorQrReturn = true;
                el('btn-scan-next-sig').style.display = 'none';
                el('btn-copy-kspt').style.display = 'none';
                if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = 'none'; // pure publish screen: counterparty scans this, nothing to scan back here
                _broadcastReturnScreen = 'covenant';
                if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                showScreen('qr-display');
                covAddActive('adaptor-swap', { address: _adaptorState.myAddr, redeem_script_hex: _adaptorState.myRedeem, counterparty_pk: _adaptorState.counterPk || '', adaptor_point: _adaptorState.T_hex || '', locktime_daa: _adaptorState.myTimeoutDaa || 0 });
                toast('Response QR ready. Fund your address after sharing.', 'ok', 3000);
            } catch (e) {
                toast('Failed: ' + e, 'error');
            }
        };
    }
    // Alice: Scan Bob's response
    if (el('btn-adaptor-scan-response')) {
        el('btn-adaptor-scan-response').onclick = () => {
            if (!_adaptorState || _adaptorState.role !== 'alice') {
                toast('Create a swap first', 'error'); return;
            }
            startScanner('Scan Counterparty Response', (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const resp = JSON.parse(text);
                    if (!resp || resp.t !== 'adaptor-response') {
                        toast('Not a swap response QR', 'error'); return;
                    }
                    stopScanner();
                    // Store Bob's info
                    _adaptorState.counterPk = resp.pk;
                    _adaptorState.counterOwnerPk = resp.opk || resp.pk;
                    _adaptorState.counterDestAddr = resp.da || '';
                    _adaptorState.counterAddr = resp.addr;
                    _adaptorState.counterRedeem = resp.rs;
                    _adaptorState.counterAmount = resp.a;
                    _adaptorState.counterAdaptorSig = resp.as || null;

                    // Compute commitment (Alice is initiator, her pk first)
                    // Compute commitment from T (same formula both sides use)
                    const commitment = adaptor_swap_commitment(
                        _adaptorState.T_hex, _adaptorState.T_hex,
                        BigInt(0), BigInt(0)
                    );
                    _adaptorState.commitment = commitment;

                    // Verify Bob's adaptor sig if present
                    if (resp.as) {
                        const valid = adaptor_verify_sig(resp.pk, commitment, resp.as, _adaptorState.T_hex);
                        if (!valid) {
                            toast('Counterparty adaptor signature verification FAILED', 'error');
                            return;
                        }
                    }

                    // Alice's UTXO is locked to Bob's pubkey (Bob claims it)
                    const net = network;
                    const addrJson = JSON.parse(adaptor_swap_address(
                        resp.pk, _adaptorState.myOwnerPk || _adaptorState.myPk,
                        _adaptorState.counterDestAddr || '',
                        BigInt(String(_adaptorState.myTimeoutDaa || 0)), net
                    ));
                    _adaptorState.myAddr = addrJson.address;
                    _adaptorState.myRedeem = addrJson.redeem_script_hex;

                    // Alice keeps her adaptor sig from the invite (shared with Bob).
                    // Do NOT create a new one here, or Bob's extraction will fail.

                    showScreen('covenant');
                    covShowPanel('adaptor-result');
                    el('adaptor-result-addr').textContent = _adaptorState.myAddr;
                    el('adaptor-result-balance').textContent = (_adaptorState.myAmount / 1e8) + ' KAS (fund this address)';
                    el('btn-adaptor-fund').style.display = '';
                    el('btn-adaptor-complete-claim').style.display = '';
                    el('adaptor-result-status').textContent = 'Counterparty verified. Fund your address, then claim theirs.';
                    covAddActive('adaptor-swap', { address: _adaptorState.myAddr, redeem_script_hex: _adaptorState.myRedeem, counterparty_pk: _adaptorState.counterPk || '', adaptor_point: _adaptorState.T_hex || '', locktime_daa: _adaptorState.myTimeoutDaa || 0 });
                    adaptorStateSave();
                    toast('Response scanned. Fund and claim.', 'ok', 3000);
                } catch (e) {
                    toast('Invalid response: ' + e, 'error');
                }
            });
        };
    }
    // Alice: Fund (opens standard deposit flow)
    if (el('btn-adaptor-fund')) {
        el('btn-adaptor-fund').onclick = async () => {
            if (!_adaptorState || !_adaptorState.myAddr) { toast('Set up swap first', 'error'); return; }
            lastCovenantResult = {
                address: _adaptorState.myAddr,
                redeem_script_hex: _adaptorState.myRedeem,
                type: 'adaptor-swap',
                locktime_daa: _adaptorState.myTimeoutDaa || 0,
                _swap_secret_key: _adaptorState.mySecretKey || '',
                _swap_adaptor_sig: _adaptorState.myAdaptorSig || '',
                _swap_counter_addr: _adaptorState.counterAddr || '',
                _swap_counter_redeem: _adaptorState.counterRedeem || '',
                _swap_counter_adaptor_sig: _adaptorState.counterAdaptorSig || '',
                _swap_T_hex: _adaptorState.T_hex || '',
                _swap_my_pk: _adaptorState.myPk || '',
            };
            _broadcastReturnScreen = 'covenant';
            await handleCovFund();
        };
    }
    // Alice: Complete & Claim Bob's funds
    if (el('btn-adaptor-complete-claim')) {
        el('btn-adaptor-complete-claim').onclick = async () => {
            if (!_adaptorState) { toast('No swap state', 'error'); return; }
            if (!_adaptorState.mySecretKey) { toast('Missing signing key', 'error'); return; }

            try {
                const wsUrl = await resolveNodeUrl();
                const fee = getCovFee();
                const commitment = _adaptorState.commitment || adaptor_swap_commitment(
                    _adaptorState.T_hex, _adaptorState.T_hex, BigInt(0), BigInt(0)
                );
                _adaptorState.commitment = commitment;

                if (_adaptorState.role === 'alice') {
                    // ─── Alice's claim: complete her adaptor with secret t ───
                    if (!_adaptorState.counterAddr || !_adaptorState.counterRedeem) {
                        toast('Scan counterparty response first', 'error'); return;
                    }
                    el('adaptor-result-status').textContent = 'Creating adaptor signature...';

                    // Create adaptor (Alice signs commitment, tweaked by T)
                    if (!_adaptorState.myAdaptorSig) {
                        const adaptorResult = JSON.parse(adaptor_create_sig(
                            _adaptorState.mySecretKey, commitment, _adaptorState.T_hex
                        ));
                        _adaptorState.myAdaptorSig = adaptorResult.adaptor_sig_hex;
                    }

                    // Complete with secret t
                    el('adaptor-result-status').textContent = 'Completing signature...';
                    const completedSigHex = adaptor_complete_sig(_adaptorState.myAdaptorSig, _adaptorState.t_hex);

                    // Verify
                    const isValid = adaptor_bip340_verify(_adaptorState.myPk, commitment, completedSigHex);
                    if (!isValid) { toast('BIP340 verification failed!', 'error'); return; }

                    // Build sig_script and broadcast
                    el('adaptor-result-status').textContent = 'Broadcasting claim TX...';
                    const sigScriptHex = adaptor_build_sig_script(completedSigHex, commitment, _adaptorState.counterRedeem);

                    const w = walletData ? JSON.parse(walletData) : null;
                    const destAddr = w && w.receive_addresses && w.receive_addresses[0] ? w.receive_addresses[0] : '';
                    if (!destAddr) { toast('Load wallet for destination', 'error'); return; }

                    _adaptorState.completedSig = completedSigHex;
                    _adaptorState.sigScript = sigScriptHex;
                    _adaptorState.completed = true;
                    adaptorStateSave();

                    const txid = await adaptor_broadcast_claim(
                        _adaptorState.counterAddr, destAddr, sigScriptHex, fee, wsUrl
                    );
                    el('adaptor-result-status').innerHTML =
                        '<span style="color:var(--teal)">\u2705 Claim TX broadcast! TXID: ' + txid.substring(0, 16) + '...</span>';
                    toast('Claim broadcast! ' + txid.substring(0, 16) + '...', 'ok', 8000);

                } else if (_adaptorState.role === 'bob') {
                    // ─── Bob's claim: extract secret from Alice's on-chain TX ───
                    // Reload state (manual paste saves to sessionStorage)
                    adaptorStateLoad();
                    // Check if Bob's UTXO was spent (Alice claimed it)
                    const bobUtxos = await fetch_utxos_for_address_js(_adaptorState.myAddr, wsUrl);
                    const bobBalance = JSON.parse(bobUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);

                    if (bobBalance > 0n) {
                        // Alice hasn't claimed yet. Start watcher.
                        adaptorWatcherStart();
                        toast('Alice hasn\'t claimed yet. Monitoring chain...', 'ok', 3000);
                        el('adaptor-result-status').textContent = 'Waiting for Alice to claim your UTXO...';
                        return;
                    }

                    // Bob's UTXO is spent. Check if we have Alice's completed sig.
                    if (!_adaptorState.counterCompletedSig) {
                        // Try REST API fallback: fetch spending TX from explorer
                        el('adaptor-result-status').textContent = 'Extracting secret from chain (REST fallback)...';
                        try {
                            const apiBase = network === 'testnet-10' ? 'https://api-tn10.kaspa.org' : network === 'testnet-12' ? 'https://api-tn12.kaspa.org' : 'https://api.kaspa.org';
                            const resp = await fetch(apiBase + '/addresses/' + _adaptorState.myAddr + '/full-transactions?limit=10&resolve_previous_outpoints=no');
                            if (resp.ok) {
                                const txs = await resp.json();
                                // Find the TX that SPENDS our UTXO (input matches our address)
                                for (const tx of txs) {
                                    if (!tx.inputs) continue;
                                    for (const inp of tx.inputs) {
                                        if (!inp.signature_script) continue;
                                        const sigHex = inp.signature_script;
                                        // sig_script starts with 0x40 (push 64 bytes) + 64-byte sig
                                        if (sigHex.length >= 130 && sigHex.startsWith('40')) {
                                            const completedSigHex = sigHex.substring(2, 130);
                                            console.log('[KasSee] REST fallback: extracted completed sig: ' + completedSigHex.substring(0, 32) + '...');
                                            _adaptorState.counterCompletedSig = completedSigHex;
                                            adaptorStateSave();
                                            toast('Secret extracted via REST fallback!', 'ok', 3000);
                                        }
                                    }
                                    if (_adaptorState.counterCompletedSig) break;
                                }
                            }
                        } catch (restErr) {
                            console.warn('[KasSee] REST fallback failed:', restErr);
                        }

                        if (!_adaptorState.counterCompletedSig) {
                            // Still no luck. Start watcher and show manual help.
                            adaptorWatcherStart();
                            toast('Secret not yet extracted. Check explorer for your UTXO address.', 'ok', 5000);
                            const explorerUrl = (network === 'testnet-12' || network === 'testnet-10')
                                ? 'https://kas.fyi/address/' + _adaptorState.myAddr + '?network=' + network
                                : 'https://kas.fyi/address/' + _adaptorState.myAddr;
                            el('adaptor-result-status').innerHTML =
                                'Could not extract secret automatically.<br>' +
                                '<a href="' + explorerUrl + '" target="_blank" style="color:var(--teal)">View your UTXO on explorer</a><br>' +
                                '<span style="font-size:10px;color:var(--text-muted)">Find the spending TX, copy the PUSH_64 value (item 0), paste below:</span><br>' +
                                '<input type="text" id="adaptor-manual-sig" placeholder="Paste 128-char hex signature" style="width:100%;margin:6px 0;padding:6px;font-size:11px;background:var(--card-bg);border:1px solid var(--border);border-radius:4px;color:var(--text-primary)">' +
                                '<button id="btn-adaptor-manual-save" style="width:100%;padding:6px;font-size:12px;background:var(--teal);border:none;border-radius:4px;color:#000;cursor:pointer;font-weight:600">Save & Retry Claim</button>';
                            // Wire the save button without inline onclick
                            setTimeout(() => {
                                const saveBtn = el('btn-adaptor-manual-save');
                                if (saveBtn) saveBtn.addEventListener('click', () => {
                                    const v = el('adaptor-manual-sig').value.trim();
                                    if (v.length !== 128) { toast('Enter 128 hex chars', 'error'); return; }
                                    _adaptorState.counterCompletedSig = v;
                                    adaptorStateSave();
                                    toast('Sig saved. Tap Claim again.', 'ok', 3000);
                                });
                            }, 50);
                            return;
                        }
                    }

                    el('adaptor-result-status').textContent = 'Extracting adaptor secret...';

                    // Extract t from Alice's completed sig vs Alice's adaptor sig
                    if (!_adaptorState.counterAdaptorSig) {
                        toast('Missing Alice\'s adaptor signature from invite', 'error'); return;
                    }
                    const extractedSecret = adaptor_extract_secret(
                        _adaptorState.counterCompletedSig, _adaptorState.counterAdaptorSig
                    );

                    // Complete Bob's adaptor with extracted t
                    el('adaptor-result-status').textContent = 'Completing your signature...';
                    let bobCompletedSig = adaptor_complete_sig(_adaptorState.myAdaptorSig, extractedSecret);

                    // BIP340 parity: try verification, if fails try negated secret
                    let isValid = adaptor_bip340_verify(_adaptorState.myPk, commitment, bobCompletedSig);
                    if (!isValid) {
                        console.log('[KasSee] BIP340 verification failed with extracted t, trying negated...');
                        const negatedSecret = adaptor_negate_scalar(extractedSecret);
                        bobCompletedSig = adaptor_complete_sig(_adaptorState.myAdaptorSig, negatedSecret);
                        isValid = adaptor_bip340_verify(_adaptorState.myPk, commitment, bobCompletedSig);
                        if (!isValid) {
                            console.log('[KasSee] BIP340 verification also failed with negated t, broadcasting anyway...');
                        } else {
                            console.log('[KasSee] Negated secret worked!');
                        }
                    }

                    // Alice's UTXO: locked to Bob's pk. Compute address.
                    const net = network;
                    const aliceUtxoJson = JSON.parse(adaptor_swap_address(
                        _adaptorState.myPk, _adaptorState.counterOwnerPk || _adaptorState.counterPk,
                        _adaptorState.myDestAddr || '',
                        BigInt(String(_adaptorState.counterTimeoutDaa || 0)), net
                    ));
                    const aliceUtxoAddr = aliceUtxoJson.address;
                    const aliceUtxoRedeem = aliceUtxoJson.redeem_script_hex;

                    // Check Alice's UTXO has funds
                    const aliceUtxos = await fetch_utxos_for_address_js(aliceUtxoAddr, wsUrl);
                    const aliceBalance = JSON.parse(aliceUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);
                    if (aliceBalance === 0n) { toast('Alice\'s UTXO has no funds', 'error'); return; }

                    // Build sig_script and broadcast
                    el('adaptor-result-status').textContent = 'Broadcasting claim TX...';
                    const sigScriptHex = adaptor_build_sig_script(bobCompletedSig, commitment, aliceUtxoRedeem);

                    const w = walletData ? JSON.parse(walletData) : null;
                    const destAddr = w && w.receive_addresses && w.receive_addresses[0] ? w.receive_addresses[0] : '';
                    if (!destAddr) { toast('Load wallet for destination', 'error'); return; }

                    _adaptorState.completed = true;
                    adaptorStateSave();

                    const txid = await adaptor_broadcast_claim(
                        aliceUtxoAddr, destAddr, sigScriptHex, fee, wsUrl
                    );
                    el('adaptor-result-status').innerHTML =
                        '<span style="color:var(--teal)">\u2705 Claim TX broadcast! TXID: ' + txid.substring(0, 16) + '...</span>';
                    toast('Bob claim broadcast! ' + txid.substring(0, 16) + '...', 'ok', 8000);
                }
            } catch (e) {
                toast('Failed: ' + e, 'error');
                el('adaptor-result-status').textContent = 'Error: ' + e;
            }
        };
    }
    // Adaptor Owner Refund: routes to standard owner spend panel
    if (el('btn-adaptor-owner-refund')) {
        el('btn-adaptor-owner-refund').onclick = () => {
            if (!_adaptorState || !_adaptorState.myAddr) { toast('No swap state', 'error'); return; }
            lastCovenantResult = {
                address: _adaptorState.myAddr,
                redeem_script_hex: _adaptorState.myRedeem,
                type: 'adaptor-swap',
                // Without this the CLTV gate/banner see 0 and silently skip —
                // the refund rode all the way to a node rejection.
                locktime_daa: _adaptorState.myTimeoutDaa || 0,
            };
            covShowPanel('owner');
            if (el('cov-owner-panel')) el('cov-owner-panel').dataset.covOwnerType = 'adaptor-swap';
            el('cov-owner-addr').value = _adaptorState.myAddr;
            el('cov-owner-script').value = _adaptorState.myRedeem;
            // This entry bypasses the generic owner-panel code path where the
            // CLTV banner is shown, so render it here.
            if (lastCovenantResult.locktime_daa > 0) {
                (async () => {
                    try {
                        let d = 0;
                        try { d = await fetchCurrentDaa(); } catch (_) {}
                        if (!d && typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) d = _lastKnownDaa;
                        const lt = Number(lastCovenantResult.locktime_daa);
                        if (d > 0 && d < lt) {
                            window.piggyStatusBanner({
                                text: 'Owner refund NOT available yet: timelock matures in ~' +
                                      formatDuration(Math.floor((lt - d) / 10)) +
                                      '. Until then only the counterparty claim is valid.',
                                color: 'var(--error, #f44336)'
                            });
                        } else if (d > 0) {
                            window.piggyStatusBanner({
                                text: 'Timelock matured — owner refund available now.',
                                color: 'var(--accent, #4caf50)'
                            });
                        }
                    } catch (_) {}
                })();
            }
        };
    }
    // Hub Resume: navigate to adaptor-result
    if (el('btn-adaptor-resume')) {
        el('btn-adaptor-resume').onclick = () => {
            if (!_adaptorState) { toast('No active swap', 'error'); return; }
            covShowPanel('adaptor-result');
        };
    }
        // Adaptor dismiss
    if (el('btn-adaptor-dismiss')) {
        el('btn-adaptor-dismiss').onclick = () => {
            adaptorStateClear();
            const activeEl = el('adaptor-hub-active');
            if (activeEl) activeEl.classList.add('hidden');
            toast('Private swap cleared', 'ok', 1500);
        };
    }
    el('btn-cov-load-back').onclick = () => covShowPanel(el('cov-load-type') && el('cov-load-type').value === 'atomic-swap' ? 'swap' : 'menu');
    // Scan covenant invite QR on Load Existing panel
    if (el('btn-cov-load-scan')) {
        el('btn-cov-load-scan').onclick = () => {
            startScanner('Scan Covenant Invite QR', async (raw) => {
                try {
                    const text = new TextDecoder().decode(raw);
                    const invite = JSON.parse(text);
                    if (!invite || (invite.t !== 'cov-invite' && invite.t !== 'swap-invite')) {
                        toast('Not a covenant invite QR', 'error'); return;
                    }
                    // Fill the load form
                    if (invite.addr) el('cov-load-addr').value = invite.addr;
                    if (invite.rs) el('cov-load-script').value = invite.rs;
                    if (invite.ct) el('cov-load-type').value = invite.ct;
                    stopScanner();

                    // Crowdfund invite: route to create panel (contributor creates own P2SH)
                    if (invite.ct === 'crowdfund') {
                        covSelectType('crowdfund');
                        // Switch to contributor tab
                        el('crowdfund-organizer-fields').style.display = 'none';
                        el('crowdfund-contributor-fields').style.display = '';
                        el('btn-crowdfund-role-organizer').className = 'btn btn-outline';
                        el('btn-crowdfund-role-contributor').className = 'btn btn-primary';
                        // Fill locktime from invite
                        if (invite.d) el('cov-crowdfund-contrib-locktime').value = invite.d;
                        // Store organizer pubkey for dual-gate
                        if (invite.opk) window._crowdfundOrganizerPk = invite.opk;
                        // Store campaign name for display
                        if (invite.name) window._crowdfundCampaignName = invite.name;
                        // Fetch VK from TX payload via REST API
                        if (invite.tx) {
                            try {
                                const apiBase = network === 'testnet-10' ? 'https://api-tn10.kaspa.org' : 'https://api.kaspa.org';
                                const resp = await fetch(apiBase + '/transactions/' + invite.tx);
                                if (resp.ok) {
                                    const txData = await resp.json();
                                    if (txData.payload && txData.payload.length > 0) {
                                        window._crowdfundVk = txData.payload;
                                        el('cov-crowdfund-vk').value = txData.payload;
                                        console.log('[KasSee] VK from TX payload:', txData.payload.substring(0, 20) + '...');
                                    } else {
                                        console.log('[KasSee] TX payload empty or missing');
                                    }
                                } else {
                                    console.log('[KasSee] REST API returned', resp.status);
                                }
                            } catch (e) {
                                console.log('[KasSee] REST fetch failed:', e);
                            }
                        }
                        // Fallback: use VK from localStorage (same device as organizer)
                        if (!el('cov-crowdfund-vk').value && window._crowdfundVk) {
                            el('cov-crowdfund-vk').value = window._crowdfundVk;
                        }
                        if (!el('cov-crowdfund-vk').value) {
                            toast('VK not found. Paste it manually from organizer.', 'warn', 4000);
                        }
                        showScreen('covenant');
                        covShowPanel('create');
                        toast('Campaign: ' + (invite.goal || '?') + ' KAS goal. Tap Generate to join.', 'ok', 3000);
                        return;
                    }

                    showScreen('covenant');
                    covShowPanel('load');
                    window._covLoadedFromInvite = true;
                    if (invite.id) window._covLoadedInactivityDaa = invite.id;
                    if (invite.ldi) window._covLoadedLdi = invite.ldi;
                    // Store oracle invite fields for role detection on load
                    if (invite.ct === 'oracle') {
                        window._covLoadedOracleInvite = { opk: invite.opk || '', bpk: invite.bpk || '', own: invite.own || '', ldi: invite.ldi || '' };
                    } else {
                        window._covLoadedOracleInvite = null;
                    }
                    toast('Invite scanned. Tap Load Covenant.', 'ok', 2000);
                } catch (e) {
                    toast('Invalid invite QR: ' + e, 'error');
                }
            }, 'load');
        };
    }
    // Load covenant from backup file (.covb or .cov)
    if (el('btn-cov-load-file')) {
        el('btn-cov-load-file').onclick = () => el('cov-load-file-input').click();
        el('cov-load-file-input').onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            try {
                const buf = await file.arrayBuffer();
                const bytes = new Uint8Array(buf);
                await handleCovbScan(bytes);
            } catch (err) {
                toast('File import failed: ' + (err.message || err), 'error');
            }
            e.target.value = ''; // reset so same file can be re-imported
        };
    }
    el('btn-cov-load-submit').onclick = () => {
        const addr = el('cov-load-addr').value.trim();
        const script = el('cov-load-script').value.trim();
        const type = el('cov-load-type').value;
        if (!addr) { toast('Enter covenant address', 'error'); return; }
        if (!script) { toast('Enter redeem script hex', 'error'); return; }
        // Auto-extract locktime from redeem script (find push before 0xb0=CLTV or 0xb1=CSV)
        let locktime = null;
        try {
            const bytes = new Uint8Array(script.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            let lastPush = 0;
            let i = 0;
            while (i < bytes.length) {
                const op = bytes[i];
                if (op === 0xb0 || op === 0xb1) { locktime = lastPush; break; }
                if (op === 0x00) { lastPush = 0; i++; }
                else if (op >= 0x51 && op <= 0x60) { lastPush = op - 0x50; i++; }
                else if (op >= 0x01 && op <= 0x4b) {
                    const len = op;
                    if (i + 1 + len <= bytes.length) {
                        let val = 0n;
                        for (let j = 0; j < len; j++) val |= BigInt(bytes[i + 1 + j]) << BigInt(j * 8);
                        lastPush = Number(val);
                    }
                    i += 1 + len;
                } else if (op === 0x4c) {
                    const len = bytes[i + 1] || 0;
                    i += 2 + len;
                } else { i++; }
            }
        } catch (_) {}
        const result = {
            address: addr,
            redeem_script_hex: script,
            locktime_daa: locktime,
            type: type,
            loaded: true,
            role: window._covLoadedFromInvite ? 'beneficiary' : undefined,
        };
        if (window._covLoadedInactivityDaa) result.inactivity_daa = window._covLoadedInactivityDaa;
        // Restore locktime ISO date from invite (ldi field)
        if (window._covLoadedLdi) { result.locktime_date_iso = window._covLoadedLdi; window._covLoadedLdi = null; }
        window._covLoadedFromInvite = false;
        window._covLoadedInactivityDaa = null;
        // Escrow: detect role from script pubkeys vs loaded wallet
        if (result.type === 'escrow' && result.role === 'beneficiary') {
            ensureEscrowParams(result);
            const myAcctPk = getAccountPubkeyHex() || '';
            const myDerivedPk = getOwnerPubkeyHex() || '';
            const matchesPk = (target) => walletMatchesPk(target);
            if (matchesPk(result.arbiter_pk)) {
                result.role = 'arbiter';
            } else if (matchesPk(result.alice_pk)) {
                result.role = 'owner';
            }
        }
        // Oracle: detect role from invite pubkeys vs loaded wallet
        if (result.type === 'oracle' && window._covLoadedOracleInvite) {
            const oi = window._covLoadedOracleInvite;
            if (oi.opk) result.oracle_pubkey_hex = oi.opk;
            if (oi.bpk) result.beneficiary_pubkey_hex = oi.bpk;
            if (oi.own) result.owner_pubkey_hex = oi.own;
            if (oi.ldi) result.locktime_date_iso = oi.ldi;
            const myAcctPk = getAccountPubkeyHex() || '';
            const myAddrPk = getOwnerPubkeyHex() || '';
            const matchesPkO = (target) => walletMatchesPk(target);
            if (matchesPkO(oi.opk)) {
                result.role = 'oracle';
            } else if (matchesPkO(oi.bpk)) {
                result.role = 'beneficiary';
            }
            window._covLoadedOracleInvite = null;
        }
        lastCovenantResult = result;
        ensureAllowanceParams(lastCovenantResult);
        try { sessionStorage.setItem('lastCovenantResult', JSON.stringify(lastCovenantResult)); } catch (_) {}
        covAddActive(type, result);
        covShowPanel('result');
        covUpdateResultButtons(type);
        el('cov-result-addr').textContent = result.address;
        el('cov-result-script').textContent = result.redeem_script_hex;
        covRenderMetaLine(result);
        el('cov-result-balance').style.display = 'none';
        toast('Covenant loaded' + (locktime ? ' (locktime: DAA ' + locktime + ')' : ''), 'ok', 2000);
    };

    el('btn-cov-scan-oracle-attestation').onclick = () => startScanner('Scan Oracle Attestation QR', (data) => {
        // Device emits 96 raw bytes: sig (64) + hash (32)
        // Full attestation from KasSee: JSON { v, t, sig, hash, text }
        const raw = new Uint8Array(data);
        if (raw.length === 96) {
            const sigHex = Array.from(raw.slice(0, 64)).map(b => b.toString(16).padStart(2, '0')).join('');
            const hashHex = Array.from(raw.slice(64, 96)).map(b => b.toString(16).padStart(2, '0')).join('');
            stopScanner();
            el('cov-oracle-claim-sig').value = sigHex;
            el('cov-oracle-claim-hash').value = hashHex;
            showScreen('covenant');
            toast('Oracle attestation scanned', 'ok', 2000);
        } else {
            // Try as text (JSON full attestation or hex)
            const text = new TextDecoder().decode(raw).trim();
            try {
                const obj = JSON.parse(text);
                if (obj && obj.t === 'oracle-attest' && obj.sig && obj.hash) {
                    stopScanner();
                    el('cov-oracle-claim-sig').value = obj.sig;
                    el('cov-oracle-claim-hash').value = obj.hash;
                    showScreen('covenant');
                    const textEl = el('cov-oracle-claim-attest-text');
                    if (obj.text && textEl) {
                        textEl.textContent = 'Oracle attested: ' + obj.text;
                        textEl.style.display = '';
                    }
                    // Persist attestation to localStorage for legal proof
                    try {
                        const covAddr = el('cov-oracle-claim-addr').value.trim();
                        if (covAddr) {
                            const record = {
                                covenant_address: covAddr,
                                sig: obj.sig,
                                hash: obj.hash,
                                text: obj.text || '',
                                scanned_at: new Date().toISOString()
                            };
                            let attestations = [];
                            try { attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]'); } catch (_) {}
                            attestations = attestations.filter(a => a.covenant_address !== covAddr);
                            attestations.unshift(record);
                            localStorage.setItem('oracleAttestations', JSON.stringify(attestations));
                        }
                    } catch (_) {}
                    toast('Oracle attestation scanned', 'ok', 2000);
                    return;
                }
            } catch (_) {}
            // Fallback: 192 hex chars
            if (/^[0-9a-fA-F]{192}$/.test(text)) {
                stopScanner();
                el('cov-oracle-claim-sig').value = text.slice(0, 128);
                el('cov-oracle-claim-hash').value = text.slice(128, 192);
                showScreen('covenant');
                toast('Oracle attestation scanned', 'ok', 2000);
            }
        }
    });
    if (el('btn-cov-swap-compute-hash')) el('btn-cov-swap-compute-hash').onclick = () => {
        const preimage = el('cov-swap-preimage').value.trim();
        if (!preimage) { toast('Enter a preimage first', 'error'); return; }
        const algo = el('cov-swap-hash-algo') ? el('cov-swap-hash-algo').value : 'blake2b';
        try {
            let hexInput;
            if (/^[0-9a-fA-F]+$/.test(preimage) && preimage.length % 2 === 0) {
                hexInput = preimage;
            } else {
                hexInput = Array.from(new TextEncoder().encode(preimage)).map(b => b.toString(16).padStart(2,'0')).join('');
            }
            let hash;
            if (algo === 'sha256') {
                hash = sha256_hash(hexInput);
            } else {
                hash = blake2b_hash(hexInput);
            }
            el('cov-swap-hash').value = hash;
            toast(algo.toUpperCase() + ' hash computed', 'ok', 1500);
        } catch (e) {
            toast('Hash error: ' + e, 'error');
        }
    };
    // Live DAA preview for swap datetime picker
    if (el('cov-swap-datetime')) {
        el('cov-swap-datetime').oninput = () => {
            const val = el('cov-swap-datetime').value;
            const preview = el('cov-swap-daa-preview');
            if (!val || !preview) return;
            const targetMs = new Date(val).getTime();
            const nowMs = Date.now();
            if (targetMs <= nowMs) { preview.textContent = 'Past date'; return; }
            const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
            const currentDaa = estimateCurrentDaaFromUtxos();
            if (currentDaa > 0) {
                const estDaa = currentDaa + secondsUntil * 10;
                preview.textContent = 'DAA ~' + estDaa.toLocaleString();
            } else {
                preview.textContent = '~' + Math.round(secondsUntil / 3600) + 'h from now';
            }
        };
    }
    el('cov-result-addr').onclick = () => { navigator.clipboard.writeText(el('cov-result-addr').textContent); toast('Address copied', 'ok', 1200); };
    el('cov-result-script').onclick = () => { navigator.clipboard.writeText(el('cov-result-script').textContent); toast('Redeem script copied', 'ok', 1200); };
    if (el('btn-cov-scan-owner-addr')) el('btn-cov-scan-owner-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); el('cov-owner-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-cov-scan-owner-dest').onclick = () => startScanner('Scan destination', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); el('cov-owner-dest').value = addr; showScreen('covenant'); covShowPanel('owner'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-consol-scan-dest').onclick = () => startScanner('Scan destination', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); el('cov-consol-dest').value = addr; showScreen('covenant'); covShowPanel('consolidate'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-cov-scan-borrower-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); el('cov-borrower-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });
    // Balance checker
    el('btn-cov-check-balance').onclick = () => {
        covShowPanel('balance');
        if (lastCovenantResult) {
            el('cov-balance-addr').value = lastCovenantResult.address || '';
        }
        el('cov-balance-result').classList.add('hidden');
    };
    el('btn-cov-owner-reclaim').onclick = () => {
        covShowPanel('owner');
        if (lastCovenantResult) {
            el('cov-owner-addr').value = lastCovenantResult.address || '';
            el('cov-owner-script').value = lastCovenantResult.redeem_script_hex || '';
        }
    };
    el('btn-cov-balance-back').onclick = () => covShowPanel('menu');
    el('btn-cov-balance-check').onclick = () => handleCovCheckBalance();
    el('btn-cov-scan-balance-addr').onclick = () => startScanner('Scan covenant address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (addr.startsWith('kaspa')) { stopScanner(); el('cov-balance-addr').value = addr; showScreen('covenant'); toast('Address scanned', 'ok', 1500); }
    });

    el('btn-refresh').onclick = () => refreshBalance();
    el('btn-reset-wallet').onclick = () => resetWallet();
    el('btn-create-tx').onclick = () => handleCreateTx();
    el('btn-send-max').onclick = () => handleSendMax();
    el('btn-scan-dest').onclick = () => startScanner('Scan address QR', handleDestScan);
    // Compound TX — disabled until KasSigner QR frame fix
    // el('btn-add-recipient').onclick = () => addRecipientRow();
    el('btn-toggle-utxos').onclick = () => toggleSendUtxos();
    el('btn-fee-low').onclick = () => setFeeLevel('low');
    el('btn-fee-normal').onclick = () => setFeeLevel('normal');
    el('btn-fee-priority').onclick = () => setFeeLevel('priority');
    el('btn-send-back').onclick = () => {
        if (_broadcastReturnScreen) {
            const ret = _broadcastReturnScreen;
            _broadcastReturnScreen = null;
            showScreen(ret);
            if (ret === 'covenant') covReturnAfterBroadcast();
        } else {
            showScreen('dashboard');
        }
    };
    el('btn-qr-back').onclick = () => {
        stopQrCycle();
        // Restore QR screen buttons (may have been hidden by piggy share)
        if (el('btn-qr-scan-signed')) el('btn-qr-scan-signed').style.display = '';
        if (el('btn-scan-next-sig')) el('btn-scan-next-sig').style.display = '';
        // Adaptor routing must be keyed on the QR actually shown, not on the
        // mere existence of _adaptorState (it persists across sessions): a
        // stale swap was hijacking Back from every other covenant's QR.
        const _wasAdaptorQr = window._adaptorQrReturn === true;
        window._adaptorQrReturn = false;
        if (window._oracleAttestQrReturn) {
            window._oracleAttestQrReturn = false;
            _broadcastReturnScreen = null;
            showScreen('covenant');
            covShowPanel('oracle-attest');
        } else if (_wasAdaptorQr && _adaptorState && _broadcastReturnScreen === 'covenant') {
            _broadcastReturnScreen = null;
            showScreen('covenant');
            if (_adaptorState.role === 'alice') covShowPanel('adaptor-result');
            else if (_adaptorState.role === 'bob') covShowPanel('adaptor-result');
            else covShowPanel('adaptor');
        } else if (_broadcastReturnScreen) {
            const ret = _broadcastReturnScreen;
            _broadcastReturnScreen = null;
            showScreen(ret);
            if (ret === 'covenant') covReturnAfterBroadcast();
        } else if (msActive && msBranch) {
            // The relay QR after building a multisig transaction. Nothing has
            // been sent, so leaving it means "go back to the wallet", not "leave
            // KasSee" - and dropping to the dashboard discards the loaded branch
            // and the transaction with it.
            //
            // Fourth screen with this same fallthrough: broadcast-done, the PSKB
            // review, the shared tabs, and now this one.
            showScreen('ms-wallet');
        } else {
            showScreen('dashboard');
        }
    };
    el('btn-scan-next-sig').onclick = () => { pauseQrCycle(); startScanner('Scan signed QR', handleSignedScan); };
    el('btn-qr-scan-signed').onclick = () => { pauseQrCycle(); startScanner('Scan signed QR', handleSignedScan); };
    el('btn-copy-kspt').onclick = () => { if (_currentKsptHex) { navigator.clipboard.writeText(_currentKsptHex); toast('KSPT hex copied — share with next signer', 'ok', 2000); } };
    el('btn-pskt-copy-hex').onclick = () => { if (_psktReviewHex) { navigator.clipboard.writeText(_psktReviewHex); toast('PSKB hex copied', 'ok', 2000); } };
    el('btn-scanner-cancel').onclick = () => stopScanner();
    el('btn-copy-address').onclick = () => copyAddress();
    el('btn-receive-back').onclick = () => {
        // Shared screen: return to whoever opened it.
        if (msReceiveReturn) {
            const ret = msReceiveReturn;
            msReceiveReturn = null;
            showScreen(ret);
        } else {
            showScreen('dashboard');
        }
    };
    el('btn-scan-signed').onclick = () => startScanner('Scan signed QR', handleSignedScan);
    el('btn-broadcast-hex').onclick = () => handleBroadcastHex();
    el('btn-broadcast-back').onclick = () => {
        if (_broadcastReturnScreen) {
            const ret = _broadcastReturnScreen;
            _broadcastReturnScreen = null;
            showScreen(ret);
            if (ret === 'covenant') covReturnAfterBroadcast();
        } else {
            showScreen(walletData ? 'dashboard' : 'welcome');
        }
    };
    el('btn-pskt-back').onclick = () => {
        _psktReviewHex = null;
        if (_broadcastReturnScreen) {
            const ret = _broadcastReturnScreen;
            _broadcastReturnScreen = null;
            showScreen(ret);
            if (ret === 'covenant') covReturnAfterBroadcast();
        } else if (msActive && msBranch) {
            // Back from the review belongs on the SEND screen: the transaction
            // has not been sent, so this is "let me change something", not
            // "take me out of the wallet". Falling through to the dashboard
            // discarded the loaded branch.
            resetMsUtxoSelection();
            showScreen('multisig');
        } else {
            showScreen('dashboard');
        }
    };
    el('btn-pskt-relay').onclick = () => openRelayModal();
    el('btn-relay-standard').onclick = () => { closeRelayModal(); handlePsktRelay(); };
    el('btn-relay-compact').onclick = () => { closeRelayModal(); handlePsktRelayCompact(); };
    el('btn-relay-cancel').onclick = () => closeRelayModal();
    el('btn-pskt-finalize').onclick = () => handlePsktFinalize();
    el('btn-broadcast-done').onclick = () => {
        hideBroadcastResult();
        window._lastClaimPreimage = null;
        if (_broadcastReturnScreen) {
            const ret = _broadcastReturnScreen;
            _broadcastReturnScreen = null;
            showScreen(ret);
            if (ret === 'covenant') covReturnAfterBroadcast();
            // 2 s, not 500 ms: half a second after submit the node's UTXO index
            // has often not caught up, especially a home node, so the first
            // refresh showed the old balance and nothing followed it.
            if (ret === 'ms-wallet') setTimeout(() => refreshMsWallet(true), 2000);
            // Refresh balance after TX broadcast
            if (walletData && ret !== 'ms-wallet') setTimeout(() => refreshBalance(), 2000);
        } else if (msBranch) {
            // A multisig SEND reaches broadcast without anyone setting a return
            // screen - only the Broadcast TX button did that - so finishing a
            // send fell through to the donation card and then out of the
            // wallet. Handled at the fallback so every route in is covered,
            // not just the one that was noticed.
            showScreen('ms-wallet');
            setTimeout(() => refreshMsWallet(true), 2000);
        } else {
            showDonateScreen();
        }
    };
    el('btn-copy-txid').onclick = () => {
        const txid = el('broadcast-result-txid').textContent.trim();
        navigator.clipboard.writeText(txid);
        toast('TX ID copied', 'ok', 1500);
    };
    el('btn-save-settings').onclick = () => saveSettings();
    el('btn-use-public').onclick = () => { clearCustomNode(); exitSettings(); };
    el('btn-settings-back').onclick = () => exitSettings();
    el('btn-settings-back-top').onclick = () => exitSettings();
    el('btn-header-settings').onclick = () => toggleGearMenu();

    // Gear menu tabs
    document.querySelectorAll('.gear-tab').forEach(tab => {
        tab.onclick = () => {
            const target = tab.dataset.target;
            // Update active tab
            document.querySelectorAll('.gear-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            // Close menu and navigate
            closeGearMenu();
            settingsReturnScreen = currentScreenName || 'dashboard';
            if (target === 'addresses') { showAddresses(); }
            else if (target === 'utxos') showUtxos();
            else if (target === 'tokens') showTokens();
            else if (target === 'history') showHistory();
            else if (target === 'settings') showSettings();
        };
    });
    el('btn-addresses-back').onclick = () => showScreen(addressesReturnScreen);
    el('btn-addresses-back-top').onclick = () => showScreen(addressesReturnScreen);
    // Reachable from the multisig wallet via the tab bar, so a hardcoded
    // dashboard exit drops the loaded branch. Same trap as addresses and utxos.
    el('btn-tokens-back').onclick = () => showScreen(tabReturnScreen());
    el('btn-tokens-back-top').onclick = () => showScreen(tabReturnScreen());
    el('btn-verify-copy').onclick = () => {
        navigator.clipboard.writeText(el('verify-address').textContent.trim());
        toast('Address copied', 'ok', 1200);
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    el('btn-verify-back').onclick = () => {
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    // Both hardcoded to the dashboard, so opening UTXOs from a multisig branch
    // and pressing Back dropped the loaded wallet. The addresses screen already
    // solves this with a return target; UTXOs never had one.
    el('btn-utxos-back').onclick = () => showScreen(utxosReturnScreen);
    el('btn-utxos-back-top').onclick = () => showScreen(utxosReturnScreen);
    el('btn-consolidate').onclick = () => {
        // Shared button: on a multisig branch it opens the picker instead of the
        // single-sig consolidation, which builds from `walletData` and would be
        // wrong here.
        if (msActive && msBranch) {
            const sel = (msConsolidateList || []).filter(u =>
                msConsolidateSel.has(u.tx_id + ':' + u.outpoint_index));
            if (sel.length < 2) {
                toast('Select at least two UTXOs to consolidate', 'error');
                return;
            }
            msPicked = sel.map(u => ({
                address: u.address, tx_id: u.tx_id, index: u.outpoint_index, amount: u.amount,
            }));
            startMsConsolidate();
            return;
        }
        handleConsolidate();
    };
    el('btn-consolidate-selected').onclick = () => handleConsolidateSelected();
    el('btn-history-back').onclick = () => showScreen(tabReturnScreen());
    el('btn-history-back-top').onclick = () => showScreen(tabReturnScreen());
    el('btn-clear-history').onclick = () => clearHistory();
    el('btn-donate-skip').onclick = () => {
        // Never route through exitSettings()/settingsReturnScreen here:
        // that can hold a stale 'welcome' and lock the user out (kpub
        // rescan). Wallet loaded → dashboard, otherwise welcome.
        showScreen(walletData ? 'dashboard' : 'welcome');
        if (walletData) refreshBalance();
    };
    el('btn-copy-donate').onclick = () => {
        navigator.clipboard.writeText(DONATE_ADDRESS);
        toast('Address copied', 'ok', 1500);
    };
}

function el(id) { return document.getElementById(id); }

// ─── Hex & address helpers ───

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/// Convert a Kaspa address to its script public key hex (without 0000 version prefix).
/// Uses the WASM decode_address binding.
// Extract CLTV locktime from a redeem script hex string.
// Scans for the last integer push before OP_CHECKLOCKTIMEVERIFY (0xb0).
// Returns the locktime as a number, or null if not found.
function extractCltvFromRedeem(scriptHex) {
    try {
        const bytes = hexToBytes(scriptHex);
        let lastPush = 0;
        let i = 0;
        while (i < bytes.length) {
            const op = bytes[i];
            if (op === 0xb0) return lastPush; // OP_CLTV
            if (op === 0x00) { lastPush = 0; i++; }
            else if (op >= 0x51 && op <= 0x60) { lastPush = op - 0x50; i++; }
            else if (op >= 0x01 && op <= 0x4b) {
                const len = op;
                if (i + 1 + len <= bytes.length) {
                    let val = 0n;
                    for (let j = 0; j < len; j++) val |= BigInt(bytes[i + 1 + j]) << BigInt(j * 8);
                    lastPush = Number(val);
                }
                i += 1 + len;
            } else if (op === 0x4c) { i += 2 + (bytes[i + 1] || 0); }
            else { i++; }
        }
    } catch (_) {}
    return null;
}

function addrToSpkHex(addr) {
    const info = JSON.parse(decode_address(addr));
    const payload = info.payload; // 32 bytes hex
    if (info.version === 0) {
        // P2PK: OP_DATA_32 <pubkey> OP_CHECKSIG
        return '20' + payload + 'ac';
    } else if (info.version === 8) {
        // P2SH: OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL
        return 'aa20' + payload + '87';
    }
    throw 'Unknown address version: ' + info.version;
}

// ─── Address index helpers (auto-expanding gap limit) ───

// Derived in one step when the list is exhausted. Was 10 and 5, which needed
// several refreshes to converge on a wallet with many used addresses - each
// refresh added one batch and the console filled with "Gap expanded" lines.
// Deriving is local and cheap; the cost is per-address REST checks, and those
// are now gap-limited and skip known addresses, so a bigger step is not a
// bigger scan.
const GAP_EXPAND_RECEIVE = 20;
const GAP_EXPAND_CHANGE = 20;
// Hard ceiling. Expansion loops until a free index exists, so a bug that marked
// every address used would otherwise derive forever.
const MAX_DERIVED_ADDRESSES = 500;

/// Expand wallet addresses if all current slots are used.
/// Derives new addresses via WASM and updates walletData in place.
/// Returns `true` if the wallet was actually extended, `false` otherwise.
function expandAddressesIfNeeded() {
    if (!walletData) return false;
    const wallet = JSON.parse(walletData);

    const rcvSkip = new Set([...fundedReceiveIndices, ...usedReceiveIndices]);
    const chgSkip = new Set([...fundedChangeIndices, ...usedChangeIndices]);

    let needReceive = true;
    for (let i = 0; i < wallet.receive_addresses.length; i++) {
        if (!rcvSkip.has(i)) { needReceive = false; break; }
    }

    let needChange = true;
    for (let i = 0; i < wallet.change_addresses.length; i++) {
        if (!chgSkip.has(i)) { needChange = false; break; }
    }

    if (!needReceive && !needChange) return false;

    // Expanding more than once is NORMAL on a wallet with deep history, not a
    // bug. A round can only test against the used/funded data it already has,
    // and that only grows once a balance refresh and a history scan have
    // reached the newly derived addresses. So the freshly added indices are
    // UNKNOWN, not unused, and on a well-used wallet many turn out to be both
    // funded and spent. Verified by index on 2026-08-16: every index in a
    // 40-address change list was genuinely accounted for.

    // Expand until a free index EXISTS, in one call.
    //
    // A single batch always creates free indices, so one round is normally
    // enough; the loop is there so that if it somehow is not, this converges
    // now instead of one batch per refresh.
    let rounds = 0;
    let expanded = false;
    while (needReceive || needChange) {
        const w = JSON.parse(walletData);
        if (w.receive_addresses.length + w.change_addresses.length >= MAX_DERIVED_ADDRESSES) {
            console.log('[KasSee] address expansion stopped at ceiling ' + MAX_DERIVED_ADDRESSES);
            break;
        }
        const extraRcv = needReceive ? GAP_EXPAND_RECEIVE : 0;
        const extraChg = needChange ? GAP_EXPAND_CHANGE : 0;
        try {
            walletData = extend_addresses(walletData, extraRcv, extraChg, network);
            expanded = true;
        } catch (e) {
            console.error('[KasSee] Address expansion failed:', e);
            break;
        }
        rounds++;
        const w2 = JSON.parse(walletData);
        needReceive = !w2.receive_addresses.some((_, i) => !rcvSkip.has(i));
        needChange = !w2.change_addresses.some((_, i) => !chgSkip.has(i));
        if (rounds >= 10) break;
    }
    if (expanded) {
        const w3 = JSON.parse(walletData);
        console.log(`[KasSee] Gap expanded to ${w3.receive_addresses.length} receive, `
            + `${w3.change_addresses.length} change (${rounds} round(s))`);
    }
    return expanded;
}

/// Pick the first change address not currently funded and not used.
/// Auto-expands if all are occupied.
function getNextChangeIndex() {
    if (!walletData) return 0;
    expandAddressesIfNeeded();
    const wallet = JSON.parse(walletData);
    const skipSet = new Set([...fundedChangeIndices, ...usedChangeIndices]);
    for (let i = 0; i < wallet.change_addresses.length; i++) {
        if (!skipSet.has(i)) return i;
    }
    return wallet.change_addresses.length - 1;
}

/// Pick the first receive address not currently funded and not used.
/// Auto-expands if all are occupied.
function getNextReceiveIndex() {
    if (!walletData) return 0;
    expandAddressesIfNeeded();
    const wallet = JSON.parse(walletData);
    const skipSet = new Set([...fundedReceiveIndices, ...usedReceiveIndices]);
    for (let i = 0; i < wallet.receive_addresses.length; i++) {
        if (!skipSet.has(i)) return i;
    }
    return wallet.receive_addresses.length - 1;
}

/// Return walletData JSON with next_change_index and next_receive_index
/// set to the correct values. Auto-expands if needed.
function walletWithFreshIndices() {
    if (!walletData) return walletData;
    expandAddressesIfNeeded();
    const w = JSON.parse(walletData);
    w.next_change_index = getNextChangeIndex();
    w.next_receive_index = getNextReceiveIndex();
    return JSON.stringify(w);
}

// ─── Auto-refresh ───

function startAutoRefresh() {
    stopAutoRefresh();
    autoRefreshTimer = setInterval(() => {
        if (currentScreenName === 'dashboard' && walletData && !refreshing) {
            refreshBalance();
        } else if (currentScreenName === 'ms-wallet' && msBranch && !msRefreshing) {
            // Light: one WebSocket scan to the node, no REST history calls.
            refreshMsWallet(true);
        }
    }, AUTO_REFRESH_INTERVAL);
}

function stopAutoRefresh() {
    if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
}

// ─── kpub import ───

function handleKpubScan(data) {
    const bytes = new Uint8Array(data);

    // Check if this is a multi-frame fragment:
    // [frame_num][total_frames][frag_len][data...] where total >= 2
    // Frame 0 must start with a recognised format marker:
    //   - ASCII "kpub" (legacy base58 kpub text payload), OR
    //   - 0x01 (V1-raw header — compact binary format, 79-byte kpub)
    const isMF = bytes.length >= 7
        && bytes[1] >= 2 && bytes[1] <= 20
        && bytes[0] < bytes[1] && bytes[2] > 0
        && (bytes[0] > 0 || (bytes.length >= 7 && (
            String.fromCharCode(bytes[3], bytes[4], bytes[5], bytes[6]) === 'kpub'
            || bytes[3] === 0x01
        )));

    if (isMF) {
        // Multi-frame: feed through decoder, keep scanning
        const hexStr = Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0')).join('');
        try {
            const result = decode_qr_frame(hexStr);
            if (result && result.length > 0) {
                stopScanner();
                // Convert assembled hex → byte array
                const assembled = [];
                for (let i = 0; i < result.length; i += 2) {
                    assembled.push(parseInt(result.substr(i, 2), 16));
                }
                const assembledBytes = new Uint8Array(assembled);

                // V1-raw path: [0x01 header][78-byte raw payload] = 79 bytes total
                if (assembledBytes.length === 79 && assembledBytes[0] === 0x01) {
                    handleKpubImportRaw(assembledBytes.slice(1));
                } else {
                    // Legacy ASCII path: assembled bytes are UTF-8 of a kpub string
                    const kpubStr = new TextDecoder().decode(assembledBytes).trim();
                    handleKpubImport(kpubStr);
                }
            } else {
                // Show frame progress
                const prog = JSON.parse(decoder_progress());
                if (prog.total > 0) {
                    let dots = '';
                    for (let i = 0; i < prog.total; i++) {
                        dots += `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:${prog.bits[i] ? 'var(--teal)' : 'var(--border)'};${prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : ''}"></span>`;
                    }
                    el('scanner-status').innerHTML = dots + `<div style="margin-top:6px;font-size:12px">${prog.count} / ${prog.total} kpub frames</div>`;
                }
            }
        } catch (e) {
            console.error('kpub multi-frame decode error:', e);
        }
        return;
    }

    // Single-frame: direct kpub text
    // Guard: only process once
    if (!scanCallback) return;
    stopScanner();

    const text = typeof data === 'string' ? data : new TextDecoder().decode(data);
    handleKpubImport(text.trim());
}

function handleKpubImport(kpubStr) {
    if (!kpubStr || !kpubStr.startsWith('kpub')) {
        toast('Invalid kpub — must start with "kpub"', 'error');
        showScreen('welcome');
        return;
    }
    showLoading('Deriving addresses...');
    try {
        walletData = import_kpub(kpubStr, network);
        hideLoading();
        // Set organizer pk for crowdfund dual-gate (account key = KaSigner signing key)
        const orgPk = getAccountPubkeyHex();
        if (orgPk) window._crowdfundOrganizerPk = orgPk;

        showScreen('dashboard');
        // Force the initial balance refresh. Reset the `refreshing` guard
        // in case a prior session left it stuck true (would silently
        // skip the refresh and leave the balance blank until the user
        // manually hits the button). Small delay lets the dashboard
        // screen finish mounting before the network call fires.
        refreshing = false;
        setTimeout(() => { refreshBalance(); }, 50);
        // Follow-up refresh ~5s later. Belt-and-suspenders for the case
        // where the gap-expansion chain inside the first refresh doesn't
        // settle before the user sees a balance number. After the chain
        // adds extra change addresses, this second refresh picks up any
        // funds at those newly-derived indices without forcing the user
        // to wait for the 30s auto-refresh tick or click manually.
        setTimeout(() => { refreshBalance(); }, 5000);
    } catch (e) {
        hideLoading();
        toast('Import failed: ' + e, 'error', 5000);
        showScreen('welcome');
    }
}

// V1-raw binary kpub entry point: called when a multi-frame QR scan
// assembles into [0x01 header][78 raw payload] = 79 bytes. The header
// is stripped by the caller; we pass the 78 raw bytes to WASM which
// re-encodes them as a standard base58check kpub internally.
//
// walletData is kept as a raw JSON string to match handleKpubImport's
// convention — downstream code (fetch_balance, fetch_utxos, etc.)
// expects `wallet_json: &str` on the WASM side and parses internally.
function handleKpubImportRaw(rawPayload) {
    if (!rawPayload || rawPayload.length !== 78) {
        toast('Invalid V1-raw kpub payload', 'error');
        return;
    }
    showLoading('Deriving addresses...');
    try {
        walletData = import_kpub_raw(rawPayload, network);
        hideLoading();
        // Set organizer pk for crowdfund dual-gate
        const orgPk2 = getAccountPubkeyHex();
        if (orgPk2) window._crowdfundOrganizerPk = orgPk2;

        showScreen('dashboard');
        // Same as handleKpubImport: reset the refreshing guard and
        // schedule the first balance fetch after the dashboard mounts.
        refreshing = false;
        setTimeout(() => { refreshBalance(); }, 50);
        // Follow-up refresh ~5s later to catch funds at change indices
        // that the gap-expansion chain only reaches on the second pass.
        setTimeout(() => { refreshBalance(); }, 5000);
    } catch (e) {
        hideLoading();
        toast('V1-raw import failed: ' + e, 'error', 5000);
    }
}

// ─── Node connection with retry ───

async function withNodeRetry(fn, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const wsUrl = await resolveNodeUrl();
            return await fn(wsUrl);
        } catch (e) {
            const msg = String(e);
            // A TIMEOUT is a failure too, and the more common one: a node that
            // has gone away leaves the socket looking open, so the request waits
            // the full 15 s and returns "WebSocket timeout" rather than an
            // error. Matching only on 'WebSocket error' meant a stale node was
            // never retried and never dropped - every refresh hit it again.
            if ((msg.includes('WebSocket error') || msg.includes('timeout'))
                && attempt < maxRetries) {
                // Drop the cached node before retrying. Without this the retry
                // would hit the SAME dead node every time, since the URL is now
                // held for the session instead of re-resolved per call.
                //
                // A custom node is the user's explicit choice, so it is not
                // dropped here; the fallback below handles it after the retries.
                if (!customNodeUrl) invalidateResolvedNode();
                console.log(`[KasSee] Retry ${attempt}/${maxRetries}: ${msg}`);
                continue;
            }
            // Custom node exhausted retries — fall back to public
            if (customNodeUrl) {
                console.log(`[KasSee] Custom node failed, falling back to public. Error: ${msg}`);
                toast('Custom node unreachable — using public', 'info', 3000);
                try {
                    const publicUrl = await resolvePublicNode();
                    return await fn(publicUrl);
                } catch (e2) {
                    throw e2;
                }
            }
            throw e;
        }
    }
}

// ─── Balance ───

async function refreshBalance() {
    if (!walletData || refreshing) return;
    refreshing = true;

    showLoading('Connecting...');
    setStatus('connecting', 'Connecting');

    try {
        const resultJson = await withNodeRetry(wsUrl => fetch_balance(walletData, wsUrl));
        const result = JSON.parse(resultJson);

        setStatus('online', 'Connected');
        hideLoading();

        el('balance-kas').textContent = result.total_kas.toFixed(8) + ' KAS';
        el('balance-sompi').textContent = result.total_sompi.toLocaleString() + ' sompi';
        el('balance-info').textContent =
            `${result.utxo_count} UTXO${result.utxo_count !== 1 ? 's' : ''} across ${result.funded_addresses} address${result.funded_addresses !== 1 ? 'es' : ''}`;

        fundedReceiveIndices = result.funded_receive_indices || [];
        fundedChangeIndices = result.funded_change_indices || [];

        // Track UTXO changes for history + session used-address tracking
        try {
            const utxosJson = await withNodeRetry(wsUrl => fetch_utxos(walletData, wsUrl));
            const currentUtxos = JSON.parse(utxosJson);
            trackUtxoChangesAndUsed(currentUtxos);
        } catch (e) {
            console.log('[KasSee] UTXO history track:', e);
        }

        // Detect used addresses via api.kaspa.org (or custom REST server)
        // then expand gap limit if all addresses are occupied.
        //
        // If expansion actually added addresses, fetch balance again so
        // funds at the new indices (e.g. user's wallet has activity at
        // index 25+ but we only derived 0-19 initially) show up without
        // requiring a manual refresh. Cap the chain at 3 cycles total
        // to bound the work for very deep wallets.
        fetchAddressHistory().then(() => {
            const expanded = expandAddressesIfNeeded();
            if (expanded && (window._refreshExpansionDepth || 0) < 3) {
                window._refreshExpansionDepth = (window._refreshExpansionDepth || 0) + 1;
                refreshBalance().finally(() => {
                    // Reset depth once the chain settles
                    if (!refreshing) window._refreshExpansionDepth = 0;
                });
            } else {
                window._refreshExpansionDepth = 0;
            }
        });

        // Fetch current DAA from node and display on dashboard
        try {
            const daa = await fetchCurrentDaa();
            if (daa > 0 && el('balance-daa')) {
                el('balance-daa').textContent = 'DAA ' + daa.toLocaleString();
            }
        } catch (_) {}
    } catch (e) {
        setStatus('offline', 'Offline');
        hideLoading();
        console.error('Balance fetch failed:', e);
        el('balance-kas').textContent = '—';
        el('balance-sompi').textContent = '';
        el('balance-info').textContent = String(e);
    } finally {
        refreshing = false;
    }

}

// ================================================================
// KasFreeze Background Scanner (local vault + beacon discovery)
// ================================================================


// Phase 1: Check local vault entries, broadcast expired ones

// Phase 2: Beacon discovery via REST API (Path A) or pure UTXO (Path C)
// First load: scan all epochs 0..current
// Returning load: scan current + previous epoch only

// Path A: REST-based beacon discovery

// Process a single beacon TX: read outputs 2-4, reconstruct, and broadcast if expired

// Extract the 32-byte payload from a P2PK script_public_key.
// P2PK SPK = "20" + 64 hex chars + "ac" = 68 hex chars total.
// REST API returns script_public_key as hex string (sometimes nested).
function extractP2pkPayload(output) {
    if (!output) return null;
    // Handle different REST API response formats
    let spkHex = null;
    if (output.script_public_key) {
        if (typeof output.script_public_key === 'string') {
            spkHex = output.script_public_key;
        } else if (output.script_public_key.script_public_key) {
            spkHex = output.script_public_key.script_public_key;
        } else if (output.script_public_key.scriptPublicKey) {
            spkHex = output.script_public_key.scriptPublicKey;
        }
    } else if (output.scriptPublicKey) {
        if (typeof output.scriptPublicKey === 'string') {
            spkHex = output.scriptPublicKey;
        } else if (output.scriptPublicKey.scriptPublicKey) {
            spkHex = output.scriptPublicKey.scriptPublicKey;
        }
    } else if (output.verbose_data && output.verbose_data.script_public_key_address) {
        // Cannot extract raw hex from address alone, skip
        return null;
    }

    if (!spkHex) return null;

    // Normalize: remove 0x prefix if present
    if (spkHex.startsWith('0x')) spkHex = spkHex.substring(2);

    // P2PK: must be 68 hex chars (34 bytes): 20 + 32 bytes + ac
    if (spkHex.length !== 68) return null;
    if (!spkHex.startsWith('20') || !spkHex.endsWith('ac')) return null;

    return spkHex.substring(2, 66); // the 32-byte payload
}

// ================================================================
// KasFreeze Beacon Path C: Pure UTXO scanner
// ================================================================



// Helper: fetch UTXOs via WASM RPC (returns JSON string)
async function fetch_utxos_wasm(address, nodeUrl) {
    return await fetch_utxos_for_address_js(address, nodeUrl);
}

// Default: query api.kaspa.org /transactions-count per address.
// Override: if user enables Address History + custom REST URL in settings,
// use the custom server's /full or /transactions endpoints instead.
// Both paths write into usedReceiveIndices / usedChangeIndices.

const KASPA_REST_API = {
    'mainnet': 'https://api.kaspa.org',
    'testnet-10': 'https://api-tn10.kaspa.org',
};

async function fetchAddressHistory() {
    if (!walletData) return;
    const wallet = JSON.parse(walletData);

    // Custom REST server path (user-configured, optional)
    if (addressHistoryEnabled && customRestUrl) {
        await fetchAddressHistoryCustom(wallet);
        return;
    }

    // Default path: api.kaspa.org /transactions-count
    const apiBase = KASPA_REST_API[network];
    if (!apiBase) return;

    // SEQUENTIAL with spacing, and a gap-limit stop.
    //
    // This fired `Promise.all` over every address at once - 80 simultaneous
    // requests once the change list had grown - which api.kaspa.org answers
    // with 429, and a 429 carries no CORS headers so the browser reports it as
    // a CORS failure with the real status hidden. The archival sweep already
    // learned this and was fixed; this function was not.
    //
    // Two changes beyond the spacing. Addresses ALREADY known used or funded
    // are skipped, since the answer cannot change and this runs on every
    // refresh. And the scan stops after GAP_STOP consecutive unused addresses,
    // which is the standard gap rule: past that, a wallet has no history to
    // find, so the remaining requests are guaranteed waste.
    const GAP_STOP = 20;
    const SPACING_MS = 250;
    let rateLimited = false;

    const check = async (addr, i, targetSet) => {
        try {
            const r = await fetch(`${apiBase}/addresses/${addr}/transactions-count`, { signal: AbortSignal.timeout(5000) });
            if (r.status === 429) { rateLimited = true; return false; }
            if (!r.ok) return false;
            const d = await r.json();
            if (d.total > 0) { targetSet.add(i); return true; }
            return false;
        } catch (_) { return false; }
    };

    const scan = async (addresses, targetSet, fundedList) => {
        let unusedRun = 0;
        for (let i = 0; i < addresses.length; i++) {
            if (rateLimited) return;
            // Known used or currently funded: no request needed.
            //
            // `targetSet` is a Set, `fundedList` is an ARRAY - they are built
            // from different places and the two are not interchangeable.
            if (targetSet.has(i) || fundedList.includes(i)) { unusedRun = 0; continue; }
            const used = await check(addresses[i], i, targetSet);
            unusedRun = used ? 0 : unusedRun + 1;
            if (unusedRun >= GAP_STOP) return;
            await new Promise(res => setTimeout(res, SPACING_MS));
        }
    };

    try {
        await scan(wallet.receive_addresses, usedReceiveIndices, fundedReceiveIndices);
        await scan(wallet.change_addresses, usedChangeIndices, fundedChangeIndices);
        if (rateLimited) {
            console.log('[KasSee] address history stopped: rate-limited by ' + apiBase);
        }
    } catch (e) {
        console.log('[KasSee] address history (default):', e);
    }
}

async function fetchAddressHistoryCustom(wallet) {
    try {
        const testUrl = `${customRestUrl}/addresses/${wallet.receive_addresses[0]}/full`;
        const probe = await fetch(testUrl, { signal: AbortSignal.timeout(5000) });
        const useFull = probe.ok;

        const check = async (addr, i, targetSet) => {
            try {
                if (useFull) {
                    const r = await fetch(`${customRestUrl}/addresses/${addr}/full`, { signal: AbortSignal.timeout(5000) });
                    if (r.ok) {
                        const d = await r.json();
                        if (d.tx_count > 0 || (d.transactions && d.transactions.length > 0)) targetSet.add(i);
                    }
                } else {
                    const r = await fetch(`${customRestUrl}/addresses/${addr}/transactions?limit=1`, { signal: AbortSignal.timeout(5000) });
                    if (r.ok) {
                        const d = await r.json();
                        const hasData = Array.isArray(d) ? d.length > 0 : (d.transactions && d.transactions.length > 0);
                        if (hasData) targetSet.add(i);
                    }
                }
            } catch (_) {}
        };

        const promises = [
            ...wallet.receive_addresses.map((addr, i) => check(addr, i, usedReceiveIndices)),
            ...wallet.change_addresses.map((addr, i) => check(addr, i, usedChangeIndices)),
        ];
        await Promise.all(promises);
    } catch (e) {
        console.log('[KasSee] address history (custom):', e);
    }
}

// ─── Send ───

async function openSendScreen() {
    selectedUtxoIndices = null;
    cachedUtxos = null;
    // Only reset _broadcastReturnScreen if not pre-set by covenant deposit
    if (_broadcastReturnScreen !== 'covenant') _broadcastReturnScreen = null;
    const utxoList = el('send-utxo-list');
    utxoList.style.display = 'none';
    utxoList.innerHTML = '';
    el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
    // el('extra-recipients').innerHTML = '';
    el('input-dest').value = '';
    el('input-amount').value = '';
    // Shared screen: always restore the amount field by default. Thread-covenant
    // deposits hide it again (handleCovFund), since they full-spend the chosen UTXOs.
    const _amtWrap = el('send-amount-wrap');
    if (_amtWrap) _amtWrap.style.display = '';

    // Show current balance on send screen
    const balText = el('balance-kas').textContent;
    const ref = el('send-balance-ref');
    if (balText && balText !== '—') {
        ref.textContent = 'Available: ' + balText;
    } else {
        ref.textContent = '';
    }

    // Update placeholder for current network
    const prefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    el('input-dest').placeholder = prefix + '...';

    showScreen('send');
    try {
        // Brief delay after broadcast to let the node process the TX
        if (window._lastBroadcastTime && Date.now() - window._lastBroadcastTime < 5000) {
            const ref3 = el('send-balance-ref');
            if (ref3) ref3.textContent = 'Refreshing balance...';
            await new Promise(r => setTimeout(r, 2000));
        }
        const wsUrl = await resolveNodeUrl();
        const resultJson = await get_fee_estimate(wsUrl);
        lastFeeEstimate = JSON.parse(resultJson);
        const isCov = (_broadcastReturnScreen === 'covenant');
        el('input-fee').value = isCov ? Math.max(400000, lastFeeEstimate.suggested_fee) : lastFeeEstimate.suggested_fee;
        updateFeeCardAmounts();
        // Reset to Normal active
        document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
        el('btn-fee-normal').classList.add('fee-card-active');
        const utxosJson = await fetch_utxos(walletData, wsUrl);
        cachedUtxos = JSON.parse(utxosJson);
        // Sort: amount desc, then tx_id asc + index asc for determinism.
        // Must match the Rust _selected functions' sort order exactly so
        // positional indices refer to the same UTXOs on both sides.
        cachedUtxos.sort((a, b) => b.amount - a.amount
            || a.tx_id.localeCompare(b.tx_id)
            || a.index - b.index);
        // Update available balance from fresh UTXOs
        const freshTotal = cachedUtxos.reduce((s, u) => s + u.amount, 0);
        const ref2 = el('send-balance-ref');
        if (ref2) ref2.textContent = 'Available: ' + (freshTotal / 1e8).toFixed(8).replace(/\.?0+$/, '') + ' KAS';
    } catch (e) {
        console.log('[KasSee] Fee/UTXO fetch:', e);
    }
}

function _isThreadDepositScreen() {
    return _broadcastReturnScreen === 'covenant' && lastCovenantResult &&
        (lastCovenantResult.type === 'global-allowance' || lastCovenantResult.type === 'global-spending-limit');
}

// Thread covenants full-spend the chosen UTXO(s) into the single thread, so the
// amount field is hidden. Mirror the selected-UTXO total into the hidden amount
// so the >0 validation passes and fee math stays consistent. Idempotent.
function syncThreadDepositAmount() {
    if (!_isThreadDepositScreen()) return;
    // Genesis funding shows the amount field and is user-driven (honor the typed
    // amount, emit change). Only a TOP-UP hides the amount field and full-spends the
    // selected UTXO(s) into the thread, so the selection-mirror applies there alone.
    const _aw = el('send-amount-wrap');
    if (_aw && _aw.style.display !== 'none') return; // visible => genesis, leave the typed amount
    let sum = 0;
    if (selectedUtxoIndices && cachedUtxos) {
        for (const i of selectedUtxoIndices) if (cachedUtxos[i]) sum += cachedUtxos[i].amount;
    }
    const amtEl = el('input-amount');
    if (amtEl) amtEl.value = sum > 0 ? (sum / 1e8).toFixed(8).replace(/\.?0+$/, '') : '';
    updateFeeCardAmounts();
}

function toggleSendUtxos() {
    const list = el('send-utxo-list');
    if (list.style.display !== 'none') {
        list.style.display = 'none';
        el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
        selectedUtxoIndices = null;
        return;
    }
    if (!cachedUtxos || cachedUtxos.length === 0) {
        toast('No UTXOs available', 'error');
        return;
    }
    el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▾';
    list.style.display = '';
    let html = '';
    cachedUtxos.forEach((u, i) => {
        const kas = (u.amount / 1e8).toFixed(8);
        html += `<div class="utxo-item" data-idx="${i}" style="cursor:pointer;display:flex;align-items:center;gap:10px">
            <span style="font-size:18px;color:var(--border)" class="utxo-check">☐</span>
            <div style="flex:1">
                <div class="utxo-amount" style="font-size:13px">${kas} KAS</div>
                <div class="utxo-detail">${u.tx_id.slice(0, 16)}…:${u.index}</div>
            </div>
        </div>`;
    });
    list.innerHTML = html;
    selectedUtxoIndices = [];

    list.querySelectorAll('.utxo-item').forEach(item => {
        item.onclick = () => {
            const idx = parseInt(item.dataset.idx);
            const check = item.querySelector('.utxo-check');
            const pos = selectedUtxoIndices.indexOf(idx);
            if (pos >= 0) {
                selectedUtxoIndices.splice(pos, 1);
                check.textContent = '☐';
                check.style.color = 'var(--border)';
                item.style.borderColor = '';
            } else if (selectedUtxoIndices.length >= 32) {
                toast('Max 32 UTXOs per transaction', 'info', 1500);
                return;
            } else {
                selectedUtxoIndices.push(idx);
                check.textContent = '☑';
                check.style.color = 'var(--teal)';
                item.style.borderColor = 'var(--teal)';
            }
            syncThreadDepositAmount(); // thread deposit: amount = selected UTXO total
        };
    });
    list.classList.remove('hidden');
}

function setFeeLevel(level) {
    if (!lastFeeEstimate) return;
    const isCovDeposit = (_broadcastReturnScreen === 'covenant');
    const mass = isCovDeposit ? 3500 : 2300;
    let feerate, minFee;
    if (level === 'low') {
        feerate = lastFeeEstimate.low_sompi_per_gram;
        minFee = isCovDeposit ? 400000 : 2500;
    } else if (level === 'priority') {
        feerate = lastFeeEstimate.priority_sompi_per_gram;
        minFee = isCovDeposit ? 500000 : 300000;
    } else {
        feerate = lastFeeEstimate.normal_sompi_per_gram;
        minFee = isCovDeposit ? 400000 : 5000;
    }
    el('input-fee').value = Math.max(minFee, Math.round(feerate * mass));

    // Update active card visual
    document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
    el('btn-fee-' + level).classList.add('fee-card-active');
}

function updateFeeCardAmounts() {
    if (!lastFeeEstimate) return;
    const isCovDeposit = (_broadcastReturnScreen === 'covenant');
    const mass = isCovDeposit ? 3500 : 2300;
    const low = Math.max(isCovDeposit ? 400000 : 2500, Math.round(lastFeeEstimate.low_sompi_per_gram * mass));
    const normal = Math.max(isCovDeposit ? 400000 : 5000, Math.round(lastFeeEstimate.normal_sompi_per_gram * mass));
    const priority = Math.max(isCovDeposit ? 500000 : 300000, Math.round(lastFeeEstimate.priority_sompi_per_gram * mass));
    el('fee-low-amount').textContent = low.toLocaleString();
    el('fee-normal-amount').textContent = normal.toLocaleString();
    el('fee-priority-amount').textContent = priority.toLocaleString();

    // Show estimated time if available from node
    const lowTime = el('fee-low-time');
    const normalTime = el('fee-normal-time');
    const priorityTime = el('fee-priority-time');
    if (lowTime && lastFeeEstimate.low_seconds != null) {
        lowTime.textContent = formatSeconds(lastFeeEstimate.low_seconds);
    }
    if (normalTime && lastFeeEstimate.normal_seconds != null) {
        normalTime.textContent = formatSeconds(lastFeeEstimate.normal_seconds);
    }
    if (priorityTime && lastFeeEstimate.priority_seconds != null) {
        priorityTime.textContent = formatSeconds(lastFeeEstimate.priority_seconds);
    }
}

function formatSeconds(s) {
    if (s == null || s <= 0) return '';
    if (s < 1) return '< 1s';
    if (s < 60) return Math.round(s) + 's';
    if (s < 3600) return Math.round(s / 60) + 'min';
    return Math.round(s / 3600) + 'h';
}

function handleSendMax() {
    if (!walletData) return;
    const defaultFee = (_broadcastReturnScreen === 'covenant') ? 400000 : 300000;
    const baseFee = parseInt(el('input-fee').value) || defaultFee;

    if (selectedUtxoIndices && selectedUtxoIndices.length > 0 && cachedUtxos) {
        const selectedTotal = selectedUtxoIndices.reduce((s, i) => s + cachedUtxos[i].amount, 0);
        const numInputs = selectedUtxoIndices.length;
        const C = 1e12;
        // Compute storage mass for send-all (1 output = full amount, no change)
        const invInSum = selectedUtxoIndices.reduce((s, i) => {
            const a = cachedUtxos[i].amount;
            return s + (a > 0 ? C / a : 0);
        }, 0);
        // With 1 output of value ~selectedTotal: storage_mass = C/amount - sum(C/input)
        // Since amount < sum(inputs), inv_out < inv_in, so storage_mass = 0 for send-all.
        // But with change output (2 outputs), both small change and big send can add mass.
        // For Max, assume send-all with no change (1 output). Storage mass is 0 or very low.
        const computeMass = 800 * numInputs + 2000;
        // 110% safety margin matching WASM
        const massFee = Math.max(Math.ceil(computeMass * 110), 300000);
        const maxAmount = selectedTotal - massFee;
        const maxKas = Math.max(0, maxAmount / 1e8);
        el('input-amount').value = maxKas.toFixed(8);
        return;
    }

    const balText = el('balance-kas').textContent;
    const match = balText.match(/([\d.]+)/);
    if (!match) { toast('Refresh balance first', 'info'); return; }
    const totalKas = parseFloat(match[1]);
    const maxKas = Math.max(0, totalKas - feeKas);
    el('input-amount').value = maxKas.toFixed(8);
}

// ─── Compound recipients ───

// ─── Destination QR scan ───

function handleDestScan(data) {
    const text = typeof data === 'string' ? data : new TextDecoder().decode(new Uint8Array(data));
    let addr = text.trim();
    const expectedPrefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    // KasSigner renders addresses with the mainnet 'kaspa:' prefix regardless
    // of network, so on a testnet the scanned string is a valid address but the
    // wrong HRP. The bech32 checksum is computed over the HRP, so a plain prefix
    // swap would corrupt it. Decode and re-encode for the active network instead
    // (the payload is HRP-independent; only the prefix + checksum change).
    if (/^kaspa(test|dev|sim)?:/.test(addr) && !addr.startsWith(expectedPrefix)) {
        try {
            const dec = JSON.parse(decode_address(addr));
            if (dec.version === 0) {
                addr = encode_p2pk_address(dec.payload, network);
            } else if (dec.version === 8) {
                addr = encode_p2sh_address(dec.payload, network);
            } else {
                toast('Unsupported address version ' + dec.version, 'err', 3000);
                return;
            }
        } catch (e) {
            toast('Could not decode scanned address', 'err', 3000);
            return;
        }
    }
    if (addr.startsWith(expectedPrefix) || addr.endsWith('.kas')) {
        stopScanner();
        el('input-dest').value = addr;
        showScreen('send');
        toast('Address scanned', 'ok', 1500);
    }
}

// ─── KSPT signature status check ───

function checkKsptSignatureStatus(hex) {
    if (hex.length < 12) return 'unknown';
    const header = hex.substring(0, 8);
    if (header !== '4b535054') return 'unknown';
    const version = parseInt(hex.substring(8, 10), 16);
    const flags = parseInt(hex.substring(10, 12), 16);
    if ((flags & 0x01) === 0x01) return 'signed';
    if (flags === 0x00 && version === 0x02) return 'partial';
    // 0x05 is v3's BODY plus a hint trailer, so it walks identically. Without it
    // a PARTIAL 0x05 fell past every case and returned 'unknown', so the scan did
    // nothing at all - no merge, no error, straight back to the scan button. A
    // fully-signed 0x05 happened to work because the flags check comes first,
    // which is why this only showed up on a partial.
    if (flags === 0x00 && (version === 0x03 || version === 0x05)) {
        // v3: signer may undercount nosig covenant inputs.
        // Scan inputs for any sig_count > 0 (and != 0xFF nosig marker).
        try {
            const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            // v3 header: 4(magic) + 1(ver) + 1(flags) + 2(tx_ver) + 1(num_in) + 1(num_out)
            //            + 8(locktime) + 20(subnet) + 8(gas) + 2(payload_len) = 48
            const numIn = bytes[8];
            const payloadLen = bytes[46] | (bytes[47] << 8);
            let pos = 48 + payloadLen;
            console.log('[KasSee] KSPT v3 sig check: numIn=' + numIn + ', payloadLen=' + payloadLen + ', startPos=' + pos);
            for (let i = 0; i < numIn && pos + 50 < bytes.length; i++) {
                pos += 32 + 4 + 8 + 8 + 1; // txid, prev_idx, amount, seq, sigop
                pos += 2; // spk_version
                const spkLen = bytes[pos]; pos += 1;
                pos += spkLen;
                const sigCount = bytes[pos]; pos += 1;
                console.log('[KasSee] KSPT v3 input[' + i + ']: sigCount=' + sigCount + ' (0xFF=nosig) at pos=' + (pos-1));
                if (sigCount > 0 && sigCount < 0xFF) return 'signed';
                const sc = (sigCount === 0xFF) ? 0 : sigCount;
                pos += sc * 66; // each sig: 1 pos + 1 sighash + 64 sig
                const redeemLen = bytes[pos] | (bytes[pos+1] << 8); pos += 2;
                pos += redeemLen;
            }
        } catch (e) { console.warn('[KasSee] KSPT v3 sig check error:', e); }
        return 'unsigned';
    }
    if (flags === 0x00) return 'unsigned';
    return 'unknown';
}

let recipientCount = 0;

function addRecipientRow() {
    recipientCount++;
    const prefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    const container = el('extra-recipients');
    const row = document.createElement('div');
    row.className = 'recipient-row';
    row.dataset.rid = recipientCount;
    row.innerHTML = `
        <button class="recipient-remove" title="Remove">&times;</button>
        <input type="text" class="input-text r-addr" placeholder="${prefix}..." autocomplete="off" spellcheck="false">
        <input type="number" class="input-text r-amount" placeholder="Amount (KAS)" step="0.00000001" min="0">
    `;
    row.querySelector('.recipient-remove').onclick = () => row.remove();
    container.appendChild(row);
}

function getExtraRecipients() {
    const container = el('extra-recipients');
    if (!container) return [];
    const rows = container.querySelectorAll('.recipient-row');
    const list = [];
    for (const row of rows) {
        const addr = row.querySelector('.r-addr').value.trim();
        const amountStr = row.querySelector('.r-amount').value.trim();
        if (addr && amountStr) {
            // The typed string, not parseFloat. This value becomes a
            // recipient's amount_sompi in a signed transaction, and a float
            // round trip (parseFloat here, String() at the call site) is only
            // lossless while JS can print the shortest representation that
            // round-trips: it stops being so above ~90M KAS in one output.
            // Keeping the string means kasToSompi sees exactly what the user
            // typed. Missed by the earlier exact-value sweep because that
            // searched for `Number(`, not `parseFloat`.
            list.push({ address: addr, amount_str: amountStr });
        }
    }
    return list;
}

// Fee for a covenant deposit or top-up, from the transaction's COMPUTE mass, the same way
// the lib.rs ZK-crowdfund sweep computes it. The covenant output's KIP-9 storage mass is 0,
// so compute mass binds. The node bills compute mass at 100 sompi/gram (a 3-input top-up of
// mass 4003 needed 400300), so:
//   compute_mass = est_tx_bytes + sig_op_count*1000*nInputs + spk_mass
//   fee = compute_mass * 100 * 1.15 (margin)
// A genesis or top-up that honours a specified amount produces TWO outputs (the covenant
// output plus a P2PK change output), so both the change output and the covenant_id binding
// on output[0] are counted here. When there is no change (full-fold), the phantom change
// output overpays by ~0.0004 KAS, which is dust and safe, so it is counted unconditionally.
// p2pkInputs: schnorr wallet inputs. redeemBytes: the covenant input's redeem script length
// in bytes (0 if none, e.g. the genesis has no thread input yet). payloadBytes: tx payload.
function covDepositFee({ p2pkInputs = 0, redeemBytes = 0, payloadBytes = 0 } = {}) {
    const FEE_RATE = 100n;                                   // sompi per gram (node relay rate)
    const nP2pk = BigInt(Math.max(0, p2pkInputs | 0));
    const rBytes = BigInt(Math.max(0, Math.floor(redeemBytes)));
    const pBytes = BigInt(Math.max(0, Math.floor(payloadBytes)));
    const hasP2sh = rBytes > 0n;
    const nInputs = nP2pk + (hasP2sh ? 1n : 0n);
    const perP2pk = nP2pk * (45n + 66n + 4n);                // outpoint+seq + 66B schnorr sig push
    const perP2sh = hasP2sh ? (45n + (66n + rBytes + 3n) + 4n) : 0n;  // sig + redeem + pushes
    // Outputs: covenant output (35B P2SH spk + 32B covenant_id binding) plus a P2PK change
    // output (~43B: 34B spk + amount + len). Both are part of the serialized tx and the
    // node's compute mass; omitting the change output is what underpaid genesis-with-change.
    const covOutBytes = 35n + 32n;                           // P2SH spk + covenant_id field
    const changeOutBytes = 43n;                              // P2PK change output
    const estTxBytes = 46n + perP2pk + perP2sh + covOutBytes + changeOutBytes + pBytes + 10n;
    const sigOpMass = nInputs * 1000n;                       // sig_op_count = 1 per input
    const spkMass = (35n + 34n) * 10n;                       // covenant P2SH spk + change P2PK spk
    const computeMass = estTxBytes + sigOpMass + spkMass;
    let fee = (computeMass * FEE_RATE * 115n) / 100n;        // * 1.15 margin
    if (fee < 100000n) fee = 100000n;                        // degenerate backstop
    return fee;
}

// Consolidation fee: N P2PK inputs into one P2PK output (no change, no covenant).
// Compute mass ~= 430 + 1115*N grams; * 100 sompi/gram * 1.15 margin. Scales with the
// input count so multi-UTXO consolidations clear the node's compute-mass floor.
function consolidateFee(n) {
    const grams = 430 + 1115 * Math.max(1, n | 0);
    return BigInt(Math.max(100000, Math.ceil(grams * 115))); // grams * 100 * 1.15
}

// Lossless decimal-KAS string -> integer sompi (BigInt). No floating point:
// Number / Math.round(x*1e8) loses a sompi on many decimals and all precision
// above ~2^53 sompi. wasm-bindgen marshals the returned BigInt to a Rust u64.
function kasToSompi(str) {
    if (typeof str !== 'string') str = String(str);
    str = str.trim();
    if (!/^\d+(\.\d{1,8})?$/.test(str)) {
        throw new Error('Invalid KAS amount: ' + str);
    }
    const [whole, frac = ''] = str.split('.');
    const fracPadded = (frac + '00000000').slice(0, 8);
    return BigInt(whole) * 100000000n + BigInt(fracPadded);
}

// Serialize a PSKT whose amounts are BigInt, emitting them as unquoted JSON
// numbers.
//
// `JSON.stringify` throws on BigInt, which is why amounts used to be cast
// through `Number()` on the way into the object. Above 2^53 sompi
// (90,071,992.55 KAS) that cast rounds, the device signs a sighash over the
// rounded value while the node computes one from the true value, and the
// signature does not verify. Every retry rounds identically, so the covenant
// cannot be spent through KasSee at all.
//
// The replacer wraps each BigInt in NUL characters, which `JSON.stringify`
// escapes as \u0000 inside the quoted string, and the regex then removes the
// quotes and the markers. NUL is safe as a marker because it cannot appear
// unescaped in JSON string content.
//
// Quoting the amounts instead was considered and rejected: the firmware
// tokenizer requires a numeric token and rejects a quoted amount outright,
// and `covenant_api.rs` reads them with `as_u64()`, which yields None for a
// string and would turn every UTXO into zero.
function psktToJson(value) {
    const s = JSON.stringify(value, (_k, v) =>
        typeof v === 'bigint' ? '\u0000' + v.toString() + '\u0000' : v);
    return s.replace(/"\\u0000(\d+)\\u0000"/g, '$1');
}

async function handleCreateTx() {
    let dest = el('input-dest').value.trim();
    // Thread-covenant deposit: amount field is hidden; ensure it reflects the
    // selected UTXO total before the >0 check (also covers any picker desync).
    syncThreadDepositAmount();
    const amountStr = el('input-amount').value.trim();
    const feeStr = el('input-fee').value.trim();

    // KNS resolution: if ends with .kas, look up address
    if (dest.endsWith('.kas')) {
        const resolved = KNS_LOOKUP[dest.toLowerCase()];
        if (resolved) {
            dest = resolved;
            toast('Resolved ' + el('input-dest').value.trim() + ' → address', 'ok', 2000);
        } else {
            toast('Unknown .kas domain: ' + dest, 'error'); return;
        }
    }

    const expectedPrefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    if (!dest || !dest.startsWith(expectedPrefix)) {
        toast('Enter a valid ' + expectedPrefix + ' address or .kas domain', 'error'); return;
    }
    if (!amountStr || parseFloat(amountStr) <= 0) {
        toast('Enter an amount > 0', 'error'); return;
    }

    const amount = parseFloat(amountStr);
    const baseFee = Math.max(300000, parseInt(feeStr) || 300000);
    const fee = baseFee;
    if (fee !== parseInt(feeStr)) {
        el('input-fee').value = fee;
    }
    const extras = getExtraRecipients();

    // Compound TX temporarily disabled — KasSigner QR display bug at 7+ frames
    if (extras.length > 0) {
        toast('Compound TX disabled — firmware update needed', 'error', 4000);
        return;
    }

    showLoading('Creating transaction...');
    try {
        let pskbHex;
        const freshWallet = walletWithFreshIndices();

        if (extras.length > 0) {
            const recipients = [{ address: dest, amount_sompi: kasToSompi(amountStr).toString() }, ...extras.map(e => ({ address: e.address, amount_sompi: kasToSompi(e.amount_str).toString() }))];
            pskbHex = await withNodeRetry(wsUrl =>
                create_compound_pskb(freshWallet, JSON.stringify(recipients), BigInt(fee), wsUrl)
            );
        } else if (_broadcastReturnScreen === 'covenant' && lastCovenantResult && dest === lastCovenantResult.address) {
            // Covenant deposit: use covenant-aware PSKB with encrypted reconstruction payload
            let amountSompi = kasToSompi(amountStr);
            const wallet = JSON.parse(walletData);
            const changeAddr = wallet.change_addresses[wallet.next_change_index || 0];
            const utxoCsv = (selectedUtxoIndices && selectedUtxoIndices.length > 0) ? selectedUtxoIndices.join(',') : '';

            // Piggy (additive) deposit: a dust change output blows up KIP-9 storage
            // mass (mass ~ 1e12/value), so the node rejects it. Require a manual
            // UTXO pick (so we know the funding total), price the fee from the actual
            // input count (the flat form fee does not scale and under-pays on many
            // inputs), and when the leftover change would fall below the viable
            // minimum, fold it into the deposit so the TX has a single output. A
            // viable change (>= 0.1 KAS) is kept as-is.
            let _additiveFee = null;
            if ((lastCovenantResult.type || '') === 'additive') {
                if (!selectedUtxoIndices || selectedUtxoIndices.length === 0) {
                    hideLoading();
                    toast('Pick the wallet UTXO(s) to deposit. The selected amount (minus fee) goes into the piggy.', 'error', 5000);
                    return;
                }
                let selTotal = 0n;
                for (const i of selectedUtxoIndices) if (cachedUtxos && cachedUtxos[i]) selTotal += BigInt(cachedUtxos[i].amount);
                // Tight compute-mass fee scaled to the picked inputs (single P2SH
                // output, no covenant input). The payload now carries the full
                // salted redeem script for recovery, so size the fee from the real
                // payload (as the savings/DMS branch below does) instead of a fixed
                // guess, or the folded single-output deposit under-pays.
                const _addParams = buildCovenantParamsHex(lastCovenantResult);
                const _addPayloadBytes = 30 + Math.ceil(_addParams.length / 2); // nonce(12)+hdr(2)+tag(16)+params
                _additiveFee = covDepositFee({ p2pkInputs: selectedUtxoIndices.length, payloadBytes: _addPayloadBytes });
                const feeN = _additiveFee;
                const KIP9_MIN = 10000000n; // 0.1 KAS — a smaller change output explodes storage mass
                const change = selTotal - amountSompi - feeN;
                if (change < KIP9_MIN) {
                    // No viable change: full-spend the selection into one piggy output.
                    const folded = selTotal - feeN;
                    if (folded <= 0n) { hideLoading(); toast('Selected UTXOs do not cover the fee.', 'error'); return; }
                    amountSompi = folded;
                }
            }

            // Payload-carrying deposits (Time-Locked Savings, Dead Man's Switch):
            // a plain send to the covenant address that also writes the ~215B
            // encrypted recovery payload. Two node-rejection traps apply to both:
            //   1) the plain Send fee does not count the payload's compute mass, so
            //      it under-pays ("fees under required for compute mass");
            //   2) a dust change output (< 0.1 KAS) explodes KIP-9 storage mass.
            // Fix: price the fee to the picked inputs PLUS the payload, and when the
            // picked UTXOs leave dust change, fold it into the deposit so the TX has a
            // single output. The deposit goes to the user's own covenant, so folding
            // the change in is safe (it just increases the locked/vault amount).
            // Viable change (>= 0.1 KAS) is kept. DMS and savings share this branch
            // because buildCovenantParamsHex and the fold are identical for both.
            if (['timelocked-savings', 'dms'].includes(lastCovenantResult.type || '')
                && selectedUtxoIndices && selectedUtxoIndices.length > 0) {
                let selTotalS = 0n;
                for (const i of selectedUtxoIndices) if (cachedUtxos && cachedUtxos[i]) selTotalS += BigInt(cachedUtxos[i].amount);
                // Reuse the SAME fee for the fold below and the builder so the
                // single-output balance still nets to zero change.
                const _savParams = buildCovenantParamsHex(lastCovenantResult);
                const _savPayloadBytes = 30 + Math.ceil(_savParams.length / 2); // nonce(12)+hdr(2)+tag(16)+params
                _additiveFee = covDepositFee({ p2pkInputs: selectedUtxoIndices.length, payloadBytes: _savPayloadBytes });
                const feeS = _additiveFee;
                const KIP9_MIN_S = 10000000n; // 0.1 KAS
                const changeS = selTotalS - amountSompi - feeS;
                if (changeS > 0n && changeS < KIP9_MIN_S) {
                    const foldedS = selTotalS - feeS;
                    if (foldedS <= 0n) { hideLoading(); toast('Selected UTXOs do not cover the fee.', 'error'); return; }
                    amountSompi = foldedS;
                    console.log('[KasSee] ' + (lastCovenantResult.type || '') + ' deposit: folded dust change ' + changeS + ' sompi into the deposit (single output, KIP-9 safe), fee=' + feeS);
                }
            }

            // -- Global spending limit: single-thread routing --
            // Whole balance lives in ONE tagged UTXO (the thread). If the address
            // already holds a UTXO, add-funds is a top-up that folds the picked
            // wallet UTXOs into that thread. First funding (empty address) is the
            // genesis and falls through to the normal tagged deposit below.
            if (['global-spending-limit', 'global-allowance'].includes(lastCovenantResult.type || '')) {
                const _isGAllow = (lastCovenantResult.type || '') === 'global-allowance';
                const _wsG = await resolveNodeUrl();
                const _covU = JSON.parse(await fetch_utxos_for_address_js(dest, _wsG));
                if (_covU.length) {
                    if (!selectedUtxoIndices || selectedUtxoIndices.length === 0) {
                        hideLoading();
                        toast('Pick the wallet UTXOs to add, then Deposit. Top-up folds whole UTXOs into the thread (no change).', 'error', 5000);
                        return;
                    }
                    const _pickG = pickThread(_covU, lastCovenantResult && lastCovenantResult.covenant_id_hex);
                    const _gThread = _pickG.thread; // tagged thread, selected by covenant_id (not size)
                    if (!_gThread) {
                        hideLoading();
                        toast(_pickG.ambiguous
                            ? 'Multiple covenant-tagged UTXOs and no known thread id, cannot safely pick the thread.'
                            : 'Thread covenant_id unavailable from the node (need version-2 UTXO entries).', 'error', 6500);
                        return;
                    }
                    const _gId = _gThread.covenant_id || ''; // thread id (G)
                    const _gEnt = activeCovenants.find(c => c.address === dest);
                    const _gRedeem = (_gEnt && _gEnt.redeem_script_hex) ? _gEnt.redeem_script_hex : (lastCovenantResult.redeem_script_hex || '');
                    const _gCsv = selectedUtxoIndices.join(',');
                    const _gTopFee = covDepositFee({ p2pkInputs: selectedUtxoIndices.length, redeemBytes: _gRedeem.length / 2 }); // 1 P2SH thread + wallet UTXOs
                    pskbHex = await withNodeRetry(wsUrl =>
                        _isGAllow
                            ? create_global_allowance_topup(walletData, dest, _gRedeem, _gId, JSON.stringify(_gThread), _gTopFee, _gCsv, wsUrl)
                            : create_global_spending_limit_topup(walletData, dest, _gRedeem, _gId, JSON.stringify(_gThread), _gTopFee, _gCsv, wsUrl)
                    );
                    hideLoading();
                    console.log('[KasSee] ' + (_isGAllow ? 'Global allowance' : 'Global limit') + ' TOP-UP: folding ' + selectedUtxoIndices.length + ' wallet UTXO(s) into the thread, pskb=' + pskbHex.length + ' chars');
                    window._covPayloadHex = '';
                    _broadcastReturnScreen = 'covenant';
                    openPsktReview(pskbHex);
                    return;
                } else {
                    // GENESIS (empty thread). Initial funding behaves like a normal
                    // covenant deposit: honor the amount field and emit change. A blank
                    // amount (amountSompi == 0) tells the builder to fund the whole
                    // selection into the thread (no change). When a manual pick leaves a
                    // dust-sized change (< 0.1 KAS), fold it in so the TX stays a single
                    // output (KIP-9 safe), matching the savings/DMS deposit path. The
                    // tagged-genesis builder below still tags output[0] with G.
                    if (amountSompi > 0n && selectedUtxoIndices && selectedUtxoIndices.length > 0) {
                        let _gSel = 0n;
                        for (const i of selectedUtxoIndices) if (cachedUtxos && cachedUtxos[i]) _gSel += BigInt(cachedUtxos[i].amount);
                        const _gFee = covDepositFee({ p2pkInputs: selectedUtxoIndices.length, payloadBytes: 230 });
                        const _gChange = _gSel - amountSompi - _gFee;
                        const KIP9_MIN_G = 10000000n; // 0.1 KAS
                        if (_gChange > 0n && _gChange < KIP9_MIN_G) {
                            amountSompi = 0n; // builder folds the whole selection into one output
                            console.log('[KasSee] thread genesis: dust change ' + _gChange + ' sompi, folding whole selection (single output, KIP-9 safe)');
                        }
                    }
                    // Fall through to the tagged-genesis builder below.
                }
            }

            // Build encrypted covenant payload for chain-backed recovery
            let payloadHex = '';
            window._covPayloadHex = ''; // for verification hash on review screen
            try {
                const covType = lastCovenantResult.type || 'unknown';
                // Crowdfund has dual payload: encrypted params + discovery tag
                if (covType === 'crowdfund' && window._crowdfundVk) {
                    // Crowdfund payloads: organizer sends full VK, contributor sends campaign_id.
                    // Both also get encrypted recovery params prepended.
                    const encPayload = await encryptCovenantPayload(covType, lastCovenantResult);
                    let discoveryHex;
                    if (lastCovenantResult.crowdfund_role === 'contributor') {
                        discoveryHex = blake2b_hash(window._crowdfundVk);
                        console.log('[KasSee] Contributor payload: campaign_id', discoveryHex.substring(0, 16) + '...');
                    } else {
                        discoveryHex = window._crowdfundVk;
                    }
                    // Format: [enc_len:2 LE][encrypted_params][discovery_payload]
                    const encBytes = hexToBytes(encPayload);
                    const lenLo = (encBytes.length & 0xFF).toString(16).padStart(2, '0');
                    const lenHi = ((encBytes.length >> 8) & 0xFF).toString(16).padStart(2, '0');
                    payloadHex = lenLo + lenHi + encPayload + discoveryHex;
                    console.log('[KasSee] Crowdfund payload: enc=' + encBytes.length + 'B + discovery=' + (discoveryHex.length/2) + 'B');
                } else if (COV_TYPE[covType]) {
                    // Standard: entire payload is encrypted recovery params
                    // For commit-reveal, cr_ciphertext_hex is already in lastCovenantResult from _covExtra
                    payloadHex = await encryptCovenantPayload(covType, lastCovenantResult);
                    console.log('[KasSee] Encrypted covenant payload: ' + (payloadHex.length/2) + ' bytes for type ' + covType);
                }
            } catch (encErr) {
                // Encryption failed. Log but don't block the deposit.
                console.warn('[KasSee] Covenant payload encryption failed, proceeding without:', encErr);
                payloadHex = '';
            }

            if (payloadHex) {
                window._covPayloadHex = payloadHex;
                // Tag the genesis output with G for covenant_id-bound threads
                // (global spending limit). The thread then carries G on-chain, so
                // the continuation reuses it and the node serves it back.
                const _tagGenesis = (['global-spending-limit', 'global-allowance'].includes(lastCovenantResult.type || ''));
                // Global SL genesis: dynamic fee scaled to the picked UTXOs. The builder folds
                // the whole selected balance into the single thread (no change) when tag_genesis.
                const _depFee = _tagGenesis ? covDepositFee({ p2pkInputs: (selectedUtxoIndices || []).length, payloadBytes: payloadHex ? payloadHex.length / 2 : 0 }) : (_additiveFee !== null ? _additiveFee : BigInt(fee));
                pskbHex = await withNodeRetry(wsUrl =>
                    create_covenant_pskb_with_payload(walletData, dest, amountSompi, _depFee, changeAddr, payloadHex, utxoCsv, wsUrl, _tagGenesis)
                );
            } else {
                pskbHex = await withNodeRetry(wsUrl =>
                    create_covenant_pskb(walletData, dest, amountSompi, (_additiveFee !== null ? _additiveFee : BigInt(fee)), changeAddr, '', utxoCsv, wsUrl)
                );
            }
        } else if (selectedUtxoIndices && selectedUtxoIndices.length > 0) {
            // Pass the actual cached UTXO objects to avoid stale-index bugs
            const selectedUtxos = selectedUtxoIndices
                .filter(i => cachedUtxos && i < cachedUtxos.length)
                .map(i => cachedUtxos[i]);
            if (selectedUtxos.length === 0) {
                throw 'Selected UTXOs no longer available. Refresh and try again.';
            }
            const utxosJson = JSON.stringify(selectedUtxos);
            pskbHex = await withNodeRetry(wsUrl =>
                create_send_pskb_with_utxos(freshWallet, dest, kasToSompi(amountStr), BigInt(fee), utxosJson, wsUrl)
            );
        } else {
            pskbHex = await withNodeRetry(wsUrl =>
                create_send_pskb(freshWallet, dest, kasToSompi(amountStr), BigInt(fee), wsUrl)
            );
        }

        hideLoading();
        console.log(`[KasSee] PSKB created: ${pskbHex.length} hex chars`);
        // Route through the existing PSKT review screen — same flow as
        // multisig: Review → Relay (standard PSKB or compact KSPT v3
        // for KasSigner) → Finalize & Broadcast.
        openPsktReview(pskbHex);

    } catch (e) {
        hideLoading();
        toast('TX creation failed: ' + e, 'error', 5000);
        console.error('TX creation failed:', e);
    }
}

// ─── TX info under QR display for verification ───

function renderQrTxInfo() {
    const box = el('qr-tx-info');
    if (!box) return;
    if (!_lastPsktSummary) { box.style.display = 'none'; return; }
    const s = _lastPsktSummary;

    // Helper: derive address from script_hex + script_kind
    function scriptAddr(scriptHex, kind) {
        try {
            if ((kind === 'p2pk' || kind === 'p2pk-schnorr') && scriptHex.length === 68)
                return encode_p2pk_address(scriptHex.substring(2, 66), network);
            if ((kind === 'p2sh' || kind === 'p2sh-multisig' || kind === 'p2sh-covenant') && scriptHex.length === 70)
                return encode_p2sh_address(scriptHex.substring(4, 68), network);
        } catch (_) {}
        return null;
    }

    function addrLabel(addr) {
        if (!addr || !walletData) return '';
        let w; try { w = JSON.parse(walletData); } catch (_) { return ''; }
        if (w.receive_addresses && w.receive_addresses.includes(addr)) return 'OWN';
        if (w.change_addresses && w.change_addresses.includes(addr)) return 'CHANGE';
        return '';
    }

    function labelStyle(lbl) {
        if (lbl === 'CHANGE') return 'background:#2d333b;color:var(--text-muted)';
        if (lbl === 'OWN') return 'background:#1a3a2a;color:var(--teal)';
        if (lbl === 'DESTINATION') return 'background:#3a2a1a;color:var(--warning)';
        if (lbl === 'COVENANT') return 'background:#2a2a3a;color:var(--teal)';
        return '';
    }

    function addrHtml(addr, label) {
        if (!addr) return '<span style="color:var(--text-muted)">(unknown)</span>';
        const tag = label ? ` <span style="font-size:9px;padding:1px 5px;border-radius:3px;${labelStyle(label)}">${label}</span>` : '';
        return `<div style="word-break:break-all;font-family:var(--mono);font-size:10px;line-height:1.3;margin-top:2px">${emphasizeAddr(addr)}${tag}</div>`;
    }

    let html = '<div style="font-size:11px;line-height:1.5">';
    html += '<div style="font-weight:600;color:var(--teal);margin-bottom:6px;font-size:12px">TX Verification</div>';

    // Fee
    html += `<div style="margin-bottom:8px;color:var(--text-dim)">Fee: ${fmtKas(s.fee_sompi)} KAS</div>`;

    // Addresses of the multisig inputs, needed before the outputs are drawn.
    //
    // `addrLabel` only knows the single-sig receive/change lists, so a P2SH
    // multisig address returns nothing and falls through to the P2SH branch
    // below, which labels ANY p2sh output COVENANT. Multisig change returns to
    // the address being spent from, so it was displayed as a covenant rather
    // than as change, and a redirected change output would have looked exactly
    // the same.
    //
    // Restricted to multisig inputs on purpose: a covenant output paying back
    // to its own address is a covenant continuation, and COVENANT is the more
    // informative label for it.
    const msInputAddrs = new Set();
    s.inputs.forEach(inp => {
        if (inp.script_kind !== 'p2sh-multisig') return;
        const a = scriptAddr(inp.script_hex, inp.script_kind);
        if (a) msInputAddrs.add(a);
    });

    // Outputs (most important for verification)
    html += '<div style="font-weight:600;margin-bottom:4px">Outputs</div>';
    s.outputs.forEach((out, i) => {
        const addr = out.address || scriptAddr(out.script_hex, out.script_kind);
        const cls = addrLabel(addr) || (addr && msInputAddrs.has(addr) ? 'CHANGE' : '');
        const isCovP2sh = out.script_kind === 'p2sh';
        const label = cls || (isCovP2sh ? 'COVENANT' : (addr ? 'DESTINATION' : ''));
        html += `<div style="margin-bottom:8px;padding:6px 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px">`;
        html += `<div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="color:var(--text-muted)">#${i} ${out.script_kind.toUpperCase()}</span><span style="color:var(--text)">${fmtKas(out.amount_sompi)} KAS</span></div>`;
        html += addrHtml(addr, label);
        // The covenant id, on the screen the QR is on: this is where the
        // user compares against the signer, so it has to be here and in
        // the signer's own 6+6 shape.
        if (out.covenant_id) {
            html += `<div style="margin-top:3px;font-family:var(--mono);font-size:10px;color:#ffa733;word-break:break-all">COVENANT ${covIdShort(out.covenant_id)}</div>`;
        }
        html += '</div>';
    });

    // Inputs
    html += '<div style="font-weight:600;margin:8px 0 4px">Inputs</div>';
    s.inputs.forEach((inp, i) => {
        let addr = scriptAddr(inp.script_hex, inp.script_kind);
        // Fallback: for P2SH covenant inputs, use the known covenant address
        if (!addr && (inp.script_kind === 'p2sh' || inp.script_kind === 'p2sh-covenant') && lastCovenantResult && lastCovenantResult.address) {
            addr = lastCovenantResult.address;
        }
        const cls = addrLabel(addr);
        const isCov = (inp.script_kind === 'p2sh' || inp.script_kind === 'p2sh-covenant') && inp.redeem_script_hex;
        const label = cls || (isCov ? 'COVENANT' : '');
        html += `<div style="margin-bottom:8px;padding:6px 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px">`;
        html += `<div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="color:var(--text-muted)">#${i} ${inp.script_kind.toUpperCase()}</span><span style="color:var(--text)">${fmtKas(inp.amount_sompi)} KAS</span></div>`;
        html += addrHtml(addr, label);
        if (inp.redeem_script_hex) {
            const rsId = 'qrtx-rs-' + i;
            html += `<div style="margin-top:4px"><span style="font-size:9px;color:var(--text-muted);cursor:pointer" onclick="var t=document.getElementById('${rsId}');t.style.display=t.style.display==='none'?'':'none'">Redeem Script \u25BC</span>`;
            html += `<div id="${rsId}" style="display:none;word-break:break-all;font-family:var(--mono);font-size:9px;color:var(--text-dim);line-height:1.2;margin-top:3px;padding:4px;background:var(--card-bg);border-radius:3px">${inp.redeem_script_hex}</div></div>`;
        }
        // The covenant id, on the screen the QR is on: this is where the
        // user compares against the signer, so it has to be here and in
        // the signer's own 6+6 shape.
        if (inp.covenant_id) {
            html += `<div style="margin-top:3px;font-family:var(--mono);font-size:10px;color:#ffa733;word-break:break-all">COVENANT ${covIdShort(inp.covenant_id)}</div>`;
        }
        html += '</div>';
    });

    html += '</div>';

    // Payload verification hash (same as pre-signing review)
    if (window._covPayloadHex && window._covPayloadHex.length > 0) {
        payloadToken(window._covPayloadHex).then(h => {
            const plDiv = document.getElementById('qrtx-pl-hash');
            if (plDiv) { plDiv.textContent = 'PL ' + h; plDiv.style.display = ''; }
        });
        html += '<div id="qrtx-pl-hash" style="text-align:right;font-family:monospace;font-size:12px;color:#4ecdc4;padding:4px 8px 0;opacity:0.85"></div>';
    }

    html += '</div>';
    box.innerHTML = html;
    box.style.display = '';
}

// ─── QR display ───

function displayKsptQr(ksptHex, title) {
    // Clear any stale QR cycle from a previous display
    if (qrCycleTimer) { clearInterval(qrCycleTimer); qrCycleTimer = null; }
    // Render TX verification info below QR
    renderQrTxInfo();
    try {
        const frames = JSON.parse(generate_qr_frames(ksptHex));
        qrFrames = frames;
        qrFrameIdx = 0;
        el('qr-display-title').textContent = title || 'Scan QR Code';

        const isRelay = title && title.includes('Relay');
        el('btn-scan-next-sig').style.display = isRelay ? 'block' : 'none';
        el('btn-copy-kspt').style.display = 'none'; // hidden until advanced tab
        _currentKsptHex = ksptHex; // L-13: module-scope, not window

        if (frames.length === 1) {
            el('qr-container').innerHTML = frames[0].svg;
            el('qr-frame-info').innerHTML = '';
        } else {
            let dots = '<div class="frame-dots">';
            for (let i = 0; i < frames.length; i++) {
                dots += `<span class="frame-dot${i === 0 ? ' active' : ''}" id="fdot-${i}"></span>`;
            }
            dots += '</div>';
            dots += '<div class="frame-controls">';
            dots += '<button class="btn-frame" id="btn-frame-prev">\u23EA</button>';
            dots += '<button class="btn-frame" id="btn-frame-pause" title="Pause/Play">\u23F8</button>';
            dots += '<button class="btn-frame" id="btn-frame-next">\u23E9</button>';
            dots += '<input type="range" id="qr-speed" min="250" max="1000" step="50" value="' + qrFrameMs + '" title="Frame period">';
            dots += '<span id="qr-speed-val">' + qrFrameMs + 'ms</span>';
            dots += '</div>';
            el('qr-frame-info').innerHTML = dots;
            renderQrFrame(0);
            qrCycleTimer = setInterval(() => {
                qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
            }, qrFrameMs);
            el('btn-frame-prev').onclick = () => {
                qrFrameIdx = (qrFrameIdx - 1 + qrFrames.length) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, qrFrameMs);
                }
            };
            el('btn-frame-next').onclick = () => {
                qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, qrFrameMs);
                }
            };
            el('qr-speed').oninput = () => {
                qrFrameMs = parseInt(el('qr-speed').value, 10);
                el('qr-speed-val').textContent = qrFrameMs + 'ms';
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, qrFrameMs);
                }
            };
            el('btn-frame-pause').onclick = () => {
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = null;
                    el('btn-frame-pause').textContent = '\u25B6';
                } else {
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, qrFrameMs);
                    el('btn-frame-pause').textContent = '\u23F8';
                }
            };
        }
        showScreen('qr-display');
    } catch (e) {
        toast('QR generation failed: ' + e, 'error', 5000);
    }
}

function renderQrFrame(idx) {
    if (!qrFrames || idx >= qrFrames.length) return;
    el('qr-container').innerHTML = qrFrames[idx].svg;
    for (let i = 0; i < qrFrames.length; i++) {
        const dot = document.getElementById(`fdot-${i}`);
        if (dot) dot.className = `frame-dot${i === idx ? ' active' : ''}`;
    }
    const c = el('qr-container');
    c.style.opacity = '0.7';
    setTimeout(() => { c.style.opacity = '1'; }, 100);
}

function stopQrCycle() {
    if (qrCycleTimer) { clearInterval(qrCycleTimer); qrCycleTimer = null; }
    qrFrames = null;
}

// Stop the animation timer but KEEP qrFrames intact. Used when the user
// briefly leaves the QR display (e.g. taps Scan Signed QR, then cancels
// the scanner) so we can resume animation on their return instead of
// leaving them stuck on a frozen QR with non-functional play/pause.
function pauseQrCycle() {
    if (qrCycleTimer) { clearInterval(qrCycleTimer); qrCycleTimer = null; }
}

// Restart the animation if we still have frames to cycle through.
// Idempotent: safe to call when already running.
function resumeQrCycleIfPossible() {
    if (!qrFrames || qrFrames.length <= 1) return;
    if (qrCycleTimer) return;
    qrCycleTimer = setInterval(() => {
        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
        renderQrFrame(qrFrameIdx);
    }, qrFrameMs);
    // Re-sync pause-button icon to the play state
    const pb = el('btn-frame-pause');
    if (pb) pb.textContent = '\u23F8';
}

// ─── Receive ───

function showReceive() {
    if (!walletData) return;
    const wallet = JSON.parse(walletData);

    const addrIdx = getNextReceiveIndex();

    const addr = wallet.receive_addresses[addrIdx];
    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(addr)));
        el('receive-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('receive-qr').innerHTML = '';
    }
    el('receive-address').textContent = addr;
    showScreen('receive');
}

function copyAddress() {
    const addr = el('receive-address').textContent;
    navigator.clipboard.writeText(addr).then(() => {
        el('btn-copy-address').textContent = 'Copied!';
        setTimeout(() => { el('btn-copy-address').textContent = 'Copy Address'; }, 1600);
    });
}

function hex_encode(str) {
    return Array.from(new TextEncoder().encode(str))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Broadcast ───

function hideBroadcastResult() {
    const card = el('broadcast-result');
    card.classList.add('hidden');
    card.className = 'result-card hidden';
    el('input-signed-hex').value = '';
    // Re-show the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = '';
}

function showBroadcastSuccess(txId) {
    window._oracleMbRollActive = false;
    window._oracleMbPendingProof = null;
    window._oracleMbPreSignAwaiting = false;
    window._oracleMbAutoBroadcast = false;
    const card = el('broadcast-result');
    card.className = 'result-card success';
    card.classList.remove('hidden');
    el('broadcast-result-icon').textContent = '';
    el('broadcast-result-msg').textContent = 'Transaction broadcast!';
    el('broadcast-result-txid').textContent = txId;
    el('btn-copy-txid').style.display = 'block';
    el('btn-broadcast-done').style.display = 'block';
    // Hide the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = 'none';

    // Preimage QR share (commented out: on-chain extraction works, no need for QR fallback)
    // Kept for potential future use where REST API is unavailable.
    /*
    const preimageShareEl = el('broadcast-preimage-share');
    if (preimageShareEl) {
        if (window._lastClaimPreimage) {
            preimageShareEl.style.display = '';
            preimageShareEl.innerHTML = '<p style="font-size:12px;color:var(--text-dim);margin:8px 0 4px;text-align:center">Preimage revealed. Show this QR to the counterparty:</p>'
                + '<button class="btn btn-outline" id="btn-show-preimage-qr" style="width:100%;margin-bottom:8px">📤 Share Preimage QR</button>'
                + '<p style="font-size:11px;color:var(--text-muted);text-align:center;word-break:break-all">Preimage: ' + window._lastClaimPreimage + '</p>';
            const btn = el('btn-show-preimage-qr');
            if (btn) {
                btn.onclick = () => {
                    try {
                        const preimageJson = JSON.stringify({ v: 1, t: 'swap-preimage', p: window._lastClaimPreimage });
                        // NOTE: single-frame QR, no stopQrCycle() here. Same stale multi-frame bleed risk the adaptor invite/response had (fixed). Add stopQrCycle() if it recurs.
                        const svg = generate_qr_svg_text(preimageJson);
                        el('qr-container').innerHTML = svg;
                        el('qr-frame-info').innerHTML = '';
                        el('qr-display-title').textContent = 'Preimage QR \u2014 counterparty scans this';
                        el('btn-scan-next-sig').style.display = 'none';
                        el('btn-copy-kspt').style.display = 'none';
                        if (el('qr-tx-info')) el('qr-tx-info').style.display = 'none';
                        showScreen('qr-display');
                    } catch (e) {
                        toast('QR generation failed: ' + e, 'error');
                    }
                };
            }
        } else {
            preimageShareEl.style.display = 'none';
            preimageShareEl.innerHTML = '';
        }
    }
    */

    // Path C post-broadcast hook: capture tx_id and trigger TX2
    if (_kasFreezePathCPostBroadcast) {
        const cb = _kasFreezePathCPostBroadcast;
        _kasFreezePathCPostBroadcast = null;
        cb(txId);
    }
}

function showBroadcastError(err) {
    const es = String(err);
    window._oracleMbPendingProof = null;
    window._oracleMbPreSignAwaiting = false;
    window._oracleMbAutoBroadcast = false;
    // Oracle roll lost the race: someone rolled the singleton first, so the node rejects ours
    // (the oracle/heartbeat UTXOs are already spent, or our tx is an orphan). No funds moved and
    // no fee was charged. Show the free-rider outcome instead of a scary error, and refresh the card.
    if (window._oracleMbRollActive && /already spent|orphan|disallow|already .*mempool/i.test(es)) {
        window._oracleMbRollActive = false;
        showScreen('broadcast');   // the finalize error path does not navigate; make the card visible
        const c = el('broadcast-result');
        c.className = 'result-card success';
        c.classList.remove('hidden');
        el('broadcast-result-icon').textContent = '';
        el('broadcast-result-msg').textContent = 'Someone rolled it first';
        el('broadcast-result-txid').textContent = "You're now on the fresh price. No fee charged.";
        el('btn-copy-txid').style.display = 'none';
        el('btn-broadcast-done').style.display = 'block';
        const formCard = document.querySelector('#screen-broadcast .card');
        if (formCard) formCard.style.display = 'none';
        try { oracleMbCardRefresh(); } catch (_) {}
        return;
    }
    window._oracleMbRollActive = false;
    const card = el('broadcast-result');
    card.className = 'result-card error';
    card.classList.remove('hidden');
    el('broadcast-result-icon').textContent = '';
    el('broadcast-result-msg').textContent = 'Broadcast failed';
    el('broadcast-result-txid').textContent = es;
    el('btn-copy-txid').style.display = 'none';
    el('btn-broadcast-done').style.display = 'block';
}

function handleSignedScan(data) {
    const hexStr = Array.from(new Uint8Array(data))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    try {
        const result = decode_qr_frame(hexStr);
        if (result && result.length > 0) {
            stopScanner();
            console.log('[KasSee] Scan complete: ' + result.length / 2 + ' bytes');

            // First: check for Kaspa-standard PSKT / PSKB envelope.
            // Device emits these after signing when the Kaspa-standard
            // wire format is selected. Legacy KSPT path handles the rest.
            const psktFormat = pskt_detect(result);
            if (psktFormat === 'pskb' || psktFormat === 'pskt') {
                console.log('[KasSee] ' + psktFormat.toUpperCase() + ' detected — opening review');
                openPsktReview(result);
                return;
            }

            const sigStatus = checkKsptSignatureStatus(result);

            // Compact-relay return path: if we sent a KSPT v3 to the
            // device via handlePsktRelayCompact, _psktReviewHex still
            // holds the canonical PSKB. Merge the new partial sigs
            // from the KSPT v3 back into the PSKB and re-open review.
            if ((sigStatus === 'partial' || sigStatus === 'signed') && _psktReviewHex) {
                console.log('[KasSee] KSPT v'
                    + parseInt(result.substring(8, 10), 16)
                    + ' return with canonical PSKB held — merging');
                try {
                    const mergedPskb = pskt_merge_signed_kspt_v2(result, _psktReviewHex);
                    openPsktReview(mergedPskb);
                    toast('Signature merged into PSKB', 'ok', 2500);
                    return;
                } catch (e) {
                    console.error('[KasSee] merge failed:', e);
                    toast('Merge failed: ' + e, 'error', 5000);
                    // Fall through to legacy relay path below.
                }
            }

            if (sigStatus === 'partial') {
                console.log('[KasSee] Partial signature — relay to next signer');
                toast('Partial signature — scan with next device', 'info', 3000);
                displayKsptQr(result, 'Relay to next signer');
            } else {
                el('input-signed-hex').value = result;
                showScreen('broadcast');
            }
        } else {
            const prog = JSON.parse(decoder_progress());
            if (prog.total > 0) {
                let dots = '';
                for (let i = 0; i < prog.total; i++) {
                    dots += `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:${prog.bits[i] ? 'var(--teal)' : 'var(--border)'};${prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : ''}"></span>`;
                }
                el('scanner-status').innerHTML = dots + `<div style="margin-top:6px;font-size:12px">${prog.count} / ${prog.total} frames</div>`;
            }
        }
    } catch (e) {
        console.error('Decode error:', e);
    }
}

async function handleBroadcastHex() {
    const hex = el('input-signed-hex').value.trim();
    if (!hex) { toast('Paste a signed KSPT hex string', 'error'); return; }

    // If someone pasted a PSKB/PSKT hex, route through the PSKT review.
    const psktFormat = pskt_detect(hex);
    if (psktFormat === 'pskb' || psktFormat === 'pskt') {
        openPsktReview(hex);
        return;
    }

    const sigStatus = checkKsptSignatureStatus(hex);
    if (sigStatus === 'partial') {
        toast('Partial signature — relay to next signer', 'info', 3000);
        displayKsptQr(hex, 'Relay to next signer');
        return;
    }
    if (sigStatus === 'unsigned') {
        // v3 KSPT sig-check can misread covenant inputs with nested scripts.
        // Show warning but allow broadcast. WASM finalization will catch real issues.
        toast('Warning: KSPT appears unsigned. If KasSigner showed signed QR, press Broadcast.', 'error', 5000);
    }

    if (!BROADCAST_ENABLED) {
        toast('Broadcast disabled in this version — testing only', 'error', 5000);
        return;
    }

    showLoading('Broadcasting...');
    try {
        const txId = await withNodeRetry(wsUrl => broadcast_signed(hex, wsUrl));
        hideLoading();
        showBroadcastSuccess(txId);
    } catch (e) {
        hideLoading();
        showBroadcastError(e);
        console.error('Broadcast failed:', e);
    }
}

// ─── PSKT / PSKB Review ───
//
// When a scan or paste yields a PSKB/PSKT envelope, we open a review
// screen showing inputs, outputs, fee, and multisig progress (M/N).
// From there the user can:
//   - Relay to next signer  (re-emit identical QR for the next device)
//   - Finalize + broadcast  (when all inputs meet their sig threshold)

// Stash the hex for the current review so both buttons can access it
// without re-parsing.
let _psktReviewHex = null;
let _lastPsktSummary = null;

/// Wrap the visual-verification zones of a kaspa address in highlight
/// spans: the network prefix + first 8 payload chars, and the last 8
/// chars. KasSigner's TX review screen emphasizes the same zones in
/// teal, so the user compares highlighted segment against highlighted
/// segment across the two screens. Non-bech32 input is escaped and
/// returned unstyled.
function emphasizeAddr(addr) {
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (!/^[a-z0-9:]+$/i.test(addr)) return esc(addr);
    const colon = addr.indexOf(':') + 1; // 0 if no prefix
    const aEnd = Math.min(colon + 8, addr.length);
    const bStart = Math.max(addr.length - 8, aEnd);
    // Prefix (up to and including ':') stays standard color for
    // legibility; emphasize only the first 8 payload chars and last 8.
    return addr.slice(0, colon)
        + '<span class="addr-hl">' + addr.slice(colon, aEnd) + '</span>'
        + addr.slice(aEnd, bStart)
        + '<span class="addr-hl">' + addr.slice(bStart) + '</span>';
}

function openPsktReview(wireHex) {
    _psktReviewHex = wireHex;
    window._oracleMbRollActive = false;   // cleared on every load; the oracle path re-arms it right after this call
    window._oracleMbReturn = false;       // clear any stale "return to oracle card" flag; only a roll's success path re-sets it

    let summary;
    try {
        summary = JSON.parse(pskt_summary(wireHex, network));
    } catch (e) {
        console.error('[KasSee] PSKT parse error:', e);
        toast('Could not parse PSKT: ' + e, 'error', 5000);
        return;
    }

    console.log('[KasSee] PSKT summary:', summary);
    _lastPsktSummary = summary;

    // Render header
    el('pskt-format').textContent = summary.format.toUpperCase();
    el('pskt-tx-version').textContent = summary.tx_version;
    el('pskt-in-count').textContent = summary.input_count;
    el('pskt-out-count').textContent = summary.output_count;
    el('pskt-fee').textContent = fmtKas(summary.fee_sompi);
    el('pskt-total-in').textContent = fmtKas(summary.total_in_sompi);
    el('pskt-total-out').textContent = fmtKas(summary.total_out_sompi);

    // Payload verification token: if a covenant payload exists, show
    // SHA-256(payload)[..8] grouped in fours. The user compares this with
    // KasSigner's "PL xxxxxxxx xxxxxxxx" on its review screen (M-12).
    const plHashEl = el('pskt-payload-hash');
    if (plHashEl) {
        if (window._covPayloadHex && window._covPayloadHex.length > 0) {
            payloadToken(window._covPayloadHex).then(h => {
                plHashEl.textContent = 'PL ' + h;
                plHashEl.style.display = '';
            });
        } else {
            plHashEl.textContent = '';
            plHashEl.style.display = 'none';
        }
    }

    // Inputs list
    const inputsEl = el('pskt-inputs');
    inputsEl.innerHTML = '';
    summary.inputs.forEach((inp, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        let sigLabel;
        if (inp.multisig_m !== null && inp.multisig_m !== undefined) {
            const ok = inp.sigs_present >= inp.multisig_m;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present}/${inp.multisig_m}-of-${inp.multisig_n}</span>`;
        } else {
            const ok = inp.sigs_present >= 1;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present} sig${inp.sigs_present === 1 ? '' : 's'}</span>`;
        }
        row.innerHTML = `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${inp.script_kind.toUpperCase()}</span>
                ${sigLabel}
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${fmtKas(inp.amount_sompi)} KAS</div>
                <div class="pskt-label">Prev TX</div>
                <div class="pskt-value pskt-mono">${shortenHex(inp.prev_tx_id)}:${inp.prev_index}</div>
                ${inp.covenant_id ? `
                <div class="pskt-label">Covenant</div>
                <div class="pskt-value pskt-mono" style="color:#ffa733">${covIdShort(inp.covenant_id)}</div>` : ''}
            </div>
        `;
        inputsEl.appendChild(row);
    });

    // Outputs list
    const outputsEl = el('pskt-outputs');
    outputsEl.innerHTML = '';
    summary.outputs.forEach((out, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        row.innerHTML = `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${out.script_kind.toUpperCase()}</span>
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${fmtKas(out.amount_sompi)} KAS</div>
                <div class="pskt-label">To</div>
                <div class="pskt-value pskt-mono">${out.address ? emphasizeAddr(out.address) : '(unrecognized script)'}</div>
                ${out.covenant_id ? `
                <div class="pskt-label">Covenant</div>
                <div class="pskt-value pskt-mono" style="color:#ffa733">${covIdShort(out.covenant_id)}</div>` : ''}
            </div>
        `;
        outputsEl.appendChild(row);
    });

    // Enable/disable Finalize button based on readiness
    const btnFinalize = el('btn-pskt-finalize');
    btnFinalize.disabled = !summary.finalize_ready;
    btnFinalize.textContent = summary.finalize_ready
        ? 'Finalize + broadcast'
        : 'Needs more signatures';

    showScreen('pskt-review');
}

/// Open the relay format picker modal. User chooses between standard
/// PSKB (any wallet) or compact KSPT v3 (KasSigner devices only).
function openRelayModal() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    el('relay-choice-modal').classList.remove('hidden');
}

function closeRelayModal() {
    el('relay-choice-modal').classList.add('hidden');
}

/// Relay in STANDARD PSKB hex — interoperable with any Kaspa wallet
/// that speaks PSKB, including another KasSee instance. The wire
/// format is not mutated; this is a display pass-through.
function handlePsktRelay() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    displayKsptQr(_psktReviewHex, 'Relay to next signer');
}

/// Relay in COMPACT KSPT v3 — converts the canonical PSKB to a KSPT
/// v2 partial blob (~5× fewer QR frames). Only KasSigner devices
/// can decode this. The PSKB stays as the canonical in-memory state;
/// only the wire transport is compressed.
///
/// Flow: KasSee holds PSKB → compact-relay to KasSigner → device
/// signs and returns a KSPT v3 → handleSignedScan merges the new
/// sigs back into _psktReviewHex via pskt_merge_signed_kspt_v2.
function handlePsktRelayCompact() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    let ksptHex;
    try {
        ksptHex = pskt_relay_to_kspt_v2(_psktReviewHex);
    } catch (e) {
        console.error('[KasSee] compact relay encode failed:', e);
        toast('Compact relay failed: ' + e, 'error', 5000);
        return;
    }
    // Report the version actually emitted. Hardcoding v3 made a v5 relay read as
    // v3 in the console, which is the one place someone checks whether the hints
    // went out.
    const relayVer = ksptHex.length >= 10 ? parseInt(ksptHex.substring(8, 10), 16) : 0;
    console.log('[KasSee] Compact relay: PSKB hex ' + _psktReviewHex.length +
                ' → KSPT v' + relayVer + ' hex ' + ksptHex.length +
                ' (' + Math.round((1 - ksptHex.length / _psktReviewHex.length) * 100) + '% smaller)');
    displayKsptQr(ksptHex, 'Relay to KasSigner (compact)');
}

/// Finalize + broadcast — PSKT-NATIVE path.
///
/// Walks the PSKB JSON once inside WASM, assembles a consensus
/// Transaction directly (sig_scripts with partial sigs + redeem
/// script for P2SH multisig), Borsh-serializes it to the node. No
/// KSPT intermediate format anywhere in the flow.
// Content-based detector for an Oracle-MB roll: the skeleton's input[0] carries
// proprietaries.risc0OracleMb. This survives the review reload that fires when the signed QR is
// scanned back (which clears the _oracleMbRollActive flag), so Finalize always routes an oracle
// roll to /roll and never to the local sealless broadcast the node rejects (seal_len=0).
function _isOracleMbRollWire(wireHex) {
  try {
    const wb = hexToBytes(wireHex);
    if (wb.length < 4 || wb[0] !== 0x50 || wb[1] !== 0x53 || wb[2] !== 0x4b || wb[3] !== 0x42) return false;
    const arr = JSON.parse(new TextDecoder().decode(hexToBytes(new TextDecoder().decode(wb.slice(4)))));
    const pskt = Array.isArray(arr) ? arr[0] : arr;
    const prop = pskt && pskt.inputs && pskt.inputs[0] && pskt.inputs[0].proprietaries;
    return !!(prop && prop.risc0OracleMb === true);
  } catch (_) { return false; }
}

// Dedicated proving/broadcasting overlay for an Oracle-MB roll. The generic spinner reads like a hang
// across the ~1-2 min GPU prove; this gives the wait an intentional screen with the price being
// committed, an elapsed timer, and two real stages (Prove -> Broadcast) driven by the actual flow.
function showProvingScreen(priceRaw) {
  hideProvingScreen();
  if (!document.getElementById('mb-prove-style')) {
    const st = document.createElement('style');
    st.id = 'mb-prove-style';
    st.textContent = '@keyframes mbpv-ring{0%{transform:scale(.55);opacity:.85}70%{opacity:0}100%{transform:scale(1.7);opacity:0}}@keyframes mbpv-spin{to{transform:rotate(360deg)}}@keyframes mbpv-fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}#mb-prove .mbpv-step.done .mbpv-num{background:#2ee6a6;color:#04221a;border-color:#2ee6a6}#mb-prove .mbpv-step.active .mbpv-num{border-color:#2ee6a6;color:#2ee6a6;box-shadow:0 0 0 4px rgba(46,230,166,.16)}#mb-prove .mbpv-step.active,#mb-prove .mbpv-step.done{color:#e8fff7}';
    document.head.appendChild(st);
  }
  const price = Number(priceRaw) / 1e8;
  const priceStr = isFinite(price) && price > 0 ? ('$' + price.toFixed(8).replace(/0+$/, '').replace(/\.$/, '')) : '';
  const o = document.createElement('div');
  o.id = 'mb-prove';
  o.style.cssText = 'position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;background:radial-gradient(1100px 560px at 50% -8%,#0c2a22 0%,#070a09 58%);font-family:inherit;';
  o.innerHTML =
    '<div style="width:min(92vw,420px);text-align:center;color:#e8fff7;animation:mbpv-fade .4s ease both;">' +
      '<div style="position:relative;width:140px;height:140px;margin:0 auto 26px;">' +
        '<div style="position:absolute;inset:0;border-radius:50%;border:2px solid rgba(46,230,166,.4);animation:mbpv-ring 2.4s ease-out infinite;"></div>' +
        '<div style="position:absolute;inset:0;border-radius:50%;border:2px solid rgba(46,230,166,.4);animation:mbpv-ring 2.4s ease-out infinite 1.2s;"></div>' +
        '<div style="position:absolute;inset:26px;border-radius:50%;border:2px solid rgba(46,230,166,.14);border-top-color:#2ee6a6;animation:mbpv-spin 1.05s linear infinite;"></div>' +
        '<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:30px;">\u26a1</div>' +
      '</div>' +
      '<div style="font-size:22px;font-weight:700;letter-spacing:.2px;">Proving your price</div>' +
      (priceStr ? '<div style="margin:10px 0 2px;font-size:34px;font-weight:800;color:#2ee6a6;font-variant-numeric:tabular-nums;">' + priceStr + '</div>' : '') +
      '<div style="color:#9fc7ba;font-size:13px;line-height:1.55;margin:12px auto 0;max-width:300px;">Generating a zero-knowledge proof on a GPU, then broadcasting through your node. This usually takes a minute or two. Keep this tab open.</div>' +
      '<div id="mb-prove-timer" style="margin-top:18px;color:#6f9286;font-size:12px;font-variant-numeric:tabular-nums;">0:00 elapsed</div>' +
      '<div style="display:flex;gap:26px;justify-content:center;margin-top:22px;color:#7fa597;font-size:11px;">' +
        '<div class="mbpv-step active" data-step="1" style="display:flex;flex-direction:column;align-items:center;gap:7px;"><div class="mbpv-num" style="width:30px;height:30px;border-radius:50%;border:2px solid #2a4a40;display:flex;align-items:center;justify-content:center;font-weight:700;transition:.3s;">1</div>Prove</div>' +
        '<div class="mbpv-step" data-step="2" style="display:flex;flex-direction:column;align-items:center;gap:7px;"><div class="mbpv-num" style="width:30px;height:30px;border-radius:50%;border:2px solid #2a4a40;display:flex;align-items:center;justify-content:center;font-weight:700;transition:.3s;">2</div>Broadcast</div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(o);
  const t0 = Date.now();
  o._timer = setInterval(() => {
    const s = Math.floor((Date.now() - t0) / 1000);
    const tEl = document.getElementById('mb-prove-timer');
    if (tEl) tEl.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') + ' elapsed';
  }, 1000);
}
function setProvingStage(stage) {
  const o = document.getElementById('mb-prove'); if (!o) return;
  if (stage === 'broadcast') {
    const s1 = o.querySelector('.mbpv-step[data-step="1"]'), s2 = o.querySelector('.mbpv-step[data-step="2"]');
    if (s1) { s1.classList.remove('active'); s1.classList.add('done'); const n = s1.querySelector('.mbpv-num'); if (n) n.textContent = '\u2713'; }
    if (s2) s2.classList.add('active');
  }
}
function hideProvingScreen() {
  const o = document.getElementById('mb-prove'); if (!o) return;
  if (o._timer) clearInterval(o._timer);
  o.remove();
}

// Roll back a failed/superseded roll: drop the half-built signed tx and the roll context, then land
// the user back on the oracle card (Ask button + last price, which the card refreshes itself) instead
// of stranding them on the review screen behind a red banner. Used for terminal roll failures only;
// the transient "prover unreachable" path keeps the roll armed for a re-tap instead of calling this.
function oracleMbReturnToCard() {
  hideProvingScreen();
  _psktReviewHex = null;
  window._oracleMbRollActive = false;
  window._oracleMbRoll = null;
  try { showScreen('covenant'); covShowPanel('oracle-mb'); } catch (_) {}
}

async function handlePsktFinalize() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    if (!BROADCAST_ENABLED) {
        toast('Broadcast disabled in this version — testing only', 'error', 5000);
        return;
    }

    // Oracle-MB paid-roll gateway: the device signed a small sealless roll that pays the service
    // fee and commits to the quoted price/T. Hand it to the prover, which validates the fee + the
    // price binding, proves the accumulator, injects the ~445 KB seal, and finalizes + broadcasts
    // itself. KasSee never receives the seal, so the fee cannot be stripped and rebroadcast. This
    // returns here (the prover broadcasts); only non-oracle PSKBs fall through to the local path.
    if (_isOracleMbRollWire(_psktReviewHex)) {
        const roll = window._oracleMbRoll;
        if (!roll || !roll.acc) {
            toast('Roll context lost. Ask for a new price to rebuild it.', 'error', 8000);
            oracleMbReturnToCard();
            return;
        }
        const base = (ORACLE_MB.proverBase || '').replace(/\/+$/, '');
        showProvingScreen(roll.price);
        let resp, body = null;
        try {
            resp = await fetch(base + '/roll', {
                method: 'POST', headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ tx: _psktReviewHex, acc: roll.acc, price: roll.price, t: roll.t }),
                signal: AbortSignal.timeout(900000),   // 15 min: covers a RunPod cold start + prove + broadcast
            });
            try { body = await resp.json(); } catch (_) {}
        } catch (e) {
            hideProvingScreen();
            toast('Roll request failed: ' + (e && e.message ? e.message : e) + '. The roll was not sent.', 'error', 9000);
            return;   // keep the roll armed so a re-tap retries the /roll path, never a local sealless broadcast
        }
        if (resp.ok && body && body.txid) {
            hideProvingScreen();
            window._oracleMbRollActive = false; window._oracleMbRoll = null;
            window._lastBroadcastTime = Date.now();
            const txId = String(body.txid);
            _psktReviewHex = null;
            _broadcastReturnScreen = 'covenant'; window._oracleMbReturn = true;   // Done/Back re-opens a LIVE oracle card (restarts age/poll/watcher), not the donate screen
            showScreen('broadcast');
            showBroadcastSuccess(txId);
            return;
        }
        if (resp.ok && body && body.sealed) {
            // TN10 mode: the prover proved and injected the seal but did not broadcast, because the
            // oracle chain lives on our node, not on the public node the prover can reach. Broadcast the
            // sealed roll through our own node (withNodeRetry tries the custom/local node first), which
            // has the inputs; the seal is now in input[0], so the node accepts it.
            setProvingStage('broadcast');
            let txId;
            try { txId = await withNodeRetry(wsUrl => pskt_finalize_and_broadcast(body.sealed, wsUrl)); }
            catch (e) {
                const m = String(e && e.message ? e.message : e);
                console.warn('[oracle-mb] sealed broadcast failed:', m);
                const moved = /already spent|orphan|already.*mempool/i.test(m);
                toast(moved
                    ? 'This roll could not land: the oracle already moved on-chain. Showing the latest price.'
                    : 'Roll could not be broadcast (the oracle may have moved, or your node was unreachable). Showing the latest price.',
                    'error', 9000);
                oracleMbReturnToCard(); return;
            }
            hideProvingScreen();
            window._oracleMbRollActive = false; window._oracleMbRoll = null;
            window._lastBroadcastTime = Date.now();
            _psktReviewHex = null;
            _broadcastReturnScreen = 'covenant'; window._oracleMbReturn = true;   // Done/Back re-opens a LIVE oracle card (restarts age/poll/watcher), not the donate screen
            showScreen('broadcast');
            showBroadcastSuccess(String(txId));
            return;
        }
        hideProvingScreen();
        if (body && body.status === 'lost_race') {
            toast('Another roll landed first. The oracle is already fresh.', 'info', 9000);
            oracleMbReturnToCard();
            return;
        }
        toast('Roll rejected: ' + ((body && (body.error || body.reason)) || ('HTTP ' + resp.status)), 'error', 10000);
        oracleMbReturnToCard();
        return;
    }

    console.log('[KasSee] PSKT-native finalize + broadcast — PSKB hex length:', _psktReviewHex.length);

    // DEBUG: dump exactly what we submit, per output, with its classification.
    // toc3 standardness accepts only p2pk / p2pk-ecdsa / p2sh; anything else is
    // rejected as "non-standard script form". This shows which output and the
    // exact SPK bytes that triggered it.
    try {
        const _dbg = JSON.parse(pskt_summary(_psktReviewHex, network));
        (_dbg.outputs || []).forEach((o, i) => {
            const sh = o.script_hex || o.scriptHex || '';
            console.log('[KasSee] OUT#' + i +
                        ' kind=' + (o.script_kind || o.scriptKind) +
                        ' spk_len=' + (sh.length / 2) + 'B' +
                        ' spk=' + sh.slice(0, 24) + '…' + sh.slice(-12));
        });
        console.log('[KasSee] full outputs JSON:', JSON.stringify(_dbg.outputs));
    } catch (_e) { console.log('[KasSee] pre-broadcast dump failed:', _e); }

    showLoading('Broadcasting...');
    try {
        const txId = await withNodeRetry(
            wsUrl => pskt_finalize_and_broadcast(_psktReviewHex, wsUrl)
        );
        console.log('[KasSee] Node accepted (PSKT path). TX ID:', txId);
        window._lastBroadcastTime = Date.now();
        // The covenant UTXO is spent from this moment, but it leaves the
        // node's UTXO index only when the transaction lands in a block, so
        // the watcher poll keeps reading the old balance for a few seconds
        // and the card went on offering "claimable" on funds already gone.
        // Cleared by the poll once the balance drops (which is what shows
        // "Claimed"), and when the watcher restarts on another covenant.
        if (_broadcastReturnScreen === 'covenant') {
            _covSpendBroadcastTx = txId || 'pending';
        }
        hideLoading();
        _psktReviewHex = null;

        // Crowdfund: store funding TXID as campaign ID for invite QR
        if (lastCovenantResult && lastCovenantResult.type === 'crowdfund' && txId) {
            lastCovenantResult.campaign_txid = txId;
            try { sessionStorage.setItem('lastCovenantResult', JSON.stringify(lastCovenantResult)); } catch (_) {}
            console.log('[KasSee] Crowdfund campaign TXID stored:', txId);
        }

        // Zero sensitive swap data after broadcast
        const claimPreimageVal = el('cov-claim-preimage') ? el('cov-claim-preimage').value.trim() : '';
        const hasPreimage = window._extractedPreimage || claimPreimageVal;
        if (hasPreimage && lastCovenantResult && lastCovenantResult.type === 'atomic-swap') {
            window._swapClaimBroadcasted = true;
            window._extractedPreimage = '';
            window._extractedPreimageHex = '';
            window._lastClaimPreimage = '';
            window._preimageFromChain = false;
            // Clear preimage from DOM fields
            if (el('cov-claim-preimage')) el('cov-claim-preimage').value = '';
            if (el('cov-swap-preimage')) el('cov-swap-preimage').value = '';
            // Update sessionStorage without preimage
            try {
                const raw = sessionStorage.getItem('kassee_swap_state');
                if (raw) {
                    const state = JSON.parse(raw);
                    if (state.preimage) { state.preimage = ''; sessionStorage.setItem('kassee_swap_state', JSON.stringify(state)); }
                }
            } catch (_) {}
        }
        showScreen('broadcast');
        showBroadcastSuccess(txId);
    } catch (e) {
        hideLoading();
        showBroadcastError(e);
        const _msg = (e && e.message) ? e.message : String(e);
        console.error('[KasSee] Broadcast failed (full):', _msg);
    }
}

function fmtKas(sompi) {
    const n = Number(sompi) / 1e8;
    if (n === 0) return '0';
    if (Math.abs(n) < 0.00000001) return n.toExponential(2);
    return n.toFixed(8).replace(/\.?0+$/, '');
}

// Covenant id in the SAME shape the signer draws it: first 6 and last 6 bytes.
// The two screens exist to be compared, so they must not format it differently.
function covIdShort(hex) {
    if (typeof hex !== 'string' || hex.length !== 64) return hex;
    return hex.slice(0, 12) + '\u2026' + hex.slice(-12);
}

function shortenHex(hex) {
    if (!hex || hex.length <= 20) return hex;
    return hex.slice(0, 10) + '\u2026' + hex.slice(-10);
}

// ─── Multisig Spend ───

function handleDescriptorScan(data) {
    // Descriptor comes as multi-frame binary (same protocol as KSPT)
    const hexStr = Array.from(new Uint8Array(data))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    try {
        const result = decode_qr_frame(hexStr);
        if (result && result.length > 0) {
            stopScanner();
            // Convert hex back to ASCII text
            const bytes = [];
            for (let i = 0; i < result.length; i += 2) {
                bytes.push(parseInt(result.substr(i, 2), 16));
            }
            const text = new TextDecoder().decode(new Uint8Array(bytes)).trim();
            // `multi_hd45(` starts with `multi_hd` but NOT with `multi_hd(`,
            // so the two-prefix test rejected every 45' descriptor.
            if (text.startsWith('multi(') || text.startsWith('multi_hd(')
                || text.startsWith('multi_hd45(')) {
                el('input-ms-descriptor').value = text;
                showScreen('multisig');
                toast('Descriptor scanned', 'ok', 1500);
            } else {
                toast('Not a valid descriptor', 'error');
            }
        } else {
            const prog = JSON.parse(decoder_progress());
            if (prog.total > 0) {
                let dots = '';
                for (let i = 0; i < prog.total; i++) {
                    dots += '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:' + (prog.bits[i] ? 'var(--teal)' : 'var(--border)') + ';' + (prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : '') + '"></span>';
                }
                el('scanner-status').innerHTML = dots + '<div style="margin-top:6px;font-size:12px">' + prog.count + ' / ' + prog.total + ' frames</div>';
            }
        }
    } catch (e) {
        console.error('Descriptor decode error:', e);
    }
}

/// Fill the "Select UTXOs manually" dropdown from the whole branch.
///
/// Same panel, same rows, same 32 cap as the single-address version - only the
/// source of the list differs, and each row carries its address so the builder
/// can derive that address's own redeem script.
function fillMsBranchUtxoList() {
    const list = el('ms-utxo-list');
    if (!list.classList.contains('hidden')) {
        list.classList.add('hidden');
        el('btn-toggle-ms-utxos').textContent = 'Select UTXOs manually \u25b8';
        msPicked = [];
        return;
    }
    const utxos = (msBranch.utxos || []).slice()
        .sort((a, b) => Number(b.amount) - Number(a.amount));
    if (utxos.length === 0) { toast('No UTXOs on this branch', 'error'); return; }

    let html = '';
    utxos.forEach((u, i) => {
        const kas = (Number(u.amount) / 1e8).toFixed(8);
        html += `<div class="utxo-item" data-idx="${i}" style="cursor:pointer;display:flex;align-items:center;gap:10px">
            <span style="font-size:18px;color:var(--border)" class="utxo-check">\u2610</span>
            <div style="flex:1">
                <div class="utxo-amount" style="font-size:13px">${kas} KAS</div>
                <div class="utxo-detail">C${u.chain} #${u.index} \u00b7 ${u.tx_id.slice(0, 16)}\u2026:${u.outpoint_index}</div>
            </div>
        </div>`;
    });
    list.innerHTML = html;
    msPicked = [];

    const sync = () => {
        const total = msPicked.reduce((a, p) => a + Number(p.amount), 0);
        const addrs = new Set(msPicked.map(p => p.address));
        el('btn-toggle-ms-utxos').textContent = msPicked.length
            ? `${msPicked.length} input(s) \u00b7 ${(total / 1e8).toFixed(8)} KAS \u00b7 `
              + `${addrs.size} address(es)`
              + (addrs.size > 1 ? ' \u2014 will be linked on chain' : '') + ' \u25b8'
            : 'Select UTXOs manually \u25b8';
    };

    list.querySelectorAll('.utxo-item').forEach(item => {
        item.onclick = () => {
            const u = utxos[parseInt(item.dataset.idx)];
            const check = item.querySelector('.utxo-check');
            const pos = msPicked.findIndex(p =>
                p.tx_id === u.tx_id && p.index === u.outpoint_index);
            if (pos >= 0) {
                msPicked.splice(pos, 1);
                check.textContent = '\u2610';
                check.style.color = 'var(--border)';
                item.style.borderColor = '';
            } else if (msPicked.length >= MS_PICK_MAX) {
                toast('Max ' + MS_PICK_MAX + ' UTXOs per transaction', 'info', 1500);
                return;
            } else {
                msPicked.push({ address: u.address, tx_id: u.tx_id,
                                index: u.outpoint_index, amount: u.amount });
                check.textContent = '\u2611';
                check.style.color = 'var(--teal)';
                item.style.borderColor = 'var(--teal)';
            }
            sync();
        };
    });
    sync();
    list.classList.remove('hidden');
}

async function toggleMsUtxos() {
    // 45' with a branch loaded: the SAME dropdown, filled from the whole branch.
    //
    // The single-address path below needs a source address and fetches only that
    // address's UTXOs, which is the limit being removed. This fills the same
    // `ms-utxo-list` panel with every outpoint on the branch instead, so the
    // control behaves exactly as it does in a single-sig wallet.
    if (msIs45Loaded()) { fillMsBranchUtxoList(); return; }
    const list = el('ms-utxo-list');
    if (!list.classList.contains('hidden')) {
        list.classList.add('hidden');
        el('btn-toggle-ms-utxos').textContent = 'Select UTXOs manually ▸';
        msSelectedUtxoIndices = null;
        return;
    }
    const sourceAddr = el('input-ms-source').value.trim();
    if (!sourceAddr) { toast('Enter source address first', 'error'); return; }

    // Fetch UTXOs for the multisig address
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(sourceAddr, wsUrl);
        msCachedUtxos = JSON.parse(utxosJson);
        msCachedUtxos.sort((a, b) => b.amount - a.amount
            || a.tx_id.localeCompare(b.tx_id)
            || a.index - b.index);
    } catch (e) {
        toast('UTXO fetch failed: ' + e, 'error');
        return;
    }

    if (!msCachedUtxos || msCachedUtxos.length === 0) {
        toast('No UTXOs for this address', 'error');
        return;
    }

    el('btn-toggle-ms-utxos').textContent = 'Select UTXOs manually ▾';
    let html = '';
    msCachedUtxos.forEach((u, i) => {
        const kas = (u.amount / 1e8).toFixed(8);
        html += `<div class="utxo-item" data-idx="${i}" style="cursor:pointer;display:flex;align-items:center;gap:10px">
            <span style="font-size:18px;color:var(--border)" class="utxo-check">☐</span>
            <div style="flex:1">
                <div class="utxo-amount" style="font-size:13px">${kas} KAS</div>
                <div class="utxo-detail">${u.tx_id.slice(0, 16)}…:${u.index}</div>
            </div>
        </div>`;
    });
    list.innerHTML = html;
    msSelectedUtxoIndices = [];

    list.querySelectorAll('.utxo-item').forEach(item => {
        item.onclick = () => {
            const idx = parseInt(item.dataset.idx);
            const check = item.querySelector('.utxo-check');
            const pos = msSelectedUtxoIndices.indexOf(idx);
            if (pos >= 0) {
                msSelectedUtxoIndices.splice(pos, 1);
                check.textContent = '☐';
                check.style.color = 'var(--border)';
                item.style.borderColor = '';
            } else if (msSelectedUtxoIndices.length >= 32) {
                toast('Max 32 UTXOs per transaction', 'info', 1500);
                return;
            } else {
                msSelectedUtxoIndices.push(idx);
                check.textContent = '☑';
                check.style.color = 'var(--teal)';
                item.style.borderColor = 'var(--teal)';
            }
        };
    });
    list.classList.remove('hidden');
}

async function handleMultisigCreate() {
    const descriptor = el('input-ms-descriptor').value.trim();
    const sourceAddr = el('input-ms-source').value.trim();
    const destAddr = el('input-ms-dest').value.trim();
    const amountStr = el('input-ms-amount').value.trim();

    if (!descriptor) { toast('Paste the multisig descriptor', 'error'); return; }
    // A selection carries its own addresses, so no source field is involved.
    if (!sourceAddr && !(msIs45Loaded() && msPicked.length > 0)) {
        toast(msIs45Loaded()
            ? 'Select UTXOs to spend'
            : 'Enter the P2SH source address', 'error');
        return;
    }
    if (!destAddr) { toast('Enter the destination address', 'error'); return; }
    if (!amountStr || parseFloat(amountStr) <= 0) { toast('Enter amount', 'error'); return; }

    let resolvedDest = destAddr;
    if (destAddr.endsWith('.kas')) {
        const kns = KNS_LOOKUP[destAddr.toLowerCase()];
        if (kns) {
            resolvedDest = kns;
            toast('Resolved ' + destAddr + ' → address', 'ok', 2000);
        } else {
            toast('Unknown .kas domain', 'error'); return;
        }
    }

    const changeAddr = sourceAddr;

    showLoading('Building multisig PSKB...');
    try {
        // Fee must cover sig_op_count = N per input, and the count of inputs the
        // builder will actually spend.
        //
        // When the user has picked UTXOs we know both exactly. When they have
        // not, `create_multisig_pskb` chooses for us and JS never learns the
        // number, so we deliberately ERR HIGH and use the cached UTXO count:
        // underpaying bounces a transaction the user has already signed on the
        // device and carried back, while overpaying costs sompi on a fee that
        // starts at 0.004 KAS. Wrong in the cheap direction on purpose.
        const nCosigners = msCosignerCount(descriptor);
        if (nCosigners === 0) {
            hideLoading();
            toast('Cannot read cosigner count from descriptor', 'error', 5000);
            return;
        }
        // A 45' selection is the real input count. Pricing it as one input is the
        // mistake this whole estimator was written to stop: it does not bounce
        // the transaction, it underpays and gets refused at relay AFTER the
        // devices have signed it.
        const nInputs = (msIs45Loaded() && msPicked.length > 0)
            ? msPicked.length
            : ((msSelectedUtxoIndices && msSelectedUtxoIndices.length > 0)
                ? msSelectedUtxoIndices.length
                : ((msCachedUtxos && msCachedUtxos.length > 0) ? msCachedUtxos.length : 1));
        const fee = getCovFee(nInputs, nCosigners);
        const wsUrl = await resolveNodeUrl();
        const addrIndexEl = el('input-ms-addr-index');
        const addrIndex = addrIndexEl ? parseInt(addrIndexEl.value) || 0 : 0;

        // Change index comes from the HISTORY scan when a branch is loaded.
        //
        // The builder's own scan sees UTXOs only, so a spent-empty address looks
        // free and change would return to an index already used. 0xFFFFFFFF means
        // "no hint" and keeps the old behaviour for 44', which has no change
        // chain anyway.
        const chgHint = (msBranch && msBranch.next_change_index != null)
            ? msBranch.next_change_index : 0xFFFFFFFF;

        let pskbHex;
        if (msIs45Loaded() && msPicked.length > 0) {
            // MULTI-ADDRESS path: the selection carries its own addresses, so
            // each input gets its own redeem script and derivation path.
            pskbHex = await create_multisig_pskb_multi_js(
                descriptor, JSON.stringify(msPicked.map(p =>
                    ({ address: p.address, tx_id: p.tx_id, index: p.index }))),
                resolvedDest, kasToSompi(amountStr), BigInt(fee),
                msBranch.cosigner, chgHint, wsUrl
            );
        } else if (msSelectedUtxoIndices && msSelectedUtxoIndices.length > 0) {
            const csv = msSelectedUtxoIndices.join(',');
            pskbHex = await create_multisig_pskb_selected(
                descriptor, sourceAddr, resolvedDest, kasToSompi(amountStr),
                BigInt(fee), changeAddr, wsUrl, chgHint, addrIndex, csv
            );
        } else {
            pskbHex = await create_multisig_pskb(
                descriptor, sourceAddr, resolvedDest, kasToSompi(amountStr),
                BigInt(fee), changeAddr, wsUrl, chgHint, addrIndex
            );
        }
        hideLoading();
        console.log('[KasSee] Multisig PSKB created: ' + pskbHex.length / 2 + ' bytes');
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Multisig TX failed: ' + e, 'error', 5000);
        console.error('Multisig TX error:', e);
    }
}

/// MAX for a 45' selection: the selected total minus the fee for those inputs.
///
/// The single-address MAX fetches a source address's UTXOs and prices them.
/// Here the inputs are already chosen, so the fee is sized from the actual count
/// and the cosigner count - getting that wrong does not bounce the transaction,
/// it quotes a MAX that fails at relay after the user has signed it.
function msMaxFromSelection() {
    const nCosigners = msCosignerCount(msBranch.descriptor);
    if (nCosigners === 0) {
        toast('Could not read the cosigner count from the descriptor', 'error', 4000);
        return;
    }
    const total = msPicked.reduce((a, p) => a + BigInt(p.amount), 0n);
    const fee = getCovFee(msPicked.length, nCosigners);
    if (total <= fee) {
        toast('Selection does not cover the fee (' + sompiToKasStr(fee) + ' KAS)',
              'error', 4000);
        return;
    }
    el('input-ms-amount').value = sompiToKasStr(total - fee);
    toast('Max: ' + sompiToKasStr(total - fee) + ' KAS after '
          + sompiToKasStr(fee) + ' fee', 'info', 2500);
}

async function handleMsMax() {
    const sourceAddr = el('input-ms-source').value.trim();
    // 45' with a selection: MAX is the selected total minus the fee for exactly
    // those inputs. There is no source address to fetch from, and asking for one
    // is the limit being removed.
    if (msIs45Loaded() && msPicked.length > 0) { msMaxFromSelection(); return; }
    if (!sourceAddr) {
        toast(msIs45Loaded()
            ? 'Select UTXOs first'
            : 'Enter source address first', 'error');
        return;
    }

    // Same correction as handleMultisigCreate: N sigops per input, real input
    // count. Getting this wrong here does not bounce a transaction, it quotes
    // the user a MAX they cannot actually send, which they then discover at
    // relay after signing.
    const descriptorEl = el('input-ms-descriptor');
    const nCosigners = msCosignerCount(descriptorEl ? descriptorEl.value : '');
    if (nCosigners === 0) {
        toast('Paste the descriptor first, so the fee can be sized', 'error', 4000);
        return;
    }

    // If UTXOs are manually selected, use those
    if (msSelectedUtxoIndices && msSelectedUtxoIndices.length > 0 && msCachedUtxos) {
        const fee = getCovFee(msSelectedUtxoIndices.length, nCosigners);
        const selectedTotal = msSelectedUtxoIndices.reduce((s, i) => s + BigInt(msCachedUtxos[i].amount), 0n);
        el('input-ms-amount').value = sompiToKasStr(selectedTotal > fee ? selectedTotal - fee : 0n);
        return;
    }

    showLoading('Fetching balance...');
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(sourceAddr, wsUrl);
        hideLoading();
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        // This branch spends EVERY UTXO, so the input count is exact here; no
        // estimate needed, unlike the create path.
        const fee = getCovFee(utxos.length, nCosigners);
        el('input-ms-amount').value = sompiToKasStr(total > fee ? total - fee : 0n);
        el('ms-balance-info').textContent = 'Balance: ' + (Number(total) / 100000000).toFixed(8) + ' KAS (' + utxos.length + ' UTXOs)';
    } catch (e) {
        hideLoading();
        toast('Balance fetch failed: ' + e, 'error');
    }
}

// ─── Covenant++ ───

// ─── Covenant scan helpers ───
// Signers show kaspa: addresses. These helpers accept any kaspa*/kaspatest* address,
// extract the x-only pubkey, and either fill a hex field or re-encode as kaspatest: address.

// Normalize a party-key field that may hold a kaspa/kaspatest address (from a
// scan) or a raw 64-char x-only hex (typed by hand). Returns the x-only hex, or
// '' if an address cannot be decoded (so the caller's length check fires). A
// raw hex or any non-address value passes through untouched.
function addrToXOnly(v) {
    v = (v || '').trim();
    if (v.startsWith('kaspa:') || v.startsWith('kaspatest:')) {
        try {
            const d = JSON.parse(decode_address(v));
            if (d.payload && d.payload.length === 64) return d.payload;
        } catch (e) {}
        return '';
    }
    return v;
}

function covScanPubkey(fieldId, label, rejectKpub) {
    startScanner(label || 'Scan address or kpub for pubkey', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data)).trim();
        // Resolve the QR to an x-only pubkey, then DISPLAY it as a network
        // address so the user can eyeball-match it against the address shown on
        // their KasSigner before generating. The create handlers decode the
        // address back to the x-only, and still accept a manually typed hex.
        // The oracle role is special: its pubkey is the ACCOUNT-LEVEL key (it must
        // match the KasSigner SIGN HASH attestation behind CHECKSIGFROMSTACK), so it
        // can only come from a kpub. Every x-only form — a /0/0 address or a raw
        // 32-byte hex — is the RECEIVE key and would bake a /0/0 oracle_pk that can
        // never satisfy the attestation. So the oracle field takes a kpub ONLY and
        // stores it raw (the create handler derives the account-level key from it,
        // and the visible kpub is the out-of-band anchor to match on KasSigner).
        const isOracleField = (fieldId === 'cov-oracle-pk');
        const finish = (xonly, note) => {
            stopScanner();
            try {
                el(fieldId).value = encode_p2pk_address(xonly, network);
            } catch (e) {
                el(fieldId).value = xonly;
            }
            showScreen('covenant');
            toast(note || 'Address scanned. Verify it matches KasSigner.', 'ok', 1800);
        };
        if (text.startsWith('kaspa')) {
            if (isOracleField) {
                stopScanner(); showScreen('covenant');
                toast('Oracle needs its KPUB (account-level), not a /0/0 address', 'error', 3500);
                return;
            }
            try {
                const decoded = JSON.parse(decode_address(text));
                if (decoded.payload && decoded.payload.length === 64) {
                    finish(decoded.payload, 'Address scanned. Verify it matches KasSigner.');
                } else {
                    stopScanner(); showScreen('covenant'); toast('Could not extract pubkey', 'error');
                }
            } catch (e) {
                stopScanner(); showScreen('covenant'); toast('Invalid address: ' + e, 'error');
            }
        } else if (text.startsWith('kpub') || text.startsWith('ktub')) {
            if (rejectKpub) {
                stopScanner(); showScreen('covenant');
                toast('Scan a single address or x-only, not a kpub', 'error');
                return;
            }
            try {
                if (isOracleField) {
                    // Account-level oracle key: validate the kpub parses, then store
                    // it RAW so it stays matchable against KasSigner's kpub. The
                    // create handler calls parse_kpub() for the account-level x-only.
                    JSON.parse(parse_kpub(text));
                    stopScanner();
                    el(fieldId).value = text;
                    showScreen('covenant');
                    toast('Oracle kpub scanned (account-level). Verify it matches KasSigner.', 'ok', 2200);
                } else {
                    const importResult = JSON.parse(import_kpub(text, network));
                    const firstAddr = importResult.receive_addresses[0];
                    const decoded = JSON.parse(decode_address(firstAddr));
                    if (decoded.payload && decoded.payload.length === 64) {
                        finish(decoded.payload, 'Address from kpub (/0/0). Verify it matches KasSigner.');
                    } else {
                        stopScanner(); showScreen('covenant'); toast('Could not derive pubkey from kpub', 'error');
                    }
                }
            } catch (e) {
                stopScanner(); showScreen('covenant'); toast('Invalid kpub: ' + e, 'error');
            }
        } else if (/^[0-9a-fA-F]{64}$/.test(text)) {
            if (isOracleField) {
                stopScanner(); showScreen('covenant');
                toast('Oracle needs its KPUB (account-level), not a raw x-only key', 'error', 3500);
                return;
            }
            // Raw x-only pubkey hex QR: show its address for verification.
            finish(text, 'Address scanned. Verify it matches KasSigner.');
        }
    });
}

function covScanAddress(fieldId, label, rejectKpub) {
    startScanner(label || 'Scan address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (rejectKpub && (addr.startsWith('kpub') || addr.startsWith('ktub'))) {
            stopScanner(); showScreen('covenant');
            toast('Scan an address, not a kpub', 'error');
            return;
        }
        if (addr.startsWith('kaspa')) {
            stopScanner();
            try {
                const decoded = JSON.parse(decode_address(addr));
                if (decoded.payload && decoded.payload.length === 64) {
                    // Re-encode as kaspatest address
                    const testAddr = encode_p2pk_address(decoded.payload, network);
                    el(fieldId).value = testAddr;
                    showScreen('covenant');
                    toast('Address scanned', 'ok', 1500);
                } else {
                    showScreen('covenant');
                    toast('Could not decode address', 'error');
                }
            } catch (e) {
                // Maybe it's already the right network — try direct
                el(fieldId).value = addr;
                showScreen('covenant');
                toast('Address pasted directly', 'ok', 1500);
            }
        }
    });
}

// Scan an address and APPEND it to a whitelist textarea (one address per line),
// de-duplicating. Used by the Merkle whitelist creation flow to build the list by
// camera instead of typing. Mirrors covScanAddress's decode/re-encode handling.
function covScanAddressAppend(textareaId, label) {
    startScanner(label || 'Scan address', (data) => {
        const addr = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (!addr.startsWith('kaspa')) {
            stopScanner(); showScreen('covenant');
            toast('Scan a kaspa address', 'error');
            return;
        }
        stopScanner();
        let toAdd = addr;
        try {
            const decoded = JSON.parse(decode_address(addr));
            if (decoded.payload && decoded.payload.length === 64) {
                toAdd = encode_p2pk_address(decoded.payload, network);
            } else {
                showScreen('covenant');
                toast('Could not decode address', 'error');
                return;
            }
        } catch (e) {
            // Already the right network — use as-is
            toAdd = addr;
        }
        const ta = el(textareaId);
        const lines = (ta.value || '').split('\n').map(s => s.trim()).filter(Boolean);
        if (lines.includes(toAdd)) {
            showScreen('covenant');
            toast('Address already in list', 'ok', 1500);
            return;
        }
        lines.push(toAdd);
        ta.value = lines.join('\n');
        showScreen('covenant');
        toast('Address added (' + lines.length + ' total)', 'ok', 1500);
    });
}

function covReturnAfterBroadcast() {
    if (window._oracleMbReturn) { window._oracleMbReturn = false; covShowPanel('oracle-mb'); return; }   // oracle roll: re-open a LIVE card; covShowPanel -> oracleMbCardOpen restarts the 1s age tick, the 12s poll, and the block watcher
    if (lastCovenantResult) {
        // Store the broadcast txid as the UTXO outpoint (for preimage extraction later)
        const broadcastTxid = el('broadcast-result-txid') ? el('broadcast-result-txid').textContent.trim() : '';
        if (broadcastTxid && broadcastTxid.length === 64 && lastCovenantResult.type === 'atomic-swap' && !_swapUtxoOutpoint) {
            // Only store outpoint if we don't already have one (first funding, not claim)
            _swapUtxoOutpoint = { txid: broadcastTxid, index: 0 };
            console.log('[KasSee] Stored funding outpoint from broadcast:', broadcastTxid);
            swapStateSave();
        }
        // Generic covenant watcher: store outpoint for BlockAdded spend detection
        if (broadcastTxid && broadcastTxid.length === 64 && !_covWatcherOutpoint && covWatcherTypes().includes(lastCovenantResult.type)) {
            _covWatcherOutpoint = { txid: broadcastTxid, index: 0 };
            console.log('[KasSee] Stored covenant outpoint from broadcast:', broadcastTxid);
        }
        // For adaptor-swap, go back to adaptor-result panel instead of generic result
        if (lastCovenantResult.type === 'adaptor-swap' && _adaptorState) {
            covShowPanel('adaptor-result');
        } else {
            covShowPanel('result');
            covUpdateResultButtons(lastCovenantResult.type || '');
            // Repopulate the result panel fields. Otherwise this leaves them
            // stale/empty (briefly shows "0 KAS, not funded" if the user
            // landed here right after broadcast). Mirrors what the
            // active-list click handler does when loading a covenant.
            const c = lastCovenantResult;
            ensureAllowanceParams(c);
            if (el('cov-result-addr')) el('cov-result-addr').textContent = c.address || '';
            if (el('cov-result-script')) el('cov-result-script').textContent = c.redeem_script_hex || '';
            if (el('cov-result-txid') && broadcastTxid && broadcastTxid.length === 64) {
                el('cov-result-txid').textContent = broadcastTxid;
                el('cov-result-txid').onclick = () => { navigator.clipboard.writeText(broadcastTxid); toast('TX ID copied', 'ok'); };
                if (el('cov-result-txid-wrap')) el('cov-result-txid-wrap').style.display = '';
            }
            if (el('cov-result-extra')) {
                covRenderMetaLine(c);
            }
            if (el('cov-result-balance')) {
                el('cov-result-balance').textContent = 'Loading...';
                el('cov-result-balance').style.display = '';
            }
        }
        setTimeout(() => { if (el('btn-cov-res-balance')) el('btn-cov-res-balance').click(); }, 500);
        // Restart watcher to pick up new UTXO state after broadcast
        covWatcherStop();
        _covWatcherOutpoint = null;
        covWatcherStart();
    } else {
        covShowPanel('menu');
    }
}

// ─── Atomic Swap Claim Watcher ───
// Polls Bob's HTLC balance. When it drops to zero (Alice claimed),
// auto-fills the claim panel with counterparty data and notifies Bob.

function swapWatcherStart() {
    if (_swapWatcherTimer) return; // already running
    if (!lastCovenantResult || lastCovenantResult.type !== 'atomic-swap') return;
    if (!_swapCounterpartyInvite) {
        const st = el('cov-watcher-status');
        if (st) { st.textContent = '⏸ Watcher off (scan counterparty invite first)'; st.style.display = ''; }
        return;
    }
    console.log('[KasSee] Swap watcher started for', lastCovenantResult.address);
    const st = el('cov-watcher-status');
    if (st) { st.textContent = '👁 Watching for counterparty claim...'; st.style.display = ''; }
    _swapWatcherTimer = setInterval(() => swapWatcherPoll(), 2000);
    swapWatcherPoll();
    swapSubscriptionStart();
}

function swapWatcherStop() {
    if (_swapWatcherTimer) {
        clearInterval(_swapWatcherTimer);
        _swapWatcherTimer = null;
        console.log('[KasSee] Swap watcher stopped');
    }
    swapSubscriptionStop();
    const st = el('cov-watcher-status');
    if (st) st.style.display = 'none';
}

// ─── UTXO Subscription for instant claim detection ───

async function swapSubscriptionStart() {
    swapSubscriptionStop();
    if (!lastCovenantResult || !lastCovenantResult.address) return;

    try {
        const wsUrl = await resolveNodeUrl();
        const blockAddedReq = new Uint8Array(build_vcc_subscribe_request(43n)); // BlockAdded scope

        const ws = new WebSocket(wsUrl);
        ws.binaryType = 'arraybuffer';
        _swapSubscriptionWs = ws;

        ws.onopen = () => { ws.send(blockAddedReq); };

        ws.onmessage = (evt) => {
            const data = new Uint8Array(evt.data);
            if (data.length < 4) return;
            let pos = (data[0] === 0x01) ? 9 : 1;
            if (pos >= data.length || data[pos] !== 0xFF) return;
            const notifOp = data[pos + 2];

            // Op 0x3C: BlockAddedNotification
            if (notifOp !== 0x3C || !_swapUtxoOutpoint || !_swapUtxoOutpoint.txid) return;

            const txidHex = _swapUtxoOutpoint.txid;
            const txidBytes = new Uint8Array(32);
            for (let j = 0; j < 32; j++) txidBytes[j] = parseInt(txidHex.substr(j * 2, 2), 16);

            for (let k = 4; k < data.length - 40; k++) {
                if (data[k] !== 37 || data[k+1] !== 0 || data[k+2] !== 0 || data[k+3] !== 0) continue;
                if (data[k+4] !== 0x01) continue;
                let match = true;
                for (let j = 0; j < 32; j++) { if (data[k+5+j] !== txidBytes[j]) { match = false; break; } }
                if (!match) continue;

                const afterOutpoint = k + 5 + 32 + 4;
                if (afterOutpoint + 4 > data.length) continue;
                const sigLen = data[afterOutpoint] | (data[afterOutpoint+1] << 8) | (data[afterOutpoint+2] << 16) | (data[afterOutpoint+3] << 24);
                if (sigLen < 10 || sigLen > 1000) continue;
                const sigStart = afterOutpoint + 4;
                if (sigStart + sigLen > data.length) continue;

                const firstByte = data[sigStart];
                let pStart, pLen;
                if (firstByte >= 1 && firstByte <= 0x4b) { pStart = sigStart + 1; pLen = firstByte; }
                else if (firstByte === 0x4c) { pStart = sigStart + 2; pLen = data[sigStart + 1]; }
                else continue;
                if (pStart + pLen > data.length || pLen === 0 || pLen > 200) continue;

                const preimageBytes = data.slice(pStart, pStart + pLen);
                const preimageHex = Array.from(preimageBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                let preimageText;
                try { preimageText = new TextDecoder().decode(preimageBytes); } catch (_) { preimageText = preimageHex; }

                console.log('[KasSee] PREIMAGE FOUND: ' + preimageText);
                window._extractedPreimage = preimageText;
                window._extractedPreimageHex = preimageHex;
                window._preimageFromChain = true;
                swapStateSave();
                toast('Preimage auto-extracted: ' + preimageText, 'ok', 10000);
                swapSubscriptionStop();
                break;
            }
        };

        ws.onerror = () => {};
        ws.onclose = () => {
            // Only act if this is still the active subscription WS
            if (_swapSubscriptionWs === ws) {
                _swapSubscriptionWs = null;
                if (_swapWatcherTimer && lastCovenantResult && lastCovenantResult.type === 'atomic-swap') {
                    setTimeout(() => swapSubscriptionStart(), 3000);
                }
            }
        };
    } catch (e) {
        console.warn('[KasSee] Swap subscription failed:', e);
        if (_swapWatcherTimer) setTimeout(() => swapSubscriptionStart(), 5000);
    }
}

function swapSubscriptionStop() {
    if (_swapSubscriptionWs) {
        try { _swapSubscriptionWs.close(); } catch (_) {}
        _swapSubscriptionWs = null;
        console.log('[KasSee] Swap subscription: stopped');
    }
}

async function swapWatcherPoll() {
    if (!lastCovenantResult || lastCovenantResult.type !== 'atomic-swap') { swapWatcherStop(); return; }
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(lastCovenantResult.address, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        const kas = Number(total) / 1e8;

        const st = el('cov-watcher-status');
        if (st && _swapWatcherTimer) {
            // Check if HTLC has expired
            const currentDaa = await fetchCurrentDaa();
            const myLocktime = lastCovenantResult.locktime_daa ? Number(lastCovenantResult.locktime_daa) : 0;
            const theirLocktime = _swapCounterpartyInvite && _swapCounterpartyInvite.d ? Number(_swapCounterpartyInvite.d) : 0;

            if (myLocktime > 0 && currentDaa >= myLocktime && total > 0n) {
                // My HTLC expired, I can refund
                st.textContent = '\u26a0 HTLC expired. Use Owner Refund to reclaim funds.';
                st.style.color = 'var(--warning)';
                swapWatcherStop();
                return;
            } else if (theirLocktime > 0 && currentDaa >= theirLocktime) {
                // Counterparty's HTLC expired, they can refund. Urgency.
                st.textContent = '\u26a0 Counterparty timeout passed! Claim NOW or funds are lost.';
                st.style.color = 'var(--warning)';
            } else if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0.00 KAS | Claimed';
                st.style.color = '';
            } else {
                let timeInfo = '';
                if (myLocktime > 0 && currentDaa > 0) {
                    const remaining = myLocktime - currentDaa;
                    if (remaining > 0) timeInfo = ' | ~' + formatDuration(Math.floor(remaining / 10)) + ' left';
                }
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...' + timeInfo;
                st.style.color = '';
            }
        }

        // First poll: record the balance and store UTXO outpoint
        if (_swapLastBalance === null) {
            _swapLastBalance = total;
            if (utxos.length > 0 && utxos[0].tx_id) {
                _swapUtxoOutpoint = { txid: utxos[0].tx_id, index: utxos[0].index || 0 };
            }
            return;
        }

        // Balance dropped to zero: HTLC was claimed!
        if (total === 0n && _swapLastBalance > 0n) {
            if (_swapWatcherTimer) { clearInterval(_swapWatcherTimer); _swapWatcherTimer = null; }

            // Give BlockAdded subscription a moment to extract preimage
            await new Promise(r => setTimeout(r, 3000));

            let extractedPreimage = window._extractedPreimage || '';

            // Stop subscription now
            swapSubscriptionStop();

            // Update balance display
            const balEl = el('cov-result-balance');
            if (balEl) { balEl.textContent = '0 KAS (claimed by counterparty)'; balEl.style.display = ''; }

            // If preimage was extracted from chain (we're Bob) and we haven't claimed yet, show claim flow.
            // If we already broadcast a claim TX (we're Alice), swap is done for us.
            const alreadyClaimed = window._swapClaimBroadcasted;
            const needToClaim = !alreadyClaimed && (window._preimageFromChain || !extractedPreimage);
            const inv = _swapCounterpartyInvite;

            if (needToClaim && inv && inv.addr) {
                el('cov-claim-addr').value = inv.addr;
                if (inv.rs) el('cov-claim-script').value = inv.rs;
                el('cov-claim-preimage').value = extractedPreimage || '';
                if (el('cov-claim-dest') && walletData && walletData.receive_addresses && walletData.receive_addresses.length > 0) {
                    // Destination address left empty for user to fill
                }

                const extra = el('cov-result-extra');
                if (extra) {
                    let preimageMsg;
                    if (extractedPreimage) {
                        preimageMsg = '<br>Preimage auto-extracted: <strong>' + extractedPreimage + '</strong>';
                    } else {
                        const explorerBase = network === 'mainnet' ? 'https://kaspa.stream' : network === 'testnet-10' ? 'https://tn10.kaspa.stream' : 'https://tn12.kaspa.stream';
                        preimageMsg = '<br>Preimage not captured. '
                            + '<a href="' + explorerBase + '/addresses/' + lastCovenantResult.address + '" target="_blank" style="color:#000;text-decoration:underline">Check explorer</a>'
                            + ' or enter it manually.';
                    }
                    extra.innerHTML = '<div style="background:var(--warning);color:#000;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;line-height:1.4">'
                        + '<strong>Your HTLC was claimed!</strong><br>'
                        + 'The counterparty revealed the preimage on chain.'
                        + preimageMsg
                        + '<br>Tap <strong>Claim (Preimage)</strong> below to claim their HTLC.'
                        + '</div>';
                }

                const toastMsg = extractedPreimage
                    ? 'HTLC claimed! Preimage extracted. Tap Claim.'
                    : 'HTLC claimed! Enter preimage and claim.';
                toast(toastMsg, 'ok', 5000);

                // Persistent banner
                const banner = el('swap-alert-banner');
                if (banner) {
                    const preimageNote = extractedPreimage ? ' Preimage: ' + extractedPreimage : '';
                    banner.innerHTML = '<strong>Your HTLC was claimed!</strong>' + preimageNote + '<br>Tap here to claim the counterparty\'s funds.';
                    banner.style.display = '';
                    banner.onclick = () => {
                        banner.style.display = 'none';
                        showScreen('covenant');
                        covShowPanel('atomic-claim');
                        if (inv.addr) el('cov-claim-addr').value = inv.addr;
                        if (inv.rs) el('cov-claim-script').value = inv.rs;
                        if (extractedPreimage) el('cov-claim-preimage').value = extractedPreimage;
                        if (el('cov-claim-dest') && walletData && walletData.receive_addresses && walletData.receive_addresses.length > 0) {
                            // Destination address left empty for user to fill
                        }
                        if (el('cov-claim-addr')) el('cov-claim-addr').dispatchEvent(new Event('input'));
                    };
                }
            } else {
                // We're Alice (initiator). Our HTLC was claimed by Bob. Swap complete.
                const extra = el('cov-result-extra');
                if (extra) {
                    extra.innerHTML = '<div style="background:var(--teal);color:#000;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;line-height:1.4">'
                        + '<strong>Swap complete!</strong><br>'
                        + 'Counterparty claimed your HTLC. You already claimed theirs. All done.'
                        + '</div>';
                }
                toast('Swap complete!', 'ok', 3000);
            }
        }

        _swapLastBalance = total;
    } catch (e) {
        // silent poll error
    }
}

// ─── Generic Covenant Watcher (DMS, Allowance, Spending Limit, etc.) ───

function covWatcherTypes() {
    return ['dms', 'timelocked-savings', 'global-spending-limit', 'global-allowance', 'additive', 'oracle', 'escrow', 'merkle-whitelist', 'payjoin', 'commit-reveal'];
}

function covWatcherStart() {
    if (_covWatcherTimer) return;
    if (!lastCovenantResult) return;
    const t = lastCovenantResult.type || '';
    if (!covWatcherTypes().includes(t)) return;

    _covWatcherSpendPath = null;
    _covSpendBroadcastTx = null;

    console.log('[KasSee] Covenant watcher started for ' + t + ': ' + lastCovenantResult.address);
    const st = el('cov-watcher-status');
    if (st) { st.textContent = '\uD83D\uDC41 Watching...'; st.style.display = ''; }
    _covWatcherTimer = setInterval(() => covWatcherPoll(), 3000);
    covWatcherPoll();
    covSubscriptionStart();
}

function covWatcherStop() {
    if (_covWatcherTimer) {
        clearInterval(_covWatcherTimer);
        _covWatcherTimer = null;
        console.log('[KasSee] Covenant watcher stopped');
    }
    covSubscriptionStop();
    _covWatcherLastBalance = null;
    // Don't hide status if swap watcher is active
    if (!_swapWatcherTimer) {
        const st = el('cov-watcher-status');
        if (st) st.style.display = 'none';
    }
}

async function covWatcherPoll() {
    if (!lastCovenantResult) { covWatcherStop(); return; }
    const t = lastCovenantResult.type || '';
    if (!covWatcherTypes().includes(t)) { covWatcherStop(); return; }

    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(lastCovenantResult.address, wsUrl);
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        const kas = Number(total) / 1e8;

        // Capture the thread covenant id (G) once. G is computable only from the
        // genesis outpoint, so it is unknown at creation and stored empty; the first
        // time the genesis thread is the lone tagged UTXO, record G so every later
        // thread pick is an exact match. A second genesis to the same address (tagged
        // with a different id) is then excluded as external instead of confusing the
        // picker. Only capture when unambiguous (exactly one tagged UTXO).
        if ((t === 'global-spending-limit' || t === 'global-allowance')
            && !(lastCovenantResult.covenant_id_hex && !/^0+$/.test(lastCovenantResult.covenant_id_hex))) {
            const _tagged = utxos.filter(u => u && u.covenant_id && !/^0+$/.test(String(u.covenant_id)));
            if (_tagged.length === 1) {
                const _g = String(_tagged[0].covenant_id);
                lastCovenantResult.covenant_id_hex = _g;
                const _ent = activeCovenants.find(c => c.address === lastCovenantResult.address);
                if (_ent && _ent.covenant_id_hex !== _g) { _ent.covenant_id_hex = _g; covSaveActive(); }
            }
        }

        // Keep top balance display in sync
        const balEl = el('cov-result-balance');
        if (balEl) {
            const kasStr = kas === 0 ? '0' : kas.toFixed(8).replace(/\.?0+$/, '');
            balEl.textContent = kasStr + ' KAS (' + utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ')';
            // Single-thread covenants: show the governed thread balance, not the raw
            // address total, and surface external (untagged) deposits separately.
            if (t === 'global-spending-limit' || t === 'global-allowance') {
                const _bp = pickThread(utxos, lastCovenantResult && lastCovenantResult.covenant_id_hex);
                const _govKas = _bp.thread ? Number(BigInt(_bp.thread.amount)) / 1e8 : 0;
                balEl.textContent = (_govKas === 0 ? '0' : _govKas.toFixed(8).replace(/\.?0+$/, '')) + ' KAS';
                if (_bp.externalSompi > 0n) {
                    const _extKas = Number(_bp.externalSompi) / 1e8;
                    const _word = (t === 'global-spending-limit') ? 'stuck' : 'owner-reclaimable';
                    balEl.textContent += ' (+' + (_extKas.toFixed(8).replace(/\.?0+$/, '')) + ' KAS external, ' + _word + ')';
                }
            }
            balEl.style.display = '';
        }

        const st = el('cov-watcher-status');
        if (!st || !_covWatcherTimer) return;

        const locktime = lastCovenantResult.locktime_daa ? Number(lastCovenantResult.locktime_daa) : 0;
        const currentDaa = await fetchCurrentDaa();
        if (currentDaa > 0) _lastKnownDaa = currentDaa;

        if (t === 'timelocked-savings') {
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                // Funds swept: one of the two wallets claimed (no owner-reclaim path here).
                st.innerHTML = '<span style="color:var(--teal)">\u2705 Claimed.</span>';
                _covSpendBroadcastTx = null;
                covWatcherStop();
                if (st) st.style.display = '';
                return;
            }
            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else if (_covSpendBroadcastTx) {
                st.innerHTML = '<span style="color:var(--warning)">\u23f3 Spend broadcast, confirming...</span>';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime + 300) {
                st.innerHTML = '<span style="color:var(--teal)">\u2705 Unlocked. ' + kas.toFixed(2) + ' KAS claimable.</span>';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime) {
                st.innerHTML = '<span style="color:var(--warning)">\u23f3 Unlocking... claim available shortly. ' + kas.toFixed(2) + ' KAS</span>';
            } else if (locktime > 0 && currentDaa > 0) {
                const remaining = locktime - currentDaa;
                const timeStr = formatDuration(Math.floor(remaining / 10));
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Locked, unlocks in ~' + timeStr;
                st.style.color = '';
            } else {
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...';
                st.style.color = '';
            }
        }

        if (t === 'dms') {
            const inactivity = lastCovenantResult.inactivity_daa ? Number(lastCovenantResult.inactivity_daa) : 0;
            const iAmOwner = lastCovenantResult.role !== 'beneficiary';
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'heir') {
                    st.innerHTML = '<span style="color:var(--warning)">\u26a0 Heir claimed the funds.</span>';
                    covWatcherStop();
                    if (st) st.style.display = '';
                    return;
                } else if (spender === 'owner') {
                    // Owner spent: could be heartbeat (funds return) or withdrawal (funds gone).
                    // Don't stop watcher. Show transitional message. Next poll resolves it.
                    st.innerHTML = '<span style="color:var(--text-muted)">\u23f3 Owner spent. Checking...</span>';
                    return;
                } else {
                    st.textContent = '\uD83D\uDC41 Funds spent (0 KAS)';
                    return;
                }
            }

            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else if (inactivity > 0 && currentDaa > 0) {
                // Find the newest UTXO (most recent heartbeat or deposit)
                let newestDaa = 0;
                for (const u of utxos) {
                    const d = Number(u.block_daa_score || 0);
                    if (d > newestDaa) newestDaa = d;
                }
                const unlockDaa = newestDaa + inactivity;
                const remaining = unlockDaa - currentDaa;
                if (remaining <= -300) {
                    st.innerHTML = '<span style="color:var(--warning)">\u26a0 Inactivity period passed. Heir can claim. ' + kas.toFixed(2) + ' KAS</span>';
                } else if (remaining <= 0) {
                    st.innerHTML = '<span style="color:var(--warning)">\u23f3 Inactivity period ending... Heir claim available shortly. ' + kas.toFixed(2) + ' KAS</span>';
                } else {
                    const timeStr = formatDuration(Math.floor(remaining / 10));
                    st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | ~' + timeStr + ' until heir can claim';
                    st.style.color = '';
                }
            } else {
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...';
                st.style.color = '';
            }
        }

        if (t === 'global-spending-limit') {
            ensureAllowanceParams(lastCovenantResult);
            const cooldown = lastCovenantResult.cooldown_daa ? Number(lastCovenantResult.cooldown_daa) : 0;
            const maxSompi = lastCovenantResult.max_withdraw_sompi ? Number(lastCovenantResult.max_withdraw_sompi) : 0;
            const maxKas = maxSompi > 0 ? (maxSompi / 1e8) : 0;
            // Governed balance = the single tagged thread; external (untagged) deposits
            // are stuck and not spendable through the limit, surfaced separately.
            const _sp = pickThread(utxos, lastCovenantResult && lastCovenantResult.covenant_id_hex);
            const _thread = _sp.thread;
            const _govSompi = _thread ? BigInt(_thread.amount) : 0n;
            const _govKas = Number(_govSompi) / 1e8;
            const _threadDaa = _thread ? Number(_thread.block_daa_score || 0) : 0;
            const _mature = !!_thread && (cooldown <= 0 || currentDaa <= 0 || currentDaa >= _threadDaa + cooldown);
            const matureSompi = _mature ? _govSompi : 0n;
            const canDrain = maxSompi > 0 && matureSompi > 0n && matureSompi <= BigInt(maxSompi);
            const maxStr = canDrain ? ' (full drain)' : (maxSompi > 0 ? ' (max ' + maxKas + ' KAS)' : '');
            const _extNote = _sp.externalSompi > 0n
                ? ' <span style="color:var(--warning)">(+' + (Number(_sp.externalSompi) / 1e8).toFixed(2) + ' KAS external, stuck)</span>'
                : '';
            st.style.color = '';
            if (_govSompi === 0n) {
                st.innerHTML = '\uD83D\uDC41 0 KAS | Not funded' + _extNote;
            } else if (matureSompi > 0n) {
                if (canDrain) {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Ready to drain all ' + _govKas.toFixed(2) + ' KAS</span>' + _extNote;
                } else {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Ready to withdraw' + maxStr + '</span>' + _extNote;
                }
            } else if (cooldown > 0 && currentDaa > 0) {
                const unlockDaa = _threadDaa + cooldown;
                const remaining = unlockDaa - currentDaa;
                if (remaining <= 0) {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Ready to withdraw' + maxStr + '</span>' + _extNote;
                } else {
                    const timeStr = formatDuration(Math.floor(remaining / 10));
                    st.innerHTML = '\uD83D\uDC41 ~' + timeStr + ' until next withdraw' + maxStr + _extNote;
                }
            } else {
                st.innerHTML = '\uD83D\uDC41 ' + _govKas.toFixed(2) + ' KAS | Watching...' + maxStr + _extNote;
            }
        }

        if (t === 'global-allowance') {
            ensureAllowanceParams(lastCovenantResult);
            const iAmOwner = lastCovenantResult.role !== 'beneficiary';
            const cooldown = lastCovenantResult.cooldown_daa ? Number(lastCovenantResult.cooldown_daa) : (lastCovenantResult.min_sequence ? Number(lastCovenantResult.min_sequence) : 0);
            const maxSompi = lastCovenantResult.max_withdraw_sompi ? Number(lastCovenantResult.max_withdraw_sompi) : 0;
            const maxKas = maxSompi > 0 ? (maxSompi / 1e8) : 0;
            const startDaa = lastCovenantResult.start_daa ? Number(lastCovenantResult.start_daa) : 0;
            // Governed balance = the single tagged thread; external (untagged) deposits
            // are recoverable only via the owner free path, surfaced separately.
            const _ap = pickThread(utxos, lastCovenantResult && lastCovenantResult.covenant_id_hex);
            const _agovSompi = _ap.thread ? BigInt(_ap.thread.amount) : 0n;
            const _agovKas = Number(_agovSompi) / 1e8;
            const _athreadDaa = _ap.thread ? Number(_ap.thread.block_daa_score || 0) : 0;
            const canDrain = maxSompi > 0 && _agovSompi > 0n && _agovSompi <= BigInt(maxSompi);
            const maxStr = canDrain ? ' (full drain)' : (maxSompi > 0 ? ' (max ' + maxKas + ' KAS)' : '');
            const _aExtNote = _ap.externalSompi > 0n
                ? ' <span style="color:var(--warning)">(+' + (Number(_ap.externalSompi) / 1e8).toFixed(2) + ' KAS external, owner-reclaimable)</span>'
                : '';

            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'heir') {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Beneficiary withdrew.</span>';
                } else if (spender === 'owner') {
                    st.innerHTML = '<span style="color:var(--warning)">\u26a0 Owner reclaimed all funds.</span>';
                } else {
                    st.textContent = '\uD83D\uDC41 Funds spent (0 KAS)';
                }
                covWatcherStop();
                if (st) st.style.display = '';
                return;
            }

            st.style.color = '';
            if (_agovSompi === 0n) {
                st.innerHTML = '\uD83D\uDC41 0 KAS | Not funded' + _aExtNote;
            } else if (iAmOwner) {
                // Owner can reclaim any time, no cooldown applies
                st.innerHTML = '\uD83D\uDC41 ' + _agovKas.toFixed(2) + ' KAS | Owner can reclaim anytime' + _aExtNote;
            } else if (startDaa > 0 && currentDaa > 0 && currentDaa < startDaa) {
                // Before start date
                const remaining = startDaa - currentDaa;
                const timeStr = formatDuration(Math.floor(remaining / 10));
                st.innerHTML = '\uD83D\uDC41 ' + _agovKas.toFixed(2) + ' KAS | Locked, ~' + timeStr + ' until start' + _aExtNote;
            } else if (cooldown > 0 && currentDaa > 0) {
                const unlockDaa = _athreadDaa + cooldown;
                const remaining = unlockDaa - currentDaa;
                if (remaining <= 0) {
                    if (canDrain) {
                        st.innerHTML = '<span style="color:var(--teal)">\u2705 Ready to drain all ' + _agovKas.toFixed(2) + ' KAS</span>' + _aExtNote;
                    } else {
                        st.innerHTML = '<span style="color:var(--teal)">\u2705 Ready to withdraw' + maxStr + '</span>' + _aExtNote;
                    }
                } else {
                    const timeStr = formatDuration(Math.floor(remaining / 10));
                    st.innerHTML = '\uD83D\uDC41 ~' + timeStr + ' until next withdraw' + maxStr + _aExtNote;
                }
            } else {
                st.innerHTML = '\uD83D\uDC41 ' + _agovKas.toFixed(2) + ' KAS | Watching...' + maxStr + _aExtNote;
            }
        }

        if (t === 'additive') {
            const threshold = lastCovenantResult.threshold_sompi ? Number(lastCovenantResult.threshold_sompi) : 0;
            const deadlineDaa = lastCovenantResult.deadline_daa ? Number(lastCovenantResult.deadline_daa) : 0;
            const thresholdKas = threshold > 0 ? (threshold / 1e8) : 0;

            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                st.innerHTML = '<span style="color:var(--teal)">\u2705 Piggy bank broken! Funds withdrawn.</span>';
                covWatcherStop();
                if (st) st.style.display = '';
                return;
            }

            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else {
                let statusParts = [];
                // Goal progress
                if (threshold > 0) {
                    const pct = Math.min(100, Math.round(kas / thresholdKas * 100));
                    statusParts.push(kas.toFixed(2) + ' / ' + thresholdKas + ' KAS (' + pct + '%)');
                    if (total >= BigInt(threshold)) {
                        statusParts.push('\u2705 Goal reached!');
                    }
                } else {
                    statusParts.push(kas.toFixed(2) + ' KAS');
                }
                // Deadline countdown
                if (deadlineDaa > 0 && currentDaa > 0) {
                    if (currentDaa >= deadlineDaa) {
                        statusParts.push('\u23F0 Deadline passed');
                    } else {
                        const remaining = deadlineDaa - currentDaa;
                        const timeStr = formatDuration(Math.floor(remaining / 10));
                        statusParts.push('~' + timeStr + ' until deadline');
                    }
                }
                // Can break?
                const canBreakGoal = threshold > 0 && total >= BigInt(threshold);
                const canBreakTime = deadlineDaa > 0 && currentDaa > 0 && currentDaa >= deadlineDaa;
                const noConditions = threshold === 0 && deadlineDaa === 0;
                if (canBreakGoal || canBreakTime || noConditions) {
                    st.innerHTML = '<span style="color:var(--teal)">\uD83D\uDC41 ' + statusParts.join(' | ') + '</span>';
                } else {
                    st.textContent = '\uD83D\uDC41 ' + statusParts.join(' | ');
                    st.style.color = '';
                }
            }
        }

        if (t === 'oracle') {
            // Update info line with human-readable date once DAA is available
            if (currentDaa > 0 && lastCovenantResult.locktime_daa) {
                const extraEl = el('cov-result-extra');
                if (extraEl) {
                    extraEl.textContent = covMetaLine(lastCovenantResult);
                }
            }
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'heir') {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Beneficiary claimed (oracle attested).</span>';
                } else if (spender === 'owner') {
                    st.innerHTML = '<span style="color:var(--warning)">\u26a0 Owner refunded (timeout).</span>';
                } else {
                    st.textContent = '\uD83D\uDC41 Funds spent (0 KAS)';
                }
                // Reset attestation state for next round (persistent watcher)
                lastCovenantResult._oracleAttestSig = null;
                lastCovenantResult._oracleAttestHash = null;
                lastCovenantResult._oraclePayloadChecked = null;
                _covWatcherSpendPath = null;
                // Clear localStorage attestation for this covenant
                try {
                    let attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]');
                    attestations = attestations.filter(a => a.covenant_address !== lastCovenantResult.address);
                    localStorage.setItem('oracleAttestations', JSON.stringify(attestations));
                } catch (_) {}
                // Clear attestation text on result panel
                const resAtt = el('cov-res-attest-text');
                if (resAtt) { resAtt.textContent = ''; resAtt.style.display = 'none'; }
                // Update active covenants
                const ac2 = activeCovenants.find(x => x.address === lastCovenantResult.address);
                if (ac2) { ac2._oracleAttestSig = null; ac2._oracleAttestHash = null; covSaveActive(); }
                if (st) st.style.display = '';
                // Don't stop watcher. Next deposit cycle resets automatically.
                _covWatcherLastBalance = total;
                return;
            }

            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else {
                // Check for ORAC attestation beacon in TX payload (any funded state)
                const currentTxId = utxos.length > 0 ? utxos[0].tx_id : null;
                if (currentTxId && lastCovenantResult._oraclePayloadChecked !== currentTxId) {
                    try {
                        const apiBase = network === 'testnet-10' ? 'https://api-tn10.kaspa.org' : 'https://api.kaspa.org';
                        const txResp = await fetch(apiBase + '/transactions/' + currentTxId, { signal: AbortSignal.timeout(5000) });
                        if (txResp.ok) {
                            lastCovenantResult._oraclePayloadChecked = currentTxId;
                            const txData = await txResp.json();
                            const payload = txData.payload || '';
                            if (payload.startsWith('4f524143') && payload.length >= 196) {
                                const sigHex = payload.substring(8, 136);
                                const hashHex = payload.substring(136, 200);
                                // Extract text from payload bytes after sig+hash (if present)
                                let attestText = '';
                                if (payload.length > 200) {
                                    try {
                                        const textHex = payload.substring(200);
                                        const textBytes = new Uint8Array(textHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                                        attestText = new TextDecoder().decode(textBytes);
                                    } catch (_) {}
                                }
                                lastCovenantResult._oracleAttestSig = sigHex;
                                lastCovenantResult._oracleAttestHash = hashHex;
                                if (el('cov-oracle-claim-sig')) el('cov-oracle-claim-sig').value = sigHex;
                                if (el('cov-oracle-claim-hash')) el('cov-oracle-claim-hash').value = hashHex;
                                try {
                                    let attestations = [];
                                    try { attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]'); } catch (_) {}
                                    attestations = attestations.filter(a => a.covenant_address !== lastCovenantResult.address);
                                    attestations.unshift({ covenant_address: lastCovenantResult.address, sig: sigHex, hash: hashHex, text: attestText, scanned_at: new Date().toISOString(), source: 'chain' });
                                    localStorage.setItem('oracleAttestations', JSON.stringify(attestations));
                                } catch (_) {}
                                toast('Oracle attestation detected on-chain!' + (attestText ? ' "' + attestText + '"' : ''), 'ok', 5000);
                                const ac = activeCovenants.find(x => x.address === lastCovenantResult.address);
                                if (ac) { ac._oracleAttestSig = sigHex; ac._oracleAttestHash = hashHex; covSaveActive(); }
                            }
                        }
                    } catch (_) {}
                }

                // Status display
                if (lastCovenantResult._oracleAttestSig) {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 ' + kas.toFixed(2) + ' KAS | Oracle attested! Ready to claim.</span>';
                } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime + 300) {
                    st.innerHTML = '<span style="color:var(--warning)">\u26a0 Timeout reached. Owner can refund. ' + kas.toFixed(2) + ' KAS</span>';
                } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime) {
                    st.innerHTML = '<span style="color:var(--warning)">\u23f3 Timeout passing... refund available shortly. ' + kas.toFixed(2) + ' KAS</span>';
                } else if (locktime > 0 && currentDaa > 0) {
                    const remaining = locktime - currentDaa;
                    const timeStr = formatDuration(Math.floor(remaining / 10));
                    st.textContent = '\uD83E\uDD16 ' + kas.toFixed(2) + ' KAS | Awaiting oracle, ~' + timeStr + ' until owner refund';
                    st.style.color = '';
                } else {
                    st.textContent = '\uD83E\uDD16 ' + kas.toFixed(2) + ' KAS | Awaiting oracle attestation...';
                    st.style.color = '';
                }
            }
        }

        if (t === 'escrow') {
            ensureEscrowParams(lastCovenantResult);
            const role = lastCovenantResult.role || 'owner';
            const roleLabel = role === 'owner' ? 'Buyer' : (role === 'beneficiary' ? 'Seller' : 'Arbiter');

            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                // Funds left the escrow. Resolved. Latch the resolved state so the
                // confirmation persists across polls: escrow keeps watching for reuse and
                // must not revert to "Awaiting deposit" on the very next poll (when
                // _covWatcherLastBalance is already 0). Also reset dispute state for the
                // next deposit cycle.
                st.innerHTML = '<span style="color:var(--teal)">\u2705 Escrow resolved. Funds released.</span>';
                if (st) st.style.display = '';
                lastCovenantResult._escrowResolved = true;
                lastCovenantResult._escrowFirstTxId = null;
                lastCovenantResult._escrowPayloadChecked = null;
                lastCovenantResult._escrowDisputed = false;
                lastCovenantResult._escrowDisputeRole = null;
                const c = activeCovenants.find(x => x.address === lastCovenantResult.address);
                if (c) { c._escrowResolved = true; c._escrowDisputed = false; c._escrowDisputeRole = null; covSaveActive(); }
            } else if (total === 0n) {
                // Zero balance, no funds-left transition this poll. If a deal already
                // resolved, keep the sticky resolved banner; otherwise it is a fresh /
                // never-funded escrow awaiting its first deposit.
                if (lastCovenantResult._escrowResolved) {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Escrow resolved. Funds released.</span>';
                } else {
                    st.textContent = '\u2696\uFE0F Awaiting deposit.';
                    st.style.color = '';
                }
            } else {
                // Funded. A new deposit starts a fresh cycle: clear any prior resolved latch.
                if (lastCovenantResult._escrowResolved) {
                    lastCovenantResult._escrowResolved = false;
                    const cr = activeCovenants.find(x => x.address === lastCovenantResult.address);
                    if (cr) { cr._escrowResolved = false; covSaveActive(); }
                }
                const currentTxId = utxos.length > 0 ? utxos[0].tx_id : '';
                if (!lastCovenantResult._escrowFirstTxId && currentTxId) {
                    lastCovenantResult._escrowFirstTxId = currentTxId;
                }

                // Check persisted dispute flag first
                let disputed = !!lastCovenantResult._escrowDisputed;

                // If not yet flagged, check if UTXO changed (potential heartbeat)
                if (!disputed && lastCovenantResult._escrowFirstTxId && currentTxId
                    && currentTxId !== lastCovenantResult._escrowFirstTxId
                    && lastCovenantResult._escrowPayloadChecked !== currentTxId) {
                    // Fetch the TX and check for ESCD dispute payload
                    // console.log('[KasSee] Escrow watcher: UTXO changed, fetching TX ' + currentTxId.substring(0, 16) + '...');
                    try {
                        const apiBase = network === 'testnet-10' ? 'https://api-tn10.kaspa.org' : 'https://api.kaspa.org';
                        const txResp = await fetch(apiBase + '/transactions/' + currentTxId, { signal: AbortSignal.timeout(5000) });
                        if (txResp.ok) {
                            lastCovenantResult._escrowPayloadChecked = currentTxId;
                            const txData = await txResp.json();
                            const payload = txData.payload || '';
                            // console.log('[KasSee] Escrow TX payload: "' + payload.substring(0, 30) + '" (' + payload.length/2 + ' bytes)');
                            // ESCD marker: hex "455343440001" or "455343440002"
                            if (payload.startsWith('4553434400')) {
                                disputed = true;
                                lastCovenantResult._escrowDisputed = true;
                                lastCovenantResult._escrowDisputeRole = payload.substring(10, 12) === '01' ? 'buyer' : 'seller';
                                const c = activeCovenants.find(x => x.address === lastCovenantResult.address);
                                if (c) {
                                    c._escrowDisputed = true;
                                    c._escrowDisputeRole = lastCovenantResult._escrowDisputeRole;
                                    covSaveActive();
                                }
                                // console.log('[KasSee] Escrow dispute detected! Role: ' + lastCovenantResult._escrowDisputeRole);
                            }
                        } else {
                            // console.log('[KasSee] Escrow TX fetch failed: ' + txResp.status);
                        }
                    } catch (e) {
                        // silent fetch error
                    }
                }

                if (disputed) {
                    const who = lastCovenantResult._escrowDisputeRole || 'party';
                    st.innerHTML = '<span style="color:var(--warning)">\u2696\uFE0F Arbitration requested by ' + who + '. ' + kas.toFixed(2) + ' KAS locked.</span>';
                } else {
                    st.textContent = '\u2696\uFE0F ' + kas.toFixed(2) + ' KAS locked. Awaiting resolution.';
                    st.style.color = '';
                }
            }
            if (st) st.style.display = '';
        }

        if (t === 'merkle-whitelist') {
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'owner') {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Owner refunded.</span>';
                } else {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Spent to whitelisted address.</span>';
                }
                if (st) st.style.display = '';
                return;
            }
            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime + 300) {
                st.innerHTML = '<span style="color:var(--teal)">\u2705 ' + kas.toFixed(2) + ' KAS | Refund available now</span>';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime) {
                st.innerHTML = '<span style="color:var(--warning)">\u23f3 ' + kas.toFixed(2) + ' KAS | Timeout passing...</span>';
            } else if (locktime > 0 && currentDaa > 0) {
                const remaining = locktime - currentDaa;
                const timeStr = formatDuration(Math.floor(remaining / 10));
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Refund in ~' + timeStr + ' | Whitelisted spend available now';
                st.style.color = '';
            } else {
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...';
                st.style.color = '';
            }
            if (st) st.style.display = '';
        }

        if (t === 'payjoin') {
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'owner') {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Owner refunded.</span>';
                } else {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 PayJoin claimed.</span>';
                }
                if (st) st.style.display = '';
                return;
            }
            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
                st.style.color = '';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime + 300) {
                st.innerHTML = '<span style="color:var(--warning)">\u26a0 ' + kas.toFixed(2) + ' KAS | Refund available. Claim still open.</span>';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime) {
                st.innerHTML = '<span style="color:var(--warning)">\u23f3 ' + kas.toFixed(2) + ' KAS | Timeout passing...</span>';
            } else if (locktime > 0 && currentDaa > 0) {
                const remaining = locktime - currentDaa;
                const timeStr = formatDuration(Math.floor(remaining / 10));
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Refund in ~' + timeStr + ' | Claim available now';
                st.style.color = '';
            } else {
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...';
                st.style.color = '';
            }
            if (st) st.style.display = '';
        }

        if (t === 'commit-reveal') {
            if (total === 0n && _covWatcherLastBalance !== null && _covWatcherLastBalance > 0n) {
                const spender = _covWatcherSpendPath || 'unknown';
                if (spender === 'owner') {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Owner refunded.</span>';
                } else {
                    st.innerHTML = '<span style="color:var(--teal)">\u2705 Preimage revealed. Funds spent.</span>';
                }
                if (st) st.style.display = '';
                return;
            }
            if (total === 0n) {
                st.textContent = '\uD83D\uDC41 0 KAS | Not funded';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime + 300) {
                st.innerHTML = '<span style="color:var(--warning)">\u26a0 ' + kas.toFixed(2) + ' KAS | Refund available. Reveal still open.</span>';
            } else if (locktime > 0 && currentDaa > 0 && currentDaa >= locktime) {
                st.innerHTML = '<span style="color:var(--warning)">\u23f3 ' + kas.toFixed(2) + ' KAS | Timeout passing...</span>';
            } else if (locktime > 0 && currentDaa > 0) {
                const remaining = locktime - currentDaa;
                const timeStr = formatDuration(Math.floor(remaining / 10));
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Refund in ~' + timeStr + ' | Reveal available';
            } else {
                st.textContent = '\uD83D\uDC41 ' + kas.toFixed(2) + ' KAS | Watching...';
            }
            if (st) st.style.display = '';
        }

        // First poll: store UTXO outpoint for BlockAdded detection
        if (_covWatcherLastBalance === null && utxos.length > 0 && utxos[0].tx_id) {
            _covWatcherOutpoint = { txid: utxos[0].tx_id, index: utxos[0].index || 0 };
        }
        _covWatcherLastBalance = total;
    } catch (e) {
        // silent poll error
    }
}

// Track which spending path was used (set by BlockAdded subscription)
let _covWatcherSpendPath = null;

async function covSubscriptionStart() {
    covSubscriptionStop();
    if (!lastCovenantResult || !lastCovenantResult.address) return;
    const t = lastCovenantResult.type || '';
    if (!covWatcherTypes().includes(t)) return;
    // Capture the covenant type at subscription time (not at message time)
    const subscribedType = t;
    const subscribedAddress = lastCovenantResult.address;

    try {
        const wsUrl = await resolveNodeUrl();
        const blockAddedReq = new Uint8Array(build_vcc_subscribe_request(43n));

        const ws = new WebSocket(wsUrl);
        ws.binaryType = 'arraybuffer';
        _covSubscriptionWs = ws;

        ws.onopen = () => { ws.send(blockAddedReq); };

        ws.onmessage = (evt) => {
            const data = new Uint8Array(evt.data);
            if (data.length < 4) return;
            let pos = (data[0] === 0x01) ? 9 : 1;
            if (pos >= data.length || data[pos] !== 0xFF) return;
            const notifOp = data[pos + 2];
            if (notifOp !== 0x3C) return; // only BlockAdded
            if (!_covWatcherOutpoint || !_covWatcherOutpoint.txid) return;

            const txidHex = _covWatcherOutpoint.txid;
            const txidBytes = new Uint8Array(32);
            for (let j = 0; j < 32; j++) txidBytes[j] = parseInt(txidHex.substr(j * 2, 2), 16);

            // Scan for outpoint pattern: u32(37) + 0x01 + txid
            for (let k = 4; k < data.length - 40; k++) {
                if (data[k] !== 37 || data[k+1] !== 0 || data[k+2] !== 0 || data[k+3] !== 0) continue;
                if (data[k+4] !== 0x01) continue;
                let match = true;
                for (let j = 0; j < 32; j++) { if (data[k+5+j] !== txidBytes[j]) { match = false; break; } }
                if (!match) continue;

                // Found our UTXO being spent. Extract sig_script to determine path.
                const afterOutpoint = k + 5 + 32 + 4; // txid(32) + index(4)
                if (afterOutpoint + 4 > data.length) continue;
                const sigLen = data[afterOutpoint] | (data[afterOutpoint+1] << 8) | (data[afterOutpoint+2] << 16) | (data[afterOutpoint+3] << 24);
                if (sigLen < 2 || sigLen > 2000) continue;
                const sigStart = afterOutpoint + 4;
                if (sigStart + sigLen > data.length) continue;

                // DMS/Vault script: IF branch = owner (OP_TRUE 0x51 before redeem push)
                //                    ELSE branch = heir (OP_FALSE 0x00 before redeem push)
                const sigBytes = data.slice(sigStart, sigStart + sigLen);
                let path = 'unknown';

                // Strategy: the redeem script hex is known. Find it at the end of sig_script,
                // then the byte before the pushdata opcode is the branch selector.
                const rsHex = (lastCovenantResult && lastCovenantResult.redeem_script_hex) || '';
                // Single-path covenants (e.g. spending-limit, allowance) have body
                // <pk:32> CHECKSIGVERIFY, optionally behind a 0x08<salt:8>0x75 prefix,
                // and no spender-selected branch. Their sig_script is <sig> <redeem>
                // with no selector byte, so the byte before the redeem is the
                // signature's sighash byte, not a branch selector. Detect by shape.
                let isSinglePath = false;
                if (rsHex.length >= 70) {
                    const b0 = parseInt(rsHex.substr(0, 2), 16);
                    const bodyOff = (b0 === 0x08 && parseInt(rsHex.substr(18, 2), 16) === 0x75) ? 10 : 0;
                    isSinglePath = parseInt(rsHex.substr(bodyOff * 2, 2), 16) === 0x20
                        && parseInt(rsHex.substr((bodyOff + 33) * 2, 2), 16) === 0xad;
                }
                if (isSinglePath) {
                    path = 'owner';
                    console.log('[KasSee] Covenant spend: single-path (no selector) => owner');
                } else if (rsHex.length > 0) {
                    const rsLen = rsHex.length / 2;
                    // Redeem is at the tail of sig_script, preceded by pushdata opcode + length
                    // OP_PUSHDATA2 (0x4D) + u16 LE: 3 bytes overhead
                    // OP_PUSHDATA1 (0x4C) + u8: 2 bytes overhead
                    // Direct push (0x01-0x4B): 1 byte overhead
                    let overhead = 0;
                    let selectorPos = -1;
                    if (sigBytes.length > rsLen + 3 && sigBytes[sigBytes.length - rsLen - 3] === 0x4D) {
                        overhead = 3; selectorPos = sigBytes.length - rsLen - 3 - 1;
                    } else if (sigBytes.length > rsLen + 2 && sigBytes[sigBytes.length - rsLen - 2] === 0x4C) {
                        overhead = 2; selectorPos = sigBytes.length - rsLen - 2 - 1;
                    } else if (sigBytes.length > rsLen + 1 && sigBytes[sigBytes.length - rsLen - 1] <= 0x4B) {
                        overhead = 1; selectorPos = sigBytes.length - rsLen - 1 - 1;
                    }
                    if (selectorPos >= 0) {
                        const selector = sigBytes[selectorPos];
                        path = (selector === 0x51) ? 'owner' : 'heir';
                        console.log('[KasSee] Branch selector byte: 0x' + selector.toString(16) + ' at pos ' + selectorPos + ' => ' + path);
                    }
                }

                console.log('[KasSee] Covenant spend detected via BlockAdded. Path: ' + path);
                _covWatcherSpendPath = path;

                // Guard: ignore if covenant was switched since subscription started
                if (!lastCovenantResult || lastCovenantResult.address !== subscribedAddress) {
                    console.log('[KasSee] BlockAdded: ignoring stale subscription (covenant switched)');
                    covSubscriptionStop();
                    break;
                }

                const ct = subscribedType;
                const isZk = false;
                const isFreeze = false;
                const typeLabels = {
                    'dms': 'DMS', 'timelocked-savings': 'Time-Locked Savings',
                    'global-allowance': 'Global Allowance', 'additive': 'Piggy Bank', 'oracle': 'Oracle',
                    'commit-reveal': 'Commit-Reveal'
                };
                const label = typeLabels[ct] || ct;
                
                if (path === 'heir') {
                    let msg;
                    if (isZk) msg = label + ': Proof verified, funds claimed!';
                    else if (isFreeze) msg = label + ': Auto-released to heir!';
                    else if (ct === 'dms') msg = label + ': Heir claimed (inactivity timeout)';
                    else if (ct === 'global-allowance') msg = label + ': Beneficiary withdrew';
                    else if (ct === 'additive') msg = label + ': Piggy bank broken!';
                    else if (ct === 'commit-reveal') msg = label + ': Secret revealed and spent!';
                    else if (ct === 'oracle') msg = null; // Suppress: could be heartbeat or claim. Watcher poll resolves.
                    // Escrow: the owner/heir selector does not map onto its six paths
                    // (buyer-release, seller-refund, arbiter-award, arbiter-refund, two
                    // disputes), so an immediate heir/owner label is wrong. Suppress and let
                    // the balance-driven escrow watcher poll report the real outcome ("Escrow
                    // resolved" on sweep, "Arbitration requested" on a dispute heartbeat).
                    else if (ct === 'escrow') msg = null;
                    else msg = label + ': Beneficiary claimed the funds!';
                    if (msg) toast(msg, 'ok', 5000);
                } else if (path === 'owner') {
                    let msg;
                    if (isZk) msg = label + ': Owner refunded (timeout)';
                    else if (isFreeze) msg = label + ': Owner cancelled the freeze';
                    else if (ct === 'dms') msg = label + ': Owner heartbeat or withdrawal';
                    // Thread covenants: an owner-path spend is ambiguous. A top-up, a
                    // capped withdrawal, and a full drain all re-spend the same thread
                    // outpoint, so this event alone cannot tell them apart. Suppress the
                    // immediate banner and let the balance-driven watcher poll report the
                    // real outcome (a continuation keeps the balance funded; a drain takes
                    // it to 0).
                    else if (ct === 'global-spending-limit' || ct === 'global-allowance') msg = null;
                    else if (ct === 'additive') msg = label + ': Owner broke the piggy bank';
                    else if (ct === 'commit-reveal') msg = label + ': Owner refunded (no reveal)';
                    else if (ct === 'escrow') msg = null; // see escrow note in the heir branch above
                    else msg = label + ': Owner reclaimed';
                    if (msg) toast(msg, 'ok', 3000);
                } else {
                    toast(label + ': Funds spent on chain', 'ok', 3000);
                }

                covSubscriptionStop();
                break;
            }
        };

        ws.onerror = () => {};
        ws.onclose = () => {
            if (_covSubscriptionWs === ws) {
                _covSubscriptionWs = null;
                if (_covWatcherTimer) {
                    setTimeout(() => covSubscriptionStart(), 3000);
                }
            }
        };
    } catch (e) {
        console.warn('[KasSee] Covenant subscription failed:', e);
        if (_covWatcherTimer) setTimeout(() => covSubscriptionStart(), 5000);
    }
}

function covSubscriptionStop() {
    if (_covSubscriptionWs) {
        try { _covSubscriptionWs.close(); } catch (_) {}
        _covSubscriptionWs = null;
    }
}

function formatDuration(seconds) {
    if (seconds <= 0) return '0s';
    const parts = [];
    const y = Math.floor(seconds / 31536000); if (y) { parts.push(y + 'y'); seconds %= 31536000; }
    const mo = Math.floor(seconds / 2592000); if (mo) { parts.push(mo + 'mo'); seconds %= 2592000; }
    const d = Math.floor(seconds / 86400); if (d) { parts.push(d + 'd'); seconds %= 86400; }
    const h = Math.floor(seconds / 3600); if (h) { parts.push(h + 'h'); seconds %= 3600; }
    const m = Math.floor(seconds / 60); if (m) { parts.push(m + 'min'); seconds %= 60; }
    if (seconds) parts.push(seconds + 's');
    return parts.join(' ');
}

// Format a start_daa value as a human-readable date.
// Uses stored ISO date string if available, otherwise estimates from DAA.
function formatStartDate(cov) {
    if (cov.start_date_iso) {
        try { return new Date(cov.start_date_iso).toLocaleString(); } catch (_) {}
    }
    // Fallback: estimate date from DAA (requires _lastKnownDaa from watcher)
    const daa = cov.start_daa || cov.locktime_daa || 0;
    if (daa > 0 && window._lastKnownDaa && window._lastKnownDaa > 0) {
        const diffSec = (daa - window._lastKnownDaa) / 10;
        const est = new Date(Date.now() + diffSec * 1000);
        return '~' + est.toLocaleString();
    }
    return 'DAA ' + daa;
}
var _lastKnownDaa = 0;

// ── Covenant result meta line ───────────────────────────────────────────────
// Single source of truth for the "Type: ... | ..." summary on the covenant
// result panel. All four entry points (creation, active-list reload,
// post-funding return, invite load) call covRenderMetaLine, so a per-type
// display change is made here once.
//
// covMetaLine(c): pure function -> string. Timed fields go through
// formatStartDate (exact date if *_date_iso present, else ~estimate from
// window._lastKnownDaa, else raw 'DAA N').
function covMetaLine(c) {
    const t = (c && c.type) || '';
    const refund = () => formatStartDate({ locktime_daa: c.locktime_daa, start_date_iso: c.locktime_date_iso });
    const cooldown = () => {
        const cd = c.cooldown_daa || c.min_sequence || 0;
        return cd ? ' | Cooldown: ' + formatDuration(Math.round(cd / 10)) : '';
    };
    if (t === 'dms' && c.inactivity_daa) {
        return 'Type: Dead Man\'s Switch | Inactivity: ' + formatDuration(Math.round(c.inactivity_daa / 10));
    }
    if (t === 'global-spending-limit') {
        let mw = c.max_withdraw_sompi || 0, cd = c.cooldown_daa || 0;
        if ((!mw || !cd) && c.redeem_script_hex) {
            const p = parseAllowanceScript(c.redeem_script_hex);
            if (!mw) mw = p.max_withdraw_sompi;
            if (!cd) cd = p.cooldown_daa;
        }
        if (mw) {
            const cdStr = cd ? ' | Cooldown: ' + formatDuration(Math.round(cd / 10)) : '';
            return 'Type: Global Spending Limit | Limit: ' + (mw / 1e8) + ' KAS/spend' + cdStr;
        }
    }
    if (t === 'global-allowance') {
        let mw = c.max_withdraw_sompi || 0, cd = c.cooldown_daa || 0;
        if ((!mw || !cd) && c.redeem_script_hex) {
            const p = parseAllowanceScript(c.redeem_script_hex);
            if (!mw) mw = p.max_withdraw_sompi;
            if (!cd) cd = p.cooldown_daa;
        }
        if (mw) {
            const cdStr = cd ? ' | Cooldown: ' + formatDuration(Math.round(cd / 10)) : '';
            // Only show the fixed start timestamp (exact ISO). The DAA-derived
            // estimate drifts with each block and never matches wall-clock once
            // the start has passed, so omit it when we lack the exact value. The
            // watcher shows the live "until start" / cooldown countdown.
            const startStr = c.start_date_iso ? ' | Start: ' + formatStartDate(c) : '';
            return 'Type: Global Allowance | Max: ' + (mw / 1e8) + ' KAS/spend' + cdStr + startStr;
        }
    }
    if (t === 'additive') {
        let s = 'Type: Piggy Bank';
        if (c.threshold_sompi) s += ' | Goal: ' + (c.threshold_sompi / 1e8) + ' KAS';
        // Show the exact deadline only when the ISO is known (owner's create
        // record). Otherwise omit it: the live "until deadline" countdown in the
        // watcher is the correct moving display (a DAA-derived date drifts).
        if (c.deadline_daa && c.deadline_date_iso) {
            s += ' | Deadline: ' + formatStartDate({ start_date_iso: c.deadline_date_iso, start_daa: c.deadline_daa });
        }
        if (!c.threshold_sompi && !c.deadline_daa) s += ' | No conditions (break anytime)';
        return s;
    }
    if (t === 'oracle') return 'Type: Oracle | Refund timeout: ' + refund();
    if (t === 'merkle-whitelist') {
        let n = 0;
        try { n = JSON.parse(c.merkle_addresses_json || '[]').length; } catch (_) {}
        return 'Type: Merkle Whitelist | ' + n + ' addresses | Refund: ' + refund();
    }
    if (t === 'payjoin') return 'Type: PayJoin | Refund timeout: ' + refund();
    if (t === 'commit-reveal') return 'Type: Commit-Reveal | Refund timeout: ' + refund();
    if (t === 'crowdfund') {
        let s = 'Type: Crowdfund';
        if (c.campaign_name) s += ' | Campaign: ' + c.campaign_name;
        if (c.goal_kas) s += ' | Goal: ' + c.goal_kas + ' KAS';
        if (c.crowdfund_role) s += ' | Role: ' + c.crowdfund_role;
        if (c.locktime_daa) s += ' | Refund: ' + refund();
        return s;
    }
    if (t === 'atomic-swap') return 'Type: Atomic Swap' + (c.hash_algo ? ' | Hash: ' + c.hash_algo : '');
    // Generic fallback (escrow, ship-escrow, deposit, persistent-vault, zk-*, treasury, ...)
    return 'Type: ' + t + (c.locktime_daa ? ' | Locktime: ' + refund() : '');
}

// covRenderMetaLine(c): write the meta line into #cov-result-extra. If a timed
// field could only resolve to a raw DAA (no *_date_iso and no cached DAA),
// fetch the current DAA once and re-render so it shows an estimated date.
function covRenderMetaLine(c) {
    const node = el('cov-result-extra');
    if (!node || !c) return;
    node.textContent = covMetaLine(c);
    const timed = c.locktime_daa || c.deadline_daa || c.start_daa;
    const hasIso = c.locktime_date_iso || c.deadline_date_iso || c.start_date_iso;
    if (timed && !hasIso && (!window._lastKnownDaa || window._lastKnownDaa <= 0)) {
        fetchCurrentDaa().then(daa => {
            if (daa > 0) { window._lastKnownDaa = daa; node.textContent = covMetaLine(c); }
        }).catch(() => {});
    }
}

// Parse max_withdraw_sompi and cooldown_daa from an allowance redeem script hex.
// Scans for the int push before OP_SUB (0x94) and OP_CSV (0xb1).
function parseAllowanceScript(hexStr) {
    const result = { max_withdraw_sompi: 0, cooldown_daa: 0, start_daa: 0 };
    try {
        const bytes = hexToBytes(hexStr);
        let lastPush = 0;
        let i = 0;
        while (i < bytes.length) {
            const op = bytes[i];
            if (op === 0x94) { result.max_withdraw_sompi = lastPush; } // OP_SUB
            if (op === 0xb1) { result.cooldown_daa = lastPush; } // OP_CSV
            if (op === 0xb0) { result.start_daa = lastPush; } // OP_CLTV
            // Decode push
            if (op === 0x00) { lastPush = 0; i++; }
            else if (op >= 0x51 && op <= 0x60) { lastPush = op - 0x50; i++; }
            else if (op >= 0x01 && op <= 0x4b) {
                const len = op;
                if (i + 1 + len <= bytes.length) {
                    let val = 0n;
                    for (let j = 0; j < len; j++) val |= BigInt(bytes[i + 1 + j]) << BigInt(j * 8);
                    lastPush = Number(val);
                }
                i += 1 + len;
            } else if (op === 0x4c) { i += 2 + (bytes[i + 1] || 0); }
            else { i++; }
        }
    } catch (_) {}
    return result;
}

// Ensure an allowance covenant entry has max_withdraw_sompi and cooldown_daa.
// Parses from redeem script if missing.
function ensureAllowanceParams(c) {
    if (c.type !== 'global-spending-limit' && c.type !== 'global-allowance') return;
    if (c.max_withdraw_sompi && c.cooldown_daa) return;
    if (!c.redeem_script_hex) return;
    const parsed = parseAllowanceScript(c.redeem_script_hex);
    if (!c.max_withdraw_sompi && parsed.max_withdraw_sompi) c.max_withdraw_sompi = parsed.max_withdraw_sompi;
    if (!c.cooldown_daa && parsed.cooldown_daa) c.cooldown_daa = parsed.cooldown_daa;
    if (!c.start_daa && parsed.start_daa) c.start_daa = parsed.start_daa;
}

// Parse a 2-of-3 escrow redeem script (with arbiter).
// Extracts: alice_pk, bob_pk, arbiter_pk, alice_spk_hex, bob_spk_hex.
// Script layout (hex): 63 20 <alice_pk:64> ad 00 c3 24 0000 20 <bob_dest_pk:64> ac 88 51
//                      67 63 20 <bob_pk:64> ad 00 c3 24 0000 20 <alice_dest_pk:64> ac 88 51
//                      67 20 <arbiter_pk:64> ad 63 ...
// 3 ENDIFs (68 68 68) at end.
function parseEscrowScript(hexStr) {
    const result = { alice_pk: '', bob_pk: '', arbiter_pk: '', alice_spk_hex: '', bob_spk_hex: '', salt: '' };
    try {
        const h = hexStr;
        // Script starts with: 08 <8B salt> 75(OP_DROP) 63(OP_IF) 20(PUSH32)
        // Salt prefix = 20 hex chars. Then OP_IF at hex offset 20, PUSH32 at 22.
        const S = 20; // salt prefix offset
        if (h.substring(S, S + 4) !== '6320') return result;
        result.salt = h.substring(2, 18); // 8 bytes salt at hex[2..18]
        // Alice pubkey at hex offset S+4..S+68
        result.alice_pk = h.substring(S + 4, S + 68);
        // bob_dest_pk at hex offset S+82
        result.bob_spk_hex = h.substring(S + 82, S + 82 + 64);
        // Path 2 starts at hex S+152: 67 63 20 (ELSE IF PUSH32)
        const path2Start = S + 152;
        if (h.substring(path2Start, path2Start + 6) !== '676320') return result;
        result.bob_pk = h.substring(path2Start + 6, path2Start + 6 + 64);
        // alice_dest_pk at path2Start + 84
        result.alice_spk_hex = h.substring(path2Start + 84, path2Start + 84 + 64);
        // arbiter_pk at path2Start + 84 + 64 + 12 = path2Start + 160
        const arbiterOffset = path2Start + 84 + 64 + 12;
        if (h.substring(arbiterOffset - 2, arbiterOffset) !== '20') {
            return result;
        }
        result.arbiter_pk = h.substring(arbiterOffset, arbiterOffset + 64);
    } catch (_) {}
    return result;
}

// Parse the role pubkeys from a supply-chain (state machine) redeem script.
// The script embeds one "OP_DATA_32 <32-byte pubkey> OP_CHECKSIGVERIFY (0xad)"
// per state, in order: [manufacturer, shipper, receiver]. The walk is
// opcode-aware so data bytes (salt, amount pushes) are never misread as
// OP_DATA_32 — the same hazard the firmware scanner had with 0x20 salt bytes.

// Populate supply-chain role pubkeys from the redeem script if missing.

function ensureEscrowParams(c) {
    if (c.type !== 'escrow') return;
    if (c.alice_pk && c.bob_pk && c.arbiter_pk) return;
    if (!c.redeem_script_hex) return;
    const parsed = parseEscrowScript(c.redeem_script_hex);
    if (!c.alice_pk && parsed.alice_pk) c.alice_pk = parsed.alice_pk;
    if (!c.bob_pk && parsed.bob_pk) c.bob_pk = parsed.bob_pk;
    if (!c.arbiter_pk && parsed.arbiter_pk) c.arbiter_pk = parsed.arbiter_pk;
    if (!c.alice_spk_hex && parsed.alice_spk_hex) c.alice_spk_hex = parsed.alice_spk_hex;
    if (!c.bob_spk_hex && parsed.bob_spk_hex) c.bob_spk_hex = parsed.bob_spk_hex;
}

// Parse threshold_sompi and deadline_daa from a piggy bank redeem script hex.
// threshold: push before first OP_GREATERTHANOREQUAL (0xa5)
// deadline: push before OP_CLTV (0xb0)
function parsePiggyScript(hexStr) {
    const result = { threshold_sompi: 0, deadline_daa: 0 };
    try {
        const bytes = hexToBytes(hexStr);
        let lastPush = 0;
        let foundFirstGte = false;
        let i = 0;
        while (i < bytes.length) {
            const op = bytes[i];
            if (op === 0xa5 && !foundFirstGte) { result.threshold_sompi = lastPush; foundFirstGte = true; }
            if (op === 0xb0) { result.deadline_daa = lastPush; }
            // Decode push
            if (op === 0x00) { lastPush = 0; i++; }
            else if (op >= 0x51 && op <= 0x60) { lastPush = op - 0x50; i++; }
            else if (op >= 0x01 && op <= 0x4b) {
                const len = op;
                if (i + 1 + len <= bytes.length) {
                    let val = 0n;
                    for (let j = 0; j < len; j++) val |= BigInt(bytes[i + 1 + j]) << BigInt(j * 8);
                    lastPush = Number(val);
                }
                i += 1 + len;
            } else if (op === 0x4c) { i += 2 + (bytes[i + 1] || 0); }
            else { i++; }
        }
    } catch (_) {}
    return result;
}

// Ensure a piggy bank covenant entry has threshold_sompi and deadline_daa.
function ensurePiggyParams(c) {
    if (c.type !== 'additive') return;
    if (c.threshold_sompi && c.deadline_daa) return;
    if (!c.redeem_script_hex) return;
    const parsed = parsePiggyScript(c.redeem_script_hex);
    if (!c.threshold_sompi && parsed.threshold_sompi) c.threshold_sompi = parsed.threshold_sompi;
    if (!c.deadline_daa && parsed.deadline_daa) c.deadline_daa = parsed.deadline_daa;
}

function covUpdateResultButtons(type) {
    const beneBtn = el('btn-cov-res-bene');
    const ownerBtn = el('btn-cov-res-owner');
    const consolBtn = el('btn-cov-res-consolidate');
    const fundBtn = el('btn-cov-fund');
    if (!beneBtn) return;
    // Reset visibility
    if (fundBtn) fundBtn.style.display = '';
    beneBtn.style.display = '';
    ownerBtn.style.display = '';
    if (consolBtn) consolBtn.style.display = 'none';

    // When loaded via invite (not created), hide owner-only buttons
    const isLoaded = lastCovenantResult && lastCovenantResult.loaded;
    const covRole = lastCovenantResult && lastCovenantResult.role;
    const isBeneficiary = isLoaded && covRole === 'beneficiary';
    const isRecoveredOwner = isLoaded && covRole === 'owner';
    const hasTimelockType = ['dms', 'escrow', 'timelocked-escrow', 'global-allowance', 'oracle'].includes(type);
    if (isBeneficiary && hasTimelockType) {
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
    }

    if (type === 'additive') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        beneBtn.style.display = 'none'; // Not used for piggy
        ownerBtn.textContent = 'Break Piggy Bank';
        if (consolBtn) consolBtn.style.display = 'none';
        // fundBtn toggles between Deposit (unfunded) and Add Funds (funded) after balance fetch
    } else if (type === 'global-allowance') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        beneBtn.textContent = 'Beneficiary Withdraw';
        ownerBtn.textContent = 'Owner Reclaim';
        if (consolBtn) consolBtn.style.display = 'none';
        // Owner sees Fund + Reclaim + Share. Beneficiary sees Withdraw only.
        if (isBeneficiary) {
            ownerBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
        } else {
            beneBtn.style.display = 'none';
        }
    } else if (type === 'atomic-swap') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        beneBtn.textContent = 'Claim (Preimage)';
        ownerBtn.textContent = 'Owner Refund';
    } else if (type === 'dms') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        ownerBtn.textContent = '\u2764\uFE0F Heartbeat (Reset Timer)';
        // Owner sees: Deposit, Withdraw, Heartbeat, Share with Heir.
        // Heir sees: Heir Claim only.
        if (isBeneficiary) {
            beneBtn.textContent = 'Heir Claim';
            beneBtn.style.display = '';
            ownerBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
        } else {
            beneBtn.textContent = 'Withdraw';
            beneBtn.style.display = '';
        }
    } else if (type === 'timelocked-savings') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        beneBtn.textContent = 'Claim Funds';
        beneBtn.style.display = '';
        ownerBtn.style.display = 'none'; // no owner-spend-anytime branch: time is the only gate
        if (consolBtn) consolBtn.style.display = 'none';
    } else if (type === 'adaptor-swap') {
        if (fundBtn) fundBtn.style.display = 'none';
        ownerBtn.textContent = 'Owner Refund (after timeout)';
        // Check if claim recovery data is available
        let hasRecovery = false;
        try {
            const covAddr = lastCovenantResult ? lastCovenantResult.address : '';
            const rec = JSON.parse(sessionStorage.getItem('kassee_adaptor_recovery_' + covAddr) || 'null');
            if (rec && rec.counterAddr && rec.counterRedeem && rec.myAdaptorSig && rec.counterAdaptorSig) {
                hasRecovery = true;
            }
        } catch (_) {}
        if (hasRecovery) {
            beneBtn.textContent = 'Recover Claim (extract secret)';
            beneBtn.style.display = '';
            beneBtn.onclick = () => handleAdaptorRecoverClaim();
        } else {
            beneBtn.style.display = 'none';
        }
    } else if (type === 'escrow') {
        const isArbiter = isLoaded && covRole === 'arbiter';
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        if (consolBtn) consolBtn.style.display = 'none'; // reset
        if (isBeneficiary) {
            // Seller: can refund to buyer or request arbitration
            beneBtn.textContent = 'Refund to Buyer';
            beneBtn.style.display = '';
            ownerBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
            if (consolBtn) {
                consolBtn.textContent = '\u2696\uFE0F Request Arbitration';
                consolBtn.style.display = '';
                consolBtn.style.fontSize = '';
            }
        } else if (isArbiter) {
            // Arbiter: can award seller or refund buyer
            ownerBtn.textContent = 'Award to Seller';
            ownerBtn.style.display = '';
            beneBtn.textContent = 'Refund to Buyer';
            beneBtn.style.display = '';
            if (fundBtn) fundBtn.style.display = 'none';
        } else {
            // Buyer (owner): can release to seller or request arbitration
            ownerBtn.textContent = 'Release to Seller';
            beneBtn.style.display = 'none';
            if (consolBtn) {
                consolBtn.textContent = '\u2696\uFE0F Request Arbitration';
                consolBtn.style.display = '';
                consolBtn.style.fontSize = '';
            }
        }
    } else if (type === 'crowdfund') {
        const isCfContributor = lastCovenantResult && lastCovenantResult.crowdfund_role === 'contributor';
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        if (isCfContributor) {
            ownerBtn.textContent = 'Refund (after deadline)';
            beneBtn.style.display = 'none'; // contributor has no sweep role
        } else {
            ownerBtn.textContent = 'Refund (after deadline)';
            beneBtn.style.display = 'none'; // sweep is via the panel below, not this button
        }
    } else if (type === 'oracle') {
        const isOracle = covRole === 'oracle';
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        if (isOracle) {
            // Oracle: can only attest and beacon. No spend buttons.
            ownerBtn.style.display = 'none';
            beneBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
        } else if (isBeneficiary) {
            // Beneficiary: can claim with attestation. No owner buttons.
            beneBtn.textContent = 'Claim with Attestation';
            beneBtn.style.display = '';
            ownerBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
        } else {
            // Owner: can deposit, refund after timeout. No beneficiary claim.
            ownerBtn.textContent = 'Owner Refund';
            beneBtn.style.display = 'none';
        }
    } else if (type === 'merkle-whitelist') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        ownerBtn.textContent = 'Owner Refund';
        beneBtn.textContent = 'Whitelisted Spend';
        beneBtn.style.display = '';
        beneBtn.onclick = () => {
            if (lastCovenantResult) {
                el('cov-mw-addr').value = lastCovenantResult.address || '';
                el('cov-mw-script').value = lastCovenantResult.redeem_script_hex || '';
                const activeEntry = activeCovenants.find(c => c.address === lastCovenantResult.address);
                const addrJson = (activeEntry && activeEntry.merkle_addresses_json) || lastCovenantResult.merkle_addresses_json || '';
                if (addrJson) {
                    try { el('cov-mw-spend-addresses').value = JSON.parse(addrJson).join('\n'); } catch (_) {}
                }
            }
            covShowPanel('mw-spend');
        };
    } else if (type === 'payjoin') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        ownerBtn.textContent = 'Owner Refund';
        beneBtn.textContent = 'PayJoin Claim';
        if (isBeneficiary) {
            // Beneficiary: only PayJoin Claim
            ownerBtn.style.display = 'none';
            if (fundBtn) fundBtn.style.display = 'none';
            beneBtn.style.display = '';
        } else {
            // Owner: Deposit + Refund + Share. No claim.
            beneBtn.style.display = 'none';
        }
        beneBtn.onclick = () => {
            if (lastCovenantResult) {
                el('cov-payjoin-claim-addr').value = lastCovenantResult.address || '';
                el('cov-payjoin-claim-script').value = lastCovenantResult.redeem_script_hex || '';
            }
            // Pre-fill mixing address from loaded wallet
            if (walletData) {
                try {
                    const w = JSON.parse(walletData);
                    if (w.receive_addresses && w.receive_addresses[0]) {
                        el('cov-payjoin-claim-mix-addr').value = w.receive_addresses[0];
                    }
                } catch (_) {}
            }
            covShowPanel('payjoin-claim');
        };
    } else if (type === 'ship-escrow') {
        // Buyer (creator) funds the full pot; all parties operate via the ship panel.
        const isShipCreator = (lastCovenantResult && lastCovenantResult.is_creator) || !isLoaded;
        if (fundBtn) {
            fundBtn.textContent = 'Fund Covenant (total)';
            fundBtn.style.display = isShipCreator ? '' : 'none';
        }
        ownerBtn.style.display = 'none';
        beneBtn.style.display = 'none';
        let shipBtn = el('btn-cov-ship-open');
        if (!shipBtn) {
            shipBtn = document.createElement('button');
            shipBtn.id = 'btn-cov-ship-open';
            shipBtn.className = 'btn btn-outline';
            shipBtn.style.cssText = 'width:100%;margin-bottom:8px;font-size:14px';
            shipBtn.textContent = 'Operate Shipment Escrow';
            const backBtn = el('btn-cov-result-back');
            if (backBtn) backBtn.parentElement.insertBefore(shipBtn, backBtn);
        }
        shipBtn.style.display = '';
        shipBtn.onclick = () => {
            if (lastCovenantResult) {
                el('cov-ship-addr').value = lastCovenantResult.address || '';
                el('cov-ship-script').value = lastCovenantResult.redeem_script_hex || '';
            }
            covShowPanel('ship');
        };
    } else if (type === 'commit-reveal') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        ownerBtn.textContent = 'Owner Refund';
        beneBtn.textContent = 'Reveal & Spend';
        beneBtn.style.display = '';
        beneBtn.onclick = () => {
            if (!lastCovenantResult) return;
            const ctHex = lastCovenantResult.cr_ciphertext_hex || '';
            if (!ctHex) {
                toast('No ciphertext found. Recover from backup file first.', 'error', 4000);
                return;
            }
            // Show ciphertext as QR for KasSigner to scan and decrypt
            // KasSigner: Single Signature -> Decrypt Secret -> scan this QR
            const ctBytes = new Uint8Array(ctHex.match(/.{2}/g).map(b => parseInt(b, 16)));
            el('cov-cr-addr').value = lastCovenantResult.address || '';
            el('cov-cr-script').value = lastCovenantResult.redeem_script_hex || '';
            // Store ciphertext bytes for QR display
            window._crDecryptCtBytes = ctBytes;
            covShowPanel('cr-reveal');
        };
    } else if (type === 'global-spending-limit') {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        ownerBtn.textContent = 'Owner Spend';
        beneBtn.style.display = 'none'; // owner-only covenant, no beneficiary path in script
    } else {
        if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
        beneBtn.textContent = 'Beneficiary Spend';
        ownerBtn.textContent = 'Owner Spend';
    }
    // Show swap share/scan buttons only for atomic-swap
    const shareSwap = el('btn-cov-res-share-swap');
    const scanSwap = el('btn-cov-res-scan-swap');
    if (shareSwap) shareSwap.style.display = type === 'atomic-swap' ? '' : 'none';
    if (scanSwap) scanSwap.style.display = type === 'atomic-swap' ? '' : 'none';
    // Verify Revelation button for commit-reveal
    let verifyBtn = el('btn-cov-cr-verify-entry');
    if (!verifyBtn && type === 'commit-reveal') {
        verifyBtn = document.createElement('button');
        verifyBtn.id = 'btn-cov-cr-verify-entry';
        verifyBtn.className = 'btn btn-outline';
        verifyBtn.style.cssText = 'width:100%;margin-top:8px;font-size:14px';
        verifyBtn.textContent = 'Verify Revelation';
        const backBtn = el('btn-cov-result-back');
        if (backBtn) backBtn.parentElement.insertBefore(verifyBtn, backBtn);
    }
    if (verifyBtn) {
        verifyBtn.style.display = type === 'commit-reveal' ? '' : 'none';
        verifyBtn.onclick = () => covShowPanel('cr-verify');
    }
    // Generic covenant invite share button
    const shareCov = el('btn-cov-res-share-cov');
    const covShareTypes = ['additive', 'dms', 'timelocked-savings', 'escrow', 'timelocked-escrow', 'global-allowance', 'treasury', 'payjoin', 'oracle', 'crowdfund'];
    // Show crowdfund sweep panel for organizer only
    if (el('crowdfund-sweep-panel')) {
        const isOrganizer = type === 'crowdfund' && lastCovenantResult && lastCovenantResult.crowdfund_role !== 'contributor';
        el('crowdfund-sweep-panel').style.display = isOrganizer ? '' : 'none';
        if (isOrganizer && lastCovenantResult) {
            // Display campaign info
            const infoEl = el('crowdfund-campaign-info');
            if (infoEl) {
                const name = lastCovenantResult.campaign_name || 'Unnamed Campaign';
                const goal = lastCovenantResult.goal_kas || '?';
                const cid = lastCovenantResult.campaign_id || '';
                infoEl.innerHTML = '<b>' + name + '</b> — Goal: ' + goal + ' KAS' +
                    (cid ? '<br><span style="font-size:9px;color:var(--text-dim)">ID: ' + cid.substring(0, 16) + '...</span>' : '');
            }
            // Auto-add organizer's own address
            const ta = el('crowdfund-sweep-addrs');
            if (lastCovenantResult.address && !ta.value.includes(lastCovenantResult.address)) {
                ta.value = lastCovenantResult.address;
            }
            // Start contributor watcher
            if (lastCovenantResult.campaign_id) {
                crowdfundWatcherStart(lastCovenantResult.campaign_id);
            }
        }
    }
    if (shareCov) {
        const isCrowdfundContributor = type === 'crowdfund' && lastCovenantResult && lastCovenantResult.crowdfund_role === 'contributor';
        const isEscrowNonOwner = type === 'escrow' && covRole && covRole !== 'owner';
        const isOracleRole = type === 'oracle' && covRole === 'oracle';
        // Supply chain: only the creator shares invites to the other parties.
        const scIsCreatorShare = (lastCovenantResult && lastCovenantResult.is_creator) || !isLoaded;
        const isScNonCreator = false;
        shareCov.style.display = (covShareTypes.includes(type) && !isBeneficiary && !isCrowdfundContributor && !isEscrowNonOwner && !isOracleRole && !isScNonCreator) ? '' : 'none';
        // Share label: the piggy shares a plain receive address (not a multi-party
        // invite to import), so it reads as an address and the user does not try to
        // load it via "Scan Covenant Invite QR". Other types keep the invite label.
        shareCov.textContent = (type === 'additive')
            ? '\uD83D\uDCE4 Share Piggy Bank Address'
            : '\uD83D\uDCE4 Share Covenant Invite QR';
    }
    // Oracle-specific: share with oracle button — HIDDEN, unified share covers both roles
    const shareOracle = el('btn-cov-res-share-oracle');
    if (shareOracle) {
        shareOracle.style.display = 'none';
    }
    // Oracle-specific: oracle attest button (oracle role only)
    const oracleAttest = el('btn-cov-res-oracle-attest');
    if (oracleAttest) {
        oracleAttest.style.display = (type === 'oracle' && covRole === 'oracle') ? '' : 'none';
    }
    // Oracle: scan attestation button — HIDDEN, attestation comes from on-chain beacon
    const scanAttest = el('btn-cov-res-scan-attestation');
    if (scanAttest) {
        scanAttest.style.display = 'none';
    }
    // Oracle: show saved attestation text on result panel
    const resAttText = el('cov-res-attest-text');
    if (resAttText) {
        resAttText.style.display = 'none';
        resAttText.textContent = '';
        if (type === 'oracle' && lastCovenantResult) {
            try {
                const attestations = JSON.parse(localStorage.getItem('oracleAttestations') || '[]');
                const saved = attestations.find(a => a.covenant_address === lastCovenantResult.address);
                if (saved && saved.text) {
                    resAttText.textContent = 'Oracle attested: ' + saved.text;
                    resAttText.style.display = '';
                }
            } catch (_) {}
        }
    }
}

function covShowPanel(panel) {
    // Stale-state guard: the piggy break-status banner belongs to the additive
    // owner flow only; hide on every panel switch, the additive entry re-shows it.
    const pb = el('cov-piggy-status-banner');
    if (pb) pb.classList.add('hidden');
    ['cov-menu', 'cov-create-panel', 'cov-result-panel', 'cov-owner-panel', 'cov-borrower-panel', 'cov-beneficiary-panel', 'cov-timeout-panel', 'cov-balance-panel', 'cov-atomic-claim-panel', 'cov-oracle-claim-panel', 'cov-oracle-attest-panel', 'cov-payjoin-claim-panel', 'cov-cr-reveal-panel', 'cov-cr-verify-panel', 'cov-mw-spend-panel', 'cov-load-panel', 'cov-consolidate-panel', 'cov-adaptor-panel', 'cov-adaptor-create-panel', 'cov-adaptor-result-panel', 'cov-adaptor-join-panel', 'cov-tagged-vault-panel', 'cov-ship-panel', 'cov-oracle-mb-panel'].forEach(id => {
        const e = el(id);
        if (e) e.classList.add('hidden');
    });
    covActiveWatcherStop();
    oracleMbAmbientStop();
    if (panel === 'menu') { el('cov-menu').classList.remove('hidden'); covFetchBalances(); swapWatcherStop(); covWatcherStop(); if (_adaptorResultPollTimer) { clearInterval(_adaptorResultPollTimer); _adaptorResultPollTimer = null; } covActiveWatcherStart(); }
    if (panel === 'create') { el('cov-create-panel').classList.remove('hidden'); }
    if (panel === 'result') { el('cov-result-panel').classList.remove('hidden'); if (el('cov-result-txid-wrap')) el('cov-result-txid-wrap').style.display = 'none'; swapWatcherStart(); covWatcherStart(); }
    if (panel === 'owner') { el('cov-owner-panel').classList.remove('hidden'); }
    if (panel === 'borrower') { el('cov-borrower-panel').classList.remove('hidden'); }
    if (panel === 'beneficiary') { el('cov-beneficiary-panel').classList.remove('hidden'); }
    if (panel === 'timeout') { el('cov-timeout-panel').classList.remove('hidden'); }
    if (panel === 'balance') { el('cov-balance-panel').classList.remove('hidden'); }
    if (panel === 'atomic-claim') { el('cov-atomic-claim-panel').classList.remove('hidden'); }
    if (panel === 'oracle-claim') { el('cov-oracle-claim-panel').classList.remove('hidden'); }
    if (panel === 'oracle-attest') { el('cov-oracle-attest-panel').classList.remove('hidden'); }
    if (panel === 'payjoin-claim') { el('cov-payjoin-claim-panel').classList.remove('hidden'); }
    if (panel === 'consolidate') { el('cov-consolidate-panel').classList.remove('hidden'); }
    if (panel === 'cr-reveal') { el('cov-cr-reveal-panel').classList.remove('hidden'); }
    if (panel === 'cr-verify') { el('cov-cr-verify-panel').classList.remove('hidden'); }
    if (panel === 'mw-spend') { el('cov-mw-spend-panel').classList.remove('hidden'); }
    if (panel === 'tagged-vault') { el('cov-tagged-vault-panel').classList.remove('hidden'); }
    if (panel === 'load') { el('cov-load-panel').classList.remove('hidden'); }
    if (panel === 'adaptor') {
        el('cov-adaptor-panel').classList.remove('hidden');
        const activeCard = el('adaptor-hub-active');
        if (_adaptorState && _adaptorState.myPk && activeCard) {
            activeCard.classList.remove('hidden');
            el('adaptor-hub-role').textContent = _adaptorState.role === 'alice' ? 'Initiator' : 'Responder';
            el('adaptor-hub-addr').textContent = _adaptorState.myAddr || 'Setting up...';
            el('adaptor-hub-status').textContent = _adaptorState.completed ? 'Completed' : 'In progress';
        } else if (activeCard) {
            activeCard.classList.add('hidden');
        }
    }
    if (panel === 'adaptor-create') { el('cov-adaptor-create-panel').classList.remove('hidden'); }
    if (panel === 'adaptor-result') {
        el('cov-adaptor-result-panel').classList.remove('hidden');
        if (_adaptorState) {
            const s = _adaptorState;
            const role = s.role;
            const hasCounter = !!s.counterPk;
            const hasAddr = !!s.myAddr;
            const kas = s.myAmount ? (s.myAmount / 1e8) : 0;

            // Title and role badge
            el('adaptor-result-title').textContent = 'Private Swap';
            const badge = el('adaptor-result-role-badge');
            if (role === 'alice') {
                badge.textContent = 'Initiator';
                badge.style.background = 'rgba(255,214,0,0.15)'; badge.style.color = '#ffd600';
            } else {
                badge.textContent = 'Responder';
                badge.style.background = 'rgba(0,200,150,0.15)'; badge.style.color = 'var(--teal)';
            }

            // Your UTXO
            el('adaptor-result-addr').textContent = hasAddr ? s.myAddr : 'Waiting for counterparty response';
            el('adaptor-result-balance').textContent = hasAddr ? '' : kas + ' KAS (to offer)';

            // Counterparty info
            const counterBox = el('adaptor-result-counter-box');
            if (hasCounter) {
                counterBox.classList.remove('hidden');
                let cAddr = s.counterAddr || '';
                // Bob can compute Alice's UTXO address (locked to Bob's pk)
                if (!cAddr && role === 'bob' && s.myPk && s.counterOwnerPk) {
                    try {
                        const cJson = JSON.parse(adaptor_swap_address(
                            s.myPk, s.counterOwnerPk,
                            s.myDestAddr || '',
                            BigInt(String(s.counterTimeoutDaa || 0)), network
                        ));
                        cAddr = cJson.address;
                        s.counterAddr = cAddr;
                        adaptorStateSave();
                    } catch (_) {}
                }
                el('adaptor-result-counter-addr').textContent = cAddr || 'Pending';
                const cKas = s.counterAmount ? (s.counterAmount / 1e8) : 0;
                el('adaptor-result-counter-balance').textContent = cKas ? cKas + ' KAS' : '';
            } else {
                counterBox.classList.add('hidden');
            }

            // Timeout display
            const timeoutDaa = role === 'alice' ? s.myTimeoutDaa : (s.myTimeoutDaa || s.counterTimeoutDaa);
            if (timeoutDaa) {
                el('adaptor-result-timeout').textContent = '';
            }

            // Buttons: hide all first, then show based on state
            ['btn-adaptor-fund', 'btn-adaptor-share-invite', 'btn-adaptor-scan-response',
             'btn-adaptor-complete-claim', 'btn-adaptor-owner-refund'].forEach(id => {
                const b = el(id); if (b) b.style.display = 'none';
            });

            if (role === 'alice') {
                if (!hasCounter) {
                    // Step 1: share invite, then scan response
                    el('btn-adaptor-share-invite').style.display = '';
                    el('btn-adaptor-scan-response').style.display = '';
                    el('adaptor-result-status').textContent = 'Step 1: Share your invite QR with your counterparty, then scan their response.';
                    el('adaptor-result-status').style.color = 'var(--text-muted)';
                } else if (hasAddr) {
                    // Step 2: fund, then claim
                    el('btn-adaptor-fund').style.display = '';
                    el('btn-adaptor-complete-claim').style.display = '';
                    el('btn-adaptor-complete-claim').textContent = 'Claim Counterparty Funds';
                    el('btn-adaptor-owner-refund').style.display = '';
                    el('adaptor-result-status').textContent = 'Step 2: Fund your address, then claim counterparty funds.';
                    el('adaptor-result-status').style.color = 'var(--teal)';
                }
            } else if (role === 'bob') {
                if (hasAddr) {
                    el('btn-adaptor-fund').style.display = '';
                    el('btn-adaptor-complete-claim').style.display = '';
                    el('btn-adaptor-complete-claim').textContent = 'Claim (extract secret)';
                    el('btn-adaptor-owner-refund').style.display = '';
                    el('adaptor-result-status').textContent = 'Fund your address. Wait for counterparty to claim first, then claim theirs.';
                    el('adaptor-result-status').style.color = 'var(--teal)';
                }
            }

            // Start balance polling and watcher
            adaptorWatcherStart();
            adaptorResultPoll();
            if (_adaptorResultPollTimer) clearInterval(_adaptorResultPollTimer);
            _adaptorResultPollTimer = setInterval(adaptorResultPoll, 5000);
        }
    }
    if (panel === 'adaptor-join') { el('cov-adaptor-join-panel').classList.remove('hidden'); }
    if (panel === 'ship') { el('cov-ship-panel').classList.remove('hidden'); shipPanelRefresh(); }
    if (panel === 'oracle-mb') { el('cov-oracle-mb-panel').classList.remove('hidden'); oracleMbCardOpen(); }
}

function covTypeChanged() {
    const t = el('cov-type').value;
    const isEscrow = t === 'escrow';
    const isShipEscrow = t === 'ship-escrow';
    const isSavings = t === 'timelocked-savings';
    const isTlEscrow = t === 'timelocked-escrow';
    const isDms = t === 'dms';
    const isGSplimit = t === 'global-spending-limit';
    const isGAllowance = t === 'global-allowance';
    const isTreasury = t === 'treasury';
    const isSwap = t === 'atomic-swap';
    const isOracle = t === 'oracle';
    const isPayjoin = t === 'payjoin';
    const isCommitReveal = t === 'commit-reveal';
    const isMerkleWhitelist = t === 'merkle-whitelist';
    const isCrowdfund = t === 'crowdfund';
    const isPiggy = t === 'additive';
    const hasSimple = !isPiggy && !isEscrow && !isShipEscrow && !isTlEscrow && !isDms && !isGSplimit && !isGAllowance && !isTreasury && !isSwap && !isOracle && !isPayjoin && !isCommitReveal && !isMerkleWhitelist && !isCrowdfund && !isSavings;
    el('cov-fields-simple').classList.toggle('hidden', !hasSimple);
    el('cov-fields-piggy').classList.toggle('hidden', !isPiggy);
    el('cov-fields-escrow').classList.toggle('hidden', !isEscrow);
    if (el('cov-fields-ship-escrow')) el('cov-fields-ship-escrow').classList.toggle('hidden', !isShipEscrow);
    if (el('cov-fields-savings')) el('cov-fields-savings').classList.toggle('hidden', !isSavings);
    if (el('cov-fields-tl-escrow')) el('cov-fields-tl-escrow').classList.toggle('hidden', !isTlEscrow);
    if (el('cov-fields-dms')) el('cov-fields-dms').classList.toggle('hidden', !isDms);
    if (el('cov-fields-splimit')) el('cov-fields-splimit').classList.toggle('hidden', !isGSplimit);
    el('cov-fields-allowance').classList.toggle('hidden', !isGAllowance);
    if (el('cov-fields-treasury')) el('cov-fields-treasury').classList.toggle('hidden', !isTreasury);
    if (el('cov-fields-atomic-swap')) el('cov-fields-atomic-swap').classList.toggle('hidden', !isSwap);
    el('cov-fields-oracle').classList.toggle('hidden', !isOracle);
    el('cov-fields-payjoin').classList.toggle('hidden', !isPayjoin);
    el('cov-fields-commit-reveal').classList.toggle('hidden', !isCommitReveal);
    el('cov-fields-merkle-whitelist').classList.toggle('hidden', !isMerkleWhitelist);
    if (el('cov-fields-crowdfund')) el('cov-fields-crowdfund').classList.toggle('hidden', !isCrowdfund);
}

// Does the loaded wallet own this x-only pubkey? Checks the account-level
// key plus EVERY receive and change address payload — a counterparty may
// have shared any index from their device, not just /0/0. Matching only
// /0/0 made escrow role detection fail whenever the shared address was at
// a browsed index (arbiter got seller tabs).
function walletMatchesPk(target) {
    if (!target || !walletData) return false;
    const acct = getAccountPubkeyHex();
    if (acct && acct === target) return true;
    try {
        const w = JSON.parse(walletData);
        const all = [...(w.receive_addresses || []), ...(w.change_addresses || [])];
        for (const a of all) {
            try {
                const d = JSON.parse(decode_address(a));
                if (d.payload && d.payload === target) return true;
            } catch (_) {}
        }
    } catch (_) {}
    return false;
}

function getOwnerPubkeyHex() {
    if (!walletData) return null;
    const w = JSON.parse(walletData);
    const addr0 = w.receive_addresses[0];
    const decoded = JSON.parse(decode_address(addr0));
    return decoded.payload || null;
}

// Get the account-level x-only pubkey (matches KaSigner's signing key)
function getAccountPubkeyHex() {
    if (!walletData) return null;
    const w = JSON.parse(walletData);
    if (!w.kpub) return null;
    const kpubInfo = JSON.parse(parse_kpub(w.kpub));
    return kpubInfo.account_pubkey || null;
}

async function handleCovGenerate() {
    const t = el('cov-type').value;
    let ownerPk = getAccountPubkeyHex();
    if (!ownerPk && t !== 'escrow') {
        toast('Load a wallet first (kpub)', 'error'); return;
    }

    try {
        let resultJson;
        let _covExtra = {}; // Carries counterparty keys for encrypted payload recovery
        if (t === 'additive') {
            const goalStr = el('cov-piggy-goal').value.trim();
            const kas = goalStr ? parseFloat(goalStr) : 0;
            const sompi = (goalStr && parseFloat(goalStr) > 0) ? kasToSompi(goalStr) : 0n;
            // Deadline: date picker to DAA
            let deadlineDaa = 0n;
            const dateVal = el('cov-piggy-deadline') ? el('cov-piggy-deadline').value : '';
            if (dateVal) {
                const targetMs = new Date(dateVal).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Pick a future date', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                try {
                    const wsUrl = await resolveNodeUrl();
                    const daaStr = await get_virtual_daa_score(wsUrl);
                    const currentDaa = BigInt(daaStr);
                    deadlineDaa = currentDaa + BigInt(secondsUntil * 10);
                    console.log('[KasSee] Piggy deadline: DAA~' + currentDaa + ' + ' + secondsUntil + 's = DAA ' + deadlineDaa);
                } catch (e) {
                    toast('Could not fetch DAA score: ' + e, 'error'); return;
                }
            }
            resultJson = covenant_additive_address(ownerPk, sompi, deadlineDaa, network);
            if (dateVal) _covExtra.deadline_date_iso = new Date(dateVal).toISOString();
        } else if (t === 'global-spending-limit') {
            const kas = parseFloat(el('cov-splimit-max').value);
            if (!kas || kas <= 0) { toast('Enter max withdrawal in KAS', 'error'); return; }
            const sompi = kasToSompi(el('cov-splimit-max').value);
            const cooldownSec = parseInt(el('cov-splimit-cooldown').value) || 0;
            if (cooldownSec <= 0) { toast('Set a cooldown period', 'error'); return; }
            const cooldownDaa = BigInt(cooldownSec * 10);
            resultJson = covenant_global_spending_limit(ownerPk, sompi, cooldownDaa, network);
            _covExtra.max_withdraw_sompi = sompi.toString();
            _covExtra.cooldown_daa = Number(cooldownDaa);
        } else if (t === 'escrow') {
            const theirPk = addrToXOnly(el('cov-escrow-pk').value);
            const arbiterPk = addrToXOnly(el('cov-escrow-arbiter-pk').value);
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            if (!theirPk || theirPk.length !== 64) { toast('Enter seller pubkey (64 hex chars)', 'error'); return; }
            if (!arbiterPk || arbiterPk.length !== 64) { toast('Enter arbiter pubkey (64 hex chars)', 'error'); return; }
            // Derive addresses from pubkeys. Use /0/0 receive address for buyer (matches wallet tracking).
            const w = JSON.parse(walletData);
            const myAddr = w.receive_addresses && w.receive_addresses[0] ? w.receive_addresses[0] : encode_p2pk_address(ownerPk, network);
            const theirAddr = encode_p2pk_address(theirPk, network);
            resultJson = covenant_escrow(ownerPk, theirPk, arbiterPk, myAddr, theirAddr, network);
            _covExtra.bob_pk = theirPk;
            _covExtra.arbiter_pk = arbiterPk;
        } else if (t === 'ship-escrow') {
            const sellerPk = addrToXOnly(el('cov-ship-seller-pk').value);
            const delivPk = addrToXOnly(el('cov-ship-deliverer-pk').value);
            const arbPk = addrToXOnly(el('cov-ship-arbiter-pk').value);
            if (!ownerPk) { toast('Load wallet first (you are the buyer)', 'error'); return; }
            if (!/^[0-9a-fA-F]{64}$/.test(sellerPk)) { toast('Enter seller pubkey (64 hex chars)', 'error'); return; }
            if (!/^[0-9a-fA-F]{64}$/.test(delivPk)) { toast('Enter deliverer pubkey (64 hex chars)', 'error'); return; }
            if (!/^[0-9a-fA-F]{64}$/.test(arbPk)) { toast('Enter arbiter pubkey (64 hex chars)', 'error'); return; }
            const product = parseFloat(el('cov-ship-product').value);
            const dfee = parseFloat(el('cov-ship-fee').value);
            if (!product || product <= 0) { toast('Enter product price in KAS', 'error'); return; }
            if (!dfee || dfee <= 0) { toast('Enter delivery fee in KAS', 'error'); return; }
            const cltv1 = BigInt(el('cov-ship-cltv1').value.trim() || '0');
            const cltv2 = BigInt(el('cov-ship-cltv2').value.trim() || '0');
            if (cltv1 <= 0n || cltv2 <= 0n) { toast('Set both deadlines (DAA score)', 'error'); return; }
            const productSompi = kasToSompi(el('cov-ship-product').value);
            const feeSompi = kasToSompi(el('cov-ship-fee').value);
            // Arg order: seller, deliverer, buyer(=owner), arbiter, product, fee, cltv1, cltv2, network
            resultJson = covenant_ship_escrow(sellerPk, delivPk, ownerPk, arbPk, productSompi, feeSompi, cltv1, cltv2, network);
            _covExtra.seller_pk = sellerPk;
            _covExtra.deliverer_pk = delivPk;
            _covExtra.buyer_pk = ownerPk;
            _covExtra.arbiter_pk = arbPk;
            _covExtra.seller_addr = encode_p2pk_address(sellerPk, network);
            _covExtra.deliverer_addr = encode_p2pk_address(delivPk, network);
            _covExtra.buyer_addr = encode_p2pk_address(ownerPk, network);
        } else if (t === 'timelocked-savings') {
            // Deposit-and-lock savings. wallet1 = the loaded wallet (primary).
            // wallet2 = optional independent recovery wallet; blank reuses wallet1
            // (no separate backup). No owner-spend-anytime branch: frozen for
            // everyone until the date, then 1-of-2 claim with a single signature.
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            let recoveryPk = el('cov-savings-recovery-pk') ? el('cov-savings-recovery-pk').value.trim() : '';
            if (!recoveryPk) {
                recoveryPk = ownerPk; // no separate recovery key
            } else if (recoveryPk.startsWith('kpub') || recoveryPk.startsWith('ktub')) {
                toast('Paste the recovery wallet address, not a kpub', 'error'); return;
            } else if (recoveryPk.startsWith('kaspa:') || recoveryPk.startsWith('kaspatest:')) {
                try {
                    const decoded = JSON.parse(decode_address(recoveryPk));
                    if (decoded.version !== 0) { toast('Recovery wallet must be a standard address (P2PK)', 'error'); return; }
                    if (!decoded.payload || decoded.payload.length !== 64) { toast('Could not read pubkey from that address', 'error'); return; }
                    recoveryPk = decoded.payload;
                    el('cov-savings-recovery-pk').value = recoveryPk;
                } catch (e) { toast('Invalid address: ' + e, 'error'); return; }
            }
            if (recoveryPk.length !== 64) { toast('Recovery wallet pubkey must be 64 hex chars (or leave blank)', 'error'); return; }
            // Datetime-to-DAA (10 BPS), same conversion as the vault.
            let locktime = el('cov-savings-locktime') ? el('cov-savings-locktime').value.trim() : '';
            const sDtEl = el('cov-savings-datetime');
            const sDtVal = sDtEl ? sDtEl.value : '';
            if (sDtVal && !locktime) {
                const targetMs = new Date(sDtVal).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Pick a future date and time', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    if (el('cov-savings-locktime')) el('cov-savings-locktime').value = locktime;
                    console.log('[KasSee] Savings: DAA~' + currentDaa + ' + ' + secondsUntil + 's = DAA ' + locktime);
                } else { toast('Could not fetch DAA score. Check node connection.', 'error'); return; }
            }
            if (!locktime || parseInt(locktime) <= 0) { toast('Set an unlock date (or DAA score)', 'error'); return; }
            resultJson = covenant_timelocked_savings(ownerPk, recoveryPk, BigInt(locktime), network);
            _covExtra.wallet1_pubkey_hex = ownerPk;
            _covExtra.wallet2_pubkey_hex = recoveryPk;
            if (sDtVal) _covExtra.locktime_date_iso = new Date(sDtVal).toISOString();
        } else if (t === 'timelocked-escrow') {
            toast('Timelocked Escrow removed — use Oracle covenant instead', 'info'); return;
        } else if (t === 'dms') {
            let heirPk = el('cov-dms2-heir-pk').value.trim();
            // Heir is given as a single Kaspa address. Decode it to the x-only
            // pubkey that the ELSE branch's CHECKSIG needs.
            if (heirPk.startsWith('kpub') || heirPk.startsWith('ktub')) {
                toast('Paste the heir address, not a kpub', 'error'); return;
            }
            if (heirPk.startsWith('kaspa:') || heirPk.startsWith('kaspatest:')) {
                try {
                    const decoded = JSON.parse(decode_address(heirPk));
                    if (decoded.version !== 0) {
                        toast('Heir must be a standard address (P2PK), not a script address', 'error'); return;
                    }
                    if (!decoded.payload || decoded.payload.length !== 64) {
                        toast('Could not read pubkey from that address', 'error'); return;
                    }
                    heirPk = decoded.payload;
                    el('cov-dms2-heir-pk').value = heirPk;
                } catch (e) {
                    toast('Invalid address: ' + e, 'error'); return;
                }
            }
            // Convert duration to DAA units (10 BPS)
            const durationSec = parseInt(el('cov-dms2-duration').value) || 0;
            if (durationSec <= 0) { toast('Set an inactivity period', 'error'); return; }
            const inactivityDaa = durationSec * 10;
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            if (!heirPk || heirPk.length !== 64) { toast('Enter the heir Kaspa address', 'error'); return; }
            resultJson = covenant_dms(ownerPk, heirPk, BigInt(inactivityDaa), network);
            // Inject inactivity_daa into result for storage
            const dmsResult = JSON.parse(resultJson);
            dmsResult.inactivity_daa = inactivityDaa;
            resultJson = JSON.stringify(dmsResult);
            _covExtra.heir_pubkey_hex = heirPk;
        } else if (t === 'global-allowance') {
            const benePk = el('cov-allowance-bene-pk').value.trim();
            if (!benePk || benePk.length < 32) { toast('Scan or paste the beneficiary address or x-only pubkey', 'error'); return; }
            // Resolve beneficiary pubkey (could be kpub, address, or raw hex)
            let benePkHex = benePk;
            if (benePk.startsWith('kpub') || benePk.startsWith('ktub')) {
                // Beneficiary privacy: a kpub exposes the whole account (every
                // derivable address). Require a SINGLE address or x-only pubkey,
                // so the owner only ever learns one key, never the account.
                toast('Use the beneficiary single address or x-only pubkey, not a kpub. A kpub would expose their whole account.', 'error', 6500);
                return;
            } else if (benePk.startsWith('kaspa') || benePk.startsWith('kaspatest')) {
                try {
                    const decoded = JSON.parse(decode_address(benePk));
                    benePkHex = decoded.payload;
                } catch (e) { toast('Invalid address: ' + e, 'error'); return; }
            }
            if (!benePkHex || benePkHex.length !== 64) { toast('Beneficiary pubkey must be 64 hex chars', 'error'); return; }
            const kas = parseFloat(el('cov-allowance-max').value);
            if (!kas || kas <= 0) { toast('Enter max withdrawal in KAS', 'error'); return; }
            const periodVal = el('cov-allowance-period').value;
            let seq;
            if (periodVal === 'custom') {
                seq = (parseInt(el('cov-allowance-seq').value) || 0) * 10;
                if (seq <= 0) { toast('Set a custom cooldown time', 'error'); return; }
            } else {
                seq = parseInt(periodVal) * 10;
            }
            const sompi = kasToSompi(el('cov-allowance-max').value);
            // Optional start date (vesting gate, CLTV in the beneficiary path)
            let startDaa = 0n;
            const startVal = el('cov-allowance-start') ? el('cov-allowance-start').value : '';
            if (startVal) {
                const targetMs = new Date(startVal).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Start date must be in the future', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                try {
                    const wsUrl = await resolveNodeUrl();
                    const daaStr = await get_virtual_daa_score(wsUrl);
                    const currentDaa = BigInt(daaStr);
                    startDaa = currentDaa + BigInt(secondsUntil * 10);
                    console.log('[KasSee] Global allowance start: DAA~' + currentDaa + ' + ' + secondsUntil + 's = DAA ' + startDaa);
                } catch (e) {
                    toast('Could not fetch DAA score: ' + e, 'error'); return;
                }
            }
            console.log('[KasSee] Global allowance: bene=' + benePkHex.substring(0,8) + '..., max=' + kas + ' KAS, cooldown=' + seq + ' blocks (' + formatDuration(seq) + '), start=' + (startDaa > 0n ? 'DAA ' + startDaa : 'immediate'));
            resultJson = covenant_global_allowance(ownerPk, benePkHex, sompi, BigInt(seq), startDaa, network);
            _covExtra.beneficiary_pubkey_hex = benePkHex;
            _covExtra.max_withdraw_sompi = sompi.toString();
            _covExtra.cooldown_daa = Number(seq);
            _covExtra.start_daa = Number(startDaa);
            if (startVal) _covExtra.start_date_iso = new Date(startVal).toISOString();
        } else if (t === 'treasury') {
            toast('Treasury removed — use Merkle Whitelist instead', 'info'); return;
        } else if (t === 'atomic-swap') {
            let counterPk = el('cov-swap-pk').value.trim();
            const expectedHash = el('cov-swap-hash').value.trim();
            const hashAlgo = el('cov-swap-hash-algo') ? el('cov-swap-hash-algo').value : 'blake2b';
            // Auto-convert kpub to x-only hex
            if (counterPk.startsWith('kpub') || counterPk.startsWith('ktub')) {
                try {
                    const importResult = JSON.parse(import_kpub(counterPk, network));
                    const firstAddr = importResult.receive_addresses[0];
                    const decoded = JSON.parse(decode_address(firstAddr));
                    if (decoded.payload && decoded.payload.length === 64) {
                        counterPk = decoded.payload;
                    } else {
                        toast('Could not derive pubkey from kpub', 'error'); return;
                    }
                } catch (e) {
                    toast('Invalid kpub: ' + e, 'error'); return;
                }
            }
            // Auto-convert kaspa address to x-only pubkey
            if (counterPk.startsWith('kaspa:') || counterPk.startsWith('kaspatest:')) {
                try {
                    const decoded = JSON.parse(decode_address(counterPk));
                    if (decoded.payload && decoded.payload.length === 64) {
                        counterPk = decoded.payload;
                    } else {
                        toast('Could not extract pubkey from address', 'error'); return;
                    }
                } catch (e) {
                    toast('Invalid address: ' + e, 'error'); return;
                }
            }
            // Datetime-to-DAA conversion
            let locktime = el('cov-swap-locktime').value.trim();
            const datetimeEl = el('cov-swap-datetime');
            const datetimeVal = datetimeEl ? datetimeEl.value : '';
            if (datetimeVal && !locktime) {
                const targetMs = new Date(datetimeVal).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) {
                    toast('Pick a future date and time', 'error');
                    return;
                }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    el('cov-swap-locktime').value = locktime;
                    console.log('[KasSee] HTLC: DAA~' + currentDaa + ' + ' + secondsUntil + 's*10 = DAA ' + locktime);
                } else {
                    toast('Could not fetch DAA score. Check node connection.', 'error');
                    return;
                }
            }
            if (!counterPk || counterPk.length !== 64) { toast('Enter counterparty pubkey, address, or kpub', 'error'); return; }
            if (!expectedHash || expectedHash.length !== 64) { toast('Enter expected hash (64 hex chars)', 'error'); return; }
            if (!locktime || parseInt(locktime) <= 0) { toast('Enter refund timeout', 'error'); return; }
            // Timeout safety: if joining a swap, your timeout must be at least 5 min shorter than the initiator's
            if (_swapCounterpartyInvite && _swapCounterpartyInvite.d) {
                const theirDaa = Number(_swapCounterpartyInvite.d);
                const myDaa = parseInt(locktime);
                const minGap = 3000; // ~5 minutes at 10 DAA/sec
                if (myDaa >= theirDaa) {
                    toast('Your timeout must be shorter than counterparty (' + theirDaa + ')', 'error');
                    return;
                }
                if (theirDaa - myDaa < minGap) {
                    const gapMin = Math.ceil((theirDaa - myDaa) / 600);
                    toast('Gap too small (' + gapMin + 'min). Need at least 5 min for safe claim.', 'error');
                    return;
                }
            }
            resultJson = covenant_atomic_swap(ownerPk, counterPk, expectedHash, BigInt(locktime), hashAlgo, network);
        } else if (t === 'oracle') {
            const benePk = addrToXOnly(el('cov-oracle-bene-pk').value);
            // Oracle pubkey is the ACCOUNT-LEVEL key (it must match the KasSigner
            // SIGN HASH attestation that drives CHECKSIGFROMSTACK), so it MUST be
            // derived from a kpub. An x-only address or raw 32-byte hex is the /0/0
            // receive key and would bake an oracle_pk the attestation can never
            // satisfy — reject anything that is not a kpub.
            const oracleField = el('cov-oracle-pk').value.trim();
            let oraclePk = '';
            if (oracleField.startsWith('kpub') || oracleField.startsWith('ktub')) {
                try {
                    oraclePk = JSON.parse(parse_kpub(oracleField)).account_pubkey;
                } catch (e) {
                    toast('Invalid oracle kpub: ' + e, 'error'); return;
                }
            } else if (oracleField) {
                toast('Oracle must be a KPUB (account-level), not an x-only address or pubkey', 'error', 3500);
                return;
            }
            let locktime = '';  // computed fresh from the datetime below — never seeded from the stale hidden field
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            if (!benePk || benePk.length !== 64) { toast('Enter beneficiary pubkey (64 hex chars)', 'error'); return; }
            if (!oraclePk || oraclePk.length !== 64) { toast('Scan the oracle kpub (account-level)', 'error'); return; }
            // The datetime picker is the single source of truth for the refund
            // timeout, so ALWAYS recompute the DAA from it. Reusing a stale hidden
            // locktime from a previous covenant would silently bake the OLD timeout
            // (wrong refund time) and yield the same P2SH address for a new date.
            const oracleDatetime = el('cov-oracle-datetime') ? el('cov-oracle-datetime').value : '';
            if (oracleDatetime) {
                const targetMs = new Date(oracleDatetime).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Pick a future date', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    el('cov-oracle-locktime').value = locktime;
                } else {
                    toast('Could not fetch current DAA. Try again.', 'error'); return;
                }
            }
            if (!locktime || parseInt(locktime) <= 0) { toast('Set a refund timeout date', 'error'); return; }
            resultJson = covenant_oracle(ownerPk, benePk, oraclePk, BigInt(locktime), network);
            _covExtra.oracle_pubkey_hex = oraclePk;
            _covExtra.beneficiary_pubkey_hex = benePk;
            if (oracleDatetime) _covExtra.locktime_date_iso = new Date(oracleDatetime).toISOString();
        } else if (t === 'payjoin') {
            const benePk = addrToXOnly(el('cov-payjoin-bene-pk').value);
            let locktime = el('cov-payjoin-locktime').value.trim();
            const pjDatetime = el('cov-payjoin-datetime') ? el('cov-payjoin-datetime').value : '';
            if (pjDatetime && !locktime) {
                const targetMs = new Date(pjDatetime).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Pick a future date', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    el('cov-payjoin-locktime').value = locktime;
                } else {
                    toast('Could not fetch DAA score. Check node connection.', 'error'); return;
                }
            }
            const minInputs = el('cov-payjoin-min-inputs').value.trim() || '2';
            const minOutputs = el('cov-payjoin-min-outputs').value.trim() || '2';
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            if (!benePk || benePk.length !== 64) { toast('Enter beneficiary pubkey (64 hex chars)', 'error'); return; }
            if (!locktime || parseInt(locktime) <= 0) { toast('Pick a refund timeout date', 'error'); return; }
            resultJson = covenant_payjoin(ownerPk, benePk, BigInt(locktime), BigInt(minInputs), BigInt(minOutputs), network);
            _covExtra.beneficiary_pubkey_hex = benePk;
            _covExtra.min_inputs = parseInt(minInputs);
            _covExtra.min_outputs = parseInt(minOutputs);
            if (pjDatetime) _covExtra.locktime_date_iso = new Date(pjDatetime).toISOString();
        } else if (t === 'commit-reveal') {
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            const hashRaw = el('cov-cr-hash-display').textContent.trim();
            const hashDisplay = hashRaw.startsWith('BLAKE2B: ') ? hashRaw.slice(9) : hashRaw;
            if (!hashDisplay || hashDisplay.length !== 64) { toast('Scan commitment from KasSigner first', 'error'); return; }
            let locktime = el('cov-cr-locktime').value.trim();
            const crDatetime = el('cov-cr-datetime') ? el('cov-cr-datetime').value : '';
            if (crDatetime && !locktime) {
                const targetMs = new Date(crDatetime).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) { toast('Pick a future date', 'error'); return; }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    el('cov-cr-locktime').value = locktime;
                } else {
                    toast('Could not fetch DAA score. Check node connection.', 'error'); return;
                }
            }
            if (!locktime || parseInt(locktime) <= 0) { toast('Pick a refund timeout date', 'error'); return; }
            resultJson = covenant_commit_reveal(ownerPk, hashDisplay, BigInt(locktime), network);
            _covExtra.commit_hash = hashDisplay;
            // Store ECIES ciphertext only (parts are never persisted in browser)
            const ctHex = el('cov-cr-ciphertext-hex') ? el('cov-cr-ciphertext-hex').value : '';
            if (ctHex) _covExtra.cr_ciphertext_hex = ctHex;
            if (crDatetime) _covExtra.locktime_date_iso = new Date(crDatetime).toISOString();
        } else if (t === 'merkle-whitelist') {
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            // Compute the merkle root inline from the whitelist (no separate button).
            const mwText = el('cov-mw-addresses').value.trim();
            if (!mwText) { toast('Enter whitelisted addresses', 'error'); return; }
            const mwAddrList = mwText.split('\n').map(a => a.trim()).filter(a => a.length > 0);
            if (mwAddrList.length < 2) { toast('Need at least 2 whitelisted addresses', 'error'); return; }
            let rootInfo;
            try {
                rootInfo = JSON.parse(merkle_root_from_addresses(JSON.stringify(mwAddrList), network));
            } catch (e) {
                toast('Merkle root failed: ' + e, 'error');
                return;
            }
            // Datetime-to-DAA conversion
            let locktime = el('cov-mw-locktime').value.trim();
            const mwDatetimeEl = el('cov-mw-datetime');
            const mwDatetimeVal = mwDatetimeEl ? mwDatetimeEl.value : '';
            if (mwDatetimeVal && !locktime) {
                const targetMs = new Date(mwDatetimeVal).getTime();
                const nowMs = Date.now();
                if (targetMs <= nowMs) {
                    toast('Pick a future date and time', 'error');
                    return;
                }
                const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                const currentDaa = await fetchCurrentDaa();
                if (currentDaa > 0) {
                    locktime = String(currentDaa + secondsUntil * 10);
                    el('cov-mw-locktime').value = locktime;
                    console.log('[KasSee] Merkle whitelist: DAA~' + currentDaa + ' + ' + secondsUntil + 's = DAA ' + locktime);
                } else {
                    toast('Could not fetch DAA score. Check node connection.', 'error');
                    return;
                }
            }
            if (!locktime || parseInt(locktime) <= 0) { toast('Pick a refund timeout date', 'error'); return; }
            resultJson = covenant_merkle_whitelist(ownerPk, rootInfo.root, rootInfo.depth, BigInt(locktime), network);
            // Capture whitelist addresses for payload backup and proof generation
            const mwAddrs = el('cov-mw-addresses').value.trim().split('\n').map(a => a.trim()).filter(a => a.length > 0);
            const mwResult = JSON.parse(resultJson);
            mwResult.merkle_addresses_json = JSON.stringify(mwAddrs);
            mwResult.merkle_root = rootInfo.root;
            mwResult.merkle_depth = rootInfo.depth;
            if (mwDatetimeVal) mwResult.locktime_date_iso = new Date(mwDatetimeVal).toISOString();
            resultJson = JSON.stringify(mwResult);
        } else if (t === 'crowdfund') {
            // Crowdfund: contributor creates their own P2SH
            // Organizer uses the same flow (they're also a contributor if they want)
            const isContributor = el('crowdfund-contributor-fields').style.display !== 'none';
            let vkHex, locktime;
            if (isContributor) {
                vkHex = el('cov-crowdfund-vk').value.trim();
                locktime = el('cov-crowdfund-contrib-locktime').value.trim();
            } else {
                // Organizer: use stored VK from setup
                if (!window._crowdfundVk) { toast('Run ZK Trusted Setup first', 'error'); return; }
                vkHex = window._crowdfundVk;
                const datetimeVal = el('cov-crowdfund-datetime') ? el('cov-crowdfund-datetime').value : '';
                if (datetimeVal) {
                    const targetMs = new Date(datetimeVal).getTime();
                    const nowMs = Date.now();
                    if (targetMs <= nowMs) { toast('Pick a future deadline', 'error'); return; }
                    const secondsUntil = Math.ceil((targetMs - nowMs) / 1000);
                    const currentDaa = await fetchCurrentDaa();
                    if (currentDaa > 0) {
                        locktime = String(currentDaa + secondsUntil * 10);
                        el('cov-crowdfund-locktime').value = locktime;
                    } else {
                        toast('Could not fetch current DAA', 'error'); return;
                    }
                } else {
                    locktime = el('cov-crowdfund-locktime').value.trim();
                }
            }
            if (!ownerPk) { toast('Load wallet first', 'error'); return; }
            if (!vkHex) { toast('VK required (run setup or paste from organizer)', 'error'); return; }
            if (!locktime || parseInt(locktime) <= 0) { toast('Set a deadline', 'error'); return; }
            // Organizer pubkey for dual-gate: from invite (contributor) or own wallet (organizer)
            const organizerPk = window._crowdfundOrganizerPk || ownerPk;
            if (isContributor && !window._crowdfundOrganizerPk) {
                toast('Organizer pubkey missing from invite', 'error'); return;
            }
            resultJson = covenant_crowdfund(ownerPk, organizerPk, vkHex, BigInt(locktime), network);
            // Persist crowdfund params for invite QR sharing
            const cfResult = JSON.parse(resultJson);
            cfResult.vk_hex = vkHex;
            cfResult.pk_hex = window._crowdfundPk || '';
            cfResult.goal_kas = el('cov-crowdfund-goal') ? el('cov-crowdfund-goal').value : '';
            cfResult.crowdfund_role = isContributor ? 'contributor' : 'organizer';
            cfResult.organizer_pk = organizerPk;
            // Campaign name and ID for watcher discovery
            const campaignName = el('cov-crowdfund-name') ? el('cov-crowdfund-name').value.trim() : '';
            cfResult.campaign_name = campaignName || (isContributor ? (window._crowdfundCampaignName || '') : '');
            cfResult.campaign_id = blake2b_hash(vkHex); // deterministic from VK
            resultJson = JSON.stringify(cfResult);
        }

        const result = JSON.parse(resultJson);
        result.type = t;

        // Merge counterparty keys for encrypted payload recovery
        Object.assign(result, _covExtra);

        // Normalize allowance field names (WASM returns min_sequence, we store cooldown_daa)
        if (result.min_sequence && !result.cooldown_daa) result.cooldown_daa = result.min_sequence;

        lastCovenantResult = result;
        _covWatcherSpendPath = null;
        _covWatcherOutpoint = null;
        _covWatcherLastBalance = null;
        try { sessionStorage.setItem('lastCovenantResult', JSON.stringify(result)); } catch (_) {}
        if (t === 'atomic-swap') swapStateSave();
        console.log('[KasSee] Covenant created:', result);

        // Add to active covenants list
        covAddActive(t, result);

        // Clear creation form so re-entering doesn't regenerate same covenant
        const formFields = {
            'timelocked-savings': ['cov-savings-recovery-pk', 'cov-savings-locktime', 'cov-savings-datetime'],
            'dms': ['cov-dms2-heir-pk', 'cov-dms2-duration'],
            'global-allowance': ['cov-allowance-bene-pk', 'cov-allowance-max', 'cov-allowance-seq', 'cov-allowance-start'],
            'global-spending-limit': ['cov-splimit-max', 'cov-splimit-cooldown'],
            'additive': ['cov-piggy-goal', 'cov-piggy-deadline'],
            'merkle-whitelist': ['cov-mw-addresses', 'cov-mw-locktime', 'cov-mw-datetime'],
        };
        if (formFields[t]) formFields[t].forEach(id => { if (el(id)) el(id).value = ''; });

        // Crowdfund: persist address->redeemScript mapping for multi-contributor sweep
        if (t === 'crowdfund' && result.address && result.redeem_script_hex) {
            try {
                const map = JSON.parse(localStorage.getItem('crowdfundRedeemMap') || '{}');
                map[result.address] = result.redeem_script_hex;
                localStorage.setItem('crowdfundRedeemMap', JSON.stringify(map));
            } catch (_) {}
        }

        el('cov-result-addr').textContent = result.address;
        el('cov-result-script').textContent = result.redeem_script_hex;
        covRenderMetaLine(result);

        covShowPanel('result');
        covUpdateResultButtons(t);
        toast('Covenant address generated', 'ok', 2000);
    } catch (e) {
        toast('Covenant error: ' + e, 'error', 5000);
        console.error('[KasSee] Covenant generate error:', e);
    }
}

async function handleCovFund() {
    if (!lastCovenantResult) { toast('No covenant address', 'error'); return; }
    // Piggy bank "Add Funds" routes through the same funding (Send) screen as the
    // first deposit: UTXO picker + amount + a send fee that scales with inputs.
    // (The old borrower-merge panel had no picker and a flat fee that under-paid
    // multi-input merges.) A plain deposit adds another covenant UTXO; the additive
    // script breaks a multi-UTXO piggy fine (the goal check reads output[0], the
    // swept total, for any input count). So Add Funds falls through to openSendScreen.
    _broadcastReturnScreen = 'covenant';
    await openSendScreen();
    el('input-dest').value = lastCovenantResult.address;
    updateFeeCardAmounts();
    setFeeLevel('normal');
    // Thread covenants (single-thread, covenant_id-bound) full-spend the chosen
    // wallet UTXO(s) into the thread: the amount is bypassed, the whole UTXO is
    // used. So drop the misleading amount field and surface the UTXO picker so
    // the user just chooses which UTXO(s) to fund/fold in.
    const _ft = lastCovenantResult.type;
    const _isThreadType = (_ft === 'global-allowance' || _ft === 'global-spending-limit');
    // Only a TOP-UP (the covenant address already holds the thread) needs the
    // whole-UTXO fold. Initial funding (genesis, empty address) behaves like a
    // normal covenant deposit: amount field + optional picker + change.
    let _isThreadTopup = false;
    if (_isThreadType) {
        try {
            const _wsTF = await resolveNodeUrl();
            const _covTF = JSON.parse(await fetch_utxos_for_address_js(lastCovenantResult.address, _wsTF));
            _isThreadTopup = Array.isArray(_covTF) && _covTF.length > 0;
        } catch (_) { _isThreadTopup = false; }
    }
    if (_isThreadType && _isThreadTopup) {
        const aw = el('send-amount-wrap');
        if (aw) aw.style.display = 'none';
        const list = el('send-utxo-list');
        if (list && list.style.display === 'none' && cachedUtxos && cachedUtxos.length) {
            toggleSendUtxos(); // expand the picker now that UTXOs are loaded
        }
        const tg = el('btn-toggle-utxos');
        if (tg) tg.textContent = 'Select UTXO(s) to fold into the thread ▾';
        toast('Top-up: pick the UTXO(s) to fold into the thread (whole UTXOs, no change).', 'info', 4000);
    } else if (_ft === 'additive' || _ft === 'timelocked-savings' || _ft === 'dms' || _isThreadType) {
        // Piggy / savings / DMS deposit: keep the amount field (partial deposits
        // allowed) and leave the UTXO picker collapsed on load. The user opens it to
        // pick which UTXOs to deposit from; a dust-sized change folds into the deposit
        // (KIP-9 safe). For savings and DMS, picking UTXOs also engages the
        // payload-aware deposit fee (the deposit carries the encrypted recovery
        // payload, which the plain send fee does not price in).
        // Initial funding of a thread covenant (genesis) also lands here. Only then
        // force the amount field visible (a prior top-up render may have hidden it);
        // savings/DMS funding is left exactly as before.
        if (_isThreadType) { const aw = el('send-amount-wrap'); if (aw) aw.style.display = ''; }
        const list = el('send-utxo-list');
        if (list && list.style.display !== 'none') {
            toggleSendUtxos(); // collapse if a prior state left it open
        }
        const tg = el('btn-toggle-utxos');
        if (tg) tg.textContent = 'Select UTXO(s) to deposit ▸';
        toast('Open the UTXO picker and choose what to deposit. A dust-sized change is folded into the deposit.', 'info', 4000);
    } else {
        toast('Sending to covenant address', 'info', 2000);
    }
}

// Adaptor swap: recover claim after browser data loss.
// Uses recovery data from sessionStorage (populated by COVB restore).
async function handleAdaptorRecoverClaim() {
    let rec;
    try {
        const covAddr = lastCovenantResult ? lastCovenantResult.address : '';
        rec = JSON.parse(sessionStorage.getItem('kassee_adaptor_recovery_' + covAddr));
    } catch (_) {}
    if (!rec || !rec.counterAddr || !rec.counterRedeem || !rec.myAdaptorSig || !rec.counterAdaptorSig) {
        toast('Missing recovery data for claim', 'error'); return;
    }
    if (!walletData) { toast('Load wallet first', 'error'); return; }

    toast('Searching for counterparty claim TX...', 'info', 5000);

    try {
        const wsUrl = await resolveNodeUrl();

        // Step 1: Check if our UTXO was spent (counterparty claimed it)
        const myUtxos = await fetch_utxos_for_address_js(rec.myAddr, wsUrl);
        const myBalance = JSON.parse(myUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);
        if (myBalance > 0n) {
            toast('Your UTXO is still funded. Counterparty has not claimed yet.', 'error'); return;
        }

        // Step 2: Find the spending TX via REST API
        let counterCompletedSig = null;
        try {
            const restBase = network.includes('test') ? 'https://api-tn10.kaspa.org' : 'https://api.kaspa.org';
            const resp = await fetch(restBase + '/addresses/' + rec.myAddr + '/full-transactions?limit=10&resolve_previous_outpoints=light');
            if (resp.ok) {
                const txs = await resp.json();
                for (const tx of txs) {
                    // Only look at TXs where our address appears in an input (spending TX)
                    let spendsOurAddr = false;
                    for (const inp of (tx.inputs || [])) {
                        if (inp.previous_outpoint_address === rec.myAddr) {
                            spendsOurAddr = true;
                            // This input's sig_script has Alice's completed signature
                            const ss = inp.signature_script || '';
                            if (ss.length >= 130 && ss.substring(0, 2) === '40') {
                                counterCompletedSig = ss.substring(2, 130);
                            }
                            break;
                        }
                    }
                    if (counterCompletedSig) break;
                }
            }
        } catch (e) {
            console.warn('[KasSee] REST lookup failed:', e);
        }

        // Step 2b: Fallback - try BlockAdded or manual entry
        if (!counterCompletedSig) {
            toast('Could not find claim TX via REST. Enter the completed signature manually or wait for archival node.', 'error');
            return;
        }

        console.log('[KasSee] Recovery: extracted counterparty completed sig:', counterCompletedSig);
        console.log('[KasSee] Recovery: counterAdaptorSig:', rec.counterAdaptorSig);
        console.log('[KasSee] Recovery: myAdaptorSig:', rec.myAdaptorSig);

        // Step 3: Extract secret t from completed sig vs adaptor sig
        const extractedSecret = adaptor_extract_secret(counterCompletedSig, rec.counterAdaptorSig);
        console.log('[KasSee] Recovery: extracted secret t:', extractedSecret);

        // Step 5: Complete Bob's adaptor sig with extracted t
        const commitment = rec.T_hex ? adaptor_swap_commitment(rec.T_hex, rec.T_hex, BigInt(0), BigInt(0)) : '';
        let bobCompletedSig = adaptor_complete_sig(rec.myAdaptorSig, extractedSecret);
        console.log('[KasSee] Recovery: T_hex:', rec.T_hex);
        console.log('[KasSee] Recovery: commitment:', commitment);
        console.log('[KasSee] Recovery: bobCompletedSig:', bobCompletedSig);
        console.log('[KasSee] Recovery: counterAddr:', rec.counterAddr);
        console.log('[KasSee] Recovery: counterRedeem:', rec.counterRedeem);

        // BIP340 parity check (optional - skip if myPk missing from older payload)
        const myPk = rec.myPk || '';
        if (myPk.length === 64 && commitment) {
            let isValid = adaptor_bip340_verify(myPk, commitment, bobCompletedSig);
            if (!isValid) {
                console.log('[KasSee] Recovery: BIP340 failed, trying negated secret...');
                const negatedSecret = adaptor_negate_scalar(extractedSecret);
                bobCompletedSig = adaptor_complete_sig(rec.myAdaptorSig, negatedSecret);
            }
        }

        // Step 6: Check Alice's UTXO has funds
        const counterUtxos = await fetch_utxos_for_address_js(rec.counterAddr, wsUrl);
        const counterBalance = JSON.parse(counterUtxos).reduce((s, u) => s + BigInt(u.amount), 0n);
        if (counterBalance === 0n) {
            toast('Counterparty UTXO already spent. Nothing to claim.', 'error'); return;
        }

        // Step 7: Build sig_script and broadcast (try both parities if no myPk)
        toast('Broadcasting claim TX...', 'info', 5000);
        const sigScriptHex = adaptor_build_sig_script(bobCompletedSig, commitment, rec.counterRedeem);

        const w = JSON.parse(walletData);
        const destAddr = w.receive_addresses[0];
        const fee = BigInt(400000);

        try {
            const claimTxid = await adaptor_broadcast_claim(
                rec.counterAddr, destAddr, sigScriptHex, fee, wsUrl
            );
            if (claimTxid) {
                toast('Claim broadcast! TXID: ' + claimTxid.substring(0, 16) + '...', 'ok', 10000);
                console.log('[KasSee] Recovery claim TX:', claimTxid);
                try { sessionStorage.removeItem('kassee_adaptor_recovery_' + rec.myAddr); } catch (_) {}
            } else {
                throw new Error('empty txid');
            }
        } catch (firstErr) {
            // First parity failed. Try negated secret.
            console.log('[KasSee] Recovery: first parity rejected, trying negated...', firstErr.toString());
            try {
                const negatedSecret = adaptor_negate_scalar(extractedSecret);
                const altSig = adaptor_complete_sig(rec.myAdaptorSig, negatedSecret);
                console.log('[KasSee] Recovery: negated bobCompletedSig:', altSig);
                const altSigScript = adaptor_build_sig_script(altSig, commitment, rec.counterRedeem);
                // Use slightly different fee to avoid TX ID collision (node caches rejections by txid)
                const fee2 = BigInt(500000);
                const claimTxid2 = await adaptor_broadcast_claim(
                    rec.counterAddr, destAddr, altSigScript, fee2, wsUrl
                );
                if (claimTxid2) {
                    toast('Claim broadcast! TXID: ' + claimTxid2.substring(0, 16) + '...', 'ok', 10000);
                    console.log('[KasSee] Recovery claim TX (negated):', claimTxid2);
                    try { sessionStorage.removeItem('kassee_adaptor_recovery_' + rec.myAddr); } catch (_) {}
                } else {
                    toast('Both parities rejected by node', 'error');
                }
            } catch (secondErr) {
                toast('Recovery claim failed both parities: ' + secondErr, 'error');
                console.error('[KasSee] Recovery claim both parities failed:', secondErr);
            }
        }
    } catch (e) {
        toast('Recovery claim failed: ' + e, 'error');
        console.error('[KasSee] Recovery claim error:', e);
    }
}

// Build and sign an escrow spend TX.
// branch: 'buyer-release' | 'seller-refund' | 'arbiter-award-seller' | 'arbiter-refund-buyer'
// ── Shipment-escrow covenant: parse params from redeem, refresh panel, spend ──

// Recover amounts and payout addresses from the redeem script. The layout is
// fixed (see build_ship_escrow_script): the multi-byte integer pushes appear in
// order total, rem, cltv1, rem, fee, cltv2; the 36-byte SPK data pushes appear
// in order seller, buyer, seller, deliverer, buyer. This lets a second device
// operate from just the address + redeem hex (no shared metadata needed).
function parseShipEscrowParams(redeemHex) {
    const b = [];
    for (let i = 0; i < redeemHex.length; i += 2) b.push(parseInt(redeemHex.substr(i, 2), 16));
    const n = b.length;
    let off = 0;
    if (b[0] === 0x08) off = 1 + 8 + 1; // skip salt push + OP_DROP
    const ints = [], spks = [];
    const decLE = (arr) => { let v = 0n; for (let k = arr.length - 1; k >= 0; k--) v = (v << 8n) | BigInt(arr[k]); return v; };
    while (off < n) {
        const op = b[off];
        if (op >= 0x01 && op <= 0x4b) {
            const len = op, data = b.slice(off + 1, off + 1 + len);
            if (len === 36) spks.push(data);
            else if (len !== 32) ints.push(decLE(data)); // 32 = pubkey push, skip
            off += 1 + len;
        } else if (op === 0x4c) { off += 2 + (b[off + 1] || 0); }
        else if (op === 0x4d) { off += 3 + ((b[off + 1] || 0) | ((b[off + 2] || 0) << 8)); }
        else { off += 1; }
    }
    const spkToAddr = (spk) => {
        // spk = 00 00 20 <32B key> ac  → key at bytes [3..35)
        const keyHex = spk.slice(3, 35).map(x => x.toString(16).padStart(2, '0')).join('');
        return encode_p2pk_address(keyHex, network);
    };
    if (ints.length < 6 || spks.length < 5) throw 'unrecognized ship-escrow redeem';
    return {
        total: ints[0], rem: ints[1], cltv1: ints[2], fee: ints[4], cltv2: ints[5],
        sellerAddr: spkToAddr(spks[0]), buyerAddr: spkToAddr(spks[1]), delivererAddr: spkToAddr(spks[3]),
    };
}

// Prefer in-session metadata (exact, from create); fall back to parsing the redeem.
function getShipParams(covAddr, redeemHex) {
    const L = lastCovenantResult;
    if (L && L.type === 'ship-escrow' && L.address === covAddr && L.total_sompi != null) {
        return {
            total: BigInt(L.total_sompi), rem: BigInt(L.rem_sompi), fee: BigInt(L.fee_sompi),
            cltv1: BigInt(L.cltv1_deadline), cltv2: BigInt(L.cltv2_deadline),
            sellerAddr: L.seller_addr, delivererAddr: L.deliverer_addr, buyerAddr: L.buyer_addr,
        };
    }
    return parseShipEscrowParams(redeemHex);
}

async function shipPanelRefresh() {
    const stateEl = el('cov-ship-state');
    const s0 = el('cov-ship-s0-actions'), s1 = el('cov-ship-s1-actions');
    if (lastCovenantResult && lastCovenantResult.type === 'ship-escrow') {
        if (el('cov-ship-addr') && !el('cov-ship-addr').value.trim()) el('cov-ship-addr').value = lastCovenantResult.address || '';
        if (el('cov-ship-script') && !el('cov-ship-script').value.trim()) el('cov-ship-script').value = lastCovenantResult.redeem_script_hex || '';
    }
    const covAddr = el('cov-ship-addr') ? el('cov-ship-addr').value.trim() : '';
    const redeemHex = el('cov-ship-script') ? el('cov-ship-script').value.trim() : '';
    if (s0) s0.style.display = 'none';
    if (s1) s1.style.display = 'none';
    if (!covAddr || !redeemHex) { if (stateEl) stateEl.textContent = 'Enter covenant address and redeem script.'; return; }
    let P;
    try { P = getShipParams(covAddr, redeemHex); } catch (e) { if (stateEl) stateEl.textContent = 'Parse error: ' + e; return; }
    if (stateEl) stateEl.textContent = 'Loading state...';
    try {
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
        const fmt = (s) => (Number(s) / 1e8).toString();
        if (!utxos.length) {
            if (stateEl) stateEl.innerHTML = '<span style="color:var(--text-dim)">Not funded. Fund with ' + fmt(P.total) + ' KAS (product + fee) to start.</span>';
            return;
        }
        const amt = BigInt(utxos[0].amount);
        if (amt === P.total) {
            if (s0) s0.style.display = '';
            if (stateEl) stateEl.innerHTML = '<span style="color:var(--teal)">State 0: funded (' + fmt(P.total) + ' KAS), awaiting pickup.</span><br>'
                + '<span style="font-size:11px;color:var(--text-dim)">Pickup releases ' + fmt(P.total - P.rem) + ' KAS to seller, continues at ' + fmt(P.rem) + ' KAS.</span>';
        } else if (amt === P.rem) {
            if (s1) s1.style.display = '';
            if (stateEl) stateEl.innerHTML = '<span style="color:var(--teal)">State 1: in transit (' + fmt(P.rem) + ' KAS), awaiting delivery.</span><br>'
                + '<span style="font-size:11px;color:var(--text-dim)">Delivery pays deliverer ' + fmt(P.fee) + ' KAS, the rest to seller.</span>';
        } else {
            if (stateEl) stateEl.innerHTML = '<span style="color:var(--text-dim)">UTXO ' + fmt(amt) + ' KAS matches neither state 0 (' + fmt(P.total) + ') nor state 1 (' + fmt(P.rem) + ').</span>';
        }
    } catch (e) { if (stateEl) stateEl.textContent = 'Error loading state: ' + e; }
}

async function handleShipEscrowSpend(branch) {
    const covAddr = el('cov-ship-addr').value.trim();
    const redeemHex = el('cov-ship-script').value.trim();
    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    let P;
    try { P = getShipParams(covAddr, redeemHex); } catch (e) { toast('Could not parse covenant: ' + e, 'error'); return; }
    if (!P.sellerAddr || !P.delivererAddr || !P.buyerAddr) { toast('Could not derive payout addresses', 'error'); return; }

    const isState0 = (branch === 'pickup' || branch === 'state0-arb-refund' || branch === 'state0-timeout');
    const expectAmt = isState0 ? P.total : P.rem;

    showLoading('Building ship-escrow ' + branch + ' TX...');
    try {
        const txfee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
        if (!utxos.length) throw 'No UTXOs at covenant address';
        const u = utxos.find(x => BigInt(x.amount) === expectAmt) || utxos[0];
        const inAmt = BigInt(u.amount);
        if (inAmt !== expectAmt) {
            throw 'UTXO ' + (Number(inAmt) / 1e8) + ' KAS does not match the ' + (isState0 ? 'state-0 total' : 'state-1') + ' amount ' + (Number(expectAmt) / 1e8) + ' KAS for this branch';
        }
        const covSpkHex = '0000' + addrToSpkHex(covAddr);
        const sellerSpk = '0000' + addrToSpkHex(P.sellerAddr);
        const delivSpk = '0000' + addrToSpkHex(P.delivererAddr);
        const buyerSpk = '0000' + addrToSpkHex(P.buyerAddr);
        const mkOut = (amt, spk) => ({ amount: BigInt(amt), scriptPublicKey: spk, bip32Derivations: [], proprietaries: [] });

        let outputs, minSig = 1, locktime = 0;
        if (branch === 'pickup') {
            const sellerAmt = inAmt - P.rem - txfee;
            if (sellerAmt <= 0n) throw 'Fee too high for pickup';
            outputs = [mkOut(P.rem, covSpkHex), mkOut(sellerAmt, sellerSpk)]; // out0 continues @ rem (exact)
        } else if (branch === 'delivery' || branch === 'state1-arb-award' || branch === 'state1-timeout') {
            const sellerAmt = inAmt - P.fee - txfee;
            if (sellerAmt <= 0n) throw 'Fee too high for delivery';
            outputs = [mkOut(sellerAmt, sellerSpk), mkOut(P.fee, delivSpk)]; // out1 = deliverer fee (exact)
            if (branch === 'state1-timeout') { minSig = 0; locktime = Number(P.cltv2); }
        } else if (branch === 'state0-arb-refund' || branch === 'state0-timeout' || branch === 'state1-arb-refund') {
            const buyerAmt = inAmt - txfee;
            if (buyerAmt <= 0n) throw 'Fee too high for refund';
            outputs = [mkOut(buyerAmt, buyerSpk)];
            if (branch === 'state0-timeout') { minSig = 0; locktime = Number(P.cltv1); }
        } else {
            throw 'Unknown branch ' + branch;
        }

        const inputs = [{
            previousOutpoint: { transactionId: u.tx_id, index: u.index },
            // sigOpCount buys script compute budget on tx v1 (1 sigop = 10
            // budget units = 100K script units on top of the 9,999 free).
            // 0 here made every signed branch blow the free allowance:
            // "script units exceeded ... used=100763, limit=9999".
            sequence: 0, sigOpCount: minSig,
            utxoEntry: { amount: inAmt, scriptPublicKey: covSpkHex, blockDaaScore: 0, isCoinbase: false },
            redeemScript: redeemHex, partialSigs: {}, minimumSignatures: minSig,
            // Lock time travels in minTime, per input, since 1.0.7: that is the
            // field rusty-kaspa and the device read. fallbackLockTime is null.
            bip32Derivations: [], proprietaries: {}, finalScriptSig: null, minTime: locktime > 0 ? locktime : 0
        }];

        const pskt = {
            global: {
                txVersion: 1,
                fallbackLockTime: null,
                inputsModifiableFlag: false, outputsModifiableFlag: false,
                inputCount: 1, outputCount: outputs.length,
                bip32Derivations: [],
                proprietaries: { shipBranch: branch }
            },
            inputs, outputs
        };

        const jsonStr = psktToJson([pskt]);
        const jsonHex = toHex(new TextEncoder().encode(jsonStr));
        const wireBytes = new TextEncoder().encode('PSKB');
        const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
        wireFull.set(wireBytes);
        wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
        const pskbHex = toHex(wireFull);

        hideLoading();
        console.log('[KasSee] ShipEscrow ' + branch + ' PSKB: ' + pskbHex.length + ' hex chars, minSig=' + minSig + ', locktime=' + locktime);
        window._covPayloadHex = '';
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Ship-escrow ' + branch + ' failed: ' + e, 'error', 5000);
        console.error('[KasSee] Ship-escrow spend error:', e);
    }
}

async function handleEscrowSpend(branch) {
    if (!lastCovenantResult) { toast('No covenant loaded', 'error'); return; }
    const covAddr = lastCovenantResult.address;
    const redeemHex = lastCovenantResult.redeem_script_hex;
    if (!covAddr || !redeemHex) { toast('Missing covenant data', 'error'); return; }

    // Parse script to get destination addresses
    ensureEscrowParams(lastCovenantResult);
    const alicePk = lastCovenantResult.alice_spk_hex || lastCovenantResult.alice_pk;
    const bobPk = lastCovenantResult.bob_spk_hex || lastCovenantResult.bob_pk;
    if (!alicePk || !bobPk) { toast('Could not parse escrow destinations from script', 'error'); return; }

    // Determine destination based on branch
    let destAddr;
    const isDispute = (branch === 'buyer-dispute' || branch === 'seller-dispute');
    if (isDispute) {
        destAddr = covAddr; // send back to same escrow address
    } else if (branch === 'buyer-release' || branch === 'arbiter-award-seller') {
        destAddr = encode_p2pk_address(bobPk, network); // funds go to seller
    } else {
        destAddr = encode_p2pk_address(alicePk, network); // funds go to buyer
    }

    showLoading('Building escrow ' + branch + ' TX...');
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
        const utxos = JSON.parse(utxosJson);
        if (!utxos.length) throw 'No UTXOs at escrow address';

        // Fee AFTER the fetch, sized to the real input count. This function
        // builds its inputs here in JS (`utxos.map` below) rather than calling
        // a wasm builder, so it gets no benefit from the fee floor added to
        // covenant_api.rs on 2026-08-14 and has to size its own. It previously
        // called getCovFee() with no arguments, pricing every escrow spend as
        // one input regardless of how many UTXOs the escrow address held.
        const fee = getCovFee(utxos.length);

        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        if (total <= fee) throw 'Balance too low: ' + Number(total) / 1e8 + ' KAS';

        const sendAmount = total - fee;
        const covSpkHex = '0000' + addrToSpkHex(covAddr);
        const destSpkHex = '0000' + addrToSpkHex(destAddr);

        const inputs = utxos.map(u => ({
            previousOutpoint: { transactionId: u.tx_id, index: u.index },
            // Every escrow branch verifies exactly one signature; sigOpCount 1
            // commits compute_budget 10 (109,999 units) on tx v1. 0 capped the
            // input at the 9,999 free units and the node rejected the spend.
            sequence: 0, sigOpCount: 1,
            utxoEntry: { amount: BigInt(u.amount), scriptPublicKey: covSpkHex, blockDaaScore: 0, isCoinbase: false },
            redeemScript: redeemHex, partialSigs: {}, minimumSignatures: 1,
            bip32Derivations: [],
            proprietaries: {},
            finalScriptSig: null, minTime: 0
        }));

        const outputs = [{ amount: BigInt(sendAmount), scriptPublicKey: destSpkHex, bip32Derivations: [], proprietaries: [] }];

        // Dispute heartbeat: attach "ESCD" + role payload so all watchers detect it
        let txPayload = '';
        if (isDispute) {
            const roleByte = (branch === 'buyer-dispute') ? '01' : '02';
            txPayload = '4553434400' + roleByte; // "ESCD\0" + role (6 bytes)
        }

        // tx_version 1 for covenant introspection on TN10
        const pskt = {
            global: {
                txVersion: 1, fallbackLockTime: null,
                inputsModifiableFlag: false, outputsModifiableFlag: false,
                inputCount: inputs.length, outputCount: outputs.length,
                bip32Derivations: [],
                proprietaries: { escrowBranch: branch },
                txPayload: txPayload || undefined
            },
            inputs, outputs
        };

        const jsonStr = psktToJson([pskt]);
        const jsonHex = toHex(new TextEncoder().encode(jsonStr));
        const wireBytes = new TextEncoder().encode('PSKB');
        const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
        wireFull.set(wireBytes);
        wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
        const pskbHex = toHex(wireFull);

        hideLoading();
        console.log('[KasSee] Escrow ' + branch + ' PSKB: ' + pskbHex.length + ' hex chars, dest=' + destAddr);
        window._covPayloadHex = ''; // Clear stale deposit payload
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Escrow spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Escrow spend error:', e);
    }
}

// Select the covenant thread UTXO by its covenant_id tag, never by size. The
// single-thread covenants (spending limit, allowance) hold the governed balance
// in ONE covenant_id-tagged UTXO; external (untagged) deposits to the same
// address must never be mistaken for the thread, since picking the largest UTXO
// lets a bigger external deposit brick withdraw/top-up. This is client-side UX
// only; the chain enforces the covenant regardless of what the client picks.
// Returns { thread, external, externalSompi, ambiguous }. thread is null when no
// tagged thread can be identified (caller surfaces the existing error).
function pickThread(utxos, expectedG) {
    const list = Array.isArray(utxos) ? utxos : [];
    const isTagged = (u) => u && u.covenant_id && !/^0+$/.test(String(u.covenant_id));
    const g = (expectedG && !/^0+$/.test(String(expectedG))) ? String(expectedG).toLowerCase() : '';
    let thread = null;
    let ambiguous = false;
    if (g) {
        // Known thread id: the thread is the UTXO tagged with exactly this G.
        thread = list.find(u => isTagged(u) && String(u.covenant_id).toLowerCase() === g) || null;
    } else {
        // No known G: the lone tagged UTXO is the thread. More than one tagged and
        // no G to match is ambiguous, so do not guess (G is recomputable, an
        // attacker could plant a tagged decoy).
        const tagged = list.filter(isTagged);
        if (tagged.length === 1) thread = tagged[0];
        else if (tagged.length > 1) ambiguous = true;
    }
    const external = list.filter(u => u !== thread);
    const externalSompi = external.reduce((s, u) => s + BigInt(u.amount || 0), 0n);
    return { thread, external, externalSompi, ambiguous };
}

async function handleCovOwnerSpend() {
    window._covPayloadHex = ''; // No payload in owner-spend/heartbeat TX
    const covAddr = el('cov-owner-addr').value.trim();
    const redeemHex = el('cov-owner-script').value.trim();
    const destAddr = el('cov-owner-dest').value.trim();
    const amountStr = el('cov-owner-amount').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    const isPartial = amountStr && parseFloat(amountStr) > 0;
    const covType = el('cov-owner-panel') ? (el('cov-owner-panel').dataset.covOwnerType || '') : '';

    // Commit-Reveal is an all-or-nothing commitment: the owner refund must reclaim
    // the whole stack. A partial refund would re-deposit a remainder into a new UTXO
    // and break the reveal and refund paths, same class as the KasFreeze case.
    if (covType === 'commit-reveal' && isPartial) {
        toast('Commit-Reveal owner refund is full-only. Clear the amount to refund the whole commitment. A partial refund would leave a remainder that breaks the reveal and refund paths.', 'error', 8000);
        return;
    }

    showLoading('Building owner-spend PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        let pskbHex;

        // Spending-limit: single-path, always partial withdraw via dedicated WASM
        if (covType === 'global-spending-limit') {
            // Single-thread global limit. Empty amount = sweep/close the whole thread
            // (allowed only when balance <= cap, enforced on-chain by the script's ELSE
            // branch); otherwise a capped partial withdrawal leaving a continuation.
            // The continuation reuses the thread's own covenant id (G), read from the node.
            const threadRaw = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
            if (!threadRaw.length) { toast('No UTXO at the covenant address', 'error'); hideLoading(); return; }
            const _pick = pickThread(threadRaw, lastCovenantResult && lastCovenantResult.covenant_id_hex);
            const thread = _pick.thread; // the tagged thread, selected by covenant_id (not size)
            if (!thread) {
                const _gKnown = !!(lastCovenantResult && lastCovenantResult.covenant_id_hex && !/^0+$/.test(lastCovenantResult.covenant_id_hex));
                const _msg = _pick.ambiguous
                    ? 'Multiple covenant-tagged UTXOs at this address and no known thread id, cannot safely pick the thread.'
                    : (_gKnown
                        ? 'Thread closed. The remaining ' + (Number(_pick.externalSompi) / 1e8) + ' KAS is external and cannot be spent through the limit.'
                        : 'Thread covenant_id unavailable from the node. The continuation must reuse the thread id; the node must serve version-2 UTXO entries.');
                toast(_msg, 'error', 6500);
                hideLoading(); return;
            }
            const threadAmt = BigInt(thread.amount);
            const gId = thread.covenant_id || ''; // thread's own covenant id (G)
            // CSV cooldown: the thread UTXO must age past the cooldown before it can be
            // spent again (a top-up or prior withdrawal reset its age). Block an early
            // withdrawal here so the user is not sent into a CSV-rejected TX.
            const _cd = (lastCovenantResult && lastCovenantResult.cooldown_daa) ? Number(lastCovenantResult.cooldown_daa) : 0;
            if (_cd > 0) {
                const _threadDaa = Number(thread.block_daa_score || 0);
                if (_threadDaa > 0) {
                    const _curDaa = await fetchCurrentDaa();
                    const _matureDaa = _threadDaa + _cd;
                    if (_curDaa > 0 && _curDaa < _matureDaa) {
                        hideLoading();
                        const _eta = formatDuration(Math.floor((_matureDaa - _curDaa) / 10));
                        toast('Cooldown not elapsed. Next withdrawal in ~' + _eta + '. An early spend is rejected by the node.', 'error', 5000);
                        return;
                    }
                }
            }
            // Empty -> sweep the whole balance (close); otherwise the entered amount.
            const withdrawSompi = isPartial ? kasToSompi(amountStr) : threadAmt;
            const capSompi = (lastCovenantResult && lastCovenantResult.max_withdraw_sompi) ? BigInt(lastCovenantResult.max_withdraw_sompi) : 0n;
            if (withdrawSompi > threadAmt) {
                toast('Amount exceeds the thread balance (' + sompiToKasStr(threadAmt) + ' KAS).', 'error');
                hideLoading(); return;
            }
            if (capSompi > 0n && withdrawSompi > capSompi) {
                // Over the per-spend cap. A partial withdrawal must be <= cap; a sweep-all
                // (close) is valid only when the whole balance is <= cap. So once the
                // balance exceeds the cap, the only legal spend is a capped partial.
                const _capK = sompiToKasStr(capSompi);
                const _msg = (withdrawSompi >= threadAmt)
                    ? 'Balance (' + sompiToKasStr(threadAmt) + ' KAS) is over the per-spend cap of ' + _capK + ' KAS, so it cannot be swept in one TX. Withdraw ' + _capK + ' KAS or less.'
                    : 'Per-spend cap is ' + _capK + ' KAS. Withdraw that or less.';
                toast(_msg, 'error', 5000);
                hideLoading(); return;
            }
            const baseFee = 300000n;
            let glFee = baseFee;
            const returnEst = threadAmt - withdrawSompi - baseFee;
            if (returnEst > 0n && withdrawSompi > 0n) {
                const C = 1000000000000n, MAX_SM = 500000n;
                const hMean = (2n * returnEst * withdrawSompi) / (returnEst + withdrawSompi);
                const storageMass = hMean > 0n ? C / hMean : 0n;
                if (storageMass > MAX_SM) {
                    toast('That withdrawal leaves too small a remainder (storage mass). Pick a different amount.', 'error');
                    hideLoading(); return;
                }
                const computeMass = 2500n;
                const totalMass = storageMass > computeMass ? storageMass : computeMass;
                const feeRate = lastFeeEstimate ? BigInt(Math.ceil(lastFeeEstimate.normal_sompi_per_gram || 1)) : 1n;
                glFee = totalMass * feeRate;
                if (glFee < baseFee) glFee = baseFee;
            }
            console.log('[KasSee] Global limit withdraw: thread ' + thread.tx_id.substring(0, 16) + ':' + thread.index + ' = ' + sompiToKasStr(threadAmt) + ' KAS, withdraw=' + sompiToKasStr(withdrawSompi) + ' KAS, fee=' + glFee);
            pskbHex = await create_global_spending_limit_withdraw(covAddr, destAddr, redeemHex, gId, withdrawSompi, glFee, JSON.stringify([thread]));
        } else if (!isPartial) {
            // Sweep all — use existing WASM function. Scale the fee to the UTXO
            // count so a multi-UTXO sweep (e.g. a vault/DMS funded several times)
            // is not rejected for compute mass.
            let branch = '';
            // Oracle escrow: the owner's ONLY reclaim path (Path 1, outer IF) IS
            // the CLTV refund — there is no no-timelock owner branch as in
            // savings/escrow — so the owner-spend TX must stamp the script's
            // locktime. Take the time path so create_covenant_owner_spend extracts
            // and stamps the CLTV locktime; otherwise tx.locktime stays 0 and the
            // node rejects with "locktime requirement not satisfied".
            if (covType === 'oracle' || covType === 'adaptor-swap' || covType === 'payjoin' || covType === 'merkle-whitelist' || covType === 'commit-reveal') branch = 'owner-time';
            // CLTV-only owner reclaim gate: for these types the owner path IS
            // the timelock branch — before it matures the node rejects the TX
            // as not finalized. Block the doomed TX with a banner instead.
            const _cltvOwnerTypes = { 'merkle-whitelist': 'only whitelisted spends are valid',
                                      'commit-reveal': 'only the reveal path is valid',
                                      'oracle': 'only the oracle-attested claim is valid',
                                      'payjoin': 'only the joint-spend path is valid',
                                      'adaptor-swap': 'only the counterparty claim is valid' };
            if (_cltvOwnerTypes[covType] && lastCovenantResult && lastCovenantResult.locktime_daa > 0) {
                let _mwDaa = 0;
                try { _mwDaa = await fetchCurrentDaa(); } catch (_) {}
                if (!_mwDaa && typeof _lastKnownDaa !== 'undefined' && _lastKnownDaa > 0) _mwDaa = _lastKnownDaa;
                const _mwLt = Number(lastCovenantResult.locktime_daa);
                if (_mwDaa > 0 && _mwDaa < _mwLt) {
                    const _mwEta = formatDuration(Math.floor((_mwLt - _mwDaa) / 10));
                    try {
                        window.piggyStatusBanner({
                            text: 'Owner reclaim NOT available yet: timelock matures in ~' + _mwEta +
                                  '. Until then ' + _cltvOwnerTypes[covType] + ' — a reclaim TX would be rejected on-chain.',
                            color: 'var(--error, #f44336)'
                        });
                    } catch (_) {}
                    hideLoading();
                    toast('Owner reclaim is timelocked for ~' + _mwEta + ' more. The node would reject this TX.', 'error', 7500);
                    return;
                }
            }
            let sweepFee = fee;
            try {
                const wsCheck = await resolveNodeUrl();
                const utxosCheck = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsCheck));
                sweepFee = getCovFee(utxosCheck.length || 1);
                // Piggy break gate: refuse to build a TX that cannot pass
                // on-chain. Goal path needs (total - fee) >= threshold;
                // deadline path needs the CLTV to have matured. If neither
                // holds, a broadcast is guaranteed to fail — block it here.
                if (covType === 'additive' && lastCovenantResult) {
                    const totalCheck = utxosCheck.reduce((s, u) => s + BigInt(u.amount), 0n);
                    const st = await window.piggyBreakStatus(totalCheck, sweepFee);
                    try { window.piggyStatusBanner(st); } catch (_) {}
                    if (!st.canBreak) {
                        hideLoading();
                        toast(st.text, 'error', 7500);
                        return;
                    }
                    if (!st.goalMet && st.deadlinePassed) {
                        branch = 'owner-time';
                        console.log('[KasSee] Piggy break: using deadline (time) path');
                    }
                }
            } catch (_) {}
            pskbHex = await create_covenant_owner_spend(covAddr, destAddr, redeemHex, sweepFee, wsUrl, branch);
        } else {
            // Partial spend — build PSKB in JS with change back to covenant
            const sendSompi = kasToSompi(amountStr);
            const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
            const utxos = JSON.parse(utxosJson);
            if (!utxos.length) throw 'No UTXOs at covenant address';

            const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
            if (total < sendSompi + fee) throw 'Balance too low: ' + Number(total) / 1e8 + ' KAS available';

            const change = total - sendSompi - fee;
            const covSpkHex = '0000' + addrToSpkHex(covAddr);
            const destSpkHex = '0000' + addrToSpkHex(destAddr);

            const inputs = utxos.map(u => ({
                previousOutpoint: { transactionId: u.tx_id, index: u.index },
                sequence: 0, sigOpCount: 1,
                utxoEntry: { amount: BigInt(u.amount), scriptPublicKey: covSpkHex, blockDaaScore: 0, isCoinbase: false },
                redeemScript: redeemHex, partialSigs: {}, minimumSignatures: 1,
                bip32Derivations: [], proprietaries: [], finalScriptSig: null, minTime: 0
            }));

            const outputs = [{ amount: BigInt(sendSompi), scriptPublicKey: destSpkHex, bip32Derivations: [], proprietaries: [] }];
            if (change > 0n) {
                outputs.push({ amount: BigInt(change), scriptPublicKey: covSpkHex, bip32Derivations: [], proprietaries: [] });
            }

            // Partial owner reclaim always spends the immediate branch (the
            // time-locked owner break is full-sweep only), so the TX must be
            // final: locktime 0. The script's CLTV lives in the beneficiary
            // branch; stamping it here would make the node reject the TX as
            // "input #0 is not finalized" before the timeout.
            const pskt = {
                global: {
                    txVersion: 0, fallbackLockTime: 0,
                    inputsModifiableFlag: false, outputsModifiableFlag: false,
                    inputCount: inputs.length, outputCount: outputs.length,
                    bip32Derivations: [], proprietaries: []
                },
                inputs, outputs
            };

            const jsonStr = psktToJson([pskt]);
            const jsonHex = toHex(new TextEncoder().encode(jsonStr));
            const wireBytes = new TextEncoder().encode('PSKB');
            const wireFull = new Uint8Array(wireBytes.length + jsonHex.length);
            wireFull.set(wireBytes);
            wireFull.set(new TextEncoder().encode(jsonHex), wireBytes.length);
            pskbHex = toHex(wireFull);
        }

        hideLoading();
        console.log('[KasSee] Covenant owner-spend PSKB: ' + pskbHex.length + ' hex chars' + (isPartial ? ' (partial)' : ' (sweep)'));
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Owner spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Owner spend error:', e);
    }
}

async function handleCovBorrowerSpend() {
    if (!walletData) { toast('Load wallet first', 'error'); return; }
    const covAddr = el('cov-borrower-addr').value.trim();
    const redeemHex = el('cov-borrower-script').value.trim();
    const amountStr = el('cov-borrower-amount').value.trim();
    const mode = el('cov-borrower-mode').value;

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!amountStr || parseFloat(amountStr) <= 0) { toast('Enter amount', 'error'); return; }

    const sompi = kasToSompi(amountStr);

    showLoading(mode === 'withdraw' ? 'Building borrower withdraw PSKB...' : 'Building borrower spend PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        let pskbHex;
        if (mode === 'withdraw') {
            pskbHex = await create_covenant_borrower_withdraw(walletData, covAddr, redeemHex, sompi, fee, wsUrl);
        } else {
            pskbHex = await create_covenant_borrower_spend(walletData, covAddr, redeemHex, sompi, fee, wsUrl);
        }
        hideLoading();
        console.log('[KasSee] Covenant borrower PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Borrower TX failed: ' + e, 'error', 5000);
        console.error('[KasSee] Borrower TX error:', e);
    }
}

async function handleCovBeneficiarySpend() {
    window._covPayloadHex = ''; // No payload in beneficiary-spend TX
    const beneType = el('cov-beneficiary-panel').dataset.covBeneType || '';
    const covAddr = el('cov-bene-addr').value.trim();
    const redeemHex = el('cov-bene-script').value.trim();
    const destAddr = el('cov-bene-dest').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    if (beneType === 'global-allowance') {
        // Global single-thread allowance: beneficiary capped withdrawal that
        // continues the thread (or closes it when balance <= cap). The whole
        // balance lives in ONE tagged UTXO; the continuation reuses the thread's
        // own covenant id (G), read from the node.
        const amountStr = el('cov-bene-amount') ? el('cov-bene-amount').value.trim() : '';
        const isPartial = !!(amountStr && parseFloat(amountStr) > 0);
        showLoading('Building global allowance withdraw PSKB...');
        try {
            const wsUrl = await resolveNodeUrl();
            const threadRaw = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
            if (!threadRaw.length) throw 'No UTXO at the covenant address';
            const _bpick = pickThread(threadRaw, lastCovenantResult && lastCovenantResult.covenant_id_hex);
            const thread = _bpick.thread; // tagged thread, selected by covenant_id (not size)
            if (!thread) {
                const _gKnown = !!(lastCovenantResult && lastCovenantResult.covenant_id_hex && !/^0+$/.test(lastCovenantResult.covenant_id_hex));
                throw _bpick.ambiguous
                    ? 'Multiple covenant-tagged UTXOs and no known thread id, cannot safely pick the thread.'
                    : (_gKnown
                        ? 'Thread closed. The remaining ' + (Number(_bpick.externalSompi) / 1e8) + ' KAS is external; the owner can reclaim it, the beneficiary cannot withdraw it.'
                        : 'Thread covenant_id unavailable from the node (need version-2 UTXO entries).');
            }
            const threadAmt = BigInt(thread.amount);
            const gId = thread.covenant_id || ''; // thread's own covenant id (G)
            // Gate the beneficiary withdrawal the same way the script does: not before
            // the CLTV start date, and not before the CSV cooldown has elapsed since the
            // thread's last spend/top-up. Block early so it does not build into a node
            // rejection. (Owner reclaim is uncapped/anytime and goes through a different
            // path, so it is not gated here.)
            const _startDaa = (lastCovenantResult && lastCovenantResult.start_daa) ? Number(lastCovenantResult.start_daa) : 0;
            const _cd = (lastCovenantResult && lastCovenantResult.cooldown_daa) ? Number(lastCovenantResult.cooldown_daa) : 0;
            if (_startDaa > 0 || _cd > 0) {
                const _curDaa = await fetchCurrentDaa();
                if (_curDaa > 0) {
                    if (_startDaa > 0 && _curDaa < _startDaa) {
                        hideLoading();
                        const _eta = formatDuration(Math.floor((_startDaa - _curDaa) / 10));
                        toast('Not started yet. Withdrawals begin in ~' + _eta + '. An early spend is rejected by the node.', 'error', 5000);
                        return;
                    }
                    const _threadDaa = Number(thread.block_daa_score || 0);
                    if (_cd > 0 && _threadDaa > 0 && _curDaa < _threadDaa + _cd) {
                        hideLoading();
                        const _eta = formatDuration(Math.floor((_threadDaa + _cd - _curDaa) / 10));
                        toast('Cooldown not elapsed. Next withdrawal in ~' + _eta + '. An early spend is rejected by the node.', 'error', 5000);
                        return;
                    }
                }
            }
            // Empty -> close (sweep whole balance, allowed only when balance <= cap);
            // otherwise the entered amount (capped).
            const withdrawSompi = isPartial ? kasToSompi(amountStr) : threadAmt;
            const capSompi = (lastCovenantResult && lastCovenantResult.max_withdraw_sompi) ? BigInt(lastCovenantResult.max_withdraw_sompi) : 0n;
            if (withdrawSompi > threadAmt) {
                throw 'Amount exceeds the thread balance (' + sompiToKasStr(threadAmt) + ' KAS).';
            }
            if (capSompi > 0n && withdrawSompi > capSompi) {
                const _capK = sompiToKasStr(capSompi);
                throw (withdrawSompi >= threadAmt)
                    ? 'Balance (' + sompiToKasStr(threadAmt) + ' KAS) is over the per-spend cap of ' + _capK + ' KAS, so it cannot be swept in one TX. Withdraw ' + _capK + ' KAS or less.'
                    : 'Per-spend cap is ' + _capK + ' KAS. Withdraw that or less.';
            }
            const baseFee = 300000n;
            let glFee = baseFee;
            const returnEst = threadAmt - withdrawSompi - baseFee;
            if (returnEst > 0n && withdrawSompi > 0n) {
                const C = 1000000000000n, MAX_SM = 500000n;
                const hMean = (2n * returnEst * withdrawSompi) / (returnEst + withdrawSompi);
                const storageMass = hMean > 0n ? C / hMean : 0n;
                if (storageMass > MAX_SM) {
                    throw 'That withdrawal leaves too small a remainder (storage mass). Pick a different amount.';
                }
                const computeMass = 2500n;
                const totalMass = storageMass > computeMass ? storageMass : computeMass;
                const feeRate = lastFeeEstimate ? BigInt(Math.ceil(lastFeeEstimate.normal_sompi_per_gram || 1)) : 1n;
                glFee = totalMass * feeRate;
                if (glFee < baseFee) glFee = baseFee;
            }
            console.log('[KasSee] Global allowance withdraw: thread ' + thread.tx_id.substring(0, 16) + ':' + thread.index + ' = ' + sompiToKasStr(threadAmt) + ' KAS, withdraw=' + sompiToKasStr(withdrawSompi) + ' KAS, fee=' + glFee);
            const pskbHex = await create_global_allowance_withdraw(covAddr, destAddr, redeemHex, gId, withdrawSompi, glFee, JSON.stringify([thread]));
            hideLoading();
            console.log('[KasSee] Global allowance withdraw PSKB: ' + pskbHex.length + ' hex chars');
            _broadcastReturnScreen = 'covenant';
            openPsktReview(pskbHex);
        } catch (e) {
            hideLoading();
            toast('Global allowance withdraw failed: ' + e, 'error', 5000);
        }
        // covBeneType intentionally NOT cleared: a retry on this same screen (e.g. after
        // lowering an over-cap amount) must stay routed to this branch. The panel render
        // is the single source of truth and re-sets covBeneType on every open.
        return;
    }

    // Standard beneficiary spend (vault/DMS) - full sweep with locktime
    const locktime = el('cov-bene-locktime').value.trim();
    const isDmsCsv = lastCovenantResult && lastCovenantResult.type === 'dms';
    if (!isDmsCsv && (!locktime || parseInt(locktime) <= 0)) { toast('Enter locktime DAA score', 'error'); return; }

    showLoading('Building beneficiary-spend PSKB...');
    try {
        const wsUrl = await resolveNodeUrl();
        // Full sweep of every covenant UTXO: scale the fee to the input count so a
        // multi-UTXO vault/DMS claim is not rejected for compute mass.
        let _nIn = 1;
        let _covUtxos = [];
        try { _covUtxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl)); _nIn = _covUtxos.length || 1; } catch (_) {}
        const fee = getCovFee(_nIn);
        const _beneType = el('cov-beneficiary-panel') ? (el('cov-beneficiary-panel').dataset.covBeneType || '') : '';
        if (_beneType === 'timelocked-savings') {
            const _lockN = parseInt(locktime || '0');
            if (_lockN > 0) {
                const _curDaa = await fetchCurrentDaa();
                if (_curDaa > 0 && _curDaa < _lockN) {
                    hideLoading();
                    const _eta = formatDuration(Math.floor((_lockN - _curDaa) / 10));
                    toast('Still locked. Unlocks in ~' + _eta + '. An early claim is rejected by the node.', 'error', 5000);
                    return;
                }
            }
        } else if (isDmsCsv) {
            // DMS heir claim is gated by CSV (per-UTXO age). A full sweep includes
            // every UTXO, so it can only succeed once the NEWEST UTXO has aged past the
            // inactivity period. Warn and stop before the node rejects the early claim.
            const _inact = lastCovenantResult.inactivity_daa ? Number(lastCovenantResult.inactivity_daa) : 0;
            if (_inact > 0 && _covUtxos.length) {
                const _curDaa = await fetchCurrentDaa();
                let _newest = 0;
                for (const u of _covUtxos) { const d = Number(u.block_daa_score || 0); if (d > _newest) _newest = d; }
                const _unlock = _newest + _inact;
                if (_curDaa > 0 && _curDaa < _unlock) {
                    hideLoading();
                    const _eta = formatDuration(Math.floor((_unlock - _curDaa) / 10));
                    toast('Still locked. The inactivity period has not elapsed for all vault UTXOs. The heir can sweep everything in ~' + _eta + '. An early claim is rejected by the node.', 'error', 6000);
                    return;
                }
            }
        }
        const pskbHex = (_beneType === 'timelocked-savings')
            ? await create_covenant_timelocked_savings_claim(covAddr, destAddr, redeemHex, BigInt(locktime), fee, wsUrl)
            : await create_covenant_beneficiary_spend(covAddr, destAddr, redeemHex, BigInt(locktime), fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Beneficiary-spend PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Beneficiary spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Beneficiary spend error:', e);
    }
}

async function handleCovTimeoutRefund() {
    const covAddr = el('cov-timeout-addr').value.trim();
    const redeemHex = el('cov-timeout-script').value.trim();
    const locktime = el('cov-timeout-locktime').value.trim();
    const destAddr = el('cov-timeout-dest').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!locktime || parseInt(locktime) <= 0) { toast('Enter locktime DAA score', 'error'); return; }
    if (!destAddr) { toast('Enter refund destination address', 'error'); return; }

    showLoading('Building timeout-refund PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const pskbHex = await create_covenant_timeout_refund(covAddr, destAddr, redeemHex, BigInt(locktime), fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Timeout-refund PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        // Timeout refund has no signature — go directly to finalize+broadcast
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Timeout refund failed: ' + e, 'error', 5000);
        console.error('[KasSee] Timeout refund error:', e);
    }
}

async function handleCovAtomicClaim() {
    const covAddr = el('cov-claim-addr').value.trim();
    const redeemHex = el('cov-claim-script').value.trim();
    const preimageRaw = el('cov-claim-preimage').value.trim();
    const destAddr = el('cov-claim-dest').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!preimageRaw) { toast('Enter preimage', 'error'); return; }
    if (!destAddr) { toast('Enter claim destination address', 'error'); return; }

    // Convert preimage to hex: if it looks like valid hex, use as-is; otherwise treat as UTF-8 text
    let preimageHex;
    if (/^[0-9a-fA-F]+$/.test(preimageRaw) && preimageRaw.length % 2 === 0) {
        preimageHex = preimageRaw;
    } else {
        preimageHex = Array.from(new TextEncoder().encode(preimageRaw)).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    showLoading('Building HTLC claim PSKB...');
    try {
        const fee = BigInt(el('cov-claim-fee') ? el('cov-claim-fee').value : '300000');
        const wsUrl = await resolveNodeUrl();
        const pskbHex = await create_covenant_atomic_claim(covAddr, destAddr, redeemHex, preimageHex, fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Atomic-claim PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        // Store preimage for QR sharing after broadcast
        window._lastClaimPreimage = preimageRaw;
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Atomic claim failed: ' + e, 'error', 5000);
        console.error('[KasSee] Atomic claim error:', e);
    }
}

async function handleCovPayjoinClaim() {
    const covAddr = el('cov-payjoin-claim-addr').value.trim();
    const redeemHex = el('cov-payjoin-claim-script').value.trim();
    const mixAddr = el('cov-payjoin-claim-mix-addr').value.trim();
    const destAddr = el('cov-payjoin-claim-dest').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!mixAddr) { toast('Enter your mixing address (must have UTXOs)', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    showLoading('Building PayJoin claim PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const pskbHex = await create_covenant_payjoin_claim(covAddr, destAddr, redeemHex, mixAddr, fee, wsUrl);
        hideLoading();
        console.log('[KasSee] PayJoin claim PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('PayJoin claim failed: ' + e, 'error', 5000);
        console.error('[KasSee] PayJoin claim error:', e);
    }
}

async function handleCovOracleClaim() {
    const covAddr = el('cov-oracle-claim-addr').value.trim();
    const redeemHex = el('cov-oracle-claim-script').value.trim();
    const oracleSig = el('cov-oracle-claim-sig').value.trim();
    const msgHash = el('cov-oracle-claim-hash').value.trim();
    const destAddr = el('cov-oracle-claim-dest').value.trim();

    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!oracleSig || oracleSig.length !== 128) { toast('Oracle signature must be 128 hex chars (64 bytes Schnorr)', 'error'); return; }
    if (!msgHash || msgHash.length !== 64) { toast('Message hash must be 64 hex chars (32 bytes)', 'error'); return; }
    if (!destAddr) { toast('Enter claim destination address', 'error'); return; }

    showLoading('Building oracle claim PSKB...');
    try {
        const fee = getCovFee();
        const wsUrl = await resolveNodeUrl();
        const pskbHex = await create_covenant_oracle_claim(covAddr, destAddr, redeemHex, oracleSig, msgHash, fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Oracle-claim PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Oracle claim failed: ' + e, 'error', 5000);
        console.error('[KasSee] Oracle claim error:', e);
    }
}


// ─── ZK Proof Covenant Handlers ───




// ─── Merkle Whitelist Vault Handlers ───

// Sompi -> KAS decimal string, exact (no float; the value feeds back into kasToSompi).
function sompiToKasStr(sompi) {
    const s = sompi.toString().padStart(9, '0');
    const intPart = s.slice(0, -8);
    const frac = s.slice(-8).replace(/0+$/, '');
    return frac ? intPart + '.' + frac : intPart;
}

// Max spendable for a merkle whitelist claim. Mirrors create_merkle_whitelist_spend:
// cap at the 4 largest UTXOs, depth-aware mass fee, 300k floor. Returns sompi or null.
// NOTE: the fee formula MUST stay in sync with create_merkle_whitelist_spend in lib.rs.
async function mwMaxSompi() {
    const covAddr = el('cov-mw-addr').value.trim();
    if (!covAddr) return null;
    const wsUrl = await resolveNodeUrl();
    const utxos = JSON.parse(await fetch_utxos_for_address_js(covAddr, wsUrl));
    if (!utxos.length) return null;
    utxos.sort((a, b) => { const x = BigInt(a.amount), y = BigInt(b.amount); return x > y ? -1 : (x < y ? 1 : 0); });
    const capped = utxos.slice(0, 4); // MAX_COV_INPUTS
    const total = capped.reduce((s, u) => s + BigInt(u.amount), 0n);
    const addrCount = el('cov-mw-spend-addresses').value.trim().split('\n').filter(a => a.trim()).length;
    const depth = Math.max(1, Math.ceil(Math.log2(Math.max(2, addrCount))));
    const perInput = 270 + 40 * depth + 1000;
    const computeMass = 46 + capped.length * perInput + 43 + 2 * 340;
    const fee = BigInt(Math.max(300000, computeMass * 115));
    const maxSompi = total - fee;
    return maxSompi > 0n ? maxSompi : null;
}

async function handleCovMwSpend() {
    const covAddr = el('cov-mw-addr').value.trim();
    const redeemHex = el('cov-mw-script').value.trim();
    const destAddr = el('cov-mw-dest').value.trim();
    const addrText = el('cov-mw-spend-addresses').value.trim();
    const amountKas = parseFloat(el('cov-mw-amount').value);

    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination (must be in whitelist)', 'error'); return; }
    if (!addrText) { toast('Enter the same whitelist used for creation', 'error'); return; }
    if (!amountKas || amountKas <= 0) { toast('Enter amount to send', 'error'); return; }

    const sendSompi = kasToSompi(el('cov-mw-amount').value);
    const addresses = addrText.split('\n').map(a => a.trim()).filter(a => a.length > 0);

    showLoading('Computing merkle proof...');
    try {
        const addrJson = JSON.stringify(addresses);
        const proofResult = merkle_proof_for_address(addrJson, destAddr);
        const proofInfo = JSON.parse(proofResult);
        console.log('[KasSee] Merkle proof:', proofInfo.proof.length, 'levels, leaf_index:', proofInfo.leaf_index);

        const fee = BigInt(300000);
        const wsUrl = await resolveNodeUrl();
        const proofStr = JSON.stringify(proofInfo.proof);
        const pskbHex = await create_merkle_whitelist_spend(
            covAddr, destAddr, redeemHex, proofStr, sendSompi, fee, wsUrl);
        hideLoading();
        console.log('[KasSee] Merkle whitelist PSKB: ' + pskbHex.length + ' hex chars');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Merkle spend failed: ' + e, 'error', 5000);
    }
}

// ─── KIP-21 ZK Bridge Handlers ───





// ─── KIP-21 ZK Rollup Handlers ───





// ─── Rollup Deposit (L1->L2) Handlers ───




// ─── Commit-Reveal Handlers ───

function handleCrHash() {
    const text = el('cov-cr-preimage').value.trim();
    if (!text) { toast('Enter your secret message', 'error'); return; }
    try {
        // Convert text to hex for WASM
        const preimageHex = Array.from(new TextEncoder().encode(text)).map(b => b.toString(16).padStart(2, '0')).join('');
        const hash = commit_hash(preimageHex);
        el('cov-cr-hash-display').textContent = 'BLAKE2B: ' + hash;
        toast('BLAKE2B hash computed', 'ok', 1500);
        console.log('[KasSee] Commit hash:', hash);
    } catch (e) {
        toast('Hash failed: ' + e, 'error');
    }
}

async function handleCovCrReveal() {
    const covAddr = el('cov-cr-addr').value.trim();
    const redeemHex = el('cov-cr-script').value.trim();
    const destAddr = el('cov-cr-dest').value.trim();

    if (!covAddr) { toast('Enter covenant address', 'error'); return; }
    if (!redeemHex) { toast('Enter redeem script hex', 'error'); return; }
    if (!destAddr) { toast('Enter destination address', 'error'); return; }

    // Get preimage from decrypt scan (stored as part_A, part_B is empty)
    const partA = window._crRevealPartA || '';
    const partB = window._crRevealPartB || '';
    if (!partA) {
        toast('Scan decrypted preimage from KasSigner first (step 2)', 'error');
        return;
    }

    showLoading('Building reveal PSKB...');
    try {
        const fee = BigInt(300000);
        const wsUrl = await resolveNodeUrl();

        // Build CR01 payload: "CR01" (4 bytes) + committed_hash (32 bytes)
        const commitHash = lastCovenantResult ? (lastCovenantResult.commit_hash || '') : '';
        let cr01Hex = '43523031'; // "CR01"
        if (commitHash.length === 64) cr01Hex += commitHash;
        window._covPayloadHex = cr01Hex;

        const pskbHex = await create_commit_reveal_spend(
            covAddr, destAddr, redeemHex, partA, partB, cr01Hex, fee, wsUrl);
        hideLoading();
        // Clear preimage from memory immediately after PSKB build
        window._crRevealPartA = null;
        window._crRevealPartB = null;
        window._crDecryptCtBytes = null;
        console.log('[KasSee] Commit-reveal PSKB built, CR01 payload: ' + cr01Hex.length/2 + ' bytes');
        _broadcastReturnScreen = 'covenant';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Reveal failed: ' + e, 'error', 5000);
    }
}

// ─── Supply Chain State Machine Handlers ───

function covScanKpubToField(fieldId, title) {
    startScanner(title || 'Scan kpub', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data)).trim();
        if (text.startsWith('kpub')) {
            stopScanner();
            try {
                const parsed = JSON.parse(parse_kpub(text));
                el(fieldId).value = text; // store the kpub — resolved at generation time
                showScreen('covenant');
                toast('kpub scanned: ' + parsed.account_pubkey.slice(0, 8) + '...', 'ok', 2000);
            } catch (e) {
                showScreen('covenant');
                toast('Invalid kpub: ' + e, 'error');
            }
        } else if (text.length === 64 && /^[0-9a-fA-F]+$/.test(text)) {
            stopScanner();
            el(fieldId).value = text;
            showScreen('covenant');
            toast('Pubkey scanned', 'ok', 1500);
        }
    });
}

function resolveKpubOrHex(value) {
    const v = value.trim();
    if (v.startsWith('kpub')) {
        try {
            const parsed = JSON.parse(parse_kpub(v));
            return parsed.account_pubkey; // x-only 32-byte hex
        } catch (e) {
            throw new Error('Invalid kpub: ' + e);
        }
    }
    if (v.length === 64 && /^[0-9a-fA-F]+$/.test(v)) {
        return v;
    }
    throw new Error('Enter a kpub string or 64-char hex pubkey');
}


// ─── RISC0 Succinct ZK Covenant Handlers ───



async function handleCovCheckBalance() {
    const covAddr = el('cov-balance-addr').value.trim();
    if (!covAddr) { toast('Enter covenant P2SH address', 'error'); return; }

    showLoading('Checking balance...');
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(covAddr, wsUrl);
        const utxos = JSON.parse(utxosJson);
        hideLoading();

        const total = utxos.reduce((s, u) => s + BigInt(u.amount), 0n);
        const kas = Number(total) / 1e8;
        const kasStr = kas === 0 ? '0' : kas.toFixed(8).replace(/\.?0+$/, '');

        el('cov-balance-kas').textContent = kasStr + ' KAS';
        el('cov-balance-utxos').textContent = utxos.length + ' UTXO' + (utxos.length !== 1 ? 's' : '') + ' · ' + total.toString() + ' sompi';
        el('cov-balance-result').classList.remove('hidden');

        if (utxos.length === 0) {
            toast('No UTXOs at this address', 'info', 2000);
        }
    } catch (e) {
        hideLoading();
        toast('Balance check failed: ' + e, 'error', 5000);
        console.error('[KasSee] Balance check error:', e);
    }
}

// ─── Stealth Addresses ───

let stealthAnnouncementsR = []; // Array of 32-byte hex R values from announcements

// ── Stealth fee selector (low / normal / priority). Mirrors the main send's
// fee-card flow (node feerate x representative mass, clamped to a floor) but on
// the stealth screens, with its own ids so it never collides with the main
// send's cards. `prefix` is the id stem ('sf' = stealth send, 'spf' = stealth
// spend); `ctx` selects the mass tier. `lastFeeEstimate` is the shared node
// estimate, so the rates adapt to live congestion.
function stealthFeeMass(ctx) { return ctx === 'spend' ? 2000 : 2500; } // 1-in-1-out vs 1-in-2-out + payload
function stealthFeeFloor(level) {
    if (level === 'low') return 2500;
    if (level === 'priority') return 300000;
    return 5000;
}
function stealthFeeCompute(level, ctx) {
    if (!lastFeeEstimate) return null;
    let feerate;
    if (level === 'low') feerate = lastFeeEstimate.low_sompi_per_gram;
    else if (level === 'priority') feerate = lastFeeEstimate.priority_sompi_per_gram;
    else feerate = lastFeeEstimate.normal_sompi_per_gram;
    return Math.max(stealthFeeFloor(level), Math.round((feerate || 1) * stealthFeeMass(ctx)));
}
function stealthFeeRenderCards(prefix, ctx) {
    if (!lastFeeEstimate) return;
    ['low', 'normal', 'priority'].forEach(lvl => {
        const amt = stealthFeeCompute(lvl, ctx);
        const a = el(prefix + '-' + lvl + '-amount');
        if (a && amt != null) a.textContent = amt.toLocaleString();
        const t = el(prefix + '-' + lvl + '-time');
        const secs = lastFeeEstimate[lvl + '_seconds'];
        if (t && secs != null) t.textContent = formatSeconds(secs);
    });
}
function stealthFeeSetLevel(prefix, ctx, level) {
    const amt = stealthFeeCompute(level, ctx);
    if (amt != null) { const inp = el('input-' + prefix + '-fee'); if (inp) inp.value = amt; }
    ['low', 'normal', 'priority'].forEach(lvl => {
        const b = el('btn-' + prefix + '-' + lvl);
        if (b) b.classList.toggle('fee-card-active', lvl === level);
    });
}
function stealthFeeValue(prefix, ctx) {
    const inp = el('input-' + prefix + '-fee');
    if (inp && inp.value) { const v = Math.round(parseFloat(inp.value)); if (v > 0) return BigInt(v); }
    const amt = stealthFeeCompute('normal', ctx);
    return BigInt(amt != null ? amt : stealthFeeFloor('normal'));
}
async function stealthFeePrepare(prefix, ctx) {
    try {
        const wsUrl = await resolveNodeUrl();
        lastFeeEstimate = JSON.parse(await get_fee_estimate(wsUrl));
    } catch (e) { console.log('[KasSee] stealth fee estimate:', e); }
    stealthFeeRenderCards(prefix, ctx);
    stealthFeeSetLevel(prefix, ctx, 'normal');
}

function stealthShowPanel(panel) {
    // Leaving the scan panel pauses only the panel-local visuals (device-QR
    // cycler + inserted QR box). The live BlockAdded watcher and the
    // accumulated R list stay alive across panel switches so payments made
    // from the send panel (or received while browsing) are still caught.
    // Full teardown happens only on leaving the stealth screen or on a
    // fresh Fetch (both call stealthScanStop()).
    if (panel !== 'scan') stealthScanPause();
    ['stealth-menu', 'stealth-meta-panel', 'stealth-send-panel', 'stealth-scan-panel'].forEach(id => {
        el(id).classList.add('hidden');
    });
    if (panel === 'menu') el('stealth-menu').classList.remove('hidden');
    if (panel === 'meta') el('stealth-meta-panel').classList.remove('hidden');
    if (panel === 'send') { el('stealth-send-panel').classList.remove('hidden'); el('stealth-send-result').classList.add('hidden'); }
    if (panel === 'scan') el('stealth-scan-panel').classList.remove('hidden');
}

function handleStealthMeta() {
    if (!walletData) { toast('Load wallet first', 'error'); return; }
    const wallet = JSON.parse(walletData);
    try {
        const result = JSON.parse(stealth_meta_from_kpub(wallet.kpub));
        el('stealth-meta-hex').textContent = result.meta_address;

        // Generate QR for the meta-address as PLAIN TEXT (the 128-hex string),
        // not the hex-decoded/framed binary form, so the meta scanner decodes it
        // directly via TextDecoder and matches /^[0-9a-fA-F]{128}$/.
        const qrContainer = el('stealth-meta-qr');
        qrContainer.innerHTML = '';
        try {
            qrContainer.innerHTML = generate_qr_svg_text(result.meta_address);
        } catch (e) {
            qrContainer.textContent = result.meta_address;
        }

        // Show announcement address
        const network = detectNetwork();
        el('stealth-announce-addr').textContent = stealth_announcement_address(network);

        stealthShowPanel('meta');
    } catch (e) {
        toast('Error: ' + e, 'error', 3000);
    }
}

function detectNetwork() {
    if (walletData) {
        const wallet = JSON.parse(walletData);
        if (wallet.receive_addresses && wallet.receive_addresses.length > 0) {
            const addr = wallet.receive_addresses[0];
            if (addr.startsWith('kaspatest:')) return network.startsWith('testnet') ? network : 'testnet-10';
            if (addr.startsWith('kaspasim:')) return 'simnet';
            if (addr.startsWith('kaspadev:')) return 'devnet';
        }
    }
    return 'mainnet';
}

function handleStealthSendGenerate() {
    const metaHex = el('stealth-send-meta').value.trim();
    if (!metaHex || metaHex.length !== 128) { toast('Enter 128-hex stealth meta-address', 'error'); return; }

    // Generate 32 bytes of entropy
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    const entropyHex = Array.from(entropy).map(b => b.toString(16).padStart(2, '0')).join('');

    const network = detectNetwork();
    try {
        const result = JSON.parse(stealth_generate_payment(metaHex, entropyHex, network));
        el('stealth-send-addr').textContent = result.address;
        el('stealth-send-r').textContent = result.ephemeral_r;
        el('stealth-send-result').classList.remove('hidden');
        stealthFeePrepare('sf', 'send'); // populate low/normal/priority from the node

        // Remember the entropy so "Send Payment" reuses the SAME R that was
        // previewed (otherwise the broadcast R would differ from what's shown).
        window._stealthSendEntropy = entropyHex;
        window._stealthSendMeta = metaHex;

        console.log('[KasSee] Stealth payment generated:',
            'address=' + result.address,
            'R=' + result.ephemeral_r,
            'index=' + result.stealth_index);
    } catch (e) {
        toast('Error: ' + e, 'error', 3000);
    }
}

// Build the actual stealth payment: pay the one-time address with R embedded
// in the TX payload, then hand the PSKB to the standard review/sign/broadcast
// flow. The receiver's live scan picks up R from the payment's payload.
async function handleStealthSendPay() {
    if (!walletData) { toast('Load wallet first', 'error'); return; }
    const metaHex = el('stealth-send-meta').value.trim();
    if (!metaHex || metaHex.length !== 128) { toast('Enter 128-hex stealth meta-address', 'error'); return; }
    const amountKas = parseFloat(el('stealth-send-amount').value);
    if (!(amountKas > 0)) { toast('Enter a valid amount', 'error'); return; }

    // Reuse the previewed entropy if it matches this meta-address; else fresh.
    let entropyHex = window._stealthSendEntropy;
    if (!entropyHex || window._stealthSendMeta !== metaHex) {
        const entropy = new Uint8Array(32);
        crypto.getRandomValues(entropy);
        entropyHex = Array.from(entropy).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    const network = detectNetwork();
    showLoading('Building stealth payment...');
    try {
        const wsUrl = await resolveNodeUrl();
        // Lane send on KSTL (device-signed). Fee from the low/normal/priority
        // selector (node feerate x mass), honoring a manual edit of the field.
        const resJson = await stealth_create_payment_lane(
            walletData, metaHex, kasToSompi(el('stealth-send-amount').value.trim()), stealthFeeValue('sf', 'send'), entropyHex, wsUrl, network
        );
        const res = JSON.parse(resJson);
        hideLoading();
        console.log('[KasSee] Stealth LANE payment PSKB:',
            'address=' + res.address, 'R=' + res.ephemeral_r, 'view_tag=' + res.view_tag);
        window._stealthSendEntropy = null; // consume
        window._stealthSendMeta = null;
        _broadcastReturnScreen = 'stealth';
        openPsktReview(res.pskb_wire);
    } catch (e) {
        hideLoading();
        toast('Stealth payment failed: ' + e, 'error', 5000);
        console.error('[KasSee] Stealth payment error:', e);
    }
}

// ─── Stealth REST catch-up (indexer-backed, survives pruning) ───
const KSTL_SUBNET_HEX = '4b53544c00000000000000000000000000000000'; // "KSTL" + 16 zeros (lane subnetwork id)
const STEALTH_MAX_R = 512;          // sanity bound on the candidate R list. The device
                                    // handoff pages in batches, so this only guards
                                    // against pathological growth; hitting it is
                                    // surfaced in the status, never a silent drop.
// Lookback in blue score. At ~10 BPS, 9000 is ~15 min.
//
// The cost is REQUESTS, and the window width is fixed by the endpoint, so
// extending the lookback multiplies the request count directly. Raising this
// only works to the extent the adaptive batch loop can push more through.
const STEALTH_LOOKBACK_BS = 9000;
// Window width. NOT tunable upward: the public endpoint caps each
// `acceptingBlueScores` range at 100 (TX_SEARCH_BS_LIMIT, noted above
// `stealthRestCatchUp`). A wider window is not a faster scan, it is a rejected
// request or a silently partial answer.
//
// And throughput cannot be raised either: concurrency was tried adaptively in
// both directions and a fixed 3 beat both. So a longer lookback simply takes
// proportionally longer.
const STEALTH_WIN_BS = 100;
// REMOVED: a truncation split on row count.
//
// The idea was insurance - halve a window that looks truncated rather than
// silently lose an announcement. It was actively harmful. A window is 100 blue
// score, about ten seconds of chain, which on mainnet routinely holds more than
// any sane threshold. So the check fired on ordinary busy windows and split
// them RECURSIVELY, doubling or quadrupling requests exactly where the chain is
// busiest - more throttling, slower scans.
//
// The endpoint caps the range at 100 rather than the row count, so a window
// cannot truncate in the first place. Insurance against a failure that cannot
// happen, paid for on every busy window.
                                    // Kept well under the public API per-IP limit where
                                    // 429s begin (~window 149), so a direct scan (no proxy)
                                    // completes cleanly. Deeper history needs the KST1 indexer.
const STEALTH_MAX_WINDOWS = 850;    // cap: each window is 100 blue score (TX_SEARCH_BS_LIMIT)

// Current tip blue score via the indexer: /info/blockdag gives the sink hash,
// /blocks/{sink} gives header.blueScore. (virtualDaaScore is NOT the blue score.)
async function stealthGetTipBlueScore(apiBase) {
    // One GET: virtual selected-parent (sink) blue score -> {"blueScore": N}.
    //
    // The SINK, deliberately, not the DAG frontier. It lags the tip, which is
    // what makes the scanned range settled: a transaction's
    // `accepting_block_blue_score` can still move near the frontier, so windows
    // taken from there could gain entries after being scanned. Starting from
    // the sink largely avoids that - "largely" because the selected-parent
    // chain can still reorganise a little near the sink.
    try {
        const j = await (await fetch(apiBase + '/info/virtual-chain-blue-score',
            { signal: AbortSignal.timeout(10000) })).json();
        const bs = parseInt((j && j.blueScore) || '0', 10);
        if (bs) return bs;
    } catch (e) { console.log('[KasSee] vc-blue-score failed, falling back to sink block:', e); }
    // Fallback: sink hash from /info/blockdag -> block header blueScore.
    const dag = await (await fetch(apiBase + '/info/blockdag', { signal: AbortSignal.timeout(10000) })).json();
    const sink = dag && dag.sink;
    if (!sink) throw new Error('no sink in /info/blockdag');
    const blk = await (await fetch(apiBase + '/blocks/' + sink, { signal: AbortSignal.timeout(10000) })).json();
    const bs2 = parseInt((blk && blk.header && blk.header.blueScore) || '0', 10);
    if (!bs2) throw new Error('no blueScore for sink block');
    return bs2;
}

// Catch-up via POST /transactions/search over accepting-blue-score windows.
// No self-hosted indexer: the public api-tn10 endpoint caps each range at 100
// blue score (TX_SEARCH_BS_LIMIT) and returns accepted txs with subnetwork_id +
// payload inline. Keep only KSTL-subnetwork txs and read R from the payload.
// Survives node pruning. Returns a deduped 64-hex R list.
async function stealthRestCatchUp(apiBase) {
    const tip = await stealthGetTipBlueScore(apiBase);
    const startBs = tip > STEALTH_LOOKBACK_BS ? tip - STEALTH_LOOKBACK_BS : 0;
    // subnetwork_id MUST be in fields= or the lane filter has nothing to match.
    const searchUrl = apiBase +
        '/transactions/search?fields=transaction_id,subnetwork_id,payload,accepting_block_blue_score&resolve_previous_outpoints=no';
    // Build 100-wide [gte, lt) windows up to the cap, NEWEST FIRST so a recent
    // announcement lands in the first batch instead of after the whole walk.
    const wins = [];
    for (let hi = tip + 1; hi > startBs && wins.length < STEALTH_MAX_WINDOWS; hi -= STEALTH_WIN_BS) {
        wins.push([Math.max(hi - STEALTH_WIN_BS, startBs), hi]);
    }
    console.log('[KasSee] REST catch-up: tip=' + tip + ' start=' + startBs +
        ' windows=' + wins.length);
    const foundR = [];
    const seen = new Set();
    let done = 0, firstErr = false;
    // Windows that returned nothing usable after their retries.
    //
    // `done` counts windows ATTEMPTED, and non-429 failures only log the first
    // one, so a run with several silent failures looked identical to a clean
    // one. For this scan that matters: a dropped window is a missed
    // announcement, which is a missed payment.
    //
    // Kept as a LIST, not a count: the failures are transient - the same
    // settings that dropped 11 windows returned all-ok on the previous run - so
    // they are worth a second pass rather than only a warning.
    let failedWins = [];
    // Counted rather than inferred: `runOne` retries internally, so a batch can
    // be throttled and still succeed. Without this the adaptive loop would read
    // a slow-but-successful batch as clean and keep ramping into the limiter.
    // FIXED 3. Not adaptive, after trying both directions.
    //
    // Ramping up made it worse - the probe is the cost, and 8 produced 429
    // floods where 3 produced none. Backing off to 2 on a throttle also made it
    // worse: one early throttle left the rest of the scan slower than the fixed
    // rate it replaced, and a longer scan is more exposure, not less.
    //
    // Every request here is also PREFLIGHTED: `application/json` is not
    // CORS-simple, so each window costs an OPTIONS plus the POST, and text/plain
    // is refused with 422 (tried 2026-08-16). At this rate the endpoint copes;
    // above it, the preflights fail first and a failed preflight blocks the
    // request with no status, which no backoff can help.
    //
    // More coverage comes from more TIME, or from STEALTH_INDEXER_URL, which is
    // not a shared public API.
    const CONC = 3;
    const sleep = ms => new Promise(res => setTimeout(res, ms));
    // Retry a throttled window instead of silently dropping it. 429 (and 503)
    // are transient: back off and retry a few times. A dropped window means a
    // missed R, so we spend a little wall time rather than lose a payment.
    async function runOne(gte, lt) {
        const MAX_RETRY = 4;
        for (let attempt = 0; attempt <= MAX_RETRY; attempt++) {
            try {
                // `application/json` and NOT text/plain, deliberately.
                //
                // text/plain is CORS-simple and would skip the OPTIONS
                // preflight, halving the requests. Tried on 2026-08-16: the
                // endpoint answers 422 Unprocessable Content - it will not
                // parse the body without a real JSON content type. So the
                // preflight cannot be avoided this way, and every window costs
                // two requests.
                //
                // Which means the earlier preflight failures were a symptom of
                // RATE, not of the header: they appeared when concurrency was
                // raised to 8 and vanished at 3. The ceiling stays at 3.
                const r = await fetch(searchUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ acceptingBlueScores: { gte: gte, lt: lt } }),
                    signal: AbortSignal.timeout(15000)
                });
                if (r.status === 429 || r.status === 503) {
                    if (attempt < MAX_RETRY) {
                        // Honor Retry-After if the server sends it, else exponential
                        // backoff with jitter: ~0.5s, 1s, 2s, 4s (+ up to 250ms).
                        const ra = parseInt(r.headers.get('retry-after') || '0', 10);
                        const backoff = ra > 0
                            ? ra * 1000
                            : (500 * Math.pow(2, attempt)) + Math.floor(Math.random() * 250);
                        await sleep(backoff);
                        continue;
                    }
                    if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search throttled (HTTP ' + r.status + ') at gte=' + gte + ' after ' + MAX_RETRY + ' retries'); }
                    failedWins.push([gte, lt]);
                    return;
                }
                if (!r.ok) {
                    if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search HTTP ' + r.status + ' at gte=' + gte); }
                    failedWins.push([gte, lt]);
                    return;
                }
                const txs = await r.json();
                if (Array.isArray(txs)) {
                    for (const tx of txs) {
                        if ((tx.subnetwork_id || '').toLowerCase() !== KSTL_SUBNET_HEX) continue;
                        let pl = (tx.payload || '').toLowerCase();
                        if (pl.startsWith('0x')) pl = pl.slice(2);
                        // lane payload = ver(0x01) || R(32) || view_tag(1) => 68 hex, R at offset 1 byte
                        if (pl.length < 68 || pl.slice(0, 2) !== '01') continue;
                        const rHex = pl.slice(2, 66);
                        if (!/^0+$/.test(rHex) && !seen.has(rHex)) { seen.add(rHex); foundR.push(rHex); }
                    }
                }
                break; // success: leave the retry loop
            } catch (e) {
                if (attempt < MAX_RETRY) { await sleep(500 * Math.pow(2, attempt)); continue; }
                if (!firstErr) { firstErr = true; console.log('[KasSee] tx-search fetch failed at gte=' + gte + ':', e); }
                failedWins.push([gte, lt]);
            }
        }
        done++;
    }
    for (let i = 0; i < wins.length; i += CONC) {
        await Promise.all(wins.slice(i, i + CONC).map(function (w) { return runOne(w[0], w[1]); }));
        // Small gap between batches so a steady scan stays well under the
        // endpoint's rate limit even when no 429 has fired yet.
        if (i + CONC < wins.length) { await sleep(150); }
        try {
            el('stealth-scan-status').textContent =
                'Scanning lane\u2026 ' + done + '/' + wins.length + ' windows, ' + foundR.length + ' R';
        } catch (_) {}
        // Surface R as soon as a batch finds it: push new ones to the global
        // list and reveal the device-QR button, so the user can proceed without
        // waiting for the whole walk to finish.
        if (foundR.length) {
            let added = false;
            for (const rHex of foundR) {
                if (rHex.length === 64 && stealthAnnouncementsR.indexOf(rHex) === -1 && stealthAnnouncementsR.length < 64) {
                    stealthAnnouncementsR.push(rHex); added = true;
                }
            }
            if (added) {
                try {
                    const list = el('stealth-r-list');
                    if (list) list.textContent = stealthAnnouncementsR.length + ' R value(s) loaded';
                    const qrBtn = el('btn-stealth-show-scan-qr');
                    if (qrBtn) qrBtn.classList.remove('hidden');
                } catch (_) {}
            }
        }
    }
    // SECOND PASS over the failures, one at a time.
    //
    // Every window is really two requests here - the CORS preflight and the
    // POST - so concurrency 3 is 6 in flight from the endpoint's side, and
    // under load the preflights are what fail first. Rather than slow the whole
    // scan for a minority of windows, retry just those serially with a wider
    // gap. Transient by nature: the same settings returned all-ok on the run
    // before the one that dropped 11.
    // Repeat until nothing is left, or the rounds run out.
    //
    // One serial pass took 16 failures down to 1, which says these are
    // transient rather than a wall: each pass clears most of what is left. So
    // repeat, with a widening gap, until coverage is complete.
    //
    // Bounded, because "until zero" against an endpoint that is genuinely
    // refusing would never end. After the last round the completion line says
    // what is still missing rather than pretending.
    const RETRY_ROUNDS = 4;
    for (let round = 1; round <= RETRY_ROUNDS && failedWins.length > 0; round++) {
        const retryList = failedWins.slice();
        failedWins = [];
        // Re-arm the one-shot error log. It is set on the first failure of the
        // first pass, so without this the retry passes would fail silently -
        // exactly the passes whose errors are worth seeing.
        firstErr = false;
        // 400, 800, 1200, 1600 ms between windows: a failure means the endpoint
        // is refusing right now, so each round asks more gently than the last.
        const gap = 400 * round;
        console.log('[KasSee] retry round ' + round + '/' + RETRY_ROUNDS + ': '
            + retryList.length + ' window(s), ' + gap + 'ms apart');
        for (const [gte, lt] of retryList) {
            await runOne(gte, lt);
            await sleep(gap);
        }
    }

    console.log('[KasSee] REST catch-up done: ' + wins.length + ' windows, '
        + (failedWins.length
            ? failedWins.length + ' FAILED after ' + RETRY_ROUNDS + ' retry rounds (coverage incomplete), '
            : 'all ok, ')
        + 'found ' + foundR.length + ' R');
    return foundR;
}

// Live on-chain stealth scan over the KSTL lane. We subscribe to BlockAdded and
// byte-scan each notification's raw Borsh for the 20-byte KSTL subnetwork id,
// then read the lane payload (ver 0x01 || R(32) || view_tag) at the offset that
// follows. A stray match is harmless: the device-side ECDH simply yields a P
// with no matching UTXO.
async function handleStealthFetchAnnouncements() {
    // Fresh scan: fully tear down any prior scan, QR, timer, and results first.
    stealthScanStop();

    // Out-of-band manual-R entry stays available as a fallback / debug path.
    ensureStealthManualRSection();

    // Drop stale candidates (stealthScanStop already cleared these; explicit for clarity).
    stealthAnnouncementsR = [];
    window._stealthBatchStart = 0;
    window._stealthResults = [];
    el('stealth-scan-status').textContent = 'Connecting to node for on-chain stealth scan...';

    try {
        const wsUrl = await resolveNodeUrl();
        const blockAddedReq = new Uint8Array(build_vcc_subscribe_request(44n)); // BlockAdded scope

        // Live-WS lifecycle: visible state + auto-reconnect. The old code
        // connected once; onerror wrote one status line that the catch-up
        // immediately overwrote, and onclose said nothing — a dead socket
        // was indistinguishable from a running one, so "live also running"
        // could be a lie. _stealthLiveUp feeds the status suffix and the
        // connector retries every 3s while this scan session is open.
        window._stealthLiveUp = false;
        window._stealthScanActive = true;
        // Dedicated live-status line: only the socket callbacks write it, so
        // catch-up status messages can never overwrite the live-scan state.
        const stealthLiveStatusEl = () => {
            let d = el('stealth-live-status');
            if (!d) {
                d = document.createElement('div');
                d.id = 'stealth-live-status';
                d.style.cssText = 'font-size:12px;margin-top:4px';
                const st = el('stealth-scan-status');
                if (st && st.parentNode) st.parentNode.insertBefore(d, st.nextSibling);
            }
            return d;
        };

        const stealthConnectLiveWs = () => {
            const ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';
            window._stealthScanWs = ws;

        // Lane discovery anchors on the 20-byte KSTL subnetwork id (see scan below).

            ws.onopen = () => {
                ws.send(blockAddedReq);
                window._stealthLiveUp = true;
                const d = stealthLiveStatusEl();
                d.style.color = 'var(--accent, #4caf50)';
                d.textContent = 'LIVE scan: connected — watching new blocks.';
                el('stealth-scan-status').textContent =
                    'Live scan running. Watching new blocks for stealth payments... (' +
                    stealthAnnouncementsR.length + ' R found)';
            };

        ws.onmessage = (evt) => {
            const data = new Uint8Array(evt.data);
            if (data.length < 4) return;
            let pos = (data[0] === 0x01) ? 9 : 1;
            if (pos >= data.length || data[pos] !== 0xFF) return;
            if (data[pos + 2] !== 0x3C) return; // BlockAddedNotification only

            let added = 0;
            // Anchor on the 20-byte KSTL subnetwork id (4b 53 54 4c + 16 zeros).
            // RpcTransaction Borsh: subnetwork[20] gas[8] payload{len u32[4], bytes}.
            // payload @ k+32 => len @ k+28 (0x22 00 00 00), ver @ k+32, R @ k+33.
            for (let k = 0; k + 66 <= data.length; k++) {
                if (data[k] !== 0x4b || data[k + 1] !== 0x53 || data[k + 2] !== 0x54 || data[k + 3] !== 0x4c) continue;
                let zeros = true;
                for (let z = 4; z < 20; z++) { if (data[k + z] !== 0x00) { zeros = false; break; } }
                if (!zeros) continue;
                if (data[k + 28] !== 0x22 || data[k + 29] !== 0x00 || data[k + 30] !== 0x00 || data[k + 31] !== 0x00) continue;
                if (data[k + 32] !== 0x01) continue;
                let rHex = '';
                for (let j = 0; j < 32; j++) rHex += data[k + 33 + j].toString(16).padStart(2, '0');
                if (/^0+$/.test(rHex)) continue;                     // skip all-zero
                if (stealthAnnouncementsR.includes(rHex)) continue;  // dedupe
                if (stealthAnnouncementsR.length >= STEALTH_MAX_R) { // never drop silently
                    el('stealth-scan-status').textContent =
                        'R list full (' + STEALTH_MAX_R + '). New payments are NOT being recorded — process the current batch first.';
                    break;
                }
                stealthAnnouncementsR.push(rHex);
                added++;
            }
            if (added > 0) {
                el('stealth-scan-status').textContent =
                    'Live scan running. ' + stealthAnnouncementsR.length +
                    ' candidate R found. Tap "Show Scan QR" to check on your device.';
                const list = el('stealth-r-list');
                if (list) list.textContent = stealthAnnouncementsR.length + ' R value(s) loaded';
                el('btn-stealth-show-scan-qr').classList.remove('hidden');
                console.log('[KasSee] Stealth scan: +' + added + ' R (total ' +
                    stealthAnnouncementsR.length + ')');
            }
        };

            ws.onerror = () => {
                console.log('[KasSee] Stealth live WS error');
            };
            // Any close (failed handshake, node drop, proxy timeout) marks the
            // live scan DOWN and retries in 3s — but only if this socket is
            // still the current one (stealthScanStop / a fresh Fetch replaces
            // _stealthScanWs, which cancels the reconnect chain).
            ws.onclose = () => {
                if (window._stealthScanWs !== ws) return;
                window._stealthScanWs = null;
                window._stealthLiveUp = false;
                // Drop the CACHED node before reconnecting.
                //
                // The resolved node is now held for the session, so without
                // this the live scan retries the SAME node every 3 s forever -
                // if that node refuses the subscription or is down, the loop
                // never escapes. Before the cache each retry re-resolved and
                // eventually found a working one; this restores that while
                // keeping the cache for everything else.
                if (typeof invalidateResolvedNode === 'function') invalidateResolvedNode();
                const d = stealthLiveStatusEl();
                d.style.color = 'var(--error, #f44336)';
                d.textContent = 'LIVE scan: DOWN — new payments are NOT being watched. Reconnecting…';
                console.log('[KasSee] Stealth live WS closed, reconnecting in 3s');
                setTimeout(() => {
                    // Reconnect only if this scan session is still active and
                    // no newer socket took over meanwhile.
                    if (window._stealthScanActive && window._stealthScanWs === null) stealthConnectLiveWs();
                }, 3000);
            };
        };
        stealthConnectLiveWs();

        // Historical catch-up via the REST indexer: scans a recent blue-score
        // window for KST1-tagged payloads. Survives node pruning and covers the
        // offline gap (the wRPC sink-walk was ~5s of history at 10 BPS).
        // While this runs, _stealthCatchupRunning gates Show-QR and Add-R so the
        // device is never handed a half-filled R set (a false "no funds").
        window._stealthCatchupRunning = true;
        try {
            const apiBase = KASPA_REST_API[network];
            if (apiBase) {
                el('stealth-scan-status').textContent = 'Scanning recent blocks via indexer\u2026 (live also running)';
                let recent;
                if (stealthIndexerEnabled) {
                    try {
                        el('stealth-scan-status').textContent = 'Fetching R from stealth indexer\u2026 (live also running)';
                        const resp = await fetch(STEALTH_INDEXER_URL + '/r?since=0', { signal: AbortSignal.timeout(10000) });
                        if (!resp.ok) throw new Error('indexer HTTP ' + resp.status);
                        recent = await resp.json();
                        if (!Array.isArray(recent)) throw new Error('indexer returned non-array');
                        console.log('[KasSee] stealth indexer returned ' + recent.length + ' R');
                    } catch (e) {
                        console.log('[KasSee] stealth indexer unreachable, falling back to in-browser scan:', e);
                        el('stealth-scan-status').textContent = 'Indexer unreachable, scanning in-browser\u2026 (live also running)';
                        recent = await stealthRestCatchUp(apiBase);
                    }
                } else {
                    recent = await stealthRestCatchUp(apiBase);
                }
                let added = 0;
                let capHit = false;
                for (const rHex of recent) {
                    if (typeof rHex !== 'string' || rHex.length !== 64) continue;
                    if (stealthAnnouncementsR.includes(rHex)) continue;
                    if (stealthAnnouncementsR.length >= STEALTH_MAX_R) { capHit = true; break; }
                    stealthAnnouncementsR.push(rHex);
                    added++;
                }
                if (capHit) {
                    console.log('[KasSee] Stealth catch-up hit STEALTH_MAX_R cap (' + STEALTH_MAX_R + ')');
                }
                if (stealthAnnouncementsR.length > 0) {
                    const list = el('stealth-r-list');
                    if (list) list.textContent = stealthAnnouncementsR.length + ' R value(s) loaded';
                    el('btn-stealth-show-scan-qr').classList.remove('hidden');
                    el('stealth-scan-status').textContent =
                        'Found ' + stealthAnnouncementsR.length +
                        ' candidate R (lane + live). Tap "Show QR for Device".';
                } else {
                    const approxMin = Math.round(STEALTH_LOOKBACK_BS / 10 / 60);
                    el('stealth-scan-status').textContent =
                        'No payments in the last ~' + approxMin + ' min. Live scan now watching for new ones while this stays open\u2026';
                }
                console.log('[KasSee] Stealth REST catch-up: +' + added + ' R (total ' +
                    stealthAnnouncementsR.length + ')');
            }
        } catch (ce) {
            console.log('[KasSee] Stealth REST catch-up skipped:', ce);
        } finally {
            window._stealthCatchupRunning = false;
        }
    } catch (e) {
        el('stealth-scan-status').textContent = 'Error: ' + e;
    }
}

// Panel-switch cleanup only: stops the device-QR frame cycler, an active
// camera scan, and removes the inserted QR box. Leaves the live BlockAdded
// WebSocket, the R list, and device results untouched.
function stealthScanPause() {
    if (window._stealthQrTimer) {
        try { clearInterval(window._stealthQrTimer); } catch (_) {}
        window._stealthQrTimer = null;
    }
    if (scanStream) { try { stopScanner(); } catch (_) {} }
    const qrBox = el('stealth-scan-qr-display');
    if (qrBox && qrBox.parentNode) qrBox.parentNode.removeChild(qrBox);
}

function stealthScanStop() {
    // Deactivate the session first: any pending live-WS reconnect timer
    // checks this flag and will not resurrect a stopped scan.
    window._stealthScanActive = false;
    window._stealthLiveUp = false;
    const liveEl = el('stealth-live-status');
    if (liveEl && liveEl.parentNode) liveEl.parentNode.removeChild(liveEl);
    // Close the live BlockAdded subscription.
    if (window._stealthScanWs) {
        try { window._stealthScanWs.close(); } catch (_) {}
        window._stealthScanWs = null;
    }
    // Stop the device-QR frame cycler.
    if (window._stealthQrTimer) {
        try { clearInterval(window._stealthQrTimer); } catch (_) {}
        window._stealthQrTimer = null;
    }
    // Stop a live camera scanner ONLY if one is actually running. stopScanner()
    // ends with showScreen(returnScreen), so calling it with no active stream
    // bounces the user to the dashboard. scanStream is non-null only during a scan.
    if (scanStream) { try { stopScanner(); } catch (_) {} }
    // Remove the dynamically inserted device-scan QR so it cannot persist on the panel.
    const qrBox = el('stealth-scan-qr-display');
    if (qrBox && qrBox.parentNode) qrBox.parentNode.removeChild(qrBox);
    // Drop candidate R set, device results, batch cursor, and the in-flight guard.
    stealthAnnouncementsR = [];
    window._stealthResults = [];
    window._stealthBatchStart = 0;
    window._stealthCatchupRunning = false;
    // Reset the scan panel UI to a clean state.
    const st = el('stealth-scan-status'); if (st) st.textContent = '';
    const fl = el('stealth-found-list'); if (fl) fl.innerHTML = '';
    const res = el('stealth-scan-results'); if (res) res.classList.add('hidden');
    const rl = el('stealth-r-list'); if (rl) rl.textContent = '';
    const mi = el('stealth-manual-r-input'); if (mi) mi.value = '';
    const bq = el('btn-stealth-show-scan-qr'); if (bq) bq.classList.add('hidden');
    const br = el('btn-stealth-scan-result-qr'); if (br) br.classList.add('hidden');
    console.log('[KasSee] Stealth scan: stopped and reset');
}

function ensureStealthManualRSection() {
    if (el('stealth-manual-r-input')) return;
    const div = document.createElement('div');
    div.id = 'stealth-manual-r-section';
    div.style.cssText = 'margin-top:8px';
    div.innerHTML = `
        <label class="input-label">Manual R entry (64 hex — out-of-band fallback)</label>
        <input type="text" id="stealth-manual-r-input" class="input-text"
               placeholder="64-char hex (sender's ephemeral R)" autocomplete="off" spellcheck="false">
        <button class="btn btn-outline" id="btn-stealth-add-r" style="width:100%;margin-top:4px">
            Add R Value
        </button>
        <div id="stealth-r-list" style="font-size:11px;margin-top:4px;color:var(--text-dim)"></div>
    `;
    el('stealth-scan-panel').insertBefore(div, el('btn-stealth-scan-back'));
    el('btn-stealth-add-r').onclick = () => {
        if (window._stealthCatchupRunning) { toast('Lane scan still running, please wait', 'error'); return; }
        const r = el('stealth-manual-r-input').value.trim();
        if (r.length !== 64 || !/^[0-9a-fA-F]+$/.test(r)) { toast('R must be 64 hex chars', 'error'); return; }
        if (!stealthAnnouncementsR.includes(r)) stealthAnnouncementsR.push(r);
        el('stealth-manual-r-input').value = '';
        el('stealth-r-list').textContent = stealthAnnouncementsR.length + ' R value(s) loaded';
        el('btn-stealth-show-scan-qr').classList.remove('hidden');
    };
}

function handleStealthShowScanQR() {
    if (window._stealthCatchupRunning) {
        const st = el('stealth-scan-status');
        if (st) st.textContent = 'Lane scan still running. Wait for it to finish before scanning to your device, so no payment is missed.';
        toast('Lane scan still running, please wait', 'error');
        return;
    }
    if (stealthAnnouncementsR.length === 0) { toast('No R values to scan', 'error'); return; }

    // The device scans up to 3 R per QR (V5 capacity). Page through the
    // candidate list in batches of 3 via _stealthBatchStart, advanced after
    // each STLR response in handleStealthScanResultQR.
    let start = window._stealthBatchStart || 0;
    if (start >= stealthAnnouncementsR.length) { start = 0; window._stealthBatchStart = 0; }
    const count = Math.min(stealthAnnouncementsR.length - start, 64);

    // Build STLH QR payload: header(4) + count(1) + R1(32) + R2(32) + ...
    const payload = new Uint8Array(5 + count * 32);
    payload[0] = 0x53; // 'S'
    payload[1] = 0x54; // 'T'
    payload[2] = 0x4C; // 'L'
    payload[3] = 0x48; // 'H'
    payload[4] = count;
    for (let i = 0; i < count; i++) {
        const rBytes = new Uint8Array(stealthAnnouncementsR[start + i].match(/.{2}/g).map(b => parseInt(b, 16)));
        payload.set(rBytes, 5 + i * 32);
    }

    // Convert to hex for generate_qr_frames
    const hexStr = Array.from(payload).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('[KasSee] STLH QR payload:', hexStr, '(' + payload.length + ' bytes, R ' +
        (start + 1) + '-' + (start + count) + ' of ' + stealthAnnouncementsR.length + ')');

    // Generate QR SVG using WASM
    if (window._stealthQrTimer) { clearInterval(window._stealthQrTimer); window._stealthQrTimer = null; }
    try {
        const frames = JSON.parse(generate_qr_frames(hexStr));
        console.log('[KasSee] STLH frames:', frames.length, 'for', payload.length, 'bytes (multi-frame if > 1)');
        const existingQr = document.getElementById('stealth-scan-qr-display');
        if (existingQr) existingQr.remove();

        const qrBox = document.createElement('div');
        qrBox.id = 'stealth-scan-qr-display';
        qrBox.style.cssText = 'margin:12px auto;text-align:center';
        el('stealth-scan-panel').insertBefore(qrBox, el('btn-stealth-scan-result-qr'));

        const rangeMsg = '<strong>Scanning R ' + (start + 1) + '\u2013' + (start + count) +
            ' of ' + stealthAnnouncementsR.length + '.</strong> ';
        if (frames.length <= 1) {
            qrBox.innerHTML = frames[0].svg;
            el('stealth-scan-status').innerHTML = rangeMsg +
                'Point the device camera at this QR, then scan the response back.';
        } else {
            // Auto-cycling multi-frame STLH; the device accumulates frames across passes.
            let fi = 0;
            const renderFrame = () => {
                qrBox.innerHTML = frames[fi].svg +
                    '<div style="font-size:11px;color:var(--text-dim);margin-top:6px">Frame ' +
                    (fi + 1) + '/' + frames.length + '</div>';
            };
            renderFrame();
            window._stealthQrTimer = setInterval(() => { fi = (fi + 1) % frames.length; renderFrame(); }, 600);
            el('stealth-scan-status').innerHTML = rangeMsg + 'Hold the device camera on this animated QR (' +
                frames.length + ' frames) until all are captured, then scan the response back.';
        }
        el('btn-stealth-scan-result-qr').classList.remove('hidden');
    } catch (e) {
        toast('QR generation failed: ' + e, 'error', 3000);
        console.error('[KasSee] QR gen error:', e);
    }
}

function handleStealthScanResultQR() {
    window._stlrFrames = null;
    const processStlr = (raw) => {
        const count = raw[4];
        stopScanner();
        if (window._stealthQrTimer) { clearInterval(window._stealthQrTimer); window._stealthQrTimer = null; }
        showScreen('stealth');
        stealthShowPanel('scan');

            window._stealthResults = window._stealthResults || [];
            for (let i = 0; i < count; i++) {
                const offset = 5 + i * 64;
                const pHex = Array.from(raw.slice(offset, offset + 32)).map(b => b.toString(16).padStart(2, '0')).join('');
                const tweakHex = Array.from(raw.slice(offset + 32, offset + 64)).map(b => b.toString(16).padStart(2, '0')).join('');
                if (/^0+$/.test(pHex)) continue;                                  // device marks invalid R as zeros
                if (window._stealthResults.some(r => r.pubkey === pHex)) continue; // dedupe across batches
                window._stealthResults.push({ pubkey: pHex, tweak: tweakHex });
            }

            // Show only the payments this wallet can actually spend. The device
            // returns a valid one-time pubkey for every R it is handed, including
            // R sent to other wallets (those derive a real address that simply
            // holds nothing) and our own already-spent R. Filtering on a live
            // balance drops both, so the list shows only funds belonging to this
            // wallet instead of a column of "already spent" rows.
            const scanNet = detectNetwork();
            el('stealth-found-list').innerHTML = 'Checking balances...';
            el('stealth-scan-results').classList.remove('hidden');

            (async () => {
                let wsUrl;
                try { wsUrl = await resolveNodeUrl(); }
                catch (_) { el('stealth-found-list').innerHTML = 'Node unavailable, cannot check balances.'; return; }

                // ONE call for every candidate, not one per candidate.
                //
                // This looped `fetch_utxos_for_address_js` over up to
                // STEALTH_MAX_R = 512 results, each a full RPC round trip, for
                // a question `getUtxosByAddresses` answers in a single request.
                //
                // Attribution comes from each UTXO's own `script_public_key`,
                // so nothing is lost by asking once: a P2PK script is
                // 0x20 <32-byte pubkey> 0xAC, and the pubkey identifies the
                // candidate it belongs to.
                const funded = [];
                const cand = [];
                for (const r of window._stealthResults) {
                    let addr = '';
                    try { addr = encode_p2pk_address(r.pubkey, scanNet); } catch (_) {}
                    if (addr) cand.push({ r: r, addr: addr });
                }
                if (cand.length > 0) {
                    let utxos = [];
                    try {
                        utxos = JSON.parse(await fetch_utxos_for_addresses_js(
                            JSON.stringify(cand.map(c => c.addr)), wsUrl));
                    } catch (_) { /* node unavailable: nothing shown as funded */ }
                    // Sum per pubkey, read out of each UTXO's script.
                    const byPubkey = new Map();
                    for (const u of utxos) {
                        const spk = u.script_public_key;
                        const hex = Array.isArray(spk)
                            ? spk.map(b => b.toString(16).padStart(2, '0')).join('')
                            : String(spk || '');
                        // 20 <64 hex> ac
                        if (hex.length < 68 || !hex.startsWith('20') || !hex.endsWith('ac')) continue;
                        const pk = hex.slice(2, 66);
                        byPubkey.set(pk, (byPubkey.get(pk) || 0n) + BigInt(u.amount));
                    }
                    for (const c of cand) {
                        const total = byPubkey.get(String(c.r.pubkey).toLowerCase()) || 0n;
                        if (total > 0n) {
                            funded.push({ pubkey: c.r.pubkey, tweak: c.r.tweak, addr: c.addr, total: total });
                        }
                    }
                }

                if (funded.length === 0) {
                    el('stealth-found-list').innerHTML = 'No funded payments for this wallet.';
                    return;
                }

                let foundHtml = '<label class="input-label">Fee</label>'
                    + '<div class="fee-cards">'
                    + '<button class="fee-card" id="btn-spf-low"><div class="fee-card-label">Low</div><div class="fee-card-amount" id="spf-low-amount">2,500</div><div class="fee-card-time" id="spf-low-time"></div></button>'
                    + '<button class="fee-card fee-card-active" id="btn-spf-normal"><div class="fee-card-label">Normal</div><div class="fee-card-amount" id="spf-normal-amount">5,000</div><div class="fee-card-time" id="spf-normal-time"></div></button>'
                    + '<button class="fee-card" id="btn-spf-priority"><div class="fee-card-label">Priority</div><div class="fee-card-amount" id="spf-priority-amount">10,000</div><div class="fee-card-time" id="spf-priority-time"></div></button>'
                    + '</div>'
                    + '<input type="number" id="input-spf-fee" class="input-text" value="5000" step="1" min="1" style="margin-bottom:10px">';
                funded.forEach((r, i) => {
                    foundHtml += '<div style="margin:6px 0;padding:10px;background:var(--card-bg);border-radius:6px">';
                    foundHtml += '<div style="font-size:12px;margin-bottom:2px">';
                    foundHtml += '<span style="color:var(--accent-teal)">Payment ' + (i + 1) + '</span> &middot; ';
                    foundHtml += '<span style="color:var(--accent-teal)">' + (Number(r.total) / 1e8).toFixed(2) + ' KAS</span></div>';
                    foundHtml += '<div style="font-size:10px;word-break:break-all;color:var(--text-dim);margin-bottom:6px">' + r.addr + '</div>';
                    foundHtml += '<button class="btn btn-primary stealth-spend-btn" style="width:100%;font-size:12px" ';
                    foundHtml += 'data-pubkey="' + r.pubkey + '" data-tweak="' + r.tweak + '">Spend This Payment</button>';
                    foundHtml += '</div>';
                });
                el('stealth-found-list').innerHTML = foundHtml;
                el('stealth-found-list').querySelectorAll('.stealth-spend-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        handleStealthSpend(btn.dataset.pubkey, btn.dataset.tweak);
                    });
                });
                ['low', 'normal', 'priority'].forEach(lvl => {
                    const b = el('btn-spf-' + lvl);
                    if (b) b.onclick = () => stealthFeeSetLevel('spf', 'spend', lvl);
                });
                stealthFeePrepare('spf', 'spend'); // populate low/normal/priority from the node
            })();

            // Advance the batch cursor; prompt for the next batch if any R remain.
            window._stealthBatchStart = (window._stealthBatchStart || 0) + count;
            const remaining = stealthAnnouncementsR.length - window._stealthBatchStart;
            if (remaining > 0) {
                el('stealth-scan-status').innerHTML = '<strong>' + remaining +
                    ' more R to check.</strong> Tap "Show Scan QR" for the next batch.';
            }
            toast('Scanned ' + count + ' result(s)' + (remaining > 0 ? ', ' + remaining + ' R left' : ''), 'ok', 2000);
    };
    startScanner('Scan Device Stealth Response', (data) => {
        const raw = new Uint8Array(data);
        // Direct single-frame STLR (checked first so its header is never read as a fragment).
        if (raw.length >= 69 && raw[0] === 0x53 && raw[1] === 0x54 && raw[2] === 0x4C && raw[3] === 0x52) {
            processStlr(raw); return;
        }
        // Multi-frame fragment: [idx][total][frag_len][payload]. A frame index is
        // always small (< n_frames), so it never collides with 'S' (0x53).
        if (raw.length >= 4 && raw[1] >= 2 && raw[2] > 0 && raw[2] + 3 <= raw.length) {
            const frameIdx = raw[0], totalFrames = raw[1], fragLen = raw[2];
            const payload = raw.slice(3, 3 + fragLen);
            if (!window._stlrFrames || window._stlrFrames.total !== totalFrames) {
                window._stlrFrames = { total: totalFrames, received: new Set(), bufs: new Array(totalFrames) };
            }
            const fr = window._stlrFrames;
            if (!fr.received.has(frameIdx)) {
                fr.received.add(frameIdx); fr.bufs[frameIdx] = payload;
                el('stealth-scan-status').innerHTML = '<strong>Receiving response ' + fr.received.size + '/' + totalFrames + '.</strong> Keep the camera on the device QR.';
            }
            if (fr.received.size < totalFrames) return;
            let totalLen = 0; for (let k = 0; k < totalFrames; k++) totalLen += fr.bufs[k].length;
            const assembled = new Uint8Array(totalLen);
            let off = 0; for (let k = 0; k < totalFrames; k++) { assembled.set(fr.bufs[k], off); off += fr.bufs[k].length; }
            window._stlrFrames = null;
            if (assembled.length >= 69 && assembled[0] === 0x53 && assembled[1] === 0x54 && assembled[2] === 0x4C && assembled[3] === 0x52) processStlr(assembled);
        }
    });
}

// ─── Stealth Spend ───

async function handleStealthSpend(pubkeyHex, tweakHex) {
    if (!walletData) { toast('Load wallet first', 'error'); return; }

    // The one-time address for this stealth UTXO
    const network = detectNetwork();
    const prefix = network.startsWith('testnet') ? 'kaspatest' : 'kaspa';

    // Build a normal P2PK spend but with stealthTweak in proprietaries
    showLoading('Building stealth spend...');
    try {
        const wsUrl = await resolveNodeUrl();
        const wallet = JSON.parse(walletData);

        // Derive the one-time address from the pubkey
        // P2PK address = encode_p2pk(pubkeyHex)
        // We need a dest address — use Bob's first receive address
        const destAddr = wallet.receive_addresses[0];

        // Spend fee from the low/normal/priority selector (node feerate x mass).
        const pskbHex = await create_stealth_spend(
            pubkeyHex, tweakHex, destAddr, stealthFeeValue('spf', 'spend'), wsUrl, network
        );

        hideLoading();
        console.log('[KasSee] Stealth spend PSKB:', pskbHex.length, 'hex chars');
        _broadcastReturnScreen = 'stealth';
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Stealth spend failed: ' + e, 'error', 5000);
        console.error('[KasSee] Stealth spend error:', e);
    }
}

// ─── Camera QR scanner ───

let _scannerReturnScreen = null;
let _scannerReturnPanel = null;

function startScanner(title, callback, returnPanel) {
    scanCallback = callback;
    _scannerReturnScreen = currentScreenName || 'dashboard';
    if (returnPanel !== undefined) _scannerReturnPanel = returnPanel;
    el('scanner-title').textContent = title;
    el('scanner-status').textContent = 'Starting camera...';
    reset_qr_decoder();
    showScreen('scanner');

    const video = el('scanner-video');
    const canvas = el('scanner-canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 720 }, height: { ideal: 720 } }
    }).then(stream => {
        scanStream = stream;
        video.srcObject = stream;
        video.play();
        el('scanner-status').textContent = 'Point at QR code';
        scanLoop(video, canvas, ctx);
    }).catch(err => {
        el('scanner-status').textContent = 'Camera error: ' + err.message;
    });
}

function scanLoop(video, canvas, ctx) {
    if (!scanStream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
        if (code && code.binaryData && code.binaryData.length > 0) {
            if (scanCallback) scanCallback(new Uint8Array(code.binaryData));
        }
    }
    scanAnimFrame = requestAnimationFrame(() => scanLoop(video, canvas, ctx));
}

function stopScanner() {
    if (scanAnimFrame) { cancelAnimationFrame(scanAnimFrame); scanAnimFrame = null; }
    if (scanStream) { scanStream.getTracks().forEach(t => t.stop()); scanStream = null; }
    scanCallback = null;
    const returnScreen = _scannerReturnScreen || (walletData ? 'dashboard' : 'welcome');
    const returnPanel = _scannerReturnPanel;
    _scannerReturnScreen = null;
    _scannerReturnPanel = null;
    showScreen(returnScreen);
    if (returnPanel) covShowPanel(returnPanel);
    // If we paused a QR cycle to open the scanner and the user cancelled
    // back to the QR display, resume the animation so they aren't stuck
    // on a frozen frame with non-functional play/pause controls.
    if (returnScreen === 'qr-display') resumeQrCycleIfPossible();
}

// ─── Addresses ───

let addressesReturnScreen = 'dashboard';
function explorerUrl(addr) {
    const prefix = (network === 'mainnet') ? '' : 'tn10.';
    return `https://${prefix}explorer.kaspa.org/addresses/${addr}`;
}
// First 20 receive and 10 change of the loaded branch, funded ones marked.
// Renders into the same `screen-addresses` as single-sig.
function showAddressesMultisig() {
    // Return where you CAME FROM, not to the wallet.
    //
    // Hardcoding 'ms-wallet' meant opening the address list while building a
    // transaction threw the half-filled form away. The single-sig path already
    // remembers the caller; this now does the same.
    addressesReturnScreen = (currentScreenName && currentScreenName !== 'addresses')
        ? currentScreenName : 'ms-wallet';
    const funded = new Set((msBranch.funded || []).map(f => f.chain + ':' + f.index));
    const row = (chain, i) => {
        let a;
        try { a = multisig_address_at_js(msBranch.descriptor, i, msBranch.cosigner, chain); }
        catch (_) { return ''; }
        const isFunded = funded.has(chain + ':' + i);
        // Spent-empty is NOT fresh. Without this an address that was funded and
        // emptied looks identical to one never used, which is exactly the
        // address that must not be handed out again.
        const usedSet = chain === 1 ? msBranch.usedChange : msBranch.usedReceive;
        const isUsed = !isFunded && usedSet && usedSet.has(i);
        // Same row shape as single-sig: explorer link, copy icon, tap to verify.
        return '<div class="addr-item' + (isFunded || isUsed ? ' addr-used' : '')
            + '" data-addr="' + i + (chain === 1 ? '-c' : '-r') + '">'
            + '<span class="addr-idx">' + i + '</span>'
            + '<span class="addr-val">' + a + '</span>'
            + (isFunded ? '<span class="addr-badge">funded</span>'
                        : (isUsed ? '<span class="addr-badge used">used</span>' : ''))
            + '<a class="addr-explore" href="' + explorerUrl(a)
            + '" target="_blank" rel="noopener" title="View in explorer">↗</a>'
            + '<span class="copy-icon">⧉</span>'
            + '</div>';
    };
    let html = "<div class=\"addr-section-title\">Receive — branch S"
        + msBranch.cosigner + " (C0)</div>";
    for (let i = 0; i < 20; i++) html += row(0, i);
    html += "<div class=\"addr-section-title\">Change — branch S"
        + msBranch.cosigner + " (C1)</div>";
    for (let i = 0; i < 10; i++) html += row(1, i);
    el('address-list').innerHTML = html;
    wireAddressRows(true);
    showScreen('addresses');
}

function showAddresses() {
    // Same screen for both wallets.
    //
    // A multisig address is a hash over EVERY cosigner's key, so it cannot come
    // from `walletData` the way a single-sig address does - but the list, the
    // styling, the funded badges and the Back behaviour are all the same, so
    // the view is shared and only the derivation differs.
    // Any multisig screen, not just the wallet: the tab is reachable from the
    // spend screen too, and there it was falling through to the single-sig
    // branch and showing the wrong wallet's addresses.
    if (msActive && msBranch) { showAddressesMultisig(); return; }
    if (!walletData) return;
    addressesReturnScreen = (currentScreenName && currentScreenName !== 'addresses') ? currentScreenName : 'dashboard';
    const wallet = JSON.parse(walletData);
    const rcvFunded = new Set(fundedReceiveIndices);
    const chgFunded = new Set(fundedChangeIndices);
    let html = '<div class="addr-section-title">Receive (m/44\'/111111\'/0\'/0)</div>';
    wallet.receive_addresses.forEach((addr, i) => {
        const funded = rcvFunded.has(i);
        const used = !funded && usedReceiveIndices.has(i);
        const dimmed = funded || used;
        html += `<div class="addr-item${dimmed ? ' addr-used' : ''}" data-addr="${i}-r">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            ${funded ? '<span class="addr-badge">funded</span>' : ''}
            ${used ? '<span class="addr-badge used">used</span>' : ''}
            <a class="addr-explore" href="${explorerUrl(addr)}" target="_blank" rel="noopener" title="View in explorer">↗</a>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    html += '<div class="addr-section-title">Change (m/44\'/111111\'/0\'/1)</div>';
    wallet.change_addresses.forEach((addr, i) => {
        const funded = chgFunded.has(i);
        const used = !funded && usedChangeIndices.has(i);
        const dimmed = funded || used;
        html += `<div class="addr-item${dimmed ? ' addr-used' : ''}" data-addr="${i}-c">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            ${funded ? '<span class="addr-badge">funded</span>' : ''}
            ${used ? '<span class="addr-badge used">used</span>' : ''}
            <a class="addr-explore" href="${explorerUrl(addr)}" target="_blank" rel="noopener" title="View in explorer">↗</a>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    el('address-list').innerHTML = html;

    wireAddressRows(false);
    showScreen('addresses');
}

/// Explorer link, copy icon and tap-to-verify on every row.
///
/// Shared by both address lists: the rows are identical markup, so the
/// behaviour should not be written twice.
function wireAddressRows(isMultisig) {
    // Stop the explorer link from also triggering the row.
    document.querySelectorAll('.addr-explore').forEach(link => {
        link.onclick = (e) => e.stopPropagation();
    });

    document.querySelectorAll('.addr-item').forEach(item => {
        const da = item.dataset.addr || '';
        const isChange = da.endsWith('-c');
        const idx = parseInt(da);

        const copyIcon = item.querySelector('.copy-icon');
        if (copyIcon) {
            copyIcon.onclick = (e) => {
                e.stopPropagation();
                const addr = item.querySelector('.addr-val').textContent.trim();
                navigator.clipboard.writeText(addr);
                copyIcon.textContent = '✓';
                setTimeout(() => { copyIcon.textContent = '⧉'; }, 800);
                toast('Address copied', 'ok', 1000);
            };
        }

        item.onclick = () => {
            const addr = item.querySelector('.addr-val').textContent.trim();
            showVerify(addr, idx, isChange, isMultisig);
        };
    });
}

function showVerify(addr, index, isChange, isMultisig) {
    // A multisig address sits under the 45' tree with a cosigner level, so the
    // 44' path shown for single-sig would be wrong - and this screen exists
    // precisely so the path can be checked against the device.
    const path = isMultisig && msBranch
        ? `m/45'/111111'/0'/${msBranch.cosigner}/${isChange ? 1 : 0}/${index}`
        : (isChange
            ? `m/44'/111111'/0'/1/${index}`
            : `m/44'/111111'/0'/0/${index}`);
    el('verify-path').textContent = path;
    el('verify-address').textContent = addr;

    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(addr)));
        el('verify-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('verify-qr').innerHTML = '';
    }

    // Explorer link
    const link = el('btn-verify-explore');
    if (link) {
        link.href = explorerUrl(addr);
    }
    showScreen('verify');
}

let consolidateSelection = new Set();

/// The loaded branch's funded addresses, in the shared UTXOs view.
///
/// Not selectable: consolidation builds a single-sig transaction from
/// `walletData`, which a multisig branch has no equivalent of. Shown for
/// reading, and the amounts come from the scan already done.
function showUtxosMultisig() {
    // Same rule: back to the caller, so opening this mid-transaction does not
    // discard the form.
    utxosReturnScreen = (currentScreenName && currentScreenName !== 'utxos')
        ? currentScreenName : 'ms-wallet';
    // Real OUTPOINTS, selectable, like the single-sig view.
    //
    // This listed per-address totals and was not selectable, so Consolidate had
    // nothing to act on. Each row is now one outpoint with its own tx id, which
    // is what an input needs.
    const list = (msBranch.utxos || []).slice().sort((a, b) => Number(b.amount) - Number(a.amount));
    const total = list.reduce((s, u) => s + Number(u.amount), 0);
    const key = u => u.tx_id + ':' + u.outpoint_index;
    msConsolidateSel = new Set();
    el('utxo-summary').textContent = list.length + ' UTXO'
        + (list.length !== 1 ? 's' : '') + ' · ' + (total / 1e8).toFixed(8) + ' KAS';
    el('utxo-list').innerHTML = list.length
        ? list.map(u => '<div class="utxo-item utxo-selectable" data-key="' + key(u) + '">'
            + '<div class="utxo-check">☐</div>'
            + '<div class="utxo-info">'
            + '<div class="utxo-amount">' + (Number(u.amount) / 1e8).toFixed(8) + ' KAS</div>'
            + '<div class="utxo-detail">C' + u.chain + ' #' + u.index + ' · '
            + u.tx_id.slice(0, 16) + '…:' + u.outpoint_index + '</div>'
            + '</div></div>').join('')
        : '<div style="text-align:center;color:var(--text-muted);padding:20px">No UTXOs found</div>';

    document.querySelectorAll('#utxo-list .utxo-selectable').forEach(item => {
        item.onclick = () => {
            const k = item.dataset.key;
            if (msConsolidateSel.has(k)) {
                msConsolidateSel.delete(k);
                item.querySelector('.utxo-check').textContent = '☐';
            } else if (msConsolidateSel.size < MS_PICK_MAX) {
                msConsolidateSel.add(k);
                item.querySelector('.utxo-check').textContent = '☑';
            } else {
                toast('Max ' + MS_PICK_MAX + ' inputs per transaction', 'info', 1500);
            }
            const sel = list.filter(u => msConsolidateSel.has(key(u)));
            const t = sel.reduce((a, u) => a + Number(u.amount), 0);
            const addrs = new Set(sel.map(u => u.address));
            el('utxo-summary').textContent = sel.length
                ? sel.length + ' selected · ' + (t / 1e8).toFixed(8) + ' KAS · '
                  + addrs.size + ' address(es)'
                  + (addrs.size > 1 ? ' — these will be linked on chain' : '')
                : list.length + ' UTXO' + (list.length !== 1 ? 's' : '')
                  + ' · ' + (total / 1e8).toFixed(8) + ' KAS';
        };
    });
    msConsolidateList = list;
    // Consolidation IS available now: the multi-address builder can merge
    // outputs from several addresses, which is the only way out of the change
    // fragmentation rotation creates.
    const b1 = el('btn-consolidate');
    if (b1) { b1.style.display = 'block'; b1.textContent = 'Consolidate…'; }
    const b2 = el('btn-consolidate-selected'); if (b2) b2.style.display = 'none';
    showScreen('utxos');
}

async function showUtxos() {
    // Same tab, both wallets - see the note on `showAddresses`. The multisig
    // scan already returns the funded set, so no second network call is needed.
    if (msActive && msBranch) { showUtxosMultisig(); return; }
    if (!walletData) return;
    utxosReturnScreen = 'dashboard';
    showLoading('Fetching UTXOs...');
    consolidateSelection = new Set();

    try {
        const utxosJson = await withNodeRetry(wsUrl => fetch_utxos(walletData, wsUrl));
        const utxos = JSON.parse(utxosJson);
        hideLoading();
        cachedUtxos = utxos;

        const totalSompi = utxos.reduce((s, u) => s + u.amount, 0);
        el('utxo-summary').textContent = `${utxos.length} UTXO${utxos.length !== 1 ? 's' : ''} · ${(totalSompi / 1e8).toFixed(8)} KAS`;

        if (utxos.length === 0) {
            el('utxo-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">No UTXOs found</div>';
            el('btn-consolidate').style.display = 'none';
            el('btn-consolidate-selected').style.display = 'none';
        } else {
            utxos.sort((a, b) => b.amount - a.amount);
            let html = '';
            utxos.forEach((u, i) => {
                const kas = (u.amount / 1e8).toFixed(8);
                html += `<div class="utxo-item utxo-selectable" data-utxo-idx="${i}">
                    <div class="utxo-check">${consolidateSelection.has(i) ? '☑' : '☐'}</div>
                    <div class="utxo-info">
                        <div class="utxo-amount">${kas} KAS</div>
                        <div class="utxo-detail">${u.tx_id.slice(0, 16)}…:${u.index}</div>
                    </div>
                </div>`;
            });
            el('utxo-list').innerHTML = html;

            // Tap to toggle selection
            document.querySelectorAll('.utxo-selectable').forEach(item => {
                item.onclick = () => {
                    const idx = parseInt(item.dataset.utxoIdx);
                    if (consolidateSelection.has(idx)) {
                        consolidateSelection.delete(idx);
                    } else if (consolidateSelection.size < 32) {
                        consolidateSelection.add(idx);
                    } else {
                        toast('Max 32 UTXOs per consolidation', 'info', 1500);
                        return;
                    }
                    // Update checkbox visual
                    const chk = item.querySelector('.utxo-check');
                    chk.textContent = consolidateSelection.has(idx) ? '☑' : '☐';
                    item.style.borderColor = consolidateSelection.has(idx) ? 'var(--teal)' : '';
                    updateConsolidateButtons(utxos.length);
                };
            });

            updateConsolidateButtons(utxos.length);
        }

        showScreen('utxos');
    } catch (e) {
        hideLoading();
        toast('Failed to fetch UTXOs: ' + e, 'error', 5000);
    }
}

function updateConsolidateButtons(totalCount) {
    const n = consolidateSelection.size;
    const btnAll = el('btn-consolidate');
    const btnSel = el('btn-consolidate-selected');
    if (totalCount <= 1) {
        btnAll.style.display = 'none';
        btnSel.style.display = 'none';
    } else if (n >= 2) {
        btnAll.style.display = 'none';
        btnSel.style.display = '';
        btnSel.textContent = `Consolidate ${n} Selected`;
    } else {
        btnAll.style.display = '';
        btnSel.style.display = 'none';
    }
}

async function handleConsolidate() {
    if (!walletData) return;
    // Builder (create_consolidate_pskb) takes up to 32 largest UTXOs; size
    // the fee to that same count. This 32 MUST match the take(N) in kspt.rs.
    const fee = consolidateFee(Math.min(32, (cachedUtxos && cachedUtxos.length) || 32));

    showLoading('Building consolidation TX...');
    try {
        const pskbHex = await withNodeRetry(wsUrl =>
            create_consolidate_pskb(walletWithFreshIndices(), BigInt(fee), wsUrl)
        );
        hideLoading();
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Consolidation failed: ' + e, 'error', 5000);
    }
}

async function handleConsolidateSelected() {
    if (!walletData || consolidateSelection.size < 2) return;
    const wallet = JSON.parse(walletData);
    const fee = consolidateFee(consolidateSelection.size);
    const indices = [...consolidateSelection].sort((a, b) => a - b);
    const indicesCsv = indices.join(',');

    // Calculate total of selected UTXOs
    let totalSelected = 0n;
    for (const idx of indices) {
        if (cachedUtxos && idx < cachedUtxos.length) {
            totalSelected += BigInt(cachedUtxos[idx].amount);
        }
    }
    const sendSompi = totalSelected - BigInt(fee);
    if (sendSompi <= 0n) {
        toast('Selected UTXOs too small to cover fee', 'error');
        return;
    }

    showLoading(`Consolidating ${indices.length} UTXOs...`);
    try {
        const destAddr = wallet.receive_addresses[getNextReceiveIndex()];
        const pskbHex = await withNodeRetry(wsUrl =>
            create_send_pskb_selected(walletWithFreshIndices(), destAddr, sendSompi, BigInt(fee), indicesCsv, wsUrl)
        );
        hideLoading();
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Consolidation failed: ' + e, 'error', 5000);
    }
}

// ─── Transaction history (UTXO diff tracking) ───

function trackUtxoChangesAndUsed(currentUtxos) {
    // Session-history persistence: entries built here live in page memory,
    // so a reload (e.g. picking up a new app.js) erased the user's own
    // broadcasts from History until the archival indexer caught up
    // (minutes+ of lag). localStorage is KasSee's sanctioned performance
    // cache: restore once per page load, persist after every update.
    if (!window.__histKey && walletData) {
        try {
            const w = JSON.parse(walletData);
            window.__histKey = 'kassee_hist_' + (w.receive_addresses && w.receive_addresses[0] || 'default');
            const stored = localStorage.getItem(window.__histKey);
            if (stored && historyEntries.length === 0) {
                const parsed = JSON.parse(stored);
                if (Array.isArray(parsed)) historyEntries = parsed;
            }
        } catch (_) {}
    }
    const now = Date.now();

    if (!utxoSnapshot) {
        // First snapshot — record all existing UTXOs as initial balance
        for (const u of currentUtxos) {
            // Skip UTXOs already present in restored history — synthesizing
            // them again would duplicate entries and stamp stale coins as
            // "just now".
            if (historyEntries.some(h => h.tx_id === u.tx_id && h.index === u.index)) continue;
            historyEntries.push({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
        if (historyEntries.length > 100) historyEntries.length = 100;
        utxoSnapshot = currentUtxos;
        persistSessionHistory();
        return;
    }

    const prevKeys = new Set(utxoSnapshot.map(u => u.tx_id + ':' + u.index));
    const currKeys = new Set(currentUtxos.map(u => u.tx_id + ':' + u.index));

    // New UTXOs = incoming
    for (const u of currentUtxos) {
        const key = u.tx_id + ':' + u.index;
        if (!prevKeys.has(key)) {
            historyEntries.unshift({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
    }

    // Gone UTXOs = spent (outgoing) — also mark the address as "used"
    if (walletData) {
        const wallet = JSON.parse(walletData);
        for (const u of utxoSnapshot) {
            const key = u.tx_id + ':' + u.index;
            if (!currKeys.has(key)) {
                historyEntries.unshift({
                    type: 'out',
                    amount: u.amount,
                    tx_id: u.tx_id,
                    index: u.index,
                    time: now,
                });
                // Match spent UTXO script to an address index
                const spkJson = JSON.stringify(u.script_public_key);
                for (let i = 0; i < wallet.receive_addresses.length; i++) {
                    try {
                        const decoded = JSON.parse(decode_address(wallet.receive_addresses[i]));
                        // P2PK script: [0x20, ...32 bytes..., 0xAC]
                        const spk = [0x20, ...Array.from(hex_to_bytes(decoded.payload)), 0xAC];
                        if (JSON.stringify(spk) === spkJson) { usedReceiveIndices.add(i); break; }
                    } catch (_) {}
                }
                for (let i = 0; i < wallet.change_addresses.length; i++) {
                    try {
                        const decoded = JSON.parse(decode_address(wallet.change_addresses[i]));
                        const spk = [0x20, ...Array.from(hex_to_bytes(decoded.payload)), 0xAC];
                        if (JSON.stringify(spk) === spkJson) { usedChangeIndices.add(i); break; }
                    } catch (_) {}
                }
            }
        }
    } else {
        for (const u of utxoSnapshot) {
            const key = u.tx_id + ':' + u.index;
            if (!currKeys.has(key)) {
                historyEntries.unshift({
                    type: 'out',
                    amount: u.amount,
                    tx_id: u.tx_id,
                    index: u.index,
                    time: now,
                });
            }
        }
    }

    if (historyEntries.length > 100) historyEntries.length = 100;
    utxoSnapshot = currentUtxos;
    persistSessionHistory();
}

// Persist the session history entries (capped) so page reloads keep the
// user's own broadcasts until the archival indexer catches up.
function persistSessionHistory() {
    if (!window.__histKey) return;
    try {
        localStorage.setItem(window.__histKey, JSON.stringify(historyEntries.slice(0, 100)));
    } catch (_) {}
}

function hex_to_bytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function showHistory() {
    // Same screen, both wallets: `renderHistory` reads a shared
    // `historyEntries` array, so only the sweep needed teaching.
    if (!walletData && !msBranch) return;
    showLoading('Loading transaction history...');
    fetchArchivalHistory().then(() => {
        hideLoading();
        renderHistory();
        showScreen('history');
    }).catch(e => {
        hideLoading();
        // Fall back to session-only history
        renderHistory();
        showScreen('history');
        console.log('[KasSee] archival history fetch failed, showing session data:', e);
    });
}

async function fetchArchivalHistory() {
    if (!walletData && !msBranch) return;
    // Cooldown: a full sweep hits api.kaspa.org once per address (~40
    // requests). Re-running it on every history open / broadcast tripped
    // the public rate limiter (429 floods). At most one sweep per 2 min;
    // between sweeps the session entries and the last sweep's results
    // render as-is.
    const nowMs = Date.now();
    // The cooldown must survive page reloads (a window var reset every
    // reload, so each reload re-swept and kept feeding the rate limiter).
    let lastSweep = 0, penaltyUntil = 0;
    try {
        lastSweep = parseInt(localStorage.getItem('kassee_last_sweep') || '0', 10) || 0;
        penaltyUntil = parseInt(localStorage.getItem('kassee_sweep_penalty') || '0', 10) || 0;
    } catch (_) {}
    if (nowMs < penaltyUntil) return;      // rate-limited recently: stay away 10 min
    if (nowMs - lastSweep < 120000) return;
    // Addresses from EITHER wallet. Everything below - the cooldown, the
    // penalty window, the chunked sweep and the retry rounds - is
    // scheme-agnostic and shared; only the source of the two lists differs.
    //
    // A multisig branch has no `walletData`: its addresses are derived from the
    // descriptor, so they are built here rather than read from a blob.
    let allAddresses, rcvAll, chgAll, rcvLive, chgLive;
    // Chosen by CONTEXT, not by walletData being absent: with both wallets
    // loaded, `!walletData` is false and the multisig branch would be skipped.
    if (msActive && msBranch) {
        rcvAll = []; chgAll = []; rcvLive = []; chgLive = [];
        for (let chain = 0; chain < 2; chain++) {
            const used = chain === 1 ? msBranch.usedChange : msBranch.usedReceive;
            const fundedSet = new Set((msBranch.funded || [])
                .filter(f => f.chain === chain).map(f => f.index));
            for (let i = 0; i < 40; i++) {
                let a;
                try { a = multisig_address_at_js(msBranch.descriptor, i, msBranch.cosigner, chain); }
                catch (_) { break; }
                (chain === 1 ? chgAll : rcvAll).push(a);
                if (fundedSet.has(i) || (used && used.has(i))) {
                    (chain === 1 ? chgLive : rcvLive).push(a);
                }
            }
        }
        allAddresses = [...rcvAll, ...chgAll];
    } else {
        const wallet = JSON.parse(walletData);
        rcvAll = wallet.receive_addresses;
        chgAll = wallet.change_addresses;
        allAddresses = [...rcvAll, ...chgAll];
        rcvLive = rcvAll.filter((_, i) =>
            fundedReceiveIndices.includes(i) || usedReceiveIndices.has(i));
        chgLive = chgAll.filter((_, i) =>
            fundedChangeIndices.includes(i) || usedChangeIndices.has(i));
    }
    // Every derived address, for CLASSIFYING a transaction as ours.
    const myAddressSet = new Set(allAddresses);

    // But only FETCH addresses that can have transactions: currently funded, or
    // known used from the transactions-count scan. An address with neither has
    // no history by definition, so querying it is guaranteed waste.
    //
    // This matters more since the gap step grew to 20: the list went from ~40
    // addresses to 100+, and at 400 ms spacing that is 40 s of requests before
    // anything renders. Sweeping only the live ones is typically a quarter of
    // that, and the result is identical.
    let sweepAddresses = [...rcvLive, ...chgLive];
    // Fallback for a freshly loaded wallet: the used/funded sets are populated
    // by a balance refresh and the transactions-count scan, so on the very
    // first open they can both be empty. Sweeping nothing would show an empty
    // history on a wallet that has plenty. Take a bounded prefix instead.
    if (sweepAddresses.length === 0) {
        sweepAddresses = [...rcvAll.slice(0, 20), ...chgAll.slice(0, 20)];
    }

    const apiBase = KASPA_REST_API[network];
    if (!apiBase) return;

    const txMap = new Map(); // tx_id → processed entry

    // Fetch full-transactions per address SEQUENTIALLY with spacing.
    // The parallel map fired 40 simultaneous requests at api.kaspa.org,
    // which rate-limits (429) — and the 429 responses carry no CORS
    // headers, flooding the console with paired CORS+429 errors. One
    // in-flight request with a small gap stays under the limit; on a
    // 429 we back off once and retry, then give up quietly for that
    // address (session history still renders).
    const fetchOne = async (addr, attempt) => {
        try {
            const r = await fetch(
                `${apiBase}/addresses/${addr}/full-transactions?resolve_previous_outpoints=light`,
                { signal: AbortSignal.timeout(10000) }
            );
            // No retry on 429: retrying against an active penalty just
            // doubles the hits and refreshes the ban.
            if (r.status === 429) return 'rate-limited';
            if (!r.ok) return;
            const txs = await r.json();
            if (!Array.isArray(txs)) return;

            for (const tx of txs) {
                if (txMap.has(tx.transaction_id)) continue;

                // Classify: sum inputs from our addresses vs outputs to our addresses
                let inputFromUs = 0;
                let inputTotal = 0;
                const senders = [];
                for (const inp of (tx.inputs || [])) {
                    const amt = inp.previous_outpoint_amount || 0;
                    inputTotal += amt;
                    if (inp.previous_outpoint_address && myAddressSet.has(inp.previous_outpoint_address)) {
                        inputFromUs += amt;
                    } else if (inp.previous_outpoint_address) {
                        senders.push(inp.previous_outpoint_address);
                    }
                }

                let outputToUs = 0;
                let outputTotal = 0;
                const recipients = [];
                for (const out of (tx.outputs || [])) {
                    const amt = out.amount || 0;
                    outputTotal += amt;
                    if (out.script_public_key_address && myAddressSet.has(out.script_public_key_address)) {
                        outputToUs += amt;
                    } else if (out.script_public_key_address) {
                        recipients.push(out.script_public_key_address);
                    }
                }

                const fee = inputTotal > 0 ? inputTotal - outputTotal : 0;

                // Direction: if we funded inputs, it's outgoing; otherwise incoming
                let type, amount, counterparty;
                if (inputFromUs > 0) {
                    // We spent — outgoing. Amount = what left our wallet (excluding change back to us)
                    amount = inputFromUs - outputToUs;
                    type = 'out';
                    counterparty = recipients.length > 0 ? recipients[0] : null;
                } else {
                    // We received
                    amount = outputToUs;
                    type = 'in';
                    counterparty = senders.length > 0 ? senders[0] : null;
                }

                txMap.set(tx.transaction_id, {
                    type,
                    amount,
                    fee,
                    tx_id: tx.transaction_id,
                    time: tx.block_time || tx.accepting_block_time || 0,
                    counterparty,
                    is_accepted: tx.is_accepted !== false,
                });
            }
        } catch (_) {}
    };

    let consecutive429 = 0;
    // Small concurrency window, not one at a time.
    //
    // Strictly serial made per-request LATENCY additive: ~26 addresses at 400 ms
    // spacing plus ~1 s each is 40 s before anything renders. Three in flight
    // overlaps the waiting while staying nowhere near the ~80 simultaneous
    // requests that caused the 429 floods in the first place.
    //
    // The circuit breaker still governs: a chunk containing any 429 counts, and
    // two in a row stops the sweep and persists the penalty window.
    const CHUNK = 3;
    const CHUNK_GAP_MS = 250;
    for (let i = 0; i < sweepAddresses.length; i += CHUNK) {
        const slice = sweepAddresses.slice(i, i + CHUNK);
        const outcomes = await Promise.all(slice.map(a => fetchOne(a, 0)));
        if (outcomes.includes('rate-limited')) {
            consecutive429++;
            // Circuit breaker: the limiter is refusing us — back off hard.
            // Persist a 10-minute penalty window so reloads don't keep
            // poking the limiter and refreshing the ban.
            if (consecutive429 >= 2) {
                try { localStorage.setItem('kassee_sweep_penalty', String(Date.now() + 600000)); } catch (_) {}
                console.log('[KasSee] archival sweep paused 10 min: rate-limited (' + txMap.size + ' txs so far)');
                break;
            }
        } else {
            consecutive429 = 0;
        }
        await new Promise(res => setTimeout(res, CHUNK_GAP_MS));
    }
    try { localStorage.setItem('kassee_last_sweep', String(Date.now())); } catch (_) {}

    // Merge archival data into historyEntries, replacing session-only entries
    if (txMap.size > 0) {
        // Keep session entries that aren't in archival (very recent, not yet indexed)
        const archivalIds = new Set(txMap.keys());
        const sessionOnly = historyEntries.filter(h => !archivalIds.has(h.tx_id));

        // Build merged list: archival (sorted by time desc) + session-only at top
        const archival = [...txMap.values()].sort((a, b) => b.time - a.time);
        historyEntries = [...sessionOnly, ...archival];

        // Cap at 200
        if (historyEntries.length > 200) historyEntries.length = 200;
        persistSessionHistory();
    }
}

function renderHistory() {
    if (historyEntries.length === 0) {
        el('history-summary').textContent = 'No transactions found';
        el('history-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">No transaction history available</div>';
        return;
    }

    el('history-summary').textContent = historyEntries.length + ' transaction' + (historyEntries.length !== 1 ? 's' : '');
    let html = '';
    // Render newest-first by date. Session entries pushed live land at the
    // array end, so sort a view: unknown/zero time = just broadcast = top.
    const sortedEntries = [...historyEntries].sort((a, b) => {
        const ta = (a.time && a.time > 0) ? a.time : Number.MAX_SAFE_INTEGER;
        const tb = (b.time && b.time > 0) ? b.time : Number.MAX_SAFE_INTEGER;
        return tb - ta;
    });
    sortedEntries.forEach(h => {
        const kas = (Math.abs(h.amount) / 1e8).toFixed(8);
        const sign = h.type === 'in' ? '+' : '-';
        const cls = h.type === 'in' ? 'incoming' : 'outgoing';
        const icon = h.type === 'in' ? '↓' : '↑';
        const timeStr = h.time > 1e12 ? formatTxTime(h.time) : (h.time > 0 ? timeAgo(h.time) : '');
        const txShort = h.tx_id ? h.tx_id.slice(0, 12) + '…' : '';
        const txLink = h.tx_id ? explorerTxUrl(h.tx_id) : '';
        const cpShort = h.counterparty ? h.counterparty.slice(0, 16) + '…' : '';

        html += `<div class="history-item">
            <div class="history-icon ${cls}">${icon}</div>
            <div class="history-info">
                <div class="history-amount ${cls}">${sign}${kas} KAS</div>
                <div class="history-time">${timeStr}${txLink ? ` · <a href="${txLink}" target="_blank" rel="noopener" style="color:var(--teal-dim)">${txShort}</a>` : ` · ${txShort}`}</div>
                ${cpShort ? `<div class="history-time">${h.type === 'in' ? 'from' : 'to'} ${cpShort}</div>` : ''}
            </div>
        </div>`;
    });
    el('history-list').innerHTML = html;
}

function explorerTxUrl(txId) {
    const prefix = (network === 'mainnet') ? '' : 'tn10.';
    return `https://${prefix}explorer.kaspa.org/txs/${txId}`;
}

function clearHistory() {
    if (!confirm('Clear transaction history?')) return;
    historyEntries = [];
    utxoSnapshot = null;
    fundedReceiveIndices = [];
    fundedChangeIndices = [];
    usedReceiveIndices = new Set();
    usedChangeIndices = new Set();
    renderHistory();
}

function formatTxTime(blockTimeMs) {
    const d = new Date(blockTimeMs);
    const now = Date.now();
    const diffMs = now - blockTimeMs;

    if (diffMs < 60000) return 'just now';
    if (diffMs < 3600000) return Math.floor(diffMs / 60000) + 'm ago';
    if (diffMs < 86400000) return Math.floor(diffMs / 3600000) + 'h ago';
    if (diffMs < 604800000) return Math.floor(diffMs / 86400000) + 'd ago';

    // Older than a week: show date
    const month = d.toLocaleString('en', { month: 'short' });
    const day = d.getDate();
    const year = d.getFullYear();
    const hr = d.getHours().toString().padStart(2, '0');
    const mn = d.getMinutes().toString().padStart(2, '0');
    return `${month} ${day}, ${year} ${hr}:${mn}`;
}

function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.floor(hrs / 24);
    return days + 'd ago';
}

// ─── KRC20 Tokens + KRC721 NFTs ───

async function showTokens() {
    if (!walletData) { toast('Import kpub first', 'info'); return; }

    showLoading('Fetching tokens & NFTs...');
    const wallet = JSON.parse(walletData);
    const allAddresses = [...wallet.receive_addresses, ...wallet.change_addresses];

    const tokenMap = {}; // tick → { balance, decimals }
    const nftList = []; // { tick, tokenId, image, name }

    // ─── KRC20 ───
    const krc20Base = KASPLEX_API[network];
    if (krc20Base) {
        for (const addr of allAddresses) {
            try {
                const resp = await fetch(`${krc20Base}/krc20/address/${addr}/tokenlist`, { signal: AbortSignal.timeout(8000) });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.result && Array.isArray(data.result)) {
                        for (const t of data.result) {
                            const tick = t.tick || t.ticker || '';
                            const bal = parseInt(t.balance || '0');
                            const dec = parseInt(t.dec || '8');
                            if (tick && bal > 0) {
                                if (!tokenMap[tick]) tokenMap[tick] = { balance: 0, decimals: dec };
                                tokenMap[tick].balance += bal;
                            }
                        }
                    }
                }
            } catch (e) { /* skip */ }
        }
    }

    // ─── KRC721 ───
    const krc721Base = KRC721_API[network];
    if (krc721Base) {
        const collectionBuri = {}; // tick → buri cache

        for (const addr of allAddresses) {
            try {
                const resp = await fetch(`${krc721Base}/address/${addr}`, { signal: AbortSignal.timeout(8000) });
                if (resp.ok) {
                    const data = await resp.json();
                    const items = data.result || [];
                    if (Array.isArray(items)) {
                        for (const nft of items) {
                            const tick = nft.tick || '';
                            const tokenId = nft.tokenId || nft.token_id || '';
                            if (!tick || !tokenId) continue;

                            // Fetch collection buri if not cached
                            if (!(tick in collectionBuri)) {
                                try {
                                    const cResp = await fetch(`${krc721Base}/nfts/${tick}`, { signal: AbortSignal.timeout(8000) });
                                    if (cResp.ok) {
                                        const cData = await cResp.json();
                                        collectionBuri[tick] = (cData.result && cData.result.buri) || '';
                                    } else {
                                        collectionBuri[tick] = '';
                                    }
                                } catch (e) { collectionBuri[tick] = ''; }
                            }

                            // Build metadata path from buri/tokenId.json
                            let image = '';
                            if (collectionBuri[tick]) {
                                image = collectionBuri[tick] + '/' + tokenId + '.json';
                            }

                            nftList.push({ tick, tokenId, image, name: tick + ' #' + tokenId });
                        }
                    }
                }
            } catch (e) { /* skip */ }
        }
    }

    // ─── KNS domains (reverse lookup from known table) ───
    const knsDomains = [];
    const addrSet = new Set(allAddresses);
    for (const [domain, addr] of Object.entries(KNS_LOOKUP)) {
        if (addrSet.has(addr)) knsDomains.push(domain);
    }

    hideLoading();

    // ─── Render ───
    const ticks = Object.keys(tokenMap).sort();
    const totalItems = ticks.length + nftList.length + knsDomains.length;

    if (totalItems === 0) {
        el('tokens-summary').textContent = 'No tokens, NFTs, or domains found';
        el('tokens-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">Your addresses have no KRC-20 tokens, KRC-721 NFTs, or KNS domains</div>';
        showScreen('tokens');
        return;
    }

    let html = '';

    // KRC20 section
    if (ticks.length > 0) {
        html += '<div class="tokens-section-label">KRC-20 Tokens</div>';
        for (const tick of ticks) {
            const t = tokenMap[tick];
            const display = (t.balance / Math.pow(10, t.decimals)).toFixed(t.decimals);
            html += `<div class="token-item">
                <div class="token-tick">${tick}</div>
                <div class="token-balance">${display}</div>
            </div>`;
        }
    }

    // KRC721 section
    if (nftList.length > 0) {
        html += '<div class="tokens-section-label" style="margin-top:12px">KRC-721 NFTs</div>';
        for (let i = 0; i < nftList.length; i++) {
            const nft = nftList[i];
            html += `<div class="token-item">
                <div class="token-tick">${nft.tick}</div>
                <div class="token-balance">#${nft.tokenId}</div>
            </div>`;
        }
    }

    // KNS domains
    if (knsDomains.length > 0) {
        html += '<div class="tokens-section-label" style="margin-top:12px">KNS Domains</div>';
        for (const d of knsDomains) {
            html += `<div class="token-item">
                <div class="token-tick">${d}</div>
            </div>`;
        }
    }

    const parts = [];
    if (ticks.length > 0) parts.push(ticks.length + ' token' + (ticks.length !== 1 ? 's' : ''));
    if (nftList.length > 0) parts.push(nftList.length + ' NFT' + (nftList.length !== 1 ? 's' : ''));
    if (knsDomains.length > 0) parts.push(knsDomains.length + ' domain' + (knsDomains.length !== 1 ? 's' : ''));
    el('tokens-summary').textContent = parts.join(', ') + ' found';
    el('tokens-list').innerHTML = html;
    showScreen('tokens');
}

// ─── Donation / support screen ───

function handleLogoTap() {
    if (walletData) {
        // Wallet loaded — open send screen prefilled with donation address
        openSendScreen().then(() => {
            el('input-dest').value = DONATE_ADDRESS;
            el('input-amount').value = '';
            el('input-amount').focus();
        });
    } else {
        // No wallet — show donation QR for copying
        showDonateScreen();
    }
}

function showDonateScreen() {
    el('donate-address').textContent = DONATE_ADDRESS;
    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(DONATE_ADDRESS)));
        el('donate-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('donate-qr').innerHTML = '';
    }
    showScreen('donate');
}

// ─── Node settings ───

function showSettings() {
    el('input-node-url').value = customNodeUrl || '';
    el('select-network').value = network;
    el('chk-addr-history').checked = addressHistoryEnabled;
    el('input-rest-url').value = customRestUrl || '';
    el('chk-stealth-indexer').checked = stealthIndexerEnabled;
    showScreen('settings');
}

function saveSettings() {
    const url = el('input-node-url').value.trim();
    if (url) {
        customNodeUrl = url;
    } else {
        clearCustomNode();
    }

    // Address history toggle + custom REST URL
    const histWas = addressHistoryEnabled;
    addressHistoryEnabled = el('chk-addr-history').checked;
    const restUrl = el('input-rest-url').value.trim();
    customRestUrl = restUrl || null;
    if (addressHistoryEnabled && !customRestUrl) {
        addressHistoryEnabled = false;
        el('chk-addr-history').checked = false;
        toast('Address history requires a REST URL', 'info', 2500);
    } else if (addressHistoryEnabled && !histWas) {
        fetchAddressHistory();
    }
    if (!addressHistoryEnabled) {
        // Keep session-tracked used indices, only clear API-sourced ones
        // (session tracking via UTXO diffs is always active)
    }

    // Stealth indexer toggle: pull R's from the keeper vs the in-browser lane scan.
    stealthIndexerEnabled = el('chk-stealth-indexer').checked;
    localStorage.setItem('kassee-stealth-indexer', stealthIndexerEnabled ? '1' : '0');

    const newNetwork = el('select-network').value;
    if (newNetwork !== network) {
        network = newNetwork;
        walletData = null;
        lastFeeEstimate = null;
        selectedUtxoIndices = null;
        cachedUtxos = null;
        historyEntries = [];
        utxoSnapshot = null;
        fundedReceiveIndices = [];
        fundedChangeIndices = [];
        usedReceiveIndices = new Set();
        usedChangeIndices = new Set();
        el('balance-kas').textContent = '—';
        el('balance-sompi').textContent = '';
        el('balance-info').textContent = '';
        el('input-kpub').value = '';
        setStatus('offline', 'Offline');
        toast('Network changed — import your kpub again', 'info', 3000);
        showScreen('welcome');
        return;
    }
    exitSettings();
}

function clearCustomNode() {
    customNodeUrl = null;
    console.log('[KasSee] Using public nodes');
}

let settingsReturnScreen = 'dashboard';

function exitSettings() {
    const target = settingsReturnScreen || (walletData ? 'dashboard' : 'welcome');
    // After broadcast, always go to dashboard (not back to send with stale state)
    if (target === 'send' || target === 'qr-display' || target === 'pskt-review') {
        // ...unless a multisig branch is loaded, where 'dashboard' means leaving
        // the wallet entirely. Same fallthrough as the four back buttons.
        if (msActive && msBranch) { showScreen('ms-wallet'); return; }
        showScreen('dashboard');
        if (walletData) refreshBalance();
    } else {
        showScreen(target);
        if (target === 'dashboard' && walletData) refreshBalance();
    }
}

// ─── Wallet reset ───

function resetWallet() {
    if (!confirm('Reset wallet? You will need to re-import your kpub.')) return;
    walletData = null;
    adaptorStateClear();
    // Preserve customNodeUrl — user's personal node config survives reset
    // Keep network setting — don't reset to mainnet
    lastFeeEstimate = null;
    selectedUtxoIndices = null;
    cachedUtxos = null;
    historyEntries = [];
    utxoSnapshot = null;
    fundedReceiveIndices = [];
    fundedChangeIndices = [];
    usedReceiveIndices = new Set();
    usedChangeIndices = new Set();
    el('balance-kas').textContent = '—';
    el('balance-sompi').textContent = '';
    el('balance-info').textContent = '';
    el('input-kpub').value = '';
    showScreen('welcome');
    setStatus('offline', 'Offline');
}

// ─── Boot ───

start().catch(e => console.error('KasSee init failed:', e));

// ── RISC0 ZK-bridge withdrawal (KIP-21) ──
let risc0BridgeTestData = null;
let groth16BridgeTestData = null;


// ── KIP-21 ZK Bridge (Groth16 wrap, roadmap Step 1) ───────────────────────────
// Groth16-wrap withdrawal. The vk / public inputs / proof are committed in the
// redeem, so the withdrawal supplies only the owner signature. The proof is tiny
// so multi-input consolidation is allowed (unlike the 222 KB RISC0 seal path).



// Step 4.2: append the current (address, redeem) as one deposit entry to the
// consolidation batch. Repeat per deposit (gen address -> Add to batch), then
// Multi-withdraw sweeps live UTXOs across all of them in one tx.


// ════════════════════════════════════════════════════════════════════════════
// ORACLE (Model B) — DISCOVERY ORACLE GLUE  [appended block]
//
// Added for the co-roll discovery oracle. Requires the rebuilt WASM (kassee/:
//   RUSTUP_TOOLCHAIN=stable ./build.sh). New/changed wasm signatures:
//   covenant_oracle_mb(genesisPrice, genesisT, imageIdHex, controlIdHex,
//       setRootHex, hashfnHex, heartbeatCovIdHex, network)   // +heartbeatCovIdHex
//   covenant_oracle_mb_heartbeat(network)                    // -max_fee
//   create_oracle_mb_publish(walletJson, oracleAddress, redeemHex, covenantIdHex,
//       heartbeatCovIdHex, imageIdHex, controlIdHex, setRootHex, hashfnHex,
//       sealHex, claimHex, controlIndexHex, controlDigestsHex, journalHex,
//       fee, changeAddress, network, wsUrl)                  // +heartbeatCovIdHex
//
// create_oracle_mb_heartbeat_roll(...) is OBSOLETE — do NOT call it. The
// heartbeat co-rolls with the oracle on every publish; a standalone roll sends
// out < in, which the new heartbeat body (out >= in) makes the node reject.
//
// VERIFY-ON-TN10: the UTXO JSON field names (utxoCovId/utxoTxid) and the REST tx
// shape are guessed with fallbacks. Adjust if your api-tn10 responses differ.
// ════════════════════════════════════════════════════════════════════════════

const ORACLE_MB = {
  // Prover/circuit pins (unchanged across a re-genesis unless you re-pin them).
  imageIdHex:   "0f3756c052ff1749fbbe0d4b28010a42c989e227130752e7188047498ba124aa",
  controlIdHex: "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e",
  setRootHex:   "dcbe0edd8a2b405aabdead896b04ae82cd9a881df095fee9805fd5584068a9b8", // set-7 (rotated 2026-06-30), verified vs Wormhole core getGuardianSet(7)
  hashfnHex:    "01",                       // poseidon2
  network:      "mainnet",                   // <-- the network string KasSee passes to the wasm
  restBase:     "https://api.kaspa.org",
  proverBase:   "https://keeper.kassigner.org", // PUBLIC prover (Caddy -> 127.0.0.1:8799), CORS-open. Domain proxies the VPS so the IP can rotate without a code change.
  // Service fee, paid per roll to the operator's prover (see /quote). v1 fixed address; rotate later.
  feeAddress:   "kaspa:qq5zdr7cwuyrqu0zmr03v3qx0tnf6psmangl4f9aecp8a4xkjmz0x5e2ejesy",
  feeSpk:       "00002028268fd877083071e2d8df1644067ae69d061becd1faa4bdce027ed4d696c4f3ac", // version-0 P2PK SPK of feeAddress
  feeSompi:     30000000n, // 0.3 KAS
  // Filled by genesis (pin after funding):
  heartbeatAddress: null, heartbeatCovIdH: null,
  oracleAddress: null,   oracleCovIdG: null,
};

function utxoCovId(u) { return (u.covenant_id ?? u.covenantId ?? u.covenant ?? null); }
function utxoTxid(u)  { return (u.tx_id ?? u.transactionId ?? u.outpoint?.transactionId ?? u.previousOutpoint?.transactionId ?? null); }
function oracleMbLeU64(h16) { let v = 0n; for (let i = 0; i < 8; i++) v |= BigInt(parseInt(h16.slice(i*2, i*2+2), 16)) << BigInt(8*i); return v; }

// ── GENESIS (order forced: heartbeat first so H exists before the oracle body) ──

// 1) FIXED heartbeat address. Fund tx_version=1 to bind covenant_id H.
function oracleMbHeartbeatAddress() {
  const j = JSON.parse(covenant_oracle_mb_heartbeat(ORACLE_MB.network));
  ORACLE_MB.heartbeatAddress = j.address;
  console.log("[oracle-mb] heartbeat address (fund tx_version=1):", j.address);
  return j;
}

// 2) After funding, read H from the heartbeat UTXO's covenant_id.
async function oracleMbReadH() {
  const wsUrl = await resolveNodeUrl();
  const utxos = JSON.parse(await fetch_utxos_for_address_js(ORACLE_MB.heartbeatAddress, wsUrl));
  if (!utxos.length) throw new Error("no heartbeat UTXO yet — fund the heartbeat address (tx_version=1)");
  const H = utxoCovId(utxos[0]);
  if (!H) throw new Error("heartbeat UTXO has no covenant_id — funded with tx_version=1?");
  ORACLE_MB.heartbeatCovIdH = H;
  console.log("[oracle-mb] heartbeat covenant_id H:", H);
  return H;
}

// 3) With H, derive the oracle genesis address. genesisT=0 to bootstrap. Fund tx_version=1.
function oracleMbOracleAddress(genesisPrice, genesisT) {
  if (!ORACLE_MB.heartbeatCovIdH) throw new Error("read H first (oracleMbReadH)");
  const j = JSON.parse(covenant_oracle_mb(
    BigInt(genesisPrice), BigInt(genesisT),
    ORACLE_MB.imageIdHex, ORACLE_MB.controlIdHex, ORACLE_MB.setRootHex, ORACLE_MB.hashfnHex,
    ORACLE_MB.heartbeatCovIdH, ORACLE_MB.network,
  ));
  ORACLE_MB.oracleAddress = j.address;
  console.log("[oracle-mb] oracle genesis address (fund tx_version=1):", j.address, "redeem_len", j.redeem_len);
  return j;
}

// 4) After funding, read G from the oracle UTXO's covenant_id.
async function oracleMbReadG() {
  const wsUrl = await resolveNodeUrl();
  const utxos = JSON.parse(await fetch_utxos_for_address_js(ORACLE_MB.oracleAddress, wsUrl));
  if (!utxos.length) throw new Error("no oracle UTXO yet — fund the oracle address (tx_version=1)");
  const G = utxoCovId(utxos[0]);
  if (!G) throw new Error("oracle UTXO has no covenant_id — funded with tx_version=1?");
  ORACLE_MB.oracleCovIdG = G;
  console.log("[oracle-mb] oracle covenant_id G:", G);
  return G;
}

// ── PUBLISH (co-roll). Proof fields come from a RISC0 prover run on the new Pyth
// price; journal = price[0:8] | T[8:16] | set_root[16:48], little-endian. The
// builder fetches the heartbeat UTXO (by H) and co-rolls it; you pass only H.
// oracleRedeemHex is the oracle's CURRENT redeem (read it from the live UTXO). ──
async function oracleMbPublish({ walletJson, oracleAddress, oracleRedeemHex, covenantIdG,
                                 seal, claim, controlIndex, controlDigests, journal,
                                 fee, changeAddress, omitHeartbeat = false }) {
  const wsUrl = await resolveNodeUrl();
  return await create_oracle_mb_publish(
    walletJson, oracleAddress, oracleRedeemHex,
    covenantIdG,
    ORACLE_MB.heartbeatCovIdH,                 // NEW arg
    ORACLE_MB.imageIdHex, ORACLE_MB.controlIdHex, ORACLE_MB.setRootHex, ORACLE_MB.hashfnHex,
    seal, claim, controlIndex, controlDigests, journal,
    BigInt(fee), changeAddress, ORACLE_MB.network, wsUrl,
    !!omitHeartbeat,                           // NEGATIVE-TEST flag (default false)
  );
}

// ── DISCOVERY READ (no indexer). Heartbeat fixed address -> latest roll txid ->
// REST tx -> price/T from the 48-byte journal in the oracle input's sig_script
// tail -> tie it live by recomputing the oracle address for (price,T) and
// matching the roll's output[0]. ──
async function oracleMbDiscoverAndRead() {
  if (!ORACLE_MB.heartbeatAddress) throw new Error("set ORACLE_MB.heartbeatAddress (genesis) first");
  const wsUrl = await resolveNodeUrl();

  const hbUtxos = JSON.parse(await fetch_utxos_for_address_js(ORACLE_MB.heartbeatAddress, wsUrl));
  if (!hbUtxos.length) throw new Error("no heartbeat UTXO at the fixed address");
  const rollTxid = utxoTxid(hbUtxos[0]);
  if (!rollTxid) throw new Error("could not read the heartbeat UTXO's txid");

  const tx = await fetch(`${ORACLE_MB.restBase}/transactions/${rollTxid}?inputs=true&outputs=true&resolve_previous_outpoints=light`)
    .then(r => { if (!r.ok) throw new Error("roll tx fetch failed: " + r.status); return r.json(); });
  const inputs = tx.inputs || tx.transaction?.inputs || [];
  const outputs = tx.outputs || tx.transaction?.outputs || [];
  if (!inputs.length || !outputs.length) throw new Error("roll tx missing inputs/outputs in the response");

  const sigOf = (i) => (i.signatureScript || i.signature_script || "");
  const oracleInput = inputs.reduce((a, b) => (sigOf(b).length > sigOf(a).length ? b : a));
  const sig = (sigOf(oracleInput) || "").toLowerCase();
  if (!sig) throw new Error("oracle input has no signatureScript in the response");
  // Robust: the ZK journal is a 48-byte push  30 | price(8 LE) | T(8 LE) | set_root(32).
  // Locate it by its set_root suffix, disambiguating from the set_root pinned inside the
  // revealed redeem (that one is a 20-prefixed OP_DATA_32 push, not 30 | price | T | set_root).
  // This is independent of the branch-selector and redeem-push opcodes in the tail.
  const SR = (ORACLE_MB.setRootHex || "").toLowerCase();
  if (SR.length !== 64) throw new Error("ORACLE_MB.setRootHex not set / not 32 bytes");
  let _from = 0, _jStart = -1;
  for (;;) {
    const s = sig.indexOf(SR, _from);
    if (s < 0) break;
    if (s >= 34 && sig.slice(s - 34, s - 32) === "30") { _jStart = s - 32; break; }
    _from = s + 2;
  }
  if (_jStart < 0) throw new Error("ZK journal (30|price|T|set_root) not found in oracle sig_script");
  const price = oracleMbLeU64(sig.slice(_jStart, _jStart + 16));
  const t     = oracleMbLeU64(sig.slice(_jStart + 16, _jStart + 32));

  const expected = JSON.parse(covenant_oracle_mb(
    BigInt(price), BigInt(t),
    ORACLE_MB.imageIdHex, ORACLE_MB.controlIdHex, ORACLE_MB.setRootHex, ORACLE_MB.hashfnHex,
    ORACLE_MB.heartbeatCovIdH, ORACLE_MB.network,
  ));
  const out0 = outputs[0];
  const out0spk = (out0.scriptPublicKey?.scriptPublicKey ?? out0.scriptPublicKey ?? out0.script_public_key ?? "");
  if (!out0spk) throw new Error("roll output[0] has no scriptPublicKey in the response");
  // Hard tie (recommended): confirm output[0] belongs to expected.address using
  // your SPK<->address helper. Loose check below logs a mismatch for inspection.
  console.log("[oracle-mb] discovery read:", {
    rollTxid, price: price.toString(), t: t.toString(), expectedOracleAddress: expected.address,
  });
  return { price, t, rollTxid, expectedOracleAddress: expected.address };
}

// ════════════════════════════ ORACLE (Model B) — KasSee CARD ════════════════════════════
// Ambient price+age read for the deployed TN10 oracle, plus the ask-for-new hook.
// Pure JS, no WASM rebuild: reuses oracleMbDiscoverAndRead (full read) plus a cheap
// heartbeat-UTXO poll (a txid-change detector), so the ~445KB roll tx is fetched ONLY
// when a new roll lands. Age ticks locally from (now - T). The oracle ADDRESS rotates on
// every forward-roll, so only the FIXED identity (heartbeat addr, H, G) is baked here;
// the live address is always rediscovered.

// Deployed MAINNET identity (fixed parts; the circuit pins already live in ORACLE_MB).
const ORACLE_MB_DEPLOY = {
  heartbeatAddress: "kaspa:ppw345sh6hm20wq9x0x9hcjjqgymq92z4z63h5d0c8cyw0mlk0s3w4sq274cq",
  heartbeatCovIdH:  "901be291efb290173ae8c021842fad986e73b878bff72d3405821b7ed0136270",
  oracleCovIdG:     "09ef275e1671c76086764b6030ea5229dbd9af0ba818db6e0aae64eb8a3f63cb", // mainnet set-7 oracle genesis (2026-06-30)
};

let _oracleMbState = null;     // { price:BigInt, t:BigInt, rollTxid, addr }
let _oracleMbFeeTotalKas = 1;  // total fee (KAS) the user picked for the next roll; miner + 0.3 service. Min 1.
let _oracleMbAgeTimer = null;  // 1s local age tick
let _oracleMbPollTimer = null; // ~12s heartbeat-txid poll (local; REST only on a watcher miss)
let _oracleMbBlockWs = null;   // BlockAdded subscription: live price/T from the block stream
let _oracleMbPriceTs = 0;      // ms timestamp of the last price/T update (watcher or REST)

function oracleMbFmtPrice(mantissa) {
  // price is USD * 1e8 (Pyth mantissa at expo -8). Render as $0.xxxxxxxx.
  const n = Number(mantissa) / 1e8;
  if (!isFinite(n)) return "—";
  return "$" + n.toFixed(8);
}
function oracleMbFmtAge(tSec) {
  let s = Math.floor(Date.now() / 1000) - Number(tSec);
  if (s < 0) s = 0;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const txt = h > 0 ? (h + "h " + m + "m ago") : (m > 0 ? (m + "m " + sec + "s ago") : (sec + "s ago"));
  // The ZK proof window is ~20-40 min; flag stale beyond ~20 min.
  return { txt: "updated " + txt, stale: s > 1200 };
}
function oracleMbShort(s) { return (!s ? "—" : (s.length > 22 ? (s.slice(0, 14) + "…" + s.slice(-6)) : s)); }

function oracleMbRenderAge() {
  const ageEl = el('oracle-mb-age');
  if (!ageEl || !_oracleMbState) return;
  const a = oracleMbFmtAge(_oracleMbState.t);
  ageEl.textContent = a.txt;
  ageEl.style.color = a.stale ? '#ffd600' : 'var(--teal)';
}
function oracleMbRenderState() {
  if (!_oracleMbState) return;
  const p = el('oracle-mb-price'); if (p) p.textContent = oracleMbFmtPrice(_oracleMbState.price);
  const ad = el('oracle-mb-addr'); if (ad) ad.textContent = oracleMbShort(_oracleMbState.addr);
  const rt = el('oracle-mb-rolltx'); if (rt) rt.textContent = oracleMbShort(_oracleMbState.rollTxid);
  oracleMbRenderAge();
}

// Cheap poll: read ONLY the heartbeat UTXO (small) -> its txid (local, no tx fetch, no lag).
// The block-stream watcher is the primary price/T source; this only refreshes the displayed
// roll txid and, as a backstop, does ONE REST read if the watcher seems to have missed a roll
// (a new txid appeared but no price/T update landed within 15s). No 12s REST flood, no 404 storm.
async function oracleMbPollOnce() {
  try {
    const wsUrl = await resolveNodeUrl();
    const hb = JSON.parse(await fetch_utxos_for_address_js(ORACLE_MB.heartbeatAddress, wsUrl));
    if (!hb.length) return;
    const txid = utxoTxid(hb[0]);
    if (!txid) return;
    const changed = !_oracleMbState || txid !== _oracleMbState.rollTxid;
    if (changed) {
      if (!_oracleMbState) _oracleMbState = { price: 0n, t: 0n, rollTxid: txid, addr: '' };
      else _oracleMbState.rollTxid = txid;       // refresh the displayed roll txid (local, cheap)
      oracleMbRenderState();
      // Backstop only: a new roll's txid is up but the BlockAdded notification didn't refresh
      // price/T within 15s -> the watcher likely missed it -> one REST catch-up read.
      if (Date.now() - _oracleMbPriceTs > 15000) await oracleMbCardRefresh();
    }
  } catch (_) { /* node hiccup; keep the last reading, retry next tick */ }
}

// Full read: discovery (heartbeat -> roll tx -> journal price/T -> rotated address).
async function oracleMbCardRefresh() {
  try {
    const r = await oracleMbDiscoverAndRead();
    _oracleMbState = { price: r.price, t: r.t, rollTxid: r.rollTxid, addr: r.expectedOracleAddress };
    _oracleMbPriceTs = Date.now();
    oracleMbRenderState();
  } catch (e) {
    const ageEl = el('oracle-mb-age');
    if (ageEl && !_oracleMbState) { ageEl.textContent = 'node unreachable, retrying…'; ageEl.style.color = 'var(--text-muted)'; }
    console.warn('[oracle-mb] refresh failed:', e && e.message ? e.message : e);
  }
}

// Panel open: preload the fixed identity, kick a full read, start age + poll timers.
function oracleMbCardOpen() {
  if (!ORACLE_MB.heartbeatAddress) ORACLE_MB.heartbeatAddress = ORACLE_MB_DEPLOY.heartbeatAddress;
  if (!ORACLE_MB.heartbeatCovIdH)  ORACLE_MB.heartbeatCovIdH  = ORACLE_MB_DEPLOY.heartbeatCovIdH;
  if (!ORACLE_MB.oracleCovIdG)     ORACLE_MB.oracleCovIdG     = ORACLE_MB_DEPLOY.oracleCovIdG;

  const askStatus = el('oracle-mb-ask-status'); if (askStatus) askStatus.style.display = 'none';
  if (_oracleMbState) oracleMbRenderState(); // paint cached immediately if we have it
  oracleMbCardRefresh();                      // one-time cold-start read (REST) for the current price

  if (_oracleMbAgeTimer) clearInterval(_oracleMbAgeTimer);
  _oracleMbAgeTimer = setInterval(oracleMbRenderAge, 1000);
  if (_oracleMbPollTimer) clearInterval(_oracleMbPollTimer);
  _oracleMbPollTimer = setInterval(oracleMbPollOnce, 12000);

  oracleMbBlockWatcherStart();                // live price/T from the block stream (no REST, no lag)
}

function oracleMbAmbientStop() {
  if (_oracleMbAgeTimer) { clearInterval(_oracleMbAgeTimer); _oracleMbAgeTimer = null; }
  if (_oracleMbPollTimer) { clearInterval(_oracleMbPollTimer); _oracleMbPollTimer = null; }
  oracleMbBlockWatcherStop();
}

// ── Live price/T from the block stream (no REST tx-by-id; kills the public-indexer lag) ──
// Subscribe BlockAdded and scan each block for the ZK journal pushed in the roll tx's oracle
// input sig_script: 0x30 (push 48) | price(8 LE) | T(8 LE) | set_root(32). The journal sits
// verbatim in the block bytes, so we match the fixed set_root and guard the 0x30 push opcode
// 17 bytes ahead of it (this disambiguates from the set_root pinned inside the revealed redeem,
// which is a 0x20 OP_DATA_32 push). On a hit we read price/T, reconstruct the rotated oracle
// address, and render — within ~1s of the roll being mined, with no indexer round-trip.
function oracleMbBlockWatcherStop() {
  if (_oracleMbBlockWs) { try { _oracleMbBlockWs.close(); } catch (_) {} _oracleMbBlockWs = null; }
}

async function oracleMbBlockWatcherStart() {
  oracleMbBlockWatcherStop();
  const SR = (ORACLE_MB.setRootHex || "").toLowerCase();
  if (SR.length !== 64) { console.warn('[oracle-mb] block watcher: setRootHex not set'); return; }
  const srBytes = new Uint8Array(32);
  for (let j = 0; j < 32; j++) srBytes[j] = parseInt(SR.substr(j * 2, 2), 16);

  try {
    const wsUrl = await resolveNodeUrl();
    const blockAddedReq = new Uint8Array(build_vcc_subscribe_request(43n)); // BlockAdded scope
    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    _oracleMbBlockWs = ws;
    ws.onopen = () => { ws.send(blockAddedReq); };

    ws.onmessage = (evt) => {
      const data = new Uint8Array(evt.data);
      if (data.length < 50) return;
      let pos = (data[0] === 0x01) ? 9 : 1;
      if (pos >= data.length || data[pos] !== 0xFF) return;
      if (data[pos + 2] !== 0x3C) return;            // BlockAddedNotification

      for (let k = 17; k + 32 <= data.length; k++) {
        if (data[k] !== srBytes[0]) continue;
        let m = true;
        for (let j = 1; j < 32; j++) { if (data[k + j] !== srBytes[j]) { m = false; break; } }
        if (!m) continue;
        if (data[k - 17] !== 0x30) continue;         // not the journal set_root (redeem's is 0x20)

        let price = 0n, t = 0n;
        for (let j = 0; j < 8; j++) price |= BigInt(data[k - 16 + j]) << BigInt(8 * j);
        for (let j = 0; j < 8; j++) t     |= BigInt(data[k - 8  + j]) << BigInt(8 * j);
        if (_oracleMbState && _oracleMbState.price === price && _oracleMbState.t === t) return; // unchanged

        let addr = _oracleMbState ? _oracleMbState.addr : '';
        try {
          const ex = JSON.parse(covenant_oracle_mb(
            price, t,
            ORACLE_MB.imageIdHex, ORACLE_MB.controlIdHex, ORACLE_MB.setRootHex, ORACLE_MB.hashfnHex,
            ORACLE_MB.heartbeatCovIdH, ORACLE_MB.network));
          addr = ex.address;
        } catch (_) {}

        const rollTxid = _oracleMbState ? _oracleMbState.rollTxid : '';
        _oracleMbState = { price, t, rollTxid, addr };
        _oracleMbPriceTs = Date.now();
        oracleMbRenderState();
        console.log('[oracle-mb] block-stream update: price', price.toString(), 'T', t.toString());
        return;
      }
    };

    ws.onerror = () => {};
    ws.onclose = () => {
      if (_oracleMbBlockWs === ws) {
        _oracleMbBlockWs = null;
        if (_oracleMbAgeTimer) setTimeout(oracleMbBlockWatcherStart, 3000); // self-heal while the card is open
      }
    };
  } catch (e) {
    console.warn('[oracle-mb] block watcher failed:', e && e.message ? e.message : e);
    if (_oracleMbAgeTimer) setTimeout(oracleMbBlockWatcherStart, 5000);
  }
}


// Ask-for-new (P3a): on-chain freshness pre-check, then drive the operator's PUBLIC prover
// (ORACLE_MB.proverBase, CORS-open), then build the forward-roll from the current oracle and
// hand it to the existing review/sign/broadcast UI. No pre-sign split (P3b) yet: this signs
// the full PSKB. The server is single-flight, so concurrent askers coalesce onto one prove.
let _oracleMbAskBusy = false;

async function oracleMbProverGet(pathQ) {
  const base = (ORACLE_MB.proverBase || "").replace(/\/+$/, "");
  const r = await fetch(base + pathQ, { signal: AbortSignal.timeout(15000) });
  let j = null; try { j = await r.json(); } catch (_) {}
  return { ok: r.ok, status: r.status, body: j };
}

// Auto-broadcast countdown on the PSKB review screen. While the oracle proof is still
// proving and a roll is signed-and-waiting, show how long until it broadcasts. Driven by
// the prover's `since` + `eta_s`, stashed in window._oracleMbProveDeadline by the ask loop.
function oracleMbCountdownTick() {
  const awaiting = window._oracleMbPreSignAwaiting || window._oracleMbAutoBroadcast;
  const review = document.getElementById('pskt-review');
  const onReview = review && !review.classList.contains('hidden') && review.style.display !== 'none';
  let box = document.getElementById('oracle-mb-countdown');
  if (!awaiting || !onReview) { if (box) box.style.display = 'none'; return; }
  if (!box) {
    const btn = document.getElementById('btn-pskt-finalize');
    if (!btn || !btn.parentNode) return;
    box = document.createElement('div');
    box.id = 'oracle-mb-countdown';
    box.style.cssText = 'margin-top:10px;text-align:center;font-size:13px;line-height:1.4;color:var(--teal);';
    btn.parentNode.insertBefore(box, btn.nextSibling);
  }
  box.style.display = 'block';
  const deadline = window._oracleMbProveDeadline || 0;
  const remMs = deadline - Date.now();
  if (!deadline || remMs <= 0) {
    box.textContent = 'Proof finishing — it will broadcast automatically any moment…';
  } else {
    const rem = Math.ceil(remMs / 1000);
    box.textContent = (window._oracleMbAutoBroadcast ? 'Signed. ' : '')
      + 'Proof proving — auto-broadcast in ~' + rem + 's';
  }
}
if (!window._oracleMbCountdownStarted) { window._oracleMbCountdownStarted = true; setInterval(oracleMbCountdownTick, 1000); }

// Little-endian u64 hex (8 bytes) for building the 48-byte journal from a target price/T.
function oracleMbLeU64Hex(v) {
  let x = BigInt(v); const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return bytesToHex(b);
}

// Pre-sign proof injection (pure JS, no rebuild). The publish PSKB carries the RISC0 witness as
// JSON proprietaries on inputs[0]: the ~445 KB seal (risc0Seal) and risc0Fields
// {claim, controlIndex, controlDigests, journal}. None of these are in a sig_script — the oracle
// sig_script is built from them only at finalize. So the device can sign a SKELETON whose seal +
// claim + controlIndex + controlDigests are empty (a few-KB QR), and we splice the proven values
// into the SIGNED PSKB here, before finalize. The fee signature is unaffected: the sighash commits
// to outpoints/amounts/SPKs/sequences/outputs/payload/locktime but NOT to any signature_script,
// and (for tx_version>=1) excludes sig_op_counts. The journal is left as the skeleton built it
// (the caller verifies the proven journal equals it before injecting), and the outputs the device
// signed were fixed by that journal, so the proof matches the bytes that were signed.
// Returns the re-encoded wire on success, or null if input[0] is not an oracle-mb ROLL input
// (a stale held proof from an abandoned ask — caller proceeds unchanged). Throws only on a corrupt
// envelope / JSON, so a genuine oracle skeleton never finalizes with empty proof fields.
function oracleMbInjectProof(wireHex, proof) {
  const wireBytes = hexToBytes(wireHex);
  if (wireBytes.length < 4 ||
      wireBytes[0] !== 0x50 || wireBytes[1] !== 0x53 || wireBytes[2] !== 0x4b || wireBytes[3] !== 0x42) {
    throw new Error('not a PSKB envelope');
  }
  // bytes[4:] are the ASCII of hex(json). hex-decode that to the JSON bytes, then UTF-8 to text.
  const jsonHexAscii = new TextDecoder().decode(wireBytes.slice(4));
  const arr = JSON.parse(new TextDecoder().decode(hexToBytes(jsonHexAscii)));
  const pskt = Array.isArray(arr) ? arr[0] : arr;
  const inp0 = pskt && pskt.inputs && pskt.inputs[0];
  const prop = inp0 && inp0.proprietaries;
  if (!prop || prop.risc0OracleMb !== true) return null;   // not an oracle skeleton; leave it alone
  prop.risc0Seal = proof.seal;
  prop.risc0Fields = prop.risc0Fields || {};
  prop.risc0Fields.claim = proof.claim;
  prop.risc0Fields.controlIndex = proof.controlIndex;
  prop.risc0Fields.controlDigests = proof.controlDigests;
  const outJsonHexAscii = bytesToHex(new TextEncoder().encode(JSON.stringify(arr)));
  return bytesToHex(new TextEncoder().encode('PSKB' + outJsonHexAscii));
}

// Splice the service-fee output into a freshly-built roll PSKB (pure JS, no rebuild). Coin selection
// for the skeleton already reserved miner + service (see the fee: line above), so the change output
// already accounts for the service fee. We APPEND the service output and do NOT trim change: adding a
// feeSompi P2PK output pulls the net miner fee down from (miner + service) back to miner, routing the
// service portion to ORACLE_MB.feeAddress while the totals still balance. The oracle covenant
// constrains only output[0] (the next oracle) and the heartbeat continuation, so appending one
// untagged output last disturbs nothing the script checks, and no change output need exist (if
// selection left none, the added output still reduces the miner fee by exactly feeSompi). Throws only
// on a corrupt envelope. (The previous version carved the fee out of change and failed with "change
// too small" whenever selection had reserved the miner fee alone.)
function oracleMbSpliceFee(wireHex, changeAddr) {
  const wireBytes = hexToBytes(wireHex);
  if (wireBytes.length < 4 ||
      wireBytes[0] !== 0x50 || wireBytes[1] !== 0x53 || wireBytes[2] !== 0x4b || wireBytes[3] !== 0x42) {
    throw new Error('not a PSKB envelope');
  }
  // Quote every amount before parsing: JSON.parse rounds integer literals
  // above 2^53, and this function re-serializes what it parsed, so a large
  // output amount would round-trip rounded. Quoted, the digits pass through
  // untouched, and the fee push below rides the same convention.
  const arr = JSON.parse(new TextDecoder().decode(hexToBytes(new TextDecoder().decode(wireBytes.slice(4))))
      .replace(/"amount"\s*:\s*(\d+)/g, '"amount":"$1"'));
  const pskt = Array.isArray(arr) ? arr[0] : arr;
  const outs = pskt && pskt.outputs;
  if (!Array.isArray(outs) || !outs.length) throw new Error('roll PSKB has no outputs to splice the fee into');
  const fee = ORACLE_MB.feeSompi;
  // Every amount is a string after the quoting above; the fee follows suit.
  outs.push({ amount: fee.toString(), scriptPublicKey: ORACLE_MB.feeSpk, proprietaries: {} });
  const outJsonHexAscii = bytesToHex(new TextEncoder().encode(JSON.stringify(arr)));
  return bytesToHex(new TextEncoder().encode('PSKB' + outJsonHexAscii));
}

// Build a seal-less, proof-less skeleton for the given 48-byte journal hex, splice in the service
// fee, and hand it to the review UI for signing. The device signs the small sealless roll (incl.
// the fee output); the prover proves the accumulator, injects the seal, and broadcasts at /roll.
// Set the oracle roll fee total (KAS). A preset highlights its chip; a custom value clears the chips.
// Updates the Ask button label. The total is reserved whole at build time (net miner = total - 0.3).
function oracleMbSetFee(totalKas, fromCustom) {
  const t = Number(totalKas);
  if (!(Number.isFinite(t) && t >= 1)) return;
  _oracleMbFeeTotalKas = t;
  document.querySelectorAll('.omb-fee-btn').forEach(b => {
    const sel = !fromCustom && Number(b.getAttribute('data-omb-fee')) === t;
    b.style.background = sel ? 'var(--teal)' : 'var(--bg)';
    b.style.color = sel ? '#0a0a0a' : 'var(--text)';
    b.style.borderColor = sel ? 'var(--teal)' : 'var(--border)';
  });
  const btn = el('btn-oracle-mb-ask');
  if (btn) btn.textContent = 'Ask for new price (\u2248' + t + ' KAS)';
}

async function oracleMbOpenSkeletonForSigning(journalHex, show) {
  const wd = walletData; // L-13: direct read, window.getWalletData removed
  if (!wd) { show('Unlock your wallet first.', '#ffd600'); return false; }
  if (!_oracleMbState) { show('Could not read the current oracle to spend.', '#ff4d4d'); return false; }
  const wallet = JSON.parse(wd);
  const changeAddr = wallet.change_addresses[wallet.next_change_index || 0];
  const cur = oracleMbOracleAddress(_oracleMbState.price, _oracleMbState.t); // current oracle: addr + redeem to spend
  // Total fee the user picked (presets or custom; min 1 KAS). Reserved whole in coin selection; the
  // splice below routes the 0.3 service fee out of it to the fee address, so the net miner fee is
  // (total - 0.3). A bigger total is a higher feerate on the fixed-mass roll, which is how a roll
  // jumps a congested mempool and confirms in seconds instead of sitting for minutes.
  const totalKas = (_oracleMbFeeTotalKas >= 1) ? _oracleMbFeeTotalKas : 1;
  const feeTotalSompi = kasToSompi(totalKas.toFixed(8));
  const pskb = await oracleMbPublish({
    walletJson: wd, oracleAddress: cur.address, oracleRedeemHex: cur.redeem_script_hex,
    covenantIdG: ORACLE_MB.oracleCovIdG,
    seal: "", claim: "", controlIndex: "", controlDigests: "", journal: journalHex,
    fee: feeTotalSompi, changeAddress: changeAddr,   // reserve the full picked total (miner + service); the splice routes 0.3 to the fee address, net miner = total - 0.3
  });
  let pskbWithFee;
  try { pskbWithFee = oracleMbSpliceFee(pskb, changeAddr); }
  catch (e) { show('Could not add the service fee: ' + (e && e.message ? e.message : e), '#ff4d4d'); return false; }
  oracleMbAmbientStop();               // handing off to the review UI
  openPsktReview(pskbWithFee);         // device signs the small sealless skeleton, including the fee output
  window._oracleMbRollActive = true;   // re-arm AFTER openPsktReview (which clears it): true only for a live roll
  return true;
}

async function oracleMbAskForNew() {
  const status = el('oracle-mb-ask-status');
  const btn = el('btn-oracle-mb-ask');
  const show = (msg, color) => { if (status) { status.style.display = 'block'; status.textContent = msg; status.style.color = color || 'var(--teal)'; } };
  if (_oracleMbAskBusy) return;
  if (!ORACLE_MB.proverBase) { show('Set ORACLE_MB.proverBase to the public prover URL first.', '#ffd600'); return; }

  _oracleMbAskBusy = true;
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; }
  const done = () => { _oracleMbAskBusy = false; if (btn) { btn.disabled = false; btn.style.opacity = ''; } };
  const MAX_AGE = 60;
  window._oracleMbRoll = null;   // {acc, price, t} stashed for the /roll POST at finalize

  try {
    // 1) Freshness pre-check: a fresh on-chain price needs no new roll (and no fee).
    show('Checking on-chain freshness...', 'var(--text-muted)');
    await oracleMbCardRefresh();
    const ageS = _oracleMbState ? (Math.floor(Date.now() / 1000) - Number(_oracleMbState.t)) : 1e9;
    if (ageS <= MAX_AGE) { show('Price is fresh (' + Math.floor(ageS / 60) + 'm old). No new roll needed.', 'var(--teal)'); done(); return; }
    if (!_oracleMbState) { show('Could not read the current oracle to spend.', '#ff4d4d'); done(); return; }

    // 1b) Already-moved guard. Our card's price read can lag (on TN10 the catch-up goes through public
    //     REST, which is blind to the local-only oracle chain), so we may believe a stale price still
    //     needs rolling when a roll has in fact already landed. The heartbeat UTXO (fixed address, read
    //     straight from our own node) names the current roll; if its txid no longer matches the roll our
    //     state is built on, the oracle already moved and a roll built now would spend an already-spent
    //     outpoint and die "already spent" AFTER a ~1 min prove we would pay for. Stop here and refresh,
    //     never quote/sign/prove. A node hiccup must not block a real roll, so a failed read falls through.
    try {
      const wsUrl = await resolveNodeUrl();
      const hb = JSON.parse(await fetch_utxos_for_address_js(ORACLE_MB.heartbeatAddress, wsUrl));
      const liveRollTxid = hb.length ? utxoTxid(hb[0]) : '';
      if (liveRollTxid && _oracleMbState.rollTxid &&
          String(liveRollTxid).toLowerCase() !== String(_oracleMbState.rollTxid).toLowerCase()) {
        show('The oracle already moved on-chain (a roll just landed). Refreshing the price, no proof spent.', 'var(--text-muted)');
        try { await oracleMbCardRefresh(); } catch (_) {}
        done(); return;
      }
    } catch (_) { /* node unreachable: do not block a legitimate roll on the guard's own failure */ }

    // 2) Quote: one free GET, no prove, no money. Returns the latest accumulator plus its price/T
    //    and the fee address. We build a roll committing to exactly this price/T and sign it once;
    //    the prover proves THIS accumulator, injects the seal, and broadcasts (it never hands us
    //    the seal, so the fee cannot be stripped). No client-side prove polling, no auto-broadcast.
    show('Fetching a price quote...', 'var(--text-muted)');
    let q;
    try { q = await oracleMbProverGet('/quote'); }
    catch (e) { show('Prover unreachable: ' + (e && e.message ? e.message : e), '#ff4d4d'); done(); return; }
    if (!q.ok || !q.body) { show('Quote failed (HTTP ' + q.status + ').', '#ff4d4d'); done(); return; }
    const qb = q.body;
    if (qb.error) { show('Quote error: ' + qb.error, '#ff4d4d'); done(); return; }
    if (!qb.acc || qb.price == null || qb.publish_time == null) { show('Quote incomplete, try again.', '#ff4d4d'); done(); return; }
    if ((qb.set_root || '').toLowerCase() !== (ORACLE_MB.setRootHex || '').toLowerCase()) {
      show('Quote set_root mismatch, aborting (guardian-set drift?).', '#ff4d4d'); done(); return;
    }
    if (qb.fee_address && qb.fee_address !== ORACLE_MB.feeAddress) {
      show('Quote fee address changed, refusing (update KasSee first).', '#ff4d4d'); done(); return;
    }

    // 3) Build the roll for this exact price/T (with the fee output) and open it for signing.
    window._oracleMbRoll = { acc: qb.acc, price: String(qb.price), t: Number(qb.publish_time) };
    const journal = oracleMbLeU64Hex(qb.price) + oracleMbLeU64Hex(qb.publish_time) + (ORACLE_MB.setRootHex || '').toLowerCase();
    show('Building the roll...', 'var(--text-muted)');
    const ok = await oracleMbOpenSkeletonForSigning(journal, show);
    if (!ok) { window._oracleMbRoll = null; done(); return; }   // soft failure already shown
    toast('Sign this small roll. When you tap Finalize, the prover proves it and broadcasts (usually ~1-2 min).', 'info', 9000);
    show('Review and sign the roll, then tap Finalize + broadcast.', 'var(--teal)');
  } catch (e) {
    window._oracleMbRoll = null;
    show('Ask-for-new failed: ' + (e && e.message ? e.message : e), '#ff4d4d');
  } finally {
    done();
  }
}
window.ORACLE_MB = ORACLE_MB;
window.oracleMbHeartbeatAddress = oracleMbHeartbeatAddress;
window.oracleMbReadH = oracleMbReadH;
window.oracleMbOracleAddress = oracleMbOracleAddress;
window.oracleMbReadG = oracleMbReadG;
window.oracleMbPublish = oracleMbPublish;
window.oracleMbDiscoverAndRead = oracleMbDiscoverAndRead;
window.oracleMbCardOpen = oracleMbCardOpen;
window.oracleMbCardRefresh = oracleMbCardRefresh;
window.oracleMbAskForNew = oracleMbAskForNew;
window.oracleMbInjectProof = oracleMbInjectProof;
window.oracleMbAmbientStop = oracleMbAmbientStop;                        // kill the watcher/poll/age timers from the console
window.oracleMbSetState = (p, t, addr) => { _oracleMbState = { price: BigInt(p), t: BigInt(t), rollTxid: '', addr: addr || '' }; }; // seed the MODULE-scoped state; a console "_oracleMbState = ..." only makes a global the module never reads
// ════════════════════════════ end ORACLE (Model B) block ════════════════════════════
