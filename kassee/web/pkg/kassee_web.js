/* @ts-self-types="./kassee_web.d.ts" */

/**
 * BIP340 Schnorr sign (PoC, both sides in browser).
 * Returns 128 hex (64-byte sig).
 * @param {string} secret_hex
 * @param {string} msg_hash_hex
 * @returns {string}
 */
export function adaptor_bip340_sign(secret_hex, msg_hash_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_bip340_sign(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * BIP340 Schnorr verify.
 * @param {string} pubkey_hex
 * @param {string} msg_hash_hex
 * @param {string} sig_hex
 * @returns {boolean}
 */
export function adaptor_bip340_verify(pubkey_hex, msg_hash_hex, sig_hex) {
    const ptr0 = passStringToWasm0(pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.adaptor_bip340_verify(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Build and broadcast an adaptor swap claim TX.
 * Fetches UTXOs at covenant_addr, builds a raw TX with the provided sig_script,
 * sends the output to dest_addr, and broadcasts to the node.
 * Returns the TX ID on success.
 * @param {string} covenant_addr
 * @param {string} dest_addr
 * @param {string} sig_script_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function adaptor_broadcast_claim(covenant_addr, dest_addr, sig_script_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(sig_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.adaptor_broadcast_claim(ptr0, len0, ptr1, len1, ptr2, len2, fee, ptr3, len3);
    return ret;
}

/**
 * Build sig_script for claiming an adaptor swap UTXO.
 * Layout: <push sig_64> <push msg_hash_32> <push redeem_script>
 * Returns sig_script hex.
 * @param {string} completed_sig_hex
 * @param {string} msg_hash_hex
 * @param {string} redeem_hex
 * @returns {string}
 */
export function adaptor_build_sig_script(completed_sig_hex, msg_hash_hex, redeem_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(completed_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(redeem_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_build_sig_script(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Complete an adaptor signature with the secret.
 * Returns completed BIP340 signature (128 hex).
 * @param {string} adaptor_sig_hex
 * @param {string} secret_hex
 * @returns {string}
 */
export function adaptor_complete_sig(adaptor_sig_hex, secret_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(adaptor_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_complete_sig(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Create an adaptor signature.
 * Returns JSON: { adaptor_sig_hex, signer_pubkey_hex }
 * @param {string} signer_secret_hex
 * @param {string} msg_hash_hex
 * @param {string} adaptor_point_hex
 * @returns {string}
 */
export function adaptor_create_sig(signer_secret_hex, msg_hash_hex, adaptor_point_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(signer_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(adaptor_point_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_create_sig(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Extract the adaptor secret from on-chain completed sig vs original adaptor.
 * Returns secret t (64 hex).
 * @param {string} completed_sig_hex
 * @param {string} adaptor_sig_hex
 * @returns {string}
 */
export function adaptor_extract_secret(completed_sig_hex, adaptor_sig_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(completed_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(adaptor_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_extract_secret(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Generate a random signing keypair (for PoC, browser-side signing).
 * Returns JSON: { secret_hex, pubkey_hex }
 * @returns {string}
 */
export function adaptor_generate_keypair() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.adaptor_generate_keypair();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate an adaptor secret (t, T) for the swap initiator.
 * Returns JSON: { t_hex, T_hex }
 * @returns {string}
 */
export function adaptor_generate_secret() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.adaptor_generate_secret();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Negate a scalar (additive inverse mod curve order).
 * Used to handle BIP340 even-Y parity when extracting adaptor secrets.
 * @param {string} scalar_hex
 * @returns {string}
 */
export function adaptor_negate_scalar(scalar_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(scalar_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_negate_scalar(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Create a P2SH address for an adaptor swap UTXO.
 * Redeem script: <claimer_pubkey> OP_CHECKSIGFROMSTACK
 * Returns JSON: { address, redeem_script_hex, claimer_pubkey_hex }
 * @param {string} claimer_pubkey_hex
 * @param {string} owner_pubkey_hex
 * @param {string} claimer_dest_addr
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function adaptor_swap_address(claimer_pubkey_hex, owner_pubkey_hex, claimer_dest_addr, locktime_daa, network) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(claimer_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(claimer_dest_addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_swap_address(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Compute swap commitment hash (both parties derive the same msg_hash).
 * Returns 64 hex (32-byte SHA256).
 * @param {string} alice_utxo_id
 * @param {string} bob_utxo_id
 * @param {bigint} alice_amount
 * @param {bigint} bob_amount
 * @returns {string}
 */
export function adaptor_swap_commitment(alice_utxo_id, bob_utxo_id, alice_amount, bob_amount) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(alice_utxo_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(bob_utxo_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adaptor_swap_commitment(ptr0, len0, ptr1, len1, alice_amount, bob_amount);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Verify an adaptor signature.
 * @param {string} pubkey_hex
 * @param {string} msg_hash_hex
 * @param {string} adaptor_sig_hex
 * @param {string} adaptor_point_hex
 * @returns {boolean}
 */
export function adaptor_verify_sig(pubkey_hex, msg_hash_hex, adaptor_sig_hex, adaptor_point_hex) {
    const ptr0 = passStringToWasm0(pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(adaptor_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(adaptor_point_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.adaptor_verify_sig(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Compute unkeyed Blake2b-256 hash of the input bytes (hex in, hex out).
 * Used for atomic swap expected hash computation from preimage.
 * @param {string} input_hex
 * @returns {string}
 */
export function blake2b_hash(input_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(input_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.blake2b_hash(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Broadcast a signed KSPT hex to the network → return TX ID
 * @param {string} signed_hex
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function broadcast_signed(signed_hex, ws_url) {
    const ptr0 = passStringToWasm0(signed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.broadcast_signed(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Build the plaintext covenant payload blob: [version:1][type:1][params...]
 * version = 0x01, type = covenant type byte. Caller provides params as hex.
 * Returns hex of the assembled plaintext (ready for AES-GCM encryption in JS).
 * @param {number} covenant_type
 * @param {string} params_hex
 * @returns {string}
 */
export function build_covenant_payload(covenant_type, params_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(params_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.build_covenant_payload(covenant_type, ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Build a NotifyUtxosChanged subscribe request.
 * @param {string} covenant_address
 * @param {bigint} request_id
 * @returns {Uint8Array}
 */
export function build_utxo_subscribe_request(covenant_address, request_id) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.build_utxo_subscribe_request(ptr0, len0, request_id);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Build a NotifyVirtualChainChanged subscribe request (raw bytes).
 * @param {bigint} request_id
 * @returns {Uint8Array}
 */
export function build_vcc_subscribe_request(request_id) {
    const ret = wasm.build_vcc_subscribe_request(request_id);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Precomputed lane_key(SUBNETWORK_ID_COINBASE). The coinbase lane is present in every block, so
 * fetching its proof confirms the seq_commit machinery is active without submitting any tx.
 * @returns {string}
 */
export function coinbase_lane_key() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.coinbase_lane_key();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Compute BLAKE2B hash of a preimage (for creating the commitment).
 * Returns hex string of the 32-byte hash.
 * @param {string} preimage_hex
 * @returns {string}
 */
export function commit_hash(preimage_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(preimage_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.commit_hash(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Build a Piggy Bank P2SH covenant address.
 * owner_pubkey_hex: 64-char hex of the 32-byte x-only pubkey
 * threshold_sompi: savings goal (0 = no goal)
 * deadline_daa: optional deadline DAA score (0 = no deadline)
 * Returns JSON: { "address": "kaspa:...", "redeem_script_hex": "...", "threshold_sompi": ..., "deadline_daa": ... }
 * @param {string} owner_pubkey_hex
 * @param {bigint} threshold_sompi
 * @param {bigint} deadline_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_additive_address(owner_pubkey_hex, threshold_sompi, deadline_daa, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_additive_address(ptr0, len0, threshold_sompi, deadline_daa, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Build an allowance covenant P2SH address.
 * Spending limit + relative time-lock (CSV). After each withdrawal,
 * min_sequence blocks must pass before the next one.
 * Returns JSON: { "address", "redeem_script_hex", "max_withdraw_sompi", "min_sequence" }
 * @param {string} owner_pubkey_hex
 * @param {string} beneficiary_pubkey_hex
 * @param {bigint} max_withdraw_sompi
 * @param {bigint} min_sequence
 * @param {bigint} start_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_allowance(owner_pubkey_hex, beneficiary_pubkey_hex, max_withdraw_sompi, min_sequence, start_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(beneficiary_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_allowance(ptr0, len0, ptr1, len1, max_withdraw_sompi, min_sequence, start_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build an atomic swap (HTLC) covenant P2SH address.
 * Counterparty claims by revealing preimage whose Blake2b hash matches;
 * owner refunds after timeout.
 * expected_hash_hex: 64-char hex of expected 32-byte hash
 * hash_algo: "blake2b" (Kaspa-native) or "sha256" (cross-chain Bitcoin-compatible)
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa", "hash_algo" }
 * @param {string} owner_pubkey_hex
 * @param {string} counterparty_pubkey_hex
 * @param {string} expected_hash_hex
 * @param {bigint} locktime_daa
 * @param {string} hash_algo
 * @param {string} network
 * @returns {string}
 */
export function covenant_atomic_swap(owner_pubkey_hex, counterparty_pubkey_hex, expected_hash_hex, locktime_daa, hash_algo, network) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(counterparty_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(hash_algo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_atomic_swap(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Create a commit-reveal covenant P2SH address.
 *
 * owner_pubkey_hex: 32-byte x-only pubkey (hex)
 * committed_hash_hex: 32-byte BLAKE2B(preimage) commitment (hex)
 * locktime_daa: DAA score for refund timeout
 *
 * Returns JSON: { address, redeem_script_hex, committed_hash, locktime_daa }
 * @param {string} owner_pubkey_hex
 * @param {string} committed_hash_hex
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_commit_reveal(owner_pubkey_hex, committed_hash_hex, locktime_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(committed_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_commit_reveal(ptr0, len0, ptr1, len1, locktime_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 *
 * contributor_pubkey_hex: 32-byte x-only pubkey (hex) — contributor's refund key
 * organizer_pubkey_hex: 32-byte x-only pubkey (hex) — organizer's sweep commitment key
 * vk_hex: verification key from crowdfund setup (hex)
 * locktime_daa: DAA score for contributor refund timeout
 *
 * Returns JSON: { address, redeem_script_hex, vk_hex, locktime_daa }
 * @param {string} contributor_pubkey_hex
 * @param {string} organizer_pubkey_hex
 * @param {string} vk_hex
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_crowdfund(contributor_pubkey_hex, organizer_pubkey_hex, vk_hex, locktime_daa, network) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(contributor_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(organizer_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(vk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_crowdfund(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Build a true dead man's switch (CSV-based) covenant P2SH address.
 * owner_pubkey_hex / heir_pubkey_hex: 32-byte x-only pubkeys (hex)
 * inactivity_daa: relative DAA units of inactivity before heir can claim
 * Returns JSON: { "address", "redeem_script_hex", "inactivity_daa" }
 * @param {string} owner_pubkey_hex
 * @param {string} heir_pubkey_hex
 * @param {bigint} inactivity_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_dms(owner_pubkey_hex, heir_pubkey_hex, inactivity_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(heir_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_dms(ptr0, len0, ptr1, len1, inactivity_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build an escrow covenant P2SH address.
 * alice_pubkey_hex, bob_pubkey_hex: 64-char hex of 32-byte x-only pubkeys
 * alice_address, bob_address: kaspa/kaspatest addresses for release destinations
 * Returns JSON: { "address", "redeem_script_hex" }
 * @param {string} alice_pubkey_hex
 * @param {string} bob_pubkey_hex
 * @param {string} arbiter_pubkey_hex
 * @param {string} alice_address
 * @param {string} bob_address
 * @param {string} network
 * @returns {string}
 */
export function covenant_escrow(alice_pubkey_hex, bob_pubkey_hex, arbiter_pubkey_hex, alice_address, bob_address, network) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(alice_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(bob_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(arbiter_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(alice_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(bob_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_escrow(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Build a GLOBAL single-thread ALLOWANCE covenant P2SH address.
 *
 * Per-spend cap applied to the whole thread balance (one tagged covenant_id
 * UTXO), withdrawn by the BENEFICIARY with a cooldown between withdrawals and
 * an optional vesting start date. The OWNER keeps a free reclaim/close path.
 * Genesis is created with `create_covenant_pskb_with_payload(tag_genesis=true)`
 * (full-spend, no change). Continued by `create_global_allowance_withdraw`
 * (beneficiary) and `create_global_allowance_topup` (owner).
 *
 * Returns JSON: { address, redeem_script_hex, max_withdraw_sompi,
 * cooldown_daa, start_daa, salt, type }
 * @param {string} owner_pubkey_hex
 * @param {string} beneficiary_pubkey_hex
 * @param {bigint} max_withdraw_sompi
 * @param {bigint} cooldown_daa
 * @param {bigint} start_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_global_allowance(owner_pubkey_hex, beneficiary_pubkey_hex, max_withdraw_sompi, cooldown_daa, start_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(beneficiary_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_global_allowance(ptr0, len0, ptr1, len1, max_withdraw_sompi, cooldown_daa, start_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build a GLOBAL spending-limit covenant P2SH address (covenant_id single-thread).
 *
 * Same per-spend cap + cooldown as `covenant_spending_limit`, but the whole
 * balance lives in ONE covenant_id-tagged UTXO (the thread), so the cap is
 * global instead of per-UTXO. Fund it as a covenant genesis via
 * `create_covenant_pskb` (passing this address), which tags the first UTXO
 * with the covenant_id that identifies the thread. Spend it later with
 * `create_global_spending_limit_withdraw`, which continues the single thread.
 *
 * Returns JSON: { address, redeem_script_hex, max_withdraw_sompi, cooldown_daa, salt }
 * @param {string} owner_pubkey_hex
 * @param {bigint} max_withdraw_sompi
 * @param {bigint} cooldown_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_global_spending_limit(owner_pubkey_hex, max_withdraw_sompi, cooldown_daa, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_global_spending_limit(ptr0, len0, max_withdraw_sompi, cooldown_daa, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Create a merkle whitelist vault covenant P2SH address.
 * @param {string} owner_pubkey_hex
 * @param {string} merkle_root_hex
 * @param {number} depth
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_merkle_whitelist(owner_pubkey_hex, merkle_root_hex, depth, locktime_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(merkle_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_merkle_whitelist(ptr0, len0, ptr1, len1, depth, locktime_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Create an oracle-gated covenant address.
 *
 * Two branches:
 *   - Owner refund after locktime (IF)
 *   - Beneficiary claims when oracle attests (ELSE, requires OpCheckSigFromStack)
 *
 * Returns JSON: { address, redeem_script_hex, locktime_daa }
 * @param {string} owner_pubkey_hex
 * @param {string} beneficiary_pubkey_hex
 * @param {string} oracle_pubkey_hex
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_oracle(owner_pubkey_hex, beneficiary_pubkey_hex, oracle_pubkey_hex, locktime_daa, network) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(beneficiary_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(oracle_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_oracle(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Oracle (Model B) genesis: the priced oracle UTXO. Commits image_id +
 * control_id + set_root + hashfn in the redeem (from the oracle-zkvm guest), at
 * an initial price / T. The covenant only advances on a fresh succinct
 * proof from the committed guest over the committed signer set.
 *
 * Fund the returned `address` with a tx_version = 1 send to bind its
 * covenant_id. image_id/control_id/set_root come from the host run:
 *   image_id   = 48701b6bf4c20e734a661d2092ba9b72fe33bec8f1c4a547dc5ddaee48fe7966
 *   control_id = 7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e
 *   set_root   = 47652e00d8cd5ec98481ee418b38ab70c471a66ee70a0564acfe879546c47778
 *   hashfn     = 01
 *
 * Returns JSON: { address, redeem_script_hex, genesis_price, genesis_t,
 * image_id, control_id, set_root, redeem_len, sig_op_count }.
 * @param {bigint} genesis_price
 * @param {bigint} genesis_t
 * @param {string} image_id_hex
 * @param {string} control_id_hex
 * @param {string} set_root_hex
 * @param {string} hashfn_hex
 * @param {string} heartbeat_cov_id_hex
 * @param {string} network
 * @returns {string}
 */
export function covenant_oracle_mb(genesis_price, genesis_t, image_id_hex, control_id_hex, set_root_hex, hashfn_hex, heartbeat_cov_id_hex, network) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(image_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(control_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(set_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(hashfn_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(heartbeat_cov_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_oracle_mb(genesis_price, genesis_t, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Oracle (Model B) heartbeat genesis: the keyless strict-singleton discovery
 * signpost. Carries no price and no T. It self-sends to a FIXED address and the
 * oracle ROLL branch requires exactly one heartbeat input, so every price roll
 * co-rolls this heartbeat in the same tx; its UTXO's txid is therefore always the
 * latest roll. A wallet finds the rotating oracle by querying this fixed address
 * (no indexer). Value rolls forward (out >= in, no skim).
 *
 * Fund the returned `address` with a tx_version = 1 send to bind its covenant_id
 * H. Do this FIRST: H is then passed to covenant_oracle_mb so the oracle body
 * embeds it (the binding is one-directional, so the heartbeat must exist first).
 *
 * Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }.
 * @param {string} network
 * @returns {string}
 */
export function covenant_oracle_mb_heartbeat(network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_oracle_mb_heartbeat(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive the standalone TEST CONSUMER address for a specific oracle lineage.
 * Fund the returned address with a normal send (it carries no covenant_id of its
 * own; only the oracle needs a tag). 2-input read: consumer + oracle, no
 * heartbeat. Returns JSON: { address, redeem_script_hex, oracle_covenant_id,
 *   redeem_len }.
 * @param {string} oracle_covenant_id_hex
 * @param {string} network
 * @returns {string}
 */
export function covenant_oracle_mb_test_consumer(oracle_covenant_id_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(oracle_covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_oracle_mb_test_consumer(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Create a PayJoin covenant address.
 *
 * Two branches:
 *   - Owner refund after locktime (IF)
 *   - Beneficiary claims only in a multi-input TX with mixed addresses (ELSE)
 *
 * Returns JSON: { address, redeem_script_hex, locktime_daa }
 * @param {string} owner_pubkey_hex
 * @param {string} beneficiary_pubkey_hex
 * @param {bigint} locktime_daa
 * @param {bigint} min_inputs
 * @param {bigint} min_outputs
 * @param {string} network
 * @returns {string}
 */
export function covenant_payjoin(owner_pubkey_hex, beneficiary_pubkey_hex, locktime_daa, min_inputs, min_outputs, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(beneficiary_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_payjoin(ptr0, len0, ptr1, len1, locktime_daa, min_inputs, min_outputs, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build a shipment-escrow covenant P2SH address.
 *
 * Three parties (seller, deliverer, buyer) + a dormant arbiter. The buyer
 * funds `total = product_sompi + fee_sompi`. Product price splits 50/50:
 * tranche1 to the seller at pickup, tranche2 held until delivery. Delivery
 * fee paid in full at delivery. Two CLTV deadlines back the liveness:
 * `cltv1_deadline` (no-pickup -> refund buyer) and `cltv2_deadline`
 * (no-delivery -> pay workers).
 *
 * Payouts go to each party's standard schnorr address (P2PK of their key),
 * built internally from the supplied pubkeys.
 *
 * Fund state 0 with exactly `total_sompi`; the pickup spend continues the
 * covenant at exactly `rem_sompi` (state 1). Returns JSON with the address,
 * redeem script, salt, and all derived amounts/deadlines for the spend UI.
 * @param {string} seller_pubkey_hex
 * @param {string} deliverer_pubkey_hex
 * @param {string} buyer_pubkey_hex
 * @param {string} arbiter_pubkey_hex
 * @param {bigint} product_sompi
 * @param {bigint} fee_sompi
 * @param {bigint} cltv1_deadline
 * @param {bigint} cltv2_deadline
 * @param {string} network
 * @returns {string}
 */
export function covenant_ship_escrow(seller_pubkey_hex, deliverer_pubkey_hex, buyer_pubkey_hex, arbiter_pubkey_hex, product_sompi, fee_sompi, cltv1_deadline, cltv2_deadline, network) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(seller_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(deliverer_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(buyer_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(arbiter_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_ship_escrow(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, product_sompi, fee_sompi, cltv1_deadline, cltv2_deadline, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Create a Split Vault covenant address.
 * Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
 * @param {string} owner_pubkey_hex
 * @param {string} network
 * @returns {string}
 */
export function covenant_split_vault(owner_pubkey_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_split_vault(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Create a Tagged Vault covenant address and redeem script.
 *
 * The tagged vault enforces state continuity via KIP-20 covenant IDs:
 * every spend must produce an output carrying the same covenant_id.
 *
 * Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
 * @param {string} owner_pubkey_hex
 * @param {string} network
 * @returns {string}
 */
export function covenant_tagged_vault(owner_pubkey_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_tagged_vault(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Build a time-locked escrow covenant P2SH address.
 * alice_pubkey_hex / bob_pubkey_hex: 32-byte x-only pubkeys (hex)
 * alice_addr / bob_addr: destination addresses for each party
 * locktime_daa: DAA score after which funds auto-refund to Alice
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
 * @param {string} alice_pubkey_hex
 * @param {string} bob_pubkey_hex
 * @param {string} alice_addr
 * @param {string} bob_addr
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_timelocked_escrow(alice_pubkey_hex, bob_pubkey_hex, alice_addr, bob_addr, locktime_daa, network) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(alice_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(bob_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(alice_addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(bob_addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_timelocked_escrow(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, locktime_daa, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Build a time-locked SAVINGS covenant P2SH address.
 * wallet1_pubkey_hex / wallet2_pubkey_hex: 32-byte x-only pubkeys (hex).
 *   wallet2 is the key-loss recovery key (1-of-2, not multisig). Pass the
 *   same value as wallet1 if you do not want a separate recovery key.
 * locktime_daa: DAA score; funds are frozen for everyone until this score,
 *   after which either wallet can sweep with a single signature.
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
 * @param {string} wallet1_pubkey_hex
 * @param {string} wallet2_pubkey_hex
 * @param {bigint} locktime_daa
 * @param {string} network
 * @returns {string}
 */
export function covenant_timelocked_savings(wallet1_pubkey_hex, wallet2_pubkey_hex, locktime_daa, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(wallet1_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet2_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_timelocked_savings(ptr0, len0, ptr1, len1, locktime_daa, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build a treasury (approved destinations) covenant P2SH address.
 * Owner can spend but ONLY to whitelisted addresses baked into the script.
 * approved_addresses_json: JSON array of kaspa/kaspatest addresses (1–4)
 * Returns JSON: { "address", "redeem_script_hex", "approved_count" }
 * @param {string} owner_pubkey_hex
 * @param {string} approved_addresses_json
 * @param {string} network
 * @returns {string}
 */
export function covenant_treasury(owner_pubkey_hex, approved_addresses_json, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(approved_addresses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.covenant_treasury(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Create a PSKB for revealing and spending a commit-reveal covenant.
 *
 * The preimage is embedded in PSKB proprietaries and assembled
 * into the sig_script at finalization.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} part_a_hex
 * @param {string} part_b_hex
 * @param {string} payload_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_commit_reveal_spend(covenant_address, dest_address, redeem_script_hex, part_a_hex, part_b_hex, payload_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(part_a_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(part_b_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(payload_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.create_commit_reveal_spend(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, fee, ptr6, len6);
    return ret;
}

/**
 * Create compound KSPT with multiple recipients
 * recipients_json: [{"address":"kaspa:...","amount_sompi":"150000000"}, ...]
 * @param {string} wallet_json
 * @param {string} recipients_json
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_compound_kspt(wallet_json, recipients_json, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(recipients_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.create_compound_kspt(ptr0, len0, ptr1, len1, fee_sompi, ptr2, len2);
    return ret;
}

/**
 * Create compound unsigned PSKB: multiple recipients.
 * @param {string} wallet_json
 * @param {string} recipients_json
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_compound_pskb(wallet_json, recipients_json, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(recipients_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.create_compound_pskb(ptr0, len0, ptr1, len1, fee_sompi, ptr2, len2);
    return ret;
}

/**
 * Consolidate all UTXOs into one
 * @param {string} wallet_json
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_consolidate_kspt(wallet_json, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.create_consolidate_kspt(ptr0, len0, fee_sompi, ptr1, len1);
    return ret;
}

/**
 * Consolidate all UTXOs into one via PSKB format.
 * @param {string} wallet_json
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_consolidate_pskb(wallet_json, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.create_consolidate_pskb(ptr0, len0, fee_sompi, ptr1, len1);
    return ret;
}

/**
 * Beneficiary signs (ELSE branch with CHECKSIGVERIFY).
 * Partial spend: withdraw_sompi goes to dest, remainder goes back to covenant.
 * CSV sequence enforced on the covenant input.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} withdraw_sompi
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_allowance_withdraw(covenant_address, dest_address, redeem_script_hex, withdraw_sompi, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_allowance_withdraw(ptr0, len0, ptr1, len1, ptr2, len2, withdraw_sompi, fee, ptr3, len3);
    return ret;
}

/**
 * Create a PSKB to claim an atomic swap covenant (counterparty reveals preimage).
 * The preimage is stored in proprietaries.atomicPreimage so the finalization
 * can include it in the sig_script.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} preimage_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_atomic_claim(covenant_address, dest_address, redeem_script_hex, preimage_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(preimage_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_atomic_claim(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, fee, ptr4, len4);
    return ret;
}

/**
 * Create a PSKB for a beneficiary spend on a time-locked vault covenant.
 * The TX locktime is set to the vault's locktime_daa so the node
 * enforces the time gate via OP_CHECKLOCKTIMEVERIFY in the script.
 * The beneficiary provides a signature; no owner signature needed.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} locktime_daa
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_beneficiary_spend(covenant_address, dest_address, redeem_script_hex, locktime_daa, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_beneficiary_spend(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, fee, ptr3, len3);
    return ret;
}

/**
 * Like `create_covenant_beneficiary_spend`, but sweeps only the caller-selected
 * UTXOs (so a vault/DMS funded with many UTXOs can be claimed in batches, e.g.
 * to keep the QR within KasSigner's frame limit). utxos_json: JSON array of
 * {tx_id, index, amount}. locktime_daa: CLTV unlock (0 for CSV/DMS).
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} locktime_daa
 * @param {string} utxos_json
 * @param {bigint} fee
 * @returns {string}
 */
export function create_covenant_beneficiary_spend_selected(covenant_address, dest_address, redeem_script_hex, locktime_daa, utxos_json, fee) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.create_covenant_beneficiary_spend_selected(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3, fee);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * No signature needed — the introspection opcodes enforce the rules.
 * The transaction spends the covenant UTXO and sends it back to the
 * SAME covenant address with at least (original amount + threshold) sompi.
 * Additional funds come from the borrower's regular P2PK UTXOs.
 *
 * borrower_wallet_json: the borrower's wallet (for funding UTXOs)
 * covenant_address: the P2SH covenant address
 * redeem_script_hex: the covenant redeem script
 * add_amount_sompi: how much extra to add (must be >= threshold)
 * fee: fee in sompi
 * @param {string} borrower_wallet_json
 * @param {string} covenant_address
 * @param {string} redeem_script_hex
 * @param {bigint} add_amount_sompi
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_borrower_spend(borrower_wallet_json, covenant_address, redeem_script_hex, add_amount_sompi, fee, ws_url) {
    const ptr0 = passStringToWasm0(borrower_wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_borrower_spend(ptr0, len0, ptr1, len1, ptr2, len2, add_amount_sompi, fee, ptr3, len3);
    return ret;
}

/**
 * Create a PSKB for a borrower WITHDRAWAL from a spending-limit covenant.
 * The borrower takes up to max_withdraw sompi. Output[0] returns the remainder
 * to the same covenant address. Output[1] is the borrower's withdrawal.
 * No covenant signature — introspection opcodes enforce the cap.
 * The borrower's P2PK funding input covers the fee.
 * @param {string} borrower_wallet_json
 * @param {string} covenant_address
 * @param {string} redeem_script_hex
 * @param {bigint} withdraw_sompi
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_borrower_withdraw(borrower_wallet_json, covenant_address, redeem_script_hex, withdraw_sompi, fee, ws_url) {
    const ptr0 = passStringToWasm0(borrower_wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_borrower_withdraw(ptr0, len0, ptr1, len1, ptr2, len2, withdraw_sompi, fee, ptr3, len3);
    return ret;
}

/**
 * Create a PSKB for an oracle-gated claim (beneficiary spend with oracle attestation).
 *
 * The oracle signature and message hash are stored in proprietaries so
 * finalization can include them in the sig_script.
 *
 * Sig_script: <oracle_sig> <msg_hash> <bene_sig> OP_FALSE <redeem>
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} oracle_sig_hex
 * @param {string} msg_hash_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_oracle_claim(covenant_address, dest_address, redeem_script_hex, oracle_sig_hex, msg_hash_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(oracle_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_oracle_claim(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, fee, ptr5, len5);
    return ret;
}

/**
 * Create a PSKB to spend a covenant UTXO via the owner path.
 * covenant_address: the P2SH covenant address (kaspatest:pz...)
 * dest_address: where to send the funds
 * redeem_script_hex: the covenant redeem script
 * fee: fee in sompi
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @param {string} covenant_branch
 * @returns {Promise<string>}
 */
export function create_covenant_owner_spend(covenant_address, dest_address, redeem_script_hex, fee, ws_url, covenant_branch) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(covenant_branch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_owner_spend(ptr0, len0, ptr1, len1, ptr2, len2, fee, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Create a PSKB for an owner spend using specific UTXOs (for consolidation).
 * utxos_json: JSON array of {tx_id, index, amount} objects (selected UTXOs).
 * dest_address: where to send (covenant address for consolidation, personal address for withdrawal).
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} utxos_json
 * @param {bigint} fee
 * @param {string} covenant_branch
 * @returns {string}
 */
export function create_covenant_owner_spend_selected(covenant_address, dest_address, redeem_script_hex, utxos_json, fee, covenant_branch) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(covenant_branch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.create_covenant_owner_spend_selected(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, fee, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Create a PSKB for a PayJoin covenant claim (beneficiary spend).
 *
 * The TX must include the caller's own UTXOs alongside the covenant UTXO
 * to satisfy the min_inputs and different-address requirements.
 *
 * `extra_utxo_address` is the caller's own address — its UTXOs will be
 * added as additional inputs to meet the PayJoin requirements.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} extra_utxo_address
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_payjoin_claim(covenant_address, dest_address, redeem_script_hex, extra_utxo_address, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(extra_utxo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_payjoin_claim(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, fee, ptr4, len4);
    return ret;
}

/**
 * Build a PSKB for a covenant genesis TX (wallet -> covenant P2SH).
 *
 * The PSKB includes covenant binding data so KasSigner computes the
 * correct sighash for TX version 1. After KasSigner signs, KasSee
 * extracts the signature and broadcasts with output v2 + covenant binding.
 *
 * Returns: PSKB hex string for QR display
 * @param {string} wallet_json
 * @param {string} covenant_address
 * @param {bigint} send_amount
 * @param {bigint} fee
 * @param {string} change_address
 * @param {string} _covenant_id_hex
 * @param {string} utxo_indices_csv
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_pskb(wallet_json, covenant_address, send_amount, fee, change_address, _covenant_id_hex, utxo_indices_csv, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(_covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(utxo_indices_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_pskb(ptr0, len0, ptr1, len1, send_amount, fee, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * Same as `create_covenant_pskb` but includes a TX payload.
 * Used for crowdfund campaign deposits where the VK is embedded in the payload.
 * @param {string} wallet_json
 * @param {string} covenant_address
 * @param {bigint} send_amount
 * @param {bigint} fee
 * @param {string} change_address
 * @param {string} payload_hex
 * @param {string} utxo_indices_csv
 * @param {string} ws_url
 * @param {boolean} tag_genesis
 * @returns {Promise<string>}
 */
export function create_covenant_pskb_with_payload(wallet_json, covenant_address, send_amount, fee, change_address, payload_hex, utxo_indices_csv, ws_url, tag_genesis) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(payload_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(utxo_indices_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_pskb_with_payload(ptr0, len0, ptr1, len1, send_amount, fee, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, tag_genesis);
    return ret;
}

/**
 * Create a PSKB to CLAIM a time-locked savings covenant (full sweep).
 *
 * Valid only after the date: the script's OP_CHECKLOCKTIMEVERIFY and the
 * node's locktime finality both gate on `locktime_daa`, which is set as the
 * TX locktime here. Sweeps every UTXO at the address to `dest_address`
 * minus `fee`. Either wallet can sign: the finalizer auto-detects the
 * signer's branch (wallet1 -> OP_IF, wallet2 -> OP_ELSE) by matching the
 * signer's pubkey, so this one builder serves the primary and the recovery
 * wallet alike. covenantBranch is left neutral ("savings") so the generic
 * covenant finalizer path runs and the selector is chosen by pubkey.
 *
 * Savings is CLTV-only (no CSV), so the gate rides entirely on the TX
 * locktime. For a vault funded with many UTXOs, a batched variant can be
 * added later (mirroring create_covenant_beneficiary_spend_selected).
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} locktime_daa
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_timelocked_savings_claim(covenant_address, dest_address, redeem_script_hex, locktime_daa, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_timelocked_savings_claim(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, fee, ptr3, len3);
    return ret;
}

/**
 * Create a PSKB to CLAIM a time-locked savings covenant from a CHOSEN subset
 * of UTXOs, for batching when the address holds too many to sweep in one TX.
 * utxos_json: JSON array of {tx_id, index, amount}. Either wallet signs; the
 * finalizer auto-detects the branch by the signer's pubkey. covenantBranch is
 * neutral ("savings"). Savings is CLTV-only, so the TX locktime carries the gate.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} locktime_daa
 * @param {string} utxos_json
 * @param {bigint} fee
 * @returns {string}
 */
export function create_covenant_timelocked_savings_claim_selected(covenant_address, dest_address, redeem_script_hex, locktime_daa, utxos_json, fee) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.create_covenant_timelocked_savings_claim_selected(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, ptr3, len3, fee);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Create a PSKB for a timeout refund on a time-locked escrow.
 * No signature needed — the CLTV branch has no CHECKSIG.
 * TX locktime is set to locktime_daa; output must go to Alice's address.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {bigint} locktime_daa
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_covenant_timeout_refund(covenant_address, dest_address, redeem_script_hex, locktime_daa, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_covenant_timeout_refund(ptr0, len0, ptr1, len1, ptr2, len2, locktime_daa, fee, ptr3, len3);
    return ret;
}

/**
 * Sweep a single crowdfund contributor UTXO using a ZK proof.
 *
 * No owner signature needed. The sig_script contains:
 *   <public_input> <1> <proof> <vk> OP_FALSE <redeem>
 *
 * The ZK proof proves that total contributions sum to S.
 * The on-chain script verifies the VK hash and the proof.
 * @param {string} contributor_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} proof_hex
 * @param {string} public_input_hex
 * @param {string} vk_hex
 * @param {string} commitment_sig_hex
 * @param {string} commitment_msg_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_crowdfund_sweep(contributor_address, dest_address, redeem_script_hex, proof_hex, public_input_hex, vk_hex, commitment_sig_hex, commitment_msg_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(contributor_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(proof_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(public_input_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(vk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(commitment_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ptr7 = passStringToWasm0(commitment_msg_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len7 = WASM_VECTOR_LEN;
    const ptr8 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len8 = WASM_VECTOR_LEN;
    const ret = wasm.create_crowdfund_sweep(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, fee, ptr8, len8);
    return ret;
}

/**
 * Create a PSKB that TOPS UP the GLOBAL ALLOWANCE thread (OWNER adds funds).
 *
 * Mirrors `create_global_spending_limit_topup`. The owner spends the thread
 * UTXO through the free top-level OWNER path (`covenantBranch` = "owner", the
 * finalizer emits the OP_TRUE selector) together with selected wallet UTXOs,
 * folding everything into ONE tagged continuation that preserves the single
 * thread id (G). The owner path is uncapped, so any amount can be added. The
 * beneficiary's per-spend cap and cooldown continue to apply to future
 * withdrawals from the enlarged thread.
 *
 * `thread_utxo_json`: the single thread UTXO, { "tx_id", "index", "amount" }
 * `utxo_indices_csv`: indices (into the sorted wallet UTXO list) to fold in.
 * @param {string} wallet_json
 * @param {string} covenant_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {string} thread_utxo_json
 * @param {bigint} fee
 * @param {string} utxo_indices_csv
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_global_allowance_topup(wallet_json, covenant_address, redeem_script_hex, covenant_id_hex, thread_utxo_json, fee, utxo_indices_csv, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(thread_utxo_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(utxo_indices_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.create_global_allowance_topup(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, fee, ptr5, len5, ptr6, len6);
    return ret;
}

/**
 * Create a PSKB for a BENEFICIARY withdrawal from a GLOBAL ALLOWANCE thread.
 *
 * Mirrors `create_global_spending_limit_withdraw`, with two differences:
 *   1. The spend takes the beneficiary ELSE branch, so `covenantBranch` is
 *      "beneficiary" (the finalizer emits the OP_FALSE selector). The firmware
 *      signs with the beneficiary's active seed (candidate 1 in the script).
 *   2. If the script carries a vesting start date (CLTV), `fallbackLockTime`
 *      is set to it so the TX clears OP_CHECKLOCKTIMEVERIFY.
 *
 * The thread is a single tagged UTXO. A normal withdrawal continues the thread
 * (one tagged continuation back to the covenant, amount >= input - max). A
 * close takes the whole balance with no continuation, allowed by the script
 * only when balance <= cap.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {bigint} withdraw_sompi
 * @param {bigint} fee
 * @param {string} selected_utxos_json
 * @returns {Promise<string>}
 */
export function create_global_allowance_withdraw(covenant_address, dest_address, redeem_script_hex, covenant_id_hex, withdraw_sompi, fee, selected_utxos_json) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(selected_utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_global_allowance_withdraw(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, withdraw_sompi, fee, ptr4, len4);
    return ret;
}

/**
 * Create a PSKB that TOPS UP / consolidates the GLOBAL spending-limit thread.
 *
 * Folds selected wallet UTXOs into the single covenant_id thread by spending
 * the thread UTXO together with those wallet UTXOs into ONE tagged continuation:
 *   inputs:  [thread UTXO (P2SH, owner-signed)] + [selected wallet UTXOs (P2PK)]
 *   output:  [continuation back to covenant, tagged with the thread's id (G)]
 * Exactly one tagged output, so the single thread is preserved. The selected
 * wallet UTXOs are folded in whole (no change output). The thread's CSV
 * cooldown applies to this spend, so the thread UTXO must be mature.
 *
 * The firmware signs the mixed inputs per type in one pass: the thread input
 * is P2SH (redeem script + owner key), the wallet inputs are P2PK.
 *
 * `thread_utxo_json`: the single thread UTXO, { "tx_id", "index", "amount" }
 * `utxo_indices_csv`: indices (into the sorted wallet UTXO list) to fold in.
 * @param {string} wallet_json
 * @param {string} covenant_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {string} thread_utxo_json
 * @param {bigint} fee
 * @param {string} utxo_indices_csv
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_global_spending_limit_topup(wallet_json, covenant_address, redeem_script_hex, covenant_id_hex, thread_utxo_json, fee, utxo_indices_csv, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(thread_utxo_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(utxo_indices_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.create_global_spending_limit_topup(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, fee, ptr5, len5, ptr6, len6);
    return ret;
}

/**
 * Create a PSKB for a GLOBAL spending-limit withdrawal (single covenant_id thread).
 *
 * Spends THE thread UTXO and continues the thread as exactly ONE tagged output
 * back to the covenant address:
 *   [0] continuation back to covenant (tagged)
 *   [1] withdrawal to dest (fee deducted from the withdrawal)
 * If the whole balance fits under the cap you may close the thread instead
 * (single output to dest, no continuation); the script enforces balance <= cap.
 *
 * The continuation `covenantId` must equal the thread's OWN covenant id (G),
 * so the spend is a true continuation: the script counts outputs tagged with
 * the input's id via OP_INPUT_COVENANT_ID + OP_COV_OUTPUT_COUNT. The UI passes
 * G (read from the thread UTXO). `authorizingInput` points at the thread (0).
 *
 * `selected_utxos_json`: JSON array with the single thread UTXO,
 *   [{ "tx_id", "index", "amount", "block_daa_score" }]
 * The node enforces the CSV cooldown on the input; this builder sets the input
 * sequence to the script's CSV value.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {bigint} withdraw_sompi
 * @param {bigint} fee
 * @param {string} selected_utxos_json
 * @returns {Promise<string>}
 */
export function create_global_spending_limit_withdraw(covenant_address, dest_address, redeem_script_hex, covenant_id_hex, withdraw_sompi, fee, selected_utxos_json) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(selected_utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_global_spending_limit_withdraw(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, withdraw_sompi, fee, ptr4, len4);
    return ret;
}

/**
 * Create a PSKB for spending a merkle whitelist vault to a proven address.
 * @param {string} covenant_address
 * @param {string} dest_address
 * @param {string} redeem_script_hex
 * @param {string} proof_json
 * @param {bigint} send_amount
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_merkle_whitelist_spend(covenant_address, dest_address, redeem_script_hex, proof_json, send_amount, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_merkle_whitelist_spend(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, send_amount, fee, ptr4, len4);
    return ret;
}

/**
 * Create unsigned multisig spend KSPT
 * descriptor: "multi(2,pk1hex,...)" or "multi_hd(2,xpub130hex,...)"
 * addr_index: HD derivation index (0 for legacy multi(...) descriptors)
 * source_address: the P2SH multisig address holding the funds
 * change_address: where change goes (typically same P2SH address)
 * @param {string} descriptor
 * @param {string} source_address
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} change_address
 * @param {string} ws_url
 * @param {number} addr_index
 * @returns {Promise<string>}
 */
export function create_multisig_kspt(descriptor, source_address, dest_address, amount_sompi, fee_sompi, change_address, ws_url, addr_index) {
    const ptr0 = passStringToWasm0(descriptor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(source_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_multisig_kspt(ptr0, len0, ptr1, len1, ptr2, len2, amount_sompi, fee_sompi, ptr3, len3, ptr4, len4, addr_index);
    return ret;
}

/**
 * Build an unsigned multisig PSKB — Path 2. Same semantics as
 * `create_multisig_kspt` but emits a Kaspa-standard PSKB wire blob
 * instead of legacy KSPT v1 binary.
 *
 * The output goes directly to `openPsktReview` on the JS side,
 * landing the user on the Review PSKB screen with 0/M sigs where
 * they can pick Relay → (Any wallet | KasSigner compact).
 * @param {string} descriptor
 * @param {string} source_address
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} change_address
 * @param {string} ws_url
 * @param {number} addr_index
 * @returns {Promise<string>}
 */
export function create_multisig_pskb(descriptor, source_address, dest_address, amount_sompi, fee_sompi, change_address, ws_url, addr_index) {
    const ptr0 = passStringToWasm0(descriptor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(source_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_multisig_pskb(ptr0, len0, ptr1, len1, ptr2, len2, amount_sompi, fee_sompi, ptr3, len3, ptr4, len4, addr_index);
    return ret;
}

/**
 * Same as `create_multisig_pskb` but with explicit UTXO indices
 * instead of greedy auto-selection.
 * @param {string} descriptor
 * @param {string} source_address
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} change_address
 * @param {string} ws_url
 * @param {number} addr_index
 * @param {string} utxo_csv
 * @returns {Promise<string>}
 */
export function create_multisig_pskb_selected(descriptor, source_address, dest_address, amount_sompi, fee_sompi, change_address, ws_url, addr_index, utxo_csv) {
    const ptr0 = passStringToWasm0(descriptor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(source_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(utxo_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.create_multisig_pskb_selected(ptr0, len0, ptr1, len1, ptr2, len2, amount_sompi, fee_sompi, ptr3, len3, ptr4, len4, addr_index, ptr5, len5);
    return ret;
}

/**
 * Oracle attestation beacon for the SIMPLE oracle covenant (`build_oracle_covenant_script`),
 * distinct from the Model B (price) oracle. Spends the covenant UTXO(s) down Path 3
 * (the inner ELSE: `<oracle> CHECKSIGVERIFY` + self-return introspection) and returns
 * the funds to the SAME covenant address, carrying the oracle's off-chain attestation
 * in the TX payload so the beneficiary's watcher can read it and claim via Path 2.
 *
 * MUST be tx_version=1: Path 3 enforces `INPUT_SPK == OUTPUT_SPK[0]` via covenant
 * introspection, which only executes on v1 transactions. (The original builder emitted
 * v0, which could not run that check at all — that, not any "singleton" rule, is why it
 * failed; this simple oracle has no covenant_id and no singleton enforcement.)
 *
 * Payload layout (what the KasSee watcher parses): "ORAC" (0x4f524143)
 * || attestation_sig (64B Schnorr over `msg_hash`) || msg_hash (32B) || optional UTF-8 text.
 * `oracle_sig_hex`/`msg_hash_hex` are the attestation cargo; the beacon-TX signature is
 * produced by KasSigner and assembled into the Path-3 sig_script by the finalizer
 * (covenantBranch = "oracle-heartbeat").
 * @param {string} covenant_address
 * @param {string} redeem_script_hex
 * @param {string} oracle_sig_hex
 * @param {string} msg_hash_hex
 * @param {string} attest_text
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_oracle_heartbeat(covenant_address, redeem_script_hex, oracle_sig_hex, msg_hash_hex, attest_text, fee, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(oracle_sig_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(msg_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(attest_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.create_oracle_heartbeat(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, fee, ptr5, len5);
    return ret;
}

/**
 * Oracle (Model B) CONSUME: read price + T from the genuine oracle lineage,
 * recreate the oracle singleton (passthrough), and release the consumer to
 * `dest_address`. 2-input (consumer + oracle), no heartbeat. Returns the "PSKB"
 * wire (hex) for pskt_finalize_and_broadcast.
 * @param {string} consumer_address
 * @param {string} consumer_redeem_hex
 * @param {string} oracle_address
 * @param {string} oracle_redeem_hex
 * @param {string} oracle_covenant_id_hex
 * @param {string} dest_address
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_oracle_mb_consume(consumer_address, consumer_redeem_hex, oracle_address, oracle_redeem_hex, oracle_covenant_id_hex, dest_address, fee, ws_url) {
    const ptr0 = passStringToWasm0(consumer_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(consumer_redeem_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(oracle_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(oracle_redeem_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(oracle_covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.create_oracle_mb_consume(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, fee, ptr6, len6);
    return ret;
}

/**
 * Oracle (Model B) HEARTBEAT roll: refresh the heartbeat's DAA by recreating
 * the singleton at the same redeem/SPK, tagged with the same covenant_id
 * (continuation). Fee taken from the heartbeat value.
 *
 * Returns the "PSKB" wire (hex) for pskt_finalize_and_broadcast.
 * @param {string} heartbeat_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {bigint} fee
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_oracle_mb_heartbeat_roll(heartbeat_address, redeem_script_hex, covenant_id_hex, fee, ws_url) {
    const ptr0 = passStringToWasm0(heartbeat_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_oracle_mb_heartbeat_roll(ptr0, len0, ptr1, len1, ptr2, len2, fee, ptr3, len3);
    return ret;
}

/**
 * Oracle (Model B) PUBLISH: advance the oracle to the price proven in `journal`.
 *
 * Spends the singleton oracle UTXO at `oracle_address` (revealing
 * `redeem_script_hex`, priced at the OLD price) and recreates the oracle UTXO at
 * the NEW price/T read from `journal`, tagged with the SAME covenant_id
 * (continuation). The keyless ROLL branch carries the RISC0 proof
 * (seal + claim + control_index + control_digests + journal); image_id /
 * control_id / set_root / hashfn are committed in the redeem and consumed by
 * OP_ZK_PRECOMPILE from there.
 *
 * Returns the "PSKB" wire (hex) to hand to pskt_finalize_and_broadcast.
 * @param {string} wallet_json
 * @param {string} oracle_address
 * @param {string} redeem_script_hex
 * @param {string} covenant_id_hex
 * @param {string} heartbeat_cov_id_hex
 * @param {string} image_id_hex
 * @param {string} control_id_hex
 * @param {string} set_root_hex
 * @param {string} hashfn_hex
 * @param {string} seal_hex
 * @param {string} claim_hex
 * @param {string} control_index_hex
 * @param {string} control_digests_hex
 * @param {string} journal_hex
 * @param {bigint} fee
 * @param {string} change_address
 * @param {string} network
 * @param {string} ws_url
 * @param {boolean} omit_heartbeat
 * @returns {Promise<string>}
 */
export function create_oracle_mb_publish(wallet_json, oracle_address, redeem_script_hex, covenant_id_hex, heartbeat_cov_id_hex, image_id_hex, control_id_hex, set_root_hex, hashfn_hex, seal_hex, claim_hex, control_index_hex, control_digests_hex, journal_hex, fee, change_address, network, ws_url, omit_heartbeat) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(oracle_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(redeem_script_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(heartbeat_cov_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(image_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(control_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ptr7 = passStringToWasm0(set_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len7 = WASM_VECTOR_LEN;
    const ptr8 = passStringToWasm0(hashfn_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len8 = WASM_VECTOR_LEN;
    const ptr9 = passStringToWasm0(seal_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len9 = WASM_VECTOR_LEN;
    const ptr10 = passStringToWasm0(claim_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len10 = WASM_VECTOR_LEN;
    const ptr11 = passStringToWasm0(control_index_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len11 = WASM_VECTOR_LEN;
    const ptr12 = passStringToWasm0(control_digests_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len12 = WASM_VECTOR_LEN;
    const ptr13 = passStringToWasm0(journal_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len13 = WASM_VECTOR_LEN;
    const ptr14 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len14 = WASM_VECTOR_LEN;
    const ptr15 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len15 = WASM_VECTOR_LEN;
    const ptr16 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len16 = WASM_VECTOR_LEN;
    const ret = wasm.create_oracle_mb_publish(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, ptr9, len9, ptr10, len10, ptr11, len11, ptr12, len12, ptr13, len13, fee, ptr14, len14, ptr15, len15, ptr16, len16, omit_heartbeat);
    return ret;
}

/**
 * Build unsigned KSPT from wallet, destination, amount, fee → return hex
 * @param {string} wallet_json
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_send_kspt(wallet_json, dest_address, amount_sompi, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.create_send_kspt(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2);
    return ret;
}

/**
 * Create unsigned KSPT with specific UTXO indices (comma-separated)
 * @param {string} wallet_json
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} utxo_indices_csv
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_send_kspt_selected(wallet_json, dest_address, amount_sompi, fee_sompi, utxo_indices_csv, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(utxo_indices_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_send_kspt_selected(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2, ptr3, len3);
    return ret;
}

/**
 * Create unsigned single-sig PSKB — same as `create_send_kspt` but
 * emits a standard PSKB wire blob. Routes through the PSKT review
 * screen on the JS side (same flow as multisig PSKB).
 * @param {string} wallet_json
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_send_pskb(wallet_json, dest_address, amount_sompi, fee_sompi, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.create_send_pskb(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2);
    return ret;
}

/**
 * Create unsigned PSKB with specific UTXO indices.
 * @param {string} wallet_json
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} utxo_csv
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_send_pskb_selected(wallet_json, dest_address, amount_sompi, fee_sompi, utxo_csv, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(utxo_csv, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_send_pskb_selected(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2, ptr3, len3);
    return ret;
}

/**
 * Create unsigned PSKB with explicit UTXO data (no re-fetch, no stale indices).
 * utxos_json: JSON array of {tx_id, index, amount, script_public_key, block_daa_score} objects.
 * @param {string} wallet_json
 * @param {string} dest_address
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} utxos_json
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function create_send_pskb_with_utxos(wallet_json, dest_address, amount_sompi, fee_sompi, utxos_json, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.create_send_pskb_with_utxos(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2, ptr3, len3);
    return ret;
}

/**
 * Create a PSKB for spending a stealth UTXO.
 * The PSKB includes the stealth tweak in proprietaries so the device
 * can derive the correct signing key (account_privkey + tweak).
 * @param {string} one_time_pubkey_hex
 * @param {string} tweak_hex
 * @param {string} dest_address
 * @param {bigint} fee
 * @param {string} ws_url
 * @param {string} network
 * @returns {Promise<string>}
 */
export function create_stealth_spend(one_time_pubkey_hex, tweak_hex, dest_address, fee, ws_url, network) {
    const ptr0 = passStringToWasm0(one_time_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tweak_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(dest_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.create_stealth_spend(ptr0, len0, ptr1, len1, ptr2, len2, fee, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Decode a Kaspa address → JSON { version, payload_hex }
 * @param {string} addr
 * @returns {string}
 */
export function decode_address(addr) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.decode_address(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Feed a scanned QR frame (hex). Returns complete KSPT hex when done, or empty string.
 * @param {string} frame_hex
 * @returns {string}
 */
export function decode_qr_frame(frame_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(frame_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.decode_qr_frame(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get decoder scan progress as JSON
 * @returns {string}
 */
export function decoder_progress() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.decoder_progress();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Derive the 32-byte AES-256 key used for encrypting covenant payloads.
 * Key = blake2b(chain_code || "covenant-payload-key"), where chain_code
 * is the 32-byte BIP32 chain code extracted from the kpub (bytes 13..45).
 * This key is deterministic from the seed (chain_code is derived from seed
 * via BIP32), so recovery only requires the seed -> kpub -> this key.
 * @param {string} kpub_str
 * @returns {string}
 */
export function derive_covenant_payload_key(kpub_str) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(kpub_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.derive_covenant_payload_key(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
 * Optional network parameter (defaults to mainnet)
 * @param {string} pubkey_hex
 * @param {string | null} [network]
 * @returns {string}
 */
export function encode_p2pk_address(pubkey_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.encode_p2pk_address(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Encode a 32-byte script hash (hex) as a Kaspa P2SH address
 * @param {string} script_hash_hex
 * @param {string | null} [network]
 * @returns {string}
 */
export function encode_p2sh_address(script_hash_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(script_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.encode_p2sh_address(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Derive additional receive/change addresses beyond the current set.
 * @param {string} wallet_json
 * @param {number} extra_receive
 * @param {number} extra_change
 * @param {string} network
 * @returns {string}
 */
export function extend_addresses(wallet_json, extra_receive, extra_change, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.extend_addresses(ptr0, len0, extra_receive, extra_change, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Connect to node via Borsh wRPC, fetch UTXOs, return JSON balance.
 * @param {string} wallet_json
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function fetch_balance(wallet_json, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.fetch_balance(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Fetch all UTXOs as JSON array
 * @param {string} wallet_json
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function fetch_utxos(wallet_json, ws_url) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.fetch_utxos(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Fetch UTXOs for a single address (for multisig balance check) → JSON array
 * @param {string} address
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function fetch_utxos_for_address_js(address, ws_url) {
    const ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.fetch_utxos_for_address_js(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Search mempool for a TX that spent a specific UTXO and extract
 * the preimage from its sig_script. Used by the atomic swap watcher.
 *
 * Returns hex-encoded preimage if found, empty string if not found.
 * @param {string} outpoint_txid_hex
 * @param {string} covenant_address
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function find_preimage_for_utxo(outpoint_txid_hex, covenant_address, ws_url) {
    const ptr0 = passStringToWasm0(outpoint_txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.find_preimage_for_utxo(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Search a specific block (by hash hex) for a TX that spent the given outpoint.
 * Returns hex-encoded preimage if found, empty string if not.
 * @param {string} block_hash_hex
 * @param {string} outpoint_txid_hex
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function find_preimage_in_block(block_hash_hex, outpoint_txid_hex, ws_url) {
    const ptr0 = passStringToWasm0(block_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(outpoint_txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.find_preimage_in_block(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Generate QR frames (SVG strings) for a KSPT hex → return JSON array
 * @param {string} kspt_hex
 * @returns {string}
 */
export function generate_qr_frames(kspt_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(kspt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.generate_qr_frames(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate a single QR code SVG from a plain UTF-8 string.
 * No framing, no hex encoding. Used for swap invites and data exchange.
 * @param {string} text
 * @returns {string}
 */
export function generate_qr_svg_text(text) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.generate_qr_svg_text(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Query node for current fee rates → return JSON
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function get_fee_estimate(ws_url) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.get_fee_estimate(ptr0, len0);
    return ret;
}

/**
 * Fetch a Seq-Commit lane proof (op 153) for `lane_key_hex` against `block_hash_hex` (a
 * selected-parent-chain block). Pass "" for block_hash to use the current sink. Returns a JS
 * object; `raw_hex` is authoritative, the parsed fields are best-effort (the lane Option wrapper).
 * @param {string} ws_url
 * @param {string} block_hash_hex
 * @param {string} lane_key_hex
 * @returns {Promise<any>}
 */
export function get_seq_commit_lane_proof(ws_url, block_hash_hex, lane_key_hex) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(block_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(lane_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.get_seq_commit_lane_proof(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Get the current virtual DAA score from the node.
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function get_virtual_daa_score(ws_url) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.get_virtual_daa_score(ptr0, len0);
    return ret;
}

/**
 * Import a kpub string + network → derive 20 receive + 20 change addresses → return JSON
 * @param {string} kpub_str
 * @param {string} network
 * @returns {string}
 */
export function import_kpub(kpub_str, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(kpub_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.import_kpub(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Import a V1-raw compact kpub (78 raw payload bytes — the header
 * byte 0x01 should already be stripped by the JS side). Same output
 * as `import_kpub` — the raw payload is re-encoded to a standard
 * base58check kpub internally so all downstream paths (storage, UI,
 * RPC) are unchanged.
 * @param {Uint8Array} raw_payload
 * @param {string} network
 * @returns {string}
 */
export function import_kpub_raw(raw_payload, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(raw_payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.import_kpub_raw(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

export function init() {
    wasm.init();
}

/**
 * Generate a merkle proof for a specific address.
 * Returns JSON: { proof: [{sibling, direction}], leaf_spk_hex }
 * @param {string} addresses_json
 * @param {string} target_address
 * @returns {string}
 */
export function merkle_proof_for_address(addresses_json, target_address) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(addresses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(target_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.merkle_proof_for_address(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Compute merkle root from a JSON array of SPK hex strings.
 * Returns hex of the 32-byte root.
 * @param {string} addresses_json
 * @param {string} _network
 * @returns {string}
 */
export function merkle_root_from_addresses(addresses_json, _network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(addresses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(_network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.merkle_root_from_addresses(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Parse a decrypted covenant payload blob: [version:1][type:1][params...]
 * Returns JSON: { "version": 1, "covenant_type": N, "params_hex": "..." }
 * @param {string} plaintext_hex
 * @returns {string}
 */
export function parse_covenant_payload(plaintext_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parse_covenant_payload(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse a kpub (extended public key) and extract the account-level xonly pubkey.
 * Returns JSON: { "account_pubkey": "64-char hex xonly" }
 * @param {string} kpub_str
 * @returns {string}
 */
export function parse_kpub(kpub_str) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(kpub_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parse_kpub(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Inspect a hex payload (output of the multi-frame QR decoder) and
 * return the detected format as a short string: "pskb", "pskt", or
 * "unknown". JS uses this to route a decoded payload to either the
 * PSKT review screen (this module) or the legacy KSPT flow.
 * @param {string} wire_hex
 * @returns {string}
 */
export function pskt_detect(wire_hex) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pskt_detect(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * PSKT-native finalize + broadcast. Walks the PSKB JSON once,
 * assembles a consensus Transaction directly (sig_scripts per input,
 * with partial sigs + redeem script for P2SH multisig), and submits
 * via Borsh wRPC. No KSPT intermediate format, no shim — PSKB JSON
 * in, Kaspa consensus transaction out, TX ID returned on acceptance.
 * @param {string} wire_hex
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function pskt_finalize_and_broadcast(wire_hex, ws_url) {
    const ptr0 = passStringToWasm0(wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.pskt_finalize_and_broadcast(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Finalize a fully-signed PSKT/PSKB into a signed KSPT v2 hex blob
 * that the existing `broadcast_signed` RPC path can consume directly.
 *
 * Fails if any multisig input lacks the required M signatures.
 * @param {string} wire_hex
 * @returns {string}
 */
export function pskt_finalize_to_kspt(wire_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pskt_finalize_to_kspt(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Inverse of `pskt_relay_to_kspt_v2`: merge the partial sigs from a
 * device-returned KSPT v2 blob into the canonical PSKB and return
 * the updated PSKB wire hex. Idempotent — existing sigs are not
 * clobbered.
 *
 * Accepts `flags = 0x00` (partial) and `flags = 0x01` (fully signed)
 * equally. Caller must still check whether the merged PSKB has ≥M
 * sigs before finalizing/broadcasting.
 * @param {string} signed_kspt_hex
 * @param {string} pskb_wire_hex
 * @returns {string}
 */
export function pskt_merge_signed_kspt_v2(signed_kspt_hex, pskb_wire_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(signed_kspt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pskb_wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.pskt_merge_signed_kspt_v2(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Re-emit a PSKB/PSKT as a KSPT v2 "partial" hex blob for relay to
 * KasSigner over QR. Does NOT require M sigs — accepts 0..=N partial
 * sigs per input. Flags byte = 0x00 (partial).
 *
 * The mainnet-verified `pskt_finalize_to_kspt` path is not touched:
 * this is a sibling function that shares no mutable state with it.
 * @param {string} wire_hex
 * @returns {string}
 */
export function pskt_relay_to_kspt_v2(wire_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pskt_relay_to_kspt_v2(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse a PSKT/PSKB payload into a review summary (JSON string).
 *
 * `network` is one of "mainnet", "testnet-10/11/12", "simnet",
 * "devnet" — used to format decoded output addresses for display.
 * @param {string} wire_hex
 * @param {string} network
 * @returns {string}
 */
export function pskt_summary(wire_hex, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(wire_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.pskt_summary(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Reset multi-frame decoder state
 */
export function reset_qr_decoder() {
    wasm.reset_qr_decoder();
}

/**
 * Derive x-only pubkey from a 32-byte secret key hex.
 * Returns 32-byte x-only pubkey hex.
 * @param {string} secret_key_hex
 * @returns {string}
 */
export function schnorr_derive_pubkey(secret_key_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.schnorr_derive_pubkey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate an ephemeral BIP340 keypair and sign a message hash.
 * For testing dual-gate ZK sweep without KaSigner firmware support.
 * Returns JSON: { pubkey_hex (32-byte x-only), signature_hex (64-byte), msg_hex }
 * @param {string} msg_hex
 * @returns {string}
 */
export function schnorr_sign_ephemeral(msg_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(msg_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.schnorr_sign_ephemeral(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Sign a message hash with a known secret key (hex).
 * For testing with a persistent ephemeral key across multiple sweeps.
 * Returns JSON: { signature_hex (64-byte), verified }
 * @param {string} secret_key_hex
 * @param {string} msg_hex
 * @returns {string}
 */
export function schnorr_sign_with_key(secret_key_hex, msg_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(msg_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.schnorr_sign_with_key(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * SMT key for a lane: BLAKE3 keyed (key = b"SeqCommitLaneKey" padded to 32 bytes) over subnetwork_id[20].
 * `subnetwork_id_hex` is 20 bytes (40 hex chars). The "KST1" lane = 4b53543100..00 (4 ASCII + 16 zeros).
 * Verified against the node: lane_key(SUBNETWORK_ID_COINBASE) == COINBASE_LANE_KEY (8aa78027..b9e4).
 * @param {string} subnetwork_id_hex
 * @returns {string}
 */
export function seq_commit_lane_key(subnetwork_id_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(subnetwork_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.seq_commit_lane_key(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Compute SHA-256 hash of the input bytes (hex in, hex out).
 * Used for cross-chain atomic swap expected hash computation.
 * @param {string} input_hex
 * @returns {string}
 */
export function sha256_hash(input_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(input_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sha256_hash(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Fund a Split Vault covenant with a genesis TX (creates covenant_id).
 * Same flow as tagged_vault_genesis but uses the split vault script.
 * Returns JSON: { txid, covenant_id_hex, covenant_address }
 * @param {string} ephemeral_address
 * @param {string} secret_key_hex
 * @param {string} owner_pubkey_hex
 * @param {bigint} send_amount
 * @param {bigint} fee
 * @param {string} network
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function split_vault_genesis(ephemeral_address, secret_key_hex, owner_pubkey_hex, send_amount, fee, network, ws_url) {
    const ptr0 = passStringToWasm0(ephemeral_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.split_vault_genesis(ptr0, len0, ptr1, len1, ptr2, len2, send_amount, fee, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Split a covenant UTXO into two outputs, both carrying the same covenant_id.
 * The split vault script enforces AUTH_OUTPUT_COUNT==2 and COV_OUTPUT_COUNT==2.
 *
 * Returns JSON: { txid, covenant_id_hex, amount_a, amount_b }
 * @param {string} covenant_address
 * @param {string} secret_key_hex
 * @param {string} owner_pubkey_hex
 * @param {string} covenant_id_hex
 * @param {bigint} fee
 * @param {string} network
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function split_vault_spend(covenant_address, secret_key_hex, owner_pubkey_hex, covenant_id_hex, fee, network, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.split_vault_spend(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, fee, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * Phase 1 (KSTL stealth lane) — software-signed announcement probe.
 *
 * Builds, signs, and broadcasts a stealth payment on the dedicated KSTL
 * seq-commit lane: subnetwork = b"KSTL" + 16 zero bytes (4b53544c00..00, a
 * valid user lane — bytes 0..4 nonzero, 16-byte zero tail), tx_version = 1,
 * gas = 0. The tx pays the recipient's one-time P2PK output (+ change to the
 * sender) and carries the announcement payload `0x01 || R(32) || view_tag(1)`
 * (34 bytes). Because the tx is tagged to the KSTL lane, consensus folds its
 * tx_id into the lane tip, which is then complete and op-153-provable via
 * `seq_commit_lane_key("4b53544c" + 16 zero bytes)` + `get_seq_commit_lane_proof`.
 *
 * This is the SOFTWARE signer (hot key) used to validate lane behaviour on
 * TN10 without the air-gapped device in the loop. The sighash it signs
 * (`compute_sighash_v1_subnet`) is byte-identical to the firmware's
 * `calculate_sighash` for a v1 lane tx (same field order, sigOpCounts omitted
 * for version >= 1, explicit subnetwork_id + gas + payload_hash), so the
 * device path is validated by construction: same serialization, same sighash.
 *
 * - `sender_secret_hex`: 64 hex, the key controlling the funding UTXO (TEST hot key).
 * - `funding_txid_hex` / `funding_index` / `funding_amount`: the P2PK UTXO to spend.
 * - `meta_hex`: the recipient's 128-hex stealth meta-address.
 * - `amount_sompi`: value sent to the one-time P2PK output (must be > 0).
 * - `fee_sompi`: network fee. Change (funding - amount - fee) returns to the sender.
 * - `entropy_hex`: 64 hex of ephemeral randomness (window.crypto).
 * - `network`: "mainnet" / "testnet-10" etc. (for address display only).
 *
 * Returns JSON: { txid, one_time_address, ephemeral_r, view_tag, subnetwork_hex, lane_key }.
 * @param {string} ws_url
 * @param {string} sender_secret_hex
 * @param {string} funding_txid_hex
 * @param {number} funding_index
 * @param {bigint} funding_amount
 * @param {string} meta_hex
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} entropy_hex
 * @param {string} network
 * @param {bigint} lane_gas
 * @returns {Promise<string>}
 */
export function stealth_announce_lane_probe(ws_url, sender_secret_hex, funding_txid_hex, funding_index, funding_amount, meta_hex, amount_sompi, fee_sompi, entropy_hex, network, lane_gas) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(sender_secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(funding_txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(meta_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(entropy_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.stealth_announce_lane_probe(ptr0, len0, ptr1, len1, ptr2, len2, funding_index, funding_amount, ptr3, len3, amount_sompi, fee_sompi, ptr4, len4, ptr5, len5, lane_gas);
    return ret;
}

/**
 * Get the well-known stealth announcement address for a network.
 * @param {string} network
 * @returns {string}
 */
export function stealth_announcement_address(network) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.stealth_announcement_address(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Create a stealth PAYMENT: pay `amount_sompi` to a freshly derived one-time
 * address for the receiver's stealth meta-address, embedding the ephemeral R
 * in the transaction payload so the receiver can detect the payment on-chain.
 * No burn address, no dust output, no separate announcement tx.
 *
 * Payload layout: b"KST1" (4) || R (32, x-only) = 36 bytes. The firmware
 * sighash commits the payload, so the device signs over R, and
 * `finalize_and_broadcast` carries it to consensus. On Toccata the payload
 * costs ~36 compute + 144 transient mass, covered by the minimum fee.
 *
 * Returns JSON: { pskb_wire, address, ephemeral_r }
 * @param {string} wallet_json
 * @param {string} meta_hex
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} entropy_hex
 * @param {string} ws_url
 * @param {string} network
 * @returns {Promise<string>}
 */
export function stealth_create_payment(wallet_json, meta_hex, amount_sompi, fee_sompi, entropy_hex, ws_url, network) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(meta_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(entropy_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.stealth_create_payment(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Device-signed stealth payment on the KSTL seq-commit lane.
 *
 * Same as `stealth_create_payment`, but the PSKB is stamped onto subnetwork
 * KSTL (b"KSTL" + 16 zero bytes), tx_version 1, gas 0, and carries the
 * announcement payload `0x01 || R(32) || view_tag(1)` (34 bytes) instead of
 * the in-band `b"KST1" || R`. Coin selection and change come from the proven
 * `create_send_pskb` path; `set_tx_lane` then restamps the global.
 *
 * The device's `calculate_sighash` for a v1 tx commits subnetwork_id, gas, and
 * payload and omits sigOpCounts (firmware sighash.rs), so it is byte-identical
 * to `compute_sighash_v1_subnet` (what the software probe signs and the node
 * already accepts on TN10). The device signs that sighash and
 * `finalize_and_broadcast` emits the matching KSTL tx, so consensus folds its
 * tx_id into the lane tip.
 *
 * Returns JSON: { pskb_wire, address, ephemeral_r, view_tag }.
 * @param {string} wallet_json
 * @param {string} meta_hex
 * @param {bigint} amount_sompi
 * @param {bigint} fee_sompi
 * @param {string} entropy_hex
 * @param {string} ws_url
 * @param {string} network
 * @returns {Promise<string>}
 */
export function stealth_create_payment_lane(wallet_json, meta_hex, amount_sompi, fee_sompi, entropy_hex, ws_url, network) {
    const ptr0 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(meta_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(entropy_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.stealth_create_payment_lane(ptr0, len0, ptr1, len1, amount_sompi, fee_sompi, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Generate a stealth payment: derive one-time address + ephemeral R.
 * `meta_hex` is the 128-char stealth meta-address.
 * `entropy_hex` is 64 hex chars (32 bytes) of randomness from window.crypto.
 * `network` is "mainnet" or "testnet-12" etc.
 * Returns JSON: { address, ephemeral_r, stealth_index }
 * @param {string} meta_hex
 * @param {string} entropy_hex
 * @param {string} network
 * @returns {string}
 */
export function stealth_generate_payment(meta_hex, entropy_hex, network) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(meta_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(entropy_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.stealth_generate_payment(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Derive a stealth meta-address from a kpub string.
 * Returns JSON: { scan_pubkey: "hex", spend_pubkey: "hex", meta_address: "hex128" }
 * @param {string} kpub_str
 * @returns {string}
 */
export function stealth_meta_from_kpub(kpub_str) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(kpub_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.stealth_meta_from_kpub(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Scan a single announcement: given scan_privkey + spend_pubkey + ephemeral R,
 * derive the one-time pubkey the sender paid to.
 * Returns JSON: { one_time_pubkey, address, stealth_index, tweak }
 * @param {string} scan_privkey_hex
 * @param {string} spend_pubkey_hex
 * @param {string} ephemeral_r_hex
 * @param {string} network
 * @returns {string}
 */
export function stealth_scan_announcement(scan_privkey_hex, spend_pubkey_hex, ephemeral_r_hex, network) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(scan_privkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(spend_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(ephemeral_r_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.stealth_scan_announcement(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Historical catch-up: scan up to `max_blocks` recent blocks for stealth
 * payments and return a JSON array of 64-hex ephemeral R values. Pair with the
 * live BlockAdded scan to also recover payments received while offline.
 * @param {string} ws_url
 * @param {number} max_blocks
 * @returns {Promise<string>}
 */
export function stealth_scan_recent_blocks(ws_url, max_blocks) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.stealth_scan_recent_blocks(ptr0, len0, max_blocks);
    return ret;
}

/**
 * Compute a KIP-20 covenant_id for a genesis Tagged Vault TX.
 *
 * This must be called with the UTXO that will fund the covenant,
 * because the covenant_id is derived from the input outpoint.
 *
 * prev_txid_hex: 32-byte transaction ID of the funding UTXO (hex)
 * prev_index: output index of the funding UTXO
 * send_amount: amount in sompi for the covenant output
 * covenant_spk_hex: the P2SH script public key (hex)
 *
 * Returns JSON: { covenant_id_hex }
 * @param {string} prev_txid_hex
 * @param {number} prev_index
 * @param {bigint} send_amount
 * @param {string} covenant_spk_hex
 * @returns {string}
 */
export function tagged_vault_covenant_id(prev_txid_hex, prev_index, send_amount, covenant_spk_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(prev_txid_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(covenant_spk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.tagged_vault_covenant_id(ptr0, len0, prev_index, send_amount, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Fund an ephemeral address, create the covenant, and broadcast the genesis TX.
 *
 * This is the main entry point for the Tagged Vault PoC.
 * Steps:
 *   1. Fetch UTXOs at the ephemeral address
 *   2. Build and sign the genesis TX in WASM
 *   3. Broadcast
 *
 * Returns JSON: { txid, covenant_id_hex, covenant_address }
 * @param {string} ephemeral_address
 * @param {string} secret_key_hex
 * @param {string} owner_pubkey_hex
 * @param {bigint} send_amount
 * @param {bigint} fee
 * @param {string} network
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function tagged_vault_genesis(ephemeral_address, secret_key_hex, owner_pubkey_hex, send_amount, fee, network, ws_url) {
    const ptr0 = passStringToWasm0(ephemeral_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.tagged_vault_genesis(ptr0, len0, ptr1, len1, ptr2, len2, send_amount, fee, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Generate an ephemeral keypair for browser-signed Tagged Vault TXs.
 * Returns JSON: { secret_key_hex, pubkey_hex, address }
 * @param {string} network
 * @returns {string}
 */
export function tagged_vault_keygen(network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.tagged_vault_keygen(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Spend a Tagged Vault UTXO with covenant-ID continuity.
 *
 * The output carries the same covenant_id (continuation).
 * Signed in-browser with the owner's secret key.
 *
 * Returns JSON: { txid, covenant_id_hex }
 * @param {string} covenant_address
 * @param {string} secret_key_hex
 * @param {string} owner_pubkey_hex
 * @param {string} covenant_id_hex
 * @param {bigint} fee
 * @param {string} network
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function tagged_vault_spend(covenant_address, secret_key_hex, owner_pubkey_hex, covenant_id_hex, fee, network, ws_url) {
    const ptr0 = passStringToWasm0(covenant_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(secret_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(owner_pubkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(covenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.tagged_vault_spend(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, fee, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * Test function: GetSink + GetBlock(sink, include_transactions=true).
 * Call from browser console: await test_getblock("ws://localhost:17210")
 * Returns a summary string. If the node crashes, you'll know GetBlock is the culprit.
 * @param {string} ws_url
 * @returns {Promise<string>}
 */
export function test_getblock(ws_url) {
    const ptr0 = passStringToWasm0(ws_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.test_getblock(ptr0, len0);
    return ret;
}

/**
 * Version string
 * @returns {string}
 */
export function version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Generate a crowdfunding ZK proof.
 * `pk_hex`: proving key from setup
 * `amounts_json`: JSON array of u64 amounts in sompi, e.g. "[100000000, 200000000]"
 * Returns JSON: { proof_hex, public_input_hex, total_sompi, proof_len, verified }
 * @param {string} pk_hex
 * @param {string} vk_hex
 * @param {string} amounts_json
 * @returns {string}
 */
export function zk_crowdfund_prove(pk_hex, vk_hex, amounts_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(vk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(amounts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.zk_crowdfund_prove(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Run Groth16 trusted setup for the crowdfunding circuit (8 contributors max).
 * Returns JSON: { pk_hex, vk_hex, vk_len }
 * @returns {string}
 */
export function zk_crowdfund_setup() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.zk_crowdfund_setup();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_debug_string_dd5d2d07ce9e6c57: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_49868bde5eb1e745: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_40c5a80572e8f9d3: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_b29b5c5a8065ba1a: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c0cca72b82b86f4d: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_81fc77679af83bc6: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_3c3b4f651835fbcb: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_buffer_a77cc90da4bdb503: function(arg0) {
            const ret = arg0.buffer;
            return ret;
        },
        __wbg_call_368fa9c372d473ba: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.call(arg1, arg2, arg3);
            return ret;
        }, arguments); },
        __wbg_call_7f2987183bb62793: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_d578befcc3145dee: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_close_f181fdc02ee236e6: function() { return handleError(function (arg0) {
            arg0.close();
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_data_60b50110c5bd9349: function(arg0) {
            const ret = arg0.data;
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_f96702c6245e4ef9: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_instanceof_ArrayBuffer_ff7c1337a5e3b33a: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_0c32cb8543c8e4c8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_log_4c0baeb8af2f8f89: function(arg0) {
            console.log(arg0);
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_40792555590ec35c: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__hb029ded8098aabe7(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_4f9fafbb3909af72: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_a2d8434834334bbf: function() { return handleError(function (arg0, arg1) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_a560378ea1240b14: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_from_slice_2580ff33d0d10520: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_14d7cc391ce53d2c: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__hb029ded8098aabe7(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_length_9cedd08484b73942: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_3e05eb9545565046: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_queueMicrotask_abaf92f0bd4e80a4: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_df5a6dac26d818f3: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_random_a72d453e63c9558c: function() {
            const ret = Math.random();
            return ret;
        },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_0a79de24e9d2267b: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_send_ef0ff91d4523ddfd: function() { return handleError(function (arg0, arg1) {
            arg0.send(arg1);
        }, arguments); },
        __wbg_set_8ee2d34facb8466e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_binaryType_95c0a0f7586a3903: function(arg0, arg1) {
            arg0.binaryType = __wbindgen_enum_BinaryType[arg1];
        },
        __wbg_set_onerror_3db8bc3e52b2b10b: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onmessage_45bd33b110c54f5b: function(arg0, arg1) {
            arg0.onmessage = arg1;
        },
        __wbg_set_onopen_7ffeb01f8a628209: function(arg0, arg1) {
            arg0.onopen = arg1;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_f2e0f995a21329ff: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_24f78b6d23f286ea: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_59fd959c540fe405: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_0f98d3fb634508ad: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_then_00eed3ac0b8e82cb: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_a0c8db0381c8994c: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 153, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 494, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__ha4ad0e5f40f3bbc4);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("MessageEvent")], shim_idx: 153, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5_2);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 152, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h148c9614421699de);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./kassee_web_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__h148c9614421699de(arg0, arg1) {
    wasm.wasm_bindgen__convert__closures_____invoke__h148c9614421699de(arg0, arg1);
}

function wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5_2(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h4f078dac72696ab5_2(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__ha4ad0e5f40f3bbc4(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__ha4ad0e5f40f3bbc4(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__hb029ded8098aabe7(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__hb029ded8098aabe7(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_BinaryType = ["blob", "arraybuffer"];

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('kassee_web_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
