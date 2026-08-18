/* tslint:disable */
/* eslint-disable */

/**
 * BIP340 Schnorr sign (PoC, both sides in browser).
 * Returns 128 hex (64-byte sig).
 */
export function adaptor_bip340_sign(secret_hex: string, msg_hash_hex: string): string;

/**
 * BIP340 Schnorr verify.
 */
export function adaptor_bip340_verify(pubkey_hex: string, msg_hash_hex: string, sig_hex: string): boolean;

/**
 * Build and broadcast an adaptor swap claim TX.
 * Fetches UTXOs at covenant_addr, builds a raw TX with the provided sig_script,
 * sends the output to dest_addr, and broadcasts to the node.
 * Returns the TX ID on success.
 */
export function adaptor_broadcast_claim(covenant_addr: string, dest_addr: string, sig_script_hex: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Build sig_script for claiming an adaptor swap UTXO.
 * Layout: <push sig_64> <push msg_hash_32> <push redeem_script>
 * Returns sig_script hex.
 */
export function adaptor_build_sig_script(completed_sig_hex: string, msg_hash_hex: string, redeem_hex: string): string;

/**
 * Complete an adaptor signature with the secret.
 * Returns completed BIP340 signature (128 hex).
 */
export function adaptor_complete_sig(adaptor_sig_hex: string, secret_hex: string): string;

/**
 * Create an adaptor signature.
 * Returns JSON: { adaptor_sig_hex, signer_pubkey_hex }
 */
export function adaptor_create_sig(signer_secret_hex: string, msg_hash_hex: string, adaptor_point_hex: string): string;

/**
 * Extract the adaptor secret from on-chain completed sig vs original adaptor.
 * Returns secret t (64 hex).
 */
export function adaptor_extract_secret(completed_sig_hex: string, adaptor_sig_hex: string): string;

/**
 * Generate a random signing keypair (for PoC, browser-side signing).
 * Returns JSON: { secret_hex, pubkey_hex }
 */
export function adaptor_generate_keypair(): string;

/**
 * Generate an adaptor secret (t, T) for the swap initiator.
 * Returns JSON: { t_hex, T_hex }
 */
export function adaptor_generate_secret(): string;

/**
 * Negate a scalar (additive inverse mod curve order).
 * Used to handle BIP340 even-Y parity when extracting adaptor secrets.
 */
export function adaptor_negate_scalar(scalar_hex: string): string;

/**
 * Create a P2SH address for an adaptor swap UTXO.
 * Redeem script: <claimer_pubkey> OP_CHECKSIGFROMSTACK
 * Returns JSON: { address, redeem_script_hex, claimer_pubkey_hex }
 */
export function adaptor_swap_address(claimer_pubkey_hex: string, owner_pubkey_hex: string, claimer_dest_addr: string, locktime_daa: bigint, network: string): string;

/**
 * Compute swap commitment hash (both parties derive the same msg_hash).
 * Returns 64 hex (32-byte SHA256).
 */
export function adaptor_swap_commitment(alice_utxo_id: string, bob_utxo_id: string, alice_amount: bigint, bob_amount: bigint): string;

/**
 * Verify an adaptor signature.
 */
export function adaptor_verify_sig(pubkey_hex: string, msg_hash_hex: string, adaptor_sig_hex: string, adaptor_point_hex: string): boolean;

/**
 * Compute unkeyed Blake2b-256 hash of the input bytes (hex in, hex out).
 * Used for atomic swap expected hash computation from preimage.
 */
export function blake2b_hash(input_hex: string): string;

/**
 * Broadcast a signed KSPT hex to the network → return TX ID
 */
export function broadcast_signed(signed_hex: string, ws_url: string): Promise<string>;

/**
 * Build the plaintext covenant payload blob: [version:1][type:1][params...]
 * version = 0x01, type = covenant type byte. Caller provides params as hex.
 * Returns hex of the assembled plaintext (ready for AES-GCM encryption in JS).
 */
export function build_covenant_payload(covenant_type: number, params_hex: string): string;

/**
 * Build a NotifyUtxosChanged subscribe request.
 */
export function build_utxo_subscribe_request(covenant_address: string, request_id: bigint): Uint8Array;

/**
 * Build a NotifyVirtualChainChanged subscribe request (raw bytes).
 */
export function build_vcc_subscribe_request(request_id: bigint): Uint8Array;

/**
 * Precomputed lane_key(SUBNETWORK_ID_COINBASE). The coinbase lane is present in every block, so
 * fetching its proof confirms the seq_commit machinery is active without submitting any tx.
 */
export function coinbase_lane_key(): string;

/**
 * Compute BLAKE2B hash of a preimage (for creating the commitment).
 * Returns hex string of the 32-byte hash.
 */
export function commit_hash(preimage_hex: string): string;

/**
 * Build a Piggy Bank P2SH covenant address.
 * owner_pubkey_hex: 64-char hex of the 32-byte x-only pubkey
 * threshold_sompi: savings goal (0 = no goal)
 * deadline_daa: optional deadline DAA score (0 = no deadline)
 * Returns JSON: { "address": "kaspa:...", "redeem_script_hex": "...", "threshold_sompi": ..., "deadline_daa": ... }
 */
export function covenant_additive_address(owner_pubkey_hex: string, threshold_sompi: bigint, deadline_daa: bigint, network: string): string;

/**
 * Build an allowance covenant P2SH address.
 * Spending limit + relative time-lock (CSV). After each withdrawal,
 * min_sequence blocks must pass before the next one.
 * Returns JSON: { "address", "redeem_script_hex", "max_withdraw_sompi", "min_sequence" }
 */
export function covenant_allowance(owner_pubkey_hex: string, beneficiary_pubkey_hex: string, max_withdraw_sompi: bigint, min_sequence: bigint, start_daa: bigint, network: string): string;

/**
 * Build an atomic swap (HTLC) covenant P2SH address.
 * Counterparty claims by revealing preimage whose Blake2b hash matches;
 * owner refunds after timeout.
 * expected_hash_hex: 64-char hex of expected 32-byte hash
 * hash_algo: "blake2b" (Kaspa-native) or "sha256" (cross-chain Bitcoin-compatible)
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa", "hash_algo" }
 */
export function covenant_atomic_swap(owner_pubkey_hex: string, counterparty_pubkey_hex: string, expected_hash_hex: string, locktime_daa: bigint, hash_algo: string, network: string): string;

/**
 * Create a commit-reveal covenant P2SH address.
 *
 * owner_pubkey_hex: 32-byte x-only pubkey (hex)
 * committed_hash_hex: 32-byte BLAKE2B(preimage) commitment (hex)
 * locktime_daa: DAA score for refund timeout
 *
 * Returns JSON: { address, redeem_script_hex, committed_hash, locktime_daa }
 */
export function covenant_commit_reveal(owner_pubkey_hex: string, committed_hash_hex: string, locktime_daa: bigint, network: string): string;

/**
 *
 * contributor_pubkey_hex: 32-byte x-only pubkey (hex) — contributor's refund key
 * organizer_pubkey_hex: 32-byte x-only pubkey (hex) — organizer's sweep commitment key
 * vk_hex: verification key from crowdfund setup (hex)
 * locktime_daa: DAA score for contributor refund timeout
 *
 * Returns JSON: { address, redeem_script_hex, vk_hex, locktime_daa }
 */
export function covenant_crowdfund(contributor_pubkey_hex: string, organizer_pubkey_hex: string, vk_hex: string, locktime_daa: bigint, network: string): string;

/**
 * Build a true dead man's switch (CSV-based) covenant P2SH address.
 * owner_pubkey_hex / heir_pubkey_hex: 32-byte x-only pubkeys (hex)
 * inactivity_daa: relative DAA units of inactivity before heir can claim
 * Returns JSON: { "address", "redeem_script_hex", "inactivity_daa" }
 */
export function covenant_dms(owner_pubkey_hex: string, heir_pubkey_hex: string, inactivity_daa: bigint, network: string): string;

/**
 * Build an escrow covenant P2SH address.
 * alice_pubkey_hex, bob_pubkey_hex: 64-char hex of 32-byte x-only pubkeys
 * alice_address, bob_address: kaspa/kaspatest addresses for release destinations
 * Returns JSON: { "address", "redeem_script_hex" }
 */
export function covenant_escrow(alice_pubkey_hex: string, bob_pubkey_hex: string, arbiter_pubkey_hex: string, alice_address: string, bob_address: string, network: string): string;

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
 */
export function covenant_global_allowance(owner_pubkey_hex: string, beneficiary_pubkey_hex: string, max_withdraw_sompi: bigint, cooldown_daa: bigint, start_daa: bigint, network: string): string;

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
 */
export function covenant_global_spending_limit(owner_pubkey_hex: string, max_withdraw_sompi: bigint, cooldown_daa: bigint, network: string): string;

/**
 * Create a merkle whitelist vault covenant P2SH address.
 */
export function covenant_merkle_whitelist(owner_pubkey_hex: string, merkle_root_hex: string, depth: number, locktime_daa: bigint, network: string): string;

/**
 * Create an oracle-gated covenant address.
 *
 * Two branches:
 *   - Owner refund after locktime (IF)
 *   - Beneficiary claims when oracle attests (ELSE, requires OpCheckSigFromStack)
 *
 * Returns JSON: { address, redeem_script_hex, locktime_daa }
 */
export function covenant_oracle(owner_pubkey_hex: string, beneficiary_pubkey_hex: string, oracle_pubkey_hex: string, locktime_daa: bigint, network: string): string;

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
 */
export function covenant_oracle_mb(genesis_price: bigint, genesis_t: bigint, image_id_hex: string, control_id_hex: string, set_root_hex: string, hashfn_hex: string, heartbeat_cov_id_hex: string, network: string): string;

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
 */
export function covenant_oracle_mb_heartbeat(network: string): string;

/**
 * Derive the standalone TEST CONSUMER address for a specific oracle lineage.
 * Fund the returned address with a normal send (it carries no covenant_id of its
 * own; only the oracle needs a tag). 2-input read: consumer + oracle, no
 * heartbeat. Returns JSON: { address, redeem_script_hex, oracle_covenant_id,
 *   redeem_len }.
 */
export function covenant_oracle_mb_test_consumer(oracle_covenant_id_hex: string, network: string): string;

/**
 * Create a PayJoin covenant address.
 *
 * Two branches:
 *   - Owner refund after locktime (IF)
 *   - Beneficiary claims only in a multi-input TX with mixed addresses (ELSE)
 *
 * Returns JSON: { address, redeem_script_hex, locktime_daa }
 */
export function covenant_payjoin(owner_pubkey_hex: string, beneficiary_pubkey_hex: string, locktime_daa: bigint, min_inputs: bigint, min_outputs: bigint, network: string): string;

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
 */
export function covenant_ship_escrow(seller_pubkey_hex: string, deliverer_pubkey_hex: string, buyer_pubkey_hex: string, arbiter_pubkey_hex: string, product_sompi: bigint, fee_sompi: bigint, cltv1_deadline: bigint, cltv2_deadline: bigint, network: string): string;

/**
 * Create a Split Vault covenant address.
 * Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
 */
export function covenant_split_vault(owner_pubkey_hex: string, network: string): string;

/**
 * Create a Tagged Vault covenant address and redeem script.
 *
 * The tagged vault enforces state continuity via KIP-20 covenant IDs:
 * every spend must produce an output carrying the same covenant_id.
 *
 * Returns JSON: { address, redeem_script_hex, redeem_len, sig_op_count }
 */
export function covenant_tagged_vault(owner_pubkey_hex: string, network: string): string;

/**
 * Build a time-locked escrow covenant P2SH address.
 * alice_pubkey_hex / bob_pubkey_hex: 32-byte x-only pubkeys (hex)
 * alice_addr / bob_addr: destination addresses for each party
 * locktime_daa: DAA score after which funds auto-refund to Alice
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
 */
export function covenant_timelocked_escrow(alice_pubkey_hex: string, bob_pubkey_hex: string, alice_addr: string, bob_addr: string, locktime_daa: bigint, network: string): string;

/**
 * Build a time-locked SAVINGS covenant P2SH address.
 * wallet1_pubkey_hex / wallet2_pubkey_hex: 32-byte x-only pubkeys (hex).
 *   wallet2 is the key-loss recovery key (1-of-2, not multisig). Pass the
 *   same value as wallet1 if you do not want a separate recovery key.
 * locktime_daa: DAA score; funds are frozen for everyone until this score,
 *   after which either wallet can sweep with a single signature.
 * Returns JSON: { "address", "redeem_script_hex", "locktime_daa" }
 */
export function covenant_timelocked_savings(wallet1_pubkey_hex: string, wallet2_pubkey_hex: string, locktime_daa: bigint, network: string): string;

/**
 * Build a treasury (approved destinations) covenant P2SH address.
 * Owner can spend but ONLY to whitelisted addresses baked into the script.
 * approved_addresses_json: JSON array of kaspa/kaspatest addresses (1–4)
 * Returns JSON: { "address", "redeem_script_hex", "approved_count" }
 */
export function covenant_treasury(owner_pubkey_hex: string, approved_addresses_json: string, network: string): string;

/**
 * Create a PSKB for revealing and spending a commit-reveal covenant.
 *
 * The preimage is embedded in PSKB proprietaries and assembled
 * into the sig_script at finalization.
 */
export function create_commit_reveal_spend(covenant_address: string, dest_address: string, redeem_script_hex: string, part_a_hex: string, part_b_hex: string, payload_hex: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create compound KSPT with multiple recipients
 * recipients_json: [{"address":"kaspa:...","amount_sompi":"150000000"}, ...]
 */
export function create_compound_kspt(wallet_json: string, recipients_json: string, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Create compound unsigned PSKB: multiple recipients.
 */
export function create_compound_pskb(wallet_json: string, recipients_json: string, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Consolidate all UTXOs into one
 */
export function create_consolidate_kspt(wallet_json: string, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Consolidate all UTXOs into one via PSKB format.
 */
export function create_consolidate_pskb(wallet_json: string, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Beneficiary signs (ELSE branch with CHECKSIGVERIFY).
 * Partial spend: withdraw_sompi goes to dest, remainder goes back to covenant.
 * CSV sequence enforced on the covenant input.
 */
export function create_covenant_allowance_withdraw(covenant_address: string, dest_address: string, redeem_script_hex: string, withdraw_sompi: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB to claim an atomic swap covenant (counterparty reveals preimage).
 * The preimage is stored in proprietaries.atomicPreimage so the finalization
 * can include it in the sig_script.
 */
export function create_covenant_atomic_claim(covenant_address: string, dest_address: string, redeem_script_hex: string, preimage_hex: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB for a beneficiary spend on a time-locked vault covenant.
 * The TX locktime is set to the vault's locktime_daa so the node
 * enforces the time gate via OP_CHECKLOCKTIMEVERIFY in the script.
 * The beneficiary provides a signature; no owner signature needed.
 */
export function create_covenant_beneficiary_spend(covenant_address: string, dest_address: string, redeem_script_hex: string, locktime_daa: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Like `create_covenant_beneficiary_spend`, but sweeps only the caller-selected
 * UTXOs (so a vault/DMS funded with many UTXOs can be claimed in batches, e.g.
 * to keep the QR within KasSigner's frame limit). utxos_json: JSON array of
 * {tx_id, index, amount}. locktime_daa: CLTV unlock (0 for CSV/DMS).
 */
export function create_covenant_beneficiary_spend_selected(covenant_address: string, dest_address: string, redeem_script_hex: string, locktime_daa: bigint, utxos_json: string, fee: bigint): string;

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
 */
export function create_covenant_borrower_spend(borrower_wallet_json: string, covenant_address: string, redeem_script_hex: string, add_amount_sompi: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB for a borrower WITHDRAWAL from a spending-limit covenant.
 * The borrower takes up to max_withdraw sompi. Output[0] returns the remainder
 * to the same covenant address. Output[1] is the borrower's withdrawal.
 * No covenant signature — introspection opcodes enforce the cap.
 * The borrower's P2PK funding input covers the fee.
 */
export function create_covenant_borrower_withdraw(borrower_wallet_json: string, covenant_address: string, redeem_script_hex: string, withdraw_sompi: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB for an oracle-gated claim (beneficiary spend with oracle attestation).
 *
 * The oracle signature and message hash are stored in proprietaries so
 * finalization can include them in the sig_script.
 *
 * Sig_script: <oracle_sig> <msg_hash> <bene_sig> OP_FALSE <redeem>
 */
export function create_covenant_oracle_claim(covenant_address: string, dest_address: string, redeem_script_hex: string, oracle_sig_hex: string, msg_hash_hex: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB to spend a covenant UTXO via the owner path.
 * covenant_address: the P2SH covenant address (kaspatest:pz...)
 * dest_address: where to send the funds
 * redeem_script_hex: the covenant redeem script
 * fee: fee in sompi
 */
export function create_covenant_owner_spend(covenant_address: string, dest_address: string, redeem_script_hex: string, fee: bigint, ws_url: string, covenant_branch: string): Promise<string>;

/**
 * Create a PSKB for an owner spend using specific UTXOs (for consolidation).
 * utxos_json: JSON array of {tx_id, index, amount} objects (selected UTXOs).
 * dest_address: where to send (covenant address for consolidation, personal address for withdrawal).
 */
export function create_covenant_owner_spend_selected(covenant_address: string, dest_address: string, redeem_script_hex: string, utxos_json: string, fee: bigint, covenant_branch: string): string;

/**
 * Create a PSKB for a PayJoin covenant claim (beneficiary spend).
 *
 * The TX must include the caller's own UTXOs alongside the covenant UTXO
 * to satisfy the min_inputs and different-address requirements.
 *
 * `extra_utxo_address` is the caller's own address — its UTXOs will be
 * added as additional inputs to meet the PayJoin requirements.
 */
export function create_covenant_payjoin_claim(covenant_address: string, dest_address: string, redeem_script_hex: string, extra_utxo_address: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Build a PSKB for a covenant genesis TX (wallet -> covenant P2SH).
 *
 * The PSKB includes covenant binding data so KasSigner computes the
 * correct sighash for TX version 1. After KasSigner signs, KasSee
 * extracts the signature and broadcasts with output v2 + covenant binding.
 *
 * Returns: PSKB hex string for QR display
 */
export function create_covenant_pskb(wallet_json: string, covenant_address: string, send_amount: bigint, fee: bigint, change_address: string, _covenant_id_hex: string, utxo_indices_csv: string, ws_url: string): Promise<string>;

/**
 * Same as `create_covenant_pskb` but includes a TX payload.
 * Used for crowdfund campaign deposits where the VK is embedded in the payload.
 */
export function create_covenant_pskb_with_payload(wallet_json: string, covenant_address: string, send_amount: bigint, fee: bigint, change_address: string, payload_hex: string, utxo_indices_csv: string, ws_url: string, tag_genesis: boolean): Promise<string>;

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
 */
export function create_covenant_timelocked_savings_claim(covenant_address: string, dest_address: string, redeem_script_hex: string, locktime_daa: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create a PSKB to CLAIM a time-locked savings covenant from a CHOSEN subset
 * of UTXOs, for batching when the address holds too many to sweep in one TX.
 * utxos_json: JSON array of {tx_id, index, amount}. Either wallet signs; the
 * finalizer auto-detects the branch by the signer's pubkey. covenantBranch is
 * neutral ("savings"). Savings is CLTV-only, so the TX locktime carries the gate.
 */
export function create_covenant_timelocked_savings_claim_selected(covenant_address: string, dest_address: string, redeem_script_hex: string, locktime_daa: bigint, utxos_json: string, fee: bigint): string;

/**
 * Create a PSKB for a timeout refund on a time-locked escrow.
 * No signature needed — the CLTV branch has no CHECKSIG.
 * TX locktime is set to locktime_daa; output must go to Alice's address.
 */
export function create_covenant_timeout_refund(covenant_address: string, dest_address: string, redeem_script_hex: string, locktime_daa: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Sweep a single crowdfund contributor UTXO using a ZK proof.
 *
 * No owner signature needed. The sig_script contains:
 *   <public_input> <1> <proof> <vk> OP_FALSE <redeem>
 *
 * The ZK proof proves that total contributions sum to S.
 * The on-chain script verifies the VK hash and the proof.
 */
export function create_crowdfund_sweep(contributor_address: string, dest_address: string, redeem_script_hex: string, proof_hex: string, public_input_hex: string, vk_hex: string, commitment_sig_hex: string, commitment_msg_hex: string, fee: bigint, ws_url: string): Promise<string>;

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
 */
export function create_global_allowance_topup(wallet_json: string, covenant_address: string, redeem_script_hex: string, covenant_id_hex: string, thread_utxo_json: string, fee: bigint, utxo_indices_csv: string, ws_url: string): Promise<string>;

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
 */
export function create_global_allowance_withdraw(covenant_address: string, dest_address: string, redeem_script_hex: string, covenant_id_hex: string, withdraw_sompi: bigint, fee: bigint, selected_utxos_json: string): Promise<string>;

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
 */
export function create_global_spending_limit_topup(wallet_json: string, covenant_address: string, redeem_script_hex: string, covenant_id_hex: string, thread_utxo_json: string, fee: bigint, utxo_indices_csv: string, ws_url: string): Promise<string>;

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
 */
export function create_global_spending_limit_withdraw(covenant_address: string, dest_address: string, redeem_script_hex: string, covenant_id_hex: string, withdraw_sompi: bigint, fee: bigint, selected_utxos_json: string): Promise<string>;

/**
 * Create a PSKB for spending a merkle whitelist vault to a proven address.
 */
export function create_merkle_whitelist_spend(covenant_address: string, dest_address: string, redeem_script_hex: string, proof_json: string, send_amount: bigint, fee: bigint, ws_url: string): Promise<string>;

/**
 * Create unsigned multisig spend KSPT
 * descriptor: "multi(2,pk1hex,...)" or "multi_hd(2,xpub130hex,...)"
 * addr_index: HD derivation index (0 for legacy multi(...) descriptors)
 * source_address: the P2SH multisig address holding the funds
 * change_address: where change goes (typically same P2SH address)
 */
export function create_multisig_kspt(descriptor: string, source_address: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, change_address: string, ws_url: string, addr_index: number): Promise<string>;

/**
 * Build an unsigned multisig PSKB — Path 2. Same semantics as
 * `create_multisig_kspt` but emits a Kaspa-standard PSKB wire blob
 * instead of legacy KSPT v1 binary.
 *
 * The output goes directly to `openPsktReview` on the JS side,
 * landing the user on the Review PSKB screen with 0/M sigs where
 * they can pick Relay → (Any wallet | KasSigner compact).
 */
export function create_multisig_pskb(descriptor: string, source_address: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, change_address: string, ws_url: string, change_index_hint: number, addr_index: number): Promise<string>;

/**
 * Build a 45' multisig PSKB spending MANY addresses of one branch.
 *
 * `sources_json` is `[{"address":"kaspa:...","tx_id":"...","index":0}, ...]` -
 * one entry per UTXO, so the caller picks both the addresses and the outputs.
 *
 * Each input carries its own redeem script and derivation path, which is the
 * whole difference from the single-address builders.
 *
 * Spending several addresses together links them permanently on chain; that is
 * the caller's choice to make, and the reason this is a separate entry point.
 */
export function create_multisig_pskb_multi_js(descriptor: string, sources_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, cosigner_index: number, change_index_hint: number, ws_url: string): Promise<string>;

/**
 * Same as `create_multisig_pskb` but with explicit UTXO indices
 * instead of greedy auto-selection.
 */
export function create_multisig_pskb_selected(descriptor: string, source_address: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, change_address: string, ws_url: string, change_index_hint: number, addr_index: number, utxo_csv: string): Promise<string>;

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
 */
export function create_oracle_heartbeat(covenant_address: string, redeem_script_hex: string, oracle_sig_hex: string, msg_hash_hex: string, attest_text: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Oracle (Model B) CONSUME: read price + T from the genuine oracle lineage,
 * recreate the oracle singleton (passthrough), and release the consumer to
 * `dest_address`. 2-input (consumer + oracle), no heartbeat. Returns the "PSKB"
 * wire (hex) for pskt_finalize_and_broadcast.
 */
export function create_oracle_mb_consume(consumer_address: string, consumer_redeem_hex: string, oracle_address: string, oracle_redeem_hex: string, oracle_covenant_id_hex: string, dest_address: string, fee: bigint, ws_url: string): Promise<string>;

/**
 * Oracle (Model B) HEARTBEAT roll: refresh the heartbeat's DAA by recreating
 * the singleton at the same redeem/SPK, tagged with the same covenant_id
 * (continuation). Fee taken from the heartbeat value.
 *
 * Returns the "PSKB" wire (hex) for pskt_finalize_and_broadcast.
 */
export function create_oracle_mb_heartbeat_roll(heartbeat_address: string, redeem_script_hex: string, covenant_id_hex: string, fee: bigint, ws_url: string): Promise<string>;

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
 */
export function create_oracle_mb_publish(wallet_json: string, oracle_address: string, redeem_script_hex: string, covenant_id_hex: string, heartbeat_cov_id_hex: string, image_id_hex: string, control_id_hex: string, set_root_hex: string, hashfn_hex: string, seal_hex: string, claim_hex: string, control_index_hex: string, control_digests_hex: string, journal_hex: string, fee: bigint, change_address: string, network: string, ws_url: string, omit_heartbeat: boolean): Promise<string>;

/**
 * Build unsigned KSPT from wallet, destination, amount, fee → return hex
 */
export function create_send_kspt(wallet_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Create unsigned KSPT with specific UTXO indices (comma-separated)
 */
export function create_send_kspt_selected(wallet_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, utxo_indices_csv: string, ws_url: string): Promise<string>;

/**
 * Create unsigned single-sig PSKB — same as `create_send_kspt` but
 * emits a standard PSKB wire blob. Routes through the PSKT review
 * screen on the JS side (same flow as multisig PSKB).
 */
export function create_send_pskb(wallet_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Create unsigned PSKB with specific UTXO indices.
 */
export function create_send_pskb_selected(wallet_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, utxo_csv: string, ws_url: string): Promise<string>;

/**
 * Create unsigned PSKB with explicit UTXO data (no re-fetch, no stale indices).
 * utxos_json: JSON array of {tx_id, index, amount, script_public_key, block_daa_score} objects.
 */
export function create_send_pskb_with_utxos(wallet_json: string, dest_address: string, amount_sompi: bigint, fee_sompi: bigint, utxos_json: string, ws_url: string): Promise<string>;

/**
 * Create a PSKB for spending a stealth UTXO.
 * The PSKB includes the stealth tweak in proprietaries so the device
 * can derive the correct signing key (account_privkey + tweak).
 */
export function create_stealth_spend(one_time_pubkey_hex: string, tweak_hex: string, dest_address: string, fee: bigint, ws_url: string, network: string): Promise<string>;

/**
 * Decode a Kaspa address → JSON { version, payload_hex }
 */
export function decode_address(addr: string): string;

/**
 * Feed a scanned QR frame (hex). Returns complete KSPT hex when done, or empty string.
 */
export function decode_qr_frame(frame_hex: string): string;

/**
 * Get decoder scan progress as JSON
 */
export function decoder_progress(): string;

/**
 * Derive the 32-byte AES-256 key used for encrypting covenant payloads.
 * Key = blake2b(chain_code || "covenant-payload-key"), where chain_code
 * is the 32-byte BIP32 chain code extracted from the kpub (bytes 13..45).
 * This key is deterministic from the seed (chain_code is derived from seed
 * via BIP32), so recovery only requires the seed -> kpub -> this key.
 */
export function derive_covenant_payload_key(kpub_str: string): string;

/**
 * Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
 * Optional network parameter (defaults to mainnet)
 */
export function encode_p2pk_address(pubkey_hex: string, network?: string | null): string;

/**
 * Encode a 32-byte script hash (hex) as a Kaspa P2SH address
 */
export function encode_p2sh_address(script_hash_hex: string, network?: string | null): string;

/**
 * Derive additional receive/change addresses beyond the current set.
 */
export function extend_addresses(wallet_json: string, extra_receive: number, extra_change: number, network: string): string;

/**
 * Connect to node via Borsh wRPC, fetch UTXOs, return JSON balance.
 */
export function fetch_balance(wallet_json: string, ws_url: string): Promise<string>;

/**
 * Fetch all UTXOs as JSON array
 */
export function fetch_utxos(wallet_json: string, ws_url: string): Promise<string>;

/**
 * Fetch UTXOs for a single address (for multisig balance check) → JSON array
 */
export function fetch_utxos_for_address_js(address: string, ws_url: string): Promise<string>;

/**
 * Fetch UTXOs for MANY addresses in one RPC call → JSON array.
 *
 * `addresses_json` is a JSON array of address strings.
 *
 * The single-address binding above, called in a loop, is one network round
 * trip per address. The stealth scan does exactly that over up to
 * STEALTH_MAX_R = 512 candidates, which is 512 sequential round trips for a
 * question the node answers in one: `getUtxosByAddresses` takes a LIST, and
 * `fetch_utxos_for_address` only ever wrapped a single-element vector around
 * it.
 *
 * Each returned UTXO carries its own `script_public_key`, so the caller can
 * still attribute results to addresses without asking per address.
 */
export function fetch_utxos_for_addresses_js(addresses_json: string, ws_url: string): Promise<string>;

/**
 * Search mempool for a TX that spent a specific UTXO and extract
 * the preimage from its sig_script. Used by the atomic swap watcher.
 *
 * Returns hex-encoded preimage if found, empty string if not found.
 */
export function find_preimage_for_utxo(outpoint_txid_hex: string, covenant_address: string, ws_url: string): Promise<string>;

/**
 * Search a specific block (by hash hex) for a TX that spent the given outpoint.
 * Returns hex-encoded preimage if found, empty string if not.
 */
export function find_preimage_in_block(block_hash_hex: string, outpoint_txid_hex: string, ws_url: string): Promise<string>;

/**
 * Generate QR frames (SVG strings) for a KSPT hex → return JSON array
 */
export function generate_qr_frames(kspt_hex: string): string;

/**
 * Generate a single QR code SVG from a plain UTF-8 string.
 * No framing, no hex encoding. Used for swap invites and data exchange.
 */
export function generate_qr_svg_text(text: string): string;

/**
 * Query node for current fee rates → return JSON
 */
export function get_fee_estimate(ws_url: string): Promise<string>;

/**
 * Fetch a Seq-Commit lane proof (op 153) for `lane_key_hex` against `block_hash_hex` (a
 * selected-parent-chain block). Pass "" for block_hash to use the current sink. Returns a JS
 * object; `raw_hex` is authoritative, the parsed fields are best-effort (the lane Option wrapper).
 */
export function get_seq_commit_lane_proof(ws_url: string, block_hash_hex: string, lane_key_hex: string): Promise<any>;

/**
 * Get the current virtual DAA score from the node.
 */
export function get_virtual_daa_score(ws_url: string): Promise<string>;

/**
 * Import a kpub string + network → derive 20 receive + 20 change addresses → return JSON
 */
export function import_kpub(kpub_str: string, network: string): string;

/**
 * Import a V1-raw compact kpub (78 raw payload bytes — the header
 * byte 0x01 should already be stripped by the JS side). Same output
 * as `import_kpub` — the raw payload is re-encoded to a standard
 * base58check kpub internally so all downstream paths (storage, UI,
 * RPC) are unchanged.
 */
export function import_kpub_raw(raw_payload: Uint8Array, network: string): string;

export function init(): void;

/**
 * Generate a merkle proof for a specific address.
 * Returns JSON: { proof: [{sibling, direction}], leaf_spk_hex }
 */
export function merkle_proof_for_address(addresses_json: string, target_address: string): string;

/**
 * Compute merkle root from a JSON array of SPK hex strings.
 * Returns hex of the 32-byte root.
 */
export function merkle_root_from_addresses(addresses_json: string, _network: string): string;

/**
 * One multisig address at an exact path → address string. No network.
 *
 * Used to identify which branch an address belongs to: derive candidates until
 * one matches. That search runs in the browser and sends nothing, which is why
 * it may try every branch while the network scan below must not.
 */
export function multisig_address_at_js(descriptor: string, addr_index: number, cosigner_index: number, chain: number): string;

/**
 * Parse a decrypted covenant payload blob: [version:1][type:1][params...]
 * Returns JSON: { "version": 1, "covenant_type": N, "params_hex": "..." }
 */
export function parse_covenant_payload(plaintext_hex: string): string;

/**
 * Parse a kpub (extended public key) and extract the account-level xonly pubkey.
 * Returns JSON: { "account_pubkey": "64-char hex xonly" }
 */
export function parse_kpub(kpub_str: string): string;

/**
 * Inspect a hex payload (output of the multi-frame QR decoder) and
 * return the detected format as a short string: "pskb", "pskt", or
 * "unknown". JS uses this to route a decoded payload to either the
 * PSKT review screen (this module) or the legacy KSPT flow.
 */
export function pskt_detect(wire_hex: string): string;

/**
 * PSKT-native finalize + broadcast. Walks the PSKB JSON once,
 * assembles a consensus Transaction directly (sig_scripts per input,
 * with partial sigs + redeem script for P2SH multisig), and submits
 * via Borsh wRPC. No KSPT intermediate format, no shim — PSKB JSON
 * in, Kaspa consensus transaction out, TX ID returned on acceptance.
 */
export function pskt_finalize_and_broadcast(wire_hex: string, ws_url: string): Promise<string>;

/**
 * Finalize a fully-signed PSKT/PSKB into a signed KSPT v2 hex blob
 * that the existing `broadcast_signed` RPC path can consume directly.
 *
 * Fails if any multisig input lacks the required M signatures.
 */
export function pskt_finalize_to_kspt(wire_hex: string): string;

/**
 * Inverse of `pskt_relay_to_kspt_v2`: merge the partial sigs from a
 * device-returned KSPT v2 blob into the canonical PSKB and return
 * the updated PSKB wire hex. Idempotent — existing sigs are not
 * clobbered.
 *
 * Accepts `flags = 0x00` (partial) and `flags = 0x01` (fully signed)
 * equally. Caller must still check whether the merged PSKB has ≥M
 * sigs before finalizing/broadcasting.
 */
export function pskt_merge_signed_kspt_v2(signed_kspt_hex: string, pskb_wire_hex: string): string;

/**
 * Re-emit a PSKB/PSKT as a KSPT v2 "partial" hex blob for relay to
 * KasSigner over QR. Does NOT require M sigs — accepts 0..=N partial
 * sigs per input. Flags byte = 0x00 (partial).
 *
 * The mainnet-verified `pskt_finalize_to_kspt` path is not touched:
 * this is a sibling function that shares no mutable state with it.
 */
export function pskt_relay_to_kspt_v2(wire_hex: string): string;

/**
 * Parse a PSKT/PSKB payload into a review summary (JSON string).
 *
 * `network` is one of "mainnet", "testnet-10/11/12", "simnet",
 * "devnet" — used to format decoded output addresses for display.
 */
export function pskt_summary(wire_hex: string, network: string): string;

/**
 * Reset multi-frame decoder state
 */
export function reset_qr_decoder(): void;

/**
 * Scan ONE cosigner branch → JSON.
 */
export function scan_multisig_branch_js(descriptor: string, cosigner_index: number, depth: number, ws_url: string): Promise<string>;

/**
 * Derive x-only pubkey from a 32-byte secret key hex.
 * Returns 32-byte x-only pubkey hex.
 */
export function schnorr_derive_pubkey(secret_key_hex: string): string;

/**
 * Generate an ephemeral BIP340 keypair and sign a message hash.
 * For testing dual-gate ZK sweep without KaSigner firmware support.
 * Returns JSON: { pubkey_hex (32-byte x-only), signature_hex (64-byte), msg_hex }
 */
export function schnorr_sign_ephemeral(msg_hex: string): string;

/**
 * Sign a message hash with a known secret key (hex).
 * For testing with a persistent ephemeral key across multiple sweeps.
 * Returns JSON: { signature_hex (64-byte), verified }
 */
export function schnorr_sign_with_key(secret_key_hex: string, msg_hex: string): string;

/**
 * SMT key for a lane: BLAKE3 keyed (key = b"SeqCommitLaneKey" padded to 32 bytes) over subnetwork_id[20].
 * `subnetwork_id_hex` is 20 bytes (40 hex chars). The "KST1" lane = 4b53543100..00 (4 ASCII + 16 zeros).
 * Verified against the node: lane_key(SUBNETWORK_ID_COINBASE) == COINBASE_LANE_KEY (8aa78027..b9e4).
 */
export function seq_commit_lane_key(subnetwork_id_hex: string): string;

/**
 * Compute SHA-256 hash of the input bytes (hex in, hex out).
 * Used for cross-chain atomic swap expected hash computation.
 */
export function sha256_hash(input_hex: string): string;

/**
 * Fund a Split Vault covenant with a genesis TX (creates covenant_id).
 * Same flow as tagged_vault_genesis but uses the split vault script.
 * Returns JSON: { txid, covenant_id_hex, covenant_address }
 */
export function split_vault_genesis(ephemeral_address: string, secret_key_hex: string, owner_pubkey_hex: string, send_amount: bigint, fee: bigint, network: string, ws_url: string): Promise<string>;

/**
 * Split a covenant UTXO into two outputs, both carrying the same covenant_id.
 * The split vault script enforces AUTH_OUTPUT_COUNT==2 and COV_OUTPUT_COUNT==2.
 *
 * Returns JSON: { txid, covenant_id_hex, amount_a, amount_b }
 */
export function split_vault_spend(covenant_address: string, secret_key_hex: string, owner_pubkey_hex: string, covenant_id_hex: string, fee: bigint, network: string, ws_url: string): Promise<string>;

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
 */
export function stealth_announce_lane_probe(ws_url: string, sender_secret_hex: string, funding_txid_hex: string, funding_index: number, funding_amount: bigint, meta_hex: string, amount_sompi: bigint, fee_sompi: bigint, entropy_hex: string, network: string, lane_gas: bigint): Promise<string>;

/**
 * Get the well-known stealth announcement address for a network.
 */
export function stealth_announcement_address(network: string): string;

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
 */
export function stealth_create_payment(wallet_json: string, meta_hex: string, amount_sompi: bigint, fee_sompi: bigint, entropy_hex: string, ws_url: string, network: string): Promise<string>;

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
 */
export function stealth_create_payment_lane(wallet_json: string, meta_hex: string, amount_sompi: bigint, fee_sompi: bigint, entropy_hex: string, ws_url: string, network: string): Promise<string>;

/**
 * Generate a stealth payment: derive one-time address + ephemeral R.
 * `meta_hex` is the 128-char stealth meta-address.
 * `entropy_hex` is 64 hex chars (32 bytes) of randomness from window.crypto.
 * `network` is "mainnet" or "testnet-12" etc.
 * Returns JSON: { address, ephemeral_r, stealth_index }
 */
export function stealth_generate_payment(meta_hex: string, entropy_hex: string, network: string): string;

/**
 * Derive a stealth meta-address from a kpub string.
 * Returns JSON: { scan_pubkey: "hex", spend_pubkey: "hex", meta_address: "hex128" }
 */
export function stealth_meta_from_kpub(kpub_str: string): string;

/**
 * Scan a single announcement: given scan_privkey + spend_pubkey + ephemeral R,
 * derive the one-time pubkey the sender paid to.
 * Returns JSON: { one_time_pubkey, address, stealth_index, tweak }
 */
export function stealth_scan_announcement(scan_privkey_hex: string, spend_pubkey_hex: string, ephemeral_r_hex: string, network: string): string;

/**
 * Historical catch-up: scan up to `max_blocks` recent blocks for stealth
 * payments and return a JSON array of 64-hex ephemeral R values. Pair with the
 * live BlockAdded scan to also recover payments received while offline.
 */
export function stealth_scan_recent_blocks(ws_url: string, max_blocks: number): Promise<string>;

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
 */
export function tagged_vault_covenant_id(prev_txid_hex: string, prev_index: number, send_amount: bigint, covenant_spk_hex: string): string;

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
 */
export function tagged_vault_genesis(ephemeral_address: string, secret_key_hex: string, owner_pubkey_hex: string, send_amount: bigint, fee: bigint, network: string, ws_url: string): Promise<string>;

/**
 * Generate an ephemeral keypair for browser-signed Tagged Vault TXs.
 * Returns JSON: { secret_key_hex, pubkey_hex, address }
 */
export function tagged_vault_keygen(network: string): string;

/**
 * Spend a Tagged Vault UTXO with covenant-ID continuity.
 *
 * The output carries the same covenant_id (continuation).
 * Signed in-browser with the owner's secret key.
 *
 * Returns JSON: { txid, covenant_id_hex }
 */
export function tagged_vault_spend(covenant_address: string, secret_key_hex: string, owner_pubkey_hex: string, covenant_id_hex: string, fee: bigint, network: string, ws_url: string): Promise<string>;

/**
 * Test function: GetSink + GetBlock(sink, include_transactions=true).
 * Call from browser console: await test_getblock("ws://localhost:17210")
 * Returns a summary string. If the node crashes, you'll know GetBlock is the culprit.
 */
export function test_getblock(ws_url: string): Promise<string>;

/**
 * Version string
 */
export function version(): string;

/**
 * Generate a crowdfunding ZK proof.
 * `pk_hex`: proving key from setup
 * `amounts_json`: JSON array of u64 amounts in sompi, e.g. "[100000000, 200000000]"
 * Returns JSON: { proof_hex, public_input_hex, total_sompi, proof_len, verified }
 */
export function zk_crowdfund_prove(pk_hex: string, vk_hex: string, amounts_json: string): string;

/**
 * Run Groth16 trusted setup for the crowdfunding circuit (8 contributors max).
 * Returns JSON: { pk_hex, vk_hex, vk_len }
 */
export function zk_crowdfund_setup(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly blake2b_hash: (a: number, b: number) => [number, number, number, number];
    readonly broadcast_signed: (a: number, b: number, c: number, d: number) => any;
    readonly build_covenant_payload: (a: number, b: number, c: number) => [number, number, number, number];
    readonly build_utxo_subscribe_request: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly build_vcc_subscribe_request: (a: bigint) => [number, number, number, number];
    readonly covenant_oracle_mb: (a: bigint, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly covenant_oracle_mb_heartbeat: (a: number, b: number) => [number, number, number, number];
    readonly covenant_oracle_mb_test_consumer: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly create_compound_kspt: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => any;
    readonly create_compound_pskb: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => any;
    readonly create_consolidate_kspt: (a: number, b: number, c: bigint, d: number, e: number) => any;
    readonly create_consolidate_pskb: (a: number, b: number, c: bigint, d: number, e: number) => any;
    readonly create_covenant_pskb: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => any;
    readonly create_covenant_pskb_with_payload: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => any;
    readonly create_multisig_kspt: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number) => any;
    readonly create_multisig_pskb: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number) => any;
    readonly create_multisig_pskb_multi_js: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number) => any;
    readonly create_multisig_pskb_selected: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => any;
    readonly create_oracle_mb_consume: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: number, o: number) => any;
    readonly create_oracle_mb_heartbeat_roll: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => any;
    readonly create_oracle_mb_publish: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number, w: number, x: number, y: number, z: number, a1: number, b1: number, c1: bigint, d1: number, e1: number, f1: number, g1: number, h1: number, i1: number, j1: number) => any;
    readonly create_send_kspt: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number) => any;
    readonly create_send_kspt_selected: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly create_send_pskb: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number) => any;
    readonly create_send_pskb_selected: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly create_send_pskb_with_utxos: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly decode_address: (a: number, b: number) => [number, number, number, number];
    readonly decode_qr_frame: (a: number, b: number) => [number, number, number, number];
    readonly decoder_progress: () => [number, number];
    readonly derive_covenant_payload_key: (a: number, b: number) => [number, number, number, number];
    readonly encode_p2pk_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encode_p2sh_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly extend_addresses: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly fetch_balance: (a: number, b: number, c: number, d: number) => any;
    readonly fetch_utxos: (a: number, b: number, c: number, d: number) => any;
    readonly fetch_utxos_for_address_js: (a: number, b: number, c: number, d: number) => any;
    readonly fetch_utxos_for_addresses_js: (a: number, b: number, c: number, d: number) => any;
    readonly find_preimage_for_utxo: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly find_preimage_in_block: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly generate_qr_frames: (a: number, b: number) => [number, number, number, number];
    readonly generate_qr_svg_text: (a: number, b: number) => [number, number, number, number];
    readonly get_fee_estimate: (a: number, b: number) => any;
    readonly get_virtual_daa_score: (a: number, b: number) => any;
    readonly import_kpub: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly import_kpub_raw: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly init: () => void;
    readonly multisig_address_at_js: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly parse_covenant_payload: (a: number, b: number) => [number, number, number, number];
    readonly parse_kpub: (a: number, b: number) => [number, number, number, number];
    readonly pskt_detect: (a: number, b: number) => [number, number];
    readonly pskt_finalize_and_broadcast: (a: number, b: number, c: number, d: number) => any;
    readonly pskt_finalize_to_kspt: (a: number, b: number) => [number, number, number, number];
    readonly pskt_merge_signed_kspt_v2: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pskt_relay_to_kspt_v2: (a: number, b: number) => [number, number, number, number];
    readonly pskt_summary: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly reset_qr_decoder: () => void;
    readonly scan_multisig_branch_js: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly sha256_hash: (a: number, b: number) => [number, number, number, number];
    readonly test_getblock: (a: number, b: number) => any;
    readonly version: () => [number, number];
    readonly coinbase_lane_key: () => [number, number];
    readonly covenant_split_vault: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly covenant_tagged_vault: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly get_seq_commit_lane_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly seq_commit_lane_key: (a: number, b: number) => [number, number, number, number];
    readonly split_vault_genesis: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number) => any;
    readonly split_vault_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number) => any;
    readonly tagged_vault_covenant_id: (a: number, b: number, c: number, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly tagged_vault_genesis: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number) => any;
    readonly tagged_vault_keygen: (a: number, b: number) => [number, number, number, number];
    readonly tagged_vault_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number) => any;
    readonly adaptor_bip340_sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly adaptor_bip340_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly adaptor_broadcast_claim: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => any;
    readonly adaptor_build_sig_script: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly adaptor_complete_sig: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly adaptor_create_sig: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly adaptor_extract_secret: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly adaptor_generate_keypair: () => [number, number, number, number];
    readonly adaptor_generate_secret: () => [number, number, number, number];
    readonly adaptor_negate_scalar: (a: number, b: number) => [number, number, number, number];
    readonly adaptor_swap_address: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly adaptor_swap_commitment: (a: number, b: number, c: number, d: number, e: bigint, f: bigint) => [number, number];
    readonly adaptor_verify_sig: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly commit_hash: (a: number, b: number) => [number, number, number, number];
    readonly covenant_commit_reveal: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => [number, number, number, number];
    readonly covenant_crowdfund: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly covenant_merkle_whitelist: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number) => [number, number, number, number];
    readonly create_commit_reveal_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: number, o: number) => any;
    readonly create_crowdfund_sweep: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: bigint, r: number, s: number) => any;
    readonly create_merkle_whitelist_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: number, l: number) => any;
    readonly merkle_proof_for_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly merkle_root_from_addresses: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly schnorr_derive_pubkey: (a: number, b: number) => [number, number, number, number];
    readonly schnorr_sign_ephemeral: (a: number, b: number) => [number, number, number, number];
    readonly schnorr_sign_with_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly zk_crowdfund_prove: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly zk_crowdfund_setup: () => [number, number, number, number];
    readonly covenant_additive_address: (a: number, b: number, c: bigint, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly covenant_allowance: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly covenant_atomic_swap: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly covenant_dms: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => [number, number, number, number];
    readonly covenant_escrow: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly covenant_global_allowance: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly covenant_global_spending_limit: (a: number, b: number, c: bigint, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly covenant_oracle: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly covenant_payjoin: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: bigint, h: number, i: number) => [number, number, number, number];
    readonly covenant_ship_escrow: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: bigint, l: bigint, m: number, n: number) => [number, number, number, number];
    readonly covenant_timelocked_escrow: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly covenant_timelocked_savings: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => [number, number, number, number];
    readonly covenant_treasury: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly create_covenant_allowance_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_covenant_atomic_claim: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => any;
    readonly create_covenant_beneficiary_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_covenant_beneficiary_spend_selected: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: bigint) => [number, number, number, number];
    readonly create_covenant_borrower_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_covenant_borrower_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_covenant_oracle_claim: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number) => any;
    readonly create_covenant_owner_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number) => any;
    readonly create_covenant_owner_spend_selected: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly create_covenant_payjoin_claim: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => any;
    readonly create_covenant_timelocked_savings_claim: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_covenant_timelocked_savings_claim_selected: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: bigint) => [number, number, number, number];
    readonly create_covenant_timeout_refund: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number) => any;
    readonly create_global_allowance_topup: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number, n: number, o: number) => any;
    readonly create_global_allowance_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: number, l: number) => any;
    readonly create_global_spending_limit_topup: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number, n: number, o: number) => any;
    readonly create_global_spending_limit_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: number, l: number) => any;
    readonly create_oracle_heartbeat: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number) => any;
    readonly create_stealth_spend: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number) => any;
    readonly stealth_announce_lane_probe: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: number, j: number, k: bigint, l: bigint, m: number, n: number, o: number, p: number, q: bigint) => any;
    readonly stealth_announcement_address: (a: number, b: number) => [number, number];
    readonly stealth_create_payment: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number, k: number, l: number) => any;
    readonly stealth_create_payment_lane: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number, k: number, l: number) => any;
    readonly stealth_generate_payment: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly stealth_meta_from_kpub: (a: number, b: number) => [number, number, number, number];
    readonly stealth_scan_announcement: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly stealth_scan_recent_blocks: (a: number, b: number, c: number) => any;
    readonly wasm_bindgen__convert__closures_____invoke__h196ac2b234377f4a: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h451a1072b4ec071e: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h6f42bb3b13a7079a: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h6f42bb3b13a7079a_2: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__hb82728a63eb39624: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
