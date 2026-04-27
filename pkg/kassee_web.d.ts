/* tslint:disable */
/* eslint-disable */

/**
 * Broadcast a signed KSPT hex to the network → return TX ID
 */
export function broadcast_signed(signed_hex: string, ws_url: string): Promise<string>;

/**
 * Create compound KSPT with multiple recipients
 * recipients_json: [{"address":"kaspa:...","amount_kas":1.5}, ...]
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
 * Create unsigned multisig spend KSPT
 * descriptor: "multi(2,pk1hex,...)" or "multi_hd(2,xpub130hex,...)"
 * addr_index: HD derivation index (0 for legacy multi(...) descriptors)
 * source_address: the P2SH multisig address holding the funds
 * change_address: where change goes (typically same P2SH address)
 */
export function create_multisig_kspt(descriptor: string, source_address: string, dest_address: string, amount_kas: number, fee_sompi: bigint, change_address: string, ws_url: string, addr_index: number): Promise<string>;

/**
 * Build an unsigned multisig PSKB — Path 2. Same semantics as
 * `create_multisig_kspt` but emits a Kaspa-standard PSKB wire blob
 * instead of legacy KSPT v1 binary.
 *
 * The output goes directly to `openPsktReview` on the JS side,
 * landing the user on the Review PSKB screen with 0/M sigs where
 * they can pick Relay → (Any wallet | KasSigner compact).
 */
export function create_multisig_pskb(descriptor: string, source_address: string, dest_address: string, amount_kas: number, fee_sompi: bigint, change_address: string, ws_url: string, addr_index: number): Promise<string>;

/**
 * Same as `create_multisig_pskb` but with explicit UTXO indices
 * instead of greedy auto-selection.
 */
export function create_multisig_pskb_selected(descriptor: string, source_address: string, dest_address: string, amount_kas: number, fee_sompi: bigint, change_address: string, ws_url: string, addr_index: number, utxo_csv: string): Promise<string>;

/**
 * Build unsigned KSPT from wallet, destination, amount, fee → return hex
 */
export function create_send_kspt(wallet_json: string, dest_address: string, amount_kas: number, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Create unsigned KSPT with specific UTXO indices (comma-separated)
 */
export function create_send_kspt_selected(wallet_json: string, dest_address: string, amount_kas: number, fee_sompi: bigint, utxo_indices_csv: string, ws_url: string): Promise<string>;

/**
 * Create unsigned single-sig PSKB — same as `create_send_kspt` but
 * emits a standard PSKB wire blob. Routes through the PSKT review
 * screen on the JS side (same flow as multisig PSKB).
 */
export function create_send_pskb(wallet_json: string, dest_address: string, amount_kas: number, fee_sompi: bigint, ws_url: string): Promise<string>;

/**
 * Create unsigned PSKB with specific UTXO indices.
 */
export function create_send_pskb_selected(wallet_json: string, dest_address: string, amount_kas: number, fee_sompi: bigint, utxo_csv: string, ws_url: string): Promise<string>;

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
 * Encode a 32-byte x-only pubkey (hex) as a Kaspa P2PK address
 * Optional network parameter (defaults to mainnet)
 */
export function encode_p2pk_address(pubkey_hex: string, network?: string | null): string;

/**
 * Encode a 32-byte script hash (hex) as a Kaspa P2SH address
 */
export function encode_p2sh_address(script_hash_hex: string, network?: string | null): string;

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
 * Generate QR frames (SVG strings) for a KSPT hex → return JSON array
 */
export function generate_qr_frames(kspt_hex: string): string;

/**
 * Query node for current fee rates → return JSON
 */
export function get_fee_estimate(ws_url: string): Promise<string>;

/**
 * Import a kpub string + network → derive 20 receive + 5 change addresses → return JSON
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
 * Version string
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly broadcast_signed: (a: number, b: number, c: number, d: number) => any;
    readonly create_compound_kspt: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => any;
    readonly create_compound_pskb: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => any;
    readonly create_consolidate_kspt: (a: number, b: number, c: bigint, d: number, e: number) => any;
    readonly create_consolidate_pskb: (a: number, b: number, c: bigint, d: number, e: number) => any;
    readonly create_multisig_kspt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: number, j: number, k: number, l: number, m: number) => any;
    readonly create_multisig_pskb: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: number, j: number, k: number, l: number, m: number) => any;
    readonly create_multisig_pskb_selected: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => any;
    readonly create_send_kspt: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number) => any;
    readonly create_send_kspt_selected: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly create_send_pskb: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number) => any;
    readonly create_send_pskb_selected: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number) => any;
    readonly decode_address: (a: number, b: number) => [number, number, number, number];
    readonly decode_qr_frame: (a: number, b: number) => [number, number, number, number];
    readonly decoder_progress: () => [number, number];
    readonly encode_p2pk_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encode_p2sh_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly fetch_balance: (a: number, b: number, c: number, d: number) => any;
    readonly fetch_utxos: (a: number, b: number, c: number, d: number) => any;
    readonly fetch_utxos_for_address_js: (a: number, b: number, c: number, d: number) => any;
    readonly generate_qr_frames: (a: number, b: number) => [number, number, number, number];
    readonly get_fee_estimate: (a: number, b: number) => any;
    readonly import_kpub: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly import_kpub_raw: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly init: () => void;
    readonly pskt_detect: (a: number, b: number) => [number, number];
    readonly pskt_finalize_and_broadcast: (a: number, b: number, c: number, d: number) => any;
    readonly pskt_finalize_to_kspt: (a: number, b: number) => [number, number, number, number];
    readonly pskt_merge_signed_kspt_v2: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pskt_relay_to_kspt_v2: (a: number, b: number) => [number, number, number, number];
    readonly pskt_summary: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly reset_qr_decoder: () => void;
    readonly version: () => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h200a37f11e89f6da: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h1256d05cffb1a37b: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h2e36b7a07a0aa581: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h2e36b7a07a0aa581_2: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__h2cbb632eee695849: (a: number, b: number) => void;
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
