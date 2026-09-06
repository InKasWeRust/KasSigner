// Stable browser-to-WASM boundary. Keep names synchronized with the generated package.
// The generated package is loaded lazily so the HTML controls remain usable when it is absent.

const GENERATED_WASM_EXPORTS = Object.freeze([
    'version',
    'import_kpub',
    'import_kpub_raw',
    'fetch_balance',
    'fetch_utxos',
    'fetch_utxos_complete',
    'get_fee_estimate',
    'create_send_pskb',
    'create_send_pskb_limited',
    'create_consolidate_pskb',
    'create_send_pskb_selected',
    'create_send_pskb_with_utxos',
    'broadcast_signed',
    'generate_qr_frames',
    'decode_qr_frame',
    'reset_qr_decoder',
    'decoder_progress',
    'fetch_utxos_for_address_js',
    'pskt_detect',
    'pskt_summary',
    'pskt_finalize_and_broadcast',
    'pskt_relay_to_kspt',
    'kassigner_sdk_limits',
    'kassigner_sdk_prepare',
    'kassigner_sdk_complete',
    'anti_klepto_begin',
    'anti_klepto_accept_commitment',
    'anti_klepto_verify_signed',
    'verify_covenant_anti_klepto',
    'create_multisig_pskb',
    'create_multisig_pskb_selected',
    'scan_multisig_branch_js',
    'create_multisig_pskb_multi_js',
    'decode_address',
    'encode_p2pk_address',
    'encode_p2sh_address',
    'extend_addresses',
    'covenant_additive_address',
    'covenant_escrow',
    'covenant_ship_escrow',
    'covenant_global_spending_limit',
    'create_global_spending_limit_withdraw',
    'create_global_spending_limit_topup',
    'covenant_global_allowance',
    'create_global_allowance_withdraw',
    'create_global_allowance_topup',
    'covenant_timelocked_savings',
    'create_covenant_timelocked_savings_claim',
    'covenant_timelocked_escrow',
    'covenant_dms',
    'covenant_private_swap',
    'private_swap_key_request',
    'private_swap_bind_request',
    'private_swap_presign_request',
    'private_swap_reveal_request',
    'private_swap_complete_request',
    'private_swap_parse_response',
    'private_swap_verify_presignature',
    'private_swap_verify_host_relation',
    'private_swap_verify_completed',
    'private_swap_complete_public',
    'private_swap_claim_sighash',
    'private_swap_extract_secret',
    'create_private_swap_claim',
    'private_swap_insert_completed_signature',
    'covenant_payjoin',
    'covenant_oracle_v1',
    'crowdfund_campaign_id',
    'covenant_crowdfund',
    'zk_crowdfund_setup',
    'zk_crowdfund_prove',
    'inspect_crowdfund_contributions',
    'create_crowdfund_sweep',
    'create_covenant_owner_spend',
    'create_covenant_owner_spend_selected',
    'create_covenant_borrower_spend',
    'create_covenant_borrower_withdraw',
    'create_covenant_beneficiary_spend',
    'create_covenant_beneficiary_spend_selected',
    'create_covenant_timelocked_savings_claim_selected',
    'create_covenant_timeout_refund',
    'create_covenant_payjoin_claim',
    'create_covenant_oracle_v1_claim',
    'verify_oracle_v1_attestation',
    'stealth_meta_from_kpub',
    'stealth_generate_payment',
    'stealth_announcement_address',
    'create_stealth_spend',
    'stealth_create_payment_lane',
    'blake2b_hash',
    'sha256_hash',
    'parse_kpub',
    'get_virtual_daa_score',
    'covenant_commit_reveal',
    'create_commit_reveal_spend',
    'merkle_root_from_addresses',
    'merkle_proof_for_address',
    'covenant_merkle_whitelist',
    'create_merkle_whitelist_spend',
    'generate_qr_svg_text',
    'tagged_vault_genesis_pskb',
    'tagged_vault_spend_pskb',
    'split_vault_genesis_pskb',
    'split_vault_spend_pskb',
    'create_covenant_pskb',
    'create_covenant_pskb_with_payload',
    'estimate_covenant_fee',
    'derive_covenant_payload_key',
    'build_covenant_payload',
    'parse_covenant_payload',
    'build_vcc_subscribe_request',
    'covenant_oracle_mb',
    'create_oracle_mb_publish',
]);

let wasmModule = null;

function packageLoadError(error) {
    const detail = error instanceof Error ? error.message : String(error);
    return new Error('KasSee WebAssembly package could not be loaded. Run `make kassee`, then reload the locally served `apps/kassee-web/web` page. ' + detail, { cause: error });
}

export async function init(input) {
    let module;
    try {
        module = await import('../../pkg/kassee_web.js');
    } catch (error) {
        wasmModule = null;
        throw packageLoadError(error);
    }
    if (typeof module.default !== 'function') {
        wasmModule = null;
        throw new Error('KasSee WebAssembly package is invalid: default initializer is missing');
    }
    await module.default(input);
    wasmModule = module;
}

function invoke(name, args) {
    if (!wasmModule) {
        throw new Error('KasSee WebAssembly is unavailable. Run `make kassee` and reload this page.');
    }
    const operation = wasmModule[name];
    if (typeof operation !== 'function') {
        throw new Error(`KasSee WebAssembly export is missing: ${name}`);
    }
    return operation(...args);
}

export function version(...args) { return invoke('version', args); }
export function import_kpub(...args) { return invoke('import_kpub', args); }
export function import_kpub_raw(...args) { return invoke('import_kpub_raw', args); }
export function fetch_balance(...args) { return invoke('fetch_balance', args); }
export function fetch_utxos(...args) { return invoke('fetch_utxos', args); }
export function fetch_utxos_complete(...args) { return invoke('fetch_utxos_complete', args); }
export function get_fee_estimate(...args) { return invoke('get_fee_estimate', args); }
export function create_send_pskb(...args) { return invoke('create_send_pskb', args); }
export function create_send_pskb_limited(...args) { return invoke('create_send_pskb_limited', args); }
export function create_consolidate_pskb(...args) { return invoke('create_consolidate_pskb', args); }
export function create_send_pskb_selected(...args) { return invoke('create_send_pskb_selected', args); }
export function create_send_pskb_with_utxos(...args) { return invoke('create_send_pskb_with_utxos', args); }
export function broadcast_signed(...args) { return invoke('broadcast_signed', args); }
export function generate_qr_frames(...args) { return invoke('generate_qr_frames', args); }
export function decode_qr_frame(...args) { return invoke('decode_qr_frame', args); }
export function reset_qr_decoder(...args) { return invoke('reset_qr_decoder', args); }
export function decoder_progress(...args) { return invoke('decoder_progress', args); }
export function fetch_utxos_for_address_js(...args) { return invoke('fetch_utxos_for_address_js', args); }
export function pskt_detect(...args) { return invoke('pskt_detect', args); }
export function pskt_summary(...args) { return invoke('pskt_summary', args); }
export function pskt_finalize_and_broadcast(...args) { return invoke('pskt_finalize_and_broadcast', args); }
export function pskt_relay_to_kspt(...args) { return invoke('pskt_relay_to_kspt', args); }
export function kassigner_sdk_limits(...args) { return invoke('kassigner_sdk_limits', args); }
export function kassigner_sdk_prepare(...args) { return invoke('kassigner_sdk_prepare', args); }
export function kassigner_sdk_complete(...args) { return invoke('kassigner_sdk_complete', args); }
export function anti_klepto_begin(...args) { return invoke('anti_klepto_begin', args); }
export function anti_klepto_accept_commitment(...args) { return invoke('anti_klepto_accept_commitment', args); }
export function anti_klepto_verify_signed(...args) { return invoke('anti_klepto_verify_signed', args); }
export function verify_covenant_anti_klepto(...args) { return invoke('verify_covenant_anti_klepto', args); }
export function create_multisig_pskb(...args) { return invoke('create_multisig_pskb', args); }
export function create_multisig_pskb_selected(...args) { return invoke('create_multisig_pskb_selected', args); }
export function scan_multisig_branch_js(...args) { return invoke('scan_multisig_branch_js', args); }
export function create_multisig_pskb_multi_js(...args) { return invoke('create_multisig_pskb_multi_js', args); }
export function decode_address(...args) { return invoke('decode_address', args); }
export function encode_p2pk_address(...args) { return invoke('encode_p2pk_address', args); }
export function encode_p2sh_address(...args) { return invoke('encode_p2sh_address', args); }
export function extend_addresses(...args) { return invoke('extend_addresses', args); }
export function covenant_additive_address(...args) { return invoke('covenant_additive_address', args); }
export function covenant_escrow(...args) { return invoke('covenant_escrow', args); }
export function covenant_ship_escrow(...args) { return invoke('covenant_ship_escrow', args); }
export function covenant_global_spending_limit(...args) { return invoke('covenant_global_spending_limit', args); }
export function create_global_spending_limit_withdraw(...args) { return invoke('create_global_spending_limit_withdraw', args); }
export function create_global_spending_limit_topup(...args) { return invoke('create_global_spending_limit_topup', args); }
export function covenant_global_allowance(...args) { return invoke('covenant_global_allowance', args); }
export function create_global_allowance_withdraw(...args) { return invoke('create_global_allowance_withdraw', args); }
export function create_global_allowance_topup(...args) { return invoke('create_global_allowance_topup', args); }
export function covenant_timelocked_savings(...args) { return invoke('covenant_timelocked_savings', args); }
export function create_covenant_timelocked_savings_claim(...args) { return invoke('create_covenant_timelocked_savings_claim', args); }
export function covenant_timelocked_escrow(...args) { return invoke('covenant_timelocked_escrow', args); }
export function covenant_dms(...args) { return invoke('covenant_dms', args); }
export function covenant_private_swap(...args) { return invoke('covenant_private_swap', args); }
export function private_swap_key_request(...args) { return invoke('private_swap_key_request', args); }
export function private_swap_bind_request(...args) { return invoke('private_swap_bind_request', args); }
export function private_swap_presign_request(...args) { return invoke('private_swap_presign_request', args); }
export function private_swap_reveal_request(...args) { return invoke('private_swap_reveal_request', args); }
export function private_swap_complete_request(...args) { return invoke('private_swap_complete_request', args); }
export function private_swap_parse_response(...args) { return invoke('private_swap_parse_response', args); }
export function private_swap_verify_presignature(...args) { return invoke('private_swap_verify_presignature', args); }
export function private_swap_verify_host_relation(...args) { return invoke('private_swap_verify_host_relation', args); }
export function private_swap_verify_completed(...args) { return invoke('private_swap_verify_completed', args); }
export function private_swap_complete_public(...args) { return invoke('private_swap_complete_public', args); }
export function private_swap_claim_sighash(...args) { return invoke('private_swap_claim_sighash', args); }
export function private_swap_extract_secret(...args) { return invoke('private_swap_extract_secret', args); }
export function create_private_swap_claim(...args) { return invoke('create_private_swap_claim', args); }
export function private_swap_insert_completed_signature(...args) { return invoke('private_swap_insert_completed_signature', args); }
export function covenant_payjoin(...args) { return invoke('covenant_payjoin', args); }
export function covenant_oracle_v1(...args) { return invoke('covenant_oracle_v1', args); }
export function crowdfund_campaign_id(...args) { return invoke('crowdfund_campaign_id', args); }
export function covenant_crowdfund(...args) { return invoke('covenant_crowdfund', args); }
export function zk_crowdfund_setup(...args) { return invoke('zk_crowdfund_setup', args); }
export function zk_crowdfund_prove(...args) { return invoke('zk_crowdfund_prove', args); }
export function inspect_crowdfund_contributions(...args) { return invoke('inspect_crowdfund_contributions', args); }
export function create_crowdfund_sweep(...args) { return invoke('create_crowdfund_sweep', args); }
export function create_covenant_owner_spend(...args) { return invoke('create_covenant_owner_spend', args); }
export function create_covenant_owner_spend_selected(...args) { return invoke('create_covenant_owner_spend_selected', args); }
export function create_covenant_borrower_spend(...args) { return invoke('create_covenant_borrower_spend', args); }
export function create_covenant_borrower_withdraw(...args) { return invoke('create_covenant_borrower_withdraw', args); }
export function create_covenant_beneficiary_spend(...args) { return invoke('create_covenant_beneficiary_spend', args); }
export function create_covenant_beneficiary_spend_selected(...args) { return invoke('create_covenant_beneficiary_spend_selected', args); }
export function create_covenant_timelocked_savings_claim_selected(...args) { return invoke('create_covenant_timelocked_savings_claim_selected', args); }
export function create_covenant_timeout_refund(...args) { return invoke('create_covenant_timeout_refund', args); }
export function create_covenant_payjoin_claim(...args) { return invoke('create_covenant_payjoin_claim', args); }
export function create_covenant_oracle_v1_claim(...args) { return invoke('create_covenant_oracle_v1_claim', args); }
export function verify_oracle_v1_attestation(...args) { return invoke('verify_oracle_v1_attestation', args); }
export function stealth_meta_from_kpub(...args) { return invoke('stealth_meta_from_kpub', args); }
export function stealth_generate_payment(...args) { return invoke('stealth_generate_payment', args); }
export function stealth_announcement_address(...args) { return invoke('stealth_announcement_address', args); }
export function create_stealth_spend(...args) { return invoke('create_stealth_spend', args); }
export function stealth_create_payment_lane(...args) { return invoke('stealth_create_payment_lane', args); }
export function blake2b_hash(...args) { return invoke('blake2b_hash', args); }
export function sha256_hash(...args) { return invoke('sha256_hash', args); }
export function parse_kpub(...args) { return invoke('parse_kpub', args); }
export function get_virtual_daa_score(...args) { return invoke('get_virtual_daa_score', args); }
export function covenant_commit_reveal(...args) { return invoke('covenant_commit_reveal', args); }
export function create_commit_reveal_spend(...args) { return invoke('create_commit_reveal_spend', args); }
export function merkle_root_from_addresses(...args) { return invoke('merkle_root_from_addresses', args); }
export function merkle_proof_for_address(...args) { return invoke('merkle_proof_for_address', args); }
export function covenant_merkle_whitelist(...args) { return invoke('covenant_merkle_whitelist', args); }
export function create_merkle_whitelist_spend(...args) { return invoke('create_merkle_whitelist_spend', args); }
export function generate_qr_svg_text(...args) { return invoke('generate_qr_svg_text', args); }
export function tagged_vault_genesis_pskb(...args) { return invoke('tagged_vault_genesis_pskb', args); }
export function tagged_vault_spend_pskb(...args) { return invoke('tagged_vault_spend_pskb', args); }
export function split_vault_genesis_pskb(...args) { return invoke('split_vault_genesis_pskb', args); }
export function split_vault_spend_pskb(...args) { return invoke('split_vault_spend_pskb', args); }
export function create_covenant_pskb(...args) { return invoke('create_covenant_pskb', args); }
export function create_covenant_pskb_with_payload(...args) { return invoke('create_covenant_pskb_with_payload', args); }
export function estimate_covenant_fee(...args) { return invoke('estimate_covenant_fee', args); }
export function derive_covenant_payload_key(...args) { return invoke('derive_covenant_payload_key', args); }
export function build_covenant_payload(...args) { return invoke('build_covenant_payload', args); }
export function parse_covenant_payload(...args) { return invoke('parse_covenant_payload', args); }
export function build_vcc_subscribe_request(...args) { return invoke('build_vcc_subscribe_request', args); }
export function covenant_oracle_mb(...args) { return invoke('covenant_oracle_mb', args); }
export function create_oracle_mb_publish(...args) { return invoke('create_oracle_mb_publish', args); }

export function generatedWasmExportNames() { return GENERATED_WASM_EXPORTS.slice(); }
