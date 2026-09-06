import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element, setFetchHook, setConfirmResult, intervals } from './web_recovery_test_harness.mjs';

export const ADDRESS = 'kaspa:runtime-owner';
export const CHANGE = 'kaspa:runtime-change';
export const BENEFICIARY = 'kaspa:runtime-beneficiary';
export const EXTERNAL = 'kaspa:runtime-external';
export const PK = '11'.repeat(32);
export const PK2 = '22'.repeat(32);
export const PK3 = '33'.repeat(32);
export const SIG = '44'.repeat(64);
export const TXID = 'aa'.repeat(32);
export const TXID2 = 'bb'.repeat(32);
export const PSKB = '50534b42' + '00'.repeat(8);
export const KSPT = '4b53505404' + '00'.repeat(8);
export const COV_ID = 'cc'.repeat(32);

export const wallet = {
  kpub: 'kpub1:' + '44'.repeat(78),
  receive_addresses: [ADDRESS, 'kaspa:runtime-owner-1', 'kaspa:runtime-owner-2'],
  change_addresses: [CHANGE, 'kaspa:runtime-change-1', 'kaspa:runtime-change-2'],
  next_receive_index: 0,
  next_change_index: 0,
};
export const utxos = [
  { tx_id: TXID, transactionId: TXID, index: 0, amount: '250000000', block_daa_score: '900', blockDaaScore: '900', covenant_id: COV_ID, script_public_key: '000051', address: ADDRESS },
  { tx_id: TXID2, transactionId: TXID2, index: 1, amount: '150000000', block_daa_score: '901', blockDaaScore: '901', covenant_id: COV_ID, script_public_key: '000051', address: CHANGE },
];

export function psktSummary({ finalize = true, multisig = false } = {}) {
  return {
    format: 'pskb', tx_version: 0, input_count: 1, output_count: 2,
    fee_sompi: '1000', total_in_sompi: '250000000', total_out_sompi: '249999000', finalize_ready: finalize,
    inputs: [{
      script_kind: multisig ? 'p2sh' : 'p2pk', sigs_present: finalize ? (multisig ? 2 : 1) : 0,
      multisig_m: multisig ? 2 : null, multisig_n: multisig ? 3 : null,
      amount_sompi: '250000000', prev_tx_id: TXID, prev_index: 0,
    }],
    outputs: [
      { script_kind: 'p2pk', amount_sompi: '100000000', address: EXTERNAL },
      { script_kind: 'p2pk', amount_sompi: '149999000', address: CHANGE },
    ],
  };
}

export function covenantResult(type = 'escrow') {
  return {
    type,
    address: 'kaspa:runtime-covenant', covenant_address: 'kaspa:runtime-covenant',
    redeem_script_hex: '51', covenant_id_hex: COV_ID, covenant_id: COV_ID,
    locktime_daa: '1200', cooldown_daa: '100', start_daa: '1000', inactivity_daa: '100',
    max_withdraw_sompi: '100000000', threshold_sompi: '100000000', goal_sompi: '500000000',
    owner_pubkey_hex: PK, beneficiary_pubkey_hex: PK2, wallet2_pubkey_hex: PK2,
    borrower_pubkey_hex: PK, lender_pubkey_hex: PK2, arbiter_pubkey_hex: PK3,
    seller_pubkey_hex: PK2, deliverer_pubkey_hex: PK3,
    alice_pk: PK, bob_pk: PK2, alice_pubkey_hex: PK, bob_pubkey_hex: PK2,
    merkle_root_hex: PK3, merkle_depth: 1, commit_hash_hex: PK3, hash_hex: PK3,
    claim_code: 'runtime-claim',
    payment_hash_hex: PK3, signer_pubkey_hex: PK,
    amount_a: '100000000', amount_b: '149999000',
    pskb_hex: PSKB,
  };
}

function response({ status = 200, json = {}, text } = {}) {
  const body = text ?? JSON.stringify(json);
  return { ok: status >= 200 && status < 300, status, headers: { get() { return null; } }, async json() { return json; }, async text() { return body; } };
}

export async function setupDeepHarness() {
  await setupHarness();
  // Never allow coverage tests to open real network sockets. The in-memory
  // transport still exercises open/send/close callbacks deterministically;
  // dedicated socket suites can override WebSocket when they need messages.
  class DeepHarnessWebSocket {
    constructor(url) { this.url=String(url); this.binaryType='arraybuffer'; this.readyState=0; queueMicrotask(()=>{ this.readyState=1; this.onopen?.(); }); }
    send(data) { this.lastSent=data; }
    close() { this.readyState=3; this.onclose?.(); }
  }
  globalThis.WebSocket = DeepHarnessWebSocket;
  const runtime = await import(moduleUrl('wasm/runtime.js'));
  runtime.markWasmReady();
  const state = await import(moduleUrl('app/state/index.js'));
  state.walletSession.replace(structuredClone(wallet));
  state.networkState.network = 'mainnet';
  state.networkState.customNodeUrl = 'wss://runtime-node';
  state.networkState.customRestUrl = 'https://runtime-api';
  state.networkState.lastFeeEstimate = { suggested_fee:'300000', suggested_fee_sompi:'300000', low_sompi_per_gram:'1', normal_sompi_per_gram:'1', priority_sompi_per_gram:'2', low_seconds:20, normal_seconds:10, priority_seconds:5 };
  state.networkState.cachedUtxos = structuredClone(utxos);
  state.networkState.utxoSnapshot = structuredClone(utxos);
  state.walletState.fundedReceiveIndices = [0];
  state.walletState.fundedChangeIndices = [0];
  state.walletState.usedReceiveIndices = new Set([0]);
  state.walletState.usedChangeIndices = new Set([0]);
  state.covenantState.lastCovenantResult = covenantResult();
  state.covenantState._covPayloadHex = 'aa'.repeat(16);
  state.stealthState.stealthAnnouncementsR = [PK3];
  state.stealthState._stealthResults = [];

  Object.assign(globalThis.__KASSEE_WASM_STUBS__, {
    version: () => 'deep-runtime',
    import_kpub: () => JSON.stringify(wallet), import_kpub_raw: () => JSON.stringify(wallet), parse_kpub: () => JSON.stringify({ account_pubkey: PK }),
    extend_addresses: walletJson => walletJson,
    decode_address: address => JSON.stringify({ payload: String(address).includes('beneficiary') ? PK2 : PK, version: 0 }),
    encode_p2pk_address: (pk, net) => String(pk).startsWith(PK2.slice(0,8)) ? BENEFICIARY : ADDRESS,
    encode_p2sh_address: () => 'kaspa:runtime-covenant',
    fetch_utxos: () => JSON.stringify(utxos), fetch_utxos_complete: () => JSON.stringify(utxos), fetch_utxos_for_address_js: () => JSON.stringify(utxos),
    fetch_balance: () => JSON.stringify({ total_kas:4, total_sompi:400000000, utxo_count:2, funded_addresses:2, funded_receive_indices:[0], funded_change_indices:[0], total:'400000000', mature:'400000000', pending:'0' }),
    get_virtual_daa_score: () => '1000', get_fee_estimate: () => JSON.stringify(state.networkState.lastFeeEstimate),
    blake2b_hash: () => PK3, sha256_hash: () => PK3,
    generate_qr_svg_text: value => `<svg data-runtime="${String(value).slice(0,8)}"></svg>`,
    generate_qr_frames: () => JSON.stringify([{svg:'<svg>1</svg>'},{svg:'<svg>2</svg>'},{svg:'<svg>3</svg>'}]),
    decode_qr_frame: () => '', reset_qr_decoder: () => '', decoder_progress: () => JSON.stringify({ total:3, count:2, bits:[true,false,true] }),
    pskt_detect: input => String(input).startsWith('50534b42') ? 'pskb' : String(input).startsWith('4b535054') ? 'kspt' : 'pskb',
    pskt_summary: () => JSON.stringify(psktSummary()), pskt_relay_to_kspt: () => KSPT, pskt_merge_signed_kspt: () => PSKB,
    pskt_finalize_and_broadcast: () => TXID, broadcast_signed: () => TXID,
    create_send_pskb: () => PSKB, create_send_pskb_limited: () => PSKB, create_send_pskb_selected: () => PSKB, create_send_pskb_with_utxos: () => PSKB,
    create_consolidate_pskb: () => PSKB, create_multisig_pskb: () => PSKB, create_multisig_pskb_selected: () => PSKB,
    create_covenant_pskb: () => PSKB, create_covenant_pskb_with_payload: () => PSKB,
    create_covenant_owner_spend: () => PSKB, create_covenant_owner_spend_selected: () => PSKB,
    create_covenant_borrower_spend: () => PSKB, create_covenant_borrower_withdraw: () => PSKB,
    create_covenant_beneficiary_spend: () => PSKB, create_covenant_beneficiary_spend_selected: () => PSKB,
    create_covenant_timelocked_savings_claim: () => PSKB, create_covenant_timelocked_savings_claim_selected: () => PSKB,
    create_covenant_timeout_refund: () => PSKB, create_covenant_payjoin_claim: () => PSKB,
    create_global_spending_limit_withdraw: () => PSKB, create_global_spending_limit_topup: () => PSKB,
    create_global_allowance_withdraw: () => PSKB, create_global_allowance_topup: () => PSKB,
    create_commit_reveal_spend: () => PSKB, create_merkle_whitelist_spend: () => PSKB,
    tagged_vault_genesis_pskb: () => JSON.stringify({ ...covenantResult('tagged-vault'), pskb_hex: PSKB }),
    tagged_vault_spend_pskb: () => JSON.stringify({ ...covenantResult('tagged-vault'), pskb_hex: PSKB }),
    split_vault_genesis_pskb: () => JSON.stringify({ ...covenantResult('split-vault'), pskb_hex: PSKB }),
    split_vault_spend_pskb: () => JSON.stringify({ ...covenantResult('split-vault'), pskb_hex: PSKB }),
    covenant_additive_address: () => JSON.stringify(covenantResult('savings')),
    covenant_escrow: () => JSON.stringify(covenantResult('escrow')), covenant_ship_escrow: () => JSON.stringify(covenantResult('shipping-escrow')),
    covenant_global_spending_limit: () => JSON.stringify(covenantResult('global-spending-limit')), covenant_global_allowance: () => JSON.stringify(covenantResult('global-allowance')),
    covenant_timelocked_savings: () => JSON.stringify(covenantResult('timelocked-savings')), covenant_timelocked_escrow: () => JSON.stringify(covenantResult('timelocked-escrow')),
    covenant_dms: () => JSON.stringify(covenantResult('dms')),
    covenant_payjoin: () => JSON.stringify(covenantResult('payjoin')),
    covenant_commit_reveal: () => JSON.stringify(covenantResult('commit-reveal')), covenant_merkle_whitelist: () => JSON.stringify(covenantResult('merkle-whitelist')),
    covenant_oracle_mb: () => JSON.stringify(covenantResult('oracle-mb')),
    merkle_root_from_addresses: () => JSON.stringify({ root:PK3, depth:1 }), merkle_proof_for_address: () => JSON.stringify({siblings:[PK2],directions:[0]}),
    derive_covenant_payload_key: () => PK3, build_covenant_payload: () => 'aa'.repeat(40), parse_covenant_payload: () => JSON.stringify({type:'generic',properties:{}}),
    stealth_meta_from_kpub: () => JSON.stringify({ scan_pubkey:PK, spend_pubkey:PK2 }), stealth_generate_payment: () => JSON.stringify({ address:ADDRESS, metadata:'aa' }),
    stealth_announcement_address: () => ADDRESS, stealth_create_payment_lane: () => PSKB, create_stealth_spend: () => PSKB,
    create_oracle_mb_publish: () => PSKB, build_vcc_subscribe_request: () => 'aa',
  });

  setFetchHook(async (url, options = {}) => {
    const u = String(url);
    if (u.includes('virtual-chain-blue-score')) return response({ text:'{"blueScore":1000}', json:{blueScore:1000} });
    if (u.includes('/info/blockdag')) return response({ json:{ sink:TXID } });
    if (u.includes('/blocks/')) return response({ text:'{"blueScore":1000}', json:{header:{blueScore:'1000'},blueScore:1000} });
    if (u.includes('/transactions/search')) return response({ json:[] });
    if (u.includes('/full-transactions')) return response({ json:[{transaction_id:TXID,block_time:1700000000000,is_accepted:true,inputs:[{previous_outpoint_amount:'250000000',previous_outpoint_address:ADDRESS}],outputs:[{amount:'249999000',script_public_key_address:EXTERNAL}]}] });
    if (u.includes('/transactions-count')) return response({ json:{total:1} });
    if (u.includes('/addresses/')) return response({ json:{total:1,tx_count:1,transactions:[{}]} });
    return response({ json:{} });
  });

  const originalGet = document.getElementById.bind(document);
  function defaultValue(id) {
    if (/addr|address|dest|recipient/.test(id)) return ADDRESS;
    if (/kpub/.test(id)) return wallet.kpub;
    if (/pub|key/.test(id)) return PK2;
    if (/script|redeem/.test(id)) return '51';
    if (/txid|hash|secret|preimage|commit/.test(id)) return PK3;
    if (/amount|fee|limit|cap|threshold|goal|target|price|kas/.test(id)) return '1';
    if (/daa|lock|delay|duration|timeout|deadline|cltv|period|seq|start/.test(id)) return '1200';
    if (/count|min-input|min-output|depth|index/.test(id)) return '2';
    if (/name|label|campaign|product/.test(id)) return 'Runtime deep coverage';
    if (/json|payload|properties/.test(id)) return '{}';
    if (/network/.test(id)) return 'mainnet';
    if (/mode/.test(id)) return 'spend';
    return '';
  }
  document.getElementById = id => {
    const node = originalGet(id);
    if (!node.__deepFilled) {
      node.__deepFilled = true;
      node.value = defaultValue(id);
      if (/checkbox|toggle|enable|manual|select/.test(id)) node.checked = true;
      if (id === 'cov-owner-panel') node.dataset.covOwnerType = 'savings';
      if (id === 'cov-beneficiary-panel') node.dataset.covBeneType = 'timelocked-savings';
      if (/hash-display/.test(id)) node.textContent = 'BLAKE2B: ' + PK3;
    }
    return node;
  };
  return { state, response, originalGet };
}

export function setValue(id, value) { const node = element(id); node.__deepFilled = true; node.value = String(value); return node; }
export function setText(id, value) { const node = element(id); node.__deepFilled = true; node.textContent = String(value); return node; }
export function eventFor(id, extra = {}) { return { target: element(id), preventDefault() {}, stopPropagation() {}, key:'Enter', ...extra }; }
export async function tick() { await new Promise(resolve => setImmediate(resolve)); }
export async function cleanupDeepHarness() { intervals.clear(); await teardownHarness(); }
export function assertWatchOnlyStorage() {
  const text = `${localStorage.getItem('kassee_private_swap_v2') ?? ''}${sessionStorage.getItem('kassee_private_swap_v2') ?? ''}`;
  assert.doesNotMatch(text, /(?:mnemonic|xprv|private[_-]?key|secret[_-]?key|mySecretKey|_swap_secret_key)/i);
}
export { element, moduleUrl, setFetchHook, setConfirmResult, intervals };
