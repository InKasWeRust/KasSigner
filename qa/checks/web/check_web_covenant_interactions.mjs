#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isolateWebPackage } from './web_pkg_fixture.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..', '..', '..');
const webRoot = path.join(root, 'apps', 'kassee-web', 'web');
const jsRoot = path.join(webRoot, 'js');
const pkgDir = path.join(webRoot, 'pkg');

function wasmNames(source) {
    const match = source.match(/const\s+GENERATED_WASM_EXPORTS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\);/);
    if (!match) throw new Error('Unable to parse wasm export inventory');
    return ['init', ...[...match[1].matchAll(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g)].map(item => item[1])];
}
function element(id = '') {
    const listeners = new Map();
    return {
        id, value: '', textContent: '', innerHTML: '', checked: false, style: { setProperty(name, value) { this[name] = value; } }, dataset: {},
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        parentElement: { classList: { toggle() {} }, querySelectorAll() { return []; } },
        addEventListener(type, listener) { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(listener); },
        async dispatch(type, event = {}) { for (const listener of listeners.get(type) || []) await listener({ target: this, preventDefault() {}, stopPropagation() {}, ...event }); }, querySelectorAll() { return []; }, querySelector() { return null; },
        appendChild() {}, replaceChildren() {}, insertBefore() {}, remove() {},
        getContext() { return { clearRect() {}, fillRect() {}, drawImage() {}, putImageData() {}, getImageData() { return { data: new Uint8ClampedArray(4), width: 1, height: 1 }; } }; },
        closest() { return null; }, setAttribute() {}, getAttribute() { return null; }, focus() {}, click() {},
    };
}
function storage() {
    const values = new Map();
    return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
}

const unhandled = [];
const onUnhandled = reason => unhandled.push(reason);
process.on('unhandledRejection', onUnhandled);
const pkgFixture = await isolateWebPackage(pkgDir);
const scheduledTimeouts = new Set();
const inertTimeouts = new Set();
let inertTimeoutId = -1;
try {
    const api = await fs.readFile(path.join(jsRoot, 'wasm/api.js'), 'utf8');
    const names = wasmNames(api);
    await pkgFixture.create();
    await fs.writeFile(path.join(pkgDir, 'kassee_web.js'), names.map(name => name === 'init'
        ? 'export default async function init() {}'
        : `export function ${name}(...args) { const hook = globalThis.__KASSEE_WASM_STUBS__?.[${JSON.stringify(name)}]; return typeof hook === 'function' ? hook(...args) : ''; }`).join('\n'));

    const elements = new Map();
    const clickListeners = [];
    globalThis.window = globalThis;
    globalThis.document = {
        getElementById(id) { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); },
        querySelector() { return element(); }, querySelectorAll() { return []; }, createElement() { return element(); },
        addEventListener(type, listener) { if (type === 'click') clickListeners.push(listener); }, body: element('body'),
    };
    globalThis.localStorage = storage(); globalThis.sessionStorage = storage();
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { clipboard: { async writeText() {} }, mediaDevices: { async getUserMedia() { return { getTracks: () => [] }; } } } });
    globalThis.location = { href: 'http://localhost/', reload() {} };
    globalThis.fetch = async () => ({ ok: false, status: 404, async json() { return {}; }, async text() { return ''; } });
    const nativeSetTimeout = globalThis.setTimeout.bind(globalThis);
    const nativeClearTimeout = globalThis.clearTimeout.bind(globalThis);
    globalThis.setInterval = () => 1; globalThis.clearInterval = () => {};
    globalThis.setTimeout = (callback, delay = 0, ...args) => {
        const milliseconds = Number(delay) || 0;
        // This handler-matrix test executes user-interaction timers, but it must
        // not turn long-lived WebSocket/poller retries into a 5 ms busy loop.
        // Dedicated watcher/socket suites exercise those retry callbacks.
        if (milliseconds > 50) {
            const handle = inertTimeoutId--;
            inertTimeouts.add(handle);
            return handle;
        }
        let handle;
        const wrapped = (...callbackArgs) => { scheduledTimeouts.delete(handle); if (typeof callback === 'function') callback(...callbackArgs); };
        handle = nativeSetTimeout(wrapped, milliseconds, ...args);
        scheduledTimeouts.add(handle);
        return handle;
    };
    globalThis.clearTimeout = handle => {
        if (inertTimeouts.delete(handle)) return;
        scheduledTimeouts.delete(handle);
        nativeClearTimeout(handle);
    };
    class HarnessWebSocket {
        constructor(url) {
            this.url = url;
            this.binaryType = 'arraybuffer';
            this.readyState = 0;
            queueMicrotask(() => { this.readyState = 1; if (typeof this.onopen === 'function') this.onopen(); });
        }
        send(data) { this.lastSent = data; }
        close() { this.readyState = 3; if (typeof this.onclose === 'function') this.onclose(); }
    }
    globalThis.WebSocket = HarnessWebSocket;
    globalThis.requestAnimationFrame = () => 1; globalThis.cancelAnimationFrame = () => {}; globalThis.QRCode = function() {}; globalThis.jsQR = () => null;
    globalThis.alert = () => {}; globalThis.confirm = () => false;
    const pskbHex = Buffer.from('PSKB' + Buffer.from(JSON.stringify([{global:{txVersion:0,fallbackLockTime:'0',inputsModifiableFlag:false,outputsModifiableFlag:false,inputCount:1,outputCount:1,bip32Derivations:[],proprietaries:[]},inputs:[{previousOutpoint:{transactionId:'aa'.repeat(32),index:0},sequence:'0',sigOpCount:1,utxoEntry:{amount:'250000000',scriptPublicKey:'000051',blockDaaScore:'900',isCoinbase:false},redeemScript:'51',partialSigs:{},minimumSignatures:1,bip32Derivations:[],proprietaries:[],finalScriptSig:null,minTime:'0'}],outputs:[{amount:'100000000',scriptPublicKey:'000051',bip32Derivations:[],proprietaries:[]}]}])).toString('hex')).toString('hex');
    const covenantResult = JSON.stringify({ address:'kaspa:covenant', redeem_script_hex:'51', covenant_id_hex:'33'.repeat(32), locktime_daa:'800', cooldown_daa:'0', max_withdraw_sompi:'100000000', threshold_sompi:'100000000', campaign_id:'runtime-campaign', claim_code:'runtime-claim' });
    const utxos = JSON.stringify([{ tx_id:'aa'.repeat(32), transactionId:'aa'.repeat(32), index:0, amount:'250000000', block_daa_score:'900', covenant_id:'33'.repeat(32), script_public_key:'000051' }]);
    globalThis.__KASSEE_WASM_STUBS__ = new Proxy({
        version: () => 'runtime-success',
        import_kpub: kpub => JSON.stringify({ kpub, receive_addresses:['kaspa:owner-receive'], change_addresses:['kaspa:change'], next_receive_index:0, next_change_index:0 }),
        import_kpub_raw: () => JSON.stringify({ kpub:'kpub1:' + '44'.repeat(78), receive_addresses:['kaspa:owner-receive'], change_addresses:['kaspa:change'], next_receive_index:0, next_change_index:0 }),
        parse_kpub: () => JSON.stringify({ account_pubkey:'11'.repeat(32) }),
        fetch_utxos_for_address_js: () => utxos, fetch_utxos: () => utxos, fetch_utxos_complete: () => utxos, fetch_balance: () => JSON.stringify({ total:'250000000', mature:'250000000', pending:'0' }),
        get_fee_estimate: () => JSON.stringify({ suggested_fee:'300000', normal_sompi_per_gram:'1', low_sompi_per_gram:'1', priority_sompi_per_gram:'2', low_seconds:20, normal_seconds:10, priority_seconds:5 }),
        get_virtual_daa_score: () => '1000', decode_address: () => JSON.stringify({ payload:'11'.repeat(32), version:0 }),
        encode_p2pk_address: () => 'kaspa:owner-receive', encode_p2sh_address: () => 'kaspa:covenant', extend_addresses: () => JSON.stringify({receive_addresses:['kaspa:owner-receive'],change_addresses:['kaspa:change']}),
        blake2b_hash: () => '44'.repeat(32), sha256_hash: () => '55'.repeat(32), generate_qr_svg_text: value => '<svg>'+String(value).slice(0,8)+'</svg>', generate_qr_frames: () => JSON.stringify([{svg:'<svg>1</svg>'},{svg:'<svg>2</svg>'}]),
        pskt_detect: () => 'pskb', pskt_summary: () => JSON.stringify({
            format:'pskb', tx_version:0, input_count:1, output_count:2,
            fee_sompi:'1000', total_in_sompi:'250000000', total_out_sompi:'249999000', finalize_ready:true,
            inputs:[{ script_kind:'p2pk', sigs_present:1, multisig_m:null, multisig_n:null, amount_sompi:'250000000', prev_tx_id:'aa'.repeat(32), prev_index:0 }],
            outputs:[
                { script_kind:'p2pk', amount_sompi:'100000000', address:'kaspa:covenant', script_hex:'51' },
                { script_kind:'p2pk', amount_sompi:'149999000', address:'kaspa:change', script_hex:'51' },
            ],
        }), pskt_relay_to_kspt: () => '4b5350540401', pskt_merge_signed_kspt: () => pskbHex, pskt_finalize_and_broadcast: () => 'aa'.repeat(32),
        broadcast_signed: () => 'aa'.repeat(32), create_send_pskb: () => pskbHex, create_send_pskb_limited: () => pskbHex, create_send_pskb_selected: () => pskbHex, create_send_pskb_with_utxos: () => pskbHex, create_consolidate_pskb: () => pskbHex, create_multisig_pskb: () => pskbHex, create_multisig_pskb_selected: () => pskbHex,
        create_covenant_owner_spend: () => pskbHex, create_covenant_owner_spend_selected: () => pskbHex, create_covenant_borrower_spend: () => pskbHex, create_covenant_borrower_withdraw: () => pskbHex, create_covenant_beneficiary_spend: () => pskbHex, create_covenant_beneficiary_spend_selected: () => pskbHex, create_covenant_timelocked_savings_claim: () => pskbHex, create_covenant_timelocked_savings_claim_selected: () => pskbHex, create_covenant_timeout_refund: () => pskbHex, create_covenant_payjoin_claim: () => pskbHex, create_global_spending_limit_withdraw: () => pskbHex, create_global_spending_limit_topup: () => pskbHex, create_global_allowance_withdraw: () => pskbHex, create_global_allowance_topup: () => pskbHex, create_commit_reveal_spend: () => pskbHex, create_merkle_whitelist_spend: () => pskbHex, tagged_vault_genesis_pskb: () => pskbHex, tagged_vault_spend_pskb: () => pskbHex, split_vault_genesis_pskb: () => pskbHex, split_vault_spend_pskb: () => pskbHex, create_covenant_pskb: () => pskbHex, create_covenant_pskb_with_payload: () => pskbHex,
        covenant_additive_address: () => covenantResult, covenant_escrow: () => covenantResult, covenant_ship_escrow: () => covenantResult, covenant_global_spending_limit: () => covenantResult, covenant_global_allowance: () => covenantResult, covenant_timelocked_savings: () => covenantResult, covenant_timelocked_escrow: () => covenantResult, covenant_dms: () => covenantResult, covenant_payjoin: () => covenantResult, covenant_commit_reveal: () => covenantResult, covenant_merkle_whitelist: () => covenantResult, covenant_oracle_mb: () => covenantResult,
        merkle_root_from_addresses: () => '66'.repeat(32), merkle_proof_for_address: () => JSON.stringify({siblings:[],directions:[]}), derive_covenant_payload_key: () => '77'.repeat(32), build_covenant_payload: () => '88'.repeat(40), parse_covenant_payload: () => JSON.stringify({type:'generic'}),
        stealth_meta_from_kpub: () => JSON.stringify({ scan_pubkey:'11'.repeat(32), spend_pubkey:'22'.repeat(32) }), stealth_generate_payment: () => JSON.stringify({address:'kaspa:stealth', metadata:'aa'}), stealth_announcement_address: () => 'kaspa:announce', stealth_create_payment_lane: () => pskbHex, create_stealth_spend: () => pskbHex,
        create_oracle_mb_publish: () => pskbHex, build_vcc_subscribe_request: () => 'aa'
    }, { get(target, prop) { return prop in target ? target[prop] : (...args) => { void args; return ''; }; } });

    const { startApplication } = await import(pathToFileURL(path.join(jsRoot, 'app', 'bootstrap.js')).href);
    await startApplication();
    const appState = await import(pathToFileURL(path.join(jsRoot, 'app', 'state', 'index.js')).href);
    appState.walletSession.replace({ kpub:'kpub1:' + '44'.repeat(78), receive_addresses:['kaspa:owner-receive'], change_addresses:['kaspa:change'] });
    appState.networkState.network = 'mainnet'; appState.networkState.customNodeUrl = 'wss://runtime-node'; appState.networkState.lastFeeEstimate = { normal_sompi_per_gram:'1', low_sompi_per_gram:'1', priority_sompi_per_gram:'2' }; appState.networkState.utxoSnapshot = JSON.parse(utxos);
    appState.covenantState.lastCovenantResult = JSON.parse(covenantResult);
    for (const [id, node] of elements) {
        if (/addr|address|dest|recipient/i.test(id)) node.value = 'kaspa:owner-receive';
        else if (/script|redeem/i.test(id)) node.value = '51';
        else if (/pub|key/i.test(id)) node.value = '11'.repeat(32);
        else if (/txid|hash|secret|preimage|commit/i.test(id)) node.value = 'aa'.repeat(32);
        else if (/amount|fee|limit|cap|threshold|goal|target|kas/i.test(id)) node.value = '1';
        else if (/daa|lock|delay|duration|timeout|deadline/i.test(id)) node.value = '100';
        else if (/name|label|campaign/i.test(id)) node.value = 'Runtime coverage';
        else if (/json|payload|properties/i.test(id)) node.value = '{}';
        if (/checkbox|toggle|enable|manual/i.test(id)) node.checked = true;
    }

    const selectCard = type => {
        const card = element(`${type}-card`); card.dataset.covType = type;
        const event = { target: { closest(selector) { return selector === '[data-cov-type]' ? card : null; } } };
        for (const listener of clickListeners) listener(event);
        const selected = elements.get('cov-type')?.value;
        if (selected !== type) throw new Error(`covenant card interaction failed: expected=${type} selected=${selected}`);
    };
    selectCard('commit-reveal');

    const requiredHandlers = [
        'btn-cov-cr-reveal-create',
        'btn-pskt-finalize', 'btn-stealth-scan', 'btn-broadcast',
    ];
    const missingHandlers = requiredHandlers.filter(id => typeof elements.get(id)?.onclick !== 'function');
    if (missingHandlers.length) throw new Error(`browser feature handlers missing: ${missingHandlers.join(', ')}`);
    if (elements.has('btn-add-recipient')) throw new Error('retired compound-recipient handler returned');
    const privatePattern = /(?:mnemonic|xprv|private[_-]?key|secret[_-]?key|mySecretKey|_swap_secret_key)/i;
    let invokedHandlers = 0;
    let controlledFailures = 0;
    // Exercise every production covenant family and participant role through the
    // real bound-handler layer.  This is intentionally a state matrix rather
    // than a generic function sweep: each row represents a user-reachable
    // covenant/result state with enough public metadata to enter its downstream
    // workflow instead of stopping at the first form guard.
    const scenarios = [
        { type:'savings', owner:'savings', bene:'timelocked-savings', role:'owner', amount:'1' },
        { type:'timelocked-savings', owner:'timelocked-savings', bene:'timelocked-savings', role:'beneficiary', amount:'' },
        { type:'dms', owner:'dms', bene:'dms', role:'beneficiary', amount:'' },
        { type:'global-spending-limit', owner:'global-spending-limit', bene:'global-allowance', role:'owner', amount:'1' },
        { type:'global-allowance', owner:'global-allowance', bene:'global-allowance', role:'owner', amount:'1' },
        { type:'global-allowance', owner:'global-allowance', bene:'global-allowance', role:'beneficiary', amount:'1' },
        { type:'escrow', owner:'escrow', bene:'timelocked-savings', role:'buyer', amount:'1' },
        { type:'escrow', owner:'escrow', bene:'timelocked-savings', role:'seller', amount:'1' },
        { type:'escrow', owner:'escrow', bene:'timelocked-savings', role:'arbiter', amount:'1' },
        { type:'ship-escrow', owner:'ship-escrow', bene:'timelocked-savings', role:'seller', amount:'1' },
        { type:'ship-escrow', owner:'ship-escrow', bene:'timelocked-savings', role:'deliverer', amount:'1' },
        { type:'ship-escrow', owner:'ship-escrow', bene:'timelocked-savings', role:'buyer', amount:'1' },
        { type:'payjoin', owner:'payjoin', bene:'timelocked-savings', role:'owner', amount:'' },
        { type:'payjoin', owner:'payjoin', bene:'timelocked-savings', role:'beneficiary', amount:'' },
        { type:'commit-reveal', owner:'commit-reveal', bene:'timelocked-savings', role:'owner', amount:'' },
        { type:'merkle-whitelist', owner:'merkle-whitelist', bene:'timelocked-savings', role:'owner', amount:'1' },
        { type:'oracle-mb', owner:'oracle-mb', bene:'timelocked-savings', role:'owner', amount:'' },
        { type:'tagged-vault', owner:'tagged-vault', bene:'timelocked-savings', role:'owner', amount:'1' },
        { type:'split-vault', owner:'split-vault', bene:'timelocked-savings', role:'owner', amount:'1' },
    ];   for (const scenario of scenarios) {
        const scenarioResult = {
            ...JSON.parse(covenantResult),
            type:scenario.type,
            role:scenario.role,
            cov_role:scenario.role,
            locktime_daa:'800', inactivity_daa:'100', start_daa:'0', deadline_daa:'1800',
            refund_daa:'1800', claim_daa:'1200', period_daa:'100', allowance_sompi:'100000000',
            owner_pk:'11'.repeat(32), beneficiary_pk:'22'.repeat(32), arbiter_pk:'33'.repeat(32),
            borrower_pk:'22'.repeat(32), lender_pk:'33'.repeat(32),
            merkle_root:'66'.repeat(32), secret_hash:'55'.repeat(32), hash_algo:'sha256',
            claim_code:'runtime-claim',
        };
        appState.covenantState.lastCovenantResult = scenarioResult;
        appState.covenantRecoveryState._covLoadedFromInvite = scenario.role !== 'owner';
        appState.covenantRecoveryState._covLoadedInactivityDaa = '100';
        appState.covenantRecoveryState._covLoadedLdi = '800';
        const ownerPanel = elements.get('cov-owner-panel'); if (ownerPanel) ownerPanel.dataset.covOwnerType = scenario.owner;
        const benePanel = elements.get('cov-beneficiary-panel'); if (benePanel) benePanel.dataset.covBeneType = scenario.bene;
        for (const [id,node] of elements) {
            if (/owner-amount|bene-amount/.test(id)) node.value = scenario.amount;
            if (/locktime|daa|cltv|deadline/.test(id) && !node.value) node.value = '800';
            if (/mode/.test(id)) node.value = scenario.type === 'global-allowance' ? 'withdraw' : 'spend';
        }
        for (const [id, node] of [...elements.entries()]) {
            for (const kind of ['onclick', 'onchange', 'onkeydown']) {
                const handler = node[kind];
                if (typeof handler !== 'function') continue;
                // Camera/file controls require user-selected File/MediaStream objects;
                // their dedicated QR/file tests cover those boundaries.
                if (/scan|upload|image|camera|file/i.test(id)) continue;
                invokedHandlers += 1;
                // Each handler gets a fresh valid watch-only baseline; preceding handlers
                // are allowed to reset screens/wallet state without making later matrix
                // entries accidentally test only empty-state guards.
                if (!appState.walletSession.hasWallet()) appState.walletSession.replace({ kpub:'kpub1:' + '44'.repeat(78), receive_addresses:['kaspa:owner-receive'], change_addresses:['kaspa:change'] });
                appState.networkState.network = 'mainnet';
                appState.networkState.customNodeUrl = 'wss://runtime-node';
                appState.networkState.lastFeeEstimate = { normal_sompi_per_gram:'1', low_sompi_per_gram:'1', priority_sompi_per_gram:'2' };
                appState.covenantState.lastCovenantResult = { ...scenarioResult };
                try {
                    const event = { target: node, key: kind === 'onkeydown' ? 'Enter' : undefined, preventDefault() {}, stopPropagation() {} };
                    const result = handler(event);
                    if (result && typeof result.then === 'function') await result;
                } catch (error) {
                    controlledFailures += 1;
                    if (!(error instanceof Error)) throw error;
                }
                const persisted = `${JSON.stringify([...elements.keys()])}${localStorage.getItem('kassee_private_swap_v2') ?? ''}${sessionStorage.getItem('kassee_private_swap_v2') ?? ''}`;
                if (privatePattern.test(persisted)) throw new Error(`watch-only event sweep leaked private material after ${scenario.type}:${id}:${kind}`);
            }
            if (typeof node.dispatch === 'function') {
                for (const type of ['change', 'keydown']) {
                    try { await node.dispatch(type, { key: type === 'keydown' ? 'Enter' : undefined }); } catch (error) {
                        controlledFailures += 1;
                        if (!(error instanceof Error)) throw error;
                    }
                }
            }
        }
    }
    await new Promise(resolve => setImmediate(resolve));
    if (invokedHandlers < 600) throw new Error(`expected broad bound-handler sweep, invoked only ${invokedHandlers}`);
    const unexpectedUnhandled = unhandled.filter(reason => !/(Create a swap first|Load a kpub|wallet|No active|missing|required|invalid|unavailable|not found|select|enter|amount|address|PSKT|KSPT)/i.test(String(reason?.message ?? reason)));
    if (unexpectedUnhandled.length) throw new Error(`unexpected unhandled UI rejection: ${unexpectedUnhandled.map(String).join(' | ')}`);
    console.log(`PASS: browser feature interactions (${clickListeners.length} delegated listeners, ${requiredHandlers.length} required handlers, ${invokedHandlers} bound handlers, ${controlledFailures} controlled failures)`);
} finally {
    for (const handle of scheduledTimeouts) clearTimeout(handle);
    scheduledTimeouts.clear();
    inertTimeouts.clear();
    process.off('unhandledRejection', onUnhandled);
    delete globalThis.__KASSEE_WASM_STUBS__;
    await pkgFixture.restore();
}
