import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue,
  ADDRESS, PK, PK2, PSKB, wallet, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

await setupDeepHarness();
try {
  const state = await import(moduleUrl('app/state/index.js'));
  const send = await import(moduleUrl('features/stealth/index/send.js'));
  const wasm = globalThis.__KASSEE_WASM_STUBS__;
  const META='ab'.repeat(64), R='cd'.repeat(32);

  // Fee policy: missing estimates, each level, manual override, invalid override, and fetch failure/success.
  state.networkState.lastFeeEstimate=null; setValue('input-sf-fee','');
  assert.equal(send.stealthFeeValue('sf','send'),5000n);
  state.networkState.lastFeeEstimate={low_sompi_per_gram:'1',normal_sompi_per_gram:'2',priority_sompi_per_gram:'3',low_seconds:20,normal_seconds:10,priority_seconds:5};
  send.stealthFeeSetLevel('sf','send','low'); assert.equal(element('input-sf-fee').value,'2500');
  send.stealthFeeSetLevel('sf','send','normal'); assert.ok(BigInt(element('input-sf-fee').value)>=5000n);
  send.stealthFeeSetLevel('sf','send','priority'); assert.ok(BigInt(element('input-sf-fee').value)>=300000n);
  setValue('input-sf-fee','123456'); assert.equal(send.stealthFeeValue('sf','send'),123456n);
  setValue('input-sf-fee','bogus'); assert.ok(send.stealthFeeValue('sf','send')>=5000n);
  setValue('input-sf-fee','0'); assert.ok(send.stealthFeeValue('sf','send')>=5000n);
  wasm.get_fee_estimate=()=>JSON.stringify({low_sompi_per_gram:'1',normal_sompi_per_gram:'2',priority_sompi_per_gram:'4',low_seconds:30,normal_seconds:12,priority_seconds:3});
  await send.stealthFeePrepare('sf','send'); assert.equal(element('sf-low-time').textContent,'30s'); assert.equal(element('sf-normal-time').textContent,'12s');
  wasm.get_fee_estimate=()=>{throw new Error('fee offline');}; await send.stealthFeePrepare('spf','spend');

  // Panel routing must pause visuals outside scan and select the requested panel deterministically.
  for (const panel of ['menu','meta','send','scan']) { send.stealthShowPanel(panel); const id=panel==='menu'?'stealth-menu':`stealth-${panel}-panel`; assert.equal(element(id).classList.contains('hidden'),false); }

  // Meta derivation: fail closed without wallet, render QR/announcement with wallet, and fall back to literal text if QR generation fails.
  const saved=state.walletSession.current(); state.walletSession.clear(); send.handleStealthMeta(); assert.equal(state.walletSession.hasWallet(),false);
  state.walletSession.replace(saved);
  wasm.stealth_meta_from_kpub=()=>JSON.stringify({meta_address:META}); wasm.stealth_announcement_address=()=>ADDRESS; wasm.generate_qr_svg_text=()=>'<svg>meta</svg>';
  send.handleStealthMeta(); assert.equal(element('stealth-meta-hex').textContent,META); assert.match(element('stealth-meta-qr').innerHTML,/svg/); assert.equal(element('stealth-announce-addr').textContent,ADDRESS);
  wasm.generate_qr_svg_text=()=>{throw new Error('QR unavailable');}; send.handleStealthMeta(); assert.equal(element('stealth-meta-qr').textContent,META);
  wasm.stealth_meta_from_kpub=()=>{throw new Error('metadata invalid');}; send.handleStealthMeta();

  // Payment preview validates exact meta width and preserves the entropy/meta pair used for the later payment.
  setValue('stealth-send-meta','bad'); send.handleStealthSendGenerate();
  setValue('stealth-send-meta',META);
  wasm.stealth_generate_payment=()=>JSON.stringify({address:ADDRESS,ephemeral_r:R,stealth_index:7}); wasm.get_fee_estimate=()=>JSON.stringify({low_sompi_per_gram:'1',normal_sompi_per_gram:'1',priority_sompi_per_gram:'2',low_seconds:20,normal_seconds:10,priority_seconds:5});
  send.handleStealthSendGenerate(); assert.equal(element('stealth-send-addr').textContent,ADDRESS); assert.equal(element('stealth-send-r').textContent,R); assert.equal(state.stealthState._stealthSendMeta,META); assert.equal(state.stealthState._stealthSendEntropy.length,64);
  wasm.stealth_generate_payment=()=>{throw new Error('payment derive failed');}; send.handleStealthSendGenerate();

  // Payment construction: every form guard, previewed-entropy reuse, fresh entropy, success cleanup, and builder failure.
  state.walletSession.clear(); await send.handleStealthSendPay();
  state.walletSession.replace(structuredClone(wallet)); setValue('stealth-send-meta','bad'); await send.handleStealthSendPay();
  setValue('stealth-send-meta',META); setValue('stealth-send-amount','bad'); await send.handleStealthSendPay();
  setValue('stealth-send-amount','0'); await send.handleStealthSendPay();
  let observed=[]; setValue('stealth-send-amount','1'); setValue('input-sf-fee','300000'); state.stealthState._stealthSendMeta=META; state.stealthState._stealthSendEntropy='11'.repeat(32);
  wasm.stealth_create_payment_lane=(walletJson,meta,amount,fee,entropy,ws,network)=>{ observed.push({meta,amount,fee,entropy,network}); return JSON.stringify({address:ADDRESS,ephemeral_r:R,view_tag:1,pskb_wire:PSKB}); };
  state.transactionState._psktReviewHex=null; await send.handleStealthSendPay(); assert.equal(state.transactionState._psktReviewHex,PSKB); assert.equal(observed[0].entropy,'11'.repeat(32)); assert.equal(observed[0].amount,100000000n); assert.equal(state.stealthState._stealthSendEntropy,null); assert.equal(state.navigationState._broadcastReturnScreen,'stealth');
  state.stealthState._stealthSendMeta='different'; state.stealthState._stealthSendEntropy='22'.repeat(32); state.transactionState._psktReviewHex=null; await send.handleStealthSendPay(); assert.notEqual(observed[1].entropy,'22'.repeat(32),'changed meta must force fresh entropy');
  wasm.stealth_create_payment_lane=()=>{throw new Error('lane build rejected');}; state.transactionState._psktReviewHex=null; await send.handleStealthSendPay(); assert.equal(state.transactionState._psktReviewHex,null);

  assertWatchOnlyStorage();
  console.log('PASS: stealth send/meta/fee watcher-only workflows');
} finally { await cleanupDeepHarness(); }
