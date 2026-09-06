import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, CHANGE, EXTERNAL, PK, PK2, SIG, TXID, PSKB, KSPT, COV_ID,
  wallet, utxos, psktSummary, covenantResult, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const wasm = globalThis.__KASSEE_WASM_STUBS__;
  const multisig = await import(moduleUrl('features/transactions/pskt_multisig/multisig.js'));
  const review = await import(moduleUrl('features/transactions/pskt_multisig/review.js'));
  const broadcast = await import(moduleUrl('features/transactions/send/broadcast.js'));
  const planner = await import(moduleUrl('features/transactions/send/compose/planners/covenant.js'));

  // Descriptor scanning: partial-frame progress, invalid decoded text, valid
  // descriptor, and decoder failure are all observable user states.
  wasm.decode_qr_frame = () => '';
  wasm.decoder_progress = () => JSON.stringify({ total:3, count:2, bits:[true,false,true] });
  multisig.handleDescriptorScan(new Uint8Array([1,2,3]));
  assert.match(element('scanner-status').innerHTML, /2 \/ 3 frames/);
  wasm.decode_qr_frame = () => Buffer.from('not-a-descriptor').toString('hex');
  multisig.handleDescriptorScan(new Uint8Array([4]));
  assert.match(element('toast').textContent, /valid descriptor/i);
  wasm.decode_qr_frame = () => Buffer.from('multi(2,' + PK + ',' + PK2 + ')').toString('hex');
  multisig.handleDescriptorScan(new Uint8Array([5]));
  assert.match(element('input-ms-descriptor').value, /^multi\(/);
  wasm.decode_qr_frame = () => { throw new Error('decoder failure'); };
  assert.doesNotThrow(() => multisig.handleDescriptorScan(new Uint8Array([6])));

  // Manual multisig UTXOs cover no-source, transport failure, empty set,
  // successful render, hide/reset, and selected/max calculations.
  element('ms-utxo-list').classList.add('hidden');
  setValue('input-ms-source',''); await multisig.toggleMsUtxos();
  assert.match(element('toast').textContent, /source address/i);
  setValue('input-ms-source', ADDRESS);
  wasm.fetch_utxos_for_address_js = () => { throw new Error('offline'); };
  await multisig.toggleMsUtxos(); assert.match(element('toast').textContent, /fetch failed/i);
  wasm.fetch_utxos_for_address_js = () => '[]';
  await multisig.toggleMsUtxos(); assert.match(element('toast').textContent, /No UTXOs/i);
  wasm.fetch_utxos_for_address_js = () => JSON.stringify(utxos);
  await multisig.toggleMsUtxos();
  assert.equal(state.transactionState.msSelectedUtxoIds?.length, 0);
  assert.equal(element('ms-utxo-list').classList.contains('hidden'), false);
  await multisig.toggleMsUtxos();
  assert.equal(state.transactionState.msSelectedUtxoIds, null);

  setValue('input-ms-descriptor',''); setValue('input-ms-dest', EXTERNAL); setValue('input-ms-amount','1');
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/descriptor/i);
  setValue('input-ms-descriptor','multi(2,a,b)'); setValue('input-ms-source','');
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/source/i);
  setValue('input-ms-source',ADDRESS); setValue('input-ms-dest','');
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/destination/i);
  setValue('input-ms-dest',EXTERNAL); setValue('input-ms-amount','bad');
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/valid amount/i);
  setValue('input-ms-amount','0'); await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/amount/i);
  setValue('input-ms-amount','1'); setValue('input-ms-dest','unknown.kas');
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/Unknown .kas/i);
  setValue('input-ms-dest','kassigner.kas');
  wasm.create_multisig_pskb = () => PSKB;
  await multisig.handleMultisigCreate(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  state.networkState.msCachedUtxos = structuredClone(utxos);
  state.transactionState.msSelectedUtxoIds = [`${TXID}:0`];
  setValue('input-ms-dest',EXTERNAL);
  wasm.create_multisig_pskb_selected = request => { assert.match(request, /utxo_csv/); return PSKB; };
  await multisig.handleMultisigCreate(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  wasm.create_multisig_pskb_selected = () => { throw new Error('builder reject'); };
  await multisig.handleMultisigCreate(); assert.match(element('toast').textContent,/Multisig TX failed/i);

  setValue('input-ms-source',''); await multisig.handleMsMax(); assert.match(element('toast').textContent,/source/i);
  setValue('input-ms-source',ADDRESS); state.transactionState.msSelectedUtxoIds=[`${TXID}:0`]; state.networkState.msCachedUtxos=structuredClone(utxos);
  await multisig.handleMsMax(); assert.ok(Number(element('input-ms-amount').value)>0);
  state.transactionState.msSelectedUtxoIds=null; wasm.fetch_utxos_for_address_js=()=>JSON.stringify(utxos);
  await multisig.handleMsMax(); assert.match(element('ms-balance-info').textContent,/Balance:/);
  wasm.fetch_utxos_for_address_js=()=>{throw new Error('balance offline');};
  await multisig.handleMsMax(); assert.match(element('toast').textContent,/Balance fetch failed/i);

  // PSKT review: parser rejection, unsigned multisig state, owned/change/external
  // totals, proprietary payload hash display, and finalize-ready state.
  wasm.pskt_summary = () => { throw new Error('bad pskt'); };
  review.openPsktReview(PSKB); assert.match(element('toast').textContent,/Could not parse PSKT/i);
  const notReady = psktSummary({finalize:false,multisig:true});
  notReady.outputs.push({script_kind:'unknown',amount_sompi:'1',address:null,script_hex:'aa'});
  wasm.pskt_summary = () => JSON.stringify(notReady);
  state.covenantState._covPayloadHex='aa'.repeat(20);
  review.openPsktReview(PSKB); await tick();
  assert.equal(element('btn-pskt-finalize').disabled,true);
  assert.ok(element('pskt-inputs').children.length >= 1);
  assert.ok(element('pskt-outputs').children.length >= 3);
  wasm.pskt_summary = () => JSON.stringify(psktSummary());
  review.openPsktReview(PSKB); await tick(); assert.equal(element('btn-pskt-finalize').disabled,false);

  // A locally-created multisig review is bound to the exact unsigned body.
  // Its descriptor-derived P2SH remainder is change, not part of the send
  // total, and that classification survives signature-only PSKT merges.
  const multisigReview = psktSummary({finalize:false,multisig:true});
  multisigReview.fee_sompi = '421700';
  multisigReview.total_out_sompi = '249578300';
  multisigReview.outputs = [
    {script_kind:'p2pk',amount_sompi:'100000000',address:EXTERNAL,script_hex:'51'},
    {script_kind:'p2sh',amount_sompi:'149578300',address:'kaspa:multisig-change',script_hex:'aa20' + '11'.repeat(32) + '87'},
  ];
  wasm.pskt_summary = () => JSON.stringify(multisigReview);
  review.openPsktReview(PSKB, {kind:'multisig-send',destinationAddress:EXTERNAL});
  assert.equal(element('pskt-send-total').textContent, '1');
  assert.equal(element('pskt-change-total').textContent, '1.495783');
  assert.match(element('pskt-outputs').children[1].innerHTML, /MULTISIG CHANGE/);
  multisigReview.finalize_ready = true;
  multisigReview.inputs[0].sigs_present = 2;
  review.openPsktReview(PSKB);
  assert.equal(element('pskt-send-total').textContent, '1');
  assert.equal(element('pskt-change-total').textContent, '1.495783');

  // A different body cannot inherit the old local multisig classification.
  const unrelatedReview = structuredClone(multisigReview);
  unrelatedReview.outputs[1].amount_sompi = '149578299';
  wasm.pskt_summary = () => JSON.stringify(unrelatedReview);
  review.openPsktReview(PSKB);
  assert.equal(state.transactionState._psktReviewContext, null);
  assert.equal(element('pskt-change-total').textContent, '0');

  // Finalizer: empty review, successful standard broadcast, and error path.
  // Private Swap uses its dedicated completed-signature finalizer and never
  // persists an HTLC preimage in transaction review state.
  const { createPsktFinalizer } = await import(moduleUrl('features/transactions/pskt_multisig/review_finalize.js'));
  const finalize=createPsktFinalizer();
  state.transactionState._psktReviewHex=null; await finalize(); assert.match(element('toast').textContent,/No PSKT/i);
  state.transactionState._psktReviewHex=PSKB; state.covenantState.lastCovenantResult=covenantResult('dms');
  await finalize(); assert.match(element('broadcast-result-txid').textContent,/[0-9a-f]{64}/i);
  state.transactionState._psktReviewHex=PSKB; wasm.pskt_finalize_and_broadcast=()=>{throw new Error('node reject');};
  await finalize(); assert.match(element('broadcast-result-txid').textContent,/node reject/i);
  wasm.pskt_finalize_and_broadcast=()=>TXID;

  // Broadcast scan/paste handles progress, decode failure, PSKB, merge success,
  // merge failure, unsupported and unsigned KSPT states, and node failure.
  let qr=''; wasm.decode_qr_frame=()=>qr; wasm.decoder_progress=()=>JSON.stringify({total:3,count:1,bits:[true,false,false]});
  assert.equal(broadcast.handleSignedScan(new Uint8Array([1]),{stopCamera:false}),false);
  assert.match(element('scanner-status').innerHTML,/1 \/ 3 frames/);
  wasm.decode_qr_frame=()=>{throw new Error('bad qr');};
  assert.equal(broadcast.handleSignedScan(new Uint8Array([1]),{stopCamera:false,showDecodeErrors:true}),null);
  qr=PSKB; wasm.decode_qr_frame=()=>qr; wasm.pskt_detect=()=> 'pskb';
  assert.equal(broadcast.handleSignedScan(new Uint8Array([2]),{stopCamera:false}),true);
  state.transactionState._psktReviewHex=PSKB; qr='4b5350540401'; wasm.pskt_detect=()=>''; wasm.kassigner_sdk_complete=()=>JSON.stringify({psktHex:PSKB});
  assert.equal(broadcast.handleSignedScan(new Uint8Array([3]),{stopCamera:false}),true);
  wasm.kassigner_sdk_complete=()=>{throw new Error('merge bad');}; state.transactionState._psktReviewHex=PSKB;
  assert.equal(broadcast.handleSignedScan(new Uint8Array([3]),{stopCamera:false}),null);
  state.transactionState._psktReviewHex=null;
  setValue('input-signed-hex','4b5350540300'); await broadcast.handleBroadcastHex(); assert.match(element('toast').textContent,/Unsupported KSPT/i);
  const unsigned = Buffer.alloc(51); unsigned.set([0x4b,0x53,0x50,0x54,0x04,0x00]);
  setValue('input-signed-hex',unsigned.toString('hex')); wasm.broadcast_signed=()=>TXID; await broadcast.handleBroadcastHex();
  assert.equal(element('broadcast-result-msg').textContent,'Transaction broadcast!');
  setValue('input-signed-hex','4b5350540401'); wasm.broadcast_signed=()=>{throw new Error('broadcast offline');}; await broadcast.handleBroadcastHex();
  assert.match(element('broadcast-result-txid').textContent,/broadcast offline/i);
  wasm.broadcast_signed=()=>TXID;

  // Covenant deposit planner: selected additive/dust folding, timelocked/dms,
  // global thread genesis/top-up, encrypted known-type payload, and no-payload fallback all stay watcher-only PSKB plans.
  state.networkState.cachedUtxos=structuredClone(utxos);
  state.transactionState.selectedUtxoIds=[`${TXID}:0`];
  wasm.fetch_utxos_for_address_js=()=> '[]';
  for (const type of ['additive','timelocked-savings','dms','escrow','payjoin','commit-reveal','merkle-whitelist']) {
    state.covenantState.lastCovenantResult=covenantResult(type);
    const result=await planner.planCovenant('kaspa:runtime-covenant','1',300000n);
    assert.equal(result?.completed,false, type);
  }
  for (const type of ['global-spending-limit','global-allowance']) {
    state.covenantState.lastCovenantResult=covenantResult(type);
    wasm.fetch_utxos_for_address_js=()=> '[]';
    let result=await planner.planCovenant('kaspa:runtime-covenant','1',300000n);
    assert.equal(result?.completed,false);
    wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{...utxos[0],covenant_id:COV_ID}]);
    result=await planner.planCovenant('kaspa:runtime-covenant','1',300000n);
    assert.equal(result?.completed,true);
  }

  assertWatchOnlyStorage();
  console.log('PASS: deep transaction/multisig/review/broadcast/covenant planner paths');
} finally {
  await cleanupDeepHarness();
}
