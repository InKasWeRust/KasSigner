import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element } from './web_recovery_test_harness.mjs';

await setupHarness();
try {
  const state = await import(moduleUrl('app/state/index.js'));
  const tx = await import(moduleUrl('features/transactions/send/compose/transaction_building.js'));
  const antiSession = await import(moduleUrl('features/transactions/anti_klepto/session.js'));
  const antiResponse = await import(moduleUrl('features/transactions/anti_klepto/response.js'));
  const broadcast = await import(moduleUrl('features/transactions/send/broadcast.js'));
  const camera = await import(moduleUrl('features/stealth/index/camera.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  // --- Ordinary-send intent validation branch ratchet ---
  const DEST = 'kaspa:destination';
  const CHANGE = 'kaspa:change';
  const wallet = JSON.stringify({ next_change_index: 0, change_addresses: [CHANGE] });
  const base = {
    total_in_sompi: '200000000', fee_sompi: '300000',
    outputs: [
      { address: DEST, amount_sompi: '100000000', derivation_branch: null },
      { address: CHANGE, amount_sompi: '99700000', derivation_branch: 1, derivation_index: 0 },
    ],
  };
  assert.doesNotThrow(() => tx.assertStandardSendIntent(base, wallet, DEST, 100000000n, 300000n));
  assert.throws(() => tx.assertStandardSendIntent(base, '{', DEST, 100000000n, 300000n), /Wallet state/);
  assert.throws(() => tx.assertStandardSendIntent({ ...base, fee_sompi: '1' }, wallet, DEST, 100000000n, 300000n), /fee does not match/);
  assert.throws(() => tx.assertStandardSendIntent({ ...base, outputs: [] }, wallet, DEST, 100000000n, 300000n), /destination payment/);
  assert.throws(() => tx.assertStandardSendIntent({ ...base, total_in_sompi: '100' }, wallet, DEST, 100000000n, 300000n), /spends more/);
  const exactSpend = { total_in_sompi: '100300000', fee_sompi: '300000', outputs: [{ address: DEST, amount_sompi: '100000000' }] };
  assert.doesNotThrow(() => tx.assertStandardSendIntent(exactSpend, wallet, DEST, 100000000n, 300000n));
  assert.throws(() => tx.assertStandardSendIntent({ ...exactSpend, outputs: [...exactSpend.outputs, { address: CHANGE, amount_sompi: '0', derivation_branch: 1, derivation_index: 0 }] }, wallet, DEST, 100000000n, 300000n), /unexpected change/);
  assert.throws(() => tx.assertStandardSendIntent(base, JSON.stringify({ next_change_index: -1, change_addresses: [] }), DEST, 100000000n, 300000n), /change address is unavailable/);
  assert.throws(() => tx.assertStandardSendIntent({ ...base, outputs: [base.outputs[0], { ...base.outputs[1], derivation_index: 1 }] }, wallet, DEST, 100000000n, 300000n), /reserved wallet address/);
  assert.throws(() => tx.assertStandardSendIntent({ ...base, outputs: [{ ...base.outputs[0], derivation_branch: 1 }, base.outputs[1]] }, wallet, DEST, 100000000n, 300000n), /destination payment/);

  // Destination scanning covers accepted .kas, wrong-network, and ignored junk.
  state.networkState.network = 'mainnet';
  tx.handleDestScan('kassigner.kas'); assert.equal(element('input-dest').value, 'kassigner.kas');
  tx.handleDestScan('kaspadev:wrong'); assert.match(element('toast').textContent, /different network/i);
  const before = element('input-dest').value; tx.handleDestScan('not-an-address'); assert.equal(element('input-dest').value, before);

  // Creation entry validation: known/unknown KNS, invalid address/amount, zero amount,
  // fee parse fallback, exact fee, and an intentionally completed planner route.
  state.walletSession.replace({ kpub:'kpub-test', receive_addresses:['kaspa:owner'], change_addresses:[CHANGE], next_receive_index:0, next_change_index:0 });
  element('input-dest').value = 'unknown.kas'; element('input-amount').value = '1'; element('input-fee').value = '300000';
  await tx.handleCreateTx(); assert.match(element('toast').textContent, /Unknown \.kas/);
  element('input-dest').value = 'bad'; await tx.handleCreateTx(); assert.match(element('toast').textContent, /valid kaspa:/i);
  element('input-dest').value = DEST; element('input-amount').value = 'bad'; await tx.handleCreateTx(); assert.match(element('toast').textContent, /8 decimal places/i);
  element('input-amount').value = '0'; await tx.handleCreateTx(); assert.match(element('toast').textContent, /> 0/);

  // --- Anti-klepto transcript branch ratchet ---
  stubs.anti_klepto_begin = () => JSON.stringify({ requestHex:'aa', hostSecretHex:'bb' });
  stubs.anti_klepto_accept_commitment = () => 'cc';
  stubs.anti_klepto_verify_signed = () => '4b5350540401';
  antiSession.clearAntiKleptoSession();
  antiSession.beginAntiKlepto('aa');
  const commitment = '4b414b50020200';
  assert.equal(antiResponse.processAntiKleptoResponse(commitment), null);
  assert.equal(antiResponse.processAntiKleptoResponse(commitment), antiResponse.ANTI_KLEPTO_KEEP_SCANNING);
  assert.throws(() => antiResponse.processAntiKleptoResponse('4b414b50020201'), /Different KasSigner commitment/);
  assert.throws(() => antiResponse.processAntiKleptoResponse('4b414b50020300'), /KasSee's reveal/);
  assert.throws(() => antiResponse.processAntiKleptoResponse('4b414b50020900'), /final anti-klepto QR/);
  antiSession.clearAntiKleptoSession();
  antiSession.beginAntiKlepto('aa');
  assert.throws(() => antiResponse.processAntiKleptoResponse('4b414b50020400'), /before KasSigner commitment/);
  antiSession.clearAntiKleptoSession();

  // --- Broadcast/result branch ratchet ---
  state.transactionState._standardChangeReservationIndex = 0;
  broadcast.showBroadcastSuccess('11'.repeat(32));
  assert.equal(state.transactionState._standardChangeReservationIndex, null);
  state.oracleState._oracleMbRollActive = true;
  broadcast.showBroadcastError('already spent by another transaction');
  assert.equal(element('broadcast-result-msg').textContent, 'Someone rolled it first');
  state.oracleState._oracleMbRollActive = false;
  broadcast.showBroadcastError('ordinary failure');
  assert.equal(element('broadcast-result-msg').textContent, 'Broadcast failed');

  // Complete commitment QR in the signed scanner: first commitment returns true
  // (host reveal displayed), an identical re-read keeps scanning, and a different
  // commitment fails closed. Use default stopCamera=true to cover that branch too.
  let decoded = commitment;
  stubs.decode_qr_frame = () => decoded;
  stubs.reset_qr_decoder = () => '';
  antiSession.beginAntiKlepto('aa');
  assert.equal(broadcast.handleSignedScan(new Uint8Array([1])), true);
  assert.equal(broadcast.handleSignedScan(new Uint8Array([1])), false);
  decoded = '4b414b50020201';
  assert.equal(broadcast.handleSignedScan(new Uint8Array([2])), null);
  antiSession.clearAntiKleptoSession();

  // Merge a signed compact return into a canonical PSKB whose summary remains
  // not-final, covering the "another signer" branch.
  const PSKB = '50534b42';
  decoded = '4b5350540401';
  stubs.pskt_detect = value => String(value).startsWith('50534b42') ? 'pskb' : '';
  stubs.kassigner_sdk_complete = () => JSON.stringify({psktHex:PSKB});
  stubs.pskt_summary = () => JSON.stringify({
    format:'pskb', tx_version:0, input_count:1, output_count:1,
    fee_sompi:'1', total_in_sompi:'2', total_out_sompi:'1', finalize_ready:false,
    inputs:[{script_kind:'p2pk',sigs_present:1,multisig_m:null,multisig_n:null,amount_sompi:'2',prev_tx_id:'aa'.repeat(32),prev_index:0}],
    outputs:[{script_kind:'p2pk',amount_sompi:'1',address:DEST,script_hex:'51'}],
  });
  state.transactionState._psktReviewHex = PSKB;
  assert.equal(broadcast.handleSignedScan(new Uint8Array([3]), { stopCamera:false }), true);
  assert.match(element('toast').textContent, /another signer/i);

  // Pasted anti-klepto commitment is consumed as a protocol step; final-before-
  // commitment is rejected; a PSKB paste routes through review.
  antiSession.clearAntiKleptoSession(); antiSession.beginAntiKlepto('aa');
  element('input-signed-hex').value = commitment; await broadcast.handleBroadcastHex();
  antiSession.clearAntiKleptoSession(); antiSession.beginAntiKlepto('aa');
  element('input-signed-hex').value = '4b414b50020400'; await broadcast.handleBroadcastHex();
  assert.match(element('toast').textContent, /verification failed/i);
  antiSession.clearAntiKleptoSession();
  element('input-signed-hex').value = PSKB; await broadcast.handleBroadcastHex();
  assert.equal(state.transactionState._psktReviewHex, PSKB);

  // --- Browser camera fallbacks ---
  const originalNavigator = globalThis.navigator;
  const video = element('scanner-video');
  video.readyState = 0; video.HAVE_ENOUGH_DATA = 4;
  globalThis.requestAnimationFrame = () => 1;
  globalThis.cancelAnimationFrame = () => {};
  const makeStream = () => ({ getTracks: () => [{ stop() {} }] });

  // No modern or legacy capture API.
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{} });
  camera.startScanner('Scan QR', () => {});
  await new Promise(resolve => setImmediate(resolve));
  assert.match(element('scanner-status').textContent, /Camera error:/i);

  // Legacy callback API succeeds and uses the createObjectURL attachment path.
  delete video.srcObject;
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ getUserMedia(_c, ok) { ok(makeStream()); } } });
  camera.startScanner('Legacy QR', () => {});
  await new Promise(resolve => setImmediate(resolve));
  assert.match(element('scanner-status').textContent, /Point at QR/i);
  camera.stopScanner();

  // Modern constraints retry only for constraint failures and the srcObject path.
  let requests = 0; video.srcObject = null;
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ mediaDevices:{ getUserMedia() { requests += 1; return requests === 1 ? Promise.reject({name:'OverconstrainedError'}) : Promise.resolve(makeStream()); } } } });
  camera.startScanner('Modern QR', () => {});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests, 2);
  assert.match(element('scanner-status').textContent, /Point at QR/i);
  camera.stopScanner();

  // Permission denial is not retried; name-only and null errors exercise the
  // fail-closed camera error formatting fallbacks.
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ mediaDevices:{ getUserMedia() { return Promise.reject({name:'NotAllowedError'}); } } } });
  camera.startScanner('Denied QR', () => {}); await new Promise(resolve => setImmediate(resolve));
  assert.match(element('scanner-status').textContent, /NotAllowedError/);
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ mediaDevices:{ getUserMedia() { return Promise.reject(null); } } } });
  camera.startScanner('Null QR', () => {}); await new Promise(resolve => setImmediate(resolve));
  assert.match(element('scanner-status').textContent, /Camera unavailable/);
  camera.stopScanner();

  // A cancelled pending getUserMedia request must never resurrect the scanner.
  let cancelledResolve; let cancelledStops = 0;
  const cancelledStream = { getTracks: () => [{ stop() { cancelledStops += 1; } }] };
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ mediaDevices:{ getUserMedia() { return new Promise(resolve => { cancelledResolve = resolve; }); } } } });
  camera.startScanner('Pending QR', () => {});
  camera.stopScanner();
  cancelledResolve(cancelledStream);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancelledStops, 1);
  assert.equal(state.scannerState.scanStream, null);

  // Two overlapping starts are generation-ordered: the older stream is stopped
  // when it resolves and cannot overwrite the newer scanner session.
  const pendingResolvers = []; let oldStops = 0; let currentStops = 0;
  const oldStream = { getTracks: () => [{ stop() { oldStops += 1; } }] };
  const currentStream = { getTracks: () => [{ stop() { currentStops += 1; } }] };
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:{ mediaDevices:{ getUserMedia() { return new Promise(resolve => pendingResolvers.push(resolve)); } } } });
  const returnScreenBeforeOverlap = state.navigationState.currentScreenName;
  camera.startScanner('Older QR', () => {});
  camera.startScanner('Current QR', () => {});
  pendingResolvers[0](oldStream);
  pendingResolvers[1](currentStream);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(oldStops, 1);
  assert.equal(state.scannerState.scanStream, currentStream);
  assert.match(element('scanner-status').textContent, /Point at QR/i);
  camera.stopScanner();
  assert.equal(currentStops, 1);
  assert.equal(state.navigationState.currentScreenName, returnScreenBeforeOverlap);
  Object.defineProperty(globalThis, 'navigator', { configurable:true, value:originalNavigator });

  console.log('PASS: web-runtime branch ratchet');
} finally {
  await teardownHarness();
}
