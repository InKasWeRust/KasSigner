import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, CHANGE, BENEFICIARY, EXTERNAL, PK, PK2, PK3, TXID, PSKB, KSPT, COV_ID,
  wallet, utxos, covenantResult, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

function treeText(node) {
  return [node?.textContent || '', ...(node?.children || []).map(treeText)].join(' ');
}

const { state } = await setupDeepHarness();
try {
  const wasm=globalThis.__KASSEE_WASM_STUBS__;
  const review=await import(moduleUrl('features/transactions/send/review.js'));
  const sendForm=await import(moduleUrl('features/transactions/send/compose/send_form.js'));

  // QR transaction review must classify owned/change/destination/covenant/unknown outputs and inputs.
  wasm.encode_p2pk_address=(pk)=>pk===PK?ADDRESS:pk===PK2?CHANGE:BENEFICIARY;
  wasm.encode_p2sh_address=()=> 'kaspa:runtime-covenant';
  state.covenantState.lastCovenantResult={...covenantResult('escrow'),address:'kaspa:runtime-covenant'};
  state.covenantState._covPayloadHex='aa'.repeat(16);
  state.transactionState._lastPsktSummary={
    fee_sompi:'300000',
    outputs:[
      {script_kind:'p2pk',script_hex:'20'+PK+'ac',amount_sompi:'100000000'},
      {script_kind:'p2pk',script_hex:'20'+PK2+'ac',amount_sompi:'20000000'},
      {script_kind:'p2sh',script_hex:'aa00'+PK3+'bb',amount_sompi:'30000000'},
      {script_kind:'unknown',script_hex:'',amount_sompi:'1'},
    ],
    inputs:[
      {script_kind:'p2pk',script_hex:'20'+PK+'ac',amount_sompi:'160000000'},
      {script_kind:'p2sh-covenant',script_hex:'',redeem_script_hex:'51',amount_sompi:'1000000'},
    ],
  };
  wasm.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>single</svg>'}]);
  review.displayKsptQr(KSPT); await tick();
  const txInfoText = treeText(element('qr-tx-info'));
  assert.match(txInfoText,/TX Verification/); assert.match(txInfoText,/OWN/); assert.match(txInfoText,/CHANGE/); assert.match(txInfoText,/COVENANT/); assert.match(txInfoText,/\(unknown\)/);
  assert.match(element('qr-container').innerHTML,/single/); assert.equal(element('btn-scan-next-sig').style.display,'none');

  // Multi-frame controls: relay indicator, next/previous, pause/resume, and public lifecycle helpers.
  wasm.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>0</svg>'},{svg:'<svg>1</svg>'},{svg:'<svg>2</svg>'}]);
  review.displayKsptQr(KSPT,'Relay to KasSigner');
  assert.equal(element('btn-scan-next-sig').style.display,'block'); assert.ok(state.scannerState.qrCycleTimer);
  element('btn-frame-next').onclick(); assert.equal(state.scannerState.qrFrameIdx,1);
  element('btn-frame-prev').onclick(); assert.equal(state.scannerState.qrFrameIdx,0);
  element('btn-frame-pause').onclick(); assert.equal(state.scannerState.qrCycleTimer,null); assert.equal(element('btn-frame-pause').textContent,'▶');
  element('btn-frame-pause').onclick(); assert.ok(state.scannerState.qrCycleTimer); assert.equal(element('btn-frame-pause').textContent,'⏸');
  review.pauseQrCycle(); assert.equal(state.scannerState.qrCycleTimer,null); review.resumeQrCycleIfPossible(); assert.ok(state.scannerState.qrCycleTimer); review.stopQrCycle(); assert.equal(state.scannerState.qrCycleTimer,null);
  wasm.generate_qr_frames=()=>{throw new Error('QR rejected');}; assert.doesNotThrow(()=>review.displayKsptQr(KSPT,'Broken'));
  state.transactionState._lastPsktSummary=null; wasm.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>x</svg>'}]); review.displayKsptQr(KSPT,'No summary'); assert.equal(element('qr-tx-info').style.display,'none');

  // Send screen bootstrap: normal and covenant fee floors, fresh UTXO normalization/sort, and fetch failure.
  state.walletSession.replace(structuredClone(wallet)); state.networkState.network='mainnet'; setValue('balance-kas',''); element('balance-kas').textContent='4 KAS';
  wasm.get_fee_estimate=()=>JSON.stringify({suggested_fee:'1000',low_sompi_per_gram:'1',normal_sompi_per_gram:'2',priority_sompi_per_gram:'3',low_seconds:20,normal_seconds:10,priority_seconds:5});
  wasm.fetch_utxos_complete=()=>JSON.stringify([{tx_id:'bb'.repeat(32),index:1,amount:'100'},{tx_id:'aa'.repeat(32),index:0,amount:'200'}]);
  state.navigationState._broadcastReturnScreen=null; await sendForm.openSendScreen(); assert.equal(element('input-fee').value,'1000'); assert.equal(state.networkState.cachedUtxos[0].amount,200n); assert.match(element('send-balance-ref').textContent,/Available:/);
  state.navigationState._broadcastReturnScreen='covenant'; await sendForm.openSendScreen(); assert.equal(element('input-fee').value,'400000');
  wasm.get_fee_estimate=()=>{throw new Error('node offline');}; await sendForm.openSendScreen();

  // Thread-deposit mirroring applies only to top-ups where amount is intentionally hidden.
  state.covenantState.lastCovenantResult={...covenantResult('global-allowance'),type:'global-allowance'}; state.navigationState._broadcastReturnScreen='covenant'; state.networkState.cachedUtxos=utxos.map(u=>({...u,amount:BigInt(u.amount)})); state.transactionState.selectedUtxoIds=[`${utxos[0].tx_id}:0`];
  element('send-amount-wrap').style.display=''; setValue('input-amount','7'); sendForm.syncThreadDepositAmount(); assert.equal(element('input-amount').value,'7');
  element('send-amount-wrap').style.display='none'; sendForm.syncThreadDepositAmount(); assert.equal(element('input-amount').value,'2.5');
  state.navigationState._broadcastReturnScreen=null; setValue('input-amount','9'); sendForm.syncThreadDepositAmount(); assert.equal(element('input-amount').value,'9');

  // Manual UTXO selector: no UTXOs, open/hide, invalid/valid limits, four-way ordering and truncation callbacks.
  element('send-utxo-advanced').classList.add('hidden'); state.networkState.cachedUtxos=[]; sendForm.toggleSendUtxos(); assert.match(element('toast').textContent,/No UTXOs/);
  state.networkState.cachedUtxos=utxos.map(u=>({...u,amount:BigInt(u.amount)})); state.transactionState.selectedUtxoIds=utxos.map(u=>`${u.tx_id}:${u.index}`); setValue('send-utxo-limit','0'); setValue('send-utxo-sort','amount-asc'); sendForm.toggleSendUtxos(); assert.equal(state.transactionState.utxoSelectionLimit,8); assert.equal(state.transactionState.utxoSort,'amount-asc'); assert.match(element('send-utxo-summary').textContent,/manually selected/);
  setValue('send-utxo-limit','1'); element('send-utxo-limit').onchange(); assert.equal(state.transactionState.utxoSelectionLimit,1); assert.equal(state.transactionState.selectedUtxoIds.length,1);
  for (const mode of ['amount-desc','amount-asc','daa-desc','daa-asc']) { setValue('send-utxo-sort',mode); element('send-utxo-sort').onchange(); assert.equal(state.transactionState.utxoSort,mode); } sendForm.toggleSendUtxos(); assert.equal(element('send-utxo-advanced').classList.contains('hidden'),true);

  // Fee cards exercise all levels in standard and covenant mass tiers plus time rendering.
  state.networkState.lastFeeEstimate={low_sompi_per_gram:'1',normal_sompi_per_gram:'2',priority_sompi_per_gram:'3',low_seconds:20,normal_seconds:10,priority_seconds:5}; state.navigationState._broadcastReturnScreen=null;
  for(const level of ['low','normal','priority']){sendForm.setFeeLevel(level); assert.equal(element('btn-fee-'+level).classList.contains('fee-card-active'),true);} sendForm.updateFeeCardAmounts(); assert.equal(element('fee-low-time').textContent,'20s');
  state.navigationState._broadcastReturnScreen='covenant'; sendForm.setFeeLevel('low'); assert.ok(BigInt(element('input-fee').value)>=400000n); sendForm.setFeeLevel('priority'); assert.ok(BigInt(element('input-fee').value)>=500000n); sendForm.updateFeeCardAmounts();
  state.networkState.lastFeeEstimate=null; assert.doesNotThrow(()=>sendForm.setFeeLevel('normal')); assert.doesNotThrow(()=>sendForm.updateFeeCardAmounts());

  // Send-max: absent wallet, selected exact UTXOs, malformed fee fallback, balance path and missing-balance message.
  const saved=state.walletSession.current(); state.walletSession.clear(); setValue('input-amount',''); sendForm.handleSendMax(); assert.equal(element('input-amount').value,''); state.walletSession.replace(saved);
  state.networkState.cachedUtxos=utxos.map(u=>({...u,amount:BigInt(u.amount)})); state.transactionState.selectedUtxoIds=[`${utxos[0].tx_id}:0`]; setValue('input-fee','300000'); sendForm.handleSendMax(); assert.ok(Number(element('input-amount').value)>0);
  state.transactionState.selectedUtxoIds=null; setValue('input-fee','not-integer'); element('balance-kas').textContent='4.0 KAS'; sendForm.handleSendMax(); assert.ok(Number(element('input-amount').value)>0);
  element('balance-kas').textContent='—'; sendForm.handleSendMax(); assert.match(element('toast').textContent,/Refresh balance/);

  // Relay actions cover modal lifecycle, standard PSKB relay, compact relay, encoder failure, AK initialization success/failure.
  const relay=(await import(moduleUrl('features/transactions/pskt_multisig/review_relay.js'))).createPsktRelayActions();
  state.transactionState._psktReviewHex=null; relay.openRelayModal(); relay.handlePsktRelay(); relay.handlePsktRelayCompact();
  state.transactionState._psktReviewHex=PSKB; relay.openRelayModal(); assert.equal(element('relay-choice-modal').classList.contains('hidden'),false); relay.closeRelayModal(); assert.equal(element('relay-choice-modal').classList.contains('hidden'),true); relay.handlePsktRelay(); assert.equal(state.transactionState._currentKsptHex,PSKB);
  wasm.pskt_relay_to_kspt=()=>KSPT; wasm.anti_klepto_begin=()=>JSON.stringify({requestHex:'4b414b500201',hostSecretHex:'aa'.repeat(32)}); wasm.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>ak</svg>'}]); relay.handlePsktRelayCompact(); assert.equal(state.transactionState._currentKsptHex,'4b414b500201');
  wasm.pskt_relay_to_kspt=()=>{throw new Error('compact reject');}; relay.handlePsktRelayCompact();
  wasm.pskt_relay_to_kspt=()=>KSPT; wasm.anti_klepto_begin=()=>JSON.stringify({}); relay.handlePsktRelayCompact();

  // Oracle Model-B finalization: missing roll context, direct txid, sealed+broadcast, lost race, rejection and fetch failure.
  const makeOracleWire=()=>{const j=JSON.stringify({inputs:[{proprietaries:{risc0OracleMb:true}}]}); return Buffer.from('PSKB'+Buffer.from(j).toString('hex')).toString('hex');};
  const finalizer=(await import(moduleUrl('features/transactions/pskt_multisig/review_finalize.js'))).createPsktFinalizer(); const oracleWire=makeOracleWire();
  state.transactionState._psktReviewHex=oracleWire; state.oracleState._oracleMbRoll=null; await finalizer(); assert.equal(state.transactionState._psktReviewHex,null);
  const setRoll=()=>{state.transactionState._psktReviewHex=oracleWire; state.oracleState._oracleMbRoll={acc:'abc',price:'123',t:'456'}; state.oracleState._oracleMbRollActive=true;};
  setRoll(); globalThis.fetch=async()=>({ok:true,status:200,async json(){return {txid:TXID};}}); await finalizer(); assert.equal(element('broadcast-result-txid').textContent,TXID);
  setRoll(); globalThis.fetch=async()=>({ok:true,status:200,async json(){return {sealed:PSKB};}}); wasm.pskt_finalize_and_broadcast=()=>TXID; await finalizer(); assert.equal(element('broadcast-result-txid').textContent,TXID);
  setRoll(); globalThis.fetch=async()=>({ok:true,status:200,async json(){return {sealed:PSKB};}}); wasm.pskt_finalize_and_broadcast=()=>{throw new Error('already spent');}; await finalizer(); assert.equal(state.transactionState._psktReviewHex,null);
  setRoll(); globalThis.fetch=async()=>({ok:false,status:409,async json(){return {status:'lost_race'};}}); await finalizer(); assert.equal(state.transactionState._psktReviewHex,null);
  setRoll(); globalThis.fetch=async()=>({ok:false,status:400,async json(){return {error:'bad roll'};}}); await finalizer(); assert.equal(state.transactionState._psktReviewHex,null);
  setRoll(); globalThis.fetch=async()=>{throw new Error('prover offline');}; await finalizer(); assert.ok(state.transactionState._psktReviewHex,'network failure keeps review available for retry');

  // Core scanner bindings are exercised through their actual click handlers.
  // Keep camera acquisition pending so this test controls the decoded payload
  // deterministically instead of entering the requestAnimationFrame scan loop.
  const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
  navigator.mediaDevices.getUserMedia = () => new Promise(() => {});
  const { bindCoreEvents } = await import(moduleUrl('app/events/system/core.js'));
  bindCoreEvents();
  element('btn-scan-ms-source').onclick();
  assert.match(element('scanner-title').textContent,/P2SH address/);
  state.scannerState.scanCallback(new TextEncoder().encode('not-an-address'));
  assert.notEqual(element('input-ms-source').value,'not-an-address');
  state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS));
  assert.equal(element('input-ms-source').value,ADDRESS);
  element('btn-scan-ms-dest').onclick();
  assert.match(element('scanner-title').textContent,/destination/);
  state.scannerState.scanCallback(new TextEncoder().encode('merchant.kas'));
  assert.equal(element('input-ms-dest').value,'merchant.kas');
  element('btn-scan-ms-descriptor').onclick();
  assert.match(element('scanner-title').textContent,/descriptor QR/);
  assert.equal(typeof state.scannerState.scanCallback,'function');
  navigator.mediaDevices.getUserMedia = originalGetUserMedia;

  assertWatchOnlyStorage(); console.log('PASS: deep transaction review/send-form/relay/oracle-finalize/core-scanner paths');
} finally { await cleanupDeepHarness(); }
