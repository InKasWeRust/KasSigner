import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick, setFetchHook,
  ADDRESS, BENEFICIARY, PK, PK2, PK3, SIG, TXID, TXID2, PSKB, COV_ID, wallet,
  covenantResult, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const commitInputs = await import(moduleUrl('app/events/contracts/covenant_specialized/commit_reveal/input_events.js'));
  const commitVerify = await import(moduleUrl('app/events/contracts/covenant_specialized/commit_reveal/verification.js'));
  const ksptStatus = await import(moduleUrl('features/transactions/send/kspt_status.js'));
  const covenantPlanner = await import(moduleUrl('features/transactions/send/compose/planners/covenant.js'));
  const psktFinalize = await import(moduleUrl('features/transactions/pskt_multisig/review_finalize.js'));
  const broadcast = await import(moduleUrl('features/transactions/send/broadcast.js'));
  const covReturn = await import(moduleUrl('features/covenants/scanning/return.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  // Commit/reveal UI consumes device commitment and decrypted-preimage QR data,
  // invalidates stale DAA values, and exposes the encrypted secret back to the signer.
  commitInputs.bindCommitRevealInputEvents();
  setValue('cov-cr-locktime','1234'); element('cov-cr-datetime').dispatch('input'); assert.equal(element('cov-cr-locktime').value,'');
  state.commitRevealState._crDecryptCtBytes=null; element('btn-cov-cr-show-ct-qr').onclick(); assert.match(element('toast').textContent,/No ciphertext/);
  state.commitRevealState._crDecryptCtBytes=new Uint8Array(61).fill(0x42); element('btn-cov-cr-show-ct-qr').onclick(); assert.ok(document.body.children.some(child=>child.id==='cr-ct-overlay'));
  const oldQr=stubs.generate_qr_svg_text; stubs.generate_qr_svg_text=()=>{throw new Error('QR fail')}; element('btn-cov-cr-show-ct-qr').onclick(); assert.match(element('toast').textContent,/QR generation failed/); stubs.generate_qr_svg_text=oldQr;
  element('btn-cov-cr-scan-commitment').onclick(); state.scannerState.scanCallback(new Uint8Array(20)); assert.match(element('toast').textContent,/too short/);
  const commitment=new Uint8Array(93); commitment.fill(0x11,0,32); commitment.fill(0x22,32); element('btn-cov-cr-scan-commitment').onclick(); state.scannerState.scanCallback(commitment); assert.equal(element('cov-cr-ciphertext-hex').value.length,122); assert.match(element('cov-cr-hash-display').textContent,/BLAKE2B/);
  element('btn-cov-cr-scan-preimage').onclick(); state.scannerState.scanCallback(new TextEncoder().encode('zz')); assert.match(element('toast').textContent,/Invalid preimage/);
  element('btn-cov-cr-scan-preimage').onclick(); state.scannerState.scanCallback(new TextEncoder().encode('aabbcc')); assert.equal(state.commitRevealState._crRevealPartA,'aabbcc'); assert.match(element('cov-cr-preimage-status').textContent,/3 bytes/);
  state.commitRevealState._crDecryptCtBytes=new Uint8Array(61); element('btn-cov-cr-reveal-back').onclick(); assert.equal(state.commitRevealState._crDecryptCtBytes,null);

  // Transaction verification parses real signature-script push structure, strips
  // the eight-byte salt for display, and compares the script-pinned hash.
  const push=bytes=>Buffer.concat([Buffer.from([bytes.length]),Buffer.from(bytes)]);
  const salt=Buffer.from('0102030405060708','hex'), text=Buffer.from('runtime-secret','utf8');
  const partA=Buffer.concat([salt,text.slice(0,4)]), partB=text.slice(4); const committed=Buffer.from(PK3,'hex');
  const redeem=Buffer.concat([Buffer.from('7eaa20','hex'),committed,Buffer.from('51','hex')]);
  const sigScript=Buffer.concat([push(partA),push(partB),push(Buffer.from(SIG,'hex')),Buffer.from([0]),push(redeem)]).toString('hex');
  stubs.blake2b_hash=()=>PK3;
  let verified=commitVerify.verifyCommitRevealTransaction({inputs:[{signature_script:sigScript}],block_time:1700000000000}); assert.equal(verified.preimageText,'runtime-secret'); assert.equal(verified.matches,true); assert.equal(verified.committedHash,PK3);
  stubs.blake2b_hash=()=>PK2; verified=commitVerify.verifyCommitRevealTransaction({inputs:[{signature_script:sigScript,previous_outpoint_resolved_daa_score:'900'}]}); assert.equal(verified.matches,false); assert.match(verified.timestamp,/DAA: 900/);
  assert.throws(()=>commitVerify.verifyCommitRevealTransaction({inputs:[{signature_script:'00'}]}),/No sig_script/);
  const shortScript=Buffer.concat([push(Buffer.from('01020304','hex')),push(Buffer.from('05','hex')),push(Buffer.from(SIG,'hex')),Buffer.from([0]),push(redeem)]).toString('hex'); assert.throws(()=>commitVerify.verifyCommitRevealTransaction({inputs:[{signature_script:shortScript}]}),/8-byte salt/);
  const badRedeem=Buffer.from('51','hex'); const badScript=Buffer.concat([push(partA),push(partB),push(Buffer.from(SIG,'hex')),Buffer.from([0]),push(badRedeem)]).toString('hex'); assert.throws(()=>commitVerify.verifyCommitRevealTransaction({inputs:[{signature_script:badScript}]}),/missing the current hash sequence/);



  // Compact KSPT status inspection covers header flags/version, compact script
  // lengths, complete/partial/unsigned input state, and every truncation guard.
  const toHex=bytes=>Buffer.from(bytes).toString('hex');
  const makeKspt=({signed=false,extended=false,truncate=0}={})=>{
    const bytes=new Uint8Array(extended?112:110); bytes.set(Buffer.from('KSPT')); bytes[4]=4; bytes[5]=0; bytes[8]=1; bytes[49]=0; bytes[50]=0;
    if(extended){bytes[106]=0xff;bytes[107]=0;bytes[108]=0;bytes[109]=signed?1:0;bytes[110]=0;bytes[111]=0;}
    else{bytes[106]=0;bytes[107]=signed?1:0;bytes[108]=0;bytes[109]=0;}
    return toHex(truncate?bytes.slice(0,bytes.length-truncate):bytes);
  };
  assert.equal(ksptStatus.inspectKsptSignatureStatus('00'),'unknown'); assert.equal(ksptStatus.inspectKsptSignatureStatus('4b5350540401'),'signed'); assert.equal(ksptStatus.inspectKsptSignatureStatus('4b5350540402'),'unknown'); assert.equal(ksptStatus.inspectKsptSignatureStatus('4b5350540300'),'unsupported');
  assert.equal(ksptStatus.inspectKsptSignatureStatus(makeKspt()),'unsigned'); assert.equal(ksptStatus.inspectKsptSignatureStatus(makeKspt({signed:true})),'partial'); assert.equal(ksptStatus.inspectKsptSignatureStatus(makeKspt({extended:true})),'unsigned'); assert.equal(ksptStatus.inspectKsptSignatureStatus(makeKspt({truncate:10})),'unknown');
  const malformedKspt = size => { const b=new Uint8Array(size); b.set(Buffer.from('KSPT')); b[4]=4; b[5]=0; b[8]=1; return b; };
  let kb=malformedKspt(106); assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unknown'); // compact length offset at EOF
  kb=malformedKspt(107); kb[106]=0xff; assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unknown'); // extended length truncated
  kb=malformedKspt(108); kb[106]=1; kb[107]=0xaa; assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unknown'); // missing signature count
  kb=malformedKspt(110); kb[106]=0; kb[107]=0xff; kb[108]=0; kb[109]=0; assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unsigned');
  kb=malformedKspt(109); kb[106]=0; kb[107]=0; kb[108]=0; assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unknown'); // missing redeem length byte
  kb=malformedKspt(110); kb[106]=0; kb[107]=0; kb[108]=5; kb[109]=0; assert.equal(ksptStatus.inspectKsptSignatureStatus(toHex(kb)),'unknown'); // redeem overruns wire
  assert.equal(ksptStatus.inspectKsptSignatureStatus('4b5350540400zz'),'unknown');

  // Covenant deposit planner exercises insufficient/folded additive deposits,
  // DMS dust folding, global-thread top-up safety, and the no-payload builder.
  state.networkState.cachedUtxos=[{tx_id:TXID,index:0,amount:'250000000',block_daa_score:'900'}]; state.networkState.utxoSnapshot=structuredClone(state.networkState.cachedUtxos);
  const select=enabled=>{state.transactionState.selectedUtxoIds=enabled?[`${TXID}:0`]:[];};
  state.covenantState.activeCovenants=[]; state.covenantState.lastCovenantResult={...covenantResult('additive'),type:'additive'}; select(false); assert.equal(await covenantPlanner.planCovenant(ADDRESS,'1','300000'),null); assert.match(element('toast').textContent,/Pick the wallet UTXO/);
  state.networkState.cachedUtxos[0].amount='1000'; select(true); { const previous=stubs.create_covenant_pskb_with_payload; stubs.create_covenant_pskb_with_payload=()=>{throw new Error('Selected UTXOs do not cover the fee');}; await assert.rejects(()=>covenantPlanner.planCovenant(ADDRESS,'0.000001','300000'),/do not cover the fee/); stubs.create_covenant_pskb_with_payload=previous; }
  state.networkState.cachedUtxos[0].amount='105000000'; select(true); stubs.create_covenant_pskb_with_payload=()=>PSKB; let plan=await covenantPlanner.planCovenant(ADDRESS,'1','300000'); assert.equal(plan?.pskbHex,PSKB);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms'}; state.networkState.cachedUtxos[0].amount='105000000'; plan=await covenantPlanner.planCovenant(ADDRESS,'1','300000'); assert.equal(plan?.pskbHex,PSKB);
  state.covenantState.lastCovenantResult={...covenantResult('global-spending-limit'),type:'global-spending-limit',covenant_id_hex:COV_ID}; stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID2,index:1,amount:'100000000',block_daa_score:'900',covenant_id:COV_ID}]); stubs.create_global_spending_limit_topup=()=>PSKB; select(false); assert.equal(await covenantPlanner.planCovenant(ADDRESS,'1','300000'),null); assert.match(element('toast').textContent,/Pick the wallet UTXO/);
  select(true); plan=await covenantPlanner.planCovenant(ADDRESS,'1','300000'); assert.equal(plan?.completed,true); assert.equal(state.navigationState._broadcastReturnScreen,'covenant');
  state.covenantState.lastCovenantResult={...covenantResult('global-spending-limit'),type:'global-spending-limit',covenant_id_hex:''}; stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'1',covenant_id:'aa'.repeat(32)},{tx_id:TXID2,index:1,amount:'1',covenant_id:'bb'.repeat(32)}]); plan=await covenantPlanner.planCovenant(ADDRESS,'1','300000'); assert.equal(plan,null); assert.match(element('toast').textContent,/Multiple covenant-tagged/);
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51',type:'unknown'}; stubs.fetch_utxos_for_address_js=()=> '[]'; stubs.create_covenant_pskb=()=>PSKB; plan=await covenantPlanner.planCovenant(ADDRESS,'1','300000'); assert.equal(plan.pskbHex,PSKB); assert.equal(state.covenantState._covPayloadHex,'');



  // Finalization and post-broadcast return behavior is tested at the actual
  // UI/protocol boundaries: malformed/non-oracle envelopes, array-form oracle
  // PSKT, prover JSON failure, generic sealed broadcast failure, reason/HTTP
  // rejection messages, standard PSKT summary fallbacks, and covenant watcher
  // restart state after a real transaction id is displayed.
  const oracleWire = decoded => Buffer.from('PSKB' + Buffer.from(JSON.stringify(decoded)).toString('hex')).toString('hex');
  const oracleObject = {inputs:[{proprietaries:{risc0OracleMb:true}}]};
  const finalizer = psktFinalize.createPsktFinalizer();
  state.transactionState._psktReviewHex='50534b42zz'; stubs.pskt_summary=()=>'{'; stubs.pskt_finalize_and_broadcast=()=>TXID; await finalizer(); assert.equal(element('broadcast-result-txid').textContent,TXID);
  const setOracleRoll=(wire=oracleWire([oracleObject]))=>{state.transactionState._psktReviewHex=wire; state.oracleState._oracleMbRoll={acc:'acc',price:'7',t:'8'};state.oracleState._oracleMbRollActive=true;};
  setOracleRoll(); setFetchHook(async()=>({ok:false,status:503,async json(){throw new Error('not json')}})); await finalizer(); assert.match(element('toast').textContent,/HTTP 503/);
  setOracleRoll(); setFetchHook(async()=>({ok:false,status:422,async json(){return {reason:'stale proof'}}})); await finalizer(); assert.match(element('toast').textContent,/stale proof/);
  setOracleRoll(); setFetchHook(async()=>({ok:true,status:200,async json(){return {sealed:PSKB}}})); stubs.pskt_finalize_and_broadcast=()=>{throw new Error('node unavailable')}; await finalizer(); assert.match(element('toast').textContent,/could not be broadcast/);
  stubs.pskt_finalize_and_broadcast=()=>TXID;

  // Broadcast renderer invokes and clears a one-shot post-broadcast hook.
  let postBroadcast=''; state.covenantState._kasFreezePathCPostBroadcast=id=>{postBroadcast=id;}; broadcast.showBroadcastSuccess(TXID2); assert.equal(postBroadcast,TXID2); assert.equal(state.covenantState._kasFreezePathCPostBroadcast,null);

  // Covenant return handles oracle short-circuit, empty result, valid watched
  // outpoint, invalid txid, metadata/address/script fallbacks, and watcher reset.
  state.oracleState._oracleMbReturn=true; covReturn.covReturnAfterBroadcast(); assert.equal(state.oracleState._oracleMbReturn,false);
  state.covenantState.lastCovenantResult=null; covReturn.covReturnAfterBroadcast();
  state.covenantState.lastCovenantResult={...covenantResult('dms'),address:'',redeem_script_hex:'',type:'dms'};
  element('broadcast-result-txid').textContent=TXID; state.covenantWatcherState._covWatcherOutpoint=null; covReturn.covReturnAfterBroadcast(); assert.equal(element('cov-result-txid').textContent,TXID); assert.equal(state.covenantWatcherState._covWatcherOutpoint,null);
  element('broadcast-result-txid').textContent='short'; covReturn.covReturnAfterBroadcast();

  assertWatchOnlyStorage();
  console.log('PASS: commit-reveal/KSPT edge workflows and covenant deposit safety paths');
} finally {
  await cleanupDeepHarness();
}
