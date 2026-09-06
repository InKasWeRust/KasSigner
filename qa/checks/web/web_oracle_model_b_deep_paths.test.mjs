import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setFetchHook,
  intervals, ADDRESS, CHANGE, PK, PK2, PK3, TXID, TXID2, wallet, psktSummary,
  assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state, response } = await setupDeepHarness();
try {
  const oracleV1Attestation = await import(moduleUrl('features/oracle/v1/attestation.js'));
  const covenantSignProtocol = await import(moduleUrl('features/covenants/signing/protocol.js'));
  const oracleV1Statement = 'KasSigner Oracle v1 00112233445566778899aabbccddeeff: Release invoice 42';
  const oracleV1Commitment = createHash('sha256').update(Buffer.from(oracleV1Statement, 'utf8')).digest('hex');
  assert.equal(await oracleV1Attestation.oracleV1MessageCommitment(oracleV1Statement), oracleV1Commitment);
  const responseHex = covenantSignProtocol.covenantSignatureResponseHex({
    sessionId: '01'.repeat(16), keyId: '02'.repeat(32), pubkey: '03'.repeat(32),
    bindingToken: '05'.repeat(32), commitment: oracleV1Commitment,
    noncePoint: `02${'04'.repeat(32)}`, signature: '11'.repeat(64),
  });
  const parsedAttestation = oracleV1Attestation.parseOracleV1Attestation(Buffer.from(responseHex, 'hex'));
  assert.equal(parsedAttestation.signature, '11'.repeat(64));
  assert.equal(parsedAttestation.commitment, oracleV1Commitment);
  assert.equal(parsedAttestation.bindingToken, '05'.repeat(32));
  await oracleV1Attestation.verifyOracleV1Attestation(parsedAttestation, oracleV1Statement);
  await assert.rejects(
    oracleV1Attestation.verifyOracleV1Attestation(parsedAttestation, `${oracleV1Statement} changed`),
    /exact statement/,
  );
  assert.throws(() => oracleV1Attestation.parseOracleV1Attestation(Buffer.alloc(96)), /current KasSigner covenant response/);
  assert.throws(() => oracleV1Attestation.parseOracleV1Attestation(Buffer.from(JSON.stringify({ signature: '11'.repeat(64), commitment: oracleV1Commitment }))), /current KasSigner covenant response/);

  const protocolMod = await import(moduleUrl('features/oracle/model_b/protocol.js'));
  const configMod = await import(moduleUrl('features/oracle/model_b/config.js'));
  const identityMod = await import(moduleUrl('features/oracle/model_b/state.js'));
  const validation = await import(moduleUrl('features/oracle/model_b/controller/proving/validation.js'));
  const clientMod = await import(moduleUrl('features/oracle/model_b/controller/proving/client.js'));
  const feeMod = await import(moduleUrl('features/oracle/model_b/controller/proving/fee.js'));
  const skeletonMod = await import(moduleUrl('features/oracle/model_b/controller/proving/skeleton.js'));
  const countdownMod = await import(moduleUrl('features/oracle/model_b/controller/proving/countdown.js'));
  const renderMod = await import(moduleUrl('features/oracle/model_b/controller/polling/render.js'));
  const refreshMod = await import(moduleUrl('features/oracle/model_b/controller/polling/refresh.js'));
  const watcherMod = await import(moduleUrl('features/oracle/model_b/controller/polling/block_watcher.js'));
  const provingMod = await import(moduleUrl('features/oracle/model_b/controller/proving.js'));
  const { ORACLE_MB_PROTOCOL, ORACLE_MB_DEPLOY } = configMod;
  const { oracleMbIdentity } = identityMod;
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  const le64 = value => {
    let n = BigInt(value), out = '';
    for (let index = 0; index < 8; index += 1) {
      out += Number(n & 0xffn).toString(16).padStart(2, '0');
      n >>= 8n;
    }
    return out;
  };
  const validPskb = outputs => {
    const bundle = [{ outputs, inputs: [], global: {} }];
    const jsonHex = Buffer.from(JSON.stringify(bundle), 'utf8').toString('hex');
    return Buffer.from(`PSKB${jsonHex}`, 'utf8').toString('hex');
  };
  const setOracleIdentity = () => {
    oracleMbIdentity.heartbeatAddress = ORACLE_MB_DEPLOY.heartbeatAddress;
    oracleMbIdentity.heartbeatCovIdH = ORACLE_MB_DEPLOY.heartbeatCovIdH;
    oracleMbIdentity.oracleCovIdG = ORACLE_MB_DEPLOY.oracleCovIdG;
  };

  // Protocol identity is mandatory and all numeric values cross the WASM boundary
  // as exact unsigned decimal strings.
  oracleMbIdentity.heartbeatCovIdH = null;
  assert.throws(() => protocolMod.oracleMbOracleAddress(42n, 100n), /heartbeatCovIdH/);
  setOracleIdentity();
  let oracleBuildRequest = null;
  stubs.covenant_oracle_mb = raw => {
    oracleBuildRequest = JSON.parse(raw);
    return JSON.stringify({ address: ADDRESS, redeem_script_hex: '51', redeem_len: 1 });
  };
  const derived = protocolMod.oracleMbOracleAddress(42n, 100n);
  assert.equal(derived.address, ADDRESS);
  assert.equal(oracleBuildRequest.genesis_price, '42');
  assert.equal(oracleBuildRequest.genesis_t, '100');
  assert.equal(oracleBuildRequest.heartbeat_cov_id_hex, ORACLE_MB_DEPLOY.heartbeatCovIdH);
  assert.equal(oracleMbIdentity.oracleAddress, ADDRESS);

  let publishRequest = null;
  stubs.create_oracle_mb_publish = raw => { publishRequest = JSON.parse(raw); return 'oracle-publish-pskb'; };
  const published = await protocolMod.oracleMbPublish({
    walletJson: JSON.stringify(wallet), oracleAddress: ADDRESS, oracleRedeemHex: '51', covenantIdG: PK3,
    seal: 'aa', claim: 'bb', controlIndex: 'cc', controlDigests: 'dd', journal: 'ee',
    fee: 1234567890123456789n, changeAddress: CHANGE, omitHeartbeat: true,
  });
  assert.equal(published, 'oracle-publish-pskb');
  assert.equal(publishRequest.fee, '1234567890123456789');
  assert.equal(publishRequest.omit_heartbeat, true);
  assert.equal(publishRequest.change_address, CHANGE);
  assert.match(publishRequest.ws_url, /^wss:/);

  // Discovery rejects each missing trust anchor and parses a valid 48-byte
  // journal from the longest oracle input without losing u64 precision.
  oracleMbIdentity.heartbeatAddress = null;
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /heartbeatAddress/);
  setOracleIdentity();
  stubs.fetch_utxos_for_address_js = () => '[]';
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /no heartbeat UTXO/);
  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ amount: '1' }]);
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /could not read.*txid/i);
  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ tx_id: TXID, transactionId: TXID, index: 0, amount: '1' }]);
  setFetchHook(async () => response({ status: 503, json: {} }));
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /roll tx fetch failed: 503/);
  setFetchHook(async () => response({ json: { inputs: [], outputs: [] } }));
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /missing inputs\/outputs/);
  setFetchHook(async () => response({ json: { inputs: [{ signatureScript: '' }], outputs: [{ scriptPublicKey: '51' }] } }));
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /no signatureScript/);
  setFetchHook(async () => response({ json: { inputs: [{ signatureScript: '00'.repeat(60) }], outputs: [{ scriptPublicKey: '51' }] } }));
  await assert.rejects(protocolMod.oracleMbDiscoverAndRead(), /journal.*not found/i);
  const journalPrice = 18_446_744_073_709_551_000n;
  const journalTime = 4_294_967_299n;
  const sigScript = `30${le64(journalPrice)}${le64(journalTime)}${ORACLE_MB_PROTOCOL.setRootHex}`;
  setFetchHook(async () => response({ json: {
    inputs: [{ signatureScript: '00' }, { signature_script: sigScript }],
    outputs: [{ scriptPublicKey: { scriptPublicKey: '000051' } }],
  } }));
  const discovery = await protocolMod.oracleMbDiscoverAndRead();
  assert.equal(discovery.price, journalPrice);
  assert.equal(discovery.t, journalTime);
  assert.equal(discovery.rollTxid, TXID);
  assert.equal(discovery.expectedOracleAddress, ADDRESS);

  // Quote validation rejects protocol drift, and live-roll detection is exact
  // and fail-closed on transport errors.
  assert.match(validation.validateOracleQuote({ ok: false, status: 500 }, ORACLE_MB_PROTOCOL), /HTTP 500/);
  assert.match(validation.validateOracleQuote({ ok: true, body: { error: 'keeper down' } }, ORACLE_MB_PROTOCOL), /keeper down/);
  assert.match(validation.validateOracleQuote({ ok: true, body: { acc: 'a' } }, ORACLE_MB_PROTOCOL), /incomplete/i);
  assert.match(validation.validateOracleQuote({ ok: true, body: { acc: 'a', price: 1, publish_time: 2, set_root: PK } }, ORACLE_MB_PROTOCOL), /set_root mismatch/);
  assert.match(validation.validateOracleQuote({ ok: true, body: { acc: 'a', price: 1, publish_time: 2, set_root: ORACLE_MB_PROTOCOL.setRootHex, fee_address: ADDRESS } }, ORACLE_MB_PROTOCOL), /fee address changed/i);
  assert.equal(validation.validateOracleQuote({ ok: true, body: { acc: 'a', price: 1, publish_time: 2, set_root: ORACLE_MB_PROTOCOL.setRootHex, fee_address: ORACLE_MB_PROTOCOL.feeAddress } }, ORACLE_MB_PROTOCOL), null);
  assert.equal(await validation.oracleAlreadyMoved(null, oracleMbIdentity.heartbeatAddress), false);
  assert.equal(await validation.oracleAlreadyMoved({ rollTxid: TXID }, ''), false);
  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ tx_id: TXID, index: 0 }]);
  assert.equal(await validation.oracleAlreadyMoved({ rollTxid: TXID.toUpperCase() }, oracleMbIdentity.heartbeatAddress), false);
  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ tx_id: TXID2, index: 0 }]);
  assert.equal(await validation.oracleAlreadyMoved({ rollTxid: TXID }, oracleMbIdentity.heartbeatAddress), true);
  stubs.fetch_utxos_for_address_js = () => { throw new Error('node unavailable'); };
  assert.equal(await validation.oracleAlreadyMoved({ rollTxid: TXID }, oracleMbIdentity.heartbeatAddress), false);

  // Prover client preserves HTTP status and tolerates a non-JSON response.
  setFetchHook(async () => ({ ok: true, status: 200, async json() { return { quote: 1 }; } }));
  const proverGet = clientMod.createOracleProverClient('https://keeper.example///');
  assert.deepEqual(await proverGet('/quote'), { ok: true, status: 200, body: { quote: 1 } });
  setFetchHook(async () => ({ ok: false, status: 502, async json() { throw new Error('not json'); } }));
  assert.deepEqual(await proverGet('/quote'), { ok: false, status: 502, body: null });

  // Fee splicing is byte-preserving around the PSKB envelope and appends the
  // exact configured service-fee output. Invalid envelopes/empty outputs fail.
  assert.throws(() => feeMod.spliceOracleServiceFee('00', ORACLE_MB_PROTOCOL), /not a PSKB/);
  assert.throws(() => feeMod.spliceOracleServiceFee(validPskb([]), ORACLE_MB_PROTOCOL), /no outputs/);
  const feeWire = feeMod.spliceOracleServiceFee(validPskb([{ amount: '100', scriptPublicKey: '51', proprietaries: {} }]), ORACLE_MB_PROTOCOL);
  const feeBytes = Buffer.from(feeWire, 'hex').toString('utf8');
  const feeBundle = JSON.parse(Buffer.from(feeBytes.slice(4), 'hex').toString('utf8'));
  assert.equal(feeBundle[0].outputs.at(-1).amount, ORACLE_MB_PROTOCOL.feeSompi.toString());
  assert.equal(feeBundle[0].outputs.at(-1).scriptPublicKey, ORACLE_MB_PROTOCOL.feeSpk);

  const feeButtons = ['1', '2'].map(value => {
    const button = document.createElement('button'); button.classList.add('omb-fee-btn'); button.setAttribute('data-omb-fee', value); return button;
  });
  const oldQuerySelectorAll = document.querySelectorAll;
  document.querySelectorAll = selector => selector === '.omb-fee-btn' ? feeButtons : oldQuerySelectorAll.call(document, selector);
  const oldFee = state.oracleState._oracleMbFeeTotalKas;
  feeMod.setOracleFee('bad', false); assert.equal(state.oracleState._oracleMbFeeTotalKas, oldFee);
  feeMod.setOracleFee('0.5', false); assert.equal(state.oracleState._oracleMbFeeTotalKas, oldFee);
  feeMod.setOracleFee('1', false); assert.equal(state.oracleState._oracleMbFeeTotalKas, '1'); assert.match(element('btn-oracle-mb-ask').textContent, /≈1 KAS/); assert.equal(feeButtons[0].style.background, 'var(--teal)');
  feeMod.setOracleFee('2', true); assert.equal(state.oracleState._oracleMbFeeTotalKas, '2'); assert.equal(feeButtons[1].style.background, 'var(--bg)');
  document.querySelectorAll = oldQuerySelectorAll;

  // Countdown is driven through the real interval callback: hidden outside a
  // signing review, created next to Finalize during proving, and distinguishes
  // active proving from the post-deadline/auto-broadcast state.
  const beforeIntervals = new Set(intervals.keys());
  countdownMod.startOracleMbCountdown();
  const countdownId = [...intervals.keys()].find(id => !beforeIntervals.has(id))
    ?? [...intervals.entries()].find(([, callback]) => callback.toString().includes('updateCountdown'))?.[0];
  assert.ok(countdownId !== undefined, 'oracle countdown owns an interval callback');
  const runCountdown = intervals.get(countdownId);
  const review = element('pskt-review'); review.classList.add('hidden'); review.style.display = 'none';
  state.oracleState._oracleMbPreSignAwaiting = false; runCountdown();
  const parent = document.createElement('div'); document.body.appendChild(parent);
  const finalize = element('btn-pskt-finalize'); parent.appendChild(finalize); finalize.parentNode = parent;
  review.classList.remove('hidden'); review.style.display = 'block'; state.oracleState._oracleMbPreSignAwaiting = true;
  state.oracleState._oracleMbAutoBroadcast = false; state.oracleState._oracleMbProveDeadline = Date.now() + 2500; runCountdown();
  const countdown = document.getElementById('oracle-mb-countdown'); assert.match(countdown.textContent, /auto-broadcast in ~[123]s/); assert.equal(countdown.style.display, 'block');
  state.oracleState._oracleMbAutoBroadcast = true; state.oracleState._oracleMbProveDeadline = Date.now() - 1; runCountdown(); assert.match(countdown.textContent, /Proof finishing/);
  state.oracleState._oracleMbPreSignAwaiting = false; state.oracleState._oracleMbAutoBroadcast = false; runCountdown(); assert.equal(countdown.style.display, 'none');

  // Rendering and refresh lifecycle cover cached/live state, node-unreachable
  // fallback, timer creation/cleanup, and block watcher ownership.
  const rendering = renderMod.createOracleRendering();
  state.oracleState._oracleMbState = null; rendering.oracleMbRenderAge(); rendering.oracleMbRenderState();
  state.oracleState._oracleMbState = { price: 123456789n, t: BigInt(Math.floor(Date.now()/1000)), rollTxid: TXID, addr: ADDRESS };
  rendering.oracleMbRenderState();
  assert.match(element('oracle-mb-price').textContent, /1\.23456789/); assert.ok(element('oracle-mb-addr').textContent.length > 0); assert.ok(element('oracle-mb-rolltx').textContent.length > 0);
  let rendered=0, watcherStarts=0, watcherStops=0;
  const refresh = refreshMod.createOracleRefresh({
    oracleMbRenderAge: () => { rendered += 1; }, oracleMbRenderState: () => { rendered += 1; },
    oracleMbBlockWatcherStart: () => { watcherStarts += 1; }, oracleMbBlockWatcherStop: () => { watcherStops += 1; },
  });
  setOracleIdentity();
  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ tx_id: TXID, transactionId: TXID, index: 0 }]);
  state.oracleState._oracleMbState = { price: 1n, t: 2n, rollTxid: TXID2, addr: ADDRESS }; state.oracleState._oracleMbPriceTs = Date.now();
  await refresh.oracleMbPollOnce(); assert.equal(state.oracleState._oracleMbState.rollTxid, TXID); assert.ok(rendered > 0);
  stubs.fetch_utxos_for_address_js = () => '[]'; await refresh.oracleMbPollOnce();
  state.oracleState._oracleMbState = null; setFetchHook(async () => response({ status:500, json:{} })); await refresh.oracleMbCardRefresh(); assert.match(element('oracle-mb-age').textContent,/node unreachable/);
  state.oracleState._oracleMbState = { price: 1n, t: 2n, rollTxid: TXID, addr: ADDRESS }; refresh.oracleMbCardOpen(); assert.equal(watcherStarts,1); assert.ok(state.oracleState._oracleMbAgeTimer); assert.ok(state.oracleState._oracleMbPollTimer); refresh.oracleMbAmbientStop(); assert.equal(watcherStops,1); assert.equal(state.oracleState._oracleMbAgeTimer,null); assert.equal(state.oracleState._oracleMbPollTimer,null);

  // BlockAdded transport is exercised with real payload parsing: malformed
  // frames are ignored, a valid journal updates price/T/address once, duplicate
  // notifications are idempotent, and stop closes the socket.
  const sockets=[];
  class CapturingWebSocket {
    constructor(url) { this.url=String(url); this.readyState=0; sockets.push(this); queueMicrotask(()=>{this.readyState=1; this.onopen?.();}); }
    send(data) { this.sent=data; }
    close() { this.readyState=3; this.onclose?.(); }
  }
  globalThis.WebSocket = CapturingWebSocket;
  setOracleIdentity(); state.oracleState._oracleMbAgeTimer = 777; state.oracleState._oracleMbState = { price: 1n, t: 2n, rollTxid: TXID, addr: ADDRESS };
  let blockRenders=0; const blockWatcher=watcherMod.createOracleBlockWatcher(()=>{blockRenders += 1;}); blockWatcher.oracleMbBlockWatcherStart(); await new Promise(resolve=>setImmediate(resolve));
  assert.equal(sockets.length,1); assert.ok(sockets[0].sent instanceof Uint8Array);
  sockets[0].onmessage?.({data:new Uint8Array(20).buffer}); assert.equal(blockRenders,0);
  const payload=new Uint8Array(66); payload[0]=0x01; payload[9]=0xff; payload[11]=0x3c; payload[17]=0x30;
  const priceBytes=Buffer.from(le64(700000000n),'hex'), timeBytes=Buffer.from(le64(9000n),'hex'), rootBytes=Buffer.from(ORACLE_MB_PROTOCOL.setRootHex,'hex'); payload.set(priceBytes,18); payload.set(timeBytes,26); payload.set(rootBytes,34);
  sockets[0].onmessage?.({data:payload.buffer}); assert.equal(state.oracleState._oracleMbState.price,700000000n); assert.equal(state.oracleState._oracleMbState.t,9000n); assert.equal(blockRenders,1);
  sockets[0].onmessage?.({data:payload.buffer}); assert.equal(blockRenders,1,'duplicate price/t does not rerender'); blockWatcher.oracleMbBlockWatcherStop(); assert.equal(sockets[0].readyState,3);

  // Skeleton and Ask-for-new cover missing wallet/state, service-fee failure,
  // fresh/stale/moved/invalid/unreachable quote paths, and a successful roll
  // that ends in unsigned PSKB review for KasSigner.
  const messages=[]; const show=(msg)=>messages.push(String(msg)); let ambientStops=0;
  const savedWallet=state.walletSession.current(); state.walletSession.clear(); state.oracleState._oracleMbState={price:1n,t:2n,rollTxid:TXID,addr:ADDRESS};
  assert.equal(await skeletonMod.openOracleSkeleton({identity:oracleMbIdentity,protocol:ORACLE_MB_PROTOCOL,journalHex:'00',ambientStop:()=>ambientStops++,show}),false); assert.match(messages.at(-1),/Unlock/); state.walletSession.replace(savedWallet);
  state.oracleState._oracleMbState=null; assert.equal(await skeletonMod.openOracleSkeleton({identity:oracleMbIdentity,protocol:ORACLE_MB_PROTOCOL,journalHex:'00',ambientStop:()=>ambientStops++,show}),false); assert.match(messages.at(-1),/current oracle/);
  state.oracleState._oracleMbState={price:1n,t:2n,rollTxid:TXID,addr:ADDRESS}; stubs.create_oracle_mb_publish=()=> '50534b42'; assert.equal(await skeletonMod.openOracleSkeleton({identity:oracleMbIdentity,protocol:ORACLE_MB_PROTOCOL,journalHex:'00',ambientStop:()=>ambientStops++,show}),false); assert.match(messages.at(-1),/service fee/);
  stubs.create_oracle_mb_publish=()=>validPskb([{amount:'100000000',scriptPublicKey:'51',proprietaries:{}}]); stubs.pskt_summary=()=>JSON.stringify(psktSummary());
  assert.equal(await skeletonMod.openOracleSkeleton({identity:oracleMbIdentity,protocol:ORACLE_MB_PROTOCOL,journalHex:'00',ambientStop:()=>ambientStops++,show}),true); assert.equal(state.oracleState._oracleMbRollActive,true); assert.ok(state.transactionState._psktReviewHex); assert.ok(ambientStops>0);

  const dependencyState={ mode:'fresh' };
  const dependencies={
    async oracleMbCardRefresh(){
      if(dependencyState.mode==='none'){state.oracleState._oracleMbState=null;return;}
      const now=Math.floor(Date.now()/1000);
      state.oracleState._oracleMbState={price:100n,t:BigInt(dependencyState.mode==='fresh'?now:now-300),rollTxid:TXID,addr:ADDRESS};
    },
    oracleMbAmbientStop(){ambientStops += 1;},
  };
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0}]);
  let quoteMode='valid';
  setFetchHook(async url=>{
    if(String(url).endsWith('/quote')){
      if(quoteMode==='throw') throw new Error('keeper offline');
      if(quoteMode==='mismatch') return response({json:{acc:'a',price:'101',publish_time:Math.floor(Date.now()/1000),set_root:PK,fee_address:ORACLE_MB_PROTOCOL.feeAddress}});
      return response({json:{acc:'a',price:'101',publish_time:Math.floor(Date.now()/1000),set_root:ORACLE_MB_PROTOCOL.setRootHex,fee_address:ORACLE_MB_PROTOCOL.feeAddress}});
    }
    return response({json:{}});
  });
  const proving=provingMod.createOracleProving(dependencies);
  dependencyState.mode='fresh'; await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/Price is fresh/); assert.equal(state.oracleState._oracleMbAskBusy,false);
  dependencyState.mode='none'; await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/Could not read/);
  dependencyState.mode='stale'; stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID2,index:0}]); await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/already moved/);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0}]); quoteMode='throw'; await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/Prover unreachable/);
  quoteMode='mismatch'; await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/set_root mismatch/);
  quoteMode='valid'; stubs.create_oracle_mb_publish=()=>validPskb([{amount:'100000000',scriptPublicKey:'51',proprietaries:{}}]); await proving.oracleMbAskForNew(); assert.match(element('oracle-mb-ask-status').textContent,/Review and sign/); assert.equal(state.oracleState._oracleMbRollActive,true); assert.equal(state.oracleState._oracleMbAskBusy,false);
  state.oracleState._oracleMbAskBusy=true; const priorStatus=element('oracle-mb-ask-status').textContent; await proving.oracleMbAskForNew(); assert.equal(element('oracle-mb-ask-status').textContent,priorStatus,'busy guard prevents a concurrent prover request'); state.oracleState._oracleMbAskBusy=false;

  assertWatchOnlyStorage();
  console.log('PASS: Oracle Model-B protocol, polling, block-stream, proving, fee, countdown, and KasSigner-review paths');
} finally {
  await cleanupDeepHarness();
}
