import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, setValue, tick, element,
  ADDRESS, BENEFICIARY, PK, PK2, TXID, PSKB, KSPT,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();

async function waitFor(predicate, label) {
  for (let attempt=0; attempt<100; attempt++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  throw new Error(`Timed out waiting for ${label}: ${element("toast").textContent}`);
}

try {
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  const swapState = await import(moduleUrl('features/covenants/private_swap/state.js'));
  const protocol = await import(moduleUrl('features/covenants/private_swap/protocol.js'));
  const controller = await import(moduleUrl('features/covenants/private_swap/controller.js'));
  const device = await import(moduleUrl('features/covenants/private_swap/device_flow.js'));
  const watcher = await import(moduleUrl('features/covenants/private_swap/watcher.js'));
  const ui = await import(moduleUrl('features/covenants/private_swap/ui.js'));
  const scanner = await import(moduleUrl('features/covenants/recovery/scanner/primary/private_swap.js'));
  const events = await import(moduleUrl('app/events/contracts/covenant_specialized/private_swap.js'));

  const KEY_ID = '10'.repeat(32);
  const CLAIM = '20'.repeat(32);
  const ADAPTOR = '30'.repeat(32);
  const TOKEN = '40'.repeat(32);
  const SIGHASH = '50'.repeat(32);
  const PRESIG = '60'.repeat(64);
  const COUNTER_PRESIG = '61'.repeat(64);
  const COMPLETED = '70'.repeat(64);
  const NONCE = `02${'80'.repeat(32)}`;
  const SWAP_ID = '90'.repeat(16);
  const REDEEM = '51'.repeat(24);
  const SALT = 'a0'.repeat(16);
  const COV_ADDR = 'kaspa:runtime-covenant';
  const scriptHash = createHash('sha256').update(Buffer.from(REDEEM, 'hex')).digest('hex');

  stubs.covenant_private_swap = () => JSON.stringify({ address:COV_ADDR, redeem_script_hex:REDEEM });
  stubs.sha256_hash = input => createHash('sha256').update(Buffer.from(String(input), 'hex')).digest('hex');
  stubs.create_private_swap_claim = () => PSKB;
  stubs.pskt_relay_to_kspt = () => KSPT;
  stubs.private_swap_claim_sighash = () => SIGHASH;
  stubs.private_swap_verify_presignature = () => true;
  stubs.private_swap_verify_completed = () => true;
  stubs.private_swap_insert_completed_signature = () => PSKB;
  stubs.pskt_finalize_and_broadcast = () => TXID;
  stubs.private_swap_extract_secret = () => '99'.repeat(32);
  stubs.private_swap_complete_public = () => COMPLETED;

  let deviceResponse = {};
  stubs.private_swap_key_request = () => 'aa';
  stubs.private_swap_bind_request = () => 'bb';
  stubs.private_swap_presign_request = () => JSON.stringify({ session_id:'12'.repeat(16), request_hex:'cc' });
  stubs.private_swap_reveal_request = () => 'dd';
  stubs.private_swap_complete_request = () => 'ee';
  stubs.private_swap_parse_response = () => JSON.stringify(deviceResponse);
  stubs.private_swap_verify_host_relation = () => true;

  // Exercise the real Alice controller path through scanner callbacks.
  controller.beginPrivateSwapCreate();
  assert.equal(swapState.privateSwapState.role, 'alice');
  setValue('private-swap-create-amount', '2.5');
  setValue('private-swap-create-datetime', '2099-01-01T00:00');
  await controller.requestAliceSwapKey();
  assert.equal(element('qr-display-title').textContent, 'Private Swap Key');

  deviceResponse = { kind:0, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR };
  controller.scanPrivateSwapDeviceResponse();
  state.scannerState.scanCallback('00');
  await waitFor(() => swapState.privateSwapState.stage === 'alice-offer-ready', 'Alice key response');
  assert.equal(swapState.privateSwapState.stage, 'alice-offer-ready');
  controller.sharePrivateSwapOffer();

  const bobTimeout = (BigInt(swapState.privateSwapState.myTimeoutDaa) - 20_000n).toString();
  const bobResponse = {
    v:2, t:'private-swap-response', swap_id:swapState.privateSwapState.swapId, network:'mainnet',
    bob:{
      key_id:'11'.repeat(32), claim_pubkey:'21'.repeat(32), adaptor_point:'31'.repeat(32),
      owner_pubkey:PK2, destination:BENEFICIARY, amount_sompi:'150000000', refund_daa:bobTimeout,
    },
    bob_covenant:{ address:COV_ADDR, redeem_script_hex:REDEEM, salt:'b0'.repeat(16) },
  };
  controller.scanPrivateSwapResponse();
  state.scannerState.scanCallback(new TextEncoder().encode(JSON.stringify(bobResponse)));
  await waitFor(() => swapState.privateSwapState.stage === 'alice-needs-binding', 'Bob response');
  assert.equal(swapState.privateSwapState.stage, 'alice-needs-binding');

  controller.requestPrivateSwapBinding();
  deviceResponse = {
    kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR,
    binding_token:TOKEN, commitment:scriptHash,
  };
  const bound = await device.acceptPrivateSwapBindingResponse('00', swapState.privateSwapState);
  swapState.privateSwapState.myBindingToken = bound.binding_token;
  swapState.privateSwapState.stage = 'alice-bound';
  swapState.savePrivateSwapState();
  assert.equal(swapState.privateSwapState.stage, 'alice-bound');
  controller.sharePrivateSwapFinal();

  // Exact claim build + two-round adaptor pre-signature.
  await controller.preparePrivateSwapPreSignature();
  assert.equal(swapState.privateSwapState.myClaimSighash, SIGHASH);
  deviceResponse = {
    kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN,
    commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE,
  };
  controller.scanPrivateSwapDeviceResponse();
  state.scannerState.scanCallback('00');
  await tick();
  deviceResponse = { ...deviceResponse, kind:3, signature:PRESIG, negated:false };
  controller.scanPrivateSwapDeviceResponse();
  state.scannerState.scanCallback('00');
  await waitFor(() => swapState.privateSwapState.stage === 'alice-presigned', 'pre-signature response');
  assert.equal(swapState.privateSwapState.stage, 'alice-presigned');
  controller.shareAlicePreSignature();

  // Bob ready acknowledgement is independently reconstructed and verified.
  const ready = {
    v:2, t:'private-swap-ready', swap_id:swapState.privateSwapState.swapId, network:'mainnet',
    alice_presig_hash:await protocol.sha256Hex(PRESIG),
    outpoint:{txid:TXID,index:0}, fee_sompi:swapState.privateSwapState.myClaimFeeSompi,
    sighash:SIGHASH, presignature:COUNTER_PRESIG, negated:false,
  };
  controller.scanBobReady();
  state.scannerState.scanCallback(new TextEncoder().encode(JSON.stringify(ready)));
  await waitFor(() => swapState.privateSwapState.stage === 'alice-bob-ready', 'Bob ready acknowledgement');
  assert.equal(swapState.privateSwapState.stage, 'alice-bob-ready');

  await controller.completeAlicePrivateSwap();
  deviceResponse = {
    kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN,
    commitment:SIGHASH, signature:COMPLETED,
  };
  controller.scanPrivateSwapDeviceResponse();
  state.scannerState.scanCallback('00');
  await waitFor(() => swapState.privateSwapState.completed === true, 'completed Alice claim');
  assert.equal(swapState.privateSwapState.completed, true);

  // Refund UI, clearing, hub navigation, and render/status branches.
  swapState.privateSwapState.completed = false;
  controller.openPrivateSwapRefund();
  assert.equal(element('cov-timeout-addr').value, swapState.privateSwapState.myAddress);
  ui.renderPrivateSwapUi({ ...swapState.privateSwapState, role:'bob', stage:'bob-presigned', completed:false }, 'presign-final');
  ui.renderPrivateSwapUi({ ...swapState.privateSwapState, role:'bob', stage:'bob-alice-presig-verified', completed:false }, '');
  ui.renderPrivateSwapUi({ ...swapState.privateSwapState, role:'alice', stage:'alice-bob-ready', readyAckHash:'aa', completed:false }, '');
  controller.privateSwapBackToHub();

  // Event binder's generic click wrapper and its panel-only callbacks are live.
  events.bindPrivateSwapEvents();
  element('btn-private-swap-dashboard-back').dispatch('click', { preventDefault() {} });
  element('btn-private-swap-resume').dispatch('click', { preventDefault() {} });
  element('btn-private-swap-back').dispatch('click', { preventDefault() {} });

  // Exercise the Bob join/key branch as well as Alice's creation branch.
  controller.clearPrivateSwap();
  controller.beginPrivateSwapJoin();
  const joinOffer = {
    v:2, t:'private-swap-offer', swap_id:SWAP_ID, network:'mainnet',
    alice:{
      key_id:'12'.repeat(32), claim_pubkey:'22'.repeat(32), adaptor_point:'32'.repeat(32),
      owner_pubkey:PK, destination:ADDRESS, amount_sompi:'250000000', refund_daa:'999999999999',
    },
  };
  state.scannerState.scanCallback(new TextEncoder().encode(JSON.stringify(joinOffer)));
  await waitFor(() => swapState.privateSwapState.stage === 'bob-offer', 'Bob offer import');
  setValue('private-swap-join-amount', '1.5');
  setValue('private-swap-join-datetime', '2099-01-01T00:00');
  await controller.requestBobSwapKey();
  deviceResponse = { kind:0, key_id:'14'.repeat(32), claim_pubkey:'24'.repeat(32), adaptor_point:'34'.repeat(32) };
  controller.scanPrivateSwapDeviceResponse();
  state.scannerState.scanCallback('00');
  await waitFor(() => swapState.privateSwapState.stage === 'bob-response-ready', 'Bob key response');
  controller.sharePrivateSwapResponse();

  // Watcher records only OP_TRUE completed claims, never OP_FALSE refunds.
  class CaptureSocket {
    static instances = [];
    constructor() { this.readyState=0; CaptureSocket.instances.push(this); queueMicrotask(()=>{this.readyState=1; this.onopen?.();}); }
    send(data) { this.sent=data; }
    close() { this.readyState=3; this.onclose?.(); }
  }
  globalThis.WebSocket = CaptureSocket;
  swapState.resetPrivateSwapState();
  Object.assign(swapState.privateSwapState, {
    role:'bob', myAddress:COV_ADDR, myAmountSompi:'250000000',
    myOutpoint:{txid:TXID,index:0}, counterCompletedSignature:'',
  });
  let observed='';
  watcher.startPrivateSwapWatcher(sig => { observed=sig; });
  await waitFor(() => CaptureSocket.instances.length > 0, 'Private Swap watcher socket');
  const socket = CaptureSocket.instances.at(-1);
  assert.ok(socket, 'watcher websocket should start');
  const claimScript = Uint8Array.from([65, ...new Array(64).fill(0x77), 0x01, 0x51, 1, 0x51]);
  const payload = new Uint8Array(4 + 41 + 4 + claimScript.length + 8);
  payload[1]=0xff; payload[3]=0x3c;
  let off=4; payload.set([37,0,0,0,1],off); off+=5;
  payload.set(Buffer.from(TXID,'hex'),off); off+=32;
  payload.set([0,0,0,0],off); off+=4;
  payload.set([claimScript.length,0,0,0],off); off+=4;
  payload.set(claimScript,off);
  socket.onmessage?.({data:payload.buffer});
  assert.equal(observed, '77'.repeat(64));
  assert.equal(swapState.privateSwapState.counterCompletedSignature, '77'.repeat(64));
  watcher.stopPrivateSwapWatcher();

  // Current encrypted recovery scanner validates both canonical covenants and
  // rejects secret/transient material rather than merely JSON-parsing it.
  const recovery = {
    role:'alice', stage:'alice-bound', swapId:SWAP_ID, network:'mainnet',
    myKeyId:KEY_ID, myClaimPubkey:CLAIM, myOwnAdaptorPoint:ADAPTOR, myBindingToken:TOKEN, adaptorPoint:ADAPTOR,
    myDestination:ADDRESS, myOwnerPubkey:PK, mySalt:SALT, myAmountSompi:'250000000', myTimeoutDaa:'50000',
    counterKeyId:'13'.repeat(32), counterClaimPubkey:'23'.repeat(32), counterDestination:BENEFICIARY,
    counterOwnerPubkey:PK2, counterSalt:'b0'.repeat(16), counterAmountSompi:'150000000', counterTimeoutDaa:'30000',
    myAddress:COV_ADDR, myRedeem:REDEEM, counterAddress:COV_ADDR, counterRedeem:REDEEM,
  };
  const le16 = n => Buffer.from([n & 0xff, (n >>> 8) & 0xff]).toString('hex');
  const jsonHex = Buffer.from(JSON.stringify(recovery),'utf8').toString('hex');
  const params = le16(REDEEM.length/2) + REDEEM + le16(jsonHex.length/2) + jsonHex;
  const recovered = scanner.rebuildPrivateSwap('private-swap', params);
  assert.equal(recovered.role, 'alice');
  assert.equal(recovered.private_swap_recovery_json, JSON.stringify(recovery));
  const unsafeHex = Buffer.from(JSON.stringify({ ...recovery, adaptorSecret:'01' }),'utf8').toString('hex');
  assert.throws(() => scanner.rebuildPrivateSwap('private-swap', le16(REDEEM.length/2)+REDEEM+le16(unsafeHex.length/2)+unsafeHex), /forbidden/);

  // Public controller guards are protocol decisions, not UI-only branches.
  // Exercise the fail-closed side of each gate with the real state object so
  // recovery/resume paths cannot bypass prerequisites.
  controller.clearPrivateSwap();
  controller.openPrivateSwap();
  assert.equal(swapState.privateSwapState.role, '');

  controller.beginPrivateSwapJoin();
  state.scannerState.scanCallback(new TextEncoder().encode('{not-json'));
  assert.match(element('toast').textContent, /Invalid Private Swap offer/);
  controller.clearPrivateSwap();

  controller.beginPrivateSwapCreate();
  setValue('private-swap-create-amount', '0');
  setValue('private-swap-create-datetime', '2099-01-01T00:00');
  await controller.requestAliceSwapKey();
  assert.match(element('toast').textContent, /Enter an amount/);
  setValue('private-swap-create-amount', '1');
  setValue('private-swap-create-datetime', '');
  await controller.requestAliceSwapKey();
  assert.match(element('toast').textContent, /Choose your refund time/);

  // A binding request cannot be synthesized until the counterparty covenant
  // transcript has been accepted.
  controller.requestPrivateSwapBinding();
  assert.match(element('toast').textContent, /counterparty|covenant|binding/i);
  controller.scanPrivateSwapDeviceResponse();
  assert.match(element('toast').textContent, /No pending KasSigner/);

  // Funding and signing each enforce their own prerequisite rather than
  // trusting an earlier UI stage.
  swapState.resetPrivateSwapState();
  Object.assign(swapState.privateSwapState, { role:'alice', myAmountSompi:'100000000' });
  await controller.fundPrivateSwapSide();
  assert.match(element('toast').textContent, /handshake/i);
  await controller.preparePrivateSwapPreSignature();
  assert.match(element('toast').textContent, /Bind the isolated claim key/);
  controller.shareAlicePreSignature();
  assert.match(element('toast').textContent, /not ready/);
  controller.scanAlicePreSignature();
  assert.match(element('toast').textContent, /Only Bob/);
  await controller.shareBobReady();
  assert.match(element('toast').textContent, /both verified adaptor pre-signatures/);
  swapState.privateSwapState.role='bob';
  controller.scanBobReady();
  assert.match(element('toast').textContent, /Only Alice/);
  swapState.privateSwapState.role='bob';
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /ready acknowledgement/);
  await controller.bobClaimPrivateSwap();
  assert.match(element('toast').textContent, /not been observed/);
  controller.openPrivateSwapRefund();
  assert.match(element('toast').textContent, /No funded-side covenant/);

  // Bob cannot fund before producing his own exact-transaction adaptor
  // pre-signature, and cannot proceed unless Alice's exact amount is funded.
  swapState.resetPrivateSwapState();
  Object.assign(swapState.privateSwapState, {
    role:'bob', myAddress:COV_ADDR, myRedeem:REDEEM, myAmountSompi:'150000000',
    myTimeoutDaa:'30000', myDestination:BENEFICIARY, counterAddress:COV_ADDR,
    counterAmountSompi:'250000000', counterRedeem:REDEEM,
  });
  await controller.fundPrivateSwapSide();
  assert.match(element('toast').textContent, /pre-signature before funding/);
  swapState.privateSwapState.myPreSignature=PRESIG;
  const normalUtxoStub=stubs.fetch_utxos_for_address_js;
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([]);
  await controller.fundPrivateSwapSide();
  assert.match(element('toast').textContent, /exactly one funding UTXO/);

  // Funding discovery rejects non-arrays and duplicate exact-amount UTXOs.
  Object.assign(swapState.privateSwapState, {
    role:'alice', myBindingToken:TOKEN, myAddress:COV_ADDR, myRedeem:REDEEM,
    myAmountSompi:'250000000', myTimeoutDaa:'50000', myDestination:ADDRESS,
    myClaimPubkey:CLAIM, counterAddress:COV_ADDR, counterRedeem:REDEEM,
    counterAmountSompi:'150000000', counterDestination:BENEFICIARY,
  });
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify({amount:'250000000'});
  await controller.preparePrivateSwapPreSignature();
  assert.match(element('toast').textContent, /exactly one funding UTXO/);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([
    {tx_id:TXID,index:0,amount:'250000000'},
    {tx_id:'bb'.repeat(32),index:1,amount:'250000000'},
  ]);
  await controller.preparePrivateSwapPreSignature();
  assert.match(element('toast').textContent, /exactly one funding UTXO/);

  // Claim fee policy is independently enforced even with a unique funding
  // output. First exceed the absolute ceiling, then the funded amount.
  swapState.privateSwapState.myAddress='kaspa:alice-covenant';
  stubs.fetch_utxos_for_address_js=address=>JSON.stringify([
    String(address)==='kaspa:alice-covenant'
      ? {tx_id:'ab'.repeat(32),index:0,amount:'250000000'}
      : {tx_id:TXID,index:0,amount:String(swapState.privateSwapState.counterAmountSompi)},
  ]);
  const oldFeeEstimate=state.networkState.lastFeeEstimate;
  state.networkState.lastFeeEstimate={ normal_sompi_per_gram:'10000000', low_sompi_per_gram:'10000000', priority_sompi_per_gram:'10000000' };
  await controller.preparePrivateSwapPreSignature();
  assert.match(element('toast').textContent, /hard ceiling/);
  state.networkState.lastFeeEstimate={ normal_sompi_per_gram:'1', low_sompi_per_gram:'1', priority_sompi_per_gram:'1' };
  swapState.privateSwapState.counterAmountSompi='1';
  await controller.preparePrivateSwapPreSignature();
  assert.match(element('toast').textContent, /too small for the claim fee/);
  state.networkState.lastFeeEstimate=oldFeeEstimate;
  swapState.privateSwapState.counterAmountSompi='150000000';

  // Recovery refuses an in-memory transaction whose stored reviewed sighash
  // changed, and refuses incomplete or policy-invalid reconstruction records.
  Object.assign(swapState.privateSwapState, {
    role:'alice', readyAckHash:'aa', myClaimPskb:PSKB, myClaimKspt:KSPT,
    myClaimSighash:'ff'.repeat(32), myBindingToken:TOKEN,
  });
  stubs.private_swap_claim_sighash=()=>SIGHASH;
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /no longer matches/);
  swapState.privateSwapState.myClaimPskb=''; swapState.privateSwapState.myClaimKspt='';
  swapState.privateSwapState.counterOutpoint=null;
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /missing the exact claim transcript/);
  Object.assign(swapState.privateSwapState, {
    counterOutpoint:{txid:TXID,index:0}, myClaimFeeSompi:'999999999', myClaimSighash:SIGHASH,
  });
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /fee violates/);

  // A recovered exact transcript must bind to the same outpoint and sighash.
  swapState.privateSwapState.myClaimFeeSompi='400000';
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:'bb'.repeat(32),index:0,amount:'150000000'}]);
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /Funding outpoint changed/);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'150000000'}]);
  stubs.private_swap_claim_sighash=()=> 'ee'.repeat(32);
  await controller.completeAlicePrivateSwap();
  assert.match(element('toast').textContent, /rebuild changed/);

  // Bob's public completion path verifies the final BIP340 signature before
  // broadcast, even after the adaptor secret was recovered successfully.
  Object.assign(swapState.privateSwapState, {
    role:'bob', counterCompletedSignature:COMPLETED, counterPreSignature:COUNTER_PRESIG,
    counterPreSignatureNegated:false, myPreSignature:PRESIG, myPreSignatureNegated:false,
    myClaimPskb:PSKB, myClaimKspt:KSPT, myClaimSighash:SIGHASH, myClaimPubkey:CLAIM,
  });
  stubs.private_swap_claim_sighash=()=>SIGHASH;
  stubs.private_swap_verify_completed=()=>false;
  await controller.bobClaimPrivateSwap();
  assert.match(element('toast').textContent, /failed exact-transaction BIP340 verification/);
  stubs.private_swap_verify_completed=()=>true;
  stubs.fetch_utxos_for_address_js=normalUtxoStub;

  controller.clearPrivateSwap();
  assert.equal(swapState.privateSwapState.role, '');
  console.log('PASS: Private Swap controller, watcher, UI events, and recovery scanner deep paths');
} finally {
  await cleanupDeepHarness();
}
