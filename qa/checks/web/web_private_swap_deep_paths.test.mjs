import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl,
  ADDRESS, BENEFICIARY, PK, PK2, PK3, SIG, TXID, PSKB, KSPT, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  const swapState = await import(moduleUrl('features/covenants/private_swap/state.js'));
  const protocol = await import(moduleUrl('features/covenants/private_swap/protocol.js'));
  const device = await import(moduleUrl('features/covenants/private_swap/device_flow.js'));
  const controller = await import(moduleUrl('features/covenants/private_swap/controller.js'));

  const KEY_ID = '10'.repeat(32);
  const CLAIM = '20'.repeat(32);
  const ADAPTOR = '30'.repeat(32);
  const TOKEN = '40'.repeat(32);
  const SIGHASH = '50'.repeat(32);
  const PRESIG = '60'.repeat(64);
  const COMPLETED = '70'.repeat(64);
  const NONCE = `02${'80'.repeat(32)}`;
  const SWAP_ID = '90'.repeat(16);
  const SALT = 'a0'.repeat(16);
  const REDEEM = '51'.repeat(24);
  const COV_ADDR = 'kaspa:runtime-covenant';

  stubs.covenant_private_swap = () => JSON.stringify({ address:COV_ADDR, redeem_script_hex:REDEEM });
  stubs.sha256_hash = input => createHash('sha256').update(Buffer.from(String(input), 'hex')).digest('hex');

  // Offer/response/final use exact decimal strings and enforce the asymmetric
  // refund ordering that protects Alice's adaptor-secret reveal window.
  const alice = {
    swapId:SWAP_ID, network:'mainnet', myKeyId:KEY_ID, myClaimPubkey:CLAIM, myOwnAdaptorPoint:ADAPTOR,
    myOwnerPubkey:PK, myDestination:ADDRESS, myAmountSompi:'250000000', myTimeoutDaa:'50000',
    myAddress:COV_ADDR, myRedeem:REDEEM, mySalt:SALT,
  };
  const offer = protocol.makeOffer(alice);
  const parsedOffer = protocol.parseOffer(JSON.stringify(offer));
  assert.equal(parsedOffer.swapId, SWAP_ID);
  assert.equal(parsedOffer.alice.amountSompi, '250000000');
  assert.equal(parsedOffer.alice.adaptorPoint, ADAPTOR);
  assert.doesNotThrow(() => protocol.assertRefundOrdering('50000', '30000'));
  assert.throws(() => protocol.assertRefundOrdering('50000', '40000'), /30 minutes later/);

  const bob = {
    ...alice, myKeyId:'11'.repeat(32), myClaimPubkey:'21'.repeat(32), myOwnAdaptorPoint:'31'.repeat(32),
    myOwnerPubkey:PK2, myDestination:BENEFICIARY, myAmountSompi:'150000000', myTimeoutDaa:'30000',
  };
  const response = protocol.parseResponse(JSON.stringify(protocol.makeResponse(bob)), SWAP_ID);
  assert.equal(response.bob.amountSompi, '150000000');
  assert.equal(response.covenant.redeemScript, REDEEM);
  assert.equal(protocol.parseFinal(JSON.stringify(protocol.makeFinal(alice)), SWAP_ID).redeemScript, REDEEM);
  assert.throws(() => protocol.parseOffer(JSON.stringify({ ...offer, network:'testnet-10' })), /different network/);

  // Adaptor packages remain bound to exact funding outpoints, fee and sighash.
  const packageState = {
    ...alice, counterOutpoint:{ txid:TXID, index:0 }, myClaimFeeSompi:'300000', myClaimSighash:SIGHASH,
    myPreSignature:PRESIG, myPreSignatureNegated:true, counterPreSignature:'61'.repeat(64),
  };
  const alicePackage = protocol.parseAlicePreSignaturePackage(JSON.stringify(protocol.makeAlicePreSignaturePackage(packageState)), SWAP_ID);
  assert.equal(alicePackage.outpoint.txid, TXID);
  assert.equal(alicePackage.feeSompi, 300000n);
  assert.equal(alicePackage.sighash, SIGHASH);
  assert.equal(alicePackage.negated, true);
  const ready = protocol.parseReadyPackage(JSON.stringify(await protocol.makeReadyPackage(packageState)), SWAP_ID);
  assert.equal(ready.sighash, SIGHASH);
  assert.equal(ready.presignature, PRESIG);
  assert.equal(ready.alicePresigHash, createHash('sha256').update(Buffer.from(packageState.counterPreSignature, 'hex')).digest('hex'));

  // Device flow: fresh swap-only key -> exact-script binding -> two-round
  // anti-klepto adaptor pre-sign -> final ordinary BIP340 completion.
  let parsedDevice = {};
  stubs.private_swap_key_request = () => 'aa';
  stubs.private_swap_bind_request = () => 'bb';
  stubs.private_swap_presign_request = (_key, _token, _adaptor, _kspt, _secret) => JSON.stringify({ session_id:'12'.repeat(16), request_hex:'cc' });
  stubs.private_swap_reveal_request = () => 'dd';
  stubs.private_swap_complete_request = () => 'ee';
  stubs.private_swap_parse_response = () => JSON.stringify(parsedDevice);
  stubs.private_swap_verify_host_relation = () => true;

  assert.equal(device.privateSwapKeyRequest(), 'aa');
  parsedDevice = { kind:0, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR };
  assert.equal(device.acceptPrivateSwapKeyResponse('00').key_id, KEY_ID);

  const flowState = {
    myKeyId:KEY_ID, myClaimPubkey:CLAIM, myOwnAdaptorPoint:ADAPTOR, myBindingToken:'',
    adaptorPoint:ADAPTOR, counterRedeem:REDEEM, myClaimKspt:KSPT, myClaimSighash:SIGHASH,
    myPreSignature:PRESIG, myPreSignatureNegated:false,
  };
  assert.equal(device.privateSwapBindingRequest(flowState), 'bb');
  const scriptHash = createHash('sha256').update(Buffer.from(REDEEM, 'hex')).digest('hex');
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:scriptHash };
  assert.equal((await device.acceptPrivateSwapBindingResponse('00', flowState)).binding_token, TOKEN);
  flowState.myBindingToken = TOKEN;

  assert.equal(device.privateSwapPreSignRequest(flowState), 'cc');
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE };
  const reveal = device.acceptPrivateSwapPreSignResponse('00', flowState);
  assert.equal(reveal.kind, 'reveal'); assert.equal(reveal.payload, 'dd');
  parsedDevice = { ...parsedDevice, kind:3, signature:PRESIG, negated:false };
  const presigned = device.acceptPrivateSwapPreSignResponse('00', flowState);
  assert.equal(presigned.kind, 'presignature'); assert.equal(presigned.response.signature, PRESIG);

  assert.equal(device.privateSwapCompleteRequest(flowState), 'ee');
  parsedDevice = { kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, signature:COMPLETED };
  assert.equal(device.acceptPrivateSwapCompletedResponse('00', flowState).signature, COMPLETED);
  assert.equal(device.pendingPrivateSwapDeviceAction(), '');

  // Device-flow fail-closed branches: each response is mutated one security
  // field at a time, exercising isolated-key, script, transcript and nonce binding.
  device.privateSwapKeyRequest();
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR };
  assert.throws(() => device.acceptPrivateSwapKeyResponse('00'), /Expected Private Swap key response/);
  parsedDevice = { kind:0, key_id:'00'.repeat(32), claim_pubkey:CLAIM, adaptor_point:ADAPTOR };
  assert.throws(() => device.acceptPrivateSwapKeyResponse('00'), /invalid Private Swap key material/);
  assert.throws(() => device.privateSwapBindingRequest({ ...flowState, counterRedeem:'' }), /Counterparty covenant/);

  device.privateSwapBindingRequest(flowState);
  parsedDevice = { kind:0, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', flowState), /Expected Private Swap binding response/);
  parsedDevice = { kind:1, key_id:'ff'.repeat(32), claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:scriptHash };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', flowState), /different isolated Private Swap key/);
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:'31'.repeat(32), binding_token:TOKEN, commitment:scriptHash };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', flowState), /changed the device-derived adaptor point/);
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:'ff'.repeat(32) };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', flowState), /different covenant script/);
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:'00'.repeat(32), commitment:scriptHash };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', { ...flowState, myBindingToken:'' }), /binding token is invalid/);

  assert.throws(() => device.privateSwapPreSignRequest({ ...flowState, myClaimKspt:'' }), /exact counterparty claim/);
  device.privateSwapPreSignRequest(flowState);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:'31'.repeat(32), binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /changed Alice adaptor point/);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:'ff'.repeat(32), session_id:'12'.repeat(16), nonce_point:NONCE };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /another exact transaction\/session/);
  parsedDevice = { kind:3, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE, signature:PRESIG };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /Expected Private Swap nonce response/);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE };
  assert.equal(device.acceptPrivateSwapPreSignResponse('00', flowState).kind, 'reveal');
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /Expected final Private Swap pre-signature response/);
  parsedDevice = { kind:3, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:`02${'81'.repeat(32)}`, signature:PRESIG };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /changed the committed nonce/);
  parsedDevice = { kind:3, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE, signature:PRESIG };
  stubs.private_swap_verify_host_relation = () => false;
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /anti-klepto nonce relation failed/);
  stubs.private_swap_verify_host_relation = () => true;

  assert.throws(() => device.privateSwapCompleteRequest({ ...flowState, myPreSignature:'' }), /pre-signature\/claim transaction/);
  device.privateSwapCompleteRequest(flowState);
  parsedDevice = { kind:3, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, signature:COMPLETED };
  assert.throws(() => device.acceptPrivateSwapCompletedResponse('00', flowState), /Expected completed Private Swap signature/);
  parsedDevice = { kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:'ff'.repeat(32), commitment:SIGHASH, signature:COMPLETED };
  assert.throws(() => device.acceptPrivateSwapCompletedResponse('00', flowState), /different Private Swap binding record/);
  parsedDevice = { kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:'ff'.repeat(32), signature:COMPLETED };
  assert.throws(() => device.acceptPrivateSwapCompletedResponse('00', flowState), /another Private Swap claim/);
  // Complete the device-flow structural branch matrix with independent field
  // failures and each supported scanner transport representation.
  device.privateSwapKeyRequest();
  parsedDevice = { kind:0, key_id:KEY_ID, claim_pubkey:'00'.repeat(32), adaptor_point:ADAPTOR };
  assert.throws(() => device.acceptPrivateSwapKeyResponse('00'), /invalid Private Swap key material/);
  parsedDevice = { kind:0, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:'00'.repeat(32) };
  assert.throws(() => device.acceptPrivateSwapKeyResponse('00'), /invalid Private Swap key material/);

  device.privateSwapBindingRequest(flowState);
  parsedDevice = { kind:1, key_id:KEY_ID, claim_pubkey:'ff'.repeat(32), adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:scriptHash };
  await assert.rejects(() => device.acceptPrivateSwapBindingResponse('00', flowState), /different isolated Private Swap key/);

  assert.throws(() => device.privateSwapPreSignRequest({ ...flowState, myClaimSighash:'' }), /exact counterparty claim/);
  device.privateSwapPreSignRequest(flowState);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'13'.repeat(16), nonce_point:NONCE };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /another exact transaction\/session/);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:'aa' };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /Expected Private Swap nonce response/);
  parsedDevice = { kind:2, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE };
  assert.equal(device.acceptPrivateSwapPreSignResponse('00', flowState).kind,'reveal');
  parsedDevice = { kind:3, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, session_id:'12'.repeat(16), nonce_point:NONCE, signature:'aa' };
  assert.throws(() => device.acceptPrivateSwapPreSignResponse('00', flowState), /changed the committed nonce/);

  device.privateSwapCompleteRequest(flowState);
  parsedDevice = { kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:'31'.repeat(32), binding_token:TOKEN, commitment:SIGHASH, signature:COMPLETED };
  assert.throws(() => device.acceptPrivateSwapCompletedResponse('00', flowState), /another Private Swap claim/);
  device.privateSwapCompleteRequest(flowState);
  parsedDevice = { kind:4, key_id:KEY_ID, claim_pubkey:CLAIM, adaptor_point:ADAPTOR, binding_token:TOKEN, commitment:SIGHASH, signature:'aa' };
  assert.throws(() => device.acceptPrivateSwapCompletedResponse('00', flowState), /another Private Swap claim/);

  let encodedInput=''; stubs.private_swap_parse_response = hex => { encodedInput=hex; return JSON.stringify({kind:0,key_id:KEY_ID,claim_pubkey:CLAIM,adaptor_point:ADAPTOR}); };
  device.privateSwapKeyRequest(); device.acceptPrivateSwapKeyResponse('aabb'); assert.equal(encodedInput,'aabb');
  device.privateSwapKeyRequest(); device.acceptPrivateSwapKeyResponse('not hex'); assert.equal(encodedInput,Buffer.from('not hex').toString('hex'));
  device.privateSwapKeyRequest(); device.acceptPrivateSwapKeyResponse(new TextEncoder().encode('aabb')); assert.equal(encodedInput,'aabb');
  device.privateSwapKeyRequest(); device.acceptPrivateSwapKeyResponse(Uint8Array.from([0xff,0x00])); assert.equal(encodedInput,'ff00');
  stubs.private_swap_parse_response = () => JSON.stringify(parsedDevice);

  device.clearPrivateSwapDeviceFlow();

  // Recovery keeps the public adaptor transcript but never PSKB/KSPT/secret
  // material. A recovered Bob flow deterministically rebuilds the exact claim
  // transaction and requires its sighash to match before using the adaptor scalar.
  swapState.resetPrivateSwapState();
  const recovery = {
    role:'bob', stage:'bob-alice-presig-verified', swapId:SWAP_ID, network:'mainnet',
    myKeyId:KEY_ID, myClaimPubkey:CLAIM, myOwnAdaptorPoint:ADAPTOR, myBindingToken:TOKEN, adaptorPoint:ADAPTOR,
    myDestination:ADDRESS, myOwnerPubkey:PK, mySalt:SALT, myAmountSompi:'250000000', myTimeoutDaa:'30000',
    counterKeyId:'13'.repeat(32), counterClaimPubkey:'23'.repeat(32), counterDestination:BENEFICIARY,
    counterOwnerPubkey:PK2, counterSalt:'b0'.repeat(16), counterAmountSompi:'250000000', counterTimeoutDaa:'50000',
    myAddress:COV_ADDR, myRedeem:REDEEM, counterAddress:COV_ADDR, counterRedeem:REDEEM,
    myOutpoint:{txid:TXID,index:0}, counterOutpoint:{txid:TXID,index:0},
    myClaimSighash:SIGHASH, myClaimFeeSompi:'300000', myPreSignature:PRESIG, myPreSignatureNegated:false,
    counterClaimSighash:'51'.repeat(32), counterClaimFeeSompi:'300000', counterPreSignature:'62'.repeat(64),
    counterPreSignatureNegated:false, counterCompletedSignature:COMPLETED, readyAckHash:'', completed:false,
  };
  swapState.restorePrivateSwapState(recovery);
  assert.equal(swapState.privateSwapState.myClaimPskb, '');
  assert.equal(swapState.privateSwapState.myClaimKspt, '');
  assert.throws(() => swapState.restorePrivateSwapState({ ...recovery, myClaimKspt:KSPT }), /forbidden/);
  assert.throws(() => swapState.restorePrivateSwapState({ ...recovery, adaptorSecret:'01' }), /forbidden/);
  swapState.restorePrivateSwapState(recovery);

  stubs.fetch_utxos_for_address_js = () => JSON.stringify([{ tx_id:TXID, index:0, amount:'250000000', block_daa_score:'900' }]);
  stubs.create_private_swap_claim = () => PSKB;
  stubs.pskt_relay_to_kspt = () => KSPT;
  stubs.private_swap_claim_sighash = () => SIGHASH;
  stubs.private_swap_extract_secret = () => '99'.repeat(32);
  stubs.private_swap_complete_public = () => COMPLETED;
  stubs.private_swap_verify_completed = () => true;
  stubs.private_swap_insert_completed_signature = () => PSKB;
  stubs.pskt_finalize_and_broadcast = () => TXID;
  await controller.bobClaimPrivateSwap();
  assert.equal(swapState.privateSwapState.myClaimPskb, PSKB, 'recovery must rebuild the exact claim PSKB');
  assert.equal(swapState.privateSwapState.myClaimKspt, KSPT, 'recovery must rebuild the exact claim KSPT');
  assert.equal(swapState.privateSwapState.completed, true);

  // Wire/protocol negative coverage: each malformed package is rejected at the
  // exact invariant it violates, preserving session/network/outpoint binding.
  assert.throws(() => protocol.parseOffer(JSON.stringify({ ...offer, v:1 })), /current Private Swap offer/);
  assert.throws(() => protocol.parseResponse(JSON.stringify({ ...protocol.makeResponse(bob), t:'wrong' }), SWAP_ID), /current Private Swap response/);
  assert.throws(() => protocol.parseResponse(JSON.stringify({ ...protocol.makeResponse(bob), swap_id:'91'.repeat(16) }), SWAP_ID), /another session\/network/);
  assert.throws(() => protocol.parseFinal(JSON.stringify({ ...protocol.makeFinal(alice), t:'wrong' }), SWAP_ID), /current Private Swap final/);
  assert.throws(() => protocol.parseFinal(JSON.stringify({ ...protocol.makeFinal(alice), network:'testnet-10' }), SWAP_ID), /another session\/network/);
  assert.throws(() => protocol.makeAlicePreSignaturePackage({ ...packageState, counterOutpoint:null }), /funding outpoint/);
  const badAlicePackage = protocol.makeAlicePreSignaturePackage(packageState);
  assert.throws(() => protocol.parseAlicePreSignaturePackage(JSON.stringify({ ...badAlicePackage, t:'wrong' }), SWAP_ID), /current Alice Private Swap pre-signature/);
  assert.throws(() => protocol.parseAlicePreSignaturePackage(JSON.stringify({ ...badAlicePackage, network:'testnet-10' }), SWAP_ID), /another swap\/network/);
  assert.throws(() => protocol.parseAlicePreSignaturePackage(JSON.stringify({ ...badAlicePackage, outpoint:{ ...badAlicePackage.outpoint, index:-1 } }), SWAP_ID), /outpoint index/);
  assert.throws(() => protocol.parseAlicePreSignaturePackage(JSON.stringify({ ...badAlicePackage, outpoint:{ ...badAlicePackage.outpoint, index:4294967296 } }), SWAP_ID), /outpoint index/);
  await assert.rejects(() => protocol.makeReadyPackage({ ...packageState, counterPreSignature:'' }), /Both verified adaptor pre-signatures/);
  const readyWire = await protocol.makeReadyPackage(packageState);
  assert.throws(() => protocol.parseReadyPackage(JSON.stringify({ ...readyWire, t:'wrong' }), SWAP_ID), /current Private Swap ready/);
  assert.throws(() => protocol.parseReadyPackage(JSON.stringify({ ...readyWire, swap_id:'91'.repeat(16) }), SWAP_ID), /another swap\/network/);
  assert.throws(() => protocol.parseReadyPackage(JSON.stringify({ ...readyWire, outpoint:{ ...readyWire.outpoint, index:1.5 } }), SWAP_ID), /outpoint index/);
  assert.throws(() => protocol.assertCovenantMatches({ label:'Alice covenant', address:'kaspa:wrong', redeemScript:REDEEM }, { address:COV_ADDR, redeem_script_hex:REDEEM }), /does not match/);
  await assert.rejects(() => protocol.sha256Hex('abc'), /Hash input is invalid/);

  assertWatchOnlyStorage();
  const persisted = sessionStorage.getItem('kassee_private_swap_v2') || '';
  assert.doesNotMatch(persisted, /(?:mnemonic|xprv|private[_-]?key|secret[_-]?key|adaptorSecret)/i);
  console.log('PASS: Private Swap v2 negotiation, device adaptor flow, exact transaction binding, and restart recovery');
} finally {
  await cleanupDeepHarness();
}
