import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, PK, PK2, PSKB, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

function responseHex({ kind, session = '00'.repeat(16), keyId, pubkey, token = '00'.repeat(32), commitment = '00'.repeat(32), nonce = '00'.repeat(33), signature = '00'.repeat(64) }) {
  const out = Buffer.alloc(247);
  out.write('CVSR', 0, 'ascii'); out[4] = 2; out[5] = kind;
  Buffer.from(session, 'hex').copy(out, 6);
  Buffer.from(keyId, 'hex').copy(out, 22);
  Buffer.from(pubkey, 'hex').copy(out, 54);
  Buffer.from(token, 'hex').copy(out, 86);
  Buffer.from(commitment, 'hex').copy(out, 118);
  Buffer.from(nonce, 'hex').copy(out, 150);
  Buffer.from(signature, 'hex').copy(out, 183);
  return out.toString('hex');
}

function requestField(hex, start, length) {
  return Buffer.from(hex, 'hex').subarray(start, start + length).toString('hex');
}

const { state } = await setupDeepHarness();
try {
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  stubs.verify_covenant_anti_klepto = () => true;
  stubs.verify_oracle_v1_attestation = () => true;
  stubs.create_covenant_oracle_v1_claim = () => PSKB;
  stubs.create_covenant_pskb_with_payload = () => PSKB;

  let lastQr = '';
  stubs.generate_qr_svg_text = value => {
    lastQr = String(value);
    return `<svg data-binding="${lastQr.slice(0, 8)}"></svg>`;
  };

  const oracle = await import(moduleUrl('features/oracle/v1/controller.js'));
  const protocol = await import(moduleUrl('features/covenants/signing/protocol.js'));
  const resultButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons.js'));
  const fund = await import(moduleUrl('features/covenants/generation/fund.js'));
  const beneficiary = await import(moduleUrl('features/covenants/recovery/export/beneficiary_payload.js'));
  const params = await import(moduleUrl('features/covenants/payload_and_swaps/params.js'));
  const oracleRecovery = await import(moduleUrl('features/covenants/recovery/scanner/primary/oracle.js'));
  const inviteImport = await import(moduleUrl('features/covenants/recovery/import/invite.js'));
  const activeRepo = await import(moduleUrl('features/covenants/recovery/active/repository.js'));

  const keyId = '12'.repeat(32);
  const pubkey = '23'.repeat(32);
  const token = '34'.repeat(32);
  const statement = 'KasSigner Oracle v1 00112233445566778899aabbccddeeff: Release invoice 42';
  const commitment = createHash('sha256').update(Buffer.from(statement, 'utf8')).digest('hex');
  const scriptHex = '51';
  const scriptHash = createHash('sha256').update(Buffer.from(scriptHex, 'hex')).digest('hex');
  const address = 'kaspa:runtime-oracle-covenant';

  // Device allocation: host sends an all-zero key ID and accepts the fresh ID/pubkey returned by KasSigner.
  oracle.showOracleV1KeyRequest();
  assert.equal(lastQr.slice(0, 12), Buffer.from('CVSG\x02\x00', 'binary').toString('hex'));
  assert.equal(requestField(lastQr, 56, 32), '00'.repeat(32));
  oracle.scanOracleV1KeyResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({ kind: 0, keyId, pubkey }), 'hex'));
  assert.equal(element('cov-oracle-v1-key-id').value, keyId);
  assert.equal(element('cov-oracle-v1-pubkey').value, pubkey);

  const result = {
    type: 'oracle-v1', address, redeem_script_hex: scriptHex, loaded: false, role: 'owner',
    oracle_covenant_key_id_hex: keyId, oracle_pubkey_hex: pubkey,
    beneficiary_pubkey_hex: PK2, owner_pubkey_hex: PK,
    attestation_statement: statement, message_commitment_hex: commitment,
    locktime_daa: '1200', locktime_date_iso: '2026-08-14T20:00:00Z',
  };
  state.covenantState.lastCovenantResult = result;
  state.covenantState.activeCovenants = [{ ...result }];

  // An unbound Oracle covenant cannot be funded and its result UI exposes the explicit binding step.
  resultButtons.covUpdateResultButtons('oracle-v1');
  assert.equal(element('btn-cov-fund').style.display, 'none');
  assert.equal(element('btn-cov-res-oracle-v1-bind').classList.contains('hidden'), false);
  await fund.handleCovFund();
  assert.match(element('toast').textContent, /Bind the isolated Oracle covenant key/);

  // Bind the device-selected ID to the exact script and persist the portable non-secret binding record.
  oracle.showOracleV1BindingRequest();
  assert.equal(requestField(lastQr, 5, 1), '03');
  assert.equal(requestField(lastQr, 56, 32), keyId);
  assert.equal(requestField(lastQr, 88, 32), '00'.repeat(32));
  oracle.scanOracleV1BindingResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({ kind: 3, keyId, pubkey, token, commitment: scriptHash }), 'hex'));
  assert.equal(result.oracle_covenant_binding_token_hex, token);
  assert.equal(state.covenantState.activeCovenants[0].oracle_covenant_binding_token_hex, token);
  assert.match(sessionStorage.getItem('lastCovenantResult') || '', new RegExp(token));
  resultButtons.covUpdateResultButtons('oracle-v1');
  assert.notEqual(element('btn-cov-fund').style.display, 'none');

  // Known signing carries the binding record and exact external SHA-256 commitment unchanged.
  oracle.openOracleV1Attest();
  await oracle.showOracleV1SignRequest();
  assert.equal(requestField(lastQr, 5, 1), '01');
  const sessionId = requestField(lastQr, 8, 16);
  assert.notEqual(sessionId, '00'.repeat(16));
  assert.equal(requestField(lastQr, 56, 32), keyId);
  assert.equal(requestField(lastQr, 88, 32), token);
  assert.equal(requestField(lastQr, 120, 32), commitment);

  const noncePoint = `02${'45'.repeat(32)}`;
  oracle.scanOracleV1CovenantSignResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({
    kind: 1, session: sessionId, keyId, pubkey, token, commitment, nonce: noncePoint,
  }), 'hex'));
  assert.equal(lastQr.slice(0, 8), Buffer.from('CVRV').toString('hex'));

  const finalResponse = protocol.covenantSignatureResponseHex({
    sessionId, keyId, pubkey, bindingToken: token, commitment, noncePoint, signature: '56'.repeat(64),
  });
  oracle.scanOracleV1CovenantSignResponse();
  await state.scannerState.scanCallback(Buffer.from(finalResponse, 'hex'));
  assert.match(element('cov-oracle-v1-attest-status').textContent, /exact statement|nonce verified/i);
  oracle.showOracleV1AttestationQr();
  assert.equal(lastQr, finalResponse);

  // The same current COVENANT SIGN response hydrates the beneficiary claim path; old raw/JSON forms are not used.
  oracle.openOracleV1Claim();
  oracle.scanOracleV1ClaimAttestation();
  await state.scannerState.scanCallback(Buffer.from(finalResponse, 'hex'));
  assert.equal(element('cov-oracle-v1-claim-sig').value, '56'.repeat(64));
  assert.equal(element('cov-oracle-v1-claim-commitment').value, commitment);
  setValue('cov-oracle-v1-claim-dest', ADDRESS);
  await oracle.buildOracleV1Claim();
  assert.ok(state.transactionState._psktReviewHex, 'oracle claim opens hardware PSKB review');
  await oracle.publishOracleV1Beacon();
  assert.ok(state.transactionState._psktReviewHex, 'oracle beacon deposit opens hardware PSKB review');

  // Negative Oracle-v1 controller paths exercise the same externally visible
  // scanner/UI workflows one invariant at a time. These are protocol failures,
  // not synthetic assertions against private helpers.
  oracle.showOracleV1BindingRequest();
  assert.match(element('toast').textContent, /already bound/i);

  async function scanBinding(hex) {
    oracle.scanOracleV1BindingResponse();
    await state.scannerState.scanCallback(Buffer.from(hex, 'hex'));
    return element('toast').textContent;
  }
  assert.match(await scanBinding(responseHex({ kind:0, keyId, pubkey })), /Expected covenant binding response/);
  assert.match(await scanBinding(responseHex({ kind:3, keyId:'13'.repeat(32), pubkey, token, commitment:scriptHash })), /different covenant key instance/);
  assert.match(await scanBinding(responseHex({ kind:3, keyId, pubkey:'24'.repeat(32), token, commitment:scriptHash })), /different covenant key/);
  assert.match(await scanBinding(responseHex({ kind:3, keyId, pubkey, token, commitment:'35'.repeat(32) })), /different covenant script/);

  // Key allocation rejects a structurally valid response of the wrong kind.
  oracle.scanOracleV1KeyResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({ kind:3, keyId, pubkey, token, commitment:scriptHash }), 'hex'));
  assert.match(element('toast').textContent, /Expected covenant-key response/);

  // Missing binding cannot start signing; restoring it immediately returns to
  // the normal signing flow.
  result.oracle_covenant_binding_token_hex = '';
  await oracle.showOracleV1SignRequest();
  assert.match(element('toast').textContent, /missing its KasSigner key binding record/);
  result.oracle_covenant_binding_token_hex = token;
  await oracle.showOracleV1SignRequest();
  const negativeSession = requestField(lastQr, 8, 16);

  async function scanSign(fields) {
    oracle.scanOracleV1CovenantSignResponse();
    await state.scannerState.scanCallback(Buffer.from(responseHex({
      kind: fields.kind ?? 1,
      session: fields.session ?? negativeSession,
      keyId: fields.keyId ?? keyId,
      pubkey: fields.pubkey ?? pubkey,
      token: fields.token ?? token,
      commitment: fields.commitment ?? commitment,
      nonce: fields.nonce ?? noncePoint,
      signature: fields.signature ?? '00'.repeat(64),
    }), 'hex'));
    return element('toast').textContent;
  }
  assert.match(await scanSign({ session:'ff'.repeat(16) }), /different covenant signing session/);
  assert.match(await scanSign({ keyId:'ff'.repeat(32) }), /different covenant key instance/);
  assert.match(await scanSign({ pubkey:'fe'.repeat(32) }), /different covenant key/);
  assert.match(await scanSign({ token:'fd'.repeat(32) }), /different covenant binding record/);
  assert.match(await scanSign({ commitment:'fc'.repeat(32) }), /different Oracle covenant/);

  // A final response before the nonce round is rejected; after committing a
  // nonce, changing it in the final response is also rejected.
  assert.match(await scanSign({ kind:2, signature:'56'.repeat(64) }), /session is missing|restart the request/);
  await scanSign({ kind:1 });
  assert.match(element('cov-oracle-v1-attest-status').textContent, /Nonce committed/);
  // The prior nonce scan committed noncePoint. A different final nonce must fail identity before anti-klepto.
  assert.match(await scanSign({ kind:2, nonce:`02${'46'.repeat(32)}`, signature:'56'.repeat(64) }), /changed the committed nonce/);

  stubs.verify_covenant_anti_klepto = () => false;
  assert.match(await scanSign({ kind:2, nonce:noncePoint, signature:'56'.repeat(64) }), /host nonce verification/);
  stubs.verify_covenant_anti_klepto = () => true;

  // Claim scanner validates every portable binding identity field.
  async function scanClaim(fields) {
    oracle.openOracleV1Claim();
    oracle.scanOracleV1ClaimAttestation();
    await state.scannerState.scanCallback(Buffer.from(responseHex({
      kind:2, session:negativeSession, keyId:fields.keyId ?? keyId,
      pubkey:fields.pubkey ?? pubkey, token:fields.token ?? token,
      commitment:fields.commitment ?? commitment, nonce:noncePoint,
      signature:'56'.repeat(64),
    }), 'hex'));
    return element('toast').textContent;
  }
  assert.match(await scanClaim({ keyId:'aa'.repeat(32) }), /different covenant key instance/);
  assert.match(await scanClaim({ pubkey:'ab'.repeat(32) }), /different covenant key/);
  assert.match(await scanClaim({ token:'ac'.repeat(32) }), /different covenant binding record/);
  assert.match(await scanClaim({ commitment:'ad'.repeat(32) }), /exact statement|different Oracle covenant|commitment/i);
  stubs.verify_oracle_v1_attestation = () => false;
  assert.match(await scanClaim({}), /signature is invalid/i);
  stubs.verify_oracle_v1_attestation = () => true;

  // Claim construction rejects missing destination and invalid signatures.
  oracle.openOracleV1Claim();
  setValue('cov-oracle-v1-claim-dest', '');
  await oracle.buildOracleV1Claim();
  assert.match(element('toast').textContent, /Enter a claim destination/);
  setValue('cov-oracle-v1-claim-dest', ADDRESS);
  setValue('cov-oracle-v1-claim-sig', '56'.repeat(64));
  setValue('cov-oracle-v1-claim-commitment', commitment);
  stubs.verify_oracle_v1_attestation = () => false;
  await oracle.buildOracleV1Claim();
  assert.match(element('toast').textContent, /not valid/i);
  stubs.verify_oracle_v1_attestation = () => true;

  // Beacon publication is watch-only but requires a funding wallet, matching
  // attestation identity, a valid signature, and a usable change/receive address.
  const savedWallet = structuredClone(state.walletSession.current());
  state.walletSession.clear();
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /Load any funding wallet/);
  state.walletSession.replace(savedWallet);

  oracle.openOracleV1Attest();
  oracle.showOracleV1AttestationQr();
  assert.match(element('toast').textContent, /Scan the covenant signature first/);

  // Corrupt/recovered Oracle records must fail closed through the public
  // controller surface, while optional persistence failures remain best-effort.
  const canonicalResult = { ...result };
  state.covenantState.lastCovenantResult = null;
  assert.throws(() => oracle.openOracleV1Claim(), /No Oracle-v1 covenant loaded/);
  state.covenantState.lastCovenantResult = { type:'escrow' };
  assert.throws(() => oracle.openOracleV1Attest(), /No Oracle-v1 covenant loaded/);
  state.covenantState.lastCovenantResult = result;

  oracle.scanOracleV1KeyResponse();
  await state.scannerState.scanCallback(Buffer.from('00', 'hex'));
  assert.match(element('toast').textContent, /response|magic|short|length/i);
  oracle.scanOracleV1BindingResponse();
  await state.scannerState.scanCallback(Buffer.from('00', 'hex'));
  assert.match(element('toast').textContent, /response|magic|short|length/i);

  // A saved beacon can hydrate claim display without fabricating the missing
  // anti-klepto transcript. Sharing remains blocked until a fresh sign flow.
  oracle.openOracleV1Attest();
  result.oracle_attestation_signature = '56'.repeat(64);
  result.oracle_attestation_commitment = commitment;
  oracle.openOracleV1Claim();
  assert.match(element('cov-oracle-v1-claim-status').textContent, /Saved oracle beacon/);
  oracle.showOracleV1AttestationQr();
  assert.match(element('toast').textContent, /Anti-klepto transcript is unavailable/);
  delete result.oracle_attestation_signature;
  delete result.oracle_attestation_commitment;

  // Missing optional record fields are displayed as empty values rather than
  // stale data, but cannot be used to construct a binding request.
  const sparse = { type:'oracle-v1' };
  state.covenantState.lastCovenantResult = sparse;
  oracle.openOracleV1Claim();
  assert.equal(element('cov-oracle-v1-claim-addr').value, '');
  assert.equal(element('cov-oracle-v1-claim-script').value, '');
  assert.equal(element('cov-oracle-v1-claim-text').value, '');
  oracle.openOracleV1Attest();
  assert.equal(element('cov-oracle-v1-attest-text').value, '');
  assert.throws(() => oracle.showOracleV1BindingRequest(), /key|commitment|script|hex|length/i);
  state.covenantState.lastCovenantResult = result;

  // Persistence is intentionally best-effort: a disabled sessionStorage and
  // an absent active-list record must not invalidate a cryptographically valid
  // device binding response.
  const savedActive = state.covenantState.activeCovenants;
  const savedSetItem = sessionStorage.setItem;
  state.covenantState.activeCovenants = [];
  sessionStorage.setItem = () => { throw new Error('storage disabled'); };
  result.oracle_covenant_binding_token_hex = '';
  oracle.scanOracleV1BindingResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({ kind:3, keyId, pubkey, token, commitment:scriptHash }), 'hex'));
  assert.equal(result.oracle_covenant_binding_token_hex, token);
  sessionStorage.setItem = savedSetItem;
  state.covenantState.activeCovenants = savedActive;

  // The sign scanner accepts only nonce/final response kinds after identity
  // binding; unrelated protocol responses fail before state transition.
  await oracle.showOracleV1SignRequest();
  const wrongKindSession = requestField(lastQr, 8, 16);
  oracle.scanOracleV1CovenantSignResponse();
  await state.scannerState.scanCallback(Buffer.from(responseHex({
    kind:3, session:'00'.repeat(16), keyId, pubkey, token, commitment,
  }), 'hex'));
  assert.match(element('toast').textContent, /Expected nonce or final covenant-sign response/);

  // Re-hydrate a cryptographically valid attestation so beacon publication can
  // exercise identity, signature, and wallet-change-address decisions.
  oracle.openOracleV1Claim();
  oracle.scanOracleV1ClaimAttestation();
  await state.scannerState.scanCallback(Buffer.from(finalResponse, 'hex'));
  const beaconWallet = structuredClone(state.walletSession.current());

  result.oracle_covenant_key_id_hex = '99'.repeat(32);
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /different covenant key/);
  result.oracle_covenant_key_id_hex = keyId;
  result.oracle_pubkey_hex = '98'.repeat(32);
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /different covenant key/);
  result.oracle_pubkey_hex = pubkey;
  result.oracle_covenant_binding_token_hex = '97'.repeat(32);
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /different covenant key/);
  result.oracle_covenant_binding_token_hex = token;
  stubs.verify_oracle_v1_attestation = () => false;
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /not valid for this covenant key/);
  stubs.verify_oracle_v1_attestation = () => true;

  state.walletSession.replace({ ...beaconWallet, change_addresses:[], receive_addresses:[] });
  await oracle.publishOracleV1Beacon();
  assert.match(element('toast').textContent, /no change address/i);

  let beaconRequest = null;
  stubs.create_covenant_pskb_with_payload = json => { beaconRequest = JSON.parse(json); return PSKB; };
  state.walletSession.replace({ ...beaconWallet, change_addresses:[], receive_addresses:[ADDRESS] });
  await oracle.publishOracleV1Beacon();
  assert.equal(beaconRequest.change_address, ADDRESS);
  state.walletSession.replace(beaconWallet);
  stubs.create_covenant_pskb_with_payload = () => PSKB;

  Object.assign(result, canonicalResult);

  // Binding metadata is exported/imported and included in encrypted recovery params.
  const exported = beneficiary.buildBeneficiaryExport(result);
  const invite = JSON.parse(Buffer.from(exported.hex.slice(8), 'hex').toString('utf8'));
  assert.equal(invite.okid, keyId);
  assert.equal(invite.obt, token);

  const paramsHex = params.buildCovenantParamsHex(result);
  const rebuilt = oracleRecovery.rebuildOracleV1('oracle-v1', paramsHex);
  assert.equal(rebuilt.oracle_covenant_key_id_hex, keyId);
  assert.equal(rebuilt.oracle_covenant_binding_token_hex, token);
  assert.equal(rebuilt.message_commitment_hex, commitment);

  state.covenantState.activeCovenants = [];
  assert.equal(inviteImport.importCovenantInvite(exported.hex), true);
  assert.equal(state.covenantState.activeCovenants[0].oracle_covenant_binding_token_hex, token);
  assert.equal(inviteImport.importCovenantInvite(exported.hex), false);

  // Repository helpers preserve the binding record through normal active-covenant persistence.
  activeRepo.addActiveRecord('oracle-v1', result);
  assert.equal(activeRepo.activeCovenants()[0].oracle_covenant_binding_token_hex, token);
  activeRepo.saveActiveRecords();
  state.covenantState.activeCovenants = [];
  activeRepo.loadActiveRecords();
  assert.equal(activeRepo.activeCovenants()[0].oracle_covenant_binding_token_hex, token);
  const copied = {};
  activeRepo.copyDefinedFields(result, copied, activeRepo.ACTIVE_METADATA_FIELDS);
  assert.equal(copied.oracle_covenant_binding_token_hex, token);
  activeRepo.removeActiveRecord(0);

  await tick();
  assertWatchOnlyStorage();
  console.log('PASS: covenant key allocation, script binding, Oracle signing, and portable binding recovery paths');
} finally {
  await cleanupDeepHarness();
}
