import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, PK, PK2, PK3, covenantResult, utxos, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
const encode = obj => new TextEncoder().encode(typeof obj === 'string' ? obj : JSON.stringify(obj));
try {
  const wasm = globalThis.__KASSEE_WASM_STUBS__;
  wasm.generate_qr_svg_text = value => `<svg>${String(value).slice(0,24)}</svg>`;

  // Share every currently supported generic invite shape. Private Swap v2
  // has its own transaction-bound adaptor handshake and is covered separately.
  const invites = await import(moduleUrl('app/events/contracts/covenant_creation/invite_sharing.js'));
  invites.registerInviteSharingActions();
  for (const type of ['additive', 'dms', 'timelocked-savings', 'global-allowance']) {
    state.covenantState.lastCovenantResult = {
      ...covenantResult(type),
      inactivity_daa: '100',
      wallet1_pubkey_hex: PK,
      wallet2_pubkey_hex: PK2,
      locktime_date_iso: '2026-08-14T12:00:00Z',
      max_withdraw_sompi: '100000000',
      cooldown_daa: '50',
      start_daa: '900',
      start_date_iso: '2026-08-14',
    };
    element('btn-cov-res-share-cov').onclick();
    assert.match(element('qr-container').innerHTML, /<svg>/);
  }

  // Current covenant invite loading accepts only the generic current schema.
  // Retired raw-signature protocol metadata has no special recovery path.
  const loading = await import(moduleUrl('app/events/contracts/covenant_loading/invites.js'));
  loading.bindInviteLoadingActions();
  setValue('cov-load-type', 'escrow');
  element('btn-cov-load-back').onclick();
  element('btn-cov-load-scan').onclick();
  state.scannerState.scanCallback(encode({t: 'wrong'}));
  assert.match(element('toast').textContent, /Not a covenant invite/i);
  element('btn-cov-load-scan').onclick();
  await state.scannerState.scanCallback(encode({
    t: 'cov-invite', ct: 'global-allowance', addr: ADDRESS, rs: '51', d: '1400', id: '100', ldi: '2026-08-14',
  }));
  await tick();
  assert.equal(state.covenantRecoveryState._covLoadedFromInvite, true);
  assert.equal(state.covenantRecoveryState._covLoadedInactivityDaa, '100');
  assert.equal(state.covenantRecoveryState._covLoadedLdi, '2026-08-14');
  assert.equal(element('cov-load-type').value, 'global-allowance');
  element('btn-cov-load-scan').onclick();
  state.scannerState.scanCallback(encode('{bad'));
  assert.match(element('toast').textContent, /Invalid invite/i);
  const fileInput = element('cov-load-file-input');
  await fileInput.onchange({target: {files: [], value: 'x'}});
  await fileInput.onchange({target: {files: [{async arrayBuffer() { throw new Error('file corrupt'); }}], value: 'x'}});
  assert.match(element('toast').textContent, /File import failed/i);

  // Load submission still covers script-number extraction and invited-role
  // restoration for supported covenant families.
  const submission = await import(moduleUrl('app/events/contracts/covenant_loading/submission.js'));
  submission.bindLoadSubmissionAction();
  setValue('cov-load-addr', '');
  setValue('cov-load-script', '51');
  element('btn-cov-load-submit').onclick();
  assert.match(element('toast').textContent, /address/i);
  setValue('cov-load-addr', ADDRESS);
  setValue('cov-load-script', '');
  element('btn-cov-load-submit').onclick();
  assert.match(element('toast').textContent, /redeem script/i);
  state.covenantRecoveryState._covLoadedFromInvite = true;
  state.covenantRecoveryState._covLoadedInactivityDaa = '100';
  state.covenantRecoveryState._covLoadedLdi = '2026-08-14';
  setValue('cov-load-type', 'global-allowance');
  setValue('cov-load-script', '0150b0');
  element('btn-cov-load-submit').onclick();
  assert.equal(state.covenantState.lastCovenantResult.loaded, true);
  assert.equal(String(state.covenantState.lastCovenantResult.locktime_daa), '80');
  assert.equal(state.covenantState.lastCovenantResult.role, 'beneficiary');

  assertWatchOnlyStorage();
  console.log('PASS: current covenant invite/load event workflows');
} finally {
  await cleanupDeepHarness();
}
