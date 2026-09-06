import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, TXID, covenantResult,
} from './web_runtime_deep_harness.mjs';
import { FakeElement } from './web_recovery_test_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const covenantReturn = await import(moduleUrl('features/covenants/scanning/return.js'));
  const imageFile = await import(moduleUrl('core/qr/image_file.js'));
  const safeHtml = await import(moduleUrl('core/security/safe_html.js'));
  const exact = await import(moduleUrl('core/exact.js'));
  const amounts = await import(moduleUrl('core/amounts.js'));
  const bytes = await import(moduleUrl('core/bytes.js'));
  const format = await import(moduleUrl('core/format.js'));
  const daa = await import(moduleUrl('core/node/daa.js'));
  const futureDaa = await import(moduleUrl('core/node/future_daa.js'));
  const screenDom = await import(moduleUrl('core/ui/screen_dom.js'));
  const utxoCore = await import(moduleUrl('core/utxo.js'));
  const resolver = await import(moduleUrl('core/node/resolver.js'));

  // Exercise the successful post-broadcast return path with a watched covenant.
  // This covers the outpoint capture guards, result-field restoration, TXID action,
  // metadata/balance restoration, and watcher restart through production routing.
  state.oracleState._oracleMbReturn = false;
  state.covenantState.lastCovenantResult = covenantResult('escrow');
  state.covenantWatcherState._covWatcherOutpoint = null;
  element('broadcast-result-txid').textContent = TXID;
  covenantReturn.covReturnAfterBroadcast();
  assert.equal(element('cov-result-addr').textContent, state.covenantState.lastCovenantResult.address);
  assert.equal(element('cov-result-script').textContent, state.covenantState.lastCovenantResult.redeem_script_hex);
  assert.equal(element('cov-result-txid').textContent, TXID);
  assert.equal(element('cov-result-balance').textContent, 'Loading...');
  await element('cov-result-txid').onclick();

  // Also cover the oracle return short-circuit without opening a real transport.
  state.oracleState._oracleMbReturn = true;
  covenantReturn.covReturnAfterBroadcast();
  assert.equal(state.oracleState._oracleMbReturn, false);

  // Cover browser-native QR image decode and the fail-closed missing-canvas path.
  const originalCreateImageBitmap = globalThis.createImageBitmap;
  const originalJsQr = globalThis.jsQR;
  const originalCreateElement = document.createElement;
  globalThis.createImageBitmap = async () => ({ width: 2, height: 2, close() {} });
  globalThis.jsQR = (_pixels, width, height) => ({ data: `${width}x${height}` });
  const file = { size: 16, type: 'image/png' };
  assert.equal((await imageFile.decodeQrImageFile(file)).data, '2x2');

  document.createElement = tag => {
    const node = new FakeElement(tag);
    if (String(tag).toLowerCase() === 'canvas') node.getContext = () => null;
    return node;
  };
  await assert.rejects(() => imageFile.decodeQrImageFile(file), /could not create an image decoder canvas/);
  document.createElement = originalCreateElement;
  if (originalCreateImageBitmap === undefined) delete globalThis.createImageBitmap;
  else globalThis.createImageBitmap = originalCreateImageBitmap;
  if (originalJsQr === undefined) delete globalThis.jsQR;
  else globalThis.jsQR = originalJsQr;

  // Minimal-DOM sanitizer fallback must preserve requested markup as literal text.
  const target = new FakeElement('div');
  safeHtml.setSafeMarkup(target, '<img src=x onerror=alert(1)>');
  assert.match(target.innerHTML, /&lt;img/);
  assert.doesNotMatch(target.innerHTML, /<img/i);

  // Exact-integer utility boundaries that are part of transaction/runtime input handling.
  assert.equal(exact.nonNegativeDifference(1n, 2n), 0n);
  assert.equal(exact.nonNegativeDifference(3n, 1n), 2n);
  assert.equal(amounts.sompiToKasFixed(100000000n, 0), '1');
  assert.throws(() => bytes.u64ToLittleEndianHex(0x10000000000000000n), /unsigned 64-bit/);

  // Presentation/nullish boundaries and deterministic DAA failure behavior.
  const originalLocaleString = Date.prototype.toLocaleString;
  Date.prototype.toLocaleString = () => { throw new Error('locale unavailable'); };
  assert.match(format.formatStartDate({ start_date_iso: '2099-01-01', start_daa: '5' }, null), /^DAA /);
  Date.prototype.toLocaleString = originalLocaleString;
  state.networkState.utxoSnapshot = [{ block_daa_score: null }];
  assert.equal(daa.estimateCurrentDaaFromUtxos(), 0n);
  const previousDaaStub = globalThis.__KASSEE_WASM_STUBS__.get_virtual_daa_score;
  globalThis.__KASSEE_WASM_STUBS__.get_virtual_daa_score = () => '0';
  state.networkState.utxoSnapshot = [];
  await assert.rejects(() => futureDaa.resolveFutureDaa('2099-01-01T00:00:00Z'), /Could not fetch DAA score/);
  globalThis.__KASSEE_WASM_STUBS__.get_virtual_daa_score = previousDaaStub;

  // Missing-screen paths are fail-closed rather than fabricating navigation targets.
  const originalGetElementById = document.getElementById;
  document.getElementById = id => String(id).includes('definitely-missing') ? null : originalGetElementById.call(document, id);
  assert.equal(screenDom.activateScreen('definitely-missing'), false);
  assert.equal(screenDom.setScreenReturn('definitely-missing', 'dashboard'), undefined);
  document.getElementById = originalGetElementById;

  // Stable UTXO ordering covers both outpoint-id and index tie breakers.
  const equalAmount = 5n;
  const ordered = utxoCore.sortUtxosLargestFirst([
    { tx_id: 'bb', index: 0, amount: equalAmount },
    { tx_id: 'aa', index: 2, amount: equalAmount },
    { tx_id: 'aa', index: 1, amount: equalAmount },
  ]);
  assert.deepEqual(ordered.map(item => `${item.tx_id}:${item.index}`), ['aa:1', 'aa:2', 'bb:0']);

  // Resolver mirrors rusty-kaspa browser policy: HTTP pages request `any`,
  // while HTTPS pages require TLS and therefore a wss:// result.
  const originalFetch = globalThis.fetch;
  const originalLocation = globalThis.location;
  const resolverRequests = [];
  globalThis.location = { protocol: 'http:' };
  globalThis.fetch = async url => {
    resolverRequests.push(String(url));
    return { ok: true, async json() { return { url: 'ws://runtime-resolved' }; } };
  };
  assert.equal(await resolver.resolvePublicNode(), 'ws://runtime-resolved');
  assert.match(resolverRequests.at(-1), /\/any\/wrpc\/borsh$/);
  globalThis.location = { protocol: 'https:' };
  globalThis.fetch = async url => {
    resolverRequests.push(String(url));
    return { ok: true, async json() { return { url: 'wss://runtime-resolved' }; } };
  };
  assert.equal(await resolver.resolvePublicNode(), 'wss://runtime-resolved');
  assert.match(resolverRequests.at(-1), /\/tls\/wrpc\/borsh$/);
  globalThis.fetch = originalFetch;
  if (originalLocation === undefined) delete globalThis.location;
  else globalThis.location = originalLocation;

  console.log('PASS: web-runtime branch ratchet');
} finally {
  await cleanupDeepHarness();
}
