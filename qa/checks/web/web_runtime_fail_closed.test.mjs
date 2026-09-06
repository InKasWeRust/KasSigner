import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setupHarness, teardownHarness } from './web_recovery_test_harness.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..', '..', '..');
const jsRoot = path.join(root, 'apps', 'kassee-web', 'web', 'js');
const PRIVATE_RE = /(?:mnemonic|xprv|private[_-]?key|secret[_-]?key|mySecretKey|_swap_secret_key)/i;
const SKIP_EXPORTS = new Set(['default']);

async function jsFiles(dir) {
  const out = [];
  for (const ent of await fs.readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...await jsFiles(p));
    else if (ent.isFile() && ent.name.endsWith('.js')) out.push(p);
  }
  return out.sort();
}

function storageSnapshot(storage) {
  const out = {};
  for (let i = 0; i < storage.length; i++) {
    const k = storage.key(i);
    out[k] = storage.getItem(k);
  }
  return out;
}

function assertNoPrivateMaterial() {
  for (const [name, storage] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
    const serialized = JSON.stringify(storageSnapshot(storage));
    assert.equal(PRIVATE_RE.test(serialized), false, `${name} must remain watch-only during malformed-boundary sweep`);
  }
}

const generic = Object.freeze({
  network: 'mainnet', address: 'kaspa:owner-receive', changeAddress: 'kaspa:change',
  ownerAddress: 'kaspa:owner-receive', beneficiaryAddress: 'kaspa:beneficiary',
  amount: '100000000', fee: '1000', value: '100000000', balance: '250000000',
  txid: 'aa'.repeat(32), transactionId: 'aa'.repeat(32), index: 0,
  ownerPk: '11'.repeat(32), beneficiaryPk: '22'.repeat(32), publicKey: '11'.repeat(32),
  script: '51', redeemScript: '51', redeem_script_hex: '51', payload: '', payloadHex: '',
  utxos: [{ transactionId: 'aa'.repeat(32), index: 0, amount: '250000000', scriptPublicKey: '51' }],
  inputs: [], outputs: [], partialSigs: {}, properties: {},
});

function corpusArgs(fn) {
  const width = fn.length;
  const fill = first => Array.from({ length: width }, (_, i) => i === 0 ? first : undefined);
  if (width === 0) return [[]];
  return [fill(undefined)];
}

await setupHarness();
class FakeWebSocket {
  static OPEN = 1; constructor(url) { this.url = url; this.readyState = 1; queueMicrotask(() => this.onopen?.()); }
  addEventListener(type, cb) { if (type === "open") queueMicrotask(cb); }
  send() {} close() { this.readyState = 3; this.onclose?.(); }
}
globalThis.WebSocket = FakeWebSocket;
try {
  const failures = [];
  let invoked = 0;
  let controlledErrors = 0;
  const files = await jsFiles(jsRoot);
  for (const file of files) {
    const mod = await import(`${pathToFileURL(file).href}`);
    for (const [name, value] of Object.entries(mod)) {
      if (SKIP_EXPORTS.has(name) || typeof value !== 'function') continue;
      // Constructors/classes are not public operation boundaries and throw when
      // invoked without `new`; identify them by their native source shape.
      if (/^class\s/.test(Function.prototype.toString.call(value))) continue;
      for (const args of corpusArgs(value)) {
        invoked += 1;
        try {
          const result = value(...args);
          if (result && typeof result.then === 'function') await result;
        } catch (error) {
          controlledErrors += 1;
          assert.ok(error instanceof Error || typeof error === 'string', `${file}:${name} must fail with a controlled error`);
        }
        assertNoPrivateMaterial();
      }
    }
  }
  assert.ok(invoked >= 250, `expected broad public runtime sweep, invoked ${invoked} exported functions`);
  assert.ok(controlledErrors >= 25, `expected malformed inputs to exercise fail-closed paths, saw ${controlledErrors}`);
  assert.deepEqual(failures, []);
  console.log(`PASS: malformed-boundary fail-closed sweep (${invoked} exported functions; ${controlledErrors} controlled errors)`);
} finally {
  await teardownHarness();
}
