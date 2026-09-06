import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue,
  ADDRESS, PK, PK2, wallet, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const bytes = text => new TextEncoder().encode(text);
await setupDeepHarness();
try {
  const { scannerState, networkState } = await import(moduleUrl('app/state/index.js'));
  const scan = await import(moduleUrl('features/covenants/scanning/pubkeys.js'));
  const invoke = data => {
    assert.equal(typeof scannerState.scanCallback, 'function');
    scannerState.scanCallback(bytes(data));
  };

  // Pubkey scanner: address, raw x-only, kpub, and rejection branches.
  networkState.network = 'mainnet';
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', false); invoke(ADDRESS); assert.match(element('cov-beneficiary-pk').value, /kaspa/);
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', false); invoke(PK2); assert.match(element('cov-beneficiary-pk').value, /kaspa/);
  globalThis.__KASSEE_WASM_STUBS__.import_kpub = () => JSON.stringify(wallet);
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => JSON.stringify({payload:PK});
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', false); invoke(wallet.kpub); assert.match(element('cov-beneficiary-pk').value, /kaspa/);
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', true); invoke(wallet.kpub); assert.equal(scannerState.scanCallback, null);

  // Invalid address payload and decode errors fail closed.
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => JSON.stringify({payload:'12'});
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', false); invoke(ADDRESS); assert.equal(scannerState.scanCallback, null);
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => { throw new Error('bad address'); };
  scan.covScanPubkey('cov-beneficiary-pk', 'beneficiary', false); invoke(ADDRESS); assert.equal(scannerState.scanCallback, null);

  // Address scanner: valid, wrong network, kpub-rejected, non-address, missing payload, decode exception.
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => JSON.stringify({payload:PK});
  scan.covScanAddress('cov-destination', 'address', false); invoke(ADDRESS); assert.equal(element('cov-destination').value, ADDRESS);
  scan.covScanAddress('cov-destination', 'address', true); invoke(wallet.kpub); assert.equal(scannerState.scanCallback, null);
  scan.covScanAddress('cov-destination', 'address', false); invoke('nonsense'); assert.equal(scannerState.scanCallback, null);
  networkState.network = 'testnet-10';
  scan.covScanAddress('cov-destination', 'address', false); invoke('kaspa:wrong-network'); assert.equal(scannerState.scanCallback, null);
  networkState.network = 'mainnet';
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => JSON.stringify({});
  scan.covScanAddress('cov-destination', 'address', false); invoke(ADDRESS); assert.equal(scannerState.scanCallback, null);
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => { throw new Error('decode'); };
  scan.covScanAddress('cov-destination', 'address', false); invoke(ADDRESS); assert.equal(scannerState.scanCallback, null);

  // Append scanner deduplicates and counts addresses.
  globalThis.__KASSEE_WASM_STUBS__.decode_address = () => JSON.stringify({payload:PK});
  setValue('cov-address-list', '');
  scan.covScanAddressAppend('cov-address-list', 'append'); invoke(ADDRESS); assert.equal(element('cov-address-list').value, ADDRESS);
  scan.covScanAddressAppend('cov-address-list', 'append'); invoke(ADDRESS); assert.equal(element('cov-address-list').value, ADDRESS);
  scan.covScanAddressAppend('cov-address-list', 'append'); invoke('not-an-address'); assert.equal(scannerState.scanCallback, null);

  // Image-file QR decoding covers validation, bitmap scaling, canvas decode, close, and decoder-unavailable/error shapes.
  const image = await import(moduleUrl('core/qr/image_file.js'));
  let closed = 0;
  globalThis.createImageBitmap = async () => ({ width:4096, height:1024, close(){ closed++; } });
  globalThis.jsQR = (data, width, height, options) => ({ data:'runtime', binaryData:[1,2,3], width, height, options });
  const code = await image.decodeQrImageFile({ size:1024, type:'image/png' });
  assert.equal(code.data, 'runtime'); assert.equal(closed, 1);
  await assert.rejects(() => image.decodeQrImageFile(null), /Choose/);
  await assert.rejects(() => image.decodeQrImageFile({size:17*1024*1024,type:'image/png'}), /16 MiB/);
  await assert.rejects(() => image.decodeQrImageFile({size:10,type:'text/plain'}), /not an image/);
  globalThis.jsQR = undefined;
  await assert.rejects(() => image.decodeQrImageFile({size:10,type:'image/png'}), /decoder is unavailable/);
  globalThis.jsQR = () => null;
  globalThis.createImageBitmap = async () => ({ width:0,height:0,close(){} });
  await assert.rejects(() => image.decodeQrImageFile({size:10,type:'image/png'}), /no readable dimensions/);

  assertWatchOnlyStorage();
  console.log('PASS: covenant scanner and QR image deep boundary paths');
} finally { await cleanupDeepHarness(); }
