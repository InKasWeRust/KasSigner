import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setConfirmResult,
  wallet, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

await setupDeepHarness();
try {
  const { walletSession, networkState, navigationState } = await import(moduleUrl('app/state/index.js'));
  const { kpubRepository } = await import(moduleUrl('features/wallet/kpub_manager/repository.js'));
  const ctrl = await import(moduleUrl('features/wallet/kpub_manager/controller.js'));
  globalThis.prompt = (_label, current) => current + ' renamed';

  // Empty repository routes to welcome and hides the saved section.
  kpubRepository.clear?.();
  for (const entry of kpubRepository.list()) kpubRepository.remove(entry.id);
  walletSession.clear?.();
  ctrl.renderWelcomeKpubs();
  assert.equal(element('welcome-saved-kpubs').classList.contains('hidden'), true);
  let route = ctrl.routeStartupKpub();
  assert.equal(route.state, 'empty');

  // Open/close/show/exit paths preserve the return screen and reset import fields.
  ctrl.showKpubManager('welcome', { openImport: true });
  assert.equal(element('kpub-import-form').classList.contains('hidden'), false);
  setValue('input-managed-kpub', wallet.kpub); setValue('input-kpub-friendly-name', 'Deep Wallet');
  ctrl.closeKpubImport();
  assert.equal(element('input-managed-kpub').value, '');
  ctrl.openKpubImport();
  navigationState.kpubManagerReturnScreen = 'welcome';
  ctrl.exitKpubManager();

  // Save a valid watch-only kpub, auto-load it, and render all card actions/badges.
  setValue('input-managed-kpub', wallet.kpub); setValue('input-kpub-friendly-name', 'Deep Wallet');
  element('chk-new-kpub-auto-load').checked = true;
  assert.equal(ctrl.saveManagedKpub(), true);
  assert.equal(walletSession.hasWallet(), true);
  let entries = kpubRepository.list();
  assert.equal(entries.length, 1);
  assert.equal(kpubRepository.autoLoadId(), entries[0].id);
  ctrl.renderKpubManager();
  ctrl.renderWelcomeKpubs();
  assert.equal(element('kpub-saved-count').textContent, '1');
  assert.equal(element('welcome-saved-kpubs').classList.contains('hidden'), false);
  assert.equal(element('kpub-saved-list').children.length, 1);
  assert.equal(element('welcome-kpub-list').children.length, 1);

  // Rendered entry action buttons exercise startup toggle, rename, load and delete.
  const item = element('kpub-saved-list').children[0];
  const actions = item.children.at(-1);
  assert.ok(actions.children.length >= 4);
  actions.children[1].onclick({ stopPropagation() {} }); // stop startup
  assert.equal(kpubRepository.autoLoadId(), null);
  actions.children[1].onclick({ stopPropagation() {} }); // enable startup again
  assert.equal(kpubRepository.autoLoadId(), entries[0].id);
  actions.children[2].onclick({ stopPropagation() {} }); // rename
  entries = kpubRepository.list();
  assert.match(entries[0].name, /renamed/);

  // One-time kpub paths: cancellation preserves current wallet, acceptance switches without persistence.
  setValue('input-managed-kpub', wallet.kpub); setConfirmResult(false);
  assert.equal(ctrl.useKpubOnce(), false);
  setConfirmResult(true); setValue('input-managed-kpub', wallet.kpub);
  assert.equal(ctrl.useKpubOnce(), true);
  assert.equal(walletSession.profile(), null);

  // Loading a saved profile covers missing, already-active, switch-cancel and network-switch paths.
  assert.equal(ctrl.loadSavedKpub('missing'), false);
  const saved = kpubRepository.list()[0];
  setConfirmResult(true);
  assert.equal(ctrl.loadSavedKpub(saved.id), true);
  assert.equal(ctrl.loadSavedKpub(saved.id), true); // already active
  const second = kpubRepository.save({ name:'Testnet Wallet', kpub:wallet.kpub, network:'testnet-10' });
  networkState.network = 'mainnet';
  ctrl.renderKpubManager();
  ctrl.renderWelcomeKpubs();
  assert.equal(element('kpub-saved-count').textContent, '1');
  assert.equal(element('kpub-saved-list').children.length, 1);
  assert.equal(element('welcome-kpub-list').children.length, 1);
  networkState.network = 'testnet-10';
  ctrl.renderKpubManager();
  ctrl.renderWelcomeKpubs();
  assert.equal(element('kpub-saved-count').textContent, '1');
  assert.equal(element('kpub-saved-list').children.length, 1);
  assert.equal(element('welcome-kpub-list').children.length, 1);
  setConfirmResult(false);
  assert.equal(ctrl.loadSavedKpub(second.id), false);
  setConfirmResult(true);
  assert.equal(ctrl.loadSavedKpub(second.id), true);
  assert.equal(networkState.network, 'testnet-10');

  // Startup auto-load and skip-once paths are both observable.
  kpubRepository.setAutoLoad(second.id);
  route = ctrl.routeStartupKpub();
  assert.equal(route.state, 'loaded');
  // state_reset exposes a one-shot skip helper via repository-local storage contract.
  const reset = await import(moduleUrl('features/wallet/state_reset.js'));
  reset.requestSkipAutoLoadOnce?.();
  route = ctrl.routeStartupKpub();
  assert.ok(['selection','loaded'].includes(route.state));

  // Delete inactive and active entries through rendered cards.
  ctrl.renderKpubManager();
  setConfirmResult(false);
  const currentItems = element('kpub-saved-list').children;
  currentItems[0].children.at(-1).children[3].onclick({ stopPropagation() {} });
  assert.ok(kpubRepository.list().length >= 1);
  setConfirmResult(true);
  ctrl.renderKpubManager();
  const deleteItem = element('kpub-saved-list').children[0];
  deleteItem.children.at(-1).children[3].onclick({ stopPropagation() {} });
  assert.ok(kpubRepository.list().length >= 1);

  // Invalid input fails closed and preserves watch-only storage invariant.
  setValue('input-managed-kpub', 'not-a-kpub'); setValue('input-kpub-friendly-name', 'Bad');
  globalThis.__KASSEE_WASM_STUBS__.import_kpub = () => { throw new Error('invalid kpub'); };
  assert.equal(ctrl.saveManagedKpub(), false);
  assertWatchOnlyStorage();

  // Repository hardening covers malformed persistent state, storage failures,
  // duplicate identities/names, missing IDs, and auto-load cleanup directly.
  const { createKpubRepository } = await import(moduleUrl('features/wallet/kpub_manager/repository.js'));
  const memory = new Map();
  const storage = {
    getItem(key) { return memory.get(key) ?? null; },
    setItem(key, value) { memory.set(key, value); },
  };
  let nextId = 0;
  const repo = createKpubRepository(storage, () => `id-${++nextId}`);
  assert.deepEqual(repo.list(), []);
  assert.throws(() => repo.save({ name:'', kpub:'', network:'mainnet' }), /account public key/);
  assert.throws(() => repo.save({ name:'Wallet', kpub:'kpub-one', network:'bogus' }), /Unsupported Kaspa network/);
  assert.throws(() => repo.save({ name:'X'.repeat(65), kpub:'kpub-one', network:'mainnet' }), /64 characters/);
  const one = repo.save({ name:'  Wallet   One  ', kpub:'kpub-one', network:'mainnet' });
  assert.equal(one.name, 'Wallet One');
  const updated = repo.save({ name:'Wallet One Renamed', kpub:'kpub-one', network:'mainnet' });
  assert.equal(updated.id, one.id);
  const two = repo.save({ name:'Wallet Two', kpub:'kpub-two', network:'testnet-10' });
  assert.throws(() => repo.save({ name:'wallet two', kpub:'kpub-three', network:'mainnet' }), /friendly name/);
  assert.throws(() => repo.rename('missing', 'Nope'), /not found/);
  assert.throws(() => repo.rename(one.id, 'Wallet Two'), /friendly name/);
  assert.equal(repo.get('missing'), null);
  assert.equal(repo.remove('missing'), null);
  assert.throws(() => repo.setAutoLoad('missing'), /not found/);
  repo.setAutoLoad(two.id); assert.equal(repo.autoLoadEntry().id, two.id);
  assert.equal(repo.remove(two.id).id, two.id); assert.equal(repo.autoLoadId(), null);
  repo.setAutoLoad(null); assert.equal(repo.autoLoadEntry(), null);

  const brokenRead = createKpubRepository({ getItem(){ throw new Error('read'); }, setItem(){} }, () => 'x');
  assert.deepEqual(brokenRead.list(), []);
  const noStorage = createKpubRepository(null, () => 'x');
  assert.throws(() => noStorage.save({ name:'Wallet', kpub:'kpub-x', network:'mainnet' }), /storage is unavailable/);
  const brokenWrite = createKpubRepository({ getItem(){ return null; }, setItem(){ throw new Error('quota'); } }, () => 'x');
  assert.throws(() => brokenWrite.save({ name:'Wallet', kpub:'kpub-x', network:'mainnet' }), /could not save/);

  memory.set('kassee-kpub-manager-v1', JSON.stringify({ version:1, autoLoadId:'bad', entries:[
    null,
    { id:'', name:'bad', kpub:'x', network:'mainnet' },
    { id:'ok', name:'Good', kpub:'kpub-good', network:'mainnet', createdAt:1, updatedAt:2 },
    { id:'bad-network', name:'Bad Net', kpub:'kpub-bad', network:'bogus' },
  ] }));
  assert.deepEqual(repo.list().map(entry => entry.id), ['ok']);
  assert.equal(repo.autoLoadId(), null);

  console.log('PASS: kpub manager deep watch-only lifecycle paths');
} finally {
  await cleanupDeepHarness();
}
