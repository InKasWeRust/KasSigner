import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue,
  ADDRESS, BENEFICIARY, PK, PK2, PK3, PSKB, covenantResult, wallet,
  assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const generate = await import(moduleUrl('features/covenants/generation/create.js'));
  const vault = await import(moduleUrl('app/events/contracts/tagged_vault/online.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  // Exercise every covenant generation family with realistic watch-only public
  // material. Each successful result must become active/persisted public state.
  const types=['additive','timelocked-savings','global-spending-limit','global-allowance','escrow','ship-escrow','dms','payjoin','commit-reveal','merkle-whitelist'];
  setValue('cov-piggy-goal','1'); setValue('cov-piggy-deadline','2000');
  setValue('cov-savings-recovery-pk',PK2); setValue('cov-savings-locktime','2000');
  setValue('cov-splimit-max','1'); setValue('cov-splimit-cooldown','10');
  setValue('cov-allowance-bene-pk',PK2); setValue('cov-allowance-max','1'); setValue('cov-allowance-seq','10'); setValue('cov-allowance-start','1000');
  setValue('cov-dms2-heir-pk',PK2); setValue('cov-dms2-duration','100');
  setValue('cov-escrow-bob-pk',PK2); setValue('cov-escrow-arbiter-pk',PK3);
  setValue('cov-ship-seller-pk',PK2); setValue('cov-ship-deliverer-pk',PK3); setValue('cov-ship-price','1');
  setValue('cov-payjoin-peer-pk',PK2); setValue('cov-payjoin-locktime','2000');
  setValue('cov-cr-hash',PK3); setValue('cov-cr-locktime','2000');
  setValue('cov-mw-addresses',ADDRESS+'\n'+BENEFICIARY); setValue('cov-mw-locktime','2000');
  let generated=0;
  for (const type of types) {
    setValue('cov-type',type);
    await generate.handleCovGenerate();
    if (state.covenantState.lastCovenantResult?.type===type) {
      generated++;
      assert.match(element('cov-result-addr').textContent,/kaspa:/);
      assert.equal(element('cov-result-script').textContent,'51');
    }
  }
  assert.ok(generated >= 5, `expected multiple covenant generation families to succeed, got ${generated}/${types.length}`);
  // Missing watch-only identity and builder failure are controlled errors.
  const saved=state.walletSession.current(); state.walletSession.clear(); setValue('cov-type','dms'); await generate.handleCovGenerate(); assert.match(element('toast').textContent,/wallet first/i); state.walletSession.replace(saved);
  const oldDms=stubs.covenant_dms; stubs.covenant_dms=()=>{throw new Error('generation fail')}; setValue('cov-dms2-heir-pk',PK2); setValue('cov-dms2-duration','100'); setValue('cov-type','dms'); await generate.handleCovGenerate(); assert.match(element('toast').textContent,/Covenant error/i); stubs.covenant_dms=oldDms;

  // Tagged/split vaults are watch-only planners: identity, validation, genesis,
  // continuation, split genesis/spend, and builder errors all end at PSKB review.
  const tvState={}; const logs=[]; vault.bindTaggedVaultOnline(tvState,msg=>logs.push(String(msg)));
  element('btn-tv-keygen').onclick(); assert.equal(tvState.pk,PK); assert.match(element('tv-eph-address').textContent,/kaspa:/);
  setValue('tv-amount','0.01'); await element('btn-tv-genesis').onclick(); assert.match(element('toast').textContent,/0.1 KAS/i);
  setValue('tv-amount','1'); await element('btn-tv-genesis').onclick(); assert.equal(state.transactionState._psktReviewHex,PSKB); assert.ok(tvState.covId);
  await element('btn-tv-spend').onclick(); assert.equal(state.transactionState._psktReviewHex,PSKB); assert.match(element('tv-spend-txid').textContent,/Pending KasSigner/);
  const freshVault={}; vault.bindTaggedVaultOnline(freshVault,()=>{}); await element('btn-tv-spend').onclick(); assert.match(element('toast').textContent,/genesis first/i);
  vault.bindTaggedVaultOnline(tvState,msg=>logs.push(String(msg)));
  tvState.splitCovId=''; tvState.splitCovAddr=''; await element('btn-tv-split').onclick(); assert.ok(tvState.splitCovId); assert.equal(state.transactionState._psktReviewHex,PSKB); await element('btn-tv-split').onclick(); assert.equal(state.transactionState._psktReviewHex,PSKB); assert.match(element('tv-split-txid').textContent,/Pending KasSigner/);
  const oldTagged=stubs.tagged_vault_genesis_pskb; stubs.tagged_vault_genesis_pskb=()=>{throw new Error('vault fail')}; const errState={}; vault.bindTaggedVaultOnline(errState,msg=>logs.push(String(msg))); setValue('tv-amount','1'); await element('btn-tv-genesis').onclick(); assert.ok(logs.some(x=>/ERROR:.*vault fail/.test(x))); stubs.tagged_vault_genesis_pskb=oldTagged;
  state.walletSession.clear(); element('btn-tv-keygen').onclick(); assert.match(element('toast').textContent,/Watch-only account required/i); state.walletSession.replace(saved);
  element('btn-tv-back').onclick();


  assertWatchOnlyStorage();
  console.log(`PASS: ${generated} covenant generators, tagged/split vault hardware planning`);
} finally { await cleanupDeepHarness(); }
