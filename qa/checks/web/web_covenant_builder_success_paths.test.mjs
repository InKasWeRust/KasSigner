import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element } from './web_recovery_test_harness.mjs';
const PK='11'.repeat(32), PK2='22'.repeat(32), PK3='33'.repeat(32), ADDR='kaspa:runtime-owner';
const result=()=>JSON.stringify({address:'kaspa:runtime-covenant',redeem_script_hex:'51'});
await setupHarness();
try {
 const {networkState,walletSession}=await import(moduleUrl('app/state/index.js'));
 networkState.network='mainnet'; walletSession.replace({kpub:'kpub-test',receive_addresses:[ADDR],change_addresses:[ADDR]});
 Object.assign(globalThis.__KASSEE_WASM_STUBS__,{
  decode_address:()=>JSON.stringify({payload:PK2,version:0}), encode_p2pk_address:()=>ADDR, import_kpub:()=>JSON.stringify({receive_addresses:[ADDR]}), parse_kpub:()=>JSON.stringify({account_pubkey:PK3}),
  covenant_additive_address:result,covenant_timelocked_savings:result,covenant_global_spending_limit:result,covenant_global_allowance:result,covenant_escrow:result,covenant_ship_escrow:result,covenant_dms:result,covenant_merkle_whitelist:result,covenant_commit_reveal:result,covenant_payjoin:result,
  merkle_root_from_addresses:()=>JSON.stringify({root:PK3,depth:1}),blake2b_hash:()=>PK3,
 });
 const savings=await import(moduleUrl('features/covenants/generation/builders/savings.js'));
 element('cov-piggy-goal').value='1'; element('cov-piggy-deadline').value=''; let built=await savings.buildAdditive(PK); assert.ok(built.resultJson);
 element('cov-savings-recovery-pk').value=PK2; element('cov-savings-locktime').value='2000'; element('cov-savings-datetime').value=''; built=await savings.buildTimelockedSavings(PK); assert.equal(built.extra.wallet2_pubkey_hex,PK2);
 const limits=await import(moduleUrl('features/covenants/generation/builders/limits.js'));
 element('cov-splimit-max').value='1'; element('cov-splimit-cooldown').value='30'; built=await limits.buildGlobalSpendingLimit(PK); assert.equal(built.extra.cooldown_daa,300n);
 element('cov-allowance-bene-pk').value=PK2;element('cov-allowance-max').value='1';element('cov-allowance-period').value='60';element('cov-allowance-start').value='';built=await limits.buildGlobalAllowance(PK);assert.equal(built.extra.beneficiary_pubkey_hex,PK2);
 element('cov-allowance-period').value='custom';element('cov-allowance-seq').value='45';built=await limits.buildGlobalAllowance(PK);assert.equal(built.extra.cooldown_daa,450n);
 const escrow=await import(moduleUrl('features/covenants/generation/builders/escrow.js'));
 element('cov-escrow-pk').value=PK2;element('cov-escrow-arbiter-pk').value=PK3;built=await escrow.buildEscrow(PK);assert.equal(built.extra.bob_pk,PK2);
 element('cov-ship-seller-pk').value=PK2;element('cov-ship-deliverer-pk').value=PK3;element('cov-ship-arbiter-pk').value='44'.repeat(32);element('cov-ship-product').value='2';element('cov-ship-fee').value='0.1';element('cov-ship-cltv1').value='2000';element('cov-ship-cltv2').value='3000';built=await escrow.buildShipEscrow(PK);assert.equal(built.extra.seller_pk,PK2);
 const dms=await import(moduleUrl('features/covenants/generation/builders/dms.js')); element('cov-dms2-heir-pk').value=PK2;element('cov-dms2-duration').value='3600';built=await dms.buildDms(PK);assert.equal(built.extra.heir_pubkey_hex,PK2);
 const mw=await import(moduleUrl('features/covenants/generation/builders/advanced/merkle_whitelist.js')); element('cov-mw-addresses').value='kaspa:a\nkaspa:b';element('cov-mw-locktime').value='5000';element('cov-mw-datetime').value='';built=await mw.buildMerkleWhitelist(PK);assert.equal(JSON.parse(built.resultJson).merkle_depth,1);
 const cr=await import(moduleUrl('features/covenants/generation/builders/advanced/commit_reveal.js'));element('cov-cr-hash-display').textContent='BLAKE2B: '+PK3;element('cov-cr-locktime').value='5000';element('cov-cr-datetime').value='';element('cov-cr-ciphertext-hex').value='aa';built=await cr.buildCommitReveal(PK);assert.equal(built.extra.commit_hash,PK3);
 const payjoin=await import(moduleUrl('features/covenants/generation/builders/advanced/payjoin.js'));element('cov-payjoin-bene-pk').value=PK2;element('cov-payjoin-locktime').value='5000';element('cov-payjoin-datetime').value='';element('cov-payjoin-min-inputs').value='2';element('cov-payjoin-min-outputs').value='3';built=await payjoin.buildPayjoin(PK);assert.equal(built.extra.min_outputs,3);
 console.log('PASS: covenant builder success paths');
} finally { teardownHarness(); }
