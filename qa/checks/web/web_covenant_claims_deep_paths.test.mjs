import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, setValue, element,
  ADDRESS, BENEFICIARY, PK, PK2, SIG, PSKB, COV_ID, TXID, TXID2, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const owner = await import(moduleUrl('features/covenants/spending/standard/thread_and_claims/owner.js'));
  const participants = await import(moduleUrl('features/covenants/spending/standard/thread_and_claims/participants.js'));
  const specialized = await import(moduleUrl('features/covenants/spending/standard/thread_and_claims/specialized.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  const baseUtxo = { tx_id:TXID,index:0,amount:'250000000',block_daa_score:'900',covenant_id:COV_ID,script_public_key:'000051' };
  let daa = '2000';
  let wasmUtxos = [baseUtxo];
  stubs.get_virtual_daa_score = () => daa;
  stubs.fetch_utxos_for_address_js = () => JSON.stringify(wasmUtxos);
  const clearReview = () => { state.transactionState._psktReviewHex = null; };
  const setDataset = (id, key, value) => { const node=element(id); node.__deepFilled=true; node.dataset[key]=value; };

  // Owner validation is fail-closed before any transaction is produced.
  setValue('cov-owner-addr',''); setValue('cov-owner-script','51'); setValue('cov-owner-dest',ADDRESS); clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-owner-addr',ADDRESS); setValue('cov-owner-script',''); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-owner-script','51'); setValue('cov-owner-dest',''); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-owner-dest',ADDRESS); setValue('cov-owner-amount','not-kas'); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-owner-amount','1'); setDataset('cov-owner-panel','covOwnerType','commit-reveal'); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);

  // Partial owner spend: missing UTXO and insufficient balance reject; valid partial remains unsigned PSKB review.
  setDataset('cov-owner-panel','covOwnerType','savings'); setValue('cov-owner-amount','1'); wasmUtxos=[]; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[{...baseUtxo,amount:'1000000'}]; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[baseUtxo]; clearReview(); await owner.handleCovOwnerSpend(); assert.match(state.transactionState._psktReviewHex,/^50534b42/);

  // Every CLTV-only owner type refuses an immature reclaim and succeeds after maturity.
  setValue('cov-owner-amount','');
  for (const type of ['payjoin','merkle-whitelist','commit-reveal']) {
    setDataset('cov-owner-panel','covOwnerType',type);
    state.covenantState.lastCovenantResult={type,address:ADDRESS,redeem_script_hex:'51',locktime_daa:'3000'};
    daa='2000'; clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null,`${type} must reject immature owner reclaim`);
    daa='4000'; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB,`${type} mature reclaim must route to KasSigner review`);
  }

  // Global spending-limit thread selection, cooldown, cap, storage mass, and success paths.
  setDataset('cov-owner-panel','covOwnerType','global-spending-limit');
  state.covenantState.lastCovenantResult={type:'global-spending-limit',address:ADDRESS,redeem_script_hex:'51',covenant_id_hex:'',cooldown_daa:'0',max_withdraw_sompi:'100000000'};
  wasmUtxos=[]; clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[baseUtxo,{...baseUtxo,tx_id:TXID2,index:1,covenant_id:'dd'.repeat(32)}]; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  state.covenantState.lastCovenantResult.covenant_id_hex=COV_ID; wasmUtxos=[{...baseUtxo,covenant_id:'dd'.repeat(32)}]; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[baseUtxo]; state.covenantState.lastCovenantResult.cooldown_daa='500'; daa='1000'; await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  state.covenantState.lastCovenantResult.cooldown_daa='0'; daa='2000'; setValue('cov-owner-amount',''); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null,'balance over cap cannot sweep');
  setValue('cov-owner-amount','2'); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,null,'partial over cap rejects');
  setValue('cov-owner-amount','1'); clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Borrower input validation, both modes, and propagated builder errors.
  setValue('cov-borrower-addr',''); setValue('cov-borrower-script','51'); setValue('cov-borrower-amount','1'); clearReview(); await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-borrower-addr',ADDRESS); setValue('cov-borrower-script',''); await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-borrower-script','51'); setValue('cov-borrower-amount','bad'); await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-borrower-amount','0'); await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-borrower-amount','1'); element('cov-borrower-mode').value='spend'; stubs.create_covenant_borrower_spend=()=>{throw new Error('builder fail')}; await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,null);
  stubs.create_covenant_borrower_spend=()=>PSKB; await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  element('cov-borrower-mode').value='withdraw'; stubs.create_covenant_borrower_withdraw=()=>PSKB; clearReview(); await participants.handleCovBorrowerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Beneficiary required fields and timelock/DMS maturity gates.
  setDataset('cov-beneficiary-panel','covBeneType','timelocked-savings');
  for (const [id,val] of [['cov-bene-addr',''],['cov-bene-script',''],['cov-bene-dest','']]) {
    setValue('cov-bene-addr',ADDRESS); setValue('cov-bene-script','51'); setValue('cov-bene-dest',BENEFICIARY); setValue(id,val); clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  }
  setValue('cov-bene-addr',ADDRESS); setValue('cov-bene-script','51'); setValue('cov-bene-dest',BENEFICIARY); setValue('cov-bene-locktime','bad'); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-bene-locktime','3000'); state.covenantState.lastCovenantResult={type:'timelocked-savings',locktime_daa:'3000'}; daa='2000'; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  daa='4000'; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  setDataset('cov-beneficiary-panel','covBeneType','dms'); state.covenantState.lastCovenantResult={type:'dms',inactivity_daa:'500'}; wasmUtxos=[baseUtxo]; daa='1000'; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  daa='2000'; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Global allowance: unavailable/ambiguous/closed threads, timing, cap, storage mass, and valid withdrawal.
  setDataset('cov-beneficiary-panel','covBeneType','global-allowance'); setValue('cov-bene-amount','1');
  state.covenantState.lastCovenantResult={type:'global-allowance',covenant_id_hex:'',start_daa:'0',cooldown_daa:'0',max_withdraw_sompi:'100000000'};
  wasmUtxos=[]; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[baseUtxo,{...baseUtxo,tx_id:TXID2,covenant_id:'dd'.repeat(32)}]; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  state.covenantState.lastCovenantResult.covenant_id_hex=COV_ID; wasmUtxos=[{...baseUtxo,covenant_id:'dd'.repeat(32),amount:'100000000'}]; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  wasmUtxos=[baseUtxo]; state.covenantState.lastCovenantResult.start_daa='3000'; daa='2000'; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  state.covenantState.lastCovenantResult.start_daa='0'; state.covenantState.lastCovenantResult.cooldown_daa='500'; daa='1000'; await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  state.covenantState.lastCovenantResult.cooldown_daa='0'; daa='2000'; setValue('cov-bene-amount','2'); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-bene-amount','1'); clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Global allowance edge policies: an untagged version-1 UTXO cannot become a
  // thread by guesswork; unavailable DAA skips only the local preflight (the
  // covenant remains enforced on-chain); zero withdrawal and storage-mass dust
  // are rejected; a high fee-rate path is reflected in the constructed PSKB.
  state.covenantState.lastCovenantResult={type:'global-allowance',covenant_id_hex:'',start_daa:'0',cooldown_daa:'0',max_withdraw_sompi:'0'};
  wasmUtxos=[{...baseUtxo,covenant_id:''}]; setValue('cov-bene-amount','1'); clearReview(); await participants.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/covenant_id unavailable/);
  wasmUtxos=[baseUtxo]; state.covenantState.lastCovenantResult.cooldown_daa='500'; state.networkState.utxoSnapshot=[]; daa='0'; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB,'unavailable DAA must not invent an early-lock rejection');
  state.covenantState.lastCovenantResult.cooldown_daa='0'; setValue('cov-bene-amount','0'); clearReview(); await participants.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/positive amount/);
  wasmUtxos=[{...baseUtxo,amount:'1000000'}]; setValue('cov-bene-amount','0.005'); clearReview(); await participants.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/storage mass/);
  wasmUtxos=[baseUtxo]; setValue('cov-bene-amount','1'); state.networkState.lastFeeEstimate={normal_sompi_per_gram:'100'}; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB); state.networkState.lastFeeEstimate=null;

  // Standard claim preflight also handles an unavailable DAA score, non-DMS
  // immediate beneficiary paths, zero-inactivity DMS, and UTXOs without DAA
  // metadata without fabricating maturity information.
  setDataset('cov-beneficiary-panel','covBeneType','ordinary'); state.covenantState.lastCovenantResult={type:'ordinary'}; setValue('cov-bene-locktime','1'); wasmUtxos=[baseUtxo]; daa='0'; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  setDataset('cov-beneficiary-panel','covBeneType','dms'); state.covenantState.lastCovenantResult={type:'dms',inactivity_daa:'0'}; setValue('cov-bene-locktime','0'); clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  state.covenantState.lastCovenantResult.inactivity_daa='500'; wasmUtxos=[{...baseUtxo,block_daa_score:undefined}]; daa='2000'; clearReview(); await participants.handleCovBeneficiarySpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Owner global-thread edge cases mirror the beneficiary safety rules: never
  // guess an untagged thread, tolerate unavailable DAA only as a local preflight
  // limitation, reject over-balance/dust-producing withdrawals, and exercise the
  // explicit no-fee-estimate calculation path.
  setDataset('cov-owner-panel','covOwnerType','global-spending-limit'); setValue('cov-owner-addr',ADDRESS); setValue('cov-owner-script','51'); setValue('cov-owner-dest',ADDRESS);
  state.covenantState.lastCovenantResult={type:'global-spending-limit',address:ADDRESS,redeem_script_hex:'51',covenant_id_hex:'',cooldown_daa:'0',max_withdraw_sompi:'0'};
  wasmUtxos=[{...baseUtxo,covenant_id:''}]; setValue('cov-owner-amount','1'); clearReview(); await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/covenant_id unavailable/);
  wasmUtxos=[baseUtxo]; state.covenantState.lastCovenantResult.cooldown_daa='500'; state.networkState.utxoSnapshot=[]; daa='0'; clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  state.covenantState.lastCovenantResult.cooldown_daa='0'; setValue('cov-owner-amount','3'); clearReview(); await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/exceeds the thread balance/);
  wasmUtxos=[{...baseUtxo,amount:'1000000'}]; setValue('cov-owner-amount','0.005'); clearReview(); await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/storage mass/);
  wasmUtxos=[baseUtxo]; setValue('cov-owner-amount','1'); state.networkState.lastFeeEstimate=null; clearReview(); await owner.handleCovOwnerSpend(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  // Timeout and specialized claim controllers cover validation and build failures.
  setValue('cov-timeout-addr',''); setValue('cov-timeout-script','51'); setValue('cov-timeout-locktime','1000'); setValue('cov-timeout-dest',ADDRESS); clearReview(); await participants.handleCovTimeoutRefund(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-timeout-addr',ADDRESS); setValue('cov-timeout-locktime','0'); await participants.handleCovTimeoutRefund(); assert.equal(state.transactionState._psktReviewHex,null);
  setValue('cov-timeout-locktime','1000'); stubs.create_covenant_timeout_refund=()=>PSKB; await participants.handleCovTimeoutRefund(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  setValue('cov-payjoin-claim-addr',ADDRESS); setValue('cov-payjoin-claim-script','51'); setValue('cov-payjoin-claim-mix-addr',ADDRESS); setValue('cov-payjoin-claim-dest',BENEFICIARY); clearReview(); await specialized.handleCovPayjoinClaim(); assert.equal(state.transactionState._psktReviewHex,PSKB);

  assert.equal(state.navigationState._broadcastReturnScreen,'covenant');
  assertWatchOnlyStorage();
  console.log('PASS: covenant claim validation, timing, thread, cap, and hardware-review paths');
} finally {
  await cleanupDeepHarness();
}
