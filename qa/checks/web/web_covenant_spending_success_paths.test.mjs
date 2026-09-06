import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element } from './web_recovery_test_harness.mjs';

const ADDRESS='kaspa:runtime-covenant'; const DEST='kaspa:runtime-dest'; const TX='aa'.repeat(32); const CID='33'.repeat(32); const PSKB='50534b42';
await setupHarness();
try {
  const { covenantState, navigationState, networkState, transactionState, walletSession } = await import(moduleUrl('app/state/index.js'));
  walletSession.replace({kpub:'kpub-test',receive_addresses:[DEST],change_addresses:[DEST],next_receive_index:0,next_change_index:0});
  networkState.network='mainnet'; networkState.customNodeUrl='wss://covenant-test'; networkState.lastFeeEstimate={normal_sompi_per_gram:'1'};
  let currentDaa='2000';
  const utxos=[{tx_id:TX,index:0,amount:'250000000',block_daa_score:'900',covenant_id:CID,script_public_key:'000051'}];
  Object.assign(globalThis.__KASSEE_WASM_STUBS__,{
    get_virtual_daa_score:()=>currentDaa, fetch_utxos_for_address_js:()=>JSON.stringify(utxos), decode_address:()=>JSON.stringify({payload:'11'.repeat(32),version:0}), encode_p2pk_address:()=>DEST,
    create_covenant_owner_spend:()=>PSKB, create_global_spending_limit_withdraw:()=>PSKB,
    create_covenant_borrower_spend:()=>PSKB, create_covenant_borrower_withdraw:()=>PSKB, create_global_allowance_withdraw:()=>PSKB,
    create_covenant_beneficiary_spend:()=>PSKB, create_covenant_timelocked_savings_claim:()=>PSKB, create_covenant_timeout_refund:()=>PSKB,
    pskt_summary:()=>JSON.stringify({format:'pskb',tx_version:0,input_count:0,output_count:0,fee_sompi:'0',total_in_sompi:'0',total_out_sompi:'0',finalize_ready:false,inputs:[],outputs:[]}),
  });
  const owner=await import(moduleUrl('features/covenants/spending/standard/thread_and_claims/owner.js'));
  element('cov-owner-addr').value=ADDRESS; element('cov-owner-script').value='51'; element('cov-owner-dest').value=DEST;
  // Standard full owner sweep.
  covenantState.lastCovenantResult={type:'savings',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0'};
  element('cov-owner-panel').dataset.covOwnerType='savings'; element('cov-owner-amount').value='';
  await owner.handleCovOwnerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  // Partial owner spend builds an unsigned PSKB locally with covenant change.
  transactionState._psktReviewHex=null; element('cov-owner-amount').value='1'; await owner.handleCovOwnerSpend();
  assert.ok(transactionState._psktReviewHex?.startsWith('50534b42'));
  // Global spending-limit close and capped partial paths.
  covenantState.lastCovenantResult={type:'global-spending-limit',address:ADDRESS,redeem_script_hex:'51',covenant_id_hex:CID,cooldown_daa:'0',max_withdraw_sompi:'250000000'};
  element('cov-owner-panel').dataset.covOwnerType='global-spending-limit'; element('cov-owner-amount').value=''; await owner.handleCovOwnerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  element('cov-owner-amount').value='1'; await owner.handleCovOwnerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  // Current CLTV owner reclaim rejects before maturity, then succeeds once mature.
  covenantState.lastCovenantResult={type:'merkle-whitelist',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'3000'}; element('cov-owner-panel').dataset.covOwnerType='merkle-whitelist'; element('cov-owner-amount').value='';
  currentDaa='2000'; transactionState._psktReviewHex=null; await owner.handleCovOwnerSpend(); assert.equal(transactionState._psktReviewHex,null);
  currentDaa='4000'; await owner.handleCovOwnerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);

  const part=await import(moduleUrl('features/covenants/spending/standard/thread_and_claims/participants.js'));
  element('cov-borrower-addr').value=ADDRESS; element('cov-borrower-script').value='51'; element('cov-borrower-amount').value='1';
  element('cov-borrower-mode').value='spend'; await part.handleCovBorrowerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  element('cov-borrower-mode').value='withdraw'; await part.handleCovBorrowerSpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  const benePanel=element('cov-beneficiary-panel'); element('cov-bene-addr').value=ADDRESS; element('cov-bene-script').value='51'; element('cov-bene-dest').value=DEST; element('cov-bene-locktime').value='1000';
  // Timelocked savings success.
  benePanel.dataset.covBeneType='timelocked-savings'; covenantState.lastCovenantResult={type:'timelocked-savings',locktime_daa:'1000'}; currentDaa='2000'; await part.handleCovBeneficiarySpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  // DMS inactivity success.
  benePanel.dataset.covBeneType='dms'; covenantState.lastCovenantResult={type:'dms',inactivity_daa:'500'}; currentDaa='2000'; await part.handleCovBeneficiarySpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  // Global allowance withdrawal with thread selection and storage-mass fee.
  benePanel.dataset.covBeneType='global-allowance'; covenantState.lastCovenantResult={type:'global-allowance',covenant_id_hex:CID,start_daa:'0',cooldown_daa:'0',max_withdraw_sompi:'200000000'}; element('cov-bene-amount').value='1'; await part.handleCovBeneficiarySpend(); assert.equal(transactionState._psktReviewHex,PSKB);
  // Timeout refund claim controller path.
  element('cov-timeout-addr').value=ADDRESS; element('cov-timeout-script').value='51'; element('cov-timeout-locktime').value='1000'; element('cov-timeout-dest').value=DEST;
  await part.handleCovTimeoutRefund(); assert.equal(transactionState._psktReviewHex,PSKB);
  // Generic escrow spend branches build local unsigned PSKBs and route to hardware review.
  const shipment=await import(moduleUrl('features/covenants/spending/standard/shipment.js'));
  covenantState.lastCovenantResult={type:'escrow',address:ADDRESS,redeem_script_hex:'51',alice_pk:'11'.repeat(32),bob_pk:'22'.repeat(32)};
  for (const branch of ['buyer-release','buyer-dispute','seller-dispute','arbiter-award-seller','arbiter-refund-buyer']) {
    transactionState._psktReviewHex=null;
    await shipment.handleEscrowSpend(branch);
    assert.ok(transactionState._psktReviewHex?.startsWith('50534b42'), `escrow ${branch} must route unsigned PSKB to review`);
  }
  assert.equal(navigationState._broadcastReturnScreen,'covenant');

  // The public spending controllers fail closed before constructing a PSKB.
  // Exercise each user-controlled field independently rather than asserting on
  // private helpers or injecting impossible return values.
  const loadedWallet={kpub:'kpub-test',receive_addresses:[DEST],change_addresses:[DEST],next_receive_index:0,next_change_index:0};
  walletSession.clear();
  await part.handleCovBorrowerSpend();
  assert.match(element('toast').textContent,/Load wallet/);
  walletSession.replace(loadedWallet);
  element('cov-borrower-addr').value=''; await part.handleCovBorrowerSpend(); assert.match(element('toast').textContent,/P2SH address/);
  element('cov-borrower-addr').value=ADDRESS; element('cov-borrower-script').value=''; await part.handleCovBorrowerSpend(); assert.match(element('toast').textContent,/redeem script/);
  element('cov-borrower-script').value='51'; element('cov-borrower-amount').value='1.000000001'; await part.handleCovBorrowerSpend(); assert.match(element('toast').textContent,/valid amount/);
  element('cov-borrower-amount').value='0'; await part.handleCovBorrowerSpend(); assert.match(element('toast').textContent,/Enter amount/);
  element('cov-borrower-amount').value='1';
  const oldBorrow=globalThis.__KASSEE_WASM_STUBS__.create_covenant_borrower_spend;
  globalThis.__KASSEE_WASM_STUBS__.create_covenant_borrower_spend=()=>{throw new Error('borrower rejected')};
  element('cov-borrower-mode').value='spend'; await part.handleCovBorrowerSpend(); assert.match(element('toast').textContent,/Borrower TX failed/);
  globalThis.__KASSEE_WASM_STUBS__.create_covenant_borrower_spend=oldBorrow;

  // Beneficiary field validation and timelock enforcement are independent of
  // the eventual covenant-signature path.
  element('cov-bene-addr').value=''; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/P2SH address/);
  element('cov-bene-addr').value=ADDRESS; element('cov-bene-script').value=''; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/redeem script/);
  element('cov-bene-script').value='51'; element('cov-bene-dest').value=''; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/destination/);
  element('cov-bene-dest').value=DEST; benePanel.dataset.covBeneType='timelocked-savings';
  element('cov-bene-locktime').value='0'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/locktime DAA/);
  element('cov-bene-locktime').value='3000'; currentDaa='2000'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/Still locked/);
  currentDaa='4000';

  // Global allowance rejects missing/ambiguous/closed thread identity and
  // policy-invalid withdrawal amounts before calling the WASM builder.
  benePanel.dataset.covBeneType='global-allowance'; element('cov-bene-amount').value='1';
  covenantState.lastCovenantResult={type:'global-allowance',covenant_id_hex:'',start_daa:'0',cooldown_daa:'0',max_withdraw_sompi:'200000000'};
  utxos.splice(0,utxos.length);
  await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/No UTXO/);
  utxos.push(
    {tx_id:TX,index:0,amount:'250000000',block_daa_score:'900',covenant_id:'11'.repeat(32)},
    {tx_id:'bb'.repeat(32),index:1,amount:'250000000',block_daa_score:'901',covenant_id:'22'.repeat(32)},
  );
  await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/Multiple covenant-tagged/);
  utxos.splice(0,utxos.length,{tx_id:TX,index:0,amount:'250000000',block_daa_score:'900',covenant_id:CID});
  covenantState.lastCovenantResult={type:'global-allowance',covenant_id_hex:CID,start_daa:'5000',cooldown_daa:'0',max_withdraw_sompi:'200000000'};
  currentDaa='4000'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/Not started yet/);
  covenantState.lastCovenantResult.start_daa='0'; covenantState.lastCovenantResult.cooldown_daa='5000'; currentDaa='4000';
  await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/Cooldown not elapsed/);
  covenantState.lastCovenantResult.cooldown_daa='0'; currentDaa='6000';
  element('cov-bene-amount').value='3'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/exceeds the thread balance/);
  element('cov-bene-amount').value='2.5'; covenantState.lastCovenantResult.max_withdraw_sompi='100000000'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/over the per-spend cap/);
  element('cov-bene-amount').value='1.5'; await part.handleCovBeneficiarySpend(); assert.match(element('toast').textContent,/Per-spend cap/);

  // Timeout-refund entry fields are separately validated.
  element('cov-timeout-addr').value=''; await part.handleCovTimeoutRefund(); assert.match(element('toast').textContent,/P2SH address/);
  element('cov-timeout-addr').value=ADDRESS; element('cov-timeout-script').value=''; await part.handleCovTimeoutRefund(); assert.match(element('toast').textContent,/redeem script/);
  element('cov-timeout-script').value='51'; element('cov-timeout-locktime').value='0'; await part.handleCovTimeoutRefund(); assert.match(element('toast').textContent,/locktime/);
  element('cov-timeout-locktime').value='1000'; element('cov-timeout-dest').value=''; await part.handleCovTimeoutRefund(); assert.match(element('toast').textContent,/refund destination/);

  // Owner spending validates input fields and full-only covenant policies.
  element('cov-owner-addr').value=''; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/P2SH address/);
  element('cov-owner-addr').value=ADDRESS; element('cov-owner-script').value=''; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/redeem script/);
  element('cov-owner-script').value='51'; element('cov-owner-dest').value=''; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/destination/);
  element('cov-owner-dest').value=DEST; element('cov-owner-amount').value='1.000000001'; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/valid KAS amount/);
  element('cov-owner-amount').value='1'; element('cov-owner-panel').dataset.covOwnerType='commit-reveal'; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/full-only/);
  element('cov-owner-panel').dataset.covOwnerType='oracle-v1'; await owner.handleCovOwnerSpend(); assert.match(element('toast').textContent,/full-only/);

  console.log('PASS: covenant owner/borrower/beneficiary/timeout success and fail-closed paths');
} finally { teardownHarness(); }
