import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, BENEFICIARY, PK, PK2, PK3, TXID, TXID2, PSKB, COV_ID, covenantResult,
  utxos, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const sharing = await import(moduleUrl('app/events/contracts/covenant_creation/sharing_and_claims.js'));
  const ownerActions = await import(moduleUrl('app/events/contracts/covenant_creation/result_actions/owner.js'));
  const beneActions = await import(moduleUrl('app/events/contracts/covenant_creation/result_actions/beneficiary.js'));
  const utilities = await import(moduleUrl('app/events/contracts/covenant_loading/utilities.js'));
  const policy = await import(moduleUrl('app/events/contracts/covenant_creation/withdrawal_and_consolidation/policy.js'));
  const build = await import(moduleUrl('app/events/contracts/covenant_creation/withdrawal_and_consolidation/build.js'));
  const withdrawal = await import(moduleUrl('app/events/contracts/covenant_creation/withdrawal_and_consolidation/controller.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  let daa = 1000n;
  let covenantUtxos = structuredClone(utxos);
  stubs.get_virtual_daa_score = () => daa.toString();
  stubs.fetch_utxos_for_address_js = () => JSON.stringify(covenantUtxos);
  stubs.pskt_summary = () => JSON.stringify({
    format:'pskb',tx_version:0,input_count:1,output_count:1,fee_sompi:'1000',total_in_sompi:'250000000',total_out_sompi:'249999000',finalize_ready:true,
    inputs:[{script_kind:'p2pk',sigs_present:1,multisig_m:null,multisig_n:null,amount_sompi:'250000000',prev_tx_id:TXID,prev_index:0}],
    outputs:[{script_kind:'p2pk',amount_sompi:'249999000',address:ADDRESS}],
  });

  sharing.registerSharingAndClaims();

  // Spend-panel navigation covers no-result/result branches and DMS
  // heartbeat prefill. Borrower/beneficiary presets copy only public covenant data.
  state.covenantState.lastCovenantResult=null; element('btn-cov-owner-back').onclick(); assert.equal(element('cov-menu').classList.contains('hidden'),false);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),address:ADDRESS,redeem_script_hex:'51'}; element('btn-cov-owner-spend').onclick(); assert.equal(element('cov-owner-dest').value,ADDRESS);
  element('btn-cov-borrower-spend').onclick(); assert.equal(element('cov-borrower-addr').value,ADDRESS); assert.equal(element('cov-borrower-script').value,'51');
  element('btn-cov-beneficiary-spend').onclick(); assert.equal(element('cov-bene-addr').value,ADDRESS);
  state.covenantState.lastCovenantResult=null; element('btn-cov-borrower-back').onclick(); assert.equal(element('cov-menu').classList.contains('hidden'),false);

  // Beneficiary picker timing preflight blocks immature absolute and relative
  // claims, then permits the same selection after the covenant matures.
  state.covenantState.lastCovenantResult={...covenantResult('timelocked-savings'),locktime_daa:'2000'}; setValue('cov-bene-dest',BENEFICIARY); setValue('cov-bene-locktime','2000'); daa=1000n;
  await element('btn-cov-bene-pick').onclick(); assert.match(element('toast').textContent,/Still locked/);
  daa=2500n; await element('btn-cov-bene-pick').onclick(); assert.equal(element('cov-consolidate-panel').classList.contains('hidden'),false);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),inactivity_daa:'500',address:ADDRESS}; covenantUtxos=[{...utxos[0],block_daa_score:'900'}]; daa=1200n;
  await element('btn-cov-bene-pick').onclick(); assert.match(element('toast').textContent,/No vault UTXO has aged/);
  daa=1500n; await element('btn-cov-bene-pick').onclick(); assert.equal(element('cov-consolidate-panel').classList.contains('hidden'),false);

  setValue('cov-dms2-preset','86400'); element('cov-dms2-preset').onchange(); assert.equal(element('cov-dms2-duration').value,'86400'); setValue('cov-dms2-preset','custom'); element('cov-dms2-preset').onchange(); assert.equal(element('cov-dms2-custom-wrap').classList.contains('hidden'),false);

  // Result owner action covers no covenant, every help/amount/control mode,
  // single-UTXO piggy status, multi-UTXO picker, and timelock status banners.
  ownerActions.registerOwnerAction();
  state.covenantState.lastCovenantResult=null; await element('btn-cov-res-owner').onclick(); assert.match(element('toast').textContent,/No covenant loaded/);
  const ownerModes=[
    {...covenantResult('global-allowance'),type:'global-allowance'},
    {...covenantResult('global-spending-limit'),type:'global-spending-limit',max_withdraw_sompi:'100000000'},
    {...covenantResult('dms'),type:'dms'},
  ];
  for(const result of ownerModes){state.covenantState.lastCovenantResult=result; await element('btn-cov-res-owner').onclick(); assert.equal(element('cov-owner-panel').dataset.covOwnerType,result.type);}
  for (const [threshold,deadline,fragment] of [['100000000','2000','goal'],['100000000','0','goal'],['0','2000','deadline'],['0','0','No conditions']]) {
    state.covenantState.lastCovenantResult={...covenantResult('additive'),type:'additive',threshold_sompi:threshold,deadline_daa:deadline}; covenantUtxos=[{...utxos[0],amount:'250000000'}]; await element('btn-cov-res-owner').onclick(); await tick(); assert.match(element('cov-owner-help').textContent,new RegExp(fragment,'i'));
  }
  state.covenantState.lastCovenantResult={...covenantResult('additive'),type:'additive',threshold_sompi:'0',deadline_daa:'0'}; covenantUtxos=structuredClone(utxos); await element('btn-cov-res-owner').onclick(); assert.equal(element('cov-consolidate-panel').classList.contains('hidden'),false);

  // Beneficiary result routing exercises DMS-owner withdrawal,
  // attestation hydration, allowance/timelocked/DMS beneficiary presentation.
  beneActions.registerBeneficiaryAction(); state.covenantState.lastCovenantResult=null; await element('btn-cov-res-bene').onclick(); assert.match(element('toast').textContent,/No covenant loaded/);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms',role:'owner'}; await element('btn-cov-res-bene').onclick(); assert.equal(element('cov-owner-panel').dataset.covOwnerMode,'withdraw'); assert.match(element('btn-cov-owner-create').textContent,/Withdrawal/);
  state.covenantState.lastCovenantResult={...covenantResult('global-allowance'),type:'global-allowance',max_withdraw_sompi:'100000000',cooldown_daa:'50'}; await element('btn-cov-res-bene').onclick(); assert.match(element('cov-bene-help').textContent,/Withdraw up to 1 KAS/);
  state.covenantState._lastKnownDaa=1000n; state.covenantState.lastCovenantResult={...covenantResult('timelocked-savings'),type:'timelocked-savings',locktime_daa:'2000',locktime_date_iso:'2026-08-14'}; await element('btn-cov-res-bene').onclick(); assert.match(element('cov-bene-help').textContent,/Claim once/);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms',role:'beneficiary',inactivity_daa:'100'}; await element('btn-cov-res-bene').onclick(); assert.match(element('cov-bene-help').textContent,/Claim inheritance/);

  // Withdrawal policy branches are checked independently: unconditional,
  // goal-met, deadline-met, dual-condition failure, goal-only/deadline-only
  // failures, and timelocked beneficiary selection.
  const selected=[{...utxos[0],amount:'100000000'}];
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms'}; assert.equal(await policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),'');
  state.covenantState.lastCovenantResult={...covenantResult('additive'),type:'additive',threshold_sompi:'0',deadline_daa:'0'}; assert.equal(await policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),'');
  state.covenantState.lastCovenantResult.threshold_sompi='50000000'; assert.equal(await policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),'');
  state.covenantState.lastCovenantResult.threshold_sompi='200000000'; state.covenantState.lastCovenantResult.deadline_daa='900'; daa=1000n; assert.equal(await policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),'owner-time');
  state.covenantState.lastCovenantResult.deadline_daa='2000'; daa=1000n; await assert.rejects(policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),error=>error instanceof policy.CovenantSpendPolicyError && /below the goal/.test(error.message) && error.duration===7500);
  state.covenantState.lastCovenantResult.deadline_daa='0'; await assert.rejects(policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),/below the goal/);
  state.covenantState.lastCovenantResult.threshold_sompi='0'; state.covenantState.lastCovenantResult.deadline_daa='2000'; await assert.rejects(policy.ownerSpendBranch({isConsolidate:false,selected,fee:1000n}),/deadline has not passed/);
  state.covenantState._lastKnownDaa=1000n; assert.doesNotThrow(()=>policy.assertBeneficiaryClaimUnlocked('dms',2000n)); assert.throws(()=>policy.assertBeneficiaryClaimUnlocked('timelocked-savings',2000n),/Still locked/); state.covenantState._lastKnownDaa=2500n; assert.doesNotThrow(()=>policy.assertBeneficiaryClaimUnlocked('timelocked-savings',2000n));

  // Selected-spend builder preserves exact owner/beneficiary branch choice and
  // refuses an early timelocked claim before any WASM transaction is created.
  const buildCalls=[];
  stubs.create_covenant_owner_spend_selected=(...args)=>{buildCalls.push(['owner',...args]);return PSKB}; stubs.create_covenant_beneficiary_spend_selected=(...args)=>{buildCalls.push(['bene',...args]);return PSKB}; stubs.create_covenant_timelocked_savings_claim_selected=(...args)=>{buildCalls.push(['time',...args]);return PSKB};
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms'}; state.covenantState._pickerBeneClaim=null; assert.equal(build.buildSelectedSpend({destination:BENEFICIARY,selected,fee:1000n,ownerBranch:'owner-time'}),PSKB); assert.equal(buildCalls.at(-1)[0],'owner');
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms'}; state.covenantState._pickerBeneClaim={locktime:'0'}; assert.equal(build.buildSelectedSpend({destination:BENEFICIARY,selected,fee:1000n,ownerBranch:''}),PSKB); assert.equal(buildCalls.at(-1)[0],'bene');
  state.covenantState.lastCovenantResult={...covenantResult('timelocked-savings'),type:'timelocked-savings'}; state.covenantState._pickerBeneClaim={locktime:'2000'}; state.covenantState._lastKnownDaa=1000n; assert.throws(()=>build.buildSelectedSpend({destination:BENEFICIARY,selected,fee:1000n,ownerBranch:''}),/Still locked/); state.covenantState._lastKnownDaa=2500n; assert.equal(build.buildSelectedSpend({destination:BENEFICIARY,selected,fee:1000n,ownerBranch:''}),PSKB); assert.equal(buildCalls.at(-1)[0],'time');

  // Withdrawal/consolidation controller validates selection/destination/count,
  // applies policy, and routes successful owner spends to hardware PSKB review.
  withdrawal.registerWithdrawalAndConsolidation();
  const list=element('cov-consol-list'); const makeChecks=count=>Array.from({length:count},(_,index)=>({checked:true,dataset:{utxoIdx:String(index)}})); let checks=[];
  list.querySelectorAll=selector=>selector==='input[type="checkbox"]'?checks:[];
  state.covenantState.lastCovenantResult=null; checks=[]; await element('btn-consol-create').onclick(); assert.match(element('toast').textContent,/No covenant loaded/);
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms',address:ADDRESS}; list.dataset.utxos=JSON.stringify(utxos); checks=[]; setValue('cov-consol-dest',BENEFICIARY); await element('btn-consol-create').onclick(); assert.match(element('toast').textContent,/Select at least 1/);
  checks=makeChecks(1); setValue('cov-consol-dest',''); await element('btn-consol-create').onclick(); assert.match(element('toast').textContent,/destination/);
  setValue('cov-consol-dest',ADDRESS); await element('btn-consol-create').onclick(); assert.match(element('toast').textContent,/at least 2 UTXOs/);
  checks=makeChecks(2); setValue('cov-consol-dest',ADDRESS); state.covenantState._pickerBeneClaim=null; await element('btn-consol-create').onclick(); assert.ok(state.transactionState._psktReviewHex,'successful consolidation opens PSKB review');
  checks=makeChecks(1); setValue('cov-consol-dest',BENEFICIARY); await element('btn-consol-create').onclick(); assert.equal(state.navigationState._broadcastReturnScreen,'covenant');
  element('btn-consol-select-none').onclick(); assert.equal(checks.every(check=>!check.checked),true); element('btn-consol-select-all').onclick(); assert.equal(checks.every(check=>check.checked),true); element('btn-consol-back').onclick(); assert.equal(element('cov-result-panel').classList.contains('hidden'),false);

  // Utility bindings cover canonical/raw hashing, failure, DAA preview, clipboard,
  // scanner callbacks, balance/reclaim panel hydration, and balance scan.
  utilities.bindSwapAndUtilityActions();
  element('cov-result-addr').textContent=ADDRESS; element('cov-result-addr').onclick(); assert.match(element('toast').textContent,/copied/); element('cov-result-script').textContent='51'; element('cov-result-script').onclick();
  for(const [button,target] of [['btn-cov-scan-owner-addr','cov-owner-addr'],['btn-cov-scan-owner-dest','cov-owner-dest'],['btn-consol-scan-dest','cov-consol-dest'],['btn-cov-scan-borrower-addr','cov-borrower-addr'],['btn-cov-scan-balance-addr','cov-balance-addr']]){element(button).onclick(); state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS)); assert.equal(element(target).value,ADDRESS);}
  state.covenantState.lastCovenantResult={...covenantResult('dms'),address:ADDRESS,redeem_script_hex:'51'}; element('btn-cov-check-balance').onclick(); assert.equal(element('cov-balance-addr').value,ADDRESS); element('btn-cov-owner-reclaim').onclick(); assert.equal(element('cov-owner-script').value,'51');

  // Sparse/corrupt recovery records exercise the display fallbacks without
  // reusing stale covenant data. Long malformed escrow scripts are contained
  // by the auto-fill parser and still leave the manual destination path usable.
  state.covenantState.lastCovenantResult={type:'unknown'};
  element('btn-cov-owner-spend').onclick(); assert.equal(element('cov-owner-addr').value,''); assert.equal(element('cov-owner-script').value,'');
  element('btn-cov-borrower-spend').onclick(); assert.equal(element('cov-borrower-addr').value,'');
  element('btn-cov-beneficiary-spend').onclick(); assert.equal(element('cov-bene-addr').value,'');
  element('btn-cov-timeout-refund').onclick(); assert.equal(element('cov-timeout-addr').value,''); assert.equal(element('cov-timeout-script').value,'');
  state.covenantState.lastCovenantResult={type:'escrow',address:ADDRESS,redeem_script_hex:'ff'.repeat(120)};
  element('btn-cov-beneficiary-spend').onclick(); assert.equal(element('cov-bene-addr').value,ADDRESS);

  // DMS picker tolerates node lookup failure and absent/zero DAA metadata by
  // falling back to the picker; a zero inactivity policy likewise has no CSV gate.
  state.covenantState.lastCovenantResult={...covenantResult('dms'),type:'dms',address:ADDRESS,inactivity_daa:'500'}; daa=1200n;
  stubs.fetch_utxos_for_address_js=()=>{throw new Error('dms lookup unavailable');};
  await element('btn-cov-bene-pick').onclick(); assert.match(element('toast').textContent,/Error loading UTXOs.*dms lookup unavailable/); assert.equal(element('cov-result-panel').classList.contains('hidden'),false);
  covenantUtxos=[{...utxos[0],block_daa_score:undefined},{...utxos[1],block_daa_score:'0'}]; stubs.fetch_utxos_for_address_js=()=>JSON.stringify(covenantUtxos);
  await element('btn-cov-bene-pick').onclick(); assert.equal(element('cov-consolidate-panel').classList.contains('hidden'),false);
  state.covenantState.lastCovenantResult.inactivity_daa='0'; await element('btn-cov-bene-pick').onclick();

  // Additive-owner status remains best-effort if UTXO discovery or amount
  // decoding fails; multiple UTXOs still route to explicit selection.
  state.covenantState.lastCovenantResult={type:'additive',address:ADDRESS,threshold_sompi:'0',deadline_daa:'0'};
  stubs.fetch_utxos_for_address_js=()=>{throw new Error('piggy lookup unavailable');}; await element('btn-cov-res-owner').onclick(); assert.match(element('toast').textContent,/Error loading UTXOs.*piggy lookup unavailable/); assert.equal(element('cov-result-panel').classList.contains('hidden'),false);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'not-a-number'}]); await element('btn-cov-res-owner').onclick(); assert.equal(element('cov-owner-panel').dataset.covOwnerType,'additive');

  // Owner/beneficiary result panels explicitly handle missing optional policy
  // fields and the Oracle-v1 route instead of inheriting a prior screen value.
  state.covenantState.lastCovenantResult={type:'global-spending-limit'}; await element('btn-cov-res-owner').onclick(); assert.match(element('cov-owner-help').textContent,/per-spend cap/);
  state.covenantState.lastCovenantResult={type:'oracle-v1',locktime_daa:'1200'}; await element('btn-cov-res-owner').onclick(); assert.match(element('btn-cov-owner-create').textContent,/Timeout Refund/);
  state.covenantState.lastCovenantResult={type:'global-allowance',max_withdraw_sompi:'0',cooldown_daa:'0'}; await element('btn-cov-res-bene').onclick(); assert.match(element('cov-bene-help').textContent,/the cap.*none cooldown/);
  state.covenantState.lastCovenantResult={type:'dms',role:'beneficiary',inactivity_daa:'0'}; await element('btn-cov-res-bene').onclick(); assert.match(element('cov-bene-help').textContent,/unknown/);
  state.covenantState.lastCovenantResult={type:'ordinary',locktime_daa:''}; await element('btn-cov-res-bene').onclick(); assert.equal(element('cov-bene-locktime').value,'');
  state.covenantState.lastCovenantResult={type:'oracle-v1',address:ADDRESS,redeem_script_hex:'51',attestation_statement:'',oracle_covenant_key_id_hex:'',oracle_pubkey_hex:'',oracle_covenant_binding_token_hex:''}; await element('btn-cov-res-bene').onclick(); assert.equal(element('cov-oracle-v1-claim-addr').value,ADDRESS);

  // Invite sharing serializes each public policy shape and refuses an unbound
  // Oracle covenant. Capture the QR payload so the assertions validate the
  // actual portable record rather than only checking that a button fired.
  let invitePayload=''; stubs.generate_qr_svg_text=value=>{invitePayload=String(value);return '<svg></svg>';};
  state.covenantState.lastCovenantResult=null; element('btn-cov-res-share-cov').onclick();
  state.covenantState.lastCovenantResult={type:'additive',address:''}; element('btn-cov-res-share-cov').onclick(); assert.equal(invitePayload,'');
  state.covenantState.lastCovenantResult={type:'dms',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0',inactivity_daa:'500'}; element('btn-cov-res-share-cov').onclick(); assert.equal(JSON.parse(invitePayload).id,'500');
  state.covenantState.lastCovenantResult={type:'timelocked-savings',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'1200',wallet1_pubkey_hex:PK,wallet2_pubkey_hex:PK2,locktime_date_iso:'2099-01-01'}; element('btn-cov-res-share-cov').onclick(); assert.equal(JSON.parse(invitePayload).w2,PK2);
  state.covenantState.lastCovenantResult={type:'global-allowance',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0',max_withdraw_sompi:'100',min_sequence:'50',start_daa:'10',start_date_iso:'2099-01-01'}; element('btn-cov-res-share-cov').onclick(); assert.equal(JSON.parse(invitePayload).cd,'50');
  state.covenantState.lastCovenantResult={type:'oracle-v1',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0'}; element('btn-cov-res-share-cov').onclick(); assert.match(element('toast').textContent,/Bind the Oracle covenant key/);
  state.covenantState.lastCovenantResult={type:'oracle-v1',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0',oracle_covenant_binding_token_hex:'ab'.repeat(32),oracle_pubkey_hex:PK2,oracle_covenant_key_id_hex:PK3,beneficiary_pubkey_hex:PK2,owner_pubkey_hex:PK,attestation_statement:'release',message_commitment_hex:PK3}; element('btn-cov-res-share-cov').onclick(); assert.equal(JSON.parse(invitePayload).obt,'ab'.repeat(32));

  stubs.fetch_utxos_for_address_js=()=>JSON.stringify(utxos);

  assertWatchOnlyStorage();
  console.log('PASS: covenant result actions, picker policy, scanner utilities, and selected-spend review paths');
} finally {
  await cleanupDeepHarness();
}
