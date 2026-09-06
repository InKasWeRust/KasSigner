import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setFetchHook,
  ADDRESS, BENEFICIARY, EXTERNAL, PK, PK2, PK3, PSKB, TXID, COV_ID,
  covenantResult, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

await setupDeepHarness();
try {
  const { covenantState, covenantWatcherState, commitRevealState, transactionState, navigationState } = await import(moduleUrl('app/state/index.js'));
  const wasm = globalThis.__KASSEE_WASM_STUBS__;

  // Advanced covenant spending: Merkle max calculation + validation/success/error.
  const advanced = await import(moduleUrl('features/covenants/spending/advanced.js'));
  setValue('cov-mw-addr', '');
  assert.equal(await advanced.mwMaxSompi(), null);
  setValue('cov-mw-addr', ADDRESS);
  wasm.fetch_utxos_for_address_js = () => '[]';
  assert.equal(await advanced.mwMaxSompi(), null);
  setValue('cov-mw-spend-addresses', [ADDRESS, BENEFICIARY, EXTERNAL, 'kaspa:four'].join('\n'));
  wasm.fetch_utxos_for_address_js = () => JSON.stringify([
    {tx_id:TXID,index:0,amount:'100000000'}, {tx_id:'bb'.repeat(32),index:1,amount:'90000000'},
    {tx_id:'cc'.repeat(32),index:2,amount:'80000000'}, {tx_id:'dd'.repeat(32),index:3,amount:'70000000'},
    {tx_id:'ee'.repeat(32),index:4,amount:'60000000'},
  ]);
  const max = await advanced.mwMaxSompi();
  assert.ok(max > 300000000n && max < 340000000n, 'merkle max must cap inputs and subtract mass fee');
  wasm.fetch_utxos_for_address_js = () => JSON.stringify([{tx_id:TXID,index:0,amount:'1'}]);
  assert.equal(await advanced.mwMaxSompi(), null);

  for (const [id, value] of [['cov-mw-addr',''], ['cov-mw-script',''], ['cov-mw-dest',''], ['cov-mw-spend-addresses','']]) {
    setValue('cov-mw-addr', ADDRESS); setValue('cov-mw-script','51'); setValue('cov-mw-dest',BENEFICIARY); setValue('cov-mw-spend-addresses',ADDRESS+'\n'+BENEFICIARY); setValue('cov-mw-amount','1');
    setValue(id, value); transactionState._psktReviewHex = null; await advanced.handleCovMwSpend(); assert.equal(transactionState._psktReviewHex, null);
  }
  setValue('cov-mw-addr', ADDRESS); setValue('cov-mw-script','51'); setValue('cov-mw-dest',BENEFICIARY); setValue('cov-mw-spend-addresses',ADDRESS+'\n'+BENEFICIARY);
  setValue('cov-mw-amount','bad'); await advanced.handleCovMwSpend();
  setValue('cov-mw-amount','0'); await advanced.handleCovMwSpend();
  setValue('cov-mw-amount','1');
  wasm.merkle_proof_for_address = () => JSON.stringify({proof:[PK3],leaf_index:0});
  wasm.create_merkle_whitelist_spend = () => PSKB;
  transactionState._psktReviewHex = null; await advanced.handleCovMwSpend(); assert.equal(transactionState._psktReviewHex, PSKB);
  wasm.create_merkle_whitelist_spend = () => { throw new Error('merkle builder rejected'); };
  transactionState._psktReviewHex = null; await advanced.handleCovMwSpend(); assert.equal(transactionState._psktReviewHex, null);

  // Commit-reveal must require decrypted material, clear it after use, and propagate builder failures without review.
  setValue('cov-cr-addr',''); setValue('cov-cr-script','51'); setValue('cov-cr-dest',EXTERNAL); commitRevealState._crRevealPartA='aa'; await advanced.handleCovCrReveal();
  setValue('cov-cr-addr',ADDRESS); setValue('cov-cr-script',''); await advanced.handleCovCrReveal();
  setValue('cov-cr-script','51'); setValue('cov-cr-dest',''); await advanced.handleCovCrReveal();
  setValue('cov-cr-dest',EXTERNAL); commitRevealState._crRevealPartA=''; await advanced.handleCovCrReveal();
  covenantState.lastCovenantResult={...covenantResult('commit-reveal'),commit_hash:PK3};
  commitRevealState._crRevealPartA='aa'; commitRevealState._crRevealPartB='bb'; commitRevealState._crDecryptCtBytes=new Uint8Array([1]);
  wasm.create_commit_reveal_spend=()=>PSKB; transactionState._psktReviewHex=null; await advanced.handleCovCrReveal();
  assert.equal(transactionState._psktReviewHex, PSKB); assert.equal(commitRevealState._crRevealPartA, null); assert.equal(commitRevealState._crRevealPartB, null); assert.equal(commitRevealState._crDecryptCtBytes, null);
  commitRevealState._crRevealPartA='aa'; wasm.create_commit_reveal_spend=()=>{throw new Error('reveal rejected');}; transactionState._psktReviewHex=null; await advanced.handleCovCrReveal(); assert.equal(transactionState._psktReviewHex,null);

  // Balance UI: validation, zero/singular/plural UTXO states, and fetch failure.
  setValue('cov-balance-addr',''); await advanced.handleCovCheckBalance();
  setValue('cov-balance-addr',ADDRESS); wasm.fetch_utxos_for_address_js=()=> '[]'; await advanced.handleCovCheckBalance();
  assert.match(element('cov-balance-utxos').textContent,/0 UTXOs/);
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'100000000'}]); await advanced.handleCovCheckBalance(); assert.match(element('cov-balance-utxos').textContent,/1 UTXO · 100000000 sompi/);
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'1'},{amount:'2'}]); await advanced.handleCovCheckBalance(); assert.match(element('cov-balance-utxos').textContent,/2 UTXOs · 3 sompi/);
  wasm.fetch_utxos_for_address_js=()=>{throw new Error('balance offline');}; await advanced.handleCovCheckBalance();

  // Shipment escrow: panel state transitions plus every branch routed as unsigned PSKB to hardware review.
  const shipment = await import(moduleUrl('features/covenants/spending/standard/shipment.js'));
  const ship = {
    ...covenantResult('ship-escrow'), address:ADDRESS, redeem_script_hex:'51', total_sompi:'250000000', rem_sompi:'150000000', fee_sompi:'10000000',
    cltv1_deadline:'1200', cltv2_deadline:'1400', seller_addr:BENEFICIARY, deliverer_addr:EXTERNAL, buyer_addr:ADDRESS,
  };
  covenantState.lastCovenantResult=ship; setValue('cov-ship-addr',''); setValue('cov-ship-script','');
  wasm.fetch_utxos_for_address_js=()=> '[]'; await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').innerHTML,/Not funded/);
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'250000000'}]); await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').innerHTML,/State 0/); assert.equal(element('cov-ship-s0-actions').style.display,'');
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'150000000'}]); await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').innerHTML,/State 1/); assert.equal(element('cov-ship-s1-actions').style.display,'');
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'123'}]); await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').innerHTML,/matches neither/);
  wasm.fetch_utxos_for_address_js=()=>{throw new Error('ship state offline');}; await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').textContent,/Error loading state/);
  covenantState.lastCovenantResult=null; setValue('cov-ship-addr',''); setValue('cov-ship-script',''); await shipment.shipPanelRefresh(); assert.match(element('cov-ship-state').textContent,/Enter covenant/);

  covenantState.lastCovenantResult=ship; setValue('cov-ship-addr',ADDRESS); setValue('cov-ship-script','51');
  for (const branch of ['pickup','state0-arb-refund','state0-timeout']) {
    wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'250000000'}]); transactionState._psktReviewHex=null; await shipment.handleShipEscrowSpend(branch); assert.ok(transactionState._psktReviewHex?.startsWith('50534b42'), `ship ${branch} must create unsigned PSKB`);
  }
  for (const branch of ['delivery','state1-arb-award','state1-timeout','state1-arb-refund']) {
    wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'150000000'}]); transactionState._psktReviewHex=null; await shipment.handleShipEscrowSpend(branch); assert.ok(transactionState._psktReviewHex?.startsWith('50534b42'), `ship ${branch} must create unsigned PSKB`);
  }
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'150000000'}]); transactionState._psktReviewHex=null; await shipment.handleShipEscrowSpend('unknown'); assert.equal(transactionState._psktReviewHex,null);
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'1'}]); transactionState._psktReviewHex=null; await shipment.handleShipEscrowSpend('pickup'); assert.equal(transactionState._psktReviewHex,null);
  wasm.fetch_utxos_for_address_js=()=> '[]'; await shipment.handleShipEscrowSpend('pickup');

  // Generic escrow validation/error states in addition to existing success branch coverage.
  covenantState.lastCovenantResult=null; await shipment.handleEscrowSpend('buyer-release');
  covenantState.lastCovenantResult={type:'escrow',address:'',redeem_script_hex:''}; await shipment.handleEscrowSpend('buyer-release');
  covenantState.lastCovenantResult={...covenantResult('escrow'),address:ADDRESS,redeem_script_hex:'51',alice_pk:PK,bob_pk:PK2};
  wasm.fetch_utxos_for_address_js=()=> '[]'; await shipment.handleEscrowSpend('buyer-release');
  wasm.fetch_utxos_for_address_js=()=>JSON.stringify([{tx_id:TXID,index:0,amount:'1',block_daa_score:'1'}]); await shipment.handleEscrowSpend('buyer-release');

  // Watcher pollers: spent/not-funded/mature/locked/watching branches.
  const savings = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/savings.js'));
  const limits = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/limits.js'));
  const st=element('runtime-poller-status');
  covenantWatcherState._covWatcherLastBalance=null; covenantWatcherState._covWatcherSpendPath='unknown';
  covenantState.lastCovenantResult={...covenantResult('dms'),inactivity_daa:'500'};
  await savings.pollDms({total:0n,kas:'0',st,currentDaa:1000n,utxos:[]}); assert.match(st.textContent,/Not funded/);
  await savings.pollDms({total:100n,kas:'0.000001',st,currentDaa:1000n,utxos:[{block_daa_score:'900'}]}); assert.match(st.textContent,/until heir can claim/);
  await savings.pollDms({total:100n,kas:'0.000001',st,currentDaa:1500n,utxos:[{block_daa_score:'900'}]}); assert.match(st.innerHTML,/ending|passed/);
  await savings.pollDms({total:100n,kas:'0.000001',st,currentDaa:1800n,utxos:[{block_daa_score:'900'}]}); assert.match(st.innerHTML,/passed/);
  covenantWatcherState._covWatcherLastBalance=10n; covenantWatcherState._covWatcherSpendPath='owner'; assert.equal(await savings.pollDms({total:0n,kas:'0',st,currentDaa:0n,utxos:[]}),true);
  covenantWatcherState._covWatcherLastBalance=10n; covenantWatcherState._covWatcherSpendPath='heir'; assert.equal(await savings.pollDms({total:0n,kas:'0',st,currentDaa:0n,utxos:[]}),true);
  covenantWatcherState._covWatcherLastBalance=10n; covenantWatcherState._covWatcherSpendPath='unknown'; assert.equal(await savings.pollDms({total:0n,kas:'0',st,currentDaa:0n,utxos:[]}),true);

  covenantWatcherState._covWatcherLastBalance=null;
  covenantState.lastCovenantResult={...covenantResult('savings'),threshold_sompi:'100',deadline_daa:'2000'};
  await savings.pollAdditive({total:0n,kas:'0',st,currentDaa:1000n}); assert.match(st.textContent,/Not funded/);
  await savings.pollAdditive({total:50n,kas:'0.0000005',st,currentDaa:1000n}); assert.match(st.textContent,/50%/);
  await savings.pollAdditive({total:100n,kas:'0.000001',st,currentDaa:1000n}); assert.match(st.innerHTML,/Goal reached/);
  await savings.pollAdditive({total:50n,kas:'0.0000005',st,currentDaa:2500n}); assert.match(st.innerHTML,/Deadline passed/);
  covenantState.lastCovenantResult={...covenantResult('savings'),threshold_sompi:'0',deadline_daa:'0'}; await savings.pollAdditive({total:1n,kas:'0.00000001',st,currentDaa:0n}); assert.match(st.innerHTML,/0.00000001/);
  covenantWatcherState._covWatcherLastBalance=5n; assert.equal(await savings.pollAdditive({total:0n,kas:'0',st,currentDaa:0n}),true);

  // Timed savings delegates the shared timing policy; exercise spent, unlocked, unlocking and locked states.
  covenantWatcherState._covWatcherLastBalance=null; covenantState.lastCovenantResult={...covenantResult('timelocked-savings'),locktime_daa:'1200'};
  await savings.pollTimelockedSavings({total:100n,kas:'0.000001',st,locktime:1200n,currentDaa:1600n,utxos:[]}); assert.match(st.innerHTML,/Unlocked/);
  await savings.pollTimelockedSavings({total:100n,kas:'0.000001',st,locktime:1200n,currentDaa:1200n,utxos:[]}); assert.match(st.innerHTML,/Unlocking/);
  await savings.pollTimelockedSavings({total:100n,kas:'0.000001',st,locktime:1200n,currentDaa:1000n,utxos:[]}); assert.match(st.textContent,/Locked/);

  const thread=[{tx_id:TXID,index:0,amount:'100000000',block_daa_score:'900',covenant_id:COV_ID},{tx_id:'bb'.repeat(32),index:1,amount:'50000000',block_daa_score:'901'}];
  covenantState.lastCovenantResult={...covenantResult('global-spending-limit'),covenant_id_hex:COV_ID,cooldown_daa:'100',max_withdraw_sompi:'100000000'};
  await limits.pollGlobalSpendingLimit({st,currentDaa:800n,utxos:[]}); assert.match(st.innerHTML,/Not funded/);
  await limits.pollGlobalSpendingLimit({st,currentDaa:950n,utxos:thread}); assert.match(st.innerHTML,/until next withdraw|Ready/);
  await limits.pollGlobalSpendingLimit({st,currentDaa:1200n,utxos:thread}); assert.match(st.innerHTML,/Ready/);
  covenantState.lastCovenantResult={...covenantResult('global-allowance'),covenant_id_hex:COV_ID,role:'beneficiary',start_daa:'1100',cooldown_daa:'100',max_withdraw_sompi:'100000000'}; covenantWatcherState._covWatcherLastBalance=null;
  await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:1000n,utxos:thread}); assert.match(st.innerHTML,/Locked/);
  await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:1050n,utxos:thread}); assert.match(st.innerHTML,/Locked|until/);
  await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:1200n,utxos:thread}); assert.match(st.innerHTML,/Ready/);
  covenantState.lastCovenantResult.role='owner'; await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:1200n,utxos:thread}); assert.match(st.innerHTML,/Owner can reclaim/);
  covenantWatcherState._covWatcherLastBalance=1n; covenantWatcherState._covWatcherSpendPath='heir'; assert.equal(await limits.pollGlobalAllowance({total:0n,st,currentDaa:1200n,utxos:[]}),true);

  // Global-limit/allowance watcher edge states: absent metadata, external UTXOs,
  // no cap/cooldown, both spent identities, and mature-but-not-drainable thread.
  const externalOnly=[{tx_id:'ef'.repeat(32),index:3,amount:'25000000'}];
  covenantWatcherState._covWatcherLastBalance=null;
  covenantState.lastCovenantResult={...covenantResult('global-spending-limit'),covenant_id_hex:COV_ID,cooldown_daa:'0',max_withdraw_sompi:'0'};
  await limits.pollGlobalSpendingLimit({st,currentDaa:0n,utxos:externalOnly}); assert.match(st.innerHTML,/external|Not funded/i);
  await limits.pollGlobalSpendingLimit({st,currentDaa:0n,utxos:[{tx_id:TXID,index:0,amount:'200000000',covenant_id:COV_ID}]}); assert.match(st.innerHTML,/Watching|Ready/i);
  covenantState.lastCovenantResult={...covenantResult('global-spending-limit'),covenant_id_hex:COV_ID,cooldown_daa:'100',max_withdraw_sompi:'50000000'};
  await limits.pollGlobalSpendingLimit({st,currentDaa:1200n,utxos:thread}); assert.match(st.innerHTML,/Ready to withdraw/);

  covenantState.lastCovenantResult={...covenantResult('global-allowance'),covenant_id_hex:COV_ID,role:'beneficiary',start_daa:'0',cooldown_daa:undefined,min_sequence:'0',max_withdraw_sompi:'0'};
  covenantWatcherState._covWatcherLastBalance=null;
  await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:0n,utxos:thread}); assert.match(st.innerHTML,/Watching/);
  covenantState.lastCovenantResult.min_sequence='100'; covenantState.lastCovenantResult.max_withdraw_sompi='50000000';
  await limits.pollGlobalAllowance({total:100000000n,st,currentDaa:1200n,utxos:thread}); assert.match(st.innerHTML,/Ready to withdraw/);
  covenantWatcherState._covWatcherLastBalance=1n; covenantWatcherState._covWatcherSpendPath='owner';
  assert.equal(await limits.pollGlobalAllowance({total:0n,st,currentDaa:1200n,utxos:[]}),true); assert.match(st.innerHTML,/Owner reclaimed/);
  covenantWatcherState._covWatcherLastBalance=1n; covenantWatcherState._covWatcherSpendPath='mystery';
  assert.equal(await limits.pollGlobalAllowance({total:0n,st,currentDaa:1200n,utxos:[]}),true); assert.match(st.textContent,/Funds spent/);
  covenantWatcherState._covWatcherLastBalance=null;
  await limits.pollGlobalAllowance({total:1n,st,currentDaa:0n,utxos:externalOnly}); assert.match(st.innerHTML,/external|Not funded/i);

  // Oracle-v1 watcher: saved beacon, spent/not-funded, malformed network
  // beacons, identity/commitment failures, and a valid on-chain attestation.
  const oraclePoller=await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/oracle_v1.js'));
  const oracleStatement='KasSigner oracle watcher branch coverage';
  const oracleCommit=createHash('sha256').update(Buffer.from(oracleStatement,'utf8')).digest('hex');
  const oracleSig='44'.repeat(64); const oraclePk=PK2;
  const oracleResult={...covenantResult('oracle-v1'),type:'oracle-v1',address:ADDRESS,attestation_statement:oracleStatement,message_commitment_hex:oracleCommit,oracle_pubkey_hex:oraclePk};
  covenantState.lastCovenantResult=oracleResult; covenantState.activeCovenants=[{...oracleResult}];
  wasm.verify_oracle_v1_attestation=()=>true;
  covenantWatcherState._covWatcherLastBalance=10n;
  assert.equal(await oraclePoller.pollOracleV1({total:0n,kas:'0',st,locktime:1200n,currentDaa:1300n,utxos:[]}),true); assert.match(st.innerHTML,/spent/i);
  covenantWatcherState._covWatcherLastBalance=null;
  assert.equal(await oraclePoller.pollOracleV1({total:0n,kas:'0',st,locktime:1200n,currentDaa:1000n,utxos:[]}),false); assert.match(st.textContent,/Not funded/);

  oracleResult.oracle_attestation_signature=oracleSig; oracleResult.oracle_attestation_commitment=oracleCommit;
  await oraclePoller.pollOracleV1({total:1n,kas:'0.00000001',st,locktime:1200n,currentDaa:1300n,utxos:[]}); assert.match(st.innerHTML,/Oracle attested|refund available/i);
  delete oracleResult.oracle_attestation_signature; delete oracleResult.oracle_attestation_commitment;

  const beaconPayload=(text=oracleStatement,commit=oracleCommit,sig=oracleSig)=>'4f525631'+sig+commit+Buffer.from(text,'utf8').toString('hex');
  let networkPayload=''; let networkOk=true;
  setFetchHook(async()=>({ok:networkOk,async json(){return {payload:networkPayload}}}));
  const pollTx=async(txid)=>{ oracleResult._oracle_v1_checked_txids=[]; delete oracleResult.oracle_attestation_signature; delete oracleResult.oracle_attestation_commitment; return oraclePoller.pollOracleV1({total:1n,kas:'0.00000001',st,locktime:1200n,currentDaa:1000n,utxos:[{tx_id:txid}]}); };
  networkOk=false; await pollTx('10'.repeat(32)); assert.match(st.textContent,/Waiting/);
  networkOk=true; networkPayload='00'; await pollTx('11'.repeat(32)); assert.match(st.textContent,/Waiting/);
  networkPayload='4f525631'+oracleSig+oracleCommit+'f'; await pollTx('12'.repeat(32)); assert.match(st.textContent,/Waiting/);
  networkPayload=beaconPayload('different statement'); await pollTx('13'.repeat(32)); assert.match(st.textContent,/Waiting/);
  networkPayload=beaconPayload(oracleStatement,'55'.repeat(32)); await pollTx('14'.repeat(32)); assert.match(st.textContent,/Waiting/);
  wasm.verify_oracle_v1_attestation=()=>false; networkPayload=beaconPayload(); await pollTx('15'.repeat(32)); assert.match(st.textContent,/Waiting/);
  wasm.verify_oracle_v1_attestation=()=>true; networkPayload=beaconPayload(); await pollTx('16'.repeat(32)); assert.match(st.innerHTML,/Oracle attested/); assert.equal(oracleResult.oracle_attestation_txid,'16'.repeat(32));

  assert.equal(navigationState._broadcastReturnScreen,'covenant');
  assertWatchOnlyStorage();
  console.log('PASS: deep covenant spending/shipment/watcher runtime paths');
} finally { await cleanupDeepHarness(); }
