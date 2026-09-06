import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setFetchHook, setConfirmResult, tick,
  ADDRESS, BENEFICIARY, PK, PK2, PK3, KSPT, wallet,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  const spendPath = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/subscription/message.js'));
  const address = await import(moduleUrl('core/address.js'));
  const { timeAgo } = await import(moduleUrl('core/time.js'));
  const outpoints = await import(moduleUrl('features/covenants/blockchain/outpoint_parser.js'));
  const crowdfund = await import(moduleUrl('features/covenants/crowdfund/model.js'));
  const antiKlepto = await import(moduleUrl('features/transactions/anti_klepto/session.js'));
  const reset = await import(moduleUrl('features/wallet/state_reset.js'));
  const savings = await import(moduleUrl('features/covenants/generation/builders/savings.js'));
  const escrow = await import(moduleUrl('features/covenants/generation/builders/escrow.js'));
  const limits = await import(moduleUrl('features/covenants/generation/builders/limits.js'));
  const dms = await import(moduleUrl('features/covenants/generation/builders/dms.js'));
  const payjoin = await import(moduleUrl('features/covenants/generation/builders/advanced/payjoin.js'));
  const commitReveal = await import(moduleUrl('features/covenants/generation/builders/advanced/commit_reveal.js'));
  const oracleV1Builder = await import(moduleUrl('features/covenants/generation/builders/advanced/oracle_v1.js'));
  const kpubImport = await import(moduleUrl('features/wallet/core/kpub_import.js'));
  const covenantKeys = await import(moduleUrl('features/covenants/generation/ui_and_keys.js'));
  const format = await import(moduleUrl('core/format.js'));
  const walletSessionMod = await import(moduleUrl('app/state/core/wallet_session.js'));

  // Spend-path detection must recognize the actual selector encodings used by
  // covenant signature scripts and must not guess when framing is malformed.
  const single = `20${PK}ad51`;
  assert.equal(spendPath.detectSpendPath(new Uint8Array(), single), 'owner');
  const saltedSingle = `08${'00'.repeat(8)}7520${PK}ad51`;
  assert.equal(spendPath.detectSpendPath(new Uint8Array(), saltedSingle), 'owner');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x51, 0x02, 0x51, 0x51]), '5151'), 'owner');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x00, 0x02, 0x51, 0x51]), '5151'), 'heir');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x51, 0x4c, 0x02, 0x51, 0x51]), '5151'), 'owner');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x00, 0x4d, 0x02, 0x00, 0x51, 0x51]), '5151'), 'heir');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x51]), '5151'), 'unknown');
  assert.equal(spendPath.detectSpendPath(Uint8Array.from([0x51, 0x50, 0x51, 0x51]), '5151'), 'unknown');

  // Address conversion accepts only the two consensus versions KasSee knows,
  // while free-form x-only input is preserved and malformed addresses fail closed.
  const oldDecode = stubs.decode_address;
  stubs.decode_address = () => JSON.stringify({ version:0, payload:PK });
  assert.equal(address.addressToScriptPublicKeyHex(ADDRESS), `20${PK}ac`);
  assert.equal(address.addressToXOnly(ADDRESS), PK);
  stubs.decode_address = () => JSON.stringify({ version:8, payload:PK2 });
  assert.equal(address.addressToScriptPublicKeyHex('kaspa:p2sh'), `aa20${PK2}87`);
  stubs.decode_address = () => JSON.stringify({ version:7, payload:PK });
  assert.throws(() => address.addressToScriptPublicKeyHex(ADDRESS), /Unknown address version/);
  stubs.decode_address = () => JSON.stringify({ version:0, payload:'aa' });
  assert.equal(address.addressToXOnly(ADDRESS), '');
  stubs.decode_address = () => { throw new Error('bad address'); };
  assert.equal(address.addressToXOnly(ADDRESS), '');
  assert.equal(address.addressToXOnly(`  ${PK2}  `), PK2);
  assert.equal(address.addressToXOnly(null), '');
  stubs.decode_address = oldDecode;

  // Relative-age buckets include future timestamps (clamped to zero).
  const now = 10_000_000;
  assert.equal(timeAgo(now + 1_000, now), 'just now');
  assert.equal(timeAgo(now - 59 * 60_000, now), '59m ago');
  assert.equal(timeAgo(now - 60 * 60_000, now), '1h ago');
  assert.equal(timeAgo(now - 23 * 60 * 60_000, now), '23h ago');
  assert.equal(timeAgo(now - 24 * 60 * 60_000, now), '1d ago');

  // BlockAdded parsing verifies the notification envelope, exact outpoint,
  // length bounds and all supported first-push encodings.
  assert.equal(outpoints.findSpendingSignatureScript(null, {txid:'aa'.repeat(32),index:0}), null);
  assert.equal(outpoints.findSpendingSignatureScript(new Uint8Array(3), {txid:'aa'.repeat(32),index:0}), null);
  assert.equal(outpoints.findSpendingSignatureScript(new Uint8Array(80), null), null);
  assert.equal(outpoints.findSpendingSignatureScript(Uint8Array.from([0,0xff,0,0x3c]), {txid:'zz',index:0}), null);
  const makeEnvelope = ({ txid='aa'.repeat(32), index=0, script=Uint8Array.from([1,0x51]), prefix=false }={}) => {
    const envelopeOffset = prefix ? 9 : 1;
    const outpointOffset = prefix ? 12 : 4;
    const data = new Uint8Array(outpointOffset + 41 + 4 + script.length);
    if (prefix) data[0]=1;
    data[envelopeOffset]=0xff; data[envelopeOffset+2]=0x3c;
    data[outpointOffset]=37; data[outpointOffset+4]=1;
    data.set(Buffer.from(txid,'hex'), outpointOffset+5);
    const io=outpointOffset+37; data[io]=index & 0xff; data[io+1]=(index>>>8)&0xff;
    const lo=outpointOffset+41; const n=script.length; data[lo]=n&0xff; data[lo+1]=(n>>>8)&0xff;
    data.set(script, lo+4); return data;
  };
  const envelope = makeEnvelope();
  assert.deepEqual([...outpoints.findSpendingSignatureScript(envelope,{txid:'aa'.repeat(32),index:0},{minLength:1,maxLength:10})],[1,0x51]);
  assert.equal(outpoints.findSpendingSignatureScript(envelope,{txid:'bb'.repeat(32),index:0}), null);
  assert.equal(outpoints.findSpendingSignatureScript(envelope,{txid:'aa'.repeat(32),index:1}), null);
  assert.equal(outpoints.findSpendingSignatureScript(envelope,{txid:'aa'.repeat(32),index:0},{minLength:3,maxLength:10}), null);
  assert.equal(outpoints.findSpendingSignatureScript(envelope,{txid:'aa'.repeat(32),index:0},{minLength:1,maxLength:1}), null);
  const prefixed = makeEnvelope({prefix:true});
  assert.ok(outpoints.findSpendingSignatureScript(prefixed,{txid:'aa'.repeat(32),index:0}));
  assert.equal(outpoints.readFirstPush(null), null);
  assert.equal(outpoints.readFirstPush(new Uint8Array()), null);
  assert.deepEqual([...outpoints.readFirstPush(Uint8Array.from([2,0xaa,0xbb]))],[0xaa,0xbb]);
  assert.deepEqual([...outpoints.readFirstPush(Uint8Array.from([0x4c,2,0xaa,0xbb]))],[0xaa,0xbb]);
  assert.equal(outpoints.readFirstPush(Uint8Array.from([0x4d,1,0,0xaa])), null);
  assert.equal(outpoints.readFirstPush(Uint8Array.from([0x4c])), null);
  assert.equal(outpoints.readFirstPush(Uint8Array.from([0x4c,0])), null);
  assert.equal(outpoints.readFirstPush(Uint8Array.from([3,1,2])), null);
  assert.equal(outpoints.readFirstPush(Uint8Array.from([3,1,2,3]),2), null);

  // Crowdfunding model validation is exercised field-by-field so persisted or
  // imported campaigns cannot bypass the same canonical constraints as UI input.
  const validContribution = {
    address:'kaspa:contribution', contributor_pubkey_hex:PK,
    redeem_script_hex:'51', crowdfund_salt_hex:'aa'.repeat(8),
  };
  assert.equal(crowdfund.validateContribution(validContribution), validContribution);
  for (const [value, pattern] of [
    [null,/missing/], [{...validContribution,address:'bad'},/address/],
    [{...validContribution,contributor_pubkey_hex:'aa'},/key/],
    [{...validContribution,redeem_script_hex:'zz'},/redeem script/],
    [{...validContribution,crowdfund_salt_hex:'aa'},/salt/],
  ]) assert.throws(()=>crowdfund.validateContribution(value), pattern);
  assert.deepEqual(crowdfund.contributionList(''), []);
  assert.throws(()=>crowdfund.contributionList('{}'), /list is invalid/);
  const dup = crowdfund.contributionList([validContribution,{...validContribution, contributor_pubkey_hex:PK2}]);
  assert.equal(dup.length,1); assert.equal(dup[0].contributor_pubkey_hex,PK2);
  assert.equal(JSON.parse(crowdfund.contributionJson([validContribution])).length,1);
  state.crowdfundState.contributions=[];
  assert.equal(crowdfund.addContribution(validContribution).length,1);
  const many=Array.from({length:9},(_,i)=>({...validContribution,address:`kaspa:c${i}`,crowdfund_salt_hex:i.toString(16).padStart(16,'0')}));
  assert.throws(()=>crowdfund.contributionList(many), /at most 8/);
  const campaign={v:2,t:'crowdfund-campaign',name:'  Runtime  ',goal:'1',daa:'2',organizer:ADDRESS,vk:'aa',id:PK3,date:''};
  assert.equal(crowdfund.normalizeCampaign(campaign).name,'Runtime');
  for (const [value,pattern] of [
    [null,/current crowdfunding/], [{...campaign,v:1},/current crowdfunding/],
    [{...campaign,goal:'0'},/goal/], [{...campaign,daa:'0'},/refund DAA/],
    [{...campaign,organizer:'bad'},/organizer/], [{...campaign,vk:''},/verifying key/],
    [{...campaign,vk:'gg'},/verifying key/], [{...campaign,id:'aa'},/campaign ID/],
  ]) assert.throws(()=>crowdfund.normalizeCampaign(value),pattern);
  crowdfund.hydrateCrowdfundState(null);
  crowdfund.hydrateCrowdfundState({type:'other'});
  const baseResult={type:'crowdfund',crowdfund_contributions_json:'[]',campaign_name:'Runtime',goal_sompi:'1',locktime_daa:'2',organizer_address:ADDRESS,vk_hex:'aa',campaign_id:PK3};
  crowdfund.hydrateCrowdfundState({...baseResult,crowdfund_role:'organizer',crowdfund_pk_hex:'bb'});
  assert.equal(state.crowdfundState.role,'organizer');
  assert.equal(state.crowdfundState.setup.vk_hash_hex,PK3);
  crowdfund.hydrateCrowdfundState({...baseResult,crowdfund_role:'contributor'});
  assert.equal(state.crowdfundState.role,'contributor');
  assert.equal(state.crowdfundState.importedCampaign.id,PK3);

  // Anti-klepto orchestration rejects incomplete initialization and enforces
  // commitment-before-final ordering; successful verification scrubs the session.
  stubs.anti_klepto_begin=()=>JSON.stringify({});
  assert.throws(()=>antiKlepto.beginAntiKlepto(KSPT),/initialization failed/);
  stubs.anti_klepto_begin=()=>JSON.stringify({requestHex:'4b414b500200',hostSecretHex:'11'.repeat(32)});
  assert.equal(antiKlepto.beginAntiKlepto(KSPT),'4b414b500200');
  assert.equal(antiKlepto.antiKleptoActive(),true);
  assert.equal(antiKlepto.antiKleptoMessageKind(null),null);
  assert.equal(antiKlepto.antiKleptoMessageKind('00'),null);
  assert.equal(antiKlepto.antiKleptoMessageKind('4b414b5002zz'),null);
  assert.equal(antiKlepto.antiKleptoMessageKind('4B414B500102'),null);
  assert.equal(antiKlepto.antiKleptoMessageKind('4B414B500204'),4);
  assert.throws(()=>antiKlepto.verifyAntiKleptoSigned('aa'),/commitment/);
  stubs.anti_klepto_accept_commitment=()=> 'reveal';
  assert.equal(antiKlepto.acceptAntiKleptoCommitment('commit'),'reveal');
  stubs.anti_klepto_verify_signed=()=>KSPT;
  assert.equal(antiKlepto.verifyAntiKleptoSigned('signed'),KSPT);
  assert.equal(antiKlepto.antiKleptoActive(),false);
  assert.throws(()=>antiKlepto.acceptAntiKleptoCommitment('commit'),/No anti-klepto/);
  antiKlepto.clearAntiKleptoSession();

  // Wallet cleanup exercises live-resource shutdown and persistence semantics.
  reset.markSkipAutoLoadOnce();
  assert.equal(reset.consumeSkipAutoLoadOnce(),true);
  assert.equal(reset.consumeSkipAutoLoadOnce(),false);
  state.walletSession.replace(structuredClone(wallet));
  state.networkState.lastFeeEstimate={normal_sompi_per_gram:'1'};
  globalThis.cancelAnimationFrame=()=>{};
  state.scannerState.scanAnimFrame=123;
  let trackStopped=false, socketClosed=false;
  state.scannerState.scanStream={getTracks:()=>[{stop(){trackStopped=true;}}]};
  state.stealthState._stealthScanWs={close(){socketClosed=true;}};
  state.uiState.toastTimer=99;
  state.covenantState.lastCovenantResult={secret:new Uint8Array([1,2,3])};
  state.oracleState._oracleMbState={value:new Uint8Array([4])};
  state.scannerState.qrFrames=[new Uint8Array([5])];
  reset.hardenedWalletCleanup();
  assert.equal(trackStopped,true); assert.equal(socketClosed,true);
  assert.equal(state.walletSession.hasWallet(),false);
  assert.equal(state.scannerState.scanStream,null);
  assert.equal(state.uiState.toastTimer,null);
  assert.deepEqual(state.walletState.historyEntries,[]);

  // Cleanup is best-effort even when browser-managed resources throw during
  // shutdown, and the one-shot autoload/reset handshake works in both host-
  // handled and browser-reload modes.
  state.scannerState.scanStream={getTracks(){throw new Error('tracks unavailable');}};
  state.stealthState._stealthScanWs={close(){throw new Error('socket close failed');}};
  state.uiState.toastTimer=null; reset.hardenedWalletCleanup(); assert.equal(state.scannerState.scanStream,null); assert.equal(state.stealthState._stealthScanWs,undefined);
  const savedLocalGet=localStorage.getItem, savedLocalSet=localStorage.setItem;
  localStorage.setItem=()=>{throw new Error('storage disabled')}; reset.markSkipAutoLoadOnce();
  localStorage.getItem=()=>{throw new Error('storage disabled')}; assert.equal(reset.consumeSkipAutoLoadOnce(),false);
  localStorage.getItem=savedLocalGet; localStorage.setItem=savedLocalSet;
  let reloads=0; globalThis.location={reload(){reloads++;}}; globalThis.CustomEvent=class{constructor(type,opts){this.type=type;this.cancelable=opts?.cancelable;}};
  globalThis.dispatchEvent=()=>false; reset.requestWalletRuntimeReset(); assert.equal(reloads,0,'host-cancelled reset event suppresses browser reload');
  globalThis.dispatchEvent=()=>true; reset.requestWalletRuntimeReset(); assert.equal(reloads,1,'unhandled reset event reloads the browser realm');
  globalThis.CustomEvent=class{constructor(){throw new Error('events disabled')}}; reset.requestWalletRuntimeReset(); assert.equal(reloads,2,'event construction failure falls back to reload');

  // History archival rendering covers incoming/outgoing classification, duplicate
  // suppression, fallback timestamps/counterparties, failed address queries, and
  // explicit user-controlled clearing. These are real wallet-history decisions.
  const history = await import(moduleUrl('features/wallet/tools/history.js'));
  state.walletSession.clear();
  history.showHistory();
  state.walletSession.replace(structuredClone(wallet));
  state.walletState.historyEntries=[{type:'out',amount:'7',fee:'0',tx_id:'ff'.repeat(32),time:0,counterparty:null}];
  const archivalTxs=[
    {transaction_id:'01'.repeat(32),block_time:1_700_000_000_000,is_accepted:true,
      inputs:[{previous_outpoint_amount:'100',previous_outpoint_address:ADDRESS}],
      outputs:[{amount:'40',script_public_key_address:ADDRESS},{amount:'50',script_public_key_address:BENEFICIARY}]},
    {transaction_id:'02'.repeat(32),accepting_block_time:1_700_000_000,is_accepted:false,
      inputs:[{previous_outpoint_amount:'90',previous_outpoint_address:BENEFICIARY}],
      outputs:[{amount:'80',script_public_key_address:ADDRESS}]},
    {transaction_id:'03'.repeat(32),inputs:[],outputs:[]},
    {transaction_id:'01'.repeat(32),inputs:[],outputs:[]},
  ];
  let historyFetch=0;
  setFetchHook(async()=>{
    historyFetch++;
    if(historyFetch===1) return {ok:true,async json(){return archivalTxs;}};
    if(historyFetch===2) return {ok:false,async json(){return [];}};
    if(historyFetch===3) return {ok:true,async json(){return {};}};
    throw new Error('archival endpoint unavailable');
  });
  history.showHistory(); await tick(); await tick();
  assert.equal(state.walletState.historyEntries.some(entry=>entry.type==='out'&&entry.tx_id==='01'.repeat(32)),true);
  assert.equal(state.walletState.historyEntries.some(entry=>entry.type==='in'&&entry.tx_id==='02'.repeat(32)),true);
  assert.match(element('history-summary').textContent,/transaction/);
  setConfirmResult(false); history.clearHistory(); assert.notEqual(state.walletState.historyEntries.length,0);
  setConfirmResult(true); history.clearHistory(); assert.equal(state.walletState.historyEntries.length,0); assert.match(element('history-summary').textContent,/No transactions/);

  // Allowance controls exercise no-wallet/no-UTXO/low-balance/full-drain/partial
  // maximum selection and all custom-period UI calculations.
  const allowanceActions=await import(moduleUrl('app/events/contracts/covenant_actions/allowance.js'));
  allowanceActions.bindAllowanceActions();
  state.covenantState.lastCovenantResult=null; await element('btn-cov-bene-max').onclick(); assert.match(element('toast').textContent,/No covenant loaded/);
  state.covenantState.lastCovenantResult={type:'global-allowance',address:ADDRESS,max_withdraw_sompi:'100000000'};
  stubs.fetch_utxos_for_address_js=()=> '[]'; await element('btn-cov-bene-max').onclick(); assert.match(element('toast').textContent,/No UTXOs/);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'50000000'}]); await element('btn-cov-bene-max').onclick(); assert.equal(element('cov-bene-amount').value,'0.5'); assert.match(element('toast').textContent,/Full drain/);
  state.covenantState.lastCovenantResult.max_withdraw_sompi='500'; stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'1000'}]); await element('btn-cov-bene-max').onclick(); assert.match(element('toast').textContent,/too low/); state.covenantState.lastCovenantResult.max_withdraw_sompi='100000000';
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'300000000'},{amount:'200000000'}]); await element('btn-cov-bene-max').onclick(); assert.ok(Number(element('cov-bene-amount').value)>0); assert.match(element('toast').textContent,/Max:/);
  stubs.fetch_utxos_for_address_js=()=>{throw new Error('allowance offline');}; await element('btn-cov-bene-max').onclick(); assert.match(element('toast').textContent,/Error:/);
  const period=element('cov-allowance-period');
  period.value='3600'; period.onchange(); assert.match(element('cov-allowance-summary').textContent,/1 hour/);
  period.value='999'; period.onchange(); assert.match(element('cov-allowance-summary').textContent,/999s/);
  period.value='custom'; setValue('cov-allowance-seq','0'); period.onchange(); assert.match(element('cov-allowance-summary').textContent,/custom period/);
  setValue('cov-allow-hours','1'); element('cov-allow-hours').oninput(); assert.equal(String(element('cov-allowance-seq').value),'3600');
  setValue('cov-allow-hours','0'); setValue('cov-allow-mins','0'); setValue('cov-allow-days','0'); setValue('cov-allow-months','0'); setValue('cov-allow-years','0'); element('cov-allow-mins').oninput(); assert.equal(element('cov-allowance-seq').value,'');
  setValue('cov-allowance-max','2'); element('cov-allowance-max').oninput(); assert.match(element('cov-allowance-summary').textContent,/2 KAS/);
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'250000000'}]);

  // Builder validation cases map directly to user-visible covenant policy.
  setValue('cov-piggy-goal','-1'); await savings.buildAdditive(PK); assert.match(element('toast').textContent,/positive savings goal/);
  setValue('cov-piggy-goal',''); setValue('cov-piggy-deadline',''); assert.ok((await savings.buildAdditive(PK)).resultJson);
  assert.equal(await savings.buildTimelockedSavings(''),undefined); assert.match(element('toast').textContent,/Load wallet/);
  setValue('cov-savings-recovery-pk','kpub1:bad'); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/not a kpub/);
  setValue('cov-savings-recovery-pk','aa'); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/64 hex/);
  setValue('cov-savings-recovery-pk',''); setValue('cov-savings-locktime','0'); setValue('cov-savings-datetime',''); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/unlock date/);
  setValue('cov-savings-locktime','1200'); assert.ok((await savings.buildTimelockedSavings(PK)).resultJson);
  setValue('cov-piggy-goal','1'); setValue('cov-piggy-deadline','not-a-date'); assert.equal(await savings.buildAdditive(PK),undefined); assert.match(element('toast').textContent,/date|Invalid|future/i);
  setValue('cov-piggy-deadline','');
  const oldDecodeAddress=stubs.decode_address;
  setValue('cov-savings-recovery-pk',ADDRESS); stubs.decode_address=()=>JSON.stringify({version:8,payload:PK2}); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/standard address/);
  stubs.decode_address=()=>JSON.stringify({version:0,payload:'aa'}); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/Could not read pubkey/);
  stubs.decode_address=()=>{throw new Error('decode unavailable')}; assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/Invalid address/);
  stubs.decode_address=oldDecodeAddress; setValue('cov-savings-recovery-pk',PK2); setValue('cov-savings-locktime','bad'); assert.equal(await savings.buildTimelockedSavings(PK),undefined); assert.match(element('toast').textContent,/unlock date/);

  // Escrow builders validate every participant role and monetary/deadline field;
  // the success records retain only public participant material.
  setValue('cov-escrow-pk',PK2); setValue('cov-escrow-arbiter-pk',PK3); assert.equal(await escrow.buildEscrow(''),undefined); assert.match(element('toast').textContent,/Load wallet/);
  setValue('cov-escrow-pk','aa'); assert.equal(await escrow.buildEscrow(PK),undefined); assert.match(element('toast').textContent,/seller pubkey/);
  setValue('cov-escrow-pk',PK2); setValue('cov-escrow-arbiter-pk','aa'); assert.equal(await escrow.buildEscrow(PK),undefined); assert.match(element('toast').textContent,/arbiter pubkey/);
  setValue('cov-escrow-arbiter-pk',PK3); const savedReceive=state.walletSession.current().receive_addresses; state.walletSession.current().receive_addresses=[]; assert.ok((await escrow.buildEscrow(PK)).resultJson); state.walletSession.current().receive_addresses=savedReceive;
  setValue('cov-ship-seller-pk',PK2); setValue('cov-ship-deliverer-pk',PK3); setValue('cov-ship-arbiter-pk','44'.repeat(32)); setValue('cov-ship-product','2'); setValue('cov-ship-fee','0.1'); setValue('cov-ship-cltv1','2000'); setValue('cov-ship-cltv2','3000');
  assert.equal(await escrow.buildShipEscrow(''),undefined); assert.match(element('toast').textContent,/Load wallet/);
  setValue('cov-ship-seller-pk','aa'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/seller pubkey/); setValue('cov-ship-seller-pk',PK2);
  setValue('cov-ship-deliverer-pk','aa'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/deliverer pubkey/); setValue('cov-ship-deliverer-pk',PK3);
  setValue('cov-ship-arbiter-pk','aa'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/arbiter pubkey/); setValue('cov-ship-arbiter-pk','44'.repeat(32));
  setValue('cov-ship-product','bad'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/product price/); setValue('cov-ship-product','2');
  setValue('cov-ship-fee','bad'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/delivery fee/); setValue('cov-ship-fee','0.1');
  setValue('cov-ship-product','0'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/product price/); setValue('cov-ship-product','2');
  setValue('cov-ship-fee','0'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/delivery fee/); setValue('cov-ship-fee','0.1');
  setValue('cov-ship-cltv1','0'); assert.equal(await escrow.buildShipEscrow(PK),undefined); assert.match(element('toast').textContent,/both deadlines/); setValue('cov-ship-cltv1','2000');
  assert.ok((await escrow.buildShipEscrow(PK)).resultJson);

  setValue('cov-splimit-max','0'); assert.equal(await limits.buildGlobalSpendingLimit(PK),undefined); assert.match(element('toast').textContent,/max withdrawal/);
  setValue('cov-splimit-max','1'); setValue('cov-splimit-cooldown','0'); assert.equal(await limits.buildGlobalSpendingLimit(PK),undefined); assert.match(element('toast').textContent,/cooldown/);
  setValue('cov-splimit-cooldown','60'); assert.ok((await limits.buildGlobalSpendingLimit(PK)).resultJson);
  setValue('cov-allowance-bene-pk',''); assert.equal(await limits.buildGlobalAllowance(PK),undefined);
  setValue('cov-allowance-bene-pk','kpub1:'+'aa'.repeat(40)); assert.equal(await limits.buildGlobalAllowance(PK),undefined); assert.match(element('toast').textContent,/not a kpub/);
  setValue('cov-allowance-bene-pk',PK2); setValue('cov-allowance-max','1'); setValue('cov-allowance-period','custom'); setValue('cov-allowance-seq','0'); assert.equal(await limits.buildGlobalAllowance(PK),undefined);
  setValue('cov-allowance-seq','60'); setValue('cov-allowance-start',''); assert.ok((await limits.buildGlobalAllowance(PK)).resultJson);
  setValue('cov-allowance-period','0'); assert.equal(await limits.buildGlobalAllowance(PK),undefined); assert.match(element('toast').textContent,/cooldown time/);

  setValue('cov-dms2-heir-pk','kpub1:bad'); setValue('cov-dms2-duration','10'); assert.equal(await dms.buildDms(PK),undefined);
  setValue('cov-dms2-heir-pk',PK2); setValue('cov-dms2-duration','0'); assert.equal(await dms.buildDms(PK),undefined); assert.match(element('toast').textContent,/inactivity/);
  setValue('cov-dms2-duration','10'); assert.ok((await dms.buildDms(PK)).resultJson);

  setValue('cov-payjoin-bene-pk',PK2); setValue('cov-payjoin-locktime','0'); setValue('cov-payjoin-datetime',''); assert.equal(await payjoin.buildPayjoin(PK),undefined);
  setValue('cov-payjoin-locktime','1200'); setValue('cov-payjoin-min-inputs',''); setValue('cov-payjoin-min-outputs',''); assert.ok((await payjoin.buildPayjoin(PK)).resultJson);
  assert.equal(await payjoin.buildPayjoin(''),undefined); assert.match(element('toast').textContent,/Load wallet/);

  setValue('cov-cr-hash-display',''); setValue('cov-cr-locktime','1200'); assert.equal(await commitReveal.buildCommitReveal(PK),undefined);
  element('cov-cr-hash-display').textContent='BLAKE2B: '+PK3; setValue('cov-cr-locktime','0'); setValue('cov-cr-datetime',''); assert.equal(await commitReveal.buildCommitReveal(PK),undefined);
  setValue('cov-cr-locktime','1200'); setValue('cov-cr-ciphertext-hex','aabb'); const cr=await commitReveal.buildCommitReveal(PK); assert.equal(cr.extra.cr_ciphertext_hex,'aabb');

  stubs.covenant_oracle_v1=()=>JSON.stringify({address:'kaspa:oracle',redeem_script_hex:'51'});
  setValue('cov-oracle-v1-bene','bad'); setValue('cov-oracle-v1-pubkey',PK2); setValue('cov-oracle-v1-key-id',PK3); setValue('cov-oracle-v1-statement','release'); setValue('cov-oracle-v1-datetime','2099-01-01T00:00'); assert.equal(await oracleV1Builder.buildOracleV1(PK),undefined);
  setValue('cov-oracle-v1-bene',BENEFICIARY); setValue('cov-oracle-v1-pubkey','aa'); assert.equal(await oracleV1Builder.buildOracleV1(PK),undefined);
  setValue('cov-oracle-v1-pubkey',PK2); setValue('cov-oracle-v1-key-id',PK3); setValue('cov-oracle-v1-statement',''); assert.equal(await oracleV1Builder.buildOracleV1(PK),undefined);
  setValue('cov-oracle-v1-statement','release'); setValue('cov-oracle-v1-datetime',''); assert.equal(await oracleV1Builder.buildOracleV1(PK),undefined);



  // Wallet import accepts every supported binary container shape and rejects
  // malformed compact keys before calling WASM. Activation preserves the
  // normalized public wallet only and invokes the caller hook exactly once.
  const rawKey = Uint8Array.from({length:78},(_,i)=>i & 0xff);
  stubs.import_kpub_raw = (_bytes, _network) => JSON.stringify({...wallet,kpub:'kpub1:raw'});
  assert.equal(kpubImport.deriveRawKpubWallet(rawKey.buffer).wallet.kpub,'kpub1:raw');
  const view = new DataView(rawKey.buffer, 0, rawKey.byteLength);
  assert.equal(kpubImport.deriveRawKpubWallet(view).wallet.kpub,'kpub1:raw');
  assert.equal(kpubImport.deriveRawKpubWallet([...rawKey]).wallet.kpub,'kpub1:raw');
  assert.throws(()=>kpubImport.deriveRawKpubWallet([1,2,3]),/78 bytes/);
  const compact = new Uint8Array(79); compact[0]=1; compact.set(rawKey,1);
  assert.equal(kpubImport.deriveKpubQrWallet(compact).wallet.kpub,'kpub1:raw');
  let imported=0; kpubImport.activateKpubWallet({...wallet,kpub:'kpub1:activated'},{profile:{id:'p',name:'P'},successScreen:'dashboard',onImported:w=>{imported++;assert.equal(w.kpub,'kpub1:activated')}}); assert.equal(imported,1);

  // Covenant role-key matching checks account keys plus every receive/change
  // address and fails closed on malformed address decoding or absent wallets.
  state.walletSession.replace(structuredClone(wallet));
  stubs.parse_kpub=()=>JSON.stringify({account_pubkey:PK3});
  assert.equal(covenantKeys.walletMatchesPk(PK3),true);
  stubs.parse_kpub=()=>JSON.stringify({account_pubkey:PK2});
  stubs.decode_address=a=>JSON.stringify({payload:String(a).includes('owner-1')?PK3:PK});
  assert.equal(covenantKeys.walletMatchesPk(PK3),true);
  stubs.decode_address=()=>{throw new Error('decode reject')}; assert.equal(covenantKeys.walletMatchesPk(PK3),false);
  stubs.decode_address=()=>JSON.stringify({payload:''}); assert.equal(covenantKeys.getOwnerPubkeyHex(),null);
  const noKpub=structuredClone(wallet); delete noKpub.kpub; state.walletSession.replace(noKpub); assert.equal(covenantKeys.getAccountPubkeyHex(),null);
  state.walletSession.clear(); assert.equal(covenantKeys.walletMatchesPk(PK),false); assert.equal(covenantKeys.getOwnerPubkeyHex(),null); assert.equal(covenantKeys.getAccountPubkeyHex(),null);
  state.walletSession.replace(structuredClone(wallet)); stubs.parse_kpub=()=>JSON.stringify({}); assert.equal(covenantKeys.getAccountPubkeyHex(),null);
  stubs.parse_kpub=()=>JSON.stringify({account_pubkey:PK}); stubs.decode_address=()=>JSON.stringify({payload:PK});

  // Presentation helpers cover all real duration/time/address buckets, including
  // huge DAA deltas and hostile address text that must be escaped rather than marked up.
  assert.equal(format.formatDuration(0),'0s'); assert.equal(format.formatDuration(31536000+2592000+86400+3600+60+1),'1y 1mo 1d 1h 1min 1s');
  assert.equal(format.formatDaaDuration(BigInt(Number.MAX_SAFE_INTEGER)*20n),'very long');
  assert.equal(format.formatSeconds(null),''); assert.equal(format.formatSeconds(0.5),'< 1s'); assert.equal(format.formatSeconds(30),'30s'); assert.equal(format.formatSeconds(120),'2min'); assert.equal(format.formatSeconds(7200),'2h');
  const txNow=Date.now(); assert.equal(format.formatTransactionTime(txNow-1000),'just now'); assert.match(format.formatTransactionTime(txNow-120000),/m ago/); assert.match(format.formatTransactionTime(txNow-7200000),/h ago/); assert.match(format.formatTransactionTime(txNow-172800000),/d ago/); assert.match(format.formatTransactionTime(txNow-700000000),/,/);
  assert.equal(format.shortenHex('abcd',3),'abcd'); assert.equal(format.shortenHex('abcdefghijklmnop',3),'abc…nop');
  assert.equal(format.emphasizeAddress('<bad&>'),'&lt;bad&amp;&gt;'); assert.match(format.emphasizeAddress('kaspa:abcdefghijklmno'),/addr-hl/);
  assert.match(format.formatStartDate({start_daa:'1100'},'1000'),/^~/); assert.equal(format.formatStartDate({start_daa:'0'},'1000'),'DAA 0');

  // Wallet-session scrubbing covers strings, numbers, booleans, bigint, cycles,
  // typed buffers, ArrayBuffer, Set/Map and the structuredClone fallback without
  // retaining private mutable references.
  const scrub={s:'secret',n:7,b:true,big:9n,arr:[1,2],set:new Set([1]),map:new Map([[1,2]]),view:new Uint8Array([1,2]),buf:new Uint8Array([3,4]).buffer}; scrub.self=scrub;
  walletSessionMod.bestEffortScrubMutable(scrub); assert.equal(scrub.s,''); assert.equal(scrub.n,0); assert.equal(scrub.b,false); assert.equal(scrub.big,0n); assert.equal(scrub.arr,null); assert.equal(scrub.set,null); assert.equal(scrub.map,null); assert.equal(scrub.view,null); assert.equal(scrub.buf,null);
  const directView=new Uint8Array([9,8]); walletSessionMod.bestEffortScrubMutable(directView); assert.deepEqual([...directView],[0,0]);
  const directBuf=new Uint8Array([7,6]).buffer; walletSessionMod.bestEffortScrubMutable(directBuf); assert.deepEqual([...new Uint8Array(directBuf)],[0,0]);
  const directSet=new Set([1]); walletSessionMod.bestEffortScrubMutable(directSet); assert.equal(directSet.size,0); const directMap=new Map([[1,2]]); walletSessionMod.bestEffortScrubMutable(directMap); assert.equal(directMap.size,0);
  assert.doesNotThrow(()=>walletSessionMod.bestEffortScrubMutable(null));
  const originalClone=globalThis.structuredClone; globalThis.structuredClone=undefined; state.walletSession.replace(JSON.stringify(wallet)); assert.equal(state.walletSession.current().kpub,wallet.kpub); globalThis.structuredClone=originalClone;
  assert.throws(()=>state.walletSession.replace(7),/JSON string or object/); assert.equal(state.walletSession.setProfile({id:'',name:'x'}),null); assert.equal(state.walletSession.setProfile(undefined),null); assert.equal(state.walletSession.primaryReceiveAddress(),ADDRESS);

  console.log('PASS: protocol/state/builder branch hardening paths');
} finally {
  await cleanupDeepHarness();
}
