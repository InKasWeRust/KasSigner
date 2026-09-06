import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setFetchHook,
  ADDRESS, PK, PK2, PK3, wallet, utxos,
} from './web_runtime_deep_harness.mjs';
import { FakeElement } from './web_recovery_test_harness.mjs';

const { state, response } = await setupDeepHarness();
try {
  const notifications = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/subscription/notifications.js'));
  const merkleButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/merkle.js'));
  const payjoinButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/payjoin.js'));
  const commitButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/commit_reveal.js'));
  const commitVerify = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/auxiliary/commit_reveal.js'));
  const additiveButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_core/additive.js'));
  const shipmentButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/shipment.js'));
  const escrowButtons = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_core/escrow.js'));
  const settings = await import(moduleUrl('features/settings/screen.js'));
  const piggy = await import(moduleUrl('app/events/contracts/covenant_creation/result_actions/piggy.js'));
  const metadata = await import(moduleUrl('features/covenants/watchers_and_ui/ui/script_metadata.js'));
  const payloadState = await import(moduleUrl('features/covenants/payload_and_swaps/state.js'));
  const connectivity = await import(moduleUrl('core/ui/connectivity_status.js'));
  const network = await import(moduleUrl('core/network.js'));
  const antiResponse = await import(moduleUrl('features/transactions/anti_klepto/response.js'));
  const planner = await import(moduleUrl('features/transactions/send/compose/planners/index.js'));
  const safeHtml = await import(moduleUrl('core/security/safe_html.js'));
  const kpubRepoMod = await import(moduleUrl('features/wallet/kpub_manager/repository.js'));
  const crowdfundModel = await import(moduleUrl('features/covenants/crowdfund/model.js'));
  const crowdfundCampaign = await import(moduleUrl('features/covenants/crowdfund/campaign.js'));

  // Spend notifications: every specialized heir/owner branch, silent escrow,
  // and generic fallback must be deterministic and must not leak markup.
  for (const [type, path, expected] of [
    ['dms','heir','Heir claimed'], ['global-allowance','heir','Beneficiary withdrew'],
    ['additive','heir','Piggy bank broken'], ['commit-reveal','heir','Secret revealed'],
    ['timelocked-savings','heir','Beneficiary claimed'],
    ['dms','owner','Owner heartbeat'], ['additive','owner','Owner broke'],
    ['commit-reveal','owner','Owner refunded'], ['timelocked-savings','owner','Owner reclaimed'],
    ['custom-type','unknown','Funds spent on chain'],
  ]) {
    notifications.notifyCovenantSpend({}, type, path);
    assert.match(element('toast').textContent, new RegExp(expected));
  }
  const priorToast = element('toast').textContent;
  notifications.notifyCovenantSpend({}, 'escrow', 'heir');
  notifications.notifyCovenantSpend({}, 'escrow', 'owner');
  notifications.notifyCovenantSpend({}, 'global-spending-limit', 'owner');
  assert.equal(element('toast').textContent, priorToast);

  const buttons = () => ({ beneBtn:new FakeElement('button'), ownerBtn:new FakeElement('button'), fundBtn:new FakeElement('button'), consolBtn:new FakeElement('button') });

  // Result-button modules are tiny but security relevant: exercise loaded/not
  // loaded, optional controls, beneficiary/owner/arbiter, absent/present result,
  // malformed JSON and missing optional recovery fields.
  let b=buttons(); additiveButtons.configureAdditive(b); assert.equal(b.fundBtn.textContent,'Covenant Deposit'); assert.equal(b.consolBtn.style.display,'none');
  b=buttons(); additiveButtons.configureAdditive({...b,fundBtn:null,consolBtn:null});

  state.covenantState.lastCovenantResult=null;
  b=buttons(); merkleButtons.configureMerkleActions(b); b.beneBtn.onclick(); assert.equal(element('cov-mw-spend-panel').classList.contains('hidden'),false);
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51',merkle_addresses_json:'not-json'};
  state.covenantState.activeCovenants=[]; b.beneBtn.onclick(); assert.equal(element('cov-mw-addr').value,ADDRESS);
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51',merkle_addresses_json:JSON.stringify(['fallback'])};
  state.covenantState.activeCovenants=[{address:ADDRESS,merkle_addresses_json:JSON.stringify(['active-a','active-b'])}]; b.beneBtn.onclick(); assert.equal(element('cov-mw-spend-addresses').value,'active-a\nactive-b');
  state.covenantState.activeCovenants=[]; b.beneBtn.onclick(); assert.equal(element('cov-mw-spend-addresses').value,'fallback');
  b=buttons(); merkleButtons.configureMerkleActions({...b,fundBtn:null});

  state.covenantState.lastCovenantResult=null;
  b=buttons(); payjoinButtons.configurePayjoinActions({...b,isBeneficiary:true}); b.beneBtn.onclick(); assert.equal(b.ownerBtn.style.display,'none');
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51'}; b.beneBtn.onclick(); assert.equal(element('cov-payjoin-claim-addr').value,ADDRESS);
  state.walletSession.clear(); element('cov-payjoin-claim-mix-addr').value=''; b.beneBtn.onclick(); assert.equal(element('cov-payjoin-claim-mix-addr').value,'');
  state.walletSession.replace(structuredClone(wallet));
  b=buttons(); payjoinButtons.configurePayjoinActions({...b,isBeneficiary:false,fundBtn:null}); assert.equal(b.beneBtn.style.display,'none');

  state.covenantState.lastCovenantResult=null;
  b=buttons(); commitButtons.configureCommitRevealActions(b); b.beneBtn.onclick();
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51',cr_ciphertext_hex:''}; b.beneBtn.onclick(); assert.match(element('toast').textContent,/No ciphertext/);
  state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51',cr_ciphertext_hex:'aabb'}; b.beneBtn.onclick(); assert.equal(element('cov-cr-addr').value,ADDRESS);
  b=buttons(); commitButtons.configureCommitRevealActions({...b,fundBtn:null});

  // Auxiliary verification: pre-existing button, newly-created button, no back
  // button, and unrelated covenant all have explicit behavior.
  const oldGet=document.getElementById.bind(document); let syntheticVerify=null; let syntheticBack=null;
  document.getElementById=id=>{
    if(id==='btn-cov-cr-verify-entry') return syntheticVerify;
    if(id==='btn-cov-result-back') return syntheticBack;
    return oldGet(id);
  };
  commitVerify.configureCommitRevealVerification('other');
  syntheticBack=new FakeElement('button'); syntheticBack.parentElement=new FakeElement('div');
  commitVerify.configureCommitRevealVerification('commit-reveal'); syntheticVerify=syntheticBack.parentElement.children[0]; assert.ok(syntheticVerify); syntheticVerify.onclick();
  commitVerify.configureCommitRevealVerification('other'); assert.equal(syntheticVerify.style.display,'none');
  document.getElementById=oldGet;

  // Shipment includes creator/imported visibility and sparse-result hydration.
  state.covenantState.lastCovenantResult={is_creator:false,address:ADDRESS,redeem_script_hex:'51'};
  b=buttons(); shipmentButtons.configureShipmentActions({...b,isLoaded:true}); assert.equal(b.fundBtn.style.display,'none'); element('btn-cov-ship-open').onclick(); assert.equal(element('cov-ship-addr').value,ADDRESS);
  state.covenantState.lastCovenantResult=null; shipmentButtons.configureShipmentActions({...b,isLoaded:false}); element('btn-cov-ship-open').onclick(); assert.equal(b.fundBtn.style.display,'');
  shipmentButtons.configureShipmentActions({...b,fundBtn:null,isLoaded:false});

  // Escrow roles: beneficiary, arbiter and creator/owner; optional buttons too.
  b=buttons(); escrowButtons.configureEscrow({...b,isLoaded:true,covRole:'seller',isBeneficiary:true}); assert.equal(b.ownerBtn.style.display,'none');
  b=buttons(); escrowButtons.configureEscrow({...b,isLoaded:true,covRole:'arbiter',isBeneficiary:false}); assert.equal(b.ownerBtn.textContent,'Award to Seller');
  b=buttons(); escrowButtons.configureEscrow({...b,isLoaded:false,covRole:'',isBeneficiary:false}); assert.equal(b.ownerBtn.textContent,'Release to Seller');
  b=buttons(); escrowButtons.configureEscrow({...b,fundBtn:null,consolBtn:null,isLoaded:false,covRole:'',isBeneficiary:false});

  // Settings: source/fallback return paths, history REST requirement, newly
  // enabled history, network switch, normal exit, and dashboard refresh route.
  state.networkState.customNodeUrl=null; state.networkState.customRestUrl=null; state.walletState.addressHistoryEnabled=false;
  settings.showSettings('send'); settings.showSettings('settings'); settings.clearCustomNode();
  setValue('input-node-url',' wss://custom '); element('chk-addr-history').checked=true; setValue('input-rest-url',''); element('chk-stealth-indexer').checked=true; setValue('select-network',state.networkState.network); settings.saveSettings(); assert.equal(state.walletState.addressHistoryEnabled,false);
  setValue('input-rest-url','https://history'); element('chk-addr-history').checked=true; settings.saveSettings(); assert.equal(state.walletState.addressHistoryEnabled,true);
  setValue('select-network','testnet-10'); settings.saveSettings(); assert.equal(state.networkState.network,'testnet-10');
  state.networkState.network='mainnet'; setValue('select-network','mainnet'); state.navigationState.settingsReturnScreen='settings'; settings.exitSettings();
  state.navigationState.settingsReturnScreen='dashboard'; settings.exitSettings();

  // Piggy status covers unconditional, goal, deadline, unknown DAA, dual-fail,
  // fallback DAA and banner create/reuse paths.
  const {piggyBreakStatus,piggyStatusBanner}=piggy.createPiggyHelpers();
  state.covenantState.lastCovenantResult={threshold_sompi:'0',deadline_daa:'0'}; assert.equal((await piggyBreakStatus(10n,1n)).canBreak,true);
  state.covenantState.lastCovenantResult={threshold_sompi:'5',deadline_daa:'0'}; assert.equal((await piggyBreakStatus(10n,1n)).goalMet,true);
  state.covenantState.lastCovenantResult={threshold_sompi:'100',deadline_daa:'500'}; state.covenantState._lastKnownDaa=1000n; assert.equal((await piggyBreakStatus(10n,1n)).deadlinePassed,true);
  state.covenantState.lastCovenantResult={threshold_sompi:'100',deadline_daa:'2000'}; state.covenantState._lastKnownDaa=1000n; assert.match((await piggyBreakStatus(10n,1n)).text,/goal.*deadline/);
  globalThis.__KASSEE_WASM_STUBS__.get_virtual_daa_score=()=>{throw new Error('daa unavailable')}; state.networkState.utxoSnapshot=[]; state.covenantState._lastKnownDaa=0n; assert.match((await piggyBreakStatus(10n,1n)).text,/unknown/); globalThis.__KASSEE_WASM_STUBS__.get_virtual_daa_score=()=> '1000';
  const banner=piggyStatusBanner({color:'red',text:'blocked'}); assert.equal(banner.textContent,'blocked'); assert.equal(piggyStatusBanner({color:'green',text:'ready'}),banner);

  // Metadata parsers: malformed input, partial escrow signatures and valid
  // allowance/piggy script opcodes all remain fail-closed and deterministic.
  assert.deepEqual(metadata.parseAllowanceScript('zz'),{max_withdraw_sompi:0n,cooldown_daa:0n,start_daa:0n});
  assert.equal(metadata.parseEscrowScript('').alice_pk,'');
  const escrowPrefix='08'+'aa'.repeat(8)+'75'+'6320'+PK;
  assert.equal(metadata.parseEscrowScript(escrowPrefix).arbiter_pk,'');
  assert.deepEqual(metadata.parsePiggyScript('zz'),{threshold_sompi:0n,deadline_daa:0n});

  // Fee state and owner address cover all fee tiers, absent estimates, invalid
  // input count and wallet/no-wallet accessors.
  state.networkState.lastFeeEstimate=null; assert.ok(payloadState.getCovFee(0)>=400000n);
  state.networkState.lastFeeEstimate={low_sompi_per_gram:'1',normal_sompi_per_gram:'2',priority_sompi_per_gram:'3'};
  for(const level of ['low','priority','normal']){state.covenantState.covFeeLevel=level;assert.ok(payloadState.getCovFee(3)>0n);}
  state.walletSession.replace(structuredClone(wallet)); assert.equal(payloadState.ownerReceiveAddr(),ADDRESS); state.walletSession.clear(); assert.equal(payloadState.ownerReceiveAddr(),''); state.walletSession.replace(structuredClone(wallet));

  // Connectivity distinguishes browser offline from node unavailable, plus
  // missing DOM and listener installation branches.
  assert.equal(connectivity.browserIsOnline(),true); connectivity.renderBrowserConnectivity(); connectivity.renderNodeUnavailable(); connectivity.bindBrowserConnectivity();
  const nav=globalThis.navigator; Object.defineProperty(globalThis,'navigator',{configurable:true,value:{...nav,onLine:false}}); assert.equal(connectivity.browserIsOnline(),false); connectivity.renderBrowserConnectivity(); connectivity.renderNodeUnavailable(); Object.defineProperty(globalThis,'navigator',{configurable:true,value:nav});
  const oldQuery=document.querySelector.bind(document); document.querySelector=()=>null; connectivity.renderBrowserConnectivity(); connectivity.renderNodeUnavailable(); document.querySelector=oldQuery;

  // Pure network selectors cover every accepted prefix and unknown network.
  assert.equal(network.detectWalletNetwork(null),'mainnet'); assert.equal(network.detectWalletNetwork({receive_addresses:['kaspatest:q']},'mainnet'),'testnet-10'); assert.equal(network.detectWalletNetwork({receive_addresses:['kaspatest:q']},'testnet-12'),'testnet-12'); assert.equal(network.detectWalletNetwork({receive_addresses:['kaspasim:q']}),'simnet'); assert.equal(network.detectWalletNetwork(JSON.stringify({receive_addresses:['kaspadev:q']})),'devnet'); assert.equal(network.detectWalletNetwork({receive_addresses:[]}),'mainnet');
  for(const [n,p] of [['mainnet','kaspa:'],['devnet','kaspadev:'],['simnet','kaspasim:'],['testnet-10','kaspatest:'],['unknown','']]) assert.equal(network.addressPrefix(n),p);

  // Anti-klepto response router: inactive passthrough, commitment, final, and
  // unexpected message kind. The active transcript remains watch-only.
  const antiSession=await import(moduleUrl('features/transactions/anti_klepto/session.js'));
  antiSession.clearAntiKleptoSession(); assert.equal(antiResponse.processAntiKleptoResponse('aa'),'aa');
  const stubs=globalThis.__KASSEE_WASM_STUBS__;
  stubs.anti_klepto_begin=()=>JSON.stringify({requestHex:'aa',hostSecretHex:'bb'});
  stubs.anti_klepto_accept_commitment=()=> 'cc'; stubs.anti_klepto_verify_signed=()=> 'dd';
  antiSession.beginAntiKlepto('aa'); assert.equal(antiResponse.processAntiKleptoResponse('4b414b50020200'),null);
  assert.equal(antiResponse.processAntiKleptoResponse('4b414b50020400'),'dd');
  antiSession.beginAntiKlepto('aa'); assert.throws(()=>antiResponse.processAntiKleptoResponse('4b414b50020900'),/Expected KasSigner/); antiSession.clearAntiKleptoSession();

  // Planner dispatch covers covenant, selected-UTXO and automatic routes.
  state.networkState.cachedUtxos=structuredClone(utxos); state.networkState.customNodeUrl='wss://runtime-node'; state.navigationState._broadcastReturnScreen='covenant'; state.covenantState.lastCovenantResult={address:ADDRESS,redeem_script_hex:'51'}; state.transactionState.selectedUtxoIds=[];
  await planner.planTransaction({destination:ADDRESS,amountString:'1',fee:1000n,freshWallet:wallet});
  state.navigationState._broadcastReturnScreen='send'; state.transactionState.selectedUtxoIds=[`${state.networkState.cachedUtxos[0].tx_id}:${state.networkState.cachedUtxos[0].index}`]; await planner.planTransaction({destination:ADDRESS,amountString:'1',fee:1000n,freshWallet:wallet});
  state.transactionState.selectedUtxoIds=[]; await planner.planTransaction({destination:ADDRESS,amountString:'1',fee:1000n,freshWallet:wallet});

  // Crowdfunding persistence/model fallbacks are covered field-by-field so a
  // sparse/corrupt recovery record cannot inherit stale contribution material.
  assert.throws(()=>crowdfundModel.contributionFromResult({}),/address/);
  assert.throws(()=>crowdfundModel.validateContribution({address:ADDRESS}),/contributor key/);
  assert.throws(()=>crowdfundModel.validateContribution({address:ADDRESS,contributor_pubkey_hex:PK}),/redeem script/);
  assert.throws(()=>crowdfundModel.validateContribution({address:ADDRESS,contributor_pubkey_hex:PK,redeem_script_hex:'51'}),/salt/);
  state.crowdfundState.contributions=[]; crowdfundModel.hydrateCrowdfundState({type:'crowdfund',crowdfund_role:'organizer',goal_sompi:'1',locktime_daa:'2',organizer_address:ADDRESS,vk_hex:'aa',campaign_id:PK3}); assert.equal(state.crowdfundState.setup.pk_hex,'');
  assert.throws(()=>crowdfundModel.campaignFromResult({}),/goal|DAA|destination|verifying/i);
  const noDate={v:2,t:'crowdfund-campaign',name:'',goal:'1',daa:'2',organizer:ADDRESS,vk:'aa',id:PK3}; assert.equal(crowdfundModel.normalizeCampaign(noDate).date,'');

  // Campaign UI covers absent wallet/address, invalid setup material, missing
  // summary DOM and covenant identity mismatch without weakening fail-closed setup.
  state.walletSession.clear(); setValue('cov-crowdfund-organizer-address',''); crowdfundCampaign.populateOrganizerDestination(); assert.equal(element('cov-crowdfund-organizer-address').value,'');
  state.walletSession.replace({...wallet,receive_addresses:[]}); crowdfundCampaign.populateOrganizerDestination(); assert.equal(element('cov-crowdfund-organizer-address').value,''); state.walletSession.replace(structuredClone(wallet)); crowdfundCampaign.populateOrganizerDestination(); assert.equal(element('cov-crowdfund-organizer-address').value,ADDRESS);
  const stubsCf=globalThis.__KASSEE_WASM_STUBS__; stubsCf.zk_crowdfund_setup=()=>JSON.stringify({pk_hex:'',vk_hex:'',vk_hash_hex:''}); await crowdfundCampaign.runCrowdfundSetup(); assert.match(element('toast').textContent,/setup failed/i);
  stubsCf.zk_crowdfund_setup=()=>JSON.stringify({pk_hex:'aa',vk_hex:'bb',vk_hash_hex:PK3}); await crowdfundCampaign.runCrowdfundSetup(); assert.match(element('crowdfund-setup-status').textContent,/Setup ready/);
  const savedGet=document.getElementById.bind(document); document.getElementById=id=>id==='crowdfund-contributor-summary'?null:savedGet(id); crowdfundCampaign.renderImportedCampaign(); document.getElementById=savedGet;
  state.crowdfundState.importedCampaign={...noDate,name:''}; crowdfundCampaign.renderImportedCampaign(); assert.match(element('crowdfund-contributor-summary').textContent,/Crowdfunding campaign/);
  state.crowdfundState.role='contributor'; stubsCf.covenant_crowdfund=()=>JSON.stringify({campaign_id:'44'.repeat(32)}); await assert.rejects(()=>crowdfundCampaign.buildCrowdfund(PK),/identity mismatch/);

  // Kpub repository persistence covers unavailable/corrupt storage, normalization,
  // deterministic default names, update/duplicate/delete/autoload and clone fallback.
  const noStore=kpubRepoMod.createKpubRepository(null,()=> 'id-none'); assert.deepEqual(noStore.list(),[]); assert.throws(()=>noStore.save({name:'X',kpub:'kpub:x',network:'mainnet'}),/storage is unavailable/);
  const values=new Map(); const mem={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,String(v))}; let id=0;
  const repo=kpubRepoMod.createKpubRepository(mem,()=>`id-${++id}`);
  assert.equal(repo.get('missing'),null); assert.equal(repo.autoLoadEntry(),null); assert.equal(repo.remove('missing'),null); assert.throws(()=>repo.setAutoLoad('missing'),/not found/);
  const one=repo.save({name:'',kpub:'kpub:one',network:'mainnet'}); assert.equal(one.name,'Wallet 1');
  const two=repo.save({name:'',kpub:'kpub:two',network:'testnet-10'}); assert.equal(two.name,'Wallet 2');
  assert.equal(repo.save({name:'',kpub:'kpub:one',network:'mainnet'}).name,'Wallet 1');
  assert.throws(()=>repo.save({name:'Wallet 1',kpub:'kpub:three',network:'mainnet'}),/friendly name/);
  assert.throws(()=>repo.save({name:'x',kpub:'',network:'mainnet'}),/public key/); assert.throws(()=>repo.save({name:'x',kpub:'kpub:x',network:'devnet'}),/network/); assert.throws(()=>repo.save({name:'x'.repeat(65),kpub:'kpub:x',network:'mainnet'}),/64/);
  assert.throws(()=>repo.rename('missing','x'),/not found/); assert.throws(()=>repo.rename(two.id,'   '),/friendly name/); assert.throws(()=>repo.rename(two.id,'Wallet 1'),/friendly name/); assert.equal(repo.rename(two.id,'  Second   Wallet ').name,'Second Wallet');
  repo.setAutoLoad(one.id); assert.equal(repo.autoLoadEntry().id,one.id); assert.equal(repo.remove(one.id).id,one.id); assert.equal(repo.autoLoadId(),null); assert.equal(repo.setAutoLoad(null),null);
  values.set('kassee-kpub-manager-v1','{broken'); assert.deepEqual(repo.list(),[]);
  values.set('kassee-kpub-manager-v1',JSON.stringify({entries:[null,{id:'',name:'x'}, {id:'ok',name:'Good',kpub:'kpub:g',network:'mainnet'}],autoLoadId:'missing'})); assert.equal(repo.list().length,1); assert.equal(repo.autoLoadId(),null);
  const oldClone=globalThis.structuredClone; globalThis.structuredClone=undefined; assert.equal(repo.get('ok').name,'Good'); globalThis.structuredClone=oldClone;
  const failing={getItem:()=>null,setItem:()=>{throw new Error('quota')}}; const failRepo=kpubRepoMod.createKpubRepository(failing,()=> 'id'); assert.throws(()=>failRepo.save({name:'x',kpub:'kpub:x',network:'mainnet'}),/could not save/i);

  // Safe-markup fallback is the security behavior for non-browser/minimal DOMs.
  const target=new FakeElement('div'); safeHtml.setSafeMarkup(target,'<img src=x onerror=1>&"\''); assert.match(target.innerHTML,/&lt;img/); assert.equal(safeHtml.escapeMarkupAsLiteral(null),''); safeHtml.setSafeMarkup(null,'x');

  console.log('PASS: UI/result/settings/network branch hardening paths');
} finally {
  await cleanupDeepHarness();
}
