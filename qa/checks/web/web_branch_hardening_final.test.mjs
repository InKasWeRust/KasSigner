import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, setFetchHook,
  ADDRESS, PK, PK2, PK3, COV_ID, wallet, utxos,
} from './web_runtime_deep_harness.mjs';
import { FakeElement } from './web_recovery_test_harness.mjs';

const { state, response, originalGet } = await setupDeepHarness();
try {
  const stubs = globalThis.__KASSEE_WASM_STUBS__;
  const scriptPushes = await import(moduleUrl('core/script_pushes.js'));
  const beneficiaryExport = await import(moduleUrl('features/covenants/recovery/export/beneficiary_payload.js'));
  const payloadState = await import(moduleUrl('features/covenants/payload_and_swaps/state.js'));
  const assets = await import(moduleUrl('features/assets/render.js'));
  const balance = await import(moduleUrl('app/events/contracts/covenant_creation/result_actions/balance.js'));
  const recoveryEvents = await import(moduleUrl('app/events/contracts/covenant_recovery.js'));
  const inviteSharing = await import(moduleUrl('app/events/contracts/covenant_creation/invite_sharing.js'));
  const merkleBuilder = await import(moduleUrl('features/covenants/generation/builders/advanced/merkle_whitelist.js'));
  const loadSubmission = await import(moduleUrl('app/events/contracts/covenant_loading/submission.js'));
  const timed = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/timed.js'));
  const limitPollers = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/limits.js'));
  const feeMath = await import(moduleUrl('core/fee_math.js'));
  const privateState = await import(moduleUrl('features/covenants/private_swap/state.js'));
  const shell = await import(moduleUrl('app/shell_controls.js'));
  const merkleEvents = await import(moduleUrl('app/events/contracts/covenant_specialized/merkle_whitelist.js'));
  const exact = await import(moduleUrl('core/exact.js'));
  const utxoCore = await import(moduleUrl('core/utxo.js'));
  const kpubQr = await import(moduleUrl('features/wallet/core/kpub_qr_payload.js'));
  const donations = await import(moduleUrl('features/donations/screen.js'));
  const limitBuilders = await import(moduleUrl('features/covenants/generation/builders/limits.js'));
  const pubkeyScanning = await import(moduleUrl('features/covenants/scanning/pubkeys.js'));
  const assetScreen = await import(moduleUrl('features/assets/index.js'));
  const paramIndex = await import(moduleUrl('features/covenants/payload_and_swaps/params/index.js'));
  const fileDownload = await import(moduleUrl('features/covenants/recovery/export/file_download.js'));
  const crRendering = await import(moduleUrl('app/events/contracts/covenant_specialized/commit_reveal/rendering.js'));
  const payloadCrypto = await import(moduleUrl('features/covenants/payload_and_swaps/payload.js'));
  const oracleAttestation = await import(moduleUrl('features/oracle/v1/attestation.js'));
  const covenantSignProtocol = await import(moduleUrl('features/covenants/signing/protocol.js'));
  const recoveryImport = await import(moduleUrl('features/covenants/recovery/import/controller.js'));
  const signerLimits = await import(moduleUrl('features/transactions/shared/signer_limits.js'));
  const kpubImage = await import(moduleUrl('features/wallet/core/kpub_image_import.js'));
  const signedImage = await import(moduleUrl('features/transactions/send/signed_qr_image_import.js'));
  const escrowController = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/conditional/escrow/controller.js'));
  const escrowFetch = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/conditional/escrow/fetch.js'));
  const escrowRender = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/conditional/escrow/render.js'));
  const escrowState = await import(moduleUrl('features/covenants/watchers_and_ui/watcher/polling/covenant_pollers/conditional/escrow/state.js'));

  // Script traversal: stop sentinel, OP_0, small ints, direct pushes,
  // PUSHDATA1, malformed/truncated payloads and ordinary opcodes.
  const seen=[];
  scriptPushes.walkScriptPushes(Uint8Array.from([0x00,0x51,0x02,0x34,0x12,0x4c,0x01,0x07,0x61]), x=>{seen.push(x);});
  assert.equal(seen.at(-1).lastInteger,7n);
  let calls=0; scriptPushes.walkScriptPushes(Uint8Array.from([0x51,0x52]),()=>{calls++; return false;}); assert.equal(calls,1);
  assert.doesNotThrow(()=>scriptPushes.walkScriptPushes(Uint8Array.from([0x4c]),()=>{}));
  assert.doesNotThrow(()=>scriptPushes.walkScriptPushes(Uint8Array.from([0x03,1]),()=>{}));

  // Portable beneficiary records must serialize sparse public data without
  // carrying values from a prior covenant.
  const sparse = beneficiaryExport.buildBeneficiaryExport({});
  const sparseInvite = JSON.parse(new TextDecoder().decode(sparse.bytes.slice(4)));
  assert.deepEqual({ct:sparseInvite.ct,addr:sparseInvite.addr,rs:sparseInvite.rs,d:sparseInvite.d},{ct:'',addr:'',rs:'',d:'0'});
  const allowance = beneficiaryExport.buildBeneficiaryExport({type:'global-allowance',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'1',max_withdraw_sompi:'2',cooldown_daa:'3',start_daa:'4',start_date_iso:'2099-01-01'});
  assert.equal(JSON.parse(new TextDecoder().decode(allowance.bytes.slice(4))).mw,'2');
  const oracle = beneficiaryExport.buildBeneficiaryExport({type:'oracle-v1',oracle_pubkey_hex:PK,oracle_covenant_key_id_hex:PK2,oracle_covenant_binding_token_hex:PK3,beneficiary_pubkey_hex:PK2,owner_pubkey_hex:PK,attestation_statement:'release',message_commitment_hex:PK3,locktime_date_iso:'2099-01-01',wallet1_pubkey_hex:PK,wallet2_pubkey_hex:PK2});
  assert.equal(JSON.parse(new TextDecoder().decode(oracle.bytes.slice(4))).oas,'release');

  // Fee fallbacks are consensus-facing arithmetic inputs: a node estimate of
  // zero must use the documented minimum rate for every fee tier.
  state.networkState.lastFeeEstimate={low_sompi_per_gram:0,normal_sompi_per_gram:0,priority_sompi_per_gram:0};
  for (const level of ['low','priority','normal']) { state.covenantState.covFeeLevel=level; assert.ok(payloadState.getCovFee(2)>0n); }
  state.networkState.lastFeeEstimate=null; assert.ok(payloadState.getCovFee(-1)>0n);

  // Asset presentation includes zero, singular and plural variants and rejects
  // malformed KRC-20 decimal metadata.
  assert.throws(()=>assets.formatTokenBalance('1',-1),/decimals/);
  assert.throws(()=>assets.formatTokenBalance('1',1.5),/decimals/);
  assert.equal(assets.formatTokenBalance('12',0),'12');
  assert.equal(assets.formatTokenBalance('1',2),'0.01');
  assets.renderWalletAssets({tokens:new Map(),nfts:[],domains:[]}); assert.match(element('tokens-summary').textContent,/No tokens/);
  assets.renderWalletAssets({tokens:new Map([['ONE',{balance:'1',decimals:0}]]),nfts:[{tick:'NFT',tokenId:'1'}],domains:['one.kas']}); assert.match(element('tokens-summary').textContent,/1 token, 1 NFT, 1 domain/);
  assets.renderWalletAssets({tokens:new Map([['A',{balance:'1',decimals:0}],['B',{balance:'2',decimals:0}]]),nfts:[{tick:'N',tokenId:'1'},{tick:'N',tokenId:'2'}],domains:['a.kas','b.kas']}); assert.match(element('tokens-summary').textContent,/2 tokens, 2 NFTs, 2 domains/);

  // Balance result action: absent covenant, additive zero/one/many UTXOs and
  // transport failure all leave an explicit user-visible result.
  balance.registerBalanceAction();
  state.covenantState.lastCovenantResult=null; await element('btn-cov-res-balance').onclick(); assert.match(element('toast').textContent,/No covenant loaded/);
  state.covenantState.lastCovenantResult={type:'additive',address:ADDRESS};
  stubs.fetch_utxos_for_address_js=()=> '[]'; await element('btn-cov-res-balance').onclick(); assert.equal(element('btn-cov-fund').dataset.piggyMode,'deposit');
  stubs.fetch_utxos_for_address_js=()=> JSON.stringify([{amount:'100000000'}]); await element('btn-cov-res-balance').onclick(); assert.match(element('cov-result-balance').textContent,/1 UTXO\)/); assert.equal(element('btn-cov-fund').dataset.piggyMode,'add');
  stubs.fetch_utxos_for_address_js=()=> JSON.stringify([{amount:'1'},{amount:'2'}]); await element('btn-cov-res-balance').onclick(); assert.match(element('cov-result-balance').textContent,/2 UTXOs/);
  stubs.fetch_utxos_for_address_js=()=>{throw new Error('balance down')}; await element('btn-cov-res-balance').onclick(); assert.match(element('cov-result-balance').textContent,/balance down/);

  // Recovery bindings: missing optional controls and both label shapes are
  // accepted without fabricating recovery state.
  let get=document.getElementById;
  document.getElementById=id=>id==='cov-load-type'?null:get(id); recoveryEvents.bindCovenantRecoveryEvents(); element('btn-cov-load-existing').onclick();
  document.getElementById=get; recoveryEvents.bindCovenantRecoveryEvents();
  const type=element('cov-load-type'); type.previousElementSibling=new FakeElement('span'); element('btn-cov-load-existing').onclick();
  type.previousElementSibling=new FakeElement('label'); type.previousElementSibling.classList.add('input-label'); element('btn-cov-load-existing').onclick(); assert.equal(type.previousElementSibling.style.display,'');

  // Invite sharing covers sparse defaults and allowance cooldown precedence.
  let invitePayload=''; stubs.generate_qr_svg_text=value=>{invitePayload=String(value); return '<svg></svg>';}; inviteSharing.registerInviteSharingActions();
  state.covenantState.lastCovenantResult={}; element('btn-cov-res-share-cov').onclick(); let parsed=JSON.parse(invitePayload); assert.deepEqual([parsed.ct,parsed.addr,parsed.rs,parsed.d],['','','','0']);
  state.covenantState.lastCovenantResult={type:'global-allowance',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'0',min_sequence:'8'}; element('btn-cov-res-share-cov').onclick(); parsed=JSON.parse(invitePayload); assert.equal(parsed.cd,'8');
  state.covenantState.lastCovenantResult={type:'timelocked-savings',address:ADDRESS,redeem_script_hex:'51',locktime_daa:'9',locktime_date_iso:'2099-01-01'}; element('btn-cov-res-share-cov').onclick(); assert.equal(JSON.parse(invitePayload).ldi,'2099-01-01');

  // Merkle builder refuses incomplete/malformed policy input and accepts a
  // canonical numeric locktime. These are deterministic host paths: no node.
  setValue('cov-mw-addresses',''); assert.equal(await merkleBuilder.buildMerkleWhitelist(PK),undefined);
  setValue('cov-mw-addresses',ADDRESS); assert.equal(await merkleBuilder.buildMerkleWhitelist(PK),undefined);
  setValue('cov-mw-addresses',`${ADDRESS}\nkaspa:other`); const oldMerkle=stubs.merkle_root_from_addresses; stubs.merkle_root_from_addresses=()=>{throw new Error('bad root')}; assert.equal(await merkleBuilder.buildMerkleWhitelist(PK),undefined); stubs.merkle_root_from_addresses=oldMerkle;
  setValue('cov-mw-locktime','bad'); setValue('cov-mw-datetime',''); assert.equal(await merkleBuilder.buildMerkleWhitelist(PK),undefined);
  setValue('cov-mw-locktime','1200'); const built=await merkleBuilder.buildMerkleWhitelist(PK); assert.ok(built?.resultJson);
  assert.equal(await merkleBuilder.buildMerkleWhitelist(''),undefined);

  // Manual covenant load parser accepts every canonical script-number opcode
  // form it supports and contains malformed hex instead of leaking stale locktime.
  loadSubmission.bindLoadSubmissionAction();
  state.covenantRecoveryState._covLoadedFromInvite=false;
  for (const [script,expected] of [['00b0',0n],['51b0',1n],['0134b0',52n],['4c00b0',0n],['zz',null]]) {
    setValue('cov-load-addr',ADDRESS); setValue('cov-load-type','dms'); setValue('cov-load-script',script); element('btn-cov-load-submit').onclick();
    assert.equal(state.covenantState.lastCovenantResult.locktime_daa,expected);
  }
  state.covenantRecoveryState._covLoadedFromInvite=true; setValue('cov-load-script','51b0'); element('btn-cov-load-submit').onclick(); assert.equal(state.covenantState.lastCovenantResult.role,'beneficiary');

  // Timed watcher rendering covers every maturity state plus a detected spend.
  const st=new FakeElement('div'); const labels={spent:s=>`spent-${s}`,onSpent:()=>{labels.called=true},availableClass:'ok',available:k=>`available-${k}`,unlockingClass:'warn',unlocking:k=>`unlocking-${k}`,locked:(k,t)=>`locked-${k}-${t}`,watching:k=>`watching-${k}`};
  state.covenantWatcherState._covWatcherLastBalance=null; assert.equal(await timed.pollTimedBalance({total:0n,kas:'0',st,locktime:0n,currentDaa:0n},labels),false);
  assert.equal(await timed.pollTimedBalance({total:1n,kas:'1',st,locktime:1000n,currentDaa:1400n},labels),false); assert.match(st.innerHTML,/available/);
  assert.equal(await timed.pollTimedBalance({total:1n,kas:'1',st,locktime:1000n,currentDaa:1100n},labels),false); assert.match(st.innerHTML,/unlocking/);
  assert.equal(await timed.pollTimedBalance({total:1n,kas:'1',st,locktime:1000n,currentDaa:900n},labels),false); assert.match(st.textContent,/locked/);
  assert.equal(await timed.pollTimedBalance({total:1n,kas:'1',st,locktime:0n,currentDaa:0n},labels),false); assert.match(st.textContent,/watching/);
  state.covenantWatcherState._covWatcherLastBalance=1n; state.covenantWatcherState._covWatcherSpendPath='owner'; assert.equal(await timed.pollTimedBalance({total:0n,kas:'0',st,locktime:0n,currentDaa:0n},labels),true); assert.equal(labels.called,true);

  // Allowance/spending-limit watcher states cover sparse defaults, external
  // funds, owner/beneficiary, pre-start, cooldown and mature drain paths.
  const thread={tx_id:'aa'.repeat(32),index:0,amount:'100',block_daa_score:'100',covenant_id:COV_ID};
  const external={tx_id:'bb'.repeat(32),index:1,amount:'50',block_daa_score:'100'};
  state.covenantState.lastCovenantResult={type:'global-spending-limit',covenant_id_hex:COV_ID,cooldown_daa:'10',max_withdraw_sompi:'100'};
  await limitPollers.pollGlobalSpendingLimit({st,currentDaa:200n,utxos:[thread]}); assert.match(st.innerHTML,/drain all/);
  await limitPollers.pollGlobalSpendingLimit({st,currentDaa:105n,utxos:[thread,external]}); assert.match(st.innerHTML,/until next withdraw/);
  state.covenantState.lastCovenantResult={type:'global-spending-limit',covenant_id_hex:COV_ID}; await limitPollers.pollGlobalSpendingLimit({st,currentDaa:0n,utxos:[]}); assert.match(st.innerHTML || st.textContent,/Not funded/);
  state.covenantState.lastCovenantResult={type:'global-allowance',role:'beneficiary',covenant_id_hex:COV_ID,start_daa:'300',cooldown_daa:'10',max_withdraw_sompi:'100'};
  state.covenantWatcherState._covWatcherLastBalance=null; await limitPollers.pollGlobalAllowance({total:100n,st,currentDaa:200n,utxos:[thread,external]}); assert.match(st.innerHTML,/until start/);
  state.covenantState.lastCovenantResult.start_daa='0'; await limitPollers.pollGlobalAllowance({total:100n,st,currentDaa:105n,utxos:[thread]}); assert.match(st.innerHTML,/until next withdraw/);
  await limitPollers.pollGlobalAllowance({total:100n,st,currentDaa:200n,utxos:[thread]}); assert.match(st.innerHTML,/drain all/);
  state.covenantState.lastCovenantResult.role='owner'; await limitPollers.pollGlobalAllowance({total:100n,st,currentDaa:200n,utxos:[thread]}); assert.match(st.innerHTML,/Owner can reclaim/);
  state.covenantState.lastCovenantResult={type:'global-allowance',role:'beneficiary',covenant_id_hex:COV_ID}; await limitPollers.pollGlobalAllowance({total:100n,st,currentDaa:0n,utxos:[thread]}); assert.match(st.innerHTML,/Watching/);

  // Exact fee arithmetic covers scientific notation, negative exponent,
  // zero-rate normalization, floor selection and markup-denominator rejection.
  assert.equal(feeMath.ceilRateToInteger('1e2'),100n);
  assert.equal(feeMath.ceilRateToInteger('1e-2'),1n);
  assert.equal(feeMath.ceilRateToInteger(0),1n);
  assert.equal(feeMath.roundFeeFromRate('1.5',2n,10n),10n);
  assert.equal(feeMath.roundFeeFromRate('1.5',10n,0n),15n);
  assert.equal(feeMath.ceilFeeFromRate('1.1',10n,0n,2n,1n),22n);
  assert.throws(()=>feeMath.ceilFeeFromRate('1',1n,0n,1n,0n),/denominator/);
  assert.throws(()=>feeMath.ceilRateToInteger('bad'),/decimal/);

  // Private Swap persistence must fail closed on malformed recovery data while
  // storage failures remain non-fatal and cannot persist transient secrets.
  sessionStorage.clear(); privateState.resetPrivateSwapState(); sessionStorage.clear(); assert.equal(privateState.loadPrivateSwapState(),privateState.privateSwapState);
  assert.throws(()=>privateState.restorePrivateSwapState('{}'),/role/);
  assert.throws(()=>privateState.restorePrivateSwapState({role:'alice'}),/ID/);
  assert.throws(()=>privateState.restorePrivateSwapState({role:'alice',swapId:'ab'.repeat(16),myClaimKspt:'secret'}),/forbidden/);
  const restored=privateState.restorePrivateSwapState(JSON.stringify({role:'bob',swapId:'ab'.repeat(16),network:'mainnet'})); assert.equal(restored.role,'bob');
  const oldSet=sessionStorage.setItem; sessionStorage.setItem=()=>{throw new Error('quota')}; assert.doesNotThrow(()=>privateState.savePrivateSwapState()); sessionStorage.setItem=oldSet;
  const oldRemove=sessionStorage.removeItem; sessionStorage.removeItem=()=>{throw new Error('remove')}; assert.doesNotThrow(()=>privateState.clearPrivateSwapState()); sessionStorage.removeItem=oldRemove;
  sessionStorage.setItem('kassee_private_swap_v2','{bad'); assert.equal(privateState.loadPrivateSwapState(),privateState.privateSwapState);

  // Shell controls cover missing gear controls, targetless tabs, donation
  // return fallback, donation self-return normalization and clipboard failure.
  const originalQueryAll=document.querySelectorAll.bind(document);
  const tabNoTarget=new FakeElement('button'); tabNoTarget.dataset={};
  const tabSettings=new FakeElement('button'); tabSettings.dataset={target:'settings'};
  document.querySelectorAll=selector=>selector==='.gear-tab'?[tabNoTarget,tabSettings]:originalQueryAll(selector);
  let originalId=document.getElementById;
  document.getElementById=id=>(id==='gear-menu'||id==='btn-header-settings')?null:originalId(id); shell.bindShellControls();
  document.getElementById=originalId; shell.bindShellControls(); tabNoTarget.onclick(); tabSettings.onclick();
  const donate=element('screen-donate'); delete donate.dataset.returnScreen; element('btn-logo').onclick(); element('btn-donate-skip').onclick();
  donate.dataset.returnScreen='donate'; element('btn-donate-skip').onclick();
  const priorNavigator=globalThis.navigator; Object.defineProperty(globalThis,'navigator',{configurable:true,value:{...priorNavigator,clipboard:{async writeText(){throw new Error('denied')}}}}); await element('btn-copy-donate').onclick(); assert.match(element('toast').textContent,/Copy failed/); Object.defineProperty(globalThis,'navigator',{configurable:true,value:priorNavigator});
  document.querySelectorAll=originalQueryAll;

  // Merkle result wiring covers no active result, active-entry precedence,
  // malformed whitelist JSON, zero balance and node failure Max paths.
  stubs.fetch_utxos_for_address_js=()=>JSON.stringify([{amount:'1000000'}]);
  state.covenantState.lastCovenantResult=null; merkleEvents.bindMerkleWhitelistEvents(); await element('btn-cov-mw-spend').onclick();
  state.covenantState.lastCovenantResult={type:'merkle-whitelist',address:ADDRESS,redeem_script_hex:'51',merkle_addresses_json:'bad'}; state.covenantState.activeCovenants=[]; await element('btn-cov-mw-spend').onclick(); assert.equal(element('cov-mw-amount').placeholder.endsWith('max'),true);
  state.covenantState.activeCovenants=[{address:ADDRESS,merkle_addresses_json:JSON.stringify(['kaspa:a','kaspa:b'])}]; await element('btn-cov-mw-spend').onclick(); assert.match(element('cov-mw-spend-addresses').value,/kaspa:a/);
  stubs.fetch_utxos_for_address_js=()=> '[]'; await element('btn-cov-mw-max').onclick(); assert.match(element('toast').textContent,/No spendable balance/);
  stubs.fetch_utxos_for_address_js=()=>{throw new Error('merkle down')}; await element('btn-cov-mw-max').onclick(); assert.match(element('toast').textContent,/Max failed/);

  // Pure exact/UTXO helpers cover signed rejection, comparison ties,
  // subtraction floor, alternate transaction-id shapes and stable amount sort.
  assert.throws(()=>exact.exactUnsigned(-1n),/unsigned/); assert.equal(exact.compareExactDescending('1','1'),0); assert.equal(exact.compareExactDescending('2','1'),-1); assert.equal(exact.compareExactDescending('1','2'),1); assert.equal(exact.nonNegativeDifference(1n,2n),0n);
  assert.equal(utxoCore.utxoTransactionId({outpoint:{transactionId:'a'}}),'a'); assert.equal(utxoCore.utxoTransactionId({previousOutpoint:{transactionId:'b'}}),'b'); assert.equal(utxoCore.utxoTransactionId({transactionId:'c'}),'c');
  assert.throws(()=>utxoCore.parseUtxosJson('{}'),/array/); const equal=[{amount:'2',index:2},{amount:'2',index:1}]; utxoCore.sortUtxosLargestFirst(equal); assert.equal(equal.length,2);

  // Kpub QR ingestion accepts every supported binary view and quote form,
  // including text recovered from binary QR payloads.
  assert.equal(kpubQr.normalizeKpubText(`'${wallet.kpub}'`),wallet.kpub); assert.equal(kpubQr.normalizeKpubText(`\"${wallet.kpub}\"`),wallet.kpub);
  const compact=new Uint8Array(79); compact[0]=1; assert.equal(kpubQr.classifyKpubQrCode({binaryData:compact.buffer}).kind,'compact'); assert.equal(kpubQr.classifyKpubQrCode({binaryData:new DataView(compact.buffer)}).kind,'compact');
  const textBytes=new TextEncoder().encode(wallet.kpub); assert.equal(kpubQr.classifyKpubQrCode({binaryData:textBytes,data:''}).kind,'text'); assert.throws(()=>kpubQr.classifyKpubQrCode({binaryData:new Uint8Array([1,2]),data:''}),/valid KasSigner kpub/);

  // Donation navigation covers DOM-active, navigation fallback, wallet/no-wallet
  // defaults and clipboard failure without ever mutating wallet state.
  const oldQuery=document.querySelector.bind(document); const active=new FakeElement('section','screen-send'); document.querySelector=sel=>sel==='.screen.active'?active:oldQuery(sel); donations.showDonateScreen(); donations.closeDonateScreen();
  document.querySelector=()=>null; state.navigationState.currentScreenName=''; state.walletSession.clear(); donations.showDonateScreen(); donations.closeDonateScreen(); state.walletSession.replace(structuredClone(wallet)); donations.showDonateScreen(); donations.closeDonateScreen(); document.querySelector=oldQuery;
  const navBefore=globalThis.navigator; Object.defineProperty(globalThis,'navigator',{configurable:true,value:{...navBefore,clipboard:{async writeText(){throw new Error('no clipboard')}}}}); await donations.copyDonationAddress(); assert.match(element('toast').textContent,/Could not copy/); Object.defineProperty(globalThis,'navigator',{configurable:true,value:navBefore});

  // Allowance builder covers address decoding, bad decoded keys, amount failure,
  // future-start conversion and the persisted ISO start-date field.
  setValue('cov-allowance-bene-pk','kaspa:'+'q'.repeat(50)); setValue('cov-allowance-max','1'); setValue('cov-allowance-period','60'); setValue('cov-allowance-start',''); stubs.decode_address=()=>JSON.stringify({payload:PK2}); assert.ok((await limitBuilders.buildGlobalAllowance(PK))?.resultJson);
  stubs.decode_address=()=>{throw new Error('decode')}; assert.equal(await limitBuilders.buildGlobalAllowance(PK),undefined); stubs.decode_address=()=>JSON.stringify({payload:'aa'}); assert.equal(await limitBuilders.buildGlobalAllowance(PK),undefined);
  setValue('cov-allowance-bene-pk',PK2); setValue('cov-allowance-max','0'); assert.equal(await limitBuilders.buildGlobalAllowance(PK),undefined); setValue('cov-allowance-max','1');
  setValue('cov-allowance-start','2099-01-01T00:00'); const futureAllowance=await limitBuilders.buildGlobalAllowance(PK); assert.ok(futureAllowance?.extra.start_date_iso); setValue('cov-allowance-start','');
  stubs.decode_address=a=>JSON.stringify({payload:String(a).includes('beneficiary')?PK2:PK,version:0});

  // Scanning is fail-closed across raw keys, invalid/wrong-network addresses,
  // missing decoded payloads and address-encoding failure.
  state.networkState.network='mainnet';
  pubkeyScanning.covScanAddress('scan-target','scan'); state.scannerState.scanCallback(new TextEncoder().encode('not-address')); assert.match(element('toast').textContent,/Kaspa address/);
  pubkeyScanning.covScanAddress('scan-target','scan'); state.scannerState.scanCallback(new TextEncoder().encode('kaspatest:wrong')); assert.match(element('toast').textContent,/different network/);
  stubs.decode_address=()=>JSON.stringify({}); pubkeyScanning.covScanAddress('scan-target','scan'); state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS)); assert.match(element('toast').textContent,/Could not decode/);
  stubs.decode_address=()=>{throw new Error('bad')}; pubkeyScanning.covScanAddress('scan-target','scan'); state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS)); assert.match(element('toast').textContent,/Could not decode/);
  stubs.decode_address=()=>JSON.stringify({payload:PK}); const oldEncode=stubs.encode_p2pk_address; stubs.encode_p2pk_address=()=>{throw new Error('encode')}; pubkeyScanning.covScanPubkey('scan-pub','pub',false); state.scannerState.scanCallback(new TextEncoder().encode(PK)); assert.equal(element('scan-pub').value,PK); stubs.encode_p2pk_address=oldEncode;
  pubkeyScanning.covScanPubkey('scan-pub','pub',true); state.scannerState.scanCallback(new TextEncoder().encode(wallet.kpub)); assert.match(element('toast').textContent,/not a kpub/);
  stubs.decode_address=()=>JSON.stringify({payload:'aa'}); pubkeyScanning.covScanPubkey('scan-pub','pub',false); state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS)); assert.match(element('toast').textContent,/Could not extract/);
  stubs.decode_address=()=>{throw new Error('bad addr')}; pubkeyScanning.covScanPubkey('scan-pub','pub',false); state.scannerState.scanCallback(new TextEncoder().encode(ADDRESS)); assert.match(element('toast').textContent,/Invalid address/);
  stubs.decode_address=a=>JSON.stringify({payload:String(a).includes('beneficiary')?PK2:PK,version:0});

  // Small integration surfaces: no-wallet token screen, unknown covenant
  // parameter serializer, filename sanitization and both verification outcomes.
  state.walletSession.clear(); assert.equal(await assetScreen.showTokens(),undefined); assert.match(element('toast').textContent,/Import kpub/); state.walletSession.replace(structuredClone(wallet));
  assert.ok(paramIndex.buildCovenantParamsHex({type:'future-type',redeem_script_hex:'51'}).length>0);
  fileDownload.downloadCovenantExport({type:'Bad TYPE!?',address:ADDRESS},{bytes:new Uint8Array([1,2]),extension:'.cov'}); assert.match(element('toast').textContent,/Saved cov-/);
  const missingGet=document.getElementById.bind(document); document.getElementById=id=>id==='cov-cr-verify-preimage'?null:missingGet(id); crRendering.clearVerificationResult(); document.getElementById=missingGet;
  crRendering.renderVerificationResult({preimageText:'a',committedHash:'b',computedHash:'b',matches:true,timestamp:'now'}); assert.match(element('cov-cr-verify-match').textContent,/MATCH/);
  crRendering.renderVerificationResult({preimageText:'a',committedHash:'b',computedHash:'c',matches:false,timestamp:'now'}); assert.match(element('cov-cr-verify-match').textContent,/MISMATCH/);

  // Payload and Oracle attestation boundaries explicitly cover no-wallet,
  // minimum framing, malformed crypto material and statement size limits.
  state.walletSession.clear(); await assert.rejects(()=>payloadCrypto.encryptCovenantPayload('dms',{}),/No wallet/); assert.equal(await payloadCrypto.decryptCovenantPayload('aa'),null);
  state.walletSession.replace(structuredClone(wallet)); assert.equal(await payloadCrypto.decryptCovenantPayload('aa'),null); assert.equal(await payloadCrypto.decryptCovenantPayload('zz'.repeat(40)),null);
  await assert.rejects(()=>oracleAttestation.oracleV1MessageCommitment(''),/exact attestation/); await assert.rejects(()=>oracleAttestation.oracleV1MessageCommitment('x'.repeat(257)),/256/);
  await assert.rejects(()=>oracleAttestation.verifyOracleV1Attestation({signature:'aa'},'release'),/64 bytes/); await assert.rejects(()=>oracleAttestation.verifyOracleV1Attestation({signature:'aa'.repeat(64)},'release'),/commitment/);

  // Final branch floor buffer: successful UTXO parse/tie ordering,
  // sparse Merkle hydration/zero/error placeholders, and raw-pubkey scanner success.
  assert.equal(utxoCore.parseUtxosJson('[{"amount":"1"}]')[0].amount,1n);
  const ties=[{amount:'2',tx_id:'b',index:0},{amount:'2',tx_id:'a',index:2},{amount:'2',tx_id:'a',index:1}]; utxoCore.sortUtxosLargestFirst(ties); assert.deepEqual(ties.map(u=>u.index),[1,2,0]);
  state.covenantState.lastCovenantResult={type:'merkle-whitelist'}; state.covenantState.activeCovenants=[]; stubs.fetch_utxos_for_address_js=()=> '[]'; await element('btn-cov-mw-spend').onclick(); assert.equal(element('cov-mw-addr').value,''); assert.equal(element('cov-mw-script').value,''); assert.equal(element('cov-mw-amount').placeholder,'e.g. 5.0');
  state.covenantState.lastCovenantResult={type:'merkle-whitelist',address:ADDRESS,redeem_script_hex:'51'}; stubs.fetch_utxos_for_address_js=()=>{throw new Error('offline')}; await element('btn-cov-mw-spend').onclick(); assert.equal(element('cov-mw-amount').placeholder,'e.g. 5.0');
  stubs.decode_address=()=>JSON.stringify({payload:PK}); pubkeyScanning.covScanPubkey('scan-pub','',false); state.scannerState.scanCallback(new TextEncoder().encode(PK)); assert.match(element('toast').textContent,/Address scanned/);

  // Shell's optional-element guards are deliberate: exercise them through the
  // registered handlers rather than weakening the null-safe UI boundary.
  const shellGet=document.getElementById.bind(document); shell.bindShellControls();
  document.getElementById=id=>id==='gear-menu'?null:shellGet(id); await element('btn-header-settings').onclick(); document.getElementById=shellGet;
  element('screen-donate').dataset.returnScreen=''; element('btn-donate-skip').onclick();
  document.getElementById=id=>id==='toast'?null:shellGet(id); await element('btn-copy-donate').onclick(); document.getElementById=shellGet;
  document.getElementById=id=>id==='btn-copy-donate'?null:shellGet(id); shell.bindShellControls(); document.getElementById=shellGet;

  // Oracle response-kind and recovery-import reentrancy/error-finalization paths.
  const sigHex=covenantSignProtocol.covenantSignatureResponseHex({sessionId:'01'.repeat(16),keyId:'02'.repeat(32),pubkey:'03'.repeat(32),bindingToken:'04'.repeat(32),commitment:'05'.repeat(32),noncePoint:`02${'06'.repeat(32)}`,signature:'07'.repeat(64)});
  const nonceBytes=Buffer.from(sigHex,'hex'); nonceBytes[5]=1; nonceBytes.fill(0,183,247); assert.throws(()=>oracleAttestation.parseOracleV1Attestation(nonceBytes),/Expected a covenant-signature/);
  state.scannerState._covbImporting=true; assert.equal(await recoveryImport.handleCovenantScan(new Uint8Array([1,2,3])),false); state.scannerState._covbImporting=false; assert.equal(await recoveryImport.handleCovenantScan(new Uint8Array([1,2,3])),false); assert.equal(state.scannerState._covbImporting,false);

  // Keep the aggregate runtime branch ratchet comfortably above its floor on
  // both Windows and POSIX V8 builds. These are real production boundary paths,
  // not coverage ignores: signer capability parsing, image-QR session handling,
  // and the escrow watcher state machine/fetch fallbacks.
  const oldLimits = stubs.kassigner_sdk_limits;
  stubs.kassigner_sdk_limits = () => JSON.stringify({ maxInputs: 64 });
  assert.equal(signerLimits.signerMaxInputs(), 64);
  stubs.kassigner_sdk_limits = () => JSON.stringify({ maxInputs: 0 });
  assert.equal(signerLimits.signerMaxInputs(), 32);
  stubs.kassigner_sdk_limits = () => { throw new Error('limits unavailable'); };
  assert.equal(signerLimits.signerMaxInputs(), 32);
  stubs.kassigner_sdk_limits = oldLimits;

  const oldBitmap = globalThis.createImageBitmap;
  const oldJsQr = globalThis.jsQR;
  globalThis.createImageBitmap = async () => ({ width: 2, height: 2, close() {} });
  globalThis.jsQR = () => ({ data: wallet.kpub });
  assert.deepEqual(await kpubImage.decodeKpubQrImage({ size: 8, type: 'image/png' }), { kind: 'text', payload: wallet.kpub });
  const oldDecodeFrame = stubs.decode_qr_frame;
  const oldResetDecoder = stubs.reset_qr_decoder;
  globalThis.jsQR = () => ({ data: 'signed-frame' });
  stubs.decode_qr_frame = () => '';
  assert.equal(await signedImage.importSignedQrImage({ size: 8, type: 'image/png' }), false);
  stubs.decode_qr_frame = () => '50534b42' + '00'.repeat(8);
  assert.equal(await signedImage.importSignedQrImage({ size: 8, type: 'image/png' }), true);
  globalThis.jsQR = () => null;
  assert.equal(await signedImage.importSignedQrImage({ size: 8, type: 'image/png' }), null);
  globalThis.jsQR = () => ({ binaryData: Uint8Array.from([1, 2, 3]), data: '' });
  stubs.decode_qr_frame = () => '';
  assert.equal(await signedImage.importSignedQrImage({ size: 8, type: 'image/png' }), false);
  globalThis.jsQR = () => ({ binaryData: new Uint8Array(), data: '' });
  assert.equal(await signedImage.importSignedQrImage({ size: 8, type: 'image/png' }), null);
  stubs.reset_qr_decoder = () => { throw new Error('decoder already reset'); };
  signedImage.resetSignedQrImageImportSession();
  stubs.decode_qr_frame = oldDecodeFrame;
  stubs.reset_qr_decoder = oldResetDecoder;
  if (oldBitmap === undefined) delete globalThis.createImageBitmap; else globalThis.createImageBitmap = oldBitmap;
  if (oldJsQr === undefined) delete globalThis.jsQR; else globalThis.jsQR = oldJsQr;

  const escrowStatus = element('runtime-escrow-status');
  state.covenantState.lastCovenantResult = { type:'escrow', address:ADDRESS, alice_pk:PK, bob_pk:PK2, arbiter_pk:PK3 };
  state.covenantState.activeCovenants = [];
  state.covenantWatcherState._covWatcherLastBalance = 1n;
  assert.equal(await escrowController.pollEscrow({ total:0n, kas:0, st:escrowStatus, utxos:[] }), false);
  assert.equal(state.covenantState.lastCovenantResult._escrowResolved, true);
  state.covenantState.lastCovenantResult._escrowResolved = false;
  state.covenantWatcherState._covWatcherLastBalance = 0n;
  assert.equal(await escrowController.pollEscrow({ total:0n, kas:0, st:escrowStatus, utxos:[] }), false);
  assert.match(escrowStatus.textContent, /Awaiting deposit/);
  assert.equal(await escrowController.pollEscrow({ total:1n, kas:1, st:escrowStatus, utxos:[{tx_id:'first'}] }), false);
  setFetchHook(async () => response({ json:{ payload:'455343440001' } }));
  assert.equal(await escrowController.pollEscrow({ total:1n, kas:1, st:escrowStatus, utxos:[{tx_id:'second'}] }), false);
  assert.equal(state.covenantState.lastCovenantResult._escrowDisputeRole, 'buyer');
  state.covenantState.lastCovenantResult._escrowResolved = true;
  escrowState.beginEscrowCycle('restart');
  assert.equal(state.covenantState.lastCovenantResult._escrowResolved, false);
  escrowState.saveEscrowDispute('checked', null);
  assert.equal(state.covenantState.lastCovenantResult._escrowPayloadChecked, 'checked');
  assert.equal(await escrowController.pollEscrow({ total:1n, kas:1, st:escrowStatus, utxos:[] }), false);
  state.covenantState.lastCovenantResult._escrowResolved = true;
  escrowRender.renderEscrowEmpty(escrowStatus);
  assert.match(escrowStatus.innerHTML, /Escrow resolved/);
  state.covenantState.lastCovenantResult._escrowDisputed = true;
  state.covenantState.lastCovenantResult._escrowDisputeRole = null;
  escrowRender.renderEscrowFunded(escrowStatus, 1);
  assert.match(escrowStatus.innerHTML, /party/);
  setFetchHook(async () => response({ json:{ payload:'455343440002' } }));
  assert.equal(await escrowFetch.fetchEscrowDispute('seller'), 'seller');
  setFetchHook(async () => response({ status:500, json:{} }));
  assert.equal(await escrowFetch.fetchEscrowDispute('third'), null);
  setFetchHook(async () => response({ json:{ payload:'not-escrow' } }));
  assert.equal(await escrowFetch.fetchEscrowDispute('third'), null);
  setFetchHook(async () => { throw new Error('offline'); });
  assert.equal(await escrowFetch.fetchEscrowDispute('third'), null);

  state.walletSession.replace(structuredClone(wallet));
  console.log('PASS: final aggregate branch-hardening vectors');
} finally {
  document.getElementById = originalGet;
  await cleanupDeepHarness();
}
