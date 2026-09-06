import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setFetchHook,
  ADDRESS, CHANGE, EXTERNAL, PK, TXID, TXID2, PSKB, wallet, utxos, psktSummary,
  assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state, response } = await setupDeepHarness();
try {
  const wasm=globalThis.__KASSEE_WASM_STUBS__;
  const consolidation=await import(moduleUrl('features/wallet/tools/consolidation.js'));
  const views=await import(moduleUrl('features/wallet/tools/address_views.js'));
  const history=await import(moduleUrl('features/wallet/core/history.js'));
  const addrState=await import(moduleUrl('features/wallet/core/address_state.js'));
  wasm.pskt_summary=()=>JSON.stringify(psktSummary());

  // Consolidation button state is derived from both wallet size and selection.
  state.transactionState.consolidateSelection=new Set();
  consolidation.updateConsolidateButtons(1); assert.equal(element('btn-consolidate').style.display,'none');
  consolidation.updateConsolidateButtons(3); assert.equal(element('btn-consolidate').style.display,'');
  state.transactionState.consolidateSelection=new Set([0,1]); consolidation.updateConsolidateButtons(3);
  assert.match(element('btn-consolidate-selected').textContent,/2 Selected/);

  // Automatic and selected consolidation success/error/insufficient routes.
  wasm.create_consolidate_pskb=()=>PSKB; await consolidation.handleConsolidate(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  wasm.create_consolidate_pskb=()=>{throw new Error('consolidate offline');}; await consolidation.handleConsolidate(); assert.match(element('toast').textContent,/Consolidation failed/i);
  wasm.create_consolidate_pskb=()=>PSKB;
  state.transactionState.consolidateSelection=new Set([0]); await consolidation.handleConsolidateSelected();
  state.transactionState.consolidateSelection=new Set([0,1]); state.networkState.cachedUtxos=[{...utxos[0],amount:'1'},{...utxos[1],amount:'1'}];
  await consolidation.handleConsolidateSelected(); assert.match(element('toast').textContent,/too small/i);
  state.networkState.cachedUtxos=structuredClone(utxos); state.transactionState.consolidateSelection=new Set([0,1]);
  wasm.create_send_pskb_selected=()=>PSKB; await consolidation.handleConsolidateSelected(); assert.equal(state.transactionState._psktReviewHex,PSKB);
  wasm.create_send_pskb_selected=()=>{throw new Error('selected offline');}; await consolidation.handleConsolidateSelected(); assert.match(element('toast').textContent,/Consolidation failed/i);
  wasm.create_send_pskb_selected=()=>PSKB;

  // UTXO change tracking: first snapshot, incoming, outgoing with address use
  // recognition, no-wallet spent path, and bounded history.
  state.walletState.historyEntries=[]; state.networkState.utxoSnapshot=null;
  consolidation.trackUtxoChangesAndUsed(structuredClone(utxos)); assert.equal(state.walletState.historyEntries.length,2);
  const spk=[0x20,...Array.from(Buffer.from(PK,'hex')),0xAC];
  wasm.decode_address=()=>JSON.stringify({payload:PK,version:0});
  state.networkState.utxoSnapshot=[{...utxos[0],script_public_key:spk}];
  const incoming={...utxos[1],tx_id:'dd'.repeat(32),index:3};
  consolidation.trackUtxoChangesAndUsed([incoming]);
  assert.ok(state.walletState.historyEntries.some(x=>x.type==='in'));
  assert.ok(state.walletState.historyEntries.some(x=>x.type==='out'));
  assert.ok(state.walletState.usedReceiveIndices.has(0) || state.walletState.usedChangeIndices.has(0));
  const saved=state.walletSession.current(); state.walletSession.clear(); state.networkState.utxoSnapshot=[utxos[0]];
  consolidation.trackUtxoChangesAndUsed([]); assert.equal(state.walletState.historyEntries[0].type,'out');
  state.walletSession.replace(saved);
  state.walletState.historyEntries=Array.from({length:110},(_,i)=>({type:'in',amount:1n,tx_id:String(i),index:0,time:i}));
  state.networkState.utxoSnapshot=[]; consolidation.trackUtxoChangesAndUsed([]); assert.equal(state.walletState.historyEntries.length,100);

  // Address list rendering covers funded/used/plain rows; custom query nodes
  // exercise copy, verify QR, and explorer branches without parsing HTML.
  state.walletState.fundedReceiveIndices=[0]; state.walletState.usedReceiveIndices=new Set([1]);
  state.walletState.fundedChangeIndices=[0]; state.walletState.usedChangeIndices=new Set([1]);
  const oldQsa=document.querySelectorAll.bind(document);
  const copyIcon=element('copy-icon-runtime'); const addrVal=element('addr-val-runtime'); addrVal.textContent=ADDRESS;
  const row=element('addr-row-runtime'); row.dataset.addr='1-r'; row.querySelector=sel=>sel==='.copy-icon'?copyIcon:sel==='.addr-val'?addrVal:null;
  const explorer=element('explorer-runtime');
  document.querySelectorAll=sel=>sel==='.addr-item'?[row]:sel==='.addr-explore'?[explorer]:oldQsa(sel);
  views.showAddresses(); assert.match(element('address-list').innerHTML,/funded/); assert.match(element('address-list').innerHTML,/used/);
  assert.doesNotThrow(()=>copyIcon.onclick({stopPropagation(){}})); assert.equal(copyIcon.textContent,'⧉');
  wasm.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>address</svg>'}]); row.onclick();
  assert.match(element('verify-path').textContent,/\/0\/1/); assert.match(element('verify-qr').innerHTML,/address/);
  wasm.generate_qr_frames=()=>{throw new Error('qr fail');}; row.onclick(); assert.equal(element('verify-qr').innerHTML,'');
  document.querySelectorAll=oldQsa;

  // Manual coin control uses an independent REST enumeration before wRPC.
  // Preserve all distinct outpoints across receive/change addresses, dedupe an
  // exact duplicate, and reject conflicting duplicate data.
  const coinControl=await import(moduleUrl('features/wallet/core/coin_control_utxos.js'));
  const restEntry=(address,txid,index,amount,daa='950')=>({
    address, outpoint:{transactionId:txid,index},
    utxoEntry:{amount:String(amount),blockDaaScore:String(daa),isCoinbase:false,scriptPublicKey:{scriptPublicKey:'000051',version:0}},
  });
  const restRows=[
    restEntry(ADDRESS,TXID,0,'250000000'),
    restEntry(CHANGE,TXID2,1,'150000000'),
    restEntry(wallet.receive_addresses[1],'cc'.repeat(32),2,'100000000'),
    restEntry(ADDRESS,TXID,0,'250000000'),
  ];
  setFetchHook(async (url,options)=>{ assert.match(String(url),/\/addresses\/utxos$/); assert.equal(options.method,'POST'); return response({json:restRows}); });
  const complete=await coinControl.fetchRestCoinControlUtxos();
  assert.equal(complete.source,'REST'); assert.equal(complete.scannedAddresses,6); assert.equal(complete.utxos.length,3);
  assert.deepEqual(complete.utxos.map(u=>u.amount),['250000000','150000000','100000000']);
  await views.showUtxos(); assert.match(element('utxo-summary').textContent,/3 current UTXOs .* REST/); assert.match(element('utxo-list').innerHTML,/2\.50000000 KAS/);
  setFetchHook(async()=>response({json:[restEntry(ADDRESS,TXID,0,'250000000'),restEntry(ADDRESS,TXID,0,'250000001')]}));
  await assert.rejects(()=>coinControl.fetchRestCoinControlUtxos(),/conflicting data/);

  // Existing screen fallbacks remain fail-safe when REST is unavailable/malformed.
  setFetchHook(async()=>response({json:{}}));

  // UTXO screen: empty, populated with selectable rows (including the
  // signer capability ceiling), and fetch failure.
  wasm.fetch_utxos_complete=()=> '[]'; await views.showUtxos(); assert.match(element('utxo-list').innerHTML,/No UTXOs/);
  const itemNodes=Array.from({length:33},(_,i)=>{const n=element('utxo-item-'+i); n.dataset.utxoIdx=String(i); const chk=element('chk-'+i); n.querySelector=()=>chk; return n;});
  document.querySelectorAll=sel=>sel==='.utxo-selectable'?itemNodes:[];
  const many=Array.from({length:33},(_,i)=>({...utxos[i%2],tx_id:(i.toString(16).padStart(2,'0')).repeat(32),index:i,amount:String(100000000+i)}));
  wasm.fetch_utxos_complete=()=>JSON.stringify(many); await views.showUtxos(); assert.match(element('utxo-summary').textContent,/33 current UTXOs/);
  for(let i=0;i<32;i++) itemNodes[i].onclick(); assert.equal(state.transactionState.consolidateSelection.size,32);
  itemNodes[32].onclick(); assert.match(element('toast').textContent,/at most 32 selected inputs/);
  itemNodes[0].onclick(); assert.equal(state.transactionState.consolidateSelection.size,31);
  wasm.fetch_utxos_complete=()=>{throw new Error('utxo offline');}; await views.showUtxos(); assert.match(element('toast').textContent,/Failed to fetch UTXOs/i);
  document.querySelectorAll=oldQsa;

  // Default and custom history services: default positive counts; custom
  // /full path; custom transaction-list fallback; unavailable API.
  state.walletState.usedReceiveIndices=new Set(); state.walletState.usedChangeIndices=new Set(); state.walletState.addressHistoryEnabled=false; state.networkState.customRestUrl=null;
  setFetchHook(async()=>response({json:{total:1}})); await history.fetchAddressHistory(); assert.ok(state.walletState.usedReceiveIndices.size>0);
  state.walletState.addressHistoryEnabled=true; state.networkState.customRestUrl='https://runtime-history'; state.walletState.usedReceiveIndices=new Set(); state.walletState.usedChangeIndices=new Set();
  setFetchHook(async url=>response({json:{tx_count:1,transactions:[{}]}})); await history.fetchAddressHistory(); assert.ok(state.walletState.usedReceiveIndices.size>0);
  state.walletState.usedReceiveIndices=new Set(); state.walletState.usedChangeIndices=new Set(); let first=true;
  setFetchHook(async url=>{ if(first){first=false; return response({status:404,json:{}});} return response({json:[{}]}); });
  await history.fetchAddressHistory(); assert.ok(state.walletState.usedReceiveIndices.size>0);
  state.networkState.network='devnet'; state.walletState.addressHistoryEnabled=false; state.networkState.customRestUrl=null; await assert.rejects(() => history.fetchAddressHistory(), /No public Kaspa REST endpoint configured for devnet/);
  state.networkState.network='mainnet';

  // Gap expansion: nothing needed, receive-only/change-only/both, failure,
  // and fresh index materialization.
  state.walletSession.replace(structuredClone(wallet)); state.walletState.fundedReceiveIndices=[]; state.walletState.usedReceiveIndices=new Set(); state.walletState.fundedChangeIndices=[]; state.walletState.usedChangeIndices=new Set();
  assert.equal(addrState.expandAddressesIfNeeded(),false);
  state.walletState.fundedReceiveIndices=[0,1,2]; state.walletState.usedReceiveIndices=new Set();
  wasm.extend_addresses=(json,r,c)=>JSON.stringify({...JSON.parse(json),receive_addresses:[...wallet.receive_addresses,...Array.from({length:r},(_,i)=>`kaspa:extra-r-${i}`)]});
  assert.equal(addrState.expandAddressesIfNeeded(),true);
  state.walletSession.replace(structuredClone(wallet)); state.walletState.fundedReceiveIndices=[0,1,2]; state.walletState.fundedChangeIndices=[0,1,2];
  wasm.extend_addresses=()=>{throw new Error('derive fail');}; assert.equal(addrState.expandAddressesIfNeeded(),false);
  wasm.extend_addresses=json=>json; state.walletSession.replace(structuredClone(wallet)); state.walletState.fundedReceiveIndices=[0]; state.walletState.fundedChangeIndices=[0];
  const fresh=JSON.parse(addrState.walletWithFreshIndices()); assert.ok(Number.isInteger(fresh.next_receive_index)); assert.ok(Number.isInteger(fresh.next_change_index));
  assert.ok(addrState.getNextReceiveIndex()>=0);

  assertWatchOnlyStorage();
  console.log('PASS: deep wallet consolidation/address/history/gap paths');
} finally { await cleanupDeepHarness(); }
