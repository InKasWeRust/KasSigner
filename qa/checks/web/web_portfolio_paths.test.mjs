import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { FakeElement } from './web_recovery_test_harness.mjs';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setFetchHook, wallet,
} from './web_runtime_deep_harness.mjs';

const { state, response } = await setupDeepHarness();
const originalCreateElementNS = document.createElementNS;
const originalCreateFragment = document.createDocumentFragment;
const originalFormData = globalThis.FormData;
try {
  document.createElementNS = (_ns, tag) => new FakeElement(tag);
  document.createDocumentFragment = () => new FakeElement('fragment');
  globalThis.FormData = class {
    constructor(form) { this.values = form._formData || {}; }
    get(name) { return this.values[name] ?? null; }
  };

  const money = await import(moduleUrl('features/portfolio/exact_money.js'));
  const calc = await import(moduleUrl('features/portfolio/calculations.js'));
  const csv = await import(moduleUrl('features/portfolio/csv.js'));
  const repo = await import(moduleUrl('features/portfolio/repository.js'));
  const pricing = await import(moduleUrl('features/portfolio/pricing.js'));
  const render = await import(moduleUrl('features/portfolio/render.js'));
  const history = await import(moduleUrl('features/portfolio/wallet_history.js'));
  const controller = await import(moduleUrl('features/portfolio/controller.js'));

  // Exact monetary paths never route KAS or USD through binary floating point.
  assert.equal(money.decimalToScaled('12.345', 3), 12345n);
  assert.throws(() => money.decimalToScaled('1.2345', 3), /at most 3/);
  assert.throws(() => money.parseKas('-1'), /non-negative/);
  assert.equal(money.usdToMicro('0.123456'), 123456n);
  assert.equal(money.microToUsd(1_234_567n, 2), '1.23');
  assert.equal(money.microToUsd(2_000_000n, 0), '2');
  assert.equal(money.formatUsd(1_234_567n), '$1.23');
  assert.equal(money.formatKas('123456789'), '1.23456789');
  assert.equal(money.kasValueMicro(100_000_000n, 123456n), 123456n);
  assert.equal(money.proportionalCost(1000n, 2n, 4n), 500n);
  assert.equal(money.proportionalCost(1000n, 0n, 4n), 0n);

  const store = { schema: 1, accounts: [], transactions: [] };
  const account = repo.createAccount(store, ' Main Wallet ');
  assert.equal(account.name, 'Main Wallet');
  repo.renameAccount(store, account.id, 'Long Term');
  assert.equal(store.accounts[0].name, 'Long Term');
  assert.throws(() => repo.createAccount(store, '  '), /required/);
  assert.throws(() => repo.renameAccount(store, 'missing', 'x'), /not found/);

  const entries = [
    { id:'a', portfolioId:account.id, type:'Buy', kasSompi:'10000000000', priceMicroUsd:'100000', feeMicroUsd:'0', timestampMs:1, createdAt:1, notes:'buy, \"quoted\"\nline two', sourceTxId:null },
    { id:'b', portfolioId:account.id, type:'Sell', kasSompi:'2500000000', priceMicroUsd:'200000', feeMicroUsd:'0', timestampMs:2, createdAt:2, notes:'sell', sourceTxId:null },
    { id:'c', portfolioId:account.id, type:'Transfer In', kasSompi:'100000000', priceMicroUsd:'0', feeMicroUsd:'0', timestampMs:3, createdAt:3, notes:'in', sourceTxId:'chain-c' },
    { id:'d', portfolioId:account.id, type:'Transfer Out', kasSompi:'50000000', priceMicroUsd:'0', feeMicroUsd:'0', timestampMs:4, createdAt:4, notes:'out', sourceTxId:null },
  ];
  for (const entry of entries) repo.upsertTransaction(store, entry);
  assert.equal(repo.importedTxIds(store, account.id).has('chain-c'), true);
  const summary = calc.holdingSummary(store.transactions);
  assert.equal(summary.holdings, 7_550_000_000n);
  assert.equal(calc.holdingsAt(store.transactions, 2), 7_500_000_000n);
  assert.equal(calc.portfolioValueMicro(store.transactions, 200000n), 15_100_000n);
  assert.equal(calc.chartValues(store.transactions, [{timestampMs:2,priceMicroUsd:200000n}])[0].valueMicroUsd, 15_000_000n);

  const encoded = csv.exportPortfolioCsv(store.transactions);
  const decoded = csv.parsePortfolioCsv(encoded, account.id);
  assert.equal(decoded.length, 4);
  assert.equal(decoded[0].kasSompi, entries[0].kasSompi);
  assert.equal(decoded[0].notes, entries[0].notes);
  assert.deepEqual(csv.parsePortfolioCsv('', account.id), []);
  assert.throws(() => csv.parsePortfolioCsv('type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\nBuy,1,1,0,2026-01-01T00:00:00Z,\"unterminated,\n', account.id), /unterminated/);
  assert.throws(() => csv.parsePortfolioCsv('type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\nBuy,1,1,0,2026-01-01T00:00:00Z\n', account.id), /fields/);
  assert.throws(() => csv.parsePortfolioCsv('type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\nBuy,1,1,0,not-a-date,,\n', account.id), /Invalid transaction timestamp/);
  const crlf = 'type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\r\nBuy,1,,,2026-01-01T00:00:00Z,,\r\n';
  assert.equal(csv.parsePortfolioCsv(crlf, account.id)[0].priceMicroUsd, '0');
  assert.match(csv.exportPortfolioCsv([{...entries[0], feeMicroUsd:null, notes:null, sourceTxId:null}]), /Buy/);
  assert.throws(() => csv.parsePortfolioCsv('bad,header\n', account.id), /CSV header/);
  assert.throws(() => csv.parsePortfolioCsv('type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\nUnknown,1,1,0,2026-01-01T00:00:00Z,,\n', account.id), /Unsupported/);

  // Pricing accepts high-precision provider/CSV decimals and rounds only at the
  // explicit fixed-point micro-USD boundary.
  const bundled = await fs.readFile(path.resolve('apps/kassee-web/web/data/kaspa_daily_usd.csv'), 'utf8');
  let currentCalls = 0;
  setFetchHook(async url => {
    const value = String(url);
    if (value.includes('simple/price')) { currentCalls += 1; return response({ text:'{"kaspa":{"usd":0.123456789123}}' }); }
    if (value.includes('market_chart')) return response({ text:'{"prices":[[1700000000000,1.23456789e-1],[1700086400000,1.23456789e+1],[1700172800000,1.23456789e+3],[1700259200000,2]]}' });
    if (value.includes('kaspa_daily_usd.csv')) return response({ text:bundled });
    return response({ status:404, text:'{}' });
  });
  assert.equal(await pricing.fetchCurrentPriceMicro(), 123457n);
  assert.equal(currentCalls, 1);
  const historical = await pricing.loadHistoricalPrices(30);
  assert.ok(historical.length > 2);
  assert.ok(pricing.historicalPriceAt(historical, historical[0].timestampMs) > 0n);
  assert.equal(pricing.historicalPriceAt([], Date.now()), 0n);
  const linear=[{timestampMs:0,priceMicroUsd:100n},{timestampMs:10,priceMicroUsd:200n},{timestampMs:20,priceMicroUsd:100n}];
  assert.equal(pricing.historicalPriceAt(linear,-1),100n);
  assert.equal(pricing.historicalPriceAt(linear,5),150n);
  assert.equal(pricing.historicalPriceAt(linear,15),150n);
  assert.equal(pricing.historicalPriceAt(linear,25),100n);

  // Provider fallback remains deterministic.
  setFetchHook(async url => String(url).includes('simple/price')
    ? response({ status:500, text:'no' })
    : response({ text:'{"quotes":{"USD":{"price":0.1111114}}}' }));
  assert.equal(await pricing.fetchCurrentPriceMicro(), 111111n);
  setFetchHook(async url => String(url).includes('market_chart') ? response({status:503,text:'offline'}) : response({text:'{}'}));
  assert.ok((await pricing.loadHistoricalPrices(7)).length >= 0);
  setFetchHook(async () => response({text:'{}'}));
  await assert.rejects(() => pricing.fetchCurrentPriceMicro(), /missing/);

  // Historical discovery proves old fully-spent addresses by transaction-count
  // gap scanning, then paginates the full transaction endpoint. Exact sompi
  // fields arrive as quoted decimal strings before JSON.parse.
  state.walletSession.replace(structuredClone(wallet));
  globalThis.__KASSEE_WASM_STUBS__.extend_addresses = (json, receiveCount, changeCount) => {
    const data = JSON.parse(json);
    const add = (list, count, prefix) => [
      ...list,
      ...Array.from({length:count}, (_, index) => `kaspa:${prefix}-${list.length + index}`),
    ];
    data.receive_addresses = add(data.receive_addresses, receiveCount, 'portfolio-r');
    data.change_addresses = add(data.change_addresses, changeCount, 'portfolio-c');
    return JSON.stringify(data);
  };
  const owner = wallet.receive_addresses[0];
  let historyPages = 0;
  let ownerCountAttempts = 0;
  setFetchHook(async url => {
    const value = String(url);
    if (value.includes('/transactions-count')) {
      if (value.includes(`/addresses/${owner}/transactions-count`)) {
        ownerCountAttempts += 1;
        if (ownerCountAttempts === 1) return response({ status:429, text:'rate limited' });
        return response({ text:'{"total":"1"}' });
      }
      return response({ text:'{"total":"0"}' });
    }
    if (value.includes('/full-transactions-page')) {
      historyPages += 1;
      const first = historyPages === 1;
      const transactions = first ? [{
        transaction_id:'ab'.repeat(32), accepting_block_time:1700000000,
        inputs:[{previous_outpoint_address:'kaspa:external',previous_outpoint_amount:201000000}],
        outputs:[{script_public_key_address:owner,amount:200000000}],
      }, {
        transaction_id:'00'.repeat(32), accepting_block_time:0,
        inputs:[{previous_outpoint_address:owner,previous_outpoint_amount:100000000}],
        outputs:[{script_public_key_address:wallet.change_addresses[0],amount:100000000}],
      }, {
        transaction_id:'11'.repeat(32), accepting_block_time:'invalid',
        outputs:[{script_public_key_address:owner,amount:1000000}],
      }, {
        transaction_id:'22'.repeat(32), block_time:1700000002,
        inputs:[{previous_outpoint_address:owner,previous_outpoint_amount:1000000}],
      }, { transaction_id:'', inputs:[], outputs:[] }] : [{
        transaction_id:'cd'.repeat(32), accepting_block_time:1700000000001,
        inputs:[{previous_outpoint_address:owner,previous_outpoint_amount:201000000}],
        outputs:[{script_public_key_address:'kaspa:external',amount:200000000}],
      }, {
        transaction_id:'ef'.repeat(32), accepting_block_time:1700000001,
        inputs:[{previous_outpoint_address:'kaspa:external',previous_outpoint_amount:100000000}],
        outputs:[{script_public_key_address:owner,amount:101000000}],
      }];
      return {
        ...response({ text: JSON.stringify(transactions) }),
        headers:{ get(name) { return name === 'X-Next-Page-Before' && first ? 'cursor-1' : null; } },
      };
    }
    if (value.includes('kaspa_daily_usd.csv')) return response({ text:bundled });
    return response({ status:404, text:'{}' });
  });
  const historyStore = { schema:1, accounts:[{id:'p',name:'P'}], transactions:[] };
  const deepFetch = await history.fetchWalletHistory(historyStore, 'p');
  const imported = deepFetch.entries;
  assert.equal(deepFetch.mode, 'deep');
  assert.equal(imported.length, 5);
  assert.equal(imported[0].kasSompi, '200000000');
  assert.ok(imported.every(entry => BigInt(entry.feeMicroUsd) >= 0n));
  assert.ok(imported.some(entry => entry.type === 'Transfer Out'));
  assert.ok(imported.some(entry => entry.sourceTxId === 'ab'.repeat(32)));
  assert.equal(historyPages, 2);
  historyStore.transactions.push(...imported);
  historyStore.accounts[0].walletHistory = deepFetch.sync;
  const incrementalFetch = await history.fetchWalletHistory(historyStore, 'p');
  assert.equal(incrementalFetch.mode, 'incremental');
  assert.equal(incrementalFetch.entries.length, 0);
  assert.equal(incrementalFetch.sync.network, state.networkState.network);
  assert.equal(incrementalFetch.sync.kpub, state.walletSession.kpub());
  state.walletSession.clear();
  await assert.rejects(() => history.discoverHistoricalWalletAddresses(), /Load a kpub/);
  state.walletSession.replace(structuredClone(wallet));
  state.networkState.network='devnet';
  await assert.rejects(() => history.discoverHistoricalWalletAddresses(), /No public Kaspa REST endpoint/);
  state.networkState.network='mainnet';
  state.walletSession.replace(structuredClone(wallet));
  setFetchHook(async () => response({status:500,text:'fail'}));
  await assert.rejects(() => history.fetchWalletHistory({schema:1,accounts:[{id:'p',name:'P'}],transactions:[]}, 'p'), /HTTP 500/);
  let badPageCount=0;
  setFetchHook(async url => {
    const value=String(url);
    if(value.includes('/transactions-count')) return response({text:value.includes(`/addresses/${owner}/transactions-count`) ? '{"total":"1"}' : '{"total":"0"}'});
    if(value.includes('/full-transactions-page')) { badPageCount += 1; return response({text:'{}'}); }
    return response({status:404,text:'{}'});
  });
  await assert.rejects(() => history.fetchWalletHistory({schema:1,accounts:[{id:'p',name:'P'}],transactions:[]}, 'p'), /history page is not an array/);
  assert.equal(badPageCount,1);

  localStorage.setItem('kassee-portfolio-v1', '{broken');
  assert.equal(repo.loadPortfolioStore().accounts.length, 0);
  localStorage.setItem('kassee-portfolio-v1', JSON.stringify({schema:999,accounts:[1],transactions:[1]}));
  assert.equal(repo.loadPortfolioStore().accounts.length, 0);
  localStorage.setItem('kassee-portfolio-v1', JSON.stringify({schema:1,accounts:null,transactions:null}));
  assert.equal(repo.loadPortfolioStore().transactions.length, 0);

  // Render all portfolio visual states with the shared DOM primitives used by
  // web/iOS/Android shells. No browser-native prompt/confirm is involved.
  const renderState = {
    store,
    selectedAccountId: account.id,
    mode:'overview', rangeDays:90, livePriceMicro:200000n,
    historicalPrices:[{timestampMs:1,priceMicroUsd:100000n},{timestampMs:4,priceMicroUsd:200000n}],
    editorOpen:true, editingEntry:entries[0], accountEditorMode:'rename',
    pendingDeleteAccountId:null, pendingDeleteTransactionId:null,
    visibleEntries(){ return this.store.transactions.filter(entry => entry.portfolioId === this.selectedAccountId); },
  };
  const root = new FakeElement('div');
  render.renderPortfolio(root, renderState);
  assert.ok(root.children.length > 3);
  renderState.editorOpen=false; renderState.accountEditorMode=null; renderState.pendingDeleteTransactionId='a'; renderState.mode='transactions';
  render.renderPortfolio(root, renderState);
  assert.ok(root.children.length > 3);
  renderState.pendingDeleteTransactionId=null; renderState.pendingDeleteAccountId=account.id;
  render.renderPortfolio(root, renderState);
  assert.ok(root.children.length > 3);

  // Exercise controller event ownership: shared inline account UI, transaction
  // editor, mode/range controls, and custom delete confirmation.
  const portfolioRoot = element('portfolio-root');
  controller.bindPortfolioEvents();
  const action = value => {
    const target = new FakeElement('button');
    target.dataset.action=value;
    target.closest=()=>target;
    portfolioRoot.dispatch('click',{target,preventDefault(){}});
  };
  const submit = (kind, values, transactionId='') => {
    const form = new FakeElement('form');
    form.dataset.action=kind;
    form.dataset.transactionId=transactionId;
    form._formData=values;
    portfolioRoot.dispatch('submit',{target:form,preventDefault(){}});
  };
  // Submit buttons are owned explicitly by the portfolio controller. A real
  // Save click must persist even when a browser/webview does not synthesize
  // a default submit event. Enter/form-submit remains covered below.
  setFetchHook(async url => {
    const value=String(url);
    if(value.includes('simple/price')) return response({text:'{"kaspa":{"usd":0.15}}'});
    if(value.includes('market_chart')) return response({text:'{"prices":[[1767225600000,0.15]]}'});
    if(value.includes('/transactions-count')) return response({text:'{"total":"0"}'});
    return response({status:404,text:'{}'});
  });
  controller.showPortfolio();
  await new Promise(resolve=>setImmediate(resolve));
  action('new-account');
  submit('account-form',{name:''});
  const accountForm = new FakeElement('form');
  accountForm.dataset.action='account-form';
  accountForm._formData={name:'Runtime Portfolio'};
  const accountSave = new FakeElement('button');
  accountSave.type='submit';
  accountSave.dataset.action='submit-account';
  accountSave.parentElement=accountForm;
  accountSave.closest=()=>accountSave;
  let accountSavePrevented=false;
  portfolioRoot.dispatch('click',{target:accountSave,preventDefault(){accountSavePrevented=true;}});
  assert.equal(accountSavePrevented,true);
  assert.equal(JSON.parse(localStorage.getItem('kassee-portfolio-v1')).accounts[0].name,'Runtime Portfolio');
  action('rename-account');
  submit('account-form',{name:'Runtime Renamed'});
  action('new-transaction');
  submit('transaction-form',{type:'Buy',kasAmount:'1.25',priceUsd:'0.10',feeUsd:'0',timestamp:'bad',notes:'runtime'});
  submit('transaction-form',{type:'Buy',kasAmount:'1.25',priceUsd:'0.10',feeUsd:'0',timestamp:'2026-01-01T00:00',notes:'runtime'});
  const runtimeStore=JSON.parse(localStorage.getItem('kassee-portfolio-v1'));
  const runtimeTx=runtimeStore.transactions[0];
  action(`edit:${runtimeTx.id}`);
  submit('transaction-form',{type:'Sell',kasAmount:'0.25',priceUsd:'0.20',feeUsd:'0.01',timestamp:'2026-01-02T00:00',notes:'edited'},runtimeTx.id);
  action('mode:transactions');
  action(`delete:${runtimeTx.id}`);
  action('cancel-inline-action');
  action(`delete:${runtimeTx.id}`);
  action('confirm-transaction-delete');
  action('mode:overview');
  action('range:7');
  await new Promise(resolve=>setImmediate(resolve));
  action('refresh-price');
  await new Promise(resolve=>setImmediate(resolve));
  action('fetch-wallet-history');
  await new Promise(resolve=>setImmediate(resolve));
  action('new-transaction');
  submit('transaction-form',{kasAmount:'0.5',priceUsd:'',timestamp:'2026-01-04T00:00'});
  action('new-transaction');
  action('cancel-editor');
  action('export-csv');

  let capturedInput=null;
  const oldCreate=document.createElement;
  document.createElement=tag=>{ const node=oldCreate(tag); if(tag==='input') capturedInput=node; return node; };
  action('import-csv');
  assert.ok(capturedInput);
  capturedInput.files=[{async text(){return 'type,kas_amount,kas_price_usd,fee_usd,timestamp,notes,source_tx_id\nBuy,2,0.1,0,2026-01-03T00:00:00Z,CSV,source-1\n';}}];
  await capturedInput.onchange();
  document.createElement=oldCreate;
  action('export-csv');
  // Import failure uses the same themed toast and never browser-native dialogs.
  setFetchHook(async () => response({status:500,text:'offline'}));
  action('fetch-wallet-history');
  await new Promise(resolve=>setImmediate(resolve));
  action('delete-account');
  action('confirm-account-delete');
  // No-selection safety branches.
  for (const value of ['rename-account','delete-account','confirm-account-delete','new-transaction','confirm-transaction-delete','fetch-wallet-history','import-wallet-history','import-csv','export-csv','cancel-editor']) action(value);
  const selectTarget=new FakeElement('select'); selectTarget.dataset.action='ignored'; selectTarget.closest=()=>selectTarget; portfolioRoot.dispatch('click',{target:selectTarget,preventDefault(){}});
  const otherChange=new FakeElement('select'); otherChange.dataset.action='other'; portfolioRoot.dispatch('change',{target:otherChange});

  repo.deleteTransaction(store, 'd');
  repo.deleteAccount(store, account.id);
  assert.equal(store.accounts.length, 0);
  console.log('PASS: portfolio exact money, pricing, history, persistence, rendering, and controller paths');
} finally {
  document.createElementNS = originalCreateElementNS;
  document.createDocumentFragment = originalCreateFragment;
  globalThis.FormData = originalFormData;
  await cleanupDeepHarness();
}
