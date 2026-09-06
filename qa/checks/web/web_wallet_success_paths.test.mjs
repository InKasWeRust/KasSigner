import assert from 'node:assert/strict';
import {
  setupHarness, teardownHarness, moduleUrl, element, setFetchHook, setConfirmResult, state,
} from './web_recovery_test_harness.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));

await setupHarness();
try {
  const { networkState, transactionState, walletSession, walletState, scannerState, uiState } = await import(moduleUrl('app/state/index.js'));
  walletSession.replace({
    kpub: 'kpub-test',
    receive_addresses: ['kaspa:recv0', 'kaspa:recv1'],
    change_addresses: ['kaspa:chg0', 'kaspa:chg1'],
    next_receive_index: 0,
    next_change_index: 0,
  });
  walletState.fundedReceiveIndices = [];
  walletState.fundedChangeIndices = [];
  walletState.usedReceiveIndices = new Set();
  walletState.usedChangeIndices = new Set();
  walletState.standardChangeReservations = new Map();
  walletState.historyEntries = [];
  walletState.addressHistoryEnabled = false;
  networkState.network = 'mainnet';
  networkState.customNodeUrl = 'wss://wallet-test';
  networkState.customRestUrl = undefined;
  networkState.cachedUtxos = null;
  networkState.utxoSnapshot = undefined;
  scannerState.refreshing = false;
  uiState._refreshExpansionDepth = 0;

  const utxos = [
    { tx_id: 'aa'.repeat(32), index: 0, amount: '250000000', block_daa_score: '900' },
    { tx_id: 'bb'.repeat(32), index: 1, amount: '150000000', block_daa_score: '901' },
  ];
  Object.assign(globalThis.__KASSEE_WASM_STUBS__, {
    fetch_balance: () => JSON.stringify({
      total_kas: 4,
      total_sompi: 400000000,
      utxo_count: 2,
      funded_addresses: 2,
      funded_receive_indices: [0],
      funded_change_indices: [1],
    }),
    fetch_utxos: () => JSON.stringify(utxos),
    fetch_utxos_complete: () => JSON.stringify(utxos),
    get_virtual_daa_score: () => '1000',
    extend_addresses: (walletJson, extraReceive, extraChange) => {
      const wallet = JSON.parse(walletJson);
      for (let i = 0; i < Number(extraReceive); i++) wallet.receive_addresses.push(`kaspa:recv-extra-${i}`);
      for (let i = 0; i < Number(extraChange); i++) wallet.change_addresses.push(`kaspa:chg-extra-${i}`);
      return JSON.stringify(wallet);
    },
    generate_qr_frames: () => JSON.stringify([{ svg: '<svg>address</svg>' }]),
    create_consolidate_pskb: () => '50534b42',
    create_send_pskb_selected: () => '50534b42',
    pskt_detect: () => 'pskb',
    pskt_summary: () => JSON.stringify({ type: 'pskb', fee_sompi: '1000', inputs: 2, outputs: 1, ready_to_sign: true }),
    pskt_relay_to_kspt: () => '4b53505404',
    decode_address: () => JSON.stringify({ payload: '11'.repeat(32) }),
  });

  // Default REST history: used receive + change indices are discovered independently.
  setFetchHook(async url => ({
    ok: true,
    async json() { return { total: String(url).includes('recv0') || String(url).includes('chg1') ? 1 : 0 }; },
    async text() { return ''; },
  }));
  const { fetchAddressHistory } = await import(moduleUrl('features/wallet/core/history.js'));
  await fetchAddressHistory();
  assert.deepEqual([...walletState.usedReceiveIndices], [0]);
  assert.deepEqual([...walletState.usedChangeIndices], [1]);

  // Custom REST /full route and fallback /transactions route both record activity.
  walletState.usedReceiveIndices.clear(); walletState.usedChangeIndices.clear();
  walletState.addressHistoryEnabled = true; networkState.customRestUrl = 'https://history.test';
  setFetchHook(async url => ({
    ok: true,
    async json() {
      const text = String(url);
      if (text.endsWith('/full')) return { tx_count: text.includes('recv0') ? 1 : 0, transactions: text.includes('chg0') ? [{}] : [] };
      return { transactions: text.includes('recv1') ? [{}] : [] };
    },
    async text() { return ''; },
  }));
  await fetchAddressHistory();
  assert.equal(walletState.usedReceiveIndices.has(0), true);
  walletState.addressHistoryEnabled = false; networkState.customRestUrl = undefined;

  // Balance refresh renders authoritative values, tracks UTXOs, and DAA.
  const { refreshBalance, isRetryableNodeError, withNodeRetry } = await import(moduleUrl('features/wallet/core/balance.js'));
  assert.equal(isRetryableNodeError(new Error('websocket timeout')), true);
  assert.equal(isRetryableNodeError(new Error('bad signature')), false);
  let retryAttempts = 0;
  const retried = await withNodeRetry(async () => {
    retryAttempts++;
    if (retryAttempts < 2) throw new Error('network unavailable');
    return 'ok';
  }, 3);
  assert.equal(retried, 'ok');
  await refreshBalance();
  assert.equal(element('balance-kas').textContent, '4.00000000 KAS');
  assert.match(element('balance-info').textContent, /2 UTXOs/);
  assert.equal(element('balance-daa').textContent, 'DAA 1,000');
  assert.equal(walletState.fundedReceiveIndices[0], 0);

  // Address index selection and gap expansion cover both no-expand and expand cases.
  const { expandAddressesIfNeeded, getNextReceiveIndex, walletWithFreshIndices } = await import(moduleUrl('features/wallet/core/address_state.js'));
  walletState.fundedReceiveIndices = [0]; walletState.usedReceiveIndices = new Set();
  walletState.fundedChangeIndices = []; walletState.usedChangeIndices = new Set();
  assert.equal(expandAddressesIfNeeded(), false);
  assert.equal(getNextReceiveIndex(), 1);
  const fresh = JSON.parse(walletWithFreshIndices());
  assert.equal(fresh.next_receive_index, 1);
  walletState.standardChangeReservations.set(0, {address:'kaspa:chg0', status:'broadcast'});
  assert.equal(JSON.parse(walletWithFreshIndices()).next_change_index, 1);
  walletState.usedChangeIndices.add(0);
  const { reconcileStandardChangeReservations } = await import(moduleUrl('features/wallet/core/address_state.js'));
  reconcileStandardChangeReservations();
  assert.equal(walletState.standardChangeReservations.has(0), false);
  walletState.usedChangeIndices.clear();
  walletState.fundedReceiveIndices = [0, 1]; walletState.usedReceiveIndices = new Set();
  walletState.fundedChangeIndices = [0, 1]; walletState.usedChangeIndices = new Set();
  assert.equal(expandAddressesIfNeeded(), true);
  assert.ok(walletSession.current().receive_addresses.length > 2);

  // UTXO change tracking covers first snapshot, incoming, and spent transitions.
  const { trackUtxoChangesAndUsed, updateConsolidateButtons, handleConsolidate, handleConsolidateSelected } = await import(moduleUrl('features/wallet/tools/consolidation.js'));
  walletState.historyEntries = []; networkState.utxoSnapshot = undefined;
  trackUtxoChangesAndUsed([{ tx_id: 'a', index: 0, amount: 100n, address: 'kaspa:recv0' }]);
  assert.equal(walletState.historyEntries.length, 1);
  trackUtxoChangesAndUsed([{ tx_id: 'b', index: 1, amount: 200n, address: 'kaspa:recv1' }]);
  assert.equal(walletState.historyEntries.some(entry => entry.type === 'out'), true);
  assert.equal(walletState.historyEntries.some(entry => entry.type === 'in' && entry.tx_id === 'b'), true);

  transactionState.consolidateSelection = new Set();
  updateConsolidateButtons(1);
  assert.equal(element('btn-consolidate').style.display, 'none');
  transactionState.consolidateSelection = new Set([0, 1]);
  updateConsolidateButtons(3);
  assert.match(element('btn-consolidate-selected').textContent, /2 Selected/);
  networkState.cachedUtxos = utxos.map(u => ({ ...u, amount: BigInt(u.amount) }));
  await handleConsolidate();
  assert.equal(transactionState._psktReviewHex, '50534b42');
  transactionState._psktReviewHex = undefined;
  await handleConsolidateSelected();
  assert.equal(transactionState._psktReviewHex, '50534b42');

  // Address/UTXO screens execute real rendering branches.
  const { showAddresses, showUtxos } = await import(moduleUrl('features/wallet/tools/address_views.js'));
  walletState.fundedReceiveIndices = [0]; walletState.fundedChangeIndices = [];
  walletState.usedReceiveIndices = new Set([1]); walletState.usedChangeIndices = new Set([1]);
  showAddresses();
  assert.match(element('address-list').innerHTML, /funded/);
  assert.match(element('address-list').innerHTML, /used/);
  await showUtxos();
  assert.match(element('utxo-summary').textContent, /2 current UTXOs/);
  assert.match(element('utxo-list').innerHTML, /2\.50000000 KAS/);

  // Archival transaction history covers outgoing/incoming classification and rendering.
  walletState.historyEntries = [];
  setFetchHook(async url => ({
    ok: true,
    async json() {
      if (!String(url).includes('full-transactions')) return { total: 0 };
      return [
        {
          transaction_id: 'cc'.repeat(32), block_time: 1_700_000_000_000, is_accepted: true,
          inputs: [{ previous_outpoint_amount: '200000000', previous_outpoint_address: 'kaspa:recv0' }],
          outputs: [
            { amount: '50000000', script_public_key_address: 'kaspa:recv1' },
            { amount: '149000000', script_public_key_address: 'kaspa:external' },
          ],
        },
        {
          transaction_id: 'dd'.repeat(32), block_time: 1_700_000_001_000, is_accepted: true,
          inputs: [{ previous_outpoint_amount: '100000000', previous_outpoint_address: 'kaspa:sender' }],
          outputs: [{ amount: '99000000', script_public_key_address: 'kaspa:recv0' }],
        },
      ];
    },
    async text() { return ''; },
  }));
  const { showHistory, clearHistory } = await import(moduleUrl('features/wallet/tools/history.js'));
  showHistory(); await tick(); await tick();
  assert.equal(walletState.historyEntries.some(h => h.type === 'out'), true);
  assert.equal(walletState.historyEntries.some(h => h.type === 'in'), true);
  assert.equal(element('history-list').children.some(item => item.classList.contains('history-item')), true);
  setConfirmResult(false); clearHistory(); assert.ok(walletState.historyEntries.length > 0);
  setConfirmResult(true); clearHistory(); assert.equal(walletState.historyEntries.length, 0);
  assert.equal(element('history-summary').textContent, 'No transactions found');

  console.log('PASS: wallet balance/history/address/UTXO/consolidation success paths');
} finally {
  await teardownHarness();
}
