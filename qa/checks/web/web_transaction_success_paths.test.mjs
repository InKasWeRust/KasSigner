import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element } from './web_recovery_test_harness.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));

await setupHarness();
try {
  const { covenantState, navigationState, networkState, oracleState, scannerState, transactionState, walletSession, walletState } = await import(moduleUrl('app/state/index.js'));
  walletSession.replace({
    kpub: 'kpub-test', receive_addresses: ['kaspa:owner-receive'], change_addresses: ['kaspa:change', 'kaspa:change-next'],
    next_receive_index: 0, next_change_index: 0,
  });
  networkState.network = 'mainnet';
  networkState.customNodeUrl = 'wss://tx-test';
  networkState.cachedUtxos = [
    { tx_id: 'aa'.repeat(32), index: 0, amount: 200000000n, block_daa_score: 900n },
    { tx_id: 'bb'.repeat(32), index: 1, amount: 100000000n, block_daa_score: 901n },
  ];
  transactionState.utxoSelectionLimit = 8;
  transactionState.utxoSort = 'amount-desc';
  walletState.fundedReceiveIndices = [];
  walletState.fundedChangeIndices = [];
  walletState.usedReceiveIndices = new Set();
  walletState.usedChangeIndices = new Set();
  walletState.historyEntries = [];
  walletState.addressHistoryEnabled = false;
  transactionState.selectedUtxoIds = null;
  element('balance-kas').textContent = '3.00000000 KAS';

  const summary = {
    format: 'pskb', tx_version: 0, input_count: 2, output_count: 3,
    fee_sompi: '1000', total_in_sompi: '300000000', total_out_sompi: '299999000', finalize_ready: true,
    inputs: [
      { script_kind: 'p2pk', sigs_present: 1, multisig_m: null, multisig_n: null, amount_sompi: '200000000', prev_tx_id: 'aa'.repeat(32), prev_index: 0 },
      { script_kind: 'multisig', sigs_present: 2, multisig_m: 2, multisig_n: 3, amount_sompi: '100000000', prev_tx_id: 'bb'.repeat(32), prev_index: 1 },
    ],
    outputs: [
      { script_kind: 'p2pk', amount_sompi: '150000000', address: 'kaspa:external', script_hex: '51' },
      { script_kind: 'p2pk', amount_sompi: '100000000', address: 'kaspa:change', script_hex: '51', derivation_branch: 1, derivation_index: 0 },
      { script_kind: 'p2pk', amount_sompi: '49999000', address: 'kaspa:owner-receive', script_hex: '51' },
    ],
  };
  let activeSummary = summary;
  let finalized = 0;
  let qrMode = 'complete';
  let sdkPrepareCalls = 0;
  const firstSignerPartialKspt = '4b5350540401aa';
  const secondSignerFinalKspt = '4b5350540401bb';
  Object.assign(globalThis.__KASSEE_WASM_STUBS__, {
    get_fee_estimate: () => JSON.stringify({
      suggested_fee: '6000', low_sompi_per_gram: '1', normal_sompi_per_gram: '2', priority_sompi_per_gram: '3',
      low_seconds: 20, normal_seconds: 10, priority_seconds: 5,
    }),
    fetch_utxos: () => JSON.stringify([
      { tx_id: 'aa'.repeat(32), index: 0, amount: '200000000', block_daa_score: '900' },
      { tx_id: 'bb'.repeat(32), index: 1, amount: '100000000', block_daa_score: '901' },
    ]),
    fetch_utxos_complete: () => JSON.stringify([
      { tx_id: 'aa'.repeat(32), index: 0, amount: '200000000', block_daa_score: '900' },
      { tx_id: 'bb'.repeat(32), index: 1, amount: '100000000', block_daa_score: '901' },
    ]),
    create_send_pskb: () => '50534b42',
    create_send_pskb_limited: () => '50534b42',
    create_send_pskb_with_utxos: () => '50534b42',
    create_covenant_pskb: () => '50534b42',
    create_covenant_pskb_with_payload: () => '50534b42',
    create_global_spending_limit_topup: () => '50534b42',
    create_global_allowance_topup: () => '50534b42',
    pskt_summary: () => JSON.stringify(activeSummary),
    pskt_detect: hex => String(hex).startsWith('50534b42') ? 'pskb' : '',
    pskt_relay_to_kspt: () => '4b5350540400',
    kassigner_sdk_prepare: () => {
      sdkPrepareCalls += 1;
      return JSON.stringify({ ksptHex: '4b5350540400' });
    },
    kassigner_sdk_complete: () => JSON.stringify({ psktHex: '50534b42' }),
    pskt_finalize_and_broadcast: () => { finalized++; return 'cc'.repeat(32); },
    broadcast_signed: () => 'dd'.repeat(32),
    generate_qr_frames: () => JSON.stringify([
      { svg: '<svg>frame1</svg>' }, { svg: '<svg>frame2</svg>' }, { svg: '<svg>frame3</svg>' },
    ]),
    decode_qr_frame: () => {
      if (qrMode === 'complete') return '50534b42';
      if (qrMode === 'first-kas-signer') return firstSignerPartialKspt;
      if (qrMode === 'second-kas-signer') return secondSignerFinalKspt;
      return '';
    },
    decoder_progress: () => JSON.stringify({ total: 3, count: 2, bits: [true, false, true] }),
    parse_kpub: () => JSON.stringify({ account_pubkey: '11'.repeat(32) }),
    build_covenant_payload: () => '',
  });

  const sendForm = await import(moduleUrl('features/transactions/send/compose/send_form.js'));
  const { normalizeUtxoSortMode, orderedUtxoEntries, renderUtxoSelector } = await import(moduleUrl('features/transactions/shared/utxo_selector.js'));
  const sortable = [
    { tx_id: 'cc'.repeat(32), index: 2, amount: 300n, block_daa_score: 10n },
    { tx_id: 'aa'.repeat(32), index: 0, amount: 100n, block_daa_score: 30n },
    { tx_id: 'bb'.repeat(32), index: 1, amount: 200n, block_daa_score: 20n },
  ];
  assert.equal(normalizeUtxoSortMode('desc'), 'amount-desc');
  assert.equal(normalizeUtxoSortMode('asc'), 'amount-asc');
  assert.deepEqual(orderedUtxoEntries(sortable, 'amount-desc').map(entry => entry.utxo.amount), [300n, 200n, 100n]);
  assert.deepEqual(orderedUtxoEntries(sortable, 'amount-asc').map(entry => entry.utxo.amount), [100n, 200n, 300n]);
  assert.deepEqual(orderedUtxoEntries(sortable, 'daa-desc').map(entry => entry.utxo.block_daa_score), [30n, 20n, 10n]);
  assert.deepEqual(orderedUtxoEntries(sortable, 'daa-asc').map(entry => entry.utxo.block_daa_score), [10n, 20n, 30n]);
  const undated = [
    { tx_id: 'dd'.repeat(32), index: 0, amount: 100n },
    { tx_id: 'ee'.repeat(32), index: 1, amount: 100n },
  ];
  assert.deepEqual(orderedUtxoEntries(undated, 'daa-asc').map(entry => entry.utxo.tx_id), ['dd'.repeat(32), 'ee'.repeat(32)]);
  renderUtxoSelector(element('send-utxo-list'), [undated[0]], [], { limit: 8, sort: 'daa-asc' }, () => {});
  assert.match(element('send-utxo-list').innerHTML, /DAA —/);
  await sendForm.openSendScreen();
  assert.equal(element('input-fee').value, '6000');
  assert.match(element('send-balance-ref').textContent, /3 KAS/);
  assert.equal(networkState.cachedUtxos.length, 2);
  sendForm.setFeeLevel('low'); assert.ok(BigInt(element('input-fee').value) >= 2500n);
  sendForm.setFeeLevel('priority'); assert.ok(BigInt(element('input-fee').value) >= 300000n);
  sendForm.setFeeLevel('normal');
  assert.notEqual(element('fee-normal-amount').textContent, '');
  sendForm.toggleSendUtxos();
  assert.equal(element('send-utxo-advanced').classList.contains('hidden'), false);
  element('send-utxo-limit').value = '1'; element('send-utxo-limit').onchange();
  assert.equal(transactionState.utxoSelectionLimit, 1);
  element('send-utxo-sort').value = 'daa-desc'; element('send-utxo-sort').onchange();
  assert.equal(transactionState.utxoSort, 'daa-desc');
  sendForm.toggleSendUtxos();
  assert.equal(element('send-utxo-advanced').classList.contains('hidden'), true);

  // UTXO explorer coin control carries exact outpoints into the standard Send screen.
  const consolidation = await import(moduleUrl('features/wallet/tools/consolidation.js'));
  networkState.cachedUtxos = [
    { tx_id: 'aa'.repeat(32), index: 0, amount: 200000000n, block_daa_score: 900n },
    { tx_id: 'bb'.repeat(32), index: 1, amount: 100000000n, block_daa_score: 901n },
  ];
  transactionState.consolidateSelection = new Set([1]);
  consolidation.updateConsolidateButtons(2);
  assert.equal(element('btn-send-selected-utxos').style.display, 'block');
  assert.match(element('btn-send-selected-utxos').textContent, /1 Selected/);
  await consolidation.handleSendSelectedUtxos();
  assert.deepEqual(transactionState.selectedUtxoIds, [`${'bb'.repeat(32)}:1`]);
  assert.equal(element('send-utxo-advanced').classList.contains('hidden'), false);
  assert.match(element('send-utxo-summary').textContent, /1 manually selected/);

  // Send maximum covers selected UTXO and total-balance routes.
  const { selectedSendMaximumSompi, balanceSendMaximumKas } = await import(moduleUrl('features/transactions/send/compose/send_max.js'));
  assert.equal(selectedSendMaximumSompi(1000000n, 1, 1000n), 692000n);
  assert.equal(balanceSendMaximumKas('1', 300000n), '0.997');
  transactionState.selectedUtxoIds = [`${'aa'.repeat(32)}:0`];
  element('input-fee').value = '300000';
  sendForm.handleSendMax();
  assert.ok(Number(element('input-amount').value) > 0);

  // Standard transaction planning: selected, automatic default, and custom limit.
  const { planSelected, planAutomatic } = await import(moduleUrl('features/transactions/send/compose/planners/standard.js'));
  let plan = await planSelected(walletSession.json(), 'kaspa:external', '1', 300000n);
  assert.equal(plan.pskbHex, '50534b42');
  transactionState.selectedUtxoIds = null; transactionState.utxoSelectionLimit = 8;
  plan = await planAutomatic(walletSession.json(), 'kaspa:external', '1', 300000n);
  assert.equal(plan.completed, false);
  transactionState.utxoSelectionLimit = 4;
  plan = await planAutomatic(walletSession.json(), 'kaspa:external', '1', 300000n);
  assert.equal(plan.pskbHex, '50534b42');

  // Full create-TX UI route reaches PSKT review with exact integer fee coercion.
  const { handleCreateTx, handleDestScan } = await import(moduleUrl('features/transactions/send/compose/transaction_building.js'));
  navigationState._broadcastReturnScreen = null;
  transactionState.selectedUtxoIds = null; transactionState.utxoSelectionLimit = 8;
  activeSummary = {
    format: 'pskb', tx_version: 0, input_count: 2, output_count: 2,
    fee_sompi: '300000', total_in_sompi: '300000000', total_out_sompi: '299700000', finalize_ready: false,
    inputs: summary.inputs,
    outputs: [
      { script_kind: 'p2pk', amount_sompi: '100000000', address: 'kaspa:external', script_hex: '51' },
      { script_kind: 'p2pk', amount_sompi: '199700000', address: 'kaspa:change', script_hex: '51', derivation_branch: 1, derivation_index: 0 },
    ],
  };
  element('input-dest').value = 'kaspa:external'; element('input-amount').value = '1'; element('input-fee').value = '1';
  await handleCreateTx();
  assert.equal(transactionState._psktReviewHex, '50534b42');
  assert.equal(element('input-fee').value, '300000');
  assert.equal(transactionState._standardChangeReservationIndex, 0);
  assert.equal(walletState.standardChangeReservations.get(0)?.status, 'pending');
  const addressState = await import(moduleUrl('features/wallet/core/address_state.js'));
  assert.equal(JSON.parse(addressState.walletWithFreshIndices()).next_change_index, 1);
  assert.equal(addressState.reserveStandardChangeFromSummary(walletSession.json(), { outputs: [] }), null);
  handleDestScan('kaspa:scanned'); assert.equal(element('input-dest').value, 'kaspa:scanned');
  handleDestScan('kaspatest:wrong'); assert.match(element('toast').textContent, /different network/i);
  activeSummary = summary;

  // Covenant planner uses the same watch-only PSKB path and payload state.
  const { planCovenant } = await import(moduleUrl('features/transactions/send/compose/planners/covenant.js'));
  covenantState.lastCovenantResult = { type: 'escrow', address: 'kaspa:covenant', redeem_script_hex: '51' };
  covenantState._covPayloadHex = '';
  navigationState._broadcastReturnScreen = 'covenant';
  transactionState.selectedUtxoIds = [`${'aa'.repeat(32)}:0`];
  plan = await planCovenant('kaspa:covenant', '1', 400000n);
  assert.equal(plan.pskbHex, '50534b42');
  assert.equal(plan.completed, false);

  // Review renders ownership totals, multisig status, and payload hash branch.
  const { openPsktReview } = await import(moduleUrl('features/transactions/pskt_multisig/review.js'));
  covenantState._covPayloadHex = 'aa';
  element('pskt-inputs').replaceChildren();
  element('pskt-outputs').replaceChildren();
  openPsktReview('50534b42'); await tick();
  assert.equal(element('pskt-format').textContent, 'PSKB');
  assert.equal(element('pskt-send-total').textContent, '1.5');
  assert.equal(element('pskt-change-total').textContent, '1');
  assert.equal(element('pskt-inputs').children.length, 2);
  assert.equal(element('pskt-outputs').children.length, 3);
  assert.equal(element('btn-pskt-finalize').disabled, false);

  // QR review exercises multi-frame controls and lifecycle.
  const review = await import(moduleUrl('features/transactions/send/review.js'));
  review.displayKsptQr('4b5350540400', 'Relay to next signer');
  assert.equal(scannerState.qrFrames.length, 3);
  assert.equal(element('btn-scan-next-sig').style.display, 'block');
  element('btn-frame-next').onclick(); assert.equal(scannerState.qrFrameIdx, 1);
  element('btn-frame-prev').onclick(); assert.equal(scannerState.qrFrameIdx, 0);
  element('btn-frame-pause').onclick(); assert.equal(scannerState.qrCycleTimer, null);
  element('btn-frame-pause').onclick(); assert.notEqual(scannerState.qrCycleTimer, null);
  review.pauseQrCycle(); assert.equal(scannerState.qrCycleTimer, null);
  review.resumeQrCycleIfPossible(); assert.notEqual(scannerState.qrCycleTimer, null);
  review.stopQrCycle(); assert.equal(scannerState.qrFrames, null);

  // Signature-state parser covers signed flag, unsupported generation, valid unsigned, and malformed wire.
  const { inspectKsptSignatureStatus } = await import(moduleUrl('features/transactions/send/kspt_status.js'));
  assert.equal(inspectKsptSignatureStatus('4b5350540401'), 'signed');
  assert.equal(inspectKsptSignatureStatus('4b5350540300'), 'unsupported');
  const unsigned = new Uint8Array(51); unsigned.set([0x4b,0x53,0x50,0x54,0x04,0x00]);
  assert.equal(inspectKsptSignatureStatus(Buffer.from(unsigned).toString('hex')), 'unsigned');
  const partial = new Uint8Array(111);
  partial.set([0x4b,0x53,0x50,0x54,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00]);
  // One input begins at byte 51: fixed input fields end at 106; empty SPK length,
  // then one signature record. The classifier only needs to observe its count.
  partial[106] = 0;
  partial[107] = 1;
  assert.equal(inspectKsptSignatureStatus(Buffer.from(partial).toString('hex')), 'partial');
  assert.equal(inspectKsptSignatureStatus('deadbeef'), 'unknown');

  // Broadcast rendering, PSKB scan routing, progress, normal KSPT broadcast, and oracle race presentation.
  const broadcast = await import(moduleUrl('features/transactions/send/broadcast.js'));
  broadcast.hideBroadcastResult(); assert.equal(element('broadcast-result').classList.contains('hidden'), true);
  broadcast.showBroadcastSuccess('ee'.repeat(32)); assert.equal(element('broadcast-result-msg').textContent, 'Transaction broadcast!');
  assert.equal(transactionState._standardChangeReservationIndex, null);
  assert.equal(walletState.standardChangeReservations.get(0)?.status, 'broadcast');
  assert.equal(JSON.parse(addressState.walletWithFreshIndices()).next_change_index, 1);
  walletState.fundedChangeIndices = [0];
  addressState.reconcileStandardChangeReservations();
  assert.equal(walletState.standardChangeReservations.has(0), false);
  walletState.fundedChangeIndices = [];
  broadcast.showBroadcastError('ordinary failure'); assert.equal(element('broadcast-result-msg').textContent, 'Broadcast failed');
  oracleState._oracleMbRollActive = true;
  broadcast.showBroadcastError('input already spent'); assert.equal(element('broadcast-result-msg').textContent, 'Someone rolled it first');
  qrMode = 'progress'; assert.equal(broadcast.handleSignedScan(new Uint8Array([1,2,3]), { stopCamera: false }), false);
  assert.match(element('scanner-status').innerHTML, /2 \/ 3 frames/);
  qrMode = 'complete'; assert.equal(broadcast.handleSignedScan(new Uint8Array([1,2,3]), { stopCamera: false }), true);
  assert.equal(transactionState._psktReviewHex, '50534b42');
  element('input-signed-hex').value = '50534b42'; await broadcast.handleBroadcastHex();
  assert.equal(transactionState._psktReviewHex, '50534b42');
  element('input-signed-hex').value = '4b5350540401'; await broadcast.handleBroadcastHex();
  assert.equal(element('broadcast-result-msg').textContent, 'Transaction broadcast!');

  // Real KasSigner multisig relay contract: signer 1's exact firmware-authored
  // partial KSPT must be handed to signer 2 without PSKB -> KSPT reconstruction.
  // The second return must merge back into the canonical PSKB and reach finalize-ready.
  activeSummary = {
    ...summary,
    finalize_ready: false,
    inputs: [{ ...summary.inputs[1], sigs_present: 1, multisig_m: 2, multisig_n: 3 }],
  };
  openPsktReview('50534b42');
  qrMode = 'first-kas-signer';
  assert.equal(broadcast.handleSignedScan(new Uint8Array([9]), { stopCamera: false }), true);
  assert.equal(transactionState._lastKasSignerKsptHex, firstSignerPartialKspt);
  const { handlePsktRelayKasSignerStandard } = await import(moduleUrl('features/transactions/pskt_multisig/review.js'));
  sdkPrepareCalls = 0;
  handlePsktRelayKasSignerStandard();
  assert.equal(transactionState._currentKsptHex, firstSignerPartialKspt);
  assert.equal(sdkPrepareCalls, 0, 'next KasSigner must receive the exact prior signer KSPT');

  activeSummary = {
    ...summary,
    finalize_ready: true,
    inputs: [{ ...summary.inputs[1], sigs_present: 2, multisig_m: 2, multisig_n: 3 }],
  };
  qrMode = 'second-kas-signer';
  assert.equal(broadcast.handleSignedScan(new Uint8Array([10]), { stopCamera: false }), true);
  assert.equal(transactionState._lastKasSignerKsptHex, secondSignerFinalKspt);
  assert.equal(element('btn-pskt-finalize').disabled, false);

  // Complete the exact two-KasSigner handoff all the way through finalization/broadcast.
  // This keeps the regression aligned with the user workflow instead of stopping at 2/2.
  const { createPsktFinalizer } = await import(moduleUrl('features/transactions/pskt_multisig/review_finalize.js'));
  const finalizedBeforeRelay = finalized;
  const finalizeRelay = createPsktFinalizer(); await finalizeRelay();
  assert.equal(finalized, finalizedBeforeRelay + 1);
  assert.equal(transactionState._psktReviewHex, null);
  assert.equal(element('broadcast-result-msg').textContent, 'Transaction broadcast!');

  // Opening a different canonical PSKB clears the device passthrough cache;
  // only then is SDK reconstruction allowed as a fallback for the first signer.
  openPsktReview('50534b42');
  assert.equal(transactionState._lastKasSignerKsptHex, null);
  sdkPrepareCalls = 0;
  handlePsktRelayKasSignerStandard();
  assert.equal(sdkPrepareCalls, 1);
  assert.equal(transactionState._currentKsptHex, '4b5350540400');

  // Native PSKT finalizer also works for the ordinary canonical-PSKB path.
  transactionState._psktReviewHex = '50534b42';
  const finalize = createPsktFinalizer(); await finalize();
  assert.equal(finalized > finalizedBeforeRelay + 1, true);
  assert.equal(transactionState._psktReviewHex, null);
  assert.equal(element('broadcast-result-msg').textContent, 'Transaction broadcast!');

  console.log('PASS: send/planning/review/QR/broadcast/PSKT success paths');
} finally {
  await teardownHarness();
}
