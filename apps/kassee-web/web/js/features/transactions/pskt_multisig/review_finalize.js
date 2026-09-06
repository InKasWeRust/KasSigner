import { navigationState, networkState, oracleState, transactionState } from '../../../app/state/index.js';
import { BROADCAST_ENABLED } from '../../../core/config/runtime.js';
import { ORACLE_MB_PROTOCOL } from '../../oracle/model_b/config.js';
import { hideLoading, showLoading, showScreen } from '../../../app/navigation.js';
import { toast } from '../../../core/ui/toast.js';
import { covShowPanel } from '../../covenants/generation/ui_and_keys.js';
import { showBroadcastError, showBroadcastSuccess } from '../send/broadcast.js';
import { withNodeRetry } from '../../wallet/core.js';
import { pskt_finalize_and_broadcast, pskt_summary } from '../../../wasm/api.js';
import { hexToBytes } from '../../../core/bytes.js';
import {
  hideOracleProvingScreen,
  setOracleProvingStage,
  showOracleProvingScreen,
} from './review_overlay.js';

function isOracleRoll(wireHex) {
  try {
    const bytes = hexToBytes(wireHex);
    if (bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x53 || bytes[2] !== 0x4b || bytes[3] !== 0x42) return false;
    const payload = new TextDecoder().decode(bytes.slice(4));
    const decoded = JSON.parse(new TextDecoder().decode(hexToBytes(payload)));
    const pskt = Array.isArray(decoded) ? decoded[0] : decoded;
    return pskt?.inputs?.[0]?.proprietaries?.risc0OracleMb === true;
  } catch (_) {
    return false;
  }
}

function returnToOracleCard() {
  hideOracleProvingScreen();
  transactionState._psktReviewHex = null;
  oracleState._oracleMbRollActive = false;
  oracleState._oracleMbRoll = null;
  try {
    showScreen('covenant');
    covShowPanel('oracle-mb');
  } catch (_) {}
}

function showOracleBroadcastSuccess(txId) {
  hideOracleProvingScreen();
  oracleState._oracleMbRollActive = false;
  oracleState._oracleMbRoll = null;
  transactionState._lastBroadcastTime = Date.now();
  transactionState._psktReviewHex = null;
  navigationState._broadcastReturnScreen = 'covenant';
  oracleState._oracleMbReturn = true;
  showScreen('broadcast');
  showBroadcastSuccess(String(txId));
}

async function finalizeOracleRoll() {
  if (!isOracleRoll(transactionState._psktReviewHex)) return false;
  const roll = oracleState._oracleMbRoll;
  if (!roll?.acc) {
    toast('Roll context lost. Ask for a new price to rebuild it.', 'error', 8000);
    returnToOracleCard();
    return true;
  }
  showOracleProvingScreen(roll.price);
  let response;
  let body = null;
  try {
    const base = (ORACLE_MB_PROTOCOL.proverBase || '').replace(/\/+$/, '');
    response = await fetch(base + '/roll', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tx: transactionState._psktReviewHex, acc: roll.acc, price: roll.price, t: roll.t }),
      signal: AbortSignal.timeout(900000),
    });
    try { body = await response.json(); } catch (_) {}
  } catch (error) {
    hideOracleProvingScreen();
    toast('Roll request failed: ' + (error?.message || error) + '. The roll was not sent.', 'error', 9000);
    return true;
  }
  if (response.ok && body?.txid) {
    showOracleBroadcastSuccess(body.txid);
    return true;
  }
  if (response.ok && body?.sealed) {
    setOracleProvingStage('broadcast');
    try {
      const txId = await withNodeRetry(wsUrl => pskt_finalize_and_broadcast(body.sealed, wsUrl));
      showOracleBroadcastSuccess(txId);
    } catch (error) {
      const message = String(error?.message || error);
      console.warn('[oracle-mb] sealed broadcast failed:', message);
      const moved = /already spent|orphan|already.*mempool/i.test(message);
      toast(
        moved
          ? 'This roll could not land: the oracle already moved on-chain. Showing the latest price.'
          : 'Roll could not be broadcast (the oracle may have moved, or your node was unreachable). Showing the latest price.',
        'error',
        9000,
      );
      returnToOracleCard();
    }
    return true;
  }
  hideOracleProvingScreen();
  if (body?.status === 'lost_race') {
    toast('Another roll landed first. The oracle is already fresh.', 'info', 9000);
  } else {
    toast('Roll rejected: ' + (body?.error || body?.reason || ('HTTP ' + response.status)), 'error', 10000);
  }
  returnToOracleCard();
  return true;
}

function logPsktOutputs() {
  try {
    const summary = JSON.parse(pskt_summary(transactionState._psktReviewHex, networkState.network));
    (summary.outputs || []).forEach((output, index) => {
      const script = output.script_hex || output.scriptHex || '';
      console.log(
        '[KasSee] OUT#' + index
        + ' kind=' + (output.script_kind || output.scriptKind)
        + ' spk_len=' + (script.length / 2) + 'B'
        + ' spk=' + script.slice(0, 24) + '…' + script.slice(-12),
      );
    });
    console.log('[KasSee] full outputs JSON:', JSON.stringify(summary.outputs));
  } catch (error) {
    console.log('[KasSee] pre-broadcast dump failed:', error);
  }
}

async function finalizeStandardPskt() {
  console.log('[KasSee] PSKT-native finalize + broadcast — PSKB hex length:', transactionState._psktReviewHex.length);
  logPsktOutputs();
  showLoading('Broadcasting...');
  try {
    const txId = await withNodeRetry(wsUrl => pskt_finalize_and_broadcast(transactionState._psktReviewHex, wsUrl));
    transactionState._lastBroadcastTime = Date.now();
    transactionState._psktReviewHex = null;
    hideLoading();
    showScreen('broadcast');
    showBroadcastSuccess(txId);
  } catch (error) {
    hideLoading();
    showBroadcastError(error);
    console.error('[KasSee] Broadcast failed (full):', error?.message || String(error));
  }
}

export function createPsktFinalizer() {
  return async function handlePsktFinalize() {
    if (!transactionState._psktReviewHex) {
      toast('No PSKT loaded', 'error');
      return;
    }
    if (!BROADCAST_ENABLED) {
      toast('Broadcast disabled in this version — testing only', 'error', 5000);
      return;
    }
    if (await finalizeOracleRoll()) return;
    await finalizeStandardPskt();
  };
}
