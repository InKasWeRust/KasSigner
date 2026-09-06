import { oracleState } from '../../../../../app/state/index.js';
import { ORACLE_MB_DEPLOY } from '../../config.js';
import { oracleMbIdentity } from '../../state.js';
import { resolveNodeUrl } from '../../../../../core/node/resolver.js';
import { oracleMbDiscoverAndRead } from '../../protocol.js';
import { utxoTransactionId } from '../../../../../core/utxo.js';
import { fetch_utxos_for_address_js } from '../../../../../wasm/api.js';
// Oracle Model B refresh and timer lifecycle.

import { byId } from '../../../../../core/dom.js';
export function createOracleRefresh(dependencies) {
const { oracleMbRenderAge, oracleMbRenderState, oracleMbBlockWatcherStart, oracleMbBlockWatcherStop } = dependencies;
async function oracleMbPollOnce() {
  try {
    const wsUrl = await resolveNodeUrl();
    const hb = JSON.parse(await fetch_utxos_for_address_js(oracleMbIdentity.heartbeatAddress, wsUrl));
    if (!hb.length) return;
    const txid = utxoTransactionId(hb[0]);
    if (!txid) return;
    const changed = !oracleState._oracleMbState || txid !== oracleState._oracleMbState.rollTxid;
    if (changed) {
      if (!oracleState._oracleMbState) oracleState._oracleMbState = { price: 0n, t: 0n, rollTxid: txid, addr: '' };
      else oracleState._oracleMbState.rollTxid = txid;       // refresh the displayed roll txid (local, cheap)
      oracleMbRenderState();
      // Backstop only: a new roll's txid is up but the BlockAdded notification didn't refresh
      // price/T within 15s -> the watcher likely missed it -> one REST catch-up read.
      if (Date.now() - oracleState._oracleMbPriceTs > 15000) await oracleMbCardRefresh();
    }
  } catch (_) { /* node hiccup; keep the last reading, retry next tick */ }
}
async function oracleMbCardRefresh() {
  try {
    const r = await oracleMbDiscoverAndRead();
    oracleState._oracleMbState = { price: r.price, t: r.t, rollTxid: r.rollTxid, addr: r.expectedOracleAddress };
    oracleState._oracleMbPriceTs = Date.now();
    oracleMbRenderState();
  } catch (e) {
    const ageEl = byId('oracle-mb-age');
    if (ageEl && !oracleState._oracleMbState) { ageEl.textContent = 'node unreachable, retrying…'; ageEl.style.color = 'var(--text-muted)'; }
    console.warn('[oracle-mb] refresh failed:', e && e.message ? e.message : e);
  }
}

function oracleMbCardOpen() {
  if (!oracleMbIdentity.heartbeatAddress) oracleMbIdentity.heartbeatAddress = ORACLE_MB_DEPLOY.heartbeatAddress;
  if (!oracleMbIdentity.heartbeatCovIdH)  oracleMbIdentity.heartbeatCovIdH  = ORACLE_MB_DEPLOY.heartbeatCovIdH;
  if (!oracleMbIdentity.oracleCovIdG)     oracleMbIdentity.oracleCovIdG     = ORACLE_MB_DEPLOY.oracleCovIdG;

  const askStatus = byId('oracle-mb-ask-status'); if (askStatus) askStatus.style.display = 'none';
  if (oracleState._oracleMbState) oracleMbRenderState(); // paint cached immediately if we have it
  oracleMbCardRefresh();                      // one-time cold-start read (REST) for the current price

  if (oracleState._oracleMbAgeTimer) clearInterval(oracleState._oracleMbAgeTimer);
  oracleState._oracleMbAgeTimer = setInterval(oracleMbRenderAge, 1000);
  if (oracleState._oracleMbPollTimer) clearInterval(oracleState._oracleMbPollTimer);
  oracleState._oracleMbPollTimer = setInterval(oracleMbPollOnce, 12000);

  oracleMbBlockWatcherStart();                // live price/T from the block stream (no REST, no lag)
}



function oracleMbAmbientStop() {
  if (oracleState._oracleMbAgeTimer) { clearInterval(oracleState._oracleMbAgeTimer); oracleState._oracleMbAgeTimer = null; }
  if (oracleState._oracleMbPollTimer) { clearInterval(oracleState._oracleMbPollTimer); oracleState._oracleMbPollTimer = null; }
  oracleMbBlockWatcherStop();
}
return { oracleMbPollOnce, oracleMbCardRefresh, oracleMbCardOpen, oracleMbAmbientStop };
}
