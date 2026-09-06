import { oracleState } from '../../../app/state/index.js';
import { ORACLE_MB_DEPLOY } from './config.js';
import { applyDeployedOracleIdentity } from './state.js';
// KasSee Web — features/oracle/model_b/controller
import { createOraclePolling } from './controller/polling.js';
import { createOracleProving } from './controller/proving.js';

applyDeployedOracleIdentity(ORACLE_MB_DEPLOY);

// Ambient price+age read for the deployed TN10 oracle, plus the ask-for-new hook.
// Pure JS, no WASM rebuild: reuses oracleMbDiscoverAndRead (full read) plus a cheap
// heartbeat-UTXO poll (a txid-change detector), so the ~445KB roll tx is fetched ONLY
// when a new roll lands. Age ticks locally from (now - T). The oracle ADDRESS rotates on
// every forward-roll, so only the FIXED identity (heartbeat addr, H, G) is baked here;
// the live address is always rediscovered.

// Deployed MAINNET identity (fixed parts; the circuit pins already live in ORACLE_MB).



oracleState._oracleMbState = null;
     // { price:BigInt, t:BigInt, rollTxid, addr }
oracleState._oracleMbFeeTotalKas = '1';
  // total fee (KAS) the user picked for the next roll; miner + 0.3 service. Min 1.
oracleState._oracleMbAgeTimer = null;
  // 1s local age tick
oracleState._oracleMbPollTimer = null;
 // ~12s heartbeat-txid poll (local; REST only on a watcher miss)
   // BlockAdded subscription: live price/T from the block stream
oracleState._oracleMbPriceTs = 0;
      // ms timestamp of the last price/T update (watcher or REST)

const polling = createOraclePolling();
const proving = createOracleProving(polling);

export const {
  oracleMbRenderAge,
  oracleMbRenderState,
  oracleMbBlockWatcherStart,
  oracleMbBlockWatcherStop,
  oracleMbPollOnce,
  oracleMbCardRefresh,
  oracleMbCardOpen,
  oracleMbAmbientStop,
} = polling;

export const {
  oracleMbSetFee,
  oracleMbAskForNew,
} = proving;
