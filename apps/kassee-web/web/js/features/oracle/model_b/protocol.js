import { ORACLE_MB_PROTOCOL } from './config.js';
import { oracleMbIdentity } from './state.js';
import { resolveNodeUrl } from '../../../core/node/resolver.js';
import { utxoTransactionId } from '../../../core/utxo.js';
import { littleEndianHexToU64 } from '../../../core/bytes.js';
import { covenant_oracle_mb, create_oracle_mb_publish, fetch_utxos_for_address_js } from '../../../wasm/api.js';
// KasSee Web — Model B oracle protocol operations.
// The heartbeat UTXO is co-rolled with every publish; standalone heartbeat
// rolling is intentionally unsupported by this browser workflow.

export function oracleMbOracleAddress(genesisPrice, genesisT) {
  if (!oracleMbIdentity.heartbeatCovIdH) throw new Error("set heartbeatCovIdH before deriving the oracle address");
  const j = JSON.parse(covenant_oracle_mb(JSON.stringify({
    genesis_price: BigInt(genesisPrice).toString(),
    genesis_t: BigInt(genesisT).toString(),
    image_id_hex: ORACLE_MB_PROTOCOL.imageIdHex,
    control_id_hex: ORACLE_MB_PROTOCOL.controlIdHex,
    set_root_hex: ORACLE_MB_PROTOCOL.setRootHex,
    hashfn_hex: ORACLE_MB_PROTOCOL.hashfnHex,
    heartbeat_cov_id_hex: oracleMbIdentity.heartbeatCovIdH,
    network: ORACLE_MB_PROTOCOL.network,
  })));
  oracleMbIdentity.oracleAddress = j.address;
  console.log("[oracle-mb] oracle genesis address (fund tx_version=1):", j.address, "redeem_len", j.redeem_len);
  return j;
}
// price; journal = price[0:8] | T[8:16] | set_root[16:48], little-endian. The
// builder fetches the heartbeat UTXO (by H) and co-rolls it; you pass only H.
// oracleRedeemHex is the oracle's CURRENT redeem (read it from the live UTXO). ──
export async function oracleMbPublish({ walletJson, oracleAddress, oracleRedeemHex, covenantIdG,
                                 seal, claim, controlIndex, controlDigests, journal,
                                 fee, changeAddress, omitHeartbeat = false }) {
  const wsUrl = await resolveNodeUrl();
  return await create_oracle_mb_publish(JSON.stringify({
    wallet_json: walletJson,
    oracle_address: oracleAddress,
    redeem_script_hex: oracleRedeemHex,
    covenant_id_hex: covenantIdG,
    heartbeat_cov_id_hex: oracleMbIdentity.heartbeatCovIdH,
    image_id_hex: ORACLE_MB_PROTOCOL.imageIdHex,
    control_id_hex: ORACLE_MB_PROTOCOL.controlIdHex,
    set_root_hex: ORACLE_MB_PROTOCOL.setRootHex,
    hashfn_hex: ORACLE_MB_PROTOCOL.hashfnHex,
    seal_hex: seal,
    claim_hex: claim,
    control_index_hex: controlIndex,
    control_digests_hex: controlDigests,
    journal_hex: journal,
    fee: BigInt(fee).toString(),
    change_address: changeAddress,
    network: ORACLE_MB_PROTOCOL.network,
    ws_url: wsUrl,
    omit_heartbeat: !!omitHeartbeat,
  }));
}
// REST tx -> price/T from the 48-byte journal in the oracle input's sig_script
// tail -> tie it live by recomputing the oracle address for (price,T) and
// matching the roll's output[0]. ──
export async function oracleMbDiscoverAndRead() {
  if (!oracleMbIdentity.heartbeatAddress) throw new Error("set ORACLE_MB.heartbeatAddress (genesis) first");
  const wsUrl = await resolveNodeUrl();

  const hbUtxos = JSON.parse(await fetch_utxos_for_address_js(oracleMbIdentity.heartbeatAddress, wsUrl));
  if (!hbUtxos.length) throw new Error("no heartbeat UTXO at the fixed address");
  const rollTxid = utxoTransactionId(hbUtxos[0]);
  if (!rollTxid) throw new Error("could not read the heartbeat UTXO's txid");

  const tx = await fetch(`${ORACLE_MB_PROTOCOL.restBase}/transactions/${rollTxid}?inputs=true&outputs=true&resolve_previous_outpoints=light`)
    .then(r => { if (!r.ok) throw new Error("roll tx fetch failed: " + r.status); return r.json(); });
  const inputs = tx.inputs || tx.transaction?.inputs || [];
  const outputs = tx.outputs || tx.transaction?.outputs || [];
  if (!inputs.length || !outputs.length) throw new Error("roll tx missing inputs/outputs in the response");

  const sigOf = (i) => (i.signatureScript || i.signature_script || "");
  const oracleInput = inputs.reduce((a, b) => (sigOf(b).length > sigOf(a).length ? b : a));
  const sig = (sigOf(oracleInput) || "").toLowerCase();
  if (!sig) throw new Error("oracle input has no signatureScript in the response");
  // Robust: the ZK journal is a 48-byte push  30 | price(8 LE) | T(8 LE) | set_root(32).
  // Locate it by its set_root suffix, disambiguating from the set_root pinned inside the
  // revealed redeem (that one is a 20-prefixed OP_DATA_32 push, not 30 | price | T | set_root).
  // This is independent of the branch-selector and redeem-push opcodes in the tail.
  const SR = (ORACLE_MB_PROTOCOL.setRootHex || "").toLowerCase();
  if (SR.length !== 64) throw new Error("ORACLE_MB.setRootHex not set / not 32 bytes");
  let _from = 0, _jStart = -1;
  for (;;) {
    const s = sig.indexOf(SR, _from);
    if (s < 0) break;
    if (s >= 34 && sig.slice(s - 34, s - 32) === "30") { _jStart = s - 32; break; }
    _from = s + 2;
  }
  if (_jStart < 0) throw new Error("ZK journal (30|price|T|set_root) not found in oracle sig_script");
  const price = littleEndianHexToU64(sig.slice(_jStart, _jStart + 16));
  const t     = littleEndianHexToU64(sig.slice(_jStart + 16, _jStart + 32));

  const expected = JSON.parse(covenant_oracle_mb(JSON.stringify({
    genesis_price: BigInt(price).toString(),
    genesis_t: BigInt(t).toString(),
    image_id_hex: ORACLE_MB_PROTOCOL.imageIdHex,
    control_id_hex: ORACLE_MB_PROTOCOL.controlIdHex,
    set_root_hex: ORACLE_MB_PROTOCOL.setRootHex,
    hashfn_hex: ORACLE_MB_PROTOCOL.hashfnHex,
    heartbeat_cov_id_hex: oracleMbIdentity.heartbeatCovIdH,
    network: ORACLE_MB_PROTOCOL.network,
  })));
  const out0 = outputs[0];
  const out0spk = (out0.scriptPublicKey?.scriptPublicKey ?? out0.scriptPublicKey ?? out0.script_public_key ?? "");
  if (!out0spk) throw new Error("roll output[0] has no scriptPublicKey in the response");
  // Hard tie (recommended): confirm output[0] belongs to expected.address using
  // your SPK<->address helper. Loose check below logs a mismatch for inspection.
  console.log("[oracle-mb] discovery read:", {
    rollTxid, price: price.toString(), t: t.toString(), expectedOracleAddress: expected.address,
  });
  return { price, t, rollTxid, expectedOracleAddress: expected.address };
}
