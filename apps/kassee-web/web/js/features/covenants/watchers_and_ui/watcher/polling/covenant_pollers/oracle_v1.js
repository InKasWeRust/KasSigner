import { covenantState, covenantWatcherState, networkState } from '../../../../../../app/state/index.js';
import { hexToBytes } from '../../../../../../core/bytes.js';
import { kaspaRestApiBase } from '../../../../../../core/config/network.js';
import { formatDaaDuration } from '../../../../../../core/format.js';
import { setSafeMarkup } from '../../../../../../core/security/safe_html.js';
import { verify_oracle_v1_attestation } from '../../../../../../wasm/api.js';
import { oracleV1MessageCommitment } from '../../../../../oracle/v1/attestation.js';
import { covSaveActive } from '../../../../recovery/active.js';

const MAGIC = '4f525631';
const HEADER_HEX = 8 + 128 + 64;
const MAX_CHECKED_TXIDS = 64;

function checkedTxids(result) {
    return Array.isArray(result._oracle_v1_checked_txids)
        ? result._oracle_v1_checked_txids.filter(txid => /^[0-9a-f]{64}$/i.test(txid)).slice(-MAX_CHECKED_TXIDS)
        : [];
}

function markChecked(result, transactionId) {
    const txids = checkedTxids(result).filter(txid => txid !== transactionId);
    txids.push(transactionId);
    result._oracle_v1_checked_txids = txids.slice(-MAX_CHECKED_TXIDS);
}

async function fetchBeacon(transactionId, result) {
    if (!/^[0-9a-f]{64}$/i.test(transactionId || '') || checkedTxids(result).includes(transactionId)) return null;
    try {
        const response = await fetch(`${kaspaRestApiBase(networkState.network)}/transactions/${transactionId}`, {
            signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) return null;
        const payload = String((await response.json()).payload || '').toLowerCase();
        markChecked(result, transactionId);
        if (!payload.startsWith(MAGIC) || payload.length < HEADER_HEX) return null;
        const signature = payload.slice(8, 136);
        const commitment = payload.slice(136, 200);
        const textHex = payload.slice(200);
        if (textHex.length % 2 !== 0) return null;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(hexToBytes(textHex));
        if (text !== (result.attestation_statement || '')) return null;
        if (commitment !== (result.message_commitment_hex || '').toLowerCase()) return null;
        if (await oracleV1MessageCommitment(text) !== commitment) return null;
        if (!verify_oracle_v1_attestation(result.oracle_pubkey_hex || '', signature, commitment)) return null;
        return { signature, commitment, text, transactionId };
    } catch (_) {
        return null;
    }
}

async function hasValidSavedAttestation(result) {
    const signature = String(result.oracle_attestation_signature || '').toLowerCase();
    const commitment = String(result.oracle_attestation_commitment || '').toLowerCase();
    const expected = String(result.message_commitment_hex || '').toLowerCase();
    const statement = String(result.attestation_statement || '');
    if (!/^[0-9a-f]{128}$/.test(signature) || !/^[0-9a-f]{64}$/.test(commitment)) return false;
    if (commitment !== expected || await oracleV1MessageCommitment(statement) !== commitment) return false;
    return verify_oracle_v1_attestation(result.oracle_pubkey_hex || '', signature, commitment);
}

function saveBeacon(result, beacon) {
    result.oracle_attestation_signature = beacon.signature;
    result.oracle_attestation_commitment = beacon.commitment;
    result.oracle_attestation_text = beacon.text;
    result.oracle_attestation_txid = beacon.transactionId;
    const active = covenantState.activeCovenants.find(item => item.address === result.address);
    if (active) {
        active.oracle_attestation_signature = beacon.signature;
        active.oracle_attestation_commitment = beacon.commitment;
        active.oracle_attestation_text = beacon.text;
        active.oracle_attestation_txid = beacon.transactionId;
        active._oracle_v1_checked_txids = [beacon.transactionId];
        covSaveActive();
    }
}

export async function pollOracleV1(state) {
    const { total, kas, st, locktime, currentDaa, utxos } = state;
    const result = covenantState.lastCovenantResult;
    if (total === 0n && covenantWatcherState._covWatcherLastBalance !== null
        && covenantWatcherState._covWatcherLastBalance > 0n) {
        setSafeMarkup(st, '<span class="u-text-teal">✅ Oracle covenant spent.</span>');
        st.style.display = '';
        return true;
    }
    if (total === 0n) {
        st.textContent = '👁 0 KAS | Not funded';
        st.style.color = '';
        return false;
    }

    let attested = await hasValidSavedAttestation(result);
    if (!attested) {
        // If persisted attestation fields were corrupted, permit its known txid to
        // be fetched again instead of trusting or permanently blacklisting state.
        if (result.oracle_attestation_txid) {
            result._oracle_v1_checked_txids = checkedTxids(result)
                .filter(txid => txid !== result.oracle_attestation_txid);
        }
        for (const utxo of utxos) {
            const beacon = await fetchBeacon(String(utxo?.tx_id || '').toLowerCase(), result);
            if (beacon) { saveBeacon(result, beacon); break; }
        }
        attested = await hasValidSavedAttestation(result);
    }
    const refund = locktime > 0n && currentDaa > 0n
        ? (currentDaa >= locktime ? 'Owner refund available now' : `Owner refund in ~${formatDaaDuration(locktime - currentDaa)}`)
        : 'Owner refund timer active';
    if (attested) {
        setSafeMarkup(st, `<span class="u-text-teal">✅ ${kas} KAS | Oracle attested | Beneficiary claim available</span><br>${refund}`);
    } else {
        st.textContent = `👁 ${kas} KAS | Waiting for oracle attestation | ${refund}`;
        st.style.color = '';
    }
    st.style.display = '';
    return false;
}
