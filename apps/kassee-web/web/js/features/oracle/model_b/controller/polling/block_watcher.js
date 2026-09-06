import { oracleState } from '../../../../../app/state/index.js';
import { hexToBytes } from '../../../../../core/bytes.js';
import { createBlockAddedTransport } from '../../../../../core/node/block_added_transport.js';
import { covenant_oracle_mb } from '../../../../../wasm/api.js';
import { ORACLE_MB_PROTOCOL } from '../../config.js';
import { oracleMbIdentity } from '../../state.js';

function processBlockNotification(setRoot, data, oracleMbRenderState) {
    if (data.length < 50) return;
    const start = data[0] === 0x01 ? 9 : 1;
    if (start >= data.length || data[start] !== 0xFF || data[start + 2] !== 0x3C) return;

    for (let offset = 17; offset + 32 <= data.length; offset += 1) {
        if (!matchesSetRoot(data, offset, setRoot) || data[offset - 17] !== 0x30) continue;
        const price = readLittleEndianU64(data, offset - 16);
        const timestamp = readLittleEndianU64(data, offset - 8);
        if (oracleState._oracleMbState?.price === price && oracleState._oracleMbState?.t === timestamp) return;
        const rollTxid = oracleState._oracleMbState?.rollTxid || '';
        oracleState._oracleMbState = {
            price,
            t: timestamp,
            rollTxid,
            addr: deriveOracleAddress(price, timestamp),
        };
        oracleState._oracleMbPriceTs = Date.now();
        oracleMbRenderState();
        console.log('[oracle-mb] block-stream update: price', price.toString(), 'T', timestamp.toString());
        return;
    }
}

function matchesSetRoot(data, offset, setRoot) {
    for (let index = 0; index < 32; index += 1) {
        if (data[offset + index] !== setRoot[index]) return false;
    }
    return true;
}

function readLittleEndianU64(data, offset) {
    let value = 0n;
    for (let index = 0; index < 8; index += 1) {
        value |= BigInt(data[offset + index]) << BigInt(8 * index);
    }
    return value;
}

function deriveOracleAddress(price, timestamp) {
    let address = oracleState._oracleMbState?.addr || '';
    try {
        address = JSON.parse(covenant_oracle_mb(JSON.stringify({
            genesis_price: price.toString(),
            genesis_t: timestamp.toString(),
            image_id_hex: ORACLE_MB_PROTOCOL.imageIdHex,
            control_id_hex: ORACLE_MB_PROTOCOL.controlIdHex,
            set_root_hex: ORACLE_MB_PROTOCOL.setRootHex,
            hashfn_hex: ORACLE_MB_PROTOCOL.hashfnHex,
            heartbeat_cov_id_hex: oracleMbIdentity.heartbeatCovIdH,
            network: ORACLE_MB_PROTOCOL.network,
        }))).address;
    } catch (_) {}
    return address;
}

export function createOracleBlockWatcher(oracleMbRenderState) {
    let transport = null;
    function stop() {
        transport?.stop();
        transport = null;
    }
    function start() {
        stop();
        const setRootHex = (ORACLE_MB_PROTOCOL.setRootHex || '').toLowerCase();
        if (setRootHex.length !== 64) {
            console.warn('[oracle-mb] block watcher: setRootHex not set');
            return;
        }
        const setRoot = hexToBytes(setRootHex);
        transport = createBlockAddedTransport({
            label: 'oracle model B',
            isActive: () => Boolean(oracleState._oracleMbAgeTimer),
            onPayload: payload => processBlockNotification(setRoot, payload, oracleMbRenderState),
        });
        transport.start();
    }
    return {
        oracleMbBlockWatcherStart: start,
        oracleMbBlockWatcherStop: stop,
    };
}
