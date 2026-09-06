import * as wasm from '/target/kassee-web/site/js/wasm/api.js';
import { networkState } from '/target/kassee-web/site/js/app/state/index.js';
import { withNodeRetry } from '/target/kassee-web/site/js/features/wallet/core.js';

const SUPPORTED_NETWORKS = new Set(['testnet-10', 'testnet-12']);
const SEND_AMOUNT_SOMPI = 20_000_000n;
const REQUESTED_FEE_SOMPI = 300_000n;
const MIN_REUSABLE_BALANCE_SOMPI = 100_000_000n;

let activeWsUrl = null;
const attemptedWsUrls = [];
const failedWsUrls = new Set();

async function finish(status, detail) {
    document.documentElement.dataset.qaStatus = status;
    document.body.textContent = JSON.stringify(detail);
    const response = await fetch('/__qa_funded_result__', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, detail }),
    });
    if (!response.ok) {
        throw new Error(`cannot publish funded-E2E result: HTTP ${response.status}`);
    }
}

function asBigInt(value, field) {
    if (typeof value !== 'string' || !/^\d+$/.test(value)) {
        throw new Error(`${field} must be an exact unsigned decimal string`);
    }
    return BigInt(value);
}

function walletBalance(utxos) {
    return utxos.reduce((total, utxo) => total + asBigInt(utxo.amount, 'UTXO amount'), 0n);
}

async function config() {
    const response = await fetch('/__qa_funded_config__', { cache: 'no-store' });
    if (!response.ok) throw new Error(`cannot load funded-E2E config: HTTP ${response.status}`);
    return response.json();
}

function validateNetwork(network) {
    if (!SUPPORTED_NETWORKS.has(network)) {
        throw new Error(`funded E2E requires a supported testnet, got: ${network}`);
    }
}

function configureNetwork(network) {
    networkState.network = network;
    networkState.customNodeUrl = null;
}

function validatePublicWsUrl(wsUrl) {
    if (!wsUrl || !(wsUrl.startsWith('ws://') || wsUrl.startsWith('wss://'))) {
        throw new Error(`invalid public wRPC URL: ${String(wsUrl)}`);
    }
    if (/^wss?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(wsUrl)) {
        throw new Error(`resolver returned a local endpoint: ${wsUrl}`);
    }
}

async function withFundedNodeRetry(operation) {
    return withNodeRetry(async (wsUrl) => {
        activeWsUrl = wsUrl;
        attemptedWsUrls.push(wsUrl);
        validatePublicWsUrl(wsUrl);
        if (failedWsUrls.has(wsUrl)) {
            throw new Error(`node unavailable: resolver repeated previously failed WebSocket endpoint ${wsUrl}`);
        }
        try {
            return await operation(wsUrl);
        } catch (error) {
            failedWsUrls.add(wsUrl);
            throw error;
        }
    });
}

function nodeEvidence() {
    return {
        ws_url: activeWsUrl,
        ws_urls_attempted: [...attemptedWsUrls],
        ws_urls_failed: [...failedWsUrls],
    };
}

function importWallet(kpub, network) {
    const wallet = JSON.parse(wasm.import_kpub(kpub, network));
    if (!wallet.receive_addresses?.length || !wallet.change_addresses?.length) {
        throw new Error('watcher did not derive receive/change addresses from the funded-E2E kpub');
    }
    return wallet;
}

async function addressCase(input, wallet) {
    await finish('pass', {
        phase: 'address',
        network: input.network,
        funding_address: wallet.receive_addresses[0],
    });
}

async function statusCase(input, wallet) {
    const utxos = JSON.parse(await withFundedNodeRetry(
        wsUrl => wasm.fetch_utxos(JSON.stringify(wallet), wsUrl),
    ));
    if (!Array.isArray(utxos)) throw new Error('funded-E2E UTXO response was not an array');
    const balance = walletBalance(utxos);
    await finish('pass', {
        phase: 'status',
        network: input.network,
        ...nodeEvidence(),
        funding_address: wallet.receive_addresses[0],
        balance_sompi: balance.toString(),
        utxo_count: utxos.length,
        funded: balance >= MIN_REUSABLE_BALANCE_SOMPI,
        minimum_reusable_balance_sompi: MIN_REUSABLE_BALANCE_SOMPI.toString(),
    });
}

async function prepareCase(input, wallet) {
    const destinationIndex = Number(input.destination_index);
    if (!Number.isInteger(destinationIndex) || destinationIndex < 1 || destinationIndex >= wallet.receive_addresses.length) {
        throw new Error(`invalid rotating destination index: ${input.destination_index}`);
    }

    const utxos = JSON.parse(await withFundedNodeRetry(
        wsUrl => wasm.fetch_utxos(JSON.stringify(wallet), wsUrl),
    ));
    const balance = walletBalance(utxos);
    if (balance < MIN_REUSABLE_BALANCE_SOMPI) {
        throw new Error(`funded-E2E wallet balance fell below reusable minimum: ${balance}`);
    }

    const feeEstimate = JSON.parse(await withFundedNodeRetry(
        wsUrl => wasm.get_fee_estimate(wsUrl),
    ));
    if (!feeEstimate || typeof feeEstimate !== 'object') throw new Error('fee estimate was not an object');

    const destination = wallet.receive_addresses[destinationIndex];
    const pskb = await withFundedNodeRetry(wsUrl => wasm.create_send_pskb(
        JSON.stringify(wallet),
        destination,
        SEND_AMOUNT_SOMPI,
        REQUESTED_FEE_SOMPI,
        wsUrl,
    ));
    if (wasm.pskt_detect(pskb) !== 'pskb') throw new Error('watcher did not create a canonical PSKB');
    const summary = JSON.parse(wasm.pskt_summary(pskb, input.network));
    const kspt = wasm.pskt_relay_to_kspt(pskb, input.network);
    if (!/^[0-9a-f]+$/i.test(kspt)) throw new Error('PSKB relay did not produce KSPT hex');

    await finish('pass', {
        phase: 'prepare',
        network: input.network,
        ...nodeEvidence(),
        destination,
        destination_index: destinationIndex,
        send_amount_sompi: SEND_AMOUNT_SOMPI.toString(),
        start_balance_sompi: balance.toString(),
        pskb_wire_hex: pskb,
        kspt_wire_hex: kspt,
        summary,
        fee_keys: Object.keys(feeEstimate).sort(),
    });
}

async function broadcastCase(input) {
    if (!/^[0-9a-f]+$/i.test(input.pskb_wire_hex || '')) throw new Error('missing PSKB wire for broadcast');
    if (!/^[0-9a-f]+$/i.test(input.signed_kspt_hex || '')) throw new Error('missing signed KSPT wire for broadcast');
    const signed = JSON.parse(wasm.kassigner_sdk_complete(
        input.pskb_wire_hex,
        input.signed_kspt_hex,
        input.network,
    ));
    const merged = signed.psktHex;
    if (!/^[0-9a-f]+$/i.test(merged || '')) {
        throw new Error('KasSigner SDK completion did not return merged PSKT/PSKB wire hex');
    }
    const summary = JSON.parse(wasm.pskt_summary(merged, input.network));
    const txid = await withFundedNodeRetry(
        wsUrl => wasm.pskt_finalize_and_broadcast(merged, wsUrl),
    );
    if (!/^[0-9a-f]{64}$/i.test(txid)) throw new Error(`node returned invalid txid: ${String(txid)}`);
    await finish('pass', {
        phase: 'broadcast',
        network: input.network,
        ...nodeEvidence(),
        txid,
        merged_pskb_wire_hex: merged,
        summary,
    });
}

async function verifyCase(input, wallet) {
    if (!/^[0-9a-f]{64}$/i.test(input.txid || '')) throw new Error('missing txid for verification');
    const destination = input.destination;
    if (typeof destination !== 'string' || !destination.startsWith('kaspatest:')) {
        throw new Error('missing funded-E2E destination address');
    }

    const destinationUtxos = JSON.parse(await withFundedNodeRetry(
        wsUrl => wasm.fetch_utxos_for_address_js(destination, wsUrl),
    ));
    const matching = destinationUtxos.find((utxo) => utxo.tx_id?.toLowerCase() === input.txid.toLowerCase());
    if (!matching) {
        await finish('pending', {
            phase: 'verify',
            network: input.network,
            ...nodeEvidence(),
            txid: input.txid,
            destination,
            destination_utxo_count: destinationUtxos.length,
        });
        return;
    }
    const received = asBigInt(matching.amount, 'resulting UTXO amount');
    if (received !== SEND_AMOUNT_SOMPI) {
        throw new Error(`resulting controlled UTXO amount mismatch: expected ${SEND_AMOUNT_SOMPI}, got ${received}`);
    }
    const allUtxos = JSON.parse(await withFundedNodeRetry(
        wsUrl => wasm.fetch_utxos(JSON.stringify(wallet), wsUrl),
    ));
    const balance = walletBalance(allUtxos);
    await finish('pass', {
        phase: 'verify',
        network: input.network,
        ...nodeEvidence(),
        txid: input.txid,
        destination,
        resulting_utxo_amount_sompi: received.toString(),
        wallet_balance_sompi: balance.toString(),
        wallet_utxo_count: allUtxos.length,
    });
}

async function run() {
    const input = await config();
    validateNetwork(input.network);
    await wasm.init();
    const wallet = importWallet(input.kpub, input.network);
    if (input.phase === 'address') return addressCase(input, wallet);
    configureNetwork(input.network);
    switch (input.phase) {
        case 'status': return statusCase(input, wallet);
        case 'prepare': return prepareCase(input, wallet);
        case 'broadcast': return broadcastCase(input);
        case 'verify': return verifyCase(input, wallet);
        default: throw new Error(`unknown funded-E2E phase: ${String(input.phase)}`);
    }
}

try {
    // Keep all network work on real browser time. The page publishes its
    // structured completion result back to the loopback QA server; Python
    // owns the wall-clock deadline and terminates Chromium after completion.
    await run();
} catch (error) {
    await finish('fail', {
        network: networkState.network,
        ...nodeEvidence(),
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : null,
    });
}
