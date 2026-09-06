import * as wasm from '/target/kassee-web/site/js/wasm/api.js';
import { networkState } from '/target/kassee-web/site/js/app/state/index.js';
import { withNodeRetry } from '/target/kassee-web/site/js/features/wallet/core.js';

async function finish(status, detail) {
    document.documentElement.dataset.qaStatus = status;
    document.body.textContent = JSON.stringify(detail);
    await fetch('/__qa_real_node_result__', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, detail }),
    });
}

async function run() {
    const params = new URLSearchParams(location.search);
    const network = params.get('network') || 'mainnet';
    if (network !== 'mainnet') throw new Error(`public-node gate requires mainnet, got: ${network}`);

    networkState.network = network;
    networkState.customNodeUrl = null;

    await wasm.init();
    const attempted = [];
    const result = await withNodeRetry(async wsUrl => {
        attempted.push(wsUrl);
        if (!wsUrl || !(wsUrl.startsWith('ws://') || wsUrl.startsWith('wss://'))) {
            throw new Error(`invalid public wRPC URL: ${String(wsUrl)}`);
        }
        if (/^wss?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(wsUrl)) {
            throw new Error(`resolver returned a local endpoint: ${wsUrl}`);
        }

        const daaText = await wasm.get_virtual_daa_score(wsUrl);
        if (!/^\d+$/.test(daaText)) throw new Error(`invalid DAA score: ${daaText}`);

        const fees = JSON.parse(await wasm.get_fee_estimate(wsUrl));
        if (!fees || typeof fees !== 'object') throw new Error('fee estimate was not an object');

        const address = wasm.encode_p2pk_address('11'.repeat(32), network);
        const utxos = JSON.parse(await wasm.fetch_utxos_for_address_js(address, wsUrl));
        if (!Array.isArray(utxos)) throw new Error('UTXO response was not an array');

        return {
            ws_url: wsUrl,
            daa_score: daaText,
            zero_balance_probe_address: address,
            utxo_count: utxos.length,
            fee_keys: Object.keys(fees).sort(),
        };
    }, 3);

    await finish('pass', {
        mode: 'public-resolver',
        network,
        ...result,
        ws_urls_attempted: attempted,
    });
}

run().catch(async (error) => {
    const detail = {
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : null,
    };
    try {
        await finish('fail', detail);
    } catch (_) {
        document.documentElement.dataset.qaStatus = 'fail';
        document.body.textContent = JSON.stringify(detail);
    }
});
