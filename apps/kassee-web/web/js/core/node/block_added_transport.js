import { build_vcc_subscribe_request } from '../../wasm/api.js';
import { resolveNodeUrl } from './resolver.js';

export function createBlockAddedTransport(options) {
    let socket = null;
    let reconnectTimer = null;
    let stopped = true;

    function clearReconnectTimer() {
        if (reconnectTimer === null) return;
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    function closeSocket() {
        const current = socket;
        socket = null;
        if (!current) return;
        try { current.close(); } catch (_) {}
    }

    function scheduleReconnect(delay) {
        clearReconnectTimer();
        if (stopped || !options.isActive()) return;
        reconnectTimer = setTimeout(start, delay);
    }

    async function start() {
        stopped = false;
        clearReconnectTimer();
        closeSocket();
        if (!options.isActive()) return;
        try {
            const wsUrl = await resolveNodeUrl();
            if (stopped || !options.isActive()) return;
            const request = new Uint8Array(build_vcc_subscribe_request(43n));
            const current = new WebSocket(wsUrl);
            current.binaryType = 'arraybuffer';
            socket = current;
            current.onopen = () => {
                if (socket === current && !stopped) current.send(request);
            };
            current.onmessage = event => {
                if (socket !== current || stopped) return;
                options.onPayload(new Uint8Array(event.data));
            };
            current.onerror = () => {};
            current.onclose = () => {
                if (socket !== current) return;
                socket = null;
                scheduleReconnect(options.reconnectDelay ?? 3000);
            };
        } catch (error) {
            console.warn(`[KasSee] ${options.label} BlockAdded transport failed:`, error);
            scheduleReconnect(options.retryDelay ?? 5000);
        }
    }

    function stop() {
        stopped = true;
        clearReconnectTimer();
        closeSocket();
    }

    return Object.freeze({ start, stop });
}
