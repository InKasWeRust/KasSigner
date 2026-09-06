export function createOracleProverClient(baseUrl) {
    const base = (baseUrl || '').replace(/\/+$/, '');
    return async function get(path) {
        const response = await fetch(base + path, { signal: AbortSignal.timeout(15000) });
        let body = null;
        try { body = await response.json(); } catch (_) {}
        return { ok: response.ok, status: response.status, body };
    };
}
