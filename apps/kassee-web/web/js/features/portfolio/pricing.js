const COINGECKO_SIMPLE = 'https://api.coingecko.com/api/v3/simple/price?ids=kaspa&vs_currencies=usd';
const COINGECKO_CHART = 'https://api.coingecko.com/api/v3/coins/kaspa/market_chart?vs_currency=usd';
const COINPAPRIKA = 'https://api.coinpaprika.com/v1/tickers/kas-kaspa';
let bundledHistoryPromise;

function externalUsdToMicro(value, field) {
    const text = String(value).trim();
    const match = text.match(/^(\d+)(?:\.(\d+))?$/);
    if (!match) throw new Error(`${field} is not a decimal price`);
    const fraction = match[2] || '';
    const firstSix = (fraction + '000000').slice(0, 6);
    let micro = BigInt(match[1]) * 1_000_000n + BigInt(firstSix);
    if (fraction.length > 6 && fraction[6] >= '5') micro += 1n;
    return micro;
}

function decimalLiteral(text, pattern, field) {
    const match = text.match(pattern);
    if (!match) throw new Error(`${field} is missing`);
    return match[1];
}

async function fetchText(url, timeoutMs = 12_000) {
    const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.text();
}

async function coinGeckoPrice() {
    const text = await fetchText(COINGECKO_SIMPLE);
    const value = decimalLiteral(text, /"usd"\s*:\s*([0-9]+(?:\.[0-9]+)?)/, 'CoinGecko USD price');
    return externalUsdToMicro(value, 'CoinGecko USD price');
}

async function coinPaprikaPrice() {
    const text = await fetchText(COINPAPRIKA);
    const value = decimalLiteral(text, /"price"\s*:\s*([0-9]+(?:\.[0-9]+)?)/, 'CoinPaprika USD price');
    return externalUsdToMicro(value, 'CoinPaprika USD price');
}

export async function fetchCurrentPriceMicro() {
    try {
        return await coinGeckoPrice();
    } catch (_) {
        return coinPaprikaPrice();
    }
}

function parseBundledCsv(text) {
    const points = [];
    for (const line of text.split(/\r?\n/).slice(1)) {
        if (!line.trim()) continue;
        const [timestamp, _open, _high, _low, close] = line.split(',');
        const timestampMs = Date.parse(timestamp);
        if (!Number.isFinite(timestampMs) || !close) continue;
        points.push({ timestampMs, priceMicroUsd: externalUsdToMicro(close, 'bundled historical price') });
    }
    return points;
}

export function loadBundledHistory() {
    if (!bundledHistoryPromise) {
        bundledHistoryPromise = fetch('data/kaspa_daily_usd.csv', { cache: 'force-cache' })
            .then(response => {
                if (!response.ok) throw new Error(`historical price HTTP ${response.status}`);
                return response.text();
            })
            .then(parseBundledCsv);
    }
    return bundledHistoryPromise;
}

function arraySegment(raw, key) {
    const start = raw.indexOf(`"${key}"`);
    const open = raw.indexOf('[', start);
    if (start < 0 || open < 0) return '';
    let depth = 0;
    for (let index = open; index < raw.length; index += 1) {
        if (raw[index] === '[') depth += 1;
        if (raw[index] === ']') depth -= 1;
        if (depth === 0) return raw.slice(open, index + 1);
    }
    return '';
}

function parseCoinGeckoHistory(raw) {
    const segment = arraySegment(raw, 'prices');
    const points = [];
    const pair = /\[(\d+),\s*([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?\d+)?)\]/g;
    for (const match of segment.matchAll(pair)) {
        const timestampMs = Number.parseInt(match[1], 10);
        if (!Number.isSafeInteger(timestampMs)) continue;
        points.push({ timestampMs, priceMicroUsd: externalUsdToMicro(expandExponent(match[2]), 'CoinGecko historical price') });
    }
    return points;
}

function expandExponent(value) {
    if (!/[eE]/.test(value)) return value;
    const match = value.match(/^(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$/);
    if (!match) throw new Error('invalid historical price');
    const digits = `${match[1]}${match[2] || ''}`;
    const decimalIndex = match[1].length + Number.parseInt(match[3], 10);
    if (decimalIndex <= 0) return `0.${'0'.repeat(-decimalIndex)}${digits}`;
    if (decimalIndex >= digits.length) return `${digits}${'0'.repeat(decimalIndex - digits.length)}`;
    return `${digits.slice(0, decimalIndex)}.${digits.slice(decimalIndex)}`;
}

async function remoteHistory(days) {
    const safeDays = Math.max(1, Math.min(365, Number.parseInt(days, 10) || 30));
    const text = await fetchText(`${COINGECKO_CHART}&days=${safeDays}&interval=daily`, 15_000);
    return parseCoinGeckoHistory(text);
}

function mergeHistory(primary, fallback) {
    const byDay = new Map();
    for (const point of fallback) byDay.set(new Date(point.timestampMs).toISOString().slice(0, 10), point);
    for (const point of primary) byDay.set(new Date(point.timestampMs).toISOString().slice(0, 10), point);
    return [...byDay.values()].sort((left, right) => left.timestampMs - right.timestampMs);
}

function historyWindow(points, days) {
    const safeDays = Math.max(1, Math.min(365, Number.parseInt(days, 10) || 30));
    const cutoff = Date.now() - safeDays * 86_400_000;
    return points.filter(point => point.timestampMs >= cutoff);
}

export async function loadHistoricalPrices(days = 90) {
    const fallback = historyWindow(await loadBundledHistory(), days);
    try {
        return mergeHistory(await remoteHistory(days), fallback);
    } catch (_) {
        return fallback;
    }
}

export function historicalPriceAt(points, timestampMs) {
    if (!points.length) return 0n;
    if (timestampMs <= points[0].timestampMs) return points[0].priceMicroUsd;
    const last = points.at(-1);
    if (timestampMs >= last.timestampMs) return last.priceMicroUsd;
    let lower = 0;
    let upper = points.length - 1;
    while (upper - lower > 1) {
        const middle = Math.floor((lower + upper) / 2);
        if (points[middle].timestampMs <= timestampMs) lower = middle;
        else upper = middle;
    }
    const previous = points[lower];
    const next = points[upper];
    const interval = BigInt(next.timestampMs - previous.timestampMs);
    if (interval <= 0n) return previous.priceMicroUsd;
    const elapsed = BigInt(timestampMs - previous.timestampMs);
    const delta = next.priceMicroUsd - previous.priceMicroUsd;
    return previous.priceMicroUsd + (delta * elapsed) / interval;
}
