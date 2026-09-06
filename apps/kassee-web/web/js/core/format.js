import { exactUnsigned } from './exact.js';
// Pure presentation helpers shared across browser features.


export function durationPartsToSeconds({
    years = 0,
    months = 0,
    days = 0,
    hours = 0,
    minutes = 0,
} = {}) {
    return years * 31536000
        + months * 2592000
        + days * 86400
        + hours * 3600
        + minutes * 60;
}

export function formatDuration(seconds) {
    if (seconds <= 0) return '0s';
    const parts = [];
    const units = [
        [31536000, 'y'],
        [2592000, 'mo'],
        [86400, 'd'],
        [3600, 'h'],
        [60, 'min'],
        [1, 's'],
    ];
    let remaining = Math.floor(seconds);
    for (const [size, suffix] of units) {
        const count = Math.floor(remaining / size);
        if (count) {
            parts.push(`${count}${suffix}`);
            remaining %= size;
        }
    }
    return parts.join(' ');
}

export function formatDaaDuration(deltaDaa) {
    const seconds = exactUnsigned(deltaDaa, 'DAA delta') / 10n;
    if (seconds > BigInt(Number.MAX_SAFE_INTEGER)) return 'very long';
    return formatDuration(Number(seconds));
}

export function formatStartDate(covenant, lastKnownDaa = 0n) {
    if (covenant.start_date_iso) {
        try {
            return new Date(covenant.start_date_iso).toLocaleString();
        } catch (_) {}
    }
    const daa = exactUnsigned(covenant.start_daa ?? covenant.locktime_daa ?? 0n, 'covenant DAA');
    const current = exactUnsigned(lastKnownDaa ?? 0n, 'current DAA');
    if (daa > 0n && current > 0n) {
        const differenceSeconds = (daa - current) / 10n;
        const maxDateSeconds = BigInt(Math.floor((8.64e15 - Date.now()) / 1000));
        if (differenceSeconds >= 0n && differenceSeconds <= maxDateSeconds) {
            return '~' + new Date(Date.now() + Number(differenceSeconds) * 1000).toLocaleString();
        }
    }
    return 'DAA ' + daa.toString();
}

export function formatSeconds(seconds) {
    if (seconds == null || seconds <= 0) return '';
    if (seconds < 1) return '< 1s';
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return Math.round(seconds / 60) + 'min';
    return Math.round(seconds / 3600) + 'h';
}

export function formatTransactionTime(blockTimeMs) {
    const date = new Date(blockTimeMs);
    const differenceMs = Date.now() - blockTimeMs;
    if (differenceMs < 60000) return 'just now';
    if (differenceMs < 3600000) return Math.floor(differenceMs / 60000) + 'm ago';
    if (differenceMs < 86400000) return Math.floor(differenceMs / 3600000) + 'h ago';
    if (differenceMs < 604800000) return Math.floor(differenceMs / 86400000) + 'd ago';
    const month = date.toLocaleString('en', { month: 'short' });
    const day = date.getDate();
    const year = date.getFullYear();
    const hour = date.getHours().toString().padStart(2, '0');
    const minute = date.getMinutes().toString().padStart(2, '0');
    return `${month} ${day}, ${year} ${hour}:${minute}`;
}

export function shortenHex(hex, edgeLength = 10) {
    if (!hex || hex.length <= edgeLength * 2) return hex;
    return hex.slice(0, edgeLength) + '\u2026' + hex.slice(-edgeLength);
}

export function emphasizeAddress(address) {
    const escapeHtml = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (!/^[a-z0-9:]+$/i.test(address)) return escapeHtml(address);
    const colon = address.indexOf(':') + 1;
    const firstEnd = Math.min(colon + 8, address.length);
    const lastStart = Math.max(address.length - 8, firstEnd);
    return address.slice(0, colon)
        + '<span class="addr-hl">' + address.slice(colon, firstEnd) + '</span>'
        + address.slice(firstEnd, lastStart)
        + '<span class="addr-hl">' + address.slice(lastStart) + '</span>';
}
