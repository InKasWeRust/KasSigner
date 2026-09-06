// Oracle Model B formatting utilities.
export function formatPrice(mantissa) {
    const value = Number(mantissa) / 1e8;
    return Number.isFinite(value) ? "$" + value.toFixed(8) : "—";
}

export function formatAge(timestampSeconds) {
    let seconds = Math.floor(Date.now() / 1000) - Number(timestampSeconds);
    if (seconds < 0) seconds = 0;
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainder = seconds % 60;
    const text = hours > 0
        ? `${hours}h ${minutes}m ago`
        : minutes > 0 ? `${minutes}m ${remainder}s ago` : `${remainder}s ago`;
    return { txt: "updated " + text, stale: seconds > 1200 };
}

export function shorten(value) {
    return !value ? "—" : value.length > 22 ? value.slice(0, 14) + "…" + value.slice(-6) : value;
}
