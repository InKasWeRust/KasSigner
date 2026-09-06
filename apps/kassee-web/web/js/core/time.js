/** Format a millisecond timestamp as a compact relative age. */
export function timeAgo(timestampMs, nowMs = Date.now()) {
    const minutes = Math.floor(Math.max(0, nowMs - timestampMs) / 60_000);
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
}
