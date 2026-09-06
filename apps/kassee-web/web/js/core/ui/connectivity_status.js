import { byId } from '../dom.js';

function statusParts() {
    return {
        dot: document.querySelector('#status-dot .dot'),
        label: document.querySelector('#status-dot .label'),
    };
}

export function browserIsOnline() {
    return typeof navigator === 'undefined' || navigator.onLine !== false;
}

export function renderBrowserConnectivity() {
    const { dot, label } = statusParts();
    if (!dot || !label || !byId('status-dot')) return;
    const online = browserIsOnline();
    dot.className = `dot ${online ? 'online' : 'offline'}`;
    label.textContent = online ? 'Online' : 'Offline';
}

export function renderNodeUnavailable() {
    const { dot, label } = statusParts();
    if (!dot || !label) return;
    if (!browserIsOnline()) {
        renderBrowserConnectivity();
        return;
    }
    dot.className = 'dot offline';
    label.textContent = 'Node unavailable';
}

export function bindBrowserConnectivity() {
    renderBrowserConnectivity();
    globalThis.addEventListener?.('online', renderBrowserConnectivity);
    globalThis.addEventListener?.('offline', renderBrowserConnectivity);
}
