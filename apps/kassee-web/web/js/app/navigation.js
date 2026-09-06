import { covenantState, navigationState, networkState, walletSession } from './state/index.js';
import { covLoadActive } from '../features/covenants/recovery/active.js';
import { startAutoRefresh, stopAutoRefresh } from '../features/wallet/core.js';
import { init, version } from '../wasm/api.js';
import { markWasmFailed, markWasmReady } from '../wasm/runtime.js';
import { parseCovenantJson } from '../features/covenants/model/exact_fields.js';
// KasSee Web — app/navigation
// Owns application startup, screen navigation, and session restoration.

import { byId } from '../core/dom.js';
import { activateScreen, visibleScreenName } from '../core/ui/screen_dom.js';
import { installBackHomeControls } from '../core/ui/navigation_controls.js';

import { bindEvents } from './events/index.js';


// ─── Init ───

export async function start() {
    installBackHomeControls(navigateHome);
    showScreen('welcome', { recordHistory: false });
    setStartupStatus('Initializing the KasSee security engine…', 'loading');
    const eventBindingFailures = bindEvents();
    let wasmStarted = false;

    try {
        await init();
        markWasmReady();
        wasmStarted = true;
        console.log(version());
        if (eventBindingFailures.length > 0) {
            setStartupStatus('KasSee loaded, but some controls could not be connected. Check the browser console.', 'warning');
        } else {
            setStartupStatus('KasSee is ready.', 'ready');
        }
    } catch (error) {
        markWasmFailed(error);
        console.error('KasSee WebAssembly initialization failed:', error);
        setStartupStatus(
            'KasSee controls are available, but the WebAssembly engine is missing. Run `make kassee`, then reload this page.',
            'error',
        );
    }

    // Restore covenant context from sessionStorage (survives reload, dies on tab close)
    try {
        const saved = sessionStorage.getItem('lastCovenantResult');
        if (saved) covenantState.lastCovenantResult = parseCovenantJson(saved);
    } catch (_) {}
    covLoadActive();

    if (wasmStarted) {
        try {
            const { routeStartupKpub } = await import('../features/wallet/kpub_manager/index.js');
            const startupRoute = routeStartupKpub();
            if (startupRoute.state === 'loaded') {
                const suffix = eventBindingFailures.length > 0
                    ? ' Some controls could not be connected; check the browser console.'
                    : '';
                setStartupStatus(`Loaded saved wallet “${startupRoute.entry.name}”.${suffix}`, eventBindingFailures.length > 0 ? 'warning' : 'ready');
            } else if (startupRoute.state === 'failed') {
                setStartupStatus(
                    `KasSee could not load saved wallet “${startupRoute.entry.name}”. Choose another saved kpub or load a new one.`,
                    'warning',
                );
            } else if (startupRoute.state === 'selection') {
                setStartupStatus('Choose a saved kpub to continue.', 'ready');
            } else {
                setStartupStatus('No saved kpubs yet. Use Load kpub to add one.', 'ready');
            }
        } catch (error) {
            console.error('KasSee saved-kpub startup failed:', error);
            setStartupStatus('KasSee is ready, but saved kpubs could not be read from browser storage.', 'warning');
        }
    }

}

export function setStartupStatus(message, state) {
    const status = byId('kassee-startup-status');
    if (!status) return;
    status.textContent = message || '';
    status.dataset.state = state || '';
}

navigationState.currentScreenName = 'welcome';

const MAX_SCREEN_HISTORY = 64;

function recordHistory(nextScreen) {
    const current = visibleScreenName(navigationState.currentScreenName || 'welcome');
    if (!current || current === nextScreen) return;
    const history = navigationState.screenHistory;
    if (history.at(-1) !== current) history.push(current);
    if (history.length > MAX_SCREEN_HISTORY) history.splice(0, history.length - MAX_SCREEN_HISTORY);
}

export function showScreen(name, options = {}) {
    if (options.recordHistory !== false) recordHistory(name);
    if (!activateScreen(name)) return false;
    navigationState.currentScreenName = name;
    // Auto-refresh when on dashboard
    if (name === 'dashboard' && walletSession.hasWallet()) {
        startAutoRefresh();
    } else {
        stopAutoRefresh();
    }
    return true;
}

export function navigateBack(fallback) {
    const current = visibleScreenName(navigationState.currentScreenName || 'welcome');
    const defaultTarget = fallback || (walletSession.hasWallet() ? 'dashboard' : 'welcome');
    let target = defaultTarget;
    while (navigationState.screenHistory.length > 0) {
        const candidate = navigationState.screenHistory.pop();
        if (candidate && candidate !== current && document.getElementById(`screen-${candidate}`)) {
            target = candidate;
            break;
        }
    }
    closeGearMenu();
    return showScreen(target, { recordHistory: false });
}

export function navigateHome() {
    navigationState.screenHistory.length = 0;
    closeGearMenu();
    const target = walletSession.hasWallet() ? 'dashboard' : 'welcome';
    return showScreen(target, { recordHistory: false });
}

export function clearNavigationHistory() {
    navigationState.screenHistory.length = 0;
}
export function showLoading(msg) {
    byId('loading-msg').textContent = msg || 'Loading...';
    byId('loading').classList.remove('hidden');
}
export function hideLoading() {
    byId('loading').classList.add('hidden');
}
export function setStatus(state, label) {
    const dot = document.querySelector('#status-dot .dot');
    const lbl = document.querySelector('#status-dot .label');
    dot.className = `dot ${state}`;
    const netTag = networkState.network !== 'mainnet' ? ` [${networkState.network.toUpperCase()}]` : '';
    lbl.textContent = label + netTag;
}
export function toggleGearMenu() {
    const menu = byId('gear-menu');
    const btn = byId('btn-header-settings');
    if (menu.classList.contains('visible')) {
        menu.classList.remove('visible');
        btn.classList.remove('active');
    } else {
        menu.classList.add('visible');
        btn.classList.add('active');
    }
}
export function closeGearMenu() {
    byId('gear-menu').classList.remove('visible');
    byId('btn-header-settings').classList.remove('active');
}
