import { navigationState, networkState, walletSession } from '../../../app/state/index.js';
import { hideLoading, navigateBack, showLoading, showScreen } from '../../../app/navigation.js';
import { byId } from '../../../core/dom.js';
import { renderBrowserConnectivity } from '../../../core/ui/connectivity_status.js';
import { setScreenReturn, takeScreenReturn, visibleScreenName } from '../../../core/ui/screen_dom.js';
import { toast } from '../../../core/ui/toast.js';
import { startScanner, stopScanner } from '../../stealth/index/camera.js';
import { activateKpubWallet, deriveKpubQrWallet, deriveKpubWallet } from '../core/kpub_import.js';
import { decodeKpubQrImage } from '../core/kpub_image_import.js';
import { clearWalletSession, consumeSkipAutoLoadOnce, hardenedWalletCleanup } from '../state_reset.js';
import { syncWalletUnloadAction } from '../reset.js';
import { kpubRepository } from './repository.js';

function networkLabel(network) {
    if (network === 'mainnet') return 'Mainnet';
    if (network === 'testnet-10') return 'Testnet 10';
    if (network === 'testnet-12') return 'Testnet 12';
    return network;
}

function keyPreview(kpub) {
    if (kpub.length <= 42) return kpub;
    return `${kpub.slice(0, 24)}…${kpub.slice(-14)}`;
}

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
}

function makeButton(label, className, action) {
    const button = makeElement('button', `btn ${className}`, label);
    button.type = 'button';
    button.onclick = event => {
        event?.stopPropagation?.();
        action();
    };
    return button;
}

function activeProfileId() {
    return walletSession.profile()?.id || null;
}

function visibleEntriesForSelectedNetwork() {
    return kpubRepository.list().filter(entry => entry.network === networkState.network);
}

function clearForWalletSwitch() {
    if (walletSession.hasWallet()) hardenedWalletCleanup();
    else clearWalletSession();
}

function clearImportForm() {
    byId('input-kpub-friendly-name').value = '';
    byId('input-managed-kpub').value = '';
    byId('chk-new-kpub-auto-load').checked = false;
    byId('input-managed-kpub-image').value = '';
}

function revealImportForm(options = {}) {
    if (options.clear !== false) clearImportForm();
    byId('kpub-import-form').classList.remove('hidden');
    if (options.focus !== false) byId('input-managed-kpub').focus();
}

function concealImportForm() {
    byId('kpub-import-form').classList.add('hidden');
    clearImportForm();
}

function populateImportCandidate(derived, message) {
    revealImportForm({ clear: false, focus: false });
    byId('input-managed-kpub').value = derived.normalizedKpub;
    byId('input-kpub-friendly-name').focus();
    if (message) toast(message, 'ok', 1800);
}

function renderCurrentStatus() {
    const status = byId('kpub-current-status');
    syncWalletUnloadAction();
    if (!walletSession.hasWallet()) {
        status.textContent = 'Choose a saved kpub to load a wallet.';
        return;
    }
    const profile = walletSession.profile();
    status.textContent = profile
        ? `Currently loaded: ${profile.name}`
        : 'One-time kpub loaded (not saved).';
}

function renderWelcomeEntry(entry) {
    const button = makeElement('button', 'welcome-kpub-entry');
    button.type = 'button';
    button.title = `Load ${entry.name}`;
    button.onclick = () => loadSavedKpub(entry.id);

    const copy = makeElement('span', 'welcome-kpub-copy');
    copy.appendChild(makeElement('strong', 'welcome-kpub-name', entry.name));
    copy.appendChild(makeElement('span', 'welcome-kpub-network', networkLabel(entry.network)));
    button.appendChild(copy);
    button.appendChild(makeElement('span', 'welcome-kpub-load-label', 'Load'));
    return button;
}

export function renderWelcomeKpubs() {
    const section = byId('welcome-saved-kpubs');
    const list = byId('welcome-kpub-list');
    if (!section || !list) return;

    const entries = visibleEntriesForSelectedNetwork();
    list.replaceChildren();
    for (const entry of entries) list.appendChild(renderWelcomeEntry(entry));
    section.classList.toggle('hidden', entries.length === 0);
}

function renameEntry(entry) {
    const name = prompt('Friendly name', entry.name);
    if (name === null) return;
    try {
        const renamed = kpubRepository.rename(entry.id, name);
        if (activeProfileId() === entry.id) walletSession.setProfile(renamed);
        renderKpubManager();
        toast('Friendly name updated', 'ok', 1500);
    } catch (error) {
        toast(String(error), 'error', 3500);
    }
}

function deleteEntry(entry) {
    if (!confirm(`Delete the saved kpub “${entry.name}”? This only removes the public watch-only key from this browser.`)) {
        return;
    }
    const wasActive = activeProfileId() === entry.id;
    kpubRepository.remove(entry.id);
    if (wasActive) walletSession.setProfile(null);
    renderKpubManager();
    toast(
        wasActive
            ? 'Saved entry deleted. The current wallet remains loaded until you switch or reset it.'
            : 'Saved kpub deleted',
        'ok',
        3000,
    );
}

function toggleStartupEntry(entry) {
    try {
        const isStartup = kpubRepository.autoLoadId() === entry.id;
        kpubRepository.setAutoLoad(isStartup ? null : entry.id);
        renderKpubManager();
        toast(isStartup ? 'Startup loading disabled' : `${entry.name} will load on startup`, 'ok', 2200);
    } catch (error) {
        toast(String(error), 'error', 3500);
    }
}

function appendBadge(container, label, className) {
    container.appendChild(makeElement('span', `kpub-entry-badge ${className}`, label));
}

function renderEntry(entry, autoLoadId, activeId) {
    const item = makeElement('article', 'kpub-entry');
    const isActive = activeId === entry.id;
    const isStartup = autoLoadId === entry.id;
    if (isActive) item.classList.add('is-active');
    item.setAttribute('role', 'listitem');
    item.tabIndex = 0;
    item.title = isActive ? `${entry.name} is currently loaded` : `Load ${entry.name}`;
    const loadEntry = () => { if (!isActive) loadSavedKpub(entry.id); };
    item.onclick = event => {
        if (event?.target?.closest?.('button')) return;
        loadEntry();
    };
    item.onkeydown = event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        loadEntry();
    };

    const header = makeElement('div', 'kpub-entry-header');
    header.appendChild(makeElement('h4', 'kpub-entry-name', entry.name));
    header.appendChild(makeElement('span', 'kpub-entry-network', networkLabel(entry.network)));
    item.appendChild(header);

    const key = makeElement('p', 'kpub-entry-key', keyPreview(entry.kpub));
    key.title = entry.kpub;
    item.appendChild(key);

    const badges = makeElement('div', 'kpub-entry-badges');
    if (isActive) appendBadge(badges, 'Active', 'is-active');
    if (isStartup) appendBadge(badges, 'Loads on startup', 'is-startup');
    item.appendChild(badges);

    const actions = makeElement('div', 'kpub-entry-actions');
    actions.appendChild(makeButton(
        isActive ? 'Loaded' : 'Load',
        isActive ? 'btn-secondary' : 'btn-primary',
        loadEntry,
    ));
    actions.appendChild(makeButton(
        isStartup ? 'Stop startup' : 'Load on startup',
        'btn-secondary',
        () => toggleStartupEntry(entry),
    ));
    actions.appendChild(makeButton('Rename', 'btn-secondary', () => renameEntry(entry)));
    actions.appendChild(makeButton('Delete', 'btn-link btn-danger', () => deleteEntry(entry)));
    item.appendChild(actions);
    return item;
}

export function renderKpubManager() {
    const entries = visibleEntriesForSelectedNetwork();
    const list = byId('kpub-saved-list');
    const empty = byId('kpub-empty-state');
    list.replaceChildren();
    byId('kpub-saved-count').textContent = String(entries.length);
    renderCurrentStatus();

    const autoLoadId = kpubRepository.autoLoadId();
    const activeId = activeProfileId();
    for (const entry of entries) list.appendChild(renderEntry(entry, autoLoadId, activeId));
    empty.classList.toggle('hidden', entries.length > 0);
    renderWelcomeKpubs();
}

export function showKpubManager(returnScreen, options = {}) {
    const fallback = walletSession.hasWallet() ? 'dashboard' : 'welcome';
    const source = returnScreen || visibleScreenName(fallback);
    if (source !== 'kpub-manager') {
        navigationState.kpubManagerReturnScreen = source;
        setScreenReturn('kpub-manager', source);
    }
    renderKpubManager();
    if (options.openImport === true) revealImportForm();
    else if (options.preserveImport !== true) concealImportForm();
    showScreen('kpub-manager');
}

export function exitKpubManager() {
    const fallback = walletSession.hasWallet() ? 'dashboard' : 'welcome';
    const target = takeScreenReturn(
        'kpub-manager',
        navigationState.kpubManagerReturnScreen || fallback,
    );
    navigationState.kpubManagerReturnScreen = undefined;
    concealImportForm();
    navigateBack(target === 'kpub-manager' ? fallback : target);
}

export function openKpubImport() {
    revealImportForm();
}

export function closeKpubImport() {
    concealImportForm();
}

export function useKpubOnce() {
    const kpubInput = byId('input-managed-kpub');
    let derived;
    try {
        derived = deriveKpubWallet(kpubInput.value, networkState.network);
    } catch (error) {
        toast(`Could not load kpub: ${error}`, 'error', 5000);
        return false;
    }
    if (walletSession.hasWallet() && !confirm(
        'Switch to this one-time kpub? Any in-progress transaction/session state will be discarded.',
    )) return false;

    showLoading('Loading one-time kpub…');
    clearForWalletSwitch();
    activateKpubWallet(derived.walletData, { profile: null, successScreen: 'dashboard' });
    clearImportForm();
    toast('One-time kpub loaded. It was not saved.', 'ok', 2400);
    return true;
}

export function scanManagedKpub() {
    startScanner('Scan kpub QR with camera', data => {
        try {
            const derived = deriveKpubQrWallet(data, networkState.network);
            stopScanner();
            populateImportCandidate(derived, 'kpub scanned. Review and save it.');
        } catch (error) {
            stopScanner();
            revealImportForm({ clear: false });
            toast(`QR scan failed: ${error}`, 'error', 5000);
        }
    });
}

export async function uploadManagedKpubImage(file) {
    if (!file) return;
    try {
        const decoded = await decodeKpubQrImage(file);
        const derived = deriveKpubQrWallet(decoded.payload, networkState.network);
        populateImportCandidate(derived, 'kpub QR image loaded. Review and save it.');
    } catch (error) {
        toast(`QR image import failed: ${error.message || error}`, 'error', 5000);
    }
}

export function saveManagedKpub() {
    const nameInput = byId('input-kpub-friendly-name');
    const kpubInput = byId('input-managed-kpub');
    const autoLoad = byId('chk-new-kpub-auto-load').checked;
    const friendlyName = nameInput.value.trim();
    showLoading(friendlyName ? `Loading ${friendlyName}…` : 'Loading wallet…');
    try {
        const derived = deriveKpubWallet(kpubInput.value, networkState.network);
        const entry = kpubRepository.save({
            name: nameInput.value,
            kpub: derived.normalizedKpub,
            network: networkState.network,
        });
        if (autoLoad) kpubRepository.setAutoLoad(entry.id);
        clearForWalletSwitch();
        activateKpubWallet(derived.walletData, {
            profile: entry,
            successScreen: 'dashboard',
        });
        clearImportForm();
        toast(`${entry.name} saved and loaded`, 'ok', 2000);
        return true;
    } catch (error) {
        hideLoading();
        renderKpubManager();
        showScreen('kpub-manager');
        revealImportForm({ clear: false, focus: false });
        toast(`Could not load kpub: ${error}`, 'error', 5000);
        return false;
    }
}

export function loadSavedKpub(id, options = {}) {
    const entry = kpubRepository.get(id);
    if (!entry) {
        if (!options.startup) toast('Saved kpub not found', 'error', 2500);
        return false;
    }
    if (walletSession.hasWallet() && activeProfileId() === entry.id) {
        showScreen('dashboard');
        return true;
    }
    if (!options.startup && walletSession.hasWallet()) {
        const current = walletSession.profile()?.name || 'the current wallet';
        if (!confirm(`Switch from ${current} to ${entry.name}? Any in-progress unsigned transaction will be discarded.`)) {
            return false;
        }
    }

    showLoading(`Loading ${entry.name}…`);
    try {
        const derived = deriveKpubWallet(entry.kpub, entry.network);
        clearForWalletSwitch();
        if (networkState.network !== entry.network) {
            networkState.network = entry.network;
            renderBrowserConnectivity();
        }
        activateKpubWallet(derived.walletData, {
            profile: entry,
            successScreen: 'dashboard',
        });
        if (!options.startup) toast(`${entry.name} loaded`, 'ok', 1800);
        return true;
    } catch (error) {
        hideLoading();
        if (options.startup) {
            renderWelcomeKpubs();
            showScreen('welcome');
        } else {
            showKpubManager('welcome');
        }
        if (!options.startup) toast(`Unable to load ${entry.name}: ${error}`, 'error', 5000);
        return false;
    }
}

export function routeStartupKpub() {
    if (consumeSkipAutoLoadOnce()) {
        const entries = kpubRepository.list();
        renderWelcomeKpubs();
        showScreen('welcome');
        return { state: entries.length > 0 ? 'selection' : 'empty', entry: null, count: entries.length };
    }
    const startupEntry = kpubRepository.autoLoadEntry();
    if (startupEntry) {
        const loaded = loadSavedKpub(startupEntry.id, { startup: true });
        return { state: loaded ? 'loaded' : 'failed', entry: startupEntry };
    }

    const entries = kpubRepository.list();
    renderWelcomeKpubs();
    showScreen('welcome');
    return {
        state: entries.length > 0 ? 'selection' : 'empty',
        entry: null,
        count: entries.length,
    };
}
