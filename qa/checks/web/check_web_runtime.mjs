#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isolateWebPackage } from './web_pkg_fixture.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..', '..', '..');
const webRoot = path.join(root, 'apps', 'kassee-web', 'web');
const jsRoot = path.join(webRoot, 'js');
const pkgDir = path.join(webRoot, 'pkg');
const generatedModule = path.join(pkgDir, 'kassee_web.js');

function parseWasmExports(source) {
    const match = source.match(/const\s+GENERATED_WASM_EXPORTS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\);/);
    if (!match) throw new Error('Unable to parse wasm/api.js export inventory');
    return ['init', ...[...match[1].matchAll(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g)].map(item => item[1])];
}

function buildWasmStub(names) {
    return names.map(name => {
        if (name === 'init') {
            return `export default async function init() {
                if (globalThis.__KASSEE_TEST_INIT_FAILURE__) throw new Error('intentional WASM init failure');
            }`;
        }
        if (name === 'version') return "export function version() { return 'web-runtime-smoke'; }";
        if (name === 'import_kpub') {
            return `export function import_kpub(kpub) {
                return JSON.stringify({
                    kpub,
                    receive_addresses: ['kaspa:runtime-receive'],
                    change_addresses: ['kaspa:runtime-change'],
                    next_receive_index: 0,
                    next_change_index: 0,
                });
            }`;
        }
        if (name === 'import_kpub_raw') {
            return `export function import_kpub_raw() {
                return JSON.stringify({
                    kpub: 'kpub1:${'22'.repeat(78)}',
                    receive_addresses: ['kaspa:runtime-receive'],
                    change_addresses: ['kaspa:runtime-change'],
                    next_receive_index: 0,
                    next_change_index: 0,
                });
            }`;
        }
        if (name === 'parse_kpub') {
            return "export function parse_kpub() { return JSON.stringify({ account_pubkey: '02' + '11'.repeat(32) }); }";
        }
        if (name === 'scan_multisig_branch_js') {
            return `export async function scan_multisig_branch_js(requestJson) {
                const request = JSON.parse(requestJson);
                const prefix = request.address_prefix || 'kaspa';
                globalThis.__KASSEE_TEST_MS_SCAN_REQUEST__ = request;
                return JSON.stringify({
                    balance_sompi: '0',
                    utxo_count: 0,
                    utxos: [],
                    next_receive_index: 0,
                    next_receive_address: prefix + ':runtime-ms-receive',
                    next_change_index: 0,
                    next_change_address: prefix + ':runtime-ms-change',
                    cosigner_index: request.cosigner_index,
                    depth: 40,
                });
            }`;
        }
        return `export function ${name}(...args) { void args; return ''; }`;
    }).join('\n') + '\n';
}

function createClassList(initial = []) {
    const classes = new Set(initial);
    return {
        add(...names) { names.forEach(name => classes.add(name)); },
        remove(...names) { names.forEach(name => classes.delete(name)); },
        toggle(name, force) {
            if (force === true) classes.add(name);
            else if (force === false) classes.delete(name);
            else if (classes.has(name)) classes.delete(name);
            else classes.add(name);
        },
        contains(name) { return classes.has(name); },
    };
}

function createElement(id = '', classes = []) {
    const element = {
        id,
        classList: createClassList(classes),
        style: {}, dataset: {}, value: '', textContent: '', innerHTML: '', checked: false,
        files: [], onclick: null, onchange: null, onkeydown: null,
        parentElement: null, previousElementSibling: null,
        querySelectorAll() { return []; }, querySelector() { return null; }, closest() { return null; },
        addEventListener() {}, appendChild() {}, replaceChildren() {}, insertBefore() {}, remove() {}, focus() {}, play() {},
        click() { if (typeof this.onclick === 'function') this.onclick({ target: this }); },
        getAttribute() { return null; }, setAttribute() {},
        getContext() {
            return {
                drawImage() {},
                getImageData() { return { data: new Uint8ClampedArray(4), width: 1, height: 1 }; },
            };
        },
    };
    return new Proxy(element, {
        get(target, property) { return property in target ? target[property] : undefined; },
        set(target, property, value) { target[property] = value; return true; },
    });
}

function createStorage() {
    const values = new Map();
    return {
        get length() { return values.size; },
        getItem(key) { return values.has(key) ? values.get(key) : null; },
        setItem(key, value) { values.set(key, String(value)); },
        removeItem(key) { values.delete(key); },
        clear() { values.clear(); },
        key(index) { return [...values.keys()][index] ?? null; },
    };
}

async function installBrowserStubs() {
    const html = await fs.readFile(path.join(webRoot, 'index.html'), 'utf8');
    const elements = new Map();
    for (const match of html.matchAll(/<([A-Za-z][A-Za-z0-9:-]*)\b([^>]*?\bid="([^"]+)"[^>]*)>/g)) {
        const attributes = match[2];
        const id = match[3];
        const classMatch = attributes.match(/\bclass="([^"]+)"/);
        const classes = classMatch ? classMatch[1].split(/\s+/).filter(Boolean) : [];
        elements.set(id, createElement(id, classes));
    }

    globalThis.window = globalThis;
    const windowListeners = new Map();
    globalThis.addEventListener = (name, handler) => windowListeners.set(name, handler);
    const statusDot = createElement('', ['dot', 'connecting']);
    const statusLabel = createElement();
    statusLabel.textContent = 'Checking';
    globalThis.document = {
        getElementById(id) { return elements.get(id) || null; },
        querySelector(selector) {
            if (selector === '#status-dot .dot') return statusDot;
            if (selector === '#status-dot .label') return statusLabel;
            if (selector === '.screen.active') {
                return [...elements.values()].find(element =>
                    element.id.startsWith('screen-') && element.classList.contains('active')) || null;
            }
            if (selector === 'main') return elements.get('main') || createElement('main');
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '.screen') {
                return [...elements.values()].filter(element => element.id.startsWith('screen-'));
            }
            if (selector === '.gear-tab') {
                return [...elements.values()].filter(element => element.id.startsWith('gear-tab-'));
            }
            return [];
        },
        addEventListener() {},
        createElement() { return createElement(); },
        body: createElement(),
    };
    for (const target of ['kpub-manager', 'addresses', 'utxos', 'tokens', 'history', 'settings']) {
        const tab = elements.get(`gear-tab-${target}`);
        if (tab) tab.dataset.target = target;
    }
    globalThis.localStorage = createStorage();
    globalThis.sessionStorage = createStorage();
    Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: {
            clipboard: { async writeText(text) { elements.get('donate-address').dataset.copied = text; } },
            mediaDevices: { async getUserMedia() { return { getTracks: () => [] }; } },
            onLine: true,
        },
    });
    globalThis.__KASSEE_TEST_RELOADS__ = 0;
    globalThis.location = { href: 'http://localhost/', reload() { globalThis.__KASSEE_TEST_RELOADS__ += 1; } };
    globalThis.fetch = async () => ({ ok: false, status: 404, async json() { return {}; }, async text() { return ''; } });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};
    globalThis.setTimeout = () => 1;
    globalThis.clearTimeout = () => {};
    globalThis.requestAnimationFrame = () => 1;
    globalThis.cancelAnimationFrame = () => {};
    globalThis.QRCode = function QRCode() {};
    globalThis.jsQR = () => null;
    globalThis.alert = () => {};
    globalThis.confirm = () => false;
    globalThis.prompt = () => null;
    globalThis.Image = class Image { async decode() {} };

    elements.set('__status-dot', statusDot);
    elements.set('__status-label', statusLabel);
    return elements;
}

const pkgFixture = await isolateWebPackage(pkgDir);
try {
    const apiSource = await fs.readFile(path.join(jsRoot, 'wasm', 'api.js'), 'utf8');
    const wasmExports = parseWasmExports(apiSource);

    const elements = await installBrowserStubs();
    const globalsBeforeStartup = new Set(Reflect.ownKeys(globalThis));
    const startupErrors = [];
    const originalError = console.error;
    console.error = (...args) => startupErrors.push(args.map(String).join(' '));

    const { bindShellControls } = await import(pathToFileURL(path.join(jsRoot, 'app', 'shell_controls.js')).href);
    bindShellControls();
    assert.equal(elements.get('__status-label').textContent, 'Online',
        'active browser connectivity must not be labeled Offline');
    assert.equal(elements.get('__status-dot').className, 'dot online',
        'active browser connectivity must use the online indicator');
    elements.get('btn-header-settings').click();
    assert.equal(elements.get('gear-menu').classList.contains('visible'), true,
        'settings cog must open the gear menu before the application module graph loads');
    elements.get('btn-header-settings').click();
    assert.equal(elements.get('gear-menu').classList.contains('visible'), false,
        'settings cog must close the gear menu when tapped again');
    elements.get('btn-logo').click();
    assert.equal(elements.get('screen-donate').classList.contains('active'), true,
        'logo must open the donation page before the application module graph loads');
    elements.get('donate-qr').click();
    await Promise.resolve();
    assert.match(elements.get('donate-address').dataset.copied, /^kaspa:/,
        'clicking the donation QR must copy the donation address');
    elements.get('btn-donate-skip').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'Close must leave the donation page');
    elements.get('btn-logo').click();
    elements.get('btn-logo').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'logo must toggle an open donation page closed');
    elements.get('btn-scan-kpub').click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(elements.get('screen-kpub-manager').classList.contains('active'), true,
        'Load kpub must open centralized kpub management before the application module graph loads');
    assert.equal(elements.get('kpub-import-form').classList.contains('hidden'), false,
        'Load kpub must reveal the managed camera, image, and text import form');
    elements.get('btn-header-settings').click();
    elements.get('gear-tab-kpub-manager').click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(elements.get('screen-kpub-manager').classList.contains('active'), true,
        'kpub management must open from the settings cog in shell mode');
    elements.get('btn-kpub-manager-back').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'kpub management Back must return to Welcome in shell mode');
    elements.get('btn-header-settings').click();
    elements.get('gear-tab-settings').click();
    assert.equal(elements.get('screen-settings').classList.contains('active'), true,
        'Node Connection must open from Welcome in shell mode');
    elements.get('btn-settings-back').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'settings Back must return to Welcome in shell mode');

    const { startApplication } = await import(pathToFileURL(path.join(jsRoot, 'app', 'bootstrap.js')).href);
    await startApplication();
    // Exercise the real stable entry module under V8 coverage as well. The entry
    // intentionally owns only shell binding + bootstrap dispatch, so importing it
    // here proves every reachable js/ module has an explicit trace record without
    // fabricating synthetic zero-coverage entries.
    await import(`${pathToFileURL(path.join(jsRoot, 'main.js')).href}?runtime-coverage-entry=1`);
    await new Promise(resolve => setImmediate(resolve));
    elements.get('btn-logo').click();
    assert.equal(elements.get('screen-donate').classList.contains('active'), true,
        'full application logo handler must open the donation page');
    elements.get('btn-logo').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'full application logo handler must close an already-open donation page');

    assert.equal(typeof elements.get('btn-scan-kpub').onclick, 'function',
        'the centralized Load kpub entry point must bind when the generated WASM package is missing');
    assert.equal(typeof elements.get('btn-open-kpub-import').onclick, 'function',
        'the kpub manager Load kpub button must be wired');
    assert.equal(typeof elements.get('btn-scan-managed-kpub').onclick, 'function',
        'managed camera QR import must be wired');
    assert.equal(typeof elements.get('btn-upload-managed-kpub').onclick, 'function',
        'managed QR image import must be wired');
    assert.equal(typeof elements.get('input-managed-kpub-image').onchange, 'function',
        'managed QR image file selection must be wired');
    assert.equal(typeof elements.get('input-kpub-friendly-name').onkeydown, 'function',
        'managed kpub naming must support Enter');
    assert.equal(typeof elements.get('btn-load-signed-qr-image').onclick, 'function',
        'signed transaction QR image import button must be wired');
    assert.equal(typeof elements.get('input-signed-qr-image').onchange, 'function',
        'signed transaction QR image file selection must be wired');
    assert.equal(typeof elements.get('btn-header-settings').onclick, 'function',
        'settings cog must remain wired after full application startup');
    assert.equal(typeof elements.get('btn-save-managed-kpub').onclick, 'function',
        'saved kpub creation must be wired after full application startup');
    assert.equal(typeof elements.get('btn-use-current-kpub').onclick, 'function',
        'current-wallet kpub capture must be wired after full application startup');
    elements.get('btn-scan-kpub').click();
    assert.equal(elements.get('screen-kpub-manager').classList.contains('active'), true,
        'Load kpub must open centralized kpub management');
    assert.equal(elements.get('kpub-import-form').classList.contains('hidden'), false,
        'centralized kpub management must reveal all import methods');
    elements.get('btn-header-settings').click();
    elements.get('gear-tab-kpub-manager').click();
    assert.equal(elements.get('screen-kpub-manager').classList.contains('active'), true,
        'kpub management must open from the settings cog after application startup');
    elements.get('btn-kpub-manager-back-top').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'kpub management Back must return to Welcome after application startup');
    elements.get('btn-scan-kpub').click();
    elements.get('btn-header-settings').click();
    elements.get('gear-tab-settings').click();
    assert.equal(elements.get('screen-settings').classList.contains('active'), true,
        'Node Connection must open from centralized kpub management');
    elements.get('btn-settings-back-top').click();
    assert.equal(elements.get('screen-kpub-manager').classList.contains('active'), true,
        'settings Back must return to centralized kpub management');
    assert.equal(elements.get('kassee-startup-status').dataset.state, 'error');
    assert.match(elements.get('kassee-startup-status').textContent, /controls are available/i,
        'missing WASM must leave controls active and explain the degraded state');

    elements.get('btn-multisig-welcome').click();
    assert.equal(elements.get('screen-multisig').classList.contains('active'), true,
        'non-WASM welcome navigation must remain usable when the package is missing');

    elements.get('input-managed-kpub').value = `kpub1:${'11'.repeat(78)}`;
    elements.get('input-kpub-friendly-name').value = 'Runtime wallet';
    elements.get('btn-save-managed-kpub').click();
    assert.match(elements.get('toast').textContent, /WebAssembly is unavailable/i,
        'WASM-dependent controls must report why the action cannot complete');

    await pkgFixture.create();
    await fs.writeFile(generatedModule, buildWasmStub(wasmExports));

    globalThis.__KASSEE_TEST_INIT_FAILURE__ = true;
    await startApplication();
    assert.equal(elements.get('kassee-startup-status').dataset.state, 'error');
    assert.match(elements.get('kassee-startup-status').textContent, /controls are available/i,
        'a failed WASM initializer must also preserve controls');

    globalThis.__KASSEE_TEST_INIT_FAILURE__ = false;
    startupErrors.length = 0;
    await startApplication();
    assert.equal(elements.get('kassee-startup-status').dataset.state, 'ready');
    assert.match(elements.get('kassee-startup-status').textContent, /No saved kpubs/i);
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'successful startup without an automatic kpub must preserve the first landing screen');
    assert.equal(elements.get('welcome-saved-kpubs').classList.contains('hidden'), true,
        'the landing screen must hide the saved-kpub list when no entries exist');

    const { networkState, transactionState, walletSession } = await import(pathToFileURL(path.join(jsRoot, 'app', 'state', 'index.js')).href);
    networkState.customNodeUrl = 'ws://runtime-node';
    networkState.network = 'testnet-10';
    elements.get('btn-multisig-welcome').click();
    elements.get('input-ms-descriptor').value = 'multi_hd45(2,runtime-a,runtime-b,runtime-c)';
    elements.get('input-ms-cosigner').value = '';
    elements.get('btn-ms-discover').click();
    await new Promise(resolve => setImmediate(resolve));
    assert.match(elements.get('ms-discovery-info').textContent, /Receive #0: kaspatest:runtime-ms-receive/,
        'multisig discovery must visibly render the next receive address even when there are no UTXOs');
    assert.match(elements.get('ms-discovery-info').textContent, /Change #0: kaspatest:runtime-ms-change/,
        'multisig discovery must visibly render the next change address');
    assert.equal(elements.get('input-ms-source').value, 'kaspatest:runtime-ms-receive',
        'empty multisig source must default to the discovered receive address for funding');
    assert.equal(elements.get('input-ms-cosigner').value, '0',
        'blank 45-prime cosigner branch input must normalize to branch 0');
    assert.equal(elements.get('input-ms-cosigner').max, '2',
        'descriptor participant count must bound the 45-prime cosigner branch input');
    assert.equal(globalThis.__KASSEE_TEST_MS_SCAN_REQUEST__.address_prefix, 'kaspatest',
        'multisig discovery must derive its address prefix from the selected testnet network');
    delete globalThis.__KASSEE_TEST_MS_SCAN_REQUEST__;
    assert.match(elements.get('ms-discovery-info').textContent, /regular wallet balance is separate/i,
        'zero-balance discovery must explain that ordinary wallet funds are not multisig funds');
    assert.equal(elements.get('btn-ms-discover').disabled, false,
        'multisig discovery must re-enable its control after completion');
    networkState.customNodeUrl = null;
    networkState.network = 'mainnet';
    elements.get('btn-ms-back').click();

    elements.get('btn-header-settings').click();
    elements.get('gear-tab-settings').click();
    assert.equal(elements.get('screen-settings').classList.contains('active'), true,
        'history regression setup must enter Node Connection');
    elements.get('btn-header-settings').click();
    elements.get('gear-tab-history').click();
    assert.equal(elements.get('screen-history').classList.contains('active'), true,
        'History must leave Node Connection immediately');
    elements.get('btn-history-back-top').click();
    assert.equal(elements.get('screen-settings').classList.contains('active'), true,
        'History Back must return to Node Connection from navigation history');
    elements.get('btn-settings-back-top').click();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'Node Back must then return to Welcome through the same history stack');

    const { kpubRepository, useKpubOnce } = await import(pathToFileURL(path.join(
        jsRoot,
        'features',
        'wallet',
        'kpub_manager',
        'index.js',
    )).href);
    elements.get('input-managed-kpub').value = `kpub1:${'44'.repeat(78)}`;
    assert.equal(useKpubOnce(), true, 'Use kpub once must load a valid temporary wallet');
    assert.equal(walletSession.profile(), null, 'one-time wallet must not have a saved profile');
    assert.equal(kpubRepository.list().length, 0, 'Use kpub once must not write the saved-kpub repository');
    assert.equal(elements.get('btn-reset-wallet').textContent, 'Unload one-time kpub',
        'one-time wallet must replace Reset Wallet with Unload one-time kpub');
    transactionState._currentKsptHex = 'one-time-deadbeef';
    sessionStorage.setItem('kassee_private_swap_v2', '{"role":"alice","stage":"offer"}');
    globalThis.confirm = () => true;
    elements.get('btn-reset-wallet').click();
    assert.equal(walletSession.hasWallet(), false, 'one-time unload must clear the active wallet');
    assert.equal(transactionState._currentKsptHex, undefined, 'one-time unload must clear transaction state');
    assert.equal(sessionStorage.getItem('kassee_private_swap_v2'), null, 'one-time unload must clear Private Swap session state');
    assert.equal(globalThis.__KASSEE_TEST_RELOADS__, 1, 'one-time unload must request a fresh JS/WASM realm');
    await startApplication();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'one-time unload must return the fresh app to Welcome');

    const startupEntry = kpubRepository.save({
        name: 'Startup wallet',
        kpub: `kpub1:${'33'.repeat(78)}`,
        network: 'mainnet',
    });
    await startApplication();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'saved kpubs without a startup selection must remain on the first landing screen');
    assert.equal(elements.get('welcome-saved-kpubs').classList.contains('hidden'), false,
        'saved kpubs without a startup selection must appear in a clickable landing-screen list');
    assert.match(elements.get('kassee-startup-status').textContent, /Choose a saved kpub/i);

    kpubRepository.setAutoLoad(startupEntry.id);
    await startApplication();
    assert.equal(elements.get('screen-dashboard').classList.contains('active'), true,
        'a selected startup kpub must go directly to the loaded-wallet dashboard');
    assert.match(elements.get('kassee-startup-status').textContent, /Loaded saved wallet/i);
    assert.equal(startupErrors.length, 0, 'successful startup must not report event-binding errors');

    assert.equal(elements.get('btn-reset-wallet').textContent, 'Reset Wallet',
        'saved wallets must retain the normal Reset Wallet label');
    transactionState._currentKsptHex = 'saved-deadbeef';
    sessionStorage.setItem('kassee_private_swap_v2', '{"role":"bob","stage":"ready"}');
    elements.get('btn-reset-wallet').click();
    assert.equal(walletSession.hasWallet(), false, 'Reset Wallet must clear the active saved wallet');
    assert.equal(transactionState._currentKsptHex, undefined, 'Reset Wallet must use the hardened transaction cleanup');
    assert.equal(sessionStorage.getItem('kassee_private_swap_v2'), null, 'Reset Wallet must clear Private Swap session state');
    assert.equal(globalThis.__KASSEE_TEST_RELOADS__, 2, 'Reset Wallet must request the same fresh JS/WASM realm');
    await startApplication();
    assert.equal(elements.get('screen-welcome').classList.contains('active'), true,
        'one-shot startup suppression must keep normal Reset Wallet on Welcome');
    assert.equal(kpubRepository.autoLoadId(), startupEntry.id,
        'Reset Wallet must preserve the saved startup-wallet preference');

    console.error = originalError;
    delete globalThis.__KASSEE_TEST_INIT_FAILURE__;
    delete globalThis.__KASSEE_TEST_RELOADS__;

    const addedGlobals = Reflect.ownKeys(globalThis)
        .filter(name => !globalsBeforeStartup.has(name))
        .filter(name => typeof name === 'string');
    if (addedGlobals.length) {
        throw new Error(`application startup leaked browser globals: ${addedGlobals.join(', ')}`);
    }

    console.log(`PASS: browser startup and centralized kpub controls (${wasmExports.length} WASM imports, no application globals)`);
} finally {
    await pkgFixture.restore();
}
