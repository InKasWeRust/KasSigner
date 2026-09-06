import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isolateWebPackage } from './web_pkg_fixture.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..', '..', '..');
const webRoot = path.join(root, 'apps', 'kassee-web', 'web');
const jsRoot = path.join(webRoot, 'js');
const pkgDir = path.join(webRoot, 'pkg');
export const moduleUrl = relative => pathToFileURL(path.join(jsRoot, relative)).href;

function parseWasmExports(source) {
    const match = source.match(/const\s+GENERATED_WASM_EXPORTS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\);/);
    if (!match) throw new Error('Unable to parse wasm/api.js export inventory');
    return [...match[1].matchAll(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g)].map(item => item[1]);
}

function buildWasmStub(names) {
    const exports = names.map(name => `export function ${name}(...args) {
        const hook = globalThis.__KASSEE_WASM_STUBS__?.[${JSON.stringify(name)}];
        return typeof hook === 'function' ? hook(...args) : '';
    }`).join('\n');
    return `export default async function init() {}\n${exports}\n`;
}

export function createClassList(initial = []) {
    const values = new Set(initial);
    return {
        add(...names) { names.forEach(name => values.add(name)); },
        remove(...names) { names.forEach(name => values.delete(name)); },
        toggle(name, force) {
            if (force === true) values.add(name);
            else if (force === false) values.delete(name);
            else if (values.has(name)) values.delete(name);
            else values.add(name);
            return values.has(name);
        },
        contains(name) { return values.has(name); },
        toString() { return [...values].join(' '); },
        values,
    };
}

export class FakeElement {
    constructor(tagName = 'div', id = '') {
        this.tagName = tagName.toUpperCase();
        this.id = id;
        this.style = { setProperty: (name, value) => { this.style[name] = value; } };
        this.dataset = {};
        this.value = '';
        this.textContent = '';
        this.hidden = false;
        this.checked = false;
        this.type = '';
        this.href = '';
        this.download = '';
        this.parentElement = null;
        this.children = [];
        this.listeners = new Map();
        this.classList = createClassList();
        this._innerHTML = '';
        this.clicked = 0;
        this.removed = false;
    }
    set className(value) {
        this.classList = createClassList(String(value).split(/\s+/).filter(Boolean));
    }
    get className() { return this.classList.toString(); }
    set innerHTML(value) { this._innerHTML = String(value); }
    get innerHTML() { return this._innerHTML; }
    append(...nodes) { nodes.forEach(node => this.appendChild(node)); }
    appendChild(node) {
        if (node == null) return node;
        node.parentElement = this;
        this.children.push(node);
        return node;
    }
    replaceChildren(...nodes) {
        this.children.forEach(child => { child.parentElement = null; });
        this.children = [];
        this.append(...nodes);
    }
    insertBefore(node) { return this.appendChild(node); }
    addEventListener(type, listener) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(listener);
    }
    dispatch(type, event = {}) {
        const payload = { target: this, stopPropagation() {}, ...event };
        for (const listener of this.listeners.get(type) || []) listener(payload);
    }
    click() {
        this.clicked += 1;
        this.dispatch('click');
        if (typeof this.onclick === 'function') this.onclick({ target: this, stopPropagation() {} });
    }
    remove() {
        this.removed = true;
        if (this.parentElement) {
            this.parentElement.children = this.parentElement.children.filter(child => child !== this);
            this.parentElement = null;
        }
    }
    focus() {}
    play() { return Promise.resolve(); }
    getContext() {
        return {
            clearRect() {}, fillRect() {}, drawImage() {}, putImageData() {},
            getImageData: (_x=0,_y=0,width=this.width||1,height=this.height||1) => ({ data: new Uint8ClampedArray(Math.max(4,width*height*4)), width, height }),
        };
    }
    closest(selector) {
        if (selector === '.cov-active-item') {
            let current = this;
            while (current) {
                if (current.classList?.contains('cov-active-item')) return current;
                current = current.parentElement;
            }
        }
        return null;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    querySelectorAll(selector) {
        const found = [];
        const className = selector.startsWith('.') ? selector.slice(1) : null;
        const visit = node => {
            for (const child of node.children || []) {
                if (className && child.classList?.contains(className)) found.push(child);
                visit(child);
            }
            if (className && node._innerHTML?.includes(`class=\"${className}`)) {
                const attribute = className === 'cov-del' ? 'covDelIdx' : 'covExportIdx';
                const regex = className === 'cov-del'
                    ? /data-cov-del-idx=\"(\d+)\"/g
                    : /data-cov-export-idx=\"(\d+)\"/g;
                for (const match of node._innerHTML.matchAll(regex)) {
                    const synthetic = new FakeElement('span');
                    synthetic.classList.add(className);
                    synthetic.dataset[attribute] = match[1];
                    synthetic.parentElement = node;
                    found.push(synthetic);
                }
            }
        };
        visit(this);
        return found;
    }
    setAttribute(name, value) { this[name] = String(value); }
    getAttribute(name) { return this[name] ?? null; }
}

function createStorage() {
    const values = new Map();
    return {
        getItem(key) { return values.has(key) ? values.get(key) : null; },
        setItem(key, value) { values.set(key, String(value)); },
        removeItem(key) { values.delete(key); },
        clear() { values.clear(); },
        values,
    };
}

export function findById(rootNode, id) {
    if (rootNode.id === id) return rootNode;
    for (const child of rootNode.children || []) {
        const found = findById(child, id);
        if (found) return found;
    }
    return null;
}

const elements = new Map();
export const body = new FakeElement('body', 'body');
export const intervals = new Map();
let timerId = 1;
let fetchHook = async () => ({ ok: false, async json() { return {}; } });
let confirmResult = true;
let objectUrlCounter = 0;
let pkgFixture;
export let state;

export function setFetchHook(hook) { fetchHook = hook; }
export function setConfirmResult(value) { confirmResult = Boolean(value); }

export function element(id) {
    if (!elements.has(id)) elements.set(id, new FakeElement('div', id));
    return elements.get(id);
}

function installGlobals() {
    globalThis.window = globalThis;
    globalThis.document = {
        body,
        getElementById(id) { return elements.get(id) || findById(body, id) || element(id); },
        createElement(tag) { return new FakeElement(tag); },
        createTextNode(text) { const node = new FakeElement('#text'); node.textContent = String(text); return node; },
        querySelector(selector) {
            const balance = selector.match(/^\[data-cov-bal-idx=\"(\d+)\"\]$/);
            if (balance) return elements.get(`balance-${balance[1]}`) || null;
            if (selector === '#status-dot .dot') return element('status-dot-value');
            if (selector === '#status-dot .label') return element('status-label-value');
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '.screen') return [...elements.values()].filter(item => item.id.startsWith('screen-'));
            return [];
        },
        addEventListener() {},
    };
    globalThis.localStorage = createStorage();
    globalThis.sessionStorage = createStorage();
    globalThis.confirm = () => confirmResult;
    globalThis.alert = () => {};
    globalThis.fetch = (...args) => fetchHook(...args);
    globalThis.setTimeout = callback => { callback(); return timerId++; };
    globalThis.clearTimeout = () => {};
    globalThis.setInterval = callback => {
        const id = timerId++;
        intervals.set(id, callback);
        return id;
    };
    globalThis.clearInterval = id => intervals.delete(id);
    globalThis.URL.createObjectURL = () => `blob:recovery-${++objectUrlCounter}`;
    globalThis.URL.revokeObjectURL = () => {};
    Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: { clipboard: { async writeText() {} }, mediaDevices: { async getUserMedia() { return { getTracks: () => [] }; } } },
    });
    for (const id of [
        'toast', 'cov-active-list', 'cov-active-items', 'cov-active-count', 'cov-menu',
        'cov-result-addr', 'cov-result-script', 'cov-result-extra', 'cov-result-balance',
        'btn-cov-res-balance', 'cov-piggy-status-banner', 'screen-welcome', 'screen-covenant',
    ]) element(id);
    for (const panel of [
        'cov-menu', 'cov-create-panel', 'cov-result-panel', 'cov-owner-panel', 'cov-borrower-panel',
        'cov-beneficiary-panel', 'cov-timeout-panel', 'cov-balance-panel',
        'cov-payjoin-claim-panel',
        'cov-consolidate-panel', 'cov-cr-reveal-panel', 'cov-cr-verify-panel', 'cov-mw-spend-panel',
        'cov-tagged-vault-panel', 'cov-load-panel', 'cov-ship-panel', 'cov-oracle-mb-panel',
    ]) element(panel).classList.add('hidden');
}

export function le16(value) {
    return (value & 0xff).toString(16).padStart(2, '0')
        + ((value >> 8) & 0xff).toString(16).padStart(2, '0');
}
export function le64(value) {
    let n = BigInt(value);
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += Number(n & 0xffn).toString(16).padStart(2, '0');
        n >>= 8n;
    }
    return result;
}
export function vstr(value) {
    const hex = Buffer.from(value, 'utf8').toString('hex');
    return le16(hex.length / 2) + hex;
}
export function storedScript(script, tail = '') { return le16(script.length / 2) + script + tail; }

export async function setupHarness() {
    pkgFixture = await isolateWebPackage(pkgDir);
    installGlobals();
    const apiSource = await fs.readFile(path.join(jsRoot, 'wasm', 'api.js'), 'utf8');
    await pkgFixture.create();
    await fs.writeFile(path.join(pkgDir, 'kassee_web.js'), buildWasmStub(parseWasmExports(apiSource)));
    globalThis.__KASSEE_WASM_STUBS__ = {
        blake2b_hash: input => `hash-${input}`,
        encode_p2sh_address: (hash, network) => `${network}:p2sh-${String(hash).slice(-12)}`,
        encode_p2pk_address: (pk, network) => `${network}:p2pk-${String(pk).slice(0, 8)}`,
        decode_address: address => JSON.stringify({ payload: address.includes('owner') ? '11'.repeat(32) : '22'.repeat(32) }),
        parse_kpub: () => JSON.stringify({ account_pubkey: '11'.repeat(32) }),
        covenant_dms: () => JSON.stringify({ address: 'kaspa:dms', redeem_script_hex: '51' }),
        covenant_timelocked_escrow: () => JSON.stringify({ address: 'kaspa:time-escrow', redeem_script_hex: '52' }),
        crowdfund_campaign_id: () => '77'.repeat(32),
        covenant_private_swap: () => JSON.stringify({ address: 'kaspa:private-swap', redeem_script_hex: '51aa' }),
        derive_covenant_payload_key: () => '11'.repeat(32),
        build_covenant_payload: () => 'aa'.repeat(40),
        generate_qr_svg_text: value => `<svg data-value="${value.slice(0, 8)}"></svg>`,
        generate_qr_frames: () => JSON.stringify([{ svg: '<svg>1</svg>' }, { svg: '<svg>2</svg>' }]),
        fetch_utxos_for_address_js: address => address.includes('fail')
            ? (() => { throw new Error('node failure'); })()
            : JSON.stringify(address.includes('empty') ? [] : [{ amount: '250000000' }]),
    };
    const wasm = await import(moduleUrl('wasm/api.js'));
    await wasm.init();
    state = await import(moduleUrl('app/state/index.js'));
    state.networkState.network = 'mainnet';
    state.networkState.customNodeUrl = 'ws://test-node';
    state.walletSession.replace({
        kpub: 'kpub-test',
        receive_addresses: ['kaspa:owner-receive'],
        change_addresses: ['kaspa:change'],
    });
}

export async function teardownHarness() {
    delete globalThis.__KASSEE_WASM_STUBS__;
    if (pkgFixture) await pkgFixture.restore();
}

