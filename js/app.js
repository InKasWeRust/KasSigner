// KasSee Web — Main application logic
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// JS handles: UI, camera, resolver query (fetch), persistence
// WASM handles: BIP32, address encoding, KSPT format, QR gen, Borsh wRPC

import init, {
    version,
    import_kpub,
    import_kpub_raw,
    fetch_balance,
    fetch_utxos,
    get_fee_estimate,
    create_send_kspt,
    create_consolidate_kspt,
    create_send_kspt_selected,
    create_compound_kspt,
    broadcast_signed,
    generate_qr_frames,
    decode_qr_frame,
    reset_qr_decoder,
    decoder_progress,
    create_multisig_kspt,
    fetch_utxos_for_address_js,
    pskt_detect,
    pskt_summary,
    pskt_finalize_to_kspt,
    pskt_finalize_and_broadcast,
    pskt_relay_to_kspt_v2,
    pskt_merge_signed_kspt_v2,
    create_multisig_pskb,
} from '../pkg/kassee_web.js';

// ─── State ───

let walletData = null;
let customNodeUrl = null;
let lastFeeEstimate = null;
let selectedUtxoIndices = null; // null = auto-select, array = manual
let cachedUtxos = null;
let scanCallback = null;
let scanStream = null;
let scanAnimFrame = null;
let qrFrames = null;
let qrFrameIdx = 0;
let qrCycleTimer = null;
let refreshing = false; // debounce guard
let network = 'mainnet'; // 'mainnet', 'testnet-10', 'testnet-11'

// No localStorage — all state lives in memory only. Session ends on tab close.
let historyEntries = [];
let utxoSnapshot = null;

// Broadcast enabled
const BROADCAST_ENABLED = true;

// Donation address
const DONATE_ADDRESS = 'kaspa:qqts8pkq5cyf63dxx5j96gm74dah5jwx7ltqflrscpt3dmrz6adqc5grpeke3';
const DONATE_KNS = 'kassigner.kns';

// Kasplex API for KRC20 token balances
const KASPLEX_API = {
    'mainnet': 'https://api.kasplex.org/v1',
    'testnet-10': 'https://tn10api.kasplex.org/v1',
};

// KNS domain → address lookup (hardcoded until KNS provides a public API)
const KNS_LOOKUP = {
    'kassigner.kas': 'kaspa:qqts8pkq5cyf63dxx5j96gm74dah5jwx7ltqflrscpt3dmrz6adqc5grpeke3',
    'inkaswerust.kas': 'kaspa:qqts8pkq5cyf63dxx5j96gm74dah5jwx7ltqflrscpt3dmrz6adqc5grpeke3',
};

// KRC721 NFT indexer API
const KRC721_API = {
    'mainnet': 'https://mainnet.krc721.stream/api/v1/krc721/mainnet',
    'testnet-10': 'https://testnet-10.krc721.stream/api/v1/krc721/testnet-10',
};

// Resolver URLs (from Kaspa SDK Resolvers.toml)
const RESOLVERS = [
    'https://maxim.kaspa.stream',
    'https://troy.kaspa.stream',
    'https://sean.kaspa.stream',
    'https://eric.kaspa.stream',
    'https://jake.kaspa.green',
    'https://mark.kaspa.green',
    'https://adam.kaspa.green',
    'https://liam.kaspa.green',
    'https://noah.kaspa.blue',
    'https://ryan.kaspa.blue',
    'https://jack.kaspa.blue',
    'https://luke.kaspa.blue',
    'https://john.kaspa.red',
    'https://mike.kaspa.red',
    'https://paul.kaspa.red',
    'https://alex.kaspa.red',
];

// ─── Toast notification system ───

let toastTimer = null;

function toast(msg, type = 'info', duration = 3000) {
    const t = el('toast');
    t.textContent = msg;
    t.className = `toast toast-${type} visible`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        t.classList.remove('visible');
        toastTimer = null;
    }, duration);
}

// ─── Resolver: get a public node wss:// URL ───

async function resolveNodeUrl() {
    if (customNodeUrl) {
        console.log(`[KasSee] Using custom node: ${customNodeUrl}`);
        return customNodeUrl;
    }
    return resolvePublicNode();
}

async function resolvePublicNode() {
    const shuffled = [...RESOLVERS].sort(() => Math.random() - 0.5);

    for (const resolver of shuffled) {
        try {
            const resp = await fetch(`${resolver}/v2/kaspa/${network}/any/wrpc/borsh`, { signal: AbortSignal.timeout(5000) });
            if (resp.ok) {
                const data = await resp.json();
                if (data.url) {
                    console.log(`[KasSee] Resolved ${network} node: ${data.url} (via ${resolver})`);
                    return data.url;
                }
            }
        } catch (e) {
            // Try next resolver
        }
    }
    throw new Error('All resolvers failed. Check internet connection.');
}

// ─── Init ───

async function start() {
    await init();
    console.log(version());

    // Always start fresh — no persistence
    walletData = null;
    customNodeUrl = null;
    network = 'mainnet';

    showScreen('welcome');
    bindEvents();
}

// ─── Screen navigation ───

let currentScreenName = 'welcome';
function showScreen(name) {
    currentScreenName = name;
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const screen = document.getElementById(`screen-${name}`);
    if (screen) screen.classList.add('active');
}

function showLoading(msg) {
    el('loading-msg').textContent = msg || 'Loading...';
    el('loading').classList.remove('hidden');
}

function hideLoading() {
    el('loading').classList.add('hidden');
}

function setStatus(state, label) {
    const dot = document.querySelector('#status-dot .dot');
    const lbl = document.querySelector('#status-dot .label');
    dot.className = `dot ${state}`;
    lbl.textContent = label;
}

function toggleGearMenu() {
    const menu = el('gear-menu');
    const btn = el('btn-header-settings');
    if (menu.classList.contains('visible')) {
        menu.classList.remove('visible');
        btn.classList.remove('active');
    } else {
        menu.classList.add('visible');
        btn.classList.add('active');
    }
}

function closeGearMenu() {
    el('gear-menu').classList.remove('visible');
    el('btn-header-settings').classList.remove('active');
}

// ─── Event binding ───

function bindEvents() {
    el('btn-scan-kpub').onclick = () => startScanner('Scan kpub QR', handleKpubScan);
    el('btn-logo').onclick = () => handleLogoTap();
    el('btn-import-kpub').onclick = () => handleKpubImport(el('input-kpub').value.trim());
    el('btn-multisig-welcome').onclick = () => showScreen('multisig');
    el('btn-send').onclick = () => openSendScreen();
    el('btn-receive').onclick = () => showReceive();
    el('btn-broadcast').onclick = () => { hideBroadcastResult(); showScreen('broadcast'); };
    el('btn-multisig-spend').onclick = () => showScreen('multisig');
    el('btn-ms-back').onclick = () => showScreen(walletData ? 'dashboard' : 'welcome');
    el('btn-ms-create').onclick = () => handleMultisigCreate();
    el('btn-ms-max').onclick = () => handleMsMax();
    el('btn-scan-ms-source').onclick = () => startScanner('Scan P2SH address', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:')) { stopScanner(); el('input-ms-source').value = addr; showScreen('multisig'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-scan-ms-dest').onclick = () => startScanner('Scan destination', (data) => {
        const text = new TextDecoder().decode(new Uint8Array(data));
        const addr = text.trim();
        if (addr.startsWith('kaspa:') || addr.endsWith('.kas')) { stopScanner(); el('input-ms-dest').value = addr; showScreen('multisig'); toast('Address scanned', 'ok', 1500); }
    });
    el('btn-scan-ms-descriptor').onclick = () => startScanner('Scan descriptor QR', handleDescriptorScan);
    el('btn-refresh').onclick = () => refreshBalance();
    el('btn-reset-wallet').onclick = () => resetWallet();
    el('btn-create-tx').onclick = () => handleCreateTx();
    el('btn-send-max').onclick = () => handleSendMax();
    el('btn-scan-dest').onclick = () => startScanner('Scan address QR', handleDestScan);
    // Compound TX — disabled until KasSigner QR frame fix
    // el('btn-add-recipient').onclick = () => addRecipientRow();
    el('btn-toggle-utxos').onclick = () => toggleSendUtxos();
    el('btn-fee-low').onclick = () => setFeeLevel('low');
    el('btn-fee-normal').onclick = () => setFeeLevel('normal');
    el('btn-fee-priority').onclick = () => setFeeLevel('priority');
    el('btn-send-back').onclick = () => showScreen('dashboard');
    el('btn-qr-back').onclick = () => { stopQrCycle(); showScreen('dashboard'); };
    el('btn-scan-next-sig').onclick = () => { stopQrCycle(); startScanner('Scan signed QR', handleSignedScan); };
    el('btn-copy-kspt').onclick = () => { if (window._currentKsptHex) { navigator.clipboard.writeText(window._currentKsptHex); toast('KSPT hex copied — share with next signer', 'ok', 2000); } };
    el('btn-scanner-cancel').onclick = () => stopScanner();
    el('btn-copy-address').onclick = () => copyAddress();
    el('btn-receive-back').onclick = () => showScreen('dashboard');
    el('btn-scan-signed').onclick = () => startScanner('Scan signed QR', handleSignedScan);
    el('btn-broadcast-hex').onclick = () => handleBroadcastHex();
    el('btn-broadcast-back').onclick = () => showScreen('dashboard');
    el('btn-pskt-back').onclick = () => { _psktReviewHex = null; showScreen('dashboard'); };
    el('btn-pskt-relay').onclick = () => openRelayModal();
    el('btn-relay-standard').onclick = () => { closeRelayModal(); handlePsktRelay(); };
    el('btn-relay-compact').onclick = () => { closeRelayModal(); handlePsktRelayCompact(); };
    el('btn-relay-cancel').onclick = () => closeRelayModal();
    el('btn-pskt-finalize').onclick = () => handlePsktFinalize();
    el('btn-broadcast-done').onclick = () => {
        hideBroadcastResult();
        showDonateScreen();
    };
    el('btn-copy-txid').onclick = () => {
        const txid = el('broadcast-result-txid').textContent.trim();
        navigator.clipboard.writeText(txid);
        toast('TX ID copied', 'ok', 1500);
    };
    el('btn-save-settings').onclick = () => saveSettings();
    el('btn-use-public').onclick = () => { clearCustomNode(); exitSettings(); };
    el('btn-settings-back').onclick = () => exitSettings();
    el('btn-header-settings').onclick = () => toggleGearMenu();

    // Gear menu tabs
    document.querySelectorAll('.gear-tab').forEach(tab => {
        tab.onclick = () => {
            const target = tab.dataset.target;
            // Update active tab
            document.querySelectorAll('.gear-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            // Close menu and navigate
            closeGearMenu();
            if (target === 'addresses') showAddresses();
            else if (target === 'utxos') showUtxos();
            else if (target === 'tokens') showTokens();
            else if (target === 'history') showHistory();
            else if (target === 'settings') showSettings();
        };
    });
    el('btn-addresses-back').onclick = () => showScreen(addressesReturnScreen);
    el('btn-addresses-back-top').onclick = () => showScreen(addressesReturnScreen);
    el('btn-tokens-back').onclick = () => showScreen('dashboard');
    el('btn-verify-copy').onclick = () => {
        navigator.clipboard.writeText(el('verify-address').textContent.trim());
        toast('Address copied', 'ok', 1200);
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    el('btn-verify-back').onclick = () => {
        showScreen('addresses');
        document.querySelector('main').scrollTop = 0;
    };
    el('btn-utxos-back').onclick = () => showScreen('dashboard');
    el('btn-consolidate').onclick = () => handleConsolidate();
    el('btn-history-back').onclick = () => showScreen('dashboard');
    el('btn-clear-history').onclick = () => clearHistory();
    el('btn-donate-skip').onclick = () => exitSettings();
    el('btn-copy-donate').onclick = () => {
        navigator.clipboard.writeText(DONATE_ADDRESS);
        toast('Address copied', 'ok', 1500);
    };
}

function el(id) { return document.getElementById(id); }

// ─── kpub import ───

function handleKpubScan(data) {
    const bytes = new Uint8Array(data);

    // Check if this is a multi-frame fragment:
    // [frame_num][total_frames][frag_len][data...] where total >= 2
    // Frame 0 must start with a recognised format marker:
    //   - ASCII "kpub" (legacy base58 kpub text payload), OR
    //   - 0x01 (V1-raw header — compact binary format, 79-byte kpub)
    const isMF = bytes.length >= 7
        && bytes[1] >= 2 && bytes[1] <= 20
        && bytes[0] < bytes[1] && bytes[2] > 0
        && (bytes[0] > 0 || (bytes.length >= 7 && (
            String.fromCharCode(bytes[3], bytes[4], bytes[5], bytes[6]) === 'kpub'
            || bytes[3] === 0x01
        )));

    if (isMF) {
        // Multi-frame: feed through decoder, keep scanning
        const hexStr = Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0')).join('');
        try {
            const result = decode_qr_frame(hexStr);
            if (result && result.length > 0) {
                stopScanner();
                // Convert assembled hex → byte array
                const assembled = [];
                for (let i = 0; i < result.length; i += 2) {
                    assembled.push(parseInt(result.substr(i, 2), 16));
                }
                const assembledBytes = new Uint8Array(assembled);

                // V1-raw path: [0x01 header][78-byte raw payload] = 79 bytes total
                if (assembledBytes.length === 79 && assembledBytes[0] === 0x01) {
                    handleKpubImportRaw(assembledBytes.slice(1));
                } else {
                    // Legacy ASCII path: assembled bytes are UTF-8 of a kpub string
                    const kpubStr = new TextDecoder().decode(assembledBytes).trim();
                    handleKpubImport(kpubStr);
                }
            } else {
                // Show frame progress
                const prog = JSON.parse(decoder_progress());
                if (prog.total > 0) {
                    let dots = '';
                    for (let i = 0; i < prog.total; i++) {
                        dots += `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:${prog.bits[i] ? 'var(--teal)' : 'var(--border)'};${prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : ''}"></span>`;
                    }
                    el('scanner-status').innerHTML = dots + `<div style="margin-top:6px;font-size:12px">${prog.count} / ${prog.total} kpub frames</div>`;
                }
            }
        } catch (e) {
            console.error('kpub multi-frame decode error:', e);
        }
        return;
    }

    // Single-frame: direct kpub text
    // Guard: only process once
    if (!scanCallback) return;
    scanCallback = null;
    if (scanAnimFrame) { cancelAnimationFrame(scanAnimFrame); scanAnimFrame = null; }
    if (scanStream) { scanStream.getTracks().forEach(t => t.stop()); scanStream = null; }

    const text = typeof data === 'string' ? data : new TextDecoder().decode(data);
    handleKpubImport(text.trim());
}

function handleKpubImport(kpubStr) {
    if (!kpubStr || !kpubStr.startsWith('kpub')) {
        toast('Invalid kpub — must start with "kpub"', 'error');
        return;
    }
    showLoading('Deriving addresses...');
    try {
        walletData = import_kpub(kpubStr, network);
        hideLoading();

        showScreen('dashboard');
        refreshBalance();
    } catch (e) {
        hideLoading();
        toast('Import failed: ' + e, 'error', 5000);
    }
}

// V1-raw binary kpub entry point: called when a multi-frame QR scan
// assembles into [0x01 header][78 raw payload] = 79 bytes. The header
// is stripped by the caller; we pass the 78 raw bytes to WASM which
// re-encodes them as a standard base58check kpub internally.
//
// walletData is kept as a raw JSON string to match handleKpubImport's
// convention — downstream code (fetch_balance, fetch_utxos, etc.)
// expects `wallet_json: &str` on the WASM side and parses internally.
function handleKpubImportRaw(rawPayload) {
    if (!rawPayload || rawPayload.length !== 78) {
        toast('Invalid V1-raw kpub payload', 'error');
        return;
    }
    showLoading('Deriving addresses...');
    try {
        walletData = import_kpub_raw(rawPayload, network);
        hideLoading();

        showScreen('dashboard');
        refreshBalance();
    } catch (e) {
        hideLoading();
        toast('V1-raw import failed: ' + e, 'error', 5000);
    }
}

// ─── Node connection with retry ───

async function withNodeRetry(fn, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const wsUrl = await resolveNodeUrl();
            return await fn(wsUrl);
        } catch (e) {
            const msg = String(e);
            if (msg.includes('WebSocket error') && attempt < maxRetries) {
                console.log(`[KasSee] Retry ${attempt}/${maxRetries}: ${msg}`);
                continue;
            }
            // Custom node exhausted retries — fall back to public
            if (customNodeUrl) {
                console.log(`[KasSee] Custom node failed, falling back to public`);
                toast('Custom node unreachable — using public', 'info', 3000);
                try {
                    const publicUrl = await resolvePublicNode();
                    return await fn(publicUrl);
                } catch (e2) {
                    throw e2;
                }
            }
            throw e;
        }
    }
}

// ─── Balance ───

async function refreshBalance() {
    if (!walletData || refreshing) return;
    refreshing = true;

    showLoading('Connecting...');
    setStatus('connecting', 'Connecting');

    try {
        const resultJson = await withNodeRetry(wsUrl => fetch_balance(walletData, wsUrl));
        const result = JSON.parse(resultJson);

        setStatus('online', 'Connected');
        hideLoading();

        el('balance-kas').textContent = result.total_kas.toFixed(8) + ' KAS';
        el('balance-sompi').textContent = result.total_sompi.toLocaleString() + ' sompi';
        el('balance-info').textContent =
            `${result.utxo_count} UTXO${result.utxo_count !== 1 ? 's' : ''} across ${result.funded_addresses} address${result.funded_addresses !== 1 ? 'es' : ''}`;

        // Track UTXO changes for history
        try {
            const wsUrl = await resolveNodeUrl();
            const utxosJson = await fetch_utxos(walletData, wsUrl);
            const currentUtxos = JSON.parse(utxosJson);
            trackUtxoChanges(currentUtxos);
        } catch (e) {
            console.log('[KasSee] UTXO history track:', e);
        }
    } catch (e) {
        setStatus('offline', 'Offline');
        hideLoading();
        console.error('Balance fetch failed:', e);
        el('balance-kas').textContent = '—';
        el('balance-sompi').textContent = '';
        el('balance-info').textContent = String(e);
    } finally {
        refreshing = false;
    }
}

// ─── Send ───

async function openSendScreen() {
    selectedUtxoIndices = null;
    cachedUtxos = null;
    el('send-utxo-list').classList.add('hidden');
    el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
    // el('extra-recipients').innerHTML = '';
    el('input-dest').value = '';
    el('input-amount').value = '';

    // Show current balance on send screen
    const balText = el('balance-kas').textContent;
    const ref = el('send-balance-ref');
    if (balText && balText !== '—') {
        ref.textContent = 'Available: ' + balText;
    } else {
        ref.textContent = '';
    }

    // Update placeholder for current network
    const prefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    el('input-dest').placeholder = prefix + '...';

    showScreen('send');
    try {
        const wsUrl = await resolveNodeUrl();
        const resultJson = await get_fee_estimate(wsUrl);
        lastFeeEstimate = JSON.parse(resultJson);
        el('input-fee').value = lastFeeEstimate.suggested_fee;
        updateFeeCardAmounts();
        // Reset to Normal active
        document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
        el('btn-fee-normal').classList.add('fee-card-active');
        const utxosJson = await fetch_utxos(walletData, wsUrl);
        cachedUtxos = JSON.parse(utxosJson);
        cachedUtxos.sort((a, b) => b.amount - a.amount);
    } catch (e) {
        console.log('[KasSee] Fee/UTXO fetch:', e);
    }
}

function toggleSendUtxos() {
    const list = el('send-utxo-list');
    if (!list.classList.contains('hidden')) {
        list.classList.add('hidden');
        el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▸';
        selectedUtxoIndices = null;
        return;
    }
    if (!cachedUtxos || cachedUtxos.length === 0) {
        toast('No UTXOs available', 'error');
        return;
    }
    el('btn-toggle-utxos').textContent = 'Select UTXOs manually ▾';
    let html = '';
    cachedUtxos.forEach((u, i) => {
        const kas = (u.amount / 1e8).toFixed(8);
        html += `<div class="utxo-item" data-idx="${i}" style="cursor:pointer;display:flex;align-items:center;gap:10px">
            <span style="font-size:18px;color:var(--border)" class="utxo-check">☐</span>
            <div style="flex:1">
                <div class="utxo-amount" style="font-size:13px">${kas} KAS</div>
                <div class="utxo-detail">${u.tx_id.slice(0, 16)}…:${u.index}</div>
            </div>
        </div>`;
    });
    list.innerHTML = html;
    selectedUtxoIndices = [];

    list.querySelectorAll('.utxo-item').forEach(item => {
        item.onclick = () => {
            const idx = parseInt(item.dataset.idx);
            const check = item.querySelector('.utxo-check');
            const pos = selectedUtxoIndices.indexOf(idx);
            if (pos >= 0) {
                selectedUtxoIndices.splice(pos, 1);
                check.textContent = '☐';
                check.style.color = 'var(--border)';
                item.style.borderColor = '';
            } else {
                selectedUtxoIndices.push(idx);
                check.textContent = '☑';
                check.style.color = 'var(--teal)';
                item.style.borderColor = 'var(--teal)';
            }
        };
    });
    list.classList.remove('hidden');
}

function setFeeLevel(level) {
    if (!lastFeeEstimate) return;
    const mass = 2300;
    let feerate, minFee;
    if (level === 'low') {
        feerate = lastFeeEstimate.low_sompi_per_gram;
        minFee = 2500;
    } else if (level === 'priority') {
        feerate = lastFeeEstimate.priority_sompi_per_gram;
        minFee = 10000;
    } else {
        feerate = lastFeeEstimate.normal_sompi_per_gram;
        minFee = 5000;
    }
    el('input-fee').value = Math.max(minFee, Math.round(feerate * mass));

    // Update active card visual
    document.querySelectorAll('.fee-card').forEach(c => c.classList.remove('fee-card-active'));
    el('btn-fee-' + level).classList.add('fee-card-active');
}

function updateFeeCardAmounts() {
    if (!lastFeeEstimate) return;
    const mass = 2300;
    const low = Math.max(2500, Math.round(lastFeeEstimate.low_sompi_per_gram * mass));
    const normal = Math.max(5000, Math.round(lastFeeEstimate.normal_sompi_per_gram * mass));
    const priority = Math.max(10000, Math.round(lastFeeEstimate.priority_sompi_per_gram * mass));
    el('fee-low-amount').textContent = low.toLocaleString();
    el('fee-normal-amount').textContent = normal.toLocaleString();
    el('fee-priority-amount').textContent = priority.toLocaleString();

    // Show estimated time if available from node
    const lowTime = el('fee-low-time');
    const normalTime = el('fee-normal-time');
    const priorityTime = el('fee-priority-time');
    if (lowTime && lastFeeEstimate.low_seconds != null) {
        lowTime.textContent = formatSeconds(lastFeeEstimate.low_seconds);
    }
    if (normalTime && lastFeeEstimate.normal_seconds != null) {
        normalTime.textContent = formatSeconds(lastFeeEstimate.normal_seconds);
    }
    if (priorityTime && lastFeeEstimate.priority_seconds != null) {
        priorityTime.textContent = formatSeconds(lastFeeEstimate.priority_seconds);
    }
}

function formatSeconds(s) {
    if (s == null || s <= 0) return '';
    if (s < 1) return '< 1s';
    if (s < 60) return Math.round(s) + 's';
    if (s < 3600) return Math.round(s / 60) + 'min';
    return Math.round(s / 3600) + 'h';
}

function handleSendMax() {
    if (!walletData) return;
    const fee = parseInt(el('input-fee').value) || 10000;
    const feeKas = fee / 100000000;

    if (selectedUtxoIndices && selectedUtxoIndices.length > 0 && cachedUtxos) {
        const selectedTotal = selectedUtxoIndices.reduce((s, i) => s + cachedUtxos[i].amount, 0);
        const maxKas = Math.max(0, selectedTotal / 1e8 - feeKas);
        el('input-amount').value = maxKas.toFixed(8);
        return;
    }

    const balText = el('balance-kas').textContent;
    const match = balText.match(/([\d.]+)/);
    if (!match) { toast('Refresh balance first', 'info'); return; }
    const totalKas = parseFloat(match[1]);
    const maxKas = Math.max(0, totalKas - feeKas);
    el('input-amount').value = maxKas.toFixed(8);
}

// ─── Compound recipients ───

// ─── Destination QR scan ───

function handleDestScan(data) {
    const text = typeof data === 'string' ? data : new TextDecoder().decode(new Uint8Array(data));
    const addr = text.trim();
    const expectedPrefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    if (addr.startsWith(expectedPrefix) || addr.endsWith('.kas')) {
        stopScanner();
        el('input-dest').value = addr;
        showScreen('send');
        toast('Address scanned', 'ok', 1500);
    }
}

// ─── KSPT signature status check ───

function checkKsptSignatureStatus(hex) {
    if (hex.length < 12) return 'unknown';
    const header = hex.substring(0, 8);
    if (header !== '4b535054') return 'unknown';
    const version = parseInt(hex.substring(8, 10), 16);
    const flags = parseInt(hex.substring(10, 12), 16);
    if (flags === 0x01) return 'signed';
    if (flags === 0x00 && version === 0x02) return 'partial';
    if (flags === 0x00) return 'unsigned';
    return 'unknown';
}

let recipientCount = 0;

function addRecipientRow() {
    recipientCount++;
    const prefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    const container = el('extra-recipients');
    const row = document.createElement('div');
    row.className = 'recipient-row';
    row.dataset.rid = recipientCount;
    row.innerHTML = `
        <button class="recipient-remove" title="Remove">&times;</button>
        <input type="text" class="input-text r-addr" placeholder="${prefix}..." autocomplete="off" spellcheck="false">
        <input type="number" class="input-text r-amount" placeholder="Amount (KAS)" step="0.00000001" min="0">
    `;
    row.querySelector('.recipient-remove').onclick = () => row.remove();
    container.appendChild(row);
}

function getExtraRecipients() {
    const container = el('extra-recipients');
    if (!container) return [];
    const rows = container.querySelectorAll('.recipient-row');
    const list = [];
    for (const row of rows) {
        const addr = row.querySelector('.r-addr').value.trim();
        const amountStr = row.querySelector('.r-amount').value.trim();
        if (addr && amountStr) {
            list.push({ address: addr, amount_kas: parseFloat(amountStr) });
        }
    }
    return list;
}

async function handleCreateTx() {
    let dest = el('input-dest').value.trim();
    const amountStr = el('input-amount').value.trim();
    const feeStr = el('input-fee').value.trim();

    // KNS resolution: if ends with .kas, look up address
    if (dest.endsWith('.kas')) {
        const resolved = KNS_LOOKUP[dest.toLowerCase()];
        if (resolved) {
            dest = resolved;
            toast('Resolved ' + el('input-dest').value.trim() + ' → address', 'ok', 2000);
        } else {
            toast('Unknown .kas domain: ' + dest, 'error'); return;
        }
    }

    const expectedPrefix = (network === 'mainnet') ? 'kaspa:' : 'kaspatest:';
    if (!dest || !dest.startsWith(expectedPrefix)) {
        toast('Enter a valid ' + expectedPrefix + ' address or .kas domain', 'error'); return;
    }
    if (!amountStr || parseFloat(amountStr) <= 0) {
        toast('Enter an amount > 0', 'error'); return;
    }

    const amount = parseFloat(amountStr);
    const fee = parseInt(feeStr) || 10000;
    const extras = getExtraRecipients();

    // Compound TX temporarily disabled — KasSigner QR display bug at 7+ frames
    if (extras.length > 0) {
        toast('Compound TX disabled — firmware update needed', 'error', 4000);
        return;
    }

    showLoading('Creating transaction...');
    try {
        let ksptHex;

        if (extras.length > 0) {
            // Compound transaction — multiple recipients
            const recipients = [{ address: dest, amount_kas: amount }, ...extras];
            ksptHex = await withNodeRetry(wsUrl =>
                create_compound_kspt(walletData, JSON.stringify(recipients), BigInt(fee), wsUrl)
            );
        } else if (selectedUtxoIndices && selectedUtxoIndices.length > 0) {
            const csv = selectedUtxoIndices.join(',');
            ksptHex = await withNodeRetry(wsUrl =>
                create_send_kspt_selected(walletData, dest, amount, BigInt(fee), csv, wsUrl)
            );
        } else {
            ksptHex = await withNodeRetry(wsUrl =>
                create_send_kspt(walletData, dest, amount, BigInt(fee), wsUrl)
            );
        }

        hideLoading();
        console.log(`[KasSee] KSPT created: ${ksptHex.length / 2} bytes`);
        window._lastKsptHex = ksptHex;
        displayKsptQr(ksptHex, 'Scan with KasSigner');

    } catch (e) {
        hideLoading();
        toast('TX creation failed: ' + e, 'error', 5000);
        console.error('TX creation failed:', e);
    }
}

// ─── QR display ───

function displayKsptQr(ksptHex, title) {
    try {
        const frames = JSON.parse(generate_qr_frames(ksptHex));
        qrFrames = frames;
        qrFrameIdx = 0;
        el('qr-display-title').textContent = title || 'Scan QR Code';

        const isRelay = title && title.includes('Relay');
        el('btn-scan-next-sig').style.display = isRelay ? 'block' : 'none';
        el('btn-copy-kspt').style.display = isRelay ? 'block' : 'none';
        window._currentKsptHex = ksptHex;

        if (frames.length === 1) {
            el('qr-container').innerHTML = frames[0].svg;
            el('qr-frame-info').innerHTML = '';
        } else {
            let dots = '<div class="frame-dots">';
            for (let i = 0; i < frames.length; i++) {
                dots += `<span class="frame-dot${i === 0 ? ' active' : ''}" id="fdot-${i}"></span>`;
            }
            dots += '</div>';
            dots += '<div class="frame-controls">';
            dots += '<button class="btn-frame" id="btn-frame-prev">\u23EA</button>';
            dots += '<button class="btn-frame" id="btn-frame-pause" title="Pause/Play">\u23F8</button>';
            dots += '<button class="btn-frame" id="btn-frame-next">\u23E9</button>';
            dots += '</div>';
            el('qr-frame-info').innerHTML = dots;
            renderQrFrame(0);
            qrCycleTimer = setInterval(() => {
                qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
            }, 2500);
            el('btn-frame-prev').onclick = () => {
                qrFrameIdx = (qrFrameIdx - 1 + qrFrames.length) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, 2500);
                }
            };
            el('btn-frame-next').onclick = () => {
                qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                renderQrFrame(qrFrameIdx);
                // Reset timer so manual nav isn't immediately overridden
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, 2500);
                }
            };
            el('btn-frame-pause').onclick = () => {
                if (qrCycleTimer) {
                    clearInterval(qrCycleTimer);
                    qrCycleTimer = null;
                    el('btn-frame-pause').textContent = '\u25B6';
                } else {
                    qrCycleTimer = setInterval(() => {
                        qrFrameIdx = (qrFrameIdx + 1) % qrFrames.length;
                        renderQrFrame(qrFrameIdx);
                    }, 2500);
                    el('btn-frame-pause').textContent = '\u23F8';
                }
            };
        }
        showScreen('qr-display');
    } catch (e) {
        toast('QR generation failed: ' + e, 'error', 5000);
    }
}

function renderQrFrame(idx) {
    if (!qrFrames || idx >= qrFrames.length) return;
    el('qr-container').innerHTML = qrFrames[idx].svg;
    for (let i = 0; i < qrFrames.length; i++) {
        const dot = document.getElementById(`fdot-${i}`);
        if (dot) dot.className = `frame-dot${i === idx ? ' active' : ''}`;
    }
    const c = el('qr-container');
    c.style.opacity = '0.7';
    setTimeout(() => { c.style.opacity = '1'; }, 100);
}

function stopQrCycle() {
    if (qrCycleTimer) { clearInterval(qrCycleTimer); qrCycleTimer = null; }
    qrFrames = null;
}

// ─── Receive ───

function showReceive() {
    if (!walletData) return;
    const wallet = JSON.parse(walletData);

    // Find first unused receive address (no UTXOs seen)
    let addrIdx = 0;
    if (utxoSnapshot && utxoSnapshot.length > 0) {
        try {
            const uniqueScripts = new Set(utxoSnapshot.map(u => JSON.stringify(u.script_public_key)));
            addrIdx = Math.min(uniqueScripts.size, wallet.receive_addresses.length - 1);
        } catch (e) {
            // Fallback to index 0
        }
    }

    const addr = wallet.receive_addresses[addrIdx];
    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(addr)));
        el('receive-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('receive-qr').innerHTML = '';
    }
    el('receive-address').textContent = addr;
    showScreen('receive');
}

function copyAddress() {
    const addr = el('receive-address').textContent;
    navigator.clipboard.writeText(addr).then(() => {
        el('btn-copy-address').textContent = 'Copied!';
        setTimeout(() => { el('btn-copy-address').textContent = 'Copy Address'; }, 1500);
    });
}

function hex_encode(str) {
    return Array.from(new TextEncoder().encode(str))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Broadcast ───

function hideBroadcastResult() {
    const card = el('broadcast-result');
    card.classList.add('hidden');
    card.className = 'result-card hidden';
    el('input-signed-hex').value = '';
    // Re-show the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = '';
}

function showBroadcastSuccess(txId) {
    const card = el('broadcast-result');
    card.className = 'result-card success';
    card.classList.remove('hidden');
    el('broadcast-result-icon').textContent = '';
    el('broadcast-result-msg').textContent = 'Transaction broadcast!';
    el('broadcast-result-txid').textContent = txId;
    el('btn-copy-txid').style.display = 'block';
    el('btn-broadcast-done').style.display = 'block';
    // Hide the form card
    const formCard = document.querySelector('#screen-broadcast .card');
    if (formCard) formCard.style.display = 'none';
}

function showBroadcastError(err) {
    const card = el('broadcast-result');
    card.className = 'result-card error';
    card.classList.remove('hidden');
    el('broadcast-result-icon').textContent = '';
    el('broadcast-result-msg').textContent = 'Broadcast failed';
    el('broadcast-result-txid').textContent = String(err);
    el('btn-copy-txid').style.display = 'none';
    el('btn-broadcast-done').style.display = 'block';
}

function handleSignedScan(data) {
    const hexStr = Array.from(new Uint8Array(data))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    try {
        const result = decode_qr_frame(hexStr);
        if (result && result.length > 0) {
            stopScanner();
            console.log('[KasSee] Scan complete: ' + result.length / 2 + ' bytes');

            // First: check for Kaspa-standard PSKT / PSKB envelope.
            // Device emits these after signing when the Kaspa-standard
            // wire format is selected. Legacy KSPT path handles the rest.
            const psktFormat = pskt_detect(result);
            if (psktFormat === 'pskb' || psktFormat === 'pskt') {
                console.log('[KasSee] ' + psktFormat.toUpperCase() + ' detected — opening review');
                openPsktReview(result);
                return;
            }

            const sigStatus = checkKsptSignatureStatus(result);

            // Compact-relay return path: if we sent a KSPT v2 to the
            // device via handlePsktRelayCompact, _psktReviewHex still
            // holds the canonical PSKB. Merge the new partial sigs
            // from the KSPT v2 back into the PSKB and re-open review.
            if ((sigStatus === 'partial' || sigStatus === 'signed') && _psktReviewHex) {
                console.log('[KasSee] KSPT v2 return with canonical PSKB held — merging');
                try {
                    const mergedPskb = pskt_merge_signed_kspt_v2(result, _psktReviewHex);
                    openPsktReview(mergedPskb);
                    toast('Signature merged into PSKB', 'ok', 2500);
                    return;
                } catch (e) {
                    console.error('[KasSee] merge failed:', e);
                    toast('Merge failed: ' + e, 'error', 5000);
                    // Fall through to legacy relay path below.
                }
            }

            if (sigStatus === 'partial') {
                console.log('[KasSee] Partial signature — relay to next signer');
                toast('Partial signature — scan with next device', 'info', 3000);
                displayKsptQr(result, 'Relay to next signer');
            } else {
                el('input-signed-hex').value = result;
                showScreen('broadcast');
            }
        } else {
            const prog = JSON.parse(decoder_progress());
            if (prog.total > 0) {
                let dots = '';
                for (let i = 0; i < prog.total; i++) {
                    dots += `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:${prog.bits[i] ? 'var(--teal)' : 'var(--border)'};${prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : ''}"></span>`;
                }
                el('scanner-status').innerHTML = dots + `<div style="margin-top:6px;font-size:12px">${prog.count} / ${prog.total} frames</div>`;
            }
        }
    } catch (e) {
        console.error('Decode error:', e);
    }
}

async function handleBroadcastHex() {
    const hex = el('input-signed-hex').value.trim();
    if (!hex) { toast('Paste a signed KSPT hex string', 'error'); return; }

    // If someone pasted a PSKB/PSKT hex, route through the PSKT review.
    const psktFormat = pskt_detect(hex);
    if (psktFormat === 'pskb' || psktFormat === 'pskt') {
        openPsktReview(hex);
        return;
    }

    const sigStatus = checkKsptSignatureStatus(hex);
    if (sigStatus === 'partial') {
        toast('Partial signature — relay to next signer', 'info', 3000);
        displayKsptQr(hex, 'Relay to next signer');
        return;
    }
    if (sigStatus === 'unsigned') {
        toast('This KSPT is unsigned — scan it with KasSigner first', 'error');
        return;
    }

    if (!BROADCAST_ENABLED) {
        toast('Broadcast disabled in this version — testing only', 'error', 5000);
        return;
    }

    showLoading('Broadcasting...');
    try {
        const txId = await withNodeRetry(wsUrl => broadcast_signed(hex, wsUrl));
        hideLoading();
        showBroadcastSuccess(txId);
    } catch (e) {
        hideLoading();
        showBroadcastError(e);
        console.error('Broadcast failed:', e);
    }
}

// ─── PSKT / PSKB Review ───
//
// When a scan or paste yields a PSKB/PSKT envelope, we open a review
// screen showing inputs, outputs, fee, and multisig progress (M/N).
// From there the user can:
//   - Relay to next signer  (re-emit identical QR for the next device)
//   - Finalize + broadcast  (when all inputs meet their sig threshold)

// Stash the hex for the current review so both buttons can access it
// without re-parsing.
let _psktReviewHex = null;

function openPsktReview(wireHex) {
    _psktReviewHex = wireHex;

    let summary;
    try {
        summary = JSON.parse(pskt_summary(wireHex, network));
    } catch (e) {
        console.error('[KasSee] PSKT parse error:', e);
        toast('Could not parse PSKT: ' + e, 'error', 5000);
        return;
    }

    console.log('[KasSee] PSKT summary:', summary);

    // Render header
    el('pskt-format').textContent = summary.format.toUpperCase();
    el('pskt-tx-version').textContent = summary.tx_version;
    el('pskt-in-count').textContent = summary.input_count;
    el('pskt-out-count').textContent = summary.output_count;
    el('pskt-fee').textContent = fmtKas(summary.fee_sompi);
    el('pskt-total-in').textContent = fmtKas(summary.total_in_sompi);
    el('pskt-total-out').textContent = fmtKas(summary.total_out_sompi);

    // Inputs list
    const inputsEl = el('pskt-inputs');
    inputsEl.innerHTML = '';
    summary.inputs.forEach((inp, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        let sigLabel;
        if (inp.multisig_m !== null && inp.multisig_m !== undefined) {
            const ok = inp.sigs_present >= inp.multisig_m;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present}/${inp.multisig_m}-of-${inp.multisig_n}</span>`;
        } else {
            const ok = inp.sigs_present >= 1;
            sigLabel = `<span class="pskt-sig-badge${ok ? ' ok' : ''}">${inp.sigs_present} sig${inp.sigs_present === 1 ? '' : 's'}</span>`;
        }
        row.innerHTML = `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${inp.script_kind}</span>
                ${sigLabel}
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${fmtKas(inp.amount_sompi)} KAS</div>
                <div class="pskt-label">Prev TX</div>
                <div class="pskt-value pskt-mono">${shortenHex(inp.prev_tx_id)}:${inp.prev_index}</div>
            </div>
        `;
        inputsEl.appendChild(row);
    });

    // Outputs list
    const outputsEl = el('pskt-outputs');
    outputsEl.innerHTML = '';
    summary.outputs.forEach((out, i) => {
        const row = document.createElement('div');
        row.className = 'pskt-row';
        row.innerHTML = `
            <div class="pskt-row-head">
                <span class="pskt-idx">#${i}</span>
                <span class="pskt-kind">${out.script_kind}</span>
            </div>
            <div class="pskt-row-body">
                <div class="pskt-label">Amount</div>
                <div class="pskt-value">${fmtKas(out.amount_sompi)} KAS</div>
                <div class="pskt-label">To</div>
                <div class="pskt-value pskt-mono">${out.address || '(unrecognized script)'}</div>
            </div>
        `;
        outputsEl.appendChild(row);
    });

    // Enable/disable Finalize button based on readiness
    const btnFinalize = el('btn-pskt-finalize');
    btnFinalize.disabled = !summary.finalize_ready;
    btnFinalize.textContent = summary.finalize_ready
        ? 'Finalize + broadcast'
        : 'Needs more signatures';

    showScreen('pskt-review');
}

/// Open the relay format picker modal. User chooses between standard
/// PSKB (any wallet) or compact KSPT v2 (KasSigner devices only).
function openRelayModal() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    el('relay-choice-modal').classList.remove('hidden');
}

function closeRelayModal() {
    el('relay-choice-modal').classList.add('hidden');
}

/// Relay in STANDARD PSKB hex — interoperable with any Kaspa wallet
/// that speaks PSKB, including another KasSee instance. The wire
/// format is not mutated; this is a display pass-through.
function handlePsktRelay() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    displayKsptQr(_psktReviewHex, 'Relay to next signer');
}

/// Relay in COMPACT KSPT v2 — converts the canonical PSKB to a KSPT
/// v2 partial blob (~5× fewer QR frames). Only KasSigner devices
/// can decode this. The PSKB stays as the canonical in-memory state;
/// only the wire transport is compressed.
///
/// Flow: KasSee holds PSKB → compact-relay to KasSigner → device
/// signs and returns a KSPT v2 → handleSignedScan merges the new
/// sigs back into _psktReviewHex via pskt_merge_signed_kspt_v2.
function handlePsktRelayCompact() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    let ksptHex;
    try {
        ksptHex = pskt_relay_to_kspt_v2(_psktReviewHex);
    } catch (e) {
        console.error('[KasSee] compact relay encode failed:', e);
        toast('Compact relay failed: ' + e, 'error', 5000);
        return;
    }
    console.log('[KasSee] Compact relay: PSKB hex ' + _psktReviewHex.length +
                ' → KSPT v2 hex ' + ksptHex.length +
                ' (' + Math.round((1 - ksptHex.length / _psktReviewHex.length) * 100) + '% smaller)');
    displayKsptQr(ksptHex, 'Relay to KasSigner (compact)');
}

/// Finalize + broadcast — PSKT-NATIVE path.
///
/// Walks the PSKB JSON once inside WASM, assembles a consensus
/// Transaction directly (sig_scripts with partial sigs + redeem
/// script for P2SH multisig), Borsh-serializes it to the node. No
/// KSPT intermediate format anywhere in the flow.
async function handlePsktFinalize() {
    if (!_psktReviewHex) { toast('No PSKT loaded', 'error'); return; }
    if (!BROADCAST_ENABLED) {
        toast('Broadcast disabled in this version — testing only', 'error', 5000);
        return;
    }

    console.log('[KasSee] PSKT-native finalize + broadcast — PSKB hex length:', _psktReviewHex.length);

    showLoading('Broadcasting...');
    try {
        const txId = await withNodeRetry(
            wsUrl => pskt_finalize_and_broadcast(_psktReviewHex, wsUrl)
        );
        console.log('[KasSee] Node accepted (PSKT path). TX ID:', txId);
        hideLoading();
        _psktReviewHex = null;
        showScreen('broadcast');
        showBroadcastSuccess(txId);
    } catch (e) {
        hideLoading();
        showBroadcastError(e);
        console.error('[KasSee] Broadcast failed:', e);
    }
}

function fmtKas(sompi) {
    const n = Number(sompi) / 1e8;
    if (n === 0) return '0';
    if (Math.abs(n) < 0.00000001) return n.toExponential(2);
    return n.toFixed(8).replace(/\.?0+$/, '');
}

function shortenHex(hex) {
    if (!hex || hex.length <= 20) return hex;
    return hex.slice(0, 10) + '\u2026' + hex.slice(-10);
}

// ─── Multisig Spend ───

function handleDescriptorScan(data) {
    // Descriptor comes as multi-frame binary (same protocol as KSPT)
    const hexStr = Array.from(new Uint8Array(data))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    try {
        const result = decode_qr_frame(hexStr);
        if (result && result.length > 0) {
            stopScanner();
            // Convert hex back to ASCII text
            const bytes = [];
            for (let i = 0; i < result.length; i += 2) {
                bytes.push(parseInt(result.substr(i, 2), 16));
            }
            const text = new TextDecoder().decode(new Uint8Array(bytes)).trim();
            if (text.startsWith('multi(') || text.startsWith('multi_hd(')) {
                el('input-ms-descriptor').value = text;
                showScreen('multisig');
                toast('Descriptor scanned', 'ok', 1500);
            } else {
                toast('Not a valid descriptor', 'error');
            }
        } else {
            const prog = JSON.parse(decoder_progress());
            if (prog.total > 0) {
                let dots = '';
                for (let i = 0; i < prog.total; i++) {
                    dots += '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 3px;background:' + (prog.bits[i] ? 'var(--teal)' : 'var(--border)') + ';' + (prog.bits[i] ? 'box-shadow:0 0 6px var(--teal-glow)' : '') + '"></span>';
                }
                el('scanner-status').innerHTML = dots + '<div style="margin-top:6px;font-size:12px">' + prog.count + ' / ' + prog.total + ' frames</div>';
            }
        }
    } catch (e) {
        console.error('Descriptor decode error:', e);
    }
}

async function handleMultisigCreate() {
    const descriptor = el('input-ms-descriptor').value.trim();
    const sourceAddr = el('input-ms-source').value.trim();
    const destAddr = el('input-ms-dest').value.trim();
    const amountStr = el('input-ms-amount').value.trim();

    if (!descriptor) { toast('Paste the multisig descriptor', 'error'); return; }
    if (!sourceAddr) { toast('Enter the P2SH source address', 'error'); return; }
    if (!destAddr) { toast('Enter the destination address', 'error'); return; }
    if (!amountStr || parseFloat(amountStr) <= 0) { toast('Enter amount', 'error'); return; }

    // Resolve KNS if needed
    let resolvedDest = destAddr;
    if (destAddr.endsWith('.kas')) {
        const kns = KNS_LOOKUP[destAddr.toLowerCase()];
        if (kns) {
            resolvedDest = kns;
            toast('Resolved ' + destAddr + ' → address', 'ok', 2000);
        } else {
            toast('Unknown .kas domain', 'error'); return;
        }
    }

    // Change goes back to the same multisig address
    const changeAddr = sourceAddr;

    showLoading('Building multisig PSKB...');
    try {
        const fee = lastFeeEstimate ? lastFeeEstimate.suggested_fee : 20000;
        const wsUrl = await resolveNodeUrl();
        // HD multisig address index — for multi_hd descriptors, selects which
        // derived address to spend from. Legacy multi() ignores this (always 0).
        const addrIndexEl = el('input-ms-addr-index');
        const addrIndex = addrIndexEl ? parseInt(addrIndexEl.value) || 0 : 0;

        // Always PSKB — the Kaspa-standard wire format. Lands on Review
        // PSKB with 0/M sigs; user relays from there via the Relay modal
        // which picks between standard PSKB (any wallet) and compact
        // KSPT v2 (KasSigner devices only).
        const pskbHex = await create_multisig_pskb(
            descriptor, sourceAddr, resolvedDest, parseFloat(amountStr),
            BigInt(fee), changeAddr, wsUrl, addrIndex
        );
        hideLoading();
        console.log('[KasSee] Multisig PSKB created: ' + pskbHex.length / 2 + ' bytes');
        openPsktReview(pskbHex);
    } catch (e) {
        hideLoading();
        toast('Multisig TX failed: ' + e, 'error', 5000);
        console.error('Multisig TX error:', e);
    }
}

async function handleMsMax() {
    const sourceAddr = el('input-ms-source').value.trim();
    if (!sourceAddr) { toast('Enter source address first', 'error'); return; }

    showLoading('Fetching balance...');
    try {
        const wsUrl = await resolveNodeUrl();
        const utxosJson = await fetch_utxos_for_address_js(sourceAddr, wsUrl);
        hideLoading();
        const utxos = JSON.parse(utxosJson);
        const total = utxos.reduce((s, u) => s + u.amount, 0);
        const fee = lastFeeEstimate ? lastFeeEstimate.suggested_fee : 20000;
        const maxKas = Math.max(0, (total - fee) / 100000000);
        el('input-ms-amount').value = maxKas.toFixed(8);
        el('ms-balance-info').textContent = 'Balance: ' + (total / 100000000).toFixed(8) + ' KAS (' + utxos.length + ' UTXOs)';
    } catch (e) {
        hideLoading();
        toast('Balance fetch failed: ' + e, 'error');
    }
}

// ─── Camera QR scanner ───

function startScanner(title, callback) {
    scanCallback = callback;
    el('scanner-title').textContent = title;
    el('scanner-status').textContent = 'Starting camera...';
    reset_qr_decoder();
    showScreen('scanner');

    const video = el('scanner-video');
    const canvas = el('scanner-canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 720 }, height: { ideal: 720 } }
    }).then(stream => {
        scanStream = stream;
        video.srcObject = stream;
        video.play();
        el('scanner-status').textContent = 'Point at QR code';
        scanLoop(video, canvas, ctx);
    }).catch(err => {
        el('scanner-status').textContent = 'Camera error: ' + err.message;
    });
}

function scanLoop(video, canvas, ctx) {
    if (!scanStream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
        if (code && code.binaryData && code.binaryData.length > 0) {
            if (scanCallback) scanCallback(new Uint8Array(code.binaryData));
        }
    }
    scanAnimFrame = requestAnimationFrame(() => scanLoop(video, canvas, ctx));
}

function stopScanner() {
    if (scanAnimFrame) { cancelAnimationFrame(scanAnimFrame); scanAnimFrame = null; }
    if (scanStream) { scanStream.getTracks().forEach(t => t.stop()); scanStream = null; }
    scanCallback = null;
    showScreen(walletData ? 'dashboard' : 'welcome');
}

// ─── Addresses ───

let addressesReturnScreen = 'dashboard';
function showAddresses() {
    if (!walletData) return;
    addressesReturnScreen = currentScreenName || 'dashboard';
    const wallet = JSON.parse(walletData);
    let html = '<div class="addr-section-title">Receive (m/44\'/111111\'/0\'/0)</div>';
    wallet.receive_addresses.forEach((addr, i) => {
        html += `<div class="addr-item" data-addr="${i}-r">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    html += '<div class="addr-section-title">Change (m/44\'/111111\'/0\'/1)</div>';
    wallet.change_addresses.forEach((addr, i) => {
        html += `<div class="addr-item" data-addr="${i}-c">
            <span class="addr-idx">${i}</span>
            <span class="addr-val">${addr}</span>
            <span class="copy-icon">⧉</span>
        </div>`;
    });
    el('address-list').innerHTML = html;

    document.querySelectorAll('.addr-item').forEach(item => {
        const da = item.dataset.addr;
        const isChange = da.endsWith('-c');
        const idx = parseInt(da);
        let pressTimer;

        item.onclick = () => {
            const addr = item.querySelector('.addr-val').textContent.trim();
            showVerify(addr, idx, isChange);
        };

        item.onpointerdown = () => {
            pressTimer = setTimeout(() => {
                const addr = item.querySelector('.addr-val').textContent.trim();
                navigator.clipboard.writeText(addr);
                const icon = item.querySelector('.copy-icon');
                icon.textContent = '✓';
                setTimeout(() => { icon.textContent = '⧉'; }, 800);
                document.querySelectorAll('.addr-item').forEach(e => e.style.borderColor = '');
                item.style.borderColor = 'var(--teal)';
            }, 500);
        };
        item.onpointerup = () => clearTimeout(pressTimer);
        item.onpointerleave = () => clearTimeout(pressTimer);
    });
    showScreen('addresses');
}

function showVerify(addr, index, isChange) {
    const path = isChange
        ? `m/44'/111111'/0'/1/${index}`
        : `m/44'/111111'/0'/0/${index}`;
    el('verify-path').textContent = path;
    el('verify-address').textContent = addr;

    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(addr)));
        el('verify-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('verify-qr').innerHTML = '';
    }
    showScreen('verify');
}

async function showUtxos() {
    if (!walletData) return;
    showLoading('Fetching UTXOs...');

    try {
        const utxosJson = await withNodeRetry(wsUrl => fetch_utxos(walletData, wsUrl));
        const utxos = JSON.parse(utxosJson);
        hideLoading();

        const totalSompi = utxos.reduce((s, u) => s + u.amount, 0);
        el('utxo-summary').textContent = `${utxos.length} UTXO${utxos.length !== 1 ? 's' : ''} · ${(totalSompi / 1e8).toFixed(8)} KAS`;

        if (utxos.length === 0) {
            el('utxo-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">No UTXOs found</div>';
        } else {
            utxos.sort((a, b) => b.amount - a.amount);
            let html = '';
            utxos.forEach((u, i) => {
                const kas = (u.amount / 1e8).toFixed(8);
                html += `<div class="utxo-item">
                    <div class="utxo-amount">${kas} KAS</div>
                    <div class="utxo-detail">${u.tx_id}:${u.index}</div>
                    <div class="utxo-detail" style="color:var(--text-dim)">DAA: ${u.block_daa_score}</div>
                </div>`;
            });
            el('utxo-list').innerHTML = html;
        }

        showScreen('utxos');
    } catch (e) {
        hideLoading();
        toast('Failed to fetch UTXOs: ' + e, 'error', 5000);
    }
}

async function handleConsolidate() {
    if (!walletData) return;
    const fee = 10000;

    showLoading('Building consolidation TX...');
    try {
        const ksptHex = await withNodeRetry(wsUrl =>
            create_consolidate_kspt(walletData, BigInt(fee), wsUrl)
        );
        hideLoading();
        displayKsptQr(ksptHex, 'Scan with KasSigner');
    } catch (e) {
        hideLoading();
        toast('Consolidation failed: ' + e, 'error', 5000);
    }
}

// ─── Transaction history (UTXO diff tracking) ───

function trackUtxoChanges(currentUtxos) {
    const now = Date.now();

    if (!utxoSnapshot) {
        // First snapshot — record all existing UTXOs as initial balance
        for (const u of currentUtxos) {
            historyEntries.push({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
        if (historyEntries.length > 100) historyEntries.length = 100;
        utxoSnapshot = currentUtxos;
        return;
    }

    const prevKeys = new Set(utxoSnapshot.map(u => u.tx_id + ':' + u.index));
    const currKeys = new Set(currentUtxos.map(u => u.tx_id + ':' + u.index));

    // New UTXOs = incoming
    for (const u of currentUtxos) {
        const key = u.tx_id + ':' + u.index;
        if (!prevKeys.has(key)) {
            historyEntries.unshift({
                type: 'in',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
    }

    // Gone UTXOs = spent (outgoing)
    for (const u of utxoSnapshot) {
        const key = u.tx_id + ':' + u.index;
        if (!currKeys.has(key)) {
            historyEntries.unshift({
                type: 'out',
                amount: u.amount,
                tx_id: u.tx_id,
                index: u.index,
                time: now,
            });
        }
    }

    if (historyEntries.length > 100) historyEntries.length = 100;
    utxoSnapshot = currentUtxos;
}

function showHistory() {
    if (historyEntries.length === 0) {
        el('history-summary').textContent = 'No transactions detected yet';
        el('history-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">Refresh balance to start tracking</div>';
    } else {
        el('history-summary').textContent = historyEntries.length + ' transaction' + (historyEntries.length !== 1 ? 's' : '') + ' detected';
        let html = '';
        historyEntries.forEach(h => {
            const kas = (h.amount / 1e8).toFixed(8);
            const sign = h.type === 'in' ? '+' : '-';
            const cls = h.type === 'in' ? 'incoming' : 'outgoing';
            const icon = h.type === 'in' ? '↓' : '↑';
            const ago = timeAgo(h.time);
            html += `<div class="history-item">
                <div class="history-icon ${cls}">${icon}</div>
                <div class="history-info">
                    <div class="history-amount ${cls}">${sign}${kas} KAS</div>
                    <div class="history-time">${ago} · ${h.tx_id.slice(0, 12)}…</div>
                </div>
            </div>`;
        });
        el('history-list').innerHTML = html;
    }
    showScreen('history');
}

function clearHistory() {
    if (!confirm('Clear transaction history?')) return;
    historyEntries = [];
    utxoSnapshot = null;
    showHistory();
}

function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.floor(hrs / 24);
    return days + 'd ago';
}

// ─── KRC20 Tokens + KRC721 NFTs ───

async function showTokens() {
    if (!walletData) { toast('Import kpub first', 'info'); return; }

    showLoading('Fetching tokens & NFTs...');
    const wallet = JSON.parse(walletData);
    const allAddresses = [...wallet.receive_addresses, ...wallet.change_addresses];

    const tokenMap = {}; // tick → { balance, decimals }
    const nftList = []; // { tick, tokenId, image, name }

    // ─── KRC20 ───
    const krc20Base = KASPLEX_API[network];
    if (krc20Base) {
        for (const addr of allAddresses) {
            try {
                const resp = await fetch(`${krc20Base}/krc20/address/${addr}/tokenlist`, { signal: AbortSignal.timeout(8000) });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.result && Array.isArray(data.result)) {
                        for (const t of data.result) {
                            const tick = t.tick || t.ticker || '';
                            const bal = parseInt(t.balance || '0');
                            const dec = parseInt(t.dec || '8');
                            if (tick && bal > 0) {
                                if (!tokenMap[tick]) tokenMap[tick] = { balance: 0, decimals: dec };
                                tokenMap[tick].balance += bal;
                            }
                        }
                    }
                }
            } catch (e) { /* skip */ }
        }
    }

    // ─── KRC721 ───
    const krc721Base = KRC721_API[network];
    if (krc721Base) {
        const collectionBuri = {}; // tick → buri cache

        for (const addr of allAddresses) {
            try {
                const resp = await fetch(`${krc721Base}/address/${addr}`, { signal: AbortSignal.timeout(8000) });
                if (resp.ok) {
                    const data = await resp.json();
                    const items = data.result || [];
                    if (Array.isArray(items)) {
                        for (const nft of items) {
                            const tick = nft.tick || '';
                            const tokenId = nft.tokenId || nft.token_id || '';
                            if (!tick || !tokenId) continue;

                            // Fetch collection buri if not cached
                            if (!(tick in collectionBuri)) {
                                try {
                                    const cResp = await fetch(`${krc721Base}/nfts/${tick}`, { signal: AbortSignal.timeout(8000) });
                                    if (cResp.ok) {
                                        const cData = await cResp.json();
                                        collectionBuri[tick] = (cData.result && cData.result.buri) || '';
                                    } else {
                                        collectionBuri[tick] = '';
                                    }
                                } catch (e) { collectionBuri[tick] = ''; }
                            }

                            // Build metadata path from buri/tokenId.json
                            let image = '';
                            if (collectionBuri[tick]) {
                                image = collectionBuri[tick] + '/' + tokenId + '.json';
                            }

                            nftList.push({ tick, tokenId, image, name: tick + ' #' + tokenId });
                        }
                    }
                }
            } catch (e) { /* skip */ }
        }
    }

    hideLoading();

    // ─── Render ───
    const ticks = Object.keys(tokenMap).sort();
    const totalItems = ticks.length + nftList.length;

    if (totalItems === 0) {
        el('tokens-summary').textContent = 'No tokens or NFTs found';
        el('tokens-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:20px">Your addresses have no KRC-20 tokens or KRC-721 NFTs</div>';
        showScreen('tokens');
        return;
    }

    let html = '';

    // KRC20 section
    if (ticks.length > 0) {
        html += '<div class="tokens-section-label">KRC-20 Tokens</div>';
        for (const tick of ticks) {
            const t = tokenMap[tick];
            const display = (t.balance / Math.pow(10, t.decimals)).toFixed(t.decimals);
            const iconUrl = `img/tokens/${tick.toLowerCase()}.png`;
            html += `<div class="token-item">
                <img class="token-icon" src="${iconUrl}" alt="${tick}" onerror="this.style.display='none'">
                <div class="token-tick">${tick}</div>
                <div class="token-balance">${display}</div>
            </div>`;
        }
    }

    // KRC721 section
    if (nftList.length > 0) {
        html += '<div class="tokens-section-label" style="margin-top:12px">KRC-721 NFTs</div>';
        for (let i = 0; i < nftList.length; i++) {
            const nft = nftList[i];
            html += `<div class="nft-item" id="nft-item-${i}">
                <div class="nft-thumb-placeholder" id="nft-img-${i}"></div>
                <div class="nft-info">
                    <div class="nft-tick">${nft.tick}</div>
                    <div class="nft-id">#${nft.tokenId}</div>
                </div>
            </div>`;
        }
    }

    const parts = [];
    if (ticks.length > 0) parts.push(ticks.length + ' token' + (ticks.length !== 1 ? 's' : ''));
    if (nftList.length > 0) parts.push(nftList.length + ' NFT' + (nftList.length !== 1 ? 's' : ''));
    el('tokens-summary').textContent = parts.join(', ') + ' found';
    el('tokens-list').innerHTML = html;
    showScreen('tokens');

    // Lazy-load NFT images from IPFS metadata
    for (let i = 0; i < nftList.length; i++) {
        const nft = nftList[i];
        if (!nft.image) continue;
        const metaUrl = nft.image.startsWith('ipfs://')
            ? 'https://gateway.pinata.cloud/ipfs/' + nft.image.slice(7)
            : nft.image;
        fetch(metaUrl, { signal: AbortSignal.timeout(15000) })
            .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
            .then(meta => {
                let imgUri = meta.image || '';
                if (imgUri.startsWith('ipfs://')) imgUri = 'https://gateway.pinata.cloud/ipfs/' + imgUri.slice(7);
                if (imgUri) {
                    const container = el('nft-img-' + i);
                    if (container) {
                        container.innerHTML = `<img class="nft-thumb" src="${imgUri}" alt="${nft.name}" onerror="this.parentElement.innerHTML=''">`;
                    }
                }
            })
            .catch(() => {});
    }
}

// ─── Donation / support screen ───

function handleLogoTap() {
    if (walletData) {
        // Wallet loaded — open send screen prefilled with donation address
        openSendScreen().then(() => {
            el('input-dest').value = DONATE_ADDRESS;
            el('input-amount').value = '';
            el('input-amount').focus();
        });
    } else {
        // No wallet — show donation QR for copying
        showDonateScreen();
    }
}

function showDonateScreen() {
    el('donate-address').textContent = DONATE_ADDRESS;
    try {
        const frames = JSON.parse(generate_qr_frames(hex_encode(DONATE_ADDRESS)));
        el('donate-qr').innerHTML = frames[0].svg;
    } catch (e) {
        el('donate-qr').innerHTML = '';
    }
    showScreen('donate');
}

// ─── Node settings ───

function showSettings() {
    el('input-node-url').value = customNodeUrl || '';
    el('select-network').value = network;
    showScreen('settings');
}

function saveSettings() {
    const url = el('input-node-url').value.trim();
    if (url) {
        customNodeUrl = url;
        console.log(`[KasSee] Custom node: ${url}`);
    } else {
        clearCustomNode();
    }
    const newNetwork = el('select-network').value;
    if (newNetwork !== network) {
        network = newNetwork;
        console.log(`[KasSee] Network: ${network}`);
        // Network changed — clear wallet, addresses are invalid for new network
        walletData = null;
        lastFeeEstimate = null;
        selectedUtxoIndices = null;
        cachedUtxos = null;
        historyEntries = [];
        utxoSnapshot = null;
        el('balance-kas').textContent = '—';
        el('balance-sompi').textContent = '';
        el('balance-info').textContent = '';
        el('input-kpub').value = '';
        setStatus('offline', 'Offline');
        toast('Network changed — import your kpub again', 'info', 3000);
        showScreen('welcome');
        return;
    }
    exitSettings();
}

function clearCustomNode() {
    customNodeUrl = null;
    console.log('[KasSee] Using public nodes');
}

function exitSettings() {
    if (walletData) {
        showScreen('dashboard');
        refreshBalance();
    } else {
        showScreen('welcome');
    }
}

// ─── Wallet reset ───

function resetWallet() {
    if (!confirm('Reset wallet? You will need to re-import your kpub.')) return;
    walletData = null;
    // Preserve customNodeUrl — user's personal node config survives reset
    // Keep network setting — don't reset to mainnet
    lastFeeEstimate = null;
    selectedUtxoIndices = null;
    cachedUtxos = null;
    historyEntries = [];
    utxoSnapshot = null;
    el('balance-kas').textContent = '—';
    el('balance-sompi').textContent = '';
    el('balance-info').textContent = '';
    el('input-kpub').value = '';
    showScreen('welcome');
    setStatus('offline', 'Offline');
}

// ─── Boot ───

start().catch(e => console.error('KasSee init failed:', e));
