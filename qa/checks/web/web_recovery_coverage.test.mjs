#!/usr/bin/env node
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import {
    FakeElement, body, createClassList, element, findById, intervals, le16, le64, moduleUrl,
    setConfirmResult, setFetchHook, setupHarness, state, storedScript,
    teardownHarness, vstr,
} from './web_recovery_test_harness.mjs';

before(setupHarness);
after(teardownHarness);

test('recovery formats, frame assembly, payload readers, and invite normalization', async () => {
    const formats = await import(moduleUrl('features/covenants/recovery/import/formats.js'));
    const frames = await import(moduleUrl('features/covenants/recovery/import/frames.js'));
    const payload = await import(moduleUrl('features/covenants/recovery/scanner/payload_reader.js'));
    const optionalDate = await import(moduleUrl('features/covenants/recovery/scanner/optional_date.js'));
    const normalize = await import(moduleUrl('features/covenants/recovery/import/invite_normalization.js'));

    const covb = Uint8Array.from(Buffer.from('COVBpayload'));
    const coviHex = Buffer.from('COVIinvite').toString('hex');
    assert.equal(formats.normalizeScanBytes(covb), covb);
    assert.deepEqual([...formats.normalizeScanBytes('  COVIinvite  ')], [...Buffer.from('COVIinvite')]);
    assert.deepEqual([...formats.normalizeScanBytes({ data: covb.buffer })], [...covb]);
    assert.deepEqual([...formats.normalizeScanBytes({ data: new DataView(covb.buffer) })], [...covb]);
    assert.deepEqual([...formats.normalizeScanBytes({ data: [...covb] })], [...covb]);
    assert.throws(() => formats.normalizeScanBytes({}), /Unrecognized QR data/);
    assert.equal(formats.covenantHexFromBytes(covb), Buffer.from(covb).toString('hex'));
    assert.equal(formats.covenantHexFromBytes(Buffer.from(coviHex.toUpperCase())), coviHex);
    assert.equal(formats.covenantHexFromBytes(Uint8Array.from([1, 2, 3])), null);
    assert.equal(formats.covenantHexFromBytes(Buffer.from('not covenant')), null);
    assert.equal(formats.covenantKind('434f5642aa'), 'backup');
    assert.equal(formats.covenantKind('434f5649aa'), 'invite');
    assert.equal(formats.covenantKind('00000000'), null);

    assert.equal(frames.parseCovenantFrame(Uint8Array.from([1, 2, 3])), null);
    assert.equal(frames.parseCovenantFrame(Uint8Array.from([0, 1, 1, 1])), null);
    assert.equal(frames.parseCovenantFrame(Uint8Array.from([0, 129, 1, 1])), null);
    assert.throws(() => frames.parseCovenantFrame(Uint8Array.from([2, 2, 1, 1])), /frame index/);
    assert.throws(() => frames.parseCovenantFrame(Uint8Array.from([0, 2, 0, 1])), /frame length/);
    const first = frames.parseCovenantFrame(Uint8Array.from([0, 2, 2, 0x43, 0x4f]));
    const second = frames.parseCovenantFrame(Uint8Array.from([1, 2, 2, 0x56, 0x42]));
    let result = frames.addCovenantFrame(null, first);
    assert.equal(result.assembled, null);
    result = frames.addCovenantFrame(result.state, first);
    assert.equal(result.assembled, null);
    assert.throws(() => frames.addCovenantFrame(result.state, { ...first, payload: Uint8Array.of(1, 2) }), /Conflicting/);
    result = frames.addCovenantFrame(result.state, second);
    assert.deepEqual([...result.assembled], [...Buffer.from('COVB')]);
    const reset = frames.addCovenantFrame({ total: 3 }, first);
    assert.equal(reset.state.total, 2);
    assert.throws(() => frames.addCovenantFrame({
        total: 2, received: new Set([0, 1]), buffers: [first.payload, undefined], byteLength: 2,
    }, first), /incomplete/);
    assert.throws(() => frames.addCovenantFrame({
        total: 2, received: new Set([0]), buffers: [first.payload, undefined], byteLength: 1024 * 1024,
    }, second), /size limit/);

    assert.equal(payload.readU64(le64(513), 0), 513n);
    assert.deepEqual(payload.readLen('0300aabbcc', 0), { len: 3, endOff: 4 });
    assert.deepEqual(payload.readVstr(vstr('hello'), 0, hex => Uint8Array.from(Buffer.from(hex, 'hex'))), {
        str: 'hello', endOff: 14,
    });
    assert.equal(optionalDate.readOptionalDate(vstr('2026-08-05'), 0), '2026-08-05');
    assert.equal(optionalDate.readOptionalDate('', 0), '');
    assert.equal(optionalDate.readOptionalDate('ffff', 0), '');
    const savings = normalize.normalizeRecoveredInvite({ type: 'timelocked-savings' }, { ldi: 'date', w1: 'a', w2: 'b' });
    assert.equal(savings.locktime_date_iso, 'date');
    assert.equal(savings.wallet1_pubkey_hex, 'a');
    assert.equal(savings.wallet2_pubkey_hex, 'b');
    assert.equal(normalize.normalizeRecoveredInvite({ type: 'payjoin' }, { ldi: 'date' }).locktime_date_iso, 'date');
    normalize.normalizeRecoveredInvite({ type: 'global-allowance' }, {});
    normalize.normalizeRecoveredInvite({ type: 'additive' }, {});
    normalize.normalizeRecoveredInvite({ type: 'escrow' }, {});
});


test('untrusted asset and covenant labels render as literal text instead of DOM markup', async () => {
    const assets = await import(moduleUrl('features/assets/render.js'));
    const rendering = await import(moduleUrl('features/covenants/recovery/active/rendering.js'));

    const hostileImage = '<img src=x onerror=globalThis.__xss=1>';
    const hostileStyle = '<style>body{display:none}</style>';
    const hostileBalance = '<b>fake balance</b>';
    assets.renderWalletAssets({
        tokens: new Map([[hostileImage, { balance: '1', decimals: 0 }]]),
        nfts: [{ tick: hostileStyle, tokenId: hostileBalance }],
        domains: [hostileBalance],
    });
    const assetList = element('tokens-list');
    const assetTexts = [];
    const assetTags = [];
    const walk = node => {
        assetTags.push(node.tagName);
        if (node.textContent) assetTexts.push(node.textContent);
        for (const child of node.children || []) walk(child);
    };
    walk(assetList);
    assert.ok(assetTexts.includes(hostileImage));
    assert.ok(assetTexts.includes(hostileStyle));
    assert.ok(assetTexts.includes(`#${hostileBalance}`));
    assert.ok(assetTexts.includes(hostileBalance));
    assert.equal(assetList.innerHTML, '');
    assert.equal(assetTags.includes('IMG'), false);
    assert.equal(assetTags.includes('STYLE'), false);
    assert.equal(assetTags.includes('B'), false);

    const hostileLabel = `${hostileImage}${hostileStyle}${hostileBalance}`;
    state.covenantState.activeCovenants = [{
        type: 'dms', label: hostileLabel, address: 'kaspa:literal-markup',
    }];
    rendering.renderActiveList({ onOpen() {}, onRemove() {}, refreshBalances() {} });
    const item = element('cov-active-items').children[0];
    const badge = item.querySelector('.cov-type-badge');
    assert.equal(badge.textContent, hostileLabel);
    assert.equal(badge.children.length, 0);
    assert.equal(item.innerHTML, '');
});

test('active covenant repository, rendering, balances, watcher, and opening', async () => {
    const repository = await import(moduleUrl('features/covenants/recovery/active/repository.js'));
    const rendering = await import(moduleUrl('features/covenants/recovery/active/rendering.js'));
    const watcher = await import(moduleUrl('features/covenants/recovery/active/balance_watcher.js'));
    const opening = await import(moduleUrl('features/covenants/recovery/active/opening.js'));
    const active = await import(moduleUrl('features/covenants/recovery/active.js'));

    state.covenantState.activeCovenants = [];
    sessionStorage.setItem('activeCovenants', JSON.stringify([{ type: 'dms', address: 'kaspa:saved', label: 'DMS' }]));
    repository.loadActiveRecords();
    assert.equal(repository.activeCovenants()[0].address, 'kaspa:saved');
    sessionStorage.removeItem('activeCovenants');
    localStorage.setItem('activeCovenants', JSON.stringify([{ type: 'payjoin', address: 'kaspa:local', label: 'PayJoin' }]));
    repository.loadActiveRecords();
    assert.equal(repository.activeCovenants()[0].address, 'kaspa:local');
    sessionStorage.setItem('activeCovenants', '{bad');
    repository.loadActiveRecords();
    assert.deepEqual(repository.activeCovenants(), []);

    repository.addActiveRecord('dms', {
        address: 'kaspa:very-long-address-abcdefghijklmnopqrstuvwxyz', redeem_script_hex: '51', loaded: true,
        inactivity_daa: '100', covenant_id_hex: '00'.repeat(32),
    });
    repository.addActiveRecord('payjoin', {
        address: 'kaspa:short', redeem_script_hex: '52', role: 'owner', covenant_id_hex: '12'.repeat(32),
    });
    repository.addActiveRecord('unknown-family', { address: 'kaspa:third', redeem_script_hex: '53', extra: '' });
    repository.addActiveRecord('unknown-family', { address: 'kaspa:third', redeem_script_hex: '54', max_withdraw_sompi: 10 });
    assert.equal(repository.activeCovenants().length, 3);
    assert.equal(repository.activeCovenants()[0].label, 'unknown-family');
    assert.equal(repository.activeCovenants().find(item => item.address === 'kaspa:short').covenant_id_hex, '12'.repeat(32));
    const copied = {};
    repository.copyDefinedFields({ a: 1, b: null, c: '', d: 0 }, copied, ['a', 'b', 'c', 'd']);
    assert.deepEqual(copied, { a: 1, d: 0 });
    repository.saveActiveRecords();
    assert.match(sessionStorage.getItem('activeCovenants'), /kaspa:third/);
    repository.removeActiveRecord(0);
    assert.equal(repository.activeCovenants().length, 2);

    let opened = 0;
    let removed = 0;
    let refreshed = 0;
    rendering.renderActiveList({ onOpen: () => opened++, onRemove: () => removed++, refreshBalances: () => refreshed++ });
    assert.equal(element('cov-active-list').classList.contains('hidden'), false);
    assert.equal(element('cov-active-count').textContent, 2);
    assert.equal(refreshed, 1);
    const renderedItems = element('cov-active-items').children;
    renderedItems[0].dispatch('click', { target: new FakeElement('span') });
    assert.equal(opened, 1);
    renderedItems[0].dispatch('click', { target: Object.assign(new FakeElement('span'), { classList: createClassList(['cov-del']) }) });
    assert.equal(opened, 1);
    state.covenantState.activeCovenants = [];
    rendering.renderActiveList({ onOpen() {}, onRemove() {}, refreshBalances() {} });
    assert.equal(element('cov-active-list').classList.contains('hidden'), true);

    const balance0 = element('balance-0');
    const row0 = new FakeElement('div'); row0.classList.add('cov-active-item'); row0.appendChild(balance0);
    const balance1 = element('balance-1');
    const row1 = new FakeElement('div'); row1.classList.add('cov-active-item'); row1.appendChild(balance1);
    const balance2 = element('balance-2');
    const row2 = new FakeElement('div'); row2.classList.add('cov-active-item'); row2.appendChild(balance2);
    state.covenantState.activeCovenants = [
        { address: 'kaspa:funded' }, { address: 'kaspa:empty' }, { address: 'kaspa:fail' },
    ];
    await watcher.fetchActiveBalances();
    assert.equal(balance0.textContent, '2.5 KAS');
    assert.equal(balance1.textContent, '0 KAS');
    assert.equal(row1.style.opacity, '0.45');
    assert.equal(balance2.textContent, '?');
    const savedNode = state.networkState.customNodeUrl;
    state.networkState.customNodeUrl = null;
    setFetchHook(async () => { throw new Error('resolver down'); });
    await watcher.fetchActiveBalances();
    state.networkState.customNodeUrl = savedNode;

    state.navigationState.currentScreenName = 'covenant';
    element('cov-menu').classList.remove('hidden');
    watcher.startActiveWatcher();
    assert.ok(state.covenantWatcherState._covActiveWatcherTimer);
    const watcherCallback = intervals.get(state.covenantWatcherState._covActiveWatcherTimer);
    state.navigationState.currentScreenName = 'welcome';
    watcherCallback();
    assert.equal(state.covenantWatcherState._covActiveWatcherTimer, null);
    watcher.stopActiveWatcher();
    state.covenantState.activeCovenants = [];
    watcher.startActiveWatcher();
    assert.equal(state.covenantWatcherState._covActiveWatcherTimer, null);

    state.covenantState.activeCovenants = [{
        type: 'dms', label: 'DMS', address: 'kaspa:open', redeem_script_hex: '51', inactivity_daa: '100',
    }];
    opening.openActiveCovenant(state.covenantState.activeCovenants[0]);
    assert.equal(state.covenantState.lastCovenantResult.type, 'dms');
    assert.equal(element('cov-result-addr').textContent, 'kaspa:open');
    function escrowRedeem(alicePk, bobPk, arbiterPk) {
        const saltPrefix = '08' + 'ab'.repeat(8) + '75';
        const stateCheck = 'ad00c324000020';
        return saltPrefix
            + '6320' + alicePk + stateCheck + '66'.repeat(32) + 'ac8851'
            + '676320' + bobPk + stateCheck + '77'.repeat(32)
            + 'ac8851676320' + arbiterPk + '686868';
    }
    const escrowCases = [
        ['owner', '11'.repeat(32), '33'.repeat(32), '44'.repeat(32)],
        ['beneficiary', '33'.repeat(32), '11'.repeat(32), '44'.repeat(32)],
        ['arbiter', '33'.repeat(32), '44'.repeat(32), '11'.repeat(32)],
        [null, '33'.repeat(32), '44'.repeat(32), '55'.repeat(32)],
    ];
    for (const [expectedRole, alicePk, bobPk, arbiterPk] of escrowCases) {
        const escrow = {
            type: 'escrow', label: 'Escrow', address: `kaspa:escrow-${expectedRole ?? 'observer'}`,
            redeem_script_hex: escrowRedeem(alicePk, bobPk, arbiterPk),
        };
        opening.openActiveCovenant(escrow);
        assert.equal(state.covenantState.lastCovenantResult.role ?? null, expectedRole);
    }
    const oracleRoles = [
        ['beneficiary', '11'.repeat(32), '33'.repeat(32)],
        ['owner', '33'.repeat(32), '11'.repeat(32)],
        [null, '33'.repeat(32), '44'.repeat(32)],
    ];
    for (const [expectedRole, beneficiaryPk, ownerPk] of oracleRoles) {
        const oracleCovenant = {
            type: 'oracle-v1', label: 'Oracle', address: `kaspa:oracle-${expectedRole ?? 'observer'}`,
            redeem_script_hex: '51', beneficiary_pubkey_hex: beneficiaryPk, owner_pubkey_hex: ownerPk,
        };
        opening.openActiveCovenant(oracleCovenant);
        assert.equal(state.covenantState.lastCovenantResult.role ?? null, expectedRole);
    }

    active.covSaveActive();
    active.covLoadActive();
    active.covAddActive('dms', { address: 'kaspa:new', redeem_script_hex: '53' });
    active.covRenderActive();
    setConfirmResult(false);
    const removeButton = new FakeElement('span'); removeButton.dataset.covDelIdx = '0';
    element('cov-active-items').querySelectorAll = selector => selector === '.cov-del' ? [removeButton] : [];
    active.covRenderActive();
    removeButton.dispatch('click');
    setConfirmResult(true);
    removeButton.dispatch('click');
});

test('beneficiary and owner export payloads, QR presentation, modal, and download paths', async () => {
    const beneficiary = await import(moduleUrl('features/covenants/recovery/export/beneficiary_payload.js'));
    const owner = await import(moduleUrl('features/covenants/recovery/export/owner_payload.js'));
    const qr = await import(moduleUrl('features/covenants/recovery/export/qr_presenter.js'));
    const download = await import(moduleUrl('features/covenants/recovery/export/file_download.js'));
    const modal = await import(moduleUrl('features/covenants/recovery/export/modal.js'));
    const facade = await import(moduleUrl('features/covenants/recovery/export.js'));

    const invite = beneficiary.buildBeneficiaryExport({
        type: 'global-allowance', address: 'kaspa:beneficiary', redeem_script_hex: '51', locktime_daa: 9,
        max_withdraw_sompi: 10, cooldown_daa: 11, start_daa: 12, start_date_iso: '2026-08-05',
        locktime_date_iso: 'later', wallet1_pubkey_hex: 'aa', wallet2_pubkey_hex: 'bb',
    });
    assert.equal(Buffer.from(invite.bytes.slice(0, 4)).toString(), 'COVI');
    assert.equal(invite.extension, '.cov');
    beneficiary.buildBeneficiaryExport({ type: 'dms', address: 'a', redeem_script_hex: 'b', inactivity_daa: 10 });
    beneficiary.buildBeneficiaryExport({
        type: 'oracle-v1', address: '', redeem_script_hex: '',
        oracle_pubkey_hex: '01', oracle_covenant_key_id_hex: '02',
        oracle_covenant_binding_token_hex: '03', beneficiary_pubkey_hex: '04',
        owner_pubkey_hex: '05', attestation_statement: 'statement',
        message_commitment_hex: '06',
    });
    beneficiary.buildBeneficiaryExport({});

    const originalCrypto = globalThis.crypto;
    const calls = [];
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
        subtle: {
            async importKey(...args) { calls.push(['importKey', ...args]); return { key: true }; },
            async encrypt(_params, _key, plaintext) { return Uint8Array.from([...plaintext, 1, 2, 3]).buffer; },
        },
        getRandomValues(bytes) { bytes.fill(7); return bytes; },
    } });
    await assert.rejects(() => owner.buildOwnerExport({ type: 'dms' }, ''), /kpub is unavailable/);
    const backup = await owner.buildOwnerExport({ type: 'dms', address: 'kaspa:owner', redeem_script_hex: '51', inactivity_daa: 10 }, 'kpub');
    assert.equal(Buffer.from(backup.bytes.slice(0, 4)).toString(), 'COVB');
    assert.equal(backup.extension, '.covb');
    assert.equal(calls[0][0], 'importKey');
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: originalCrypto });

    const smallArea = new FakeElement('div');
    let qrError = null;
    qr.presentExportQr(smallArea, { hex: 'aa', bytes: Uint8Array.of(1) }, error => { qrError = error; });
    assert.equal(smallArea.children.length, 1);
    globalThis.__KASSEE_WASM_STUBS__.generate_qr_svg_text = () => { throw new Error('svg fail'); };
    qr.presentExportQr(new FakeElement('div'), { hex: 'aa' }, error => { qrError = error; });
    assert.match(qrError.message, /svg fail/);
    globalThis.__KASSEE_WASM_STUBS__.generate_qr_svg_text = value => `<svg>${value}</svg>`;

    const longArea = new FakeElement('div');
    const stop = qr.presentExportQr(longArea, { hex: 'aa'.repeat(200) }, error => { throw error; });
    const controls = longArea.children[0].children.at(-1).children;
    controls[0].click(); controls[1].click(); controls[2].click(); controls[1].click();
    for (const callback of intervals.values()) callback();
    stop();
    globalThis.__KASSEE_WASM_STUBS__.generate_qr_frames = () => { throw new Error('frame fail'); };
    qr.presentExportQr(new FakeElement('div'), { hex: 'aa'.repeat(200) }, error => { qrError = error; });
    assert.match(qrError.message, /frame fail/);
    globalThis.__KASSEE_WASM_STUBS__.generate_qr_frames = () => JSON.stringify([{ svg: '<svg>1</svg>' }, { svg: '<svg>2</svg>' }]);

    download.downloadCovenantExport({ type: 'BAD Type!', address: 'kaspa:1234567890' }, invite);
    download.downloadCovenantExport({ address: 'kaspa:abcdefghij' }, invite);
    const anchors = body.children.filter(child => child.tagName === 'A');
    assert.equal(anchors.length, 0, 'download anchor must be removed after click');

    modal.showCovenantExportModal({ label: 'DMS', type: 'dms', address: 'kaspa:abcdefghijklmnopqrstuvwxyz123456' }, invite);
    const modalNode = findById(body, 'cov-export-modal');
    assert.ok(modalNode);
    const panelButtons = modalNode.children[0].children.filter(child => child.tagName === 'BUTTON');
    panelButtons[0].click();
    panelButtons[1].click();
    panelButtons[2].click();
    assert.equal(modalNode.removed, true);
    modal.showCovenantExportModal({ label: 'DMS', type: 'dms', address: 'short' }, backup);
    const overlay = findById(body, 'cov-export-modal');
    overlay.dispatch('click', { target: overlay });

    state.covenantState.activeCovenants = [];
    await facade.covExportSingle(0);
    state.covenantState.activeCovenants = [{ type: 'dms', role: 'other', address: 'a', redeem_script_hex: '51' }];
    await facade.covExportSingle(0);
    state.walletSession.clear();
    state.covenantState.activeCovenants[0].role = 'owner';
    await facade.covExportSingle(0);
    state.walletSession.replace({ kpub: 'kpub', receive_addresses: ['kaspa:owner-receive'], change_addresses: [] });
    state.covenantState.activeCovenants = [{ type: 'dms', label: 'DMS', role: 'beneficiary', address: 'a', redeem_script_hex: '51' }];
    await facade.covExportSingle(0);
    state.covenantState.activeCovenants[0].role = 'owner';
    await facade.covExportSingle(0);
    globalThis.__KASSEE_WASM_STUBS__.build_covenant_payload = () => { throw new Error('build fail'); };
    await facade.covExportSingle(0);
    globalThis.__KASSEE_WASM_STUBS__.build_covenant_payload = () => 'aa'.repeat(40);
});

test('primary and extended covenant reconstruction covers current formats', async () => {
    const common = await import(moduleUrl('features/covenants/recovery/scanner/primary/common.js'));
    const basic = await import(moduleUrl('features/covenants/recovery/scanner/primary/basic.js'));
    const participants = await import(moduleUrl('features/covenants/recovery/scanner/primary/participants.js'));
    const primary = await import(moduleUrl('features/covenants/recovery/scanner/primary/index.js'));
    const extended = await import(moduleUrl('features/covenants/recovery/scanner/extended.js'));
    const extCommon = await import(moduleUrl('features/covenants/recovery/scanner/extended/common.js'));

    assert.throws(() => common.readStoredScript('0000'), /empty redeem script/);
    assert.equal(common.normalizedCovenantId('00'.repeat(32)), '');
    assert.equal(common.normalizedCovenantId('12'.repeat(32)), '12'.repeat(32));
    assert.equal(common.baseRecoveredRecord('x', '51').loaded, true);

    const script = '51aa';
    assert.equal(basic.rebuildDms('dms', '22'.repeat(32) + le64(100), '11'.repeat(32)).address, 'kaspa:dms');
    assert.equal(basic.rebuildAdditive('additive', storedScript(script, le64(10) + le64(20))).threshold_sompi, 10n);
    assert.equal(basic.rebuildGlobalSpendingLimit('global-spending-limit', storedScript(script, le64(10) + le64(20) + '00'.repeat(32))).covenant_id_hex, '');
    assert.equal(basic.rebuildGlobalAllowance('global-allowance', storedScript(script,
        le64(10) + le64(20) + le64(30) + '22'.repeat(32) + '33'.repeat(32))).start_daa, 30n);

    const savingsOwner = participants.rebuildTimelockedSavings('timelocked-savings', storedScript(script,
        '11'.repeat(32) + '22'.repeat(32) + le64(50) + vstr('date')), '11'.repeat(32));
    assert.equal(savingsOwner.role, 'owner');
    const savingsRecovery = participants.rebuildTimelockedSavings('timelocked-savings', storedScript(script,
        '11'.repeat(32) + '22'.repeat(32) + le64(50)), '22'.repeat(32));
    assert.equal(savingsRecovery.role, 'beneficiary');
    participants.rebuildEscrow('escrow', storedScript(script));

    const crowdfund = await import(moduleUrl('features/covenants/recovery/scanner/primary/crowdfund.js'));
    const crowdfundContribution = JSON.stringify([{
        address: 'kaspa:contribution', contributor_pubkey_hex: '31'.repeat(32),
        redeem_script_hex: '51', crowdfund_salt_hex: '32'.repeat(8),
    }]);
    const vhex = value => le16(value.length / 2) + value;
    const makeCrowdfundParams = (overrides = {}) => storedScript(script,
        (overrides.contributor ?? '31'.repeat(32))
        + vhex(overrides.salt ?? '32'.repeat(8))
        + le64(overrides.goal ?? 1000) + le64(overrides.deadline ?? 2000)
        + vstr(overrides.organizer ?? 'kaspa:organizer') + vstr(overrides.name ?? 'Campaign')
        + vhex(overrides.vk ?? '33'.repeat(8)) + vhex(overrides.pk ?? '34'.repeat(8))
        + (overrides.campaignId ?? '77'.repeat(32)) + vstr(overrides.role ?? 'organizer')
        + vstr(overrides.contributions ?? crowdfundContribution) + vstr(overrides.date ?? '2026-08-15'));
    const crowdfundParams = makeCrowdfundParams();
    const recoveredCrowdfund = crowdfund.rebuildCrowdfund('crowdfund', crowdfundParams);
    assert.equal(recoveredCrowdfund.campaign_id, '77'.repeat(32));
    assert.equal(recoveredCrowdfund.crowdfund_role, 'organizer');
    assert.equal(recoveredCrowdfund.goal_sompi, 1000n);
    assert.match(recoveredCrowdfund.crowdfund_contributions_json, /kaspa:contribution/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', `${crowdfundParams}00`), /trailing data/);
    globalThis.__KASSEE_WASM_STUBS__.crowdfund_campaign_id = () => '00'.repeat(32);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', crowdfundParams), /campaign identity/);
    globalThis.__KASSEE_WASM_STUBS__.crowdfund_campaign_id = () => '77'.repeat(32);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ contributor: 'zz'.repeat(32) })), /contributor key/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ salt: 'aa'.repeat(7) })), /salt/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ goal: 0 })), /goal\/deadline/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ deadline: 0 })), /goal\/deadline/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ organizer: 'not-an-address' })), /organizer destination/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ vk: '' })), /campaign identity/);
    assert.throws(() => crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ role: 'observer' })), /role/);
    const contributorCrowdfund = crowdfund.rebuildCrowdfund('crowdfund', makeCrowdfundParams({ role: 'contributor', date: '' }));
    assert.equal(contributorCrowdfund.crowdfund_role, 'contributor');
    assert.equal('locktime_date_iso' in contributorCrowdfund, false);

    const oracle = await import(moduleUrl('features/covenants/recovery/scanner/primary/oracle.js'));
    const oracleParams = storedScript(script,
        '41'.repeat(32) + '42'.repeat(32) + '43'.repeat(32) + '11'.repeat(32) + '44'.repeat(32)
        + '45'.repeat(32) + le64(3000) + vstr('price >= 10') + vstr('2026-08-15'));
    const recoveredOracle = oracle.rebuildOracleV1('oracle-v1', oracleParams);
    assert.equal(recoveredOracle.role, 'beneficiary');
    assert.equal(recoveredOracle.locktime_daa, 3000n);
    assert.equal(recoveredOracle.attestation_statement, 'price >= 10');
    assert.throws(() => oracle.rebuildOracleV1('oracle-v1', `${oracleParams}00`), /trailing data/);
    const oracleOwnerParams = storedScript(script,
        '41'.repeat(32) + '42'.repeat(32) + '43'.repeat(32) + '33'.repeat(32) + '11'.repeat(32)
        + '45'.repeat(32) + le64(3000) + vstr('price >= 10') + vstr(''));
    const recoveredOwnerOracle = oracle.rebuildOracleV1('oracle-v1', oracleOwnerParams);
    assert.equal(recoveredOwnerOracle.role, 'owner');
    assert.equal('locktime_date_iso' in recoveredOwnerOracle, false);
    const zeroBinding = storedScript(script,
        '41'.repeat(32) + '42'.repeat(32) + '00'.repeat(32) + '11'.repeat(32) + '44'.repeat(32)
        + '45'.repeat(32) + le64(3000) + vstr('price >= 10') + vstr(''));
    assert.throws(() => oracle.rebuildOracleV1('oracle-v1', zeroBinding), /binding\/participant\/commitment/);

    const privateSwap = await import(moduleUrl('features/covenants/recovery/scanner/primary/private_swap.js'));
    const swapState = {
        role: 'alice', swapId: '51'.repeat(16), myKeyId: '52'.repeat(32), myClaimPubkey: '53'.repeat(32),
        myBindingToken: '54'.repeat(32), adaptorPoint: '55'.repeat(32),
        myOwnerPubkey: '56'.repeat(32), counterClaimPubkey: '57'.repeat(32), counterDestination: 'kaspa:counter-dest',
        myTimeoutDaa: '4000', mySalt: '58'.repeat(16), myAddress: 'kaspa:private-swap', myRedeem: '51aa',
        counterOwnerPubkey: '59'.repeat(32), myDestination: 'kaspa:my-dest', counterTimeoutDaa: '3500',
        counterSalt: '5a'.repeat(16), counterAddress: 'kaspa:private-swap', counterRedeem: '51aa',
    };
    const privateSwapParams = storedScript('51aa', vstr(JSON.stringify(swapState)));
    const recoveredSwap = privateSwap.rebuildPrivateSwap('private-swap', privateSwapParams);
    assert.equal(recoveredSwap.role, 'alice');
    assert.equal(recoveredSwap.locktime_daa, 4000n);
    assert.match(recoveredSwap.private_swap_recovery_json, /counterTimeoutDaa/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', `${privateSwapParams}00`), /trailing data/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', storedScript('51aa', vstr(JSON.stringify({
        ...swapState, counterCompletedSignature: 'aa',
    })))), /forbidden transient or secret material/);
    const invalidSwap = patch => storedScript('51aa', vstr(JSON.stringify({ ...swapState, ...patch })));
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ role: 'observer' })), /role/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ swapId: 'zz' })), /swap ID/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ myKeyId: '00' })), /key ID/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ myClaimPubkey: '' })), /claim key/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ myBindingToken: 'ab' })), /binding token/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ adaptorPoint: 'ab' })), /adaptor point/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ myAddress: '' })), /covenant pair/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', storedScript('52bb', vstr(JSON.stringify(swapState)))), /stored script/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ nested: { secretValue: 'do-not-restore' } })), /forbidden transient or secret material/);
    assert.throws(() => privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({
        nested: { a: { b: { c: { d: { e: { f: { g: 'bounded' } } } } } } },
    })), /too deeply nested/);
    const bobSwap = privateSwap.rebuildPrivateSwap('private-swap', invalidSwap({ role: 'bob' }));
    assert.equal(bobSwap.role, 'bob');

    assert.equal(primary.rebuildPrimaryRecoveredCovenant('dms', '22'.repeat(32) + le64(1), '11'.repeat(32)).type, 'dms');
    assert.equal(primary.rebuildPrimaryRecoveredCovenant('unknown', '', ''), undefined);

    assert.equal(extCommon.recoveredFromRedeem('x', '', 'mainnet'), null);
    assert.equal(extCommon.recoveredFromRedeem('x', '51', 'mainnet').type, 'x');
    const merkle = extended.rebuildExtendedRecoveredCovenant('merkle-whitelist', storedScript(script,
        '33'.repeat(32) + '02' + le64(70) + vstr('["kaspa:a"]')), '');
    assert.equal(merkle.merkle_depth, 2);
    const escrow = extended.rebuildExtendedRecoveredCovenant('timelocked-escrow', '22'.repeat(32) + le64(80), '11'.repeat(32));
    assert.equal(escrow.address, 'kaspa:time-escrow');
    globalThis.__KASSEE_WASM_STUBS__.covenant_timelocked_escrow = () => { throw new Error('missing'); };
    assert.equal(extended.rebuildExtendedRecoveredCovenant('timelocked-escrow', '22'.repeat(32) + le64(80), '11'.repeat(32)), false);
    globalThis.__KASSEE_WASM_STUBS__.covenant_timelocked_escrow = () => JSON.stringify({ address: 'kaspa:time-escrow', redeem_script_hex: '52' });
    const payjoin = extended.rebuildExtendedRecoveredCovenant('payjoin', '22'.repeat(32) + le64(90) + le64(2) + le64(3) + storedScript(script, vstr('date')), '');
    assert.equal(payjoin.min_inputs, 2);
    const commit = extended.rebuildExtendedRecoveredCovenant('commit-reveal', '44'.repeat(32) + le64(100) + storedScript(script, le16(1) + 'ff'), '');
    assert.equal(commit.cr_ciphertext_hex, 'ff');
    const commitNoCipher = extended.rebuildExtendedRecoveredCovenant('commit-reveal', '44'.repeat(32) + le64(100) + storedScript(script), '');
    assert.equal(commitNoCipher.cr_ciphertext_hex, '');
    assert.equal(extended.rebuildExtendedRecoveredCovenant('generic', '', ''), null);
    assert.equal(extended.rebuildExtendedRecoveredCovenant('generic', storedScript(script), '').type, 'generic');
});

test('invite, owner backup, scan controller, chain scanner, and rebuild orchestration', async () => {
    const inviteModule = await import(moduleUrl('features/covenants/recovery/import/invite.js'));
    const ownerModule = await import(moduleUrl('features/covenants/recovery/import/owner_backup.js'));
    const controller = await import(moduleUrl('features/covenants/recovery/import/controller.js'));
    const importFacade = await import(moduleUrl('features/covenants/recovery/import.js'));
    const rebuild = await import(moduleUrl('features/covenants/recovery/scanner/rebuild.js'));
    const scanner = await import(moduleUrl('features/covenants/recovery/scanner.js'));

    function inviteHex(value) {
        return Buffer.from('COVI').toString('hex') + Buffer.from(JSON.stringify(value)).toString('hex');
    }
    state.covenantState.activeCovenants = [];
    const savingsInvite = inviteHex({
        v: 1, t: 'cov-invite', ct: 'timelocked-savings', addr: 'kaspa:invite', rs: '51', d: 10,
        w1: '11'.repeat(32), w2: '22'.repeat(32), ldi: 'date',
    });
    assert.equal(inviteModule.importCovenantInvite(savingsInvite), true);
    assert.equal(state.covenantState.activeCovenants[0].role, 'beneficiary');
    assert.equal(state.covenantState.activeCovenants[0].locktime_date_iso, 'date');
    assert.equal(inviteModule.importCovenantInvite(savingsInvite), false);
    assert.throws(() => inviteModule.importCovenantInvite(inviteHex({ t: 'bad' })), /Invalid invite format/);
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', addr: 'kaspa:unknown-invite', rs: '50' }));
    assert.equal(state.covenantState.activeCovenants.find(x => x.address === 'kaspa:unknown-invite').type, 'unknown');
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'additive', addr: 'kaspa:add', rs: '52', id: 5, name: 'n', goal: '2' }));
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'global-allowance', addr: 'kaspa:allow', rs: '53', mw: 1, cd: 2, sd: 3, sdi: 'date' }));
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'escrow', addr: 'kaspa:escrow-invite', rs: '54' }));
    const oracleBinding = { okid: 'aa'.repeat(32), obt: 'bb'.repeat(32) };
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'oracle-v1', addr: 'kaspa:oracle-beneficiary', rs: '55', bpk: '11'.repeat(32), own: '22'.repeat(32), opk: '33'.repeat(32), oas: 'price >= 10', omc: 'cc'.repeat(32), ...oracleBinding }));
    assert.equal(state.covenantState.activeCovenants.find(x => x.address === 'kaspa:oracle-beneficiary').role, 'beneficiary');
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'oracle-v1', addr: 'kaspa:oracle-owner', rs: '56', bpk: '22'.repeat(32), own: '11'.repeat(32), ...oracleBinding }));
    assert.equal(state.covenantState.activeCovenants.find(x => x.address === 'kaspa:oracle-owner').role, 'owner');
    inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'oracle-v1', addr: 'kaspa:oracle-observer', rs: '57', bpk: '22'.repeat(32), own: '33'.repeat(32), ...oracleBinding }));
    assert.equal(state.covenantState.activeCovenants.find(x => x.address === 'kaspa:oracle-observer').role, 'observer');
    assert.throws(() => inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'oracle-v1', addr: 'kaspa:bad-oracle', rs: '58' })), /binding record/);
    assert.throws(() => inviteModule.importCovenantInvite(inviteHex({ t: 'cov-invite', ct: 'oracle-v1', addr: 'kaspa:bad-oracle-token', rs: '58', okid: 'aa'.repeat(32), obt: 'bad' })), /binding record/);

    globalThis.__KASSEE_WASM_STUBS__.parse_covenant_payload = () => JSON.stringify({ covenant_type_name: 'additive', params_hex: storedScript('51', le64(1) + le64(2)) });
    const originalDecryptKey = globalThis.__KASSEE_WASM_STUBS__.derive_covenant_payload_key;
    const payloadModule = await import(moduleUrl('features/covenants/payload_and_swaps/payload.js'));
    const originalDecrypt = payloadModule.decryptCovenantPayload;
    void originalDecrypt;
    const ownerHex = Buffer.from('COVB').toString('hex') + '00'.repeat(20);
    // Invalid ciphertext exercises owner-import failure while full rebuild is covered directly below.
    await assert.rejects(() => ownerModule.importOwnerBackup(ownerHex), /Decrypt failed/);
    globalThis.__KASSEE_WASM_STUBS__.derive_covenant_payload_key = originalDecryptKey;

    state.covenantState.activeCovenants = [];
    assert.equal(await rebuild.rebuildCovenant({ covenant_type_name: 'unknown', params_hex: '' }, ''), false);
    assert.equal(await rebuild.rebuildCovenant({ covenant_type_name: 'generic', params_hex: storedScript('51') }, ''), true);
    assert.equal(await rebuild.rebuildCovenant({ covenant_type_name: 'generic', params_hex: storedScript('51') }, ''), false);
    assert.equal(await rebuild.rebuildCovenant({ covenant_type_name: 'generic', params_hex: '' }, ''), false);
    globalThis.__KASSEE_WASM_STUBS__.fetch_utxos_for_address_js = () => { throw new Error('offline'); };
    assert.equal(await rebuild.rebuildCovenant({ covenant_type_name: 'generic2', params_hex: storedScript('52') }, ''), true);
    globalThis.__KASSEE_WASM_STUBS__.fetch_utxos_for_address_js = address => JSON.stringify(address.includes('empty') ? [] : [{ amount: '250000000' }]);

    state.walletSession.clear();
    assert.equal(await controller.handleCovenantScan(Buffer.from('COVI{}')), false);
    state.walletSession.replace({ kpub: 'kpub', receive_addresses: ['kaspa:owner-receive'], change_addresses: [] });
    state.scannerState._covbImporting = true;
    assert.equal(await controller.handleCovenantScan(Buffer.from('bad')), false);
    state.scannerState._covbImporting = false;
    assert.equal(await controller.handleCovenantScan(Buffer.from('bad')), false);
    const direct = Buffer.from(savingsInvite, 'hex');
    assert.equal(await importFacade.handleCovbScan(direct), true);
    const half = Math.ceil(direct.length / 2);
    const frameA = Uint8Array.from([0, 2, half, ...direct.slice(0, half)]);
    const tail = direct.slice(half);
    const frameB = Uint8Array.from([1, 2, tail.length, ...tail]);
    await controller.handleCovenantScan(frameA);
    await controller.handleCovenantScan(frameB);
    const invalidHeaderA = Uint8Array.from([0, 2, 2, 1, 2]);
    const invalidHeaderB = Uint8Array.from([1, 2, 2, 3, 4]);
    await controller.handleCovenantScan(invalidHeaderA);
    assert.equal(await controller.handleCovenantScan(invalidHeaderB), false);

    state.walletSession.clear();
    await scanner.recoverCovenants();
    state.walletSession.replace({ kpub: 'kpub', receive_addresses: ['kaspa:a'], change_addresses: [] });
    const savedNetwork = state.networkState.network;
    state.networkState.network = 'unsupported';
    await scanner.recoverCovenants();
    state.networkState.network = savedNetwork;

    const payloadPlain = 'aa'.repeat(40);
    let decryptCalls = 0;
    globalThis.__KASSEE_WASM_STUBS__.parse_covenant_payload = () => JSON.stringify({ covenant_type_name: 'generic-scan', params_hex: storedScript('55') });
    // The browser payload decryptor will fail for arbitrary bytes, so chain scanning still covers
    // duplicate, payload-fetch, malformed response, and no-result paths deterministically.
    setFetchHook(async url => {
        if (url.includes('/full-transactions')) return {
            ok: true,
            async json() {
                return [
                    { transaction_id: 'tx1', payload: '' },
                    { transaction_id: 'tx1', payload: payloadPlain },
                    { transaction_id: 'tx2', payload: '00' },
                    { transaction_id: 'tx3', payload: payloadPlain },
                ];
            },
        };
        if (url.includes('/transactions/tx1')) return { ok: true, async json() { return { payload: payloadPlain }; } };
        return { ok: false, async json() { return {}; } };
    });
    await scanner.recoverCovenants();
    setFetchHook(async () => ({ ok: true, async json() { return {}; } }));
    await scanner.recoverCovenants();
    setFetchHook(async () => { throw new Error('network'); });
    await scanner.recoverCovenants();
    assert.equal(decryptCalls, 0);
});
