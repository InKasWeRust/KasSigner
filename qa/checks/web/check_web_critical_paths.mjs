#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..', '..', '..');
const jsRoot = path.join(root, 'apps', 'kassee-web', 'web', 'js');
const read = relative => fs.readFile(path.join(jsRoot, relative), 'utf8');

const standard = await read('features/transactions/send/compose/planners/standard.js');
assert.equal((standard.match(/const pskbHex\s*=\s*await/g) || []).length, 2,
    'both standard planners must declare their PSKB result');
assert.match(standard, /create_send_pskb_with_utxos\([\s\S]*?utxosJson\s*\)/,
    'selected planning must pass explicit UTXOs without an unused node URL');
assert.doesNotMatch(standard, /(^|\n)\s*pskbHex\s*=/,
    'standard planners must not assign an undeclared PSKB binding');
assert.doesNotMatch(standard, /kassigner_(?:sdk|wallet)_.*create_transaction|prepareSend/,
    'KasSee coin selection must stay in the wallet transaction builder, outside the KasSigner SDK');

const utxoSelector = await read('features/transactions/shared/utxo_selector.js');
assert.match(utxoSelector, /SORT_MODES = new Set\(\['amount-desc', 'amount-asc', 'daa-desc', 'daa-asc'\]\)/,
    'manual UTXO inspection must keep all four amount/recency sort modes');
assert.match(utxoSelector, /const entries = orderedUtxoEntries\(utxos, mode\);[\s\S]*const chosen = entries\.filter[\s\S]*const available = entries\.filter/,
    'selected and available UTXOs must preserve the same deterministic requested ordering');
assert.ok(utxoSelector.indexOf('SELECTED UTXOs') < utxoSelector.indexOf('AVAILABLE UTXOs'),
    'selected UTXOs must always render before available UTXOs');
assert.doesNotMatch(utxoSelector, /style=["']/,
    'UTXO selector must not reintroduce inline styling');
assert.match(standard, /limit === 8[\s\S]*create_send_pskb\([\s\S]*create_send_pskb_limited\(/,
    'automatic selection must use the default 8-input policy unless Advanced overrides it');

const networkCore = await read('core/network.js');
assert.match(networkCore, /testnet[^]*kaspatest:/,
    'testnet must map directly to the kaspatest HRP');
assert.match(networkCore, /devnet[^]*kaspadev:/,
    'devnet must map directly to the kaspadev HRP');
assert.match(networkCore, /simnet[^]*kaspasim:/,
    'simnet must map directly to the kaspasim HRP');

const sendForm = await read('features/transactions/send/compose/send_form.js');
assert.match(sendForm, /balanceSendMaximumKas\(match\[1\], feeSompi\)/,
    'Send Max must pass the exact parsed fee through the pure calculator');
assert.doesNotMatch(sendForm, /\bfeeKas\b/,
    'Send Max must not depend on the removed undefined feeKas binding');

const broadcast = await read('features/transactions/send/broadcast.js');
assert.equal((broadcast.match(/processAntiKleptoResponse\(/g) || []).length, 2,
    'both scanned/image and pasted signer responses must pass through anti-klepto verification');
const compactRelay = await read('features/transactions/pskt_multisig/review_relay.js');
assert.match(compactRelay, /beginAntiKlepto\(ksptHex\)/,
    'KasSigner compact relay must begin the anti-klepto transcript before displaying the request');

const payjoinActions = await read('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/payjoin.js');
assert.match(payjoinActions, /configurePayjoinActions\(\{[^}]*\bisBeneficiary\b[^}]*\}\)/,
    'PayJoin result configuration must receive isBeneficiary explicitly');

const controller = await read('features/covenants/recovery/import/controller.js');
assert.match(controller, /finally\s*\{\s*scannerState\._covbImporting\s*=\s*false;/s,
    'covenant imports must always release the import lock');


for (const retired of [
    'features/covenants/payload_and_swaps/adaptor_policy.js',
    'app/events/contracts/adaptor_swap.js',
    'app/state/covenants/adaptor_state.js',
]) {
    await assert.rejects(
        fs.access(path.join(jsRoot, retired)),
        `retired raw-signature module must stay physically absent: ${retired}`,
    );
}


const kpubPayloadUrl = pathToFileURL(path.join(
    jsRoot,
    'features/wallet/core/kpub_qr_payload.js',
)).href;
const {
    classifyKpubQrCode,
    isBip32XpubText,
    isCanonicalKpubText,
    isLegacyKpubText,
    isSupportedKpubText,
    normalizeKpubText,
} = await import(kpubPayloadUrl);
const canonicalKpub = `kpub1:${'ab'.repeat(78)}`;
assert.equal(isCanonicalKpubText(canonicalKpub), true,
    'manual kpub input must accept the canonical text format');
assert.equal(isCanonicalKpubText(canonicalKpub.toUpperCase()), false,
    'manual kpub input must reject noncanonical uppercase text');
const legacyKpub = 'kpub2JigDdskmLLjkiA8PVnrGyEaCvwGrzET2X26crHBHDtGZERboYT4SnGXXRc7vyyNgvfuJF2XaFxqQ9uBVpU9FosVzcDhe5nfHyi2CLLzpPm';
assert.equal(isLegacyKpubText(legacyKpub), true,
    'manual kpub input must accept original Base58Check exports');
assert.equal(isSupportedKpubText(legacyKpub), true,
    'the browser must pass legacy account keys to the Rust compatibility parser');
assert.equal(isLegacyKpubText(`${legacyKpub}0`), false,
    'legacy account-key prevalidation must reject non-Base58 characters');
const kaspaCliXpub = 'xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6';
assert.equal(isBip32XpubText(kaspaCliXpub), true,
    'manual account-key input must accept account-level xpubs from the Kaspa CLI');
assert.equal(isSupportedKpubText(kaspaCliXpub), true,
    'the browser must pass Kaspa CLI xpubs to the Rust compatibility parser');
assert.equal(normalizeKpubText(`"${kaspaCliXpub}"`), kaspaCliXpub,
    'manual import must remove one matching pair of copy/pasted quotes');
const compactKpub = Uint8Array.from([1, ...new Uint8Array(78)]);
assert.deepEqual(classifyKpubQrCode({ binaryData: compactKpub, data: '' }), {
    kind: 'compact', payload: compactKpub,
}, 'QR image import must preserve the compact binary account-key envelope');
assert.deepEqual(classifyKpubQrCode({ binaryData: [], data: canonicalKpub }), {
    kind: 'text', payload: canonicalKpub,
}, 'QR image import must accept canonical textual kpub QR codes');
assert.deepEqual(classifyKpubQrCode({ binaryData: [], data: legacyKpub }), {
    kind: 'text', payload: legacyKpub,
}, 'QR image import must accept original Base58Check kpub QR codes');
assert.deepEqual(classifyKpubQrCode({ binaryData: [], data: kaspaCliXpub }), {
    kind: 'text', payload: kaspaCliXpub,
}, 'QR image import must accept account-level Kaspa CLI xpub QR codes');
assert.throws(
    () => classifyKpubQrCode({ binaryData: [1, 2, 3], data: 'not-a-kpub' }),
    /does not contain a valid KasSigner kpub/,
    'QR image import must reject unrelated QR content',
);

const sendMaxUrl = pathToFileURL(path.join(jsRoot, 'features/transactions/send/compose/send_max.js')).href;
const { balanceSendMaximumKas, selectedSendMaximumSompi } = await import(sendMaxUrl);
assert.equal(balanceSendMaximumKas('5', 300000n), '4.997');
assert.equal(balanceSendMaximumKas('0.001', 300000n), '0');
assert.equal(selectedSendMaximumSompi(100_000_000n, 1, 300_000n), 99_692_000n);
assert.equal(selectedSendMaximumSompi(100_000n, 2, 300_000n), 0n);

const exactUrl = pathToFileURL(path.join(jsRoot, 'core/exact.js')).href;
const feeMathUrl = pathToFileURL(path.join(jsRoot, 'core/fee_math.js')).href;
const { exactUnsigned, exactUnsignedJsonField, exactJsonStringify } = await import(exactUrl);
const { roundFeeFromRate, ceilFeeFromRate } = await import(feeMathUrl);
assert.equal(exactUnsigned('18446744073709551615'), 18446744073709551615n,
    'consensus u64 decimal strings must remain exact above JavaScript safe integers');
assert.equal(exactJsonStringify({ amount: 9007199254740993n }), '{"amount":"9007199254740993"}',
    'BigInt consensus values must cross JSON as decimal strings');
assert.throws(() => exactUnsigned(Number.MAX_SAFE_INTEGER + 1, 'amount'), /exact unsigned decimal integer/,
    'unsafe pre-rounded JSON Numbers must be rejected rather than trusted');
assert.equal(roundFeeFromRate('1.5', 2300n), 3450n,
    'final sompi fee rounding must use rational BigInt arithmetic');
assert.equal(ceilFeeFromRate('2.5', 10n, 0n, 11n, 10n), 28n,
    'fee markup and ceiling must remain exact');

assert.equal(exactUnsignedJsonField('{"blueScore":9007199254740993}', 'blueScore'), 9007199254740993n,
    'consensus JSON integers must be parsed before JavaScript Number conversion');
assert.throws(() => exactUnsignedJsonField('{"blueScore":1,"blueScore":2}', 'blueScore'),
    /exactly once/, 'duplicate consensus JSON fields must be rejected');


const literalTextRenderers = [
    'features/assets/render.js',
    'features/covenants/recovery/active/rendering.js',
];
for (const relative of literalTextRenderers) {
    const source = await read(relative);
    assert.doesNotMatch(source, /\.innerHTML\s*=/,
        `${relative} must not render imported or remote values through innerHTML`);
    assert.match(source, /textContent\s*=/,
        `${relative} must render untrusted display values as literal text`);
}

const assetRenderUrl = pathToFileURL(path.join(jsRoot, 'features/assets/render.js')).href;
const { formatTokenBalance } = await import(assetRenderUrl);
assert.equal(formatTokenBalance(9007199254740993n, 8), '90071992.54740993',
    'KRC20 rendering must remain exact above JavaScript safe integers');
assert.equal(formatTokenBalance('100000001', 8), '1.00000001',
    'KRC20 decimal formatting must not round through Number');

const outpointParserUrl = pathToFileURL(path.join(
    jsRoot,
    'features/covenants/blockchain/outpoint_parser.js',
)).href;
const { findSpendingSignatureScript, readFirstPush } = await import(outpointParserUrl);
const txid = '01'.repeat(32);
const signatureScript = Uint8Array.from([3, 0xaa, 0xbb, 0xcc]);
const notification = new Uint8Array(4 + 41 + 4 + signatureScript.length);
notification[1] = 0xff;
notification[3] = 0x3c;
notification.set([37, 0, 0, 0, 1], 4);
notification.set(Uint8Array.from({ length: 32 }, () => 1), 9);
notification.set([2, 0, 0, 0], 41);
notification.set([signatureScript.length, 0, 0, 0], 45);
notification.set(signatureScript, 49);
assert.deepEqual(
    [...findSpendingSignatureScript(notification, { txid, index: 2 }, { minLength: 1, maxLength: 100 })],
    [...signatureScript],
    'shared BlockAdded parsing must return the matching outpoint signature script',
);
assert.equal(findSpendingSignatureScript(notification, { txid, index: 3 }, { minLength: 1, maxLength: 100 }), null,
    'BlockAdded parsing must reject a different output index');
assert.deepEqual([...readFirstPush(signatureScript)], [0xaa, 0xbb, 0xcc],
    'shared script parsing must decode the first pushed value');


const walletSessionUrl = pathToFileURL(path.join(jsRoot, 'app/state/core/wallet_session.js')).href;
const { walletSession } = await import(walletSessionUrl);
const sourceWallet = { kpub: 'kpub-test', receive_addresses: ['kaspa:test'] };
walletSession.replace(sourceWallet);
sourceWallet.receive_addresses[0] = 'mutated-source';
const firstSnapshot = walletSession.current();
firstSnapshot.receive_addresses[0] = 'mutated-consumer';
assert.equal(walletSession.current().receive_addresses[0], 'kaspa:test',
    'wallet session must not expose mutable internal state');
assert.equal(walletSession.kpub(), 'kpub-test',
    'wallet session must expose narrow wallet metadata without reparsing JSON');
walletSession.setProfile({ id: 'saved-1', name: 'Main wallet' });
assert.deepEqual(walletSession.profile(), { id: 'saved-1', name: 'Main wallet' },
    'wallet session must track the active saved-kpub profile without exposing mutable state');
const profileSnapshot = walletSession.profile();
profileSnapshot.name = 'mutated';
assert.equal(walletSession.profile().name, 'Main wallet',
    'saved-kpub profile metadata must be copied at the session boundary');
walletSession.clear();
assert.equal(walletSession.profile(), null,
    'clearing the wallet must also clear the active saved-kpub profile');

const kpubRepositoryUrl = pathToFileURL(path.join(
    jsRoot,
    'features/wallet/kpub_manager/repository.js',
)).href;
const { createKpubRepository } = await import(kpubRepositoryUrl);
const savedValues = new Map();
const storage = {
    getItem(key) { return savedValues.has(key) ? savedValues.get(key) : null; },
    setItem(key, value) { savedValues.set(key, String(value)); },
    removeItem(key) { savedValues.delete(key); },
};
let nextId = 1;
const repository = createKpubRepository(storage, () => `saved-${nextId++}`);
const firstSaved = repository.save({ name: 'Main wallet', kpub: canonicalKpub, network: 'mainnet' });
assert.equal(firstSaved.id, 'saved-1');
assert.equal(repository.list().length, 1,
    'saving a named kpub must persist one managed entry');
repository.setAutoLoad(firstSaved.id);
assert.equal(repository.autoLoadEntry().name, 'Main wallet',
    'one saved kpub must be selectable for startup loading');
const updatedSaved = repository.save({ name: 'Everyday wallet', kpub: canonicalKpub, network: 'mainnet' });
assert.equal(updatedSaved.id, firstSaved.id,
    'saving the same kpub and network must update its friendly name instead of duplicating it');
const secondSaved = repository.save({ name: 'Test wallet', kpub: canonicalKpub, network: 'testnet-10' });
assert.equal(secondSaved.id, 'saved-2',
    'the same account key may be managed separately on another network');
assert.throws(
    () => repository.rename(secondSaved.id, 'Everyday wallet'),
    /already uses that friendly name/,
    'friendly names must remain unambiguous');
repository.remove(firstSaved.id);
assert.equal(repository.autoLoadId(), null,
    'deleting the startup kpub must clear the startup selection');
assert.equal(repository.list().length, 1,
    'deleting a saved kpub must leave unrelated entries intact');
storage.setItem('kassee-kpub-manager-v1', '{broken');
assert.deepEqual(repository.list(), [],
    'corrupt browser storage must fail closed to an empty managed-kpub list');
const unnamedFirst = repository.save({ name: '', kpub: `${canonicalKpub}-unnamed-1`, network: 'mainnet' });
const unnamedSecond = repository.save({ name: '   ', kpub: `${canonicalKpub}-unnamed-2`, network: 'mainnet' });
assert.equal(unnamedFirst.name, 'Wallet 1',
    'an omitted friendly name must receive the first available default wallet name');
assert.equal(unnamedSecond.name, 'Wallet 2',
    'automatic wallet names must remain unique and increment predictably');

const commitRevealPushdataUrl = pathToFileURL(path.join(
    jsRoot,
    'app/events/contracts/covenant_specialized/commit_reveal/pushdata.js',
)).href;
const { parseCommitRevealSignatureScript } = await import(commitRevealPushdataUrl);
const commitRevealScript = Uint8Array.from([
    2, 0xaa, 0xbb,
    0x4c, 1, 0xcc,
    1, 0xdd,
    0x00,
    0x4d, 2, 0, 0xee, 0xff,
]);
assert.deepEqual(parseCommitRevealSignatureScript(
    Buffer.from(commitRevealScript).toString('hex'),
), {
    partA: Uint8Array.from([0xaa, 0xbb]),
    partB: Uint8Array.from([0xcc]),
    redeemScript: Uint8Array.from([0xee, 0xff]),
}, 'commit-reveal verification must use the focused bounded pushdata parser');
assert.throws(
    () => parseCommitRevealSignatureScript('4c02aa'),
    /Truncated signature-script push/,
    'commit-reveal pushdata parsing must fail closed on truncated payloads',
);

const framesUrl = pathToFileURL(path.join(jsRoot, 'features/covenants/recovery/import/frames.js')).href;
const { parseCovenantFrame, addCovenantFrame } = await import(framesUrl);
assert.throws(() => parseCovenantFrame(Uint8Array.from([2, 2, 1, 0xaa])), /Invalid covenant frame index/);
assert.throws(() => parseCovenantFrame(Uint8Array.from([0, 2, 2, 0xaa])), /Invalid covenant frame length/);
const first = parseCovenantFrame(Uint8Array.from([0, 2, 2, 0x43, 0x4f]));
const second = parseCovenantFrame(Uint8Array.from([1, 2, 2, 0x56, 0x42]));
const partial = addCovenantFrame(null, first);
assert.equal(partial.assembled, null);
assert.throws(
    () => addCovenantFrame(partial.state, { ...first, payload: Uint8Array.from([0x43, 0x58]) }),
    /Conflicting duplicate covenant frame/,
);
const complete = addCovenantFrame(partial.state, second);
assert.deepEqual([...complete.assembled], [0x43, 0x4f, 0x56, 0x42]);
assert.equal(complete.state, null);


const optionalDateUrl = pathToFileURL(path.join(
    jsRoot,
    'features/covenants/recovery/scanner/optional_date.js',
)).href;
const { readOptionalDate } = await import(optionalDateUrl);
const recoveryDate = '2024-01-01';
const recoveryDateHex = Buffer.from(recoveryDate, 'utf8').toString('hex');
assert.equal(readOptionalDate(`0a00${recoveryDateHex}`, 0), recoveryDate,
    'optional recovery dates must round-trip');
assert.equal(readOptionalDate('', 0), '',
    'recovery records without an optional date must remain valid');

const inviteNormalizationSource = await read(
    'features/covenants/recovery/import/invite_normalization.js',
);
const inviteNormalizationModule = inviteNormalizationSource.replace(
    /import \{[\s\S]*?\} from '\.\.\/\.\.\/watchers_and_ui\/ui\/metadata\.js';/,
    `const ensureAllowanceParams = entry => { entry.allowanceNormalized = true; };
     const ensureEscrowParams = entry => { entry.escrowNormalized = true; };
     const ensurePiggyParams = entry => { entry.piggyNormalized = true; };`,
);
const inviteNormalizationUrl = `data:text/javascript;base64,${Buffer.from(inviteNormalizationModule).toString('base64')}`;
const { normalizeRecoveredInvite } = await import(inviteNormalizationUrl);
assert.deepEqual(
    normalizeRecoveredInvite(
        { type: 'timelocked-savings' },
        { ldi: '2024-01-01', w1: '11'.repeat(32), w2: '22'.repeat(32) },
    ),
    {
        type: 'timelocked-savings',
        locktime_date_iso: '2024-01-01',
        wallet1_pubkey_hex: '11'.repeat(32),
        wallet2_pubkey_hex: '22'.repeat(32),
    },
    'historical savings invites must normalize into the current record shape',
);
const allowanceRecord = normalizeRecoveredInvite({ type: 'global-allowance' }, {});
assert.equal(allowanceRecord.allowanceNormalized, true,
    'historical allowance records must pass through current metadata normalization');

console.log('PASS: browser critical transaction, PayJoin, covenant-import, and current recovery paths');
