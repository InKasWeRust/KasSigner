import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..', '..');
const protocol = await import(pathToFileURL(path.join(root, 'apps/kassee-web/web/js/features/covenants/signing/protocol.js')).href);

const {
    CovenantKnownScheme,
    covenantBindRequestHex,
    covenantKeyRequestHex,
    covenantKnownRequestHex,
    covenantOpaqueRequestHex,
    covenantRevealHex,
    covenantScriptFingerprint,
    covenantSignatureResponseHex,
    createCovenantSigningChallenge,
    parseCovenantResponse,
    sha256Commitment,
} = protocol;

const hex = bytes => Buffer.from(bytes).toString('hex');
const ascii = bytes => Buffer.from(bytes).toString('ascii');
const bytes = value => Buffer.from(value, 'hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');

// Key IDs are allocated by KasSigner, never selected by the host.
const keyRequest = bytes(covenantKeyRequestHex());
assert.equal(ascii(keyRequest.subarray(0, 4)), 'CVSG');
assert.equal(keyRequest[4], 2);
assert.equal(keyRequest[5], 0);
assert.equal(hex(keyRequest.subarray(56, 88)), '00'.repeat(32));
assert.equal(hex(keyRequest.subarray(88, 120)), '00'.repeat(32));

const keyId = '10'.repeat(32);
const pubkey = '22'.repeat(32);
const bindingToken = '33'.repeat(32);
const challenge = await createCovenantSigningChallenge();
const expectedHostCommitment = sha256(Buffer.concat([
    Buffer.from('KasSigner/anti-klepto/host-commit/v1', 'utf8'),
    bytes(challenge.hostSecret),
]));
assert.equal(challenge.hostCommitment, expectedHostCommitment,
    'host commitment must match the transaction anti-klepto domain exactly');

// The protocol maximum is a reviewable 1,024-byte context; it is never preview-truncated.
const context = 'K'.repeat(1024);
const commitment = sha256(Buffer.from(context, 'utf8'));
assert.equal(await sha256Commitment(context), commitment);
const canonicalScript = `20${commitment}20${pubkey}d7`;

const bind = bytes(covenantBindRequestHex({
    keyIdHex: keyId,
    commitmentHex: commitment,
    scriptHex: canonicalScript,
    context,
    scheme: CovenantKnownScheme.SHA256_PREIMAGE,
}));
assert.equal(bind[4], 2);
assert.equal(bind[5], 3);
assert.equal(hex(bind.subarray(56, 88)), keyId);
assert.equal(hex(bind.subarray(88, 120)), '00'.repeat(32));
assert.equal(hex(bind.subarray(120, 152)), commitment);
assert.equal(bind.readUInt16BE(154), 1024);
assert.equal(hex(bind.subarray(156, 156 + canonicalScript.length / 2)), canonicalScript);
assert.throws(() => covenantBindRequestHex({
    keyIdHex: keyId, commitmentHex: sha256(Buffer.from('x'.repeat(1025))),
    scriptHex: canonicalScript, context: 'x'.repeat(1025), scheme: CovenantKnownScheme.SHA256_PREIMAGE,
}), /protocol limit/);

const known = bytes(covenantKnownRequestHex({
    sessionIdHex: challenge.sessionId,
    hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId,
    bindingTokenHex: bindingToken,
    commitmentHex: commitment,
    scriptHex: canonicalScript,
    context,
    scheme: CovenantKnownScheme.SHA256_PREIMAGE,
}));
assert.equal(known[5], 1);
assert.equal(hex(known.subarray(88, 120)), bindingToken);
assert.equal(hex(known.subarray(120, 152)), commitment,
    'CVSG must carry the external commitment unchanged');
assert.equal(known.readUInt16BE(154), 1024);
assert.equal(hex(known.subarray(156, 156 + canonicalScript.length / 2)), canonicalScript);

const opaqueCommitment = 'ab'.repeat(32);
const opaqueScript = '6a20' + 'cd'.repeat(32);
const opaque = bytes(covenantOpaqueRequestHex({
    sessionIdHex: challenge.sessionId,
    hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId,
    bindingTokenHex: bindingToken,
    commitmentHex: opaqueCommitment,
    scriptHex: opaqueScript,
}));
assert.equal(opaque[5], 2);
assert.equal(hex(opaque.subarray(88, 120)), bindingToken);
assert.equal(hex(opaque.subarray(120, 152)), opaqueCommitment,
    'opaque mode must not rehash the external commitment');
assert.equal(opaque.readUInt16BE(154), 0,
    'opaque mode must not carry unreviewed host context');

const reveal = bytes(covenantRevealHex({
    sessionId: challenge.sessionId,
    keyId,
    commitment: opaqueCommitment,
    hostSecret: challenge.hostSecret,
}));
assert.equal(ascii(reveal.subarray(0, 4)), 'CVRV');
assert.equal(hex(reveal.subarray(53, 85)), opaqueCommitment,
    'CVRV must repeat the same exact covenant commitment');

const noncePoint = `02${'44'.repeat(32)}`;
const signature = '55'.repeat(64);
const responseHex = covenantSignatureResponseHex({
    sessionId: challenge.sessionId,
    keyId,
    pubkey,
    bindingToken,
    commitment: opaqueCommitment,
    noncePoint,
    signature,
});
const parsed = parseCovenantResponse(bytes(responseHex));
assert.equal(parsed.kind, 'signature');
assert.equal(parsed.sessionId, challenge.sessionId);
assert.equal(parsed.keyId, keyId);
assert.equal(parsed.pubkey, pubkey);
assert.equal(parsed.bindingToken, bindingToken);
assert.equal(parsed.commitment, opaqueCommitment,
    'CVSR must report the exact commitment that was signed');
assert.equal(parsed.noncePoint, noncePoint);
assert.equal(parsed.signature, signature);
assert.equal(await covenantScriptFingerprint(opaqueScript), sha256(bytes(opaqueScript)));

assert.throws(() => covenantKnownRequestHex({
    sessionIdHex: challenge.sessionId,
    hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId,
    bindingTokenHex: '',
    commitmentHex: commitment,
    scriptHex: canonicalScript,
    context,
}), /32 bytes/);

console.log('PASS: universal COVENANT SIGN browser protocol v2');

// Shape/error hardening: every wire family rejects an independently malformed
// security field instead of silently coercing it into another request kind.
assert.throws(() => covenantBindRequestHex({
    keyIdHex: keyId, scriptHex: canonicalScript, context: new Uint8Array(),
    scheme: CovenantKnownScheme.SHA256_PREIMAGE, commitmentHex: commitment,
}), /Invalid covenant binding request/);
const directBind = bytes(covenantBindRequestHex({
    keyIdHex: keyId, scriptHex: canonicalScript, verifyDirectKeyBinding: true,
}));
assert.equal(directBind[7], 1);
const opaqueDirect = bytes(covenantOpaqueRequestHex({
    sessionIdHex: challenge.sessionId, hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId, bindingTokenHex: bindingToken, commitmentHex: opaqueCommitment,
    scriptHex: opaqueScript, verifyDirectKeyBinding: true,
}));
assert.equal(opaqueDirect[7], 1);
assert.throws(() => covenantKnownRequestHex({
    sessionIdHex: challenge.sessionId, hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId, bindingTokenHex: bindingToken, commitmentHex: commitment,
    scriptHex: canonicalScript, context: 'review', scheme: 99,
}), /Unknown known-covenant scheme/);
assert.throws(() => covenantSignatureResponseHex({
    sessionId: challenge.sessionId, keyId, pubkey, bindingToken,
    commitment: opaqueCommitment, noncePoint: `03${'44'.repeat(32)}`, signature,
}), /even-Y/);
assert.throws(() => covenantRevealHex({
    sessionId: '00'.repeat(16), keyId, commitment, hostSecret: challenge.hostSecret,
}), /session cannot be zero/);

function rawResponse(kind, overrides = {}) {
    const out = Buffer.alloc(247);
    out.write('CVSR', 0, 'ascii'); out[4] = 2; out[5] = kind;
    Buffer.from(overrides.sessionId ?? challenge.sessionId, 'hex').copy(out, 6);
    Buffer.from(overrides.keyId ?? keyId, 'hex').copy(out, 22);
    Buffer.from(overrides.pubkey ?? pubkey, 'hex').copy(out, 54);
    Buffer.from(overrides.bindingToken ?? bindingToken, 'hex').copy(out, 86);
    Buffer.from(overrides.commitment ?? opaqueCommitment, 'hex').copy(out, 118);
    Buffer.from(overrides.noncePoint ?? noncePoint, 'hex').copy(out, 150);
    Buffer.from(overrides.signature ?? signature, 'hex').copy(out, 183);
    return out;
}

const zero16 = '00'.repeat(16), zero32 = '00'.repeat(32), zero33 = '00'.repeat(33), zero64 = '00'.repeat(64);
const keyResponse = rawResponse(0, { sessionId: zero16, bindingToken: zero32, commitment: zero32, noncePoint: zero33, signature: zero64 });
assert.equal(parseCovenantResponse(keyResponse).kind, 'key');
const bindingResponse = rawResponse(3, { sessionId: zero16, noncePoint: zero33, signature: zero64 });
assert.equal(parseCovenantResponse(bindingResponse).kind, 'binding');
const nonceResponse = rawResponse(1, { signature: zero64 });
assert.equal(parseCovenantResponse(nonceResponse).kind, 'nonce');
assert.equal(parseCovenantResponse(Buffer.from(responseHex, 'utf8')).kind, 'signature', 'ASCII-hex scanner payload is accepted exactly');

for (const [buffer, error] of [
    [Buffer.alloc(10), /current KasSigner covenant response/],
    [rawResponse(9), /Unknown covenant response kind/],
    [rawResponse(2, { keyId: zero32 }), /Invalid covenant response key/],
    [rawResponse(0), /Malformed covenant key response/],
    [rawResponse(3, { sessionId: zero16, bindingToken: zero32, noncePoint: zero33, signature: zero64 }), /Malformed covenant binding response/],
    [rawResponse(1, { sessionId: zero16, signature: zero64 }), /Malformed covenant nonce transcript/],
    [rawResponse(1), /Nonce response must not contain a final signature/],
    [rawResponse(2, { signature: zero64 }), /Final covenant response is missing its signature/],
]) assert.throws(() => parseCovenantResponse(buffer), error);

// Branch ratchet: byte-context encoding, independent magic/version rejection,
// direct-key binding off/on, and all-zero RNG fallback stay deterministic.
const bytesContext = new Uint8Array([0x41, 0x42]);
const knownBytesContext = bytes(covenantKnownRequestHex({
    sessionIdHex: challenge.sessionId,
    hostCommitmentHex: challenge.hostCommitment,
    keyIdHex: keyId,
    bindingTokenHex: bindingToken,
    commitmentHex: sha256(bytesContext),
    scriptHex: canonicalScript,
    context: bytesContext,
    scheme: CovenantKnownScheme.SHA256_PREIMAGE,
}));
assert.equal(knownBytesContext.readUInt16BE(154), 2);
const ordinaryBind = bytes(covenantBindRequestHex({ keyIdHex:keyId, scriptHex:opaqueScript }));
assert.equal(ordinaryBind[7], 0);
const badMagic = Buffer.from(keyResponse); badMagic[0] = 0;
assert.throws(() => parseCovenantResponse(badMagic), /current KasSigner covenant response/);
const badVersion = Buffer.from(keyResponse); badVersion[4] = 9;
assert.throws(() => parseCovenantResponse(badVersion), /current KasSigner covenant response/);
const savedCrypto = globalThis.crypto; const cryptoDescriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');
Object.defineProperty(globalThis,'crypto',{configurable:true,value:{ getRandomValues(array) { array.fill(0); return array; }, subtle: savedCrypto.subtle }});
const zeroFallbackChallenge = await createCovenantSigningChallenge();
assert.notEqual(zeroFallbackChallenge.sessionId, '00'.repeat(16));
assert.notEqual(zeroFallbackChallenge.hostSecret, '00'.repeat(32));
Object.defineProperty(globalThis,'crypto',cryptoDescriptor ?? {configurable:true,value:savedCrypto});
