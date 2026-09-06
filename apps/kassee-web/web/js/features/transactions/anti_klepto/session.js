import {
  anti_klepto_accept_commitment,
  anti_klepto_begin,
  anti_klepto_verify_signed,
} from '../../../wasm/api.js';

let session = null;

export function beginAntiKlepto(ksptHex) {
  const started = JSON.parse(anti_klepto_begin(ksptHex));
  if (!started.requestHex || !started.hostSecretHex) {
    throw new Error('Anti-klepto session initialization failed');
  }
  session = {
    requestHex: started.requestHex,
    hostSecretHex: started.hostSecretHex,
    commitmentHex: null,
  };
  return started.requestHex;
}

export function antiKleptoActive() {
  return session !== null;
}

export function antiKleptoPhase() {
  if (!session) return 'inactive';
  return session.commitmentHex ? 'awaiting-final' : 'awaiting-commitment';
}

export function antiKleptoMessageKind(hex) {
  if (typeof hex !== 'string' || hex.length < 12 || hex.slice(0, 8).toLowerCase() !== '4b414b50') {
    return null;
  }
  const version = Number.parseInt(hex.slice(8, 10), 16);
  if (version !== 2) return null;
  const kind = Number.parseInt(hex.slice(10, 12), 16);
  return Number.isInteger(kind) ? kind : null;
}

export function acceptedAntiKleptoCommitmentMatches(commitmentHex) {
  if (!session?.commitmentHex || typeof commitmentHex !== 'string') return false;
  return session.commitmentHex.toLowerCase() === commitmentHex.toLowerCase();
}

export function acceptAntiKleptoCommitment(commitmentHex) {
  if (!session) throw new Error('No anti-klepto signing session is active');
  if (session.commitmentHex) {
    throw new Error('KasSigner commitment already accepted; scan the final KasSigner QR');
  }
  const revealHex = anti_klepto_accept_commitment(
    session.requestHex,
    commitmentHex,
    session.hostSecretHex,
  );
  session.commitmentHex = commitmentHex;
  return revealHex;
}

export function verifyAntiKleptoSigned(signedHex) {
  if (!session || !session.commitmentHex) {
    throw new Error('Anti-klepto nonce commitment has not been verified');
  }
  const finalKsptHex = anti_klepto_verify_signed(
    session.requestHex,
    session.commitmentHex,
    signedHex,
    session.hostSecretHex,
  );
  clearAntiKleptoSession();
  return finalKsptHex;
}

export function clearAntiKleptoSession() {
  if (session) {
    session.requestHex = '';
    session.hostSecretHex = '';
    session.commitmentHex = '';
  }
  session = null;
}
