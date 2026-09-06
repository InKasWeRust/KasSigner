import { networkState, transactionState } from '../../../app/state/index.js';
import { toast } from '../../../core/ui/toast.js';
import { displayKsptQr } from '../send/review.js';
import { kassigner_sdk_prepare, pskt_relay_to_kspt } from '../../../wasm/api.js';
import { byId } from '../../../core/dom.js';
import { beginAntiKlepto, clearAntiKleptoSession } from '../anti_klepto/session.js';

export function createPsktRelayActions() {
  function openRelayModal() {
    if (!transactionState._psktReviewHex) {
      toast('No PSKT loaded', 'error');
      return;
    }
    byId('relay-choice-modal').classList.remove('hidden');
  }

  function closeRelayModal() {
    byId('relay-choice-modal').classList.add('hidden');
  }

  function handlePsktRelay() {
    clearAntiKleptoSession();
    if (!transactionState._psktReviewHex) {
      toast('No PSKT loaded', 'error');
      return;
    }
    displayKsptQr(transactionState._psktReviewHex, 'Relay to next signer');
  }

  function handlePsktRelayKasSignerStandard() {
    clearAntiKleptoSession();
    if (!transactionState._psktReviewHex) {
      toast('No PSKT loaded', 'error');
      return;
    }
    let ksptHex = transactionState._lastKasSignerKsptHex;
    if (ksptHex) {
      console.log('[KasSee] KasSigner standard relay: preserving exact signer-returned KSPT v4 (' + ksptHex.length + ' hex chars)');
    } else {
      try {
        const request = JSON.parse(kassigner_sdk_prepare(
          transactionState._psktReviewHex,
          networkState.network,
        ));
        ksptHex = request.ksptHex;
      } catch (error) {
        console.error('[KasSee] KasSigner standard compact encode failed:', error);
        toast('KasSigner relay failed: ' + error, 'error', 5000);
        return;
      }
      console.log(
        '[KasSee] KasSigner standard relay: PSKB hex ' + transactionState._psktReviewHex.length
        + ' → KSPT v4 hex ' + ksptHex.length,
      );
    }
    displayKsptQr(ksptHex, 'Scan with KasSigner', {
      mode: 'kassigner-standard',
      instruction: 'Scan these compact transaction QR codes with KasSigner. After signing, scan the signed KasSigner QR back into KasSee.',
      primaryScanLabel: 'Scan Signed KasSigner QR',
      scannerTitle: 'Scan signed KasSigner QR',
    });
  }

  function handlePsktRelayCompact() {
    if (!transactionState._psktReviewHex) {
      toast('No PSKT loaded', 'error');
      return;
    }
    let ksptHex = transactionState._lastKasSignerKsptHex;
    if (!ksptHex) {
      try {
        ksptHex = pskt_relay_to_kspt(transactionState._psktReviewHex, networkState.network);
      } catch (error) {
        console.error('[KasSee] compact relay encode failed:', error);
        toast('Compact relay failed: ' + error, 'error', 5000);
        return;
      }
    }
    console.log(
      '[KasSee] Compact relay: PSKB hex ' + transactionState._psktReviewHex.length
      + ' → KSPT v4 hex ' + ksptHex.length
      + ' (' + Math.round((1 - ksptHex.length / transactionState._psktReviewHex.length) * 100) + '% smaller)',
    );
    try {
      const requestHex = beginAntiKlepto(ksptHex);
      displayKsptQr(requestHex, 'Anti-klepto 1/3 — Scan request with KasSigner', {
        mode: 'anti-klepto-request',
        instruction: 'Scan this request with KasSigner and confirm the transaction there. KasSigner will show a commitment QR first; scan that commitment back into KasSee.',
        primaryScanLabel: 'Scan KasSigner Commitment',
        scannerTitle: 'Scan KasSigner commitment',
      });
    } catch (error) {
      console.error('[KasSee] anti-klepto session failed:', error);
      toast('Anti-klepto setup failed: ' + error, 'error', 5000);
    }
  }

  return { openRelayModal, closeRelayModal, handlePsktRelay, handlePsktRelayKasSignerStandard, handlePsktRelayCompact };
}
