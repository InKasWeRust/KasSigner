import { toast } from '../../../core/ui/toast.js';
import { displayKsptQr } from '../send/review.js';
import {
    acceptAntiKleptoCommitment,
    acceptedAntiKleptoCommitmentMatches,
    antiKleptoActive,
    antiKleptoMessageKind,
    antiKleptoPhase,
    verifyAntiKleptoSigned,
} from './session.js';

export const ANTI_KLEPTO_KEEP_SCANNING = Symbol('anti-klepto-keep-scanning');

/**
 * Gate a signer response through the active anti-klepto transcript.
 *
 * Returns the verified compact KSPT when the response is ready for the normal
 * PSKT/KSPT pipeline, `null` when the signer nonce commitment was accepted and
 * KasSee has displayed the host reveal, `ANTI_KLEPTO_KEEP_SCANNING` when the
 * camera re-sees the exact already-accepted commitment while awaiting the final
 * response, or the original value when no anti-klepto session is active.
 */
export function processAntiKleptoResponse(responseHex) {
    if (!antiKleptoActive()) return responseHex;

    const kind = antiKleptoMessageKind(responseHex);
    const phase = antiKleptoPhase();
    if (kind === 2) {
        if (phase === 'awaiting-final' && acceptedAntiKleptoCommitmentMatches(responseHex)) {
            // Camera workflows can legitimately see the just-accepted commitment
            // again while the device changes screens. It is already transcript-
            // bound, so ignore this exact duplicate and keep collecting the final
            // signed multi-frame response. A different commitment still fails.
            return ANTI_KLEPTO_KEEP_SCANNING;
        }
        if (phase !== 'awaiting-commitment') {
            throw new Error('Different KasSigner commitment received while waiting for final signed QR');
        }
        const revealHex = acceptAntiKleptoCommitment(responseHex);
        displayKsptQr(revealHex, 'Anti-klepto 2/3 — Scan reveal with KasSigner', {
            mode: 'anti-klepto-reveal',
            instruction: 'This QR is the host reveal. On KasSigner, tap its commitment QR; KasSigner will show LOADING while it scans this reveal, then go directly to QR Display Mode for the final signed response. Scan that final response back into KasSee.',
            primaryScanLabel: 'Scan Final KasSigner QR',
            scannerTitle: 'Scan final KasSigner QR',
        });
        toast('Commitment received — this is not the final signature. Scan the displayed reveal with KasSigner, then scan KasSigner\'s final QR.', 'ok', 6000);
        return null;
    }
    if (kind === 4) {
        if (phase !== 'awaiting-final') {
            throw new Error('Unexpected final anti-klepto response before KasSigner commitment');
        }
        const verifiedKsptHex = verifyAntiKleptoSigned(responseHex);
        toast('Anti-klepto 3/3 verified — final signature accepted', 'ok', 3000);
        return verifiedKsptHex;
    }
    if (kind === 3) {
        throw new Error('That is KasSee\'s reveal QR. Scan it with KasSigner, then scan KasSigner\'s final QR here');
    }
    throw new Error(phase === 'awaiting-final'
        ? 'Expected KasSigner final anti-klepto QR'
        : 'Expected KasSigner anti-klepto commitment QR');
}
