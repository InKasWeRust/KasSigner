import { kassigner_sdk_limits } from '../../../wasm/api.js';

const REFERENCE_SIGNER_MAX_INPUTS = 32;

// Read the active KasSigner capability contract rather than duplicating the
// hardware ceiling in coin-control callers. The fallback is the pinned v2
// reference-signer limit and is used only while the WASM facade is unavailable.
export function signerMaxInputs() {
    try {
        const limits = JSON.parse(kassigner_sdk_limits());
        const value = Number(limits.maxInputs);
        if (Number.isSafeInteger(value) && value >= 1) return value;
    } catch (_) {
        // Keep local coin control usable while the WASM package is initializing.
    }
    return REFERENCE_SIGNER_MAX_INPUTS;
}
