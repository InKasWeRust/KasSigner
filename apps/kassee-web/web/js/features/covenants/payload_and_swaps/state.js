import { covenantState, networkState, walletSession } from '../../../app/state/index.js';
import { ceilFeeFromRate } from '../../../core/fee_math.js';
// KasSee Web — features/covenants/payload_and_swaps/state


// Fee and owner-address accessors are pure with respect to module loading.

export function getCovFee(numInputs = 1) {
    // Owner sweeps spend P2SH covenant inputs that each carry a redeem script
    // (sig + redeem + pushes), so they are heavier than plain P2PK inputs and the
    // node's compute mass scales with input count. The old 1400 gram/input estimate
    // plus a 400000 floor under-paid 3+ input sweeps (a 3-input tx needs ~450000),
    // which the node rejects as "fees under the required amount for compute mass".
    // Model per-input bytes + sig-op mass at 100 sompi/gram with a 1.15 margin, the
    // same basis as covDepositFee.
    const n = BigInt(numInputs > 0 ? numInputs : 1);
    const perInputMass = 300n + 1000n;                 // ~300B covenant input + sig_op_count*1000
    const mass = 46n + n * perInputMass + 43n + 340n;  // base + inputs + one swept output (+spk)
    const minFee = ceilFeeFromRate(100, mass, 400000n, 115n, 100n);
    if (!networkState.lastFeeEstimate) return minFee;
    let feerate;
    if (covenantState.covFeeLevel === 'low') {
        feerate = networkState.lastFeeEstimate.low_sompi_per_gram || 1;
    } else if (covenantState.covFeeLevel === 'priority') {
        feerate = networkState.lastFeeEstimate.priority_sompi_per_gram || 1;
    } else {
        feerate = networkState.lastFeeEstimate.normal_sompi_per_gram || 1;
    }
    return ceilFeeFromRate(feerate, mass, minFee, 115n, 100n);
}
export function ownerReceiveAddr() {
    try {
        const w = walletSession.current();
        return (w && w.receive_addresses && w.receive_addresses[0]) || '';
    } catch (_) { return ''; }
}
