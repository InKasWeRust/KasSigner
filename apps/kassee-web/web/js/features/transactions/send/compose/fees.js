// Pure fee estimators shared by send and consolidation workflows.

/// Estimate the fee for consolidating P2PK inputs into one P2PK output.
export function consolidationFee(inputCount) {
    const count = BigInt(Math.max(1, inputCount | 0));
    const grams = 430n + 1115n * count;
    const estimated = grams * 115n;
    return estimated > 100000n ? estimated : 100000n;
}
