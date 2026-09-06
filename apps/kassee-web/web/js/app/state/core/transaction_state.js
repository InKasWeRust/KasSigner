// Transaction composition and review session state.
export const transactionState = Object.seal({
    '_currentKsptHex': undefined,
    '_psktReviewHex': undefined,
    '_lastKasSignerKsptHex': null,
    '_lastBroadcastTime': undefined,
    '_lastPsktSummary': undefined,
    '_psktReviewContext': null,
    '_standardChangeReservationIndex': null,
    'consolidateSelection': undefined,
    'selectedUtxoIds': null,
    'utxoSelectionLimit': 8,
    'utxoSort': 'amount-desc',
    'msSelectedUtxoIds': null,
    'msBranchSelectedUtxos': [],
});
