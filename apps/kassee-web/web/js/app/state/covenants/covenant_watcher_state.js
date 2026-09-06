// Focused covenantWatcher session state.
export const covenantWatcherState = Object.seal({
    '_covActiveWatcherTimer': null,
    '_covWatcherLastBalance': null,
    '_covWatcherOutpoint': null,
    '_covWatcherSpendPath': undefined,
    '_covWatcherTimer': null,
});
