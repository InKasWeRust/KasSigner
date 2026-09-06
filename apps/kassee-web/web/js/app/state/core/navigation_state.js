// Screen navigation state shared by top-level application routing.
export const navigationState = Object.seal({
    'currentScreenName': undefined,
    'screenHistory': [],
    'settingsReturnScreen': undefined,
    'kpubManagerReturnScreen': undefined,
    'addressesReturnScreen': undefined,
    '_broadcastReturnScreen': null,
});
