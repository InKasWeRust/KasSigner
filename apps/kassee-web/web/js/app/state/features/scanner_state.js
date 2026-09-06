// Explicit scannerState shape. Complex behavior belongs in domain facades; this object holds simple session state.
export const scannerState = Object.seal({
    '_covbFrames': null,
    '_covbImporting': false,
    'qrCycleTimer': null,
    'qrFrameIdx': 0,
    'qrFrames': null,
    'refreshing': false,
    'scanAnimFrame': null,
    'scanCallback': null,
    'scanStream': null,
    '_stlrFrames': null,
    '_scannerReturnPanel': undefined,
    '_scannerReturnScreen': undefined,
});
