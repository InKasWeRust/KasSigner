// Explicit stealthState shape. Complex behavior belongs in domain facades; this object holds simple session state.
export const stealthState = Object.seal({
    '_stealthBatchStart': undefined,
    '_stealthCatchupRunning': undefined,
    '_stealthQrTimer': undefined,
    '_stealthResults': undefined,
    '_stealthScanActive': undefined,
    '_stealthScanWs': undefined,
    '_stealthSendEntropy': undefined,
    '_stealthSendMeta': undefined,
    'stealthAnnouncementsR': undefined,
    'stealthIndexerEnabled': undefined,
});
