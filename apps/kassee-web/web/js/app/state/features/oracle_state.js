// Explicit oracleState shape. Complex behavior belongs in domain facades; this object holds simple session state.
export const oracleState = Object.seal({
    '_oracleMbAgeTimer': undefined,
    '_oracleMbAskBusy': undefined,
    '_oracleMbAutoBroadcast': undefined,
    '_oracleMbFeeTotalKas': undefined,
    '_oracleMbPollTimer': undefined,
    '_oracleMbPreSignAwaiting': undefined,
    '_oracleMbPriceTs': undefined,
    '_oracleMbRoll': undefined,
    '_oracleMbRollActive': undefined,
    '_oracleMbState': undefined,
    '_oracleMbProveDeadline': undefined,
    '_oracleMbReturn': undefined,
});
