export const oracleMbIdentity = {
    heartbeatAddress: null,
    heartbeatCovIdH: null,
    oracleAddress: null,
    oracleCovIdG: null,
};

export function applyDeployedOracleIdentity(deploy) {
    oracleMbIdentity.heartbeatAddress ||= deploy.heartbeatAddress;
    oracleMbIdentity.heartbeatCovIdH ||= deploy.heartbeatCovIdH;
    oracleMbIdentity.oracleCovIdG ||= deploy.oracleCovIdG;
}
