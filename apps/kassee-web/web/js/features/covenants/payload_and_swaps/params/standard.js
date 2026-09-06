import { pubkeyHex as pk, u64LeHex as u64, variableHex as vhex, variableString as vstr } from './primitives.js';

export const standardSerializers = Object.freeze({
    'timelocked-savings': (result) => vhex(result.redeem_script_hex)
        + pk(result.wallet1_pubkey_hex) + pk(result.wallet2_pubkey_hex)
        + u64(result.locktime_daa) + vstr(result.locktime_date_iso),
    dms: (result) => pk(result.heir_pubkey_hex || result.beneficiary_pubkey_hex)
        + u64(result.inactivity_daa),
    'global-spending-limit': (result) => vhex(result.redeem_script_hex)
        + u64(result.max_withdraw_sompi) + u64(result.cooldown_daa) + pk(result.covenant_id_hex),
    'global-allowance': (result) => vhex(result.redeem_script_hex)
        + u64(result.max_withdraw_sompi) + u64(result.cooldown_daa) + u64(result.start_daa)
        + pk(result.beneficiary_pubkey_hex) + pk(result.covenant_id_hex),
    escrow: (result) => vhex(result.redeem_script_hex),
    'timelocked-escrow': (result) => pk(result.beneficiary_pubkey_hex) + u64(result.locktime_daa),
});
