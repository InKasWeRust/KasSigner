import { ensureEscrowParams } from '../../../watchers_and_ui/ui/metadata.js';
import { readU64 } from '../payload_reader.js';
import { baseRecoveredRecord, readStoredScript } from './common.js';
import { readOptionalDate } from '../optional_date.js';

export function rebuildTimelockedSavings(type, params, ownerPk) {
    const { redeemScriptHex, offset } = readStoredScript(params);
    const wallet1PubkeyHex = params.slice(offset, offset + 64);
    const wallet2PubkeyHex = params.slice(offset + 64, offset + 128);
    const locktimeDaa = readU64(params, offset + 128);
    const isRecoveryWallet = Boolean(ownerPk && ownerPk === wallet2PubkeyHex && ownerPk !== wallet1PubkeyHex);
    const record = {
        ...baseRecoveredRecord(type, redeemScriptHex, isRecoveryWallet ? 'beneficiary' : 'owner'),
        wallet1_pubkey_hex: wallet1PubkeyHex,
        wallet2_pubkey_hex: wallet2PubkeyHex,
        locktime_daa: locktimeDaa,
    };
    const dateIso = readOptionalDate(params, offset + 144);
    if (dateIso) record.locktime_date_iso = dateIso;
    return record;
}

export function rebuildEscrow(type, params) {
    const { redeemScriptHex } = readStoredScript(params);
    const record = baseRecoveredRecord(type, redeemScriptHex);
    ensureEscrowParams(record);
    return record;
}
