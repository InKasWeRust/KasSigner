import { oracleState } from '../../../../app/state/index.js';
import { toast } from '../../../../core/ui/toast.js';
import { u64ToLittleEndianHex } from '../../../../core/bytes.js';
import { ORACLE_MB_PROTOCOL } from '../config.js';
import { oracleMbIdentity } from '../state.js';
import { startOracleMbCountdown } from './proving/countdown.js';
import { createOracleProverClient } from './proving/client.js';
import { setOracleFee } from './proving/fee.js';
import { openOracleSkeleton } from './proving/skeleton.js';
import { createOracleAskUi } from './proving/ui.js';
import { oracleAlreadyMoved, validateOracleQuote } from './proving/validation.js';

const MAX_FRESH_AGE_SECONDS = 60;

async function askForNew({ dependencies, proverGet }) {
    const ui = createOracleAskUi();
    if (!ui.begin()) return;
    oracleState._oracleMbRoll = null;
    try {
        ui.show('Checking on-chain freshness...', 'var(--text-muted)');
        await dependencies.oracleMbCardRefresh();
        const state = oracleState._oracleMbState;
        const age = state ? Math.floor(Date.now() / 1000) - Number(state.t) : Number.MAX_SAFE_INTEGER;
        if (age <= MAX_FRESH_AGE_SECONDS) {
            ui.show(`Price is fresh (${Math.floor(age / 60)}m old). No new roll needed.`);
            return;
        }
        if (!state) {
            ui.show('Could not read the current oracle to spend.', '#ff4d4d');
            return;
        }
        if (await oracleAlreadyMoved(state, oracleMbIdentity.heartbeatAddress)) {
            ui.show('The oracle already moved on-chain. Refreshing without spending a proof.', 'var(--text-muted)');
            try { await dependencies.oracleMbCardRefresh(); } catch (_) {}
            return;
        }

        ui.show('Fetching a price quote...', 'var(--text-muted)');
        let quote;
        try {
            quote = await proverGet('/quote');
        } catch (error) {
            ui.show(`Prover unreachable: ${error?.message || error}`, '#ff4d4d');
            return;
        }
        const validationError = validateOracleQuote(quote, ORACLE_MB_PROTOCOL);
        if (validationError) {
            ui.show(validationError, '#ff4d4d');
            return;
        }
        const body = quote.body;
        oracleState._oracleMbRoll = { acc: body.acc, price: String(body.price), t: Number(body.publish_time) };
        const journal = u64ToLittleEndianHex(body.price)
            + u64ToLittleEndianHex(body.publish_time)
            + ORACLE_MB_PROTOCOL.setRootHex.toLowerCase();
        ui.show('Building the roll...', 'var(--text-muted)');
        const opened = await openOracleSkeleton({
            identity: oracleMbIdentity,
            protocol: ORACLE_MB_PROTOCOL,
            journalHex: journal,
            ambientStop: dependencies.oracleMbAmbientStop,
            show: ui.show,
        });
        if (!opened) {
            oracleState._oracleMbRoll = null;
            return;
        }
        toast('Sign this roll, then tap Finalize + broadcast.', 'info', 9000);
        ui.show('Review and sign the roll, then tap Finalize + broadcast.');
    } catch (error) {
        oracleState._oracleMbRoll = null;
        ui.show(`Ask-for-new failed: ${error?.message || error}`, '#ff4d4d');
    } finally {
        ui.finish();
    }
}

export function createOracleProving(dependencies) {
    startOracleMbCountdown();
    oracleState._oracleMbAskBusy = false;
    const request = {
        dependencies,
        proverGet: createOracleProverClient(ORACLE_MB_PROTOCOL.proverBase),
    };
    return {
        oracleMbSetFee: (totalKas, fromCustom) => setOracleFee(totalKas, fromCustom),
        oracleMbAskForNew: askForNew.bind(null, request),
    };
}
