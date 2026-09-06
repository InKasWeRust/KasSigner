import { covenantState } from '../../../../app/state/index.js';
import { fetchCurrentDaa } from '../../../../core/node/daa.js';
import { parseAllowanceScript, parseEscrowScript, parsePiggyScript } from './script_metadata.js';
// KasSee Web — features/covenants/watchers_and_ui/ui/metadata
import { byId } from '../../../../core/dom.js';
import { exactUnsigned } from '../../../../core/exact.js';
import { sompiToKasString } from '../../../../core/amounts.js';
import { formatDaaDuration, formatStartDate } from '../../../../core/format.js';

// ── Covenant result meta line ───────────────────────────────────────────────
// Single source of truth for the "Type: ... | ..." summary on the covenant
// result panel. All four entry points (creation, active-list reload,
// post-funding return, invite load) call covRenderMetaLine, so a per-type
// display change is made here once.
//
// covMetaLine(c): pure function -> string. Timed fields go through
// formatStartDate (exact date if *_date_iso present, else ~estimate from
// covenantState._lastKnownDaa, else raw 'DAA N').
export function covMetaLine(c) {
    const t = (c && c.type) || '';
    const refund = () => formatStartDate({ locktime_daa: c.locktime_daa, start_date_iso: c.locktime_date_iso }, covenantState._lastKnownDaa);
    if (t === 'dms' && c.inactivity_daa) {
        return `Type: Dead Man's Switch | Inactivity: ${formatDaaDuration(exactUnsigned(c.inactivity_daa, 'inactivity DAA'))}`;
    }
    if (t === 'global-spending-limit' || t === 'global-allowance') {
        let mw = exactUnsigned(c.max_withdraw_sompi ?? 0n, 'withdrawal limit');
        let cd = exactUnsigned(c.cooldown_daa ?? 0n, 'cooldown DAA');
        if ((mw === 0n || cd === 0n) && c.redeem_script_hex) {
            const parsed = parseAllowanceScript(c.redeem_script_hex);
            if (mw === 0n) mw = parsed.max_withdraw_sompi;
            if (cd === 0n) cd = parsed.cooldown_daa;
        }
        if (mw > 0n) {
            const cdStr = cd > 0n ? ` | Cooldown: ${formatDaaDuration(cd)}` : '';
            const label = t === 'global-spending-limit' ? 'Global Spending Limit | Limit' : 'Global Allowance | Max';
            const startStr = t === 'global-allowance' && c.start_date_iso
                ? ` | Start: ${formatStartDate(c, covenantState._lastKnownDaa)}`
                : '';
            return `Type: ${label}: ${sompiToKasString(mw)} KAS/spend${cdStr}${startStr}`;
        }
    }
    if (t === 'additive') {
        const threshold = exactUnsigned(c.threshold_sompi ?? 0n, 'savings threshold');
        const deadline = exactUnsigned(c.deadline_daa ?? 0n, 'deadline DAA');
        let line = 'Type: Piggy Bank';
        if (threshold > 0n) line += ` | Goal: ${sompiToKasString(threshold)} KAS`;
        if (deadline > 0n && c.deadline_date_iso) {
            line += ' | Deadline: ' + formatStartDate({ start_date_iso: c.deadline_date_iso, start_daa: deadline }, covenantState._lastKnownDaa);
        }
        if (threshold === 0n && deadline === 0n) line += ' | No conditions (break anytime)';
        return line;
    }
    if (t === 'merkle-whitelist') {
        let n = 0;
        try { n = JSON.parse(c.merkle_addresses_json || '[]').length; } catch (_) {}
        return 'Type: Merkle Whitelist | ' + n + ' addresses | Refund: ' + refund();
    }
    if (t === 'payjoin') return 'Type: PayJoin | Refund timeout: ' + refund();
    if (t === 'commit-reveal') return 'Type: Commit-Reveal | Refund timeout: ' + refund();
    if (t === 'oracle-v1') return 'Type: Oracle | Attestation-bound release | Owner refund: ' + refund();
    if (t === 'crowdfund') return `Type: ZK Crowdfunding | Goal: ${sompiToKasString(c.goal_sompi ?? 0n)} KAS | ${c.crowdfund_role === 'organizer' ? 'Organizer' : 'Contributor'} | Refund: ${refund()}`;
    if (t === 'private-swap') return 'Type: Private Swap (adaptor signature)';
    return 'Type: ' + t + (c.locktime_daa ? ' | Locktime: ' + refund() : '');
}
// field could only resolve to a raw DAA (no *_date_iso and no cached DAA),
// fetch the current DAA once and re-render so it shows an estimated date.
export function covRenderMetaLine(c) {
    const node = byId('cov-result-extra');
    if (!node || !c) return;
    node.textContent = covMetaLine(c);
    const timed = c.locktime_daa || c.deadline_daa || c.start_daa;
    const hasIso = c.locktime_date_iso || c.deadline_date_iso || c.start_date_iso;
    if (timed && !hasIso && exactUnsigned(covenantState._lastKnownDaa ?? 0n, 'last known DAA') === 0n) {
        fetchCurrentDaa().then(daa => {
            if (daa > 0n) { covenantState._lastKnownDaa = daa; node.textContent = covMetaLine(c); }
        }).catch(() => {});
    }
}
// Scans for the int push before OP_SUB (0x94) and OP_CSV (0xb1).



// Ensure an allowance covenant entry has max_withdraw_sompi and cooldown_daa.
// Parses from redeem script if missing.
export function ensureAllowanceParams(c) {
    if (c.type !== 'global-spending-limit' && c.type !== 'global-allowance') return;
    if (c.max_withdraw_sompi && c.cooldown_daa) return;
    if (!c.redeem_script_hex) return;
    const parsed = parseAllowanceScript(c.redeem_script_hex);
    if (!c.max_withdraw_sompi && parsed.max_withdraw_sompi) c.max_withdraw_sompi = parsed.max_withdraw_sompi;
    if (!c.cooldown_daa && parsed.cooldown_daa) c.cooldown_daa = parsed.cooldown_daa;
    if (!c.start_daa && parsed.start_daa) c.start_daa = parsed.start_daa;
}
// Extracts: alice_pk, bob_pk, arbiter_pk, alice_spk_hex, bob_spk_hex.
// Script layout (hex): 63 20 <alice_pk:64> ad 00 c3 24 0000 20 <bob_dest_pk:64> ac 88 51
//                      67 63 20 <bob_pk:64> ad 00 c3 24 0000 20 <alice_dest_pk:64> ac 88 51
//                      67 20 <arbiter_pk:64> ad 63 ...
// 3 ENDIFs (68 68 68) at end.



// Parse the role pubkeys from a supply-chain (state machine) redeem script.
// The script embeds one "OP_DATA_32 <32-byte pubkey> OP_CHECKSIGVERIFY (0xad)"
// per state, in order: [manufacturer, shipper, receiver]. The walk is
// opcode-aware so data bytes (salt, amount pushes) are never misread as
// OP_DATA_32 — the same hazard the firmware scanner had with 0x20 salt bytes.

// Populate supply-chain role pubkeys from the redeem script if missing.

export function ensureEscrowParams(c) {
    if (c.type !== 'escrow') return;
    if (c.alice_pk && c.bob_pk && c.arbiter_pk) return;
    if (!c.redeem_script_hex) return;
    const parsed = parseEscrowScript(c.redeem_script_hex);
    if (!c.alice_pk && parsed.alice_pk) c.alice_pk = parsed.alice_pk;
    if (!c.bob_pk && parsed.bob_pk) c.bob_pk = parsed.bob_pk;
    if (!c.arbiter_pk && parsed.arbiter_pk) c.arbiter_pk = parsed.arbiter_pk;
    if (!c.alice_spk_hex && parsed.alice_spk_hex) c.alice_spk_hex = parsed.alice_spk_hex;
    if (!c.bob_spk_hex && parsed.bob_spk_hex) c.bob_spk_hex = parsed.bob_spk_hex;
}
// threshold: push before first OP_GREATERTHANOREQUAL (0xa5)
// deadline: push before OP_CLTV (0xb0)



// Ensure a piggy bank covenant entry has threshold_sompi and deadline_daa.
export function ensurePiggyParams(c) {
    if (c.type !== 'additive') return;
    if (c.threshold_sompi && c.deadline_daa) return;
    if (!c.redeem_script_hex) return;
    const parsed = parsePiggyScript(c.redeem_script_hex);
    if (!c.threshold_sompi && parsed.threshold_sompi) c.threshold_sompi = parsed.threshold_sompi;
    if (!c.deadline_daa && parsed.deadline_daa) c.deadline_daa = parsed.deadline_daa;
}
