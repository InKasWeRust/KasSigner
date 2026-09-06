import { walletSession } from '../../../app/state/index.js';
import { decode_address, parse_kpub } from '../../../wasm/api.js';
// KasSee Web — features/covenants/generation/ui_and_keys
import { showCovenantPanel } from './panels/router.js';
import { byId } from '../../../core/dom.js';


export function covShowPanel(panel) {
    showCovenantPanel(panel);
}
export function covTypeChanged() {
    const t = byId('cov-type').value;
    const isEscrow = t === 'escrow';
    const isShipEscrow = t === 'ship-escrow';
    const isSavings = t === 'timelocked-savings';
    const isDms = t === 'dms';
    const isGSplimit = t === 'global-spending-limit';
    const isGAllowance = t === 'global-allowance';
    const isPayjoin = t === 'payjoin';
    const isCommitReveal = t === 'commit-reveal';
    const isMerkleWhitelist = t === 'merkle-whitelist';
    const isPiggy = t === 'additive';
    const isOracleV1 = t === 'oracle-v1';
    const isCrowdfund = t === 'crowdfund';
    const hasSimple = !isPiggy && !isEscrow && !isShipEscrow && !isDms && !isGSplimit && !isGAllowance && !isPayjoin && !isCommitReveal && !isMerkleWhitelist && !isSavings && !isOracleV1 && !isCrowdfund;
    byId('cov-fields-simple').classList.toggle('hidden', !hasSimple);
    byId('cov-fields-piggy').classList.toggle('hidden', !isPiggy);
    byId('cov-fields-escrow').classList.toggle('hidden', !isEscrow);
    if (byId('cov-fields-ship-escrow')) byId('cov-fields-ship-escrow').classList.toggle('hidden', !isShipEscrow);
    if (byId('cov-fields-savings')) byId('cov-fields-savings').classList.toggle('hidden', !isSavings);
    if (byId('cov-fields-dms')) byId('cov-fields-dms').classList.toggle('hidden', !isDms);
    if (byId('cov-fields-splimit')) byId('cov-fields-splimit').classList.toggle('hidden', !isGSplimit);
    byId('cov-fields-allowance').classList.toggle('hidden', !isGAllowance);
    byId('cov-fields-payjoin').classList.toggle('hidden', !isPayjoin);
    byId('cov-fields-commit-reveal').classList.toggle('hidden', !isCommitReveal);
    byId('cov-fields-merkle-whitelist').classList.toggle('hidden', !isMerkleWhitelist);
    byId('cov-fields-oracle-v1')?.classList.toggle('hidden', !isOracleV1);
    byId('cov-fields-crowdfund')?.classList.toggle('hidden', !isCrowdfund);
}
// key plus EVERY receive and change address payload — a counterparty may
// have shared any index from their device, not just /0/0. Matching only
// /0/0 made escrow role detection fail whenever the shared address was at
// a browsed index (arbiter got seller tabs).
export function walletMatchesPk(target) {
    if (!target || !walletSession.hasWallet()) return false;
    const acct = getAccountPubkeyHex();
    if (acct && acct === target) return true;
    try {
        const w = walletSession.current();
        const all = [...(w.receive_addresses || []), ...(w.change_addresses || [])];
        for (const a of all) {
            try {
                const d = JSON.parse(decode_address(a));
                if (d.payload && d.payload === target) return true;
            } catch (_) {}
        }
    } catch (_) {}
    return false;
}
export function getOwnerPubkeyHex() {
    if (!walletSession.hasWallet()) return null;
    const w = walletSession.current();
    const addr0 = w.receive_addresses[0];
    const decoded = JSON.parse(decode_address(addr0));
    return decoded.payload || null;
}
export function getAccountPubkeyHex() {
    if (!walletSession.hasWallet()) return null;
    const w = walletSession.current();
    if (!w.kpub) return null;
    const kpubInfo = JSON.parse(parse_kpub(w.kpub));
    return kpubInfo.account_pubkey || null;
}
