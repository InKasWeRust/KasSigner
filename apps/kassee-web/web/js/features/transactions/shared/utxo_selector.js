import { setSafeMarkup } from '../../../core/security/safe_html.js';
import { toast } from '../../../core/ui/toast.js';
import { sompiToKasFixed } from '../../../core/amounts.js';
import { utxoId } from './utxo_selection.js';

const SORT_MODES = new Set(['amount-desc', 'amount-asc', 'daa-desc', 'daa-asc']);

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
}

export function normalizeUtxoSortMode(value) {
    if (value === 'desc') return 'amount-desc';
    if (value === 'asc') return 'amount-asc';
    return SORT_MODES.has(value) ? value : 'amount-desc';
}

function compareExact(left, right, direction) {
    if (left === right) return 0;
    const ascending = left < right ? -1 : 1;
    return direction === 'asc' ? ascending : -ascending;
}

function compareEntries(mode) {
    const normalized = normalizeUtxoSortMode(mode);
    const [field, direction] = normalized.split('-');
    return (left, right) => {
        const leftValue = field === 'daa' ? (left.utxo.block_daa_score ?? 0n) : left.utxo.amount;
        const rightValue = field === 'daa' ? (right.utxo.block_daa_score ?? 0n) : right.utxo.amount;
        const primary = compareExact(leftValue, rightValue, direction);
        return primary || utxoId(left.utxo).localeCompare(utxoId(right.utxo));
    };
}

export function orderedUtxoEntries(utxos, mode) {
    return utxos.map((utxo, index) => ({ utxo, index })).sort(compareEntries(mode));
}

function renderRow(entry, selected) {
    const { utxo, index } = entry;
    const kas = sompiToKasFixed(utxo.amount);
    const daa = utxo.block_daa_score ?? '—';
    const address = utxo.address || utxo.source_address || '';
    const safeId = escapeHtml(utxoId(utxo));
    const safeTxId = escapeHtml(utxo.tx_id);
    const safeDaa = escapeHtml(daa);
    const safeAddress = escapeHtml(address);
    return `<div class="utxo-item" data-idx="${index}" data-id="${safeId}">
        <span class="utxo-check">${selected ? '☑' : '☐'}</span>
        <div class="u-grow">
            <div class="utxo-amount u-text-13px">${kas} KAS</div>
            <div class="utxo-detail">${safeTxId}:${utxo.index}</div>
            <div class="utxo-detail">DAA ${safeDaa}${address ? ` · ${safeAddress}` : ''}</div>
        </div>
    </div>`;
}

export function renderUtxoSelector(list, utxos, selectedIds, options, onChange) {
    const selected = new Set(selectedIds || []);
    const limit = Math.max(1, Number(options?.limit) || 8);
    const mode = normalizeUtxoSortMode(options?.sort);
    const entries = orderedUtxoEntries(utxos, mode);
    const chosen = entries.filter(entry => selected.has(utxoId(entry.utxo)));
    const available = entries.filter(entry => !selected.has(utxoId(entry.utxo)));

    setSafeMarkup(list, [
        '<div class="utxo-detail"><strong>SELECTED UTXOs</strong></div>',
        ...(chosen.length ? chosen.map(entry => renderRow(entry, true)) : ['<div class="utxo-detail">None selected — automatic selection will be used</div>']),
        '<div class="utxo-detail utxo-section-heading"><strong>AVAILABLE UTXOs</strong></div>',
        ...available.map(entry => renderRow(entry, false)),
    ].join(''));

    list.querySelectorAll('.utxo-item').forEach(item => {
        item.onclick = () => {
            const id = item.dataset.id;
            if (selected.has(id)) selected.delete(id);
            else if (selected.size >= limit) {
                toast(`Current manual-selection limit is ${limit} UTXOs`, 'info', 1800);
                return;
            } else selected.add(id);
            const ids = [...selected];
            onChange?.(ids);
            renderUtxoSelector(list, utxos, ids, options, onChange);
        };
    });
    list.style.display = '';
    list.classList.remove('hidden');
}
