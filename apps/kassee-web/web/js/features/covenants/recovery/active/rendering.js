import { byId } from '../../../../core/dom.js';
import { covExportSingle } from '../export.js';
import { activeCovenants } from './repository.js';

export function renderActiveList({ onOpen, onRemove, refreshBalances }) {
    const list = byId('cov-active-list');
    const items = byId('cov-active-items');
    const count = byId('cov-active-count');
    if (!list || !items || !count) return;
    const covenants = activeCovenants();
    if (covenants.length === 0) {
        list.classList.add('hidden');
        return;
    }
    list.classList.remove('hidden');
    count.textContent = covenants.length;
    items.replaceChildren(...covenants.map((covenant, index) => createActiveItem(covenant, index, onOpen)));
    wireActiveActions(items, onRemove);
    refreshBalances();
}

function span(className, text) {
    const element = document.createElement('span');
    element.className = className;
    element.textContent = String(text);
    return element;
}

function createActiveItem(covenant, index, onOpen) {
    const item = document.createElement('div');
    item.className = 'cov-active-item';
    if (covenant._empty) item.style.opacity = '0.45';

    const shortAddress = covenant.address.length > 24
        ? `${covenant.address.substring(0, 16)}...${covenant.address.substring(covenant.address.length - 6)}`
        : covenant.address;
    const subtitle = covenant.type === 'crowdfund' && covenant.campaign_name
        ? `${covenant.campaign_name} (${covenant.crowdfund_role === 'organizer' ? 'organizer' : 'contributor'})`
        : shortAddress;
    const balance = span('cov-bal', covenant._balText || '...');
    balance.dataset.covBalIdx = String(index);
    const exportButton = span('cov-export', '\u21E9');
    exportButton.dataset.covExportIdx = String(index);
    exportButton.title = 'Export backup';
    const deleteButton = span('cov-del', '\u2715');
    deleteButton.dataset.covDelIdx = String(index);
    deleteButton.title = 'Remove';
    item.append(
        span('cov-type-badge', covenant.label),
        span('cov-addr', subtitle),
        balance,
        exportButton,
        deleteButton,
    );
    item.addEventListener('click', (event) => {
        if (event.target.classList.contains('cov-del') || event.target.classList.contains('cov-export')) return;
        onOpen(covenant);
    });
    return item;
}

function wireActiveActions(items, onRemove) {
    items.querySelectorAll('.cov-del').forEach((button) => {
        button.addEventListener('click', (event) => onRemove(event, button));
    });
    items.querySelectorAll('.cov-export').forEach((button) => {
        button.addEventListener('click', (event) => {
            event.stopPropagation();
            covExportSingle(Number(button.dataset.covExportIdx));
        });
    });
}
