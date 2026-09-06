import { chartValues, holdingSummary, portfolioValueMicro } from './calculations.js';
import { formatKas, formatUsd, microToUsd } from './exact_money.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function button(text, action, className = 'btn btn-outline') {
    const node = el('button', className, text);
    node.type = 'button';
    node.dataset.action = action;
    return node;
}

function accountSelector(state) {
    const row = el('div', 'portfolio-toolbar');
    const select = el('select', 'portfolio-select');
    select.dataset.action = 'select-account';
    const all = el('option', '', 'All Portfolios');
    all.value = '';
    select.appendChild(all);
    for (const account of state.store.accounts) {
        const option = el('option', '', account.name);
        option.value = account.id;
        option.selected = account.id === state.selectedAccountId;
        select.appendChild(option);
    }
    row.append(select, button('New', 'new-account', 'btn btn-secondary portfolio-compact-btn'));
    if (state.selectedAccountId) {
        row.append(button('Rename', 'rename-account', 'btn btn-link portfolio-compact-btn'));
        row.append(button('Delete', 'delete-account', 'btn btn-link btn-danger portfolio-compact-btn'));
    }
    return row;
}

function accountEditor(state) {
    const account = state.store.accounts.find(candidate => candidate.id === state.selectedAccountId);
    const form = el('form', 'card portfolio-inline-card');
    form.dataset.action = 'account-form';
    form.appendChild(el('div', 'portfolio-section-title', state.accountEditorMode === 'rename' ? 'Rename Portfolio' : 'New Portfolio'));
    form.appendChild(inputField('Portfolio Name', 'name', state.accountEditorMode === 'rename' ? account?.name || '' : ''));
    const actions = el('div', 'portfolio-actions');
    const save = button('Save', 'submit-account', 'btn btn-primary');
    save.type = 'submit';
    actions.append(save, button('Cancel', 'cancel-inline-action', 'btn btn-link'));
    form.appendChild(actions);
    return form;
}

function deleteConfirmation(state) {
    if (!state.pendingDeleteAccountId && !state.pendingDeleteTransactionId) return null;
    const card = el('div', 'card portfolio-inline-card portfolio-warning-card');
    if (state.pendingDeleteAccountId) {
        const account = state.store.accounts.find(candidate => candidate.id === state.pendingDeleteAccountId);
        card.appendChild(el('div', 'portfolio-section-title', 'Delete Portfolio?'));
        card.appendChild(el('p', 'portfolio-empty', `This permanently removes ${account?.name || 'this portfolio'} and its portfolio transactions.`));
    } else {
        card.appendChild(el('div', 'portfolio-section-title', 'Delete Transaction?'));
        card.appendChild(el('p', 'portfolio-empty', 'This removes the selected portfolio transaction.'));
    }
    const actions = el('div', 'portfolio-actions');
    actions.append(
        button('Delete', state.pendingDeleteAccountId ? 'confirm-account-delete' : 'confirm-transaction-delete', 'btn btn-danger'),
        button('Cancel', 'cancel-inline-action', 'btn btn-link'),
    );
    card.appendChild(actions);
    return card;
}

function valueCard(state, entries) {
    const summary = holdingSummary(entries);
    const card = el('div', 'balance-card portfolio-value-card');
    card.appendChild(el('div', 'balance-label', 'Portfolio Value'));
    const valueRow = el('div', 'portfolio-value-row');
    valueRow.appendChild(el('div', 'balance-amount', state.livePriceMicro === null ? '—' : formatUsd(portfolioValueMicro(entries, state.livePriceMicro))));
    const refresh = button('↻', 'refresh-price', 'btn btn-secondary portfolio-price-refresh');
    refresh.title = 'Refresh KAS price';
    refresh.setAttribute('aria-label', 'Refresh KAS price');
    valueRow.appendChild(refresh);
    card.appendChild(valueRow);
    card.appendChild(el('div', 'balance-sub', `${formatKas(summary.holdings, 4)} KAS`));
    const price = state.livePriceMicro === null ? 'Price unavailable' : `KAS ${formatUsd(state.livePriceMicro, 6)}`;
    card.appendChild(el('div', 'balance-info', price));
    return card;
}

function sectionTabs(state) {
    const row = el('div', 'portfolio-tabs');
    for (const [mode, label] of [['overview', 'Overview'], ['transactions', 'Transactions']]) {
        const tab = button(label, `mode:${mode}`, `portfolio-tab${state.mode === mode ? ' active' : ''}`);
        row.appendChild(tab);
    }
    return row;
}

function summaryGrid(entries) {
    const summary = holdingSummary(entries);
    const grid = el('div', 'portfolio-summary-grid');
    const items = [
        ['Holdings', `${formatKas(summary.holdings, 4)} KAS`],
        ['Remaining basis', formatUsd(summary.remainingCostBasis)],
        ['Lifetime buys', `${formatKas(summary.totalBought, 4)} KAS`],
        ['Transferred in', `${formatKas(summary.totalTransferredIn, 4)} KAS`],
    ];
    for (const [label, value] of items) {
        const cell = el('div', 'portfolio-stat');
        cell.append(el('div', 'portfolio-stat-label', label), el('div', 'portfolio-stat-value', value));
        grid.appendChild(cell);
    }
    return grid;
}

function chartSvg(values) {
    const wrap = el('div', 'portfolio-chart');
    if (values.length < 2) { wrap.appendChild(el('div', 'portfolio-empty', 'Add transactions to build a historical value chart.')); return wrap; }
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 320 150');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Portfolio value history');
    let min = values[0].valueMicroUsd;
    let max = min;
    for (const point of values) { if (point.valueMicroUsd < min) min = point.valueMicroUsd; if (point.valueMicroUsd > max) max = point.valueMicroUsd; }
    const span = max > min ? max - min : 1n;
    const points = values.map((point, index) => {
        const x = values.length === 1 ? 0 : Math.round((index * 310) / (values.length - 1)) + 5;
        const scaled = Number(((point.valueMicroUsd - min) * 1200n) / span) / 10;
        return `${x},${135 - scaled}`;
    }).join(' ');
    const polyline = document.createElementNS(SVG_NS, 'polyline');
    polyline.setAttribute('points', points);
    polyline.setAttribute('class', 'portfolio-chart-line');
    svg.appendChild(polyline);
    wrap.appendChild(svg);
    return wrap;
}

function rangeControls(state) {
    const row = el('div', 'portfolio-range-row');
    for (const days of [7, 30, 90, 365]) {
        const active = state.rangeDays === days;
        const node = button(days === 365 ? '1Y' : `${days}D`, `range:${days}`, `portfolio-range${active ? ' active' : ''}`);
        row.appendChild(node);
    }
    return row;
}

function overview(state, entries) {
    const fragment = document.createDocumentFragment();
    const actions = el('div', 'portfolio-actions');
    actions.append(
        button('Import Wallet History', 'import-wallet-history', 'btn btn-primary'),
        button('Fetch Wallet History', 'fetch-wallet-history', 'btn btn-secondary'),
    );
    fragment.append(summaryGrid(entries), actions, rangeControls(state));
    const card = el('div', 'card portfolio-chart-card');
    card.append(el('div', 'portfolio-section-title', 'Historical Value'), chartSvg(chartValues(entries, state.historicalPrices)));
    fragment.appendChild(card);
    return fragment;
}

function transactionRow(entry) {
    const row = el('div', 'portfolio-transaction');
    const main = el('div', 'portfolio-transaction-main');
    main.append(el('div', 'portfolio-transaction-type', entry.type), el('div', 'portfolio-transaction-meta', new Date(entry.timestampMs).toLocaleString()));
    if (entry.notes) main.appendChild(el('div', 'portfolio-transaction-meta', entry.notes));
    const amount = el('div', 'portfolio-transaction-amount', `${entry.type === 'Buy' || entry.type === 'Transfer In' ? '+' : '-'}${formatKas(entry.kasSompi, 4)} KAS`);
    const actions = el('div', 'portfolio-transaction-actions');
    const edit = button('Edit', `edit:${entry.id}`, 'btn btn-link portfolio-row-action');
    const remove = button('Delete', `delete:${entry.id}`, 'btn btn-link btn-danger portfolio-row-action');
    actions.append(edit, remove);
    row.append(main, amount, actions);
    return row;
}

function transactionList(entries) {
    const list = el('div', 'portfolio-transaction-list');
    const sorted = [...entries].sort((left, right) => right.timestampMs - left.timestampMs);
    if (!sorted.length) list.appendChild(el('div', 'portfolio-empty', 'No portfolio transactions yet.'));
    for (const entry of sorted) list.appendChild(transactionRow(entry));
    return list;
}

function transactionTools(state) {
    const row = el('div', 'portfolio-actions portfolio-actions-wrap');
    const add = button('Add Transaction', 'new-transaction', 'btn btn-primary');
    add.disabled = !state.selectedAccountId;
    const importCsv = button('Import CSV', 'import-csv', 'btn btn-secondary');
    importCsv.disabled = !state.selectedAccountId;
    const exportCsv = button('Export CSV', 'export-csv', 'btn btn-outline');
    exportCsv.disabled = !state.selectedAccountId;
    row.append(add, importCsv, exportCsv);
    return row;
}

function inputField(label, name, value = '', type = 'text') {
    const wrap = el('label', 'portfolio-field');
    wrap.appendChild(el('span', 'input-label', label));
    const input = el('input', 'input');
    input.type = type;
    input.name = name;
    input.value = value;
    wrap.appendChild(input);
    return wrap;
}

export function renderEditor(entry) {
    const card = el('form', 'card portfolio-editor');
    card.dataset.action = 'transaction-form';
    card.dataset.transactionId = entry?.id || '';
    card.appendChild(el('div', 'portfolio-section-title', entry ? 'Edit Transaction' : 'New Transaction'));
    const selectWrap = el('label', 'portfolio-field');
    selectWrap.appendChild(el('span', 'input-label', 'Type'));
    const typeSelect = el('select', 'input'); typeSelect.name = 'type';
    for (const type of ['Buy', 'Sell', 'Transfer In', 'Transfer Out']) {
        const option = el('option', '', type); option.value = type; option.selected = type === (entry?.type || 'Buy'); typeSelect.appendChild(option);
    }
    selectWrap.appendChild(typeSelect);
    const timestamp = entry ? new Date(entry.timestampMs).toISOString().slice(0, 16) : new Date().toISOString().slice(0, 16);
    card.append(selectWrap,
        inputField('KAS Amount', 'kasAmount', entry ? formatKas(entry.kasSompi) : '', 'text'),
        inputField('KAS Price (USD)', 'priceUsd', entry ? microToUsd(entry.priceMicroUsd, 6) : '', 'text'),
        inputField('Fee (USD)', 'feeUsd', entry ? microToUsd(entry.feeMicroUsd || '0', 6) : '0', 'text'),
        inputField('Date / Time', 'timestamp', timestamp, 'datetime-local'),
        inputField('Notes', 'notes', entry?.notes || '', 'text'));
    const actions = el('div', 'portfolio-actions');
    const save = button('Save', 'submit-transaction', 'btn btn-primary'); save.type = 'submit';
    actions.append(save, button('Cancel', 'cancel-editor', 'btn btn-link'));
    card.appendChild(actions);
    return card;
}

export function renderPortfolio(root, state) {
    root.replaceChildren();
    root.append(accountSelector(state));
    if (state.accountEditorMode) root.appendChild(accountEditor(state));
    const confirmation = deleteConfirmation(state);
    if (confirmation) root.appendChild(confirmation);
    const entries = state.visibleEntries();
    if (!state.store.accounts.length) {
        const empty = el('div', 'card portfolio-empty-state');
        empty.append(el('div', 'portfolio-section-title', 'No Portfolio'), el('p', 'portfolio-empty', 'Create a portfolio to track KAS buys, sells, transfers, and imported wallet activity.'), button('New Portfolio', 'new-account', 'btn btn-primary'));
        root.appendChild(empty); return;
    }
    root.append(valueCard(state, entries), sectionTabs(state));
    if (state.editorOpen) root.appendChild(renderEditor(state.editingEntry));
    if (state.mode === 'overview') root.appendChild(overview(state, entries));
    else root.append(transactionTools(state), transactionList(entries));
}
