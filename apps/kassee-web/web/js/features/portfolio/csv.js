import { newId } from './repository.js';
import { parseKas, usdToMicro, microToUsd, formatKas } from './exact_money.js';

const TYPES = new Set(['Buy', 'Sell', 'Transfer In', 'Transfer Out']);
const HEADER = ['type', 'kas_amount', 'kas_price_usd', 'fee_usd', 'timestamp', 'notes', 'source_tx_id'];

function parseRecords(text) {
    const records = [];
    let row = [];
    let cell = '';
    let quoted = false;
    const source = String(text ?? '');
    for (let index = 0; index < source.length; index += 1) {
        const char = source[index];
        if (char === '"' && quoted && source[index + 1] === '"') { cell += '"'; index += 1; continue; }
        if (char === '"') { quoted = !quoted; continue; }
        if (char === ',' && !quoted) { row.push(cell); cell = ''; continue; }
        if ((char === '\n' || char === '\r') && !quoted) {
            if (char === '\r' && source[index + 1] === '\n') index += 1;
            row.push(cell);
            if (row.some(value => value.trim())) records.push(row);
            row = [];
            cell = '';
            continue;
        }
        cell += char;
    }
    if (quoted) throw new Error('CSV contains an unterminated quoted field');
    row.push(cell);
    if (row.some(value => value.trim())) records.push(row);
    return records;
}

function csvEscape(value) {
    const text = String(value ?? '');
    return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function parseType(value) {
    const type = String(value ?? '').trim();
    if (!TYPES.has(type)) throw new Error(`Unsupported transaction type: ${type}`);
    return type;
}

function parseTimestamp(value) {
    const timestampMs = Date.parse(String(value ?? '').trim());
    if (!Number.isFinite(timestampMs)) throw new Error(`Invalid transaction timestamp: ${value}`);
    return timestampMs;
}

export function parsePortfolioCsv(text, portfolioId) {
    const records = parseRecords(text);
    if (!records.length) return [];
    const header = records[0].map(value => value.trim().toLowerCase());
    if (HEADER.some((field, index) => header[index] !== field)) throw new Error(`CSV header must be: ${HEADER.join(',')}`);
    return records.slice(1).map((cells, index) => {
        if (cells.length !== HEADER.length) throw new Error(`CSV row ${index + 2} has ${cells.length} fields; expected ${HEADER.length}`);
        return {
            id: newId(), portfolioId, type: parseType(cells[0]),
            kasSompi: parseKas(cells[1]).toString(),
            priceMicroUsd: usdToMicro(cells[2] || '0', 'CSV KAS price').toString(),
            feeMicroUsd: usdToMicro(cells[3] || '0', 'CSV fee').toString(),
            timestampMs: parseTimestamp(cells[4]), notes: cells[5].slice(0, 500),
            sourceTxId: cells[6].trim() || null, createdAt: Date.now() + index,
        };
    });
}

export function exportPortfolioCsv(entries) {
    const rows = [HEADER.join(',')];
    for (const entry of entries) {
        rows.push([
            entry.type,
            formatKas(entry.kasSompi),
            microToUsd(entry.priceMicroUsd, 6),
            microToUsd(entry.feeMicroUsd || '0', 6),
            new Date(entry.timestampMs).toISOString(),
            entry.notes || '',
            entry.sourceTxId || '',
        ].map(csvEscape).join(','));
    }
    return `${rows.join('\n')}\n`;
}
