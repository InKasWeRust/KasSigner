import { fetchActiveBalances, startActiveWatcher, stopActiveWatcher } from './active/balance_watcher.js';
import { openActiveCovenant } from './active/opening.js';
import {
    activeCovenants,
    addActiveRecord,
    loadActiveRecords,
    removeActiveRecord,
    saveActiveRecords,
} from './active/repository.js';
import { renderActiveList } from './active/rendering.js';

export function covLoadActive() {
    loadActiveRecords();
    covRenderActive();
}

export function covSaveActive() {
    saveActiveRecords();
}

export function covAddActive(type, result) {
    addActiveRecord(type, result);
    saveActiveRecords();
    covRenderActive();
}

export function covRenderActive() {
    renderActiveList({
        onOpen: openActiveCovenant,
        onRemove: removeActiveCovenant,
        refreshBalances: fetchActiveBalances,
    });
}

function removeActiveCovenant(event, button) {
    event.stopPropagation();
    const index = Number(button.dataset.covDelIdx);
    const covenant = activeCovenants()[index];
    if (!covenant) return;
    if (!confirm(`Remove ${covenant.label} covenant?\n${covenant.address.substring(0, 24)}...`)) return;
    removeActiveRecord(index);
    saveActiveRecords();
    covRenderActive();
}

export const covFetchBalances = fetchActiveBalances;
export const covActiveWatcherStart = startActiveWatcher;
export const covActiveWatcherStop = stopActiveWatcher;
