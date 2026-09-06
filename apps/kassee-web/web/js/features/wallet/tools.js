// Wallet inspection and consolidation façade. Focused modules own their state access.
export { showAddresses, showUtxos } from './tools/address_views.js';
export { handleConsolidate, handleConsolidateSelected, handleSendSelectedUtxos, trackUtxoChangesAndUsed } from './tools/consolidation.js';
export { showHistory, clearHistory } from './tools/history.js';
