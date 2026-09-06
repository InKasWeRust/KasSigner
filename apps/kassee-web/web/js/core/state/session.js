import { covenantState, networkState, stealthState, uiState, walletState } from '../../app/state/index.js';
// In-memory application session. State is discarded when the tab closes.


walletState.historyEntries = [];
networkState.utxoSnapshot = null;
walletState.fundedReceiveIndices = [];
walletState.fundedChangeIndices = [];
walletState.usedReceiveIndices = new Set();
walletState.usedChangeIndices = new Set();
walletState.standardChangeReservations = new Map();
walletState.addressHistoryEnabled = false;
networkState.customRestUrl = null;
stealthState.stealthIndexerEnabled = localStorage.getItem('kassee-stealth-indexer') === '1';
uiState.autoRefreshTimer = null;
uiState.toastTimer = null;
covenantState._kasFreezePathCPostBroadcast = null;
