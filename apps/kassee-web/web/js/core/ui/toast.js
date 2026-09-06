import { uiState } from '../../app/state/index.js';
import { byId } from '../dom.js';


export function toast(message, type = 'info', duration = 3000) {
    const element = byId('toast');
    element.textContent = message;
    element.className = `toast toast-${type} visible`;
    if (uiState.toastTimer) clearTimeout(uiState.toastTimer);
    uiState.toastTimer = setTimeout(() => {
        element.classList.remove('visible');
        uiState.toastTimer = null;
    }, duration);
}
