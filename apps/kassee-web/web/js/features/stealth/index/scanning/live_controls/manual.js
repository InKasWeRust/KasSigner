import { setSafeMarkup } from '../../../../../core/security/safe_html.js';
import { stealthState } from '../../../../../app/state/index.js';
import { byId } from '../../../../../core/dom.js';
import { toast } from '../../../../../core/ui/toast.js';

export function ensureStealthManualRSection() {
    if (byId('stealth-manual-r-input')) return;
    const section = document.createElement('div');
    section.id = 'stealth-manual-r-section';
    section.classList.add('u-mt-8px');
    setSafeMarkup(section, `
        <label class="input-label">Manual R entry (64 hex — out-of-band fallback)</label>
        <input type="text" id="stealth-manual-r-input" class="input-text"
               placeholder="64-char hex (sender's ephemeral R)" autocomplete="off" spellcheck="false">
        <button class="btn btn-outline u-full-width-mt-4px" id="btn-stealth-add-r">Add R Value</button>
        <div class="u-text-11px-mt-4px-text-text-dim" id="stealth-r-list"></div>
    `);
    byId('stealth-scan-panel').insertBefore(section, byId('btn-stealth-scan-back'));
    byId('btn-stealth-add-r').onclick = () => {
        if (stealthState._stealthCatchupRunning) {
            toast('Lane scan still running, please wait', 'error');
            return;
        }
        const value = byId('stealth-manual-r-input').value.trim();
        if (value.length !== 64 || !/^[0-9a-fA-F]+$/.test(value)) {
            toast('R must be 64 hex chars', 'error');
            return;
        }
        if (!stealthState.stealthAnnouncementsR.includes(value)) {
            stealthState.stealthAnnouncementsR.push(value);
        }
        byId('stealth-manual-r-input').value = '';
        byId('stealth-r-list').textContent = `${stealthState.stealthAnnouncementsR.length} R value(s) loaded`;
        byId('btn-stealth-show-scan-qr').classList.remove('hidden');
    };
}
