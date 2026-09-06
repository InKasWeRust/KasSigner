import { byId } from '../../../../../../core/dom.js';
import { covShowPanel } from '../../../../generation/ui_and_keys.js';

export function configureCommitRevealVerification(type) {
    let button = byId('btn-cov-cr-verify-entry');
    if (!button && type === 'commit-reveal') {
        button = document.createElement('button');
        button.id = 'btn-cov-cr-verify-entry';
        button.className = 'btn btn-outline commit-reveal-result-action';
        button.textContent = 'Verify Revelation';
        const backButton = byId('btn-cov-result-back');
        if (backButton) backButton.parentElement.insertBefore(button, backButton);
    }
    if (!button) return;
    button.style.display = type === 'commit-reveal' ? '' : 'none';
    button.onclick = () => covShowPanel('cr-verify');
}
