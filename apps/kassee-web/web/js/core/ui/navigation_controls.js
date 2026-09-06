// Shared Back/Home control layout. Existing Back handlers retain their cleanup
// semantics; Home invokes Back first, then navigates to the wallet-aware home.
export function installBackHomeControls(onHome) {
    if (typeof onHome !== 'function') return;
    document.querySelectorAll('.btn-back').forEach(backButton => {
        if (backButton.closest('.back-home-row')) return;
        const parent = backButton.parentNode;
        if (!parent) return;
        const row = document.createElement('div');
        row.className = 'back-home-row';
        if (backButton.id.endsWith('-back-top')) row.classList.add('back-home-row-top');
        parent.insertBefore(row, backButton);
        row.appendChild(backButton);
        const homeButton = document.createElement('button');
        homeButton.type = 'button';
        homeButton.className = 'btn btn-home-nav';
        homeButton.textContent = 'Home';
        homeButton.setAttribute('aria-label', 'Home');
        homeButton.addEventListener('click', () => {
            backButton.click();
            queueMicrotask(onHome);
        });
        row.appendChild(homeButton);
    });
}
