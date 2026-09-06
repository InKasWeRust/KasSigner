export function configureAdditive({ beneBtn, ownerBtn, consolBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    beneBtn.style.display = 'none';
    ownerBtn.textContent = 'Break Piggy Bank';
    if (consolBtn) consolBtn.style.display = 'none';
}
