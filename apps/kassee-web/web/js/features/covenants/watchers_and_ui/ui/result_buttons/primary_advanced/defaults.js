export function configureDefaultActions({ type, beneBtn, ownerBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    if (type === 'global-spending-limit') {
        ownerBtn.textContent = 'Owner Spend';
        beneBtn.style.display = 'none';
        return;
    }
    beneBtn.textContent = 'Beneficiary Spend';
    ownerBtn.textContent = 'Owner Spend';
}
