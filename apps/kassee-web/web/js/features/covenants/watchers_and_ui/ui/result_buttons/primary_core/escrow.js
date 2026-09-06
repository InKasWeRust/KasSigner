export function configureEscrow({ beneBtn, ownerBtn, consolBtn, fundBtn, isLoaded, covRole, isBeneficiary }) {
    const isArbiter = isLoaded && covRole === 'arbiter';
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    if (consolBtn) consolBtn.style.display = 'none';

    if (isBeneficiary) {
        beneBtn.textContent = 'Refund to Buyer';
        beneBtn.style.display = '';
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
        if (consolBtn) {
            consolBtn.textContent = '⚖️ Request Arbitration';
            consolBtn.style.display = '';
            consolBtn.style.fontSize = '';
        }
        return;
    }
    if (isArbiter) {
        ownerBtn.textContent = 'Award to Seller';
        ownerBtn.style.display = '';
        beneBtn.textContent = 'Refund to Buyer';
        beneBtn.style.display = '';
        if (fundBtn) fundBtn.style.display = 'none';
        return;
    }
    ownerBtn.textContent = 'Release to Seller';
    beneBtn.style.display = 'none';
    if (consolBtn) {
        consolBtn.textContent = '⚖️ Request Arbitration';
        consolBtn.style.display = '';
        consolBtn.style.fontSize = '';
    }
}
