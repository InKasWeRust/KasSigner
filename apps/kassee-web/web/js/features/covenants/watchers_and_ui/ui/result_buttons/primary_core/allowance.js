export function configureAllowance({ beneBtn, ownerBtn, consolBtn, fundBtn, isBeneficiary }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    beneBtn.textContent = 'Beneficiary Withdraw';
    ownerBtn.textContent = 'Owner Reclaim';
    if (consolBtn) consolBtn.style.display = 'none';
    if (isBeneficiary) {
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
    } else {
        beneBtn.style.display = 'none';
    }
}
