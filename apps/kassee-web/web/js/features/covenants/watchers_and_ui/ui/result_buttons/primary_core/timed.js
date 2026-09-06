export function configureDeadManSwitch({ beneBtn, ownerBtn, fundBtn, isBeneficiary }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    ownerBtn.textContent = '❤️ Heartbeat (Reset Timer)';
    if (isBeneficiary) {
        beneBtn.textContent = 'Heir Claim';
        beneBtn.style.display = '';
        ownerBtn.style.display = 'none';
        if (fundBtn) fundBtn.style.display = 'none';
    } else {
        beneBtn.textContent = 'Withdraw';
        beneBtn.style.display = '';
    }
}

export function configureTimelockedSavings({ beneBtn, ownerBtn, consolBtn, fundBtn }) {
    if (fundBtn) fundBtn.textContent = 'Covenant Deposit';
    beneBtn.textContent = 'Claim Funds';
    beneBtn.style.display = '';
    ownerBtn.style.display = 'none';
    if (consolBtn) consolBtn.style.display = 'none';
}
