import { oracleState } from '../../../../../app/state/index.js';
// Oracle roll review countdown.

function updateCountdown() {
  const awaiting = oracleState._oracleMbPreSignAwaiting || oracleState._oracleMbAutoBroadcast;
  const review = document.getElementById('pskt-review');
  const onReview = review && !review.classList.contains('hidden') && review.style.display !== 'none';
  let box = document.getElementById('oracle-mb-countdown');
  if (!awaiting || !onReview) {
    if (box) box.style.display = 'none';
    return;
  }
  if (!box) {
    const button = document.getElementById('btn-pskt-finalize');
    if (!button || !button.parentNode) return;
    box = document.createElement('div');
    box.id = 'oracle-mb-countdown';
    box.classList.add('oracle-proof-countdown');
    button.parentNode.insertBefore(box, button.nextSibling);
  }
  box.style.display = 'block';
  const remainingMs = (oracleState._oracleMbProveDeadline || 0) - Date.now();
  if (!oracleState._oracleMbProveDeadline || remainingMs <= 0) {
    box.textContent = 'Proof finishing — it will broadcast automatically any moment…';
    return;
  }
  const seconds = Math.ceil(remainingMs / 1000);
  box.textContent = (oracleState._oracleMbAutoBroadcast ? 'Signed. ' : '')
    + 'Proof proving — auto-broadcast in ~' + seconds + 's';
}

let countdownTimer = null;

export function startOracleMbCountdown() {
  if (countdownTimer !== null) return;
  updateCountdown();
  countdownTimer = setInterval(() => updateCountdown(), 1000);
}

export function stopOracleMbCountdown() {
  if (countdownTimer !== null) clearInterval(countdownTimer);
  countdownTimer = null;
  const box = document.getElementById('oracle-mb-countdown');
  if (box) box.style.display = 'none';
}
