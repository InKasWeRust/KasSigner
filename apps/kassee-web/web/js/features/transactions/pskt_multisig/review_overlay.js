import { setSafeMarkup } from '../../../core/security/safe_html.js';
export function showOracleProvingScreen(priceRaw) {
  hideOracleProvingScreen();
  const price = Number(priceRaw) / 1e8;
  const priceText = Number.isFinite(price) && price > 0
    ? ('$' + price.toFixed(8).replace(/0+$/, '').replace(/\.$/, ''))
    : '';
  const overlay = document.createElement('div');
  overlay.id = 'mb-prove';
  overlay.classList.add('price-proof-overlay');
  setSafeMarkup(overlay, `
    <div class="price-proof-panel">
      <div class="price-proof-animation">
        <div class="price-proof-ring"></div>
        <div class="price-proof-ring-delayed"></div>
        <div class="price-proof-spinner"></div>
        <div class="price-proof-bolt">⚡</div>
      </div>
      <div class="price-proof-title">Proving your price</div>
      ${priceText ? `<div class="price-proof-value">${priceText}</div>` : ''}
      <div class="price-proof-description">Generating a zero-knowledge proof on a GPU, then broadcasting through your node. This usually takes a minute or two. Keep this tab open.</div>
      <div class="" id="mb-prove-timer">0:00 elapsed</div>
      <div class="price-proof-metrics">
        <div class="mbpv-step active u-display-flex-direction-column-align-center-gap-7px" data-step="1"><div class="mbpv-num u-width-30px-height-30px-rounded-50pct-border-2px-solid-2a4a40">1</div>Prove</div>
        <div class="mbpv-step u-display-flex-direction-column-align-center-gap-7px" data-step="2"><div class="mbpv-num u-width-30px-height-30px-rounded-50pct-border-2px-solid-2a4a40">2</div>Broadcast</div>
      </div>
    </div>`);
  document.body.appendChild(overlay);
  const startedAt = Date.now();
  overlay._timer = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startedAt) / 1000);
    const timer = document.getElementById('mb-prove-timer');
    if (timer) timer.textContent = Math.floor(elapsed / 60) + ':' + String(elapsed % 60).padStart(2, '0') + ' elapsed';
  }, 1000);
}

export function setOracleProvingStage(stage) {
  const overlay = document.getElementById('mb-prove');
  if (!overlay || stage !== 'broadcast') return;
  const prove = overlay.querySelector('.mbpv-step[data-step="1"]');
  const broadcast = overlay.querySelector('.mbpv-step[data-step="2"]');
  if (prove) {
    prove.classList.remove('active');
    prove.classList.add('done');
    const number = prove.querySelector('.mbpv-num');
    if (number) number.textContent = '✓';
  }
  if (broadcast) broadcast.classList.add('active');
}

export function hideOracleProvingScreen() {
  const overlay = document.getElementById('mb-prove');
  if (!overlay) return;
  if (overlay._timer) clearInterval(overlay._timer);
  overlay.remove();
}
