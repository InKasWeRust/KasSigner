
// ── touch device detection ─────────────────────────────
document.addEventListener('touchstart', function onFirstTouch() {
  document.body.classList.add('touch-device');
  document.removeEventListener('touchstart', onFirstTouch);
}, { passive: true });
// also detect on load for iPad
if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
  document.body.classList.add('touch-device');
}

// ── cursor ──────────────────────────────────────────────
const cur = document.getElementById('cur');
const isTouch = document.body.classList.contains('touch-device');
cur.style.opacity = '0';
if (isTouch) cur.style.display = 'none';
let MX = -200, MY = -200;
document.addEventListener('mousemove', e => {
  if (document.body.classList.contains('touch-device')) return;
  MX = e.clientX; MY = e.clientY;
  cur.style.left = MX + 'px';
  cur.style.top  = MY + 'px';
  if (cur.style.opacity === '0') {
    cur.style.opacity = '1';
    document.body.classList.add('moved');
  }
}, { once: false });
document.addEventListener('mousedown', () => cur.classList.add('dn'));
document.addEventListener('mouseup',   () => cur.classList.remove('dn'));

// ── screen manager ───────────────────────────────────────
