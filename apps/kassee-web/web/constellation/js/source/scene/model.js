const connections = [
  ['ethos','chain'],['ethos','multisig'],['ethos','sovereign'],['ethos','stego'],
  ['chain','build'],['build','device'],
  ['device','kassee'],['kassee','security'],
  ['security','sovereign'],['security','stego'],
  ['multisig','device'],['multisig','kassee'],
];

// ── ghost shapes ─────────────────────────────────────────
function makeGhosts(W, H) {
  const ghosts = [];
  const count = 18;
  for (let i = 0; i < count; i++) {
    const type = ['circle','ring','arc','poly'][Math.floor(Math.random()*4)];
    ghosts.push({
      type,
      x: Math.random() * W,
      y: Math.random() * H,
      r: 8 + Math.random() * 55,
      speed: (0.04 + Math.random() * 0.12) * (Math.random() > 0.5 ? 1 : -1),
      angle: Math.random() * Math.PI * 2,
      orbitR: 60 + Math.random() * 200,
      cx: Math.random() * W,
      cy: Math.random() * H,
      sides: 3 + Math.floor(Math.random() * 4),
      opacity: 0.015 + Math.random() * 0.04,
      phase: Math.random() * Math.PI * 2,
    });
  }
  return ghosts;
}

// ── star particles ──────────────────────────────────────
function makeStars(W, H) {
  const stars = [];
  for (let i = 0; i < 120; i++) {
    stars.push({
      x: Math.random() * W,
      y: Math.random() * H,
      r: 0.3 + Math.random() * 1.5,
      speed: 0.05 + Math.random() * 0.2,
      drift: (Math.random() - 0.5) * 0.3,
      phase: Math.random() * Math.PI * 2,
      bright: 0.15 + Math.random() * 0.5,
    });
  }
  return stars;
}

// ── node color scheme ───────────────────────────────────
const nodeColors = {
  ethos:     { base: '#2a6b4a', glow: '#1D9E75', accent: '#c8a846', ring: 'rgba(200,168,70,0.12)',
               sphere: ['#243e24','#18291a','#0e180e','#080c06'], spec: 'rgba(200,168,70,0.14)', rim: 'rgba(200,168,70,0.10)' },
  multisig:  { base: '#2a6b4a', glow: '#1D9E75', accent: '#d4a843', ring: 'rgba(212,168,67,0.1)',
               sphere: ['#303624','#222818','#161a0e','#0c0e06'], spec: 'rgba(212,168,67,0.12)', rim: 'rgba(212,168,67,0.08)' },
  chain:     { base: '#1a5040', glow: '#1D9E75', accent: '#1D9E75', ring: 'rgba(29,158,117,0.08)',
               sphere: ['#183e30','#0e2418','#081410','#040c08'], spec: 'rgba(29,158,117,0.10)', rim: 'rgba(29,158,117,0.06)' },
  build:     { base: '#1a5040', glow: '#1D9E75', accent: '#1D9E75', ring: 'rgba(29,158,117,0.08)',
               sphere: ['#183e30','#0e2418','#081410','#040c08'], spec: 'rgba(29,158,117,0.10)', rim: 'rgba(29,158,117,0.06)' },
  device:    { base: '#1D9E75', glow: '#3ffcb0', accent: '#3ffcb0', ring: 'rgba(63,252,176,0.15)',
               sphere: ['#18443a','#104430','#0a3024','#061a14'], spec: 'rgba(63,252,176,0.22)', rim: 'rgba(63,252,176,0.14)' },
  kassee:    { base: '#1D9E75', glow: '#3ffcb0', accent: '#3ffcb0', ring: 'rgba(63,252,176,0.15)',
               sphere: ['#183c44','#0e3038','#082428','#04161c'], spec: 'rgba(80,210,255,0.18)', rim: 'rgba(80,210,255,0.10)' },
  security:  { base: '#993C1D', glow: '#F0997B', accent: '#F0997B', ring: 'rgba(240,153,123,0.08)',
               sphere: ['#302018','#241610','#180e0a','#0e0806'], spec: 'rgba(240,153,123,0.12)', rim: 'rgba(240,153,123,0.08)' },
  sovereign: { base: '#6b5a2a', glow: '#d4a843', accent: '#d4a843', ring: 'rgba(212,168,67,0.12)',
               sphere: ['#302c18','#242010','#181408','#0e0c06'], spec: 'rgba(212,168,67,0.16)', rim: 'rgba(212,168,67,0.10)' },
  stego:     { base: '#4a2a6b', glow: '#b080e0', accent: '#b080e0', ring: 'rgba(176,128,224,0.10)',
               sphere: ['#241830','#1a1224','#120c18','#0a060c'], spec: 'rgba(176,128,224,0.14)', rim: 'rgba(176,128,224,0.08)' },
};

// ── satellite orbit state ────────────────────────────────
