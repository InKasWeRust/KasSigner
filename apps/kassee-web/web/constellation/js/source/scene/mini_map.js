const miniCanvas = document.getElementById('mini-canvas');
const mctx = miniCanvas.getContext('2d');
const MS = 120;

function drawMini() {
  mctx.clearRect(0, 0, MS, MS);

  // subtle circle bg
  mctx.beginPath();
  mctx.arc(MS/2, MS/2, MS/2 - 1, 0, Math.PI * 2);
  mctx.fillStyle = 'rgba(14,15,12,0.85)';
  mctx.fill();
  mctx.strokeStyle = '#1a2a1e';
  mctx.lineWidth = 0.5;
  mctx.stroke();

  // connections
  connections.forEach(([a, b]) => {
    const na = acts.find(n => n.id === a);
    const nb = acts.find(n => n.id === b);
    mctx.beginPath();
    mctx.moveTo(na.x * MS, na.y * MS);
    mctx.lineTo(nb.x * MS, nb.y * MS);
    mctx.strokeStyle = '#182218';
    mctx.lineWidth = 0.4;
    mctx.stroke();
  });

  // nodes
  acts.forEach(n => {
    const mx = n.x * MS, my = n.y * MS;
    const isActive = n === activeNode;
    const r = isActive ? 6 : 4;
    mctx.beginPath();
    mctx.arc(mx, my, r, 0, Math.PI * 2);
    mctx.fillStyle = isActive ? '#1D9E75' : '#0f1a10';
    mctx.fill();
    mctx.strokeStyle = isActive ? '#9fcfbc' : '#1a3025';
    mctx.lineWidth = 0.5;
    mctx.stroke();
  });

  // satellites of active
  if (activeNode && activeNode.satellites.length > 0) {
    const mx = activeNode.x * MS, my = activeNode.y * MS;
    for (let si = 0; si < activeNode.satellites.length; si += 1) {
      const baseAngle = (si / activeNode.satellites.length) * Math.PI * 2 - Math.PI / 2;
      const orbitR = 18;
      const sx = mx + Math.cos(baseAngle) * orbitR;
      const sy = my + Math.sin(baseAngle) * orbitR;
      mctx.beginPath();
      mctx.arc(sx, sy, 3, 0, Math.PI * 2);
      mctx.fillStyle = '#0d5c42';
      mctx.fill();
    }
  }

  requestAnimationFrame(drawMini);
}

// ── interaction ──────────────────────────────────────────
