function drawGhost(ghost, time) {
  ctx.save();
  ctx.globalAlpha = ghost.opacity * (0.7 + 0.3 * Math.sin(time * 0.4 + ghost.phase));
  ctx.strokeStyle = '#1D9E75';
  ctx.lineWidth = 0.4;
  ctx.fillStyle = 'none';

  const x = ghost.cx + Math.cos(ghost.angle + time * ghost.speed * 0.3) * ghost.orbitR;
  const y = ghost.cy + Math.sin(ghost.angle + time * ghost.speed * 0.3) * ghost.orbitR;
  ctx.beginPath();
  if (ghost.type === 'circle') {
    ctx.arc(x, y, ghost.r, 0, Math.PI * 2);
  } else if (ghost.type === 'ring') {
    ctx.arc(x, y, ghost.r, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y, ghost.r * 0.6, 0, Math.PI * 2);
  } else if (ghost.type === 'arc') {
    const start = time * ghost.speed + ghost.phase;
    ctx.arc(x, y, ghost.r, start, start + Math.PI * (0.6 + 0.4 * Math.sin(time * 0.2)));
  } else if (ghost.type === 'poly') {
    ctx.moveTo(x + ghost.r * Math.cos(time * ghost.speed * 0.5), y + ghost.r * Math.sin(time * ghost.speed * 0.5));
    for (let index = 1; index <= ghost.sides; index += 1) {
      const angle = (index / ghost.sides) * Math.PI * 2 + time * ghost.speed * 0.5;
      ctx.lineTo(x + ghost.r * Math.cos(angle), y + ghost.r * Math.sin(angle));
    }
    ctx.closePath();
  }
  ctx.stroke();
  ctx.restore();
}

function drawStars(time) {
  stars.forEach(star => {
    star.y -= star.speed;
    star.x += star.drift;
    if (star.y < -5) { star.y = H + 5; star.x = Math.random() * W; }
    if (star.x < -5) star.x = W + 5;
    if (star.x > W + 5) star.x = -5;
    const flicker = star.bright * (0.6 + 0.4 * Math.sin(time * 2.5 + star.phase));
    ctx.beginPath();
    ctx.arc(star.x, star.y, star.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(200, 220, 190, ${flicker})`;
    ctx.fill();
  });
}

function drawConnections(time) {
  connections.forEach(([fromId, toId], index) => {
    const fromNode = acts.find(node => node.id === fromId);
    const toNode = acts.find(node => node.id === toId);
    const from = nodePos(fromNode);
    const to = nodePos(toNode);
    const highlighted = [fromNode, toNode].includes(hoveredNode) || [fromNode, toNode].includes(activeNode);

    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.strokeStyle = highlighted ? 'rgba(29,158,117,0.25)' : 'rgba(29,60,40,0.35)';
    ctx.lineWidth = highlighted ? 1 : 0.5;
    ctx.stroke();

    const position = (time * (0.15 + index * 0.02) + index * 0.37) % 1;
    drawConnectionParticle(
      from.x + (to.x - from.x) * position,
      from.y + (to.y - from.y) * position,
      highlighted,
    );
  });
}

function drawConnectionParticle(x, y, highlighted) {
  if (!Number.isFinite(x) || !Number.isFinite(y)) return;
  const size = highlighted ? 3 : 1.5;
  const alpha = highlighted ? 0.6 : 0.2;
  const gradient = ctx.createRadialGradient(x, y, 0, x, y, size * 4);
  gradient.addColorStop(0, `rgba(29,158,117,${alpha})`);
  gradient.addColorStop(1, 'rgba(29,158,117,0)');
  ctx.beginPath();
  ctx.arc(x, y, size * 4, 0, Math.PI * 2);
  ctx.fillStyle = gradient;
  ctx.fill();
  ctx.beginPath();
  ctx.arc(x, y, size, 0, Math.PI * 2);
  ctx.fillStyle = `rgba(63,252,176,${alpha})`;
  ctx.fill();
}
