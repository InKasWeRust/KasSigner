function drawNode(node, index, time) {
  const { x, y } = nodePos(node);
  const hovered = node === hoveredNode || node === activeNode;
  const colors = nodeColors[node.id] || nodeColors.chain;
  const pulse = Math.sin(time * 0.7 + index * 1.05) * 2;
  const breathe = Math.sin(time * 0.3 + index * 0.8) * 0.5 + 0.5;
  const radius = node.r + (hovered ? 6 : 0);
  drawNodeGlow(x, y, radius, pulse, breathe, hovered, colors);
  drawNodeSphere(x, y, radius, pulse, breathe, hovered, colors);
  drawNodeLabel(node.label, x, y, hovered);
  drawSatellites(node, x, y, time);
}

function drawNodeGlow(x, y, radius, pulse, breathe, hovered, colors) {
  const glowRadius = radius + 28 + pulse * 2;
  if (Number.isFinite(x) && Number.isFinite(y) && Number.isFinite(glowRadius) && glowRadius > 0) {
    const gradient = ctx.createRadialGradient(x, y, radius * 0.5, x, y, glowRadius);
    gradient.addColorStop(0, hovered ? colors.ring.replace(/[\d.]+\)$/, '0.3)') : colors.ring);
    gradient.addColorStop(0.5, hovered ? colors.ring.replace(/[\d.]+\)$/, '0.1)') : colors.ring.replace(/[\d.]+\)$/, '0.04)'));
    gradient.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath();
    ctx.arc(x, y, glowRadius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();
  }
  if (hovered) {
    ctx.beginPath();
    ctx.arc(x, y, radius + 18 + pulse, 0, Math.PI * 2);
    ctx.strokeStyle = colors.ring.replace(/[\d.]+\)$/, `${(0.15 + breathe * 0.15).toFixed(2)})`);
    ctx.lineWidth = 0.8;
    ctx.stroke();
  }
}

function drawNodeSphere(x, y, radius, pulse, breathe, hovered, colors) {
  const renderedRadius = radius + pulse * 0.3;
  if (Number.isFinite(radius) && radius > 0) {
    const sphere = colors.sphere;
    const fill = ctx.createRadialGradient(x - radius * 0.35, y - radius * 0.35, radius * 0.05, x, y, renderedRadius);
    fill.addColorStop(0, hovered ? sphere[0] : sphere[1]);
    fill.addColorStop(0.4, hovered ? sphere[1] : sphere[2]);
    fill.addColorStop(0.85, hovered ? sphere[2] : sphere[3]);
    fill.addColorStop(1, sphere[3]);
    ctx.beginPath();
    ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
    ctx.fillStyle = fill;
    ctx.fill();

    const specular = ctx.createRadialGradient(x - radius * 0.28, y - radius * 0.3, 0, x - radius * 0.28, y - radius * 0.3, radius * 0.45);
    specular.addColorStop(0, hovered ? colors.spec.replace(/[\d.]+\)$/, '0.22)') : colors.spec);
    specular.addColorStop(0.5, hovered ? colors.spec.replace(/[\d.]+\)$/, '0.06)') : colors.spec.replace(/[\d.]+\)$/, '0.02)'));
    specular.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath();
    ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
    ctx.fillStyle = specular;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(x, y, renderedRadius - 1, Math.PI * 0.1, Math.PI * 0.65);
    ctx.strokeStyle = hovered ? colors.rim.replace(/[\d.]+\)$/, `${(0.14 + breathe * 0.1).toFixed(2)})`) : colors.rim;
    ctx.lineWidth = hovered ? 1.5 : 0.8;
    ctx.stroke();
  }

  ctx.beginPath();
  ctx.arc(x, y, renderedRadius, 0, Math.PI * 2);
  ctx.strokeStyle = hovered ? colors.glow : colors.base;
  ctx.lineWidth = hovered ? 1.2 : 0.5;
  ctx.stroke();
  if (hovered) {
    ctx.beginPath();
    ctx.arc(x, y, radius - 3, -Math.PI * 0.8, -Math.PI * 0.2);
    ctx.strokeStyle = 'rgba(63,252,176,0.12)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }
}

function drawNodeLabel(label, x, y, hovered) {
  ctx.font = hovered ? '600 14px "Rubik"' : '500 12px "Rubik"';
  ctx.fillStyle = hovered ? '#e0ecd8' : '#4a6858';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(label, x, y);
}
