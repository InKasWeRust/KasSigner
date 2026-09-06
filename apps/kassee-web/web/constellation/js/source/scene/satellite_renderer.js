function drawSatellites(node, x, y, time) {
  if (node !== hoveredNode || !node.satellites?.length || satProgress <= 0.02) return;
  node.satellites.forEach((satellite, index) => {
    const position = satPos(node, index, node.satellites.length, satProgress);
    const hovered = isSatHovered(node, index);
    const radius = satellite.r * satProgress;
    const pulse = Math.sin(time * 1.5 + index * 2.0) * 0.5 + 0.5;
    drawSatelliteConnector(x, y, position);
    drawSatelliteGlow(position, radius, pulse, hovered);
    drawSatelliteBody(position, radius, hovered);
    drawSatelliteLabel(satellite, position, radius, hovered);
  });
}

function drawSatelliteConnector(x, y, position) {
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(position.x, position.y);
  ctx.strokeStyle = `rgba(29,158,117,${0.3 * satProgress})`;
  ctx.lineWidth = 0.8;
  ctx.setLineDash([4, 4]);
  ctx.stroke();
  ctx.setLineDash([]);
}

function drawSatelliteGlow(position, radius, pulse, hovered) {
  if (satProgress > 0.3) {
    const glowRadius = radius + 10 + pulse * 4;
    const gradient = ctx.createRadialGradient(position.x, position.y, radius * 0.5, position.x, position.y, glowRadius);
    gradient.addColorStop(0, hovered ? 'rgba(29,158,117,0.25)' : 'rgba(29,158,117,0.12)');
    gradient.addColorStop(1, 'rgba(29,158,117,0)');
    ctx.beginPath();
    ctx.arc(position.x, position.y, glowRadius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.globalAlpha = satProgress;
    ctx.fill();
    ctx.globalAlpha = 1;
  }
  if (satProgress > 0.4) {
    ctx.beginPath();
    ctx.arc(position.x, position.y, radius + 4 + pulse * 3, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(29,158,117,${(hovered ? 0.5 : 0.25) * satProgress})`;
    ctx.lineWidth = 0.6;
    ctx.stroke();
  }
}

function drawSatelliteBody(position, radius, hovered) {
  ctx.beginPath();
  ctx.arc(position.x, position.y, radius, 0, Math.PI * 2);
  ctx.fillStyle = hovered ? '#0f3828' : '#0a2418';
  ctx.fill();
  ctx.strokeStyle = hovered ? '#3ffcb0' : '#1D9E75';
  ctx.lineWidth = hovered ? 1.2 : 0.8;
  ctx.stroke();
}

function drawSatelliteLabel(satellite, position, radius, hovered) {
  if (satProgress <= 0.3) return;
  ctx.font = `400 ${Math.round(11 * satProgress)}px "IBM Plex Mono"`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = hovered ? '#e0f4ec' : '#9fcfbc';
  ctx.globalAlpha = Math.min(1, (satProgress - 0.3) * 1.5);
  ctx.fillText(satellite.label, position.x, position.y + radius + 14);
  ctx.globalAlpha = 1;
}
